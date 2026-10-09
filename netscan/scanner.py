"""Wrapper sobre nmap: construccion de comandos, control de procesos y parseo XML.

Reglas de seguridad aplicadas en todo el modulo:
  * Los comandos se construyen SIEMPRE como lista de argumentos.
  * Nunca se usa shell=True, nunca os.system, nunca se concatena entrada de
    usuario en una cadena de shell.
  * El XML de nmap (-oX) se parsea SIEMPRE con xml.etree.ElementTree.
  * Ante cualquier fallo de nmap NO se genera un reporte falso: se lanza
    ErrorDeEscaneo con un mensaje accionable.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .osdetect import (
    InfoNmap,
    aviso_privilegios_sudo,
    obtener_info_sistema,
    version_es_valida,
)
from .targets import Objetivo
from .utils import Consola, duracion_humana, obtener_logger

LOG = obtener_logger("scanner")

CODIGO_ERROR_EJECUCION = 2

# --------------------------------------------------------------------------
# Perfiles de escaneo
# --------------------------------------------------------------------------

PERFIL_DESCUBRIMIENTO = "discovery"
PERFIL_PUERTOS = "puertos"
PERFIL_COMPLETO = "completo"
PERFIL_WEB = "web"

PUERTOS_WEB = "80,443,8080,8443,8000,8888,3000,5000,9090"

# Flags no soportados en algunas combinaciones /versiones.
FLAGS_NO_SOPORTADOS_SIN_SUDO = ("-sS", "-O", "--osscan-limit", "-oA")


@dataclass(frozen=True)
class Perfil:
    """Perfil de escaneo: flags base + descripcion."""

    clave: str
    titulo: str
    descripcion: str
    flags_base: Tuple[str, ...]
    requiere_ss: bool = False


PERFILES: Dict[str, Perfil] = {
    PERFIL_DESCUBRIMIENTO: Perfil(
        clave=PERFIL_DESCUBRIMIENTO,
        titulo="Descubrimiento de hosts",
        descripcion="Solo descubre hosts activos (-sn). No enumera puertos.",
        flags_base=("-sn",),
    ),
    PERFIL_PUERTOS: Perfil(
        clave=PERFIL_PUERTOS,
        titulo="Puertos y servicios",
        descripcion="TCP connect scan (-sT) con deteccion de versiones, 1000 puertos top.",
        flags_base=("-sT", "-sV", "--top-ports", "1000"),
    ),
    PERFIL_COMPLETO: Perfil(
        clave=PERFIL_COMPLETO,
        titulo="Completo (servicios + scripts + OS)",
        descripcion="Deteccion de versiones, scripts NSE por defecto y deteccion de SO (-A).",
        flags_base=("-sV", "-sC", "-A"),
    ),
    PERFIL_WEB: Perfil(
        clave=PERFIL_WEB,
        titulo="Servidor web",
        descripcion="Solo puertos web habituales, con scripts http-* de NSE.",
        flags_base=("-sV", "-p", PUERTOS_WEB, "--script", "http-*"),
    ),
}

VELOCIDADES = {
    "T2": "T2 - muy lento, muy discreto (recomendado en redes sensibles)",
    "T3": "T3 - lento, poco ruido",
    "T4": "T4 - rapido (valor por defecto de NetAudit)",
    "T5": "T5 - muy rapido, mas ruido, solo en redes propias y aisladas",
}


class ErrorDeEscaneo(RuntimeError):
    """Fallo de nmap. Se muestra al usuario sin traceback crudo."""


# --------------------------------------------------------------------------
# Modelos de resultado
# --------------------------------------------------------------------------


@dataclass
class Servicio:
    """Un puerto con su servicio y banners."""

    puerto: int
    protocolo: str
    estado: str
    servicio: str = ""
    producto: str = ""
    version: str = ""
    extra: str = ""
    metodo: str = ""
    confianza: int = 0
    banner: str = ""
    scripts: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def nombre_completo(self) -> str:
        partes = [p for p in (self.servicio, self.producto, self.version, self.extra) if p]
        return " ".join(partes) if partes else "desconocido"

    @property
    def etiqueta(self) -> str:
        return f"{self.puerto}/{self.protocolo}"


@dataclass
class Host:
    """Un host analizado."""

    direccion: str
    tipo_direccion: str = "ipv4"
    estado: str = "unknown"
    motivo_estado: str = ""
    hostnames: List[str] = field(default_factory=list)
    puertos: List[Servicio] = field(default_factory=list)
    os_nombre: str = ""
    os_precision: int = 0
    scripts_host: List[Tuple[str, str]] = field(default_factory=list)
    latitud: str = ""
    longitud: str = ""

    @property
    def nombre_principal(self) -> str:
        return self.hostnames[0] if self.hostnames else ""

    @property
    def puertos_abiertos(self) -> List[Servicio]:
        return [p for p in self.puertos if p.estado == "open"]

    @property
    def etiqueta(self) -> str:
        if self.nombre_principal:
            return f"{self.direccion} ({self.nombre_principal})"
        return self.direccion


@dataclass
class ResultadoEscaneo:
    """Resultado completo de un escaneo."""

    objetivos: List[Objetivo]
    comandos: List[List[str]] = field(default_factory=list)
    hosts: List[Host] = field(default_factory=list)
    xml_crudo: str = ""
    duracion_segundos: float = 0.0
    inicio: str = ""
    fin: str = ""
    perfil: str = ""
    velocidad: str = ""
    lotes: int = 0
    nmap_ruta: str = ""
    nmap_version: str = ""
    avisos: List[str] = field(default_factory=list)

    @property
    def hosts_activos(self) -> List[Host]:
        return [h for h in self.hosts if h.estado == "up"]

    @property
    def total_puertos_abiertos(self) -> int:
        return sum(len(h.puertos_abiertos) for h in self.hosts)

    def buscar_host(self, direccion: str) -> Optional[Host]:
        """Busca un host por direccion. Devuelve None si no esta en el resultado."""
        for host in self.hosts:
            if host.direccion == direccion:
                return host
        return None


# --------------------------------------------------------------------------
# Construccion del comando
# --------------------------------------------------------------------------


def construir_comando_nmap(
    info_nmap: InfoNmap,
    objetivos_nmap: Sequence[str],
    perfil: str,
    velocidad: str = "T4",
    usar_ss: bool = False,
    puertos: Optional[str] = None,
    host_timeout: Optional[str] = None,
    xml_ruta: Optional[str] = None,
    excluir: Optional[Sequence[str]] = None,
    usar_sin_ping: bool = False,
    plantillas_extra: Optional[Sequence[str]] = None,
) -> List[str]:
    """Construye la lista de argumentos para nmap.

    Devuelve una LISTA. Nunca una cadena de shell.
    """
    if perfil not in PERFILES:
        raise ErrorDeEscaneo(f"Perfil desconocido: {perfil!r}")
    if velocidad not in VELOCIDADES:
        raise ErrorDeEscaneo(
            f"Velocidad invalida: {velocidad!r}. Opciones: {', '.join(VELOCIDADES)}."
        )
    if not objetivos_nmap:
        raise ErrorDeEscaneo("No hay objetivos que escanear.")

    definicion = PERFILES[perfil]
    comando: List[str] = [info_nmap.ruta]

    flags: List[str] = list(definicion.flags_base)

    if usar_ss:
        # SYN scan solo si el usuario lo pide explicitamente.
        if "-sT" in flags:
            flags.remove("-sT")
        if "-sS" not in flags:
            flags.insert(0, "-sS")
    elif "-sS" in flags:
        flags.remove("-sS")

    if host_timeout:
        flags += ["--host-timeout", host_timeout]

    if excluir:
        flags.append("--exclude")
        flags.append(",".join(excluir))

    if usar_sin_ping:
        flags.append("-Pn")

    if puertos:
        # Si el perfil define puertos propios, se reemplazan por los del usuario.
        if "-p" in flags:
            indice = flags.index("-p")
            del flags[indice : indice + 2]
        flags += ["-p", puertos]

    if plantillas_extra:
        flags.append("--script")
        flags.append(",".join(plantillas_extra))

    # -sn (descubrimiento) y -sV/sC son incompatibles en algunos casos.
    if perfil == PERFIL_DESCUBRIMIENTO and ("-sV" in flags or "-sC" in flags):
        raise ErrorDeEscaneo(
            "El perfil 'discovery' usa -sn y no admite deteccion de versiones (-sV/-sC)."
        )

    comando += flags
    comando += [f"-{velocidad}"]
    comando += ["-oX", xml_ruta or "-"]
    comando += ["-v"]  # una pasada de verbosity: progreso en la salida
    comando += list(objetivos_nmap)
    return comando


def _validar_flags_para_entorno(comando: List[str], usar_ss: bool, consola: Optional[Consola]) -> None:
    """Ajusta diferencias reales de ejecucion segun SO y privilegios."""
    info = obtener_info_sistema()
    if usar_ss and info.requiere_sudo_para_syn and consola:
        aviso_privilegios_sudo(consola, usar_ss=True)


# --------------------------------------------------------------------------
# Ejecucion
# --------------------------------------------------------------------------


def _terminar_hijo(proceso: subprocess.Popen) -> None:
    """Termina el proceso hijo de forma limpia (y su arbol en Windows)."""
    if proceso.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/PID", str(proceso.pid), "/T", "/F"],
                capture_output=True,
                timeout=30,
                shell=False,
                check=False,
            )
        else:
            proceso.send_signal(signal.SIGINT)
            try:
                proceso.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proceso.kill()
    except Exception as exc:  # pragma: no cover - defensivo
        LOG.warning("No se pudo terminar el proceso hijo limpiamente: %s", exc)


def ejecutar_nmap(
    comando: List[str],
    host_timeout: Optional[str] = None,
    timeout_global: int = 7200,
    consola: Optional[Consola] = None,
    descripcion: str = "escaneo",
    ruta_xml: Optional[str] = None,
) -> str:
    """Ejecuta nmap y devuelve el XML producido.

    nmap escribe el XML en el fichero indicado por -oX (la salida por stdout es
    el progreso legible). Si ruta_xml es '-' o None se usa stdout.

    Lanza ErrorDeEscaneo con mensaje accionable si nmap falla, se cuelga o
    produce salida vacia.
    """
    LOG.info("Ejecutando nmap (%s): %s", descripcion, " ".join(comando))
    inicio = time.time()

    timeout = timeout_global
    if host_timeout:
        try:
            timeout = min(timeout_global, int(_segundos_de_host_timeout(host_timeout)) + 120)
        except ValueError:
            pass

    try:
        proceso = subprocess.Popen(
            comando,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise ErrorDeEscaneo(
            f"No se pudo ejecutar nmap: {comando[0]!r} no existe o no es ejecutable.\n"
            "  Verifica la instalacion de nmap (>= 7.80) y que esta en el PATH."
        ) from exc
    except OSError as exc:
        raise ErrorDeEscaneo(f"No se pudo lanzar nmap: {exc}") from exc

    stdout = ""
    stderr = ""
    try:
        salida_completa, error_completo = proceso.communicate(timeout=timeout)
        stdout = salida_completa or ""
        stderr = error_completo or ""
    except subprocess.TimeoutExpired:
        _terminar_hijo(proceso)
        try:
            salida_completa, error_completo = proceso.communicate(timeout=30)
            stdout, stderr = salida_completa or "", error_completo or ""
        except Exception:
            pass
        raise ErrorDeEscaneo(
            f"nmap se cuelgo y fue terminado tras {duracion_humana(timeout)} "
            f"(descripcion: {descripcion}).\n"
            "  Causa habitual: el escaneo es demasiado lento para la red, o un host no\n"
            "  responde. Soluciones:\n"
            "    - reduce el alcance (menos hosts o menos puertos),\n"
            "    - baja la velocidad (T2/T3),\n"
            "    - usa --host-timeout 30s para acotar cada host,\n"
            "    - usa el perfil 'discovery' primero para acotar los hosts activos."
        )
    except Exception as exc:  # pragma: no cover - defensivo
        _terminar_hijo(proceso)
        raise ErrorDeEscaneo(f"Fallo inesperado ejecutando nmap: {exc}") from exc

    duracion = time.time() - inicio
    codigo = proceso.returncode
    LOG.info(
        "nmap terminado en %s (codigo=%s)", duracion_humana(duracion), codigo
    )

    # El XML se lee del fichero si nmap escribio en disco; si no, de stdout.
    xml = ""
    if ruta_xml and ruta_xml != "-":
        if os.path.isfile(ruta_xml):
            with open(ruta_xml, "r", encoding="utf-8", errors="replace") as manejador:
                xml = manejador.read()
        else:
            raise ErrorDeEscaneo(
                "nmap no genero el fichero XML esperado.\n"
                f"  Ruta prevista: {ruta_xml}\n"
                "  Revisa los permisos de escritura del directorio temporal."
            )
    else:
        xml = stdout

    LOG.debug("XML obtenido: %d bytes", len(xml))

    if codigo != 0:
        raise ErrorDeEscaneo(
            f"nmap termino con codigo de salida {codigo} sin generar un XML valido.\n"
            f"  Ultimas lineas de salida de nmap:\n{_ultimas_lineas(stdout or stderr, 8)}\n"
            "  Causas frecuentes: falta de privilegios para el tipo de escaneo elegido,\n"
            "  sintaxis no soportada por la version de nmap, o el escaneo fue cancelado."
        )

    if not xml.strip():
        raise ErrorDeEscaneo(
            "nmap no devolvio ninguna salida XML.\n"
            f"  Ultimas lineas de salida de nmap:\n{_ultimas_lineas(stdout or stderr, 8)}\n"
            "  No se genera reporte para no mostrar datos falsos."
        )

    return xml


def _segundos_de_host_timeout(valor: str) -> float:
    """Convierte '30s', '2m', '1h' a segundos."""
    valor = valor.strip().casefold()
    multiplicadores = {"s": 1, "m": 60, "h": 3600}
    if valor and valor[-1] in multiplicadores:
        return float(valor[:-1]) * multiplicadores[valor[-1]]
    return float(valor)


def _ultimas_lineas(texto: str, cantidad: int = 6) -> str:
    lineas = [linea.rstrip() for linea in (texto or "").splitlines() if linea.strip()]
    if not lineas:
        return "      (nmap no escribio nada en stderr)"
    return "\n".join(f"      {linea}" for linea in lineas[-cantidad:])


# --------------------------------------------------------------------------
# Parseo del XML
# --------------------------------------------------------------------------


def parsear_xml_nmap(xml_texto: str) -> ResultadoEscaneo:
    """Parsea el XML de nmap con xml.etree.ElementTree.

    Lanza ErrorDeEscaneo si el XML esta truncado o malformado.
    """
    if not xml_texto or not xml_texto.strip():
        raise ErrorDeEscaneo("El XML de nmap esta vacio.")

    try:
        raiz = ET.fromstring(xml_texto.strip())
    except ET.ParseError as exc:
        # Comprobamos si es un XML truncado: caso muy habitual si se corta nmap.
        if not xml_texto.rstrip().endswith("</nmaprun>"):
            detalle = (
                "El XML parece truncado: nmap fue interrumpido antes de cerrar "
                "</nmaprun>.\n"
                "  El XML crudo se ha conservado en "
                f"{os.path.join('reportes', 'datos_crudos_fallidos')} para auditoria.\n"
                "  Vuelve a ejecutar el escaneo con mayor --timeout o con menos hosts."
            )
        else:
            detalle = (
                "El XML esta mal formado. Revisa la copia conservada en "
                f"{os.path.join('reportes', 'datos_crudos_fallidos')}."
            )
        raise ErrorDeEscaneo(f"No se pudo parsear el XML de nmap: {exc}\n  {detalle}") from exc

    if raiz.tag != "nmaprun":
        raise ErrorDeEscaneo(
            f"El XML de nmap no tiene el elemento raiz esperado 'nmaprun' (es {raiz.tag!r})."
        )

    resultado = ResultadoEscaneo(objetivos=[], xml_crudo=xml_texto)
    resultado.inicio = raiz.get("startstr", "")
    resultado.nmap_ruta = str(raiz.get("program", "") or "")

    for elemento_host in raiz.findall("host"):
        host = _parsear_host(elemento_host)
        if host is not None:
            resultado.hosts.append(host)

    for elemento_run in raiz.findall("runstats/finished"):
        resultado.fin = elemento_run.get("timestr", "")
    return resultado


def _parsear_host(elemento_host: ET.Element) -> Optional[Host]:
    estado_elemento = elemento_host.find("status")
    estado = estado_elemento.get("state", "unknown") if estado_elemento is not None else "unknown"
    motivo = estado_elemento.get("reason", "") if estado_elemento is not None else ""

    direccion = ""
    tipo = "ipv4"
    mac = ""
    for direccion_elemento in elemento_host.findall("address"):
        tipo_addr = direccion_elemento.get("addrtype", "")
        if tipo_addr in ("ipv4", "ipv6") and not direccion:
            direccion = direccion_elemento.get("addr", "")
            tipo = tipo_addr
        elif tipo_addr == "mac":
            mac = direccion_elemento.get("addr", "")

    if not direccion and mac:
        direccion = mac

    if not direccion:
        return None

    host = Host(direccion=direccion, tipo_direccion=tipo, estado=estado, motivo_estado=motivo)

    for contenedor_nombres in elemento_host.findall("hostnames"):
        for nombre in contenedor_nombres.findall("hostname"):
            valor = nombre.get("name", "")
            if valor:
                host.hostnames.append(valor)

    for geo in elemento_host.findall("geolocation"):
        host.latitud = geo.get("lat", "")
        host.longitud = geo.get("lon", "")

    for elemento_puerto in elemento_host.findall("ports/port"):
        servicio = _parsear_puerto(elemento_puerto)
        if servicio is not None:
            host.puertos.append(servicio)

    for osmatch in elemento_host.findall("os/osmatch"):
        nombre = osmatch.get("name", "")
        precision = int(osmatch.get("accuracy", "0") or 0)
        if precision >= host.os_precision:
            host.os_precision = precision
            host.os_nombre = nombre

    for script in elemento_host.findall("hostscript/script"):
        host.scripts_host.append((script.get("id", ""), script.get("output", "")))

    return host


def _parsear_puerto(elemento_puerto: ET.Element) -> Optional[Servicio]:
    try:
        puerto_id = int(elemento_puerto.get("portid", "0"))
    except ValueError:
        return None
    protocolo = elemento_puerto.get("protocol", "tcp")

    estado_elemento = elemento_puerto.find("state")
    estado = estado_elemento.get("state", "closed") if estado_elemento is not None else "closed"

    servicio_elemento = elemento_puerto.find("service")
    servicio = Servicio(puerto=puerto_id, protocolo=protocolo, estado=estado)
    if servicio_elemento is not None:
        servicio.servicio = servicio_elemento.get("name", "")
        servicio.producto = servicio_elemento.get("product", "")
        servicio.version = servicio_elemento.get("version", "")
        servicio.extra = servicio_elemento.get("extrainfo", "")
        servicio.metodo = servicio_elemento.get("method", "")
        try:
            servicio.confianza = int(servicio_elemento.get("conf", "0") or 0)
        except ValueError:
            servicio.confianza = 0
        # El banner real de nmap es el elemento hijo <banner> de <service>.
        banner_elemento = servicio_elemento.find("banner")
        if banner_elemento is not None and banner_elemento.text:
            servicio.banner = banner_elemento.text

    for script in elemento_puerto.findall("script"):
        servicio.scripts.append((script.get("id", ""), script.get("output", "")))

    servicio.banner = _extraer_banner(servicio)
    return servicio


def _extraer_banner(servicio: Servicio) -> str:
    """Banner mas representativo de un servicio, para usar como evidencia.

    Prioriza el banner real (elemento <banner> de nmap o producto/version) y
    solo recurre a la salida de scripts si no hay nada mejor.
    """
    if servicio.banner:
        return servicio.banner
    partes = [p for p in (servicio.producto, servicio.version, servicio.extra) if p]
    if partes:
        return " ".join(partes)
    for identificador, salida in servicio.scripts:
        if identificador == "banner" and salida:
            return salida
    return ""


# --------------------------------------------------------------------------
# Planificacion de lotes
# --------------------------------------------------------------------------


def dividir_en_lotes(objetivos: Sequence[Objetivo], hosts_por_lote: int) -> List[List[Objetivo]]:
    """Agrupa objetivos en lotes acotados por numero de hosts estimados."""
    lotes: List[List[Objetivo]] = []
    actual: List[Objetivo] = []
    actual_hosts = 0
    for objetivo in objetivos:
        hosts = max(1, objetivo.hosts_aproximados)
        if actual and actual_hosts + hosts > hosts_por_lote:
            lotes.append(actual)
            actual = []
            actual_hosts = 0
        actual.append(objetivo)
        actual_hosts += hosts
    if actual:
        lotes.append(actual)
    return lotes


def ejecutar_escaneo(
    info_nmap: InfoNmap,
    objetivos: Sequence[Objetivo],
    perfil: str,
    velocidad: str = "T4",
    usar_ss: bool = False,
    puertos: Optional[str] = None,
    exclusiones: Optional[Sequence[str]] = None,
    host_timeout: Optional[str] = None,
    limite_hosts: int = 1024,
    hosts_por_lote: int = 256,
    timeout_global: int = 7200,
    consola: Optional[Consola] = None,
    resultado_parcial: Optional[ResultadoEscaneo] = None,
    base_reportes: str = "reportes",
) -> ResultadoEscaneo:
    """Ejecuta el escaneo completo, en lotes, y devuelve el resultado agregado."""
    if not objetivos:
        raise ErrorDeEscaneo("No hay objetivos validos para escanear.")

    _validar_flags_para_entorno([], usar_ss, consola)

    if not version_es_valida(info_nmap):
        if consola:
            consola.aviso(
                f"nmap {info_nmap.version_completa} es antiguo; algunas detecciones fallaran."
            )

    lotes = dividir_en_lotes(objetivos, hosts_por_lote)
    total_hosts = sum(max(1, o.hosts_aproximados) for o in objetivos)

    resultado = resultado_parcial or ResultadoEscaneo(objetivos=list(objetivos))
    resultado.objetivos = list(objetivos)
    resultado.perfil = perfil
    resultado.velocidad = velocidad
    resultado.nmap_ruta = info_nmap.ruta
    resultado.nmap_version = info_nmap.version_completa
    resultado.lotes = len(lotes)

    inicio_global = time.time()
    xml_partes: List[str] = []
    lotes_ok = 0

    # Directorio de trabajo para conservar XML crudo si algo falla.
    directorio_xml = os.path.join(base_reportes, "datos_crudos_fallidos")
    os.makedirs(directorio_xml, exist_ok=True)

    for indice, lote in enumerate(lotes, start=1):
        objetivos_nmap = [o.valor_normalizado for o in lote]
        if consola:
            hosts_lote = sum(max(1, o.hosts_aproximados) for o in lote)
            consola.info(
                f"Lote {indice}/{len(lotes)} - {len(lote)} objetivo(s), "
                f"~{hosts_lote} host(s) | perfil={perfil} velocidad=-{velocidad}"
            )

        with tempfile.TemporaryDirectory(prefix="netaudit_") as temporal:
            ruta_xml = os.path.join(temporal, "salida.xml")
            comando = construir_comando_nmap(
                info_nmap=info_nmap,
                objetivos_nmap=objetivos_nmap,
                perfil=perfil,
                velocidad=velocidad,
                usar_ss=usar_ss,
                puertos=puertos,
                host_timeout=host_timeout,
                xml_ruta=ruta_xml,
                excluir=exclusiones,
            )
            resultado.comandos.append(list(comando))

            inicio_lote = time.time()
            xml = ejecutar_nmap(
                comando,
                host_timeout=host_timeout,
                timeout_global=timeout_global,
                consola=consola,
                descripcion=f"lote {indice}/{len(lotes)}",
                ruta_xml=ruta_xml,
            )
            duracion_lote = time.time() - inicio_lote

            try:
                parcial = parsear_xml_nmap(xml)
            except ErrorDeEscaneo:
                # Conservamos el XML crudo para auditoria antes de propagar.
                xml_parcial = os.path.join(directorio_xml, f"nmap_lote_{indice}.xml")
                _escribir_local(xml_parcial, xml)
                LOG.error("XML del lote %s conservado en %s", indice, xml_parcial)
                raise

            resultado.hosts.extend(parcial.hosts)
            if parcial.inicio and not resultado.inicio:
                resultado.inicio = parcial.inicio
            if parcial.fin:
                resultado.fin = parcial.fin
            xml_partes.append(envolver_xml_lote(xml, indice, len(lotes), parcial))
            lotes_ok += 1

            if consola:
                activos = len(parcial.hosts_activos)
                consola.ok(
                    f"Lote {indice}/{len(lotes)} completado en {duracion_humana(duracion_lote)}: "
                    f"{activos} host(s) activo(s), "
                    f"{len(parcial.hosts)} analizado(s)"
                )

    resultado.xml_crudo = unir_lotes_xml(xml_partes, perfil, len(lotes))
    resultado.duracion_segundos = time.time() - inicio_global

    if lotes_ok == 0:
        raise ErrorDeEscaneo(
            "Ningun lote de escaneo se completo correctamente. No se genera reporte."
        )
    if consola:
        consola.ok(
            f"Escaneo completo en {duracion_humana(resultado.duracion_segundos)} "
            f"({total_hosts} host(s) estimados, {lotes_ok} lote(s))."
        )
    return resultado


def _escribir_local(ruta: str, contenido: str) -> None:
    """Escribe un fichero creando directorios, sin fallar el escaneo."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(ruta)), exist_ok=True)
        with open(ruta, "w", encoding="utf-8", newline="\n") as manejador:
            manejador.write(contenido)
    except OSError as exc:
        LOG.warning("No se pudo guardar el XML crudo en %s: %s", ruta, exc)


def envolver_xml_lote(xml: str, indice: int, total: int, parcial: ResultadoEscaneo) -> str:
    """Envuelve el XML de un lote en un nmaprun valido para poder concatenarlos.

    nmap antepone la declaracion XML, una instruccion de proceso y un comentario
    antes de <nmaprun>, y anade atributos a esa etiqueta. Todo eso se elimina
    para dejar solo el contenido del lote y poder unir varios en un XML bien
    formado, que ademas se puede volver a parsear con parsear_xml_lotes.
    """
    limpio = xml.strip()
    if not limpio:
        return ""

    inicio = limpio.find("<nmaprun")
    if inicio == -1:
        raise ErrorDeEscaneo(
            f"El XML del lote {indice}/{total} no contiene el elemento <nmaprun>."
        )
    fin_apertura = limpio.find(">", inicio)
    if fin_apertura == -1:
        raise ErrorDeEscaneo(
            f"La etiqueta <nmaprun> del lote {indice}/{total} esta sin cerrar."
        )
    cuerpo = limpio[fin_apertura + 1 :]

    posicion_cierre = cuerpo.rfind("</nmaprun>")
    if posicion_cierre != -1:
        cuerpo = cuerpo[:posicion_cierre]

    encabezado = (
        f'<nmaprun lote="{indice}/{total}" hosts_en_lote="{len(parcial.hosts)}">'
    )
    return encabezado + cuerpo + "</nmaprun>"


def unir_lotes_xml(partes: Sequence[str], perfil: str = "", total_lotes: int = 0) -> str:
    """Une los XML de cada lote en un unico documento XML valido.

    Un fichero con varios elementos raiz no es XML bien formado y no lo pueden
    leer las herramientas estandar, asi que se envuelve todo en <netaudit_lotes>.
    """
    validas = [p for p in partes if p and p.strip()]
    if not validas:
        return ""
    if len(validas) == 1:
        return validas[0]
    cabecera = (
        '<netaudit_lotes herramienta="NetAudit" '
        f'perfil="{perfil}" total_lotes="{total_lotes or len(validas)}">'
    )
    pie = "</netaudit_lotes>"
    encabezado_xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    cuerpo = "\n\n".join(validas)
    return f"{encabezado_xml}{cabecera}\n{cuerpo}\n{pie}"


def parsear_xml_lotes(xml_concatenado: str) -> ResultadoEscaneo:
    """Parsea el XML guardado por NetAudit, que puede contener varios lotes.

    Acepta las tres formas posibles:
      * un unico <nmaprun> (escaneo de un solo lote),
      * varios <nmaprun> sueltos (formato antiguo),
      * <netaudit_lotes> con un <nmaprun> por lote.
    """
    if not xml_concatenado or not xml_concatenado.strip():
        raise ErrorDeEscaneo("El XML de lotes esta vacio.")

    # Se envuelve en un contenedor para poder tratar uniformemente todos los
    # casos, quitando antes la posible declaracion XML.
    cuerpo = re.sub(r"^\s*<\?xml[^>]*\?>\s*", "", xml_concatenado.strip())
    cuerpo = re.sub(r"<\?xml-stylesheet[^>]*\?>", "", cuerpo)

    try:
        raiz = ET.fromstring(f"<netaudit>{cuerpo}</netaudit>")
    except ET.ParseError as exc:
        # Si el documento parece truncado (nmap interrumpido), se delega en
        # parsear_xml_nmap, que sabe explicar ese caso concreto.
        if not xml_concatenado.rstrip().endswith("</nmaprun>"):
            return parsear_xml_nmap(xml_concatenado)
        raise ErrorDeEscaneo(
            f"El XML de lotes no es valido: {exc}\n"
            "  Revisa el fichero: debe contener un unico <nmaprun> o un "
            "<netaudit_lotes> con varios."
        ) from exc

    if raiz.tag == "nmaprun":
        # Documento normal de nmap.
        combined = ET.Element("nmaprun")
        for hijo in list(raiz):
            combined.append(hijo)
        return parsear_xml_nmap(ET.tostring(combined, encoding="unicode"))

    # Descendientes a cualquier nivel: los lotes pueden estar sueltos o anidados
    # dentro de <netaudit_lotes>.
    lotes = list(raiz.iter("nmaprun"))
    if not lotes:
        raise ErrorDeEscaneo(
            "El XML no contiene ningun elemento <nmaprun> de nmap."
        )

    combined = ET.Element("nmaprun")
    for lote in lotes:
        for hijo in list(lote):
            # Los runstats de cada lote se conservan solo del ultimo: son
            # globales y duplicarlos daria tiempos contradictorios.
            if hijo.tag == "runstats":
                continue
            combined.append(hijo)
    runstats = lotes[-1].find("runstats")
    if runstats is not None:
        for hijo in list(runstats):
            combined.append(hijo)

    return parsear_xml_nmap(ET.tostring(combined, encoding="unicode"))
