"""Interfaz de linea de comandos de NetAudit: menu interactivo + argparse.

Codigos de salida:
  0  escaneo correcto sin hallazgos
  1  escaneo correcto con hallazgos
  2  error de uso o dependencia obligatoria ausente (nmap)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, Sequence, Tuple

from . import __version__
from .attack import construir_informe_attack
from .osdetect import (
    CODIGO_SIN_DEPENDENCIA,
    NmapNoDisponible,
    SO_LINUX,
    SO_MACOS,
    SO_WINDOWS,
    aviso_privilegios_sudo,
    buscar_nmap,
    comprobar_dependencia_nmap,
    mostrar_instrucciones_instalacion,
    mostrar_menu_so,
    obtener_info_sistema,
    resumen_entorno,
)
from .report import guardar_reporte, guardar_xml_crudo
from .scanner import (
    CODIGO_ERROR_EJECUCION,
    PERFIL_COMPLETO,
    PERFIL_DESCUBRIMIENTO,
    PERFIL_PUERTOS,
    PERFIL_WEB,
    PERFILES,
    VELOCIDADES,
    ErrorDeEscaneo,
    ResultadoEscaneo,
    ejecutar_escaneo,
)
from .targets import (
    LIMITE_HOSTS_POR_DEFECTO,
    ObjetivoInvalido,
    construir_exclusiones,
    construir_objetivos,
    filtrar_excluidos,
    total_hosts,
)
from .utils import (
    CONFIRMACION_AUTORIZACION,
    CONFIRMACION_SEGURO,
    Consola,
    configurar_logging,
    escribir_archivo_texto,
    forzar_utf8,
    leer_linea,
    obtener_logger,
    pedir_confirmacion,
)
from .vulns import calcular_resumen, evaluar

LOG = obtener_logger("cli")

CODIGO_OK = 0
CODIGO_HALLAZGOS = 1

BASE_REPORTES = "reportes"
DIRECTORIO_LOG = "logs"

# Mapa: opcion de menu -> perfil de escaneo.
# 'Escaneo rapido' usa el perfil 'puertos' (-sT -sV --top-ports 1000): rapido y
# util. El perfil 'discovery' (-sn) queda disponible desde --profile para acotar
# primero que hosts estan vivos.
MENU_PERFILES = {
    "1": PERFIL_PUERTOS,
    "2": PERFIL_COMPLETO,
    "3": PERFIL_WEB,
}

DESCRIPCION_ATAJOS = {
    "1": ("Escaneo rapido", "TCP connect scan con deteccion de versiones en los 1000 puertos mas comunes (perfil 'puertos')."),
    "2": ("Escaneo completo", "Servicios, scripts NSE por defecto y deteccion de SO (perfil 'completo')."),
    "3": ("Servidor web", "Solo puertos web, con scripts http-* (perfil 'web')."),
    "4": ("Puerto especifico", "Escanea los puertos que indiques, sin perfil previo."),
    "5": ("Informe de un escaneo previo", "Genera el informe a partir de un XML de nmap existente."),
    "6": ("Configuracion", "Guarda, carga y borra perfiles de escaneo."),
    "0": ("Salir", "Termina NetAudit."),
}


# --------------------------------------------------------------------------
# Perfiles de configuracion guardados
# --------------------------------------------------------------------------

ARCHIVO_PERFILES = os.path.join("config", "perfiles.json")


def cargar_perfiles() -> dict:
    """Carga los perfiles guardados en config/perfiles.json.

    Devuelve un diccionario vacio si no existen o estan corruptos: un fallo de
    configuracion no debe impedir escanear.
    """
    if not os.path.isfile(ARCHIVO_PERFILES):
        return {}
    try:
        with open(ARCHIVO_PERFILES, "r", encoding="utf-8") as manejador:
            datos = json.load(manejador)
        return datos if isinstance(datos, dict) else {}
    except (OSError, json.JSONDecodeError) as exc:
        LOG.warning("No se pudieron cargar los perfiles: %s", exc)
        return {}


def guardar_perfiles(perfiles: dict) -> None:
    """Guarda los perfiles en config/perfiles.json."""
    escribir_archivo_texto(ARCHIVO_PERFILES, json.dumps(perfiles, ensure_ascii=False, indent=2))


# --------------------------------------------------------------------------
# Flujo interactivo comun
# --------------------------------------------------------------------------


def confirmar_autorizacion(consola: Consola, objetivo_texto: str) -> bool:
    """Confirmacion interactiva obligatoria: escribir AUTORIZADO + el objetivo."""
    consola.titulo("Confirmacion de autorizacion (obligatoria)")
    consola.escribir("NetAudit solo puede usarse sobre redes con autorizacion escrita.")
    consola.escribir("Declara el objetivo exacto sobre el que tienes autorizacion:")
    consola.escribir("")
    consola.escribir(f"    Objetivo indicado: {objetivo_texto}")
    return pedir_confirmacion(
        "Confirma que tienes autorizacion escrita para escanear ese objetivo.",
        CONFIRMACION_AUTORIZACION,
        consola,
    )


def confirmar_rango_sensible(consola: Consola, motivos: Sequence[str], objetivo_texto: str) -> bool:
    """Segunda confirmacion para rangos sensibles (0.0.0.0/0, publicos, etc.)."""
    consola.titulo("Confirmacion adicional: objetivo de alcance SENSIBLE")
    consola.aviso(f"El objetivo {objetivo_texto} cae en rangos sensibles:")
    for motivo in motivos:
        consola.escribir(f"    - {motivo}")
    consola.escribir("")
    consola.aviso("Un escaneo sobre redes publicas o de produccion puede generar ruido,")
    consola.aviso("avisos legales y, en el caso de 0.0.0.0/0, impacto real sobre terceros.")
    return pedir_confirmacion(
        "Revisa los motivos anteriores.",
        CONFIRMACION_SEGURO,
        consola,
    )


def preguntar_velocidad(consola: Consola, por_defecto: str = "T4") -> str:
    """El menu pregunta SIEMPRE la velocidad."""
    consola.seccion("Velocidad de escaneo (nmap -T)")
    for clave, descripcion in VELOCIDADES.items():
        marca = " (por defecto)" if clave == por_defecto else ""
        consola.escribir(f"  [{clave}] {descripcion}{marca}")
    while True:
        respuesta = leer_linea(f"  Velocidad [{por_defecto}]: ").strip().upper()
        if not respuesta:
            return por_defecto
        respuesta = respuesta.replace("-", "").replace("T", "T")
        if respuesta in VELOCIDADES:
            return respuesta
        consola.error("Velocidad no valida. Usa T2, T3, T4 o T5.")


def preguntar_perfil(consola: Consola, por_defecto: str = PERFIL_PUERTOS) -> str:
    """Muestra los perfiles con sus flags de nmap y devuelve el elegido."""
    consola.seccion("Perfil de escaneo")
    claves = list(PERFILES.keys())
    for indice, clave in enumerate(claves, start=1):
        perfil = PERFILES[clave]
        marca = " (por defecto)" if clave == por_defecto else ""
        consola.escribir(f"  [{indice}] {perfil.titulo}{marca}")
        consola.escribir(f"      {perfil.descripcion}")
        consola.escribir(f"      nmap {' '.join(perfil.flags_base)}")
    while True:
        respuesta = leer_linea(f"  Perfil [1-{len(claves)}, por defecto {por_defecto}]: ").strip()
        if not respuesta:
            return por_defecto
        if respuesta.isdigit() and 1 <= int(respuesta) <= len(claves):
            return claves[int(respuesta) - 1]
        if respuesta in PERFILES:
            return respuesta
        consola.error("Opcion no valida.")


def preguntar_puerto_especifico(consola: Consola) -> Optional[str]:
    """Pide una lista de puertos o rangos (22,80,443,8000-8100)."""
    while True:
        respuesta = leer_linea("  Puertos (ej. 22,80,443,8000-8100): ").strip()
        if not respuesta:
            consola.error("Debes indicar al menos un puerto.")
            continue
        partes = [p.strip() for p in respuesta.split(",") if p.strip()]
        validas = []
        for parte in partes:
            if "-" in parte:
                inicio, _, fin = parte.partition("-")
                if inicio.isdigit() and fin.isdigit() and 0 < int(inicio) <= int(fin) <= 65535:
                    validas.append(f"{int(inicio)}-{int(fin)}")
                    continue
            elif parte.isdigit() and 0 < int(parte) <= 65535:
                validas.append(str(int(parte)))
                continue
            consola.error(f"Puerto no valido: {parte!r}")
            break
        else:
            return ",".join(validas)


def preguntar_objetivos(consola: Consola) -> Tuple[str, Optional[str]]:
    """Pide el objetivo. Devuelve (texto, archivo_opcional)."""
    consola.seccion("Objetivo del escaneo")
    consola.escribir("  Formatos: 192.168.1.10 | 192.168.1.0/24 | 192.168.1.1-50 | host.example.com")
    respuesta = leer_linea("  Objetivo (o 'a,b,c' para varios): ").strip()
    archivo = None
    if respuesta.casefold().endswith(".txt"):
        archivo = respuesta
    return respuesta, archivo


def preguntar_exclusiones(consola: Consola) -> List[str]:
    """Pide las IPs o CIDR a excluir del escaneo."""
    consola.seccion("Exclusiones (opcional, IPs o CIDR separados por comas)")
    return [p.strip() for p in leer_linea("  Excluir (vacio = ninguna): ").split(",") if p.strip()]


def preguntar_usar_ss(consola: Consola, clave_so: str) -> bool:
    """Pregunta si usar SYN scan (-sS). Solo tiene sentido con privilegios."""
    info = obtener_info_sistema(clave_so)
    if info.clave_so not in (SO_LINUX, SO_MACOS):
        consola.info("En Windows se usa TCP connect scan (-sT). -sS requiere Npcap con modo RAW.")
    if not info.requiere_sudo_para_syn:
        return False
    respuesta = leer_linea("  Usar SYN scan (-sS, requiere privilegios root)? [s/N]: ").strip().casefold()
    usar = respuesta in ("s", "si", "y", "yes")
    if usar:
        aviso_privilegios_sudo(consola, usar_ss=True)
    return usar


def confirmar_ejecucion(
    consola: Consola,
    objetivos_texto: str,
    objetivos,
    perfil: Optional[str],
    velocidad: str,
    usar_ss: bool,
    puertos: Optional[str],
    exclusiones: Sequence[str],
    limite_hosts: int,
) -> bool:
    """Muestra el resumen del escaneo y pide la ultima confirmacion."""
    consola.titulo("Resumen del escaneo")
    consola.escribir(f"  Objetivo(s)      : {objetivos_texto}")
    consola.escribir(f"  Host(s) estimado : {total_hosts(objetivos)} (limite {limite_hosts})")
    if perfil:
        consola.escribir(f"  Perfil           : {perfil}")
    if puertos:
        consola.escribir(f"  Puertos          : {puertos}")
    consola.escribir(f"  Velocidad        : -{velocidad}")
    consola.escribir(f"  Tipo de escaneo  : {'-sS (SYN)' if usar_ss else '-sT (TCP connect)'}")
    if exclusiones:
        consola.escribir(f"  Exclusiones      : {', '.join(exclusiones)}")
    consola.escribir("")
    return pedir_confirmacion(
        "Ejecutar el escaneo con estos parametros?",
        CONFIRMACION_AUTORIZACION,
        consola,
    )


# --------------------------------------------------------------------------
# Ejecucion del escaneo
# --------------------------------------------------------------------------


def ejecutar_flujo_escaneo(
    consola: Consola,
    objetivos_texto: str,
    archivo: Optional[str],
    perfil: str,
    velocidad: str,
    usar_ss: bool = False,
    puertos: Optional[str] = None,
    exclusiones: Optional[Sequence[str]] = None,
    limite_hosts: int = LIMITE_HOSTS_POR_DEFECTO,
    hosts_por_lote: int = 256,
    host_timeout: Optional[str] = None,
    timeout_global: int = 7200,
    formato: Optional[str] = None,
    clave_so: Optional[str] = None,
    no_guardar: bool = False,
) -> int:
    """Ejecuta el escaneo completo con todas las validaciones. Devuelve el codigo de salida."""
    clave = clave_so or obtener_info_sistema().clave_so

    # 1) nmap es obligatorio: se resuelve en cada invocacion (nunca cacheado).
    try:
        info_nmap = comprobar_dependencia_nmap(consola, clave)
    except NmapNoDisponible as exc:
        consola.critico(str(exc))
        if exc.detalles:
            consola.error(exc.detalles)
        return CODIGO_SIN_DEPENDENCIA

    # 2) Validacion de objetivos.
    try:
        objetivos_validos, errores = construir_objetivos(
            [objetivos_texto] if objetivos_texto else [], archivo, limite_hosts
        )
    except ObjetivoInvalido as exc:
        consola.error(str(exc))
        return CODIGO_ERROR_EJECUCION

    if errores:
        consola.seccion("Objetivos rechazados")
        for error in errores:
            consola.error(error)

    if not objetivos_validos:
        consola.error("No hay objetivos validos. Corrige la entrada y vuelve a intentarlo.")
        return CODIGO_ERROR_EJECUCION

    # 3) Exclusiones.
    exclusiones_texto, redes_exclusion, errores_excl = construir_exclusiones(exclusiones or [])
    for error in errores_excl:
        consola.error(f"Exclusion ignorada: {error}")
    objetivos_validos, objetivos_excluidos = filtrar_excluidos(objetivos_validos, redes_exclusion)
    if objetivos_excluidos:
        consola.aviso(
            "Excluidos por --exclude: "
            + ", ".join(o.valor_normalizado for o in objetivos_excluidos)
        )
    if not objetivos_validos:
        consola.error("Todos los objetivos quedaron excluidos. No hay nada que escanear.")
        return CODIGO_ERROR_EJECUCION

    # 4) Confirmacion de autorizacion (obligatoria).
    if not confirmar_autorizacion(consola, objetivos_texto or (archivo or "")):
        return CODIGO_ERROR_EJECUCION

    # 5) Segunda confirmacion para rangos sensibles.
    for objetivo in objetivos_validos:
        if objetivo.sensible:
            if not confirmar_rango_sensible(
                consola, objetivo.motivos_sensibilidad, objetivo.valor_normalizado
            ):
                return CODIGO_ERROR_EJECUCION

    # 6) Confirmacion final con parametros.
    if not confirmar_ejecucion(
        consola,
        objetivos_texto or (archivo or ""),
        objetivos_validos,
        perfil,
        velocidad,
        usar_ss,
        puertos,
        exclusiones_texto,
        limite_hosts,
    ):
        return CODIGO_ERROR_EJECUCION

    # 7) Escaneo.
    consola.seccion("Ejecutando nmap")
    try:
        resultado = ejecutar_escaneo(
            info_nmap=info_nmap,
            objetivos=objetivos_validos,
            perfil=perfil,
            velocidad=velocidad,
            usar_ss=usar_ss,
            puertos=puertos,
            exclusiones=exclusiones_texto,
            host_timeout=host_timeout,
            limite_hosts=limite_hosts,
            hosts_por_lote=hosts_por_lote,
            timeout_global=timeout_global,
            consola=consola,
        )
    except ErrorDeEscaneo as exc:
        consola.critico("El escaneo fallo. No se genera reporte para evitar datos falsos.")
        consola.error(str(exc))
        # Si hay XML parcial lo conservamos para auditoria.
        return CODIGO_ERROR_EJECUCION

    # 8) Analisis y reporte.
    return finalizar_escaneo(consola, resultado, formato, no_guardar)


def finalizar_escaneo(
    consola: Consola,
    resultado: ResultadoEscaneo,
    formato: Optional[str],
    no_guardar: bool,
) -> int:
    """Analiza, genera el reporte y devuelve el codigo de salida."""
    hallazgos = evaluar(resultado)
    resumen = calcular_resumen(hallazgos)

    if formato == "json":
        from .report import construir_json

        datos = construir_json(resultado, hallazgos, resumen)
        sys.stdout.write(json.dumps(datos, ensure_ascii=False, indent=2))
        sys.stdout.write("\n")
        return CODIGO_HALLAZGOS if hallazgos else CODIGO_OK

    mostrar_resumen_consola(consola, resultado, hallazgos, resumen)

    if no_guardar:
        consola.info("Reporte no guardado (opcion --sin-reporte).")
        return CODIGO_HALLAZGOS if hallazgos else CODIGO_OK

    try:
        generado = guardar_reporte(resultado, hallazgos, BASE_REPORTES)
    except OSError as exc:
        consola.error(f"No se pudo escribir el reporte en disco: {exc}")
        return CODIGO_ERROR_EJECUCION

    consola.seccion("Reporte generado")
    consola.ok(f"HTML : {generado.ruta_html}")
    consola.ok(f"JSON : {generado.ruta_json}")
    if generado.ruta_xml:
        consola.ok(f"XML  : {generado.ruta_xml} (auditoria)")
    consola.escribir(f"  Abre el HTML en tu navegador: file:///{generado.ruta_html.replace(os.sep, '/')}")

    return CODIGO_HALLAZGOS if hallazgos else CODIGO_OK


def mostrar_resumen_consola(consola: Consola, resultado: ResultadoEscaneo, hallazgos, resumen) -> None:
    """Muestra en consola el resumen y los 10 hallazgos mas graves."""
    consola.titulo("Resumen de resultados")
    consola.escribir(f"  Hosts activos     : {len(resultado.hosts_activos)} / {len(resultado.hosts)}")
    consola.escribir(f"  Puertos abiertos  : {resultado.total_puertos_abiertos}")
    consola.escribir(f"  Hallazgos         : {resumen.total} (score {resumen.score}/100)")
    for nivel, cantidad in resumen.por_severidad.items():
        if cantidad:
            consola.escribir(f"      {nivel:<8} {cantidad}")
    if hallazgos:
        consola.seccion("Top 10 hallazgos")
        for hallazgo in hallazgos[:10]:
            consola.escribir(
                f"  [{hallazgo.severidad:<7}] {hallazgo.host}:{hallazgo.puerto} - {hallazgo.titulo}"
            )


# --------------------------------------------------------------------------
# Menu principal
# --------------------------------------------------------------------------


def mostrar_menu_principal(consola: Consola) -> str:
    """Muestra el menu principal y devuelve la opcion elegida."""
    consola.titulo("NetAudit - auditoria de red defensiva")
    for clave in ("1", "2", "3", "4", "5", "6", "0"):
        titulo, descripcion = DESCRIPCION_ATAJOS[clave]
        consola.escribir(f"  [{clave}] {titulo:<30} {descripcion}")
    consola.escribir("")
    return leer_linea("  Opcion [1-6, 0]: ").strip()


def bucle_interactivo(consola: Consola) -> int:
    """Menu interactivo principal.

    Devuelve el codigo de salida del ULTIMO escaneo realizado, de modo que el
    menu tambien sea utilizable desde scripts y CI (0 sin hallazgos,
    1 con hallazgos, 2 error).
    """
    clave_so = mostrar_menu_so(consola) or obtener_info_sistema().clave_so
    ultimo_codigo = CODIGO_OK

    while True:
        opcion = mostrar_menu_principal(consola)

        if opcion == "0":
            consola.info("Saliendo de NetAudit.")
            return ultimo_codigo

        if opcion in MENU_PERFILES:
            ultimo_codigo = ejecutar_opcion_escaneo(consola, MENU_PERFILES[opcion], clave_so)

        elif opcion == "4":
            ultimo_codigo = ejecutar_opcion_puerto(consola, clave_so)

        elif opcion == "5":
            ultimo_codigo = ejecutar_opcion_informe_previo(consola)

        elif opcion == "6":
            ejecutar_opcion_configuracion(consola)

        else:
            consola.error("Opcion no valida. Elige un numero entre 0 y 6.")
            consola.escribir("")


def ejecutar_opcion_escaneo(consola: Consola, perfil: str, clave_so: str) -> int:
    """Opcion 1-3 del menu: pregunta objetivo, velocidad y lanza el escaneo."""
    objetivos_texto, archivo = preguntar_objetivos(consola)
    if not objetivos_texto:
        consola.error("No se indico objetivo. Operacion cancelada.")
        return CODIGO_ERROR_EJECUCION
    velocidad = preguntar_velocidad(consola)
    usar_ss = preguntar_usar_ss(consola, clave_so)
    exclusiones = preguntar_exclusiones(consola)
    return ejecutar_flujo_escaneo(
        consola, objetivos_texto, archivo, perfil, velocidad, usar_ss,
        exclusiones=exclusiones, clave_so=clave_so,
    )


def ejecutar_opcion_puerto(consola: Consola, clave_so: str) -> int:
    """Opcion 4 del menu: escanea una lista de puertos indicada por el usuario."""
    objetivos_texto, archivo = preguntar_objetivos(consola)
    if not objetivos_texto:
        consola.error("No se indico objetivo. Operacion cancelada.")
        return CODIGO_ERROR_EJECUCION
    puertos = preguntar_puerto_especifico(consola)
    if not puertos:
        return CODIGO_ERROR_EJECUCION
    velocidad = preguntar_velocidad(consola)
    usar_ss = preguntar_usar_ss(consola, clave_so)
    exclusiones = preguntar_exclusiones(consola)
    # Con -p explicito se usa el perfil 'puertos' y se anaden los puertos del
    # usuario, que reemplazan a los del perfil.
    return ejecutar_flujo_escaneo(
        consola, objetivos_texto, archivo, PERFIL_PUERTOS, velocidad, usar_ss,
        puertos=puertos, exclusiones=exclusiones, clave_so=clave_so,
    )


def ejecutar_opcion_informe_previo(consola: Consola) -> int:
    """Genera el informe a partir de un XML de nmap ya existente."""
    consola.seccion("Informe de un escaneo previo")
    consola.info("Indica la ruta de un XML generado con 'nmap -oX'.")
    ruta = leer_linea("  Ruta del XML: ").strip().strip('"')
    if not ruta:
        consola.error("No se indico ruta. Operacion cancelada.")
        return CODIGO_ERROR_EJECUCION
    if not os.path.isfile(ruta):
        consola.error(f"No existe el archivo: {ruta}")
        return CODIGO_ERROR_EJECUCION

    from .scanner import ErrorDeEscaneo as _Error, parsear_xml_lotes

    with open(ruta, "r", encoding="utf-8", errors="replace") as manejador:
        xml = manejador.read()

    try:
        resultado = parsear_xml_lotes(xml)
    except _Error as exc:
        consola.critico("El XML no se pudo interpretar:")
        consola.error(str(exc))
        return CODIGO_ERROR_EJECUCION

    resultado.xml_crudo = xml
    resultado.nmap_version = "XML externo (no verificada)"
    resultado.perfil = "escaneo previo"
    consola.ok(f"XML valido: {len(resultado.hosts)} host(es), "
               f"{sum(len(h.puertos_abiertos) for h in resultado.hosts)} puerto(s) abierto(s).")
    return finalizar_escaneo(consola, resultado, None, False)


def ejecutar_opcion_configuracion(consola: Consola) -> None:
    """Guarda, carga y borra perfiles de escaneo."""
    perfiles = cargar_perfiles()
    while True:
        consola.seccion("Configuracion - perfiles guardados")
        if perfiles:
            for nombre, datos in perfiles.items():
                consola.escribir(
                    f"  - {nombre}: perfil={datos.get('perfil')} velocidad={datos.get('velocidad')} "
                    f"objetivo={datos.get('objetivo')}"
                )
        else:
            consola.info("No hay perfiles guardados.")
        consola.escribir("  [1] Guardar perfil actual")
        consola.escribir("  [2] Cargar y ejecutar un perfil")
        consola.escribir("  [3] Borrar un perfil")
        consola.escribir("  [0] Volver")
        opcion = leer_linea("  Opcion: ").strip()

        if opcion == "0":
            return
        if opcion == "1":
            nombre = leer_linea("  Nombre del perfil: ").strip()
            if not nombre:
                consola.error("Nombre vacio.")
                continue
            objetivos_texto, archivo = preguntar_objetivos(consola)
            perfil = preguntar_perfil(consola)
            velocidad = preguntar_velocidad(consola)
            perfiles[nombre] = {
                "objetivo": objetivos_texto,
                "archivo": archivo,
                "perfil": perfil,
                "velocidad": velocidad,
            }
            try:
                guardar_perfiles(perfiles)
            except OSError as exc:
                consola.error(f"No se pudo guardar la configuracion: {exc}")
            else:
                consola.ok(f"Perfil '{nombre}' guardado en {ARCHIVO_PERFILES}")
        elif opcion == "2":
            if not perfiles:
                consola.error("No hay perfiles que cargar.")
                continue
            nombre = leer_linea("  Nombre del perfil: ").strip()
            datos = perfiles.get(nombre)
            if not datos:
                consola.error(f"No existe el perfil '{nombre}'.")
                continue
            consola.ok(f"Perfil '{nombre}' cargado: {datos}")
            ejecutar_flujo_escaneo(
                consola,
                datos.get("objetivo", ""),
                datos.get("archivo"),
                datos.get("perfil", PERFIL_PUERTOS),
                datos.get("velocidad", "T4"),
                clave_so=obtener_info_sistema().clave_so,
            )
        elif opcion == "3":
            nombre = leer_linea("  Nombre del perfil a borrar: ").strip()
            if nombre in perfiles:
                del perfiles[nombre]
                guardar_perfiles(perfiles)
                consola.ok(f"Perfil '{nombre}' borrado.")
            else:
                consola.error(f"No existe el perfil '{nombre}'.")
        else:
            consola.error("Opcion no valida.")


# --------------------------------------------------------------------------
# Modo no interactivo (argparse)
# --------------------------------------------------------------------------


def construir_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos de la CLI."""
    parser = argparse.ArgumentParser(
        prog="python -m netscan.cli",
        description=(
            "NetAudit: auditoria de red defensiva con nmap. "
            "Solo para redes con autorizacion escrita. No explota vulnerabilidades."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python -m netscan.cli scan --target 192.168.1.0/24 --profile web --format json\n"
            "  python -m netscan.cli scan --target 192.168.1.10 -p 22,80,443\n"
            "  python -m netscan.cli informe --xml salida_nmap.xml\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"NetAudit {__version__}")

    sub = parser.add_subparsers(dest="comando", metavar="{scan,informe,menu}")

    escaneo = sub.add_parser("scan", help="Escaneo no interactivo (un solo objetivo a la vez).")
    escaneo.add_argument("--target", required=True, help="Objetivo: IP, CIDR, rango, hostname o lista.")
    escaneo.add_argument("--target-file", dest="target_file", help="Archivo .txt con objetivos.")
    escaneo.add_argument(
        "--profile",
        choices=sorted(PERFILES.keys()),
        default=PERFIL_PUERTOS,
        help=f"Perfil de escaneo (por defecto: {PERFIL_PUERTOS}).",
    )
    escaneo.add_argument("-p", "--puerto", dest="puertos", help="Puertos: 22,80,443,8000-8100.")
    escaneo.add_argument(
        "-T", "--velocidad", dest="velocidad", default="T4",
        choices=sorted(VELOCIDADES.keys()), help="Velocidad nmap (por defecto: T4).",
    )
    escaneo.add_argument("--ss", action="store_true", help="Usar SYN scan (-sS). Requiere privilegios.")
    escaneo.add_argument("--exclude", action="append", default=[], help="Excluir IP o CIDR (repetible).")
    escaneo.add_argument("--limite-hosts", type=int, default=LIMITE_HOSTS_POR_DEFECTO,
                         help=f"Limite de hosts por objetivo (por defecto {LIMITE_HOSTS_POR_DEFECTO}).")
    escaneo.add_argument("--hosts-por-lote", type=int, default=256, help="Hosts por lote de escaneo.")
    escaneo.add_argument("--host-timeout", help="Timeout por host (ej. 30s, 2m).")
    escaneo.add_argument("--timeout", type=int, default=7200, help="Timeout global en segundos.")
    escaneo.add_argument("--format", choices=("html", "json"), default="html",
                         help="Formato de salida. 'json' imprime el JSON por stdout.")
    escaneo.add_argument("--sin-reporte", action="store_true", help="No escribir ficheros en disco.")
    escaneo.add_argument("--autorizado", action="store_true",
                         help="Salta la confirmacion interactiva. Implica autorizacion escrita.")

    informe = sub.add_parser("informe", help="Genera el informe a partir de un XML de nmap existente.")
    informe.add_argument("--xml", required=True, help="Ruta del XML generado con 'nmap -oX'.")

    sub.add_parser("menu", help="Menu interactivo (opcion por defecto).")
    return parser


def ejecutar_scan_no_interactivo(args: argparse.Namespace, consola: Consola) -> int:
    """Flujo no interactivo. La autorizacion se declara con --autorizado."""
    if not args.autorizado:
        consola.titulo("Confirmacion de autorizacion obligatoria")
        consola.error(
            "El modo no interactivo exige declarar la autorizacion por escrito.\n"
            "  Vuelve a ejecutar anadiendo --autorizado, que confirma que tienes\n"
            "  permiso escrito para escanear el objetivo indicado."
        )
        consola.aviso(f"Objetivo solicitado: {args.target}")
        return CODIGO_ERROR_EJECUCION

    clave_so = obtener_info_sistema().clave_so
    try:
        info_nmap = comprobar_dependencia_nmap(consola, clave_so)
    except NmapNoDisponible as exc:
        consola.critico(str(exc))
        if exc.detalles:
            consola.error(exc.detalles)
        return CODIGO_SIN_DEPENDENCIA

    try:
        objetivos, errores = construir_objetivos(
            [args.target], args.target_file, args.limite_hosts
        )
    except ObjetivoInvalido as exc:
        consola.error(str(exc))
        return CODIGO_ERROR_EJECUCION
    for error in errores:
        consola.error(error)
    if not objetivos:
        consola.error("No hay objetivos validos.")
        return CODIGO_ERROR_EJECUCION

    exclusiones_texto, redes_exclusion, errores_excl = construir_exclusiones(args.exclude)
    for error in errores_excl:
        consola.error(f"Exclusion ignorada: {error}")
    objetivos, excluidos = filtrar_excluidos(objetivos, redes_exclusion)
    if excluidos:
        consola.aviso("Excluidos: " + ", ".join(o.valor_normalizado for o in excluidos))
    if not objetivos:
        consola.error("Todos los objetivos quedaron excluidos.")
        return CODIGO_ERROR_EJECUCION

    for objetivo in objetivos:
        if objetivo.sensible:
            consola.titulo("Objetivo SENSIBLE detectado")
            consola.aviso(f"{objetivo.valor_normalizado}: {', '.join(objetivo.motivos_sensibilidad)}")
            if not args.autorizado:
                consola.error("Se requiere autorizacion explicita (--autorizado).")
                return CODIGO_ERROR_EJECUCION

    consola.titulo("NetAudit - escaneo no interactivo")
    for linea in resumen_entorno(clave_so):
        consola.escribir(f"  {linea}")
    consola.escribir(f"  Objetivo : {args.target}")
    consola.escribir(f"  Perfil   : {args.profile}   Velocidad: -{args.velocidad}")
    if args.puertos:
        consola.escribir(f"  Puertos  : {args.puertos}")
    if args.ss:
        aviso_privilegios_sudo(consola, usar_ss=True)

    try:
        resultado = ejecutar_escaneo(
            info_nmap=info_nmap,
            objetivos=objetivos,
            perfil=args.profile,
            velocidad=args.velocidad,
            usar_ss=args.ss,
            puertos=args.puertos,
            exclusiones=exclusiones_texto,
            host_timeout=args.host_timeout,
            limite_hosts=args.limite_hosts,
            hosts_por_lote=args.hosts_por_lote,
            timeout_global=args.timeout,
            consola=consola,
        )
    except ErrorDeEscaneo as exc:
        consola.critico("El escaneo fallo. No se genera reporte para evitar datos falsos.")
        consola.error(str(exc))
        return CODIGO_ERROR_EJECUCION

    return finalizar_escaneo(consola, resultado, args.format, args.sin_reporte)


def ejecutar_informe_no_interactivo(args: argparse.Namespace, consola: Consola) -> int:
    """Subcomando 'informe': genera el informe desde un XML de nmap existente."""
    from .scanner import ErrorDeEscaneo as _Error, parsear_xml_lotes

    if not os.path.isfile(args.xml):
        consola.error(f"No existe el archivo XML: {args.xml}")
        return CODIGO_ERROR_EJECUCION
    with open(args.xml, "r", encoding="utf-8", errors="replace") as manejador:
        xml = manejador.read()
    try:
        resultado = parsear_xml_lotes(xml)
    except _Error as exc:
        consola.critico("El XML no se pudo interpretar:")
        consola.error(str(exc))
        return CODIGO_ERROR_EJECUCION
    resultado.xml_crudo = xml
    resultado.nmap_version = "XML externo (no verificada)"
    resultado.perfil = "escaneo previo"
    return finalizar_escaneo(consola, resultado, None, False)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Punto de entrada. Devuelve el codigo de salida."""
    parser = construir_parser()
    args = parser.parse_args(argv)

    # Con --format json, stdout queda reservado al JSON: toda la informacion
    # de progreso se desvía a stderr. Ademas se fuerza UTF-8 para que el JSON
    # sea valido aunque se redirja a un fichero en Windows (cp1252).
    if getattr(args, "comando", None) == "scan" and getattr(args, "format", None) == "json":
        consola = Consola().a_stderr()
        if not forzar_utf8(sys.stdout):
            LOG.warning(
                "No se pudo forzar UTF-8 en stdout; el JSON se escribira con la "
                "codificacion local y puede contener caracteres alterados."
            )
    else:
        consola = Consola()

    configurar_logging(DIRECTORIO_LOG)

    # Sin subcomando: menu interactivo.
    if not getattr(args, "comando", None):
        try:
            return bucle_interactivo(consola)
        except KeyboardInterrupt:
            consola.escribir("")
            consola.info("Interrumpido por el usuario.")
            return CODIGO_ERROR_EJECUCION

    try:
        if args.comando == "scan":
            return ejecutar_scan_no_interactivo(args, consola)
        if args.comando == "informe":
            return ejecutar_informe_no_interactivo(args, consola)
        if args.comando == "menu":
            return bucle_interactivo(consola)
    except KeyboardInterrupt:
        consola.escribir("")
        consola.aviso("Escaneo interrumpido por el usuario. No se genera reporte parcial.")
        return CODIGO_ERROR_EJECUCION
    except Exception as exc:  # nunca mostrar traceback crudo
        LOG.exception("Error no controlado en NetAudit")
        consola.critico("Se produjo un error inesperado:")
        consola.error(str(exc))
        consola.aviso("El detalle tecnico completo esta en el archivo de log.")
        return CODIGO_ERROR_EJECUCION

    parser.print_help()
    return CODIGO_ERROR_EJECUCION


if __name__ == "__main__":
    sys.exit(main())
