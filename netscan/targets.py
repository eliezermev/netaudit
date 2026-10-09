"""Validacion y normalizacion de objetivos de escaneo.

Formatos aceptados:
  * IP unica            192.168.1.10
  * CIDR                192.168.1.0/24
  * Rango               192.168.1.1-50   /   192.168.1.10-192.168.1.50
  * Dominio / hostname  ejemplo.com, host.lan
  * Archivo .txt        -f objetivos.txt (una linea por objetivo)

No se ejecuta nada aqui: solo se valida y normaliza.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from .utils import obtener_logger

LOG = obtener_logger("targets")

LIMITE_HOSTS_POR_DEFECTO = 1024
MAX_LINES_ARCHIVO = 10000
MAX_LONGITUD_HOSTNAME = 253
MAX_LONGITUD_ETIQUETA = 63

_RE_HOSTNAME = re.compile(
    r"^(?=.{1," + str(MAX_LONGITUD_HOSTNAME) + r"}$)"
    r"([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_RE_RANGO = re.compile(r"^(?P<a>\d{1,3}(?:\.\d{1,3}){3})-(?P<b>\d{1,3}(?:\.\d{1,3}){3}|\d{1,5})$")
_RE_COMENTARIO = re.compile(r"^\s*#")
# Forma de IPv4 (para distinguir un tecleo de IP de un hostname legitimo).
_RE_CUADRUPLO = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# Forma de IPv4 con grupos de mas de 3 digitos o con exceso de octetos.
_RE_CUADRUPLO_EXTRA = re.compile(r"^\d+(?:\.\d+){3,}$")

TIPO_IP = "ip"
TIPO_CIDR = "cidr"
TIPO_RANGO = "rango"
TIPO_HOSTNAME = "hostname"


class ObjetivoInvalido(ValueError):
    """El objetivo no cumple el formato esperado."""


@dataclass(frozen=True)
class Objetivo:
    """Un objetivo ya validado y normalizado."""

    tipo: str
    valor: str            # tal cual se paso a nmap
    valor_normalizado: str
    hosts_aproximados: int
    sensible: bool = False
    motivos_sensibilidad: Tuple[str, ...] = field(default_factory=tuple)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.tipo}:{self.valor_normalizado}"

    def a_dict(self) -> dict:
        """Representacion para el reporte JSON."""
        return {
            "tipo": self.tipo,
            "valor": self.valor,
            "valor_normalizado": self.valor_normalizado,
            "hosts_aproximados": self.hosts_aproximados,
            "sensible": self.sensible,
            "motivos_sensibilidad": list(self.motivos_sensibilidad),
        }


# ---------------------------------------------------------------------------
# Primitivas de validacion
# ---------------------------------------------------------------------------


def es_ipv4(texto: str) -> bool:
    try:
        ipaddress.IPv4Address(texto)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def es_ipv6(texto: str) -> bool:
    try:
        ipaddress.IPv6Address(texto)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def es_cidr(texto: str) -> bool:
    """True si el texto es una red CIDR valida (prefijo y mascara correctos)."""
    if "/" not in texto:
        return False
    try:
        ipaddress.ip_network(texto, strict=False)
        return True
    except (ipaddress.NetmaskValueError, ValueError):
        return False


def es_hostname(texto: str) -> bool:
    """True si el texto cumple las reglas de un nombre de host o dominio."""
    if not texto or len(texto) > MAX_LONGITUD_HOSTNAME:
        return False
    if ".." in texto or texto.startswith("-") or texto.endswith("-"):
        return False
    for etiqueta in texto.split("."):
        if not etiqueta or len(etiqueta) > MAX_LONGITUD_ETIQUETA:
            return False
    return bool(_RE_HOSTNAME.match(texto))


def normalizar_rango(texto: str) -> str:
    """Normaliza '192.168.1.1-50' a '192.168.1.1-192.168.1.50'."""
    coincidencia = _RE_RANGO.match(texto.strip())
    if not coincidencia:
        raise ObjetivoInvalido(f"Rango con formato no valido: {texto!r}")
    inicio = coincidencia.group("a")
    fin = coincidencia.group("b")
    if not es_ipv4(inicio):
        raise ObjetivoInvalido(f"Inicio de rango no valido: {inicio!r}")
    if "." not in fin:
        octetos = inicio.split(".")
        fin = ".".join(octetos[:3] + [fin])
    if not es_ipv4(fin):
        raise ObjetivoInvalido(f"Fin de rango no valido: {fin!r}")

    ip_inicio = ipaddress.IPv4Address(inicio)
    ip_fin = ipaddress.IPv4Address(fin)
    if ip_inicio > ip_fin:
        raise ObjetivoInvalido(
            f"El inicio del rango ({inicio}) es mayor que el fin ({fin})."
        )
    total = int(ip_fin) - int(ip_inicio) + 1
    if total > LIMITE_HOSTS_POR_DEFECTO * 64:
        raise ObjetivoInvalido(
            f"El rango abarca {total} direcciones, demasiado para un rango de IPs. "
            "Usa notacion CIDR."
        )
    return f"{inicio}-{fin}"


# ---------------------------------------------------------------------------
# Deteccion de rangos sensibles
# ---------------------------------------------------------------------------


def clasificar_sensibilidad(texto: str) -> Tuple[bool, Tuple[str, ...]]:
    """Determina si el objetivo cae en un rango que exige confirmacion extra.

    Rangos sensibles: 0.0.0.0/0, 127.0.0.0/8, multicast, loopback,
    direcciones publicas (posible produccion) y redes internas reservadas
    de documentacion.
    """
    motivos: List[str] = []
    valor = texto.strip()

    if valor == "0.0.0.0/0":
        return True, ("0.0.0.0/0 (Internet entero)",)
    if valor == "::/0":
        return True, ("::/0 (Internet entero, IPv6)",)

    try:
        if "/" in valor:
            red = ipaddress.ip_network(valor, strict=False)
        elif "-" in valor and _RE_RANGO.match(valor):
            a, b = valor.split("-", 1)
            if "." not in b:
                b = ".".join(a.split(".")[:3] + [b])
            red = ipaddress.ip_network(f"{a}/{b}", strict=False)
        else:
            red = ipaddress.ip_network(valor, strict=False)
    except ValueError:
        # Hostname: no se puede clasificar, se trata como no sensible aqui
        # (la confirmacion principal AUTORIZADO sigue siendo obligatoria).
        return False, ()

    if red.version == 4:
        if red.is_loopback:
            motivos.append("loopback (127.0.0.0/8) en la propia maquina")
        if red.is_multicast:
            motivos.append("multicast (224.0.0.0/4)")
        motivo_extra = _red_reservada_riesgo(net=red)
        if motivo_extra:
            motivos.append(motivo_extra)
    else:
        if red.is_loopback:
            motivos.append("loopback IPv6 (::1)")
        if red.is_multicast:
            motivos.append("multicast IPv6 (ff00::/8)")

    # Determinar si incluye IPs publicas no privadas.
    incluye_publico = _incluye_ip_publica(red)
    if incluye_publico:
        motivos.append("incluye direcciones IP publicas (posible produccion)")

    return (bool(motivos), tuple(motivos))


_REDES_RANGO_RIESGO = (
    (ipaddress.ip_network("192.0.2.0/24"), "red de documentacion TEST-NET-1 (192.0.2.0/24)"),
    (ipaddress.ip_network("198.51.100.0/24"), "red de documentacion TEST-NET-2 (198.51.100.0/24)"),
    (ipaddress.ip_network("203.0.113.0/24"), "red de documentacion TEST-NET-3 (203.0.113.0/24)"),
    (ipaddress.ip_network("169.254.0.0/16"), "enlace local 169.254.0.0/16"),
    (ipaddress.ip_network("100.64.0.0/10"), "espacio compartido CGNAT (100.64.0.0/10)"),
)
# Nota: las redes privadas RFC1918 (10/8, 172.16/12, 192.168/16) NO se marcan como
# sensibles: son el caso de uso habitual de un escaneo autorizado y solo exigen la
# confirmacion principal AUTORIZADO, no la doble confirmacion SEGURO.


def _red_reservada_riesgo(net: "ipaddress._BaseNetwork") -> Optional[str]:
    """Motivo adicional si la red es una rango sensible conocido."""
    for red_riesgo, motivo in _REDES_RANGO_RIESGO:
        if net.version != red_riesgo.version:
            continue
        if net == red_riesgo:
            return motivo
    return None


def _incluye_ip_publica(net: "ipaddress._BaseNetwork") -> bool:
    """True si alguna direccion de la red es publica (no privada/loopback/etc)."""
    if net.is_private or net.is_loopback or net.is_link_local or net.is_multicast:
        return False
    if net.version == 4:
        # 0.0.0.0/0 y aggregatedes (/0../7) abarcan Internet entero.
        return net.prefixlen < 8 or not net.is_reserved
    return not net.is_private


# ---------------------------------------------------------------------------
# Validacion principal
# ---------------------------------------------------------------------------


def validar_objetivo(texto: str, limite_hosts: int = LIMITE_HOSTS_POR_DEFECTO) -> Objetivo:
    """Valida un objetivo individual. Lanza ObjetivoInvalido si es incorrecto."""
    if texto is None:
        raise ObjetivoInvalido("El objetivo no puede ser nulo.")
    limpio = texto.strip()
    if not limpio:
        raise ObjetivoInvalido("El objetivo esta vacio.")
    if any(c.isspace() for c in limpio):
        raise ObjetivoInvalido(
            f"El objetivo {limpio!r} contiene espacios. Separa varios objetivos con comas."
        )

    limpio = limpio.strip("[]")
    if not limpio:
        raise ObjetivoInvalido("El objetivo esta vacio tras limpiar corchetes.")

    # IP unica
    if es_ipv4(limpio) or es_ipv6(limpio):
        direccion = ipaddress.ip_address(limpio)
        if direccion.is_unspecified:
            raise ObjetivoInvalido(
                "0.0.0.0 no es un objetivo valido en nmap; usa 0.0.0.0/0 "
                "(que requiere confirmacion extra)."
            )
        sensible, motivos = clasificar_sensibilidad(limpio)
        return Objetivo(
            tipo=TIPO_IP,
            valor=limpio,
            valor_normalizado=limpio,
            hosts_aproximados=1,
            sensible=sensible,
            motivos_sensibilidad=motivos,
        )

    # CIDR
    if "/" in limpio:
        if not es_cidr(limpio):
            raise ObjetivoInvalido(
                f"'{limpio}' parece una notacion CIDR pero la red no es valida "
                "(comprueba la mascara y las IPs)."
            )
        red = ipaddress.ip_network(limpio, strict=False)

        # La sensibilidad se evalua ANTES que el limite: un rango sensible debe
        # llegar a la doble confirmacion, no morir con un error de limite.
        sensible, motivos = clasificar_sensibilidad(limpio)

        if red.num_addresses > limite_hosts:
            if sensible:
                # Se acepta para que el usuario pase por la confirmacion
                # reforzada, que es mas fuerte que un simple limite de tamano.
                motivos = motivos + (
                    f"alcance muy amplio ({red.num_addresses} direcciones); "
                    "el escaneo sera muy lento y generara mucho trafico",
                )
            else:
                raise ObjetivoInvalido(
                    f"La red {limpio} contiene {red.num_addresses} direcciones y supera el "
                    f"limite de {limite_hosts}. Divide la red o aumenta el limite con "
                    "--limite-hosts."
                )
        return Objetivo(
            tipo=TIPO_CIDR,
            valor=limpio,
            valor_normalizado=str(red),
            hosts_aproximados=red.num_addresses,
            sensible=sensible,
            motivos_sensibilidad=motivos,
        )

    # Rango
    if "-" in limpio:
        normalizado = normalizar_rango(limpio)
        a, b = normalizado.split("-", 1)
        total = int(ipaddress.IPv4Address(b)) - int(ipaddress.IPv4Address(a)) + 1
        sensible, motivos = clasificar_sensibilidad(normalizado)
        if total > limite_hosts and not sensible:
            raise ObjetivoInvalido(
                f"El rango {limpio} abarca {total} direcciones y supera el limite de "
                f"{limite_hosts}."
            )
        return Objetivo(
            tipo=TIPO_RANGO,
            valor=limpio,
            valor_normalizado=normalizado,
            hosts_aproximados=total,
            sensible=sensible,
            motivos_sensibilidad=motivos,
        )

    # Hostname / dominio
    if es_hostname(limpio):
        # Un cuádruplo con forma de IP pero invalido no puede ser un hostname:
        # '999.1.1.1' o '1.2.3.4.5' son errores de tecleo, no nombres de dominio.
        if _RE_CUADRUPLO.match(limpio) or _RE_CUADRUPLO_EXTRA.match(limpio):
            raise ObjetivoInvalido(
                f"'{limpio}' tiene forma de direccion IPv4 pero no es una IP valida "
                "(comprueba cada octeto: debe estar entre 0 y 255)."
            )
        return Objetivo(
            tipo=TIPO_HOSTNAME,
            valor=limpio,
            valor_normalizado=limpio,
            hosts_aproximados=1,
            sensible=False,
        )

    raise ObjetivoInvalido(
        f"'{limpio}' no es una IP, un CIDR, un rango ni un hostname valido.\n"
        "    Formatos aceptados: 192.168.1.10 | 192.168.1.0/24 | "
        "192.168.1.1-50 | host.example.com"
    )


def leer_archivo_objetivos(ruta: str) -> List[str]:
    """Lee un archivo .txt con un objetivo por linea. Ignora comentarios y vacios."""
    if not os.path.isfile(ruta):
        raise ObjetivoInvalido(f"No se encuentra el archivo de objetivos: {ruta}")
    try:
        with open(ruta, "r", encoding="utf-8-sig", errors="replace") as manejador:
            lineas = [linea.strip() for linea in manejador]
    except OSError as exc:
        raise ObjetivoInvalido(f"No se pudo leer el archivo '{ruta}': {exc}") from exc

    resultado = [linea for linea in lineas if linea and not _RE_COMENTARIO.match(linea)]
    if not resultado:
        raise ObjetivoInvalido(f"El archivo '{ruta}' no contiene objetivos validos.")
    if len(resultado) > MAX_LINES_ARCHIVO:
        raise ObjetivoInvalido(
            f"El archivo '{ruta}' tiene {len(resultado)} lineas, superar el maximo de "
            f"{MAX_LINES_ARCHIVO}."
        )
    return resultado


def validar_exclusion(texto: str) -> Tuple[str, "ipaddress._BaseNetwork | ipaddress._BaseAddress"]:
    """Valida una IP o CIDR de exclusion. Devuelve (texto, red/direccion)."""
    limpio = texto.strip().strip("[]")
    if not limpio:
        raise ObjetivoInvalido("Una exclusion esta vacia.")
    if "/" in limpio:
        if not es_cidr(limpio):
            raise ObjetivoInvalido(f"Exclusion CIDR no valida: {texto!r}")
        return limpio, ipaddress.ip_network(limpio, strict=False)
    if es_ipv4(limpio):
        return limpio, ipaddress.IPv4Address(limpio)
    if es_ipv6(limpio):
        return limpio, ipaddress.IPv6Address(limpio)
    raise ObjetivoInvalido(
        f"Exclusion no valida: {texto!r}. Debe ser una IP o un CIDR."
    )


def dividir_entradas(entrada: str) -> List[str]:
    """Divide 'a,b,c' o 'a b c' en lista de objetivos individuales."""
    if not entrada:
        return []
    if "," in entrada:
        partes = entrada.split(",")
    else:
        partes = entrada.split()
    return [p.strip() for p in partes if p.strip()]


def construir_objetivos(
    objetivos: Sequence[str],
    archivo: Optional[str] = None,
    limite_hosts: int = LIMITE_HOSTS_POR_DEFECTO,
) -> Tuple[List[Objetivo], List[str]]:
    """Valida la lista completa de objetivos. Devuelve (validos, errores)."""
    candidatos: List[str] = []
    for entrada in objetivos or []:
        candidatos.extend(dividir_entradas(entrada))
    if archivo:
        candidatos.extend(leer_archivo_objetivos(archivo))

    if not candidatos:
        return [], ["No se indico ningun objetivo."]

    validos: List[Objetivo] = []
    errores: List[str] = []
    vistos: Set[str] = set()
    for candidato in candidatos:
        try:
            objetivo = validar_objetivo(candidato, limite_hosts)
        except ObjetivoInvalido as exc:
            errores.append(str(exc))
            LOG.debug("Objetivo rechazado %r: %s", candidato, exc)
            continue
        clave = f"{objetivo.tipo}|{objetivo.valor_normalizado.casefold()}"
        if clave in vistos:
            continue
        vistos.add(clave)
        validos.append(objetivo)
    return validos, errores


def total_hosts(objetivos: Iterable[Objetivo]) -> int:
    return sum(objetivo.hosts_aproximados for objetivo in objetivos)


def construir_exclusiones(
    exclusiones: Sequence[str],
) -> Tuple[List[str], List["ipaddress._BaseNetwork | ipaddress._BaseAddress"], List[str]]:
    """Valida exclusiones. Devuelve (textos, redes, errores)."""
    textos: List[str] = []
    redes: List["ipaddress._BaseNetwork | ipaddress._BaseAddress"] = []
    errores: List[str] = []
    for entrada in exclusiones or []:
        for parte in dividir_entradas(entrada):
            try:
                texto, red = validar_exclusion(parte)
            except ObjetivoInvalido as exc:
                errores.append(str(exc))
                continue
            textos.append(texto)
            redes.append(red)
    return textos, redes, errores


def objetivo_esta_excluido(
    objetivo: Objetivo,
    redes_exclusion: Sequence["ipaddress._BaseNetwork | ipaddress._BaseAddress"],
) -> bool:
    """True si el objetivo cae dentro de alguna red de exclusion."""
    if not redes_exclusion:
        return False
    if objetivo.tipo == TIPO_CIDR:
        try:
            red = ipaddress.ip_network(objetivo.valor_normalizado, strict=False)
        except ValueError:
            return False
        for excluir in redes_exclusion:
            if isinstance(excluir, ipaddress._BaseNetwork):
                if red.version == excluir.version and red.subnet_of(excluir):  # type: ignore[arg-type]
                    return True
        return False
    if objetivo.tipo in (TIPO_IP, TIPO_RANGO):
        try:
            if objetivo.tipo == TIPO_IP:
                direccion = ipaddress.ip_address(objetivo.valor_normalizado)
            else:
                inicio, _fin = objetivo.valor_normalizado.split("-", 1)
                direccion = ipaddress.IPv4Address(inicio)
        except ValueError:
            return False
        for excluir in redes_exclusion:
            if isinstance(excluir, ipaddress._BaseNetwork):
                if direccion.version == excluir.version and direccion in excluir:  # type: ignore[operator]
                    return True
            else:
                if direccion == excluir:
                    return True
        return False
    return False


def filtrar_excluidos(
    objetivos: Sequence[Objetivo],
    redes_exclusion: Sequence["ipaddress._BaseNetwork | ipaddress._BaseAddress"],
) -> Tuple[List[Objetivo], List[Objetivo]]:
    """Separa (objetivos_validos, objetivos_excluidos)."""
    if not redes_exclusion:
        return list(objetivos), []
    conservados: List[Objetivo] = []
    excluidos: List[Objetivo] = []
    for objetivo in objetivos:
        if objetivo_esta_excluido(objetivo, redes_exclusion):
            excluidos.append(objetivo)
        else:
            conservados.append(objetivo)
    return conservados, excluidos
