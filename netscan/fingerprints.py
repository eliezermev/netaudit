"""Extraccion de evidencia pasiva: banners, cabeceras HTTP/TLS y configs inseguras.

Este modulo SOLO LEE lo que nmap ya obtuvo. No abre conexiones propias, no envia
peticiones y no intenta autenticarse en ningun servicio.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .scanner import Host, ResultadoEscaneo, Servicio
from .utils import limpiar_espacios, truncar

# --------------------------------------------------------------------------
# Puertos de referencia usados por las reglas
# --------------------------------------------------------------------------

PUERTOS_TELNET = (23,)
PUERTOS_FTP = (20, 21)
PUERTOS_FTP_PASIVO = (20,)
PUERTOS_SSH = (22,)
PUERTOS_SMB = (139, 445)
PUERTOS_SNMP = (161,)
PUERTOS_MYSQL = (3306,)
PUERTOS_MONGO = (27017,)
PUERTOS_REDIS = (6379,)
PUERTOS_RABBITMQ = (5672, 15672, 25672, 4369)
PUERTOS_ELASTIC = (9200, 9300, 5601)
PUERTOS_ADMINISTRACION = (8161, 4848, 9000, 8009, 6443, 2375, 9200)
PUERTOS_HTTP_COMUNES = (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090)

NOMBRES_ADMINISTRACION = {
    8161: "ActiveMQ Web",
    4848: "GlassFish Admin",
    9000: "PHP-FPM / Node genérico / SonarQube",
    8009: "AJP (Apache JServ)",
    6443: "Kubernetes API server",
    2375: "Docker Remote API sin TLS",
    9200: "Elasticsearch",
}

RUTAS_SOSPECHOSAS = (
    ("/admin", "panel de administracion", "MEDIA"),
    ("/.git", "repositorio Git expuesto", "ALTA"),
    ("/.env", "archivo de variables de entorno expuesto", "ALTA"),
    ("/phpmyadmin", "consola de base de datos phpMyAdmin", "MEDIA"),
    ("/actuator/env", "Spring Boot Actuator con volcado de entorno", "ALTA"),
    ("/.git/config", "fichero de configuracion de Git expuesto", "ALTA"),
    ("/.svn", "repositorio Subversion expuesto", "MEDIA"),
    ("/wp-login.php", "panel de login WordPress", "BAJA"),
    ("/server-status", "estado del servidor Apache", "MEDIA"),
    ("/config.json", "fichero de configuracion expuesto", "MEDIA"),
)

# Versiones de OpenSSH consideradas antiguas (EOL o con CVEs publicas graves).
VERSIONES_OPENSSSH_ANTIGUAS = [
    (re.compile(r"OpenSSH[_ ]([0-7])(\.|\d)"), "OpenSSH anterior a 8.0"),
    (re.compile(r"OpenSSH[_ ]?([0-9])\.([0-3])\b"), "OpenSSH 8.0-8.3 (EOL, sin mantenimiento)"),
]

PRODUCTOS_EOL = {
    "apache httpd": "2.2",
    "apache": "2.2",
    "nginx": "1.18",
    "openssl": "1.0.2",
    "php": "5.",
    "mysql": "5.0",
    "mariadb": "10.1",
    "microsoft iis": "6.0",
    "iis": "6.0",
    "tomcat": "7.",
    "jboss": "6.",
    "struts": "2.3",
    "log4j": "1.2",
    "wordpress": "3.",
    "jre": "1.7",
    "java": "1.7",
    "openssh": "7.",
}


@dataclass
class CabecerasHTTP:
    """Cabeceras HTTP observadas por nmap (solo lectura)."""

    codigo: str = ""
    servidor: str = ""
    encabezados: Dict[str, str] = field(default_factory=dict)
    metodos: List[str] = field(default_factory=list)
    cookies: List[str] = field(default_factory=list)
    titulo: str = ""
    metodos_fuente: str = ""

    def obtener(self, nombre: str) -> str:
        return self.encabezados.get(nombre.casefold(), "")

    @property
    def tiene_seguridad(self) -> bool:
        return self.codigo.startswith("2") or self.codigo.startswith("3")


@dataclass
class InfoTLS:
    """Datos de certificado TLS observados por nmap."""

    tiene_certificado: bool = False
    autofirmado: bool = False
    expirado: bool = False
    protocolo: str = ""
    protocolo_obsoleto: bool = False
    cifrado: str = ""
    emisor: str = ""
    sujeto: str = ""
    valido_desde: str = ""
    valido_hasta: str = ""
    dias_para_caducar: Optional[int] = None
    sni_soportado: Optional[bool] = None
    evidencia: str = ""


@dataclass
class Observacion:
    """Dato crudo extraido de un servicio, base de las reglas de vulns.py."""

    host: Host
    servicio: Servicio
    datos: Dict[str, object] = field(default_factory=dict)

    @property
    def etiqueta_puerto(self) -> str:
        return f"{self.servicio.puerto}/{self.servicio.protocolo}"


# --------------------------------------------------------------------------
# Extraccion de banners
# --------------------------------------------------------------------------

_RE_VERSION_SSH = re.compile(r"OpenSSH[_\s-]?([0-9]+(?:\.[0-9]+)*)")
_RE_SMB_V1 = re.compile(r"\bNT LM 0\.12\b|SMBv1|smb1|Dialect:\s*NT LM", re.IGNORECASE)
_RE_FTP_ANON = re.compile(r"anonymous|anon\b|guest", re.IGNORECASE)
_RE_FTP_220 = re.compile(r"^\s*220\b", re.MULTILINE)
_RE_SNMP_COMMUNITY = re.compile(
    r"(community(?:String)?\s*[:=]?\s*|SNMPv[12]c?\b.*?\b)(\"?)(public|private)\2",
    re.IGNORECASE,
)
_RE_METHODS = re.compile(
    r"Allowed methods:\s*(?P<metodos>[A-Z, ]+)", re.IGNORECASE
)
_RE_PUT_ALLOWED = re.compile(
    r"(PUT|DELETE|TRACE|MOVE|CONNECT)\s+[\w./%-]+\s+HTTP/[\d.]+\s+(200|201|204|405|501)", re.IGNORECASE
)
_RE_HTTP_STATUS = re.compile(r"HTTP/[\d.]+\s+(\d{3})")
_RE_SET_COOKIE = re.compile(r"Set-Cookie:\s*(?P<valor>[^\r\n]+)", re.IGNORECASE)
_RE_SERVER = re.compile(r"^Server:\s*(?P<valor>.+)$", re.IGNORECASE | re.MULTILINE)
_RE_LOCATIONS = re.compile(r"Location:\s*(?P<valor>https?://[^\s]+)", re.IGNORECASE)


def banner_texto(servicio: Servicio) -> str:
    """Texto de banner utilizable como evidencia."""
    partes: List[str] = []
    if servicio.banner:
        partes.append(servicio.banner)
    for identificador, salida in servicio.scripts:
        if identificador.startswith("http-") and salida:
            partes.append(salida)
            break
    return limpiar_espacios("\n".join(partes))


def _texto_observado(servicio: Servicio, solo_prefijo: Optional[Tuple[str, ...]] = None) -> str:
    """Todo el texto que nmap obtuvo del servicio: banner + scripts relevantes.

    `solo_prefijo` limita los scripts incluidos (p. ej. ('smb',) o ('http-',)).
    """
    partes: List[str] = []
    if servicio.banner:
        partes.append(servicio.banner)
    for identificador, salida in servicio.scripts:
        if not salida:
            continue
        if solo_prefijo is None:
            partes.append(salida)
        elif any(identificador == p or identificador.startswith(p) for p in solo_prefijo):
            partes.append(salida)
    return "\n".join(partes)


def extraer_http(servicio: Servicio) -> Optional[CabecerasHTTP]:
    """Extrae cabeceras/methods/cookies de la salida de scripts http-* de nmap."""
    if servicio.puerto not in PUERTOS_HTTP_COMUNES:
        return None
    salida = _texto_observado(servicio, solo_prefijo=("http-",))
    if not salida.strip():
        return None

    http = CabecerasHTTP(metodos_fuente="scripts http-* de nmap (observacion pasiva)")

    estado = _RE_HTTP_STATUS.search(salida)
    if estado:
        http.codigo = estado.group(1)

    # Cabeceras, cookies y titulo pueden venir en el banner o en cualquier script.
    for coincidencia in _RE_SET_COOKIE.finditer(salida):
        valor = coincidencia.group("valor").strip()
        if valor and valor not in http.cookies:
            http.cookies.append(valor)

    servidor = _RE_SERVER.search(salida)
    if servidor:
        http.servidor = servidor.group("valor").strip()
        http.encabezados["server"] = http.servidor

    titulo = re.search(r"<title>(?P<valor>[^<]*)</title>", salida, re.IGNORECASE)
    if titulo:
        http.titulo = limpiar_espacios(titulo.group("valor"))

    # Cabeceras de seguridad presentes en la respuesta observada.
    for linea in salida.splitlines():
        coincide_cabecera = re.match(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.+)$", linea)
        if not coincide_cabecera:
            continue
        clave = coincide_cabecera.group(1).strip().casefold()
        valor = coincide_cabecera.group(2).strip()
        if clave in {
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "server",
            "location",
        }:
            http.encabezados[clave] = valor

    metodos = _RE_METHODS.search(salida)
    if metodos:
        http.metodos = [m.strip().upper() for m in metodos.group("metodos").split(",") if m.strip()]
    else:
        http.metodos = sorted({m.group(1).upper() for m in _RE_PUT_ALLOWED.finditer(salida)})

    if not (http.codigo or http.servidor or http.encabezados or http.metodos or http.cookies):
        return None
    return http


def extraer_tls(servicio: Servicio) -> Optional[InfoTLS]:
    """Extrae datos de certificado y protocolo TLS de ssl-cert / ssl-enum-ciphers."""
    salida = "\n".join(
        salida
        for identificador, salida in servicio.scripts
        if identificador.startswith("ssl-") or identificador.startswith("tls-")
    )
    if not salida.strip():
        return None

    tls = InfoTLS(evidencia=truncar(salida, 1500))

    issuer = re.search(r"Issuer:\s*(?P<valor>.+)", salida)
    if issuer:
        tls.emisor = limpiar_espacios(issuer.group("valor"))
    sujeto = re.search(r"Subject:\s*(?P<valor>.+)", salida)
    if sujeto:
        tls.sujeto = limpiar_espacios(sujeto.group("valor"))

    validez = re.search(
        r"Not valid before:\s*(?P<desde>.+?)\s*Not valid after\s*:?\s*(?P<hasta>.+)", salida
    )
    if validez:
        tls.valido_desde = limpiar_espacios(validez.group("desde"))
        tls.valido_hasta = limpiar_espacios(validez.group("hasta"))
        tls.dias_para_caducar = _dias_para_caducar(tls.valido_hasta)

    if re.search(r"self.signed|selfsigned|Self-signed", salida, re.IGNORECASE):
        tls.autofirmado = True
    tls.tiene_certificado = bool(tls.emisor or tls.sujeto or tls.valido_hasta)

    if re.search(r"expired|Expired", salida):
        tls.expirado = True
    if tls.dias_para_caducar is not None and tls.dias_para_caducar < 0:
        tls.expirado = True

    protocolo = re.search(r"\b(TLSv?1\.[0-3]|SSLv[23]|TLSv1)\b", salida)
    if protocolo:
        tls.protocolo = protocolo.group(1)
        if protocolo.group(1) in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"):
            tls.protocolo_obsoleto = True

    cifrado = re.search(r"Cipher\s*:\s*(?P<valor>[A-Za-z0-9_-]+)", salida)
    if cifrado:
        tls.cifrado = cifrado.group("valor")

    if re.search(r"Server Name Indication|SNI|no SNI|does not support SNI", salida, re.IGNORECASE):
        tls.sni_soportado = "not support" not in salida.casefold()

    return tls


def _dias_para_caducar(fecha_texto: str) -> Optional[int]:
    from datetime import datetime, timezone

    limpio = (fecha_texto or "").strip()
    for formato in (
        "%b %d %H:%M:%S %Y GMT",
        "%b %d %H:%M:%S %Y",
        "%Y%m%d%H%M%SZ",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            fecha = datetime.strptime(limpio, formato).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        return (fecha - datetime.now(timezone.utc)).days
    return None


# --------------------------------------------------------------------------
# Analisis por servicio
# --------------------------------------------------------------------------


def analizar_servicios(resultado: ResultadoEscaneo) -> List[Observacion]:
    """Recorre el resultado y produce una Observacion por servicio abierto."""
    observaciones: List[Observacion] = []
    for host in resultado.hosts_activos:
        for servicio in host.puertos_abiertos:
            observacion = Observacion(host=host, servicio=servicio)
            _rellenar_datos(observacion)
            observaciones.append(observacion)
    return observaciones


def _rellenar_datos(observacion: Observacion) -> None:
    servicio = observacion.servicio
    puerto = servicio.puerto
    banner = banner_texto(servicio)
    datos = observacion.datos

    datos["banner"] = banner
    datos["nombre_servicio"] = servicio.nombre_completo
    datos["nombre_nse"] = servicio.servicio

    if puerto in PUERTOS_TELNET:
        datos["telnet"] = True
        datos["sin_cifrado"] = True

    if puerto in PUERTOS_FTP:
        ftp = _analizar_ftp(servicio, banner)
        if ftp:
            datos.update(ftp)

    if puerto in PUERTOS_SMB:
        datos["smb"] = True
        # El dialecto SMBv1 puede aparecer en el banner o en la salida del
        # script smb-os-discovery, segun la version de nmap.
        if _RE_SMB_V1.search(_texto_observado(servicio, solo_prefijo=("smb",))):
            datos["smbv1"] = True

    if puerto in PUERTOS_SNMP:
        community = _detectar_community_snmp(banner)
        if community:
            datos["snmp_community"] = community

    if puerto in PUERTOS_SSH:
        version = _extraer_version_openssh(banner)
        if version:
            datos["openssh_version"] = version
        if re.search(r"root", banner, re.IGNORECASE):
            datos["ssh_root_presente"] = True

    if puerto in PUERTOS_ADMINISTRACION:
        datos["puerto_administracion"] = puerto
        datos["puerto_administracion_nombre"] = NOMBRES_ADMINISTRACION.get(puerto, "servicio de administracion")

    # Servicios de datos sin autenticacion
    if puerto in PUERTOS_MYSQL and re.search(r"host\s+'.+?'\s+is not allowed|Access denied", banner, re.IGNORECASE):
        datos["db_sin_auth"] = "MySQL"
    if puerto in PUERTOS_MONGO:
        datos["db_sin_auth_posible"] = "MongoDB"
    if puerto in PUERTOS_REDIS and re.search(r"redis_version|denied|NOAUTH|requirepass", banner, re.IGNORECASE):
        datos["redis_presente"] = True
    if puerto in PUERTOS_RABBITMQ:
        datos["rabbitmq_presible"] = True
    if puerto in PUERTOS_ELASTIC:
        datos["elasticsearch_presible"] = True

    # Version EOL
    eol = _detectar_version_eol(servicio)
    if eol:
        datos["version_eol"] = eol

    # HTTP
    http = extraer_http(servicio)
    if http is not None:
        datos["http"] = http

    # TLS
    tls = extraer_tls(servicio)
    if tls is not None:
        datos["tls"] = tls


def _analizar_ftp(servicio: Servicio, banner: str) -> Dict[str, object]:
    """Analiza el banner FTP.

    El login anonimo SOLO se marca cuando el banner 220 lo anuncia o cuando
    nmap ejecuto el script ftp-anon y devolvio exito. Nunca se intenta
    conectar ni autenticar.
    """
    datos: Dict[str, object] = {}
    if not _RE_FTP_220.search(banner):
        return datos

    lineas = [linea for linea in banner.splitlines() if linea.strip()]
    datos["ftp_banner_220"] = lineas[0].strip()

    scripts = dict(servicio.scripts)
    salida_anon = scripts.get("ftp-anon", "")
    if re.search(r"Anonymous login|anonymous ftp login|anonymous.*allowed", banner) or (
        salida_anon and re.search(r"Anonymous|anon", salida_anon, re.IGNORECASE)
        and not re.search(r"not allowed|denied|failed|530", salida_anon, re.IGNORECASE)
    ):
        datos["ftp_anonimo"] = True
    elif re.search(r"230", banner):
        datos["ftp_anonimo_posible"] = True

    if re.search(r"\bAUTH\s+TLS|STARTTLS|Explicit TLS", banner, re.IGNORECASE):
        datos["ftp_tls"] = True
    else:
        datos["ftp_sin_tls"] = True
    return datos


def _detectar_community_snmp(banner: str) -> str:
    coincidencia = _RE_SNMP_COMMUNITY.search(banner)
    if coincidencia:
        return coincidencia.group(3).casefold()
    if re.search(r"\bSNMPv[123]\b", banner, re.IGNORECASE):
        return "desconocida"
    return ""


def _extraer_version_openssh(banner: str) -> str:
    coincidencia = _RE_VERSION_SSH.search(banner)
    return coincidencia.group(1) if coincidencia else ""


def _detectar_version_eol(servicio: Servicio) -> str:
    """Detecta productos en version sin soporte (EOL)."""
    texto = " ".join(
        p for p in (servicio.servicio, servicio.producto, servicio.version, servicio.extra) if p
    ).casefold()
    for producto, prefijo in PRODUCTOS_EOL.items():
        if producto in texto and prefijo in texto:
            return f"{servicio.producto or producto} {servicio.version or ''}".strip()
    return ""


# --------------------------------------------------------------------------
# HTTP: rutas y cabeceras (evaluacion de exposicion, sin explotar)
# --------------------------------------------------------------------------


def evaluar_rutas_sospechosas(servicio: Servicio, http: CabecerasHTTP) -> List[Tuple[str, str, str]]:
    """Rutas sospechosas que nmap ya localizo en su salida.

    Devuelve (ruta, descripcion, severidad_sugerida). No se realizaran
    peticiones adicionales.
    """
    encontradas: List[Tuple[str, str, str]] = []
    salida = _texto_observado(servicio, solo_prefijo=("http-",))
    for ruta, descripcion, severidad in RUTAS_SOSPECHOSAS:
        if ruta in salida or ruta.casefold() in salida.casefold():
            encontradas.append((ruta, descripcion, severidad))
    return encontradas


def evaluar_cabeceras_inseguras(http: CabecerasHTTP) -> List[Tuple[str, str, str]]:
    """Devuelve (cabecera_ausente, descripcion, severidad_sugerida)."""
    problemas: List[Tuple[str, str, str]] = []
    servidor = http.servidor or http.obtener("server")
    if servidor and re.search(r"\d+\.\d+", servidor):
        problemas.append(
            (f"Server: {servidor}", "La cabecera Server expone la version exacta del software", "MEDIA")
        )
    if not http.obtener("strict-transport-security") and http.codigo.startswith(("2", "3")):
        problemas.append(
            ("Strict-Transport-Security ausente",
             "No hay HSTS: el navegador no fuerza HTTPS y admite degradacion a HTTP", "MEDIA")
        )
    if not http.obtener("content-security-policy"):
        problemas.append(
            ("Content-Security-Policy ausente",
             "Sin CSP la defensa frente a XSS se apoya solo en el navegador", "BAJA")
        )
    if not http.obtener("x-frame-options") and "frame-ancestors" not in http.obtener("content-security-policy"):
        problemas.append(
            ("X-Frame-Options ausente",
             "Sin XFO ni frame-ancestors la pagina puede incrustarse en un iframe (clickjacking)", "MEDIA")
        )
    if not http.obtener("x-content-type-options"):
        problemas.append(
            ("X-Content-Type-Options ausente",
             "Sin nosniff el navegador puede interpretar tipos MIME inesperados", "BAJA")
        )
    for cookie in http.cookies:
        if not re.search(r"secure", cookie, re.IGNORECASE):
            problemas.append((f"Cookie sin Secure: {truncar(cookie, 90)}",
                              "La cookie puede enviarse en claro sobre HTTP", "MEDIA"))
        if not re.search(r"httponly", cookie, re.IGNORECASE):
            problemas.append((f"Cookie sin HttpOnly: {truncar(cookie, 90)}",
                              "La cookie es accesible desde JavaScript (robo de sesion)", "MEDIA"))
    return problemas
