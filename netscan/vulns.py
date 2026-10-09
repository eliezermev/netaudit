"""Reglas heuristicas de evaluacion defensiva sobre las observaciones pasivas.

Cada hallazgo incluye: titulo, severidad, riesgo real, evidencia exacta
(banner/respuesta), puerto, servicio y mitigacion concreta.

Ademas cada regla documenta sus FALSOS POSITIVOS CONOCIDOS, porque estas
comprobaciones son heuristicas sobre banners y no pruebas de explotabilidad.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import fingerprints as fp
from .attack import TecnicaATTACK
from .scanner import ResultadoEscaneo
from .utils import obtener_logger, truncar

LOG = obtener_logger("vulns")

# --------------------------------------------------------------------------
# Severidades
# --------------------------------------------------------------------------

CRITICA = "CRITICA"
ALTA = "ALTA"
MEDIA = "MEDIA"
BAJA = "BAJA"
INFO = "INFO"

ORDEN_SEVERIDAD = (CRITICA, ALTA, MEDIA, BAJA, INFO)

PESO_SEVERIDAD: Dict[str, int] = {
    CRITICA: 10,
    ALTA: 7,
    MEDIA: 4,
    BAJA: 1,
    INFO: 0,
}

DESCRIPCION_SEVERIDAD = {
    CRITICA: "Exposicion que permite compromiso inmediato o acceso no autenticado.",
    ALTA: "Riesgo serio de compromiso o de exposicion de datos sensibles.",
    MEDIA: "Debilidad que facilita ataques posteriores o reduce la defensa.",
    BAJA: "Endurecimiento recomendado. Sin impacto directo conocido.",
    INFO: "Observacion informativa para contexto.",
}


class SeveridadInvalida(ValueError):
    """Severidad fuera del catalogo permitido."""


def normalizar_severidad(texto: str) -> str:
    """Normaliza a CRITICA/ALTA/MEDIA/BAJA/INFO. Lanza si es desconocida."""
    if texto is None:
        raise SeveridadInvalida("La severidad no puede ser nula.")
    clave = str(texto).strip().upper()
    mapa = {
        "CRITICA": CRITICA, "CRÍTICA": CRITICA, "CRITICAL": CRITICA, "C": CRITICA,
        "ALTA": ALTA, "ALTO": ALTA, "HIGH": ALTA, "H": ALTA,
        "MEDIA": MEDIA, "MEDIO": MEDIA, "MEDIUM": MEDIA, "M": MEDIA,
        "BAJA": BAJA, "BAJO": BAJA, "LOW": BAJA, "L": BAJA,
        "INFO": INFO, "INFORMATIVA": INFO, "INFORMATIONAL": INFO, "I": INFO,
    }
    if clave in mapa:
        return mapa[clave]
    raise SeveridadInvalida(
        f"Severidad no valida: {texto!r}. Usa una de: {', '.join(ORDEN_SEVERIDAD)}."
    )


def peso_severidad(severidad: str) -> int:
    return PESO_SEVERIDAD.get(normalizar_severidad(severidad), 0)


# --------------------------------------------------------------------------
# Modelo de hallazgo
# --------------------------------------------------------------------------


@dataclass
class Hallazgo:
    """Un hallazgo de evaluacion defensiva."""

    titulo: str
    severidad: str
    riesgo: str
    evidencia: str
    mitigacion: str
    host: str = ""
    puerto: str = ""
    servicio: str = ""
    regla: str = ""
    tecnicas: List[TecnicaATTACK] = field(default_factory=list)
    falsos_positivos: str = ""
    categoria: str = "configuracion"

    @property
    def severidad_orden(self) -> int:
        return ORDEN_SEVERIDAD.index(normalizar_severidad(self.severidad))

    def a_dict(self) -> Dict[str, object]:
        return {
            "titulo": self.titulo,
            "severidad": self.severidad,
            "peso": peso_severidad(self.severidad),
            "riesgo": self.riesgo,
            "evidencia": self.evidencia,
            "puerto": self.puerto,
            "servicio": self.servicio,
            "host": self.host,
            "regla": self.regla,
            "categoria": self.categoria,
            "mitigacion": self.mitigacion,
            "falsos_positivos": self.falsos_positivos,
            "mitre_attack": [t.a_dict() for t in self.tecnicas],
        }


@dataclass(frozen=True)
class Resumen:
    """Contadores por severidad y score global."""

    por_severidad: Dict[str, int]
    total: int
    score: int
    nota: str


def calcular_resumen(hallazgos: Sequence[Hallazgo]) -> Resumen:
    """Contadores por severidad y score global normalizado 0-100."""
    conteo = {nivel: 0 for nivel in ORDEN_SEVERIDAD}
    for hallazgo in hallazgos:
        conteo[normalizar_severidad(hallazgo.severidad)] += 1

    suma = sum(peso_severidad(h.severidad) for h in hallazgos)
    # 100 = 10 hallazgos criticos o mas; escala logaritmica suave.
    score = min(100, int(round(100 * (1 - pow(2.718281828, -suma / 12.0)))))
    nota = (
        "Score 0: no se detectaron debilidades. "
        "Score 100: exposicion critica extendida. "
        "El score es orientativo y se calcula a partir del peso por severidad."
    )
    return Resumen(por_severidad=conteo, total=len(hallazgos), score=score, nota=nota)


# --------------------------------------------------------------------------
# Motor de reglas
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Regla:
    """Definicion de una regla heuristica."""

    identificador: str
    titulo: str
    severidad: str
    riesgo: str
    mitigacion: str
    falsos_positivos: str
    tecnicas: Tuple[TecnicaATTACK, ...] = ()
    categoria: str = "configuracion"

    def aplicar(self, observacion: fp.Observacion) -> Optional[Hallazgo]:
        """Evalua la regla sobre una observacion. Devuelve None si no aplica."""
        raise NotImplementedError  # type: ignore[abstract]

    def construir(self, observacion: fp.Observacion, evidencia: str) -> Hallazgo:
        return Hallazgo(
            titulo=self.titulo,
            severidad=self.severidad,
            riesgo=self.riesgo,
            evidencia=evidencia,
            mitigacion=self.mitigacion,
            host=observacion.host.direccion,
            puerto=observacion.etiqueta_puerto,
            servicio=str(observacion.datos.get("nombre_servicio") or observacion.servicio.servicio or "?"),
            regla=self.identificador,
            tecnicas=list(self.tecnicas),
            falsos_positivos=self.falsos_positivos,
            categoria=self.categoria,
        )


# ---- Red / exposicion de servicios ---------------------------------------


class ReglaTelnetAbierto(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        if not o.datos.get("telnet"):
            return None
        banner = str(o.datos.get("banner") or "")
        return self.construir(
            o,
            f"Servicio Telnet escuchando sin cifrado. Banner: {truncar(banner, 200) or '(sin banner)'}",
        )


class ReglaFtpAnonimo(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        if not o.datos.get("ftp_anonimo"):
            return None
        banner = str(o.datos.get("ftp_banner_220") or "")
        return self.construir(
            o,
            f"El servidor FTP anuncia acceso anonimo. Banner 220: {truncar(banner, 200) or '(sin banner)'}",
        )


class ReglaFtpSinTls(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        if not o.datos.get("ftp_sin_tls"):
            return None
        banner = str(o.datos.get("banner") or "")
        return self.construir(
            o,
            f"El banner FTP no anuncia AUTH TLS/STARTTLS. Banner: {truncar(banner, 200)}",
        )


class ReglaSmbSinCifrado(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        if not o.datos.get("smb"):
            return None
        banner = str(o.datos.get("banner") or "")
        return self.construir(
            o,
            f"SMB expuesto sin cifrado de transporte negociado. Evidencia: {truncar(banner, 200)}",
        )


class ReglaSmbv1(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        if not o.datos.get("smbv1"):
            return None
        banner = str(o.datos.get("banner") or "")
        return self.construir(
            o,
            f"El servidor acepta dialecto SMBv1 (NT LM 0.12). Evidencia: {truncar(banner, 200)}",
        )


class ReglaSnmpDebil(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        community = o.datos.get("snmp_community")
        if not community:
            return None
        banner = str(o.datos.get("banner") or "")
        return self.construir(
            o,
            f"SNMP responde con community por defecto o trivial ({community}). "
            f"Evidencia: {truncar(banner, 200)}",
        )


class ReglaSshAntiguo(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        version = o.datos.get("openssh_version")
        if not version:
            return None
        partes = [int(p) for p in str(version).split(".") if p.isdigit()]
        if not partes:
            return None
        mayor = partes[0]
        menor = partes[1] if len(partes) > 1 else 0
        if mayor > 8 or (mayor == 8 and menor >= 0):
            return None
        banner = str(o.datos.get("banner") or "")
        return self.construir(
            o,
            f"OpenSSH {version} anterior a 8.0. Banner: {truncar(banner, 200)}",
        )


class ReglaPuertoAdministracion(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        puerto = o.datos.get("puerto_administracion")
        if puerto is None:
            return None
        banner = str(o.datos.get("banner") or "")
        nombre = o.datos.get("puerto_administracion_nombre", "administracion")
        return self.construir(
            o,
            f"Puerto de administracion {puerto} ({nombre}) accesible desde la red. "
            f"Evidencia: {truncar(banner, 200) or 'puerto abierto'}",
        )


class ReglaVersionEol(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        eol = o.datos.get("version_eol")
        if not eol:
            return None
        return self.construir(
            o,
            f"Servicio en version sin soporte (EOL): {eol}. "
            f"Evidencia: {truncar(str(o.datos.get('banner') or ''), 200)}",
        )


class ReglaVersionNmapAntigua(Regla):
    """Version de nmap demasiado antigua: limita la fiabilidad del analisis."""

    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        return None  # se evalua a nivel de analisis, no por servicio


# ---- Servicios de datos sin autenticacion ---------------------------------


class ReglaServicioDatosSinAuth(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        db = o.datos.get("db_sin_auth")
        if db:
            return self.construir(
                o,
                f"{db} acepta conexiones sin autenticacion. "
                f"Evidencia: {truncar(str(o.datos.get('banner') or ''), 200)}",
            )
        for clave, nombre in (
            ("db_sin_auth_posible", "MongoDB"),
            ("redis_presente", "Redis"),
            ("rabbitmq_presible", "RabbitMQ"),
            ("elasticsearch_presible", "Elasticsearch"),
        ):
            if o.datos.get(clave):
                return self.construir(
                    o,
                    f"{nombre} expuesto en {o.etiqueta_puerto}; el banner sugiere acceso "
                    f"sin autenticacion. Evidencia: "
                    f"{truncar(str(o.datos.get('banner') or ''), 200) or 'puerto abierto'}",
                )
        return None


# ---- HTTP ----------------------------------------------------------------


class ReglaMetodosHttp(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        http = o.datos.get("http")
        if not isinstance(http, fp.CabecerasHTTP):
            return None
        peligrosos = [m for m in http.metodos if m in ("PUT", "DELETE", "TRACE", "MOVE", "CONNECT")]
        if not peligrosos:
            return None
        return self.construir(
            o,
            f"Metodos HTTP potencialmente peligrosos habilitados: {', '.join(peligrosos)}. "
            f"Metodos observados: {', '.join(http.metodos) or 'n/d'} "
            f"(fuente: {http.metodos_fuente})",
        )


class ReglaRutaSospechosa(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        http = o.datos.get("http")
        if not isinstance(http, fp.CabecerasHTTP):
            return None
        encontradas = fp.evaluar_rutas_sospechosas(o.servicio, http)
        if not encontradas:
            return None
        rutas = ", ".join(ruta for ruta, _d, _s in encontradas)
        severidad_max = max((s for _r, _d, s in encontradas), key=lambda s: ORDEN_SEVERIDAD.index(s))
        regla = self.construir(
            o,
            f"Rutas sensibles localizadas por nmap: {rutas}. "
            f"HTTP {http.codigo or 'n/d'}, Server: {http.servidor or 'n/d'}",
        )
        return Hallazgo(
            titulo=regla.titulo,
            severidad=severidad_max,
            riesgo=regla.riesgo,
            evidencia=regla.evidencia,
            mitigacion=regla.mitigacion,
            host=regla.host,
            puerto=regla.puerto,
            servicio=regla.servicio,
            regla=regla.regla,
            tecnicas=regla.tecnicas,
            falsos_positivos=regla.falsos_positivos,
            categoria="web",
        )


class ReglaCabecerasInseguras(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        http = o.datos.get("http")
        if not isinstance(http, fp.CabecerasHTTP):
            return None
        problemas = fp.evaluar_cabeceras_inseguras(http)
        if not problemas:
            return None
        severidad_max = max((s for _c, _d, s in problemas), key=lambda s: ORDEN_SEVERIDAD.index(s))
        evidencia = (
            f"Server: {http.servidor or 'n/d'} | HTTP {http.codigo or 'n/d'} | "
            f"HSTS: {'si' if http.obtener('strict-transport-security') else 'no'} | "
            f"CSP: {'si' if http.obtener('content-security-policy') else 'no'} | "
            f"XFO: {'si' if http.obtener('x-frame-options') else 'no'} | "
            f"Cookies: {len(http.cookies)}\n"
            + "\n".join(f"- {descripcion} [{nombre}]" for nombre, descripcion, _s in problemas)
        )
        regla = self.construir(o, evidencia)
        return Hallazgo(
            titulo=regla.titulo,
            severidad=severidad_max,
            riesgo=regla.riesgo,
            evidencia=regla.evidencia,
            mitigacion=regla.mitigacion,
            host=regla.host,
            puerto=regla.puerto,
            servicio=regla.servicio,
            regla=regla.regla,
            tecnicas=regla.tecnicas,
            falsos_positivos=regla.falsos_positivos,
            categoria="web",
        )


# ---- TLS -----------------------------------------------------------------


class ReglaTls(Regla):
    def aplicar(self, o: fp.Observacion) -> Optional[Hallazgo]:
        tls = o.datos.get("tls")
        if not isinstance(tls, fp.InfoTLS):
            return None

        problemas: List[Tuple[str, str, str]] = []  # (descripcion, severidad, evidencia)
        if tls.expirado:
            problemas.append((
                "Certificado TLS caducado o fuera de vigencia",
                CRITICA if tls.expirado and tls.autofirmado else ALTA,
                f"valido hasta {tls.valido_hasta or 'n/d'} (hace {abs(tls.dias_para_caducar or 0)} dias)"
                if tls.dias_para_caducar is not None else f"valido hasta {tls.valido_hasta or 'n/d'}",
            ))
        if tls.autofirmado:
            problemas.append((
                "Certificado TLS autofirmado",
                ALTA,
                f"emisor={truncar(tls.emisor, 120) or 'n/d'}",
            ))
        if tls.protocolo_obsoleto:
            problemas.append((
                f"Protocolo obsoleto negociado ({tls.protocolo})",
                ALTA,
                f"protocolo={tls.protocolo} cifrado={tls.cifrado or 'n/d'}",
            ))
        if tls.sni_soportado is False:
            problemas.append((
                "El servidor no soporta SNI (Server Name Indication)",
                MEDIA,
                "respuesta sin indicador de nombre de servidor",
            ))
        if tls.dias_para_caducar is not None and 0 <= tls.dias_para_caducar <= 15:
            problemas.append((
                f"Certificado caduca en {tls.dias_para_caducar} dias",
                MEDIA,
                f"valido hasta {tls.valido_hasta}",
            ))

        if not problemas:
            return None

        severidad_max = max((s for _d, s, _e in problemas), key=lambda s: ORDEN_SEVERIDAD.index(s))
        evidencia = f"{tls.evidencia}\n" + "\n".join(
            f"- {descripcion}: {evid}" for descripcion, _s, evid in problemas
        )
        regla = self.construir(o, truncar(evidencia, 2000))
        return Hallazgo(
            titulo=regla.titulo,
            severidad=severidad_max,
            riesgo=regla.riesgo,
            evidencia=regla.evidencia,
            mitigacion=regla.mitigacion,
            host=regla.host,
            puerto=regla.puerto,
            servicio=regla.servicio,
            regla=regla.regla,
            tecnicas=regla.tecnicas,
            falsos_positivos=regla.falsos_positivos,
            categoria="criptografia",
        )


# --------------------------------------------------------------------------
# Catalogo de reglas
# --------------------------------------------------------------------------

CATALOGO_REGLAS: Tuple[Regla, ...] = (
    ReglaTelnetAbierto(
        identificador="TELNET_ABIERTO",
        titulo="Telnet (23) abierto: credenciales en claro",
        severidad=CRITICA,
        riesgo="Telnet transmite usuario y contrasena sin cifrar. Cualquiera en el mismo "
               "segmento de red puede capturarlos con un simple sniffer y reutilizarlos "
               "en otros servicios. Es la causa mas directa de compromiso posterior.",
        mitigacion="Desactiva Telnet y usa SSH (puerto 22). Si el servicio es legacy, "
                   "restringe el acceso por firewall a una IP de administracion y migra "
                   "a un tunel SSH o VPN.",
        falsos_positivos="Ninguno relevante: la exposicion del puerto 23 es objetiva. "
                        "El impacto real depende de la topologia de red.",
        tecnicas=(
            TecnicaATTACK("T1046", "Network Service Discovery", "Discovery"),
            TecnicaATTACK("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
        ),
    ),
    ReglaFtpAnonimo(
        identificador="FTP_ANONIMO",
        titulo="FTP con acceso anonimo habilitado",
        severidad=ALTA,
        riesgo="El acceso anonimo permite a cualquier atacante listar, leer y a menudo "
               "subir ficheros en el servidor sin ninguna credencial. Es un punto de "
               "entrada trivial para distribuir malware o reemplazar contenido.",
        mitigacion="Desactiva el login anonimo (anonymous_enable NO en vsftpd, "
                   "prohibit_anonymous in ProFTPD) y autentica con credenciales "
                   "individuales. Revisa si habia contenido publicado en el arbol anonimo.",
        falsos_positivos="Un banner 220 que menciona 'anonymous' puede indicar solo "
                        "propaganda del producto y no acceso real. nmap no confirma el "
                        "login salvo que se ejecute el script ftp-anon; verifica manualmente.",
        tecnicas=(
            TecnicaATTACK("T1190", "Exploit Public-Facing Application", "Initial Access"),
            TecnicaATTACK("T1083", "File and Directory Discovery", "Discovery"),
        ),
        categoria="autenticacion",
    ),
    ReglaFtpSinTls(
        identificador="FTP_SIN_TLS",
        titulo="FTP sin TLS: transferencia de datos sin cifrar",
        severidad=ALTA,
        riesgo="Los datos, incluidas las credenciales, viajan en claro. Cualquier "
               "atacante con acceso a la red puede interceptarlos o modificarlos.",
        mitigacion="Activa AUTH TLS/STARTTLS o sustituye FTP por SFTP (que viaja sobre "
                   "SSH). Como alternativa, restringe el puerto 21 con TLS-required.",
        falsos_positivos="Algunos servidores FTP soportan TLS pero no lo anuncian en el "
                        "banner. Verifica con 'openssl s_client -starttls ftp -connect HOST:21'.",
        tecnicas=(TecnicaATTACK("T1040", "Network Sniffing", "Credential Access"),),
        categoria="criptografia",
    ),
    ReglaSmbSinCifrado(
        identificador="SMB_SIN_CIFRADO",
        titulo="SMB expuesto sin cifrado de transporte",
        severidad=ALTA,
        riesgo="SMBv2/v3 sin cifrado permite capturar credenciales yManipular trafico. "
               "En redes con transito hostil equivale a entregar el acceso al sistema.",
        mitigacion="Exige SMB3 con cifrado obligatorio, desactiva SMBv1, restringe el "
                   "puerto 445 a las redes de administracion y segmenta con firewall.",
        falsos_positivos="La deteccion se basa en la version de SMB y el cifrado "
                        "anunciado; un servidor puede anunciar cifrado y aplicarlo solo "
                        "parcialmente. Verifica la configuracion real de comparticion.",
        tecnicas=(TecnicaATTACK("T1040", "Network Sniffing", "Credential Access"),),
        categoria="criptografia",
    ),
    ReglaSmbv1(
        identificador="SMBV1",
        titulo="SMBv1 habilitado: vulnerable a EternalBlue y a ransomware tipo WannaCry",
        severidad=CRITICA,
        riesgo="SMBv1 esta sin soporte desde 2016 y es el vector de EternalBlue "
               "(MS17-010) y de los ransomware WannaCry/NotPetya. Su presencia en un "
               "servidor significa que un parche ausente puede derivar en ejecucion "
               "remota de codigo.",
        mitigacion="Desactiva SMBv1 en el servidor y en el cliente (Set-SmbServerConfiguration "
                   "-EnableSMB1Protocol $false / registry Smb1). Aplica los parches MS17-010. "
                   "No necesitas SMBv1 para nada soportado hoy.",
        falsos_positivos="'NT LM 0.12' puede aparecer en la salida de algunos scripts "
                        "como indicador de dialecto del cliente, no del servidor. Confirma "
                        "con 'nmap --script smb-protocols -p 445'.",
        tecnicas=(
            TecnicaATTACK("T1210", "Exploitation of Remote Services", "Lateral Movement"),
            TecnicaATTACK("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
        ),
    ),
    ReglaSnmpDebil(
        identificador="SNMP_COMMUNITY_DEBIL",
        titulo="SNMPv1/v2c con community publica o privada",
        severidad=CRITICA,
        riesgo="Las community por defecto permiten leer y modificar el MIB completo del "
               "dispositivo: usuarios, interfaces, tabla deARP y, con la community "
               "'private', la configuracion completa. Es una de las Disclosure "
               "Information mas graves en redes corporativas.",
        mitigacion="Migra a SNMPv3 con autenticacion (authPriv) y cifra con AES. Elimina "
                   "las community public/private. Si no puedes migrar ya, restringe el "
                   "puerto 161 por ACL a las IPs del sistema de monitorizacion.",
        falsos_positivos="Un banner con la palabra 'public' puede ser la descripcion del "
                        "producto y no una community aceptada. Confirma con "
                        "'snmpwalk -v2c -c public HOST' y revisa que la consulta responde "
                        "con datos reales del MIB.",
        tecnicas=(
            TecnicaATTACK("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),
            TecnicaATTACK("T1087", "Account Discovery", "Discovery"),
            TecnicaATTACK("T1049", "System Network Connections Discovery", "Discovery"),
        ),
        categoria="autenticacion",
    ),
    ReglaSshAntiguo(
        identificador="SSH_VERSION_ANTIGUA",
        titulo="OpenSSH con version anterior a 8.0",
        severidad=MEDIA,
        riesgo="Las ramas antiguas de OpenSSH acumulan vulnerabilidades publicadas y "
               "dejan de recibir parches. Un banner de version es, ademas, una fuga de "
               "informacion que permite elegir el exploit adecuado.",
        mitigacion="Actualiza OpenSSH a una rama mantenida (9.x o superior). Configura "
                   "'PasswordAuthentication no' y 'PermitRootLogin no' en sshd_config, "
                   "y filtra el banner con 'DebianBanner no' si es posible.",
        falsos_positivos="El banner puede anunciar una version superada por el backport "
                        "del fabricante (por ejemplo Ubuntu parchea sin cambiar la "
                        "version). Verifica el aviso de seguridad del paquete antes de "
                        "priorizar.",
        tecnicas=(TecnicaATTACK("T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance"),),
        categoria="software",
    ),
    ReglaPuertoAdministracion(
        identificador="PUERTO_ADMIN_EXPUESTO",
        titulo="Puerto de administracion expuesto en la red",
        severidad=ALTA,
        riesgo="Paneles de administracion (ActiveMQ, GlassFish, Kubernetes API, Docker "
               "Remote API sin TLS) suelen traer credenciales por defecto oFeatures sin "
               "autenticacion. Docker en 2375 sin TLS equivale a acceso de root total "
               "en el host.",
        mitigacion="Mueve estos puertos a una interfaz de administracion, restringelos por "
                   "firewall/VPN y exige autenticacion fuerte. En 2375 activa TLS o "
                   "elimina el socket sin protección. Protege 6443 con RBAC y MFA.",
        falsos_positivos="El puerto puede estar abierto pero exigir autenticacion valida. "
                        "La severidad ALTA indica exposicion de superficie, no compromiso "
                        "demostrado. Confirma la politica de autenticacion.",
        tecnicas=(
            TecnicaATTACK("T1190", "Exploit Public-Facing Application", "Initial Access"),
            TecnicaATTACK("T1133", "External Remote Services", "Initial Access"),
        ),
        categoria="exposicion",
    ),
    ReglaServicioDatosSinAuth(
        identificador="SERVICIO_DATOS_SIN_AUTH",
        titulo="Base de datos o broker expuesto sin autenticacion",
        severidad=CRITICA,
        riesgo="MySQL, MongoDB, Redis, RabbitMQ o Elasticsearch sin autenticacion "
               "permiten leer, modificar o borrar la informacion almacenada. Redis sin "
               "password permite además escribir claves y ejecutar modulos en versiones "
               "afectadas. Es acceso directo a datos de negocio.",
        mitigacion="Activa la autenticacion en el servicio (requirepass en Redis, "
                   "auth en MongoDB, usuario/clave en MySQL), enlaza el servicio a "
                   "localhost o a una red interna y filtra el puerto por ACL.",
        falsos_positivos="La deteccion se basa en el banner. Un servicio puede anunciar "
                        "version y responder 'NOAUTH/ERR' real sin ser accesible: en ese "
                        "caso el banner se interpreta como exposicion potencial, no como "
                        "acceso confirmado. Verifica con una conexion de solo lectura "
                        "en una ventana autorizada.",
        tecnicas=(
            TecnicaATTACK("T1190", "Exploit Public-Facing Application", "Initial Access"),
            TecnicaATTACK("T1213", "Data from Information Repositories", "Collection"),
        ),
        categoria="autenticacion",
    ),
    ReglaMetodosHttp(
        identificador="HTTP_METODOS_PELIGROSOS",
        titulo="Metodos HTTP PUT/DELETE/TRACE habilitados",
        severidad=MEDIA,
        riesgo="PUT y DELETE permiten escribir o borrar contenido sin pasar por el flujo "
               "normal; TRACE puede devolver cabeceras internas y facilitating XST. En "
               "servidores mal configurados, PUT permite subir un web shell.",
        mitigacion="Restringe los metodos permitidos en el servidor web (Allow GET, HEAD "
                   "en Apache/Nginx; limit_except en Apache). Desactiva TRACE si no es "
                   "necesario y revisa permisos de escritura en el directorio web.",
        falsos_positivos="nmap puede reportar metodos a partir de respuestas 405 (Method "
                        "Not Allowed), que en realidad indica que estan bloqueados. "
                        "Comprueba el codigo de respuesta antes de concluir.",
        tecnicas=(TecnicaATTACK("T1190", "Exploit Public-Facing Application", "Initial Access"),),
        categoria="web",
    ),
    ReglaRutaSospechosa(
        identificador="HTTP_RUTA_SENSIBLE",
        titulo="Rutas sensibles accesibles en el servidor web",
        severidad=ALTA,
        riesgo="La presencia de /.env, /.git o /actuator/env permite obtener secretos, "
               "codigo fuente completo o la configuracion de la aplicacion. /.git expone "
               "el historico y las credenciales commiteadas; /.env suele contener "
               "claves de base de datos y tokens.",
        mitigacion="Elimina /.git, /.env y los paneles de administracion del arbol "
                   "publico o bloquealos en el servidor web y en el WAF. Rota cualquier "
                   "secreto que haya podido quedar exposed y anade comprobaciones en CI "
                   "para impedir nuevos secretos en el repositorio.",
        falsos_positivos="La deteccion depende de que nmap haya ejecutado los scripts "
                        "http-* y de que la ruta aparezca en su salida. Un 404 real no "
                        "se reporta. Confirma siempre el codigo de respuesta antes de "
                        "escalar el hallazgo.",
        tecnicas=(
            TecnicaATTACK("T1190", "Exploit Public-Facing Application", "Initial Access"),
            TecnicaATTACK("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),
            TecnicaATTACK("T1083", "File and Directory Discovery", "Discovery"),
        ),
        categoria="web",
    ),
    ReglaCabecerasInseguras(
        identificador="HTTP_CABECERAS_INSEGURAS",
        titulo="Cabeceras HTTP de seguridad ausentes o inseguras",
        severidad=MEDIA,
        riesgo="La ausencia de HSTS, CSP, X-Frame-Options y nosniff, junto con cookies sin "
               "Secure/HttpOnly y un Server que expone la version, facilita XSS, "
               "clickjacking y robo de sesion, y reduce la dificultad del atacante.",
        mitigacion="Anade Strict-Transport-Security (tras confirmar HTTPS completo), "
                   "Content-Security-Policy, X-Frame-Options: DENY o frame-ancestors, "
                   "X-Content-Type-Options: nosniff, y marca las cookies con Secure y "
                   "HttpOnly. Oculta la version en la cabecera Server.",
        falsos_positivos="Estas cabeceras solo tienen efecto si el resto de la "
                        "configuracion es coherente. HSTS solo aplica si todo el sitio "
                        "es HTTPS. El impacto real depende de si existe XSS en la "
                        "aplicacion.",
        tecnicas=(TecnicaATTACK("T1189", "Drive-by Compromise", "Initial Access"),),
        categoria="web",
    ),
    ReglaTls(
        identificador="TLS_DEBIL",
        titulo="Configuracion TLS insegura o certificado invalido",
        severidad=ALTA,
        riesgo="Un certificado caducado o autofirmado provoca advertencias en el "
               "navegador y forma parte de cadenas de interceptacion. TLSv1.0/1.1 y "
               "SSLv3 tienen ataques conocidos (POODLE, BEAST, DROWN). La ausencia de "
               "SNI impide alojar varios virtual hosts correctamente.",
        mitigacion="Emite el certificado desde una CA de confianza (o Let's Encrypt) y "
                   "renueva antes de caducar. Desactiva SSLv2/SSLv3, TLSv1.0 y TLSv1.1; "
                   "habilita TLSv1.2/1.3 con cifrados AEAD. Configura SNI en el servidor.",
        falsos_positivos="El script ssl-cert puede no incluir todos los datos de "
                        "validez o el banner puede indicar un certificado distinto del "
                        "servido por defecto en cada virtual host. Verifica con "
                        "'openssl s_client' antes de actuar.",
        tecnicas=(TecnicaATTACK("T1040", "Network Sniffing", "Credential Access"),),
        categoria="criptografia",
    ),
    ReglaVersionEol(
        identificador="VERSION_EOL",
        titulo="Servicio en version sin soporte (EOL)",
        severidad=MEDIA,
        riesgo="Un producto en fin de vida no recibe parches de seguridad, incluidos los "
               "de clientes TLS. Cualquier vulnerabilidad futura queda sin corregir de "
               "forma permanente.",
        mitigacion="Migra a una version mantenida del producto o a un equivalente soportado. "
                   "Si no es posible a corto plazo, aísla el servicio con firewall y "
                   "monitorea con reglas de deteccion específicas.",
        falsos_positivos="La deteccion se basa en cadenas de texto en el banner y puede "
                        "confundir versiones de backport o distribuciones que ya "
                        "parchean. Verifica el estado real con el fabricante.",
        tecnicas=(TecnicaATTACK("T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance"),),
        categoria="software",
    ),
)


def reglas_por_identificador() -> Dict[str, Regla]:
    return {regla.identificador: regla for regla in CATALOGO_REGLAS}


# --------------------------------------------------------------------------
# Ejecucion del motor
# --------------------------------------------------------------------------


def evaluar(resultado: ResultadoEscaneo) -> List[Hallazgo]:
    """Aplica todas las reglas sobre el resultado y devuelve los hallazgos."""
    observaciones = fp.analizar_servicios(resultado)
    hallazgos: List[Hallazgo] = []

    for observacion in observaciones:
        for regla in CATALOGO_REGLAS:
            try:
                hallazgo = regla.aplicar(observacion)
            except Exception as exc:  # una regla rota no debe tumbar el analisis
                LOG.warning(
                    "La regla %s fallo sobre %s: %s",
                    getattr(regla, "identificador", "?"),
                    observacion.host.direccion,
                    exc,
                )
                continue
            if hallazgo is not None:
                hallazgos.append(hallazgo)

    hallazgos.extend(_evaluar_entorno(resultado))
    hallazgos.sort(key=lambda h: (h.severidad_orden, h.host, h.puerto))
    return hallazgos


def _evaluar_entorno(resultado: ResultadoEscaneo) -> List[Hallazgo]:
    """Hallazgos sobre la propia ejecucion del analisis (no del objetivo)."""
    from .osdetect import VERSI_MINIMA_NMAP

    hallazgos: List[Hallazgo] = []
    version_texto = resultado.nmap_version or ""

    coincidencia = re.search(r"(\d+)\.(\d+)", version_texto)
    if not coincidencia:
        return hallazgos

    tupla = (int(coincidencia.group(1)), int(coincidencia.group(2)))
    if tupla >= VERSI_MINIMA_NMAP:
        return hallazgos

    minima = ".".join(str(n) for n in VERSI_MINIMA_NMAP)
    hallazgos.append(
        Hallazgo(
            titulo="Version de nmap anterior a la minima recomendada",
            severidad=INFO,
            riesgo=f"nmap {tupla[0]}.{tupla[1]} es anterior a {minima}. Las detecciones "
                   "de servicio y los scripts NSE pueden fallar, por lo que el informe "
                   "puede contener falsos negativos.",
            evidencia=f"nmap --version: {version_texto}",
            mitigacion=f"Actualiza nmap a {minima} o superior antes de repetir el escaneo "
                       "para obtener resultados fiables.",
            regla="NMAP_VERSION_ANTIGUA",
            puerto="n/a",
            servicio="nmap",
            host="herramienta",
            falsos_positivos="Ninguno: la version se lee directamente de la salida de "
                            "'nmap --version'.",
            categoria="calidad",
            tecnicas=(),
        )
    )
    return hallazgos


def ordenar_hallazgos(hallazgos: Sequence[Hallazgo]) -> List[Hallazgo]:
    return sorted(hallazgos, key=lambda h: (h.severidad_orden, h.host, h.puerto, h.titulo))
