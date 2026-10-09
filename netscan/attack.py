"""Mapeo de hallazgos a tecnicas MITRE ATT&CK Enterprise y caminos de ataque.

Este modulo NO contiene tecnicas ofensivas: solo clasifica los hallazgos de
evaluacion defensiva en el marco publico de MITRE ATT&CK para que el equipo
pueda priorizarlos y relacionarlos con su deteccion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .utils import obtener_logger

LOG = obtener_logger("attack")

# Orden canonico de las tacticas Enterprise (13 columnas de la matriz).
TACTICAS: Tuple[str, ...] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)

# Descripcion breve de cada tactica, para la leyenda del reporte.
DESCRIPCION_TACTICA = {
    "Reconnaissance": "Recopilar informacion sobre el objetivo antes de tocarlo.",
    "Resource Development": "Preparar infraestructura, cuentas o recursos para el ataque.",
    "Initial Access": "Entrar en la red o en el sistema.",
    "Execution": "Ejecutar codigo en el sistema comprometido.",
    "Persistence": "Mantener el acceso tras el compromiso.",
    "Privilege Escalation": "Ganar mas privilegios dentro del sistema.",
    "Defense Evasion": "Evadir deteccion y defensa.",
    "Credential Access": "Robar credenciales.",
    "Discovery": "Enumerar la red y el sistema interno.",
    "Lateral Movement": "Moverse a otros sistemas de la red.",
    "Collection": "Reunir datos de valor.",
    "Command and Control": "Comunicar con la infraestructura atacante.",
    "Exfiltration": "Sacar datos de la organizacion.",
    "Impact": "Causar dano: cifrado, destruccion, denegacion de servicio.",
}


@dataclass(frozen=True)
class TecnicaATTACK:
    """Una tecnica MITRE ATT&CK Enterprise."""

    identificador: str
    nombre: str
    tactica: str
    justificacion: str = ""

    def a_dict(self) -> Dict[str, str]:
        """Representacion plana de la tecnica para el JSON del reporte."""
        return {
            "id": self.identificador,
            "nombre": self.nombre,
            "tactica": self.tactica,
            "justificacion": self.justificacion or (
                f"La exposicion detectada habilita la tecnica {self.identificador} "
                f"({self.nombre}) dentro de la tactica {self.tactica}."
            ),
        }


@dataclass
class NodoMatriz:
    """Una celda de la matriz: tecnica + hallazgos que la sustentan."""

    tecnica: TecnicaATTACK
    hallazgos: List[object] = None  # type: ignore[assignment]
    hosts: Set[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.hallazgos is None:
            self.hallazgos = []
        if self.hosts is None:
            self.hosts = set()

    @property
    def severidad_maxima(self) -> str:
        """Severidad mas grave entre los hallazgos de la celda."""
        from .vulns import ORDEN_SEVERIDAD

        if not self.hallazgos:
            return "INFO"
        return min(
            (getattr(h, "severidad", "INFO") for h in self.hallazgos),
            key=lambda s: ORDEN_SEVERIDAD.index(s) if s in ORDEN_SEVERIDAD else 99,
        )

    def a_dict(self) -> Dict[str, object]:
        """Representacion plana del nodo de matriz para el JSON."""
        from .vulns import PESO_SEVERIDAD

        return {
            "tecnica": self.tecnica.a_dict(),
            "severidad_maxima": self.severidad_maxima,
            "hosts": sorted(self.hosts),
            "hallazgos": [
                {
                    "titulo": getattr(h, "titulo", ""),
                    "severidad": getattr(h, "severidad", ""),
                    "host": getattr(h, "host", ""),
                    "puerto": getattr(h, "puerto", ""),
                }
                for h in self.hallazgos
            ],
            "peso": sum(
                PESO_SEVERIDAD.get(getattr(h, "severidad", "INFO"), 0)
                for h in self.hallazgos
            ),
        }


@dataclass
class CaminoAtaque:
    """Una cadena logica de hallazgos que forma un camino de ataque probable."""

    titulo: str
    pasos: List[str]
    tecnicas: List[str]
    hosts: List[str]
    severidad: str
    impacto: str

    def a_dict(self) -> Dict[str, object]:
        """Representacion plana del camino de ataque para el JSON."""
        return {
            "titulo": self.titulo,
            "pasos": list(self.pasos),
            "tecnicas": list(self.tecnicas),
            "hosts": list(self.hosts),
            "severidad": self.severidad,
            "impacto": self.impacto,
        }


# --------------------------------------------------------------------------
# Construccion de la matriz
# --------------------------------------------------------------------------


def construir_matriz(hallazgos: Sequence[object]) -> List[NodoMatriz]:
    """Agrupa los hallazgos por tecnica ATT&CK."""
    indice: Dict[str, NodoMatriz] = {}
    for hallazgo in hallazgos:
        for tecnica in getattr(hallazgo, "tecnicas", []) or []:
            clave = tecnica.identificador
            if clave not in indice:
                indice[clave] = NodoMatriz(tecnica=tecnica)
            indice[clave].hallazgos.append(hallazgo)
            host = getattr(hallazgo, "host", "")
            if host:
                indice[clave].hosts.add(host)
    return list(indice.values())


def agrupar_por_tactica(matriz: Sequence[NodoMatriz]) -> Dict[str, List[NodoMatriz]]:
    """Agrupa los nodos por columna de tactica, en el orden canonico."""
    agrupado: Dict[str, List[NodoMatriz]] = {tactica: [] for tactica in TACTICAS}
    for nodo in matriz:
        tactica = nodo.tecnica.tactica
        if tactica not in agrupado:
            agrupado[tactica] = []
        agrupado[tactica].append(nodo)
    return agrupado


# --------------------------------------------------------------------------
# Caminos de ataque probables
# --------------------------------------------------------------------------


def _hallazgos_con_regla(hallazgos: Sequence[object], *reglas: str) -> List[object]:
    reglas = set(reglas)
    return [h for h in hallazgos if getattr(h, "regla", "") in reglas]


def _hosts_de(hallazgos: Iterable[object]) -> List[str]:
    return sorted({getattr(h, "host", "") for h in hallazgos if getattr(h, "host", "")})


def generar_caminos_ataque(hallazgos: Sequence[object]) -> List[CaminoAtaque]:
    """Construye cadenas logicas a partir de combinaciones de hallazgos.

    Son RAZONAMIENTOS sobre la exposicion observada, no predicciones ni
    actividades ofensivas. Sirven para priorizar.
    """
    caminos: List[CaminoAtaque] = []

    paneles = _hallazgos_con_regla(
        hallazgos, "PUERTO_ADMIN_EXPUESTO", "HTTP_RUTA_SENSIBLE"
    )
    datos_sin_auth = _hallazgos_con_regla(hallazgos, "SERVICIO_DATOS_SIN_AUTH")
    smbv1 = _hallazgos_con_regla(hallazgos, "SMBV1")
    snmp = _hallazgos_con_regla(hallazgos, "SNMP_COMMUNITY_DEBIL")
    credenciales_claro = _hallazgos_con_regla(
        hallazgos, "TELNET_ABIERTO", "FTP_SIN_TLS", "SMB_SIN_CIFRADO"
    )
    ftp_anon = _hallazgos_con_regla(hallazgos, "FTP_ANONIMO")
    tls_debil = _hallazgos_con_regla(hallazgos, "TLS_DEBIL")
    web_debil = _hallazgos_con_regla(hallazgos, "HTTP_CABECERAS_INSEGURAS", "HTTP_METODOS_PELIGROSOS")

    # 1) Panel expuesto -> credencial debil -> movimiento lateral
    if paneles and credenciales_claro:
        hosts = sorted(set(_hosts_de(paneles)) | set(_hosts_de(credenciales_claro)))
        caminos.append(
            CaminoAtaque(
                titulo="Panel de administracion expuesto + credenciales en claro",
                pasos=[
                    f"1) Panel o ruta de administracion accesible: {', '.join(sorted(set(_hosts_de(paneles)))) or 'n/d'}",
                    "2) La ausencia de cifrado permite capturar credenciales validas en transito",
                    "3) Esas credenciales se reutilizan en el panel y en el resto de la red",
                    "4) Acceso administrativo obtenido en uno o varios sistemas",
                ],
                tecnicas=["T1133", "T1040", "T1078"],
                hosts=hosts,
                severidad="CRITICA",
                impacto="Compromiso administrativo de los hosts implicados con alta "
                        "probabilidad, sin necesidad de exploits.",
            )
        )

    # 2) Panel expuesto -> base de datos sin autenticacion -> exfiltracion
    if paneles and datos_sin_auth:
        hosts = sorted(set(_hosts_de(paneles)) | set(_hosts_de(datos_sin_auth)))
        pasos = [
            f"1) Servicio de administracion expuesto: {', '.join(sorted(set(_hosts_de(paneles)))) or 'n/d'}",
            f"2) Base de datos o broker sin autenticacion: {', '.join(sorted(set(_hosts_de(datos_sin_auth)))) or 'n/d'}",
            "3) Acceso directo de lectura y escritura a la informacion almacenada",
            "4) Recoleccion y posible exfiltracion de datos de negocio",
        ]
        caminos.append(
            CaminoAtaque(
                titulo="Servicio expuesto + almacenamiento sin autenticacion",
                pasos=pasos,
                tecnicas=["T1190", "T1213"],
                hosts=hosts,
                severidad="CRITICA",
                impacto="Acceso directo a datos: lectura, modificacion o borrado de "
                        "informacion de negocio.",
            )
        )

    # 3) SNMP -> inventario completo -> descubrimiento ->Credentials en otros sistemas
    if snmp and (paneles or datos_sin_auth or credenciales_claro):
        objetivo = paneles or datos_sin_auth or credenciales_claro
        pasos = [
            f"1) SNMPv1/v2c con community trivial: {', '.join(_hosts_de(snmp)) or 'n/d'}",
            "2) El MIB revela usuarios, interfaces, ARP y vecindad de red",
            "3) Ese inventario permite elegir el objetivo mas debil",
            f"4) Ataque dirigido a: {', '.join(sorted(set(_hosts_de(objetivo)))) or 'n/d'}",
        ]
        caminos.append(
            CaminoAtaque(
                titulo="SNMP con community por defecto como reconocimiento",
                pasos=pasos,
                tecnicas=["T1552.001", "T1087", "T1049", "T1190"],
                hosts=sorted(set(_hosts_de(snmp)) | set(_hosts_de(objetivo))),
                severidad="ALTA",
                impacto="Mapa completo de la red y de los dispositivos de "
                        "autenticacion, que reduce drásticamente el esfuerzo del atacante.",
            )
        )

    # 4) SMBv1 -> explotacion remota -> movimiento lateral
    if smbv1:
        pasos = [
            f"1) SMBv1 habilitado en: {', '.join(_hosts_de(smbv1)) or 'n/d'}",
            "2) SMBv1 sin parchear es vulnerable a explotacion remota (MS17-010)",
            "3) Ejecucion de codigo en el sistema comprometido",
            "4) Uso de recursos compartidos o credenciales para moverse lateralmente",
        ]
        caminos.append(
            CaminoAtaque(
                titulo="SMBv1 como punto de entrada y movimiento lateral",
                pasos=pasos,
                tecnicas=["T1210", "T1021.002", "T1059.001"],
                hosts=_hosts_de(smbv1),
                severidad="CRITICA",
                impacto="Ejecucion remota de codigo y propagacion lateral automatica "
                        "a otros sistemas Windows de la red.",
            )
        )

    # 5) FTP anonimo -> lectura de ficheros -> secrets -> otras credenciales
    if ftp_anon:
        pasos = [
            f"1) FTP anonimo en: {', '.join(_hosts_de(ftp_anon)) or 'n/d'}",
            "2) Listado y lectura de ficheros publicados sin credencial",
            "3) Posible obtencion de codigo fuente, configuraciones o ficheros de credenciales",
            "4) Reutilizacion de los secretos obtenidos en otros servicios",
        ]
        caminos.append(
            CaminoAtaque(
                titulo="FTP anonimo como fuente de secretos",
                pasos=pasos,
                tecnicas=["T1083", "T1552.001", "T1213"],
                hosts=_hosts_de(ftp_anon),
                severidad="ALTA",
                impacto="Fuga de configuracion y credenciales reutilizables en otros "
                        "servicios de la organizacion.",
            )
        )

    # 6) TLS/ cifrado debil -> interceptacion -> credenciales
    if tls_debil:
        pasos = [
            f"1) TLS inseguro en: {', '.join(_hosts_de(tls_debil)) or 'n/d'}",
            "2) Protocolos obsoletos o certificados invalidos en transito",
            "3) Posibilidad de interceptar el trafico o de generar advertencias ignoradas",
            "4) Credenciales de sesion capturadas en el trafico",
        ]
        caminos.append(
            CaminoAtaque(
                titulo="Cifrado debil habilitando interceptacion",
                pasos=pasos,
                tecnicas=["T1040", "T1557"],
                hosts=_hosts_de(tls_debil),
                severidad="ALTA",
                impacto="Credenciales y datos de sesion expuestos a cualquier atacante "
                        "en la misma red.",
            )
        )

    # 7) Web debil + panel expuesto: drive-by sobre el panel interno
    if web_debil and paneles:
        pasos = [
            f"1) Aplicacion web con cabeceras y metodos inseguros: {', '.join(sorted(set(_hosts_de(web_debil)))) or 'n/d'}",
            f"2) Rutas o puertos de administracion accesibles: {', '.join(sorted(set(_hosts_de(paneles)))) or 'n/d'}",
            "3) Un XSS o clickjacking sobre la aplicacion lleva a la sesion administrativa",
            "4) Control de la aplicacion y de los datos que manages",
        ]
        caminos.append(
            CaminoAtaque(
                titulo="Debilidades web como via hacia el panel de administracion",
                pasos=pasos,
                tecnicas=["T1189", "T1539", "T1190"],
                hosts=sorted(set(_hosts_de(web_debil)) | set(_hosts_de(paneles))),
                severidad="MEDIA",
                impacto="Toma de control de la aplicacion web y de los datos que "
                        "procesa, a traves de la sesion de un administrador.",
            )
        )

    orden = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3, "INFO": 4}
    caminos.sort(key=lambda c: orden.get(c.severidad, 9))
    return caminos


# --------------------------------------------------------------------------
# Resumen para el reporte
# --------------------------------------------------------------------------


def construir_informe_attack(hallazgos: Sequence[object]) -> Dict[str, object]:
    """Estructura completa de la seccion ATT&CK, lista para el reporte."""
    matriz = construir_matriz(hallazgos)
    agrupado = agrupar_por_tactica(matriz)
    caminos = generar_caminos_ataque(hallazgos)
    tecnicas_totales: Set[str] = {n.tecnica.identificador for n in matriz}

    return {
        "matriz": [nodo.a_dict() for nodo in matriz],
        "por_tactica": {
            tactica: [nodo.a_dict() for nodo in nodos]
            for tactica, nodos in agrupado.items()
        },
        "caminos_ataque": [camino.a_dict() for camino in caminos],
        "tecnicas_totales": sorted(tecnicas_totales),
        "tacticas_alcanzadas": sorted(
            {n.tecnica.tactica for n in matriz if n.tecnica.tactica in TACTICAS}
        ),
        "total_tecnicas": len(tecnicas_totales),
    }
