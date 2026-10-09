"""Deteccion del sistema operativo y gestion de la dependencia obligatoria nmap.

nmap es una dependencia OBLIGATORIA. No existe modo reducido, ni simulacion,
ni fallback pasivo: sin nmap el programa no puede escanear y termina con
codigo de salida 2.

La ruta de nmap se resuelve SIEMPRE con shutil.which en cada invocacion de
`resolver_nmap()`, nunca se cachea: si el usuario instala nmap en el PATH
desde otra terminal, la siguiente invocacion lo detecta correctamente.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional

from .utils import Consola, leer_linea, obtener_logger, stdin_interactivo

LOG = obtener_logger("osdetect")

VERSI_MINIMA_NMAP = (7, 80)
CODIGO_SIN_DEPENDENCIA = 2

# Opciones del menu de SO solicitadas por el usuario.
SO_WINDOWS = "windows"
SO_LINUX = "linux"
SO_MACOS = "macos"
SO_OTRO = "otro"

_ETIQUETA_SO = {
    SO_WINDOWS: "Windows",
    SO_LINUX: "Linux",
    SO_MACOS: "macOS",
    SO_OTRO: "Otro",
}

# Rutas habituales de instalacion de nmap en Windows (no siempre estan en PATH).
RUTAS_NMAP_WINDOWS = (
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Nmap",
)

# Comandos de instalacion listos para copiar, por sistema operativo.
COMANDOS_INSTALACION = {
    SO_WINDOWS: [
        "winget install Insecure.Nmap",
        "Descargalo desde https://nmap.org/download.html y ejecuta el instalador como administrador",
    ],
    SO_LINUX: [
        "sudo apt install nmap        # Debian / Ubuntu / Kali",
        "sudo dnf install nmap        # Fedora / RHEL",
        "sudo pacman -S nmap          # Arch / Manjaro",
    ],
    SO_MACOS: [
        "brew install nmap            # Homebrew",
    ],
    SO_OTRO: [
        "Compila o instala nmap >= 7.80 desde https://nmap.org/download.html",
        "Asegurate de que el binario 'nmap' quede en tu PATH",
    ],
}


class NmapNoDisponible(RuntimeError):
    """nmap no esta instalado, no responde o es demasiado antiguo.

    Se propaga con el mensaje exacto requerido: "nmap no esta instalado".
    """

    def __init__(self, mensaje: str = "nmap no esta instalado", detalles: Optional[str] = None):
        super().__init__(mensaje)
        self.detalles = detalles


# ---------------------------------------------------------------------------
# Deteccion de SO
# ---------------------------------------------------------------------------


def detectar_so() -> str:
    """Devuelve una de las claves: windows / linux / macos / otro."""
    plataforma = sys.platform.casefold()
    if plataforma.startswith("win") or os.name == "nt":
        return SO_WINDOWS
    if plataforma.startswith("darwin"):
        return SO_MACOS
    if plataforma.startswith("linux"):
        return SO_LINUX
    return SO_OTRO


@dataclass(frozen=True)
class InfoSistema:
    """Informacion del sistema operativo y de Python detectada."""

    clave_so: str
    nombre_so: str
    plataforma: str
    version: str
    python: str

    @property
    def requiere_sudo_para_syn(self) -> bool:
        """-sS (SYN scan) necesita root en macOS/Linux."""
        return self.clave_so in (SO_LINUX, SO_MACOS)

    @property
    def es_windows(self) -> bool:
        return self.clave_so == SO_WINDOWS


def obtener_info_sistema(clave_so: Optional[str] = None) -> InfoSistema:
    """Informacion del sistema operativo y de Python. Sin argumentos, detecta el SO real."""
    clave = clave_so or detectar_so()
    return InfoSistema(
        clave_so=clave,
        nombre_so=_ETIQUETA_SO.get(clave, "Otro"),
        plataforma=platform.system(),
        version=platform.release(),
        python=platform.python_version(),
    )


def mostrar_menu_so(consola: Consola) -> Optional[str]:
    """Muestra el menu [1] Windows [2] Linux [3] macOS [4]Otro.

    El menu NO simula ejecucion: un SO distinto del real solo cambia los
    comandos de instalacion que se muestran y las diferencias de ejecucion
    documentadas. Devuelve la clave elegida, o None si el usuario cancela.
    """
    real = obtener_info_sistema()
    consola.titulo("Seleccion de sistema operativo")
    consola.info(f"SO detectado automaticamente: {real.nombre_so} ({real.plataforma} {real.version})")
    consola.aviso("Esta opcion NO cambia el sistema real. Solo ajusta los comandos de")
    consola.aviso("instalacion que se muestran y las diferencias de ejecucion (sudo, rutas).")
    consola.escribir("")
    opciones = [
        ("1", SO_WINDOWS, "winget / instalador .exe (requiere administrador)"),
        ("2", SO_LINUX, "apt / dnf / pacman"),
        ("3", SO_MACOS, "Homebrew (brew)"),
        ("4", SO_OTRO, "compilacion manual u otro gestor de paquetes"),
    ]
    for numero, clave, nota in opciones:
        marca = "  (detectado)" if clave == real.clave_so else ""
        consola.escribir(f"  [{numero}] {_ETIQUETA_SO[clave]:<8} - {nota}{marca}")
    consola.escribir("  [0] Cancelar / usar el SO detectado")

    while True:
        respuesta = leer_linea("  Elige una opcion [1-4, 0]: ")
        mapa = {"1": SO_WINDOWS, "2": SO_LINUX, "3": SO_MACOS, "4": SO_OTRO}
        if respuesta == "0":
            return None
        if respuesta in mapa:
            elegida = mapa[respuesta]
            if elegida != real.clave_so:
                consola.aviso(
                    f"Has elegido {_ETIQUETA_SO[elegida]} pero estas en {real.nombre_so}."
                )
                consola.aviso(
                    "Se mostraran sus comandos, pero los escaneos seguiran ejecutandose con "
                    "nmap real en este equipo."
                )
            return elegida
        consola.error("Opcion no valida.")


# ---------------------------------------------------------------------------
# Resolucion de nmap (OBLIGATORIA, sin cache)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InfoNmap:
    """Ruta y version de nmap detectadas en una invocacion concreta."""

    ruta: str
    version_completa: str
    version_tupla: tuple
    origen: str  # "PATH" o "ruta absoluta Windows"
    raw_version: str


_RE_VERSION = re.compile(r"Nmap version\s+(\d+)\.(\d+)(?:\.(\d+))?", re.IGNORECASE)


def _extraer_version(salida: str) -> tuple:
    coincidencia = _RE_VERSION.search(salida or "")
    if not coincidencia:
        return (0, 0, 0)
    mayor = int(coincidencia.group(1))
    menor = int(coincidencia.group(2))
    parche = int(coincidencia.group(3) or 0)
    return (mayor, menor, parche)


def _version_completa(salida: str) -> str:
    for linea in (salida or "").splitlines():
        if "nmap version" in linea.casefold():
            return linea.strip()
    return "desconocida"


def _buscar_ruta_absoluta_windows(clave_so: str) -> Optional[str]:
    """Busca nmap.exe en las rutas habituales de Windows.

    Se usa cuando nmap no esta en el PATH pero si instalado (por ejemplo en
    'C:\\Program Files (x86)\\Nmap\\nmap.exe').
    """
    if clave_so != SO_WINDOWS:
        return None
    for ruta in RUTAS_NMAP_WINDOWS:
        if os.path.isfile(ruta) and ruta.casefold().endswith("nmap.exe"):
            return ruta
    base = os.environ.get("ProgramFiles(x86)") or os.environ.get("ProgramFiles")
    if base:
        candidato = os.path.join(base, "Nmap", "nmap.exe")
        if os.path.isfile(candidato):
            return candidato
    return None


def ejecutar_version_nmap(ruta_nmap: str, timeout: int = 30) -> str:
    """Ejecuta 'nmap --version' como lista de argumentos (nunca shell)."""
    try:
        completado = subprocess.run(
            [ruta_nmap, "--version"],
            capture_output=True,
            timeout=timeout,
            shell=False,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapNoDisponible(
            "nmap no esta instalado",
            f"'{ruta_nmap} --version' no respondio en {timeout}s. Puede estar colgado.",
        ) from exc
    except OSError as exc:
        raise NmapNoDisponible(
            "nmap no esta instalado",
            f"No se pudo ejecutar '{ruta_nmap}': {exc}",
        ) from exc

    salida = (completado.stdout or "") + (completado.stderr or "")
    if completado.returncode != 0 or "nmap version" not in salida.casefold():
        raise NmapNoDisponible(
            "nmap no esta instalado",
            f"'{ruta_nmap} --version' devolvio codigo {completado.returncode} sin salida valida.",
        )
    return salida


def buscar_nmap(clave_so: Optional[str] = None, permitir_ruta_absoluta: bool = True) -> Optional[InfoNmap]:
    """Localiza nmap. Devuelve None si no esta disponible.

    NO propaga excepciones: permite al menus preguntar al usuario antes de
    fallar. Usa shutil.which en CADA llamada (requisito de redeteccion).
    """
    clave = clave_so or detectar_so()

    # 1) PATH - se resuelve siempre de nuevo, nunca se cachea.
    ruta = shutil.which("nmap")
    origen = "PATH"
    if not ruta and permitir_ruta_absoluta:
        ruta = _buscar_ruta_absoluta_windows(clave)
        origen = "ruta absoluta Windows"

    if not ruta:
        LOG.debug("nmap no encontrado en el PATH (SO=%s)", clave)
        return None

    try:
        salida = ejecutar_version_nmap(ruta)
    except NmapNoDisponible:
        LOG.debug("nmap presente en %s pero no responde correctamente", ruta)
        return None

    version_tupla = _extraer_version(salida)
    LOG.debug("nmap detectado en %s (origen=%s) version=%s", ruta, origen, version_tupla)
    return InfoNmap(
        ruta=ruta,
        version_completa=_version_completa(salida),
        version_tupla=version_tupla,
        origen=origen,
        raw_version=salida,
    )


def version_es_valida(info: InfoNmap) -> bool:
    """True si la version es >= 7.80."""
    return info.version_tupla >= VERSI_MINIMA_NMAP


def comprobar_dependencia_nmap(
    consola: Consola,
    clave_so: Optional[str] = None,
    estricto: bool = True,
    permitir_ruta_absoluta: bool = True,
) -> InfoNmap:
    """Verifica nmap. Si falta y `estricto`, muestra las opciones de SO y lanza.

    - Si nmap no esta en el PATH pero existe en las rutas de Windows,
      ofrece detectarlo y usar la ruta absoluta.
    - Si la version es < 7.80 avisa pero CONTINUA (no bloquea).
    """
    clave = clave_so or detectar_so()
    info_sistema = obtener_info_sistema(clave)

    # Ofrecemos la deteccion en ruta absoluta de Windows si aplica.
    if permitir_ruta_absoluta and clave == SO_WINDOWS:
        ruta_abs = _buscar_ruta_absoluta_windows(clave)
        if ruta_abs and not shutil.which("nmap"):
            interactivo = stdin_interactivo()
            if interactivo:
                consola.aviso("nmap NO esta en el PATH, pero parece instalado en:")
                consola.escribir(f"    {ruta_abs}")
                desde = leer_linea("  Usar esa ruta absoluta? [S/n]: ").strip().casefold()
                usar = desde in ("", "s", "si", "y", "yes")
            else:
                # Sin consola no se puede preguntar: se usa la ruta absoluta,
                # que es el comportamiento util en pipelines y CI.
                LOG.info(
                    "nmap no esta en el PATH; se usara la ruta absoluta %s", ruta_abs
                )
                usar = True

            if usar:
                try:
                    salida = ejecutar_version_nmap(ruta_abs)
                except NmapNoDisponible as exc:
                    consola.error(str(exc))
                else:
                    tupla = _extraer_version(salida)
                    info = InfoNmap(
                        ruta_abs, _version_completa(salida), tupla,
                        "ruta absoluta Windows", salida,
                    )
                    if interactivo:
                        consola.ok(f"Usando nmap en {ruta_abs}")
                    _avisar_si_es_antigua(info, consola)
                    return info

    info = buscar_nmap(clave, permitir_ruta_absoluta=permitir_ruta_absoluta)
    if info is None:
        if estricto:
            mostrar_instrucciones_instalacion(consola, clave)
            raise NmapNoDisponible("nmap no esta instalado")
        return None  # type: ignore[return-value]

    _avisar_si_es_antigua(info, consola)
    return info


def _avisar_si_es_antigua(info: InfoNmap, consola: Consola) -> None:
    if not version_es_valida(info):
        requerida = ".".join(str(n) for n in VERSI_MINIMA_NMAP)
        actual = ".".join(str(n) for n in info.version_tupla)
        consola.aviso(f"Version de nmap {actual} anterior a la recomendada {requerida}.")
        consola.aviso("Se continua igualmente, pero algunas detecciones pueden fallar.")
        LOG.warning("nmap %s es anterior a la version minima recomendada %s", actual, requerida)


def mostrar_instrucciones_instalacion(consola: Consola, clave_so: Optional[str] = None) -> None:
    """Muestra los comandos de instalacion listos para copiar, por SO."""
    clave = clave_so or detectar_so()
    nombre = _ETIQUETA_SO.get(clave, "Otro")
    consola.titulo(f"nmap es una dependencia obligatoria - instalacion en {nombre}")
    consola.error("nmap no esta instalado o no responde. No se puede continuar.")
    consola.escribir("")
    consola.info("Comandos listos para copiar:")
    for comando in COMANDOS_INSTALACION.get(clave, COMANDOS_INSTALACION[SO_OTRO]):
        consola.escribir(f"    {comando}")
    consola.escribir("")
    consola.info("Notas por sistema operativo:")
    if clave == SO_WINDOWS:
        consola.escribir("    - El instalador requiere permisos de administrador.")
        consola.escribir("    - winget anade nmap al PATH, pero la terminal actual puede necesitar")
        consola.escribir("      reabrirse para que 'nmap' quede resoluble.")
        consola.escribir("    - NetAudit detecta automaticamente 'C:\\Program Files (x86)\\Nmap\\nmap.exe'.")
    elif clave == SO_LINUX:
        consola.escribir("    - Desinstalar del PATH no es necesario; reinicia la terminal si no aparece.")
        consola.escribir("    - El escaneo con '-sS' requiere sudo (ver aviso de privilegios).")
    elif clave == SO_MACOS:
        consola.escribir("    - El escaneo con '-sS' requiere sudo (ver aviso de privilegios).")
    else:
        consola.escribir("    - Compila desde el codigo fuente y anade el binario a tu PATH.")
    consola.escribir("")


def aviso_privilegios_sudo(consola: Consola, clave_so: Optional[str] = None, usar_ss: bool = False) -> None:
    """Explica que en macOS/Linux solo nmap necesita privilegios, no el script."""
    clave = clave_so or detectar_so()
    if clave not in (SO_LINUX, SO_MACOS):
        return
    if not usar_ss:
        return
    consola.aviso_privilegios(
        "El escaneo '-sS' (SYN) requiere privilegios root para abrir sockets RAW."
    )
    consola.aviso_privilegios(
        "NO necesitas ejecutar todo NetAudit con sudo: basta con dar permisos a nmap."
    )
    if clave == SO_MACOS:
        consola.escribir("    sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)")
        consola.escribir("    # Si prefieres: ejecuta solo el comando nmap generado con sudo.")
    else:
        consola.escribir("    sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)")
        consola.escribir("    # Alternativa: 'sudo nmap ...' solo para el comando de escaneo.")
    consola.escribir("")


def comprobar_privilegios_root(clave_so: Optional[str] = None) -> bool:
    """True si el proceso actual tiene privilegios root/elevados."""
    if (clave_so or detectar_so()) != SO_WINDOWS:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def resumen_entorno(clave_so: Optional[str] = None) -> List[str]:
    """Lineas de resumen del entorno, para el panel de inicio."""
    sistema = obtener_info_sistema(clave_so)
    lineas = [
        f"Sistema operativo : {sistema.nombre_so} ({sistema.plataforma} {sistema.version})",
        f"Python            : {sistema.python} ({platform.python_implementation()})",
        f"Privilegios root  : {'si' if comprobar_privilegios_root(sistema.clave_so) else 'no'}",
    ]
    return lineas
