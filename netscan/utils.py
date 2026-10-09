"""Utilidades comunes: logging, colores de consola y helpers de entrada/salida.

Todo el texto visible de NetAudit esta en espanol.
Este modulo no contiene variables globales mutables: el estado (paleta, logger)
se devuelve en objetos y se pasa explicitamente.
"""

from __future__ import annotations

import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Optional, Sequence, TextIO

# ---------------------------------------------------------------------------
# Colores
# ---------------------------------------------------------------------------

_SIN_COLOR = "\033[0m"


@dataclass(frozen=True)
class Paleta:
    """Codigos ANSI inmutables para pintar la salida por consola."""

    reset: str = _SIN_COLOR
    negrita: str = "\033[1m"
    rojo: str = "\033[31m"
    verde: str = "\033[32m"
    amarillo: str = "\033[33m"
    azul: str = "\033[34m"
    magenta: str = "\033[35m"
    cian: str = "\033[36m"
    gris: str = "\033[90m"

    def desactivar(self) -> "Paleta":
        """Devuelve una paleta sin ningun codigo de color."""
        return Paleta(
            reset="",
            negrita="",
            rojo="",
            verde="",
            amarillo="",
            azul="",
            magenta="",
            cian="",
            gris="",
        )


def crear_paleta(flujo: Optional[TextIO] = None, forzar_color: Optional[bool] = None) -> Paleta:
    """Construye la paleta segun el soporte del terminal.

    En Windows solo se activa si la consola lo soporta (Windows Terminal o
    VT100 habilitado); en otro caso devuelve la paleta vacia.
    """
    if flujo is None:
        flujo = sys.stdout

    if forzar_color is not None:
        return Paleta() if not forzar_color else Paleta()

    if os.environ.get("NO_COLOR"):
        return Paleta().desactivar()
    if os.environ.get("NETAUDIT_COLOR") == "1":
        return Paleta()

    try:
        soporta = bool(flujo.isatty())
    except (AttributeError, ValueError):
        soporta = False
    if not soporta:
        return Paleta().desactivar()

    if sys.platform == "win32":
        if os.environ.get("WT_SESSION") or os.environ.get("TERM_PROGRAM"):
            return Paleta()
        if os.environ.get("ANSICON") is not None:
            return Paleta()
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            return Paleta().desactivar()
    return Paleta()


class Consola:
    """Salida por consola con color y soporte de salida sin color (archivos).

    `flujo` permite desviar todos los mensajes informativos a stderr cuando
    stdout debe reservar su contenido para datos (por ejemplo `--format json`).
    """

    def __init__(self, paleta: Optional[Paleta] = None, flujo: Optional[TextIO] = None) -> None:
        # El flujo se resuelve en el momento de construir la consola, NO como
        # valor por defecto: si se usara sys.stdout como default se capturaria
        # en el instante de importar el modulo y la redireccion de salida
        # (pipes, tests, subprocess) dejaria de funcionar.
        objetivo = flujo if flujo is not None else sys.stdout
        self._paleta = paleta if paleta is not None else crear_paleta(objetivo)
        self._flujo = objetivo

    def a_stderr(self) -> "Consola":
        """Devuelve una consola equivalente que escribe en stderr."""
        return Consola(paleta=self._paleta, flujo=sys.stderr)

    @property
    def flujo(self) -> TextIO:
        return self._flujo

    @property
    def paleta(self) -> Paleta:
        return self._paleta

    def escribir(self, texto: str = "", fin: str = "\n") -> None:
        try:
            self._flujo.write(texto + fin)
            self._flujo.flush()
        except (UnicodeEncodeError, ValueError):
            # Terminal legado de Windows: degradamos a ASCII sin perder info.
            segura = texto.encode("ascii", "replace").decode("ascii")
            self._flujo.write(segura + fin)
            self._flujo.flush()

    def titulo(self, texto: str) -> None:
        """Cabecera destacada entre lineas de iguales."""
        p = self._paleta
        self.escribir(f"{p.cian}{p.negrita}{'=' * 68}{p.reset}")
        self.escribir(f"{p.cian}{p.negrita} {texto}{p.reset}")
        self.escribir(f"{p.cian}{p.negrita}{'=' * 68}{p.reset}")

    def seccion(self, texto: str) -> None:
        """Subtitulo de seccion dentro del flujo."""
        p = self._paleta
        self.escribir("")
        self.escribir(f"{p.negrita}{p.azul}--- {texto} ---{p.reset}")

    def info(self, texto: str) -> None:
        """Mensaje informativo con marca [i]."""
        self.escribir(f"{self._paleta.azul}[i]{self._paleta.reset} {texto}")

    def ok(self, texto: str) -> None:
        """Mensaje de operacion correcta con marca [+]."""
        self.escribir(f"{self._paleta.verde}[+]{self._paleta.reset} {texto}")

    def aviso(self, texto: str) -> None:
        """Advertencia con marca [!]."""
        self.escribir(f"{self._paleta.amarillo}[!]{self._paleta.reset} {texto}")

    def error(self, texto: str) -> None:
        """Error con marca [-]."""
        self.escribir(f"{self._paleta.rojo}[-]{self._paleta.reset} {texto}")

    def critico(self, texto: str) -> None:
        """Error destacado con marca [!!]."""
        p = self._paleta
        self.escribir(f"{p.rojo}{p.negrita}[!!] {texto}{p.reset}")

    def aviso_privilegios(self, texto: str) -> None:
        """Aviso relacionado con permisos y sudo, con marca [sudo]."""
        p = self._paleta
        self.escribir(f"{p.magenta}[sudo]{p.reset} {texto}")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_CODIGO_TRACE = "netscan"


def configurar_logging(
    directorio_log: str,
    nivel: int = logging.INFO,
    a_consola: bool = True,
) -> logging.Logger:
    """Configura logging a archivo (siempre) y consola (opcional)."""
    os.makedirs(directorio_log, exist_ok=True)
    marca = time.strftime("%Y%m%d_%H%M%S")
    ruta = os.path.join(directorio_log, f"netaudit_{marca}.log")

    logger = logging.getLogger(_CODIGO_TRACE)
    logger.setLevel(logging.DEBUG)
    # Limpiamos handlers previos para que multiples llamadas no dupliquen salida.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formato = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"

    archivo = logging.FileHandler(ruta, encoding="utf-8")
    archivo.setLevel(logging.DEBUG)
    archivo.setFormatter(logging.Formatter(formato))
    logger.addHandler(archivo)

    if a_consola:
        consola = logging.StreamHandler(stream=sys.stderr)
        consola.setLevel(nivel)
        consola.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
        logger.addHandler(consola)

    logger.debug("Archivo de log: %s", ruta)
    return logger


def obtener_logger(nombre: Optional[str] = None) -> logging.Logger:
    """Devuelve el logger del paquete (nunca None)."""
    return logging.getLogger(_CODIGO_TRACE if not nombre else f"{_CODIGO_TRACE}.{nombre}")


# ---------------------------------------------------------------------------
# Entrada de usuario
# ---------------------------------------------------------------------------

CONFIRMACION_AUTORIZACION = "AUTORIZADO"
CONFIRMACION_SEGURO = "SEGURO"


def leer_linea(mensaje: str) -> str:
    """Lee una linea de entrada. Ctrl+C / Ctrl+D se manejan como vacio."""
    try:
        return input(mensaje).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def forzar_utf8(flujo: TextIO) -> bool:
    """Fuerza UTF-8 en un flujo de salida. Devuelve True si se aplico.

    En Windows, al redirigir la salida a un fichero, Python usa la codificacion
    local (cp1252). Para datos legibles por maquinas (JSON) eso es frágil: un
    fichero JSON debe ser UTF-8. Se usa errors='replace' para que un caracter no
    representable nunca provoque un fallo en mitad del escaneo.
    """
    reconfigurar = getattr(flujo, "reconfigure", None)
    if reconfigurar is None:
        return False
    try:
        reconfigurar(encoding="utf-8", errors="replace")
        return True
    except (ValueError, OSError, AttributeError):
        return False


def stdin_interactivo() -> bool:
    """True si hay una consola real para preguntar al usuario.

    En canalizacion (pip, CI, --format json) no se debe preguntar: se
    devuelven valores por defecto o se falla con un mensaje claro.
    """
    try:
        return bool(sys.stdin) and sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def pedir_confirmacion(mensaje: str, palabra: str, consola: Consola) -> bool:
    """Pide escribir exactamente `palabra` para confirmar. Case-insensitive.

    Devuelve True solo si coincide. Cualquier otra respuesta cancela.
    """
    consola.escribir(f"{consola.paleta.amarillo}{mensaje}{consola.paleta.reset}")
    respuesta = leer_linea(f"  Escribe '{palabra}' para confirmar (o cualquier otra cosa para cancelar): ")
    coincide = respuesta.strip().casefold() == palabra.casefold()
    if not coincide:
        consola.error("Confirmacion no valida. Operacion cancelada.")
    return coincide


# ---------------------------------------------------------------------------
# Formato y helpers
# ---------------------------------------------------------------------------

_RE_NO_ALFANUM = re.compile(r"[^a-zA-Z0-9]+")


def slug(texto: str, maximo: int = 60) -> str:
    """Convierte texto en un identificador seguro para nombres de archivo."""
    limpio = _RE_NO_ALFANUM.sub("_", texto.strip().casefold()).strip("_")
    return (limpio or "sin_nombre")[:maximo]


def duracion_humana(segundos: float) -> str:
    """'1h 02m 03s' a partir de segundos."""
    segundos = int(max(0.0, segundos))
    horas, resto = divmod(segundos, 3600)
    minutos, segs = divmod(resto, 60)
    if horas:
        return f"{horas}h {minutos:02d}m {segs:02d}s"
    if minutos:
        return f"{minutos}m {segs:02d}s"
    return f"{segs}s"


def truncar(texto: str, maximo: int = 300) -> str:
    """Recorta texto largo conservando que quede legible."""
    if texto is None:
        return ""
    limpio = texto.replace("\x00", "").strip()
    if len(limpio) <= maximo:
        return limpio
    return limpio[: maximo - 3] + "..."


def limpiar_espacios(texto: str) -> str:
    return re.sub(r"\s+", " ", texto or "").strip()


def ahora_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def marca_temporal_directorio() -> str:
    """AAAA-MM-DD_HHMMSS usado para ./reportes/<marca>/."""
    return time.strftime("%Y-%m-%d_%H%M%S")


def unir_lineas(secuencia: Sequence[str], prefijo: str = "  ") -> str:
    return "\n".join(f"{prefijo}{linea}" for linea in secuencia)


def escribir_archivo_texto(ruta: str, contenido: str) -> str:
    """Escribe texto en UTF-8 creando los directorios necesarios."""
    directorio = os.path.dirname(os.path.abspath(ruta))
    if directorio:
        os.makedirs(directorio, exist_ok=True)
    with open(ruta, "w", encoding="utf-8", newline="\n") as manejador:
        manejador.write(contenido)
    return ruta


def decodificar_bytes(datos: bytes) -> str:
    """Decodifica de forma tolerante los bytes que devuelven los servicios."""
    if not datos:
        return ""
    for codificacion in ("utf-8", "latin-1"):
        try:
            return datos.decode(codificacion)
        except UnicodeDecodeError:
            continue
    return datos.decode("utf-8", errors="replace")
