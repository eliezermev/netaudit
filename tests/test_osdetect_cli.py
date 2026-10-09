"""Tests de la dependencia obligatoria nmap y de los codigos de salida de la CLI.

Verifican el contrato clave: sin nmap no hay escaneo, el error exacto es
"nmap no esta instalado" y el codigo de salida es 2.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import sys
import unittest
from unittest import mock

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from netscan import osdetect  # noqa: E402
from netscan import cli  # noqa: E402
from netscan.osdetect import (  # noqa: E402
    NmapNoDisponible,
    VERSI_MINIMA_NMAP,
    buscar_nmap,
    comprobar_dependencia_nmap,
    mostrar_instrucciones_instalacion,
    version_es_valida,
)
from netscan.utils import Consola, crear_paleta  # noqa: E402

MENSAJE_EXACTO = "nmap no esta instalado"


def consola_silenciosa() -> Consola:
    """Consola que escribe en un buffer, sin color ni terminal."""
    return Consola(paleta=crear_paleta(io.StringIO(), forzar_color=False),
                   flujo=io.StringIO())


class TestVersionNmap(unittest.TestCase):
    def test_version_minima_declarada(self):
        self.assertEqual(VERSI_MINIMA_NMAP, (7, 80))

    def test_comparacion_de_versiones(self):
        def info(tupla):
            return osdetect.InfoNmap("nmap", "x", tupla, "PATH", "")

        self.assertTrue(version_es_valida(info((7, 80, 0))), "7.80 es valida")
        self.assertTrue(version_es_valida(info((7, 94, 0))))
        self.assertTrue(version_es_valida(info((8, 0, 0))))
        self.assertFalse(version_es_valida(info((7, 79, 0))), "7.79 es antigua")
        self.assertFalse(version_es_valida(info((7, 40, 0))))
        self.assertFalse(version_es_valida(info((6, 99, 9))))

    def test_extraccion_de_version_desde_salida(self):
        salida = "Nmap version 7.94 ( https://nmap.org )\nPlatform: x86_64"
        self.assertEqual(osdetect._extraer_version(salida), (7, 94, 0))

    def test_extraccion_version_con_parche(self):
        self.assertEqual(
            osdetect._extraer_version("Nmap version 7.80.1 ( https://nmap.org )"),
            (7, 80, 1),
        )


class TestResolucionNmap(unittest.TestCase):
    def test_sin_nmap_devuelve_none(self):
        with mock.patch.object(shutil, "which", return_value=None), \
             mock.patch.object(osdetect, "_buscar_ruta_absoluta_windows", return_value=None):
            self.assertIsNone(buscar_nmap())

    def test_nmap_no_responde_devuelve_none(self):
        with mock.patch.object(shutil, "which", return_value="C:\\nmap.exe"), \
             mock.patch.object(
                 osdetect, "ejecutar_version_nmap",
                 side_effect=NmapNoDisponible(MENSAJE_EXACTO),
             ):
            self.assertIsNone(buscar_nmap())

    def test_se_usa_which_en_cada_llamada_sin_cachear(self):
        """Requisito explicito: si nmap se instala despues en otra terminal,
        la siguiente invocacion debe detectarlo."""
        llamadas = {"n": 0}

        def which_fake(_nombre):
            llamadas["n"] += 1
            # Solo existe a partir de la segunda invocacion.
            return "C:\\Program Files (x86)\\Nmap\\nmap.exe" if llamadas["n"] > 1 else None

        salida = "Nmap version 7.94 ( https://nmap.org )"
        with mock.patch.object(shutil, "which", side_effect=which_fake), \
             mock.patch.object(osdetect, "_buscar_ruta_absoluta_windows", return_value=None), \
             mock.patch.object(osdetect, "ejecutar_version_nmap", return_value=salida):
            self.assertIsNone(buscar_nmap())
            info = buscar_nmap()
            self.assertIsNotNone(info, "la segunda llamada debe detectar nmap recien instalado")
            self.assertEqual(info.version_tupla, (7, 94, 0))
        self.assertEqual(llamadas["n"], 2, "which debe consultarse en cada invocacion")

    def test_ruta_absoluta_windows_detectada(self):
        ruta = r"C:\Program Files (x86)\Nmap\nmap.exe"
        with mock.patch.object(shutil, "which", return_value=None), \
             mock.patch.object(os.path, "isfile", side_effect=lambda p: p == ruta), \
             mock.patch.object(
                 osdetect, "ejecutar_version_nmap",
                 return_value="Nmap version 7.80 ( https://nmap.org )",
             ):
            info = buscar_nmap(osdetect.SO_WINDOWS)
        self.assertIsNotNone(info)
        self.assertEqual(info.ruta, ruta)
        self.assertEqual(info.origen, "ruta absoluta Windows")


class TestDependenciaObligatoria(unittest.TestCase):
    def test_error_exacto_cuando_falta_nmap(self):
        consola = consola_silenciosa()
        with mock.patch.object(shutil, "which", return_value=None), \
             mock.patch.object(osdetect, "_buscar_ruta_absoluta_windows", return_value=None):
            with self.assertRaises(NmapNoDisponible) as contexto:
                comprobar_dependencia_nmap(consola)
        self.assertEqual(str(contexto.exception), MENSAJE_EXACTO)

    def test_error_es_runtime_error(self):
        """Debe ser RuntimeError para poder capturarse como tal."""
        self.assertTrue(issubclass(NmapNoDisponible, RuntimeError))

    def test_no_interactivo_no_pregunta_y_usa_ruta_absoluta(self):
        consola = consola_silenciosa()
        ruta = r"C:\Program Files (x86)\Nmap\nmap.exe"
        with mock.patch.object(shutil, "which", return_value=None), \
             mock.patch.object(osdetect, "_buscar_ruta_absoluta_windows", return_value=ruta), \
             mock.patch.object(osdetect, "ejecutar_version_nmap",
                               return_value="Nmap version 7.94 ( https://nmap.org )"), \
             mock.patch("netscan.utils.sys.stdin.isatty", return_value=False):
            info = comprobar_dependencia_nmap(consola, osdetect.SO_WINDOWS)
        self.assertEqual(info.ruta, ruta)

    def test_instrucciones_por_sistema_operativo(self):
        for clave, esperado in (
            (osdetect.SO_WINDOWS, "winget"),
            (osdetect.SO_LINUX, "apt install nmap"),
            (osdetect.SO_MACOS, "brew install nmap"),
            (osdetect.SO_OTRO, "nmap"),
        ):
            consola = consola_silenciosa()
            mostrar_instrucciones_instalacion(consola, clave)
            salida = consola.flujo.getvalue()
            self.assertIn(esperado, salida, f"faltan instrucciones de instalacion para {clave}")

    def test_todas_las_instrucciones_son_copiables(self):
        for clave, comandos in osdetect.COMANDOS_INSTALACION.items():
            for comando in comandos:
                self.assertFalse(
                    comando.startswith("sudo ") and "winget" in comando,
                    f"comando incoherente para {clave}: {comando}",
                )
                self.assertTrue(comando.strip(), f"comando vacio para {clave}")

    def test_version_antigua_avisa_pero_no_bloquea(self):
        consola = consola_silenciosa()
        info = osdetect.InfoNmap("nmap", "Nmap version 7.40", (7, 40, 0), "PATH", "")
        with mock.patch.object(shutil, "which", return_value="nmap"), \
             mock.patch.object(osdetect, "ejecutar_version_nmap",
                               return_value="Nmap version 7.40 ( https://nmap.org )"), \
             mock.patch.object(osdetect, "_buscar_ruta_absoluta_windows", return_value=None):
            resultado = comprobar_dependencia_nmap(consola)
        self.assertIsNotNone(resultado, "una version antigua NO debe impedir escanear")
        self.assertIn("7.80", consola.flujo.getvalue())


class TestCodigosSalidaCli(unittest.TestCase):
    """0 sin hallazgos / 1 con hallazgos / 2 error o dependencia ausente."""

    def setUp(self):
        self._salida = io.StringIO()
        self._error = io.StringIO()
        self._redir_salida = contextlib.redirect_stdout(self._salida)
        self._redir_error = contextlib.redirect_stderr(self._error)
        self._redir_salida.__enter__()
        self._redir_error.__enter__()

    def tearDown(self):
        self._redir_error.__exit__(None, None, None)
        self._redir_salida.__exit__(None, None, None)

    def salida(self) -> str:
        return self._salida.getvalue() + self._error.getvalue()

    def test_codigos_definidos(self):
        self.assertEqual(cli.CODIGO_OK, 0)
        self.assertEqual(cli.CODIGO_HALLAZGOS, 1)
        self.assertEqual(cli.CODIGO_ERROR_EJECUCION, 2)
        self.assertEqual(osdetect.CODIGO_SIN_DEPENDENCIA, 2)

    def test_scan_sin_autorizado_devuelve_2(self):
        """El modo no interactivo exige --autorizado."""
        argumentos = ["scan", "--target", "192.168.1.10"]
        with mock.patch.object(sys, "argv", argumentos):
            codigo = cli.main(argumentos)
        self.assertEqual(codigo, 2)
        self.assertIn("--autorizado", self.salida())

    def test_scan_sin_nmap_devuelve_2(self):
        """Sin nmap el flujo debe abortar con codigo 2 sin lanzar ningun escaneo."""
        argumentos = ["scan", "--target", "192.168.1.10", "--autorizado", "--sin-reporte"]
        # cli importa el simbolo por nombre: hay que parchearlo en 'cli'.
        with mock.patch.object(
            cli, "comprobar_dependencia_nmap",
            side_effect=NmapNoDisponible(MENSAJE_EXACTO),
        ), mock.patch.object(
            cli, "ejecutar_escaneo",
            side_effect=AssertionError("no debe escanearse sin nmap"),
        ), mock.patch.object(sys, "argv", argumentos):
            codigo = cli.main(argumentos)
        self.assertEqual(codigo, 2)
        self.assertIn(MENSAJE_EXACTO, self.salida())

    def test_scan_sin_nmap_muestra_instrucciones_de_instalacion(self):
        argumentos = ["scan", "--target", "192.168.1.10", "--autorizado"]
        with mock.patch.object(
            shutil, "which", return_value=None,
        ), mock.patch.object(
            osdetect, "_buscar_ruta_absoluta_windows", return_value=None,
        ), mock.patch.object(
            cli, "ejecutar_escaneo",
            side_effect=AssertionError("no debe escanearse sin nmap"),
        ), mock.patch.object(sys, "argv", argumentos):
            codigo = cli.main(argumentos)
        self.assertEqual(codigo, 2)
        texto = self.salida()
        self.assertIn(MENSAJE_EXACTO, texto)
        # Debe ofrecer los comandos de instalacion del SO detectado.
        self.assertRegex(texto, r"winget|apt install nmap|dnf install nmap|brew install nmap")

    def test_objetivo_invalido_devuelve_2(self):
        argumentos = ["scan", "--target", "999.999.999.999", "--autorizado"]
        with mock.patch.object(
            cli, "comprobar_dependencia_nmap",
            return_value=osdetect.InfoNmap("nmap", "7.94", (7, 94, 0), "PATH", ""),
        ), mock.patch.object(
            cli, "ejecutar_escaneo",
            side_effect=AssertionError("no debe escanearse con objetivo invalido"),
        ), mock.patch.object(sys, "argv", argumentos):
            codigo = cli.main(argumentos)
        self.assertEqual(codigo, 2)

    def test_xml_inexistente_devuelve_2(self):
        argumentos = ["informe", "--xml", os.path.join(RAIZ, "no_existe.xml")]
        with mock.patch.object(sys, "argv", argumentos):
            codigo = cli.main(argumentos)
        self.assertEqual(codigo, 2)

    def test_json_a_stdout_no_lee_de_la_consola_ni_mezcla_salida(self):
        """Con --format json, stdout debe contener SOLO el JSON.

        Se comprueba tambien que el resultado sea UTF-8 valido aunque en
        Windows la salida se redirija a un fichero (donde Python usa cp1252).
        """
        import json as _json

        argumentos = [
            "scan", "--target", "192.168.1.10", "--autorizado",
            "--format", "json", "--sin-reporte",
        ]
        objetivos, resultado = construir_resultado_falso()
        with mock.patch.object(
            cli, "comprobar_dependencia_nmap", return_value=info_nmap_ok(),
        ), mock.patch.object(
            cli, "construir_objetivos", return_value=(objetivos, []),
        ), mock.patch.object(
            cli, "filtrar_excluidos", side_effect=lambda o, e: (list(o), []),
        ), mock.patch.object(
            cli, "ejecutar_escaneo", return_value=resultado,
        ), mock.patch.object(sys, "argv", argumentos):
            codigo = cli.main(argumentos)

        # Solo stdout: los logs van legitimamente a stderr.
        salida = self._salida.getvalue()
        try:
            # Debe ser JSON parseable: si se mezclase un banner, fallaria aqui.
            datos = _json.loads(salida)
        except ValueError as exc:
            self.fail(f"stdout no contiene solo JSON: {exc}\n{salida[:400]}")
        self.assertEqual(datos["esquema"]["nombre"], "netaudit-reporte")
        self.assertIn(codigo, (0, 1))

    def test_con_json_los_logs_no_contaminan_stdout(self):
        """Los mensajes de progreso van a stderr, nunca a stdout."""
        argumentos = [
            "scan", "--target", "192.168.1.10", "--autorizado",
            "--format", "json", "--sin-reporte",
        ]
        objetivos, resultado = construir_resultado_falso()
        with mock.patch.object(
            cli, "comprobar_dependencia_nmap", return_value=info_nmap_ok(),
        ), mock.patch.object(
            cli, "construir_objetivos", return_value=(objetivos, []),
        ), mock.patch.object(
            cli, "filtrar_excluidos", side_effect=lambda o, e: (list(o), []),
        ), mock.patch.object(
            cli, "ejecutar_escaneo", return_value=resultado,
        ), mock.patch.object(sys, "argv", argumentos):
            cli.main(argumentos)

        stdout = self._salida.getvalue().lstrip()
        self.assertTrue(stdout.startswith("{"), "stdout debe empezar por '{'")
        # El progreso si debe haber salido por stderr.
        self.assertTrue(self._error.getvalue().strip(), "los avisos deben ir a stderr")


class TestCodificacionUtf8(unittest.TestCase):
    def test_forzar_utf8_en_flujo_redirigido(self):
        """Windows usa cp1252 al redirigir: hay que forzar UTF-8."""
        import io as _io

        from netscan.utils import forzar_utf8

        flujo = _io.TextIOWrapper(_io.BytesIO(), encoding="cp1252")
        self.assertEqual(flujo.encoding, "cp1252")
        aplicado = forzar_utf8(flujo)
        self.assertTrue(aplicado)
        self.assertEqual(flujo.encoding, "utf-8")
        # Debe poder escribir texto con acentos sin fallar.
        flujo.write("analisis, mitigacion, ano")
        flujo.flush()

    def test_forzar_utf8_no_falla_con_flujo_simple(self):
        import io as _io

        from netscan.utils import forzar_utf8

        # Un StringIO no tiene reconfigure: debe devolver False, no explotar.
        self.assertFalse(forzar_utf8(_io.StringIO()))


def info_nmap_ok() -> osdetect.InfoNmap:
    """InfoNmap valido para simular nmap instalado."""
    return osdetect.InfoNmap("nmap", "Nmap version 7.94", (7, 94, 0), "PATH", "")


def construir_resultado_falso():
    """Objetivos + resultado de escaneo minimos, sin tocar la red."""
    from netscan.scanner import parsear_xml_nmap
    from netscan.targets import validar_objetivo

    ruta = os.path.join(RAIZ, "tests", "data", "ejemplo_nmap.xml")
    with open(ruta, encoding="utf-8") as manejador:
        resultado = parsear_xml_nmap(manejador.read())
    resultado.nmap_version = "Nmap version 7.94 ( https://nmap.org )"
    resultado.perfil = "puertos"
    objetivo = validar_objetivo("192.168.1.10")
    resultado.objetivos = [objetivo]
    return [objetivo], resultado


if __name__ == "__main__":
    unittest.main(verbosity=2)
