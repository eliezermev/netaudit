"""Tests de severidad, mapeo MITRE ATT&CK y generacion de reporte."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from netscan.attack import (  # noqa: E402
    TACTICAS,
    TecnicaATTACK,
    agrupar_por_tactica,
    construir_informe_attack,
    construir_matriz,
    generar_caminos_ataque,
)
from netscan.report import construir_html, construir_json, guardar_reporte  # noqa: E402
from netscan.scanner import ResultadoEscaneo, parsear_xml_nmap  # noqa: E402
from netscan.targets import validar_objetivo  # noqa: E402
from netscan.vulns import (  # noqa: E402
    ALTA,
    BAJA,
    CRITICA,
    INFO,
    MEDIA,
    ORDEN_SEVERIDAD,
    PESO_SEVERIDAD,
    SeveridadInvalida,
    calcular_resumen,
    evaluar,
    normalizar_severidad,
    peso_severidad,
)

RUTA_XML = os.path.join(RAIZ, "tests", "data", "ejemplo_nmap.xml")


def construir_resultado() -> ResultadoEscaneo:
    with open(RUTA_XML, "r", encoding="utf-8") as manejador:
        resultado = parsear_xml_nmap(manejador.read())
    resultado.nmap_version = "Nmap version 7.80 ( https://nmap.org )"
    resultado.perfil = "completo"
    resultado.comandos = [["nmap", "-sV", "-sC", "-A", "-T4", "-oX", "-", "192.168.1.0/29"]]
    resultado.objetivos = [validar_objetivo("192.168.1.0/29")]
    return resultado


class TestSeveridad(unittest.TestCase):
    def test_normalizar_acepta_alias(self):
        self.assertEqual(normalizar_severidad("critica"), CRITICA)
        self.assertEqual(normalizar_severidad("ALTO"), ALTA)
        self.assertEqual(normalizar_severidad(" Medium "), MEDIA)
        self.assertEqual(normalizar_severidad("low"), BAJA)
        self.assertEqual(normalizar_severidad("informational"), INFO)

    def test_normalizar_rechaza_desconocida(self):
        with self.assertRaises(SeveridadInvalida):
            normalizar_severidad("PESIMA")

    def test_pesos_coherentes(self):
        self.assertGreater(peso_severidad(CRITICA), peso_severidad(ALTA))
        self.assertGreater(peso_severidad(ALTA), peso_severidad(MEDIA))
        self.assertGreater(peso_severidad(MEDIA), peso_severidad(BAJA))
        self.assertEqual(peso_severidad(INFO), 0)
        self.assertEqual(PESO_SEVERIDAD[CRITICA], 10)

    def test_orden_de_severidad(self):
        self.assertEqual(ORDEN_SEVERIDAD, (CRITICA, ALTA, MEDIA, BAJA, INFO))

    def test_score_crece_con_severidad(self):
        bajo = calcular_resumen([])
        self.assertEqual(bajo.score, 0)
        self.assertEqual(bajo.total, 0)

        resultado = construir_resultado()
        hallazgos = evaluar(resultado)
        resumen = calcular_resumen(hallazgos)
        self.assertEqual(resumen.total, len(hallazgos))
        self.assertTrue(0 < resumen.score <= 100)

    def test_score_satura_en_100(self):
        from netscan.vulns import Hallazgo

        muchos = [
            Hallazgo(
                titulo="x",
                severidad=CRITICA,
                riesgo="r",
                evidencia="e",
                mitigacion="m",
                falsos_positivos="f",
            )
            for _ in range(200)
        ]
        self.assertEqual(calcular_resumen(muchos).score, 100)


class TestMitreAttack(unittest.TestCase):
    def setUp(self):
        self.resultado = construir_resultado()
        self.hallazgos = evaluar(self.resultado)
        self.matriz = construir_matriz(self.hallazgos)

    def test_matriz_no_vacia(self):
        self.assertGreater(len(self.matriz), 0)

    def test_todas_las_tecnicas_cumplen_formato(self):
        for nodo in self.matriz:
            tecnica = nodo.tecnica
            self.assertRegex(tecnica.identificador, r"^T\d{4}(\.\d{3})?$")
            self.assertTrue(tecnica.nombre)
            self.assertIn(tecnica.tactica, TACTICAS)

    def test_tecnicas_clave_presentes(self):
        ids = {n.tecnica.identificador for n in self.matriz}
        for esperada in ("T1046", "T1210", "T1552.001", "T1190", "T1040"):
            self.assertIn(esperada, ids)

    def test_agrupacion_por_tactica_conserva_orden(self):
        agrupado = agrupar_por_tactica(self.matriz)
        self.assertEqual(list(agrupado.keys()), list(TACTICAS))

    def test_celda_hereda_severidad_maxima(self):
        from netscan.attack import NodoMatriz

        critico = next(h for h in self.hallazgos if h.severidad == CRITICA)
        nodo = NodoMatriz(tecnica=critico.tecnicas[0])
        nodo.hallazgos.append(critico)
        nodo.hosts.add(critico.host)
        self.assertEqual(nodo.severidad_maxima, CRITICA)

    def test_todo_hallazgo_tiene_tecnica_o_esta_en_info(self):
        for hallazgo in self.hallazgos:
            if hallazgo.severidad != INFO:
                self.assertTrue(
                    hallazgo.tecnicas, f"{hallazgo.regla} sin tecnica ATT&ACK"
                )

    def test_tecnica_a_dict_incluye_justificacion(self):
        tecnica = TecnicaATTACK("T1046", "Network Service Discovery", "Discovery")
        datos = tecnica.a_dict()
        self.assertEqual(datos["id"], "T1046")
        self.assertEqual(datos["tactica"], "Discovery")
        self.assertTrue(datos["justificacion"])

    def test_caminos_de_ataque_generados(self):
        caminos = generar_caminos_ataque(self.hallazgos)
        self.assertGreater(len(caminos), 0)
        for camino in caminos:
            self.assertTrue(camino.titulo)
            self.assertGreaterEqual(len(camino.pasos), 2)
            self.assertTrue(camino.tecnicas)
            self.assertIn(camino.severidad, ORDEN_SEVERIDAD)

    def test_caminos_ordenados_por_severidad(self):
        caminos = generar_caminos_ataque(self.hallazgos)
        orden = {n: i for i, n in enumerate(ORDEN_SEVERIDAD)}
        indices = [orden[c.severidad] for c in caminos]
        self.assertEqual(indices, sorted(indices))

    def test_informe_attack_completo(self):
        informe = construir_informe_attack(self.hallazgos)
        for clave in ("matriz", "por_tactica", "caminos_ataque", "tecnicas_totales"):
            self.assertIn(clave, informe)
        self.assertGreater(informe["total_tecnicas"], 0)


def _extraer_bloque(html: str, clase: str) -> str:
    """Extrae el contenido de un div por equilibrio de etiquetas anidadas."""
    import re as _re

    patron = rf'<div class="{clase}"'
    inicio = html.find(patron)
    if inicio == -1:
        raise AssertionError(f"no se encontro un div con class={clase!r}")
    posicion = html.index(">", inicio) + 1
    profundidad = 1
    cursor = posicion
    while profundidad > 0 and cursor < len(html):
        siguiente_abre = html.find("<div", cursor)
        siguiente_cierra = html.find("</div>", cursor)
        if siguiente_cierra == -1:
            break
        if siguiente_abre != -1 and siguiente_abre < siguiente_cierra:
            profundidad += 1
            cursor = siguiente_abre + 4
        else:
            profundidad -= 1
            cursor = siguiente_cierra + 6
    return html[posicion : cursor - 6]


class TestReporte(unittest.TestCase):
    def setUp(self):
        self.resultado = construir_resultado()
        self.hallazgos = evaluar(self.resultado)
        self.resumen = calcular_resumen(self.hallazgos)
        self.datos = construir_json(self.resultado, self.hallazgos, self.resumen)

    def test_json_tiene_esquema_estable(self):
        for clave in (
            "esquema",
            "herramienta",
            "metodologia",
            "resumen",
            "hosts",
            "hallazgos",
            "mitre_attack",
            "recomendaciones",
            "limitaciones",
        ):
            self.assertIn(clave, self.datos)
        self.assertEqual(self.datos["esquema"]["nombre"], "netaudit-reporte")

    def test_json_es_serializable(self):
        texto = json.dumps(self.datos, ensure_ascii=False)
        self.assertGreater(len(texto), 1000)
        self.assertEqual(json.loads(texto)["resumen"]["hallazgos"], len(self.hallazgos))

    def test_json_incluye_comandos_nmap(self):
        self.assertTrue(self.datos["metodologia"]["comandos_nmap"])
        self.assertIn("nmap", self.datos["metodologia"]["comandos_nmap"][0])

    def test_recomendaciones_por_plazo(self):
        reco = self.datos["recomendaciones"]
        self.assertEqual(list(reco.keys()), ["24_horas", "7_dias", "30_dias"])
        self.assertTrue(reco["24_horas"]["acciones"])

    def test_html_autonomo_sin_recursos_externos(self):
        html = construir_html(self.datos, self.resultado, self.hallazgos)
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn("<style>", html)
        self.assertNotIn("<script", html)
        self.assertNotIn("http://", html)
        self.assertNotIn("src=", html)

    def test_html_escapa_contenido(self):
        self.assertNotIn("<img", construir_html(self.datos, self.resultado, self.hallazgos))

    def test_html_contiene_secciones_requeridas(self):
        html = construir_html(self.datos, self.resultado, self.hallazgos)
        for seccion in (
            "Resumen ejecutivo",
            "Metodologia",
            "Hosts",
            "Puertos, servicios y banners",
            "Hallazgos",
            "Matriz MITRE ATT&amp;CK",
            "Recomendaciones priorizadas",
            "Anexo A",
            "Anexo B",
            "Limitaciones del analisis",
        ):
            self.assertIn(seccion, html, f"falta la seccion {seccion}")

    def test_html_no_contiene_html_anidado_corrupto(self):
        """Una fila pasada como texto a _tabla genera HTML invalido que el
        navegador renderiza como texto. Este test lo detecta."""
        import re as _re

        from netscan.report import _tabla

        with self.assertRaises(ValueError):
            _tabla(["A"], ["<tr><td>x</td></tr>"])

        html = construir_html(self.datos, self.resultado, self.hallazgos)
        # Ninguna celda debe contener una fila completa.
        self.assertIsNone(_re.search(r"<td[^>]*>\s*<tr>", html), "celda con <tr> anidado")
        # Ningun HTML debe aparecer escapado y visible como texto.
        self.assertIsNone(
            _re.search(r"&lt;tr&gt;|&lt;span|&lt;div|&lt;code", html),
            "HTML escapado visible",
        )
        self.assertEqual(
            html.count("<table>"), html.count("</table>"), "tablas desbalanceadas"
        )

    def test_html_estructura_de_tablas_coherente(self):
        """Cada etiqueta debe abrir y cerrar el mismo numero de veces.

        Se cuentan con regex para no confundir <th> con <thead>.
        """
        import re as _re

        html = construir_html(self.datos, self.resultado, self.hallazgos)
        for etiqueta in ("td", "th", "div", "pre", "tr", "table", "span", "p", "code"):
            abres = len(_re.findall(rf"<{etiqueta}(\s|>)", html))
            cierres = html.count(f"</{etiqueta}>")
            self.assertEqual(
                abres, cierres, f"desbalance en <{etiqueta}>: {abres} abre, {cierres} cierra"
            )

    def test_matriz_muestra_todas_las_tacticas_con_actividad(self):
        """Recortar columnas ocultaria hallazgos criticos (p. ej. Credential
        Access o Lateral Movement). Deben aparecer todas."""
        import re as _re

        html = construir_html(self.datos, self.resultado, self.hallazgos)
        matriz = _extraer_bloque(html, "matriz-tabl")
        columnas = _re.findall(r'<div class="col">([^<]+)</div>', matriz)
        filas = _re.findall(r'<div class="fila">([^<]+)</div>', matriz)
        esperadas = [
            t for t, n in self.datos["mitre_attack"]["por_tactica"].items() if n
        ]
        self.assertTrue(
            set(esperadas).issubset(set(columnas)),
            f"faltan tacticas en la matriz: {set(esperadas) - set(columnas)}",
        )
        # Cabecera y etiqueta de fila deben cubrir las mismas tacticas.
        self.assertEqual(set(columnas), set(filas))
        # Y el orden debe ser el canonico de MITRE, no uno arbitrario.
        self.assertEqual(columnas, [t for t in TACTICAS if t in set(columnas)])

    def test_matriz_tiene_celda_de_esquina_alineada(self):
        """Cada fila debe tener su etiqueta y su zona de celdas, de modo que
        una tactica con mas celdas que columnas no desalinee las filas."""
        import re as _re

        html = construir_html(self.datos, self.resultado, self.hallazgos)
        matriz = _extraer_bloque(html, "matriz-tabl")
        self.assertTrue(
            matriz.lstrip().startswith('<div class="esquina">'),
            "falta la celda de esquina inicial de la matriz",
        )
        etiquetas = len(_re.findall(r'<div class="fila">', matriz))
        zonas = len(_re.findall(r'<div class="celda-zona"', matriz))
        self.assertEqual(etiquetas, zonas, "cada fila debe tener su zona de celdas")
        # Todas las zonas deben compartir la misma plantilla de columnas.
        plantillas = set(_re.findall(r'<div class="celda-zona" style="([^"]+)"', matriz))
        self.assertEqual(len(plantillas), 1, "las zonas de celdas no comparten columnas")

    def test_matriz_agrupa_hallazgos_repetidos(self):
        """Un mismo hallazgo en varios puertos no debe repetirse por celda."""
        import re as _re

        html = construir_html(self.datos, self.resultado, self.hallazgos)
        matriz = _extraer_bloque(html, "matriz-tabl")
        # Si hay agrupacion, alguna celda debe indicar varios hosts.
        self.assertRegex(matriz, r"\d+ host\(s\)|\+\d+ mas")

    def test_chips_attack_no_se_muestran_como_texto_escapado(self):
        """Los chips <code> de ATT&CK deben renderizarse, no aparecer como
        texto literal &lt;code&gt;."""
        html = construir_html(self.datos, self.resultado, self.hallazgos)
        self.assertNotIn("&lt;code&gt;", html, "HTML escapado visible en el informe")
        self.assertRegex(html, r"<code>T\d{4}")

    def test_html_aclara_que_no_es_ataque(self):
        html = construir_html(self.datos, self.resultado, self.hallazgos)
        self.assertIn("no explota vulnerabilidades", html)
        self.assertIn("autorizacion", html)

    def test_guardar_reporte_crea_estructura(self):
        with tempfile.TemporaryDirectory() as temporal:
            generado = guardar_reporte(
                self.resultado, self.hallazgos, base_reportes=temporal
            )
            self.assertTrue(os.path.isfile(generado.ruta_html))
            self.assertTrue(os.path.isfile(generado.ruta_json))
            self.assertTrue(os.path.isfile(generado.ruta_xml))
            self.assertTrue(generado.ruta_xml.endswith(os.path.join("datos_crudos", "nmap.xml")))
            self.assertEqual(os.path.basename(generado.directorio)[:10].count("-"), 2)
            with open(generado.ruta_json, "r", encoding="utf-8") as manejador:
                datos = json.load(manejador)
            self.assertEqual(datos["esquema"]["nombre"], "netaudit-reporte")

    def test_json_es_la_ultima_palabra(self):
        """El JSON del disco debe contener exactamente los mismos hallazgos."""
        with tempfile.TemporaryDirectory() as temporal:
            generado = guardar_reporte(
                self.resultado, self.hallazgos, base_reportes=temporal
            )
            with open(generado.ruta_json, "r", encoding="utf-8") as manejador:
                datos = json.load(manejador)
        self.assertEqual(len(datos["hallazgos"]), len(self.hallazgos))
        for hallazgo, serializado in zip(self.hallazgos, datos["hallazgos"]):
            self.assertEqual(hallazgo.regla, serializado["regla"])
            self.assertEqual(hallazgo.severidad, serializado["severidad"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
