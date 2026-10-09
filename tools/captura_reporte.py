"""Captura el reporte HTML para verificar visualmente que renderiza bien.

Uso: python tools/captura_reporte.py [ruta_html]
Genera tools/captura_reporte.png
"""
import os
import sys

from playwright.sync_api import sync_playwright

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ruta_html_mas_reciente() -> str:
    base = os.path.join(RAIZ, "reportes")
    carpetas = sorted(
        (d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))),
        reverse=True,
    )
    for carpeta in carpetas:
        candidato = os.path.join(base, carpeta, "reporte.html")
        if os.path.isfile(candidato):
            return candidato
    raise SystemExit("No se encontro ningun reporte.html en ./reportes")


def main() -> None:
    ruta = sys.argv[1] if len(sys.argv) > 1 else ruta_html_mas_reciente()
    salida = os.path.join(RAIZ, "tools", "captura_reporte.png")
    os.makedirs(os.path.dirname(salida), exist_ok=True)
    print(f"Capturando: {ruta}")
    with sync_playwright() as p:
        navegador = p.chromium.launch()
        pagina = navegador.new_page(viewport={"width": 1400, "height": 1100})
        pagina.goto(f"file:///{ruta.replace(os.sep, '/')}")
        pagina.wait_for_timeout(600)
        # Vista completa del informe + un recorte de la zona de hallazgos.
        pagina.screenshot(path=salida, full_page=True)
        hallazgos = pagina.query_selector_all(".hallazgo")
        if hallazgos:
            hallazgos[0].scroll_into_view_if_needed()
            pagina.wait_for_timeout(300)
            pagina.screenshot(path=salida.replace(".png", "_hallazgos.png"))
        ancho = pagina.evaluate("document.body.scrollWidth")
        alto = pagina.evaluate("document.body.scrollHeight")
        print(f"Lienzo: {ancho}x{alto}")
        print(f"Secciones h2: {len(pagina.query_selector_all('h2'))}")
        print(f"Hallazgos renderizados: {len(hallazgos)}")
        navegador.close()
    print(f"OK -> {salida}")


if __name__ == "__main__":
    main()
