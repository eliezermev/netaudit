"""Generacion del reporte HTML autonomo y del JSON de datos.

El HTML es autocontenido: CSS embebido, sin recursos externos, sin JavaScript
obligatorio y sin fuentes remotas. Se puede abrir sin conexion a internet.
"""

from __future__ import annotations

import html
import json
import os
from typing import Any, Dict, List, Optional, Sequence

from .attack import DESCRIPCION_TACTICA, TACTICAS, construir_informe_attack
from .scanner import ResultadoEscaneo
from .utils import (
    ahora_iso,
    duracion_humana,
    escribir_archivo_texto,
    marca_temporal_directorio,
    obtener_logger,
    truncar,
)
from .vulns import (
    ALTA,
    BAJA,
    CRITICA,
    DESCRIPCION_SEVERIDAD,
    INFO,
    MEDIA,
    ORDEN_SEVERIDAD,
    Hallazgo,
    calcular_resumen,
    normalizar_severidad,
)

LOG = obtener_logger("report")

VERSION_ESQUEMA = "1.0"
NOMBRE_HERRAMIENTA = "NetAudit"

# --------------------------------------------------------------------------
# Estructura JSON
# --------------------------------------------------------------------------


def construir_json(
    resultado: ResultadoEscaneo,
    hallazgos: Sequence[Hallazgo],
    resumen,
    metadatos: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Estructura estable del reporte JSON."""
    return {
        "esquema": {
            "nombre": "netaudit-reporte",
            "version": VERSION_ESQUEMA,
            "generado": ahora_iso(),
        },
        "herramienta": {
            "nombre": NOMBRE_HERRAMIENTA,
            "version": metadatos.get("version", "2.0") if metadatos else "2.0",
            "nmap_ruta": resultado.nmap_ruta,
            "nmap_version": resultado.nmap_version,
        },
        "metadatos": metadatos or {},
        "metodologia": {
            "perfil": resultado.perfil,
            "velocidad": resultado.velocidad,
            "objetivos": [o.a_dict() for o in resultado.objetivos],
            "inicio": resultado.inicio,
            "fin": resultado.fin,
            "duracion_segundos": round(resultado.duracion_segundos, 2),
            "duracion_legible": duracion_humana(resultado.duracion_segundos),
            "lotes": resultado.lotes,
            "comandos_nmap": [" ".join(c) for c in resultado.comandos],
        },
        "resumen": {
            "hosts_analizados": len(resultado.hosts),
            "hosts_activos": len(resultado.hosts_activos),
            "total_puertos": sum(len(h.puertos) for h in resultado.hosts),
            "puertos_abiertos": resultado.total_puertos_abiertos,
            "hallazgos": resumen.total,
            "por_severidad": resumen.por_severidad,
            "score": resumen.score,
            "nota_score": resumen.nota,
        },
        "hosts": [
            {
                "direccion": host.direccion,
                "tipo": host.tipo_direccion,
                "estado": host.estado,
                "motivo_estado": host.motivo_estado,
                "nombres": host.hostnames,
                "sistema_operativo": host.os_nombre,
                "sistema_operativo_precision": host.os_precision,
                "geolocalizacion": {"latitud": host.latitud, "longitud": host.longitud}
                if (host.latitud or host.longitud)
                else None,
                "puertos": [
                    {
                        "puerto": servicio.puerto,
                        "protocolo": servicio.protocolo,
                        "estado": servicio.estado,
                        "servicio": servicio.servicio,
                        "producto": servicio.producto,
                        "version": servicio.version,
                        "extra": servicio.extra,
                        "nombre_completo": servicio.nombre_completo,
                        "metodo": servicio.metodo,
                        "confianza": servicio.confianza,
                        "banner": servicio.banner,
                        "scripts": [
                            {"id": identificador, "salida": salida}
                            for identificador, salida in servicio.scripts
                        ],
                    }
                    for servicio in host.puertos
                ],
                "scripts_host": [
                    {"id": identificador, "salida": salida}
                    for identificador, salida in host.scripts_host
                ],
            }
            for host in resultado.hosts
        ],
        "hallazgos": [hallazgo.a_dict() for hallazgo in hallazgos],
        "mitre_attack": construir_informe_attack(hallazgos),
        "recomendaciones": construir_recomendaciones(hallazgos),
        "avisos": list(resultado.avisos),
        "limitaciones": LIMITACIONES_ANALISIS,
    }


LIMITACIONES_ANALISIS = [
    "El analisis se basa unicamente en lo que nmap observa desde fuera. Los servicios "
    "que solo responden en la red interna no aparecen.",
    "Las heuristicas se basan en banners y cabeceras. Un banner puede estar manipulado, "
    "ser generico o estar desactualizado: cada regla documenta sus falsos positivos "
    "conocidos.",
    "No se verifica la explotabilidad real de ningun hallazgo: NetAudit no intenta "
    "obtener acceso, no explota vulnerabilidades y no escala privilegios.",
    "La ausencia de un hallazgo NO demuestra que el sistema sea seguro: puede haber "
    "falsos negativos por filtrado de paquetes, versiones de deteccion o falta de permisos.",
    "No se prueban credenciales por defecto ni se realizan ataques de fuerza bruta.",
    "Los resultados dependen de la version de nmap: una version antigua reduce la "
    "fiabilidad de la deteccion de versiones y de los scripts NSE.",
    "Los puertos cerrados o filtrados se listan solo si nmap los determino; un filtrado "
    "silencioso puede parecer un puerto cerrado.",
]

# Substituciones de terminologia clara para el reporte (el original tenia
# mezclas de idiomas que se corrigen aqui de forma explicita).


def construir_recomendaciones(hallazgos: Sequence[Hallazgo]) -> Dict[str, List[Dict[str, str]]]:
    """Recomendaciones priorizadas por plazo: 24 horas / 7 dias / 30 dias."""
    criticos = [h for h in hallazgos if normalizar_severidad(h.severidad) == CRITICA]
    altos = [h for h in hallazgos if normalizar_severidad(h.severidad) == ALTA]
    medios = [h for h in hallazgos if normalizar_severidad(h.severidad) == MEDIA]
    bajos = [h for h in hallazgos if normalizar_severidad(h.severidad) in (BAJA, INFO)]

    def agrupar(items: Sequence[Hallazgo]) -> List[Dict[str, str]]:
        """Acciones deduplicadas por mitigacion, con los hosts donde aplican."""
        vistos = set()
        salida: List[Dict[str, str]] = []
        for hallazgo in items:
            if hallazgo.mitigacion in vistos:
                continue
            vistos.add(hallazgo.mitigacion)
            hosts = sorted({h.host for h in items if h.mitigacion == hallazgo.mitigacion})
            salida.append(
                {
                    "accion": hallazgo.mitigacion,
                    "regla": hallazgo.regla,
                    "severidad": hallazgo.severidad,
                    "hosts": ", ".join(hosts),
                }
            )
        return salida

    return {
        "24_horas": {
            "titulo": "24 horas - contener y proteger",
            "objetivo": "Cerrar las exposiciones que permiten acceso directo o inmediato.",
            "acciones": agrupar(criticos),
        },
        "7_dias": {
            "titulo": "7 dias - corregir exposiciones serias",
            "objetivo": "Reducir la superficie de ataque y proteger los datos en transito.",
            "acciones": agrupar(altos),
        },
        "30_dias": {
            "titulo": "30 dias - endurecer y mantener",
            "objetivo": "Mejoras estructurales y mantenimiento continuo.",
            "acciones": agrupar(medios) + agrupar(bajos),
        },
    }


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

CSS = """
:root{
  --fondo:#0f1419; --panel:#161d26; --panel2:#1c242f; --borde:#2b3644;
  --texto:#e6edf3; --tenue:#9aa7b4; --acento:#58a6ff;
  --critica:#f85149; --alta:#ff8c42; --media:#f2cc60; --baja:#58d68d; --info:#7f8c8d;
}
*{box-sizing:border-box}
body{margin:0;padding:0;background:var(--fondo);color:var(--texto);
  font-family:"Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif;
  font-size:15px;line-height:1.55}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 80px}
header{border-bottom:2px solid var(--acento);padding-bottom:18px;margin-bottom:26px}
h1{margin:0 0 6px;font-size:27px;letter-spacing:.3px}
h2{margin:34px 0 12px;font-size:20px;border-left:4px solid var(--acento);padding-left:10px}
h3{margin:20px 0 8px;font-size:16px;color:var(--acento)}
.sub{color:var(--tenue);font-size:14px}
.aviso-legal{background:#2d1b1b;border:1px solid #6b2b2b;color:#ffc9c9;
  padding:12px 14px;border-radius:7px;margin:16px 0;font-size:13.5px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin:16px 0}
.card{background:var(--panel);border:1px solid var(--borde);border-radius:9px;padding:14px}
.card .valor{font-size:26px;font-weight:700}
.card .etiqueta{color:var(--tenue);font-size:12.5px;text-transform:uppercase;letter-spacing:.5px}
table{width:100%;border-collapse:collapse;margin:12px 0;font-size:13.5px;
  background:var(--panel);border-radius:8px;overflow:hidden}
th,td{padding:8px 10px;border-bottom:1px solid var(--borde);text-align:left;vertical-align:top}
th{background:var(--panel2);color:var(--acento);font-weight:600;font-size:12.5px;
  text-transform:uppercase;letter-spacing:.4px}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1b232e}
code,pre{font-family:"Cascadia Mono",Consolas,"Courier New",monospace;font-size:12.5px}
pre{background:#0b0f14;border:1px solid var(--borde);border-radius:7px;padding:11px;
  overflow-x:auto;color:#c9d1d9;white-space:pre-wrap;word-break:break-word}
code{background:#0b0f14;border:1px solid var(--borde);border-radius:4px;padding:1px 5px}
.sev{display:inline-block;padding:2px 9px;border-radius:11px;font-size:11.5px;
  font-weight:700;letter-spacing:.3px;white-space:nowrap}
.sev-CRITICA{background:var(--critica);color:#2b0d0d}
.sev-ALTA{background:var(--alta);color:#331a06}
.sev-MEDIA{background:var(--media);color:#332a06}
.sev-BAJA{background:var(--baja);color:#06301a}
.sev-INFO{background:var(--info);color:#0f1419}
.sev-bar{height:9px;border-radius:5px;background:var(--panel2);overflow:hidden;margin-top:6px}
.sev-bar span{display:block;height:100%}
.hallazgo{background:var(--panel);border:1px solid var(--borde);border-left-width:4px;
  border-radius:8px;padding:14px;margin:12px 0}
.hallazgo.CRITICA{border-left-color:var(--critica)}
.hallazgo.ALTA{border-left-color:var(--alta)}
.hallazgo.MEDIA{border-left-color:var(--media)}
.hallazgo.BAJA{border-left-color:var(--baja)}
.hallazgo.INFO{border-left-color:var(--info)}
.hallazgo h3{margin:0 0 8px;color:var(--texto);display:flex;gap:10px;
  align-items:center;flex-wrap:wrap;font-size:15.5px}
.campo{margin:8px 0}
.campo .k{color:var(--tenue);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.campo .v{color:var(--texto)}
.matriz{overflow-x:auto;background:var(--panel);border:1px solid var(--borde);
  border-radius:8px;padding:12px}
.matriz-tabl{display:grid;gap:8px}
.matriz-tabl .col{font-size:11.5px;color:var(--acento);text-align:center;font-weight:600;
  padding:6px 4px;text-transform:uppercase;letter-spacing:.3px;line-height:1.25}
.matriz-tabl .esquina{border-bottom:2px solid var(--acento)}
.matriz-tabl .col-zona,.matriz-tabl .celda-zona{display:grid;gap:6px;align-items:start}
.matriz-tabl .col-zona{border-bottom:2px solid var(--acento);padding-bottom:6px}
.matriz-tabl .fila{font-size:12px;color:var(--texto);font-weight:600;
  border-right:1px solid var(--borde);padding-right:8px;align-self:stretch;
  display:flex;align-items:center}
.celda{background:var(--panel2);border-radius:6px;padding:7px;font-size:11.5px;
  border:1px solid var(--borde)}
.celda.vacia{background:transparent;border:1px dashed var(--borde);color:var(--tenue);
  text-align:center;grid-column:1 / -1}
.celda .tid{color:var(--acento);font-weight:700;font-size:12px}
.celda .tnombre{margin:2px 0 4px;color:var(--texto)}
.celda .thall{color:var(--tenue);font-size:11px;line-height:1.35}
.celda.CRITICA{border-color:var(--critica)}
.celda.ALTA{border-color:var(--alta)}
.celda.MEDIA{border-color:var(--media)}
.camino{background:var(--panel);border:1px solid var(--borde);border-radius:8px;
  padding:14px;margin:12px 0}
.camino ol{margin:8px 0;padding-left:20px}
.camino li{margin:5px 0}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--borde);
  color:var(--tenue);font-size:12.5px}
.principal{font-weight:600;color:var(--texto)}
ul.limpio{list-style:none;padding-left:0}
ul.limpio li{margin:6px 0;padding:9px 12px;background:var(--panel);
  border:1px solid var(--borde);border-radius:7px}
@media print{
  body{background:#fff;color:#111}
  .card,table,.hallazgo,.camino,.matriz{background:#fff;border-color:#bbb}
  th{background:#eee;color:#111} pre,code{background:#f4f4f4;color:#111}
  h2,h3,.card .valor{color:#111}
}
"""


def _e(texto: Any) -> str:
    """Escapa HTML."""
    if texto is None:
        return ""
    return html.escape(str(texto), quote=True)


def _sev(severidad: str) -> str:
    return normalizar_severidad(severidad)


def _etiqueta_sev(severidad: str) -> str:
    nivel = _sev(severidad)
    return f'<span class="sev sev-{nivel}">{nivel}</span>'


def _bloque(campo: str, valor: Any, pre: bool = False) -> str:
    """Campo con texto ESCAPADO. Usar para cualquier dato del escaneo."""
    if valor is None or valor == "":
        return ""
    if pre:
        contenido = f"<pre>{_e(valor)}</pre>"
    else:
        contenido = f'<div class="v">{_e(valor)}</div>'
    return f'<div class="campo"><div class="k">{_e(campo)}</div>{contenido}</div>'


def _bloque_html(campo: str, html: Any) -> str:
    """Campo con HTML YA construccion interna y de confianza.

    Solo usar con contenido generado por el propio modulo (por ejemplo chips
    `<code>` de tecnicas ATT&CK). Nunca con datosTexts del objetivo: para eso
    esta `_bloque`, que escapa.
    """
    if html is None or html == "":
        return ""
    return f'<div class="campo"><div class="k">{_e(campo)}</div><div class="v">{html}</div></div>'


def _tabla(cabeceras: Sequence[str], filas: Sequence[Sequence[Any]]) -> str:
    """Construye una tabla.

    `filas` debe ser una secuencia de filas, y cada fila una secuencia de
    celdas ya en HTML. Se valida explicitamente porque un error aqui produce
    HTML corrupto que el navegador renderiza como texto (y rompe el informe).
    """
    if not filas:
        return '<p class="sub">Sin datos.</p>'

    for indice, fila in enumerate(filas):
        if isinstance(fila, str):
            raise ValueError(
                f"_tabla recibio una fila como texto en la posicion {indice}. "
                "Cada fila debe ser una LISTA de celdas, no un <tr> completo."
            )

    encabezado = "".join(f"<th>{_e(c)}</th>" for c in cabeceras)
    cuerpo = "\n".join(
        "<tr>" + "".join(f"<td>{celda}</td>" for celda in fila) + "</tr>" for fila in filas
    )
    return f"<table><thead><tr>{encabezado}</tr></thead><tbody>{cuerpo}</tbody></table>"


def _seccion_resumen(resumen, resultado: ResultadoEscaneo) -> str:
    tarjetas = [
        ("Hosts activos", str(len(resultado.hosts_activos))),
        ("Hosts analizados", str(len(resultado.hosts))),
        ("Puertos abiertos", str(resultado.total_puertos_abiertos)),
        ("Hallazgos", str(resumen.total)),
        ("Score global", f"{resumen.score}/100"),
        ("Duracion", duracion_humana(resultado.duracion_segundos)),
    ]
    bloques = "".join(
        f'<div class="card"><div class="valor">{_e(valor)}</div>'
        f'<div class="etiqueta">{_e(etiqueta)}</div></div>'
        for etiqueta, valor in tarjetas
    )

    total = max(1, resumen.total)
    barras = []
    for nivel in ORDEN_SEVERIDAD:
        cantidad = resumen.por_severidad.get(nivel, 0)
        porcentaje = int(round(100 * cantidad / total)) if resumen.total else 0
        color = {
            CRITICA: "var(--critica)", ALTA: "var(--alta)",
            MEDIA: "var(--media)", BAJA: "var(--baja)", INFO: "var(--info)",
        }[nivel]
        barras.append(
            [
                _etiqueta_sev(nivel),
                f'<span class="principal">{cantidad}</span>',
                f'<div class="sev-bar"><span style="width:{porcentaje}%;background:{color}"></span></div>',
                _e(DESCRIPCION_SEVERIDAD[nivel]),
            ]
        )
    return f'<div class="grid">{bloques}</div>{_tabla(["Severidad", "Total", "Proporcion", "Significado"], barras)}'


def _seccion_hosts(resultado: ResultadoEscaneo) -> str:
    filas = []
    for host in resultado.hosts:
        puertos = ", ".join(
            f"{s.puerto}/{s.protocolo}" for s in host.puertos_abiertos
        ) or "ninguno"
        filas.append(
            [
                f'<span class="principal">{_e(host.direccion)}</span>',
                _e(host.nombre_principal or "-"),
                _e(host.estado),
                _e(puertos),
                _e(host.os_nombre or "-"),
                f"{host.os_precision}%" if host.os_precision else "-",
            ]
        )
    return _tabla(["IP", "Hostname", "Estado", "Puertos abiertos", "SO detectado", "Precision"], filas)


def _seccion_puertos(resultado: ResultadoEscaneo) -> str:
    filas = []
    for host in resultado.hosts:
        for servicio in host.puertos:
            filas.append(
                [
                    _e(host.direccion),
                    f"{servicio.puerto}/{servicio.protocolo}",
                    _etiqueta_sev("BAJA") if servicio.estado == "open" else _e(servicio.estado),
                    _e(servicio.nombre_completo),
                    _e(servicio.metodo or "-"),
                    _e(truncar(servicio.banner, 220) or "-"),
                ]
            )
    return _tabla(
        ["IP", "Puerto", "Estado", "Servicio", "Metodo", "Banner"], filas
    )


def _seccion_hallazgos(hallazgos: Sequence[Hallazgo]) -> str:
    if not hallazgos:
        return (
            '<div class="hallazgo INFO"><h3>Sin hallazgos</h3>'
            "<p>Las reglas heuristicas no detectaron debilidades. Esto NO demuestra que "
            "la red sea segura: revisa las limitaciones del analisis.</p></div>"
        )
    bloques = []
    for indice, hallazgo in enumerate(hallazgos, start=1):
        nivel = _sev(hallazgo.severidad)
        tecnicas = ""
        if hallazgo.tecnicas:
            chips = " ".join(
                f'<code>{_e(t.identificador)} {_e(t.nombre)}</code>' for t in hallazgo.tecnicas
            )
            tecnicas = _bloque_html("MITRE ATT&CK", chips)
        bloques.append(
            f'<div class="hallazgo {nivel}">'
            f"<h3>{indice}. {_e(hallazgo.titulo)} {_etiqueta_sev(hallazgo.severidad)}</h3>"
            f"{_bloque('Host / Puerto / Servicio', f'{hallazgo.host} | {hallazgo.puerto} | {hallazgo.servicio}')}"
            f"{_bloque('Riesgo real', hallazgo.riesgo)}"
            f"{_bloque('Evidencia exacta', truncar(hallazgo.evidencia, 2500), pre=True)}"
            f"{_bloque('Mitigacion concreta', hallazgo.mitigacion)}"
            f"{tecnicas}"
            f"{_bloque('Falsos positivos conocidos', hallazgo.falsos_positivos)}"
            f"{_bloque('Regla', hallazgo.regla)}"
            f"</div>"
        )
    return "\n".join(bloques)


def _seccion_attack(informe_attack: Dict[str, Any]) -> str:
    matriz = informe_attack.get("matriz") or []
    if not matriz:
        return '<p class="sub">Ningun hallazgo pudo mapearse a una tecnica ATT&CK.</p>'

    por_tactica = informe_attack.get("por_tactica") or {}

    # Se muestran TODAS las tacticas con tecnicas mapeadas, en el orden
    # canonico de MITRE. No se recortan columnas: esconder 'Credential Access'
    # o 'Lateral Movement' ocultaria precisamente los hallazgos mas graves.
    columnas = [t for t in TACTICAS if por_tactica.get(t)]
    if not columnas:
        columnas = list(TACTICAS)

    ancho_columna = 168
    ancho_total = 150 + ancho_columna * len(columnas)
    # Rejilla de DOS niveles: la etiqueta de tactica siempre ocupa la columna 1
    # y su zona de celdas la columna 2, de modo que las filas no pueden
    # desalinearse por tener mas o menos celdas que columnas.
    estilo_interno = (
        f"grid-template-columns:repeat({len(columnas)},minmax({ancho_columna}px,1fr));"
    )
    estilo_externo = f"grid-template-columns:150px 1fr;min-width:{ancho_total}px;"

    celdas_html = [
        f'<div class="esquina"></div>',
        f'<div class="col-zona" style="{estilo_interno}">'
        + "".join(f'<div class="col">{_e(t)}</div>' for t in columnas)
        + "</div>",
    ]

    for tactica in columnas:
        nodos = por_tactica.get(tactica) or []
        celdas = [
            f'<div class="celda {_sev(nodo.get("severidad_maxima", "INFO"))}">'
            f'<div class="tid">{_e(nodo["tecnica"]["id"])}</div>'
            f'<div class="tnombre">{_e(nodo["tecnica"]["nombre"])}</div>'
            f'<div class="thall">{_resumen_hallazgos_celda(nodo.get("hallazgos") or [])}</div>'
            f"</div>"
            for nodo in nodos
        ] or ['<div class="celda vacia">Sin tecnicas mapeadas</div>']
        celdas_html.append(f'<div class="fila">{_e(tactica)}</div>')
        celdas_html.append(
            f'<div class="celda-zona" style="{estilo_interno}">' + "".join(celdas) + "</div>"
        )

    html_matriz = (
        '<div class="matriz"><div class="matriz-tabl" style="'
        + estilo_externo
        + '">'
        + "".join(celdas_html)
        + "</div></div>"
    )

    filas = []
    for nodo in matriz:
        tecnica = nodo["tecnica"]
        filas.append(
            [
                f'<code>{_e(tecnica["id"])}</code>',
                _e(tecnica["nombre"]),
                _e(tecnica["tactica"]),
                _e(truncar(tecnica["justificacion"], 200)),
                ", ".join(nodo.get("hosts", [])[:6]) or "-",
                _etiqueta_sev(nodo.get("severidad_maxima", "INFO")),
            ]
        )
    tabla = _tabla(["ID", "Tecnica", "Tactica", "Justificacion", "Hosts", "Severidad"], filas)

    caminos_html = ""
    caminos = informe_attack.get("caminos_ataque") or []
    if caminos:
        items = []
        for camino in caminos:
            pasos = "".join(f"<li>{_e(paso)}</li>" for paso in camino["pasos"])
            items.append(
                f'<div class="camino"><h3>{_e(camino["titulo"])} {_etiqueta_sev(camino["severidad"])}</h3>'
                f'<div class="sub">Hosts: {_e(", ".join(camino["hosts"]) or "n/d")} | '
                f'Tecnicas: {_e(", ".join(camino["tecnicas"]))}</div>'
                f"<ol>{pasos}</ol>"
                f"{_bloque('Impacto probable', camino['impacto'])}</div>"
            )
        caminos_html = (
            "<h3>Caminos de ataque probables</h3>"
            '<p class="sub">Cadenas logicas construidas a partir de la exposicion '
            "detectada. Son razonamientos de priorizacion, no actividades realizadas "
            "ni predicciones de un atacante real.</p>" + "".join(items)
        )

    return (
        f'<p class="sub">Tecnicas alcanzadas: '
        f"{_e(', '.join(informe_attack.get('tecnicas_totales', [])) or 'ninguna')} | "
        f"Tacticas con actividad: {_e(', '.join(columnas))}</p>"
        '<p class="sub">La matriz se desplaza horizontalmente para mostrar todas las '
        "tacticas implicadas.</p>"
        + html_matriz
        + tabla
        + caminos_html
    )


def _resumen_hallazgos_celda(hallazgos: Sequence[Any], maximo: int = 3) -> str:
    """Resume los hallazgos de una celda agrupando titulos repetidos.

    Evita repetir 'Base de datos sin autenticacion (host)' cuatro veces cuando
    el mismo hallazgo aparece en varios puertos del mismo host.
    """
    conteo: Dict[str, List[str]] = {}
    orden: List[str] = []
    for hallazgo in hallazgos:
        titulo = str(hallazgo.get("titulo", "")).strip() or "Hallazgo"
        host = str(hallazgo.get("host", "")).strip()
        if titulo not in conteo:
            conteo[titulo] = []
            orden.append(titulo)
        if host and host not in conteo[titulo]:
            conteo[titulo].append(host)

    partes: List[str] = []
    for titulo in orden[:maximo]:
        hosts = conteo[titulo]
        sufijo = f" ({len(hosts)} host(s))" if len(hosts) > 1 else (
            f" ({hosts[0]})" if hosts else ""
        )
        partes.append(f'<div class="thall">{_e(titulo)}{_e(sufijo)}</div>')
    restantes = len(orden) - maximo
    if restantes > 0:
        partes.append(f'<div class="thall">+{restantes} mas</div>')
    return "".join(partes)


def _seccion_recomendaciones(recomendaciones: Dict[str, Any]) -> str:
    bloques = []
    for clave in ("24_horas", "7_dias", "30_dias"):
        grupo = recomendaciones.get(clave) or {}
        acciones = grupo.get("acciones") or []
        lista = "".join(
            f'<li><b>{_e(a["accion"])}</b><br><span class="sub">'
            f'Regla: {_e(a["regla"])} | Hosts: {_e(a["hosts"] or "n/d")}</span></li>'
            for a in acciones
        ) or "<li class='sub'>Sin acciones pendientes en este plazo.</li>"
        bloques.append(
            f'<h3>{_e(grupo.get("titulo", clave))}</h3>'
            f'<p class="sub">{_e(grupo.get("objetivo", ""))}</p>'
            f'<ul class="limpio">{lista}</ul>'
        )
    return "".join(bloques)


def construir_html(
    datos: Dict[str, Any],
    resultado: ResultadoEscaneo,
    hallazgos: Sequence[Hallazgo],
) -> str:
    """Genera el HTML autonomo del reporte."""
    resumen = datos["resumen"]
    metodologia = datos["metodologia"]
    objetivos = ", ".join(o.valor_normalizado for o in resultado.objetivos)

    comandos_html = "\n".join(_e(" ".join(c)) for c in resultado.comandos)
    limitaciones_html = "".join(f"<li>{_e(limite)}</li>" for limite in LIMITACIONES_ANALISIS)

    tecnicas_html = ""
    if datos["mitre_attack"].get("total_tecnicas"):
        tacticas = datos["mitre_attack"].get("tacticas_alcanzadas", [])
        chips = " ".join(
            f'<code>{_e(t)} - {_e(DESCRIPCION_TACTICA.get(t, ""))}</code>' for t in tacticas
        )
        tecnicas_html = _bloque_html("Tacticas alcanzadas", chips)

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(NOMBRE_HERRAMIENTA)} - Reporte {_e(datos['esquema']['generado'])}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>{_e(NOMBRE_HERRAMIENTA)} - Reporte de evaluacion de red</h1>
  <div class="sub">Generado el {_e(datos['esquema']['generado'])} | Autorizado por escrito por el responsable de la red</div>
</header>

<div class="aviso-legal">
  <b>Alcance y autorizacion.</b> Este informe se genero unicamente sobre redes con
  autorizacion escrita explicita. NetAudit es una herramienta de descubrimiento y
  evaluacion defensiva: no explota vulnerabilidades, no obtiene acceso, no escala
  privilegios y no evade deteccion. Los hallazgos describen exposicion observada,
  no compromiso demostrado.
</div>

<h2>1. Resumen ejecutivo</h2>
<p class="sub">Se analizaron {_e(resumen['hosts_analizados'])} host(s), de los que
{_e(resumen['hosts_activos'])} respondieron, con {_e(resumen['puertos_abiertos'])} puerto(s)
abierto(s). El motor de reglas identifico {_e(resumen['hallazgos'])} hallazgo(s)
({_e(resumen['por_severidad'][CRITICA])} critico(s),
{_e(resumen['por_severidad'][ALTA])} alto(s),
{_e(resumen['por_severidad'][MEDIA])} medio(s),
{_e(resumen['por_severidad'][BAJA])} bajo(s)). Score global de exposicion:
{_e(resumen['score'])}/100.</p>
{_seccion_resumen(_reconstruir_resumen(resumen), resultado)}
{_bloque('Nota sobre el score', resumen['nota_score'])}

<h2>2. Metodologia</h2>
{_tabla(["Parametro", "Valor"], [
    ["Herramienta", f"{NOMBRE_HERRAMIENTA} {datos['herramienta']['version']}"],
    ["nmap", _e(datos['herramienta']['nmap_version'] or 'n/d')],
    ["Ruta de nmap", _e(datos['herramienta']['nmap_ruta'] or 'n/d')],
    ["Perfil de escaneo", _e(metodologia['perfil'])],
    ["Velocidad (-T)", _e(metodologia['velocidad'])],
    ["Objetivos", _e(objetivos)],
    ["Inicio / Fin", f"{_e(metodologia['inicio'] or 'n/d')} / {_e(metodologia['fin'] or 'n/d')}"],
    ["Duracion", _e(metodologia['duracion_legible'])],
    ["Lotes de escaneo", _e(metodologia['lotes'])],
])}
<p class="sub">Metodologia: descubrimiento y enumeracion con nmap en modo solo-lectura,
seguido de analisis heuristico de banners y cabeceras ya obtenidas. No se envio ninguna
peticion de escritura ni se intento autenticarse en ningun servicio.</p>

<h2>3. Hosts</h2>
{_seccion_hosts(resultado)}

<h2>4. Puertos, servicios y banners</h2>
{_seccion_puertos(resultado)}

<h2>5. Hallazgos</h2>
<p class="sub">Cada hallazgo incluye riesgo real, evidencia exacta, mitigacion concreta
y los falsos positivos conocidos de su regla.</p>
{_seccion_hallazgos(hallazgos)}

<h2>6. Matriz MITRE ATT&amp;CK</h2>
{tecnicas_html}
{_seccion_attack(datos['mitre_attack'])}

<h2>7. Recomendaciones priorizadas</h2>
{_seccion_recomendaciones(datos['recomendaciones'])}

<h2>8. Anexo A - Comandos nmap ejecutados</h2>
<pre>{comandos_html}</pre>

<h2>9. Anexo B - Limitaciones del analisis</h2>
<ul>{limitaciones_html}</ul>
{_bloque('Avisos de la ejecucion', "\n".join(datos.get('avisos') or []) or 'ninguno', pre=True)}

<footer>
  {_e(NOMBRE_HERRAMIENTA)} | Informe generado automaticamente a partir de la salida XML de nmap.
  Documento de evaluacion defensiva. Distribuir solo dentro del ambito autorizado.
</footer>
</div>
</body>
</html>"""


def _reconstruir_resumen(resumen_json: Dict[str, Any]):
    """Reconstruye el objeto Resumen desde el JSON para las funciones de render."""
    from .vulns import Resumen

    por_severidad = {nivel: resumen_json["por_severidad"].get(nivel, 0) for nivel in ORDEN_SEVERIDAD}
    return Resumen(
        por_severidad=por_severidad,
        total=resumen_json["hallazgos"],
        score=resumen_json["score"],
        nota=resumen_json["nota_score"],
    )


# --------------------------------------------------------------------------
# Escritura en disco
# --------------------------------------------------------------------------


class ResultadoReporte:
    """Rutas de los ficheros generados."""

    def __init__(self, directorio: str, html: str, json_ruta: str, xml_ruta: Optional[str]):
        self.directorio = directorio
        self.ruta_html = html
        self.ruta_json = json_ruta
        self.ruta_xml = xml_ruta

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.directorio


def guardar_reporte(
    resultado: ResultadoEscaneo,
    hallazgos: Sequence[Hallazgo],
    base_reportes: str = "reportes",
    metadatos: Optional[Dict[str, Any]] = None,
    guardar_xml: bool = True,
) -> ResultadoReporte:
    """Genera el reporte en ./reportes/AAAA-MM-DD_HHMMSS/."""
    directorio = os.path.join(base_reportes, marca_temporal_directorio())
    os.makedirs(os.path.join(directorio, "datos_crudos"), exist_ok=True)

    resumen = calcular_resumen(hallazgos)
    datos = construir_json(resultado, hallazgos, resumen, metadatos)

    ruta_html = os.path.join(directorio, "reporte.html")
    ruta_json = os.path.join(directorio, "reporte.json")

    contenido_html = construir_html(datos, resultado, hallazgos)
    escribir_archivo_texto(ruta_html, contenido_html)
    escribir_archivo_texto(ruta_json, json.dumps(datos, ensure_ascii=False, indent=2))

    ruta_xml = None
    if guardar_xml and resultado.xml_crudo:
        ruta_xml = os.path.join(directorio, "datos_crudos", "nmap.xml")
        escribir_archivo_texto(ruta_xml, resultado.xml_crudo)

    LOG.info("Reporte generado en %s", directorio)
    return ResultadoReporte(directorio, ruta_html, ruta_json, ruta_xml)


def guardar_xml_crudo(xml: str, base_reportes: str = "reportes") -> str:
    """Guarda el XML crudo aunque el escaneo haya fallado (para auditoria)."""
    directorio = os.path.join(base_reportes, marca_temporal_directorio())
    os.makedirs(os.path.join(directorio, "datos_crudos"), exist_ok=True)
    ruta = os.path.join(directorio, "datos_crudos", "nmap.xml")
    escribir_archivo_texto(ruta, xml)
    return ruta


def nombre_archivo_sugerido() -> str:
    return f"netaudit_{marca_temporal_directorio()}"
