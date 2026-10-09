# NetAudit 2.0 — auditoría de red defensiva

**NetAudit** es una herramienta de *pentesting* de red **pasivo y defensivo** que
usa `nmap` como motor de descubrimiento. Analiza los servicios expuestos, aplica
reglas heurísticas sobre banners y cabeceras, clasifica los hallazgos en
**MITRE ATT&CK** y genera un informe HTML autónomo.

---

## ⚠️ Aviso legal y de autorización

> **Use NetAudit únicamente sobre redes para las que tenga autorización escrita
> y explícita del responsable de la red.**
>
> Escanear sistemas de terceros sin permiso puede ser **ilegal** en la mayoría
> de países (leyes de abuso de equipos y de intrusión en redes, CFAA, NIS2,
> LSSI…). Usted es el único responsable de cómo usa esta herramienta.

NetAudit **exige una confirmación interactiva antes de escanear**: hay que
escribir literalmente la palabra `AUTORIZADO` y el objetivo. En los objetivos
sensibles (`0.0.0.0/0`, loopback, multicast, IPs públicas) además se exige una
segunda confirmación con la palabra `SEGURO`.

### Qué NO hace NetAudit

NetAudit está construida para **descubrir y evaluar**, no para atacar. No incluye
y no hará nunca:

| No hace | Detalle |
|---|---|
| Exploits | Ningún exploit, PoC ni payload. |
| Credenciales por defecto | No prueba `public`/`private`, `admin/admin`, ni ninguna credencial contra ningún servicio. |
| Obtención de acceso | No se autentica en ningún servicio ni intenta iniciar sesión. |
| Escalamiento de privilegios | No busca ni ejecuta nada que eleve privilegios. |
| Evasión | No oculta su actividad, no evade IDS/AV y no borra rastros. |
| Movimiento lateral | No salta de un host a otro. |
| Ataques de denegación | No genera carga para tumbar servicios (solo `-T5` acelera el escaneo). |
| Escritura en objetivos | No envía peticiones de escritura ni modifica nada en el objetivo. |

Toda la información procede de lo que **nmap ya observó** en modo lectura. Las
reglas son heurísticas sobre banners: describen **exposición**, nunca compromiso
demostrado.

---

## Requisitos

| Requisito | Detalle |
|---|---|
| Python | **3.11 o superior** (probado en 3.11/3.12/3.13) |
| nmap | **7.80 o superior** (dependencia **obligatoria**) |
| Dependencias pip | **Ninguna**. Solo biblioteca estándar. |

> **nmap no es opcional.** No existe modo reducido, ni modo simulación, ni
> fallback pasivo: sin nmap el programa termina con código de salida **2**.

### Instalar Python

- **Windows**: `winget install Python.Python.3.12` (o desde <https://www.python.org/downloads/>)
- **Linux**: `sudo apt install python3 python3-venv` / `dnf install python3`
- **macOS**: `brew install python@3.12`

### Instalar nmap

**Windows**
```powershell
winget install Insecure.Nmap
```
También puedes descargar el instalador desde <https://nmap.org/download.html>
(requiere permisos de administrador). NetAudit detecta automáticamente
`C:\Program Files (x86)\Nmap\nmap.exe` si `nmap` no está en el `PATH`.

**Linux**
```bash
sudo apt install nmap        # Debian / Ubuntu / Kali
sudo dnf install nmap        # Fedora / RHEL
sudo pacman -S nmap          # Arch / Manjaro
```

**macOS**
```bash
brew install nmap
```

> Si instalas nmap **mientras NetAudit está abierto**, no hace falta reiniciar
> nada: la ruta se vuelve a resolver con `shutil.which()` en **cada**
> invocación, nunca se cachea al inicio.

### Privilegios y `-sS`

En **macOS y Linux**, el escaneo SYN (`-sS`) necesita sockets RAW. NetAudit
**no necesita que ejecute todo el script con sudo**: basta con dar permisos a
nmap o usar `sudo` solo para el comando de nmap.

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)
```

En Windows se usa TCP connect scan (`-sT`) por defecto y **no hace falta ser
administrador** para el escaneo básico.

---

## Instalación

NetAudit es un paquete de la biblioteca estándar: no requiere `pip install`.

```bash
git clone <repo> netaudit
cd netaudit
python -m netscan.cli --help
```

Opcionalmente, para tener el comando `netaudit` disponible:

```bash
python -m pip install -e .
```

---

## Uso rápido (5 pasos)

```bash
python -m netscan.cli                                              # 1. menú interactivo
#   -> elige SO -> opción 1 -> objetivo -> velocidad -> escribe AUTORIZADO
python -m netscan.cli scan --target 192.168.1.0/24 --autorizado    # 2. no interactivo
python -m netscan.cli scan --target 192.168.1.10 -p 22,80,443 --autorizado
python -m netscan.cli scan --target 192.168.1.0/24 --profile web --format json --autorizado
xdg-open reportes/AAAA-MM-DD_HHMMSS/reporte.html                  # 3. abrir informe
```

---

## Modo interactivo

```bash
python -m netscan.cli
```

Al arrancar muestra el menú de sistema operativo (**no simula ejecución**: solo
adapta los comandos de instalación que se muestran y las diferencias reales de
ejecución) y después el menú principal:

```
  [1] Escaneo rapido                 TCP connect scan con deteccion de versiones (1000 puertos)
  [2] Escaneo completo               Servicios, scripts NSE y deteccion de SO
  [3] Servidor web                   Solo puertos web, con scripts http-*
  [4] Puerto especifico              Escanea los puertos que indiques
  [5] Informe de un escaneo previo   Genera el informe desde un XML de nmap existente
  [6] Configuracion                  Guardar / cargar / borrar perfiles
  [0] Salir
```

Cada escaneo pide **siempre**: objetivo, perfil, **velocidad** (`-T2`…`-T5`) y
las confirmaciones.

---

## Modo no interactivo

```bash
python -m netscan.cli scan --target 192.168.1.0/24 --profile web --format json --autorizado
python -m netscan.cli scan --target 192.168.1.10 -p 22,80,443 --autorizado
python -m netscan.cli scan --target objetivos.txt --exclude 192.168.1.1-50 --autorizado
python -m netscan.cli informe --xml salida_nmap.xml
```

### Opciones de `scan`

| Opción | Descripción |
|---|---|
| `--target` | IP, CIDR, rango, hostname o lista `a,b,c` (**obligatorio**) |
| `--target-file` | Archivo `.txt` con un objetivo por línea |
| `--profile` | `discovery`, `puertos`, `completo`, `web` (def. `puertos`) |
| `-p`, `--puerto` | `22,80,443,8000-8100` |
| `-T`, `--velocidad` | `T2`, `T3`, `T4` (def.), `T5` |
| `--ss` | Usar SYN scan (`-sS`). Requiere privilegios |
| `--exclude` | Excluir IP o CIDR (repetible) |
| `--limite-hosts` | Límite de hosts por objetivo (def. **1024**) |
| `--hosts-por-lote` | Hosts por lote (def. 256) |
| `--host-timeout` | Timeout por host, p. ej. `30s`, `2m` |
| `--timeout` | Timeout global en segundos (def. 7200) |
| `--format` | `html` (def.) o `json` (imprime el JSON por **stdout**) |
| `--sin-reporte` | No escribir ficheros en disco |
| `--autorizado` | **Obligatorio**: declara la autorización escrita |

> Con `--format json`, **stdout queda reservado al JSON**; toda la información
> de progreso se escribe en **stderr**, así que `... > resultado.json` funciona.

### Códigos de salida

| Código | Significado |
|---|---|
| `0` | Escaneo correcto **sin hallazgos** |
| `1` | Escaneo correcto **con hallazgos** |
| `2` | Error de uso, objetivo inválido o **dependencia `nmap` ausente** |

---

## Perfiles de escaneo

| Perfil | Flags de nmap | Cuándo usarlo |
|---|---|---|
| `discovery` | `-sn -T4` | Acotar primero qué hosts están vivos |
| `puertos` | `-sT -sV -T4 --top-ports 1000` | Valor por defecto: rápido y útil |
| `completo` | `-sV -sC -A -T4` | Análisis detallado, más lento y más ruido |
| `web` | `-sV -p 80,443,8080,8443,8000,8888,3000,5000,9090 --script http-*` | Aplicaciones web |

La **velocidad** se pregunta siempre: `-T2` (muy discreto) · `-T3` (lento) ·
`-T4` (rápido, por defecto) · `-T5` (muy rápido, más ruido).

---

## Objetivos admitidos

| Formato | Ejemplo |
|---|---|
| IP única | `192.168.1.10` |
| CIDR | `192.168.1.0/24` |
| Rango | `192.168.1.1-50` → `192.168.1.1-192.168.1.50` |
| Hostname | `servidor.lan`, `app.example.com` |
| Varios | `192.168.1.1,192.168.1.2,servidor.lan` |
| Archivo | `-f objetivos.txt` (`--target-file`) |

Se validan formato, longitud de dominio y límites. El límite por defecto es
**1024 hosts** por objetivo (`--limite-hosts`).

### Rangos sensibles (doble confirmación)

`0.0.0.0/0`, loopback (`127.0.0.0/8`), multicast (`224.0.0.0/4`), enlace local
(`169.254.0.0/16`), CGNAT, redes de documentación y **cualquier IP pública**
exigen además escribir `SEGURO`. Un rango sensible **no** se bloquea por el
límite de hosts: es la doble confirmación lo que lo bloquea.

> Las redes privadas RFC1918 (`10/8`, `172.16/12`, `192.168/16`) son el caso de
> uso normal y solo requieren `AUTORIZADO`.

---

## Reglas de detección

Todas son **de solo lectura** sobre banners y cabeceras ya observados.

| Regla | Severidad | ATT&CK |
|---|---|---|
| Telnet (23) abierto | **CRÍTICA** | T1046, T1110.001 |
| FTP anónimo permitido | ALTA | T1190, T1083 |
| FTP sin TLS / SMB sin cifrado | ALTA | T1040 |
| SMBv1 en 445 | **CRÍTICA** | T1210, T1021.002 |
| SNMPv1/v2c con community `public`/`private` | **CRÍTICA** | T1552.001, T1087 |
| OpenSSH < 8.0 | MEDIA | T1595.002 |
| MySQL/Mongo/Redis/RabbitMQ/Elastic sin auth | **CRÍTICA** | T1190, T1213 |
| Puertos de administración (8161, 4848, 9000, 8009, 6443, 2375, 9200) | ALTA | T1190, T1133 |
| HTTP con PUT/DELETE/TRACE | MEDIA | T1190 |
| HTTP `/admin`, `/.git`, `/.env`, `/phpmyadmin`, `/actuator/env` | MEDIA/ALTA | T1190, T1552.001 |
| Cabeceras inseguras o ausentes (Server con versión, sin HSTS/CSP/XFO, cookies sin Secure/HttpOnly) | MEDIA/BAJA | T1189 |
| TLS: caducado, autofirmado, TLSv1.0/1.1, sin SNI | ALTA | T1040 |
| Servicio en versión EOL | MEDIA | T1595.002 |
| Versión de nmap antigua | INFO | — |

**Cada hallazgo incluye**: título, severidad, **riesgo real**, **evidencia exacta**
(banner o respuesta), puerto, servicio, mitigación concreta, mapeo ATT&CK y los
**falsos positivos conocidos de esa regla**.

---

## Informe generado

En `./reportes/AAAA-MM-DD_HHMMSS/`:

```
reportes/2026-10-08_191918/
├── reporte.html              # autónomo: CSS embebido, sin recursos externos
├── reporte.json              # estructura completa, esquema estable
└── datos_crudos/
    └── nmap.xml              # XML original para auditoría
```

### Cómo leer `reporte.html`

1. **Resumen ejecutivo** — tarjetas de hosts/puertos/hallazgos, **score global**
   (0–100, donde 100 es exposición crítica extendida), barras por severidad.
2. **Metodología** — versión de nmap, perfil, velocidad, objetivos, duración.
3. **Hosts** — estado, hostnames, puertos abiertos, SO detectado y su precisión.
4. **Puertos, servicios y banners** — inventario completo con el banner literal.
5. **Hallazgos** — uno a uno, ordenados por severidad. Cada tarjeta trae
   *riesgo real*, *evidencia exacta* (copiable), *mitigación concreta*,
   *técnicas ATT&CK* y *falsos positivos conocidos*.
6. **Matriz MITRE ATT&CK** — técnicas agrupadas por columna de táctica (se
   desplazan en horizontal), tabla con ID/nombre/táctica/justificación/hosts, y
   **caminos de ataque probables** (cadenas lógicas de priorización).
7. **Recomendaciones priorizadas** — acciones a **24 h / 7 días / 30 días**.
8. **Anexo A** — comandos nmap exactos ejecutados.
9. **Anexo B** — limitaciones del análisis (léelas siempre).

El HTML **no necesita internet**: ábralo con doble clic o con
`xdg-open` / `start`.

### `reporte.json`

Esquema estable, pensado para automatizar:

```jsonc
{
  "esquema":    { "nombre": "netaudit-reporte", "version": "1.0", "generado": "..." },
  "herramienta":{ "nombre": "NetAudit", "version": "2.0.0", "nmap_version": "..." },
  "metodologia":{ "perfil": "...", "velocidad": "T4", "objetivos": [...],
                  "comandos_nmap": ["..."], "duracion_segundos": 0 },
  "resumen":    { "hosts_activos": 3, "puertos_abiertos": 14, "hallazgos": 24,
                  "por_severidad": { "CRITICA": 6, "ALTA": 6, "MEDIA": 10,
                                     "BAJA": 2, "INFO": 0 },
                  "score": 100 },
  "hosts":      [ { "direccion": "...", "puertos": [ { "puerto": 23, "banner": "..." } ] } ],
  "hallazgos":  [ { "titulo": "...", "severidad": "CRITICA", "evidencia": "...",
                    "mitigacion": "...", "falsos_positivos": "...",
                    "mitre_attack": [ { "id": "T1046", "tactica": "Discovery" } ] } ],
  "mitre_attack":  { "matriz": [...], "por_tactica": {...}, "caminos_ataque": [...] },
  "recomendaciones": { "24_horas": {...}, "7_dias": {...}, "30_dias": {...} },
  "limitaciones":   [ "..." ]
}
```

---

## Arquitectura

```
netaudit2.0/
├── netscan/
│   ├── __init__.py      # metadatos del paquete
│   ├── cli.py           # menú interactivo + argparse, códigos de salida
│   ├── osdetect.py      # detección de SO, resolución e instalación de nmap
│   ├── targets.py       # validación y normalización de objetivos
│   ├── scanner.py       # invocación de nmap, lotes, parseo XML, control de procesos
│   ├── fingerprints.py  # banners, cabeceras HTTP/TLS, configs inseguras
│   ├── vulns.py         # reglas heurísticas, severidad, recomendaciones
│   ├── attack.py        # mapeo MITRE ATT&CK y caminos de ataque
│   ├── report.py        # informe HTML autónomo + JSON
│   └── utils.py         # logging, colores, helpers
├── tests/
│   ├── test_targets.py            # validación de objetivos
│   ├── test_scanner_parseo.py     # parseo de XML de nmap + construcción de comandos
│   ├── test_vulns_attack_report.py# severidad, ATT&CK y reporte
│   ├── test_osdetect_cli.py       # dependencia nmap y códigos de salida
│   ├── test_calidad_codigo.py     # calidad: sin shell=True, sin eval/exec, en español
│   └── data/ejemplo_nmap.xml      # XML de ejemplo
├── tools/                # utilidades de verificación (captura de informe)
├── requirements.txt
└── README.md
```

---

## Tests

```bash
python -m unittest discover -s tests -v
```

Cubren: validación y normalización de objetivos (incluidos rangos sensibles y
exclusiones), parseo del XML de ejemplo de nmap (incluido XML truncado y
malformado), construcción de comandos nmap, reglas y severidad, mapeo ATT&CK,
generación del informe y los **códigos de salida** de la CLI.

Los tests **no realizan escaneos reales ni acceden a la red**.

---

## Seguridad del propio código

- Los comandos de nmap se construyen **siempre como lista de argumentos**.
- **Nunca** `shell=True`, `os.system`, `eval` ni `exec`
  (verificado automáticamente por `tests/test_calidad_codigo.py`).
- Sin variables globales mutables.
- Los datos del objetivo se **escapan** al generar el HTML.
- Ante cualquier fallo de nmap (código ≠ 0, XML truncado, cuelgue) se muestra un
  mensaje accionable y **no se genera un informe falso**.

---

## Solución de problemas

| Síntoma | Causa y solución |
|---|---|
| `nmap no esta instalado` (salida 2) | Instálalo con los comandos del apartado *Instalar nmap*. |
| NetAudit no ve nmap tras instalarlo | Reabre la terminal, o acepta la detección de `C:\Program Files (x86)\Nmap\nmap.exe`. |
| `-sS` falla con *"permission denied"* | Dale permisos a nmap: `sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)`. |
| El escaneo tarda mucho | Menos objetivos, perfil `discovery` primero, `-T3`, `--host-timeout 30s`. |
| `El XML parece truncado` | nmap se interrumpió. Sube `--timeout` o reduce el alcance. El XML se conserva en `reportes/datos_crudos_fallidos/`. |
| Aviso de nmap antiguo | Actualiza a 7.80+. Se continúa, pero el análisis puede tener falsos negativos. |
| Faltan hallazgos esperados | Los banners genéricos o los falsos positivos documentados pueden ocultarlos. Revisa el Anexo B. |

---

## Licencia y uso responsable

Herramienta de auditoría defensiva. Úsela solo con autorización escrita, sobre
redes propias o sobre las que tenga permiso contractual explícito.
