# DiskHoard

Analizador y limpiador de disco para Windows. Escanea el árbol que le digas, te enseña
**cuánto pesa cada carpeta por nivel**, te dice **dónde se concentra el peso de verdad** y
te deja borrar desde la propia interfaz.

Nace de un problema concreto: tener cientos de gigas ocupados sin saber en qué, y acabar
abriendo *Propiedades* carpeta por carpeta, bajando un nivel cada vez que aparece una
gorda. El explorador de Windows sabe la respuesta pero no te la da.

Sin dependencias: Python 3 de la librería estándar y el navegador que ya tienes. Incluido
el servidor MCP: cualquier asistente (Faustus, Claude Desktop, Cursor…) puede escanear,
explicarte qué es cada carpeta y limpiar por ti, con las mismas reglas de seguridad.

![Explorador](docs/explorador.jpg)

## Uso

Doble clic en `DiskHoard.bat`. Se abre el navegador en `127.0.0.1`.

1. Eliges punto de partida: una unidad entera, un atajo (Escritorio, Descargas, AppData…)
   o una ruta a mano.
2. Escanea.
3. Navegas por niveles. Cada fila lleva su barra de peso, su tamaño, el porcentaje que se
   lleva de la carpeta actual, cuántos ficheros contiene y cuándo se tocó por última vez.

`DiskHoard (admin).bat` hace lo mismo como administrador, para que no aparezcan carpetas
del sistema marcadas como «sin permiso».

También hay modo consola, sin navegador:

```
python selftest.py "C:\ruta\a\escanear"
```

## Qué enseña

### Puntos calientes

La respuesta directa a *«¿dónde están mis 300 GB?»*. No es un ranking de carpetas —eso
repite abuelo, padre e hijo y no dice nada—, sino una **partición en trozos que no se
solapan**: baja por cada rama mientras el peso se pueda atribuir a una subcarpeta
concreta, y donde deja de poderse, para y lo apunta. Lo que queda repartido entre muchas
cosas pequeñas se marca como «resto disperso».

![Puntos calientes](docs/puntos-calientes.jpg)

### Basura detectada

Un catálogo de carpetas conocidas: `node_modules`, entornos virtuales, cachés de
conda/pip/npm/Gradle/Maven, `target/` de Rust, `Library/` de Unity, intermedios de Unreal,
modelos de Ollama, Hugging Face y LM Studio, cachés de uv/Bun/Go/Flutter, shaders de la GPU,
cachés de Spotify/Adobe/DaVinci, temporales de Windows, papelera, discos de Docker y WSL…

Cada una viene con **qué es, si se puede borrar y cómo se regenera**, clasificada en tres
niveles:

| | |
|---|---|
| **Seguro de borrar** | se regenera solo (`npm install`, `cargo build`, la app rehace su caché) |
| **Revisar antes** | pesado y recuperable, pero igual tardaste horas en bajarlo |
| **No tocar** | `Windows\Installer`, `WinSxS`, `.git`, `pagefile.sys`… ni seleccionable |

Las reglas usan marcadores para no dar falsos positivos: `target/` solo cuenta si hay un
`Cargo.toml` al lado, `Library/` solo si hay un `Assets/`, `venv/` solo si contiene un
`pyvenv.cfg`. Y algunas carpetas son cajones de sastre (`.cache`, `Descargas`,
`LocalCache`): se informan pero se sigue bajando dentro, y no suman en el total
recuperable para no contar dos veces.

![Basura detectada](docs/basura.jpg)

### Mapa

Treemap de la carpeta actual: el área de cada rectángulo es lo que ocupa. Clic para
entrar.

![Mapa](docs/mapa.jpg)

### Y además

- **Ficheros grandes** — los 500 más pesados del escaneo, con nota para los sospechosos
  habituales (`hiberfil.sys`, `pagefile.sys`, `.vhdx`, copias `.blend1` de Blender).
- **Por tipo** — en qué se te va el disco por categoría: vídeo, modelos de IA, discos
  virtuales, comprimidos, código…
- **Sin tocar** — carpetas de más de 1 GB cuyo fichero más reciente tiene más de un año.

## Borrado

Seleccionas con las casillas y decides:

- **Mover a la papelera** — reversible, vía `SHFileOperation` con `FOF_ALLOWUNDO`.
- **Borrar definitivamente** — no pasa por la papelera. Rápido e irreversible.
- **Generar script** — un `.ps1` comentado que revisas y ejecutas tú, con soporte de
  `-WhatIf` para ver qué haría sin tocar nada.

Nada se borra sin confirmación explícita en un diálogo que lista lo seleccionado y avisa
si hay algo marcado como «no tocar». Tras borrar, **⟳ esta carpeta** vuelve a leer solo
ese subárbol en un par de segundos y te dice cuánto ha cambiado.

## Control por agente (MCP)

`mcp_server.py` es un servidor MCP por stdio, también sin dependencias. Expone 14
herramientas que reenvía a la app en marcha (y si no está en marcha, la arranca):

| Herramienta | Qué hace |
|---|---|
| `disk_drives` | unidades con espacio usado/libre y atajos |
| `disk_scan` / `disk_status` | escanea una carpeta o unidad (espera a que acabe) / progreso |
| `disk_dir` | contenido de una carpeta del escaneo, de mayor a menor, con etiqueta de basura |
| `disk_hotspots` | los puntos calientes, sin solapes |
| `disk_junk` | basura conocida filtrada por seguridad, categoría o tamaño, con totales |
| `disk_stale` / `disk_top_files` / `disk_types` | sin tocar, ficheros grandes, por tipo |
| `disk_find` | buscar ficheros por patrón, tamaño o antigüedad en cualquier carpeta |
| `disk_explain` | qué es una carpeta o fichero, si se puede borrar y por qué |
| `disk_script` | genera y guarda el `.ps1` de limpieza (`-WhatIf`) sin tocar nada |
| `disk_delete` | borra: a la papelera por defecto; definitivo solo con `mode="permanent"` y `confirm=true` |
| `disk_rescan` | vuelve a leer una subcarpeta y empalma los números |

Lo que un agente **nunca** puede borrar, diga lo que diga: raíces de unidad, el perfil de
usuario y sus carpetas principales, `Windows`, `Archivos de programa`, `ProgramData` y todo lo
que el catálogo marca como «no tocar» (`.git`, `WinSxS`, `Windows\Installer`…). Dentro de
`Windows` solo pasa lo que el catálogo conoce como seguro (descargas de Windows Update,
volcados, logs de CBS).

Todo lo que hace el agente queda en un registro que la interfaz enseña en la cabecera
(«MCP · delete · …»); clic para ver la lista. Si el agente escanea otra raíz o borra algo,
la interfaz lo sigue sola.

Configuración para un cliente MCP genérico (Claude Desktop, Cursor…):

```json
{ "mcpServers": { "diskhoard": { "command": "python", "args": ["C:\\ruta\\DiskHoard\\mcp_server.py"] } } }
```

Variables opcionales: `DISKHOARD_URL` (por defecto `http://127.0.0.1:8817`),
`DISKHOARD_DATA_DIR` (token, url y scripts generados; por defecto `data/`),
`DISKHOARD_AUTOSTART=0` para que el puente no arranque la app por su cuenta.

### Como plugin de Faustus

El repo lleva `faustus-plugin.json`: con DiskHoard en marcha, Faustus la ve en el puerto
8817, ofrece conectarla con el formulario relleno, y usa su propio Python para el puente
(no hace falta entorno virtual). Desde el chat: «¿dónde se me va el disco?», «limpia lo
seguro de `D:\proyectos`», «¿qué es esta carpeta?».

La app también se puede arrancar a mano en el puerto que quieras:
`python -m diskhoard --port 8817 --no-browser`. `/api/health` responde sin token.

### En la familia (Hoard Hub)

DiskHoard sigue el contrato de la familia de Hoards: `GET /api/agent/tools` y `POST /api/agent/call`
aceptan también `Authorization: Bearer <data/mcp-token>` (lo que envían el proxy del Hoard Hub y los
puentes MCP, además del `X-DH-Token` / `?t=` de la interfaz); `/api/health` lleva el bloque `hoard_link`;
y cada llamada de agente se anota en el bus del hub como `agent.call` (`HOARD_EVENTS=0` lo silencia,
`HOARD_HUB_URL` cambia el hub). La librería va vendida en `diskhoard/hoard_link/` (solo librería
estándar, como el resto de la app) y se refresca con `scripts/sync_vendored.py` del repositorio del hub.

## Atajos

| Tecla | Acción |
|---|---|
| Retroceso | subir un nivel |
| Supr | mover la selección a la papelera |
| Ctrl+A | seleccionar todo en la carpeta actual |
| Esc | limpiar selección / cerrar diálogo |

## Cómo funciona por dentro

- **Escaneo multihilo con `os.scandir`.** En Windows la enumeración de un directorio ya
  devuelve los metadatos de cada entrada, así que `entry.stat()` no cuesta una llamada
  extra al sistema. De ahí la diferencia de velocidad con el explorador.
- **En memoria solo viven los directorios** (tamaño acumulado, número de ficheros, fecha
  más reciente). Los ficheros de una carpeta se listan en vivo al entrar, que es
  instantáneo y siempre está al día después de borrar.
- **Los tamaños se agregan en un recorrido post-orden iterativo**, no recursivo: hay
  árboles de `node_modules` que revientan la pila.
- **Rutas largas con prefijo `\\?\`** en todo el escaneo, porque `node_modules` pasa de
  260 caracteres constantemente. (Ojo: `SHFileOperation` no acepta ese prefijo, así que la
  papelera trabaja con la ruta normal.)
- **No se siguen *junctions* ni enlaces simbólicos.** Si se siguen, el mismo contenido se
  cuenta varias veces y los totales mienten.
- **Servidor local** con `http.server`, escuchando solo en `127.0.0.1` y con un token que
  se genera una vez y se guarda en `data/mcp-token`: la interfaz lo lleva en la URL y el
  puente MCP lo lee del fichero. La interfaz entera es un único fichero HTML sin
  dependencias externas.
- **El puente MCP no sabe de discos.** Habla JSON-RPC por stdin/stdout y reenvía cada
  llamada por HTTP; el catálogo de herramientas vive en `diskhoard/agent.py`, el mismo
  módulo que las ejecuta, así que no pueden discrepar.

### Rendimiento

Medido en un NVMe con Windows 11:

| Objetivo | Tamaño | Ficheros | Carpetas | Tiempo |
|---|---|---|---|---|
| `C:\` completo | 1,54 TB | 3,72 M | 677 k | 56 s |
| Perfil de usuario | 1,17 TB | 2,88 M | 463 k | 33 s |

Unos 50-90 k ficheros por segundo según lo caliente que esté la caché del sistema.

## Estructura

```
DiskHoard/
├── DiskHoard.bat          arranque normal
├── DiskHoard (admin).bat  arranque como administrador
├── selftest.py            modo consola
├── mcp_server.py          servidor MCP (stdio) para agentes
├── faustus-plugin.json    manifiesto para conectarla a Faustus
├── tests/                 pytest: herramientas del agente y puente MCP
└── diskhoard/
    ├── scanner.py         motor de escaneo multihilo
    ├── junk.py            catálogo de basura + puntos calientes
    ├── winfs.py           rutas largas, unidades, papelera, borrado
    ├── agent.py           catálogo de herramientas del agente y reglas de borrado
    ├── server.py          servidor HTTP local + API
    ├── hoard_link/        librería de la familia (vendida): eventos al hub, bloque de salud
    └── web/index.html     interfaz entera en un fichero
```

Tests: `python -m pytest -q tests` (solo necesita pytest).

## Limitaciones

- Solo Windows. El motor de escaneo es portable, pero la papelera y la enumeración de
  unidades usan la API de Windows.
- La interfaz está solo en castellano.
- Los tamaños son lógicos, no *tamaño en disco*: no tiene en cuenta compresión NTFS,
  ficheros dispersos ni el tamaño de clúster.

## Licencia

MIT. Ver [LICENSE](LICENSE).
