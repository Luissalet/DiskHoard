# -*- coding: utf-8 -*-
"""Catalogo de basura conocida y deteccion de puntos calientes.

Cada regla identifica carpetas que suelen ocupar mucho y explica en cristiano
que son, si se pueden borrar y como se regeneran. Nada se borra desde aqui:
esto solo clasifica.
"""
from __future__ import annotations

import os

SAFE = "safe"        # regenerable, borrar es seguro
REVIEW = "review"    # pesado y recuperable, pero mira antes
DANGER = "danger"    # no lo toques

# name: nombre exacto de carpeta (minusculas)
# suffix: la ruta completa debe terminar asi (minusculas)
# marker: alguno de estos ficheros/carpetas debe existir en el PADRE
# self_marker: alguno de estos debe existir DENTRO de la propia carpeta
RULES = [
    # ---------------------------------------------- dependencias de desarrollo
    dict(id="node_modules", name="node_modules", cat="Dependencias de desarrollo",
         safety=SAFE, label="node_modules",
         why="Dependencias de npm/pnpm/yarn de un proyecto JS.",
         how="Se recrean con `npm install` en la carpeta del proyecto."),
    dict(id="venv", name=("venv", ".venv", "virtualenv", "env"),
         self_marker=("pyvenv.cfg",), cat="Dependencias de desarrollo",
         safety=SAFE, label="Entorno virtual de Python",
         why="Entorno virtual de Python de un proyecto.",
         how="Se recrea con `python -m venv .venv` + `pip install -r requirements.txt`."),
    dict(id="pycache", name="__pycache__", cat="Dependencias de desarrollo",
         safety=SAFE, label="__pycache__",
         why="Bytecode compilado de Python.",
         how="Python lo regenera solo al ejecutar."),
    dict(id="pytest", name=(".pytest_cache", ".mypy_cache", ".ruff_cache",
                            ".tox", ".nox", ".ipynb_checkpoints"),
         cat="Dependencias de desarrollo", safety=SAFE, label="Cache de herramientas Python",
         why="Cache de pytest/mypy/ruff/tox o checkpoints de Jupyter.",
         how="Se regenera al volver a ejecutar la herramienta."),
    dict(id="cargo_registry", suffix=(".cargo\\registry", ".cargo\\git"),
         cat="Dependencias de desarrollo", safety=SAFE, label="Registro de Cargo (Rust)",
         why="Copia local de los crates descargados de crates.io.",
         how="`cargo build` los vuelve a bajar."),
    dict(id="rustup", suffix=(".rustup\\toolchains", ".rustup\\downloads"),
         cat="Dependencias de desarrollo", safety=REVIEW, label="Toolchains de Rust",
         why="Compiladores de Rust instalados. Cada toolchain son cientos de MB.",
         how="`rustup toolchain list` y `rustup toolchain uninstall <x>` para quitar los que no uses."),
    dict(id="gradle", suffix=(".gradle\\caches", ".gradle\\wrapper", ".gradle\\daemon"),
         cat="Dependencias de desarrollo", safety=SAFE, label="Cache de Gradle",
         why="Dependencias y distribuciones descargadas por Gradle (Android/Java).",
         how="Se vuelven a descargar en la siguiente compilacion."),
    dict(id="m2", suffix=(".m2\\repository",), cat="Dependencias de desarrollo",
         safety=REVIEW, label="Repositorio de Maven",
         why="Todos los .jar que ha bajado Maven en tu vida.",
         how="Se recuperan compilando otra vez (requiere red)."),
    dict(id="nuget", suffix=(".nuget\\packages",), cat="Dependencias de desarrollo",
         safety=REVIEW, label="Paquetes de NuGet",
         why="Paquetes .NET descargados.",
         how="`dotnet restore` los vuelve a bajar."),
    dict(id="npmcache", name=("npm-cache", "_cacache", ".npm"),
         cat="Dependencias de desarrollo", safety=SAFE, label="Cache de npm",
         why="Tarballs de paquetes npm ya descargados.",
         how="`npm cache clean --force` o borrarlo: npm lo rehace."),
    dict(id="pnpm", name=(".pnpm-store", "pnpm-store", "pnpm-cache"),
         cat="Dependencias de desarrollo", safety=SAFE, label="Store de pnpm",
         why="Almacen global de paquetes de pnpm.",
         how="`pnpm store prune` o borrarlo."),
    dict(id="yarncache", suffix=("yarn\\cache", "yarn\\global"),
         cat="Dependencias de desarrollo", safety=SAFE, label="Cache de Yarn",
         why="Paquetes descargados por Yarn.", how="Se regenera solo."),
    dict(id="pipcache", suffix=("pip\\cache", "pip\\http", ".cache\\pip"),
         cat="Dependencias de desarrollo", safety=SAFE, label="Cache de pip",
         why="Ruedas (.whl) descargadas por pip.",
         how="`pip cache purge` o borrarlo."),
    dict(id="condapkgs", suffix=("miniconda3\\pkgs", "anaconda3\\pkgs",
                                 ".conda\\pkgs", "conda\\pkgs"),
         cat="Dependencias de desarrollo", safety=SAFE, label="Paquetes de Conda",
         why="Paquetes descomprimidos que conda guarda por si los reinstalas.",
         how="`conda clean --all`. Suele liberar varios GB."),
    dict(id="vscodeext", suffix=(".vscode\\extensions", ".vscode-server\\extensions"),
         cat="Dependencias de desarrollo", safety=REVIEW, label="Extensiones de VS Code",
         why="Extensiones instaladas. Algunas (Python, C++) pesan cientos de MB.",
         how="Desinstala las que no uses desde VS Code, no borres a mano."),
    dict(id="uv", suffix=("uv\\cache", ".cache\\uv"),
         cat="Dependencias de desarrollo", safety=SAFE, label="Cache de uv",
         why="Ruedas y fuentes descargadas por uv (el gestor de paquetes de Python).",
         how="`uv cache clean` o borrarlo: se vuelve a llenar al instalar."),
    dict(id="bun", suffix=(".bun\\install\\cache",),
         cat="Dependencias de desarrollo", safety=SAFE, label="Cache de Bun",
         why="Paquetes descargados por Bun.", how="`bun pm cache rm` o borrarlo."),
    dict(id="gomod", suffix=("go\\pkg\\mod",),
         cat="Dependencias de desarrollo", safety=REVIEW, label="Modulos de Go",
         why="Cache de modulos de Go de todos los proyectos.",
         how="`go clean -modcache`; se vuelven a bajar al compilar (requiere red)."),
    dict(id="pubcache", suffix=("\\.pub-cache", "pub\\cache"),
         cat="Dependencias de desarrollo", safety=SAFE, label="Cache de Dart/Flutter",
         why="Paquetes de pub.dev descargados por Flutter/Dart.",
         how="`flutter pub get` los vuelve a bajar."),

    # ------------------------------------------------------ compilaciones
    dict(id="rust_target", name="target", marker=("Cargo.toml",),
         cat="Compilaciones", safety=SAFE, label="target/ de Rust",
         why="Salida de compilacion de Cargo. Es de lo mas gordo que existe.",
         how="`cargo clean` o borrarlo; se regenera al compilar."),
    dict(id="maven_target", name="target", marker=("pom.xml",),
         cat="Compilaciones", safety=SAFE, label="target/ de Maven",
         why="Salida de compilacion de Maven.", how="`mvn clean`."),
    dict(id="js_build", name=("build", "dist", "out"),
         marker=("package.json", "pyproject.toml", "setup.py", "CMakeLists.txt"),
         cat="Compilaciones", safety=SAFE, label="Salida de compilacion",
         why="Artefactos generados por el build del proyecto.",
         how="Se regeneran con `npm run build` / `python -m build`."),
    dict(id="dotnet_bin", name=("bin", "obj"), marker=(".csproj", ".vbproj", ".sln", ".fsproj"),
         marker_is_ext=True, cat="Compilaciones", safety=SAFE, label="bin/obj de .NET",
         why="Binarios intermedios de un proyecto .NET.",
         how="`dotnet clean` o recompilar."),
    dict(id="nextcache", name=(".next", ".nuxt", ".svelte-kit", ".angular",
                               ".turbo", ".parcel-cache", ".vite", ".astro"),
         cat="Compilaciones", safety=SAFE, label="Cache de framework web",
         why="Cache de build de Next/Nuxt/Svelte/Angular/Vite.",
         how="Se regenera en el siguiente build."),
    dict(id="unreal", name=("DerivedDataCache", "Intermediate", "Saved", "Binaries"),
         marker=(".uproject",), marker_is_ext=True, cat="Compilaciones",
         safety=SAFE, label="Intermedios de Unreal Engine",
         why="Cache y binarios generados por Unreal.",
         how="Se regeneran al abrir y compilar el proyecto."),
    dict(id="unity", name=("Library", "Obj", "Temp"), marker=("Assets", "ProjectSettings"),
         cat="Compilaciones", safety=SAFE, label="Library/ de Unity",
         why="Cache de importacion de Unity. Pesa mas que el propio proyecto.",
         how="Unity la reconstruye al abrir el proyecto (tarda un rato)."),
    dict(id="cmake", name=("cmake-build-debug", "cmake-build-release", "CMakeFiles"),
         cat="Compilaciones", safety=SAFE, label="Build de CMake",
         why="Directorio de compilacion de CMake.", how="Se regenera al compilar."),

    # -------------------------------------------------- temporales y sistema
    dict(id="temp", name=("temp", "tmp"), cat="Temporales y sistema", safety=SAFE,
         label="Carpeta temporal",
         why="Ficheros temporales que casi nadie limpia nunca.",
         how="Cierra los programas y borra. Lo que este en uso no se dejara borrar."),
    dict(id="winupdate", suffix=("softwaredistribution\\download",),
         cat="Temporales y sistema", safety=SAFE, label="Descargas de Windows Update",
         why="Instaladores de actualizaciones ya aplicadas.",
         how="Detener el servicio wuauserv y borrar, o usar el Liberador de espacio."),
    dict(id="deliveryopt", suffix=("deliveryoptimization\\cache", "softwaredistribution\\deliveryoptimization"),
         cat="Temporales y sistema", safety=SAFE, label="Optimizacion de entrega de Windows",
         why="Trozos de actualizaciones que Windows guarda para compartirlos con otros equipos.",
         how="Liberador de espacio > 'Archivos de optimizacion de entrega', o borrar la cache."),
    dict(id="cbslogs", suffix=("windows\\logs\\cbs", "windows\\logs\\dism"),
         cat="Temporales y sistema", safety=SAFE, label="Logs de mantenimiento de Windows",
         why="Registros de CBS/DISM; a veces crecen a varios GB por un CbsPersist atascado.",
         how="Borrar los .log y .cab antiguos; Windows crea uno nuevo."),
    dict(id="windowsold", name=("Windows.old", "$WINDOWS.~BT", "$WINDOWS.~WS"),
         cat="Temporales y sistema", safety=REVIEW, label="Instalacion anterior de Windows",
         why="Copia de la version anterior de Windows. Suele ocupar 20-40 GB.",
         how="Usa 'Liberar espacio' de Windows: 'Instalaciones anteriores de Windows'. No lo borres a mano."),
    dict(id="crashdumps", name=("CrashDumps", "Minidump", "LiveKernelReports",
                                "WER", "ReportQueue", "ReportArchive"),
         cat="Temporales y sistema", safety=SAFE, label="Volcados de errores",
         why="Informes de cuelgues de programas y del sistema.",
         how="Borrar sin miedo."),
    dict(id="recycle", name="$Recycle.Bin", cat="Temporales y sistema", safety=REVIEW,
         label="Papelera de reciclaje",
         why="Lo que has 'borrado' pero sigue ocupando disco. Windows solo ensena aqui lo "
             "que tiene indexado: si el indice se rompio quedan ficheros huerfanos que la "
             "papelera del escritorio NO lista y que 'Vaciar papelera' no borra.",
         how="Vacia la papelera normal primero. Si esto sigue pesando, son huerfanos: "
             "`rd /s /q C:\\$Recycle.Bin` en un CMD como administrador (Windows la recrea)."),
    dict(id="prefetch", suffix=("windows\\prefetch",), cat="Temporales y sistema",
         safety=REVIEW, label="Prefetch de Windows",
         why="Datos de arranque de aplicaciones. Se gana poco y ralentiza el primer arranque.",
         how="Se puede borrar, pero el beneficio es minimo."),
    dict(id="installer", suffix=("windows\\installer",), cat="No tocar", safety=DANGER,
         label="Windows\\Installer",
         why="Copias de los instaladores MSI. Si lo borras, no podras desinstalar ni reparar programas.",
         how="NO lo borres. Se limpia solo con la desinstalacion correcta de programas."),
    dict(id="winsxs", suffix=("windows\\winsxs",), cat="No tocar", safety=DANGER,
         label="WinSxS",
         why="Almacen de componentes de Windows. Borrarlo rompe el sistema.",
         how="Usa `DISM /Online /Cleanup-Image /StartComponentCleanup` para reducirlo."),
    dict(id="sysvol", name=("System Volume Information", "Recovery", "$WinREAgent",
                            "Config.Msi", "$SysReset"),
         cat="No tocar", safety=DANGER, label="Datos del sistema",
         why="Puntos de restauracion, recuperacion y metadatos de Windows.",
         how="Se gestiona desde Propiedades del sistema > Proteccion del sistema."),
    dict(id="git", name=".git", cat="No tocar", safety=DANGER, label="Repositorio Git",
         why="Es el historial completo del proyecto. Si no esta subido, lo pierdes todo.",
         how="Nunca lo borres. Si pesa mucho: `git gc --aggressive --prune=now`."),

    # -------------------------------------------------- caches de aplicaciones
    dict(id="appcache", name=("Cache", "cache", "GPUCache", "Code Cache", "DawnCache",
                              "ShaderCache", "CacheStorage", "blob_storage",
                              "GrShaderCache", "component_crx_cache"),
         cat="Caches de aplicaciones", safety=SAFE, label="Cache de aplicacion",
         why="Cache de navegador o de app Electron (Chrome, Edge, Discord, Slack, Spotify...).",
         how="Borrar solo hace que la app tarde un poco mas la primera vez."),
    dict(id="dotcache", name=".cache", cat="Caches de aplicaciones", safety=REVIEW,
         descend=True, label="Carpeta .cache",
         why="Cajon de sastre: dentro suele haber caches triviales pero tambien "
             "modelos de Hugging Face de varios GB que tardaron en bajar.",
         how="Mira dentro antes de vaciarla entera."),
    dict(id="localcache", suffix=("\\localcache",), cat="Caches de aplicaciones",
         safety=REVIEW, descend=True, label="LocalCache de app de la Store",
         why="Datos locales de una app de Microsoft Store. A veces es cache de usar y "
             "tirar y a veces son discos virtuales y sesiones de verdad.",
         how="Entra a ver que hay: si son .vhdx, borrarlos rompe la aplicacion."),
    dict(id="thumbs", name=(".thumbnails", "Explorer", "FontCache"),
         cat="Caches de aplicaciones", safety=SAFE, label="Miniaturas y fuentes",
         why="Cache de miniaturas del explorador.", how="Se regenera sola."),
    dict(id="shadercache", name=("DXCache", "GLCache", "D3DSCache", "ShaderCache", "shadercache"),
         cat="Caches de aplicaciones", safety=SAFE, label="Cache de shaders",
         why="Shaders compilados por el driver (NVIDIA/AMD/DirectX) para juegos y apps 3D.",
         how="Se recompilan al volver a abrir cada juego (primer arranque algo mas lento)."),
    dict(id="spotify", suffix=("spotify\\data", "spotify\\storage"),
         cat="Caches de aplicaciones", safety=SAFE, label="Cache de Spotify",
         why="Canciones en cache para no volver a descargarlas.",
         how="Spotify > Configuracion > Almacenamiento > Borrar cache. Se rellena sola."),
    dict(id="adobecache", name=("Media Cache", "Media Cache Files", "Peak Files"),
         cat="Caches de aplicaciones", safety=SAFE, label="Cache de medios de Adobe",
         why="Previsualizaciones y picos de audio de Premiere/After Effects. Crece sin limite.",
         how="Se regenera al abrir cada proyecto. Tambien: Preferencias > Cache de medios > Eliminar."),
    dict(id="davinci", name=("CacheClip", "ProxyMedia"),
         cat="Caches de aplicaciones", safety=SAFE, label="Cache de DaVinci Resolve",
         why="Clips optimizados y cache de render de Resolve.",
         how="Se regeneran al volver a trabajar en el proyecto."),
    dict(id="dottrace", name=("dotTraceSnapshots", "dotMemorySnapshots"),
         cat="Caches de aplicaciones", safety=SAFE, label="Snapshots de dotTrace",
         why="Capturas de profiling de JetBrains. Cada una puede pesar GB.",
         how="Borrar las que ya no analices."),
    dict(id="jetbrains", suffix=("jetbrains\\shared", "\\jetbrains"),
         cat="Caches de aplicaciones", safety=REVIEW, label="Datos de JetBrains",
         why="Indices y caches de IDEs de JetBrains.",
         how="Se regeneran al abrir el proyecto (tarda)."),
    dict(id="pkgcache", suffix=("programdata\\package cache",),
         cat="Caches de aplicaciones", safety=REVIEW, label="Package Cache",
         why="Instaladores guardados por Visual Studio y similares.",
         how="Solo hacen falta para reparar/modificar la instalacion."),

    # ---------------------------------------------------- modelos IA y datos
    dict(id="ollama", suffix=(".ollama\\models", "ollama\\models"),
         cat="Modelos de IA y datasets", safety=REVIEW, label="Modelos de Ollama",
         why="Pesos de los modelos locales. Un modelo mediano son 4-40 GB.",
         how="`ollama list` y `ollama rm <modelo>` para quitar los que no uses."),
    dict(id="hf", suffix=("huggingface\\hub", ".cache\\huggingface", "huggingface_hub"),
         cat="Modelos de IA y datasets", safety=REVIEW, label="Cache de Hugging Face",
         why="Modelos y datasets descargados.",
         how="Se vuelven a descargar. Ojo con los que tardaron horas."),
    dict(id="lmstudio", suffix=(".lmstudio\\models", "lm-studio\\models", ".cache\\lm-studio"),
         cat="Modelos de IA y datasets", safety=REVIEW, label="Modelos de LM Studio",
         why="GGUF descargados desde LM Studio. Varios GB cada uno.",
         how="Borralos desde LM Studio (My Models) o a mano; se vuelven a bajar."),
    dict(id="torch", suffix=("torch\\hub", ".cache\\torch", "\\torch\\kernels"),
         cat="Modelos de IA y datasets", safety=REVIEW, label="Cache de PyTorch",
         why="Pesos preentrenados descargados por torch.hub.", how="Se redescargan."),
    dict(id="mlcaches", name=(".keras", ".EasyOCR", ".paddlex", "scikit_learn_data",
                              ".wdm", ".ipython", ".matplotlib", ".javacpp"),
         cat="Modelos de IA y datasets", safety=REVIEW, label="Cache de libreria ML",
         why="Modelos y datasets que descargan Keras/EasyOCR/PaddleX/sklearn.",
         how="Se redescargan al usarlas."),
    dict(id="ai_ui", name=("stable-diffusion-webui", "ComfyUI", "automatic1111",
                           "text-generation-webui", "koboldcpp", "LM Studio",
                           "invokeai", "Fooocus"),
         cat="Modelos de IA y datasets", safety=REVIEW,
         label="Interfaz de IA local",
         why="Instalacion de una UI de IA local con sus modelos dentro.",
         how="Revisa que checkpoints usas de verdad: cada uno son 2-7 GB."),
    dict(id="modelsdir", name="models", min=2 * 1024 ** 3,
         cat="Modelos de IA y datasets", safety=REVIEW,
         label="Carpeta de modelos",
         why="Checkpoints, LoRAs, VAEs o pesos descargados.",
         how="Revisa cuales usas de verdad."),

    # ----------------------------------------------------- contenido pesado
    dict(id="steam", suffix=("steamapps\\common",), cat="Contenido pesado",
         safety=REVIEW, label="Juegos de Steam",
         why="Juegos instalados.", how="Desinstala desde Steam, no borres a mano."),
    dict(id="steamjunk", suffix=("steamapps\\downloading", "steamapps\\shadercache",
                                 "steamapps\\temp"),
         cat="Contenido pesado", safety=SAFE, label="Temporales de Steam",
         why="Descargas a medias y cache de shaders.", how="Steam los rehace."),
    dict(id="avd", suffix=(".android\\avd", "\\avd"), cat="Contenido pesado",
         safety=REVIEW, label="Emuladores de Android",
         why="Imagenes de disco de emuladores. Cada AVD son 8-15 GB.",
         how="Borra los AVD que no uses desde el Device Manager de Android Studio."),
    dict(id="sdk", suffix=("android\\sdk", "\\sdk\\system-images", "androidsdk"),
         cat="Contenido pesado", safety=REVIEW, label="SDK de Android",
         why="Plataformas e imagenes de sistema descargadas.",
         how="Quita las versiones viejas desde el SDK Manager."),
    dict(id="docker", suffix=("docker\\wsl", "dockerdesktop", "docker desktop"),
         cat="Contenido pesado", safety=REVIEW, label="Datos de Docker",
         why="Imagenes y contenedores. El disco virtual no se encoge solo.",
         how="`docker system prune -a` y luego compactar el vhdx."),
    dict(id="wsl", name=("rootfs", "LocalState"), suffix=("\\localstate",),
         cat="Contenido pesado", safety=REVIEW, label="Disco de WSL",
         why="Sistema de ficheros de una distribucion Linux.",
         how="Borra dentro de WSL y luego compacta el ext4.vhdx con diskpart."),
    dict(id="nox", name=("Nox_share", "Nox", "BlueStacks", "LDPlayer", "MEmu"),
         cat="Contenido pesado", safety=REVIEW, label="Emulador Android de escritorio",
         why="Discos virtuales del emulador.",
         how="Desinstala el emulador si ya no lo usas."),
    dict(id="blenderkit", name=("blenderkit_data", "Zotero", "Calibre Library"),
         cat="Contenido pesado", safety=REVIEW, label="Biblioteca de contenido",
         why="Assets, PDFs o libros descargados.",
         how="Revisa a mano: aqui puede haber cosas que quieras conservar."),
    dict(id="downloads", suffix=("\\downloads", "\\descargas"), cat="Contenido pesado",
         safety=REVIEW, descend=True, label="Descargas",
         why="El cementerio clasico: instaladores viejos, ZIPs y ISOs.",
         how="Ordena por tamano y borra lo que ya instalaste."),
    dict(id="onedrive", name=("OneDrive", "Dropbox", "Google Drive"),
         cat="Contenido pesado", safety=REVIEW, label="Carpeta de nube sincronizada",
         why="Copia local de tu nube.",
         how="Usa 'Archivos a peticion' para liberar espacio sin perder nada."),
]

# ficheros sueltos que merecen explicacion
FILE_NOTES = {
    "hiberfil.sys": ("Fichero de hibernacion. Ocupa como tu RAM.",
                     "Si no usas hibernacion: `powercfg /h off` en un CMD como administrador."),
    "pagefile.sys": ("Memoria virtual de Windows.",
                     "Se ajusta en Propiedades del sistema > Rendimiento > Memoria virtual."),
    "swapfile.sys": ("Intercambio para apps de la Store.", "Va ligado al pagefile."),
    "ext4.vhdx": ("Disco virtual de WSL. No se encoge solo al borrar dentro.",
                  "Borra dentro de WSL y compacta con `diskpart` > `compact vdisk`."),
    "MEMORY.DMP": ("Volcado de memoria de un pantallazo azul.", "Se puede borrar."),
}


EXT_NOTES = {
    ".blend1": ("Copia de seguridad automatica de Blender.",
                "Borrable: el .blend bueno es el otro. Ajusta las copias en Preferencias > Guardar."),
    ".blend2": ("Segunda copia de seguridad de Blender.", "Borrable."),
    ".bak": ("Copia de seguridad.", "Borrable si conservas el original."),
    ".old": ("Version antigua guardada a mano.", "Borrable si ya no la necesitas."),
    ".tmp": ("Fichero temporal huerfano.", "Borrable."),
    ".crdownload": ("Descarga a medias del navegador.", "Borrable."),
    ".part": ("Descarga incompleta.", "Borrable."),
    ".dmp": ("Volcado de memoria de un cuelgue.", "Borrable."),
    ".vhdx": ("Disco virtual (WSL, Docker o Hyper-V). No se encoge solo al borrar dentro.",
              "Libera espacio dentro y luego compactalo con diskpart."),
    ".vdi": ("Disco virtual de VirtualBox.", "Se compacta con VBoxManage modifymedium --compact."),
    ".iso": ("Imagen de disco.", "Si ya lo instalaste, sobra."),
    ".log": ("Registro de una aplicacion.", "Borrable salvo que estes depurando algo."),
}


def _norm_names(rule):
    n = rule.get("name")
    if n is None:
        return []
    if isinstance(n, str):
        return [n.lower()]
    return [x.lower() for x in n]


_VENV_RULE = next(r for r in RULES if r["id"] == "venv")
_BY_NAME = {}
_SUFFIX_ONLY = []
for _r in RULES:
    names = _norm_names(_r)
    if names:
        for _n in names:
            _BY_NAME.setdefault(_n, []).append(_r)
    else:
        _SUFFIX_ONLY.append(_r)
_SUFFIX_TAILS = {}
for _r in _SUFFIX_ONLY:
    for _s in _r.get("suffix", ()):  # indexamos por ultimo componente
        _SUFFIX_TAILS.setdefault(_s.rstrip("\\").split("\\")[-1], []).append((_s, _r))


def _marker_ok(rule, parent_path):
    markers = rule.get("marker")
    if not markers:
        return True
    try:
        if rule.get("marker_is_ext"):
            names = os.listdir(parent_path)
            return any(any(n.lower().endswith(m.lower()) for m in markers) for n in names)
        return any(os.path.exists(os.path.join(parent_path, m)) for m in markers)
    except OSError:
        return False


def _self_marker_ok(rule, path):
    markers = rule.get("self_marker")
    if not markers:
        return True
    try:
        return any(os.path.exists(os.path.join(path, m)) for m in markers)
    except OSError:
        return False


def match_rule(path: str, name: str):
    """Devuelve la regla que aplica a esta carpeta, o None."""
    low_name = name.lower()
    low_path = path.lower().rstrip("\\")
    parent = os.path.dirname(path)

    for sfx, rule in _SUFFIX_TAILS.get(low_name, ()):
        if low_path.endswith(sfx):
            return rule
    for rule in _BY_NAME.get(low_name, ()):
        sfx = rule.get("suffix")
        if sfx and not any(low_path.endswith(s) for s in sfx):
            continue
        if not _marker_ok(rule, parent):
            continue
        if not _self_marker_ok(rule, path):
            continue
        return rule
    # un entorno virtual con nombre libre (venv-ocr, .env310...) se delata por
    # su pyvenv.cfg: lo pillamos aunque el nombre no este en la lista
    if low_name not in _BY_NAME and _self_marker_ok(_VENV_RULE, path):
        return _VENV_RULE
    return None


def scan_junk(root_node, root_path, min_bytes=20 * 1024 * 1024, limit=600):
    """Recorre el arbol buscando basura conocida. No entra dentro de lo que ya casa."""
    from .winfs import norm_display
    base = norm_display(root_path).rstrip("\\/")
    found = []
    stack = [(base, root_node, root_node.name)]
    while stack:
        path, node, name = stack.pop()
        rule = None
        if node is not root_node:
            rule = match_rule(path, name)
        if rule is not None:
            if node.size >= max(min_bytes, rule.get("min", 0)):
                found.append({
                    "path": path, "size": node.size, "files": node.nfiles,
                    "mtime": node.mtime, "rule": rule["id"], "cat": rule["cat"],
                    "safety": rule["safety"], "label": rule["label"],
                    "why": rule["why"], "how": rule["how"],
                    "container": bool(rule.get("descend")),
                })
            if not rule.get("descend"):
                continue  # no bajamos dentro de una carpeta ya clasificada
        if node.children:
            for cname, child in node.children.items():
                if child.size >= min_bytes:
                    stack.append((path + os.sep + cname, child, cname))
    found.sort(key=lambda d: -d["size"])
    return found[:limit]


def summarize_junk(items):
    cats = {}
    for it in items:
        if it.get("container"):
            continue
        c = cats.setdefault(it["cat"], {"cat": it["cat"], "size": 0, "count": 0,
                                        "safe": 0, "review": 0, "danger": 0})
        c["size"] += it["size"]
        c["count"] += 1
        c[it["safety"]] += it["size"]
    out = sorted(cats.values(), key=lambda d: -d["size"])
    return out


# ------------------------------------------------------------ puntos calientes

def hotspots(root_node, root_path, min_frac=0.008, floor=256 * 1024 ** 2, limit=45):
    """Parte el arbol en trozos disjuntos y los ordena por peso.

    Baja por cada rama mientras el tamano se pueda atribuir a una subcarpeta
    concreta. Donde ya no se puede, para y lo apunta. Cada resultado es un sitio
    distinto (no se solapan), asi que la lista se lee de arriba abajo: eso es
    literalmente donde esta el disco.
    """
    from .winfs import norm_display
    base = norm_display(root_path).rstrip("\\/")
    total = root_node.size or 1
    min_bytes = max(total * min_frac, floor)
    out = []
    stack = [(base, root_node, 0)]
    while stack:
        path, node, depth = stack.pop()
        kids = node.children or {}
        big = [(k, v) for k, v in kids.items() if v.size >= min_bytes]
        preview = [{"name": k, "size": v.size}
                   for k, v in sorted(kids.items(), key=lambda kv: -kv[1].size)[:6]
                   if v.size > 0]
        if not big or depth >= 24:
            out.append({
                "path": path, "size": node.size, "files": node.nfiles,
                "mtime": node.mtime, "depth": depth, "kind": "carpeta",
                "pct": node.size * 100.0 / total, "own": node.own,
                "children": preview,
            })
            continue
        covered = sum(v.size for _, v in big)
        rest = node.size - covered
        if rest >= min_bytes:
            out.append({
                "path": path, "size": rest,
                "files": node.nfiles - sum(v.nfiles for _, v in big),
                "mtime": node.mtime, "depth": depth, "kind": "resto",
                "pct": rest * 100.0 / total, "own": node.own,
                "children": [c for c in preview if c["size"] < min_bytes][:6],
                "nbig": len(big), "nsmall": len(kids) - len(big),
            })
        for k, v in big:
            stack.append((path + os.sep + k, v, depth + 1))
    out.sort(key=lambda d: -d["size"])
    return out[:limit]


def stale_folders(root_node, root_path, months=12, min_bytes=1024 ** 3, limit=40):
    """Carpetas grandes que no tocas desde hace tiempo."""
    import time as _t
    from .winfs import norm_display
    base = norm_display(root_path).rstrip("\\/")
    cutoff = _t.time() - months * 30 * 86400
    out = []
    stack = [(base, root_node)]
    while stack:
        path, node = stack.pop()
        if node.size < min_bytes:
            continue
        if node is not root_node and node.mtime and node.mtime < cutoff:
            out.append({"path": path, "size": node.size, "mtime": node.mtime,
                        "files": node.nfiles})
            continue  # ya es antigua entera, no hace falta bajar
        if node.children:
            for k, v in node.children.items():
                stack.append((path + os.sep + k, v))
    out.sort(key=lambda d: -d["size"])
    return out[:limit]
