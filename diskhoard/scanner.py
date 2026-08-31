# -*- coding: utf-8 -*-
"""Motor de escaneo de disco.

Recorre un arbol de directorios con os.scandir y varios hilos. En Windows
scandir ya trae los metadatos de cada entrada, asi que entry.stat() no cuesta
una llamada extra al sistema: por eso esto vuela comparado con el explorador.

Guarda en memoria SOLO los directorios (tamano acumulado, numero de ficheros,
fecha mas reciente). Los ficheros de una carpeta concreta se listan en vivo
cuando hace falta, que es instantaneo.
"""
from __future__ import annotations

import heapq
import os
import threading
import time
from collections import deque

from .winfs import IS_WIN, long_path, norm_display

TOP_FILES = 500

FLAG_ERROR = 1
FLAG_LINK = 2

EXT_CATEGORIES = {
    "video": (".mp4 .mkv .avi .mov .wmv .flv .webm .m4v .mpg .mpeg .ts .vob .m2ts"),
    "audio": ".mp3 .flac .wav .aac .ogg .m4a .wma .opus .aiff",
    "imagen": ".jpg .jpeg .png .gif .bmp .tiff .tif .webp .heic .raw .cr2 .nef .arw .psd .xcf .svg",
    "modelos IA": ".gguf .safetensors .ckpt .pt .pth .onnx .h5 .pb .tflite .msgpack .npz .lora .vae",
    "comprimidos": ".zip .rar .7z .tar .gz .bz2 .xz .zst .cab .iso .tgz",
    "instaladores": ".exe .msi .msix .appx .deb .rpm .dmg .pkg",
    "discos virtuales": ".vhd .vhdx .vdi .vmdk .qcow2 .img .sys",
    "documentos": ".pdf .doc .docx .xls .xlsx .ppt .pptx .odt .ods .epub .mobi .azw3 .txt .md .rtf",
    "datos": (".csv .json .xml .parquet .db .sqlite .sqlite3 .sql .jsonl .arrow "
              ".feather .pkl .npy .bin .dat .idx .index"),
    "codigo": ".py .js .ts .tsx .jsx .java .c .cpp .h .hpp .cs .go .rs .rb .php .html .css .scss .lua .kt .swift",
    "3D y juegos": (".blend .blend1 .blend2 .fbx .obj .glb .gltf .stl .dae .unity .uasset "
                    ".pak .bsa .vpk .wad .mca .mcr .nbt .mcmeta .schematic .upk .umap"),
    "fuentes y libs": ".dll .so .lib .a .jar .whl .egg .nupkg .pdb",
}

_EXT_MAP = {}
for _cat, _exts in EXT_CATEGORIES.items():
    for _e in _exts.split():
        _EXT_MAP[_e] = _cat


class Node:
    __slots__ = ("name", "size", "own", "nfiles", "nown", "mtime", "children", "flags")

    def __init__(self, name):
        self.name = name
        self.size = 0        # bytes acumulados (recursivo)
        self.own = 0         # bytes de los ficheros directos
        self.nfiles = 0      # ficheros acumulados (recursivo)
        self.nown = 0        # ficheros directos
        self.mtime = 0.0     # fecha de modificacion mas reciente del subarbol
        self.children = None  # dict nombre -> Node
        self.flags = 0


class Scanner:
    """Escaneo de un arbol. Se lanza en segundo plano y se puede consultar."""

    def __init__(self, root: str, threads: int = 0):
        self.root_display = norm_display(root)
        self.root_scan = long_path(self.root_display)
        self.root = Node(self.root_display)
        self.threads = threads or min(16, max(4, (os.cpu_count() or 4) * 2))

        self._tasks = deque()
        self._cond = threading.Condition()
        self._pending = 0
        self._cancel = False
        self._workers = []

        # progreso
        self.p_files = 0
        self.p_bytes = 0
        self.p_dirs = 0
        self.p_errors = 0
        self.current = ""
        self._plock = threading.Lock()

        self.started = 0.0
        self.finished = 0.0
        self.done = False
        self.error = ""

        self.top_files = []       # [(size, path)]
        self.ext_stats = {}       # ext -> [count, bytes]
        self.error_paths = []

    # ------------------------------------------------------------------ ciclo
    def start(self):
        self.started = time.time()
        try:
            os.lstat(self.root_scan)
        except OSError as exc:
            self.error = "No se puede acceder a %s (%s)" % (
                self.root_display, getattr(exc, "strerror", exc))
            self.done = True
            self.finished = time.time()
            return
        self._pending = 1
        self._tasks.append((self.root, self.root_scan))
        for i in range(self.threads):
            t = threading.Thread(target=self._worker, name="dh-scan-%d" % i,
                                 daemon=True)
            t.start()
            self._workers.append(t)
        threading.Thread(target=self._finish, daemon=True).start()

    def cancel(self):
        with self._cond:
            self._cancel = True
            self._cond.notify_all()

    def _finish(self):
        for t in self._workers:
            t.join()
        if not self._cancel:
            _aggregate(self.root)
        self.finished = time.time()
        self.done = True

    def progress(self):
        return {
            "done": self.done,
            "cancelled": self._cancel,
            "error": self.error,
            "root": self.root_display,
            "files": self.p_files,
            "bytes": self.p_bytes,
            "dirs": self.p_dirs,
            "errors": self.p_errors,
            "current": self.current,
            "elapsed": (self.finished or time.time()) - self.started,
        }

    # ---------------------------------------------------------------- worker
    def _worker(self):
        loc_files = loc_bytes = loc_dirs = loc_errors = 0
        heap = []
        exts = {}
        errs = []
        flush_at = 400

        while True:
            with self._cond:
                while not self._tasks and self._pending > 0 and not self._cancel:
                    self._cond.wait(0.2)
                if self._cancel or (not self._tasks and self._pending == 0):
                    break
                if not self._tasks:
                    continue
                node, path = self._tasks.popleft()

            new_tasks = []
            try:
                with os.scandir(path) as it:
                    for entry in it:
                        try:
                            is_dir = entry.is_dir(follow_symlinks=False)
                        except OSError:
                            loc_errors += 1
                            continue
                        if is_dir:
                            child = Node(entry.name)
                            try:
                                if entry.is_symlink() or (
                                        IS_WIN and entry.is_junction()):
                                    child.flags |= FLAG_LINK
                            except (OSError, AttributeError):
                                pass
                            if node.children is None:
                                node.children = {}
                            node.children[entry.name] = child
                            loc_dirs += 1
                            if not child.flags & FLAG_LINK:
                                new_tasks.append((child, entry.path))
                        else:
                            try:
                                st = entry.stat(follow_symlinks=False)
                            except OSError:
                                loc_errors += 1
                                continue
                            sz = st.st_size
                            node.own += sz
                            node.nown += 1
                            if st.st_mtime > node.mtime:
                                node.mtime = st.st_mtime
                            loc_files += 1
                            loc_bytes += sz
                            ext = os.path.splitext(entry.name)[1].lower()
                            slot = exts.get(ext)
                            if slot is None:
                                exts[ext] = [1, sz]
                            else:
                                slot[0] += 1
                                slot[1] += sz
                            if len(heap) < TOP_FILES:
                                heapq.heappush(heap, (sz, entry.path))
                            elif sz > heap[0][0]:
                                heapq.heapreplace(heap, (sz, entry.path))
            except PermissionError:
                node.flags |= FLAG_ERROR
                loc_errors += 1
                if len(errs) < 200:
                    errs.append(norm_display(path))
            except OSError:
                node.flags |= FLAG_ERROR
                loc_errors += 1
                if len(errs) < 200:
                    errs.append(norm_display(path))

            with self._cond:
                if new_tasks and not self._cancel:
                    self._pending += len(new_tasks)
                    self._tasks.extend(new_tasks)
                self._pending -= 1
                if self._pending == 0 or new_tasks:
                    self._cond.notify_all()

            if loc_files >= flush_at:
                with self._plock:
                    self.p_files += loc_files
                    self.p_bytes += loc_bytes
                    self.p_dirs += loc_dirs
                    self.p_errors += loc_errors
                    self.current = norm_display(path)
                loc_files = loc_bytes = loc_dirs = loc_errors = 0

        with self._plock:
            self.p_files += loc_files
            self.p_bytes += loc_bytes
            self.p_dirs += loc_dirs
            self.p_errors += loc_errors
            for ext, slot in exts.items():
                cur = self.ext_stats.get(ext)
                if cur is None:
                    self.ext_stats[ext] = slot
                else:
                    cur[0] += slot[0]
                    cur[1] += slot[1]
            merged = self.top_files + heap
            merged.sort(reverse=True)
            self.top_files = merged[:TOP_FILES]
            for e in errs:
                if len(self.error_paths) < 400:
                    self.error_paths.append(e)


def _aggregate(root: Node):
    """Suma tamanos de abajo arriba, sin recursion (arboles muy profundos)."""
    stack = [(root, False)]
    while stack:
        node, visited = stack.pop()
        if visited:
            size = node.own
            nf = node.nown
            mt = node.mtime
            if node.children:
                for c in node.children.values():
                    size += c.size
                    nf += c.nfiles
                    if c.mtime > mt:
                        mt = c.mtime
            node.size = size
            node.nfiles = nf
            node.mtime = mt
        else:
            stack.append((node, True))
            if node.children:
                for c in node.children.values():
                    stack.append((c, False))


# ------------------------------------------------------------------ utilidades

def find(root: Node, root_path: str, target: str):
    """Localiza el nodo de una ruta dentro del arbol escaneado."""
    rp = norm_display(root_path).rstrip("\\/")
    tp = norm_display(target).rstrip("\\/")
    if not rp:
        rp = norm_display(root_path)
    if tp.lower() == rp.lower():
        return root
    if not tp.lower().startswith(rp.lower() + os.sep):
        return None
    rel = tp[len(rp) + 1:]
    node = root
    for part in rel.split(os.sep):
        if not part:
            continue
        if not node.children:
            return None
        nxt = node.children.get(part)
        if nxt is None:
            low = part.lower()
            nxt = next((v for k, v in node.children.items() if k.lower() == low), None)
        if nxt is None:
            return None
        node = nxt
    return node


def ext_category(ext: str) -> str:
    return _EXT_MAP.get(ext.lower(), "otros")


def walk(root: Node, root_path: str):
    """Genera (ruta, nodo) para todo el arbol, iterativo."""
    stack = [(norm_display(root_path).rstrip("\\/") or root_path, root)]
    while stack:
        path, node = stack.pop()
        yield path, node
        if node.children:
            for name, child in node.children.items():
                stack.append((path + os.sep + name, child))
