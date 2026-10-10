# -*- coding: utf-8 -*-
"""Copias de seguridad de Ollama y blobs huerfanos: detector y liberador.

Por que existe
--------------
Ollama 0.40 migra en segundo plano los modelos descargados con versiones
anteriores (las notas de 0.40.2 lo cuentan) y, para poder volver a una version
anterior, conserva la copia original como "copia de seguridad" hasta que se
borra a mano. Esa copia puede ser un modelo entero (decenas de GB).

Como esta guardado (leido del propio Ollama, manifest/paths.go de 0.40 y las
notas de la version)::

    <modelos>/blobs/sha256-<hex>                        ficheros de contenido
    <modelos>/manifests-v2/<host>/<ns>/<modelo>/<tag>   0.40+: enlace (o copia) a un
                                                        manifiesto-blob; ``:`` del host = ``%3A``
    <modelos>/manifests/<host>/<ns>/<modelo>/<tag>      antes de 0.40; desde 0.40 queda
                                                        solo como ancla para volver atras
    <modelos>/metadata/sha256-<hex>.json                (0.34+) metadatos GGUF por blob

Desde 0.40 una etiqueta puede ser una *lista de manifiestos* (``mediaType``
``application/vnd.ollama.manifest.list.v2+json``) con un hijo por ejecutor
(``runner``): ``llamacpp`` (la version migrada) y ``ggml`` (el original, que es
la copia de seguridad). Ollama la borra con ``ollama rm <digest-del-hijo-ggml>``.

Que hace este modulo
--------------------
``scan()`` solo LEE y clasifica, sin tocar nada:

* ``ggml_backup``: el hijo ``ggml`` de una lista que tambien tiene hijo
  ``llamacpp``. Solo es "seguro de liberar" si el manifiesto migrado y todos sus
  blobs existen (y miden lo que dice el manifiesto). Los bytes recuperables son
  los blobs que nadie mas usa.
* ``orphan_blob``: blobs que ningun manifiesto referencia (ni v2, ni antiguo, ni
  hijos de listas). Solo con todos los manifiestos legibles y sin escrituras recientes.
* ``partial``: descargas a medias abandonadas (``-partial``), si son antiguas.
* ``orphan_metadata``: ``metadata/*.json`` de blobs que ya no existen.
* ``backup_dir`` / ``backup_file``: carpetas y ficheros con aspecto de copia
  (``*.bak``, ``backup``, ``old``, con fecha...) dentro del almacen; solo son
  seguros si el almacen vivo esta sano y la copia no contiene nada que el vivo no tenga.

``free()`` borra SOLO lo que ``scan()`` marca seguro, solo con confirmacion
explicita, con simulacro (``dry_run``) por defecto, con registro de auditoria, y
se niega mientras Ollama descarga, migra o tiene modelos cargados, o si la
carpeta de modelos no se puede verificar. Los ficheros van a la Papelera (o se
borran para siempre con ``mode="permanent"``); las copias ``ggml`` se quitan con
``ollama rm`` porque es el camino que Ollama documenta (no toca su lista de manifiestos a mano).

Solo libreria estandar (Python 3.9+).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request

from .winfs import IS_WIN, delete_permanent, long_path, norm_display, send_to_trash

BLOB_RE = re.compile(r"^sha256-([0-9a-f]{64})$")
PARTIAL_RE = re.compile(r"^sha256-([0-9a-f]{64})-partial(?:-\d+)?$")
DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
LIST_MEDIA = "application/vnd.ollama.manifest.list.v2+json"
LIVE_DIRS = ("blobs", "manifests", "manifests-v2", "metadata")
PUBLIC_HOSTS = ("registry.ollama.ai", "ollama.com")

BACKUP_TOKENS = {"backup", "backups", "bak", "old", "orig", "prev", "previous", "premigration",
                 "migrated", "migration"}
_DATE_TOKEN = re.compile(r"^(?:20\d{6}(?:t?\d{4,6})?|20\d{2}[-_]\d{2}[-_]\d{2})$")
_BACKUP_TAG_SUFFIX = re.compile(r"(?i)(?:\.(?:bak|old|backup|orig)(?:[-_.]?\d+)?|~)$")

MAX_MANIFEST = 2 * 1024 * 1024
MIN_ORPHAN_AGE_S = 3600            # un blob recien escrito puede ser de una descarga que aun no ha escrito el manifiesto
PARTIAL_MIN_AGE_S = 7 * 86400
RECENT_WRITE_S = 120               # actividad reciente en el almacen = alguien lo esta usando
PARTIAL_ACTIVE_S = 600
KINDS = ("ggml_backup", "orphan_blob", "partial", "orphan_metadata", "backup_dir", "backup_file")

KIND_LABEL = {
    "ggml_backup": "Copia de seguridad de la migración",
    "orphan_blob": "Fichero huérfano",
    "partial": "Descarga a medias abandonada",
    "orphan_metadata": "Metadatos huérfanos",
    "backup_dir": "Carpeta de copia de seguridad",
    "backup_file": "Fichero de copia de seguridad",
}

_AUDIT_LOCK = threading.Lock()


def fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return "%.1f TB" % n


# ------------------------------------------------------------------ utilidades

def _is_link(path):
    """Enlace simbolico, union (junction) o cualquier punto de reanalisis."""
    try:
        if os.path.islink(path):
            return True
        isj = getattr(os.path, "isjunction", None)
        if isj is not None and isj(path):
            return True
        if IS_WIN:
            return bool(os.lstat(long_path(path)).st_file_attributes & 0x400)
    except OSError:
        return False
    return False


def _blobname(digest):
    """``sha256:<hex>`` -> ``sha256-<hex>``; None si no es un digest sha256 valido."""
    m = DIGEST_RE.match(str(digest or ""))
    return "sha256-" + m.group(1) if m else None


def _read_json(path, limit=MAX_MANIFEST):
    with open(long_path(path), "rb") as fh:
        raw = fh.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("manifiesto demasiado grande")
    return raw, json.loads(raw.decode("utf-8"))


def looks_like_backup(name):
    """Nombre con pinta de copia: ``manifests.bak``, ``blobs-old``, ``backup-20261008``..."""
    low = str(name or "").lower()
    if low in LIVE_DIRS:
        return False
    tokens = [t for t in re.split(r"[^a-z0-9]+", low) if t]
    return any(t in BACKUP_TOKENS or _DATE_TOKEN.match(t) for t in tokens)


def _canon_host(host):
    host = (host or "").replace("%3A", ":").replace("%3a", ":")
    return "ollama.com" if host.lower() in PUBLIC_HOSTS else host


def _display_name(host, ns, model, tag):
    host = _canon_host(host)
    if host == "ollama.com":
        base = model if ns == "library" else "%s/%s" % (ns, model)
    else:
        base = "%s/%s/%s" % (host, ns, model)
    return "%s:%s" % (base, tag)


def _tree_size(path, collect=None):
    """Suma de tamanos de un arbol sin seguir enlaces: (bytes, ficheros, enlaces, errores, ficheros con otro nombre duro)."""
    total = nfiles = 0
    links = []
    errors = []
    hard = 0
    stack = [path]
    while stack:
        cur = stack.pop()
        try:
            it = os.scandir(long_path(cur))
        except OSError as exc:
            errors.append("%s: %s" % (norm_display(cur), exc.strerror or exc))
            continue
        with it:
            for e in it:
                try:
                    if e.is_symlink() or _is_link(e.path):
                        links.append(norm_display(e.path))
                        continue
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
                        continue
                    st = e.stat(follow_symlinks=False)
                except OSError as exc:
                    errors.append("%s: %s" % (norm_display(e.path), exc.strerror or exc))
                    continue
                nfiles += 1
                if getattr(st, "st_nlink", 1) > 1:
                    hard += 1          # otro nombre sigue apuntando a los datos: borrar este no libera nada
                else:
                    total += st.st_size
                if collect is not None:
                    collect.append((e.path, st.st_size))
    return total, nfiles, links, errors, hard


# ------------------------------------------------------------------ carpeta de modelos

def candidate_dirs(explicit=None):
    """Donde puede estar el almacen, en el orden en que Ollama lo buscaria."""
    out = []
    if explicit:
        out.append(("arg", str(explicit)))
    env = os.environ.get("OLLAMA_MODELS")
    if env:
        out.append(("env", env))
    if IS_WIN:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                val, _typ = winreg.QueryValueEx(key, "OLLAMA_MODELS")
                if val:
                    out.append(("registry", os.path.expandvars(val)))
        except (OSError, ImportError):
            pass
    out.append(("default", os.path.join(os.path.expanduser("~"), ".ollama", "models")))
    seen, uniq = set(), []
    for src, p in out:
        k = os.path.normcase(os.path.abspath(p))
        if k not in seen:
            seen.add(k)
            uniq.append((src, p))
    return uniq


def resolve_models_dir(explicit=None):
    """(ruta, origen, candidatos). Con ``explicit`` solo vale ese; si no, el primer candidato con ``blobs/``."""
    cands = candidate_dirs(explicit)
    info = [{"source": s, "path": p, "exists": os.path.isdir(long_path(p)),
             "has_blobs": os.path.isdir(long_path(os.path.join(p, "blobs")))} for s, p in cands]
    if explicit:
        return cands[0][1], "arg", info
    for (s, p), i in zip(cands, info):
        if i["has_blobs"]:
            return p, s, info
    return cands[0][1], cands[0][0], info


def _protected_roots():
    roots = set()
    home = os.path.expanduser("~")
    for p in (home, os.path.join(home, "Desktop"), os.path.join(home, "Documents"),
              os.path.join(home, "Downloads"), os.environ.get("SystemRoot", ""),
              os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", ""),
              os.environ.get("ProgramData", ""), os.environ.get("SystemDrive", "")):
        if p:
            roots.add(os.path.normcase(os.path.abspath(p)).rstrip("\\/"))
    return roots


def verify_models_dir(path):
    """(problema de lectura | None, [razones por las que NO se puede borrar ahi])."""
    if not path or not os.path.isabs(str(path)):
        return "La ruta de modelos no es absoluta.", []
    p = os.path.abspath(path)
    if not os.path.isdir(long_path(p)):
        return "No existe la carpeta de modelos: %s" % norm_display(p), []
    if not os.path.isdir(long_path(os.path.join(p, "blobs"))):
        return "No parece un almacén de Ollama (falta blobs/): %s" % norm_display(p), []
    if not any(os.path.isdir(long_path(os.path.join(p, d))) for d in ("manifests", "manifests-v2")):
        return "No parece un almacén de Ollama (faltan manifests/ y manifests-v2/): %s" % norm_display(p), []
    block = []
    stripped = os.path.normcase(p).rstrip("\\/")
    if len(stripped) <= 2 or stripped in ("", "/"):
        block.append("es la raíz de una unidad")
    elif stripped in _protected_roots():
        block.append("es una carpeta protegida del sistema o del perfil")
    for d in ("", "blobs", "manifests", "manifests-v2"):
        q = os.path.join(p, d) if d else p
        if os.path.lexists(long_path(q)) and _is_link(q):
            block.append("%s es un enlace o unión: no se puede verificar dónde está de verdad"
                         % (d + "/" if d else "la carpeta de modelos"))
    return None, block


# ------------------------------------------------------------------ el almacen

class Store:
    """Foto de solo lectura del almacen: blobs, etiquetas, hijos de listas."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.blobs = {}        # nombre -> {size, mtime, path, link}
        self.partials = []     # {name, size, mtime, path, link}
        self.metadata = []     # {name, blob, size, mtime, path}
        self.tags = []         # etiquetas v2 y antiguas
        self.children = {}     # nombre de blob hijo -> {present, refs, error}
        self.problems = []     # cosas ilegibles: sin ellas no se puede asegurar que un blob sobre
        self.candidates = []   # copias con pinta de backup
        self.stray = []        # ficheros que no reconocemos (no se tocan)
        self.last_write = 0.0
        self.refs = {}
        self.models = []

    # ---- carga
    def load(self):
        self._load_blobs()
        for sub, kind in (("manifests-v2", "v2"), ("manifests", "legacy")):
            self._load_manifests(sub, kind)
        self._load_children()
        self._load_metadata()
        self._load_root()
        self._derive()
        return self

    def _p(self, *parts):
        return os.path.join(self.root, *parts)

    def _note_mtime(self, mtime):
        if mtime and mtime > self.last_write:
            self.last_write = mtime

    def _load_blobs(self):
        base = self._p("blobs")
        try:
            it = os.scandir(long_path(base))
        except OSError as exc:
            self.problems.append("No se puede leer blobs/: %s" % (exc.strerror or exc))
            return
        with it:
            for e in it:
                name = e.name
                try:
                    st = e.stat(follow_symlinks=False)
                    is_dir = e.is_dir(follow_symlinks=False)
                    link = e.is_symlink() or _is_link(e.path)
                except OSError:
                    continue
                if is_dir and not link:
                    if looks_like_backup(name):
                        self.candidates.append({"path": norm_display(e.path), "rel": "blobs/" + name, "dir": True,
                                                "area": "blobs"})
                    else:
                        self.stray.append("blobs/" + name + "/")
                    continue
                if BLOB_RE.match(name):
                    self.blobs[name] = {"size": st.st_size, "mtime": st.st_mtime,
                                        "path": norm_display(e.path), "link": link}
                    self._note_mtime(st.st_mtime)
                elif PARTIAL_RE.match(name):
                    self.partials.append({"name": name, "size": st.st_size, "mtime": st.st_mtime,
                                          "path": norm_display(e.path), "link": link})
                    self._note_mtime(st.st_mtime)
                elif looks_like_backup(name) and not link:
                    self.candidates.append({"path": norm_display(e.path), "rel": "blobs/" + name, "dir": False,
                                            "area": "blobs", "size": st.st_size})
                else:
                    self.stray.append("blobs/" + name)

    def _load_manifests(self, sub, kind):
        base = self._p(sub)
        if not os.path.isdir(long_path(base)):
            return
        stack = [(base, ())]
        while stack:
            cur, rel = stack.pop()
            try:
                it = list(os.scandir(long_path(cur)))
            except OSError as exc:
                self.problems.append("No se puede leer %s/: %s" % (sub, exc.strerror or exc))
                continue
            for e in it:
                name = e.name
                parts = rel + (name,)
                try:
                    is_dir = e.is_dir()          # sigue enlaces: v2 usa enlaces a ficheros, no a carpetas
                    is_file = e.is_file()
                    is_sym = e.is_symlink()
                except OSError:
                    is_dir = is_file = is_sym = False
                if is_dir and not is_sym:
                    if len(parts) == 1 and looks_like_backup(name):
                        self.candidates.append({"path": norm_display(e.path), "rel": "%s/%s" % (sub, name),
                                                "dir": True, "area": sub})
                        continue
                    if len(parts) < 4:
                        stack.append((e.path, parts))
                    else:
                        self.problems.append("Carpeta inesperada en %s/%s" % (sub, "/".join(parts)))
                    continue
                if name.startswith("."):
                    continue                         # temporales de un manifiesto que se esta escribiendo
                if is_sym and not is_file:
                    self.problems.append("Enlace roto en %s/%s (su fichero ya no existe)" % (sub, "/".join(parts)))
                    continue
                if not is_file:
                    continue
                if _BACKUP_TAG_SUFFIX.search(name):
                    try:
                        size = e.stat().st_size
                    except OSError:
                        size = 0
                    self.candidates.append({"path": norm_display(e.path), "rel": "%s/%s" % (sub, "/".join(parts)),
                                            "dir": False, "area": sub, "size": size, "parts": parts})
                    continue
                if len(parts) != 4:
                    self.problems.append("Manifiesto en una ruta inesperada: %s/%s" % (sub, "/".join(parts)))
                    continue
                self._add_tag(kind, sub, parts, e.path, is_sym)

    def _add_tag(self, kind, sub, parts, path, is_sym):
        host, ns, model, tag = parts
        chost = _canon_host(host)
        tg = {"kind": kind, "host": chost, "ns": ns, "model": model, "tag": tag, "path": norm_display(path),
              "key": "%s/%s/%s:%s" % (chost, ns, model, tag), "name": _display_name(host, ns, model, tag),
              "rel": "%s/%s" % (sub, "/".join(parts)), "symlink": bool(is_sym),
              "hidden": chost == "ollama.com" and ns == "library" and model == "llamacpp",
              "layout": None, "refs": [], "children": [], "self_blob": None, "error": None}
        try:
            raw, doc = _read_json(path)
            st = os.stat(long_path(path))
            self._note_mtime(st.st_mtime)
            tg["self_blob"] = "sha256-" + hashlib.sha256(raw).hexdigest()
            if not isinstance(doc, dict):
                raise ValueError("el manifiesto no es un objeto JSON")
            if doc.get("mediaType") == LIST_MEDIA or ("manifests" in doc and "layers" not in doc):
                tg["layout"] = "list"
                for c in doc.get("manifests") or []:
                    if not isinstance(c, dict):
                        raise ValueError("hijo de lista no válido")
                    bn = _blobname(c.get("digest"))
                    if bn is None:
                        raise ValueError("digest no válido en la lista: %r" % (c.get("digest"),))
                    tg["children"].append({"blob": bn, "runner": str(c.get("runner") or "").lower(),
                                           "size": c.get("size")})
            else:
                tg["layout"] = "plain"
                tg["refs"] = self._plain_refs(doc)
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            tg["error"] = "%s" % (getattr(exc, "strerror", None) or exc)
            if not tg["hidden"]:
                self.problems.append("Manifiesto ilegible %s: %s" % (tg["rel"], tg["error"]))
        self.tags.append(tg)

    @staticmethod
    def _plain_refs(doc):
        refs = []
        items = []
        if isinstance(doc.get("config"), dict):
            items.append(doc["config"])
        for lay in doc.get("layers") or []:
            if not isinstance(lay, dict):
                raise ValueError("capa no válida")
            items.append(lay)
        for it in items:
            bn = _blobname(it.get("digest"))
            if bn is None:
                raise ValueError("digest no válido: %r" % (it.get("digest"),))
            size = it.get("size")
            refs.append((bn, size if isinstance(size, int) and not isinstance(size, bool) else None))
        return refs

    def _load_children(self):
        wanted = set()
        for tg in self.tags:
            for c in tg["children"]:
                wanted.add(c["blob"])
        for bn in sorted(wanted):
            child = {"present": bn in self.blobs, "refs": [], "error": None}
            if child["present"]:
                try:
                    _raw, doc = _read_json(self.blobs[bn]["path"])
                    if not isinstance(doc, dict) or ("layers" not in doc and "config" not in doc):
                        raise ValueError("el hijo no es un manifiesto de modelo")
                    child["refs"] = self._plain_refs(doc)
                except (OSError, ValueError, UnicodeDecodeError) as exc:
                    child["error"] = "%s" % (getattr(exc, "strerror", None) or exc)
                    self.problems.append("Manifiesto hijo ilegible %s: %s" % (bn, child["error"]))
            self.children[bn] = child

    def _load_metadata(self):
        base = self._p("metadata")
        if not os.path.isdir(long_path(base)):
            return
        try:
            it = os.scandir(long_path(base))
        except OSError:
            return
        with it:
            for e in it:
                m = re.match(r"^(sha256-[0-9a-f]{64})\.json$", e.name)
                try:
                    st = e.stat(follow_symlinks=False)
                    link = e.is_symlink() or _is_link(e.path)
                    is_file = e.is_file(follow_symlinks=False)
                except OSError:
                    continue
                if m and not link and is_file:
                    self.metadata.append({"name": e.name, "blob": m.group(1), "size": st.st_size,
                                          "mtime": st.st_mtime, "path": norm_display(e.path)})
                else:
                    self.stray.append("metadata/" + e.name)

    def _load_root(self):
        try:
            it = os.scandir(long_path(self.root))
        except OSError:
            return
        with it:
            for e in it:
                if e.name in LIVE_DIRS:
                    continue
                try:
                    link = e.is_symlink() or _is_link(e.path)
                    is_dir = e.is_dir(follow_symlinks=False)
                    size = 0 if is_dir else e.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
                if looks_like_backup(e.name):
                    self.candidates.append({"path": norm_display(e.path), "rel": e.name, "dir": is_dir,
                                            "area": "root", "size": size, "link": link})
                else:
                    self.stray.append(e.name + ("/" if is_dir else ""))

    # ---- derivados
    def _derive(self):
        """Quien referencia a cada blob, y que modelos estan completos."""
        def add(blob, who):
            self.refs.setdefault(blob, set()).add(who)

        for tg in self.tags:
            who = "tag:%s:%s" % (tg["kind"], tg["key"])
            tg["who"] = who
            if tg["self_blob"] and tg["self_blob"] in self.blobs:
                add(tg["self_blob"], who)
            for blob, _sz in tg["refs"]:
                add(blob, who)
            for c in tg["children"]:
                add(c["blob"], who)
        for bn, child in self.children.items():
            for blob, _sz in child["refs"]:
                add(blob, "child:" + bn)

        v2 = {t["key"] for t in self.tags if t["kind"] == "v2"}
        for tg in self.tags:
            if tg["hidden"] or (tg["kind"] == "legacy" and tg["key"] in v2):
                continue
            m = {"name": tg["name"], "key": tg["key"], "store": tg["kind"], "layout": tg["layout"],
                 "runners": sorted({c["runner"] for c in tg["children"] if c["runner"]}),
                 "serving": None, "complete": False, "missing": [],
                 "also_legacy": tg["kind"] == "v2" and any(
                     t["kind"] == "legacy" and t["key"] == tg["key"] for t in self.tags),
                 "error": tg["error"]}
            if tg["error"]:
                m["missing"] = [{"blob": None, "why": "manifiesto ilegible: %s" % tg["error"]}]
            elif tg["layout"] == "plain":
                m["missing"] = self.missing(tg["refs"])
                m["complete"] = not m["missing"]
            elif tg["layout"] == "list":
                serv = self.serving_child(tg)
                if serv is None:
                    m["missing"] = [{"blob": None, "why": "la lista no tiene ningún hijo"}]
                else:
                    m["serving"] = serv["runner"] or "?"
                    m["missing"] = self.child_missing(serv["blob"])
                    m["complete"] = not m["missing"]
            self.models.append(m)

    def missing(self, refs):
        out = []
        for blob, size in refs:
            b = self.blobs.get(blob)
            if b is None:
                out.append({"blob": blob, "why": "falta"})
            elif size is not None and b["size"] != size:
                out.append({"blob": blob, "why": "mide %d en vez de %d" % (b["size"], size)})
        return out

    def child_missing(self, blob):
        ch = self.children.get(blob)
        if ch is None or not ch["present"]:
            return [{"blob": blob, "why": "falta el manifiesto"}]
        if ch["error"]:
            return [{"blob": blob, "why": "manifiesto ilegible: %s" % ch["error"]}]
        return self.missing(ch["refs"])

    @staticmethod
    def serving_child(tg):
        for runner in ("llamacpp", "mlx", "ggml"):
            for c in tg["children"]:
                if c["runner"] == runner:
                    return c
        return tg["children"][0] if tg["children"] else None

    @property
    def trusted(self):
        return not self.problems

    def referenced(self):
        return set(self.refs)


# ------------------------------------------------------------------ deteccion

def _item(kind, ident, path, nbytes, safe, reasons, **extra):
    d = {"id": ident, "kind": kind, "label": KIND_LABEL[kind], "path": path, "bytes": int(nbytes),
         "human": fmt_bytes(nbytes), "safe": bool(safe), "reasons": list(reasons), "model": None,
         "how": "file"}
    d.update(extra)
    return d


def _short(blob):
    return blob[7:19]


def _ggml_backups(st):
    items = []
    legacy_keys = {t["key"] for t in st.tags if t["kind"] == "legacy"}
    for tg in st.tags:
        if tg["kind"] != "v2" or tg["layout"] != "list" or tg["error"]:
            continue
        migrated = [c for c in tg["children"] if c["runner"] == "llamacpp"]
        if not migrated:
            continue
        for g in tg["children"]:
            if g["runner"] != "ggml":
                continue
            reasons = []
            safe = True
            # la version migrada tiene que funcionar sin la copia
            lc = migrated[0]
            miss = st.child_missing(lc["blob"])
            if miss:
                safe = False
                reasons.append("La versión migrada (%s) no está completa: %s. La copia es la única que funciona."
                               % (_short(lc["blob"]), "; ".join(
                                   "%s %s" % (_short(m["blob"]) if m["blob"] else "?", m["why"]) for m in miss[:3])))
            # bytes que solo ella usa
            ignorable = {tg["who"], "child:" + g["blob"]}
            if tg["key"] in legacy_keys:
                ignorable.add("tag:legacy:" + tg["key"])
            blobs = [g["blob"]]
            gch = st.children.get(g["blob"])
            if gch is None or not gch["present"]:
                safe = False
                reasons.append("El manifiesto de la copia (%s) no está en blobs/; no hay nada que liberar con ollama rm."
                               % _short(g["blob"]))
            elif gch["error"]:
                safe = False
                reasons.append("El manifiesto de la copia no se puede leer: %s" % gch["error"])
            else:
                blobs += [b for b, _s in gch["refs"]]
            uniq, shared = [], []
            for b in dict.fromkeys(blobs):
                info = st.blobs.get(b)
                if info is None:
                    continue
                (uniq if st.refs.get(b, set()) <= ignorable else shared).append((b, info["size"]))
            nbytes = sum(s for _b, s in uniq)
            if safe and nbytes == 0:
                safe = False
                reasons.append("No libera espacio: todos sus ficheros los usa también otro modelo.")
            if not st.trusted and safe:
                safe = False
                reasons.append("Hay manifiestos ilegibles en el almacén; no se puede asegurar qué ficheros comparte.")
            digest = g["blob"][7:]
            items.append(_item(
                "ggml_backup", "ggml:" + digest[:16], st._p("blobs", g["blob"]), nbytes, safe, reasons,
                model=tg["name"], how="ollama_rm", digest="sha256:" + digest,
                command="ollama rm sha256:" + digest,
                working_build={"runner": "llamacpp", "digest": "sha256:" + lc["blob"][7:],
                               "complete": not miss, "problems": miss[:5]},
                blobs=[{"digest": "sha256:" + b[7:], "bytes": s} for b, s in uniq],
                shared_blobs=len(shared), tag_key=tg["key"]))
    return items


def _orphans(st, now, min_age):
    items = []
    referenced = st.referenced()
    for name, b in sorted(st.blobs.items()):
        if name in referenced:
            continue
        reasons, safe = [], True
        age = now - b["mtime"]
        if not st.trusted:
            safe = False
            reasons.append("Hay manifiestos ilegibles: no se puede asegurar que ninguno use este fichero.")
        if age < min_age:
            safe = False
            reasons.append("Modificado hace %d min: puede ser de una descarga en curso." % max(0, int(age // 60)))
        if b["link"]:
            safe = False
            reasons.append("Es un enlace: no se toca.")
        items.append(_item("orphan_blob", "blob:" + name[7:23], b["path"], b["size"], safe, reasons,
                           mtime=b["mtime"], name=name))
    for p in st.partials:
        reasons, safe = [], True
        age = now - p["mtime"]
        if age < PARTIAL_MIN_AGE_S:
            safe = False
            reasons.append("Tocado hace %.1f días: puede ser una descarga que se reanudará." % (age / 86400.0))
        if p["link"]:
            safe = False
            reasons.append("Es un enlace: no se toca.")
        items.append(_item("partial", "partial:" + p["name"][7:23] + p["name"][71:], p["path"], p["size"], safe,
                           reasons, mtime=p["mtime"], name=p["name"]))
    return items


def _orphan_metadata(st, now, min_age):
    items = []
    names = set(st.blobs) | {p["name"][:71] for p in st.partials}
    for m in st.metadata:
        if m["blob"] in names:
            continue
        safe = (now - m["mtime"]) >= min_age
        items.append(_item("orphan_metadata", "meta:" + m["blob"][7:23], m["path"], m["size"], safe,
                           [] if safe else ["Reciente: puede acompañar a un blob que aún se está escribiendo."],
                           mtime=m["mtime"], name=m["name"]))
    return items


def _backup_candidates(st):
    items = []
    live_keys = {m["key"]: m for m in st.models}
    why_unhealthy = None
    if not st.trusted:
        why_unhealthy = "Hay manifiestos ilegibles en el almacén vivo."
    else:
        broken = [m["name"] for m in st.models if not m["complete"]]
        if broken:
            why_unhealthy = ("El almacén vivo tiene modelos incompletos (%s): la copia podría ser lo único que queda."
                             % ", ".join(broken[:4]))
    v2_links = []
    for t in st.tags:
        if t["kind"] == "v2" and t["symlink"]:
            try:
                v2_links.append(os.path.normcase(os.path.realpath(long_path(t["path"]))))
            except OSError:
                pass
    for c in st.candidates:
        reasons, safe = [], True
        path = c["path"]
        if c.get("link"):
            items.append(_item("backup_dir" if c["dir"] else "backup_file", "bk:" + c["rel"], path, 0, False,
                               ["Es un enlace: no se toca."], rel=c["rel"]))
            continue
        if c["dir"]:
            coll = []
            total, nfiles, links, errors, hard = _tree_size(path, coll)
            if nfiles == 0 and not links:
                continue
            if links:
                safe = False
                reasons.append("Contiene enlaces simbólicos o uniones (%d): no se puede verificar qué hay detrás." % len(links))
            if errors:
                safe = False
                reasons.append("No se puede leer todo su contenido (%d errores)." % len(errors))
            real = os.path.normcase(os.path.realpath(long_path(path)))
            if any(r == real or r.startswith(real + os.sep) for r in v2_links):
                safe = False
                reasons.append("Un manifiesto vivo apunta dentro de esta carpeta.")
            models_in, unknown = {}, 0
            for fpath, _fsz in coll:
                fpath = norm_display(fpath)
                fname = os.path.basename(fpath)
                if BLOB_RE.match(fname) or PARTIAL_RE.match(fname):
                    continue
                try:
                    rel_parts = os.path.relpath(fpath, path).split(os.sep)
                    _raw, doc = _read_json(fpath)
                    if isinstance(doc, dict) and ("layers" in doc or "manifests" in doc) and len(rel_parts) >= 4:
                        host, ns, model, tag = rel_parts[-4:]
                        models_in["%s/%s/%s:%s" % (_canon_host(host), ns, model, tag)] = (
                            _display_name(host, ns, model, tag))
                        continue
                except (OSError, ValueError, UnicodeDecodeError):
                    pass
                unknown += 1
            if unknown:
                safe = False
                reasons.append("Contiene %d ficheros que no son ni blobs ni manifiestos de Ollama." % unknown)
            lost = [nm for k, nm in models_in.items() if k not in live_keys or not live_keys[k]["complete"]]
            if lost:
                safe = False
                reasons.append("Guarda modelos que el almacén vivo no tiene completos: %s." % ", ".join(sorted(lost)[:4]))
            if why_unhealthy:
                safe = False
                reasons.append(why_unhealthy)
            items.append(_item("backup_dir", "bk:" + c["rel"], path, total, safe, reasons, rel=c["rel"],
                               files=nfiles, models=sorted(models_in.values()), hardlinked_files=hard))
        else:
            fname = os.path.basename(path)
            size = c.get("size", 0)
            if c["area"] == "blobs":
                m = re.match(r"^(sha256-[0-9a-f]{64})", fname)
                if m and m.group(1) in st.blobs:
                    pass
                elif m:
                    safe = False
                    reasons.append("El fichero original (%s) ya no está: esta copia es la única." % _short(m.group(1)))
                else:
                    safe = False
                    reasons.append("No es un blob de Ollama conocido.")
            elif c["area"] in ("manifests", "manifests-v2") and c.get("parts") and len(c["parts"]) == 4:
                parts = list(c["parts"])
                base = _BACKUP_TAG_SUFFIX.sub("", parts[-1])
                key = "%s/%s/%s:%s" % (_canon_host(parts[0]), parts[1], parts[2], base)
                live = live_keys.get(key)
                if live is None:
                    safe = False
                    reasons.append("No hay un modelo vivo con ese nombre: la copia es la única.")
                elif not live["complete"]:
                    safe = False
                    reasons.append("El modelo vivo '%s' no está completo." % live["name"])
            else:
                safe = False
                reasons.append("No es un fichero de Ollama conocido.")
            if safe and why_unhealthy:
                safe = False
                reasons.append(why_unhealthy)
            items.append(_item("backup_file", "bk:" + c["rel"], path, size, safe, reasons, rel=c["rel"]))
    return items


_VER_CACHE = {"t": 0.0, "v": None}


def _cli_version():
    """Version de Ollama segun ``ollama --version`` (cliente), con cache de 10 min. None si no se puede."""
    now = time.time()
    if now - _VER_CACHE["t"] < 600:
        return _VER_CACHE["v"]
    ver = None
    exe = shutil.which("ollama")
    try:
        if not exe:
            raise OSError("ollama no esta en el PATH")
        r = subprocess.run([exe, "--version"], capture_output=True, timeout=6,
                           creationflags=0x08000000 if IS_WIN else 0)
        txt = (r.stdout + b"\n" + r.stderr).decode("utf-8", "replace")
        m = re.search(r"(?i)(?:client )?version is\s+v?(\d+\.\d+\.\d+\S*)", txt)
        ver = m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        ver = None
    _VER_CACHE.update({"t": now, "v": ver})
    return ver


def scan(models_dir=None, now=None, min_age=MIN_ORPHAN_AGE_S, api=None, procs=None):
    """Detecta copias y huerfanos. Solo lee. Devuelve un dict listo para JSON."""
    now = time.time() if now is None else now
    root, source, cands = resolve_models_dir(models_dir)
    problem, blockers = verify_models_dir(root)
    out = {"models_dir": norm_display(root), "source": source, "candidates": cands, "error": problem,
           "items": [], "models": [], "problems": [], "reclaimable_bytes": 0, "reclaimable_human": "0 B",
           "unsafe_bytes": 0, "unsafe_human": "0 B", "counts": {}, "free_blockers": list(blockers),
           "busy": [], "warnings": [], "can_free": False}
    if problem:
        return out
    st = Store(root).load()
    items = (_ggml_backups(st) + _orphans(st, now, min_age) + _orphan_metadata(st, now, min_age)
             + _backup_candidates(st))
    items.sort(key=lambda i: (not i["safe"], -i["bytes"]))
    safe_b = sum(i["bytes"] for i in items if i["safe"])
    unsafe_b = sum(i["bytes"] for i in items if not i["safe"])
    counts = {}
    for i in items:
        c = counts.setdefault(i["kind"], {"count": 0, "safe": 0, "bytes": 0, "safe_bytes": 0})
        c["count"] += 1
        c["bytes"] += i["bytes"]
        if i["safe"]:
            c["safe"] += 1
            c["safe_bytes"] += i["bytes"]
    act = activity(root, st, now, api=api, procs=procs)
    if act["ollama"]["version"] is None:
        act["ollama"]["version"] = _cli_version()
    blob_bytes = sum(b["size"] for b in st.blobs.values())
    out.update({
        "items": items, "models": st.models, "problems": st.problems, "stray": st.stray,
        "reclaimable_bytes": safe_b, "reclaimable_human": fmt_bytes(safe_b),
        "unsafe_bytes": unsafe_b, "unsafe_human": fmt_bytes(unsafe_b), "counts": counts,
        "layout": {"manifests_v2": os.path.isdir(long_path(st._p("manifests-v2"))),
                   "manifests_legacy": os.path.isdir(long_path(st._p("manifests"))),
                   "metadata": os.path.isdir(long_path(st._p("metadata"))),
                   "blobs": len(st.blobs), "blob_bytes": blob_bytes, "blob_human": fmt_bytes(blob_bytes),
                   "partials": len(st.partials), "tags": len([t for t in st.tags if not t["hidden"]]),
                   "lists": len([t for t in st.tags if t["layout"] == "list"])},
        "ollama": act["ollama"], "busy": act["busy"], "warnings": act["warnings"],
        "can_free": not blockers and not act["busy"],
    })
    return out


# ------------------------------------------------------------------ actividad de Ollama

def _ollama_base():
    host = os.environ.get("OLLAMA_HOST", "").strip()
    if host:
        h = host.split("://", 1)[-1].split("/", 1)[0]
        name, _, port = h.rpartition(":") if ":" in h and not h.endswith("]") else (h, "", "")
        if name in ("", "0.0.0.0", "localhost", "127.0.0.1", "[::]", "::", "[::1]"):
            return "http://127.0.0.1:%s" % (port or "11434")
        # un servidor remoto no nos dice nada sobre este almacen
    return "http://127.0.0.1:11434"


def _api_get(path, timeout=1.5):
    try:
        with urllib.request.urlopen(_ollama_base() + path, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8") or "{}")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _list_processes():
    """[(nombre, linea de comandos)] de los procesos ollama, o None si no se pudo mirar."""
    try:
        if IS_WIN:
            cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                   "Get-CimInstance Win32_Process -Filter \"Name like 'ollama%'\" | "
                   "Select-Object Name,CommandLine | ConvertTo-Json -Compress"]
            r = subprocess.run(cmd, capture_output=True, timeout=25, creationflags=0x08000000)
            txt = r.stdout.decode("utf-8", "replace").strip()
            if not txt:
                return []
            data = json.loads(txt)
            data = data if isinstance(data, list) else [data]
            return [(str(d.get("Name") or ""), str(d.get("CommandLine") or "")) for d in data]
        r = subprocess.run(["ps", "-eo", "comm,args"], capture_output=True, timeout=10)
        rows = []
        for line in r.stdout.decode("utf-8", "replace").splitlines()[1:]:
            parts = line.strip().split(None, 1)
            if parts and "ollama" in parts[0].lower():
                rows.append((parts[0], parts[1] if len(parts) > 1 else ""))
        return rows
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


_BUSY_CMD = re.compile(r"(?i)ollama(?:\.exe)?\"?\s+(pull|run|create|push|cp|copy|runner)\b")


def activity(root, st, now, api=None, procs=None):
    """Que esta haciendo Ollama ahora. ``busy`` = razones para negarse a borrar."""
    api = api or _api_get
    procs = procs or _list_processes
    busy, warnings = [], []
    info = {"running": False, "loaded": [], "version": None, "processes": None}
    ps = api("/api/ps")
    if ps is not None:
        info["running"] = True
        loaded = [str(m.get("name") or m.get("model") or "?") for m in (ps.get("models") or [])]
        info["loaded"] = loaded
        if loaded:
            busy.append("Hay modelos cargados en Ollama (%s): pueden estar migrándose o usándose. "
                        "Descárgalos con `ollama stop <modelo>` y vuelve a probar." % ", ".join(loaded[:4]))
        ver = api("/api/version")
        if ver:
            info["version"] = ver.get("version")
    rows = procs()
    if rows is None:
        warnings.append("No se han podido listar los procesos de Ollama; se confía en la API y en la actividad del disco.")
    else:
        info["processes"] = len(rows)
        for name, cmd in rows:
            m = _BUSY_CMD.search(cmd or "")
            if m:
                busy.append("Hay un proceso de Ollama haciendo `%s` (%s)." % (m.group(1), name))
    if st is not None:
        hot = [p for p in st.partials if now - p["mtime"] < PARTIAL_ACTIVE_S]
        if hot:
            busy.append("Hay una descarga en curso (%d fichero(s) -partial tocado(s) hace menos de %d min)."
                        % (len(hot), PARTIAL_ACTIVE_S // 60))
        if st.last_write and now - st.last_write < RECENT_WRITE_S:
            busy.append("Se ha escrito en el almacén hace menos de %d s." % RECENT_WRITE_S)
    return {"busy": busy, "warnings": warnings, "ollama": info}


# ------------------------------------------------------------------ liberar

def audit_path(data_dir):
    return os.path.join(data_dir, "ollama-free-audit.jsonl")


def _audit(data_dir, record):
    if not data_dir:
        return None
    path = audit_path(data_dir)
    try:
        os.makedirs(data_dir, exist_ok=True)
        with _AUDIT_LOCK, open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        return path
    except OSError:
        return None


def read_audit(data_dir, limit=50):
    try:
        with open(audit_path(data_dir), "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()[-int(limit):]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out


def _run_ollama_rm(digest, timeout=600):
    exe = shutil.which("ollama")
    if not exe:
        return 127, "", "No se encuentra el ejecutable `ollama` en el PATH."
    try:
        r = subprocess.run([exe, "rm", digest], capture_output=True, timeout=timeout,
                           creationflags=0x08000000 if IS_WIN else 0)
    except FileNotFoundError:
        return 127, "", "No se encuentra el ejecutable `ollama` en el PATH."
    except subprocess.TimeoutExpired:
        return 124, "", "ollama rm no terminó en %d s." % timeout
    return r.returncode, r.stdout.decode("utf-8", "replace").strip(), r.stderr.decode("utf-8", "replace").strip()


def _inside(root, path):
    r = os.path.normcase(os.path.realpath(long_path(root)))
    p = os.path.normcase(os.path.realpath(long_path(path)))
    return p != r and p.startswith(r + os.sep)


def _brief(i):
    d = {"id": i["id"], "kind": i["kind"], "path": i["path"], "bytes": i["bytes"], "human": i["human"],
         "how": i["how"], "model": i.get("model")}
    if i.get("command"):
        d["command"] = i["command"]
    return d


def free(models_dir=None, ids=None, dry_run=True, confirm=False, mode="trash", data_dir=None, caller="",
         now=None, min_age=MIN_ORPHAN_AGE_S, api=None, procs=None, run_rm=None, trash=None, perm=None):
    """Libera lo que ``scan`` marca seguro. Simulacro por defecto; borrar de verdad exige ``confirm=True``.

    ``ids``: lista de ids de ``scan`` (o ``None``/``"all_safe"`` para todo lo seguro).
    ``mode``: ``trash`` (Papelera) o ``permanent`` para los ficheros; las copias ggml siempre van por ``ollama rm``.
    """
    now = time.time() if now is None else now
    run_rm = run_rm or _run_ollama_rm
    trash = trash or send_to_trash
    perm = perm or delete_permanent
    if mode not in ("trash", "permanent"):
        return {"error": "mode debe ser 'trash' o 'permanent'."}
    snap = scan(models_dir, now=now, min_age=min_age, api=api, procs=procs)
    root = snap["models_dir"]
    audit = {"t": now, "when": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)), "action": "free",
             "dry_run": bool(dry_run), "mode": mode, "models_dir": root, "caller": caller or "ui",
             "requested": ids if isinstance(ids, list) else (ids or "all_safe")}
    if snap["error"]:
        audit.update({"outcome": "refused", "reason": snap["error"]})
        _audit(data_dir, audit)
        return {"error": snap["error"], "models_dir": root}
    by_id = {i["id"]: i for i in snap["items"]}
    wanted, missing_ids = [], []
    if ids in (None, "all", "all_safe", ""):
        wanted = [i for i in snap["items"] if i["safe"]]
    else:
        for ident in ids:
            if ident in by_id:
                wanted.append(by_id[ident])
            else:
                missing_ids.append(ident)
    refused = [{"id": i["id"], "path": i["path"], "reasons": i["reasons"] or ["No está marcado como seguro."]}
               for i in wanted if not i["safe"]]
    refused += [{"id": ident, "path": None, "reasons": ["Ya no existe en el almacén (vuelve a detectar)."]}
                for ident in missing_ids]
    plan = [i for i in wanted if i["safe"]]
    blocked = []
    if snap["free_blockers"]:
        blocked.append("La carpeta de modelos no se puede verificar: " + "; ".join(snap["free_blockers"]) + ".")
    blocked += snap["busy"]
    if any(i["how"] == "ollama_rm" for i in plan) and not snap["ollama"]["running"]:
        blocked.append("Ollama no está en marcha: las copias de la migración se quitan con `ollama rm`, "
                       "que necesita el servidor. Arráncalo (sin cargar modelos) y repite.")
    if mode == "trash" and not IS_WIN and any(i["how"] == "file" for i in plan):
        blocked.append("La Papelera solo existe en Windows; usa mode='permanent' con confirm=true.")
    total = sum(i["bytes"] for i in plan)
    res = {"dry_run": bool(dry_run), "mode": mode, "models_dir": root, "planned": [_brief(i) for i in plan],
           "planned_bytes": total, "planned_human": fmt_bytes(total), "refused": refused, "blocked": blocked,
           "done": [], "failed": [], "freed_bytes": 0, "freed_human": "0 B"}
    if dry_run:
        res["note"] = "Simulacro: no se ha tocado nada."
        audit.update({"outcome": "dry_run", "planned": res["planned"], "planned_bytes": total,
                      "blocked": blocked, "refused": refused})
        res["audit"] = _audit(data_dir, audit)
        return res
    if not confirm:
        res["error"] = "Borrar de verdad necesita confirm=true (enséñale antes a la persona la lista y los tamaños)."
        audit.update({"outcome": "refused", "reason": "sin confirmación", "planned": res["planned"]})
        res["audit"] = _audit(data_dir, audit)
        return res
    if blocked:
        res["error"] = "No se borra nada ahora: " + " ".join(blocked)
        audit.update({"outcome": "refused", "reason": "bloqueado", "blocked": blocked})
        res["audit"] = _audit(data_dir, audit)
        return res
    if not plan:
        res["error"] = "No hay nada seguro que liberar" + (" con esos ids." if ids not in (None, "all_safe", "all", "") else ".")
        audit.update({"outcome": "refused", "reason": "nada seguro", "refused": refused})
        res["audit"] = _audit(data_dir, audit)
        return res
    for it in plan:
        rec = _brief(it)
        try:
            if it["how"] == "ollama_rm":
                rc, so, se = run_rm(it["digest"])
                rec["output"] = (so or se)[:300]
                if rc != 0:
                    rec["error"] = (se or so or "ollama rm devolvió %s" % rc)[:300]
                    res["failed"].append(rec)
                    continue
                again = scan(root, now=time.time(), min_age=min_age, api=api, procs=procs)
                still = any(i["id"] == it["id"] for i in again["items"])
                good = next((m for m in again["models"] if m["key"] == it.get("tag_key")), None)
                rec["verified"] = (not still) and bool(good and good["complete"])
                rec["freed"] = it["bytes"]
                if not rec["verified"]:
                    rec["warning"] = "ollama rm terminó bien pero la copia sigue ahí o el modelo no se ve completo."
                res["done"].append(rec)
            else:
                path = it["path"]
                if not os.path.lexists(long_path(path)):
                    rec["error"] = "ya no existe"
                    res["failed"].append(rec)
                    continue
                if _is_link(path) or not _inside(root, path):
                    rec["error"] = "no está dentro de la carpeta de modelos verificada o es un enlace"
                    res["failed"].append(rec)
                    continue
                if mode == "trash":
                    ok, err = trash([path])
                    if not ok:
                        rec["error"] = str(err)[:300]
                        res["failed"].append(rec)
                        continue
                    rec["freed"] = it["bytes"]
                else:
                    freed, _nf, errs = perm(path)
                    if errs:
                        rec["error"] = "; ".join(errs[:3])[:300]
                        res["failed"].append(rec)
                        continue
                    rec["freed"] = freed
                rec["verified"] = not os.path.lexists(long_path(path))
                res["done"].append(rec)
        except Exception as exc:  # noqa: BLE001 - una copia que falla no tumba el resto
            rec["error"] = "%s: %s" % (type(exc).__name__, exc)
            res["failed"].append(rec)
    freed = sum(d.get("freed", 0) for d in res["done"])
    res["freed_bytes"] = freed
    res["freed_human"] = fmt_bytes(freed)
    if mode == "trash" and any(d["how"] == "file" for d in res["done"]):
        res["note"] = ("Los ficheros están en la Papelera: el disco no se libera hasta vaciarla. Si alguno pesaba "
                       "más que la Papelera, Windows lo ha borrado directamente.")
    audit.update({"outcome": "freed" if res["done"] else "failed", "done": res["done"], "failed": res["failed"],
                  "refused": refused, "freed_bytes": freed})
    res["audit"] = _audit(data_dir, audit)
    return res
