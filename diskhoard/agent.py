# -*- coding: utf-8 -*-
"""Lo que DiskHoard le ofrece a un agente (Faustus, Claude, cualquier cliente MCP).

Un catalogo de herramientas con su esquema de entrada, y un despachador que
las ejecuta contra el estado del servidor. El puente MCP (`mcp_server.py`)
no sabe nada de discos: pide la lista aqui y reenvia cada llamada por HTTP.
Asi el puente y la app no pueden discrepar: son el mismo codigo.

Reglas de la casa para el borrado por agente:
- a la papelera por defecto; definitivo solo con mode="permanent" y confirm=true;
- nunca una raiz de unidad, el perfil, Windows, Archivos de programa ni nada
  que el catalogo marque como "no tocar";
- todo queda apuntado en un registro que la interfaz ensena.
"""
from __future__ import annotations

import fnmatch
import os
import time

from . import junk as junkmod
from .winfs import IS_WIN, long_path, norm_display

MB = 1024 ** 2
GB = 1024 ** 3


# ------------------------------------------------------------------ catalogo

def _tool(name, description, props=None, required=None, *, read_only=True,
          destructive=False, idempotent=False):
    schema = {"type": "object", "properties": props or {}, "additionalProperties": False}
    if required:
        schema["required"] = list(required)
    return {
        "name": name,
        "description": description,
        "inputSchema": schema,
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": idempotent,
            "openWorldHint": False,
        },
    }


_PATH = {"type": "string", "description": "Absolute folder path, e.g. C:\\Users\\me or D:\\. "
                                          "Omit for the root of the current scan."}
_LIMIT = lambda d, m=200: {"type": "integer", "minimum": 1, "maximum": m, "default": d}  # noqa: E731

CATALOG = [
    _tool("disk_drives",
          "Drives with used and free space. Keywords: discos, unidades, espacio libre, cuánto queda, disk space.\n"
          "Returns every mounted drive (path, label, type, total, free) plus shortcuts such as Downloads or "
          "AppData. Use it first to decide where to scan.",
          idempotent=True),
    _tool("disk_scan",
          "Scan a folder or drive to measure what takes space. Keywords: escanear, analizar disco, qué ocupa, scan.\n"
          "Walks the tree in parallel (a full 1.5 TB drive takes about a minute) and keeps a size map in "
          "memory that the other tools query. By default waits for the scan to end; with wait=false it "
          "returns at once and disk_status reports progress. Replaces any previous scan.",
          {"path": {"type": "string", "description": "Absolute folder or drive to scan, e.g. C:\\ or C:\\Users\\me"},
           "wait": {"type": "boolean", "default": True, "description": "Block until the scan finishes"},
           "timeout_s": {"type": "integer", "minimum": 5, "maximum": 900, "default": 240,
                         "description": "Maximum seconds to wait when wait=true"}},
          ["path"]),
    _tool("disk_status",
          "Progress of the running scan or summary of the last one. Keywords: estado, progreso, cuánto falta.\n"
          "Cheap to call. Says whether a scan is running, how many files and bytes it has seen, and when "
          "done the root, total size, file and folder counts.",
          idempotent=True),
    _tool("disk_dir",
          "Contents of a scanned folder, biggest first, with junk tags. Keywords: carpeta, qué hay dentro, listar.\n"
          "Each entry has size, file count, share of the parent, last modified date and, when the "
          "catalog knows the folder, what it is and whether it is safe to delete. Files are listed live so "
          "the view is always current.",
          {"path": _PATH, "limit": _LIMIT(40, 500),
           "dirs_only": {"type": "boolean", "default": False}},
          idempotent=True),
    _tool("disk_hotspots",
          "Where the space really goes: disjoint heavy spots. Keywords: puntos calientes, dónde están mis gigas.\n"
          "Not a folder ranking (that repeats parent and child): a partition of the tree into pieces that "
          "do not overlap, each attributed as deep as the weight can be pinned. What is spread over many "
          "small things appears as 'scattered rest'.",
          {"limit": _LIMIT(30, 100)}, idempotent=True),
    _tool("disk_junk",
          "Known junk with safety level: caches, node_modules, temp. Keywords: basura, limpiar, liberar espacio.\n"
          "Every item says what it is, why it is there, how it regenerates and whether it is 'safe' "
          "(regenerates alone), 'review' (heavy but recoverable) or 'danger' (never delete). Totals per "
          "category and the reclaimable sum come with it. Filter by safety, category or minimum size.",
          {"safety": {"type": "string", "enum": ["safe", "review", "danger", "all"], "default": "all"},
           "category": {"type": "string", "description": "Exact category name as returned, e.g. 'Compilaciones'"},
           "min_mb": {"type": "number", "minimum": 0, "default": 20},
           "limit": _LIMIT(60, 600)},
          idempotent=True),
    _tool("disk_stale",
          "Big folders nobody touched in months. Keywords: sin tocar, olvidado, antiguo, stale, untouched.\n"
          "Folders above a size floor whose newest file is older than the given number of months. Good "
          "candidates for archiving or asking the user about.",
          {"months": {"type": "integer", "minimum": 1, "maximum": 120, "default": 12},
           "min_gb": {"type": "number", "minimum": 0.05, "default": 1},
           "limit": _LIMIT(40, 200)},
          idempotent=True),
    _tool("disk_top_files",
          "The heaviest single files of the scan. Keywords: ficheros grandes, archivos pesados, biggest files.\n"
          "Up to 500 largest files with a note for the usual suspects (hiberfil.sys, pagefile.sys, .vhdx, "
          "Blender .blend1 copies). Optionally restrict to an extension.",
          {"limit": _LIMIT(30, 500),
           "ext": {"type": "string", "description": "Only this extension, e.g. '.iso' or 'mp4'"}},
          idempotent=True),
    _tool("disk_types",
          "Space by file category: video, AI models, archives, code. Keywords: por tipo, extensiones, file types.\n"
          "Aggregates the scan by category with the top extensions of each.",
          {"limit": _LIMIT(20, 40)}, idempotent=True),
    _tool("disk_find",
          "Find files by name glob, extension, size or age in a folder. Keywords: buscar ficheros, mayores de, find.\n"
          "Walks the folder live (bounded to max_entries) and returns matches biggest first. Combine "
          "filters: name glob (*.iso), minimum size, older than N days. Works on any folder, scanned or not.",
          {"path": _PATH,
           "pattern": {"type": "string", "description": "Case-insensitive glob on the file name, e.g. '*.iso' or 'backup*'"},
           "min_mb": {"type": "number", "minimum": 0, "default": 0},
           "older_than_days": {"type": "integer", "minimum": 0, "default": 0},
           "limit": _LIMIT(50, 500),
           "max_entries": {"type": "integer", "minimum": 1000, "maximum": 2000000, "default": 300000}},
          idempotent=True),
    _tool("disk_explain",
          "What a folder or file is and whether it is safe to delete. Keywords: qué es esta carpeta, se puede borrar.\n"
          "Matches the path against the junk catalog (node_modules, caches, WinSxS...) and the file notes, "
          "and adds its measured size when it is inside the current scan. Answers 'danger' for anything "
          "the assistant must never delete.",
          {"path": {"type": "string", "description": "Absolute path of a folder or file"}},
          ["path"], idempotent=True),
    _tool("disk_script",
          "Write a reviewable PowerShell cleanup script for paths. Keywords: script de limpieza, powershell, dry run.\n"
          "Nothing is deleted: the script is saved under the app's data folder and returned, with -WhatIf "
          "support so the user can simulate it first. Prefer this over disk_delete when the user wants to "
          "look before anything happens.",
          {"paths": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 500}},
          ["paths"]),
    _tool("disk_delete",
          "Delete paths: Recycle Bin by default, permanent only with confirm. Keywords: borrar, eliminar, papelera.\n"
          "Refuses drive roots, the user profile, Windows, Program Files and anything the catalog marks "
          "'danger'. mode='trash' is reversible; mode='permanent' needs confirm=true and cannot be undone. "
          "Waits for the job and returns bytes freed and per-path errors. The size map is updated in place.",
          {"paths": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 500},
           "mode": {"type": "string", "enum": ["trash", "permanent"], "default": "trash"},
           "confirm": {"type": "boolean", "default": False,
                       "description": "Must be true for mode='permanent'. Say so to the user first."},
           "timeout_s": {"type": "integer", "minimum": 5, "maximum": 1800, "default": 600}},
          ["paths"], read_only=False, destructive=True),
    _tool("disk_rescan",
          "Re-read one subfolder and splice fresh numbers into the scan. Keywords: refrescar, actualizar, rescan.\n"
          "Seconds instead of a full scan. Use it after deleting outside the app or when a folder changed.",
          {"path": _PATH}, idempotent=True),
]

TOOL_NAMES = [t["name"] for t in CATALOG]

INSTRUCTIONS = (
    "DiskHoard measures what fills the user's disks and knows which folders are regenerable junk. "
    "Start with disk_drives, then disk_scan on the drive or folder the user cares about, then read "
    "disk_hotspots and disk_junk. Quote sizes in GB with one decimal. Before any disk_delete, list "
    "the exact paths and their safety level to the user; use mode='permanent' only when they ask for it "
    "explicitly. When unsure, hand them a disk_script instead."
)


# ---------------------------------------------------------------- utilidades

def _fmt(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%.1f %s" if unit not in ("B",) else "%d %s") % (n, unit)
        n /= 1024.0
    return "%.1f TB" % n


def _day(ts):
    return time.strftime("%Y-%m-%d", time.localtime(ts)) if ts else ""


def _norm(path):
    p = norm_display(os.path.abspath(str(path or "")))
    return p


def _protected_roots():
    """Rutas que un agente no borra jamas, pase lo que pase."""
    roots = set()
    home = os.path.expanduser("~")
    for p in (home, os.path.join(home, "Desktop"), os.path.join(home, "Documents"),
              os.path.join(home, "Pictures"), os.path.join(home, "Videos"),
              os.path.join(home, "Music"), os.path.join(home, "Downloads"),
              os.environ.get("SystemRoot", ""), os.environ.get("ProgramFiles", ""),
              os.environ.get("ProgramFiles(x86)", ""), os.environ.get("ProgramData", ""),
              os.environ.get("SystemDrive", "")):
        if p:
            roots.add(os.path.abspath(p).rstrip("\\/").lower())
    return roots


def refuse_reason(path):
    """Por que un agente no puede borrar esta ruta, o None si puede."""
    if not os.path.isabs(str(path or "")):
        return "not an absolute path"
    p = _norm(path)
    stripped = p.rstrip("\\/")
    if IS_WIN and len(stripped) <= 2:
        return "a drive root"
    if not IS_WIN and stripped in ("", "/"):
        return "the filesystem root"
    low = stripped.lower()
    if low in _protected_roots():
        return "a protected system or profile folder"
    sysroot = os.environ.get("SystemRoot", "")
    if sysroot and low.startswith(os.path.abspath(sysroot).lower().rstrip("\\/") + os.sep):
        # dentro de Windows solo se permite lo que el catalogo marca como seguro
        rule = junkmod.match_rule(stripped, os.path.basename(stripped))
        if rule is None or rule["safety"] != junkmod.SAFE:
            return "inside the Windows folder and not a known safe cache"
    name = os.path.basename(stripped)
    if os.path.isdir(long_path(p)):
        rule = junkmod.match_rule(stripped, name)
        if rule is not None and rule["safety"] == junkmod.DANGER:
            return "marked 'do not touch' (%s)" % rule["label"]
        # un .git o WinSxS dentro de la ruta tampoco se lleva por delante
        parts = stripped.replace("/", "\\").split("\\")
        if any(part.lower() in (".git",) for part in parts[:-1]):
            return "lives inside a Git repository's metadata"
    elif name in junkmod.FILE_NOTES:
        return "a system file (%s)" % junkmod.FILE_NOTES[name][0]
    return None


# --------------------------------------------------------------- despachador

class Agent:
    """Ejecuta las herramientas del catalogo contra el servidor.

    `srv` es el modulo `server` (se pasa para evitar la importacion circular):
    de el se usan ST y las funciones api_*.
    """

    def __init__(self, srv):
        self.srv = srv
        self.log = []
        self.seq = 0

    # ---- registro
    def _note(self, tool, summary, args=None):
        self.seq += 1
        item = {"seq": self.seq, "t": time.time(), "tool": tool, "summary": summary}
        if args:
            item["args"] = args
        self.log.append(item)
        del self.log[:-200]

    def recent(self, since=0):
        return {"seq": self.seq, "items": [i for i in self.log if i["seq"] > since][-50:]}

    # ---- entrada
    def call(self, name, arguments):
        if name not in TOOL_NAMES:
            return {"error": "unknown tool: %s" % name}, True
        args = dict(arguments or {})
        fn = getattr(self, "t_" + name)
        try:
            out = fn(**args)
        except TypeError as exc:
            return {"error": "bad arguments for %s: %s" % (name, exc)}, True
        except Exception as exc:  # noqa: BLE001 - el agente debe recibir el error, no un 500
            return {"error": "%s: %s" % (type(exc).__name__, exc)}, True
        is_err = isinstance(out, dict) and bool(out.get("error"))
        return out, is_err

    # ---- lo que hay que tener
    def _need_scan(self):
        sc = self.srv.ST.scanner
        if sc is None:
            return None, {"error": "No scan yet: call disk_scan with a path first."}
        if not sc.done:
            return None, {"error": "A scan is still running (%s); wait or call disk_status." % sc.root_display}
        if sc.error:
            return None, {"error": sc.error}
        return sc, None

    # ---- herramientas
    def t_disk_drives(self):
        d = self.srv.api_drives()
        for dr in d["drives"]:
            dr["used"] = max(0, (dr.get("total") or 0) - (dr.get("free") or 0))
            dr["human"] = "%s free of %s" % (_fmt(dr.get("free")), _fmt(dr.get("total")))
        self._note("disk_drives", "%d drives" % len(d["drives"]))
        return d

    def t_disk_scan(self, path, wait=True, timeout_s=240):
        r = self.srv.api_scan(path)
        if "error" in r:
            return r
        self._note("disk_scan", r["root"], {"path": r["root"]})
        if not wait:
            return {"started": True, "root": r["root"]}
        deadline = time.time() + max(5, min(900, int(timeout_s)))
        sc = self.srv.ST.scanner
        while not sc.done and time.time() < deadline:
            time.sleep(0.2)
        if not sc.done:
            p = self.srv.api_progress()
            p["timeout"] = True
            p["hint"] = "Still scanning; call disk_status until done is true."
            return p
        if sc.error:
            return {"error": sc.error}
        return self._summary(sc)

    def _summary(self, sc):
        p = self.srv.api_progress()
        return {"done": True, "root": sc.root_display, "size": sc.root.size,
                "human": _fmt(sc.root.size), "files": sc.root.nfiles, "dirs": p.get("dirs"),
                "errors": p.get("errors"), "elapsed_s": round(sc.finished - sc.started, 1)}

    def t_disk_status(self):
        sc = self.srv.ST.scanner
        if sc is None:
            return {"idle": True, "hint": "No scan yet: call disk_scan."}
        p = self.srv.api_progress()
        p["root"] = sc.root_display
        p["human"] = _fmt(p.get("total") if p.get("done") else p.get("bytes"))
        return p

    def t_disk_dir(self, path=None, limit=40, dirs_only=False):
        sc, err = self._need_scan()
        if err:
            return err
        d = self.srv.api_dir(path or sc.root_display)
        if "error" in d:
            return d
        ents = d["entries"]
        if dirs_only:
            ents = [e for e in ents if e["dir"]]
        total = d["size"] or 1
        out = []
        for e in ents[:int(limit)]:
            item = {"name": e["name"], "path": e["path"], "dir": e["dir"], "size": e["size"],
                    "human": _fmt(e["size"]), "share": round(100.0 * e["size"] / total, 1),
                    "files": e["files"], "modified": _day(e["mtime"])}
            if e.get("tag"):
                item["tag"] = {k: e["tag"][k] for k in ("label", "safety", "why", "how")}
            if e.get("err"):
                item["no_permission"] = True
            if e.get("link"):
                item["link"] = True
            out.append(item)
        self._note("disk_dir", d["path"])
        return {"path": d["path"], "parent": d["parent"], "size": d["size"], "human": _fmt(d["size"]),
                "files": d["files"], "shown": len(out), "total_entries": len(ents), "entries": out}

    def t_disk_hotspots(self, limit=30):
        sc, err = self._need_scan()
        if err:
            return err
        h = self.srv.api_hotspots()
        items = []
        for it in h["items"][:int(limit)]:
            item = dict(it)
            item["human"] = _fmt(it["size"])
            item["share"] = round(100.0 * it["size"] / (h["total"] or 1), 1)
            items.append(item)
        self._note("disk_hotspots", "%d spots" % len(items))
        return {"root": h["root"], "total": h["total"], "human": _fmt(h["total"]), "items": items}

    def t_disk_junk(self, safety="all", category=None, min_mb=20, limit=60):
        sc, err = self._need_scan()
        if err:
            return err
        floor = int(float(min_mb or 0) * MB)
        found = self.srv._cached(("junk", floor),
                                 lambda: junkmod.scan_junk(sc.root, sc.root_display, min_bytes=floor))
        real = [i for i in found if not i.get("container")]
        j = {"items": found, "cats": junkmod.summarize_junk(found),
             "reclaimable": sum(i["size"] for i in real if i["safety"] == junkmod.SAFE),
             "review": sum(i["size"] for i in real if i["safety"] == junkmod.REVIEW)}
        items = []
        for it in j["items"]:
            if it.get("container"):
                continue
            if safety != "all" and it["safety"] != safety:
                continue
            if category and it["cat"] != category:
                continue
            item = {k: it[k] for k in ("path", "size", "files", "cat", "safety", "label", "why", "how")}
            item["human"] = _fmt(it["size"])
            item["modified"] = _day(it["mtime"])
            items.append(item)
        items = items[:int(limit)]
        self._note("disk_junk", "%d items, %s reclaimable" % (len(items), _fmt(j["reclaimable"])))
        return {"root": sc.root_display, "reclaimable_safe": j["reclaimable"],
                "reclaimable_safe_human": _fmt(j["reclaimable"]), "review": j["review"],
                "review_human": _fmt(j["review"]),
                "categories": [dict(c, human=_fmt(c["size"])) for c in j["cats"]],
                "shown": len(items), "items": items}

    def t_disk_stale(self, months=12, min_gb=1, limit=40):
        sc, err = self._need_scan()
        if err:
            return err
        items = junkmod.stale_folders(sc.root, sc.root_display, months=int(months),
                                      min_bytes=int(float(min_gb) * GB), limit=int(limit))
        for it in items:
            it["human"] = _fmt(it["size"])
            if "mtime" in it:
                it["modified"] = _day(it["mtime"])
        self._note("disk_stale", "%d folders" % len(items))
        return {"months": int(months), "items": items}

    def t_disk_top_files(self, limit=30, ext=None):
        sc, err = self._need_scan()
        if err:
            return err
        items = self.srv.api_topfiles()["items"]
        if ext:
            want = ext.lower() if ext.startswith(".") else "." + ext.lower()
            items = [i for i in items if os.path.splitext(i["name"])[1].lower() == want]
        items = items[:int(limit)]
        for it in items:
            it["human"] = _fmt(it["size"])
        self._note("disk_top_files", "%d files" % len(items))
        return {"items": items}

    def t_disk_types(self, limit=20):
        sc, err = self._need_scan()
        if err:
            return err
        d = self.srv.api_exts()
        items = d["items"][:int(limit)]
        for it in items:
            it["human"] = _fmt(it["size"])
            it["share"] = round(100.0 * it["size"] / (d["total"] or 1), 1)
        self._note("disk_types", "%d categories" % len(items))
        return {"total": d["total"], "items": items}

    def t_disk_find(self, path=None, pattern=None, min_mb=0, older_than_days=0, limit=50,
                    max_entries=300000):
        if not path:
            sc = self.srv.ST.scanner
            if sc is None:
                return {"error": "Give a path, or scan first so the root can be used."}
            path = sc.root_display
        base = _norm(path)
        if not os.path.isdir(long_path(base)):
            return {"error": "Not a folder: %s" % base}
        pat = (pattern or "").lower() or None
        floor = float(min_mb or 0) * MB
        cutoff = time.time() - int(older_than_days or 0) * 86400 if older_than_days else None
        seen = 0
        hits = []
        stack = [long_path(base)]
        started = time.time()
        truncated = False
        while stack:
            cur = stack.pop()
            try:
                it = os.scandir(cur)
            except OSError:
                continue
            with it:
                for entry in it:
                    seen += 1
                    if seen > int(max_entries) or time.time() - started > 60:
                        truncated = True
                        break
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                            continue
                        if pat and not fnmatch.fnmatch(entry.name.lower(), pat):
                            continue
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if st.st_size < floor:
                        continue
                    if cutoff is not None and st.st_mtime > cutoff:
                        continue
                    hits.append((st.st_size, st.st_mtime, norm_display(entry.path)))
            if truncated:
                break
        hits.sort(reverse=True)
        items = [{"path": p, "name": os.path.basename(p), "size": s, "human": _fmt(s),
                  "modified": _day(m)} for s, m, p in hits[:int(limit)]]
        self._note("disk_find", "%d matches under %s" % (len(hits), base))
        return {"path": base, "matches": len(hits), "shown": len(items), "entries_seen": seen,
                "truncated": truncated, "total_matched_bytes": sum(h[0] for h in hits), "items": items}

    def t_disk_explain(self, path):
        p = _norm(path)
        stripped = p.rstrip("\\/")
        name = os.path.basename(stripped)
        exists = os.path.exists(long_path(p))
        out = {"path": p, "exists": exists, "kind": "folder" if os.path.isdir(long_path(p)) else "file"}
        if out["kind"] == "folder":
            rule = junkmod.match_rule(stripped, name)
            if rule is not None:
                out.update({"known": True, "label": rule["label"], "category": rule["cat"],
                            "safety": rule["safety"], "why": rule["why"], "how": rule["how"]})
            else:
                out.update({"known": False, "safety": "unknown",
                            "hint": "Not in the catalog: judge by contents (disk_dir) and age (disk_stale)."})
        else:
            note = junkmod.FILE_NOTES.get(name) or junkmod.EXT_NOTES.get(os.path.splitext(name)[1].lower())
            if note:
                out.update({"known": True, "why": note[0], "how": note[1],
                            "safety": junkmod.DANGER if name in junkmod.FILE_NOTES else junkmod.REVIEW})
            else:
                out.update({"known": False, "safety": "unknown"})
            if exists:
                try:
                    out["size"] = os.lstat(long_path(p)).st_size
                    out["human"] = _fmt(out["size"])
                except OSError:
                    pass
        sc = self.srv.ST.scanner
        if out["kind"] == "folder" and sc is not None and sc.done:
            chain = self.srv._find_chain(sc.root, sc.root_display, p)
            if chain:
                node = chain[-1]
                out.update({"size": node.size, "human": _fmt(node.size), "files": node.nfiles,
                            "modified": _day(node.mtime), "in_scan": True})
        reason = refuse_reason(p)
        out["agent_may_delete"] = reason is None
        if reason:
            out["refusal"] = reason
        self._note("disk_explain", p)
        return out

    def t_disk_script(self, paths):
        clean = [_norm(p) for p in paths]
        r = self.srv.api_script(clean)
        data_dir = self.srv.data_dir()
        os.makedirs(data_dir, exist_ok=True)
        fname = os.path.join(data_dir, "limpieza-%s.ps1" % time.strftime("%Y%m%d-%H%M%S"))
        with open(fname, "w", encoding="utf-8-sig", newline="") as fh:
            fh.write(r["script"])
        self._note("disk_script", "%d paths -> %s" % (len(clean), os.path.basename(fname)),
                   {"paths": clean})
        return {"saved_to": fname, "paths": clean, "script": r["script"],
                "run": "powershell -ExecutionPolicy Bypass -File \"%s\" -WhatIf   (then without -WhatIf)" % fname}

    def t_disk_delete(self, paths, mode="trash", confirm=False, timeout_s=600):
        if mode not in ("trash", "permanent"):
            return {"error": "mode must be 'trash' or 'permanent'"}
        if mode == "permanent" and not confirm:
            return {"error": "Permanent deletion needs confirm=true. Tell the user it cannot be undone."}
        clean, refused = [], []
        for p in paths:
            n = _norm(p)
            reason = refuse_reason(n)
            if reason:
                refused.append({"path": n, "reason": reason})
            elif not os.path.lexists(long_path(n)):
                refused.append({"path": n, "reason": "does not exist"})
            else:
                clean.append(n)
        if not clean:
            return {"error": "Nothing deletable in the list.", "refused": refused}
        if mode == "trash" and not IS_WIN:
            return {"error": "The Recycle Bin is only available on Windows; use mode='permanent' with confirm.",
                    "refused": refused}
        r = self.srv.api_delete(clean, "trash" if mode == "trash" else "perm")
        job = self.srv.ST.jobs[r["job"]]
        deadline = time.time() + max(5, min(1800, int(timeout_s)))
        while not job["finished"] and time.time() < deadline:
            time.sleep(0.15)
        summary = "%s %d paths, freed %s" % (mode, len(clean), _fmt(job["freed"]))
        self._note("disk_delete", summary, {"paths": clean, "mode": mode})
        out = {"job": r["job"], "finished": job["finished"], "mode": mode, "deleted": clean,
               "freed": job["freed"], "freed_human": _fmt(job["freed"]),
               "errors": job["errors"], "refused": refused}
        sc = self.srv.ST.scanner
        if sc is not None and sc.done:
            out["root_size_now"] = sc.root.size
            out["root_size_human"] = _fmt(sc.root.size)
        return out

    def t_disk_rescan(self, path=None):
        sc, err = self._need_scan()
        if err:
            return err
        r = self.srv.api_rescan(path or sc.root_display)
        if "error" in r:
            return r
        r["human"] = _fmt(r.get("size", 0))
        r["delta_human"] = ("-" if r.get("delta", 0) < 0 else "+") + _fmt(abs(r.get("delta", 0)))
        self._note("disk_rescan", "%s (%s)" % (path or sc.root_display, r["delta_human"]))
        return r
