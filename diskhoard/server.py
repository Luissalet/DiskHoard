# -*- coding: utf-8 -*-
"""Servidor local de DiskHoard. Solo libreria estandar."""
from __future__ import annotations

import json
import mimetypes
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

from . import __version__
from . import agent as agentmod
from . import junk as junkmod
from . import scanner as scanmod
from .hoard_link import family
from .winfs import (IS_WIN, delete_permanent, list_drives, long_path,
                    norm_display, send_to_trash)

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PORT = 8817
SERVICE = "disk-hoard"


def data_dir():
    """Carpeta de datos: token del puente MCP, scripts generados, url en uso."""
    return os.environ.get("DISKHOARD_DATA_DIR") or os.path.join(PKG_ROOT, "data")


def load_token():
    """Un token por instalacion, guardado en data/mcp-token para el puente MCP.

    La interfaz lo recibe en la URL como siempre; el puente lo lee del fichero.
    Si el fichero no existe se crea (solo legible por el usuario donde el SO
    lo permite).
    """
    path = os.path.join(data_dir(), "mcp-token")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            tok = fh.read().strip()
        if len(tok) >= 16:
            return tok
    except OSError:
        pass
    tok = secrets.token_urlsafe(24)
    os.makedirs(data_dir(), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(tok)
    return tok


TOKEN = load_token()


class State:
    def __init__(self):
        self.lock = threading.RLock()
        self.scanner = None
        self.cache = {}
        self.jobs = {}
        self.job_seq = 0
        self.port = 0
        self.started = time.time()


ST = State()
AGENT = agentmod.Agent(sys.modules[__name__])


# ------------------------------------------------------------------ arbol

def _find_chain(root, root_path, target):
    """Devuelve la lista de nodos desde la raiz hasta target (incluido)."""
    rp = norm_display(root_path).rstrip("\\/")
    tp = norm_display(target).rstrip("\\/")
    if tp.lower() == rp.lower():
        return [root]
    if not tp.lower().startswith(rp.lower() + os.sep):
        return None
    chain = [root]
    node = root
    for part in tp[len(rp) + 1:].split(os.sep):
        if not part or not node.children:
            return None
        nxt = node.children.get(part)
        if nxt is None:
            low = part.lower()
            nxt = next((v for k, v in node.children.items() if k.lower() == low), None)
        if nxt is None:
            return None
        chain.append(nxt)
        node = nxt
    return chain


def _detach(path):
    """Quita una ruta del arbol y descuenta su peso a los padres."""
    sc = ST.scanner
    if sc is None or not sc.done:
        return 0
    chain = _find_chain(sc.root, sc.root_display, path)
    if not chain or len(chain) < 2:
        return 0
    node = chain[-1]
    parent = chain[-2]
    name = os.path.basename(norm_display(path).rstrip("\\/"))
    if parent.children:
        for k in list(parent.children):
            if k.lower() == name.lower():
                del parent.children[k]
                break
    for anc in chain[:-1]:
        anc.size -= node.size
        anc.nfiles -= node.nfiles
    ST.cache.clear()
    return node.size


def _detach_file(path, size):
    sc = ST.scanner
    if sc is None or not sc.done:
        return
    parent_path = os.path.dirname(norm_display(path).rstrip("\\/"))
    chain = _find_chain(sc.root, sc.root_display, parent_path)
    if not chain:
        return
    chain[-1].own -= size
    chain[-1].nown -= 1
    for anc in chain:
        anc.size -= size
        anc.nfiles -= 1
    ST.cache.clear()


# --------------------------------------------------------------- endpoints

def api_drives():
    quick = []
    home = os.path.expanduser("~")
    for label, p in (("Perfil", home), ("Escritorio", os.path.join(home, "Desktop")),
                     ("Descargas", os.path.join(home, "Downloads")),
                     ("Documentos", os.path.join(home, "Documents")),
                     ("AppData", os.path.join(home, "AppData")),
                     ("Archivos de programa", os.environ.get("ProgramFiles", "")),
                     ("ProgramData", os.environ.get("ProgramData", ""))):
        if p and os.path.isdir(p):
            quick.append({"label": label, "path": p})
    return {"drives": list_drives(), "quick": quick, "home": home}


def api_scan(path):
    path = norm_display(path)
    if not os.path.isdir(long_path(path)):
        return {"error": "No existe la carpeta: %s" % path}
    with ST.lock:
        if ST.scanner is not None and not ST.scanner.done:
            ST.scanner.cancel()
        ST.cache.clear()
        sc = scanmod.Scanner(path)
        ST.scanner = sc
    sc.start()
    return {"ok": True, "root": sc.root_display}


def api_progress():
    sc = ST.scanner
    if sc is None:
        return {"idle": True}
    p = sc.progress()
    if p["done"] and not p["error"]:
        p["total"] = sc.root.size
        p["dirs_total"] = p["dirs"]
    return p


def _tag_for(path, name):
    rule = junkmod.match_rule(path, name)
    if rule is None:
        return None
    return {"label": rule["label"], "safety": rule["safety"],
            "why": rule["why"], "how": rule["how"], "cat": rule["cat"]}


def api_dir(path):
    sc = ST.scanner
    if sc is None or not sc.done:
        return {"error": "Todavia no hay un escaneo terminado."}
    path = norm_display(path or sc.root_display)
    chain = _find_chain(sc.root, sc.root_display, path)
    if chain is None:
        return {"error": "Esa carpeta esta fuera del escaneo actual (%s)." % sc.root_display}
    node = chain[-1]
    entries = []
    if node.children:
        for name, child in node.children.items():
            full = path.rstrip("\\/") + os.sep + name
            entries.append({
                "name": name, "path": full, "dir": True, "size": child.size,
                "files": child.nfiles, "mtime": child.mtime,
                "link": bool(child.flags & scanmod.FLAG_LINK),
                "err": bool(child.flags & scanmod.FLAG_ERROR),
                "tag": _tag_for(full, name),
            })
    # los ficheros se listan en vivo: es instantaneo y siempre esta al dia
    try:
        with os.scandir(long_path(path)) as it:
            for entry in it:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        continue
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                note = junkmod.FILE_NOTES.get(entry.name)
                entries.append({
                    "name": entry.name, "path": norm_display(entry.path), "dir": False,
                    "size": st.st_size, "files": 0, "mtime": st.st_mtime,
                    "link": False, "err": False,
                    "tag": ({"label": entry.name, "safety": junkmod.DANGER,
                             "why": note[0], "how": note[1], "cat": "Sistema"}
                            if note else None),
                })
    except OSError as exc:
        pass
    entries.sort(key=lambda e: -e["size"])
    crumbs = []
    base = norm_display(sc.root_display).rstrip("\\/")
    acc = base
    crumbs.append({"name": base, "path": base})
    rest = path.rstrip("\\/")[len(base):].strip(os.sep)
    if rest:
        for part in rest.split(os.sep):
            acc = acc + os.sep + part
            crumbs.append({"name": part, "path": acc})
    parent = crumbs[-2]["path"] if len(crumbs) > 1 else None
    return {"path": path, "parent": parent, "crumbs": crumbs, "entries": entries,
            "size": node.size, "files": node.nfiles, "own": node.own,
            "root": sc.root_display, "root_size": sc.root.size,
            "err": bool(node.flags & scanmod.FLAG_ERROR)}


def _cached(key, fn):
    with ST.lock:
        if key in ST.cache:
            return ST.cache[key]
    val = fn()
    with ST.lock:
        ST.cache[key] = val
    return val


def api_rescan(path):
    """Vuelve a escanear solo una subcarpeta y la empalma en el arbol."""
    sc = ST.scanner
    if sc is None or not sc.done:
        return {"error": "Todavia no hay un escaneo terminado."}
    path = norm_display(path or sc.root_display)
    chain = _find_chain(sc.root, sc.root_display, path)
    if chain is None:
        return {"error": "Esa carpeta esta fuera del escaneo actual."}
    if not os.path.isdir(long_path(path)):
        # ha desaparecido: la quitamos del arbol y listo
        _detach(path)
        return {"ok": True, "gone": True, "root_size": sc.root.size}

    sub = scanmod.Scanner(path)
    sub.start()
    while not sub.done:
        time.sleep(0.12)
    if sub.error:
        return {"error": sub.error}

    old, new = chain[-1], sub.root
    new.name = old.name
    if len(chain) >= 2:
        parent = chain[-2]
        name = os.path.basename(path.rstrip("\\/"))
        if parent.children:
            for k in list(parent.children):
                if k.lower() == name.lower():
                    parent.children[k] = new
                    break
    else:
        sc.root = new
    dsize = new.size - old.size
    dfiles = new.nfiles - old.nfiles
    for anc in chain[:-1]:
        anc.size += dsize
        anc.nfiles += dfiles
    ST.cache.clear()
    return {"ok": True, "size": new.size, "files": new.nfiles, "delta": dsize,
            "root_size": sc.root.size, "elapsed": sub.finished - sub.started}


def api_hotspots():
    sc = ST.scanner
    if sc is None or not sc.done:
        return {"error": "Sin escaneo"}
    items = _cached("hot", lambda: junkmod.hotspots(sc.root, sc.root_display))
    return {"items": items, "total": sc.root.size, "root": sc.root_display}


def api_junk():
    sc = ST.scanner
    if sc is None or not sc.done:
        return {"error": "Sin escaneo"}
    items = _cached("junk", lambda: junkmod.scan_junk(sc.root, sc.root_display))
    real = [i for i in items if not i.get("container")]
    return {"items": items, "cats": junkmod.summarize_junk(items),
            "total": sc.root.size,
            "reclaimable": sum(i["size"] for i in real if i["safety"] == junkmod.SAFE),
            "review": sum(i["size"] for i in real if i["safety"] == junkmod.REVIEW)}


def api_stale():
    sc = ST.scanner
    if sc is None or not sc.done:
        return {"error": "Sin escaneo"}
    return {"items": _cached("stale", lambda: junkmod.stale_folders(sc.root, sc.root_display))}


def api_topfiles():
    sc = ST.scanner
    if sc is None or not sc.done:
        return {"error": "Sin escaneo"}
    out = []
    for size, p in sorted(sc.top_files, reverse=True):
        name = os.path.basename(p)
        note = junkmod.FILE_NOTES.get(name)
        sysfile = note is not None
        if note is None:
            note = junkmod.EXT_NOTES.get(os.path.splitext(name)[1].lower())
        out.append({"path": norm_display(p), "size": size, "name": name, "sys": sysfile,
                    "why": note[0] if note else "", "how": note[1] if note else ""})
    return {"items": out}


def api_exts():
    sc = ST.scanner
    if sc is None or not sc.done:
        return {"error": "Sin escaneo"}
    cats = {}
    for ext, (count, size) in sc.ext_stats.items():
        cat = scanmod.ext_category(ext)
        c = cats.setdefault(cat, {"cat": cat, "size": 0, "count": 0, "exts": {}})
        c["size"] += size
        c["count"] += count
        c["exts"][ext or "(sin extension)"] = c["exts"].get(ext or "(sin extension)", 0) + size
    out = []
    for c in cats.values():
        top = sorted(c["exts"].items(), key=lambda kv: -kv[1])[:8]
        out.append({"cat": c["cat"], "size": c["size"], "count": c["count"],
                    "top": [{"ext": e, "size": s} for e, s in top]})
    out.sort(key=lambda d: -d["size"])
    return {"items": out, "total": sc.root.size if sc.root else 0}


# ------------------------------------------------------------------ borrado

def api_delete(paths, mode):
    with ST.lock:
        ST.job_seq += 1
        jid = str(ST.job_seq)
        job = {"id": jid, "total": len(paths), "done": 0, "freed": 0,
               "errors": [], "current": "", "finished": False, "mode": mode}
        ST.jobs[jid] = job

    def run():
        for p in paths:
            job["current"] = p
            try:
                sz = 0
                is_dir = os.path.isdir(long_path(p))
                if not is_dir:
                    try:
                        sz = os.lstat(long_path(p)).st_size
                    except OSError:
                        sz = 0
                if mode == "trash":
                    ok, err = send_to_trash([p])
                    if not ok:
                        job["errors"].append("%s: %s" % (p, err))
                    else:
                        if is_dir:
                            job["freed"] += _detach(p)
                        else:
                            _detach_file(p, sz)
                            job["freed"] += sz
                else:
                    freed, nf, errs = delete_permanent(p)
                    job["errors"].extend(errs[:20])
                    if is_dir:
                        _detach(p)
                    else:
                        _detach_file(p, sz)
                    job["freed"] += freed
            except Exception as exc:  # noqa: BLE001
                job["errors"].append("%s: %s" % (p, exc))
            job["done"] += 1
        job["current"] = ""
        job["finished"] = True

    threading.Thread(target=run, daemon=True).start()
    return {"job": jid}


def api_job(jid):
    return ST.jobs.get(jid, {"error": "job desconocido"})


def api_script(paths):
    lines = [
        "# Script de limpieza generado por DiskHoard",
        "# Fecha: %s" % time.strftime("%Y-%m-%d %H:%M"),
        "#",
        "# REVISA la lista antes de ejecutar. Nada se borra hasta que tu lo lances.",
        "# 1) Ejecuta primero en modo simulacion:   .\\limpieza.ps1 -WhatIf",
        "# 2) Si te convence:                       .\\limpieza.ps1",
        "#",
        "[CmdletBinding(SupportsShouldProcess=$true)]",
        "param()",
        "",
        "$total = 0",
        "function Remove-Target($p) {",
        "    if (-not (Test-Path -LiteralPath $p)) { Write-Host \"  (ya no existe) $p\"; return }",
        "    $size = (Get-ChildItem -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue |",
        "             Measure-Object -Property Length -Sum).Sum",
        "    if (-not $size) { $size = 0 }",
        "    Write-Host (\"  {0,10:N2} GB  {1}\" -f ($size/1GB), $p)",
        "    if ($PSCmdlet.ShouldProcess($p, 'Borrar')) {",
        "        Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Continue",
        "        $script:total += $size",
        "    }",
        "}",
        "",
    ]
    for p in paths:
        lines.append("Remove-Target '%s'" % p.replace("'", "''"))
    lines += ["", "Write-Host ''",
              "Write-Host (\"Liberado: {0:N2} GB\" -f ($total/1GB)) -ForegroundColor Green"]
    return {"script": "\r\n".join(lines)}


def api_open(path):
    try:
        if IS_WIN:
            if os.path.isdir(path):
                subprocess.Popen(["explorer", path])
            else:
                subprocess.Popen(["explorer", "/select,", path])
        return {"ok": True}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


# -------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "DiskHoard"

    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _auth(self, qs):
        """The UI sends ?t= or X-DH-Token; the family (hub proxy, MCP bridge) sends Authorization: Bearer."""
        auth = self.headers.get("Authorization") or ""
        bearer = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        tok = self.headers.get("X-DH-Token") or bearer or (qs.get("t", [""])[0])
        return tok == TOKEN

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        p = u.path
        if p == "/api/health":
            return self._json(api_health())
        if p == "/api/agent/tools":
            # The catalogue is public in every family app (the hub and the workspace list it
            # before they hold a token); calling a tool still needs the token.
            return self._json({"tools": agentmod.CATALOG, "instructions": agentmod.INSTRUCTIONS,
                               "service": SERVICE, "version": __version__})
        if p.startswith("/api/"):
            if not self._auth(qs):
                return self._json({"error": "token invalido"}, 403)
            return self._api_get(p, qs)
        if p in ("/", "/index.html"):
            return self._file(os.path.join(WEB_DIR, "index.html"))
        safe = os.path.normpath(p.lstrip("/")).replace("..", "")
        return self._file(os.path.join(WEB_DIR, safe))

    def _api_get(self, p, qs):
        one = lambda k, d="": qs.get(k, [d])[0]
        if p == "/api/drives":
            return self._json(api_drives())
        if p == "/api/progress":
            return self._json(api_progress())
        if p == "/api/dir":
            return self._json(api_dir(unquote(one("path"))))
        if p == "/api/hotspots":
            return self._json(api_hotspots())
        if p == "/api/junk":
            return self._json(api_junk())
        if p == "/api/stale":
            return self._json(api_stale())
        if p == "/api/topfiles":
            return self._json(api_topfiles())
        if p == "/api/exts":
            return self._json(api_exts())
        if p == "/api/job":
            return self._json(api_job(one("id")))
        if p == "/api/agent/tools":
            return self._json({"tools": agentmod.CATALOG, "instructions": agentmod.INSTRUCTIONS,
                               "service": SERVICE, "version": __version__})
        if p == "/api/agent/log":
            return self._json(AGENT.recent(int(one("since", "0") or 0)))
        return self._json({"error": "endpoint desconocido"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if not self._auth(qs):
            return self._json({"error": "token invalido"}, 403)
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        except Exception:
            body = {}
        p = u.path
        if p == "/api/scan":
            return self._json(api_scan(body.get("path", "")))
        if p == "/api/rescan":
            return self._json(api_rescan(body.get("path", "")))
        if p == "/api/cancel":
            if ST.scanner:
                ST.scanner.cancel()
            return self._json({"ok": True})
        if p == "/api/delete":
            return self._json(api_delete(body.get("paths", []),
                                         body.get("mode", "trash")))
        if p == "/api/script":
            return self._json(api_script(body.get("paths", [])))
        if p == "/api/open":
            return self._json(api_open(body.get("path", "")))
        if p == "/api/quit":
            threading.Timer(0.4, lambda: os._exit(0)).start()
            return self._json({"ok": True})
        if p == "/api/agent/call":
            name = body.get("name", "")
            t0 = time.time()
            out, is_err = AGENT.call(name, body.get("arguments") or {})
            family.record_call(name, not is_err, int((time.time() - t0) * 1000), caller=str(body.get("caller") or ""),
                               error=str((out or {}).get("error") or "") if is_err else "")
            return self._json(out, 400 if is_err else 200)
        return self._json({"error": "endpoint desconocido"}, 404)

    def _file(self, path):
        if not os.path.isfile(path):
            self.send_error(404)
            return
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        with open(path, "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def api_health():
    """Sin token: es lo que Faustus y el puente MCP consultan para saber si estamos."""
    sc = ST.scanner
    scan = None
    if sc is not None:
        scan = {"root": sc.root_display, "done": sc.done, "error": sc.error or None,
                "size": sc.root.size if sc.done and not sc.error else None}
    return {"service": SERVICE, "name": "DiskHoard", "version": __version__,
            "status": "healthy", "port": ST.port, "uptime_s": round(time.time() - ST.started),
            "scan": scan, "agent_calls": AGENT.seq, "tools": len(agentmod.CATALOG),
            "hoard_link": family.health_block()}


def free_port(start=DEFAULT_PORT, span=60):
    for port in range(start, start + span):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return 0


def _parse_args(argv):
    opts = {"browser": True, "port": 0, "host": "127.0.0.1"}
    it = iter(argv)
    for a in it:
        if a == "--no-browser":
            opts["browser"] = False
        elif a == "--port":
            opts["port"] = int(next(it, "0") or 0)
        elif a.startswith("--port="):
            opts["port"] = int(a.split("=", 1)[1] or 0)
        elif a in ("-h", "--help"):
            print("uso: python -m diskhoard [--port N] [--no-browser]\n"
                  "     DISKHOARD_PORT y DISKHOARD_DATA_DIR tambien valen como variables de entorno.")
            raise SystemExit(0)
    if not opts["port"]:
        opts["port"] = int(os.environ.get("DISKHOARD_PORT") or 0) or None
    return opts


def serve(port=None, open_browser=False):
    """Arranca el servidor y devuelve (servidor, url).

    port=None: el 8817 o el primero libre a partir de el. port=0: uno
    cualquiera que elija el sistema (tests). Otro valor: ese o error.
    """
    if port is None:
        port = free_port()
        if not port:
            raise OSError("No hay puertos libres a partir del %d" % DEFAULT_PORT)
    family.configure("diskhoard", data_dir(), token_file=os.path.join(data_dir(), "mcp-token"))
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    ST.port = srv.server_address[1]
    base = "http://127.0.0.1:%d" % ST.port
    try:
        os.makedirs(data_dir(), exist_ok=True)
        with open(os.path.join(data_dir(), "url"), "w", encoding="utf-8") as fh:
            fh.write(base)
    except OSError:
        pass
    url = "%s/?t=%s" % (base, TOKEN)
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    return srv, url


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    opts = _parse_args(argv)
    try:
        srv, url = serve(opts["port"], open_browser=opts["browser"])
    except OSError as exc:
        print("No se puede escuchar: %s" % exc)
        return 1
    print("", flush=True)
    print("  DiskHoard %s escuchando en %s" % (__version__, url), flush=True)
    print("  Puente MCP: python mcp_server.py  (token en %s)" % os.path.join(data_dir(), "mcp-token"),
          flush=True)
    print("  Deja esta ventana abierta. Ctrl+C para salir.", flush=True)
    print("", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
