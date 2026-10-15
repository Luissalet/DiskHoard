# -*- coding: utf-8 -*-
"""Servidor local de DiskHoard. Solo libreria estandar."""
from __future__ import annotations

import hmac
import json
import mimetypes
import os
import socket
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

from . import __version__
from . import agent as agentmod
from . import junk as junkmod
from . import ollama_backups
from . import scanner as scanmod
from . import zipsplit
from .hoard_link import family
from .hoard_link.copilot_stdlib import CopilotRelay
from .hoard_link.atomic import write_text_atomic
from .hoard_link.guard import check_request, parse_allowed_hosts
from .hoard_link.proc import reveal_in_file_manager
from .hoard_link.tokens import read_or_create_token
from .winfs import (delete_permanent, list_drives, long_path,
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
    return read_or_create_token(os.path.join(data_dir(), "mcp-token"), min_len=16)


TOKEN = load_token()


class State:
    def __init__(self):
        self.lock = threading.RLock()
        self.scanner = None
        self.cache = {}
        self.jobs = {}
        self.job_seq = 0
        self.proposals = {}   # ruta (minusculas) -> lo que se le dijo al usuario: size/files/mtime
        self.port = 0
        self.started = time.time()


ST = State()
AGENT = agentmod.Agent(sys.modules[__name__])


# ---------------------------------------------------- lo que se propone borrar

MAX_PROPOSALS = 20000


def _pkey(path):
    return norm_display(path).rstrip("\\/").lower()


def note_proposal(path, size, mtime=None, files=1):
    """Apunta lo que el escaneo (o un listado en vivo) dijo de un fichero que se
    va a proponer para borrar. Sirve de referencia al re-medir antes de borrar
    (los ficheros sueltos no estan en el arbol). Un dato con fecha no se
    machaca con uno sin fecha."""
    key = _pkey(path)
    with ST.lock:
        cur = ST.proposals.get(key)
        if cur is not None and cur.get("mtime") is not None and mtime is None:
            return
        if len(ST.proposals) >= MAX_PROPOSALS and key not in ST.proposals:
            ST.proposals.pop(next(iter(ST.proposals)))
        ST.proposals[key] = {"size": int(size), "files": files, "mtime": mtime}


def note_proposals(items):
    """Ficheros de una lista de basura (los directorios ya estan en el arbol)."""
    for it in items:
        if it.get("file"):
            note_proposal(it["path"], it["size"], it.get("mtime"))


def _drop_proposals(path):
    key = _pkey(path)
    with ST.lock:
        for k in [k for k in ST.proposals if k == key or k.startswith(key + os.sep)]:
            del ST.proposals[k]


def baseline_for(path, is_dir, expected=None):
    """(referencia, origen) de lo que se esperaba encontrar en esta ruta.

    Orden: lo que el cliente diga explicitamente, el nodo del escaneo (carpetas)
    y lo apuntado al proponerla (ficheros). (None, None) si no hay referencia.
    """
    if expected:
        want = _pkey(path)
        for k, v in expected.items():
            if isinstance(v, dict) and _pkey(k) == want:
                return {x: v.get(x) for x in ("size", "files", "mtime")}, "given"
    sc = ST.scanner
    if is_dir and sc is not None and sc.done and not sc.error:
        chain = _find_chain(sc.root, sc.root_display, path)
        if chain:
            node = chain[-1]
            return {"size": node.size, "files": node.nfiles, "mtime": node.mtime}, "scan"
    with ST.lock:
        prop = ST.proposals.get(_pkey(path))
    if prop is not None:
        return dict(prop), "proposal"
    return None, None


# ------------------------------------------------------------- instantanea

def snapshot_path():
    return os.path.join(data_dir(), "last-scan.pkl.gz")


def _save_snapshot_async(sc):
    """Guarda el escaneo en data/ sin bloquear a quien llama (un disco
    entero son cientos de miles de carpetas)."""
    def run():
        try:
            if ST.scanner is sc:
                scanmod.save_snapshot(sc, snapshot_path())
        except Exception:  # noqa: BLE001 - sin instantanea solo se pierde la comodidad
            pass
    threading.Thread(target=run, name="dh-snapshot", daemon=True).start()


def restore_snapshot():
    """Al arrancar: el ultimo escaneo guardado pasa a ser el actual, salvo
    que alguien haya lanzado ya uno nuevo."""
    sc = scanmod.load_snapshot(snapshot_path())
    if sc is None:
        return False
    with ST.lock:
        if ST.scanner is not None:
            return False
        ST.scanner = sc
        ST.cache.clear()
    return True


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
    _drop_proposals(path)
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
    _save_snapshot_async(sc)
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
    _save_snapshot_async(sc)


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
        ST.proposals.clear()
        sc = scanmod.Scanner(path)
        sc.on_done = _save_snapshot_async
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
    prot = junkmod.protected_reason(path)
    if prot:
        return junkmod.protected_tag(prot)
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
                fpath = norm_display(entry.path)
                prot = junkmod.protected_reason(fpath)
                frule = None if (note or prot) else junkmod.match_file_rule(fpath, entry.name)
                if prot:
                    tag = junkmod.protected_tag(prot)
                elif note:
                    tag = {"label": entry.name, "safety": junkmod.DANGER,
                           "why": note[0], "how": note[1], "cat": "Sistema"}
                elif frule:
                    tag = junkmod.file_tag(frule)
                else:
                    tag = None
                entries.append({
                    "name": entry.name, "path": fpath, "dir": False,
                    "size": st.st_size, "files": 0, "mtime": st.st_mtime,
                    "link": False, "err": False, "tag": tag,
                })
    except OSError as exc:
        pass
    entries.sort(key=lambda e: -e["size"])
    for e in [e for e in entries if not e["dir"]][:300]:
        note_proposal(e["path"], e["size"], e["mtime"])
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
    _drop_proposals(path)
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
    note_proposals(items)
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
        note_proposal(p, size)
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

def _diff_fields(expected, now, is_dir):
    out = []
    for key in ("size", "files", "mtime"):
        if expected.get(key) is None or (key == "files" and not is_dir):
            continue
        if key == "mtime":
            if abs(float(expected[key]) - float(now[key])) > 0.002:
                out.append(key)
        elif int(expected[key]) != int(now[key]):
            out.append(key)
    return out


def api_delete(paths, mode, expected=None, force=False):
    """Borra en segundo plano. Antes de tocar cada elemento lo vuelve a medir
    (bytes, ficheros, fecha mas reciente) y lo compara con lo que se propuso;
    si no cuadra no lo borra: queda en job["changed"] con la pista "rescan".
    force=True se salta esa comprobacion (solo si el usuario insiste).

    El resultado separa lo esperado (lo que decia el escaneo) de lo liberado
    (medido): en la papelera el espacio del disco no sube hasta vaciarla."""
    with ST.lock:
        ST.job_seq += 1
        jid = str(ST.job_seq)
        job = {"id": jid, "total": len(paths), "done": 0, "freed": 0,
               "errors": [], "current": "", "finished": False, "mode": mode,
               "force": bool(force), "changed": [], "items": [],
               "expected_bytes": 0, "freed_bytes": 0, "diff_bytes": 0,
               "freed_on_disk_bytes": 0, "binned_bytes": 0, "skipped_bytes": 0}
        ST.jobs[jid] = job
    trash = mode == "trash"

    def run():
        for p in paths:
            job["current"] = p
            item = {"path": p, "status": "", "expected_bytes": None, "freed_bytes": 0, "verified": False}
            try:
                is_dir = os.path.isdir(long_path(p))
                base, source = baseline_for(p, is_dir, expected)
                # con force y borrado definitivo no hace falta medir: delete_permanent ya cuenta los bytes
                skip_measure = bool(force) and not trash
                live = None if skip_measure else scanmod.fingerprint(p)
                if live is None and not skip_measure:
                    item["status"] = "changed"
                    job["changed"].append({"path": p, "reason": "missing", "expected": base, "now": None,
                                           "hint": "rescan"})
                    if base:
                        job["skipped_bytes"] += int(base.get("size") or 0)
                    job["items"].append(item)
                    job["done"] += 1
                    continue
                if base is not None and not force:
                    item["verified"] = True
                    if not scanmod.same_fingerprint(base, live, is_dir):
                        item["status"] = "changed"
                        job["changed"].append({"path": p, "reason": "changed since the scan",
                                               "fields": _diff_fields(base, live, is_dir),
                                               "expected": base, "now": live, "hint": "rescan"})
                        job["skipped_bytes"] += int(base.get("size") or 0)
                        job["items"].append(item)
                        job["done"] += 1
                        continue
                if base is not None:
                    item["expected_bytes"] = int(base.get("size") or 0)
                elif live is not None:
                    item["expected_bytes"] = int(live["size"])
                item["expected_source"] = source or "live"
                sz = live["size"] if live is not None else 0
                if trash:
                    ok, err = send_to_trash([p])
                    if not ok:
                        job["errors"].append("%s: %s" % (p, err))
                        item["status"] = "error"
                        item["freed_bytes"] = 0
                    else:
                        item["status"] = "deleted"
                        item["freed_bytes"] = sz
                        job["binned_bytes"] += sz
                else:
                    freed, nf, errs = delete_permanent(p)
                    job["errors"].extend(errs[:20])
                    item["freed_bytes"] = freed
                    job["freed_on_disk_bytes"] += freed
                    item["status"] = "partial" if os.path.lexists(long_path(p)) else "deleted"
                    if item["status"] == "partial" and not errs:
                        job["errors"].append("%s: sigue existiendo" % p)
                if item["status"] == "deleted":
                    if is_dir:
                        _detach(p)
                    else:
                        _detach_file(p, sz)
                elif item["status"] == "partial" and is_dir:
                    try:
                        api_rescan(p)  # el arbol refleja lo que queda de verdad
                    except Exception:  # noqa: BLE001
                        pass
                job["freed"] += item["freed_bytes"]
                job["freed_bytes"] += item["freed_bytes"]
                job["expected_bytes"] += item["expected_bytes"] or 0
            except Exception as exc:  # noqa: BLE001
                job["errors"].append("%s: %s" % (p, exc))
                item["status"] = item["status"] or "error"
            job["items"].append(item)
            job["done"] += 1
        job["diff_bytes"] = job["freed_bytes"] - job["expected_bytes"]
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
    """Muestra el fichero (seleccionado) o la carpeta en el explorador del sistema (Hoard Link)."""
    try:
        if reveal_in_file_manager(path):
            return {"ok": True}
        return {"error": "No se pudo abrir el explorador en esa ruta."}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


# --------------------------------------------------------------- partir en ZIPs

def api_zip_plan(body):
    """Plan en seco: nada se escribe."""
    try:
        o = zipsplit.options_from(body)
        return zipsplit.plan(o, confirm=bool(body.get("confirm")), files=bool(body.get("files")))
    except zipsplit.ZipSplitError as exc:
        return {"error": str(exc)}


def api_zip_split(body):
    """Lanza el trabajo en segundo plano; el estado sale de api_zip_job."""
    try:
        o = zipsplit.options_from(body)
        job = zipsplit.REGISTRY.start(o, confirm=bool(body.get("confirm")))
    except zipsplit.ZipSplitError as exc:
        return {"error": str(exc)}
    return {"ok": True, "job": job.id, "out_dir": job.opts.out_dir}


def api_zip_job(jid=None):
    job = zipsplit.REGISTRY.get(jid)
    if job is None:
        return {"error": "No hay ningún trabajo de ZIP" + (" con ese id." if jid else ".")}
    return job.snapshot()


def api_zip_cancel(jid=None):
    job = zipsplit.REGISTRY.get(jid)
    if job is None:
        return {"error": "No hay ningún trabajo de ZIP que cancelar."}
    job.cancel()
    return {"ok": True, "job": job.id, "was_running": job.running}


# --------------------------------------------------------- copias de Ollama

def api_ollama_backups(models_dir=None):
    """Solo lectura: copias de la migracion, huerfanos y su estado."""
    return ollama_backups.scan(models_dir or None)


def api_ollama_free(body):
    """Simulacro por defecto; borrar de verdad exige dry_run=false y confirm=true."""
    return ollama_backups.free(body.get("dir") or None, ids=body.get("ids"),
                               dry_run=body.get("dry_run", True) is not False, confirm=bool(body.get("confirm")),
                               mode=body.get("mode") or "trash", data_dir=data_dir(), caller="ui")


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
        return hmac.compare_digest(tok.encode("utf-8"), TOKEN.encode("utf-8"))

    def _blocked(self, method):
        """The shared Host / Origin / Fetch Metadata rules (DNS rebinding, cross-site pages). True when the
        request was refused and answered. DISKHOARD_ALLOWED_HOSTS opens a LAN name on purpose."""
        verdict = check_request(method, {k.lower(): v for k, v in self.headers.items()}, ST.port,
                                parse_allowed_hosts(os.environ.get("DISKHOARD_ALLOWED_HOSTS")), strict_ports=True)
        if verdict is None:
            return False
        self._json({"error": verdict[1]}, verdict[0])
        return True

    def do_GET(self):
        if self._blocked("GET"):
            return
        if self.server.copilot.handle(self):
            return
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
        if p == "/api/ollama/backups":
            return self._json(api_ollama_backups(unquote(one("dir"))))
        if p == "/api/ollama/audit":
            return self._json({"items": ollama_backups.read_audit(data_dir(), int(one("limit", "30") or 30))})
        if p == "/api/zip/job":
            out = api_zip_job(one("id") or None)
            return self._json(out, 404 if "error" in out else 200)
        if p == "/api/agent/tools":
            return self._json({"tools": agentmod.CATALOG, "instructions": agentmod.INSTRUCTIONS,
                               "service": SERVICE, "version": __version__})
        if p == "/api/agent/log":
            return self._json(AGENT.recent(int(one("since", "0") or 0)))
        return self._json({"error": "endpoint desconocido"}, 404)

    def do_POST(self):
        if self._blocked("POST"):
            return
        if self.server.copilot.handle(self):
            return
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
        if p == "/api/pick-folder":
            return self._json(api_pick_folder(body.get("initial", ""), body.get("title", "")))
        if p == "/api/scan":
            return self._json(api_scan(body.get("path", "")))
        if p == "/api/rescan":
            return self._json(api_rescan(body.get("path", "")))
        if p == "/api/cancel":
            if ST.scanner:
                ST.scanner.cancel()
            return self._json({"ok": True})
        if p == "/api/delete":
            return self._json(api_delete(body.get("paths", []), body.get("mode", "trash"),
                                         expected=body.get("expected") or None,
                                         force=bool(body.get("force"))))
        if p == "/api/script":
            return self._json(api_script(body.get("paths", [])))
        if p == "/api/open":
            return self._json(api_open(body.get("path", "")))
        if p in ("/api/zip/plan", "/api/zip/split", "/api/zip/cancel"):
            if p == "/api/zip/plan":
                out = api_zip_plan(body)
            elif p == "/api/zip/split":
                out = api_zip_split(body)
            else:
                out = api_zip_cancel(body.get("id") or body.get("job") or None)
            return self._json(out, 400 if "error" in out else 200)
        if p == "/api/ollama/free":
            out = api_ollama_free(body)
            if out.get("error"):
                AGENT._note("ollama_free", "refused: %s" % out["error"][:90])
            else:
                AGENT._note("ollama_free", "%s: %d items, %s" % (
                    "dry run" if out["dry_run"] else "freed", len(out["planned"] if out["dry_run"] else out["done"]),
                    out["planned_human"] if out["dry_run"] else out["freed_human"]))
            return self._json(out, 400 if out.get("error") else 200)
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
        if ctype.startswith("text/html"):
            # The page only reaches here after _blocked() (Host / Origin / Fetch Metadata), so a
            # same-origin tab opened without ?t= (hub link, bookmark, typed URL) still gets the token.
            data = data.replace(b'<meta charset="utf-8">',
                                b'<meta charset="utf-8">\n<meta name="dh-token" content="' + TOKEN.encode("ascii") + b'">', 1)
            data = self.server.copilot.inject_html(data)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)



# Native folder picker: the Windows "select folder" dialog, run in its own pythonw process so Tk
# never shares a thread with the HTTP server. Topmost so it opens over the browser.
_PICKER_SRC = r"""
import sys, tkinter as tk
from tkinter import filedialog
root = tk.Tk()
root.withdraw()
try:
    root.attributes("-topmost", True)
except Exception:
    pass
root.update()
path = filedialog.askdirectory(parent=root, initialdir=sys.argv[2] or None,
                               title=sys.argv[3], mustexist=True)
root.destroy()
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    fh.write(path or "")
"""
_PICK_LOCK = threading.Lock()


def api_pick_folder(initial="", title=""):
    import subprocess
    import tempfile
    if not _PICK_LOCK.acquire(blocking=False):
        return {"error": "Ya hay un selector de carpetas abierto."}
    out = None
    try:
        init = initial if initial and os.path.isdir(initial) else ""
        fd, out = tempfile.mkstemp(prefix="dh-pick-", suffix=".txt")
        os.close(fd)
        exe = sys.executable
        windowed = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.isfile(windowed):
            exe = windowed
        try:
            subprocess.run([exe, "-c", _PICKER_SRC, out, init, title or "Elige una carpeta"],
                           timeout=900, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired:
            return {"error": "El selector de carpetas se cerro por tiempo."}
        with open(out, encoding="utf-8") as fh:
            path = fh.read().strip()
        if not path:
            return {"cancelled": True}
        return {"path": os.path.normpath(path)}
    finally:
        if out and os.path.exists(out):
            try:
                os.remove(out)
            except OSError:
                pass
        _PICK_LOCK.release()


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
    srv.copilot = CopilotRelay("diskhoard", data_dir(), app_name="DiskHoard")
    srv.daemon_threads = True
    ST.port = srv.server_address[1]
    base = "http://127.0.0.1:%d" % ST.port
    try:
        write_text_atomic(os.path.join(data_dir(), "url"), base)
    except OSError:
        pass
    url = "%s/?t=%s" % (base, TOKEN)
    if os.environ.get("DISKHOARD_RESTORE", "1") != "0":
        threading.Thread(target=restore_snapshot, name="dh-restore", daemon=True).start()
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
