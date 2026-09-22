# -*- coding: utf-8 -*-
"""Puente MCP (stdio) de DiskHoard. Solo libreria estandar, como todo lo demas.

Habla JSON-RPC 2.0 por lineas (una peticion por linea, una respuesta por
linea) tal como pide el transporte stdio de MCP, y reenvia cada llamada a la
app que ya corre en 127.0.0.1 (`POST /api/agent/call`) con el token de
`data/mcp-token`. La lista de herramientas sale del propio paquete
(`diskhoard.agent.CATALOG`): puente y app son el mismo codigo en disco.

Si la app no esta arrancada, el puente la lanza (`python -m diskhoard
--no-browser`) y espera a que conteste. `DISKHOARD_AUTOSTART=0` lo desactiva.

Variables de entorno:
  DISKHOARD_URL         http://127.0.0.1:8817 (o lo que diga data/url)
  DISKHOARD_TOKEN_FILE  ruta al token (por defecto <repo>/data/mcp-token)
  DISKHOARD_DATA_DIR    carpeta de datos, la misma que use la app
  DISKHOARD_AUTOSTART   1 (por defecto) para arrancar la app si no esta
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from diskhoard import __version__  # noqa: E402
from diskhoard import agent as agentmod  # noqa: E402

PROTOCOL_FALLBACK = "2025-03-26"
NOT_RUNNING = ("DiskHoard is not running and could not be started. Launch DiskHoard.bat "
               "(or `python -m diskhoard --no-browser`) and try again.")


def data_dir():
    return os.environ.get("DISKHOARD_DATA_DIR") or os.path.join(ROOT, "data")


def base_url():
    url = os.environ.get("DISKHOARD_URL", "").strip()
    if not url:
        try:
            with open(os.path.join(data_dir(), "url"), "r", encoding="utf-8") as fh:
                url = fh.read().strip()
        except OSError:
            url = ""
    url = (url or "http://127.0.0.1:8817").rstrip("/")
    host = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("The MCP bridge only talks to the local DiskHoard (got %s)." % url)
    return url


def token():
    env = os.environ.get("DISKHOARD_TOKEN", "").strip()
    if env:
        return env
    path = os.environ.get("DISKHOARD_TOKEN_FILE") or os.path.join(data_dir(), "mcp-token")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().strip()


def _http(method, path, body=None, timeout=900):
    url = base_url() + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if path != "/api/health":
        req.add_header("X-DH-Token", token())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8") or "{}")
        except Exception:  # noqa: BLE001
            return exc.code, {"error": "HTTP %d" % exc.code}


def alive():
    try:
        code, body = _http("GET", "/api/health", timeout=3)
        return code == 200 and body.get("service") == "disk-hoard"
    except Exception:  # noqa: BLE001
        return False


def autostart():
    """Lanza la app en segundo plano, separada del puente, y espera al health."""
    if os.environ.get("DISKHOARD_AUTOSTART", "1") in ("0", "false", "no"):
        return False
    port = base_url().rsplit(":", 1)[-1]
    env = dict(os.environ)
    env.setdefault("DISKHOARD_PORT", port)
    env.setdefault("DISKHOARD_DATA_DIR", data_dir())
    kw = {"cwd": ROOT, "env": env, "stdin": subprocess.DEVNULL,
          "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if os.name == "nt":
        kw["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    try:
        subprocess.Popen([sys.executable, "-m", "diskhoard", "--no-browser"], **kw)
    except OSError as exc:
        log("autostart failed: %s" % exc)
        return False
    deadline = time.time() + 20
    while time.time() < deadline:
        if alive():
            return True
        time.sleep(0.3)
    return False


def ensure_running():
    if alive():
        return True
    log("DiskHoard not reachable at %s; starting it" % base_url())
    return autostart()


# ----------------------------------------------------------------- JSON-RPC

def log(msg):
    sys.stderr.write("[diskhoard-mcp] %s\n" % msg)
    sys.stderr.flush()


def _text(obj, is_error=False):
    return {"content": [{"type": "text", "text": json.dumps(obj, ensure_ascii=False)}],
            "isError": bool(is_error)}


def handle(msg):
    """Devuelve la respuesta JSON-RPC a `msg`, o None si es una notificacion."""
    method = msg.get("method", "")
    params = msg.get("params") or {}
    rid = msg.get("id")
    is_notification = "id" not in msg

    if method == "initialize":
        proto = params.get("protocolVersion") or PROTOCOL_FALLBACK
        result = {
            "protocolVersion": proto,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "disk-hoard", "version": __version__},
            "instructions": agentmod.INSTRUCTIONS,
        }
        return {"jsonrpc": "2.0", "id": rid, "result": result}
    if method in ("notifications/initialized", "notifications/cancelled",
                  "notifications/roots/list_changed"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        tools = [{"name": t["name"], "description": t["description"],
                  "inputSchema": t["inputSchema"], "annotations": t["annotations"]}
                 for t in agentmod.CATALOG]
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}}
    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        if name not in agentmod.TOOL_NAMES:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32602, "message": "Unknown tool: %s" % name}}
        if not ensure_running():
            return {"jsonrpc": "2.0", "id": rid, "result": _text({"error": NOT_RUNNING}, True)}
        try:
            code, body = _http("POST", "/api/agent/call", {"name": name, "arguments": arguments})
        except FileNotFoundError:
            return {"jsonrpc": "2.0", "id": rid,
                    "result": _text({"error": "Token file missing; start DiskHoard once to create it."}, True)}
        except Exception as exc:  # noqa: BLE001 - el puente nunca muere por una llamada
            return {"jsonrpc": "2.0", "id": rid, "result": _text({"error": str(exc)}, True)}
        return {"jsonrpc": "2.0", "id": rid, "result": _text(body, code >= 400)}
    if method in ("resources/list", "resources/templates/list"):
        key = "resourceTemplates" if method.endswith("templates/list") else "resources"
        return {"jsonrpc": "2.0", "id": rid, "result": {key: []}}
    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"prompts": []}}
    if is_notification:
        return None
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": "Method not found: %s" % method}}


def main():
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line.decode("utf-8"))
        except ValueError:
            out = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        else:
            if isinstance(msg, list):  # lote: una respuesta por peticion con id
                outs = [r for r in (handle(m) for m in msg if isinstance(m, dict)) if r]
                out = outs or None
            elif isinstance(msg, dict):
                out = handle(msg)
            else:
                out = {"jsonrpc": "2.0", "id": None,
                       "error": {"code": -32600, "message": "Invalid request"}}
        if out is not None:
            stdout.write((json.dumps(out, ensure_ascii=False) + "\n").encode("utf-8"))
            stdout.flush()


if __name__ == "__main__":
    main()
