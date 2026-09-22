# -*- coding: utf-8 -*-
"""El puente MCP como lo usa un cliente: proceso aparte, JSON-RPC por lineas."""
import json
import os
import subprocess
import sys
import time
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRIDGE = os.path.join(ROOT, "mcp_server.py")


class Client:
    def __init__(self, env):
        self.proc = subprocess.Popen([sys.executable, BRIDGE], cwd=ROOT, env=env,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        self.n = 0

    def request(self, method, params=None):
        self.n += 1
        msg = {"jsonrpc": "2.0", "id": self.n, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        assert line, self.proc.stderr.read().decode(errors="replace")
        out = json.loads(line)
        assert out["id"] == self.n
        return out

    def notify(self, method):
        self.proc.stdin.write((json.dumps({"jsonrpc": "2.0", "method": method}) + "\n").encode())
        self.proc.stdin.flush()

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        return self.proc.stderr.read().decode(errors="replace")


def tool_text(resp):
    return json.loads(resp["result"]["content"][0]["text"]), resp["result"]["isError"]


@pytest.fixture
def client(server, data_dir):
    env = dict(os.environ, DISKHOARD_URL=server["url"], DISKHOARD_DATA_DIR=str(data_dir),
               DISKHOARD_AUTOSTART="0")
    c = Client(env)
    yield c
    c.close()


def test_handshake_lists_the_catalog_and_calls_through(client, tree):
    init = client.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                         "clientInfo": {"name": "test", "version": "0"}})
    assert init["result"]["protocolVersion"] == "2025-06-18"
    assert init["result"]["serverInfo"]["name"] == "disk-hoard"
    assert "disk_scan" in init["result"]["instructions"]
    client.notify("notifications/initialized")
    assert client.request("ping")["result"] == {}

    tools = client.request("tools/list")["result"]["tools"]
    names = [t["name"] for t in tools]
    assert names[:2] == ["disk_drives", "disk_scan"] and "disk_delete" in names
    delete = next(t for t in tools if t["name"] == "disk_delete")
    assert delete["annotations"]["destructiveHint"] is True
    assert delete["inputSchema"]["required"] == ["paths"]

    out, is_err = tool_text(client.request("tools/call", {"name": "disk_scan",
                                                          "arguments": {"path": str(tree)}}))
    assert not is_err and out["done"] and out["files"] >= 9

    out, is_err = tool_text(client.request("tools/call", {"name": "disk_junk",
                                                          "arguments": {"min_mb": 0, "safety": "safe"}}))
    assert not is_err and all(i["safety"] == "safe" for i in out["items"])

    out, is_err = tool_text(client.request("tools/call", {"name": "disk_delete",
                                                          "arguments": {"paths": [str(tree / "proyecto" / ".git")],
                                                                        "mode": "permanent", "confirm": True}}))
    assert is_err and out["refused"][0]["path"].endswith(".git")

    bad = client.request("tools/call", {"name": "disk_nope", "arguments": {}})
    assert bad["error"]["code"] == -32602
    assert client.request("no/such")["error"]["code"] == -32601
    assert client.request("resources/list")["result"] == {"resources": []}


def test_batch_and_garbage_lines_do_not_kill_the_bridge(client):
    client.proc.stdin.write(b"not json\n")
    client.proc.stdin.write(b'[{"jsonrpc":"2.0","id":7,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]\n')
    client.proc.stdin.flush()
    first = json.loads(client.proc.stdout.readline())
    assert first["error"]["code"] == -32700
    batch = json.loads(client.proc.stdout.readline())
    assert batch == [{"jsonrpc": "2.0", "id": 7, "result": {}}]
    assert client.request("ping")["result"] == {}


def test_bridge_starts_the_app_when_it_is_down(tmp_path):
    """Sin app en ese puerto, el puente la arranca y la primera llamada llega."""
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    data = tmp_path / "datos"
    env = dict(os.environ, DISKHOARD_URL="http://127.0.0.1:%d" % port, DISKHOARD_DATA_DIR=str(data))
    env.pop("DISKHOARD_AUTOSTART", None)
    c = Client(env)
    try:
        out, is_err = tool_text(c.request("tools/call", {"name": "disk_drives", "arguments": {}}))
        assert not is_err and "drives" in out, out
        with urllib.request.urlopen("http://127.0.0.1:%d/api/health" % port, timeout=3) as r:
            assert json.loads(r.read())["service"] == "disk-hoard"
        assert (data / "mcp-token").is_file()
    finally:
        stderr = c.close()
        assert "starting it" in stderr
        # apagar la app que arranco el puente
        tok = (data / "mcp-token").read_text().strip()
        req = urllib.request.Request("http://127.0.0.1:%d/api/quit" % port, method="POST", data=b"{}")
        req.add_header("X-DH-Token", tok)
        try:
            urllib.request.urlopen(req, timeout=3)
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.6)
