# -*- coding: utf-8 -*-
"""Lo que DiskHoard toma de Hoard Link: la guardia de Host/Origin, el token, el reemplazo atomico y el explorador."""
import json
import os
import time
import urllib.error
import urllib.request

import pytest

from diskhoard import scanner as scanmod
from diskhoard import zipsplit as zs


def get(server, path, headers=None):
    req = urllib.request.Request(server["url"] + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode("utf-8") or "null")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8") or "null")


def test_a_foreign_host_name_is_refused(server):
    # a page that rebinds its DNS name to 127.0.0.1 sends its own name in Host
    code, body = get(server, "/api/health", {"Host": "evil.example"})
    assert code == 403 and body["error"] == "Only local access is allowed."
    assert get(server, "/api/health")[0] == 200
    # the port in Host must be this app's
    assert get(server, "/api/health", {"Host": "127.0.0.1:9"})[0] == 403


def test_cross_site_fetches_are_refused_but_navigation_is_not(server):
    assert get(server, "/api/health", {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"})[0] == 403
    nav = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
    assert get(server, "/api/health", nav)[0] == 200
    req = urllib.request.Request(server["url"] + "/api/cancel?t=" + server["token"], data=b"{}", method="POST",
                                 headers={"Origin": "http://evil.example"})
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code == 403


def test_an_allowed_host_name_is_opened_by_the_environment(server, monkeypatch):
    monkeypatch.setenv("DISKHOARD_ALLOWED_HOSTS", "pc2.example")
    assert get(server, "/api/health", {"Host": "pc2.example"})[0] == 200
    assert get(server, "/api/health", {"Host": "evil.example"})[0] == 403


def test_the_token_is_checked_on_the_api_and_the_catalogue_stays_public(server):
    assert get(server, "/api/drives")[0] == 403
    assert get(server, "/api/drives", {"Authorization": "Bearer wrong"})[0] == 403
    assert get(server, "/api/drives", {"Authorization": "Bearer " + server["token"]})[0] == 200
    assert get(server, "/api/drives", {"X-DH-Token": server["token"]})[0] == 200
    assert get(server, "/api/agent/tools")[0] == 200


def test_the_token_file_is_created_once_and_kept(tmp_path, monkeypatch):
    from diskhoard import server as srv  # imported late: importing it reads the token of the data folder in force
    monkeypatch.setenv("DISKHOARD_DATA_DIR", str(tmp_path))
    first = srv.load_token()
    assert len(first) >= 16 and (tmp_path / "mcp-token").read_text(encoding="utf-8").strip() == first
    assert srv.load_token() == first
    (tmp_path / "mcp-token").write_text("short", encoding="utf-8")
    assert len(srv.load_token()) >= 16  # a token under 16 characters is replaced


def test_open_reveals_in_the_file_manager(server, monkeypatch, tmp_path):
    srv = server["mod"]
    seen = []
    monkeypatch.setattr(srv, "reveal_in_file_manager", lambda p: seen.append(p) or True)
    assert srv.api_open(str(tmp_path)) == {"ok": True} and seen == [str(tmp_path)]
    monkeypatch.setattr(srv, "reveal_in_file_manager", lambda p: False)
    assert "error" in srv.api_open(str(tmp_path / "nada" / "nada"))


def test_the_snapshot_and_the_zip_parts_are_replaced_with_retry(tree, tmp_path, monkeypatch):
    calls = []
    real = scanmod.replace_with_retry

    def spy(src, dst, **kw):
        calls.append(os.path.basename(str(dst)))
        return real(src, dst, **kw)

    monkeypatch.setattr(scanmod, "replace_with_retry", spy)
    monkeypatch.setattr(zs, "replace_with_retry", spy)
    sc = scanmod.Scanner(str(tree))
    sc.start()
    while not sc.done:
        time.sleep(0.02)
    assert scanmod.save_snapshot(sc, str(tmp_path / "last.pkl.gz"))
    assert calls == ["last.pkl.gz"] and not (tmp_path / "last.pkl.gz.tmp").exists()
    src = tmp_path / "origen"
    src.mkdir()
    (src / "a.bin").write_bytes(os.urandom(50_000))
    r = zs.split(zs.options_from({"path": str(src), "out_dir": str(tmp_path / "o"), "limit": 300_000, "margin": 10_000}))
    assert r["ok"] and "part_001.zip" in calls
