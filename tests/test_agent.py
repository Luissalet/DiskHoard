# -*- coding: utf-8 -*-
"""Las herramientas del agente contra un arbol real, por HTTP como hace el puente."""
import json
import os
import urllib.error
import urllib.request

import pytest

from diskhoard import agent as agentmod
from diskhoard import junk as junkmod


def call(server, name, arguments=None, expect=200):
    req = urllib.request.Request(server["url"] + "/api/agent/call", method="POST",
                                 data=json.dumps({"name": name, "arguments": arguments or {}}).encode())
    req.add_header("Content-Type", "application/json")
    req.add_header("X-DH-Token", server["token"])
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            assert r.status == expect
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        assert exc.code == expect, exc.read()
        return json.loads(exc.read())


def get(server, path, auth=True):
    req = urllib.request.Request(server["url"] + path)
    if auth:
        req.add_header("X-DH-Token", server["token"])
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


# ----------------------------------------------------------------- catalogo

def test_catalog_first_lines_fit_the_tool_index():
    for t in agentmod.CATALOG:
        first = t["description"].split("\n")[0]
        assert len(first) <= 110, (t["name"], len(first))
        assert "Keywords:" in first
        assert t["inputSchema"]["type"] == "object"
        assert "readOnlyHint" in t["annotations"]


WRITERS = {"disk_delete", "disk_zip_split", "disk_zip_cancel"}


def test_only_delete_is_destructive():
    destructive = [t["name"] for t in agentmod.CATALOG if t["annotations"]["destructiveHint"]]
    assert destructive == ["disk_delete"]
    assert all(t["annotations"]["readOnlyHint"] for t in agentmod.CATALOG if t["name"] not in WRITERS)
    assert not any(t["annotations"]["readOnlyHint"] for t in agentmod.CATALOG if t["name"] in WRITERS)


def test_health_needs_no_token_and_names_the_service(server):
    h = get(server, "/api/health", auth=False)
    assert h["service"] == "disk-hoard"
    assert h["tools"] == len(agentmod.CATALOG)


def test_agent_endpoints_need_the_token(server):
    # The catalogue is public (as in every family app); the log and the calls are not.
    assert [t["name"] for t in get(server, "/api/agent/tools", auth=False)["tools"]] == agentmod.TOOL_NAMES
    with pytest.raises(urllib.error.HTTPError) as exc:
        get(server, "/api/agent/log", auth=False)
    assert exc.value.code == 403
    cat = get(server, "/api/agent/tools")
    assert [t["name"] for t in cat["tools"]] == agentmod.TOOL_NAMES


def test_token_file_is_reused_between_starts(server, data_dir):
    path = os.path.join(str(data_dir), "mcp-token")
    assert open(path, encoding="utf-8").read().strip() == server["token"]
    assert server["mod"].load_token() == server["token"]
    assert open(os.path.join(str(data_dir), "url")).read().strip() == server["url"]


# ------------------------------------------------------------- herramientas

def test_unknown_tool_and_bad_arguments_are_errors_not_500s(server):
    assert "error" in call(server, "disk_nope", expect=400)
    out = call(server, "disk_scan", {"nope": 1}, expect=400)
    assert "bad arguments" in out["error"]


def test_tools_before_a_scan_say_so(server):
    out = call(server, "disk_hotspots", expect=400)
    assert "disk_scan" in out["error"]
    assert call(server, "disk_status")["idle"] is True


def test_scan_waits_and_summarises(server, tree):
    out = call(server, "disk_scan", {"path": str(tree)})
    assert out["done"] is True
    assert out["files"] == 10
    assert out["size"] == 300_000 + 200_000 + 150_000 + 50 + 120_000 + 20 + 90_000 + 900_000 + 700_000 + 10
    st = call(server, "disk_status")
    assert st["done"] and st["root"] == out["root"]


def test_dir_lists_biggest_first_with_tags(server, tree):
    call(server, "disk_scan", {"path": str(tree)})
    out = call(server, "disk_dir", {"path": str(tree / "proyecto"), "dirs_only": True})
    names = [e["name"] for e in out["entries"]]
    assert names[0] == "node_modules"
    tags = {e["name"]: e.get("tag", {}).get("safety") for e in out["entries"]}
    assert tags["node_modules"] == "safe"
    assert tags[".git"] == "danger"
    assert tags["dist"] == "safe"       # package.json al lado
    assert tags[".venv"] == "safe"      # pyvenv.cfg dentro
    assert out["entries"][0]["share"] > 40


def test_junk_filters_by_safety_and_size(server, tree):
    call(server, "disk_scan", {"path": str(tree)})
    out = call(server, "disk_junk", {"min_mb": 0})
    by = {i["path"].split(os.sep)[-1]: i for i in out["items"]}
    assert by["node_modules"]["safety"] == "safe"
    assert by[".git"]["safety"] == "danger"
    assert out["reclaimable_safe"] == 500_000 + 120_000 + 90_020
    safe = call(server, "disk_junk", {"min_mb": 0, "safety": "safe"})
    assert {i["safety"] for i in safe["items"]} == {"safe"}
    big = call(server, "disk_junk", {"min_mb": 0.4})
    assert [i["path"].split(os.sep)[-1] for i in big["items"]] == ["node_modules"]


def test_hotspots_types_stale_top_files(server, tree):
    call(server, "disk_scan", {"path": str(tree)})
    hot = call(server, "disk_hotspots")
    assert hot["items"] and hot["items"][0]["share"] > 0
    types = call(server, "disk_types")
    assert types["items"][0]["human"].endswith("KB")
    stale = call(server, "disk_stale", {"months": 12, "min_gb": 0.0005})
    assert any(i["path"].endswith("videos") for i in stale["items"])
    top = call(server, "disk_top_files", {"limit": 2})
    assert [i["name"] for i in top["items"]] == ["peli.mp4", "imagen.iso"]
    only = call(server, "disk_top_files", {"ext": "iso"})
    assert [i["name"] for i in only["items"]] == ["imagen.iso"]


def test_find_combines_pattern_size_and_age(server, tree):
    out = call(server, "disk_find", {"path": str(tree), "pattern": "*.mp4"})
    assert out["matches"] == 1 and out["items"][0]["name"] == "peli.mp4"
    old = call(server, "disk_find", {"path": str(tree), "older_than_days": 3650})
    assert [i["name"] for i in old["items"]] == ["peli.mp4"]
    big = call(server, "disk_find", {"path": str(tree), "min_mb": 0.5})
    assert {i["name"] for i in big["items"]} == {"peli.mp4", "imagen.iso"}
    assert call(server, "disk_find", {"path": str(tree / "no-existe")}, expect=400)["error"]


def test_explain_knows_the_catalog_and_the_scan(server, tree):
    call(server, "disk_scan", {"path": str(tree)})
    nm = call(server, "disk_explain", {"path": str(tree / "proyecto" / "node_modules")})
    assert nm["known"] and nm["safety"] == "safe" and nm["in_scan"] and nm["size"] == 500_000
    assert nm["agent_may_delete"] is True
    git = call(server, "disk_explain", {"path": str(tree / "proyecto" / ".git")})
    assert git["safety"] == "danger" and git["agent_may_delete"] is False
    unknown = call(server, "disk_explain", {"path": str(tree / "videos")})
    assert unknown["known"] is False and unknown["files"] == 1


def test_script_is_saved_and_returned(server, tree, data_dir):
    out = call(server, "disk_script", {"paths": [str(tree / "proyecto" / "node_modules")]})
    assert out["saved_to"].startswith(str(data_dir))
    assert os.path.isfile(out["saved_to"])
    assert "Remove-Target" in out["script"] and "-WhatIf" in out["run"]


# ------------------------------------------------------------------ borrado

def test_refusals(server, tree):
    home = os.path.expanduser("~")
    assert agentmod.refuse_reason(home)
    assert agentmod.refuse_reason("/" if os.name != "nt" else "C:\\")
    assert agentmod.refuse_reason(str(tree / "proyecto" / ".git"))
    assert agentmod.refuse_reason(str(tree / "proyecto" / ".git" / "objects"))
    assert "protected folder" in agentmod.refuse_reason(str(tree / "proyecto"))
    assert "protected folder" in agentmod.refuse_reason(str(tree))
    assert agentmod.refuse_reason(str(tree / "proyecto" / "node_modules")) is None
    assert agentmod.refuse_reason("relativa/ruta")


def test_permanent_needs_confirm_and_refuses_danger(server, tree):
    out = call(server, "disk_delete", {"paths": [str(tree / "proyecto" / "node_modules")],
                                       "mode": "permanent"}, expect=400)
    assert "confirm" in out["error"]
    out = call(server, "disk_delete", {"paths": [str(tree / "proyecto" / ".git")],
                                       "mode": "permanent", "confirm": True}, expect=400)
    assert out["refused"][0]["reason"].startswith("marked")
    assert os.path.isdir(str(tree / "proyecto" / ".git"))


def test_parent_of_protected_folder_cannot_be_deleted(server, tree):
    parent = str(tree / "proyecto")
    out = call(server, "disk_delete", {"paths": [parent], "mode": "permanent",
                                       "confirm": True}, expect=400)
    assert out["refused"][0]["path"] == os.path.abspath(parent)
    assert "protected folder" in out["refused"][0]["reason"]
    assert os.path.isfile(str(tree / "proyecto" / ".git" / "objects" / "pack" / "x.pack"))


def test_permanent_delete_updates_the_tree(server, tree):
    call(server, "disk_scan", {"path": str(tree)})
    before = call(server, "disk_status")["total"]
    target = str(tree / "proyecto" / "dist")
    out = call(server, "disk_delete", {"paths": [target, str(tree / "proyecto" / ".git")],
                                       "mode": "permanent", "confirm": True})
    assert out["finished"] and out["freed"] == 120_000 and out["errors"] == []
    assert out["deleted"] == [os.path.abspath(target)]
    assert out["refused"][0]["path"].endswith(".git")
    assert not os.path.exists(target)
    assert out["root_size_now"] == before - 120_000
    d = call(server, "disk_dir", {"path": str(tree / "proyecto"), "dirs_only": True})
    assert "dist" not in [e["name"] for e in d["entries"]]
    log = get(server, "/api/agent/log")
    assert "disk_delete" in [i["tool"] for i in log["items"]]


@pytest.mark.skipif(os.name == "nt", reason="en Windows la papelera existe")
def test_trash_is_windows_only(server, tree):
    out = call(server, "disk_delete", {"paths": [str(tree / "descargas" / "notas.txt")]}, expect=400)
    assert "Recycle Bin" in out["error"]
    assert os.path.exists(str(tree / "descargas" / "notas.txt"))


def test_rescan_after_outside_change(server, tree):
    call(server, "disk_scan", {"path": str(tree)})
    extra = tree / "videos" / "nuevo.mp4"
    with open(str(extra), "wb") as fh:
        fh.write(b"\0" * 5000)
    out = call(server, "disk_rescan", {"path": str(tree / "videos")})
    assert out["delta"] == 5000 and out["delta_human"].startswith("+")
    os.remove(str(extra))


def test_new_catalog_rules_are_wired():
    ids = {r["id"] for r in junkmod.RULES}
    for wanted in ("uv", "bun", "gomod", "pubcache", "lmstudio", "shadercache", "deliveryopt", "spotify"):
        assert wanted in ids, wanted


def test_a_venv_with_any_name_is_recognised_by_its_pyvenv_cfg(tmp_path):
    odd = tmp_path / "venv-ocr"
    (odd / "Lib").mkdir(parents=True)
    (odd / "pyvenv.cfg").write_text("home = x")
    assert junkmod.match_rule(str(odd), "venv-ocr")["id"] == "venv"
    plain = tmp_path / "datos"
    plain.mkdir()
    assert junkmod.match_rule(str(plain), "datos") is None


# ----------------------------------------------------------------- familia

def test_family_contract_bearer_token_health_block_and_call_events(server, monkeypatch):
    """The hub proxy and the MCP bridge speak Authorization: Bearer; every call lands in the bus as agent.call."""
    from diskhoard.hoard_link import family

    h = get(server, "/api/health", auth=False)
    assert h["hoard_link"]["app"] == "diskhoard" and h["hoard_link"]["family"] and "events" in h["hoard_link"]

    seen = []
    monkeypatch.setattr(family, "emit", lambda t, d=None, **kw: seen.append((t, d)) or True)

    req = urllib.request.Request(server["url"] + "/api/agent/call", method="POST",
                                 data=json.dumps({"name": "disk_drives", "arguments": {}, "caller": "hub"}).encode())
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Bearer " + server["token"])
    with urllib.request.urlopen(req, timeout=30) as r:
        assert r.status == 200 and "drives" in json.loads(r.read())
    assert seen and seen[-1][0] == "agent.call"
    assert seen[-1][1]["tool"] == "disk_drives" and seen[-1][1]["ok"] is True and seen[-1][1]["caller"] == "hub" and "ms" in seen[-1][1]

    bad = urllib.request.Request(server["url"] + "/api/agent/log")
    bad.add_header("Authorization", "Bearer not-the-token")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(bad, timeout=10)
    assert exc.value.code == 403

    call(server, "no_such_tool", expect=400)
    assert seen[-1][1]["tool"] == "no_such_tool" and seen[-1][1]["ok"] is False and "unknown tool" in seen[-1][1]["error"]


# --------------------------------------------------------------- partir en ZIPs

ZIP_TOOLS = ["disk_zip_plan", "disk_zip_split", "disk_zip_status", "disk_zip_cancel"]


def zip_tree(base, sizes=(100_000,) * 7, folder="origen"):
    import random
    rng = random.Random(11)
    root = os.path.join(str(base), folder)
    os.makedirs(root, exist_ok=True)
    for i, size in enumerate(sizes):
        with open(os.path.join(root, "f%02d.bin" % i), "wb") as fh:
            fh.write(rng.randbytes(size))
    return root


def test_zip_tools_are_in_the_catalog_with_spanish_phrases():
    names = [t["name"] for t in agentmod.CATALOG]
    assert names[-4:] == ZIP_TOOLS and agentmod.TOOL_NAMES == names
    by = {t["name"]: t for t in agentmod.CATALOG}
    first = by["disk_zip_split"]["description"].split("\n")[0]
    assert "partir en zips" in first.lower() and "990 MB" in first
    assert "dividir en partes" in by["disk_zip_plan"]["description"].split("\n")[0]
    for name in ZIP_TOOLS:
        assert "Sinónimos: " in by[name]["description"]
    assert by["disk_zip_plan"]["annotations"]["readOnlyHint"] is True
    assert by["disk_zip_split"]["inputSchema"]["required"] == ["path"]
    assert set(by["disk_zip_split"]["inputSchema"]["properties"]) >= {
        "path", "out_dir", "limit", "margin", "prefix", "sort", "compression", "too_large", "include", "exclude",
        "overwrite", "manifest", "confirm", "wait", "timeout_s"}
    assert by["disk_zip_split"]["inputSchema"]["properties"]["too_large"]["default"] == "skip"
    assert by["disk_zip_split"]["inputSchema"]["properties"]["wait"]["default"] is True
    assert by["disk_zip_split"]["inputSchema"]["properties"]["timeout_s"]["default"] == 150
    assert by["disk_zip_status"]["inputSchema"]["properties"]["wait_s"]["maximum"] == 150


def test_zip_plan_tool_is_read_only(server, tmp_path):
    root = zip_tree(tmp_path)
    out = call(server, "disk_zip_plan", {"path": root, "limit": "300000", "margin": "10000"})
    assert out["dry_run"] and out["part_count"] == 4 and out["files"] == 7
    assert not os.path.exists(root + "_zips")
    assert out["parts"][0]["sample"] and "files" not in out["parts"][0]
    full = call(server, "disk_zip_plan", {"path": root, "limit": "300000", "margin": "10000", "list_files": True})
    assert sum(len(p["files"]) for p in full["parts"]) == 7
    assert "error" in call(server, "disk_zip_plan", {"path": root, "limit": "tres"}, expect=400)
    assert "dentro" in call(server, "disk_zip_plan", {"path": root, "out_dir": os.path.join(root, "x")},
                            expect=400)["error"]
    assert call(server, "disk_zip_plan", {"path": root, "prefix": "foto", "limit": "300000", "margin": "10000"}
                )["parts"][0]["name"] == "foto_001.zip"


def test_zip_split_tool_waits_logs_and_reports_real_sizes(server, tmp_path):
    root = zip_tree(tmp_path)
    before = get(server, "/api/agent/log")["seq"]
    out = call(server, "disk_zip_split", {"path": root, "limit": "300kb", "margin": "10kb"})
    assert out["out_dir"] == root + "_zips" and out["part_count"] == 4 and out["files_added"] == 7
    for p in out["parts"]:
        assert p["size"] == os.path.getsize(p["path"]) <= 300_000 and p["within_limit"]
    assert out["too_large"] == [] and out["job"] and out["manifest"].endswith("manifest.txt")
    st = call(server, "disk_zip_status")
    assert st["finished"] and st["state"] == "done" and st["summary"]["part_count"] == 4
    assert call(server, "disk_zip_status", {"job": out["job"]})["id"] == out["job"]
    assert "error" in call(server, "disk_zip_status", {"job": "9999"}, expect=400)
    items = get(server, "/api/agent/log", )["items"]
    mine = [i for i in items if i["seq"] > before]
    assert [i["tool"] for i in mine] == ["disk_zip_split"] and "4 parts" in mine[0]["summary"]
    # la carpeta de salida ya no está vacía: hay que decir overwrite
    again = call(server, "disk_zip_split", {"path": root, "limit": "300kb", "margin": "10kb"}, expect=400)
    assert "no está vacía" in again["error"]
    ok = call(server, "disk_zip_split", {"path": root, "limit": "300kb", "margin": "10kb", "overwrite": True})
    assert ok["part_count"] == 4


def test_zip_split_tool_nowait_status_and_cancel(server, tmp_path):
    import time
    root = zip_tree(tmp_path, sizes=(1_500_000,) * 6)
    started = call(server, "disk_zip_split", {"path": root, "limit": "2mb", "margin": "1kb", "wait": False})
    assert started["started"] and started["job"]
    cancelled = call(server, "disk_zip_cancel", {"job": started["job"]})
    assert cancelled["finished"] and cancelled["state"] in ("cancelled", "done")
    if os.path.isdir(root + "_zips"):
        assert [n for n in os.listdir(root + "_zips") if n.endswith(".tmp")] == []
    idle = call(server, "disk_zip_cancel")
    assert idle["was_running"] is False
    tools = [i["tool"] for i in get(server, "/api/agent/log")["items"]]
    assert "disk_zip_cancel" in tools


def test_zip_move_and_drive_root_need_confirm(server, tmp_path):
    root = zip_tree(tmp_path, sizes=(50_000, 700_000, 40_000))
    out = call(server, "disk_zip_split", {"path": root, "limit": "300kb", "margin": "10kb", "too_large": "move"},
               expect=400)
    assert "confirm" in out["error"]
    assert os.path.exists(os.path.join(root, "f01.bin")) and not os.path.exists(root + "_zips")
    ok = call(server, "disk_zip_split", {"path": root, "limit": "300kb", "margin": "10kb", "too_large": "move",
                                         "confirm": True})
    assert ok["too_large"][0]["result"] == "moved" and not os.path.exists(os.path.join(root, "f01.bin"))
    assert os.path.isfile(os.path.join(root + "_zips", "too_large", "f01.bin"))
    drive = os.path.abspath(os.sep)
    assert "confirm" in call(server, "disk_zip_split", {"path": drive, "out_dir": str(tmp_path / "d")}, expect=400)["error"]
    assert "confirm" in call(server, "disk_zip_plan", {"path": drive, "out_dir": str(tmp_path / "d")}, expect=400)["error"]


def test_zip_split_tool_volumes_and_default_skip(server, tmp_path):
    root = zip_tree(tmp_path, sizes=(50_000, 700_000, 40_000))
    skipped = call(server, "disk_zip_split", {"path": root, "limit": "300kb", "margin": "10kb"})
    assert skipped["too_large"][0]["result"] == "skipped" and os.path.exists(os.path.join(root, "f01.bin"))
    out = call(server, "disk_zip_split", {"path": root, "limit": "300kb", "margin": "10kb", "too_large": "split",
                                          "out_dir": str(tmp_path / "volumenes")})
    vols = out["too_large"][0]["volumes"]
    assert len(vols) >= 3 and all(v["size"] <= 300_000 for v in vols)
    assert all(v["name"].startswith("part_") for v in vols)
