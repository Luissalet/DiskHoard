# -*- coding: utf-8 -*-
"""Catalogo de agentes de IA, re-verificacion antes de borrar y esperado frente a liberado."""
import json
import os
import shutil
import time
import urllib.error
import urllib.request

import pytest

from diskhoard import agent as agentmod
from diskhoard import junk as junkmod
from diskhoard import scanner as scanmod


# ------------------------------------------------------------------ ayudas

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


def put(path, size=1000):
    os.makedirs(os.path.dirname(str(path)), exist_ok=True)
    with open(str(path), "wb") as fh:
        fh.write(b"\0" * size)
    return str(path)


def build_profile(base):
    """Un perfil de Windows de mentira con la estructura real de cada herramienta."""
    home = base / "Users" / "luism"
    roaming = home / "AppData" / "Roaming"
    local = home / "AppData" / "Local"
    # Claude Code
    for d in ("cache", "debug", "downloads", "shell-snapshots", "session-env",
              "projects", "sessions", "file-history", "plans", "backups",
              "skills", "plugins", "ide", "chrome"):
        put(home / ".claude" / d / "f.bin", 5000)
    for f in (".credentials.json", ".claude.json", "settings.json"):
        put(home / ".claude" / f, 300)
    put(home / ".claude" / "history.jsonl", 90_000)
    put(home / ".claude" / "stats-cache.json", 90_000)
    # Claude Desktop
    for d in ("Cache", "Code Cache", "GPUCache", "DawnGraphiteCache", "DawnWebGPUCache", "GrShaderCache",
              "GPUPersistentCache", "ShaderCache", "Crashpad", "logs", "sentry",
              "claude-code-sessions", "local-agent-mode-sessions", "vm_bundles", "claude-code-vm",
              "Local Storage", "IndexedDB", "Session Storage"):
        put(roaming / "Claude" / d / "f.bin", 5000)
    put(roaming / "Claude" / "claude_desktop_config.json", 300)
    put(roaming / "Claude" / "config.json", 300)
    put(local / "claude-cli-nodejs" / "Cache" / "f.bin", 5000)
    put(local / "Packages" / "Claude_pzs8sxrjxfjjc" / "LocalCache" / "x" / "f.bin", 5000)
    # Codex
    for d in (".tmp", "tmp", "cache", "sessions", "worktrees", "generated_images", "attachments",
              "sqlite", "memories", "rules", "skills", "plugins", "automations"):
        put(home / ".codex" / d / "f.bin", 5000)
    put(home / ".codex" / "..codex-global-state.json.bak.tmp-1", 90_000)
    put(home / ".codex" / "..codex-global-state.json.tmp-2", 90_000)
    put(home / ".codex" / "config.toml", 300)
    # Cursor
    for d in ("Cache", "Code Cache", "GPUCache", "CachedData", "CachedExtensionVSIXs", "CachedProfilesData",
              "DawnGraphiteCache", "DawnWebGPUCache", "Crashpad", "logs", "sentry",
              "Backups", "User", "Workspaces"):
        put(roaming / "Cursor" / d / "f.bin", 5000)
    for d in ("chats", "projects", "worktrees", "extensions", "ai-tracking"):
        put(home / ".cursor" / d / "f.bin", 5000)
    put(home / ".cursor" / "statsig-cache.json.1.tmp", 90_000)
    # VS Code
    for d in ("Cache", "CachedData", "User", "Backups"):
        put(roaming / "Code" / d / "f.bin", 5000)
    return home


@pytest.fixture
def profile(tmp_path):
    return build_profile(tmp_path)


def rule_of(path):
    p = str(path)
    return junkmod.match_rule(p, os.path.basename(p))


# ---------------------------------------------------------------- catalogo

@pytest.mark.parametrize("rel,rule_id,safety", [
    # Claude Code
    ((".claude", "cache"), "ai_claude_code_cache", "safe"),
    ((".claude", "debug"), "ai_claude_code_cache", "safe"),
    ((".claude", "downloads"), "ai_claude_code_cache", "safe"),
    ((".claude", "shell-snapshots"), "ai_claude_code_cache", "safe"),
    ((".claude", "session-env"), "ai_claude_code_cache", "safe"),
    ((".claude", "projects"), "ai_claude_code_history", "review"),
    ((".claude", "sessions"), "ai_claude_code_history", "review"),
    ((".claude", "file-history"), "ai_claude_code_history", "review"),
    ((".claude", "plans"), "ai_claude_code_plans", "review"),
    ((".claude", "backups"), "ai_claude_code_plans", "review"),
    # Claude Desktop
    (("AppData", "Roaming", "Claude", "Cache"), "ai_claude_desktop_cache", "safe"),
    (("AppData", "Roaming", "Claude", "Code Cache"), "ai_claude_desktop_cache", "safe"),
    (("AppData", "Roaming", "Claude", "DawnGraphiteCache"), "ai_claude_desktop_cache", "safe"),
    (("AppData", "Roaming", "Claude", "GPUPersistentCache"), "ai_claude_desktop_cache", "safe"),
    (("AppData", "Roaming", "Claude", "Crashpad"), "ai_claude_desktop_cache", "safe"),
    (("AppData", "Roaming", "Claude", "logs"), "ai_claude_desktop_cache", "safe"),
    (("AppData", "Roaming", "Claude", "sentry"), "ai_claude_desktop_cache", "safe"),
    (("AppData", "Roaming", "Claude", "claude-code-sessions"), "ai_claude_desktop_sessions", "review"),
    (("AppData", "Roaming", "Claude", "local-agent-mode-sessions"), "ai_claude_desktop_sessions", "review"),
    (("AppData", "Roaming", "Claude", "vm_bundles"), "ai_claude_desktop_vm", "review"),
    (("AppData", "Roaming", "Claude", "claude-code-vm"), "ai_claude_desktop_vm", "review"),
    (("AppData", "Local", "claude-cli-nodejs", "Cache"), "ai_claude_cli_cache", "safe"),
    (("AppData", "Local", "Packages", "Claude_pzs8sxrjxfjjc", "LocalCache"), "ai_claude_msix", "review"),
    # Codex
    ((".codex", ".tmp"), "ai_codex_temp", "safe"),
    ((".codex", "tmp"), "ai_codex_temp", "safe"),
    ((".codex", "cache"), "ai_codex_temp", "safe"),
    ((".codex", "sessions"), "ai_codex_sessions", "review"),
    ((".codex", "worktrees"), "ai_codex_worktrees", "review"),
    ((".codex", "generated_images"), "ai_codex_media", "review"),
    ((".codex", "attachments"), "ai_codex_media", "review"),
    # Cursor
    (("AppData", "Roaming", "Cursor", "Cache"), "ai_cursor_cache", "safe"),
    (("AppData", "Roaming", "Cursor", "CachedData"), "ai_cursor_cache", "safe"),
    (("AppData", "Roaming", "Cursor", "CachedExtensionVSIXs"), "ai_cursor_cache", "safe"),
    (("AppData", "Roaming", "Cursor", "CachedProfilesData"), "ai_cursor_cache", "safe"),
    (("AppData", "Roaming", "Cursor", "DawnWebGPUCache"), "ai_cursor_cache", "safe"),
    (("AppData", "Roaming", "Cursor", "Crashpad"), "ai_cursor_cache", "safe"),
    ((".cursor", "worktrees"), "ai_cursor_worktrees", "review"),
    ((".cursor", "chats"), "ai_cursor_chats", "review"),
    # VS Code
    (("AppData", "Roaming", "Code", "Cache"), "ai_vscode_cache", "safe"),
    (("AppData", "Roaming", "Code", "CachedData"), "ai_vscode_cache", "safe"),
])
def test_catalog_classifies_each_ai_tool_folder(profile, rel, rule_id, safety):
    rule = rule_of(os.path.join(str(profile), *rel))
    assert rule is not None, rel
    assert rule["id"] == rule_id and rule["safety"] == safety
    assert rule["cat"] == junkmod.AI_CAT == "Agentes de IA"


@pytest.mark.parametrize("rel", [
    (".claude", "skills"), (".claude", "plugins"), (".claude", "ide"), (".claude", "chrome"),
    (".codex", "memories"), (".codex", "rules"), (".codex", "skills"), (".codex", "plugins"),
    (".codex", "automations"), (".codex", "sqlite"),
    (".cursor", "extensions"), (".cursor", "projects"), (".cursor", "ai-tracking"),
    ("AppData", "Roaming", "Claude", "Local Storage"), ("AppData", "Roaming", "Claude", "IndexedDB"),
    ("AppData", "Roaming", "Claude", "Session Storage"),
    ("AppData", "Roaming", "Cursor", "Backups"), ("AppData", "Roaming", "Cursor", "User"),
    ("AppData", "Roaming", "Cursor", "Workspaces"),
    ("AppData", "Roaming", "Code", "User"),
])
def test_what_must_never_be_cataloged_is_not(profile, rel):
    assert rule_of(os.path.join(str(profile), *rel)) is None, rel


def test_a_folder_named_like_an_app_cache_elsewhere_is_not_matched(tmp_path):
    other = tmp_path / "proyectos" / "Claude" / "logs"
    other.mkdir(parents=True)
    rule = rule_of(other)
    assert rule is None or not rule["id"].startswith("ai_")


def test_generic_rules_still_win_where_the_ai_catalog_has_nothing_to_say(tmp_path):
    # un temp cualquiera sigue siendo temp, no una regla de agente
    t = tmp_path / "otro" / "tmp"
    t.mkdir(parents=True)
    assert rule_of(t)["id"] == "temp"


def test_ai_rules_have_unique_ids_and_complete_text():
    ids = [r["id"] for r in junkmod.RULES]
    assert len(ids) == len(set(ids))
    for r in junkmod.RULES:
        if r["id"].startswith("ai_"):
            assert r["why"] and r["how"] and r["label"] and r["safety"] in (junkmod.SAFE, junkmod.REVIEW)


def test_review_rules_state_the_impact():
    by_id = {r["id"]: r for r in junkmod.RULES}
    assert "historial de conversaciones" in by_id["ai_claude_code_history"]["why"]
    assert "sin commitear" in by_id["ai_codex_worktrees"]["why"]
    assert "sin commitear" in by_id["ai_cursor_worktrees"]["why"]


@pytest.mark.parametrize("name,rule_id,safety", [
    (".claude/stats-cache.json", "ai_claude_code_stats", "safe"),
    (".claude/history.jsonl", "ai_claude_code_prompts", "review"),
    (".codex/..codex-global-state.json.bak.tmp-1", "ai_codex_orphans", "safe"),
    (".codex/..codex-global-state.json.tmp-2", "ai_codex_orphans", "safe"),
    (".cursor/statsig-cache.json.1.tmp", "ai_cursor_statsig", "safe"),
])
def test_loose_files_have_their_own_rules(profile, name, rule_id, safety):
    p = os.path.join(str(profile), *name.split("/"))
    rule = junkmod.match_file_rule(p)
    assert rule is not None and rule["id"] == rule_id and rule["safety"] == safety


@pytest.mark.parametrize("name", [".claude/.credentials.json", ".claude/settings.json", ".codex/config.toml",
                                  ".claude/.claude.json", ".claude/chrome"])
def test_credentials_and_settings_are_not_loose_file_rules(profile, name):
    assert junkmod.match_file_rule(os.path.join(str(profile), *name.split("/"))) is None


def test_scan_junk_lists_ai_items_and_nothing_protected(profile):
    sc = scanmod.Scanner(str(profile))
    sc.start()
    while not sc.done:
        time.sleep(0.02)
    items = junkmod.scan_junk(sc.root, sc.root_display, min_bytes=1000)
    ai = {os.path.relpath(i["path"], str(profile)).replace("\\", "/"): i for i in items if i["rule"].startswith("ai_")}
    assert ai[".claude/cache"]["safety"] == "safe"
    assert ai[".claude/projects"]["safety"] == "review"
    assert ai[".codex/worktrees"]["safety"] == "review"
    assert ai["AppData/Roaming/Cursor/CachedData"]["safety"] == "safe"
    assert ai["AppData/Roaming/Claude/vm_bundles"]["safety"] == "review"
    # ficheros sueltos leidos en vivo
    f = ai[".codex/..codex-global-state.json.tmp-2"]
    assert f["file"] is True and f["safety"] == "safe" and f["size"] == 90_000
    assert ai[".claude/history.jsonl"]["safety"] == "review"
    assert ai[".cursor/statsig-cache.json.1.tmp"]["safety"] == "safe"
    # lo que no se cataloga no aparece
    bad = ("skills", "plugins", "ide", "memories", "rules", "sqlite", "extensions", "Local Storage", "IndexedDB",
           "Session Storage", "settings.json", ".credentials.json", ".claude.json", "config.toml", "automations")
    for rel in ai:
        assert os.path.basename(rel) not in bad, rel
    assert all(i["cat"] == "Agentes de IA" for i in ai.values())


def test_protected_reason_covers_things_inside_and_files(profile):
    h = str(profile)
    assert junkmod.protected_reason(os.path.join(h, ".claude", "skills"))
    assert junkmod.protected_reason(os.path.join(h, ".claude", "skills", "mi", "SKILL.md"))
    assert junkmod.protected_reason(os.path.join(h, ".claude", ".credentials.json"))
    assert junkmod.protected_reason(os.path.join(h, ".claude.json"))
    assert junkmod.protected_reason(os.path.join(h, "AppData", "Roaming", "Claude", "config.json"))
    assert junkmod.protected_reason(os.path.join(h, ".codex", "memories"))
    assert junkmod.protected_reason(os.path.join(h, ".cursor", "extensions"))
    assert junkmod.protected_reason(os.path.join(h, "AppData", "Roaming", "Claude", "Local Storage"))
    assert junkmod.protected_reason(os.path.join(h, ".claude", "cache")) is None
    # un .json dentro de una cache no es config
    assert junkmod.protected_reason(os.path.join(h, "AppData", "Roaming", "Claude", "Cache", "a.json")) is None


# ----------------------------------------------------- rechazos del agente

@pytest.mark.parametrize("rel", [
    (".claude", "skills"), (".claude", ".credentials.json"), (".claude.json",), (".codex", "memories"),
    (".codex", "config.toml"), (".cursor", "extensions"),
    ("AppData", "Roaming", "Claude", "Local Storage"), ("AppData", "Roaming", "Claude", "config.json"),
])
def test_agent_refuses_protected_ai_data(profile, rel):
    reason = agentmod.refuse_reason(os.path.join(str(profile), *rel))
    assert reason and "protected AI-tool data" in reason


def test_agent_refuses_parents_that_hide_protected_data(profile):
    for rel in ((".claude",), (".codex",), (".cursor",), ("AppData", "Roaming", "Claude")):
        reason = agentmod.refuse_reason(os.path.join(str(profile), *rel))
        assert reason and "protected AI-tool data" in reason, rel


def test_agent_allows_the_safe_and_review_folders(profile):
    h = str(profile)
    for rel in ((".claude", "cache"), (".claude", "projects"), (".codex", "tmp"), (".codex", "worktrees"),
                ("AppData", "Roaming", "Cursor", "Cache"), ("AppData", "Roaming", "Claude", "Crashpad"),
                (".codex", "..codex-global-state.json.tmp-2")):
        assert agentmod.refuse_reason(os.path.join(h, *rel)) is None, rel


def test_explain_reports_protected_and_known_ai_paths(server, profile):
    h = str(profile)
    out = call(server, "disk_explain", {"path": os.path.join(h, ".claude", "skills")})
    assert out["safety"] == "danger" and out["agent_may_delete"] is False
    out = call(server, "disk_explain", {"path": os.path.join(h, ".claude", "cache")})
    assert out["safety"] == "safe" and out["category"] == "Agentes de IA" and out["agent_may_delete"] is True
    out = call(server, "disk_explain", {"path": os.path.join(h, ".codex", "..codex-global-state.json.tmp-2")})
    assert out["safety"] == "safe" and out["known"] is True and out["kind"] == "file"
    out = call(server, "disk_explain", {"path": os.path.join(h, ".claude", "history.jsonl")})
    assert out["safety"] == "review"


def test_disk_junk_tool_lists_the_ai_category(server, profile):
    call(server, "disk_scan", {"path": str(profile)})
    out = call(server, "disk_junk", {"category": "Agentes de IA", "min_mb": 0.0005, "limit": 200})
    paths = {os.path.relpath(i["path"], str(profile)).replace("\\", "/") for i in out["items"]}
    assert ".claude/cache" in paths and ".codex/worktrees" in paths
    assert ".claude/skills" not in paths and ".claude/settings.json" not in paths
    assert any(c["cat"] == "Agentes de IA" for c in out["categories"])


# ----------------------------------------------------------- huella en vivo

def test_fingerprint_counts_like_the_scan_and_ignores_links(tmp_path):
    d = tmp_path / "d"
    put(d / "a.bin", 100)
    put(d / "sub" / "b.bin", 250)
    big = tmp_path / "fuera"
    put(big / "grande.bin", 50_000)
    link = d / "enlace"
    try:
        os.symlink(str(big), str(link), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("sin symlinks")
    os.utime(d / "sub" / "b.bin", (2_000_000_000, 2_000_000_000))
    fp = scanmod.fingerprint(str(d))
    # el enlace a carpeta no se sigue: cuenta solo como la entrada que es, no como los 50 KB de fuera
    link_size = os.lstat(str(link)).st_size
    assert fp["size"] == 350 + link_size < 50_000 and fp["files"] == 3 and fp["errors"] == 0
    assert fp["mtime"] == pytest.approx(2_000_000_000)
    sc = scanmod.Scanner(str(d))
    sc.start()
    while not sc.done:
        time.sleep(0.02)
    assert (sc.root.size, sc.root.nfiles) == (fp["size"], fp["files"])
    assert sc.root.mtime == pytest.approx(fp["mtime"])
    assert scanmod.fingerprint(str(link))["size"] == link_size
    assert scanmod.fingerprint(str(tmp_path / "nada")) is None
    assert os.path.isfile(str(big / "grande.bin"))


def test_same_fingerprint_compares_only_given_keys():
    now = {"size": 10, "files": 2, "mtime": 5.0}
    assert scanmod.same_fingerprint({"size": 10}, now)
    assert not scanmod.same_fingerprint({"size": 11}, now)
    assert not scanmod.same_fingerprint({"size": 10, "files": 3, "mtime": 5.0}, now)
    assert not scanmod.same_fingerprint({"size": 10, "files": 2, "mtime": 6.0}, now)
    assert scanmod.same_fingerprint({"size": 10, "files": 9}, now, is_dir=False)
    assert not scanmod.same_fingerprint({}, now)


# ------------------------------------- re-verificacion antes de borrar (agent)

def scan(server, path):
    call(server, "disk_scan", {"path": str(path)})


def test_unchanged_item_is_deleted_and_expected_matches_freed(server, profile):
    scan(server, profile)
    target = str(profile / ".claude" / "cache")
    out = call(server, "disk_delete", {"paths": [target], "mode": "permanent", "confirm": True})
    assert out["changed"] == [] and out["deleted"] == [os.path.abspath(target)]
    assert out["expected_bytes"] == out["freed_bytes"] == 5000 == out["freed"]
    assert out["difference_bytes"] == 0
    assert out["freed_on_disk_bytes"] == 5000
    assert out["items"][0]["status"] == "deleted" and out["items"][0]["verified"] is True
    assert not os.path.exists(target)


def test_changed_file_between_scan_and_delete_is_not_deleted(server, profile):
    scan(server, profile)
    target = profile / ".claude" / "cache"
    with open(str(target / "f.bin"), "ab") as fh:
        fh.write(b"x" * 10)
    out = call(server, "disk_delete", {"paths": [str(target)], "mode": "permanent", "confirm": True})
    assert out["deleted"] == [] and os.path.isdir(str(target))
    ch = out["changed"][0]
    assert ch["hint"] == "rescan" and ch["path"] == os.path.abspath(str(target))
    assert ch["expected"]["size"] == 5000 and ch["now"]["size"] == 5010
    assert "size" in ch["fields"]
    assert out["freed_bytes"] == 0 and out["expected_bytes"] == 0
    assert "disk_rescan" in out["changed_hint"]
    # tras reescanear ya cuadra y se borra
    call(server, "disk_rescan", {"path": str(target)})
    out = call(server, "disk_delete", {"paths": [str(target)], "mode": "permanent", "confirm": True})
    assert out["changed"] == [] and out["freed_bytes"] == 5010 == out["expected_bytes"]
    assert not os.path.exists(str(target))


def test_a_new_file_or_a_new_mtime_also_counts_as_changed(server, profile):
    scan(server, profile)
    a = profile / ".codex" / "tmp"
    b = profile / ".codex" / "cache"
    put(a / "nuevo.bin", 0)  # mismo tamano, un fichero mas
    os.utime(str(b / "f.bin"), (2_000_000_000, 2_000_000_000))  # mismos bytes, otra fecha
    out = call(server, "disk_delete", {"paths": [str(a), str(b)], "mode": "permanent", "confirm": True})
    assert out["deleted"] == [] and len(out["changed"]) == 2
    fields = {os.path.basename(c["path"]): c["fields"] for c in out["changed"]}
    assert "files" in fields["tmp"] and "size" not in fields["tmp"]
    assert fields["cache"] == ["mtime"]
    assert os.path.isdir(str(a)) and os.path.isdir(str(b))


def test_only_the_changed_item_is_kept_the_rest_goes(server, profile):
    scan(server, profile)
    keep = profile / ".claude" / "debug"
    gone = profile / ".claude" / "downloads"
    with open(str(keep / "f.bin"), "ab") as fh:
        fh.write(b"y")
    out = call(server, "disk_delete", {"paths": [str(keep), str(gone)], "mode": "permanent", "confirm": True})
    assert out["deleted"] == [os.path.abspath(str(gone))]
    assert [c["path"] for c in out["changed"]] == [os.path.abspath(str(keep))]
    assert os.path.isdir(str(keep)) and not os.path.exists(str(gone))
    assert out["expected_bytes"] == out["freed_bytes"] == 5000


def test_force_deletes_a_changed_item(server, profile):
    scan(server, profile)
    target = profile / ".claude" / "shell-snapshots"
    with open(str(target / "f.bin"), "ab") as fh:
        fh.write(b"z" * 7)
    out = call(server, "disk_delete", {"paths": [str(target)], "mode": "permanent", "confirm": True,
                                       "force": True})
    assert out["changed"] == [] and out["deleted"] == [os.path.abspath(str(target))]
    assert out["freed_bytes"] == 5007 and out["expected_bytes"] == 5000
    assert out["difference_bytes"] == 7 and out["difference_human"].startswith("+")
    assert not os.path.exists(str(target))


def test_loose_files_are_reverified_from_what_was_proposed(server, profile):
    scan(server, profile)
    junk = call(server, "disk_junk", {"category": "Agentes de IA", "min_mb": 0.0005, "limit": 200})
    orphan = [i for i in junk["items"] if i.get("file") and i["path"].endswith("tmp-2")][0]["path"]
    with open(orphan, "ab") as fh:
        fh.write(b"cambiado")
    out = call(server, "disk_delete", {"paths": [orphan], "mode": "permanent", "confirm": True})
    assert out["deleted"] == [] and out["changed"][0]["now"]["size"] == 90_008
    assert os.path.isfile(orphan)
    # lo que se vuelve a proponer ya cuadra
    junk = call(server, "disk_explain", {"path": orphan})
    out = call(server, "disk_delete", {"paths": [orphan], "mode": "permanent", "confirm": True})
    assert out["deleted"] == [os.path.abspath(orphan)] and out["freed_bytes"] == 90_008 == out["expected_bytes"]


def test_files_without_a_reference_are_deleted_but_flagged_unverified(server, tmp_path):
    f = put(tmp_path / "suelto.bin", 321)
    out = call(server, "disk_delete", {"paths": [f], "mode": "permanent", "confirm": True})
    assert out["deleted"] == [os.path.abspath(f)]
    assert out["items"][0]["verified"] is False and out["items"][0]["expected_source"] == "live"
    assert out["freed_bytes"] == 321


def test_agent_never_deletes_ai_config_even_with_force(server, profile):
    scan(server, profile)
    for rel in ((".claude", "skills"), (".claude", ".credentials.json"), (".claude",)):
        p = os.path.join(str(profile), *rel)
        out = call(server, "disk_delete", {"paths": [p], "mode": "permanent", "confirm": True, "force": True},
                   expect=400)
        assert out["refused"] and "protected AI-tool data" in out["refused"][0]["reason"]
        assert os.path.exists(p)


# ------------------------------------------------ esperado frente a liberado

def test_trash_mode_separates_moved_bytes_from_space_freed_on_disk(server, profile, monkeypatch):
    from diskhoard import server as srv
    moved = []

    def fake_trash(paths):
        for p in paths:
            moved.append(p)
            shutil.rmtree(p) if os.path.isdir(p) else os.unlink(p)
        return True, ""

    monkeypatch.setattr(srv, "send_to_trash", fake_trash)
    monkeypatch.setattr(agentmod, "IS_WIN", True)
    scan(server, profile)
    target = str(profile / ".codex" / "sessions")
    out = call(server, "disk_delete", {"paths": [target]})
    assert moved == [os.path.abspath(target)]
    assert out["expected_bytes"] == 5000 and out["freed_bytes"] == 5000 and out["moved_to_bin_bytes"] == 5000
    assert out["freed_on_disk_bytes"] == 0
    assert "Recycle Bin" in out["note"] and "empties" in out["note"]


def test_given_expectation_and_real_measure_can_differ(server, tmp_path):
    from diskhoard import server as srv
    d = tmp_path / "x"
    put(d / "a.bin", 4000)
    r = srv.api_delete([str(d)], "perm", expected={str(d): {"size": 1000}}, force=True)
    job = srv.ST.jobs[r["job"]]
    deadline = time.time() + 10
    while not job["finished"] and time.time() < deadline:
        time.sleep(0.05)
    assert job["expected_bytes"] == 1000 and job["freed_bytes"] == 4000
    assert job["diff_bytes"] == 3000 and job["items"][0]["expected_source"] == "given"


def test_http_delete_endpoint_reports_changed_expected_and_freed(server, profile):
    scan(server, profile)

    def post(path, body):
        req = urllib.request.Request(server["url"] + path, method="POST", data=json.dumps(body).encode())
        req.add_header("X-DH-Token", server["token"])
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    def wait(jid):
        for _ in range(200):
            req = urllib.request.Request(server["url"] + "/api/job?id=" + jid)
            req.add_header("X-DH-Token", server["token"])
            with urllib.request.urlopen(req, timeout=10) as r:
                j = json.loads(r.read())
            if j["finished"]:
                return j
            time.sleep(0.05)
        raise AssertionError("el trabajo no termino")

    ok = str(profile / "AppData" / "Roaming" / "Cursor" / "Crashpad")
    moved = str(profile / "AppData" / "Roaming" / "Cursor" / "logs")
    with open(os.path.join(moved, "f.bin"), "ab") as fh:
        fh.write(b"q")
    j = wait(post("/api/delete", {"paths": [ok, moved], "mode": "perm"})["job"])
    assert j["expected_bytes"] == 5000 and j["freed_bytes"] == 5000 and j["diff_bytes"] == 0
    assert j["freed_on_disk_bytes"] == 5000 and j["binned_bytes"] == 0
    assert [c["hint"] for c in j["changed"]] == ["rescan"] and j["changed"][0]["path"].endswith("logs")
    assert os.path.isdir(moved) and not os.path.exists(ok)
    j = wait(post("/api/delete", {"paths": [moved], "mode": "perm", "force": True})["job"])
    assert j["changed"] == [] and j["freed_bytes"] == 5001 and j["force"] is True


def test_dir_listing_tags_ai_folders_and_files(server, profile):
    scan(server, profile)
    req = urllib.request.Request(server["url"] + "/api/dir?path=" + urllib.request.quote(str(profile / ".claude")))
    req.add_header("X-DH-Token", server["token"])
    with urllib.request.urlopen(req, timeout=10) as r:
        d = json.loads(r.read())
    tags = {e["name"]: (e["tag"] or {}).get("safety") for e in d["entries"]}
    assert tags["cache"] == "safe" and tags["projects"] == "review"
    assert tags["skills"] == "danger" and tags["plugins"] == "danger"
    assert tags[".credentials.json"] == "danger" and tags["settings.json"] == "danger"
    assert tags["history.jsonl"] == "review" and tags["stats-cache.json"] == "safe"
    assert tags["chrome"] is None


def test_disk_delete_schema_has_force_and_stays_short():
    tool = {t["name"]: t for t in agentmod.CATALOG}["disk_delete"]
    assert "force" in tool["inputSchema"]["properties"]
    assert tool["annotations"]["destructiveHint"] is True
    first = tool["description"].split("\n", 1)[0]
    assert len(first) <= 110


def test_junk_inside_protected_ai_folders_is_not_listed(tmp_path):
    """A plugin ships its own .claude\\plans or node_modules: deleting them breaks the plugin."""
    home = tmp_path / "home"
    nested = home / ".claude" / "plugins" / "marketplaces" / "someone" / ".claude" / "plans"
    nested.mkdir(parents=True)
    (nested / "p.md").write_bytes(b"x" * 4096)
    nm = home / ".claude" / "plugins" / "tool" / "node_modules"
    nm.mkdir(parents=True)
    (nm / "a.js").write_bytes(b"y" * 4096)
    plans = home / ".claude" / "plans"
    plans.mkdir(parents=True)
    (plans / "mine.md").write_bytes(b"z" * 4096)
    sc = scanmod.Scanner(str(home))
    sc.start()
    while not sc.done:
        time.sleep(0.02)
    items = junkmod.scan_junk(sc.root, sc.root_display, min_bytes=0)
    paths = [i["path"].replace("/", "\\").lower() for i in items]
    assert not any("\\plugins\\" in p for p in paths), paths
    assert any(p.endswith("\\.claude\\plans") for p in paths), paths
