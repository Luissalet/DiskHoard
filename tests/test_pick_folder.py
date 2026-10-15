# -*- coding: utf-8 -*-
"""Native folder picker endpoint (the dialog itself is replaced by a fake process)."""
import subprocess

from diskhoard import server


def _fake_run(chosen):
    def run(args, **kw):
        with open(args[3], "w", encoding="utf-8") as fh:
            fh.write(chosen)
        return subprocess.CompletedProcess(args, 0)
    return run


def test_pick_folder_returns_path(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", _fake_run(str(tmp_path)))
    out = server.api_pick_folder(str(tmp_path))
    assert out == {"path": str(tmp_path)}


def test_pick_folder_cancelled(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run(""))
    assert server.api_pick_folder("") == {"cancelled": True}


def test_pick_folder_single_dialog(monkeypatch):
    assert server._PICK_LOCK.acquire(blocking=False)
    try:
        assert "error" in server.api_pick_folder("")
    finally:
        server._PICK_LOCK.release()
