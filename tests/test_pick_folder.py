# -*- coding: utf-8 -*-
"""Native folder picker endpoint (the dialog itself is replaced by a fake process)."""
import subprocess

import pytest


@pytest.fixture
def srv(server):
    """The server module, imported only once the test data folder is in force: importing it reads (and writes) the
    token of the data folder of the moment, so importing it at collection time used the real data folder."""
    return server["mod"]


def _fake_run(chosen):
    def run(args, **kw):
        with open(args[3], "w", encoding="utf-8") as fh:
            fh.write(chosen)
        return subprocess.CompletedProcess(args, 0)
    return run


def test_pick_folder_returns_path(srv, monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", _fake_run(str(tmp_path)))
    out = srv.api_pick_folder(str(tmp_path))
    assert out == {"path": str(tmp_path)}


def test_pick_folder_cancelled(srv, monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run(""))
    assert srv.api_pick_folder("") == {"cancelled": True}


def test_pick_folder_single_dialog(srv, monkeypatch):
    assert srv._PICK_LOCK.acquire(blocking=False)
    try:
        assert "error" in srv.api_pick_folder("")
    finally:
        srv._PICK_LOCK.release()
