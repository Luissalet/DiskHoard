# -*- coding: utf-8 -*-
"""El ultimo escaneo sobrevive a un reinicio: se guarda en data/ y se carga al arrancar."""
import os
import time

from diskhoard import scanner as scanmod


def _scan(path):
    sc = scanmod.Scanner(str(path))
    sc.start()
    deadline = time.time() + 30
    while not sc.done and time.time() < deadline:
        time.sleep(0.05)
    assert sc.done and not sc.error
    return sc


def test_snapshot_round_trip(tree, tmp_path):
    sc = _scan(tree)
    target = str(tmp_path / "last-scan.pkl.gz")
    assert scanmod.save_snapshot(sc, target)
    back = scanmod.load_snapshot(target)
    assert back is not None and back.done and back.from_snapshot
    assert back.root.size == sc.root.size and back.root.nfiles == sc.root.nfiles
    for path, node in scanmod.walk(sc.root, sc.root_display):
        twin = scanmod.find(back.root, back.root_display, path)
        assert twin is not None, path
        assert (twin.size, twin.own, twin.nfiles, twin.nown) == (node.size, node.own, node.nfiles, node.nown)
    assert back.top_files[0] == sc.top_files[0]
    assert back.progress()["from_snapshot"] is True


def test_snapshot_refuses_bad_files(tmp_path):
    assert scanmod.load_snapshot(str(tmp_path / "missing.pkl.gz")) is None
    junk = tmp_path / "junk.pkl.gz"
    junk.write_bytes(b"not gzip at all")
    assert scanmod.load_snapshot(str(junk)) is None


def test_server_restores_the_saved_scan(tree, server):
    srv = server["mod"]
    sc = _scan(tree)
    assert scanmod.save_snapshot(sc, srv.snapshot_path())
    with srv.ST.lock:
        srv.ST.scanner = None
    assert srv.restore_snapshot() is True
    assert srv.ST.scanner.from_snapshot
    out, err = srv.AGENT.call("disk_dir", {})
    assert not err and out["snapshot"]["hint"].startswith("Tree from the last saved scan")
    fresh = srv.api_scan(str(tree))  # a new scan replaces the restored tree
    assert fresh["ok"]
    deadline = time.time() + 30
    while not srv.ST.scanner.done and time.time() < deadline:
        time.sleep(0.05)
    out, err = srv.AGENT.call("disk_dir", {})
    assert not err and "snapshot" not in out
    deadline = time.time() + 10  # ...and is saved in turn
    while time.time() < deadline and os.path.getmtime(srv.snapshot_path()) < srv.ST.scanner.finished - 1:
        time.sleep(0.05)
