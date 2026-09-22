# -*- coding: utf-8 -*-
"""Un arbol de prueba con basura conocida, y un servidor DiskHoard vivo."""
import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _write(path, size):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(b"\0" * size)


@pytest.fixture(scope="session")
def tree(tmp_path_factory):
    """proyecto/ con node_modules (seguro), .git (no tocar), un build con
    package.json al lado, un venv con pyvenv.cfg, un video gordo y un .iso."""
    base = tmp_path_factory.mktemp("arbol")
    p = base / "proyecto"
    _write(str(p / "node_modules" / "a" / "index.js"), 300_000)
    _write(str(p / "node_modules" / "b" / "index.js"), 200_000)
    _write(str(p / ".git" / "objects" / "pack" / "x.pack"), 150_000)
    _write(str(p / "package.json"), 50)
    _write(str(p / "dist" / "bundle.js"), 120_000)
    _write(str(p / ".venv" / "pyvenv.cfg"), 20)
    _write(str(p / ".venv" / "lib" / "site.py"), 90_000)
    _write(str(base / "videos" / "peli.mp4"), 900_000)
    _write(str(base / "descargas" / "imagen.iso"), 700_000)
    _write(str(base / "descargas" / "notas.txt"), 10)
    old = str(base / "videos" / "peli.mp4")
    os.utime(old, (1_000_000_000, 1_000_000_000))  # 2001
    return base


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("datos")
    os.environ["DISKHOARD_DATA_DIR"] = str(d)
    return d


@pytest.fixture(scope="session")
def server(data_dir):
    from diskhoard import server as srv
    httpd, url = srv.serve(port=0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = url.split("/?", 1)[0]
    yield {"mod": srv, "url": base, "token": srv.TOKEN, "httpd": httpd}
    httpd.shutdown()
