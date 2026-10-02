# -*- coding: utf-8 -*-
"""Partir carpetas en ZIPs: lógica pura, trabajos y rutas HTTP. Todo con datos inventados."""
import json
import os
import random
import threading
import time
import urllib.error
import urllib.request
import zipfile

import pytest

from diskhoard import zipsplit as zs
from diskhoard.zipsplit import ZipSplitError


# ----------------------------------------------------------------- utilidades

def make_tree(base, sizes, seed=7, folder="origen"):
    """Árbol con ficheros incompresibles (aleatorios) de los tamaños dados; devuelve (raíz, {rel: bytes})."""
    rng = random.Random(seed)
    root = os.path.join(str(base), folder)
    files = {}
    for i, size in enumerate(sizes):
        sub = ("sub%d" % (i % 3)) if i % 2 else ""
        rel = ("%s/f%03d.bin" % (sub, i)) if sub else "f%03d.bin" % i
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = rng.randbytes(size)
        with open(path, "wb") as fh:
            fh.write(data)
        files[rel] = data
    return root, files


def opts(root, out, **kw):
    args = {"path": root, "out_dir": str(out), "limit": 300_000, "margin": 10_000}
    args.update(kw)
    return zs.options_from(args)


def read_back(parts):
    """Todo lo que hay en las partes: {arcname: bytes}. Comprueba la integridad de cada ZIP."""
    got = {}
    for p in parts:
        with zipfile.ZipFile(p["path"]) as zf:
            assert zf.testzip() is None
            for info in zf.infolist():
                assert "\\" not in info.filename
                assert info.filename not in got, "fichero repetido: " + info.filename
                got[info.filename] = zf.read(info)
    return got


def leftovers(folder):
    return [n for n in os.listdir(str(folder)) if n.endswith(".tmp")]


# -------------------------------------------------------------------- tamaños

def test_parse_size_decimal_binary_and_bytes():
    assert zs.parse_size("990mb") == 990_000_000
    assert zs.parse_size("990 MB") == 990_000_000
    assert zs.parse_size("990mib") == 990 * 1024 ** 2
    assert zs.parse_size("50000000") == 50_000_000
    assert zs.parse_size(2048) == 2048
    assert zs.parse_size("1,5gb") == 1_500_000_000
    assert zs.parse_size("1.5GiB") == int(1.5 * 1024 ** 3)
    assert zs.parse_size("25k") == 25_000 and zs.parse_size("2tb") == 2 * 1000 ** 4
    assert zs.parse_size("0") == 0
    for bad in ("", "mb", "12xb", "-5mb", "1..2mb", None, True):
        with pytest.raises(ZipSplitError):
            zs.parse_size(bad)


def test_human_is_decimal():
    assert zs.human(990_000_000) == "990.00 MB"
    assert zs.human(999) == "999 B"
    assert zs.human(1_500_000_000) == "1.50 GB"


def test_options_validation():
    with pytest.raises(ZipSplitError):
        zs.options_from({})
    for bad in ({"sort": "random"}, {"compression": "lzma"}, {"too_large": "burn"}, {"prefix": "a/b"},
                {"limit": "1xb"}):
        with pytest.raises(ZipSplitError):
            zs.options_from(dict(bad, path="/x"))
    o = zs.options_from({"path": "/x", "compression": "deflate", "include": "*.jpg, *.png"})
    assert o.compression == "deflated" and o.include == ["*.jpg", "*.png"]
    assert o.exclude == list(zs.DEFAULT_EXCLUDE)             # por defecto
    assert zs.options_from({"path": "/x", "exclude": []}).exclude == []   # una lista explícita la sustituye


# ------------------------------------------------------------ cuentas del ZIP

def test_zip64_overheads():
    n = 10
    assert zs.local_overhead(n, 1000) == 30 + n
    assert zs.local_overhead(n, 5 * 1024 ** 3) == 30 + n + 20
    assert zs.local_overhead(n, 5 * 1024 ** 3, streaming=True) == 30 + n + 20 + 24
    assert zs.local_overhead(n, 1000, streaming=True) == 30 + n + 16
    assert zs.central_overhead(n) == 46 + n and zs.central_overhead(n, zip64=True) == 46 + n + 28
    assert zs.end_overhead(3) == 22
    assert zs.end_overhead(70_000) == 22 + 56 + 20 and zs.end_overhead(3, zip64=True) == 98
    # la cabecera local que escribe zipfile coincide con la cuenta
    zi = zipfile.ZipInfo("x" * n)
    zi.CRC = 0
    zi.compress_size = 0
    zi.file_size = 5 * 1024 ** 3
    assert len(zi.FileHeader(True)) == zs.local_overhead(n, 5 * 1024 ** 3)       # zipfile pide ZIP64 al pasar de 2 GiB
    zi.file_size = 1000
    assert len(zi.FileHeader(False)) == zs.local_overhead(n, 1000)
    assert zs.data_bound(1000, "stored") == 1000
    assert zs.data_bound(10 ** 6, "deflated") > 10 ** 6


def test_budget_switches_to_zip64_costs():
    b = zs.Budget(10 ** 12, "stored")
    small = b.projected(10, 1000)
    assert small == 30 + 10 + 1000 + 46 + 10 + 22
    huge = b.projected(10, 5 * 1024 ** 3)
    assert huge == 30 + 10 + 20 + 5 * 1024 ** 3 + 46 + 10 + 28 + 22 + 56 + 20
    b.add(10, 5 * 1024 ** 3)
    assert b.final_size() == 30 + 10 + 20 + 5 * 1024 ** 3 + 46 + 10 + 28 + 98
    b.reset()
    b.pos = zs.ZIP64_LIMIT - 100          # un archivo que cruza los 2 GiB por acumulación
    b.n = 4
    b.cd = 4 * 56
    assert b.projected(10, 1000) == b.pos + 40 + 1000 + 5 * 28 + 4 * 56 + 56 + 98


def test_real_zip64_paths_stay_inside_the_limit(tmp_path, monkeypatch):
    """Con los umbrales ZIP64 de zipfile bajados, el código real escribe extras ZIP64 y el límite sigue valiendo."""
    monkeypatch.setattr(zipfile, "ZIP64_LIMIT", 40_000)
    monkeypatch.setattr(zs, "ZIP64_LIMIT", 40_000)
    monkeypatch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 6)
    monkeypatch.setattr(zs, "ZIP_FILECOUNT_LIMIT", 6)
    root, files = make_tree(tmp_path, [9000] * 30 + [50_000, 3000, 70_000])
    for comp in ("stored", "deflated"):
        o = opts(root, tmp_path / ("o_" + comp), limit=200_000, margin=2_000, compression=comp, too_large="skip")
        pl = zs.plan(o)
        r = zs.split(o)
        assert r["part_count"] >= 2
        for p in r["parts"]:
            assert os.path.getsize(p["path"]) == p["size"] <= 200_000
        for est, real in zip(pl["parts"], r["parts"]):
            assert real["size"] <= est["est_size"]
        assert any(b"PK\x06\x06" in open(p["path"], "rb").read() for p in r["parts"])    # hubo registro ZIP64 real
        got = read_back(r["parts"])
        assert set(got) == set(files) - {k for k, v in files.items() if len(v) > 190_000}  # >190 KB no cabe ni solo
        assert all(files[k] == v for k, v in got.items())


# ----------------------------------------------------------------------- plan

def test_plan_is_exact_for_stored_and_writes_nothing(tmp_path):
    root, files = make_tree(tmp_path, [40_000, 90_000, 120_000, 25_000, 70_000, 60_000, 5_000, 100_000])
    out = tmp_path / "salida"
    o = opts(root, out)
    pl = zs.plan(o, files=True)
    assert not out.exists()
    assert pl["dry_run"] and pl["estimate"] == "exact" and pl["effective_limit"] == 290_000
    assert pl["files"] == len(files) and pl["too_large_count"] == 0
    planned = [f["path"] for p in pl["parts"] for f in p["files"]]
    assert sorted(planned) == sorted(files)
    r = zs.split(o)
    assert [p["name"] for p in r["parts"]] == [p["name"] for p in pl["parts"]]
    assert [p["size"] for p in r["parts"]] == [p["est_size"] for p in pl["parts"]]
    assert all(p["files"] == q["file_count"] for p, q in zip(r["parts"], pl["parts"]))


def test_plan_lists_too_large_and_deflate_is_an_upper_bound(tmp_path):
    root, files = make_tree(tmp_path, [50_000, 400_000, 60_000])
    pl = zs.plan(opts(root, tmp_path / "o", compression="deflated", too_large="split"))
    assert pl["estimate"] == "upper_bound" and "cota" in pl["note"]
    assert [t["size"] for t in pl["too_large"]] == [400_000]
    assert pl["too_large"][0]["volumes_estimate"] >= 2
    assert pl["files"] == 2


def test_sort_by_size_puts_small_files_first(tmp_path):
    root, files = make_tree(tmp_path, [90_000, 10_000, 50_000])
    pl = zs.plan(opts(root, tmp_path / "o", sort="size", limit=400_000), files=True)
    sizes = [f["size"] for f in pl["parts"][0]["files"]]
    assert sizes == sorted(sizes)


# ---------------------------------------------------------------- escritura real

@pytest.mark.parametrize("comp", ["stored", "deflated"])
def test_real_split_respects_the_limit_with_incompressible_data(tmp_path, comp):
    rng = random.Random(3)
    sizes = [rng.randint(1_000, 140_000) for _ in range(60)] + [0, 1, 0]
    root, files = make_tree(tmp_path, sizes)
    o = opts(root, tmp_path / "o", compression=comp)
    r = zs.split(o)
    assert r["ok"] and not r["cancelled"] and not r["errors"]
    assert r["files_added"] == len(files)
    assert r["part_count"] >= 5
    for p in r["parts"]:
        real = os.path.getsize(p["path"])
        assert real == p["size"] and real <= 300_000 and p["within_limit"]
        assert real <= 290_000 and p["within_effective"]
    assert [p["name"] for p in r["parts"]] == ["part_%03d.zip" % (i + 1) for i in range(r["part_count"])]
    got = read_back(r["parts"])
    assert set(got) == set(files)
    assert all(got[k] == files[k] for k in files)
    assert leftovers(o.out_dir) == []
    assert "manifest.txt" in os.listdir(o.out_dir)


def test_deflate_compresses_when_it_can_and_still_fits(tmp_path):
    root = tmp_path / "texto"
    root.mkdir()
    for i in range(12):
        (root / ("t%02d.txt" % i)).write_bytes((b"hola mundo " * 20_000))      # 220 KB cada uno
    r = zs.split(opts(str(root), tmp_path / "o", compression="deflated", limit=300_000, margin=0))
    assert sum(p["files"] for p in r["parts"]) == 12
    assert all(p["size"] <= 300_000 for p in r["parts"])
    assert r["bytes_out"] < r["bytes_in"] / 10


def test_arcnames_keep_the_structure_with_forward_slashes_and_utf8(tmp_path):
    root = tmp_path / "origen"
    (root / "niño" / "dentro").mkdir(parents=True)
    (root / "niño" / "dentro" / "año.txt").write_bytes(b"x" * 100)
    (root / "raíz.txt").write_bytes(b"y" * 50)
    r = zs.split(opts(str(root), tmp_path / "o"))
    with zipfile.ZipFile(r["parts"][0]["path"]) as zf:
        assert sorted(zf.namelist()) == ["niño/dentro/año.txt", "raíz.txt"]
        assert all(i.flag_bits & 0x800 for i in zf.infolist())          # indicador UTF-8


def test_empty_folder_and_no_matches(tmp_path):
    root = tmp_path / "vacia"
    root.mkdir()
    r = zs.split(opts(str(root), tmp_path / "o"))
    assert r["parts"] == [] and "No hay ficheros" in r["message"]


# ------------------------------------------------------------- demasiado grandes

def big_tree(tmp_path):
    return make_tree(tmp_path, [50_000, 650_000, 60_000, 40_000])


def test_too_large_skip_is_the_default_and_reports(tmp_path):
    root, files = big_tree(tmp_path)
    r = zs.split(opts(root, tmp_path / "o"))
    assert [t["result"] for t in r["too_large"]] == ["skipped"] and r["too_large"][0]["size"] == 650_000
    got = read_back(r["parts"])
    assert len(got) == 3 and all(len(v) < 100_000 for v in got.values())
    assert os.path.exists(os.path.join(root, *r["too_large"][0]["path"].split("/")))   # no se toca


def test_too_large_fail_refuses_before_writing(tmp_path):
    root, _ = big_tree(tmp_path)
    out = tmp_path / "o"
    with pytest.raises(ZipSplitError) as exc:
        zs.split(opts(root, out, too_large="fail"))
    assert "too_large=fail" in str(exc.value) and "650" in str(exc.value)
    assert not out.exists() or os.listdir(str(out)) == []


def test_too_large_move_needs_confirm_and_moves(tmp_path):
    root, files = big_tree(tmp_path)
    big_rel = next(k for k, v in files.items() if len(v) == 650_000)
    with pytest.raises(ZipSplitError) as exc:
        zs.split(opts(root, tmp_path / "o", too_large="move"))
    assert "confirm" in str(exc.value)
    assert os.path.exists(os.path.join(root, *big_rel.split("/")))
    # el plan en seco no necesita confirmación porque no mueve nada
    assert zs.plan(opts(root, tmp_path / "o", too_large="move"))["too_large_count"] == 1
    r = zs.split(opts(root, tmp_path / "o", too_large="move"), confirm=True)
    moved = os.path.join(str(tmp_path / "o"), "too_large", *big_rel.split("/"))
    assert r["too_large"][0]["result"] == "moved" and r["too_large"][0]["moved_to"] == moved
    assert open(moved, "rb").read() == files[big_rel]
    assert not os.path.exists(os.path.join(root, *big_rel.split("/")))


@pytest.mark.parametrize("comp", ["stored", "deflated"])
def test_too_large_split_makes_volumes_that_rejoin(tmp_path, comp):
    root, files = big_tree(tmp_path)
    big_rel = next(k for k, v in files.items() if len(v) == 650_000)
    o = opts(root, tmp_path / "o", too_large="split", compression=comp)
    r = zs.split(o)
    row = r["too_large"][0]
    assert row["result"] == "split" and len(row["volumes"]) >= 3
    assert all(v["size"] <= 290_000 and v["within_limit"] for v in row["volumes"])
    assert [v["name"] for v in row["volumes"]][:2] == [row["volumes_base"] + ".001", row["volumes_base"] + ".002"]
    assert row["volumes_base"].startswith("part_") and row["volumes_base"].endswith(".zip")
    assert "copy /b" in row["join_windows"]
    joined = tmp_path / "unido.zip"
    with open(str(joined), "wb") as out:
        for v in row["volumes"]:
            assert os.path.getsize(v["path"]) == v["size"]
            with open(v["path"], "rb") as fh:
                out.write(fh.read())
    with zipfile.ZipFile(str(joined)) as zf:
        assert zf.testzip() is None
        assert zf.namelist() == [big_rel]
        assert zf.read(big_rel) == files[big_rel]
    assert leftovers(o.out_dir) == []
    got = read_back(r["parts"])                       # el resto sigue yendo en partes normales
    assert len(got) == 3 and big_rel not in got
    assert r["bytes_out"] == sum(p["size"] for p in r["parts"]) + sum(v["size"] for v in row["volumes"])


# ------------------------------------------------------------ filtros y destino

def test_include_exclude_and_default_excludes(tmp_path):
    root = tmp_path / "origen"
    (root / "fotos").mkdir(parents=True)
    (root / "node_modules").mkdir()
    for name in ("fotos/a.jpg", "fotos/b.png", "notas.txt", "Thumbs.db", "desktop.ini", "x.tmp", "~$doc.docx",
                 "node_modules/m.js"):
        (root / name).write_bytes(b"d" * 100)
    names = lambda r: sorted(read_back(r["parts"]))
    r = zs.split(opts(str(root), tmp_path / "o1"))
    assert names(r) == ["fotos/a.jpg", "fotos/b.png", "node_modules/m.js", "notas.txt"]
    assert r["excluded"] == 4
    r = zs.split(opts(str(root), tmp_path / "o2", include="*.jpg, *.png"))
    assert names(r) == ["fotos/a.jpg", "fotos/b.png"]
    r = zs.split(opts(str(root), tmp_path / "o3", exclude="node_modules, *.png, *.tmp"))
    assert names(r) == ["Thumbs.db", "desktop.ini", "fotos/a.jpg", "notas.txt", "~$doc.docx"]
    r = zs.split(opts(str(root), tmp_path / "o4", exclude="fotos/*"))
    assert "fotos/a.jpg" not in names(r) and "notas.txt" in names(r)


def test_default_output_is_next_to_the_source_never_inside(tmp_path):
    root, _ = make_tree(tmp_path, [1000, 2000])
    o = zs.options_from({"path": root})
    r = zs.split(o)
    assert r["out_dir"] == root + "_zips"
    assert os.path.isfile(os.path.join(root + "_zips", "part_001.zip"))
    assert not os.path.exists(os.path.join(root, "part_001.zip"))


def test_output_inside_input_or_equal_is_refused(tmp_path):
    root, _ = make_tree(tmp_path, [1000])
    for bad in (os.path.join(root, "zips"), root, os.path.join(root, "a", "b")):
        with pytest.raises(ZipSplitError) as exc:
            zs.plan(zs.options_from({"path": root, "out_dir": bad}))
        assert "dentro" in str(exc.value)
        with pytest.raises(ZipSplitError):
            zs.split(zs.options_from({"path": root, "out_dir": bad}))
    assert not os.path.exists(os.path.join(root, "zips"))


def test_output_must_be_empty_or_new_unless_overwrite(tmp_path):
    root, files = make_tree(tmp_path, [30_000, 30_000, 30_000])
    out = tmp_path / "o"
    zs.split(opts(root, out, limit=50_000, margin=1_000))
    assert len(list(out.glob("part_*.zip"))) == 3
    with pytest.raises(ZipSplitError) as exc:
        zs.split(opts(root, out, limit=50_000, margin=1_000))
    assert "no está vacía" in str(exc.value)
    (out / "mis_notas.txt").write_text("importante")
    (out / "otro_001.zip").write_bytes(b"no soy de este prefijo")
    r = zs.split(opts(root, out, limit=200_000, margin=1_000, overwrite=True))
    assert r["part_count"] == 1
    assert sorted(os.listdir(str(out))) == ["manifest.txt", "mis_notas.txt", "otro_001.zip", "part_001.zip"]
    assert (out / "mis_notas.txt").read_text() == "importante"      # solo se sustituyen partes con el mismo prefijo
    assert leftovers(out) == []


def test_output_that_is_a_file_is_refused(tmp_path):
    root, _ = make_tree(tmp_path, [1000])
    f = tmp_path / "fichero"
    f.write_text("x")
    with pytest.raises(ZipSplitError):
        zs.plan(zs.options_from({"path": root, "out_dir": str(f)}))


def test_output_and_drive_root_safety(tmp_path, monkeypatch):
    root, _ = make_tree(tmp_path, [1000])
    fake = tmp_path / "fakewin"
    (fake / "System32").mkdir(parents=True)
    pf = tmp_path / "fakepf"
    pf.mkdir()
    monkeypatch.setenv("SystemRoot", str(fake))
    monkeypatch.setenv("ProgramFiles", str(pf))
    home = tmp_path / "perfil"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    drive = os.path.abspath(os.sep)
    for bad in (drive, str(fake), str(fake / "System32"), str(pf), str(pf / "App"), str(home)):
        assert zs.output_refusal(bad), bad
        with pytest.raises(ZipSplitError) as exc:
            zs.plan(zs.options_from({"path": root, "out_dir": bad}))
        assert "No se escribe el destino" in str(exc.value)
    assert zs.output_refusal(str(home / "Descargas" / "zips")) is None
    assert zs.output_refusal("relativa") is not None
    # un origen que es una unidad entera exige confirm, y la lectura no empieza sin él
    with pytest.raises(ZipSplitError) as exc:
        zs.plan(zs.options_from({"path": drive, "out_dir": str(tmp_path / "o")}))
    assert "confirm" in str(exc.value)


def test_limit_and_margin_validation(tmp_path):
    root, _ = make_tree(tmp_path, [1000])
    for lim, mar in (("0", "0"), ("1mb", "1mb"), ("1mb", "2mb"), ("1000", "0")):
        with pytest.raises(ZipSplitError):
            zs.plan(zs.options_from({"path": root, "limit": lim, "margin": mar, "out_dir": str(tmp_path / "o")}))
    with pytest.raises(ZipSplitError):
        zs.plan(zs.options_from({"path": str(tmp_path / "no-existe"), "out_dir": str(tmp_path / "o")}))
    with pytest.raises(ZipSplitError):
        zs.plan(zs.options_from({"path": "relativa", "out_dir": str(tmp_path / "o")}))


# -------------------------------------------------------------------- cancelar

def test_cancel_midway_keeps_closed_parts_and_deletes_the_partial_one(tmp_path):
    root, files = make_tree(tmp_path, [100_000] * 12)
    o = opts(root, tmp_path / "o")
    seen = {"files": 0}

    def progress(p):
        seen["files"] = p["files_done"]

    r = zs.split(o, should_stop=lambda: seen["files"] >= 5, progress=progress)
    assert r["cancelled"] is True
    assert leftovers(o.out_dir) == []
    names = sorted(n for n in os.listdir(o.out_dir) if n.endswith(".zip"))
    assert names == [p["name"] for p in r["parts"]] == ["part_001.zip", "part_002.zip"]   # solo las cerradas
    got = read_back(r["parts"])
    assert len(got) == 4 and all(got[k] == files[k] for k in got)       # el quinto fichero iba en la parte a medias
    manifest = open(os.path.join(o.out_dir, "manifest.txt"), encoding="utf-8").read()
    assert "se canceló" in manifest


def test_cancel_mid_file_leaves_no_zip_at_all(tmp_path):
    root, _ = make_tree(tmp_path, [2_500_000], folder="uno")
    o = opts(root, tmp_path / "o", limit=5_000_000, margin=1000)
    seen = {"b": 0}
    r = zs.split(o, should_stop=lambda: seen["b"] > 0, progress=lambda p: seen.__setitem__("b", p["bytes_done"]))
    assert r["cancelled"] and r["parts"] == []
    assert [n for n in os.listdir(o.out_dir) if n.endswith((".zip", ".tmp"))] == []


def test_cancel_while_splitting_volumes_removes_them(tmp_path):
    root, _ = make_tree(tmp_path, [3_000_000], folder="uno")
    o = opts(root, tmp_path / "o", limit=500_000, margin=1000, too_large="split")
    seen = {"b": 0}
    r = zs.split(o, should_stop=lambda: seen["b"] >= 1_500_000,
                 progress=lambda p: seen.__setitem__("b", p["bytes_done"]))
    assert r["cancelled"]
    assert [n for n in os.listdir(o.out_dir) if ".zip" in n] == []


def test_unreadable_file_is_reported_not_fatal(tmp_path, monkeypatch):
    root, files = make_tree(tmp_path, [10_000, 20_000, 30_000])
    victim = os.path.join(root, "f000.bin")
    real_open = open

    def fake_open(path, *a, **k):
        # on Windows the module opens long_path() spellings (\\?\C:\...): compare without that prefix
        if os.path.normcase(os.fspath(path).replace("\\\\?\\", "")) == os.path.normcase(victim) and a and a[0] == "rb":
            raise PermissionError(13, "Acceso denegado")
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)
    r = zs.split(opts(root, tmp_path / "o"))
    monkeypatch.undo()
    assert len(r["errors"]) == 1 and "f000.bin" in r["errors"][0]
    assert sorted(read_back(r["parts"])) == sorted(k for k in files if k != "f000.bin")


def test_symlinks_are_not_followed(tmp_path):
    root, files = make_tree(tmp_path, [1000, 2000])
    outside = tmp_path / "fuera"
    outside.mkdir()
    (outside / "secreto.txt").write_text("no")
    try:
        os.symlink(str(outside), os.path.join(root, "enlace"))
        os.symlink(os.path.join(root, "f000.bin"), os.path.join(root, "enlace.bin"))
    except (OSError, NotImplementedError):
        pytest.skip("sin permiso para crear enlaces simbólicos")
    r = zs.split(opts(root, tmp_path / "o"))
    assert r["skipped_links"] == 2
    assert sorted(read_back(r["parts"])) == sorted(files)


# ------------------------------------------------------------------- manifiesto

def test_manifest_lists_parts_and_contents_and_can_be_disabled(tmp_path):
    root, files = big_tree(tmp_path)
    r = zs.split(opts(root, tmp_path / "o", too_large="split"))
    text = open(os.path.join(str(tmp_path / "o"), "manifest.txt"), encoding="utf-8").read()
    assert r["manifest"].endswith("manifest.txt")
    for p in r["parts"]:
        assert p["name"] in text
    for rel in files:
        assert rel in text
    assert ".zip.001" in text and "copy /b" in text and "Límite: 300.00 KB" in text
    r2 = zs.split(opts(root, tmp_path / "o2", manifest=False))
    assert "manifest.txt" not in os.listdir(str(tmp_path / "o2")) and "manifest" not in r2


# ---------------------------------------------------------------------- trabajo

def wait_job(job, timeout=30):
    end = time.time() + timeout
    while job.running and time.time() < end:
        time.sleep(0.05)
    assert not job.running
    return job.snapshot()


def test_job_runs_in_a_thread_with_progress_and_summary(tmp_path):
    root, files = make_tree(tmp_path, [100_000] * 8)
    reg = zs.JobRegistry()
    job = reg.start(opts(root, tmp_path / "o"))
    snap = wait_job(job)
    assert snap["state"] == "done" and snap["finished"] and snap["percent"] == 100.0
    assert snap["bytes_done"] == snap["bytes_total"] == 800_000 and snap["files_done"] == 8
    assert snap["summary"]["part_count"] >= 3 and snap["parts_done"] == snap["summary"]["part_count"]
    assert reg.get() is job and reg.get(job.id) is job and reg.get("999") is None


def test_only_one_job_at_a_time_and_cancel(tmp_path):
    root, _ = make_tree(tmp_path, [1_500_000] * 6)
    reg = zs.JobRegistry()
    job = reg.start(opts(root, tmp_path / "o", limit=2_000_000, margin=1000))
    with pytest.raises(ZipSplitError) as exc:
        reg.start(opts(root, tmp_path / "o2"))
    assert "en marcha" in str(exc.value)
    job.cancel()
    snap = wait_job(job)
    assert snap["state"] in ("cancelled", "done")
    if (tmp_path / "o").exists():
        assert leftovers(tmp_path / "o") == []
    # tras acabar se puede lanzar otro
    again = reg.start(opts(root, tmp_path / "o3", limit=2_000_000, margin=1000))
    again.cancel()
    wait_job(again)


def test_job_error_is_reported(tmp_path):
    root, _ = big_tree(tmp_path)
    reg = zs.JobRegistry()
    job = reg.start(opts(root, tmp_path / "o", too_large="fail"))
    snap = wait_job(job)
    assert snap["state"] == "error" and "too_large=fail" in snap["error"]


# ------------------------------------------------------------------------- HTTP

def http(server, method, path, body=None, auth=True):
    req = urllib.request.Request(server["url"] + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if auth:
        req.add_header("X-DH-Token", server["token"])
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def wait_http_job(server, jid=None, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        code, j = http(server, "GET", "/api/zip/job" + ("?id=" + jid if jid else ""))
        if j.get("finished"):
            return j
        time.sleep(0.1)
    raise AssertionError("el trabajo no terminó")


def test_http_routes_plan_split_job_cancel(server, tmp_path):
    root, files = make_tree(tmp_path, [100_000] * 7)
    body = {"path": root, "out_dir": str(tmp_path / "o"), "limit": "300000", "margin": "10000"}
    code, plan = http(server, "POST", "/api/zip/plan", body)
    assert code == 200 and plan["dry_run"] and plan["part_count"] >= 3 and not (tmp_path / "o").exists()
    code, started = http(server, "POST", "/api/zip/split", body)
    assert code == 200 and started["job"] and started["out_dir"] == str(tmp_path / "o")
    j = wait_http_job(server, started["job"])
    assert j["state"] == "done" and j["summary"]["files_added"] == 7
    code, last = http(server, "GET", "/api/zip/job")
    assert code == 200 and last["id"] == started["job"]
    code, c = http(server, "POST", "/api/zip/cancel", {"id": started["job"]})
    assert code == 200 and c["was_running"] is False
    # errores: 400 con mensaje; id desconocido: 404; sin token: 403
    code, err = http(server, "POST", "/api/zip/split", dict(body, out_dir=str(tmp_path / "o")))
    assert code == 400 and "no está vacía" in err["error"]
    code, err = http(server, "POST", "/api/zip/split", dict(body, too_large="move", out_dir=str(tmp_path / "o9")))
    assert code == 400 and "confirm" in err["error"]
    code, err = http(server, "POST", "/api/zip/plan", {"path": root, "out_dir": os.path.join(root, "dentro")})
    assert code == 400 and "dentro" in err["error"]
    assert http(server, "GET", "/api/zip/job?id=999")[0] == 404
    assert http(server, "GET", "/api/zip/job", auth=False)[0] == 403
    assert http(server, "POST", "/api/zip/plan", body, auth=False)[0] == 403


def test_ui_has_the_zip_panel(server):
    with urllib.request.urlopen(server["url"] + "/", timeout=10) as r:
        html = r.read().decode("utf-8")
    for needle in ("Partir en ZIPs", 'id="zSrc"', 'id="zOut"', 'id="zLimit"', "25 MB correo", "990 MB", "4 GB",
                   'id="zPlan"', 'id="zRun"', 'id="zCancel"', "Abrir carpeta", "/api/zip/split", "/api/zip/job",
                   'id="btnZipDir"', 'id="bZip"'):
        assert needle in html, needle
