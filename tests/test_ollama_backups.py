# -*- coding: utf-8 -*-
"""Copias de Ollama: detector, reglas de seguridad, simulacro y liberacion contra un almacen SINTETICO.

Nada de aqui toca el almacen real: todo vive en tmp_path con blobs de unos pocos bytes.
"""
import hashlib
import json
import os
import shutil
import urllib.error
import urllib.request

import pytest

from diskhoard import agent as agentmod
from diskhoard import ollama_backups as ob

NOW = 1_800_000_000.0
DAY = 86400.0
LIST_MEDIA = ob.LIST_MEDIA
MT = "application/vnd.docker.distribution.manifest.v2+json"


def no_api(path):
    return None


def no_procs():
    return []


@pytest.fixture(autouse=True)
def _no_cli(monkeypatch):
    monkeypatch.setattr(ob, "_cli_version", lambda: "0.40.2")


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Store:
    """Constructor de almacenes de Ollama de juguete."""

    def __init__(self, root):
        self.root = root
        os.makedirs(os.path.join(root, "blobs"))
        os.makedirs(os.path.join(root, "manifests"))
        os.makedirs(os.path.join(root, "manifests-v2"))
        self.sizes = {}

    def _touch(self, path, age):
        os.utime(path, (NOW - age, NOW - age))

    def blob(self, data, age=40 * DAY):
        h = sha(data)
        p = os.path.join(self.root, "blobs", "sha256-" + h)
        with open(p, "wb") as fh:
            fh.write(data)
        self._touch(p, age)
        self.sizes[h] = len(data)
        return "sha256:" + h

    @staticmethod
    def desc(digest, data_len, media="application/vnd.ollama.image.model", **extra):
        d = {"mediaType": media, "digest": digest, "size": data_len}
        d.update(extra)
        return d

    def layer(self, data, media="application/vnd.ollama.image.model", age=40 * DAY):
        return self.desc(self.blob(data, age), len(data), media)

    def manifest(self, config, layers):
        return {"schemaVersion": 2, "mediaType": MT, "config": config, "layers": layers}

    def write_tag(self, area, host, ns, model, tag, content, age=40 * DAY):
        p = os.path.join(self.root, area, host, ns, model, tag)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        data = content if isinstance(content, bytes) else json.dumps(content).encode()
        with open(p, "wb") as fh:
            fh.write(data)
        self._touch(p, age)
        return p

    def plain_model(self, model, tag="latest", layers=(b"weights",), shared=(), area="manifests",
                    host="registry.ollama.ai", age=40 * DAY):
        cfg = self.layer(b'{"config":"%s"}' % model.encode(), "application/vnd.docker.container.image.v1+json", age)
        lays = [self.layer(w, age=age) for w in layers] + [
            self.layer(s, "application/vnd.ollama.image.template", age) for s in shared]
        m = self.manifest(cfg, lays)
        self.write_tag(area, host, "library", model, tag, m, age)
        return m

    def migrated_model(self, model, tag="latest", old=(b"OLD-WEIGHTS-" * 20,), new=(b"new-weights-" * 10,),
                       shared=(b"{{ .Prompt }}",), new_missing=False):
        """Etiqueta v2 = lista [llamacpp, ggml]; ancla antigua = manifiesto ggml; sombra llamacpp:<digest>."""
        s_layers = [self.layer(s, "application/vnd.ollama.image.template") for s in shared]
        g_cfg = self.layer(b'{"build":"ggml","m":"%s"}' % model.encode(),
                           "application/vnd.docker.container.image.v1+json")
        l_cfg = self.layer(b'{"build":"llamacpp","m":"%s"}' % model.encode(),
                           "application/vnd.docker.container.image.v1+json")
        g_layers = [self.layer(o) for o in old]
        l_layers = [self.layer(n) for n in new]
        g_man = self.manifest(g_cfg, g_layers + s_layers)
        l_man = self.manifest(l_cfg, l_layers + s_layers)
        g_digest = self.blob(json.dumps(g_man).encode())
        l_digest = self.blob(json.dumps(l_man).encode())
        if new_missing:
            os.remove(os.path.join(self.root, "blobs", "sha256-" + l_layers[0]["digest"][7:]))
        lst = {"schemaVersion": 2, "mediaType": LIST_MEDIA, "manifests": [
            {"mediaType": MT, "digest": l_digest, "size": len(json.dumps(l_man)), "runner": "llamacpp"},
            {"mediaType": MT, "digest": g_digest, "size": len(json.dumps(g_man)), "runner": "ggml"}]}
        self.blob(json.dumps(lst).encode())             # el manifiesto-blob al que apunta el enlace v2
        self.write_tag("manifests-v2", "ollama.com", "library", model, tag, lst)
        self.write_tag("manifests", "registry.ollama.ai", "library", model, tag, g_man)       # ancla antigua
        self.write_tag("manifests", "registry.ollama.ai", "library", "llamacpp", l_digest[7:], l_man)
        uniq = [o["digest"] for o in g_layers] + [g_cfg["digest"], g_digest]
        return {"g_digest": g_digest, "l_digest": l_digest, "unique_old": uniq,
                "unique_bytes": sum(self.sizes[d[7:]] for d in uniq)}

    def path(self, *parts):
        return os.path.join(self.root, *parts)

    def write_file(self, rel, data, age=40 * DAY):
        p = self.path(*rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
        self._touch(p, age)
        return p


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "models"))


def scan(store_or_root, **kw):
    root = store_or_root.root if isinstance(store_or_root, Store) else store_or_root
    kw.setdefault("now", NOW)
    kw.setdefault("api", no_api)
    kw.setdefault("procs", no_procs)
    return ob.scan(root, **kw)


def by_kind(res, kind):
    return [i for i in res["items"] if i["kind"] == kind]


def full_store(store):
    """Alpha migrada, Beta sin migrar (comparten plantilla), huerfanos, parciales, metadatos y copias."""
    info = {}
    info["alpha"] = store.migrated_model("alpha", "7b")
    store.plain_model("beta", "latest", layers=(b"beta-weights",), shared=(b"{{ .Prompt }}",))
    info["old_orphan"] = store.blob(b"ORPHAN-OLD" * 50)
    info["fresh_orphan"] = store.blob(b"ORPHAN-FRESH" * 30, age=600)
    store.write_file("blobs/sha256-%s-partial" % sha(b"p-old"), b"x" * 123, age=10 * DAY)
    store.write_file("blobs/sha256-%s-partial-2" % sha(b"p-new"), b"y" * 77, age=3 * DAY)
    store.write_file("metadata/sha256-%s.json" % sha(b"gone-blob"), b'{"kv":{}}')
    return info


# ------------------------------------------------------------------ deteccion

def test_a_clean_store_has_nothing_to_free(store):
    store.migrated_model("alpha")
    store.plain_model("beta")
    res = scan(store)
    assert res["error"] is None and res["problems"] == []
    assert [i["kind"] for i in res["items"]] == ["ggml_backup"]    # lo unico que sobra es la copia de la migracion
    assert all(m["complete"] for m in res["models"])


def test_detects_every_kind_with_exact_sizes(store):
    info = full_store(store)
    res = scan(store)
    assert res["error"] is None and res["problems"] == []
    ggml = by_kind(res, "ggml_backup")
    assert len(ggml) == 1
    g = ggml[0]
    assert g["safe"] and g["model"] == "alpha:7b" and g["how"] == "ollama_rm"
    assert g["bytes"] == info["alpha"]["unique_bytes"]            # sin la plantilla, que comparte con el modelo migrado
    assert g["digest"] == info["alpha"]["g_digest"] and g["command"] == "ollama rm " + info["alpha"]["g_digest"]
    assert g["shared_blobs"] == 1 and g["working_build"]["complete"] is True
    assert g["working_build"]["digest"] == info["alpha"]["l_digest"]

    orphans = {i["name"]: i for i in by_kind(res, "orphan_blob")}
    assert orphans["sha256-" + info["old_orphan"][7:]]["safe"] is True
    fresh = orphans["sha256-" + info["fresh_orphan"][7:]]
    assert fresh["safe"] is False and "descarga en curso" in fresh["reasons"][0]

    parts = {i["name"]: i for i in by_kind(res, "partial")}
    assert len(parts) == 2
    assert [p["safe"] for n, p in sorted(parts.items(), key=lambda kv: kv[1]["bytes"])] == [False, True]
    assert len(by_kind(res, "orphan_metadata")) == 1 and by_kind(res, "orphan_metadata")[0]["safe"]

    safe_total = sum(i["bytes"] for i in res["items"] if i["safe"])
    assert res["reclaimable_bytes"] == safe_total == g["bytes"] + len(b"ORPHAN-OLD" * 50) + 123 + len(b'{"kv":{}}')
    assert res["unsafe_bytes"] == len(b"ORPHAN-FRESH" * 30) + 77
    assert res["counts"]["ggml_backup"]["safe_bytes"] == g["bytes"]
    assert {m["name"] for m in res["models"]} == {"alpha:7b", "beta:latest"}
    assert all(m["complete"] for m in res["models"])
    assert res["layout"]["lists"] == 1 and res["layout"]["manifests_v2"] is True


def test_shared_blobs_are_never_counted_as_reclaimable(store):
    info = store.migrated_model("alpha", shared=(b"SHARED-TEMPLATE",))
    store.plain_model("beta", layers=(b"w",), shared=(b"SHARED-TEMPLATE",))
    g = by_kind(scan(store), "ggml_backup")[0]
    shared_digest = "sha256:" + sha(b"SHARED-TEMPLATE")
    assert shared_digest not in [b["digest"] for b in g["blobs"]]
    assert g["bytes"] == info["unique_bytes"]


def test_blob_used_by_a_second_model_is_kept(store):
    """Si otra etiqueta usa tambien un peso viejo, ya no es exclusivo de la copia."""
    store.migrated_model("alpha", old=(b"OLD-A" * 40, b"COMMON-OLD" * 40))
    store.plain_model("beta", layers=(b"COMMON-OLD" * 40,))
    g = by_kind(scan(store), "ggml_backup")[0]
    assert "sha256:" + sha(b"COMMON-OLD" * 40) not in [b["digest"] for b in g["blobs"]]
    assert "sha256:" + sha(b"OLD-A" * 40) in [b["digest"] for b in g["blobs"]]


def test_backup_is_unsafe_when_the_migrated_build_is_incomplete(store):
    store.migrated_model("alpha")
    store.migrated_model("gamma", old=(b"GAMMA-OLD" * 30,), new=(b"gamma-new" * 10,), new_missing=True)
    res = scan(store)
    ggml = {i["model"]: i for i in by_kind(res, "ggml_backup")}
    assert ggml["alpha:latest"]["safe"] is True
    gm = ggml["gamma:latest"]
    assert gm["safe"] is False and gm["working_build"]["complete"] is False
    assert "versión migrada" in gm["reasons"][0] and "falta" in gm["reasons"][0]
    assert res["reclaimable_bytes"] == ggml["alpha:latest"]["bytes"]
    gamma = next(m for m in res["models"] if m["name"] == "gamma:latest")
    assert gamma["complete"] is False and gamma["serving"] == "llamacpp"


def test_backup_is_unsafe_when_the_migrated_manifest_is_missing(store):
    info = store.migrated_model("alpha")
    os.remove(store.path("blobs", "sha256-" + info["l_digest"][7:]))
    g = by_kind(scan(store), "ggml_backup")[0]
    assert not g["safe"] and "falta el manifiesto" in g["reasons"][0]


def test_wrong_size_counts_as_a_missing_blob(store):
    info = store.migrated_model("alpha", new=(b"n" * 100,))
    with open(store.path("blobs", "sha256-" + sha(b"n" * 100)), "ab") as fh:
        fh.write(b"corrupt")
    g = by_kind(scan(store), "ggml_backup")[0]
    assert not g["safe"] and "mide" in g["reasons"][0]


def test_manifest_pointing_to_a_missing_blob_is_reported_broken(store):
    store.plain_model("beta", layers=(b"w",))
    m = json.load(open(store.path("manifests", "registry.ollama.ai", "library", "beta", "latest")))
    os.remove(store.path("blobs", "sha256-" + m["layers"][0]["digest"][7:]))
    res = scan(store)
    beta = res["models"][0]
    assert beta["complete"] is False and beta["missing"][0]["why"] == "falta"
    assert res["problems"] == []                      # un blob que falta no impide saber que se usa el resto


def test_unreadable_manifest_makes_every_orphan_unsafe(store):
    full_store(store)
    store.write_tag("manifests", "registry.ollama.ai", "library", "broken", "latest", b"{not json")
    res = scan(store)
    assert res["problems"] and "ilegible" in res["problems"][0]
    assert by_kind(res, "orphan_blob") and not any(i["safe"] for i in by_kind(res, "orphan_blob"))
    assert "manifiestos ilegibles" in by_kind(res, "orphan_blob")[0]["reasons"][0]
    assert not by_kind(res, "ggml_backup")[0]["safe"]
    assert res["reclaimable_bytes"] == sum(i["bytes"] for i in res["items"] if i["safe"])
    assert all(i["safe"] for i in by_kind(res, "partial") if i["bytes"] == 123)       # el parcial viejo no depende de manifiestos


def test_dangling_v2_link_is_a_verification_problem(store, tmp_path):
    store.plain_model("beta")
    link = store.path("manifests-v2", "ollama.com", "library", "ghost", "latest")
    os.makedirs(os.path.dirname(link))
    try:
        os.symlink(store.path("blobs", "sha256-" + "0" * 64), link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not allowed here")
    store.blob(b"some orphan")
    res = scan(store)
    assert any("Enlace roto" in p for p in res["problems"])
    assert not any(i["safe"] for i in by_kind(res, "orphan_blob"))


def test_v2_symlink_manifest_is_followed(store):
    info = store.migrated_model("alpha")
    tag = store.path("manifests-v2", "ollama.com", "library", "alpha", "latest")
    blob_copy = store.path("blobs", "sha256-" + sha(open(tag, "rb").read()))
    os.remove(tag)
    try:
        os.symlink(blob_copy, tag)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not allowed here")
    res = scan(store)
    assert res["problems"] == [] and by_kind(res, "ggml_backup")[0]["bytes"] == info["unique_bytes"]
    assert by_kind(res, "orphan_blob") == []          # el blob de la lista no es huerfano


def test_listed_child_and_list_blob_are_not_orphans(store):
    store.migrated_model("alpha")
    assert by_kind(scan(store), "orphan_blob") == []


# ------------------------------------------------------------------ copias con pinta de backup

def test_backup_dir_is_safe_only_when_live_store_has_everything(store):
    store.plain_model("beta", layers=(b"w",))
    m = store.path("manifests", "registry.ollama.ai", "library", "beta", "latest")
    store.write_file("manifests.bak-20261008/registry.ollama.ai/library/beta/latest", open(m, "rb").read())
    store.write_file("blobs.old/sha256-%s" % sha(b"w"), b"w")
    res = scan(store)
    dirs = {i["rel"]: i for i in by_kind(res, "backup_dir")}
    assert set(dirs) == {"manifests.bak-20261008", "blobs.old"}
    assert all(d["safe"] for d in dirs.values()) and dirs["blobs.old"]["bytes"] == 1
    assert dirs["manifests.bak-20261008"]["models"] == ["beta:latest"]


def test_backup_dir_with_a_model_missing_live_is_unsafe(store):
    store.plain_model("beta")
    store.write_file("backup/registry.ollama.ai/library/omega/1", json.dumps(
        {"schemaVersion": 2, "layers": []}).encode())
    d = by_kind(scan(store), "backup_dir")[0]
    assert d["safe"] is False and "omega:1" in d["reasons"][0]


def test_backup_dir_is_unsafe_when_live_store_is_broken(store):
    store.plain_model("beta", layers=(b"w",))
    m = json.load(open(store.path("manifests", "registry.ollama.ai", "library", "beta", "latest")))
    os.remove(store.path("blobs", "sha256-" + m["layers"][0]["digest"][7:]))
    store.write_file("old/readme.txt", b"hola")
    d = by_kind(scan(store), "backup_dir")[0]
    assert not d["safe"] and any("incompletos" in r for r in d["reasons"])


def test_backup_dir_with_unknown_files_or_links_is_unsafe(store):
    store.plain_model("beta")
    store.write_file("bak/notes.txt", b"mis apuntes")
    d = by_kind(scan(store), "backup_dir")[0]
    assert not d["safe"] and "no son ni blobs ni manifiestos" in d["reasons"][0]
    try:
        os.symlink(store.path("blobs"), store.path("bak", "lnk"), target_is_directory=True)
    except (OSError, NotImplementedError):
        return
    d = by_kind(scan(store), "backup_dir")[0]
    assert not d["safe"] and any("enlaces" in r for r in d["reasons"])


def test_backup_manifest_file_needs_its_live_twin(store):
    store.plain_model("beta")
    live = store.path("manifests", "registry.ollama.ai", "library", "beta", "latest")
    store.write_file("manifests/registry.ollama.ai/library/beta/latest.bak", open(live, "rb").read())
    store.write_file("manifests/registry.ollama.ai/library/zeta/latest.bak", b"{}")
    store.write_file("blobs/sha256-%s.bak" % sha(b"weights"), b"x")
    store.write_file("blobs/sha256-%s.bak" % sha(b"vanished"), b"x")
    files = {i["rel"]: i for i in by_kind(scan(store), "backup_file")}
    assert files["manifests/registry.ollama.ai/library/beta/latest.bak"]["safe"]
    assert not files["manifests/registry.ollama.ai/library/zeta/latest.bak"]["safe"]
    assert files["blobs/sha256-%s.bak" % sha(b"weights")]["safe"]
    assert not files["blobs/sha256-%s.bak" % sha(b"vanished")]["safe"]


def test_a_tag_named_like_a_backup_suffix_is_not_parsed_as_a_model(store):
    store.plain_model("beta")
    store.write_file("manifests/registry.ollama.ai/library/beta/latest.bak", b"not json at all")
    res = scan(store)
    assert res["problems"] == [] and [m["name"] for m in res["models"]] == ["beta:latest"]


# ------------------------------------------------------------------ verificar la carpeta

def test_unverifiable_dirs_are_rejected(tmp_path):
    res = ob.scan(str(tmp_path / "nope"), now=NOW, api=no_api, procs=no_procs)
    assert "No existe" in res["error"]
    (tmp_path / "plain").mkdir()
    assert "falta blobs/" in ob.scan(str(tmp_path / "plain"), now=NOW, api=no_api, procs=no_procs)["error"]
    assert "absoluta" in ob.scan("models", now=NOW, api=no_api, procs=no_procs)["error"]
    r = ob.free(str(tmp_path / "nope"), dry_run=False, confirm=True)
    assert "No existe" in r["error"]


def test_a_protected_folder_can_be_read_but_never_freed(store, monkeypatch):
    store.blob(b"orphan" * 10)
    monkeypatch.setattr(ob, "_protected_roots", lambda: {os.path.normcase(os.path.abspath(store.root)).rstrip("\\/")})
    res = scan(store)
    assert res["free_blockers"] and "protegida" in res["free_blockers"][0] and not res["can_free"]
    r = ob.free(store.root, dry_run=False, confirm=True, now=NOW, api=no_api, procs=no_procs)
    assert "error" in r and "no se puede verificar" in r["error"]
    assert os.path.exists(store.path("blobs", "sha256-" + sha(b"orphan" * 10)))


def test_a_link_as_models_dir_is_not_freeable(store, tmp_path):
    store.blob(b"orphan" * 10)
    link = str(tmp_path / "via-link")
    try:
        os.symlink(store.root, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not allowed here")
    res = scan(link)
    assert res["items"] and any("enlace" in b for b in res["free_blockers"]) and not res["can_free"]


# ------------------------------------------------------------------ actividad de Ollama

def test_activity_loaded_models_and_pull_processes_block(store):
    full_store(store)
    loaded = lambda p: {"models": [{"name": "alpha:7b"}]} if p == "/api/ps" else {"version": "0.40.2"}   # noqa: E731
    res = scan(store, api=loaded)
    assert res["ollama"]["running"] and res["ollama"]["loaded"] == ["alpha:7b"] and not res["can_free"]
    assert "cargados" in res["busy"][0] and res["ollama"]["version"] == "0.40.2"
    pulling = lambda: [("ollama.exe", '"C:\\Program Files\\Ollama\\ollama.exe" pull qwen3')]       # noqa: E731
    res = scan(store, procs=pulling)
    assert "`pull`" in res["busy"][0] and not res["can_free"]
    runner = lambda: [("ollama.exe", "ollama.exe runner --ollama-engine --port 5555")]               # noqa: E731
    assert "`runner`" in scan(store, procs=runner)["busy"][0]
    serving = lambda: [("ollama.exe", "ollama.exe serve"), ("ollama app.exe", '"C:\\x\\ollama app.exe"')]   # noqa: E731
    assert scan(store, procs=serving)["busy"] == []


def test_recent_partial_or_recent_writes_mean_busy(store):
    store.blob(b"x" * 10)
    store.write_file("blobs/sha256-%s-partial" % sha(b"live"), b"y" * 10, age=60)      # se esta descargando
    res = scan(store)
    assert any("descarga en curso" in b for b in res["busy"])
    res = scan(store, now=NOW + 3600)                                                # una hora despues ya no
    assert not any("descarga en curso" in b or "escrito" in b for b in res["busy"])
    store.blob(b"recent" * 4, age=30)
    assert any("escrito en el almacén" in b for b in scan(store)["busy"])


def test_process_listing_failure_is_a_warning_not_a_block(store):
    store.blob(b"o" * 10)
    res = scan(store, procs=lambda: None)
    assert res["busy"] == [] and "procesos" in res["warnings"][0]


# ------------------------------------------------------------------ liberar

def snapshot(root):
    out = {}
    for base, _d, files in os.walk(root):
        for f in files:
            p = os.path.join(base, f)
            out[os.path.relpath(p, root)] = os.path.getsize(p)
    return out


class Spy:
    def __init__(self, root):
        self.rm_calls = []
        self.trashed = []
        self.root = root

    def run_rm(self, digest):
        self.rm_calls.append(digest)
        return 0, "deleted", ""

    def trash(self, paths):
        for p in paths:
            self.trashed.append(p)
            dest = os.path.join(self.root + "_bin", os.path.basename(p))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.move(p, dest)
        return True, ""


def running_api(path):
    return {"models": []} if path == "/api/ps" else {"version": "0.40.2"}


def kw(spy, data_dir, **extra):
    d = dict(now=NOW, api=running_api, procs=no_procs, run_rm=spy.run_rm, trash=spy.trash, data_dir=data_dir)
    d.update(extra)
    return d


def test_dry_run_changes_nothing_and_writes_an_audit_line(store, tmp_path):
    full_store(store)
    before = snapshot(store.root)
    spy = Spy(store.root)
    dd = str(tmp_path / "data")
    r = ob.free(store.root, **kw(spy, dd))                     # dry_run por defecto
    assert r["dry_run"] is True and r["done"] == [] and spy.rm_calls == [] and spy.trashed == []
    assert snapshot(store.root) == before
    ids = {p["id"] for p in r["planned"]}
    assert any(i.startswith("ggml:") for i in ids) and not any(i.startswith("blob:") and "FRESH" in i for i in ids)
    assert r["planned_bytes"] == scan(store)["reclaimable_bytes"]
    assert r["blocked"] == [] and "Simulacro" in r["note"]
    log = ob.read_audit(dd)
    assert len(log) == 1 and log[0]["dry_run"] is True and log[0]["outcome"] == "dry_run"
    assert log[0]["planned_bytes"] == r["planned_bytes"] and log[0]["caller"] == "ui"


def test_real_free_needs_confirmation(store, tmp_path):
    full_store(store)
    spy = Spy(store.root)
    r = ob.free(store.root, **kw(spy, str(tmp_path / "d"), dry_run=False))
    assert "confirm=true" in r["error"] and spy.rm_calls == [] and r["done"] == []
    assert ob.read_audit(str(tmp_path / "d"))[-1]["outcome"] == "refused"


def test_free_moves_files_to_the_bin_and_uses_ollama_rm_for_backups(store, tmp_path):
    info = full_store(store)
    spy = Spy(store.root)
    dd = str(tmp_path / "d")
    r = ob.free(store.root, **kw(spy, dd, dry_run=False, confirm=True, caller="agent"))
    assert "error" not in r and r["failed"] == []
    assert spy.rm_calls == [info["alpha"]["g_digest"]]
    done = {d["id"]: d for d in r["done"]}
    assert len(done) == 4 and all(d.get("freed") is not None for d in done.values())
    ggml = next(d for d in r["done"] if d["how"] == "ollama_rm")
    assert ggml["freed"] == info["alpha"]["unique_bytes"]
    # los ficheros seguros salieron del almacen (a la papelera simulada); lo inseguro sigue en su sitio
    assert not os.path.exists(store.path("blobs", "sha256-" + info["old_orphan"][7:]))
    assert os.path.exists(store.path("blobs", "sha256-" + info["fresh_orphan"][7:]))
    assert os.path.exists(store.path("blobs", "sha256-%s-partial-2" % sha(b"p-new")))
    assert len(spy.trashed) == 3 and r["freed_bytes"] == sum(d["freed"] for d in r["done"])
    assert "Papelera" in r["note"]
    entry = ob.read_audit(dd)[-1]
    assert entry["outcome"] == "freed" and entry["dry_run"] is False and entry["caller"] == "agent"
    assert entry["freed_bytes"] == r["freed_bytes"] and len(entry["done"]) == 4
    # el modelo vivo sigue entero
    res = scan(store)
    assert all(m["complete"] for m in res["models"])


def test_free_only_what_was_asked_and_never_unsafe_ids(store, tmp_path):
    info = full_store(store)
    spy = Spy(store.root)
    fresh_id = [i["id"] for i in by_kind(scan(store), "orphan_blob") if not i["safe"]][0]
    old_id = [i["id"] for i in by_kind(scan(store), "orphan_blob") if i["safe"]][0]
    r = ob.free(store.root, ids=[old_id, fresh_id, "blob:doesnotexist"],
                **kw(spy, str(tmp_path / "d"), dry_run=False, confirm=True))
    assert [d["id"] for d in r["done"]] == [old_id] and spy.rm_calls == []
    reasons = {x["id"]: x["reasons"][0] for x in r["refused"]}
    assert "descarga en curso" in reasons[fresh_id] and "Ya no existe" in reasons["blob:doesnotexist"]
    assert os.path.exists(store.path("blobs", "sha256-" + info["fresh_orphan"][7:]))


def test_permanent_mode_really_deletes_files(store, tmp_path):
    info = store.blob(b"ORPHAN-OLD" * 50)
    store.plain_model("beta")
    spy = Spy(store.root)
    r = ob.free(store.root, **kw(spy, str(tmp_path / "d"), dry_run=False, confirm=True, mode="permanent"))
    assert r["failed"] == [] and spy.trashed == []
    assert not os.path.exists(store.path("blobs", "sha256-" + info[7:]))
    assert r["done"][0]["verified"] is True and r["freed_bytes"] == len(b"ORPHAN-OLD" * 50)
    assert "note" not in r or "Papelera" not in r.get("note", "")


def test_refuses_while_ollama_is_busy_but_dry_run_explains(store, tmp_path):
    full_store(store)
    spy = Spy(store.root)
    loaded = lambda p: {"models": [{"name": "alpha:7b"}]} if p == "/api/ps" else {}          # noqa: E731
    r = ob.free(store.root, **kw(spy, str(tmp_path / "d"), dry_run=False, confirm=True, api=loaded))
    assert "cargados" in r["error"] and r["done"] == [] and spy.rm_calls == [] and spy.trashed == []
    dry = ob.free(store.root, **kw(spy, str(tmp_path / "d"), api=loaded))
    assert "error" not in dry and "cargados" in dry["blocked"][0] and dry["planned"]
    pull = lambda: [("ollama.exe", "ollama.exe pull x")]                                    # noqa: E731
    r = ob.free(store.root, **kw(spy, str(tmp_path / "d"), dry_run=False, confirm=True, procs=pull))
    assert "`pull`" in r["error"] and spy.trashed == []


def test_ggml_backups_need_the_ollama_server_running(store, tmp_path):
    store.migrated_model("alpha")
    spy = Spy(store.root)
    r = ob.free(store.root, **kw(spy, str(tmp_path / "d"), dry_run=False, confirm=True, api=no_api))
    assert "ollama rm" in r["error"] and spy.rm_calls == []
    # un huerfano suelto, en cambio, no necesita el servidor
    orphan = store.blob(b"orphan" * 20)
    r = ob.free(store.root, ids=["blob:" + orphan[7:23]], **kw(spy, str(tmp_path / "d"), dry_run=False,
                                                              confirm=True, api=no_api))
    assert "error" not in r and len(r["done"]) == 1


def test_ollama_rm_failure_is_reported_and_nothing_else_breaks(store, tmp_path):
    info = store.migrated_model("alpha")
    spy = Spy(store.root)
    spy.run_rm = lambda d: (1, "", "Error: model not found")
    r = ob.free(store.root, **kw(spy, str(tmp_path / "d"), dry_run=False, confirm=True))
    assert r["done"] == [] and "model not found" in r["failed"][0]["error"]
    assert all(m["complete"] for m in scan(store)["models"])
    assert ob.read_audit(str(tmp_path / "d"))[-1]["outcome"] == "failed"


def test_ollama_rm_is_verified_by_rescanning(store, tmp_path):
    info = store.migrated_model("alpha")
    root = store.root

    def fake_rm(digest):
        """Hace lo que haria Ollama: quita el hijo ggml de la lista, su ancla y los blobs solo suyos."""
        tag = os.path.join(root, "manifests-v2", "ollama.com", "library", "alpha", "latest")
        lst = json.load(open(tag))
        lst["manifests"] = [m for m in lst["manifests"] if m["runner"] != "ggml"]
        open(tag, "w").write(json.dumps(lst))
        os.utime(tag, (NOW - 5 * DAY, NOW - 5 * DAY))
        os.remove(os.path.join(root, "manifests", "registry.ollama.ai", "library", "alpha", "latest"))
        for d in info["unique_old"]:
            os.remove(os.path.join(root, "blobs", "sha256-" + d[7:]))
        return 0, "deleted 'sha256:...'", ""

    spy = Spy(root)
    spy.run_rm = fake_rm
    r = ob.free(root, **kw(spy, str(tmp_path / "d"), dry_run=False, confirm=True))
    assert r["failed"] == [] and r["done"][0]["verified"] is True
    again = scan(store)
    assert by_kind(again, "ggml_backup") == [] and again["models"][0]["complete"]
    # el hijo ggml ya no esta en la lista pero el modelo migrado sigue sirviendose
    assert again["models"][0]["serving"] == "llamacpp"
    # sobrevivio la plantilla que compartia con el modelo migrado
    assert os.path.exists(store.path("blobs", "sha256-" + sha(b"{{ .Prompt }}")))


def test_never_touches_paths_outside_the_verified_dir(store, tmp_path):
    """Aunque un id apuntara fuera (p. ej. un enlace colocado despues del escaneo), no se borra."""
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"precious")
    orphan = store.blob(b"orphan" * 20)
    path = store.path("blobs", "sha256-" + orphan[7:])
    os.remove(path)
    try:
        os.symlink(str(outside), path)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not allowed here")
    res = scan(store)
    item = by_kind(res, "orphan_blob")[0]
    assert item["safe"] is False and "enlace" in item["reasons"][-1]
    r = ob.free(store.root, **kw(Spy(store.root), str(tmp_path / "d"), dry_run=False, confirm=True))
    assert outside.read_bytes() == b"precious"


def test_invalid_mode_is_rejected(store):
    assert "mode" in ob.free(store.root, mode="shred", now=NOW, api=no_api, procs=no_procs)["error"]


# ------------------------------------------------------------------ resolver la carpeta

def test_resolve_prefers_explicit_then_env(monkeypatch, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    (b / "blobs").mkdir(parents=True)
    monkeypatch.setenv("OLLAMA_MODELS", str(b))
    path, source, _ = ob.resolve_models_dir(None)
    assert os.path.normcase(path) == os.path.normcase(str(b)) and source in ("env", "registry")
    path, source, _ = ob.resolve_models_dir(str(a))
    assert source == "arg" and os.path.normcase(path) == os.path.normcase(str(a))


# ------------------------------------------------------------------ agente, HTTP y puente

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


def http(server, method, path, body=None, expect=200, auth=True):
    req = urllib.request.Request(server["url"] + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if auth:
        req.add_header("X-DH-Token", server["token"])
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            assert r.status == expect
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        assert exc.code == expect, exc.read()
        return json.loads(exc.read())


def test_tools_are_in_the_catalog_before_the_zip_tools():
    names = [t["name"] for t in agentmod.CATALOG]
    assert names[-6:-4] == ["disk_ollama_backups", "disk_ollama_free"]
    by = {t["name"]: t for t in agentmod.CATALOG}
    assert by["disk_ollama_backups"]["annotations"]["readOnlyHint"] is True
    assert by["disk_ollama_free"]["annotations"]["destructiveHint"] is True
    props = by["disk_ollama_free"]["inputSchema"]["properties"]
    assert props["dry_run"]["default"] is True and props["confirm"]["default"] is False
    assert "Sinónimos" in by["disk_ollama_free"]["description"]
    assert "disk_ollama_free" in agentmod.INSTRUCTIONS


def test_agent_detects_dry_runs_and_refuses_without_confirm(server, store, data_dir, monkeypatch):
    full_store(store)
    monkeypatch.setattr(ob, "_api_get", no_api)
    monkeypatch.setattr(ob, "_list_processes", no_procs)
    out = call(server, "disk_ollama_backups", {"models_dir": store.root})
    assert out["reclaimable_bytes"] > 0 and out["counts"]["ggml_backup"]["count"] == 1
    assert {i["kind"] for i in out["items"]} >= {"ggml_backup", "orphan_blob", "partial", "orphan_metadata"}
    only = call(server, "disk_ollama_backups", {"models_dir": store.root, "kind": "ggml_backup", "safe_only": True})
    assert only["matching"] == 1 and only["items"][0]["safe"]

    before = snapshot(store.root)
    dry = call(server, "disk_ollama_free", {"models_dir": store.root})
    assert dry["dry_run"] is True and dry["planned"] and snapshot(store.root) == before
    err = call(server, "disk_ollama_free", {"models_dir": store.root, "dry_run": False}, expect=400)
    assert "confirm=true" in err["error"] and snapshot(store.root) == before
    bad = call(server, "disk_ollama_backups", {"models_dir": store.root + "-nope"}, expect=400)
    assert "No existe" in bad["error"]
    log = ob.read_audit(str(data_dir))
    assert [e["outcome"] for e in log[-2:]] == ["dry_run", "refused"] and log[-1]["caller"] == "agent"


def test_http_routes_need_the_token_and_do_the_same(server, store, data_dir, monkeypatch):
    full_store(store)
    monkeypatch.setattr(ob, "_api_get", no_api)
    monkeypatch.setattr(ob, "_list_processes", no_procs)
    from urllib.parse import quote
    http(server, "GET", "/api/ollama/backups?dir=" + quote(store.root), expect=403, auth=False)
    res = http(server, "GET", "/api/ollama/backups?dir=" + quote(store.root))
    assert res["reclaimable_bytes"] > 0 and res["models_dir"].lower() == store.root.lower()
    http(server, "POST", "/api/ollama/free", {"dir": store.root}, expect=403, auth=False)
    before = snapshot(store.root)
    dry = http(server, "POST", "/api/ollama/free", {"dir": store.root})                # simulacro por defecto
    assert dry["dry_run"] is True and snapshot(store.root) == before
    nope = http(server, "POST", "/api/ollama/free", {"dir": store.root, "dry_run": False}, expect=400)
    assert "confirm=true" in nope["error"]
    audit = http(server, "GET", "/api/ollama/audit")
    assert audit["items"] and audit["items"][-1]["caller"] == "ui"
