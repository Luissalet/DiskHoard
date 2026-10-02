# -*- coding: utf-8 -*-
"""Partir una carpeta en ZIPs que no pasen de un tamaño (webs con límite por fichero).

Lógica pura, solo librería estándar: la usan el servidor (interfaz y /api/zip/*) y el
agente (herramientas disk_zip_*). Sustituye al viejo "Zip splitter" de Tkinter y lo mejora:

- El límite se GARANTIZA, no se estima. Para decidir si un fichero cabe en la parte actual se
  suma el tamaño real del archivo (posición del fichero tras la última entrada) + el tamaño del
  fichero + cabecera local + entrada del directorio central + registro final, con los extras ZIP64
  cuando hacen falta, y en deflate la cota máxima de crecimiento. Al cerrar cada parte se
  comprueba el tamaño real contra el límite.
- Un fichero que por sí solo no cabe se salta, se mueve a too_large/, hace fallar el trabajo o se
  parte en volúmenes crudos `.zip.001`, `.zip.002`... (7-Zip los abre; `copy /b` los une).
- Las partes se escriben como `*.tmp` y se renombran al cerrarse: si se cancela o falla, no queda
  ninguna parte a medias con nombre definitivo.
"""
from __future__ import annotations

import fnmatch
import math
import os
import re
import shutil
import threading
import time
import zipfile
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation

from .hoard_link.atomic import replace_with_retry
from .winfs import IS_WIN, long_path, norm_display, strip_long

# --------------------------------------------------------------------- tamaños

DECIMAL_SUFFIXES = {"": 1, "b": 1, "k": 1000, "kb": 1000, "m": 1000 ** 2, "mb": 1000 ** 2,
                    "g": 1000 ** 3, "gb": 1000 ** 3, "t": 1000 ** 4, "tb": 1000 ** 4}
BINARY_SUFFIXES = {"kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3, "tib": 1024 ** 4}

# Umbrales de la librería zipfile: a partir de aquí escribe extras ZIP64.
ZIP64_LIMIT = (1 << 31) - 1
ZIP_FILECOUNT_LIMIT = 65535

LOCAL_HEADER = 30          # cabecera local fija
CENTRAL_ENTRY = 46         # entrada del directorio central fija
END_RECORD = 22            # registro de fin de directorio central
ZIP64_END_RECORD = 56      # registro ZIP64 de fin de directorio central
ZIP64_END_LOCATOR = 20     # localizador de ese registro
ZIP64_LOCAL_EXTRA = 20     # 4 de cabecera + tamaño y tamaño comprimido
ZIP64_CENTRAL_EXTRA = 28   # 4 de cabecera + tamaño, comprimido y desplazamiento (cota)

CHUNK = 1024 * 1024
MIN_EFFECTIVE = 1024

# Se excluyen por defecto (sustituye a esta lista cualquier `exclude` que se pase, aunque sea vacío).
DEFAULT_EXCLUDE = ("Thumbs.db", "desktop.ini", ".DS_Store", "*.tmp", "~$*")

TOO_LARGE_MODES = ("skip", "fail", "move", "split")
SORT_MODES = ("name", "size")
COMPRESSIONS = ("stored", "deflated")


class ZipSplitError(ValueError):
    """Entrada no válida o trabajo que no se puede hacer (mensaje listo para mostrar)."""


class Cancelled(Exception):
    pass


def parse_size(value):
    """'990mb' (decimal), '990mib' (binario), '1,5gb', '50000000' (bytes) -> bytes."""
    if isinstance(value, bool):
        raise ZipSplitError("Tamaño inválido: %r" % (value,))
    if isinstance(value, int):
        if value < 0:
            raise ZipSplitError("El tamaño no puede ser negativo")
        return value
    if isinstance(value, float):
        if value < 0:
            raise ZipSplitError("El tamaño no puede ser negativo")
        return int(value)
    s = str(value if value is not None else "").strip().lower().replace(" ", "").replace("_", "")
    if not s:
        raise ZipSplitError("Tamaño vacío")
    m = re.fullmatch(r"(\d+(?:[.,]\d+)?)([a-z]*)", s)
    if not m:
        raise ZipSplitError("Tamaño inválido: %s" % s)
    num, suf = m.group(1).replace(",", "."), m.group(2)
    if suf in DECIMAL_SUFFIXES:
        mult = DECIMAL_SUFFIXES[suf]
    elif suf in BINARY_SUFFIXES:
        mult = BINARY_SUFFIXES[suf]
    else:
        raise ZipSplitError("Sufijo inválido '%s'. Usa kb/mb/gb (decimal) o kib/mib/gib (binario)." % suf)
    try:
        return int(Decimal(num) * mult)
    except InvalidOperation:
        raise ZipSplitError("Tamaño inválido: %s" % s)


def human(n):
    """Solo para mostrar, en decimal (1 MB = 1.000.000 bytes), que es lo que cuentan las webs."""
    x = float(n or 0)
    units = ("B", "KB", "MB", "GB", "TB")
    i = 0
    while x >= 1000 and i < len(units) - 1:
        x /= 1000.0
        i += 1
    return "%d B" % x if i == 0 else "%.2f %s" % (x, units[i])


# ------------------------------------------------------------ cuentas del ZIP

def data_bound(size, compression):
    """Bytes máximos que ocupan los datos de un fichero de `size` bytes en el ZIP.

    stored: exactos. deflated: la salida solo puede crecer lo que dice la cota de zlib.
    """
    size = int(size)
    if compression == "stored":
        return size
    return size + (size >> 12) + (size >> 14) + (size >> 25) + 13 + 16


def local_overhead(name_len, file_size, streaming=False):
    """Cabecera local de una entrada (más el descriptor de datos si se escribe sin rebobinar).

    `name_len` son los bytes UTF-8 del nombre dentro del ZIP.
    """
    zip64 = file_size * 1.05 > ZIP64_LIMIT
    n = LOCAL_HEADER + name_len + (ZIP64_LOCAL_EXTRA if zip64 else 0)
    if streaming:
        n += 24 if zip64 else 16
    return n


def central_overhead(name_len, zip64=False):
    """Entrada del directorio central; con extras ZIP64 en cota (ficheros o desplazamientos > 2 GiB)."""
    return CENTRAL_ENTRY + name_len + (ZIP64_CENTRAL_EXTRA if zip64 else 0)


def end_overhead(n_entries, zip64=False):
    """Registro final del ZIP; ZIP64 si hay más de 65535 entradas o el directorio pasa de 2 GiB."""
    if zip64 or n_entries > ZIP_FILECOUNT_LIMIT:
        return END_RECORD + ZIP64_END_RECORD + ZIP64_END_LOCATOR
    return END_RECORD


class Budget:
    """Tamaño del ZIP en curso: el real (o el simulado en el plan) y lo que costaría una entrada más."""

    def __init__(self, effective, compression, streaming=False):
        self.effective = effective
        self.compression = compression
        self.streaming = streaming
        self.reset()

    def reset(self):
        self.pos = 0          # donde acaban las entradas escritas
        self.n = 0
        self.cd = 0           # directorio central sin extras
        self.big_entry = False

    @staticmethod
    def _end(pos, n, cd_plain, big_entry):
        z = big_entry or pos > ZIP64_LIMIT
        cd = cd_plain + (ZIP64_CENTRAL_EXTRA * n if z else 0)
        return pos + cd + end_overhead(n, z or cd > ZIP64_LIMIT)

    def final_size(self):
        """Tamaño del ZIP si se cerrase ahora."""
        return self._end(self.pos, self.n, self.cd, self.big_entry)

    def projected(self, name_len, size):
        """Tamaño máximo del ZIP si se añade un fichero de `size` bytes y se cierra."""
        pos = self.pos + local_overhead(name_len, size, self.streaming) + data_bound(size, self.compression)
        return self._end(pos, self.n + 1, self.cd + central_overhead(name_len),
                         self.big_entry or size > ZIP64_LIMIT)

    def add(self, name_len, size, real_pos=None):
        if real_pos is None:
            real_pos = self.pos + local_overhead(name_len, size, self.streaming) + data_bound(size, self.compression)
        self.pos = real_pos
        self.n += 1
        self.cd += central_overhead(name_len)
        if size > ZIP64_LIMIT:
            self.big_entry = True


# ------------------------------------------------------------------- opciones

@dataclass
class Options:
    input_dir: str
    out_dir: str = ""
    limit: int = 990_000_000
    margin: int = 5_000_000
    prefix: str = "part"
    sort: str = "name"
    compression: str = "stored"
    too_large: str = "skip"
    include: list = field(default_factory=list)
    exclude: list = field(default_factory=lambda: list(DEFAULT_EXCLUDE))
    overwrite: bool = False
    manifest: bool = True

    @property
    def effective(self):
        return self.limit - self.margin


def _patterns(value, default=None):
    if value is None:
        return list(default) if default is not None else []
    if isinstance(value, str):
        value = re.split(r"[,;\n]", value)
    return [str(p).strip() for p in value if str(p).strip()]


def _truthy(v, default):
    if v is None or v == "":
        return default
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "si", "sí", "on")
    return bool(v)


def options_from(args):
    """Diccionario (HTTP o herramienta del agente) -> Options validadas. No toca el disco."""
    a = dict(args or {})
    src = str(a.get("path") or a.get("input") or a.get("input_dir") or "").strip()
    if not src:
        raise ZipSplitError("Falta la carpeta de origen (path).")
    comp = str(a.get("compression") or "stored").strip().lower()
    comp = {"store": "stored", "none": "stored", "deflate": "deflated", "zip": "deflated"}.get(comp, comp)
    if comp not in COMPRESSIONS:
        raise ZipSplitError("compression debe ser 'stored' o 'deflated'.")
    sort = str(a.get("sort") or "name").strip().lower()
    if sort not in SORT_MODES:
        raise ZipSplitError("sort debe ser 'name' o 'size'.")
    tl = str(a.get("too_large") or "skip").strip().lower()
    if tl not in TOO_LARGE_MODES:
        raise ZipSplitError("too_large debe ser skip, fail, move o split.")
    prefix = str(a.get("prefix") or "part").strip()
    if re.search(r'[\\/:*?"<>|\x00-\x1f]', prefix) or prefix in (".", ".."):
        raise ZipSplitError("El prefijo no puede llevar \\ / : * ? \" < > |")
    if len(prefix) > 60:
        raise ZipSplitError("El prefijo es demasiado largo (máximo 60 caracteres).")
    limit = parse_size(a["limit"] if a.get("limit") not in (None, "") else "990mb")
    margin = parse_size(a["margin"] if a.get("margin") not in (None, "") else "5mb")
    return Options(
        input_dir=src, out_dir=str(a.get("out_dir") or "").strip(), limit=limit, margin=margin,
        prefix=prefix, sort=sort, compression=comp, too_large=tl,
        include=_patterns(a.get("include")),
        exclude=_patterns(a.get("exclude"), DEFAULT_EXCLUDE),
        overwrite=_truthy(a.get("overwrite"), False), manifest=_truthy(a.get("manifest"), True))


def _is_root(path):
    p = os.path.abspath(path)
    return os.path.dirname(p) == p


def _same(a, b):
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _inside(child, parent):
    c = os.path.normcase(os.path.abspath(child)).rstrip("\\/")
    p = os.path.normcase(os.path.abspath(parent)).rstrip("\\/")
    return c != p and c.startswith(p + os.sep)


_POSIX_SYSTEM = ("/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/sbin", "/sys", "/usr")


def output_refusal(path):
    """Por qué no se escribe la salida aquí (raíz de unidad, Windows, Archivos de programa, el perfil), o None."""
    if not os.path.isabs(str(path or "")):
        return "no es una ruta absoluta"
    p = os.path.abspath(norm_display(path))
    if _is_root(p):
        return "es la raíz de una unidad"
    for env in ("SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        base = os.environ.get(env)
        if base and (_same(p, base) or _inside(p, base)):
            return "es una carpeta del sistema (%s)" % os.path.basename(base.rstrip("\\/"))
    home = os.path.expanduser("~")
    if home and home != "~" and _same(p, home):
        return "es la carpeta raíz del perfil de usuario"
    if not IS_WIN:
        for base in _POSIX_SYSTEM:
            if _same(p, base) or _inside(p, base):
                return "es una carpeta del sistema (%s)" % base
    return None


def default_out_dir(input_dir):
    p = os.path.abspath(input_dir).rstrip("\\/")
    base = os.path.basename(p)
    if not base or _is_root(input_dir):
        raise ZipSplitError("La carpeta de origen es una raíz de unidad: indica una carpeta de destino.")
    return os.path.join(os.path.dirname(p), base + "_zips")


def prepare(opts, confirm=False, writing=False):
    """Valida origen, destino y límites sin escribir nada. Devuelve una copia con rutas normalizadas.

    `writing=True` es para quien va a crear ZIPs: too_large=move mueve ficheros del usuario y exige confirm.
    """
    o = Options(**{k: (list(v) if isinstance(v, list) else v) for k, v in opts.__dict__.items()})
    if not os.path.isabs(str(o.input_dir)):
        raise ZipSplitError("La carpeta de origen debe ser una ruta absoluta.")
    o.input_dir = os.path.abspath(norm_display(o.input_dir))
    if not os.path.isdir(long_path(o.input_dir)):
        raise ZipSplitError("No existe la carpeta de origen: %s" % o.input_dir)
    if writing and o.too_large == "move" and not confirm:
        raise ZipSplitError("too_large=move MUEVE ficheros del usuario a too_large/: hace falta confirm=true.")
    if _is_root(o.input_dir) and not confirm:
        raise ZipSplitError("El origen es una unidad entera (%s). Hace falta confirmarlo (confirm=true)." % o.input_dir)
    if o.limit <= 0:
        raise ZipSplitError("El límite debe ser mayor que 0.")
    if o.margin < 0:
        raise ZipSplitError("El margen no puede ser negativo.")
    if o.margin >= o.limit:
        raise ZipSplitError("El margen no puede ser mayor o igual que el límite.")
    if o.effective < MIN_EFFECTIVE:
        raise ZipSplitError("El límite menos el margen debe ser al menos %d bytes." % MIN_EFFECTIVE)
    out = o.out_dir or default_out_dir(o.input_dir)
    if not os.path.isabs(out):
        raise ZipSplitError("La carpeta de destino debe ser una ruta absoluta.")
    out = os.path.abspath(norm_display(out))
    why = output_refusal(out)
    if why:
        raise ZipSplitError("No se escribe el destino en %s: %s." % (out, why))
    if _same(out, o.input_dir) or _inside(out, o.input_dir):
        raise ZipSplitError("La carpeta de destino no puede estar dentro de la de origen (%s)." % out)
    if os.path.lexists(long_path(out)):
        if not os.path.isdir(long_path(out)):
            raise ZipSplitError("El destino existe y no es una carpeta: %s" % out)
        if not o.overwrite and os.listdir(long_path(out)):
            raise ZipSplitError("La carpeta de destino no está vacía (%s). Usa otra o overwrite=true "
                                "(solo sustituye partes con el mismo prefijo)." % out)
    o.out_dir = out
    return o


# ------------------------------------------------------------------ recorrido

@dataclass
class Item:
    rel: str            # ruta relativa con /
    path: str           # ruta real
    size: int
    mtime: float
    name_len: int       # bytes UTF-8 del nombre dentro del ZIP


def _matches(rel, name, patterns):
    low_rel, low_name = rel.lower(), name.lower()
    for p in patterns:
        pl = p.lower()
        if fnmatch.fnmatchcase(low_name, pl) or fnmatch.fnmatchcase(low_rel, pl):
            return True
    return False


def collect(o, should_stop=None):
    """Ficheros a empaquetar (ya ordenados) y contadores. No sigue enlaces ni uniones y se salta el destino."""
    stats = {"excluded": 0, "links": 0, "unreadable": [], "other": 0}
    items = []
    out_norm = os.path.normcase(os.path.abspath(o.out_dir)) if o.out_dir else None
    stack = [(long_path(o.input_dir), "")]
    while stack:
        if should_stop and should_stop():
            raise Cancelled()
        cur, rel_dir = stack.pop()
        try:
            it = os.scandir(cur)
        except OSError:
            stats["unreadable"].append(rel_dir.rstrip("/") or ".")
            continue
        with it:
            for e in it:
                rel = rel_dir + e.name
                try:
                    junction = getattr(e, "is_junction", None)
                    if e.is_symlink() or (junction is not None and junction()):
                        stats["links"] += 1
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if out_norm and os.path.normcase(os.path.abspath(strip_long(e.path))) == out_norm:
                            continue
                        if o.exclude and _matches(rel, e.name, o.exclude):
                            continue
                        stack.append((e.path, rel + "/"))
                        continue
                    if not e.is_file(follow_symlinks=False):
                        stats["other"] += 1
                        continue
                    if o.exclude and _matches(rel, e.name, o.exclude):
                        stats["excluded"] += 1
                        continue
                    if o.include and not _matches(rel, e.name, o.include):
                        stats["excluded"] += 1
                        continue
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    stats["unreadable"].append(rel)
                    continue
                items.append(Item(rel, e.path, st.st_size, st.st_mtime, len(rel.encode("utf-8"))))
    if o.sort == "size":
        items.sort(key=lambda i: (i.size, i.rel.lower()))
    else:
        items.sort(key=lambda i: i.rel.lower())
    return items, stats


def _split_items(o, items):
    """(los que caben en una parte, los que no caben ni solos)."""
    solo = Budget(o.effective, o.compression)
    regular, big = [], []
    for it in items:
        (regular if solo.projected(it.name_len, it.size) <= o.effective else big).append(it)
    return regular, big


def _part_name(o, n):
    return "%s_%03d.zip" % (o.prefix, n)


def _volume_estimate(o, it):
    b = Budget(1 << 62, o.compression, streaming=True)
    total = b.projected(it.name_len, it.size)
    return max(2, int(math.ceil(total / float(o.effective))))


# ----------------------------------------------------------------------- plan

def plan(o, confirm=False, files=False, should_stop=None):
    """Qué fichero va a qué parte y cuánto ocupará cada una, sin escribir nada.

    En stored el tamaño estimado es el real. En deflated es una cota superior (lo comprimible
    ocupará menos y puede salir alguna parte menos).
    """
    o = prepare(o, confirm=confirm)
    items, stats = collect(o, should_stop)
    regular, big = _split_items(o, items)
    parts = []
    b = Budget(o.effective, o.compression)
    cur = None

    def close():
        nonlocal cur
        cur["est_size"] = b.final_size()
        cur["est_human"] = human(cur["est_size"])
        cur["fill_pct"] = round(100.0 * cur["est_size"] / o.limit, 1)
        parts.append(cur)
        cur = None
        b.reset()

    for it in regular:
        if cur is not None and b.projected(it.name_len, it.size) > o.effective:
            close()
        if cur is None:
            cur = {"n": len(parts) + 1, "name": _part_name(o, len(parts) + 1), "file_count": 0, "data_bytes": 0}
            if files:
                cur["files"] = []
        b.add(it.name_len, it.size)
        cur["file_count"] += 1
        cur["data_bytes"] += it.size
        if files:
            cur["files"].append({"path": it.rel, "size": it.size})
        elif cur["file_count"] <= 5:
            cur.setdefault("sample", []).append(it.rel)
    if cur is not None:
        close()
    too_large = []
    for it in big:
        row = {"path": it.rel, "size": it.size, "human": human(it.size), "action": o.too_large}
        if o.too_large == "split":
            vols = _volume_estimate(o, it)
            row["volumes_estimate"] = vols
            row["volumes_prefix"] = "%s_%s.zip" % (o.prefix, _flat_name(it.rel))
        too_large.append(row)
    out = {
        "ok": True, "dry_run": True, "input": o.input_dir, "out_dir": o.out_dir,
        "limit": o.limit, "limit_human": human(o.limit), "margin": o.margin,
        "effective_limit": o.effective, "effective_human": human(o.effective),
        "compression": o.compression, "sort": o.sort, "prefix": o.prefix, "too_large_mode": o.too_large,
        "estimate": "exact" if o.compression == "stored" else "upper_bound",
        "files": len(regular), "files_total": len(items), "bytes": sum(i.size for i in regular),
        "bytes_human": human(sum(i.size for i in regular)),
        "parts": parts, "part_count": len(parts),
        "too_large": too_large, "too_large_count": len(big),
        "excluded": stats["excluded"], "skipped_links": stats["links"],
        "unreadable": stats["unreadable"][:50], "unreadable_count": len(stats["unreadable"]),
        "exclude": o.exclude, "include": o.include,
    }
    if o.too_large == "fail" and big:
        out["warning"] = ("Hay %d fichero(s) mayores que el límite y too_large=fail: el trabajo se negaría a "
                          "empezar." % len(big))
    if o.compression == "deflated":
        out["note"] = "Con deflate el plan es una cota superior: las partes reales pueden ser menores."
    return out


# ------------------------------------------------------------------ escritura

_BAD_NAME = re.compile(r'[\\/:*?"<>|\x00-\x1f]+')


def _flat_name(rel):
    s = _BAD_NAME.sub("_", rel.replace("/", "__")).strip(" .")
    return (s or "fichero")[:120]


def _dos_time(ts):
    """Fecha de un fichero en el rango que admite ZIP (1980-2107)."""
    try:
        t = time.localtime(ts)
    except (OverflowError, OSError, ValueError):
        return (1980, 1, 1, 0, 0, 0)
    if not 1980 <= t.tm_year <= 2107:
        return (1980, 1, 1, 0, 0, 0)
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, min(t.tm_sec, 59))


def _rm(path):
    try:
        os.remove(long_path(path))
    except OSError:
        pass


class _VolumeWriter:
    """Fichero de salida que se corta solo cada `size` bytes: `<base>.001`, `<base>.002`...

    Solo tiene write/tell/flush (no seek): zipfile entonces escribe en streaming, con descriptores de datos.
    """

    def __init__(self, folder, base, size):
        self.folder, self.base, self.size = folder, base, size
        self.total = 0
        self._fh = None
        self._room = 0
        self.volumes = []     # [(ruta temporal, ruta final)]

    def _roll(self):
        if self._fh:
            self._fh.close()
        final = os.path.join(self.folder, "%s.%03d" % (self.base, len(self.volumes) + 1))
        tmp = final + ".tmp"
        self._fh = open(long_path(tmp), "wb")
        self.volumes.append((tmp, final))
        self._room = self.size

    def write(self, data):
        mv = memoryview(data)
        done = 0
        while done < len(mv):
            if self._room == 0 or self._fh is None:
                self._roll()
            n = min(self._room, len(mv) - done)
            self._fh.write(mv[done:done + n])
            self._room -= n
            done += n
        self.total += len(mv)
        return len(mv)

    def tell(self):
        return self.total

    def flush(self):
        if self._fh:
            self._fh.flush()

    def close(self):
        if self._fh:
            self._fh.close()
            self._fh = None

    def abort(self):
        self.close()
        for tmp, _final in self.volumes:
            _rm(tmp)

    def finish(self):
        self.close()
        out = []
        for tmp, final in self.volumes:
            replace_with_retry(long_path(tmp), long_path(final))
            out.append((final, os.path.getsize(long_path(final))))
        return out


def _make_info(it, compression, st_mode):
    zi = zipfile.ZipInfo(it.rel, date_time=_dos_time(it.mtime))
    zi.compress_type = zipfile.ZIP_STORED if compression == "stored" else zipfile.ZIP_DEFLATED
    zi.external_attr = (st_mode & 0xFFFF) << 16
    zi.file_size = it.size
    return zi


def _copy_into(zf, it, src, compression, should_stop, on_bytes, warnings):
    """Escribe el fichero ya abierto como una entrada, leyendo como mucho lo medido (el límite no se rompe)."""
    mode = os.fstat(src.fileno()).st_mode
    zi = _make_info(it, compression, mode)
    with zf.open(zi, "w") as dest:
        remaining = it.size
        while remaining > 0:
            if should_stop and should_stop():
                raise Cancelled()
            chunk = src.read(min(CHUNK, remaining))
            if not chunk:
                break
            dest.write(chunk)
            remaining -= len(chunk)
            on_bytes(len(chunk))
        else:
            if src.read(1):
                warnings.append("%s ha crecido mientras se leía: se guardó lo medido al empezar." % it.rel)


class _Tracker:
    def __init__(self, cb):
        self.cb = cb
        self.v = {"phase": "scanning", "bytes_done": 0, "bytes_total": 0, "files_done": 0, "files_total": 0,
                  "current": "", "part": 0, "parts_done": 0, "volumes_done": 0}

    def set(self, **kw):
        self.v.update(kw)
        if self.cb:
            self.cb(dict(self.v))

    def add_bytes(self, n):
        self.v["bytes_done"] += n
        if self.cb:
            self.cb(dict(self.v))


def _unique(path_set, base):
    n = 1
    name = base
    while name.lower() in path_set:
        n += 1
        name = "%s_%d" % (base, n)
    path_set.add(name.lower())
    return name


def _old_outputs(o):
    """Ficheros de una ejecución anterior con este prefijo (lo único que overwrite puede sustituir)."""
    pre = re.escape(o.prefix)
    pats = [re.compile(r"^%s_\d{3,}\.zip(\.tmp)?$" % pre),
            re.compile(r"^%s_.+\.zip\.\d{3,}(\.tmp)?$" % pre),
            re.compile(r"^manifest\.txt$")]
    found = []
    try:
        names = os.listdir(long_path(o.out_dir))
    except OSError:
        return found
    for n in names:
        if any(p.match(n) for p in pats) and os.path.isfile(long_path(os.path.join(o.out_dir, n))):
            found.append(n)
    return found


def split(o, should_stop=None, progress=None, confirm=False):
    """Crea part_001.zip, part_002.zip... y devuelve el resumen con los tamaños reales.

    Lanza ZipSplitError si no se puede empezar. Si se cancela, devuelve el resumen con
    `cancelled: true`; las partes ya cerradas se quedan y la que estaba a medias se borra.
    """
    o = prepare(o, confirm=confirm, writing=True)
    trk = _Tracker(progress)
    started = time.time()
    trk.set(phase="scanning")
    try:
        items, stats = collect(o, should_stop)
    except Cancelled:
        return {"ok": True, "cancelled": True, "out_dir": o.out_dir, "parts": [], "too_large": [],
                "files_added": 0, "bytes_in": 0, "bytes_out": 0, "warnings": [], "errors": [],
                "elapsed_s": round(time.time() - started, 1)}
    regular, big = _split_items(o, items)
    if big and o.too_large == "fail":
        names = ", ".join("%s (%s)" % (b.rel, human(b.size)) for b in big[:5])
        raise ZipSplitError("Hay %d fichero(s) mayores que el límite efectivo (%s) y too_large=fail: %s%s" % (
            len(big), human(o.effective), names, "…" if len(big) > 5 else ""))
    split_big = big if o.too_large == "split" else []
    trk.set(phase="writing", files_total=len(regular) + len(split_big),
            bytes_total=sum(i.size for i in regular) + sum(i.size for i in split_big))

    summary = {"ok": True, "cancelled": False, "input": o.input_dir, "out_dir": o.out_dir, "limit": o.limit,
               "limit_human": human(o.limit), "margin": o.margin, "effective_limit": o.effective,
               "compression": o.compression, "sort": o.sort, "prefix": o.prefix,
               "parts": [], "too_large": [], "files_added": 0, "bytes_in": 0, "bytes_out": 0,
               "excluded": stats["excluded"], "skipped_links": stats["links"],
               "warnings": [], "errors": []}
    if stats["unreadable"]:
        summary["warnings"].append("%d entrada(s) sin permiso de lectura no se incluyen." % len(stats["unreadable"]))
    warnings, errors = summary["warnings"], summary["errors"]
    if not regular and not split_big and not big:
        summary["message"] = "No hay ficheros que empaquetar en el origen."
        summary["elapsed_s"] = round(time.time() - started, 1)
        trk.set(phase="done")
        return summary

    os.makedirs(long_path(o.out_dir), exist_ok=True)
    old = _old_outputs(o) if o.overwrite else []
    written = set()        # nombres definitivos creados en esta ejecución
    state = {"writer": None}

    def abort_part():
        w = state["writer"]
        if w is not None:
            try:
                w["zf"].close()
            except Exception:  # noqa: BLE001
                pass
            try:
                w["fp"].close()
            except Exception:  # noqa: BLE001
                pass
            _rm(w["tmp"])
            state["writer"] = None

    def open_part():
        n = len(summary["parts"]) + 1
        final = os.path.join(o.out_dir, _part_name(o, n))
        tmp = final + ".tmp"
        fp = open(long_path(tmp), "wb")
        zf = zipfile.ZipFile(fp, "w", allowZip64=True)
        state["writer"] = {"fp": fp, "zf": zf, "tmp": tmp, "final": final, "n": n,
                           "budget": Budget(o.effective, o.compression), "files": []}
        trk.set(part=n, current="")

    def close_part():
        w = state["writer"]
        w["zf"].close()
        w["fp"].close()
        size = os.path.getsize(long_path(w["tmp"]))
        if size > o.limit:
            _rm(w["tmp"])
            state["writer"] = None
            raise ZipSplitError("Error interno: %s ocupa %s y pasa el límite (%s)." % (
                os.path.basename(w["final"]), human(size), human(o.limit)))
        replace_with_retry(long_path(w["tmp"]), long_path(w["final"]))
        written.add(os.path.basename(w["final"]).lower())
        summary["parts"].append({
            "n": w["n"], "name": os.path.basename(w["final"]), "path": w["final"], "kind": "zip",
            "files": len(w["files"]), "size": size, "human": human(size),
            "within_limit": size <= o.limit, "within_effective": size <= o.effective,
            "fill_pct": round(100.0 * size / o.limit, 1), "contents": w["files"]})
        summary["bytes_out"] += size
        state["writer"] = None
        trk.set(parts_done=len(summary["parts"]))

    try:
        for it in regular:
            if should_stop and should_stop():
                raise Cancelled()
            trk.set(current=it.rel)
            try:
                src = open(long_path(it.path), "rb")
            except OSError as exc:
                errors.append("%s: %s" % (it.rel, exc.strerror or exc))
                continue
            with src:
                w = state["writer"]
                if w is not None and w["budget"].projected(it.name_len, it.size) > o.effective:
                    close_part()
                if state["writer"] is None:
                    open_part()
                w = state["writer"]
                _copy_into(w["zf"], it, src, o.compression, should_stop, trk.add_bytes, warnings)
                w["budget"].add(it.name_len, it.size, real_pos=w["fp"].tell())
                if w["budget"].final_size() > o.effective:
                    raise ZipSplitError("Error interno: %s superaría el límite efectivo al añadir %s." % (
                        os.path.basename(w["final"]), it.rel))
                w["files"].append({"path": it.rel, "size": it.size})
                summary["files_added"] += 1
                summary["bytes_in"] += it.size
                trk.set(files_done=trk.v["files_done"] + 1)
        if state["writer"] is not None:
            if state["writer"]["files"]:
                close_part()
            else:
                abort_part()

        used_flat = set()
        for it in big:
            if should_stop and should_stop():
                raise Cancelled()
            row = {"path": it.rel, "size": it.size, "human": human(it.size), "action": o.too_large}
            if o.too_large == "skip":
                row["result"] = "skipped"
            elif o.too_large == "move":
                row["result"] = "moved"
                row["moved_to"] = _move_too_large(o, it)
            else:
                trk.set(current=it.rel, phase="splitting")
                row.update(_write_volumes(o, it, used_flat, written, should_stop, trk, warnings))
                summary["bytes_in"] += it.size
                for v in row["volumes"]:
                    summary["bytes_out"] += v["size"]
                trk.set(files_done=trk.v["files_done"] + 1, volumes_done=trk.v["volumes_done"] + len(row["volumes"]))
            summary["too_large"].append(row)
    except Cancelled:
        abort_part()
        summary["cancelled"] = True
    except BaseException:
        abort_part()
        raise

    # restos de una ejecución anterior con el mismo prefijo que esta ya no necesita
    if not summary["cancelled"]:
        for n in old:
            if n.lower() not in written and not n.lower() == "manifest.txt":
                _rm(os.path.join(o.out_dir, n))

    summary["elapsed_s"] = round(time.time() - started, 1)
    if o.manifest and (summary["parts"] or summary["too_large"]):
        try:
            summary["manifest"] = _write_manifest(o, summary)
        except OSError as exc:
            warnings.append("No se pudo escribir manifest.txt: %s" % exc)
    for p in summary["parts"]:
        p.pop("contents", None)   # el listado completo vive en manifest.txt
    summary["part_count"] = len(summary["parts"])
    summary["bytes_out_human"] = human(summary["bytes_out"])
    summary["bytes_in_human"] = human(summary["bytes_in"])
    trk.set(phase="cancelled" if summary["cancelled"] else "done")
    return summary


def _move_too_large(o, it):
    dest = os.path.join(o.out_dir, "too_large", *it.rel.split("/"))
    base, ext = os.path.splitext(dest)
    n = 1
    while os.path.lexists(long_path(dest)):
        n += 1
        dest = "%s (%d)%s" % (base, n, ext)
    os.makedirs(long_path(os.path.dirname(dest)), exist_ok=True)
    shutil.move(long_path(it.path), long_path(dest))
    return dest


def _write_volumes(o, it, used_flat, written, should_stop, trk, warnings):
    """Un fichero mayor que el límite: se guarda solo en un ZIP que se corta en volúmenes `.zip.001`..."""
    flat = _unique(used_flat, _flat_name(it.rel))
    base = "%s_%s.zip" % (o.prefix, flat)
    vw = _VolumeWriter(o.out_dir, base, o.effective)
    try:
        src = open(long_path(it.path), "rb")
    except OSError as exc:
        raise ZipSplitError("No se puede leer %s: %s" % (it.rel, exc.strerror or exc))
    try:
        with src:
            zf = zipfile.ZipFile(vw, "w", allowZip64=True)
            try:
                _copy_into(zf, it, src, o.compression, should_stop, trk.add_bytes, warnings)
            finally:
                zf.close()
        vols = vw.finish()
    except BaseException:
        vw.abort()
        raise
    out = []
    for path, size in vols:
        if size > o.limit:
            raise ZipSplitError("Error interno: el volumen %s pasa el límite." % os.path.basename(path))
        written.add(os.path.basename(path).lower())
        out.append({"name": os.path.basename(path), "path": path, "size": size, "human": human(size),
                    "within_limit": size <= o.limit, "kind": "volume"})
    return {"result": "split", "volumes": out, "volumes_base": base,
            "join_windows": "copy /b %s %s" % ("+".join('"%s"' % v["name"] for v in out), '"%s"' % base),
            "join_linux": "cat %s > %s" % (" ".join(v["name"] for v in out), base)}


def _write_manifest(o, summary):
    path = os.path.join(o.out_dir, "manifest.txt")
    lines = [
        "DiskHoard - partir en ZIPs",
        "Fecha: %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
        "Origen: %s" % o.input_dir,
        "Destino: %s" % o.out_dir,
        "Límite: %s (margen %s, efectivo %s) · compresión %s · orden %s" % (
            human(o.limit), human(o.margin), human(o.effective), o.compression, o.sort),
        "Partes: %d · ficheros: %d · entrada %s · salida %s" % (
            len(summary["parts"]), summary["files_added"], human(summary["bytes_in"]), human(summary["bytes_out"])),
        "Excluidos por patrón: %d · enlaces omitidos: %d" % (summary["excluded"], summary["skipped_links"]),
    ]
    if summary["cancelled"]:
        lines.append("ATENCIÓN: el trabajo se canceló; la lista está incompleta.")
    for p in summary["parts"]:
        lines += ["", "== %s  (%s, %d ficheros)" % (p["name"], p["human"], p["files"])]
        lines += ["   %s  (%s)" % (c["path"], human(c["size"])) for c in p.get("contents", [])]
    if summary["too_large"]:
        lines += ["", "== Ficheros mayores que el límite (acción: %s)" % o.too_large]
        for r in summary["too_large"]:
            lines.append("   %s  (%s) -> %s" % (r["path"], r["human"], r["result"]))
            if r.get("moved_to"):
                lines.append("      movido a %s" % r["moved_to"])
            for v in r.get("volumes", []):
                lines.append("      %s  (%s)" % (v["name"], v["human"]))
            if r.get("join_windows"):
                lines.append("      Unir en Windows: %s" % r["join_windows"])
    with open(long_path(path), "w", encoding="utf-8", newline="\r\n") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


# ----------------------------------------------------------------- trabajos

class ZipJob:
    """split() en un hilo, con progreso, cancelación y resumen final."""

    def __init__(self, jid, opts, confirm=False):
        self.id = str(jid)
        self.opts = opts
        self.confirm = confirm
        self.state = "queued"      # queued | running | done | cancelled | error
        self.error = None
        self.summary = None
        self.progress = {"phase": "queued", "bytes_done": 0, "bytes_total": 0, "files_done": 0,
                         "files_total": 0, "current": "", "part": 0, "parts_done": 0, "volumes_done": 0}
        self.started = time.time()
        self.finished = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.thread = threading.Thread(target=self._run, name="dh-zipsplit", daemon=True)

    def start(self):
        self.state = "running"
        self.thread.start()
        return self

    def cancel(self):
        self._stop.set()

    def _cb(self, snap):
        with self._lock:
            self.progress = snap

    def _run(self):
        try:
            res = split(self.opts, should_stop=self._stop.is_set, progress=self._cb, confirm=self.confirm)
            self.summary = res
            self.state = "cancelled" if res.get("cancelled") else "done"
        except ZipSplitError as exc:
            self.error = str(exc)
            self.state = "error"
        except Exception as exc:  # noqa: BLE001 - el hilo no debe morir en silencio
            self.error = "%s: %s" % (type(exc).__name__, exc)
            self.state = "error"
        self.finished = time.time()

    @property
    def running(self):
        return self.state in ("queued", "running")

    def snapshot(self):
        with self._lock:
            p = dict(self.progress)
        total = p.get("bytes_total") or 0
        out = {"id": self.id, "state": self.state, "running": self.running,
               "finished": not self.running, "phase": p.get("phase"),
               "bytes_done": p["bytes_done"], "bytes_total": total,
               "percent": round(100.0 * p["bytes_done"] / total, 1) if total else (100.0 if not self.running else 0.0),
               "files_done": p["files_done"], "files_total": p["files_total"], "current": p["current"],
               "part": p["part"], "parts_done": p["parts_done"], "volumes_done": p.get("volumes_done", 0),
               "elapsed_s": round((self.finished or time.time()) - self.started, 1),
               "out_dir": self.opts.out_dir or None}
        if self.error:
            out["error"] = self.error
        if self.summary is not None:
            out["summary"] = self.summary
        return out


class JobRegistry:
    """Un solo trabajo a la vez (el disco es lo escaso); se recuerda el último."""

    def __init__(self):
        self.lock = threading.Lock()
        self.jobs = {}
        self.seq = 0
        self.last = None

    def start(self, opts, confirm=False):
        o = prepare(opts, confirm=confirm, writing=True)       # valida antes de gastar un hilo
        with self.lock:
            if self.last is not None and self.jobs[self.last].running:
                raise ZipSplitError("Ya hay un trabajo de ZIP en marcha (id %s). Espera o cancélalo." % self.last)
            self.seq += 1
            job = ZipJob(self.seq, o, confirm=confirm)
            self.jobs[job.id] = job
            self.last = job.id
            for old in list(self.jobs)[:-20]:
                if not self.jobs[old].running:
                    del self.jobs[old]
        return job.start()

    def get(self, jid=None):
        with self.lock:
            key = str(jid) if jid not in (None, "") else self.last
            return self.jobs.get(key) if key is not None else None


REGISTRY = JobRegistry()
