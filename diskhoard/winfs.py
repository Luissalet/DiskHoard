# -*- coding: utf-8 -*-
"""Utilidades de sistema de ficheros para Windows.

Rutas largas (>260 caracteres), unidades, papelera de reciclaje y borrado
permanente rapido. Todo con la libreria estandar: cero dependencias.
"""
from __future__ import annotations

import ctypes
import os
import stat
import string
import sys

IS_WIN = os.name == "nt"

# ---------------------------------------------------------------- rutas largas

def long_path(p: str) -> str:
    """Devuelve la ruta con el prefijo \\\\?\\ para superar el limite MAX_PATH."""
    if not IS_WIN:
        return p
    if p.startswith("\\\\?\\"):
        return p
    p = os.path.abspath(p)
    if p.startswith("\\\\"):          # UNC  \\servidor\recurso
        return "\\\\?\\UNC" + p[1:]
    return "\\\\?\\" + p


def strip_long(p: str) -> str:
    """Quita el prefijo \\\\?\\ para mostrar la ruta al usuario."""
    if p.startswith("\\\\?\\UNC\\"):
        return "\\\\" + p[8:]
    if p.startswith("\\\\?\\"):
        return p[4:]
    return p


def norm_display(p: str) -> str:
    p = strip_long(p)
    if len(p) == 2 and p[1] == ":":
        p += "\\"
    return p


# --------------------------------------------------------------------- discos

def _drive_space(root: str):
    try:
        free_user = ctypes.c_ulonglong(0)
        total = ctypes.c_ulonglong(0)
        free_total = ctypes.c_ulonglong(0)
        ok = ctypes.windll.kernel32.GetDiskFreeSpaceExW(
            ctypes.c_wchar_p(root),
            ctypes.pointer(free_user),
            ctypes.pointer(total),
            ctypes.pointer(free_total),
        )
        if not ok:
            return None
        return total.value, free_user.value
    except Exception:
        return None


DRIVE_TYPES = {0: "desconocido", 1: "invalido", 2: "extraible", 3: "fijo",
               4: "red", 5: "cd", 6: "ram"}


def list_drives():
    """Unidades disponibles con espacio total/libre y etiqueta."""
    out = []
    if not IS_WIN:
        st = os.statvfs("/")
        out.append({"path": "/", "label": "raiz", "type": "fijo",
                    "total": st.f_blocks * st.f_frsize,
                    "free": st.f_bavail * st.f_frsize})
        return out
    k32 = ctypes.windll.kernel32
    mask = k32.GetLogicalDrives()
    for i, letter in enumerate(string.ascii_uppercase):
        if not (mask >> i) & 1:
            continue
        root = letter + ":\\"
        dtype = DRIVE_TYPES.get(k32.GetDriveTypeW(ctypes.c_wchar_p(root)), "?")
        if dtype in ("cd", "invalido", "desconocido"):
            continue
        space = _drive_space(root)
        label = ""
        try:
            buf = ctypes.create_unicode_buffer(261)
            fsbuf = ctypes.create_unicode_buffer(261)
            if k32.GetVolumeInformationW(ctypes.c_wchar_p(root), buf, 261,
                                         None, None, None, fsbuf, 261):
                label = buf.value
        except Exception:
            pass
        out.append({
            "path": root,
            "label": label or root,
            "type": dtype,
            "total": space[0] if space else 0,
            "free": space[1] if space else 0,
        })
    return out


# ------------------------------------------------------------------- papelera

FO_DELETE = 3
FOF_SILENT = 0x0004
FOF_NOCONFIRMATION = 0x0010
FOF_ALLOWUNDO = 0x0040
FOF_NOERRORUI = 0x0400
FOF_NOCONFIRMMKDIR = 0x0200
FOF_WANTNUKEWARNING = 0x4000

if IS_WIN:
    from ctypes import wintypes

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_uint),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]


def send_to_trash(paths):
    """Mueve rutas a la papelera. Devuelve (ok, mensaje_error)."""
    if not IS_WIN:
        return False, "La papelera solo esta implementada en Windows"
    real = []
    for p in paths:
        p = os.path.abspath(strip_long(p))
        if len(p) >= 250:
            return False, "Ruta demasiado larga para la papelera: %s" % p
        real.append(p)
    if not real:
        return True, ""
    buf = "\0".join(real) + "\0\0"
    op = SHFILEOPSTRUCTW()
    op.hwnd = None
    op.wFunc = FO_DELETE
    op.pFrom = buf
    op.pTo = None
    op.fFlags = (FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT
                 | FOF_NOERRORUI | FOF_NOCONFIRMMKDIR)
    op.fAnyOperationsAborted = False
    op.hNameMappings = None
    op.lpszProgressTitle = None
    res = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    if res != 0:
        return False, "SHFileOperation devolvio el codigo %s" % res
    if op.fAnyOperationsAborted:
        return False, "Operacion cancelada por el sistema"
    return True, ""


# --------------------------------------------------- borrado permanente rapido

def _force_writable(path):
    try:
        os.chmod(path, stat.S_IWRITE)
    except Exception:
        pass


FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _is_link_stat(st) -> bool:
    """A symlink, a junction or any other reparse point: a link to somewhere else, never a folder of its own."""
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def is_link(path) -> bool:
    """True for symlinks AND junctions (os.path.islink says False for a junction; os.walk walks into it)."""
    try:
        return _is_link_stat(os.lstat(long_path(path)))
    except OSError:
        return False


def _remove_link(lp, st):
    """Remove the link itself. RemoveDirectory on a directory junction or symlink removes the reparse point and leaves the
    folder it points to untouched; a file symlink goes with unlink."""
    if stat.S_ISDIR(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x10:   # FILE_ATTRIBUTE_DIRECTORY
        try:
            os.rmdir(lp)
            return
        except OSError:
            pass
    os.unlink(lp)


def _unlink_file(fp, errors):
    try:
        os.unlink(fp)
        return True
    except PermissionError:
        _force_writable(fp)
        try:
            os.unlink(fp)
            return True
        except OSError as exc:
            errors.append("%s: %s" % (norm_display(fp), exc.strerror or exc))
    except OSError as exc:
        errors.append("%s: %s" % (norm_display(fp), exc.strerror or exc))
    return False


def delete_permanent(path, progress=None):
    """Borra un fichero o arbol completo. Devuelve (bytes, ficheros, errores).

    Nunca entra en un enlace: un symlink o una junction (de la ruta o de cualquier carpeta de dentro) se borra como
    enlace y lo que hay al otro lado se queda como estaba. os.walk(followlinks=False) SI entra en las junctions de
    Windows, y por eso este recorrido es propio: una copia de trabajo con node_modules enlazado al repositorio
    original vaciaba el original al borrar la copia."""
    freed = 0
    nfiles = 0
    errors = []
    lp = long_path(path)
    try:
        st = os.lstat(lp)
    except OSError as exc:
        return 0, 0, ["%s: %s" % (norm_display(path), exc.strerror or exc)]

    if _is_link_stat(st):
        try:
            _remove_link(lp, st)
        except OSError as exc:
            return 0, 0, ["%s: %s" % (norm_display(path), exc.strerror or exc)]
        return 0, 1, []

    if not stat.S_ISDIR(st.st_mode):
        if not _unlink_file(lp, errors):
            return 0, 0, errors
        return st.st_size, 1, []

    # post-order, iterative (node_modules can be deeper than the recursion limit)
    stack = [(lp, False)]
    while stack:
        cur, emptied = stack.pop()
        if emptied:
            try:
                os.rmdir(cur)
            except OSError as exc:
                if cur != lp:
                    errors.append("%s: %s" % (norm_display(cur), exc.strerror or exc))
            continue
        stack.append((cur, True))
        try:
            with os.scandir(cur) as it:
                entries = list(it)
        except OSError as exc:
            errors.append("%s: %s" % (norm_display(cur), exc.strerror or exc))
            continue
        for e in entries:
            try:
                est = e.stat(follow_symlinks=False)
            except OSError as exc:
                errors.append("%s: %s" % (norm_display(e.path), exc.strerror or exc))
                continue
            if _is_link_stat(est):
                try:
                    _remove_link(e.path, est)
                    nfiles += 1
                except OSError as exc:
                    errors.append("%s: %s" % (norm_display(e.path), exc.strerror or exc))
                continue
            if stat.S_ISDIR(est.st_mode):
                stack.append((e.path, False))
                continue
            if _unlink_file(e.path, errors):
                freed += est.st_size
                nfiles += 1
                if progress and nfiles % 500 == 0:
                    progress(freed, nfiles)
    try:
        if os.path.lexists(lp):
            os.rmdir(lp)
    except OSError as exc:
        errors.append("%s: %s" % (norm_display(path), exc.strerror or exc))
    if progress:
        progress(freed, nfiles)
    return freed, nfiles, errors
