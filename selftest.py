# -*- coding: utf-8 -*-
"""Prueba rapida del motor sin levantar el servidor:
    python selftest.py "C:\\ruta\\a\\escanear"
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from diskhoard import junk, scanner
from diskhoard.winfs import list_drives


def fb(b):
    for unit, size in (("TB", 1024**4), ("GB", 1024**3), ("MB", 1024**2), ("KB", 1024)):
        if b >= size:
            return "%.2f %s" % (b / size, unit)
    return "%d B" % b


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    print("Unidades:")
    for d in list_drives():
        print("   %-4s %-18s %10s usados  %10s libres" % (
            d["path"], d["label"][:18], fb(d["total"] - d["free"]), fb(d["free"])))
    print("\nEscaneando %s ..." % root)
    t0 = time.time()
    sc = scanner.Scanner(root)
    sc.start()
    while not sc.done:
        time.sleep(0.4)
        p = sc.progress()
        sys.stdout.write("\r  %s  %d ficheros  %d carpetas   " % (
            fb(p["bytes"]), p["files"], p["dirs"]))
        sys.stdout.flush()
    dt = time.time() - t0
    if sc.error:
        print("\nERROR:", sc.error)
        return 1
    print("\n\nTotal: %s en %d ficheros / %d carpetas  (%.1fs, %.0f ficheros/s)" % (
        fb(sc.root.size), sc.p_files, sc.p_dirs, dt, sc.p_files / max(dt, .001)))
    if sc.p_errors:
        print("Sin permiso: %d entradas" % sc.p_errors)

    print("\n--- Primer nivel ---")
    kids = sorted((sc.root.children or {}).items(), key=lambda kv: -kv[1].size)
    for name, node in kids[:18]:
        pct = node.size * 100.0 / max(sc.root.size, 1)
        print("  %10s  %5.1f%%  %s" % (fb(node.size), pct, name))

    print("\n--- Puntos calientes ---")
    for h in junk.hotspots(sc.root, sc.root_display)[:12]:
        print("  %10s  %5.1f%%  %s" % (fb(h["size"]), h["pct"], h["path"]))

    print("\n--- Basura detectada ---")
    items = junk.scan_junk(sc.root, sc.root_display)
    for c in junk.summarize_junk(items):
        print("  %10s  %s (%d)" % (fb(c["size"]), c["cat"], c["count"]))
    print("  --")
    for i in items[:15]:
        print("  %10s  [%-6s] %-28s %s" % (fb(i["size"]), i["safety"], i["label"][:28], i["path"]))

    print("\n--- Ficheros mas grandes ---")
    for size, p in sorted(sc.top_files, reverse=True)[:12]:
        print("  %10s  %s" % (fb(size), p))

    print("\n--- Por tipo ---")
    cats = {}
    for ext, (n, b) in sc.ext_stats.items():
        cats.setdefault(scanner.ext_category(ext), [0, 0])
        cats[scanner.ext_category(ext)][0] += n
        cats[scanner.ext_category(ext)][1] += b
    for cat, (n, b) in sorted(cats.items(), key=lambda kv: -kv[1][1])[:12]:
        print("  %10s  %-20s %d ficheros" % (fb(b), cat, n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
