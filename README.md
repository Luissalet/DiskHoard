# DiskHoard

[Español](README.es.md)

A local disk explorer and cleaner for Windows. Scan a drive or folder, see **where the space actually goes**, browse folder sizes by level and clean from the interface. It uses Python's standard library and a browser; its MCP stdio server lets Faustus or another assistant use the same scan and cleanup tools.

![Explorer](docs/explorador.jpg)

## Start

Double-click `DiskHoard.bat` to open the local interface at `127.0.0.1`. Choose a drive, a shortcut such as Desktop or Downloads, or a path, then scan and browse. `DiskHoard (admin).bat` can include system folders that a normal scan cannot read. For a console-only check:

```sh
python selftest.py "C:\path\to\scan"
```

The last completed folder scan is cached in `data/last-scan.pkl.gz` and restored on launch. Assistant tools report its age as `snapshot.age_h`; `disk_scan` refreshes it. Set `DISKHOARD_RESTORE=0` to disable restore.

## What the explorer shows

- **Hotspots:** a non-overlapping partition of the disk usage. The algorithm descends through each branch until it can attribute weight to a specific subfolder and groups scattered remainder separately.
- **Known reclaimable folders:** `node_modules`, virtual environments, package caches, build artifacts, model caches, GPU shaders, Windows temporary files, Docker/WSL disks and more. Each rule explains what it is, how it regenerates and whether deletion is safe, needs review or must be avoided. Context checks prevent false positives such as treating any folder named `target` as Rust output.
- **Treemap, large files, file types and stale folders:** browse visually, inspect the 500 largest files, understand categories and find large folders untouched for over a year.

![Hotspots](docs/puntos-calientes.jpg)

## Cleanup

Choose **Move to Recycle Bin**, **Delete permanently** or **Generate script**. The PowerShell script is reviewable and supports `-WhatIf`. A confirmation dialog names every target before deletion. Afterward, rescan just that subtree to see the effect. Permanent deletion is irreversible.

The assistant can never delete drive roots, the user profile and main folders, Windows, Program Files, ProgramData or other protected targets. The MCP layer applies the same rules as the UI.

## MCP tools

`mcp_server.py` exposes 14 stdio tools and starts the local app if needed:

| Tools | Purpose |
| --- | --- |
| `disk_drives`, `disk_scan`, `disk_status` | Find drives and shortcuts; start or check a scan. |
| `disk_dir`, `disk_hotspots`, `disk_junk` | Browse folder sizes, non-overlapping hotspots and known cleanup candidates. |
| `disk_stale`, `disk_top_files`, `disk_types`, `disk_find` | Find old, large or matching files and size by type. |
| `disk_explain`, `disk_script`, `disk_delete`, `disk_rescan` | Explain a target, prepare a script, delete or refresh a subtree. |

See [the Spanish README](README.es.md) for the full rule catalogue and examples.
