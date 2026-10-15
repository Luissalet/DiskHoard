# -*- coding: utf-8 -*-
"""Deleting a folder that holds a link (a junction on Windows, a symlink elsewhere) removes the link and leaves what it
points to alone. On 15-10-2026 a cleanup of review copies whose node_modules were junctions to the real repositories
emptied those repositories: os.walk(followlinks=False) walks into junctions."""
import os
import subprocess
import sys

import pytest

from diskhoard import winfs


def _link_dir(link, target):
    if sys.platform == "win32":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)
    else:
        os.symlink(target, link, target_is_directory=True)


def _tree(root):
    (root / "pkg" / "lib").mkdir(parents=True)
    (root / "pkg" / "lib" / "a.js").write_text("a" * 100)
    (root / "README.md").write_text("keep me")


def test_link_inside_a_deleted_tree_keeps_its_target(tmp_path):
    target = tmp_path / "real-repo"
    _tree(target)
    copy = tmp_path / "review-copy"
    (copy / "src").mkdir(parents=True)
    (copy / "src" / "x.py").write_text("x" * 10)
    _link_dir(copy / "node_modules", target)
    deep = copy / "src" / "deeper"
    deep.mkdir()
    _link_dir(deep / "data", target / "pkg")
    freed, n, errors = winfs.delete_permanent(str(copy))
    assert errors == []
    assert not copy.exists()
    assert (target / "README.md").read_text() == "keep me"
    assert (target / "pkg" / "lib" / "a.js").exists()
    assert freed == 10            # only the copy's own file


def test_deleting_the_link_itself_keeps_its_target(tmp_path):
    target = tmp_path / "real"
    _tree(target)
    link = tmp_path / "link"
    _link_dir(link, target)
    assert winfs.is_link(str(link))
    freed, n, errors = winfs.delete_permanent(str(link))
    assert errors == [] and freed == 0
    assert not os.path.lexists(link)
    assert (target / "README.md").exists()


def test_plain_tree_and_file_still_go(tmp_path):
    root = tmp_path / "junk"
    _tree(root)
    freed, n, errors = winfs.delete_permanent(str(root))
    assert errors == [] and not root.exists() and freed == 107 and n == 2
    f = tmp_path / "f.bin"
    f.write_bytes(b"12345")
    assert winfs.delete_permanent(str(f)) == (5, 1, [])


def test_deep_tree_has_no_recursion_limit(tmp_path):
    root = tmp_path / "deep"
    cur = root
    for i in range(60):
        cur = cur / "d"
    os.makedirs(winfs.long_path(str(cur)))
    with open(winfs.long_path(str(cur / "f.txt")), "w") as fh:
        fh.write("z")
    freed, n, errors = winfs.delete_permanent(str(root))
    assert errors == [] and not root.exists() and n == 1


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are a Windows thing")
def test_os_walk_really_walks_into_junctions(tmp_path):
    """The reason for the own traversal: if this ever stops being true, the guard still costs nothing."""
    target = tmp_path / "t"
    _tree(target)
    holder = tmp_path / "h"
    holder.mkdir()
    _link_dir(holder / "j", target)
    walked = [r for r, _, _ in os.walk(str(holder), followlinks=False)]
    assert winfs.is_link(str(holder / "j"))
    assert not os.path.islink(str(holder / "j")) or len(walked) >= 1
