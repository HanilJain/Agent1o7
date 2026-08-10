"""Tests for the decompiled-C mirror tree path algebra in
`fw_audit.stage2_extraction.layout` (pure functions — no I/O, no executor).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fw_audit.stage2_extraction.layout import (
    decompiled_tree_dir,
    decompiled_tree_file,
    is_contained,
)


def test_decompiled_tree_dir_is_sibling(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    db_subfolder.mkdir(parents=True)

    tree = decompiled_tree_dir(db_subfolder)

    assert tree == tmp_path / "db" / "fw_decompiled"
    assert tree.parent == db_subfolder.parent


def test_decompiled_tree_dir_resolves_relative_db_subfolder(tmp_path, monkeypatch):
    # db_subfolder as Stage 1 actually records it is CWD-relative (verified
    # against a real stage1_summary.json: is_absolute() == False) — a
    # sibling of a relative path is only well-defined once anchored.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data" / "db" / "fw").mkdir(parents=True)
    relative_db_subfolder = Path("data") / "db" / "fw"

    tree = decompiled_tree_dir(relative_db_subfolder)

    assert tree == tmp_path / "data" / "db" / "fw_decompiled"
    assert tree.is_absolute()


@pytest.mark.parametrize(
    "rootfs_rel,expected_parts",
    [
        ("bin/busybox", ("bin", "busybox.c")),
        ("lib/libbcm_boardctl.so", ("lib", "libbcm_boardctl.so.c")),
        ("lib/modules/wifi.ko", ("lib", "modules", "wifi.ko.c")),
        ("lib/libnvram-2.so", ("lib", "libnvram-2.so.c")),
        ("/bin/httpd", ("bin", "httpd.c")),  # leading slash stripped, not an escape
    ],
)
def test_decompiled_tree_file_appends_c(tmp_path, rootfs_rel, expected_parts):
    tree_dir = tmp_path / "fw_decompiled"

    result = decompiled_tree_file(tree_dir, rootfs_rel)

    assert result == tree_dir.joinpath(*expected_parts)


def test_decompiled_tree_file_never_replaces_extension(tmp_path):
    tree_dir = tmp_path / "fw_decompiled"

    result = decompiled_tree_file(tree_dir, "lib/libbcm_boardctl.so")

    assert result.name == "libbcm_boardctl.so.c"
    assert result != tree_dir / "lib" / "libbcm_boardctl.c"


def test_is_contained_accepts_paths_inside(tmp_path):
    parent = tmp_path / "fw_decompiled"
    parent.mkdir()
    child = parent / "bin" / "busybox.c"

    assert is_contained(child, parent) is True


@pytest.mark.parametrize(
    "rootfs_rel",
    [
        "../escape",
        "../../etc/passwd",
        "Z:/evil/x",  # a DIFFERENT drive than tmp_path's own -- genuinely escapes
    ],
)
def test_is_contained_rejects_traversal(tmp_path, rootfs_rel):
    parent = tmp_path / "fw_decompiled"
    parent.mkdir()
    candidate = decompiled_tree_file(parent, rootfs_rel)

    assert is_contained(candidate, parent) is False


def test_is_contained_same_drive_letter_literal_stays_contained(tmp_path):
    # A literal "C:" segment matching tree_dir's OWN drive is silently
    # absorbed by Path.joinpath (a same-drive bare "X:" is a no-op, not an
    # anchor reset) -- verified: the result lands INSIDE tree_dir, so this
    # is safe (not a containment bypass), just a data-fidelity oddity where
    # the "C:" segment vanishes from the mirrored path. Only a DIFFERENT
    # drive letter (see test_is_contained_rejects_traversal) resets the
    # anchor and escapes.
    parent = tmp_path / "fw_decompiled"
    parent.mkdir()
    own_drive = parent.drive  # e.g. "C:" on the machine actually running this
    candidate = decompiled_tree_file(parent, f"{own_drive}/Windows/x")

    assert is_contained(candidate, parent) is True
