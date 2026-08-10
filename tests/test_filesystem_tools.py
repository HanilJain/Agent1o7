"""Tests for fw_audit.stage1_ingestion.tools.filesystem_tools.

This module belongs to Component 1 (Extraction Script): it describes ELF
files factually (for tree.txt annotation) but never scores/judges them —
that's the Identifier Agent's job (see tests/test_identifier_agent.py).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fw_audit.common.schemas import ELFArch
from fw_audit.stage1_ingestion.tools.filesystem_tools import (
    ELFParseError,
    is_elf,
    parse_elf_header,
    write_tree_txt,
)


def test_is_elf_true_for_elf_magic(work_dir: Path, synthetic_elf_bytes: bytes):
    p = work_dir / "httpd"
    p.write_bytes(synthetic_elf_bytes)
    assert is_elf(p) is True


def test_is_elf_false_for_non_elf(work_dir: Path):
    p = work_dir / "notelf.txt"
    p.write_text("hello")
    assert is_elf(p) is False


def test_is_elf_false_for_missing_file(work_dir: Path):
    assert is_elf(work_dir / "nope") is False


def test_parse_elf_header_reads_arch_and_endianness(work_dir: Path, synthetic_elf_bytes: bytes):
    p = work_dir / "httpd"
    p.write_bytes(synthetic_elf_bytes)
    info = parse_elf_header(p)
    assert info.arch == ELFArch.MIPS
    assert info.is_64bit is False
    assert info.is_little_endian is True
    assert info.size_bytes == len(synthetic_elf_bytes)


def test_parse_elf_header_raises_on_bad_magic(work_dir: Path):
    p = work_dir / "notelf"
    p.write_bytes(b"not an elf file at all")
    with pytest.raises(ELFParseError):
        parse_elf_header(p)


def test_parse_elf_header_raises_on_truncated_header(work_dir: Path):
    p = work_dir / "truncated"
    p.write_bytes(b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8 + b"\x00\x00")
    with pytest.raises(ELFParseError):
        parse_elf_header(p)


def test_describe_renders_readable_summary(work_dir: Path, synthetic_elf_bytes: bytes):
    p = work_dir / "httpd"
    p.write_bytes(synthetic_elf_bytes)
    info = parse_elf_header(p)
    description = info.describe()
    assert "ELF" in description
    assert "32-bit" in description
    assert "LSB" in description
    assert "MIPS" in description


def test_write_tree_txt_lists_nested_structure(work_dir: Path):
    root = work_dir / "rootfs"
    (root / "bin").mkdir(parents=True)
    (root / "etc").mkdir()
    (root / "bin" / "httpd").write_text("x")
    (root / "etc" / "config").write_text("y")

    out = work_dir / "tree.txt"
    write_tree_txt(root, out)
    content = out.read_text()

    assert "bin/" in content
    assert "httpd" in content
    assert "etc/" in content
    assert "config" in content


def test_write_tree_txt_skips_pseudo_dirs(work_dir: Path):
    root = work_dir / "rootfs"
    (root / "proc").mkdir(parents=True)
    (root / "bin").mkdir()
    (root / "bin" / "sh").write_text("x")

    out = work_dir / "tree.txt"
    write_tree_txt(root, out)
    content = out.read_text()

    assert "proc" not in content
    assert "bin/" in content


def test_write_tree_txt_annotates_file_sizes(work_dir: Path):
    root = work_dir / "rootfs"
    root.mkdir()
    (root / "config.txt").write_text("hello world")  # 11 bytes

    out = work_dir / "tree.txt"
    write_tree_txt(root, out)
    content = out.read_text()

    assert "config.txt  11B" in content


def test_write_tree_txt_annotates_elf_with_descriptor(work_dir: Path, synthetic_elf_bytes: bytes):
    root = work_dir / "rootfs"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "httpd").write_bytes(synthetic_elf_bytes)

    out = work_dir / "tree.txt"
    write_tree_txt(root, out)
    content = out.read_text()

    assert "httpd" in content
    assert "ELF 32-bit LSB MIPS" in content


def test_write_tree_txt_survives_entry_whose_is_dir_raises(work_dir: Path, monkeypatch):
    """Regression test for a real bug hit against real firmware on Windows:
    a dangling relative symlink (`debug -> sys/kernel/debug` in a static
    rootfs where sysfs was never populated by a running kernel) makes
    `Path.is_dir()` raise `OSError` (WinError 1920) when it tries to
    resolve the symlink target. The sort key used to call `is_dir()`
    unconditionally on every entry, so ONE such entry destroyed the
    ENTIRE sibling listing for that directory — `sorted()` can't return
    partial results on exception — silently dropping `bin/`, `sbin/`,
    `usr/`, and every other directory actually containing binaries, with
    only `[unreadable: ...]` left behind. Reproduced here without relying
    on OS-specific symlink error codes, by directly forcing `is_dir()` to
    raise for one named entry."""
    root = work_dir / "rootfs"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "httpd").write_text("x")
    (root / "broken").write_text("")  # stands in for the problematic entry

    real_is_dir = Path.is_dir

    def _flaky_is_dir(self: Path, *args, **kwargs):
        if self.name == "broken":
            raise OSError(1920, "The file cannot be accessed by the system")
        return real_is_dir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_dir", _flaky_is_dir)

    out = work_dir / "tree.txt"
    write_tree_txt(root, out)
    content = out.read_text()

    assert "bin/" in content
    assert "httpd" in content
    assert "broken" in content


def test_write_tree_txt_directories_have_no_size_annotation(work_dir: Path):
    root = work_dir / "rootfs"
    (root / "bin").mkdir(parents=True)

    out = work_dir / "tree.txt"
    write_tree_txt(root, out)
    lines = out.read_text().splitlines()

    bin_line = next(line for line in lines if "bin/" in line)
    assert "B" not in bin_line.split("bin/")[-1]
