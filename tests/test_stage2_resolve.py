"""Tests for fw_audit.stage2_extraction.resolve.

Covers the resolver's containment guarantees against untrusted,
LLM-authored IdentifiedBinary.path input — see the module docstring for the
never-raises contract this exercises end to end.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fw_audit.common.schemas import IdentifiedBinary
from fw_audit.stage2_extraction import resolve as resolve_module
from fw_audit.stage2_extraction.resolve import Resolution, resolve_binaries


def _symlink_or_skip(link: Path, target: str) -> None:
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(
            "symlink creation requires elevated privileges or Windows Developer "
            f"Mode on this host: {exc}"
        )


def _make_rootfs(tmp_path: Path) -> Path:
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "usr" / "sbin").mkdir(parents=True)
    return rootfs


def _write_elf(path: Path, elf_bytes: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(elf_bytes)


def test_leading_slash_is_stripped_not_rejected(tmp_path, synthetic_elf_bytes):
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "bin" / "httpd", synthetic_elf_bytes)

    report = resolve_binaries(
        [IdentifiedBinary(path="/bin/httpd")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    assert report.resolved[0].rootfs_rel == "bin/httpd"
    assert report.resolved[0].resolution == Resolution.DIRECT


def test_backslashes_are_normalized(tmp_path, synthetic_elf_bytes):
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "usr" / "sbin" / "httpd", synthetic_elf_bytes)

    report = resolve_binaries(
        [IdentifiedBinary(path="usr\\sbin\\httpd")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    assert report.resolved[0].rootfs_rel == "usr/sbin/httpd"


def test_dotdot_traversal_is_rejected(tmp_path, synthetic_elf_bytes):
    rootfs = _make_rootfs(tmp_path)
    (tmp_path / "outside.bin").write_bytes(synthetic_elf_bytes)

    report = resolve_binaries(
        [IdentifiedBinary(path="../outside.bin")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert report.resolved == ()
    assert len(report.unresolved) == 1
    assert report.unresolved[0].problem == "not_a_rootfs_path"


def test_windows_drive_prefix_is_rejected(tmp_path):
    rootfs = _make_rootfs(tmp_path)
    report = resolve_binaries(
        [IdentifiedBinary(path="C:\\Windows\\system32\\cmd.exe")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )
    assert report.unresolved[0].problem == "not_a_rootfs_path"


def test_absolute_symlink_is_rerooted_inside_rootfs_not_followed_to_host(
    tmp_path, synthetic_elf_bytes
):
    """usr/bin/wget -> /bin/busybox must resolve to rootfs/bin/busybox, NOT
    to the host's own /bin/busybox (Path.resolve() would do the latter)."""
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "bin" / "busybox", synthetic_elf_bytes)
    (rootfs / "usr" / "bin").mkdir(parents=True, exist_ok=True)
    _symlink_or_skip(rootfs / "usr" / "bin" / "wget", "/bin/busybox")

    report = resolve_binaries(
        [IdentifiedBinary(path="usr/bin/wget")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    resolved = report.resolved[0]
    assert resolved.host_path == (rootfs / "bin" / "busybox").resolve()
    assert resolved.resolution == Resolution.SYMLINK
    # The requested name ("wget") is what gets decompiled/reported under --
    # bin_id, DecompiledBinary.rootfs_path, and the mirror tree all derive
    # from this -- even though the actual bytes come from busybox.
    assert resolved.rootfs_rel == "usr/bin/wget"


def test_symlink_target_requested_separately_becomes_an_alias(tmp_path, synthetic_elf_bytes):
    """When BOTH a symlink and its real target are separately requested
    (e.g. Stage 1 flags "sbin/wpasupp" AND "sbin/rc"), only one physical
    decompilation happens -- whichever was listed first keeps its own name
    as the identity, the other folds into aliases. This mirrors the
    existing content-hash dedup policy (first-in-order wins), just via the
    host-path fold instead."""
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "sbin" / "rc", synthetic_elf_bytes)
    _symlink_or_skip(rootfs / "sbin" / "wpasupp", "rc")

    report = resolve_binaries(
        [IdentifiedBinary(path="sbin/wpasupp"), IdentifiedBinary(path="sbin/rc")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    resolved = report.resolved[0]
    assert resolved.rootfs_rel == "sbin/wpasupp"  # first-listed wins as identity
    assert resolved.aliases == ("sbin/rc",)


def test_basename_rescan_still_reports_actual_found_location_not_requested(
    tmp_path, synthetic_elf_bytes
):
    """Unlike a symlink, a basename-rescan recovery means the REQUESTED
    path was wrong (a hallucinated directory) -- the identity must stay
    the actual found location, not the incorrect request, or the report
    would claim a file lives somewhere it doesn't."""
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "bin" / "httpd", synthetic_elf_bytes)

    report = resolve_binaries(
        [IdentifiedBinary(path="usr/sbin/httpd")],  # wrong directory
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    resolved = report.resolved[0]
    assert resolved.resolution == Resolution.BASENAME_RESCAN
    assert resolved.requested == "usr/sbin/httpd"  # what was (wrongly) asked
    assert resolved.rootfs_rel == "bin/httpd"  # where it actually is


def test_symlink_escaping_rootfs_is_rejected(tmp_path, synthetic_elf_bytes):
    rootfs = _make_rootfs(tmp_path)
    outside = tmp_path / "outside_target"
    outside.write_bytes(synthetic_elf_bytes)
    _symlink_or_skip(rootfs / "bin" / "escapee", "../../outside_target")

    report = resolve_binaries(
        [IdentifiedBinary(path="bin/escapee")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert report.resolved == ()
    assert report.unresolved[0].problem == "escapes_rootfs"


def test_symlink_loop_hits_hop_cap(tmp_path):
    rootfs = _make_rootfs(tmp_path)
    _symlink_or_skip(rootfs / "bin" / "a", "b")
    _symlink_or_skip(rootfs / "bin" / "b", "a")

    report = resolve_binaries(
        [IdentifiedBinary(path="bin/a")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert report.resolved == ()
    assert report.unresolved[0].problem == "symlink_loop"


def test_single_hit_basename_rescan_recovers_hallucinated_directory(tmp_path, synthetic_elf_bytes):
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "bin" / "httpd", synthetic_elf_bytes)

    report = resolve_binaries(
        [IdentifiedBinary(path="usr/sbin/httpd")],  # wrong directory
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    assert report.resolved[0].rootfs_rel == "bin/httpd"
    assert report.resolved[0].resolution == Resolution.BASENAME_RESCAN
    assert any("basename rescan" in w for w in report.warnings)


def test_basename_rescan_skips_dangling_symlink_without_raising(tmp_path, synthetic_elf_bytes):
    """A router rootfs can contain a dangling relative symlink like
    `debug -> sys/kernel/debug` (sysfs is normally populated by a running
    kernel, absent from a static extracted image). `_is_file_safe`'s
    `is_symlink()` short-circuit (an `lstat`, never follows the link) must
    skip it cleanly during the basename-rescan fallback."""
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "bin" / "httpd", synthetic_elf_bytes)
    _symlink_or_skip(rootfs / "debug", "sys/kernel/debug")  # target never exists

    report = resolve_binaries(
        [IdentifiedBinary(path="usr/sbin/httpd")],  # wrong directory -> forces rescan
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    assert report.resolved[0].rootfs_rel == "bin/httpd"


def test_basename_rescan_skips_unstattable_entry_without_raising(
    tmp_path, synthetic_elf_bytes, monkeypatch
):
    """Regression test for the actual bug observed against a real firmware
    rootfs: `.../squashfs-root/debug` is NOT reported as a symlink by
    `Path.is_symlink()` (confirmed `False` against the real entry) --
    `unsquashfs` materialized some other special-file type (most likely a
    device/socket/FIFO from the original Linux rootfs) that Windows can't
    `stat()`, raising `OSError: [WinError 1920] The file cannot be
    accessed by the system`. This is the case the `is_symlink()`
    short-circuit does NOT catch -- only `_is_file_safe`'s `try/except
    OSError` backstop does, which this test pins directly (a real dangling
    symlink can't be reliably created cross-platform in a unit test, but
    the failure mode -- `Path.is_file()` raising `OSError` on a listed
    entry -- is exactly what's being guarded against, and is reproduced
    here via monkeypatch)."""
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "bin" / "httpd", synthetic_elf_bytes)
    unstattable = rootfs / "debug"
    unstattable.write_bytes(b"")  # must exist for os.walk to list it

    real_is_file = Path.is_file

    def fake_is_file(self, *args, **kwargs):
        if self == unstattable:
            raise OSError(
                1920, "The file cannot be accessed by the system", str(unstattable)
            )
        return real_is_file(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", fake_is_file)

    report = resolve_binaries(
        [IdentifiedBinary(path="usr/sbin/httpd")],  # wrong directory -> forces rescan
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    assert report.resolved[0].rootfs_rel == "bin/httpd"


def test_lx_symlink_reparse_point_is_followed_on_windows(
    tmp_path, synthetic_elf_bytes, monkeypatch
):
    """Regression test for the actual bug observed against a real firmware
    rootfs: a rootfs extracted via a Linux container through Docker
    Desktop's WSL2 backend stores real POSIX symlinks as
    `IO_REPARSE_TAG_LX_SYMLINK` reparse points — `Path.is_symlink()`
    doesn't recognize this tag at all and reports `False`, so the old code
    treated a genuine symlink (confirmed: `sbin/nordvpn -> rc`, one of 409
    affected entries in one real committed firmware) as a terminal,
    unreadable regular file and silently reported it `not_found`.

    A real `IO_REPARSE_TAG_LX_SYMLINK` reparse point can't portably be
    created in a unit test (it requires WSL2/Docker Desktop's filesystem
    driver, not just admin rights) — this instead monkeypatches
    `winreparse.read_lx_symlink_target` (the exact seam `_walk_symlinks`
    calls) to simulate what a real one returns, which is enough to pin the
    `_walk_symlinks` control flow this bug was in.
    """
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "sbin" / "rc", synthetic_elf_bytes)
    # A plain regular file standing in for the LX-symlink reparse point --
    # is_symlink() is False for it, exactly like the real broken case.
    (rootfs / "sbin" / "nordvpn").write_bytes(b"")

    def fake_lx_target(path: Path) -> str | None:
        if path.name == "nordvpn":
            return "rc"
        return None

    monkeypatch.setattr(resolve_module, "read_lx_symlink_target", fake_lx_target)

    report = resolve_binaries(
        [IdentifiedBinary(path="sbin/nordvpn")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert report.unresolved == ()
    assert len(report.resolved) == 1
    resolved = report.resolved[0]
    assert resolved.resolution == Resolution.SYMLINK
    assert resolved.symlink_chain == ("rc",)
    assert resolved.rootfs_rel == "sbin/nordvpn"  # identity kept as requested
    assert resolved.host_path == rootfs / "sbin" / "rc"  # bytes come from the real target


def test_lx_symlink_fallback_not_triggered_for_a_real_regular_file(
    tmp_path, synthetic_elf_bytes, monkeypatch
):
    """The fallback must never fire for an ordinary file that just happens
    to not be a symlink -- `read_lx_symlink_target` returning `None` (as it
    always does for a non-reparse-point entry) must leave normal DIRECT
    resolution working exactly as before."""
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "bin" / "httpd", synthetic_elf_bytes)

    calls: list[Path] = []

    def tracking_lx_target(path: Path) -> str | None:
        calls.append(path)
        return None

    monkeypatch.setattr(resolve_module, "read_lx_symlink_target", tracking_lx_target)

    report = resolve_binaries(
        [IdentifiedBinary(path="bin/httpd")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    assert report.resolved[0].resolution == Resolution.DIRECT
    assert calls == [rootfs / "bin" / "httpd"]  # the fallback WAS consulted, and correctly declined


def test_is_symlink_raising_oserror_is_treated_as_terminal_not_a_crash(
    tmp_path, synthetic_elf_bytes, monkeypatch
):
    """A sufficiently broken/exotic filesystem entry can make even
    `Path.is_symlink()` itself raise `OSError` (confirmed against a real
    firmware rootfs: an entry unreadable by `fsutil`/Git Bash's own `ls`
    too, unrelated to the LX-symlink case above). `resolve_binaries` must
    still never raise -- this pins that `_walk_symlinks` catches it and
    treats the entry as a non-symlink terminal, letting `_is_file_safe`
    downstream reject it cleanly."""
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "bin" / "httpd", synthetic_elf_bytes)
    broken = rootfs / "bin" / "broken"
    broken.write_bytes(b"")

    real_is_symlink = Path.is_symlink

    def fake_is_symlink(self, *args, **kwargs):
        if self == broken:
            raise OSError(1920, "The file cannot be accessed by the system", str(broken))
        return real_is_symlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    report = resolve_binaries(
        [IdentifiedBinary(path="bin/broken"), IdentifiedBinary(path="bin/httpd")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    assert report.resolved[0].rootfs_rel == "bin/httpd"
    assert len(report.unresolved) == 1
    assert report.unresolved[0].requested_path == "bin/broken"


def test_ambiguous_basename_rescan_is_unresolved(tmp_path, synthetic_elf_bytes):
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "bin" / "toolA" / "httpd", synthetic_elf_bytes)
    _write_elf(rootfs / "usr" / "toolB" / "httpd", synthetic_elf_bytes)
    # Neither candidate shares a path-component suffix with "opt/httpd" —
    # both score 0 beyond the basename match itself -> tie -> ambiguous.
    report = resolve_binaries(
        [IdentifiedBinary(path="opt/httpd")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert report.resolved == ()
    assert "ambiguous_basename" in report.unresolved[0].problem


def test_non_elf_hit_is_rejected(tmp_path):
    rootfs = _make_rootfs(tmp_path)
    (rootfs / "etc").mkdir()
    (rootfs / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/sh\n", encoding="utf-8")

    report = resolve_binaries(
        [IdentifiedBinary(path="etc/passwd")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert report.resolved == ()
    assert report.unresolved[0].problem == "not_an_elf"


def test_allowed_extensions_are_resolved(tmp_path, synthetic_elf_bytes):
    """.so, .ko, .bin, and no extension at all are the only extensions
    Stage 2 sends to Ghidra."""
    rootfs = _make_rootfs(tmp_path)
    names = ["busybox", "libfoo.so", "driver.ko", "firmware.bin"]
    for i, name in enumerate(names):
        _write_elf(rootfs / "bin" / name, synthetic_elf_bytes + bytes([i]))

    report = resolve_binaries(
        [IdentifiedBinary(path=f"bin/{name}") for name in names],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == len(names)
    assert report.unresolved == ()


def test_versioned_shared_library_extension_is_allowed(tmp_path, synthetic_elf_bytes):
    """libc.so.6-style versioned libraries must still match .so — checked
    via the FIRST suffix, not Path.suffix's last one (".6")."""
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "bin" / "libc.so.6", synthetic_elf_bytes)

    report = resolve_binaries(
        [IdentifiedBinary(path="bin/libc.so.6")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    assert report.unresolved == ()


def test_disallowed_extension_is_rejected(tmp_path, synthetic_elf_bytes):
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "bin" / "module.prog", synthetic_elf_bytes)

    report = resolve_binaries(
        [IdentifiedBinary(path="bin/module.prog")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert report.resolved == ()
    assert report.unresolved[0].problem == "disallowed_extension"


def test_content_identical_binaries_dedupe_into_aliases(tmp_path, synthetic_elf_bytes):
    """The busybox case: multiple shortlisted paths that are byte-identical
    must decompile once, with the others folded into `aliases`."""
    rootfs = _make_rootfs(tmp_path)
    for name in ("ls", "cat", "echo"):
        _write_elf(rootfs / "bin" / name, synthetic_elf_bytes)

    report = resolve_binaries(
        [
            IdentifiedBinary(path="bin/ls"),
            IdentifiedBinary(path="bin/cat"),
            IdentifiedBinary(path="bin/echo"),
        ],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    kept = report.resolved[0]
    assert kept.requested == "bin/ls"
    assert set(kept.aliases) == {"bin/cat", "bin/echo"}


def test_duplicate_requested_paths_dedupe_by_host_path(tmp_path, synthetic_elf_bytes):
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "bin" / "httpd", synthetic_elf_bytes)

    report = resolve_binaries(
        [
            IdentifiedBinary(path="bin/httpd"),
            IdentifiedBinary(path="/bin/httpd"),
        ],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    assert report.resolved[0].aliases == ("/bin/httpd",)


def test_missing_path_is_unresolved_run_continues(tmp_path, synthetic_elf_bytes):
    rootfs = _make_rootfs(tmp_path)
    _write_elf(rootfs / "bin" / "httpd", synthetic_elf_bytes)

    report = resolve_binaries(
        [
            IdentifiedBinary(path="bin/httpd"),
            IdentifiedBinary(path="bin/does_not_exist_anywhere"),
        ],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    assert len(report.unresolved) == 1
    assert report.unresolved[0].problem == "not_found"


def test_empty_path_is_unresolved(tmp_path):
    rootfs = _make_rootfs(tmp_path)
    report = resolve_binaries(
        [IdentifiedBinary(path="   ")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )
    assert report.unresolved[0].problem == "empty_path"


def test_max_binaries_cap_drops_overflow_as_warning_not_failure(tmp_path, synthetic_elf_bytes):
    rootfs = _make_rootfs(tmp_path)
    items = []
    for i in range(5):
        name = f"bin{i}"
        unique_elf = synthetic_elf_bytes + bytes([i])  # unique content -> no dedupe
        _write_elf(rootfs / "bin" / name, unique_elf)
        items.append(IdentifiedBinary(path=f"bin/{name}"))

    report = resolve_binaries(items, rootfs, max_binaries=2, max_rescan_files=10_000)

    assert len(report.resolved) == 2
    assert any("max_binaries" in w for w in report.warnings)


def test_unparseable_elf_header_kept_with_none_elf(tmp_path):
    """Ghidra's own loader is more tolerant than parse_elf_header — a
    truncated header must not drop a real ELF-magic'd binary."""
    rootfs = _make_rootfs(tmp_path)
    truncated = rootfs / "bin" / "weird"
    truncated.write_bytes(b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8 + b"\x00\x00")

    report = resolve_binaries(
        [IdentifiedBinary(path="bin/weird")],
        rootfs,
        max_binaries=25,
        max_rescan_files=10_000,
    )

    assert len(report.resolved) == 1
    assert report.resolved[0].elf is None
