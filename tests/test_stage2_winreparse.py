"""Tests for `fw_audit.stage2_extraction.winreparse` — parsing of
`IO_REPARSE_TAG_LX_SYMLINK` reparse-point payloads.

`_parse_lx_symlink_payload` is pure (bytes in, `str | None` out) and is
tested directly against the exact byte layout confirmed with `fsutil
reparsepoint query` on a real affected file (`sbin/nordvpn -> rc` in a
real committed firmware's rootfs) — see `winreparse.py`'s module
docstring. The Win32 API-calling half (`read_lx_symlink_target`) is
platform-gated and exercised indirectly via `test_stage2_resolve.py`'s
monkeypatched integration tests, since it needs a real reparse point on
disk to test meaningfully.
"""

from __future__ import annotations

import sys

import pytest

from fw_audit.stage2_extraction.winreparse import (
    _parse_lx_symlink_payload,
    read_lx_symlink_target,
)

# The exact bytes `DeviceIoControl(FSCTL_GET_REPARSE_POINT)` returned for
# a real `sbin/nordvpn -> rc` LX symlink: tag(4)=0xA000001D LE,
# data_len(2)=6 LE, reserved(2)=0, version(4)=2 LE, target="rc" (UTF-8).
_REAL_NORDVPN_TO_RC_BYTES = bytes.fromhex("1d0000a006000000020000007263")


def test_parses_real_captured_reparse_point_bytes():
    assert _parse_lx_symlink_payload(_REAL_NORDVPN_TO_RC_BYTES) == "rc"


def test_parses_longer_multi_component_target():
    target = "../../bin/busybox"
    target_bytes = target.encode("utf-8")
    data_len = 4 + len(target_bytes)  # version(4) + target
    raw = (
        (0xA000001D).to_bytes(4, "little")
        + data_len.to_bytes(2, "little")
        + b"\x00\x00"  # reserved
        + (2).to_bytes(4, "little")  # version
        + target_bytes
    )
    assert _parse_lx_symlink_payload(raw) == target


def test_wrong_reparse_tag_returns_none():
    """A DIFFERENT reparse tag (e.g. `IO_REPARSE_TAG_SYMLINK`, the one
    CPython's own `Path.is_symlink()` already handles, or a mount point)
    must be ignored, not misparsed."""
    raw = (0xA000000C).to_bytes(4, "little") + (6).to_bytes(2, "little") + b"\x00\x00rc"
    assert _parse_lx_symlink_payload(raw) is None


def test_truncated_buffer_returns_none():
    assert _parse_lx_symlink_payload(b"\x1d\x00\x00") is None


def test_empty_target_returns_none():
    """`data_len == 4` means only the version field, no target bytes at
    all -- not a usable symlink target."""
    raw = (0xA000001D).to_bytes(4, "little") + (4).to_bytes(2, "little") + b"\x00\x00" + (
        2
    ).to_bytes(4, "little")
    assert _parse_lx_symlink_payload(raw) is None


def test_invalid_utf8_target_returns_none_not_raises():
    raw = (
        (0xA000001D).to_bytes(4, "little")
        + (5).to_bytes(2, "little")
        + b"\x00\x00"
        + (2).to_bytes(4, "little")
        + b"\xff\xfe"
    )
    assert _parse_lx_symlink_payload(raw) is None


@pytest.mark.skipif(sys.platform == "win32", reason="tests the non-Windows short-circuit")
def test_read_lx_symlink_target_returns_none_off_windows(tmp_path):
    assert read_lx_symlink_target(tmp_path / "anything") is None


def test_read_lx_symlink_target_never_raises_for_nonexistent_path(tmp_path):
    """Never-raises contract: a path that doesn't exist at all must yield
    `None`, not an exception -- `resolve.py`'s symlink walk depends on
    this never surfacing an error outward."""
    assert read_lx_symlink_target(tmp_path / "does" / "not" / "exist") is None
