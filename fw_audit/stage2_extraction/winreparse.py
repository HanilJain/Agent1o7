"""Read `IO_REPARSE_TAG_LX_SYMLINK` reparse points directly, when standard
library symlink APIs can't see them at all.

Why this exists
--------------------------------------------------------------------------
A firmware rootfs extracted by `unsquashfs` running inside a Linux
container (Stage 1's Docker executor), writing onto a Windows-hosted bind
mount via Docker Desktop's WSL2 backend, produces REAL POSIX symlinks —
but WSL2 stores them on NTFS as `IO_REPARSE_TAG_LX_SYMLINK` reparse points
(tag `0xA000001D`), not the older `IO_REPARSE_TAG_SYMLINK` (`0xA000000C`)
Windows' own symlink APIs understand. The practical result, confirmed
against a real extracted rootfs: `Path.is_symlink()` returns `False` (CPython
only recognizes `IO_REPARSE_TAG_SYMLINK`/`IO_REPARSE_TAG_MOUNT_POINT`), and
`Path.is_file()`/`os.stat()` — which follow the reparse point — raise
`OSError: [WinError 1920] The file cannot be accessed by the system`,
because Win32's own `CreateFile` has no filter driver installed that
resolves this tag either (only WSL's own filesystem driver does). Every
entry silently looks like neither a symlink nor a readable file, and
`resolve.py`'s symlink walk gives up — which is exactly what happened for
409 real symlinks (busybox applets, `sbin/nordvpn -> rc`, etc.) in one
real committed firmware's extracted rootfs.

Git-for-Windows' MSYS2 runtime (`readlink`, `ls -la`) DOES understand this
tag — which is why `readlink sbin/nordvpn` in Git Bash correctly prints
"rc" while the exact same path is invisible to Python. That gap is what
this module closes: read the reparse point's raw bytes ourselves via
`DeviceIoControl(FSCTL_GET_REPARSE_POINT)` and parse the (documented, if
obscure) `IO_REPARSE_TAG_LX_SYMLINK` payload — 4-byte version, then the
UTF-8 target, no NUL terminator — confirmed byte-for-byte against
`fsutil reparsepoint query` on a real affected file.

Scope and safety
--------------------------------------------------------------------------
Windows-only (`sys.platform == "win32"`), stdlib `ctypes` only — no new
dependency, no admin/Developer Mode privilege needed to READ a reparse
point (only creating a native Win32 symlink needs that). `read_lx_symlink_target`
NEVER raises: any failure (wrong platform, wrong tag, malformed payload,
API error) returns `None`, and `resolve.py`'s caller treats `None` exactly
like "not a symlink" — this module can only ever recover a target that a
plain existence check would otherwise have missed, never mask a genuine
problem.
"""

from __future__ import annotations

import sys
from pathlib import Path

#: The one non-standard reparse tag this module knows how to parse.
#: `0xA000000C` (`IO_REPARSE_TAG_SYMLINK`, the tag CPython's `os` module
#: already understands) is deliberately NOT handled here — that path is
#: already covered by `Path.is_symlink()`/`Path.readlink()`.
_IO_REPARSE_TAG_LX_SYMLINK = 0xA000001D

_FSCTL_GET_REPARSE_POINT = 0x900A8
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x1
_FILE_SHARE_WRITE = 0x2
_FILE_SHARE_DELETE = 0x4
_OPEN_EXISTING = 3
#: Reparse-point payloads are capped well under 16 KiB by the NTFS spec;
#: this comfortably covers any real symlink target.
_REPARSE_BUFFER_SIZE = 16 * 1024
#: `REPARSE_DATA_BUFFER`'s fixed header: ReparseTag(4) + ReparseDataLength(2)
#: + Reserved(2), before the tag-specific payload begins.
_HEADER_SIZE = 8
#: `IO_REPARSE_TAG_LX_SYMLINK`'s own payload header: a 4-byte version field
#: (observed value 2) preceding the raw UTF-8 target bytes.
_LX_SYMLINK_VERSION_SIZE = 4

is_supported = sys.platform == "win32"


def read_lx_symlink_target(path: Path) -> str | None:
    """Return the raw target string of `path` if it's an
    `IO_REPARSE_TAG_LX_SYMLINK` reparse point, else `None`.

    `None` covers every non-match/failure case uniformly (wrong platform,
    path doesn't exist, not a reparse point, a DIFFERENT reparse tag e.g.
    a mount point or Windows-native symlink, or any Win32 API error) —
    callers never need to distinguish "not applicable" from "failed",
    matching this module's own never-raises contract.
    """
    if not is_supported:
        return None
    try:
        return _read_lx_symlink_target_win32(path)
    except Exception:  # pragma: no cover - defensive: never let a raw
        # ctypes/Win32 call surface an exception into resolve.py's walk;
        # any failure here just means "couldn't recover this one", not a
        # reason to abort resolution.
        return None


def _read_lx_symlink_target_win32(path: Path) -> str | None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    invalid_handle = wintypes.HANDLE(-1).value

    handle = kernel32.CreateFileW(
        str(path),
        _GENERIC_READ,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == invalid_handle:
        return None
    try:
        buf = ctypes.create_string_buffer(_REPARSE_BUFFER_SIZE)
        bytes_returned = wintypes.DWORD(0)
        ok = kernel32.DeviceIoControl(
            handle,
            _FSCTL_GET_REPARSE_POINT,
            None,
            0,
            buf,
            len(buf),
            ctypes.byref(bytes_returned),
            None,
        )
        if not ok:
            return None
        raw = buf.raw[: bytes_returned.value]
        return _parse_lx_symlink_payload(raw)
    finally:
        kernel32.CloseHandle(handle)


def _parse_lx_symlink_payload(raw: bytes) -> str | None:
    """Parse a raw `DeviceIoControl(FSCTL_GET_REPARSE_POINT)` buffer,
    returning the target string only if it's tagged
    `IO_REPARSE_TAG_LX_SYMLINK` — confirmed byte layout against `fsutil
    reparsepoint query` on a real affected file: `tag(4) | data_len(2) |
    reserved(2) | version(4) | target(UTF-8, data_len - 4 bytes)`."""
    if len(raw) < _HEADER_SIZE:
        return None
    tag = int.from_bytes(raw[0:4], "little")
    if tag != _IO_REPARSE_TAG_LX_SYMLINK:
        return None
    data_len = int.from_bytes(raw[4:6], "little")
    payload = raw[_HEADER_SIZE : _HEADER_SIZE + data_len]
    if len(payload) <= _LX_SYMLINK_VERSION_SIZE:
        return None
    target_bytes = payload[_LX_SYMLINK_VERSION_SIZE:]
    try:
        return target_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None


__all__ = ["read_lx_symlink_target", "is_supported"]
