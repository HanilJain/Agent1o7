"""Pure path algebra for Stage 2's on-disk output tree.

Every function here takes paths in, returns paths out — no filesystem I/O,
no `mkdir`. This is the single source of truth for where every Stage 2
artifact lives, so `ghidra/command.py`, `ghidra/client.py`, `normalize/*`,
and `extract.py` never hand-roll a path string independently and drift out
of sync with each other. Callers are responsible for creating directories
at the point they actually write into them.

Layout, under `<db_subfolder>/stage2/`::

    stage2_summary.json
    resolution_report.json
    binaries/<bin_id>/
      binary_info.json
      ghidra/{headless_stdout.txt, ghidra.log, ghidra_script.log}
      raw/metadata.json
      raw/decompiled/{whole.c, whole.h}
      normalized/joern/whole.c
      normalized/normalization_report.json

Additionally, as a SIBLING of `<db_subfolder>` (an alternate flat view of
the normalized Joern C, keyed by rootfs path rather than bin_id, with `.c`
APPENDED to the original filename rather than replacing its extension)::

    <db_subfolder>_decompiled/
      bin/busybox.c                 <- rootfs bin/busybox
      lib/libbcm_boardctl.so.c      <- rootfs lib/libbcm_boardctl.so
      lib/modules/wifi.ko.c         <- rootfs lib/modules/wifi.ko
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.]+")


def bin_id(rootfs_rel: str, sha256: str) -> str:
    """`<rootfs-rel with '/' -> '_'>__<sha256[:12]>`.

    The sha256 prefix makes same-basename binaries in different rootfs
    directories collision-proof, and makes an unchanged re-run's cache hit
    (same bytes -> same bin_id) detectable without re-hashing everything.
    """
    safe_rel = _SAFE_NAME_RE.sub("_", rootfs_rel.strip("/")).strip("_")
    return f"{safe_rel}__{sha256[:12]}"


def stage2_summary_path(stage2_dir: Path) -> Path:
    return stage2_dir / "stage2_summary.json"


def resolution_report_path(stage2_dir: Path) -> Path:
    return stage2_dir / "resolution_report.json"


def binaries_dir(stage2_dir: Path) -> Path:
    return stage2_dir / "binaries"


def binary_dir(stage2_dir: Path, binary_id: str) -> Path:
    return binaries_dir(stage2_dir) / binary_id


def binary_info_path(bin_dir: Path) -> Path:
    return bin_dir / "binary_info.json"


def ghidra_log_dir(bin_dir: Path) -> Path:
    return bin_dir / "ghidra"


def headless_stdout_path(bin_dir: Path) -> Path:
    return ghidra_log_dir(bin_dir) / "headless_stdout.txt"


def ghidra_log_path(bin_dir: Path) -> Path:
    return ghidra_log_dir(bin_dir) / "ghidra.log"


def ghidra_scriptlog_path(bin_dir: Path) -> Path:
    return ghidra_log_dir(bin_dir) / "ghidra_script.log"


def raw_dir(bin_dir: Path) -> Path:
    return bin_dir / "raw"


def raw_metadata_path(bin_dir: Path) -> Path:
    return raw_dir(bin_dir) / "metadata.json"


def raw_decompiled_dir(bin_dir: Path) -> Path:
    return raw_dir(bin_dir) / "decompiled"


def raw_decompiled_whole_c(bin_dir: Path) -> Path:
    return raw_decompiled_dir(bin_dir) / "whole.c"


def raw_decompiled_whole_h(bin_dir: Path) -> Path:
    return raw_decompiled_dir(bin_dir) / "whole.h"


def normalized_dir(bin_dir: Path) -> Path:
    return bin_dir / "normalized"


def normalized_joern_dir(bin_dir: Path) -> Path:
    return normalized_dir(bin_dir) / "joern"


def normalized_joern_whole_c(bin_dir: Path) -> Path:
    return normalized_joern_dir(bin_dir) / "whole.c"


def normalization_report_path(bin_dir: Path) -> Path:
    return normalized_dir(bin_dir) / "normalization_report.json"


def relative_to_db_subfolder(path: Path, db_subfolder: Path) -> str:
    """POSIX-style path relative to `db_subfolder`, for `Stage2Summary`
    fields — kept relative (unlike Stage 1's absolute paths) so the
    Database directory stays relocatable."""
    return path.resolve().relative_to(db_subfolder.resolve()).as_posix()


# --------------------------------------------------------------------- #
# The flat decompiled-C mirror tree — a SIBLING of db_subfolder, NOT under
# stage2_dir. It is an alternate view of `normalized/joern/whole.c`, keyed
# by the binary's rootfs path instead of by bin_id, so a consumer can find
# "the C for bin/busybox" without reading stage2_summary.json first.
# --------------------------------------------------------------------- #

DECOMPILED_TREE_SUFFIX = "_decompiled"


def decompiled_tree_dir(db_subfolder: Path) -> Path:
    """`<db_subfolder>/../<db_subfolder.name>_decompiled/`.

    Resolved, because `db_subfolder` as recorded by Stage 1 is CWD-relative
    (see `Settings.data_dir`'s default) and a sibling of a relative path is
    only well-defined once anchored.
    """
    resolved = db_subfolder.resolve()
    return resolved.parent / f"{resolved.name}{DECOMPILED_TREE_SUFFIX}"


def decompiled_tree_file(tree_dir: Path, rootfs_rel: str) -> Path:
    """Mirror `rootfs_rel` under `tree_dir` with `.c` APPENDED to the
    filename (`lib/x.so` -> `lib/x.so.c`), never replacing the extension.

    Splits on `/` only (via `PurePosixPath`), so a leading `/` is stripped
    (matching the "rootfs-relative" convention elsewhere in Stage 2) rather
    than being treated as an escape — `is_contained` below is what actually
    guards against traversal.
    """
    rel = PurePosixPath(rootfs_rel.strip("/"))
    return tree_dir.joinpath(*rel.parts[:-1], f"{rel.name}.c")


def is_contained(child: Path, parent: Path) -> bool:
    """True if `child` resolves to a path inside `parent`.

    Defense in depth before writing to a path built from `rootfs_path` —
    which `stage2_extraction.resolve` already validates as contained
    *within `rootfs_dir`*, a guarantee that doesn't automatically transfer
    to a path joined onto this DIFFERENT base (the mirror tree). Uses
    `.resolve()` (follows symlinks), which is correct here since `parent`
    is our own freshly-created output tree, not untrusted firmware content
    (contrast with `stage2_extraction.resolve`, where following a symlink
    onto the host would be exactly the violation being guarded against).
    """
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True
