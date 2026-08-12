"""Locate a matched binary's source file in the decompiled mirror tree, and
scan that tree for files no whitelist entry claims.

The only filesystem-touching module in Component 1's Step 1 besides
`stage2_io`/`ingest` themselves — `whitelist.py` stays pure so it's
unit-testable with no fixtures on disk.
"""

from __future__ import annotations

from pathlib import Path

from fw_audit.common.schemas import DecompiledBinary
from fw_audit.stage2_extraction import layout as stage2_layout

#: `.h` is included for forward-compatibility: Stage 2 does not currently
#: mirror any header (`artifacts.raw_header` is always `None` today, and
#: `whole.h` is never written despite being named in `stage2_extraction.
#: layout`'s module docstring) — this costs nothing now and avoids a
#: follow-up change if that changes later.
SOURCE_SUFFIXES: frozenset[str] = frozenset({".c", ".h"})


def locate_source(binary: DecompiledBinary, tree_dir: Path) -> Path | None:
    """Find `binary`'s file inside `tree_dir`, or `None` if it can't be
    found safely.

    Resolution order:
    1. `tree_dir / binary.artifacts.decompiled_tree_c` — authoritative when
       present. Note the documented relativity exception this field has:
       it's relative to the TREE dir, not `db_subfolder`
       (`DecompilationArtifacts.decompiled_tree_c`'s docstring).
    2. `stage2_layout.decompiled_tree_file(tree_dir, binary.rootfs_path)` —
       recompute the expected mirror path, covering a run where
       `decompiled_tree_c` was never recorded (e.g. the mirror write step
       failed non-fatally; see `extract.py::_write_mirror`).

    Both candidates are checked with `stage2_layout.is_contained` before
    any `stat()` — `decompiled_tree_c` ultimately derives from an untrusted
    Stage 1 LLM path threaded through `rootfs_path`, so the traversal guard
    is mandatory here, not decorative.
    """
    candidates: list[Path] = []
    if binary.artifacts.decompiled_tree_c:
        candidates.append(tree_dir / binary.artifacts.decompiled_tree_c)
    candidates.append(stage2_layout.decompiled_tree_file(tree_dir, binary.rootfs_path))

    for candidate in candidates:
        if not stage2_layout.is_contained(candidate, tree_dir):
            continue
        if candidate.is_file():
            return candidate
    return None


def scan_tree(tree_dir: Path) -> tuple[Path, ...]:
    """Every `.c`/`.h` file under `tree_dir`, for orphan accounting —
    independent of `stage2_summary.json`, so a mismatch between what's on
    disk and what the summary claims is still visible in the report."""
    if not tree_dir.is_dir():
        return ()
    found = [
        p for p in tree_dir.rglob("*") if p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES
    ]
    return tuple(sorted(found))
