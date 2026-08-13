"""Load Stage 2's persisted cleaned artifact (`cleaned/whole.c` +
`cleaned/functions.json`) into an `ExtractedSource`, replacing Stage 3's
former in-memory `clean.extract.extract_functions()` call.

Stage 3 no longer runs tree-sitter at all: Stage 2 already did (see
`stage2_extraction.clean` / `stage2_extraction.extract._clean_whole_c`)
and persisted the result. This module only reads two files and slices
text — no parsing, no `tree-sitter` import, so it works whether or not the
`stage2` extra is installed anywhere Stage 3 runs standalone.
"""

from __future__ import annotations

import json
from pathlib import Path

from fw_audit.common.schemas import DecompiledBinary, ExtractedSource
from fw_audit.stage2_extraction import layout as stage2_layout
from fw_audit.stage2_extraction.clean.index import source_from_index_and_text


def resolve_cleaned_paths(binary: DecompiledBinary, db_subfolder: Path) -> tuple[Path, Path] | None:
    """Resolve `binary`'s `cleaned/whole.c` + `cleaned/functions.json`
    paths, or `None` if this binary has no recorded cleaned artifact
    (cleaning was skipped in Stage 2 — e.g. `tree-sitter`/`tree-sitter-c`
    weren't installed there; see `DecompiledBinary.warnings`).

    Both `artifacts.cleaned_c`/`cleaned_index_json` are relative to
    `db_subfolder`, same convention as every other `DecompilationArtifacts`
    field except `decompiled_tree_c` — see that class's docstring.
    """
    if not binary.artifacts.cleaned_c or not binary.artifacts.cleaned_index_json:
        return None
    whole_c = db_subfolder / binary.artifacts.cleaned_c
    index_json = db_subfolder / binary.artifacts.cleaned_index_json
    if not stage2_layout.is_contained(
        whole_c, db_subfolder
    ) or not stage2_layout.is_contained(index_json, db_subfolder):
        return None
    return whole_c, index_json


def load_cleaned_source(whole_c: Path, index_json: Path) -> ExtractedSource:
    """Read `whole_c` + `index_json` and reconstruct the `ExtractedSource`
    Stage 2 wrote — the exact input `chunk.strategy.chunk_source` needs.

    Raises `OSError`/`json.JSONDecodeError` on a read/parse failure;
    callers (`ingest.py`, `chunk_queue.py`) catch these per-target, same
    discipline as every other per-binary Stage 3 problem — never a hard
    failure of the whole run.
    """
    whole_c_text = whole_c.read_text(encoding="utf-8", errors="replace")
    index = json.loads(index_json.read_text(encoding="utf-8"))
    return source_from_index_and_text(index, whole_c_text)


__all__ = ["resolve_cleaned_paths", "load_cleaned_source"]
