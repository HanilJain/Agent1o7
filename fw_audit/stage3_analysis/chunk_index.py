"""The editable chunk manifest (`stage3/chunk_index.json`) and the
`--chunks-file` input it feeds: select which already-persisted chunks
`--analyze` should analyze, without re-chunking.

Two halves of one contract, named after the `stage4_rag.sink_index` /
`stage5_verification.candidate_index` precedent (an id-carrying index a
later step reads back), but this module is an INPUT resolver rather than a
findings resolver: `write_chunk_index` is the OUTPUT side (called from both
chunking paths — `ingest._write_chunk_debug_sources`,
`chunk_queue.produce_chunks`), `load_chunk_selection`/`resolve_chunk_handles`
are the INPUT side (`runner.main`'s `--chunks-file` handling).

Chunk id normalization
--------------------------------------------------------------------------
A `chunk_id` is `<bin_id>#<ordinal:04d>` (`chunk.strategy.chunk_source`);
`layout.chunk_filename` swaps the `#` for `__` for its on-disk name. Since
`bin_id` itself routinely CONTAINS `__` (Stage 2's disambiguation suffix,
e.g. "sbin_hostapd__5d85c80abc0a"), inverting a filename back to a chunk_id
must use `rpartition("__")` — splitting on the LAST occurrence — never a
blind `str.replace("__", "#")`, which would corrupt
"sbin_hostapd__5d85c80abc0a__0021" into "sbin_hostapd#5d85c80abc0a#0021"
(two "#"s, the wrong one where `bin_id`'s own "__" was). This is exactly
the bug `stage4_rag.sink_index`/`stage5_verification.candidate_index` carry
as a latent fallback — see their `_chunk_id_from_findings_filename` — not
repeated here.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from fw_audit.stage3_analysis import layout
from fw_audit.stage3_analysis.errors import Stage3InputError
from fw_audit.stage3_analysis.models import ChunkHandle, IngestionReport

logger = logging.getLogger("fw_audit.stage3_analysis")


@dataclass(frozen=True)
class ChunkSelection:
    """One entry from a `--chunks-file` — a normalized `chunk_id` plus
    whatever metadata the source file happened to carry alongside it (all
    optional: a bare id list carries none of it). `resolve_chunk_handles`
    uses these as a fallback when `IngestionReport.targets` has no matching
    `bin_id` (e.g. the selection file outlived a re-run under `--only`)."""

    chunk_id: str
    rootfs_path: str | None = None
    source_relpath: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    oversized: bool | None = None


def write_chunk_index(stage3_dir_: Path, entries: Sequence[Mapping[str, object]]) -> None:
    """Best-effort write of `layout.chunk_index_path(stage3_dir_)`.

    `entries` must be metadata-only dicts — callers pass `Chunk.
    to_json_dict()` output, never a `Chunk` itself: that method deliberately
    excludes `functions` (and every function's full text), and accumulating
    live `Chunk` objects across a whole producer run would reintroduce the
    exact in-memory cost `chunk_queue.py`'s module docstring says this
    pipeline avoids by treating disk as the queue's source of truth.

    A no-op when `entries` is empty — NOT a write of `[]`. Without this
    guard, a run that chunks zero targets (e.g. `--only bin/nonexistent
    --queue`) would silently clobber a good, previously written manifest
    from an earlier full run. Matches `ingest._write_report`'s "recoverable,
    not fatal" discipline: logs a warning on `OSError` rather than raising,
    since the caller (a producer already mid-flight) must not be aborted by
    a manifest write failing.
    """
    if not entries:
        return
    try:
        stage3_dir_.mkdir(parents=True, exist_ok=True)
        layout.chunk_index_path(stage3_dir_).write_text(
            json.dumps({"chunks": list(entries)}, indent=2), encoding="utf-8"
        )
    except OSError as exc:
        logger.warning("chunk index write failed for %s: %s", stage3_dir_, exc)


def _normalize_chunk_id(raw: str) -> str:
    """`"sbin_hostapd__5d85c80abc0a#0021"` (already a chunk_id, kept as-is),
    `"sbin_hostapd__5d85c80abc0a__0021"` or `"...__0021.c"` (on-disk
    filename form, inverted via `rpartition` — see this module's docstring)
    all normalize to the same id. `.c`/`.json` suffixes are stripped first
    so either a `chunks/*.c` or `findings/*.json` style name works.

    Rejects anything that looks like a path (`/`, `\\`, or `..`) — a
    `--chunks-file` is user-authored, untrusted input that ultimately
    builds a filesystem path in `resolve_chunk_handles`, same discipline
    `discover.locate_source`'s traversal guard applies to Stage 1's LLM
    output.
    """
    stem = raw.strip()
    for suffix in (".c", ".json"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break

    if "/" in stem or "\\" in stem or ".." in stem:
        raise Stage3InputError(
            f"invalid chunk id {raw!r}: must not contain a path separator or '..'"
        )

    if "#" in stem:
        return stem

    bin_part, sep, ordinal = stem.rpartition("__")
    if not sep:
        raise Stage3InputError(
            f"invalid chunk id {raw!r}: expected '<bin_id>#<ordinal>' or the on-disk "
            "'<bin_id>__<ordinal>' filename form"
        )
    return f"{bin_part}#{ordinal}"


def _selection_from_entry(entry: str | Mapping[str, object]) -> ChunkSelection:
    if isinstance(entry, str):
        return ChunkSelection(chunk_id=_normalize_chunk_id(entry))

    raw_id = entry.get("chunk_id")
    if not isinstance(raw_id, str) or not raw_id:
        raise Stage3InputError(f"chunk entry missing a string 'chunk_id': {entry!r}")

    def _opt_str(key: str) -> str | None:
        value = entry.get(key)
        return value if isinstance(value, str) else None

    def _opt_int(key: str) -> int | None:
        value = entry.get(key)
        return value if isinstance(value, int) else None

    def _opt_bool(key: str) -> bool | None:
        value = entry.get(key)
        return value if isinstance(value, bool) else None

    return ChunkSelection(
        chunk_id=_normalize_chunk_id(raw_id),
        rootfs_path=_opt_str("rootfs_path"),
        source_relpath=_opt_str("source_relpath"),
        start_line=_opt_int("start_line"),
        end_line=_opt_int("end_line"),
        oversized=_opt_bool("oversized"),
    )


def load_chunk_selection(path: Path) -> tuple[ChunkSelection, ...]:
    """Parse and validate a `--chunks-file`.

    Raises `Stage3InputError` with an actionable message for anything that
    prevents forming a selection — missing file, malformed JSON, wrong
    shape, or a file naming zero chunks. Mirrors `stage2_io.
    load_stage2_summary`'s three-message structure exactly, plus a fourth
    check this contract needs that that one doesn't (non-empty).

    Accepts either shape, so an unedited `chunk_index.json` or
    `stage3_summary.json` works verbatim:
    - a bare JSON array of chunk id strings, or
    - `{"chunks": [...]}` where each entry is either a chunk id string or an
      object carrying at least `chunk_id` (both `chunk_index.json`'s own
      entries and `Stage3Summary`'s `ChunkRecord` entries qualify).

    Duplicate ids (after normalization) are dropped, keeping the first
    occurrence's metadata — a user may list the same chunk twice across
    edits without it costing two LLM calls.
    """
    if not path.is_file():
        raise Stage3InputError(
            f"chunks file not found: {path}. Produce one with `fw-analyze "
            "<stage1_summary.json> --debug-chunks` or `--queue` (writes "
            "stage3/chunk_index.json), copy it, delete the rows you don't want, "
            "and pass the copy here."
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Stage3InputError(f"Could not read/parse {path}: {exc}") from exc

    if isinstance(raw, list):
        raw_entries: list[object] = raw
    elif isinstance(raw, dict) and isinstance(raw.get("chunks"), list):
        raw_entries = raw["chunks"]
    else:
        raise Stage3InputError(
            f"{path} does not match the accepted --chunks-file shapes: a bare JSON "
            "array of chunk ids, or an object with a 'chunks' array (chunk_index.json's "
            "and stage3_summary.json's own shape)."
        )

    selections: list[ChunkSelection] = []
    seen: set[str] = set()
    for entry in raw_entries:
        if not isinstance(entry, (str, dict)):
            raise Stage3InputError(f"chunk entry has an unsupported type: {entry!r}")
        selection = _selection_from_entry(entry)
        if selection.chunk_id in seen:
            continue
        seen.add(selection.chunk_id)
        selections.append(selection)

    if not selections:
        raise Stage3InputError(f"{path} names no chunks — nothing to analyze.")

    return tuple(selections)


def _bin_id_from_chunk_id(chunk_id: str) -> str:
    """`chunk_id` format is `<bin_id>#<ordinal:04d>` — the bin_id is
    everything before the LAST `#` (a chunk_id itself never contains `#`
    elsewhere, but `rpartition` costs nothing and stays consistent with
    this module's other id-splitting)."""
    bin_id, _, _ordinal = chunk_id.rpartition("#")
    return bin_id or chunk_id


def resolve_chunk_handles(
    selections: Sequence[ChunkSelection], *, report: IngestionReport
) -> tuple[list[ChunkHandle], list[str]]:
    """Build `ChunkHandle`s for a `--chunks-file` selection, pointing at
    chunk payloads already persisted under `stage3/chunks/` — no chunking,
    no Stage 2 cleaned-artifact read.

    `rootfs_path`/`source_relpath` precedence: the matching `Target` in
    `report.targets` (authoritative, current) → the selection's own field
    (present when `--chunks-file` was an unedited `chunk_index.json`/
    `stage3_summary.json`) → `bin_id` itself, with a warning (both fields
    are non-essential to the analyst prompt's correctness, just its
    context, so this never blocks the run).

    Every missing or unreadable chunk file is collected and raised together
    as ONE `Stage3InputError` — not one-at-a-time — so a typo in a long
    selection list fails loudly, before any LLM call, listing every
    problem at once rather than the first.

    Returns `(handles, warnings)`; `handles` preserves `selections`' order.
    """
    targets_by_bin_id = {t.bin_id: t for t in report.targets}
    chunks_dir = layout.chunks_dir(layout.stage3_dir(report.db_subfolder))
    chunks_dir_resolved = chunks_dir.resolve()

    handles: list[ChunkHandle] = []
    warnings: list[str] = []
    problems: list[str] = []

    for selection in selections:
        chunk_path = chunks_dir / layout.chunk_filename(selection.chunk_id)
        resolved = chunk_path.resolve()
        if not (resolved == chunks_dir_resolved or resolved.is_relative_to(chunks_dir_resolved)):
            problems.append(f"{selection.chunk_id}: resolves outside {chunks_dir}")
            continue
        if not chunk_path.is_file():
            problems.append(f"{selection.chunk_id}: no chunk file at {chunk_path}")
            continue

        try:
            text = chunk_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            problems.append(f"{selection.chunk_id}: could not read {chunk_path}: {exc}")
            continue

        bin_id = _bin_id_from_chunk_id(selection.chunk_id)
        target = targets_by_bin_id.get(bin_id)
        if target is not None:
            rootfs_path = target.rootfs_path
            source_relpath = target.source_relpath
        elif selection.rootfs_path or selection.source_relpath:
            rootfs_path = selection.rootfs_path or bin_id
            source_relpath = selection.source_relpath or bin_id
        else:
            warnings.append(
                f"chunk {selection.chunk_id}: no matching target for bin_id {bin_id!r} "
                "in this run's ingestion report and the selection carried no "
                "rootfs_path/source_relpath — falling back to bin_id for both."
            )
            rootfs_path = bin_id
            source_relpath = bin_id

        handles.append(
            ChunkHandle(
                chunk_id=selection.chunk_id,
                bin_id=bin_id,
                rootfs_path=rootfs_path,
                source_relpath=source_relpath,
                chunk_path=chunk_path,
                start_line=selection.start_line or 0,
                end_line=selection.end_line or 0,
                approx_tokens=len(text) // 4,
                oversized=bool(selection.oversized),
            )
        )

    if problems:
        raise Stage3InputError(
            "could not resolve every selected chunk (fix or remove these entries from "
            "the --chunks-file, then re-run):\n" + "\n".join(f"  - {p}" for p in problems)
        )

    return handles, warnings


__all__ = [
    "ChunkSelection",
    "write_chunk_index",
    "load_chunk_selection",
    "resolve_chunk_handles",
]
