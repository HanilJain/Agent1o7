"""Resolves Stage 3's findings into `VerificationCandidate`s Stage 5's
driver can loop over.

Mirrors `stage4_rag.sink_index.discover_sink_candidates` closely (same
`global_id`/`decision`-filter/skip-on-malformed shape), with one addition:
each candidate also carries the ABSOLUTE host path to its binary's
`normalized/joern/whole.c` — the Joern-target whole-program C file Stage 2
already produced (see `stage2_extraction.CLAUDE.md`) — resolved via
`stage2_summary.json`. Stage 5 needs this because the Joern tool (`tools.
joern_tool.build_cpg`) has to know exactly which file to parse; Stage 4's
`SinkCandidate` never needed a filesystem path at all.

Per your confirmed choice, this reads **Stage 3 findings only** — never
Stage 4's `stage4/taint/*.json`, even when present.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from fw_audit.common.findings import AnalysisReport, Decision, Finding
from fw_audit.common.schemas import ELFInfo, GhidraFunction, Stage2Summary
from fw_audit.stage5_verification.errors import Stage5InputError

logger = logging.getLogger("fw_audit.stage5_verification.candidate_index")

DEFAULT_DECISIONS: frozenset[Decision] = frozenset({Decision.ESCALATE})
"""Verification is expensive (a full CPG build plus a multi-turn agent
loop) — default to only the strongest Stage 3 candidates. `CONTEXT_REQUIRED`
findings are excluded by default: they name specific MISSING context
(callers/globals/macros/ABI facts, per `common.findings.Decision`'s
docstring), which a single binary's CPG often cannot supply either, so
spending a full verification run on them is usually premature. Overridable
via `discover_candidates(..., decisions=...)`."""


@dataclass(frozen=True)
class VerificationCandidate:
    """One Stage 3 finding selected for verification — by the existing
    Joern static track, the new QEMU+GDB dynamic track, or both (FVVW v3)."""

    global_id: str
    """`f"{chunk_id}::{finding.finding_id}"` — same format as
    `stage4_rag.sink_index.SinkCandidate.global_id`."""
    chunk_id: str
    bin_id: str
    finding: Finding
    source_path: Path | None
    """Absolute host path to the binary's `normalized/joern/whole.c`.
    `None` if `bin_id` couldn't be resolved against `stage2_summary.json`
    (binary removed/renamed since Stage 3 ran, or Stage 2 never produced a
    Joern artifact for it) — such candidates are still discovered but
    `driver.py` records them as `failed` rather than attempting a CPG build
    against a file that doesn't exist. UNCHANGED by the fields below — the
    existing static track keeps using ONLY this field, exactly as before."""

    # ---- FVVW v3 additions (Phase 1) — resolved for the DYNAMIC track and
    # `characterize_target`. All `None`/empty when unresolved; a candidate
    # missing these can still run the static track normally, it just can't
    # run the dynamic track (characterize_target reports "target mismatch"
    # / the dynamic track terminates not_run — see fvvw.dynamic_track). ----
    binary_path: Path | None = None
    """Absolute host path to the REAL target ELF —
    `Path(stage2_summary.rootfs_dir) / DecompiledBinary.rootfs_path` — what
    the dynamic track actually emulates. `None` if `bin_id` didn't resolve
    or `rootfs_dir` isn't a real directory."""
    rootfs_dir: Path | None = None
    """Absolute host path to the extracted firmware filesystem root
    (`stage2_summary.rootfs_dir`) — what `bringup_stabilize` chroots/binds
    into the dynamic-track session container. Shared by every candidate
    from the same firmware run, not just this one binary."""
    elf: ELFInfo | None = None
    """Arch/endianness/stripped/interpreter facts already computed by
    Stage 2 (`DecompiledBinary.elf`) — `characterize_target` seeds
    `mem.target` from this and only shells out for what it doesn't carry
    (PIE, offset validation). `None` if Stage 2 never resolved ELF facts
    for this binary (e.g. `readelf` failed at Stage 2 time)."""
    functions: tuple[GhidraFunction, ...] = ()
    """The function/offset table (`DecompiledBinary.functions`) —
    `characterize_target` looks up `finding.evidence_span.function_id`'s
    `entry_point` here to validate the claimed offset against the real
    binary. A tuple (not `list`) to keep this frozen dataclass genuinely
    immutable."""


def _chunk_id_from_findings_filename(path: Path) -> str:
    """Inverts `stage3_analysis.layout.finding_filename`'s `#` -> `__`
    substitution — same as `stage4_rag.sink_index._chunk_id_from_findings_filename`."""
    return path.stem.replace("__", "#")


def _bin_id_from_chunk_id(chunk_id: str) -> str:
    """`chunk_id` format is `<bin_id>#<ordinal:04d>` — the bin_id is
    everything before the last `#`. Same as
    `stage4_rag.sink_index._bin_id_from_chunk_id`."""
    bin_id, _, _ordinal = chunk_id.rpartition("#")
    return bin_id or chunk_id


def load_stage2_summary(stage2_dir: Path) -> Stage2Summary:
    path = stage2_dir / "stage2_summary.json"
    if not path.is_file():
        raise Stage5InputError(
            f"Stage 2 summary not found: {path}. Run `fw-extract <stage1_summary.json>` "
            "first — Stage 5 needs it to locate each binary's normalized Joern C."
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Stage5InputError(f"Could not read/parse {path}: {exc}") from exc
    try:
        return Stage2Summary.model_validate(raw)
    except ValidationError as exc:
        raise Stage5InputError(
            f"{path} does not match the Stage2Summary contract: {exc}."
        ) from exc


def resolve_source_path(
    bin_id: str, *, db_subfolder: Path, stage2_summary: Stage2Summary
) -> Path | None:
    for binary in stage2_summary.binaries:
        if binary.bin_id != bin_id:
            continue
        relpath = binary.artifacts.normalized_joern_c
        if not relpath:
            return None
        candidate = (db_subfolder / relpath).resolve()
        return candidate if candidate.is_file() else None
    return None


@dataclass(frozen=True)
class ResolvedBinaryTarget:
    """The dynamic-track resolution result — a plain return value rather
    than mutating `VerificationCandidate` in place (this whole dataclass
    tree stays immutable, per this project's coding-style convention).
    `discover_candidates` unpacks this into the matching
    `VerificationCandidate` fields."""

    binary_path: Path | None
    rootfs_dir: Path | None
    elf: ELFInfo | None
    functions: tuple[GhidraFunction, ...]


_EMPTY_BINARY_TARGET = ResolvedBinaryTarget(
    binary_path=None, rootfs_dir=None, elf=None, functions=()
)


def resolve_binary_target(
    bin_id: str, *, stage2_summary: Stage2Summary
) -> ResolvedBinaryTarget:
    """Resolve the REAL target ELF + rootfs + already-computed ELF/function
    facts for `bin_id`, for the dynamic (QEMU+GDB) track and
    `characterize_target` — the counterpart to `resolve_source_path`, which
    resolves the DECOMPILED C the static track needs instead.

    `stage2_summary.rootfs_dir` is Stage 1's originally-published absolute
    host path to the extracted firmware filesystem (see
    `common.schemas.Stage2Summary.rootfs_dir`'s docstring) — NOT relative to
    `db_subfolder` like `DecompiledBinary.artifacts.*` are, so it is used
    directly rather than joined onto `db_subfolder`. `binary.rootfs_path` IS
    relative to it (POSIX, per `DecompiledBinary.rootfs_path`'s docstring):
    the real ELF is `rootfs_dir / binary.rootfs_path`.

    Returns `_EMPTY_BINARY_TARGET` (all `None`/empty) if `bin_id` isn't
    found, `rootfs_dir` isn't set, or the resolved ELF path doesn't exist on
    disk — never raises; a candidate can still run the static track without
    this resolving (see `VerificationCandidate`'s field docstrings).
    """
    if not stage2_summary.rootfs_dir:
        return _EMPTY_BINARY_TARGET
    rootfs_dir = Path(stage2_summary.rootfs_dir)
    if not rootfs_dir.is_dir():
        return _EMPTY_BINARY_TARGET

    for binary in stage2_summary.binaries:
        if binary.bin_id != bin_id:
            continue
        binary_path = (rootfs_dir / binary.rootfs_path).resolve()
        if not binary_path.is_file():
            return ResolvedBinaryTarget(
                binary_path=None,
                rootfs_dir=rootfs_dir,
                elf=binary.elf,
                functions=tuple(binary.functions),
            )
        return ResolvedBinaryTarget(
            binary_path=binary_path,
            rootfs_dir=rootfs_dir,
            elf=binary.elf,
            functions=tuple(binary.functions),
        )
    return _EMPTY_BINARY_TARGET


def discover_candidates(
    db_subfolder: Path,
    *,
    decisions: frozenset[Decision] = DEFAULT_DECISIONS,
) -> list[VerificationCandidate]:
    """Globs `<db_subfolder>/stage3/findings/*.json`, loads each as an
    `AnalysisReport`, and flattens every `Finding` whose `decision` is in
    `decisions` into a `VerificationCandidate` — resolving `source_path`
    against `stage2_summary.json` along the way.

    Raises `Stage5InputError` if `stage2_summary.json` itself can't be
    loaded (needed for EVERY candidate's `source_path`) — fails fast,
    before any per-finding work, same as `stage4_rag.driver.run_queue`'s
    up-front `Stage4InputError` for a missing findings directory. A
    malformed/unreadable individual findings file is logged and skipped
    rather than aborting the whole scan, matching
    `sink_index.discover_sink_candidates`'s discipline.
    """
    stage3_dir = db_subfolder / "stage3"
    findings_dir = stage3_dir / "findings"
    if not findings_dir.is_dir():
        return []

    findings_paths = sorted(findings_dir.glob("*.json"))
    if not findings_paths:
        # Nothing to resolve a source path for — don't require
        # stage2_summary.json to exist just to return an empty list.
        return []

    stage2_summary = load_stage2_summary(db_subfolder / "stage2")

    candidates: list[VerificationCandidate] = []
    for path in findings_paths:
        try:
            report = AnalysisReport.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, ValueError) as exc:
            logger.warning("skipping unreadable findings file %s: %s", path, exc)
            continue

        chunk_id = report.chunk_id or _chunk_id_from_findings_filename(path)
        bin_id = _bin_id_from_chunk_id(chunk_id)
        source_path = resolve_source_path(
            bin_id, db_subfolder=db_subfolder, stage2_summary=stage2_summary
        )
        if source_path is None:
            logger.warning(
                "no normalized Joern C resolved for bin_id=%s (chunk_id=%s) — "
                "candidates from this chunk will fail verification",
                bin_id,
                chunk_id,
            )
        binary_target = resolve_binary_target(bin_id, stage2_summary=stage2_summary)
        if binary_target.binary_path is None:
            # Not a warning-level event on its own: the static track (the
            # only track that existed before FVVW v3) never needed this,
            # so plenty of legitimate runs will hit this path — logged at
            # debug, not warning, unlike the source_path miss above.
            logger.debug(
                "no real ELF resolved for bin_id=%s (chunk_id=%s) — dynamic track "
                "will report not_run for candidates from this chunk",
                bin_id,
                chunk_id,
            )

        for finding in report.findings:
            if finding.decision not in decisions:
                continue
            candidates.append(
                VerificationCandidate(
                    global_id=f"{chunk_id}::{finding.finding_id}",
                    chunk_id=chunk_id,
                    bin_id=bin_id,
                    finding=finding,
                    source_path=source_path,
                    binary_path=binary_target.binary_path,
                    rootfs_dir=binary_target.rootfs_dir,
                    elf=binary_target.elf,
                    functions=binary_target.functions,
                )
            )
    return candidates


__all__ = [
    "DEFAULT_DECISIONS",
    "ResolvedBinaryTarget",
    "VerificationCandidate",
    "discover_candidates",
    "load_stage2_summary",
    "resolve_binary_target",
    "resolve_source_path",
]
