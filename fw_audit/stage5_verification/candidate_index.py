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
from fw_audit.common.schemas import Stage2Summary
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
    """One Stage 3 finding selected for Joern verification."""

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
    against a file that doesn't exist."""


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
                )
            )
    return candidates


__all__ = [
    "DEFAULT_DECISIONS",
    "VerificationCandidate",
    "discover_candidates",
    "load_stage2_summary",
    "resolve_source_path",
]
