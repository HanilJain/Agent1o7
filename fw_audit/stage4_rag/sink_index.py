"""Stage 4 Component 0's finding resolver (C0-M2).

Resolves Stage 3's per-chunk findings into flat `SinkCandidate`s the local
driver (`driver.py`, C6) can loop over. Deliberately summary-free: Stage 3's
`stage3_summary.json`/`analysis_summary.json` are both best-effort writes
(`except OSError: pass`) and routinely absent — this module never depends on
either, only on `stage3/findings/*.json` itself, which is what Component 2's
consumer actually persists per acked chunk.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from fw_audit.common.findings import AnalysisReport, Decision, Finding

logger = logging.getLogger("fw_audit.stage4_rag.sink_index")

DEFAULT_DECISIONS: frozenset[Decision] = frozenset({Decision.ESCALATE, Decision.CONTEXT_REQUIRED})


@dataclass(frozen=True)
class SinkCandidate:
    """One Stage 3 finding selected for Stage 4 sink-to-source tracing."""

    global_id: str
    """`f"{chunk_id}::{finding.finding_id}"` — `Finding.finding_id` is
    unique only within its own chunk's report, so the chunk id must be
    part of any cross-chunk identifier."""
    chunk_id: str
    bin_id: str
    finding: Finding


def _chunk_id_from_findings_filename(path: Path) -> str:
    """Inverts `stage3_analysis.layout.finding_filename`'s `#` -> `__`
    substitution to recover the original `chunk_id`."""
    return path.stem.replace("__", "#")


def _bin_id_from_chunk_id(chunk_id: str) -> str:
    """`chunk_id` format is `<bin_id>#<ordinal:04d>` (see
    `stage3_analysis.chunk.strategy`) — the bin_id is everything before the
    last `#`."""
    bin_id, _, _ordinal = chunk_id.rpartition("#")
    return bin_id or chunk_id


def discover_sink_candidates(
    stage3_dir: Path,
    *,
    decisions: frozenset[Decision] = DEFAULT_DECISIONS,
) -> list[SinkCandidate]:
    """Globs `stage3_dir/findings/*.json`, loads each as an `AnalysisReport`,
    and flattens every `Finding` whose `decision` is in `decisions` into a
    `SinkCandidate`. A malformed/unreadable findings file is logged and
    skipped rather than aborting the whole scan — mirrors the rest of this
    pipeline's "per-item problems don't abort the run" discipline (see
    `stage3_analysis.ingest`'s `SkippedTarget` precedent).
    """
    findings_dir = stage3_dir / "findings"
    if not findings_dir.is_dir():
        return []

    candidates: list[SinkCandidate] = []
    for path in sorted(findings_dir.glob("*.json")):
        try:
            report = AnalysisReport.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, ValueError) as exc:
            logger.warning("skipping unreadable findings file %s: %s", path, exc)
            continue

        chunk_id = report.chunk_id or _chunk_id_from_findings_filename(path)
        bin_id = _bin_id_from_chunk_id(chunk_id)
        for finding in report.findings:
            if finding.decision not in decisions:
                continue
            candidates.append(
                SinkCandidate(
                    global_id=f"{chunk_id}::{finding.finding_id}",
                    chunk_id=chunk_id,
                    bin_id=bin_id,
                    finding=finding,
                )
            )
    return candidates


__all__ = ["DEFAULT_DECISIONS", "SinkCandidate", "discover_sink_candidates"]
