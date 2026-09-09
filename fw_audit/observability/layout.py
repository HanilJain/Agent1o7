"""Pure path algebra for the per-run LLM usage artifact.

Same discipline as every stage's own `layout.py` (e.g.
`stage3b_claims.layout`): every function here takes paths in, returns paths
out — no filesystem I/O, no `mkdir`. `observability.usage`'s `UsageRegistry`
creates directories at the point it actually writes into them.

Layout, under `<db_subfolder>/usage/`::

    <stage>.<run_id>.jsonl     one UsageRecord (JSON) per LLM call, appended
                                as it happens
    <stage>.<run_id>.json      the aggregate UsageReport, (re)written once
                                at the end of the run

Filenames are keyed by BOTH `stage` and `run_id` — deliberately, since
multiple stages (and multiple runs of the same stage) write into the same
shared `<db_subfolder>/usage/` directory; a single fixed `usage.json` name
would let a later stage's run silently clobber an earlier one's. This
mirrors `stage5_verification.layout`'s per-candidate/per-track file keying
for the same reason (its `<gid>.<track>.jsonl` command logs).
"""

from __future__ import annotations

import re
from pathlib import Path

_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def usage_dir(db_subfolder: Path) -> Path:
    return db_subfolder / "usage"


def _sanitize(part: str) -> str:
    """Replace anything that isn't filesystem-safe with `_` — `run_id`
    values are free-form strings (some are timestamps with `:`, e.g. a
    UTC isoformat fallback) and must not produce path separators or other
    filesystem-hostile characters."""
    return _SANITIZE_RE.sub("_", part) or "run"


def _stem(stage: str, run_id: str) -> str:
    return f"{_sanitize(stage)}.{_sanitize(run_id)}"


def usage_jsonl_path(usage_dir_: Path, *, stage: str, run_id: str) -> Path:
    """Append-only per-call log — one JSON object per line, written as
    each LLM call completes."""
    return usage_dir_ / f"{_stem(stage, run_id)}.jsonl"


def usage_report_path(usage_dir_: Path, *, stage: str, run_id: str) -> Path:
    """The aggregate `UsageReport`, (re)written once at the end of the
    run — analogous to every stage's own `*_summary.json`."""
    return usage_dir_ / f"{_stem(stage, run_id)}.json"


__all__ = ["usage_dir", "usage_jsonl_path", "usage_report_path"]
