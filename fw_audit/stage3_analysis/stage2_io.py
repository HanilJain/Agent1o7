"""Load and validate Stage 2's hand-off (`stage2_summary.json`), and resolve
the decompiled mirror tree directory every `DecompiledBinary.artifacts.
decompiled_tree_c` is relative to.

Mirrors `stage2_extraction.stage1_io` one stage over: that module's whole
job is making Stage 1's "where's the rootfs root" ambiguity disappear
behind one well-tested resolution order; this module does the same for
Stage 2's "where's the decompiled mirror tree" ambiguity, which exists for
an analogous reason — `Stage2Summary.decompiled_tree_dir` defaults to `""`
for summaries written before that field existed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from fw_audit.common.schemas import Stage1Summary, Stage2Summary
from fw_audit.stage2_extraction import layout as stage2_layout
from fw_audit.stage2_extraction.stage1_io import load_stage1_summary
from fw_audit.stage3_analysis.errors import Stage3InputError


def resolve_stage2_summary_path(stage1_summary_path: Path) -> Path:
    """Given Stage 1's hand-off, locate the Stage 2 hand-off it fed.

    Reuses Stage 2's own `load_stage1_summary` (rather than re-parsing
    `stage1_summary.json` a second, independent way), so Stage 1's contract
    validation — including its `status` repr normalization — is not
    duplicated here.
    """
    stage1 = load_stage1_summary(stage1_summary_path)
    return _stage2_summary_path_for(stage1)


def _stage2_summary_path_for(stage1: Stage1Summary) -> Path:
    db_subfolder = Path(stage1.db_subfolder)
    return stage2_layout.stage2_summary_path(db_subfolder / "stage2")


def load_stage2_summary(path: Path) -> Stage2Summary:
    """Parse and validate `stage2_summary.json`.

    Raises `Stage3InputError` with an actionable message for anything that
    prevents forming a `Stage2Summary` — missing file, malformed JSON, or a
    document that doesn't match the contract. Mirrors
    `stage1_io.load_stage1_summary`'s three-message structure exactly.
    """
    if not path.is_file():
        raise Stage3InputError(
            f"Stage 2 summary not found: {path}. Run `fw-extract <stage1_summary.json>` "
            "first — it writes stage2_summary.json under <db_subfolder>/stage2/."
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Stage3InputError(f"Could not read/parse {path}: {exc}") from exc

    try:
        return Stage2Summary.model_validate(raw)
    except Exception as exc:  # pydantic.ValidationError — kept broad and re-raised
        raise Stage3InputError(
            f"{path} does not match the Stage2Summary contract: {exc}. "
            "Was it written by an incompatible fw-audit version?"
        ) from exc


@dataclass(frozen=True)
class TreeResolution:
    """Result of `resolve_decompiled_tree_dir`: the resolved directory, plus
    any warnings about *how* it was resolved (e.g. a fallback was needed)."""

    tree_dir: Path
    warnings: tuple[str, ...] = ()


def resolve_decompiled_tree_dir(summary: Stage2Summary) -> TreeResolution:
    """Determine the decompiled-C mirror tree directory every
    `DecompiledBinary.artifacts.decompiled_tree_c` is relative to.

    Resolution order:
    1. `Path(summary.db_subfolder).parent / summary.decompiled_tree_dir`, if
       the field is non-empty and the directory exists — the authoritative,
       recorded location.
    2. `stage2_layout.decompiled_tree_dir(Path(summary.db_subfolder))` —
       recompute the sibling name from `db_subfolder` itself. Needed for a
       summary written before `decompiled_tree_dir` existed (field defaults
       to `""`; see `Stage2Summary`'s docstring in `common.schemas`). Emits
       a warning naming the cause and the fix.
    3. Hard-fail `Stage3InputError`, naming every location checked and the
       exact command to fix it.
    """
    db_subfolder = Path(summary.db_subfolder)

    if summary.decompiled_tree_dir:
        candidate = db_subfolder.parent / summary.decompiled_tree_dir
        if candidate.is_dir():
            return TreeResolution(tree_dir=candidate)

    recomputed = stage2_layout.decompiled_tree_dir(db_subfolder)
    if recomputed.is_dir():
        return TreeResolution(
            tree_dir=recomputed,
            warnings=(
                "stage2_summary.json has no usable decompiled_tree_dir; recovered it "
                f"by recomputing the sibling directory name as {recomputed}. Re-run "
                "`fw-extract` on this firmware to regenerate a summary with "
                "decompiled_tree_dir published.",
            ),
        )

    recorded = (
        db_subfolder.parent / summary.decompiled_tree_dir if summary.decompiled_tree_dir else None
    )
    checked = ", ".join(str(p) for p in (recorded, recomputed) if p is not None)
    raise Stage3InputError(
        f"Could not locate the decompiled mirror tree for {db_subfolder}. Checked: "
        f"{checked}. Re-run `fw-extract <stage1_summary.json>` on this firmware to "
        "regenerate the mirror tree, or confirm it hasn't been moved/deleted."
    )
