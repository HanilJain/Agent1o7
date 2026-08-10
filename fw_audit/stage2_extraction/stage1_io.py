"""Load and validate Stage 1's hand-off (`stage1_summary.json`), and resolve
the rootfs root directory that every `IdentifiedBinary.path` is relative to.

Stage 1 does not reliably publish the rootfs root in one unambiguous place
across every summary version — see `Stage1Summary.rootfs_dir`'s docstring —
so this module's whole job is making that gap disappear behind a single,
well-tested resolution order, instead of every later Stage 2 module
reimplementing its own fallback.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from fw_audit.common.schemas import Stage1Summary


class Stage2InputError(RuntimeError):
    """Stage 1's hand-off could not be loaded, or its rootfs root could not
    be determined by any of `stage1_io`'s resolution strategies.

    This is Stage 2's only hard-failure exception — everything past this
    point (binary resolution, decompilation, normalization) is per-binary
    isolated and reported through `Stage2Summary`, never raised.
    """


@dataclass(frozen=True)
class RootfsResolution:
    """Result of `resolve_rootfs_dir`: the resolved directory, plus any
    warnings about *how* it was resolved (e.g. a fallback was needed)."""

    rootfs_dir: Path
    warnings: tuple[str, ...] = ()


def load_stage1_summary(path: Path) -> Stage1Summary:
    """Parse and validate `stage1_summary.json`.

    Raises `Stage2InputError` with an actionable message for anything that
    prevents forming a `Stage1Summary` — missing file, malformed JSON, or a
    document that doesn't match the contract.
    """
    if not path.is_file():
        raise Stage2InputError(
            f"Stage 1 summary not found: {path}. Run `fw-ingest <firmware>` "
            "first — it writes stage1_summary.json next to tree.txt."
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Stage2InputError(f"Could not read/parse {path}: {exc}") from exc

    try:
        return Stage1Summary.model_validate(raw)
    except Exception as exc:  # pydantic.ValidationError — kept broad and re-raised
        raise Stage2InputError(
            f"{path} does not match the Stage1Summary contract: {exc}. "
            "Was it written by an incompatible fw-audit version?"
        ) from exc


def resolve_rootfs_dir(summary: Stage1Summary) -> RootfsResolution:
    """Determine the rootfs root every `IdentifiedBinary.path` is relative
    to, trying each of Stage 1's possible publication points in order.

    Resolution order:
    1. `summary.rootfs_dir`, if present and an existing directory.
    2. Line 1 of `summary.tree_txt_path` (`write_tree_txt` always writes the
       rootfs's `str(root)` as the file's first line) — covers a summary
       written before Stage 1 started publishing `rootfs_dir` directly.
    3. `<db_subfolder>/tree.txt`, in case `tree_txt_path` itself is stale —
       e.g. the Database was copied from another machine, and it records a
       host-absolute, platform-native path that no longer resolves there.
    4. Hard-fail (`Stage2InputError`), naming every location checked and the
       exact command to fix it.
    """
    db_subfolder = Path(summary.db_subfolder)

    if summary.rootfs_dir:
        candidate = Path(summary.rootfs_dir)
        if candidate.is_dir():
            return RootfsResolution(rootfs_dir=candidate)

    tree_candidates: list[Path] = []
    if summary.tree_txt_path:
        tree_candidates.append(Path(summary.tree_txt_path))
    tree_candidates.append(db_subfolder / "tree.txt")

    for tree_path in tree_candidates:
        if not tree_path.is_file():
            continue
        first_line = _read_first_line(tree_path)
        if first_line is None:
            continue
        candidate = Path(first_line)
        if candidate.is_dir():
            return RootfsResolution(
                rootfs_dir=candidate,
                warnings=(
                    f"stage1_summary.json has no rootfs_dir; recovered it from "
                    f"the first line of {tree_path}. Re-run `fw-ingest` on this "
                    "firmware to regenerate a summary with rootfs_dir published.",
                ),
            )

    checked = ", ".join(str(p) for p in tree_candidates)
    raise Stage2InputError(
        f"Could not determine the rootfs root for {db_subfolder}. Checked "
        f"summary.rootfs_dir={summary.rootfs_dir!r} and the first line of: "
        f"{checked}. Re-run `fw-ingest <firmware> --db-subfolder "
        f"{db_subfolder.name}` to regenerate a usable summary."
    )


def _read_first_line(path: Path) -> str | None:
    try:
        with path.open("r", encoding="utf-8") as f:
            line = f.readline()
    except OSError:
        return None
    line = line.rstrip("\r\n")
    return line or None
