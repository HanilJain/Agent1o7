"""Stage 3's internal data shapes for Component 1 (ingest & whitelist).

Frozen dataclasses, not Pydantic — per the project's immutability
convention, and because these are internal to Stage 3, not a cross-stage
wire contract like `common.schemas`. If a future step needs to publish a
`Stage3Summary` alongside `stage2_summary.json`, that belongs in
`fw_audit.common.schemas` next to `Stage2Summary`, not here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from fw_audit.common.schemas import DecompilationStatus, GhidraFunction


@dataclass(frozen=True)
class Target:
    """One binary Stage 3 will analyze: whitelisted by Stage 1, resolved and
    decompiled by Stage 2, and located on disk in the decompiled mirror
    tree by `discover.locate_source`."""

    bin_id: str
    """Stage 2's identity for this binary, e.g. "sbin_wpasupp__b86e5cadc3c9"."""
    rootfs_path: str
    """POSIX, relative to the firmware's rootfs root — Stage 2-verified."""
    requested_path: str
    """Verbatim path as Stage 1's Identifier Agent wrote it (untrusted LLM
    output) — kept for traceability even though `rootfs_path` is what
    actually pinned down the bytes."""
    aliases: tuple[str, ...]
    """Other requested paths that deduped onto this same binary by content
    hash (e.g. busybox applets)."""
    sha256: str
    source_path: Path
    """Absolute host path to the decompiled-C mirror file."""
    source_relpath: str
    """POSIX path relative to the decompiled tree directory."""
    size_bytes: int
    status: DecompilationStatus
    function_count: int
    functions: tuple[GhidraFunction, ...] = ()
    """The matched `DecompiledBinary.functions` list, carried through so
    `clean.extract.extract_functions` can build a `BinaryContext` (see
    `stage2_extraction.normalize.context.build_context`) without re-reading
    `stage2_summary.json` — zero extra I/O, since `ingest.py` already has
    this in memory at `Target` construction time. Deliberately NOT included
    in `IngestionReport.to_json_dict()`'s per-target serialization: it would
    add ~2,000 `GhidraFunction` dicts to the report for no reader benefit."""


@dataclass(frozen=True)
class SkippedTarget:
    """One whitelisted entry that did NOT become a `Target`, and why.

    `reason` is a machine-ish code (see `ingest.py`'s module docstring for
    the full table), mirroring `UnresolvedBinaryRecord.problem`'s style in
    `common.schemas` — deliberately terse and grep-able rather than prose.
    """

    requested_path: str
    reason: str
    detail: str | None = None

    def to_json_dict(self) -> dict:
        return {
            "requested_path": self.requested_path,
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class IngestionReport:
    """Step 1's complete output: what will be analyzed, what was skipped and
    why, and what was present on disk but never whitelisted at all.

    Written to `layout.ingestion_report_path(...)` by `ingest.ingest()`
    itself — not only by the CLI — so a programmatic caller (a future
    Component 2) invoking `ingest()` directly still gets a report, mirroring
    why `Stage2Summary` is written by `run_extraction()` itself.
    """

    db_subfolder: Path
    decompiled_tree_dir: Path
    targets: tuple[Target, ...]
    skipped: tuple[SkippedTarget, ...] = field(default_factory=tuple)
    orphans: tuple[str, ...] = field(default_factory=tuple)
    """POSIX paths (relative to `decompiled_tree_dir`) present in the mirror
    tree but not matched by any whitelist entry — reported for visibility,
    never analyzed, per the brief's "ignore all non-whitelisted files"."""
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_json_dict(self) -> dict:
        return {
            "db_subfolder": str(self.db_subfolder),
            "decompiled_tree_dir": str(self.decompiled_tree_dir),
            "targets": [
                {
                    "bin_id": t.bin_id,
                    "rootfs_path": t.rootfs_path,
                    "requested_path": t.requested_path,
                    "aliases": list(t.aliases),
                    "sha256": t.sha256,
                    "source_path": str(t.source_path),
                    "source_relpath": t.source_relpath,
                    "size_bytes": t.size_bytes,
                    "status": t.status.value,
                    "function_count": t.function_count,
                }
                for t in self.targets
            ],
            "skipped": [s.to_json_dict() for s in self.skipped],
            "orphans": list(self.orphans),
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class ExtractedFunction:
    """One `function_definition` AST node kept by `clean.extract.
    extract_functions`, verbatim except for the repair passes that ran
    before parsing (thunk-stub replacement, register-var declaration,
    blank-line collapsing)."""

    name: str
    start_line: int
    """1-indexed, relative to the REPAIRED text `extract_functions` parsed
    — NOT the original mirror file. `collapse_blank_lines` changes line
    counts, so a 1:1 mapping back to the raw file isn't preserved; this is
    the same "or note the offset" allowance the project's broader chunking
    design already carries."""
    end_line: int
    text: str
    """Verbatim function source (declarator + body), never reformatted."""


@dataclass(frozen=True)
class ExtractedSource:
    """One binary's complete function-only extraction result — the input
    to (not-yet-built) chunking, and what `--debug` dumps to
    `stage3/debug/<bin_id>.cleaned.c`."""

    bin_id: str
    functions: tuple[ExtractedFunction, ...]
    total_lines: int
    """Line count of the repaired text, before extraction — the baseline
    `dropped_line_count` is measured against."""
    dropped_line_count: int
    """`total_lines` minus every kept function's own line span — lines that
    were prelude, type declarations, thunk-wall externs, or scaffolding
    comments, none of which survive into `functions`."""

    def to_text(self) -> str:
        """Functions joined in original source order (tree-sitter's
        `root_node.children` preserves node order, and only
        `function_definition` nodes were kept), separated by one blank
        line, each verbatim — no reformatting of any kept function body."""
        return "\n\n".join(f.text for f in self.functions)
