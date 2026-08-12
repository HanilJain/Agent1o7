"""Cross-stage Pydantic schemas.

These models are the data contracts passed between pipeline stages (e.g.
Stage 1's identified-binary list is consumed by Stage 2's Ghidra MCP node).
Keeping them here — rather than duplicating ad-hoc dicts per stage — is what
lets later stages import Stage 1 output without re-deriving its shape.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator


def extension_from_path(path: str) -> str:
    """Derive a file extension straight from a path string, without the
    leading dot (e.g. "lib/libbcm_boardctl.so" -> "so"; "bin/httpd" -> "").

    The single source of truth for "what's this file's extension" —
    there is deliberately no separate `extension` field anywhere in these
    schemas to keep in sync with `path`; every consumer (Stage 1's output,
    Stage 2's Ghidra input handling in `stage2_extraction.resolve`) derives
    it on demand from `path`/`requested_path` via this function instead.

    Handles both POSIX and Windows separators. A basename with no `.`, or
    one that only starts with `.` (a dotfile like ".profile"), has no
    extension. Uses the LAST `.` in the basename (`libc.so.6` -> "6") — this
    is a simple display/logging helper, not the allow-list gate; see
    `stage2_extraction.resolve._extension_allowed`, which deliberately
    matches the FIRST suffix instead so a shared-library version number
    doesn't hide the `.so`.
    """
    basename = path.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in basename or basename.startswith("."):
        return ""
    return basename.rsplit(".", 1)[-1]


class FirmwareMetadata(BaseModel):
    """Metadata about the raw firmware image as originally supplied."""

    original_filename: str
    size_bytes: int
    sha256: str
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExtractionArtifactKind(str, Enum):
    """What kind of extraction step produced an artifact."""

    UNZIP = "unzip"
    BINWALK = "binwalk"
    UNSQUASHFS = "unsquashfs"
    VENDOR_DECRYPT = "vendor_decrypt"
    NORMALIZE_PERMISSIONS = "normalize_permissions"
    TREE_LISTING = "tree_listing"
    OTHER = "other"


class ExtractionArtifact(BaseModel):
    """A single step in the Extraction Script's audit trail.

    Every extraction/decrypt/unpack action appends one of these, so a full
    record of what tool ran, on what input, and what it produced is always
    available for debugging and for Stage 3's RAG ingestion. Written to the
    Database alongside the extracted filesystem — never sent to Stage 2.
    """

    kind: ExtractionArtifactKind
    path: str
    source_tool: str
    success: bool
    notes: str | None = None


class ELFArch(str, Enum):
    """Target CPU architecture, as read from the ELF header."""

    MIPS = "mips"
    ARM = "arm"
    AARCH64 = "aarch64"
    X86 = "x86"
    X86_64 = "x86_64"
    UNKNOWN = "unknown"


class ELFInfo(BaseModel):
    """Descriptive (non-judging) facts about one ELF file, read from its header.

    Purely factual — this feeds `tree.txt` annotation (a `file(1)`-style
    descriptor per entry) so the Identifier Agent has real signal to reason
    over. It carries no priority/score/verdict: identification is the
    Identifier Agent's job, not the Extraction Script's (see the Component 1
    / Component 2 privilege split in the Stage 1 policy doc).
    """

    path: str
    """Path relative to the extracted rootfs root."""

    absolute_path: str
    size_bytes: int

    arch: ELFArch = ELFArch.UNKNOWN
    is_64bit: bool | None = None
    is_little_endian: bool | None = None
    is_stripped: bool | None = None
    interpreter: str | None = None
    """Dynamic linker path (PT_INTERP), if any; None implies static linking."""

    @classmethod
    def path_key(cls, path: str | Path) -> str:
        """Normalize a path for use as a dict/shortlist key."""
        return str(path).replace("\\", "/")

    def describe(self) -> str:
        """Render a compact, `file(1)`-style descriptor for tree.txt annotation.

        e.g. "ELF 32-bit LSB MIPS, dynamically linked, stripped".
        """
        bits = "64-bit" if self.is_64bit else "32-bit" if self.is_64bit is False else "?-bit"
        endian = "LSB" if self.is_little_endian else "MSB" if self.is_little_endian is False else "?"
        arch = self.arch.value.upper() if self.arch != ELFArch.UNKNOWN else "unknown arch"
        linkage = "dynamically linked" if self.interpreter else "statically linked"
        stripped = "stripped" if self.is_stripped else "not stripped" if self.is_stripped is False else ""
        parts = [p for p in (f"ELF {bits} {endian} {arch}", linkage, stripped) if p]
        return ", ".join(parts)


class IdentifiedBinary(BaseModel):
    """One entry in the Identifier Agent's output.

    Per the Stage 1 policy: the Identifier Agent reads `tree.txt` text only
    (no filesystem/execution access) and returns a JSON list of binaries
    worth deeper security analysis, each with its location inside the
    firmware's Database subfolder. This is Stage 1's ONLY artifact that
    bypasses the Database and goes straight to Stage 2's Ghidra Binary
    Parser — Stage 2 fetches the actual binary bytes itself using `path`.

    Strictly `{"path": str}` — no separate `extension` field. The Identifier
    Agent is not asked for a justification or any derived metadata; when an
    extension is needed (Stage 1's own display, Stage 2's Ghidra input
    handling), it's computed on demand from `path` via
    `extension_from_path`, never carried as a second field that could drift
    out of sync with it. This also means `path` MUST be the complete
    filename as it appears in the listing, extension included — see
    `identifier/prompts.py`, which instructs exactly that.
    """

    path: str = Field(
        description=(
            "The file's complete path exactly as it appears in the listing, "
            "including its extension if it has one (e.g. 'lib/libbcm_boardctl.so', "
            "not 'lib/libbcm_boardctl')."
        )
    )
    """The binary's path as the Identifier Agent wrote it — rootfs-relative
    POSIX by prompt convention only (see `identifier/prompts.py`), never
    validated or resolved here. Untrusted LLM output: may carry a leading
    `/`, be hallucinated, contain `..`, or duplicate another entry. Stage 2's
    `stage2_extraction.resolve` module is what turns this into verified
    bytes; nothing in Stage 1 does."""


class Stage1Summary(BaseModel):
    """Stage 1's machine-readable hand-off (`stage1_summary.json`).

    Stage 2 parses this rather than hand-rolling dict access on Stage 1's
    JSON, so the one messy detail in that JSON — `status` serializing as the
    enum's `str()` repr (`"IngestionStatus.COMPLETED"`) on summaries written
    before `stage1_ingestion/runner.py` started using `.value` — is
    normalized here, once, declaratively, instead of at every call site.
    """

    schema_version: int = 1
    run_id: str | None = None
    status: str
    db_subfolder: str
    tree_txt_path: str | None = None
    rootfs_dir: str | None = None
    """Absent on summaries written before Stage 1 started publishing this
    (see `stage1_ingestion/state.py`). Stage 2's `stage1_io` module falls
    back to parsing `tree.txt`'s first line when this is `None`."""
    identified_binaries: list[IdentifiedBinary] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @field_validator("status", mode="before")
    @classmethod
    def _normalize_status(cls, value: object) -> object:
        """Accept both `"completed"` (current) and `"IngestionStatus.COMPLETED"`
        (older summaries) transparently, so callers never see the repr form."""
        if isinstance(value, str) and value.startswith("IngestionStatus."):
            return value.removeprefix("IngestionStatus.").lower()
        return value


# --------------------------------------------------------------------- #
# Stage 2 — Feature Extraction (Ghidra decompilation & disassembly)
# --------------------------------------------------------------------- #


class DecompilationStatus(str, Enum):
    """Outcome of decompiling a single resolved binary."""

    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    SKIPPED = "skipped"


class ExtractionStatus(str, Enum):
    """Coarse-grained outcome of an entire Stage 2 run.

    Stage 2 is a plain async pipeline, not a LangGraph state machine (it has
    no LLM in it at all) — so unlike `IngestionStatus` there are no in-flight
    states to model here, only the three possible final outcomes."""

    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"


class GhidraFunction(BaseModel):
    """One function recovered by Ghidra, from the Program DB rather than the
    decompiler — signature, calling convention, and the call graph come from
    `Function`/`ReferenceManager` APIs that don't require decompilation to
    have succeeded, which is why a binary with `decompiled=False` functions
    can still carry a populated function list."""

    name: str
    entry_point: str
    size: int
    signature: str
    calling_convention: str | None = None
    is_thunk: bool = False
    is_external: bool = False
    calls: list[str] = Field(default_factory=list)
    called_by: list[str] = Field(default_factory=list)
    c_relpath: str | None = None
    """Per-function raw decompiled C, relative to db_subfolder."""
    asm_relpath: str | None = None
    """Per-function raw disassembly, relative to db_subfolder."""
    decompiled: bool = True
    decompile_error: str | None = None


class BinarySymbol(BaseModel):
    """One import or export symbol; the same shape serves both roles —
    which list it's in is what distinguishes them."""

    name: str
    library: str | None = None
    address: str | None = None


class DecompilationArtifacts(BaseModel):
    """Every output file for one binary. All paths are relative to
    `db_subfolder` — unlike Stage 1's absolute host paths — so the Database
    directory stays relocatable/shareable (see `Stage2Summary`)."""

    raw_c: str | None = None
    raw_header: str | None = None
    raw_functions_dir: str | None = None
    disasm_listing: str | None = None
    disasm_functions_dir: str | None = None
    metadata_json: str | None = None
    normalized_joern_c: str | None = None
    normalized_llm_functions_dir: str | None = None
    ghidra_log: str | None = None
    decompiled_tree_c: str | None = None
    """Flat mirror copy of `normalized_joern_c` (same bytes), relative to
    `Stage2Summary.decompiled_tree_dir` — the ONE exception to this class's
    "relative to db_subfolder" docstring above, because the mirror tree is
    a sibling of db_subfolder, not inside it. See
    `stage2_extraction.layout.decompiled_tree_dir`."""


class DecompiledBinary(BaseModel):
    """One resolved-and-(attempted-)decompiled binary from Stage 1's shortlist."""

    bin_id: str
    """`<rootfs-rel with '/' -> '_'>__<sha256[:12]>` — collision-proof across
    same-basename binaries in different directories; the sha256 prefix also
    makes an unchanged re-run's cache hit detectable."""
    rootfs_path: str
    """POSIX, relative to rootfs_dir — the actual resolved location."""
    requested_path: str
    """What the Identifier Agent actually wrote in `IdentifiedBinary.path`,
    verbatim — may differ from `rootfs_path` (basename rescan recovery,
    leading-slash normalization, etc.); see `stage2_extraction.resolve`. Use
    `extension_from_path(requested_path)` (or `rootfs_path`) if an extension
    is needed — there is no separate stored `extension` field, by design."""
    aliases: list[str] = Field(default_factory=list)
    """Other requested paths that deduped onto this same binary by content
    hash — e.g. busybox applets that are all symlinks to one file."""
    sha256: str
    size_bytes: int
    elf: ELFInfo | None = None
    ghidra_language_id: str | None = None
    status: DecompilationStatus
    function_count: int = 0
    decompiled_function_count: int = 0
    skipped_function_count: int = 0
    functions: list[GhidraFunction] = Field(default_factory=list)
    imports: list[BinarySymbol] = Field(default_factory=list)
    exports: list[BinarySymbol] = Field(default_factory=list)
    artifacts: DecompilationArtifacts = Field(default_factory=DecompilationArtifacts)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class UnresolvedBinaryRecord(BaseModel):
    """One `IdentifiedBinary.path` Stage 2 could not turn into real bytes.

    Recorded, never fatal — an untrusted, LLM-authored path failing to
    resolve is expected input, not a bug (see `stage2_extraction.resolve`).
    """

    requested_path: str
    """Use `extension_from_path(requested_path)` if an extension is needed —
    no separate stored `extension` field, by design (see that function)."""
    problem: str
    """Machine-ish reason code, e.g. "not_found", "escapes_rootfs", "not_an_elf"."""


class Stage2Summary(BaseModel):
    """Stage 2's machine-readable hand-off (`stage2/stage2_summary.json`).

    Two deliberate contract improvements over Stage 1's summary: every path
    here is relative to `db_subfolder` (not host-absolute), so the Database
    directory is relocatable; and this is written directly by
    `run_extraction()` itself, not only by the CLI, so a programmatic caller
    (Stage 3) invoking the function directly still gets a summary.

    ONE documented exception to the relative-to-`db_subfolder` rule:
    `decompiled_tree_dir` below, and by extension every
    `DecompiledBinary.artifacts.decompiled_tree_c` — see that field's
    docstring. The mirror tree is required to live as a SIBLING of
    `db_subfolder` (see `stage2_extraction.layout.decompiled_tree_dir`), so
    it cannot be expressed relative to `db_subfolder` without raising; it
    is instead relative to `db_subfolder`'s own parent. Reconstruct a
    mirror file's full path as:
    `Path(db_subfolder).parent / decompiled_tree_dir / artifacts.decompiled_tree_c`.
    """

    schema_version: int = 1
    run_id: str
    stage1_run_id: str | None = None
    status: ExtractionStatus
    db_subfolder: str
    rootfs_dir: str
    stage2_dir: str
    decompiled_tree_dir: str = ""
    """Name of the sibling mirror directory (`<db_subfolder.name>_decompiled`),
    relative to `db_subfolder`'s PARENT — see the class docstring's
    exception note. Empty string only for summaries written before this
    field existed (`schema_version` stays 1; this is additive)."""
    ghidra_image: str
    ghidra_version: str | None = None
    binaries: list[DecompiledBinary] = Field(default_factory=list)
    unresolved: list[UnresolvedBinaryRecord] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime | None = None
