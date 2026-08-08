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

from pydantic import BaseModel, Field


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
    """

    path: str
    """Location of the binary inside the firmware's Database subfolder."""

    reason: str
    """Why the agent judged this binary worth deeper analysis."""
