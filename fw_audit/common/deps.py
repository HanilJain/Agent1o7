"""Binary dependency discovery and execution-readiness schema.

The on-disk shape of ``stage5/deps/<sha256[:16]>.json`` and the structured
contracts consumed by Stage 5's dependency resolver and readiness assessor.
Kept in its own module rather than appended to ``common/schemas.py`` or
``common/verification.py`` — those already carry the pipeline-plumbing
contracts and the FVVW fork-join verdict contracts respectively, and
dependency discovery is a genuinely separate concern (pre-execution
environment assessment, not vulnerability scoring or verification outcome).

Unlike ``common/findings.py`` and ``common/taint.py``, none of the models
here are LLM-facing structured-output targets — every field is populated by
the deterministic host-side ``dep_resolver`` and ``readiness`` modules.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class DependencyKind(StrEnum):
    """What kind of runtime prerequisite a dependency represents."""

    SHARED_LIBRARY = "shared_library"
    INTERPRETER = "interpreter"
    CONFIG_FILE = "config_file"
    DEVICE_NODE = "device_node"
    EXTERNAL_BINARY = "external_binary"
    IPC_ENDPOINT = "ipc_endpoint"
    ENV_VAR = "env_var"


class DependencyStatus(StrEnum):
    """Whether a dependency was found in the rootfs and is usable."""

    PRESENT = "present"
    """Found in the rootfs and ABI-compatible with the target binary."""
    PRESENT_INCOMPATIBLE = "present_incompatible"
    """Found in the rootfs but arch/bitness/endianness does not match."""
    MISSING = "missing"
    """Not found anywhere in the rootfs search paths."""
    MISSING_EXPECTED = "missing_expected"
    """Missing but typical for a partially-extracted firmware rootfs; a stub
    may be enough for the binary to load."""
    SYMLINK_BROKEN = "symlink_broken"
    """A symlink pointing at this path exists but its target is absent."""


class ConfidenceLevel(StrEnum):
    """How the dependency was discovered."""

    CONFIRMED = "confirmed"
    """Directly parsed from ELF program/dynamic headers (DT_NEEDED, PT_INTERP)."""
    OBSERVED = "observed"
    """Seen at runtime via QEMU strace or dynamic analysis."""
    INFERRED = "inferred"
    """Derived from Stage 2 import symbols or function call patterns."""
    UNRESOLVED = "unresolved"
    """Could not determine whether this dependency exists or is required."""


# ---------------------------------------------------------------------------
# Dependency resolution models
# ---------------------------------------------------------------------------


class ResolvedDependency(BaseModel):
    """One non-library runtime prerequisite (config file, device node, …)."""

    name: str
    kind: DependencyKind
    status: DependencyStatus
    confidence: ConfidenceLevel
    resolved_path: str = ""
    expected_paths: list[str] = Field(default_factory=list)
    arch_compatible: bool | None = None
    notes: str = ""


class LibraryResolution(BaseModel):
    """Resolution result for one DT_NEEDED shared library entry."""

    soname: str
    """The soname as it appears in the binary's DT_NEEDED, e.g. 'libssl.so.1.0.0'."""
    status: DependencyStatus
    resolved_path: str = ""
    """Rootfs-relative path where the library ELF was found."""
    needed_by: list[str] = Field(default_factory=list)
    """sonames (or target binary name) that directly require this library."""
    transitive_deps: list[str] = Field(default_factory=list)
    """DT_NEEDED sonames declared by THIS library (one level deep)."""
    arch_compatible: bool | None = None


class DependencyReport(BaseModel):
    """Complete dependency analysis for one firmware binary against its rootfs.

    Written to ``stage5/deps/<sha256[:16]>.json``.  Cache key is
    ``(binary_sha256, rootfs_dir)`` — the same binary in a different rootfs
    produces a separate report.
    """

    schema_version: int = 1
    binary_path: str
    """Rootfs-relative path of the binary that was analysed."""
    binary_sha256: str
    rootfs_dir: str
    """Absolute host path of the firmware rootfs used for resolution."""
    is_static: bool = False
    """True when the binary has no PT_DYNAMIC segment (statically linked)."""

    # ELF dynamic section facts
    interpreter: str | None = None
    interpreter_status: DependencyStatus | None = None
    interpreter_arch_compatible: bool | None = None
    dt_needed: list[str] = Field(default_factory=list)
    dt_rpath: str = ""
    dt_runpath: str = ""
    dt_soname: str = ""

    # Resolved results
    libraries: list[LibraryResolution] = Field(default_factory=list)
    runtime_deps: list[ResolvedDependency] = Field(default_factory=list)

    # Counts
    total_needed: int = 0
    total_resolved: int = 0
    total_missing: int = 0
    total_incompatible: int = 0

    blocking_reasons: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    resolved_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Readiness assessment
# ---------------------------------------------------------------------------


class ReadinessLevel(StrEnum):
    """Evidence-based execution-readiness verdict for one firmware binary."""

    BLOCKED = "blocked"
    """A known prerequisite prevents meaningful execution: interpreter absent,
    wrong-arch library, or binary arch unsupported by QEMU."""

    UNCERTAIN = "uncertain"
    """Important dependencies are missing or unresolved, but the binary MAY
    still run with stubs.  The interpreter is present; some libraries are
    absent (MISSING_EXPECTED); or runtime deps were inferred but unverified."""

    STATIC_READY = "static_ready"
    """No known static blocker.  All DT_NEEDED resolved or MISSING_EXPECTED;
    interpreter present and ABI-compatible.  Runtime viability unverified."""

    RUNTIME_READY = "runtime_ready"
    """The binary started and advanced past its entry point under QEMU
    (T1-C liveness probe passed).  Set externally by the health gate."""

    VERIFICATION_READY = "verification_ready"
    """The environment is prepared for the specific vulnerability hypothesis:
    binary running, guards satisfied, trigger believed reachable."""


class ReadinessAssessment(BaseModel):
    """Structured execution-readiness verdict derived from a DependencyReport
    and TargetMeta.

    This is a JUDGEMENT (is the binary ready to run?), distinct from
    DependencyReport (FACTUAL: what dependencies does it have?).  Same split
    as ELFInfo (facts) vs the Stage 1 Identifier Agent's selection decision.
    """

    schema_version: int = 1
    binary_path: str
    binary_sha256: str
    level: ReadinessLevel
    blocking_reasons: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    remediation_hints: list[str] = Field(default_factory=list)
    """Concrete suggestions for the bringup agent: stub libraries to create,
    dummy config files to touch, device nodes to mknod."""
    dep_report_path: str = ""
    """Relative path (from db_subfolder) to the cached DependencyReport JSON."""
    assessed_at: datetime = Field(default_factory=datetime.utcnow)
