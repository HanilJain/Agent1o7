"""Cross-stage shared schemas and constants."""

from fw_audit.common.constants import (
    ELF_MAGIC,
    ROOTFS_BIN_DIRS,
    ROOTFS_SKIP_DIRS,
    TARGET_DAEMON_SUBSTRINGS,
    TARGET_DAEMONS,
)
from fw_audit.common.schemas import (
    BinarySymbol,
    DecompilationArtifacts,
    DecompilationStatus,
    DecompiledBinary,
    ELFArch,
    ELFInfo,
    ExtractionArtifact,
    ExtractionArtifactKind,
    ExtractionStatus,
    FirmwareMetadata,
    GhidraFunction,
    IdentifiedBinary,
    Stage1Summary,
    Stage2Summary,
    UnresolvedBinaryRecord,
)

__all__ = [
    "ELF_MAGIC",
    "ROOTFS_BIN_DIRS",
    "ROOTFS_SKIP_DIRS",
    "TARGET_DAEMON_SUBSTRINGS",
    "TARGET_DAEMONS",
    "BinarySymbol",
    "DecompilationArtifacts",
    "DecompilationStatus",
    "DecompiledBinary",
    "ELFArch",
    "ELFInfo",
    "ExtractionArtifact",
    "ExtractionArtifactKind",
    "ExtractionStatus",
    "FirmwareMetadata",
    "GhidraFunction",
    "IdentifiedBinary",
    "Stage1Summary",
    "Stage2Summary",
    "UnresolvedBinaryRecord",
]
