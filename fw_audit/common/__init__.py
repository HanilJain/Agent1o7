"""Cross-stage shared schemas and constants."""

from fw_audit.common.constants import (
    ELF_MAGIC,
    ROOTFS_BIN_DIRS,
    ROOTFS_SKIP_DIRS,
    TARGET_DAEMON_SUBSTRINGS,
    TARGET_DAEMONS,
)
from fw_audit.common.schemas import (
    ELFArch,
    ELFInfo,
    ExtractionArtifact,
    ExtractionArtifactKind,
    FirmwareMetadata,
    IdentifiedBinary,
)

__all__ = [
    "ELF_MAGIC",
    "ROOTFS_BIN_DIRS",
    "ROOTFS_SKIP_DIRS",
    "TARGET_DAEMON_SUBSTRINGS",
    "TARGET_DAEMONS",
    "ELFArch",
    "ELFInfo",
    "ExtractionArtifact",
    "ExtractionArtifactKind",
    "FirmwareMetadata",
    "IdentifiedBinary",
]
