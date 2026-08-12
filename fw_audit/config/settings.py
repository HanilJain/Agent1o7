"""Application settings, loaded from environment / `.env`.

All configuration is centralized here so no module reaches for ``os.environ``
directly. Access settings via :func:`get_settings` (cached singleton).

Environment-variable conventions:

* LLM credentials use their conventional names (``ANTHROPIC_API_KEY``,
  ``GOOGLE_API_KEY``, ``OLLAMA_BASE_URL``) so existing shells work unchanged.
* Application-specific settings use the ``FWA_`` prefix.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Repository root = two levels up from this file (fw_audit/config/settings.py).
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Typed, validated application configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # ---- Environment / logging ----------------------------------------
    environment: str = Field(default="development", validation_alias="FWA_ENVIRONMENT")
    log_level: str = Field(default="INFO", validation_alias="FWA_LOG_LEVEL")

    # ---- LLM credentials ----------------------------------------------
    anthropic_api_key: str | None = Field(
        default=None, validation_alias="ANTHROPIC_API_KEY"
    )
    google_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GOOGLE_API_KEY", "GEMINI_API_KEY"),
    )
    ollama_base_url: str = Field(
        default="http://localhost:11434", validation_alias="OLLAMA_BASE_URL"
    )

    # ---- Directories ----------------------------------------------------
    data_dir: Path = Field(default=PROJECT_ROOT / "data", validation_alias="FWA_DATA_DIR")
    firmware_dir: Path | None = Field(default=None, validation_alias="FWA_FIRMWARE_DIR")
    database_dir: Path | None = Field(default=None, validation_alias="FWA_DATABASE_DIR")
    """Where per-firmware Database subfolders (extracted FS + tree.txt) live."""

    # ---- Execution backend ----------------------------------------------
    executor_backend: str = Field(default="docker", validation_alias="FWA_EXECUTOR_BACKEND")
    """One of "docker" (production default), "local" (tests/dev), "sandbox"
    (reserved, unimplemented — see fw_audit.executors.sandbox_executor)."""
    docker_bin: str = Field(default="docker", validation_alias="FWA_DOCKER_BIN")
    docker_image: str = Field(
        default="fw-audit-sandbox:latest", validation_alias="FWA_DOCKER_IMAGE"
    )

    # ---- Stage 2: Ghidra decompilation -----------------------------------
    ghidra_image: str = Field(
        default="fw-audit-ghidra:latest", validation_alias="FWA_GHIDRA_IMAGE"
    )
    ghidra_timeout_seconds: int = Field(
        default=3600, ge=60, validation_alias="FWA_GHIDRA_TIMEOUT_SECONDS"
    )
    """Wall-clock cap for ONE analyzeHeadless invocation (one binary).
    Distinct from subprocess_timeout_seconds (900s default) — a multi-MB
    stripped MIPS binary routinely exceeds that."""
    ghidra_analysis_timeout_seconds: int = Field(
        default=1800, ge=60, validation_alias="FWA_GHIDRA_ANALYSIS_TIMEOUT_SECONDS"
    )
    """Passed to analyzeHeadless as -analysisTimeoutPerFile; bounds Ghidra's
    own auto-analysis, distinct from the outer process-level timeout above."""
    ghidra_max_mem: str = Field(
        default="4g", pattern=r"^\d+[mMgG]$", validation_alias="FWA_GHIDRA_MAX_MEM"
    )
    ghidra_max_cpu: int = Field(default=2, ge=1, validation_alias="FWA_GHIDRA_MAX_CPU")
    ghidra_max_functions: int = Field(
        default=2000, ge=1, validation_alias="FWA_GHIDRA_MAX_FUNCTIONS"
    )
    """Router binaries routinely exceed 10,000 functions; the export script
    caps at this many (largest/most-referenced first) and records the rest
    as skipped rather than letting a single binary run unbounded."""
    ghidra_decompile_timeout_seconds: int = Field(
        default=60, ge=1, validation_alias="FWA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS"
    )
    ghidra_emit_strings: bool = Field(
        default=True, validation_alias="FWA_GHIDRA_EMIT_STRINGS"
    )
    stage2_concurrency: int = Field(
        default=1, ge=1, le=8, validation_alias="FWA_STAGE2_CONCURRENCY"
    )
    """Binaries decompiled in parallel. Default 1: each analyzeHeadless JVM
    reserves ghidra_max_mem, so N concurrent means N x that on the host."""
    stage2_max_binaries: int = Field(
        default=25, ge=1, validation_alias="FWA_STAGE2_MAX_BINARIES"
    )
    stage2_max_rescan_files: int = Field(
        default=200_000, ge=1, validation_alias="FWA_STAGE2_MAX_RESCAN_FILES"
    )
    """Cap on the lazily-built rootfs basename index used to recover an
    IdentifiedBinary.path that doesn't resolve directly (see
    stage2_extraction.resolve)."""

    # ---- Stage 3: analysis core (ingest / clean / chunk / queue) --------
    stage3_chunk_lines: int = Field(
        default=1000, ge=50, validation_alias="FWA_STAGE3_CHUNK_LINES"
    )
    """Soft per-chunk line-count target for Step 3's AST-aware chunker.
    Unused by this session's code (Step 1 only); reserved so `Settings` and
    the `fw-analyze --chunk-lines` flag don't need a second change once
    chunking lands."""
    stage3_max_chunk_lines: int = Field(
        default=4000, ge=1, validation_alias="FWA_STAGE3_MAX_CHUNK_LINES"
    )
    """Hard cap before a single oversized AST node (e.g. one huge function)
    is emitted as its own oversized chunk rather than merged with others.
    Unused by this session's code; reserved for Step 3."""
    stage3_debug_dump: bool = Field(
        default=False, validation_alias="FWA_STAGE3_DEBUG_DUMP"
    )
    """When true, Step 4's queue writes chunk payloads to
    <db_subfolder>/stage3/chunks/ as they're produced. Unused by this
    session's code; reserved for Step 4."""

    # ---- External tool invocation (LocalExecutor / the `docker` CLI call) -
    # Prepended to every host-level command. Firmware-extraction tool names
    # (binwalk/unsquashfs/etc.) are no longer configurable here — those run
    # inside the sandbox image at fixed PATH locations
    # (see stage1_ingestion/extraction/script.py), not on the host.
    # NoDecode: pydantic-settings otherwise JSON-decodes complex-typed env
    # values before our "before" validator runs, which raises on a plain
    # (or empty) string like `FWA_COMMAND_PREFIX=` — NoDecode hands the raw
    # string straight to `_split_command_prefix` below instead.
    command_prefix: Annotated[list[str], NoDecode] = Field(
        default_factory=list, validation_alias="FWA_COMMAND_PREFIX"
    )
    subprocess_timeout_seconds: int = Field(
        default=900, ge=1, validation_alias="FWA_SUBPROCESS_TIMEOUT_SECONDS"
    )

    # ------------------------------------------------------------------ #
    # Validators
    # ------------------------------------------------------------------ #
    @field_validator("command_prefix", mode="before")
    @classmethod
    def _split_command_prefix(cls, value: object) -> object:
        """Allow a comma- or space-separated string for the command prefix."""
        if isinstance(value, str):
            return [tok for tok in value.replace(",", " ").split() if tok]
        return value

    # ------------------------------------------------------------------ #
    # Derived helpers
    # ------------------------------------------------------------------ #
    @property
    def firmware_path(self) -> Path:
        """Directory where raw firmware inputs live."""
        return self.firmware_dir or (self.data_dir / "firmware")

    @property
    def database_path(self) -> Path:
        """Root of the per-firmware Database (extracted FS + tree.txt live here)."""
        return self.database_dir or (self.data_dir / "db")

    def ensure_dirs(self) -> None:
        """Create the data/firmware/db directories if they do not exist."""
        for path in (self.data_dir, self.firmware_path, self.database_path):
            path.mkdir(parents=True, exist_ok=True)

    def db_subfolder(self, firmware_stem: str) -> Path:
        """Return (and create) the Database subfolder for a firmware image.

        Named after the input file (``router-fw-1.2.bin`` -> ``router-fw-1.2/``),
        per the naming convention: every artifact for that image accumulates here.
        """
        path = self.database_path / firmware_stem
        path.mkdir(parents=True, exist_ok=True)
        return path

    def stage2_dir(self, firmware_stem: str) -> Path:
        """Return (and create) `<db_subfolder>/stage2/` for a firmware image."""
        path = self.db_subfolder(firmware_stem) / "stage2"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def stage3_dir(self, firmware_stem: str) -> Path:
        """Return (and create) `<db_subfolder>/stage3/` for a firmware image."""
        path = self.db_subfolder(firmware_stem) / "stage3"
        path.mkdir(parents=True, exist_ok=True)
        return path


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()
