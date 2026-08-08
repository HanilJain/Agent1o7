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

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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

    # ---- External tool invocation (LocalExecutor / the `docker` CLI call) -
    # Prepended to every host-level command. Firmware-extraction tool names
    # (binwalk/unsquashfs/etc.) are no longer configurable here — those run
    # inside the sandbox image at fixed PATH locations
    # (see stage1_ingestion/extraction/script.py), not on the host.
    command_prefix: list[str] = Field(
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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()
