"""Tests for fw_audit.config.settings."""

from __future__ import annotations

from pathlib import Path

from fw_audit.config.settings import Settings


def test_defaults_apply_when_env_absent(monkeypatch):
    monkeypatch.delenv("FWA_ENVIRONMENT", raising=False)
    monkeypatch.delenv("FWA_COMMAND_PREFIX", raising=False)
    settings = Settings(_env_file=None)
    assert settings.environment == "development"
    assert settings.command_prefix == []
    assert settings.subprocess_timeout_seconds == 900
    assert settings.executor_backend == "docker"


def test_command_prefix_parses_space_separated_string():
    settings = Settings(_env_file=None, FWA_COMMAND_PREFIX="wsl")
    assert settings.command_prefix == ["wsl"]


def test_command_prefix_parses_multi_token_string():
    settings = Settings(_env_file=None, FWA_COMMAND_PREFIX="wsl -e")
    assert settings.command_prefix == ["wsl", "-e"]


def test_command_prefix_accepts_list_passthrough():
    settings = Settings(_env_file=None, FWA_COMMAND_PREFIX=["wsl"])
    assert settings.command_prefix == ["wsl"]


def test_firmware_and_database_path_default_under_data_dir(tmp_path: Path):
    settings = Settings(_env_file=None, FWA_DATA_DIR=str(tmp_path))
    assert settings.firmware_path == tmp_path / "firmware"
    assert settings.database_path == tmp_path / "db"


def test_explicit_firmware_dir_overrides_default(tmp_path: Path):
    custom = tmp_path / "custom_fw"
    settings = Settings(_env_file=None, FWA_DATA_DIR=str(tmp_path), FWA_FIRMWARE_DIR=str(custom))
    assert settings.firmware_path == custom


def test_explicit_database_dir_overrides_default(tmp_path: Path):
    custom = tmp_path / "custom_db"
    settings = Settings(_env_file=None, FWA_DATA_DIR=str(tmp_path), FWA_DATABASE_DIR=str(custom))
    assert settings.database_path == custom


def test_ensure_dirs_creates_directories(tmp_path: Path):
    settings = Settings(_env_file=None, FWA_DATA_DIR=str(tmp_path / "data"))
    settings.ensure_dirs()
    assert settings.data_dir.is_dir()
    assert settings.firmware_path.is_dir()
    assert settings.database_path.is_dir()


def test_db_subfolder_creates_and_names_by_stem(tmp_path: Path):
    settings = Settings(_env_file=None, FWA_DATA_DIR=str(tmp_path / "data"))
    sub = settings.db_subfolder("router-fw-1.2")
    assert sub.is_dir()
    assert sub == settings.database_path / "router-fw-1.2"


def test_google_api_key_accepts_gemini_alias():
    settings = Settings(_env_file=None, GEMINI_API_KEY="abc123")
    assert settings.google_api_key == "abc123"


def test_docker_settings_defaults():
    settings = Settings(_env_file=None)
    assert settings.docker_bin == "docker"
    assert settings.docker_image == "fw-audit-sandbox:latest"
