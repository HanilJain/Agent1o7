"""Tests for fw_audit.stage1_ingestion.tools.extraction_tools.

These are the low-level subprocess primitives backing `LocalExecutor`
(and, via `run_command`, the `docker` CLI invocation inside
`DockerExecutor`). Per-tool composition (unzip/binwalk/tp-link-decrypt
command strings) lives in `stage1_ingestion/extraction/script.py` now, not
here — see tests/test_docker_executor.py and tests/test_trigger_policy.py
for that layer.
"""

from __future__ import annotations

from fw_audit.config.settings import Settings
from fw_audit.stage1_ingestion.tools.extraction_tools import run_command, tool_available


def test_tool_available_optimistic_under_command_prefix():
    settings = Settings(_env_file=None, FWA_COMMAND_PREFIX="wsl")
    assert tool_available("definitely_not_a_real_binary_xyz", settings) is True


def test_tool_available_checks_path_without_prefix():
    settings = Settings(_env_file=None)
    assert tool_available("definitely_not_a_real_binary_xyz", settings) is False


def test_tool_available_true_for_real_binary():
    settings = Settings(_env_file=None)
    assert tool_available("python", settings) is True


async def test_run_command_missing_binary_reports_failure_not_raise():
    result = await run_command("definitely_not_a_real_binary_xyz", [])
    assert result.ok is False
    assert result.returncode is None
    assert result.timed_out is False


async def test_run_command_success():
    result = await run_command("python", ["--version"])
    assert result.ok is True
    assert result.returncode == 0


async def test_run_command_nonzero_exit_reported_not_raised():
    result = await run_command("python", ["-c", "import sys; sys.exit(7)"])
    assert result.ok is False
    assert result.returncode == 7
    assert result.timed_out is False
