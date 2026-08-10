"""Tests for fw_audit.stage2_extraction.ghidra.command.

Pure string assertions — no Docker, no filesystem, matching command.py's
own "no I/O" contract.
"""

from __future__ import annotations

from fw_audit.common.schemas import ELFArch, ELFInfo
from fw_audit.stage2_extraction.ghidra.command import (
    build_analyze_headless_command,
    resolve_language_id,
    sanitize_project_name,
)


def _elf(arch: ELFArch, is_64bit: bool, is_little_endian: bool) -> ELFInfo:
    return ELFInfo(
        path="bin/httpd",
        absolute_path="/x/bin/httpd",
        size_bytes=1000,
        arch=arch,
        is_64bit=is_64bit,
        is_little_endian=is_little_endian,
    )


def test_resolve_language_id_known_combos():
    assert resolve_language_id(_elf(ELFArch.MIPS, False, False)) == "MIPS:BE:32:default"
    assert resolve_language_id(_elf(ELFArch.MIPS, False, True)) == "MIPS:LE:32:default"
    assert resolve_language_id(_elf(ELFArch.ARM, False, True)) == "ARM:LE:32:v7"
    assert resolve_language_id(_elf(ELFArch.AARCH64, True, True)) == "AARCH64:LE:64:v8A"


def test_resolve_language_id_unknown_arch_returns_none():
    assert resolve_language_id(_elf(ELFArch.UNKNOWN, False, True)) is None


def test_resolve_language_id_none_elf_returns_none():
    assert resolve_language_id(None) is None


def test_sanitize_project_name_is_shell_safe():
    name = sanitize_project_name("run one/two", "bin id!!")
    assert " " not in name
    assert "/" not in name
    assert "!" not in name


def _build(**overrides):
    kwargs = {
        "run_id": "run1",
        "bin_id": "bin_httpd__abc123",
        "container_import_path": "/work/binwalk_1/squashfs-root/usr/sbin/httpd",
        "container_out_dir": "/work/stage2/binaries/bin_httpd__abc123/raw",
        "container_ghidra_log_dir": "/work/stage2/binaries/bin_httpd__abc123/ghidra",
        "max_mem": "4g",
        "max_functions": 2000,
        "decompile_timeout_seconds": 60,
        "emit_strings": True,
        "analysis_timeout_seconds": 1800,
        "max_cpu": 2,
    }
    kwargs.update(overrides)
    return build_analyze_headless_command(**kwargs)


def test_command_uses_pyghidra_run_not_bare_analyze_headless():
    """analyzeHeadless directly fails PyGhidra .py postScripts with "Ghidra
    was not started with PyGhidra" — pyghidraRun -H is the real entry point
    (confirmed against a live build; see command.py's module docstring)."""
    cmd = _build()
    assert "/opt/ghidra/support/pyghidraRun -H " in cmd.command
    assert "/opt/ghidra/support/analyzeHeadless" not in cmd.command


def test_command_contains_import_and_scriptpath():
    cmd = _build()
    assert '-import "/work/binwalk_1/squashfs-root/usr/sbin/httpd"' in cmd.command
    assert "-scriptPath /opt/fwaudit/ghidra_scripts" in cmd.command
    assert "-postScript fw_audit_export.py" in cmd.command


def test_command_uses_post_script_not_pre_script():
    cmd = _build()
    assert "-preScript" not in cmd.command
    assert "-postScript" in cmd.command


def test_command_has_deleteproject_and_logs():
    cmd = _build()
    assert "-deleteProject" in cmd.command
    assert "-log " in cmd.command
    assert "-scriptlog " in cmd.command


def test_command_redirects_stdout_to_file():
    cmd = _build()
    assert "2>&1" in cmd.command
    assert "headless_stdout.txt" in cmd.command


def test_command_sets_java_heap():
    cmd = _build(max_mem="6g")
    assert 'export _JAVA_OPTIONS="-Xmx6g"' in cmd.command


def test_command_paths_are_all_container_absolute_never_host():
    cmd = _build()
    assert "C:\\" not in cmd.command
    assert cmd.command.count("/work/") >= 3


def test_command_processor_absent_by_default():
    cmd = _build()
    assert "-processor" not in cmd.command
    assert cmd.used_processor_override is False


def test_command_processor_present_on_retry():
    cmd = _build(language_id="MIPS:BE:32:default")
    assert "-processor MIPS:BE:32:default" in cmd.command
    assert cmd.used_processor_override is True


def test_command_project_name_differs_with_retry_suffix():
    first = _build()
    retry = _build(project_suffix="retry")
    assert first.project_name != retry.project_name


def test_command_passes_export_script_args_in_order():
    cmd = _build(max_functions=1500, decompile_timeout_seconds=45, emit_strings=False)
    assert (
        '-postScript fw_audit_export.py "/work/stage2/binaries/bin_httpd__abc123/raw" 1500 45 false'
        in cmd.command
    )
