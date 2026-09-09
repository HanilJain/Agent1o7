"""Tests for `fw_audit.stage3b_claims.resolve` — pure, zero-LLM binary/
function hint resolution against a synthetic `Stage2Summary`."""

from __future__ import annotations

from datetime import UTC, datetime

from fw_audit.common.schemas import (
    DecompilationArtifacts,
    DecompilationStatus,
    DecompiledBinary,
    ExtractionStatus,
    GhidraFunction,
    Stage2Summary,
)
from fw_audit.stage3b_claims.resolve import resolve_binary, resolve_function
from fw_audit.stage5_verification.tools.characterize_tool import _find_function


def _function(name: str, entry_point: str) -> GhidraFunction:
    return GhidraFunction(name=name, entry_point=entry_point, size=100, signature="void f()")


def _binary(
    bin_id: str, rootfs_path: str, functions: list[GhidraFunction] | None = None
) -> DecompiledBinary:
    return DecompiledBinary(
        bin_id=bin_id,
        rootfs_path=rootfs_path,
        requested_path=f"/{rootfs_path}",
        sha256="a" * 64,
        size_bytes=100,
        status=DecompilationStatus.SUCCEEDED,
        artifacts=DecompilationArtifacts(),
        functions=functions or [],
    )


def _summary(binaries: list[DecompiledBinary]) -> Stage2Summary:
    return Stage2Summary(
        run_id="r1",
        status=ExtractionStatus.COMPLETED,
        db_subfolder="/db",
        rootfs_dir="/rootfs",
        stage2_dir="/db/stage2",
        ghidra_image="fw-audit-ghidra:latest",
        binaries=binaries,
        started_at=datetime.now(UTC),
    )


def test_resolve_binary_empty_hint_returns_none():
    summary = _summary([_binary("b1", "sbin/httpd")])
    result = resolve_binary("", stage2_summary=summary)
    assert result.bin_id is None


def test_resolve_binary_exact_rootfs_path_match():
    summary = _summary([_binary("b1", "sbin/httpd")])
    result = resolve_binary("sbin/httpd", stage2_summary=summary)
    assert result.bin_id == "b1"
    assert result.matched_on == "rootfs_path"


def test_resolve_binary_basename_match():
    summary = _summary([_binary("b1", "sbin/httpd")])
    result = resolve_binary("httpd", stage2_summary=summary)
    assert result.bin_id == "b1"
    assert result.matched_on == "basename"


def test_resolve_binary_basename_match_with_leading_slash():
    summary = _summary([_binary("b1", "sbin/httpd")])
    result = resolve_binary("/usr/sbin/httpd", stage2_summary=summary)
    assert result.bin_id == "b1"
    assert result.matched_on == "basename"


def test_resolve_binary_normalized_basename_match():
    # "HTTPD-daemon" normalizes to "httpddaemon"; hint "httpd_daemon"
    # normalizes identically — exercises case + punctuation insensitivity
    # without the exact/basename tiers already catching it first.
    summary = _summary([_binary("b1", "sbin/HTTPD-daemon")])
    result = resolve_binary("httpd_daemon", stage2_summary=summary)
    assert result.bin_id == "b1"
    assert result.matched_on == "normalized_basename"


def test_resolve_binary_bin_id_substring_match():
    summary = _summary([_binary("sbin_hostapd__5d85c8", "sbin/hostapd")])
    result = resolve_binary("hostapd_daemon", stage2_summary=summary)
    # "hostapd_daemon" normalizes to "hostapddaemon" — does NOT appear as a
    # substring of the normalized bin_id, so this should NOT match via
    # bin_id_substring (it already matched via basename... use a name that
    # only the bin_id itself would contain instead).
    assert result.bin_id is None


def test_resolve_binary_bin_id_substring_match_positive():
    summary = _summary(
        [_binary("usr_sbin_wpa__supplicant_abc123", "usr/sbin/wpa_supplicant_renamed")]
    )
    result = resolve_binary("wpa_supplicant", stage2_summary=summary)
    assert result.bin_id == "usr_sbin_wpa__supplicant_abc123"
    assert result.matched_on == "bin_id_substring"


def test_resolve_binary_no_match_returns_none():
    summary = _summary([_binary("b1", "sbin/httpd")])
    result = resolve_binary("totally_unrelated_name", stage2_summary=summary)
    assert result.bin_id is None


def test_resolve_function_empty_hint_returns_none():
    functions = [_function("formSetWanNonLogin", "0x004053a8")]
    result = resolve_function("", functions=functions)
    assert result.function_name is None


def test_resolve_function_no_functions_returns_none():
    result = resolve_function("formSetWanNonLogin", functions=[])
    assert result.function_name is None


def test_resolve_function_exact_match():
    functions = [_function("formSetWanNonLogin", "0x004053a8")]
    result = resolve_function("formSetWanNonLogin", functions=functions)
    assert result.function_name == "formSetWanNonLogin"
    assert result.matched_on == "exact"


def test_resolve_function_case_sensitive_exact_only():
    # Deliberately case-sensitive — mirrors characterize_tool._find_function
    # exactly (no case-insensitive tier there).
    functions = [_function("formSetWanNonLogin", "0x004053a8")]
    result = resolve_function("FORMSETWANNONLOGIN", functions=functions)
    assert result.function_name is None


def test_resolve_function_entry_point_substring_match():
    functions = [_function("FUN_004053a8", "0x004053a8")]
    result = resolve_function("004053a8", functions=functions)
    assert result.function_name == "FUN_004053a8"
    assert result.matched_on == "entry_point_substring"


def test_resolve_function_no_match_returns_none():
    functions = [_function("formSetWanNonLogin", "0x004053a8")]
    result = resolve_function("nonexistent_function", functions=functions)
    assert result.function_name is None


def test_resolve_function_match_implies_characterize_tool_match():
    """The load-bearing guarantee `resolve.py`'s module docstring makes:
    whatever `resolve_function` matches, `characterize_tool._find_function`
    (Stage 5's own stricter lookup) must also match — checked here against
    a battery of hint/function-table combinations."""
    cases = [
        ("formSetWanNonLogin", [_function("formSetWanNonLogin", "0x1000")]),
        ("0x1000", [_function("FUN_1000", "0x1000")]),
        ("1000", [_function("FUN_00001000", "0x00001000")]),
    ]
    for hint, functions in cases:
        resolution = resolve_function(hint, functions=tuple(functions))
        if resolution.function_name is not None:
            found = _find_function(tuple(functions), hint)
            assert found is not None, f"resolve_function matched {hint!r} but _find_function didn't"
            assert found.name == resolution.function_name
