"""Tests for `stage5_verification.tools.crosscheck_tool` — Stage 5 FVVW v3
Phase 3. Same `FakeExecutor` mechanics as `tests/test_stage5_joern_tool.py`
(no real Docker/objdump involved)."""

from __future__ import annotations

from pathlib import Path

from fw_audit.common.verification import StaticPlan
from fw_audit.config.settings import Settings
from fw_audit.executors.base import ExecutionResult
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.tools.crosscheck_tool import (
    CrosscheckResult,
    objdump_disassemble_command,
    readelf_dynsym_command,
    resolve_sink_addresses,
    static_crosscheck,
)

_DISASSEMBLY = """
00026938 <FUN_00026938>:
   26938:       bl      26a10 <strcpy@plt>
   2693c:       bl      26a20 <snprintf@plt>
   26940:       bl      26a30 <system@plt>
"""


def _candidate(*, binary_path: Path | None) -> VerificationCandidate:
    from fw_audit.common.findings import (
        Confidence,
        Decision,
        EvidenceSpan,
        Finding,
        FindingSink,
        FindingSource,
        Severity,
    )

    finding = Finding(
        finding_id="candidate_001",
        title="t",
        category="command_execution",
        severity=Severity(impact=3, exploitability=3, reachability=3),
        confidence=Confidence.MEDIUM,
        decision=Decision.ESCALATE,
        evidence_span=EvidenceSpan(function_id="f", line_start=1, line_end=2, code="x"),
        source=FindingSource(expression="s", type="NVRAM", attacker_control="UNKNOWN"),
        sink=FindingSink(expression="system(s)", type="COMMAND_EXECUTION"),
        security_condition="c",
        exploitability="e",
        impact="i",
        why_vulnerable="w",
        why_not_false_positive="n",
    )
    return VerificationCandidate(
        global_id="vulnbin#0000::candidate_001",
        chunk_id="vulnbin#0000",
        bin_id="vulnbin",
        finding=finding,
        source_path=None,
        binary_path=binary_path,
    )


def _plan(**overrides) -> StaticPlan:
    defaults = dict(
        target_function="FUN_00026938",
        expected_intermediate_calls=["strcpy", "snprintf"],
        sanitizer_patterns=["escapeshellarg"],
        decisive_observable="obs",
    )
    defaults.update(overrides)
    return StaticPlan(**defaults)


def test_objdump_disassemble_command_shape():
    cmd = objdump_disassemble_command("vulnbin")
    assert cmd.startswith("objdump -d -C")
    assert "vulnbin" in cmd


def test_readelf_dynsym_command_shape():
    cmd = readelf_dynsym_command("vulnbin")
    assert cmd == "readelf --dyn-syms vulnbin"


async def test_static_crosscheck_confirms_expected_calls_present(fake_executor, tmp_path: Path):
    binary_path = tmp_path / "vulnbin"
    binary_path.write_bytes(b"\x7fELF")

    def on_run(command, files):
        return ExecutionResult(
            command=command, returncode=0, stdout=_DISASSEMBLY, stderr="", timed_out=False
        )

    executor = fake_executor(on_run)
    result = await static_crosscheck(
        _candidate(binary_path=binary_path),
        _plan(),
        executor=executor,
        settings=Settings(_env_file=None),
    )

    assert isinstance(result, CrosscheckResult)
    assert result.ok is True
    assert result.calls_confirmed == {"strcpy": True, "snprintf": True}
    assert result.all_expected_calls_confirmed is True
    assert result.sanitizers_found == {"escapeshellarg": False}
    assert result.any_sanitizer_found is False


async def test_static_crosscheck_detects_missing_call(fake_executor, tmp_path: Path):
    binary_path = tmp_path / "vulnbin"
    binary_path.write_bytes(b"\x7fELF")

    def on_run(command, files):
        return ExecutionResult(
            command=command,
            returncode=0,
            stdout="00026938 <FUN_00026938>:\n   26938:       bl      26a30 <system@plt>\n",
            stderr="",
            timed_out=False,
        )

    executor = fake_executor(on_run)
    result = await static_crosscheck(
        _candidate(binary_path=binary_path),
        _plan(),
        executor=executor,
        settings=Settings(_env_file=None),
    )

    assert result.calls_confirmed == {"strcpy": False, "snprintf": False}
    assert result.all_expected_calls_confirmed is False


async def test_static_crosscheck_detects_sanitizer_present(fake_executor, tmp_path: Path):
    binary_path = tmp_path / "vulnbin"
    binary_path.write_bytes(b"\x7fELF")

    disasm_with_sanitizer = _DISASSEMBLY + "   26944:       bl      26a40 <escapeshellarg@plt>\n"

    def on_run(command, files):
        return ExecutionResult(
            command=command, returncode=0, stdout=disasm_with_sanitizer, stderr="", timed_out=False
        )

    executor = fake_executor(on_run)
    result = await static_crosscheck(
        _candidate(binary_path=binary_path),
        _plan(),
        executor=executor,
        settings=Settings(_env_file=None),
    )

    assert result.sanitizers_found == {"escapeshellarg": True}
    assert result.any_sanitizer_found is True


async def test_static_crosscheck_returns_not_ok_when_no_binary_path(tmp_path: Path):
    result = await static_crosscheck(
        _candidate(binary_path=None), _plan(), settings=Settings(_env_file=None)
    )
    assert result.ok is False
    assert result.calls_confirmed == {"strcpy": False, "snprintf": False}
    assert "no binary_path resolved" in result.stderr


async def test_static_crosscheck_returns_not_ok_when_disassembly_fails(
    fake_executor, tmp_path: Path
):
    binary_path = tmp_path / "vulnbin"
    binary_path.write_bytes(b"\x7fELF")

    def on_run(command, files):
        return ExecutionResult(
            command=command,
            returncode=1,
            stdout="",
            stderr="objdump: not an object file",
            timed_out=False,
        )

    executor = fake_executor(on_run)
    result = await static_crosscheck(
        _candidate(binary_path=binary_path),
        _plan(),
        executor=executor,
        settings=Settings(_env_file=None),
    )
    assert result.ok is False


def test_crosscheck_result_to_evidence_dict_shape():
    result = CrosscheckResult(
        ok=True,
        disassembly="x" * 5000,
        calls_confirmed={"strcpy": True},
        sanitizers_found={"escapeshellarg": False},
    )
    evidence = result.to_evidence_dict()
    assert evidence["ok"] is True
    assert evidence["all_expected_calls_confirmed"] is True
    assert evidence["any_sanitizer_found"] is False
    assert len(evidence["disassembly_excerpt"]) == 4000


# --------------------------------------------------------------------- #
# resolve_sink_addresses — T2-F: real sink/PLT-GOT/call-site addresses
# --------------------------------------------------------------------- #


async def test_sink_addr_resolved_to_plt_call_site(fake_executor, tmp_path: Path):
    """T2-F end-to-end: disassemble the real target ELF, resolve the
    relocation table, and find the ACTUAL call-site address of the
    `system` sink inside the target function — never the function's own
    entry point (where `(char*)$a0` would read param_1, never the string
    actually passed to `system()`)."""
    binary_path = tmp_path / "vulnbin"
    binary_path.write_bytes(b"\x7fELF")

    reloc_output = (
        "Relocation section '.rel.plt' at offset 0x2f0 contains 3 entries:\n"
        " Offset     Info    Type            Sym.Value  Sym. Name\n"
        "00026a30  00030016 R_ARM_JUMP_SLOT   00000000   system\n"
    )

    def on_run(command, files):
        if command.startswith("objdump"):
            return ExecutionResult(
                command=command, returncode=0, stdout=_DISASSEMBLY, stderr="", timed_out=False
            )
        if command.startswith("readelf"):
            return ExecutionResult(
                command=command, returncode=0, stdout=reloc_output, stderr="", timed_out=False
            )
        return ExecutionResult(command=command, returncode=0, stdout="", stderr="", timed_out=False)

    executor = fake_executor(on_run)
    result = await resolve_sink_addresses(
        _candidate(binary_path=binary_path),
        target_function="FUN_00026938",
        sink_names=["system", "strcpy"],
        executor=executor,
        settings=Settings(_env_file=None),
    )
    assert result.resolved("system")
    assert result.best_call_site("system") == "0x26940"
    assert result.addresses["system"]["plt_addr"] == "0x00026a30"
    # T2-F: the PLT address alone is NEVER an acceptable breakpoint
    # location — best_call_site must return the CALL-SITE, not the stub.
    assert result.best_call_site("system") != result.addresses["system"]["plt_addr"]


async def test_sink_addr_unresolved_when_sink_not_called_in_target_function(
    fake_executor, tmp_path: Path
):
    """An honest 'unresolved' outcome (never a guess) when the named sink
    doesn't actually appear as a call inside the target function's own
    disassembly slice — this is what lets the dynamic track refuse a
    CONFIRMED verdict built on an unresolved sink (T1-B/T2-F)."""
    binary_path = tmp_path / "vulnbin"
    binary_path.write_bytes(b"\x7fELF")

    def on_run(command, files):
        if command.startswith("objdump"):
            return ExecutionResult(
                command=command, returncode=0, stdout=_DISASSEMBLY, stderr="", timed_out=False
            )
        return ExecutionResult(command=command, returncode=0, stdout="", stderr="", timed_out=False)

    executor = fake_executor(on_run)
    result = await resolve_sink_addresses(
        _candidate(binary_path=binary_path),
        target_function="FUN_00026938",
        sink_names=["never_called_sink"],
        executor=executor,
        settings=Settings(_env_file=None),
    )
    assert result.resolved("never_called_sink") is False
    assert result.best_call_site("never_called_sink") == ""
