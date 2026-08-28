"""Tests for `stage5_verification.tools.characterize_tool` — Stage 5 FVVW
v3 Phase 2. `detect_pie`/`guess_libc` are pure functions tested directly;
`characterize_target` is tested against constructed `VerificationCandidate`
objects, same style as `tests/test_stage5_binary_target.py`.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from fw_audit.common.findings import (
    Confidence,
    Decision,
    EvidenceSpan,
    Finding,
    FindingSink,
    FindingSource,
    Severity,
)
from fw_audit.common.schemas import ELFArch, ELFInfo, GhidraFunction
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.errors import Stage5InputError
from fw_audit.stage5_verification.tools.characterize_tool import (
    characterize_target,
    detect_pie,
    guess_libc,
)


def _elf_bytes(*, e_type: int, is_little_endian: bool = True, is_64bit: bool = False) -> bytes:
    """Mirrors `tests/conftest.py::synthetic_elf_bytes` exactly (same
    13-field e_type..e_shstrndx layout), parameterized on e_type/endian/
    bitness since `detect_pie`/`characterize_target` need to vary those.
    Fields: e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
    e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
    e_shstrndx — 13 values regardless of 32/64-bit (only e_entry/e_phoff/
    e_shoff widen to Q on 64-bit)."""
    ei_class = 2 if is_64bit else 1
    ei_data = 1 if is_little_endian else 2
    e_ident = b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    endian_prefix = "<" if is_little_endian else ">"
    fmt = endian_prefix + ("HHQQQIHHHHHHH" if is_64bit else "HHIIIIIHHHHHH")
    rest = struct.pack(fmt, e_type, 8, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0)
    return e_ident + rest


def _finding(function_id: str = "FUN_00026938") -> Finding:
    return Finding(
        finding_id="candidate_001",
        title="t",
        category="command_execution",
        severity=Severity(impact=3, exploitability=3, reachability=3),
        confidence=Confidence.MEDIUM,
        decision=Decision.ESCALATE,
        evidence_span=EvidenceSpan(
            function_id=function_id, line_start=1, line_end=2, code="x"
        ),
        source=FindingSource(
            expression="argv[1]", type="FUNCTION_PARAMETER", attacker_control="YES"
        ),
        sink=FindingSink(expression="system(cmd)", type="COMMAND_EXECUTION"),
        security_condition="c",
        exploitability="e",
        impact="i",
        why_vulnerable="w",
        why_not_false_positive="n",
    )


def _candidate(
    *,
    binary_path: Path | None = None,
    rootfs_dir: Path | None = None,
    elf: ELFInfo | None = None,
    functions: tuple[GhidraFunction, ...] = (),
    function_id: str = "FUN_00026938",
) -> VerificationCandidate:
    return VerificationCandidate(
        global_id="vulnbin#0000::candidate_001",
        chunk_id="vulnbin#0000",
        bin_id="vulnbin",
        finding=_finding(function_id=function_id),
        source_path=None,
        binary_path=binary_path,
        rootfs_dir=rootfs_dir,
        elf=elf,
        functions=functions,
    )


# ---------------------------------------------------------------------- #
# detect_pie
# ---------------------------------------------------------------------- #


def test_detect_pie_true_for_et_dyn(tmp_path: Path):
    path = tmp_path / "pie_bin"
    path.write_bytes(_elf_bytes(e_type=3))
    assert detect_pie(path) is True


def test_detect_pie_false_for_et_exec(tmp_path: Path):
    path = tmp_path / "static_bin"
    path.write_bytes(_elf_bytes(e_type=2))
    assert detect_pie(path) is False


def test_detect_pie_none_for_non_elf(tmp_path: Path):
    path = tmp_path / "not_elf"
    path.write_bytes(b"not an elf file at all")
    assert detect_pie(path) is None


def test_detect_pie_none_for_missing_file(tmp_path: Path):
    assert detect_pie(tmp_path / "does_not_exist") is None


def test_detect_pie_works_big_endian_64bit(tmp_path: Path):
    path = tmp_path / "be64_bin"
    path.write_bytes(_elf_bytes(e_type=3, is_little_endian=False, is_64bit=True))
    assert detect_pie(path) is True


# ---------------------------------------------------------------------- #
# guess_libc
# ---------------------------------------------------------------------- #


def test_guess_libc_none_for_static_binary():
    assert guess_libc(None) is None


def test_guess_libc_detects_uclibc():
    assert guess_libc("/lib/ld-uClibc.so.0") == "uClibc"


def test_guess_libc_detects_musl():
    assert guess_libc("/lib/ld-musl-armhf.so.1") == "musl"


def test_guess_libc_detects_glibc():
    assert guess_libc("/lib/ld-linux.so.3") == "glibc"


def test_guess_libc_none_for_unrecognized_interpreter():
    assert guess_libc("/some/weird/loader") is None


# ---------------------------------------------------------------------- #
# characterize_target
# ---------------------------------------------------------------------- #


async def test_characterize_target_seeds_from_stage2_elf_facts(tmp_path: Path):
    binary_path = tmp_path / "vulnbin"
    binary_path.write_bytes(_elf_bytes(e_type=2))
    elf = ELFInfo(
        path="bin/vulnbin",
        absolute_path=str(binary_path),
        size_bytes=100,
        arch=ELFArch.ARM,
        is_64bit=False,
        is_little_endian=True,
        is_stripped=True,
        interpreter="/lib/ld-uClibc.so.0",
    )
    fn = GhidraFunction(
        name="FUN_00026938",
        entry_point="0x00026938",
        size=100,
        signature="void FUN_00026938()",
        called_by=["FUN_00022594"],
    )
    candidate = _candidate(
        binary_path=binary_path, rootfs_dir=tmp_path, elf=elf, functions=(fn,)
    )

    target = await characterize_target(candidate)

    assert target.arch == "arm"
    assert target.endianness == "little"
    assert target.is_64bit is False
    assert target.stripped is True
    assert target.libc == "uClibc"
    assert target.pie is False
    assert target.func_offset == "0x00026938"
    assert target.dispatch_resolvable is True
    assert target.binary_path == str(binary_path)
    assert target.rootfs_dir == str(tmp_path)


async def test_characterize_target_raises_on_unresolvable_function_offset(tmp_path: Path):
    binary_path = tmp_path / "vulnbin"
    binary_path.write_bytes(_elf_bytes(e_type=2))
    fn = GhidraFunction(
        name="FUN_deadbeef", entry_point="0xdeadbeef", size=10, signature="void f()"
    )
    candidate = _candidate(
        binary_path=binary_path,
        functions=(fn,),
        function_id="FUN_00026938",  # does not match the only known function
    )

    with pytest.raises(Stage5InputError, match="target mismatch"):
        await characterize_target(candidate)


async def test_characterize_target_degrades_gracefully_with_no_functions_known(tmp_path: Path):
    """No function table at all (Stage 2 never populated it) must NOT raise
    — only a genuine mismatch against a KNOWN table raises."""
    candidate = _candidate(binary_path=None, functions=())
    target = await characterize_target(candidate)
    assert target.func_offset == ""
    assert target.dispatch_resolvable is False


async def test_characterize_target_dispatch_not_resolvable_for_thunk():
    fn = GhidraFunction(
        name="FUN_00026938",
        entry_point="0x00026938",
        size=10,
        signature="void f()",
        called_by=["FUN_1"],
        is_thunk=True,
    )
    candidate = _candidate(functions=(fn,))
    target = await characterize_target(candidate)
    assert target.dispatch_resolvable is False


async def test_characterize_target_dispatch_not_resolvable_with_no_callers():
    fn = GhidraFunction(
        name="FUN_00026938", entry_point="0x00026938", size=10, signature="void f()", called_by=[]
    )
    candidate = _candidate(functions=(fn,))
    target = await characterize_target(candidate)
    assert target.dispatch_resolvable is False


async def test_characterize_target_matches_function_by_substring_of_entry_point():
    """A finding may record a raw address instead of a decompiler name —
    fall back to substring-matching against entry_point."""
    fn = GhidraFunction(
        name="some_other_name",
        entry_point="0x00026938",
        size=10,
        signature="void f()",
        called_by=["caller"],
    )
    candidate = _candidate(functions=(fn,), function_id="0x00026938")
    target = await characterize_target(candidate)
    assert target.func_offset == "0x00026938"


async def test_characterize_target_handles_missing_elf_info():
    candidate = _candidate(elf=None)
    target = await characterize_target(candidate)
    assert target.arch == "unknown"
    assert target.endianness == ""
    assert target.stripped is None
