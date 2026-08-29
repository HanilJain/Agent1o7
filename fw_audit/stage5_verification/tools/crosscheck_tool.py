"""`static_crosscheck`'s tool primitives (FVVW v3 §6 node 7) — a
sandboxed (`objdump`/`readelf`), pattern-search corroboration for the
existing Joern static track, NOT a replacement for it.

Runs against the REAL target ELF (`VerificationCandidate.binary_path`),
not the decompiled `whole.c` the Joern track works from — a genuinely
independent signal source. Disassembles the target function, then
(script-based, no LLM by default) confirms each `StaticPlan.
expected_intermediate_calls` is actually present in the disassembly
(recording where), and confirms the absence of every
`StaticPlan.sanitizer_pattern` across the whole function body. This is
what lets an inconclusive/empty Joern taint-flow (a common decompiler-
fidelity failure mode) be reported as "inconclusive but calls
independently confirmed present" rather than a bare tool failure — see
`joern_evaluate`'s rule 3 in the design doc for the taxonomy this feeds.

Command composition lives entirely here (never LLM-controlled), same
discipline as `tools/joern_tool.py` — the strategy agent only supplies
`StaticPlan.expected_intermediate_calls`/`sanitizer_patterns` as data; it
never constructs the `objdump`/`readelf` invocation itself.
"""

from __future__ import annotations

import re
import shlex

from fw_audit.common.verification import StaticPlan
from fw_audit.config.settings import Settings, get_settings
from fw_audit.executors.base import Executor
from fw_audit.observability import aspan
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.tools.verification_sandbox import verification_executor

CROSSCHECK_CONTAINER_WORKDIR = "/work"


def objdump_disassemble_command(binary_relpath: str) -> str:
    """Disassemble `binary_relpath` (relative to the bind-mounted workspace)
    with symbol names where available — `-d` (disassemble executable
    sections) `-C` (demangle, harmless no-op for C) `--no-show-raw-insn`
    (readable output, no hex bytes cluttering the pattern search)."""
    return f"objdump -d -C --no-show-raw-insn {shlex.quote(binary_relpath)}"


def readelf_dynsym_command(binary_relpath: str) -> str:
    """Dump the dynamic symbol table — the cross-check falls back to this
    when a call target in the disassembly is a PLT stub (`call <sym@plt>`)
    rather than a resolved name, common for dynamically-linked firmware
    binaries with partial/no debug info."""
    return f"readelf --dyn-syms {shlex.quote(binary_relpath)}"


class CrosscheckResult:
    """Plain result object (not a pydantic model — this is intermediate
    tool output, not a persisted/LLM-facing schema; `fvvw.static_track`/
    `fvvw.joint` fold the fields that matter into `TrackResult.evidence`
    and `mem.joint.residual_unknowns`)."""

    def __init__(
        self,
        *,
        ok: bool,
        disassembly: str,
        calls_confirmed: dict[str, bool],
        sanitizers_found: dict[str, bool],
        stderr: str = "",
    ) -> None:
        self.ok = ok
        self.disassembly = disassembly
        self.calls_confirmed = calls_confirmed
        """`{expected_call_name: found_in_disassembly}` — see
        `StaticPlan.expected_intermediate_calls`."""
        self.sanitizers_found = sanitizers_found
        """`{sanitizer_pattern: found_in_disassembly}` — see
        `StaticPlan.sanitizer_patterns`. ANY `True` value here is a strong
        signal toward REFUTED (a sanitizer/allow-list check exists on the
        path), per `joern_evaluate`'s rule 5."""
        self.stderr = stderr

    @property
    def all_expected_calls_confirmed(self) -> bool:
        return bool(self.calls_confirmed) and all(self.calls_confirmed.values())

    @property
    def any_sanitizer_found(self) -> bool:
        return any(self.sanitizers_found.values())

    def to_evidence_dict(self) -> dict:
        return {
            "ok": self.ok,
            "calls_confirmed": self.calls_confirmed,
            "sanitizers_found": self.sanitizers_found,
            "all_expected_calls_confirmed": self.all_expected_calls_confirmed,
            "any_sanitizer_found": self.any_sanitizer_found,
            "disassembly_excerpt": self.disassembly[:4000],
            "stderr": self.stderr,
        }


def _search_disassembly(disassembly: str, pattern: str) -> bool:
    """Case-insensitive substring/regex-lite search — `pattern` is treated
    as a plain substring first (the common case: a function name like
    `strcpy`), falling back to a regex search if the literal substring
    isn't found and the pattern looks like it might be one (contains
    regex metacharacters). Never raises on an invalid regex — a bad
    pattern just degrades to "not found" rather than crashing the whole
    cross-check."""
    if not pattern:
        return False
    if pattern.lower() in disassembly.lower():
        return True
    try:
        return re.search(pattern, disassembly, re.IGNORECASE) is not None
    except re.error:
        return False


async def static_crosscheck(
    candidate: VerificationCandidate,
    plan: StaticPlan,
    *,
    executor: Executor | None = None,
    settings: Settings | None = None,
) -> CrosscheckResult:
    """Disassemble `candidate.binary_path` and confirm/refute
    `plan.expected_intermediate_calls`/`plan.sanitizer_patterns` against it.

    Runs unconditionally when `plan.crosscheck_required` is True (the
    caller — `fvvw.static_track`/`fvvw.graph` — decides whether to call
    this at all; this function itself always runs when invoked). Returns
    a `CrosscheckResult` with `ok=False` (never raises) if
    `candidate.binary_path` is unresolved or the sandbox is unreachable —
    the static track's Joern half is unaffected either way, this is purely
    corroborative.
    """
    settings = settings or get_settings()
    executor = executor or verification_executor(settings)

    if candidate.binary_path is None:
        return CrosscheckResult(
            ok=False,
            disassembly="",
            calls_confirmed=dict.fromkeys(plan.expected_intermediate_calls, False),
            sanitizers_found=dict.fromkeys(plan.sanitizer_patterns, False),
            stderr="no binary_path resolved for this candidate — cannot disassemble.",
        )

    workspace_dir = candidate.binary_path.parent
    binary_name = candidate.binary_path.name

    async with aspan(
        "stage5.static_crosscheck",
        run_type="tool",
        inputs={"global_id": candidate.global_id, "bin_id": candidate.bin_id},
    ) as run:
        result = await executor.run(
            objdump_disassemble_command(binary_name),
            files=workspace_dir,
            timeout=settings.stage5_qemu_timeout_seconds,
        )
        disassembly = result.stdout
        ok = result.ok and bool(disassembly.strip())

        calls_confirmed = {
            call: _search_disassembly(disassembly, call)
            for call in plan.expected_intermediate_calls
        }
        sanitizers_found = {
            pattern: _search_disassembly(disassembly, pattern)
            for pattern in plan.sanitizer_patterns
        }

        if run is not None:
            run.end(
                outputs={
                    "ok": ok,
                    "calls_confirmed": calls_confirmed,
                    "sanitizers_found": sanitizers_found,
                }
            )

    return CrosscheckResult(
        ok=ok,
        disassembly=disassembly,
        calls_confirmed=calls_confirmed,
        sanitizers_found=sanitizers_found,
        stderr=result.stderr,
    )


__all__ = [
    "CrosscheckResult",
    "objdump_disassemble_command",
    "readelf_dynsym_command",
    "static_crosscheck",
]
