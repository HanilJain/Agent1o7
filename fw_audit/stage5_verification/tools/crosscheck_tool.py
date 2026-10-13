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
from fw_audit.stage5_verification.cmdlog import CommandLog
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


def readelf_relocs_command(binary_relpath: str) -> str:
    """T2-F: dump the relocation table (`.rel.plt`/`.rela.plt` for a
    dynamically-linked ELF) — where an imported sink symbol's PLT/GOT
    entry ADDRESS actually lives, which `readelf --dyn-syms` alone does
    not carry (that only gives the symbol's own st_value, typically 0 for
    an UNDEFINED imported symbol)."""
    return f"readelf -r {shlex.quote(binary_relpath)}"


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
    command_log: CommandLog | None = None,
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

    `command_log`, when given, records the `objdump` command + its full
    result to `stage5/fvvw/logs/<gid>.static.jsonl` — previously visible
    only in the LangSmith span (a no-op without `--trace`). `None` (the
    default) behaves exactly as before.
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

    command = objdump_disassemble_command(binary_name)
    async with aspan(
        "stage5.static_crosscheck",
        run_type="tool",
        inputs={"global_id": candidate.global_id, "bin_id": candidate.bin_id},
    ) as run:
        result = await executor.run(
            command,
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

        if command_log is not None:
            command_log.record(
                node="static_crosscheck",
                kind="objdump",
                command=command,
                result=result,
                notes={"calls_confirmed": calls_confirmed, "sanitizers_found": sanitizers_found},
            )

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


# --------------------------------------------------------------------- #
# T2-F: resolve real sink / PLT-GOT / call-site addresses. Deterministic,
# script-based, never LLM-controlled — the same discipline this module's
# own docstring already establishes for `static_crosscheck`. Consumed by
# `fvvw.graph.run_fvvw` to populate/override `DynamicPlan.sink_addr` (and
# guard addrs) with the REAL call-site address of the sink, rather than
# leaving the dynamic track's sink breakpoint to fall back to the
# function's own entry (where `(char*)$a0` reads whatever parameter
# happens to sit in that register at entry — never the actual string
# passed to the sink call).
# --------------------------------------------------------------------- #


class SinkAddressResolution:
    """Plain result object (same "intermediate tool output, not a
    persisted/LLM-facing schema" posture as `CrosscheckResult`) —
    `{sink_name: {"plt_addr": str, "call_site_addr": str}}`-shaped,
    exposed as a typed accessor rather than a bare dict so a caller gets
    `.resolved(sink_name)`/`.best_call_site(sink_name)` instead of
    re-deriving "empty string means unresolved" at every call site."""

    def __init__(self, *, addresses: dict[str, dict[str, str]], stderr: str = "") -> None:
        self.addresses = addresses
        """`{sink_name: {"plt_addr": "0x...", "call_site_addr": "0x..."}}` —
        `plt_addr` is the imported symbol's PLT/GOT stub address (from the
        relocation table); `call_site_addr` is the address, inside the
        TARGET function's own disassembly, of the instruction that CALLS
        that stub — the actual sink breakpoint address. Either may be the
        empty string if that half couldn't be resolved."""
        self.stderr = stderr

    def resolved(self, sink_name: str) -> bool:
        return bool(self.best_call_site(sink_name))

    def best_call_site(self, sink_name: str) -> str:
        """The address to actually set the sink breakpoint at: the real
        CALL-SITE address when resolved (this is what T2-F exists to
        produce), else empty string — deliberately NEVER falls back to
        `plt_addr` alone (a breakpoint on the PLT stub itself, rather than
        the call site inside the target function, would fire for EVERY
        caller of that imported function anywhere in the binary, not just
        the one path this finding claims — a materially different,
        weaker breakpoint location the caller must not silently accept as
        equivalent)."""
        return self.addresses.get(sink_name, {}).get("call_site_addr", "")

    def to_evidence_dict(self) -> dict:
        return {"addresses": self.addresses, "stderr": self.stderr}


_HEX_TOKEN_RE = re.compile(r"^[0-9a-fA-F]+$")
_SYMBOL_TOKEN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*(?:@\S+)?$")

_CALL_MNEMONICS = frozenset({"call", "callq", "bl", "blx", "jal"})
"""Call mnemonics across every arch `QEMU_ARCH_TABLE` supports:
`call`/`callq` (x86, kept for host-tooling parity), `bl`/`blx` (ARM/
Thumb — `blx` for a Thumb<->ARM interworking call), `jal` (MIPS)."""

_CALL_INSN_LINE_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+(?P<rest>.+)$"
)
"""Matches ONE disassembly line's leading address column — `objdump -d`'s
own per-instruction line shape (`  <addr>:\\t<hex bytes>\\t<mnemonic>
<operands>`). Deliberately scoped to a SINGLE line's text (this module
processes `_CALL_INSN_LINE_RE` line-by-line, never with `re.MULTILINE`
across the whole disassembly blob at once) — an earlier version of this
regex spanned multiple lines because `\\s` also matches the newline
between instructions, which silently anchored a call's captured ADDRESS
to a PRECEDING, unrelated line. Line-by-line matching makes that class of
bug structurally impossible: `finditer` is never called against a
multi-line blob for this pattern."""

_CALL_TARGET_RE = re.compile(r"<([^>]+)>\s*$")
"""Matches the trailing `<symbol[+offset]>` objdump annotates a resolved
call target with, once a line has already been confirmed to contain a
call mnemonic — kept as a separate, narrower pattern from
`_CALL_INSN_LINE_RE` so the two concerns (`is this a call line at all`
vs `what does it target`) stay independently readable."""


def _resolve_plt_addresses(reloc_output: str, sink_names: list[str]) -> dict[str, str]:
    """`{sink_name: plt_addr}` from a `readelf -r` relocation table — the
    PLT/GOT slot address for each named sink that appears in the
    relocation table at all (an imported dynamic symbol). A sink not
    present here is either statically linked (no relocation needed — its
    calls resolve directly to a local address, handled entirely by
    `_resolve_call_sites` below) or genuinely absent from this binary.

    Deliberately TOKEN-based rather than one fixed-column regex: `readelf
    -r`'s exact column count/spacing varies across binutils versions and
    relocation types (REL vs RELA carries an extra addend column; some
    reloc types omit Sym.Value entirely) — real firmware toolchains are
    never guaranteed to match one fixed layout. The first HEX token on a
    data row is always the Offset (the PLT/GOT slot address this function
    needs); the LAST token that looks like a symbol name (starts with a
    letter/underscore, never pure hex) is always the Sym.Name column,
    regardless of how many hex-looking columns sit between them."""
    plt_addrs: dict[str, str] = {}
    sink_set = set(sink_names)
    for line in reloc_output.splitlines():
        tokens = line.split()
        if not tokens or not _HEX_TOKEN_RE.match(tokens[0]):
            continue
        offset = tokens[0]
        symbol_token = next(
            (t for t in reversed(tokens[1:]) if _SYMBOL_TOKEN_RE.match(t)), None
        )
        if symbol_token is None:
            continue
        base_symbol = symbol_token.split("@", 1)[0]
        if base_symbol in sink_set and base_symbol not in plt_addrs:
            plt_addrs[base_symbol] = f"0x{offset}"
    return plt_addrs


def _resolve_call_sites(disassembly: str, sink_names: list[str]) -> dict[str, list[str]]:
    """`{sink_name: [call_site_addr, ...]}` — every address, ANYWHERE in
    the supplied disassembly text, of an instruction that calls a symbol
    matching one of `sink_names` (by exact name, or `name@plt` for an
    imported symbol's PLT stub — objdump's own annotation convention).
    Caller passes just the TARGET FUNCTION's own disassembly slice (not
    the whole binary's) so "anywhere" in practice means "anywhere inside
    the one function this finding claims the sink call happens in".

    Processes `disassembly` STRICTLY line by line (never one regex against
    the whole multi-line blob) — see `_CALL_INSN_LINE_RE`'s own docstring
    for the cross-line-capture bug this avoids."""
    call_sites: dict[str, list[str]] = {name: [] for name in sink_names}
    for line in disassembly.splitlines():
        line_match = _CALL_INSN_LINE_RE.match(line)
        if line_match is None:
            continue
        insn_addr = line_match.group(1)
        rest = line_match.group("rest")
        rest_tokens = rest.split()
        if not any(tok.lower().rstrip(":") in _CALL_MNEMONICS for tok in rest_tokens):
            continue
        target_match = _CALL_TARGET_RE.search(rest)
        if target_match is None:
            continue
        target_symbol = target_match.group(1)
        base_symbol = target_symbol.split("@", 1)[0].split("+", 1)[0]
        if base_symbol in call_sites:
            call_sites[base_symbol].append(f"0x{insn_addr}")
    return call_sites


def _extract_function_disassembly(full_disassembly: str, function_name: str) -> str:
    """Slice out just ONE function's disassembly block from `objdump -d`'s
    whole-binary output — objdump prints each function under its own
    `<name>:` header line, so this returns the text from that header up to
    (not including) the NEXT such header, or end of text if this is the
    last function. Falls back to the WHOLE disassembly when the function
    header can't be found (e.g. a stripped binary with no symbol for it,
    or a name mismatch) — resolution then degrades to "match call sites
    anywhere in the binary" rather than failing outright, since a false
    positive here is still bounded by requiring an EXACT sink-name match
    at the call instruction itself."""
    header_re = re.compile(
        rf"^[0-9a-fA-F]+\s*<{re.escape(function_name)}>:\s*$", re.MULTILINE
    )
    match = header_re.search(full_disassembly)
    if match is None:
        return full_disassembly
    next_header = re.search(
        r"^[0-9a-fA-F]+\s*<[^>]+>:\s*$", full_disassembly[match.end() :], re.MULTILINE
    )
    end = match.end() + next_header.start() if next_header is not None else len(full_disassembly)
    return full_disassembly[match.start() : end]


async def resolve_sink_addresses(
    candidate: VerificationCandidate,
    *,
    target_function: str,
    sink_names: list[str],
    executor: Executor | None = None,
    settings: Settings | None = None,
    command_log: CommandLog | None = None,
) -> SinkAddressResolution:
    """T2-F's deterministic sink-address resolver: disassemble the REAL
    target ELF (reusing `objdump_disassemble_command`, the SAME
    disassembly `static_crosscheck` already produces — this function
    re-runs it independently rather than threading a `CrosscheckResult`
    through, since the two calls can run concurrently and neither should
    depend on the other's completion), slice out `target_function`'s own
    disassembly block, and find the CALL-SITE address of each named
    `sink_names` entry inside that block. Falls back to the relocation
    table (`readelf -r`) to resolve a sink's PLT/GOT stub address too,
    for completeness/evidence, even though `SinkAddressResolution.
    best_call_site` never uses the PLT address alone as a breakpoint
    location (see that method's own docstring on why).

    Returns a `SinkAddressResolution` with EMPTY entries (never raises)
    when `candidate.binary_path` is unresolved or the sandbox is
    unreachable — mirrors `static_crosscheck`'s own "purely corroborative,
    never blocks the track" posture. An unresolved sink address is the
    honest, expected outcome for many real binaries (stripped symbols,
    an inlined/optimized-away call, a sink this finding named that
    doesn't actually appear in THIS function) — the caller
    (`fvvw.graph.run_fvvw`) is what turns "never resolved" into "cannot
    honestly confirm" for a CONFIRMED verdict, not this function raising.
    """
    settings = settings or get_settings()
    executor = executor or verification_executor(settings)

    if candidate.binary_path is None or not sink_names:
        return SinkAddressResolution(
            addresses={},
            stderr="no binary_path resolved for this candidate, or no sink_names given — "
            "cannot resolve sink addresses.",
        )

    workspace_dir = candidate.binary_path.parent
    binary_name = candidate.binary_path.name

    async with aspan(
        "stage5.resolve_sink_addresses",
        run_type="tool",
        inputs={
            "global_id": candidate.global_id,
            "bin_id": candidate.bin_id,
            "sink_names": sink_names,
        },
    ) as run:
        disasm_command = objdump_disassemble_command(binary_name)
        disasm_result = await executor.run(
            disasm_command, files=workspace_dir, timeout=settings.stage5_qemu_timeout_seconds
        )
        reloc_command = readelf_relocs_command(binary_name)
        reloc_result = await executor.run(
            reloc_command, files=workspace_dir, timeout=settings.stage5_qemu_timeout_seconds
        )

        if command_log is not None:
            command_log.record(
                node="resolve_sink_addresses", kind="objdump", command=disasm_command,
                result=disasm_result,
            )
            command_log.record(
                node="resolve_sink_addresses", kind="readelf", command=reloc_command,
                result=reloc_result,
            )

        plt_addrs = _resolve_plt_addresses(reloc_result.stdout, sink_names)
        function_slice = _extract_function_disassembly(disasm_result.stdout, target_function)
        call_sites = _resolve_call_sites(function_slice, sink_names)

        addresses: dict[str, dict[str, str]] = {}
        for name in sink_names:
            # The EARLIEST call site inside the target function is the
            # one a straightforward, non-inlined control flow reaches
            # first — a deterministic, reproducible choice rather than an
            # arbitrary "last match wins".
            sites = call_sites.get(name) or []
            addresses[name] = {
                "plt_addr": plt_addrs.get(name, ""),
                "call_site_addr": sites[0] if sites else "",
            }

        if run is not None:
            run.end(outputs={"addresses": addresses})

    return SinkAddressResolution(
        addresses=addresses,
        stderr=(disasm_result.stderr + reloc_result.stderr).strip(),
    )


__all__ = [
    "CrosscheckResult",
    "SinkAddressResolution",
    "objdump_disassemble_command",
    "readelf_dynsym_command",
    "readelf_relocs_command",
    "resolve_sink_addresses",
    "static_crosscheck",
]
