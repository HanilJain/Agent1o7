"""`characterize_target`'s tool primitives (FVVW v3 §6 node 2) — resolves
`mem.target.*` for one `VerificationCandidate`.

Deliberately CHEAP: almost every fact `TargetMeta` needs was already
computed by Stage 2 (`DecompiledBinary.elf`, `.functions`) — this module
seeds from that and only does real work for the two things Stage 2's
`common.schemas.ELFInfo` does NOT carry:

  1. **PIE** (position-independent executable, ET_DYN vs ET_EXEC) — no
     field for it anywhere in `ELFInfo`. Computed here with a small,
     dependency-free ELF-header read (`_read_elf_type`), deliberately
     mirroring `stage1_ingestion.tools.filesystem_tools.parse_elf_header`'s
     "no external tools required" approach rather than shelling out to
     `readelf` in the sandbox for one field this cheap to read directly —
     see that module for the precedent this follows. Reading only the
     16-byte `e_ident` + 2-byte `e_type` (never the full header Stage 1
     already parsed) keeps this a few dozen bytes of I/O, not a re-parse.
  2. **Function-offset validation** — cross-checks the finding's claimed
     `evidence_span.function_id` against `VerificationCandidate.functions`
     (Stage 2's `GhidraFunction` list) to confirm the address still
     resolves in the real binary, the way the design doc's
     `characterize_target` node requires ("claimed offset doesn't resolve
     in the real binary -> halt this claim with a 'target mismatch'
     error").
  3. **`dispatch_resolvable`** — best-effort: is there a statically
     resolvable caller into the target function at all (`GhidraFunction.
     called_by` non-empty)? Feeds `DynamicPlan.reach_strategy`'s
     natural_drive vs inferior_call choice (via the strategy agent).
  4. **`libc`** — best-effort flavor guess from `ELFInfo.interpreter`'s
     path (e.g. `ld-uClibc`, `ld-musl`, `ld-linux`).

No Docker/sandbox call is needed for any of this — everything above reads
only the already-resolved local host file
(`VerificationCandidate.binary_path`) and in-memory Stage 2 facts. This
module still exposes the `characterize_target` node as `async` (matching
every other FVVW node's shape) even though the work is synchronous.
"""

from __future__ import annotations

import struct
from pathlib import Path

from fw_audit.common.schemas import GhidraFunction
from fw_audit.common.verification import TargetMeta
from fw_audit.observability import aspan
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.errors import Stage5InputError

_ELF_MAGIC = b"\x7fELF"
_EI_CLASS = 4
_EI_DATA = 5
# ELF e_type values (first field after the 16-byte e_ident).
_ET_EXEC = 2
_ET_DYN = 3

_LIBC_MARKERS: tuple[tuple[str, str], ...] = (
    ("uclibc", "uClibc"),
    ("musl", "musl"),
    ("ld-linux", "glibc"),
    ("ld.so", "glibc"),
)


def _read_elf_type(path: Path) -> int | None:
    """Read just `e_type` (offset 16, 2 bytes) from an ELF file — enough to
    distinguish ET_EXEC (2, non-PIE) from ET_DYN (3, PIE/shared object).
    Returns `None` if the file isn't a well-formed-enough ELF to read this
    far (never raises — same "describe what's there, don't judge" posture
    as `filesystem_tools.parse_elf_header`, except this returns `None`
    instead of raising, since callers here treat "undetermined" as a normal
    outcome, not an error worth surfacing)."""
    try:
        with path.open("rb") as f:
            e_ident = f.read(16)
            if len(e_ident) < 16 or e_ident[:4] != _ELF_MAGIC:
                return None
            is_little_endian = e_ident[_EI_DATA] == 1
            raw_type = f.read(2)
            if len(raw_type) < 2:
                return None
            fmt = "<H" if is_little_endian else ">H"
            return struct.unpack(fmt, raw_type)[0]
    except OSError:
        return None


def detect_pie(binary_path: Path) -> bool | None:
    """`True` if the ELF is ET_DYN (PIE or a shared object), `False` if
    ET_EXEC (fixed-base, non-PIE), `None` if undetermined. Non-PIE means
    decompiler addresses map 1:1 to runtime addresses; PIE means every
    address needs rebasing against the runtime load base — this is exactly
    the fact `bringup_stabilize`/`reach_target` need to decide whether a
    GDB breakpoint address needs a load-base offset added."""
    e_type = _read_elf_type(binary_path)
    if e_type == _ET_DYN:
        return True
    if e_type == _ET_EXEC:
        return False
    return None


def guess_libc(interpreter: str | None) -> str | None:
    """Best-effort libc flavor from the PT_INTERP dynamic-linker path —
    `None` for a statically-linked binary (`interpreter is None`) or an
    interpreter path that doesn't match a known marker."""
    if not interpreter:
        return None
    lowered = interpreter.lower()
    for marker, label in _LIBC_MARKERS:
        if marker in lowered:
            return label
    return None


def _find_function(
    functions: tuple[GhidraFunction, ...], function_id: str
) -> GhidraFunction | None:
    """`function_id` (from `Finding.evidence_span.function_id`) is a
    decompiler-derived name (e.g. `FUN_00026938`) — match by name first
    (the common case), falling back to a substring match against
    `entry_point` in case the finding instead recorded a raw address."""
    for fn in functions:
        if fn.name == function_id:
            return fn
    for fn in functions:
        if function_id and function_id in fn.entry_point:
            return fn
    return None


# --------------------------------------------------------------------- #
# T2-G: daemon / startup-reachability signal. Deliberately CHEAP (a string
# scan over Stage 2's already-computed GhidraFunction.calls table — no
# sandbox call, no new decompilation) — the same "seed from what Stage 2
# already computed" posture this whole module follows for every other
# fact. Best-effort by design: a false negative here just means
# `plan_emulation` falls back to its existing guard-name heuristic; a
# false positive just means a strategy prefers direct_call slightly more
# often than strictly necessary — neither can produce an incorrect
# VERDICT, since Tier 1's positive-evidence gates are what actually decide
# CONFIRMED, independent of which reach strategy was tried.
# --------------------------------------------------------------------- #

_DAEMON_CALL_MARKERS: tuple[str, ...] = ("daemon", "fork", "setsid", "openlog", "daemonize")
"""Call names that, on a self-contained Linux/embedded C daemon, are the
standard way a process detaches into the background and announces itself
as a long-running service — see `daemon(3)`/`fork(2)`/`setsid(2)`/
`openlog(3)`'s own man pages. A match against `GhidraFunction.calls` (a
plain list of called-symbol NAMES Stage 2 already resolved) is
necessarily best-effort: a statically-linked or PLT-stub-only call table
may not carry every libc symbol by its familiar name, so absence here is
never treated as proof the target ISN'T a daemon — only presence is
treated as a positive signal."""

_CONFIG_PARSE_MARKERS: tuple[str, ...] = (
    "fopen",
    "getconfig",
    "config_read",
    "parseconfig",
    "parse_config",
    "readconfig",
    "read_config",
    "nvram_get",
)
"""Call names suggesting a mandatory config-file/NVRAM read near `main` —
the concrete "hard startup dependency" half of `startup_reachable=False`'s
definition (daemon-ness ALONE is not enough; plenty of daemons run fine
with no config file present at all under partial emulation)."""


def detect_daemon_signal(functions: tuple[GhidraFunction, ...]) -> tuple[bool, bool | None]:
    """Returns `(is_daemon, startup_reachable)` — T2-G's deterministic,
    dependency-free scan over Stage 2's already-computed function/call
    table (`VerificationCandidate.functions`), no sandbox/readelf call
    needed.

    `is_daemon`: any function's `calls` list contains one of
    `_DAEMON_CALL_MARKERS`.

    `startup_reachable`: `None` (undetermined — the common, "nothing
    suspicious" case) unless `is_daemon` is `True` AND at least one
    function ALSO calls something in `_CONFIG_PARSE_MARKERS` — that
    combination (daemonizes AND reads a config/NVRAM value somewhere) is
    the concrete "mandatory config-file parser near main" signal the plan
    calls for; in that case `startup_reachable=False` (the plan's own
    "PLUS an apparent hard startup dependency" qualifier — daemon-ness
    alone never sets this False, since a daemon with no config dependency
    may well start fine under partial emulation).
    """
    is_daemon = False
    has_config_dependency = False
    for fn in functions:
        calls_lower = [c.lower() for c in fn.calls]
        if not is_daemon and any(
            any(marker in call for marker in _DAEMON_CALL_MARKERS) for call in calls_lower
        ):
            is_daemon = True
        if not has_config_dependency and any(
            any(marker in call for marker in _CONFIG_PARSE_MARKERS) for call in calls_lower
        ):
            has_config_dependency = True
        if is_daemon and has_config_dependency:
            break
    startup_reachable = False if (is_daemon and has_config_dependency) else None
    return is_daemon, startup_reachable


async def characterize_target(candidate: VerificationCandidate) -> TargetMeta:
    """Build `mem.target` for one candidate — the `characterize_target`
    node's actual work, factored out from any LangGraph node wrapper so
    `debug.py`/tests can call it directly (same "bypass the LLM/graph
    machinery" precedent as `joern_tool.build_cpg_async`).

    Raises `Stage5InputError` — NOT a soft `TargetMeta` with empty fields —
    when the finding's claimed function offset does not resolve against the
    real binary's function table, per the design doc: "claimed offset
    doesn't resolve in the real binary -> halt this claim with a 'target
    mismatch' error rather than analyzing the wrong address." This is
    distinct from simply having NO function table at all (e.g.
    `candidate.binary_path is None`, so nothing can be cross-checked) —
    that degrades gracefully to `dispatch_resolvable=False` and an empty
    `func_offset`, since a hard failure there would block the static track
    too, which doesn't need `mem.target` to be complete.
    """
    elf = candidate.elf
    arch = elf.arch.value if elf is not None else "unknown"
    if elf is None or elf.is_little_endian is None:
        endianness = ""
    else:
        endianness = "little" if elf.is_little_endian else "big"
    is_64bit = elf.is_64bit if elf is not None else None
    stripped = elf.is_stripped if elf is not None else None
    libc = guess_libc(elf.interpreter if elf is not None else None)

    pie: bool | None = None
    async with aspan(
        "stage5.characterize_target",
        run_type="tool",
        inputs={"global_id": candidate.global_id, "bin_id": candidate.bin_id},
    ) as run:
        if candidate.binary_path is not None:
            pie = detect_pie(candidate.binary_path)

        func_offset = ""
        dispatch_resolvable = False
        function_id = candidate.finding.evidence_span.function_id
        if candidate.functions:
            resolved_fn = _find_function(candidate.functions, function_id)
            if resolved_fn is None:
                raise Stage5InputError(
                    f"{candidate.global_id}: claimed function_id={function_id!r} does not "
                    f"resolve against bin_id={candidate.bin_id}'s real function table "
                    f"({len(candidate.functions)} functions known) — target mismatch."
                )
            func_offset = resolved_fn.entry_point
            dispatch_resolvable = bool(resolved_fn.called_by) and not resolved_fn.is_thunk

        # T2-G: cheap, dependency-free daemon/startup-reachability signal
        # — scans the SAME already-computed function/call table above, no
        # extra sandbox call.
        is_daemon, startup_reachable = detect_daemon_signal(candidate.functions)

        if run is not None:
            run.end(
                outputs={
                    "arch": arch,
                    "pie": pie,
                    "func_offset": func_offset,
                    "dispatch_resolvable": dispatch_resolvable,
                    "is_daemon": is_daemon,
                    "startup_reachable": startup_reachable,
                }
            )

    return TargetMeta(
        arch=arch,
        endianness=endianness,
        is_64bit=is_64bit,
        pie=pie,
        stripped=stripped,
        libc=libc,
        func_offset=func_offset,
        dispatch_resolvable=dispatch_resolvable,
        binary_path=str(candidate.binary_path) if candidate.binary_path else "",
        rootfs_dir=str(candidate.rootfs_dir) if candidate.rootfs_dir else "",
        is_daemon=is_daemon,
        startup_reachable=startup_reachable,
    )


__all__ = ["characterize_target", "detect_daemon_signal", "detect_pie", "guess_libc"]
