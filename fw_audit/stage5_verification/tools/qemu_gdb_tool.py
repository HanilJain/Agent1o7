"""QEMU+GDB command-composition primitives for the dynamic-verification
track (FVVW v3 §7-§8) — owns EVERY `qemu-*`/`gdb-multiarch` invocation the
dynamic track's nodes (`fvvw.dynamic_track`) run. Command composition lives
entirely here, never LLM-controlled: the strategy agent supplies only
`DynamicPlan` DATA (addresses, guard names/forced-values, the benign
payload marker) — never a shell command string — mirroring the exact
discipline `tools/joern_tool.py` already established for the static track
("the generator LLM never constructs the underlying docker run/joern-parse/
joern --script command line — only the script BODY").

Full multi-arch build (per the confirmed implementation direction): the
complete arch -> QEMU-binary mapping (user AND system mode) and the
argument-register map for every supported architecture, not a single-arch
placeholder.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from fw_audit.common.verification import GDB_FORCED_VALUE_RE

CONTAINER_WORKDIR = "/work"

CONTAINER_SCRATCH = "/tmp/fvvw"
"""Where GDB recipes and the QEMU stdout/stderr log are written — deliberately
OUTSIDE `CONTAINER_WORKDIR`, which is a bind mount of `candidate.rootfs_dir`
(the extracted firmware filesystem itself, see `dynamic_track._workspace_dir_for`).
Writing recipes/logs under `CONTAINER_WORKDIR` would pollute the extracted
firmware with `recipe_*.gdb`/`.fvvw_qemu.log` files that are never cleaned up
and would still be present on a later re-run. Both the shell redirect (`>
{CONTAINER_SCRATCH}/...`) and the `gdb-multiarch` invocation are evaluated by
the OUTER container shell, never inside the `chroot` `bringup_stabilize`
issues for the emulated process itself, so this absolute container-local path
resolves correctly regardless of whether the target is chrooted. No copy-out
step is needed: the recipe text and every stdout/stderr this produces are
captured verbatim in the host-side `cmdlog.CommandLog` JSONL instead."""


@dataclass(frozen=True)
class QemuArchSpec:
    """One architecture's QEMU binaries + calling-convention facts — the
    doc's §8 arch table, expressed as data rather than a chain of
    `if arch == ...` branches, so a new arch is one dict entry, not a new
    code path."""

    user_binary: str
    """`qemu-<arch>` — user-mode emulation binary (chroot + one process)."""
    system_binary: str
    """`qemu-system-<arch>` — full-kernel-boot emulation binary, for
    `plan_emulation`'s system-mode path (guards/reach requiring live
    kernel/NVRAM/IPC)."""
    arg_registers: tuple[str, ...]
    """GDB register names for the first N integer/pointer arguments, in
    calling-convention order — read by `instrument_trigger` to capture the
    sink call's actual argument value."""
    cpu_probe_env: dict[str, str]
    """Known CPU-feature-probe environment-variable fixes
    (`bringup_stabilize`'s repair catalog) — e.g. the ARM `libcrypto`
    SIGILL-during-CRT-init fix. Empty dict if this arch has no known
    quirk."""


# The full FVVW v3 §8 arch table. Keyed on (arch, endianness) since
# `common.schemas.ELFArch` doesn't itself distinguish endianness variants
# (armeb vs arm, mipsel vs mips) — `TargetMeta.arch`/`TargetMeta.endianness`
# together are what this table is actually looked up against (see
# `resolve_qemu_arch_spec` below).
QEMU_ARCH_TABLE: dict[tuple[str, str], QemuArchSpec] = {
    ("arm", "little"): QemuArchSpec(
        user_binary="qemu-arm",
        system_binary="qemu-system-arm",
        arg_registers=("$r0", "$r1", "$r2", "$r3"),
        cpu_probe_env={"OPENSSL_armcap": "0"},
    ),
    ("arm", "big"): QemuArchSpec(
        user_binary="qemu-armeb",
        system_binary="qemu-system-arm",
        arg_registers=("$r0", "$r1", "$r2", "$r3"),
        cpu_probe_env={"OPENSSL_armcap": "0"},
    ),
    ("aarch64", "little"): QemuArchSpec(
        user_binary="qemu-aarch64",
        system_binary="qemu-system-aarch64",
        arg_registers=("$x0", "$x1", "$x2", "$x3", "$x4", "$x5", "$x6", "$x7"),
        cpu_probe_env={},
    ),
    ("aarch64", "big"): QemuArchSpec(
        user_binary="qemu-aarch64_be",
        system_binary="qemu-system-aarch64",
        arg_registers=("$x0", "$x1", "$x2", "$x3", "$x4", "$x5", "$x6", "$x7"),
        cpu_probe_env={},
    ),
    ("mips", "big"): QemuArchSpec(
        user_binary="qemu-mips",
        system_binary="qemu-system-mips",
        arg_registers=("$a0", "$a1", "$a2", "$a3"),
        cpu_probe_env={},
    ),
    ("mips", "little"): QemuArchSpec(
        user_binary="qemu-mipsel",
        system_binary="qemu-system-mipsel",
        arg_registers=("$a0", "$a1", "$a2", "$a3"),
        cpu_probe_env={},
    ),
    # mips64/mips64el and ppc/ppc64 share the plain "mips"/"unknown"-style
    # ELFArch bucket in this repo's schema (no dedicated ELFArch member) —
    # entries kept here keyed on the string a future characterize_target
    # refinement could emit, so adding real 64-bit-MIPS/PPC detection later
    # is a schema+lookup change, not a new arch-table shape.
    ("mips64", "big"): QemuArchSpec(
        user_binary="qemu-mips64",
        system_binary="qemu-system-mips64",
        arg_registers=("$a0", "$a1", "$a2", "$a3"),
        cpu_probe_env={},
    ),
    ("mips64", "little"): QemuArchSpec(
        user_binary="qemu-mips64el",
        system_binary="qemu-system-mips64",
        arg_registers=("$a0", "$a1", "$a2", "$a3"),
        cpu_probe_env={},
    ),
    ("ppc", "big"): QemuArchSpec(
        user_binary="qemu-ppc",
        system_binary="qemu-system-ppc",
        arg_registers=("$r3", "$r4", "$r5", "$r6"),
        cpu_probe_env={},
    ),
    ("ppc64", "big"): QemuArchSpec(
        user_binary="qemu-ppc64",
        system_binary="qemu-system-ppc",
        arg_registers=("$r3", "$r4", "$r5", "$r6"),
        cpu_probe_env={},
    ),
}


def resolve_qemu_arch_spec(arch: str, endianness: str) -> QemuArchSpec | None:
    """Look up `QEMU_ARCH_TABLE`, returning `None` for an unsupported
    combination — the caller (`plan_emulation`) treats `None` as hard
    infeasibility (`dynamic_runnable=False`), per the design doc's "false
    ONLY for hard infeasibility, e.g. no QEMU support for the arch"."""
    return QEMU_ARCH_TABLE.get((arch, endianness))


def gdb_binary() -> str:
    """The ONE GDB binary every dynamic session drives, regardless of
    target architecture — `gdb-multiarch`, never a native single-arch
    `gdb` (targets are cross-architecture)."""
    return "gdb-multiarch"


def build_qemu_user_launch_command(
    *,
    arch_spec: QemuArchSpec,
    target_relpath: str,
    argv: list[str] | None = None,
    rootfs_relpath: str | None = None,
    gdb_port: int = 1234,
    qemu_binary_in_chroot: str | None = None,
) -> str:
    """Assemble the exact user-mode QEMU launch command
    (`bringup_stabilize`'s job per the design doc), in order: chroot prefix
    (if `rootfs_relpath` is given — the target resolves paths relative to
    its own rootfs, as `/sbin/rc`-style dispatcher binaries do), the
    CPU-probe environment-variable fixes (`arch_spec.cpu_probe_env`), the
    QEMU user-mode binary, the GDB stub flag `-g <port>`, the library/
    sysroot path `-L <rootfs>`, then the target path and any argv.

    All paths are relative to the bind-mounted session workspace
    (`CONTAINER_WORKDIR`) — this function never sees or needs a host path.

    When chrooting (`rootfs_relpath` given), the QEMU emulator binary must
    exist INSIDE the rootfs to be reachable after `chroot`, and the `-L`
    sysroot resolves against the POST-chroot root (`/`), not the pre-chroot
    path. The caller (`bringup_stabilize`) stages a static QEMU binary into
    the rootfs and passes its absolute-in-chroot path as
    `qemu_binary_in_chroot` (e.g. `/qemu-mips`); `-L /` then points QEMU at
    the (now-root) rootfs for library resolution. Without a chroot
    (`rootfs_relpath is None`), the container's own `qemu-<arch>` on PATH is
    used and no `-L` is emitted."""
    if rootfs_relpath and not qemu_binary_in_chroot:
        raise ValueError(
            "qemu_binary_in_chroot is required when rootfs_relpath is set: after "
            "chroot the container's qemu-<arch> is unreachable, so the caller must "
            "stage a static QEMU binary into the rootfs and pass its in-chroot path."
        )
    parts: list[str] = []
    if rootfs_relpath:
        parts += ["chroot", shlex.quote(rootfs_relpath)]
    for key, value in arch_spec.cpu_probe_env.items():
        parts.append(f"{key}={shlex.quote(value)}")
    # After chroot, the container's /usr/bin/qemu-<arch> is no longer
    # reachable — use the copy the caller staged inside the rootfs.
    parts.append(shlex.quote(qemu_binary_in_chroot) if rootfs_relpath else arch_spec.user_binary)
    parts += ["-g", str(gdb_port)]
    if rootfs_relpath:
        # Post-chroot, the rootfs IS `/`, so that's the sysroot for -L.
        parts += ["-L", "/"]
    parts.append(shlex.quote(target_relpath))
    if argv:
        parts += [shlex.quote(a) for a in argv]
    return " ".join(parts)


def build_qemu_system_launch_command(
    *,
    arch_spec: QemuArchSpec,
    kernel_relpath: str,
    rootfs_image_relpath: str,
    extra_args: list[str] | None = None,
    gdb_port: int = 1234,
) -> str:
    """Assemble a full-kernel-boot QEMU launch command for
    `plan_emulation`'s system-mode path — used when a guard/reach path
    requires a live kernel/NVRAM/IPC rather than a self-contained
    dispatcher binary. Deliberately minimal (kernel + root filesystem image
    + GDB stub) since the exact machine/network/device flags a given
    firmware's system-mode boot needs are firmware-specific;
    `bringup_stabilize`'s repair catalog is where those get filled in via
    `extra_args` as they're discovered, without this function's own shape
    changing."""
    parts = [
        arch_spec.system_binary,
        "-kernel",
        shlex.quote(kernel_relpath),
        "-drive",
        f"file={shlex.quote(rootfs_image_relpath)},format=raw",
        "-gdb",
        f"tcp::{gdb_port}",
        "-S",  # start halted, so GDB always attaches before any code runs
        "-nographic",
    ]
    if extra_args:
        parts += extra_args
    return " ".join(parts)


def build_gdb_batch_command(recipe_relpath: str, target_relpath: str) -> str:
    """`gdb-multiarch -batch -x <recipe> <target>` — runs a pre-written GDB
    command file non-interactively against the target binary (loaded for
    its symbols/sections), then connects to the QEMU stub the recipe itself
    issues `target remote localhost:<port>` for (see
    `render_gdb_recipe`). One call per `reach_target`/`satisfy_guards`/
    `instrument_trigger`/`collect_signals` node, executed via
    `SandboxExecutor.exec_in_session()` against the SAME running session
    container QEMU was started in — never `run()`, since the emulated
    process must stay alive between these calls."""
    return f"{gdb_binary()} -batch -x {shlex.quote(recipe_relpath)} {shlex.quote(target_relpath)}"


def normalize_hex_addr(addr: str) -> str:
    """Normalize a code address to the `0x`-prefixed hex form GDB requires
    for `break *<addr>`. Ghidra/Stage 2 emit bare hex (`00400900`), and a
    strategy agent may echo that verbatim — GDB rejects a bare-hex operand
    to `break *` with `Invalid number "00400900"`, since without `0x` it is
    parsed as decimal and `0x`-less hex digits like `f` are invalid. Accept
    both forms (already-prefixed passes through untouched) and leave a
    genuinely symbolic operand (e.g. `main`, `*fn+4`) alone."""
    a = addr.strip()
    if a.lower().startswith("0x"):
        return a
    # Bare hex (only 0-9a-f) -> prefix it; anything else is symbolic, leave it.
    if a and all(c in "0123456789abcdefABCDEF" for c in a):
        return f"0x{a}"
    return a


def render_gdb_recipe(
    *,
    architecture: str,
    gdb_port: int,
    entry_addr: str,
    breakpoint_commands: list[str],
) -> str:
    """Render the shared GDB-recipe preamble (connect + pagination/confirm
    settings + break at the functional entry) followed by
    `breakpoint_commands` — the caller-supplied per-node body (guard
    forcing, trigger instrumentation, signal capture). This is the ONE
    place the `target remote`/`set architecture`/`set pagination off`/
    `set confirm off` boilerplate FVVW §7's recipe describes lives, so
    every dynamic-track node's recipe shares it instead of re-deriving it.

    Raises `ValueError` if `entry_addr` is empty/unresolved — an unresolved
    functional entry is a genuine bring-up/plan fault (there is nothing to
    break at), not something to paper over by emitting a bare `break *`,
    which GDB rejects with "Argument required (expression to compute)" and
    aborts the ENTIRE batch script at that line — silently skipping every
    breakpoint_commands entry after it too. Callers (`fvvw.dynamic_track`)
    catch this and re-raise as their own `DynamicFault`, matching the
    documented "raises DynamicFault if the GDB batch call itself errors"
    contract each node already carries.
    """
    if not entry_addr.strip():
        raise ValueError(
            "render_gdb_recipe: entry_addr is empty — cannot emit 'break *' with no "
            "operand (GDB rejects it and aborts the whole recipe)."
        )
    lines = [
        f"set architecture {architecture}",
        "set pagination off",
        "set confirm off",
        f"target remote localhost:{gdb_port}",
        f"break *{normalize_hex_addr(entry_addr)}",
        "continue",
        *breakpoint_commands,
    ]
    return "\n".join(lines) + "\n"


def render_guard_breakpoint_commands(
    *, addr: str, register: str, forced_value: str, log_marker: str
) -> list[str]:
    """The `satisfy_guards` recipe body for ONE guard: break at its
    address, print the REAL (un-overridden) return value first (logged via
    a distinguishable marker so `bringup_stabilize`/the report can later
    state honestly what the default behavior was), force it to
    `forced_value` IF one was given, then continue. Register defaults to
    the architecture's first return-value-bearing register
    (`arg_registers[0]`) unless the caller names a different one.

    Two deliberate safety behaviors, both guarding against the same class
    of "GDB aborts mid-script, everything after this guard silently never
    runs" failure a single bad line can cause:

    - If `addr` is empty/unresolved, this guard is skipped ENTIRELY (no
      break/continue emitted for it) rather than emitting `break *` with no
      operand, which GDB rejects and which aborts the rest of the recipe —
      including every OTHER guard queued after this one. An unresolved
      guard address means "we can't test this guard dynamically", not
      "test it by breaking everywhere".
    - If `forced_value` is empty, this guard is OBSERVED (the real value is
      still logged via `printf`) but not forced — no `set` line is emitted.
      This is for guards that document an absence (e.g. "no sanitizer was
      found on this path") rather than a concrete value to drive execution
      past a check; manufacturing a fake forced value for something that
      was never meant to be executed is exactly the historical bug this
      guards against (see `common.verification.GuardSpec`'s docstring).
    - If `forced_value` is non-empty, it is validated against
      `common.verification.GDB_FORCED_VALUE_RE` before being interpolated —
      raises `ValueError` on anything that isn't a GDB-expression-shaped
      value (integer literal, `$register`, or bare symbol), so a rationale
      sentence can never reach the `set` line even if `GuardSpec`'s own
      pydantic validation were somehow bypassed upstream. Defense in depth,
      not a substitute for the schema-level check.
    """
    if not addr.strip():
        return []
    commands = [
        f"break *{normalize_hex_addr(addr)}",
        "continue",
        f'printf "{log_marker}:real=%d\\n", {register}',
    ]
    if forced_value.strip():
        if not GDB_FORCED_VALUE_RE.match(forced_value.strip()):
            raise ValueError(
                f"render_guard_breakpoint_commands: forced_value={forced_value!r} is not a "
                "valid GDB expression (integer literal, $register, or bare symbol) — refusing "
                "to interpolate it into a 'set' statement. This should have been caught by "
                "GuardSpec's own field validator; treat this as a defense-in-depth failure."
            )
        commands.append(f"set {register} = {forced_value}")
    commands.append("continue")
    return commands


_BARE_BREAK_STAR_RE = re.compile(r"^\s*break\s*\*\s*$")
"""Matches a `break *` line with NO address operand — the exact GDB error
`Argument required (expression to compute).` this project hit in
production (see `render_gdb_recipe`/`render_guard_breakpoint_commands`'s
empty-addr guards). A trailing `*<addr>` or `*<symbol>` does not match."""

_SET_REGISTER_LINE_RE = re.compile(r"^\s*set\s+(\$[a-zA-Z][a-zA-Z0-9]*)\s*=\s*(.+?)\s*$")
"""Matches a `set $reg = <rhs>` line and captures the right-hand side, so
`lint_gdb_recipe` can validate it against `GDB_FORCED_VALUE_RE` the same
way `render_guard_breakpoint_commands` does. Deliberately narrow to `set
$reg = ...` (register assignment) — other `set` lines this recipe emits
(`set architecture ...`, `set pagination off`, `set confirm off`) are
fixed boilerplate this module controls itself, not guard-supplied data,
so they are intentionally not in scope for this check."""


def lint_gdb_recipe(recipe: str) -> None:
    """Pre-flight syntax check run on a FULLY ASSEMBLED recipe (the output
    of `render_gdb_recipe`) right before it is written to disk and handed
    to `gdb-multiarch -batch -x`, independent of whatever path built it.

    This is deliberately a second, recipe-level check — not a replacement
    for the per-guard validation `render_guard_breakpoint_commands` and
    `GuardSpec`'s own pydantic validator already do. Those two catch a bad
    VALUE before a line is even constructed; this one catches a bad LINE
    regardless of how the recipe text was assembled (e.g. a future
    call site that concatenates recipe fragments some other way, or a
    hand-edited recipe passed into a debug helper) — the same
    defense-in-depth reasoning `render_guard_breakpoint_commands`'s own
    docstring gives for re-validating `forced_value` there.

    Raises `ValueError` (never partially — the whole recipe is checked
    before any of it is reported) describing every offending line found,
    so a caller gets one clear "invalid GDB recipe" failure instead of
    watching GDB abort silently mid-session with everything after that
    line never executing. Does nothing (returns `None`) on a clean recipe.
    """
    problems: list[str] = []
    for lineno, line in enumerate(recipe.splitlines(), start=1):
        if _BARE_BREAK_STAR_RE.match(line):
            problems.append(f"line {lineno}: 'break *' has no address operand: {line!r}")
            continue
        set_match = _SET_REGISTER_LINE_RE.match(line)
        if set_match and not GDB_FORCED_VALUE_RE.match(set_match.group(2)):
            problems.append(
                f"line {lineno}: 'set {set_match.group(1)} = ...' right-hand side "
                f"{set_match.group(2)!r} is not a valid GDB expression "
                "(integer literal, $register, or bare symbol): "
                f"{line!r}"
            )
    if problems:
        raise ValueError(
            "invalid GDB recipe — refusing to write it to disk:\n" + "\n".join(problems)
        )


def render_trigger_breakpoint_commands(
    *, sink_addr: str, argument_register: str, capture_marker: str
) -> list[str]:
    """The `instrument_trigger` recipe body: break at the sink, print the
    actual sink argument (as a C string) verbatim — this is the direct
    sink-argument-capture signal `collect_signals`/`dynamic_evaluate` reads
    to test the decisive observable."""
    return [
        f"break *{normalize_hex_addr(sink_addr)}",
        "continue",
        f'printf "{capture_marker}:%s\\n", (char*){argument_register}',
    ]


def build_qemu_strace_command(
    *,
    arch_spec: QemuArchSpec,
    target_relpath: str,
    argv: list[str] | None = None,
    rootfs_relpath: str | None = None,
    qemu_binary_in_chroot: str | None = None,
) -> str:
    """Assemble a ONE-SHOT (no `-g`/gdbstub, runs to completion or a short
    timeout) `qemu-<arch> -strace` invocation — the Node 3 (Bring-Up &
    Arbitration) agent's discovery tool, per the spec's "strace -f -e
    trace=open,openat,stat,access,readlink" step. qemu-user-static ships
    `-strace` as a built-in flag (no separate `strace` package needed in
    the image — confirmed against `docker/Dockerfile.verification`), so
    this reuses the exact chroot/env-fix/binary-selection logic
    `build_qemu_user_launch_command` already established rather than
    re-deriving it, just without the `-g <port>` flag (no debugger attaches
    to a discovery run) and with `-strace` prepended to the QEMU flags.
    Caller redirects stderr (where `-strace` writes) to a log file and
    greps it for `ENOENT`/failed-open lines — see `dynamic_agents.
    bringup_agent`'s discovery step."""
    if rootfs_relpath and not qemu_binary_in_chroot:
        raise ValueError(
            "qemu_binary_in_chroot is required when rootfs_relpath is set — see "
            "build_qemu_user_launch_command's identical requirement."
        )
    parts: list[str] = []
    if rootfs_relpath:
        parts += ["chroot", shlex.quote(rootfs_relpath)]
    for key, value in arch_spec.cpu_probe_env.items():
        parts.append(f"{key}={shlex.quote(value)}")
    parts.append(shlex.quote(qemu_binary_in_chroot) if rootfs_relpath else arch_spec.user_binary)
    parts.append("-strace")
    if rootfs_relpath:
        parts += ["-L", "/"]
    parts.append(shlex.quote(target_relpath))
    if argv:
        parts += [shlex.quote(a) for a in argv]
    return " ".join(parts)


def render_memory_dump_command(*, address: str, length_bytes: int = 32) -> str:
    """One GDB `x` command dumping `length_bytes` of hex from `address` —
    the Node 5/7 substitute for a hardware watchpoint (QEMU user-mode
    emulation does not support watchpoints; see this module's and
    `dynamic_track`'s docstrings). Called twice per risky operation (before
    and after) so the caller can diff the two dumps — `ObservationRecord.
    memory_before`/`memory_after`/`memory_diff_detected`."""
    return f"x/{length_bytes}xb {normalize_hex_addr(address)}"


def render_crash_capture_commands() -> list[str]:
    """GDB commands ensuring SIGSEGV/SIGABRT/SIGILL are caught and reported
    rather than silently passed through to the target (spec Node 5: "make
    sure GDB is set to stop and report on SIGSEGV, SIGABRT, and SIGILL"),
    plus the register/backtrace/PC dump to capture at the moment of a stop
    — issued once at the START of a recipe (before `continue`), so any
    breakpoint OR crash encountered later in the same batch is caught by
    the same handler."""
    return [
        "handle SIGSEGV stop print nopass",
        "handle SIGABRT stop print nopass",
        "handle SIGILL stop print nopass",
    ]


def render_crash_report_commands(*, marker: str) -> list[str]:
    """The commands to run ONCE a crash/breakpoint stop has occurred —
    prints the faulting PC, a full register dump, and a backtrace, each
    tagged with `marker` so the caller can parse them back out of GDB's
    combined stdout (same tagged-printf convention
    `render_guard_breakpoint_commands`/`render_trigger_breakpoint_commands`
    already use)."""
    return [
        f'printf "{marker}:PC:%p\\n", $pc',
        f"echo {marker}:REGISTERS:\\n",
        "info registers",
        f"echo {marker}:BACKTRACE:\\n",
        "bt",
    ]


def render_direct_call_recipe_body(
    *,
    target_function_addr: str,
    call_expression: str,
) -> list[str]:
    """The Node 6 direct-call-harness recipe body (last-resort emulation
    mode): break at the target function's own entry (so the process is
    halted with a valid stack/registers to call FROM), then issue GDB's
    `call` command with the crafted argument — bypassing whatever broken or
    unreachable normal dispatch path made partial emulation insufficient.
    `call_expression` is the full `fn(arg1, arg2, ...)` text the trigger
    agent constructed; composition of the C-expression TEXT itself is the
    agent's job (data), this function only wires it into the recipe shape
    (mirrors `tools/joern_tool.py`'s "the LLM supplies script BODY, this
    module supplies the command line" split). The caller (`fvvw.
    dynamic_track`'s direct-call path) MUST clearly label any result from
    this recipe as a direct invocation, not a realistic end-to-end
    trigger — see `common.verification.FVVWReport.emulation_mode`."""
    return [
        f"break *{normalize_hex_addr(target_function_addr)}",
        "continue",
        f"call {call_expression}",
    ]


__all__ = [
    "CONTAINER_SCRATCH",
    "CONTAINER_WORKDIR",
    "QEMU_ARCH_TABLE",
    "QemuArchSpec",
    "build_gdb_batch_command",
    "build_qemu_strace_command",
    "build_qemu_system_launch_command",
    "build_qemu_user_launch_command",
    "gdb_binary",
    "normalize_hex_addr",
    "render_crash_capture_commands",
    "render_crash_report_commands",
    "render_direct_call_recipe_body",
    "render_gdb_recipe",
    "render_guard_breakpoint_commands",
    "render_memory_dump_command",
    "render_trigger_breakpoint_commands",
    "resolve_qemu_arch_spec",
]
