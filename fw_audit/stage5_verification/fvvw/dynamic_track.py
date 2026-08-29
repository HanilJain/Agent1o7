"""The fork-join's dynamic (QEMU+GDB) track — FVVW v3 §6 nodes 9-15, §7's
GDB session recipe, §8's `bringup_stabilize` repair catalog, and §9's
hypothesis A/B switching logic.

Every function here is written to be called EITHER as a standalone
function (tests, `fw-verify debug dynamic`) or wrapped as a LangGraph node
by `fvvw.graph` (Phase 5) — each takes/returns plain dicts shaped like
`fvvw.state.FVVWState`'s `dynamic_*`/`emulation_plan`/`gdb_transcript`/
`signals`/`active_hypothesis`/`repair_*` keys, the same "node returns only
its own new state" shape `agent.graph`'s nodes already establish.

Command composition for every QEMU/GDB invocation lives in
`tools.qemu_gdb_tool` (imported, never re-implemented here) — this module
is the ORCHESTRATION of those commands into the reach -> guards -> trigger
-> collect -> evaluate sequence, plus the bring-up/repair loop and the
benign-marker-only invariant enforcement.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from fw_audit.common.verification import DynamicPlan, TargetMeta, TrackResult, VerificationVerdict
from fw_audit.config.settings import Settings
from fw_audit.executors.base import SessionHandle
from fw_audit.executors.sandbox_executor import SandboxExecutor
from fw_audit.observability import aspan
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.tools.qemu_gdb_tool import (
    CONTAINER_WORKDIR,
    build_gdb_batch_command,
    build_qemu_user_launch_command,
    render_gdb_recipe,
    render_guard_breakpoint_commands,
    render_trigger_breakpoint_commands,
    resolve_qemu_arch_spec,
)

# Where bringup_stabilize redirects the backgrounded QEMU process's
# stdout/stderr inside the session container — read back into the
# DynamicFault message if the gdbstub readiness probe times out, so a
# silent "never opened the port" failure carries QEMU's own diagnostic
# (bad chroot, missing interpreter/libs, unsupported syscall, ...) instead
# of forcing a manual `docker exec` to find out why.
_QEMU_LOG_PATH = f"{CONTAINER_WORKDIR}/.fvvw_qemu.log"

# --------------------------------------------------------------------- #
# Benign-marker-only invariant (FVVW §0/§12) — a hard, validated invariant
# on instrument_trigger. Anything matching these patterns is refused
# outright: network-reaching, privilege-escalating, or destructive
# content. The allow-list (benign markers) is intentionally narrow: a
# harmless filesystem side-effect (touch/echo/mkdir of a unique,
# clearly-scoped path) is the only shape this workflow ever injects.
# --------------------------------------------------------------------- #

_DENY_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\brm\s+-rf\b",
        r"\bmkfs\b",
        r"\bdd\s+if=",
        r"\breboot\b",
        r"\bshutdown\b",
        r"\bnc\b.*-e\b",  # netcat reverse shell
        r"\bnetcat\b.*-e\b",
        r"/dev/tcp/",
        r"\bcurl\b|\bwget\b",  # any network fetch
        r"\bchmod\s+(?:-R\s+)?[augo]*\+?s\b",  # setuid grant
        r"\bpasswd\b",
        r"\buseradd\b|\buserdel\b",
        r"\biptables\b",
        r"\bmknod\b",
        r"\b(reverse|bind)[\s_-]?shell\b",
        r">\s*/etc/",  # overwriting system config
        r"\bexec\s*\(",
        r"\|",  # any pipe — a marker is a single benign command, never a pipeline
    )
)

_ALLOW_MARKER_RE = re.compile(
    r"^\s*;?\s*(touch|mkdir\s+-p)\s+[\w./\-]+\s*;?\s*$"
    r"|^\s*;?\s*echo\s+[\w./\- ]+?\s*(>\s*[\w./\-]+)?\s*;?\s*$",
    re.IGNORECASE,
)


class BenignMarkerViolation(ValueError):
    """Raised by `validate_benign_marker` when a proposed
    `DynamicPlan.payload_marker` fails the benign-only check — a hard
    invariant `instrument_trigger` refuses to proceed past, per FVVW §0/§12:
    "the workflow produces test infrastructure and disclosure docs, never
    an exploit." Never caught and silently downgraded; a caller that hits
    this must treat the dynamic track as `not_run` for this candidate, not
    retry with a "safer" auto-edited marker."""


def validate_benign_marker(marker: str) -> None:
    """Raises `BenignMarkerViolation` if `marker` is not a benign,
    filesystem-side-effect-only marker. Deliberately a DENY-list plus a
    narrow ALLOW-list, both checked: the deny-list catches obviously
    dangerous content even in a marker shape we haven't anticipated; the
    allow-list positively confirms the marker is one of the sanctioned
    shapes (touch/echo/mkdir of a scoped path) rather than merely "didn't
    match anything on the deny-list", which would let a novel dangerous
    pattern through by omission.
    """
    if not marker or not marker.strip():
        raise BenignMarkerViolation("payload_marker is empty — refusing to inject nothing.")
    for pattern in _DENY_PATTERNS:
        if pattern.search(marker):
            raise BenignMarkerViolation(
                f"payload_marker matched a denied (non-benign) pattern {pattern.pattern!r}: "
                f"{marker!r}"
            )
    # Strip a leading/trailing `;` shell-separator before allow-list
    # matching — `';touch /tmp/x;'` is the doc's own canonical example.
    stripped = marker.strip().strip(";").strip()
    if not _ALLOW_MARKER_RE.match(f" {stripped} "):
        raise BenignMarkerViolation(
            f"payload_marker does not match an approved benign shape "
            f"(touch/echo/mkdir of a scoped path): {marker!r}"
        )


# --------------------------------------------------------------------- #
# plan_emulation
# --------------------------------------------------------------------- #


def plan_emulation(target: TargetMeta, plan: DynamicPlan) -> dict:
    """Rule-based (script, no LLM) user-vs-system mode decision (FVVW §6
    node 9). User-mode (QEMU user + chroot) for a self-contained dispatcher
    binary whose behavior doesn't need live kernel/NVRAM/IPC — the common
    case, including every `natural_drive`/`inferior_call` single-binary
    reach strategy the strategy agent would produce for a
    dispatcher-style finding (e.g. DEFECT-02-style multi-call binaries).
    System-mode is selected only when a guard NAME hints at kernel/NVRAM/IPC
    dependence (best-effort heuristic — refined by `bringup_stabilize` if
    user-mode later proves insufficient).

    Returns `{"emulation_plan": {...}}` — the `mem.dynamic.emulation_plan`
    update. `mode` is `"user"` or `"system"`; `arch_spec_key` is the
    `(arch, endianness)` tuple `tools.qemu_gdb_tool.QEMU_ARCH_TABLE` is
    keyed on, so later nodes don't re-derive the lookup key.
    """
    arch_spec = resolve_qemu_arch_spec(target.arch, target.endianness)
    if arch_spec is None:
        return {
            "emulation_plan": {
                "mode": "unsupported",
                "arch_spec_key": (target.arch, target.endianness),
                "reason": f"no QEMU support for arch={target.arch!r} "
                f"endianness={target.endianness!r}",
            }
        }

    kernel_hint_terms = ("nvram", "kernel", "ipc", "driver", "/proc/", "/sys/")
    needs_system_mode = any(
        any(term in guard.name.lower() for term in kernel_hint_terms) for guard in plan.guards
    )
    mode: Literal["user", "system"] = "system" if needs_system_mode else "user"

    return {
        "emulation_plan": {
            "mode": mode,
            "arch_spec_key": (target.arch, target.endianness),
            "reason": "",
        }
    }


# --------------------------------------------------------------------- #
# bringup_stabilize — setup + on-demand repair engine
# --------------------------------------------------------------------- #


@dataclass
class BringupContext:
    """Everything `bringup_stabilize` needs across its whole lifetime
    (initial stand-up AND every later repair invocation) — kept as one
    object rather than threading a dozen loose parameters through every
    dynamic-track node, since ALL of them route back here on a fault."""

    candidate: VerificationCandidate
    target: TargetMeta
    plan: DynamicPlan
    emulation_plan: dict
    settings: Settings
    session_executor: SandboxExecutor
    handle: SessionHandle | None = None
    launch_cmd: str = ""
    applied_fixes: list[str] | None = None
    repair_count: int = 0

    def __post_init__(self) -> None:
        if self.applied_fixes is None:
            self.applied_fixes = []


class BringupExhausted(RuntimeError):
    """Raised when `bringup_stabilize` cannot make the target run within
    `Settings.stage5_bringup_max_repairs` — the caller writes
    `mem.dynamic.result = not_run` (distinct from `refuted`) and lets the
    dynamic branch terminate; the static track is unaffected either way."""


async def bringup_stabilize(ctx: BringupContext) -> SessionHandle:
    """Stand emulation up (first call) or repair it (later calls, after a
    QEMU/GDB fault). Full behavior per FVVW §8:

    1. Select the correct `qemu-<arch>` binary from `mem.target.arch` via
       `resolve_qemu_arch_spec` (already validated by `plan_emulation`).
    2. Build the exact launch command (chroot + CPU-probe env fix + QEMU +
       GDB stub flag + `-L` sysroot + target + argv) via
       `tools.qemu_gdb_tool.build_qemu_user_launch_command`.
    3. Start (or reuse) the session container and launch QEMU inside it via
       `exec_in_session` — backgrounded (the caller of THIS function is
       responsible for not blocking on it; see `_launch_qemu_backgrounded`).
    4. Verify the GDB stub is reachable with a lightweight probe.

    Requirement fixes (missing files/mounts/libs, chroot, CPU-probe SIGILL,
    scoped network grant) are applied BEFORE the launch is attempted, using
    facts already known to `ctx` — this function does not itself run a
    trial-and-error loop past `Settings.stage5_bringup_max_repairs`; a
    caller that keeps hitting the same fault should stop calling this and
    let the branch terminate `not_run` (see `BringupExhausted`).
    """
    if ctx.repair_count >= ctx.settings.stage5_bringup_max_repairs:
        raise BringupExhausted(
            f"{ctx.candidate.global_id}: exceeded stage5_bringup_max_repairs="
            f"{ctx.settings.stage5_bringup_max_repairs} repair attempts."
        )
    ctx.repair_count += 1

    arch, endianness = ctx.emulation_plan.get("arch_spec_key", ("unknown", ""))
    arch_spec = resolve_qemu_arch_spec(arch, endianness)
    if arch_spec is None:
        raise BringupExhausted(
            f"{ctx.candidate.global_id}: no QEMU support for arch={arch!r} "
            f"endianness={endianness!r} — cannot bring up emulation."
        )

    async with aspan(
        "stage5.bringup_stabilize",
        run_type="tool",
        inputs={"global_id": ctx.candidate.global_id, "repair_count": ctx.repair_count},
    ) as run:
        network_name: str | None = None
        if _target_needs_network(ctx.plan) and ctx.settings.stage5_allow_network_grant:
            network_name = f"fvvw-{uuid.uuid4().hex[:12]}"
            ctx.applied_fixes.append(f"granted scoped network {network_name}")

        # "." — the bind-mounted workspace root itself IS the rootfs root
        # (see `_workspace_dir_for`'s docstring); `chroot .` inside
        # CONTAINER_WORKDIR is what actually changes root correctly here.
        rootfs_relpath = "." if ctx.candidate.rootfs_dir is not None else None
        target_relpath = _target_relpath_in_workspace(ctx.candidate)

        launch_cmd = build_qemu_user_launch_command(
            arch_spec=arch_spec,
            target_relpath=target_relpath,
            argv=list(ctx.plan.argv_template),
            rootfs_relpath=rootfs_relpath,
        )
        ctx.launch_cmd = launch_cmd

        if ctx.handle is None:
            ctx.handle = await ctx.session_executor.start(
                image=ctx.settings.stage5_verification_image,
                files=_workspace_dir_for(ctx),
                network=network_name,
            )
            ctx.applied_fixes.append(f"started session {ctx.handle.container_name}")

        # Launch QEMU in the background inside the session so this call
        # returns quickly and reach_target can connect the GDB stub next —
        # `&` backgrounds it inside the container's shell, `disown` detaches
        # it from the exec'd shell's job table so it survives that shell
        # exiting (the exec_in_session call itself completes once the
        # background job is started, not once QEMU exits). stdout/stderr
        # are redirected to a log file rather than discarded: if QEMU dies
        # immediately (bad chroot, missing interpreter/libs, unsupported
        # syscall) the only symptom would otherwise be a silent gdbstub
        # readiness-probe timeout with no clue why — see the DynamicFault
        # raised below, which reads this log back into its message.
        await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cd {CONTAINER_WORKDIR} && "
            f"({launch_cmd} > {_QEMU_LOG_PATH} 2>&1 &) ",
            timeout=ctx.settings.stage5_qemu_timeout_seconds,
        )

        # Backgrounding the launch means this call returns as soon as the
        # shell accepts the job, NOT once QEMU has actually bound the GDB
        # stub's listening port — reach_target's very first GDB command is
        # `target remote localhost:1234`, which races that bind and fails
        # with "Connection refused" if it runs first. That failure matches
        # `_looks_like_setup_fault` and used to route back to
        # `bringup_stabilize`, which just re-launched QEMU and retried at
        # the same speed — a repair that never addressed the actual defect,
        # burning the whole `stage5_bringup_max_repairs` budget on a pure
        # timing race. Poll for the port here instead, bounded by
        # `stage5_qemu_timeout_seconds`, so `reach_target` only ever runs
        # once QEMU is actually listening (or bringup fails fast and
        # honestly if it never does).
        probe = (
            "for i in $(seq 1 50); do "
            "grep -q ':04D2 ' /proc/net/tcp 2>/dev/null && exit 0; "
            "sleep 0.2; "
            "done; exit 1"
        )
        readiness = await ctx.session_executor.exec_in_session(
            ctx.handle,
            probe,
            timeout=ctx.settings.stage5_qemu_timeout_seconds,
        )
        if not readiness.ok:
            log_result = await ctx.session_executor.exec_in_session(
                ctx.handle,
                f"cat {_QEMU_LOG_PATH} 2>/dev/null",
                timeout=ctx.settings.stage5_qemu_timeout_seconds,
            )
            qemu_output = (log_result.stdout + log_result.stderr).strip() or "(empty)"
            raise DynamicFault(
                f"{ctx.candidate.global_id}: QEMU gdbstub never opened port 1234 "
                f"within the readiness window — launch_cmd={launch_cmd!r} "
                f"qemu_output={qemu_output!r}"
            )

        if run is not None:
            run.end(
                outputs={
                    "launch_cmd": launch_cmd,
                    "applied_fixes": list(ctx.applied_fixes),
                    "network_granted": network_name is not None,
                    "gdbstub_ready": readiness.ok,
                }
            )

    return ctx.handle


def _target_needs_network(plan: DynamicPlan) -> bool:
    """Best-effort: does anything in the plan hint the target binds a
    socket or expects a reachable service? Conservative — only a guard/argv
    entry explicitly naming networking triggers this, never assumed by
    default (default stays no-egress per FVVW §12)."""
    haystack = " ".join([*plan.argv_template, *(g.name for g in plan.guards)]).lower()
    return any(term in haystack for term in ("socket", "bind", "listen", "network_daemon"))


def _target_relpath_in_workspace(candidate: VerificationCandidate) -> str:
    """The target ELF's path relative to the bind-mounted session
    workspace. `_workspace_dir_for` mounts `candidate.rootfs_dir` itself
    (not its parent) directly at `CONTAINER_WORKDIR`, so a binary at
    `rootfs_dir/sbin/vulnbin` becomes plain `sbin/vulnbin` inside the
    container — there is no separate `rootfs/` subdirectory to descend
    into; the workspace root IS the rootfs root. (An earlier version of
    this mounted `rootfs_dir.parent` and prefixed `rootfs/`, assuming the
    host directory Stage 1/2 extracted the firmware into was literally
    named `rootfs` — false in general, e.g. binwalk's own `squashfs-root`
    naming, which made every chroot fail with 'cannot change root
    directory to rootfs: No such file or directory'.)"""
    if candidate.binary_path is None or candidate.rootfs_dir is None:
        return candidate.bin_id  # best-effort fallback, will fail to launch
    rel = candidate.binary_path.relative_to(candidate.rootfs_dir)
    return rel.as_posix()


def _workspace_dir_for(ctx: BringupContext) -> Path | None:
    """Resolve the host directory bind-mounted into the session container —
    `Settings.stage5_dynamic_workspace_root` override, or
    `candidate.rootfs_dir` ITSELF (mounted directly at `CONTAINER_WORKDIR`,
    so the container's workspace root IS the rootfs root — see
    `_target_relpath_in_workspace`'s docstring for why this must not be
    the parent directory), or `None` if nothing is resolvable (bring-up
    will then fail fast, which is correct — there's nothing to emulate)."""
    if ctx.settings.stage5_dynamic_workspace_root:
        return Path(ctx.settings.stage5_dynamic_workspace_root)
    if ctx.candidate.rootfs_dir is not None:
        return ctx.candidate.rootfs_dir
    return None


# --------------------------------------------------------------------- #
# reach_target / satisfy_guards / instrument_trigger / collect_signals
# --------------------------------------------------------------------- #


class DynamicFault(RuntimeError):
    """Raised by `reach_target`/`satisfy_guards`/`instrument_trigger` on a
    QEMU/GDB setup or connection fault — the FVVW §5 dotted "repair"
    back-edge. A caller (the LangGraph wiring in Phase 5, or a direct
    caller in tests) catches this and routes to `bringup_stabilize` again,
    setting `mem.repair.return_to` to the node that raised."""


async def reach_target(
    ctx: BringupContext, *, gdb_transcript_so_far: str = ""
) -> tuple[str, bool]:
    """Drive the target to a stable, fully-relocated process state at the
    functional entry point. `natural_drive`: argv/env already supplied at
    launch, just continue past entry. `inferior_call`: same recipe shape —
    the actual "call the target function directly" mechanics live in the
    trigger recipe's breakpoint placement (breaking directly at
    `target_addr` rather than relying on natural control flow), since GDB
    itself doesn't need a different CONNECTION step for either strategy.

    Returns `(new_transcript_text, reached: bool)`. Raises `DynamicFault`
    if the GDB batch call itself errors (stub unreachable, timeout) —
    distinct from "connected but breakpoint never hit", which
    `dynamic_evaluate` treats as a retry/hypothesis-switch signal, not a
    bring-up fault.
    """
    arch, _ = ctx.emulation_plan.get("arch_spec_key", ("unknown", ""))
    entry_addr = ctx.plan.entry_addr or ctx.target.func_offset
    recipe = render_gdb_recipe(
        architecture=arch, gdb_port=1234, entry_addr=entry_addr, breakpoint_commands=[]
    )
    recipe_path = "recipe_reach.gdb"
    target_relpath = _target_relpath_in_workspace(ctx.candidate)

    if ctx.handle is None:
        raise DynamicFault(f"{ctx.candidate.global_id}: no active session to reach_target on.")

    async with aspan(
        "stage5.reach_target", run_type="tool", inputs={"global_id": ctx.candidate.global_id}
    ) as run:
        await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cat > {CONTAINER_WORKDIR}/{recipe_path} << 'FVVWEOF'\n{recipe}FVVWEOF",
            timeout=ctx.settings.stage5_gdb_timeout_seconds,
        )
        result = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cd {CONTAINER_WORKDIR} && "
            + build_gdb_batch_command(recipe_path, target_relpath),
            timeout=ctx.settings.stage5_gdb_timeout_seconds,
        )
        if run is not None:
            run.end(outputs={"ok": result.ok, "stdout_excerpt": result.stdout[:500]})

    if not result.ok and _looks_like_setup_fault(result.stderr):
        raise DynamicFault(
            f"{ctx.candidate.global_id}: reach_target GDB/QEMU setup fault: {result.stderr}"
        )

    transcript = gdb_transcript_so_far + result.stdout + result.stderr
    reached = "Breakpoint" in result.stdout or result.ok
    return transcript, reached


async def satisfy_guards(
    ctx: BringupContext, *, gdb_transcript_so_far: str = ""
) -> tuple[str, list[dict]]:
    """Break at each guard, log the REAL un-overridden return value first,
    then force it to `forced_value`, then continue — FVVW §7's recipe.
    Returns `(new_transcript_text, guard_logs)` where each `guard_logs`
    entry is `{"name", "addr", "real_value", "forced_value"}` — this is
    what later lets `joint_evaluate`'s reachability axis state honestly
    "both gates false by default" rather than just "path reached"."""
    arch, _ = ctx.emulation_plan.get("arch_spec_key", ("unknown", ""))
    if ctx.handle is None:
        raise DynamicFault(f"{ctx.candidate.global_id}: no active session to satisfy_guards on.")

    arch_spec = resolve_qemu_arch_spec(*ctx.emulation_plan.get("arch_spec_key", ("unknown", "")))
    register = arch_spec.arg_registers[0] if arch_spec else "$r0"

    breakpoint_commands: list[str] = []
    for guard in ctx.plan.guards:
        marker = f"GUARD:{guard.name}"
        breakpoint_commands += render_guard_breakpoint_commands(
            addr=guard.addr,
            register=register,
            forced_value=guard.forced_value,
            log_marker=marker,
        )

    recipe = render_gdb_recipe(
        architecture=arch,
        gdb_port=1234,
        entry_addr=ctx.plan.entry_addr or ctx.target.func_offset,
        breakpoint_commands=breakpoint_commands,
    )
    recipe_path = "recipe_guards.gdb"
    target_relpath = _target_relpath_in_workspace(ctx.candidate)

    async with aspan(
        "stage5.satisfy_guards", run_type="tool", inputs={"global_id": ctx.candidate.global_id}
    ) as run:
        await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cat > {CONTAINER_WORKDIR}/{recipe_path} << 'FVVWEOF'\n{recipe}FVVWEOF",
            timeout=ctx.settings.stage5_gdb_timeout_seconds,
        )
        result = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cd {CONTAINER_WORKDIR} && "
            + build_gdb_batch_command(recipe_path, target_relpath),
            timeout=ctx.settings.stage5_gdb_timeout_seconds,
        )
        if run is not None:
            run.end(outputs={"ok": result.ok, "guard_count": len(ctx.plan.guards)})

    if not result.ok and _looks_like_setup_fault(result.stderr):
        raise DynamicFault(
            f"{ctx.candidate.global_id}: satisfy_guards GDB/QEMU setup fault: {result.stderr}"
        )

    guard_logs = _parse_guard_logs(result.stdout, ctx.plan.guards)
    transcript = gdb_transcript_so_far + result.stdout + result.stderr
    return transcript, guard_logs


def _parse_guard_logs(stdout: str, guards) -> list[dict]:
    logs = []
    for guard in guards:
        match = re.search(rf"GUARD:{re.escape(guard.name)}:real=(-?\d+)", stdout)
        real_value = match.group(1) if match else None
        logs.append(
            {
                "name": guard.name,
                "addr": guard.addr,
                "real_value": real_value,
                "forced_value": guard.forced_value,
            }
        )
    return logs


async def instrument_trigger(
    ctx: BringupContext, *, gdb_transcript_so_far: str = ""
) -> tuple[str, str | None]:
    """Break at the sink, inject EXACTLY `plan.payload_marker` (benign,
    validated by `validate_benign_marker` before this function does
    anything else — refuses to run on a violation), read the actual sink
    argument, log it verbatim. Returns `(new_transcript_text,
    captured_sink_argument_or_None)` — `None` means the breakpoint never
    fired (sink not reached), distinct from "reached but the marker text
    isn't present" (neutralized), which `dynamic_evaluate` treats very
    differently (retry/repair signal vs. real evidence toward B).
    """
    validate_benign_marker(ctx.plan.payload_marker)

    arch, _ = ctx.emulation_plan.get("arch_spec_key", ("unknown", ""))
    if ctx.handle is None:
        raise DynamicFault(
            f"{ctx.candidate.global_id}: no active session to instrument_trigger on."
        )
    arch_spec = resolve_qemu_arch_spec(*ctx.emulation_plan.get("arch_spec_key", ("unknown", "")))
    register = arch_spec.arg_registers[0] if arch_spec else "$r0"

    marker = "TRIGGER:sink_arg"
    breakpoint_commands = render_trigger_breakpoint_commands(
        sink_addr=ctx.plan.sink_addr or ctx.target.func_offset,
        argument_register=register,
        capture_marker=marker,
    )
    recipe = render_gdb_recipe(
        architecture=arch,
        gdb_port=1234,
        entry_addr=ctx.plan.entry_addr or ctx.target.func_offset,
        breakpoint_commands=breakpoint_commands,
    )
    recipe_path = "recipe_trigger.gdb"
    target_relpath = _target_relpath_in_workspace(ctx.candidate)

    async with aspan(
        "stage5.instrument_trigger",
        run_type="tool",
        inputs={"global_id": ctx.candidate.global_id},
    ) as run:
        await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cat > {CONTAINER_WORKDIR}/{recipe_path} << 'FVVWEOF'\n{recipe}FVVWEOF",
            timeout=ctx.settings.stage5_gdb_timeout_seconds,
        )
        result = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cd {CONTAINER_WORKDIR} && "
            + build_gdb_batch_command(recipe_path, target_relpath),
            timeout=ctx.settings.stage5_gdb_timeout_seconds,
        )
        captured = _parse_trigger_capture(result.stdout, marker)
        if run is not None:
            run.end(outputs={"ok": result.ok, "captured": captured})

    if not result.ok and _looks_like_setup_fault(result.stderr):
        raise DynamicFault(
            f"{ctx.candidate.global_id}: instrument_trigger GDB/QEMU setup fault: {result.stderr}"
        )

    transcript = gdb_transcript_so_far + result.stdout + result.stderr
    return transcript, captured


def _parse_trigger_capture(stdout: str, marker: str) -> str | None:
    match = re.search(rf"{re.escape(marker)}:(.*)", stdout)
    return match.group(1).strip() if match else None


async def collect_signals(
    ctx: BringupContext,
    *,
    captured_sink_argument: str | None,
) -> list[dict]:
    """Independent of the direct capture (`instrument_trigger`'s
    `captured_sink_argument`): scan the target's own stdout/stderr for a
    self-report only possible if the marker took effect, and check the
    filesystem for the marker's side-effect artifact. Returns the
    `mem.dynamic.signals` list this call contributes (appended via the
    `operator.add` reducer at the graph level, per `fvvw.state`).
    """
    signals: list[dict] = []
    if captured_sink_argument is not None:
        signals.append(
            {
                "kind": "sink_argument_capture",
                "value": captured_sink_argument,
                "marker_present": _marker_text_present(
                    captured_sink_argument, ctx.plan.payload_marker
                ),
            }
        )

    if ctx.handle is None:
        return signals

    async with aspan(
        "stage5.collect_signals", run_type="tool", inputs={"global_id": ctx.candidate.global_id}
    ) as run:
        artifact_path = _marker_artifact_path(ctx.plan.payload_marker)
        if artifact_path:
            check = await ctx.session_executor.exec_in_session(
                ctx.handle,
                f"test -e {artifact_path} && echo FOUND || echo NOTFOUND",
                timeout=ctx.settings.stage5_gdb_timeout_seconds,
            )
            signals.append(
                {
                    "kind": "filesystem_artifact",
                    "value": artifact_path,
                    "marker_present": "FOUND" in check.stdout,
                }
            )

        self_report = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cat {CONTAINER_WORKDIR}/target_stdout.log 2>/dev/null || true",
            timeout=ctx.settings.stage5_gdb_timeout_seconds,
        )
        marker_id = _extract_marker_identifier(ctx.plan.payload_marker)
        signals.append(
            {
                "kind": "target_self_report",
                "value": self_report.stdout[:1000],
                "marker_present": bool(marker_id) and marker_id in self_report.stdout,
            }
        )

        if run is not None:
            run.end(outputs={"signal_count": len(signals)})

    return signals


def _marker_text_present(captured: str, marker: str) -> bool:
    marker_id = _extract_marker_identifier(marker)
    return bool(marker_id) and marker_id in captured


def _extract_marker_identifier(marker: str) -> str:
    """Extract the fully-qualified path/identifier out of a marker like
    `';touch /tmp/claim_001_proof;'` -> `/tmp/claim_001_proof` — used both
    to check the filesystem artifact and to scan target self-reports,
    avoiding tokenizer ambiguity (FVVW §6 node 14's own concern)."""
    match = re.search(r"(/[\w./\-]+)", marker)
    return match.group(1) if match else ""


def _marker_artifact_path(marker: str) -> str:
    return _extract_marker_identifier(marker)


def _looks_like_setup_fault(stderr: str) -> bool:
    """Heuristic: does this stderr look like a QEMU/GDB SETUP/connection
    problem (routes to `bringup_stabilize`) rather than the target simply
    not reaching a breakpoint (a normal, non-fault outcome `dynamic_evaluate`
    handles)? Conservative — only recognizable connection/launch failures
    trigger a repair; an empty or merely-unexpected stderr does not."""
    if not stderr:
        return False
    fault_markers = (
        "connection refused",
        "could not connect",
        "no such file or directory",
        "not found",
        "permission denied",
        "sigill",
        "sigsegv",
        "exec format error",
    )
    lowered = stderr.lower()
    return any(marker in lowered for marker in fault_markers)


# --------------------------------------------------------------------- #
# dynamic_evaluate — rule engine + hypothesis A/B switch (FVVW §9)
# --------------------------------------------------------------------- #


def dynamic_evaluate(
    *,
    reached: bool,
    captured_sink_argument: str | None,
    signals: list[dict],
    plan: DynamicPlan,
    active_hypothesis: Literal["A", "B"],
    iteration: int,
    max_iterations: int,
) -> dict:
    """Deterministic (script, no LLM) verdict + hypothesis-switch router —
    FVVW §9's rule, applied mechanically:

    1. Not reached (breakpoint never fired) -> retry signal, no verdict yet
       (unless the retry budget is exhausted, in which case `inconclusive`).
    2. Reached + marker present unmodified in >= 3 signals -> hypothesis A
       proved, `verdict=confirmed`.
    3. Reached + marker demonstrably NEUTRALIZED (captured but the marker
       text is absent/altered) -> that IS proof of B, `verdict=refuted`.
    4. Same non-confirming, non-refuting result recurring at the iteration
       cap -> SWITCH `active_hypothesis` to the other one and signal the
       caller to re-run reach/guards/trigger aimed at proving the new
       hypothesis, rather than terminating.
    5. Neither provable within `max_iterations` -> terminate
       `inconclusive`, `proved_hypothesis=none`.

    Returns a dict with `route` (`"retry"` | `"switch_hypothesis"` |
    `"done"`) plus (`done` only) a `TrackResult`-shaped `result` dict —
    kept as a plain dict rather than constructing `TrackResult` directly so
    a non-terminal call doesn't need a placeholder verdict.
    """
    required = max(3, len(plan.required_signals) or 3)
    marker_signals_present = sum(1 for s in signals if s.get("marker_present"))
    marker_signals_seen = sum(1 for s in signals if "marker_present" in s)

    if not reached:
        if iteration >= max_iterations:
            return _terminal(
                VerificationVerdict.INCONCLUSIVE, "none", iteration, reason="sink never reached"
            )
        return {"route": "retry"}

    if captured_sink_argument is not None and marker_signals_present >= required:
        return _terminal(VerificationVerdict.CONFIRMED, "A", iteration, reason="")

    if (
        captured_sink_argument is not None
        and marker_signals_seen > 0
        and marker_signals_present == 0
    ):
        # Reached, captured, but the marker is demonstrably ABSENT from
        # every signal that could show it — clean neutralization, proof of B.
        return _terminal(VerificationVerdict.REFUTED, "B", iteration, reason="")

    if iteration >= max_iterations:
        if active_hypothesis == "A":
            return {"route": "switch_hypothesis", "next_hypothesis": "B"}
        return _terminal(
            VerificationVerdict.INCONCLUSIVE,
            "none",
            iteration,
            reason="neither A nor B provable within budget",
        )

    return {"route": "retry"}


def _terminal(
    verdict: VerificationVerdict, proved_hypothesis: str, iteration: int, *, reason: str
) -> dict:
    return {
        "route": "done",
        "result": TrackResult(
            verdict=verdict,
            proved_hypothesis=proved_hypothesis,
            evidence={"reason": reason} if reason else {},
            iters_used=iteration,
        ),
    }


__all__ = [
    "BenignMarkerViolation",
    "BringupContext",
    "BringupExhausted",
    "DynamicFault",
    "bringup_stabilize",
    "collect_signals",
    "dynamic_evaluate",
    "instrument_trigger",
    "plan_emulation",
    "reach_target",
    "satisfy_guards",
    "validate_benign_marker",
]
