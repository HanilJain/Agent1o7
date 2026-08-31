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

import contextlib
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
from fw_audit.stage5_verification.cmdlog import aphase
from fw_audit.stage5_verification.tools.qemu_gdb_tool import (
    CONTAINER_SCRATCH,
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
# of forcing a manual `docker exec` to find out why. Lives under
# CONTAINER_SCRATCH (never CONTAINER_WORKDIR, which is a bind mount of the
# extracted firmware rootfs) so this never pollutes the firmware being
# analyzed — see qemu_gdb_tool.CONTAINER_SCRATCH's own docstring.
_QEMU_LOG_PATH = f"{CONTAINER_SCRATCH}/.fvvw_qemu.log"

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

# The echo branch's content class permits quotes (`'` and `"`) in addition
# to word chars / `.` / `/` / `-` / space, because a strategy agent
# naturally emits `echo 'proof_of_exploit'` — quotes are cosmetic and
# benign here (the shell strips them). This stays safe because the class
# still EXCLUDES every shell metacharacter that would give a marker teeth:
# no `$`, `(`, `)`, backtick, `&`, `|`, `<`, or mid-string `;`, so
# `echo '$(evil)'` / `echo 'a'&&rm` never match the allow-list, and the
# deny-list (checked first) independently rejects dangerous content.
_ALLOW_MARKER_RE = re.compile(
    r"^\s*;?\s*(touch|mkdir\s+-p)\s+[\w./\-]+\s*;?\s*$"
    r"|^\s*;?\s*echo\s+[\w./\-'\" ]+?\s*(>\s*[\w./\-]+)?\s*;?\s*$",
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


# GDB's own escape hatches — anything here would execute a HOST-side command
# (a shell, an interpreter, arbitrary file read) outside the benign-marker
# discipline `validate_benign_marker` enforces for the marker text itself.
# An operator-injected raw recipe (HITL's "inject" action) bypasses
# `plan.payload_marker` entirely, so `validate_benign_marker` never sees it —
# this is that recipe's OWN gate, checked line-by-line before the recipe is
# ever written into a session container.
_GDB_ESCAPE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"^\s*shell\b",
        r"^\s*!",
        r"^\s*pipe\b",
        r"^\s*\|",
        r"^\s*python\b",
        r"^\s*python-interactive\b",
        r"^\s*pi\b",
        r"^\s*eval\b",
        r"^\s*define\b",
        r"^\s*source\b",
        r"^\s*dump\b",  # dump memory/binary to an arbitrary host file
        r"^\s*generate-core-file\b",
    )
)


def validate_injected_recipe(recipe: str) -> None:
    """Raises `BenignMarkerViolation` if an operator-supplied raw GDB recipe
    (HITL's "inject" action — see `fvvw.hitl`) contains any of GDB's own
    escape hatches, which would let the recipe execute host-side commands
    outside the benign-marker-only discipline. Reuses `BenignMarkerViolation`
    (rather than a new exception type) since this is the SAME hard-stop
    invariant applied to a different input shape — a caller that hits this
    must treat the dynamic track as `not_run` for this round, never retry
    with an auto-"sanitized" recipe. Checked line-by-line so a legitimate
    `break`/`continue`/`printf`/`set $reg = ...` line elsewhere in the
    recipe doesn't cause a false positive from a substring match against the
    whole text."""
    if not recipe or not recipe.strip():
        raise BenignMarkerViolation("injected recipe is empty — refusing to run nothing.")
    for lineno, line in enumerate(recipe.splitlines(), start=1):
        for pattern in _GDB_ESCAPE_PATTERNS:
            if pattern.search(line):
                raise BenignMarkerViolation(
                    f"injected recipe line {lineno} matched a denied GDB escape hatch "
                    f"{pattern.pattern!r}: {line!r}"
                )
    # The deny-list `validate_benign_marker` already applies to a payload
    # marker also catches obviously dangerous shell content that might be
    # embedded in a `printf`/`call` line (e.g. a reverse shell one-liner),
    # so run it too — never bypassed just because this is a "recipe" rather
    # than a bare marker string.
    for pattern in _DENY_PATTERNS:
        if pattern.search(recipe):
            raise BenignMarkerViolation(
                f"injected recipe matched a denied (non-benign) pattern "
                f"{pattern.pattern!r}."
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
    raw_recipe_override: str | None = None
    """Set by HITL's "inject" action (`fvvw.hitl`) to run an operator-supplied
    GDB recipe VERBATIM in `instrument_trigger` instead of the one
    `render_gdb_recipe`/`render_trigger_breakpoint_commands` would build —
    validated by `validate_injected_recipe` (never `validate_benign_marker`,
    which only understands a bare marker string) before use. `None` (the
    default) means every dynamic-track node behaves exactly as it did before
    this field existed."""

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
    ) as run, aphase("bringup_stabilize"):
        network_name: str | None = None
        if _target_needs_network(ctx.plan) and ctx.settings.stage5_allow_network_grant:
            network_name = f"fvvw-{uuid.uuid4().hex[:12]}"
            ctx.applied_fixes.append(f"granted scoped network {network_name}")

        # "." — the bind-mounted workspace root itself IS the rootfs root
        # (see `_workspace_dir_for`'s docstring); `chroot .` inside
        # CONTAINER_WORKDIR is what actually changes root correctly here.
        chrooting = ctx.candidate.rootfs_dir is not None
        rootfs_relpath = "." if chrooting else None
        target_relpath = _target_relpath_in_workspace(ctx.candidate)

        # After `chroot`, the container's own /usr/bin/qemu-<arch> is no
        # longer reachable — the emulator binary has to live INSIDE the
        # rootfs. qemu-user-static's binaries are statically linked exactly
        # for this, so a plain copy into the rootfs works with no library
        # dependencies inside the foreign-arch tree.
        qemu_binary_in_chroot = f"/{arch_spec.user_binary}" if chrooting else None

        launch_cmd = build_qemu_user_launch_command(
            arch_spec=arch_spec,
            target_relpath=target_relpath,
            argv=list(ctx.plan.argv_template),
            rootfs_relpath=rootfs_relpath,
            qemu_binary_in_chroot=qemu_binary_in_chroot,
        )
        ctx.launch_cmd = launch_cmd

        if ctx.handle is None:
            ctx.handle = await ctx.session_executor.start(
                image=ctx.settings.stage5_verification_image,
                files=_workspace_dir_for(ctx),
                network=network_name,
            )
            ctx.applied_fixes.append(f"started session {ctx.handle.container_name}")

        # Stage the static QEMU binary into the rootfs so `chroot . <qemu>`
        # can find it (see build_qemu_user_launch_command). Resolve the
        # real path via `command -v` (the Dockerfile symlinks
        # qemu-<arch> -> qemu-<arch>-static under /usr/bin) and copy it to
        # the rootfs root as `<arch>`-named, matching qemu_binary_in_chroot.
        if chrooting:
            copy_cmd = (
                f"cp \"$(command -v {arch_spec.user_binary})\" "
                f"{CONTAINER_WORKDIR}/{arch_spec.user_binary}"
            )
            copy_result = await ctx.session_executor.exec_in_session(
                ctx.handle, copy_cmd, timeout=ctx.settings.stage5_qemu_timeout_seconds
            )
            if not copy_result.ok:
                raise DynamicFault(
                    f"{ctx.candidate.global_id}: failed to stage QEMU binary "
                    f"{arch_spec.user_binary!r} into the rootfs for chroot: "
                    f"{copy_result.stderr.strip() or copy_result.stdout.strip()!r}"
                )
            ctx.applied_fixes.append(f"staged {arch_spec.user_binary} into rootfs")

        await _launch_qemu_and_wait(ctx)

        if run is not None:
            run.end(
                outputs={
                    "launch_cmd": launch_cmd,
                    "applied_fixes": list(ctx.applied_fixes),
                    "network_granted": network_name is not None,
                }
            )

    return ctx.handle


async def _launch_qemu_and_wait(ctx: BringupContext) -> None:
    """(Re)launch the backgrounded QEMU user-mode process and block until
    its GDB stub is listening on port 1234. Uses `ctx.launch_cmd` (built by
    `bringup_stabilize`), redirecting QEMU's stdout/stderr to a log file so
    a silent readiness timeout carries QEMU's own diagnostic.

    Idempotent by design — it kills any prior QEMU first — because it is
    called before EVERY GDB batch, not just once: user-mode QEMU runs the
    target to completion and exits the instant a `gdb -batch` client
    disconnects, so the reach/guards/trigger batches cannot share one QEMU
    and each needs its own fresh launch. Raises `DynamicFault` (retriable
    via bringup's repair budget) if the stub never opens.

    Backgrounding means this returns as soon as the shell accepts the job,
    NOT once QEMU has bound the port — a GDB `target remote localhost:1234`
    that ran first would race the bind and fail with connection refused, so
    the readiness poll here is what makes the subsequent batch reliable."""
    if ctx.handle is None:
        raise DynamicFault(f"{ctx.candidate.global_id}: no active session to launch QEMU in.")

    arch, endianness = ctx.emulation_plan.get("arch_spec_key", ("unknown", ""))
    arch_spec = resolve_qemu_arch_spec(arch, endianness)
    # Kill any straggler from a previous batch (best-effort — pkill exits
    # nonzero when nothing matches, which is fine); ` ; true` keeps the
    # exec from reporting failure on the common "nothing to kill" case.
    if arch_spec is not None:
        await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"pkill -f {arch_spec.user_binary} 2>/dev/null ; true",
            timeout=ctx.settings.stage5_qemu_timeout_seconds,
        )

    await ctx.session_executor.exec_in_session(
        ctx.handle,
        f"cd {CONTAINER_WORKDIR} && mkdir -p {CONTAINER_SCRATCH} && "
        f"({ctx.launch_cmd} > {_QEMU_LOG_PATH} 2>&1 &) ",
        timeout=ctx.settings.stage5_qemu_timeout_seconds,
    )

    probe = (
        "for i in $(seq 1 50); do "
        "grep -q ':04D2 ' /proc/net/tcp 2>/dev/null && exit 0; "
        "sleep 0.2; "
        "done; exit 1"
    )
    readiness = await ctx.session_executor.exec_in_session(
        ctx.handle, probe, timeout=ctx.settings.stage5_qemu_timeout_seconds
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
            f"within the readiness window — launch_cmd={ctx.launch_cmd!r} "
            f"qemu_output={qemu_output!r}"
        )


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
    recipe_path = f"{CONTAINER_SCRATCH}/recipe_reach.gdb"
    target_relpath = _target_relpath_in_workspace(ctx.candidate)

    if ctx.handle is None:
        raise DynamicFault(f"{ctx.candidate.global_id}: no active session to reach_target on.")

    async with aspan(
        "stage5.reach_target", run_type="tool", inputs={"global_id": ctx.candidate.global_id}
    ) as run, aphase("reach_target"):
        # QEMU is single-use per gdb batch (it runs to completion and exits
        # on GDB disconnect), so relaunch a fresh one for this batch.
        await _launch_qemu_and_wait(ctx)
        await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"mkdir -p {CONTAINER_SCRATCH} && cat > {recipe_path} << 'FVVWEOF'\n{recipe}FVVWEOF",
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

    if not result.ok and _looks_like_setup_fault(result.stdout + result.stderr):
        raise DynamicFault(
            f"{ctx.candidate.global_id}: reach_target GDB/QEMU setup fault: {result.stderr}"
        )

    transcript = gdb_transcript_so_far + result.stdout + result.stderr
    # A real breakpoint HIT prints "Breakpoint N, 0x... in ..." (note the
    # comma). "Breakpoint N at 0x..." is only the SET confirmation and does
    # NOT mean control ever reached it — the old `"Breakpoint" in stdout or
    # result.ok` matched the set message (and any successful batch), a
    # false positive: on real firmware (MIPS mailosd) the entry breakpoint
    # was set but the process took SIGTERM before it fired, yet reach still
    # reported reached=True. Require an actual hit line instead.
    reached = bool(re.search(r"Breakpoint \d+, ", result.stdout))
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
    recipe_path = f"{CONTAINER_SCRATCH}/recipe_guards.gdb"
    target_relpath = _target_relpath_in_workspace(ctx.candidate)

    async with aspan(
        "stage5.satisfy_guards", run_type="tool", inputs={"global_id": ctx.candidate.global_id}
    ) as run, aphase("satisfy_guards"):
        # Fresh QEMU for this batch (single-use per gdb disconnect).
        await _launch_qemu_and_wait(ctx)
        await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"mkdir -p {CONTAINER_SCRATCH} && cat > {recipe_path} << 'FVVWEOF'\n{recipe}FVVWEOF",
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

    if not result.ok and _looks_like_setup_fault(result.stdout + result.stderr):
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

    When `ctx.raw_recipe_override` is set (HITL's "inject" action — see
    `fvvw.hitl`), that recipe text is used VERBATIM instead of the one this
    function would otherwise build, validated by `validate_injected_recipe`
    (never `validate_benign_marker`, since a raw recipe is not a bare marker
    string) before anything else happens. `_parse_trigger_capture`'s marker
    is still `"TRIGGER:sink_arg"` for the override case too, so an operator
    writing a raw recipe should reuse that same `printf` marker if they want
    `captured_sink_argument` populated from it.
    """
    if ctx.raw_recipe_override is not None:
        validate_injected_recipe(ctx.raw_recipe_override)
    else:
        validate_benign_marker(ctx.plan.payload_marker)

    arch, _ = ctx.emulation_plan.get("arch_spec_key", ("unknown", ""))
    if ctx.handle is None:
        raise DynamicFault(
            f"{ctx.candidate.global_id}: no active session to instrument_trigger on."
        )
    arch_spec = resolve_qemu_arch_spec(*ctx.emulation_plan.get("arch_spec_key", ("unknown", "")))
    register = arch_spec.arg_registers[0] if arch_spec else "$r0"

    marker = "TRIGGER:sink_arg"
    if ctx.raw_recipe_override is not None:
        recipe = ctx.raw_recipe_override
        recipe_path = f"{CONTAINER_SCRATCH}/recipe_trigger.gdb"
        target_relpath = _target_relpath_in_workspace(ctx.candidate)
        async with aspan(
            "stage5.instrument_trigger",
            run_type="tool",
            inputs={"global_id": ctx.candidate.global_id, "injected": True},
        ) as run, aphase("instrument_trigger"):
            await _launch_qemu_and_wait(ctx)
            await ctx.session_executor.exec_in_session(
                ctx.handle,
                f"mkdir -p {CONTAINER_SCRATCH} && cat > {recipe_path} << 'FVVWEOF'\n"
                f"{recipe}FVVWEOF",
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
                run.end(outputs={"ok": result.ok, "captured": captured, "injected": True})

        if not result.ok and _looks_like_setup_fault(result.stdout + result.stderr):
            raise DynamicFault(
                f"{ctx.candidate.global_id}: instrument_trigger (injected recipe) "
                f"GDB/QEMU setup fault: {result.stderr}"
            )

        transcript = gdb_transcript_so_far + result.stdout + result.stderr
        return transcript, captured

    # This is a FRESH QEMU run (see _launch_qemu_and_wait) — the guards
    # forced in `satisfy_guards`'s separate run do not carry over, so this
    # recipe must re-force them itself BEFORE the sink breakpoint, or the
    # real (blocking) guard return would stop the path from ever reaching
    # the sink and the capture would spuriously report "sink not reached".
    guard_commands: list[str] = []
    for guard in ctx.plan.guards:
        guard_commands += render_guard_breakpoint_commands(
            addr=guard.addr,
            register=register,
            forced_value=guard.forced_value,
            log_marker=f"GUARD:{guard.name}",
        )
    breakpoint_commands = guard_commands + render_trigger_breakpoint_commands(
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
    recipe_path = f"{CONTAINER_SCRATCH}/recipe_trigger.gdb"
    target_relpath = _target_relpath_in_workspace(ctx.candidate)

    async with aspan(
        "stage5.instrument_trigger",
        run_type="tool",
        inputs={"global_id": ctx.candidate.global_id},
    ) as run, aphase("instrument_trigger"):
        # Fresh QEMU for this batch (single-use per gdb disconnect).
        await _launch_qemu_and_wait(ctx)
        await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"mkdir -p {CONTAINER_SCRATCH} && cat > {recipe_path} << 'FVVWEOF'\n{recipe}FVVWEOF",
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

    if not result.ok and _looks_like_setup_fault(result.stdout + result.stderr):
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
    ) as run, aphase("collect_signals"):
        artifact_path = _marker_artifact_path(ctx.plan.payload_marker)
        if artifact_path:
            # The marker is created by the EMULATED process running under
            # `chroot .` (CONTAINER_WORKDIR as the new root — see
            # bringup_stabilize's "." comment), so an in-chroot absolute
            # path like `/tmp/claim_001_proof` actually lands at
            # `<CONTAINER_WORKDIR>/tmp/claim_001_proof` in the CONTAINER's
            # own namespace, which is where THIS check (not chrooted
            # itself) runs `test -e` from. Probing only the bare
            # `artifact_path` here was a false negative on every chrooted
            # run (i.e. every real firmware run) — probe both candidates
            # and record which one hit.
            chrooting = ctx.candidate.rootfs_dir is not None
            candidates = [artifact_path]
            if chrooting:
                candidates.append(f"{CONTAINER_WORKDIR}{artifact_path}")
            found_at: str | None = None
            for candidate_path in candidates:
                check = await ctx.session_executor.exec_in_session(
                    ctx.handle,
                    f"test -e {candidate_path} && echo FOUND || echo NOTFOUND",
                    timeout=ctx.settings.stage5_gdb_timeout_seconds,
                )
                # `"FOUND" in check.stdout` is a bug the both-path probe
                # exposed: "FOUND" is a SUBSTRING of "NOTFOUND", so that
                # check was always true regardless of which branch the
                # shell took. `.strip() == "FOUND"` is exact.
                if check.stdout.strip() == "FOUND":
                    found_at = candidate_path
                    break
            signals.append(
                {
                    "kind": "filesystem_artifact",
                    "value": artifact_path,
                    "marker_present": found_at is not None,
                    "probed": candidates,
                    "found_at": found_at,
                }
            )

        # QEMU's own stdout/stderr is captured at `_QEMU_LOG_PATH` by
        # `_launch_qemu_and_wait`'s redirect — this used to read a
        # different, never-written filename (`target_stdout.log`), which
        # made this signal permanently absent. `_QEMU_LOG_PATH` is
        # truncated on every relaunch (`>`, not `>>`) and `collect_signals`
        # always runs immediately after `instrument_trigger`'s relaunch, so
        # this holds exactly the target's output from the marker-injecting
        # run.
        self_report = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cat {_QEMU_LOG_PATH} 2>/dev/null || true",
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


async def cleanup_marker_artifact(ctx: BringupContext) -> None:
    """Remove any pre-existing benign-marker artifact BEFORE the
    reach/guards/trigger loop starts. Without this, a marker file left
    behind by an earlier run against the same rootfs (nothing ever removed
    it) makes `collect_signals`'s `filesystem_artifact` check report FOUND
    unconditionally on every later run, regardless of whether THAT run's
    sink was ever reached — a permanent false positive once the check
    itself was fixed to probe the right (in-chroot) path. Called once,
    right after bring-up succeeds, from `fvvw.graph.run_dynamic_track_only`
    — never inside the per-iteration loop, since the marker is expected to
    (re)appear as evidence within that loop.

    Best-effort: probes and removes both the pre-chroot and in-chroot
    candidate paths (same two paths `collect_signals` checks), and never
    raises — a failed cleanup should not abort the run; at worst a stale
    artifact survives and the run proceeds exactly as it did before this
    function existed."""
    if ctx.handle is None:
        return
    artifact_path = _marker_artifact_path(ctx.plan.payload_marker)
    if not artifact_path:
        return
    chrooting = ctx.candidate.rootfs_dir is not None
    candidates = [artifact_path]
    if chrooting:
        candidates.append(f"{CONTAINER_WORKDIR}{artifact_path}")
    for candidate_path in candidates:
        with contextlib.suppress(Exception):
            await ctx.session_executor.exec_in_session(
                ctx.handle,
                f"rm -f {candidate_path}",
                timeout=ctx.settings.stage5_gdb_timeout_seconds,
            )


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
        "connection timed out",
        "connection closed",
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
    evidence: dict = {"reason": reason} if reason else {}
    if verdict == VerificationVerdict.INCONCLUSIVE:
        # HITL's trigger condition (fvvw.graph.run_fvvw, see fvvw.hitl) is a
        # FACT tagged here, not an inference made later from the verdict
        # alone — a candidate could in principle reach INCONCLUSIVE some
        # other way in the future, so this stays an explicit marker rather
        # than "verdict == INCONCLUSIVE" being re-derived at the call site.
        evidence["budget_exhausted"] = True
    return {
        "route": "done",
        "result": TrackResult(
            verdict=verdict,
            proved_hypothesis=proved_hypothesis,
            evidence=evidence,
            iters_used=iteration,
        ),
    }


__all__ = [
    "BenignMarkerViolation",
    "BringupContext",
    "BringupExhausted",
    "DynamicFault",
    "bringup_stabilize",
    "cleanup_marker_artifact",
    "collect_signals",
    "dynamic_evaluate",
    "instrument_trigger",
    "plan_emulation",
    "reach_target",
    "satisfy_guards",
    "validate_benign_marker",
    "validate_injected_recipe",
]
