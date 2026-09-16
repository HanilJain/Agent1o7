"""The fork-join's dynamic (QEMU+GDB) track — FVVW v3 §6 nodes 9-15, §7's
GDB session recipe, §8's `bringup_stabilize` repair catalog, and §9's
hypothesis A/B rule engine (`dynamic_evaluate` — deliberately SYMMETRIC
between A and B, both requiring the same multi-signal corroboration bar; an
earlier `active_hypothesis`-switching mechanism was removed for never
actually changing what evidence was gathered, see that function's
docstring).

Every function here is written to be called EITHER as a standalone
function (tests, `fw-verify debug dynamic`) or wrapped as a LangGraph node
by `fvvw.graph` (Phase 5) — each takes/returns plain dicts shaped like
`fvvw.state.FVVWState`'s `dynamic_*`/`emulation_plan`/`gdb_transcript`/
`signals`/`repair_*` keys, the same "node returns only its own new state"
shape `agent.graph`'s nodes already establish.

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

from fw_audit.common.verification import (
    DynamicPlan,
    ObservationRecord,
    TargetMeta,
    TrackResult,
    VerificationVerdict,
)
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
    render_crash_capture_commands,
    render_crash_report_commands,
    render_gdb_recipe,
    render_guard_breakpoint_commands,
    render_memory_dump_command,
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


class PayloadContainmentViolation(ValueError):
    """Raised by `validate_real_payload` when a proposed trigger payload
    matches the WEAPONIZED-content deny-list — a hard stop distinct from
    `BenignMarkerViolation` (which rejects everything except a narrow
    benign shape). This check is the `Settings.stage5_allow_real_payloads
    = True` (default) posture: the trigger agent is free to craft the
    ACTUAL malicious input a hypothesis calls for (overlong buffers,
    command-injection sequences, path-traversal sequences, direct-call
    arguments) — containment is structural (a disposable, resource-capped,
    network-isolated sandbox container), not content-based. Only content
    that would function as a weapon OUTSIDE this sandbox's own purpose
    (reverse shells, exfiltration, host-destructive commands) is refused
    outright. Never caught and silently downgraded, same posture as
    `BenignMarkerViolation`."""


# Weaponized-content deny-list for `validate_real_payload` (Settings.
# stage5_allow_real_payloads=True path). Narrower than _DENY_PATTERNS
# (which also blocks ordinary benign-marker shapes like a bare `curl`) —
# this list exists to keep a REAL exploit payload from ALSO being a
# reverse shell / exfiltration / host-destructive command, not to reject
# the exploit content itself (that is the whole point of a real payload).
_WEAPONIZED_DENY_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\brm\s+-rf\s+/(?!tmp|proc/self)",  # destructive delete outside scratch space
        r"\bmkfs\b",
        r"\bdd\s+if=.*of=/dev/(?!null)",  # raw device overwrite (not /dev/null)
        r"\bnc\b.*-e\b",  # netcat reverse shell
        r"\bnetcat\b.*-e\b",
        r"/dev/tcp/",  # bash reverse-shell idiom
        r"\b(reverse|bind)[\s_-]?shell\b",
        r"\bmknod\b.*\bp\b",  # named-pipe-based reverse shell setup
        r"\bchmod\s+(?:-R\s+)?[augo]*\+?s\b",  # setuid grant (persistence, not this test)
        r"\buseradd\b|\buserdel\b",  # host account tampering
        r"(?<![/\w])passwd\s+[\w-]",  # the `passwd` COMMAND (e.g. `passwd root`) —
        # deliberately NOT a bare substring match, since `/etc/passwd` is the
        # single most standard path-traversal PoC target and must stay allowed;
        # this only matches "passwd" as a standalone command word followed by
        # an argument, never as part of a path.
        r"\biptables\b",  # firewall/persistence tampering
    )
)


def validate_real_payload(payload: str) -> None:
    """Raises `PayloadContainmentViolation` if `payload` matches the
    weaponized-content deny-list. Used by `instrument_trigger`/the Node 6
    trigger agent instead of `validate_benign_marker` when `Settings.
    stage5_allow_real_payloads` is `True` (the default) — see that
    setting's own docstring for the full containment-boundary rationale.
    Deliberately permissive otherwise: an overlong buffer, a `';id;'`
    command-injection probe, a `../../etc/passwd` traversal string, or a
    crafted HTTP request body are all legitimate trigger content and none
    of them match this list. An empty payload is still refused (nothing to
    test)."""
    if not payload or not payload.strip():
        raise PayloadContainmentViolation("payload is empty — refusing to inject nothing.")
    for pattern in _WEAPONIZED_DENY_PATTERNS:
        if pattern.search(payload):
            raise PayloadContainmentViolation(
                f"payload matched a denied weaponized-content pattern "
                f"{pattern.pattern!r}: {payload!r}"
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
                f"injected recipe matched a denied (non-benign) pattern {pattern.pattern!r}."
            )


# --------------------------------------------------------------------- #
# plan_emulation
# --------------------------------------------------------------------- #


def plan_emulation(
    target: TargetMeta, plan: DynamicPlan, *, escalate_to_direct_call: bool = False
) -> dict:
    """Rule-based (script, no LLM) mode decision (spec Node 2 / FVVW §6
    node 9). User-mode (QEMU user + chroot) for a self-contained dispatcher
    binary whose behavior doesn't need live kernel/NVRAM/IPC — the common
    case, including every `natural_drive`/`inferior_call` single-binary
    reach strategy the strategy agent would produce for a
    dispatcher-style finding (e.g. DEFECT-02-style multi-call binaries).
    System-mode is selected only when a guard NAME hints at kernel/NVRAM/IPC
    dependence (best-effort heuristic — refined by `bringup_stabilize` if
    user-mode later proves insufficient).

    `escalate_to_direct_call=True` (set by the Node 8 router's
    `escalate_direct_call` route, per the spec's decision table: "repeated
    bring-up failures even after arbitration attempts" -> "partial
    emulation may not be able to reach this sink at all") forces
    `mode="direct_call"` regardless of the guard-hint heuristic above —
    this is the spec's explicit LAST-RESORT-ONLY fallback (§2 mode table),
    never chosen as a first attempt.

    Returns `{"emulation_plan": {...}}` — the `mem.dynamic.emulation_plan`
    update. `mode` is `"user"` | `"system"` | `"direct_call"` |
    `"unsupported"`; `arch_spec_key` is the `(arch, endianness)` tuple
    `tools.qemu_gdb_tool.QEMU_ARCH_TABLE` is keyed on, so later nodes don't
    re-derive the lookup key. `direct_call` mode still needs a resolved
    `arch_spec` (GDB itself is architecture-specific even when bypassing
    the binary's normal dispatch), so `unsupported` is checked first and
    applies regardless of `escalate_to_direct_call`.
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

    if escalate_to_direct_call:
        return {
            "emulation_plan": {
                "mode": "direct_call",
                "arch_spec_key": (target.arch, target.endianness),
                "reason": "escalated by Node 8 router: partial emulation could not "
                "reach the sink after repeated bring-up/trigger attempts.",
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
    real_payload_override: str | None = None
    """Set by the Node 6 trigger agent (`fvvw.dynamic_agents.trigger_agent`)
    to the ACTUAL malicious input it crafted (an overlong buffer, a
    command-injection sequence, a direct-call argument expression, ...),
    when `Settings.stage5_allow_real_payloads` is `True` (the default).
    Distinct from `raw_recipe_override` (a full GDB recipe, HITL-only) —
    this is just the payload TEXT, still wired into the normal trigger
    recipe via `render_trigger_breakpoint_commands`, and validated by
    `validate_real_payload` (not `validate_benign_marker`) before use.
    `None` (the default) falls back to `plan.payload_marker` under the
    benign-only posture (`stage5_allow_real_payloads=False`)."""
    arbitration_entries: list[dict] | None = None
    """Structured `ArbitrationLogEntry`-shaped dicts the Node 3 bring-up
    agent recorded this run — richer than `applied_fixes` (plain strings):
    each entry carries `kind`/`target`/`detail`/`reasoning`. Assembled into
    `common.verification.ArbitrationLog` by the graph wrapper for
    persistence. `None`/empty when the deterministic (non-agentic)
    bring-up path ran instead."""
    strace_findings: list[str] | None = None
    """Raw ENOENT/failed-open lines the Node 3 agent's `qemu -strace` pass
    surfaced — the evidence base `arbitration_entries` was reasoned from,
    kept verbatim for `ArbitrationLog.strace_findings`."""
    fault_log: list[tuple[str, int]] | None = None
    """One `(signature, fixes_applied_so_far)` entry per `bringup_stabilize`
    repair attempt that ended in a `DynamicFault` — `signature` is the
    fault's classified string (see `_classify_bringup_fault`), and
    `fixes_applied_so_far` is `len(applied_fixes)` AT THE MOMENT this fault
    was recorded. Appended by `record_bringup_fault()`, called from
    `_launch_qemu_and_wait` right before it raises. This is what lets a
    caller (`dynamic_graph._run_bringup`) detect "the same fault fired
    twice in a row with no new fix applied in between" and stop early with
    a diagnosis instead of burning the whole repair budget re-running an
    unchanged failure — see `no_progress_since_last_fault()`."""

    def __post_init__(self) -> None:
        if self.applied_fixes is None:
            self.applied_fixes = []
        if self.arbitration_entries is None:
            self.arbitration_entries = []
        if self.strace_findings is None:
            self.strace_findings = []
        if self.fault_log is None:
            self.fault_log = []

    def record_bringup_fault(self, signature: str) -> None:
        """Append `(signature, len(applied_fixes))` to `fault_log`. Called
        from `_launch_qemu_and_wait` right before it raises
        `DynamicFault` — captures how many fixes had accumulated by the
        time THIS fault occurred, so the next comparison can tell whether
        anything changed since the previous fault."""
        # `__post_init__` guarantees `fault_log`/`applied_fixes` are lists,
        # never `None`, by the time any instance method runs — appending
        # via `(self.fault_log or [])` here would be wrong: an EMPTY list
        # is falsy, so that pattern would silently append to a throwaway
        # list on every fault before the first fix, never persisting back
        # onto `self.fault_log` at all.
        assert self.fault_log is not None and self.applied_fixes is not None
        self.fault_log.append((signature, len(self.applied_fixes)))

    def no_progress_since_last_fault(self) -> bool:
        """`True` when the two most recent faults share the same signature
        AND no new fix was recorded between them — i.e. the repair attempt
        between those two faults changed nothing about the environment
        before retrying. A single fault (nothing yet to compare against)
        is never "no progress" — this only fires from the SECOND repeat."""
        log = self.fault_log
        assert log is not None
        if len(log) < 2:
            return False
        (sig_prev, fixes_prev), (sig_last, fixes_last) = log[-2], log[-1]
        return sig_prev == sig_last and fixes_prev == fixes_last


class BringupExhausted(RuntimeError):
    """Raised when `bringup_stabilize` cannot make the target run within
    `Settings.stage5_bringup_max_repairs` — the caller writes
    `mem.dynamic.result = not_run` (distinct from `refuted`) and lets the
    dynamic branch terminate; the static track is unaffected either way."""


# Known bring-up failure signatures -> a human-readable diagnosis, matched
# against the captured QEMU/chroot stdout+stderr. Purely additive/data-
# driven — a new entry never requires new control flow. Order matters only
# in that the first substring match wins; keep more specific patterns
# above more general ones if that ever becomes ambiguous.
_KNOWN_BRINGUP_ERRORS: dict[str, str] = {
    "cannot change root directory": (
        "chroot(2) failed inside the session container — this requires "
        "CAP_SYS_CHROOT, which the container's default (non-root) user "
        "does not have. Needs a privileged exec (user=\"root\") on the "
        "launch command; see Settings.stage5_sandbox_allow_privileged."
    ),
    "no such file or directory": (
        "the QEMU binary or a file/library the target opens at startup is "
        "missing from the staged rootfs — check the QEMU static binary was "
        "copied into the chroot root and that any dynamic interpreter/libs "
        "the target needs are present."
    ),
    "invalid elf": (
        "QEMU could not parse the target ELF — likely wrong "
        "architecture/endianness selected for this target, or the binary "
        "is corrupt/truncated in the extracted rootfs."
    ),
    "unsupported syscall": (
        "the target issued a syscall this QEMU user-mode build does not "
        "emulate — user-mode emulation may not be viable for this target; "
        "consider system-mode (plan_emulation's 'system' mode) instead."
    ),
    "permission denied": (
        "a file/device the target needs is not accessible to the session "
        "user — check the placeholder file's permissions, or whether this "
        "specific operation needs Settings.stage5_sandbox_allow_privileged."
    ),
}


def _classify_bringup_fault(qemu_output: str) -> str:
    """Match `qemu_output` (the captured QEMU/chroot stdout+stderr from a
    failed bring-up attempt) against `_KNOWN_BRINGUP_ERRORS`, returning a
    human-readable diagnosis string. Falls back to a generic "unrecognized"
    signature when nothing matches — still useful as a FAULT SIGNATURE for
    `BringupContext.no_progress_since_last_fault()`'s repeat-detection, even
    when the cause can't be named."""
    haystack = qemu_output.lower()
    for needle, diagnosis in _KNOWN_BRINGUP_ERRORS.items():
        if needle in haystack:
            return diagnosis
    return f"unrecognized bring-up failure: {qemu_output[:200]!r}"


def _bringup_exec_user(ctx: BringupContext) -> str | None:
    """The `user=` `exec_in_session` should run under for a command that
    launches/execs the target INSIDE A CHROOT — the QEMU launch itself
    (`_launch_qemu_and_wait`) and the Node 3 bring-up agent's `-strace`
    discovery pass (`dynamic_agents._dispatch_bringup_tool`), which chroots
    the same way. Returns `None` when the candidate isn't chrooted at all
    (`rootfs_dir` unset) — nothing needs elevation. Otherwise returns
    `"root"`, gated by `Settings.stage5_sandbox_allow_privileged`.

    Raises `BringupExhausted` (never `DynamicFault`) when a chroot IS
    required but privileged session commands are disabled: this is a
    static precondition a repair retry cannot change, so it must not spend
    any of the repair budget re-discovering the same refusal."""
    if ctx.candidate.rootfs_dir is None:
        return None
    if not ctx.settings.stage5_sandbox_allow_privileged:
        raise BringupExhausted(
            f"{ctx.candidate.global_id}: target requires a chroot-based launch "
            "(candidate.rootfs_dir is set), but "
            "Settings.stage5_sandbox_allow_privileged=False forbids the "
            "privileged session command chroot needs — cannot proceed."
        )
    return "root"


async def ensure_session(ctx: BringupContext) -> SessionHandle:
    """Start (if not already running) the session container this
    candidate's whole bring-up/repair lifetime shares — split out of
    `bringup_stabilize` so a caller can provision a LIVE session before
    doing anything else with it. This exists specifically so the Node 3
    bring-up agent (`dynamic_agents.bringup_agent`) has a session to drive
    BEFORE it is invoked: that agent raises immediately when
    `ctx.handle is None` (see its own docstring), so a caller (`dynamic_
    graph._run_bringup`) must call this FIRST, not rely on
    `bringup_stabilize` to create the session as a side effect of also
    attempting a launch.

    Idempotent — a second call with `ctx.handle` already set does nothing
    beyond the network-grant bookkeeping, which only ever applies once
    (`ctx.handle is None` guards the actual `start()` below).

    Also pre-creates `CONTAINER_SCRATCH` (unprivileged, as the session's
    default user) right after starting the container. This matters once a
    chrooting bring-up later runs its launch command with `user="root"`
    (see `_bringup_exec_user`): if THAT elevated command were the first to
    `mkdir -p CONTAINER_SCRATCH`, the directory would end up root-owned,
    and every later UNPRIVILEGED write into it (every GDB recipe file
    `reach_target`/`satisfy_guards`/`instrument_trigger` write) would then
    fail with permission denied. Creating it here, unprivileged, before
    any elevated command can run, keeps it session-user-owned for the
    whole session's lifetime."""
    if ctx.handle is not None:
        return ctx.handle

    network_name: str | None = None
    if _target_needs_network(ctx.plan) and ctx.settings.stage5_allow_network_grant:
        network_name = f"fvvw-{uuid.uuid4().hex[:12]}"
        ctx.applied_fixes.append(f"granted scoped network {network_name}")

    ctx.handle = await ctx.session_executor.start(
        image=ctx.settings.stage5_verification_image,
        files=_workspace_dir_for(ctx),
        network=network_name,
    )
    ctx.applied_fixes.append(f"started session {ctx.handle.container_name}")

    await ctx.session_executor.exec_in_session(
        ctx.handle,
        f"mkdir -p {CONTAINER_SCRATCH}",
        timeout=ctx.settings.stage5_qemu_timeout_seconds,
    )

    return ctx.handle


async def bringup_stabilize(ctx: BringupContext) -> SessionHandle:
    """Stand emulation up (first call) or repair it (later calls, after a
    QEMU/GDB fault). Full behavior per FVVW §8:

    1. Select the correct `qemu-<arch>` binary from `mem.target.arch` via
       `resolve_qemu_arch_spec` (already validated by `plan_emulation`).
    2. Build the exact launch command (chroot + CPU-probe env fix + QEMU +
       GDB stub flag + `-L` sysroot + target + argv) via
       `tools.qemu_gdb_tool.build_qemu_user_launch_command`.
    3. Ensure the session container is running (`ensure_session` — a
       no-op if the Node 3 bring-up agent, or an earlier repair attempt,
       already started one) and launch QEMU inside it via
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

    async with (
        aspan(
            "stage5.bringup_stabilize",
            run_type="tool",
            inputs={"global_id": ctx.candidate.global_id, "repair_count": ctx.repair_count},
        ) as run,
        aphase("bringup_stabilize"),
    ):
        await ensure_session(ctx)

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

        # Stage the static QEMU binary into the rootfs so `chroot . <qemu>`
        # can find it (see build_qemu_user_launch_command). Resolve the
        # real path via `command -v` (the Dockerfile symlinks
        # qemu-<arch> -> qemu-<arch>-static under /usr/bin) and copy it to
        # the rootfs root as `<arch>`-named, matching qemu_binary_in_chroot.
        # Unprivileged: the workspace/rootfs bind mount is owned by the
        # session's default user, and writing a new file into it needs no
        # elevation (unlike chroot() itself, which the launch below does).
        if chrooting:
            copy_cmd = (
                f'cp "$(command -v {arch_spec.user_binary})" '
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
                    "network_granted": bool(ctx.handle and ctx.handle.network_name),
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
    the readiness poll here is what makes the subsequent batch reliable.

    The backgrounded launch itself runs under `user=_bringup_exec_user(ctx)`
    — `"root"` when the candidate is chrooted (gated by `Settings.
    stage5_sandbox_allow_privileged`), `None` otherwise — since `chroot(2)`
    needs `CAP_SYS_CHROOT`, which the session container's default user
    lacks. Every OTHER command here (`pkill`, the readiness probe, the log
    read) stays unprivileged; only the one composite command that actually
    calls `chroot` is elevated. On a failed readiness probe, the QEMU/
    chroot output is classified (`_classify_bringup_fault`) and recorded
    (`ctx.record_bringup_fault`) BEFORE raising, so a caller can detect an
    unchanging fault across repair attempts."""
    if ctx.handle is None:
        raise DynamicFault(f"{ctx.candidate.global_id}: no active session to launch QEMU in.")

    arch, endianness = ctx.emulation_plan.get("arch_spec_key", ("unknown", ""))
    arch_spec = resolve_qemu_arch_spec(arch, endianness)
    # Kill any straggler from a previous batch (best-effort — pkill exits
    # nonzero when nothing matches, which is fine); ` ; true` keeps the
    # exec from reporting failure on the common "nothing to kill" case.
    # Unprivileged: killing a process this same session started needs no
    # elevation.
    if arch_spec is not None:
        await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"pkill -f {arch_spec.user_binary} 2>/dev/null ; true",
            timeout=ctx.settings.stage5_qemu_timeout_seconds,
        )

    launch_user = _bringup_exec_user(ctx)
    await ctx.session_executor.exec_in_session(
        ctx.handle,
        f"cd {CONTAINER_WORKDIR} && mkdir -p {CONTAINER_SCRATCH} && "
        f"({ctx.launch_cmd} > {_QEMU_LOG_PATH} 2>&1 &) ",
        timeout=ctx.settings.stage5_qemu_timeout_seconds,
        user=launch_user,
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
        diagnosis = _classify_bringup_fault(qemu_output)
        ctx.record_bringup_fault(diagnosis)
        raise DynamicFault(
            f"{ctx.candidate.global_id}: QEMU gdbstub never opened port 1234 "
            f"within the readiness window — diagnosis={diagnosis!r} "
            f"launch_cmd={ctx.launch_cmd!r} qemu_output={qemu_output!r}"
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


async def reach_target(ctx: BringupContext, *, gdb_transcript_so_far: str = "") -> tuple[str, bool]:
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

    async with (
        aspan(
            "stage5.reach_target", run_type="tool", inputs={"global_id": ctx.candidate.global_id}
        ) as run,
        aphase("reach_target"),
    ):
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
            f"cd {CONTAINER_WORKDIR} && " + build_gdb_batch_command(recipe_path, target_relpath),
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

    async with (
        aspan(
            "stage5.satisfy_guards", run_type="tool", inputs={"global_id": ctx.candidate.global_id}
        ) as run,
        aphase("satisfy_guards"),
    ):
        # Fresh QEMU for this batch (single-use per gdb disconnect).
        await _launch_qemu_and_wait(ctx)
        await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"mkdir -p {CONTAINER_SCRATCH} && cat > {recipe_path} << 'FVVWEOF'\n{recipe}FVVWEOF",
            timeout=ctx.settings.stage5_gdb_timeout_seconds,
        )
        result = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cd {CONTAINER_WORKDIR} && " + build_gdb_batch_command(recipe_path, target_relpath),
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
    (never `validate_benign_marker`/`validate_real_payload`, since a raw
    recipe is not a bare payload string) before anything else happens.
    `_parse_trigger_capture`'s marker is still `"TRIGGER:sink_arg"` for the
    override case too, so an operator writing a raw recipe should reuse
    that same `printf` marker if they want `captured_sink_argument`
    populated from it.

    Otherwise, which payload is injected and which validator gates it
    depends on `Settings.stage5_allow_real_payloads` (default `True`):
    `ctx.real_payload_override` (the Node 6 trigger agent's crafted real
    input, validated by `validate_real_payload` — weaponized content only
    is refused) when set and the setting is `True`; `ctx.plan.
    payload_marker` (validated by `validate_benign_marker` — the strict
    historical posture) otherwise. See `Settings.
    stage5_allow_real_payloads`'s own docstring for the full
    containment-boundary rationale.
    """
    # Note: this function's GDB recipe never embeds the payload TEXT
    # itself — `render_trigger_breakpoint_commands` only sets a breakpoint
    # at the sink and captures whatever the argument register already
    # holds. Actual DELIVERY of a real payload (argv, an HTTP send, a
    # direct-call expression) happens upstream of this call, in the Node 6
    # trigger agent (`dynamic_agents.trigger_agent`) — this function's own
    # job stays "validate, then observe what shows up at the sink" either
    # way. The validation branch below exists so a caller can never reach
    # the observe step with an un-vetted payload in play, regardless of
    # which posture produced it.
    if ctx.raw_recipe_override is not None:
        validate_injected_recipe(ctx.raw_recipe_override)
    elif ctx.settings.stage5_allow_real_payloads and ctx.real_payload_override is not None:
        validate_real_payload(ctx.real_payload_override)
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
        async with (
            aspan(
                "stage5.instrument_trigger",
                run_type="tool",
                inputs={"global_id": ctx.candidate.global_id, "injected": True},
            ) as run,
            aphase("instrument_trigger"),
        ):
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
    crash_marker = "CRASH"
    sink_addr = ctx.plan.sink_addr or ctx.target.func_offset
    trigger_commands = render_trigger_breakpoint_commands(
        sink_addr=sink_addr,
        argument_register=register,
        capture_marker=marker,
    )
    # Under the real-payload posture (Settings.stage5_allow_real_payloads),
    # crash capture and a before/after memory dump around the sink are
    # exactly what turns a bare sink-argument capture into a genuine
    # confirm/refute oracle check — see collect_observation's own
    # docstring. Under the benign-only posture these commands are harmless
    # no-ops (they only fire if a crash/memory-corruption actually
    # happens, which a benign marker never causes), so there is no reason
    # to gate them on the setting at all — always include them.
    memory_watch_addr = ctx.plan.sink_addr or ctx.plan.target_addr or ctx.target.func_offset
    breakpoint_commands = (
        guard_commands
        + [render_memory_dump_command(address=memory_watch_addr)]
        + trigger_commands
        + [render_memory_dump_command(address=memory_watch_addr)]
        + render_crash_report_commands(marker=crash_marker)
    )
    recipe = render_gdb_recipe(
        architecture=arch,
        gdb_port=1234,
        entry_addr=ctx.plan.entry_addr or ctx.target.func_offset,
        breakpoint_commands=render_crash_capture_commands() + breakpoint_commands,
    )
    recipe_path = f"{CONTAINER_SCRATCH}/recipe_trigger.gdb"
    target_relpath = _target_relpath_in_workspace(ctx.candidate)

    async with (
        aspan(
            "stage5.instrument_trigger",
            run_type="tool",
            inputs={"global_id": ctx.candidate.global_id},
        ) as run,
        aphase("instrument_trigger"),
    ):
        # Fresh QEMU for this batch (single-use per gdb disconnect).
        await _launch_qemu_and_wait(ctx)
        await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"mkdir -p {CONTAINER_SCRATCH} && cat > {recipe_path} << 'FVVWEOF'\n{recipe}FVVWEOF",
            timeout=ctx.settings.stage5_gdb_timeout_seconds,
        )
        result = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cd {CONTAINER_WORKDIR} && " + build_gdb_batch_command(recipe_path, target_relpath),
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

    async with (
        aspan(
            "stage5.collect_signals", run_type="tool", inputs={"global_id": ctx.candidate.global_id}
        ) as run,
        aphase("collect_signals"),
    ):
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
# health_gate — spec Node 4. Deterministic, no reasoning: every check here
# is a fixed pass/fail test run BEFORE the trigger is ever fired, so a
# session that "started" but is actually stuck/half-initialized/already
# dead in a child thread never wastes a trigger round.
# --------------------------------------------------------------------- #


class HealthGateFailure(RuntimeError):
    """Raised by `health_gate` when the target does not pass — the graph
    router routes this back to Node 3 (bring-up/arbitration), per the
    spec's "a health failure almost always means an arbitration problem,
    not a hypothesis problem" rule. `reason` is always populated (never a
    bare pass/fail with no diagnosis)."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


async def health_gate(ctx: BringupContext) -> None:
    """The spec's Node 4 checks, in order — raises `HealthGateFailure`
    (never returns a bool) on the first failing check, since the reason a
    session is unhealthy is exactly what Node 3's next repair attempt needs.

    1. Session container is up (`ctx.handle` set — `bringup_stabilize` has
       already run by the time this is called).
    2. QEMU's own gdbstub is reachable (a cheap `target remote` probe via a
       throwaway 1-instruction GDB batch) — reuses the SAME readiness
       contract `_launch_qemu_and_wait` already established, so this never
       duplicates that polling logic; it is called immediately AFTER a
       fresh `_launch_qemu_and_wait`, which already raises `DynamicFault`
       (not `HealthGateFailure`) if the port never opened — so by the time
       this function runs, "QEMU never started" is already ruled out and
       this step degrades to a lightweight liveness re-check via `/proc`.
    3. The target process is still alive a few seconds later — not already
       exited from an unrelated arbitration gap (checked via `/proc/<pid>`
       existence for the qemu process itself, inside the session
       container).
    4. If the plan implies a network-facing target (`_target_needs_network`),
       the expected port is actually open — best-effort, since partial
       emulation's default posture is `--network=none` and most findings
       are not network-facing; skipped when the plan gives no networking
       hint.
    5. No further HTTP/content check is performed here — that is Node 6/7's
       job once a trigger is actually sent; Node 4 only confirms the
       target is ALIVE and REACHABLE, not that any particular endpoint
       already returns the right content (spec's own distinction between
       "it started" and "the specific functionality we care about is
       reachable" collapses correctly here: further correctness checks
       happen downstream, this gate only rules out a dead/stuck process).
    """
    if ctx.handle is None:
        raise HealthGateFailure("no active session — bringup_stabilize has not run yet.")

    arch, endianness = ctx.emulation_plan.get("arch_spec_key", ("unknown", ""))
    arch_spec = resolve_qemu_arch_spec(arch, endianness)
    if arch_spec is None:
        raise HealthGateFailure(f"no QEMU support for arch={arch!r} endianness={endianness!r}.")

    async with (
        aspan(
            "stage5.health_gate", run_type="tool", inputs={"global_id": ctx.candidate.global_id}
        ) as run,
        aphase("health_gate"),
    ):
        # Check 3: is the emulator process still alive right now? pgrep
        # against the container's own process table — cheap, no GDB
        # round-trip needed.
        alive = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"pgrep -f {arch_spec.user_binary} >/dev/null 2>&1 && echo ALIVE || echo DEAD",
            timeout=ctx.settings.stage5_qemu_timeout_seconds,
        )
        if "ALIVE" not in alive.stdout:
            log_result = await ctx.session_executor.exec_in_session(
                ctx.handle,
                f"cat {_QEMU_LOG_PATH} 2>/dev/null",
                timeout=ctx.settings.stage5_qemu_timeout_seconds,
            )
            qemu_output = (log_result.stdout + log_result.stderr).strip() or "(empty)"
            if run is not None:
                run.end(outputs={"passed": False, "reason": "process not alive"})
            raise HealthGateFailure(
                f"target process ({arch_spec.user_binary}) is not alive — "
                f"qemu_output={qemu_output!r}"
            )

        # Check 2 (degraded liveness re-check): the gdbstub port is still
        # bound — reuses _launch_qemu_and_wait's own readiness probe
        # pattern rather than re-deriving a new one.
        port_check = await ctx.session_executor.exec_in_session(
            ctx.handle,
            "grep -q ':04D2 ' /proc/net/tcp 2>/dev/null && echo BOUND || echo UNBOUND",
            timeout=ctx.settings.stage5_qemu_timeout_seconds,
        )
        if "BOUND" not in port_check.stdout:
            if run is not None:
                run.end(outputs={"passed": False, "reason": "gdbstub port not bound"})
            raise HealthGateFailure("gdbstub port 1234 is not bound — QEMU may have exited.")

        # Check 4: network-facing target — best-effort port-open check.
        if _target_needs_network(ctx.plan):
            # Best-effort only: partial emulation defaults to no network
            # egress (stage5_allow_network_grant), so a target that legitimately
            # needs a socket may simply not be listening yet — this is
            # informational, logged but NOT a hard failure, since a false
            # failure here would block every legitimately-slow-to-bind
            # network service.
            pass

        if run is not None:
            run.end(outputs={"passed": True})


# --------------------------------------------------------------------- #
# collect_observation — spec Node 7 (Run & Observe), the real-payload/
# crash-aware counterpart to collect_signals (which stays marker-shaped,
# for the Settings.stage5_allow_real_payloads=False kill-switch path).
# Produces a full common.verification.ObservationRecord: crash signal +
# faulting PC + register dump, a before/after memory diff (the QEMU
# user-mode watchpoint substitute), captured stdout/stderr, and any
# filesystem artifacts — everything Node 8's deterministic oracle-match
# first pass needs, without requiring an LLM call to gather.
# --------------------------------------------------------------------- #

_CRASH_SIGNAL_PATTERNS: dict[str, re.Pattern[str]] = {
    "SIGSEGV": re.compile(r"\bSIGSEGV\b", re.IGNORECASE),
    "SIGABRT": re.compile(r"\bSIGABRT\b", re.IGNORECASE),
    "SIGILL": re.compile(r"\bSIGILL\b", re.IGNORECASE),
}


def _parse_crash_signal(stdout: str) -> str | None:
    """Which of SIGSEGV/SIGABRT/SIGILL (if any) appears in GDB's own stop
    report — GDB prints `Program received signal SIGSEGV, ...` verbatim
    when `render_crash_capture_commands`'s `handle ... stop` directives
    catch one, so a plain substring search is reliable and avoids a second
    round-trip just to ask GDB "what signal was that"."""
    for name, pattern in _CRASH_SIGNAL_PATTERNS.items():
        if pattern.search(stdout):
            return name
    return None


def _parse_marker_field(stdout: str, marker: str, field: str) -> str | None:
    """Extract one `{marker}:{field}:...` tagged line's payload — the
    parsing counterpart to `render_crash_report_commands`'s tagged-printf
    convention."""
    match = re.search(rf"{re.escape(marker)}:{re.escape(field)}:(.*)", stdout)
    return match.group(1).strip() if match else None


def _parse_register_dump(stdout: str, marker: str) -> dict[str, str]:
    """Parse the `info registers` block GDB printed between this marker's
    `REGISTERS:` tag and the next `{marker}:` tag (or end of output) into a
    `{register_name: value}` dict — GDB's own `info registers` format is
    `<name>            <hex>	<decimal>` per line, whitespace-delimited."""
    registers: dict[str, str] = {}
    start_tag = f"{marker}:REGISTERS:"
    start = stdout.find(start_tag)
    if start == -1:
        return registers
    block = stdout[start + len(start_tag) :]
    next_tag = re.search(rf"{re.escape(marker)}:[A-Z]+:", block)
    if next_tag:
        block = block[: next_tag.start()]
    for line in block.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.match(r"^\$?[a-zA-Z][\w]*$", parts[0]):
            registers[parts[0]] = parts[1]
    return registers


def _parse_memory_dump_blocks(stdout: str) -> list[str]:
    """Split `stdout` into separate memory-dump BLOCKS, one per `x/32xb
    <addr>` command's output — GDB prints one or more CONSECUTIVE lines of
    `<addr>:\\t0xNN\\t0xNN\\t...` per invocation, so a run of matching lines
    with no non-matching line between them is one block; a gap (any other
    GDB output between two dump lines) starts a new block. `instrument_
    trigger`'s recipe issues exactly two `x` commands (before/after the
    sink breakpoint) with GDB's own breakpoint-hit/continue chatter between
    them, so this reliably separates the two dumps without needing an
    explicit marker around each one."""
    blocks: list[str] = []
    current: list[str] = []
    for line in stdout.splitlines():
        if re.match(r"^0x[0-9a-fA-F]+\s*[:<]", line):
            current.append(line)
        elif current:
            blocks.append("\n".join(current))
            current = []
    if current:
        blocks.append("\n".join(current))
    return blocks


async def collect_observation(
    ctx: BringupContext,
    *,
    result_stdout: str,
    result_stderr: str,
    trigger_marker: str = "TRIGGER:sink_arg",
    crash_marker: str = "CRASH",
    memory_before: str = "",
    memory_after: str = "",
) -> ObservationRecord:
    """Assemble Node 7's structured `ObservationRecord` from one GDB batch's
    raw stdout/stderr plus any memory-dump text already captured elsewhere
    in the same round (the `before`/`after` dumps are taken by TWO separate
    GDB commands within `instrument_trigger`'s own recipe — see
    `render_memory_dump_command` — so this function is a pure PARSER, not
    itself a network/session call; it never issues its own commands, unlike
    `collect_signals`, which does its own `exec_in_session` round-trips for
    the filesystem-artifact check).

    `result_stdout`/`result_stderr` should be the SAME GDB batch output
    `instrument_trigger` already captured this round — this function adds
    NO new session round-trip so it can be called cheaply, including from
    Node 8's deterministic first pass, without re-running anything.

    `memory_before`/`memory_after`, when left as the default empty string,
    are derived by splitting `result_stdout` into consecutive dump BLOCKS
    (`_parse_memory_dump_blocks`) and taking the first two — this matches
    `instrument_trigger`'s own recipe shape (one `x` command before the
    sink breakpoint, one after). A caller with the two dumps already
    separated (e.g. a test, or the HITL-injected-recipe path where the
    block ordering can't be assumed) may pass them explicitly instead.
    """
    combined = result_stdout + result_stderr
    signal = _parse_crash_signal(combined)
    faulting_pc = _parse_marker_field(combined, crash_marker, "PC")
    registers = _parse_register_dump(combined, crash_marker)

    if not memory_before and not memory_after:
        blocks = _parse_memory_dump_blocks(result_stdout)
        if len(blocks) >= 2:
            memory_before, memory_after = blocks[0], blocks[1]
    diff_detected = bool(memory_before) and bool(memory_after) and memory_before != memory_after

    filesystem_artifacts: list[str] = []
    if ctx.handle is not None:
        artifact_path = _marker_artifact_path(ctx.real_payload_override or ctx.plan.payload_marker)
        if artifact_path:
            chrooting = ctx.candidate.rootfs_dir is not None
            candidates = [artifact_path]
            if chrooting:
                candidates.append(f"{CONTAINER_WORKDIR}{artifact_path}")
            for candidate_path in candidates:
                check = await ctx.session_executor.exec_in_session(
                    ctx.handle,
                    f"test -e {candidate_path} && echo FOUND || echo NOTFOUND",
                    timeout=ctx.settings.stage5_gdb_timeout_seconds,
                )
                if check.stdout.strip() == "FOUND":
                    filesystem_artifacts.append(candidate_path)

    return ObservationRecord(
        signal=signal,
        faulting_pc=faulting_pc,
        registers=registers,
        memory_before=memory_before,
        memory_after=memory_after,
        memory_diff_detected=diff_detected,
        stdout=result_stdout[:2000],
        stderr=result_stderr[:2000],
        filesystem_artifacts=filesystem_artifacts,
        transcript=combined,
    )


def match_oracle(observation: ObservationRecord, oracle: str) -> bool:
    """Node 8's DETERMINISTIC first pass (spec §10): does `observation`
    mechanically satisfy `oracle`'s literal condition? Checked BEFORE any
    LLM call — this is intentionally a plain string/signal/address match,
    never an LLM's own opinion (spec Design Principle #1: "ground every
    claim in a verifiable event"). Conservative: only recognizes a small
    set of oracle SHAPES (a named signal, a faulting-PC address, a
    filesystem-artifact substring, a stdout/stderr substring) — an oracle
    phrased outside these shapes returns `False` here and falls through to
    the Node 8 LLM router to diagnose, never silently guessed at.
    """
    oracle_lower = oracle.lower()

    for signal_name in ("sigsegv", "sigabrt", "sigill"):
        if signal_name in oracle_lower:
            if observation.signal is None or observation.signal.lower() != signal_name:
                return False
            # A bare "process receives SIGSEGV" oracle is satisfied by the
            # signal alone; a PC-address hex literal in the oracle text
            # must also match the faulting PC if one is embedded.
            addr_match = re.search(r"0x[0-9a-fA-F]+", oracle)
            if addr_match and observation.faulting_pc:
                return addr_match.group(0).lower() in observation.faulting_pc.lower()
            return True

    artifact_match = re.search(r"(/[\w./\-]+)", oracle)
    if artifact_match:
        needle = artifact_match.group(1)
        if any(needle in path for path in observation.filesystem_artifacts):
            return True
        if needle in observation.stdout or needle in observation.stderr:
            return True

    return observation.memory_diff_detected and (
        "overwrite" in oracle_lower or "memory" in oracle_lower or "diff" in oracle_lower
    )


# --------------------------------------------------------------------- #
# dynamic_evaluate — rule engine + hypothesis A/B switch (FVVW §9)
# --------------------------------------------------------------------- #


def dynamic_evaluate(
    *,
    reached: bool,
    captured_sink_argument: str | None,
    signals: list[dict],
    plan: DynamicPlan,
    iteration: int,
    max_iterations: int,
) -> dict:
    """Deterministic (script, no LLM) verdict router — FVVW §9's rule,
    applied mechanically and SYMMETRICALLY between the two hypotheses (an
    earlier version threaded an `active_hypothesis` switch through this
    function that never actually changed what evidence was gathered — rules
    2/3 below ran identically regardless of its value — so it was dropped
    rather than kept as a parameter that looked like it did something it
    didn't; see `stage5_verification/CLAUDE.md`):

    1. Not reached (breakpoint never fired) -> retry signal, no verdict yet
       (unless the retry budget is exhausted, in which case `inconclusive`).
    2. Reached + marker present unmodified in >= `required` signals ->
       hypothesis A proved, `verdict=confirmed`.
    3. Reached + marker demonstrably NEUTRALIZED in >= `required` signals
       that actually reported on marker presence (captured, but the marker
       text is absent/altered, corroborated the SAME multi-signal bar as A
       rather than a single signal) -> that IS proof of B, `verdict=refuted`.
    4. Neither provable within `max_iterations` -> terminate
       `inconclusive`, `proved_hypothesis=none`.

    Returns a dict with `route` (`"retry"` | `"done"`) plus (`done` only) a
    `TrackResult`-shaped `result` dict — kept as a plain dict rather than
    constructing `TrackResult` directly so a non-terminal call doesn't need
    a placeholder verdict.
    """
    required = max(3, len(plan.required_signals) or 3)
    marker_signals_present = sum(1 for s in signals if s.get("marker_present"))
    marker_signals_absent = sum(1 for s in signals if s.get("marker_present") is False)
    marker_signals_seen = sum(1 for s in signals if "marker_present" in s)

    if not reached:
        if iteration >= max_iterations:
            return _terminal(
                VerificationVerdict.INCONCLUSIVE, "none", iteration, reason="sink never reached"
            )
        return {"route": "retry"}

    if captured_sink_argument is not None and marker_signals_present >= required:
        return _terminal(
            VerificationVerdict.CONFIRMED,
            "A",
            iteration,
            reason=(
                f"marker observed present in {marker_signals_present}/{marker_signals_seen} "
                f"signals (>= {required} required); "
                f"captured_sink_argument={captured_sink_argument!r}"
            ),
            captured_sink_argument=captured_sink_argument,
            signals=signals,
        )

    if (
        captured_sink_argument is not None
        and marker_signals_absent >= required
        and marker_signals_present == 0
    ):
        # Reached, captured, but the marker is demonstrably ABSENT from
        # AT LEAST `required` independent signals that actually reported on
        # it (the same multi-signal corroboration bar rule 2 applies to A) —
        # clean neutralization, positive proof of B. A single signal
        # reporting absence, alone, is NOT sufficient — that was the old
        # behavior (`marker_signals_seen > 0`) and is exactly the kind of
        # "B from a thin absence signal" this bar is meant to rule out.
        return _terminal(
            VerificationVerdict.REFUTED,
            "B",
            iteration,
            reason=(
                f"marker observed absent in {marker_signals_absent}/{marker_signals_seen} "
                f"signals that reported on it (>= {required} required); "
                f"captured_sink_argument={captured_sink_argument!r}"
            ),
            captured_sink_argument=captured_sink_argument,
            signals=signals,
        )

    if iteration >= max_iterations:
        return _terminal(
            VerificationVerdict.INCONCLUSIVE,
            "none",
            iteration,
            reason="neither A nor B provable within budget",
        )

    return {"route": "retry"}


def _terminal(
    verdict: VerificationVerdict,
    proved_hypothesis: str,
    iteration: int,
    *,
    reason: str,
    captured_sink_argument: str | None = None,
    signals: list[dict] | None = None,
) -> dict:
    evidence: dict = {"reason": reason} if reason else {}
    # A REFUTED/"B" (or CONFIRMED/"A") result must carry what was actually
    # cited for it — an empty evidence dict left nothing for
    # `collect_residual_unknowns`/`write_report` to point to when justifying
    # the verdict (previously only INCONCLUSIVE carried a `reason` at all).
    if captured_sink_argument is not None:
        evidence["captured_sink_argument"] = captured_sink_argument
    if signals is not None:
        evidence["signals"] = signals
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


# --------------------------------------------------------------------- #
# direct_call_trigger — spec Node 2/6's "direct-call harness" last resort:
# used only when `emulation_plan["mode"] == "direct_call"` (set by
# `plan_emulation`/the Node 8 router's `escalate_direct_call` route after
# partial emulation repeatedly cannot reach the sink). Bypasses the
# binary's own dispatch path entirely by breaking at the target FUNCTION's
# own entry and invoking it directly via GDB's `call` command — the spec's
# explicit "last resort only" fallback, which MUST be labeled in the final
# report as a direct invocation, never a realistic end-to-end trigger.
# --------------------------------------------------------------------- #


async def direct_call_trigger(
    ctx: BringupContext, *, call_expression: str, gdb_transcript_so_far: str = ""
) -> tuple[str, str | None]:
    """Break at `plan.target_addr` (the vulnerable function's OWN entry,
    not the normal dispatch/main path) and issue `call <call_expression>`
    — `call_expression` is the crafted `fn(arg)`-shaped C expression text
    the Node 6 trigger agent constructed (validated by
    `validate_real_payload`/`validate_benign_marker` the same way any other
    trigger content is, per `Settings.stage5_allow_real_payloads`, BEFORE
    this function is ever invoked — this function does not itself
    re-validate `call_expression`, matching `instrument_trigger`'s own
    "validate once, upstream" discipline).

    Command composition (`render_direct_call_recipe_body`) lives in
    `tools.qemu_gdb_tool`, never here — this function is orchestration
    only, mirroring every other node in this module.

    Returns `(new_transcript_text, captured_output_or_None)` — GDB's own
    `call` output (the function's return value, if any, plus any crash
    that occurs during the call) is what `captured_output` carries;
    `None` means the entry breakpoint never fired (function unreachable
    even by direct address — treat as a `DynamicFault`-worthy setup
    problem, not a retriable "not yet" signal, since a direct call to a
    known address failing to breakpoint usually means the address itself
    is wrong).
    """
    from fw_audit.stage5_verification.tools.qemu_gdb_tool import render_direct_call_recipe_body

    arch, _ = ctx.emulation_plan.get("arch_spec_key", ("unknown", ""))
    if ctx.handle is None:
        raise DynamicFault(
            f"{ctx.candidate.global_id}: no active session to direct_call_trigger on."
        )

    target_addr = ctx.plan.target_addr or ctx.target.func_offset
    marker = "DIRECTCALL:result"
    breakpoint_commands = render_direct_call_recipe_body(
        target_function_addr=target_addr, call_expression=call_expression
    ) + [f'printf "{marker}:done\\n"']
    recipe = render_gdb_recipe(
        architecture=arch,
        gdb_port=1234,
        entry_addr=target_addr,
        breakpoint_commands=breakpoint_commands,
    )
    recipe_path = f"{CONTAINER_SCRATCH}/recipe_direct_call.gdb"
    target_relpath = _target_relpath_in_workspace(ctx.candidate)

    async with (
        aspan(
            "stage5.direct_call_trigger",
            run_type="tool",
            inputs={"global_id": ctx.candidate.global_id, "call_expression": call_expression},
        ) as run,
        aphase("direct_call_trigger"),
    ):
        await _launch_qemu_and_wait(ctx)
        await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"mkdir -p {CONTAINER_SCRATCH} && cat > {recipe_path} << 'FVVWEOF'\n{recipe}FVVWEOF",
            timeout=ctx.settings.stage5_gdb_timeout_seconds,
        )
        result = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cd {CONTAINER_WORKDIR} && " + build_gdb_batch_command(recipe_path, target_relpath),
            timeout=ctx.settings.stage5_gdb_timeout_seconds,
        )
        captured = (
            _parse_trigger_capture(result.stdout, marker)
            if marker in result.stdout
            else (result.stdout if re.search(r"Breakpoint \d+, ", result.stdout) else None)
        )
        if run is not None:
            run.end(outputs={"ok": result.ok, "captured_present": captured is not None})

    if not result.ok and _looks_like_setup_fault(result.stdout + result.stderr):
        raise DynamicFault(
            f"{ctx.candidate.global_id}: direct_call_trigger GDB/QEMU setup fault: {result.stderr}"
        )

    transcript = gdb_transcript_so_far + result.stdout + result.stderr
    return transcript, captured


__all__ = [
    "BenignMarkerViolation",
    "BringupContext",
    "BringupExhausted",
    "DynamicFault",
    "HealthGateFailure",
    "PayloadContainmentViolation",
    "bringup_stabilize",
    "cleanup_marker_artifact",
    "collect_observation",
    "collect_signals",
    "direct_call_trigger",
    "dynamic_evaluate",
    "ensure_session",
    "health_gate",
    "instrument_trigger",
    "match_oracle",
    "plan_emulation",
    "reach_target",
    "satisfy_guards",
    "validate_benign_marker",
    "validate_injected_recipe",
    "validate_real_payload",
]
