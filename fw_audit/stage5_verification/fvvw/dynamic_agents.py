"""The dynamic track's three agentic tool-calling loops — spec Node 3
(Bring-Up & Arbitration), Node 6 (Trigger / PoC), and Node 8's LLM router
(invoked only when the deterministic oracle-match first pass doesn't
settle a round). Each is a bounded ReAct-shaped cycle: the LLM proposes
ONE action as JSON per turn (`fvvw.dynamic_prompts`' tool vocabulary,
parsed via the SAME `agent.cleaning.clean_json_payload` discipline
`fvvw.strategy` already established); a deterministic dispatcher in THIS
module `await`s that action against the persistent session container
(`ctx.session_executor.exec_in_session`); the result is appended to the
loop's own transcript and shown back to the LLM next turn.

This is the "QEMU+GDB session driven async by the agents that need it"
requirement: every tool dispatch here is an `await` against the SAME
`BringupContext.handle`/`session_executor` the rest of `fvvw.dynamic_track`
already uses — no new session model, no synchronous blocking call anywhere
in these loops.

Command composition for every QEMU/GDB invocation still lives entirely in
`tools.qemu_gdb_tool` — these loops call into `fvvw.dynamic_track`'s own
node functions (`_launch_qemu_and_wait`, `instrument_trigger`, GDB batch
helpers) and `tools.qemu_gdb_tool`'s builders directly, never construct a
shell command line inline. The LLM never sees or writes a shell command —
only the tool-call JSON `{tool, args}` shape.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

from fw_audit.common.verification import (
    ArbitrationLog,
    ArbitrationLogEntry,
    DynamicPlan,
    ObservationRecord,
    RouteDecision,
    TargetMeta,
)
from fw_audit.config.settings import Settings
from fw_audit.observability import run_config
from fw_audit.stage5_verification.agent.cleaning import clean_json_payload
from fw_audit.stage5_verification.cmdlog import aphase
from fw_audit.stage5_verification.fvvw.dynamic_prompts import (
    BRINGUP_AGENT_SYSTEM_PROMPT,
    DYNAMIC_ROUTER_SYSTEM_PROMPT,
    TRIGGER_AGENT_SYSTEM_PROMPT,
    render_bringup_brief,
    render_router_brief,
    render_trigger_brief,
)
from fw_audit.stage5_verification.fvvw.dynamic_track import (
    BenignMarkerViolation,
    BringupContext,
    DynamicFault,
    PayloadContainmentViolation,
    _launch_qemu_and_wait,
    _target_relpath_in_workspace,
    collect_observation,
    instrument_trigger,
    resolve_qemu_arch_spec,
    validate_benign_marker,
    validate_real_payload,
)
from fw_audit.stage5_verification.tools.qemu_gdb_tool import (
    CONTAINER_WORKDIR,
    build_qemu_strace_command,
)


def _parse_action(raw: object) -> dict | None:
    """Parse one LLM turn's action JSON via the SAME cleaning pipeline
    every other Stage 5 LLM call site uses — returns `None` (never raises)
    on unparseable output, exactly like `strategy.parse_strategy_response`.
    """
    payload = clean_json_payload(raw)
    if payload is None:
        return None
    try:
        parsed = json.loads(payload)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict) or "tool" not in parsed:
        return None
    return parsed


# --------------------------------------------------------------------- #
# Node 3 — bringup_agent
# --------------------------------------------------------------------- #


@dataclass
class BringupAgentResult:
    """What `bringup_agent` hands back to `bringup_stabilize`/the dynamic
    graph: the structured arbitration log plus whether the agent itself
    believes bring-up succeeded (still subject to the deterministic
    `health_gate` check downstream — an agent's own "done" belief is never
    trusted as the final health signal)."""

    arbitration_log: ArbitrationLog
    applied_fixes: list[str]
    believes_ready: bool
    summary: str


async def bringup_agent(
    ctx: BringupContext,
    *,
    llm: BaseChatModel,
    settings: Settings,
    max_steps: int | None = None,
) -> BringupAgentResult:
    """Run the Node 3 bring-up/arbitration loop for one invocation (one
    pass through the strace-discover-fix-relaunch cycle, bounded by
    `Settings.stage5_bringup_agent_max_steps`). Distinct from
    `bringup_stabilize`'s own repair-count budget
    (`stage5_bringup_max_repairs`), which bounds how many times the GRAPH
    re-enters Node 3 after a later fault — this bounds the AGENT's own
    tool-calling turns within a single one of those invocations.

    Dispatches every tool call as an `await` against `ctx.session_executor`
    — the async QEMU/GDB session driving this module's docstring describes.
    Never raises on a normal "ran out of steps without finishing" outcome
    (returns `believes_ready=False` with whatever partial log was built);
    raises `DynamicFault` only if the session itself is unusable (no
    `ctx.handle`), matching every other dynamic-track node's contract.
    """
    if ctx.handle is None:
        raise DynamicFault(f"{ctx.candidate.global_id}: no active session for bringup_agent.")

    step_budget = max_steps or settings.stage5_bringup_agent_max_steps
    arch, endianness = ctx.emulation_plan.get("arch_spec_key", ("unknown", ""))
    arch_spec = resolve_qemu_arch_spec(arch, endianness)

    brief = render_bringup_brief(
        global_id=ctx.candidate.global_id,
        target_arch=arch,
        target_endianness=endianness,
        launch_cmd=ctx.launch_cmd,
    )
    messages: list[BaseMessage] = [
        SystemMessage(content=BRINGUP_AGENT_SYSTEM_PROMPT),
        HumanMessage(content=f"{brief}\nPropose your first action."),
    ]

    entries: list[ArbitrationLogEntry] = []
    strace_findings: list[str] = []
    applied_fixes: list[str] = []
    believes_ready = False
    summary = "step budget exhausted before the agent signaled done"

    async with aphase("bringup_agent"):
        for step in range(step_budget):
            response = await llm.ainvoke(
                messages,
                config=run_config(
                    run_name="stage5.bringup_agent",
                    metadata={"global_id": ctx.candidate.global_id, "step": step},
                    settings=settings,
                ),
            )
            action = _parse_action(response.content)
            if action is None:
                messages.append(
                    HumanMessage(
                        content="That did not parse as a valid JSON action object. "
                        "Respond with ONLY the JSON action, e.g. "
                        '{"tool": "run_strace_discovery", "args": {}}.'
                    )
                )
                continue

            tool = str(action.get("tool", ""))
            args = action.get("args") or {}

            if tool == "done":
                believes_ready = bool(args.get("launch_recipe_ready", False))
                summary = str(args.get("summary", ""))
                break

            observation, entry = await _dispatch_bringup_tool(
                ctx, tool=tool, args=args, arch_spec=arch_spec
            )
            if entry is not None:
                entries.append(entry)
                applied_fixes.append(f"{entry.kind}: {entry.target}")
            if tool == "run_strace_discovery" and observation:
                strace_findings.extend(
                    line for line in observation.splitlines() if "ENOENT" in line or "= -1" in line
                )

            messages.append(HumanMessage(content=f"Observation:\n{observation}\n\nNext action?"))

    arbitration_log = ArbitrationLog(
        entries=entries, strace_findings=strace_findings, launch_recipe=ctx.launch_cmd
    )
    return BringupAgentResult(
        arbitration_log=arbitration_log,
        applied_fixes=applied_fixes,
        believes_ready=believes_ready,
        summary=summary,
    )


async def _dispatch_bringup_tool(
    ctx: BringupContext, *, tool: str, args: dict, arch_spec
) -> tuple[str, ArbitrationLogEntry | None]:
    """Deterministic dispatcher for one bring-up agent tool call — every
    branch here `await`s against `ctx.session_executor`, so the whole loop
    stays async end to end. Returns `(observation_text_for_the_llm,
    optional_arbitration_entry)`."""
    if ctx.handle is None:
        return "no active session", None

    if tool == "run_strace_discovery":
        target_relpath = _target_relpath_in_workspace(ctx.candidate)
        chrooting = ctx.candidate.rootfs_dir is not None
        qemu_binary_in_chroot = f"/{arch_spec.user_binary}" if chrooting and arch_spec else None
        cmd = build_qemu_strace_command(
            arch_spec=arch_spec,
            target_relpath=target_relpath,
            argv=list(ctx.plan.argv_template),
            rootfs_relpath="." if chrooting else None,
            qemu_binary_in_chroot=qemu_binary_in_chroot,
        )
        result = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cd {CONTAINER_WORKDIR} && timeout 5 {cmd} 2>&1 | head -100",
            timeout=ctx.settings.stage5_qemu_timeout_seconds,
        )
        return (result.stdout + result.stderr)[:4000], None

    if tool == "inspect_binary":
        command = args.get("command", "file")
        target_relpath = _target_relpath_in_workspace(ctx.candidate)
        if command == "strings":
            grep_pattern = r"\.conf|\.cfg|/etc/|/var/|/tmp/"
            shell = f"strings {shlex.quote(target_relpath)} | grep -E '{grep_pattern}' | head -40"
        elif command == "readelf_dynamic":
            shell = f"readelf -d {shlex.quote(target_relpath)} 2>&1 | head -40"
        else:
            shell = f"file {shlex.quote(target_relpath)}"
        result = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"cd {CONTAINER_WORKDIR} && {shell}",
            timeout=ctx.settings.stage5_qemu_timeout_seconds,
        )
        return (result.stdout + result.stderr)[:3000], None

    if tool == "create_dummy_file":
        path = str(args.get("path", "")).strip()
        content = str(args.get("content", ""))
        if not path:
            return "refused: empty path", None
        result = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"mkdir -p {shlex.quote(_dirname(path))} && "
            f"cat > {shlex.quote(_container_path(path))} << 'FVVWEOF'\n{content}\nFVVWEOF",
            timeout=ctx.settings.stage5_qemu_timeout_seconds,
        )
        entry = ArbitrationLogEntry(
            kind="dummy_file",
            target=path,
            detail=content[:200],
            reasoning=str(args.get("reasoning", "")),
        )
        return f"created dummy file at {path}: {'ok' if result.ok else result.stderr}", entry

    if tool == "create_dummy_dir":
        path = str(args.get("path", "")).strip()
        if not path:
            return "refused: empty path", None
        result = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"mkdir -p {shlex.quote(_container_path(path))}",
            timeout=ctx.settings.stage5_qemu_timeout_seconds,
        )
        entry = ArbitrationLogEntry(kind="dummy_dir", target=path, detail="mkdir -p")
        return f"created dummy dir at {path}: {'ok' if result.ok else result.stderr}", entry

    if tool == "create_device_node":
        path = str(args.get("path", "")).strip()
        if not path:
            return "refused: empty path", None
        result = await ctx.session_executor.exec_in_session(
            ctx.handle,
            f"mkdir -p {shlex.quote(_dirname(path))} && touch {shlex.quote(_container_path(path))}",
            timeout=ctx.settings.stage5_qemu_timeout_seconds,
        )
        entry = ArbitrationLogEntry(
            kind="device_node", target=path, detail="empty placeholder file"
        )
        return (
            f"created device-node placeholder at {path}: {'ok' if result.ok else result.stderr}",
            entry,
        )

    if tool == "force_env_var":
        name = str(args.get("name", "")).strip()
        value = str(args.get("value", ""))
        if not name:
            return "refused: empty env var name", None
        # Env fixes are folded into the NEXT relaunch via ctx.launch_cmd
        # (bringup_stabilize's own build_qemu_user_launch_command already
        # applies arch_spec.cpu_probe_env this same way) — recorded here
        # for the arbitration log; actually taking effect requires the
        # caller to fold it into the launch command before relaunch_and_check.
        entry = ArbitrationLogEntry(kind="env_override", target=name, detail=value)
        return f"recorded env override {name}={value} for the next relaunch", entry

    if tool == "relaunch_and_check":
        try:
            await _launch_qemu_and_wait(ctx)
            return "relaunch OK: gdbstub port opened", None
        except DynamicFault as exc:
            return f"relaunch FAILED: {exc}", None

    return f"unknown tool {tool!r} — ignored", None


def _dirname(path: str) -> str:
    idx = path.rfind("/")
    return path[:idx] if idx > 0 else "/"


def _container_path(path: str) -> str:
    """Bring-up dummy files are created relative to the bind-mounted
    workspace root (which IS the rootfs root — see `dynamic_track.
    _workspace_dir_for`'s docstring), so an absolute in-chroot path like
    `/etc/config/wireless` becomes plain `CONTAINER_WORKDIR/etc/config/
    wireless` from the outer container shell's own point of view."""
    return f"{CONTAINER_WORKDIR}{path}" if path.startswith("/") else f"{CONTAINER_WORKDIR}/{path}"


# --------------------------------------------------------------------- #
# Node 6 — trigger_agent
# --------------------------------------------------------------------- #


@dataclass
class TriggerAgentResult:
    """What `trigger_agent` hands back: the delivered-payload text (for
    `BringupContext.real_payload_override`), the delivery channel actually
    used, and the final `ObservationRecord` captured for this invocation
    (may be the zero-value default if the agent never reached
    `observe_result` before its step budget ran out)."""

    delivered_payload: str
    delivery_channel: str
    observation: ObservationRecord
    gdb_transcript: str
    summary: str


async def trigger_agent(
    ctx: BringupContext,
    *,
    llm: BaseChatModel,
    settings: Settings,
    target: TargetMeta,
    plan: DynamicPlan,
    vuln_class: str,
    sink_expression: str,
    max_steps: int | None = None,
) -> TriggerAgentResult:
    """Run the Node 6 trigger/PoC loop for one invocation. Every payload
    the agent proposes is validated (`validate_real_payload` when
    `Settings.stage5_allow_real_payloads` is `True`, else
    `validate_benign_marker`) BEFORE it is ever delivered — a rejected
    payload is reported back to the LLM as a validation failure, giving it
    a chance to reshape the payload rather than silently downgrading it.

    `deliver_via_direct_call` is only meaningful when
    `ctx.emulation_plan["mode"] == "direct_call"` — the dispatcher does not
    itself enforce that gate (the graph router controls which mode this
    invocation runs under), it simply issues the GDB `call` command as
    asked.
    """
    if ctx.handle is None:
        raise DynamicFault(f"{ctx.candidate.global_id}: no active session for trigger_agent.")

    step_budget = max_steps or settings.stage5_trigger_agent_max_steps
    emulation_mode = ctx.emulation_plan.get("mode", "user")

    brief = render_trigger_brief(
        global_id=ctx.candidate.global_id,
        trigger_shape=plan.trigger_shape or "cli_argv",
        oracle=plan.oracle or plan.decisive_observable,
        disconfirm_condition=plan.disconfirm_condition,
        preconditions=list(plan.preconditions),
        vuln_class=vuln_class,
        sink_expression=sink_expression,
        emulation_mode=emulation_mode,
    )
    messages: list[BaseMessage] = [
        SystemMessage(content=TRIGGER_AGENT_SYSTEM_PROMPT),
        HumanMessage(content=f"{brief}\nPropose your first action."),
    ]

    delivered_payload = ""
    delivery_channel = ""
    observation = ObservationRecord()
    gdb_transcript = ""
    summary = "step budget exhausted before the agent signaled done"

    async with aphase("trigger_agent"):
        for step in range(step_budget):
            response = await llm.ainvoke(
                messages,
                config=run_config(
                    run_name="stage5.trigger_agent",
                    metadata={"global_id": ctx.candidate.global_id, "step": step},
                    settings=settings,
                ),
            )
            action = _parse_action(response.content)
            if action is None:
                messages.append(
                    HumanMessage(
                        content="That did not parse as a valid JSON action object. "
                        "Respond with ONLY the JSON action."
                    )
                )
                continue

            tool = str(action.get("tool", ""))
            args = action.get("args") or {}

            if tool == "done":
                summary = str(args.get("summary", ""))
                break

            if tool == "craft_payload":
                payload = str(args.get("payload", ""))
                try:
                    if settings.stage5_allow_real_payloads:
                        validate_real_payload(payload)
                    else:
                        validate_benign_marker(payload)
                    delivered_payload = payload
                    messages.append(
                        HumanMessage(content=f"Payload accepted: {payload!r}. Next action?")
                    )
                except PayloadContainmentViolation as exc:
                    messages.append(
                        HumanMessage(
                            content=f"Payload REJECTED (containment violation): {exc}. "
                            "Propose a different payload that stays within bounds."
                        )
                    )
                except BenignMarkerViolation as exc:
                    messages.append(
                        HumanMessage(
                            content=f"Payload REJECTED (benign-only posture): {exc}. "
                            "Propose a corrected payload."
                        )
                    )
                continue

            if tool == "apply_precondition":
                messages.append(
                    HumanMessage(
                        content=f"Precondition noted: {args.get('description', '')}. Next action?"
                    )
                )
                continue

            if tool in ("deliver_via_argv", "deliver_via_network"):
                delivery_channel = tool
                observation_text, ctx.plan.argv_template = await _dispatch_delivery(
                    ctx, tool=tool, args=args, delivered_payload=delivered_payload
                )
                messages.append(
                    HumanMessage(content=f"Delivery result:\n{observation_text}\nNext action?")
                )
                continue

            if tool == "deliver_via_direct_call":
                delivery_channel = "deliver_via_direct_call"
                ctx.real_payload_override = str(args.get("call_expression", delivered_payload))
                messages.append(
                    HumanMessage(
                        content="Direct-call expression recorded. Call observe_result next."
                    )
                )
                continue

            if tool == "observe_result":
                if delivered_payload and settings.stage5_allow_real_payloads:
                    ctx.real_payload_override = delivered_payload
                try:
                    transcript, captured = await instrument_trigger(
                        ctx, gdb_transcript_so_far=gdb_transcript
                    )
                    gdb_transcript = transcript
                    observation = await collect_observation(
                        ctx,
                        result_stdout=transcript,
                        result_stderr="",
                    )
                    messages.append(
                        HumanMessage(
                            content=f"Observation: signal={observation.signal} "
                            f"faulting_pc={observation.faulting_pc} "
                            f"captured_sink_argument={captured!r}\nNext action?"
                        )
                    )
                except DynamicFault as exc:
                    messages.append(
                        HumanMessage(
                            content=f"Observation failed (setup fault): {exc}. Next action?"
                        )
                    )
                continue

            messages.append(HumanMessage(content=f"unknown tool {tool!r} — ignored. Next action?"))

    return TriggerAgentResult(
        delivered_payload=delivered_payload,
        delivery_channel=delivery_channel,
        observation=observation,
        gdb_transcript=gdb_transcript,
        summary=summary,
    )


async def _dispatch_delivery(
    ctx: BringupContext, *, tool: str, args: dict, delivered_payload: str
) -> tuple[str, list[str]]:
    """Fold the crafted payload into the launch mechanism the trigger will
    actually use on the NEXT relaunch — argv is the only delivery channel
    partial (single-service) user-mode emulation directly supports without
    a live network stack; `deliver_via_network` still resolves to an argv
    entry carrying the crafted request content, since a genuinely separate
    HTTP client would need a reachable listening service this sandbox's
    default `--network=none` posture does not provide (see `Settings.
    stage5_allow_network_grant`) — this is a documented simplification,
    not silent behavior: the observation this produces is exactly as real
    as the underlying reach_strategy already is."""
    argv = list(ctx.plan.argv_template)
    if tool == "deliver_via_argv":
        extra = args.get("argv") or ([delivered_payload] if delivered_payload else [])
        argv = argv + [str(a) for a in extra]
        return f"argv set to {argv}", argv
    # deliver_via_network
    path = str(args.get("path", "/"))
    body = str(args.get("body", delivered_payload))
    argv = argv + [path, body]
    return f"network-shaped request folded into argv (path={path!r}, body={body!r})", argv


# --------------------------------------------------------------------- #
# Node 8 — route_observation (LLM router, invoked only after the
# deterministic match_oracle first pass fails to settle the round)
# --------------------------------------------------------------------- #


async def route_observation(
    *,
    llm: BaseChatModel,
    settings: Settings,
    global_id: str,
    oracle: str,
    disconfirm_condition: str,
    observation: ObservationRecord,
    reached_sink: bool,
    breakpoint_hit: bool,
    iteration: int,
    max_iterations: int,
) -> RouteDecision:
    """Node 8's LLM step — called ONLY when `dynamic_track.match_oracle`
    already checked `observation` against `oracle` and returned `False`
    (or the caller otherwise needs a diagnosis rather than a bare
    yes/no). Returns a `RouteDecision`; falls back to a conservative
    `"inconclusive"` route (never raises) if the LLM's response doesn't
    parse as valid JSON within one retry — an unparseable router response
    must never crash the whole dynamic-track run."""
    observation_summary = (
        f"signal={observation.signal} faulting_pc={observation.faulting_pc} "
        f"memory_diff_detected={observation.memory_diff_detected} "
        f"filesystem_artifacts={observation.filesystem_artifacts} "
        f"stdout_excerpt={observation.stdout[:300]!r} "
        f"stderr_excerpt={observation.stderr[:300]!r}"
    )
    brief = render_router_brief(
        global_id=global_id,
        oracle=oracle,
        disconfirm_condition=disconfirm_condition,
        observation_summary=observation_summary,
        reached_sink=reached_sink,
        breakpoint_hit=breakpoint_hit,
        iteration=iteration,
        max_iterations=max_iterations,
    )
    messages: list[BaseMessage] = [
        SystemMessage(content=DYNAMIC_ROUTER_SYSTEM_PROMPT),
        HumanMessage(content=brief),
    ]

    for attempt in range(2):
        response = await llm.ainvoke(
            messages,
            config=run_config(
                run_name="stage5.dynamic_evaluate",
                metadata={"global_id": global_id, "iteration": iteration, "attempt": attempt},
                settings=settings,
            ),
        )
        payload = clean_json_payload(response.content)
        if payload is not None:
            try:
                decision = RouteDecision.model_validate_json(payload)
                return decision
            except Exception:  # noqa: BLE001 - fall through to retry/fallback
                pass
        messages.append(
            HumanMessage(
                content="That did not parse as the required JSON object. Return ONLY "
                '{"route": "...", "diagnosis": "...", "confidence": "..."}.'
            )
        )

    return RouteDecision(
        route="inconclusive",
        diagnosis="router response never parsed as valid JSON within the retry budget",
        confidence="LOW",
    )


__all__ = [
    "BringupAgentResult",
    "TriggerAgentResult",
    "bringup_agent",
    "route_observation",
    "trigger_agent",
]
