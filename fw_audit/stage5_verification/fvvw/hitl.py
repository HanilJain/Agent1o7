"""Human-in-the-loop intervention when a fork-join track exhausts its own
budget without reaching a decisive verdict.

Trigger condition (per the FVVW HITL plan): a track's terminal
`TrackResult.evidence` carries `budget_exhausted=True` — set by
`fvvw.dynamic_track._terminal`/`fvvw.graph.run_dynamic_track_only`'s
`BringupExhausted` handler for the dynamic track, and by
`fvvw.static_track.run_static_track` for the static track. This is a FACT
tagged at the point of exhaustion, not an inference made here from the bare
verdict value (`INCONCLUSIVE`/`ERROR` can in principle arise other ways).

Where the prompt is raised: hoisted to `fvvw.graph.run_fvvw`, immediately
after the fork-join's hard barrier (`await_both_tracks`) and before
`joint_evaluate` — never inside a track function. The fork spawns THREE
concurrent tasks inside a worker pool (`fvvw.driver`'s `stage5_workers`
concurrent candidates), so a blocking prompt inside a track would interleave
stdout with sibling tasks and stall the pool. `run_fvvw`'s caller
(`runner.py`'s `_cmd_run`) is responsible for forcing `stage5_workers=1`
when `--hitl=prompt` is passed — see that module's own comment.

Both tracks' results are in hand by the time this hook runs, so one prompt
point covers whichever track(s) actually need it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING

from fw_audit.common.verification import (
    DynamicPlan,
    HumanReviewRecord,
    StaticPlan,
    TargetMeta,
    TrackResult,
    VerificationVerdict,
)

if TYPE_CHECKING:
    from fw_audit.stage5_verification.cmdlog import CommandRecord


class HitlAction(str, Enum):
    """The four interventions offered at the HITL prompt — see the FVVW
    HITL plan's "the four actions, per track" table for exactly what each
    does on the static vs. dynamic track."""

    RETRY = "retry"
    OVERRIDE_PLAN = "override_plan"
    INJECT = "inject"
    FORCE_VERDICT = "force_verdict"
    SKIP = "skip"
    """Accept the track's current (non-decisive) result as-is and proceed to
    `joint_evaluate` — the "do nothing" choice, distinct from `force_verdict`
    (which substitutes a human-attributed verdict): `skip` leaves the track's
    own INCONCLUSIVE/ERROR result untouched."""


@dataclass(frozen=True)
class HitlRequest:
    """Everything shown to the operator at one HITL prompt round, for ONE
    track. `fvvw.graph.run_fvvw`'s post-barrier hook builds one of these per
    track whose `TrackResult.evidence.get("budget_exhausted")` is true."""

    global_id: str
    track: str
    """`"static"` or `"dynamic"`."""
    result: TrackResult
    plan: DynamicPlan | StaticPlan | None
    """`None` only on the `--joern-only` path, which has no `StrategyPlan`/
    `StaticPlan` at all (see `driver._run_hitl_joern_only`)."""
    target: TargetMeta | None
    """`None` only on the `--joern-only` path — see `plan`'s docstring."""
    recent_commands: list[CommandRecord | dict]
    """Tail of the track's `cmdlog.CommandLog.read_all()` — dicts when read
    back from JSONL, `CommandRecord`s if a caller has them in memory
    already; the terminal prompter only reads a handful of common keys
    (`node`/`kind`/`command`/`ok`/`stdout`/`stderr`) so either shape works."""
    round_number: int = 1


@dataclass(frozen=True)
class HitlDecision:
    """The operator's response to one `HitlRequest`."""

    action: HitlAction
    extra_iterations: int = 0
    plan_overrides: dict = field(default_factory=dict)
    injected_payload: str = ""
    forced_verdict: VerificationVerdict | None = None
    rationale: str = ""


Prompter = Callable[[HitlRequest], HitlDecision]
"""An injectable callable — this is what makes HITL testable: a test passes
a scripted fake that returns pre-chosen `HitlDecision`s with no real stdin
needed, matching this repo's existing "duck-typed fake" testing convention
for LLMs/executors."""


def _command_field(record: CommandRecord | dict, name: str, default=""):
    if isinstance(record, dict):
        return record.get(name, default)
    return getattr(record, name, default)


def _format_command_line(record: CommandRecord | dict) -> str:
    node = _command_field(record, "node")
    kind = _command_field(record, "kind")
    command = _command_field(record, "command")
    ok = _command_field(record, "ok", False)
    status = "ok" if ok else "FAIL"
    stdout = str(_command_field(record, "stdout", ""))[:300]
    stderr = str(_command_field(record, "stderr", ""))[:300]
    lines = [f"  [{status}] {node}/{kind}: {command}"]
    if stdout.strip():
        lines.append(f"    stdout: {stdout.strip()}")
    if stderr.strip():
        lines.append(f"    stderr: {stderr.strip()}")
    return "\n".join(lines)


def _format_plan(plan: DynamicPlan | StaticPlan | None) -> str:
    if plan is None:
        # The --joern-only path has no StrategyPlan/StaticPlan at all (see
        # driver._run_hitl_joern_only) — nothing to show here.
        return "(no plan — --joern-only path has no StrategyPlan)"
    if isinstance(plan, DynamicPlan):
        guard_lines = "\n".join(
            f"    - {g.name}: addr={g.addr!r} forced_value={g.forced_value!r}"
            for g in plan.guards
        ) or "    (none)"
        return (
            f"entry_addr: {plan.entry_addr!r}\n"
            f"target_addr: {plan.target_addr!r}\n"
            f"sink_addr: {plan.sink_addr!r}\n"
            f"argv_template: {plan.argv_template!r}\n"
            f"guards:\n{guard_lines}"
        )
    return (
        f"target_function: {plan.target_function!r}\n"
        f"expected_intermediate_calls: {plan.expected_intermediate_calls!r}\n"
        f"sanitizer_patterns: {plan.sanitizer_patterns!r}"
    )


def terminal_prompter(req: HitlRequest) -> HitlDecision:
    """The real, interactive terminal UI. Prints both tracks' context for
    the ONE track this request concerns, the exhausted budget, the last few
    commands read back from the JSONL, the current plan's key fields, then a
    menu — and blocks on `input()`.

    Called via `asyncio.to_thread(...)` by `run_hitl_for_track` (never
    directly `await`ed), so the blocking `input()` call never freezes the
    event loop the way calling it inline from an async function would."""
    print(f"\n{'=' * 70}")
    print(f"HITL: {req.global_id} — {req.track} track exhausted its budget "
          f"(round {req.round_number})")
    print(f"{'=' * 70}")
    print(f"verdict: {req.result.verdict.value}  "
          f"proved_hypothesis: {req.result.proved_hypothesis}  "
          f"iters_used: {req.result.iters_used}")
    print(f"\nplan:\n{_format_plan(req.plan)}")
    if req.recent_commands:
        print("\nrecent commands:")
        for record in req.recent_commands[-10:]:
            print(_format_command_line(record))
    print(
        "\nChoose an action:\n"
        "  1) retry — re-run this track with more iterations\n"
        "  2) override_plan — edit plan values, then re-run\n"
        "  3) inject — supply a raw payload/recipe directly\n"
        "  4) force_verdict — set the verdict by hand, with a rationale\n"
        "  5) skip — accept the current non-decisive result as-is\n"
    )
    choice = input("action [1-5]: ").strip()
    action_map = {
        "1": HitlAction.RETRY,
        "2": HitlAction.OVERRIDE_PLAN,
        "3": HitlAction.INJECT,
        "4": HitlAction.FORCE_VERDICT,
        "5": HitlAction.SKIP,
    }
    action = action_map.get(choice, HitlAction.SKIP)

    if action == HitlAction.RETRY:
        raw = input("extra iterations [default 4]: ").strip()
        extra = int(raw) if raw.isdigit() else 4
        return HitlDecision(action=action, extra_iterations=extra)
    if action == HitlAction.OVERRIDE_PLAN:
        print("Enter overrides as key=value, one per line, blank line to finish:")
        overrides: dict = {}
        while True:
            line = input("  ").strip()
            if not line:
                break
            if "=" in line:
                key, _, value = line.partition("=")
                overrides[key.strip()] = value.strip()
        return HitlDecision(action=action, plan_overrides=overrides)
    if action == HitlAction.INJECT:
        print("Enter injected payload/recipe text, blank line to finish:")
        payload_lines = []
        while True:
            line = input()
            if not line:
                break
            payload_lines.append(line)
        return HitlDecision(action=action, injected_payload="\n".join(payload_lines))
    if action == HitlAction.FORCE_VERDICT:
        raw = input("verdict [CONFIRMED/REFUTED/INCONCLUSIVE]: ").strip().upper()
        try:
            verdict = VerificationVerdict(raw)
        except ValueError:
            verdict = VerificationVerdict.INCONCLUSIVE
        rationale = input("rationale: ").strip()
        return HitlDecision(action=action, forced_verdict=verdict, rationale=rationale)
    return HitlDecision(action=HitlAction.SKIP)


def is_budget_exhausted(result: TrackResult) -> bool:
    """The HITL trigger condition, checked against the FACT tagged by the
    producing track (see this module's docstring) — never re-derived from
    the bare verdict value alone."""
    return bool((result.evidence or {}).get("budget_exhausted"))


def force_verdict_result(
    *, previous: TrackResult, verdict: VerificationVerdict, rationale: str
) -> TrackResult:
    """Build the `TrackResult` a `force_verdict` decision produces —
    `evidence["human_attributed"]=True` is what lets `joint_evaluate`'s
    `collect_residual_unknowns` (and `fvvw.report`'s prompt) state the
    attribution explicitly rather than presenting a hand-set verdict as
    machine-derived. `proved_hypothesis` maps the same way
    `fvvw.static_track` already does (CONFIRMED->A, REFUTED->B, else
    'none') so downstream consumers of `proved_hypothesis` don't need a
    special case for a human-forced result."""
    if verdict == VerificationVerdict.CONFIRMED:
        proved_hypothesis = "A"
    elif verdict == VerificationVerdict.REFUTED:
        proved_hypothesis = "B"
    else:
        proved_hypothesis = "none"
    return TrackResult(
        verdict=verdict,
        proved_hypothesis=proved_hypothesis,
        evidence={
            **(previous.evidence or {}),
            "human_attributed": True,
            "rationale": rationale,
        },
        iters_used=previous.iters_used,
    )


async def prompt_for_track(
    req: HitlRequest, *, prompter: Prompter = terminal_prompter
) -> HitlDecision:
    """Run `prompter` off the event loop thread (`asyncio.to_thread`) so a
    blocking terminal prompt (or a test's scripted callable — either way,
    `prompter` itself stays a plain sync callable, never an async one,
    which is what keeps a real `input()`-based prompter and a scripted test
    fake interchangeable) never stalls `run_fvvw`'s caller."""
    return await asyncio.to_thread(prompter, req)


def build_human_review_record(
    *, track: str, decision: HitlDecision, rounds: int
) -> HumanReviewRecord:
    """Assemble the persisted `HumanReviewRecord` from the FINAL round's
    decision — `rounds` is the total number of prompt rounds this candidate
    went through (bounded by `Settings.stage5_hitl_max_rounds`), not just
    this one decision's own round number."""
    overrides: dict = {}
    if decision.action == HitlAction.OVERRIDE_PLAN:
        overrides = dict(decision.plan_overrides)
    elif decision.action == HitlAction.INJECT:
        overrides = {"injected_payload": decision.injected_payload}
    return HumanReviewRecord(
        track=track,
        action=decision.action.value,
        rationale=decision.rationale,
        overrides=overrides,
        rounds=rounds,
        timestamp=datetime.now(UTC),
    )


__all__ = [
    "HitlAction",
    "HitlDecision",
    "HitlRequest",
    "Prompter",
    "build_human_review_record",
    "force_verdict_result",
    "is_budget_exhausted",
    "prompt_for_track",
    "terminal_prompter",
]
