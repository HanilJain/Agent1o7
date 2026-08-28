"""`strategy_agent` (FVVW v3 §6 node 3) — the single LLM pass that merges
what the design doc calls three conceptual steps (threat modeling,
hypothesis formulation, per-track plan compilation) into one structured
`StrategyPlan`.

Plain text in / JSON text out, reusing `agent.cleaning.clean_json_payload`
+ `StrategyPlan.model_validate_json` — the SAME parsing discipline the
existing evaluator role already established (see `agent.graph.
parse_evaluator_response`'s docstring for why this project prefers that
over `with_structured_output` at every Stage 5 LLM call site: local-model
reliability). This module never imports `agent.graph`/`agent.prompts`
directly — it reuses `candidate_index.VerificationCandidate` and
`agent.prompts.render_finding_brief`'s OUTPUT indirectly (via its own
`render_strategy_brief`, which layers `mem.target` on top), but composes
its own prompt text; the existing generator/evaluator prompts are
untouched.

Translating a finding's PROSE guards (`Finding.security_condition`/
`data_flow`) into `DynamicPlan.guards`'s structured
`[{name, addr, forced_value}]` form is explicitly this LLM's job — no
deterministic parser could reliably extract "which branch, forced to
what value" from open-ended analyst prose, which is exactly the kind of
genuinely-open-ended task this project's script-first principle reserves
for an LLM node (see the FVVW v3 design doc's script-first principle).
"""

from __future__ import annotations

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from pydantic import ValidationError

from fw_audit.common.verification import StrategyPlan, TargetMeta
from fw_audit.config.settings import Settings
from fw_audit.observability import run_config
from fw_audit.stage5_verification.agent.cleaning import clean_json_payload
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.errors import Stage5InputError

STRATEGY_SYSTEM_PROMPT = """\
You are a firmware vulnerability verification strategist. You are given one \
static-analysis finding plus facts about its real binary target, and must \
produce a single verification STRATEGY that two independent tracks — a \
Joern static-analysis track and a QEMU+GDB dynamic-emulation track — will \
each execute BLIND to each other, so their results can be compared as two \
genuinely independent witnesses.

# WHAT TO PRODUCE

1. threat_model: the normal data flow, the attack scenario, the PRECISE \
trust boundary (e.g. "the argv[2] value", never vaguely "network input" \
unless the finding's own evidence establishes that), and an access \
requirement stated as narrowly as the evidence supports — never claim \
"unauthenticated remote" unless the finding's source/sink/data_flow \
actually establish that.

2. hypotheses: hypothesis A (the finding IS exploitable as claimed) and \
hypothesis B (the path is constrained/safe — sanitized, unreachable, or \
guarded), plus ONE decisive_observable: the single fact that, if observed, \
would prove A, and if observed differently, would prove B. This observable \
must be independently expressible in BOTH a static (CPGQL) and a dynamic \
(GDB) sense — restate it in both plans below using the SAME underlying \
claim, in each track's own vocabulary.

3. static_plan: target_function (the finding's evidence_span.function_id), \
source_fields, sink_names, expected_intermediate_calls (named functions the \
data flow should pass through, from the finding's own data_flow steps), \
sanitizer_patterns (what a sanitizer/allow-list check on this path would \
look like), crosscheck_required (true whenever the evidence traces back to \
decompiler output, which is nearly always), and decisive_observable \
restated in CPGQL/data-flow terms.

4. dynamic_plan: reach_strategy ("natural_drive" if the target's dispatch \
is statically resolvable per the supplied target facts, else \
"inferior_call"), entry_addr/target_addr/sink_addr (from the supplied \
target facts — func_offset is the target function's own validated address; \
leave sink_addr empty if it cannot be inferred), guards (translate the \
finding's security_condition/data_flow PROSE into a structured list of \
{name, addr, forced_value} — addr may be empty if unresolved, but name and \
forced_value must always be filled from the prose), argv_template, \
payload_marker (a BENIGN distinguishing marker only — e.g. \
';touch /tmp/<claim_id>_proof;' — NEVER a functional exploit, reverse \
shell, exfiltration command, or destructive operation; this is verification \
infrastructure, not an exploit), required_signals (list at least 3 \
independent signals, e.g. sink_argument_capture, target_self_report, \
filesystem_artifact), and decisive_observable restated in GDB/runtime terms.

5. static_runnable / dynamic_runnable: false ONLY for hard infeasibility \
(e.g. no source available for a CPG; the target architecture has no QEMU \
support) — never merely because a track is "expected to be hard". Default \
both to true unless the supplied facts clearly rule one out.

# HARD RULES

- The payload_marker MUST be benign — refuse to name a real exploit, \
reverse shell, credential exfiltration, or destructive command. A marker \
like a harmless touch/echo of a unique string is correct; anything that \
could function as an actual attack is not.
- static_plan.decisive_observable, dynamic_plan.decisive_observable, and \
hypotheses.decisive_observable must all describe the SAME underlying fact, \
just phrased for each track/purpose.
- Never invent facts the finding/target data doesn't support — an unknown \
addr/offset is an empty string, not a guess.

Return ONLY a single JSON object (no markdown fences, no commentary, no \
<think> reasoning in your final answer) matching this shape exactly:
{"threat_model": {...}, "hypotheses": {"a": "...", "b": "...", \
"decisive_observable": "..."}, "static_plan": {"target_function": "...", \
"source_fields": [...], "sink_names": [...], \
"expected_intermediate_calls": [...], "sanitizer_patterns": [...], \
"crosscheck_required": true, "decisive_observable": "..."}, \
"dynamic_plan": {"reach_strategy": "...", "entry_addr": "...", \
"target_addr": "...", "sink_addr": "...", "guards": [{"name": "...", \
"addr": "...", "forced_value": "..."}], "argv_template": [...], \
"payload_marker": "...", "required_signals": [...], \
"decisive_observable": "..."}, "static_runnable": true, \
"dynamic_runnable": true}
"""


def render_strategy_brief(candidate: VerificationCandidate, target: TargetMeta) -> str:
    """Renders the finding + `mem.target` facts into the plain-text brief
    the strategy agent reasons over — layers `TargetMeta` on top of the
    SAME finding fields `agent.prompts.render_finding_brief` already
    renders for the static track, without importing that function (keeping
    this module's prompt fully independent of the existing generator/
    evaluator prompt module, per this project's "don't touch Joern" reuse
    discipline)."""
    finding = candidate.finding
    lines = [
        f"global_id: {candidate.global_id}",
        f"bin_id: {candidate.bin_id}",
        "",
        f"## Finding: {finding.title}",
        f"category: {finding.category}",
        f"cwe: {', '.join(finding.cwe) or '(none)'}",
        f"security_condition: {finding.security_condition}",
        "",
        f"source: {finding.source.expression} ({finding.source.type}, "
        f"attacker_control={finding.source.attacker_control})",
        f"sink: {finding.sink.expression} ({finding.sink.type})",
        "",
        "data_flow (as claimed by the original static analysis):",
        *[f"  - {step}" for step in finding.data_flow],
        "",
        f"evidence_span (function_id={finding.evidence_span.function_id}, "
        f"lines {finding.evidence_span.line_start}-{finding.evidence_span.line_end}):",
        finding.evidence_span.code,
        "",
        f"exploitability (original assessment): {finding.exploitability}",
        "",
        "## Target facts (characterize_target)",
        f"arch: {target.arch}",
        f"endianness: {target.endianness}",
        f"is_64bit: {target.is_64bit}",
        f"pie: {target.pie}",
        f"stripped: {target.stripped}",
        f"libc: {target.libc}",
        f"func_offset (validated entry point of the claimed function): {target.func_offset}",
        f"dispatch_resolvable: {target.dispatch_resolvable}",
    ]
    return "\n".join(lines)


def build_strategy_messages(
    *, brief: str, system_prompt: str | None = None
) -> list[BaseMessage]:
    """Compose the strategy agent's (system, human) message pair.
    `system_prompt` overrides `STRATEGY_SYSTEM_PROMPT` for this call only —
    same debugging-override shape `agent.prompts.build_generator_messages`
    already established."""
    system = system_prompt if system_prompt is not None else STRATEGY_SYSTEM_PROMPT
    user = (
        f"Finding + target facts to plan verification for:\n\n{brief}\n\n"
        "Produce the StrategyPlan JSON object described in your instructions."
    )
    return [SystemMessage(content=system), HumanMessage(content=user)]


def validate_decisive_observable(plan: StrategyPlan) -> bool:
    """The FVVW v3 post-check (script, not LLM): confirms the SAME
    `decisive_observable` claim is traceably restated across all three
    places it must appear. Deliberately loose — non-empty in all three
    places, not exact-string equality — since the strategy agent is
    instructed to restate it in each track's own vocabulary, not copy it
    verbatim three times. This only catches the failure mode where one
    plan's observable is missing entirely (empty string / whitespace-only),
    the actual "same claim" check a human/LLM review would still need to do
    is out of scope for a deterministic validator."""
    observables = (
        plan.hypotheses.decisive_observable.strip(),
        plan.static_plan.decisive_observable.strip(),
        plan.dynamic_plan.decisive_observable.strip(),
    )
    return all(observables)


def parse_strategy_response(raw: object) -> StrategyPlan | None:
    """Clean + parse one strategy LLM response into a `StrategyPlan`.
    Returns `None` (never raises) on unparseable/invalid JSON — same
    contract as `agent.graph.parse_evaluator_response`."""
    payload = clean_json_payload(raw)
    if payload is None:
        return None
    try:
        return StrategyPlan.model_validate_json(payload)
    except (ValidationError, ValueError):
        return None


async def strategy_agent(
    candidate: VerificationCandidate,
    target: TargetMeta,
    *,
    llm: BaseChatModel,
    settings: Settings,
    system_prompt: str | None = None,
    max_regenerate_attempts: int = 2,
) -> StrategyPlan:
    """Run the strategy agent for one candidate, retrying (bounded) when
    the post-check validator rejects the plan (mismatched/missing
    `decisive_observable`) or the response doesn't parse at all — same
    "in-process re-invocation before giving up" pattern
    `agent.graph.evaluate_node` already uses for the evaluator role.

    Raises `Stage5InputError` if no valid `StrategyPlan` could be produced
    within the attempt budget — this halts the whole fork-join for this
    candidate (both tracks need `mem.plan` before they can start), unlike
    `characterize_target`'s narrower "target mismatch" failure.
    """
    brief = render_strategy_brief(candidate, target)
    messages = build_strategy_messages(brief=brief, system_prompt=system_prompt)

    last_raw = ""
    for attempt in range(max_regenerate_attempts + 1):
        response = await llm.ainvoke(
            messages,
            config=run_config(
                run_name="stage5.strategy_agent",
                metadata={"global_id": candidate.global_id, "attempt": attempt},
                settings=settings,
            ),
        )
        last_raw = str(getattr(response, "content", response))
        plan = parse_strategy_response(response.content)
        if plan is not None and validate_decisive_observable(plan):
            return plan

        if attempt < max_regenerate_attempts:
            nudge = (
                "Your previous response either did not parse as the required JSON "
                "object, or its hypotheses/static_plan/dynamic_plan decisive_observable "
                "values did not consistently restate the same underlying claim. Return "
                "ONLY the corrected JSON object this time, with all three "
                "decisive_observable fields describing the same fact."
            )
            messages = [*messages, HumanMessage(content=nudge)]

    raise Stage5InputError(
        f"{candidate.global_id}: strategy_agent failed to produce a valid StrategyPlan "
        f"after {max_regenerate_attempts + 1} attempts. Last raw response (truncated): "
        f"{last_raw[:500]}"
    )


__all__ = [
    "STRATEGY_SYSTEM_PROMPT",
    "build_strategy_messages",
    "parse_strategy_response",
    "render_strategy_brief",
    "strategy_agent",
    "validate_decisive_observable",
]
