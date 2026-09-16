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
from fw_audit.stage5_verification.cmdlog import CommandLog
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
hypothesis B (the path is constrained/safe), plus ONE decisive_observable: \
the single fact that, if observed, proves A. Hypothesis B must NAME WHAT \
WOULD HAVE TO BE OBSERVED TO PROVE IT — the specific sanitizer, bounds \
check, allow-list, guard, or constant argument that makes the path safe. \
"The A-observable was not seen" is NOT hypothesis B; that is an unproven \
round, not a proof of safety. If no positive B-observable can be named from \
the evidence, say so explicitly in hypotheses.b rather than inventing one — \
an honest "no B-observable is evident from the finding" is a valid answer. \
The decisive_observable must be independently expressible in BOTH a static \
(CPGQL) and a dynamic (GDB) sense — restate it in both plans below using \
the SAME underlying claim, in each track's own vocabulary.

Also produce hypotheses.oracle: the EXACT, mechanically-checkable condition \
that means "confirmed" — e.g. "process receives SIGSEGV with PC pointing \
inside the strcpy call site", "a file is written to /tmp/<id>_proof \
containing OVERFLOW_CONFIRMED", "HTTP response contains command output not \
part of any legitimate response field". This must be a literal, checkable \
fact — never "the code looks exploitable" or any other subjective \
judgement. And hypotheses.disconfirm_condition: what result means \
"false positive" — e.g. "input reaches the sink but is safely \
bounds-checked before use" or "the path is provably unreachable from any \
network-facing input".

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
trigger_shape (roughly how the trigger should reach the sink: \
"network_http" for an HTTP/CGI/UPnP/SOAP endpoint, "cli_argv" for a \
CLI-argument-facing binary, or "direct_call" only if the finding's own \
evidence gives no realistic front-door path), preconditions (anything that \
must be true before the sink is reachable, e.g. "must be authenticated", \
"NVRAM key X must be set" — from the finding's own evidence, never \
invented), oracle (dynamic_plan's own restatement of hypotheses.oracle in \
GDB/runtime terms — a crash signal name, a captured register/memory value, \
a filesystem artifact path, or specific stdout/stderr content), \
disconfirm_condition (dynamic_plan's own restatement of \
hypotheses.disconfirm_condition), payload_marker (ONLY used as a fallback \
when this run's containment posture is benign-only — see below; when real \
payloads are allowed, leave this as a short informational label, e.g. \
"overflow probe for <claim_id>", since the actual payload construction is \
a separate agent's job downstream), required_signals (list at least 3 \
independent signals appropriate to the vuln class — e.g. \
["crash_signal", "faulting_pc", "memory_diff"] for a memory-corruption bug, \
or ["sink_argument_capture", "target_self_report", "filesystem_artifact"] \
for a marker-based check), and decisive_observable restated in GDB/runtime \
terms.

5. static_runnable / dynamic_runnable: false ONLY for hard infeasibility \
(e.g. no source available for a CPG; the target architecture has no QEMU \
support) — never merely because a track is "expected to be hard". Default \
both to true unless the supplied facts clearly rule one out.

# HARD RULES

- This run's containment posture is stated explicitly in the brief below \
("payload posture: real payloads allowed" or "payload posture: \
benign-only"). Under "benign-only", payload_marker MUST be a benign, \
scoped filesystem side-effect only (e.g. ';touch /tmp/<claim_id>_proof;') \
— never a functional exploit, reverse shell, exfiltration command, or \
destructive operation. Under "real payloads allowed" (the default), the \
oracle/disconfirm_condition you specify is what actually matters — a \
downstream trigger agent crafts the concrete payload from your \
oracle/trigger_shape/preconditions, inside a disposable, network-isolated \
sandbox container; you do not construct the payload text yourself here, \
only the CONDITIONS that would prove or disprove the hypothesis.
- Regardless of posture: never specify a reverse shell, host credential \
exfiltration, or a command intended to persist/escape the sandbox — that \
is refused at execution time regardless of what you write here, but do not \
plan around needing one; every genuine memory-safety/injection/traversal \
bug is provable without it.
- static_plan.decisive_observable, dynamic_plan.decisive_observable, and \
hypotheses.decisive_observable must all describe the SAME underlying fact, \
just phrased for each track/purpose. Likewise hypotheses.oracle/\
dynamic_plan.oracle must describe the same confirming condition, and \
hypotheses.disconfirm_condition/dynamic_plan.disconfirm_condition the same \
disconfirming condition.
- Never invent facts the finding/target data doesn't support — an unknown \
addr/offset is an empty string, not a guess.

Return ONLY a single JSON object (no markdown fences, no commentary, no \
<think> reasoning in your final answer) matching this shape exactly:
{"threat_model": {...}, "hypotheses": {"a": "...", "b": "...", \
"oracle": "...", "disconfirm_condition": "...", \
"decisive_observable": "..."}, "static_plan": {"target_function": "...", \
"source_fields": [...], "sink_names": [...], \
"expected_intermediate_calls": [...], "sanitizer_patterns": [...], \
"crosscheck_required": true, "decisive_observable": "..."}, \
"dynamic_plan": {"reach_strategy": "...", "entry_addr": "...", \
"target_addr": "...", "sink_addr": "...", "guards": [{"name": "...", \
"addr": "...", "forced_value": "..."}], "argv_template": [...], \
"trigger_shape": "...", "preconditions": [...], "oracle": "...", \
"disconfirm_condition": "...", "payload_marker": "...", \
"required_signals": [...], "decisive_observable": "..."}, \
"static_runnable": true, "dynamic_runnable": true}
"""


def render_strategy_brief(
    candidate: VerificationCandidate, target: TargetMeta, *, settings: Settings
) -> str:
    """Renders the finding + `mem.target` facts into the plain-text brief
    the strategy agent reasons over — layers `TargetMeta` on top of the
    SAME finding fields `agent.prompts.render_finding_brief` already
    renders for the static track, without importing that function (keeping
    this module's prompt fully independent of the existing generator/
    evaluator prompt module, per this project's "don't touch Joern" reuse
    discipline). Also states this run's containment posture
    (`Settings.stage5_allow_real_payloads`) explicitly, so the strategy
    agent knows whether payload_marker must stay benign-only (see the
    system prompt's HARD RULES) or is a fallback-only field this run."""
    finding = candidate.finding
    posture = (
        "real payloads allowed"
        if settings.stage5_allow_real_payloads
        else "benign-only (payload_marker must be a scoped touch/echo/mkdir side effect)"
    )
    lines = [
        f"global_id: {candidate.global_id}",
        f"bin_id: {candidate.bin_id}",
        f"payload posture: {posture}",
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
    # oracle/disconfirm_condition are the Node 8 deterministic first pass's
    # ground truth (match_oracle) — an empty oracle would mean every round
    # falls straight through to the LLM router with nothing to check
    # mechanically first, defeating spec Design Principle #1 ("ground every
    # claim in a verifiable event, not the LLM's opinion"). Same "non-empty
    # in every place it must appear" looseness as decisive_observable
    # above — disconfirm_condition is checked too since an empty one would
    # leave hypothesis B with no positive proof condition either.
    oracles = (plan.hypotheses.oracle.strip(), plan.dynamic_plan.oracle.strip())
    disconfirms = (
        plan.hypotheses.disconfirm_condition.strip(),
        plan.dynamic_plan.disconfirm_condition.strip(),
    )
    return all(observables) and all(oracles) and all(disconfirms)


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
    command_log: CommandLog | None = None,
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

    `llm` is normally a `llm_logging.LoggingChatModel` (see `fvvw.graph.
    resolve_fvvw_deps`) — the raw prompt/raw response for every attempt is
    ALREADY captured by that wrapper's own `ainvoke`, before this function
    ever parses anything. `command_log`, when given, additionally logs the
    "after parser" half PER ATTEMPT — whether that attempt's response
    parsed+validated (and the resulting `StrategyPlan`) or failed
    (and why) — something a bare final return value can't show for the
    attempts that got rejected along the way.
    """
    brief = render_strategy_brief(candidate, target, settings=settings)
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
            if command_log is not None:
                command_log.record(
                    node="strategy_agent",
                    kind="parsed_action",
                    command=f"strategy_agent attempt {attempt} parsed+validated",
                    payload=plan.model_dump_json(),
                    ok=True,
                )
            return plan

        if command_log is not None:
            reason = (
                "parsed but failed validate_decisive_observable"
                if plan is not None
                else "did not parse as a StrategyPlan"
            )
            command_log.record(
                node="strategy_agent",
                kind="parse_failed",
                command=f"strategy_agent attempt {attempt}: {reason}",
                payload=last_raw,
                ok=False,
            )

        if attempt < max_regenerate_attempts:
            nudge = (
                "Your previous response either did not parse as the required JSON "
                "object, or one of hypotheses/static_plan/dynamic_plan's "
                "decisive_observable/oracle/disconfirm_condition fields was empty or did "
                "not consistently restate the same underlying claim. Return ONLY the "
                "corrected JSON object this time, with decisive_observable describing the "
                "same fact everywhere it appears, and hypotheses.oracle/dynamic_plan.oracle "
                "(and hypotheses.disconfirm_condition/dynamic_plan.disconfirm_condition) "
                "both filled in with the exact, mechanically-checkable confirm/disconfirm "
                "conditions — never left empty."
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
