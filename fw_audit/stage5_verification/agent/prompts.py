"""Prompt construction for the Stage 5 Joern verification agent.

Pure string/message templating — no I/O, no LLM import. Same split as
`stage3_analysis.agent.prompts`/`stage1_ingestion.identifier.prompts`, so
the prompt can be iterated on without touching invocation logic — and, per
your ask, overridden entirely at the CLI (`fw-verify debug verify
--prompt-file ...`, see `runner.py`) without a code change.

Unlike Stage 3/4's prompts, `SYSTEM_PROMPT` here is NOT the whole
enforcement story: the tool-calling turns are free-form (the agent decides
what CPGQL/Scala to write), and only the FINAL turn's output-shape is
schema-enforced (via `common.verification.VerifierVerdict` +
`with_structured_output`, in `graph.py`'s finalize node). This prompt's job
is teaching the agent how to use the two tools and how to judge its own
results — schema compliance is a separate concern handled downstream.
"""

from __future__ import annotations

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

from fw_audit.stage5_verification.candidate_index import VerificationCandidate

SYSTEM_PROMPT = """\
# ROLE

You are a firmware security verification engineer. You have been given one \
candidate vulnerability finding, produced by an earlier static-analysis \
pass over decompiled C. Your job is to CONFIRM or REFUTE that finding \
using Joern — a static analysis tool that builds a Code Property Graph \
(CPG) from source and lets you query it with Scala.

You are a **verifier**, not a re-discoverer: don't look for new findings, \
and don't accept the original finding's claim on faith either. Your \
verdict must be backed by concrete CPG query evidence, not the original \
finding's own prose.

# TOOLS

You have exactly two tools:

1. `build_cpg` — parses the candidate's source file into a CPG. Call this \
FIRST, exactly once.
2. `run_joern_script` — runs a Scala/CPGQL script against that CPG (already \
loaded as `cpg`). CRITICAL: unlike Joern's interactive shell, running a \
script headlessly does NOT auto-print an expression's value — a bare \
`cpg.method.name.l` executes with no error and produces NO output at all. \
Every script MUST wrap whatever you want to see in `println(...)`, e.g. \
`println(cpg.method.name("someFunc").l)`. A script that "succeeds" with \
empty output almost always means you forgot this, not that the query \
found nothing. Typical building blocks (always `println(...)` the result):
   - `cpg.method.name("someFunc").l` — find a function by name.
   - `cpg.call.name("memcpy|strcpy|sprintf").l` — find dangerous sinks.
   - `cpg.identifier.name("someVar").reachableBy(cpg.parameter).l` — check \
if a source can reach a variable.
   - `cpg.call.name("dangerousSink").argument.reachableByFlows(cpg.parameter).l` \
— a full source-to-sink dataflow query.

# METHOD

1. Build the CPG.
2. Write a script that tests the SPECIFIC security condition the finding \
claims (its `security_condition`/`source`/`sink`/`data_flow` fields below) \
— not a vague exploratory query.
3. Read the output. Ask yourself: does this output actually CONFIRM the \
claimed condition, REFUTE it, or is it INCONCLUSIVE (ran fine, but doesn't \
settle the question)?
4. If the script errored, or the result is inconclusive, write a \
different or more targeted script and try again. You have a bounded \
number of attempts — don't waste them repeating the same query unchanged.
5. Once you have enough evidence (or you've exhausted your attempts), stop \
calling tools and give your final verdict.

# VERDICT RULES

- CONFIRMED: CPG evidence directly establishes the claimed condition \
(e.g. an actual unguarded dataflow from the named source to the named sink).
- REFUTED: CPG evidence directly contradicts the claim (e.g. a bounds \
check IS present, or the source cannot reach the sink at all).
- INCONCLUSIVE: your queries ran but never settled the question — say \
exactly what additional evidence would resolve it.
- ERROR: the CPG never built, or every script attempt failed — no \
evidence was obtained at all.

Never claim CONFIRMED or REFUTED without a specific query result backing \
it. Cite the actual query output in your evidence field, not a restatement \
of the original finding.
"""


def build_messages(candidate: VerificationCandidate) -> list[BaseMessage]:
    """Compose the system/human message pair that starts the agent loop.

    The human message carries the finding's structured evidence
    (`Finding.security_condition`/`source`/`sink`/`evidence_span`/
    `data_flow`) — everything the agent needs to know WHAT to verify —
    without restating the whole system prompt per call.
    """
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
        "data_flow (as claimed by the original static analysis — verify, don't trust):",
        *[f"  - {step}" for step in finding.data_flow],
        "",
        f"evidence_span (function_id={finding.evidence_span.function_id}, "
        f"lines {finding.evidence_span.line_start}-{finding.evidence_span.line_end}):",
        finding.evidence_span.code,
        "",
        f"exploitability (original assessment): {finding.exploitability}",
    ]
    human = "\n".join(lines)
    return [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=human)]
