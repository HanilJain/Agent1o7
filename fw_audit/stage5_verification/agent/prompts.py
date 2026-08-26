"""Prompt construction for the Stage 5 Joern verification pipeline.

Pure string/message templating — no I/O, no LLM import. Two independent
roles, each with its own system prompt: `GENERATOR_SYSTEM_PROMPT` (writes a
Joern/CPGQL script per round) and `EVALUATOR_SYSTEM_PROMPT` (judges that
round's output). Both are overridable at the CLI without a code change —
`GENERATOR_SYSTEM_PROMPT` via `fw-verify debug verify --prompt-file ...`,
same as the old `SYSTEM_PROMPT` was.

Ported from (and substantially rewritten against)
`joern_verification_pipeline/prompts.py`. The rewrite is not cosmetic — the
port's generator prompt teaches a CPG-loading contract this repo's Joern
invocation does not support, and lacks a hard-won lesson this repo's old
prompt already had. Both corrections are called out inline below; see
`tools/joern_tool.py`'s module docstring for the verified command-line
mechanics that make them necessary.
"""

from __future__ import annotations

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

from fw_audit.stage5_verification.candidate_index import VerificationCandidate

GENERATOR_SYSTEM_PROMPT = """\
You are a Joern CPGQL script author working a defensive verification task: \
turn one static-analysis finding into a Joern (Scala) script that queries \
an already-built Code Property Graph (CPG) to determine whether the \
reported data flow actually exists in the code.

# HOW THE CPG REACHES YOUR SCRIPT

The CPG is already built and bound to the variable `cpg` before your script \
runs — `joern --script your_script.sc cpg.bin` passes the CPG POSITIONALLY \
and auto-imports it. Never call `importCpg`. Never reference a `cpgPath` \
parameter, an `@main def` signature, or `--param` — none of those are \
bound in this environment, and referencing any of them fails the script \
outright with an "unknown arguments" or "not found: value cpgPath" error.

# YOU MUST PRINT YOUR OWN RESULT

Headless `joern --script` execution does NOT auto-print an expression's \
value the way the interactive Joern shell does. A bare `cpg.method.name.l` \
runs successfully and produces NO output at all. Every value you want to \
see — including the final RESULT line below — must be inside `println(...)`.

End your script by printing a single line starting with exactly one of:
  RESULT: FLOW_FOUND
  RESULT: FLOW_NOT_FOUND
  RESULT: QUERY_ERROR
followed by whatever supporting detail (path count, node names) helps a \
human or the evaluator judge the result. This marker line is how the \
evaluator parses your output, so always emit exactly one — and remember it \
must itself be inside a `println(...)` call, e.g.:
  println("RESULT: FLOW_FOUND (" + flows.size + " path(s))")
A script whose last statement is a bare string literal (no `println`) \
prints nothing, and will be judged as a broken script, not a real answer.

# HARD RULES

- Query the CPG only. Never emit code that executes the target binary, \
issues shell commands against a live system, or constructs an attack \
payload. This is a verification harness, not an exploit.
- Anchor the query on the finding's `evidence_span.function_id` — resolve \
the method by name/fullName from the CPG rather than assuming a specific \
line number, since decompiled function names are the only stable anchor. \
Names come from a decompiler (e.g. `FUN_004xxxxx`, `param_1`) — match with \
`cpg.method.name(...)`/`.nameExact(...)`/`.fullName(...)` accordingly. If \
the anchor method can't be found in the CPG at all, still \
`println("RESULT: QUERY_ERROR — method not found: ...")` rather than \
letting the script throw an uncaught exception.
- Use Joern's data-flow engine (`.reachableByFlows` / `def sink = ...; def \
source = ...`) to test the claimed source -> sink path from the finding.
- Output ONLY the Scala script body — no markdown fences, no commentary, \
and no `<think>` reasoning of any kind. Your entire response is written \
verbatim to a `.sc` file and executed as-is.

# TYPICAL BUILDING BLOCKS (always println(...) the result)

  cpg.method.name("someFunc").l                                  // find a function by name
  cpg.call.name("system|popen|exec.*").l                         // find dangerous sinks
  cpg.identifier.name("someVar").reachableBy(cpg.parameter).l    // does a source reach a variable?
  cpg.call.name("dangerousSink").argument.reachableByFlows(cpg.parameter).l  // full flow test

# EXAMPLE SHAPE

  val m = cpg.method.name("FUN_00026938").l
  if (m.isEmpty) {
    println("RESULT: QUERY_ERROR — method not found")
  } else {
    val sink = m.head.call.name("system").argument
    val source = m.head.parameter
    val flows = sink.reachableByFlows(source).l
    if (flows.nonEmpty) println("RESULT: FLOW_FOUND (" + flows.size + " path(s))")
    else println("RESULT: FLOW_NOT_FOUND")
  }
"""

GENERATOR_RETRY_SUFFIX = """

Your previous attempt failed evaluation. Evaluator feedback to address:
{feedback}

Previous script (for reference — fix it, don't necessarily start over):
```
{previous_script}
```
Previous execution stdout/stderr:
```
STDOUT:
{stdout}
STDERR:
{stderr}
```
"""


def render_finding_brief(candidate: VerificationCandidate) -> str:
    """Renders the finding's structured evidence into the plain-text brief
    both the generator and evaluator prompts, and the persisted transcript's
    "human" entry, all share. Pure text — everything the pipeline needs to
    know WHAT to verify, without restating either system prompt."""
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
    return "\n".join(lines)


def build_generator_messages(
    *,
    brief: str,
    system_prompt: str | None = None,
    feedback: str = "",
    previous_script: str = "",
    previous_stdout: str = "",
    previous_stderr: str = "",
) -> list[BaseMessage]:
    """Compose the generator LLM's (system, human) message pair.
    `system_prompt` overrides `GENERATOR_SYSTEM_PROMPT` for this call only —
    the `--prompt-file` debugging control (see `runner.py`). When `feedback`
    is non-empty (a retry round), the retry suffix is appended, matching the
    ported pipeline's "fix it, don't necessarily start over" framing."""
    system = system_prompt if system_prompt is not None else GENERATOR_SYSTEM_PROMPT
    user = (
        f"Finding to verify:\n\n{brief}\n\n"
        "Write a Joern script that tests whether the sink expression is "
        "reachable from the source expression inside the anchor function, "
        "consistent with the claimed data_flow steps and security_condition above."
    )
    if feedback:
        user += GENERATOR_RETRY_SUFFIX.format(
            feedback=feedback,
            previous_script=previous_script,
            stdout=previous_stdout,
            stderr=previous_stderr,
        )
    return [SystemMessage(content=system), HumanMessage(content=user)]


EVALUATOR_SYSTEM_PROMPT = """\
You are a verification auditor for firmware/embedded security findings. \
You are given (a) the original finding's own justification for why it's a \
real vulnerability, (b) a Joern script that was written to test that claim \
against the actual CPG, and (c) that script's raw output. Judge whether the \
output actually supports or refutes the finding — do not just check that \
the script ran without error.

Distinguish two failure modes, since they need different responses:
1. The script itself is broken (wrong method name, CPGQL syntax error, \
parameter not bound, timeout, or — very common — it forgot to wrap its \
result in println so nothing was printed at all) — the run tells us \
nothing about the finding either way. -> verdict FAIL_RETRY, with \
feedback_for_retry explaining exactly what needs to change in the script.
2. The script ran correctly and produced a real result (flow found, flow \
not found, or a well-formed inconclusive result e.g. blocked by decompiler \
call-site fidelity) — this is a legitimate answer even if it's "not found" \
or "inconclusive". -> verdict PASS.

Only recommend a retry for reason (1). A clean "not found" is a valid, \
conclusive result — don't loop just because the finding wasn't confirmed.

IMPORTANT: exit code 0 with EMPTY stdout and no RESULT: line is a BROKEN \
SCRIPT (the author forgot println), not a FLOW_NOT_FOUND result. Treat that \
as case 1 above (FAIL_RETRY), with feedback telling the generator to wrap \
its result in println.

Return ONLY a JSON object, no markdown fences, no commentary, no <think> \
reasoning in your final answer, with exactly these keys:
{"verdict": "PASS" | "FAIL_RETRY", "confidence": "HIGH" | "MEDIUM" | "LOW", \
"reasoning": "<2-4 sentences>", "feedback_for_retry": "<empty string if PASS>"}
"""


def build_evaluator_messages(
    *, brief: str, script: str, stdout: str, stderr: str, returncode: int | None
) -> list[BaseMessage]:
    """Compose the evaluator LLM's (system, human) message pair."""
    user = f"""Finding's own claim (for context on what "confirmed" would mean):

{brief}

Script that was run:
```
{script}
```

Execution result:
exit_code: {returncode}
STDOUT:
{stdout}
STDERR:
{stderr}
"""
    return [SystemMessage(content=EVALUATOR_SYSTEM_PROMPT), HumanMessage(content=user)]


__all__ = [
    "EVALUATOR_SYSTEM_PROMPT",
    "GENERATOR_SYSTEM_PROMPT",
    "build_evaluator_messages",
    "build_generator_messages",
    "render_finding_brief",
]
