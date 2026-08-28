"""`write_report` (FVVW v3 §6 node 18, §11) — the fork-join's LLM
disclosure-report node. Composes the seven-layer document plus a
reconciliation section (independence statement + `agreement` value)
from the completed STM (`run_fvvw`'s return dict).

Reuses `report_writer.py`'s deterministic scaffold conventions (code
fences, evidence-block truncation, `_sanitize`) for the parts that ARE
deterministic (raw tool output quoted verbatim, the reproduction command)
— that module itself is not imported or modified, since it renders the
STATIC track's OWN `VerificationReport` specifically and this module
renders the merged `FVVWReport` instead; duplicating the small amount of
shared formatting logic here keeps `report_writer.py`'s "don't touch"
status intact.
"""

from __future__ import annotations

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from fw_audit.common.findings import Finding
from fw_audit.common.verification import Agreement, TrackResult
from fw_audit.config.settings import Settings
from fw_audit.observability import run_config
from fw_audit.stage5_verification.candidate_index import VerificationCandidate

REPORT_SYSTEM_PROMPT = """\
You are a firmware vulnerability disclosure report writer. You are given \
the complete record of a two-track verification run — a Joern static \
analysis track and a QEMU+GDB dynamic emulation track, run independently \
under one shared strategy plan — plus their joint reconciliation. Compose \
a professional disclosure report in Markdown with these sections, in order:

1. Executive summary — lead with BOTH confidence axes (mechanism and \
reachability) and the agreement classification, in plain language a \
non-specialist reader can act on.
2. Component context — what binary/firmware component this is, briefly.
3. Architecture & threat model — the trust boundary and access requirement \
EXACTLY as characterized (never inflate "local shell access" into \
"unauthenticated remote attacker" or similar).
4. Vulnerability analysis — the vulnerable code path and how it compares to \
correct/reference handling.
5. Static analysis — summarize the Joern script's approach and result; the \
raw script/output is quoted verbatim elsewhere in the document, so \
summarize here, don't re-paste it.
6. Dynamic analysis — the emulation environment, harness, and how the \
required signals corroborated (or didn't) the claim.
6b. Reconciliation — explicitly state that static and dynamic ran \
INDEPENDENTLY under one shared plan, and report the agreement \
classification and what it means for confidence.
7. Method to reproduce + limitations — pull limitations directly from the \
supplied residual_unknowns list; never omit or soften one.

Hard rules: never state a confidence level not supported by the supplied \
data. Never claim reachability was confirmed if any guard was FORCED \
rather than naturally satisfied — say so explicitly. Output ONLY the \
Markdown document, no commentary before or after it, no markdown code \
fence wrapping the whole document.
"""


def _sanitize(global_id: str) -> str:
    return global_id.replace("::", "__")


def render_report_brief(
    *,
    candidate: VerificationCandidate,
    finding: Finding,
    static_result: TrackResult,
    dynamic_result: TrackResult,
    agreement: Agreement,
    mechanism_confidence: str,
    reachability_confidence: str,
    residual_unknowns: list[str],
    dynamic_gdb_transcript: str = "",
) -> str:
    """Render the complete STM into the plain-text brief `write_report`
    reasons over. Raw tool output (the static track's Joern
    stdout/attempts, the dynamic track's GDB transcript) is included
    VERBATIM — FVVW §11's "every raw tool output... quoted verbatim"
    requirement — so the LLM can quote/summarize accurately rather than
    inventing plausible-sounding output.
    """
    static_evidence = static_result.evidence or {}
    lines = [
        f"global_id: {candidate.global_id}",
        f"bin_id: {candidate.bin_id}",
        "",
        "## Original finding (Stage 3)",
        f"title: {finding.title}",
        f"category: {finding.category}",
        f"cwe: {', '.join(finding.cwe) or '(none)'}",
        f"source: {finding.source.expression} ({finding.source.type}, "
        f"attacker_control={finding.source.attacker_control})",
        f"sink: {finding.sink.expression} ({finding.sink.type})",
        f"security_condition: {finding.security_condition}",
        "",
        "## Static track (Joern) result",
        f"verdict: {static_result.verdict.value}",
        f"proved_hypothesis: {static_result.proved_hypothesis}",
        f"summary: {static_evidence.get('summary', '(none)')}",
        f"confidence: {static_evidence.get('confidence', '(none)')}",
        "",
        "Raw Joern attempts (verbatim):",
    ]
    for attempt in static_evidence.get("attempts", []):
        lines.append(f"--- attempt {attempt.get('attempt_index')} ---")
        lines.append("script:")
        lines.append(str(attempt.get("script", "")))
        lines.append("stdout:")
        lines.append(str(attempt.get("stdout", "")))
    lines += [
        "",
        "## Dynamic track (QEMU+GDB) result",
        f"verdict: {dynamic_result.verdict.value}",
        f"proved_hypothesis: {dynamic_result.proved_hypothesis}",
        f"evidence: {dynamic_result.evidence}",
        "",
        "Raw GDB transcript (verbatim):",
        dynamic_gdb_transcript or "(no transcript — dynamic track did not run to completion)",
        "",
        "## Reconciliation (joint_evaluate — deterministic, computed by code)",
        f"agreement: {agreement.value}",
        f"mechanism_confidence: {mechanism_confidence}",
        f"reachability_confidence: {reachability_confidence}",
        "",
        "residual_unknowns (include EVERY one of these in your limitations section, "
        "verbatim or lightly rephrased — never drop one):",
        *[f"  - {u}" for u in residual_unknowns],
    ]
    return "\n".join(lines)


async def write_report(
    *,
    candidate: VerificationCandidate,
    finding: Finding,
    static_result: TrackResult,
    dynamic_result: TrackResult,
    agreement: Agreement,
    mechanism_confidence: str,
    reachability_confidence: str,
    residual_unknowns: list[str],
    dynamic_gdb_transcript: str,
    llm: BaseChatModel,
    settings: Settings,
    system_prompt: str | None = None,
) -> str:
    """Run the `write_report` LLM node — one call, plain text in/text out
    (no structured output needed; the output IS the artifact, not
    something downstream code parses), same discipline as the static
    track's generator/evaluator roles. Returns the composed Markdown
    directly (no cleaning/JSON-extraction needed — unlike the
    generator/evaluator/strategy roles, this response is never re-parsed,
    so `agent.cleaning`'s think-stripping isn't required, though a caller
    piping this through a local model that emits `<think>` blocks should
    still consider stripping them before persisting — left as the caller's
    choice since this function's OWN contract is "return exactly what the
    LLM said").
    """
    brief = render_report_brief(
        candidate=candidate,
        finding=finding,
        static_result=static_result,
        dynamic_result=dynamic_result,
        agreement=agreement,
        mechanism_confidence=mechanism_confidence,
        reachability_confidence=reachability_confidence,
        residual_unknowns=residual_unknowns,
        dynamic_gdb_transcript=dynamic_gdb_transcript,
    )
    system = system_prompt if system_prompt is not None else REPORT_SYSTEM_PROMPT
    messages = [
        SystemMessage(content=system),
        HumanMessage(
            content=f"Complete verification record to report on:\n\n{brief}\n\n"
            "Compose the disclosure report now."
        ),
    ]
    response = await llm.ainvoke(
        messages,
        config=run_config(
            run_name="stage5.fvvw.write_report",
            metadata={"global_id": candidate.global_id},
            settings=settings,
        ),
    )
    content = getattr(response, "content", response)
    if isinstance(content, list):
        content = "\n".join(
            str(block.get("text", "")) for block in content if isinstance(block, dict)
        )
    return str(content).strip()


__all__ = ["REPORT_SYSTEM_PROMPT", "render_report_brief", "write_report"]
