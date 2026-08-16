"""Renders one `VerificationReport` to a human-readable Markdown report.

Answers your "simple, easy to understand report... how to test the claim"
ask directly: this is meant to be readable without opening the JSON, and it
ends with an exact, copy-pasteable reproduction command.
"""

from __future__ import annotations

from fw_audit.common.findings import Finding
from fw_audit.common.verification import VerificationReport
from fw_audit.stage5_verification.tools.joern_tool import (
    CPG_FILENAME,
    joern_parse_command,
    joern_script_command,
)


def render_report(report: VerificationReport, *, finding: Finding | None = None) -> str:
    """`finding` is optional context (the original Stage 3 claim) — when
    given, it's summarized at the top so the report is self-contained
    without cross-referencing `stage3/findings/*.json` by hand."""
    lines: list[str] = []
    lines.append(f"# Verification report: {report.global_id}")
    lines.append("")
    lines.append(f"**Verdict: {report.verdict.value}** (confidence: {report.confidence or 'n/a'})")
    lines.append("")
    lines.append(report.summary or "_(no summary provided)_")
    lines.append("")

    if finding is not None:
        lines.append("## Original claim (Stage 3)")
        lines.append("")
        cwe_label = ", ".join(finding.cwe) or "no CWE"
        lines.append(f"- **{finding.title}** ({finding.category}, {cwe_label})")
        lines.append(f"- source: `{finding.source.expression}` ({finding.source.type})")
        lines.append(f"- sink: `{finding.sink.expression}` ({finding.sink.type})")
        lines.append(f"- claimed condition: {finding.security_condition}")
        lines.append("")

    lines.append("## What was checked")
    lines.append("")
    lines.append(
        f"Tool: **{report.tool}**. Model: `{report.model}`. Binary: `{report.bin_id}`."
    )
    lines.append("")

    lines.append("## CPG build")
    lines.append("")
    status = "succeeded" if report.cpg_build.ok else "FAILED"
    lines.append(
        f"`{report.cpg_build.command}` — {status} in {report.cpg_build.duration_seconds:.1f}s."
    )
    if not report.cpg_build.ok and report.cpg_build.stderr:
        lines.append("")
        lines.append("```")
        lines.append(report.cpg_build.stderr.strip()[-2000:])
        lines.append("```")
    lines.append("")

    lines.append(f"## Query attempts ({len(report.attempts)})")
    lines.append("")
    for attempt in report.attempts:
        status = "ok" if attempt.ok else f"FAILED (returncode={attempt.returncode})"
        lines.append(f"### Attempt {attempt.attempt_index} — {status}")
        lines.append("")
        lines.append("```scala")
        lines.append(attempt.script.strip())
        lines.append("```")
        lines.append("")
        output = attempt.stdout if attempt.ok else attempt.stderr
        if output.strip():
            lines.append("Output:")
            lines.append("```")
            lines.append(output.strip()[-2000:])
            lines.append("```")
            lines.append("")

    lines.extend(_render_transcript_section(report))

    lines.append("## Evidence")
    lines.append("")
    lines.append(report.evidence or "_(no evidence recorded)_")
    lines.append("")

    if report.recommended_next_steps:
        lines.append("## Recommended next steps")
        lines.append("")
        for step in report.recommended_next_steps:
            lines.append(f"- {step}")
        lines.append("")

    lines.append("## How to reproduce this yourself")
    lines.append("")
    lines.append(
        "From a workspace directory containing the same `whole.c` this run used "
        f"(`stage5/workspace/{_sanitize(report.global_id)}/`), inside the Joern sandbox image:"
    )
    lines.append("")
    lines.append("```bash")
    lines.append(joern_parse_command())
    if report.attempts:
        last_script_name = f"query_{report.attempts[-1].attempt_index:03d}.sc"
        lines.append(joern_script_command(last_script_name))
    else:
        lines.append(joern_script_command("your_query.sc"))
    lines.append("```")
    lines.append("")
    lines.append(
        f"Or run it through fw-audit directly: `fw-verify debug script --workspace "
        f"<path to that directory> --script-file <your .sc file>` — see this stage's "
        f"CLAUDE.md for the full debugging command reference. The CPG itself "
        f"(`{CPG_FILENAME}`) is left in the workspace directory when "
        "`FWA_STAGE5_KEEP_WORKSPACE=true` (or `--keep-workspace`), so it doesn't need "
        "to be rebuilt to try another query."
    )
    return "\n".join(lines)


def _render_transcript_section(report: VerificationReport) -> list[str]:
    """The full "chat with tools" log — what the agent said, which tools it
    called with what arguments, and each tool's response, in order. The
    `system` entry (the static verification brief, `agent.prompts.
    SYSTEM_PROMPT` unless overridden) is skipped here to keep every report
    readable rather than repeating ~1-2KB of boilerplate every time — its
    presence is noted instead, with a pointer to where to actually see it."""
    lines: list[str] = ["## Agent transcript", ""]

    visible = [e for e in report.transcript if e.role != "system"]
    if not visible:
        lines.append("_(no transcript recorded)_")
        lines.append("")
        return lines

    lines.append(
        "The system prompt (verification instructions) is omitted below — see "
        "`agent/prompts.py`'s `SYSTEM_PROMPT`, or the `--prompt-file` you passed, "
        "for its exact text."
    )
    lines.append("")

    for entry in visible:
        if entry.role == "human":
            lines.append(f"**[turn {entry.turn}] Task given to the agent:**")
            lines.append("")
            lines.append("> " + entry.content.replace("\n", "\n> "))
            lines.append("")
        elif entry.role == "ai":
            lines.append(f"**[turn {entry.turn}] Agent:**")
            lines.append("")
            if entry.content.strip():
                lines.append(entry.content.strip())
                lines.append("")
            for call in entry.tool_calls:
                args_str = ", ".join(f"{k}={v!r}" for k, v in call.args.items())
                lines.append(f"→ calls `{call.name}({args_str})`")
                lines.append("")
        elif entry.role == "tool":
            lines.append(f"**[turn {entry.turn}] Tool response:**")
            lines.append("")
            lines.append("```")
            lines.append(entry.content.strip()[-2000:] or "(empty)")
            lines.append("```")
            lines.append("")

    return lines


def _sanitize(global_id: str) -> str:
    return global_id.replace("::", "__")
