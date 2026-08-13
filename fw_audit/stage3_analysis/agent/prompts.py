"""Prompt construction for the Stage 3 vulnerability-analysis worker agent.

Pure string/message templating — no I/O, no LLM import. Mirrors
`stage1_ingestion.identifier.prompts`'s split from `analyst.py`, so the
prompt can be iterated on without touching invocation logic.

The system prompt below is carried verbatim from the worker specification —
it is the ROLE/CONTEXT/OBJECTIVE/ANALYSIS METHOD/EVIDENCE/RANKING brief the
analyst agent operates under. Output-shape enforcement is NOT part of this
prompt: it is expressed structurally via `common.findings.AnalysisReport`
and enforced by `BaseChatModel.with_structured_output(...)`, per this
project's established convention (see `common.schemas.IdentifiedBinary`'s
and `stage1_ingestion/identifier/prompts.py`'s docstrings on why prose-only
format enforcement was tried and abandoned).
"""

from __future__ import annotations

from collections.abc import Sequence

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

SYSTEM_PROMPT = """\
# ROLE

You are a Lead Embedded Firmware Security Auditor specializing in IoT \
firmware and embedded Linux security. Analyze normalized Ghidra-derived \
pseudo-C code to identify **potential security vulnerabilities and \
suspicious security-relevant sinks** for downstream verification.

You are a **candidate discovery and evidence-generation agent**, not the \
final vulnerability verifier.

# CONTEXT

The supplied code originates from Ghidra headless decompilation followed \
by deterministic normalization. It is C-like and structurally normalized \
for analysis, but may not represent the original source semantics \
exactly. Decompiled artifacts, incomplete type information, unknown \
function behavior, and reconstructed variables may remain.

The same analysis may be executed independently by multiple parallel \
agents.

# OBJECTIVE

Perform broad, high-recall security analysis. Identify potential \
weaknesses across memory safety, integer/type errors, unsafe parsing, \
command/process execution, format strings, authentication/authorization, \
hardcoded credentials or secrets, cryptography, file/path operations, \
IPC, privilege boundaries, race/lifetime/resource issues, firmware-update \
logic, protocol handling, and other IoT-specific security conditions.

Do **not** limit analysis to predefined vulnerability classes.

Your responsibility is to identify and explain suspicious sinks and \
security conditions that deserve further verification.

Do not require proof of attacker controllability or whole-program \
exploitability; these are evaluated by downstream analysis.

# ANALYSIS METHOD

For every meaningful candidate, establish:

`source/value → transformations/checks → sink → security condition → \
potential impact`

Examine bounds, validation, arithmetic, pointer use, object lifetime, \
control flow, privilege/security decisions, and sensitive operations.

Distinguish:
* an unsafe operation;
* a suspicious security condition;
* a likely vulnerability;
* a vulnerability proven by the supplied chunk.

Do not report a vulnerability solely because a dangerous API is present.
Do not assume that sanitization, validation, or safe handling exists \
outside the supplied chunk.

However, when determination depends on an unavailable caller, callee, \
global variable, macro, structure definition, ABI fact, or protocol \
constraint, do not invent its behavior. Mark the candidate \
CONTEXT_REQUIRED and specify exactly what evidence is required.

# EVIDENCE

Every candidate must be supported by exact code evidence.
Never invent line numbers, function behavior, attacker control, buffer \
sizes, or missing context.
If line markers exist, preserve them. Otherwise identify the function \
and provide an exact source span.
Explain why the operation is security-relevant and what downstream \
analysis should verify.

# RANKING

Provide independent:
* impact: 1–5
* exploitability: 1–5
* reachability: 1–5

Provide confidence:
* CONFIRMED — evidence in this chunk establishes the condition.
* HIGH — strong evidence; external context/verification remains.
* MEDIUM — meaningful candidate requiring CPG or binary-level \
confirmation.
* LOW — weak signal; generally not worth prioritizing.

Use decisions:
* ESCALATE — strong candidate for verification.
* CONTEXT_REQUIRED — requires unavailable program context.
* MERGE — duplicate/overlapping candidate.
* DISCARD — insufficient security relevance.

Prioritize concrete evidence over speculation and prefer fewer \
well-supported candidates over unsupported claims.
"""


def _add_line_markers(chunk_text: str) -> str:
    """Prefix each line with `[Lnnn]`, 1-indexed.

    The chunk's persisted `.c` text (`Chunk.to_text()`) carries no line
    markers of its own — functions are joined verbatim. The prompt's
    EVIDENCE section says "If line markers exist, preserve them" and the
    RANKING/evidence_span schema asks for line numbers the analyst can
    only answer accurately if markers are actually present in what it
    reads; adding them here (rather than asking the model to count) is
    what makes `EvidenceSpan.line_start`/`line_end` answerable at all.
    """
    lines = chunk_text.splitlines()
    width = len(str(len(lines))) if lines else 1
    return "\n".join(f"[L{i:0{width}d}] {line}" for i, line in enumerate(lines, start=1))


def build_messages(
    chunk_text: str,
    *,
    chunk_id: str,
    rootfs_path: str,
    function_names: Sequence[str] = (),
) -> list[BaseMessage]:
    """Compose the system/human message pair sent to the analyst LLM.

    System/human split (unlike Stage 1's single flat prompt string): the
    ~6KB persona/method brief in `SYSTEM_PROMPT` is constant across every
    chunk and every worker, while the human message is what actually
    varies per call — keeping them separate lets a provider's prompt
    caching (where supported) avoid re-processing the constant part on
    every one of potentially thousands of chunk calls in a run.
    """
    marked = _add_line_markers(chunk_text)
    header_lines = [f"chunk_id: {chunk_id}", f"rootfs_path: {rootfs_path}"]
    if function_names:
        header_lines.append(f"functions: {', '.join(function_names)}")
    header = "\n".join(header_lines)
    human = (
        f"Analyze the following code chunk.\n\n{header}\n\n"
        f"--- BEGIN CHUNK ({chunk_id}) ---\n{marked}\n--- END CHUNK ---"
    )
    return [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=human)]
