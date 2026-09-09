"""Prompt construction for Stage 3b's claim-extraction call.

Pure string/message templating — no I/O, no LLM import. Mirrors
`stage3_analysis.agent.prompts`'s system/human split for the same reason:
the system prompt is constant across every block and every worker, so a
provider's prompt caching (where supported) can skip reprocessing it on
every one of potentially dozens of block calls per report.

Deliberately a TRANSCRIPTION brief, not an analysis brief — the opposite
posture from Stage 3's `SYSTEM_PROMPT` (which asks for judgment over code).
This prompt explicitly forbids inference: extract what the block asserts,
leave a field at its schema default rather than guessing. Output-shape
enforcement is, as in Stage 3, NOT part of this prompt — it's expressed
structurally via `common.claims.ClaimExtractionBatch` and enforced by
`BaseChatModel.with_structured_output(...)`.
"""

from __future__ import annotations

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

SYSTEM_PROMPT = """\
# ROLE

You are a transcription assistant extracting vulnerability CLAIMS from a \
third-party security report. This report is NOT ground truth — it makes \
assertions that a downstream verification pipeline will independently \
check. Your job is to faithfully transcribe what THIS block of the report \
says, not to judge, verify, or improve upon it.

# OBJECTIVE

For each distinct vulnerability claim in the supplied block, extract:
* what the report says is affected (a binary/service/component name, a \
function/symbol name, if named);
* what the report says the security condition is;
* what evidence (code, logs, config) the report itself offers;
* what the report itself asserts about severity/impact;
* any CVE/CWE identifiers the report itself cites.

# RULES — READ CAREFULLY

1. Never infer, assume, or add information the block does not state. If \
the block does not name a function, leave `function_hint` empty — do not \
guess one from context.
2. Never judge whether the claim is TRUE, exploitable, or well-supported. \
That is downstream verification's job, not yours.
3. Copy identifiers (CVE, CWE, function names, file paths) VERBATIM. Do \
not normalize, correct, or reformat them.
4. If a code listing or log excerpt is present in the block and belongs \
to a specific claim, copy it verbatim into that claim's evidence_quote.
5. If the block contains NO vulnerability claim of its own (prose \
introduction, table of contents, disclosure timeline, boilerplate), set \
`not_a_finding` to true and return an empty `claims` list.
6. A block may describe more than one distinct claim (e.g. a summary \
table row covering several CVEs for the same underlying issue) — extract \
each as its own entry rather than merging them.

Prioritize faithful transcription over completeness: an empty field is \
correct when the block simply doesn't say. Never fabricate a plausible-\
sounding value to fill a field.
"""


def build_messages(
    block_text: str, *, doc_stem: str, page_numbers: tuple[int, ...]
) -> list[BaseMessage]:
    """Compose the system/human message pair sent to the extractor LLM for
    one claim block.

    `page_numbers` is passed so the human message can remind the model
    what to put in each extracted claim's own `page_numbers` field —
    `driver.py` also fills this in deterministically afterward as a
    backstop, but giving the model the real numbers up front produces a
    more accurate first attempt.
    """
    pages_str = ", ".join(str(p) for p in page_numbers) if page_numbers else "unknown"
    header = f"source_document: {doc_stem}\npage(s): {pages_str}"
    human = (
        f"Extract vulnerability claims from the following report excerpt.\n\n"
        f"{header}\n\n"
        f"--- BEGIN EXCERPT ---\n{block_text}\n--- END EXCERPT ---"
    )
    return [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=human)]
