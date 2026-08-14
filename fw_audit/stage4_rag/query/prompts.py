"""Prompt construction for Component 3's multi-query generator agent.

Pure string/message templating — no I/O, no LLM import. Mirrors
`stage3_analysis.agent.prompts`'s system/human split so a provider's prompt
caching can skip re-processing the constant system prompt across calls.

**PLACEHOLDER SYSTEM PROMPT.** Per `MASTERPLAN_STAGE4.md` §7, this system
prompt's specialized content is the user's to supply — nothing here is
invented as a substitute for that. The prompt below is a minimal, honest
default (not a guess at the user's intended wording) so the pipeline runs
end to end today; replace `SYSTEM_PROMPT` with the user's actual brief when
supplied. Output-shape enforcement is NOT part of this prompt — it is
`query.schemas.MultiQueryPlan` enforced via `with_structured_output`, same
convention as Stage 3 (see `common.findings`'s docstring).
"""

from __future__ import annotations

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

from fw_audit.common.findings import Finding

# TODO(user): replace with the specialized query-generation prompt — this is
# a placeholder default, not the final content.
SYSTEM_PROMPT = """\
# ROLE

You are a firmware security research assistant helping trace a candidate \
vulnerability finding back to its real data source (NVRAM, HTTP parameter, \
network input, IPC, file, CLI argument, environment variable, or a \
hardcoded constant) across the whole firmware image.

# OBJECTIVE

Given one Stage 3 finding — a sink expression, an incomplete source guess, \
and (often) a list of missing context the original chunk-local analysis \
could not resolve — produce 4-5 targeted search queries. Each query will be \
run against a vector index of the firmware's rootfs text files (web UI, \
CGI scripts, config files) and every decompiled binary's cleaned C source.

Queries should target plausible sources of the tainted value: the NVRAM key \
name if one is visible, the HTTP parameter name, related function names, \
config file keys, or any identifier mentioned in the finding's evidence \
that could appear verbatim elsewhere in the firmware.

Do not invent identifiers that don't appear in the supplied finding — base \
each query on what the finding evidence actually names.
"""


def build_messages(finding: Finding, *, global_id: str) -> list[BaseMessage]:
    """Compose the system/human message pair sent to the query-planner LLM."""
    human = (
        f"Generate a MultiQueryPlan for this Stage 3 finding.\n\n"
        f"finding_id (global): {global_id}\n"
        f"title: {finding.title}\n"
        f"category: {finding.category}\n"
        f"sink: {finding.sink.expression} ({finding.sink.type})\n"
        f"source (as guessed by Stage 3): {finding.source.expression} "
        f"({finding.source.type}, attacker_control={finding.source.attacker_control})\n"
        f"decision: {finding.decision.value}\n"
        f"missing_context: {finding.missing_context}\n"
        f"data_flow: {finding.data_flow}\n"
        f"why_vulnerable: {finding.why_vulnerable}\n"
    )
    return [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=human)]
