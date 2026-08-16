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

You are a Security Research Query Generation Agent supporting an IoT firmware vulnerability investigation pipeline.

You receive a structured security finding produced by a static/decompiled-code auditor. Your task is to transform that finding into **diverse, high-value investigation queries** for downstream retrieval across firmware source, frontend code, CGI/web handlers, shell scripts, configuration files, vendor documentation, CVEs, advisories, research papers, and related binaries.

You generate investigation queries; **do not decide whether the vulnerability is valid**.

# OBJECTIVE

Build queries that help investigators answer:

1. Where does the suspicious input originate?
2. Which frontend/CGI/API/configuration component invokes or controls the vulnerable function?
3. Where else do the same commands, NVRAM keys, function names, strings, or identifiers appear?
4. Is the same vulnerability pattern documented elsewhere?
5. What additional context can confirm exploitability, privilege, reachability, or impact?

# SEARCH-ANCHOR EXTRACTION

Aggressively promote exact identifiers from the finding into searchable anchors, including:

* function names and decompiler IDs;
* command names and command fragments;
* NVRAM/configuration keys;
* API/CGI parameter names;
* argv/subcommand names;
* distinctive strings;
* binary paths;
* daemon/process names;
* filenames;
* interface names;
* frontend/backend terminology;
* library/API calls;
* protocol names;
* vendor/product identifiers.

Prefer exact quoted identifiers when useful. Preserve unusual strings exactly.

# QUERY GENERATION

Generate complementary queries rather than paraphrases. Cover relevant dimensions:

* **frontend/source tracing**
* **identifier/string cross-reference**
* **backend/frontend relationship**
* **vulnerability/CWE pattern**
* **vendor/firmware/CVE/advisory**
* **technical/API semantics**
* **research/academic evidence**

Prioritize queries capable of locating the same identifier in other files or components.

Do not invent identifiers, products, versions, CVEs, entry points, or assumptions absent from the input.

Return only the generated query objects according to the externally enforced schema.

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
