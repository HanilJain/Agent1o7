"""The Identifier Agent (Component 2): tree.txt text -> identified-binary list.

Privilege boundary (Stage 1 policy): this module has NO execution access and
NO Database access. It reads only the `tree_text` string passed to it and
returns structured data — it never imports `fw_audit.executors`, `os`,
`pathlib`, or `subprocess`. An import-purity test enforces this boundary
(see tests/test_identifier_agent.py); keep it that way when editing.
"""

from __future__ import annotations

import json
import re

from pydantic import BaseModel, ValidationError

from fw_audit.common.constants import TARGET_DAEMONS
from fw_audit.common.schemas import IdentifiedBinary
from fw_audit.config.llm_config import AgentRole, get_llm_for_agent
from fw_audit.stage1_ingestion.identifier.prompts import build_prompt


class IdentifierUnavailableError(RuntimeError):
    """No LLM provider is reachable, or its output couldn't be parsed.

    Per the Stage 1 policy the Identifier Agent is REQUIRED (no deterministic
    fallback) — this is a hard-fail signal for the calling node
    (`nodes.identify_binaries`), not something to silently degrade past.
    """


class _IdentifiedBinaryList(BaseModel):
    binaries: list[IdentifiedBinary]


def _extract_json(text: str) -> str:
    """Best-effort extraction of a JSON array/object from LLM response text.

    Handles the common case of a model wrapping its JSON in a markdown code
    fence despite being instructed not to.
    """
    fence_match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    return fence_match.group(1) if fence_match else text.strip()


async def identify_binaries(tree_text: str) -> list[IdentifiedBinary]:
    """Ask the Identifier Agent which binaries in `tree_text` are worth analyzing.

    Raises :class:`IdentifierUnavailableError` if no LLM is reachable or its
    output can't be parsed into the expected schema. Callers must treat this
    as a hard failure of the run — there is no heuristic fallback here.
    """
    try:
        llm = get_llm_for_agent(AgentRole.STAGE1_BINARY_IDENTIFIER)
    except (ImportError, ValueError) as exc:
        raise IdentifierUnavailableError(str(exc)) from exc

    prompt = build_prompt(tree_text, target_daemons=TARGET_DAEMONS)

    try:
        response = await llm.ainvoke(prompt)
    except (OSError, TimeoutError) as exc:
        raise IdentifierUnavailableError(f"LLM call failed: {exc}") from exc

    content = response.content if hasattr(response, "content") else response
    if not isinstance(content, str):
        content = str(content)

    try:
        payload = json.loads(_extract_json(content))
        parsed = _IdentifiedBinaryList.model_validate(
            {"binaries": payload} if isinstance(payload, list) else payload
        )
    except (json.JSONDecodeError, ValidationError) as exc:
        raise IdentifierUnavailableError(
            f"Identifier Agent returned unparseable output: {exc}"
        ) from exc

    return parsed.binaries
