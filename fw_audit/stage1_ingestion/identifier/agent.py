"""The Identifier Agent (Component 2): tree.txt text -> identified-binary list.

Privilege boundary (Stage 1 policy): this module has NO execution access and
NO Database access. It reads only the `tree_text` string passed to it and
returns structured data — it never imports `fw_audit.executors`, `os`,
`pathlib`, or `subprocess`. An import-purity test enforces this boundary
(see tests/test_identifier_agent.py); keep it that way when editing.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, ValidationError

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
    """Structured-output schema requested from the LLM.

    `IdentifiedBinary` (see `common/schemas.py`) IS the wire shape here —
    strictly `{"path": str}`, nothing else. No separate "extension" field:
    `path` is required to be the complete filename (extension included) as
    it appears in the listing, and `extension_from_path` derives an
    extension from it on demand wherever one is needed downstream, rather
    than asking the model for a second, redundant field that could drift
    out of sync with `path`. No separate "raw" model to translate
    afterward either: the model's `Field(description=...)` is the
    schema-level instruction the LLM sees (via
    `BaseChatModel.with_structured_output`), which is the enforcement
    mechanism now, not prose in the prompt or a post-hoc synthesized field.
    Works identically across providers (Ollama's native `json_schema`
    structured output locally, tool-calling-based structured output for
    Anthropic/Google) since `with_structured_output` is a `BaseChatModel`
    method, not provider-specific code here.
    """

    binaries: list[IdentifiedBinary] = Field(
        default_factory=list,
        description=(
            "ELF binaries in the listing worth deeper security analysis. "
            "Empty list if nothing looks worth flagging."
        ),
    )


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

    structured_llm = llm.with_structured_output(_IdentifiedBinaryList)
    prompt = build_prompt(tree_text, target_daemons=TARGET_DAEMONS)

    try:
        parsed = await structured_llm.ainvoke(prompt)
    except (OSError, TimeoutError) as exc:
        raise IdentifierUnavailableError(f"LLM call failed: {exc}") from exc
    except ValidationError as exc:
        raise IdentifierUnavailableError(
            f"Identifier Agent returned output that doesn't match the expected schema: {exc}"
        ) from exc

    if not isinstance(parsed, _IdentifiedBinaryList):
        # with_structured_output(..., include_raw=False) (our default) should
        # always return the Pydantic model or raise — this is a defensive
        # backstop against a provider returning e.g. a bare dict instead.
        raise IdentifierUnavailableError(
            f"Identifier Agent returned an unexpected result type: {type(parsed).__name__}"
        )

    return parsed.binaries
