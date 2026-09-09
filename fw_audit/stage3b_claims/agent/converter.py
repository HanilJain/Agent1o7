"""The extractor LLM call: one claim block of PDF text in, one validated
`ClaimExtractionBatch` out.

Mirrors `stage3_analysis.agent.analyst.analyze_chunk`'s shape almost
exactly (`get_llm_for_agent` -> `.with_structured_output(...)` ->
`.ainvoke(...)`, funneled into one module-specific `*UnavailableError`,
with the same bounded in-process schema-repair retry) — see that module's
docstring for the full rationale. Two differences, both intentional:

1. `AgentRole.STAGE3B_CLAIM_EXTRACTOR` resolves to `ModelTier.BALANCED`,
   not `HIGH_REASONING` (see that role's docstring) — this call is meant
   to be cheap.
2. The schema (`ClaimExtractionBatch`) is small — a handful of short
   fields per claim, not `AnalysisReport`'s large nested shape — so a
   repair-retry failure here is a genuine anomaly, not an expected
   friction point the way it can be for Stage 3's much larger schema.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from langchain_core.exceptions import OutputParserException
from langchain_core.messages import BaseMessage, HumanMessage
from pydantic import ValidationError

from fw_audit.common.claims import ClaimExtractionBatch
from fw_audit.config.llm_config import AgentRole, get_llm_for_agent
from fw_audit.config.settings import Settings
from fw_audit.observability import run_config
from fw_audit.stage3b_claims.agent.prompts import build_messages
from fw_audit.stage3b_claims.errors import ClaimExtractionUnavailableError
from fw_audit.stage3b_claims.models import ClaimBlock

logger = logging.getLogger("fw_audit.stage3b_claims.agent")


async def extract_claims(
    block: ClaimBlock, *, doc_stem: str, settings: Settings
) -> ClaimExtractionBatch:
    """Ask the extractor LLM to transcribe `block` into a structured
    `ClaimExtractionBatch`.

    Raises :class:`ClaimExtractionUnavailableError` if the model/credential
    can't be resolved, the call transport-fails, or structured output never
    validates within `settings.stage3b_repair_attempts` extra attempts.
    """
    try:
        llm = get_llm_for_agent(AgentRole.STAGE3B_CLAIM_EXTRACTOR, settings=settings)
    except (ImportError, ValueError) as exc:
        raise ClaimExtractionUnavailableError(str(exc)) from exc

    structured_llm = llm.with_structured_output(
        ClaimExtractionBatch, method=settings.stage3b_structured_output_method
    )
    messages = build_messages(block.text, doc_stem=doc_stem, page_numbers=block.page_numbers)

    attempts_allowed = settings.stage3b_repair_attempts + 1
    last_error: ValidationError | OutputParserException | None = None
    for attempt in range(attempts_allowed):
        if settings.stage3b_log_prompts:
            _log_prompt(messages, block_id=block.block_id, attempt=attempt)
        try:
            config = run_config(
                run_name="stage3b.extract_claims",
                tags=["repair"] if attempt else [],
                metadata={"attempt": attempt, "block_id": block.block_id},
                settings=settings,
            )
            parsed = await structured_llm.ainvoke(messages, config=config)
        except (OSError, TimeoutError) as exc:
            # Transport failures get no repair attempt — same reasoning as
            # stage3_analysis.agent.analyst.analyze_chunk.
            raise ClaimExtractionUnavailableError(f"LLM call failed: {exc}") from exc
        except (ValidationError, OutputParserException) as exc:
            last_error = exc
            if attempt < attempts_allowed - 1:
                messages = [*messages, _repair_request(exc)]
                continue
            raise ClaimExtractionUnavailableError(
                f"Extractor agent returned output that doesn't match the expected schema "
                f"after {attempts_allowed} attempt(s): {exc}"
            ) from exc

        if not isinstance(parsed, ClaimExtractionBatch):
            raise ClaimExtractionUnavailableError(
                f"Extractor agent returned an unexpected result type: {type(parsed).__name__}"
            )
        return parsed

    raise ClaimExtractionUnavailableError(  # pragma: no cover - defensive
        f"Extractor agent produced no result: {last_error}"
    )


def _log_prompt(messages: Sequence[BaseMessage], *, block_id: str, attempt: int) -> None:
    """Same rationale as `stage3_analysis.agent.analyst._log_prompt` — INFO
    level so `FWA_STAGE3B_LOG_PROMPTS=true` alone is enough to see it
    without enabling DEBUG globally."""
    logger.info(
        "block %s attempt %d: sending %d message(s) to the extractor LLM",
        block_id,
        attempt + 1,
        len(messages),
    )
    for i, message in enumerate(messages):
        logger.info(
            "block %s attempt %d message[%d] (%s):\n%s",
            block_id,
            attempt + 1,
            i,
            message.type,
            message.content,
        )


def _repair_request(error: ValidationError | OutputParserException) -> HumanMessage:
    return HumanMessage(
        content=(
            f"Your previous response failed schema validation:\n{error}\n\n"
            "Return a corrected response that fully satisfies the required schema."
        )
    )
