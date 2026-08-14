"""Component 5's LLM call: one assembled C5 prompt in, one validated
`TaintPathReport` out.

Identical shape to `query.planner.generate_queries`/
`stage3_analysis.agent.analyst.analyze_chunk`: `get_llm_for_agent` ->
`.with_structured_output(...)` -> bounded schema-repair retry -> immediate
raise on transport failure. No tool access.
"""

from __future__ import annotations

from langchain_core.messages import HumanMessage
from pydantic import ValidationError

from fw_audit.common.taint import TaintPathReport
from fw_audit.config.llm_config import AgentRole, get_llm_for_agent
from fw_audit.config.settings import Settings
from fw_audit.stage4_rag.taint.prompts import build_messages


class TaintAnalystUnavailableError(RuntimeError):
    """No LLM provider is reachable, or its output never validated.

    Raised after `settings.stage4_repair_attempts` repair attempts are
    exhausted, or immediately for a transport/build failure — left to the
    driver's own nack()/retry path, same division as Stage 3's
    `AnalysisUnavailableError`.
    """


async def analyze_taint(
    c5_prompt_text: str,
    *,
    global_id: str,
    settings: Settings,
) -> TaintPathReport:
    """Ask the taint analyst LLM to produce a `TaintPathReport` for one
    Stage 3 finding, given its assembled Component 4 context.

    Raises :class:`TaintAnalystUnavailableError` if the model/credential
    can't be resolved, the call transport-fails, or structured output never
    validates within `settings.stage4_repair_attempts` extra attempts.
    """
    try:
        llm = get_llm_for_agent(AgentRole.STAGE4_TAINT_ANALYST, settings=settings)
    except (ImportError, ValueError) as exc:
        raise TaintAnalystUnavailableError(str(exc)) from exc

    structured_llm = llm.with_structured_output(TaintPathReport)
    messages = build_messages(c5_prompt_text)

    attempts_allowed = settings.stage4_repair_attempts + 1
    last_error: ValidationError | None = None
    for attempt in range(attempts_allowed):
        try:
            parsed = await structured_llm.ainvoke(messages)
        except (OSError, TimeoutError) as exc:
            raise TaintAnalystUnavailableError(f"LLM call failed: {exc}") from exc
        except ValidationError as exc:
            last_error = exc
            if attempt < attempts_allowed - 1:
                messages = [*messages, _repair_request(exc)]
                continue
            raise TaintAnalystUnavailableError(
                f"Taint analyst returned output that doesn't match the expected schema "
                f"after {attempts_allowed} attempt(s): {exc}"
            ) from exc

        if not isinstance(parsed, TaintPathReport):
            raise TaintAnalystUnavailableError(
                f"Taint analyst returned an unexpected result type: {type(parsed).__name__}"
            )

        if parsed.finding_id != global_id:
            parsed = parsed.model_copy(update={"finding_id": global_id})
        return parsed

    raise TaintAnalystUnavailableError(  # pragma: no cover - defensive
        f"Taint analyst produced no result: {last_error}"
    )


def _repair_request(error: ValidationError) -> HumanMessage:
    return HumanMessage(
        content=(
            f"Your previous response failed schema validation:\n{error}\n\n"
            "Return a corrected response that fully satisfies the required schema."
        )
    )
