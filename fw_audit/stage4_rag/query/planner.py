"""Component 3's LLM call: one Stage 3 finding in, one validated
`MultiQueryPlan` out.

Mirrors `stage3_analysis.agent.analyst.analyze_chunk`'s exact shape:
`get_llm_for_agent` -> `.with_structured_output(...)` -> bounded schema-repair
retry -> immediate raise on transport failure (no repair, left to the
driver's own queue-level retry). No tool access.
"""

from __future__ import annotations

from langchain_core.messages import HumanMessage
from pydantic import ValidationError

from fw_audit.config.llm_config import AgentRole, get_llm_for_agent
from fw_audit.config.settings import Settings
from fw_audit.observability import run_config
from fw_audit.stage4_rag.query.prompts import build_messages
from fw_audit.stage4_rag.query.schemas import MultiQueryPlan
from fw_audit.stage4_rag.sink_index import SinkCandidate


class QueryPlannerUnavailableError(RuntimeError):
    """No LLM provider is reachable, or its output never validated.

    Raised after `settings.stage4_repair_attempts` repair attempts are
    exhausted, or immediately for a transport/build failure. Callers
    (`driver.py`) let this propagate so the driver's own nack()/retry path
    handles it — this module has no queue awareness of its own, same
    division of concerns as Stage 3's `analyze_chunk`/`chunk_queue` split.
    """


async def generate_queries(
    candidate: SinkCandidate,
    *,
    settings: Settings,
) -> MultiQueryPlan:
    """Ask the query-planner LLM to produce a `MultiQueryPlan` for one
    Stage 3 finding.

    Raises :class:`QueryPlannerUnavailableError` if the model/credential
    can't be resolved, the call transport-fails, or structured output never
    validates within `settings.stage4_repair_attempts` extra attempts.
    """
    try:
        llm = get_llm_for_agent(AgentRole.STAGE4_QUERY_PLANNER, settings=settings)
    except (ImportError, ValueError) as exc:
        raise QueryPlannerUnavailableError(str(exc)) from exc

    structured_llm = llm.with_structured_output(MultiQueryPlan)
    messages = build_messages(candidate.finding, global_id=candidate.global_id)

    attempts_allowed = settings.stage4_repair_attempts + 1
    last_error: ValidationError | None = None
    for attempt in range(attempts_allowed):
        try:
            config = run_config(
                run_name="stage4.c3.plan_queries",
                tags=["repair"] if attempt else [],
                metadata={"attempt": attempt, "global_id": candidate.global_id},
                settings=settings,
            )
            parsed = await structured_llm.ainvoke(messages, config=config)
        except (OSError, TimeoutError) as exc:
            raise QueryPlannerUnavailableError(f"LLM call failed: {exc}") from exc
        except ValidationError as exc:
            last_error = exc
            if attempt < attempts_allowed - 1:
                messages = [*messages, _repair_request(exc)]
                continue
            raise QueryPlannerUnavailableError(
                f"Query planner returned output that doesn't match the expected schema "
                f"after {attempts_allowed} attempt(s): {exc}"
            ) from exc

        if not isinstance(parsed, MultiQueryPlan):
            raise QueryPlannerUnavailableError(
                f"Query planner returned an unexpected result type: {type(parsed).__name__}"
            )

        if parsed.finding_id != candidate.global_id:
            parsed = parsed.model_copy(update={"finding_id": candidate.global_id})
        return parsed

    raise QueryPlannerUnavailableError(  # pragma: no cover - defensive
        f"Query planner produced no result: {last_error}"
    )


def _repair_request(error: ValidationError) -> HumanMessage:
    return HumanMessage(
        content=(
            f"Your previous response failed schema validation:\n{error}\n\n"
            "Return a corrected response that fully satisfies the required schema."
        )
    )
