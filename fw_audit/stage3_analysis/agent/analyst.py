"""The analyst LLM call: one chunk of decompiled C in, one validated
`AnalysisReport` out.

Mirrors `stage1_ingestion.identifier.agent`'s shape (`get_llm_for_agent` ->
`.with_structured_output(...)` -> `.ainvoke(...)`, funneled into one
module-specific `*UnavailableError`), with one addition this role needs
that Stage 1's single-call-per-firmware identifier doesn't: a bounded
schema-repair retry. The `AnalysisReport` schema is large (nested findings,
enums, evidence spans, half a dozen prose fields) and this call runs once
per CHUNK — potentially hundreds of times per firmware — so a model that
fumbles the schema on a transient basis is worth one extra attempt with the
validation error fed back, rather than immediately falling through to
`chunk_queue`'s queue-level retry (which re-prompts with zero feedback
about what went wrong). The repair retry covers both ways a model can
fumble structured output: `ValidationError` (valid JSON, wrong shape) and
`langchain_core.exceptions.OutputParserException` (not valid JSON at all —
common on local/smaller models given this schema's size).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from langchain_core.exceptions import OutputParserException
from langchain_core.messages import BaseMessage, HumanMessage
from pydantic import ValidationError

from fw_audit.common.findings import AnalysisReport
from fw_audit.config.llm_config import AgentRole, get_llm_for_agent
from fw_audit.config.settings import Settings
from fw_audit.observability import run_config
from fw_audit.stage3_analysis.agent.prompts import build_messages

logger = logging.getLogger("fw_audit.stage3_analysis.agent")


class AnalysisUnavailableError(RuntimeError):
    """No LLM provider is reachable, or its output never validated.

    Raised after `settings.stage3_repair_attempts` repair attempts are
    exhausted (schema failures) or immediately for a transport/build
    failure (no repair possible — see `analyze_chunk`'s docstring on which
    exceptions get a repair attempt and which don't). Callers
    (`agent.consumer.AnalysisConsumer`) let this propagate so
    `chunk_queue._worker`'s existing `except Exception` -> `nack()` path
    handles the queue-level retry — this module has no queue awareness of
    its own.
    """


async def analyze_chunk(
    chunk_text: str,
    *,
    chunk_id: str,
    rootfs_path: str,
    function_names: Sequence[str] = (),
    settings: Settings,
) -> AnalysisReport:
    """Ask the analyst LLM to produce a structured `AnalysisReport` for one chunk.

    Raises :class:`AnalysisUnavailableError` if the model/credential can't
    be resolved, the call transport-fails, or structured output never
    validates within `settings.stage3_repair_attempts` extra attempts.

    `with_structured_output`'s `method=` comes from
    `settings.stage3_structured_output_method` (default `"json_schema"`)
    rather than being hardcoded — see that `Settings` field's docstring for
    why a local Ollama model may need `"function_calling"` instead.
    """
    try:
        llm = get_llm_for_agent(AgentRole.STAGE3_VULN_ANALYST, settings=settings)
    except (ImportError, ValueError) as exc:
        raise AnalysisUnavailableError(str(exc)) from exc

    structured_llm = llm.with_structured_output(
        AnalysisReport, method=settings.stage3_structured_output_method
    )
    messages = build_messages(
        chunk_text, chunk_id=chunk_id, rootfs_path=rootfs_path, function_names=function_names
    )

    attempts_allowed = settings.stage3_repair_attempts + 1
    last_error: ValidationError | OutputParserException | None = None
    for attempt in range(attempts_allowed):
        if settings.stage3_log_prompts:
            _log_prompt(messages, chunk_id=chunk_id, attempt=attempt)
        try:
            config = run_config(
                run_name="stage3.c2.analyze_chunk",
                tags=["repair"] if attempt else [],
                metadata={"attempt": attempt},
                settings=settings,
            )
            parsed = await structured_llm.ainvoke(messages, config=config)
        except (OSError, TimeoutError) as exc:
            # Transport failures get no repair attempt: re-prompting a dead
            # socket/rate-limited endpoint wastes tokens and time. Let
            # chunk_queue's own nack()/retry (with AnalysisConsumer's
            # backoff) handle it instead.
            raise AnalysisUnavailableError(f"LLM call failed: {exc}") from exc
        except (ValidationError, OutputParserException) as exc:
            # OutputParserException (langchain_core) covers a model
            # returning text that isn't parseable JSON at all — distinct
            # from ValidationError (parses fine, fails the AnalysisReport
            # schema) but the same "the model fumbled the output format,
            # ask it to try again" situation local/smaller models hit
            # often on this large a schema. Both get the same bounded
            # repair-retry treatment rather than only ValidationError
            # getting feedback and OutputParserException falling straight
            # through to chunk_queue's blind, feedback-free retry.
            last_error = exc
            if attempt < attempts_allowed - 1:
                messages = [
                    *messages,
                    _repair_request(exc),
                ]
                continue
            raise AnalysisUnavailableError(
                f"Analyst agent returned output that doesn't match the expected schema "
                f"after {attempts_allowed} attempt(s): {exc}"
            ) from exc

        if not isinstance(parsed, AnalysisReport):
            # with_structured_output(..., include_raw=False) (our default)
            # should always return the Pydantic model or raise — defensive
            # backstop against a provider returning e.g. a bare dict.
            raise AnalysisUnavailableError(
                f"Analyst agent returned an unexpected result type: {type(parsed).__name__}"
            )

        # The model is asked for chunk_id but is prone to mis-copying or
        # hallucinating it; the caller already knows the true value, so
        # overwrite rather than trust the model's echo.
        if parsed.chunk_id != chunk_id:
            parsed = parsed.model_copy(update={"chunk_id": chunk_id})
        return parsed

    # Unreachable: attempts_allowed >= 1 guarantees the loop above either
    # returns or raises. Kept as a defensive backstop for mypy/clarity.
    raise AnalysisUnavailableError(  # pragma: no cover - defensive
        f"Analyst agent produced no result: {last_error}"
    )


def _log_prompt(messages: Sequence[BaseMessage], *, chunk_id: str, attempt: int) -> None:
    """Print the exact messages about to be sent to the analyst LLM —
    gated behind `settings.stage3_log_prompts` (see that field's
    docstring), so it's an explicit opt-in rather than firing on every one
    of potentially hundreds of chunk calls per firmware.

    Logs at INFO rather than DEBUG so `FWA_STAGE3_LOG_PROMPTS=true` alone
    is enough to see it under the project's default `FWA_LOG_LEVEL=INFO` —
    turning on DEBUG globally instead would also surface every HTTP
    client's own request/response logging (see the repeated `httpx: HTTP
    Request` lines this project's own logs already show)."""
    logger.info(
        "chunk %s attempt %d: sending %d message(s) to the analyst LLM",
        chunk_id,
        attempt + 1,
        len(messages),
    )
    for i, message in enumerate(messages):
        role = message.type  # "system" / "human" / ...
        logger.info(
            "chunk %s attempt %d message[%d] (%s):\n%s",
            chunk_id,
            attempt + 1,
            i,
            role,
            message.content,
        )


def _repair_request(error: ValidationError | OutputParserException) -> HumanMessage:
    return HumanMessage(
        content=(
            f"Your previous response failed schema validation:\n{error}\n\n"
            "Return a corrected response that fully satisfies the required schema."
        )
    )
