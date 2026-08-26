"""LangSmith tracing configuration — the single sanctioned `os.environ`
write in this codebase.

`config.settings`'s own module docstring states "no module reaches for
`os.environ` directly" — this is the deliberate, documented exception,
required because the LangSmith SDK (and LangChain's tracing middleware) are
configured through environment variables, not through a constructor
argument threaded via `init_chat_model`. `configure_tracing()` is the only
place that translates typed `Settings` fields into that env, so the
exception stays contained to one function instead of leaking `os.environ`
calls across the codebase.

Every function here degrades to an inert no-op rather than raising when:
tracing is disabled (`Settings.langsmith_tracing` is `False`, the default);
or the `langsmith` package can't be imported (an offline dev machine, or a
minimal install without the `observability` extra). A firmware analysis run
must never fail because of a tracing misconfiguration.
"""

from __future__ import annotations

import logging
import os

from fw_audit.config.settings import Settings

logger = logging.getLogger("fw_audit.observability.tracing")

_configured = False


def _langsmith_importable() -> bool:
    try:
        import langsmith  # noqa: F401
    except ImportError:
        return False
    return True


def tracing_enabled(settings: Settings) -> bool:
    """True only when the user has opted in AND the `langsmith` package is
    actually importable. Callers should treat this as the single source of
    truth for "is any of this active" rather than re-checking
    `settings.langsmith_tracing` themselves."""
    if not settings.langsmith_tracing:
        return False
    if not _langsmith_importable():
        logger.warning(
            "LANGSMITH_TRACING is set but the `langsmith` package is not "
            'installed; tracing stays disabled. Install with `pip install '
            '"fw-audit[observability]"`.'
        )
        return False
    return True


def configure_tracing(settings: Settings) -> bool:
    """Translate `settings` into the env vars the LangSmith SDK reads, once.
    Safe to call multiple times (e.g. once per runner `main()` in a test
    process) — it only ever re-asserts the same values.

    Returns whether tracing ended up active, so a runner can log/skip
    `flush_traces()` accordingly. Never raises: any failure here degrades to
    "tracing off" rather than aborting the pipeline run it's instrumenting.
    """
    global _configured

    if not tracing_enabled(settings):
        return False

    os.environ["LANGSMITH_TRACING"] = "true"
    if settings.langsmith_api_key:
        os.environ["LANGSMITH_API_KEY"] = settings.langsmith_api_key
    os.environ["LANGSMITH_PROJECT"] = settings.langsmith_project
    os.environ["LANGSMITH_ENDPOINT"] = settings.langsmith_endpoint
    os.environ["LANGSMITH_HIDE_INPUTS"] = "true" if settings.langsmith_hide_inputs else "false"
    os.environ["LANGSMITH_HIDE_OUTPUTS"] = "true" if settings.langsmith_hide_outputs else "false"
    os.environ["LANGSMITH_TRACING_SAMPLE_RATE"] = str(settings.langsmith_sample_rate)

    if not settings.langsmith_api_key:
        logger.warning(
            "LANGSMITH_TRACING is set but no LANGSMITH_API_KEY is configured; "
            "trace uploads will fail at the LangSmith client, not here."
        )

    _configured = True
    logger.info(
        "LangSmith tracing enabled (project=%s, endpoint=%s).",
        settings.langsmith_project,
        settings.langsmith_endpoint,
    )
    return True


def flush_traces() -> None:
    """Best-effort flush of any buffered LangSmith runs, called at the end
    of a runner's `main()`. `fw-analyze`/`fw-trace`/`fw-verify` are
    short-lived CLI processes — without an explicit flush, the client's
    background batching thread can be killed mid-buffer on process exit,
    silently dropping the last few runs of an otherwise-successful pipeline
    run. A no-op if tracing was never configured or `langsmith` isn't
    installed."""
    if not _configured:
        return
    try:
        from langsmith import Client

        Client().flush()
    except Exception:  # noqa: BLE001 - flushing telemetry must never fail the CLI
        logger.debug("LangSmith flush failed; continuing.", exc_info=True)
