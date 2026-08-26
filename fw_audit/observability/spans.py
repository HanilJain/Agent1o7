"""Span helpers for the work LangSmith cannot see on its own.

LangSmith auto-instruments LangChain `Runnable`s (chat models,
`with_structured_output` chains, compiled LangGraph graphs) once tracing is
configured — no code change needed for those. It knows nothing about raw
SDK calls or subprocesses: Chroma's `collection.query(...)`, the Qwen3
`SentenceTransformer` embedder, or `docker run` for Joern's CPG build and
script execution. `traced()` and `span()` wrap exactly that gap, both as
thin pass-throughs over `langsmith.trace`/`@traceable` that become true
no-ops (return the wrapped function/value unchanged, no `langsmith` import
attempted) when `tracing_enabled()` is false — so importing this module
never requires the `observability` extra to be installed.

`run_config()` builds the `RunnableConfig` dict passed as the second
positional-or-keyword argument to a chat model's `.ainvoke(messages, config=...)`
— this project's models are built once per call via `init_chat_model` and
resolved through `with_structured_output`, and `RunnableBinding` (what
`with_structured_output` returns) has no `.with_config()` counterpart for
structured output, so per-call `run_name`/`tags`/`metadata` must go through
`config=`, never through a chained `.with_config()` on the model itself.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import Any, TypeVar

from fw_audit.config.settings import Settings, get_settings
from fw_audit.observability.context import current_context
from fw_audit.observability.tracing import tracing_enabled

logger = logging.getLogger("fw_audit.observability.spans")

F = TypeVar("F", bound=Callable[..., Any])


def run_config(
    *,
    run_name: str,
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    settings: Settings | None = None,
) -> dict[str, Any] | None:
    """Build a `RunnableConfig`-shaped dict for `.ainvoke(messages, config=...)`,
    merging the active `TraceContext` (run_id, chunk_id, bin_id, ...) with
    call-specific `tags`/`metadata`. Returns `None` when tracing is disabled
    so a caller can do `await llm.ainvoke(messages, config=run_config(...))`
    unconditionally — passing `config=None` to `.ainvoke` is equivalent to
    omitting it entirely.
    """
    settings = settings or get_settings()
    if not tracing_enabled(settings):
        return None

    ctx = current_context()
    merged_tags = [*ctx.to_tags(), *(tags or [])]
    merged_metadata = {**ctx.to_metadata(), **(metadata or {})}
    return {"run_name": run_name, "tags": merged_tags, "metadata": merged_metadata}


def traced(
    name: str | None = None,
    *,
    run_type: str = "chain",
) -> Callable[[F], F]:
    """Decorator wrapping a sync or async function in a LangSmith span
    named `name` (defaults to the function's `__qualname__`). A true
    pass-through — returns the original function object unmodified — when
    tracing is disabled at decoration time... except tracing's on/off state
    is a per-call `Settings` value, not known at import/decoration time, so
    the wrapper instead checks `tracing_enabled()` on every call and skips
    straight to the wrapped function when it's false. This keeps
    `@traced(...)`-decorated functions safe to import and call with no
    `langsmith` package installed at all.
    """

    def decorator(func: F) -> F:
        span_name = name or getattr(func, "__qualname__", getattr(func, "__name__", "span"))
        is_coroutine = _is_coroutine_function(func)

        if is_coroutine:

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                settings = get_settings()
                if not tracing_enabled(settings):
                    return await func(*args, **kwargs)  # type: ignore[misc]
                async with _span_async(span_name, run_type=run_type) as run:
                    result = await func(*args, **kwargs)  # type: ignore[misc]
                    if run is not None:
                        run.end(outputs=_safe_outputs(result))
                    return result

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            settings = get_settings()
            if not tracing_enabled(settings):
                return func(*args, **kwargs)
            with _span_sync(span_name, run_type=run_type) as run:
                result = func(*args, **kwargs)
                if run is not None:
                    run.end(outputs=_safe_outputs(result))
                return result

        return sync_wrapper  # type: ignore[return-value]

    return decorator


@contextmanager
def span(
    name: str,
    *,
    run_type: str = "chain",
    inputs: dict[str, Any] | None = None,
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    settings: Settings | None = None,
) -> Iterator[Any]:
    """Context-manager form of `traced()`, for a block of code rather than
    a whole function — used where only PART of a function's body is worth
    its own span (e.g. `retrieve()`'s per-query embed-then-search loop).
    Yields the LangSmith `RunTree` (to call `.add_metadata`/`.end(outputs=...)`
    on) when tracing is active, or `None` when it's a no-op — callers must
    guard `run is not None` before touching it, exactly like `traced()`
    does internally.
    """
    settings = settings or get_settings()
    if not tracing_enabled(settings):
        yield None
        return

    ctx = current_context()
    merged_tags = [*ctx.to_tags(), *(tags or [])]
    merged_metadata = {**ctx.to_metadata(), **(metadata or {})}
    with _span_sync(
        name, run_type=run_type, inputs=inputs, tags=merged_tags, metadata=merged_metadata
    ) as run:
        yield run


@asynccontextmanager
async def aspan(
    name: str,
    *,
    run_type: str = "chain",
    inputs: dict[str, Any] | None = None,
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    settings: Settings | None = None,
) -> AsyncIterator[Any]:
    """Async counterpart of `span()` — for `async def` blocks (Joern's Docker
    calls, the async retrieval path) where an `async with` is required."""
    settings = settings or get_settings()
    if not tracing_enabled(settings):
        yield None
        return

    ctx = current_context()
    merged_tags = [*ctx.to_tags(), *(tags or [])]
    merged_metadata = {**ctx.to_metadata(), **(metadata or {})}
    async with _span_async(
        name, run_type=run_type, inputs=inputs, tags=merged_tags, metadata=merged_metadata
    ) as run:
        yield run


def current_trace_url() -> str | None:
    """Best-effort LangSmith URL for whatever span/run is currently active —
    used to stamp `VerificationReport.trace_url` so a persisted Stage 5
    report links back to its live trace. Returns `None` whenever there is no
    active run (tracing disabled, or called outside any `span`/`traced`),
    never raises."""
    try:
        from langsmith.run_helpers import get_current_run_tree
    except ImportError:
        return None
    try:
        run = get_current_run_tree()
    except Exception:  # noqa: BLE001 - best-effort only
        return None
    if run is None:
        return None
    try:
        return run.get_url()
    except Exception:  # noqa: BLE001 - best-effort only
        return None


def _is_coroutine_function(func: Callable[..., Any]) -> bool:
    import asyncio

    return asyncio.iscoroutinefunction(func)


def _safe_outputs(result: Any) -> dict[str, Any]:
    """Best-effort coercion of a function's return value into the dict
    shape LangSmith's `RunTree.end(outputs=...)` expects — never raises, so
    a span never fails because the wrapped function returned something
    un-serializable-looking."""
    if isinstance(result, dict):
        return result
    if hasattr(result, "model_dump"):
        try:
            dumped = result.model_dump()
            if isinstance(dumped, dict):
                return dumped
        except Exception:  # noqa: BLE001
            pass
    return {"result": repr(result)}


def _span_sync(
    name: str,
    *,
    run_type: str = "chain",
    inputs: dict[str, Any] | None = None,
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Any:
    from langsmith.run_helpers import trace

    return trace(name, run_type, inputs=inputs, tags=tags, metadata=metadata)


def _span_async(
    name: str,
    *,
    run_type: str = "chain",
    inputs: dict[str, Any] | None = None,
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Any:
    from langsmith.run_helpers import trace

    return trace(name, run_type, inputs=inputs, tags=tags, metadata=metadata)
