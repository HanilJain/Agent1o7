"""LangSmith observability for Stages 3, 4 and 5.

Public API. See each submodule's docstring for the rationale behind its
piece of the design:

* `tracing` — `configure_tracing()`/`tracing_enabled()`/`flush_traces()`:
  the on/off switch and the codebase's one sanctioned `os.environ` write.
* `context` — `trace_context()`/`current_context()`: the `run_id`-keyed
  correlation context propagated via `contextvars` across each stage's
  `asyncio.create_task` worker pool.
* `spans` — `traced()`/`span()`/`aspan()`/`run_config()`/`current_trace_url()`:
  instrumentation for the non-LangChain work (Chroma, embeddings, Joern's
  Docker calls) that LangSmith cannot see on its own, plus the
  `RunnableConfig` builder for `.ainvoke(..., config=...)` calls.

Every public function here is a true no-op — same behavior, same return
values, no `langsmith` import attempted — when `Settings.langsmith_tracing`
is `False` (the default) or the `langsmith` package isn't installed. No
caller needs to guard calls into this module with an `if tracing_enabled():`
check; the guard already lives inside each function.
"""

from __future__ import annotations

from fw_audit.observability.context import (
    TraceContext,
    current_context,
    trace_context,
)
from fw_audit.observability.spans import (
    aspan,
    current_trace_url,
    run_config,
    span,
    traced,
)
from fw_audit.observability.tracing import (
    configure_tracing,
    flush_traces,
    tracing_enabled,
)

__all__ = [
    "TraceContext",
    "current_context",
    "trace_context",
    "aspan",
    "current_trace_url",
    "run_config",
    "span",
    "traced",
    "configure_tracing",
    "flush_traces",
    "tracing_enabled",
]
