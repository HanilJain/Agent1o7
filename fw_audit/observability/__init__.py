"""LangSmith observability, plus LLM usage tracking, for Stages 1, 3, 3b, 4
and 5.

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
* `usage` — `usage_registry()`/`UsageTrackingCallbackHandler`/
  `format_usage_summary()`/`stamp_usage_metadata()`: per-call token/cost
  counting, attached to every constructed chat model at
  `llm_config._build_from_spec`. UNLIKE `tracing`/`spans`, this is NOT
  gated on `langsmith_tracing` or the `langsmith` package — it works
  standalone, following `stage5_verification.cmdlog`'s "always on, never
  breaks a run" precedent rather than the "no-op unless LangSmith is
  configured" one. See `usage`'s own module docstring.
* `pricing` — `lookup_price()`/`estimate_cost()`: the USD-per-token price
  table `usage` consults, kept as its own module since pricing is a
  policy table independent of the counting mechanism.
* `layout` — pure path algebra for the `<db_subfolder>/usage/` artifact,
  matching every stage's own `layout.py` convention.

Every public function in `tracing`/`context`/`spans` is a true no-op — same
behavior, same return values, no `langsmith` import attempted — when
`Settings.langsmith_tracing` is `False` (the default) or the `langsmith`
package isn't installed. No caller needs to guard calls into those modules
with an `if tracing_enabled():` check; the guard already lives inside each
function. `usage`/`pricing`/`layout` have no such gate — see their own
docstrings.
"""

from __future__ import annotations

from fw_audit.observability.context import (
    TraceContext,
    current_context,
    trace_context,
)
from fw_audit.observability.pricing import ModelPrice, estimate_cost, lookup_price
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
from fw_audit.observability.usage import (
    UsageBudgetExceededError,
    UsageRecord,
    UsageRegistry,
    UsageReport,
    UsageTrackingCallbackHandler,
    current_registry,
    format_usage_summary,
    stamp_usage_metadata,
    usage_registry,
)

__all__ = [
    "TraceContext",
    "ModelPrice",
    "UsageBudgetExceededError",
    "UsageRecord",
    "UsageRegistry",
    "UsageReport",
    "UsageTrackingCallbackHandler",
    "current_context",
    "current_registry",
    "estimate_cost",
    "lookup_price",
    "trace_context",
    "aspan",
    "current_trace_url",
    "format_usage_summary",
    "run_config",
    "span",
    "stamp_usage_metadata",
    "traced",
    "configure_tracing",
    "flush_traces",
    "tracing_enabled",
    "usage_registry",
]
