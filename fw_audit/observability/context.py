"""Run correlation context shared by Stages 3, 4 and 5.

All three stages already mint a `run_id` for one pipeline invocation
(`stage3_analysis.agent.orchestrator.run_analysis`,
`stage4_rag.driver.run_queue`, `stage5_verification.driver.run_queue` — the
last two also exposed as each CLI's `--run-id` flag). This module turns that
existing identifier into the LangSmith correlation key rather than minting a
new one, and defines the canonical tag/metadata vocabulary so filtering
works the same way across all three stages.

Held in a `contextvars.ContextVar` rather than threaded as an explicit
parameter through every function: all three stages fan work out with
`asyncio.create_task` over a shared bounded queue, in one event loop, one
thread. `create_task` copies the current context at creation time, so
context set BEFORE a task is created is inherited by it, but context set
inside one worker never leaks to a sibling task — exactly the isolation a
per-chunk/per-finding/per-candidate span needs. The corollary every caller
must respect: enter `trace_context()` inside the per-unit function
(`AnalysisConsumer.__call__`, `stage4_rag.driver._process_one`,
`stage5_verification.driver._process_one`), not once around the whole
worker-pool loop.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace

# Canonical metadata/tag keys — shared across all three stages so a
# LangSmith filter like `metadata.run_id = "..."` or `tag:stage:3` means the
# same thing everywhere it's used.
KEY_STAGE = "stage"
KEY_ROLE = "role"
KEY_RUN_ID = "run_id"
KEY_DB_SUBFOLDER = "db_subfolder"
KEY_BIN_ID = "bin_id"
KEY_CHUNK_ID = "chunk_id"
KEY_GLOBAL_ID = "global_id"
KEY_ATTEMPT = "attempt"
KEY_MODEL = "model"


@dataclass(frozen=True)
class TraceContext:
    """Correlation fields attached to every span/run opened while this
    context is active. All fields are optional — a stage fills in only what
    it has (e.g. Stage 3 has `chunk_id` but not `global_id`)."""

    stage: str | None = None
    run_id: str | None = None
    db_subfolder: str | None = None
    bin_id: str | None = None
    chunk_id: str | None = None
    global_id: str | None = None
    model: str | None = None

    def to_metadata(self) -> dict[str, str]:
        """Render as a flat string-keyed dict suitable for a LangSmith
        `metadata=` payload or `RunnableConfig["metadata"]` — omits unset
        fields rather than sending `None`s."""
        pairs = (
            (KEY_STAGE, self.stage),
            (KEY_RUN_ID, self.run_id),
            (KEY_DB_SUBFOLDER, self.db_subfolder),
            (KEY_BIN_ID, self.bin_id),
            (KEY_CHUNK_ID, self.chunk_id),
            (KEY_GLOBAL_ID, self.global_id),
            (KEY_MODEL, self.model),
        )
        return {key: value for key, value in pairs if value is not None}

    def to_tags(self) -> list[str]:
        """Render as coarse filterable tags (`stage:3`, `run:<id>`) — kept
        separate from `to_metadata()` because LangSmith tags are meant to be
        low-cardinality/filterable, while metadata carries the rest."""
        tags = []
        if self.stage is not None:
            tags.append(f"stage:{self.stage}")
        if self.run_id is not None:
            tags.append(f"run:{self.run_id}")
        return tags


_current: ContextVar[TraceContext | None] = ContextVar("fw_audit_trace_context", default=None)


def current_context() -> TraceContext:
    """Returns the active `TraceContext`, or an all-`None` one if nothing
    has entered `trace_context()` yet — callers never need a `None` check."""
    return _current.get() or TraceContext()


@contextmanager
def trace_context(**updates: str | None) -> Iterator[TraceContext]:
    """Enter a nested trace context, merging `updates` onto whatever is
    already active (so an inner `chunk_id` doesn't need to repeat an outer
    `run_id`/`stage`). Restores the previous context on exit regardless of
    how the `with` block ends.

    Example:
        with trace_context(stage="3", run_id=run_id):
            ...
            with trace_context(chunk_id=handle.chunk_id):
                ...
    """
    parent = current_context()
    merged = replace(parent, **{k: v for k, v in updates.items() if v is not None})
    token = _current.set(merged)
    try:
        yield merged
    finally:
        _current.reset(token)
