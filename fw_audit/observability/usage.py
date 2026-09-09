"""LLM token-usage tracking: per-call counting, per-role/per-run roll-up,
console/JSONL/LangSmith reporting, and an opt-in spend budget.

This is deliberately separate from `observability.tracing`/`spans` even
though it hooks the same models: LangSmith tracing is opt-in, requires an
account, and (per `tracing.py`'s own docstring) "a firmware analysis run
must never fail because of a tracing misconfiguration." Token usage is the
opposite kind of concern — an operator needs to know what a run cost
whether or not LangSmith is configured — so this module follows
`stage5_verification.cmdlog`'s precedent instead: ALWAYS on by default
(`Settings.llm_usage_tracking`), no `langsmith` dependency, never breaks a
real run (a disk write failure latches quiet, exactly like `CommandLog`),
and works standalone from a fresh `pytest` environment with no extras
installed.

Attribution reuses `observability.context.TraceContext` rather than
inventing a second correlation mechanism: that ContextVar already tracks
`stage`/`run_id`/`bin_id`/`chunk_id`/`global_id` across every stage's
`asyncio.create_task` fan-out, is entered per-unit-of-work, and — critically
— is NOT gated on `langsmith_tracing`, so it is available here unconditionally.
`UsageTrackingCallbackHandler.on_llm_end` reads `current_context()` at call
time (not at handler construction time), which is what makes attribution
correct even though `AgentRole`-specific chat models are rebuilt per unit of
work rather than cached (Stage 5 FVVW builds 4 models per candidate,
`fvvw/graph.py`'s `strategy_llm`/`static_generator_llm`/
`static_evaluator_llm`/`report_llm`) — records key on the RUNTIME `AgentRole`
carried by each handler instance plus whatever `TraceContext` is active for
that particular call, not on model identity.

Registry access is scoped by an opaque token from `usage_registry()`, not a
bare global — callers (mainly test code) can install an isolated registry
for the duration of a `with` block; production code lets it default to one
process-level registry for the run.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler
from pydantic import BaseModel, Field

from fw_audit.observability.context import current_context
from fw_audit.observability.pricing import ModelPrice, estimate_cost, lookup_price
from fw_audit.observability.tracing import tracing_enabled

if TYPE_CHECKING:
    from langchain_core.outputs import LLMResult

    from fw_audit.config.settings import Settings

logger = logging.getLogger("fw_audit.observability.usage")


class UsageBudgetExceededError(BaseException):
    """Reserved for a future hard-stop budget mode. NOT currently raised
    anywhere — `Settings.llm_budget_action` accepts only `"warn"` today
    (see that field's docstring): a prototyped `"stop"` mode that raised
    this from `UsageTrackingCallbackHandler.on_llm_end` reproducibly HUNG
    the process when the budget was crossed mid-stream during a
    structured-output parse (a faulthandler dump showed the interpreter
    stuck inside `pydantic.BaseModel.__init__`), so it was pulled before
    shipping. The class (and its deliberate `BaseException`, not
    `Exception`, base — see below) is kept because the design rationale
    for a future attempt is still correct; only the wiring that raised it
    was removed.

    Deliberately a `BaseException` subclass, NOT `Exception`, in
    anticipation of that future mode: every worker pool in this repo
    (`stage3_analysis.chunk_queue._worker`, `stage4_rag.driver._worker`,
    `stage5_verification.driver._worker`,
    `stage5_verification.fvvw.driver._worker`) catches a broad
    `except Exception` around one unit of work and converts it into a
    per-item `nack()`/retry — a hard budget stop needs to abort the run
    instead, so an `Exception` subclass would instead be retried, spending
    MORE past the budget than "warn" mode ever would. `BaseException`
    passes through those handlers untouched, the same way
    `KeyboardInterrupt`/`asyncio.CancelledError` do. (Those 4 worker loops
    also gained an `except BaseException: <queue>.abandon(item); raise`
    clause, and each queue class an `abandon()` method, as part of this
    same prototyping — required so `close()`'s `Queue.join()` doesn't hang
    waiting on a `task_done()` that a `BaseException` skips past `ack()`/
    `nack()`. That part of the fix is real and kept even though "stop"
    itself isn't wired up — a future `BaseException`-shaped abort of any
    kind would need it too.)
    """


@dataclass(frozen=True)
class UsageRecord:
    """One LLM call's measured (or, failing that, at-least-acknowledged)
    token usage. Frozen/immutable per this repo's coding-style rule —
    `UsageRegistry.record()` appends new instances, never mutates one."""

    seq: int
    ts: str
    role: str
    provider: str
    model: str
    measured: bool
    """False for a call whose provider/response carried no usage data at
    all (see `UsageTrackingCallbackHandler.on_llm_end`'s fallback chain) —
    kept in the record, not merely dropped, so a report can say
    "47 calls (2 unmeasured)" instead of silently under-reporting."""
    stage: str = ""
    run_id: str = ""
    db_subfolder: str = ""
    bin_id: str = ""
    chunk_id: str = ""
    global_id: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    reasoning_tokens: int = 0
    cost_usd: float | None = None
    duration_ms: int = 0

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "role": self.role,
            "provider": self.provider,
            "model": self.model,
            "measured": self.measured,
            "stage": self.stage,
            "run_id": self.run_id,
            "db_subfolder": self.db_subfolder,
            "bin_id": self.bin_id,
            "chunk_id": self.chunk_id,
            "global_id": self.global_id,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_creation_tokens": self.cache_creation_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "cost_usd": self.cost_usd,
            "duration_ms": self.duration_ms,
        }


@dataclass
class RoleTotals:
    """Running totals for one grouping key (a role, a model, or the whole
    run) — mutated in place under `UsageRegistry._lock`, unlike the
    immutable `UsageRecord`s it's derived from: this is pure accumulator
    state, never handed out for a caller to hold onto and mutate further
    (`UsageRegistry.totals()`/`by_role()` return fresh copies)."""

    calls: int = 0
    unmeasured_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    reasoning_tokens: int = 0
    cost_usd: float = 0.0
    has_unpriced: bool = False
    """True if at least one call in this group had no price entry
    (`cost_usd is None` on the underlying record) — surfaced so a report
    can flag "cost excludes N calls" rather than implying `cost_usd` is
    complete."""

    def add(self, rec: UsageRecord) -> None:
        self.calls += 1
        if not rec.measured:
            self.unmeasured_calls += 1
        self.input_tokens += rec.input_tokens
        self.output_tokens += rec.output_tokens
        self.total_tokens += rec.total_tokens
        self.cache_read_tokens += rec.cache_read_tokens
        self.cache_creation_tokens += rec.cache_creation_tokens
        self.reasoning_tokens += rec.reasoning_tokens
        if rec.cost_usd is None:
            self.has_unpriced = True
        else:
            self.cost_usd += rec.cost_usd


class UsageReport(BaseModel):
    """JSON-serializable snapshot of a `UsageRegistry` at a point in time —
    written to `<stage>.<run_id>.json` (see `observability.layout`) and
    used to build the console summary / LangSmith root-span stamp.
    `schema_version` follows every other `*RunSummary` in this repo
    (`common/schemas.py`, `common/findings.py`, ...) for the same forward-
    compatibility reason, even though this artifact deliberately does NOT
    live alongside those models — see this package's module docstring on
    why usage tracking is cross-cutting infrastructure, not stage-domain
    data."""

    schema_version: int = 1
    stage: str = ""
    run_id: str = ""
    generated_at: str = ""
    calls: int = 0
    unmeasured_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    reasoning_tokens: int = 0
    cost_usd: float = 0.0
    has_unpriced: bool = False
    budget_exceeded: bool = False
    by_role: dict[str, dict[str, Any]] = Field(default_factory=dict)
    by_model: dict[str, dict[str, Any]] = Field(default_factory=dict)


def _totals_to_dict(totals: RoleTotals) -> dict[str, Any]:
    return {
        "calls": totals.calls,
        "unmeasured_calls": totals.unmeasured_calls,
        "input_tokens": totals.input_tokens,
        "output_tokens": totals.output_tokens,
        "total_tokens": totals.total_tokens,
        "cache_read_tokens": totals.cache_read_tokens,
        "cache_creation_tokens": totals.cache_creation_tokens,
        "reasoning_tokens": totals.reasoning_tokens,
        "cost_usd": round(totals.cost_usd, 6),
        "has_unpriced": totals.has_unpriced,
    }


class UsageRegistry:
    """Process/run-level accumulator for `UsageRecord`s.

    Models are constructed once per unit of work across this repo (once
    per chunk in Stage 3, once per candidate x 4 roles in FVVW) rather
    than cached and reused — so a per-model-instance counter would
    fragment into dozens of short-lived pieces. This registry is instead
    long-lived (for the duration of one `usage_registry()` context, or the
    whole process if none was entered) and every constructed handler
    writes into whichever registry is `current_registry()` AT CALL TIME.

    Thread-safety: `record()` is called from `UsageTrackingCallbackHandler
    .on_llm_end`, which LangChain may invoke either inline on the event
    loop thread (`run_inline = True`, this handler's setting) or, for a
    THIRD-PARTY sync handler also registered on the same model, from a
    thread-pool executor — so this class is guarded by a plain
    `threading.Lock`, not "we're single-threaded" reasoning.

    Never raises past `record()`/`attach_jsonl()`: a filesystem error
    latches `_broken` after logging one warning, mirroring
    `stage5_verification.cmdlog.CommandLog` exactly.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[UsageRecord] = []
        self._by_role: dict[str, RoleTotals] = {}
        self._by_model: dict[str, RoleTotals] = {}
        self._totals = RoleTotals()
        self._seq = 0
        self._jsonl_path: Path | None = None
        self._broken = False
        self._budget_exceeded = False
        self._budget_warned = False

    def attach_jsonl(self, path: Path | None) -> None:
        """Start (or stop, if `path` is `None`) appending every recorded
        call to `path` as one JSON line. Safe to call multiple times;
        creates the parent directory eagerly so a later write failure is
        specifically about the file, not a missing directory."""
        if path is None:
            self._jsonl_path = None
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("UsageRegistry: could not create %s: %s", path.parent, exc)
            self._broken = True
            return
        self._jsonl_path = path

    def record(self, rec_kwargs: dict[str, Any]) -> UsageRecord:
        """Build and store one `UsageRecord`. Returns the stored record
        (mainly for tests); never raises."""
        with self._lock:
            self._seq += 1
            rec = UsageRecord(seq=self._seq, **rec_kwargs)
            self._records.append(rec)
            self._totals.add(rec)
            self._by_role.setdefault(rec.role, RoleTotals()).add(rec)
            self._by_model.setdefault(f"{rec.provider}:{rec.model}", RoleTotals()).add(rec)
            jsonl_path = self._jsonl_path
            broken = self._broken

        if jsonl_path is not None and not broken:
            self._append_jsonl(jsonl_path, rec)
        return rec

    def _append_jsonl(self, path: Path, rec: UsageRecord) -> None:
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec.to_json_dict(), default=str) + "\n")
        except OSError as exc:
            logger.warning("UsageRegistry: disabling JSONL log at %s: %s", path, exc)
            with self._lock:
                self._broken = True

    def note_budget_exceeded(self) -> bool:
        """Mark the run as over budget; returns True only the FIRST time
        this is called (a latch), so a "warn" caller logs exactly once
        regardless of how many subsequent calls also cross the
        threshold."""
        with self._lock:
            already = self._budget_warned
            self._budget_exceeded = True
            self._budget_warned = True
        return not already

    @property
    def budget_exceeded(self) -> bool:
        with self._lock:
            return self._budget_exceeded

    def totals(self) -> RoleTotals:
        with self._lock:
            return RoleTotals(**vars(self._totals))

    def by_role(self) -> dict[str, RoleTotals]:
        with self._lock:
            return {k: RoleTotals(**vars(v)) for k, v in self._by_role.items()}

    def by_model(self) -> dict[str, RoleTotals]:
        with self._lock:
            return {k: RoleTotals(**vars(v)) for k, v in self._by_model.items()}

    def records(self) -> list[UsageRecord]:
        with self._lock:
            return list(self._records)

    def snapshot(self, *, stage: str = "", run_id: str = "") -> UsageReport:
        """Build the JSON-serializable `UsageReport` for this registry's
        current state."""
        totals = self.totals()
        return UsageReport(
            stage=stage,
            run_id=run_id,
            generated_at=datetime.now(UTC).isoformat(),
            calls=totals.calls,
            unmeasured_calls=totals.unmeasured_calls,
            input_tokens=totals.input_tokens,
            output_tokens=totals.output_tokens,
            total_tokens=totals.total_tokens,
            cache_read_tokens=totals.cache_read_tokens,
            cache_creation_tokens=totals.cache_creation_tokens,
            reasoning_tokens=totals.reasoning_tokens,
            cost_usd=round(totals.cost_usd, 6),
            has_unpriced=totals.has_unpriced,
            budget_exceeded=self.budget_exceeded,
            by_role={k: _totals_to_dict(v) for k, v in self.by_role().items()},
            by_model={k: _totals_to_dict(v) for k, v in self.by_model().items()},
        )

    def write_report(self, path: Path, *, stage: str = "", run_id: str = "") -> None:
        """Best-effort write of `snapshot()` to `path`, mirroring every
        stage's own `_write_summary`'s `except OSError: pass` discipline —
        never raises, never blocks a run's own return value."""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                self.snapshot(stage=stage, run_id=run_id).model_dump_json(indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("UsageRegistry: could not write report to %s: %s", path, exc)


_registry_var: ContextVar[UsageRegistry | None] = ContextVar(
    "fw_audit_usage_registry", default=None
)
_default_registry = UsageRegistry()


def current_registry() -> UsageRegistry:
    """The active `UsageRegistry` — whatever `usage_registry()` context is
    entered, or one shared process-level default if none is. Every
    production call path (`_build_from_spec`'s attached handler) uses
    this, never the private module attribute directly, so tests can swap
    the registry via `usage_registry()` without any call-site change."""
    return _registry_var.get() or _default_registry


@contextmanager
def usage_registry(
    *, jsonl_path: Path | None = None, settings: Settings | None = None
) -> Iterator[UsageRegistry]:
    """Enter a fresh, isolated `UsageRegistry` for the duration of the
    `with` block — the run-scoped entry point each runner's `main()` wraps
    its work in. `jsonl_path`, if given, starts per-call JSONL logging
    immediately (see `UsageRegistry.attach_jsonl`).

    Mirrors `observability.context.trace_context`'s ContextVar idiom
    exactly, including the "handlers resolve the registry at CALL time"
    property that makes this safe across `asyncio.create_task` fan-out:
    context set before a task is created is inherited by it, so a worker
    pool started inside this block has every task correctly attributed.
    """
    registry = UsageRegistry()
    if jsonl_path is not None:
        registry.attach_jsonl(jsonl_path)
    token = _registry_var.set(registry)
    try:
        yield registry
    finally:
        _registry_var.reset(token)


def _extract_usage_metadata(response: LLMResult) -> tuple[dict[str, Any] | None, str | None]:
    """Best-effort extraction of `(usage_metadata_dict, model_name)` from
    one `LLMResult`, trying `AIMessage.usage_metadata` first (the modern,
    provider-normalized path) and falling back to `llm_output`'s raw
    `token_usage`/`usage` dict for providers that only populate that.
    Returns `(None, None)` when nothing is available at all — the caller
    records an "unmeasured" row rather than raising or silently dropping
    the call."""
    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration

    model_name: str | None = None
    if response.generations and response.generations[0]:
        gen = response.generations[0][0]
        if isinstance(gen, ChatGeneration) and isinstance(gen.message, AIMessage):
            model_name = gen.message.response_metadata.get("model_name") or None
            usage = gen.message.usage_metadata
            if usage:
                return dict(usage), model_name

    llm_output = response.llm_output or {}
    model_name = model_name or llm_output.get("model_name")
    raw_usage = llm_output.get("token_usage") or llm_output.get("usage")
    if isinstance(raw_usage, dict):
        input_tokens = int(
            raw_usage.get("prompt_tokens", raw_usage.get("input_tokens", 0)) or 0
        )
        output_tokens = int(
            raw_usage.get("completion_tokens", raw_usage.get("output_tokens", 0)) or 0
        )
        total_tokens = int(raw_usage.get("total_tokens", input_tokens + output_tokens) or 0)
        return (
            {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": total_tokens,
            },
            model_name,
        )
    return None, model_name


class UsageTrackingCallbackHandler(BaseCallbackHandler):
    """Attached via `callbacks=[...]` at `BaseChatModel` construction time
    (`llm_config._build_from_spec`) — a CONSTRUCTOR kwarg, not chained via
    `.with_config()`, for the exact reason `tags`/`metadata` already are
    there: `with_structured_output()` returns a `RunnableBinding` with no
    `.with_config()` counterpart, but `callbacks` set at construction
    propagates through it automatically since the binding delegates to the
    bound model. This is what lets ALL 9 of this repo's LLM call sites
    (5 structured, 4 raw) get tracked with zero call-site edits — including
    Stage 1's Identifier Agent, whose call site passes no `config=` at all.

    `run_inline = True`: without it, `BaseCallbackHandler` defaults to
    running sync handlers in a thread-pool executor via
    `copy_context().run(...)` (confirmed against `langchain_core.callbacks
    .manager._ahandle_event_for_handler`) — context IS preserved either
    way, but inline execution skips a thread hop per LLM call for what is
    just dict arithmetic plus an optional file append.

    `raise_error` stays at `False` (LangChain's default — the same
    function swallows handler exceptions with a `logger.warning`
    otherwise): `Settings.llm_budget_action` currently only supports
    `"warn"`, which must never abort the call that already happened and
    was already paid for. See `UsageBudgetExceededError`'s docstring for
    why a `"stop"` mode that would flip this to `True` was prototyped and
    pulled rather than shipped here.
    """

    run_inline = True

    def __init__(
        self, *, role: str, provider: str, model: str, settings: Settings
    ) -> None:
        super().__init__()
        self._role = role
        self._provider = provider
        self._model = model
        self._settings = settings
        self._started: dict[UUID, float] = {}
        price_path = settings.llm_price_table_path
        self._price: ModelPrice | None = lookup_price(
            provider, model, override_path=price_path
        )

    # -- timing -----------------------------------------------------------
    def on_llm_start(
        self, serialized: dict[str, Any], prompts: list[str], *, run_id: UUID, **kwargs: Any
    ) -> None:
        self._started[run_id] = time.monotonic()

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        # Implemented explicitly (not inherited) so LangChain doesn't take
        # the NotImplementedError -> retry-as-on_llm_start fallback path in
        # `_ahandle_event_for_handler` on every single chat-model call —
        # every real call site in this repo is a chat model, never a bare
        # text-completion LLM.
        self._started[run_id] = time.monotonic()

    def on_llm_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        self._started.pop(run_id, None)

    # -- the measurement ----------------------------------------------------
    def on_llm_end(self, response: LLMResult, *, run_id: UUID, **kwargs: Any) -> None:
        started = self._started.pop(run_id, None)
        duration_ms = int((time.monotonic() - started) * 1000) if started is not None else 0

        usage, response_model = _extract_usage_metadata(response)
        ctx = current_context()
        base_kwargs: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "role": self._role,
            "provider": self._provider,
            "model": response_model or self._model,
            "stage": ctx.stage or "",
            "run_id": ctx.run_id or "",
            "db_subfolder": ctx.db_subfolder or "",
            "bin_id": ctx.bin_id or "",
            "chunk_id": ctx.chunk_id or "",
            "global_id": ctx.global_id or "",
            "duration_ms": duration_ms,
        }

        if usage is None:
            registry = current_registry()
            registry.record({**base_kwargs, "measured": False})
            return

        input_tokens = int(usage.get("input_tokens", 0) or 0)
        output_tokens = int(usage.get("output_tokens", 0) or 0)
        total_tokens = int(usage.get("total_tokens", input_tokens + output_tokens) or 0)
        input_details = usage.get("input_token_details") or {}
        output_details = usage.get("output_token_details") or {}
        cache_read = int(input_details.get("cache_read") or 0)
        cache_creation = int(input_details.get("cache_creation") or 0)
        reasoning = int(output_details.get("reasoning") or 0)

        cost = estimate_cost(
            self._price,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read,
            cache_creation_tokens=cache_creation,
        )

        registry = current_registry()
        registry.record(
            {
                **base_kwargs,
                "measured": True,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": total_tokens,
                "cache_read_tokens": cache_read,
                "cache_creation_tokens": cache_creation,
                "reasoning_tokens": reasoning,
                "cost_usd": cost,
            }
        )

        self._check_budget(registry)

    def _check_budget(self, registry: UsageRegistry) -> None:
        """Warn-only. `Settings.llm_budget_action` currently accepts only
        `"warn"` (see its docstring) — a `"stop"` mode that would raise
        `UsageBudgetExceededError` here was prototyped and pulled after a
        reproducible hang; see that class's docstring before re-adding
        one."""
        max_tokens = self._settings.llm_max_total_tokens
        max_cost = self._settings.llm_max_cost_usd
        if max_tokens <= 0 and max_cost <= 0:
            return

        totals = registry.totals()
        over_tokens = max_tokens > 0 and totals.total_tokens >= max_tokens
        over_cost = max_cost > 0 and totals.cost_usd >= max_cost
        if not (over_tokens or over_cost):
            return

        first_crossing = registry.note_budget_exceeded()
        if first_crossing:
            logger.warning(
                "LLM usage budget exceeded: %s tokens, $%.4f (limits: %s tokens, $%s)",
                f"{totals.total_tokens:,}",
                totals.cost_usd,
                f"{max_tokens:,}" if max_tokens > 0 else "unlimited",
                f"{max_cost:.2f}" if max_cost > 0 else "unlimited",
            )


def format_usage_summary(report: UsageReport, *, show_roles: bool = True) -> str:
    """Render `report` as the plain-text console block every runner
    prints. Returns `""` when there were zero calls, so callers can do
    `if text := format_usage_summary(report): print(text)` unconditionally
    rather than special-casing an empty run. Bare f-strings, no rich/
    tabulate — this repo uses neither anywhere."""
    if report.calls == 0:
        return ""

    lines: list[str] = ["LLM usage"]
    measured = report.calls - report.unmeasured_calls
    calls_line = f"  calls:   {report.calls:,}"
    if report.unmeasured_calls:
        calls_line += f"  ({report.unmeasured_calls:,} unmeasured)"
    lines.append(calls_line)

    if measured:
        cache_bits = []
        if report.cache_read_tokens:
            cache_bits.append(f"cache read {report.cache_read_tokens:,}")
        if report.cache_creation_tokens:
            cache_bits.append(f"write {report.cache_creation_tokens:,}")
        cache_note = f"  ({' / '.join(cache_bits)})" if cache_bits else ""
        lines.append(f"  input:   {report.input_tokens:,} tokens{cache_note}")

        reasoning_note = (
            f"  (reasoning {report.reasoning_tokens:,})" if report.reasoning_tokens else ""
        )
        lines.append(f"  output:  {report.output_tokens:,} tokens{reasoning_note}")
        lines.append(f"  total:   {report.total_tokens:,} tokens")

        cost_note = " (estimated)" if not report.has_unpriced else " (estimated, partial)"
        lines.append(f"  cost:    ${report.cost_usd:,.2f}{cost_note}")

    if report.budget_exceeded:
        lines.append(
            "  ** usage budget exceeded — see FWA_LLM_MAX_TOTAL_TOKENS/FWA_LLM_MAX_COST_USD **"
        )

    if show_roles and report.by_role:
        lines.append("  by role:")
        for role, totals in sorted(report.by_role.items(), key=lambda kv: -kv[1]["total_tokens"]):
            cost_str = f"${totals['cost_usd']:.2f}" if totals["cost_usd"] else "$0.00"
            lines.append(
                f"    {role:<28} {totals['calls']:>3} calls   "
                f"{totals['total_tokens']:>10,} tok   {cost_str}"
            )

    if report.has_unpriced:
        unpriced_models = sorted(
            model for model, totals in report.by_model.items() if totals.get("has_unpriced")
        )
        if unpriced_models:
            lines.append(f"  note: no price entry for {', '.join(unpriced_models)}")

    return "\n".join(lines)


def stamp_usage_metadata(report: UsageReport, *, settings: Settings) -> None:
    """Attach `report`'s aggregate as metadata on the currently active
    LangSmith root span, when tracing is on. A no-op (no `langsmith`
    import attempted) when it's off — same discipline as every function in
    `observability.spans`.

    What this adds beyond LangChain's own native per-call LangSmith
    reporting (which already happens automatically once tracing is
    configured): LangSmith aggregates per-TRACE, and a run that fans out
    over hundreds of chunk/candidate traces has no single place showing
    the RUN total. This stamps that total onto the root run so it's
    visible without summing child traces by hand.
    """
    if not tracing_enabled(settings):
        return
    try:
        from langsmith.run_helpers import get_current_run_tree
    except ImportError:
        return
    try:
        run = get_current_run_tree()
        if run is None:
            return
        run.add_metadata(
            {
                "usage.calls": report.calls,
                "usage.total_tokens": report.total_tokens,
                "usage.cost_usd": report.cost_usd,
                "usage.by_role": report.by_role,
            }
        )
    except Exception:  # noqa: BLE001 - best-effort only, must never fail a run
        logger.debug("stamp_usage_metadata failed; continuing.", exc_info=True)


__all__ = [
    "RoleTotals",
    "UsageBudgetExceededError",
    "UsageRecord",
    "UsageRegistry",
    "UsageReport",
    "UsageTrackingCallbackHandler",
    "current_registry",
    "format_usage_summary",
    "stamp_usage_metadata",
    "usage_registry",
]
