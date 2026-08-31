"""Tests for fw_audit.observability.

Covers exactly the safety properties the design in the plan rests on:
tracing off by default, true pass-through behavior when disabled, graceful
degradation when `langsmith` can't be imported, `configure_tracing`
idempotency, and `trace_context` nesting/isolation across concurrent
`asyncio.create_task` workers (the concurrency guarantee Stage 3/4/5's
worker pools depend on).
"""

from __future__ import annotations

import asyncio
import builtins

import pytest

from fw_audit.config.settings import Settings
from fw_audit.observability import tracing as tracing_module
from fw_audit.observability.context import TraceContext, current_context, trace_context
from fw_audit.observability.spans import aspan, current_trace_url, run_config, span, traced
from fw_audit.observability.tracing import configure_tracing, flush_traces, tracing_enabled


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


_LANGSMITH_ENV_KEYS = (
    "LANGSMITH_TRACING",
    "LANGSMITH_API_KEY",
    "LANGSMITH_PROJECT",
    "LANGSMITH_ENDPOINT",
    "LANGSMITH_HIDE_INPUTS",
    "LANGSMITH_HIDE_OUTPUTS",
    "LANGSMITH_TRACING_SAMPLE_RATE",
)


@pytest.fixture(autouse=True)
def _isolated_langsmith_env(monkeypatch):
    """`configure_tracing()` writes directly to `os.environ` (that's its
    whole job) rather than through `monkeypatch.setenv`, so without this
    fixture a test that enables tracing leaks `LANGSMITH_TRACING=true` (etc.)
    into every test that runs after it in the same process — including
    `_settings()` calls elsewhere in this file, since `Settings(_env_file=None)`
    still reads real env vars for any field not passed explicitly. Clearing
    before AND restoring after each test keeps every test's env footprint
    contained to itself."""
    for key in _LANGSMITH_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(tracing_module, "_configured", False)
    yield
    for key in _LANGSMITH_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


# --------------------------------------------------------------------- #
# tracing_enabled / configure_tracing
# --------------------------------------------------------------------- #


def test_tracing_disabled_by_default():
    settings = _settings()
    assert settings.langsmith_tracing is False
    assert tracing_enabled(settings) is False


def test_tracing_enabled_when_flag_set_and_langsmith_importable():
    settings = _settings(LANGSMITH_TRACING="true", LANGSMITH_API_KEY="test-key")
    assert tracing_enabled(settings) is True


def test_tracing_disabled_when_langsmith_not_importable(monkeypatch):
    settings = _settings(LANGSMITH_TRACING="true", LANGSMITH_API_KEY="test-key")

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "langsmith":
            raise ImportError("simulated missing package")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert tracing_enabled(settings) is False


def test_configure_tracing_noop_when_disabled(monkeypatch):
    settings = _settings()
    result = configure_tracing(settings)
    assert result is False

    import os

    assert "LANGSMITH_TRACING" not in os.environ


def test_configure_tracing_sets_only_langsmith_keys(monkeypatch):
    settings = _settings(
        LANGSMITH_TRACING="true",
        LANGSMITH_API_KEY="test-key",
        LANGSMITH_PROJECT="fw-audit-test",
    )
    result = configure_tracing(settings)
    assert result is True

    import os

    assert os.environ["LANGSMITH_TRACING"] == "true"
    assert os.environ["LANGSMITH_API_KEY"] == "test-key"
    assert os.environ["LANGSMITH_PROJECT"] == "fw-audit-test"
    assert os.environ["LANGSMITH_ENDPOINT"] == "https://api.smith.langchain.com"


def test_configure_tracing_is_idempotent(monkeypatch):
    settings = _settings(LANGSMITH_TRACING="true", LANGSMITH_API_KEY="test-key")
    first = configure_tracing(settings)
    second = configure_tracing(settings)
    assert first is True
    assert second is True


def test_flush_traces_noop_when_never_configured(monkeypatch):
    monkeypatch.setattr(tracing_module, "_configured", False)
    # Must not raise even though nothing was configured.
    flush_traces()


# --------------------------------------------------------------------- #
# spans: pass-through behavior when tracing is disabled
# --------------------------------------------------------------------- #


def test_run_config_returns_none_when_disabled():
    settings = _settings()
    assert run_config(run_name="x", settings=settings) is None


def test_run_config_returns_dict_when_enabled():
    settings = _settings(LANGSMITH_TRACING="true", LANGSMITH_API_KEY="k")
    with trace_context(stage="3", run_id="abc123", chunk_id="chunk-1"):
        cfg = run_config(run_name="stage3.analyze", tags=["custom"], settings=settings)
    assert cfg is not None
    assert cfg["run_name"] == "stage3.analyze"
    assert "custom" in cfg["tags"]
    assert "stage:3" in cfg["tags"]
    assert "run:abc123" in cfg["tags"]
    assert cfg["metadata"]["chunk_id"] == "chunk-1"
    assert cfg["metadata"]["run_id"] == "abc123"


def test_traced_sync_passthrough_when_disabled(monkeypatch):
    from fw_audit.config import settings as settings_module

    monkeypatch.setattr(settings_module, "get_settings", lambda: _settings())

    calls = []

    @traced("my-span")
    def compute(x, y):
        calls.append((x, y))
        return x + y

    result = compute(2, 3)
    assert result == 5
    assert calls == [(2, 3)]


@pytest.mark.asyncio
async def test_traced_async_passthrough_when_disabled(monkeypatch):
    from fw_audit.config import settings as settings_module

    monkeypatch.setattr(settings_module, "get_settings", lambda: _settings())

    @traced("my-async-span")
    async def compute(x, y):
        await asyncio.sleep(0)
        return x * y

    result = await compute(4, 5)
    assert result == 20


def test_span_yields_none_when_disabled():
    settings = _settings()
    with span("noop-span", settings=settings) as run:
        assert run is None


@pytest.mark.asyncio
async def test_aspan_yields_none_when_disabled():
    settings = _settings()
    async with aspan("noop-async-span", settings=settings) as run:
        assert run is None


def test_span_yields_run_when_enabled():
    settings = _settings(LANGSMITH_TRACING="true", LANGSMITH_API_KEY="k")
    with span("real-span", run_type="tool", settings=settings) as run:
        assert run is not None
        run.end(outputs={"ok": True})


@pytest.mark.asyncio
async def test_aspan_yields_run_when_enabled():
    settings = _settings(LANGSMITH_TRACING="true", LANGSMITH_API_KEY="k")
    async with aspan("real-async-span", run_type="tool", settings=settings) as run:
        assert run is not None
        run.end(outputs={"ok": True})


def test_current_trace_url_none_with_no_active_run():
    assert current_trace_url() is None


# --------------------------------------------------------------------- #
# context: nesting and asyncio.create_task isolation
# --------------------------------------------------------------------- #


def test_current_context_defaults_to_empty():
    ctx = current_context()
    assert ctx == TraceContext()


def test_trace_context_nests_and_merges():
    with trace_context(stage="4", run_id="run-1"):
        assert current_context().stage == "4"
        assert current_context().run_id == "run-1"
        with trace_context(global_id="gid-1"):
            inner = current_context()
            assert inner.stage == "4"
            assert inner.run_id == "run-1"
            assert inner.global_id == "gid-1"
        # global_id must not leak back out of the inner block.
        assert current_context().global_id is None


def test_trace_context_restores_previous_on_exit():
    baseline = current_context()
    with trace_context(stage="5"):
        pass
    assert current_context() == baseline


def test_trace_context_isolated_across_sibling_tasks():
    """The concurrency guarantee the whole design rests on: context set
    inside one asyncio.create_task-spawned worker must not leak into a
    sibling task, even though both were created from the same parent
    context. Mirrors how Stage 3/4/5's worker pools fan out."""

    async def _run():
        seen: dict[str, str | None] = {}

        async def worker(name: str, chunk_id: str, delay: float):
            with trace_context(chunk_id=chunk_id):
                await asyncio.sleep(delay)
                # If context leaked between tasks, this would see a sibling's
                # chunk_id instead of its own.
                seen[name] = current_context().chunk_id

        with trace_context(stage="3", run_id="shared-run"):
            task_a = asyncio.create_task(worker("a", "chunk-a", 0.02))
            task_b = asyncio.create_task(worker("b", "chunk-b", 0.01))
            await asyncio.gather(task_a, task_b)

        return seen

    seen = asyncio.run(_run())
    assert seen["a"] == "chunk-a"
    assert seen["b"] == "chunk-b"


def test_trace_context_to_metadata_omits_unset_fields():
    ctx = TraceContext(stage="3", chunk_id="c1")
    metadata = ctx.to_metadata()
    assert metadata == {"stage": "3", "chunk_id": "c1"}


def test_trace_context_to_tags():
    ctx = TraceContext(stage="5", run_id="r1")
    assert ctx.to_tags() == ["stage:5", "run:r1"]


# --------------------------------------------------------------------- #
# thread_id — LangSmith Threads-view grouping
# --------------------------------------------------------------------- #


def test_effective_thread_id_falls_back_to_global_id():
    ctx = TraceContext(global_id="chunk1::finding1")
    assert ctx.effective_thread_id == "chunk1::finding1"


def test_effective_thread_id_prefers_explicit_thread_id():
    ctx = TraceContext(global_id="chunk1::finding1", thread_id="bin-level-thread")
    assert ctx.effective_thread_id == "bin-level-thread"


def test_effective_thread_id_none_when_nothing_set():
    ctx = TraceContext()
    assert ctx.effective_thread_id is None


def test_to_metadata_includes_thread_id_from_global_id():
    ctx = TraceContext(stage="5", global_id="chunk1::finding1")
    metadata = ctx.to_metadata()
    assert metadata["thread_id"] == "chunk1::finding1"
    assert metadata["global_id"] == "chunk1::finding1"


def test_to_metadata_omits_thread_id_when_nothing_to_derive_it_from():
    ctx = TraceContext(stage="5")
    assert "thread_id" not in ctx.to_metadata()


def test_every_span_in_one_candidates_verification_shares_a_thread_id():
    """The behavior this feature is actually for: every span opened while
    verifying ONE Stage 3 finding — strategy, static track, dynamic track,
    report — must carry the same thread_id with zero call-site changes,
    because they all already run inside one `trace_context(global_id=...)`
    block (fvvw/driver.py's _process_one_fvvw)."""
    with trace_context(stage="5", run_id="run-1", global_id="chunk1::finding1"):
        strategy_meta = current_context().to_metadata()
        with trace_context(bin_id="sbin_mailosd"):
            static_track_meta = current_context().to_metadata()
            dynamic_track_meta = current_context().to_metadata()
    assert strategy_meta["thread_id"] == "chunk1::finding1"
    assert static_track_meta["thread_id"] == "chunk1::finding1"
    assert dynamic_track_meta["thread_id"] == "chunk1::finding1"
