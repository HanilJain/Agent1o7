"""Tests for fw_audit.stage3_analysis.agent.consumer.AnalysisConsumer."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from fw_audit.common.findings import AnalysisReport
from fw_audit.config.settings import Settings
from fw_audit.stage3_analysis.agent.analyst import AnalysisUnavailableError
from fw_audit.stage3_analysis.agent.consumer import AnalysisConsumer
from fw_audit.stage3_analysis.models import ChunkHandle


def _handle(
    tmp_path: Path, *, chunk_id="test_bin#0000", approx_tokens=100, attempt=0
) -> ChunkHandle:
    chunk_path = tmp_path / "chunks" / f"{chunk_id.replace('#', '__')}.c"
    chunk_path.parent.mkdir(parents=True, exist_ok=True)
    chunk_path.write_text("void f(void) {}", encoding="utf-8")
    return ChunkHandle(
        chunk_id=chunk_id,
        bin_id="test_bin",
        rootfs_path="bin/test",
        source_relpath="bin/test.c",
        chunk_path=chunk_path,
        start_line=1,
        end_line=1,
        approx_tokens=approx_tokens,
        oversized=False,
        attempt=attempt,
    )


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


async def test_consumer_writes_findings_file_and_records_success(tmp_path, monkeypatch):
    report = AnalysisReport(chunk_id="test_bin#0000", findings=[], checked_categories=[])

    async def fake_analyze_chunk(text, *, chunk_id, rootfs_path, settings, function_names=()):
        return report

    monkeypatch.setattr(
        "fw_audit.stage3_analysis.agent.consumer.analyze_chunk", fake_analyze_chunk
    )

    consumer = AnalysisConsumer(db_subfolder=tmp_path, settings=_settings())
    handle = _handle(tmp_path)
    await consumer(handle)

    findings_path = tmp_path / "stage3" / "findings" / "test_bin__0000.json"
    assert findings_path.is_file()
    written = json.loads(findings_path.read_text(encoding="utf-8"))
    assert written["chunk_id"] == "test_bin#0000"

    assert len(consumer.records) == 1
    record = consumer.records[0]
    assert record.status == "analyzed"
    assert record.attempts == 1
    assert record.finding_count == 0
    assert record.findings_relpath == str(
        (tmp_path / "stage3" / "findings" / "test_bin__0000.json").relative_to(tmp_path)
    )


async def test_consumer_skips_oversized_chunk_without_llm_call(tmp_path, monkeypatch):
    called = False

    async def fake_analyze_chunk(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("should not be called for an oversized chunk")

    monkeypatch.setattr(
        "fw_audit.stage3_analysis.agent.consumer.analyze_chunk", fake_analyze_chunk
    )

    consumer = AnalysisConsumer(
        db_subfolder=tmp_path, settings=_settings(stage3_max_chunk_tokens=10)
    )
    handle = _handle(tmp_path, approx_tokens=1000)
    await consumer(handle)

    assert not called
    assert len(consumer.records) == 1
    assert consumer.records[0].status == "skipped_oversized"
    # No findings file should have been written.
    assert not (tmp_path / "stage3" / "findings").exists() or not list(
        (tmp_path / "stage3" / "findings").iterdir()
    )


async def test_consumer_raises_on_analysis_failure_no_record_appended(tmp_path, monkeypatch):
    async def fake_analyze_chunk(*args, **kwargs):
        raise AnalysisUnavailableError("boom")

    monkeypatch.setattr(
        "fw_audit.stage3_analysis.agent.consumer.analyze_chunk", fake_analyze_chunk
    )

    consumer = AnalysisConsumer(db_subfolder=tmp_path, settings=_settings())
    handle = _handle(tmp_path)

    with pytest.raises(RuntimeError, match="analysis failed"):
        await consumer(handle)

    # No record appended on failure — chunk_queue's nack()/retry owns this
    # outcome; the orchestrator reconciles permanent failure afterward.
    assert consumer.records == []


async def test_consumer_timeout_message_names_the_configured_seconds(tmp_path, monkeypatch):
    """`asyncio.wait_for`'s `TimeoutError` carries no message of its own
    (`str(TimeoutError()) == ""`) — the consumer must build an actual
    message naming the configured timeout, not rely on `{exc}` producing a
    blank, content-free "analysis failed for X: " log line."""

    async def fake_analyze_chunk(*args, **kwargs):
        await asyncio.sleep(10)

    monkeypatch.setattr(
        "fw_audit.stage3_analysis.agent.consumer.analyze_chunk", fake_analyze_chunk
    )

    consumer = AnalysisConsumer(
        db_subfolder=tmp_path, settings=_settings(stage3_llm_timeout_seconds=1)
    )
    handle = _handle(tmp_path)

    with pytest.raises(RuntimeError, match=r"exceeded stage3_llm_timeout_seconds \(1s\)"):
        await consumer(handle)

    assert consumer.records == []


async def test_consumer_backs_off_only_on_retried_attempts(tmp_path, monkeypatch):
    sleep_calls = []

    async def fake_sleep(seconds):
        sleep_calls.append(seconds)

    monkeypatch.setattr("fw_audit.stage3_analysis.agent.consumer.asyncio.sleep", fake_sleep)

    report = AnalysisReport(chunk_id="test_bin#0000", findings=[], checked_categories=[])

    async def fake_analyze_chunk(*args, **kwargs):
        return report

    monkeypatch.setattr(
        "fw_audit.stage3_analysis.agent.consumer.analyze_chunk", fake_analyze_chunk
    )

    settings = _settings(stage3_llm_retry_backoff_seconds=2.0)
    consumer = AnalysisConsumer(db_subfolder=tmp_path, settings=settings)

    # First attempt (attempt=0): no backoff.
    await consumer(_handle(tmp_path, chunk_id="test_bin#0000", attempt=0))
    assert sleep_calls == []

    # Retried attempt (attempt=1): backoff = base * 2**(1-1) = base.
    await consumer(_handle(tmp_path, chunk_id="test_bin#0001", attempt=1))
    assert sleep_calls == [2.0]

    # Second retry (attempt=2): backoff = base * 2**(2-1) = 2*base.
    await consumer(_handle(tmp_path, chunk_id="test_bin#0002", attempt=2))
    assert sleep_calls == [2.0, 4.0]


async def test_consumer_reads_chunk_text_from_disk(tmp_path, monkeypatch):
    captured_text = None

    async def fake_analyze_chunk(text, *, chunk_id, rootfs_path, settings, function_names=()):
        nonlocal captured_text
        captured_text = text
        return AnalysisReport(chunk_id=chunk_id, findings=[], checked_categories=[])

    monkeypatch.setattr(
        "fw_audit.stage3_analysis.agent.consumer.analyze_chunk", fake_analyze_chunk
    )

    consumer = AnalysisConsumer(db_subfolder=tmp_path, settings=_settings())
    handle = _handle(tmp_path)
    await consumer(handle)

    assert captured_text == "void f(void) {}"
