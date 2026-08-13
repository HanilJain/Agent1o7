"""End-to-end tests for fw_audit.stage3_analysis.agent.orchestrator.run_analysis.

Reuses the `_setup_run` builder pattern from `test_stage3_chunk_queue.py`
(real `ingest()`, real chunker, real queue — only the LLM is faked) since
`run_analysis()` is a thin wrapper around the already-tested `run_queue()`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from fw_audit.common.findings import AnalysisReport, Finding
from fw_audit.common.schemas import ExtractionStatus
from fw_audit.config.settings import Settings
from fw_audit.stage3_analysis.agent.orchestrator import (
    AnalystModelUnavailableError,
    run_analysis,
)
from fw_audit.stage3_analysis.ingest import ingest


def _setup_run(
    tmp_path: Path,
    *,
    source_text: str,
    bin_id: str = "bin_busybox",
    rootfs_path: str = "bin/busybox",
) -> Path:
    """Mirrors test_stage3_chunk_queue.py's `_setup_run`."""
    db_subfolder = tmp_path / "db" / "fw"
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True)
    tree_dir = tmp_path / "db" / "fw_decompiled"
    rel_dir = "/".join(rootfs_path.split("/")[:-1])
    (tree_dir / rel_dir).mkdir(parents=True, exist_ok=True)
    (tree_dir / f"{rootfs_path}.c").write_text(source_text, encoding="utf-8")

    summary_path = db_subfolder / "stage1_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "identified_binaries": [{"path": rootfs_path}],
            }
        ),
        encoding="utf-8",
    )
    (stage2_dir / "stage2_summary.json").write_text(
        json.dumps(
            {
                "run_id": "r",
                "status": ExtractionStatus.COMPLETED.value,
                "db_subfolder": str(db_subfolder),
                "rootfs_dir": str(db_subfolder / "rootfs"),
                "stage2_dir": str(stage2_dir),
                "decompiled_tree_dir": "fw_decompiled",
                "ghidra_image": "fw-audit-ghidra:latest",
                "binaries": [
                    {
                        "bin_id": bin_id,
                        "rootfs_path": rootfs_path,
                        "requested_path": rootfs_path,
                        "sha256": "0" * 64,
                        "size_bytes": len(source_text.encode("utf-8")),
                        "status": "succeeded",
                        "function_count": 1,
                        "artifacts": {"decompiled_tree_c": f"{rootfs_path}.c"},
                    }
                ],
                "started_at": datetime.now(UTC).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    return summary_path


def _padded_function(name: str, n_statements: int = 60) -> str:
    body = "\n".join(f"  x += {i};" for i in range(n_statements))
    return f"int {name}(int x)\n{{\n{body}\n  return x;\n}}\n"


def _patch_analyze_chunk(monkeypatch, fn) -> None:
    monkeypatch.setattr("fw_audit.stage3_analysis.agent.consumer.analyze_chunk", fn)


async def test_run_analysis_end_to_end_all_succeed(tmp_path, monkeypatch):
    pytest.importorskip("tree_sitter_c")
    source = _padded_function("add") + "\n" + _padded_function("sub")
    summary_path = _setup_run(tmp_path, source_text=source)
    report = ingest(stage1_summary_path=summary_path)
    settings = Settings(_env_file=None, stage3_chunk_lines=50, stage3_queue_workers=3)

    async def fake_analyze_chunk(text, *, chunk_id, rootfs_path, settings, function_names=()):
        return AnalysisReport(
            chunk_id=chunk_id,
            findings=[
                Finding(
                    finding_id="f1",
                    title="test finding",
                    category="memory_safety",
                    severity={"impact": 3, "exploitability": 2, "reachability": 2},
                    confidence="MEDIUM",
                    decision="ESCALATE",
                    evidence_span={
                        "function_id": "f",
                        "line_start": 1,
                        "line_end": 1,
                        "code": "x",
                    },
                    source={"expression": "x", "type": "LOCAL", "attacker_control": "UNKNOWN"},
                    sink={"expression": "y", "type": "MEMORY_WRITE"},
                    security_condition="test condition",
                    exploitability="test exploitability",
                    impact="test impact",
                    why_vulnerable="test",
                    why_not_false_positive="test",
                )
            ],
            checked_categories=[],
        )

    _patch_analyze_chunk(monkeypatch, fake_analyze_chunk)

    analysis_summary, queue_summary = await run_analysis(report, settings=settings)

    assert queue_summary.total_chunks == 2
    assert queue_summary.total_acked == 2
    assert analysis_summary.total_chunks == 2
    assert analysis_summary.total_analyzed == 2
    assert analysis_summary.total_failed == 0
    assert analysis_summary.total_findings == 2
    assert analysis_summary.findings_by_decision.get("ESCALATE") == 2
    assert analysis_summary.findings_by_confidence.get("MEDIUM") == 2

    findings_dir = tmp_path / "db" / "fw" / "stage3" / "findings"
    assert findings_dir.is_dir()
    assert len(list(findings_dir.glob("*.json"))) == 2

    summary_path_on_disk = tmp_path / "db" / "fw" / "stage3" / "analysis_summary.json"
    assert summary_path_on_disk.is_file()
    written = json.loads(summary_path_on_disk.read_text(encoding="utf-8"))
    assert written["total_analyzed"] == 2
    assert written["model"]


async def test_run_analysis_records_permanent_failure_after_retries_exhausted(
    tmp_path, monkeypatch
):
    pytest.importorskip("tree_sitter_c")
    source = _padded_function("add")
    summary_path = _setup_run(tmp_path, source_text=source)
    report = ingest(stage1_summary_path=summary_path)
    settings = Settings(
        _env_file=None,
        stage3_chunk_lines=50,
        stage3_queue_workers=1,
        stage3_queue_max_attempts=2,
        stage3_llm_retry_backoff_seconds=0,
    )

    async def always_fails(text, *, chunk_id, rootfs_path, settings, function_names=()):
        raise RuntimeError("permanent failure")

    _patch_analyze_chunk(monkeypatch, always_fails)

    analysis_summary, queue_summary = await run_analysis(report, settings=settings)

    assert queue_summary.total_failed == 1
    assert analysis_summary.total_failed == 1
    assert analysis_summary.total_analyzed == 0
    failed_record = analysis_summary.chunks[0]
    assert failed_record.status == "failed"
    assert failed_record.attempts == 2


async def test_run_analysis_missing_credential_raises_before_any_chunk(tmp_path, monkeypatch):
    pytest.importorskip("tree_sitter_c")
    source = _padded_function("add")
    summary_path = _setup_run(tmp_path, source_text=source)
    report = ingest(stage1_summary_path=summary_path)
    settings = Settings(_env_file=None, stage3_chunk_lines=50)

    def _raise(role, settings=None):
        raise ValueError("ANTHROPIC_API_KEY is not set.")

    monkeypatch.setattr(
        "fw_audit.stage3_analysis.agent.orchestrator.resolve_usable_spec", _raise
    )

    with pytest.raises(AnalystModelUnavailableError, match="ANTHROPIC_API_KEY"):
        await run_analysis(report, settings=settings)
