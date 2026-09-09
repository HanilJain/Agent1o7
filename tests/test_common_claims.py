"""Sanity tests for `fw_audit.common.claims` — the Stage 3b LLM structured-
output contract and run-bookkeeping schema."""

from __future__ import annotations

from datetime import UTC, datetime

from fw_audit.common.claims import (
    ClaimExtraction,
    ClaimExtractionBatch,
    ClaimRecord,
    ClaimsRunSummary,
)


def test_claim_extraction_minimal_construction():
    claim = ClaimExtraction(
        claim_id="c1",
        title="t",
        category="memory_safety",
        security_condition="unchecked copy",
    )
    assert claim.cwe == []
    assert claim.cve_ids == []
    assert claim.binary_hint == ""
    assert claim.attacker_control == "UNKNOWN"
    assert claim.page_numbers == []


def test_claim_extraction_batch_defaults():
    batch = ClaimExtractionBatch()
    assert batch.claims == []
    assert batch.not_a_finding is False


def test_claim_extraction_batch_round_trips_json():
    claim = ClaimExtraction(
        claim_id="c1", title="t", category="cat", security_condition="sc", cwe=["CWE-121"]
    )
    batch = ClaimExtractionBatch(claims=[claim])
    raw = batch.model_dump_json()
    back = ClaimExtractionBatch.model_validate_json(raw)
    assert back.claims[0].claim_id == "c1"
    assert back.claims[0].cwe == ["CWE-121"]


def test_claim_record_defaults():
    record = ClaimRecord(
        global_id="bin#9000::c1", claim_id="c1", chunk_id="bin#9000", bin_id="bin", status="emitted"
    )
    assert record.binary_resolved is False
    assert record.findings_relpath is None
    assert record.error is None


def test_claims_run_summary_round_trips_json():
    summary = ClaimsRunSummary(
        status="completed",
        db_subfolder="/db",
        source_pdf="/report.pdf",
        doc_stem="report",
        model="ollama:kimi-k3",
        started_at=datetime.now(UTC),
    )
    back = ClaimsRunSummary.model_validate_json(summary.model_dump_json())
    assert back.status == "completed"
    assert back.schema_version == 1
