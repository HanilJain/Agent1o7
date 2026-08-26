"""Tests for `fw_audit.stage5_verification.agent.verifier` — the entry
point tying workspace setup, LLM resolution, and graph invocation together.
Mocks `get_llm_for_agent` and `build_verifier_graph` so this never needs a
real LLM, Docker, or Joern."""

from __future__ import annotations

import pytest

from fw_audit.common.verification import VerificationVerdict
from fw_audit.config.settings import Settings
from fw_audit.stage5_verification.agent import verifier as verifier_mod
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.errors import (
    SandboxUnavailableError,
    VerifierModelUnavailableError,
)


def _candidate(source_path) -> VerificationCandidate:
    from fw_audit.common.findings import (
        Confidence,
        Decision,
        EvidenceSpan,
        Finding,
        FindingSink,
        FindingSource,
        Severity,
    )

    finding = Finding(
        finding_id="c1",
        title="t",
        category="command_execution",
        severity=Severity(impact=3, exploitability=3, reachability=3),
        confidence=Confidence.MEDIUM,
        decision=Decision.ESCALATE,
        evidence_span=EvidenceSpan(function_id="f", line_start=1, line_end=2, code="x"),
        source=FindingSource(expression="s", type="NVRAM", attacker_control="UNKNOWN"),
        sink=FindingSink(expression="system(s)", type="COMMAND_EXECUTION"),
        security_condition="c",
        exploitability="e",
        impact="i",
        why_vulnerable="w",
        why_not_false_positive="n",
    )
    return VerificationCandidate(
        global_id="bin#0000::c1",
        chunk_id="bin#0000",
        bin_id="bin",
        finding=finding,
        source_path=source_path,
    )


class _FakeGraph:
    def __init__(self, final_state) -> None:
        self._final_state = final_state
        self.invocations: list = []

    async def ainvoke(self, initial_state, config=None):
        # config=... is verifier.py's LangSmith run_config passthrough (see
        # fw_audit.observability) — accepted and ignored here.
        self.invocations.append(initial_state)
        return self._final_state


class _FakeAvailableExecutor:
    def available(self) -> bool:
        return True


async def test_source_path_unresolved_raises_sandbox_unavailable(tmp_path):
    candidate = _candidate(None)
    with pytest.raises(SandboxUnavailableError, match="no resolved normalized Joern C"):
        await verifier_mod.verify_candidate(
            candidate, db_subfolder=tmp_path, settings=Settings(_env_file=None)
        )


async def test_sandbox_unavailable_raises(tmp_path, monkeypatch):
    source = tmp_path / "whole.c"
    source.write_text("int main(){}", encoding="utf-8")

    class _Unavailable:
        def available(self):
            return False

    monkeypatch.setattr(verifier_mod, "joern_executor", lambda settings: _Unavailable())

    with pytest.raises(SandboxUnavailableError, match="Sandbox executor unavailable"):
        await verifier_mod.verify_candidate(
            _candidate(source), db_subfolder=tmp_path, settings=Settings(_env_file=None)
        )


async def test_model_unavailable_raises(tmp_path, monkeypatch):
    source = tmp_path / "whole.c"
    source.write_text("int main(){}", encoding="utf-8")
    monkeypatch.setattr(verifier_mod, "joern_executor", lambda settings: _FakeAvailableExecutor())

    def raise_value_error(role, settings=None):
        raise ValueError("no credential")

    monkeypatch.setattr(verifier_mod, "get_llm_for_agent", raise_value_error)

    with pytest.raises(VerifierModelUnavailableError, match="no credential"):
        await verifier_mod.verify_candidate(
            _candidate(source), db_subfolder=tmp_path, settings=Settings(_env_file=None)
        )


async def test_verify_candidate_assembles_report_from_graph_state(tmp_path, monkeypatch):
    source = tmp_path / "whole.c"
    source.write_text("int main(){}", encoding="utf-8")
    monkeypatch.setattr(verifier_mod, "joern_executor", lambda settings: _FakeAvailableExecutor())
    monkeypatch.setattr(verifier_mod, "get_llm_for_agent", lambda role, settings=None: object())

    final_state = {
        "verdict": VerificationVerdict.CONFIRMED,
        "verdict_confidence": "HIGH",
        "verdict_summary": "summary text",
        "verdict_evidence": "evidence text",
        "verdict_next_steps": ["step 1"],
    }
    fake_graph = _FakeGraph(final_state)
    monkeypatch.setattr(verifier_mod, "build_verifier_graph", lambda **kwargs: fake_graph)

    report = await verifier_mod.verify_candidate(
        _candidate(source), db_subfolder=tmp_path, settings=Settings(_env_file=None)
    )

    assert report.verdict == VerificationVerdict.CONFIRMED
    assert report.confidence == "HIGH"
    assert report.summary == "summary text"
    assert report.evidence == "evidence text"
    assert report.recommended_next_steps == ["step 1"]
    assert report.global_id == "bin#0000::c1"
    assert report.bin_id == "bin"
    assert len(fake_graph.invocations) == 1

    # source file must have been copied into the per-candidate workspace
    from fw_audit.stage5_verification import layout

    workspace = layout.workspace_dir(layout.stage5_dir(tmp_path), "bin#0000::c1")
    assert (workspace / "whole.c").read_text(encoding="utf-8") == "int main(){}"


async def test_system_prompt_override_replaces_system_message(tmp_path, monkeypatch):
    source = tmp_path / "whole.c"
    source.write_text("int main(){}", encoding="utf-8")
    monkeypatch.setattr(verifier_mod, "joern_executor", lambda settings: _FakeAvailableExecutor())
    monkeypatch.setattr(verifier_mod, "get_llm_for_agent", lambda role, settings=None: object())

    final_state = {
        "verdict": VerificationVerdict.INCONCLUSIVE,
        "verdict_confidence": "LOW",
        "verdict_summary": "",
        "verdict_evidence": "",
        "verdict_next_steps": [],
    }
    fake_graph = _FakeGraph(final_state)
    monkeypatch.setattr(verifier_mod, "build_verifier_graph", lambda **kwargs: fake_graph)

    await verifier_mod.verify_candidate(
        _candidate(source),
        db_subfolder=tmp_path,
        settings=Settings(_env_file=None),
        system_prompt="CUSTOM PROMPT TEXT",
    )

    invocation = fake_graph.invocations[0]
    assert invocation["system_prompt"] == "CUSTOM PROMPT TEXT"
    assert invocation["transcript"][0].content == "CUSTOM PROMPT TEXT"
