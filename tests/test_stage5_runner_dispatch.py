"""Tests for `stage5_verification.runner._cmd_run`'s dispatch — Stage 5
FVVW v3 Phase 6. Confirms `--joern-only` actually routes to the original
`driver.run_queue`, and its absence routes to `fvvw.driver.run_fvvw_queue`
— the behavioral guarantee behind the CLI's new default, not just its
argparse shape (already covered by `test_stage5_runner.py`)."""

from __future__ import annotations

from datetime import UTC, datetime

from fw_audit.common.verification import VerificationRunSummary
from fw_audit.stage5_verification import runner


def _fake_summary() -> VerificationRunSummary:
    return VerificationRunSummary(
        run_id="r1",
        status="completed",
        db_subfolder="db",
        candidates=[],
        total_candidates=0,
        total_verified=0,
        total_failed=0,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )


def test_cmd_run_joern_only_calls_run_queue_not_fvvw(monkeypatch, tmp_path, capsys):
    calls = {"joern": 0, "fvvw": 0}

    async def fake_run_queue(**kwargs):
        calls["joern"] += 1
        return _fake_summary()

    async def fake_run_fvvw_queue(**kwargs):
        calls["fvvw"] += 1
        return _fake_summary()

    monkeypatch.setattr(runner, "run_queue", fake_run_queue)
    monkeypatch.setattr(runner, "run_fvvw_queue", fake_run_fvvw_queue)

    args = runner._parse_args(
        ["run", "--db-subfolder", str(tmp_path), "--joern-only"]
    )
    exit_code = runner._cmd_run(args)

    assert exit_code == 0
    assert calls == {"joern": 1, "fvvw": 0}


def test_cmd_run_default_calls_fvvw_queue_not_joern(monkeypatch, tmp_path, capsys):
    calls = {"joern": 0, "fvvw": 0}

    async def fake_run_queue(**kwargs):
        calls["joern"] += 1
        return _fake_summary()

    async def fake_run_fvvw_queue(**kwargs):
        calls["fvvw"] += 1
        return _fake_summary()

    monkeypatch.setattr(runner, "run_queue", fake_run_queue)
    monkeypatch.setattr(runner, "run_fvvw_queue", fake_run_fvvw_queue)

    args = runner._parse_args(["run", "--db-subfolder", str(tmp_path)])
    exit_code = runner._cmd_run(args)

    assert exit_code == 0
    assert calls == {"joern": 0, "fvvw": 1}
    captured = capsys.readouterr()
    assert "Full FVVW v3 fork-join run" in captured.out


def test_cmd_run_joern_only_output_omits_fork_join_note(monkeypatch, tmp_path, capsys):
    async def fake_run_queue(**kwargs):
        return _fake_summary()

    monkeypatch.setattr(runner, "run_queue", fake_run_queue)

    args = runner._parse_args(["run", "--db-subfolder", str(tmp_path), "--joern-only"])
    runner._cmd_run(args)

    captured = capsys.readouterr()
    assert "Full FVVW v3 fork-join run" not in captured.out
    assert "Verdicts:" in captured.out


def test_cmd_run_default_uses_mechanism_confidence_label(monkeypatch, tmp_path, capsys):
    async def fake_run_fvvw_queue(**kwargs):
        return _fake_summary()

    monkeypatch.setattr(runner, "run_fvvw_queue", fake_run_fvvw_queue)

    args = runner._parse_args(["run", "--db-subfolder", str(tmp_path)])
    runner._cmd_run(args)

    captured = capsys.readouterr()
    assert "Mechanism confidence tallies:" in captured.out
