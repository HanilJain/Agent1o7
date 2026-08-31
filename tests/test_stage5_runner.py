"""Tests for `fw_audit.stage5_verification.runner`'s CLI argument parsing —
specifically `--decisions`, the override for the default ESCALATE-only
candidate filter."""

from __future__ import annotations

import pytest

from fw_audit.common.findings import Decision
from fw_audit.stage5_verification.runner import _parse_args, _parse_decisions


def test_parse_decisions_single_value():
    assert _parse_decisions("CONTEXT_REQUIRED") == frozenset({Decision.CONTEXT_REQUIRED})


def test_parse_decisions_multiple_comma_separated_values():
    result = _parse_decisions("ESCALATE,CONTEXT_REQUIRED")
    assert result == frozenset({Decision.ESCALATE, Decision.CONTEXT_REQUIRED})


def test_parse_decisions_tolerates_surrounding_whitespace():
    assert _parse_decisions(" ESCALATE , CONTEXT_REQUIRED ") == frozenset(
        {Decision.ESCALATE, Decision.CONTEXT_REQUIRED}
    )


def test_parse_decisions_rejects_unknown_value():
    with pytest.raises(ValueError, match="Unknown --decisions value 'BOGUS'"):
        _parse_decisions("BOGUS")


def test_parse_decisions_rejects_empty_string():
    with pytest.raises(ValueError, match="empty after parsing"):
        _parse_decisions("")


def test_run_subcommand_decisions_defaults_to_none():
    args = _parse_args(["run", "--db-subfolder", "x"])
    assert args.decisions is None


def test_run_subcommand_decisions_flag_is_captured_raw():
    args = _parse_args(["run", "--db-subfolder", "x", "--decisions", "CONTEXT_REQUIRED"])
    assert args.decisions == "CONTEXT_REQUIRED"


# ---------------------------------------------------------------------- #
# --joern-only (Stage 5 FVVW v3 Phase 6) — `run` defaults to the fork-join;
# this flag reaches the ORIGINAL static-only pipeline unchanged.
# ---------------------------------------------------------------------- #


def test_run_subcommand_joern_only_defaults_to_false():
    args = _parse_args(["run", "--db-subfolder", "x"])
    assert args.joern_only is False


def test_run_subcommand_joern_only_flag_sets_true():
    args = _parse_args(["run", "--db-subfolder", "x", "--joern-only"])
    assert args.joern_only is True


# ---------------------------------------------------------------------- #
# --hitl / --max-iterations / --dynamic-max-iterations / --no-command-log
# (Stage 5 HITL plan Part 4)
# ---------------------------------------------------------------------- #


def test_run_subcommand_hitl_defaults_to_none():
    args = _parse_args(["run", "--db-subfolder", "x"])
    assert args.hitl is None


def test_run_subcommand_hitl_prompt_flag_parses():
    args = _parse_args(["run", "--db-subfolder", "x", "--hitl", "prompt"])
    assert args.hitl == "prompt"


def test_run_subcommand_hitl_off_flag_parses():
    args = _parse_args(["run", "--db-subfolder", "x", "--hitl", "off"])
    assert args.hitl == "off"


def test_run_subcommand_hitl_rejects_unknown_value():
    with pytest.raises(SystemExit):
        _parse_args(["run", "--db-subfolder", "x", "--hitl", "bogus"])


def test_run_subcommand_max_iterations_defaults_to_none():
    args = _parse_args(["run", "--db-subfolder", "x"])
    assert args.max_iterations is None


def test_run_subcommand_max_iterations_flag_parses():
    args = _parse_args(["run", "--db-subfolder", "x", "--max-iterations", "10"])
    assert args.max_iterations == 10


def test_run_subcommand_dynamic_max_iterations_flag_parses():
    args = _parse_args(["run", "--db-subfolder", "x", "--dynamic-max-iterations", "8"])
    assert args.dynamic_max_iterations == 8


def test_run_subcommand_no_command_log_defaults_to_false():
    args = _parse_args(["run", "--db-subfolder", "x"])
    assert args.no_command_log is False


def test_run_subcommand_no_command_log_flag_sets_true():
    args = _parse_args(["run", "--db-subfolder", "x", "--no-command-log"])
    assert args.no_command_log is True


def test_cmd_run_hitl_prompt_forces_single_worker(monkeypatch, tmp_path, capsys):
    """--hitl=prompt must force stage5_workers=1 and print a notice —
    a blocking terminal prompt cannot safely interleave with a concurrent
    candidate's own stdout."""
    from datetime import UTC, datetime

    from fw_audit.common.verification import VerificationRunSummary
    from fw_audit.stage5_verification import runner as runner_mod

    captured_settings = {}

    async def fake_run_fvvw_queue(*, db_subfolder, settings, only_global_ids, run_id, **kw):
        captured_settings["settings"] = settings
        return VerificationRunSummary(
            status="completed",
            db_subfolder=str(db_subfolder),
            started_at=datetime.now(UTC),
        )

    monkeypatch.setattr(runner_mod, "run_fvvw_queue", fake_run_fvvw_queue)

    args = runner_mod._parse_args(
        ["run", "--db-subfolder", str(tmp_path), "--hitl", "prompt"]
    )
    rc = runner_mod._cmd_run(args)

    assert rc == 0
    assert captured_settings["settings"].stage5_hitl_mode == "prompt"
    assert captured_settings["settings"].stage5_workers == 1
    stderr = capsys.readouterr().err
    assert "stage5_workers=1" in stderr


# ---------------------------------------------------------------------- #
# New per-track debug subcommands (Stage 5 FVVW v3 Phase 6)
# ---------------------------------------------------------------------- #


def test_debug_strategy_subcommand_parses():
    args = _parse_args(["debug", "strategy", "--db-subfolder", "x", "--gid", "g"])
    assert args.debug_command == "strategy"
    assert args.db_subfolder == "x"
    assert args.gid == "g"


def test_debug_dynamic_subcommand_parses():
    args = _parse_args(["debug", "dynamic", "--db-subfolder", "x", "--gid", "g"])
    assert args.debug_command == "dynamic"
    assert args.gid == "g"


def test_debug_fvvw_subcommand_parses_with_optional_output():
    args = _parse_args(["debug", "fvvw", "--db-subfolder", "x", "--gid", "g"])
    assert args.debug_command == "fvvw"
    assert args.output is None

    args2 = _parse_args(
        ["debug", "fvvw", "--db-subfolder", "x", "--gid", "g", "--output", "out.md"]
    )
    assert args2.output == "out.md"
