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
