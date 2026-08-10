"""Tests for the Identifier Agent (Component 2).

Includes the import-purity guard: this module must never pull in
`fw_audit.executors` or any of Python's own execution/filesystem primitives
(`os`, `pathlib`, `subprocess`) — that boundary is the whole point of
splitting it out from the Extraction Script.
"""

from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from fw_audit.common.schemas import IdentifiedBinary
from fw_audit.stage1_ingestion.identifier.agent import (
    IdentifierUnavailableError,
    _IdentifiedBinaryList,
    identify_binaries,
)
from fw_audit.stage1_ingestion.identifier.prompts import build_prompt


def _fake_llm(*, result=None, side_effect=None):
    """Build a fake `BaseChatModel` stand-in matching the
    `with_structured_output(...).ainvoke(...)` call shape `agent.py` uses.
    """
    structured = SimpleNamespace(
        ainvoke=AsyncMock(return_value=result, side_effect=side_effect)
    )
    return SimpleNamespace(with_structured_output=lambda schema: structured)


def test_import_purity_no_executor_module():
    """The Identifier Agent must never gain execution capability.

    Run in a FRESH interpreter, not by manipulating this process's
    `sys.modules`: other test modules in this same session legitimately
    import `fw_audit.executors` (e.g. via `nodes.py`), which would make an
    in-process check see it as "leaked" regardless of what `identifier.agent`
    itself imports. A subprocess is the only reliable way to observe this
    module's *own* transitive import set in isolation.
    """
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import fw_audit.stage1_ingestion.identifier.agent, sys; "
            "assert 'fw_audit.executors' not in sys.modules, "
            "'identifier.agent transitively imported fw_audit.executors'",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr


def test_build_prompt_includes_tree_text_and_daemons():
    prompt = build_prompt("bin/httpd  84K  ELF ...", target_daemons={"httpd", "hostapd"})
    assert "bin/httpd" in prompt
    assert "httpd" in prompt
    assert "hostapd" in prompt
    # No prose-based format enforcement anymore — that's the whole point of
    # switching to with_structured_output (see prompts.py's module docstring).
    assert "JSON object" not in prompt
    assert '"binaries"' not in prompt
    # The one content rule the schema itself can't express: path must be
    # the complete filename, extension included — there's no separate
    # extension field for the model to fall back on.
    assert "COMPLETE path" in prompt
    assert "extension" in prompt


async def test_identify_binaries_returns_binaries_from_structured_output(monkeypatch):
    fake_llm = _fake_llm(
        result=_IdentifiedBinaryList(binaries=[IdentifiedBinary(path="bin/httpd")])
    )
    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", lambda role: fake_llm
    )

    result = await identify_binaries("bin/httpd  84K  ELF ...")

    assert result == [IdentifiedBinary(path="bin/httpd")]


async def test_identify_binaries_strict_shape_no_extra_fields(monkeypatch):
    # The whole point: output is strictly {"path": str} -- no "extension",
    # no synthesized "reason", no other field tacked on afterward. An
    # extension, when needed, is derived from `path` on demand instead
    # (see common/schemas.py::extension_from_path).
    fake_llm = _fake_llm(
        result=_IdentifiedBinaryList(binaries=[IdentifiedBinary(path="lib/modules/foo.ko")])
    )
    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", lambda role: fake_llm
    )

    result = await identify_binaries("lib/modules/foo.ko  20K  ELF ...")

    assert result[0].path == "lib/modules/foo.ko"
    assert set(result[0].model_dump().keys()) == {"path"}


async def test_identify_binaries_empty_list_is_valid(monkeypatch):
    fake_llm = _fake_llm(result=_IdentifiedBinaryList(binaries=[]))
    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", lambda role: fake_llm
    )

    result = await identify_binaries("etc/config.txt  1K")

    assert result == []


async def test_identify_binaries_validation_error_raises_unavailable(monkeypatch):
    # Simulate with_structured_output raising because the model/provider
    # produced output that doesn't satisfy the schema (missing "path").
    try:
        IdentifiedBinary.model_validate({})
    except ValidationError as exc:
        validation_error = exc
    else:  # pragma: no cover - defensive, "path" is required
        raise AssertionError("expected path to be required")

    fake_llm = _fake_llm(side_effect=validation_error)
    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", lambda role: fake_llm
    )

    with pytest.raises(IdentifierUnavailableError, match="schema"):
        await identify_binaries("bin/httpd")


async def test_identify_binaries_unexpected_result_type_raises_unavailable(monkeypatch):
    # Defensive backstop: with_structured_output should always return the
    # Pydantic model or raise, but guard against a provider handing back
    # something else (e.g. a bare dict) unnoticed.
    fake_llm = _fake_llm(result={"binaries": []})
    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", lambda role: fake_llm
    )

    with pytest.raises(IdentifierUnavailableError, match="unexpected result type"):
        await identify_binaries("bin/httpd")


async def test_identify_binaries_llm_construction_failure_raises_unavailable(monkeypatch):
    def raise_import_error(role):
        raise ImportError("langchain-ollama is required")

    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", raise_import_error
    )

    with pytest.raises(IdentifierUnavailableError, match="langchain-ollama"):
        await identify_binaries("bin/httpd")


async def test_identify_binaries_llm_missing_credentials_raises_unavailable(monkeypatch):
    def raise_value_error(role):
        raise ValueError("ANTHROPIC_API_KEY is not set")

    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", raise_value_error
    )

    with pytest.raises(IdentifierUnavailableError, match="ANTHROPIC_API_KEY"):
        await identify_binaries("bin/httpd")


async def test_identify_binaries_connection_failure_raises_unavailable(monkeypatch):
    fake_llm = _fake_llm(side_effect=OSError("connection refused"))
    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", lambda role: fake_llm
    )

    with pytest.raises(IdentifierUnavailableError, match="LLM call failed"):
        await identify_binaries("bin/httpd")
