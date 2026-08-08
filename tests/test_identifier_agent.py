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

from fw_audit.common.schemas import IdentifiedBinary
from fw_audit.stage1_ingestion.identifier.agent import IdentifierUnavailableError, identify_binaries
from fw_audit.stage1_ingestion.identifier.prompts import build_prompt


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
    assert "JSON array" in prompt


async def test_identify_binaries_parses_plain_json_array(monkeypatch):
    fake_llm = SimpleNamespace(
        ainvoke=AsyncMock(
            return_value=SimpleNamespace(
                content='[{"path": "bin/httpd", "reason": "HTTP admin interface"}]'
            )
        )
    )
    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", lambda role: fake_llm
    )

    result = await identify_binaries("bin/httpd  84K  ELF ...")

    assert result == [IdentifiedBinary(path="bin/httpd", reason="HTTP admin interface")]


async def test_identify_binaries_strips_markdown_fence(monkeypatch):
    fenced = '```json\n[{"path": "sbin/hostapd", "reason": "WiFi auth daemon"}]\n```'
    fake_llm = SimpleNamespace(ainvoke=AsyncMock(return_value=SimpleNamespace(content=fenced)))
    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", lambda role: fake_llm
    )

    result = await identify_binaries("sbin/hostapd  120K  ELF ...")

    assert result[0].path == "sbin/hostapd"


async def test_identify_binaries_empty_list_is_valid(monkeypatch):
    fake_llm = SimpleNamespace(ainvoke=AsyncMock(return_value=SimpleNamespace(content="[]")))
    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", lambda role: fake_llm
    )

    result = await identify_binaries("etc/config.txt  1K")

    assert result == []


async def test_identify_binaries_malformed_json_raises_unavailable(monkeypatch):
    fake_llm = SimpleNamespace(
        ainvoke=AsyncMock(return_value=SimpleNamespace(content="not json at all"))
    )
    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", lambda role: fake_llm
    )

    with pytest.raises(IdentifierUnavailableError, match="unparseable"):
        await identify_binaries("bin/httpd")


async def test_identify_binaries_missing_required_field_raises(monkeypatch):
    fake_llm = SimpleNamespace(
        ainvoke=AsyncMock(return_value=SimpleNamespace(content='[{"path": "bin/httpd"}]'))
    )
    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", lambda role: fake_llm
    )

    with pytest.raises(IdentifierUnavailableError):
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
    fake_llm = SimpleNamespace(ainvoke=AsyncMock(side_effect=OSError("connection refused")))
    monkeypatch.setattr(
        "fw_audit.stage1_ingestion.identifier.agent.get_llm_for_agent", lambda role: fake_llm
    )

    with pytest.raises(IdentifierUnavailableError, match="LLM call failed"):
        await identify_binaries("bin/httpd")
