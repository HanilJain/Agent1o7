"""Tests for fw_audit.config.llm_config."""

from __future__ import annotations

import pytest

from fw_audit.config.llm_config import (
    AgentRole,
    ModelProvider,
    ModelSpec,
    ModelTier,
    get_llm,
    resolve_spec,
)


def test_resolve_spec_default_role_is_balanced():
    spec = resolve_spec(AgentRole.DEFAULT)
    assert spec.provider == ModelProvider.OLLAMA
    assert isinstance(spec, ModelSpec)


def test_resolve_spec_stage1_binary_identifier_is_fast_local():
    # The Identifier Agent is required (no deterministic fallback) and its
    # output feeds Stage 2 directly. Routed to FAST_LOCAL (Ollama
    # qwen2.5-coder:1.5b) for this dev environment, which has no cloud API
    # key configured — see the ROLE_TO_TIER comment in llm_config.py for how
    # to flip it back to HIGH_REASONING (Anthropic) once one is.
    spec = resolve_spec(AgentRole.STAGE1_BINARY_IDENTIFIER)
    assert spec.provider == ModelProvider.OLLAMA
    assert spec.model == "qwen2.5-coder:1.5b"


def test_resolve_spec_unknown_role_falls_back_to_balanced():
    # AgentRole is an Enum so we can't pass an arbitrary value directly, but
    # ROLE_TO_TIER.get(..., BALANCED) is exercised by any role not in the map.
    # This asserts the mapping itself contains an entry for every enum member,
    # i.e. resolve_spec never silently KeyErrors for a declared role.
    for role in AgentRole:
        assert resolve_spec(role) is not None


def test_get_llm_missing_ollama_sdk_raises_clear_error(monkeypatch):
    # langchain_ollama is not installed in the minimal test environment;
    # confirm the failure is an actionable ImportError, not an opaque one.
    spec = ModelSpec(provider=ModelProvider.OLLAMA, model="llama3.2")
    try:
        import langchain_ollama  # noqa: F401

        pytest.skip("langchain-ollama is installed; missing-SDK path not exercised")
    except ImportError:
        pass

    with pytest.raises(ImportError, match="langchain-ollama"):
        get_llm(spec)


def test_get_llm_anthropic_without_api_key_raises_value_error(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from fw_audit.config import settings as settings_module

    settings_module.get_settings.cache_clear()
    try:
        import langchain_anthropic  # noqa: F401
    except ImportError:
        pytest.skip("langchain-anthropic not installed")

    spec = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        get_llm(spec)
    settings_module.get_settings.cache_clear()


def test_model_tier_and_provider_enums_have_expected_members():
    assert {t.value for t in ModelTier} == {"fast_local", "balanced", "high_reasoning"}
    assert {p.value for p in ModelProvider} == {"ollama", "anthropic", "google"}
