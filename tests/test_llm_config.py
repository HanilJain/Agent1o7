"""Tests for fw_audit.config.llm_config."""

from __future__ import annotations

import pytest

from fw_audit.config.llm_config import (
    AgentRole,
    ModelProvider,
    ModelSpec,
    ModelTier,
    _parse_model_override,
    get_llm,
    resolve_spec,
)


def _clear_settings_cache():
    from fw_audit.config import settings as settings_module

    settings_module.get_settings.cache_clear()


def test_resolve_spec_default_role_is_balanced():
    spec = resolve_spec(AgentRole.DEFAULT)
    assert spec.provider == ModelProvider.OLLAMA
    assert isinstance(spec, ModelSpec)


def test_resolve_spec_stage1_binary_identifier_is_high_reasoning():
    # The Identifier Agent is required (no deterministic fallback) and its
    # output feeds Stage 2 directly. Production default is HIGH_REASONING
    # (Anthropic Claude Sonnet) — see the ROLE_TO_TIER comment in
    # llm_config.py for the offline-testing override (FWA_LLM_MODEL).
    spec = resolve_spec(AgentRole.STAGE1_BINARY_IDENTIFIER)
    assert spec.provider == ModelProvider.ANTHROPIC
    assert spec.model == "claude-sonnet-4-5"


def test_resolve_spec_stage3_vuln_analyst_is_high_reasoning():
    spec = resolve_spec(AgentRole.STAGE3_VULN_ANALYST)
    assert spec.provider == ModelProvider.ANTHROPIC
    assert spec.model == "claude-sonnet-4-5"


def test_resolve_spec_unknown_role_falls_back_to_balanced():
    # AgentRole is an Enum so we can't pass an arbitrary value directly, but
    # ROLE_TO_TIER.get(..., BALANCED) is exercised by any role not in the map.
    # This asserts the mapping itself contains an entry for every enum member,
    # i.e. resolve_spec never silently KeyErrors for a declared role.
    for role in AgentRole:
        assert resolve_spec(role) is not None


def test_resolve_spec_global_llm_model_override(monkeypatch):
    monkeypatch.setenv("FWA_LLM_MODEL", "ollama:qwen2.5-coder:1.5b")
    _clear_settings_cache()
    try:
        spec = resolve_spec(AgentRole.STAGE1_BINARY_IDENTIFIER)
        assert spec.provider == ModelProvider.OLLAMA
        assert spec.model == "qwen2.5-coder:1.5b"
    finally:
        _clear_settings_cache()


def test_resolve_spec_per_role_override_takes_precedence_over_global(monkeypatch):
    monkeypatch.setenv("FWA_LLM_MODEL", "anthropic:claude-sonnet-4-5")
    monkeypatch.setenv("FWA_STAGE3_ANALYST_MODEL", "ollama:qwen2.5-coder:1.5b")
    _clear_settings_cache()
    try:
        # The per-role override wins for STAGE3_VULN_ANALYST specifically.
        analyst_spec = resolve_spec(AgentRole.STAGE3_VULN_ANALYST)
        assert analyst_spec.provider == ModelProvider.OLLAMA
        assert analyst_spec.model == "qwen2.5-coder:1.5b"

        # Other roles still see the global override, not the per-role one.
        identifier_spec = resolve_spec(AgentRole.STAGE1_BINARY_IDENTIFIER)
        assert identifier_spec.provider == ModelProvider.ANTHROPIC
    finally:
        _clear_settings_cache()


def test_parse_model_override_splits_on_first_colon_only():
    spec = _parse_model_override("ollama:qwen2.5-coder:1.5b")
    assert spec.provider == ModelProvider.OLLAMA
    assert spec.model == "qwen2.5-coder:1.5b"


def test_parse_model_override_unknown_provider_raises():
    with pytest.raises(ValueError, match="Unknown model provider"):
        _parse_model_override("bogus:some-model")


def test_parse_model_override_missing_colon_raises():
    with pytest.raises(ValueError, match="expected"):
        _parse_model_override("no-colon-here")


def test_parse_model_override_missing_model_name_raises():
    with pytest.raises(ValueError, match="missing model name"):
        _parse_model_override("anthropic:")


def test_model_provider_langchain_id_maps_google_to_google_genai():
    assert ModelProvider.GOOGLE.langchain_id == "google_genai"
    assert ModelProvider.ANTHROPIC.langchain_id == "anthropic"
    assert ModelProvider.OLLAMA.langchain_id == "ollama"
    assert ModelProvider.OPENAI.langchain_id == "openai"


def test_get_llm_ollama_builds_without_credentials():
    # Ollama needs no API key; confirm init_chat_model wiring produces a
    # real ChatOllama with our num_ctx/num_predict settings applied.
    pytest.importorskip("langchain_ollama")
    spec = ModelSpec(provider=ModelProvider.OLLAMA, model="qwen2.5-coder:1.5b")
    llm = get_llm(spec)
    assert type(llm).__name__ == "ChatOllama"


def test_get_llm_missing_anthropic_credential_falls_back_to_local_ollama(monkeypatch):
    # No ANTHROPIC_API_KEY: get_llm no longer fails outright — it falls back
    # to the local Ollama spec (always "available" since Ollama needs no
    # credential) rather than raising. See test_get_llm_no_fallback_when_*
    # below for the case where fallback is genuinely exhausted.
    pytest.importorskip("langchain_ollama")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _clear_settings_cache()
    try:
        spec = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")
        llm = get_llm(spec)
        assert type(llm).__name__ == "ChatOllama"
    finally:
        _clear_settings_cache()


def test_get_llm_openai_without_api_key_falls_back_to_local_ollama(monkeypatch):
    pytest.importorskip("langchain_ollama")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    _clear_settings_cache()
    try:
        spec = ModelSpec(provider=ModelProvider.OPENAI, model="gpt-4o")
        llm = get_llm(spec)
        assert type(llm).__name__ == "ChatOllama"
    finally:
        _clear_settings_cache()


def test_get_llm_google_without_api_key_falls_back_to_local_ollama(monkeypatch):
    pytest.importorskip("langchain_ollama")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    _clear_settings_cache()
    try:
        spec = ModelSpec(provider=ModelProvider.GOOGLE, model="gemini-2.5-flash")
        llm = get_llm(spec)
        assert type(llm).__name__ == "ChatOllama"
    finally:
        _clear_settings_cache()


def test_get_llm_ollama_spec_has_no_fallback_and_raises_if_unusable(monkeypatch):
    # An OLLAMA-provider spec has no "more local" fallback (_fallback_spec
    # returns None for it) — if it's ever made unusable, get_llm must raise
    # rather than loop back to itself.
    from fw_audit.config import llm_config as llm_config_module

    def _always_fail(provider, settings):
        return None, "simulated ollama failure"

    monkeypatch.setattr(llm_config_module, "_try_credential_kwargs", _always_fail)
    spec = ModelSpec(provider=ModelProvider.OLLAMA, model="qwen2.5-coder:1.5b")
    with pytest.raises(ValueError, match="No usable LLM found"):
        get_llm(spec)


def test_get_llm_raises_when_both_preferred_and_fallback_unavailable(monkeypatch):
    # Force every provider's credential check to fail so neither the
    # preferred (Anthropic) nor the fallback (Ollama) spec is usable —
    # confirms the combined-message ValueError path in _pick_usable_spec.
    from fw_audit.config import llm_config as llm_config_module

    def _always_fail(provider, settings):
        return None, f"simulated {provider.value} failure"

    monkeypatch.setattr(llm_config_module, "_try_credential_kwargs", _always_fail)
    spec = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")
    with pytest.raises(ValueError, match="No usable LLM found"):
        get_llm(spec)


def test_resolve_usable_spec_prefers_api_and_falls_back_to_local(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("FWA_STAGE3_ANALYST_MODEL", "")
    monkeypatch.setenv("FWA_LLM_MODEL", "")
    _clear_settings_cache()
    try:
        from fw_audit.config.llm_config import resolve_usable_spec

        spec = resolve_usable_spec(AgentRole.STAGE3_VULN_ANALYST)
        assert spec.provider == ModelProvider.OLLAMA
    finally:
        _clear_settings_cache()


def test_settings_use_local_model_prefers_local_tier(monkeypatch):
    monkeypatch.setenv("FWA_USE_LOCAL_MODEL", "true")
    _clear_settings_cache()
    try:
        spec = resolve_spec(AgentRole.STAGE3_VULN_ANALYST)
        assert spec.provider == ModelProvider.OLLAMA
        assert spec.model == "qwen2.5-coder:1.5b"
    finally:
        _clear_settings_cache()


def test_model_tier_and_provider_enums_have_expected_members():
    assert {t.value for t in ModelTier} == {"fast_local", "balanced", "high_reasoning"}
    assert {p.value for p in ModelProvider} == {"ollama", "anthropic", "google", "openai"}


def test_agent_role_has_stage3_vuln_analyst_member():
    assert AgentRole.STAGE3_VULN_ANALYST.value == "stage3_vuln_analyst"
