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
from fw_audit.config.settings import Settings


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
    assert {p.value for p in ModelProvider} == {
        "ollama",
        "anthropic",
        "google",
        "openai",
        "opencode_go",
    }


def test_agent_role_has_stage3_vuln_analyst_member():
    assert AgentRole.STAGE3_VULN_ANALYST.value == "stage3_vuln_analyst"


def test_agent_role_has_stage3b_claim_extractor_member():
    assert AgentRole.STAGE3B_CLAIM_EXTRACTOR.value == "stage3b_claim_extractor"


def test_resolve_spec_stage3b_claim_extractor_is_balanced_not_high_reasoning():
    """Confirmed project requirement: Stage 3b must stay cheap — the ONE
    exception to this table's HIGH_REASONING-by-default pattern."""
    from fw_audit.config.llm_config import ROLE_TO_TIER, ModelTier

    assert ROLE_TO_TIER[AgentRole.STAGE3B_CLAIM_EXTRACTOR] == ModelTier.BALANCED


def test_resolve_spec_stage3b_extractor_model_override(monkeypatch):
    monkeypatch.setenv("FWA_STAGE3B_EXTRACTOR_MODEL", "ollama:qwen2.5-coder:1.5b")
    _clear_settings_cache()
    try:
        spec = resolve_spec(AgentRole.STAGE3B_CLAIM_EXTRACTOR)
        assert spec.provider == ModelProvider.OLLAMA
        assert spec.model == "qwen2.5-coder:1.5b"
    finally:
        monkeypatch.delenv("FWA_STAGE3B_EXTRACTOR_MODEL", raising=False)
        _clear_settings_cache()


def test_model_provider_langchain_id_maps_opencode_go_to_openai():
    # OpenCode Go (https://opencode.ai/docs/go/) is mechanically an
    # OpenAI-compatible endpoint, just with its own API key/base_url — it
    # resolves through init_chat_model's "openai" id, not a custom class.
    assert ModelProvider.OPENCODE_GO.langchain_id == "openai"


def test_parse_model_override_opencode_go_uses_bare_model_id():
    # Confirmed against a real account's GET /v1/models response: OpenCode
    # Go's own endpoint expects BARE model ids ("kimi-k3"), not the
    # "opencode-go/<model-id>" form OpenCode's general docs use elsewhere —
    # that prefixed form 401s ("Model opencode-go/<id> is not supported").
    spec = _parse_model_override("opencode_go:kimi-k3")
    assert spec.provider == ModelProvider.OPENCODE_GO
    assert spec.model == "kimi-k3"


def test_resolve_spec_stage1_identifier_model_override(monkeypatch):
    monkeypatch.setenv("FWA_STAGE1_IDENTIFIER_MODEL", "opencode_go:kimi-k3")
    _clear_settings_cache()
    try:
        spec = resolve_spec(AgentRole.STAGE1_BINARY_IDENTIFIER)
        assert spec.provider == ModelProvider.OPENCODE_GO
        assert spec.model == "kimi-k3"

        # Other roles are unaffected by this role-specific override.
        analyst_spec = resolve_spec(AgentRole.STAGE3_VULN_ANALYST)
        assert analyst_spec.provider == ModelProvider.ANTHROPIC
    finally:
        _clear_settings_cache()


def test_credential_kwargs_opencode_go_requires_api_key():
    from fw_audit.config.llm_config import _credential_kwargs

    with pytest.raises(ValueError, match="FWA_OPENCODE_API_KEY"):
        _credential_kwargs(ModelProvider.OPENCODE_GO, Settings(opencode_api_key=None))


def test_credential_kwargs_opencode_go_returns_key_and_base_url():
    from fw_audit.config.llm_config import _credential_kwargs

    kwargs = _credential_kwargs(
        ModelProvider.OPENCODE_GO, Settings(opencode_api_key="test-key")
    )
    assert kwargs["api_key"] == "test-key"
    assert kwargs["base_url"] == "https://opencode.ai/zen/go/v1"
    # OpenCode Go 400s ("MissingSessionID") without this header on every
    # request — see the long comment in _credential_kwargs.
    assert "x-opencode-session" in kwargs["default_headers"]
    assert kwargs["default_headers"]["x-opencode-session"]


def test_credential_kwargs_opencode_go_generates_a_fresh_session_id_each_call():
    from fw_audit.config.llm_config import _credential_kwargs

    settings = Settings(opencode_api_key="test-key")
    first = _credential_kwargs(ModelProvider.OPENCODE_GO, settings)
    second = _credential_kwargs(ModelProvider.OPENCODE_GO, settings)
    assert (
        first["default_headers"]["x-opencode-session"]
        != second["default_headers"]["x-opencode-session"]
    )


def test_get_llm_opencode_go_builds_chat_openai_via_init_chat_model():
    # No custom chat-model class: OPENCODE_GO must flow through the normal
    # init_chat_model("openai", ...) path, getting native tool-calling/
    # with_structured_output support for free.
    pytest.importorskip("langchain_openai")
    spec = ModelSpec(provider=ModelProvider.OPENCODE_GO, model="kimi-k3")
    llm = get_llm(spec, settings=Settings(opencode_api_key="test-key"))
    assert type(llm).__name__ == "ChatOpenAI"
    assert llm.model_name == "kimi-k3"
    assert llm.openai_api_base == "https://opencode.ai/zen/go/v1"
    assert "x-opencode-session" in llm.default_headers


# ---------------------------------------------------------------------- #
# Token usage tracking / rate limiting attachment (_build_from_spec)
# ---------------------------------------------------------------------- #


def test_build_from_spec_attaches_usage_tracking_callback_by_default():
    from fw_audit.observability.usage import UsageTrackingCallbackHandler

    pytest.importorskip("langchain_ollama")
    spec = ModelSpec(provider=ModelProvider.OLLAMA, model="qwen2.5-coder:1.5b")
    settings = Settings(_env_file=None)
    llm = get_llm(spec, settings=settings)
    assert llm.callbacks is not None
    handlers = [h for h in llm.callbacks if isinstance(h, UsageTrackingCallbackHandler)]
    assert len(handlers) == 1


def test_build_from_spec_callback_carries_the_resolved_role():
    from fw_audit.observability.usage import UsageTrackingCallbackHandler

    pytest.importorskip("langchain_ollama")
    settings = Settings(_env_file=None, use_local_model=True)
    llm = get_llm(AgentRole.STAGE3_VULN_ANALYST, settings=settings)
    handler = next(h for h in llm.callbacks if isinstance(h, UsageTrackingCallbackHandler))
    assert handler._role == "stage3_vuln_analyst"


def test_build_from_spec_omits_callbacks_when_usage_tracking_disabled():
    pytest.importorskip("langchain_ollama")
    spec = ModelSpec(provider=ModelProvider.OLLAMA, model="qwen2.5-coder:1.5b")
    settings = Settings(_env_file=None, llm_usage_tracking=False)
    llm = get_llm(spec, settings=settings)
    assert not llm.callbacks


def test_build_from_spec_omits_rate_limiter_when_rps_zero():
    pytest.importorskip("langchain_ollama")
    spec = ModelSpec(provider=ModelProvider.OLLAMA, model="qwen2.5-coder:1.5b")
    settings = Settings(_env_file=None, llm_rate_limit_rps=0.0)
    llm = get_llm(spec, settings=settings)
    assert llm.rate_limiter is None


def test_build_from_spec_attaches_shared_rate_limiter_across_two_get_llm_calls():
    from fw_audit.config.rate_limits import reset_rate_limiters

    pytest.importorskip("langchain_ollama")
    reset_rate_limiters()
    try:
        spec = ModelSpec(provider=ModelProvider.OLLAMA, model="qwen2.5-coder:1.5b")
        settings = Settings(_env_file=None, llm_rate_limit_rps=2.0)
        llm1 = get_llm(spec, settings=settings)
        llm2 = get_llm(spec, settings=settings)
        assert llm1.rate_limiter is not None
        assert llm1.rate_limiter is llm2.rate_limiter
    finally:
        reset_rate_limiters()


def test_build_from_spec_tags_and_metadata_still_set_alongside_new_kwargs():
    # Regression guard: the new callbacks/rate_limiter kwargs must not
    # displace the existing tags/metadata identity stamping.
    pytest.importorskip("langchain_ollama")
    settings = Settings(_env_file=None, use_local_model=True)
    llm = get_llm(AgentRole.STAGE3_VULN_ANALYST, settings=settings)
    assert llm.tags == ["role:stage3_vuln_analyst"]
    assert llm.metadata["role"] == "stage3_vuln_analyst"
