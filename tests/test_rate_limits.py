"""Tests for fw_audit.config.rate_limits."""

from __future__ import annotations

import pytest

from fw_audit.config.llm_config import AgentRole, ModelProvider, ModelSpec
from fw_audit.config.rate_limits import get_rate_limiter, limiter_key, reset_rate_limiters
from fw_audit.config.settings import Settings


@pytest.fixture(autouse=True)
def _reset_limiters():
    reset_rate_limiters()
    yield
    reset_rate_limiters()


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def test_get_rate_limiter_disabled_by_default_returns_none():
    settings = _settings()
    spec = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")
    assert get_rate_limiter(spec, role=AgentRole.STAGE3_VULN_ANALYST, settings=settings) is None


def test_get_rate_limiter_zero_rps_returns_none():
    settings = _settings(llm_rate_limit_rps=0.0)
    spec = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")
    assert get_rate_limiter(spec, role=None, settings=settings) is None


def test_get_rate_limiter_same_provider_shares_one_instance():
    """The whole point of the registry: two models resolving to the same
    provider must share ONE limiter, not get independent buckets — this is
    what makes rate limiting actually enforce anything when FVVW builds 4
    models per candidate."""
    settings = _settings(llm_rate_limit_rps=2.0)
    spec_a = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")
    spec_b = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-haiku-4-5")

    limiter_a = get_rate_limiter(spec_a, role=AgentRole.STAGE5_SCRIPT_GENERATOR, settings=settings)
    limiter_b = get_rate_limiter(spec_b, role=AgentRole.STAGE5_RESULT_EVALUATOR, settings=settings)

    assert limiter_a is not None
    assert limiter_a is limiter_b


def test_get_rate_limiter_different_provider_gets_different_instance():
    settings = _settings(llm_rate_limit_rps=2.0)
    spec_anthropic = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")
    spec_ollama = ModelSpec(provider=ModelProvider.OLLAMA, model="qwen2.5-coder:1.5b")

    limiter_a = get_rate_limiter(spec_anthropic, role=None, settings=settings)
    limiter_b = get_rate_limiter(spec_ollama, role=None, settings=settings)

    assert limiter_a is not limiter_b


def test_per_provider_override_beats_global_default():
    settings = _settings(
        llm_rate_limit_rps=1.0,
        llm_rate_limit_rps_by_provider={"anthropic": 5.0},
    )
    spec = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")
    limiter = get_rate_limiter(spec, role=None, settings=settings)
    assert limiter is not None
    assert limiter.requests_per_second == 5.0


def test_provider_absent_from_override_dict_falls_through_to_global():
    settings = _settings(
        llm_rate_limit_rps=1.0,
        llm_rate_limit_rps_by_provider={"anthropic": 5.0},
    )
    spec = ModelSpec(provider=ModelProvider.OLLAMA, model="qwen2.5-coder:1.5b")
    limiter = get_rate_limiter(spec, role=None, settings=settings)
    assert limiter is not None
    assert limiter.requests_per_second == 1.0


def test_scope_model_gives_different_keys_for_different_models_same_provider():
    settings = _settings(llm_rate_limit_rps=1.0, llm_rate_limit_scope="model")
    spec_a = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")
    spec_b = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-haiku-4-5")

    limiter_a = get_rate_limiter(spec_a, role=None, settings=settings)
    limiter_b = get_rate_limiter(spec_b, role=None, settings=settings)
    assert limiter_a is not limiter_b


def test_scope_role_gives_different_keys_for_different_roles():
    settings = _settings(llm_rate_limit_rps=1.0, llm_rate_limit_scope="role")
    spec = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")

    limiter_a = get_rate_limiter(spec, role=AgentRole.STAGE3_VULN_ANALYST, settings=settings)
    limiter_b = get_rate_limiter(spec, role=AgentRole.STAGE5_STRATEGY_AGENT, settings=settings)
    assert limiter_a is not limiter_b


def test_limiter_key_role_scope_falls_back_to_provider_when_role_none():
    settings = _settings(llm_rate_limit_scope="role")
    spec = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")
    key = limiter_key(spec, role=None, settings=settings)
    assert key == "provider:anthropic"


def test_reset_rate_limiters_clears_the_cache():
    settings = _settings(llm_rate_limit_rps=2.0)
    spec = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")
    limiter_before = get_rate_limiter(spec, role=None, settings=settings)
    reset_rate_limiters()
    limiter_after = get_rate_limiter(spec, role=None, settings=settings)
    assert limiter_before is not limiter_after


def test_burst_defaults_to_rps_when_unset():
    settings = _settings(llm_rate_limit_rps=3.0, llm_rate_limit_burst=0.0)
    spec = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")
    limiter = get_rate_limiter(spec, role=None, settings=settings)
    assert limiter is not None
    assert limiter.max_bucket_size == 3.0


def test_burst_explicit_value_is_used():
    settings = _settings(llm_rate_limit_rps=3.0, llm_rate_limit_burst=10.0)
    spec = ModelSpec(provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5")
    limiter = get_rate_limiter(spec, role=None, settings=settings)
    assert limiter is not None
    assert limiter.max_bucket_size == 10.0
