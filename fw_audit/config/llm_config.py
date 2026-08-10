"""Multi-provider LLM factory.

Provides a unified interface so agents can request an LLM by *role* (what the
agent is doing) rather than a hardcoded model name. Each role maps to a
*tier* (capability/cost class), and each tier maps to a concrete
:class:`ModelSpec` (provider + model name). Provider SDKs are imported
lazily so a missing optional dependency only breaks the providers that need
it, not the whole application.

Supported providers: Ollama (local), Anthropic (Claude), Google (Gemini).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from fw_audit.config.settings import get_settings

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel


class ModelProvider(str, Enum):
    """Backing LLM provider."""

    OLLAMA = "ollama"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"


class ModelTier(str, Enum):
    """Capability/cost class an agent can request instead of a raw model name."""

    FAST_LOCAL = "fast_local"
    BALANCED = "balanced"
    HIGH_REASONING = "high_reasoning"


class AgentRole(str, Enum):
    """Semantic role an agent is performing.

    Each role resolves to a :class:`ModelTier` via :data:`ROLE_TO_TIER`. New
    stages should add their roles here rather than requesting a tier
    directly, so tier assignments stay centralized and tunable.
    """

    DEFAULT = "default"
    STAGE1_BINARY_IDENTIFIER = "stage1_binary_identifier"
    """The Stage 1 Identifier Agent — the sole judge of which binaries are
    worth deeper analysis. Required (hard-fail if unreachable), one call per
    firmware, so HIGH_REASONING is worth the cost (see ROLE_TO_TIER)."""


@dataclass(frozen=True)
class ModelSpec:
    """A concrete, resolved model configuration."""

    provider: ModelProvider
    model: str
    temperature: float = 0.0
    kwargs: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------- #
# Role -> Tier routing
# ---------------------------------------------------------------------- #
ROLE_TO_TIER: dict[AgentRole, ModelTier] = {
    AgentRole.DEFAULT: ModelTier.BALANCED,
    # The Identifier Agent IS the identification step (no deterministic
    # fallback) and its JSON output feeds Stage 2 directly, so HIGH_REASONING
    # (cloud) is preferred when a provider key is configured — one call per
    # firmware makes the cost negligible relative to the quality it buys.
    # Routed to FAST_LOCAL here because this dev environment has no cloud
    # API key configured, only a local Ollama install (qwen2.5-coder:1.5b).
    # Flip back to ModelTier.HIGH_REASONING once ANTHROPIC_API_KEY (or
    # GOOGLE_API_KEY) is set, for better accuracy on the untrusted-path-list
    # judgment call Stage 2 depends on.
    AgentRole.STAGE1_BINARY_IDENTIFIER: ModelTier.FAST_LOCAL,
}

# ---------------------------------------------------------------------- #
# Tier -> concrete ModelSpec
# ---------------------------------------------------------------------- #
TIER_TO_SPEC: dict[ModelTier, ModelSpec] = {
    # Locally installed via `ollama pull qwen2.5-coder:1.5b`. Small (1.5B)
    # but coder-tuned, and runs fully offline against OLLAMA_BASE_URL.
    #
    # No format="json" here: output-shape enforcement is done via
    # `BaseChatModel.with_structured_output(...)` at the call site
    # (`identifier/agent.py`), not a constructor-level format kwarg or
    # prompt prose. That method resolves per-provider (Ollama's native
    # `json_schema` structured-output API by default here; tool-calling for
    # Anthropic/Google), so nothing provider-specific belongs in this spec.
    #
    # num_ctx=32768: Ollama's server-side default context window is only
    # 2048 tokens — confirmed against a real run that this silently
    # truncates the Identifier Agent's prompt for any non-trivial firmware
    # (a real router rootfs's tree.txt is routinely 150K+ chars / 30-40K+
    # tokens), producing a cut-off, unparseable JSON response rather than a
    # clean error. 32768 is qwen2.5-coder:1.5b's own trained context limit
    # (raising it further wouldn't help — the model can't use it). Even at
    # 32768 an unusually large tree.txt can still exceed the model's
    # window; see AgentRole.STAGE1_BINARY_IDENTIFIER's docstring — this is
    # exactly the kind of accuracy tradeoff HIGH_REASONING (a cloud model
    # with a much larger context) is meant to remove once a key is set.
    #
    # num_predict=4096: a hard cap on generation length. Confirmed
    # necessary against a real (large, repetitive) firmware tree: without
    # it, this model can fall into a degenerate repetition loop and
    # generate 1MB+ of output before Ollama cuts it off mid-token — several
    # minutes spent producing something `agent.py` was always going to
    # reject as unparseable anyway. 4096 tokens is generous for the
    # expected shape of the response (a JSON list of short path/reason
    # pairs) and turns that failure mode into a fast, clean one instead.
    ModelTier.FAST_LOCAL: ModelSpec(
        provider=ModelProvider.OLLAMA,
        model="qwen2.5-coder:1.5b",
        kwargs={"num_ctx": 32768, "num_predict": 4096},
    ),
    ModelTier.BALANCED: ModelSpec(provider=ModelProvider.OLLAMA, model="kimi-k3"),
    ModelTier.HIGH_REASONING: ModelSpec(
        provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5"
    ),
}

# Alternate high-reasoning spec (Gemini), available for callers that prefer
# Google over Anthropic without editing the tier table.
GEMINI_HIGH_REASONING = ModelSpec(provider=ModelProvider.GOOGLE, model="gemini-2.5-flash")


def resolve_spec(role: AgentRole = AgentRole.DEFAULT) -> ModelSpec:
    """Resolve an :class:`AgentRole` to a concrete :class:`ModelSpec`."""
    tier = ROLE_TO_TIER.get(role, ModelTier.BALANCED)
    return TIER_TO_SPEC[tier]


def _build_ollama(spec: ModelSpec) -> "BaseChatModel":
    try:
        from langchain_ollama import ChatOllama
    except ImportError as exc:  # pragma: no cover - exercised only if SDK missing
        raise ImportError(
            "langchain-ollama is required for Ollama models. "
            'Install it with: pip install "fw-audit[ollama]"'
        ) from exc

    settings = get_settings()
    return ChatOllama(
        model=spec.model,
        base_url=settings.ollama_base_url,
        temperature=spec.temperature,
        **spec.kwargs,
    )


def _build_anthropic(spec: ModelSpec) -> "BaseChatModel":
    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError as exc:  # pragma: no cover - exercised only if SDK missing
        raise ImportError(
            "langchain-anthropic is required for Anthropic models. "
            'Install it with: pip install "fw-audit[anthropic]"'
        ) from exc

    settings = get_settings()
    if not settings.anthropic_api_key:
        raise ValueError(
            "ANTHROPIC_API_KEY is not set. Add it to your .env or environment "
            "before requesting an Anthropic-backed model."
        )
    return ChatAnthropic(
        model=spec.model,
        api_key=settings.anthropic_api_key,
        temperature=spec.temperature,
        **spec.kwargs,
    )


def _build_google(spec: ModelSpec) -> "BaseChatModel":
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
    except ImportError as exc:  # pragma: no cover - exercised only if SDK missing
        raise ImportError(
            "langchain-google-genai is required for Google models. "
            'Install it with: pip install "fw-audit[google]"'
        ) from exc

    settings = get_settings()
    if not settings.google_api_key:
        raise ValueError(
            "GOOGLE_API_KEY is not set. Add it to your .env or environment "
            "before requesting a Google-backed model."
        )
    return ChatGoogleGenerativeAI(
        model=spec.model,
        google_api_key=settings.google_api_key,
        temperature=spec.temperature,
        **spec.kwargs,
    )


_PROVIDER_BUILDERS = {
    ModelProvider.OLLAMA: _build_ollama,
    ModelProvider.ANTHROPIC: _build_anthropic,
    ModelProvider.GOOGLE: _build_google,
}


def get_llm(spec_or_role: ModelSpec | AgentRole = AgentRole.DEFAULT) -> "BaseChatModel":
    """Build a chat model from a :class:`ModelSpec` or :class:`AgentRole`.

    Passing an :class:`AgentRole` resolves it to a spec via :func:`resolve_spec`
    first. Provider SDKs are imported lazily; a missing SDK or credential
    raises a clear, actionable error rather than an opaque import failure.
    """
    spec = spec_or_role if isinstance(spec_or_role, ModelSpec) else resolve_spec(spec_or_role)
    builder = _PROVIDER_BUILDERS.get(spec.provider)
    if builder is None:  # pragma: no cover - defensive, all enum members covered
        raise ValueError(f"Unsupported model provider: {spec.provider}")
    return builder(spec)


def get_llm_for_agent(role: AgentRole) -> "BaseChatModel":
    """Convenience wrapper: resolve `role` to a spec, then build the model."""
    return get_llm(resolve_spec(role))
