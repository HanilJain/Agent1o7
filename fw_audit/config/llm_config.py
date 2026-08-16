"""Multi-provider LLM factory.

Provides a unified interface so agents can request an LLM by *role* (what the
agent is doing) rather than a hardcoded model name. Each role maps to a
*tier* (capability/cost class), and each tier maps to a concrete
:class:`ModelSpec` (provider + model name). Construction itself goes through
LangChain's own :func:`langchain.chat_models.init_chat_model` factory rather
than one hand-rolled `_build_*` function per provider — `init_chat_model`
already knows how to import and construct every provider's chat model class;
this module's job is only to resolve *which* provider/model a role should
use and to supply the credentials/base-url `init_chat_model` doesn't know
where to find (those live in `Settings`, never `os.environ` directly).

Supported providers: Ollama (local), Anthropic (Claude), Google (Gemini),
OpenAI — and anything OpenAI-API-compatible (vLLM, LM Studio) via the
"openai" provider pointed at `Settings.openai_base_url`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from fw_audit.config.settings import Settings, get_settings

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger("fw_audit.config.llm_config")


class ModelProvider(str, Enum):
    """Backing LLM provider."""

    OLLAMA = "ollama"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    OPENAI = "openai"

    @property
    def langchain_id(self) -> str:
        """The `model_provider` string `init_chat_model` expects.

        Only GOOGLE differs from its own value: LangChain splits "Google"
        into `google_genai` (AI Studio / Gemini API — what
        `GEMINI_API_KEY`/`GOOGLE_API_KEY` authenticate against) and
        `google_vertexai` (GCP-project-based auth, unused here). Every other
        member's `.value` already matches `init_chat_model`'s provider id.
        """
        if self is ModelProvider.GOOGLE:
            return "google_genai"
        return self.value


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
    STAGE3_VULN_ANALYST = "stage3_vuln_analyst"
    """Stage 3 Component 2's worker-pool agent (`stage3_analysis.agent`):
    reads one chunk of decompiled C at a time and returns a structured
    `AnalysisReport` of candidate security findings. Runs many times per
    firmware (once per chunk, across `stage3_queue_workers` parallel
    workers), unlike the Identifier Agent's single call — still routed to
    HIGH_REASONING by default because the report schema is large and
    reasoning-heavy; see ROLE_TO_TIER for the offline-testing override."""
    STAGE4_QUERY_PLANNER = "stage4_query_planner"
    """Stage 4 Component 3 (`stage4_rag.query.planner`): given one Stage 3
    finding, produces a `MultiQueryPlan` of 4-5 targeted search queries fed
    to Component 4's retrieval. No tool access."""
    STAGE4_TAINT_ANALYST = "stage4_taint_analyst"
    """Stage 4 Component 5 (`stage4_rag.taint.analyst`): reasons over
    Component 4's retrieved context + the original Stage 3 finding to build
    a structured `TaintPathReport`. No tool access."""
    STAGE5_VERIFIER = "stage5_verifier"
    """Stage 5's Joern verification agent (`stage5_verification.agent`): the
    first role in this repo with actual tool access (`build_cpg`,
    `run_joern_script`, bound via LangGraph) rather than a one-shot
    structured-output call. Routed to HIGH_REASONING by default (Claude
    Sonnet) — same reasoning as Stage 3/4's roles — but commonly overridden
    to a local Ollama model (e.g. `FWA_STAGE5_VERIFIER_MODEL=ollama:qwen3:8b`)
    for offline/cheap iteration; a weaker model just means the bounded
    `stage5_max_agent_iterations`/`stage5_repair_attempts` retries matter more."""


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
    # fallback) and its JSON output feeds Stage 2 directly — HIGH_REASONING
    # (Anthropic Claude Sonnet via the cloud API) is the production default.
    # One call per firmware makes the cost negligible relative to the
    # quality it buys. For fully-offline testing without an API key, set
    # `FWA_LLM_MODEL=ollama:qwen2.5-coder:1.5b` (see Settings.llm_model) —
    # resolve_spec() honors that override before consulting this table.
    AgentRole.STAGE1_BINARY_IDENTIFIER: ModelTier.HIGH_REASONING,
    # Same reasoning as above: the vulnerability-analysis report schema is
    # large and reasoning-heavy, so the production default is Claude
    # Sonnet. `FWA_STAGE3_ANALYST_MODEL` overrides this role specifically
    # (e.g. to a local Ollama model) without affecting other roles.
    AgentRole.STAGE3_VULN_ANALYST: ModelTier.HIGH_REASONING,
    # Stage 4's two local LLM roles (query planning, taint-path reasoning)
    # get the same HIGH_REASONING default as Stage 3's analyst — both
    # produce large, reasoning-heavy structured output. Their own
    # `FWA_STAGE4_*_MODEL` overrides (see _ROLE_OVERRIDE_SETTINGS_FIELD)
    # let either be pointed at a local Ollama model independently.
    AgentRole.STAGE4_QUERY_PLANNER: ModelTier.HIGH_REASONING,
    AgentRole.STAGE4_TAINT_ANALYST: ModelTier.HIGH_REASONING,
    # Stage 5's verification agent gets the same HIGH_REASONING default —
    # it drives real tool calls (Joern CPG queries) and a final structured
    # verdict, both reasoning-heavy. `FWA_STAGE5_VERIFIER_MODEL` overrides
    # this role specifically (e.g. to a local Ollama qwen3 model).
    AgentRole.STAGE5_VERIFIER: ModelTier.HIGH_REASONING,
}

# ---------------------------------------------------------------------- #
# Tier -> concrete ModelSpec
# ---------------------------------------------------------------------- #
TIER_TO_SPEC: dict[ModelTier, ModelSpec] = {
    # Locally installed via `ollama pull qwen2.5-coder:1.5b`. Small (1.5B)
    # but coder-tuned, and runs fully offline against OLLAMA_BASE_URL.
    # Intended for offline testing (see FWA_LLM_MODEL / per-role overrides
    # in ROLE_TO_TIER's comments above), not production analysis quality.
    #
    # No format="json" here: output-shape enforcement is done via
    # `BaseChatModel.with_structured_output(...)` at the call site, not a
    # constructor-level format kwarg or prompt prose. That method resolves
    # per-provider (Ollama's native `json_schema` structured-output API by
    # default here; tool-calling for Anthropic/Google/OpenAI), so nothing
    # provider-specific belongs in this spec.
    #
    # num_ctx/num_predict come from `Settings` (ollama_num_ctx/
    # ollama_num_predict, defaults 32768/4096) and are applied to EVERY
    # Ollama-backed spec by `_credential_kwargs`, not hardcoded per tier —
    # see that function. Rationale (confirmed against real runs):
    # Ollama's server-side default context is only 2048 tokens, which
    # silently truncates any non-trivial prompt (a real router's tree.txt
    # or a large chunk routinely exceeds 30K+ tokens) into a cut-off,
    # unparseable response rather than a clean error; num_predict guards
    # against a degenerate repetition loop this model can fall into,
    # generating 1MB+ of unusable output before Ollama cuts it off.
    ModelTier.FAST_LOCAL: ModelSpec(
        provider=ModelProvider.OLLAMA,
        model="qwen2.5-coder:1.5b",
    ),
    ModelTier.BALANCED: ModelSpec(provider=ModelProvider.OLLAMA, model="kimi-k3"),
    ModelTier.HIGH_REASONING: ModelSpec(
        provider=ModelProvider.ANTHROPIC, model="claude-sonnet-4-5"
    ),
}

# Alternate high-reasoning spec (Gemini), available for callers that prefer
# Google over Anthropic without editing the tier table.
GEMINI_HIGH_REASONING = ModelSpec(provider=ModelProvider.GOOGLE, model="gemini-2.5-flash")

# ---------------------------------------------------------------------- #
# Role -> per-role Settings override field name
# ---------------------------------------------------------------------- #
# Maps a role to the `Settings` attribute holding its own
# `"<provider>:<model>"` override (checked before the global `llm_model`
# override — see resolve_spec()). Add an entry here, not another `if`
# branch, when a new role gets its own override field.
_ROLE_OVERRIDE_SETTINGS_FIELD: dict[AgentRole, str] = {
    AgentRole.STAGE3_VULN_ANALYST: "stage3_analyst_model",
    AgentRole.STAGE4_QUERY_PLANNER: "stage4_query_planner_model",
    AgentRole.STAGE4_TAINT_ANALYST: "stage4_taint_analyst_model",
    AgentRole.STAGE5_VERIFIER: "stage5_verifier_model",
}


def _parse_model_override(value: str) -> ModelSpec:
    """Parse a `"<provider>:<model>"` override string (e.g. from
    `Settings.llm_model`/`stage3_analyst_model`) into a `ModelSpec`.

    Splits on only the FIRST `:` — Ollama model tags themselves contain a
    colon (`qwen2.5-coder:1.5b`), so `"ollama:qwen2.5-coder:1.5b"` must
    resolve to `model="qwen2.5-coder:1.5b"`, not be rejected or truncated.
    Raises `ValueError` (never a silent fallback) for a malformed string or
    an unrecognized provider — mirrors `executors.manager.get_executor()`'s
    posture on an unrecognized backend name.
    """
    if ":" not in value:
        raise ValueError(
            f"Invalid model override {value!r}: expected '<provider>:<model>', "
            f"e.g. 'anthropic:claude-sonnet-4-5' or 'ollama:qwen2.5-coder:1.5b'."
        )
    provider_str, model = value.split(":", 1)
    try:
        provider = ModelProvider(provider_str)
    except ValueError as exc:
        valid = ", ".join(p.value for p in ModelProvider)
        raise ValueError(
            f"Unknown model provider {provider_str!r} in override {value!r}. "
            f"Valid providers: {valid}."
        ) from exc
    if not model:
        raise ValueError(f"Invalid model override {value!r}: missing model name after ':'.")
    return ModelSpec(provider=provider, model=model)


def resolve_spec(
    role: AgentRole = AgentRole.DEFAULT, *, settings: Settings | None = None
) -> ModelSpec:
    """Resolve an :class:`AgentRole` to a concrete :class:`ModelSpec`.

    Override precedence, most specific first:
    1. A per-role override — see `_ROLE_OVERRIDE_SETTINGS_FIELD` for which
       `Settings` attribute backs which role (e.g.
       `Settings.stage3_analyst_model` for `STAGE3_VULN_ANALYST`).
    2. `Settings.llm_model` — a global override applied to every role.
    3. `Settings.use_local_model` picks which half of the tier table to
       prefer: the tier's own (API-backed) spec when `False` (default), or
       `ModelTier.FAST_LOCAL`'s local Ollama spec when `True`. This is only
       a *preference* — `get_llm`/`get_llm_for_agent` fall back to the
       opposite mode if the preferred one turns out to be unavailable (see
       their docstrings), so this function alone doesn't guarantee the
       returned spec is actually usable.

    `settings` defaults to the cached `get_settings()` singleton, but a
    caller holding a run-specific `Settings` (e.g. `runner.py`'s
    `--model`/`--chunk-lines`-style `settings.model_copy(update={...})`
    overrides) MUST pass it explicitly — the singleton never reflects a
    CLI override made via `model_copy`, only real env vars.
    """
    settings = settings or get_settings()

    override_field = _ROLE_OVERRIDE_SETTINGS_FIELD.get(role)
    if override_field:
        override_value = getattr(settings, override_field, None)
        if override_value:
            return _parse_model_override(override_value)
    if settings.llm_model:
        return _parse_model_override(settings.llm_model)

    tier = ROLE_TO_TIER.get(role, ModelTier.BALANCED)
    if settings.use_local_model:
        return TIER_TO_SPEC[ModelTier.FAST_LOCAL]
    return TIER_TO_SPEC[tier]


def _fallback_spec(spec: ModelSpec, *, settings: Settings) -> ModelSpec | None:
    """The opposite-mode spec to retry with if `spec` turns out to be
    unavailable (missing credential/SDK) — API-backed <-> local Ollama.

    Returns `None` if `spec` is already the local Ollama spec (there's
    nothing "more local" to fall back to) or if the opposite spec would be
    identical to `spec` (nothing gained by "falling back" to itself).
    """
    if spec.provider is ModelProvider.OLLAMA:
        return None
    fallback = TIER_TO_SPEC[ModelTier.FAST_LOCAL]
    if fallback == spec:
        return None
    return fallback


def _try_credential_kwargs(
    provider: ModelProvider, settings: Settings
) -> tuple[dict[str, Any] | None, str | None]:
    """Like `_credential_kwargs`, but returns `(None, reason)` instead of
    raising when the provider is unavailable — used by `get_llm`'s
    local/API fallback so a missing credential can be tried against the
    other mode instead of failing outright."""
    try:
        return _credential_kwargs(provider, settings), None
    except ValueError as exc:
        return None, str(exc)


def _credential_kwargs(provider: ModelProvider, settings: Settings) -> dict[str, Any]:
    """Provider-specific constructor kwargs `init_chat_model` can't infer on
    its own: API keys/base URLs pulled from `Settings` (never `os.environ`
    directly, per this project's config convention), plus Ollama's
    context/generation-length overrides applied uniformly to every
    Ollama-backed spec (see the FAST_LOCAL comment in `TIER_TO_SPEC` for
    why those two are necessary). Raises `ValueError` with an actionable
    message for a missing credential, rather than letting `init_chat_model`
    fail deep inside the provider SDK with an opaque error.
    """
    if provider is ModelProvider.OLLAMA:
        return {
            "base_url": settings.ollama_base_url,
            "num_ctx": settings.ollama_num_ctx,
            "num_predict": settings.ollama_num_predict,
        }
    if provider is ModelProvider.ANTHROPIC:
        if not settings.anthropic_api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set. Add it to your .env or environment "
                "before requesting an Anthropic-backed model."
            )
        return {"api_key": settings.anthropic_api_key}
    if provider is ModelProvider.GOOGLE:
        if not settings.google_api_key:
            raise ValueError(
                "GOOGLE_API_KEY is not set. Add it to your .env or environment "
                "before requesting a Google-backed model."
            )
        return {"api_key": settings.google_api_key}
    if provider is ModelProvider.OPENAI:
        # base_url may be unset (real OpenAI); api_key is required either
        # way — including for local OpenAI-compatible servers that ignore
        # the key's value but still expect the header to be present.
        if not settings.openai_api_key:
            raise ValueError(
                "OPENAI_API_KEY is not set. Add it to your .env or environment "
                "before requesting an OpenAI-backed model. For a local "
                "OpenAI-compatible server (vLLM, LM Studio), any non-empty "
                "placeholder value works alongside OPENAI_BASE_URL."
            )
        kwargs: dict[str, Any] = {"api_key": settings.openai_api_key}
        if settings.openai_base_url:
            kwargs["base_url"] = settings.openai_base_url
        return kwargs
    raise ValueError(f"Unsupported model provider: {provider}")  # pragma: no cover - defensive


_PROVIDER_INSTALL_HINTS: dict[ModelProvider, str] = {
    ModelProvider.OLLAMA: "ollama",
    ModelProvider.ANTHROPIC: "anthropic",
    ModelProvider.GOOGLE: "google",
    ModelProvider.OPENAI: "openai",
}


def _pick_usable_spec(
    spec: ModelSpec, *, settings: Settings
) -> tuple[ModelSpec, dict[str, Any]]:
    """Core of the API/local fallback: try `spec` first, then its opposite
    mode (see `_fallback_spec`), returning whichever is usable along with
    its already-validated credential kwargs. Raises `ValueError` (naming
    both attempts) only when neither is usable. Shared by
    `resolve_usable_spec` (spec only, no client construction) and
    `get_llm` (which also builds the client) so the fallback policy and
    its error messages live in exactly one place.
    """
    credential_kwargs, error = _try_credential_kwargs(spec.provider, settings)
    if credential_kwargs is not None:
        return spec, credential_kwargs

    fallback = _fallback_spec(spec, settings=settings)
    if fallback is not None:
        fallback_kwargs, fallback_error = _try_credential_kwargs(
            fallback.provider, settings
        )
        if fallback_kwargs is not None:
            logger.warning(
                "Preferred model %s:%s unavailable (%s); falling back to %s:%s.",
                spec.provider.value,
                spec.model,
                error,
                fallback.provider.value,
                fallback.model,
            )
            return fallback, fallback_kwargs
        raise ValueError(
            f"No usable LLM found. Preferred {spec.provider.value}:{spec.model} "
            f"unavailable ({error}); fallback {fallback.provider.value}:"
            f"{fallback.model} also unavailable ({fallback_error}). Configure "
            f"either an API credential (e.g. ANTHROPIC_API_KEY) or a reachable "
            f"local Ollama model (OLLAMA_BASE_URL) before retrying."
        )

    raise ValueError(
        f"No usable LLM found. {spec.provider.value}:{spec.model} unavailable "
        f"({error}), and no fallback mode is available for it. Configure a "
        f"usable credential before retrying."
    )


def resolve_usable_spec(
    role: AgentRole = AgentRole.DEFAULT, *, settings: Settings | None = None
) -> ModelSpec:
    """Resolve `role` to a spec via :func:`resolve_spec`, then verify it (or
    its automatic API/local fallback — see `get_llm`'s docstring) is
    actually usable, WITHOUT constructing the chat model.

    For callers that need to fail fast on a bad configuration before doing
    any other work (e.g. `agent.orchestrator.run_analysis` checking the
    analyst model up front, before chunking a single target) without the
    cost/side-effect of building the client via `init_chat_model`. Returns
    whichever spec (preferred or fallback) is usable; raises `ValueError`
    with the same combined message `get_llm` would raise if neither is.
    """
    settings = settings or get_settings()
    spec = resolve_spec(role, settings=settings)
    usable_spec, _ = _pick_usable_spec(spec, settings=settings)
    return usable_spec


def _build_from_spec(spec: ModelSpec, credential_kwargs: dict[str, Any]) -> "BaseChatModel":
    """Shared `init_chat_model` call, factored out so `get_llm`'s
    preferred/fallback attempts don't duplicate the try/except ImportError
    handling."""
    from langchain.chat_models import init_chat_model

    try:
        return init_chat_model(
            model=spec.model,
            model_provider=spec.provider.langchain_id,
            temperature=spec.temperature,
            **credential_kwargs,
            **spec.kwargs,
        )
    except ImportError as exc:
        hint = _PROVIDER_INSTALL_HINTS.get(spec.provider, spec.provider.value)
        raise ImportError(
            f"The integration package for provider {spec.provider.value!r} is not "
            f'installed. Install it with: pip install "fw-audit[{hint}]"'
        ) from exc


def get_llm(
    spec_or_role: ModelSpec | AgentRole = AgentRole.DEFAULT,
    *,
    settings: Settings | None = None,
) -> "BaseChatModel":
    """Build a chat model from a :class:`ModelSpec` or :class:`AgentRole`.

    Passing an :class:`AgentRole` resolves it to a spec via :func:`resolve_spec`
    first (see that function's docstring on why `settings` should be passed
    explicitly by any caller holding a run-specific `Settings`) — that spec
    reflects `Settings.use_local_model`'s API-vs-local preference.

    Fallback: if the preferred spec's credential is missing, this
    automatically retries with the OPPOSITE mode (API-backed <-> local
    Ollama) rather than failing immediately — e.g. `use_local_model=False`
    (API preferred) but no `ANTHROPIC_API_KEY` set falls back to the local
    Ollama spec; `use_local_model=True` (local preferred) but Ollama is
    unreachable falls back to the API spec if a credential for it exists.
    Only when NEITHER mode is usable does this raise `ValueError`, naming
    both failures. An explicit `ModelSpec` passed directly (not via a role)
    is tried as-is with the same fallback behavior.

    Construction itself is delegated to `langchain.chat_models.init_chat_model`,
    which lazily imports the matching provider integration package — a missing
    SDK surfaces as `init_chat_model`'s own `ImportError`, which already names
    the missing package.
    """
    settings = settings or get_settings()
    spec = (
        spec_or_role
        if isinstance(spec_or_role, ModelSpec)
        else resolve_spec(spec_or_role, settings=settings)
    )

    usable_spec, credential_kwargs = _pick_usable_spec(spec, settings=settings)
    return _build_from_spec(usable_spec, credential_kwargs)


def get_llm_for_agent(
    role: AgentRole, *, settings: Settings | None = None
) -> "BaseChatModel":
    """Convenience wrapper: resolve `role` to a spec, then build the model.

    `settings` defaults to the cached singleton — see `resolve_spec`'s
    docstring for when a caller must pass its own instead.
    """
    settings = settings or get_settings()
    return get_llm(resolve_spec(role, settings=settings), settings=settings)
