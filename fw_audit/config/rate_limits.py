"""Shared request-rate limiters for LLM calls.

Lives in `config/`, not `observability/`, deliberately: this is CONSTRUCTION
policy consumed by `llm_config._build_from_spec` (which model instance gets
which limiter), not an observability/tracing concern — the same reason
`llm_config.py` itself sits in `config/`.

The one thing that makes this non-trivial: models in this repo are NOT
cached and reused. `fvvw/graph.py` builds 4 model objects per candidate
(strategy/generator/evaluator/report roles), `stage5_verification/agent/
verifier.py` builds 2 per candidate, and Stage 3/3b/4 each build one per
unit of work across their own worker pool. A rate limiter constructed
FRESH inside `_build_from_spec` for each of those would enforce nothing —
4 independent token buckets don't add up to one shared budget. So this
module keeps a process-level registry keyed by provider (by default) and
hands back the SAME `BaseRateLimiter` instance to every caller resolving
to the same key, exactly the sharing a real API-side rate limit needs.

Default scope is per-PROVIDER, not per-model or per-role, because that is
what actually matches a real vendor quota: Anthropic's rate limit is an
org-level budget across every Claude model called with that API key, not
a separate budget per model or per `AgentRole` — a per-role limiter would
let Stage 3's analyst and Stage 5's evaluator each burn a full quota
against the same underlying account limit.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from langchain_core.rate_limiters import BaseRateLimiter, InMemoryRateLimiter

if TYPE_CHECKING:
    from fw_audit.config.llm_config import AgentRole, ModelSpec
    from fw_audit.config.settings import Settings

_limiters: dict[str, BaseRateLimiter] = {}
_limiters_lock = threading.Lock()


def limiter_key(spec: ModelSpec, *, role: AgentRole | None, settings: Settings) -> str:
    """The registry key for `spec`/`role` under `settings.llm_rate_limit_scope`
    (`"provider"` (default) | `"model"` | `"role"`). An unrecognized scope
    value falls back to `"provider"` rather than raising — a typo'd env var
    should degrade to the safe default, not break every LLM call."""
    scope = settings.llm_rate_limit_scope
    if scope == "model":
        return f"model:{spec.provider.value}:{spec.model}"
    if scope == "role" and role is not None:
        return f"role:{role.value}"
    return f"provider:{spec.provider.value}"


def _resolve_rps(spec: ModelSpec, *, settings: Settings) -> float:
    per_provider = settings.llm_rate_limit_rps_by_provider.get(spec.provider.value)
    if per_provider is not None:
        return per_provider
    return settings.llm_rate_limit_rps


def get_rate_limiter(
    spec: ModelSpec, *, role: AgentRole | None, settings: Settings
) -> BaseRateLimiter | None:
    """Return the SHARED rate limiter for `spec`/`role`'s key, creating it
    on first use. Returns `None` when the resolved requests-per-second is
    `<= 0` (the default — rate limiting is opt-in, see
    `Settings.llm_rate_limit_rps`'s docstring), so `_build_from_spec` can
    do `if limiter is not None: kwargs["rate_limiter"] = limiter`
    unconditionally.
    """
    rps = _resolve_rps(spec, settings=settings)
    if rps <= 0:
        return None

    key = limiter_key(spec, role=role, settings=settings)
    with _limiters_lock:
        existing = _limiters.get(key)
        if existing is not None:
            return existing
        burst = settings.llm_rate_limit_burst if settings.llm_rate_limit_burst > 0 else max(
            1.0, rps
        )
        limiter = InMemoryRateLimiter(requests_per_second=rps, max_bucket_size=burst)
        _limiters[key] = limiter
        return limiter


def reset_rate_limiters() -> None:
    """Clear the shared-limiter cache. Test-only hook — production code
    never needs to reset it (a limiter keyed by provider/model/role is
    valid for the whole process lifetime), but tests that vary
    `llm_rate_limit_*` settings across cases need a clean slate so an
    earlier test's limiter isn't silently reused."""
    with _limiters_lock:
        _limiters.clear()


__all__ = ["get_rate_limiter", "limiter_key", "reset_rate_limiters"]
