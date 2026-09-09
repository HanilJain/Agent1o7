"""Cost estimation for LLM token usage.

A small, operator-editable price table — USD per MILLION tokens, matching
how every vendor publishes pricing — plus the arithmetic to turn one call's
`usage_metadata` into an estimated dollar cost. This is deliberately
separate from `observability.usage` (which owns *counting* tokens): pricing
is a policy table that goes stale and needs editing independent of the
counting mechanism, exactly the same "genuinely different concern" split
`common/findings.py` vs `common/claims.py` already follows in this repo.

Prices are LOOKED UP, never hardcoded per call site — `lookup_price()` does
a longest-prefix match on `"<provider>:<model>"` because real model ids
carry date/version suffixes (`claude-sonnet-4-5-20250929`,
`gpt-4.1-2025-04-14`) that would all miss an exact-match table. An unknown
model returns `None` from `lookup_price`, and `estimate_cost(None, ...)`
returns `None` — NEVER `0.0` — so a report can show "cost: n/a" for models
it can't price rather than silently under-reporting spend as free. Local
Ollama models are the one deliberate exception: priced at an explicit
`ModelPrice(0, 0, 0, 0)`, so "unpriced" (`None`) and "actually free"
(`0.0`) stay distinguishable in the console/JSON output.

Prices below are approximate list prices as of MID-2025 (Claude Sonnet 4.5/
Haiku 4.5, GPT-4.1/4.1-mini, Gemini 2.5 Flash) — vendors change these
without notice, so treat this table as a rough estimate, not a billing
source of truth. Override/extend it without touching source via
`Settings.llm_price_table_path`, a JSON file merged on top of the built-in
table (same `{"<provider>:<model-prefix>": {...}}` shape as `_PRICES`
below); a malformed override file logs one warning and is ignored, never
crashes a run.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("fw_audit.observability.pricing")


@dataclass(frozen=True)
class ModelPrice:
    """USD per MILLION tokens for one model. `cache_read`/`cache_write`
    matter specifically for Anthropic prompt caching (this repo's default
    HIGH_REASONING tier): a cache read is typically ~10% of the base input
    price, a cache write (creation) ~125% — folding both into a flat
    `input` price would misprice any run that uses caching by a wide
    margin, which is most Stage 3/5 runs given their repair-loop message
    reuse."""

    input: float
    output: float
    cache_read: float = 0.0
    cache_write: float = 0.0


# ---------------------------------------------------------------------- #
# Built-in price table — USD / 1,000,000 tokens.
# ---------------------------------------------------------------------- #
# Keys are "<provider>:<model-prefix>", matched via longest-prefix in
# `lookup_price` below. Provider strings match `ModelProvider.value`
# (llm_config.py), never `ModelProvider.langchain_id`.
_PRICES: dict[str, ModelPrice] = {
    # Anthropic Claude — see AgentRole's docstrings: Sonnet is this repo's
    # HIGH_REASONING default across every stage.
    "anthropic:claude-sonnet-4": ModelPrice(
        input=3.00, output=15.00, cache_read=0.30, cache_write=3.75
    ),
    "anthropic:claude-opus-4": ModelPrice(
        input=15.00, output=75.00, cache_read=1.50, cache_write=18.75
    ),
    "anthropic:claude-haiku-4": ModelPrice(
        input=1.00, output=5.00, cache_read=0.10, cache_write=1.25
    ),
    "anthropic:claude-3-5-sonnet": ModelPrice(
        input=3.00, output=15.00, cache_read=0.30, cache_write=3.75
    ),
    "anthropic:claude-3-5-haiku": ModelPrice(
        input=0.80, output=4.00, cache_read=0.08, cache_write=1.00
    ),
    # OpenAI (also covers ModelProvider.OPENCODE_GO, which resolves through
    # init_chat_model's "openai" id — see ModelProvider.langchain_id).
    "openai:gpt-4.1": ModelPrice(input=2.00, output=8.00, cache_read=0.50),
    "openai:gpt-4.1-mini": ModelPrice(input=0.40, output=1.60, cache_read=0.10),
    "openai:gpt-4.1-nano": ModelPrice(input=0.10, output=0.40, cache_read=0.025),
    "openai:gpt-4o": ModelPrice(input=2.50, output=10.00, cache_read=1.25),
    "openai:gpt-4o-mini": ModelPrice(input=0.15, output=0.60, cache_read=0.075),
    "openai:o3": ModelPrice(input=2.00, output=8.00, cache_read=0.50),
    "openai:o4-mini": ModelPrice(input=1.10, output=4.40, cache_read=0.275),
    # Google Gemini.
    "google:gemini-2.5-pro": ModelPrice(input=1.25, output=10.00),
    "google:gemini-2.5-flash": ModelPrice(input=0.30, output=2.50),
    "google:gemini-2.0-flash": ModelPrice(input=0.10, output=0.40),
    # Ollama — always local, explicitly free (see module docstring on why
    # this is `ModelPrice(0, 0, 0, 0)` rather than simply absent).
    "ollama:": ModelPrice(input=0.0, output=0.0, cache_read=0.0, cache_write=0.0),
}

_MILLION = 1_000_000.0


def _load_override_table(path: Path) -> dict[str, ModelPrice]:
    """Parse a JSON override file into the same `{key: ModelPrice}` shape
    as `_PRICES`. Never raises — a malformed file logs one warning and
    yields an empty table, so a typo in the override never breaks a run."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("llm_price_table_path %s could not be read: %s", path, exc)
        return {}

    if not isinstance(raw, dict):
        logger.warning("llm_price_table_path %s: expected a JSON object, ignoring.", path)
        return {}

    table: dict[str, ModelPrice] = {}
    for key, value in raw.items():
        if not isinstance(value, dict):
            continue
        try:
            table[key] = ModelPrice(
                input=float(value.get("input", 0.0)),
                output=float(value.get("output", 0.0)),
                cache_read=float(value.get("cache_read", 0.0)),
                cache_write=float(value.get("cache_write", 0.0)),
            )
        except (TypeError, ValueError):
            logger.warning("llm_price_table_path %s: bad entry for %r, skipping.", path, key)
    return table


def _build_table(override_path: Path | None) -> dict[str, ModelPrice]:
    table = dict(_PRICES)
    if override_path is not None:
        table.update(_load_override_table(override_path))
    return table


def lookup_price(
    provider: str, model: str, *, override_path: Path | None = None
) -> ModelPrice | None:
    """Longest-prefix match of `"<provider>:<model>"` against the price
    table (built-ins merged with `override_path`, if given). Returns
    `None` when nothing matches — callers must treat that as "unknown",
    never as free (see module docstring)."""
    table = _build_table(override_path)
    full_key = f"{provider}:{model}"

    best_key: str | None = None
    for key in table:
        if full_key.startswith(key) and (best_key is None or len(key) > len(best_key)):
            best_key = key
    if best_key is None:
        return None
    return table[best_key]


def estimate_cost(
    price: ModelPrice | None,
    *,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
    cache_creation_tokens: int = 0,
) -> float | None:
    """Estimate USD cost for one call's usage. Returns `None` when `price`
    is `None` (unpriced model) — never `0.0`, see module docstring.

    Per LangChain's `UsageMetadata` contract, `input_tokens` is the TOTAL
    input including any `cache_read`/`cache_creation` portion — so the
    "fresh" (non-cached) input priced at the full input rate is
    `input_tokens - cache_read_tokens - cache_creation_tokens`, clamped at
    zero in case a provider reports numbers that don't add up cleanly.
    """
    if price is None:
        return None

    cache_read_tokens = max(0, cache_read_tokens)
    cache_creation_tokens = max(0, cache_creation_tokens)
    fresh_input = max(0, input_tokens - cache_read_tokens - cache_creation_tokens)

    cost = (
        fresh_input * price.input
        + output_tokens * price.output
        + cache_read_tokens * price.cache_read
        + cache_creation_tokens * price.cache_write
    ) / _MILLION
    return cost


__all__ = ["ModelPrice", "estimate_cost", "lookup_price"]
