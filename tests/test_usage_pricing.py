"""Tests for fw_audit.observability.pricing."""

from __future__ import annotations

import json

from fw_audit.observability.pricing import ModelPrice, estimate_cost, lookup_price


def test_lookup_price_longest_prefix_match_on_dated_model_id():
    # Real Anthropic model ids carry a date suffix — an exact-match table
    # would miss every one of them.
    price = lookup_price("anthropic", "claude-sonnet-4-5-20250929")
    assert price is not None
    assert price.input > 0
    assert price.output > 0


def test_lookup_price_unknown_model_returns_none_not_zero():
    price = lookup_price("anthropic", "some-model-that-does-not-exist-v99")
    assert price is None


def test_lookup_price_ollama_is_explicitly_free():
    price = lookup_price("ollama", "qwen2.5-coder:1.5b")
    assert price == ModelPrice(input=0.0, output=0.0, cache_read=0.0, cache_write=0.0)


def test_estimate_cost_none_price_returns_none_never_zero():
    cost = estimate_cost(None, input_tokens=1000, output_tokens=500)
    assert cost is None


def test_estimate_cost_prices_cache_buckets_separately_without_double_counting():
    price = ModelPrice(input=3.00, output=15.00, cache_read=0.30, cache_write=3.75)
    # input_tokens is the TOTAL including cache_read/cache_creation per
    # LangChain's UsageMetadata contract.
    cost = estimate_cost(
        price,
        input_tokens=1000,
        output_tokens=200,
        cache_read_tokens=800,
        cache_creation_tokens=100,
    )
    # fresh input = 1000 - 800 - 100 = 100
    expected = (100 * 3.00 + 200 * 15.00 + 800 * 0.30 + 100 * 3.75) / 1_000_000
    assert cost is not None
    assert abs(cost - expected) < 1e-12


def test_estimate_cost_clamps_when_cache_exceeds_input_tokens():
    # A provider reporting inconsistent numbers must never produce a
    # negative "fresh tokens" cost.
    price = ModelPrice(input=3.00, output=15.00, cache_read=0.30, cache_write=3.75)
    cost = estimate_cost(
        price,
        input_tokens=100,
        output_tokens=0,
        cache_read_tokens=500,
        cache_creation_tokens=0,
    )
    assert cost is not None
    assert cost >= 0


def test_lookup_price_override_file_merges_over_builtins(tmp_path):
    override = tmp_path / "prices.json"
    override.write_text(
        json.dumps(
            {
                "myvendor:custom-model": {
                    "input": 1.0,
                    "output": 2.0,
                    "cache_read": 0.1,
                    "cache_write": 1.5,
                }
            }
        ),
        encoding="utf-8",
    )
    price = lookup_price("myvendor", "custom-model", override_path=override)
    assert price == ModelPrice(input=1.0, output=2.0, cache_read=0.1, cache_write=1.5)

    # Built-ins are still there.
    builtin = lookup_price("ollama", "qwen2.5-coder:1.5b", override_path=override)
    assert builtin == ModelPrice(0.0, 0.0, 0.0, 0.0)


def test_lookup_price_malformed_override_file_is_ignored(tmp_path, caplog):
    override = tmp_path / "bad.json"
    override.write_text("{not valid json", encoding="utf-8")
    price = lookup_price("ollama", "qwen2.5-coder:1.5b", override_path=override)
    # Built-in table still resolves normally.
    assert price == ModelPrice(0.0, 0.0, 0.0, 0.0)


def test_lookup_price_missing_override_file_is_ignored(tmp_path):
    missing = tmp_path / "does-not-exist.json"
    price = lookup_price("anthropic", "claude-sonnet-4-5-20250929", override_path=missing)
    assert price is not None
