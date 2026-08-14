"""Tests for `fw_audit.stage4_rag.query.schemas`."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from fw_audit.stage4_rag.query.schemas import MultiQueryPlan, SearchQuery


def test_search_query_requires_text_and_focus():
    q = SearchQuery(query_text="nvram_get admin_password", focus="config_key_origin")
    assert q.query_text == "nvram_get admin_password"
    assert q.focus == "config_key_origin"


def test_multi_query_plan_round_trips_json():
    plan = MultiQueryPlan(
        finding_id="bin#0000::c1",
        queries=[
            SearchQuery(query_text="q1", focus="f1"),
            SearchQuery(query_text="q2", focus="f2"),
        ],
    )
    restored = MultiQueryPlan.model_validate_json(plan.model_dump_json())
    assert restored == plan


def test_multi_query_plan_missing_queries_field_raises():
    with pytest.raises(ValidationError):
        MultiQueryPlan.model_validate({"finding_id": "x"})
