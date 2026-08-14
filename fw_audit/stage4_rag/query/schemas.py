"""Component 3's structured-output contract.

The Pydantic model passed to `BaseChatModel.with_structured_output(...)` in
`planner.py`, and the on-disk shape of `stage4/queries/<gid>.json`. Every
field carries a `Field(description=...)` — schema-is-the-prompt convention,
see `common.findings`'s module docstring for the rationale this follows.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class SearchQuery(BaseModel):
    """One targeted search query for Component 4's vector retrieval."""

    query_text: str = Field(
        description="A natural-language or code-fragment search query, phrased to retrieve "
        "firmware source/config text semantically relevant to tracing this finding's "
        "source. E.g. 'nvram_get admin_password web login handler'."
    )
    focus: str = Field(
        description="What this query is trying to find, e.g. 'caller_context', "
        "'global_definition', 'config_key_origin', 'http_param_binding', "
        "'related_sink_usage'. Free-form, not a closed enum — the analyst decides "
        "what's worth searching for per finding."
    )


class MultiQueryPlan(BaseModel):
    """Component 3's full structured output for one Stage 3 finding."""

    finding_id: str = Field(
        description="The global finding id this plan targets, '<chunk_id>::<finding_id>' "
        "— copied from the input, never invented."
    )
    queries: list[SearchQuery] = Field(
        description="4-5 targeted search queries, each with a distinct focus, together covering "
        "the plausible sources/context this finding's sink might need to be resolved."
    )
