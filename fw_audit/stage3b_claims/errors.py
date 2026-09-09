"""Stage 3b's hard-failure exceptions."""

from __future__ import annotations


class Stage3bInputError(RuntimeError):
    """The PDF report could not be read, or `db_subfolder` is unusable.

    Stage 3b's primary hard-failure exception — mirrors
    `stage3_analysis.errors.Stage3InputError`'s contract. Everything past
    document extraction (segmenting, resolving a claim's binary, emitting
    a `Finding`) is per-claim isolated and reported through
    `common.claims.ClaimRecord`, never raised.
    """


class ClaimExtractionUnavailableError(RuntimeError):
    """No LLM provider is reachable for `AgentRole.STAGE3B_CLAIM_EXTRACTOR`,
    or its output never validated within the configured repair budget.

    Mirrors `stage3_analysis.agent.analyst.AnalysisUnavailableError`'s
    contract exactly — see `agent/converter.py` for which exceptions get a
    repair attempt and which don't.
    """
