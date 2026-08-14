"""Stage 4's hard-failure exceptions.

Same discipline as `stage3_analysis.errors.Stage3InputError`: these are
raised only when a required hand-off cannot be loaded at all. Per-finding
or per-chunk problems past that point are recorded (skipped/failed) rather
than raised — see `driver.py` once it lands (C6-M1).
"""

from __future__ import annotations


class Stage4InputError(RuntimeError):
    """Stage 3's findings could not be located, or the local Chroma
    collection (downloaded from the Colab-built corpus) could not be
    loaded/opened.

    Stage 4's hard-failure exception for missing hand-offs — mirrors
    `stage3_analysis.errors.Stage3InputError`'s exact contract one stage
    over.
    """


class VectorStoreUnavailableError(RuntimeError):
    """No local Chroma collection is present under
    `Settings.stage4_chroma_path` (or the configured path doesn't look
    like a valid persisted Chroma directory).

    Raised by C4 (`retrieval/store.py`) before any query embedding is
    attempted — mirrors Stage 3's `AnalystModelUnavailableError` "fail
    fast on a missing precondition, before doing any per-item work"
    pattern.
    """
