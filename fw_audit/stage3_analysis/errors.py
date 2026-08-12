"""Stage 3's single hard-failure exception."""

from __future__ import annotations


class Stage3InputError(RuntimeError):
    """Stage 2's hand-off could not be loaded, or the decompiled mirror tree
    could not be located.

    Stage 3's ONLY hard-failure exception — everything past this point
    (matching a whitelisted binary to its mirror file, reading that file,
    cleaning it) is per-binary isolated and reported through
    `IngestionReport`/`SkippedTarget`, never raised. This mirrors
    `stage2_extraction.stage1_io.Stage2InputError`'s exact contract one
    stage over.
    """
