"""Lazy `tree-sitter-c` parser factory.

`tree-sitter`/`tree-sitter-c` are an optional extra (`pip install -e
".[stage3]"`), not a core dependency — this module must import cleanly
without them installed; only calling `get_parser()` requires them, mirroring
`fw_audit.config.llm_config`'s per-provider lazy-import convention.
"""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING

from fw_audit.stage3_analysis.errors import Stage3InputError

if TYPE_CHECKING:
    import tree_sitter


@functools.lru_cache(maxsize=1)
def get_parser() -> tree_sitter.Parser:
    """Return a `tree-sitter-c` `Parser`, built once per process.

    Raises `Stage3InputError` (not caught here — callers decide whether a
    missing optional dependency is fatal or something to degrade around;
    `ingest.py`'s `--debug` cleaned-dump path treats it as the latter) with
    an actionable install command when the extra isn't installed.

    `lru_cache` does not cache exceptions, so a failed call here doesn't
    poison later ones — if the extra gets installed mid-process (unusual,
    but free to support), the next call succeeds normally.
    """
    try:
        import tree_sitter
        import tree_sitter_c
    except ImportError as exc:
        raise Stage3InputError(
            'tree-sitter/tree-sitter-c not installed. Install with: pip install -e ".[stage3]"'
        ) from exc
    return tree_sitter.Parser(tree_sitter.Language(tree_sitter_c.language()))
