"""Stage 4 Component 4 — retrieval engine (local).

v1 is deliberately basic: embed each Component 3 query with the same Qwen3
model used to build the corpus, run a plain top-k similarity search per
query against the local Chroma collection, merge/dedupe by chunk id. No
hybrid symbol-index or call-graph fusion — see `MASTERPLAN_STAGE4.md` §14.
"""

from __future__ import annotations
