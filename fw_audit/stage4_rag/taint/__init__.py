"""Stage 4 Component 5 — taint path analyzer (local, no tool access).

Reasons over Component 4's retrieved context + the original Stage 3 finding
to build a structured `TaintPathReport` (`common.taint`). Hand-off data for
pipeline Stage 6 (Reporting) — this component does not synthesize a final
audit report itself.
"""

from __future__ import annotations
