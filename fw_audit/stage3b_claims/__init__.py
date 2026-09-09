"""Stage 3b — External Claim Ingestion (PDF -> Stage-3-compatible findings).

Stage 3 *discovers* vulnerabilities: it runs an LLM analyst over decompiled
firmware chunks and decides for itself what looks suspicious. Stage 3b does
the mirror-image job: a third party (a pentest firm, a CVE writeup, a prior
audit) hands you a PDF report making its OWN claims about the same
firmware, and this package's only responsibility is to transcribe those
claims into `common.findings.AnalysisReport` JSON — the exact on-disk shape
Stage 3 already produces — so the EXISTING Stage 4 (RAG sink-to-source) and
Stage 5 (Joern static + QEMU/GDB dynamic fork-join) verification machinery
can check them, unchanged.

This is a PARALLEL sibling of `stage3_analysis`, not a downstream stage of
it: neither package imports the other, both write to their own directory
under `<db_subfolder>/` (`stage3/` vs `stage3b/`), and both feed Stage 4/5
independently. A firmware run can have Stage 3 findings, Stage 3b claims,
both, or neither.

Design posture — confirmed explicitly with the project owner, and the
single biggest influence on every design choice in this package: this is a
CHEAP TRANSCRIPTION task, not a reasoning task. Concretely:

* PDF extraction (`extractor.py`) and claim-block segmentation
  (`segmenter.py`) are 100% deterministic, zero-LLM, zero-token.
* The LLM (`agent/converter.py`) sees ONE claim block at a time, never the
  whole document, and is constrained to `common.claims.ClaimExtraction` —
  a narrow ~15-field schema, not the full `common.findings.Finding` shape.
* The extractor role resolves to `ModelTier.BALANCED`, not
  `HIGH_REASONING` — see `config.llm_config.ROLE_TO_TIER`. Transcription
  does not need the expensive tier; that's the single largest cost lever
  available.
* Binary/function resolution (`resolve.py`) and the `ClaimExtraction` ->
  `Finding` expansion (`emit.py`) are both pure, deterministic, zero-LLM.

A claim this package emits is NEVER treated as verified. `emit.py` pins
`Finding.confidence` to `MEDIUM` (never `CONFIRMED`/`HIGH`) and writes an
honest `why_not_false_positive` naming this as an unverified third-party
assertion pending Stage 4/5 verification — see that module's docstring.

Every persisted path is relative to `db_subfolder`, same convention Stage 3
follows. This package never writes into `stage2/`, `stage3/`, `stage4/`, or
`stage5/` — only into its own `stage3b/`.
"""
