# CLAUDE.md — Stage 3b: External Claim Ingestion

Read this file first for Stage 3b work. Stage 3b transcribes a third-party
PDF vulnerability report's claims into `common.findings.AnalysisReport`
JSON — the SAME on-disk shape Stage 3 produces — so the existing Stage 4/5
verification machinery can check them, **unverified and unchanged**. It
runs **parallel to Stage 3** (a sibling, not a downstream stage): Stage 3
*discovers* vulnerabilities by reading code; Stage 3b *transcribes claims*
someone else made about the same firmware. Root `CLAUDE.md` covers
cross-cutting concerns (LLM routing, Settings).

## Hard constraints — never violate

- Never write into `stage2/`, `stage3/`, `stage4/`, or `stage5/` — only
  into this stage's own `stage3b/` directory.
- **This is a cheap transcription task, not a reasoning task** (confirmed
  project requirement). `AgentRole.STAGE3B_CLAIM_EXTRACTOR` resolves to
  `ModelTier.BALANCED`, never `HIGH_REASONING` — don't change that without
  the same confirmation. PDF extraction (`extractor.py`) and block
  segmentation (`segmenter.py`) are 100% deterministic, zero-LLM; the
  extractor LLM sees ONE block at a time, never the whole document.
- `emit.py`'s `Finding.confidence` is ALWAYS `MEDIUM`, never
  `CONFIRMED`/`HIGH` — an unverified third-party claim must never present
  as strongly evidenced. Never relax this.
- `emit.py`'s `Finding.decision` is `ESCALATE` only when BOTH the binary
  and the function resolved against real Stage 2 output (`resolve.py`).
  Otherwise `CONTEXT_REQUIRED`. This is load-bearing: Stage 5's
  `characterize_target` HARD-FAILS on an unresolvable
  `evidence_span.function_id` — `CONTEXT_REQUIRED` keeps an unresolved
  claim out of Stage 5's `ESCALATE`-only default instead of crashing it.
- `resolve.resolve_function` must stay EXACTLY as strict as
  `stage5_verification.tools.characterize_tool._find_function` (same two
  tiers, same order) — a looser match here would let a claim `ESCALATE`
  into a Stage 5 hard failure. See that function's docstring.
- `pdfplumber` is imported LAZILY inside `extractor.extract_document()`,
  never at module import time — the unit suite must never need it
  installed.
- `driver.py` uses a plain `asyncio.Semaphore`-bounded pool, deliberately
  NOT `stage3_analysis.chunk_queue.ChunkQueue` — Stage 3b has no
  disk-backed-backpressure problem (one PDF's blocks are already in
  memory), so don't introduce that machinery here.
- One claim per `AnalysisReport` file (unlike Stage 3, which batches
  several findings per chunk) — a bad claim must never take out a sibling.

## Files

| File | Purpose |
|---|---|
| `extractor.py` | Deterministic PDF -> per-page text (`pdfplumber`, lazy import). Zero tokens. |
| `segmenter.py` | Deterministic claim-block segmentation — the main token-control lever; see its docstring. Zero tokens. |
| `resolve.py` | Deterministic `binary_hint`/`function_hint` -> real Stage 2 `bin_id`/`GhidraFunction` resolution. Zero tokens. |
| `agent/prompts.py`, `agent/converter.py` | The ONE LLM call: one block in, one `ClaimExtractionBatch` out. Two-tier repair retry, mirrors `stage3_analysis.agent.analyst`. |
| `emit.py` | Deterministic `ClaimExtraction` -> `Finding` expansion — the narrow LLM schema becomes the full contract with no extra tokens. |
| `driver.py` | `ingest_report()` — extract -> segment -> bounded concurrent extraction -> resolve -> emit -> write. Writes `claims_summary.json` itself (best-effort). |
| `debug.py` | `debug_extract`/`debug_segment`/`debug_resolve` — all zero-token dry runs. |
| `layout.py`, `models.py`, `errors.py` | Path algebra, internal dataclasses, `Stage3bInputError`/`ClaimExtractionUnavailableError`. |
| `runner.py` | `fw-claims` CLI entry point. |

## Invoke

```bash
fw-claims ingest report.pdf --db-subfolder data/db/<stem>
fw-claims ingest report.pdf --db-subfolder data/db/<stem> --model ollama:kimi-k3 --pages 4-19

fw-claims debug extract report.pdf                 # pdfplumber text, 0 tokens
fw-claims debug segment report.pdf                 # block count/sizes = cost estimate, 0 tokens
fw-claims debug resolve --db-subfolder data/db/<stem> --binary httpd --function formSetWanNonLogin

# verify the claims through the existing Stage 4/5 machinery
fw-trace  run --db-subfolder data/db/<stem> --claims
fw-verify run --db-subfolder data/db/<stem> --claims
```

## Input

A PDF vulnerability report. `stage2/stage2_summary.json`, if present, is
used for binary/function resolution — its absence never raises, every
claim simply comes back `CONTEXT_REQUIRED`.

## Output — `data/db/<stem>/stage3b/`

`source/<doc_stem>.pages.json` (cached extraction) → `findings/<chunk_id>.json`
(one `AnalysisReport` per claim — the Stage 4/5 input) →
`claims_summary.json` (best-effort). `debug/<doc_stem>.blocks.json` on
`--debug` only.

## Debugging

- `fw-claims debug segment` BEFORE a real ingest — block count × size is
  the direct token-cost estimate (each block = one LLM call).
- `ExtractorModelUnavailableError` → no usable credential for
  `AgentRole.STAGE3B_CLAIM_EXTRACTOR`; set `FWA_STAGE3B_EXTRACTOR_MODEL`.
- `Stage3bInputError` naming `pip install "fw-audit[pdf]"` → `pdfplumber`
  not installed.
- A claim with `binary_resolved=False` in `claims_summary.json` → its
  `binary_hint` didn't match anything in `stage2_summary.json`; run
  `fw-claims debug resolve` to iterate on the match.
- Unit: `pytest -m "not integration" tests/test_stage3b_*.py tests/test_common_claims.py`
  — no Docker/LLM/`pdfplumber` required.

## Adding a feature here

New segmentation heuristics go in `segmenter.py`, never inline in
`driver.py`. New claim fields go in `common/claims.py` (not
`common/findings.py`). A change to how a claim maps onto `Finding` belongs
in `emit.py` — keep it deterministic; do not add an LLM call there.
