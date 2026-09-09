# Stage 3b — External Claim Ingestion

Turns a third-party PDF vulnerability report into `common.findings.
AnalysisReport` JSON — the exact shape Stage 3 already produces — so
Stage 4 (RAG sink-to-source) and Stage 5 (Joern static + QEMU/GDB dynamic
fork-join) can verify its claims, unchanged. Runs **parallel to Stage 3**:
Stage 3 discovers vulnerabilities by reading decompiled code; Stage 3b
transcribes claims a third party already made about the same firmware.
Every emitted claim is explicitly marked unverified (`confidence=MEDIUM`,
never higher) — verification is Stage 4/5's job, not this stage's.

## What it does

- **Extract** (`extractor.py`): deterministic per-page text extraction via
  `pdfplumber` (lazily imported — install `fw-audit[pdf]` to use it). Zero
  LLM calls.
- **Segment** (`segmenter.py`): deterministic claim-block splitting on
  CVE/CWE identifiers, numbered-finding headings, and severity-table rows.
  Zero LLM calls — this is the main lever on how many (and how large) LLM
  calls the run makes.
- **Extract claims** (`agent/converter.py`): the ONE LLM call in this
  stage. One block in, one narrow `ClaimExtractionBatch` out
  (`AgentRole.STAGE3B_CLAIM_EXTRACTOR`, `ModelTier.BALANCED` by default —
  deliberately NOT the expensive tier Stage 3/4/5 use, since this is
  transcription, not analysis).
- **Resolve** (`resolve.py`): deterministic matching of a claim's
  free-text binary/function name against Stage 2's real `bin_id`/
  `GhidraFunction` table. Zero LLM calls.
- **Emit** (`emit.py`): deterministic expansion of the narrow
  `ClaimExtraction` into a full `common.findings.Finding` — `decision`
  is `ESCALATE` only when both binary and function resolved, otherwise
  `CONTEXT_REQUIRED` (keeps an ungrounded claim out of Stage 5's default
  scope instead of crashing its function-offset validation).

## Files

See [CLAUDE.md](CLAUDE.md) for the full file-by-file table.

## How to run

```bash
pip install -e ".[pdf,anthropic]"   # or ollama/opencode for the extractor model

fw-claims ingest report.pdf --db-subfolder data/db/<stem>
fw-claims ingest report.pdf --db-subfolder data/db/<stem> --model ollama:kimi-k3 --pages 4-19

# zero-token inspection, before spending anything on a real run
fw-claims debug extract report.pdf
fw-claims debug segment report.pdf     # block count x size = the cost estimate
fw-claims debug resolve --db-subfolder data/db/<stem> --binary httpd --function formSetWanNonLogin

# hand the claims to the existing verification pipeline
fw-trace  run --db-subfolder data/db/<stem> --claims
fw-verify run --db-subfolder data/db/<stem> --claims
```

## Input

A PDF report. `stage2/stage2_summary.json` if present (for binary/function
resolution) — its absence never fails the run, every claim simply comes
back `CONTEXT_REQUIRED`.

## Output

`data/db/<stem>/stage3b/`: `source/<doc_stem>.pages.json` (cached
extraction), `findings/<chunk_id>.json` (one `AnalysisReport` per claim —
the Stage 4/5 input), `claims_summary.json` (best-effort run summary).
Never writes into `stage2/`, `stage3/`, `stage4/`, or `stage5/`.

## Debugging

- Run `fw-claims debug segment` before a real ingest — the printed block
  count and character totals are a direct proxy for the run's token cost.
- `ExtractorModelUnavailableError` → no usable credential for the
  extractor role; set `FWA_STAGE3B_EXTRACTOR_MODEL` (or `ANTHROPIC_API_KEY`
  for the tier default).
- A `pdfplumber`-related `Stage3bInputError` names the exact
  `pip install "fw-audit[pdf]"` fix.
- Claims that never resolved a binary/function show up in
  `claims_summary.json` with `binary_resolved=false` and `decision:
  CONTEXT_REQUIRED` — use `fw-claims debug resolve` to iterate on the
  match before re-running the full ingest.

## Testing

```bash
pytest -m "not integration" tests/test_stage3b_*.py tests/test_common_claims.py
```

No Docker, no LLM credential, and no `pdfplumber` installation required for
the unit suite — `pdfplumber` is faked via `sys.modules`, and the LLM call
is mocked. See the [project CLAUDE.md](../../CLAUDE.md) and
[project README.md](../../README.md) for LLM provider setup.
