"""Stage 3 Component 2: the LLM vulnerability-analysis worker pool.

Fills the `consumer` extension point `chunk_queue.run_queue(...)` was built
with (see `stage3_analysis/__init__.py`'s Component 1/2 boundary docstring)
— it does not reimplement the queue, the worker pool, or its backpressure/
retry semantics. `agent.orchestrator.run_analysis()` is the entry point:
it builds an `agent.consumer.AnalysisConsumer` and hands it to the existing
`run_queue()` unchanged.

Modules:

* `prompts` — pure string/message templating for the worker system prompt.
  No I/O, no LLM import — mirrors `stage1_ingestion.identifier.prompts`.
* `analyst` — `analyze_chunk()`: one chunk's text in, one validated
  `AnalysisReport` out, via `get_llm_for_agent(AgentRole.STAGE3_VULN_ANALYST)
  .with_structured_output(AnalysisReport)` plus a bounded schema-repair
  retry. Mirrors `stage1_ingestion.identifier.agent`.
* `consumer` — `AnalysisConsumer`: the `Consumer` (`ChunkHandle ->
  Awaitable[None]`) that `run_queue(..., consumer=...)` expects. Reads a
  chunk's persisted `.c` payload, calls `analyst.analyze_chunk`, and
  persists the result to `stage3/findings/<chunk_id>.json`.
* `orchestrator` — `run_analysis()`: resolves the analyst model up front,
  builds the consumer, delegates to `chunk_queue.run_queue()`, and writes
  `stage3/analysis_summary.json` (`common.findings.AnalysisRunSummary`).

Never writes into `stage2/`, the decompiled mirror tree, or touches
`chunk_queue.py` — the whole point of the `consumer=` seam is that
Component 1 needed no changes to support this.
"""

from __future__ import annotations
