"""Application settings, loaded from environment / `.env`.

All configuration is centralized here so no module reaches for ``os.environ``
directly. Access settings via :func:`get_settings` (cached singleton).

Environment-variable conventions:

* LLM credentials use their conventional names (``ANTHROPIC_API_KEY``,
  ``GOOGLE_API_KEY``, ``OLLAMA_BASE_URL``) so existing shells work unchanged.
* Application-specific settings use the ``FWA_`` prefix.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Repository root = two levels up from this file (fw_audit/config/settings.py).
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Typed, validated application configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # ---- Environment / logging ----------------------------------------
    environment: str = Field(default="development", validation_alias="FWA_ENVIRONMENT")
    log_level: str = Field(default="INFO", validation_alias="FWA_LOG_LEVEL")

    # ---- LLM credentials ----------------------------------------------
    anthropic_api_key: str | None = Field(
        default=None, validation_alias="ANTHROPIC_API_KEY"
    )
    google_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GOOGLE_API_KEY", "GEMINI_API_KEY"),
    )
    openai_api_key: str | None = Field(default=None, validation_alias="OPENAI_API_KEY")
    openai_base_url: str | None = Field(default=None, validation_alias="OPENAI_BASE_URL")
    """Override the OpenAI API endpoint. Unset = real OpenAI. Point this at a
    local OpenAI-compatible server (vLLM, LM Studio, ...) to run the "openai"
    provider fully offline without a new ModelProvider member."""
    ollama_base_url: str = Field(
        default="http://localhost:11434", validation_alias="OLLAMA_BASE_URL"
    )
    ollama_num_ctx: int = Field(
        default=32768, ge=1, validation_alias="FWA_OLLAMA_NUM_CTX"
    )
    """Ollama's server-side default context window is only 2048 tokens,
    which silently truncates prompts for any non-trivial firmware/chunk —
    see the long comment in `config.llm_config` for the empirical basis.
    Applied to every Ollama-backed spec, not just one hardcoded tier."""
    ollama_num_predict: int = Field(
        default=4096, ge=1, validation_alias="FWA_OLLAMA_NUM_PREDICT"
    )
    """Hard cap on Ollama generation length — guards against a small
    model's degenerate repetition loops burning minutes producing
    unusably long, unparseable output. See `config.llm_config`."""

    # ---- LLM model routing overrides -----------------------------------
    llm_model: str | None = Field(default=None, validation_alias="FWA_LLM_MODEL")
    """Global override, `"<provider>:<model>"` (e.g. `"anthropic:claude-
    sonnet-4-5"`, `"ollama:qwen2.5-coder:1.5b"`). Consulted by
    `llm_config.resolve_spec()` before the tier table, for every role that
    has no more specific per-role override set. `provider` must be one of
    `ModelProvider`'s values; `model` may itself contain `:` (Ollama tags),
    so only the FIRST `:` is split on."""
    stage3_analyst_model: str | None = Field(
        default=None, validation_alias="FWA_STAGE3_ANALYST_MODEL"
    )
    """Per-role override for `AgentRole.STAGE3_VULN_ANALYST`, same
    `"<provider>:<model>"` syntax as `llm_model`. Takes precedence over
    `llm_model` for that role only — e.g. set this to
    `"ollama:qwen2.5-coder:1.5b"` to run Stage 3's analysis offline while
    leaving Stage 1's identifier (or `llm_model`) on the cloud default."""
    use_local_model: bool = Field(
        default=False, validation_alias="FWA_USE_LOCAL_MODEL"
    )
    """Preference switch consulted by `llm_config.resolve_spec()` for every
    role that has no explicit `"<provider>:<model>"` override set (those
    above always win outright — this only decides between the API-backed
    and local-Ollama halves of the tier table).

    * `False` (default) = prefer the API-backed model (e.g. Anthropic
      Claude Sonnet, `ModelTier.HIGH_REASONING`'s normal spec).
    * `True` = prefer the local Ollama model (`ModelTier.FAST_LOCAL`'s
      spec) instead.

    Whichever is preferred is tried first; if its credential/provider is
    unavailable, `llm_config.get_llm`/`get_llm_for_agent` automatically
    fall back to the OTHER mode (API <-> local) rather than failing
    immediately. Only when *neither* the preferred nor the fallback model
    is usable does resolution raise — see `llm_config.get_llm`'s
    docstring for the exact precedence."""

    # ---- Observability (LangSmith tracing, Stages 3/4/5) -----------------
    langsmith_tracing: bool = Field(default=False, validation_alias="LANGSMITH_TRACING")
    """Master switch. `False` (default) means `fw_audit.observability` is a
    complete no-op everywhere it's called — no env var written, no
    `langsmith` import attempted, zero behavior change to any persisted
    artifact. Conventional (non-`FWA_`) name so it lines up with the
    LangSmith SDK's own env var and any existing LangSmith shell setup."""
    langsmith_api_key: str | None = Field(default=None, validation_alias="LANGSMITH_API_KEY")
    langsmith_project: str = Field(
        default="fw-audit", validation_alias="LANGSMITH_PROJECT"
    )
    """Project name traces are grouped under in the LangSmith UI. One
    project shared by Stages 3, 4 and 5 — the `stage` tag (see
    `fw_audit.observability.context`) is how you filter within it, not a
    separate project per stage."""
    langsmith_endpoint: str = Field(
        default="https://api.smith.langchain.com", validation_alias="LANGSMITH_ENDPOINT"
    )
    """LangSmith cloud by default. Point at a self-hosted instance's URL to
    keep traces off the public endpoint entirely."""
    langsmith_hide_inputs: bool = Field(
        default=False, validation_alias="LANGSMITH_HIDE_INPUTS"
    )
    langsmith_hide_outputs: bool = Field(
        default=False, validation_alias="LANGSMITH_HIDE_OUTPUTS"
    )
    """Together, redact prompt/completion bodies from uploaded traces while
    keeping run structure, timing, and metadata — for firmware where the
    decompiled source itself shouldn't leave the machine, at the cost of
    losing the single most useful debugging signal (the actual failing
    prompt). Off by default: see this project's LangSmith deployment
    decision (traces go to LangSmith cloud, payloads included)."""
    langsmith_sample_rate: float = Field(
        default=1.0, ge=0.0, le=1.0, validation_alias="LANGSMITH_TRACING_SAMPLE_RATE"
    )
    """Fraction of runs actually traced when tracing is on. 1.0 (default) =
    trace everything — the env var name matches the LangSmith SDK's own so
    it's honored even by code paths this module doesn't control."""

    # ---- Directories ----------------------------------------------------
    data_dir: Path = Field(default=PROJECT_ROOT / "data", validation_alias="FWA_DATA_DIR")
    firmware_dir: Path | None = Field(default=None, validation_alias="FWA_FIRMWARE_DIR")
    database_dir: Path | None = Field(default=None, validation_alias="FWA_DATABASE_DIR")
    """Where per-firmware Database subfolders (extracted FS + tree.txt) live."""

    # ---- Execution backend ----------------------------------------------
    executor_backend: str = Field(default="docker", validation_alias="FWA_EXECUTOR_BACKEND")
    """One of "docker" (production default), "local" (tests/dev), "sandbox"
    (reserved, unimplemented — see fw_audit.executors.sandbox_executor)."""
    docker_bin: str = Field(default="docker", validation_alias="FWA_DOCKER_BIN")
    docker_image: str = Field(
        default="fw-audit-sandbox:latest", validation_alias="FWA_DOCKER_IMAGE"
    )
    docker_run_as_host_user: bool = Field(
        default=True, validation_alias="FWA_DOCKER_RUN_AS_HOST_USER"
    )
    """When true (default) and running on a POSIX host, every `DockerExecutor`
    invocation adds `--user "<host uid>:<host gid>"`, so the container writes
    to the bind-mounted workspace as the SAME user that owns it on the host —
    instead of whatever `USER` an image bakes in (e.g. `docker/Dockerfile.ghidra`'s
    non-root `ghidra`, UID 1000). Without this, a host directory owned by a
    different UID (commonly: created by a `fw-ingest`/`fw-extract` run as
    root, then written to by an image's non-root user, or vice versa) causes
    a `Permission denied` deep inside the container — e.g. Stage 2's
    `analyzeHeadless` failing to create `.../ghidra/headless_stdout.txt`.
    Matching the host UID sidesteps the mismatch entirely, no `chown`/`chmod`
    of `data/db/` required. No-op on Windows (`os.getuid` doesn't exist) —
    Docker Desktop's Linux VM + bind-mount layer doesn't hit this class of
    permission error the same way a native Linux host does."""

    # ---- Stage 2: Ghidra decompilation -----------------------------------
    ghidra_image: str = Field(
        default="fw-audit-ghidra:latest", validation_alias="FWA_GHIDRA_IMAGE"
    )
    ghidra_timeout_seconds: int = Field(
        default=3600, ge=60, validation_alias="FWA_GHIDRA_TIMEOUT_SECONDS"
    )
    """Wall-clock cap for ONE analyzeHeadless invocation (one binary).
    Distinct from subprocess_timeout_seconds (900s default) — a multi-MB
    stripped MIPS binary routinely exceeds that."""
    ghidra_analysis_timeout_seconds: int = Field(
        default=1800, ge=60, validation_alias="FWA_GHIDRA_ANALYSIS_TIMEOUT_SECONDS"
    )
    """Passed to analyzeHeadless as -analysisTimeoutPerFile; bounds Ghidra's
    own auto-analysis, distinct from the outer process-level timeout above."""
    ghidra_max_mem: str = Field(
        default="4g", pattern=r"^\d+[mMgG]$", validation_alias="FWA_GHIDRA_MAX_MEM"
    )
    ghidra_max_cpu: int = Field(default=2, ge=1, validation_alias="FWA_GHIDRA_MAX_CPU")
    ghidra_max_functions: int = Field(
        default=2000, ge=1, validation_alias="FWA_GHIDRA_MAX_FUNCTIONS"
    )
    """Router binaries routinely exceed 10,000 functions; the export script
    caps at this many (largest/most-referenced first) and records the rest
    as skipped rather than letting a single binary run unbounded."""
    ghidra_decompile_timeout_seconds: int = Field(
        default=60, ge=1, validation_alias="FWA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS"
    )
    ghidra_emit_strings: bool = Field(
        default=True, validation_alias="FWA_GHIDRA_EMIT_STRINGS"
    )
    stage2_concurrency: int = Field(
        default=1, ge=1, le=8, validation_alias="FWA_STAGE2_CONCURRENCY"
    )
    """Binaries decompiled in parallel. Default 1: each analyzeHeadless JVM
    reserves ghidra_max_mem, so N concurrent means N x that on the host."""
    stage2_max_binaries: int = Field(
        default=25, ge=1, validation_alias="FWA_STAGE2_MAX_BINARIES"
    )
    stage2_max_rescan_files: int = Field(
        default=200_000, ge=1, validation_alias="FWA_STAGE2_MAX_RESCAN_FILES"
    )
    """Cap on the lazily-built rootfs basename index used to recover an
    IdentifiedBinary.path that doesn't resolve directly (see
    stage2_extraction.resolve)."""

    # ---- Stage 3: analysis core (ingest / clean / chunk / queue) --------
    stage3_chunk_lines: int = Field(
        default=1000, ge=50, validation_alias="FWA_STAGE3_CHUNK_LINES"
    )
    """Soft per-chunk line-count target consumed by
    `chunk.strategy.chunk_source`: a chunk closes once its accumulated
    functions reach this many lines (the function that crosses it stays
    in that chunk — see that function's docstring for the exact
    algorithm). `chunk_source` raises `ValueError` if this exceeds
    `stage3_max_chunk_lines` below. Threaded through by the
    `fw-analyze --chunk-lines` flag."""
    stage3_max_chunk_lines: int = Field(
        default=4000, ge=1, validation_alias="FWA_STAGE3_MAX_CHUNK_LINES"
    )
    """Hard cap consumed by `chunk.strategy.chunk_source`, two roles: (1)
    a single function whose own line span exceeds this becomes its own
    `oversized=True` chunk rather than being merged with neighbors or
    (never allowed) split; (2) merging a function into an in-progress
    chunk is refused — the chunk is flushed first — if it would push the
    chunk's total over this cap."""
    stage3_debug_dump: bool = Field(
        default=False, validation_alias="FWA_STAGE3_DEBUG_DUMP"
    )
    """When true, `ingest()` writes Step 1's raw resolved-source dump
    (`stage3/debug/<bin_id>.c`) and Step 2's function-only cleaned dump
    (`stage3/debug/<bin_id>.cleaned.c`) for every target. Purely for
    manual testing/verification, never read back by any later step. Does
    NOT gate chunk-payload dumps — see `stage3_chunk_debug_dump` below,
    an independent flag for Step 3's own debug output."""
    stage3_chunk_debug_dump: bool = Field(
        default=False, validation_alias="FWA_STAGE3_CHUNK_DEBUG_DUMP"
    )
    """When true, `ingest()` additionally chunks every Target's function-
    only extraction via `chunk.strategy.chunk_source` and writes one file
    per `Chunk` to `<db_subfolder>/stage3/chunks/<chunk_id>.c`. Independent
    of `stage3_debug_dump` above — dumping chunk payloads and dumping
    raw/cleaned source answer different questions, gated separately,
    mirroring why `debug_dir` and `chunks_dir` are separate directories in
    `layout.py`. Same discipline as `stage3_debug_dump`: manual
    testing/verification only, best-effort per file, never read back by
    any later step."""
    stage3_queue_maxsize: int = Field(
        default=6, ge=1, validation_alias="FWA_STAGE3_QUEUE_MAXSIZE"
    )
    """Bounded backpressure for `chunk_queue.ChunkQueue`: `put()` blocks
    once this many un-acked chunk handles are pending. Default 6 = 2x the
    default worker count below, so the producer stays a bit ahead of
    consumers without ever materializing a whole firmware's chunk set in
    memory at once — the concern that motivated persisting chunks to disk
    as the queue's source of truth (`ChunkHandle` carries a `chunk_path`
    pointer, never the chunk text itself) rather than passing `Chunk`
    objects through the queue directly."""
    stage3_queue_workers: int = Field(
        default=3, ge=1, le=16, validation_alias="FWA_STAGE3_QUEUE_WORKERS"
    )
    """Concurrent consumer tasks `chunk_queue.run_queue()` spawns. Matches
    the "three workers deep" figure `stage3_analysis/__init__.py`'s own
    module docstring already commits to for Component 2 — this session's
    placeholder no-op consumer runs at that same target concurrency, so
    the plumbing (backpressure, ack/nack, sentinel-based shutdown) is
    exercised realistically even before Component 2's real LLM agent
    exists."""
    stage3_queue_max_attempts: int = Field(
        default=3, ge=1, validation_alias="FWA_STAGE3_QUEUE_MAX_ATTEMPTS"
    )
    """Retry cap for `ChunkQueue.nack()`: a chunk is re-queued (with
    `ChunkHandle.attempt` incremented) up to this many total attempts
    before `Stage3Summary` records it as permanently failed rather than
    retried forever. Only meaningful once a consumer can actually fail
    (the no-op placeholder consumer never does) — reserved for Component
    2's real LLM calls, which can fail transiently (timeouts, rate
    limits) in ways this session's placeholder cannot."""

    # ---- Stage 3 Component 2: LLM vulnerability-analysis worker pool ----
    stage3_llm_timeout_seconds: int = Field(
        default=300, ge=1, validation_alias="FWA_STAGE3_LLM_TIMEOUT_SECONDS"
    )
    """Per-chunk wall-clock cap on the analyst LLM call
    (`agent.consumer.AnalysisConsumer`), enforced via `asyncio.wait_for`.
    A `TimeoutError` here is caught by `chunk_queue._worker`'s broad
    `except Exception` and retried through the normal nack() path."""
    stage3_llm_retry_backoff_seconds: float = Field(
        default=2.0, ge=0, validation_alias="FWA_STAGE3_LLM_RETRY_BACKOFF_SECONDS"
    )
    """Base delay for `AnalysisConsumer`'s exponential backoff on a retried
    chunk (`ChunkHandle.attempt > 0`) — `ChunkQueue.nack()` itself re-queues
    instantly with no delay, so the backoff lives in the consumer instead,
    keyed off the `attempt` counter the handle already carries."""
    stage3_max_chunk_tokens: int = Field(
        default=100_000, ge=1, validation_alias="FWA_STAGE3_MAX_CHUNK_TOKENS"
    )
    """A chunk whose `ChunkHandle.approx_tokens` exceeds this is skipped
    (recorded `skipped_oversized`, acked without an LLM call) rather than
    burning `stage3_queue_max_attempts` retries on a prompt that cannot
    fit the model's context window."""
    stage3_repair_attempts: int = Field(
        default=1, ge=0, validation_alias="FWA_STAGE3_REPAIR_ATTEMPTS"
    )
    """Extra in-process re-invocations `agent.analyst.analyze_chunk` makes
    when the LLM's structured output fails Pydantic validation, feeding
    the validation error back as an additional message. 0 disables
    repair — a schema miss then falls straight through to the queue's
    own nack()/retry instead."""
    stage3_structured_output_method: str = Field(
        default="json_schema", validation_alias="FWA_STAGE3_STRUCTURED_OUTPUT_METHOD"
    )
    """`method=` passed to `BaseChatModel.with_structured_output(...)` in
    `agent.analyst.analyze_chunk` — one of `"json_schema"` (default),
    `"function_calling"`, or `"json_mode"` (see LangChain's own
    `with_structured_output` docstring for what each does per-provider).
    `AnalysisReport` is a large, deeply nested schema (see
    `common.findings`'s module docstring), and some local Ollama models/
    server versions fail to render their chat template when a schema this
    large is injected via Ollama's `json_schema` `format=` payload —
    observed as the model erroring with something like "no user query
    found in messages" on the FIRST attempt, not a retry, which rules out
    a message-construction bug on our side. Setting this to
    `"function_calling"` routes through Ollama's tool-calling endpoint
    instead, sidestepping that template path entirely. Left at
    `"json_schema"` by default because it's the correct/well-supported
    choice for the production Anthropic/Google/OpenAI backends this
    project targets — only override for a local Ollama model that hits
    the failure mode above."""
    stage3_log_prompts: bool = Field(
        default=False, validation_alias="FWA_STAGE3_LOG_PROMPTS"
    )
    """When true, `agent.analyst.analyze_chunk` logs the full message list
    (system prompt + human message, and any repair-retry message appended
    on a later attempt) sent to the analyst LLM, at INFO level so it's
    visible under the default `FWA_LOG_LEVEL` without also having to enable
    DEBUG globally (which would additionally flood the console with every
    HTTP client's own request/response logging). Off by default — same
    "opt-in, verbose debugging aid" discipline as `stage3_debug_dump`/
    `stage3_chunk_debug_dump` — the full prompt includes the entire chunk's
    source text and would otherwise flood the console on every one of
    potentially hundreds of chunk calls per firmware."""

    # ---- Stage 4: RAG sink-to-source identifier (local, all components) --
    stage4_embedding_model: str = Field(
        default="Qwen/Qwen3-Embedding-0.6B", validation_alias="FWA_STAGE4_EMBEDDING_MODEL"
    )
    """Sentence-transformers checkpoint tag used for BOTH corpus embedding
    (`corpus_build.py`, C2) and query embedding (`retrieval/store.py`, C4)
    — these MUST match exactly, or queries land in a different vector space
    than the documents they're searched against. 0.6B (not the larger 4B/8B
    tiers) keeps local CPU embedding fast enough for iterative testing."""
    stage4_embedding_device: str | None = Field(
        default=None, validation_alias="FWA_STAGE4_EMBEDDING_DEVICE"
    )
    """`None` = sentence-transformers auto-picks CUDA if present, else CPU."""
    stage4_chunk_words: int = Field(default=500, ge=10, validation_alias="FWA_STAGE4_CHUNK_WORDS")
    stage4_chunk_overlap_words: int = Field(
        default=0, ge=0, validation_alias="FWA_STAGE4_CHUNK_OVERLAP_WORDS"
    )
    stage4_include_decompiled_c: bool = Field(
        default=False, validation_alias="FWA_STAGE4_INCLUDE_DECOMPILED_C"
    )
    """Whether `build-corpus` also ingests Stage 2's `cleaned/whole.c` per
    binary (`CorpusKind.DECOMPILED_C`). Defaults to False — the corpus is
    rootfs text only, strictly limited to
    `colab.chunk_and_embed.ALLOWED_TEXT_EXTENSIONS` (no printable-byte
    heuristic fallback for unlisted/extensionless files)."""
    stage4_chroma_collection_name: str = Field(
        default="stage4_corpus", validation_alias="FWA_STAGE4_CHROMA_COLLECTION_NAME"
    )
    stage4_embed_batch_size: int = Field(
        default=8, ge=1, validation_alias="FWA_STAGE4_EMBED_BATCH_SIZE"
    )
    """Kept conservative (not e.g. 32) because ~500-word chunks on an 8GB
    consumer GPU (e.g. a 4060 laptop) OOM at higher batch sizes with the
    0.6B model's attention memory — confirmed via a real
    `torch.OutOfMemoryError` at batch_size=32 on such a card. Raise this if
    your GPU has more headroom (24GB+ cards can likely go back to 32+), or
    lower it further if 8 still OOMs."""
    stage4_embed_max_seq_length: int = Field(
        default=2048, ge=32, validation_alias="FWA_STAGE4_EMBED_MAX_SEQ_LENGTH"
    )
    """Hard token cap per chunk passed to the embedding model, independent
    of `stage4_chunk_words`'s WORD-count limit — see
    `colab.chunk_and_embed.DEFAULT_MAX_SEQ_LENGTH`'s docstring: a single
    chunk with pathological tokenization (minified JS, base64, a long
    unbroken hex string — all things a real firmware rootfs contains) can
    OOM a small GPU at ANY batch size without this, since attention memory
    scales with sequence_length^2. Confirmed via a real
    `torch.OutOfMemoryError` that persisted down to batch_size=4 until this
    cap was added. Lower further (e.g. 512-1024) if OOMs still occur."""
    stage4_top_k: int = Field(default=8, ge=1, validation_alias="FWA_STAGE4_TOP_K")
    """Per-query top-k similarity search result count in C4 — see
    `retrieval/engine.py`. Merged/deduped across a `MultiQueryPlan`'s 4-5
    queries, so the final retrieved-chunk count is usually larger than this."""
    stage4_workers: int = Field(default=3, ge=1, le=16, validation_alias="FWA_STAGE4_WORKERS")
    stage4_queue_maxsize: int = Field(
        default=6, ge=1, validation_alias="FWA_STAGE4_QUEUE_MAXSIZE"
    )
    stage4_queue_max_attempts: int = Field(
        default=3, ge=1, validation_alias="FWA_STAGE4_QUEUE_MAX_ATTEMPTS"
    )
    stage4_repair_attempts: int = Field(
        default=1, ge=0, validation_alias="FWA_STAGE4_REPAIR_ATTEMPTS"
    )
    """Same repair-retry budget as `stage3_repair_attempts`, shared by both
    C3 (`query/planner.py`) and C5 (`taint/analyst.py`)."""
    stage4_query_planner_model: str | None = Field(
        default=None, validation_alias="FWA_STAGE4_QUERY_PLANNER_MODEL"
    )
    """Per-role override for `AgentRole.STAGE4_QUERY_PLANNER`, same
    `"<provider>:<model>"` syntax as `stage3_analyst_model`."""
    stage4_taint_analyst_model: str | None = Field(
        default=None, validation_alias="FWA_STAGE4_TAINT_ANALYST_MODEL"
    )
    """Per-role override for `AgentRole.STAGE4_TAINT_ANALYST`."""

    # ---- Stage 5: sandboxed verification (generator/evaluator Joern loop) -
    stage5_verifier_model: str | None = Field(
        default=None, validation_alias="FWA_STAGE5_VERIFIER_MODEL"
    )
    """Shared override applied to BOTH Stage 5 roles
    (`AgentRole.STAGE5_SCRIPT_GENERATOR` and `AgentRole.STAGE5_RESULT_EVALUATOR`)
    unless a role-specific override below is also set — same
    `"<provider>:<model>"` syntax as `stage3_analyst_model`. This is what
    `fw-verify run --model ...` writes, and the common way to point the
    whole pipeline at one local model, e.g. `ollama:qwen3:32b`."""
    stage5_generator_model: str | None = Field(
        default=None, validation_alias="FWA_STAGE5_GENERATOR_MODEL"
    )
    """Per-role override for `AgentRole.STAGE5_SCRIPT_GENERATOR` specifically
    — takes precedence over `stage5_verifier_model` for that role only.
    Lets the script-writing role be pointed at a different model than the
    judging role (e.g. a bigger/cheaper split)."""
    stage5_evaluator_model: str | None = Field(
        default=None, validation_alias="FWA_STAGE5_EVALUATOR_MODEL"
    )
    """Per-role override for `AgentRole.STAGE5_RESULT_EVALUATOR` specifically
    — takes precedence over `stage5_verifier_model` for that role only."""
    stage5_joern_image: str = Field(
        default="fw-audit-joern:latest", validation_alias="FWA_STAGE5_JOERN_IMAGE"
    )
    stage5_joern_timeout_seconds: int = Field(
        default=300, ge=1, validation_alias="FWA_STAGE5_JOERN_TIMEOUT_SECONDS"
    )
    """Wall-clock cap for ONE `run_joern_script` tool call (one script
    execution against an already-built CPG)."""
    stage5_cpg_build_timeout_seconds: int = Field(
        default=900, ge=1, validation_alias="FWA_STAGE5_CPG_BUILD_TIMEOUT_SECONDS"
    )
    """Wall-clock cap for the `build_cpg` tool call — larger than
    `stage5_joern_timeout_seconds` because parsing a whole-program `.c` file
    into a CPG is typically slower than running one query against it."""
    stage5_max_agent_iterations: int = Field(
        default=6, ge=1, validation_alias="FWA_STAGE5_MAX_AGENT_ITERATIONS"
    )
    """Hard cap on generate -> run -> evaluate rounds in the verification
    pipeline (`stage5_verification.agent.graph`) — once hit, a `FAIL_RETRY`
    verdict is downgraded to `FAIL_STOP` inside the evaluate node instead of
    looping again, so `conclude` always sees a decisive verdict. Bounds
    runaway loops, especially important against a smaller local model
    (e.g. Ollama qwen3) that may not reliably converge."""
    stage5_repair_attempts: int = Field(
        default=1, ge=0, validation_alias="FWA_STAGE5_REPAIR_ATTEMPTS"
    )
    """Extra in-process re-invocations the evaluate node makes when the
    evaluator LLM's response never parses as `EvaluatorVerdict` JSON (after
    `agent.cleaning` strips `<think>` blocks/fences) — before giving up and
    treating it as `FAIL_STOP`. Same pattern as
    `stage3_repair_attempts`/`stage4_repair_attempts`; matters more here
    than it used to, since a local model's first response can occasionally
    be nothing but an unterminated `<think>` block."""
    stage5_sandbox_memory: str = Field(
        default="4g", pattern=r"^\d+[mMgG]$", validation_alias="FWA_STAGE5_SANDBOX_MEMORY"
    )
    stage5_sandbox_cpus: float = Field(
        default=2.0, gt=0, validation_alias="FWA_STAGE5_SANDBOX_CPUS"
    )
    stage5_sandbox_pids_limit: int = Field(
        default=256, ge=1, validation_alias="FWA_STAGE5_SANDBOX_PIDS_LIMIT"
    )
    """Resource caps applied by `SandboxExecutor` (never by `DockerExecutor`)
    — this backend runs LLM-authored script content, so it gets a tighter
    posture than the fixed deterministic pipelines `DockerExecutor` runs."""
    stage5_workers: int = Field(default=2, ge=1, le=16, validation_alias="FWA_STAGE5_WORKERS")
    stage5_queue_maxsize: int = Field(
        default=4, ge=1, validation_alias="FWA_STAGE5_QUEUE_MAXSIZE"
    )
    stage5_queue_max_attempts: int = Field(
        default=2, ge=1, validation_alias="FWA_STAGE5_QUEUE_MAX_ATTEMPTS"
    )
    """Worker-pool sizing, mirrors `stage4_workers`/`stage4_queue_maxsize`/
    `stage4_queue_max_attempts` — kept smaller by default than Stage 4's
    since each candidate here drives a multi-turn agent loop plus a Docker
    CPG build, both far more expensive per item than a RAG retrieval call."""
    stage5_keep_workspace: bool = Field(
        default=False, validation_alias="FWA_STAGE5_KEEP_WORKSPACE"
    )
    """When true, `stage5/workspace/<gid>/` (the copied source, built CPG,
    and every script attempt) is left on disk after a run instead of being
    cleaned up — debugging convenience, mirrors `stage3_debug_dump`'s
    "manual testing/verification only" posture."""

    # ---- Stage 5 FVVW v3: fork-join orchestration (strategy agent + report) -
    stage5_strategy_model: str | None = Field(
        default=None, validation_alias="FWA_STAGE5_STRATEGY_MODEL"
    )
    """Per-role override for `AgentRole.STAGE5_STRATEGY_AGENT` — falls back
    to `stage5_verifier_model` like the generator/evaluator roles do. The
    strategy agent produces the threat model, A/B hypotheses, and both
    tracks' plans in one pass (`stage5_verification.fvvw.strategy`)."""
    stage5_report_model: str | None = Field(
        default=None, validation_alias="FWA_STAGE5_REPORT_MODEL"
    )
    """Per-role override for `AgentRole.STAGE5_REPORT_WRITER` — falls back
    to `stage5_verifier_model`. Composes the final disclosure Markdown
    (`stage5_verification.fvvw.report`)."""
    stage5_checkpoint_backend: str = Field(
        default="memory", validation_alias="FWA_STAGE5_CHECKPOINT_BACKEND"
    )
    """`"memory"` (LangGraph `MemorySaver`, per-process, tests/dev) or
    `"sqlite"` (persists across process restarts, needed for
    `bringup_stabilize` repair resume in a long-running production queue).
    Unrecognized values raise `ValueError` at graph-build time, same
    "no silent fallback" posture as `executor_backend`."""

    # ---- Stage 5 FVVW v3: dynamic (QEMU+GDB) verification track ----------
    stage5_verification_image: str = Field(
        default="fw-audit-verification-sandbox:latest",
        validation_alias="FWA_STAGE5_VERIFICATION_IMAGE",
    )
    """The superset sandbox image (`docker/Dockerfile.verification`) backing
    `characterize_target`, `static_crosscheck`, and the whole dynamic track
    — Joern's own `SandboxExecutor` calls keep pointing at
    `stage5_joern_image`/`Dockerfile.joern` unchanged; this is a SEPARATE
    image, not a replacement, so the static track is never affected by
    anything installed here."""
    stage5_qemu_timeout_seconds: int = Field(
        default=120, ge=1, validation_alias="FWA_STAGE5_QEMU_TIMEOUT_SECONDS"
    )
    """Wall-clock cap for one QEMU launch/bring-up step inside a dynamic
    session (`bringup_stabilize`, `reach_target`)."""
    stage5_gdb_timeout_seconds: int = Field(
        default=60, ge=1, validation_alias="FWA_STAGE5_GDB_TIMEOUT_SECONDS"
    )
    """Wall-clock cap for one `gdb-multiarch -batch -x recipe.gdb` call
    (`reach_target`/`satisfy_guards`/`instrument_trigger`)."""
    stage5_bringup_max_repairs: int = Field(
        default=5, ge=1, validation_alias="FWA_STAGE5_BRINGUP_MAX_REPAIRS"
    )
    """Cap on `bringup_stabilize` repair attempts within one dynamic-track
    run before giving up and writing `mem.dynamic.result = not_run` — bounds
    the repair loop the same way `stage5_max_agent_iterations` bounds the
    static generate/evaluate loop."""
    stage5_dynamic_max_iterations: int = Field(
        default=4, ge=1, validation_alias="FWA_STAGE5_DYNAMIC_MAX_ITERATIONS"
    )
    """Cap on `dynamic_evaluate`'s retry/hypothesis-switch loop (reach ->
    guards -> trigger -> collect -> evaluate), per active hypothesis, before
    forcing an `inconclusive` terminal verdict — see FVVW's hypothesis A/B
    switching logic."""
    stage5_allow_network_grant: bool = Field(
        default=False, validation_alias="FWA_STAGE5_ALLOW_NETWORK_GRANT"
    )
    """Master switch for `bringup_stabilize`'s scoped, per-run network grant
    (FVVW §8/§12): when `False` (the default), every dynamic-track container
    stays `--network=none` even if a target would otherwise need a reachable
    socket — that repair case is instead reported as a residual unknown
    rather than silently opening egress. Set `True` only for an operator who
    has read and accepted that a specific run's container may gain scoped,
    revoked-after egress."""
    stage5_dynamic_workspace_root: str | None = Field(
        default=None, validation_alias="FWA_STAGE5_DYNAMIC_WORKSPACE_ROOT"
    )
    """Override for where a dynamic-track session's rootfs copy/scratch
    files are staged on the host before being bind-mounted — defaults to
    `stage5/workspace/<gid>/dynamic/` under the run's own `db_subfolder`
    (see `stage5_verification.layout`) when unset."""
    stage5_command_log: bool = Field(default=True, validation_alias="FWA_STAGE5_COMMAND_LOG")
    """Master switch for `stage5_verification.cmdlog.CommandLog` — every
    command either fork-join track executes, plus its full result, appended
    to `stage5/fvvw/logs/<gid>.<track>.jsonl`. Unlike LangSmith tracing,
    this stays on by default and is NOT governed by `langsmith_tracing`: the
    whole point is a diagnosable run with no `--trace`/LangSmith account.
    Set `False` only to suppress the extra disk writes (e.g. a constrained
    CI runner); it never affects a verdict either way."""

    # ---- External tool invocation (LocalExecutor / the `docker` CLI call) -
    # Prepended to every host-level command. Firmware-extraction tool names
    # (binwalk/unsquashfs/etc.) are no longer configurable here — those run
    # inside the sandbox image at fixed PATH locations
    # (see stage1_ingestion/extraction/script.py), not on the host.
    # NoDecode: pydantic-settings otherwise JSON-decodes complex-typed env
    # values before our "before" validator runs, which raises on a plain
    # (or empty) string like `FWA_COMMAND_PREFIX=` — NoDecode hands the raw
    # string straight to `_split_command_prefix` below instead.
    command_prefix: Annotated[list[str], NoDecode] = Field(
        default_factory=list, validation_alias="FWA_COMMAND_PREFIX"
    )
    subprocess_timeout_seconds: int = Field(
        default=900, ge=1, validation_alias="FWA_SUBPROCESS_TIMEOUT_SECONDS"
    )

    # ------------------------------------------------------------------ #
    # Validators
    # ------------------------------------------------------------------ #
    @field_validator("command_prefix", mode="before")
    @classmethod
    def _split_command_prefix(cls, value: object) -> object:
        """Allow a comma- or space-separated string for the command prefix."""
        if isinstance(value, str):
            return [tok for tok in value.replace(",", " ").split() if tok]
        return value

    # ------------------------------------------------------------------ #
    # Derived helpers
    # ------------------------------------------------------------------ #
    @property
    def firmware_path(self) -> Path:
        """Directory where raw firmware inputs live."""
        return self.firmware_dir or (self.data_dir / "firmware")

    @property
    def database_path(self) -> Path:
        """Root of the per-firmware Database (extracted FS + tree.txt live here)."""
        return self.database_dir or (self.data_dir / "db")

    def ensure_dirs(self) -> None:
        """Create the data/firmware/db directories if they do not exist."""
        for path in (self.data_dir, self.firmware_path, self.database_path):
            path.mkdir(parents=True, exist_ok=True)

    def db_subfolder(self, firmware_stem: str) -> Path:
        """Return (and create) the Database subfolder for a firmware image.

        Named after the input file (``router-fw-1.2.bin`` -> ``router-fw-1.2/``),
        per the naming convention: every artifact for that image accumulates here.
        """
        path = self.database_path / firmware_stem
        path.mkdir(parents=True, exist_ok=True)
        return path

    def stage2_dir(self, firmware_stem: str) -> Path:
        """Return (and create) `<db_subfolder>/stage2/` for a firmware image."""
        path = self.db_subfolder(firmware_stem) / "stage2"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def stage3_dir(self, firmware_stem: str) -> Path:
        """Return (and create) `<db_subfolder>/stage3/` for a firmware image."""
        path = self.db_subfolder(firmware_stem) / "stage3"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def stage4_dir(self, firmware_stem: str) -> Path:
        """Return (and create) `<db_subfolder>/stage4/` for a firmware image."""
        path = self.db_subfolder(firmware_stem) / "stage4"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def stage5_dir(self, firmware_stem: str) -> Path:
        """Return (and create) `<db_subfolder>/stage5/` for a firmware image."""
        path = self.db_subfolder(firmware_stem) / "stage5"
        path.mkdir(parents=True, exist_ok=True)
        return path


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()
