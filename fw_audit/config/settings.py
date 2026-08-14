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
    stage4_chroma_collection_name: str = Field(
        default="stage4_corpus", validation_alias="FWA_STAGE4_CHROMA_COLLECTION_NAME"
    )
    stage4_embed_batch_size: int = Field(
        default=4, ge=1, validation_alias="FWA_STAGE4_EMBED_BATCH_SIZE"
    )
    """Kept conservative (not e.g. 32) because ~500-word chunks on an 8GB
    consumer GPU (e.g. a 4060 laptop) OOM at higher batch sizes with the
    0.6B model's attention memory — confirmed via a real
    `torch.OutOfMemoryError` at batch_size=32 on such a card. Raise this if
    your GPU has more headroom (24GB+ cards can likely go back to 32+), or
    lower it further if 8 still OOMs."""
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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()
