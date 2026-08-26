"""Debug module — inspect and verify each Stage 5 component in isolation,
without re-running (or paying for) the whole pipeline.

Every function here is a dry run: none of them write into `verifications/`
or `reports/` (the pipeline's own persisted, tracked output) — only
`stage5/debug/`, if anything at all. Mirrors `stage4_rag.debug`'s exact
discipline.

Wired into `runner.py debug {build-cpg,script,verify}`.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from fw_audit.common.verification import CpgBuildRecord, JoernScriptAttempt, VerificationReport
from fw_audit.config.settings import Settings, get_settings
from fw_audit.stage5_verification import layout
from fw_audit.stage5_verification.agent.verifier import OnStep, verify_candidate
from fw_audit.stage5_verification.candidate_index import (
    VerificationCandidate,
    discover_candidates,
    load_stage2_summary,
    resolve_source_path,
)
from fw_audit.stage5_verification.errors import Stage5InputError
from fw_audit.stage5_verification.tools.joern_tool import (
    build_cpg_async,
    joern_executor,
    run_joern_script_async,
)


@dataclass(frozen=True)
class DebugCpgResult:
    workspace_dir: Path
    record: CpgBuildRecord


async def debug_build_cpg(
    db_subfolder: Path, bin_id: str, *, settings: Settings | None = None
) -> DebugCpgResult:
    """Resolves `bin_id`'s `normalized/joern/whole.c` via `stage2_summary.json`,
    stages it into a scratch workspace under `stage5/debug/<bin_id>/`, and
    runs `build_cpg` — CPG build only, no LLM involved at all."""
    settings = settings or get_settings()
    stage2_summary = load_stage2_summary(db_subfolder / "stage2")
    source_path = resolve_source_path(
        bin_id, db_subfolder=db_subfolder, stage2_summary=stage2_summary
    )
    if source_path is None:
        raise Stage5InputError(
            f"No normalized Joern C resolved for bin_id={bin_id!r} under {db_subfolder}."
        )

    stage5_dir_ = layout.stage5_dir(db_subfolder)
    workspace_dir_ = layout.debug_dir(stage5_dir_) / bin_id
    workspace_dir_.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_path, layout.source_path(workspace_dir_))

    executor = joern_executor(settings)
    record = await build_cpg_async(
        workspace_dir=workspace_dir_, executor=executor, settings=settings
    )
    return DebugCpgResult(workspace_dir=workspace_dir_, record=record)


async def debug_run_script(
    workspace_dir: Path, script_text: str, *, settings: Settings | None = None
) -> JoernScriptAttempt:
    """Runs one hand-written script against an already-built CPG in
    `workspace_dir` (e.g. from `debug_build_cpg`, or a real run's
    `stage5/workspace/<gid>/` when `FWA_STAGE5_KEEP_WORKSPACE=true`) —
    bypasses the LLM entirely, same "test the tool mechanics directly"
    precedent as `stage4_rag.debug.debug_search` bypassing C3."""
    settings = settings or get_settings()
    if not layout.cpg_path(workspace_dir).is_file():
        raise Stage5InputError(
            f"No cpg.bin in {workspace_dir} — run `fw-verify debug build-cpg` (or a real "
            "verification with --keep-workspace) against this workspace first."
        )
    executor = joern_executor(settings)
    return await run_joern_script_async(
        script_text,
        attempt_index=0,
        workspace_dir=workspace_dir,
        executor=executor,
        settings=settings,
    )


def _find_candidate(db_subfolder: Path, global_id: str) -> VerificationCandidate:
    # DEFAULT_DECISIONS may exclude the finding the caller wants to debug —
    # debug tooling should never silently hide an item the user explicitly
    # asked for by id, so this scans every Decision value, mirroring
    # stage4_rag.debug._find_candidate's exact precedent.
    from fw_audit.common.findings import Decision

    all_candidates = discover_candidates(db_subfolder, decisions=frozenset(Decision))
    for candidate in all_candidates:
        if candidate.global_id == global_id:
            return candidate
    raise ValueError(f"No finding with global_id {global_id!r} found under {db_subfolder}/stage3")


async def debug_verify(
    db_subfolder: Path,
    global_id: str,
    *,
    prompt_override: str | None = None,
    settings: Settings | None = None,
    on_step: OnStep | None = None,
) -> VerificationReport:
    """Runs the full generate/run/evaluate pipeline for ONE finding — a dry
    run: returns the `VerificationReport` without persisting it to
    `stage5/verifications/` or `stage5/reports/` (use `fw-verify run` for
    the persisting version). `prompt_override` replaces
    `agent.prompts.GENERATOR_SYSTEM_PROMPT` for this call only — the
    `--prompt-file` debugging control. `on_step`, when given, is forwarded
    straight through to `agent.verifier.verify_candidate` — see that
    function's docstring; `runner.py`'s `fw-verify debug verify` uses this
    to print the pipeline's progress live as it happens."""
    settings = settings or get_settings()
    candidate = _find_candidate(db_subfolder, global_id)
    return await verify_candidate(
        candidate,
        db_subfolder=db_subfolder,
        settings=settings,
        system_prompt=prompt_override,
        on_step=on_step,
    )


__all__ = [
    "DebugCpgResult",
    "debug_build_cpg",
    "debug_run_script",
    "debug_verify",
]
