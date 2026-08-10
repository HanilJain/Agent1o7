"""Stage 2 orchestrator: resolve -> decompile -> normalize -> summarize.

A plain async pipeline, not a LangGraph state machine — Stage 2 has no LLM
anywhere in it (see the package docstring), so there's no agent state to
model and the graph machinery would be pure overhead. Error isolation is
explicit instead of LangGraph's `operator.add` accumulators: each binary's
decompile/normalize failure becomes a `DecompiledBinary(status=FAILED, ...)`
rather than propagating, and only the load phase (`Stage2InputError`) can
fail the run outright.

`stage2_summary.json` is written by `run_extraction()` itself, not only by
the CLI (`runner.py`) — unlike Stage 1's summary, a programmatic caller
(Stage 3) invoking this function directly still gets one.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fw_audit.common.schemas import (
    DecompilationStatus,
    DecompiledBinary,
    ExtractionStatus,
    Stage2Summary,
    UnresolvedBinaryRecord,
)
from fw_audit.config.settings import Settings, get_settings
from fw_audit.executors.base import Executor
from fw_audit.stage2_extraction import layout
from fw_audit.stage2_extraction.ghidra.client import decompile_binary, ghidra_executor
from fw_audit.stage2_extraction.normalize.pipeline import JOERN_PIPELINE, LLM_PIPELINE, normalize
from fw_audit.stage2_extraction.normalize.prelude import PRELUDE_HEADER
from fw_audit.stage2_extraction.resolve import ResolvedBinary, resolve_binaries
from fw_audit.stage2_extraction.stage1_io import (
    Stage2InputError,
    load_stage1_summary,
    resolve_rootfs_dir,
)

__all__ = ["Stage2InputError", "run_extraction"]

_SUCCEEDED_STATUSES = (DecompilationStatus.SUCCEEDED, DecompilationStatus.PARTIAL)


async def run_extraction(
    *,
    stage1_summary_path: Path,
    run_id: str | None = None,
    settings: Settings | None = None,
    only: tuple[str, ...] = (),
    dry_run: bool = False,
) -> Stage2Summary:
    """Run Stage 2 end to end and return (and persist) the `Stage2Summary`.

    Raises `Stage2InputError` ONLY from the load phase — everything after
    that is per-binary isolated and folded into the returned summary.
    """
    settings = settings or get_settings()
    run_id = run_id or uuid.uuid4().hex[:12]
    started_at = datetime.now(UTC)
    warnings: list[str] = []
    errors: list[str] = []

    stage1_summary = load_stage1_summary(stage1_summary_path)
    rootfs_resolution = resolve_rootfs_dir(stage1_summary)
    rootfs_dir = rootfs_resolution.rootfs_dir
    warnings.extend(rootfs_resolution.warnings)

    db_subfolder = Path(stage1_summary.db_subfolder)
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True, exist_ok=True)

    decompiled_tree = layout.decompiled_tree_dir(db_subfolder)

    def _finish(
        status: ExtractionStatus,
        binaries: list[DecompiledBinary],
        unresolved: list[UnresolvedBinaryRecord],
    ) -> Stage2Summary:
        summary = Stage2Summary(
            run_id=run_id,
            stage1_run_id=stage1_summary.run_id,
            status=status,
            db_subfolder=str(db_subfolder),
            rootfs_dir=str(rootfs_dir),
            stage2_dir=str(stage2_dir),
            decompiled_tree_dir=decompiled_tree.name,
            ghidra_image=settings.ghidra_image,
            binaries=binaries,
            unresolved=unresolved,
            warnings=warnings,
            errors=errors,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )
        layout.stage2_summary_path(stage2_dir).write_text(
            summary.model_dump_json(indent=2), encoding="utf-8"
        )
        return summary

    if not stage1_summary.identified_binaries:
        # Stage 1 legitimately finding nothing worth analyzing is not an
        # error — an empty shortlist is a valid, complete outcome.
        warnings.append("Stage 1 identified no binaries; nothing to decompile.")
        return _finish(ExtractionStatus.COMPLETED, [], [])

    resolution = resolve_binaries(
        stage1_summary.identified_binaries,
        rootfs_dir,
        max_binaries=settings.stage2_max_binaries,
        max_rescan_files=settings.stage2_max_rescan_files,
    )
    warnings.extend(resolution.warnings)
    layout.resolution_report_path(stage2_dir).write_text(
        json.dumps(resolution.to_json_dict(), indent=2, default=str), encoding="utf-8"
    )

    resolved_list = list(resolution.resolved)
    if only:
        wanted = set(only)
        resolved_list = [
            r
            for r in resolved_list
            if r.requested in wanted or r.rootfs_rel in wanted or wanted & set(r.aliases)
        ]

    unresolved = list(resolution.unresolved)

    if not resolved_list:
        errors.append(
            f"Stage 1 identified {len(stage1_summary.identified_binaries)} binaries but "
            f"none resolved to verified bytes ({len(unresolved)} unresolved) — see "
            "resolution_report.json for why."
        )
        return _finish(ExtractionStatus.FAILED, [], unresolved)

    if dry_run:
        warnings.append(
            f"--dry-run: {len(resolved_list)} binaries resolved, none decompiled."
        )
        return _finish(ExtractionStatus.COMPLETED, [], unresolved)

    executor = ghidra_executor(settings)
    if not executor.available():
        raise Stage2InputError(
            "Execution backend unavailable for the Ghidra image; if using the "
            "default 'docker' backend, start the Docker daemon and ensure the "
            "fw-audit-ghidra image is built "
            "(docker build -f docker/Dockerfile.ghidra -t fw-audit-ghidra:latest .)."
        )

    layout.ghidra_types_header_path(stage2_dir).write_text(PRELUDE_HEADER, encoding="utf-8")

    decompiled = await _decompile_all(
        tuple(resolved_list),
        run_id=run_id,
        workspace=db_subfolder,
        rootfs_dir=rootfs_dir,
        stage2_dir=stage2_dir,
        settings=settings,
        executor=executor,
    )
    decompiled, mirror_warnings = _normalize_all(
        decompiled, stage2_dir, db_subfolder, decompiled_tree=decompiled_tree
    )
    warnings.extend(mirror_warnings)

    succeeded = [b for b in decompiled if b.status in _SUCCEEDED_STATUSES]
    failed = [b for b in decompiled if b.status not in _SUCCEEDED_STATUSES]
    if failed:
        warnings.append(f"{len(failed)} of {len(decompiled)} binaries failed to decompile.")

    if not succeeded:
        status = ExtractionStatus.FAILED
    elif failed or unresolved:
        status = ExtractionStatus.COMPLETED_WITH_ERRORS
    else:
        status = ExtractionStatus.COMPLETED

    return _finish(status, decompiled, unresolved)


async def _decompile_all(
    resolved: tuple[ResolvedBinary, ...],
    *,
    run_id: str,
    workspace: Path,
    rootfs_dir: Path,
    stage2_dir: Path,
    settings: Settings,
    executor: Executor,
) -> list[DecompiledBinary]:
    """Fan out with a hard concurrency cap — N concurrent JVMs each reserve
    `settings.ghidra_max_mem`, so unbounded fan-out (e.g. via LangGraph's
    `Send`) would risk OOMing the host. Each binary is isolated: an
    unhandled exception from `decompile_binary` (itself already
    never-raises by contract, but defended here regardless) becomes a
    failed `DecompiledBinary`, never a crashed run."""
    semaphore = asyncio.Semaphore(settings.stage2_concurrency)

    async def _one(item: ResolvedBinary) -> DecompiledBinary:
        bin_id = layout.bin_id(item.rootfs_rel, item.sha256)
        async with semaphore:
            try:
                return await decompile_binary(
                    item,
                    run_id=run_id,
                    bin_id=bin_id,
                    workspace=workspace,
                    rootfs_dir=rootfs_dir,
                    stage2_dir=stage2_dir,
                    settings=settings,
                    executor=executor,
                )
            except Exception as exc:  # pragma: no cover - defensive, last line of isolation
                return DecompiledBinary(
                    bin_id=bin_id,
                    rootfs_path=item.rootfs_rel,
                    requested_path=item.requested,
                    aliases=list(item.aliases),
                    sha256=item.sha256,
                    size_bytes=item.size_bytes,
                    elf=item.elf,
                    status=DecompilationStatus.FAILED,
                    errors=[f"unhandled exception: {type(exc).__name__}: {exc}"],
                )

    return list(await asyncio.gather(*(_one(item) for item in resolved)))


def _write_mirror(
    tree_dir: Path, rootfs_rel: str, text: str, warnings: list[str]
) -> str | None:
    """Write `text` into the decompiled-C mirror tree; return the path
    relative to `tree_dir` (POSIX), or `None` if the write was skipped.

    Never raises: the mirror is a convenience view, and the authoritative
    copy under `stage2/normalized/joern/whole.c` has already been written
    by the time this is called. `rootfs_rel` is LLM-influenced in origin
    (threaded from `IdentifiedBinary.path` through `resolve.py`), so
    `layout.is_contained` is a defense-in-depth check before ever touching
    disk — `resolve.py` only guarantees containment within `rootfs_dir`,
    a different base than `tree_dir`.
    """
    target = layout.decompiled_tree_file(tree_dir, rootfs_rel)
    if not layout.is_contained(target, tree_dir):
        warnings.append(
            f"decompiled mirror skipped for {rootfs_rel!r}: path escapes the mirror root."
        )
        return None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    except OSError as exc:
        warnings.append(f"decompiled mirror write failed for {rootfs_rel!r}: {exc}")
        return None
    return target.relative_to(tree_dir).as_posix()


def _normalize_all(
    decompiled: list[DecompiledBinary],
    stage2_dir: Path,
    workspace: Path,
    *,
    decompiled_tree: Path | None = None,
) -> tuple[list[DecompiledBinary], list[str]]:
    """Pure CPU, no executor — runs after every Ghidra call has completed.
    A binary that never produced raw C (any non-succeeded/partial status)
    passes through untouched; normalization has nothing to work on.

    When `decompiled_tree` is given, also mirrors each binary's normalized
    whole-program C into it under the binary's rootfs-relative path (see
    `layout.decompiled_tree_dir`) — a human-oriented alternate view,
    sibling to `workspace` (== db_subfolder), alongside the machine-
    oriented `stage2/` tree. Returns `(binaries, warnings)`; a mirror-write
    failure is a warning, never a failed binary — the authoritative
    artifact under `stage2/` is unaffected either way.
    """
    updated: list[DecompiledBinary] = []
    mirror_warnings: list[str] = []
    for binary in decompiled:
        if binary.status not in _SUCCEEDED_STATUSES:
            updated.append(binary)
            continue

        bin_dir = layout.binary_dir(stage2_dir, binary.bin_id)
        artifacts_update: dict[str, str] = {}

        whole_c = layout.raw_decompiled_whole_c(bin_dir)
        if whole_c.is_file():
            joern_out = layout.normalized_joern_whole_c(bin_dir)
            joern_out.parent.mkdir(parents=True, exist_ok=True)
            raw_text = whole_c.read_text(encoding="utf-8", errors="replace")
            result = normalize(raw_text, JOERN_PIPELINE)
            joern_out.write_text(result.text, encoding="utf-8")
            artifacts_update["normalized_joern_c"] = layout.relative_to_db_subfolder(
                joern_out, workspace
            )
            if decompiled_tree is not None:
                mirrored = _write_mirror(
                    decompiled_tree, binary.rootfs_path, result.text, mirror_warnings
                )
                if mirrored is not None:
                    artifacts_update["decompiled_tree_c"] = mirrored

        functions_dir = layout.raw_decompiled_functions_dir(bin_dir)
        if functions_dir.is_dir() and any(functions_dir.glob("*.c")):
            llm_functions_dir = layout.normalized_llm_functions_dir(bin_dir)
            llm_functions_dir.mkdir(parents=True, exist_ok=True)
            for func_file in sorted(functions_dir.glob("*.c")):
                result = normalize(
                    func_file.read_text(encoding="utf-8", errors="replace"), LLM_PIPELINE
                )
                (llm_functions_dir / func_file.name).write_text(result.text, encoding="utf-8")
            artifacts_update["normalized_llm_functions_dir"] = layout.relative_to_db_subfolder(
                llm_functions_dir, workspace
            )

        if artifacts_update:
            new_artifacts = binary.artifacts.model_copy(update=artifacts_update)
            binary = binary.model_copy(update={"artifacts": new_artifacts})
        updated.append(binary)
    return updated, mirror_warnings
