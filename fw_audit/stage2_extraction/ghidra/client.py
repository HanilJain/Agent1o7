"""Executes `command.py`'s composed `analyzeHeadless` invocation via the
`Executor` abstraction, and turns the result (plus the export script's
`metadata.json`) into a `DecompiledBinary`.

Never raises: every failure mode — Docker/the Ghidra image unavailable, a
timeout, a non-zero exit, malformed or missing `metadata.json` — becomes a
`DecompiledBinary` with a non-`SUCCEEDED` status and populated
warnings/errors, mirroring the never-raises contract `resolve.py` already
establishes for binary resolution. `extract.py` is what decides whether one
binary's failure fails the whole Stage 2 run.
"""

from __future__ import annotations

import json
from pathlib import Path

from fw_audit.common.schemas import (
    BinarySymbol,
    DecompilationArtifacts,
    DecompilationStatus,
    DecompiledBinary,
    GhidraFunction,
)
from fw_audit.config.settings import Settings, get_settings
from fw_audit.executors.base import Executor
from fw_audit.executors.docker_executor import to_container_path
from fw_audit.executors.manager import get_executor
from fw_audit.stage2_extraction import layout
from fw_audit.stage2_extraction.ghidra.command import (
    build_analyze_headless_command,
    resolve_language_id,
)
from fw_audit.stage2_extraction.resolve import ResolvedBinary


def ghidra_executor(settings: Settings | None = None) -> Executor:
    """Resolve an `Executor` pointed at the Ghidra image.

    Deliberately goes through `get_executor()` rather than instantiating
    `DockerExecutor` directly, so `FWA_EXECUTOR_BACKEND=local` still works
    for a developer with a host Ghidra install, and so
    `executors.manager`'s "single place that decides isolation level"
    invariant holds. Uses the same `model_copy` idiom `DockerExecutor`
    itself already applies internally for a per-call timeout override."""
    settings = settings or get_settings()
    return get_executor(
        settings.model_copy(
            update={
                "docker_image": settings.ghidra_image,
                "subprocess_timeout_seconds": settings.ghidra_timeout_seconds,
            }
        )
    )


# Substrings observed in analyzeHeadless's log output when the ELF loader
# couldn't identify a usable language for the binary — the trigger for the
# `-processor`-forced retry. Best-effort: an unrecognized failure just means
# no retry is attempted, not a crash.
_LOADER_FAILURE_MARKERS = (
    "no loader found",
    "unable to identify",
    "import failed",
    "could not determine a suitable language",
)


def _looks_like_loader_failure(text: str) -> bool:
    haystack = text.lower()
    return any(marker in haystack for marker in _LOADER_FAILURE_MARKERS)


async def decompile_binary(
    resolved: ResolvedBinary,
    *,
    run_id: str,
    bin_id: str,
    workspace: Path,
    rootfs_dir: Path,
    stage2_dir: Path,
    settings: Settings | None = None,
    executor: Executor | None = None,
) -> DecompiledBinary:
    """Run `analyzeHeadless` for one resolved binary, end to end, including
    the ELF-arch-forced retry when the processor-unspecified first attempt
    fails to import."""
    settings = settings or get_settings()
    executor = executor or ghidra_executor(settings)
    bin_dir = layout.binary_dir(stage2_dir, bin_id)
    for d in (
        layout.raw_dir(bin_dir),
        layout.raw_decompiled_functions_dir(bin_dir),
        layout.raw_disasm_functions_dir(bin_dir),
        layout.ghidra_log_dir(bin_dir),
    ):
        d.mkdir(parents=True, exist_ok=True)

    try:
        container_import_path = to_container_path(resolved.host_path, workspace)
        container_out_dir = to_container_path(layout.raw_dir(bin_dir), workspace)
        container_ghidra_log_dir = to_container_path(layout.ghidra_log_dir(bin_dir), workspace)
    except ValueError as exc:
        return _failed(resolved, bin_id, errors=[f"path containment check failed: {exc}"])

    def _build_cmd(*, language_id: str | None = None, project_suffix: str | None = None):
        return build_analyze_headless_command(
            run_id=run_id,
            bin_id=bin_id,
            container_import_path=container_import_path,
            container_out_dir=container_out_dir,
            container_ghidra_log_dir=container_ghidra_log_dir,
            max_mem=settings.ghidra_max_mem,
            max_functions=settings.ghidra_max_functions,
            decompile_timeout_seconds=settings.ghidra_decompile_timeout_seconds,
            emit_strings=settings.ghidra_emit_strings,
            analysis_timeout_seconds=settings.ghidra_analysis_timeout_seconds,
            max_cpu=settings.ghidra_max_cpu,
            language_id=language_id,
            project_suffix=project_suffix,
        )

    ghidra_cmd = _build_cmd()
    result = await executor.run(
        ghidra_cmd.command, files=workspace, timeout=settings.ghidra_timeout_seconds
    )

    if result.timed_out:
        return _failed(
            resolved,
            bin_id,
            status=DecompilationStatus.TIMED_OUT,
            errors=[
                f"analyzeHeadless timed out after {settings.ghidra_timeout_seconds}s "
                f"(FWA_GHIDRA_TIMEOUT_SECONDS)"
            ],
            artifacts=_artifacts(bin_dir, workspace),
        )

    if not result.ok and _looks_like_loader_failure(result.stdout + result.stderr):
        language_id = resolve_language_id(resolved.elf)
        if language_id is not None:
            retry_cmd = _build_cmd(language_id=language_id, project_suffix="retry")
            result = await executor.run(
                retry_cmd.command, files=workspace, timeout=settings.ghidra_timeout_seconds
            )

    artifacts = _artifacts(bin_dir, workspace)

    if not result.ok:
        return _failed(
            resolved,
            bin_id,
            errors=[
                f"analyzeHeadless exited non-zero: "
                f"{result.stderr[-2000:] or result.stdout[-2000:]}"
            ],
            artifacts=artifacts,
        )

    metadata_path = layout.raw_metadata_path(bin_dir)
    if not metadata_path.is_file():
        return _failed(
            resolved,
            bin_id,
            errors=[
                "Ghidra reported success but produced no metadata.json — this is a "
                "bug in fw_audit_export.py or the analyzeHeadless invocation, not a "
                "binary-specific failure."
            ],
            artifacts=artifacts,
        )

    try:
        raw_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _failed(
            resolved,
            bin_id,
            status=DecompilationStatus.PARTIAL,
            errors=[f"metadata.json unreadable/malformed: {exc}"],
            artifacts=artifacts,
        )

    return _from_metadata(resolved, bin_id, raw_metadata, artifacts)


def _artifacts(bin_dir: Path, workspace: Path) -> DecompilationArtifacts:
    def _rel_if_exists(path: Path) -> str | None:
        return layout.relative_to_db_subfolder(path, workspace) if path.exists() else None

    return DecompilationArtifacts(
        raw_c=_rel_if_exists(layout.raw_decompiled_whole_c(bin_dir)),
        raw_header=_rel_if_exists(layout.raw_decompiled_whole_h(bin_dir)),
        raw_functions_dir=_rel_if_exists(layout.raw_decompiled_functions_dir(bin_dir)),
        disasm_listing=_rel_if_exists(layout.raw_disasm_listing(bin_dir)),
        disasm_functions_dir=_rel_if_exists(layout.raw_disasm_functions_dir(bin_dir)),
        metadata_json=_rel_if_exists(layout.raw_metadata_path(bin_dir)),
        normalized_joern_c=None,  # populated by normalize_all, not this module
        normalized_llm_functions_dir=None,
        ghidra_log=_rel_if_exists(layout.ghidra_log_path(bin_dir)),
    )


def _failed(
    resolved: ResolvedBinary,
    bin_id: str,
    *,
    status: DecompilationStatus = DecompilationStatus.FAILED,
    errors: list[str],
    artifacts: DecompilationArtifacts | None = None,
) -> DecompiledBinary:
    return DecompiledBinary(
        bin_id=bin_id,
        rootfs_path=resolved.rootfs_rel,
        requested_path=resolved.requested,
        aliases=list(resolved.aliases),
        sha256=resolved.sha256,
        size_bytes=resolved.size_bytes,
        elf=resolved.elf,
        status=status,
        artifacts=artifacts or DecompilationArtifacts(),
        errors=errors,
    )


def _from_metadata(
    resolved: ResolvedBinary, bin_id: str, raw: dict, artifacts: DecompilationArtifacts
) -> DecompiledBinary:
    analysis = raw.get("analysis", {})
    raw_status = analysis.get("status")
    status = (
        DecompilationStatus.SUCCEEDED if raw_status == "succeeded" else DecompilationStatus.PARTIAL
    )

    functions: list[GhidraFunction] = []
    for f in raw.get("functions", []):
        try:
            functions.append(
                GhidraFunction(
                    name=f["name"],
                    entry_point=f["entry_point"],
                    size=f.get("size", 0),
                    signature=f.get("signature", ""),
                    calling_convention=f.get("calling_convention"),
                    is_thunk=f.get("is_thunk", False),
                    is_external=f.get("is_external", False),
                    calls=f.get("calls", []),
                    called_by=f.get("called_by", []),
                    c_relpath=f.get("c_relpath"),
                    asm_relpath=f.get("asm_relpath"),
                    decompiled=f.get("decompiled", True),
                    decompile_error=f.get("error"),
                )
            )
        except (KeyError, TypeError):
            continue  # one malformed function record must not sink the whole binary

    imports = [BinarySymbol(**s) for s in raw.get("imports", []) if _is_symbol_shaped(s)]
    exports = [BinarySymbol(**s) for s in raw.get("exports", []) if _is_symbol_shaped(s)]

    decompiled_count = sum(1 for f in functions if f.decompiled)
    warnings = []
    decompile_failures = analysis.get("decompile_failures", [])
    if decompile_failures:
        warnings.append(f"{len(decompile_failures)} function(s) failed to decompile")

    return DecompiledBinary(
        bin_id=bin_id,
        rootfs_path=resolved.rootfs_rel,
        requested_path=resolved.requested,
        aliases=list(resolved.aliases),
        sha256=resolved.sha256,
        size_bytes=resolved.size_bytes,
        elf=resolved.elf,
        status=status,
        function_count=len(functions),
        decompiled_function_count=decompiled_count,
        skipped_function_count=len(analysis.get("skipped_functions", [])),
        functions=functions,
        imports=imports,
        exports=exports,
        artifacts=artifacts,
        warnings=warnings,
    )


def _is_symbol_shaped(entry: object) -> bool:
    return isinstance(entry, dict) and "name" in entry
