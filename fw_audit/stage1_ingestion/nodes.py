"""LangGraph node functions for Stage 1.

Implements the ordered procedure from the Stage 1 policy doc:

    initialize -> unzip_and_binwalk_1 -> [tplink_decrypt_and_binwalk_2]? -> generate_tree
               -> identify_binaries -> finalize
                                    -> fail_unsupported (terminal, on any hard failure)

The four-rule trigger policy (`tplink_decrypt_and_binwalk_2` only runs on
attempt-1 failure *and* the explicit `--tplink` flag) is expressed as
conditional edges in `graph.py`, not here — these functions only run one
step and report what happened via a partial state update.

Component boundary: every node up to and including `generate_tree` is
Component 1 (Extraction Script) — it holds an `Executor` (sandbox access)
and never touches an LLM. `identify_binaries` is Component 2 (Identifier
Agent) — it reads `tree_txt_path`'s *content* only, holds no executor, and
never touches the Database directly.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from fw_audit.common.schemas import ExtractionArtifact, ExtractionArtifactKind, FirmwareMetadata
from fw_audit.executors import get_executor
from fw_audit.stage1_ingestion.extraction.binwalk import (
    binwalk_indicates_encryption,
    binwalk_succeeded,
    find_extracted_rootfs,
    find_squashfs_candidates,
)
from fw_audit.stage1_ingestion.extraction.script import (
    BINWALK_1_DIR,
    BINWALK_2_DIR,
    DECRYPTED_DIR,
    binwalk_attempt,
    binwalk_target,
    stage_firmware,
    tplink_decrypt,
    unsquashfs_fallback,
    unzip_archive,
)
from fw_audit.stage1_ingestion.identifier.agent import IdentifierUnavailableError, identify_binaries as _identify
from fw_audit.stage1_ingestion.state import FirmwareIngestionState, IngestionStatus
from fw_audit.stage1_ingestion.tools.filesystem_tools import write_tree_txt

UNSUPPORTED_MESSAGE = "squashfs filesystem not found or not supported"


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


async def initialize(state: FirmwareIngestionState) -> dict:
    """Validate the input, compute metadata, and stage firmware into the Database."""
    firmware_path = Path(state["firmware_path"])
    workspace = Path(state["db_subfolder"])

    if not firmware_path.is_file():
        return {
            "status": IngestionStatus.FAILED,
            "errors": [f"firmware_path does not exist or is not a file: {firmware_path}"],
        }

    executor = get_executor()
    if not executor.available():
        return {
            "status": IngestionStatus.FAILED,
            "errors": [
                f"Execution backend unavailable ({type(executor).__name__}); "
                "if using the default 'docker' backend, start the Docker daemon "
                "and ensure the fw-audit-sandbox image is built "
                "(docker build -f docker/Dockerfile -t fw-audit-sandbox:latest .)."
            ],
        }

    metadata = FirmwareMetadata(
        original_filename=firmware_path.name,
        size_bytes=firmware_path.stat().st_size,
        sha256=_sha256_of(firmware_path),
    )
    staged_name = stage_firmware(firmware_path, workspace)

    return {
        "status": IngestionStatus.STAGING,
        "firmware_metadata": metadata,
        "staged_firmware_name": staged_name,
        "warnings": [],
    }


async def unzip_and_binwalk_1(state: FirmwareIngestionState) -> dict:
    """Step 1-2: best-effort unzip, then the first binwalk attempt."""
    if state.get("status") == IngestionStatus.FAILED:
        return {}

    workspace = Path(state["db_subfolder"])
    staged_name = state["staged_firmware_name"]
    executor = get_executor()
    artifacts: list[ExtractionArtifact] = []

    unzip_result = await unzip_archive(executor, workspace, staged_name)
    artifacts.append(
        ExtractionArtifact(
            kind=ExtractionArtifactKind.UNZIP,
            path=str(workspace / "raw_extract"),
            source_tool="unzip",
            success=unzip_result.ok,
            notes=unzip_result.stderr or None,
        )
    )

    target = binwalk_target(workspace, staged_name)
    result = await binwalk_attempt(executor, workspace, target, BINWALK_1_DIR)
    artifacts.append(
        ExtractionArtifact(
            kind=ExtractionArtifactKind.BINWALK,
            path=str(workspace / BINWALK_1_DIR),
            source_tool="binwalk",
            success=binwalk_succeeded(result, workspace / BINWALK_1_DIR),
            notes=result.stderr or None,
        )
    )

    return {
        "status": IngestionStatus.BINWALK_ATTEMPT_1,
        "binwalk_1_result": result,
        "binwalk_1_target": target,
        "artifacts": artifacts,
    }


async def tplink_decrypt_and_binwalk_2(state: FirmwareIngestionState) -> dict:
    """Decrypt (rule 3: decrypt THEN re-run binwalk), only reached per the trigger policy."""
    workspace = Path(state["db_subfolder"])
    target = state["binwalk_1_target"]
    executor = get_executor()
    artifacts: list[ExtractionArtifact] = []
    warnings: list[str] = []

    decrypt_result = await tplink_decrypt(executor, workspace, target)
    artifacts.append(
        ExtractionArtifact(
            kind=ExtractionArtifactKind.VENDOR_DECRYPT,
            path=str(workspace / DECRYPTED_DIR),
            source_tool="tp-link-decrypt",
            success=decrypt_result.ok,
            notes=decrypt_result.stderr or None,
        )
    )
    if not decrypt_result.ok:
        warnings.append(f"tp-link-decrypt failed: {decrypt_result.stderr}")

    decrypted_dir = workspace / DECRYPTED_DIR
    decrypted_files = [p for p in decrypted_dir.rglob("*") if p.is_file()] if decrypted_dir.exists() else []
    binwalk_2_target = (
        f"{DECRYPTED_DIR}/{max(decrypted_files, key=lambda p: p.stat().st_size).relative_to(decrypted_dir).as_posix()}"
        if decrypted_files
        else target
    )

    binwalk_2_result = await binwalk_attempt(executor, workspace, binwalk_2_target, BINWALK_2_DIR)
    artifacts.append(
        ExtractionArtifact(
            kind=ExtractionArtifactKind.BINWALK,
            path=str(workspace / BINWALK_2_DIR),
            source_tool="binwalk",
            success=binwalk_succeeded(binwalk_2_result, workspace / BINWALK_2_DIR),
            notes=binwalk_2_result.stderr or None,
        )
    )

    return {
        "status": IngestionStatus.BINWALK_ATTEMPT_2,
        "decrypt_result": decrypt_result,
        "binwalk_2_result": binwalk_2_result,
        "artifacts": artifacts,
        "warnings": warnings,
    }


async def fail_unsupported(state: FirmwareIngestionState) -> dict:
    """Terminal failure: no usable extraction, and either no --tplink flag or decrypt didn't help."""
    if state.get("status") == IngestionStatus.FAILED:
        return {}

    result = state.get("binwalk_2_result") or state.get("binwalk_1_result")
    detail = ""
    if result is not None and binwalk_indicates_encryption(result):
        detail = " (binwalk output suggests the image may be encrypted or vendor-wrapped)"

    return {
        "status": IngestionStatus.FAILED,
        "errors": [f"{UNSUPPORTED_MESSAGE}{detail}"],
    }


async def generate_tree(state: FirmwareIngestionState) -> dict:
    """Locate the unpacked rootfs and write the enriched tree.txt (Hand-off 1)."""
    workspace = Path(state["db_subfolder"])
    out_dir_name = BINWALK_2_DIR if state.get("binwalk_2_result") is not None else BINWALK_1_DIR
    out_dir = workspace / out_dir_name

    rootfs_dir = find_extracted_rootfs(out_dir)
    artifacts: list[ExtractionArtifact] = []

    if rootfs_dir is None:
        squashfs_candidates = find_squashfs_candidates(out_dir)
        if squashfs_candidates:
            executor = get_executor()
            fallback_dir_name = f"{out_dir_name}_unsquashed"
            squashfs_rel = f"{out_dir_name}/{squashfs_candidates[0].relative_to(out_dir).as_posix()}"
            result = await unsquashfs_fallback(executor, workspace, squashfs_rel, fallback_dir_name)
            artifacts.append(
                ExtractionArtifact(
                    kind=ExtractionArtifactKind.UNSQUASHFS,
                    path=str(workspace / fallback_dir_name),
                    source_tool="unsquashfs/sasquatch",
                    success=result.ok,
                    notes=result.stderr or None,
                )
            )
            rootfs_dir = find_extracted_rootfs(workspace / fallback_dir_name) or (workspace / fallback_dir_name)
        else:
            rootfs_dir = out_dir  # last resort: scan whatever binwalk produced directly

    tree_path = workspace / "tree.txt"
    write_tree_txt(rootfs_dir, tree_path)
    artifacts.append(
        ExtractionArtifact(
            kind=ExtractionArtifactKind.TREE_LISTING,
            path=str(tree_path),
            source_tool="fw_audit.filesystem_tools",
            success=True,
        )
    )

    return {
        "status": IngestionStatus.GENERATING_TREE,
        "tree_txt_path": str(tree_path),
        "artifacts": artifacts,
    }


async def identify_binaries(state: FirmwareIngestionState) -> dict:
    """Component 2: hand tree.txt's content to the Identifier Agent (Hand-off 2).

    Hard-fails the run if no LLM provider is reachable — per policy, the
    Identifier Agent is required, not optional (unlike the old deterministic
    scorer this replaces).
    """
    tree_path = Path(state["tree_txt_path"])
    tree_text = tree_path.read_text(encoding="utf-8")

    try:
        identified = await _identify(tree_text)
    except IdentifierUnavailableError as exc:
        return {
            "status": IngestionStatus.FAILED,
            "errors": [f"Identifier Agent unavailable: {exc}"],
        }

    return {
        "status": IngestionStatus.IDENTIFYING_BINARIES,
        "identified_binaries": identified,
    }


async def finalize(state: FirmwareIngestionState) -> dict:
    """Terminal node."""
    if state.get("status") not in (IngestionStatus.COMPLETED, IngestionStatus.FAILED):
        return {"status": IngestionStatus.COMPLETED}
    return {}
