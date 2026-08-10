"""LangGraph state schema for Stage 1.

`FirmwareIngestionState` is threaded through every node in the graph
(`stage1_ingestion/graph.py`). Nodes return partial updates (a dict with only
the keys they touch); LangGraph merges them into the running state using the
reducers declared below (list fields accumulate via `operator.add`, everything
else is last-write-wins).

The state's shape mirrors the Component 1 / Component 2 privilege split: the
Extraction Script's fields (binwalk attempts, db_subfolder, tree_txt_path)
are populated with sandbox access; `identified_binaries` is populated by the
Identifier Agent, which never touches any of the extraction fields directly —
it only ever reads `tree_txt_path`'s *content*, handed to it in the same run.
"""

from __future__ import annotations

import operator
from enum import Enum
from typing import Annotated, TypedDict

from fw_audit.common.schemas import ExtractionArtifact, FirmwareMetadata, IdentifiedBinary
from fw_audit.executors.base import ExecutionResult


class IngestionStatus(str, Enum):
    """Coarse-grained lifecycle status of an ingestion run."""

    PENDING = "pending"
    STAGING = "staging"
    UNZIPPING = "unzipping"
    BINWALK_ATTEMPT_1 = "binwalk_attempt_1"
    TPLINK_DECRYPTING = "tplink_decrypting"
    BINWALK_ATTEMPT_2 = "binwalk_attempt_2"
    GENERATING_TREE = "generating_tree"
    IDENTIFYING_BINARIES = "identifying_binaries"
    COMPLETED = "completed"
    FAILED = "failed"


class FirmwareIngestionState(TypedDict, total=False):
    """Shared state for the Stage 1 LangGraph workflow.

    `total=False` so each node can return a partial update dict without
    needing to populate every key.
    """

    # ---- Run identity / input -----------------------------------------
    run_id: str
    firmware_path: str
    """Path to the raw, as-uploaded firmware image (outside the Database)."""
    firmware_metadata: FirmwareMetadata | None
    is_tplink: bool
    """Explicit user-supplied flag — rule 1 of the trigger policy. Never
    inferred from the firmware's contents (that would violate rule 1)."""

    # ---- Database workspace ---------------------------------------------
    db_subfolder: str
    """`data/db/<firmware-stem>/` — bind-mounted to the executor as `/work`;
    every extraction path below is relative to this directory."""
    staged_firmware_name: str | None
    """Firmware's filename inside `db_subfolder`, once staged."""

    # ---- Extraction attempts (Component 1 / Extraction Script) -----------
    binwalk_1_result: ExecutionResult | None
    binwalk_1_target: str | None
    decrypt_result: ExecutionResult | None
    binwalk_2_result: ExecutionResult | None

    # ---- Hand-off 1: filesystem structure -------------------------------
    tree_txt_path: str | None
    """Absolute host path to tree.txt, inside db_subfolder. This is also
    what's read and handed directly to the Identifier Agent in this run."""
    rootfs_dir: str | None
    """Absolute host path to the directory tree.txt is rooted at. Computed
    by `generate_tree` after its four-way search (binwalk rootfs / unsquashfs
    fallback rootfs / the fallback dir itself / out_dir as a last resort).
    Stage 2 cannot reconstruct this by convention — every path in
    `identified_binaries` is relative to it — so it must be published here
    rather than left to be recovered from line 1 of tree.txt."""

    # ---- Hand-off 2: identified binaries (Component 2 / Identifier Agent) -
    identified_binaries: Annotated[list[IdentifiedBinary], operator.add]

    # ---- Audit trail / diagnostics ---------------------------------------
    artifacts: Annotated[list[ExtractionArtifact], operator.add]
    errors: Annotated[list[str], operator.add]
    warnings: Annotated[list[str], operator.add]

    # ---- Status -----------------------------------------------------------
    status: IngestionStatus


def initial_state(
    run_id: str, firmware_path: str, db_subfolder: str, *, is_tplink: bool = False
) -> FirmwareIngestionState:
    """Build the initial state dict to kick off a Stage 1 graph run."""
    return FirmwareIngestionState(
        run_id=run_id,
        firmware_path=firmware_path,
        firmware_metadata=None,
        is_tplink=is_tplink,
        db_subfolder=db_subfolder,
        staged_firmware_name=None,
        binwalk_1_result=None,
        binwalk_1_target=None,
        decrypt_result=None,
        binwalk_2_result=None,
        tree_txt_path=None,
        rootfs_dir=None,
        identified_binaries=[],
        artifacts=[],
        errors=[],
        warnings=[],
        status=IngestionStatus.PENDING,
    )
