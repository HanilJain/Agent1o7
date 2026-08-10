# scratch_identify.py
#
# Runs only the Identifier Agent (Component 2) against an existing tree.txt,
# skipping the rest of Stage 1 (no Docker, no binwalk/unsquashfs), and writes
# a stage1_summary.json in exactly the shape fw-ingest itself would produce
# (see fw_audit/stage1_ingestion/runner.py::main) using the real Stage1Summary
# schema — not a hand-rolled dict — so Stage 2 (fw-extract) can consume it
# unmodified.
import asyncio
import time
import uuid
from pathlib import Path

from fw_audit.common.schemas import Stage1Summary, extension_from_path
from fw_audit.stage1_ingestion.identifier.agent import identify_binaries
from fw_audit.stage1_ingestion.state import IngestionStatus

TREE_PATH = Path("C:\\Users\\Asus\\NULLVOID\\SUTD\\Agent1o7\\tests\\tree_test.txt")


async def main():
    tree_text = TREE_PATH.read_text(encoding="utf-8")
    print(f"tree.txt: {len(tree_text)} chars, {tree_text.count(chr(10))} lines")

    t0 = time.monotonic()
    result = await identify_binaries(tree_text)
    print(f"Done in {time.monotonic() - t0:.1f}s -- {len(result)} binaries identified")
    for b in result:
        print(" -", b.path, "|", extension_from_path(b.path) or "(no extension)")

    # Mirrors write_tree_txt's convention: line 1 of tree.txt is always the
    # rootfs root (see filesystem_tools.py::write_tree_txt) — reading it back
    # out here is how Stage 2's stage1_io fallback chain is meant to be fed
    # when a real Stage 1 run wrote this file.
    rootfs_dir = tree_text.splitlines()[0].strip() if tree_text.strip() else None

    db_subfolder = TREE_PATH.parent
    summary = Stage1Summary(
        run_id=uuid.uuid4().hex[:12],
        status=IngestionStatus.COMPLETED.value,
        db_subfolder=str(db_subfolder),
        tree_txt_path=str(TREE_PATH),
        rootfs_dir=rootfs_dir,
        identified_binaries=result,
        warnings=[],
        errors=[],
    )

    summary_path = db_subfolder / "stage1_summary.json"
    summary_path.write_text(summary.model_dump_json(indent=2), encoding="utf-8")
    print(f"\nMachine-readable summary: {summary_path}")


asyncio.run(main())
