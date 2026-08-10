"""Integration tests for Stage 2 against a real Ghidra image / real firmware.

All three require Docker and the `fw-audit-ghidra:latest` image built
(`docker build -f docker/Dockerfile.ghidra -t fw-audit-ghidra:latest .`,
~10 min, ~2.2 GB) — this suite cannot make any of them pass on its own; see
each test's skip message for exactly what's missing when it does skip.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from fw_audit.config.settings import Settings
from fw_audit.stage2_extraction.extract import run_extraction

_IMAGE_NOT_BUILT_MESSAGE = (
    "fw-audit-ghidra:latest is not built. Build it first: "
    "docker build -f docker/Dockerfile.ghidra -t fw-audit-ghidra:latest . "
    "(~10 min, ~2.2 GB)."
)


def _ghidra_image_available() -> bool:
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", "fw-audit-ghidra:latest"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        return proc.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


@pytest.mark.integration
def test_ghidra_image_available():
    if not _ghidra_image_available():
        pytest.skip(_IMAGE_NOT_BUILT_MESSAGE)


@pytest.mark.integration
async def test_decompiles_a_real_elf(tmp_path: Path):
    """Decompile /bin/ls FROM INSIDE the Ghidra image itself — no firmware
    fixture needed, only Docker. Proves the whole chain end to end: the
    image's PyGhidra/JPype install works, fw_audit_export.py runs, and the
    normalizer actually strips every `undefined`-family type real Ghidra
    output contains."""
    if not _ghidra_image_available():
        pytest.skip(_IMAGE_NOT_BUILT_MESSAGE)

    # rootfs MUST live under db_subfolder, not beside it — DockerExecutor
    # bind-mounts only db_subfolder (see decompile_binary's `files=workspace`),
    # and to_container_path()'s containment check will (correctly) reject
    # anything outside that mount. This mirrors how Stage 1 always lays
    # things out for real (rootfs is always a subdirectory of db_subfolder).
    db_subfolder = tmp_path / "db"
    rootfs = db_subfolder / "rootfs" / "bin"
    rootfs.mkdir(parents=True)
    # Copy /bin/ls out of the Ghidra image itself, so this test needs
    # nothing but Docker — no real firmware fixture required.
    copy = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{db_subfolder}:/out", "fw-audit-ghidra:latest",
         "sh", "-c", "cp /bin/ls /out/rootfs/bin/ls || cp /bin/true /out/rootfs/bin/ls"],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert copy.returncode == 0, copy.stderr.decode(errors="replace")
    (db_subfolder / "tree.txt").write_text(f"{rootfs}\nls\n", encoding="utf-8")
    stage1_summary_path = db_subfolder / "stage1_summary.json"
    stage1_summary_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "tree_txt_path": str(db_subfolder / "tree.txt"),
                "rootfs_dir": str(rootfs),
                "identified_binaries": [{"path": "ls"}],
            }
        ),
        encoding="utf-8",
    )

    settings = Settings(_env_file=None, FWA_GHIDRA_TIMEOUT_SECONDS=900)
    summary = await run_extraction(stage1_summary_path=stage1_summary_path, settings=settings)

    assert summary.binaries, "expected exactly one decompiled binary"
    binary = summary.binaries[0]
    print(
        f"\nDecompiled {binary.rootfs_path}: status={binary.status}, "
        f"functions={binary.function_count}"
    )

    metadata_path = Path(summary.db_subfolder) / binary.artifacts.metadata_json
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert len(metadata.get("functions", [])) > 0, "expected real Ghidra output to find functions"

    raw_c_path = Path(summary.db_subfolder) / binary.artifacts.raw_c
    raw_text = raw_c_path.read_text(encoding="utf-8", errors="replace")
    assert "undefined" in raw_text, (
        "expected real (unnormalized) Ghidra output to use undefined-family types"
    )

    joern_path = Path(summary.db_subfolder) / binary.artifacts.normalized_joern_c
    joern_text = joern_path.read_text(encoding="utf-8", errors="replace")
    assert "typedef uint32_t undefined4;" in joern_text  # prelude inlined
    assert "::" not in joern_text


@pytest.mark.integration
async def test_stage2_on_real_firmware(real_firmware_path: Path | None):
    """Full chain after a REAL Stage 1 CLI run.

    Deliberately does NOT call `run_ingestion()` directly — only
    `fw-ingest`'s CLI `main()` writes `stage1_summary.json` (a known Stage 1
    quirk: `runner.run_ingestion()` returns the graph's final state dict but
    never persists it). So this test expects the user to have already run
    `fw-ingest <firmware>` for real, and looks for the summary at the
    conventional location it leaves behind.
    """
    if real_firmware_path is None:
        pytest.skip(
            "No real firmware image found. Set FWA_TEST_FIRMWARE or place an "
            "image under tests/fixtures/ to run this test."
        )
    if not _ghidra_image_available():
        pytest.skip(_IMAGE_NOT_BUILT_MESSAGE)

    settings = Settings(_env_file=None)
    db_subfolder = settings.database_path / real_firmware_path.stem
    stage1_summary_path = db_subfolder / "stage1_summary.json"
    if not stage1_summary_path.is_file():
        pytest.skip(
            f"No stage1_summary.json at {stage1_summary_path}. Run "
            f"`fw-ingest {real_firmware_path}` first, then re-run this test."
        )
    summary = await run_extraction(stage1_summary_path=stage1_summary_path, settings=settings)

    print(f"\nStage 2 status: {summary.status}")
    for b in summary.binaries[:10]:
        print(f"  {b.rootfs_path}  [{b.status}]  {b.function_count} functions")

    assert summary.status is not None
