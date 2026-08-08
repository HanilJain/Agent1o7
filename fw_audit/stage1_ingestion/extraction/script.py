"""The Extraction Script's individual steps (Component 1).

Each function runs one step against an injected `Executor`, using paths
*relative* to `workspace` — the directory the executor exposes as its
working directory (a Docker bind mount for `DockerExecutor`, `cwd` for
`LocalExecutor`). Keeping every command workspace-relative means these
functions work unchanged regardless of which backend answers `executor.run()`.

The conditional branching between these steps — the four-rule trigger policy
governing when `tplink_decrypt` runs — lives in `graph.py`, not here. This
module only knows how to run one step and report what happened.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from fw_audit.executors.base import ExecutionResult, Executor

RAW_EXTRACT_DIR = "raw_extract"
BINWALK_1_DIR = "binwalk_1"
BINWALK_2_DIR = "binwalk_2"
DECRYPTED_DIR = "decrypted"
_INPUT_STEM = "input"


def stage_firmware(firmware_path: Path, workspace: Path) -> str:
    """Copy the raw firmware into `workspace` so the executor's mount can see it.

    A plain host-side file copy — no execution, no parsing of untrusted
    content — so this runs outside any `Executor`, unlike every other
    function in this module. Returns the staged file's name (relative to
    `workspace`) for use in subsequent commands.

    A no-op if `firmware_path` already *is* the destination (e.g. a caller
    re-running ingestion against an already-staged file) — `shutil.copy2`
    would otherwise raise `PermissionError` on Windows for a same-path copy.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    staged_name = f"{_INPUT_STEM}{firmware_path.suffix}"
    dest = workspace / staged_name
    if firmware_path.resolve() != dest.resolve():
        shutil.copy2(firmware_path, dest)
    return staged_name


async def unzip_archive(executor: Executor, workspace: Path, staged_name: str) -> ExecutionResult:
    """Best-effort unzip of the staged firmware file.

    Not every firmware image is a zip archive — most raw `.bin` dumps
    aren't. A failure here is expected and non-fatal: `binwalk_target`
    falls back to the original staged file when this produced nothing.
    """
    return await executor.run(f"unzip -o {staged_name} -d {RAW_EXTRACT_DIR}", files=workspace)


def binwalk_target(workspace: Path, staged_name: str) -> str:
    """Decide what binwalk should scan.

    If `unzip_archive` produced output, binwalk targets the largest file
    found there (the common case: a vendor zips a single firmware image).
    Otherwise it targets the staged firmware file directly.
    """
    extract_dir = workspace / RAW_EXTRACT_DIR
    if extract_dir.exists():
        candidates = [p for p in extract_dir.rglob("*") if p.is_file()]
        if candidates:
            largest = max(candidates, key=lambda p: p.stat().st_size)
            return f"{RAW_EXTRACT_DIR}/{largest.relative_to(extract_dir).as_posix()}"
    return staged_name


async def binwalk_attempt(
    executor: Executor, workspace: Path, target: str, out_dir: str
) -> ExecutionResult:
    """Run `binwalk -e` against `target`, extracting into `out_dir` (workspace-relative)."""
    return await executor.run(f"binwalk -e --run-as=root -C {out_dir} {target}", files=workspace)


async def tplink_decrypt(executor: Executor, workspace: Path, target: str) -> ExecutionResult:
    """Run `tp-link-decrypt` on `target`, writing output into `DECRYPTED_DIR`."""
    return await executor.run(
        f"mkdir -p {DECRYPTED_DIR} && cp {target} {DECRYPTED_DIR}/ && "
        f"cd {DECRYPTED_DIR} && tp-link-decrypt $(basename {target})",
        files=workspace,
    )


async def unsquashfs_fallback(
    executor: Executor, workspace: Path, squashfs_path: str, out_dir: str
) -> ExecutionResult:
    """Explicitly unpack a SquashFS image binwalk found but didn't auto-unpack.

    binwalk's own `-e` extraction rules normally shell out to `unsquashfs`
    automatically when it recognizes a SquashFS signature. This function is
    the *fallback* for when that didn't yield a usable rootfs — e.g. a
    vendor-modified compression scheme stock `unsquashfs` 4.5.1 rejects.
    Tries stock `unsquashfs` first, then `sasquatch` (the patched,
    vendor-quirk-tolerant build) if that fails.
    """
    result = await executor.run(
        f"unsquashfs -f -d {out_dir} {squashfs_path}", files=workspace
    )
    if result.ok:
        return result
    return await executor.run(f"sasquatch -f -d {out_dir} {squashfs_path}", files=workspace)
