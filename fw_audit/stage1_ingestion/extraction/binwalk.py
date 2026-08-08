"""binwalk outcome parsing.

binwalk frequently exits 0 having found and extracted nothing of use, so
"success" for our purposes is stronger than `returncode == 0`: a *usable*
extraction (an unpacked rootfs, or at least a SquashFS image to unpack) must
also have been produced.

The trigger-policy gate itself (graph.py) is deliberately simple, per the
Stage 1 policy's four rules: `tplink_decrypt` runs iff attempt 1 did **not**
succeed by the definition below **and** the user passed `--tplink`.
`binwalk_indicates_encryption()` is diagnostic only — it enriches the
warning/error message shown to the user, it does not gate the trigger.
"""

from __future__ import annotations

from pathlib import Path

from fw_audit.executors.base import ExecutionResult

# Patterns in binwalk's stdout/stderr that plausibly indicate an encrypted or
# vendor-wrapped image. Deliberately small and conservative — refine this
# list as real firmware samples are run through the pipeline. A false
# positive here just adds context to a message; it never itself triggers or
# blocks the decrypt step (see module docstring).
_ENCRYPTION_INDICATORS: tuple[str, ...] = (
    "encrypt",
    "invalid squashfs",
    "invalid data",
    "unknown compression",
    "no valid",
)


def find_squashfs_candidates(extract_dir: Path) -> list[Path]:
    """Locate likely SquashFS images produced by a binwalk extraction."""
    if not extract_dir.exists():
        return []
    candidates: list[Path] = []
    for pattern in ("*.squashfs", "*squashfs*"):
        candidates.extend(p for p in extract_dir.rglob(pattern) if p.is_file())
    return candidates


def find_extracted_rootfs(extract_dir: Path) -> Path | None:
    """Locate an already-unpacked rootfs directory (has bin/ or sbin/ at some depth)."""
    if not extract_dir.exists():
        return None
    for candidate in extract_dir.rglob("*"):
        if (
            candidate.is_dir()
            and candidate.name in {"bin", "sbin"}
            and candidate.parent != candidate
        ):
            return candidate.parent
    return None


def binwalk_succeeded(result: ExecutionResult, extract_dir: Path) -> bool:
    """True iff binwalk exited cleanly AND produced a usable extraction."""
    if not result.ok:
        return False
    return find_extracted_rootfs(extract_dir) is not None or bool(
        find_squashfs_candidates(extract_dir)
    )


def binwalk_indicates_encryption(result: ExecutionResult) -> bool:
    """Best-effort: does binwalk's output suggest an encrypted/wrapped image?

    Diagnostic only (see module docstring) — used to make the
    `fail_unsupported` / decrypt-trigger warning message more specific, not
    to gate any branch of the trigger policy.
    """
    haystack = (result.stdout + result.stderr).lower()
    return any(indicator in haystack for indicator in _ENCRYPTION_INDICATORS)
