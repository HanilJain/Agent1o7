"""Join Stage 1's whitelist (`identified_binaries`) against Stage 2's
verified index (`binaries[]`/`unresolved[]`) — pure, zero filesystem I/O.

Deliberately does not re-walk symlinks or re-normalize `..` components the
way `stage2_extraction.resolve` does: that untrusted-path work is already
done by the time `stage2_summary.json` exists. This module's only job is
matching normalized path strings against each other.
"""

from __future__ import annotations

from dataclasses import dataclass

from fw_audit.common.schemas import DecompiledBinary, Stage1Summary, Stage2Summary
from fw_audit.stage3_analysis.models import SkippedTarget


def normalize_path(raw: str) -> str:
    """The join key: backslashes to forward slashes, leading slash and
    surrounding whitespace stripped, doubled slashes collapsed.

    Does NOT resolve `..` or touch the filesystem — `stage2_extraction.
    resolve` already did the untrusted-path resolution; redoing any of its
    symlink/containment logic here would duplicate it, not add safety.
    """
    posix = raw.strip().replace("\\", "/")
    while "//" in posix:
        posix = posix.replace("//", "/")
    return posix.strip("/")


def build_whitelist(stage1: Stage1Summary, only: tuple[str, ...] = ()) -> frozenset[str]:
    """Normalized paths from `stage1.identified_binaries`, optionally
    intersected with `only` (mirroring `fw-extract --only`'s narrowing)."""
    whitelist = frozenset(normalize_path(b.path) for b in stage1.identified_binaries)
    if not only:
        return whitelist
    only_normalized = frozenset(normalize_path(o) for o in only)
    return whitelist & only_normalized


def _binary_keys(binary: DecompiledBinary) -> frozenset[str]:
    """Every normalized name a whitelist entry could plausibly match this
    binary under: its requested path, its resolved rootfs path, and every
    alias (the busybox-applet case — N shortlisted paths dedupe onto one
    binary; see `DecompiledBinary.aliases`'s docstring)."""
    keys = {normalize_path(binary.requested_path), normalize_path(binary.rootfs_path)}
    keys.update(normalize_path(a) for a in binary.aliases)
    return frozenset(keys)


@dataclass(frozen=True)
class JoinResult:
    matched: tuple[DecompiledBinary, ...]
    skipped: tuple[SkippedTarget, ...]
    orphan_bin_ids: tuple[str, ...]


def join_targets(whitelist: frozenset[str], stage2: Stage2Summary) -> JoinResult:
    """Match `whitelist` entries against `stage2.binaries`, and account for
    every whitelist entry and every Stage 2 binary, whichever side it lands
    on.

    A binary matches when ANY of its requested path, resolved rootfs path,
    or aliases (see `_binary_keys`) normalizes into `whitelist`. Every
    whitelist entry that doesn't match any binary is checked against
    `stage2.unresolved` next (to distinguish "Stage 2 tried and failed" from
    "Stage 2 never saw this at all"), and every `stage2.binaries` entry that
    matches no whitelist entry is reported as an orphan bin_id.
    """
    matched: list[DecompiledBinary] = []
    matched_whitelist_keys: set[str] = set()

    for binary in stage2.binaries:
        keys = _binary_keys(binary)
        if keys & whitelist:
            matched.append(binary)
            matched_whitelist_keys.update(keys & whitelist)

    orphan_bin_ids = tuple(
        b.bin_id for b in stage2.binaries if not (_binary_keys(b) & whitelist)
    )

    unresolved_by_key = {normalize_path(u.requested_path): u for u in stage2.unresolved}

    skipped: list[SkippedTarget] = []
    for entry in sorted(whitelist - matched_whitelist_keys):
        unresolved = unresolved_by_key.get(entry)
        if unresolved is not None:
            skipped.append(
                SkippedTarget(
                    requested_path=entry,
                    reason="unresolved_upstream",
                    detail=unresolved.problem,
                )
            )
        else:
            skipped.append(SkippedTarget(requested_path=entry, reason="not_in_stage2"))

    return JoinResult(
        matched=tuple(matched), skipped=tuple(skipped), orphan_bin_ids=orphan_bin_ids
    )
