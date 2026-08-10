"""Turn Stage 1's untrusted, LLM-authored `IdentifiedBinary.path` entries
into verified bytes on disk.

Contract: `resolve_binaries` never raises and never fails the run — a
hallucinated, malformed, or missing path is expected input (the Identifier
Agent's output is never validated by Stage 1; see `IdentifiedBinary.path`'s
docstring in `common/schemas.py`), not a bug. Every entry ends up either in
`ResolutionReport.resolved` or `ResolutionReport.unresolved`, and the report
is written verbatim to `stage2/resolution_report.json` as the audit trail of
what Stage 2 actually looked at versus what Stage 1 asked for.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from fw_audit.common.constants import ROOTFS_SKIP_DIRS
from fw_audit.common.schemas import (
    ELFInfo,
    IdentifiedBinary,
    UnresolvedBinaryRecord,
    extension_from_path,
)
from fw_audit.stage1_ingestion.tools.filesystem_tools import ELFParseError, is_elf, parse_elf_header

_DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:")
_URL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_MAX_SYMLINK_HOPS = 12

# Only these extensions get sent to Ghidra, on top of the existing is_elf
# gate — an ELF-magic'd hit with an extension outside this set (e.g. a
# stray ".debug" symbol file or ".prog" vendor blob) is still recorded, just
# as unresolved rather than decompiled.
_ALLOWED_EXTENSIONS = frozenset({"", ".so", ".ko", ".bin", ".elf"})


def _extension_allowed(path: Path) -> bool:
    """True for `.so` (including versioned shared libraries like
    `libc.so.6` — matched via the FIRST suffix, not `Path.suffix`'s last
    one, so the trailing version number doesn't hide the `.so`), `.ko`
    (kernel modules), `.bin` (generic firmware blobs), or no extension at
    all (the common case for a compiled ELF executable in an embedded
    Linux rootfs, e.g. `busybox`, `httpd`)."""
    suffixes = path.suffixes
    if not suffixes:
        return True
    return suffixes[0].lower() in _ALLOWED_EXTENSIONS


class Resolution(str, Enum):
    """How a `ResolvedBinary` was found."""

    DIRECT = "direct"
    SYMLINK = "symlink"
    BASENAME_RESCAN = "basename_rescan"


@dataclass(frozen=True)
class ResolvedBinary:
    """One `IdentifiedBinary` successfully turned into verified host bytes."""

    requested: str
    host_path: Path
    rootfs_rel: str
    sha256: str
    size_bytes: int
    elf: ELFInfo | None
    resolution: Resolution
    symlink_chain: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    """Other requested paths that deduped onto this same file (identical
    host_path, or identical content by sha256 — the busybox-applet case)."""

    def to_json_dict(self) -> dict:
        return {
            "requested": self.requested,
            # Derived from `requested` on demand, not stored — see
            # `extension_from_path`'s docstring.
            "extension": extension_from_path(self.requested),
            "host_path": str(self.host_path),
            "rootfs_rel": self.rootfs_rel,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "elf": self.elf.model_dump(mode="json") if self.elf is not None else None,
            "resolution": self.resolution.value,
            "symlink_chain": list(self.symlink_chain),
            "aliases": list(self.aliases),
        }


@dataclass(frozen=True)
class ResolutionReport:
    """The full outcome of `resolve_binaries`: what resolved, what didn't,
    and why. Serialized verbatim to `stage2/resolution_report.json`."""

    resolved: tuple[ResolvedBinary, ...]
    unresolved: tuple[UnresolvedBinaryRecord, ...]
    warnings: tuple[str, ...]

    def to_json_dict(self) -> dict:
        return {
            "resolved": [r.to_json_dict() for r in self.resolved],
            "unresolved": [u.model_dump(mode="json") for u in self.unresolved],
            "warnings": list(self.warnings),
        }


def resolve_binaries(
    identified: Sequence[IdentifiedBinary],
    rootfs_dir: Path,
    *,
    max_binaries: int,
    max_rescan_files: int,
) -> ResolutionReport:
    """Resolve every `IdentifiedBinary` against `rootfs_dir`.

    Ordered per entry: normalize the path -> walk symlinks (re-rooted inside
    `rootfs_dir`, never followed onto the host) -> on a miss, fall back to a
    lazily-built basename index -> reject non-ELF hits -> dedupe by host
    path and then by content hash. See the module docstring for the
    never-raises contract.
    """
    warnings: list[str] = []
    unresolved: list[UnresolvedBinaryRecord] = []
    hits: list[tuple[IdentifiedBinary, _Hit]] = []
    basename_index: dict[str, list[str]] | None = None

    for item in identified:
        rel_posix, problem = _normalize(item.path)
        if problem is not None:
            unresolved.append(UnresolvedBinaryRecord(requested_path=item.path, problem=problem))
            continue
        assert rel_posix is not None  # guaranteed by _normalize's contract

        hit, walk_problem = _resolve_direct_or_symlink(rootfs_dir, rel_posix)
        if walk_problem is not None:
            unresolved.append(
                UnresolvedBinaryRecord(requested_path=item.path, problem=walk_problem)
            )
            continue

        if hit is None:
            if basename_index is None:
                basename_index = _build_basename_index(
                    rootfs_dir, ROOTFS_SKIP_DIRS, max_rescan_files
                )
            hit, rescan_problem, rescan_warning = _basename_rescan(
                rootfs_dir, rel_posix, basename_index
            )
            if rescan_problem is not None:
                unresolved.append(
                    UnresolvedBinaryRecord(requested_path=item.path, problem=rescan_problem)
                )
                continue
            if rescan_warning is not None:
                warnings.append(f"{item.path!r}: {rescan_warning}")

        assert hit is not None  # narrowed by the two branches above
        if not is_elf(hit.host_path):
            unresolved.append(
                UnresolvedBinaryRecord(requested_path=item.path, problem="not_an_elf")
            )
            continue

        if not _extension_allowed(hit.host_path):
            unresolved.append(
                UnresolvedBinaryRecord(requested_path=item.path, problem="disallowed_extension")
            )
            continue

        hits.append((item, hit))

    resolved = _dedupe_and_hash(hits, warnings)

    if len(resolved) > max_binaries:
        overflow, resolved = resolved[max_binaries:], resolved[:max_binaries]
        warnings.append(
            f"{len(overflow)} resolved binaries exceeded stage2_max_binaries="
            f"{max_binaries} and were dropped: {[r.requested for r in overflow]}."
        )

    return ResolutionReport(
        resolved=tuple(resolved), unresolved=tuple(unresolved), warnings=tuple(warnings)
    )


# --------------------------------------------------------------------- #
# Path normalization
# --------------------------------------------------------------------- #


def _normalize(raw: str) -> tuple[str | None, str | None]:
    """Return `(normalized_posix_rel_path, None)` or `(None, problem_code)`.

    A leading `/` is stripped rather than rejected — it's the single most
    common benign deviation from the "rootfs-relative" prompt convention an
    LLM produces. `..` components are rejected outright here as defense in
    depth; the symlink walk re-checks containment regardless.
    """
    candidate = raw.strip()
    if not candidate:
        return None, "empty_path"
    if "\x00" in candidate:
        return None, "not_a_rootfs_path"
    if _DRIVE_PREFIX_RE.match(candidate) or _URL_SCHEME_RE.match(candidate):
        return None, "not_a_rootfs_path"

    posix = candidate.replace("\\", "/")
    while "//" in posix:
        posix = posix.replace("//", "/")
    posix = posix.strip("/")
    while posix.startswith("./"):
        posix = posix[2:].lstrip("/")

    if not posix or posix in (".", ".."):
        return None, "not_a_rootfs_path"
    if ".." in posix.split("/"):
        return None, "not_a_rootfs_path"

    return posix, None


# --------------------------------------------------------------------- #
# Symlink walk (manual — Path.resolve() would follow an absolute symlink
# target onto the HOST filesystem, which is both a containment violation
# and semantically wrong for a firmware rootfs)
# --------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Hit:
    host_path: Path
    rootfs_rel: str
    resolution: Resolution
    symlink_chain: tuple[str, ...]


def _is_within(path: Path, root: Path) -> bool:
    """Textual containment check via `os.path.normpath` — no filesystem
    access, so it catches a `..` escape even when the target doesn't exist.
    `normcase` makes the comparison case-insensitive on Windows, a no-op
    elsewhere."""
    root_norm = os.path.normpath(str(root))
    path_norm = os.path.normpath(str(path))
    try:
        common = os.path.commonpath([root_norm, path_norm])
    except ValueError:
        return False  # e.g. different drives on Windows
    return os.path.normcase(common) == os.path.normcase(root_norm)


def _walk_symlinks(
    rootfs_dir: Path, rel_posix: str
) -> tuple[Path | None, tuple[str, ...], str | None]:
    """Manually walk symlinks from `rootfs_dir / rel_posix`, re-rooting any
    absolute link target inside `rootfs_dir` instead of following it onto
    the host. Returns `(final_path_or_None, hop_chain, problem_or_None)`."""
    current = rootfs_dir / rel_posix
    chain: list[str] = []

    for _ in range(_MAX_SYMLINK_HOPS):
        if not _is_within(current, rootfs_dir):
            return None, tuple(chain), "escapes_rootfs"
        if not current.is_symlink():
            return current, tuple(chain), None
        try:
            target = current.readlink()
        except OSError:
            return None, tuple(chain), "unreadable_symlink"

        # A POSIX-style leading "/" always means "absolute within the
        # firmware rootfs", regardless of the host OS — `target.is_absolute()`
        # is unusable here since Windows' pathlib does not consider
        # "/bin/busybox" absolute (no drive letter), but that is exactly
        # what a router firmware's symlink means.
        target_str = str(target).replace("\\", "/")
        if target_str.startswith("/"):
            current = rootfs_dir / target_str.lstrip("/")
        else:
            current = current.parent / target
        current = Path(os.path.normpath(str(current)))
        chain.append(target_str)

    return None, tuple(chain), "symlink_loop"


def _is_file_safe(path: Path) -> bool:
    """`Path.is_file()` (a `stat()`) can raise `OSError` for an entry that
    exists in the directory listing but can't actually be stat'd —
    confirmed against a real firmware rootfs on Windows as WinError 1920
    for `.../squashfs-root/debug`. Same symptom `filesystem_tools`'s
    `_is_dir_safe` guards against for a genuinely dangling relative
    symlink (`debug -> sys/kernel/debug`, unpopulated because sysfs is
    normally filled in by a running kernel, absent from a static extracted
    image) — but here `path.is_symlink()` is confirmed `False`, so the
    real `debug` entry is something else `unsquashfs` materialized that
    Windows can't represent as a regular file either (most likely a
    device/socket/FIFO special file from the original Linux rootfs). The
    `is_symlink()` short-circuit is kept anyway since it's a real,
    free-of-a-syscall-round-trip case (`lstat`, never follows), but the
    `try/except OSError` is what actually catches this specific one — it's
    the backstop that matters, not just a defensive nicety."""
    if path.is_symlink():
        return False
    try:
        return path.is_file()
    except OSError:
        return False


def _resolve_direct_or_symlink(rootfs_dir: Path, rel_posix: str) -> tuple[_Hit | None, str | None]:
    """`(hit, None)` on success, `(None, problem)` on a hard failure
    (escape/loop/unreadable), or `(None, None)` meaning "not found here,
    try the basename rescan fallback"."""
    final, chain, problem = _walk_symlinks(rootfs_dir, rel_posix)
    if problem is not None:
        return None, problem
    # `final` is already guaranteed non-symlink by `_walk_symlinks`'s exit
    # condition, but `_is_file_safe`'s try/except backstop is kept anyway
    # for any other unresolvable-entry case beyond a dangling symlink.
    if final is None or not _is_file_safe(final):
        return None, None
    rootfs_rel = os.path.relpath(str(final), str(rootfs_dir)).replace("\\", "/")
    resolution = Resolution.SYMLINK if chain else Resolution.DIRECT
    hit = _Hit(host_path=final, rootfs_rel=rootfs_rel, resolution=resolution, symlink_chain=chain)
    return hit, None


# --------------------------------------------------------------------- #
# Basename rescan fallback (recovers a hallucinated directory, e.g.
# "usr/sbin/httpd" when the real path is "bin/httpd")
# --------------------------------------------------------------------- #


def _build_basename_index(
    rootfs_dir: Path, skip_dirs: frozenset[str], max_files: int
) -> dict[str, list[str]]:
    """`{basename: [rootfs-relative paths]}` over `rootfs_dir`, built once
    lazily per run. Uses `os.walk(followlinks=False)` — not `Path.rglob`,
    which has no built-in symlink-loop guard — since a self-referential
    rootfs symlink is a real risk with untrusted firmware (see
    `filesystem_tools.write_tree_txt`'s identical concern)."""
    index: dict[str, list[str]] = {}
    count = 0
    for dirpath, dirnames, filenames in os.walk(str(rootfs_dir), followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        if count >= max_files:
            break
        for fname in filenames:
            if count >= max_files:
                break
            full = Path(dirpath) / fname
            if not _is_file_safe(full):
                continue
            rel = full.relative_to(rootfs_dir).as_posix()
            index.setdefault(fname, []).append(rel)
            count += 1
    return index


def _score_common_suffix(requested_rel: str, candidate_rel: str) -> int:
    """Number of matching path components counted from the right —
    disambiguates multiple basename hits by how much of the requested
    directory structure the candidate also matches."""
    score = 0
    req_parts = reversed(requested_rel.split("/"))
    cand_parts = reversed(candidate_rel.split("/"))
    for a, b in zip(req_parts, cand_parts, strict=False):
        if a != b:
            break
        score += 1
    return score


def _basename_rescan(
    rootfs_dir: Path, rel_posix: str, index: dict[str, list[str]]
) -> tuple[_Hit | None, str | None, str | None]:
    """`(hit, None, warning)` on a resolved rescan, `(None, problem, None)`
    on failure."""
    basename = rel_posix.rsplit("/", 1)[-1]
    candidates = index.get(basename, [])
    if not candidates:
        return None, "not_found", None

    if len(candidates) == 1:
        chosen = candidates[0]
        warning = f"not found directly; recovered via basename rescan as {chosen!r}."
    else:
        scored = sorted(
            ((c, _score_common_suffix(rel_posix, c)) for c in candidates),
            key=lambda pair: pair[1],
            reverse=True,
        )
        best_score = scored[0][1]
        best = [c for c, s in scored if s == best_score]
        if len(best) != 1:
            return None, f"ambiguous_basename: candidates={candidates}", None
        chosen = best[0]
        warning = (
            f"not found directly; recovered via basename rescan as {chosen!r} "
            f"(disambiguated among {len(candidates)} candidates)."
        )

    hit = _Hit(
        host_path=rootfs_dir / chosen,
        rootfs_rel=chosen,
        resolution=Resolution.BASENAME_RESCAN,
        symlink_chain=(),
    )
    return hit, None, warning


# --------------------------------------------------------------------- #
# Dedupe + hashing
# --------------------------------------------------------------------- #


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_parse_elf(path: Path) -> ELFInfo | None:
    """Ghidra's own loader is more tolerant than this 100-line parser — a
    header it can't fully parse is kept (with `elf=None`), never dropped."""
    try:
        return parse_elf_header(path)
    except (ELFParseError, OSError):
        return None


def _add_alias(resolved: ResolvedBinary, alias_path: str) -> ResolvedBinary:
    if alias_path == resolved.requested or alias_path in resolved.aliases:
        return resolved
    return dataclasses.replace(resolved, aliases=(*resolved.aliases, alias_path))


def _dedupe_and_hash(
    hits: list[tuple[IdentifiedBinary, _Hit]], warnings: list[str]
) -> list[ResolvedBinary]:
    """Single pass, immutable: fold a hit into an existing `ResolvedBinary`
    (via `dataclasses.replace`, never in-place mutation) when its resolved
    host path, or its content hash, matches one already seen. The
    content-hash fold is the busybox case — N applets symlinked to one
    binary must decompile once, not N times."""
    results: list[ResolvedBinary] = []
    index_by_host_path: dict[str, int] = {}
    index_by_sha256: dict[str, int] = {}

    for item, hit in hits:
        host_key = str(hit.host_path.resolve())

        existing = index_by_host_path.get(host_key)
        if existing is not None:
            results[existing] = _add_alias(results[existing], item.path)
            warnings.append(
                f"{item.path!r} is the same file as an already-resolved binary; "
                "folded into aliases."
            )
            continue

        try:
            sha256 = _sha256_of(hit.host_path)
            size_bytes = hit.host_path.stat().st_size
        except OSError as exc:
            warnings.append(f"could not read {hit.host_path} ({item.path!r}): {exc}; skipped.")
            continue

        existing = index_by_sha256.get(sha256)
        if existing is not None:
            results[existing] = _add_alias(results[existing], item.path)
            index_by_host_path[host_key] = existing
            warnings.append(
                f"{item.path!r} is content-identical (sha256) to an already-resolved "
                "binary (likely a busybox-style symlink); folded into aliases instead "
                "of a duplicate decompilation run."
            )
            continue

        new_index = len(results)
        results.append(
            ResolvedBinary(
                requested=item.path,
                host_path=hit.host_path,
                rootfs_rel=hit.rootfs_rel,
                sha256=sha256,
                size_bytes=size_bytes,
                elf=_safe_parse_elf(hit.host_path),
                resolution=hit.resolution,
                symlink_chain=hit.symlink_chain,
            )
        )
        index_by_host_path[host_key] = new_index
        index_by_sha256[sha256] = new_index

    return results
