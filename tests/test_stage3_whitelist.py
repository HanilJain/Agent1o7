"""Tests for `fw_audit.stage3_analysis.whitelist` — pure join logic, no
filesystem access at all (unlike `test_stage3_ingest.py`, which exercises
the full orchestrator against real files).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fw_audit.common.schemas import (
    DecompilationStatus,
    DecompiledBinary,
    ExtractionStatus,
    IdentifiedBinary,
    Stage1Summary,
    Stage2Summary,
    UnresolvedBinaryRecord,
)
from fw_audit.stage3_analysis.whitelist import build_whitelist, join_targets, normalize_path


def _binary(
    rootfs_path: str,
    *,
    requested_path: str | None = None,
    aliases: list[str] | None = None,
    bin_id: str | None = None,
    status: DecompilationStatus = DecompilationStatus.SUCCEEDED,
) -> DecompiledBinary:
    return DecompiledBinary(
        bin_id=bin_id or rootfs_path.replace("/", "_"),
        rootfs_path=rootfs_path,
        requested_path=requested_path or rootfs_path,
        aliases=aliases or [],
        sha256="0" * 64,
        size_bytes=1024,
        status=status,
    )


def _stage2(
    binaries: list[DecompiledBinary] | None = None,
    unresolved: list[UnresolvedBinaryRecord] | None = None,
) -> Stage2Summary:
    return Stage2Summary(
        run_id="test-run",
        status=ExtractionStatus.COMPLETED,
        db_subfolder="db/fw",
        rootfs_dir="db/fw/binwalk_1/squashfs-root",
        stage2_dir="db/fw/stage2",
        ghidra_image="fw-audit-ghidra:latest",
        binaries=binaries or [],
        unresolved=unresolved or [],
        started_at=datetime.now(UTC),
    )


def _stage1(paths: list[str]) -> Stage1Summary:
    return Stage1Summary(
        status="completed",
        db_subfolder="db/fw",
        identified_binaries=[IdentifiedBinary(path=p) for p in paths],
    )


# --------------------------------------------------------------------- #
# normalize_path
# --------------------------------------------------------------------- #


def test_normalize_path_converts_backslashes():
    assert normalize_path("sbin\\wpasupp") == "sbin/wpasupp"


def test_normalize_path_strips_leading_slash():
    assert normalize_path("/sbin/wpasupp") == "sbin/wpasupp"


def test_normalize_path_collapses_double_slashes():
    assert normalize_path("sbin//wpasupp") == "sbin/wpasupp"


def test_normalize_path_strips_whitespace():
    assert normalize_path("  sbin/wpasupp  ") == "sbin/wpasupp"


def test_normalize_path_does_not_resolve_dotdot():
    # Deliberately NOT this module's job -- stage2_extraction.resolve
    # already did the untrusted-path resolution by the time
    # stage2_summary.json exists; redoing it here would just duplicate it.
    assert normalize_path("../etc/passwd") == "../etc/passwd"


# --------------------------------------------------------------------- #
# build_whitelist
# --------------------------------------------------------------------- #


def test_build_whitelist_normalizes_every_entry():
    stage1 = _stage1(["/sbin/wpasupp", "bin\\httpd"])

    result = build_whitelist(stage1)

    assert result == frozenset({"sbin/wpasupp", "bin/httpd"})


def test_build_whitelist_intersects_with_only():
    stage1 = _stage1(["sbin/wpasupp", "bin/httpd"])

    result = build_whitelist(stage1, only=("bin/httpd",))

    assert result == frozenset({"bin/httpd"})


def test_build_whitelist_only_narrowing_normalizes_too():
    stage1 = _stage1(["sbin/wpasupp"])

    result = build_whitelist(stage1, only=("/sbin/wpasupp",))

    assert result == frozenset({"sbin/wpasupp"})


# --------------------------------------------------------------------- #
# join_targets
# --------------------------------------------------------------------- #


def test_join_targets_direct_match():
    whitelist = frozenset({"sbin/wpasupp"})
    stage2 = _stage2([_binary("sbin/wpasupp")])

    result = join_targets(whitelist, stage2)

    assert [b.rootfs_path for b in result.matched] == ["sbin/wpasupp"]
    assert result.skipped == ()
    assert result.orphan_bin_ids == ()


def test_join_targets_matches_via_alias():
    # The busybox-applet case: N shortlisted paths dedupe onto one binary
    # via DecompiledBinary.aliases, so the whitelist entry that matches an
    # alias (not requested_path/rootfs_path directly) must still resolve.
    whitelist = frozenset({"bin/ls"})
    stage2 = _stage2(
        [_binary("bin/busybox", requested_path="bin/busybox", aliases=["bin/ls", "bin/cat"])]
    )

    result = join_targets(whitelist, stage2)

    assert [b.rootfs_path for b in result.matched] == ["bin/busybox"]


def test_join_targets_matches_via_rootfs_path_basename_rescan():
    # requested_path differs from rootfs_path (a basename-rescan recovery,
    # e.g. Stage 1 hallucinated "usr/sbin/httpd" but it's really "bin/httpd")
    # -- the whitelist entry was written against the REQUESTED path, so the
    # match must succeed via requested_path even when rootfs_path differs.
    whitelist = frozenset({"usr/sbin/httpd"})
    stage2 = _stage2([_binary("bin/httpd", requested_path="usr/sbin/httpd")])

    result = join_targets(whitelist, stage2)

    assert [b.rootfs_path for b in result.matched] == ["bin/httpd"]


def test_join_targets_normalizes_leading_slash_and_backslash():
    whitelist = build_whitelist(_stage1(["\\sbin\\wpasupp"]))
    stage2 = _stage2([_binary("sbin/wpasupp")])

    result = join_targets(whitelist, stage2)

    assert [b.rootfs_path for b in result.matched] == ["sbin/wpasupp"]


def test_join_targets_non_whitelisted_binary_is_orphan():
    whitelist = frozenset({"sbin/wpasupp"})
    stage2 = _stage2([_binary("sbin/wpasupp"), _binary("lib/libnvram.so")])

    result = join_targets(whitelist, stage2)

    assert len(result.matched) == 1
    assert result.orphan_bin_ids == (_binary("lib/libnvram.so").bin_id,)


def test_join_targets_whitelisted_but_unresolved_upstream():
    whitelist = frozenset({"bin/missing"})
    stage2 = _stage2(
        unresolved=[UnresolvedBinaryRecord(requested_path="bin/missing", problem="not_found")]
    )

    result = join_targets(whitelist, stage2)

    assert result.matched == ()
    assert len(result.skipped) == 1
    assert result.skipped[0].reason == "unresolved_upstream"
    assert result.skipped[0].detail == "not_found"


def test_join_targets_whitelisted_in_neither_list():
    # Stage 2 ran with --only and never even attempted this path -- neither
    # resolved nor recorded as unresolved.
    whitelist = frozenset({"bin/never_attempted"})
    stage2 = _stage2()

    result = join_targets(whitelist, stage2)

    assert result.skipped[0].reason == "not_in_stage2"
    assert result.skipped[0].detail is None


def test_join_targets_every_whitelist_entry_accounted_for():
    whitelist = frozenset({"sbin/wpasupp", "bin/missing", "bin/never_attempted"})
    stage2 = _stage2(
        binaries=[_binary("sbin/wpasupp")],
        unresolved=[UnresolvedBinaryRecord(requested_path="bin/missing", problem="not_found")],
    )

    result = join_targets(whitelist, stage2)

    assert len(result.matched) == 1
    reasons = {s.requested_path: s.reason for s in result.skipped}
    assert reasons == {
        "bin/missing": "unresolved_upstream",
        "bin/never_attempted": "not_in_stage2",
    }
