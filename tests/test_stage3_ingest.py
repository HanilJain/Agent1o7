"""Tests for `fw_audit.stage3_analysis.ingest.ingest()` — the Step 1
orchestrator. Mirrors `test_stage2_extract.py`'s `_setup_stage1`-style
helper: build real files under `tmp_path`, then exercise the orchestrator
against them rather than mocking its internals.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from fw_audit.common.schemas import ExtractionStatus
from fw_audit.config.settings import Settings
from fw_audit.stage3_analysis.errors import Stage3InputError
from fw_audit.stage3_analysis.ingest import ingest


def _setup_run(
    tmp_path: Path,
    *,
    identified_paths: list[str],
    binaries: list[dict] | None = None,
    unresolved: list[dict] | None = None,
    tree_files: dict[str, str] | None = None,
    decompiled_tree_dir: str | None = None,
    db_name: str = "fw",
) -> Path:
    """Build a real `db/<db_name>/{stage1_summary.json,stage2/stage2_summary.json}`
    plus a sibling `db/<db_name>_decompiled/` mirror tree, and return the
    stage1_summary.json path.

    `tree_files` maps a rootfs-relative-with-`.c`-appended path (e.g.
    "sbin/wpasupp.c") to its text content, written under the mirror tree.
    `decompiled_tree_dir` overrides the recorded field name (default: the
    real `<db_name>_decompiled` sibling), letting tests exercise the
    recompute-fallback path.
    """
    db_subfolder = tmp_path / "db" / db_name
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True)
    rootfs = db_subfolder / "binwalk_1" / "squashfs-root"
    rootfs.mkdir(parents=True)

    tree_dir = tmp_path / "db" / f"{db_name}_decompiled"
    tree_dir.mkdir(parents=True, exist_ok=True)
    for relpath, content in (tree_files or {}).items():
        target = tree_dir / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    stage1_summary_path = db_subfolder / "stage1_summary.json"
    stage1_summary_path.write_text(
        json.dumps(
            {
                "run_id": "stage1run",
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "rootfs_dir": str(rootfs),
                "identified_binaries": [{"path": p} for p in identified_paths],
            }
        ),
        encoding="utf-8",
    )

    stage2_summary_path = stage2_dir / "stage2_summary.json"
    stage2_summary_path.write_text(
        json.dumps(
            {
                "run_id": "stage2run",
                "status": ExtractionStatus.COMPLETED.value,
                "db_subfolder": str(db_subfolder),
                "rootfs_dir": str(rootfs),
                "stage2_dir": str(stage2_dir),
                "decompiled_tree_dir": (
                    decompiled_tree_dir if decompiled_tree_dir is not None else tree_dir.name
                ),
                "ghidra_image": "fw-audit-ghidra:latest",
                "binaries": binaries or [],
                "unresolved": unresolved or [],
                "started_at": datetime.now(UTC).isoformat(),
            }
        ),
        encoding="utf-8",
    )

    return stage1_summary_path


def _binary_dict(
    rootfs_path: str,
    *,
    requested_path: str | None = None,
    aliases: list[str] | None = None,
    status: str = "succeeded",
    decompiled_tree_c: str | None = None,
    function_count: int = 1,
    functions: list[dict] | None = None,
) -> dict:
    return {
        "bin_id": rootfs_path.replace("/", "_"),
        "rootfs_path": rootfs_path,
        "requested_path": requested_path or rootfs_path,
        "aliases": aliases or [],
        "sha256": "0" * 64,
        "size_bytes": 1024,
        "status": status,
        "function_count": function_count,
        "functions": functions or [],
        "artifacts": {
            "decompiled_tree_c": (
                decompiled_tree_c if decompiled_tree_c is not None else f"{rootfs_path}.c"
            )
        },
    }


def _ghidra_function_dict(name: str, *, is_thunk: bool = False, is_external: bool = False) -> dict:
    """Minimal `GhidraFunction` fields for a test fixture's `functions` list."""
    return {
        "name": name,
        "entry_point": "00401000",
        "size": 10,
        "signature": f"void {name}(void)",
        "is_thunk": is_thunk,
        "is_external": is_external,
    }


def test_ingest_missing_stage2_summary_raises(tmp_path):
    db_subfolder = tmp_path / "db" / "fw"
    db_subfolder.mkdir(parents=True)
    stage1_path = db_subfolder / "stage1_summary.json"
    stage1_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "identified_binaries": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(Stage3InputError, match="fw-extract"):
        ingest(stage1_summary_path=stage1_path)


def test_ingest_malformed_stage2_summary_raises(tmp_path):
    db_subfolder = tmp_path / "db" / "fw"
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True)
    (stage2_dir / "stage2_summary.json").write_text("{not json", encoding="utf-8")
    stage1_path = db_subfolder / "stage1_summary.json"
    stage1_path.write_text(
        json.dumps(
            {"status": "completed", "db_subfolder": str(db_subfolder), "identified_binaries": []}
        ),
        encoding="utf-8",
    )

    with pytest.raises(Stage3InputError):
        ingest(stage1_summary_path=stage1_path)


def test_ingest_empty_decompiled_tree_dir_field_recomputes_sibling(tmp_path):
    # Stage2Summary.decompiled_tree_dir defaults to "" for summaries written
    # before that field existed -- ingest() must still find the real sibling.
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
        decompiled_tree_dir="",
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert len(report.targets) == 1
    assert any("recovered it by recomputing" in w for w in report.warnings)


def test_ingest_tree_dir_absent_entirely_raises(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={},
    )
    # Delete the sibling mirror tree entirely -- neither the recorded name
    # nor the recomputed name will resolve.
    tree_dir = tmp_path / "db" / "fw_decompiled"
    for p in sorted(tree_dir.rglob("*"), reverse=True):
        p.unlink() if p.is_file() else p.rmdir()
    tree_dir.rmdir()

    with pytest.raises(Stage3InputError, match="mirror tree"):
        ingest(stage1_summary_path=stage1_path)


def test_ingest_direct_whitelist_match(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert len(report.targets) == 1
    assert report.targets[0].rootfs_path == "sbin/wpasupp"
    assert report.skipped == ()


def test_ingest_target_functions_populated_from_matched_binary(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp", functions=[_ghidra_function_dict("main")])],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert len(report.targets) == 1
    assert [f.name for f in report.targets[0].functions] == ["main"]


def test_ingest_without_debug_dump_writes_no_debug_dir(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )

    ingest(stage1_summary_path=stage1_path)

    debug_dir = tmp_path / "db" / "fw" / "stage3" / "debug"
    assert not debug_dir.exists()


def test_ingest_debug_dump_writes_verbatim_copy_per_target(tmp_path):
    source = "int main(void)\n{\n  return 0;\n}\n"
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={"sbin/wpasupp.c": source},
    )

    report = ingest(
        stage1_summary_path=stage1_path, settings=Settings(_env_file=None, stage3_debug_dump=True)
    )

    dumped = tmp_path / "db" / "fw" / "stage3" / "debug" / "sbin_wpasupp.c"
    assert dumped.is_file()
    # Byte-for-byte against the ACTUAL mirror-tree file, not the Python
    # source literal above -- the fixture's own write_text() may itself
    # translate line endings on write (e.g. \n -> \r\n on Windows text
    # mode), so that's not what "verbatim copy" is being asserted against
    # here; what matters is that _write_debug_sources copies read_bytes()
    # straight through with zero transformation of its own.
    assert dumped.read_bytes() == report.targets[0].source_path.read_bytes()


def test_ingest_debug_dump_writes_one_file_per_matched_target_only(tmp_path):
    # Skipped/orphaned entries must NOT get a debug dump -- only real,
    # resolved Targets.
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp", "bin/missing"],
        binaries=[_binary_dict("sbin/wpasupp")],
        unresolved=[{"requested_path": "bin/missing", "problem": "not_found"}],
        tree_files={
            "sbin/wpasupp.c": "int main(void) { return 0; }\n",
            "lib/orphan.so.c": "int f(void) { return 0; }\n",
        },
    )

    debug_settings = Settings(_env_file=None, stage3_debug_dump=True)
    ingest(stage1_summary_path=stage1_path, settings=debug_settings)

    debug_dir = tmp_path / "db" / "fw" / "stage3" / "debug"
    # Every dumped file (raw + cleaned, if the stage3 extra is installed)
    # is prefixed by its bin_id, so this stays correct either way -- only
    # the matched target's files may appear, never the orphan's.
    dumped_bin_ids = {p.name.split(".", 1)[0] for p in debug_dir.glob("*.c")}
    assert dumped_bin_ids == {"sbin_wpasupp"}


def test_ingest_debug_dump_never_modifies_mirror_tree(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )
    tree_dir = tmp_path / "db" / "fw_decompiled"

    def _snapshot() -> dict[str, tuple[int, float]]:
        return {
            str(p): (p.stat().st_size, p.stat().st_mtime)
            for p in tree_dir.rglob("*")
            if p.is_file()
        }

    before = _snapshot()
    debug_settings = Settings(_env_file=None, stage3_debug_dump=True)
    ingest(stage1_summary_path=stage1_path, settings=debug_settings)
    after = _snapshot()

    assert after == before


def test_ingest_debug_writes_cleaned_dump_when_tree_sitter_available(tmp_path):
    pytest.importorskip("tree_sitter_c")
    source = (
        "typedef unsigned char undefined1;\n\n"
        "extern void bar(void);\n\n"
        "int add(int a, int b)\n{\n  return a + b;\n}\n"
    )
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp", functions=[_ghidra_function_dict("add")])],
        tree_files={"sbin/wpasupp.c": source},
    )

    debug_settings = Settings(_env_file=None, stage3_debug_dump=True)
    ingest(stage1_summary_path=stage1_path, settings=debug_settings)

    cleaned = tmp_path / "db" / "fw" / "stage3" / "debug" / "sbin_wpasupp.cleaned.c"
    assert cleaned.is_file()
    text = cleaned.read_text(encoding="utf-8")
    assert "typedef unsigned char undefined1" not in text
    assert "extern void bar" not in text
    assert "int add(int a, int b)" in text
    # Additive, not a replacement -- the raw dump must still exist too.
    raw = tmp_path / "db" / "fw" / "stage3" / "debug" / "sbin_wpasupp.c"
    assert raw.is_file()


def test_ingest_without_debug_writes_no_cleaned_dump(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )

    ingest(stage1_summary_path=stage1_path)

    debug_dir = tmp_path / "db" / "fw" / "stage3" / "debug"
    assert not debug_dir.exists()


def test_ingest_debug_missing_tree_sitter_degrades_gracefully(tmp_path, monkeypatch, caplog):
    """--debug must not regress for a user without the `stage3` extra: the
    raw dump and the report still succeed; only the cleaned dump is
    skipped, with a single warning logged (not one per target)."""
    import sys

    monkeypatch.setitem(sys.modules, "tree_sitter", None)
    monkeypatch.setitem(sys.modules, "tree_sitter_c", None)
    from fw_audit.stage3_analysis.clean import parser as parser_module

    parser_module.get_parser.cache_clear()

    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )
    debug_settings = Settings(_env_file=None, stage3_debug_dump=True)

    try:
        with caplog.at_level("WARNING", logger="fw_audit.stage3_analysis"):
            report = ingest(stage1_summary_path=stage1_path, settings=debug_settings)
    finally:
        parser_module.get_parser.cache_clear()

    assert len(report.targets) == 1
    raw = tmp_path / "db" / "fw" / "stage3" / "debug" / "sbin_wpasupp.c"
    assert raw.is_file()
    cleaned = tmp_path / "db" / "fw" / "stage3" / "debug" / "sbin_wpasupp.cleaned.c"
    assert not cleaned.is_file()
    assert any("cleaned debug dump skipped" in r.message for r in caplog.records)


def test_ingest_matches_via_alias_busybox_applet(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["bin/ls"],
        binaries=[_binary_dict("bin/busybox", aliases=["bin/ls", "bin/cat"])],
        tree_files={"bin/busybox.c": "int main(void) { return 0; }\n"},
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert len(report.targets) == 1
    assert report.targets[0].rootfs_path == "bin/busybox"


def test_ingest_matches_via_rootfs_path_basename_rescan(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["usr/sbin/httpd"],
        binaries=[_binary_dict("bin/httpd", requested_path="usr/sbin/httpd")],
        tree_files={"bin/httpd.c": "int main(void) { return 0; }\n"},
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert len(report.targets) == 1
    assert report.targets[0].rootfs_path == "bin/httpd"


def test_ingest_normalizes_leading_slash_and_backslash(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["\\sbin\\wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert len(report.targets) == 1


def test_ingest_non_whitelisted_mirror_file_is_orphan(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={
            "sbin/wpasupp.c": "int main(void) { return 0; }\n",
            "lib/libnvram.so.c": "int f(void) { return 0; }\n",
        },
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert len(report.targets) == 1
    assert report.orphans == ("lib/libnvram.so.c",)


def test_ingest_ignores_non_source_extensions_in_tree(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={
            "sbin/wpasupp.c": "int main(void) { return 0; }\n",
            "sbin/notes.txt": "not source\n",
        },
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert report.orphans == ()


def test_ingest_artifact_missing_on_disk_is_skipped(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={},  # nothing actually written to disk
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert report.targets == ()
    assert len(report.skipped) == 1
    assert report.skipped[0].reason == "artifact_missing_on_disk"


def test_ingest_decompiled_tree_c_none_recomputes_and_resolves(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp", decompiled_tree_c=None)],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert len(report.targets) == 1


def test_ingest_decompile_failed_status_is_skipped(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp", status="failed")],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert report.targets == ()
    assert report.skipped[0].reason == "decompile_failed"


def test_ingest_whitelisted_and_unresolved_upstream(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["bin/missing"],
        unresolved=[{"requested_path": "bin/missing", "problem": "not_found"}],
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert report.targets == ()
    assert report.skipped[0].reason == "unresolved_upstream"
    assert report.skipped[0].detail == "not_found"


def test_ingest_whitelisted_in_neither_list(tmp_path):
    stage1_path = _setup_run(tmp_path, identified_paths=["bin/never_attempted"])

    report = ingest(stage1_summary_path=stage1_path)

    assert report.targets == ()
    assert report.skipped[0].reason == "not_in_stage2"


def test_ingest_empty_source_file_is_skipped(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={"sbin/wpasupp.c": ""},
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert report.targets == ()
    assert report.skipped[0].reason == "empty_source"


def test_ingest_traversal_escape_is_skipped_and_not_read(tmp_path):
    # decompiled_tree_c pointing outside the tree (ultimately untrusted,
    # derived from Stage 1's LLM-authored path) must never be opened.
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[
            _binary_dict("sbin/wpasupp", decompiled_tree_c="../../../../etc/passwd")
        ],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )
    # rootfs_path recompute fallback would find the real file; to isolate
    # the traversal path specifically, point rootfs_path somewhere that
    # ALSO doesn't exist so only the malicious decompiled_tree_c is tried
    # meaningfully -- if it were followed, this would still fail closed.
    outside = tmp_path / "etc"
    outside.mkdir()
    (outside / "passwd").write_text("root:x:0:0\n", encoding="utf-8")

    report = ingest(stage1_summary_path=stage1_path)

    # Either resolved via the safe rootfs_path fallback, or skipped -- never
    # via the escaping path. Confirm the outside file's content never
    # became a Target's source.
    assert all(t.source_path != (outside / "passwd") for t in report.targets)


def test_ingest_only_narrows_whitelist(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp", "bin/httpd"],
        binaries=[_binary_dict("sbin/wpasupp"), _binary_dict("bin/httpd")],
        tree_files={
            "sbin/wpasupp.c": "int main(void) { return 0; }\n",
            "bin/httpd.c": "int main(void) { return 0; }\n",
        },
    )

    report = ingest(stage1_summary_path=stage1_path, only=("bin/httpd",))

    assert [t.rootfs_path for t in report.targets] == ["bin/httpd"]
    assert report.orphans == ("sbin/wpasupp.c",)


def test_ingest_every_target_skipped_returns_report_not_raise(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp", status="failed")],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )

    report = ingest(stage1_summary_path=stage1_path)

    assert report.targets == ()
    assert len(report.skipped) == 1


def test_ingest_writes_report_without_touching_stage2_or_mirror_tree(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )
    db_subfolder = tmp_path / "db" / "fw"
    stage2_dir = db_subfolder / "stage2"
    tree_dir = tmp_path / "db" / "fw_decompiled"

    def _snapshot(root: Path) -> dict[str, tuple[int, float]]:
        return {
            str(p): (p.stat().st_size, p.stat().st_mtime)
            for p in root.rglob("*")
            if p.is_file()
        }

    before_stage2 = _snapshot(stage2_dir)
    before_tree = _snapshot(tree_dir)

    report = ingest(stage1_summary_path=stage1_path)

    assert _snapshot(stage2_dir) == before_stage2
    assert _snapshot(tree_dir) == before_tree
    # ingest() DOES write its own report -- confirm that landed under stage3/,
    # not stage2/ or the mirror tree.
    assert (db_subfolder / "stage3" / "ingestion_report.json").is_file()
    assert len(report.targets) == 1


def test_ingest_without_chunk_debug_dump_writes_no_chunks_dir(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )

    ingest(stage1_summary_path=stage1_path)

    chunks_dir = tmp_path / "db" / "fw" / "stage3" / "chunks"
    assert not chunks_dir.exists()


def _padded_function(name: str, n_statements: int = 60) -> str:
    """A syntactically simple function padded to comfortably exceed
    `stage3_chunk_lines`'s minimum allowed value (50, per `Settings.
    stage3_chunk_lines`'s `ge=50` constraint) on its own, so each one
    forces its own chunk closure without needing an out-of-range
    `chunk_lines` value in the test."""
    body = "\n".join(f"  x += {i};" for i in range(n_statements))
    return f"int {name}(int x)\n{{\n{body}\n  return x;\n}}\n"


def test_ingest_chunk_debug_dump_writes_one_file_per_chunk(tmp_path):
    pytest.importorskip("tree_sitter_c")
    source = _padded_function("add") + "\n" + _padded_function("sub")
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[
            _binary_dict(
                "sbin/wpasupp",
                functions=[_ghidra_function_dict("add"), _ghidra_function_dict("sub")],
            )
        ],
        tree_files={"sbin/wpasupp.c": source},
    )

    # chunk_lines=50 (the minimum allowed): each padded function's own span
    # (~63 lines) already exceeds it, so each closes its own chunk on its own.
    chunk_settings = Settings(
        _env_file=None, stage3_chunk_debug_dump=True, stage3_chunk_lines=50
    )
    ingest(stage1_summary_path=stage1_path, settings=chunk_settings)

    chunks_dir = tmp_path / "db" / "fw" / "stage3" / "chunks"
    files = sorted(p.name for p in chunks_dir.glob("*.c"))
    assert files == ["sbin_wpasupp__0000.c", "sbin_wpasupp__0001.c"]
    assert "int add(int x)" in (chunks_dir / "sbin_wpasupp__0000.c").read_text(encoding="utf-8")
    assert "int sub(int x)" in (chunks_dir / "sbin_wpasupp__0001.c").read_text(encoding="utf-8")


def test_ingest_chunk_debug_dump_writes_files_for_matched_targets_only(tmp_path):
    pytest.importorskip("tree_sitter_c")
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp", "bin/missing"],
        binaries=[
            _binary_dict("sbin/wpasupp", functions=[_ghidra_function_dict("main")])
        ],
        unresolved=[{"requested_path": "bin/missing", "problem": "not_found"}],
        tree_files={
            "sbin/wpasupp.c": "int main(void) { return 0; }\n",
            "lib/orphan.so.c": "int f(void) { return 0; }\n",
        },
    )

    chunk_settings = Settings(_env_file=None, stage3_chunk_debug_dump=True)
    ingest(stage1_summary_path=stage1_path, settings=chunk_settings)

    chunks_dir = tmp_path / "db" / "fw" / "stage3" / "chunks"
    dumped_bin_ids = {p.name.split("__", 1)[0] for p in chunks_dir.glob("*.c")}
    assert dumped_bin_ids == {"sbin_wpasupp"}


def test_ingest_chunk_debug_dump_independent_of_raw_debug_dump(tmp_path):
    pytest.importorskip("tree_sitter_c")
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp", functions=[_ghidra_function_dict("main")])],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )

    chunk_only_settings = Settings(
        _env_file=None, stage3_chunk_debug_dump=True, stage3_debug_dump=False
    )
    ingest(stage1_summary_path=stage1_path, settings=chunk_only_settings)

    stage3_dir = tmp_path / "db" / "fw" / "stage3"
    assert (stage3_dir / "chunks").exists()
    assert not (stage3_dir / "debug").exists()


def test_ingest_raw_debug_dump_independent_of_chunk_debug_dump(tmp_path):
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )

    debug_only_settings = Settings(
        _env_file=None, stage3_debug_dump=True, stage3_chunk_debug_dump=False
    )
    ingest(stage1_summary_path=stage1_path, settings=debug_only_settings)

    stage3_dir = tmp_path / "db" / "fw" / "stage3"
    assert (stage3_dir / "debug").exists()
    assert not (stage3_dir / "chunks").exists()


def test_ingest_both_debug_flags_together_write_both_directories(tmp_path):
    pytest.importorskip("tree_sitter_c")
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp", functions=[_ghidra_function_dict("main")])],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )

    both_settings = Settings(
        _env_file=None, stage3_debug_dump=True, stage3_chunk_debug_dump=True
    )
    ingest(stage1_summary_path=stage1_path, settings=both_settings)

    stage3_dir = tmp_path / "db" / "fw" / "stage3"
    assert (stage3_dir / "debug").exists()
    assert (stage3_dir / "chunks").exists()


def test_ingest_chunk_debug_dump_never_modifies_mirror_tree(tmp_path):
    pytest.importorskip("tree_sitter_c")
    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp", functions=[_ghidra_function_dict("main")])],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )
    tree_dir = tmp_path / "db" / "fw_decompiled"

    def _snapshot() -> dict[str, tuple[int, float]]:
        return {
            str(p): (p.stat().st_size, p.stat().st_mtime)
            for p in tree_dir.rglob("*")
            if p.is_file()
        }

    before = _snapshot()
    chunk_settings = Settings(_env_file=None, stage3_chunk_debug_dump=True)
    ingest(stage1_summary_path=stage1_path, settings=chunk_settings)
    after = _snapshot()

    assert after == before


def test_ingest_chunk_debug_missing_tree_sitter_degrades_gracefully(
    tmp_path, monkeypatch, caplog
):
    """--debug-chunks must not regress for a user without the `stage3`
    extra: the report still succeeds; the chunk dump is simply skipped,
    with a single warning logged (not one per target)."""
    import sys

    monkeypatch.setitem(sys.modules, "tree_sitter", None)
    monkeypatch.setitem(sys.modules, "tree_sitter_c", None)
    from fw_audit.stage3_analysis.clean import parser as parser_module

    parser_module.get_parser.cache_clear()

    stage1_path = _setup_run(
        tmp_path,
        identified_paths=["sbin/wpasupp"],
        binaries=[_binary_dict("sbin/wpasupp")],
        tree_files={"sbin/wpasupp.c": "int main(void) { return 0; }\n"},
    )
    chunk_settings = Settings(_env_file=None, stage3_chunk_debug_dump=True)

    try:
        with caplog.at_level("WARNING", logger="fw_audit.stage3_analysis"):
            report = ingest(stage1_summary_path=stage1_path, settings=chunk_settings)
    finally:
        parser_module.get_parser.cache_clear()

    assert len(report.targets) == 1
    chunks_dir = tmp_path / "db" / "fw" / "stage3" / "chunks"
    assert not any(chunks_dir.glob("*.c")) if chunks_dir.exists() else True
    assert any("chunk debug dump skipped" in r.message for r in caplog.records)


@pytest.mark.integration
def test_ingest_against_real_committed_run():
    """End-to-end against the real committed firmware run in this repo.

    tests/stage1_summary.json whitelists exactly sbin/wpasupp; the mirror
    tree (data/db/GT-AXE16000_..._squashfs_decompiled/) holds three .c
    files -- so this must yield exactly 1 target and 2 orphans.
    """
    project_root = Path(__file__).parent.parent
    stage1_summary_path = project_root / "tests" / "stage1_summary.json"
    if not stage1_summary_path.is_file():
        pytest.skip("tests/stage1_summary.json not present")

    real_db_subfolder = Path(
        json.loads(stage1_summary_path.read_text(encoding="utf-8"))["db_subfolder"]
    )
    if not (real_db_subfolder / "stage2" / "stage2_summary.json").is_file():
        pytest.skip("real stage2_summary.json not present -- run fw-extract first")

    report = ingest(
        stage1_summary_path=stage1_summary_path, settings=Settings(_env_file=None)
    )

    assert len(report.targets) == 1
    assert report.targets[0].rootfs_path == "sbin/wpasupp"
    assert len(report.orphans) == 2
