"""Tests for fw_audit.stage2_extraction.extract.

Mirrors tests/test_graph_integration.py's idiom: FakeExecutor + a hand-built
stage1_summary.json + rootfs, no live Docker daemon required.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from fw_audit.common.schemas import DecompilationStatus, ExtractionStatus
from fw_audit.config.settings import Settings
from fw_audit.executors.base import ExecutionResult
from fw_audit.stage2_extraction import layout
from fw_audit.stage2_extraction.extract import Stage2InputError, _write_mirror, run_extraction

_OUT_DIR_RE = re.compile(r'-postScript fw_audit_export\.py "(/work/[^"]+)"')


def _container_out_dir(command: str) -> str:
    match = _OUT_DIR_RE.search(command)
    assert match, command
    return match.group(1)


def _host_out_dir(command: str, files: Path) -> Path:
    rel = _container_out_dir(command).removeprefix("/work/")
    return files / rel


def _setup_stage1(tmp_path: Path, *, binaries: list[dict], elf_bytes: bytes) -> Path:
    db_subfolder = tmp_path / "db" / "fw"
    rootfs = db_subfolder / "binwalk_1" / "squashfs-root"
    rootfs.mkdir(parents=True)
    for b in binaries:
        target = rootfs / b["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(elf_bytes)

    tree_txt = db_subfolder / "tree.txt"
    tree_txt.write_text(f"{rootfs}\n", encoding="utf-8")

    summary_path = db_subfolder / "stage1_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "run_id": "stage1run",
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "tree_txt_path": str(tree_txt),
                "rootfs_dir": str(rootfs),
                "identified_binaries": binaries,
            }
        ),
        encoding="utf-8",
    )
    return summary_path


def _write_metadata(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "program": {"name": "x"},
        "analysis": {
            "status": "succeeded",
            "elapsed_seconds": 1.0,
            "skipped_functions": [],
            "decompile_failures": [],
        },
        "functions": [
            {
                "name": "main",
                "entry_point": "00401000",
                "size": 10,
                "signature": "void main(void)",
                "calls": [],
                "called_by": [],
                "decompiled": True,
            }
        ],
        "imports": [],
        "exports": [],
        "strings": [],
    }
    (out_dir / "metadata.json").write_text(json.dumps(payload), encoding="utf-8")
    (out_dir / "decompiled").mkdir(exist_ok=True)
    (out_dir / "decompiled" / "whole.c").write_text(
        "undefined4 main(void)\n{\n  return 0;\n}\n", encoding="utf-8"
    )
    (out_dir / "decompiled" / "functions").mkdir(exist_ok=True)
    (out_dir / "decompiled" / "functions" / "00401000_main.c").write_text(
        "undefined4 main(void)\n{\n  return 0;\n}\n", encoding="utf-8"
    )


def _write_metadata_with_thunk(out_dir: Path) -> None:
    """Like `_write_metadata`, but `whole.c` contains a self-forwarding
    Ghidra thunk stub for `calloc`, and `metadata.json` marks it
    `is_thunk: true` — exercises the end-to-end thunk-replacement path
    through `run_extraction` (not just `passes.replace_thunk_bodies` in
    isolation)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "program": {"name": "x"},
        "analysis": {
            "status": "succeeded",
            "elapsed_seconds": 1.0,
            "skipped_functions": [],
            "decompile_failures": [],
        },
        "functions": [
            {
                "name": "main",
                "entry_point": "00401000",
                "size": 10,
                "signature": "void main(void)",
                "is_thunk": False,
                "is_external": False,
                "calls": [],
                "called_by": [],
                "decompiled": True,
            },
            {
                "name": "calloc",
                "entry_point": "00401100",
                "size": 8,
                "signature": "void * calloc(size_t n, size_t s)",
                "is_thunk": True,
                "is_external": False,
                "calls": [],
                "called_by": [],
                "decompiled": True,
            },
        ],
        "imports": [],
        "exports": [],
        "strings": [],
    }
    whole_c = (
        "undefined4 main(void)\n{\n  return 0;\n}\n"
        "\n"
        "void * calloc(size_t n,size_t s)\n"
        "{\n"
        "  void *p;\n"
        "  p = calloc(n,s);\n"
        "  return p;\n"
        "}\n"
    )
    (out_dir / "metadata.json").write_text(json.dumps(payload), encoding="utf-8")
    (out_dir / "decompiled").mkdir(exist_ok=True)
    (out_dir / "decompiled" / "whole.c").write_text(whole_c, encoding="utf-8")
    (out_dir / "decompiled" / "functions").mkdir(exist_ok=True)
    (out_dir / "decompiled" / "functions" / "00401000_main.c").write_text(
        "undefined4 main(void)\n{\n  return 0;\n}\n", encoding="utf-8"
    )


def _patch_ghidra_executor(monkeypatch, executor) -> None:
    monkeypatch.setattr(
        "fw_audit.stage2_extraction.extract.ghidra_executor", lambda settings: executor
    )


async def test_two_binaries_completes(tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    rootfs = db_subfolder / "binwalk_1" / "squashfs-root"
    (rootfs / "bin").mkdir(parents=True)
    # Distinct content per binary — identical content would (correctly)
    # dedupe into one resolved binary, which is a different test below.
    (rootfs / "bin" / "a").write_bytes(synthetic_elf_bytes + b"\x01")
    (rootfs / "bin" / "b").write_bytes(synthetic_elf_bytes + b"\x02")
    tree_txt = db_subfolder / "tree.txt"
    tree_txt.write_text(f"{rootfs}\n", encoding="utf-8")
    summary_path = db_subfolder / "stage1_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "tree_txt_path": str(tree_txt),
                "rootfs_dir": str(rootfs),
                "identified_binaries": [
                    {"path": "bin/a"},
                    {"path": "bin/b"},
                ],
            }
        ),
        encoding="utf-8",
    )

    def on_run(command, files):
        _write_metadata(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    assert summary.status == ExtractionStatus.COMPLETED
    assert len(summary.binaries) == 2
    assert all(b.status == DecompilationStatus.SUCCEEDED for b in summary.binaries)
    assert all(b.function_count == 1 for b in summary.binaries)


async def test_one_binary_fails_other_still_produced(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    # Distinct content so they resolve to different files, not deduped.
    elf_a = synthetic_elf_bytes + b"\x01"
    elf_b = synthetic_elf_bytes + b"\x02"
    db_subfolder = tmp_path / "db" / "fw"
    rootfs = db_subfolder / "binwalk_1" / "squashfs-root"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "a").write_bytes(elf_a)
    (rootfs / "bin" / "b").write_bytes(elf_b)
    tree_txt = db_subfolder / "tree.txt"
    tree_txt.write_text(f"{rootfs}\n", encoding="utf-8")
    summary_path = db_subfolder / "stage1_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "tree_txt_path": str(tree_txt),
                "rootfs_dir": str(rootfs),
                "identified_binaries": [
                    {"path": "bin/a"},
                    {"path": "bin/b"},
                ],
            }
        ),
        encoding="utf-8",
    )

    def on_run(command, files):
        out_dir = _host_out_dir(command, files)
        if "bin_a" in str(out_dir):
            return ExecutionResult(
                command=command, returncode=1, stdout="", stderr="ghidra crashed", timed_out=False
            )
        _write_metadata(out_dir)
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    assert summary.status == ExtractionStatus.COMPLETED_WITH_ERRORS
    statuses = {b.rootfs_path: b.status for b in summary.binaries}
    assert statuses["bin/a"] == DecompilationStatus.FAILED
    assert statuses["bin/b"] == DecompilationStatus.SUCCEEDED


async def test_all_binaries_fail_is_failed(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        return ExecutionResult(
            command=command, returncode=1, stdout="", stderr="boom", timed_out=False
        )

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    assert summary.status == ExtractionStatus.FAILED
    assert summary.binaries[0].status == DecompilationStatus.FAILED


async def test_zero_identified_binaries_completes_with_warning(tmp_path):
    summary_path = _setup_stage1(tmp_path, binaries=[], elf_bytes=b"")

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    assert summary.status == ExtractionStatus.COMPLETED
    assert summary.binaries == []
    assert any("no binaries" in w for w in summary.warnings)


async def test_executor_unavailable_raises_stage2_input_error_with_build_command(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )
    executor = fake_executor()
    executor.available = lambda: False
    _patch_ghidra_executor(monkeypatch, executor)

    try:
        await run_extraction(stage1_summary_path=summary_path, settings=Settings(_env_file=None))
        raise AssertionError("expected Stage2InputError")
    except Stage2InputError as exc:
        assert "docker build -f docker/Dockerfile.ghidra" in str(exc)


async def test_all_unresolved_is_failed_without_touching_executor(
    tmp_path, fake_executor, monkeypatch
):
    """Stage 1 identified binaries, but none exist in the rootfs — must
    fail without ever needing the Ghidra image."""
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/does_not_exist"}], elf_bytes=b""
    )
    executor = fake_executor()
    _patch_ghidra_executor(monkeypatch, executor)

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    assert summary.status == ExtractionStatus.FAILED
    assert len(summary.unresolved) == 1
    assert executor.calls == []


async def test_dry_run_resolves_but_does_not_decompile(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )
    executor = fake_executor()
    _patch_ghidra_executor(monkeypatch, executor)

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None), dry_run=True
    )

    assert summary.status == ExtractionStatus.COMPLETED
    assert summary.binaries == []
    assert executor.calls == []
    resolution_report = json.loads(
        (Path(summary.stage2_dir) / "resolution_report.json").read_text(encoding="utf-8")
    )
    assert len(resolution_report["resolved"]) == 1


async def test_stage2_summary_written_with_relative_artifact_paths(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    binary = summary.binaries[0]
    assert not Path(binary.artifacts.raw_c).is_absolute()
    assert not Path(binary.artifacts.normalized_joern_c).is_absolute()

    # And the written file on disk matches what run_extraction returned.
    on_disk_path = Path(summary.stage2_dir) / "stage2_summary.json"
    on_disk = json.loads(on_disk_path.read_text(encoding="utf-8"))
    assert on_disk["status"] == "completed"
    assert on_disk["binaries"][0]["bin_id"] == binary.bin_id


async def test_normalized_output_written_and_free_of_bare_undefined_types(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    joern_path = Path(summary.db_subfolder) / summary.binaries[0].artifacts.normalized_joern_c
    joern_text = joern_path.read_text(encoding="utf-8")
    assert "typedef" in joern_text  # prelude inlined
    assert "undefined4 main" in joern_text  # still present textually...
    # ...but now a real type, not a bare undeclared one:
    assert "typedef uint32_t undefined4;" in joern_text


async def test_thunk_stub_becomes_extern_declaration_in_delivered_output(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    """End-to-end: a self-forwarding Ghidra thunk stub for `calloc`,
    flagged `is_thunk: true` in metadata.json, must come out of
    `run_extraction` as an `extern` declaration in the normalized Joern
    output — not as a self-recursive body."""
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata_with_thunk(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    joern_path = Path(summary.db_subfolder) / summary.binaries[0].artifacts.normalized_joern_c
    joern_text = joern_path.read_text(encoding="utf-8")
    assert "extern void * calloc(size_t n,size_t s);" in joern_text
    assert "p = calloc(n,s);" not in joern_text


# --------------------------------------------------------------------- #
# cleaned/ — the LLM-target function-only extraction (moved into Stage 2
# from Stage 3, persisted so it's no longer recomputed on every Stage 3 run).
# --------------------------------------------------------------------- #


async def test_cleaned_artifact_written_with_relative_paths(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    pytest.importorskip("tree_sitter_c")
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    binary = summary.binaries[0]
    assert binary.artifacts.cleaned_c is not None
    assert binary.artifacts.cleaned_index_json is not None
    assert not Path(binary.artifacts.cleaned_c).is_absolute()
    assert not Path(binary.artifacts.cleaned_index_json).is_absolute()

    cleaned_c_path = Path(summary.db_subfolder) / binary.artifacts.cleaned_c
    index_path = Path(summary.db_subfolder) / binary.artifacts.cleaned_index_json
    assert cleaned_c_path.is_file()
    assert index_path.is_file()

    cleaned_text = cleaned_c_path.read_text(encoding="utf-8")
    assert "main" in cleaned_text

    index = json.loads(index_path.read_text(encoding="utf-8"))
    assert index["bin_id"] == binary.bin_id
    assert len(index["functions"]) == binary.cleaned_function_count
    for entry in index["functions"]:
        assert set(entry.keys()) == {"name", "start_line", "end_line"}


async def test_cleaned_function_count_and_dropped_line_count_populated(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    pytest.importorskip("tree_sitter_c")
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    binary = summary.binaries[0]
    assert binary.cleaned_function_count == 1  # the fixture's one `main`
    assert binary.dropped_line_count >= 0


async def test_cleaned_index_spans_slice_back_to_identical_function_text(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    """The critical invariant: every recorded span must slice `cleaned/
    whole.c` back to exactly the function it names -- what `stage3_
    analysis.cleaned_io.load_cleaned_source` relies on."""
    pytest.importorskip("tree_sitter_c")
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata_with_thunk(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    binary = summary.binaries[0]
    cleaned_c_path = Path(summary.db_subfolder) / binary.artifacts.cleaned_c
    index_path = Path(summary.db_subfolder) / binary.artifacts.cleaned_index_json

    lines = cleaned_c_path.read_text(encoding="utf-8").split("\n")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    assert index["functions"]  # the fixture has real functions to check
    for entry in index["functions"]:
        sliced = "\n".join(lines[entry["start_line"] - 1 : entry["end_line"]])
        assert entry["name"] in sliced


async def test_cleaning_missing_tree_sitter_degrades_gracefully(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    """Cleaning must not fail the whole Stage 2 run when `tree-sitter`/
    `tree-sitter-c` (the `stage2` extra) aren't installed -- the Joern
    artifact and stage2_summary.json still succeed, only the cleaned
    artifact is skipped for that binary, with a warning recorded in
    `Stage2Summary.warnings` (best-effort, same discipline as a mirror-write
    failure -- not routed through `logging`)."""
    import sys

    monkeypatch.setitem(sys.modules, "tree_sitter", None)
    monkeypatch.setitem(sys.modules, "tree_sitter_c", None)
    from fw_audit.stage2_extraction.clean import parser as parser_module

    parser_module.get_parser.cache_clear()

    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    try:
        summary = await run_extraction(
            stage1_summary_path=summary_path, settings=Settings(_env_file=None)
        )
    finally:
        parser_module.get_parser.cache_clear()

    assert summary.status == ExtractionStatus.COMPLETED
    binary = summary.binaries[0]
    assert binary.status == DecompilationStatus.SUCCEEDED
    assert binary.artifacts.cleaned_c is None
    assert binary.artifacts.cleaned_index_json is None
    # The Joern artifact is unaffected -- cleaning is a sibling, not a dependency.
    assert binary.artifacts.normalized_joern_c is not None
    assert any("cleaning skipped" in w for w in summary.warnings)


# --------------------------------------------------------------------- #
# normalized/normalization_report.json — the per-pass audit trail.
# --------------------------------------------------------------------- #


async def test_normalization_report_written(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    stage2_dir = Path(summary.stage2_dir)
    bin_dir = layout.binary_dir(stage2_dir, summary.binaries[0].bin_id)
    report_path = layout.normalization_report_path(bin_dir)
    assert report_path.is_file()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["bin_id"] == summary.binaries[0].bin_id
    assert report["context_summary"]["functions"] == 1
    assert report["context_summary"]["thunks"] == 0
    assert report["joern_whole_c"] is not None
    joern_pass_names = [s["name"] for s in report["joern_whole_c"]["stats"]]
    from fw_audit.stage2_extraction.normalize.pipeline import JOERN_PIPELINE

    assert joern_pass_names == [p.name for p in JOERN_PIPELINE]


async def test_normalization_report_reflects_thunk_context(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata_with_thunk(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    stage2_dir = Path(summary.stage2_dir)
    bin_dir = layout.binary_dir(stage2_dir, summary.binaries[0].bin_id)
    report = json.loads(
        layout.normalization_report_path(bin_dir).read_text(encoding="utf-8")
    )
    assert report["context_summary"]["functions"] == 2
    assert report["context_summary"]["thunks"] == 1


# --------------------------------------------------------------------- #
# The decompiled-C mirror tree: <db_subfolder.name>_decompiled/, a sibling
# of db_subfolder mirroring the rootfs layout with .c appended.
# --------------------------------------------------------------------- #


async def test_decompiled_mirror_tree_written_as_sibling_of_db_subfolder(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    db_subfolder = Path(summary.db_subfolder)
    mirror_root = db_subfolder.parent / "fw_decompiled"
    assert (mirror_root / "bin" / "a.c").is_file()
    # Guard against accidentally nesting it INSIDE the run dir instead.
    assert not (db_subfolder / "fw_decompiled").exists()


async def test_decompiled_mirror_content_equals_normalized_joern_c(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    binary = summary.binaries[0]
    joern_text = (Path(summary.db_subfolder) / binary.artifacts.normalized_joern_c).read_text(
        encoding="utf-8"
    )
    mirror_path = (
        Path(summary.db_subfolder).parent
        / summary.decompiled_tree_dir
        / binary.artifacts.decompiled_tree_c
    )
    assert mirror_path.read_text(encoding="utf-8") == joern_text
    # Normalized, not raw Ghidra C: the prelude typedef is inlined.
    assert "typedef uint32_t undefined4;" in joern_text


@pytest.mark.parametrize(
    "rootfs_path,expected_mirror",
    [
        ("bin/a", "bin/a.c"),
        ("lib/liba.so", "lib/liba.so.c"),
        ("lib/modules/a.ko", "lib/modules/a.ko.c"),
    ],
)
async def test_decompiled_mirror_appends_c_without_replacing_extension(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch, rootfs_path, expected_mirror
):
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": rootfs_path}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    mirror_root = Path(summary.db_subfolder).parent / summary.decompiled_tree_dir
    assert (mirror_root / expected_mirror).is_file()
    # The extension-REPLACING variant (e.g. lib/liba.c instead of
    # lib/liba.so.c) must NOT exist -- .c is appended, never substituted.
    replaced_variant = Path(rootfs_path).with_suffix(".c").as_posix()
    if replaced_variant != expected_mirror:
        assert not (mirror_root / replaced_variant).exists()


async def test_decompiled_mirror_nested_dirs_created(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "lib/modules/net/wifi.ko"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    mirror_root = Path(summary.db_subfolder).parent / summary.decompiled_tree_dir
    assert (mirror_root / "lib" / "modules" / "net" / "wifi.ko.c").is_file()


async def test_stage2_summary_records_decompiled_tree_paths(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )

    def on_run(command, files):
        _write_metadata(_host_out_dir(command, files))
        return None

    _patch_ghidra_executor(monkeypatch, fake_executor(on_run))

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None)
    )

    assert summary.decompiled_tree_dir == "fw_decompiled"
    binary = summary.binaries[0]
    assert binary.artifacts.decompiled_tree_c == "bin/a.c"
    assert not Path(binary.artifacts.decompiled_tree_c).is_absolute()

    reconstructed = (
        Path(summary.db_subfolder).parent
        / summary.decompiled_tree_dir
        / binary.artifacts.decompiled_tree_c
    )
    assert reconstructed.is_file()


async def test_decompiled_mirror_not_created_on_dry_run(
    tmp_path, synthetic_elf_bytes, fake_executor, monkeypatch
):
    summary_path = _setup_stage1(
        tmp_path, binaries=[{"path": "bin/a"}], elf_bytes=synthetic_elf_bytes
    )
    executor = fake_executor()
    _patch_ghidra_executor(monkeypatch, executor)

    summary = await run_extraction(
        stage1_summary_path=summary_path, settings=Settings(_env_file=None), dry_run=True
    )

    mirror_root = Path(summary.db_subfolder).parent / "fw_decompiled"
    assert not mirror_root.exists()


def test_write_mirror_skips_and_warns_on_escape(tmp_path):
    tree_dir = tmp_path / "fw_decompiled"
    tree_dir.mkdir()
    warnings: list[str] = []

    result = _write_mirror(tree_dir, "../escape", "int x;", warnings)

    assert result is None
    assert any("escapes the mirror root" in w for w in warnings)
    assert list(tree_dir.iterdir()) == []
