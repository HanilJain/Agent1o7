"""Smoke tests for `fw_audit.stage4_rag.runner` — argparse wiring only, with
the underlying calls mocked out. Full behavior is covered by
`test_stage4_corpus_build.py`/`test_stage4_driver.py`/`test_stage4_debug.py`.
"""

from __future__ import annotations

from fw_audit.stage4_rag import runner
from fw_audit.stage4_rag.corpus_build import CorpusBuildReport
from fw_audit.stage4_rag.errors import Stage4InputError


def test_parse_args_build_corpus():
    args = runner._parse_args(
        [
            "build-corpus",
            "--db-subfolder",
            "db/fw",
            "--rootfs",
            "rootfs",
            "--stage2-binaries",
            "stage2/binaries",
        ]
    )
    assert args.command == "build-corpus"
    assert args.db_subfolder == "db/fw"


def test_parse_args_run_with_only_repeatable():
    args = runner._parse_args(
        ["run", "--db-subfolder", "db/fw", "--only", "a::1", "--only", "a::2"]
    )
    assert args.command == "run"
    assert args.only == ["a::1", "a::2"]


def test_parse_args_debug_subcommands():
    args = runner._parse_args(["debug", "corpus", "--db-subfolder", "db/fw"])
    assert args.command == "debug"
    assert args.debug_command == "corpus"

    args = runner._parse_args(["debug", "parity"])
    assert args.debug_command == "parity"

    args = runner._parse_args(["debug", "taint", "--db-subfolder", "db/fw", "--gid", "a::1"])
    assert args.debug_command == "taint"
    assert args.gid == "a::1"


def test_parse_args_debug_search_repeatable_query_and_top_k():
    args = runner._parse_args(
        [
            "debug",
            "search",
            "--db-subfolder",
            "db/fw",
            "--query",
            "find exec calls",
            "--query",
            "find popen calls",
            "--top-k",
            "15",
        ]
    )
    assert args.debug_command == "search"
    assert args.query == ["find exec calls", "find popen calls"]
    assert args.top_k == 15


def test_cmd_build_corpus_invokes_build_corpus_and_prints(monkeypatch, tmp_path, capsys):
    fake_report = CorpusBuildReport(
        total_files=1,
        total_chunks=1,
        chunks_by_kind={"ROOTFS_TEXT": 1},
        embedding_model="Qwen/Qwen3-Embedding-0.6B",
        chroma_dir=tmp_path / "chroma",
        corpus_report_path=tmp_path / "corpus_report.json",
    )
    monkeypatch.setattr(runner, "build_corpus", lambda **kwargs: fake_report)

    args = runner._parse_args(
        [
            "build-corpus",
            "--db-subfolder",
            str(tmp_path / "db" / "fw"),
            "--rootfs",
            str(tmp_path / "rootfs"),
            "--stage2-binaries",
            str(tmp_path / "stage2" / "binaries"),
        ]
    )
    code = runner._cmd_build_corpus(args)

    assert code == 0
    out = capsys.readouterr().out
    assert "Qwen/Qwen3-Embedding-0.6B" in out


def test_cmd_run_reports_input_error_as_exit_code_2(monkeypatch, tmp_path, capsys):
    def raise_input_error(**kwargs):
        raise Stage4InputError("no findings")

    monkeypatch.setattr(runner, "run_queue", raise_input_error)

    args = runner._parse_args(["run", "--db-subfolder", str(tmp_path / "db" / "fw")])
    code = runner._cmd_run(args)

    assert code == 2
    assert "no findings" in capsys.readouterr().err
