"""Tests for `fw_audit.stage5_verification.cmdlog` — the per-track
append-only JSONL command log."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path

from fw_audit.executors.base import ExecutionResult, SessionHandle
from fw_audit.stage5_verification.cmdlog import (
    CommandLog,
    JsonlRecordingList,
    LoggingSessionExecutor,
    current_phase,
    phase,
)


def _result(*, returncode=0, stdout="out", stderr="") -> ExecutionResult:
    return ExecutionResult(
        command="irrelevant", returncode=returncode, stdout=stdout, stderr=stderr, timed_out=False
    )


def test_disabled_log_never_writes(tmp_path: Path):
    log = CommandLog.disabled()
    log.record(node="reach_target", kind="gdb_batch", command="gdb-multiarch -batch -x r.gdb t")
    assert log.read_all() == []


def test_record_appends_one_json_line(tmp_path: Path):
    path = tmp_path / "gid.dynamic.jsonl"
    log = CommandLog(path, track="dynamic")
    log.record(
        node="reach_target",
        kind="gdb_batch",
        command="gdb-multiarch -batch -x recipe_reach.gdb sbin/mailosd",
        result=_result(returncode=0, stdout="Breakpoint 1, 0x00400900 in main ()", stderr=""),
        payload="set architecture mips\ntarget remote localhost:1234\n",
        reached=True,
    )
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["seq"] == 1
    assert record["track"] == "dynamic"
    assert record["node"] == "reach_target"
    assert record["kind"] == "gdb_batch"
    assert record["command"] == "gdb-multiarch -batch -x recipe_reach.gdb sbin/mailosd"
    assert record["exit_code"] == 0
    assert record["ok"] is True
    assert "Breakpoint 1" in record["stdout"]
    assert record["payload"].startswith("set architecture mips")
    assert record["notes"] == {"reached": True}
    assert record["ts"]


def test_record_captures_stderr_and_failure(tmp_path: Path):
    path = tmp_path / "gid.dynamic.jsonl"
    log = CommandLog(path, track="dynamic")
    log.record(
        node="satisfy_guards",
        kind="gdb_batch",
        command="gdb-multiarch -batch -x recipe_guards.gdb sbin/mailosd",
        result=_result(returncode=1, stdout="", stderr="connection refused"),
    )
    record = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert record["exit_code"] == 1
    assert record["ok"] is False
    assert record["stderr"] == "connection refused"


def test_seq_increments_across_records(tmp_path: Path):
    path = tmp_path / "gid.static.jsonl"
    log = CommandLog(path, track="static")
    log.record(node="a", kind="k", command="cmd1")
    log.record(node="b", kind="k", command="cmd2")
    log.record(node="c", kind="k", command="cmd3")
    seqs = [r["seq"] for r in log.read_all()]
    assert seqs == [1, 2, 3]


def test_two_tracks_write_independent_files(tmp_path: Path):
    dynamic_log = CommandLog(tmp_path / "gid.dynamic.jsonl", track="dynamic")
    static_log = CommandLog(tmp_path / "gid.static.jsonl", track="static")
    dynamic_log.record(node="reach_target", kind="gdb_batch", command="gdb ...")
    static_log.record(node="joern_script", kind="joern_script", command="joern --script q.sc")
    dynamic_records = dynamic_log.read_all()
    static_records = static_log.read_all()
    assert len(dynamic_records) == 1
    assert len(static_records) == 1
    assert dynamic_records[0]["track"] == "dynamic"
    assert static_records[0]["track"] == "static"


def test_write_failure_disables_log_without_raising(tmp_path: Path, monkeypatch):
    path = tmp_path / "gid.dynamic.jsonl"
    log = CommandLog(path, track="dynamic")

    def _broken_open(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(Path, "open", _broken_open)
    # Must not raise — the run continues even though logging is broken.
    log.record(node="reach_target", kind="gdb_batch", command="gdb ...")
    log.record(node="reach_target", kind="gdb_batch", command="gdb ...")


def test_constructor_survives_unwritable_parent_dir(tmp_path: Path, monkeypatch):
    path = tmp_path / "nested" / "gid.dynamic.jsonl"

    def _broken_mkdir(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "mkdir", _broken_mkdir)
    log = CommandLog(path, track="dynamic")
    # Should be silently disabled, not raise.
    log.record(node="n", kind="k", command="cmd")
    assert log.read_all() == []


def test_payload_path_and_cwd_recorded(tmp_path: Path):
    path = tmp_path / "gid.dynamic.jsonl"
    log = CommandLog(path, track="dynamic")
    log.record(
        node="reach_target",
        kind="write_recipe",
        command="cat > /tmp/fvvw/recipe_reach.gdb << 'FVVWEOF'",
        payload="break *0x400900\ncontinue\n",
        payload_path="/tmp/fvvw/recipe_reach.gdb",
        cwd="/work",
    )
    record = log.read_all()[0]
    assert record["payload_path"] == "/tmp/fvvw/recipe_reach.gdb"
    assert record["cwd"] == "/work"


def test_read_all_ignores_malformed_lines(tmp_path: Path):
    path = tmp_path / "gid.dynamic.jsonl"
    path.write_text('{"seq": 1, "notes": {}}\nnot json\n{"seq": 2, "notes": {}}\n')
    log = CommandLog(path, track="dynamic")
    records = log.read_all()
    assert [r["seq"] for r in records] == [1, 2]


def test_read_all_missing_file_returns_empty(tmp_path: Path):
    log = CommandLog(tmp_path / "does_not_exist.jsonl", track="dynamic")
    assert log.read_all() == []


def test_duration_ms_from_started_at(tmp_path: Path):
    import time

    path = tmp_path / "gid.dynamic.jsonl"
    log = CommandLog(path, track="dynamic")
    started = time.monotonic() - 0.05  # pretend the command took ~50ms
    log.record(node="n", kind="k", command="cmd", started_at=started)
    record = log.read_all()[0]
    assert record["duration_ms"] >= 40


# --------------------------------------------------------------------- #
# phase() / current_phase() — ContextVar isolation
# --------------------------------------------------------------------- #


def test_phase_sets_and_restores():
    assert current_phase() == ""
    with phase("reach_target"):
        assert current_phase() == "reach_target"
    assert current_phase() == ""


def test_phase_isolated_across_concurrent_tasks():
    """Mirrors observability.context's sibling-task isolation test — the
    static+crosscheck+dynamic fork in fvvw.graph.run_fvvw must never let
    one task's phase leak into another's."""

    async def _run():
        seen: dict[str, str] = {}

        async def worker(name: str, phase_name: str, delay: float):
            with phase(phase_name):
                await asyncio.sleep(delay)
                seen[name] = current_phase()

        task_a = asyncio.create_task(worker("dynamic", "reach_target", 0.02))
        task_b = asyncio.create_task(worker("static", "run_joern_script", 0.01))
        await asyncio.gather(task_a, task_b)
        return seen

    seen = asyncio.run(_run())
    assert seen == {"dynamic": "reach_target", "static": "run_joern_script"}


# --------------------------------------------------------------------- #
# LoggingSessionExecutor — composition wrapper, never edits SandboxExecutor
# --------------------------------------------------------------------- #


class _FakeSessionExecutor:
    """Minimal duck-typed fake matching SandboxExecutor's session trio,
    same shape tests/test_fvvw_graph.py already uses."""

    def __init__(self):
        self.started_with: dict | None = None
        self.exec_calls: list[tuple] = []
        self.stopped_handle: SessionHandle | None = None

    async def start(self, *, image=None, files=None, network=None, extra_args=None):
        self.started_with = {"image": image, "files": files, "network": network}
        return SessionHandle(container_name="fake-container-abc123", workspace_dir=files)

    async def exec_in_session(self, handle, command, *, timeout=None):
        self.exec_calls.append((handle, command, timeout))
        return ExecutionResult(
            command=command, returncode=0, stdout="ok", stderr="", timed_out=False
        )

    async def stop(self, handle):
        self.stopped_handle = handle


def test_logging_session_executor_passes_through_return_values(tmp_path: Path):
    async def _run():
        inner = _FakeSessionExecutor()
        log = CommandLog(tmp_path / "gid.dynamic.jsonl", track="dynamic")
        wrapped = LoggingSessionExecutor(inner, log)

        handle = await wrapped.start(image="fw-audit-verification-sandbox:latest")
        assert handle.container_name == "fake-container-abc123"

        result = await wrapped.exec_in_session(handle, "echo hi", timeout=30)
        assert result.stdout == "ok"
        assert result.returncode == 0

        await wrapped.stop(handle)
        assert inner.stopped_handle is handle
        return log

    log = asyncio.run(_run())
    records = log.read_all()
    kinds = [r["kind"] for r in records]
    assert kinds == ["session_start", "exec_in_session", "session_stop"]


def test_logging_session_executor_tags_records_with_active_phase(tmp_path: Path):
    async def _run():
        inner = _FakeSessionExecutor()
        log = CommandLog(tmp_path / "gid.dynamic.jsonl", track="dynamic")
        wrapped = LoggingSessionExecutor(inner, log)
        handle = await wrapped.start()
        with phase("reach_target"):
            await wrapped.exec_in_session(handle, "gdb-multiarch -batch -x r.gdb t")
        with phase("satisfy_guards"):
            await wrapped.exec_in_session(handle, "gdb-multiarch -batch -x g.gdb t")
        return log

    log = asyncio.run(_run())
    records = [r for r in log.read_all() if r["kind"] == "exec_in_session"]
    assert [r["node"] for r in records] == ["reach_target", "satisfy_guards"]


def test_logging_session_executor_records_full_stdout_and_stderr(tmp_path: Path):
    class _FailingExecutor(_FakeSessionExecutor):
        async def exec_in_session(self, handle, command, *, timeout=None):
            return ExecutionResult(
                command=command,
                returncode=1,
                stdout="",
                stderr="connection refused: gdbstub never opened port 1234",
                timed_out=False,
            )

    async def _run():
        inner = _FailingExecutor()
        log = CommandLog(tmp_path / "gid.dynamic.jsonl", track="dynamic")
        wrapped = LoggingSessionExecutor(inner, log)
        handle = await wrapped.start()
        with phase("reach_target"):
            await wrapped.exec_in_session(handle, "gdb-multiarch -batch -x r.gdb t")
        return log

    log = asyncio.run(_run())
    record = [r for r in log.read_all() if r["kind"] == "exec_in_session"][0]
    assert record["exit_code"] == 1
    assert record["ok"] is False
    assert "connection refused" in record["stderr"]


def test_logging_session_executor_proxies_unknown_attrs(tmp_path: Path):
    class _WithExtra(_FakeSessionExecutor):
        def available(self):
            return True

    inner = _WithExtra()
    log = CommandLog(tmp_path / "gid.dynamic.jsonl", track="dynamic")
    wrapped = LoggingSessionExecutor(inner, log)
    assert wrapped.available() is True


# --------------------------------------------------------------------- #
# JsonlRecordingList — static-track logging without editing agent/graph.py
# --------------------------------------------------------------------- #


@dataclass
class _FakeCpgBuildRecord:
    command: str = ""
    ok: bool = True
    duration_seconds: float = 1.0
    stderr: str = ""


@dataclass
class _FakeJoernScriptAttempt:
    attempt_index: int = 0
    script: str = "cpg.method.name(\"main\").l"
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = 0
    ok: bool = True
    result_marker: str | None = None
    evaluator_verdict: str | None = None
    evaluator_confidence: str = ""


def test_jsonl_recording_list_behaves_like_a_plain_list(tmp_path: Path):
    log = CommandLog(tmp_path / "gid.static.jsonl", track="static")
    holder = JsonlRecordingList(
        log,
        node="build_cpg",
        kind="joern_parse",
        to_fields=lambda r: {"command": r.command, "result": None},
    )
    holder.clear()  # plain list method, must not require overriding
    holder.append(_FakeCpgBuildRecord(command="joern-parse whole.c"))
    assert len(holder) == 1
    assert holder[0].command == "joern-parse whole.c"


def test_jsonl_recording_list_logs_on_append(tmp_path: Path):
    log = CommandLog(tmp_path / "gid.static.jsonl", track="static")
    attempts = JsonlRecordingList(
        log,
        node="run_script",
        kind="joern_script",
        to_fields=lambda a: {
            "command": f"joern --script query_{a.attempt_index:03d}.sc",
            "payload": a.script,
            "notes": {"result_marker": a.result_marker},
        },
    )
    attempts.append(_FakeJoernScriptAttempt(attempt_index=0, script="cpg.method.l"))
    records = log.read_all()
    assert len(records) == 1
    assert records[0]["kind"] == "joern_script"
    assert records[0]["node"] == "run_script"
    assert records[0]["payload"] == "cpg.method.l"
    assert "query_000.sc" in records[0]["command"]


def test_jsonl_recording_list_logs_on_setitem(tmp_path: Path):
    log = CommandLog(tmp_path / "gid.static.jsonl", track="static")
    attempts = JsonlRecordingList(
        log,
        node="evaluate",
        kind="joern_script",
        to_fields=lambda a: {
            "command": "",
            "notes": {"evaluator_verdict": a.evaluator_verdict},
        },
    )
    attempts.append(_FakeJoernScriptAttempt(attempt_index=0))
    attempts[-1] = _FakeJoernScriptAttempt(attempt_index=0, evaluator_verdict="PASS")
    records = log.read_all()
    assert len(records) == 2
    assert records[0]["kind"] == "joern_script"
    assert records[1]["kind"] == "joern_script_update"
    assert records[1]["notes"]["evaluator_verdict"] == "PASS"
