"""Tests for `stage5_verification.fvvw.monitors` — Tier 3's (T3-L)
concurrent bounded pollers. Every monitor round-trips through a duck-typed
`SandboxExecutor`-shaped fake (mirroring `tests/test_fvvw_dynamic_track.py::
_FakeSessionExecutor`'s spirit) — no real Docker/QEMU/GDB session
involved anywhere in this file.

Two groups:
1. Per-monitor unit tests — each monitor emits the correct event(s) for a
   scripted sequence of fake `exec_in_session` results.
2. `run_monitors_until` — several monitors actually run CONCURRENTLY
   (via `asyncio.gather`), each detecting its own aspect independently
   and emitting into the shared queue regardless of what the others are
   doing — the "process exit / debugger failure / stalled execution /
   failed trigger / new artifact detected immediately, not only after
   the current step finishes" requirement, exercised directly.
"""

from __future__ import annotations

import asyncio

from fw_audit.executors.base import ExecutionResult, SessionHandle
from fw_audit.stage5_verification.fvvw.monitors import (
    EventSequencer,
    artifact_monitor,
    drain_queue,
    parse_transcript_events,
    process_health_monitor,
    run_monitors_until,
    stall_monitor,
)
from fw_audit.stage5_verification.tools.qemu_gdb_tool import STOPPED_MARKER_PREFIX


class _ScriptedSessionExecutor:
    """A fake session executor whose `exec_in_session` response depends
    on how many times a MATCHING command has already been called — lets
    a test script "first poll: X, second poll: Y" sequences per command
    kind, which is what proving a monitor detects a TRANSITION (not just
    a static fact) needs."""

    def __init__(self) -> None:
        self.call_counts: dict[str, int] = {}
        self.responses: dict[str, list[ExecutionResult]] = {}

    def script(self, match: str, *responses: ExecutionResult) -> None:
        self.responses[match] = list(responses)

    async def exec_in_session(self, handle, command, *, timeout=None, user=None):
        for match, responses in self.responses.items():
            if match in command:
                idx = self.call_counts.get(match, 0)
                self.call_counts[match] = idx + 1
                if idx < len(responses):
                    return responses[idx]
                return responses[-1]
        return ExecutionResult(command=command, returncode=0, stdout="", stderr="", timed_out=False)


def _ok(stdout: str) -> ExecutionResult:
    return ExecutionResult(command="x", returncode=0, stdout=stdout, stderr="", timed_out=False)


# --------------------------------------------------------------------- #
# EventSequencer
# --------------------------------------------------------------------- #


def test_event_sequencer_is_monotonic_per_kind():
    seq = EventSequencer()
    assert seq.next("TARGET_STARTED") == 1
    assert seq.next("TARGET_STARTED") == 2
    assert seq.next("TARGET_EXITED") == 1  # independent counter per kind


# --------------------------------------------------------------------- #
# process_health_monitor — process-exit detection
# --------------------------------------------------------------------- #


async def test_process_health_monitor_detects_start_then_exit():
    """Process-exit detection: the monitor emits TARGET_STARTED the first
    time the process is observed alive, then TARGET_EXITED the first time
    it is observed gone afterward — the exact transition-detection
    behavior a bare one-shot `pgrep` check cannot provide."""
    session = _ScriptedSessionExecutor()
    session.script("pgrep", _ok("ALIVE\n"), _ok("ALIVE\n"), _ok("DEAD\n"))

    handle = SessionHandle(container_name="fake")
    queue: asyncio.Queue = asyncio.Queue()
    seq = EventSequencer()
    stop_event = asyncio.Event()

    await process_health_monitor(
        handle=handle,
        session_executor=session,
        process_binary="qemu-arm",
        queue=queue,
        sequencer=seq,
        stop_event=stop_event,
        poll_seconds=0.001,
        timeout_seconds=1,
    )

    events = await drain_queue(queue)
    kinds = [e.kind for e in events]
    assert kinds == ["TARGET_STARTED", "TARGET_EXITED"]


async def test_process_health_monitor_stops_polling_after_exit_detected():
    """Once TARGET_EXITED is emitted, the monitor returns (stops itself)
    rather than continuing to poll a process that cannot un-exit — a
    bounded, finite poller, never an unbounded loop."""
    session = _ScriptedSessionExecutor()
    session.script("pgrep", _ok("ALIVE\n"), _ok("DEAD\n"))
    handle = SessionHandle(container_name="fake")
    queue: asyncio.Queue = asyncio.Queue()
    seq = EventSequencer()
    stop_event = asyncio.Event()

    await asyncio.wait_for(
        process_health_monitor(
            handle=handle,
            session_executor=session,
            process_binary="qemu-arm",
            queue=queue,
            sequencer=seq,
            stop_event=stop_event,
            poll_seconds=0.001,
            timeout_seconds=1,
        ),
        timeout=2,
    )  # must complete on its own — a hang here fails the test via timeout
    assert session.call_counts["pgrep"] == 2


async def test_process_health_monitor_never_alive_emits_no_events():
    session = _ScriptedSessionExecutor()
    session.script("pgrep", _ok("DEAD\n"))
    handle = SessionHandle(container_name="fake")
    queue: asyncio.Queue = asyncio.Queue()
    seq = EventSequencer()
    stop_event = asyncio.Event()
    stop_event.set()  # stop immediately after the first poll

    await process_health_monitor(
        handle=handle,
        session_executor=session,
        process_binary="qemu-arm",
        queue=queue,
        sequencer=seq,
        stop_event=stop_event,
        poll_seconds=0.001,
        timeout_seconds=1,
    )
    events = await drain_queue(queue)
    assert events == []


# --------------------------------------------------------------------- #
# parse_transcript_events — debugger/execution-progress events from a
# GDB transcript
# --------------------------------------------------------------------- #


def test_parse_transcript_events_stopped_marker_emits_hit():
    seq = EventSequencer()
    transcript = f"Breakpoint 1, 0x1000 in main ()\n{STOPPED_MARKER_PREFIX}0x1000\n"
    events = parse_transcript_events(transcript, sequencer=seq)
    kinds = {e.kind for e in events}
    assert "GDB_CONNECTED" in kinds
    assert "BREAKPOINT_HIT" in kinds


def test_parse_transcript_events_exit_line_emits_target_exited():
    seq = EventSequencer()
    transcript = "Continuing.\n[Inferior 1 (process 1) exited with code 01]\n"
    events = parse_transcript_events(transcript, sequencer=seq)
    exit_events = [e for e in events if e.kind == "TARGET_EXITED"]
    assert len(exit_events) == 1
    assert exit_events[0].payload["exit_code"] == 1


def test_parse_transcript_events_signal_emits_signal_received():
    seq = EventSequencer()
    transcript = "Program received signal SIGSEGV, Segmentation fault.\n"
    events = parse_transcript_events(transcript, sequencer=seq)
    signal_events = [e for e in events if e.kind == "SIGNAL_RECEIVED"]
    assert len(signal_events) == 1
    assert signal_events[0].payload["signal"] == "SIGSEGV"


def test_parse_transcript_events_empty_transcript_emits_nothing():
    seq = EventSequencer()
    assert parse_transcript_events("", sequencer=seq) == []


# --------------------------------------------------------------------- #
# artifact_monitor — filesystem evidence, detected as it appears
# --------------------------------------------------------------------- #


async def test_artifact_monitor_emits_once_artifact_appears():
    session = _ScriptedSessionExecutor()
    session.script("test -e", _ok("NOTFOUND\n"), _ok("NOTFOUND\n"), _ok("FOUND\n"))
    handle = SessionHandle(container_name="fake")
    queue: asyncio.Queue = asyncio.Queue()
    seq = EventSequencer()
    stop_event = asyncio.Event()

    await artifact_monitor(
        handle=handle,
        session_executor=session,
        artifact_path="/tmp/claim_001_proof",
        queue=queue,
        sequencer=seq,
        stop_event=stop_event,
        poll_seconds=0.001,
        timeout_seconds=1,
    )
    events = await drain_queue(queue)
    assert len(events) == 1
    assert events[0].kind == "ARTIFACT_CREATED"
    assert events[0].payload["path"] == "/tmp/claim_001_proof"


async def test_artifact_monitor_empty_path_is_a_no_op():
    session = _ScriptedSessionExecutor()
    handle = SessionHandle(container_name="fake")
    queue: asyncio.Queue = asyncio.Queue()
    seq = EventSequencer()
    stop_event = asyncio.Event()
    await artifact_monitor(
        handle=handle,
        session_executor=session,
        artifact_path="",
        queue=queue,
        sequencer=seq,
        stop_event=stop_event,
        poll_seconds=0.001,
        timeout_seconds=1,
    )
    assert await drain_queue(queue) == []


# --------------------------------------------------------------------- #
# stall_monitor — timeouts
# --------------------------------------------------------------------- #


async def test_stall_monitor_emits_timeout_when_never_stopped():
    queue: asyncio.Queue = asyncio.Queue()
    seq = EventSequencer()
    stop_event = asyncio.Event()  # never set
    await stall_monitor(
        queue=queue, sequencer=seq, stop_event=stop_event, stall_after_seconds=0.01
    )
    events = await drain_queue(queue)
    assert len(events) == 1
    assert events[0].kind == "TIMEOUT"


async def test_stall_monitor_emits_nothing_when_stopped_in_time():
    queue: asyncio.Queue = asyncio.Queue()
    seq = EventSequencer()
    stop_event = asyncio.Event()
    stop_event.set()
    await stall_monitor(
        queue=queue, sequencer=seq, stop_event=stop_event, stall_after_seconds=10
    )
    assert await drain_queue(queue) == []


# --------------------------------------------------------------------- #
# run_monitors_until — several monitors running CONCURRENTLY
# --------------------------------------------------------------------- #


async def test_monitors_emit_events_concurrently():
    """Several independent monitors (process health + filesystem
    artifact + a stall timer) run under asyncio.gather and each detects
    its own aspect independently — a process exit, a new artifact, and a
    stall are all observed in the SAME run, regardless of which monitor
    'finishes first', proving genuine concurrency rather than a
    disguised sequential loop."""
    session = _ScriptedSessionExecutor()
    session.script("pgrep", _ok("ALIVE\n"), _ok("DEAD\n"))
    session.script("test -e", _ok("NOTFOUND\n"), _ok("FOUND\n"))

    handle = SessionHandle(container_name="fake")
    queue: asyncio.Queue = asyncio.Queue()
    seq = EventSequencer()
    stop_event = asyncio.Event()

    monitors = [
        process_health_monitor(
            handle=handle,
            session_executor=session,
            process_binary="qemu-arm",
            queue=queue,
            sequencer=seq,
            stop_event=stop_event,
            poll_seconds=0.001,
            timeout_seconds=1,
        ),
        artifact_monitor(
            handle=handle,
            session_executor=session,
            artifact_path="/tmp/claim_001_proof",
            queue=queue,
            sequencer=seq,
            stop_event=stop_event,
            poll_seconds=0.001,
            timeout_seconds=1,
        ),
        stall_monitor(
            queue=queue, sequencer=seq, stop_event=stop_event, stall_after_seconds=5
        ),
    ]

    await run_monitors_until(monitors, stop_event=stop_event, deadline_seconds=2.0)

    events = await drain_queue(queue)
    kinds = {e.kind for e in events}
    assert "TARGET_STARTED" in kinds
    assert "TARGET_EXITED" in kinds
    assert "ARTIFACT_CREATED" in kinds
    # stall_monitor must NOT have fired — the other two monitors finished
    # and set stop_event well before its own 5s deadline.
    assert "TIMEOUT" not in kinds


async def test_run_monitors_until_respects_hard_deadline_even_if_stop_event_never_set():
    """A monitor that (by bug or design) never notices stop_event cannot
    outlive run_monitors_until's own hard deadline — bounded concurrency,
    never an unbounded task leak."""

    async def _never_finishing_monitor(stop_event: asyncio.Event) -> None:
        await stop_event.wait()  # would hang forever if stop_event is never set

    stop_event = asyncio.Event()
    started = asyncio.get_event_loop().time()
    await run_monitors_until(
        [_never_finishing_monitor(stop_event)], stop_event=stop_event, deadline_seconds=0.2
    )
    elapsed = asyncio.get_event_loop().time() - started
    assert elapsed < 2.0, "run_monitors_until did not respect its own deadline"
    assert stop_event.is_set()  # finally block always sets it on exit


async def test_run_monitors_until_cancels_stragglers():
    """Every still-running monitor task is cancelled on exit — no task is
    ever leaked across rounds, regardless of how the batch ended."""
    cancelled = asyncio.Event()

    async def _straggler(stop_event: asyncio.Event) -> None:
        try:
            await asyncio.sleep(100)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    stop_event = asyncio.Event()
    await run_monitors_until(
        [_straggler(stop_event)], stop_event=stop_event, deadline_seconds=0.1
    )
    assert cancelled.is_set()


# --------------------------------------------------------------------- #
# drain_queue — never blocks on an empty queue
# --------------------------------------------------------------------- #


async def test_drain_queue_never_blocks_on_empty_queue():
    queue: asyncio.Queue = asyncio.Queue()
    events = await asyncio.wait_for(drain_queue(queue), timeout=1)
    assert events == []
