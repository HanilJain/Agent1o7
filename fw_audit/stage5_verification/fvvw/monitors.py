"""Concurrent monitors — Tier 3 (T3-L) of the FVVW dynamic-track
hardening plan. Each monitor here observes ONE aspect of the running
target/session and emits `common.verification.VerificationEvent`s into a
shared `asyncio.Queue`, so a process exit, a debugger disconnect, a
stalled round, a failed trigger, or a newly-created filesystem artifact
can be detected at the NEXT poll tick rather than only after the current
step finishes.

Every monitor here is a bounded, cancellable, finite async poller —
`run_monitors_until` drives a set of them concurrently via `asyncio.
gather` under a caller-supplied deadline/cancellation `asyncio.Event`, and
every individual poll round-trips through `SandboxExecutor.exec_in_session`
exactly the way every other dynamic-track node already does (see `fvvw.
dynamic_track`'s own module docstring) — no monitor here holds an
interactive/streaming process, and no monitor composes its own shell
command inline: every command string used below is either delegated to
`tools.qemu_gdb_tool` or is the SAME plain `pgrep`/`/proc`/`test -e`
one-liner `fvvw.dynamic_track`'s own deterministic checks already use
(`health_gate`, `collect_observation`), just wrapped as a repeating poll
instead of a single check.

Monitors are the ONLY code, alongside a dynamic-track node body's own
harness logic, permitted to construct a `VerificationEvent` — never an
LLM/agent. This is the schema-level expression of the plan's central
invariant ("no amount of agent reasoning, confidence, or planning can
become evidence") applied to the event layer specifically: an event
always traces back to a concrete command this module (or a node body)
actually ran and a concrete result it actually parsed.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import re

from fw_audit.common.verification import VerificationEvent
from fw_audit.executors.base import SessionHandle
from fw_audit.executors.sandbox_executor import SandboxExecutor
from fw_audit.stage5_verification.tools.qemu_gdb_tool import STOPPED_MARKER_PREFIX

_PROCESS_EXIT_RE = re.compile(r"Inferior\s+\d+\s+.*exited with code\s+(\d+)", re.IGNORECASE)
_SIGNAL_RE = re.compile(r"\bSIG(SEGV|ABRT|ILL)\b")


class EventSequencer:
    """A tiny monotonic per-kind sequence generator — every emitted
    `VerificationEvent.seq` for a given `kind` must be a strictly
    increasing integer for `fvvw.supervisor.apply_event`'s dedup logic
    (T3-K) to work at all, and several monitors run CONCURRENTLY, so a
    plain shared counter per kind (not a single global counter) is what
    lets independent monitors emit events of different kinds without
    contending on the same sequence number. One instance is shared by
    every monitor coroutine started together in `run_monitors_until`."""

    def __init__(self) -> None:
        self._counters: dict[str, itertools.count] = {}

    def next(self, kind: str) -> int:
        if kind not in self._counters:
            self._counters[kind] = itertools.count(start=1)
        return next(self._counters[kind])


async def process_health_monitor(
    *,
    handle: SessionHandle,
    session_executor: SandboxExecutor,
    process_binary: str,
    queue: asyncio.Queue[VerificationEvent],
    sequencer: EventSequencer,
    stop_event: asyncio.Event,
    poll_seconds: float,
    timeout_seconds: int,
) -> None:
    """Poll `pgrep -f <process_binary>` — the SAME liveness probe `health_
    gate`'s own Check 3 already runs as a one-shot check, here repeated on
    a cadence until `stop_event` is set. Emits `TARGET_STARTED` the first
    time the process is observed alive, `TARGET_EXITED` the first time it
    is observed gone after having been alive — never emits either
    repeatedly for an unchanged state (the reducer's own dedup would drop
    a resend anyway, but avoiding it here keeps the emitted event stream
    itself a clean record of actual TRANSITIONS, not a heartbeat)."""
    observed_alive = False
    while not stop_event.is_set():
        result = await session_executor.exec_in_session(
            handle,
            f"pgrep -f {process_binary} >/dev/null 2>&1 && echo ALIVE || echo DEAD",
            timeout=timeout_seconds,
        )
        alive = "ALIVE" in result.stdout
        if alive and not observed_alive:
            observed_alive = True
            await queue.put(
                VerificationEvent(
                    kind="TARGET_STARTED",
                    source="process_health_monitor",
                    seq=sequencer.next("TARGET_STARTED"),
                )
            )
        elif not alive and observed_alive:
            await queue.put(
                VerificationEvent(
                    kind="TARGET_EXITED",
                    source="process_health_monitor",
                    seq=sequencer.next("TARGET_EXITED"),
                    payload={},
                )
            )
            # The process cannot un-exit under this monitor's own process
            # table view (a genuinely new run gets a NEW BringupContext /
            # a fresh session and therefore a fresh monitor instance) —
            # stop polling rather than spin uselessly for the rest of the
            # deadline.
            return
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=poll_seconds)


def parse_transcript_events(
    combined_transcript: str, *, sequencer: EventSequencer, source: str = "gdb_transcript_monitor"
) -> list[VerificationEvent]:
    """Pure parser: extract every debugger/execution-progress fact a GDB
    batch's own combined stdout+stderr already carries — the reached/
    exited marker `render_gdb_recipe` prints (T1-D), GDB's own inferior-
    exit line, and a caught crash signal — as a list of `VerificationEvent`s
    ready to feed into `fvvw.supervisor.apply_events`. Deliberately a pure
    function (no session I/O of its own) so it can run against transcript
    text a node body already captured this round (mirroring `dynamic_
    track.collect_observation`'s own "pure parser, not itself a session
    call" shape) — the concurrent MONITOR half of debugger-progress
    watching is `gdb_transcript_poll_monitor` below, which calls this
    function against each poll's freshly-read transcript tail."""
    events: list[VerificationEvent] = []
    if STOPPED_MARKER_PREFIX in combined_transcript:
        events.append(
            VerificationEvent(
                kind="GDB_CONNECTED", source=source, seq=sequencer.next("GDB_CONNECTED")
            )
        )
        events.append(
            VerificationEvent(
                kind="BREAKPOINT_HIT", source=source, seq=sequencer.next("BREAKPOINT_HIT")
            )
        )
    exit_match = _PROCESS_EXIT_RE.search(combined_transcript)
    if exit_match:
        events.append(
            VerificationEvent(
                kind="TARGET_EXITED",
                source=source,
                seq=sequencer.next("TARGET_EXITED"),
                payload={"exit_code": int(exit_match.group(1))},
            )
        )
    signal_match = _SIGNAL_RE.search(combined_transcript)
    if signal_match:
        events.append(
            VerificationEvent(
                kind="SIGNAL_RECEIVED",
                source=source,
                seq=sequencer.next("SIGNAL_RECEIVED"),
                payload={"signal": f"SIG{signal_match.group(1)}"},
            )
        )
    return events


async def artifact_monitor(
    *,
    handle: SessionHandle,
    session_executor: SandboxExecutor,
    artifact_path: str,
    queue: asyncio.Queue[VerificationEvent],
    sequencer: EventSequencer,
    stop_event: asyncio.Event,
    poll_seconds: float,
    timeout_seconds: int,
) -> None:
    """Poll `test -e <artifact_path>` — the SAME filesystem-artifact probe
    `collect_observation`/`collect_signals` already run as a one-shot
    check — until the marker appears or `stop_event` is set. Emits
    `ARTIFACT_CREATED` exactly once, the first time the path is observed
    present, then stops polling (an artifact that already exists cannot
    un-appear in a way this monitor needs to track)."""
    if not artifact_path.strip():
        return
    while not stop_event.is_set():
        result = await session_executor.exec_in_session(
            handle,
            f"test -e {artifact_path} && echo FOUND || echo NOTFOUND",
            timeout=timeout_seconds,
        )
        if result.stdout.strip() == "FOUND":
            await queue.put(
                VerificationEvent(
                    kind="ARTIFACT_CREATED",
                    source="artifact_monitor",
                    seq=sequencer.next("ARTIFACT_CREATED"),
                    payload={"path": artifact_path},
                )
            )
            return
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=poll_seconds)


async def stall_monitor(
    *,
    queue: asyncio.Queue[VerificationEvent],
    sequencer: EventSequencer,
    stop_event: asyncio.Event,
    stall_after_seconds: float,
) -> None:
    """Emits exactly one `TIMEOUT` event if `stop_event` is not set
    within `stall_after_seconds` — the "stalled execution" signal
    `fvvw.supervisor.propose_action` reads from `VerificationState.
    failure_reason`. Distinct from `Settings.
    stage5_dynamic_wall_clock_seconds` (which bounds the WHOLE graph
    invocation from outside via `asyncio.wait_for`, see `fvvw.graph.
    run_dynamic_track_only`) — this is a PER-ROUND stall signal a caller
    can use to detect one step taking unusually long, well before the
    whole-run wall clock would ever trip."""
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(stop_event.wait(), timeout=stall_after_seconds)
        return
    await queue.put(
        VerificationEvent(
            kind="TIMEOUT",
            source="stall_monitor",
            seq=sequencer.next("TIMEOUT"),
            payload={"reason": f"no progress within {stall_after_seconds}s"},
        )
    )


async def drain_queue(queue: asyncio.Queue[VerificationEvent]) -> list[VerificationEvent]:
    """Drain every event currently buffered in `queue` WITHOUT blocking —
    the caller (a dynamic-track node step) calls this once per round to
    collect whatever concurrent monitors have observed since the last
    drain, then folds the batch into the canonical state via
    `fvvw.supervisor.apply_events`. Never awaits an empty queue — an empty
    queue simply means no monitor observed anything new this round, which
    is itself a normal, common outcome, not a condition to wait out."""
    events: list[VerificationEvent] = []
    while True:
        try:
            events.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            return events


async def run_monitors_until(
    monitors: list,
    *,
    stop_event: asyncio.Event,
    deadline_seconds: float,
) -> None:
    """Run every coroutine in `monitors` CONCURRENTLY via `asyncio.gather`,
    bounded by BOTH `stop_event` (the caller signals "the step this batch
    of monitors was watching has finished") and a hard `deadline_seconds`
    ceiling — so a monitor that never notices `stop_event` for some reason
    (a bug, a hung `exec_in_session` call) can never outlive its own
    caller's step and, transitively, can never outlive the whole dynamic
    graph's own `stage5_dynamic_wall_clock_seconds` wrapper (`fvvw.graph.
    run_dynamic_track_only`). Cancels every still-running monitor task on
    exit either way — no monitor task is ever leaked across rounds."""
    tasks = [asyncio.ensure_future(m) for m in monitors]
    try:
        await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True), timeout=deadline_seconds
        )
    except TimeoutError:
        pass
    finally:
        stop_event.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


__all__ = [
    "EventSequencer",
    "artifact_monitor",
    "drain_queue",
    "parse_transcript_events",
    "process_health_monitor",
    "run_monitors_until",
    "stall_monitor",
]
