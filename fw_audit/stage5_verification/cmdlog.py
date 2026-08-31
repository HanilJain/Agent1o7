"""Per-track, append-only JSONL command logging for Stage 5's fork-join.

Every command either the static (Joern) or dynamic (QEMU+GDB) track
executes — plus its full result — gets one `CommandRecord` appended to
`stage5/fvvw/logs/<gid>.<track>.jsonl` via `CommandLog.record()`. This is
deliberately separate from `observability/` (LangSmith spans): a span is a
no-op when tracing is off and its content is capped/truncated for a
dashboard; this log is ALWAYS on by default (`Settings.stage5_command_log`)
and NEVER truncates, so a failed run stays diagnosable from disk alone
without needing `--trace` or a LangSmith account. It inherits ONLY the
"never breaks a real run" half of `observability/`'s discipline (fail once,
then go quiet), not the "no-op when tracing is off" half — this log's whole
purpose is to exist even with `--no-trace`.

Two extra pieces beyond the bare `CommandLog` sink:

* `LoggingSessionExecutor` — wraps a `SandboxExecutor` (or anything
  duck-typing its `start`/`exec_in_session`/`stop` trio; `fvvw.
  dynamic_track` only ever calls those three) so EVERY dynamic-track
  command is captured centrally, including the ones today's code discards
  the result of entirely (`pkill`, the backgrounded launch, the readiness
  probe). This wraps by COMPOSITION, never by editing `SandboxExecutor`
  itself — that class is shared with Stage 1/2 via `run()`, which stays
  untouched (see its own module docstring).
* `JsonlRecordingList` — a `list` subclass that logs on `append`/
  `__setitem__`. `fvvw.static_track.run_static_track` already passes two
  plain lists (`cpg_build_holder`, `attempts`) into `agent.graph.
  build_verifier_graph`, which is the ONLY thing that ever mutates them
  (`.clear()`/`.append()`/`attempts[-1] = ...`). Passing a
  `JsonlRecordingList` instead gives full static-track logging with ZERO
  edits to `agent/graph.py` — see `stage5_verification/CLAUDE.md`'s "reused
  UNCHANGED" constraint.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from fw_audit.executors.base import ExecutionResult, SessionHandle

logger = logging.getLogger(__name__)

# The active node/phase name (e.g. "reach_target", "satisfy_guards") for
# whichever dynamic-track function is currently issuing commands through a
# `LoggingSessionExecutor` — read by that wrapper on every call so node
# functions don't need a `log=`/`node=` parameter threaded through them.
# A ContextVar, not a plain module global, for the same reason
# `observability.context`'s `TraceContext` is one: concurrent
# `asyncio.create_task`/`ensure_future` fan-out (the static+crosscheck+
# dynamic fork in `fvvw.graph.run_fvvw`) must never let one task's phase
# leak into a sibling's.
_phase: ContextVar[str] = ContextVar("fvvw_cmdlog_phase", default="")


@contextmanager
def phase(name: str) -> Iterator[None]:
    """Mark every command issued through a `LoggingSessionExecutor` inside
    this block as belonging to node/phase `name`. Restores the previous
    phase on exit (nested phases are legal, though the dynamic track's
    nodes don't currently nest them)."""
    token = _phase.set(name)
    try:
        yield
    finally:
        _phase.reset(token)


@asynccontextmanager
async def aphase(name: str) -> AsyncIterator[None]:
    """Async counterpart of `phase()` — for use as one of the items in a
    compound `async with aspan(...) as run, aphase("node_name"):` statement
    (Python requires every item in an `async with` tuple to itself be an
    async context manager; a plain `@contextmanager` can't be mixed in).
    Behavior is identical to `phase()`, just entered/exited via
    `__aenter__`/`__aexit__` instead of `__enter__`/`__exit__`."""
    token = _phase.set(name)
    try:
        yield
    finally:
        _phase.reset(token)


def current_phase() -> str:
    return _phase.get()


@dataclass
class CommandRecord:
    """One executed command and its outcome. `payload` carries the GDB
    recipe / Joern script text verbatim when the command ran one (empty
    otherwise) — kept as its own field rather than folded into `command`
    so the command line itself stays short and greppable."""

    seq: int
    track: str
    """`"dynamic"` or `"static"` — which track issued this command."""
    node: str
    """The node/function that issued it, e.g. `"reach_target"`,
    `"joern_script"` — matches the LangSmith span name's tail where one
    exists, so the two logs can be cross-referenced by eye."""
    kind: str
    """A short tag for the command's role, e.g. `"gdb_batch"`,
    `"qemu_launch"`, `"joern_script"`, `"fault"` — see each track's own
    call sites for the vocabulary in use."""
    command: str
    cwd: str = ""
    exit_code: int | None = None
    ok: bool = False
    duration_ms: int = 0
    stdout: str = ""
    stderr: str = ""
    payload: str = ""
    payload_path: str = ""
    notes: dict = field(default_factory=dict)
    ts: str = ""

    def to_json_line(self) -> str:
        return json.dumps(
            {
                "seq": self.seq,
                "ts": self.ts,
                "track": self.track,
                "node": self.node,
                "kind": self.kind,
                "command": self.command,
                "cwd": self.cwd,
                "exit_code": self.exit_code,
                "ok": self.ok,
                "duration_ms": self.duration_ms,
                "stdout": self.stdout,
                "stderr": self.stderr,
                "payload": self.payload,
                "payload_path": self.payload_path,
                "notes": self.notes,
            },
            default=str,
        )


class CommandLog:
    """Append-only JSONL sink for one track's `CommandRecord`s. Construct
    one per (candidate, track) — `seq` is local to the instance.

    Never raises past `record()`: a filesystem error on the first write
    disables the log (falls back to `disabled()` behavior) for the rest of
    its lifetime, logging one `logger.warning` so the operator learns why
    the file is short, without the verification node itself failing."""

    def __init__(self, path: Path | None, *, track: str = ""):
        self._path = path
        self._track = track
        self._seq = 0
        self._broken = False
        if self._path is not None:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                logger.warning("CommandLog: could not create %s: %s", self._path, exc)
                self._broken = True

    @classmethod
    def disabled(cls) -> CommandLog:
        """A no-op instance — used when `Settings.stage5_command_log` is
        `False`, or as the default for any context that never received a
        real path (e.g. `debug.py`'s dry runs)."""
        return cls(None)

    @property
    def path(self) -> Path | None:
        """The JSONL file this log writes to, or `None` for a disabled
        instance — exposed read-only so a caller (a test, or the HITL
        prompt) can point the operator at the file without reaching into
        the private `_path`."""
        return self._path

    def record(
        self,
        *,
        node: str,
        kind: str,
        command: str,
        result: ExecutionResult | None = None,
        payload: str = "",
        payload_path: str = "",
        cwd: str = "",
        duration_ms: int = 0,
        started_at: float | None = None,
        exit_code: int | None = None,
        ok: bool | None = None,
        stdout: str = "",
        stderr: str = "",
        notes: dict | None = None,
        **extra_notes: object,
    ) -> None:
        """Append one record. `result`, when given, supplies
        `exit_code`/`ok`/`stdout`/`stderr` from an `ExecutionResult` —
        callers that already have one pass it instead of unpacking it by
        hand. A caller with no `ExecutionResult` (e.g. `fvvw.static_track`
        logging from an already-parsed `JoernScriptAttempt`) passes
        `exit_code`/`ok`/`stdout`/`stderr` directly instead — `result`
        wins if both are given. `started_at` (a `time.monotonic()`
        timestamp taken before the command ran) computes `duration_ms`
        automatically; pass `duration_ms` directly when the caller measured
        it itself. `notes` (a dict) and any extra keyword arguments are
        merged together into the record's `notes` field — e.g. both
        `record(..., reached=True)` and `record(..., notes={"reached":
        True})` work, and a caller building its dict programmatically
        (`JsonlRecordingList`'s `to_fields`) can use whichever reads
        better. Never raises."""
        if self._path is None or self._broken:
            return

        self._seq += 1
        if result is not None:
            exit_code = result.returncode
            ok = result.ok
            stdout = result.stdout
            stderr = result.stderr

        if duration_ms == 0 and started_at is not None:
            duration_ms = int((time.monotonic() - started_at) * 1000)

        merged_notes = {**(notes or {}), **extra_notes}
        record = CommandRecord(
            seq=self._seq,
            track=self._track,
            node=node,
            kind=kind,
            command=command,
            cwd=cwd,
            exit_code=exit_code,
            ok=bool(ok),
            duration_ms=duration_ms,
            stdout=stdout,
            stderr=stderr,
            payload=payload,
            payload_path=payload_path,
            notes=merged_notes,
            ts=datetime.now(UTC).isoformat(),
        )
        try:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(record.to_json_line() + "\n")
        except OSError as exc:
            logger.warning(
                "CommandLog: disabling log at %s after write failure: %s", self._path, exc
            )
            self._broken = True

    def read_all(self) -> list[dict]:
        """Best-effort read-back of every record written so far — used by
        the HITL prompt to show recent command history. Returns `[]` on
        any error (missing/unreadable file) rather than raising; this is a
        UI convenience, not a data path anything depends on."""
        if self._path is None:
            return []
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        records: list[dict] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records


class LoggingSessionExecutor:
    """Wraps a session-capable executor (`SandboxExecutor`, or a test
    fake — `fvvw.dynamic_track` only ever calls `start`/`exec_in_session`/
    `stop`, so this only needs to forward those three) and logs every
    `exec_in_session()` call through `log`, tagged with whatever `phase()`
    block is active. `start()`/`stop()` are also logged (`kind=
    "session_start"`/`"session_stop"`) since those are the two calls
    today's code has zero visibility into.

    A pure pass-through of return values — every method returns exactly
    what the wrapped executor returned, so callers (and existing tests
    against a fake session executor) see no behavior change, only an added
    log side effect."""

    def __init__(self, inner: Any, log: CommandLog) -> None:
        self._inner = inner
        self._log = log

    async def start(
        self,
        *,
        image: str | None = None,
        files: Path | None = None,
        network: str | None = None,
        extra_args: list[str] | None = None,
    ) -> SessionHandle:
        started = time.monotonic()
        # `extra_args` is forwarded only when actually given — the wrapped
        # executor may be a narrower test fake (see
        # tests/test_fvvw_graph.py's `_FakeSessionExecutor`) that doesn't
        # accept it at all; no real call site in this repo passes it today.
        kwargs: dict[str, Any] = {"image": image, "files": files, "network": network}
        if extra_args is not None:
            kwargs["extra_args"] = extra_args
        handle = await self._inner.start(**kwargs)
        self._log.record(
            node=current_phase() or "session",
            kind="session_start",
            command=f"docker run -d ... {image or ''}".strip(),
            duration_ms=int((time.monotonic() - started) * 1000),
            container=handle.container_name,
            files=str(files) if files else "",
            network=network or "",
        )
        return handle

    async def exec_in_session(
        self,
        handle: SessionHandle,
        command: str,
        *,
        timeout: int | None = None,
    ) -> ExecutionResult:
        started = time.monotonic()
        result = await self._inner.exec_in_session(handle, command, timeout=timeout)
        self._log.record(
            node=current_phase() or "exec",
            kind="exec_in_session",
            command=command,
            result=result,
            duration_ms=int((time.monotonic() - started) * 1000),
            cwd="",
            container=handle.container_name,
            timeout=timeout,
        )
        return result

    async def stop(self, handle: SessionHandle) -> None:
        started = time.monotonic()
        await self._inner.stop(handle)
        self._log.record(
            node=current_phase() or "session",
            kind="session_stop",
            command=f"docker rm -f {handle.container_name}",
            duration_ms=int((time.monotonic() - started) * 1000),
            container=handle.container_name,
        )

    def __getattr__(self, name: str) -> Any:
        # Anything beyond the three session methods (e.g. `run()`, if a
        # caller ever needed it) falls through to the wrapped executor
        # unlogged — dynamic_track.py never calls anything else, but this
        # keeps the wrapper a transparent proxy rather than a partial one.
        return getattr(self._inner, name)


_T = TypeVar("_T")


class JsonlRecordingList(list):
    """A `list` subclass that logs to a `CommandLog` on `append`/
    `__setitem__`, otherwise behaving exactly like a plain list — used to
    intercept `agent.graph.build_verifier_graph`'s `cpg_build_holder`/
    `attempts` parameters (see this module's docstring) WITHOUT editing
    that graph. `to_fields` converts one appended/set item into the
    `CommandLog.record()` keyword arguments — the caller supplies it so
    this class stays generic over `CpgBuildRecord` vs `JoernScriptAttempt`
    rather than importing either."""

    def __init__(
        self,
        log: CommandLog,
        *,
        node: str,
        kind: str,
        to_fields: Callable[[Any], dict],
    ) -> None:
        super().__init__()
        self._log = log
        self._node = node
        self._kind = kind
        self._to_fields = to_fields

    def append(self, item: _T) -> None:
        super().append(item)
        self._log.record(node=self._node, kind=self._kind, **self._to_fields(item))

    def __setitem__(self, index: Any, item: Any) -> None:
        super().__setitem__(index, item)
        self._log.record(
            node=self._node, kind=f"{self._kind}_update", **self._to_fields(item)
        )


__all__ = [
    "CommandLog",
    "CommandRecord",
    "JsonlRecordingList",
    "LoggingSessionExecutor",
    "aphase",
    "current_phase",
    "phase",
]
