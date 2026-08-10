"""Low-level async subprocess primitive, shared by the `Executor` backends.

`run_command()` and `CommandResult` back `fw_audit.executors.local_executor.
LocalExecutor` directly, and `fw_audit.executors.docker_executor.
DockerExecutor` uses `run_command()` to invoke the `docker` CLI itself.
Neither executor calls out to `binwalk`/`unsquashfs`/etc. through this
module directly anymore — that command composition lives in
`stage1_ingestion/extraction/script.py`, which goes through an `Executor`
so the actual firmware-unpacking commands always run in the configured
backend (Docker in production), never bypassing it.
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass
from pathlib import Path

from fw_audit.config.settings import Settings, get_settings


@dataclass(frozen=True)
class CommandResult:
    """Outcome of an external command invocation."""

    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


async def run_command(
    binary: str,
    args: list[str],
    *,
    settings: Settings | None = None,
    cwd: str | Path | None = None,
) -> CommandResult:
    """Run `binary args...`, prefixed with `settings.command_prefix`.

    Never raises on non-zero exit or a missing binary; both are reported via
    the returned :class:`CommandResult` so callers can decide how to react.
    """
    settings = settings or get_settings()
    full_command = [*settings.command_prefix, binary, *args]

    try:
        proc = await asyncio.create_subprocess_exec(
            *full_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
        )
    except (FileNotFoundError, OSError) as exc:
        return CommandResult(
            command=full_command, returncode=None, stdout="", stderr=str(exc), timed_out=False
        )

    comm = asyncio.ensure_future(proc.communicate())
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            asyncio.shield(comm), timeout=settings.subprocess_timeout_seconds
        )
        timed_out = False
    except TimeoutError:
        timed_out = True
        proc.kill()
        # `shield` kept `comm` alive across the cancelled `wait_for` wrapper
        # (shield cancels the wrapper, not the inner future) — `kill()` EOFs
        # the pipes, so this now resolves with whatever the process had
        # already written instead of discarding it. A Ghidra run that times
        # out at minute 29 of 30 still yields its partial log output.
        stdout_b, stderr_b = await comm

    return CommandResult(
        command=full_command,
        returncode=proc.returncode,
        stdout=stdout_b.decode("utf-8", errors="replace"),
        stderr=stderr_b.decode("utf-8", errors="replace"),
        timed_out=timed_out,
    )


def tool_available(binary: str, settings: Settings | None = None) -> bool:
    """Best-effort check for whether `binary` is runnable.

    Under a non-empty `command_prefix` we cannot reliably probe PATH from
    the host process, so this optimistically returns True and lets the
    actual invocation report failure instead.
    """
    settings = settings or get_settings()
    if settings.command_prefix:
        return True
    return shutil.which(binary) is not None
