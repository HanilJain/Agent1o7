"""LocalExecutor — runs commands directly on the host.

Intended for tests and non-firmware-touching dev workflows only. The real
firmware-extraction path in production always uses `DockerExecutor` (see
`fw_audit/executors/manager.py`); `LocalExecutor` never touches untrusted
firmware in the shipped pipeline — that boundary is enforced by what
`manager.get_executor()` wires by default (`FWA_EXECUTOR_BACKEND=docker`),
not by `LocalExecutor` being incapable.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from fw_audit.config.settings import Settings, get_settings
from fw_audit.executors.base import ExecutionResult, Executor
from fw_audit.stage1_ingestion.tools.extraction_tools import run_command


class LocalExecutor(Executor):
    """Adapter over the existing host subprocess primitive (`run_command`).

    Splits `command` with `shlex` and executes it directly — no shell
    features (pipes, redirects, globbing) are supported. That is an
    intentional limitation: every command routed through here is
    Stage-authored (e.g. `binwalk -e fw.bin`), never an agent-authored
    arbitrary shell script.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(
        self,
        command: str,
        *,
        files: Path | None = None,
        timeout: int | None = None,
    ) -> ExecutionResult:
        argv = shlex.split(command)
        if not argv:
            return ExecutionResult(
                command=command, returncode=1, stdout="", stderr="empty command", timed_out=False
            )

        settings = self._settings
        if timeout is not None and timeout != settings.subprocess_timeout_seconds:
            settings = settings.model_copy(update={"subprocess_timeout_seconds": timeout})

        result = await run_command(argv[0], argv[1:], settings=settings, cwd=files)
        return ExecutionResult(
            command=command,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
        )
