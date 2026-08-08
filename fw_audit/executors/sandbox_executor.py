"""SandboxExecutor — reserved for future LLM-controlled execution. Not implemented.

Later stages (4: ACID controllability analysis, 5: dialectical hypothesis
verification / PoC generation) will need an agent to write and execute code
it generated itself — genuinely unknown code, not a fixed procedure. That
calls for a different isolation posture than `DockerExecutor` (deterministic
pipelines): stronger resource limits, likely no bind-mounted host workspace,
and probably a managed sandbox service rather than a bare `docker run`.

Stage 1 never uses this. The Identifier Agent (Stage 1's only LLM component)
has zero execution rights of any kind — it reads `tree.txt` text and returns
JSON; it does not even import this module. `SandboxExecutor` exists purely so
a later stage can implement it against the same `Executor` interface without
another refactor of executor call sites.
"""

from __future__ import annotations

from pathlib import Path

from fw_audit.config.settings import Settings, get_settings
from fw_audit.executors.base import ExecutionResult, Executor


class SandboxExecutor(Executor):
    """Stub. Raises `NotImplementedError` on every `run()` call."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    def available(self) -> bool:
        return False

    async def run(
        self,
        command: str,
        *,
        files: Path | None = None,
        timeout: int | None = None,
    ) -> ExecutionResult:
        raise NotImplementedError(
            "SandboxExecutor is reserved for future LLM-controlled execution "
            "stages (4/5) where an agent runs code it wrote itself. It is not "
            "implemented or wired into Stage 1 — Stage 1's Identifier Agent has "
            "no execution rights at all."
        )
