"""Executor interface: the uniform contract for running a command, regardless
of backend (a plain Docker container, a Docker Sandbox, or the host directly).

Callers never branch on which backend answers `run()`:

    result = await executor.run(command="binwalk -e fw.bin", files=workspace)

Two execution *regimes* exist and must stay visibly distinct at the call site
that WIRES an executor (`fw_audit.executors.manager`), never at the call site
that USES one:

* Docker containers (`DockerExecutor`) — deterministic pipelines. A fixed,
  known command sequence (Stage 1's Extraction Script: unzip, binwalk,
  unsquashfs, tp-link-decrypt).
* Docker Sandboxes (`SandboxExecutor`) — reserved for later stages where an
  LLM agent writes/modifies scripts, executes unknown code, or experiments
  with binaries. Not implemented yet; see `sandbox_executor.py`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExecutionResult:
    """Outcome of a single `Executor.run()` call."""

    command: str
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class Executor(ABC):
    """Uniform command-execution interface across backends."""

    @abstractmethod
    async def run(
        self,
        command: str,
        *,
        files: Path | None = None,
        timeout: int | None = None,
    ) -> ExecutionResult:
        """Run `command`, optionally with `files` as its working directory.

        `files`, when given, is exposed as the command's working directory —
        backend-specific in how (a bind mount for Docker, `cwd=` on the
        host). Never raises on command failure; failures are reported via the
        returned `ExecutionResult` so callers can inspect/branch on them.
        """
        raise NotImplementedError

    def available(self) -> bool:
        """Best-effort synchronous readiness probe (e.g. is Docker reachable).

        Default: assume available. Backends that can cheaply verify
        readiness (`DockerExecutor`) override this for useful preflight
        error messages before any async work starts.
        """
        return True
