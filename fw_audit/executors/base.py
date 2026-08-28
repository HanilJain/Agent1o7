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


@dataclass(frozen=True)
class SessionHandle:
    """A live, still-running container a session-capable executor started —
    the opaque token `exec_in_session()`/`stop()` take.

    Introduced for Stage 5's QEMU+GDB dynamic-verification track (see
    `sandbox_executor.SandboxExecutor`'s module docstring): unlike `run()`,
    which is one-shot by design and fine for Joern (state survives via the
    host-mounted workspace between calls), an interactive QEMU+GDB session
    is inherently stateful and not disk-replayable — the emulated process
    and the GDB stub connected to it must stay alive across multiple
    `docker exec` calls (reach -> guards -> trigger -> collect). This
    dataclass carries just enough to address that running container; it is
    NOT an `Executor` itself and has no `run()`/`available()` of its own.
    """

    container_name: str
    """The `docker run -d --name <this>` container this handle addresses —
    same naming scheme `SandboxExecutor.run()` already uses for its one-shot
    containers, so orphan cleanup tooling recognizes both."""
    workspace_dir: Path | None = None
    """Host path bind-mounted into the session container, if any — mirrors
    `run()`'s `files` parameter. `None` for a session with no bind mount."""
    network_name: str | None = None
    """The scoped Docker network this session was started on, if
    `bringup_stabilize` requested one (see `Settings.stage5_allow_network_grant`).
    `None` means the session runs with the default `--network=none` posture.
    `stop()` implementations should tear this network down too, once no
    session references it."""


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
