"""SandboxExecutor — runs commands inside a Docker container backing
LLM-controlled execution (an agent writing/running its own verification
code), unlike `DockerExecutor`'s fixed deterministic command sequences.

Stage 5's Joern verification agent (`stage5_verification.tools.joern_tool`)
is the first real consumer: the LLM decides WHEN to call `build_cpg`/
`run_joern_script` and WHAT Scala/CPGQL script content to run, but never
constructs the underlying `docker run`/`joern` command itself — that's
composed by the tool functions, same "LLM authors content, never the
command line" boundary `DockerExecutor` already draws for Stage 1/2.

Shape is deliberately close to `DockerExecutor.run()` (same `docker run
--rm --init --network=none`, bind-mounted workspace, orphaned-container
cleanup on timeout) with two differences: (1) an explicit `image` param, so
each tool module points this at its own image (mirrors
`stage2_extraction.ghidra.client.ghidra_executor()`'s `docker_image`
override, rather than a hardcoded `settings.docker_image`); (2) tighter
resource limits (`--memory`/`--cpus`/`--pids-limit`, from
`Settings.stage5_sandbox_*`) — this backend runs less-trusted,
LLM-authored script CONTENT, so it gets a stricter posture than the fixed
pipelines `DockerExecutor` runs.

IMPORTANT — `run()` itself is one-shot only, by design: every call starts a
fresh `--rm` container and it's gone when the command exits, exactly like
`DockerExecutor`. Stage 5's Joern tool works around this by persisting
state (the built CPG) to the host-mounted workspace directory between
calls, not via a live process — see `stage5_verification`'s own docs for
why that's sufficient for Joern. `run()` is NOT modified for the session
capability below — Joern's call sites (`tools/joern_tool.py`) keep using it
exactly as before.

SESSION CAPABILITY (`start()`/`exec_in_session()`/`stop()`): added
alongside `run()`, never retrofitted onto it, for Stage 5's QEMU+GDB
dynamic-verification track — an interactive debugging session is inherently
stateful and not disk-replayable (the emulated process and the GDB stub
attached to it must stay alive across several `reach_target`/
`satisfy_guards`/`instrument_trigger`/`collect_signals` calls). `start()`
runs `docker run -d --rm --init` (backgrounded, not `--rm`-and-gone) with
the same resource caps and bind-mount convention as `run()`, and returns a
`SessionHandle` carrying the container name. `exec_in_session()` runs a
command inside that already-running container via `docker exec`. `stop()`
force-removes it (and the scoped network, if one was granted) — safe to
call even if the container already exited on its own. Every method here
still funnels through `run_command()`, never a raw `subprocess`/`asyncio`
call, so the same timeout/prefix/logging discipline `run()` gets applies to
session calls too.
"""

from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

from fw_audit.config.settings import Settings, get_settings
from fw_audit.executors.base import ExecutionResult, Executor, SessionHandle
from fw_audit.executors.docker_executor import CONTAINER_WORKDIR, _host_user_flag
from fw_audit.stage1_ingestion.tools.extraction_tools import run_command


class SandboxExecutor(Executor):
    """Runs `command` inside `image` (or `settings.docker_image` if unset)
    via `docker run`, with tighter resource limits than `DockerExecutor`."""

    def __init__(self, settings: Settings | None = None, *, image: str | None = None) -> None:
        self._settings = settings or get_settings()
        self._image = image or self._settings.docker_image

    def available(self) -> bool:
        """Cheap synchronous preflight: is the Docker daemon reachable?

        Same check `DockerExecutor.available()` performs — deliberately
        synchronous so a caller can preflight before any async work starts.
        """
        try:
            proc = subprocess.run(
                [self._settings.docker_bin, "info"],
                capture_output=True,
                timeout=10,
                check=False,
            )
            return proc.returncode == 0
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return False

    async def run(
        self,
        command: str,
        *,
        files: Path | None = None,
        timeout: int | None = None,
    ) -> ExecutionResult:
        settings = self._settings
        container_name = f"fw-audit-sandbox-{uuid.uuid4().hex[:12]}"
        docker_args = [
            "run",
            "--rm",
            "--init",
            "--network=none",
            "--name",
            container_name,
            f"--memory={settings.stage5_sandbox_memory}",
            f"--cpus={settings.stage5_sandbox_cpus}",
            f"--pids-limit={settings.stage5_sandbox_pids_limit}",
        ]
        if settings.docker_run_as_host_user:
            docker_args += _host_user_flag()

        if files is not None:
            files = Path(files).resolve()
            files.mkdir(parents=True, exist_ok=True)
            docker_args += ["-v", f"{files}:{CONTAINER_WORKDIR}", "-w", CONTAINER_WORKDIR]

        docker_args += [self._image, "sh", "-c", command]

        run_settings = settings
        if timeout is not None and timeout != settings.subprocess_timeout_seconds:
            run_settings = run_settings.model_copy(update={"subprocess_timeout_seconds": timeout})
        # Same reasoning as DockerExecutor: the `docker` CLI call itself is
        # never routed through settings.command_prefix (e.g. WSL) — Docker
        # Desktop's own Linux VM is the sandbox.
        run_settings = run_settings.model_copy(update={"command_prefix": []})

        result = await run_command(settings.docker_bin, docker_args, settings=run_settings)
        stderr = result.stderr
        if result.timed_out:
            stderr = await self._cleanup_orphaned_container(container_name, run_settings, stderr)

        return ExecutionResult(
            command=command,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=stderr,
            timed_out=result.timed_out,
        )

    async def _cleanup_orphaned_container(
        self, container_name: str, settings: Settings, stderr: str
    ) -> str:
        """Best-effort `docker rm -f` after a timeout — same rationale as
        `DockerExecutor._cleanup_orphaned_container`: `run_command`'s
        `asyncio.wait_for` cancellation kills the host `docker` CLI
        process, not the daemon-side container it started."""
        cleanup_settings = settings.model_copy(update={"subprocess_timeout_seconds": 30})
        cleanup = await run_command(
            self._settings.docker_bin, ["rm", "-f", container_name], settings=cleanup_settings
        )
        if cleanup.ok:
            return stderr
        return (
            f"{stderr}\n[fw-audit] cleanup of orphaned sandbox container {container_name} "
            f"failed: {cleanup.stderr}"
        )

    # ------------------------------------------------------------------ #
    # Session capability — see this module's docstring. Added alongside
    # run(), never used by Joern's call sites.
    # ------------------------------------------------------------------ #

    async def start(
        self,
        *,
        image: str | None = None,
        files: Path | None = None,
        network: str | None = None,
        extra_args: list[str] | None = None,
    ) -> SessionHandle:
        """Start a long-lived, backgrounded container (`docker run -d`) and
        return a `SessionHandle` addressing it. The container is NOT
        `--rm`'d automatically — `stop()` is responsible for removing it, so
        state (a live QEMU process + its GDB stub) survives across multiple
        `exec_in_session()` calls.

        `network`, when given, is passed as `--network=<name>` instead of
        the default `--network=none` — the caller (`bringup_stabilize`) is
        responsible for having created that network first and for checking
        `Settings.stage5_allow_network_grant` before ever passing one; this
        method does not itself gate that policy, matching `run()`'s "the
        caller decides, this composes the command" division of
        responsibility.
        """
        settings = self._settings
        container_name = f"fw-audit-sandbox-session-{uuid.uuid4().hex[:12]}"
        docker_args = [
            "run",
            "-d",
            "--init",
            f"--network={network}" if network else "--network=none",
            "--name",
            container_name,
            f"--memory={settings.stage5_sandbox_memory}",
            f"--cpus={settings.stage5_sandbox_cpus}",
            f"--pids-limit={settings.stage5_sandbox_pids_limit}",
        ]
        if settings.docker_run_as_host_user:
            docker_args += _host_user_flag()

        workspace_dir: Path | None = None
        if files is not None:
            workspace_dir = Path(files).resolve()
            workspace_dir.mkdir(parents=True, exist_ok=True)
            docker_args += ["-v", f"{workspace_dir}:{CONTAINER_WORKDIR}", "-w", CONTAINER_WORKDIR]

        if extra_args:
            docker_args += extra_args

        run_image = image or self._image
        # A backgrounded session needs a command that keeps the container
        # alive (dockerd exits the container the instant its PID 1 command
        # returns) — `sleep infinity` is the standard idiom; the actual
        # work (QEMU, gdb-multiarch) happens via later `exec_in_session()`
        # calls, never as this container's entrypoint.
        docker_args += [run_image, "sleep", "infinity"]

        run_settings = settings.model_copy(update={"command_prefix": []})
        result = await run_command(settings.docker_bin, docker_args, settings=run_settings)
        if not result.ok:
            raise RuntimeError(
                f"failed to start sandbox session {container_name!r} "
                f"(image={run_image!r}): {result.stderr}"
            )
        return SessionHandle(
            container_name=container_name, workspace_dir=workspace_dir, network_name=network
        )

    async def exec_in_session(
        self,
        handle: SessionHandle,
        command: str,
        *,
        timeout: int | None = None,
    ) -> ExecutionResult:
        """Run `command` inside `handle`'s already-running container via
        `docker exec` — the session equivalent of `run()`, addressed at an
        existing container instead of starting a fresh one."""
        settings = self._settings
        docker_args = ["exec", handle.container_name, "sh", "-c", command]

        run_settings = settings
        if timeout is not None and timeout != settings.subprocess_timeout_seconds:
            run_settings = run_settings.model_copy(update={"subprocess_timeout_seconds": timeout})
        run_settings = run_settings.model_copy(update={"command_prefix": []})

        result = await run_command(settings.docker_bin, docker_args, settings=run_settings)
        return ExecutionResult(
            command=command,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
        )

    async def stop(self, handle: SessionHandle) -> None:
        """Force-remove `handle`'s container (`docker rm -f`) and, if it was
        granted a scoped network, remove that network too. Best-effort and
        idempotent — safe to call on a container that already exited or was
        already removed; failures are swallowed the same way
        `_cleanup_orphaned_container` treats a failed `docker rm` as
        non-fatal (the caller has nothing further to retry)."""
        cleanup_settings = self._settings.model_copy(
            update={"subprocess_timeout_seconds": 30, "command_prefix": []}
        )
        await run_command(
            self._settings.docker_bin,
            ["rm", "-f", handle.container_name],
            settings=cleanup_settings,
        )
        if handle.network_name:
            await run_command(
                self._settings.docker_bin,
                ["network", "rm", handle.network_name],
                settings=cleanup_settings,
            )
