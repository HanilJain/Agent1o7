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

IMPORTANT — one-shot only, by design, for now: every `run()` call starts a
fresh `--rm` container and it's gone when the command exits, exactly like
`DockerExecutor`. Stage 5's Joern tool works around this by persisting
state (the built CPG) to the host-mounted workspace directory between
calls, not via a live process — see `stage5_verification`'s own docs for
why that's sufficient for Joern. It will NOT be sufficient for an
interactive QEMU+GDB debugging session (inherently stateful, not
disk-replayable) — that will need a real session API (`start()`/
`exec_in_session()`/`stop()`, or a `docker run -d` + repeated `docker exec`
against the same container) added here as a genuinely new capability, not
retrofitted onto `run()`. Flagged here explicitly so a future implementer
doesn't mistake this one-shot shape for the final design.
"""

from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

from fw_audit.config.settings import Settings, get_settings
from fw_audit.executors.base import ExecutionResult, Executor
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
