"""DockerExecutor — runs commands inside a plain, deterministic container.

This is the production backend for Stage 1's Extraction Script: a fixed,
known command sequence (unzip -> binwalk -> [tp-link-decrypt -> binwalk] ->
tree.txt) running isolated, with no network access at runtime. It is a plain
container, NOT a "sandbox" in the LLM-controlled-execution sense — see
`sandbox_executor.py` for that (unimplemented, reserved for later stages).
"""

from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

from fw_audit.config.settings import Settings, get_settings
from fw_audit.executors.base import ExecutionResult, Executor
from fw_audit.stage1_ingestion.tools.extraction_tools import run_command

CONTAINER_WORKDIR = "/work"


def to_container_path(host_path: str | Path, workspace_root: Path) -> str:
    """Translate a host path under `workspace_root` to its in-container mount path.

    `workspace_root` is bind-mounted at `/work`; a path outside it is not
    visible to the container and raises `ValueError`.
    """
    resolved = Path(host_path).resolve()
    root = workspace_root.resolve()
    try:
        rel = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"{resolved} is not inside the mounted workspace {root}; "
            "the container cannot see it."
        ) from exc
    rel_posix = rel.as_posix()
    return f"{CONTAINER_WORKDIR}/{rel_posix}" if rel_posix != "." else CONTAINER_WORKDIR


class DockerExecutor(Executor):
    """Runs `command` inside `settings.docker_image` via `docker run`."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    def available(self) -> bool:
        """Cheap synchronous preflight: is the Docker daemon reachable?

        Deliberately synchronous (not the async `run_command`) so a caller
        can preflight before any event loop / async work starts.
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
        # Named (rather than anonymous) so a timeout can address it for
        # cleanup below; `--init` reaps zombie processes a long-running tool
        # like Ghidra's JVM can otherwise leave behind as PID 1.
        container_name = f"fw-audit-{uuid.uuid4().hex[:12]}"
        docker_args = ["run", "--rm", "--init", "--network=none", "--name", container_name]

        if files is not None:
            files = Path(files).resolve()
            files.mkdir(parents=True, exist_ok=True)
            docker_args += ["-v", f"{files}:{CONTAINER_WORKDIR}", "-w", CONTAINER_WORKDIR]

        docker_args += [settings.docker_image, "sh", "-c", command]

        run_settings = settings
        if timeout is not None and timeout != settings.subprocess_timeout_seconds:
            run_settings = run_settings.model_copy(update={"subprocess_timeout_seconds": timeout})
        # The `docker` CLI call itself is never routed through
        # settings.command_prefix (e.g. WSL) — Docker Desktop's own Linux VM
        # is the sandbox; layering WSL routing underneath it would be
        # redundant and, on this host, unnecessary (docker.exe is on PATH).
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
        """Best-effort `docker rm -f` after a timeout.

        `run_command`'s `asyncio.wait_for` cancellation kills the host
        `docker` CLI process, not the daemon-side container it started
        (dockerd owns the container, not the CLI's process tree) — so
        without this, a timed-out run leaves the container running
        indefinitely despite `--rm`. Cleanup failure is appended to stderr,
        never raised: a best-effort cleanup must not turn a reported timeout
        into a different, more confusing error.
        """
        cleanup_settings = settings.model_copy(update={"subprocess_timeout_seconds": 30})
        cleanup = await run_command(
            self._settings.docker_bin, ["rm", "-f", container_name], settings=cleanup_settings
        )
        if cleanup.ok:
            return stderr
        return (
            f"{stderr}\n[fw-audit] cleanup of orphaned container {container_name} "
            f"failed: {cleanup.stderr}"
        )
