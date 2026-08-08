"""DockerExecutor — runs commands inside a plain, deterministic container.

This is the production backend for Stage 1's Extraction Script: a fixed,
known command sequence (unzip -> binwalk -> [tp-link-decrypt -> binwalk] ->
tree.txt) running isolated, with no network access at runtime. It is a plain
container, NOT a "sandbox" in the LLM-controlled-execution sense — see
`sandbox_executor.py` for that (unimplemented, reserved for later stages).
"""

from __future__ import annotations

import subprocess
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
        docker_args = ["run", "--rm", "--network=none"]

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
        return ExecutionResult(
            command=command,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
        )
