"""Executor abstraction: uniform command execution across backends.

Two regimes:

* Docker containers (`DockerExecutor`) — deterministic pipelines. Used by
  Stage 1's Extraction Script.
* Docker Sandboxes (`SandboxExecutor`) — reserved for future LLM-controlled
  execution (an agent writing/running its own code); not implemented yet.

Plus `LocalExecutor`, a host-subprocess backend for tests and non-firmware
dev workflows.

    from fw_audit.executors import get_executor
    executor = get_executor()
    result = await executor.run(command="binwalk -e fw.bin", files=workspace)
"""

from fw_audit.executors.base import ExecutionResult, Executor
from fw_audit.executors.docker_executor import DockerExecutor
from fw_audit.executors.local_executor import LocalExecutor
from fw_audit.executors.manager import get_executor
from fw_audit.executors.sandbox_executor import SandboxExecutor

__all__ = [
    "DockerExecutor",
    "ExecutionResult",
    "Executor",
    "LocalExecutor",
    "SandboxExecutor",
    "get_executor",
]
