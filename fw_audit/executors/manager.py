"""Executor backend selection.

`get_executor(settings)` is the single place that decides which concrete
`Executor` a caller gets, keyed off `Settings.executor_backend`
(`FWA_EXECUTOR_BACKEND`). Callers depend only on the `Executor` interface —
swapping backends here requires no changes anywhere else.
"""

from __future__ import annotations

from fw_audit.config.settings import Settings, get_settings
from fw_audit.executors.base import Executor
from fw_audit.executors.docker_executor import DockerExecutor
from fw_audit.executors.local_executor import LocalExecutor
from fw_audit.executors.sandbox_executor import SandboxExecutor

_BACKENDS: dict[str, type[Executor]] = {
    "docker": DockerExecutor,
    "local": LocalExecutor,
    "sandbox": SandboxExecutor,
}


def get_executor(settings: Settings | None = None) -> Executor:
    """Resolve the configured `Executor` backend.

    Raises `ValueError` for an unrecognized `FWA_EXECUTOR_BACKEND` rather
    than silently falling back — a typo'd backend name should never quietly
    downgrade the isolation guarantees the caller expects.
    """
    settings = settings or get_settings()
    backend = settings.executor_backend.lower()
    try:
        executor_cls = _BACKENDS[backend]
    except KeyError as exc:
        raise ValueError(
            f"Unknown FWA_EXECUTOR_BACKEND={backend!r}; expected one of {sorted(_BACKENDS)}"
        ) from exc
    return executor_cls(settings)
