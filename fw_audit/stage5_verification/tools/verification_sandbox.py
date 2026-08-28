"""Shared executor resolution for the FVVW v3 dynamic-verification tools —
`characterize_tool.py`, `crosscheck_tool.py`, and `qemu_gdb_tool.py` all
call `verification_executor()`/`verification_session_executor()` from here
rather than resolving an `Executor` themselves, so there is exactly one
place that decides which image/settings those three tool modules run
against.

Mirrors `joern_tool.joern_executor()`'s shape exactly — including its
"always override the image, regardless of backend" discipline (see that
function's docstring for the `joern-parse: not found` failure mode this
avoids) — but points at `Settings.stage5_verification_image`
(`docker/Dockerfile.verification`) instead of `stage5_joern_image`. The two
images and the two `*_executor()` helpers are deliberately kept separate:
the static (Joern) track must never be affected by anything this module
resolves, and vice versa.
"""

from __future__ import annotations

from fw_audit.config.settings import Settings, get_settings
from fw_audit.executors.base import Executor
from fw_audit.executors.manager import get_executor
from fw_audit.executors.sandbox_executor import SandboxExecutor


def verification_executor(settings: Settings | None = None) -> Executor:
    """Resolve an `Executor` pointed at the verification-sandbox image, for
    one-shot calls (`characterize_target`, `static_crosscheck`) — the same
    shape as Joern's `build_cpg`/`run_joern_script`, just a different image.

    Always overrides `docker_image` to `settings.stage5_verification_image`
    before delegating to `get_executor()`, regardless of which backend
    `FWA_EXECUTOR_BACKEND` selects — mirrors `joern_executor()` exactly, see
    that function's docstring for the image-mismatch bug this avoids.
    """
    settings = settings or get_settings()
    return get_executor(
        settings.model_copy(
            update={
                "docker_image": settings.stage5_verification_image,
                "subprocess_timeout_seconds": settings.stage5_qemu_timeout_seconds,
            }
        )
    )


def verification_session_executor(settings: Settings | None = None) -> SandboxExecutor:
    """Resolve a session-CAPABLE executor pointed at the verification-sandbox
    image, for the dynamic track's `start()`/`exec_in_session()`/`stop()`
    calls (`bringup_stabilize` and every later dynamic-track node).

    Unlike `verification_executor()`, this is deliberately typed as
    `SandboxExecutor` rather than the generic `Executor` ABC — the session
    methods (`start`/`exec_in_session`/`stop`) are `SandboxExecutor`-specific
    additions, not part of the `Executor` interface every backend
    implements (see `executors/base.py`'s `SessionHandle` docstring for why
    a session needs a genuinely different capability than `run()`). The
    dynamic track always needs a real session, so it constructs
    `SandboxExecutor` directly rather than routing through
    `executors.manager.get_executor()`'s backend-selection indirection —
    `FWA_EXECUTOR_BACKEND=local`/`docker` have no session equivalent to
    select, and silently downgrading an interactive QEMU+GDB flow to a
    one-shot backend would produce confusing mid-session failures rather
    than a clear "sessions require the sandbox backend" contract.
    """
    settings = settings or get_settings()
    return SandboxExecutor(settings, image=settings.stage5_verification_image)


__all__ = ["verification_executor", "verification_session_executor"]
