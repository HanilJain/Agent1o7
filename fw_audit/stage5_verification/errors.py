"""Stage 5's hard-failure exceptions.

Same discipline as `stage3_analysis.errors.Stage3InputError`/
`stage4_rag.errors.Stage4InputError`: raised only when a required hand-off
or precondition cannot be satisfied at all, before any per-candidate work
starts. Per-candidate problems past that point are recorded (failed) rather
than raised — see `driver.py`.
"""

from __future__ import annotations


class Stage5InputError(RuntimeError):
    """Stage 3's findings, or Stage 2's `stage2_summary.json` (needed to
    resolve a finding's `bin_id` to its `normalized/joern/whole.c`), could
    not be located or loaded."""


class SandboxUnavailableError(RuntimeError):
    """The `SandboxExecutor` backend isn't usable (Docker unreachable, or
    `Settings.executor_backend` isn't `"sandbox"`/`"docker"`) — raised
    before any CPG build is attempted."""


class VerifierModelUnavailableError(RuntimeError):
    """The configured `AgentRole.STAGE5_VERIFIER` model/credential could
    not be resolved at all — mirrors `stage3_analysis.agent.orchestrator.
    AnalystModelUnavailableError`'s "whole run cannot proceed" contract,
    checked up front rather than surfacing per-candidate."""
