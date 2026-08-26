"""The Joern invocation primitives: `build_cpg_async` + `run_joern_script_async`,
called directly by `agent.graph`'s `build_cpg`/`run_script` nodes.

Command composition lives here, never in the LLM's control — the generator
LLM supplies only the Scala/CPGQL script BODY (see `agent/prompts.py`).
Everything else (the `docker run`/`joern-parse`/`joern --script` invocation
itself) is composed by this module.

CPG lifecycle (see `stage5_verification`'s `README.md`/`CLAUDE.md` for the
full rationale): `build_cpg` writes `cpg.bin` into the host-mounted
per-candidate workspace directory via one `docker run`; every subsequent
`run_joern_script` call is its own fresh one-shot `docker run` against the
SAME mounted workspace, loading the already-built `cpg.bin` from disk.
State survives across tool calls via the filesystem, not a live container.

Joern CLI syntax note: `joern-parse <path> --output <cpg>` builds the CPG;
`joern --script <script.sc> <cpg>` (CPG given POSITIONALLY, not via
`--param`) runs a script against it. Verified against a real build of
`docker/Dockerfile.joern` (Joern 4.0.420) — `joern --help`'s own text says
`--param key=value` is "for main function in script", i.e. it only binds
values to a script-declared `@main def main(...)` signature; a plain
expression script like `cpg.method.name.l` has no such signature and
`--param cpgPath=...` fails with `Unknown arguments: "--cpgPath" ...`. The
positional-CPG form auto-imports the CPG as `cpg` before the script runs,
with no signature required — confirmed working end-to-end (`joern-parse`
then `joern --script smoke.sc cpg.bin` produced the expected query output).
An earlier revision of this module used the (untested) `--param` form,
copied from Joern's own docs without a real build to check it against —
same mistake the module-level docstring above warns to never repeat;
this comment IS that verification now. `joern_parse_command`/
`joern_script_command` below are the single place to fix if a future
Joern version's syntax differs — also reused by `report_writer.py` to
print an exact reproduction command.

Script content note: headless `--script` execution does NOT auto-print an
expression's value the way the interactive REPL does — a bare
`cpg.method.name.l` runs successfully but produces no stdout at all. Every
script must end with an explicit `println(...)` around whatever it wants
to surface. `agent/prompts.py`'s `SYSTEM_PROMPT` must say this explicitly,
or the agent will "successfully" run scripts that report empty evidence.

Workspace side effect: each `--script` run creates (and keeps) a small
`workspace/<cpg-basename>[N]/` project directory next to the CPG, and
re-running against the same CPG filename increments the suffix
(`cpg.bin`, `cpg.bin1`, `cpg.bin2`, ...) rather than reusing one. Harmless
(each is a small working copy, not a duplicate of the whole CPG) but it
does mean a long attempt sequence leaves several of these behind in the
bind-mounted workspace directory — expected, not a leak to chase.
"""

from __future__ import annotations

import shlex
import time
from pathlib import Path

from fw_audit.common.verification import CpgBuildRecord, JoernScriptAttempt
from fw_audit.config.settings import Settings, get_settings
from fw_audit.executors.base import Executor
from fw_audit.executors.docker_executor import CONTAINER_WORKDIR
from fw_audit.executors.manager import get_executor
from fw_audit.observability import aspan

CPG_FILENAME = "cpg.bin"
SOURCE_FILENAME = "whole.c"


def joern_executor(settings: Settings | None = None) -> Executor:
    """Resolve an `Executor` pointed at the Joern image.

    Mirrors `stage2_extraction.ghidra.client.ghidra_executor()` EXACTLY:
    override `settings.docker_image` via `model_copy` before delegating to
    `get_executor()`, unconditionally — regardless of which backend
    `FWA_EXECUTOR_BACKEND` selects. `get_executor()` is what actually
    decides `DockerExecutor` vs `SandboxExecutor` vs `LocalExecutor`; this
    function's only job is making sure whichever one it returns is pointed
    at the Joern image, not Stage 1's `fw-audit-sandbox` image.

    A prior version of this function special-cased on
    `executor_backend == "sandbox"` and left the default ("docker") branch
    calling `get_executor(settings)` un-overridden — which silently ran
    `joern-parse` inside Stage 1's sandbox container (no Joern installed
    there at all), producing a `joern-parse: not found` failure instead of
    a clear image-not-found error. Fixed by always overriding, exactly
    like `ghidra_executor()` — see that function's own docstring.
    """
    settings = settings or get_settings()
    return get_executor(
        settings.model_copy(
            update={
                "docker_image": settings.stage5_joern_image,
                "subprocess_timeout_seconds": settings.stage5_joern_timeout_seconds,
            }
        )
    )


def joern_parse_command() -> str:
    """`joern-parse` the staged source into a CPG. `--output` writes the CPG
    to a path relative to the container's CWD (`/work`, the bind-mounted
    workspace) — see this module's docstring on re-verifying this syntax
    against the pinned Joern release."""
    return f"joern-parse {shlex.quote(SOURCE_FILENAME)} --output {shlex.quote(CPG_FILENAME)}"


def joern_script_command(script_filename: str) -> str:
    """CPG given positionally (auto-imported as `cpg`), not via `--param`
    — see this module's docstring for why `--param cpgPath=...` doesn't
    work against a plain expression script."""
    return f"joern --script {shlex.quote(script_filename)} {shlex.quote(CPG_FILENAME)}"


async def build_cpg_async(
    *,
    workspace_dir: Path,
    executor: Executor,
    settings: Settings,
) -> CpgBuildRecord:
    """The logic behind the `build_cpg` tool, factored out so `debug.py` can
    invoke it directly without going through the LLM/tool-calling machinery
    at all (mirrors `stage4_rag.debug`'s "bypass the agent" precedent).

    Wrapped in a `run_type="tool"` span (a no-op unless tracing is on): this
    is one of the two highest-latency operations in the whole pipeline (a
    raw `docker run`, invisible to LangSmith's automatic LangChain
    instrumentation) and today has no timing attribution at all beyond
    `CpgBuildRecord.duration_seconds`, which only reaches disk inside the
    final persisted report.
    """
    command = joern_parse_command()
    async with aspan(
        "stage5.build_cpg", run_type="tool", inputs={"command": command}
    ) as run:
        started = time.monotonic()
        result = await executor.run(
            command, files=workspace_dir, timeout=settings.stage5_cpg_build_timeout_seconds
        )
        duration = time.monotonic() - started
        ok = result.ok and (workspace_dir / CPG_FILENAME).is_file()
        if run is not None:
            run.end(
                outputs={
                    "ok": ok,
                    "duration_seconds": duration,
                    "stderr": result.stderr[:500],
                }
            )
    return CpgBuildRecord(command=command, ok=ok, duration_seconds=duration, stderr=result.stderr)


async def run_joern_script_async(
    script: str,
    *,
    attempt_index: int,
    workspace_dir: Path,
    executor: Executor,
    settings: Settings,
) -> JoernScriptAttempt:
    """The logic behind the `run_script` tool — see `build_cpg_async`'s
    docstring for why this is also wrapped in a `run_type="tool"` span:
    the other of the pipeline's two highest-latency raw `docker run` calls.
    """
    from fw_audit.stage5_verification import layout

    script_path = layout.script_path(workspace_dir, attempt_index)
    script_path.write_text(script, encoding="utf-8")

    command = joern_script_command(script_path.name)
    async with aspan(
        "stage5.run_joern_script",
        run_type="tool",
        inputs={"command": command, "attempt_index": attempt_index},
    ) as run:
        result = await executor.run(
            command, files=workspace_dir, timeout=settings.stage5_joern_timeout_seconds
        )
        if run is not None:
            run.end(
                outputs={
                    "returncode": result.returncode,
                    "ok": result.ok,
                    "stdout": result.stdout[:500],
                    "stderr": result.stderr[:500],
                }
            )
    return JoernScriptAttempt(
        attempt_index=attempt_index,
        script=script,
        stdout=result.stdout,
        stderr=result.stderr,
        returncode=result.returncode,
        ok=result.ok,
    )


def container_source_path() -> str:
    """The in-container path `build_cpg`'s `joern-parse` reads — the
    workspace is bind-mounted at `CONTAINER_WORKDIR`, and the source file
    is staged directly under it (see `layout.source_path`)."""
    return f"{CONTAINER_WORKDIR}/{SOURCE_FILENAME}"


__all__ = [
    "CPG_FILENAME",
    "SOURCE_FILENAME",
    "build_cpg_async",
    "joern_executor",
    "joern_parse_command",
    "joern_script_command",
    "run_joern_script_async",
]
