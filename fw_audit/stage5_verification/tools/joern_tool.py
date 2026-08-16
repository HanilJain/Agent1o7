"""The Joern tool: `build_cpg` + `run_joern_script`, bound to the
verification agent via LangGraph.

Command composition lives here, never in the LLM's control — the agent
supplies only WHEN to call which tool and, for `run_joern_script`, the
Scala/CPGQL script BODY. Everything else (the `docker run`/`joern-parse`/
`joern --script` invocation itself) is composed by this module.

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

from langchain_core.tools import BaseTool, tool

from fw_audit.common.verification import CpgBuildRecord, JoernScriptAttempt
from fw_audit.config.settings import Settings, get_settings
from fw_audit.executors.base import Executor
from fw_audit.executors.docker_executor import CONTAINER_WORKDIR
from fw_audit.executors.manager import get_executor

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
    at all (mirrors `stage4_rag.debug`'s "bypass the agent" precedent)."""
    command = joern_parse_command()
    started = time.monotonic()
    result = await executor.run(
        command, files=workspace_dir, timeout=settings.stage5_cpg_build_timeout_seconds
    )
    duration = time.monotonic() - started
    ok = result.ok and (workspace_dir / CPG_FILENAME).is_file()
    return CpgBuildRecord(command=command, ok=ok, duration_seconds=duration, stderr=result.stderr)


async def run_joern_script_async(
    script: str,
    *,
    attempt_index: int,
    workspace_dir: Path,
    executor: Executor,
    settings: Settings,
) -> JoernScriptAttempt:
    from fw_audit.stage5_verification import layout

    script_path = layout.script_path(workspace_dir, attempt_index)
    script_path.write_text(script, encoding="utf-8")

    command = joern_script_command(script_path.name)
    result = await executor.run(
        command, files=workspace_dir, timeout=settings.stage5_joern_timeout_seconds
    )
    return JoernScriptAttempt(
        attempt_index=attempt_index,
        script=script,
        stdout=result.stdout,
        stderr=result.stderr,
        returncode=result.returncode,
        ok=result.ok,
    )


def build_joern_tools(
    *,
    workspace_dir: Path,
    settings: Settings,
    cpg_build_holder: list[CpgBuildRecord],
    attempts: list[JoernScriptAttempt],
) -> list[BaseTool]:
    """Construct the two Joern tools, closure-bound to one candidate's
    workspace/settings and to shared mutable result lists.

    The shared lists are how the graph recovers full attempt detail
    (returncode/stderr/timing) for `VerificationReport` — the `ToolNode`
    only ever sees each tool's returned STRING (what the LLM reads), not
    these richer records. Appended to only from within an awaited tool
    call on the single event loop, no lock needed — same reasoning
    `stage3_analysis.agent.consumer.AnalysisConsumer.records` documents
    for its own shared list.
    """
    executor = joern_executor(settings)

    @tool
    async def build_cpg() -> str:
        """Parse the candidate's source file into a Code Property Graph
        (CPG) via `joern-parse`. Call this FIRST, exactly once, before any
        `run_joern_script` call — every script call loads the CPG this
        produces. Returns a short success/failure summary; on failure the
        summary includes the tail of Joern's stderr."""
        record = await build_cpg_async(
            workspace_dir=workspace_dir, executor=executor, settings=settings
        )
        cpg_build_holder.clear()
        cpg_build_holder.append(record)
        if record.ok:
            return f"CPG built successfully in {record.duration_seconds:.1f}s."
        return (
            f"CPG build FAILED after {record.duration_seconds:.1f}s. "
            f"stderr:\n{record.stderr[-2000:]}"
        )

    @tool
    async def run_joern_script(script: str) -> str:
        """Run a Scala/CPGQL Joern script against the CPG `build_cpg`
        already produced. `script` is the full body of a `.sc` file — the
        CPG is already loaded as `cpg` when your script runs. IMPORTANT:
        headless execution does NOT auto-print expression results the way
        the interactive Joern shell does — wrap whatever you want to see in
        `println(...)` (e.g. `println(cpg.method.name.l)`), or your script
        will "succeed" with empty output. If the script errors, or its
        output doesn't clearly confirm or refute the finding, write a
        different or refined script and call this again — you have a
        bounded number of attempts. Returns Joern's stdout (or an error
        summary) as plain text."""
        attempt_index = len(attempts)
        attempt = await run_joern_script_async(
            script,
            attempt_index=attempt_index,
            workspace_dir=workspace_dir,
            executor=executor,
            settings=settings,
        )
        attempts.append(attempt)
        if not attempt.ok:
            return (
                f"Script attempt {attempt_index} FAILED (returncode={attempt.returncode}). "
                f"stderr:\n{attempt.stderr[-2000:]}"
            )
        return attempt.stdout or "(script ran successfully but produced no stdout output)"

    return [build_cpg, run_joern_script]


def container_source_path() -> str:
    """The in-container path `build_cpg`'s `joern-parse` reads — the
    workspace is bind-mounted at `CONTAINER_WORKDIR`, and the source file
    is staged directly under it (see `layout.source_path`)."""
    return f"{CONTAINER_WORKDIR}/{SOURCE_FILENAME}"


__all__ = [
    "CPG_FILENAME",
    "SOURCE_FILENAME",
    "build_cpg_async",
    "build_joern_tools",
    "joern_executor",
    "joern_parse_command",
    "joern_script_command",
    "run_joern_script_async",
]
