"""Pure composition of the `pyghidraRun -H` shell command Stage 2 runs per
binary. No filesystem access, no `fw_audit.executors` import — every
function here takes already-container-side path STRINGS in (built by
`client.py`, which legitimately owns the executor/path-translation
concern) and returns a command string out, so this module's output is
assertable in tests with zero Docker involved.

`pyghidraRun -H <analyzeHeadless-style args>`, NOT bare `analyzeHeadless`:
confirmed against a real build that invoking `analyzeHeadless` directly
with a `.py` `-postScript` fails with "Ghidra was not started with
PyGhidra. Python is not available" — PyGhidra needs the JVM started BY
Python (via JPype), not the reverse. `pyghidraRun -H <args>` (a script
bundled with Ghidra, see `docker/Dockerfile.ghidra`'s smoke-test comment)
forwards to `python3 -m pyghidra.ghidra_launch --install-dir <dir>
ghidra.app.util.headless.AnalyzeHeadless <args>` — the real PyGhidra
equivalent of a plain `analyzeHeadless` call. Every argument after `-H
<project-dir> <project-name>` is otherwise identical to classic
`analyzeHeadless` usage.

Container-side layout (baked into `docker/Dockerfile.ghidra`):

    /opt/ghidra                    GHIDRA_INSTALL_DIR
    /opt/fwaudit/ghidra_scripts    -scriptPath (fw_audit_export.py lives here)
    /ghidra_projects               container-local Ghidra project dir,
                                    never on the bind mount (see the
                                    Dockerfile's comment on why)
    /work                          the bind-mounted workspace — this module
                                    never hardcodes or imports that constant;
                                    it only ever sees full paths already
                                    rooted there, handed in by client.py
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from fw_audit.common.schemas import ELFArch, ELFInfo

CONTAINER_GHIDRA_INSTALL_DIR = "/opt/ghidra"
CONTAINER_PYGHIDRA_RUN = f"{CONTAINER_GHIDRA_INSTALL_DIR}/support/pyghidraRun"
CONTAINER_SCRIPT_PATH = "/opt/fwaudit/ghidra_scripts"
CONTAINER_PROJECTS_DIR = "/ghidra_projects"
EXPORT_SCRIPT_NAME = "fw_audit_export.py"

# (arch, is_64bit, is_little_endian) -> Ghidra language ID. Used ONLY as a
# retry when the first, processor-unspecified import attempt fails or the
# ELF header couldn't be parsed with a known architecture — Ghidra's own
# ELF loader derives the language from e_machine/e_flags/endianness, and
# forcing -processor on a well-formed ELF pushes it toward raw-binary
# handling and degrades symbol recovery.
_LANGUAGE_ID_BY_ARCH: dict[tuple[ELFArch, bool, bool], str] = {
    (ELFArch.MIPS, False, False): "MIPS:BE:32:default",
    (ELFArch.MIPS, False, True): "MIPS:LE:32:default",
    (ELFArch.ARM, False, True): "ARM:LE:32:v7",
    (ELFArch.ARM, False, False): "ARM:BE:32:v7",
    (ELFArch.AARCH64, True, True): "AARCH64:LE:64:v8A",
    (ELFArch.X86, False, True): "x86:LE:32:default",
    (ELFArch.X86_64, True, True): "x86:LE:64:default",
}

_SAFE_TOKEN_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def resolve_language_id(elf: ELFInfo | None) -> str | None:
    """The Ghidra language ID to force via `-processor` on a RETRY attempt,
    or `None` if `elf` doesn't map to a known combination (in which case
    the retry doesn't add `-processor` either — there's nothing better to
    tell Ghidra than what it already tried)."""
    if elf is None or elf.is_64bit is None or elf.is_little_endian is None:
        return None
    return _LANGUAGE_ID_BY_ARCH.get((elf.arch, elf.is_64bit, elf.is_little_endian))


def sanitize_project_name(run_id: str, bin_id: str) -> str:
    """A unique-enough, shell-and-filesystem-safe Ghidra project name.
    Uniqueness matters because concurrent binaries each get `-deleteProject`
    -- a name collision under concurrency would be a real (if rare) hazard."""
    token = _SAFE_TOKEN_RE.sub("_", f"fwaudit_{run_id}_{bin_id}")
    return token[:180]  # generous but bounded; project dirs are host-filesystem paths too


@dataclass(frozen=True)
class GhidraCommand:
    """A fully-composed `pyghidraRun -H` invocation, ready to hand to
    `Executor.run(command.command, files=workspace)`."""

    command: str
    project_name: str
    container_out_dir: str
    """Where the export script's outputs land, container-side (`/work/...`)."""
    used_processor_override: bool


def build_analyze_headless_command(
    *,
    run_id: str,
    bin_id: str,
    container_import_path: str,
    container_out_dir: str,
    container_ghidra_log_dir: str,
    max_mem: str,
    max_functions: int,
    decompile_timeout_seconds: int,
    emit_strings: bool,
    analysis_timeout_seconds: int,
    max_cpu: int,
    language_id: str | None = None,
    project_suffix: str | None = None,
) -> GhidraCommand:
    """Compose the full shell command for one binary's `pyghidraRun -H` run.

    `container_import_path`/`container_out_dir`/`container_ghidra_log_dir`
    are already full, container-side paths (e.g. `/work/binwalk_1/.../httpd`)
    — this module never joins a `CONTAINER_WORKDIR` prefix itself, so it
    never needs to know it. `client.py` builds them via
    `fw_audit.executors.docker_executor.to_container_path`, which also gives
    a free containment check (it raises if a path falls outside the mount).
    """
    project_name = sanitize_project_name(run_id, bin_id)
    if project_suffix:
        # Distinguishes a retry attempt's project from the first attempt's
        # (both would otherwise reuse the same, already-deleted, name).
        project_name = f"{project_name}_{project_suffix}"[:180]

    import_path = container_import_path
    out_dir = container_out_dir
    ghidra_dir = container_ghidra_log_dir

    analyze_argv = [
        CONTAINER_PYGHIDRA_RUN,
        "-H",
        CONTAINER_PROJECTS_DIR,
        project_name,
        "-import",
        f'"{import_path}"',
        "-scriptPath",
        CONTAINER_SCRIPT_PATH,
        # -postScript, NOT -preScript: decompilation requires Ghidra's
        # auto-analysis to have already run.
        "-postScript",
        EXPORT_SCRIPT_NAME,
        f'"{out_dir}"',
        str(max_functions),
        str(decompile_timeout_seconds),
        "true" if emit_strings else "false",
        "-analysisTimeoutPerFile",
        str(analysis_timeout_seconds),
        "-max-cpu",
        str(max_cpu),
    ]
    if language_id:
        analyze_argv += ["-processor", language_id]
    analyze_argv += [
        # Unique project name + -deleteProject keeps /ghidra_projects
        # bounded and avoids lock contention across concurrent binaries.
        "-deleteProject",
        "-log",
        f'"{ghidra_dir}/ghidra.log"',
        "-scriptlog",
        f'"{ghidra_dir}/ghidra_script.log"',
    ]

    # Redirected to a file rather than left on stdout/stderr: analyzeHeadless
    # is extremely chatty (an INFO line per analyzer per function), and
    # DockerExecutor's underlying run_command buffers everything from
    # communicate() in memory — routing it to a file on the bind mount
    # avoids that, and survives a timeout (stdout.txt is already on disk,
    # unlike whatever the killed process still had buffered).
    stdout_redirect = f'"{ghidra_dir}/headless_stdout.txt"'
    command = (
        f'export _JAVA_OPTIONS="-Xmx{max_mem}" ; '
        f'mkdir -p "{out_dir}" "{ghidra_dir}" ; '
        f"{' '.join(analyze_argv)} > {stdout_redirect} 2>&1"
    )

    return GhidraCommand(
        command=command,
        project_name=project_name,
        container_out_dir=out_dir,
        used_processor_override=language_id is not None,
    )
