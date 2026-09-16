"""Persisted console log per run, plus a cross-reference to that run's
LangSmith trace when one exists.

Every stage's `runner.py::main()` calls `logging.basicConfig(...)` — console
only, nothing kept on disk. Once the terminal scrolls, that output is gone.
This module adds a SECOND handler, attached to the root logger alongside
`basicConfig`'s `StreamHandler` (never replacing it — the console must keep
working exactly as before), writing the identical formatted lines to
`<db_subfolder>/logs/<stage>.<run_id>.log`. `TeeStdout` additionally mirrors
raw `print()` output (every runner's human-readable summary block, printed
directly rather than through `logging`) into the same file, so the persisted
log is a complete transcript of what the terminal showed, not just the
`logging`-routed half of it.

This is deliberately a THIRD sink, alongside `observability.tracing`
(LangSmith, cloud, opt-in) and `stage5_verification.cmdlog` (Stage 5's own
structured per-command JSONL, disk-only). It does not duplicate either:
LangSmith carries structured LLM-call spans, not raw console text; `cmdlog`
carries structured tool-call records for Stage 5 specifically. This module
carries the plain scrollback every stage's terminal already shows, persisted
for every stage, not just Stage 5. Follows `stage5_verification.cmdlog`'s
"always on, never breaks a real run" precedent: a file-open failure logs one
warning to the console and the run proceeds with console-only logging,
exactly as it did before this module existed.

Cross-referencing with LangSmith: when tracing is active, `close_log_file()`
appends the run's LangSmith project/URL to the tail of the log file, so
reading the file tells you both what happened AND where to find the fuller
trace — without copying trace content into the file itself (that would
duplicate, not cross-reference, and traces are already durably stored in
LangSmith). When tracing is off, nothing LangSmith-shaped is written — the
log file is then the only record of the run, which is the whole point of
having it unconditionally.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

from fw_audit.config.settings import Settings
from fw_audit.observability.tracing import tracing_enabled

logger = logging.getLogger("fw_audit.observability.logfile")

_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _sanitize(part: str) -> str:
    """Same filesystem-safety rule as `observability.layout._sanitize` —
    `run_id` values can be timestamps with `:`, which aren't valid in a
    Windows path component."""
    return _SANITIZE_RE.sub("_", part) or "run"


def logs_dir(db_subfolder: Path) -> Path:
    return db_subfolder / "logs"


def log_file_path(db_subfolder: Path, *, stage: str, run_id: str) -> Path:
    """`<db_subfolder>/logs/<stage>.<run_id>.log` — mirrors
    `observability.layout.usage_jsonl_path`'s `<stage>.<run_id>` keying, so
    a run's usage artifact and its console log sit side by side under the
    same naming convention."""
    return logs_dir(db_subfolder) / f"{_sanitize(stage)}.{_sanitize(run_id)}.log"


class TeeStdout:
    """Wraps a text stream (`sys.stdout`) so every `write()` also lands in a
    log file, while the original stream still receives every byte
    unchanged — a bare tee, not a replacement. Used to capture the
    plain `print()` calls every runner's `main()`/summary-printing helpers
    make, which `logging`'s own handlers never see."""

    def __init__(self, original: TextIO, log_fh: TextIO) -> None:
        self._original = original
        self._log_fh = log_fh

    def write(self, data: str) -> int:
        self._original.write(data)
        try:
            self._log_fh.write(data)
        except OSError:
            pass  # best-effort: the FileHandler on the logger already warned
        return len(data)

    def flush(self) -> None:
        self._original.flush()
        try:
            self._log_fh.flush()
        except OSError:
            pass

    def __getattr__(self, name: str) -> object:
        return getattr(self._original, name)


@contextmanager
def capture_run_log(
    settings: Settings,
    *,
    db_subfolder: Path,
    stage: str,
    run_id: str,
) -> Iterator[Path | None]:
    """Persist this run's console output (both `logging` records and plain
    `print()` output) to `<db_subfolder>/logs/<stage>.<run_id>.log`, for the
    duration of the `with` block. Yields the log path, or `None` if writing
    is disabled/failed — never raises, matching every other observability
    sink's "never break a real run" discipline.

    Call this AFTER `logging.basicConfig(...)` (so the console handler it
    installs is already in place) and around the rest of `main()`'s body —
    it wraps `sys.stdout` for that scope only and restores it on exit
    regardless of how the block ends.
    """
    if not settings.log_to_file:
        yield None
        return

    path = log_file_path(db_subfolder, stage=stage, run_id=run_id)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        log_fh = path.open("a", encoding="utf-8")
    except OSError as exc:
        logger.warning("capture_run_log: could not open %s: %s", path, exc)
        yield None
        return

    file_handler = logging.FileHandler(path, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root_logger = logging.getLogger()
    root_logger.addHandler(file_handler)

    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = TeeStdout(original_stdout, log_fh)  # type: ignore[assignment]
    sys.stderr = TeeStdout(original_stderr, log_fh)  # type: ignore[assignment]

    try:
        yield path
    finally:
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        root_logger.removeHandler(file_handler)
        file_handler.close()
        _append_trace_reference(log_fh, settings=settings)
        try:
            log_fh.close()
        except OSError:
            pass


def _append_trace_reference(log_fh: TextIO, *, settings: Settings) -> None:
    """Cross-reference, not duplication: when LangSmith tracing was active
    for this run, note the project so a reader of the log file knows where
    the fuller structured trace lives, without copying any trace content
    into this file."""
    if not tracing_enabled(settings):
        return
    try:
        log_fh.write(
            f"\n-- LangSmith tracing was active for this run "
            f"(project={settings.langsmith_project!r}, "
            f"endpoint={settings.langsmith_endpoint!r}) --\n"
        )
    except OSError:
        pass


__all__ = [
    "TeeStdout",
    "capture_run_log",
    "log_file_path",
    "logs_dir",
]
