"""Dependency-free console progress reporting for Stage 2.

No tqdm/rich — Stage 2 has no such dependency today and a single in-place
progress line doesn't warrant adding one. Writes to **stderr**, not stdout,
following the curl/pip/docker convention: progress is ephemeral operator
feedback, not part of the pipeline's machine-readable or piped output
(`runner.py::_print_summary` and `stage2_summary.json` remain the actual
output contract).

On a TTY, renders a single line that overwrites itself in place via `\\r` —
however many binaries there are, the terminal scrollback grows by exactly
one line. Off a TTY (redirected to a file, CI logs), `\\r` overwriting is
invisible, so this instead emits a handful of plain lines at 20% boundaries
— bounded output regardless of how many binaries there are, which is the
point: this must never scale with binary count.
"""

from __future__ import annotations

import sys
import time
from typing import TextIO

_BAR_WIDTH = 24
_MIN_REDRAW_INTERVAL_SECONDS = 0.15
_NON_TTY_STEP_PERCENT = 20


class ProgressBar:
    """Call `advance()` once per completed unit of work; call `close()` when
    the phase is done (only matters on a TTY, to leave the cursor on a fresh
    line rather than mid-bar)."""

    def __init__(self, total: int, *, label: str, stream: TextIO | None = None) -> None:
        self._total = total
        self._label = label
        self._stream = stream if stream is not None else sys.stderr
        self._done = 0
        self._is_tty = bool(getattr(self._stream, "isatty", lambda: False)())
        self._last_render_time = 0.0
        self._last_logged_percent = -1
        self._closed = False

    def advance(self, note: str = "") -> None:
        """Record one more completed unit and, if due, render."""
        self._done += 1
        is_last = self._done >= self._total
        if self._is_tty:
            now = time.monotonic()
            if not is_last and (now - self._last_render_time) < _MIN_REDRAW_INTERVAL_SECONDS:
                return
            self._last_render_time = now
            self._render_tty(note)
        else:
            percent = self._percent()
            if is_last or percent >= self._last_logged_percent + _NON_TTY_STEP_PERCENT:
                self._last_logged_percent = percent
                self._render_line(note)

    def close(self) -> None:
        """End the phase: on a TTY, move off the in-place line so the next
        thing printed doesn't collide with it."""
        if self._closed:
            return
        self._closed = True
        if self._is_tty and self._total > 0:
            self._stream.write("\n")
            self._stream.flush()

    def _percent(self) -> int:
        return int(self._done * 100 / self._total) if self._total else 100

    def _bar(self) -> str:
        filled = int(_BAR_WIDTH * self._done / self._total) if self._total else _BAR_WIDTH
        return "#" * filled + "-" * (_BAR_WIDTH - filled)

    def _render_tty(self, note: str) -> None:
        suffix = f"  {note}" if note else ""
        line = (
            f"{self._label} [{self._bar()}] "
            f"{self._done}/{self._total} ({self._percent()}%){suffix}"
        )
        # Pad to a fixed width so a shorter line doesn't leave stale
        # characters from a longer previous one; \r returns without a newline
        # so the next render overwrites this line in place.
        self._stream.write("\r" + line.ljust(100))
        self._stream.flush()

    def _render_line(self, note: str) -> None:
        suffix = f"  {note}" if note else ""
        line = f"{self._label}: {self._done}/{self._total} ({self._percent()}%){suffix}"
        self._stream.write(line + "\n")
        self._stream.flush()
