# -*- coding: utf-8 -*-
"""Build-time smoke test for the fw-audit Ghidra image.

Run via `analyzeHeadless ... -postScript smoke_test.py` against ANY
importable binary (docker/Dockerfile.ghidra uses `/bin/true`) purely to
prove that PyGhidra's headless script execution actually works end to end
in this image — a broken PyGhidra/JPype install, or an import-time error
in `fw_audit_export.py`, fails the Docker BUILD here rather than 40 minutes
into a real firmware analysis run. Not part of the real export path; see
`fw_audit_export.py` for that.
"""

from __future__ import annotations


def run() -> None:
    # `currentProgram` is injected into a headless GhidraScript's globals by
    # analyzeHeadless (both the classic Jython engine and PyGhidra's
    # GhidraScript-compatibility layer) — referencing it here doubles as the
    # actual "did script execution work" proof; a no-op script wouldn't prove
    # that PyGhidra can reach the Program API at all.
    name = currentProgram.getName()  # noqa: F821 - injected by Ghidra headless
    with open("/tmp/fwaudit_smoke_ok", "w", encoding="utf-8") as f:
        f.write(f"fw-audit Ghidra image smoke test ok: imported {name}\n")


run()
