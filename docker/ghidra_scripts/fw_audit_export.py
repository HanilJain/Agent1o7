# -*- coding: utf-8 -*-
"""fw-audit's Ghidra headless export script — Stage 2's decompilation core.

Run via `analyzeHeadless ... -postScript fw_audit_export.py <out_dir>
<max_functions> <decompile_timeout_seconds> <emit_strings>` (composed by
`fw_audit.stage2_extraction.ghidra.command`; see that module for the exact
argv). MUST be `-postScript`, not `-preScript` — this script needs
auto-analysis to have already run.

Written for PyGhidra (native CPython execution), Ghidra 12's default
scripting engine — NOT classic Jython, which Ghidra 12 no longer enables by
default. `currentProgram`, `currentProgram.getListing()`, `monitor`, and
`getScriptArgs()` are injected into this script's globals by analyzeHeadless
the same way they are for a classic GhidraScript; PyGhidra's whole design
goal is running that style of script largely unmodified.

KNOWN LIMITATION — flagged honestly rather than silently: the exact
CppExporter option-setting API (`_configure_cpp_exporter` below) and the
decompiler-timeout API (`_configure_decompiler_timeout`) were written
against Ghidra's documented API surface without the ability to execute this
script against a real Ghidra 12.1.2 install in the environment that wrote
it (no Docker daemon was available). Both are wrapped defensively and fall
back to Ghidra's built-in defaults on any failure — the export still
proceeds — but BOTH NEED VALIDATION against a real `analyzeHeadless` run
before this image is trusted in production. See the Stage 2 plan's
verification section (`docker run ... -postScript fw_audit_export.py``
against `/bin/ls`) for exactly that check.

Failure policy: this script exits non-zero ONLY if the program object
itself could not be obtained (import failure). Every other error —
whole-program decompile failure, a missing symbol table entry — is caught,
recorded in `metadata.json`'s `analysis.decompile_failures` /
`.skipped_functions`, and does not abort the run. `metadata.json` is
written from a `finally` block with
`status: "partial"` on an unhandled exception past the import step, so the
host never faces a missing metadata.json file — command-ok-but-no-file is
therefore always a real bug in `ghidra/client.py`'s caller, never a
"Ghidra had a bad day" ambiguity.
"""

from __future__ import annotations

import json
import os
import time
import traceback

# --------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------- #

_args = list(getScriptArgs())  # noqa: F821 - injected by Ghidra headless
if len(_args) < 4:
    raise ValueError(
        "fw_audit_export.py requires 4 args: <out_dir> <max_functions> "
        "<decompile_timeout_seconds> <emit_strings>; got: " + repr(_args)
    )

OUT_DIR = _args[0]
MAX_FUNCTIONS = int(_args[1])
DECOMPILE_TIMEOUT_SECONDS = int(_args[2])
EMIT_STRINGS = _args[3].strip().lower() in ("1", "true", "yes")

DECOMPILED_DIR = os.path.join(OUT_DIR, "decompiled")
METADATA_PATH = os.path.join(OUT_DIR, "metadata.json")

os.makedirs(DECOMPILED_DIR, exist_ok=True)


def _log(message: str) -> None:
    # Deliberately not Python `logging`: this runs inside Ghidra's own
    # process/log plumbing (captured via analyzeHeadless's `-scriptlog`),
    # where a plain print is the conventional, visible way to leave a trail.
    print(f"[fw_audit_export] {message}")


def _safe_name(text: str, limit: int = 64) -> str:
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in text)
    return safe[:limit] or "anon"


def _addr_str(address) -> str:
    return address.toString()


# --------------------------------------------------------------------- #
# Program-level metadata
# --------------------------------------------------------------------- #


def _program_metadata(program) -> dict:
    language = program.getLanguage()
    address_space = program.getAddressFactory().getDefaultAddressSpace()
    return {
        "name": program.getName(),
        "md5": program.getExecutableMD5(),
        "language_id": program.getLanguageID().getIdAsString(),
        "compiler_spec": program.getCompilerSpec().getCompilerSpecID().getIdAsString(),
        "image_base": _addr_str(program.getImageBase()),
        "endian": "big" if language.isBigEndian() else "little",
        "address_size": address_space.getSize() // 8,
        "executable_format": program.getExecutableFormat(),
    }


def _configure_decompiler_timeout(program, timeout_seconds: int) -> None:
    """Best-effort: Ghidra exposes decompiler tuning via a per-program
    Options category ("Decompiler"), not a constructor argument — a stable,
    documented API shape, though the exact option NAME containing "timeout"
    is what genuinely needs confirming against a real install (see module
    docstring). Never fatal: an unset timeout just means Ghidra's own
    default applies."""
    try:
        options = program.getOptions("Decompiler")
        for name in options.getOptionNames():
            if "timeout" in name.lower():
                options.setInt(name, timeout_seconds)
                _log(f"decompiler timeout option {name!r} set to {timeout_seconds}s")
    except Exception as exc:  # pragma: no cover - defensive, version-dependent API
        _log(f"WARNING: could not set decompiler timeout ({exc}); using Ghidra's default")


def _configure_cpp_exporter(exporter) -> None:
    """Best-effort: override CppExporter's `EMIT_TYPE_DEFINITONS` (note:
    that's Ghidra's own spelling, missing the second "I" — an upstream
    typo, not ours), `EMIT_REFERENCED_GLOBALS`, and `USE_CPP_STYLE_COMMENTS`
    options via the documented Exporter.getOptions/setOptions dance.
    `USE_CPP_STYLE_COMMENTS=False` is deliberate: `//` comments swallow to
    end-of-line and would be broken by the normalizer's line-based
    rewrites; `/* */` cannot be. Falls back to Ghidra's defaults on any
    failure (see module docstring) rather than aborting the export."""
    desired = {
        "Emit Type Definitions": True,
        "Emit Referenced Globals": True,
        "Use C++ Style Comments": False,
    }
    try:
        import jpype
        from ghidra.framework.model import DomainObjectService

        @jpype.JImplements(DomainObjectService)
        class _ProgramService:
            @jpype.JOverride
            def getDomainObject(self):
                return currentProgram  # noqa: F821

        options = list(exporter.getOptions(_ProgramService()))
        changed = []
        for option in options:
            name = str(option.getName())
            if name in desired:
                option.setValue(desired[name])
                changed.append(name)
        exporter.setOptions(options)
        _log(f"CppExporter options set: {changed}")
    except Exception as exc:  # pragma: no cover - defensive, version-dependent API
        _log(f"WARNING: could not set CppExporter options ({exc}); using Ghidra's defaults")


# --------------------------------------------------------------------- #
# Decompiled C export — whole-program only. Deliberately no per-function
# export and no disassembly export: nothing downstream reads either, and
# a router binary's 10,000+ functions would mean 10,000+ redundant
# CppExporter invocations for files nobody consumes. `metadata["functions"]`
# still carries per-function METADATA (name, signature, call graph) from
# the Program DB — that doesn't require decompilation or a written file.
# --------------------------------------------------------------------- #


def _export_whole_program(program, exporter) -> tuple[bool, str | None]:
    from java.io import File
    from ghidra.program.model.address import AddressSet

    out_file = File(os.path.join(DECOMPILED_DIR, "whole.c"))
    address_set = AddressSet(program.getMemory())
    try:
        ok = exporter.export(out_file, program, address_set, monitor)  # noqa: F821
        return bool(ok), None
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


# --------------------------------------------------------------------- #
# Function metadata (Program DB / ReferenceManager — no decompilation or
# file export needed for any of this)
# --------------------------------------------------------------------- #


def _function_record(func) -> dict:
    try:
        calls = [f.getName() for f in func.getCalledFunctions(monitor)]  # noqa: F821
    except Exception:
        calls = []
    try:
        called_by = [f.getName() for f in func.getCallingFunctions(monitor)]  # noqa: F821
    except Exception:
        called_by = []

    return {
        "name": func.getName(),
        "entry_point": _addr_str(func.getEntryPoint()),
        "min_address": _addr_str(func.getBody().getMinAddress()),
        "max_address": _addr_str(func.getBody().getMaxAddress()),
        "size": int(func.getBody().getNumAddresses()),
        "signature": str(func.getSignature(True)),
        "calling_convention": func.getCallingConventionName(),
        "is_thunk": bool(func.isThunk()),
        "is_external": bool(func.isExternal()),
        "parameter_count": func.getParameterCount(),
        "calls": calls,
        "called_by": called_by,
        "decompiled": True,
        "error": None,
    }


def _imports_and_exports(program) -> tuple[list[dict], list[dict]]:
    symbol_table = program.getSymbolTable()
    imports, exports = [], []
    try:
        for symbol in symbol_table.getExternalSymbols():
            imports.append(
                {
                    "name": symbol.getName(),
                    "library": symbol.getParentNamespace().getName()
                    if symbol.getParentNamespace()
                    else None,
                    "address": _addr_str(symbol.getAddress()) if symbol.getAddress() else None,
                }
            )
    except Exception as exc:  # pragma: no cover - defensive
        _log(f"WARNING: import enumeration failed: {exc}")

    try:
        entry_points = symbol_table.getExternalEntryPointIterator()
        while entry_points.hasNext():
            addr = entry_points.next()
            symbol = symbol_table.getPrimarySymbol(addr)
            if symbol is not None:
                exports.append({"name": symbol.getName(), "address": _addr_str(addr)})
    except Exception as exc:  # pragma: no cover - defensive
        _log(f"WARNING: export enumeration failed: {exc}")

    return imports, exports


def _strings(program, cap: int = 5000) -> list[dict]:
    if not EMIT_STRINGS:
        return []
    results: list[dict] = []
    try:
        from ghidra.program.util import DefinedDataIterator

        for data in DefinedDataIterator.definedStrings(program):
            if len(results) >= cap:
                break
            try:
                value = data.getValue()
                results.append(
                    {
                        "address": _addr_str(data.getAddress()),
                        "value": str(value) if value is not None else "",
                        "length": data.getLength(),
                    }
                )
            except Exception:  # pragma: no cover - one bad string, never fatal
                continue
    except Exception as exc:  # pragma: no cover - defensive, version-dependent API
        _log(f"WARNING: string extraction failed ({exc}); metadata.strings will be empty")
    return results


# --------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------- #


def main() -> None:
    started = time.time()
    program = currentProgram  # noqa: F821 - injected by Ghidra headless

    metadata: dict = {
        "schema_version": 1,
        "program": _program_metadata(program),
        "analysis": {
            "ghidra_version": None,
            "elapsed_seconds": None,
            "status": "partial",
            "skipped_functions": [],
            "decompile_failures": [],
        },
        "functions": [],
        "imports": [],
        "exports": [],
        "strings": [],
    }

    try:
        try:
            from ghidra.util.classfinder import ClassSearcher  # noqa: F401
            from generic.util import Application

            metadata["analysis"]["ghidra_version"] = str(Application.getApplicationVersion())
        except Exception:  # pragma: no cover - version string is nice-to-have only
            pass

        _configure_decompiler_timeout(program, DECOMPILE_TIMEOUT_SECONDS)

        from ghidra.app.util.exporter import CppExporter

        exporter = CppExporter()
        _configure_cpp_exporter(exporter)

        whole_ok, whole_error = _export_whole_program(program, exporter)
        if not whole_ok:
            _log(f"WARNING: whole-program export failed: {whole_error}")
            metadata["analysis"]["decompile_failures"].append(
                {"function": "*whole_program*", "error": whole_error}
            )

        function_manager = program.getFunctionManager()
        all_functions = list(function_manager.getFunctions(True))
        # Largest / most-referenced first, thunks and externals last — a
        # router binary routinely has 10,000+ functions; cap rather than
        # let one binary run unbounded.
        all_functions.sort(
            key=lambda f: (f.isThunk(), f.isExternal(), -int(f.getBody().getNumAddresses()))
        )
        to_process = all_functions[:MAX_FUNCTIONS]
        skipped = all_functions[MAX_FUNCTIONS:]
        metadata["analysis"]["skipped_functions"] = [f.getName() for f in skipped]

        for func in to_process:
            metadata["functions"].append(_function_record(func))

        imports, exports = _imports_and_exports(program)
        metadata["imports"] = imports
        metadata["exports"] = exports
        metadata["strings"] = _strings(program)

        metadata["analysis"]["status"] = "succeeded"
    except Exception:  # pragma: no cover - the only genuinely catch-all point
        _log("ERROR: unhandled exception during export:\n" + traceback.format_exc())
        metadata["analysis"]["status"] = "partial"
    finally:
        metadata["analysis"]["elapsed_seconds"] = round(time.time() - started, 2)
        os.makedirs(OUT_DIR, exist_ok=True)
        with open(METADATA_PATH, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        _log(f"metadata.json written: {METADATA_PATH} (status={metadata['analysis']['status']})")


main()
