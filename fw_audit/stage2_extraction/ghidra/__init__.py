"""Ghidra headless driver. Privilege class: sandboxed execution, no LLM.

`command.py` composes the `analyzeHeadless` invocation as a plain string —
pure, no I/O, no `fw_audit.executors` import, so its output is assertable
with zero infrastructure. `client.py` is the only module that actually runs
it, via the `Executor` abstraction (never a bare `docker`/`subprocess` call
of its own), and turns the result into a `DecompiledBinary`.
"""
