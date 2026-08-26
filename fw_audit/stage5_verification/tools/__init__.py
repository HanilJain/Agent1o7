"""The Joern invocation primitives Stage 5's verification graph calls
directly (`agent.graph`'s `build_cpg`/`run_script` nodes) — not LangChain
tools bound to an LLM (there is no tool-calling in this pipeline; the
generator LLM only supplies the Scala/CPGQL script BODY, never the command
line), backed by `SandboxExecutor`.
"""

from __future__ import annotations
