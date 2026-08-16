"""LangChain tool functions the Stage 5 verification agent is bound to.

In-process tools (per your confirmed choice), not a real MCP server: plain
`@tool`-decorated Python functions run via LangGraph's `ToolNode`, backed by
`SandboxExecutor`. The LLM decides which tool to call and (for
`run_joern_script`) what Scala/CPGQL script content to run — it never
constructs the underlying Docker/shell command itself.
"""

from __future__ import annotations
