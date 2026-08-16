"""Stage 5: sandboxed verification — Joern tool-calling agent (v1).

Proves/disproves a Stage 3 finding by actually building a CPG for its
binary and running Joern/CPGQL queries against it, rather than trusting the
LLM's static read alone. QEMU+GDB dynamic verification is a planned second
tool, not implemented here — see this package's `CLAUDE.md`.
"""

from __future__ import annotations
