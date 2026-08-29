"""FVVW v3 — the fork-join verification workflow that sits ABOVE Stage 5's
existing Joern static pipeline (`stage5_verification.agent`,
`stage5_verification.tools.joern_tool`), which this package reuses
unchanged as one of its two independent tracks.

One Stage 3 finding is verified two independent ways under a single
strategy plan — the existing Joern static track and a new QEMU+GDB dynamic
track (`tools.qemu_gdb_tool`) — then reconciled by a deterministic joint
evaluator into a two-axis verdict (mechanism confidence x reachability
confidence) plus an LLM-composed disclosure report.

See `../CLAUDE.md` for the full file-by-file map and
`../../../../.claude/plans/` (or the project's own docs once written) for
the FVVW v3 design document this package implements. Nothing in
`stage5_verification.agent`/`stage5_verification.tools.joern_tool` is
modified by this package — see each module's own docstring for the "hard
reuse constraints" this implementation commits to.
"""

from __future__ import annotations
