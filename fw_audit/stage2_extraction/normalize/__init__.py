"""Post-Decompilation Handler / C Normalizer. Privilege class: pure text,
no execution, no LLM.

Sanitizes Ghidra's decompiled C output — non-standard types (`undefined4`,
`uint`, `code`, `bool`, `pointer`), intrinsic macros (`CONCAT44`, `SUB84`,
`ZEXT48`), illegal syntax (`::` switch-case labels, `TYPE[N] name;` array
declarations), undeclared register variables (`in_FS_OFFSET`, `unaff_EBX`,
`extraout_EAX`), self-forwarding Ghidra thunk/PLT stub bodies, and
duplicate/conflicting global declarations — shared repair work behind TWO
delivery targets: whole-program C compilable by a CPG builder like Joern
(`pipeline.py::JOERN_PIPELINE`/`build_joern_pipeline`), and LLM-facing
function-only text (`pipeline.py::CLEAN_PIPELINE`/`build_clean_pipeline`,
consumed by the sibling `stage2_extraction.clean` package — see that
package's module docstring for the tree-sitter filtering step this module
itself never performs).

Three-part design, each doing only what it's suited for:

* `prelude.py` generates `ghidra_types.h` — a header that turns every
  non-standard TYPE into a `typedef` and every intrinsic MACRO into a
  `#define`. A declaration cannot corrupt code, so this owns the entire
  "naming problem" category of distortion with zero rewriting risk.
* `passes.py` handles what a declaration cannot express: illegal tokens,
  undeclared identifiers, duplicate/conflicting definitions, comment
  policy, and — via `structure.py` — function-body-scoped rewrites (thunk
  stub replacement, register-variable declaration). Every pass is a pure
  `(str) -> str` function (or, for the two context-bound passes, a
  `(BinaryContext, str) -> str` function bound via `functools.partial`
  before it enters a pipeline — see `pipeline.py`'s module docstring) —
  regex/structural, not a real C parser, because pycparser needs *valid* C
  to build a tree (the entire premise here is that Ghidra's output isn't
  valid C — it would fail on exactly the inputs this module exists to
  fix), and Ghidra's emitter is generated text with a small, fixed, highly
  regular vocabulary once the Ghidra version is pinned — not the
  open-ended grammar a real parser earns its keep against. `spans.py`
  closes the main regex risk (matching inside a string/char literal or
  comment) by tokenizing each file once and handing a pass either only its
  CODE spans (`apply_to_code`) or a same-length, non-CODE-blanked copy
  (`mask_non_code`) for structural matching that must still see gap
  positions accurately.
* `context.py` carries a per-binary `BinaryContext` (thunk/external/known-
  function name sets, from `GhidraFunction` records already parsed by
  `ghidra/client.py` — no extra I/O) into the two passes that need more
  than the text alone: `replace_thunk_bodies`, `dedupe_global_declarations`.
  Metadata acts as a VETO only, never a gate — `metadata.json`'s function
  list is capped (`Settings.ghidra_max_functions`) while the C export it
  describes is not, so an unlisted name means "metadata has no opinion"
  (truncation), not "definitely not a thunk". `BinaryContext.may_stub`'s
  docstring has the full argument. This is also why every context-bound
  pass is designed to do useful, safe work under `EMPTY_CONTEXT` alone —
  the textual shape check carries the safety burden; context can only ever
  narrow what a pass does, never widen it.

Deliberately out of scope, as a decision rather than an oversight: renaming
`FUN_*`/`DAT_*`/`LAB_*`/`PTR_*`/`switchD_*` symbols (the only identity those
entities have in a CPG); rewriting `CONCAT`/`SUB`/`ZEXT`/`SEXT` expressions
into plain arithmetic; restructuring `goto`/`do{}while` control flow into
structured loops; and repairing function-signature inconsistencies (e.g.
Ghidra emitting `void uptime(void)` against a call site that uses its
result) — Joern's Eclipse-CDT-based C frontend does not type-check and
builds the CPG regardless, so there is no CPG-quality payoff proportional
to the rewriting risk that class of fix would carry.

This module must NEVER import `fw_audit.executors`, `subprocess`, or `os` —
enforced by an import-purity test (see `tests/test_normalizer.py`), mirroring
the same guard on `stage1_ingestion.identifier.agent`. It must also NEVER
write into a binary's `raw/` directory — only `normalized/` — enforced by
`tests/test_normalizer.py::test_never_writes_into_raw`.
"""
