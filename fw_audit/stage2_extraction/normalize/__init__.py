"""Post-Decompilation Handler / C Normalizer. Privilege class: pure text,
no execution, no LLM.

Sanitizes Ghidra's decompiled C output — non-standard types (`undefined4`,
`uint`, `code`), intrinsic macros (`CONCAT44`, `SUB84`, `ZEXT48`), illegal
`::` switch-case labels, and undeclared register variables (`in_FS_OFFSET`,
`unaff_EBX`, `extraout_EAX`) — into two targets: whole-program C compilable
by a CPG builder like Joern (`normalize/pipeline.py::JOERN_PIPELINE`), and
per-function C for LLM analysis (`::LLM_PIPELINE`).

Two-part design, each doing only what it's suited for:

* `prelude.py` generates `ghidra_types.h` — a header that turns every
  non-standard TYPE into a `typedef` and every intrinsic MACRO into a
  `#define`. A declaration cannot corrupt code, so this owns the entire
  "naming problem" category of distortion with zero rewriting risk.
* `passes.py` handles only what a declaration cannot express: illegal
  tokens, undeclared identifiers, duplicate definitions, comment policy.
  Every pass is a pure `(str) -> str` function — regex/line-based, not a
  real C parser, because pycparser needs *valid* C to build a tree (the
  entire premise here is that Ghidra's output isn't valid C — it would
  fail on exactly the inputs this module exists to fix), and Ghidra's
  emitter is generated text with a small, fixed, highly regular vocabulary
  once the Ghidra version is pinned — not the open-ended grammar a real
  parser earns its keep against. `spans.py` closes the main regex risk
  (matching inside a string/char literal or comment) by tokenizing each
  file once and only ever handing a pass its CODE spans.

This module must NEVER import `fw_audit.executors`, `subprocess`, or `os` —
enforced by an import-purity test (see `tests/test_normalizer.py`), mirroring
the same guard on `stage1_ingestion.identifier.agent`. It must also NEVER
write into a binary's `raw/` directory — only `normalized/` — enforced by
`tests/test_normalizer.py::test_never_writes_into_raw`.
"""
