"""Stage 2 — Feature Extraction (Ghidra Decompilation, Disassembly & C Normalization).

Consumes Stage 1's hand-off (`stage1_summary.json` + `identified_binaries`),
resolves each shortlisted, LLM-authored path to verified bytes in the
extracted rootfs, runs Ghidra Headless against each one to recover
decompiled C and raw disassembly, and sanitizes the decompiler's output —
Ghidra's non-standard types, intrinsic macros, and undeclared register
variables don't parse in CPG builders like Joern and are noisy for LLM
analysis — producing:

* Hand-off: `stage2_summary.json` + per-binary `normalized/joern/whole.c`
  and `normalized/llm/functions/*.c` -> Stage 3 (RAG ingestion) and
  Stage 4 (agentic analysis).
* A flat, human-oriented alternate view: `<firmware-stem>_decompiled/`,
  a sibling of the run dir mirroring the firmware's rootfs layout with
  `.c` appended to each binary's filename (never replacing its
  extension). Same content as that binary's `normalized/joern/whole.c` —
  see `stage2_extraction.layout.decompiled_tree_dir`.

Unlike Stage 1, Stage 2 has no LLM anywhere in it — it is a fully
deterministic pipeline (resolve -> decompile -> normalize), orchestrated as
a plain async runner rather than a LangGraph state machine.
"""
