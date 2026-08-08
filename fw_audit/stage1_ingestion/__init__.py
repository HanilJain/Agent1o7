"""Stage 1 — Firmware Ingestion & Pre-processing.

Unpacks a raw firmware image (archive -> optional vendor decryption -> root
filesystem), generates a `tree.txt` listing of the extracted rootfs, and
scans for candidate ELF network-daemon binaries, producing:

* Hand-off 1: `tree.txt` + filesystem structure -> Stage 3 (RAG ingestion).
* Hand-off 2: ELF Binary Shortlist -> Stage 2 (Ghidra MCP processing).
"""
