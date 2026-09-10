#!/usr/bin/env bash
# Stage 2 Normalization Hardening Spec's illustrative CI gate — a thin
# shell wrapper around the REAL validation logic in
# fw_audit.stage2_extraction.validate (structural.py/syntax.py/policy.py),
# not a reimplementation of it.
#
# Why this is a wrapper, not the gate itself: the Spec's original draft was
# a self-contained bash script using `grep -oP`. That syntax does not run
# unmodified on this project's own Windows development environment
# (confirmed directly: `grep: -P supports only unibyte and UTF-8 locales`
# on Git Bash/MSYS grep) — and Stage 2 is meant to run identically on
# whatever platform CI or a developer's own machine happens to be. Rather
# than hand-maintain two implementations of the same seven defect-class
# checks (one in Python, one in bash-and-grep) that could silently drift
# apart, this script is a compatibility shim: it calls the one real
# implementation everywhere Python itself runs, and exists so a CI system
# that only knows how to invoke a shell script still works.
#
# Usage:
#   fw_audit/stage2_extraction/validate.sh path/to/whole.c
#   fw_audit/stage2_extraction/validate.sh --gcc path/to/whole.c
#
# Exit code: 0 if the file has zero ERROR-severity validation issues,
# 1 otherwise — matches `python -m fw_audit.stage2_extraction.validate`
# exactly, because this literally IS that command.

set -euo pipefail

PYTHON="${PYTHON:-python}"

exec "$PYTHON" -m fw_audit.stage2_extraction.validate "$@"
