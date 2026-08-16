"""Stage 5's Joern verification agent — the repo's first genuine
multi-turn, tool-calling LLM loop (every earlier stage's LLM call is a
one-shot `with_structured_output(...).ainvoke(...)`, no tool access)."""

from __future__ import annotations
