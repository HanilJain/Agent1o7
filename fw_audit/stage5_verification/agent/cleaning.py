"""Response sanitation for the generator/evaluator pipeline.

Both LLM calls in `agent.graph` are plain text in / text out — no
`with_structured_output`, no tool-calling — specifically so this pipeline
runs on a local Ollama model (qwen3:32b and similar). That trade buys
reliability on `bind_tools`/structured-output but costs cleanup: a local
model's raw response needs stripping before it's a script Joern can run or
JSON `EvaluatorVerdict` can parse. This module is that stripping, isolated
from `agent.graph` because it is the most bug-prone part of the whole
integration and deserves its own test module (`tests/test_stage5_cleaning.py`).

Three qwen3-specific behaviours a simple `re.sub` (the one-liner the ported
`joern_verification_pipeline` used) does not handle:

- Some Ollama chat templates emit the opening `<think>` tag as part of the
  template itself, so the model's own generated text starts mid-thought and
  contains only the closing `</think>` — an "orphan" close with no matching
  open in the text we actually see. `strip_think` handles this as a second
  pass after the balanced-pair pass.
- `Settings.ollama_num_predict` defaults to 4096. qwen3 can burn the entire
  budget reasoning inside `<think>` with no closing tag at all. Returning
  `""` in that case would be worse than returning the input unchanged — the
  caller (a broken script, or an unparseable evaluator response) already
  degrades correctly (FAIL_RETRY / FAIL_STOP) on either kind of garbage, so
  `strip_think` never invents an empty string where the input had content.
- A model that appends a trailing sentence after its JSON payload silently
  defeats an anchored `^```json\\n|\\n```$` substitution. `extract_json_object`
  does a real balanced-brace, string-literal-aware scan instead.
"""

from __future__ import annotations

import re

_THINK_RE = re.compile(r"<think\b[^>]*>.*?</think\s*>", re.DOTALL | re.IGNORECASE)
_ORPHAN_CLOSE_RE = re.compile(r"\A.*?</think\s*>", re.DOTALL | re.IGNORECASE)
_FENCE_RE = re.compile(r"\A\s*```[A-Za-z0-9_+-]*[ \t]*\r?\n(.*?)\r?\n?[ \t]*```\s*\Z", re.DOTALL)


def message_text(content: object) -> str:
    """Flatten a `BaseMessage.content` value to plain text.

    Usually already a `str`, but some providers (Anthropic in particular)
    return a LIST of content blocks (`[{"type": "text", "text": "..."},
    ...]`) when a message mixes reasoning text with other block types. Only
    text blocks are kept. Moved here verbatim from the old tool-calling
    graph's `_message_text` — still needed because both the generator and
    evaluator calls go through `BaseChatModel.ainvoke(...) -> AIMessage`.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
            else:
                parts.append(str(block))
        return "\n".join(p for p in parts if p)
    return str(content) if content else ""


def strip_think(text: str) -> str:
    """Remove `<think>...</think>` reasoning blocks a local model may emit.

    Two passes: first, any well-formed (opening-and-closing) block anywhere
    in the text; then, an "orphan" leading `</think>` with no matching open
    tag in view (see this module's docstring) — everything up to and
    including that close is dropped. If neither pattern matches (including
    the "unclosed `<think>`, budget ran out" case), the input is returned
    unchanged rather than guessing.
    """
    cleaned = _THINK_RE.sub("", text)
    cleaned = _ORPHAN_CLOSE_RE.sub("", cleaned, count=1)
    return cleaned


def strip_code_fence(text: str) -> str:
    """Strip one leading/trailing markdown code fence, of any language tag,
    if the ENTIRE (stripped) text is wrapped in one. Text that merely
    contains a fence somewhere in the middle is left alone — this is for a
    response that is *only* a fenced block, e.g. ` ```scala\\n...\\n``` `."""
    match = _FENCE_RE.match(text)
    if match:
        return match.group(1)
    return text


def extract_json_object(text: str) -> str | None:
    """Extract the first balanced top-level `{...}` JSON object from `text`,
    tolerating leading/trailing prose the model added around it.

    A simple anchored regex (`^```json\\n|\\n```$`) silently no-ops the
    moment a model adds so much as a trailing sentence after its JSON. This
    does a real brace-matching scan instead, string-literal and
    backslash-escape aware so a `}` or `{` inside a quoted string doesn't
    prematurely close/open the count. Returns `None` if no balanced object
    is found at all.
    """
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def clean_script(raw: object) -> str:
    """Full cleanup pipeline for a generator response: flatten -> strip
    `<think>` -> strip a wrapping code fence -> strip whitespace. The result
    is written verbatim to a `.sc` file, so nothing here should leave any
    non-Scala commentary behind that a human wouldn't also want removed."""
    text = message_text(raw)
    text = strip_think(text)
    text = strip_code_fence(text)
    return text.strip()


def clean_json_payload(raw: object) -> str | None:
    """Full cleanup pipeline for an evaluator response: flatten -> strip
    `<think>` -> strip a wrapping code fence -> extract the JSON object.
    Returns `None` if no JSON object could be found at all (a caller should
    treat that as an unparseable response, same as a `json.JSONDecodeError`)."""
    text = message_text(raw)
    text = strip_think(text)
    text = strip_code_fence(text)
    return extract_json_object(text)


__all__ = [
    "clean_json_payload",
    "clean_script",
    "extract_json_object",
    "message_text",
    "strip_code_fence",
    "strip_think",
]
