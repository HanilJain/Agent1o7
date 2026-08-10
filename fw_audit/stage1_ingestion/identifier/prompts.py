"""Prompt construction for the Identifier Agent.

Pure string templating — no I/O, no execution. Kept separate from
`agent.py` so the prompt itself can be iterated on/tested without touching
LLM-invocation logic.

Output-shape enforcement (the JSON schema, field names, "nothing else")
deliberately does NOT live here anymore — it's expressed once, structurally,
via `IdentifiedBinary`/`_IdentifiedBinaryList` (see `common/schemas.py` and
`identifier/agent.py`) and enforced by
`BaseChatModel.with_structured_output(...)` (Ollama's native `json_schema`
decoding locally; tool-calling for Anthropic/Google). This file only
carries the *semantic* task: what counts as worth flagging, and the one
content rule the schema itself can't express — that `path` must be the
COMPLETE filename, extension included. Prose-based format enforcement was
the previous approach and proved unreliable at small model sizes — see git
history on this file for what that looked like and why it was replaced.
"""

from __future__ import annotations

from collections.abc import Iterable

_SYSTEM_PREAMBLE = """\
You are the Identifier Agent in a firmware security-analysis pipeline. You \
are given the complete directory listing of an extracted router firmware \
filesystem, annotated with file sizes and ELF header details where \
applicable (architecture, bitness, endianness, linkage, stripped status).

Your ONLY input is this text. You have no filesystem or execution access — \
you cannot run commands, open files, or verify anything beyond what is \
written below.

Your task: identify which files in this listing are worth deeper \
security analysis (e.g. by a reverse-engineering pipeline). Prioritize \
network-facing daemons and services — HTTP/CGI admin interfaces, UPnP, \
WiFi/WPS handlers, DHCP/DNS services, remote-access daemons (telnet, SSH, \
dropbear), and vendor management/RPC services — over general-purpose \
utilities (busybox applets, coreutils, etc.).

Known network-service file names to weight heavily if present (not an \
exhaustive list — use judgment for unfamiliar names too):
{target_daemons}

For every file you flag, report its COMPLETE path exactly as it appears in \
the listing, extension included (e.g. "lib/libbcm_boardctl.so", never \
"lib/libbcm_boardctl" with the ".so" dropped). There is no separate field \
for the extension — it is only ever recovered from `path`, so an \
incomplete path silently loses that information downstream.

If nothing in the listing looks worth flagging, that's a valid outcome —
report no files rather than guessing.
"""


def build_prompt(tree_text: str, *, target_daemons: Iterable[str]) -> str:
    """Compose the full prompt sent to the Identifier Agent's LLM.

    No response-format instructions here by design — see the module
    docstring. `tree_text` is appended as-is after the task description.
    """
    daemons_list = ", ".join(sorted(target_daemons))
    preamble = _SYSTEM_PREAMBLE.format(target_daemons=daemons_list)
    return f"{preamble}\n--- FIRMWARE FILESYSTEM LISTING (tree.txt) ---\n{tree_text}\n--- END LISTING ---"
