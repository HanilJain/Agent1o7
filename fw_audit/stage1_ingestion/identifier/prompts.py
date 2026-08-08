"""Prompt construction for the Identifier Agent.

Pure string templating — no I/O, no execution. Kept separate from
`agent.py` so the prompt itself can be iterated on/tested without touching
LLM-invocation logic.
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

Your task: identify which ELF binaries in this listing are worth deeper \
security analysis (e.g. by a reverse-engineering pipeline). Prioritize \
network-facing daemons and services — HTTP/CGI admin interfaces, UPnP, \
WiFi/WPS handlers, DHCP/DNS services, remote-access daemons (telnet, SSH, \
dropbear), and vendor management/RPC services — over general-purpose \
utilities (busybox applets, coreutils, etc.).

Known network-service binary names to weight heavily if present (not an \
exhaustive list — use judgment for unfamiliar names too):
{target_daemons}

Respond with ONLY a JSON array (no markdown fence, no commentary) where \
each element has exactly these two fields:
  "path":   the binary's path exactly as it appears in the listing
  "reason": one concise sentence on why it's worth analyzing

Example response shape:
[{{"path": "usr/sbin/httpd", "reason": "HTTP admin interface, common source of auth-bypass and command-injection CVEs in router firmware."}}]

If nothing in the listing looks worth flagging, respond with an empty JSON \
array: []
"""


def build_prompt(tree_text: str, *, target_daemons: Iterable[str]) -> str:
    """Compose the full prompt sent to the Identifier Agent's LLM."""
    daemons_list = ", ".join(sorted(target_daemons))
    preamble = _SYSTEM_PREAMBLE.format(target_daemons=daemons_list)
    return f"{preamble}\n--- FIRMWARE FILESYSTEM LISTING (tree.txt) ---\n{tree_text}\n--- END LISTING ---"
