"""Deterministic, zero-LLM resolution of a claim's free-text
`binary_hint`/`function_hint` against a firmware's real Stage 2 output.

Per the confirmed "binary-level only" grounding decision: this module never
calls an LLM and never slices source code out of Stage 2's decompiled C —
it only matches free text against `Stage2Summary`'s already-computed
`DecompiledBinary`/`GhidraFunction` tables. A claim whose function resolves
here is guaranteed to also resolve against
`stage5_verification.tools.characterize_tool._find_function`'s own lookup
(`resolve_function` below runs the EXACT same two matching tiers, in the
same order, against the same `GhidraFunction.name`/`entry_point` fields —
see that function's docstring) — this is what lets `emit.py` safely set
`decision=ESCALATE` only when both resolutions hit, keeping an unresolved
claim as `CONTEXT_REQUIRED` instead of reaching Stage 5's hard
`Stage5InputError("target mismatch")` failure.
"""

from __future__ import annotations

import re

from fw_audit.common.schemas import GhidraFunction, Stage2Summary
from fw_audit.stage3b_claims.models import BinaryResolution, FunctionResolution

_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")


def _normalize(name: str) -> str:
    """Lowercase, strip non-alphanumerics — turns 'httpd', 'HTTPD',
    '/usr/sbin/httpd', and 'httpd.exe' into a comparable form without
    claiming any semantic understanding of the name itself."""
    return _NORMALIZE_RE.sub("", name.lower())


def resolve_binary(binary_hint: str, *, stage2_summary: Stage2Summary) -> BinaryResolution:
    """Match `binary_hint` (a claim's free-text executable/component name)
    against `stage2_summary.binaries`, trying progressively looser tiers:

    1. exact `rootfs_path` match (the hint IS a path Stage 2 already knows)
    2. exact basename match (`rootfs_path`'s final path segment)
    3. normalized-basename match (case/punctuation-insensitive)
    4. `bin_id` substring match (last resort — `bin_id` embeds the
       sanitized rootfs path, so a hint like 'sbin_hostapd' can still hit)

    Returns `BinaryResolution(bin_id=None)` — never raises — if
    `binary_hint` is empty or nothing matches at any tier; an unresolved
    binary is a legitimate, common outcome for a PDF report, not an error.
    """
    hint = binary_hint.strip()
    if not hint:
        return BinaryResolution(bin_id=None)

    for binary in stage2_summary.binaries:
        if binary.rootfs_path == hint:
            return BinaryResolution(bin_id=binary.bin_id, matched_on="rootfs_path")

    hint_basename = hint.rsplit("/", 1)[-1]
    for binary in stage2_summary.binaries:
        basename = binary.rootfs_path.rsplit("/", 1)[-1]
        if basename == hint_basename:
            return BinaryResolution(bin_id=binary.bin_id, matched_on="basename")

    normalized_hint = _normalize(hint_basename)
    if normalized_hint:
        for binary in stage2_summary.binaries:
            basename = binary.rootfs_path.rsplit("/", 1)[-1]
            if _normalize(basename) == normalized_hint:
                return BinaryResolution(bin_id=binary.bin_id, matched_on="normalized_basename")

    if normalized_hint:
        for binary in stage2_summary.binaries:
            if normalized_hint in _normalize(binary.bin_id):
                return BinaryResolution(bin_id=binary.bin_id, matched_on="bin_id_substring")

    return BinaryResolution(bin_id=None)


def resolve_function(
    function_hint: str, *, functions: tuple[GhidraFunction, ...]
) -> FunctionResolution:
    """Match `function_hint` against one binary's real Ghidra function
    table, using EXACTLY the same two tiers, in the same order, as
    `stage5_verification.tools.characterize_tool._find_function`: exact
    `GhidraFunction.name` match, then `function_hint in fn.entry_point`
    substring match (covers a report citing a raw address instead of a
    symbol name). Deliberately NOT looser than that function — a match
    returned here must imply that stricter downstream lookup will also
    succeed, or `emit.py`'s `decision=ESCALATE` promise (see this module's
    docstring) would be broken for exactly the claims it's meant to
    protect.

    Returns `FunctionResolution(function_name=None)` if `function_hint` is
    empty, `functions` is empty, or nothing matches.
    """
    hint = function_hint.strip()
    if not hint or not functions:
        return FunctionResolution(function_name=None)

    for fn in functions:
        if fn.name == hint:
            return FunctionResolution(function_name=fn.name, matched_on="exact")

    for fn in functions:
        if hint in fn.entry_point:
            return FunctionResolution(function_name=fn.name, matched_on="entry_point_substring")

    return FunctionResolution(function_name=None)
