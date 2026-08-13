"""JSON (de)serialization of `cleaned/functions.json` — the per-function
index that lets a reader reconstruct an `ExtractedSource` from
`cleaned/whole.c` without re-running tree-sitter.

Shared by `stage2_extraction.extract` (writer) and
`stage3_analysis.cleaned_io` (reader) — living here rather than duplicated
in both places, since Stage 3 already depends on `stage2_extraction` for
`layout`/`normalize.context` and this is the same kind of cross-stage path
algebra, just for a JSON shape instead of a filesystem path.
"""

from __future__ import annotations

from fw_audit.common.schemas import ExtractedFunction, ExtractedSource


def to_index_json_dict(source: ExtractedSource) -> dict:
    """`source.functions` must already carry CONCATENATED-text-relative
    spans (see `clean.extract.respan_for_concatenated_text`) — this
    function does no respanning of its own, it only serializes."""
    return {
        "bin_id": source.bin_id,
        "total_lines": source.total_lines,
        "dropped_line_count": source.dropped_line_count,
        "functions": [
            {"name": f.name, "start_line": f.start_line, "end_line": f.end_line}
            for f in source.functions
        ],
    }


def source_from_index_and_text(index: dict, whole_c_text: str) -> ExtractedSource:
    """Reconstruct an `ExtractedSource` by slicing `whole_c_text`'s lines
    per the index's recorded spans — the inverse of writing `cleaned/
    whole.c` + `functions.json` from `to_index_json_dict`.

    `start_line`/`end_line` are 1-indexed and inclusive, matching every
    other line-number convention in this project (`ExtractedFunction`,
    `Chunk`, Ghidra's own `metadata.json`).
    """
    lines = whole_c_text.split("\n")
    functions = tuple(
        ExtractedFunction(
            name=entry["name"],
            start_line=entry["start_line"],
            end_line=entry["end_line"],
            text="\n".join(lines[entry["start_line"] - 1 : entry["end_line"]]),
        )
        for entry in index.get("functions", [])
    )
    return ExtractedSource(
        bin_id=index.get("bin_id", ""),
        functions=functions,
        total_lines=index.get("total_lines", 0),
        dropped_line_count=index.get("dropped_line_count", 0),
    )


__all__ = ["to_index_json_dict", "source_from_index_and_text"]
