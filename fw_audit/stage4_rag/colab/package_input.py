"""One-off local helper: zips Stage 1's rootfs + Stage 2's `stage2/binaries/`
into a single archive for upload into the `stage4_colab.ipynb` notebook
(Option A in its Section 2). Not part of the Colab-pasted script itself —
this runs locally, before you ever open Colab.

Handles the same class of Windows `OSError` on unreadable entries
(device nodes, unsupported reparse points inside an extracted Linux
rootfs) that `chunk_and_embed.discover_rootfs_files` already guards
against — `shutil.make_archive`/PowerShell's `Compress-Archive` both abort
the whole zip on the first one instead of skipping it.

Usage
-----
```bash
python fw_audit/stage4_rag/colab/package_input.py \\
    --rootfs data/db/<stem>/binwalk_1/_input.pkgtb.extracted/squashfs-root \\
    --stage2-binaries data/db/<stem>/stage2/binaries \\
    --output stage4_colab_input.zip
```

The resulting zip's internal layout matches what `stage4_colab.ipynb`
Section 2's unzip step expects: `squashfs-root/...` and
`stage2_binaries/...` at the archive root.
"""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path


def _iter_readable_files(root: Path) -> list[Path]:
    """Same `OSError`-tolerant walk as `chunk_and_embed.discover_rootfs_files`
    — a real extracted rootfs routinely contains entries `Path.is_file()`/
    `.is_symlink()` raise on rather than returning `False` for."""
    files: list[Path] = []
    for p in root.rglob("*"):
        try:
            if p.is_symlink() or not p.is_file():
                continue
        except OSError:
            continue
        files.append(p)
    return files


def package_input(*, rootfs_dir: Path, stage2_binaries_dir: Path, output: Path) -> Path:
    written = 0
    skipped = 0
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in _iter_readable_files(rootfs_dir):
            try:
                arcname = str(Path("squashfs-root") / path.relative_to(rootfs_dir))
                zf.write(path, arcname=arcname)
                written += 1
            except OSError:
                skipped += 1
        for path in _iter_readable_files(stage2_binaries_dir):
            try:
                arcname = str(Path("stage2_binaries") / path.relative_to(stage2_binaries_dir))
                zf.write(path, arcname=arcname)
                written += 1
            except OSError:
                skipped += 1
    print(f"[package_input] wrote {written} files, skipped {skipped} unreadable entries")
    print(f"[package_input] {output} ({output.stat().st_size / 1e6:.1f} MB)")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--stage2-binaries", required=True, type=Path)
    parser.add_argument("--output", default=Path("stage4_colab_input.zip"), type=Path)
    args = parser.parse_args()

    package_input(
        rootfs_dir=args.rootfs, stage2_binaries_dir=args.stage2_binaries, output=args.output
    )
