"""Pure-Python filesystem utilities: enriched tree.txt generation and ELF parsing.

No external tools required for ELF identification — everything here works
with nothing but the standard library. This module belongs to Component 1
(the Extraction Script): it produces `tree.txt`, the artifact handed
directly to Component 2 (the Identifier Agent). It never scores or judges
binaries — that's the Identifier Agent's job (see `identifier/agent.py`);
this module only describes what's there.
"""

from __future__ import annotations

import os
import stat
import struct
from pathlib import Path

from fw_audit.common.constants import ELF_MAGIC, ROOTFS_SKIP_DIRS
from fw_audit.common.schemas import ELFArch, ELFInfo

# ELF header field offsets/sizes we care about (e_ident is the first 16 bytes).
_EI_CLASS = 4
_EI_DATA = 5
_ELF32_HEADER_FMT_LE = "<HHIIIIIHHHHHH"  # after e_ident, e_type..e_shstrndx
_ELF32_HEADER_FMT_BE = ">HHIIIIIHHHHHH"
_ELF64_HEADER_FMT_LE = "<HHIQQQIHHHHHH"
_ELF64_HEADER_FMT_BE = ">HHIQQQIHHHHHH"

_EM_TO_ARCH: dict[int, ELFArch] = {
    3: ELFArch.X86,
    8: ELFArch.MIPS,
    40: ELFArch.ARM,
    62: ELFArch.X86_64,
    183: ELFArch.AARCH64,
}

_PT_INTERP = 3


def is_elf(path: Path) -> bool:
    """Cheap magic-byte check; does not validate the rest of the header."""
    try:
        with path.open("rb") as f:
            return f.read(4) == ELF_MAGIC
    except OSError:
        return False


class ELFParseError(ValueError):
    """Raised when a file has the ELF magic but a malformed/truncated header."""


def parse_elf_header(path: Path) -> ELFInfo:
    """Dependency-free ELF header parser.

    Reads just enough of the file (e_ident + the fixed-size header + the
    program header table) to determine architecture, bitness, endianness,
    and whether a dynamic linker interpreter (PT_INTERP) is present. Raises
    :class:`ELFParseError` if the file isn't a well-formed ELF.
    """
    size_bytes = path.stat().st_size
    with path.open("rb") as f:
        e_ident = f.read(16)
        if len(e_ident) < 16 or e_ident[:4] != ELF_MAGIC:
            raise ELFParseError(f"{path}: missing ELF magic")

        ei_class = e_ident[_EI_CLASS]  # 1 = ELF32, 2 = ELF64
        ei_data = e_ident[_EI_DATA]  # 1 = little-endian, 2 = big-endian
        is_64bit = ei_class == 2
        is_little_endian = ei_data == 1

        if ei_class not in (1, 2) or ei_data not in (1, 2):
            raise ELFParseError(f"{path}: invalid EI_CLASS/EI_DATA")

        if is_64bit:
            fmt = _ELF64_HEADER_FMT_LE if is_little_endian else _ELF64_HEADER_FMT_BE
        else:
            fmt = _ELF32_HEADER_FMT_LE if is_little_endian else _ELF32_HEADER_FMT_BE

        rest_size = struct.calcsize(fmt)
        rest = f.read(rest_size)
        if len(rest) < rest_size:
            raise ELFParseError(f"{path}: truncated ELF header")

        fields = struct.unpack(fmt, rest)
        (
            _e_type,
            e_machine,
            _e_version,
            _e_entry,
            e_phoff,
            _e_shoff,
            _e_flags,
            _e_ehsize,
            e_phentsize,
            e_phnum,
            _e_shentsize,
            _e_shnum,
            _e_shstrndx,
        ) = fields

        arch = _EM_TO_ARCH.get(e_machine, ELFArch.UNKNOWN)

        interpreter: str | None = None
        if e_phoff and e_phnum:
            for i in range(e_phnum):
                f.seek(e_phoff + i * e_phentsize)
                ph_raw = f.read(e_phentsize)
                if len(ph_raw) < 8:
                    continue
                p_type = struct.unpack(("<I" if is_little_endian else ">I"), ph_raw[:4])[0]
                if p_type == _PT_INTERP:
                    # Layout differs between ELF32/ELF64; re-derive offset/filesz.
                    endian = "<" if is_little_endian else ">"
                    if is_64bit:
                        # p_type,p_flags,p_offset,p_vaddr,p_paddr,p_filesz,...
                        _, _, p_offset, _, _, p_filesz = struct.unpack(
                            endian + "IIQQQQ", ph_raw[:40]
                        )
                    else:
                        _, p_offset, _, _, p_filesz = struct.unpack(
                            endian + "IIIII", ph_raw[:20]
                        )
                    f.seek(p_offset)
                    raw = f.read(min(p_filesz, 4096))
                    interpreter = raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

        # Stripped heuristic: no section header table (zero sections) is a
        # strong signal, since debug/symtab info lives in sections, not
        # segments. This is a heuristic, not a guarantee.
        is_stripped: bool | None = _e_shnum == 0

    return ELFInfo(
        path=str(path),
        absolute_path=str(path.resolve()),
        size_bytes=size_bytes,
        arch=arch,
        is_64bit=is_64bit,
        is_little_endian=is_little_endian,
        is_stripped=is_stripped,
        interpreter=interpreter,
    )


def _format_size(size_bytes: int) -> str:
    """Human-readable size, e.g. `84.2K`, matching `tree -h`/`ls -lh` conventions."""
    size = float(size_bytes)
    for unit in ("B", "K", "M", "G"):
        if size < 1024 or unit == "G":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}G"  # pragma: no cover - unreachable for realistic firmware sizes


def write_tree_txt(root: Path, out_path: Path) -> Path:
    """Write an enriched, recursive `tree`-style listing of `root` to `out_path`.

    Every file entry is annotated with its size; ELF files additionally get a
    `file(1)`-style descriptor (architecture, bitness, endianness, linkage,
    stripped status). This is the artifact handed directly to the Identifier
    Agent — an LLM with `tree.txt` text as its *only* input, no filesystem
    access — so the annotation is what lets it actually recognise ELF
    binaries instead of guessing from filenames alone.

    Symlinks are listed but not followed, to avoid infinite loops on
    self-referential rootfs images.
    """
    lines: list[str] = [str(root)]

    def _is_dir_safe(entry: Path) -> bool:
        """`Path.is_dir()` follows symlinks and can raise `OSError` for a
        dangling or otherwise unresolvable one — observed in practice on
        Windows as WinError 1920 for a relative symlink whose target was
        never populated in a static rootfs dump (e.g. `debug ->
        sys/kernel/debug`, since sysfs is normally populated by a running
        kernel, not present in an extracted image). A symlink is always
        treated as a leaf here regardless of what it resolves to — this
        function never walks into one (see this function's docstring) — so
        it short-circuits on `is_symlink()` and never calls `is_dir()` on a
        symlink at all, rather than merely catching the error after the
        fact."""
        if entry.is_symlink():
            return False
        try:
            return entry.is_dir()
        except OSError:
            return False

    def _annotate(entry: Path) -> str:
        try:
            size = entry.stat().st_size
        except OSError:
            return ""
        annotation = f"  {_format_size(size)}"
        if is_elf(entry):
            try:
                annotation += f"  ({parse_elf_header(entry).describe()})"
            except (ELFParseError, OSError, struct.error):
                annotation += "  (ELF, unparseable header)"
        return annotation

    def _walk(dir_path: Path, prefix: str) -> None:
        try:
            entries = sorted(
                dir_path.iterdir(), key=lambda p: (not _is_dir_safe(p), p.name.lower())
            )
        except (PermissionError, OSError) as exc:
            lines.append(f"{prefix}[unreadable: {exc}]")
            return

        # Skip virtual/pseudo directories that make no sense in a static rootfs dump.
        entries = [e for e in entries if e.name not in ROOTFS_SKIP_DIRS]

        for i, entry in enumerate(entries):
            is_last = i == len(entries) - 1
            connector = "└── " if is_last else "├── "
            is_symlink = entry.is_symlink()
            is_dir = _is_dir_safe(entry)  # already False for any symlink
            suffix = "/" if is_dir else ""
            symlink_note = f" -> {entry.readlink()}" if is_symlink else ""
            annotation = "" if is_dir or is_symlink else _annotate(entry)
            lines.append(f"{prefix}{connector}{entry.name}{suffix}{symlink_note}{annotation}")

            if is_dir:
                extension = "    " if is_last else "│   "
                _walk(entry, prefix + extension)

    _walk(root, "")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


def _ensure_owner_writable(entry: Path, *, is_dir: bool) -> None:
    """OR in the owner-write bit (and owner-execute for a directory, so it
    stays traversable), never removing any bit already set. Never raises —
    one entry's mode failing to change must not abort extraction over a
    cosmetic permission issue."""
    try:
        mode = entry.stat().st_mode
        new_mode = mode | stat.S_IWUSR | (stat.S_IXUSR if is_dir else 0)
        if new_mode != mode:
            entry.chmod(new_mode)
    except OSError:
        pass


def normalize_rootfs_permissions(rootfs_dir: Path) -> None:
    """Ensure every file/dir under `rootfs_dir` is owner-writable.

    `unsquashfs` faithfully preserves the ORIGINAL firmware's file mode —
    router vendors routinely ship files read-only (confirmed against a
    real firmware: `sbin/rc` extracted as `-r--r--r--`). Left as-is, Stage
    2's later Docker bind-mount of this same rootfs into the Ghidra
    container fails to even READ that file — Ghidra's
    `java.io.RandomAccessFile` opens in a mode that still needs the host
    write bit set, surfacing as an opaque
    "java.io.FileNotFoundException: ... (Permission denied)" deep inside a
    container log a user would have no reason to associate with a file
    permission from the original router's firmware. Called once, right
    after `rootfs_dir` is settled and before anything reads from it (see
    `nodes.generate_tree`), so every later consumer — Stage 1's own
    `write_tree_txt` below, and Stage 2's Ghidra invocation — sees a
    filesystem it can always open.

    Symlinks are never touched (`os.walk(followlinks=False)` doesn't
    recurse into one, and this function only chmods regular files/dirs it
    is handed) — matching this module's established policy of treating a
    symlink as a leaf, never dereferencing it (see `write_tree_txt`).
    """
    for dirpath, dirnames, filenames in os.walk(str(rootfs_dir), followlinks=False):
        for name in dirnames:
            entry = Path(dirpath) / name
            if not entry.is_symlink():
                _ensure_owner_writable(entry, is_dir=True)
        for name in filenames:
            entry = Path(dirpath) / name
            if not entry.is_symlink():
                _ensure_owner_writable(entry, is_dir=False)
