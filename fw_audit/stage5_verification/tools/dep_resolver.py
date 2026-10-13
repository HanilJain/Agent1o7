"""Binary dependency resolver for Stage 5 FVVW v3 dynamic track.

Resolves shared-library dependencies (DT_NEEDED), interpreter (PT_INTERP),
and inferred runtime prerequisites (config files, device nodes, env vars) for
a firmware binary against its rootfs — entirely host-side, no Docker/sandbox
needed.  Follows ``characterize_tool``'s "deliberately cheap" posture: stdlib
``struct`` only (no pyelftools), ``async`` interface, ``aspan`` tracing, never
raises on soft failures.

The key parsing work this module adds beyond ``stage1_ingestion.tools.
filesystem_tools.parse_elf_header`` is reading the ELF dynamic section
(program header type PT_DYNAMIC = 2), walking the ``Elf{32,64}_Dyn`` tag/value
array to extract DT_NEEDED sonames.  DT_STRTAB gives a *virtual address*, not a
file offset, so a ``_vaddr_to_file_offset`` helper converts it via the PT_LOAD
segment table before the string table is read — a well-understood 20-line
transformation, no external tool needed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import struct
from collections import deque
from pathlib import Path

from fw_audit.common.deps import (
    ConfidenceLevel,
    DependencyKind,
    DependencyReport,
    DependencyStatus,
    LibraryResolution,
    ResolvedDependency,
)
from fw_audit.observability import aspan

logger = logging.getLogger("fw_audit.stage5_verification.tools.dep_resolver")

# ---------------------------------------------------------------------------
# ELF constants
# ---------------------------------------------------------------------------

_ELF_MAGIC = b"\x7fELF"
_EI_CLASS = 4
_EI_DATA = 5

# Program header types
_PT_LOAD = 1
_PT_DYNAMIC = 2

# Dynamic section tags
_DT_NULL = 0
_DT_NEEDED = 1
_DT_PLTRELSZ = 2
_DT_SONAME = 14
_DT_RPATH = 15
_DT_SYMBOLIC = 16
_DT_RELSZ = 18
_DT_STRTAB = 5
_DT_STRSZ = 10
_DT_RUNPATH = 29

# Arch triplets for standard ld.so lib search paths
_ARCH_TRIPLETS: dict[int, list[str]] = {
    40: ["arm-linux-gnueabi", "arm-linux-gnueabihf"],
    183: ["aarch64-linux-gnu"],
    8: ["mips-linux-gnu", "mipsel-linux-gnu"],
    3: ["i386-linux-gnu"],
    62: ["x86_64-linux-gnu"],
}

# Standard fallback library search paths inside rootfs (ld.so order)
_STANDARD_LIB_PATHS = [
    "/lib",
    "/usr/lib",
    "/lib64",
    "/usr/lib64",
    "/usr/local/lib",
]

_MAX_SYMLINK_DEPTH = 10
_MAX_DEP_DEPTH = 10


# ---------------------------------------------------------------------------
# Internal ELF parsing helpers
# ---------------------------------------------------------------------------


class _ElfInfo:
    """Minimal ELF facts needed by the dep resolver — enough to walk PT_LOAD
    and PT_DYNAMIC.  Parsed once per file; never re-raised to callers."""

    __slots__ = (
        "is_64bit",
        "is_little_endian",
        "e_phoff",
        "e_phentsize",
        "e_phnum",
        "e_machine",
    )

    def __init__(
        self,
        is_64bit: bool,
        is_little_endian: bool,
        e_phoff: int,
        e_phentsize: int,
        e_phnum: int,
        e_machine: int,
    ) -> None:
        self.is_64bit = is_64bit
        self.is_little_endian = is_little_endian
        self.e_phoff = e_phoff
        self.e_phentsize = e_phentsize
        self.e_phnum = e_phnum
        self.e_machine = e_machine


def _parse_elf_header_minimal(f: object) -> _ElfInfo | None:  # type: ignore[type-arg]
    """Read e_ident + fixed header from an already-open binary file.
    Returns None for non-ELF or truncated/malformed files — never raises."""
    try:
        e_ident = f.read(16)  # type: ignore[attr-defined]
        if len(e_ident) < 16 or e_ident[:4] != _ELF_MAGIC:
            return None
        ei_class = e_ident[_EI_CLASS]
        ei_data = e_ident[_EI_DATA]
        if ei_class not in (1, 2) or ei_data not in (1, 2):
            return None
        is_64bit = ei_class == 2
        is_little_endian = ei_data == 1
        endian = "<" if is_little_endian else ">"

        # ELF32 after e_ident: HHIIIIIHHHHHH  (e_type..e_shstrndx)
        # ELF64 after e_ident: HHIQQQIHHHHHH
        fmt = endian + ("HHIQQQIHHHHHH" if is_64bit else "HHIIIIIHHHHHH")
        size = struct.calcsize(fmt)
        rest = f.read(size)  # type: ignore[attr-defined]
        if len(rest) < size:
            return None
        fields = struct.unpack(fmt, rest)
        # fields: e_type(0), e_machine(1), e_version(2), e_entry(3), e_phoff(4),
        #         e_shoff(5), e_flags(6), e_ehsize(7), e_phentsize(8), e_phnum(9), ...
        e_machine = fields[1]
        e_phoff = fields[4]
        e_phentsize = fields[8]
        e_phnum = fields[9]
        return _ElfInfo(
            is_64bit=is_64bit,
            is_little_endian=is_little_endian,
            e_phoff=e_phoff,
            e_phentsize=e_phentsize,
            e_phnum=e_phnum,
            e_machine=e_machine,
        )
    except (OSError, struct.error):
        return None


def _read_ph(f: object, elf: _ElfInfo, i: int) -> tuple[int, int, int, int] | None:  # type: ignore[type-arg]
    """Read the i-th program header, returning (p_type, p_offset, p_vaddr,
    p_filesz).  Returns None on read failure."""
    try:
        f.seek(elf.e_phoff + i * elf.e_phentsize)  # type: ignore[attr-defined]
        ph_raw = f.read(elf.e_phentsize)  # type: ignore[attr-defined]
        if len(ph_raw) < elf.e_phentsize:
            return None
        endian = "<" if elf.is_little_endian else ">"
        if elf.is_64bit:
            # Elf64_Phdr: p_type(I) p_flags(I) p_offset(Q) p_vaddr(Q) p_paddr(Q)
            #             p_filesz(Q) p_memsz(Q) p_align(Q)
            p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz = struct.unpack(
                endian + "IIQQQQ", ph_raw[:40]
            )
        else:
            # Elf32_Phdr: p_type(I) p_offset(I) p_vaddr(I) p_paddr(I)
            #             p_filesz(I) p_memsz(I) p_flags(I) p_align(I)
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz = struct.unpack(
                endian + "IIIII", ph_raw[:20]
            )
        return p_type, p_offset, p_vaddr, p_filesz
    except (OSError, struct.error):
        return None


def _vaddr_to_file_offset(vaddr: int, load_segments: list[tuple[int, int, int]]) -> int | None:
    """Convert a virtual address to a file offset using the PT_LOAD segment
    table.  Each entry is (p_vaddr, p_offset, p_filesz).  Returns None if
    no segment covers the address."""
    for seg_vaddr, seg_offset, seg_filesz in load_segments:
        if seg_vaddr <= vaddr < seg_vaddr + seg_filesz:
            return seg_offset + (vaddr - seg_vaddr)
    return None


class _DynamicInfo:
    """Extracted dynamic section facts."""

    __slots__ = ("needed", "rpath", "runpath", "soname", "is_static")

    def __init__(self) -> None:
        self.needed: list[str] = []
        self.rpath: str = ""
        self.runpath: str = ""
        self.soname: str = ""
        self.is_static: bool = True


def parse_dynamic_section(path: Path) -> _DynamicInfo | None:
    """Parse the ELF dynamic section of ``path``, returning DT_NEEDED sonames,
    DT_RPATH, DT_RUNPATH, DT_SONAME.  Returns None for non-ELF or
    statically-linked binaries (no PT_DYNAMIC segment).  Never raises."""
    info = _DynamicInfo()
    try:
        with path.open("rb") as f:
            elf = _parse_elf_header_minimal(f)
            if elf is None:
                return None
            # No program headers → statically linked
            if not elf.e_phoff or not elf.e_phnum:
                return info  # is_static=True

            # First pass: collect PT_LOAD segments (for vaddr→offset) and
            # locate the PT_DYNAMIC segment.
            load_segs: list[tuple[int, int, int]] = []
            dyn_offset: int | None = None
            dyn_filesz: int | None = None

            for i in range(elf.e_phnum):
                ph = _read_ph(f, elf, i)
                if ph is None:
                    continue
                p_type, p_offset, p_vaddr, p_filesz = ph
                if p_type == _PT_LOAD:
                    load_segs.append((p_vaddr, p_offset, p_filesz))
                elif p_type == _PT_DYNAMIC:
                    dyn_offset = p_offset
                    dyn_filesz = p_filesz

            if dyn_offset is None:
                # No PT_DYNAMIC → statically linked
                return info  # is_static=True, empty lists

            info.is_static = False

            # Read the dynamic section
            f.seek(dyn_offset)
            dyn_raw = f.read(dyn_filesz or 0)

            endian = "<" if elf.is_little_endian else ">"
            # Each Elf{32,64}_Dyn entry: (d_tag, d_val/d_ptr)
            entry_fmt = endian + ("qQ" if elf.is_64bit else "iI")
            entry_size = struct.calcsize(entry_fmt)

            # Collect raw tag→value pairs; resolve strings in a second pass.
            strtab_vaddr: int | None = None
            strtab_size: int | None = None
            raw_entries: list[tuple[int, int]] = []

            off = 0
            while off + entry_size <= len(dyn_raw):
                d_tag, d_val = struct.unpack(entry_fmt, dyn_raw[off : off + entry_size])
                off += entry_size
                if d_tag == _DT_NULL:
                    break
                if d_tag == _DT_STRTAB:
                    strtab_vaddr = d_val
                elif d_tag == _DT_STRSZ:
                    strtab_size = d_val
                raw_entries.append((d_tag, d_val))

            # Locate the string table on disk via vaddr→offset.
            strtab_data: bytes = b""
            if strtab_vaddr is not None:
                strtab_file_off = _vaddr_to_file_offset(strtab_vaddr, load_segs)
                if strtab_file_off is not None:
                    f.seek(strtab_file_off)
                    strtab_data = f.read(strtab_size or 65536)

            def _str_at(idx: int) -> str:
                if not strtab_data or idx < 0 or idx >= len(strtab_data):
                    return ""
                end = strtab_data.find(b"\x00", idx)
                if end == -1:
                    end = len(strtab_data)
                return strtab_data[idx:end].decode("utf-8", errors="replace")

            for d_tag, d_val in raw_entries:
                if d_tag == _DT_NEEDED:
                    s = _str_at(d_val)
                    if s:
                        info.needed.append(s)
                elif d_tag == _DT_RPATH:
                    info.rpath = _str_at(d_val)
                elif d_tag == _DT_RUNPATH:
                    info.runpath = _str_at(d_val)
                elif d_tag == _DT_SONAME:
                    info.soname = _str_at(d_val)

    except (OSError, struct.error, ValueError):
        return None

    return info


# ---------------------------------------------------------------------------
# Library resolution
# ---------------------------------------------------------------------------


def _clamp_to_rootfs(host_path: Path, rootfs: Path) -> Path | None:
    """Ensure ``host_path`` (an absolute path on the host) is inside
    ``rootfs``.  Returns None if it escaped the rootfs boundary."""
    try:
        host_path.relative_to(rootfs)
        return host_path
    except ValueError:
        return None


def _rootfs_join(rootfs: Path, abs_path: str) -> Path:
    """Join an absolute-inside-rootfs path (e.g. '/lib/libc.so.6') onto the
    host rootfs root, stripping any leading slash to avoid os.path.join's
    drive-letter override on Windows."""
    return rootfs / abs_path.lstrip("/\\")


def _follow_symlink_in_rootfs(link_path: Path, rootfs: Path, depth: int = 0) -> Path | None:
    """Follow a symlink chain, keeping all targets inside ``rootfs``.
    Returns the final resolved path (a real file) or None if the chain
    escapes the rootfs, exceeds the max depth, or hits a dangling link."""
    if depth > _MAX_SYMLINK_DEPTH:
        return None
    if not link_path.is_symlink():
        return link_path if link_path.exists() else None
    try:
        target = Path(link_path.readlink())  # type: ignore[attr-defined]
    except (OSError, AttributeError):
        try:
            target = Path(link_path.resolve())
        except OSError:
            return None

    if target.is_absolute():
        resolved = _rootfs_join(rootfs, str(target))
    else:
        resolved = link_path.parent / target

    clamped = _clamp_to_rootfs(resolved, rootfs)
    if clamped is None:
        return None
    return _follow_symlink_in_rootfs(clamped, rootfs, depth + 1)


def _build_search_paths(
    rootfs: Path,
    rpath: str,
    runpath: str,
    elf_dir: Path,
    e_machine: int,
) -> list[Path]:
    """Build the ld.so library search order, re-rooted inside ``rootfs``.

    Order: DT_RPATH (if DT_RUNPATH is absent) → DT_RUNPATH → standard lib
    paths → arch-specific triplet dirs.  ``$ORIGIN`` is substituted with the
    binary's own directory (relative to rootfs), following the ELF spec.
    """
    paths: list[Path] = []
    origin = str(elf_dir)

    def _expand(raw: str) -> list[Path]:
        result: list[Path] = []
        for entry in raw.split(":"):
            entry = entry.strip()
            if not entry:
                continue
            # $ORIGIN substitution
            if "$ORIGIN" in entry or "${ORIGIN}" in entry:
                entry = entry.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)
            candidate = _rootfs_join(rootfs, entry) if entry.startswith("/") else (rootfs / entry)
            clamped = _clamp_to_rootfs(candidate, rootfs)
            if clamped is not None:
                result.append(clamped)
        return result

    # DT_RPATH only wins when DT_RUNPATH is absent
    if rpath and not runpath:
        paths.extend(_expand(rpath))
    if runpath:
        paths.extend(_expand(runpath))

    for std in _STANDARD_LIB_PATHS:
        paths.append(_rootfs_join(rootfs, std))

    for triplet in _ARCH_TRIPLETS.get(e_machine, []):
        paths.append(_rootfs_join(rootfs, f"/lib/{triplet}"))
        paths.append(_rootfs_join(rootfs, f"/usr/lib/{triplet}"))

    # Deduplicate while preserving order
    seen: set[Path] = set()
    deduped: list[Path] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return deduped


def _read_arch_bits_endian(path: Path) -> tuple[int, bool, bool] | None:
    """Read (e_machine, is_64bit, is_little_endian) from a library ELF
    header — just enough to check ABI compatibility.  Returns None on
    failure."""
    try:
        with path.open("rb") as f:
            elf = _parse_elf_header_minimal(f)
            if elf is None:
                return None
            return elf.e_machine, elf.is_64bit, elf.is_little_endian
    except OSError:
        return None


def _check_abi_compatible(
    target_machine: int,
    target_64bit: bool,
    target_le: bool,
    lib_path: Path,
) -> bool:
    """Returns True if the library at ``lib_path`` has the same arch/bitness/
    endianness as the target binary.  Returns True (optimistic) when the
    library ELF can't be read."""
    result = _read_arch_bits_endian(lib_path)
    if result is None:
        return True  # can't tell — don't block on it
    lib_machine, lib_64bit, lib_le = result
    return lib_machine == target_machine and lib_64bit == target_64bit and lib_le == target_le


def _resolve_soname(
    soname: str,
    search_paths: list[Path],
    rootfs: Path,
    target_machine: int,
    target_64bit: bool,
    target_le: bool,
    tried: list[str],
) -> tuple[Path | None, DependencyStatus, bool | None]:
    """Try to find ``soname`` in ``search_paths`` inside ``rootfs``.

    Returns (resolved_path | None, status, arch_compatible | None).
    Appends every tried path to ``tried`` for diagnostics."""
    for search_dir in search_paths:
        candidate = search_dir / soname
        tried.append(str(candidate))
        if not candidate.exists() and not candidate.is_symlink():
            continue
        if candidate.is_symlink():
            real = _follow_symlink_in_rootfs(candidate, rootfs)
            if real is None:
                return None, DependencyStatus.SYMLINK_BROKEN, None
            candidate = real
        if candidate.is_file():
            abi_ok = _check_abi_compatible(
                target_machine, target_64bit, target_le, candidate
            )
            status = (
                DependencyStatus.PRESENT
                if abi_ok
                else DependencyStatus.PRESENT_INCOMPATIBLE
            )
            return candidate, status, abi_ok
    return None, DependencyStatus.MISSING, None


# ---------------------------------------------------------------------------
# Recursive resolution (BFS)
# ---------------------------------------------------------------------------


def _is_missing_expected(soname: str) -> bool:
    """True for sonames that are often absent in partial firmware extractions
    but unlikely to actually block execution (e.g. host-only tooling, kernel
    helpers).  A heuristic — errs on the side of MISSING_EXPECTED rather than
    blocking a verification attempt unnecessarily."""
    _expected_missing = (
        "libgcc_s",
        "libstdc++",
        "libpthread",
        "libdl.so",
        "libm.so",
        "librt.so",
        "libnsl.so",
        "libresolv.so",
        "libcrypt.so",
        "linux-vdso",
        "ld-linux",
        "ld-uClibc",
        "ld-musl",
    )
    lower = soname.lower()
    return any(marker in lower for marker in _expected_missing)


def _resolve_libraries(
    binary_path: Path,
    rootfs: Path,
    dyn: _DynamicInfo,
    elf: _ElfInfo,
    max_depth: int = _MAX_DEP_DEPTH,
) -> list[LibraryResolution]:
    """BFS over DT_NEEDED → resolve each → parse their own DT_NEEDED up to
    ``max_depth`` levels.  A visited-set prevents circular chains."""
    results: dict[str, LibraryResolution] = {}
    # queue items: (soname, needed_by_name, depth)
    queue: deque[tuple[str, str, int]] = deque()

    binary_name = binary_path.name
    elf_dir_abs = binary_path.parent
    # Make elf_dir rootfs-relative for $ORIGIN
    try:
        elf_dir_rel = "/" + str(elf_dir_abs.relative_to(rootfs)).replace("\\", "/")
    except ValueError:
        elf_dir_rel = str(elf_dir_abs).replace("\\", "/")

    search_paths = _build_search_paths(
        rootfs, dyn.rpath, dyn.runpath, Path(elf_dir_rel), elf.e_machine
    )

    for soname in dyn.needed:
        queue.append((soname, binary_name, 0))

    visited: set[str] = set()

    while queue:
        soname, needed_by, depth = queue.popleft()
        if soname in visited:
            # Already processed — just add this needed_by edge
            if soname in results and needed_by not in results[soname].needed_by:
                results[soname] = results[soname].model_copy(
                    update={"needed_by": [*results[soname].needed_by, needed_by]}
                )
            continue
        visited.add(soname)

        tried: list[str] = []
        resolved_path, status, abi_ok = _resolve_soname(
            soname, search_paths, rootfs,
            elf.e_machine, elf.is_64bit, elf.is_little_endian,
            tried,
        )

        # Upgrade MISSING → MISSING_EXPECTED where appropriate
        if status == DependencyStatus.MISSING and _is_missing_expected(soname):
            status = DependencyStatus.MISSING_EXPECTED

        transitive: list[str] = []
        if resolved_path is not None and depth < max_depth:
            # Parse this library's own DT_NEEDED
            lib_dyn = parse_dynamic_section(resolved_path)
            if lib_dyn is not None and not lib_dyn.is_static:
                transitive = list(lib_dyn.needed)
                for dep_soname in lib_dyn.needed:
                    if dep_soname not in visited:
                        queue.append((dep_soname, soname, depth + 1))

        results[soname] = LibraryResolution(
            soname=soname,
            status=status,
            resolved_path=str(resolved_path) if resolved_path else "",
            needed_by=[needed_by],
            transitive_deps=transitive,
            arch_compatible=abi_ok,
        )

    return list(results.values())


# ---------------------------------------------------------------------------
# Runtime dependency inference from Stage 2 data
# ---------------------------------------------------------------------------

# Patterns that suggest a runtime dependency of each kind
_ENV_CALL_PATTERNS = ("getenv", "secure_getenv", "getenv_r")
_DEV_OPEN_PATTERNS = ("/dev/", "/proc/")
_CFG_OPEN_PATTERNS = ("/etc/", "/var/", "/tmp/")


def discover_runtime_deps_from_stage2(
    calls: list[str],
    strings: list[str] | None = None,
) -> list[ResolvedDependency]:
    """Infer runtime prerequisites from Stage 2 function call names and binary
    strings (both are already computed and in-memory — no new sandbox call).
    Confidence is always INFERRED — the bringup agent's strace pass validates.

    ``calls`` is the flat list of called-symbol names gathered from the binary's
    function table (``GhidraFunction.calls``). ``strings`` is an optional list of
    literal strings extracted from the binary (Stage 2 may not supply these —
    pass ``None`` to skip string-based inference).
    """
    deps: list[ResolvedDependency] = []
    seen: set[str] = set()

    for call in calls:
        cl = call.lower()
        if any(p in cl for p in _ENV_CALL_PATTERNS):
            name = call
            key = f"env:{name}"
            if key not in seen:
                seen.add(key)
                deps.append(
                    ResolvedDependency(
                        name=name,
                        kind=DependencyKind.ENV_VAR,
                        status=DependencyStatus.MISSING,
                        confidence=ConfidenceLevel.INFERRED,
                        notes=f"binary calls {call}()",
                    )
                )

    for s in strings or []:
        for prefix in _DEV_OPEN_PATTERNS:
            if s.startswith(prefix) and "\x00" not in s:
                key = f"dev:{s}"
                if key not in seen:
                    seen.add(key)
                    deps.append(
                        ResolvedDependency(
                            name=s,
                            kind=DependencyKind.DEVICE_NODE,
                            status=DependencyStatus.MISSING,
                            confidence=ConfidenceLevel.INFERRED,
                            notes="path literal in binary",
                        )
                    )
                break

        for prefix in _CFG_OPEN_PATTERNS:
            if s.startswith(prefix) and "\x00" not in s and "/" in s[1:]:
                key = f"cfg:{s}"
                if key not in seen:
                    seen.add(key)
                    deps.append(
                        ResolvedDependency(
                            name=s,
                            kind=DependencyKind.CONFIG_FILE,
                            status=DependencyStatus.MISSING,
                            confidence=ConfidenceLevel.INFERRED,
                            notes="path literal in binary",
                        )
                    )
                break

    return deps


# ---------------------------------------------------------------------------
# Interpreter resolution
# ---------------------------------------------------------------------------


def _resolve_interpreter(
    interpreter: str | None,
    rootfs: Path,
    target_machine: int,
    target_64bit: bool,
    target_le: bool,
) -> tuple[DependencyStatus | None, bool | None]:
    """Check whether the PT_INTERP dynamic linker exists inside ``rootfs``
    and is ABI-compatible.  Returns (status, arch_compatible) or (None, None)
    for a statically-linked binary (no interpreter)."""
    if not interpreter:
        return None, None

    interp_host = _rootfs_join(rootfs, interpreter)
    if interp_host.is_symlink():
        real = _follow_symlink_in_rootfs(interp_host, rootfs)
        if real is None:
            return DependencyStatus.SYMLINK_BROKEN, None
        interp_host = real

    if not interp_host.exists():
        return DependencyStatus.MISSING, None

    abi_ok = _check_abi_compatible(target_machine, target_64bit, target_le, interp_host)
    status = (
        DependencyStatus.PRESENT if abi_ok else DependencyStatus.PRESENT_INCOMPATIBLE
    )
    return status, abi_ok


# ---------------------------------------------------------------------------
# SHA-256 helper
# ---------------------------------------------------------------------------


def _sha256_of(path: Path) -> str:
    """SHA-256 hex digest of a file; returns '' on I/O error."""
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Top-level entry points
# ---------------------------------------------------------------------------


async def resolve_dependencies(
    binary_path: Path,
    rootfs_dir: Path,
    *,
    interpreter: str | None = None,
    calls: list[str] | None = None,
    strings: list[str] | None = None,
    max_depth: int = _MAX_DEP_DEPTH,
) -> DependencyReport:
    """Resolve all dependencies of ``binary_path`` against ``rootfs_dir``.

    * Parses the ELF dynamic section (PT_DYNAMIC) — DT_NEEDED, DT_RPATH,
      DT_RUNPATH, DT_SONAME.
    * Checks the PT_INTERP interpreter path inside ``rootfs_dir``.
    * Recursively resolves shared libraries (BFS, ``max_depth`` levels).
    * Infers runtime deps from Stage 2 call patterns and string literals.

    Never raises — all failures produce a partial report with appropriate
    ``blocking_reasons`` or ``warnings``.  Wrapped in an ``aspan`` so every
    call site appears in LangSmith under ``"stage5.resolve_dependencies"``.

    ``interpreter`` may be supplied from ``VerificationCandidate.elf.interpreter``
    (Stage 2 already parsed PT_INTERP via ``parse_elf_header``); if not
    supplied, the field is left as-is in the report.
    """
    rootfs = rootfs_dir.resolve()
    binary_sha256 = _sha256_of(binary_path)

    async with aspan(
        "stage5.resolve_dependencies",
        run_type="tool",
        inputs={"binary_path": str(binary_path), "rootfs_dir": str(rootfs_dir)},
    ) as run:
        try:
            rootfs_rel = str(binary_path.relative_to(rootfs))
        except ValueError:
            rootfs_rel = str(binary_path)

        report = DependencyReport(
            binary_path=rootfs_rel,
            binary_sha256=binary_sha256,
            rootfs_dir=str(rootfs),
        )

        with binary_path.open("rb") as f:
            elf_info = _parse_elf_header_minimal(f)

        if elf_info is None:
            report.blocking_reasons.append("could not parse ELF header")
            if run is not None:
                run.end(outputs={
                    "is_static": False, "total_needed": 0, "error": "elf_parse_failed"
                })
            return report

        dyn = parse_dynamic_section(binary_path)
        if dyn is None:
            report.warnings.append("parse_dynamic_section returned None — treating as static")
            report.is_static = True
        elif dyn.is_static:
            report.is_static = True
        else:
            report.dt_needed = list(dyn.needed)
            report.dt_rpath = dyn.rpath
            report.dt_runpath = dyn.runpath
            report.dt_soname = dyn.soname

            # Interpreter
            interp_str = interpreter  # prefer caller-supplied (Stage 2 already parsed it)
            interp_status, interp_abi = _resolve_interpreter(
                interp_str, rootfs,
                elf_info.e_machine, elf_info.is_64bit, elf_info.is_little_endian,
            )
            report.interpreter = interp_str
            report.interpreter_status = interp_status
            report.interpreter_arch_compatible = interp_abi

            if interp_status == DependencyStatus.MISSING:
                report.blocking_reasons.append(
                    f"dynamic interpreter not found in rootfs: {interp_str}"
                )
            elif interp_status == DependencyStatus.SYMLINK_BROKEN:
                report.blocking_reasons.append(
                    f"dynamic interpreter symlink broken: {interp_str}"
                )
            elif interp_status == DependencyStatus.PRESENT_INCOMPATIBLE:
                report.blocking_reasons.append(
                    f"dynamic interpreter ABI mismatch: {interp_str}"
                )

            # Shared libraries
            libs = _resolve_libraries(
                binary_path, rootfs, dyn, elf_info, max_depth=max_depth
            )
            report.libraries = libs

            report.total_needed = len(dyn.needed)
            report.total_resolved = sum(
                1 for lib in libs if lib.status == DependencyStatus.PRESENT
            )
            report.total_missing = sum(
                1 for lib in libs
                if lib.status in (DependencyStatus.MISSING, DependencyStatus.SYMLINK_BROKEN)
            )
            report.total_incompatible = sum(
                1 for lib in libs if lib.status == DependencyStatus.PRESENT_INCOMPATIBLE
            )

            for lib in libs:
                if lib.status == DependencyStatus.PRESENT_INCOMPATIBLE:
                    report.blocking_reasons.append(
                        f"ABI-incompatible library in rootfs: {lib.soname} at {lib.resolved_path}"
                    )

        # Runtime dependencies from Stage 2 data
        runtime_deps = discover_runtime_deps_from_stage2(
            calls or [], strings=strings
        )
        report.runtime_deps = runtime_deps

        if run is not None:
            run.end(
                outputs={
                    "is_static": report.is_static,
                    "total_needed": report.total_needed,
                    "total_resolved": report.total_resolved,
                    "total_missing": report.total_missing,
                    "total_incompatible": report.total_incompatible,
                    "blocking_reasons": report.blocking_reasons,
                }
            )

    return report


async def resolve_or_load_cached(
    binary_path: Path,
    rootfs_dir: Path,
    dep_report_path: Path,
    *,
    interpreter: str | None = None,
    calls: list[str] | None = None,
    strings: list[str] | None = None,
    max_depth: int = _MAX_DEP_DEPTH,
    use_cache: bool = True,
) -> DependencyReport:
    """Load a cached ``DependencyReport`` from ``dep_report_path`` if it exists
    and was produced against the same ``rootfs_dir``; otherwise run
    ``resolve_dependencies`` and persist the result.

    Cache key is (binary_sha256, rootfs_dir) — the same binary in a different
    rootfs produces a separate report.  ``dep_report_path`` is the caller's
    chosen path (typically from ``layout.dep_report_path(...)``).
    """
    if use_cache and dep_report_path.is_file():
        try:
            raw = json.loads(dep_report_path.read_text(encoding="utf-8"))
            cached = DependencyReport.model_validate(raw)
            if cached.rootfs_dir == str(rootfs_dir.resolve()):
                logger.debug("dep_resolver: cache hit for %s", binary_path.name)
                return cached
        except Exception:  # noqa: BLE001
            logger.debug("dep_resolver: cache invalid for %s, re-resolving", binary_path.name)

    report = await resolve_dependencies(
        binary_path,
        rootfs_dir,
        interpreter=interpreter,
        calls=calls,
        strings=strings,
        max_depth=max_depth,
    )

    if use_cache:
        try:
            dep_report_path.parent.mkdir(parents=True, exist_ok=True)
            dep_report_path.write_text(
                report.model_dump_json(indent=2), encoding="utf-8"
            )
        except OSError as exc:
            logger.warning("dep_resolver: could not persist cache to %s: %s", dep_report_path, exc)

    return report


__all__ = [
    "parse_dynamic_section",
    "resolve_dependencies",
    "resolve_or_load_cached",
    "discover_runtime_deps_from_stage2",
]
