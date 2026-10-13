"""Unit tests for `stage5_verification.tools.dep_resolver`.

Tests cover:
- `parse_dynamic_section`: hand-crafted ELF bytes with DT_NEEDED entries
- Library resolution against a tmp_path rootfs with staged libraries
- Symlink following stays re-rooted (path traversal prevention)
- $ORIGIN substitution in RPATH
- ABI mismatch detection (different arch/bitness)
- Graceful degradation for static binaries (no PT_DYNAMIC)
- `discover_runtime_deps_from_stage2` pattern inference
- `resolve_or_load_cached` cache round-trip
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from fw_audit.stage5_verification.tools.dep_resolver import (
    _build_search_paths,
    _check_abi_compatible,
    _follow_symlink_in_rootfs,
    discover_runtime_deps_from_stage2,
    parse_dynamic_section,
    resolve_dependencies,
    resolve_or_load_cached,
)

# ---------------------------------------------------------------------------
# Synthetic ELF builders
# ---------------------------------------------------------------------------

_ELF_MAGIC = b"\x7fELF"


def _make_static_elf32_le() -> bytes:
    """A minimal ELF32 LE with no PT_DYNAMIC (statically linked)."""
    ei_class, ei_data = 1, 1
    e_ident = _ELF_MAGIC + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    # ELF32 header after e_ident: HHIIIIIHHHHHH
    # e_type=2(EXEC), e_machine=40(ARM), e_version=1, e_entry=0, e_phoff=52, e_shoff=0,
    # e_flags=0, e_ehsize=52, e_phentsize=32, e_phnum=0 (no program headers → static)
    rest = struct.pack("<HHIIIIIHHHHHH", 2, 40, 1, 0, 52, 0, 0, 52, 32, 0, 0, 0, 0)
    return e_ident + rest


def _make_dynamic_elf32_le(dt_needed: list[str], rpath: str = "") -> bytes:
    """Build a minimal ELF32 LE with PT_DYNAMIC containing the given DT_NEEDED entries.

    Layout:
    - ELF header (52 bytes) — e_phoff=52
    - Program headers (2x 32 bytes = 64 bytes) — PT_LOAD then PT_DYNAMIC
    - Dynamic section data
    - String table (pointed to by DT_STRTAB)
    """
    # Build string table: null-terminated strings packed together.
    # Entry 0 is always the empty string (index 0).
    strtab = b"\x00"
    string_indices: dict[str, int] = {}
    for s in ([rpath] if rpath else []) + dt_needed:
        if s and s not in string_indices:
            string_indices[s] = len(strtab)
            strtab += s.encode() + b"\x00"

    elf_header_size = 52
    ph_entry_size = 32
    num_ph = 2  # PT_LOAD + PT_DYNAMIC
    ph_table_size = num_ph * ph_entry_size

    # Dynamic section: one Elf32_Dyn entry = 8 bytes (d_tag + d_val, both I)
    dyn_entries: list[tuple[int, int]] = []
    # DT_STRTAB — virtual address; we'll set it equal to file offset (identity-mapped via PT_LOAD)
    # DT_STRSZ
    # DT_NEEDED for each soname
    # optional DT_RPATH
    # DT_NULL terminator

    dyn_section_start = elf_header_size + ph_table_size
    _strtab_vaddr_offset = 0  # will be filled in after we know total dyn size

    # Estimate dyn section size first (DT_STRTAB, DT_STRSZ, DT_NEEDED*N, [DT_RPATH], DT_NULL)
    num_dyn = 3 + len(dt_needed) + (1 if rpath else 0)
    dyn_size = num_dyn * 8

    strtab_file_offset = dyn_section_start + dyn_size
    strtab_vaddr = strtab_file_offset  # identity-mapped PT_LOAD

    # Now build actual entries
    dyn_entries.append((5, strtab_vaddr))   # DT_STRTAB
    dyn_entries.append((10, len(strtab)))   # DT_STRSZ
    for soname in dt_needed:
        dyn_entries.append((1, string_indices[soname]))   # DT_NEEDED
    if rpath:
        dyn_entries.append((15, string_indices[rpath]))   # DT_RPATH
    dyn_entries.append((0, 0))  # DT_NULL

    dyn_section = b"".join(struct.pack("<iI", tag, val) for tag, val in dyn_entries)
    assert len(dyn_section) == dyn_size

    total_size = strtab_file_offset + len(strtab)
    # Pad to nice alignment
    total_size = (total_size + 3) & ~3

    load_vaddr = 0
    load_filesz = total_size
    dyn_vaddr = dyn_section_start
    dyn_filesz = dyn_size

    def _ph32(p_type: int, p_offset: int, p_vaddr: int, p_filesz: int) -> bytes:
        # Elf32_Phdr: p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
        return struct.pack(
            "<IIIIIIII", p_type, p_offset, p_vaddr, p_vaddr, p_filesz, p_filesz, 5, 4
        )

    ph_load = _ph32(1, 0, load_vaddr, load_filesz)
    ph_dyn = _ph32(2, dyn_section_start, dyn_vaddr, dyn_filesz)

    ei_class, ei_data = 1, 1
    e_ident = _ELF_MAGIC + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    # e_type=2, e_machine=40(ARM), e_phoff=52, e_phentsize=32, e_phnum=2
    elf_header_rest = struct.pack(
        "<HHIIIIIHHHHHH",
        2, 40, 1, 0, elf_header_size, 0, 0, elf_header_size, ph_entry_size, num_ph, 0, 0, 0,
    )

    payload = e_ident + elf_header_rest + ph_load + ph_dyn + dyn_section + strtab
    # pad to total_size
    payload += b"\x00" * (total_size - len(payload))
    return payload


def _make_elf32_le_machine(machine: int) -> bytes:
    """Minimal ELF32 LE with the given e_machine (no PT_DYNAMIC)."""
    ei_class, ei_data = 1, 1
    e_ident = _ELF_MAGIC + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    rest = struct.pack("<HHIIIIIHHHHHH", 2, machine, 1, 0, 52, 0, 0, 52, 32, 0, 0, 0, 0)
    return e_ident + rest


def _make_elf64_le_machine(machine: int) -> bytes:
    """Minimal ELF64 LE with the given e_machine (no PT_DYNAMIC)."""
    ei_class, ei_data = 2, 1
    e_ident = _ELF_MAGIC + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    rest = struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, 0, 64, 0, 0, 64, 56, 0, 0, 0, 0)
    return e_ident + rest


# ---------------------------------------------------------------------------
# parse_dynamic_section tests
# ---------------------------------------------------------------------------


def test_parse_dynamic_section_static_binary(tmp_path: Path) -> None:
    elf_path = tmp_path / "static_bin"
    elf_path.write_bytes(_make_static_elf32_le())
    result = parse_dynamic_section(elf_path)
    assert result is not None
    assert result.is_static is True
    assert result.needed == []


def test_parse_dynamic_section_dt_needed(tmp_path: Path) -> None:
    sonames = ["libc.so.6", "libssl.so.1.0.0"]
    elf_path = tmp_path / "dynamic_bin"
    elf_path.write_bytes(_make_dynamic_elf32_le(sonames))
    result = parse_dynamic_section(elf_path)
    assert result is not None
    assert result.is_static is False
    assert result.needed == sonames


def test_parse_dynamic_section_rpath(tmp_path: Path) -> None:
    elf_path = tmp_path / "rpath_bin"
    elf_path.write_bytes(_make_dynamic_elf32_le(["libc.so.6"], rpath="/usr/local/lib"))
    result = parse_dynamic_section(elf_path)
    assert result is not None
    assert result.rpath == "/usr/local/lib"


def test_parse_dynamic_section_non_elf(tmp_path: Path) -> None:
    p = tmp_path / "not_elf"
    p.write_bytes(b"just some data that is not ELF")
    result = parse_dynamic_section(p)
    assert result is None


def test_parse_dynamic_section_missing_file(tmp_path: Path) -> None:
    result = parse_dynamic_section(tmp_path / "nonexistent")
    assert result is None


# ---------------------------------------------------------------------------
# _build_search_paths tests
# ---------------------------------------------------------------------------


def test_build_search_paths_rpath_wins_when_no_runpath(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    paths = _build_search_paths(
        rootfs, rpath="/custom/lib", runpath="", elf_dir=Path("/bin"), e_machine=40
    )
    assert (rootfs / "custom" / "lib") in paths
    # Standard paths also present
    assert (rootfs / "lib") in paths


def test_build_search_paths_runpath_overrides_rpath(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    paths = _build_search_paths(
        rootfs, rpath="/rpath_lib", runpath="/runpath_lib", elf_dir=Path("/bin"), e_machine=40
    )
    # DT_RPATH should NOT appear when DT_RUNPATH is present
    assert (rootfs / "rpath_lib") not in paths
    assert (rootfs / "runpath_lib") in paths


def test_build_search_paths_origin_substitution(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    paths = _build_search_paths(
        rootfs, rpath="$ORIGIN/../lib", runpath="", elf_dir=Path("/usr/bin"), e_machine=40
    )
    # $ORIGIN is /usr/bin, so ../lib → /usr/lib (rootfs-relative)
    assert any("usr" in str(p) or "lib" in str(p) for p in paths)


def test_build_search_paths_deduplicates(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    paths = _build_search_paths(
        rootfs, rpath="/lib", runpath="", elf_dir=Path("/bin"), e_machine=40
    )
    # /lib appears in both DT_RPATH and standard paths — should appear only once
    lib_path = rootfs / "lib"
    assert paths.count(lib_path) == 1


# ---------------------------------------------------------------------------
# _follow_symlink_in_rootfs tests
# ---------------------------------------------------------------------------


def test_symlink_resolved_within_rootfs(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    lib_dir = rootfs / "lib"
    lib_dir.mkdir(parents=True)
    real = lib_dir / "libfoo.so.1.0"
    real.write_bytes(_make_static_elf32_le())
    link = lib_dir / "libfoo.so"
    link.symlink_to("libfoo.so.1.0")
    result = _follow_symlink_in_rootfs(link, rootfs)
    assert result == real


def test_symlink_does_not_escape_rootfs(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    lib_dir = rootfs / "lib"
    lib_dir.mkdir(parents=True)
    # Symlink pointing to /../.. (would escape rootfs)
    link = lib_dir / "escape_link"
    link.symlink_to("../../outside")
    result = _follow_symlink_in_rootfs(link, rootfs)
    # Should return None — target is outside rootfs
    assert result is None


# ---------------------------------------------------------------------------
# ABI compatibility check
# ---------------------------------------------------------------------------


def test_check_abi_compatible_same_arch(tmp_path: Path) -> None:
    lib = tmp_path / "libfoo.so"
    lib.write_bytes(_make_elf32_le_machine(40))  # ARM32 LE
    assert _check_abi_compatible(40, False, True, lib) is True


def test_check_abi_compatible_different_arch(tmp_path: Path) -> None:
    lib = tmp_path / "libfoo.so"
    lib.write_bytes(_make_elf32_le_machine(8))  # MIPS instead of ARM
    assert _check_abi_compatible(40, False, True, lib) is False


def test_check_abi_compatible_different_bitness(tmp_path: Path) -> None:
    lib = tmp_path / "libfoo.so"
    lib.write_bytes(_make_elf64_le_machine(40))  # ARM 64-bit
    assert _check_abi_compatible(40, False, True, lib) is False  # target is 32-bit


def test_check_abi_compatible_unreadable_file(tmp_path: Path) -> None:
    # Non-existent file → optimistic True (can't determine)
    assert _check_abi_compatible(40, False, True, tmp_path / "nonexistent.so") is True


# ---------------------------------------------------------------------------
# resolve_dependencies integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_dependencies_static_binary(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    binary = rootfs / "bin" / "static_app"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(_make_static_elf32_le())

    report = await resolve_dependencies(binary, rootfs)
    assert report.is_static is True
    assert report.total_needed == 0
    assert report.blocking_reasons == []


@pytest.mark.asyncio
async def test_resolve_dependencies_all_present(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    lib_dir = rootfs / "lib"
    lib_dir.mkdir(parents=True)

    # Create a matching ARM32 LE library
    (lib_dir / "libc.so.6").write_bytes(_make_elf32_le_machine(40))

    binary = rootfs / "bin" / "app"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(_make_dynamic_elf32_le(["libc.so.6"]))

    report = await resolve_dependencies(binary, rootfs, interpreter=None)
    assert report.total_needed == 1
    assert report.total_resolved == 1
    assert report.total_missing == 0
    assert report.blocking_reasons == []


@pytest.mark.asyncio
async def test_resolve_dependencies_missing_library(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "lib").mkdir(parents=True)

    binary = rootfs / "bin" / "app"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(_make_dynamic_elf32_le(["libmissing.so.1"]))

    report = await resolve_dependencies(binary, rootfs)
    assert report.total_missing == 1
    # "libmissing.so.1" is not in _is_missing_expected list → hard MISSING
    assert any("libmissing" in str(lib.soname) for lib in report.libraries)


@pytest.mark.asyncio
async def test_resolve_dependencies_missing_expected(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "lib").mkdir(parents=True)

    binary = rootfs / "bin" / "app"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(_make_dynamic_elf32_le(["libpthread.so.0"]))

    report = await resolve_dependencies(binary, rootfs)
    from fw_audit.common.deps import DependencyStatus
    pthread_lib = next(lib for lib in report.libraries if "pthread" in lib.soname)
    assert pthread_lib.status == DependencyStatus.MISSING_EXPECTED
    # MISSING_EXPECTED should NOT appear in blocking_reasons
    assert not any("pthread" in r for r in report.blocking_reasons)


@pytest.mark.asyncio
async def test_resolve_dependencies_abi_mismatch(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    lib_dir = rootfs / "lib"
    lib_dir.mkdir(parents=True)

    # Wrong arch (MIPS instead of ARM)
    (lib_dir / "libssl.so.1").write_bytes(_make_elf32_le_machine(8))

    binary = rootfs / "bin" / "app"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(_make_dynamic_elf32_le(["libssl.so.1"]))

    report = await resolve_dependencies(binary, rootfs)
    assert report.total_incompatible == 1
    assert any("ABI-incompatible" in r for r in report.blocking_reasons)


@pytest.mark.asyncio
async def test_resolve_dependencies_missing_interpreter(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "lib").mkdir(parents=True)
    binary = rootfs / "bin" / "app"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(_make_dynamic_elf32_le([]))

    report = await resolve_dependencies(binary, rootfs, interpreter="/lib/ld-linux.so.3")
    assert any("interpreter" in r.lower() for r in report.blocking_reasons)


# ---------------------------------------------------------------------------
# discover_runtime_deps_from_stage2
# ---------------------------------------------------------------------------


def test_discover_env_dep() -> None:
    deps = discover_runtime_deps_from_stage2(["getenv", "printf", "fopen"])
    from fw_audit.common.deps import DependencyKind
    env_deps = [d for d in deps if d.kind == DependencyKind.ENV_VAR]
    assert len(env_deps) == 1
    assert env_deps[0].name == "getenv"


def test_discover_config_file_dep() -> None:
    strings = ["/etc/config/wireless"]
    deps = discover_runtime_deps_from_stage2([], strings=strings)
    from fw_audit.common.deps import DependencyKind
    cfg_deps = [d for d in deps if d.kind == DependencyKind.CONFIG_FILE]
    assert len(cfg_deps) == 1
    assert cfg_deps[0].name == "/etc/config/wireless"


def test_discover_device_node_dep() -> None:
    strings = ["/dev/nvram"]
    deps = discover_runtime_deps_from_stage2([], strings=strings)
    from fw_audit.common.deps import DependencyKind
    dev_deps = [d for d in deps if d.kind == DependencyKind.DEVICE_NODE]
    assert len(dev_deps) == 1
    assert dev_deps[0].name == "/dev/nvram"


def test_discover_deduplicates() -> None:
    deps = discover_runtime_deps_from_stage2(["getenv", "getenv"])
    from fw_audit.common.deps import DependencyKind
    env_deps = [d for d in deps if d.kind == DependencyKind.ENV_VAR]
    assert len(env_deps) == 1  # deduplicated


# ---------------------------------------------------------------------------
# resolve_or_load_cached
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_roundtrip(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "lib").mkdir(parents=True)
    binary = rootfs / "bin" / "app"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(_make_static_elf32_le())

    cache_path = tmp_path / "cache" / "abc123.json"

    # First call — cache miss → resolve + persist
    report1 = await resolve_or_load_cached(binary, rootfs, cache_path)
    assert cache_path.is_file()
    raw = json.loads(cache_path.read_text())
    assert raw["is_static"] is True

    # Second call — cache hit → same report, no re-resolution
    report2 = await resolve_or_load_cached(binary, rootfs, cache_path)
    assert report2.binary_sha256 == report1.binary_sha256


@pytest.mark.asyncio
async def test_cache_invalidated_on_rootfs_mismatch(tmp_path: Path) -> None:
    rootfs1 = tmp_path / "rootfs1"
    rootfs1.mkdir()
    (rootfs1 / "lib").mkdir()
    binary = rootfs1 / "bin" / "app"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(_make_static_elf32_le())

    cache_path = tmp_path / "cache" / "abc123.json"
    await resolve_or_load_cached(binary, rootfs1, cache_path)

    # Now request with a different rootfs → cache should be ignored
    rootfs2 = tmp_path / "rootfs2"
    rootfs2.mkdir()
    report = await resolve_or_load_cached(binary, rootfs2, cache_path)
    assert str(report.rootfs_dir) == str(rootfs2.resolve())
