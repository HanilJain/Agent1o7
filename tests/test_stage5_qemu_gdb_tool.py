"""Tests for `stage5_verification.tools.qemu_gdb_tool` — Stage 5 FVVW v3
Phase 4. Pure command-composition tests, no Docker/QEMU/GDB involved —
same discipline as `tests/test_stage5_joern_tool.py`'s command-string
assertions."""

from __future__ import annotations

import pytest

from fw_audit.stage5_verification.tools.qemu_gdb_tool import (
    QEMU_ARCH_TABLE,
    build_gdb_batch_command,
    build_qemu_system_launch_command,
    build_qemu_user_launch_command,
    gdb_binary,
    normalize_hex_addr,
    render_gdb_recipe,
    render_guard_breakpoint_commands,
    render_trigger_breakpoint_commands,
    resolve_qemu_arch_spec,
)

# ---------------------------------------------------------------------- #
# QEMU_ARCH_TABLE / resolve_qemu_arch_spec
# ---------------------------------------------------------------------- #


def test_arch_table_covers_full_doc_spec():
    """FVVW v3 §8's full arch table — every entry must resolve."""
    expected = [
        ("arm", "little"),
        ("arm", "big"),
        ("aarch64", "little"),
        ("mips", "big"),
        ("mips", "little"),
        ("mips64", "big"),
        ("mips64", "little"),
        ("ppc", "big"),
        ("ppc64", "big"),
    ]
    for arch, endian in expected:
        spec = resolve_qemu_arch_spec(arch, endian)
        assert spec is not None, f"missing arch table entry for ({arch}, {endian})"
        assert spec.user_binary.startswith("qemu-")
        assert spec.system_binary.startswith("qemu-system-")


def test_resolve_qemu_arch_spec_returns_none_for_unsupported_combo():
    assert resolve_qemu_arch_spec("x86_64", "little") is None
    assert resolve_qemu_arch_spec("unknown", "") is None


def test_arm_user_binary_is_little_endian_variant():
    spec = resolve_qemu_arch_spec("arm", "little")
    assert spec.user_binary == "qemu-arm"


def test_arm_user_binary_is_big_endian_variant():
    spec = resolve_qemu_arch_spec("arm", "big")
    assert spec.user_binary == "qemu-armeb"


def test_mips_user_binary_distinguishes_endianness():
    be = resolve_qemu_arch_spec("mips", "big")
    le = resolve_qemu_arch_spec("mips", "little")
    assert be.user_binary == "qemu-mips"
    assert le.user_binary == "qemu-mipsel"


def test_argument_registers_differ_by_architecture():
    arm = resolve_qemu_arch_spec("arm", "little")
    aarch64 = resolve_qemu_arch_spec("aarch64", "little")
    mips = resolve_qemu_arch_spec("mips", "big")
    ppc = resolve_qemu_arch_spec("ppc", "big")
    assert arm.arg_registers[:4] == ("$r0", "$r1", "$r2", "$r3")
    assert aarch64.arg_registers[:4] == ("$x0", "$x1", "$x2", "$x3")
    assert mips.arg_registers == ("$a0", "$a1", "$a2", "$a3")
    assert ppc.arg_registers == ("$r3", "$r4", "$r5", "$r6")


def test_arm_has_cpu_probe_env_fix():
    spec = resolve_qemu_arch_spec("arm", "little")
    assert spec.cpu_probe_env == {"OPENSSL_armcap": "0"}


def test_mips_has_no_known_cpu_probe_quirk():
    spec = resolve_qemu_arch_spec("mips", "big")
    assert spec.cpu_probe_env == {}


# ---------------------------------------------------------------------- #
# gdb_binary
# ---------------------------------------------------------------------- #


def test_gdb_binary_is_always_multiarch():
    assert gdb_binary() == "gdb-multiarch"


# ---------------------------------------------------------------------- #
# build_qemu_user_launch_command
# ---------------------------------------------------------------------- #


def test_user_launch_command_basic_shape():
    spec = QEMU_ARCH_TABLE[("mips", "little")]
    cmd = build_qemu_user_launch_command(
        arch_spec=spec, target_relpath="sbin/rc", gdb_port=1234
    )
    assert cmd == "qemu-mipsel -g 1234 sbin/rc"


def test_user_launch_command_with_chroot_and_rootfs():
    spec = QEMU_ARCH_TABLE[("arm", "little")]
    cmd = build_qemu_user_launch_command(
        arch_spec=spec,
        target_relpath="sbin/rc",
        rootfs_relpath=".",
        gdb_port=1234,
        qemu_binary_in_chroot="/qemu-arm",
    )
    # After chroot the emulator runs from inside the rootfs (staged static
    # binary at /qemu-arm) and the sysroot is the new root `/`, not the
    # pre-chroot path.
    assert cmd.startswith("chroot . OPENSSL_armcap=0 /qemu-arm -g 1234 -L / sbin/rc")


def test_user_launch_command_chroot_requires_qemu_binary_in_chroot():
    spec = QEMU_ARCH_TABLE[("arm", "little")]
    with pytest.raises(ValueError, match="qemu_binary_in_chroot is required"):
        build_qemu_user_launch_command(
            arch_spec=spec, target_relpath="sbin/rc", rootfs_relpath="."
        )


def test_user_launch_command_includes_argv():
    spec = QEMU_ARCH_TABLE[("mips", "little")]
    cmd = build_qemu_user_launch_command(
        arch_spec=spec,
        target_relpath="sbin/rc",
        argv=["vuln_path", "; touch /tmp/proof;"],
        gdb_port=1234,
    )
    assert cmd.endswith("sbin/rc vuln_path '; touch /tmp/proof;'")


def test_user_launch_command_without_rootfs_omits_chroot_and_dash_l():
    spec = QEMU_ARCH_TABLE[("mips", "little")]
    cmd = build_qemu_user_launch_command(arch_spec=spec, target_relpath="sbin/rc")
    assert "chroot" not in cmd
    assert "-L" not in cmd


# ---------------------------------------------------------------------- #
# build_qemu_system_launch_command
# ---------------------------------------------------------------------- #


def test_system_launch_command_shape():
    spec = QEMU_ARCH_TABLE[("arm", "little")]
    cmd = build_qemu_system_launch_command(
        arch_spec=spec,
        kernel_relpath="boot/zImage",
        rootfs_image_relpath="boot/rootfs.img",
        gdb_port=1234,
    )
    assert cmd.startswith("qemu-system-arm -kernel boot/zImage")
    assert "-drive file=boot/rootfs.img,format=raw" in cmd
    assert "-gdb tcp::1234" in cmd
    assert "-S" in cmd


def test_system_launch_command_accepts_extra_args():
    spec = QEMU_ARCH_TABLE[("mips", "big")]
    cmd = build_qemu_system_launch_command(
        arch_spec=spec,
        kernel_relpath="k",
        rootfs_image_relpath="r",
        extra_args=["-m", "64"],
    )
    assert cmd.endswith("-m 64")


# ---------------------------------------------------------------------- #
# build_gdb_batch_command
# ---------------------------------------------------------------------- #


def test_gdb_batch_command_shape():
    cmd = build_gdb_batch_command("recipe.gdb", "sbin/rc")
    assert cmd == "gdb-multiarch -batch -x recipe.gdb sbin/rc"


# ---------------------------------------------------------------------- #
# render_gdb_recipe
# ---------------------------------------------------------------------- #


def test_render_gdb_recipe_includes_connect_and_entry_breakpoint():
    recipe = render_gdb_recipe(
        architecture="arm",
        gdb_port=1234,
        entry_addr="0x00022594",
        breakpoint_commands=["break *0x00026938", "continue"],
    )
    lines = recipe.splitlines()
    assert "set architecture arm" in lines
    assert "target remote localhost:1234" in lines
    assert "break *0x00022594" in lines
    assert lines[-2:] == ["break *0x00026938", "continue"]


# ---------------------------------------------------------------------- #
# render_guard_breakpoint_commands / render_trigger_breakpoint_commands
# ---------------------------------------------------------------------- #


def test_render_guard_breakpoint_commands_logs_real_value_before_forcing():
    commands = render_guard_breakpoint_commands(
        addr="0x000276dc",
        register="$r0",
        forced_value="1",
        log_marker="GUARD:acscli2_acs_restart",
    )
    assert commands[0] == "break *0x000276dc"
    # real value logged BEFORE the force — order matters (design doc:
    # "log the real un-overridden return value first").
    log_index = next(i for i, c in enumerate(commands) if "real=%d" in c)
    force_index = next(i for i, c in enumerate(commands) if c.startswith("set $r0"))
    assert log_index < force_index
    assert "set $r0 = 1" in commands


def test_render_trigger_breakpoint_commands_captures_sink_argument():
    commands = render_trigger_breakpoint_commands(
        sink_addr="0x00020ba8", argument_register="$r0", capture_marker="TRIGGER:sink_arg"
    )
    assert commands[0] == "break *0x00020ba8"
    assert any("TRIGGER:sink_arg" in c and "(char*)$r0" in c for c in commands)


# ---------------------------------------------------------------------- #
# normalize_hex_addr — GDB `break *<addr>` needs a 0x prefix on bare hex
# ---------------------------------------------------------------------- #


def test_normalize_hex_addr_prefixes_bare_hex():
    # Ghidra/Stage 2 emit bare hex; GDB rejects `break *00400900` with
    # 'Invalid number "00400900"' (observed on real MIPS firmware).
    assert normalize_hex_addr("00400900") == "0x00400900"


def test_normalize_hex_addr_passes_through_already_prefixed():
    assert normalize_hex_addr("0x00400900") == "0x00400900"
    assert normalize_hex_addr("0X1A2B") == "0X1A2B"


def test_normalize_hex_addr_leaves_symbolic_operand_alone():
    assert normalize_hex_addr("main") == "main"
    assert normalize_hex_addr("fn+4") == "fn+4"


def test_render_gdb_recipe_normalizes_bare_hex_entry_addr():
    recipe = render_gdb_recipe(
        architecture="mips", gdb_port=1234, entry_addr="00400900", breakpoint_commands=[]
    )
    assert "break *0x00400900" in recipe.splitlines()
    assert "break *00400900" not in recipe


def test_render_guard_and_trigger_normalize_bare_hex():
    guard = render_guard_breakpoint_commands(
        addr="000276dc", register="$a0", forced_value="1", log_marker="GUARD:g"
    )
    assert guard[0] == "break *0x000276dc"
    trigger = render_trigger_breakpoint_commands(
        sink_addr="00020ba8", argument_register="$a0", capture_marker="TRIGGER:t"
    )
    assert trigger[0] == "break *0x00020ba8"
