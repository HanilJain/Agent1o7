"""QEMU+GDB command-composition primitives for the dynamic-verification
track (FVVW v3 §7-§8) — owns EVERY `qemu-*`/`gdb-multiarch` invocation the
dynamic track's nodes (`fvvw.dynamic_track`) run. Command composition lives
entirely here, never LLM-controlled: the strategy agent supplies only
`DynamicPlan` DATA (addresses, guard names/forced-values, the benign
payload marker) — never a shell command string — mirroring the exact
discipline `tools/joern_tool.py` already established for the static track
("the generator LLM never constructs the underlying docker run/joern-parse/
joern --script command line — only the script BODY").

Full multi-arch build (per the confirmed implementation direction): the
complete arch -> QEMU-binary mapping (user AND system mode) and the
argument-register map for every supported architecture, not a single-arch
placeholder.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

CONTAINER_WORKDIR = "/work"


@dataclass(frozen=True)
class QemuArchSpec:
    """One architecture's QEMU binaries + calling-convention facts — the
    doc's §8 arch table, expressed as data rather than a chain of
    `if arch == ...` branches, so a new arch is one dict entry, not a new
    code path."""

    user_binary: str
    """`qemu-<arch>` — user-mode emulation binary (chroot + one process)."""
    system_binary: str
    """`qemu-system-<arch>` — full-kernel-boot emulation binary, for
    `plan_emulation`'s system-mode path (guards/reach requiring live
    kernel/NVRAM/IPC)."""
    arg_registers: tuple[str, ...]
    """GDB register names for the first N integer/pointer arguments, in
    calling-convention order — read by `instrument_trigger` to capture the
    sink call's actual argument value."""
    cpu_probe_env: dict[str, str]
    """Known CPU-feature-probe environment-variable fixes
    (`bringup_stabilize`'s repair catalog) — e.g. the ARM `libcrypto`
    SIGILL-during-CRT-init fix. Empty dict if this arch has no known
    quirk."""


# The full FVVW v3 §8 arch table. Keyed on (arch, endianness) since
# `common.schemas.ELFArch` doesn't itself distinguish endianness variants
# (armeb vs arm, mipsel vs mips) — `TargetMeta.arch`/`TargetMeta.endianness`
# together are what this table is actually looked up against (see
# `resolve_qemu_arch_spec` below).
QEMU_ARCH_TABLE: dict[tuple[str, str], QemuArchSpec] = {
    ("arm", "little"): QemuArchSpec(
        user_binary="qemu-arm",
        system_binary="qemu-system-arm",
        arg_registers=("$r0", "$r1", "$r2", "$r3"),
        cpu_probe_env={"OPENSSL_armcap": "0"},
    ),
    ("arm", "big"): QemuArchSpec(
        user_binary="qemu-armeb",
        system_binary="qemu-system-arm",
        arg_registers=("$r0", "$r1", "$r2", "$r3"),
        cpu_probe_env={"OPENSSL_armcap": "0"},
    ),
    ("aarch64", "little"): QemuArchSpec(
        user_binary="qemu-aarch64",
        system_binary="qemu-system-aarch64",
        arg_registers=("$x0", "$x1", "$x2", "$x3", "$x4", "$x5", "$x6", "$x7"),
        cpu_probe_env={},
    ),
    ("aarch64", "big"): QemuArchSpec(
        user_binary="qemu-aarch64_be",
        system_binary="qemu-system-aarch64",
        arg_registers=("$x0", "$x1", "$x2", "$x3", "$x4", "$x5", "$x6", "$x7"),
        cpu_probe_env={},
    ),
    ("mips", "big"): QemuArchSpec(
        user_binary="qemu-mips",
        system_binary="qemu-system-mips",
        arg_registers=("$a0", "$a1", "$a2", "$a3"),
        cpu_probe_env={},
    ),
    ("mips", "little"): QemuArchSpec(
        user_binary="qemu-mipsel",
        system_binary="qemu-system-mipsel",
        arg_registers=("$a0", "$a1", "$a2", "$a3"),
        cpu_probe_env={},
    ),
    # mips64/mips64el and ppc/ppc64 share the plain "mips"/"unknown"-style
    # ELFArch bucket in this repo's schema (no dedicated ELFArch member) —
    # entries kept here keyed on the string a future characterize_target
    # refinement could emit, so adding real 64-bit-MIPS/PPC detection later
    # is a schema+lookup change, not a new arch-table shape.
    ("mips64", "big"): QemuArchSpec(
        user_binary="qemu-mips64",
        system_binary="qemu-system-mips64",
        arg_registers=("$a0", "$a1", "$a2", "$a3"),
        cpu_probe_env={},
    ),
    ("mips64", "little"): QemuArchSpec(
        user_binary="qemu-mips64el",
        system_binary="qemu-system-mips64",
        arg_registers=("$a0", "$a1", "$a2", "$a3"),
        cpu_probe_env={},
    ),
    ("ppc", "big"): QemuArchSpec(
        user_binary="qemu-ppc",
        system_binary="qemu-system-ppc",
        arg_registers=("$r3", "$r4", "$r5", "$r6"),
        cpu_probe_env={},
    ),
    ("ppc64", "big"): QemuArchSpec(
        user_binary="qemu-ppc64",
        system_binary="qemu-system-ppc",
        arg_registers=("$r3", "$r4", "$r5", "$r6"),
        cpu_probe_env={},
    ),
}


def resolve_qemu_arch_spec(arch: str, endianness: str) -> QemuArchSpec | None:
    """Look up `QEMU_ARCH_TABLE`, returning `None` for an unsupported
    combination — the caller (`plan_emulation`) treats `None` as hard
    infeasibility (`dynamic_runnable=False`), per the design doc's "false
    ONLY for hard infeasibility, e.g. no QEMU support for the arch"."""
    return QEMU_ARCH_TABLE.get((arch, endianness))


def gdb_binary() -> str:
    """The ONE GDB binary every dynamic session drives, regardless of
    target architecture — `gdb-multiarch`, never a native single-arch
    `gdb` (targets are cross-architecture)."""
    return "gdb-multiarch"


def build_qemu_user_launch_command(
    *,
    arch_spec: QemuArchSpec,
    target_relpath: str,
    argv: list[str] | None = None,
    rootfs_relpath: str | None = None,
    gdb_port: int = 1234,
    qemu_binary_in_chroot: str | None = None,
) -> str:
    """Assemble the exact user-mode QEMU launch command
    (`bringup_stabilize`'s job per the design doc), in order: chroot prefix
    (if `rootfs_relpath` is given — the target resolves paths relative to
    its own rootfs, as `/sbin/rc`-style dispatcher binaries do), the
    CPU-probe environment-variable fixes (`arch_spec.cpu_probe_env`), the
    QEMU user-mode binary, the GDB stub flag `-g <port>`, the library/
    sysroot path `-L <rootfs>`, then the target path and any argv.

    All paths are relative to the bind-mounted session workspace
    (`CONTAINER_WORKDIR`) — this function never sees or needs a host path.

    When chrooting (`rootfs_relpath` given), the QEMU emulator binary must
    exist INSIDE the rootfs to be reachable after `chroot`, and the `-L`
    sysroot resolves against the POST-chroot root (`/`), not the pre-chroot
    path. The caller (`bringup_stabilize`) stages a static QEMU binary into
    the rootfs and passes its absolute-in-chroot path as
    `qemu_binary_in_chroot` (e.g. `/qemu-mips`); `-L /` then points QEMU at
    the (now-root) rootfs for library resolution. Without a chroot
    (`rootfs_relpath is None`), the container's own `qemu-<arch>` on PATH is
    used and no `-L` is emitted."""
    if rootfs_relpath and not qemu_binary_in_chroot:
        raise ValueError(
            "qemu_binary_in_chroot is required when rootfs_relpath is set: after "
            "chroot the container's qemu-<arch> is unreachable, so the caller must "
            "stage a static QEMU binary into the rootfs and pass its in-chroot path."
        )
    parts: list[str] = []
    if rootfs_relpath:
        parts += ["chroot", shlex.quote(rootfs_relpath)]
    for key, value in arch_spec.cpu_probe_env.items():
        parts.append(f"{key}={shlex.quote(value)}")
    # After chroot, the container's /usr/bin/qemu-<arch> is no longer
    # reachable — use the copy the caller staged inside the rootfs.
    parts.append(shlex.quote(qemu_binary_in_chroot) if rootfs_relpath else arch_spec.user_binary)
    parts += ["-g", str(gdb_port)]
    if rootfs_relpath:
        # Post-chroot, the rootfs IS `/`, so that's the sysroot for -L.
        parts += ["-L", "/"]
    parts.append(shlex.quote(target_relpath))
    if argv:
        parts += [shlex.quote(a) for a in argv]
    return " ".join(parts)


def build_qemu_system_launch_command(
    *,
    arch_spec: QemuArchSpec,
    kernel_relpath: str,
    rootfs_image_relpath: str,
    extra_args: list[str] | None = None,
    gdb_port: int = 1234,
) -> str:
    """Assemble a full-kernel-boot QEMU launch command for
    `plan_emulation`'s system-mode path — used when a guard/reach path
    requires a live kernel/NVRAM/IPC rather than a self-contained
    dispatcher binary. Deliberately minimal (kernel + root filesystem image
    + GDB stub) since the exact machine/network/device flags a given
    firmware's system-mode boot needs are firmware-specific;
    `bringup_stabilize`'s repair catalog is where those get filled in via
    `extra_args` as they're discovered, without this function's own shape
    changing."""
    parts = [
        arch_spec.system_binary,
        "-kernel",
        shlex.quote(kernel_relpath),
        "-drive",
        f"file={shlex.quote(rootfs_image_relpath)},format=raw",
        "-gdb",
        f"tcp::{gdb_port}",
        "-S",  # start halted, so GDB always attaches before any code runs
        "-nographic",
    ]
    if extra_args:
        parts += extra_args
    return " ".join(parts)


def build_gdb_batch_command(recipe_relpath: str, target_relpath: str) -> str:
    """`gdb-multiarch -batch -x <recipe> <target>` — runs a pre-written GDB
    command file non-interactively against the target binary (loaded for
    its symbols/sections), then connects to the QEMU stub the recipe itself
    issues `target remote localhost:<port>` for (see
    `render_gdb_recipe`). One call per `reach_target`/`satisfy_guards`/
    `instrument_trigger`/`collect_signals` node, executed via
    `SandboxExecutor.exec_in_session()` against the SAME running session
    container QEMU was started in — never `run()`, since the emulated
    process must stay alive between these calls."""
    return (
        f"{gdb_binary()} -batch -x {shlex.quote(recipe_relpath)} {shlex.quote(target_relpath)}"
    )


def render_gdb_recipe(
    *,
    architecture: str,
    gdb_port: int,
    entry_addr: str,
    breakpoint_commands: list[str],
) -> str:
    """Render the shared GDB-recipe preamble (connect + pagination/confirm
    settings + break at the functional entry) followed by
    `breakpoint_commands` — the caller-supplied per-node body (guard
    forcing, trigger instrumentation, signal capture). This is the ONE
    place the `target remote`/`set architecture`/`set pagination off`/
    `set confirm off` boilerplate FVVW §7's recipe describes lives, so
    every dynamic-track node's recipe shares it instead of re-deriving it.
    """
    lines = [
        f"set architecture {architecture}",
        "set pagination off",
        "set confirm off",
        f"target remote localhost:{gdb_port}",
        f"break *{entry_addr}",
        "continue",
        *breakpoint_commands,
    ]
    return "\n".join(lines) + "\n"


def render_guard_breakpoint_commands(
    *, addr: str, register: str, forced_value: str, log_marker: str
) -> list[str]:
    """The `satisfy_guards` recipe body for ONE guard: break at its
    address, print the REAL (un-overridden) return value first (logged via
    a distinguishable marker so `bringup_stabilize`/the report can later
    state honestly what the default behavior was), force it to
    `forced_value`, then continue. Register defaults to the architecture's
    first return-value-bearing register (`arg_registers[0]`) unless the
    caller names a different one."""
    return [
        f"break *{addr}",
        "continue",
        f'printf "{log_marker}:real=%d\\n", {register}',
        f"set {register} = {forced_value}",
        "continue",
    ]


def render_trigger_breakpoint_commands(
    *, sink_addr: str, argument_register: str, capture_marker: str
) -> list[str]:
    """The `instrument_trigger` recipe body: break at the sink, print the
    actual sink argument (as a C string) verbatim — this is the direct
    sink-argument-capture signal `collect_signals`/`dynamic_evaluate` reads
    to test the decisive observable."""
    return [
        f"break *{sink_addr}",
        "continue",
        f'printf "{capture_marker}:%s\\n", (char*){argument_register}',
    ]


__all__ = [
    "CONTAINER_WORKDIR",
    "QEMU_ARCH_TABLE",
    "QemuArchSpec",
    "build_gdb_batch_command",
    "build_qemu_system_launch_command",
    "build_qemu_user_launch_command",
    "gdb_binary",
    "render_gdb_recipe",
    "render_guard_breakpoint_commands",
    "render_trigger_breakpoint_commands",
    "resolve_qemu_arch_spec",
]
