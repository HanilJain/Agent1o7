/* Defect Class 4 — this file's only own types are ones the SELF-CONTAINED
 * prelude must supply without a real #include <stdint.h>. Real collision
 * confirmed on both a MinGW host and a glibc host: each collides on a
 * DIFFERENT subset of stdint.h's transitively-pulled-in POSIX internal
 * typedefs (size_t/ssize_t/time_t/intptr_t/__gnuc_va_list/...), because
 * this translation unit is closed-world and never actually links against
 * real libc.
 *
 * uintptr_t specifically is what passes.declare_register_vars synthesizes
 * for every in_/unaff_/extraout_-prefixed register reference — this file
 * has one, exercising that dependency directly.
 */

uint32_t compute(uint8_t a, uint16_t b)

{
  uintptr_t addr;
  addr = in_FS_OFFSET;
  return (uint32_t)a + (uint32_t)b + (uint32_t)addr;
}
