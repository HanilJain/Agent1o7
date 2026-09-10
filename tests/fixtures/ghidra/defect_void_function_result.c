/* Defect Class 5 — a shared low-level trampoline typed `void` but used as
 * a value at its call sites. Real shape confirmed against DIR-825's
 * hostapd binary: FUN_004056f0, FUN_004530f0, and FUN_00456a70 are each
 * declared `void` but assigned-from at dozens of call sites elsewhere in
 * the same file (`iVar1 = FUN_004056f0();`, `sVar1 = FUN_004056f0();`,
 * ...) — Ghidra couldn't resolve the shared trampoline's return type and
 * defaulted to `void`, but the binary calls it polymorphically.
 *
 * FUN_00457000 is deliberately genuinely void and never used as a value —
 * repair_void_function_results must leave it untouched (the intersection
 * with used-as-value names must exclude it).
 */

void FUN_004056f0(void)

{
  return;
}

void FUN_00457000(void)

{
  return;
}

int caller(void)

{
  int iVar1;
  iVar1 = FUN_004056f0();
  FUN_00457000();
  return iVar1;
}
