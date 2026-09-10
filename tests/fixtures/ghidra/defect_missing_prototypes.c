/* Defect Class 6 — no forward declaration for a function called before
 * its own definition appears in the file. Real shape confirmed against
 * DIR-825's hostapd binary: a statically linked binary's real libc
 * functions (gmtime, fcntl, ...) are decompiled as ordinary functions
 * defined LATER in the whole-program export, so C99's implicit-int
 * fallback fires at the first call site and then collides with the real
 * (later) definition.
 *
 * FIRST is called (from SECOND, below) before its own definition, which
 * appears after SECOND in source order — the exact call-before-
 * definition shape hoist_function_prototypes must forward-declare.
 */

int SECOND(int x)

{
  return FIRST(x) + 1;
}

int FIRST(int x)

{
  return x * 2;
}
