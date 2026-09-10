/* Defect Class 7 — intrinsic macro coverage, including the specific
 * "phantom type" regression: an earlier version of prelude._concat_macros
 * generated CONCAT13/CONCAT31/etc. casting a 3-byte operand to `uint24_t`,
 * a type that never exists anywhere. Confirmed against DIR-825's hostapd
 * binary: 8 of the 11 CONCAT macros shipped in that version referenced a
 * phantom NN-bit type, and all 8 were actually used in the real file.
 *
 * CONCAT21 alone was the originally-reported symptom (used, never
 * #define'd at all under the OLD power-of-two-only {2,4,8} generator);
 * CONCAT13/CONCAT31/CONCAT53 additionally exercise the phantom-type
 * variant of the same defect class.
 */

unsigned int concat_examples(unsigned char a, unsigned short b, unsigned int c)
{
  unsigned int r1 = CONCAT21(b, a);
  unsigned int r2 = CONCAT13(a, b);
  unsigned int r3 = CONCAT31(b, a);
  unsigned long long r4 = CONCAT53(c, a);
  return r1 + r2 + r3 + (unsigned int)r4;
}

unsigned int sub_zext_examples(unsigned int x, unsigned long long y)
{
  unsigned int a = SUB41(x, 0);
  unsigned int b = SUB42(x, 1);
  unsigned short c = ZEXT816(y);
  return a + b + c;
}
