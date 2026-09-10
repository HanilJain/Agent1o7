/* Defect Class 1 — value-only (anonymous) enumerator.
 * Real shape confirmed against Ghidra's decompilation of DIR-825's
 * hostapd binary (Elf_SectionHeaderType_MIPS at raw line 259): Ghidra
 * dropped the enumerator's NAME while keeping its VALUE, producing a
 * bare `= value,` line inside the enum body — a hard parse error.
 *
 * Two enums sharing the SAME anonymous value exercises the collision
 * suffix (`_2`) name_anonymous_enumerators must apply, since C
 * enumerators share one file-scope namespace regardless of which enum
 * declared them.
 */

typedef enum Elf_SectionHeaderType_MIPS {
    SHT_NULL=0,
    SHT_PROGBITS=1,
    SHT_MIPS_RELD=1879048201,
    =1879048203,
    SHT_MIPS_CONTENT=1879048204,
} Elf_SectionHeaderType_MIPS;

typedef enum Second_Enum {
    SECOND_A=1,
    =1879048203,
} Second_Enum;
