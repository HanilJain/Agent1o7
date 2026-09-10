/* Defect Class 3 (+ the root-cause span desync it causes, + Class 2) —
 * illegal characters in Ghidra symbol names.
 *
 * Real shape confirmed against DIR-825's hostapd binary, raw lines
 * 732-739: Ghidra names PTR_s_* symbols after the literal string CONTENT
 * they reference. An embedded, unbalanced '"' desyncs spans.tokenize's
 * STRING regex, silently disabling every apply_to_code-guarded pass for
 * hundreds of real lines afterward (measured on the real file: 91 such
 * spans, 4,680 swallowed lines) — this fixture's trailing marker line
 * proves the desync no longer reaches past this declaration block once
 * canonicalize_ghidra_symbols runs first.
 *
 * The three DAT_10000db0 declarations (also real, immediately following
 * the illegal PTR_s_* block in the source file) exercise Class 2 once
 * Class 3 stops them from hiding inside the bogus STRING span.
 *
 * The use site below intentionally spells the symbol the way GHIDRA
 * ITSELF partially sanitizes it at use sites (different from the
 * declaration spelling) — proving canonicalize_ghidra_symbols converges
 * both spellings to the SAME identifier, not just legalizes each
 * independently.
 */

undefined *PTR_s_<?xml_version="1.0"_encoding="ut_1000011c;
undefined *PTR_s_<e:property>_<%s>%s</%s>_</e:pro_10000120;
undefined *PTR_s_</e:propertyset>_004692dc+0x12c_10000124;
int *DAT_10000db0;
undefined4 *DAT_10000db0;
void *DAT_10000db0;

int fetch_xml_decl(void)

{
  undefined *puVar1;
  puVar1 = PTR_s_<_xml_version__1_0__encoding__ut_1000011c;
  return (int)puVar1;
}

/* A later, ordinary balanced string literal — this is what the stray
 * unbalanced quote above pairs against, exactly like the real file's
 * line 732 pairs against its own line 852. Without canonicalize_ghidra_
 * symbols running first, everything between them (including MARKER
 * below) is silently absorbed into one bogus multi-line STRING span. */
char *later_string(void) { return "a later, unrelated string"; }

/* MARKER: if this line survives normalization unmasked (not silently
 * absorbed into a bogus string span), the tokenizer never desynced. */
int marker_after_illegal_block(void) { return 1; }
