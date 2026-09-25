# x86 source/profile evidence resolution

The source-assignment queue is audited against the checked-in corpus and the
pinned `xed-dec` build.  `EXTRA_OK` rows are decoded in three XED profiles:
the default profile, `-mpx`, and `-cet`.  This matters because XED disables
MPX and CET by default and otherwise reports their legacy opcode collisions
(usually `NOP`) instead of the requested IFORM.

The queue was reduced as follows:

| Initial classification | Resolved | Remaining | Evidence |
| --- | ---: | ---: | --- |
| MPX | 19 | 0 | `-mpx` decode of existing corpus witnesses |
| CET | 14 | 0 | `-cet` decode of existing corpus witnesses |
| APX LZCNT/POPCNT/TZCNT | 6 | 0 | Added exact EVEX register and memory witnesses |
| Base UD0 | 2 | 0 | Exact `PPRO_UD0_LONG` witnesses decoded with the Pentium 4 chip profile |
| Base NOP 0F18 | 3 | 0 | Exact legacy `FAT_NOP` witnesses decoded with the Pentium 4 chip profile |
| 3DNow reserved prefetch | 4 | 0 | Exact profile-aware corpus witnesses added |
| IBHF | 1 | 0 | Exact five-byte corpus witness added |

The KNM/VL rejection remains a CPU/profile legality test, but it no longer
leaves the XMM `VGETEXPPS` IFORM outside exact evidence.  A matching
Skylake-SP witness proves the same 128-bit encoding on a profile that exposes
AVX512VL, while the existing KNM row continues to verify the rejection.

FRED `ERETS`/`ERETU` and LKGS are now covered by focused ABI tests in
`tests/test_x86_fred_lkgs.c`.  The two FRED forms are intentionally exposed
as zero-explicit-operand generated descriptors: the architectural return
frame, privilege transition, and flags-pop side effects are suppressed state
and are not fabricated as ordinary cdisasm operands.  LKGS is structurally
exact for both its 16-bit register and 16-bit memory forms (forms 1589/1590),
including its long-mode and exact `CDISASM_X86_DECODE_BIT_LKGS` gate.  CPU
legality for these catalog rows remains represented by the generated profile
bitmaps; the catalog evidence ledger continues to mark semantic legality as
`structural_only` until an independent architectural legality oracle is
available.

The residual legacy queue is now represented by checked-in corpus witnesses:
`IBHF`, Pentium-4 `UD0` long register/memory forms, legacy NOP `0F 18
/4,/6,/7` forms, and `PREFETCH_RESERVED 0F 0D /4--/7`.  Modern prefetch
collisions are still retained as separate profile-sensitive cases; the
Pentium-4 decode is used only to prove the old `FAT_NOP` identities.

The authoritative per-IFORM status, source reference, successful cases,
missing cases, and profile cases are emitted in
`generated/x86_forms.tsv`.  The focused decoder check is:

```powershell
& .\_x86_audit_verify\cdisasm_opcode_corpus_tests.exe `
  .\tests\data\x86_opcodes.tsv
```
