# cdisasm

A C11 disassembler for x86, ARM, MIPS, Motorola 68000 and PowerPC, with structured instruction data
and optional text formatting. The API is stateless and allocation-free.

- x86 16/32/64-bit, ARM A32/Thumb/A64, MIPS32/64, M68K and PowerPC decoding.
- Typed operands, register access, branch targets and CPU profiles.
- Selectable architectures and opcode families; static or shared builds.

Instruction coverage varies by architecture and CPU family.

MIPS processor profiles include classic R-series, Aptiv, M5100, I7200,
Octeon and Ingenic configurations. Optional FPU/DSP variants have distinct
profiles; I7200 profiles support nanoMIPS only. Profile sources and limits are
recorded in `tools/data/mips/cpu_profile_facts.json`.

The MIPS V3 API retains feature selections beyond the first flag word,
including the interAptiv MR2 `SAVE`, `RESTORE`, `COPYW` and `UCOPYW` family.
V3 also retains the Octeon II/III generation selectors and their exact operand
and multiplier-state contracts. Legacy V1/V2 APIs retain their common standard
subset. nanoMIPS64 supports a bounded author-source inventory of 64-bit forms
and inherited nano32 recipes with mode-specific register/address widths.
Use the register-effect limitation queries when consuming vendor, block-copy
or stack-save instructions whose implicit effects are only partly known.

M68K (`USE_ARCH_M68K`, `cdisasm_m68k.h`) covers the 68000, 68008, 68010,
68020, 68030, 68040 and 68060 (with LC/EC variants) and CPU32, the
68881/68882 FPU, and the 68030/68040/68060 and 68851 MMU instructions. Each CPU
ID maps to a feature mask; the decoders' `mode` adds features (a 68881 on a
68020, `CDISASM_M68K_FEATURE_FPU`). Decoding is table-driven from
`tools/data/m68k/m68k_opcodes.txt` (transcribed from the Motorola manuals;
`tools/isa_codegen/generate_m68k.py` writes `src/m68k/generated/m68k_forms.inc`),
and the same form table is public (`cdisasm_m68k_forms()`) for encoders. The
formatter prints Motorola syntax (`move.l (8,a0),d1`), or `%`-prefixed
registers with `CDISASM_M68K_FORMAT_REGISTER_PREFIX`. Hardware behaviour is
followed where the manual leaves bits "ignored": the 68000/68010 ignore bits
10-8 of the brief extension word, bit numbers are taken modulo 8/32, and the
EA field of register-to-register FPU operations is ignored. The 68060 omits the
instructions it traps as unimplemented (MOVEP, CMP2/CHK2, CAS2, 64-bit
MUL/DIV). `tools/validation/m68k_capstone_diff.py` compares every first
opcode word, with several extension tails, against Capstone 5.0.7 for the
68000-68060 and classifies each disagreement with the manual reference that
decides it (ctest `cdisasm_m68k_capstone_differential` when python3-capstone
is installed).

ColdFire uses the same API and form table with its own CPU IDs and features
(64-bit feature masks): ISA_A (with or without hardware divide), ISA_A+,
ISA_B (with or without USP), ISA_C, CFV4E and `CDISASM_M68K_CPU_COLDFIRE`
(every ColdFire feature); `cdisasm_m68k_cpu_from_name()` also accepts GNU's
names (`isa-a:nodiv`, `5206e`, `528x`, `547x`, ...). The MAC unit, EMAC and
the FPU are `mode` options (`CDISASM_M68K_FEATURE_MAC`, `_EMAC`, `_CFFPU`;
`cdisasm_m68k_cpu_name_options()` gives a part's units). The rows are
transcribed from the ColdFire Family Programmer's Reference Manual (CFPRM
rev. 3): restricted sizes and EA modes, the MOVE source/destination
combinations, brief extension words with long indexes only (scale 8 only with
an FPU), mov3q/mvs/mvz/sats/tas/Bcc.L, bitrev/byterev/ff1/strldsr,
remu/rems, tpf, halt/pulse, intouch, wddata/wdebug, ColdFire movec registers
(`asid`, `acr0`-`acr3`, `mmubar`, `rambar0`, `mbar`, ...), MAC/EMAC
(`mac.w d1.u,d2.l<<,(a0)&,d3,acc1`, `movclr.l`, `macsr`, `mask`,
`accext01/23`) and the double-precision FPU (no `.x`/`.p`, no transcendental
operations, no indexed or immediate FPU operands). ColdFire and
68000-family profiles never mix (CDISASM_M68K_CPU_ANY is the 68000 family).
`tools/validation/m68k_gnu_diff.py` compares every first word, with eight
extension tails, against GNU objdump (binutils-m68k-linux-gnu, run as an
external program) for 14 ColdFire machine/unit combinations; each
disagreement is a GNU behaviour listed with the CFPRM reference that decides
it (ctest `cdisasm_m68k_gnu_differential` when an m68k objdump is found;
0 unexplained differences with binutils 2.47).

## PowerPC

PowerPC (`USE_ARCH_PPC`, enabled by default; `cdisasm_ppc.h`) uses a
manual-transcribed catalog of **1,995 forms, 442 reversible aliases and 40
profiles**. The public `cdisasm_ppc_forms()` and alias/field queries provide
the same encoding descriptions to xxasm. Generated runtime tables live under
`src/ppc/generated/`; ordinary builds and installed consumers need no Python,
opcode catalogs or external assembler. CMake consumers can request the
`cdisasm_ppc` component and link `cdisasm::cdisasm_ppc`.
Version 12.17.0 adds 324 forms, 392 aliases and ten profiles to the initial
PPC release, preserving the earlier form IDs and CPU ordinals.

| Profiles | Implemented scope |
| --- | --- |
| `ppc32`, `601`, `603`, `604`, `750` | Classic integer, branch, scalar FP, memory, CR/SPR and selected system instructions; 601 POWER-compatibility forms |
| `7400`, `7410`, `7450`, `7455` (`g4` = `7450`) | Original AltiVec/VMX and profile-specific scalar/cache/TLB forms |
| `750cl`, `gekko`, `broadway` | Paired-single arithmetic and all eight quantized transfer forms; Broadway is the Gekko-compatible subset |
| `ppc64`, `970`, `power4` through `power10` | Scalar 64-bit and explicit generation inventories; 970 includes VMX, POWER6 VMX/DFP, POWER7 VSX, POWER8 crypto/HTM, POWER9 ISA 3.0 and POWER10 prefixed/MMA forms |
| `403`, `405`, `440`, `460`, `476` | Explicit PPC4xx/Book-E inventories; 403 is the 403GA baseline, 460 retains the audited 440-core subset, and 476 adds its FP/DCR/cache forms |
| `e500v1`, `e500v2` | SPE and embedded scalar FP, including e500v2's four extended-GPR64 conversions |
| `e500mc`, `e5500`, `e6500` | Conventional scalar FPU and embedded hypervisor/cache/TLB/messaging facilities; e5500/e6500 support 64-bit execution, e6500 adds AltiVec; none has SPE |
| `vle`, `e200z0`, `e200z0h`, `e200z3`, `e200z4`, `e200z6`, `e200z7` | Explicit VLE with nine SCI8 immediate families, core-specific system/context forms, and applicable SPE/EFPU; z0/z0h are VLE-only |
| `a2`, `a2qpx` | Book-E64 subset with ERAT, guest/hypervisor, messaging, cache/TLB and coprocessor forms; `a2qpx` adds scalar FP and 118 canonical QPX forms plus logical aliases |

CPU identity, execution width, byte order and enabled facilities are separate.
`mode` is 32 or 64 (zero selects 32); server, A2, e5500 and e6500 profiles
support both, while the remaining profiles support 32 only. Doubleword operations on
64-bit processors remain available in mode 32; effective addresses use the
selected width. Generic `ppc64` is a scalar baseline without VMX/VSX. Zero
decode flags mean BE; `CDISASM_PPC_DECODE_LITTLE_ENDIAN` selects LE buffer
storage. Facility enable/disable bitmaps are validated against the profile,
including unavailable facilities, unknown bits and incompatible dialects.
There is no unrestricted VMX/VSX/PS/SPE/QPX union. VLE additionally requires
`CDISASM_PPC_DECODE_VLE` and always uses BE halfwords, with 2/4-byte framing
and halfword alignment. Native PPC CPU detection currently returns unknown.

Formatting defaults to reversible preferred mnemonics and bare registers
(`li 3,8`, `lwz 3,8(1)`). `CDISASM_PPC_FORMAT_REGISTER_NAMES` selects
`r3`, `f3`, `v3`, `vs3`, `cr3` or `q3` as appropriate;
`CDISASM_PPC_FORMAT_BASE_MNEMONICS` selects canonical spellings. Structured
results retain typed operands, zero-base semantics, CR fields/bits, signed
and scaled displacements, branch targets and encoded controls. An alias that
would discard controls is not printed. Prefixed instructions preserve two
ordered words, including in LE buffers; truncation, invalid combinations and
prohibited 64-byte-boundary crossings are rejected atomically.

Development validation enumerates each form/profile/mode/endian/encoding
combination, including classic and VLE streams on dual-mode e200 cores.
`ppc_capstone_diff.py`, `ppc_llvm_diff.py` and `ppc_gnu_diff.py` compare typed
semantics and require a versioned, manual-backed KNOWN classification for
any oracle disagreement. Oracle acceptance does not establish CPU legality.
Form coverage, reserved-bit negatives, truncation tests, opcode-space sweeps
and exact xxasm round trips supplement these comparisons. Retained gap-round
validation covers **40,987 form/profile/mode/endian/encoding pairs** in 107
configurations and **491,844 exact xxasm round trips**. Each strict disassembly
oracle checked 163,948 cases: GNU had 160,376 equal / 3,572 KNOWN, LLVM
149,984 / 13,964, and Capstone 125,794 / 38,154, all with zero unexplained
outcomes. The VLE hand suite exercises 30,720 selected SCI8 encodings.
Independent external evidence covers 40,963 pairs; 24 samples remain explicitly
unverified (18 nonzero `ehpriv` operations, three `e_dnh` and three `se_dnh`).
The strict assembly generator still fails that completeness requirement;
successful catalog round trips do not replace independent evidence.
These checks validate encodings and formatting, not hardware execution or
floating-point numerical results.

Profile names describe the enumerated subset, not complete processor support.
Server support includes all 29 masked prefixed MMA forms, paired-VSR and
prefixed scalar-VSX transfers, POWER10 vector insertion/extraction and DFP
quadword conversions, POWER6 paired-FPR transfers, 970 segment bridges,
nonzero BH hints and noncanonical `pnop` suffixes. Additional server system
controls and profile-specific SPR aliases are enumerated in the catalog.
The remaining scope and evidence gaps are:

- POWER6 raw-mode `mffgpr`/`mftgpr` need a primary encoding source. Full ISA
  3.1C errata reconciliation remains incomplete; `lxvkq UIM=0` stays reserved
  under the inspected manual. Earlier server `tlbie` retains its released
  32/64-bit decoding policy despite the documented undefined SF=0 execution.
- Implementation-specific SPR names need further processor-by-processor
  audits; numeric selectors remain available.
- Later 403GCX MMU variants and the 460 auxiliary/conventional-FPU inventory
  still need a primary encoding audit; their existing baselines are unchanged.
- e200z7 includes 23 later EFPU2 forms, but full SPE2.1 integer/complex and
  combined-vector/addressing inventories, optional e200 APUs, per-SoC variants,
  complete e200/476 SPR lists and later embedded sync E variants remain partial.
- A2 `wchkall` awaits a deciding original-A2 manual page or erratum for its
  opcode disagreement. Additional A2 debug availability (including `dnh` and
  `rfdi`), `wclr` extended aliases and unaudited SPR names remain gaps.
- Original POWER/POWER2 lacks an audited primary instruction inventory.
  Xenon VMX128 and Cell SPU lack an independent oracle; SPU requires a separate
  architecture backend.
- The 24 external assembly evidence gaps above remain visible in the strict
  completeness result.

See [PowerPC details](docs/ppc.md) for profile and syntax boundaries.

## Build

See [build instructions](docs/BUILD.md).

CMake consumers link `cdisasm::cdisasm`.

See the [public headers](include/cdisasm/),
[coverage tools](tools/coverage/README.md) and
[generated data guide](tools/isa_codegen/README.md).
Licensed under [MIT](LICENSE); generated data has additional
[third-party notices](THIRD_PARTY_NOTICES.md).
