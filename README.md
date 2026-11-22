# cdisasm

A C11 disassembler for x86, ARM, MIPS and Motorola 68000, with structured instruction data
and optional text formatting. The API is stateless and allocation-free.

- x86 16/32/64-bit, ARM A32/Thumb/A64, MIPS32/64 and M68K decoding.
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

## Build

See [build instructions](docs/BUILD.md).

CMake consumers link `cdisasm::cdisasm`.

See the [public headers](include/cdisasm/),
[coverage tools](tools/coverage/README.md) and
[generated data guide](tools/isa_codegen/README.md).
Licensed under [MIT](LICENSE); generated data has additional
[third-party notices](THIRD_PARTY_NOTICES.md).
