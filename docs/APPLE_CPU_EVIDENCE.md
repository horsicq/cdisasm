# Apple CPU-profile evidence policy

This file records why cdisasm's Apple private-instruction gates are narrower
than its list of Apple CPU names. It is a release input, not an assertion that
every named Apple processor has been tested locally.

Evidence was rechecked on 2026-08-26. Private-instruction support is enabled
for a named CPU profile only when a public architecture source identifies a
generation boundary or reproducible execution work covers that generation.
Numeric CPU order, product branding, a related accelerator, and Capstone's
architecture-wide `+apple` switch are not sufficient evidence. Unknown or
future binaries can deliberately select `CDISASM_ARM_CPU_ANY`.

| Family | Named-profile policy | Evidence and limitation |
| --- | --- | --- |
| Cyclone `CPM_IOACC_CTL_EL3` | Apple A7 only | LLVM/Capstone identify the system register with Cyclone. Later cores are not inferred to retain it. |
| `MUL53LO.2D` / `MUL53HI.2D` | Apple A11--A19 and M1--M5 | The reverse-engineering report identifies A11 as the introduction point. The shared later-core policy is covered by positive and negative profile tests. |
| Apple AMX private map | M1--M4 only | The maintained AMX study reports direct work on M1, M2, M3, and M4 and explicitly warns that newer chips may differ. Its current checked text does not report M5 execution. |
| `WKDMC`, `WKDMD`, `GENTER`, `GEXIT`, `AT_AS1ELX`, `SDSB` | M1--M5 only | The public opcode map establishes encodings but no reliable A- or S-series cutoff. Those series therefore remain disabled. |

The public Arm ISA extension gates used by the optional A64 opcode tranche are
separate from those private-instruction gates. They follow LLVM's checked Apple
processor feature models and aliases:

| Standard ISA feature | Accepted Apple profiles | Boundary used by cdisasm |
| --- | --- | --- |
| FEAT_LOR | A10--A19, M1--M5, S4--S10 | A10/A10X is the first accepted Apple profile |
| FEAT_LSE | A11--A19, M1--M5, S4--S10 | A11 is the first accepted Apple profile |
| FEAT_LRCPC | A12--A19, M1--M5, S4--S10 | A12/A12X/A12Z is the first accepted Apple profile |

`CDISASM_ARM_CPU_ANY` deliberately accepts all implemented standard ISA
features. Apple A4--A9 and the currently named Cortex profiles do not acquire
these capabilities by numeric ordering or branding. The source of truth for
these standard feature boundaries is LLVM's
[AArch64 processor feature table](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/AArch64/AArch64Processors.td).

The M5 cutoff was searched again rather than inferred. Apple's public M5
material describes neural acceleration in GPU cores, which is not evidence for
the undocumented CPU-issued AMX opcode map. No authoritative documentation or
reproducible M5 execution result for that private map was found, so the M5 AMX
gate stays off. Promotion requires all of the following:

1. exact M5 model and OS/build identification;
2. execution of representative load/store, extract, and arithmetic AMX forms
   with AMX state enabled by the operating system;
3. recorded instruction bytes and success/fault results;
4. a stable public report or an authoritative architecture document; and
5. positive M5 plus negative boundary tests in `test_arm_apple.c` and the ARM
   opcode corpus.

References:

- [Asahi Linux Apple proprietary instruction map](https://asahilinux.org/docs/hw/cpu/apple-instructions/)
- [corsix/amx hardware study](https://github.com/corsix/amx)
- [Capstone Apple AArch64 support change](https://github.com/capstone-engine/capstone/pull/2692)
- [A11 MUL53 investigation](https://gist.github.com/TrungNguyen1909/5b323edda9a21550a1621af506e8ce5f)
- [Apple M5 platform overview](https://developer.apple.com/videos/play/tech-talks/111432/)
- [LLVM AArch64 processor feature table](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/AArch64/AArch64Processors.td)
