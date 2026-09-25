# cdisasm

`cdisasm` is a structured disassembler suite written in C11 with no
third-party disassembly dependency. Its x86 and ARM decoders are implemented
in this directory and do not link to Capstone or another disassembly engine.
The decoder and formatter ABI is stateless, allocation-free, reentrant, and
usable from both C and C++. Normal platform runtime libraries (for example the
MSVC/UCRT runtime on Windows) remain ordinary binary dependencies of the
compiler toolchain.

The version-12 package keeps common services, every enabled decoder, and the
optional x86/ARM text layer in one library. Standard CMake
`BUILD_SHARED_LIBS` defaults to `ON`, producing one shared library; setting it
to `OFF` produces one static archive instead. Version 12.0 replaces the
by-value 64-bit decoder option argument with a pointer to the fixed-size
`cdisasm_decode_flags` bitmap. The structure is exactly 64 bytes: eight
`uint64_t` bitmap words provide 512 architecture-specific logical bits.
Passing `NULL` selects the all-zero base/default policy. This deliberate ABI
break advances the Windows runtime name to `cdisasm-12.dll` and Unix-like
SONAMEs to major 12; both fixed instruction-result layouts remain unchanged.

Version 11.28 added
`cdisasm_current_cpu()` for best-effort detection of the closest named catalog
profile visible to the calling process. Version 11.27 made Intel VMX, AMD SVM,
and Intel SMX independent runtime families while preserving every published
bitmap-0 flag value. Version 11.26 added the exact
MAP6 `VGETEXPPH`, `VGETEXPSH`, and AVX10.2 `VGETEXPBF16` EVEX forms. It also
adds four exact unpredicated pair-conversion allocations: SME2 `BFCVT` and
`BFCVTN` from two S elements to H, SME2+FP8 `BFCVT` from two H elements to B,
and (SVE2 or SME2)+FP8 `BFCVTN` from two H elements to B. All are gated by
`USE_EXTRA_OPCODES`. The PH/SH legacy route requires AVX512-FP16, with
AVX512VL also required for packed 128/256-bit PH; AVX10.1 is an independent
alternative. BF16 GETEXP requires AVX10.2. The ARM forms use independent SME2,
SVE2-or-SME2, and FP8 capability checks instead of a chronological CPU cutoff.
Other GETMANT/conversion maps and cross-instruction MOVPRFX diagnostics remain
outside this bounded release slice.
Version 9.0 added explicit formatter syntax and presentation flags.
`USE_DISASM_FORMAT` independently
controls whether the text layer is compiled in, while `USE_EXTRA_OPCODES`
controls the extended opcode families beyond the baseline decoders:

Neither decoder is exhaustively validated. With `USE_EXTRA_OPCODES=1`, the
hand-written decoders are augmented by numeric generated inventories pinned to
XED and open AARCHMRS. A generated fallback is considered only after the hand
decoder returns `UNSUPPORTED_INSTRUCTION`; it never replaces a definitive
`INVALID_INSTRUCTION` or `TRUNCATED` result. Generated ARM recognition without
exact fixed-layout operands also remains unsupported. Catalog coverage
therefore does not by itself claim complete legality or semantics.

| CMake target | Physical library | Responsibility |
| --- | --- | --- |
| `cdisasm::cdisasm` | Selected shared library or static archive | Common services, generic dispatch, enabled explicit x86/ARM APIs, and optional formatting |
| `cdisasm::cdisasm_x86` | Same physical library | Compatibility CMake proxy to `cdisasm::cdisasm` when x86 is enabled; no separate library |
| `cdisasm::cdisasm_arm` | Same physical library | Compatibility CMake proxy to `cdisasm::cdisasm` when ARM is enabled; no separate library |
| `cdisasm::cdisasm_format` | Same physical library | Compatibility CMake proxy to `cdisasm::cdisasm` when formatting and at least one architecture are enabled; no separate library |

New code includes `cdisasm_common.h`, `cdisasm_x86.h`, or `cdisasm_arm.h`
according to what it uses. The generated build configuration defines numeric
`USE_ARCH_X86`, `USE_ARCH_ARM`, `USE_DISASM_FORMAT`, and
`USE_EXTRA_OPCODES` macros as zero or one.
`cdisasm.h` always
includes the common declarations and conditionally includes each enabled
architecture header. It does not restore removed function names. The core
library provides `cdisasm_decode` and, according to its build options,
`cdisasm_x86_decode` and/or `cdisasm_arm_decode`. The generic function examines
only the architecture group in `cpu_id` and forwards the call to the
corresponding compiled-in decoder. `cdisasm_decode_flags` is the common
eight-word, 64-byte storage type. `cdisasm_x86_decode_flags` and
`cdisasm_arm_decode_flags` are layout-identical aliases, but their bit meanings
are independent. In bitmap 0, x86 bit 0 enables x87/FPU instructions, while
ARM bit 0 selects big-endian input and ARM bit 1 supplies T32 IT-block state.
The generated x86 ISA-set catalog assigns logical bits through 270 across
bitmap words 0--4. Each architecture rejects bits outside its published known
masks. The legacy singular
`cdisasm_decode_option`, `cdisasm_x86_decode_option`, and
`cdisasm_arm_decode_option` names remain aliases for one `uint64_t` bitmap
word; they are no longer decoder argument types.
The explicit x86 API also exposes `cdisasm_x86_cpu_mode_mask` and
`cdisasm_x86_cpu_decode_flag_mask` so callers can select a valid mode and
runtime family bitmap before decoding. The latter writes a caller-owned
`cdisasm_x86_decode_flags` object and reports a `cdisasm_status`.
ARM provides the analogous `cdisasm_arm_cpu_decode_flag_mask`; the generic
`cdisasm_cpu_decode_flag_mask` dispatches either query by CPU group into a
caller-owned `cdisasm_decode_flags` object.

Both decoders return stable numeric mnemonic/register IDs and typed operands.
Callers decode a byte stream by advancing by the returned instruction size.
The decoder code in `cdisasm` contains no instruction or register spelling tables.
When `USE_DISASM_FORMAT=1`, optional formatting code in `cdisasm` translates
successful results to text.
Use `cdisasm_x86_format` for x86 and `cdisasm_arm_format` for ARM;
`cdisasm_format` remains an x86-only compatibility spelling for
`cdisasm_x86_format`. The functions are declared only when their corresponding
`USE_ARCH_X86` or `USE_ARCH_ARM` macro and `USE_DISASM_FORMAT` are one. A
formatter-disabled installation still installs `cdisasm_format.h`, but a
direct include emits a focused compile-time error. This makes header discovery
identical in the build and install trees while keeping unavailable formatter
declarations impossible to use accidentally.

Version 4.0 widens `cdisasm_x86_reg_id` to 16 bits and extends the structured
result with operand access and broadcast metadata, instruction decorators, and
encoding-field offsets. All register values published before version 4 retain
their numbers, including the two reserved holes. The append-only namespace now
also represents x87 stack, MMX, XMM/YMM/ZMM, mask, bound, tile, and APX general
registers. Mask merge/zero behavior, broadcast ratios, rounding control, and
suppress-all-exceptions state remain numeric metadata; the decoder does not
construct text.

Version 4.1 keeps ABI major 4 and appends the `UD0` and `UD1` mnemonic IDs.
Structural selection now uses dense numeric descriptor tables for the primary,
`0F`, `0F38`, `0F3A`, and trailing 3DNow! selector maps. These tables contain
no instruction strings or CPU policy. CPU capabilities are accumulated while
decoding and validated once the complete instruction structure is known, so
truncated input takes precedence over an unavailable CPU feature.

`opcode_groups` remains the compact set of semantic flags (branch, call,
privileged, and similar classifications); it has not been repurposed as an
ISA-feature mask. `x86_group_ids` contains a bounded, sorted, unique list of
16-bit `cdisasm_x86_group_id` values. The append-only group catalog includes
both current and retired families, including 3DNow!, 3DNow! Extended, XOP,
FMA4, TBM, LWP, and MPX. Catalog presence does not claim complete decoder
support: successful forms are tagged with the families they actually use,
while unimplemented forms continue to report
`CDISASM_STATUS_UNSUPPORTED_INSTRUCTION`.

`cdisasm_x86_format` and `cdisasm_arm_format` turn successful structured
results into selected x86 syntax and canonical ARM syntax, respectively. They
are declared in `cdisasm_format.h` and exported by the same `cdisasm` library
as the decoders. The formatter reports the complete required length, supports a
`NULL, 0` size query, and always NUL-terminates a nonempty writable buffer even
when the text is truncated. `cdisasm_format` is retained as the x86
compatibility spelling of `cdisasm_x86_format`; version 9 adds the same flags
parameter to both names.

Version 9 adds the formatter API's 32-bit `flags` parameter immediately after
the instruction pointer to `cdisasm_x86_format`, `cdisasm_arm_format`, and the
x86 compatibility wrapper `cdisasm_format`. This width is independent of the
64-byte decoder-flags ABI. The formatter flag layout is shared by both architectures:

| Value or mask | Public define | Behavior |
| ---: | --- | --- |
| `0x00` | `CDISASM_FORMAT_SYNTAX_0`, `CDISASM_FORMAT_SYNTAX_INTEL` | Selects Intel syntax for x86 and canonical syntax for ARM. This preserves version-8.1 output. |
| `0x01` | `CDISASM_FORMAT_SYNTAX_1`, `CDISASM_FORMAT_SYNTAX_ATT` | Selects AT&T syntax for x86. ARM continues to emit canonical syntax. |
| `0x02`--`0x07` | `CDISASM_FORMAT_SYNTAX_2` through `CDISASM_FORMAT_SYNTAX_7` (`CDISASM_FORMAT_SYNTAX_MASK`) | Permanent compatibility aliases for Intel on x86 and canonical syntax on ARM; their meanings will not be reassigned. |
| `0x08` | `CDISASM_FORMAT_UPPERCASE_OPCODE` | Uppercases only the opcode/mnemonic token and its attached suffixes (plus textual x86 instruction prefixes); operands, registers, and modifiers retain canonical case. |
| `0x0f` | `CDISASM_FORMAT_KNOWN_FLAGS_MASK` | Mask of every flag bit understood by version 9.0. |
| `0x10` and above | reserved | Must be zero. Either formatter rejects any reserved bit, returns zero, and clears a nonempty writable output buffer. |

Syntax selection occupies the low three bits, so it can be combined with
`CDISASM_FORMAT_UPPERCASE_OPCODE`. Prefer the semantic x86 names
`CDISASM_FORMAT_SYNTAX_INTEL` and `CDISASM_FORMAT_SYNTAX_ATT`; pass syntax 0 to
preserve the canonical version-8.1 output. ARM accepts every syntax value from
0 through 7 as a permanent alias of its canonical output. New dialects use new
option space instead of changing any published selector.

### x86 AT&T formatting

`CDISASM_FORMAT_SYNTAX_ATT` derives AT&T text from the same structured x86
result; it does not decode the bytes again. The principal differences from
Intel output are:

| Feature | Intel syntax | AT&T syntax |
| --- | --- | --- |
| Registers | `rax`, `fs`, `zmm0 {k1}{z}` | `%rax`, `%fs`, `%zmm0{%k1}{z}` |
| Immediate data | `-0x8` | `$-0x8` |
| Operand order | destination, then sources | sources, then destination; multi-operands are reversed except fixed-order `ENTER` and `INVLPGA` |
| Memory | `qword ptr fs:[rax + rcx*4 + 0x8]` | `%fs:0x8(%rax,%rcx,4)`; no `ptr` phrase |
| Scalar width | inferred from registers or a `ptr` phrase | mnemonic suffix such as `b`, `w`, `l`, or `q` when result metadata identifies the width |
| Control target | `call 0x1015`, `call qword ptr [rax + 0x8]` | `call 0x1015`, `callq *0x8(%rax)` |
| SAE/rounding | `vaddps zmm0, zmm1, {rn-sae}` | `vaddps {rn-sae}, %zmm1, %zmm0` |

Thus `mov rax, qword ptr [rbx + rcx*4 - 0x10]` becomes
`movq -0x10(%rbx,%rcx,4), %rax`, and `imul rax, rbx, -0x8` becomes
`imulq $-0x8, %rbx, %rax`. Absolute memory is a bare address, index-only
memory uses `disp(,index,scale)`, and RIP-relative memory uses
`disp(%rip)`. Resolved PC-relative call/jump targets are direct expressions:
they have neither `$` nor `*`. Register- and memory-indirect `CALL`/`JMP` use
`*`; an indirect form receives a size suffix only when its operand carries an
unambiguous width.

The formatter emits standard width spellings such as `movzbl`, `movsbq`, and
`movslq`, the `cbtw`/`cwtl`/`cltq` and `cwtd`/`cltd`/`cqto` conversion names,
source-width suffixes for `CRC32` and `CVTSI2SS`/`CVTSI2SD`, and `l` for the
32-bit string aliases. SIMD and 3DNow! mnemonics otherwise remain unsuffixed.
AT&T `{sae}` and embedded-rounding decorators follow the mnemonic and precede
the operand list, matching GNU/LLVM assembly order.
The legacy `cdisasm_x86_format` entry point does not know the decode mode, so
direct PC-relative calls/jumps and immediate `PUSH`/`RET` keep their compatible
unsuffixed spelling. New code can pass the original 16-, 32-, or 64-bit mode to
`cdisasm_x86_format_mode`; AT&T output then emits the exact mode-dependent
suffix for direct and indirect `CALL`/`JMP`, immediate `PUSH`, `RET`, and
`RETF`. Intel output is identical through either entry point.

Combining AT&T syntax with `CDISASM_FORMAT_UPPERCASE_OPCODE` changes only
instruction-prefix and mnemonic text, including an attached size suffix:
`movq %rsp, %rbp` becomes `MOVQ %rsp, %rbp`. Register names, numbers, memory
syntax, and decorators remain in canonical lowercase.

Version 5.0 retains the version-4 x86 result layout and append-only x86 IDs,
but moves that decoder into `cdisasm_x86` and introduces the separate common
and ARM ABIs. ARM uses its own `cdisasm_arm_instruction`, name IDs, register
IDs, CPU profiles, and mode values; x86 and ARM structures are never
type-punned or multiplexed through one architecture-dependent result.

Version 5.1 adds the T32 decoder, ARM legality and address-direction flags,
`cdisasm_arm_decoder_mode_mask()`, x86 HLE prefix metadata, VEX2/VEX3
`VZEROUPPER`/`VZEROALL`, and separate data-driven ARM corpus/fuzz coverage.
These are append-only API and decoder changes; the fixed 216-byte x86 and
168-byte ARM instruction layouts are unchanged.

Version 5.2 appends Apple A4 through A19, M1 through M5, and S4 through S10
ARM CPU profiles, including product-suffix aliases, and separate
Cortex-A7-with-NEON and Cortex-A9-with-NEON profiles.
It adds table-driven legacy SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4a, and SSE4.2
decoding on x86 and an initial packed Advanced SIMD/NEON subset in A32, T32,
and A64. Vector lane information is returned numerically; neither decoder
constructs instruction text. Both fixed instruction layouts remain unchanged.

Version 5.3 adds the complete Apple-proprietary A64 instruction inventory from
the pinned Capstone 6 audit: 24 AMX mnemonics, both MUL53 forms, six Apple
system mnemonics, and the readable/writable Cyclone
`CPM_IOACC_CTL_EL3` system register. The implementation is cdisasm's own
string-free numeric descriptor table; Capstone is a comparison oracle and is
not linked, copied into, or required by any cdisasm target. Name/register IDs
and four Apple classification flags are appended while the 168-byte ARM result
layout remains unchanged.

Version 5.4 appends six exact Intel processor profiles for post-AVX-era parts
whose advertised instruction-set extensions stop at SSE4.2: Celeron G1840,
G3900, N3350, N4020, and G5900, plus Pentium Silver N6000. Each supports x86-64
but deliberately rejects AVX. In the version-5 numbering, the new profiles use
ordinals 39--44 after APX ordinal 38, preserving every earlier version-5 CPU
value.

The current version-12 source retains four explicit pre-80486 CPU-plus-x87
profiles, the complete D8--DF x87 memory/register map, and the ARMv8.0 A64
ordered/exclusive load-store family. These additions only append CPU,
mnemonic, and instruction-flag values; every previously published numeric ID
and both fixed result layouts retain their values.

Version 6.0 renames the public decoding functions to `cdisasm_x86_decode`,
`cdisasm_decode`, and `cdisasm_arm_decode`. Their version-5 names ending in
`decode2` are not declared or exported. This is a deliberate source and binary
API break. Version 6 also namespaces every CPU profile: x86 IDs contain
`CDISASM_CPU_GROUP_X86` (`0x00010000`) and ARM IDs contain
`CDISASM_CPU_GROUP_ARM` (`0x00020000`) in their upper 16 bits, while the
version-5 profile number remains the low-16-bit ordinal. Result layouts and
non-CPU numeric IDs remain unchanged, and named profiles retain their decoder
behavior. Windows runtime filenames consequently use the `-6` ABI-major suffix.

Version 7.0 moves `cdisasm_decode` from the x86 DLL to the common DLL and turns
it into a CPU-group dispatcher. Its result parameter is `void *`: callers pass
`cdisasm_instruction *` for an x86 CPU ID and
`cdisasm_arm_instruction *` for an ARM CPU ID. The dispatcher itself validates
only the upper-bit CPU group; the selected architecture decoder performs all
CPU-ordinal, mode, input, option, and instruction validation. An unknown group
or a group disabled by `USE_ARCH_X86` or `USE_ARCH_ARM` returns zero without
modifying the supplied result object. The explicit architecture entry points
and both fixed result layouts are unchanged. Moving the exported symbol and
generalizing its pointer type are deliberate ABI changes, so Windows runtime
filenames use the `-7` major suffix.

For new generic callers, `cdisasm_instruction_size(cpu_id)` returns the exact
result-object size selected by the CPU group, and `cdisasm_decode_checked`
takes that size beside the `void *` result. It rejects an unknown or disabled
group, `NULL`, or a non-exact size without reading or writing the object. This
removes the most common cross-architecture buffer mistake while preserving the
unchecked `cdisasm_decode` API. Version-8 and older generic callers must
rebuild for the 64-bit decode-option parameter introduced in version 9.
Explicitly typed code can
continue to call `cdisasm_x86_decode` or `cdisasm_arm_decode` directly.

Version 8.0 folds both architecture decoder DLLs into `cdisasm`. A full build
therefore installs only `cdisasm-8.dll` and the optional
`cdisasm_format-8.dll`. The explicit x86 and ARM symbols
move into the core import library without changing their signatures, IDs, or
fixed result layouts. Enabled packages retain `cdisasm::cdisasm_x86` and
`cdisasm::cdisasm_arm` as compatibility CMake proxies to
`cdisasm::cdisasm`, but they do not create `cdisasm_x86` or `cdisasm_arm`
runtime/import libraries. This symbol-ownership and deployment change advances
the ABI-major DLL suffix to `-8`.

Version 8.1 keeps that two-DLL maximum and adds ARM formatting to the optional
formatter library. A build with either decoder creates `cdisasm_format-8.dll`;
a common-only build does not. The new architecture-explicit entry points are
`cdisasm_x86_format` and `cdisasm_arm_format`, while `cdisasm_format` remains
the x86 compatibility wrapper. The decoder result layouts and ABI-major DLL
suffix do not change.

Version 9.0 adds the shared 32-bit formatter `flags` argument immediately after
each formatter instruction pointer. For x86, syntax 0 is Intel and syntax 1 is
AT&T; syntax values 2 through 7 are permanent Intel compatibility aliases. All
eight selectors are permanent aliases of canonical ARM output. Bit `0x08` uppercases only the
opcode/mnemonic text. Bits `0x10` and above are reserved and rejected. Because
all three formatter function signatures change, this is a deliberate ABI
break. Version 9 also moves the optional formatter exports into `cdisasm` and
adds the default-on `USE_DISASM_FORMAT` build option. The standard
`BUILD_SHARED_LIBS` option defaults to `ON`, yielding the single
`cdisasm-9.dll` runtime on Windows, while `OFF` yields one static archive.
`cdisasm::cdisasm_format` is only an interface compatibility target and creates
no additional library. Decoder result layouts remain unchanged. The generic
and explicit x86 decode-option parameters widen to the 64-bit
`cdisasm_decode_option`/`cdisasm_x86_decode_option` ABI; explicit ARM decoding
retains its 32-bit option word. Version 9 also adds the default-on `USE_EXTRA_OPCODES`
extension tranche. Existing numeric IDs retain their values; x87 names, x86
VEX names 610--669, ARMv8.0 atomic names, and optional ARM LSE/LOR/RCpc names
132--216 are append-only additions in their architecture namespaces.

Version 10.0 widens `cdisasm_arm_decode_option` and the explicit
`cdisasm_arm_decode` parameter to the same 64-bit word used by generic and x86
decoding. This is an explicit-decoder ABI break, so direct ARM callers must
rebuild and relink; the Windows runtime becomes `cdisasm-10.dll` and Unix-like
SONAMEs use major 10. Numeric IDs and both result layouts remain unchanged.

Version 10.1 appends x86 name IDs 743--839, the independent `AMX_FP16` group
ID 93, and the Granite Rapids CPU profile at ordinal 49. Its bounded optional
x86 expansion completes the 60-name FMA3 and 20-name FMA4 mnemonic matrices,
adds XOP variable shifts and 256-bit `VPCMOV`, widens VAES/VPCLMUL and EVEX
arithmetic coverage, and adds `TDPFP16PS`, `JMPABS`, and twelve CET
shadow-stack mnemonics. It does not claim complete VEX, XOP, EVEX, AVX-512,
AVX10, APX, AMX, crypto, or system-map coverage.

Version 10.2 appends the WAITPKG names `UMONITOR` (840), `UMWAIT` (841), and
`TPAUSE` (842), plus independent group ID 94. It also realizes all 60 existing
FMA3 names through EVEX: 36 packed PS/PD forms at 128, 256, and 512 bits and 24
scalar SS/SD forms, with their legal masking, broadcast, and embedded
rounding/SAE behavior and distinct AVX-512/AVX10 admission. This expands
implemented encodings without adding a second spelling catalog or changing
either result layout. Coverage remains bounded; the unlisted modern maps are
still unsupported.

Version 11.0 appends x86 name IDs 843--993, group IDs 95--107, and the
Arrow Lake and Diamond Rapids CPU profiles at ordinals 50 and 51. The optional
x86 tranche completes the release's cataloged AMD XOP map-8/map-9 and `/is4`
families; adds SHA-512, SM3, and SM4 vector crypto; fills common VEX
arithmetic/conversion gaps; and adds cache-management, direct-store, RDPID,
SERIALIZE, and WBNOINVD system forms. Its bounded next-generation slice adds
AMX-COMPLEX, AMX-FP8, AMX-MOVRS, and AMX-to-vector row operations; four
AVX10.2 BF16 arithmetic forms; and broader APX REX2, NDD/NF ALU, CET, and
MOVDIR handling.

The packaged ABI major for that release was 11: Windows used
`cdisasm-11.dll`, Unix-like SONAMEs used major 11, and older-major binaries had
to rebuild and relink. Decoder options remained 64-bit in version 11;
`CDISASM_INSTRUCTION_SIZE` pins the current x86 structured result at 248 bytes.

The same release implements the complete classic 51-mnemonic VEX K-mask
family represented by IDs 943--993. Its 65 exact descriptor forms cover the
AVX-512F word foundation and the AVX-512DQ/AVX-512BW byte, dword, and qword
extensions, including KMOV register/memory/GPR directions and width aliases.
Abstract AVX10/APX profiles admit these encodings through AVX10.1 rather than
requiring a legacy AVX-512F profile; physical AVX-512 profiles retain their
most-specific AVX-512F/DQ/BW gates. This is not a claim of complete EVEX,
AVX-512, AVX10, APX, or AMX coverage.

Version 11.1 appends x86 name IDs 994--1001 for the complete packed-integer
EVEX compare-to-mask family: `VPCMPB/W/D/Q` and
`VPCMPUB/UW/UD/UQ`. The descriptor route covers XMM, YMM, and ZMM sources,
K-register destinations and merge masks, full-width memory operands,
dword/qword broadcast, compressed displacement, and the predicate imm8.
Legacy profiles require AVX-512F, plus AVX-512VL below 512 bits and AVX-512BW
for byte/word elements. Abstract AVX10/APX profiles use AVX10.1 as a mutually
alternative route and never acquire fabricated legacy AVX-512F/BW/VL
requirements.

The same minor release appends ARM name IDs 332--341 and completes the
15-operation SVE predicate-logical submap: `AND/ANDS`, `BIC/BICS`, `EOR/EORS`,
`NAND/NANDS`, `NOR/NORS`, `ORR/ORRS`, `ORN/ORNS`, and `SEL`. Existing IDs are
reused where a spelling already existed; the ten new IDs end at `SEL` (341).
The result retains typed predicate operands, zeroing versus select-guard
semantics, flag-setting metadata, SVE CPU validation, endian parity, and the
extra-opcode build gate. Version 11.1 changes neither structured result layout
nor the ABI-major library suffix.

Version 11.2 reuses the four existing `VPMINSW`, `VPMINUB`, `VPMAXSW`, and
`VPMAXUB` IDs and appends x86 name IDs 1002--1013 to complete the 16-mnemonic
EVEX packed signed/unsigned MIN/MAX class. Its 48 register forms cover XMM,
YMM, and ZMM widths; all forms also accept memory, with legal dword/qword
broadcast. AVX-512F/BW/VL and AVX10.1 remain alternative CPU/runtime routes.
The same release reuses ARM `ADD`/`SUB` and appends IDs 342--347 for
`SQADD`, `UQADD`, `SQSUB`, `UQSUB`, `ADDPT`, and `SUBPT`, completing the
26 valid operation/element-width combinations in the selected A64 SVE
unpredicated integer-arithmetic class. `ADDPT`/`SUBPT` are restricted to
64-bit elements and strictly require SVE plus CPA. The other six operations
follow Arm's SVE-or-SME admission rule, including Apple A18/M4. Version 11.2
does not change either structured-result layout or the ABI-major suffix.

Version 11.3 reuses `VPMULLW`, `VPMULUDQ`, and `VPMADDWD` and appends x86
name IDs 1014--1020 to complete the ten-mnemonic classic EVEX packed-integer
multiply/multiply-add class. Its 30 register shapes cover XMM, YMM, and ZMM,
with memory, masking/zeroing, compressed displacement, and legal dword or
qword broadcast forms. The same release appends ARM IDs 348--353 for `ZIP1`,
`ZIP2`, `UZP1`, `UZP2`, `TRN1`, and `TRN2`, completing all 24 byte,
halfword, word, and doubleword forms in that SVE vector-permute class and
rejecting its eight unallocated selectors structurally. The append-only A64FX
CPU profile at ARM ordinal 38 provides an A64+SVE, non-SME target for exact
SVE-or-SME policy tests. Version 11.3 changes neither result layout nor the
ABI-major suffix.

Version 11.4 reuses the existing x86 IDs for `VPADDB/W/D/Q` and
`VPSUBB/W/D/Q` and realizes all 60 modular EVEX register, full-memory, and
legal dword/qword broadcast shapes. Legacy AVX-512F/BW/VL and abstract
AVX10.1 admission remain alternative CPU/runtime routes. The same release
appends ARM IDs 354--356 for `TBL`, `TBX`, and `TBXQ` and completes all 16
byte/halfword/word/doubleword forms in the selected SVE table-lookup controls.
Four adjacent `MOV zN.<T>, Wn/Xn` controls reuse `MOV`. `TBL`, `TBX`, and `MOV` follow
their exact SVE/SVE2-or-SME alternatives. `TBXQ` requires SVE2.1 or SME2.1,
which is conservatively available only through `CDISASM_ARM_CPU_ANY` until a
named profile is supported by authoritative evidence. Adjacent selector-14
encodings belong to other SVE classes and remain unowned/unsupported; the
unallocated selector-15 region is rejected structurally. Version 11.4 changes
neither result layout nor the ABI-major suffix.

Version 11.5 appends x86 IDs 1021--1028 for `VPADDSB`, `VPADDSW`,
`VPADDUSB`, `VPADDUSW`, `VPSUBSB`, `VPSUBSW`, `VPSUBUSB`, and
`VPSUBUSW`. The complete saturating family covers VEX.128/256 register and
full-width memory sources plus EVEX.128/256/512 register and full-width memory
sources. VEX.128 uses AVX, VEX.256 uses AVX2, and EVEX uses mutually
alternative AVX-512F/BW/VL or AVX10.1 CPU/runtime routes. VEX and EVEX W are
ignored, EVEX masking/zeroing is represented, and EVEX broadcast is invalid
for every byte/word member. The same release appends ARM `TBLQ` at ID 357 and
owns the exact `(word & 0xff20fc00) == 0x4400f800` class: all 131,072
combinations of four element widths and three five-bit Z-register fields are
valid. `TBLQ` writes its destination, reads a singleton table list and index,
and requires SVE2.1 or SME2.1; no current named CPU profile claims either 2.1
capability. Version 11.5 changes neither fixed result layout nor the ABI-major
suffix.

Version 11.6 appends x86 IDs 1029--1036 for `VPANDD/Q`, `VPANDND/Q`,
`VPORD/Q`, and `VPXORD/Q`. These eight names complete their EVEX.66.0F class
at XMM, YMM, and ZMM widths with register and full-width memory sources,
dword/qword broadcast, merge/zero masking, compressed displacement, and exact
AVX-512F/VL versus AVX10.1 admission. Existing `VPAVGB` (663) and `VPAVGW`
(664) now cover their complete EVEX byte/word average class at all three vector
lengths, without broadcast. Both classes own their exact APX P0.B4 register and
EGPR-memory forms while leaving unrelated P0.B4 space unclaimed.

The same release appends ARM IDs 358--364 for `SUBR`, `SABD`, `UABD`,
`SMULH`, `UMULH`, `SDIVR`, and `UDIVR`. Together with existing names they
complete 74 allocated operation/width pairs in the 22-operation destructive
predicated SVE integer arithmetic/logical class. It also reuses `ZIP1/2`,
`UZP1/2`, and `TRN1/2` for all 42 allocated fixed-width A64 Advanced SIMD
arrangements. Version 11.6 changes neither fixed result layout nor the
ABI-major suffix.

Version 11.7 appends x86 IDs 1037--1042 for `VPSLLVD`, `VPSLLVQ`,
`VPSRLVD`, `VPSRLVQ`, `VPSRAVD`, and `VPSRAVQ`. The complete dword/qword
tranche covers
VEX.128/256 where architecturally allocated and EVEX.128/256/512 register,
full-memory, and legal dword/qword broadcast forms. EVEX masks, compressed
displacement, AVX-512-versus-AVX10 admission, and exact APX P0.B4/U0 ownership
remain numeric metadata and independent gates.

The same release appends ARM IDs 365--377 for `CLS`, `CNOT`, `NOT`,
`SXTB`, `SXTH`, `SXTW`, `UXTB`, `UXTH`, `UXTW`, `REVB`, `REVH`, `REVW`,
and `RBIT`. Together with existing `ABS`, `NEG`, `CLZ`, `CNT`, `FABS`, and
`FNEG`, they complete three exact predicated SVE unary classifiers containing
917,504 allocated and 393,216 reserved words. Merge forms admit SVE or SME;
zeroing forms require SVE2p2 or SME2p2. Version 11.7 changes neither fixed
result layout nor the ABI-major suffix.

Version 11.8 appends x86 IDs 1043--1045 for `VPSLLVW`, `VPSRLVW`, and
`VPSRAVW`. Their EVEX.66.0F38.W1 opcodes `12`, `10`, and `11` cover
XMM/YMM/ZMM register and full-width memory sources, merge/zero masks, compressed
displacement, exact AVX-512F/BW/VL or alternative AVX10.1 admission, and exact
APX P0.B4 plus U0/X4 ownership; broadcast is invalid. This completes the
remaining word forms adjacent to the dword/qword forms added in 11.7.

The same release appends ARM IDs 378--380 for `ASRR`, `LSRR`, and `LSLR`,
while reusing `ASR`, `LSR`, and `LSL`. The exact predicated vector-shift
classifier `(word & 0xff30e000) == 0x04108000` contains 270,336 allocated and
253,952 reserved words. Direct and reverse forms cover B/H/S/D elements; the
wide-count direct forms cover B/H/S destinations with a `.d` count source.
Allocated forms admit SVE or SME. Version 11.8 changes neither fixed result
layout nor the ABI-major suffix.

The release adds 36 x86 opcode-corpus rows and 21 independently reachable
one-vector word-shift seeds, plus 17 ARM opcode-corpus rows and two reviewed
predicated-vector-shift seeds.
The separate reviewed `vex_modern_crypto.hex` seed covers the existing
vector-crypto decoder path.

Version 11.9 appends x86 IDs 1046--1049 for `VPROLVD`, `VPROLVQ`,
`VPRORVD`, and `VPRORVQ`. Their EVEX.66.0F38 opcodes `15` and `14`, with W
selecting dword or qword elements, cover XMM/YMM/ZMM register, full-memory,
and legal dword/qword broadcast sources. Masks, zeroing, compressed
displacement, AVX-512F plus AVX-512VL below 512 bits or alternative AVX10.1
admission, and exact APX P0.B4/U0/X4 ownership remain independent numeric
metadata. LL=3, zeroing with `k0`, and other reserved controls are invalid;
complete valid forms in an extra-opcodes-OFF build are unsupported, and short
forms retain truncation precedence.

The same release appends ARM IDs 381--386 for `ASRD`, `SQSHL`, `UQSHL`,
`SRSHR`, `URSHR`, and `SQSHLU`, while reusing `ASR`, `LSR`, and `LSL`. The
exact A64 classifier `(word & 0xff30e000) == 0x04008000` structurally owns all
524,288 words: 276,480 are allocated and 247,808 are reserved. The immediate
is derived from the encoded element-width/control field rather than stored as
text. `ASR`, `LSR`, `LSL`, and `ASRD` admit SVE or SME; the saturating and
rounding SVE2 operations admit SVE2 or SME. Legality is resolved before feature
and build gates, so reserved words are invalid, valid OFF-build words are
unsupported, and incomplete words are truncated.

Version 11.9 adds 40 x86 opcode-corpus rows and seven independently reachable
one-vector rotate seeds, plus 18 ARM opcode-corpus rows and two immediate-shift
seeds.

Version 11.10 appends x86 IDs 1050--1053 for `VPROLD`, `VPROLQ`, `VPRORD`,
and `VPRORQ`. EVEX.66.0F opcode `72` uses ModRM `/0` for right rotate and `/1`
for left rotate, W for dword/qword elements, EVEX.vvvv/V' for the destination,
and an explicit imm8 count. XMM/YMM/ZMM register, full-memory, scalar-broadcast,
mask/zero, compressed-displacement, AVX-512F/VL or alternative AVX10.1, and
exact APX P0.B4/U0/X4 routes are represented numerically. Adjacent allocated
shift controls `/2` W0, `/4` W0/W1, and `/6` W0 remain unsupported. Controls
`/2` W1 and `/6` W1 plus every `/3`, `/5`, and `/7` control are reserved and
invalid. Both classifications consume imm8 first so incomplete input retains
truncation precedence.

The same release appends ARM IDs 387--396 and owns the exact A64 classifier
`(word & 0xff200000) == 0x24000000`. Its 8,388,608 words split into 7,077,888
allocated and 1,310,720 reserved encodings. All sixteen controls allocate
B/H/S; the six same-width controls also allocate D, while wide forms use a
`.d` second source and reject a D destination. Results contain a written typed
predicate, zeroing governing predicate, two read vector sources, scalable and
predicated flags, and `SETS_FLAGS` because these compares update NZCV. Valid
forms require A64 plus SVE or SME; reserved, OFF-build, and incomplete forms
remain independently invalid, unsupported, and truncated.

Version 11.10 adds 43 x86 opcode-corpus rows and seven reviewed immediate-rotate
seeds, plus 27 ARM rows and two integer-compare seeds.

Version 11.11 appends x86 IDs 1054--1057 for `VPSRLD`, `VPSRAD`, `VPSRAQ`,
and `VPSLLD`. These are the remaining allocated EVEX.66.0F opcode-`72`
immediate shift controls: `/2` W0, `/4` W0, `/4` W1, and `/6` W0. Together
with the version-11.10 rotates, the complete extension/W matrix is now decoded:
W0 `/0`--`/2`, `/4`, and `/6` select `VPRORD`, `VPROLD`, `VPSRLD`, `VPSRAD`,
and `VPSLLD`; W1 `/0`, `/1`, and `/4` select `VPRORQ`, `VPROLQ`, and
`VPSRAQ`. W0/W1 `/3`, `/5`, `/7`, plus W1 `/2` and `/6`, remain reserved and
invalid. All XMM/YMM/ZMM lengths, register and full-memory operands, legal
scalar broadcasts, masks, compressed displacement, AVX-512F/VL or alternative
AVX10.1 admission, and exact APX P0.B4/U0/X4 routes retain numeric metadata.

The same release completes both exact A64 SVE integer compare-with-immediate
envelopes without adding ARM mnemonic IDs. The signed envelope
`(word & 0xff204000) == 0x25000000` accepts `#-16` through `#15` for
`CMPGE`, `CMPGT`, `CMPLT`, `CMPLE`, `CMPEQ`, and `CMPNE`; its 4,194,304 words
split into 3,145,728 allocated and 1,048,576 reserved encodings. The unsigned
envelope `(word & 0xff200000) == 0x24200000` accepts `#0` through `#127` for
`CMPHS`, `CMPHI`, `CMPLO`, and `CMPLS`; all 8,388,608 words are allocated.
Every B/H/S/D form writes `Pd`, reads `Pg/z` and `Zn`, stores the immediate
numerically, and records scalable, predicated, and `SETS_FLAGS` metadata for
the NZCV update. Valid forms require A64 plus SVE or SME.

Version 11.11 adds 32 x86 opcode-corpus rows and six reviewed immediate-shift
seeds, plus 16 ARM rows and three signed/unsigned/reserved compare-immediate
seeds.

Version 11.12 appends x86 IDs 1058--1064 for `VPSRLW`, `VPSRAW`, `VPSLLW`,
`VPSRLQ`, `VPSRLDQ`, `VPSLLQ`, and `VPSLLDQ`. EVEX.66.0F opcode `71` owns
WIG `/2`, `/4`, and `/6` as word logical-right, arithmetic-right, and left
shifts. Opcode `73` owns W1 `/2` and `/6` as qword logical-right and left
shifts, and WIG `/3` and `/7` as byte-lane `VPSRLDQ` and `VPSLLDQ`. The word
and byte-lane classes require AVX-512BW; the qword class requires AVX-512F.
XMM/YMM/ZMM, register/full-memory, compressed-displacement, exact masking and
broadcast rules, imm8 consumption, and the owned APX P0.B4/U0/X4 routes remain
numeric metadata. All other extension/W controls in these two opcodes are
reserved and invalid, and incomplete owned encodings remain truncated.

The same release appends ARM IDs 397--402 for `FCMEQ`, `FCMNE`, `FCMGE`,
`FCMGT`, `FCMLE`, and `FCMLT`. The exact A64 classifier
`(word & 0xff3ce000) == 0x65102000` owns 131,072 words. H/S/D forms allocate
73,728 words across operation controls 0--4 and 6; B forms and controls 5/7
are the remaining 57,344 reserved words. Results write typed `Pd`, read
zeroing `Pg/z` in P0--P7 and typed `Zn`, and store `#0.0` as numeric immediate
metadata. They are scalable, predicated floating-point operations but do not
set NZCV. Valid forms require A64 plus SVE or SME.

Version 11.12 adds seven x86 opcode-corpus rows and three reviewed immediate-
shift-group seeds, plus 14 ARM rows and two floating-compare-zero seeds.

Version 11.13 appends x86 IDs 1065--1076 for `VPSHLDW`, `VPSHLDD`, `VPSHLDQ`,
`VPSHLDVW`, `VPSHLDVD`, `VPSHLDVQ`, `VPSHRDW`, `VPSHRDD`, `VPSHRDQ`,
`VPSHRDVW`, `VPSHRDVD`, and `VPSHRDVQ`. With mandatory `66`, EVEX map 3 owns
the six immediate forms at opcodes `70`--`73`, while map 2 owns the matching
six variable-count forms. Across both maps and both W values, the exact 16
map/opcode/W controls split into 12 allocated and four reserved word/W0
controls; every allocated map-3 control accepts every imm8. XMM/YMM/ZMM,
masking, register/full-memory, legal dword/qword broadcast, compressed disp8,
AVX-512F plus AVX512VBMI2 (and AVX512VL below 512 bits) or alternative
AVX10.1 admission are preserved. Exact 64-bit APX-F P0.B4 register/EGPR-memory
and U0 no-SIB/X4 memory routes are owned; U0 register forms remain reserved.

The same release appends ARM IDs 403--405 for `FCMUO`, `FACGE`, and `FACGT`,
while reusing `FCMGE`, `FCMGT`, `FCMEQ`, and `FCMNE`. The exact A64 classifier
`(word & 0xff204000) == 0x65004000` owns 4,194,304 words. Seven H/S/D operation
controls allocate 2,752,512 words; byte width and operation six account for
1,441,792 reserved words. Results write typed `Pd`, read zeroing `Pg/z` and two
typed Z sources, set scalable/predicated/floating-point metadata without NZCV,
and require SVE or SME. Version 11.13 adds 27 x86 and 17 ARM corpus rows plus
six reviewed x86 seeds and four reviewed ARM seeds.

Version 11.14 appends x86 IDs 1077--1084 for `VPCOMPRESSB`, `VPCOMPRESSW`,
`VPCOMPRESSD`, `VPCOMPRESSQ`, `VPEXPANDB`, `VPEXPANDW`, `VPEXPANDD`, and
`VPEXPANDQ`. The exact mandatory-`66` EVEX map-2 rows own opcodes `62`, `63`,
`89`, and `8B` at both W values and all three vector lengths. Byte/word forms
require AVX512VBMI2; dword/qword forms require AVX512F; sub-512-bit forms also
require AVX512VL, with AVX10.1 as an alternative encoding foundation. The
decoder keeps compress memory destinations distinct from expand memory
sources, models merge/zero masking exactly, uses element-sized GSCAT disp8
scaling, rejects EVEX.b and reserved controls, and preserves the reviewed
64-bit APX-F B4/U0 memory-addressing routes.

The release also appends `VPOPCNTB` (1085), `VPOPCNTW` (1086),
`VPOPCNTQ` (1087), and `VPSHUFBITQMB` (1088), while reusing the established
`VPOPCNTD` ID. These exact EVEX map-2 rows distinguish BITALG from
VPOPCNTDQ, preserve byte/word versus dword/qword feature gates, allow
broadcast only for dword/qword memory popcount, and model the mask-register
destination of `VPSHUFBITQMB`. The expanded 64-bit runtime mask adds
descriptor-backed selectors through bit 59 without assigning bits to
catalog-only opcode groups.

The same release appends ARM IDs 406--414 for `FSUBR`, `FMAXNM`, `FMINNM`,
`FMAX`, `FMIN`, `FABD`, `FSCALE`, `FMULX`, and `FDIVR`, while reusing the
established `FADD`, `FSUB`, `FMUL`, and `FDIV` IDs. The exact A64 destructive
predicated FP binary class owns H/S/D operation controls 0--13 except reserved
control 11; byte width, separately featured B16B16 forms, and newer FAMINMAX
controls remain outside this classifier. Results read/write typed `Zdn`, read
merging `Pg/m` and typed `Zm`, and require SVE or SME.

Version 11.15 appends x86 IDs 1089--1092 for `VPCONFLICTD`, `VPCONFLICTQ`,
`VPLZCNTD`, and `VPLZCNTQ`. These mandatory-`66` EVEX map-2 instructions own
opcodes `C4` and `44`, with W selecting dword or qword elements. The exact
slice covers XMM/YMM/ZMM register and full-vector memory sources, legal scalar
broadcast, merge/zero masking, compressed displacement, and the reviewed APX
P0.B4/U0 extension routes. It requires AVX512F plus AVX512CD (and AVX512VL
below 512 bits), or AVX10.1 as the alternative vector foundation. Runtime bit
60 is the narrow `CDISASM_X86_DECODE_FLAG_AVX512_CD` selector; the original
`AVX512` bit remains its compatibility umbrella.

The same release appends ARM IDs 415--419 for `FADDV`, `FMAXNMV`, `FMINNMV`,
`FMAXV`, and `FMINV`. The exact A64 classifier
`(word & 0xff38e000) == 0x65002000` owns 262,144 words. H/S/D element sizes
and operation selectors zero and four through seven allocate 122,880 words;
byte width and selectors one through three are the remaining 139,264 reserved
words. Results write a scalar H/S/D register, read an unqualified governing
P0--P7 predicate and typed scalable Z source, and require SVE or SME.

Version 11.16 appends x86 IDs 1093 and 1094 for `VPBROADCASTMB2Q` and
`VPBROADCASTMW2D`. The exact mandatory-`F3` EVEX map-2 rows use opcodes `2A`
at W=1 and `3A` at W=0. They accept XMM/YMM/ZMM destinations and a K0--K7
source only: memory, writemasking, zeroing, broadcast decorators, LL=3, and
noncanonical vvvv/V' controls are rejected. The AVX-512 route requires
AVX512F plus AVX512CD and AVX512VL below 512 bits; AVX10.1 is the alternative
foundation. Reviewed APX P0.B4 forms require 64-bit APX-F. The existing
`CDISASM_X86_DECODE_FLAG_AVX512_CD` bit 60 selects both rows, completing all
six AVX-512CD mnemonics without consuming another runtime-mask bit.

The same release appends ARM ID 420 for `FADDA`. Its exact A64 SVE classifier
`(word & 0xff3fe000) == 0x65182000` owns 32,768 words: 24,576 H/S/D forms are
allocated and the 8,192 byte-width forms are reserved. Results preserve the
architectural duplicate scalar accumulator as read/write `Vdn`, read `Pg`,
read `Vdn` again, and read typed `Zm`. Unlike the neighboring fast reductions,
`FADDA` requires FEAT_SVE specifically; an SME-only profile is not sufficient.

Version 11.17 completes the mandatory-`66`, W=0 EVEX map-2 AVX-512 VNNI
dot-product row at opcodes `50`--`53`. The existing `VPDPBUSD` ID 715 is
retained and IDs 1095--1097 append `VPDPBUSDS`, `VPDPWSSD`, and `VPDPWSSDS`.
All four operations accept XMM/YMM/ZMM register or full-tuple memory sources,
legal `m32bcst`, merge/zero writemasks, compressed displacement, and a
read/write accumulator destination. Admission independently requires
AVX512F+AVX512VNNI(+VL), or AVX10.1, plus the existing VNNI runtime selector;
reviewed 64-bit APX P0.B4/U0 address extensions remain separately gated.

The same release appends ARM IDs 421--428 for `FRINTN`, `FRINTP`, `FRINTM`,
`FRINTZ`, `FRINTA`, `FRINTX`, `FRINTI`, and `FRECPX`, while reusing `FSQRT`
ID 234. Four disjoint masks own the exact A64 SVE predicated FP-unary
envelope: merging controls 0--7 and 12--13 and their newer zeroing forms.
Across both predication variants, 442,368 H/S/D words are allocated and
212,992 byte-width or operation-5 words are reserved. Merging forms require
SVE or SME; zeroing forms require SVE2p2 or SME2p2. Adjacent operation
controls are left unowned rather than guessed.

Version 11.18 completes the classic EVEX AVX512_VBMI byte
permute/multishift slice. It reuses `VPERMB` ID 714 and appends `VPERMI2B`
(1098), `VPERMT2B` (1099), and `VPMULTISHIFTQB` (1100). The exact
mandatory-`66` map-2 rows at opcodes `75`, `7D`, `83`, and `8D` preserve
XMM/YMM/ZMM lengths, merge/zero masks, Full-tuple displacement scaling, and
the `VPMULTISHIFTQB`-only `m64bcst` form. AVX-512 admission independently
requires AVX512F, AVX512VBMI, and AVX512VL below 512 bits; AVX10.1 is the
alternative vector foundation. Reviewed 64-bit APX P0.B4/U0 address routes
remain separately gated. At the 11.18 boundary, the allocated W=1
`VPERMI2W`/`VPERMT2W`/`VPERMW` siblings were consumed as unsupported rather
than misclassified as reserved; version 11.19 implements them.
These opcode, tuple, and feature boundaries follow Intel's checked-in
[XED VBMI definitions](https://github.com/intelxed/xed/blob/main/datafiles/avx512vbmi/vbmi-isa.xed.txt).

The same release appends ARM IDs 429 and 430 for `FRECPE` and `FRSQRTE`.
The exact A64 classifier `(word & 0xff3efc00) == 0x650e3000` owns 8,192
words: 6,144 H/S/D forms are allocated and 2,048 byte-width forms are
reserved. Results write typed `Zd`, read typed `Zn`, and require SVE or SME.
The class is unpredicated and carries only scalable-vector and floating-point
instruction flags.
The mask, operation selector, and SVE-or-SME gate follow Arm's official
[A64 XML package](https://developer.arm.com/-/cdn-downloads/permalink/Exploration-Tools-A64-ISA/ISA_A64/ISA_A64_xml_A_profile-2025-12.tar.gz).

Version 11.19 appends x86 `VPERMI2W` (1101), `VPERMT2W` (1102), and `VPERMW`
(1103), bringing `CDISASM_X86_NAME_COUNT` to 1104. These W=1 mandatory-`66`
map-2 rows reuse the exact vector-length, mask, Full-tuple memory, compressed-
displacement, APX P0.B4/U0, invalid-decorator, and truncation policy of the
adjacent byte-permute class, but do not permit broadcast. Legacy processors use
the AVX512F+AVX512BW(+VL) capability route and the
`CDISASM_X86_DECODE_FLAG_AVX512_BW` selector. AVX10.1 is a separate foundation
selected with `CDISASM_X86_DECODE_FLAG_AVX10`; it does not synthesize a legacy
AVX512BW result group or runtime selector.
The legacy opcode, tuple, and operand boundaries follow Intel's checked-in
[XED Skylake-X definitions](https://github.com/intelxed/xed/blob/main/datafiles/avx512-skx/skx-isa.xed.txt).

The same release reuses ARM `FRECPE` (429) and `FRSQRTE` (430) for the exact
fixed-width Advanced SIMD scalar and vector union. Across both operations and
all register pairs, 18,432 words are owned: 16,384 scalar H/S/D and vector
4H/8H/2S/4S/2D forms are allocated, while the 2,048 one-lane-D vector controls
are reserved. All valid forms require A64 plus Advanced SIMD; half-precision
forms independently require FP16. The catalog therefore remains at 431 ARM
names. The masks and reserved controls follow Arm's official
[A64 XML package](https://developer.arm.com/-/cdn-downloads/permalink/Exploration-Tools-A64-ISA/ISA_A64/ISA_A64_xml_A_profile-2025-12.tar.gz).

Version 11.20 reuses x86 `VPDPBUSD` (715), `VPDPBUSDS` (1095), `VPDPWSSD`
(1096), and `VPDPWSSDS` (1097) for their exact classic VEX AVX-VNNI forms.
The mandatory-`66` VEX map-2 opcodes `50`--`53` accept 128- and 256-bit
register or full-width memory sources, write and read the destination, and read
the encoded `vvvv` and ModRM sources. W=1 is invalid; adjacent prefix/map
controls remain unowned. Admission requires
`CDISASM_X86_DECODE_FLAG_AVX_VNNI` independently of an AVX-VNNI-capable CPU
profile. Current positive physical profiles are Alder Lake, Arrow Lake,
Sapphire Rapids, Granite Rapids, and Diamond Rapids; the abstract AVX10 and
APX profiles also expose the capability. Haswell, Ice Lake, Tiger Lake, and
AMD Zen 4 remain negative boundaries.

The same release reuses ARM `ZIP1`/`ZIP2`/`UZP1`/`UZP2`/`TRN1`/`TRN2`
IDs 348--353 for the exact FEAT_F64MM Q-element SVE class. The classifier
`(word & 0xffe0e000) == 0x05a00000` owns 262,144 words: selector values
0--3, 6, and 7 allocate 196,608 forms, while selectors 4 and 5 reserve 65,536
forms. Results write `Zd.q` and read `Zn.q` and `Zm.q`, with scalable-vector
metadata and 16-byte elements. Valid forms require A64, ARMv8, F64MM, and
`USE_EXTRA_OPCODES=1`. `CPU_ANY` admits the implemented class; current named
profiles, including A64FX and Apple M4, reject it conservatively rather than
inferring F64MM from profile order or unrelated SVE/SME support.
Arm also constrains these allocated forms to an implemented SVE vector length
of at least 256 bits. cdisasm performs static instruction decoding and its
public API has no live vector-length input, so it reports the encoding and
feature requirement but does not diagnose that execution-state constraint.

Version 11.21 appends x86 IDs 1104--1109 for `VPDPBSSD`, `VPDPBSSDS`,
`VPDPBSUD`, `VPDPBSUDS`, `VPDPBUUD`, and `VPDPBUUDS`, plus
`CDISASM_X86_GROUP_AVX_VNNI_INT8` at group ID 108. The exact
`VEX.NDS.128/256.0F38.W0` map-2 row uses opcodes `50` and `51`: F2 selects
signed-by-signed forms, F3 selects signed-by-unsigned forms, and no mandatory
prefix selects unsigned-by-unsigned forms. All six operations read and write
the destination and read the encoded `vvvv` and register or full-width memory
sources. Across both lengths and every ModRM value, 3,072 forms are allocated;
the corresponding 3,072 W=1 forms are reserved. Non-66 opcodes `52`/`53` and
map-3 neighbors remain unowned. Admission requires the new
`CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8` bit 62 independently of
CPUID.7.1.EDX[4]. The unrestricted `CDISASM_CPU_X86` profile and the Arrow Lake
and Diamond Rapids named profiles admit the class; every other named profile
rejects it.

The same release appends ARM `SCVTF` (431) and `UCVTF` (432) for the exact
A64 classifier `(word & 0xfff8e000) == 0x6550a000`. Selectors zero and one
reserve 16,384 words. Selectors two through seven are respectively `SCVTF H`,
`UCVTF H`, `SCVTF S`, `UCVTF S`, `SCVTF D`, and `UCVTF D`. They allocate
49,152 merging predicated conversions from signed or unsigned H/S/D elements
to H elements,
for a 65,536-word owned envelope. Results read and write `Zd.h`, read `Pg/m`
and `Zn`, and type both the predicate and source with the encoded source
granularity. They carry scalable-vector, predicated, and floating-point
metadata and require A64, ARMv8, and either SVE or SME. A64FX proves the SVE
route; Apple A18 and M4 prove the SME route.

Version 11.22 appends x86 IDs 1110--1115 for `VPDPWSUD`, `VPDPWSUDS`,
`VPDPWUSD`, `VPDPWUSDS`, `VPDPWUUD`, and `VPDPWUUDS`, plus
`CDISASM_X86_GROUP_AVX_VNNI_INT16` at group ID 109. The exact classic
`VEX.NDS.128/256.0F38.W0` map-2 row uses opcodes `D2` and `D3`: F3 selects
word-signed by word-unsigned, 66 selects word-unsigned by word-signed, and no
mandatory prefix selects word-unsigned by word-unsigned. Opcode `D2` selects
the non-saturating result and `D3` the saturating result. Across both vector
lengths and every ModRM value, 3,072 W=0 controls are allocated and the
corresponding 3,072 W=1 controls are reserved. Admission requires runtime bit
63, `CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16`, independently of
CPUID.7.1.EDX[10]. The unrestricted `CDISASM_CPU_X86` profile and the Arrow
Lake and Diamond Rapids named profiles admit the class; Granite Rapids and
every other current named profile reject it. Intel XED's feature mapping
supplies the CPUID bit and the focused
encoding oracle; this scoped row is not a claim of complete AVX-VNNI coverage.

The same release reuses ARM `SCVTF` (431) and `UCVTF` (432) for four disjoint
`0xfffee000` envelopes with values `0x6594a000`, `0x65d4a000`, `0x65d0a000`,
and `0x65d6a000`. They allocate all 65,536 signed/unsigned S-to-S, D-to-S,
S-to-D, and D-to-D merging forms across the governing predicate and vector
register fields. Results read and write the typed destination, read `Pg/m` at
the source granularity, and read the typed source. Valid forms require A64,
ARMv8, and either SVE or SME. A64FX, Apple A18, and Apple M4 are positive named
profiles. These forms, like the earlier H-destination forms, are available only
with `USE_EXTRA_OPCODES=1`.

Version 11.23 appends x86 IDs 1116/1117 for `VP4DPWSSD` and `VP4DPWSSDS`.
They use the existing AVX512_4VNNIW group 71 and the existing
`CDISASM_X86_DECODE_FLAG_AVX512` runtime umbrella (bit 19), while CPU admission
uses an independent AVX512_4VNNIW capability. The exact
`EVEX.512.F2.0F38.W0` map-2 opcodes `52`/`53` require U=1, B=0, and a memory-
only 128-bit source. Tuple1_4X compresses disp8 by 16 bytes, and the encoded
ZMM source is displayed as the four-register block `zmmN+3`. The appended
`CDISASM_CPU_KNIGHTS_MILL` profile is the only current named physical profile
that admits the pair; the unrestricted profile remains available for
profile-independent analysis. Intel XED v2026.08.23's
[4VNNIW definitions](https://github.com/intelxed/xed/blob/main/datafiles/4vnniw-512/4vnniw-512-isa.xed.txt)
supply the independent encoding and formatting oracle.

The same release appends ARM `FCVT` (433), `FCVTZS` (434), and `FCVTZU` (435).
Six precision-conversion forms cover H/S/D in both directions where widths
differ; seven signed and seven unsigned FP-to-integer forms cover the allocated
H/S/D source/destination combinations. Across their exact classifiers, 163,840
words are allocated and 40,960 are reserved, for 204,800 owned words. Valid
forms require A64, ARMv8, and either SVE or SME. The distinct BFCVT neighbor is
left unowned rather than inferred from the baseline `FCVT` class. The bounded
selection follows LLVM's reviewed
[AArch64 SVE definitions](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/AArch64/AArch64SVEInstrInfo.td).

Version 11.24 appends x86 IDs 1118--1121 for `V4FMADDPS`, `V4FMADDSS`,
`V4FNMADDPS`, and `V4FNMADDSS`. They use the existing AVX512_4FMAPS group 72
and the existing `CDISASM_X86_DECODE_FLAG_AVX512` runtime umbrella (bit 19),
while CPU admission uses an independent AVX512_4FMAPS capability. Packed
opcodes `9A`/`AA` are `EVEX.512.F2.0F38.W0`; scalar opcodes `9B`/`AB` are LLIG
with fixed 128-bit XMM operands. Every form requires U=1, B=0, and a memory-only
m128 Tuple1_4X source, whose compressed disp8 scale is 16 bytes. The encoded
four-register source block is displayed as `zmmN+3` or `xmmN+3`. Across the
four-opcode, W, LL, and ModRM control lattice, 1,536 of 8,192 controls are
allocated and 6,656 are rejected. All three x86 decode modes admit the family
in an extras-enabled build. `CDISASM_CPU_KNIGHTS_MILL` is the only exact
named physical profile that admits the family; the unrestricted profile remains
available for profile-independent analysis. Intel XED's reviewed
[4FMAPS definitions](https://github.com/intelxed/xed/blob/main/datafiles/4fmaps-512/4fmaps-512-isa.xed.txt)
supply the encoding, Tuple1_4X, and formatting oracle.

The same release appends ARM `BFCVT` (436) for the exact merging encoding
`(word & 0xffffe000) == 0x658aa000`. Its `Pg`, `Zn`, and `Zd` fields allocate
all 8,192 words in that exact class. The focused four-selector envelope owns
32,768 words: 16,384 existing baseline `FCVT` words, 8,192 merging `BFCVT`
words, and 8,192 reserved controls. This is additive to the existing
65,536-word precision-`FCVT` sweep. Successful results read and write `Zd.h`,
read `Pg/m` at single-precision source granularity, and read `Zn.s`. Admission
requires A64, ARMv8, BF16, and either SVE or SME. `CPU_ANY`, Apple A18, and
Apple M4 admit it; A64FX lacks BF16, M3 lacks both SVE and SME, and the A19/M5
profiles remain deliberately conservative. The 11.24 completion was only the
merging SVE/SME encoding; version 11.25 below adds the exact zeroing pair and
merging BFCVTNT, and version 11.26 adds the bounded unpredicated pair forms.

Version 11.25 appends x86 IDs 1122--1125 for `VGETEXPPS`, `VGETEXPPD`,
`VGETEXPSS`, and `VGETEXPSD`. Packed opcode `42` uses W=0/1 for PS/PD and
scalar opcode `43` uses W=0/1 for SS/SD in `EVEX.66.0F38`. The packed forms are
unary and reserve `vvvv`; scalar forms use it as their passthrough source.
The exact 8,192-cell structural lattice contains 5,248 valid and 2,944 invalid
controls. Register `EVEX.b` selects SAE for packed 512-bit and scalar forms;
packed memory `EVEX.b` selects broadcast. The legacy route requires AVX512F
and the AVX-512 runtime selector, with AVX512VL additionally required for
packed 128/256-bit forms. The alternative route requires AVX10.1 and the AVX10
runtime selector. That historical 11.25 tranche did not include PH, SH, BF16,
or GETMANT; version 11.26 below adds the exact PH/SH/BF16 forms only.

The same release appends ARM `BFCVTNT` (437), while reusing `BFCVT` (436) for
the zeroing form. Merging `BFCVTNT` is
`(word & 0xffffe000) == 0x648aa000`; zeroing `BFCVT` and `BFCVTNT` are
`0x649ac000` and `0x6482a000` under the same mask. Each exact class contains
8,192 words. Merging `BFCVTNT` requires BF16 plus SVE or SME. The two zeroing
classes instead require SVE2.2 or SME2.2, without an independent BF16 gate;
no current named physical profile advertises either capability, so only
`CPU_ANY` admits them. Zeroing `BFCVT` writes `Zd.h`, while both `BFCVTNT`
forms read and write it because the even halfwords are preserved. Two adjacent
unallocated rows add 16,384 exact invalid controls. Version 11.26 below adds
the separately encoded unpredicated pair forms; MOVPRFX-dependent
unpredictability remains outside the stateless decoder.

Version 11.26 appends x86 IDs 1126--1128 for `VGETEXPPH`, `VGETEXPSH`, and
`VGETEXPBF16`. They use MAP6 opcodes `42`, `43`, and `42` with P66, P66, and
NP respectively; all require W=0. PH is unary packed, SH is scalar NDS, and
BF16 is unary packed. PH/SH are admitted by either AVX512-FP16 (plus AVX512VL
for packed 128/256-bit PH) or AVX10.1. BF16 has no AVX-512 alternative and
requires AVX10.2. The named legacy PH/SH route includes Sapphire Rapids,
Granite Rapids, and Diamond Rapids. Dual-capable Granite/Diamond profiles are
canonicalized to that legacy route; the abstract AVX10/APX profiles expose the
alternate AVX10.1 route. Named BF16 admission starts at Diamond Rapids and the
abstract AVX10/APX profiles. Register `EVEX.b` selects
SAE for PH/SH, while BF16 reserves
that register-source control. Packed PH/BF16 memory uses m16 broadcast; scalar
SH memory remains an m16 source without broadcast. With `EVEX.b=0`, LL=0--2
are allocated and LL=3 is reserved. With register `EVEX.b=1`, PH is forced to
512 bits and PH/SH accept all LL aliases for SAE; with memory `EVEX.b=1`, only
packed PH/BF16 LL=0--2 broadcast forms are allocated.
The focused 12,288-cell W/LL/b/ModRM lattice distinguishes 3,968 accepted from
8,320 reserved controls and also locks U, prefix, mask, `vvvv`, and truncation
boundaries. In 64-bit mode, APX EVEX.X4 memory forms may use R16--R31 as the
SIB index for all three new names; they add `APX_F` metadata and require the
APX CPU/runtime route. Register-source U=0 forms and every non-64-bit X4 form
remain invalid.

The same release appends ARM `BFCVTN` (438) and reuses `BFCVT` (436) for four
exact unpredicated pair conversions. Under mask `0xfffffc20`, SME2 `BFCVT`
and `BFCVTN` S-pair-to-H are `0xc160e000` and `0xc160e020`; SME2+FP8
H-pair-to-B `BFCVT` is `0xc164e000`. (SVE2 or SME2)+FP8 H-pair-to-B `BFCVTN`
is `0x650a3800` under the same mask. Each exact form has 512 legal
destination/source-pair combinations, and the source field always names an
even consecutive Z-register pair. Apple A18 and M4 admit the two non-FP8 SME2
forms. FP8 admission is kept independent and is currently exposed only by
`CPU_ANY`; no named processor gains it by age or ID.
There is no unpredicated pair `BFCVTNT` allocation in this map.

The current post-12.0 opcode tranche reuses existing append-only catalog IDs
and adds exact semantics on both architectures. On x86, REX2 map-1 forms
`D5 xx 01 C8` and `D5 xx 01 C9` now decode as `MONITOR` and `MWAIT` with
forms 1639 and 1821. The six `VPDPBSSD`/`VPDPBSSDS`, `VPDPBSUD`/
`VPDPBSUDS`, and `VPDPBUUD`/`VPDPBUUDS` names now cover their complete EVEX
AVX10.2 VNNI-INT8 row: W=0 map-2 opcodes `50`/`51`, NP/F3/F2 selection,
XMM/YMM/ZMM register and Full-tuple memory sources, m32 broadcast, merge/zero
masks, compressed displacement, and 36 native XED IFORM identities. Ordinary
forms use the AVX10 runtime selector; reviewed B4/U0 address-extension forms
also require the independent APX selector and APX-F CPU capability. All four
ACE_1 `TILEMOVROW`/`TILEMOVCOL` GPR32/IMM8 forms 3299--3302 are now exact as
well. They are 64-bit, register-only, W=1, U=1, VL=512 EVEX forms with a
write-only TMM destination, a read-only ZMM source, and either a read GPR32 or
an imm8 selector; masks and zeroing are rejected.
The ten ACE_1 TOP forms 3310--3319 are exact too: `TOP2BF16PS`, the four
signed/unsigned `TOP4B*D` combinations, and the five immediate `TOP4MX*PS`
forms. They are 64-bit, register-only, W=0, U=1, VL=512 EVEX encodings with a
read/write TMM destination and two read ZMM sources; the `TOP4MX*PS` forms add
an imm8. The optional B4 route independently requires APX-F. The legacy
RAO-INT `AADD`/`AAND`/`AOR`/`AXOR` dword/qword IFORMs 2/3, 8/9, 257/258, and
263/264 are also exact. They share memory-only opcode `0f 38 fc /r`, use
NP/66/F2/F3 as operation selectors and REX.W for qword width, and expose the
memory destination as read/write and the GPR source as read-only. The eight
APX-F siblings (IFORMS 4/5, 10/11, 259/260, and 265/266) are exact as well:
EVEX map 4 opcode `fc`, NP/66/F2/F3 operation selection, W-selected dword/qword
width, both defined U states, EGPR addressing, and a memory-only destination.
Legacy RAO-INT and APX-F RAO-INT have independent high decode-family bits and
remain unavailable to named profiles that do not advertise them.
The complete ACE_1 BSR state-transfer family is exact as well: `BSRINIT` and
all register/m512 directions of `BSRMOVF`, `BSRMOVH`, and `BSRMOVL`, IFORMs
378--388. `BSR0` is now the append-only public register ID 308 and is emitted
as a visible 128-byte implicit state operand with its architectural read/write
direction; its signed EVEX disp8 is unscaled. The eight
`URDMSR`/`UWRMSR` IFORMs 3353--3360 cover legacy register, VEX imm32, APX
register, and APX imm32 routes. `USER_MSR` and `APX_F_USER_MSR` retain
independent high runtime-family bits, with exact EGPR and opcode-collision
handling.
The neighboring privileged MSR system row is exact too. Fixed register tuple
`0F 01 C6` selects 64-bit `RDMSRLIST`/`WRMSRLIST` with F2/F3 and
mode-independent `WRMSRNS` without a mandatory prefix; suppressed
architectural register state remains outside the syntax-oriented operand ABI.
VEX map-7 `F6 /0 id` and APX EVEX map-7 `F6 /0 id` select the immediate
`RDMSR r64, imm32` and `WRMSRNS imm32, r64` forms. APX B/B4 exposes
R0--R31, all immediate forms require 64-bit mode, and malformed complete
controls are invalid only after the complete owned ModRM/address/imm32 body is
consumed. Intel ISE #319433-060's W=0 requirement is enforced for VEX and
APX even though the pinned XED 2026.08 patterns also accept W=1. MSRLIST,
MSR_IMM, APX_F_MSR_IMM, and WRMSRNS retain independent runtime-family gates;
only the unrestricted profile admits the immediate forms, while the fixed
forms also admit Diamond Rapids where the pinned profile table does.
The legacy memory half of F2/F3 `0f 38 f8 /r` is exact `ENQCMD`/`ENQCMDS`
in all three modes. Its public cdisasm form IDs are 1144/1142 (the pinned XED
enum ordinals are 1142/1144), `GPRa` follows effective address size, and the
second operand is a read-only 64-byte memory block. Operand-size override and
REX.W are ignored, both instructions publish aggregate arithmetic-status
writes, and only `ENQCMDS` is privileged. Register controls remain the
64-bit legacy USER_MSR collision and likewise accept ignored `66`/`67`.
The complete pinned Key Locker family is now exact too. Its eleven IFORMs are
the eight `AESENC*KL`/`AESDEC*KL` narrow and wide memory forms, register-only
`ENCODEKEY128`/`ENCODEKEY256`, and privileged register-only `LOADIWKEY`.
Mandatory-F3 selection, the `DC` memory/register collision, 384-/512-bit key
memory widths, WIG REX.W, REX register/address extensions, aggregate status-
flag writes, CPU/runtime-family admission, and malformed/truncated neighbors
are handled explicitly. `KEYLOCKER` and `KEYLOCKER_WIDE` remain independent
runtime selectors.
Four more pinned x86 system slices are exact. `HRESET` IFORM 1319 is the
mandatory-F3 `0F 3A F0 C0 ib` form in every mode, with one read imm8, CPL0,
WIG REX.W, and no REX2 route. `CLDEMOTE` IFORM 710 owns only the unprefixed
memory `/0` part of `0F 1C`; register forms, `/1`--`/7`, mandatory-prefix
forms, and unsupported CPU profiles retain the P6 multi-byte `NOP` meaning.
Its byte-sized memory operand is address-only, and a 64-bit REX2 spelling
requires APX independently. AMD `CLZERO` IFORM 719 is fixed `0F 01 FC` in all
modes, has no visible operands, accepts the architecturally ignored legacy/REX
prefixes, rejects LOCK, and admits only the unrestricted and Zen/Zen 4
profiles. Its REX2 spelling likewise requires APX. The exact runtime
selectors/groups are HRESET 218/271, CLDEMOTE 211/264, and CLZERO 213/266.
The two pinned `PCONFIG` descriptors are exact as well. NP/OSZ=0 fixed opcode
`0F 01 C5` selects IFORM 2084 in 16-/32-bit mode and `PCONFIG64` IFORM 2085
in 64-bit mode. The suppressed accumulator-family state is omitted from the
public operand list, while CPL0 and aggregate status-flag writes remain
visible. Address-size, segment, and ordinary REX prefixes are ignored;
LOCK, F2/F3, and 66 are rejected. The 64-bit REX2 spelling independently
requires APX-F. Exact runtime bit 236/group 289 admits the unrestricted,
Tiger Lake, Alder Lake, Sapphire Rapids, AVX10, APX, Granite Rapids, Arrow
Lake, and Diamond Rapids profiles; other named profiles reject the allocation.
`PBNDKB` IFORM 2039 is exact at the adjacent fixed NP/OSZ=0 tuple
`0F 01 C7`. It is 64-bit and privileged, publishes aggregate status-flag
writes, and has no visible syntax operands because XED classifies its
EAX/RBX/RCX state as suppressed. Address-size, segment, and ordinary REX
prefixes are ignored; LOCK, F2/F3, and 66 are malformed. Runtime bit
235/group 288 admits only unrestricted `CDISASM_CPU_X86`, because the pinned
profile first exposes PBNDKB on Panther Lake and cdisasm has no Panther Lake
profile. A REX2 spelling additionally requires APX-F.

AMD `RDPRU` IFORM 2578 is the fixed `0F 01 FD` allocation in 16-, 32-, and
64-bit modes. EDX:EAX and ECX are suppressed architectural state, so the
syntax-oriented result has no visible operands. Operand-size, address-size,
segment, F2/F3, ordinary REX, and map-1 REX2 prefixes are redundant; LOCK is
invalid. Exact runtime bit 247/group 300 admits only unrestricted
`CDISASM_CPU_X86`, because the pinned XED profile first exposes RDPRU at Zen 2
and cdisasm has no named Zen 2 profile. REX2 independently requires APX-F.

The complete `0F 18` collision row is partitioned explicitly. Memory `/0`--`/3`
retains `PREFETCHNTA/T0/T1/T2`; every register tuple retains its P6 fat-`NOP`
identity. Memory `/4` promotes to `PREFETCHRST2` IFORM 2311 only for
Diamond Rapids or unrestricted `CDISASM_CPU_X86` with exact MOVRS runtime bit
232/group 285; on other profiles it retains memory-NOP form 1860. Memory `/5`
always remains its NOP identity. Memory `/6` and `/7` promote to
`PREFETCHIT1` IFORM 2309 and `PREFETCHIT0` IFORM 2308 only in 64-bit mode with
effective 64-bit addressing, a genuine RIP-relative address, an
ICACHE_PREFETCH-capable CPU, and runtime bit 223/group 276. Otherwise they
remain NOPs. All promoted hints expose one byte-sized address-only read
operand; only PREFETCHIT0/1 require and report PC-relative/RIP-relative
addressing. LOCK is malformed, while ignored legacy prefixes do not acquire
false `rep` formatting. Granite Rapids, Diamond Rapids, and unrestricted
`CDISASM_CPU_X86` admit PREFETCHIT0/1; PREFETCHRST2 is limited to Diamond
Rapids and unrestricted `CDISASM_CPU_X86`. Its `66`/F2/F3 prefixes are ignored.
REX2 independently requires APX-F.

`PREFETCHWT1` IFORM 2315 is the memory-only `0F 0D /2` allocation in every
mode; the adjacent register `/2` tuple remains P6 NOP form 1851. It requires
the exact PREFETCHWT1 runtime bit 242/group 295 and is admitted by Knights Mill
or unrestricted `CDISASM_CPU_X86`; a complete encoding on another named
profile is invalid. Its single byte-sized memory operand is address-only and
read, `66`/F2/F3 are ignored, and LOCK is invalid. REX2 map 1 preserves the
same collision partition while independently requiring APX-F.
AMD `MONITORX` IFORM 1640 and `MWAITX` IFORM 1822 own the fixed NP/OSZ=0
`0F 01 FA` and `0F 01 FB` tuples in every mode. Their address-size-dependent
AX/EAX/RAX and control-register inputs are suppressed by XED and therefore do
not appear in the syntax-oriented operand ABI. `MCOMMIT` IFORM 1629 shares the
FA selector under mandatory F3, has no operands, and publishes aggregate
status-flag-write metadata. Address-size, segment, and ordinary REX prefixes
are ignored by all three; MONITORX/MWAITX reject LOCK, F2/F3, and 66, while
MCOMMIT accepts redundant 66 or an earlier F2 only when F3 remains the
rightmost repeat prefix and rejects LOCK. The 64-bit REX2 spellings require
APX-F independently. Runtime bit/group 229/282 selects MCOMMIT and 231/284
selects both MONITORX and MWAITX. The pinned AMDONLY profile table maps none of
these ISA sets to a public named CPU, so only unrestricted `CDISASM_CPU_X86`
admits complete encodings; extras-off builds retain structural ownership and
report them unsupported.

The adjacent AMD_FUTURE-only `0F 01 FE/FF` cluster is also exact. NP selects
no-operand `INVLPGB` IFORM 1410 and `TLBSYNC` IFORM 3309; INVLPGB requires
EASZ32/64 while TLBSYNC is mode/address-size independent. Mandatory F2 selects
`RMPUPDATE RAX, RCX` IFORM 2633 and `PVALIDATE RAX, ECX, EDX` IFORM 2487;
mandatory F3 selects `RMPADJUST RAX, RCX, RDX` IFORM 2632 and `PSMASH RAX`
IFORM 2370. The SNP registers are explicit ABI operands marked implicit with
their exact access, and the forms publish aggregate status-flag writes.
PVALIDATE is valid in every mode; the other SNP forms require mode 64. LOCK
is rejected, NP rejects 66, F2/F3 accept redundant 66, and rightmost F2/F3
selection is preserved without false repeat formatting. All six are
privileged. Exact runtime bit/group pairs are 67/119 for AMD_INVLPGB and
254/307 for SNP. No current named CPU maps to pinned XED's AMD_FUTURE profile,
so only unrestricted `CDISASM_CPU_X86` admits them; REX2 additionally requires
APX-F and extras-off builds report structurally recognized encodings as
unsupported.

Exact `VP2INTERSECTD`/`VP2INTERSECTQ` forms 6074--6085 now cover every
XMM/YMM/ZMM register and Full-tuple memory source shape at EVEX map 2 opcode
`68`. W selects dword or qword elements. The low bit of ModRM.reg is ignored
architecturally: cdisasm clears it to select the first even K destination,
publishes that register and its odd successor as two structured write
operands, marks the second one implicit, and formats the pair as `kN+1`.
Memory forms retain scalar broadcast and 16/32/64-byte compressed-displacement
scales; 64-bit B4/U0/X4 address extensions require APX independently. Exact
width runtime groups and the exact Tiger Lake feature route are enforced,
while malformed R/R', `aaa`, `z`, LL=3, and extension controls remain invalid.
The exhaustive focused lattice classifies 8,064 allocated and 778,368 reserved
controls across all 786,432 cases.

The packed-integer MIN/MAX implementation now covers the complete 144-form
VEX/EVEX block, forms 7160--7303: 48 VEX identities and 96 EVEX identities for
signed and unsigned byte, word, dword, and qword elements. VEX routes retain
their exact AVX/AVX2 admission, while EVEX routes preserve mask, broadcast,
compressed-displacement, AVX-512/AVX10, and APX address semantics. Its focused
classifier checks 2,457,600 allocated and 7,372,800 reserved controls.

GFNI is complete for the pinned XED inventory. Legacy forms 1308--1313 and all
VEX/EVEX forms 5505--5534 implement `GF2P8AFFINEINVQB`, `GF2P8AFFINEQB`, and
`GF2P8MULB` plus their vector spellings. The decoder preserves affine imm8,
legal EVEX broadcast and masking, non-long ignored aliases, exact `AVX_GFNI`
and width-specific `AVX512_GFNI` bits, AVX10 alternatives, and APX-only U0/X4
memory promotion. Register U0, malformed EVEX controls, and missing family
bits remain fail-closed.

On A64, `FCVT Zd.H, Pg/z, Zn.S` form 2952 is implemented under the exact
`0xffffe000/0x649a8000` classifier with the SVE2.2-or-SME2.2 gate. Seven
destructive halfword forms—`BFADD`, `BFSUB`, `BFMUL`, `BFMAXNM`, `BFMINNM`,
`BFMAX`, and `BFMIN`—cover 57,344 allocated words under FEAT_SVE_B16B16;
the adjacent operation selector 3 accounts for 8,192 invalid words. A64
`DCPS1`/`DCPS2`/`DCPS3` forms 4453--4455 now expose the optional imm16 in
bits 20:5 as a structured read operand, retain generated interrupt/privileged
metadata, and omit `#0` in canonical text. SVE indexed `DUP` form 2439 is now
structured with its preferred `MOV` alias, element type, and lane immediate.
The baseline A64 permanently-undefined `UDF #imm16` form 4387 is exact across
all 65,536 immediates as well. It returns a successful structured decode with
the interrupt group and a two-byte read immediate. That group records the
architectural Undefined Instruction exception; `ILLEGAL`, `UNPREDICTABLE`,
and execution-state flags remain clear because the encoding itself is
allocated and the pinned operation deliberately specifies no state effects.
The A64 FEAT_WFxT pair is exact as well. `WFET Xt` form 4457 uses
`0xffffffe0/0xd5031000`, and `WFIT Xt` form 4458 uses
`0xffffffe0/0xd5031020`. Their five-bit operand is a read X0--X30 or XZR,
never SP. The independent WFxT capability is intentionally available through
`CPU_ANY` only because no current named cdisasm profile advertises it;
extras-off builds retain structural ownership without publishing partial
metadata.
The A64 FEAT_FlagM/FlagM2 slice is exact too. FEAT_FlagM supplies fixed
no-operand `CFINV` form 4499, `RMIF Xn|XZR, #shift6, #mask4` form 5696, and
`SETF8`/`SETF16 Wn|WZR` forms 5697--5698; FEAT_FlagM2 supplies fixed
no-operand `XAFLAG`/`AXFLAG` forms 4500--4501. RMIF reads its 64-bit register
and two immediate operands, each SETF form reads one 32-bit register, and all
six results carry exact status-flag-write metadata. Only `CPU_ANY` admits
these features because no current named profile advertises either one.
Extras-off builds report allocated words as unsupported while the RMIF
`o2=1` half, the unallocated SETF low controls, and other malformed neighbors
remain invalid in both variants.
The A64 SVE first-fault-register slice is exact for `RDFFR`, `RDFFRS`,
`WRFFR`, and `SETFFR`. Predicated `RDFFR Pd.B, Pg/Z` form 2562 and
`RDFFRS Pd.B, Pg/Z` form 2563 write the destination predicate and read the
zeroing guard predicate; only RDFFRS sets NZCV. Unpredicated `RDFFR Pd.B`
form 2564 writes one predicate, `WRFFR Pn.B` form 2617 reads one predicate,
and zero-operand `SETFFR` form 2618 updates FFR. All five forms carry scalable-
vector metadata and require SVE. `CPU_ANY` and Fujitsu A64FX admit them; every
other current named profile rejects them. Extras-off builds retain allocated
words as unsupported, while reserved controls remain invalid. The focused
suite exhausts all 545 valid words and 611 reserved parent-envelope words,
and also locks fixed-bit neighbors, both byte orders, generic transport,
truncation, profile gates, structured operands, and canonical formatting.
The FP8 pair-narrowing row now covers `FCVTN`/`FCVTNB`/`BFCVTN`/`FCVTNT`
forms 3165--3168. The SME2 two-vector conversion row covers all forms
4312--4324: `FCVT`, `BFCVT`, `FCVTN`, `BFCVTN`, `FCVTZS`, `FCVTZU`,
`SCVTF`, `UCVTF`, `SQCVT`, `SQCVTU`, `UQCVT`, and the FP8 `BFCVT`/`FCVT`
forms. Adjacent SME2 `SUNPK`/`UUNPK` forms 4325--4326 and the eight
SME2+FP8 widening `F1CVT`/`BF1CVT`/`F2CVT`/`BF2CVT` forms, including their
`L` variants, 4327--4334 are exact too. The SVE2.1-or-SME2 multi-extract
`SQCVTN`/`SQCVTUN`/`UQCVTN` forms 2881--2883, SME2 two-vector
`FRINTN`/`FRINTP`/`FRINTM`/`FRINTA` forms 4335--4338, and SME_F16F16
`FCVT`/`FCVTL` forms 4339--4340 are now exact. The complete adjacent SME2
four-vector block is exact through form 4362: conversions and saturating
narrowing 4341--4350, FP8 `FCVT`/`FCVTN` 4351--4352, `SUNPK`/`UUNPK`
4353--4354, ordinary and quadword `ZIP`/`UZP` 4355--4358, and
`FRINTN`/`FRINTP`/`FRINTM`/`FRINTA` 4359--4362. Its focused test exhausts
5,504 allocated encodings and 3,072 reserved neighbors. The preceding
multi-extract/two-vector focused tests exhaust
3,584 allocated and 4,608 structurally owned reserved words. Forms 4363--4370
add the exact SME multi-vector `FMUL`/`BFMUL` block: aligned two- or four-Z
destination and first-source lists multiply either an equally sized aligned
list or scalar `z0`--`z15`. Encoded sizes one through three select
`FMUL` H/S/D and require SME2.2; size zero selects fixed-H `BFMUL` and
requires SME2 plus FEAT_SVE_BFSCALE. The four envelopes contain 29,184 FMUL
and 9,728 BFMUL words, with no reserved word in their combined lattice; every
current named profile rejects the exact generated requirements, while
`CPU_ANY` is the positive analysis route. Forms 4373--4380 and 4385--4386 now
implement all baseline-SME predicated contiguous ZA-slice transfers:
`LD1B/H/W/D/Q` and `ST1B/H/W/D/Q`. Every leaf has exact mask
`0xffe00010` and 1,048,576 allocated words. The twenty variable bits select
X0--X30 or omitted XZR index, horizontal/vertical view, W12--W15, P0--P7,
X0--X30/SP base, and the size-dependent ZA tile/offset partition. Indexed
H/W/D/Q addresses carry `LSL #1/#2/#3/#4`; loads use `Pg/Z`, write the tile,
and read memory, while stores read the unqualified predicate and tile and
write memory. Runtime-sized memory reports `size == 0`; the selected element
width remains on both tile and predicate operands, and
`CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL` distinguishes the V view without an
ABI layout change. Results carry SME, matrix, scalable-vector, and predicated
metadata, deliberately not streaming-state metadata. `CPU_ANY`, Apple A18,
and Apple M4 admit the SME requirement. The focused suite checks 20,480
factorized-exhaustive field combinations, fixed boundaries, formatter schema,
profiles, endian/generic transport, truncation, and extras/formatter-off
ownership against pinned AARCHMRS, LLVM 21, and Capstone 5.

Baseline-SME predicated ZA-slice `MOVA` is exact for insert forms 3862--3866
and extract forms 3877--3881, including the preferred `MOV` spelling. The two
disjoint classifiers preserve B/H/S/D/Q tile views, horizontal/vertical
selection, W12--W15 slice selectors, P0--P7 merge predicates, all Z0--Z31
registers, and the width-dependent ZA tile/offset split. Inserts read the Z
source and read/write ZA; extracts read ZA and read/write the predicated Z
destination. Q uses its dedicated control bit only with the D-sized selector;
the other three Q-control combinations are invalid. Results carry exactly
SME, matrix, scalable-vector, and predicated metadata. The focused suite checks
10,880 bounded field combinations, reserved controls, profile and endian
transport, canonical formatting, forged-metadata rejection, and extras-off
ownership; LLVM 21 independently agrees with representative encodings for all
ten forms.

SME2 multi-register `MOVA` inserts 3867--3876 and extracts 3882--3891 are
exact and also use the preferred `MOV` spelling. The visible Z operand is an
explicit contiguous, correctly aligned pair or quad; ordinary ZA operands are
B/H/S/D horizontal or vertical slices with an explicit two- or four-element
range, while the D-only whole-array forms use `ZA.D[W8-W11, off, VGx2|VGx4]`.
Together with the adjacent baseline forms, the implemented ZA-transfer slice
spans B/H/S/D/Q views. Inserts write ZA and read the Z list; extracts read ZA
and write the Z list. All forms require SME2, carry SME, matrix, and scalable-
vector metadata, and are admitted by `CPU_ANY`, Apple A18, and Apple M4.
Reserved quad slice controls remain invalid. The focused suite checks 12,288
bounded cases plus the reserved quad controls and locks exact reciprocal
access, pair/quad alignment, canonical text, profiles, both byte orders,
generic dispatch, truncation, and extras-off
ownership against pinned AARCHMRS.

SME2.1 zeroing ZA extracts `MOVAZ` forms 3892--3906 are exact. The five
single-register leaves cover B/H/S/D/Q destinations; four aligned-pair and
four aligned-quad leaves cover B/H/S/D lists; and the two D-only whole-array
leaves use `ZA.D[W8-W11, off, VGx2|VGx4]`. Slice forms use W12--W15 and
horizontal/vertical ZA views. Unlike predicated `MOVA`, these forms have no
predicate, retain the canonical `MOVAZ` mnemonic with no `MOV` alias, write
the Z destination or list, and read ZA. Results carry exactly SME, matrix,
and scalable-vector metadata and require FEAT_SME2p1. Only `CPU_ANY` currently
admits that feature: Apple A18 and M4 stop at SME2 and reject every MOVAZ form.
The focused suite checks all 26,624 allocated control words, single-Q and
B/H/S-quad reserved controls, alignment, access, exact text, every named
profile, endian/generic transport, truncation, formatter-schema rejection,
and extras/formatter-off ownership. Pinned AARCHMRS supplies the allocation
and feature contract; LLVM 21 independently confirms representative encodings
under `+sme2p1` and rejects them under `+sme2` alone.

Forms 4381--4382 now implement the
complete baseline-SME ZA array-vector transfer leaves. Their exact
`0xffff9c10` mask varies W12--W15, X0--X30/SP, and an unsigned four-bit
ZA array-vector selector offset. That offset is also the memory displacement
coefficient, so nonzero values format as `#off, mul vl`; all 4,096 allocated words are
covered. The memory operand has runtime size zero, and its `imm` plus
`CDISASM_ARM_OPERAND_FLAG_VL_SCALED` preserve the exact address without
inventing a fixed SVL. `CPU_ANY`, Apple A18, and Apple M4 admit SME. Forms
4383--4384 add exact SME2
`LDR ZT0, [Xn|SP]` and `STR ZT0, [Xn|SP]` leaves. Each instruction allocates
all 32 base registers, for 64 legal words; the exhaustive 8,192-word parent
envelope rejects the remaining 8,128 operation/ZT-selector combinations.
`CPU_ANY`, Apple A18, and Apple M4 admit the SME2 requirement. T32
`DCPS1`/`DCPS2`/`DCPS3` forms 1853--1855 are also structured as exact
no-operand 32-bit T32 instructions with interrupt/privileged metadata.
The same tranche now includes SVE/SME `ADDVL`/`ADDPL`/`RDVL` forms
2348/2349/2352 with signed imm6 and exact SP-versus-XZR handling; Advanced
SIMD `REV16`/`REV32`/`REV64` forms 6004/6038/6003 with their allocated
arrangement lattice; Advanced SIMD `CLS`/`CNT`/`CLZ` forms 6007/6008/6041;
and baseline SVE/SME integer reductions `SADDV`, `UADDV`,
`SMAXV`, `SMINV`, `UMAXV`, `UMINV`, `ORV`, `EORV`, and `ANDV` forms
2243/2244/2246--2249/2255--2257. Their focused test exhausts 452,608 owned
words: 432,128 allocated and 20,480 reserved.
The separate bit-count test exhausts its 24,576-word lattice: CLS and CLZ each
allocate 6,144 B/H/S words and reserve 2,048 size-three words, while CNT
allocates its 2,048 8B/16B words and reserves 6,144 non-byte arrangements.
Every allocated form requires A64 plus Advanced SIMD, writes a typed V-register
and reads one typed V-register.

All 30 pinned fixed-width SHA1/SHA256 leaves are exact across A32, T32, and
A64, including their scalar and Advanced SIMD operand layouts, feature gates,
endianness, and reserved neighbors. The focused classifier covers 291,328
allocated and 883,200 reserved encodings.

The contiguous fixed A64 crypto block 6287--6303 is also complete:
`SM3TT1A/B`, `SM3TT2A/B`, `SHA512H/H2/SU0/SU1`, `RAX1`, `SM3PARTW1/W2`,
`SM4EKEY`, `EOR3`, `BCAX`, `SM3SS1`, `XAR`, and `SM4E`. Exact SHA3, SHA512,
SM3, and SM4 requirements, destination access (including write-only
`SM4EKEY`), indexed lanes, immediates, and shared SVE-name isolation are
preserved. The focused suite exhausts all 5,998,592 allocated encodings.

The current catalogs contain the established names plus append-only generated
XED and AARCHMRS allocations, ARM scalar/vector, scalable-vector, predicate,
and matrix register IDs 164--374, and numeric operand/type metadata. They are
defined in every build of the corresponding enabled architecture, in both
`USE_EXTRA_OPCODES` variants: current totals are 2,028 x86 name IDs including
`NONE`, 307 defined x86 register IDs in a 309-slot ID space, 323 x86 groups,
2,054 ARM name IDs including `NONE`, and
375 ARM registers. This
keeps persisted numeric records, the 248-byte x86 result, and the 168-byte ARM
result ABI-identical between
feature variants. Catalog presence is not semantic availability. Every opcode
semantic and formatter spelling in the optional tranches is compiled only
when `USE_EXTRA_OPCODES=1`.

For x86, both `cdisasm_decode` and `cdisasm_x86_decode` can target
introduction-level CPU profiles from the 8086 through APX, exact modern no-AVX
processor profiles, pre-486 CPU/coprocessor combinations, and Granite Rapids.
The appended physical presets also include Arrow Lake, Diamond Rapids, and
Knights Mill.
Named profiles enforce historical mode limits (`80386` for 32-bit and
`ATHLON_64` for 64-bit) and use Intel/AMD capability masks for implemented
instruction families. `CDISASM_CPU_X86` is the x86 group combined with ordinal
zero and remains the unrestricted *CPU-capability* setting. It does not bypass
the caller's opcode-family allow bitmap. ISA group tags describe the decoded
encoding; CPU availability is a separate, vendor-aware and non-monotonic
decision.

### x86 CPU mode and decode-family queries

`cdisasm_x86_cpu_mode_mask(cpu_id)` reports the execution widths supported by
an x86 profile without attempting a decode. Its mask values are independent of
the numeric mode arguments passed to `cdisasm_x86_decode`:

| Mask value | Public define | Corresponding decode mode |
| ---: | --- | --- |
| `0x00` | `CDISASM_X86_MODE_MASK_NONE` | No available mode, including an invalid CPU ID |
| `0x01` | `CDISASM_X86_MODE_MASK_16` | `CDISASM_X86_MODE_16` / `CDISASM_MODE_16` |
| `0x02` | `CDISASM_X86_MODE_MASK_32` | `CDISASM_X86_MODE_32` / `CDISASM_MODE_32` |
| `0x04` | `CDISASM_X86_MODE_MASK_64` | `CDISASM_X86_MODE_64` / `CDISASM_MODE_64` |

The bits may be ORed. For example, an 80386 profile returns `0x03`, while an
Athlon 64 profile returns `0x07`. An unknown ordinal, a raw legacy ordinal
without `CDISASM_CPU_GROUP_X86`, or an ID from another architecture returns
`CDISASM_X86_MODE_MASK_NONE`.

`cdisasm_x86_cpu_decode_flag_mask(cpu_id, mode, &flags)` writes the non-base
runtime families that this build implements and the selected CPU profile can
use in that mode. Its output is a complete `cdisasm_x86_decode_flags` object
containing only known x86 bits. Base scalar decoding is implicit and is
represented by an all-zero object, so there is no separate base bit to return.
For example:

```c
cdisasm_x86_decode_flags available =
    CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
cdisasm_status status = cdisasm_x86_cpu_decode_flag_mask(
    CDISASM_CPU_HASWELL, CDISASM_MODE_64, &available);
if (status == CDISASM_STATUS_OK) {
    /* Pass &available to cdisasm_x86_decode. */
}
```

The query requires a non-NULL output pointer and clears the whole object before
validating the CPU and mode. An invalid CPU ID, invalid mode, or impossible
CPU/mode pair returns `CDISASM_STATUS_INVALID_ARGUMENT` with a cleared output.
When `USE_EXTRA_OPCODES=0`, every valid CPU/mode pair returns
`CDISASM_STATUS_OK` with an all-zero object because that build accepts only the
base policy. A returned family bit means that implemented instructions in that
family can be selected for the profile; it does not promise complete coverage
of every encoding in the family and does not model runtime state such as
OS-enabled vector context.

With extra opcodes enabled, the virtualization-related subset of that query is
exact:

| CPU profile | Included selector(s) | Excluded selector(s) |
| --- | --- | --- |
| `CDISASM_CPU_INTEL_VT_X` | `VMX` | `SMX`, `SVM` |
| `CDISASM_CPU_AMD_V` | `SVM` | `SMX`, `VMX` |
| `CDISASM_CPU_CORE_2` | `SMX`, `VMX` | `SVM` |
| `CDISASM_CPU_X86` | `SMX`, `VMX`, `SVM` | — |

The regression matrix checks this virtualization subset for all 53 unique x86
CPU profiles in every mode each profile supports, not only the four examples
shown above.

### x86 runtime opcode-family bitmap

The `flags` argument to `cdisasm_x86_decode` is a pointer to an allow bitmap
independent of the CPU profile. `NULL` or an all-zero object admits only the
ordinary scalar/base opcode set. Base instructions remain admitted when other
bits are present. A non-base instruction also needs its selected family bit;
allowing a family never grants a CPU capability and never adds an unimplemented
encoding.

`cdisasm_x86_decode_flags` is an alias of the common
`cdisasm_decode_flags`: eight `uint64_t` words, exactly 64 bytes and 512 logical
bit positions. Generic declarations can use
`CDISASM_DECODE_FLAGS_NONE_INITIALIZER` or
`CDISASM_DECODE_FLAGS_INITIALIZER(bitmap0)`. X86 declarations can use
`CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER`,
`CDISASM_X86_DECODE_FLAGS_INITIALIZER(bitmap0)`, or
`CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER` for declarations. The common
`cdisasm_decode_flags_reset`, `cdisasm_decode_flags_set_bit`,
`cdisasm_decode_flags_clear_bit`, and `cdisasm_decode_flags_test_bit` helpers
operate on the complete object. The append-only `CDISASM_X86_DECODE_BIT_*`
IDs currently run from 0 through 63 and can extend past 63 without changing
the ABI:

```c
cdisasm_x86_decode_flags flags =
    CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

cdisasm_decode_flags_set_bit(&flags, CDISASM_X86_DECODE_BIT_AVX);
cdisasm_decode_flags_set_bit(&flags, CDISASM_X86_DECODE_BIT_FMA3);
if (cdisasm_decode_flags_test_bit(
        &flags, CDISASM_X86_DECODE_BIT_FMA3)) {
    cdisasm_decode_flags_clear_bit(
        &flags, CDISASM_X86_DECODE_BIT_FMA3);
}
```

The existing `CDISASM_X86_DECODE_FLAG_*` masks remain bitmap-0 masks and may
be OR-composed inside `CDISASM_X86_DECODE_FLAGS_INITIALIZER(...)`. The singular
`cdisasm_x86_decode_option` type and `_OPTION_*` constants likewise describe
only one legacy 64-bit bitmap word; they are not the type accepted by the
version-12 decoder.

| Bitmap 0 bit | Bitmap 0 value | Public mask define | Selected family |
| ---: | ---: | --- | --- |
| — | `0x00000000` | `CDISASM_X86_DECODE_FLAG_BASE` | Ordinary scalar/base instructions; no non-base family is enabled |
| 0 | `0x00000001` | `CDISASM_X86_DECODE_FLAG_FPU` | x87/FPU and WAIT/FWAIT |
| 1 | `0x00000002` | `CDISASM_X86_DECODE_FLAG_MMX` | MMX |
| 2 | `0x00000004` | `CDISASM_X86_DECODE_FLAG_3DNOW` | Base and Extended 3DNow! |
| 3 | `0x00000008` | `CDISASM_X86_DECODE_FLAG_SSE` | SSE |
| 4 | `0x00000010` | `CDISASM_X86_DECODE_FLAG_SSE2` | SSE2 |
| 5 | `0x00000020` | `CDISASM_X86_DECODE_FLAG_SSE3` | SSE3 |
| 6 | `0x00000040` | `CDISASM_X86_DECODE_FLAG_SSSE3` | SSSE3 |
| 7 | `0x00000080` | `CDISASM_X86_DECODE_FLAG_SSE4` | SSE4.1, SSE4.2, and SSE4a |
| 8 | `0x00000100` | `CDISASM_X86_DECODE_FLAG_AVX` | AVX |
| 9 | `0x00000200` | `CDISASM_X86_DECODE_FLAG_AVX2` | AVX2 |
| 10 | `0x00000400` | `CDISASM_X86_DECODE_FLAG_F16C` | F16C |
| 11 | `0x00000800` | `CDISASM_X86_DECODE_FLAG_FMA3` | FMA3 |
| 12 | `0x00001000` | `CDISASM_X86_DECODE_FLAG_XOP` | AMD XOP |
| 13 | `0x00002000` | `CDISASM_X86_DECODE_FLAG_FMA4` | AMD FMA4 |
| 14 | `0x00004000` | `CDISASM_X86_DECODE_FLAG_AES` | AES-NI and VAES |
| 15 | `0x00008000` | `CDISASM_X86_DECODE_FLAG_PCLMUL` | PCLMULQDQ and VPCLMULQDQ |
| 16 | `0x00010000` | `CDISASM_X86_DECODE_FLAG_SHA` | SHA and SHA-512 extensions |
| 17 | `0x00020000` | `CDISASM_X86_DECODE_FLAG_GFNI` | GFNI |
| 18 | `0x00040000` | `CDISASM_X86_DECODE_FLAG_BITMANIP` | LZCNT, POPCNT, TBM, BMI1/2, and ADX |
| 19 | `0x00080000` | `CDISASM_X86_DECODE_FLAG_AVX512` | AVX-512 families |
| 20 | `0x00100000` | `CDISASM_X86_DECODE_FLAG_AVX10` | Implemented AVX10.1/2 forms and AVX10-promoted classic K-mask forms |
| 21 | `0x00200000` | `CDISASM_X86_DECODE_FLAG_AMX` | Implemented AMX-TILE/INT8/BF16/FP16/COMPLEX/FP8/MOVRS/AVX512 forms |
| 22 | `0x00400000` | `CDISASM_X86_DECODE_FLAG_APX` | Implemented APX REX2 and EVEX NDD/NF forms |
| 23 | `0x00800000` | `CDISASM_X86_DECODE_FLAG_SMX` | Intel SMX (`GETSEC`) only; `CDISASM_X86_DECODE_FLAG_VIRTUALIZATION` is the historical exact alias |
| 24 | `0x01000000` | `CDISASM_X86_DECODE_FLAG_SYSTEM` | System/privileged facilities, including implemented RDPID/SERIALIZE/MOVDIR/WBNOINVD forms |
| 25 | `0x02000000` | `CDISASM_X86_DECODE_FLAG_CET` | CET indirect-branch tracking and shadow stack |
| 26 | `0x04000000` | `CDISASM_X86_DECODE_FLAG_STATE` | FXSAVE/FXRSTOR and XSAVE state-management families |
| 27 | `0x08000000` | `CDISASM_X86_DECODE_FLAG_TRANSACTIONAL` | HLE and RTM transactional forms |
| 28 | `0x10000000` | `CDISASM_X86_DECODE_FLAG_SECURITY` | RDRAND, RDSEED, SGX, and MPX |
| 29 | `0x20000000` | `CDISASM_X86_DECODE_FLAG_MEMORY_HINTS` | PAUSE, prefetch, CLFLUSH, CLFLUSHOPT, and CLWB |
| 30 | `0x40000000` | `CDISASM_X86_DECODE_FLAG_UNDOCUMENTED` | Undocumented/compatibility opcodes, including UD0/UD1 and LOADALL |
| 31 | `0x080000000` | `CDISASM_X86_DECODE_FLAG_SM3` | SM3 vector-crypto forms |
| 32 | `0x100000000` | `CDISASM_X86_DECODE_FLAG_SM4` | SM4 vector-crypto forms |
| 33 | `0x200000000` | `CDISASM_X86_DECODE_FLAG_AVX512_VBMI2` | Implemented AVX512VBMI2 forms, including double shifts |
| 34 | `0x400000000` | `CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ` | Implemented AVX512VPOPCNTDQ forms |
| 35 | `0x800000000` | `CDISASM_X86_DECODE_FLAG_AVX512_BITALG` | Implemented AVX512BITALG forms |
| 36 | `0x1000000000` | `CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND` | Exact EVEX byte/word/dword/qword COMPRESS/EXPAND class |
| 37 | `0x2000000000` | `CDISASM_X86_DECODE_FLAG_AVX512_IFMA` | Implemented AVX512IFMA forms |
| 38 | `0x4000000000` | `CDISASM_X86_DECODE_FLAG_AVX512_VBMI` | Implemented AVX512VBMI forms |
| 39 | `0x8000000000` | `CDISASM_X86_DECODE_FLAG_AVX512_VNNI` | Implemented AVX512VNNI forms |
| 40 | `0x10000000000` | `CDISASM_X86_DECODE_FLAG_VAES` | VAES forms (separate from scalar AES-NI) |
| 41 | `0x20000000000` | `CDISASM_X86_DECODE_FLAG_VPCLMULQDQ` | Vector PCLMULQDQ forms |
| 42 | `0x40000000000` | `CDISASM_X86_DECODE_FLAG_SHA512` | Vector SHA-512 forms |
| 43 | `0x80000000000` | `CDISASM_X86_DECODE_FLAG_AMX_TILE` | AMX tile configuration/load/store/zero forms |
| 44 | `0x100000000000` | `CDISASM_X86_DECODE_FLAG_AMX_INT8` | AMX INT8 forms |
| 45 | `0x200000000000` | `CDISASM_X86_DECODE_FLAG_AMX_BF16` | AMX BF16 forms |
| 46 | `0x400000000000` | `CDISASM_X86_DECODE_FLAG_AMX_FP16` | AMX FP16 forms |
| 47 | `0x800000000000` | `CDISASM_X86_DECODE_FLAG_AMX_COMPLEX` | AMX complex-number forms |
| 48 | `0x1000000000000` | `CDISASM_X86_DECODE_FLAG_AMX_FP8` | AMX FP8 forms |
| 49 | `0x2000000000000` | `CDISASM_X86_DECODE_FLAG_AMX_MOVRS` | AMX MOVRS tile-load forms |
| 50 | `0x4000000000000` | `CDISASM_X86_DECODE_FLAG_AMX_AVX512` | AMX row/AVX-512 transfer forms |
| 51 | `0x8000000000000` | `CDISASM_X86_DECODE_FLAG_AVX512_DQ` | Implemented AVX512DQ forms |
| 52 | `0x10000000000000` | `CDISASM_X86_DECODE_FLAG_AVX512_BW` | Implemented AVX512BW forms |
| 53 | `0x20000000000000` | `CDISASM_X86_DECODE_FLAG_VMX` | Intel VMX forms |
| 54 | `0x40000000000000` | `CDISASM_X86_DECODE_FLAG_SVM` | AMD SVM forms |
| 55 | `0x80000000000000` | `CDISASM_X86_DECODE_FLAG_SSE41` | SSE4.1 forms |
| 56 | `0x100000000000000` | `CDISASM_X86_DECODE_FLAG_SSE42` | SSE4.2 forms |
| 57 | `0x200000000000000` | `CDISASM_X86_DECODE_FLAG_SSE4A` | AMD SSE4a forms |
| 58 | `0x400000000000000` | `CDISASM_X86_DECODE_FLAG_BMI1` | BMI1 forms |
| 59 | `0x800000000000000` | `CDISASM_X86_DECODE_FLAG_BMI2` | BMI2 forms |
| 60 | `0x1000000000000000` | `CDISASM_X86_DECODE_FLAG_AVX512_CD` | Exact AVX-512CD conflict/leading-zero-count class |
| 61 | `0x2000000000000000` | `CDISASM_X86_DECODE_FLAG_AVX_VNNI` | Exact classic VEX AVX-VNNI dot-product row |
| 62 | `0x4000000000000000` | `CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8` | Exact classic VEX AVX-VNNI-INT8 dot-product row |
| 63 | `0x8000000000000000` | `CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16` | Exact classic VEX AVX-VNNI-INT16 dot-product row |

`CDISASM_X86_DECODE_FLAG_ALL` (also
`CDISASM_X86_DECODE_OPTION_ALL`) and the bitmap-0
`CDISASM_X86_DECODE_FLAG_KNOWN_MASK` remain `0xffffffffffffffff`.
`CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER` is the complete all-known-bits
object. In the current version-12 catalog, words 0--3 are full, bits 0--14 of
word 4 are assigned, and the remaining positions through logical ID 511 are
reserved. Every reserved bit must be zero; setting one reports
`CDISASM_STATUS_INVALID_ARGUMENT` rather than silently enabling a future
family. Generated exact ISA-set selectors currently occupy logical IDs through
270; later compatible releases may append further assignments.

The older version-11 scalar namespace was saturated. Version 11.23 therefore
used the AVX-512 umbrella for AVX512_4VNNIW, and version 11.24 did the same for
AVX512_4FMAPS. Both retain independent group-71 and group-72 Knights Mill CPU
capabilities. The version-12 `ALL` object is still an allow policy, not a
coverage or hardware claim. The original `AVX512`, `AES`, `PCLMUL`, `SHA`,
`AMX`, `SSE4`, and
`BITMANIP` bits remain backward-compatible umbrellas for their narrower
selectors; callers that need tighter policy can pass a specific bit without
its umbrella. `VIRTUALIZATION` retains bit 23 as an exact alias of `SMX`; it
does not admit VMX or SVM. Use `VMX` or `SVM` for hardware-virtualization
instructions. The readable `INTEL_VIRTUALIZATION` and `AMD_VIRTUALIZATION`
aliases name those same vendor-specific bits. Catalog-only families receive
no new selector until at least one instruction is implemented.
The decoder assigns most instructions to their most-specific selectable
family, so AES does not also require the SSE2 flag and AVX2 does not also
require AVX. The CPU profile still checks those architectural prerequisites.
An undocumented x87 instruction is the deliberate combined case and requires
both `FPU` and `UNDOCUMENTED`.

Nonzero x86 family bits are usable only in a build with
`USE_EXTRA_OPCODES=1`. Such a build accepts only the current known-mask subset
across all eight words. A `USE_EXTRA_OPCODES=0` build accepts only `NULL` or a
completely zero object; any set bit is `INVALID_ARGUMENT`. With a valid
zero object, a complete CPU-eligible non-base encoding is still structurally
owned and returns a zeroed `UNSUPPORTED_INSTRUCTION` result; reserved forms
remain `INVALID_INSTRUCTION` and incomplete forms remain `TRUNCATED`.

## Why choose cdisasm

No disassembler is best for every application. Capstone and LLVM are better
choices when one API must cover many architectures, while Zydis and LLVM have
much broader modern x86 instruction coverage than cdisasm currently provides.
cdisasm is the better fit when the target x86 processor is part of the input,
when retired or vendor-specific instructions must be filtered historically,
or when a small deterministic C ABI matters more than maximum ISA breadth.
Typical examples are firmware and ROM inspection, old executable analysis,
hypervisor tooling, binary translation, and checking a program's declared
minimum CPU. A modern decoder recognizing an opcode does not by itself prove
that the chosen historical processor could execute it or used the same
mnemonic.

### x86 opcode families still worth adding

The public family bitmap already has selectors for most of these areas. The
table tracks encoding coverage still to be added or widened; a selector being
present does not mean that every instruction in that family is implemented.

| Priority | Family to add or widen | Representative gaps | Implementation focus |
| --- | --- | --- | --- |
| P0 | VEX map coverage | Remaining `0F`, `0F 38`, and `0F 3A` arithmetic, compare, permute, convert, and load/store forms | Finish VEX2/VEX3 operand rules, tuple widths, `vvvv`, `L`, `W`, and exact CPU gates |
| P0 | EVEX / AVX-512 core | Remaining packed integer and floating-point arithmetic, compare, convert, permute, gather/scatter, and mask forms | Complete maps 1/2/3/5/6/7, `EVEX.b`, broadcast, SAE/rounding, `{k}` merge/zero, compressed displacement, and reserved-control rejection |
| P0 | FMA3/F16C/BMI permutations | Unimplemented scalar/packed FMA3 controls, F16C conversions, BMI1/BMI2 operand variants | Generate every valid opcode/control permutation and keep width-specific feature admission independent |
| P0 | XOP and FMA4 | Remaining AMD XOP map-8/map-9/map-A rows and FMA4 three-/four-operand forms | Add XOP map selection, `/is4`, `vvvv`, immediate fields, AMD-only CPU checks, and invalid-prefix handling |
| P1 | AVX-512 extension families | Broader `VBMI/VBMI2`, `VPOPCNTDQ`, `BITALG`, `IFMA`, `CD`, `VNNI`, `4VNNIW`, and `4FMAPS` | Fill remaining vector lengths, element widths, mask/broadcast combinations, and Knights Mill versus AVX-512F gates |
| P1 | AVX-512 FP16 and BF16 | Remaining `PH/SH`, BF16 arithmetic/conversions, and mixed-precision dot products | Model map-6 encodings, SAE/rounding, memory broadcast restrictions, and AVX10.2 versus AVX-512 admission |
| P1 | Vector crypto | Remaining AES/VAES, PCLMUL/VPCLMUL, SHA/SHA-512, GFNI, SM3, SM4, and newer hash/crypto forms | Keep scalar and vector selectors separate and add exact `W`, VL, immediate, and mask semantics |
| P1 | Gather/scatter and vector memory | Remaining AVX-512 gathers/scatters, masked fault-suppression, and prefetch variants | Extend the narrow AVX2 VSIB implementation to EVEX tuple/index/address-size rules, mask behavior, and 32-/64-bit mode differences |
| P1 | AMX | Remaining tile matrix, transpose, FP8, complex, MOVRS, and vector-transfer instructions | Extend tile-register operands and palette state while retaining independent AMX subfamily flags |
| P1 | APX | Remaining REX2, NDD/NF, extended-register, `PUSH2/POP2`, `CCMP/CTEST`, and APX-F forms | Add R16--R31 register/address fields, 64-bit-only checks, and collisions with legacy/VEX/EVEX encodings |
| P1 | AVX10 | Versioned AVX10.1/10.2 forms not covered by the current promoted rows | Represent version and vector-length policy explicitly; do not infer AVX-512 support from AVX10 support |
| P2 | Intel virtualization and platform system maps | Remaining VMX/VMFUNC/SEAM/TDX and system-management forms | Keep Intel VMX, SMX, and newer platform families distinct with privilege and mode validation |
| P2 | AMD virtualization and platform extensions | Remaining SVM, `MONITORX/MWAITX`, `RDPRU`, `CLZERO`, `INVLPGB`, SNP/SEV, and TBM rows | Keep AMD-only capability checks independent from Intel VMX and preserve vendor-specific invalid encodings |
| P2 | CET, FRED, user-interrupt, and MSR facilities | Remaining shadow-stack, `WRMSRNS/MSRLIST`, `UINTR`, `SERIALIZE`, and future control-transfer forms | Add system-map descriptors, privilege metadata, and APX/REX2 collision partitions |
| P2 | SGX, MPX, PKU, and memory-ordering facilities | Remaining enclave, bounds, protection-key, `CLDEMOTE`, `CLWB`, `WBNOINVD`, and wait-package forms | Complete system/security metadata and keep memory-hint families separate from ordinary loads/stores |
| P3 | Legacy and compatibility edge cases | Uncommon x87/MMX, BCD, 8086--286 protected-mode, aliases, and undocumented compatibility opcodes | Add only architecturally documented or deliberately classified encodings, with explicit `UNDOCUMENTED` gating |

Recommended order is P0 map/operand infrastructure first, then P1 modern vector,
AMX, APX, and AVX10 families, followed by P2 vendor/system extensions. Each
row should add descriptor data and focused positive, negative, CPU-gate, and
truncation tests before its family is marked complete.

The checked-in XED-backed fallback already contains the following requested
families when `USE_EXTRA_OPCODES=1`; the remaining work is to widen semantic
coverage and keep adding focused edge-case tests:

| Requested area | Current generated inventory |
| --- | ---: |
| VEX maps | 1,718 descriptors |
| EVEX maps / AVX-512 | 6,851 descriptors |
| FMA3, F16C, BMI1, BMI2 | 192, 8, 32, and 48 descriptors |
| XOP / FMA4 | 196 XOP-space descriptors and 128 FMA4 descriptors |
| AVX-512 FP16 / BF16 | 597 FP16 and 18 BF16 descriptors |
| AVX10.2 BF16 | 170 descriptors |
| AES, VAES, PCLMUL, VPCLMUL, SHA, SM3, SM4, GFNI | 12, 8, 2, 2, 17, 6, 20, and 6 descriptors |

The same generated fallback already covers the requested system and
next-generation groups:

| Requested area | Current generated inventory |
| --- | ---: |
| AMX | 33 descriptors across tile, INT8, BF16, FP16, complex, FP8, MOVRS, and transfer forms |
| APX | 2,460 descriptors, including REX2, NDD/NF, BMI, ADX, MOVBE, CMPCCXADD, CET, and system variants |
| AVX10 | 296 descriptors, including versioned BF16, MOVRS, and auxiliary rows |
| Intel VMX/system | VTX 20, VMFUNC 1, TDX 5, and APX-F VMX 2 descriptors |
| AMD SVM/platform | SVM 8, INVLPGB 3, MONITORX 5, MCOMMIT 1, CLZERO 1, and RDPRU 1 descriptors |
| CET/FRED/UINTR/MSR | CET 14, FRED 2, UINTR 5, MSRLIST 2, MSR-imm 2, USER_MSR 4, and WRMSRNS 1 descriptors |
| SGX/MPX/PKU | SGX 3, MPX 30, and PKU 2 descriptors |

The comparison below is about public integration models, not a claim that one
project is universally superior. Capstone's public x86 configuration exposes
16-, 32-, and 64-bit modes; the normal Zydis initializer accepts a machine mode
and stack width and offers individual compatibility switches rather than named
CPU generations; LLVM MC can accept CPU and feature strings through its
subtarget API. See the pinned [Capstone public header](https://github.com/capstone-engine/capstone/blob/862b59717d54769036f89fd9f780f634e030cf56/include/capstone/capstone.h),
[Zydis decoder API](https://doc.zydis.re/v4.1.1/html/Decoder_8h_source), and
[LLVM C disassembler API](https://llvm.org/doxygen/include_2llvm-c_2Disassembler_8h.html).

| Requirement | cdisasm 12.0 | Capstone x86 | Zydis | LLVM MC |
| --- | --- | --- | --- | --- |
| Built-in x86 target presets | 52 named nonzero profile values: 38 chronological introduction levels through APX, six exact no-AVX SKUs, four pre-486 CPU+external-x87 combinations, and Granite Rapids, Arrow Lake, Diamond Rapids, and Knights Mill physical presets (53 values including the unrestricted ordinal-zero profile) | Public x86 mode selects width, not a processor profile | Initializer selects machine mode and stack width; decoder modes control selected ambiguities | CPU and feature strings are available through the target/subtarget system |
| Vendor-aware availability check | Yes; Intel VMX, AMD SVM, 3DNow!, aliases, and dropped features are separate capabilities | No equivalent CPU argument in the normal x86 decode call | Selected behavior can be toggled, but there is no named chronological CPU argument | Possible through subtarget feature configuration |
| Retired-extension policy | Explicit and non-monotonic for implemented families | Decodes supported encodings without cdisasm-style target-profile filtering | Individual compatibility modes rather than historical CPU presets | Controlled by the selected subtarget/features |
| Decoder state and allocation | One stateless, allocation-free C call | Handle-based API; bulk and iterative decode APIs | Caller-owned decoder/result structures | Disassembler context plus target/subtarget objects |
| Text in the decoder core | No; the decoder emits IDs. Optional formatter sources and spelling tables are omitted with `USE_DISASM_FORMAT=OFF` | Text and optional detail are exposed by the same library | Decoder and formatter are separate APIs in the same project | `MCInst` and instruction-printer layers are separate components |
| Stable storage/FFI contract | Architecture-tagged, append-only ordinals; fixed result layouts; fixed 64-byte decode-flags object passed by pointer; ABI-major DLL suffix | Project-specific C ABI | Project-specific C ABI | C++ framework with a smaller C disassembler wrapper |
| Current coverage advantage | Historical targeting and the implemented legacy/virtualization subset | Much broader and multi-architecture | Much broader x86 coverage | Much broader and multi-architecture |

Version-11 audits use the pinned Capstone snapshot and current Intel XED as
independent comparison oracles for overlapping FMA, XOP, vector-crypto, EVEX,
CET, WAITPKG, VEX K-mask, classic VEX AVX-VNNI, AVX-VNNI-INT8,
AVX-VNNI-INT16, and Knights Mill AVX512_4VNNIW/AVX512_4FMAPS,
the exact AVX512F/AVX10.1 VGETEXP PS/PD/SS/SD tranche and the exact MAP6
AVX512-FP16/AVX10.1 PH/SH plus AVX10.2 BF16 forms,
packed-integer EVEX families through word/dword/qword
per-element variable shifts and rotates, immediate packed rotates and shifts,
  including the opcode-`71`/`73` shift groups, and the selected ARM SVE classes
  through predicated unary, predicated
  vector-shift, predicated immediate-shift, the SVE2/SME merging variable
  shift/saturating-round family, integer vector-compare, and integer
compare-with-immediate and floating compare-with-zero operations, plus the
F64MM Q-element SVE and fixed-width Advanced SIMD permutation classes, and the
bounded SVE/SME integer-to-floating and floating-point precision/integer
conversion classes, including the exact merging and zeroing BFCVT/BFCVTNT
single-vector forms.
Architectural specifications remain
authoritative; an oracle's omission is not evidence that an encoding is
invalid. Numeric mnemonic totals are ABI-catalog sizes, not directly
comparable instruction-coverage measurements.

A separate local Capstone 5.0.6 check recognized the twelve overlapping CET
shadow-stack mnemonics and the surrounding `UMONITOR`, NOP, `ADCX`, and `ADOX`
collisions. It described `CLRSSBSY` and `RSTORSSP` memory operands as 32-bit;
cdisasm deliberately emits 64-bit memory metadata because Intel specifies both
operands as `m64` in the [CLRSSBSY reference](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf)
and the [RSTORSSP reference](https://cdrdv2-public.intel.com/835781/325462-sdm-vol-1-2abcd-3abcd-4.pdf).
The collision and prefix rules were additionally checked against
[Intel XED's](https://github.com/intelxed/xed) current CET and WAITPKG tables:
non-CET `F3 0F 1E /r` forms remain WIDENOPs, a
redundant `66` may coexist with the mandatory CET `F3` selector, and REX2 map 1
promotes the WAITPKG and overlapping CET register forms to APX extended
registers.
The completed scalar EVEX-FMA3 table was likewise checked against current
Intel XED: all 192 valid controls and all 48 reserved controls agreed.

### Historical 5.4 comparison (not current 12.0 evidence)

The binary-size figures below are retained only as a historical cdisasm 5.4
snapshot, not as measurements of the current 12.0 tree or a universal
performance claim. They were recorded from x64 MSVC Release builds on 2026-08-25;
Capstone was pinned to `862b59717d54769036f89fd9f780f634e030cf56`
(`next`) and built separately with only the named architecture enabled. Compiler,
linker, debug information, and feature-selection changes can alter every size.
No checked-in reproduction driver exists for this old snapshot, so do not cite
its byte counts as current benchmark results. The corpus row counts describe the
current checked-in data and are independently verified by the test runners.

| Measured artifact or test data | cdisasm 5.4 snapshot | Pinned Capstone snapshot |
| --- | ---: | ---: |
| version-5.4 x86 decoder DLL | 55,296 bytes | 2,926,592 bytes |
| version-5.4 combined ARM decoder DLL (implemented A32/T32/A64 subset) | 27,136 bytes | 4,255,744-byte ARM DLL and 7,566,336-byte AArch64 DLL |
| all four version-5.4 cdisasm DLLs | 123,904 bytes | Not comparable: Capstone uses a different library split |
| checked-in x86 data corpus | 5,126 rows plus native unit suites | 18 YAML streams / 2,745 expected instructions |
| checked-in ARM data corpus | 3,541 rows plus native A32/T32/A64/Apple unit suites | 144 ARM streams / 9,584 instructions; 1,012 AArch64 streams / 34,770 instructions |

This table records that the historical 5.4 build produced smaller binaries; it
does not establish the size of the current library. cdisasm exposes historical
CPU filtering directly, while Capstone has substantially broader instruction
coverage and a much larger upstream regression inventory. The corpus rows and
Capstone stream/instruction counts are inventories, not equivalent coverage
units. Choose cdisasm for the former constraints and Capstone for breadth.

### Why numeric CPU defines are useful

`CDISASM_CPU_*` values describe the code being inspected, not the processor
running the disassembler. This is important for cross-analysis: decoding an
80386 ROM on a modern Zen or Intel machine must still apply 80386 rules. A
misspelled constant is a build error rather than an unrecognized runtime CPU
string; the numeric value is also inexpensive to pass across an FFI, easy to
store in a trace or database, and needs no CPU-name parser. The same input
therefore produces the same result on every host.

Version 6 CPU IDs have a common 32-bit layout. The upper 16 bits identify the
architecture and the lower 16 bits hold the stable, architecture-local ordinal:

| Architecture | Group define | Group value | Generic profile | First named example | Last current profile |
| --- | --- | ---: | ---: | ---: | ---: |
| x86 | `CDISASM_CPU_GROUP_X86` | `0x00010000` | `CDISASM_CPU_X86 = group \| 0x0000` | `CDISASM_CPU_8086 = group \| 0x0001` | `CDISASM_CPU_LAST = group \| 0x0034` |
| ARM | `CDISASM_CPU_GROUP_ARM` | `0x00020000` | `CDISASM_ARM_CPU_ANY = group \| 0x0000` | `CDISASM_ARM_CPU_ARM7TDMI = group \| 0x0001` | `CDISASM_ARM_CPU_LAST = group \| 0x0026` |

`CDISASM_CPU_GROUP_OF(id)` and `CDISASM_CPU_ORDINAL_OF(id)` extract those
fields using `CDISASM_CPU_GROUP_MASK` and `CDISASM_CPU_ORDINAL_MASK`. Thus the
full x86 80386 ID is `0x00010004`, while the full ARM Cortex-A32 ID is
`0x00020004`; equal ordinals no longer collide across architectures. The
generic profiles are not numeric zero: they are their architecture group ORed
with ordinal zero.

### Detecting the caller-visible CPU profile

`cdisasm_current_cpu()` returns the closest **named catalog profile** that
cdisasm can identify for the instruction environment visible to the calling
process. It returns `CDISASM_CPU_UNKNOWN` (`0`) when the enabled build has no
reliable catalog match. The query never returns the unrestricted
`CDISASM_CPU_X86` or `CDISASM_ARM_CPU_ANY` profiles: those are explicit analysis
choices, not physical processors.

```c
cdisasm_cpu_id cpu_id = cdisasm_current_cpu();

if (cpu_id == CDISASM_CPU_UNKNOWN) {
    /* Select an explicit target profile or decline host-targeted decoding. */
}
```

The result is advisory and does not select a decoder, mode, endian option, or
x86 runtime-family bitmap. Pass the returned ID explicitly to the appropriate
mode/flag query and decode function. In particular, detecting an AVX-, VMX-,
SVM-, SVE-, or SME-capable catalog profile does not enable that optional decode
family and does not prove that the operating system has enabled all execution
state needed to run such instructions.

Detection describes the process-visible or guest-visible CPU contract, which
can differ from the processor's retail name or the physical host behind a
hypervisor, compatibility layer, or virtual machine. CPUID may be masked or
synthesized, OS APIs may omit a feature, and a VM can expose a deliberately
older virtual CPU. Callers analyzing code for another machine should continue
to pass that target's explicit `CDISASM_CPU_*` profile instead.

ARM identification is necessarily best effort. Linux exposes a per-CPU
`MIDR_EL1` value only when the kernel and environment permit it; heterogeneous
cores, unavailable sysfs entries, or an unrecognized implementer/part can
prevent an exact catalog match. Darwin uses numeric `sysctl` CPU-family data
and, where available, its processor brand information; those values are not an
ordered feature hierarchy and future Apple families may be unknown to an older
cdisasm build. Legacy Darwin Cortex-A8 and Cortex-A9 families map to the Apple
A4 and A5 profiles; the legacy Cortex-A7 family uses the conservative generic
Cortex-A7 profile. S-series IDs require a matching `Apple S#` brand because no
distinct public family values identify them. When a family is shared by an
A-series and M-series design and
the brand is unavailable, detection selects the conservative A-series ISA
profile instead of assuming M-series-only Apple AMX. Unresolved cases return
`CDISASM_CPU_UNKNOWN` rather than silently selecting `CPU_ANY`.

Within the original chronological x86 profiles (ordinals 1--38), 32-bit mode
starts at `CDISASM_CPU_80386` and 64-bit mode at
`CDISASM_CPU_ATHLON_64`. Appended exact, CPU+coprocessor, and server-generation
profiles make a raw comparison invalid for the full namespace, so the decoder
uses explicit mode metadata for every profile. Instruction availability
likewise uses independent capability bits rather than assuming that a
numerically later ID contains every earlier feature. APX remains the end of
the original chronological sequence at ordinal 38 (`0x00010026`); exact no-AVX profiles occupy
ordinals 39--44, optional pre-486 x87 combinations occupy ordinals 45--48,
Granite Rapids is ordinal 49, Arrow Lake is ordinal 50, Diamond Rapids is
ordinal 51, and the appended exact Knights Mill profile is ordinal 52.
`CDISASM_CPU_LATEST` remains Diamond Rapids (`0x00010033`), the latest
chronological preset represented here, while `CDISASM_CPU_LAST` is Knights Mill
(`0x00010034`), the numeric enumeration bound. Neither define means that every
earlier or vendor-specific capability is present.

The tradeoff is intentional: these IDs are fixed, reviewed presets rather than
an arbitrary CPUID-feature builder. LLVM MC's CPU/feature strings and Zydis's
individual decoder modes are a better fit when a caller must construct unusual
combinations or control one ambiguity directly. cdisasm's defines are better
when a compact, reproducible historical target is the desired contract.

The version-5.4 profiles name exact processor models because "Celeron" is a
market family, not an ISA contract. Different Celeron generations expose
different extensions, so a generic Celeron preset would either enable
instructions missing from some models or unnecessarily disable instructions
present on others. All six profiles below allow 16-, 32-, and 64-bit modes and
SSE through SSE4.2, but leave AVX disabled:

| Ordinal | Composite ID (v6+) | Exact profile | Intel generation / launch | x86-64 | SSE4.2 | AVX |
| ---: | ---: | --- | --- | :---: | :---: | :---: |
| 39 | `0x00010027` | [`CDISASM_CPU_CELERON_G1840`](https://www.intel.com/content/www/us/en/products/sku/80800/intel-celeron-processor-g1840-2m-cache-2-80-ghz/specifications.html) | Haswell, 2014 | yes | yes | no |
| 40 | `0x00010028` | [`CDISASM_CPU_CELERON_G3900`](https://www.intel.com/content/www/us/en/products/sku/90741/intel-celeron-processor-g3900-2m-cache-2-80-ghz/specifications.html) | Skylake, 2015 | yes | yes | no |
| 41 | `0x00010029` | [`CDISASM_CPU_CELERON_N3350`](https://www.intel.com/content/www/us/en/products/sku/95598/intel-celeron-processor-n3350-2m-cache-up-to-2-40-ghz/specifications.html) | Apollo Lake, 2016 | yes | yes | no |
| 42 | `0x0001002a` | [`CDISASM_CPU_CELERON_N4020`](https://www.intel.com/content/www/us/en/products/sku/197310/intel-celeron-processor-n4020-4m-cache-up-to-2-80-ghz/specifications.html) | Gemini Lake Refresh, 2019 | yes | yes | no |
| 43 | `0x0001002b` | [`CDISASM_CPU_CELERON_G5900`](https://www.intel.com/content/www/us/en/products/sku/199268/intel-celeron-processor-g5900-2m-cache-3-40-ghz/specifications.html) | Comet Lake, 2020 | yes | yes | no |
| 44 | `0x0001002c` | [`CDISASM_CPU_PENTIUM_SILVER_N6000`](https://www.intel.com/content/www/us/en/products/sku/212330/intel-pentium-silver-n6000-processor-4m-cache-up-to-3-30-ghz/specifications.html) | Jasper Lake, 2021 | yes | yes | no |

Same-capability aliases cover the [Celeron J4125](https://www.intel.com/content/www/us/en/products/sku/197305/intel-celeron-processor-j4125-4m-cache-up-to-2-70-ghz/specifications.html)
(`CDISASM_CPU_CELERON_J4125`, ordinal 42),
[Celeron G5905](https://www.intel.com/content/www/us/en/products/sku/201899/intel-celeron-processor-g5905-4m-cache-3-50-ghz/specifications.html)
(`CDISASM_CPU_CELERON_G5905`, ordinal 43), and
[Celeron N5105](https://www.intel.com/content/www/us/en/products/sku/212328/intel-celeron-processor-n5105-4m-cache-up-to-2-90-ghz/specifications.html)
(`CDISASM_CPU_CELERON_N5105`, ordinal 44). Generation-style aliases are also
provided, but there is deliberately no catch-all `CDISASM_CPU_CELERON`.

The optional crypto capabilities are also SKU-specific and do not imply AVX.
When `USE_EXTRA_OPCODES=1` and the corresponding `AES`, `PCLMUL`, or `SHA`
runtime bit is present, G3900 and G5900 accept the implemented AES-NI and
PCLMULQDQ forms but not SHA; N3350, N4020, and N6000 accept the implemented
AES-NI, PCLMULQDQ, and SHA forms while still rejecting AVX. G1840 accepts none
of these optional crypto families. With `USE_EXTRA_OPCODES=0`, all of these
new crypto semantics are unsupported regardless of profile.

| Exact no-AVX profile | Implemented AES-NI | Implemented PCLMULQDQ | Implemented SHA |
| --- | :---: | :---: | :---: |
| G1840 | no | no | no |
| G3900, G5900 | yes | yes | no |
| N3350, N4020, N6000 | yes | yes | yes |

Pre-80486 x87 was an optional external coprocessor, so selecting a plain CPU
profile does not silently assume one. Four append-only combination profiles
make that hardware choice explicit while keeping the host CPU's integer ISA
and mode limits independent from the coprocessor generation:

| Ordinal | Profile | Host modes | x87 level |
| ---: | --- | --- | --- |
| 45 | `CDISASM_CPU_8086_8087` (`8088_8087` alias) | 16-bit | 8087 base |
| 46 | `CDISASM_CPU_80186_80187` | 16-bit | 80C187 full 80387-compatible instruction set |
| 47 | `CDISASM_CPU_80286_80287` (`286_287` alias) | 16-bit | 80287 additions |
| 48 | `CDISASM_CPU_80386_80387` (`386_387` alias) | 16/32-bit | 80387 additions |

`CDISASM_CPU_GRANITE_RAPIDS` is the appended ordinal-49 server-generation
profile. It has explicit 16/32/64-bit decode-mode metadata and independently
exposes the implemented AVX10.1 and AMX-FP16 forms. Its numeric position after
the old CPU/coprocessor profiles is append order, not a chronological comparison.

Plain 8086 through 80386 profiles reject x87 instructions. The 80486 and later
milestone profiles include the integrated 80387-level FPU, and
`CDISASM_CPU_X86` remains unrestricted at the CPU-capability gate. Successful
x87 decode still requires `USE_EXTRA_OPCODES=1` and the `FPU` runtime bit. This
mirrors the separate ARM Cortex-A7/A9-with-NEON profiles: optional hardware is
part of the selected target rather than inferred from the product family.

[Intel documents](https://www.intel.com/content/www/us/en/support/articles/000057621/processors.html)
the product specification's **Instruction Set Extensions** field as the place
to determine SSE and AVX support. The absence of AVX in these exact profiles is
therefore intentional, not inferred from their price tier or brand. The
presets remain conservative for implemented cdisasm families and are not
substitutes for a complete CPUID dump.

This is a case where processor gating answers a question that Capstone's normal
x86 mode-only decode cannot. In 64-bit mode Capstone can correctly identify
`C5 F8 77` as `VZEROUPPER`, but the mode does not say whether the deployment
processor implements AVX. With `USE_EXTRA_OPCODES=1` and the `AVX` allow bit,
cdisasm accepts those bytes for Sandy Bridge and rejects them for all six exact
profiles while continuing to accept their implemented SSE4.2 forms when the
`SSE4` bit is selected.

### Why CPU cutoffs and text formatting are separate

A mode cutoff answers a narrow monotonic question before opcode policy is
considered: an 8086 cannot execute 32-bit code, and a Pentium 4 cannot execute
64-bit code. Rejecting an impossible CPU/mode pair at the API boundary prevents
the decoder from producing plausible-looking instructions for a machine that
cannot enter that instruction state. Instruction features are then checked by
independent vendor-aware capability bits, because chronology alone is not a
valid feature test.

The decoder also stops at structured numeric metadata. It does not allocate a
mnemonic string, repeatedly convert registers to text, or discard information
that an analyzer must parse back out. A caller doing control-flow analysis,
indexing, emulation, or CPU-compatibility checks can compare IDs and consume
typed operands directly. Builds that display assembly enable
`USE_DISASM_FORMAT` and call `cdisasm_x86_format` or `cdisasm_arm_format`; one
decoded result may be formatted later, in another thread, or not at all.

| Workload | Coupled decode-and-string path | cdisasm split path |
| --- | --- | --- |
| Control-flow scan | Builds text that is never shown | Reads branch groups and numeric targets only |
| Register/data-flow analysis | Parses register spellings back into meaning | Reads stable register IDs and access flags |
| Database or FFI record | Stores locale/syntax-sensitive text or reparses it | Stores fixed-width IDs and operands |
| Interactive disassembly | Text is immediately available | Calls the optional formatter explicitly |

This separation does not guarantee that every workload is faster; actual speed
depends on the input and compiler. It removes avoidable text work from
non-display workloads and keeps syntax policy outside the correctness-critical
decoder core.

| Tempting but incorrect rule | Incorrect consequence | cdisasm rule |
| --- | --- | --- |
| `cpu_id >= CDISASM_CPU_PENTIUM_PRO` means CMOV exists | Pentium MMX is numerically later but does not provide the P6 CMOV feature | Test the P6/CMOV capability |
| `cpu_id >= CDISASM_CPU_AMD_K6_2` means 3DNow! exists forever | It would enable an AMD-only extension on Intel CPUs and on later AMD families that dropped it | Track base and Extended 3DNow! independently and remove them from Bulldozer/Zen profiles |
| Every virtualization-capable CPU accepts VMX and SVM | It would decode Intel `VMCALL` on AMD and AMD `VMRUN` on Intel | Keep SMX, VMX, and SVM as separate CPU capabilities and runtime selectors |
| A later CPU always keeps every earlier alias meaning | It would miss NOP/PAUSE, BSF/TZCNT, BSR/LZCNT, and VMMCALL/VMGEXIT transitions | Select the effective mnemonic from the target capability set |
| Host CPUID determines what bytes mean | Results would change with the workstation running the analysis | Require an explicit target CPU ID; use `cdisasm_current_cpu()` only when the caller intentionally targets its local process-visible environment, and use `CDISASM_CPU_X86` only for unrestricted analysis with the intended runtime allow bitmap |

The practical effect is visible when identical bytes are decoded for different
targets. These rows assume `USE_EXTRA_OPCODES=1` and the listed runtime mask.
`INVALID_ARGUMENT` below means that the CPU/mode pairing itself is impossible;
`INVALID_INSTRUCTION` means that the bytes were structurally decoded but the
selected CPU lacks the required capability.

| Bytes | Mode | CPU profile | Required x86 mask | Result |
| --- | ---: | --- | --- | --- |
| `90` | 32 | `CDISASM_CPU_8086` | `BASE` | `INVALID_ARGUMENT` — the target has no 32-bit mode |
| `90` | 32 | `CDISASM_CPU_80386` | `BASE` | `nop` |
| `90` | 64 | `CDISASM_CPU_PENTIUM_4` | `BASE` | `INVALID_ARGUMENT` — the target has no long mode |
| `90` | 64 | `CDISASM_CPU_ATHLON_64` | `BASE` | `nop` |
| `0F A2` | 32 | `CDISASM_CPU_80486` | `SYSTEM` | `INVALID_INSTRUCTION` — this profile predates CPUID |
| `0F A2` | 32 | `CDISASM_CPU_80486_CPUID` | `SYSTEM` | `cpuid` |
| `F3 90` | 32 | `CDISASM_CPU_PENTIUM_III` | `BASE` | `nop` |
| `F3 90` | 32 | `CDISASM_CPU_PENTIUM_4` | `MEMORY_HINTS` | `pause` |
| `F3 0F BC C3` | 32 | `CDISASM_CPU_IVY_BRIDGE` | `BASE` | `bsf eax, ebx` |
| `F3 0F BC C3` | 32 | `CDISASM_CPU_HASWELL` | `BITMANIP` | `tzcnt eax, ebx` |
| `F2 0F 38 F0 C1` | 64 | `CDISASM_CPU_CELERON_N4020` | `SSE4` | `crc32 eax, cl` — SSE4.2 remains available |
| `C5 F8 77` | 64 | `CDISASM_CPU_SANDY_BRIDGE` | `AVX` | `vzeroupper` — AVX is available |
| `C5 F8 77` | 64 | `CDISASM_CPU_CELERON_N4020` | `AVX` | `INVALID_INSTRUCTION` — this exact modern SKU has no AVX |
| `C5 F8 77` | 64 | `CDISASM_CPU_PENTIUM_SILVER_N6000` | `AVX` | `INVALID_INSTRUCTION` — this exact modern SKU has no AVX |
| `0F 0F C1 0C` | 32 | `CDISASM_CPU_AMD_K6_2` | `3DNOW` | `INVALID_INSTRUCTION` — Extended 3DNow! is unavailable |
| `0F 0F C1 0C` | 32 | `CDISASM_CPU_ATHLON_64` | `3DNOW` | `pi2fw mm0, mm1` |
| `0F 0F C1 0C` | 32 | `CDISASM_CPU_AMD_BULLDOZER` | `3DNOW` | `INVALID_INSTRUCTION` — 3DNow! was dropped |
| `0F 01 C1` | 32 | `CDISASM_CPU_INTEL_VT_X` | `VMX` | `vmcall` |
| `0F 01 C1` | 32 | `CDISASM_CPU_AMD_V` | `VMX` | `INVALID_INSTRUCTION` — VMX is Intel-specific |
| `0F 01 C1` | 32 | `CDISASM_CPU_X86` | `SVM` | `UNSUPPORTED_INSTRUCTION` — the Intel runtime family is not selected |
| `0F 01 D8` | 64 | `CDISASM_CPU_AMD_V` | `SVM` | `vmrun rax` |
| `0F 01 D8` | 64 | `CDISASM_CPU_INTEL_VT_X` | `SVM` | `INVALID_INSTRUCTION` — SVM is AMD-specific |
| `0F 01 D8` | 64 | `CDISASM_CPU_X86` | `VMX` | `UNSUPPORTED_INSTRUCTION` — the AMD runtime family is not selected |
| `0F 37` | 32 | `CDISASM_CPU_CORE_2` | `SMX` | `getsec` |
| `0F 37` | 32 | `CDISASM_CPU_X86` | `VMX` | `UNSUPPORTED_INSTRUCTION` — SMX is independently selected |
| `0F 05` | 16 | `CDISASM_CPU_80286` | `UNDOCUMENTED` | `loadall286` |
| `0F 05` | 64 | `CDISASM_CPU_X86` | `SYSTEM` | `syscall` |
| `C0 F0` | 16 | `CDISASM_CPU_8086` | `BASE` | `TRUNCATED` — the immediate byte is missing |
| `C0 F0 01` | 16 | `CDISASM_CPU_8086` | `BASE` | `INVALID_INSTRUCTION` — the complete form requires 80186 |

This filtering occurs after structural decoding. A missing ModRM, SIB,
displacement, immediate, or 3DNow! selector still reports
`CDISASM_STATUS_TRUNCATED`, even when the selected CPU would reject the
completed instruction. That precedence makes stream recovery and malformed
input diagnostics deterministic.

The CPU profiles are conservative decoder presets, not complete processor
emulators. The six version-5.4 constants intentionally model named SKUs; the
other constants remain introduction-level profiles. None inspect host CPUID,
model individual steppings, or represent runtime state such as CPL, control
registers, SMM, or VMX/SVM enablement. They filter only instruction families
implemented by cdisasm.
`CDISASM_CPU_X86` means unrestricted CPU capability within cdisasm's implemented
coverage, not a physical generic processor. It still obeys the runtime allow
mask, and an `APX` profile name does not imply that every APX encoding is
already implemented.

## ARM CPU and mode model

ARM processor IDs are stable profile keys. Unlike x86's legacy mode thresholds,
they are **not ordered cutoffs**. Do not write
`cpu_id >= CDISASM_ARM_CPU_CORTEX_A35` to infer A64 support. Cortex-A32 is a
later Armv8-A product with only AArch32, Cortex-A34 is AArch64-only, and
Cortex-A35/A53 support both execution states. Query
`cdisasm_arm_cpu_mode_mask()` for physical execution states,
`cdisasm_arm_decoder_mode_mask()` for states implemented by this decoder, or
pass the exact CPU and mode to `cdisasm_arm_decode()`.

The mode values name instruction-set states rather than instruction widths:

- `CDISASM_ARM_MODE_A32` decodes the fixed-width 32-bit A32 instruction set.
- `CDISASM_ARM_MODE_T32` decodes implemented 16- and 32-bit Thumb forms and
  returns the actual two- or four-byte instruction width.
- `CDISASM_ARM_MODE_A64` decodes the fixed-width 32-bit A64 instruction set in
  the 64-bit execution state.

The physical CPU-state mask is:

| ARM CPU profile | A32 mask | T32 mask | A64 mask |
| --- | :---: | :---: | :---: |
| `CDISASM_ARM_CPU_ANY` | yes | yes | yes |
| `CDISASM_ARM_CPU_ARM7TDMI` | yes | yes | no |
| `CDISASM_ARM_CPU_CORTEX_A7` | yes | yes | no |
| `CDISASM_ARM_CPU_CORTEX_A7_NEON` | yes | yes | no |
| `CDISASM_ARM_CPU_CORTEX_A9` | yes | yes | no |
| `CDISASM_ARM_CPU_CORTEX_A9_NEON` | yes | yes | no |
| `CDISASM_ARM_CPU_CORTEX_A32` | yes | yes | no |
| `CDISASM_ARM_CPU_CORTEX_A34` | no | no | yes |
| `CDISASM_ARM_CPU_CORTEX_A35` | yes | yes | yes |
| `CDISASM_ARM_CPU_CORTEX_A53` | yes | yes | yes |
| Apple A4--A6 | yes | yes | no |
| Apple A7--A10 | yes | yes | yes |
| Apple A11--A19 | no | no | yes |
| Apple M1--M5 | no | no | yes |
| Apple S4--S10 | no | no | yes |
| Fujitsu A64FX | no | no | yes |

`cdisasm_arm_cpu_mode_mask()` returns this hardware table.
`cdisasm_arm_decoder_mode_mask()` intersects it with the states compiled into
the decoder; the current build implements A32, T32, and A64, so the two masks
currently match. Keeping the queries separate prevents a future hardware-state
entry from being mistaken for decoder coverage. `CDISASM_ARM_CPU_ANY` is
`CDISASM_CPU_GROUP_ARM | 0x0000`, the unrestricted ARM decoder profile, not a
physical processor. An invalid
ID returns `CDISASM_ARM_MODE_MASK_NONE`. A decode with a valid CPU but impossible
state, such as A64 on Cortex-A7 or A32 on Cortex-A34, reports
`CDISASM_STATUS_INVALID_ARGUMENT`.

The base Cortex-A7 and Cortex-A9 profiles are deliberately conservative:
their NEON blocks were optional implementation choices. Select the appended
`CDISASM_ARM_CPU_CORTEX_A7_NEON` or
`CDISASM_ARM_CPU_CORTEX_A9_NEON` profile only when that block is known to be
present. CPU mode and per-instruction SIMD availability are independent
queries; a valid A32/T32 mode does not by itself promise NEON.

Apple opcode availability is also separate from the A64 mode bit. A CPU can
execute A64 while lacking a particular Apple extension. The current policy is:

| Numeric instruction family | Enabled physical profiles | Why the cutoff matters |
| --- | --- | --- |
| Cyclone `CPM_IOACC_CTL_EL3` through `MRS`/`MSR` | Apple A7 only | LLVM describes this as a Cyclone-specific system register; later Apple IDs are not assumed equivalent |
| `MUL53LO.2D`, `MUL53HI.2D` | Apple A11--A19 and M1--M5 | The reverse-engineered encoding is documented as introduced by A11 |
| 24 Apple AMX mnemonics | M1--M4 | The checked source reports testing through M4 and warns that older/newer chips may differ; M5 therefore remains disabled until verified |
| `WKDMC`, `WKDMD`, `GENTER`, `GEXIT`, `AT_AS1ELX`, `SDSB` | M1--M5 | Their public reverse-engineering does not provide an A- or S-series cutoff, so those families are not guessed |
| Any implemented Apple encoding | `CDISASM_ARM_CPU_ANY` | Explicit unrestricted analysis mode for unknown dumps or forward investigation |

The standard architectural extensions in the modern tranche have their own
exact profile entries, all effective only when `USE_EXTRA_OPCODES=1`. Apple
A18 and M4 expose the implemented SME/SME2 representatives; this does not
implicitly enable SME on A19 or M5. Apple S4--S10 expose the implemented FP16
and pointer-authentication representatives. Fujitsu A64FX is AArch64-only and
exposes SVE, but not SVE2, SME, or CPA; this follows Fujitsu's
[A64FX datasheet](https://www.fujitsu.com/downloads/SUPER/a64fx/a64fx_datasheet_en.pdf).
These are explicit capability
assignments, not `cpu_id >= ...` comparisons, so newer-looking or numerically
larger profile IDs do not inherit them automatically. `CDISASM_ARM_CPU_ANY`
remains the unrestricted choice for every implemented optional family.

This is stricter than Capstone's single `+apple` mode, which enables AMX,
MUL53, and AppleSys together without a processor-generation argument. The
separate cdisasm capability bits let a scanner distinguish “known encoding but
wrong selected CPU” (`INVALID_INSTRUCTION`) from “not implemented/unknown
encoding” (`UNSUPPORTED_INSTRUCTION`). That distinction is useful when
checking a binary's minimum target or avoiding false positives in arbitrary
data. The descriptor table still recognizes the encoding before CPU policy is
applied, so changing a future profile cutoff does not renumber IDs or alter the
result ABI. See the pinned [Capstone Apple change](https://github.com/capstone-engine/capstone/pull/2692),
the [Asahi Apple instruction map](https://github.com/AsahiLinux/docs/blob/main/docs/hw/cpu/apple-instructions.md),
the [MUL53 investigation](https://gist.github.com/TrungNguyen1909/5b323edda9a21550a1621af506e8ce5f),
and the [AMX hardware study](https://github.com/corsix/amx).
The checked cutoff evidence, conservative promotion rule, and M5 recheck are
recorded in [`docs/APPLE_CPU_EVIDENCE.md`](docs/APPLE_CPU_EVIDENCE.md).

These profile distinctions follow Arm's published
[Cortex-A comparison table](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Cortex-A%20R%20M%20datasheets/Arm%20Cortex-A%20Comparison%20Table_v4.pdf).
Arm also describes Cortex-A32 as
[A32/T32-only](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/introducing-cortex-a32-arm-s-smallest-lowest-power-armv8-a-processor-for-next-generation-32-bit-embedded-applications),
Cortex-A35 as supporting
[A32/T32 and A64](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/introducing-cortex-a35-arm-s-most-efficient-application-processor),
and Cortex-A53 as supporting
[AArch32 and AArch64](https://developer.arm.com/compute-ip/cortex-a53).

The ARM decoder consumes little-endian instruction bytes by default. Passing
an ARM flags object containing `CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN` in
bitmap 0 reads A32/A64 as a big-endian 32-bit word and T32 as a sequence of
big-endian 16-bit halfwords, so the first Thumb halfword remains first for a
32-bit instruction. `NULL` or `CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER`
selects the default little-endian representation. A32 and A64 consume four
bytes; T32 determines a two- or four-byte width from the first halfword and
reports `TRUNCATED` when the selected encoding is incomplete. Equivalent
little- and big-endian encodings produce identical semantic metadata. For T32,
`CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK` tells the one-instruction API that the
instruction is inside an active IT block; this is required to select exact
state-dependent aliases and flag-setting semantics. The option is rejected in
A32/A64. Decoder bits are architecture-specific: ARM logical bits 0 and 1 are
byte order and T32 IT state, whereas x86 logical bit 0 is
`CDISASM_X86_DECODE_BIT_FPU`. Generic dispatch forwards the complete 64-byte
object without translating it. ARM requires every remaining reserved bit in
bitmap 0 and every bit in words 1--7 to be zero.
`cdisasm_arm_cpu_decode_flag_mask(cpu_id, mode, &flags)` and generic
`cdisasm_cpu_decode_flag_mask` clear their output first, return
`CDISASM_STATUS_INVALID_ARGUMENT` for an invalid request, and expose
BIG_ENDIAN for every valid ARM CPU/mode pair plus IN_IT_BLOCK for T32. Decoder
results contain numeric
`CDISASM_ARM_NAME_*` and
`CDISASM_ARM_REG_*` IDs, raw encoding, condition, ISA, branch, data-flow, shift,
extend, memory, register-list, and writeback metadata. Text remains a separate
optional API: `USE_DISASM_FORMAT=ON` adds `cdisasm_arm_format` to the core
library for canonical A32, T32, and A64 assembly.

Initial A32 coverage includes conditional data processing, shifted register and
rotated-immediate forms, B/BL, BX/BLX, SVC, BKPT, LDR/STR byte and word forms
(including unprivileged T variants),
LDM/STM, PUSH/POP, and NOP. T32 coverage includes common 16-bit data-processing,
high-register, load/store, address-generation, stack/multiple-transfer,
exception, and branch forms, plus 32-bit BL. A32 and T32 also decode selected
packed NEON integer, bitwise, and floating-point operations. Initial A64
coverage includes B/BL and conditional,
compare, and test branches; BR/BLR/RET; ADR/ADRP; add/subtract immediate;
logical shifted-register and move aliases; MOVN/MOVZ/MOVK; scaled and unscaled
loads/stores; load/store pairs; NOP; SVC/HVC/SMC/BRK; selected packed
Advanced SIMD integer, bitwise, and floating-point operations; ARMv8.0
`LDAR`/`STLR`, `LDXR`/`LDAXR`, `STXR`/`STLXR`, and their byte, halfword, and
pair variants; and the CPU-gated Apple A64 extensions listed above.

Every addition in the following modern ARM tranche is present only with
`USE_EXTRA_OPCODES=1`:

- Common A64 scalar-register forms now include shifted-register `ADD`/`SUB`,
  carry arithmetic, conditional selects and their canonical aliases,
  signed/unsigned division, variable shifts/rotate, and multiply-add/subtract.
  Reserved shift encodings are rejected before the optional-feature gate, and
  all register-31 uses retain the instruction-specific ZR semantics.
- The A64 logical-immediate family includes W/X `AND`, `ORR`, `EOR`, and
  flag-setting `ANDS`, with canonical `TST` and bitmask-`MOV` aliases. Bitmask
  legality and move-wide preference are resolved before formatting; source 31
  is ZR, non-flag-setting destination 31 is SP, and `ANDS` destination 31 is
  the omitted destination of `TST`.
- Broader representative A32/T32 core forms include multiply-accumulate,
  `MOVW`/`MOVT`, `CLZ`/`REV`, signed loads, barriers, Thumb `IT`, division,
  and selected wider shifts, together with representative VFP and NEON
  multiply/add/divide forms.
- Wider A64 FP/Advanced SIMD coverage includes representative FP16 scalar
  operations, fused arithmetic, comparisons/selects, and signed/unsigned
  vector min/max forms.
- SVE representatives cover predicate creation and loop predicates, vector
  length queries, predicated and unpredicated arithmetic, and contiguous
  load/store forms. The complete 15-operation predicate-logical submap covers
  `AND/ANDS`, `BIC/BICS`, `EOR/EORS`, `NAND/NANDS`, `NOR/NORS`, `ORR/ORRS`,
  `ORN/ORNS`, and `SEL`, including typed predicate operands, zeroing/select
  guard metadata, and flag-setting forms. SVE2 representatives include
  `ADCLB`, `ADCLT`, `EOR3`, `RAX1`, and `SQRDMLAH`.
- The exact non-saturating SVE/SME element-count family covers all eighteen
  forms 2374--2391: vector `INCH`/`DECH`, `INCW`/`DECW`, and `INCD`/`DECD`;
  scalar `CNTB`/`CNTH`/`CNTW`/`CNTD`; and scalar `INCB`/`DECB` through
  `INCD`/`DECD`. Destructive destinations are read/write, `CNT*` destinations
  are write-only, and scalar register 31 is XZR. The raw five-bit pattern and
  one-through-sixteen multiplier are separate immediate operands; canonical
  text names standard patterns, retains numeric patterns, and omits the
  default `all, mul #1`. FEAT_SVE or FEAT_SME admits the 294,912 allocated
  words; the exact three-parent classifier rejects 98,304 reserved size or
  operation controls before feature admission. `CPU_ANY`, A64FX, Apple A18,
  and Apple M4 supply the required SVE-or-SME route.
- The exact saturating SVE/SME element-count and SVE predicate-count/search
  family covers all 64 forms 2362--2373, 2392--2423, and 2597--2616.
  `SQINC*`/`UQINC*`/`SQDEC*`/`UQDEC*` vector destinations are read/write and
  allocate H/S/D; their scalar W/X and tied `Xd, Wd` variants allocate
  B/H/S/D. Pattern and one-through-sixteen multiplier remain separate read
  immediates. Predicate forms cover `CNTP`, `FIRSTP`, `LASTP`, `SQINCP`/`UQINCP`,
  `SQDECP`/`UQDECP`, `INCP`, and `DECP`; predicate operands are read and typed,
  while classic two-predicate `CNTP`, `FIRSTP`, and `LASTP` also carry
  `PREDICATED` beside `SCALABLE_VECTOR`. The ordinary forms require SVE or SME;
  counter-predicate `CNTP Xd, PNd, VLx2|VLx4` form 2600 instead requires SVE2.1
  or SME2, and `FIRSTP`/`LASTP` forms 2598--2599 require SVE2.2 or SME2.2.
  The focused classifiers exhaust 720,896 saturating and 132,096 predicate
  count/search allocations, including all 65,536 `FIRSTP`/`LASTP` words, and
  mark 65,536 saturating plus 293,888 predicate-parent residual controls
  invalid. Eligible allocated words become unsupported with extra opcodes
  disabled, while reserved controls remain invalid. No named CPU profile
  currently advertises SVE2.2 or SME2.2, so only `CPU_ANY` admits forms
  2598--2599.
- `CTERMEQ` form 2593 and `CTERMNE` form 2594 exactly own mask
  `0xffa0fc1f` at values `0x25a02000` and `0x25a02010`. The free `sz`, `Rm`,
  and `Rn` fields allocate 2,048 words per leaf; `sz` selects W or X sources
  and register 31 is represented as WZR or XZR. Both operands are read, NZCV
  is written, no generic opcode group is set, and the exact flags are
  `SCALABLE_VECTOR | SETS_FLAGS`. Either SVE or SME admits the forms, while
  all 4,096 `op=0` parent words remain invalid. The focused suite exhausts
  the 4,096 allocated and 4,096 reserved words; 16 opcode rows, six reviewed
  seeds, LLVM 21 comparisons, and extras-ON/OFF sanitizer campaigns preserve
  endian, formatting, profile, truncation, and disabled-build behavior.
- The ten baseline SVE predicate-break forms 2546--2555 are exact:
  `BRKPA`/`BRKPAS`, `BRKPB`/`BRKPBS`, `BRKA`/`BRKAS`, `BRKB`/`BRKBS`, and
  `BRKN`/`BRKNS`. Every predicate has byte granularity; data predicates carry
  typed metadata and governing `Pg` carries `/z` or `/m`. BRKP forms write
  `Pd` and read `Pg`, `Pn`, and `Pm`; BRKA/BRKB use a three-operand shape whose
  merging controls read/write `Pd` and whose zeroing controls write it;
  BRKN forms write `Pd` and expose the architecturally tied `Pd` source as a
  fourth read operand. All forms carry exactly scalable-vector and predicated
  metadata, while the five `S` forms additionally write NZCV. SVE or SME
  admits the 294,912 allocated words. The exact parent classifiers reject
  270,336 residual controls, including the complete BRKP `op=1` half and the
  unallocated flag-setting merge controls, before feature admission.
- The adjacent baseline predicate-control forms 2556--2561 are exact:
  `PTEST`, `PFIRST`, `PNEXT`, ordinary `PTRUE`, `PTRUES`, and `PFALSE`.
  `PTEST` reads untyped `Pg` and typed `Pn.B`; `PFIRST` writes `Pdn.B`, reads
  `Pg`, and exposes the tied old `Pdn.B` as a final read operand. `PNEXT`
  similarly writes and rereads typed `Pdn.B/H/S/D` around its untyped `Pv`.
  `PTRUE`/`PTRUES` write typed `Pd` and retain the raw five-bit pattern as a
  read immediate, while `PFALSE` writes `Pd.B`. Only PTEST and PTRUES set
  NZCV; only PTEST and PFIRST carry `PREDICATED`; all six carry
  `SCALABLE_VECTOR` and require SVE or SME. Canonical pattern text uses the
  architectural names, preserves unnamed values numerically, and omits the
  default `all`. The exact union contains 5,648 allocated words and 16,944
  reserved parent residuals.
- `PSEL` form 2565 exactly owns mask/value `0xff20c210/0x25204000` and
  formats `Pd, Pn, Pm.T[Wv, lane]`. It writes `Pd` and reads `Pn` at the
  selected element granularity, then reads indexed typed `Pm.B/H/S/D` with
  counter register W12--W15 and the size-dependent lane. It carries only
  `SCALABLE_VECTOR` and requires either SVE2.1 or baseline SME, so Apple
  A18/M4 use the SME route while plain-SVE A64FX is rejected. Thirty of the
  32 `i1:tsz` controls allocate 491,520
  words; the two `tsz=0000` controls have no assembly type and make 32,768
  words invalid. The adjacent 524,288 bit-4 words remain delegated, including
  the counter-predicate forms beginning at 2566. LLVM 21 agrees on all 30
  legal type/lane controls and rejects both untyped controls.
- The A64 SVE/SME wide-immediate block is exact through forms 2619--2632.
  Forms 2619--2630 implement destructive `ADD`, `SUB`, `SUBR`, `SQADD`,
  `SQSUB`, `UQADD`, `UQSUB`, `SMAX`, `SMIN`, `UMAX`, `UMIN`, and `MUL` as a
  typed `Zdn` write, the tied old `Zdn` read, and an immediate read. The first
  seven operations use an unsigned imm8 with optional `lsl #8` and reject the
  byte-width shifted control; `SMAX`, `SMIN`, and `MUL` use signed imm8 while
  `UMAX` and `UMIN` use unsigned imm8. Nonzero shifted values are stored as
  semantic scaled integers, while shifted zero retains its explicit LSL
  modifier so the distinct encoding remains printable. Form 2631 is integer
  `DUP`, exposed with its preferred `MOV` name and a signed imm8; form 2632 is
  `FDUP`, exposed as preferred `FMOV` with imm8 expanded to the exact H/S/D
  IEEE element bits. FDUP's immediate operand size is one byte, describing the
  encoded imm8 field; the destination element type records the H/S/D width.
  All forms require SVE or SME and carry scalable-vector metadata; FDUP also
  carries floating-point metadata. Across the 2,097,152-word parent,
  arithmetic contributes 565,248 allocations and 57,344 leaf-reserved
  controls, DUP contributes 57,344 allocations and 8,192 reserved byte-shift
  controls, FDUP contributes 24,576 allocations and 8,192 reserved byte-width
  controls, and the other 1,376,256 words are reserved.
- A64 unpredicated `SDOT`/`UDOT` forms 2633--2636 are exact. Baseline
  SVE-or-SME forms widen `Zn.B`/`Zm.B` into a tied read/write `Zda.S`, or
  `Zn.H`/`Zm.H` into `Zda.D`; the SVE2p3-or-SME2p3 forms widen byte sources
  into `Zda.H`. All three registers span Z0--Z31, the sources are read-only,
  and the only instruction flag is `SCALABLE_VECTOR`. The shared 262,144-word
  parent contains 196,608 allocations and 65,536 reserved `size=00` words,
  with no delegated residual. A64FX reaches the baseline through SVE and
  Apple A18/M4 through SME; no named profile currently advertises SVE2p3 or
  SME2p3, so the byte-to-half forms are `CPU_ANY`-only. LLVM 21 confirms the
  baseline arrangements; the pinned AARCHMRS data is the oracle for the p3
  forms that LLVM 21 does not yet assemble.
- A64 SVE2-or-SME complex/widening multiply-add forms 2637--2641 are exact.
  `SQDMLALBT`/`SQDMLSLBT` widen B/H/S sources into a tied read/write H/S/D
  destination and reserve `size=00`; `CDOT` widens B/H sources into S/D and
  reserves `size=00/01`; `CMLA` and `SQRDCMLAH` accept B/H/S/D. `CDOT`,
  `CMLA`, and `SQRDCMLAH` expose semantic `#0/#90/#180/#270` rotation
  immediates. All sources are read-only, all destinations span Z0--Z31, and
  the only instruction flag is `SCALABLE_VECTOR`. The three exact parents
  contain 1,507,328 allocated and 327,680 reserved words, with no delegated
  residual. LLVM 21 confirms every legal arrangement/rotation combination
  and rejects the reserved-width spellings.
- A64 SVE2-or-SME unpredicated multiply-long and rounding multiply-add forms
  2642--2655 are exact. `SMLALB`/`SMLSLB`/`SMLALT`/`SMLSLT` and their
  unsigned counterparts, plus `SQDMLALB`/`SQDMLSLB`/`SQDMLALT`/`SQDMLSLT`,
  widen B/H/S sources into tied read/write H/S/D accumulators and reserve
  `size=00`. `SQRDMLAH`/`SQRDMLSH` instead use same-width B/H/S/D operands,
  including the byte arrangement. Both sources are read-only Z registers and
  the only instruction flag is `SCALABLE_VECTOR`. The three exact parents own
  1,441,792 allocated and 393,216 reserved words. SME-only Apple A18/M4 and
  SVE2-capable profiles use the alternative feature routes; the adjacent
  mixed-sign dot-product parent now dispatches separately to exact `USDOT`.
- A64 indexed SVE2-or-SME `MLA`/`MLS` forms 2722--2727 are exact. Their six
  wholly allocated leaves use mask/value `ffa0fc00/44200800` and
  `ffa0fc00/44200c00` for H, `ffe0fc00/44a00800` and
  `ffe0fc00/44a00c00` for S, and `ffe0fc00/44e00800` and
  `ffe0fc00/44e00c00` for D. Every word exposes destructive read/write `Zda`,
  read-only `Zn`, and read-only `Zm.T[lane]`: H admits Zm0--Zm7 and lanes
  0--7, S admits Zm0--Zm7 and lanes 0--3, and D admits Zm0--Zm15 and lanes
  0--1. The family contains 262,144 allocated words and no internal reserved
  controls, carries only `SCALABLE_VECTOR`, and requires SVE2 or SME. Apple
  A18/M4 use the SME route while A64FX and Cortex-A53 reject it. The focused
  suite exhausts all six leaves, LLVM 21 confirms their boundary encodings,
  and 22 corpus rows plus 15 MLA/MLS seeds retain exact formatting, profile,
  endian/generic, truncation, collision, and extras-OFF ownership against the
  adjacent indexed rounding family.
- A64 indexed SVE2-or-SME `SQRDMLAH`/`SQRDMLSH` forms 2728--2733 are exact.
  Their H leaves use mask `0xffa0fc00` with values `0x44201000`/`0x44201400`;
  the S leaves use mask `0xffe0fc00` with values
  `0x44a01000`/`0x44a01400`, and the D leaves use the same mask with values
  `0x44e01000`/`0x44e01400`. Every word exposes destructive read/write `Zda`,
  read-only `Zn`, and read-only `Zm.T[lane]`: H admits Zm0--Zm7 and lanes
  0--7, S admits Zm0--Zm7 and lanes 0--3, and D admits Zm0--Zm15 and lanes
  0--1. All 262,144 family words are allocated, carry only
  `SCALABLE_VECTOR`, and require SVE2 or SME. The adjacent indexed `USDOT`
  leaf remains separately owned. The focused suite exhausts all six leaves;
  LLVM 21 and pinned AARCHMRS confirm the boundary, while 20 corpus rows and
  15 total family seeds retain formatting, profiles, endian/generic transport,
  truncation, collision, and extras-OFF ownership.
- A64 `USDOT` form 2656 exactly owns mask/value `ffe0fc00/44807800` inside
  parent `ff20fc00/44007800`. Its 32,768 allocated `size=10` words expose a
  tied read/write `Zda.S` and read-only `Zn.B`/`Zm.B`; the other 98,304 words
  (`size=00/01/11`) are reserved. The only instruction flag is
  `SCALABLE_VECTOR`, and admission is the conjunctive `(SVE or SME) and I8MM`
  rule. `CPU_ANY` admits the form, while A64FX, Apple A18/M4, and Cortex-A53
  reject it because their current profiles do not advertise I8MM. LLVM 21
  confirms low/high-register encodings and the pinned AARCHMRS input confirms
  the complete parent partition.
- A64 indexed `USDOT`/`SUDOT` forms 2734--2735 exactly own the wholly
  allocated `0xffe0fc00` leaves at `0x44a01800`/`0x44a01c00`. Their 65,536
  words expose a tied read/write `Zda.S`, read-only `Zn.B`, and read-only
  `Zm.B[lane]`; `Zda` and `Zn` span Z0--Z31, `Zm` spans Z0--Z7, and the lane
  spans 0--3. Both require `(SVE or SME) and I8MM`, carry only scalable-vector
  metadata, and are currently `CPU_ANY`-only. The focused suite exhausts both
  32,768-word leaves, and LLVM 21 recognizes every encoding. Eighteen corpus
  rows and eight reviewed seeds retain exact operands, lane formatting,
  profiles, endian/generic transport, sibling identity, truncation, formatter
  forgery rejection, and extras-OFF ownership.
- A64 SVE `AESMC`/`AESIMC` forms 2903--2904 exactly own the 64 allocated words
  at `0xffffffe0`/`0x4520e000` and `0xffffffe0`/`0x4520e400`. Each publishes
  the two explicit tied `Zdn.B` operands as read/write, carries only
  scalable-vector metadata, and requires FEAT_SVE_AES. The remaining 192
  size controls in parent `0xff3ffbe0`/`0x4520e000` are owned invalid space in
  both build variants. `CPU_ANY` admits the leaves; all current named profiles
  reject them. LLVM 21 `+sve2-aes`, the exhaustive focused suite, 13 corpus
  rows, and six reviewed seeds retain the complete partition and schema.
- A64 SVE `AESE`/`AESD` forms 2905--2906 and `SM4E` form 2907 exactly own
  three 1,024-word leaves in the 16,384-word crypto binary-destination parent
  `0xff3ef800`/`0x4522e000`. `AESE`/`AESD` publish tied read/write `Zdn.B`
  operands plus a read-only `Zm.B` and require FEAT_SVE_AES; `SM4E` uses the
  same access recipe with `.S` elements and requires FEAT_SVE_SM4. The other
  thirteen selector rows (13,312 words) are owned invalid space in both build
  variants. LLVM 21 accepts all 3,072 allocated words and rejects the complete
  reserved set; the focused suite, 19 corpus rows, and nine reviewed seeds
  retain feature, profile, endian, format, truncation, and ownership contracts.
- A64 SVE `PUNPKLO` form 2468 and `PUNPKHI` form 2469 exactly own all 512
  words in parent `0xfffefe10`/`0x05304000`; bit 16 selects low versus high.
  Each result writes `Pd.H`, reads `Pn.B`, carries only scalable-vector
  metadata, and requires SVE or SME. A64FX is admitted through SVE and Apple
  A18/M4 through SME, while Cortex-A53 rejects the family. The focused suite
  and LLVM 21 exhaust both 256-word leaves under SVE and SME; 12 corpus rows
  and four reviewed seeds retain profile, endian/generic, format, truncation,
  and extras-OFF ownership contracts.
- A64 SVE/SME `SUNPKLO`/`SUNPKHI`/`UUNPKLO`/`UUNPKHI` forms 2456--2459
  exactly own parent `0xff3cfc00`/`0x05303800`. Control bits 17:16 select
  the four leaves under mask `0xff3ffc00` at values `0x05303800`,
  `0x05313800`, `0x05323800`, and `0x05333800` in form/name order;
  `size=01/10/11` widens B-to-H, H-to-S, or S-to-D, while all `size=00`
  words are reserved. Each result writes `Zd.T`, reads `Zn` at half that
  element width, and carries only scalable-vector metadata. It requires SVE
  or SME. A64FX is admitted through SVE and Apple A18/M4 through SME. The
  `cdisasm_arm_sve_unpack_tests` suite exhausts 12,288 allocated and
  4,096 reserved words, profile and endian/generic transport, canonical
  formatting and forged-schema rejection, truncation, and extras-OFF
  ownership. LLVM 21 matches every allocated formula word and reports all
  reserved words unknown; 22 corpus rows and nine reviewed seeds retain the
  boundary.
- A64 SVE2/SME `SRI` form 2846 and `SLI` form 2847 exactly own parent
  `0xff20f800`/`0x4500f000`; their leaves use mask `0xff20fc00` at values
  `0x4500f000` and `0x4500f400`. Encoded `tszh:tszl:imm3` values 8--127
  allocate B/H/S/D elements by highest-set-bit band, while values 0--7 are
  reserved. `SRI` publishes immediate `2*element_bits-encoded` (#element_bits
  through #1); `SLI` publishes `encoded-element_bits` (#0 through
  #element_bits-1). Both expose tied read/write `Zdn.T`, read-only `Zn.T`, and
  a read immediate, carry only scalable-vector metadata, and require SVE2 or
  SME. The `cdisasm_arm_sve_shift_insert_tests` suite exhausts 245,760
  allocated and 16,384 reserved words and locks profiles, both byte orders,
  generic transport, formatting and forged-schema rejection, truncation, and
  extras-OFF ownership. LLVM 21 matches the complete domain; 21 corpus rows
  and ten reviewed seeds retain the boundary.
- A64 baseline Advanced SIMD `BSL`/`BIT`/`BIF` forms 6188/6196/6198 exactly
  own three disjoint leaves under mask `0xbfe0fc00` at `0x2e601c00`,
  `0x2ea01c00`, and `0x2ee01c00`. Q selects `.8B` or `.16B`; `Vd` is
  read/write and `Vn`/`Vm` are read-only byte vectors. Each successful result
  carries only SIMD metadata and requires NEON. The adjacent
  `AND`/`BIC`/`ORR`/`ORN`/`EOR` leaves remain outside this ownership set. The
  `cdisasm_arm_advsimd_bitwise_select_tests` suite exhausts all 196,608
  allocated words with no reserved word inside the three exact leaves and
  locks A64/profile, endian/generic transport, canonical formatting,
  forged-schema rejection, truncation, and extras-OFF ownership. LLVM 21 and
  pinned AARCHMRS agree; 18 corpus rows and seven reviewed seeds retain the
  boundary.
- A64 baseline Advanced SIMD `ADDHN`/`SUBHN`/`RADDHN`/`RSUBHN` forms
  6093/6095/6108/6110 exactly own four `0xbf20fc00` leaves at values
  `0x0e204000`, `0x0e206000`, `0x2e204000`, and `0x2e206000`. Size controls
  zero through two narrow H/S/D sources to B/H/S results; size three is
  reserved. Q=0 writes an 8-byte destination with the base mnemonic, while
  Q=1 preserves its low half, writes the high half, and formats the `*HN2`
  spelling with a read/write 16-byte destination. Both sources are read-only
  16-byte vectors and every result carries only SIMD metadata under the
  baseline NEON gate. The `cdisasm_arm_advsimd_high_narrow_tests` suite
  exhausts 786,432 allocated and 262,144 reserved words, and locks profiles,
  endian/generic transport, canonical formatting and forged-schema rejection,
  truncation, fixed neighbors, and extras-OFF ownership. Twenty-two corpus
  rows and 11 reviewed seeds retain the boundary against pinned AARCHMRS and
  LLVM 21.
- A64 baseline Advanced SIMD `SADDL`/`SADDW`/`SSUBL`/`SSUBW` forms
  6089--6092 and `UADDL`/`UADDW`/`USUBL`/`USUBW` forms 6104--6107 exactly
  own eight `0xbf20fc00` leaves at opcode nibbles zero through three. Size
  controls zero through two widen B/H/S elements to H/S/D; size three is
  reserved. Q selects the base or `2` spelling and the lower or upper half of
  each narrow source. Long forms write a 16-byte wide destination and read
  two narrow sources; wide forms instead read a wide first source and a
  narrow second source. Every result carries only SIMD metadata under the
  baseline NEON gate. The `cdisasm_arm_advsimd_widening_add_sub_tests` suite
  exhausts 1,572,864 allocated and 524,288 reserved words and locks profiles,
  endian/generic transport, canonical formatting, independent raw/form/name
  ownership, forged-schema rejection, fixed neighbors, truncation, and
  extras-OFF ownership. Thirty-four corpus rows and 13 reviewed seeds retain
  the pinned-AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD `SABAL`/`SABDL` forms 6094/6096 and
  `UABAL`/`UABDL` forms 6109/6111 exactly own four `0xbf20fc00` leaves at
  values `0x0e205000`, `0x0e207000`, `0x2e205000`, and `0x2e207000`.
  Size controls zero through two widen B/H/S inputs to H/S/D results; size
  three is reserved. Q selects the base or `2` spelling and the lower or
  upper narrow source halves. Every destination is a 16-byte wide vector:
  `SABAL`/`UABAL` read and update it, while `SABDL`/`UABDL` write it; both
  narrow inputs are read-only. Results carry only SIMD metadata under the
  baseline NEON gate. The focused suite exhausts 786,432 allocated and
  262,144 reserved words and locks profiles, endian/generic transport,
  formatting and independent raw/form/name ownership, fixed neighbors,
  truncation, and extras-OFF behavior. The shared-name SVE2p3/SME2p3
  `SABAL`/`UABAL` forms 2709--2710 remain separately owned and unsupported
  until exact operand lowering is available. Twenty-two corpus rows and
  eight reviewed seeds retain the pinned-AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD `SMLAL`/`SMLSL`/`SMULL` forms
  6097/6099/6101 and `UMLAL`/`UMLSL`/`UMULL` forms 6112--6114 exactly own
  six `0xbf20fc00` leaves at values `0x0e208000`, `0x0e20a000`,
  `0x0e20c000`, `0x2e208000`, `0x2e20a000`, and `0x2e20c000`. Size
  controls zero through two widen B/H/S inputs to H/S/D results; size three
  is reserved. Q selects the base or `2` spelling and the lower or upper
  halves of both narrow inputs. Multiply-add/subtract-long forms read and
  update the 16-byte destination, while multiply-long forms only write it.
  Results carry SIMD-only metadata and require baseline Advanced SIMD/NEON.
  The focused suite partitions 1,572,864 words into 1,179,648 allocated and
  393,216 reserved encodings and locks profiles, endian/generic transport,
  exact formatting, fixed neighbors, truncation, and extras-OFF ownership.
  Formatter collision tests retain exact legacy A32/T32 long multiplies and
  generated A64 scalar aliases/SME forms while rejecting cross-schema name
  and form grafts. Twenty-eight corpus rows and ten reviewed seeds retain the
  pinned-AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD `SQDMLAL`/`SQDMLSL`/`SQDMULL` forms
  6098/6100/6102 exactly own the three `0xbf20fc00` leaves at values
  `0x0e209000`, `0x0e20b000`, and `0x0e20d000`. The H/S source sizes widen
  to S/D destinations, while the byte and size-three controls are reserved;
  Q selects the base or `2` spelling and the low or high halves of both
  sources. `SQDMLAL` and `SQDMLSL` read and update the destination, whereas
  `SQDMULL` only writes it. The focused suite locks baseline NEON admission,
  endian/generic transport, exact formatting and sibling separation,
  truncation, fixed neighbors, and extras-OFF ownership across 393,216
  allocated and 393,216 reserved words. Twenty-two corpus rows and eight
  reviewed seeds retain the pinned-AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD `SQDMULH`/`SQRDMULH` forms 6136/6178 exactly
  own the `0xbf20fc00` leaves at values `0x0e20b400`/`0x2e20b400`.
  Q selects 4H/8H or 2S/4S vectors; byte and doubleword size controls are
  reserved. Both forms write the destination, read both sources, carry only
  SIMD metadata, and require baseline Advanced SIMD/NEON. The focused suite
  exhausts 262,144 allocated and 262,144 reserved words and locks profiles,
  endian/generic transport, formatting, sibling separation, truncation, and
  extras-OFF ownership. Twenty-two corpus rows and eight reviewed seeds
  retain the pinned-AARCHMRS and LLVM 21 boundary.
- A64 Advanced SIMD `PMULL`/`PMULL2` form 6103 exactly owns mask/value
  `0xbf20fc00`/`0x0e20e000`. Size zero selects byte-to-halfword polynomial
  multiplication under baseline Advanced SIMD; size three selects D-to-Q
  multiplication and additionally requires FEAT_PMULL. Sizes one and two are
  reserved, while Q selects the base or `2` spelling and the low or high input
  halves. Every allocated form writes a 16-byte destination and reads two
  8- or 16-byte sources. `CPU_ANY` admits both sizes; current named profiles
  conservatively reject size three because the repository has no authoritative
  per-profile PMULL metadata. The focused suite exhausts 131,072 allocated and
  131,072 reserved words and locks feature/profile gates, endian/generic
  transport, formatting, truncation, sibling separation, and extras-OFF
  ownership. Twenty corpus rows and eight reviewed seeds retain the pinned-
  AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD `PMUL` form 6175 exactly owns mask/value
  `0xbf20fc00`/`0x2e209c00`. Only size zero is allocated; Q selects the 8B or
  16B vector arrangement, while sizes one through three are reserved. The
  result writes Vd, reads Vn and Vm, carries fixed-width SIMD metadata, and
  requires baseline Advanced SIMD/NEON. The focused suite exhausts 65,536
  allocated and 196,608 reserved words and locks profiles, endian/generic
  transport, exact formatting, sibling isolation, truncation, and extras-OFF
  ownership. Eighteen corpus rows and eight reviewed seeds retain the pinned-
  AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD pairwise `SMAXP`/`SMINP` forms 6134--6135 and
  `UMAXP`/`UMINP` forms 6176--6177 exactly own four `0xbf20fc00` leaves at
  values `0x0e20a400`, `0x0e20ac00`, `0x2e20a400`, and `0x2e20ac00`.
  Sizes zero through two select B/H/S elements, size three is reserved, and Q
  selects 64- or 128-bit vectors. Every allocated form writes Vd, reads Vn and
  Vm, carries SIMD-only metadata, and requires baseline Advanced SIMD/NEON.
  The focused suite exhausts 1,048,576 words as 786,432 allocated and 262,144
  reserved while locking profiles, endian/generic transport, exact formatting,
  same-name SVE isolation, truncation, and extras-OFF ownership. Forty-two
  corpus rows and eight reviewed seeds retain the pinned-AARCHMRS and LLVM 21
  boundary.
- A64 baseline Advanced SIMD `ADDP` scalar form 5808 exactly owns mask/value
  `0xfffffc00`/`0x5ef1b800` and writes `Dd` while reading `Vn.2D`. Its
  fixed-vector form 6137 owns `0xbf20fc00`/`0x0e20bc00`, writes Vd, and reads
  Vn and Vm in the legal 8B/16B, 4H/8H, 2S/4S, and 2D arrangements; Q=0 with
  size=3 is the reserved 1D cell. Both forms require baseline Advanced SIMD
  and carry exact scalar/vector operand typing and canonical formatting. The
  focused suite exhausts all 1,024 scalar allocations and partitions the
  vector parent into 229,376 allocated and 32,768 reserved words while locking
  profiles, endian/generic transport, truncation, sibling separation,
  formatter forgery rejection, and extras-OFF ownership. Sixteen corpus rows
  and ten reviewed seeds retain the pinned-AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD `ADDV` form 6077 exactly owns mask/value
  `0xbf3ffc00`/`0x0e31b800`. Q:size allocates `8B`/`16B` to a scalar B
  destination, `4H`/`8H` to H, and `4S` to S; `2S`, `1D`, and `2D` are
  reserved. The allocated form writes the scalar destination, reads the
  fixed-width vector source, carries SIMD-only metadata, and requires baseline
  Advanced SIMD/NEON. The focused suite exhausts the 8,192-word envelope as
  5,120 allocated and 3,072 reserved words while locking profiles,
  endian/generic transport, exact formatting and forged-schema rejection,
  sibling separation, truncation, and extras-OFF ownership. Thirteen corpus
  rows and ten reviewed seeds retain the pinned-AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD regular `SMAX`/`SMIN` forms 6126--6127 and
  `UMAX`/`UMIN` forms 6168--6169 exactly own four `0xbf20fc00` leaves at
  values `0x0e206400`, `0x0e206c00`, `0x2e206400`, and `0x2e206c00`.
  Sizes zero through two select B/H/S elements, size three is reserved, and Q
  selects 64- or 128-bit vectors. Every allocated form writes Vd, reads Vn
  and Vm, carries SIMD-only metadata, and requires baseline Advanced
  SIMD/NEON. The focused suite exhausts 1,048,576 words as 786,432 allocated
  and 262,144 reserved while locking profiles, endian/generic transport,
  exact formatting and forged-schema rejection, truncation, extras-OFF
  ownership, and independent SVE, SME2, and CSSC same-name siblings. Forty-two
  corpus rows and eight reviewed seeds retain the pinned-AARCHMRS and LLVM 21
  boundary.
- A64 baseline Advanced SIMD register `CMGT`/`CMGE` forms 6120--6121,
  `CMHI`/`CMHS` forms 6162--6163, and `CMEQ` form 6173 exactly own five
  `0xbf20fc00` leaves at values `0x0e203400`, `0x0e203c00`, `0x2e203400`,
  `0x2e203c00`, and `0x2e208c00`. Q=0 allocates B/H/S arrangements and
  reserves 1D; Q=1 allocates B/H/S/D arrangements. Every allocated form
  writes Vd, reads Vn and Vm, carries SIMD-only metadata, and requires
  baseline Advanced SIMD/NEON. The focused suite exhausts 1,310,720 words as
  1,146,880 allocated and 163,840 reserved while locking profiles,
  endian/generic transport, canonical formatting, forged-schema rejection,
  scalar and compare-with-zero sibling isolation, truncation, and extras-OFF
  ownership. Fifty-seven corpus rows and nine reviewed seeds retain the
  pinned-AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD `CMTST` scalar form 5831 exactly owns
  `0xffe0fc00`/`0x5ee08c00` and writes `Dd` while reading `Dn` and `Dm`.
  Vector form 6131 owns `0xbf20fc00`/`0x0e208c00`: Q=0 allocates B/H/S
  arrangements and reserves 1D, while Q=1 allocates B/H/S/D arrangements.
  Both forms carry SIMD-only metadata and require baseline Advanced
  SIMD/NEON. The focused suite exhausts 294,912 words as 262,144 allocated
  and 32,768 reserved while locking profiles, endian/generic transport,
  canonical scalar/vector formatting, raw/form/name forgery rejection,
  adjacent `CMEQ` and compare-with-zero siblings, truncation, and extras-OFF
  ownership. Eighteen corpus rows and eight reviewed seeds retain the
  pinned-AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD `SSHL`/`USHL` scalar forms 5826/5841 exactly
  own `0xffe0fc00` leaves `0x5ee04400`/`0x7ee04400`; vector forms 6122/6164
  own `0xbf20fc00` leaves `0x0e204400`/`0x2e204400`. Scalar forms use D
  registers. Vector B/H/S arrangements exist at both Q widths, D exists only
  at Q=1, and Q=0 1D is reserved. Every allocated form writes its destination,
  reads both sources, carries SIMD-only metadata, and requires baseline
  Advanced SIMD/NEON. The focused suite exhausts 589,824 words as 524,288
  allocated and 65,536 reserved while locking profiles, endian/generic
  transport, canonical scalar/vector formatting, raw/form/name forgery
  rejection, saturating and rounding-shift sibling isolation, truncation, and
  extras-OFF ownership. Twenty-seven corpus rows and 34 reviewed variable-
  shift seeds retain the pinned-AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD fixed-vector `SABA`/`UABA` forms 6129/6171
  exactly own `0xbf20fc00` leaves `0x0e207c00`/`0x2e207c00`. Q selects
  64- or 128-bit vectors; B/H/S arrangements are allocated at both widths and
  size=3 is reserved. Every allocated form reads and updates Vd, reads Vn and
  Vm, carries SIMD-only metadata, and requires baseline Advanced SIMD/NEON.
  The focused suite exhausts the 524,288-word parent as 393,216 allocated and
  131,072 reserved while locking all registers and arrangements, profiles,
  endian/generic transport, canonical formatting, raw/form/name forgery
  rejection, truncation, and extras-OFF ownership. `SABD`/`UABD`, widening
  `SABAL`/`UABAL`, and generated SVE same-name siblings remain independent.
  Twenty-three corpus rows and 30 reviewed seeds retain the pinned-AARCHMRS
  and LLVM 21 boundary.
- A64 baseline Advanced SIMD fixed-vector `SABD`/`UABD` forms 6128/6170
  exactly own `0xbf20fc00` leaves `0x0e207400`/`0x2e207400`. Q selects
  64- or 128-bit vectors; B/H/S arrangements are allocated at both widths and
  size=3 is reserved. Every allocated form writes Vd and reads Vn and Vm,
  carries SIMD-only metadata, and requires baseline Advanced SIMD/NEON. The
  focused suite exhausts the 524,288-word parent as 393,216 allocated and
  131,072 reserved while locking every register and arrangement, named
  profiles, endian/generic transport, canonical formatting, raw/form/name
  forgery rejection, truncation, and extras-OFF ownership. Accumulating
  `SABA`/`UABA`, widening `SABDL`/`UABDL`, and generated SVE same-name forms
  remain independently owned. Twenty-three corpus rows and 24 reviewed seeds
  retain the pinned-AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD fixed-vector `MLA`/`MLS` forms 6132/6174
  exactly own `0xbf20fc00` leaves `0x0e209400`/`0x2e209400`. Q selects
  64- or 128-bit vectors; B/H/S arrangements are allocated at both widths and
  size=3 is reserved. Every allocated form reads and updates Vd, reads Vn and
  Vm, carries SIMD-only metadata, and requires baseline Advanced SIMD/NEON.
  The focused suite exhausts the 524,288-word parent as 393,216 allocated and
  131,072 reserved while locking every register and arrangement, named
  profiles, endian/generic transport, canonical formatting, raw/form/name
  forgery rejection, truncation, and extras-OFF ownership. Existing A32/T32,
  predicated SVE, indexed-SVE, and Advanced SIMD by-element same-name forms
  remain independently classified. Thirty-four corpus rows and 41 reviewed
  seeds retain the pinned-AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD by-element `MLA`/`MLS` forms 6268/6270
  exactly own mask `0xbf00f400` with leaves `0x2f000000`/`0x2f004000`.
  Only halfword and word arrangements are allocated: H forms name V0--V15
  with lane H:L:M in the range 0--7, while S forms name V0--V31 with lane
  H:L in the range 0--3. Q selects the 64- or 128-bit destination and first
  source arrangement. Every allocated form reads and updates Vd, reads Vn
  and the indexed Vm element, carries SIMD-only metadata, and requires
  baseline Advanced SIMD/NEON. The focused suite exhausts all 2,097,152
  words as 1,048,576 allocated and 1,048,576 reserved, with 262,144 in each
  class per operation/Q partition. It locks every register/lane boundary,
  profiles, endian/generic transport, canonical formatting, raw/form/name
  forgery rejection, truncation, and extras-OFF ownership while preserving
  fixed-vector, A32/T32, predicated SVE, indexed-SVE, and adjacent widening
  siblings. Twenty-five corpus rows and 14 reviewed seeds retain the pinned-
  AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD widening by-element `SMLAL`/`SQDMLAL`/`SMLSL`/
  `SQDMLSL`/`SMULL`/`SQDMULL`/`UMLAL`/`UMLSL`/`UMULL` forms
  6243--6246/6248--6249/6269/6271--6272 exactly own nine leaves under mask
  `0xbf00f400`. Only H-to-S and S-to-D forms are allocated. Q selects the
  base or `2` spelling and the low or high half of Vn, while Vd is always a
  128-bit 4S or 2D result. Multiply-add/subtract-long destinations are
  read/write accumulators; multiply-long destinations are write-only. H forms
  restrict Vm to V0--V15 and derive lanes 0--7 from H:L:M; S forms admit
  V0--V31 and derive lanes 0--3 from H:L. Every allocated form reads the
  selected Vn half and indexed Vm element, carries SIMD and NEON metadata,
  and requires baseline Advanced SIMD. The unified focused suite exhausts
  9,437,184 controls as 4,718,592 allocated and 4,718,592 reserved. It locks
  destination access, signed/unsigned/saturating identity, all adjacent
  multiply/dot-product siblings, profiles, endian/generic transport,
  canonical formatting, raw/form/name forgery rejection, truncation, and
  extras-OFF ownership. Seventy-five corpus rows and 32 reviewed seeds retain
  the pinned-AARCHMRS and LLVM 21 boundary.
- A64 baseline Advanced SIMD signed compare-with-zero `CMLT`/`CMLE` scalar
  forms 5777/5794 and vector forms 6013/6045 are exact. Scalar leaves use
  masks/values `0xfffffc00`/`0x5ee0a800` and
  `0xfffffc00`/`0x7ee09800`; vector leaves use
  `0xbf3ffc00`/`0x0e20a800` and `0xbf3ffc00`/`0x2e209800`.
  Scalar forms write Dd, read Dn, and expose explicit `#0`; vector forms
  allocate B/H/S at both Q widths and D only at Q=1, reserving 1D. All carry
  SIMD-only metadata and require baseline Advanced SIMD/NEON. The focused
  suite exhausts 18,432 words as 16,384 allocated and 2,048 reserved while
  locking profiles, endian/generic transport, canonical formatting,
  raw/form/name schema rejection, fixed-bit neighbors, truncation, and
  extras-OFF ownership. Existing scalar/vector `CMGT`/`CMEQ`/`CMGE` and
  register-register compare siblings remain independent. Twenty-seven corpus
  rows and eight reviewed seeds retain the pinned-AARCHMRS and LLVM 21 boundary.
- A64 FEAT_PAuth authenticated register branches `BRAAZ`/`BRABZ`/`BLRAAZ`/
  `BLRABZ` forms 4510/4511/4513/4514 and `BRAA`/`BRAB`/`BLRAA`/`BLRAB`
  forms 4525--4528 exactly own parent `0xfedff800`/`0xd61f0800`. The four
  zero-modifier leaves fix `Rm=31` and contain 32 words each; the four
  explicit-modifier leaves contain 1,024 words each. Targets read X0--X30 or
  XZR, while the explicit modifier reads X0--X30 or SP. Branch forms carry
  JUMP and pointer-authentication metadata; link forms carry CALL, LINK, and
  pointer-authentication metadata. The focused suite exhausts the 8,192-word
  parent as 4,224 allocated and 3,968 reserved words and locks PAuth profiles,
  both byte orders, generic transport, canonical formatting and raw/form/name
  forgery rejection, truncation, and extras-OFF ownership. RETAA/RETAB remain
  outside this tranche. Twenty-three corpus rows and 11 reviewed seeds retain
  the pinned-AARCHMRS and LLVM 21 boundary.
- A64 SVE BitPerm `BEXT`/`BDEP`/`BGRP` forms 2829--2831 exactly own parent
  `0xff20f000`/`0x4500b000`. Selector values 0/1/2 choose the three leaves;
  selector 3 is the sole reserved quarter. Each B/H/S/D result writes `Zd.T`
  and reads `Zn.T` and `Zm.T`, carries only scalable-vector metadata, and
  requires FEAT_SVE_BitPerm. `CPU_ANY` admits the family; every current named
  profile rejects it. The `cdisasm_arm_sve_bitperm_tests` suite exhausts all
  524,288 parent words as 393,216 allocated and 131,072 reserved and locks
  both byte orders, generic transport, canonical formatting, forged-schema
  rejection, truncation, profile gates, and extras-OFF ownership. Pinned
  AARCHMRS and LLVM 21 agree; 24 corpus rows and eight reviewed seeds retain
  the boundary.
- A64 SVE2-or-SME predicated merging shift/saturating-round forms 2657--2668
  are exact under parent mask/value `ff30e000/44008000`. Selector values
  2/6/8/10/12/14 implement `SRSHL`, `SRSHLR`, `SQSHL`, `SQRSHL`, `SQSHLR`,
  and `SQRSHLR`; 3/7/9/11/13/15 implement the unsigned counterparts
  `URSHL`, `URSHLR`, `UQSHL`, `UQRSHL`, `UQSHLR`, and `UQRSHLR`.
  Selectors 0, 1, 4, and 5 are reserved. Every B/H/S/D result exposes
  `Zdn.T, Pg/m, Zdn.T, Zm.T`: the first destination is read/write, the
  governing predicate and both sources are read, and the predicate retains
  merge metadata. The complete parent contains 393,216 allocated and 131,072
  reserved words, with `SCALABLE_VECTOR | PREDICATED` metadata. Apple A18/M4
  are admitted through SME; baseline-SVE-only A64FX is rejected.
- A64 predicated integer-unary forms 2669--2676 are exact under parent
  mask/value `ff34e000/4400a000`. `URECPE` and `URSQRTE` allocate only `.S`,
  while `SQABS` and `SQNEG` allocate B/H/S/D; this gives 163,840 allocated
  and 98,304 reserved words. Merging forms expose
  `Zd.T, Pg/m, Zn.T` with a read/write destination and require SVE2 or SME;
  zeroing forms use `Pg/z`, write the destination, and require SVE2.2 or
  SME2.2. Every success carries `SCALABLE_VECTOR | PREDICATED`. Apple A18/M4
  reach only the merging forms through SME; no current named profile admits
  the zeroing forms.
- A64 predicated accumulating-long `SADALP`/`UADALP` forms 2677--2678 are
  exact for B-to-H, H-to-S, and S-to-D. The destination is read/write, the
  `/m` predicate is typed at destination granularity, and the half-width source
  is read-only. Their parent contains 49,152 allocated words and 16,384
  reserved `size=00` controls. The adjacent destructive halving row implements
  `SHADD`, `SHSUB`, `SRHADD`, `SHSUBR`, `UHADD`, `UHSUB`, `URHADD`, and
  `UHSUBR` forms 2679--2686 for every B/H/S/D arrangement, covering 262,144
  allocated words. Both families carry scalable-vector and predicated metadata
  and require SVE2 or SME, so Apple A18/M4 use the SME route while A64FX is
  rejected.
- A64 destructive predicated pairwise `SUBP`/`ADDP`/`SMAXP`/`SMINP`/
  `UMAXP`/`UMINP` forms 2687--2692 are exact for every B/H/S/D arrangement.
  They expose `Zdn.T, Pg/m, Zdn.T, Zm.T`: the destination is read/write and
  both the typed governing predicate and source are reads. `SUBP` requires
  SVE2p3 or SME2p3; the other five require SVE2 or SME. The complete parent
  contains 196,608 allocated and 65,536 reserved operation-2/3 words.
  Pinned AARCHMRS supplies the authoritative identities and encoding rules;
  LLVM 21 reproduces the other five SVE2 encodings but does not yet accept
  SVE2p3 `SUBP`. Nineteen corpus rows and eight reviewed seeds cover the six
  leaves, both reserved operations, profiles, endian transport, formatting,
  truncation, and extras-OFF ownership.
- A64 destructive predicated saturating `SQADD`/`SQSUB`/`SUQADD`/`USQADD`/
  `SQSUBR`/`UQADD`/`UQSUB`/`UQSUBR` forms 2693--2700 are exact for every
  B/H/S/D arrangement. Each exposes `Zdn.T, Pg/m, Zdn.T, Zm.T`, with a
  read/write destination and read-only typed predicate, tied source, and
  second source. Every form requires SVE2 or SME and carries scalable-vector
  and predicated metadata. The complete 262,144-word parent is allocated,
  with no reserved or delegated residual. Fifteen corpus rows and eight
  reviewed seeds cover all names, widths, profiles, endian transport,
  formatting and forged-schema rejection, truncation, neighboring same-name
  forms, and extras-OFF ownership; LLVM 21 confirms representative encodings
  for all eight leaves.
- A64 destructive unpredicated `SCLAMP` form 2701 and `UCLAMP` form 2702 are
  exact under parent `(word & 0xff20f800) == 0x4400c000`. Every B/H/S/D form
  exposes `Zd.T, Zn.T, Zm.T`: the destination is read/write and both sources
  are read-only. The two leaves allocate all 262,144 parent words, carry
  scalable-vector metadata, and require SVE2.1 or SME. Fifteen corpus rows and
  six reviewed seeds cover both names, every width, profile and endian
  transport, canonical formatting and forged-schema rejection, fixed
  neighbors, truncation, and extras-OFF ownership. Pinned AARCHMRS and LLVM 21
  establish the encodings and feature boundary, with an independent operand
  oracle confirming the destructive access contract.
- A64 pointer multiply-add transform `MLAPT` form 2707 and `MADPT` form 2708
  exactly own parent `(word & 0xff20f400) == 0x4400d000`. Only `.D` is
  allocated: 32,768 words per leaf, 65,536 total, with the B/H/S quarters
  reserving the other 196,608 words. Both expose a destructive read/write
  destination and two read-only Z sources; MLAPT uses `Zda.D, Zn.D, Zm.D`,
  while MADPT uses `Zdn.D, Zm.D, Za.D`. Their gate is the conjunction
  FEAT_SVE and FEAT_CPA, so `CPU_ANY` admits them and every current named
  profile rejects them. Fifteen corpus rows and seven reviewed seeds cover
  both leaves, reserved sizes, all named profiles, endian/generic transport,
  formatting and forged-schema rejection, truncation, fixed neighbors, and
  extras-OFF ownership. The focused suite exhausts the complete 262,144-word
  parent; pinned AARCHMRS and LLVM 21 provide independent encoding evidence.
- A64 quad-permute `ZIPQ1`/`UZPQ1` forms 2711--2712 and `ZIPQ2`/`UZPQ2`
  forms 2714--2715 are exact for every B/H/S/D arrangement. Each exposes
  `Zd.T, Zn.T, Zm.T`, with a write-only destination and two read-only sources,
  carries scalable-vector metadata, and requires SVE2.1 or SME2.1. In their
  complete 1,048,576-word parent, controls 000--011 contribute 524,288 exact
  Q1/Q2 words; control 110 remains routed to the 131,072-word `TBLQ` sibling,
  while controls 100, 101, and 111 are owned as 393,216 invalid words. The Q2
  allocations become unsupported when extras are disabled, reserved controls
  remain invalid, and short words are truncated. The Q2 tranche adds 14 corpus
  rows and four reviewed seeds to the Q1 evidence, covering every width, high
  registers, all named-profile rejections,
  endian/generic transport, formatting and forged-schema rejection,
  truncation, sibling/reserved routing, and extras-OFF ownership against
  pinned AARCHMRS and LLVM 21.
- The single-predicate `WHILEGE`/`WHILEHS`/`WHILEGT`/`WHILEHI` and
  `WHILELT`/`WHILELO`/`WHILELE`/`WHILELS` leaves are exact forms 2585--2592.
  They write typed `Pd.B/H/S/D`, read Wn/Wm or Xn/Xm according to `sf`, map
  register 31 to WZR/XZR, set NZCV, and carry exactly
  `SCALABLE_VECTOR | PREDICATED | SETS_FLAGS`. The first four relations require
  SVE2 or SME; the latter four require SVE or SME. The focused suite exhausts
  all 1,048,576 allocations, 131,072 per form.
- The counter-predicate versions of those eight relations are exact forms
  2566--2573. They write typed `PN8`--`PN15`, read `Xn` and `Xm` with register
  31 represented as XZR, expose the final operand as `VLx2` or `VLx4`, and
  carry exactly `SCALABLE_VECTOR | PREDICATED | SETS_FLAGS`. SVE2.1 or SME2
  admits all eight leaves. The focused suite exhausts all 524,288 allocations,
  65,536 per form.
- Paired-predicate versions of the same eight relations are exact forms
  2574--2581. They write one typed, consecutive even/odd predicate pair and
  read Xn/Xm, including XZR, under the SVE2.1-or-SME2 gate. Their metadata
  matches the single-predicate family, and the focused suite exhausts all
  262,144 allocations, 32,768 per form.
- `PEXT` forms 2582--2583 and counter-predicate `PTRUE` form 2584 exactly own
  the adjacent SVE2.1-or-SME2 block. One-result `PEXT` writes a typed ordinary
  predicate and reads the untyped indexed source syntax `PNn[index]`; pair
  `PEXT` writes two typed consecutive predicates, including the architectural
  `p15, p0` wrap, and reads the same untyped indexed PN source. `PTRUE` writes
  typed `PN8`--`PN15`. They carry `SCALABLE_VECTOR` without a predication or
  flag-write bit. The focused suite exhausts 2,048 single-result `PEXT`, 1,024
  pair-result `PEXT`, and 32 `PTRUE` allocations, 3,104 total, and rejects
  1,024 reserved parent controls.
- The exact non-counting loop predicates are `WHILEWR` form 2595 and
  `WHILERW` form 2596. Their `0xff20fc10` leaves select values `0x25203000`
  and `0x25203010`; all 65,536 B/H/S/D, `Rm`, `Rn`, and `Pd` payloads in
  each leaf are allocated. Results write typed `Pd.B/H/S/D`, read `Xn` and
  `Xm` with register 31 represented as XZR, set NZCV, and carry exactly
  `SCALABLE_VECTOR | PREDICATED | SETS_FLAGS` with no generic opcode group.
  Either SVE2 or SME admits the family, so A18/M4 exercise its SME route while
  plain-SVE A64FX rejects it. The focused suite exhausts all 131,072 words;
  14 opcode rows, six reviewed fuzz seeds, LLVM 21 comparisons, and 6,000-run
  ASan+UBSan campaigns in both extras configurations cover transport,
  formatting, feature gates, and disabled-build ownership.
- The complete bounded SVE unpredicated integer-arithmetic class covers
  `ADD`, `SUB`, `SQADD`, `UQADD`, `SQSUB`, and `UQSUB` for byte, halfword,
  word, and doubleword elements, plus Armv9.5 `ADDPT` and `SUBPT` for their
  allocated doubleword form. The six unallocated smaller-width CPA forms are
  rejected structurally rather than falling through to feature validation.
- The complete bounded destructive predicated SVE integer class covers 74
  allocated operation/element-width pairs across 22 operations. `ADD`, `SUB`,
  `SUBR`, signed/unsigned MIN/MAX and absolute difference, `MUL`, `SMULH`,
  `UMULH`, and `AND`/`BIC`/`EOR`/`ORR` accept byte, halfword, word, and
  doubleword elements. `SDIV`, `UDIV`, `SDIVR`, and `UDIVR` accept word and
  doubleword elements; `ADDPT` and `SUBPT` accept only doubleword. Ordinary
  forms admit SVE or SME, while the pointer forms require SVE plus CPA. All
  442,368 reserved words in the exact class are rejected structurally.
- Three exact predicated SVE unary classifiers cover integer extensions and
  absolute/negate (`SXTB`, `UXTB`, `SXTH`, `UXTH`, `SXTW`, `UXTW`, `ABS`,
  `NEG`), bitwise/count and floating absolute/negate (`CLS`, `CLZ`, `CNT`,
  `CNOT`, `NOT`, `FABS`, `FNEG`), and element bit reversal (`REVB`, `REVH`,
  `REVW`, `RBIT`). Their width rules leave 917,504 concrete words allocated
  and classify 393,216 concrete words as reserved. Merge-predicated `/m` forms
  admit SVE or SME; zero-predicated `/z` forms require SVE2p2 or SME2p2.
- Four disjoint predicated SVE floating-point unary classifiers cover H/S/D
  `FRINTN`, `FRINTP`, `FRINTM`, `FRINTZ`, `FRINTA`, `FRINTX`, `FRINTI`,
  `FRECPX`, and `FSQRT` in merging and zeroing forms. Their exact union owns
  655,360 words: 442,368 are allocated and 212,992 byte-width or operation-5
  words are reserved. Merging `/m` forms admit SVE or SME; zeroing `/z` forms
  require SVE2p2 or SME2p2. Adjacent controls remain unowned.
- The exact unpredicated SVE/SME floating-point estimate classifier
  `(word & 0xff3efc00) == 0x650e3000` covers H/S/D `FRECPE` and `FRSQRTE`.
  Its 6,144 allocated words write typed `Zd` and read typed `Zn`; all 2,048
  byte-width words are reserved. Valid forms admit either SVE or SME.
- The exact fixed-width Advanced SIMD `FRECPE`/`FRSQRTE` union covers scalar
  H/S/D and vector 4H/8H/2S/4S/2D. It owns 18,432 words: 16,384 are allocated
  and the 2,048 vector `Q=0,sz=1` one-lane-D controls are reserved. All valid
  forms require Advanced SIMD, and half-precision forms additionally require
  FP16.
- The bounded merging SVE/SME integer-to-floating conversion support covers
  the 49,152 allocated H/S/D-to-H `SCVTF`/`UCVTF` words in the original
  65,536-word selector envelope and all 65,536 signed/unsigned S-to-S, D-to-S,
  S-to-D, and D-to-D words in four disjoint `0xfffee000` envelopes. Results
  preserve typed source/destination and source-granularity predicate metadata;
  valid forms admit either SVE or SME.
- The complete baseline merging SVE/SME floating conversion slice covers six
  H/S/D `FCVT` precision conversions and seven each of `FCVTZS` and `FCVTZU`.
  Its 204,800-word exact union contains 163,840 allocated forms and 40,960
  reserved controls. Results preserve typed source/destination and `Pg/m`
  source-granularity metadata. The adjacent BFCVT word is separately featured
  and is not inferred from this baseline class.
- The exact predicated BFloat16 conversion slice owns four allocated
  `0xffffe000` classes: merging `BFCVT` at `0x658aa000`, merging `BFCVTNT` at
  `0x648aa000`, zeroing `BFCVT` at `0x649ac000`, and zeroing `BFCVTNT` at
  `0x6482a000`. Each class contains all 8,192 `Pg`/`Zn`/`Zd` combinations.
  Merging forms require BF16 and SVE or SME; zeroing forms require SVE2.2 or
  SME2.2 without a separate BF16 gate. `BFCVT` `/z` writes `Zd.h`; both
  `BFCVTNT` forms read and write it because they preserve even halfwords. All
  forms read the predicate at single-precision source granularity and read
  `Zn.s`. Three adjacent selector rows are exact invalid controls.
- The exact unpredicated two-vector conversion slice owns all thirteen SME2
  forms 4312--4324: `FCVT`, `BFCVT`, `FCVTN`, `BFCVTN`, `FCVTZS`,
  `FCVTZU`, `SCVTF`, `UCVTF`, `SQCVT`, `SQCVTU`, `UQCVT`, and the
  SME2+FP8 `BFCVT`/`FCVT` H-pair-to-B forms. Floating-to-integer and
  integer-to-floating forms write an even consecutive Z-register pair; the
  remaining forms write one Z register. Every source is an even consecutive
  Z-register pair. The adjacent SME2 `SUNPK`/`UUNPK` forms 4325--4326 own two
  exact 2,048-word envelopes: encoded size zero reserves 1,024 words, while the
  B-to-H, H-to-S, and S-to-D widths allocate 3,072. The SME2+FP8 `F1CVT`,
  `BF1CVT`, `F2CVT`, and `BF2CVT` widening row, including all four `L`
  variants, owns forms 4327--4334 and another 4,096 allocated words. The
  combined focused conversion/unpack test classifies 14,848 allocated and
  7,680 reserved words. The
  four-form SVE2-or-SME2 FP8 narrowing row 3165--3168 adds `FCVTN`, `FCVTNB`,
  `BFCVTN`, and `FCVTNT`, all writing B elements from H- or S-element source
  pairs. SME2-only forms are admitted by Apple A18/M4 where their independent
  element feature is available; FP8 remains `CPU_ANY`-only. Other conversion
  families and MOVPRFX-dependent diagnostics remain outside this bounded
  slice.
- The exact SVE2.1-or-SME2 multi-extract narrowing row owns forms 2881--2883:
  `SQCVTN`, `SQCVTUN`, and `UQCVTN` write `Zd.h` from an even consecutive
  two-register `.s` source list. Its 1,536 allocated words and the 1,536
  unallocated bit-5 neighbors are exhaustively classified. Four SME2
  two-vector rounding rows, forms 4335--4338, add `FRINTN`, `FRINTP`,
  `FRINTM`, and `FRINTA`; 1,024 words allocate and 3,072 bit-5/bit-0 controls
  remain invalid. SME_F16F16 `FCVT`/`FCVTL` forms 4339--4340 add another
  1,024 allocated words, widening one `.h` source into an even `.s` pair
  under their independent extended feature gate.
- The complete SME2 group-of-four block owns forms 4341--4362. Four
  floating/integer conversion rows read and write aligned four-Z lists; six
  saturating narrowing rows and two FP8 rows write one Z register from an
  aligned four-Z source. `SUNPK`/`UUNPK` widen an aligned two-Z source into a
  four-Z destination, `ZIP`/`UZP` permute aligned four-Z lists at B/H/S/D or
  fixed Q element size, and the four `FRINT*` rows round four `.s` vectors.
  SME2 is required throughout and FP8 is independently required for forms
  4351--4352. The exhaustive classifier covers 5,504 allocated words and
  rejects 3,072 reserved size/operation controls before feature admission.
- The adjacent SME multi-vector multiply block owns forms 4363--4370 through
  four exact mask/value pairs: `0xff21fc21/0xc120e400` for two-list by
  two-list, `0xff23fc63/0xc121e400` for four-list by four-list,
  `0xff21fc21/0xc120e800` for two-list by scalar, and
  `0xff21fc63/0xc121e800` for four-list by scalar. List bases are aligned to
  their two- or four-register length, and scalar sources are limited to
  `z0`--`z15`. Sizes one, two, and three are `FMUL` H/S/D and require SME2.2;
  size zero is not an FMUL allocation but the fixed-H `BFMUL` form requiring
  SME2 plus FEAT_SVE_BFSCALE. The list/list and list/scalar counts are
  respectively 12,288+4,096, 1,536+512, 12,288+4,096, and 3,072+1,024
  FMUL+BFMUL words: 38,912 allocated and no reserved word in the combined
  envelope. Results write the destination list, read both sources, and carry
  SME, scalable-vector, and floating-point metadata. `CPU_ANY` admits the
  exact features; all current named profiles remain negative. Focused checks
  cover every word, canonical list text, endian and generic-dispatch parity,
  truncation, named profiles, fixed neighbors, and extras-OFF ownership.
- Forms 4373--4380 and 4385--4386 are the ten exact baseline-SME predicated
  contiguous ZA-slice leaves: `LD1B/H/W/D/Q` and `ST1B/H/W/D/Q`, all under
  mask `0xffe00010`. Each leaf allocates 1,048,576 words (10,485,760 total,
  zero reserved in the union). Rm selects X0--X30 or the omitted XZR index;
  V selects `ZA...H`/`ZA...V`; Rs selects W12--W15; Pg selects P0--P7; Rn
  selects X0--X30/SP; and bits 3:0 split into tile number and slice offset as
  B `0+4`, H `1+3`, S `2+2`, D `3+1`, and Q `4+0`. Indexed H/W/D/Q memory
  carries the required `LSL #1/#2/#3/#4`; every memory operand has runtime
  `size == 0`. Loads write the tile, read `Pg/Z`, and read memory; stores read
  the tile and unqualified Pg and write memory. Tile and predicate operands
  retain element granularity, and the public
  `CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL` flag distinguishes V from the
  default H view. Results carry SME, matrix, scalable-vector, and predicated
  flags, but deliberately no streaming-state flag. `CPU_ANY`, Apple A18, and
  Apple M4 admit SME. The focused suite checks 20,480 factorized-exhaustive
  field combinations, exact fixed boundaries, all named profiles,
  endian/generic dispatch, truncation, canonical braced text, forged-schema
  rejection, and both disabled build axes. Twelve seeds and a dedicated fuzz
  invariant lock the metadata against pinned AARCHMRS, LLVM 21, and Capstone
  5 executable oracles.
- Forms 4381--4382 are the exact baseline-SME ZA array-vector load/store leaves.
  Mask/value `0xffff9c10/0xe1000000` selects
  `LDR ZA[Wv, off], [Xn|SP, #off, MUL VL]`; value `0xe1200000` under the
  same mask selects `STR`. Bits 14:13 map to W12--W15, bits 9:5 map register
  31 to SP, and bits 3:0 provide the shared unsigned 0--15 ZA array-vector
  selector offset and displacement coefficient. Each leaf therefore allocates
  2,048 words, with no reserved cell in their 4,096-word union. The tile
  operand writes on LDR and reads on STR; memory has the reciprocal access.
  One complete ZA array vector is transferred. Its runtime size is SVL/8 bytes
  (16--256), so the public memory operand keeps `size == 0`. For nonzero
  offsets, `imm` stores the coefficient and the paired `HAS_DISPLACEMENT` and
  `CDISASM_ARM_OPERAND_FLAG_VL_SCALED` flags mean `base + imm * VL`; offset
  zero has no displacement flag and formats simply as `[base]`. Results carry
  SME, matrix, and scalable-vector metadata but not streaming-state metadata,
  require A64 plus SME, and are admitted by `CPU_ANY`, Apple A18, and Apple
  M4. The focused suite exhausts all 4,096 words, every fixed-bit neighbor,
  every named profile, endian/generic dispatch, truncation, canonical text,
  forged flag combinations, and extras-OFF ownership. Five reviewed seeds
  and an exact fuzz invariant are pinned against AARCHMRS and LLVM 21, with
  Capstone providing a second independent disassembly comparison.
- The exact SME2 ZT0 load/store leaves use
  `0xfffffc1f/0xe11f8000` for form 4383 `LDR ZT0, [Xn|SP]` and
  `0xfffffc1f/0xe13f8000` for form 4384 `STR ZT0, [Xn|SP]`. Their enclosing
  `0xffc0fc1c/0xe1008000` class varies a six-bit operation, five-bit base,
  and two-bit ZT selector: only operation 31/63 with selector zero allocates,
  so the complete 8,192-word sweep contains 32 LDR, 32 STR, and 8,128
  reserved words. The untyped ZT0 tile operand and exact 64-byte memory
  operand use write/read access for LDR and read/write for STR; base 31 is SP.
  Results carry SME and matrix metadata and require A64 plus SME2. `CPU_ANY`,
  Apple A18, and Apple M4 admit them; every other current named profile is
  negative. The focused suite also checks all 54 one-bit fixed-neighbor
  perturbations, canonical text, endian and generic-dispatch parity,
  truncation, and extras-OFF structural ownership. Four reviewed seeds and an
  exact fuzz invariant lock allocated and reserved paths against pinned
  AARCHMRS and LLVM 21 evidence.
- Baseline A64 `UDF #imm16` form 4387 owns the complete
  `0xffff0000/0x00000000` leaf. Bits 15:0 are one unsigned, two-byte read
  immediate; all 65,536 values decode for every A64-capable profile. The
  result carries exactly `CDISASM_GROUP_INTERRUPT`, with no architectural
  instruction flag and no branch target. This is intentionally a successful
  decode: UDF is an allocated instruction whose execution raises the
  Undefined Instruction exception, rather than a malformed encoding. The
  focused suite exhausts the immediate domain, perturbs every fixed bit,
  verifies profile, endian, generic-dispatch, formatting, truncation, and
  extras-OFF behavior, and the four reviewed seeds plus a fuzz invariant lock
  both the allocated leaf and its fixed boundary. Pinned AARCHMRS supplies
  the form and no-state-effects operation, while LLVM 21 and Capstone
  independently confirm the encodings and canonical immediate syntax.
- The exact predicated SVE vector-shift classifier
  `(word & 0xff30e000) == 0x04108000` covers direct `ASR`, `LSR`, and `LSL`
  plus reverse `ASRR`, `LSRR`, and `LSLR`. Direct and reverse same-width forms
  accept B/H/S/D elements; wide-count direct forms accept B/H/S destinations
  with a `.d` count source. All register and predicate combinations give
  270,336 allocated and 253,952 reserved words. Valid forms use destructive
  `/m` metadata and admit SVE or SME.
- The exact predicated SVE/SVE2 immediate-shift classifier
  `(word & 0xff30e000) == 0x04008000` owns 524,288 words. Its 276,480
  allocated forms cover B/H/S/D `ASR`, `LSR`, `LSL`, `ASRD`, `SQSHL`,
  `UQSHL`, `SRSHR`, `URSHR`, and `SQSHLU`; its remaining 247,808 words are
  reserved. Baseline shifts admit SVE or SME, while the saturating and
  rounding operations require SVE2 or SME. Results retain a destructive typed
  Z destination/source, `Pg/m`, and the exact numeric immediate.
- The separate predicated SVE2/SME variable shift/saturating-round classifier
  `(word & 0xff30e000) == 0x44008000` owns 524,288 words. Twelve selector
  values implement signed/unsigned `RSHL`, `RSHLR`, `QSHL`, `QRSHL`, `QSHLR`,
  and `QRSHLR` spellings across B/H/S/D; selectors 0, 1, 4, and 5 reserve the
  remaining 131,072 words. The 393,216 allocations expose destructive
  `Zdn.T`, `Pg/m`, the tied `Zdn.T` read, and `Zm.T`, carry scalable/predicated
  metadata, and require SVE2 or SME.
- The complete bounded SVE vector-permute class covers `ZIP1`, `ZIP2`,
  `UZP1`, `UZP2`, `TRN1`, and `TRN2` for byte, halfword, word, and
  doubleword elements. Operation selectors six and seven are unallocated at
  every width and are rejected before CPU capability validation. The valid
  class admits SVE-only A64FX and SME-only A18/M4 profiles through the
  architectural SVE-or-SME rule.
- The fixed-width A64 Advanced SIMD vector-permute class reuses `ZIP1/2`,
  `UZP1/2`, and `TRN1/2` across `8B`, `16B`, `4H`, `8H`, `2S`, `4S`, and
  `2D`, for 42 allocated forms with three typed V-register operands. It
  requires A64 plus NEON; selectors zero/four and the Q=0,size=3 arrangement
  are invalid before CPU validation.
- The exact fixed-width Advanced SIMD bit-count envelope
  `(word & 0xbf3ffc00)` owns `CLS` at `0x0e204800`, `CNT` at `0x0e205800`,
  and `CLZ` at `0x2e204800`, forms 6007/6008/6041. Q selects 64- or 128-bit
  vectors. CLS and CLZ allocate B/H/S arrangements and reserve size three;
  CNT allocates only 8B/16B and reserves H/S/size-three controls. Across all
  register pairs this is 14,336 allocated and 10,240 reserved words, split as
  6,144/2,048 for each of CLS and CLZ and 2,048/6,144 for CNT. Allocated
  results write `Vd`, read `Vn`, preserve lane and total-vector widths, carry
  SIMD metadata, and require A64 plus NEON. The exhaustive focused test also
  locks canonical arrangement text, endian/generic-dispatch parity, named
  profiles, truncation, fixed neighbors, and extras-OFF ownership.
- The completed bounded SVE table-lookup controls cover two-register
  `TBL`, extending `TBX`, one-register `TBL`, and SVE2.1/SME2.1 `TBXQ` for
  byte, halfword, word, and doubleword elements. Its four adjacent
  MOV-from-GPR widths emit W/WSP sources below 64 bits and X/SP at 64 bits.
  Capability alternatives are exact: the one-table `TBL` and MOV forms admit
  SVE or SME, the two-table `TBL` and `TBX` forms admit SVE2 or SME, and
  `TBXQ` admits SVE2.1 or SME2.1. Adjacent selector-14 encodings remain
  unowned/unsupported, while selector 15 is structurally invalid before
  feature validation. The disjoint `TBLQ` class is now also complete for all
  four element widths and all three five-bit Z-register fields. It writes the
  destination, reads a singleton table list and an index register, and admits
  only SVE2.1 or SME2.1; every current named profile rejects it, while
  `CDISASM_ARM_CPU_ANY` supplies the explicit unrestricted analysis route.
- SME representatives cover streaming-state control, `RDSVL`, `FMOPA`,
  `SMOPA`, `UMOPA`, and ZA loads/stores. SME2 representatives cover ZT0
  loads/stores and `LUTI2`.
- The atomic tranche includes FEAT_LSE `CAS`/`CASP` and common RMW operations,
  FEAT_LOR, FEAT_LRCPC, representative FEAT_LSE128 pair atomics, and RCpc3
  `LDIAPP`/`STILP`. FEAT_LRCPC3 SIMD/FP unscaled ordered-memory forms
  (`STLUR`/`LDAPUR` B/H/S/D/Q) are also decoded with signed imm9, exact
  vector/scalar register metadata, and acquire/release flags.
- Later A64 representatives include BTI, pointer authentication, MTE, MOPS,
  LS64, and CSSC.

In a `USE_EXTRA_OPCODES=1` build, `CDISASM_ARM_CPU_ANY` enables every
implemented optional ARM family. Named profiles remain independent and
conservative: they receive only capabilities
that their profile table explicitly lists. For example, the existing Apple
cutoffs provide LOR beginning at A10/A10X, LSE beginning at A11, RCpc beginning
at A12, FP16/pointer authentication on their listed profiles (including
S4--S10), and SME/SME2 specifically on A18 and M4. SVE/SME and the other later
families are never inferred from an Apple ordinal. Atomic results preserve
read/write operands and independently tag atomic, acquire, release, pair, and
exclusive semantics. For an LSE read/modify/write or `SWP` encoding whose
result register is ZR, Arm drops the encoded acquire semantic; cdisasm
therefore keeps the mnemonic but clears the acquire metadata flag.

This is representative hand-written coverage, not complete A32, T32, A64,
Advanced SIMD, SVE, SVE2, SME, SME2, LSE2, or LSE128 semantic coverage. The
generated selector inventories all 6,569 canonical leaves from the pinned open
AARCHMRS input. It returns a successful public decode only when exact operands
can be lowered into the fixed result ABI; catalog-only or operand-opaque forms
return `CDISASM_STATUS_UNSUPPORTED_INSTRUCTION`.

## Implemented x86 instruction coverage

The ordinary scalar/base bullets are available with the zero mask. Every
implemented non-base family mentioned below—including x87, MMX/3DNow!, SIMD,
virtualization, system, memory-hint, CET, and undocumented forms—requires
`USE_EXTRA_OPCODES=1` and its corresponding `CDISASM_X86_DECODE_FLAG_*` bit in
addition to the selected CPU capability. The words “implemented” and
“complete” below describe cdisasm's encoding coverage only; they do not bypass
either gate.

- Legacy prefixes, operand/address-size overrides, segment overrides, and REX.
- 16-bit addressing and 32/64-bit ModRM and SIB addressing, including extended
  registers, RIP/EIP-relative addressing, and signed displacements.
- Integer ALU, move, test, exchange, stack, multiply/divide, shifts, bit tests,
  sign/zero extension, and common system instructions.
- Direct and indirect calls/jumps, short and near conditional branches, loops,
  returns, interrupts, and resolved relative targets.
- String instructions with `rep`/`repne`, multibyte NOP, `pause`, and CET
  `endbr32`/`endbr64`.
- The complete base and Extended 3DNow! selector maps, including register and
  memory source forms, plus `femms`, `prefetch`, and `prefetchw`. Retired
  instructions remain available only on CPU profiles that implemented them.
- The complete 13-instruction Intel VMX set, the eight base AMD SVM opcodes,
  and the SEV-ES `VMGEXIT` encoding, with vendor-specific CPU-profile gates.
- Stable historical/reserved encodings: SALC/UDB, 286/386 LOADALL, ICEBP as
  the INT1 alias, UD0/UD1, opcode `82`, shift-group `/6`, and TEST-group `/1`.
- Hardware entropy forms `RDRAND` and `RDSEED`, plus the complete RTM control
  set `XBEGIN`, `XABORT`, `XEND`, and `XTEST`. Their SECURITY/TRANSACTIONAL
  runtime bits and CPU profiles are independent: Ivy Bridge introduces
  `RDRAND`, Broadwell introduces `RDSEED`, and the named RTM profiles are
  Haswell through Skylake-SP, Sapphire Rapids, Granite Rapids, and Diamond
  Rapids. `CDISASM_CPU_ICE_LAKE`
  denotes the 2019 client family and exposes neither HLE nor RTM, matching
  Intel's [Ice Lake i7-1065G7 product specification](https://www.intel.com/content/www/us/en/products/sku/196597/intel-core-i71065g7-processor-8m-cache-up-to-3-90-ghz/specifications.html).
  Tiger Lake and Alder Lake likewise expose neither feature, following the
  [Tiger Lake processor datasheet](https://cdrdv2-public.intel.com/631121/631121_TGL%20Datasheet%20Volume1of2%20rev012_PUBLIC.pdf)
  and Alder Lake's [deprecated-technologies list](https://edc.intel.com/content/www/us/en/design/ipla/software-development-platforms/client/platforms/alder-lake-desktop/12th-generation-intel-core-processors-datasheet-volume-1-of-2/011/deprecated-technologies/).
  Sapphire Rapids restores the RTM gate: Intel lists TSX for the
  [Xeon Platinum 8490H](https://www.intel.com/content/www/us/en/products/sku/231747/intel-xeon-platinum-8490h-processor-112-5m-cache-1-90-ghz/specifications.html)
  and documents its new TSX load-tracking commands in the
  [4th Gen Xeon overview](https://www.intel.com/content/www/us/en/developer/articles/technical/fourth-generation-xeon-scalable-family-overview.html).
  The abstract AVX10 and APX presets conservatively inherit neither HLE nor
  RTM. `XBEGIN`, `XABORT`, and `XEND` require RTM; Intel defines `XTEST` when
  either HLE or RTM is present. Redundant `66`, `F2`/`F3`, and REX bytes are
  retained as encountered but are not reported as effective REP prefixes.
  `LOCK` on register-form group-9 entropy/collision encodings and mandatory
  prefixes on memory-form `/7` are invalid; unprefixed memory `/7` remains
  `VMPTRST`. The colliding 64-bit `F3 0F C7 /6` `SENDUIPI` encoding is
  structurally recognized as unsupported rather than mislabeled as `RDRAND`.
- The complete x87 D8--DF memory and register maps, including WAIT/no-WAIT
  mnemonic aliases, 14/28-byte environment and 94/108-byte state operands,
  8087/287/387/P6/SSE3 feature gates, and the nine Intel-documented 8087
  compatibility ranges/behaviors, including `FSTPNCE` and `FFREEP`. Plain
  pre-486 CPU profiles reject optional x87;
  the explicit CPU-plus-coprocessor profiles enable the appropriate level.
- VEX2/VEX3 `VZEROUPPER` and `VZEROALL`, with reserved-field validation, exact
  prefix/encoding offsets, LES/LDS ambiguity handling, and AVX CPU-profile gates.
- With the `AVX`/`AVX2` allow bits, 60 table-driven VEX2/VEX3 map-1 operations:
  packed/scalar `VADD`, `VSUB`, `VMUL`, `VDIV`, `VMIN`, and `VMAX`; packed
  `VAND`, `VANDN`, `VOR`, and `VXOR`; and common packed-integer add, subtract,
  logic, compare, multiply, average, min/max, and sum-of-absolute-differences
  forms. XMM forms require AVX, while YMM packed-integer forms independently
  require AVX2; exact no-AVX CPU profiles remain rejected.
- The modern descriptor tables also add representative VEX map-2/map-3 forms:
  `VPSHUFB`, `VPALIGNR`, BMI1/BMI2 (`ANDN`, `BEXTR`,
  `BLSI`/`BLSMSK`/`BLSR`, `BZHI`, `PDEP`, `PEXT`, `MULX`, `RORX`, `SARX`,
  `SHLX`, and `SHRX`), F16C conversions, and the complete 60-name packed and
  scalar VEX FMA3 132/213/231 matrix.
- The same optional tranche adds legacy AES-NI/PCLMULQDQ and SHA forms,
  implemented VEX/EVEX VAES and VPCLMULQDQ variants, and vector SHA-512,
  SM3, and SM4 forms. The complete 20-name AMD FMA4 matrix is joined by the
  release's complete cataloged XOP map-8/map-9 and `/is4` families, including
  variable shifts, rotates, horizontal operations, multiply-accumulate,
  comparisons, `VPPERM`, `VPERMIL2PS`/`VPERMIL2PD`, and XMM/YMM `VPCMOV`.
  AMD/Intel and chronological CPU capability checks remain separate;
  recognizing an XOP encoding does not enable it on an Intel profile.
- Representative EVEX descriptors cover AVX-512F, BW, VBMI, VNNI,
  VPOPCNTDQ, and IFMA. The structured result carries mask merge/zero,
  broadcast, compressed-displacement, embedded-rounding, and SAE metadata.
  The complete 60-name FMA3 matrix now decodes through EVEX: 36 packed PS/PD
  forms at 128, 256, and 512 bits plus 24 scalar SS/SD forms. Packed memory
  forms support broadcast; scalar memory stays m32/m64, while scalar register
  forms support embedded rounding/SAE. For scalar EVEX.b=0, LL=0--2 is LIG and
  LL=3 is reserved; register EVEX.b=1 uses all four LL values as rounding plus
  SAE, while memory EVEX.b=1 is reserved. The AVX-512 route uses the single
  most-specific AVX-512 runtime bit; its CPU and result groups independently
  include FMA3 and AVX-512F. The AVX10.1 route likewise uses only the AVX10
  runtime bit while retaining FMA3 as a CPU/group prerequisite. This is not a
  full AVX10 decoder.
- The exact Knights Mill AVX512_4VNNIW pair covers memory-only
  `VP4DPWSSD`/`VP4DPWSSDS` at EVEX.512 map-2 opcodes `52`/`53`. It requires
  W=0, U=1, B=0, a 128-bit Tuple1_4X source, and an AVX-512 runtime mask plus
  the independent Knights Mill CPU capability. Register sources and other
  vector lengths are reserved; compressed disp8 scales by 16 bytes.
- The classic mandatory-`66` EVEX map-2 permute/multishift slice covers
  `VPERMI2B`, `VPERMT2B`, `VPMULTISHIFTQB`, and `VPERMB` at all three vector
  lengths, including masks, full memory, compressed displacement, and the
  multishift-only `m64bcst` form. Its W=1 `VPERMI2W`, `VPERMT2W`, and `VPERMW`
  rows use AVX512BW on legacy processors and AVX10 as a separate route; reviewed
  APX address admission remains independent.
- The complete classic 51-mnemonic VEX K-mask family covers AVX-512F word
  operations plus AVX-512DQ/AVX-512BW byte, dword, and qword extensions.
  `KMOVB`/`KMOVW`/`KMOVD`/`KMOVQ` distinguish mask, memory, and GPR directions;
  shifts retain imm8 metadata, and unpack forms retain their source widths.
  Legacy profiles require the exact AVX-512F/DQ/BW capability route, while
  abstract AVX10/APX profiles promote the same classic encodings through the
  independently selected AVX10.1 route.
- The complete packed-integer EVEX compare-to-mask family covers
  `VPCMPB/W/D/Q` and `VPCMPUB/UW/UD/UQ` at 128, 256, and 512 bits. Results
  preserve the K destination, optional merge mask, exact mask-result width,
  vector or memory source, imm8 predicate, compressed displacement, and legal
  dword/qword broadcast. Zeroing, extended K destinations, byte/word
  broadcast, register-source EVEX.b, and LL=3 are rejected. Legacy profiles
  require AVX-512F, plus AVX-512VL below 512 bits and AVX-512BW for byte/word
  elements, together with the `AVX512` runtime bit. Abstract AVX10/APX profiles
  select only AVX10.1 and the `AVX10` runtime bit.
- The complete 144-form VEX/EVEX packed-integer MIN/MAX family covers signed
  and unsigned byte, word, dword, and qword elements. Its 48 VEX identities use
  exact AVX/AVX2 admission; its 96 EVEX identities preserve merge/zero masking,
  destination access, vector or memory sources, compressed displacement, and
  legal dword/qword broadcast. Legacy profiles require the exact
  AVX-512F/BW/VL route; abstract AVX10/APX profiles use AVX10.1 without
  fabricating legacy AVX-512 capabilities.
- The complete 36-form GFNI family covers legacy `GF2P8AFFINEINVQB`,
  `GF2P8AFFINEQB`, and `GF2P8MULB` plus every pinned VEX/EVEX vector identity.
  It preserves affine imm8, masks, legal broadcast, non-long aliases, exact
  `AVX_GFNI`/width-specific `AVX512_GFNI` admission, AVX10 alternatives, and
  APX-only U0/X4 memory addressing.
- The complete classic EVEX packed-integer multiply/multiply-add family covers
  `VPMULLW/D/Q`, `VPMULHW`, `VPMULHUW`, `VPMULHRSW`, `VPMULUDQ`,
  `VPMULDQ`, `VPMADDWD`, and `VPMADDUBSW` at all three vector lengths. It
  preserves exact AVX-512F/DQ/BW/VL versus AVX10.1 routes, masks, memory,
  compressed displacement, and the legal dword/qword broadcasts.
- The complete eight-mnemonic modular EVEX.66.0F packed-integer ADD/SUB matrix covers
  `VPADDB/W/D/Q` and `VPSUBB/W/D/Q` at XMM, YMM, and ZMM lengths. Its 24
  register and 24 full-memory shapes preserve masks and compressed
  displacement; dword/qword forms add 12 legal scalar-broadcast shapes.
  Byte/word forms use the exact AVX-512BW foundation, dword/qword forms use
  AVX-512F, sub-512-bit forms additionally use AVX-512VL, and AVX10.1 remains
  a mutually alternative route.
- The complete eight-name EVEX.66.0F packed-integer D/Q logical class covers
  `VPANDD/Q`, `VPANDND/Q`, `VPORD/Q`, and `VPXORD/Q` at XMM, YMM, and ZMM
  lengths. It preserves register and full-width memory sources, merge/zero
  masks, compressed displacement, and legal dword/qword scalar broadcast.
  Legacy profiles use AVX-512F and AVX-512VL below 512 bits; abstract
  AVX10/APX profiles use the mutually alternative AVX10.1 route.
- The complete dword/qword per-element variable packed-shift tranche covers
  `VPSLLVD/Q`, `VPSRLVD/Q`, and `VPSRAVD/Q`. VEX map-2 forms cover their allocated
  XMM/YMM register and full-memory shapes with AVX2 admission;
  `VPSRAVQ` has no VEX form. EVEX map-2 covers all six names at XMM/YMM/ZMM
  lengths with register, full-memory, legal dword/qword broadcast, merge/zero
  masks, and compressed displacement. Its legacy route requires AVX-512F/VL
  as applicable, while AVX10.1 is the mutually alternative route. Exact APX
  P0.B4 register/EGPR-memory and U0 memory forms are owned only with the
  independent long-mode and APX-F gates.
- The adjacent EVEX word variable-shift class covers `VPSLLVW`, `VPSRLVW`,
  and `VPSRAVW` at XMM, YMM, and ZMM lengths. EVEX.66.0F38.W1 opcodes
  `12`, `10`, and `11` accept register or full-width memory count sources,
  merge/zero masks, and compressed displacement but reject broadcast. Legacy
  profiles require AVX-512F/BW and AVX-512VL below 512 bits; AVX10.1 is the
  mutually alternative route. Exact APX P0.B4 and U0/X4 ownership additionally
  requires long mode and APX-F.
- The EVEX variable packed-rotate class covers `VPROLVD/Q` and `VPRORVD/Q`
  at XMM, YMM, and ZMM lengths. EVEX.66.0F38 opcodes `15` and `14` use W to
  select dword or qword elements and support register, full-memory, legal
  scalar-broadcast, mask/zero, and compressed-displacement forms. Legacy
  profiles require AVX-512F and AVX-512VL below 512 bits; AVX10.1 is the
  mutually alternative route. Exact APX P0.B4/U0/X4 forms additionally require
  long mode and APX-F.
- The adjacent EVEX immediate packed-rotate class covers `VPROLD/Q` and
  `VPRORD/Q` at XMM, YMM, and ZMM lengths. EVEX.66.0F opcode `72` uses
  ModRM `/0` or `/1` as a group selector, EVEX.vvvv/V' as the destination,
  and an imm8 count. Register, full-memory, legal scalar-broadcast, mask/zero,
  compressed-displacement, AVX-512F/VL or alternative AVX10.1, and exact APX
  P0.B4/U0/X4 routes are covered.
- The same opcode-`72` group now covers the remaining allocated immediate
  packed shifts: `VPSRLD` at `/2` W0, `VPSRAD` at `/4` W0, `VPSRAQ` at `/4`
  W1, and `VPSLLD` at `/6` W0. They share the rotate class's three vector
  lengths, register/full-memory/broadcast shapes, masks, compressed
  displacement, feature alternatives, APX routes, and truncation precedence.
  `/2` W1, `/6` W1, and every `/3`, `/5`, and `/7` control are reserved and
  invalid after the shared imm8 has been consumed.
- The adjacent EVEX.66.0F immediate-shift groups cover opcode `71` word forms
  `VPSRLW`, `VPSRAW`, and `VPSLLW`; opcode `73` qword forms `VPSRLQ` and
  `VPSLLQ`; and opcode `73` byte-lane forms `VPSRLDQ` and `VPSLLDQ`.
  XMM/YMM/ZMM lengths, register/full-memory operands, compressed displacement,
  imm8, exact AVX-512F/BW/VL versus AVX10 admission, and owned APX
  P0.B4/U0/X4 routes are represented. Masks and qword broadcast are admitted
  only where the architectural form permits them; byte-lane forms reject both.
  The other 20 opcode/W/extension controls are reserved and invalid.
- Existing `VPAVGB` and `VPAVGW` now cover their complete EVEX.66.0F
  packed-integer average class at XMM, YMM, and ZMM lengths. Register and
  full-width memory sources, masks, and compressed displacement are preserved;
  broadcast, SAE, and embedded rounding are invalid. The legacy route requires
  AVX-512F/BW/VL as applicable, while AVX10.1 remains an alternative.
- For these logical and average classes, exact APX P0.B4 register and
  EGPR-memory forms are owned in 64-bit mode and require APX-F. This does not
  claim unrelated P0.B4 encodings or make APX admission replace the independent
  AVX/AVX-512-or-AVX10 feature checks.
- The complete eight-mnemonic signed/unsigned saturating packed ADD/SUB family
  covers `VPADDSB/W`, `VPADDUSB/W`, `VPSUBSB/W`, and `VPSUBUSB/W` through
  VEX.128/256 and EVEX.128/256/512. Its 32 VEX and 48 EVEX operand shapes each
  accept a register or full-width memory source; none accepts broadcast. VEX
  W and EVEX W are ignored. VEX.128 requires AVX, VEX.256 requires AVX2, and
  EVEX uses the exact AVX-512F/BW/VL or mutually alternative AVX10.1 route.
  EVEX merge/zero masks, compressed displacement, extended registers, and
  16/32/64-bit decode-mode legality remain numeric metadata rather than text
  stored in the decoder.
- Representative AMX-TILE/BF16/INT8 forms include tile configuration,
  load/store/zero/release, and dot-product operations. The bounded newer slice
  adds AMX-FP16, AMX-COMPLEX, AMX-FP8, MOVRS tile loads, and AMX-to-vector row
  conversion/move forms. Four AVX10.2 BF16 arithmetic forms cover add,
  subtract, multiply, and divide. The APX slice includes REX2 integer and
  memory forms, two- and three-operand NDD/NF forms for the implemented ALU
  families, selected extended-register vector operands, `PUSH2`/`POP2`,
  `JMPABS`, and MOVDIR forms.
- Cache/system coverage includes `CLFLUSH`, `CLFLUSHOPT`, `CLWB`, `RDPID`,
  `SERIALIZE`, `MOVDIRI`, `MOVDIR64B`, `WBNOINVD`, `MONITORX`, `MWAITX`,
  `MCOMMIT`, `INVLPGB`, `TLBSYNC`, `RMPUPDATE`, `PVALIDATE`, `RMPADJUST`, and
  `PSMASH`. Their shared opcode-map
  collisions are resolved structurally before CPU and runtime-family
  validation; a recognized form is not enabled merely because its name ID is
  public.
- Twelve CET shadow-stack mnemonics cover `CLRSSBSY`, 32/64-bit `INCSSP` and
  `RDSSP`, `RSTORSSP`, `SAVEPREVSSP`, `SETSSBSY`, and 32/64-bit `WRSS` and
  `WRUSS`. The fixed-width/32-bit forms are accepted in 16-, 32-, and 64-bit
  decode modes; the `Q` forms require 64-bit mode. Redundant `66` bytes do not
  displace the mandatory `F3` selector. CET-SS CPU/runtime gating and
  instruction-specific privilege metadata remain independent.
- The WAITPKG register forms `UMONITOR`, `UMWAIT`, and `TPAUSE` require the
  `SYSTEM` runtime bit and an explicit WAITPKG CPU capability. The physical
  presets that expose it are Tremont-based Pentium Silver N6000, Alder Lake,
  Sapphire Rapids, Granite Rapids, Arrow Lake, and Diamond Rapids; Ice Lake,
  Tiger Lake, AMD Zen 4, and the abstract AVX10/APX profiles deliberately do not infer it.
  The unrestricted `CDISASM_CPU_X86` profile accepts the implemented forms.
  REX2 map 1 also
  requires APX-F; Diamond Rapids and the unrestricted profile provide the
  combined route, while the earlier named WAITPKG profiles do not.
- WAITPKG shares `0F AE` with CET and cache-management forms. The rightmost
  `F2`/`F3` selector chooses `UMWAIT`/`UMONITOR` and takes precedence over a
  redundant `66`; plain `66` chooses `TPAUSE`. The memory encodings retain
  separate ownership: mandatory-`F3` memory `/6` remains CET `CLRSSBSY`, while
  register `/5` remains CET `INCSSP`; `66` memory is the independently gated
  CLWB route, and reserved F2 memory, reserved F2/66 register extensions, and LOCKed
  WAITPKG forms are rejected as invalid. REX2 does not change the architectural
  ModRM `mod=00` SIB `base=5` disp32/no-base exception even when B4 is set.
- `PTWRITE` register form 2438 and memory form 2439 exactly own mandatory-F3
  `0F AE /4` in 16-, 32-, and 64-bit modes. Their single read operand is GPRy
  or MEMy: dword in every mode unless effective W selects qword in 64-bit
  mode. Any `66`, a rightmost `F2`, LOCK, and malformed REX2 map controls are
  invalid; unprefixed memory `/4` remains the XSAVE collision. REX.R and
  REX2.R/R4 do not extend the `/4` opcode field, while B/B4 and SIB X/X4
  extend the source. A REX2 form independently requires APX-F in addition to
  the PTWRITE runtime bit and CPU capability. The unrestricted, N4020, N6000,
  Alder Lake, Sapphire Rapids, Granite Rapids, Arrow Lake, Diamond Rapids,
  AVX10, and APX profiles admit ordinary PTWRITE; all other named profiles
  reject it. The focused suite sweeps all 768 F3/0F/AE ModRM controls across
  the three modes and locks prefix, profile, REX2, truncation, and formatter
  behavior; AT&T adds `l`/`q` only for memory operands.
- `MOVNTI` dword form 1692 and qword form 1693 exactly own the SSE2
  NP/OSZ=0 `0F C3 /r` memory-only row. The destination memory operand is
  write-only and the GPR source is read-only; dword is selected in every mode
  unless effective W selects qword in 64-bit mode. `66`, F2, F3, LOCK, and a
  register ModRM are invalid, while address-size and segment prefixes remain
  valid. Ordinary REX W/R/B/X and map-1 REX2 W/R/R4/B/B4/X/X4 transport are
  exact; a legacy prefix after REX makes that earlier REX ineffective, REX
  plus REX2 is invalid, and 64-bit-only REX2 map 0 never aliases MOVNTI.
  MOVNTI is nonprivileged/CPL3. Ordinary forms
  require the SSE2 runtime bit; CPU admission is unrestricted X86, every
  applicable profile from Pentium 4 through Pentium Silver N6000, and every
  applicable profile from Granite Rapids through Knights Mill. Earlier
  x87-only profiles reject them. REX2 requires
  both SSE2 and APX runtime bits plus SSE2 and APX-F CPU capabilities, which
  only unrestricted X86, APX, and Diamond Rapids currently combine. Eligible
  forms remain structurally owned as unsupported when extras are disabled;
  profiles lacking SSE2 remain invalid. Intel formatting keeps memory first
  with an explicit dword/qword size, while AT&T reverses the operands without
  inventing a mnemonic suffix. The focused suite sweeps all 768 mode/ModRM
  cells, 16 ordinary REX controls, 256 REX2 controls, prefix ordering,
  truncation, profiles, and formatter variants.
- The exact non-temporal SIMD-store tranche covers eighteen legacy, VEX, and
  EVEX forms: `MOVNTDQ` 1691 and `VMOVNTDQ` 5869--5873; `MOVNTPD` 1694 and
  `VMOVNTPD` 5874--5878; and `MOVNTPS` 1695 and `VMOVNTPS` 5879--5883.
  Every form is memory-only, writes its non-temporal destination, and reads an
  MMX, XMM, YMM, or ZMM source. Legacy forms use MMX/SSE/SSE2/SSE4a, VEX
  128/256-bit forms use AVX, and EVEX 128/256/512-bit forms use their
  width-specific AVX-512F groups with 16/32/64-byte compressed-displacement
  scaling; masking, zeroing, broadcast, and register ModRM forms are invalid.
  The legacy prefix
  lattice also preserves exact `MOVNTQ` form 1696 and AMD `MOVNTSD`/`MOVNTSS`
  forms 1697--1698: NP versus `66` selects MMX `MOVNTQ` versus `MOVNTDQ`, while
  NP/`66`/F2/F3 on `0F 2B` selects `MOVNTPS`/`MOVNTPD`/`MOVNTSD`/`MOVNTSS`.
  Rightmost F2/F3 selection, REX/REX2 and APX extended addressing, malformed
  controls, truncation precedence, both syntaxes, and extras-OFF ownership are
  locked by complete legacy-ModRM and EVEX-control sweeps.
- Memory-source `MOVNTDQA` form 1690 and `VMOVNTDQA` forms 5864--5868 are
  exact. Legacy `66 0F 38 2A /r` writes XMM from m128 and uses pinned SSE4
  ISA-set group 310/runtime bit 270 with SSE4.1-capable profile admission.
  VEX.128 uses AVX, VEX.256 uses AVX2 with its AVX foundation, and EVEX
  128/256/512 uses the corresponding AVX512F width group and runtime bit.
  All six forms have one write-only vector destination and one read-only
  full-width memory source; register ModRM, masks, broadcast, rounding, and
  SAE are invalid. VEX/EVEX reserved `vvvv`, EVEX W/LL/z/b/aaa controls,
  mandatory-prefix selection, and the non-66 `VPBROADCASTMB2Q` collision are
  preserved. EVEX compressed disp8 scales by 16/32/64 bytes, and 64-bit APX
  B4/U0/X4 addressing additionally requires APX/APX-F. The focused ModRM
  sweeps cover 576/384/576 allocated legacy/VEX/EVEX memory controls and
  192/128/192 register-reserved controls, plus complete VEX and EVEX control,
  profile, formatting, truncation, and extras-OFF checks.
- Unaligned memory-load `LDDQU` form 1574 and `VLDDQU` forms 5583--5584 are
  exact. Legacy `F2 0F F0 /r` writes XMM from m128 under SSE3; operand-size
  `66` is explicitly ignored even when it follows F2, and REX.W is ignored.
  The 64-bit REX2 map-1 route preserves the SSE3 requirement while adding an
  independent APX/APX-F gate and extending destination and address registers.
  `VEX.128/256.F2.0F.WIG F0 /r` writes XMM/YMM from equal-width memory; both
  widths require AVX, encoded `vvvv` must be all ones, and W is ignored.
  Every form is memory-only. Register ModRM, LOCK, wrong mandatory-prefix
  controls, noncanonical `vvvv`, and malformed REX2 controls are invalid.
  Other maps and EVEX map-1/F0 are unowned and therefore report
  `UNSUPPORTED_INSTRUCTION`, not an LDDQU-family invalid control. Focused tests
  exhaust legacy prefixes/ModRM, all VEX control bytes and ModRM values, the
  REX2 payload space, profiles, formatting, truncation, and extras-OFF ownership.
- VEX move-mask forms are exact in pinned-XED order: `VMOVMSKPD` XMM/YMM are
  forms 5860--5861, followed by `VMOVMSKPS` XMM/YMM as forms 5862--5863.
  VEX map 1 opcode `50` uses NP/`66` and VL to select those four forms, ignores
  W, requires raw `vvvv=1111` and register ModRM, writes a GPR32, reads the
  selected XMM/YMM register, and requires AVX. In 16/32-bit modes VEX3.B is
  ignored while the C4/LES disambiguation still fixes R/X; in long mode R/B
  extend the two registers. F2/F3 and memory controls are invalid. Legacy and
  REX2 map-1 `0F 50` remain `MOVMSKPS`/`MOVMSKPD`, EVEX map-1 opcode `50`
  remains unowned, and the VEX map-2 opcode-`50` VNNI row remains disjoint.
  The focused suite exhausts 7,168 allocated encodings across all modes,
  exactly 1,792 per form.
- `VMOVQ` forms 5884--5896 exactly own the qword subset of VEX/EVEX map-1
  opcodes `6e`, `7e`, and `d6`. Opcode and pp select GPR/memory/XMM direction;
  fixed-W `66/6e` and `66/7e` are 64-bit-only, while WIG `F3/7e` and `66/d6`
  run in all modes. VEX requires VL128 and raw `vvvv=1111`. EVEX additionally
  requires W1, U1, V'=1, LL=00, z/b/aaa=0, except that long-mode memory forms
  admit APX-gated B4 and raw-U0/X4 address extensions. W0 and non-long fixed-W
  rows retain their `VMOVD`/MOVZXC collision ownership. Classic forms require
  AVX; EVEX forms use the no-VL AVX512F-128 foundation or AVX10.1, including
  Knights Mill. The focused and pinned-XED sweeps agree on all 79,872
  allocations: 18,432 VEX and 61,440 EVEX across the 13 public forms.
- `VMOVRSB`/`VMOVRSD`/`VMOVRSQ`/`VMOVRSW` forms 5897--5908 exactly own the
  64-bit EVEX map-5 opcode-`6f` memory-source rows at 128, 256, and 512 bits.
  Each form writes an XMM/YMM/ZMM destination, reads full-width memory, and
  supports k-mask merge or zeroing; register ModRM and reserved EVEX controls
  are rejected. The three widths use their exact AVX10 MOVRS groups and runtime
  bits, compressed disp8 scales by 16/32/64 bytes, and B4/X4 address promotion
  independently requires APX. The focused suite exhausts 2,211,840 allocated
  encodings, 184,320 per form.
- `VMOVSD` forms 5909--5915 exactly own the scalar-double VEX/EVEX map-1
  opcode-`10`/`11` F2 rows without disturbing legacy `MOVSD`. VEX memory
  load/store and both three-register directions require AVX, treat L/W as
  ignored, and require reserved `vvvv` only for memory forms. EVEX W1 accepts
  LL=0--2, uses the AVX512F scalar group/runtime bit, supports merge/zero masks
  on register destinations and merge-only masked stores, and scales compressed
  disp8 by eight. Long-mode B4/X4 addressing independently requires APX;
  U0 register forms remain invalid. The focused suite exhausts 7,721,472
  allocations: 132,096 VEX and 7,589,376 EVEX across all seven forms.
- `VMOVSHDUP` forms 5916--5925 and `VMOVSLDUP` forms 5929--5938 exactly
  own the PF3 VEX/EVEX map-1 opcode-`16`/`12` unary duplicate moves. VEX
  provides XMM/YMM register and full-width memory sources under AVX, with W
  ignored and encoded `vvvv=1111`. EVEX provides XMM/YMM/ZMM register and
  full-width memory sources at W0 with fixed `vvvv`/V', b=0, merge/zero
  masks, and the exact AVX512F-128/256/512 width group and runtime bit;
  merge-masked destinations are read/write and every source is read-only.
  Compressed disp8 scales by 16/32/64 bytes, and long-mode B4/X4 addressing
  independently requires APX/APX-F. Legacy `MOVSHDUP`/`MOVSLDUP`, wrong
  mandatory prefixes, and reserved EVEX controls remain disjoint.
- `VMOVSH` forms 5926--5928 exactly own the EVEX map-5 PF3/W0 scalar-half
  opcode-`10`/`11` block: m16 store, m16 load, and three-XMM register form.
  It requires the exact AVX512-FP16 scalar group/runtime bit, supports
  merge/zero masks on register destinations and merge-only masked stores,
  and scales compressed disp8 by two. Long-mode B4/X4 address promotion
  independently requires APX/APX-F. Together, the three FP16 scalar forms
  and twenty duplicate-move forms allocate 9,092,608 encodings; factored
  boundary sweeps reject 3,337 controls and retain 2,308 legacy/neighbor
  collision-selector cells. Pinned XED accepts all 42 valid corpus witnesses
  as the intended family and rejects all 18 reserved-control witnesses.
- `VMOVSS` forms 5939--5945 exactly own the scalar-single VEX/EVEX map-1
  opcode-`10`/`11` PF3 rows without disturbing legacy `MOVSS`. They mirror the
  scalar-move direction and NDS shapes while fixing W0 and dword memory:
  VEX requires AVX, and EVEX uses the `AVX512F_SCALAR` group/runtime bit. EVEX
  register destinations support merge/zero masks, masked stores are merge-
  only, and ignored LL and merge-destination access follow the exact scalar
  rules; compressed disp8 scales by four, and long-mode B4/X4 address
  promotion independently requires APX. Reserved decorators and U0 register
  controls remain invalid. The focused suite exhausts 7,721,472 allocations:
  132,096 VEX and 7,589,376 EVEX across all seven forms.
- `VMOVUPD` forms 5946--5962 and `VMOVUPS` forms 5963--5979 exactly own the
  packed unaligned VEX/EVEX map-1 opcode-`10`/`11` rows. NP/W0 selects UPS and
  `66`/W1 selects UPD; opcode `10` writes a vector destination, while opcode
  `11` writes its register or full-width memory destination. VEX provides
  XMM/YMM forms under AVX with W ignored and encoded `vvvv=1111`. EVEX adds
  XMM/YMM/ZMM forms through the exact AVX512F width group or AVX10.1 route,
  merge/zero masking on register destinations, merge-only masked stores, and
  16/32/64-byte Full-tuple disp8 scaling. Long-mode B4/X4 address promotion
  independently requires APX/APX-F. Legacy moves and the F2/F3 scalar rows
  remain delegated rather than being relabeled. The focused classifier owns
  2,425,856 allocated encodings, rejects 3,190 reserved controls, and retains
  1,544 collision/delegation selector cells across the 34 forms.
- `VMOVW` forms 5980--5986 exactly own all eight pinned-XED EVEX map-5
  opcode-`6e`/`7e` records. The WIG `66` selector maps the GPR32, m16, and XMM
  directions to `AVX512_FP16_128N`; F3/W0 maps the two m16 directions and both
  register-direction records sharing form 5986 to `AVX512_MOVZXC_128`. Every
  form is VL128 with fixed `vvvv`/V', U1 for register operands, no masks,
  broadcast, rounding, or SAE, and Tuple2 compressed displacement for m16.
  Long-mode B4/X4 address or GPR promotion independently requires APX/APX-F;
  non-long extension fields follow the exact ignored-or-invalid boundaries.
  The seven form identities allocate respectively 5,120, 27,648, 13,824,
  5,120, 27,648, 13,824, and 5,120 encodings, for 98,304 total. Factored P1/P2
  sweeps reject 3,046 target-owned controls while map-1 VMOVD/VMOVQ and map-2
  neighbors retain their own identities.
- `VMPSADBW` forms 5987--5996 exactly cover the ten pinned-XED VEX/EVEX
  records. VEX map-3 opcode `42` uses mandatory `66`, WIG, and VL128/VL256
  with AVX/AVX2; EVEX uses F3/W0 at 128, 256, and 512 bits with the exact
  `AVX512_MEDIAX_128/256/512` group and runtime route. Every form writes a
  vector destination, reads the `vvvv` vector and a same-width register or
  Full-tuple memory source, and reads imm8. EVEX destinations support k-mask
  merge/zero semantics, with merge destinations read/write, and compressed
  displacement scales by 16/32/64 bytes. Promoted B4/X4 memory addressing
  independently requires APX/APX-F; register B4 and non-long extension fields
  retain their exact ignored-or-invalid behavior. Legacy `MPSADBW` and the
  EVEX `VDBPSADBW` selector remain disjoint. Focused representative-immediate
  sweeps cover 196,608 VEX and 829,440 canonical EVEX control/ModRM cells;
  separate P1/P2 sweeps and all-imm8 checks retain reserved prefix, decorator,
  vector-length, memory, and truncation boundaries.
- The exact virtualization tranche covers `VMPTRLD`/`VMPTRST` forms
  5997--5998, the four register/memory and 32-/64-bit `VMREAD` forms
  5999--6002, `VMRESUME` form 6003, `VMRUN` form 6004, and `VMSAVE` form
  6005. Pointer operands are qword memory, VMREAD writes its register or memory
  destination and reads the VMCS-field register, and VMRUN exposes its implicit
  address-sized AX/EAX/RAX operand; the other fixed forms have no explicit
  operands. Forms 5997--6003 publish both the VMX capability umbrella and the
  exact pinned VTX ISA-set group; exact VTX bit 267 admits those forms, while
  VMRUN/VMSAVE retain the separate SVM route. Privilege/status-flag metadata,
  all-mode sizing, ignored versus reserved prefixes, APX-gated REX2 promotion, and the
  VMCLEAR/EXTRQ/INSERTQ collision partitions remain distinct. Focused
  sweeps cover all 768 legacy VMREAD mode/ModRM tuples, 32,768 REX2 VMREAD
  tuples, and 2,432 REX2 pointer/fixed tuples.
- `VMULBF16` forms 6006--6011 exactly cover the pinned XED
  `AVX10_2_BF16_128/256/512` register and memory leaves. EVEX map 5 opcode
  `59`, mandatory `66`, and W0 select XMM/YMM/ZMM forms; destinations support
  k-mask merge/zero semantics, memory accepts Full-tuple disp8 compression or
  BF16 `1to8/16/32` broadcast, and register `EVEX.b` is reserved. Exact
  runtime bits 99--101 select one width without admitting siblings through
  the AVX10 umbrella. APX B4 extends a memory base, U0/X4 extends a memory
  index, U0 register forms are invalid, and B4 register forms remain
  APX-qualified while leaving the vector source unchanged.
- `VMULPH` forms 6022--6027 and scalar `VMULSH` forms 6042--6043 exactly own
  EVEX map 5 opcode `59` with no mandatory prefix or F3, respectively, and
  W0. Packed XMM/YMM/ZMM forms support Full-tuple memory, FP16
  `1to8/16/32` broadcast, masks, and fixed-ZMM embedded rounding; scalar
  forms use an m16 Tuple2 source and fixed-XMM embedded rounding. Exact
  `AVX512_FP16_128/256/512/SCALAR` runtime bits admit only their own forms
  through either the AVX512-FP16 or AVX10.1 route. APX B4/U0/X4 ownership,
  high registers, LLIG scalar aliases, all four rounding controls, and the
  neighboring `VMULBF16`, mandatory-F2, W1, and reserved-decorator partitions
  remain distinct.
- Classic `VMULPD`/`VMULPS`/`VMULSD`/`VMULSS` forms 6012--6021,
  6028--6041, and 6044--6047 are exact. VEX forms use AVX with XMM/YMM packed
  or XMM scalar register/memory sources. EVEX forms retain exact
  `AVX512F_128/256/512/SCALAR` identities and runtime bits 128/130/131/133,
  with AVX-512F/AVX512VL or AVX10.1 profile routes as appropriate. Packed
  memory supports Full-tuple disp8 compression and scalar broadcast; scalar
  memory uses its element tuple and reserves `EVEX.b`. Register `EVEX.b`
  selects all four embedded-rounding/SAE controls, with fixed ZMM packed or
  XMM scalar identity. Masks, merge/zero access, VEX WIG and scalar LIG,
  high registers, APX B4/U0/X4 addressing, legacy-prefix collisions, reserved
  W/LL/decorator controls, Arrow Lake rejection, and the Knights Mill
  AVX512VL boundary remain explicit.
- The follow-on exact VTX block covers `VMWRITE` forms 6048--6051,
  `VMXOFF` form 6052, and `VMXON` form 6053. NP `0F 79 /r` selects the
  GPR32/register-or-dword-memory forms outside long mode and the
  GPR64/register-or-qword-memory forms in long mode; both operands are reads.
  Fixed `0F 01 C4` `VMXOFF` has no visible operands, while mandatory-F3
  `0F C7 /6` `VMXON` reads qword memory. All six forms retain CPL0, aggregate
  status-flag writes, the VMX umbrella, and exact VTX runtime identity.
  `VMXOFF` and `VMXON` additionally carry NOTSX, and `VMXON` requires protected
  mode.
  Ordinary REX is accepted where architectural, and REX2 map-1 promotion
  independently requires APX-F. Prefix `66` selects `EXTRQ`, F2 and both
  `66`+F2 orders select `INSERTQ`, and F3 is invalid for `VMWRITE`; `VMCLEAR`,
  malformed controls, and truncation remain disjoint. The focused suite now
  covers all 15 virtualization forms, 1,536
  legacy and 65,536 REX2 VMREAD/VMWRITE tuples, 3,584 REX2 pointer/fixed
  tuples, and 33,536 VMXOFF classifier cells against pinned XED.
- Classic packed logical-OR `VORPD` forms 6054--6063 and `VORPS` forms
  6064--6073 are exact. VEX map-1 opcode `56` provides XMM/YMM register and
  equal-width memory sources under AVX. EVEX provides XMM/YMM/ZMM register,
  Full-memory, and scalar-broadcast sources with exact
  `AVX512DQ_128/256/512` group/runtime admission through AVX-512DQ/VL or
  AVX10.1. It preserves merge/zero masks, Full-tuple disp8 scaling, ordinary
  high registers, and APX B4/U0/X4 memory addressing. Register `EVEX.b` is
  reserved: these logical operations never acquire embedded rounding or SAE.
  The VEX/EVEX W and mandatory-prefix selectors, non-long ignored-extension
  rules, legacy LES/LDS collisions, malformed decorators, and truncation
  boundaries remain explicit.
- `VPABSB` forms 6088--6097, `VPABSD` forms 6098--6107, `VPABSQ` forms
  6108--6113, and `VPABSW` forms 6114--6123 are exact in their non-linear
  pinned-XED order. VEX map-2 unary byte/word/dword forms provide XMM under
  AVX and YMM under AVX2. EVEX adds XMM/YMM/ZMM mask-merge/zero forms:
  byte/word use the exact AVX512BW width route, dword/qword use AVX512F, and
  the allocated AVX10.1 alternatives remain distinct. Full-memory disp8
  scales by 16/32/64 bytes; only dword/qword memory admits scalar broadcast
  with four-/eight-byte tuple scaling. Reserved `vvvv`/V', W, LL, decorator,
  and prefix controls, non-long extension aliases, high registers, APX
  B4/U0/X4 addressing, collisions, and truncation precedence are explicit.
  The bounded suite classifies 9,216 VEX allocations plus 580,608 reserved
  controls and 259,200 EVEX allocations plus 527,232 reserved controls.
  Pinned XED validates all 36 identities and their width/feature routes;
  82 corpus rows and 60 reviewed seeds retain the complete form set and
  representative legality, formatting, profile, and extras-OFF boundaries.
- `VPACKSSDW` forms 6124--6133, `VPACKSSWB` forms 6134--6143,
  `VPACKUSDW` forms 6144--6153, and `VPACKUSWB` forms 6154--6163 are exact.
  Their three operands are an XMM/YMM/ZMM destination, an equal-width first
  register source, and an equal-width register or memory source. VEX XMM uses
  AVX and VEX YMM uses AVX2. EVEX adds exact AVX512BW_128/256/512 width
  routes, mask merge/zero, high registers, Full-tuple disp8, and four-byte
  broadcast only for the dword-source families; allocated AVX10.1 and
  independently gated APX address extensions remain distinct. Reserved
  prefix, W, LL, decorator,
  extension, collision, and truncation controls retain exact ownership. The
  bounded suite classifies 196,608 allocated plus 589,824 reserved VEX cells
  and 40,320 allocated plus 746,112 reserved EVEX cells. Pinned XED and LLVM
  21 confirm all 40 forms; 80 corpus rows and 60 reviewed seeds cover the
  semantic, formatting, profile, truncation, and extras-OFF boundaries.
- `VPBLENDD` forms 6306--6309 and `VPBLENDW` forms 6338--6341 are exact
  VEX.0F3A.66 NDS-plus-imm8 encodings with destination, `vvvv` source,
  register-or-memory ModRM source, and immediate operands. `VPBLENDD` requires
  AVX2 and W=0 at both XMM and YMM widths. `VPBLENDW` uses AVX for XMM and
  AVX2 for YMM while treating W as ignored. The focused suite exhausts
  294,912 allocated and 1,277,952 reserved controls and locks all four operand
  access records, address formation, prefix and collision ownership, formatter
  schemas, and truncation precedence. Pinned XED and LLVM 21 independently
  confirm the encodings; 30 corpus rows and 16 reviewed seeds retain both
  syntaxes, profile/runtime boundaries, and extras-OFF ownership.
- `VPBLENDVB` forms 6334--6337 are exact VEX.0F3A.66.W0 encodings. Forms
  6334/6335 are the L=0 XMM memory/register pair, while 6336/6337 are the L=1
  YMM memory/register pair. They expose a written destination,
  read-only `vvvv` and ModRM sources, and a fourth read-only vector source
  selected by the high nibble of the trailing `SE_IMM8`; the low nibble is
  ignored. That byte is encoding metadata, so `encoding.selector_offset`
  records it and `encoding.immediate_count` remains zero. XMM requires AVX;
  YMM independently requires AVX2. A complete form rejected by the selected CPU
  profile is invalid, while a missing runtime-family bit is unsupported.
  Address-size and segment overrides are accepted, while legacy
  operand/repeat/LOCK/REX prefixes, W=1, and pp other than 66 are invalid after
  the complete ModRM/SIB/displacement/selector payload is consumed; incomplete
  owned inputs therefore remain truncated, while wrong-map/opcode neighbors and
  allocated extras-OFF forms remain unsupported. In non-long modes, C4 R/X
  collisions retain LES/invalid routing, while B, high `vvvv`, and the
  selector high bit alias into the eight-register namespace. This follows
  pinned XED; LLVM 21 and Capstone instead expose an impossible high selector
  register for that non-long spelling. The focused suite classifies 98,304
  allocated and 688,128 reserved controls and sweeps all 1,536 mode/L/selector
  combinations. Thirty-four corpus rows and 18 reviewed seeds retain form,
  operand, status, formatting-schema, profile/runtime, address, and extras-OFF
  boundaries.
- VEX `VPBROADCASTB` forms 6342/6343/6347/6348 and `VPBROADCASTW` forms
  6387/6388/6392/6393 exactly own C4 map-2 opcodes `78`/`79` with pp=66,
  W=0, and encoded `vvvv=1111`. Each writes an XMM/YMM destination and reads
  either a byte/word of memory or the low byte/word of an XMM register,
  without publishing broadcast metadata.
  Results carry both AVX and AVX2 groups, while the most-specific AVX2 runtime
  selector alone admits both widths; a missing runtime bit is unsupported and
  a selected profile lacking AVX2 is invalid. Address-size and segment
  overrides are accepted. W, pp, `vvvv`, or legacy operand/repeat/LOCK/REX
  violations become invalid only after the complete ModRM/SIB/displacement
  payload is consumed, preserving truncation precedence; allocated extras-OFF
  forms are unsupported. In non-long modes raw C4 R'/X' collisions remain LES,
  while B' aliases into the eight-register namespace. EVEX opcode `78`/`79`
  remains separately owned. The combined focused suite partitions 1,572,864
  controls into 12,288 allocated and 1,560,576 reserved cells. Pinned XED and
  LLVM 21 samples confirm all eight forms. Sixty-two corpus rows and 36 reviewed
  seeds retain operand, status, formatting, address, profile/runtime,
  collision, and extras-OFF contracts.
- VEX `VPBROADCASTD` forms 6355/6356/6360/6361 and `VPBROADCASTQ` forms
  6374/6375/6379/6380 exactly own C4 map-2 opcodes `58`/`59`. They extend the
  byte/word contract with dword/qword memory or low-XMM-register reads, while
  retaining pp=66, W=0, encoded `vvvv=1111`, XMM/YMM writes, AVX+AVX2
  metadata, AVX2 admission, non-long aliases, and late payload-truncation
  precedence. Their focused suite partitions 1,572,864 controls into 12,288
  allocated and 1,560,576 reserved cells. Pinned XED and LLVM 21 confirm all
  eight forms; 62 corpus rows and 36 reviewed seeds retain the exact boundary.
- VEX `VPCMPEQQ` forms 6454--6457 exactly own C4 map-2 opcode `29` with
  pp=66 and W ignored. L=0 selects XMM register/memory forms under AVX; L=1
  selects YMM register/memory forms under AVX2 while retaining AVX metadata.
  The destination is write-only and both NDS `vvvv` and ModRM sources are
  read-only. All modes, high registers and addresses, non-long aliases,
  address/segment overrides, legacy and EVEX siblings, and complete-payload
  truncation precedence remain distinct. The focused suite exhausts 786,432
  controls as 196,608 allocated and 589,824 reserved. Pinned XED and LLVM 21
  confirm the forms; 30 corpus rows and 16 reviewed seeds retain the boundary.
- VEX `VBLENDPD` forms 3527--3530 and `VBLENDPS` forms 3531--3534 exactly
  own C4 map-3 opcodes `0D`/`0C` with pp=66 and W ignored. L=0 selects XMM
  register/memory forms and L=1 selects YMM register/memory forms; both widths
  require and publish AVX, never AVX2. The destination is write-only, the NDS
  `vvvv` and ModRM sources are read-only, and the trailing imm8 is the fourth
  read operand. All modes, W aliases, high registers and addresses, non-long
  C4/LES and B-extension behavior, address/segment overrides, reserved pp and
  legacy-prefix controls, and complete-payload truncation precedence remain
  distinct. The `cdisasm_x86_vblend_tests` suite partitions 1,572,864 controls
  into 393,216 allocated and 1,179,648 reserved: each memory form accounts for
  73,728 encodings and each register form for 24,576. It also locks Intel and
  AT&T formatting, forged-schema rejection, CPU/runtime gates, and extras-OFF
  ownership. Pinned XED and LLVM 21 confirm all eight forms; 32 corpus rows and
  16 reviewed seeds retain the boundary.
- VEX `VBLENDVPD` forms 3535--3538 and `VBLENDVPS` forms 3539--3542 exactly
  own C4 map-3 opcodes `4B`/`4A` with pp=66, W=0, and L selecting XMM or YMM.
  Both widths require and publish AVX. The destination is write-only; NDS
  `vvvv`, ModRM, and selector vector sources are read-only. The trailing
  `SE_IMM8` high nibble selects the fourth vector register, its low nibble is
  ignored, `encoding.selector_offset` records the byte, and no immediate
  operand is published. Long-mode mask/value through the opcode is
  `ff 1f 83 ff / c4 03 01 4b|4a`; non-long C4 ownership uses
  `ff df 83 ff / c4 c3 01 4b|4a`, preserving LES collisions and B-extension
  aliases. Reserved pp/W and legacy-prefix controls are decided only after the
  complete ModRM/address/selector payload, so truncation retains precedence.
  The `cdisasm_x86_vblendv_tests` suite partitions 1,572,864 controls into
  196,608 allocated and 1,376,256 reserved and locks all modes, profiles,
  runtime gates, both syntaxes, forged-schema rejection, and extras-OFF
  ownership. Pinned XED and LLVM 21 confirm all eight forms; 38 corpus rows and
  23 reviewed seeds retain the boundary.
- VEX `VBROADCASTF128` form 3543 and `VBROADCASTI128` form 3554 exactly own
  C4 map-2 opcodes `1A`/`5A` with pp=66, W=0, L=1, encoded `vvvv=1111`, and
  memory-only ModRM. Both write a YMM register and read m128 without publishing
  an EVEX-style broadcast decorator. `F128` requires AVX; `I128` requires AVX2
  while retaining AVX as its encoding foundation. Long-mode mask/value through
  the opcode is `ff 1f ff ff / c4 02 7d 1a|5a`; non-long ownership is
  `ff df ff ff / c4 c2 7d 1a|5a`, with B' aliases retained and the other raw
  C4 collisions left to `LES`. The `cdisasm_x86_vbroadcast128_tests` suite
  exhausts 1,572,864 controls as 4,608 allocated and 1,568,256 reserved,
  including late address-payload truncation, runtime/profile gates, both
  syntaxes, formatter forgery rejection, and extras-OFF ownership. Pinned XED
  and LLVM 21 confirm both forms; 39 corpus rows and 18 reviewed seeds retain
  the boundary.
- VEX `VBROADCASTSD` forms 3569--3570 and `VBROADCASTSS` forms 3573--3574 and
  3579--3580 exactly own C4 map-2 opcodes `19`/`18` with pp=66, W=0, and
  encoded `vvvv=1111`. `VBROADCASTSD` requires L=1; `VBROADCASTSS` accepts
  L=0/1. Memory forms read m64/m32 and require AVX. Register forms read a full
  XMM source, additionally require and publish AVX2, and write XMM/YMM as
  selected by L. Adjacent EVEX encodings remain separately owned. All modes,
  non-long C4/LES and B-extension aliases, address and segment overrides,
  legacy-prefix rejection, and complete-payload
  truncation precedence remain distinct. The
  `cdisasm_x86_vbroadcast_scalar_tests` suite exhausts 1,572,864 controls as
  9,216 allocated and 1,563,648 reserved, including exact operand access,
  profile/runtime gates, both syntaxes, formatter forgery rejection, and
  extras-OFF ownership. Pinned XED and LLVM 21 confirm all six forms; 41
  corpus rows and 18 reviewed seeds retain the boundary.
- VEX `VEXTRACTF128` forms 4539--4540, `VEXTRACTI128` forms 4553--4554,
  `VINSERTF128` forms 5551--5552, and `VINSERTI128` forms 5565--5566 exactly
  own the 256-bit, map-3, pp=66, W=0, L=1 opcode `19`/`39` and `18`/`38`
  rows. Extract writes XMM or m128, reads YMM, and requires encoded
  `vvvv=1111`; insert writes YMM and reads its YMM `vvvv` source plus XMM or
  m128. All eight forms expose the full trailing imm8 as a read operand.
  Floating forms require AVX and integer forms add AVX2. The
  `cdisasm_x86_lane_insert_extract_tests` suite classifies 104,448 allocated
  and 3,041,280 reserved controls while locking all modes, non-long aliases,
  high registers and addresses, prefix/field ownership, complete-payload
  truncation precedence, EVEX separation, both syntaxes, formatter forgery,
  profile/runtime gates, and extras-OFF behavior. Twenty-three corpus rows and
  14 reviewed seeds retain the boundary against pinned XED and LLVM 21.
- VEX `VEXTRACTPS` forms 4567/4569 and `VINSERTPS` forms 5579--5580 exactly
  own their map-3 opcodes `17`/`21` at pp=66 and L=0; W is ignored.
  `VEXTRACTPS` requires encoded `vvvv=1111`, writes r32 or m32, and reads XMM.
  `VINSERTPS` writes XMM and reads its XMM NDS source plus XMM or m32. All four
  forms expose the trailing imm8 as a read operand and require AVX. The
  `cdisasm_x86_vextractps_vinsertps_tests` suite exhausts 1,572,864
  mode/prefix/ModRM controls as 104,448 allocated and 1,468,416 reserved,
  including both W values, every imm8, all modes, non-long aliases, complete-
  payload truncation, both syntaxes, formatter forgery rejection, profiles,
  and extras-OFF ownership. The interleaved EVEX forms 4568/4570/5581/5582
  remain separately owned. Twenty-four corpus rows and 15 reviewed seeds
  retain the pinned-XED and LLVM 21 boundary.
- VEX `VPERM2F128` forms 6770--6771 and `VPERM2I128` forms 6772--6773
  exactly own map-3 opcodes `06`/`46` with pp=66, W=0, and L=1. They write
  YMM, read the YMM NDS source plus YMM or m256, and expose the full imm8 as
  a read operand. Floating-point permutation requires AVX; integer
  permutation additionally requires AVX2. The
  `cdisasm_x86_vperm2_128_tests` suite exhausts 1,572,864 controls as 98,304
  allocated and 1,474,560 reserved, including all 16 `vvvv` sources, every
  imm8, all modes, non-long aliases, prefix/field ownership, complete-payload
  truncation, both syntaxes, formatter forgery rejection, profile gates, and
  extras-OFF ownership. No EVEX sibling shares either mnemonic. Twenty-three
  corpus rows and 15 reviewed seeds retain the pinned-XED and LLVM 21
  boundary.
- VEX `VPERMD` forms 6780--6781 and `VPERMPS` forms 6886--6887 exactly own
  map-2 opcodes `36`/`16` with pp=66, W=0, and L=1. Both are AVX2 NDS
  operations that write YMM, read the YMM `vvvv` source, and read YMM or
  m256 through ModRM. The focused suite exhausts 1,572,864 controls as
  98,304 allocated and 1,474,560 reserved, including all modes and NDS
  sources, non-long aliases, prefix/field ownership, complete-address
  truncation, both syntaxes, AVX2 profile/runtime gates, and extras-OFF
  ownership. Existing EVEX `VPERMD` forms 6782--6785 and EVEX `VPERMPS`
  forms 6884--6885/6888--6889 remain independently formatable, while VEX/
  EVEX and name/form forgeries are rejected. Twenty-five corpus rows and 15
  reviewed seeds retain the pinned-XED and LLVM 21 boundary.
- VEX `VPERMPD` forms 6878--6879 and `VPERMQ` forms 6890--6891 exactly own
  map-3 opcodes `01`/`00` with pp=66, W=1, L=1, and encoded `vvvv=1111`.
  Both require AVX2, write YMM, read YMM or m256 through ModRM, and expose
  the full imm8 selector as a read operand. The focused suite exhausts
  1,572,864 controls as 6,144 allocated and 1,566,720 reserved, including
  all modes, non-long B aliases, prefix/field ownership, complete-payload
  truncation, both syntaxes, profile/runtime gates, and extras-OFF ownership.
  The sixteen same-name EVEX forms 6874--6877/6880--6883 and 6892--6899
  retain independent exact formatter schemas. Twenty-six corpus rows and 15
  reviewed seeds preserve the pinned-XED and LLVM 21 boundary.
- Classic-VEX `VPERMILPD` forms 6834--6837/6846--6849 and `VPERMILPS`
  forms 6854--6857/6866--6869 exactly own their XMM/YMM register and memory
  spellings. Map-3 opcodes `05`/`04` carry an imm8 and require encoded
  `vvvv=1111`; map-2 opcodes `0D`/`0C` instead use `vvvv` as the NDS
  variable-control source. Both routes require pp=66 and W=0, L selects the
  vector width, and AVX admits every allocated form. The focused suite locks
  all modes, non-long aliases, prefix and complete-payload boundaries, both
  syntaxes, exact formatter validation, independent same-name EVEX ownership,
  and extras-OFF behavior across 208,896 allocated and 2,936,832 reserved
  controls. Thirty-six corpus rows and 26 reviewed seeds retain the pinned-XED
  and LLVM 21 boundary.
- Classic-VEX `VROUNDPD` forms 8539--8542, `VROUNDPS` forms 8543--8546,
  `VROUNDSD` forms 8547--8548, and `VROUNDSS` forms 8549--8550 exactly own
  map-3 pp=66 opcodes `09`/`08`/`0B`/`0A`. Packed forms are NOVSR with
  encoded `vvvv=1111` and L-selected XMM/YMM width; scalar forms are NDS and
  LIG. Every form is WIG, accepts every imm8, and requires AVX. The focused
  suite exhausts 417,792 allocated and 2,727,936 reserved controls and locks
  all modes, non-long C4/LES and extension aliases, register/memory addressing,
  complete-payload truncation, exact formatter validation, and independent
  legacy `ROUND*`/EVEX `VRNDSCALE*` boundaries. Thirty-six corpus rows and 26
  reviewed seeds retain the pinned-XED and LLVM 21 boundary.
- Classic-VEX `VSHUFPD` forms 8664--8665/8670--8671 and `VSHUFPS` forms
  8674--8675/8680--8681 exactly own map-1 opcode `C6`. pp=66 selects PD and
  pp=none selects PS; pp=F3/F2 are reserved. The family is WIG and NDS, L
  selects XMM/YMM width, every imm8 is accepted, and all forms require AVX.
  The destination is write-only and both vector sources plus imm8 are read.
  The focused suite exhausts the recognized VEX3 envelope as 393,216 allocated
  and 393,216 reserved controls and additionally locks VEX2, all modes,
  non-long aliases, prefixes and addressing, complete-payload truncation, both
  syntaxes, profile/runtime gates, and extras-OFF ownership. Same-name EVEX
  forms 8666--8669/8672--8673 and 8676--8679/8682--8683 retain independent
  exact formatter schemas. Thirty-six corpus rows and 24 reviewed seeds retain
  the pinned-XED and LLVM 21 boundary.
- Classic-VEX `VTESTPD` forms 8795--8798 and `VTESTPS` forms 8799--8802
  exactly own map-2 opcodes `0F` and `0E`. Both require pp=66, W=0, encoded
  `vvvv=1111`, and AVX; L selects XMM or YMM, and register and memory second
  sources remain distinct. Both explicit operands are read and the result
  reports architectural status-flag writes. The focused suite exhausts the
  recognized VEX3 envelope as 12,288 allocated and 1,560,576 reserved
  controls and locks every mode, non-long aliases, prefixes and addressing,
  payload-first truncation, both syntaxes, profile/runtime gates, map-3
  siblings, formatter-schema rejection, and extras-OFF ownership. Thirty-one
  corpus rows and 21 reviewed seeds retain the pinned-XED and LLVM 21 boundary.
- Classic-VEX `VPTEST` forms 8319--8322 exactly own VEX3 map-2
  mandatory-66 opcode `17 /r`; map 2 has no two-byte VEX encoding. Encoded
  `vvvv` must be 1111b, W is ignored, and L selects XMM/m128 or YMM/m256.
  Both widths require AVX, both explicit operands are read, and successful
  results publish architectural status-flag writes. The focused suite
  exhausts 786,432 controls as 12,288 allocated and 774,144 reserved while
  locking every mode, non-long aliases, high registers and addressing,
  payload-first truncation, both syntaxes, formatter-schema rejection,
  profile/runtime gates, and extras-OFF ownership. Legacy `PTEST`,
  `VTESTPD`/`VTESTPS`, map-3 `VEXTRACTPS`, and EVEX `VPTESTM*`/`VPTESTNM*`
  remain independent. Twenty-five corpus rows and 15 reviewed seeds retain
  the pinned-XED and LLVM 21 boundary.
- Classic-VEX `VPMOVMSKB` forms 7334--7335 exactly own map-1 mandatory-66
  opcode `D7 /r`. The ModRM must be register-only, encoded `vvvv` must be
  1111b, W is ignored, and L selects XMM or YMM. The XMM form requires AVX;
  the YMM form requires AVX2. Both write a GPR32 destination and read their
  vector source without changing flags. The focused suite covers 3,584
  allocated encodings across all modes, exactly 1,792 per form, and partitions
  the long-mode C5 parent into 256 allocated plus 65,280 reserved cells and
  the C4 parent into 2,048 allocated plus 522,240 reserved cells. It also
  locks non-long aliases, high registers, WIG, profile/runtime gates, both
  syntaxes, formatter-schema rejection, extras-OFF ownership, and payload-first
  truncation for incomplete prefixed addresses. Legacy `PMOVMSKB` and EVEX
  `VPMOV{B,W,D,Q}2M`/`VPMOVM2{B,W,D,Q}` remain independent. Twenty-five
  corpus rows and 14 reviewed seeds retain the pinned-XED and LLVM 21 boundary.
- Classic-VEX `VPSIGNB`/`VPSIGND`/`VPSIGNW` forms 7921--7932 exactly own
  C4 map-2 mandatory-66 opcodes `08`/`0A`/`09`. W is ignored, `vvvv` names
  the first source, and L selects XMM or YMM; XMM requires AVX and YMM
  requires AVX2. Each result writes its destination and reads both equal-width
  vector sources without flag effects. The focused suite exhausts 2,359,296
  controls as 589,824 allocated and 1,769,472 reserved, hitting each memory
  form 73,728 times and each register form 24,576 times. It locks all modes,
  non-long aliases, high registers and addressing, payload-first truncation,
  WIG, profile/runtime gates, both syntaxes, formatter-schema rejection, and
  extras-OFF ownership. Legacy `PSIGN*` and unowned EVEX/VEX2 neighbors remain
  independent. Thirty-two corpus rows and 20 reviewed seeds retain the
  pinned-XED and LLVM 21 boundary.
- Classic-VEX `VPSHUFD` forms 7891--7892/7895--7896, `VPSHUFHW` forms
  7901--7902/7905--7906, and `VPSHUFLW` forms 7911--7912/7915--7916 exactly
  own map-1 opcode `70 /r ib`. Mandatory 66/F3/F2 selects D/HW/LW, encoded
  `vvvv` must be 1111b, W is ignored, and L selects XMM/m128 or YMM/m256.
  XMM forms require AVX and YMM forms require AVX2; the destination is written
  while the source and imm8 are read. The focused suite partitions 884,736
  all-mode C4/C5 controls into 43,008 allocated and 841,728 reserved cells,
  including 5,376 hits per memory form and 1,792 per register form. It locks
  every imm8, all modes, non-long aliases, high registers and addressing,
  payload-first truncation, WIG, profile/runtime gates, both syntaxes,
  formatter-schema rejection, and extras-OFF ownership. Legacy `PSHUF*` and
  generated same-name EVEX siblings remain independent. Their P0.B4 and
  U0/X4 memory spellings require APX and carry the `APX_F` group as formatter
  provenance for EGPR addresses. Forty-two corpus rows and 26 reviewed seeds
  retain the pinned-XED and LLVM 21 boundary.
- Classic-VEX `VUCOMISD` forms 8803--8804 and `VUCOMISS` forms 8809--8810
  exactly own map-1 opcode `2E`. pp=66 selects SD and pp=none selects SS;
  pp=F3/F2 and encoded `vvvv` values other than 1111b are reserved. W and L
  are ignored, all
  allocated forms require AVX, both explicit operands are read, and the result
  reports architectural status-flag writes. The focused suite exhausts the
  recognized VEX3 envelope as 24,576 allocated and 761,856 reserved controls
  and locks every mode, non-long aliases, prefixes and addressing,
  payload-first truncation, both syntaxes, profile/runtime gates, exact
  formatter rejection, and extras-OFF ownership. Legacy `UCOMI*`, same-name
  EVEX forms 8805--8806/8811--8812, and `VUCOMISH` forms 8807--8808 remain
  independent. Thirty-two corpus rows and 20 reviewed seeds retain the
  pinned-XED and LLVM 21 boundary.
- Classic-VEX `VCOMISD` forms 3629--3630 and `VCOMISS` forms 3633--3634
  exactly own map-1 opcode `2F`. pp=66 selects SD and pp=none selects SS;
  pp=F3/F2 are reserved, encoded `vvvv` must be 1111b (`VEX.NOVSR`), and W
  and L are ignored. The first XMM operand and scalar 64-bit or 32-bit second
  source are read, the result reports architectural status-flag writes, and
  every allocated form requires AVX. The focused suite partitions the
  recognized VEX3 envelope into 24,576 allocated and 761,856 reserved
  controls and locks every mode, non-long aliases, prefixes and addressing,
  payload-first truncation, both syntaxes, profile/runtime gates, exact
  formatter rejection, and extras-OFF ownership. Legacy `COMI*`, same-name
  EVEX `VCOMISD`/`VCOMISS`, and `VCOMISH` remain independent. Thirty-two
  corpus rows and 20 reviewed seeds retain the pinned-XED and LLVM 21
  boundary.
- Classic-VEX `VDPPD` forms 4507--4508 and `VDPPS` forms 4515--4518 exactly
  own map-3 mandatory-66 opcodes `41 /r ib` and `40 /r ib`. Both are WIG NDS
  encodings with an allocated full imm8. `VDPPD` allocates only the 128-bit
  register/m128 forms and reserves L=1; `VDPPS` uses L to select 128- or
  256-bit register/memory forms. Every allocated form writes its destination,
  reads both vector sources and the immediate, and requires AVX. The focused
  suite partitions the C4 envelope into 294,912 allocated and 1,277,952
  reserved controls and checks 196,608 C5 collision/exclusion controls. It
  locks every mode, WIG, non-long B-prime/`vvvv` aliases, long-mode high
  registers and addressing, prefixes, payload-first truncation, both
  syntaxes, formatter-schema rejection, profile/runtime gates, legacy `DPP*`
  siblings, and extras-OFF ownership. Thirty-nine corpus rows and 21 reviewed
  seeds retain the pinned-XED and LLVM 21 boundary.
- Classic-VEX `VCMPPD` forms 3595--3598, `VCMPPS` forms 3611--3614,
  `VCMPSD` forms 3617--3618, and `VCMPSS` forms 3623--3624 exactly own
  map-1 opcode `C2 /r ib`. Mandatory none/66/F3/F2 selects PS/PD/SS/SD,
  encoded `vvvv` is the NDS source, and W is ignored. Packed forms use L to
  select XMM or YMM operands; scalar forms are LIG and retain their 128-bit
  destination/source-1 with a 32- or 64-bit register/memory source-2. Every
  imm8 is allocated: its low five bits select the comparison predicate and
  its high three bits are aliases. The destination is written, both sources
  and the immediate are read, and every form requires AVX and reports MXCSR
  use. The focused suite exhausts all 884,736 C4/C5 controls, including every
  imm8, WIG, packed-L/scalar-LIG behavior, all modes, non-long B-prime and
  `vvvv` aliases, long-mode high registers, addressing, truncation,
  profile/runtime gates, both syntaxes, formatter-schema rejection, and
  extras-OFF ownership. Legacy `CMP*` and generated same-name EVEX siblings
  remain independent. Forty-two corpus rows and 20 reviewed seeds retain the
  pinned-XED and LLVM 21 boundary.
- Classic-VEX `VUNPCKHPD` forms 8825--8826/8831--8832, `VUNPCKHPS` forms
  8835--8836/8841--8842, `VUNPCKLPD` forms 8845--8846/8851--8852, and
  `VUNPCKLPS` forms 8855--8856/8861--8862 exactly own map-1 opcodes `15`
  (high) and `14` (low). pp=66 selects PD, pp=none selects PS, pp=F3/F2 are
  reserved, W is ignored, `vvvv` is the NDS source, and L selects XMM/YMM.
  Every allocated form writes its destination, reads both vector sources, and
  requires AVX. The focused suite exhausts the VEX3 envelope as 786,432
  allocated and 786,432 reserved controls and the VEX2 envelope as 98,304
  allocated and 98,304 reserved controls, while locking every mode, non-long
  aliases, addressing, payload-first truncation, both syntaxes,
  formatter-schema rejection, profile/runtime gates, and extras-OFF
  ownership. Legacy `UNPCK*` and same-name EVEX forms remain independently
  owned. Fifty-six corpus rows and 24 reviewed seeds retain the pinned-XED and
  LLVM 21 boundary.
- Classic-VEX integer `VPUNPCKHBW` forms 8323--8324/8327--8328,
  `VPUNPCKHDQ` forms 8333--8334/8337--8338, `VPUNPCKHQDQ` forms
  8343--8344/8347--8348, `VPUNPCKHWD` forms 8353--8354/8357--8358,
  `VPUNPCKLBW` forms 8363--8364/8367--8368, `VPUNPCKLDQ` forms
  8373--8374/8377--8378, `VPUNPCKLQDQ` forms 8383--8384/8387--8388, and
  `VPUNPCKLWD` forms 8393--8394/8397--8398 exactly own map-1 mandatory-66
  opcodes `68`/`6A`/`6D`/`69` and `60`/`62`/`6C`/`61`. All are WIG NDS
  encodings; L selects XMM or YMM, XMM requires AVX, and YMM requires AVX2.
  Every allocated form writes its destination and reads both equal-width
  vector sources. The focused suite partitions the C4 parent's 6,291,456
  controls into 1,572,864 allocated and 4,718,592 reserved and the C5
  parent's 786,432 controls into 196,608 allocated and 589,824 reserved. It
  locks all modes, non-long aliases, addressing, payload-first truncation,
  exact register mapping, both syntaxes, formatter-schema rejection,
  profile/runtime gates, and extras-OFF ownership while preserving legacy
  `PUNPCK*` and generated EVEX siblings. Sixty-nine corpus rows and 40
  reviewed seeds retain the pinned-XED and LLVM 21 boundary.
- Classic-VEX horizontal integer `VPHADDD` forms 7012--7015, `VPHADDSW`
  forms 7016--7019, `VPHADDW` forms 7036--7039, `VPHSUBD` forms 7046--7049,
  `VPHSUBSW` forms 7050--7053, and `VPHSUBW` forms 7056--7059 exactly own C4
  map-2 mandatory-66 opcodes `02`/`03`/`01` and `06`/`07`/`05`. These are WIG
  NDS encodings: L=0 selects XMM/m128 and requires AVX; L=1 selects YMM/m256
  and requires AVX2. Each form writes its destination and reads both sources.
  The focused suite exhausts 4,718,592 all-mode controls as 1,179,648
  allocated and 3,538,944 reserved, with 73,728 hits per memory form and
  24,576 per register form. It locks non-long aliases, high registers and
  addressing, payload-first truncation, WIG, profile/runtime gates, both
  syntaxes, formatter-schema rejection, and extras-OFF ownership while
  preserving legacy `PHADD*`/`PHSUB*` and AMD-XOP horizontal siblings.
  Forty-nine corpus rows and 37 reviewed seeds retain the pinned-XED and
  LLVM 21 boundary.
- Classic-VEX `VPHMINPOSUW` forms 7040--7041 exactly own C4 map-2
  mandatory-66 opcode `41 /r`. This is a fixed-width NOVSR encoding:
  encoded `vvvv` must be 1111b, L must be zero, W is ignored, and all three
  modes require AVX. The destination is a written XMM register and the source
  is a read XMM register or m128. The focused suite exhausts the 786,432
  all-mode controls as 6,144 allocated and 780,288 reserved, including 4,608
  memory-form and 1,536 register-form hits. It locks non-long aliases, high
  registers and addressing, payload-first truncation, WIG, profile/runtime
  gates, both syntaxes, formatter-schema rejection, and extras-OFF ownership
  while preserving legacy `PHMINPOSUW`, same-opcode `KANDB`/`KANDW`, and the
  adjacent EVEX `VPMOVSSDB` route. Thirty-five corpus rows and 17 reviewed
  seeds retain the pinned-XED and LLVM 21 boundary.
- Classic-VEX `VPINSRB`/`VPINSRD`/`VPINSRQ`/`VPINSRW` forms
  7060--7061/7064--7065/7068--7069/7072--7073 exactly own fixed-width XMM
  NDS inserts with an imm8 selector. B/D/W register sources are GPR32, Q is
  GPR64, and their memory alternatives are m8/m32/m16/m64 respectively.
  B and W are WIG; map-3 opcode `22` selects D with W=0 and Q with W=1 in
  long mode, while non-long W=1 aliases D. VPINSRW's map-1 opcode `C4` admits
  both C4 and C5 spellings. Every allocated form writes its XMM destination,
  reads the NDS XMM source and scalar source, reads imm8, and requires AVX.
  The focused selector/ModRM sweep partitions 2,359,296 C4 controls into
  294,912 allocated and 2,064,384 reserved, and 98,304 C5 controls into
  12,288 allocated and 86,016 reserved. It locks every form, mode and
  non-long alias, high registers and addressing, payload-first truncation,
  profile/runtime gates, both syntaxes, formatter-schema rejection, and
  extras-OFF ownership while preserving legacy `PINSR*` and all same-name
  EVEX siblings. Fifty-two corpus rows and 24 reviewed seeds retain the
  pinned-XED and LLVM 21 boundary.
- Classic-VEX `VPEXTRB`/`VPEXTRD`/`VPEXTRQ`/`VPEXTRW` forms
  6966/6968, 6970/6972, 6974/6976, 6978/6983, and register-only map-1 form
  6979 exactly own fixed-width XMM extracts with an imm8 selector. B/D/W
  register destinations are GPR32, Q is GPR64, and the memory alternatives
  are m8/m32/m16/m64; map-1 `VPEXTRW` reverses the usual ModRM ownership and
  has no memory form. Encoded `vvvv` must be 1111b, L must be zero, B/W are
  WIG, and map-3 opcode `16` selects D with W=0 and Q with W=1 in long mode,
  while non-long W=1 aliases D. Every allocated form writes its scalar
  destination, reads the XMM source and imm8, and requires AVX. The exhaustive
  selector/ModRM sweep partitions 3,145,728 C4 controls into 19,968 allocated
  and 3,125,760 reserved, and 98,304 C5 controls into 256 allocated and
  98,048 reserved. It locks all modes, C4/C5 spellings, non-long aliases,
  register and addressing boundaries, payload-first truncation, both syntaxes,
  formatter-schema rejection, and extras-OFF ownership while preserving
  legacy `PEXTR*` and all same-name EVEX siblings. Sixty-six corpus rows and
  30 reviewed seeds retain the pinned-XED and LLVM 21 boundary.
- Classic-VEX `VPMOVSXBW`/`VPMOVSXBD`/`VPMOVSXBQ`/`VPMOVSXWD`/
  `VPMOVSXWQ`/`VPMOVSXDQ` forms 7419--7420/7425--7426,
  7399--7400/7405--7406, 7409--7410/7415--7416,
  7439--7440/7445--7446, 7449--7450/7455--7456, and
  7429--7430/7435--7436 exactly own C4 map-2 mandatory-66 opcodes `20`--`25`.
  They are WIG NOVSR operations: encoded `vvvv` must be 1111b, while L=0
  selects an AVX XMM destination and L=1 an AVX2 YMM destination. Sources are
  XMM registers or exact low-width memory operands ranging from m16 to m128
  according to the widening ratio; every destination is written and every
  source is read. The focused all-mode control sweep partitions 4,718,592
  encodings into 73,728 allocated and 4,644,864 reserved, with 4,608
  memory-form and 1,536 register-form hits per family/width pair. It locks
  non-long aliases, high registers
  and addressing, payload-first truncation, profile/runtime gates, both
  syntaxes, formatter-schema rejection, and extras-OFF ownership while
  preserving legacy `PMOVSX*` and generated EVEX siblings. Sixty-two corpus
  rows and 36 reviewed seeds retain the pinned-XED and LLVM 21 boundary.
- Classic-VEX `VPMOVZXBW`/`VPMOVZXBD`/`VPMOVZXBQ`/`VPMOVZXWD`/
  `VPMOVZXWQ`/`VPMOVZXDQ` forms 7524--7525/7530--7531,
  7504--7505/7510--7511, 7514--7515/7520--7521,
  7544--7545/7550--7551, 7554--7555/7560--7561, and
  7534--7535/7540--7541 exactly own C4 map-2 mandatory-66 opcodes `30`--`35`.
  Like their signed counterparts they are WIG NOVSR operations, with AVX XMM
  and AVX2 YMM destinations and exact m16--m128 or XMM low-width sources.
  Destinations are writes and sources are reads. The focused all-mode control
  sweep partitions 4,718,592 encodings into 73,728 allocated and 4,644,864
  reserved, with 4,608 memory-form and 1,536 register-form hits per
  family/width pair. It locks non-long aliases, high registers and addresses,
  payload-first truncation, profile/runtime gates, both syntaxes, strict
  formatter schemas, and extras-OFF ownership while preserving legacy
  `PMOVZX*`, C5 non-siblings, and generated EVEX siblings. Sixty-two corpus
  rows and 36 reviewed seeds retain the pinned-XED and LLVM 21 boundary.
- AMD XOP `VPCMOV` forms 6410--6415 are exact for XMM/YMM register and memory
  sources. W swaps the memory and selector-source operand positions; the two
  all-register W spellings collapse to one form per width. The trailing
  `SE_IMM8` byte is selector metadata, not an immediate operand: its high
  nibble selects the fourth vector register, its low nibble is ignored, and
  `encoding.selector_offset` records its byte position while
  `encoding.immediate_count` remains zero. The result carries the AVX and XOP
  groups. Outside long mode, XOP extension bits and the high bits of `vvvv`
  and the selector alias as XED and LLVM 21 specify. The focused suite
  classifies 393,216 allocated and 1,179,648 reserved controls and locks
  address formation, prefix/pp ownership, complete-payload truncation
  precedence, formatting-schema rejection, CPU/runtime gates, and
  extras-OFF behavior. Twenty-five corpus rows and 16 reviewed seeds retain
  those boundaries.
- AMD XOP `VPPERM` forms 7686--7688 are exact for XMM operands. W selects
  whether the ModRM memory source precedes or follows the selector source;
  both all-register W encodings collapse to form 7688. The trailing `SE_IMM8`
  byte is selector metadata rather than an immediate operand: its high nibble
  names the fourth XMM source, its low nibble is ignored, and only
  `encoding.selector_offset` is populated. L and nonzero pp are reserved;
  legacy operand/repeat/LOCK/REX prefixes are invalid, while address-size and
  segment overrides remain valid. The decoder consumes the complete
  ModRM/SIB/displacement/selector payload before reporting those invalid
  controls, so incomplete owned inputs remain truncated. All three modes are
  covered, with non-long R/X/B, `vvvv`, and selector extensions aliased into
  the eight-register namespace. This follows LLVM's 32-bit SIB.X behavior;
  pinned XED's isolated exposure of `r12d` for that spelling is treated as an
  anomalous non-long result. The exact result carries AVX+XOP groups and
  requires the XOP runtime selector and a compatible CPU profile. The focused
  suite classifies 196,608 allocated and 1,376,256 reserved controls; 27
  corpus rows and 16 reviewed seeds retain operands, aliases, prefix and
  truncation precedence, formatting-schema rejection, gates, and extras-OFF
  ownership against pinned XED and LLVM 21.
- SMAP `CLAC` form 707 and `STAC` form 3158 exactly own the fixed no-prefix,
  OSZ=0 `0F 01 CA` and `0F 01 CB` allocations in 16-, 32-, and 64-bit modes.
  Both are CPL0, have no explicit operands, and publish an aggregate status-
  flag write for AC. Address-size and segment overrides are accepted; `66`
  and LOCK are invalid. Every ordinary REX payload is ignored, and every
  REX2-map-1 payload is likewise ignored while independently requiring APX-F.
  The exact SMAP runtime bit is required. Ordinary profile admission is
  unrestricted X86 plus Broadwell, Skylake, Goldmont, AMD Zen, Skylake-SP,
  Ice Lake, Tiger Lake, Alder Lake, AMD Zen 4, Sapphire Rapids, AVX10, APX,
  Celeron G3900/N3350/N4020/G5900, Pentium Silver N6000, Granite Rapids,
  Arrow Lake, and Diamond Rapids; REX2 narrows that set to X86, APX, and
  Diamond Rapids. Mandatory F2/F3 on `0F 01 CA` instead selects the existing
  generated FRED `ERETS`/`ERETU` fallback in 64-bit X86/Diamond Rapids and is
  never relabeled as SMAP; exact FRED suppressed-state semantics remain
  deferred. F2/F3 on `0F 01 CB` is invalid. The focused suite sweeps all 768
  mode/ModRM cells, 32 form/REX controls, and 384 map-0/map-1 REX2 controls,
  together with runtime, profile, collision, truncation, and formatter cases.
- FRED `ERETS`/`ERETU` and LKGS have focused exact-byte ABI coverage in
  `tests/test_x86_fred_lkgs.c`. FRED remains a zero-explicit-operand
  generated descriptor because its return-frame, privilege-transition, and
  flags-pop state cannot be represented as ordinary operands. LKGS exposes
  its exact 16-bit register and memory forms (1589/1590), with generated
  long-mode CPU/profile and `CDISASM_X86_DECODE_BIT_LKGS` gates; semantic
  legality is marked `structural_only` in the catalog ledger.
- AVX2 VEX VSIB gathers are routed through the generated descriptor table after
  a narrow structural retry gate. All 16 `VPGATHER*` and `VGATHER*` XMM/YMM
  forms preserve the vector index register, mask/source operand, tuple width,
  and exact Intel/AT&T formatting; arbitrary invalid VEX opcodes are not
  retried.
- Table-driven legacy SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4a, and SSE4.2 forms
  across the `0F`, `0F 38`, and `0F 3A` maps. Implemented forms cover scalar
  and packed floating-point arithmetic, packed integer operations, moves,
  conversions, comparisons, shuffles, blends, rounding, dot products, string
  compares, CRC32, MXCSR access, prefetches, and fences. Mandatory `66`, `F2`,
  and `F3` bytes select an opcode structurally and are not exposed as false
  `rep`/`repne` actions. Conflicting mandatory-selector classes, such as both
  `66` and `F3`, are rejected instead of choosing one by prefix order.

The optional modern bullets above are bounded slices. The VEX FMA3, EVEX FMA3,
FMA4, cataloged XOP, classic 51-name VEX K-mask, eight-name packed-integer
EVEX compare-to-mask, 16-name/144-form VEX/EVEX packed-integer MIN/MAX, the
complete 36-form GFNI family, and ten-name
packed-integer EVEX multiply/multiply-add and eight-name modular packed-integer
EVEX ADD/SUB matrices, plus the eight-name D/Q logical, two-name byte/word
average, eight-name VEX/EVEX saturating packed-integer ADD/SUB, the six-name
VEX/EVEX dword/qword variable-shift tranche, and the three-name EVEX word
variable-shift class, the four-name EVEX dword/qword variable packed-rotate
class, and the four-name EVEX dword/qword immediate packed-rotate class,
described above are complete within their stated scope. The generated fallback
additionally carries all 10,994 descriptors and 9,001 IFORMs from the pinned
XED export, including the cataloged MMX/SSE, VEX/EVEX, AVX-512, AVX10, APX,
AMX, crypto, and system families. It runs only after an explicit unsupported
hand-decoder result and cannot override known-invalid input. This closes the
pinned allocation-recognition gap, not every semantic-validity gap: some late
register relations, legacy-prefix actions, suppressed execution state, and
state-sized operands remain conservatively documented limitations. CPU and
runtime-family selection remain independent gates. Generated FP16 width forms
also publish the same stable `AVX`/`AVX512FP16` umbrella groups as their
hand-decoder counterparts. Run `python tools/coverage/check_x86_coverage.py`
to verify that the checked-in fallback metadata, coverage inventory, and
decoder integration remain synchronized.

## Build

From this directory on Windows with Visual Studio 2022 installed, the exact
dual-architecture shared build for the modern tranche is:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DUSE_ARCH_X86=ON -DUSE_ARCH_ARM=ON `
  -DUSE_DISASM_FORMAT=ON -DUSE_EXTRA_OPCODES=ON `
  -DBUILD_SHARED_LIBS=ON -DBUILD_TESTING=ON `
  -DCDISASM_BUILD_PACKAGE_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Top-level builds with `BUILD_TESTING=ON` also default
`CDISASM_VERIFY_GENERATED=ON` and therefore require Python 3.10 or newer. A
lightweight build dependency and two CTests verify that the ARM recipe-opcode
map still matches its checked-in generated enum. To verify every generated ARM
assembly artifact against the pinned upstream data as well, configure
`CDISASM_ARM_AARCHMRS_ROOT` with that checkout; this adds the
`cdisasm_check_arm_catalog` target and a full freshness CTest. Embedded builds
default this developer check to `OFF` and do not acquire a Python dependency.

`USE_ARCH_X86`, `USE_ARCH_ARM`, `USE_DISASM_FORMAT`, and `USE_EXTRA_OPCODES`
are independent CMake options and all default to `ON`. For example, an ARM-only build uses
`-DUSE_ARCH_X86=OFF -DUSE_ARCH_ARM=ON`; an x86-only build uses
`-DUSE_ARCH_X86=ON -DUSE_ARCH_ARM=OFF`. Add `-DUSE_DISASM_FORMAT=OFF` to omit
all formatter code and exports. Add `-DUSE_EXTRA_OPCODES=OFF` for a smaller
decoder. For x86 that variant accepts only runtime mask zero and reports all
complete CPU-eligible non-base forms as unsupported; every nonzero x86 mask is
an invalid argument. ARM retains its existing endian option, but its optional
modern semantic tranche remains unavailable.
To build and test that ABI-identical OFF variant without reusing the ON build
tree:

```powershell
cmake -S . -B build-no-extra -G "Visual Studio 17 2022" -A x64 `
  -DUSE_ARCH_X86=ON -DUSE_ARCH_ARM=ON `
  -DUSE_DISASM_FORMAT=ON -DUSE_EXTRA_OPCODES=OFF `
  -DBUILD_SHARED_LIBS=ON -DBUILD_TESTING=ON `
  -DCDISASM_BUILD_PACKAGE_TESTS=OFF
cmake --build build-no-extra --config Release
ctest --test-dir build-no-extra -C Release --output-on-failure
```

The recorded 2026-09-09 version-12 validation used strict Clang 21.1.8 builds
with `-Wall -Wextra -Wpedantic -Werror` and both architectures. The direct
matrix passes 257/257 non-package CTests with extra opcodes and formatting enabled, 252/252
with extra opcodes disabled, and 255/255 with formatting disabled and extra
opcodes enabled. A separate fresh installed-package run passes both end-to-end
tests and all 16 shared plus all 16 static feature cells. At that snapshot,
the pinned ARM freshness check verified 3,191 assembly rules, 5,164 direct
canonical forms, 481 direct aliases, and 1,535 explicit opaque records. Four ASan+UBSan
libFuzzer cells (x86/ARM by extras ON/OFF) each completed 6,000 runs with no
sanitizer, invariant, timeout, leak, or crash artifact. The current reviewed
source inventories contained 2,395 x86 and 1,679 ARM seeds. Deterministic seed
replay reported 2,396 x86 and 1,680 ARM libFuzzer runs because each replay also
includes libFuzzer's empty unit.

The current ARM assembly-recipe audit verifies 3,191 rules, 6,569 direct
canonical forms, 595 direct aliases, and 16 explicitly classified opaque
records, with zero actionable unresolved recipes. PSTATE-immediate `MSR` now
has a byte-derived numeric field operand, formatter support, and conservative
CPU-feature gating. Eight VORR-derived `VRSHR`/`VSHR` source aliases have no
encoded datatype or shift and therefore cannot be reconstructed from bytes.
Eight VORN-immediate source aliases are assembly-only pseudo-instructions;
their bytes disassemble as the canonical VORR/VBIC form or a supported preferred
alias. These 16 source spellings intentionally remain opaque. The 8,730-case
ARM corpus, ARM formatter tests, and focused recipe regressions pass for these
tables; the earlier sanitizer/fuzzer matrix has not been rerun for this update.

The live x86 coverage audit now resolves all 9,001 pinned IFORMs through the
checked-in byte corpus: effective `catalog_only`, `corpus_partial`,
`profile_rejected_probe`, and `source_assignment_only` counts are all zero.
The corpus contains 12,529 x86 cases and every case passes in both
`USE_EXTRA_OPCODES=ON` and `USE_EXTRA_OPCODES=OFF` builds. The generated
manifest still preserves the historical XED allocation snapshot for
provenance, while the audit's exact mode/byte overlay is the authoritative
current reachability result. The ARM inventory remains independently reported
by its generated manifest and is not folded into the x86 result.
Generator/manifest
v4 maps A32/A64 big-endian words and T32
big-endian halfwords before classification and invokes `xed-dec` in its
default 32-bit mode instead of passing the unsupported `-32` option. The
endian correction removed eight historical false-positive ARM form credits.
SVE2/SME `XAR` form 2325 moved from `verified_missing_encoding` to
`corpus_reachable`; neither architecture now has a `verified_missing_encoding`
row. Advanced SIMD `ADDV` form 6077 previously moved to exact
corpus-reachable coverage, as did classic-VEX
`VDPPD` forms 4507--4508 and `VDPPS` forms 4515--4518, including the allocated
32-bit B-prime alias `c4 c3 71 41 c2 01`. The latest exact tranche completes
all 144 pinned VEX/EVEX packed-integer MIN/MAX forms and all 36 pinned GFNI
forms on x86. It also completes all 30 fixed-width A32/T32/A64 SHA1/SHA256
leaves and the 17-form fixed A64 SHA3/SHA512/SM3/SM4 block 6287--6303. These
are joined by all 24 floating `VCOMPRESSPD/PS` and `VEXPANDPD/PS` forms
3637--3648/4527--4538, all six `VDBPSADBW` forms 4453--4458, and all twelve
`VPTERNLOGD/Q` forms 8259--8270. These x86 families preserve exact
XMM/YMM/ZMM identity, width-specific AVX-512 or AVX10.1 admission, mask,
broadcast, memory, compressed-displacement, APX-address, malformed, and
truncation behavior. `VPTERNLOG` keeps its destination read/write even without
a merge mask because the old destination is a truth-table input. They add
24/30/37 corpus rows and 24/13/20 reviewed seeds respectively.

The latest ARM tranche adds all twenty FEAT_CRC32 leaves across A32 forms
98--103, T32 forms 2169--2174, and A64 forms 5582--5587/5602--5603; SVE/SME
`AND`/`ORR`/`EOR`/`BIC` forms 2321--2324; SVE2/SME `XAR` form 2325; and
fourteen architectural synchronization/debug-hint leaves across A32 forms
247--251, T32 forms 1831--1835, and A64 forms 4471/4473/4475/4476. The block
preserves the `MOV` alias for equal `ORR` sources, tied destructive `XAR`
spelling and width-dependent immediate, A32 conditions, PC and A64 sf/size
restrictions, `DBG #imm4`, fixed `TSB CSYNC`, endian transport, and conservative
feature/profile gates.

The following exact tranche adds all 48 EVEX `VPTESTMB/MD/MQ/MW` and
`VPTESTNMB/NMD/NMQ/NMW` forms 8271--8318. It preserves mask-register
destinations, optional merge writemasks, XMM/YMM/ZMM width identity,
byte/word FullMem tuples, dword/qword broadcasts, compressed displacements,
AVX-512F/BW/VL versus AVX10.1 admission, APX addressing, and reserved EVEX
controls. The same tranche completes scalar A32/T32 `MUL` forms 50/1122/2177
and long `UMULL`/`UMLAL`/`SMULL`/`SMLAL` forms 56/58/60/62 and
2206--2208/2217, including the A32 flag-setting leaf, T32 IT behavior,
conditions, endian transport, PC rejection, and destination-pair overlap.

The next exact ARM tranche completes all 48 A32 extra-load/store forms 1--48:
`STRH`, `LDRH`, `LDRSB`, `LDRSH`, `LDRD`, `STRD`, and their unprivileged
`*T` variants across register, split-immediate, literal, offset, pre-index,
and post-index leaves. It preserves signed register offsets, 64-bit pair
transfers, PC-relative addresses, writeback/unprivileged flags, conditional
execution, and rejects invalid PC, odd-pair, and writeback-overlap encodings.

The following tranche completes 34 wide T32 transfer leaves: `LDRD`/`STRD`
forms 1750--1756 and all wide `STRH`/`LDRH`/`LDRSB`/`LDRSH` plus `*T` forms
2049--2108. Native decoding preserves register shifts, positive and negative
immediates, literals, pre/post writeback, unprivileged access, pair ordering,
Thumb PC alignment, and the neighboring `STREX`/`LDREX` and prefetch spaces.

The adjacent tranche completes the 26 wide T32 byte/word `STRB`/`LDRB` and
`STR`/`LDR` leaves 2045--2090, including their `*T` identities. It preserves
the same register-shift, signed/unsigned immediate, literal, writeback, byte,
and unprivileged metadata without taking the neighboring prefetch encodings.

The next tranche completes all 24 T32 table-branch and exclusive/acquire-release
leaves 1726--1749: `TBB`/`TBH`, `STREX*`/`LDREX*`, `STL*`/`LDA*`, and
`STLEX*`/`LDAEX*`. Native results retain table index scaling, exclusive status
registers, pair ordering, atomic memory access, immediate scaling, and ARMv7
versus ARMv8 capability admission.

The following tranche completes all 11 wide T32 `PLD`/`PLDW`/`PLI` prefetch
leaves 2047--2107. Native results retain register offsets and shifts, signed
and unsigned immediates, aligned PC-relative literal addresses, zero-sized
read-only memory hints, ARMv7 admission, reserved-register rejection, and
extras-disabled ownership.

The next tranche completes all eight wide T32 block-transfer leaves 1718--1725:
`SRSDB`/`SRS`, `RFEDB`/`RFE`, `STM`/`LDM`, and `STMDB`/`LDMDB`. Results retain
register lists and access, base writeback, increment/decrement and pre/post
indexing, exception-return and privileged groups, valid exception modes,
reserved-register-list boundaries, and ARMv7 admission.

The following tranche completes all 18 wide T32 shifted-register logical
leaves 1757--1774 for `AND`/`ANDS`/`TST`, `BIC`/`BICS`, `ORR`/`ORRS`, and
`MOV`/`MOVS`. Results retain exact LSL/LSR/ASR/ROR amounts, distinct RRX
semantics, flag-setting identities, test/move operand elision, PC legality,
and ARMv7 admission.

The adjacent 14 leaves 1775--1788 complete `ORN`/`ORNS`, `MVN`/`MVNS`,
`EOR`/`EORS`, and `TEQ` under the same exact shifted-register and RRX contract.
The packing pair 1789--1790 completes `PKHBT` and `PKHTB`, including exact
LSL/ASR immediates, encoded ASR #32, PC legality, ARMv6 admission, and
extras-disabled ownership.
The next four leaves 1791--1794 complete shifted-register `ADD` and `ADDS`,
including RRX, exact shift metadata, flag-setting identity, PC/SP legality,
ARMv7 admission, and extras-disabled ownership.
The adjacent six leaves 1795--1800 complete the SP-source `ADD`/`ADDS` forms
and the destination-eliding `CMN` alias under the same shifted-register,
flag-setting, legality, admission, and ownership contract.
The next eight leaves 1801--1808 complete `ADC`/`ADCS` and `SBC`/`SBCS`,
including RRX and exact shift metadata, carry-consuming identities, flag
metadata, register legality, ARMv7 admission, and extras-disabled ownership.
The following fourteen leaves 1809--1822 complete `SUB`/`SUBS`, their
SP-source forms, destination-eliding `CMP`, and `RSB`/`RSBS`, including RRX,
exact shifts, flags, register legality, ARMv7 admission, and disabled ownership.
The six wide T32 hint leaves 1825--1830 complete `NOP`, `YIELD`, `WFE`, `WFI`,
`SEV`, and `SEVL`, with ARMv7/ARMv8 admission and extras-disabled ownership.
Six T32 system leaves 1841--1846 complete `CLREX`, `DSB`, `SSBB`, `PSSBB`,
`DMB`, and `ISB`, including barrier options, alias operand elision, ARMv7
admission, and extras-disabled ownership. `SB` remains feature-gate deferred.
The three T32 exception leaves 1856--1858 add exact `HVC #imm16`, `SMC #imm4`,
and `UDF #imm16`, with interrupt/privilege metadata, ARMv7 admission,
big-endian transport, truncation, corpus, fuzz, and extras-disabled ownership.
T32 forms 1848--1850 add exact `BXJ Rm`, `SUBS PC, LR, #imm8`, and the
zero-immediate `ERET` alias. They preserve indirect-jump and privileged
interrupt-return grouping, flag updates, reserved-register rejection,
ARMv7 admission, endian transport, truncation, and extras-disabled ownership.
T32 conditional `B.W` form 1859 and immediate `BLX` form 1861 now have exact
signed target reconstruction. Conditional branches preserve the encoded
condition; BLX uses the aligned PC base and link/call metadata. Reserved
conditions, backward targets, endian transport, architecture admission,
truncation, and neighboring `B.W`/`BL` ownership are covered.
The first T32 modified-immediate logical block adds exact `AND`, `ANDS`, `TST`,
`BIC`, and `BICS` forms 1863--1867. The decoder performs architectural Thumb
immediate expansion, rejects forbidden zero-replication encodings, selects the
`TST` alias, preserves flag writes, and enforces SP/PC register legality.
The remaining modified-immediate logical block, forms 1868--1878, adds exact
`ORR`, `ORRS`, `MOV`, `MOVS`, `ORN`, `ORNS`, `MVN`, `MVNS`, `EOR`, `EORS`,
and `TEQ`. Source-PC and destination-PC aliases are classified before ordinary
register legality, with expanded immediates and flag access preserved.
Modified-immediate arithmetic forms 1879--1883 add exact `ADD`, `ADDS`, their
SP-source variants, and destination-eliding `CMN`. They reuse architectural
Thumb expansion while preserving SP-specific form identity, flag writes, and
destination/source legality. Immediate `ADC/SBC` remains uncredited because
LLVM 21 rejects those catalog spellings and no independent oracle is available.
Plain-imm12 T32 forms 1895--1900 add exact `ADDW`, `SUBW`, their SP-source
variants, and positive/negative `ADR.W` aliases. ADR uses the aligned PC base
and exposes the resolved address plus signed displacement without branch
metadata; ordinary arithmetic retains the unexpanded imm12 operand.
Modified-immediate forms 1888--1894 add exact `SUB`, `SUBS`, their SP-source
variants, destination-eliding `CMP`, and `RSB`/`RSBS`. Exact Thumb expansion,
flag writes, SP restrictions for reverse subtraction, invalid zero replication,
endian transport, truncation, and extras-disabled ownership are covered.

These
numbers are evidence for the checked-in probes
and generated catalogs, not totals of semantically complete forms for either
ISA. Neither decoder is ISA-complete, and these inventories do not claim
complete x86 or ARM coverage.

Disabling both architectures creates a common-only
build for version, status, CPU-profile detection, CPU-group, and common-ID
services; its generic
`cdisasm_decode` entry point has no destination decoder and returns zero without
modifying the result pointer. These options select which decoder sources and
explicit exports are compiled into `cdisasm-12`; they do not describe the
processor running CMake. An x86 host can build ARM decoding into the core, an
ARM host can build x86 decoding into it, and a cross build behaves the same way.
`cdisasm_current_cpu()` runs in the finished library rather than during CMake
configuration and returns `CDISASM_CPU_UNKNOWN` when the caller-visible
architecture is disabled or cannot be mapped to an enabled named profile.
`USE_DISASM_FORMAT=ON` only adds implementations for enabled architectures. A
common-only build records the request but publishes effective
`USE_DISASM_FORMAT=0`, has no formatter symbols, target, or package component,
and installs the diagnostic-only `cdisasm_format.h` just like every other
variant.
`USE_EXTRA_OPCODES=ON` similarly adds extended families only to enabled
decoders. A common-only build records the request but publishes effective
`USE_EXTRA_OPCODES=0`.

The option controls a precise append-only extension tranche; it is not a
promise that every modern encoding is implemented. Public name IDs remain
defined in both variants, as are the appended register IDs, operand kinds,
metadata flags, and count constants. Stored numeric records and result
structure sizes therefore do not change. Every semantic decoder descriptor and
every mnemonic/register spelling introduced by the modern tranche is guarded
by `USE_EXTRA_OPCODES=1`; there is no fallback spelling in an OFF formatter.
The structural classifiers remain compiled in both variants so they can own a
controlled encoding and report its precise status without accidentally falling
through to an older instruction map.

For x86, build selection, the runtime allow bitmap, and CPU availability are
three independent gates:

| x86 call/input | `USE_EXTRA_OPCODES=1` | `USE_EXTRA_OPCODES=0` |
| --- | --- | --- |
| `flags == NULL` or points to an all-zero object, with a base encoding | Decode, subject to mode and CPU validation | Same |
| `flags == NULL` or points to an all-zero object, with a complete CPU-eligible non-base encoding | `CDISASM_STATUS_UNSUPPORTED_INSTRUCTION` | `CDISASM_STATUS_UNSUPPORTED_INSTRUCTION` |
| Pointer to known nonzero family bits | Allow selected families, then independently apply CPU capability gates | `CDISASM_STATUS_INVALID_ARGUMENT` before decoding input |
| Pointer to `CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER` | Valid all-known-family policy; CPU gates still apply | `CDISASM_STATUS_INVALID_ARGUMENT` |
| Any reserved bit in any bitmap word | `CDISASM_STATUS_INVALID_ARGUMENT` | `CDISASM_STATUS_INVALID_ARGUMENT` |
| Reserved or malformed encoding | `CDISASM_STATUS_INVALID_INSTRUCTION` | `CDISASM_STATUS_INVALID_INSTRUCTION` |
| Incomplete controlled encoding | `CDISASM_STATUS_TRUNCATED` | `CDISASM_STATUS_TRUNCATED` |

The malformed and truncated rows assume a valid mask; argument validation runs
first. A matching family bit also does not override CPU policy: for example,
AES bytes plus the `AES` bit still return `INVALID_INSTRUCTION` on a pre-AES
profile.

Every controlled-encoding failure from an architecture decoder clears the
entire architecture result and sets only `last_error_id`. In an OFF build, a
formatter given a forged result containing one of the gated IDs returns zero
and clears a nonempty output buffer. Thus an
OFF build cannot decode or print a modern-tranche opcode even though its public
numeric ID remains available for ABI stability.
Existing non-base x86 families such as x87, 3DNow!, legacy SSE, VMX/SVM, and
undocumented forms now use the same explicit runtime policy: successful decode
requires `USE_EXTRA_OPCODES=1`, the corresponding family bit, and a compatible
CPU. This runtime policy does not change their append-only IDs or structural
classification. Baseline ARM NEON and Apple-private instructions retain their
architecture-specific decode-flag and CPU behavior; the x86 allow bitmap does
not apply to ARM.

The current post-12.0 additions supplement the compact table below with all
ten ACE TOP2/TOP4 forms, both legacy/APX-F RAO-INT rows, the complete ACE BSR
state-transfer family, all legacy/VEX/APX USER_MSR routes, the complete
eleven-form Key Locker family, and exact HRESET, CLDEMOTE, CLZERO,
PCONFIG/PCONFIG64, PBNDKB, PREFETCHIT0/PREFETCHIT1,
MONITORX/MWAITX/MCOMMIT, AMD_INVLPGB, and SNP system slices
plus MSRLIST/MSR_IMM/WRMSRNS, RDPRU, PREFETCHRST2, PREFETCHWT1, exact
register/memory PTWRITE forms 2438--2439, memory-only MOVNTI forms 1692--1693,
the eighteen-form legacy/VEX/EVEX `MOVNTDQ`/`MOVNTPD`/`MOVNTPS` store family
and its exact `MOVNTQ`/`MOVNTSD`/`MOVNTSS` prefix collisions, and fixed SMAP
`CLAC`/`STAC` forms 707/3158, memory-source `MOVNTDQA` form 1690 and
`VMOVNTDQA` forms 5864--5868, and `LDDQU`/`VLDDQU` forms
1574/5583--5584, plus exact scalar `VMOVSD` forms 5909--5915, FP16 scalar
`VMOVSH` forms 5926--5928, `VMOVSHDUP`/`VMOVSLDUP` forms
5916--5925/5929--5938, `VMOVSS` forms 5939--5945, and packed unaligned
`VMOVUPD`/`VMOVUPS` forms 5946--5979, exact EVEX map-5 `VMOVW` forms
5980--5986, VEX/EVEX `VMPSADBW` forms 5987--5996, exact VMX/SVM
virtualization forms 5997--6005/6048--6053, `VMULBF16` forms 6006--6011,
`VMULPH` forms
6022--6027, `VMULSH` forms 6042--6043, and classic
`VMULPD`/`VMULPS`/`VMULSD`/`VMULSS` forms 6012--6021, 6028--6041, and
6044--6047, packed logical-OR `VORPD`/`VORPS` forms 6054--6073, and exact
`VP2INTERSECTD/Q` forms 6074--6085, `VPABSB/D/Q/W` forms 6088--6123, and
`VPACKSSDW/SSWB/USDW/USWB` forms 6124--6163 and exact VEX
`VPBLENDD` forms 6306--6309, `VPBLENDVB` forms 6334--6337, and `VPBLENDW`
forms 6338--6341, plus VEX `VPBROADCASTB` forms
6342/6343/6347/6348, `VPBROADCASTD` forms 6355/6356/6360/6361,
`VPBROADCASTQ` forms 6374/6375/6379/6380, and `VPBROADCASTW` forms
6387/6388/6392/6393, plus VEX `VPCMPEQQ` forms 6454--6457 and
`VBLENDPD`/`VBLENDPS` forms 3527--3534 and
  `VBLENDVPD`/`VBLENDVPS` forms 3535--3542, and
  `VBROADCASTF128`/`VBROADCASTI128` forms 3543/3554, and VEX
  `VBROADCASTSD`/`VBROADCASTSS` forms 3569--3570/3573--3574/3579--3580,
  plus VEX `VEXTRACTF128`/`VEXTRACTI128` forms 4539--4540/4553--4554 and
  `VINSERTF128`/`VINSERTI128` forms 5551--5552/5565--5566, plus VEX
  `VEXTRACTPS`/`VINSERTPS` forms 4567/4569/5579--5580, plus VEX
  `VPERM2F128`/`VPERM2I128` forms 6770--6773 and VEX
  `VPERMD`/`VPERMPS` forms 6780--6781/6886--6887, exact AMD XOP
  `VPCMOV` forms 6410--6415, exact XMM `VPPERM` forms 7686--7688, and
  classic-VEX `VPTEST` forms 8319--8322, plus
  classic-VEX `VPMOVMSKB` forms 7334--7335, `VPSIGNB/W/D` forms
  7921--7932, and `VPSHUFD/HW/LW` forms 7891--7916, plus
  classic-VEX `VCOMISD`/`VCOMISS` forms 3629--3630/3633--3634, plus
  classic-VEX `VDPPD`/`VDPPS` forms 4507--4508/4515--4518, plus
  classic-VEX `VCMPPD`/`VCMPPS`/`VCMPSD`/`VCMPSS` forms
  3595--3598/3611--3614/3617--3618/3623--3624, plus
  classic-VEX `VUNPCKHPD`/`VUNPCKHPS`/`VUNPCKLPD`/`VUNPCKLPS` forms
  8825--8862, all 32 classic-VEX integer `VPUNPCK*` forms 8323--8398, and
  all 24 classic-VEX horizontal integer `VPHADD*`/`VPHSUB*` forms 7012--7059,
  plus classic-VEX `VPHMINPOSUW` forms 7040--7041, `VPINSRB/D/Q/W` forms
  7060--7061/7064--7065/7068--7069/7072--7073, and `VPEXTRB/D/Q/W` forms
  6966/6968/6970/6972/6974/6976/6978--6979/6983, plus all 24 classic-VEX
  `VPMOVSXBW/BD/BQ/WD/WQ/DQ` and all 24 classic-VEX
  `VPMOVZXBW/BD/BQ/WD/WQ/DQ` forms listed above, the complete packed-integer
  MIN/MAX block 7160--7303, and all GFNI forms 1308--1313/5505--5534 on x86.
On ARM
they add indexed `DUP`/preferred `MOV`, FP8 narrowing, the complete SME2
two-vector conversion/unpack/widening/rounding block 4312--4338,
SME_F16F16 widening forms 4339--4340, the complete SME2 four-vector block
4341--4362, SME `FMUL`/`BFMUL` forms 4363--4370, baseline-SME predicated
ZA-slice `MOVA` forms 3862--3866/3877--3881, SME2 pair/quad ZA-transfer
forms 3867--3876/3882--3891, SME2.1 zeroing ZA-extract `MOVAZ` forms
3892--3906, FEAT_FlagM/FlagM2 forms 4499--4501/5696--5698, SVE FFR forms
2562--2564/2617--2618, baseline-SME ZA load/store
forms 4381--4382, SME2 ZT0 load/store forms
4383--4384, baseline A64 `UDF` form 4387, FEAT_WFxT `WFET`/`WFIT` forms
4457--4458, SVE2.1-or-SME2 multi-extract
narrowing, `ADDVL`/`ADDPL`/`RDVL`,
Advanced SIMD `REV16`/`REV32`/`REV64` and `CLS`/`CNT`/`CLZ`, and nine baseline
SVE/SME integer reductions, plus all eighteen non-saturating SVE/SME
element-count forms 2374--2391 and all 64 saturating/predicate-count/search
forms 2362--2373, 2392--2423, and 2597--2616, including SVE2.2-or-SME2.2
`FIRSTP`/`LASTP` forms 2598--2599, predicate-break forms 2546--2555,
predicate-control forms 2556--2561, `PSEL` form 2565, the complete
wide-immediate arithmetic and preferred `MOV`/`FMOV` broadcast block
2619--2632, exact unpredicated `SDOT`/`UDOT` forms 2633--2636, exact
`SQDMLALBT`/`SQDMLSLBT`/`CDOT`/`CMLA`/`SQRDCMLAH` forms 2637--2641, the
unpredicated widening/rounding multiply-add forms 2642--2655, exact mixed-sign
  `USDOT` form 2656, indexed `MLA`/`MLS` forms 2722--2727, indexed
  `SQRDMLAH`/`SQRDMLSH` forms 2728--2733, indexed `USDOT`/`SUDOT` forms
  2734--2735, and SVE
`AESMC`/`AESIMC` forms 2903--2904 and crypto-binary `AESE`/`AESD`/`SM4E`
forms 2905--2907, plus predicate-unpack `PUNPKLO`/`PUNPKHI` forms 2468--2469
and vector-unpack `SUNPKLO`/`SUNPKHI`/`UUNPKLO`/`UUNPKHI` forms 2456--2459,
  plus SVE2/SME shift-insert `SRI`/`SLI` forms 2846--2847, Advanced SIMD
  `BSL`/`BIT`/`BIF` forms 6188/6196/6198 and
  `ADDHN`/`SUBHN`/`RADDHN`/`RSUBHN` forms 6093/6095/6108/6110, plus
  Advanced SIMD `SADDL`/`SADDW`/`SSUBL`/`SSUBW` and unsigned forms
  6089--6092/6104--6107, FEAT_PAuth
  authenticated register branches 4510/4511/4513/4514/4525--4528, and SVE BitPerm
`BEXT`/`BDEP`/`BGRP` forms 2829--2831,
baseline Advanced SIMD scalar/vector `CMTST` forms 5831/6131,
`SSHL`/`USHL` forms 5826/5841/6122/6164, fixed-vector `SABA`/`UABA`
forms 6129/6171, fixed-vector `SABD`/`UABD` forms 6128/6170, and fixed-vector
`MLA`/`MLS` forms 6132/6174 plus by-element forms 6268/6270 and widening
by-element `SMLAL`/`SQDMLAL`/`SMLSL`/`SQDMLSL`/`SMULL`/`SQDMULL`/
`UMLAL`/`UMLSL`/`UMULL` forms 6243--6246/6248--6249/6269/6271--6272,
predicated merging
shift/saturating-round forms 2657--2668,
predicated `URECPE`/`URSQRTE`/`SQABS`/`SQNEG` forms 2669--2676,
predicated accumulating-long `SADALP`/`UADALP` forms 2677--2678, the
eight-operation predicated halving row 2679--2686, and predicated pairwise
`SUBP`/`ADDP`/`SMAXP`/`SMINP`/`UMAXP`/`UMINP` forms 2687--2692,
plus predicated saturating `SQADD`/`SQSUB`/`SUQADD`/`USQADD`/`SQSUBR`/
`UQADD`/`UQSUB`/`UQSUBR` forms 2693--2700 and destructive unpredicated
`SCLAMP`/`UCLAMP` forms 2701--2702, plus `.D` pointer multiply-add transform
`MLAPT`/`MADPT` forms 2707--2708 and quad-permute `ZIPQ1`/`UZPQ1`/
`ZIPQ2`/`UZPQ2` forms 2711--2712/2714--2715, all single, paired, and
counter-predicate WHILE relations
2566--2581/2585--2592, `PEXT`/counter-predicate `PTRUE` forms 2582--2584,
and scalar/vector Advanced SIMD `ADDP` forms 5808/6137 plus Advanced SIMD
`ADDV` form 6077 and fixed-vector
`SMAX`/`SMIN`/`UMAX`/`UMIN` forms
6126--6127/6168--6169 plus register `CMGT`/`CMGE`/`CMHI`/`CMHS`/`CMEQ`
forms 6120--6121/6162--6163/6173, scalar/vector `CMTST` forms 5831/6131,
scalar/vector `SSHL`/`USHL` forms 5826/5841/6122/6164,
and scalar/vector compare-with-zero `CMLT`/`CMLE` forms
5777/5794/6013/6045, all 30 A32/T32/A64 SHA1/SHA256 leaves, and the complete
fixed A64 SHA3/SHA512/SM3/SM4 crypto block 6287--6303.

| Decoder | Additional families when `USE_EXTRA_OPCODES=ON` | CPU policy |
| --- | --- | --- |
| x86 | The 60-name VEX AVX/AVX2 slice; representative map-2/map-3 and BMI1/2/F16C forms; complete VEX/EVEX FMA3 and FMA4 matrices; the cataloged XOP tranche; all 51 classic VEX K-mask mnemonics; complete packed-integer EVEX compare-to-mask, MIN/MAX, multiply/multiply-add, modular/wrapping ADD/SUB, D/Q logical, byte/word average, word/dword/qword per-element variable-shift, dword/qword variable and immediate packed-rotate, opcode-`72` dword/qword immediate shifts, opcode-`71`/`73` word/qword/byte-lane immediate shifts, and byte/word/dword/qword COMPRESS/EXPAND; the complete eight-name VEX/EVEX saturating packed ADD/SUB family; the complete BITALG/VPOPCNT and six-name AVX-512CD families; the complete four-operation EVEX AVX-512 VNNI, complete six-name EVEX AVX10.2 VNNI-INT8 row, and bounded classic VEX AVX-VNNI, AVX-VNNI-INT8, and AVX-VNNI-INT16 dot-product rows; the exact Knights Mill `VP4DPWSSD`/`VP4DPWSSDS` AVX512_4VNNIW pair and complete `V4FMADDPS`/`V4FMADDSS`/`V4FNMADDPS`/`V4FNMADDSS` AVX512_4FMAPS family; the exact AVX512F/AVX10.1 `VGETEXPPS`/`VGETEXPPD`/`VGETEXPSS`/`VGETEXPSD` tranche and exact MAP6 `VGETEXPPH`/`VGETEXPSH`/`VGETEXPBF16` forms; classic AVX512_VBMI byte-permute/multishift slice; and AVX512BW/AVX10 `VPERMI2W`/`VPERMT2W`/`VPERMW` rows; exact scalar `VMOVSD`, `VMOVSH`, and `VMOVSS`, exact `VMOVSHDUP`/`VMOVSLDUP`, packed unaligned `VMOVUPD`/`VMOVUPS`, exact `VMOVW`, VEX/EVEX `VMPSADBW`, VMX/SVM virtualization forms 5997--6005/6048--6053, AVX10.2 `VMULBF16` forms 6006--6011, all 28 classic floating multiply forms 6012--6021/6028--6041/6044--6047, all twenty `VORPD`/`VORPS` forms 6054--6073, exact `VP2INTERSECTD/Q` and `VPABSB/D/Q/W`, all 40 `VPACKSSDW/SSWB/USDW/USWB` forms 6124--6163, exact VEX `VPBLENDD`/`VPBLENDVB`/`VPBLENDW` forms 6306--6309/6334--6341, and classic-VEX `VUNPCKHPD`/`VUNPCKHPS`/`VUNPCKLPD`/`VUNPCKLPS` forms 8825--8862; exact APX P0.B4 and selected U0/X4 ownership; REX2 `MONITOR`/`MWAIT`; exact HRESET, CLDEMOTE, CLZERO, PCONFIG/PCONFIG64, PBNDKB, PREFETCHIT0/PREFETCHIT1, MONITORX/MWAITX/MCOMMIT, AMD_INVLPGB, SNP, Key Locker, ACE BSR, USER_MSR, MSRLIST/MSR_IMM/WRMSRNS, RDPRU, PREFETCHRST2, PREFETCHWT1, PTWRITE, MOVNTI, `MOVNTDQA`/`VMOVNTDQA`, SMAP, and RAO-INT slices; and bounded AES/SHA/PCLMUL, VAES/VPCLMUL, other EVEX AVX-512/AVX10, AMX, APX, CET, WAITPKG, entropy, RTM, and system forms listed above | Independent chronological and vendor-aware capabilities; classic VEX AVX-VNNI, AVX-VNNI-INT8, and AVX-VNNI-INT16 use separate bit-61/62/63 selectors and CPU features, while EVEX VNNI-INT8 uses AVX10; VMPSADBW uses AVX/AVX2 for VEX and its exact AVX512-MEDIAX width routes for EVEX; virtualization forms retain independent VMX/SVM/VTX and APX-F gates; VMULBF16 uses exact width bits 99--101 plus AVX10.2, while classic EVEX VMUL uses exact AVX512F width/scalar bits 128/130/131/133 through AVX-512F/VL or AVX10.1; VOR EVEX forms use the exact AVX512DQ width routes through AVX-512DQ/VL or AVX10.1 and reserve register `EVEX.b`; promoted encodings independently require APX-F; AVX512_4VNNIW and AVX512_4FMAPS reuse the AVX-512 runtime umbrella with independent exact Knights Mill CPU gates; PS/PD/SS/SD VGETEXP uses mutually exclusive AVX512F/AVX512VL and AVX10.1 CPU/runtime routes; PH/SH uses AVX512-FP16 (plus AVX512VL for packed 128/256-bit PH) or AVX10.1, while BF16 and EVEX VNNI-INT8 require AVX10.2 and the AVX10 runtime selector; RDPRU, MOVRS, PREFETCHWT1, PTWRITE, and SMAP use independent exact runtime selectors and conservative profile gates; PTWRITE and SMAP REX2 routes additionally require APX-F; MOVNTI uses the SSE2 selector, and its REX2 route requires both SSE2 and APX/APX-F; `MOVNTDQA` uses exact SSE4 ISA-set bit 270, VEX forms use AVX/AVX2, EVEX forms use their exact AVX512F width bit, and APX-promoted EVEX addresses additionally require APX/APX-F; SMAP shares `0F 01 CA` with the mandatory-F2/F3 FRED fallback without claiming exact FRED state semantics; no-AVX SKUs, WAITPKG/APX cross-gates, mutually alternative AVX-512-versus-AVX10 admission, and retired AMD/Intel boundaries remain non-monotonic |
| ARM A32/T32 | Representative wider core, VFP, and NEON forms listed above, plus exact no-operand T32 `DCPS1`/`DCPS2`/`DCPS3` forms 1853--1855 | Architecture/VFP/NEON and architectural-version capability checks per named profile; `CPU_ANY` is unrestricted within an ON build |
| ARM A64 | Existing LSE/LOR/RCpc; complete bounded SVE predicate-logical, integer vector-compare, integer compare-with-immediate, floating compare-with-zero, floating vector-compare, destructive predicated floating binary-arithmetic, the seven-name FEAT_SVE_B16B16 binary row, fast-reduction, `FADDA`, predicated FP-unary, and exact SVE FFR `RDFFR`/`RDFFRS`/`WRFFR`/`SETFFR`; exact SVE/SME wide-immediate integer arithmetic and preferred `MOV`/`FMOV` broadcasts through form 2632; the exact merging H/S/D-to-H plus S-to-S/D and D-to-S/D `SCVTF`/`UCVTF` classes, the complete baseline merging H/S/D `FCVT`/`FCVTZS`/`FCVTZU` class plus exact S-to-H zeroing `FCVT`, exact merging SVE/SME `BFCVT`/`BFCVTNT Zd.H, Pg/m, Zn.S`, exact SVE2.2/SME2.2 zeroing `BFCVT`/`BFCVTNT Zd.H, Pg/z, Zn.S`, and exact unpredicated SME2/SVE2 pair `BFCVT`/`BFCVTN` S-to-H and H-to-FP8 forms; structured A64 `DCPS1`/`DCPS2`/`DCPS3`, exact baseline `UDF #imm16`, and exact FEAT_WFxT `WFET`/`WFIT`; exact FEAT_FlagM/FlagM2 `CFINV`/`XAFLAG`/`AXFLAG`/`RMIF`/`SETF8`/`SETF16`; unpredicated SVE/SME and fixed-width Advanced SIMD `FRECPE`/`FRSQRTE` classes; exact Advanced SIMD regular `SMAX`/`SMIN`/`UMAX`/`UMIN`, `REV16`/`REV32`/`REV64`, and `CLS`/`CNT`/`CLZ`; unpredicated and destructive-predicated integer-arithmetic, integer unary, vector-shift, immediate-shift, SVE2/SME merging variable shift/saturating-round, exact accumulating-long, halving, pairwise, and eight-form predicated saturating arithmetic through form 2700, and exact destructive `SCLAMP`/`UCLAMP` forms 2701--2702; exact non-saturating and saturating element-count plus predicate-count classes; exact SVE predicate-break forms 2546--2555; scalable vector ZIP/UZP/TRN, the disjoint F64MM Q-element ZIP/UZP/TRN class, and fixed-width Advanced SIMD ZIP/UZP/TRN classes; the selected SVE table-lookup/MOV class; complete disjoint SVE2.1/SME2.1 `TBLQ`; exact SME `FMUL`/`BFMUL`, baseline-SME predicated ZA-slice `MOVA`, SME2 aligned-pair/quad ZA `MOVA`, SME2.1 zeroing ZA-extract `MOVAZ`, baseline-SME ZA load/store, and SME2 ZT0 load/store slices; and representative wider FP/NEON, other SVE/SVE2, SME/SME2, LSE128/RCpc3, BTI, PAuth, MTE, MOPS, LS64, and CSSC forms | Existing Apple evidence cutoffs remain explicit; `CPU_ANY` exposes all; baseline UDF is admitted by every A64-capable profile and reports a successful interrupt-group decode without `ILLEGAL`; WFxT and FlagM/FlagM2 are independently `CPU_ANY`-only because no current named profile advertises those features; the exact SVE FFR and wide-immediate blocks admit SVE or SME, including A64FX through SVE and A18/M4 through SME; ordinary element and predicate count forms admit SVE or SME, while PN-counter `CNTP` requires SVE2.1 or SME2; the bounded merging integer/FP conversions admit SVE or SME with source-granularity predicate metadata; S-to-H zeroing `FCVT` requires SVE2p2 or SME2p2, and the BFloat16 binary row requires FEAT_SVE_B16B16; both are currently `CPU_ANY`-only; merging `BFCVT` and `BFCVTNT` additionally require BF16 and are admitted by A18/M4, while the zeroing pair requires SVE2p2 or SME2p2 and is currently `CPU_ANY`-only; pair S-to-H `BFCVT`/`BFCVTN` requires SME2 and is admitted by A18/M4, pair H-to-FP8 `BFCVT` requires SME2+FP8, and pair H-to-FP8 `BFCVTN` requires (SVE2 or SME2)+FP8; FP8 is independently `CPU_ANY`-only and there is no pair `BFCVTNT`; the F64MM Q-element class is conservatively `CPU_ANY`-only; SVE/SME FP estimates admit SVE or SME, while fixed-width estimates require Advanced SIMD and half-precision forms also require FP16; FP-unary zeroing requires SVE2p2 or SME2p2; `FADDA` strictly requires SVE; saturating/rounding immediate shifts and merging variable shift/saturating-round forms require SVE2 or SME; `SCLAMP`/`UCLAMP` require SVE2.1 or SME; fixed-width permutation and bit count require NEON; baseline ZA transfers and MOVA require SME, while multi-register MOVA and ZT0 transfer require SME2; those are admitted by A18/M4. MOVAZ instead requires SME2.1 and is `CPU_ANY`-only because every current named profile, including A18/M4, lacks SME2.1; lookup forms use exact SVE/SVE2/SME/SVE2.1/SME2.1 alternatives; `TBLQ` requires SVE2.1 or SME2.1 and is unavailable to every current named profile; `ADDPT`/`SUBPT` strictly require SVE plus CPA; A64FX exposes SVE without SME, A18/M4 expose SME/SME2, and S4--S10 expose FP16/PAuth; no ordinal comparison is used |

The x86 row additionally includes exact `VPBLENDVB` forms 6334--6337 with
AVX/AVX2 groups and selector-byte semantics, AVX2 VEX `VPBROADCASTB` forms
6342/6343/6347/6348, `VPBROADCASTD` forms 6355/6356/6360/6361,
`VPBROADCASTQ` forms 6374/6375/6379/6380, and `VPBROADCASTW` forms
6387/6388/6392/6393, plus VEX `VPCMPEQQ` forms 6454--6457,
  `VBLENDPD`/`VBLENDPS` forms 3527--3534 and `VBLENDVPD`/`VBLENDVPS` forms
  3535--3542, plus `VEXTRACTF128`/`VEXTRACTI128` forms
  4539--4540/4553--4554 and `VINSERTF128`/`VINSERTI128` forms
  5551--5552/5565--5566, plus `VEXTRACTPS`/`VINSERTPS` forms
  4567/4569/5579--5580, `VPERM2F128`/`VPERM2I128` forms 6770--6773, and
  `VPERMD`/`VPERMPS` forms 6780--6781/6886--6887, and
  `VPCMOV` forms 6410--6415 and `VPPERM` forms
  7686--7688 with AVX+XOP metadata, plus classic-VEX `VPHMINPOSUW` forms
  7040--7041. The ARM A64 row additionally includes exact
`.D`-only `MLAPT`/`MADPT` forms 2707--2708 under the conjunctive SVE+CPA
gate, B/H/S/D `ZIPQ1`/`UZPQ1`/`ZIPQ2`/`UZPQ2` forms
2711--2712/2714--2715 under the SVE2.1-or-SME2.1 gate, indexed
`MLA`/`MLS` forms 2722--2727 under the SVE2-or-SME gate, indexed
`USDOT`/`SUDOT` forms 2734--2735 under the SVE-or-SME plus I8MM gate, and
SVE `AESMC`/`AESIMC` forms 2903--2904 under FEAT_SVE_AES, plus
  `AESE`/`AESD` forms 2905--2906 under FEAT_SVE_AES and `SM4E` form 2907 under
FEAT_SVE_SM4, plus `PUNPKLO`/`PUNPKHI` forms 2468--2469 and
  `SUNPKLO`/`SUNPKHI`/`UUNPKLO`/`UUNPKHI` forms 2456--2459 under SVE or SME,
  plus `SRI`/`SLI` forms 2846--2847 under SVE2 or SME, and Advanced SIMD
  `ADDHN`/`SUBHN`/`RADDHN`/`RSUBHN` forms 6093/6095/6108/6110 under NEON,
  plus Advanced SIMD widening add/sub forms 6089--6092/6104--6107 and
  absolute-difference-long forms 6094/6096/6109/6111 under NEON, and
  authenticated register branches 4510/4511/4513/4514/4525--4528 under
  PAuth, plus fixed-vector Advanced SIMD `MLA`/`MLS` forms 6132/6174 under
  baseline NEON. The x86 row also includes exact classic-VEX `VDPPD`/`VDPPS`
forms 4507--4508/4515--4518 and `VCMPPD`/
`VCMPPS`/`VCMPSD`/`VCMPSS` forms 3595--3598/3611--3614/3617--3618/
3623--3624 under AVX with MXCSR metadata. The ARM A64 row also includes exact
scalar/vector Advanced SIMD `ADDP` forms 5808/6137 and reduction `ADDV` form
6077 under baseline NEON.
These additions
remain bounded;
neither decoder is ISA-complete.

The x86 row also includes exact `LDDQU`/`VLDDQU`: legacy form 1574 uses SSE3
and adds APX only for REX2 map 1, while VEX forms 5583--5584 use AVX at both
widths. It also includes `VMOVW` forms 5980--5986, whose `66` and F3 selectors
use independent `AVX512_FP16_128N` and `AVX512_MOVZXC_128` runtime/profile
routes, followed by exact `VMPSADBW` forms 5987--5996 and exact VMX/SVM
virtualization forms 5997--6005/6048--6053, `VMULBF16` forms 6006--6011,
`VMULPH` forms
6022--6027, `VMULSH` forms 6042--6043, and classic
`VMULPD`/`VMULPS`/`VMULSD`/`VMULSS` forms 6012--6021, 6028--6041, and
6044--6047, followed by `VORPD`/`VORPS` forms 6054--6073,
`VP2INTERSECTD/Q` forms 6074--6085, and `VPABSB/D/Q/W` forms 6088--6123. The
VOR VEX forms
require AVX; EVEX forms use exact AVX512DQ width selectors through an
AVX-512DQ/VL or AVX10.1 route, reserve register `EVEX.b`, and retain masks,
broadcast, Full-tuple disp8, high-register, and APX addressing semantics.
VP2INTERSECT uses exact AVX512_VP2INTERSECT width selectors, the Tiger Lake
feature route, an even/odd K destination pair, and independently APX-gated
address extensions. In the ARM row,
predicate count/search includes `FIRSTP`/`LASTP` forms
2598--2599; unlike the ordinary SVE-or-SME count forms, they require SVE2.2 or
SME2.2 and are currently admitted only by `CPU_ANY`. The adjacent exact `PSEL`
form 2565 instead admits either SVE2.1 or baseline SME. Wide-immediate forms
2619--2632 admit either SVE or SME and preserve preferred `MOV`/`FMOV` aliases
for the two broadcast leaves. The following `SDOT`/`UDOT` forms 2633--2636
use the same baseline alternative for B-to-S and H-to-D widening; B-to-H
requires SVE2p3 or SME2p3 and is currently `CPU_ANY`-only.
Forms 2637--2641 then require SVE2 or SME for
`SQDMLALBT`/`SQDMLSLBT`/`CDOT`/`CMLA`/`SQRDCMLAH`.
Forms 2642--2655 continue that SVE2-or-SME alternative for the exact
unpredicated widening and same-width rounding multiply-add block. Form 2656
then uses the distinct conjunctive `(SVE or SME) and I8MM` gate for exact
`USDOT Zda.S, Zn.B, Zm.B`; no current named profile advertises I8MM, so it is
currently `CPU_ANY`-only. Forms 2657--2668 instead require SVE2 or SME for the
twelve merging variable shift/saturating-round operations, admitting Apple
A18/M4 through SME while rejecting baseline-SVE-only A64FX. Forms 2669--2676
then add merging and zeroing `URECPE`/`URSQRTE`/`SQABS`/`SQNEG`: merging
requires SVE2 or SME, zeroing requires SVE2.2 or SME2.2, the estimate pair is
`.S`-only, and the saturating pair accepts B/H/S/D.
Forms 2677--2686 then add exact SVE2-or-SME `SADALP`/`UADALP` accumulating-
long operations and all eight signed/unsigned halving arithmetic operations.
The former widen B/H/S sources to H/S/D destinations and reserve `size=00`;
the latter allocate every B/H/S/D arrangement.
Forms 2687--2692 add the six destructive predicated pairwise operations for
every B/H/S/D arrangement. `SUBP` requires SVE2p3 or SME2p3; the other five
require SVE2 or SME.
Forms 2693--2700 add the eight destructive predicated saturating operations
under SVE2 or SME. Forms 2701--2702 then add destructive unpredicated
`SCLAMP`/`UCLAMP` under SVE2.1 or SME. Forms 2707--2708 add `.D`-only
destructive `MLAPT`/`MADPT` under the conjunctive SVE-and-CPA gate; every
current named profile rejects them, while `CPU_ANY` supplies the explicit
unrestricted route.

`BUILD_SHARED_LIBS` is independent of those feature selections and also
defaults to `ON`. Use `-DBUILD_SHARED_LIBS=OFF` for a static build:

```powershell
cmake -S . -B build-static -DBUILD_SHARED_LIBS=OFF
cmake --build build-static --config Release
```

When cdisasm is embedded with `add_subdirectory`, it does not create or change
the parent's global `BUILD_SHARED_LIBS` cache entry. Its scoped
`CDISASM_BUILD_SHARED_LIBS` option defaults from a parent value when one exists,
and the cdisasm target is explicitly typed. This prevents cdisasm from changing
the linkage of later untyped sibling targets.

| `BUILD_SHARED_LIBS` | `cdisasm::cdisasm` type | Windows output | Typical non-Windows output |
| --- | --- | --- | --- |
| `ON` (default) | shared library | `cdisasm-12.dll` plus `cdisasm.lib` import library | versioned `libcdisasm.so` or `libcdisasm.dylib` |
| `OFF` | static library | `cdisasm.lib` static archive; no DLL or import library | `libcdisasm.a` |

`CDISASM_BUILD_PACKAGE_TESTS` defaults to `ON` for a top-level build and to
`OFF` when cdisasm is included as a subproject. With `BUILD_TESTING=ON`, it adds
two isolated end-to-end tests. Together they exercise the complete 32-cell
shared/static × dual/x86/ARM/common-only × format-requested-ON/OFF ×
extra-opcodes-requested-ON/OFF release
matrix. Every cell builds a producer, consumes its build-tree package, installs
and relocates it, audits exact headers/libraries/symbols and component
acceptance/rejection, then builds and runs C and C++17 consumers through the
core and compatibility targets. Static ELF/Mach-O cells also embed the archive
in a wrapper shared object and reject leaked cdisasm symbols. Set the option to
`OFF` to run only the native executables and the two non-package CMake
integration tests for the current build. Cross-compiling builds omit these
runtime tests.

The architecture/formatter matrix is identical for shared and static builds.
Every row below is tested with `USE_EXTRA_OPCODES` both `ON` and `OFF`, but the
x86 legacy-extension suites are selected only in the ON variant because an OFF
decoder intentionally admits only base instructions. Focused suites are added
as coverage grows, so `ctest -N` for the configured tree is the authoritative
test count; the matrix records the stable dimensions instead of freezing a
quickly stale executable total:

`cdisasm_extra_opcode_contract_tests` is built whenever at least one
architecture is enabled. It pins the public x86/ARM result layouts and all
previously published ID ranges independently of `USE_EXTRA_OPCODES`. It also
checks representative VEX and A64 LSE encodings: `EXTRA_OK` corpus rows decode
and format with extras enabled, but return a zeroed
`UNSUPPORTED_INSTRUCTION` result and are rejected by the formatter when extras
are disabled. `EXTRA_PROFILE` and `EXTRA_INVALID` make CPU-policy and malformed
encoding expectations explicit rather than deriving them from case names.
`cdisasm_x86_flag_tests` is built whenever x86 is enabled. It pins every
numeric mask value, base-only zero behavior, each implemented selectable
family, combined undocumented-x87 permissions, encoding-only undocumented
aliases, all 64 assigned bits, all-bits-mask behavior, and CPU-gate independence
in both variants.
`cdisasm_x86_modern_tests` and `cdisasm_arm_modern_tests` pin the newly
appended catalogs and exercise modern semantics, formatter output, CPU gates,
reserved fields, truncation, big-endian ARM parity, and the full zeroed-failure
contract in both ON and OFF builds. The x86 build also runs dedicated CET,
WAITPKG, complete EVEX-FMA3, cross-map expansion, AMD XOP/FMA4 expansion,
next-generation AMX/AVX10/APX/system, exhaustive 51-name VEX K-mask, and
complete packed-integer EVEX compare-to-mask suites. The ARM build adds a
dedicated complete SVE predicate-logical submap suite. Version 11.2 also adds
exhaustive EVEX packed MIN/MAX and SVE unpredicated integer-arithmetic suites;
version 11.3 adds exhaustive EVEX packed multiply/multiply-add and SVE vector
ZIP/UZP/TRN suites; version 11.4 adds exhaustive modular EVEX packed ADD/SUB
and selected SVE table-lookup/MOV-control suites; version 11.5 adds the
complete VEX/EVEX saturating packed ADD/SUB and disjoint SVE2.1/SME2.1
`TBLQ` suites; version 11.6 adds exhaustive EVEX D/Q logical and byte/word
average suites, the destructive predicated SVE integer sweep, and the
  fixed-width A64 Advanced SIMD ZIP/UZP/TRN suite; version 11.7 adds the
  dword/qword VEX/EVEX variable packed-shift suite and an exhaustive sweep of
  the three predicated SVE unary classifiers; version 11.8 adds the adjacent
  EVEX word variable-shift suite and an exhaustive predicated SVE vector-shift
  classifier sweep; version 11.9 adds the EVEX variable packed-rotate suite
  and an exhaustive predicated SVE/SVE2 immediate-shift classifier sweep;
  version 11.10 adds the EVEX immediate packed-rotate suite and an exhaustive
  8,388,608-word SVE integer vector-compare classifier sweep; version 11.11
  adds the EVEX immediate packed-shift suite and an exhaustive 12,582,912-word
  sweep across both SVE integer compare-with-immediate envelopes; version
  11.12 adds the EVEX opcode-`71`/`73` immediate-shift-group suite and an
  exhaustive 131,072-word SVE floating compare-with-zero classifier sweep;
  11.13 adds the AVX512VBMI2 map-2/map-3 double-shift suite and an exhaustive
  4,194,304-word SVE floating vector-compare classifier sweep.
Version 11.14 adds the COMPRESS/EXPAND, BITALG/VPOPCNT, and destructive
predicated FP-binary suites; 11.15 adds the AVX-512CD unary and SVE FP fast-
reduction suites; 11.16 adds the AVX-512CD mask-broadcast and exhaustive
`FADDA` suites. Version 11.17 adds
`cdisasm_x86_evex_avx512vnni_tests` and
`cdisasm_arm_sve_predicated_fp_unary_tests`; the latter exhausts every one of
the 655,360 words owned by its four exact masks.
Version 11.18 adds `cdisasm_x86_evex_avx512vbmi_tests` and
`cdisasm_arm_sve_fp_estimate_tests`. The x86 suite enumerates all W, vector
length, register/memory, broadcast, mask, and zeroing controls for the four
rows and distinguishes 405 implemented byte forms, 270 allocated word
siblings, and 1,373 reserved cells. The ARM suite exhausts all 8,192 words in
its exact mask.
Version 11.19 extends the x86 suite so all 675 allocated byte and word forms in
that 2,048-cell lattice decode and all 1,373 reserved cells remain invalid. It
also adds `cdisasm_arm_advsimd_fp_estimate_tests`, which exhausts the exact
18,432-word fixed-width union and distinguishes 16,384 allocated forms from
2,048 reserved controls.
The version-11.3 x86 vectors were also replayed through an out-of-tree build of
[Intel XED](https://github.com/intelxed/xed) v2026.08.23: all 21 positive
checked-in encodings matched their mnemonics, all 72 register, full-memory, and
legal-broadcast descriptor shapes matched, and all nine malformed, unowned, or
short controls were rejected. Pinned Capstone 6 independently matched the same 21
x86 positives, all 24 allocated ARM vector-permute forms, and rejected all
eight reserved ARM selectors. These tools are validation oracles only; neither
is linked into cdisasm or used to generate its decoder.
For version 11.4, XED and the pinned Capstone build accepted all 60 legal
modular EVEX ADD/SUB shapes, while XED rejected all 11 reserved controls in
the focused suite. Capstone accepted all 20 owned ARM lookup/MOV forms. An
exhaustive adjacent sweep was essential: Capstone decoded 54 of the 124
non-MOV selector-14 controls as other SVE instructions and none of the 128
selector-15 controls. cdisasm therefore leaves the whole selector-14 residual
unowned/unsupported and classifies only the exact selector-15 region as
invalid.
For version 11.5, focused independent-oracle checks cover the two new bounded
classes. Current Intel XED and pinned Capstone each accept all 96 VEX and all
96 EVEX saturating ADD/SUB wire variants, covering 80 distinct operand shapes
plus VEX-prefix and W aliases. XED rejects all 72 focused invalid EVEX words:
48 register/memory EVEX.b controls and eight each for LL=3, U=0, and
zero-without-mask. Capstone rejects 56/72 but accepts the eight LL=3 and eight
zero-without-mask words, so cdisasm follows the architectural/XED boundary. Pinned
Capstone accepts all 16 unique checked-in `TBLQ` reference shapes, and LLVM 21
reproduces the exact B/H/S/D bytes. The dedicated cdisasm ARM suite
independently exhausts all 131,072 valid `TBLQ` words and keeps adjacent
allocated instruction classes outside this exact mask unowned. These focused
tranche checks are supplemented by the completed final 11.5 validation matrix.
The full strict top-level CTest passed 43/43. Final Clang 21.1.6 strict fast
matrices passed 39/39 with extra opcodes and formatting enabled, 33/33 with
extra opcodes disabled, and 37/37 with formatting disabled and extra opcodes
enabled; the MSVC 19.44 Release shared matrix passed 39/39. The installed-package
matrix passed all 16 shared cells in 1730.31 seconds and all 16 static cells in
1889.55 seconds. Windows overlay integration passed in 106.92 seconds, and the
WSL Unix `DESTDIR` overlay passed in 73.19 seconds. Refreshed WSL2 Clang 14
ASan+UBSan libFuzzer runs completed 10,000 executions for each x86 and ARM
harness with extra opcodes enabled and 5,000 each with them disabled.

For version 11.6, independent x86 enumeration extends beyond a few examples.
Current XED and pinned Capstone each accept all 648 classic logical wire forms
and all 216 classic `VPAVGB/W` wire forms. XED rejects all 80 logical and all
20 average negative controls; Capstone rejects 48/80 and 12/20 respectively,
accepting the LL=3 and zero-without-mask controls that cdisasm rejects at the
architectural/XED boundary. XED's Diamond Rapids model accepts both checked
APX P0.B4 controls in each class (2/2 logical and 2/2 average); the pinned
Capstone snapshot accepts 0/2 in each because it does not implement those APX
forms. For ARM, pinned Capstone matches all 74 valid destructive-predicated SVE
operation/width pairs and rejects all 54 reserved pairs. It also matches exact
text for all 42 allocated fixed-width Advanced SIMD permutation arrangements
and rejects all 22 reserved controls.

The completed version-11.6 build matrix is similarly explicit. A fresh Clang
21.1.6 dual-architecture Release build with strict warnings, formatting, and
extra opcodes passed all 45/45 CTests, including the two integration tests; the
ARM-only strict build passed 18/18. Semantic matrices passed 37/37 with extra
opcodes disabled and 41/41 with formatting disabled. An MSVC 19.44 Release
shared build passed 43/43 semantic tests. The installed static package's
external C and C++17 consumer passed 8/8, and Windows package-overlay
integration completed successfully in 124.51 seconds. WSL2 Clang 14
ASan+UBSan libFuzzer campaigns passed 10,000 executions for x86 with extra
opcodes ON and 10,000 OFF, plus 10,000 for ARM ON and 5,000 OFF. Replays then
covered all 797/724 mutated x86 and 321/255 ARM build-local corpus files.

For version 11.7, Intel XED and pinned Capstone accept all 546/546 canonical
VEX/EVEX variable-shift encodings. XED rejects all 192/192 focused reserved
controls, while Capstone rejects 120/192; cdisasm follows the architectural/XED
legality boundary. XED's Diamond Rapids model additionally accepts all 162/162
enumerated APX P0.B4 forms and all 216/216 U0 memory forms. On ARM, pinned
Capstone accepts all 56/56 merge-predicated unary operation/width controls and
rejects all 24/24 reserved controls. LLVM 21 accepts all 56/56 corresponding
zero-predicated controls, rejects all 24/24 reserved controls, and confirms the
feature boundary: `/m` admits either SVE or SME, while `/z` requires SVE2p2 or
SME2p2. These are bounded family-oracle results, not claims of complete x86 or
ARM coverage.

The completed version-11.7 native matrix passed all 47/47 non-package CTests
in a fresh Clang 21.1.6 static dual-architecture build with extra opcodes and
formatting enabled: 45 semantic tests plus the 21.08-second subproject and
107.11-second overlay integrations, 132.79 seconds total. The matching static
dual extras-OFF build passed 39/39 semantic tests and its previously completed
full run passed 41/41 including integrations; the format-OFF, extras-ON build
passed 43/43 semantic tests and its previously completed full run passed 45/45
including integrations. An MSVC 19.44.35224 shared Release build passed 45/45
semantic tests. The installed-package matrix passed all 16 shared cells in
1764.07 seconds and all 16 static cells in 1897.99 seconds.

Final WSL2 Clang 14 ASan+UBSan libFuzzer campaigns with extra opcodes ON ran
10,000 executions for x86 (`avg 277/s`, `new 781`, `RSS 112 MB`) and 10,000
for ARM (`avg 555/s`, `new 410`, `RSS 64 MB`). With extra opcodes OFF they ran
10,000 for x86 (`avg 384/s`, `new 726`, `RSS 103 MB`) and 10,000 for ARM
(`avg 666/s`, `new 328`, `RSS 58 MB`). Saved regression inputs replayed and
clean reruns passed. The source seed inventories remained unchanged at 115 x86
and 80 ARM files.

For version 11.8, current Intel XED and pinned Capstone each accept all 162/162
canonical EVEX word variable-shift encodings. XED rejects all 513/513 focused
reserved controls; Capstone rejects 405/513 and permissively accepts 108
`LL=3` or zero-with-`k0` controls, so cdisasm follows the architectural/XED
boundary. XED's Diamond Rapids model accepts all 108/108 enumerated APX P0.B4
and U0/X4 forms, while the pinned Capstone snapshot accepts 0/108. On ARM,
pinned Capstone 6 matches all 33 canonical allocated vector-shift controls and
rejects all 31 canonical reserved controls. Capstone 5 exhaustively agrees on
all 270,336 allocated and 253,952 reserved words, and LLVM 14/21 feature probes
confirm the exact SVE-or-SME admission paths.

Final version-11.8 build evidence includes focused extra-opcode ON, OFF, and
formatter-disabled suites. A fresh Clang 21.1.6 Release package build passed
47/47 direct tests and all 2/2 subproject/overlay integrations; an MSVC
19.44.35224 x64 shared Release build passed 47/47 direct tests. The installed
shared package passed all 16/16 feature-matrix cells in 1693.90 seconds, and the
installed static package passed all 16/16 cells in 1832.75 seconds. ARM
ASan+UBSan libFuzzer campaigns ran 10,000 executions with extra opcodes ON and
5,000 with them OFF. Fresh WSL Clang 14 ASan+UBSan x86 builds each stage
exactly 137 reviewed seeds (maximum 189 raw bytes). All
21 word-shift files plus the crypto seed replay 22/22 with extras ON and OFF;
recommended `-max_len=192` campaigns pass 10,000 executions in 32 and 28
seconds respectively. Their initial corpora retain 135/128 entries, confirming
that the older long hexadecimal seeds are normalized and reachable. The source
corpus contains no generated non-`.hex` artifact. These results complete the
stable-tree 11.8 package and focused validation evidence; they do not claim
exhaustive x86 or ARM ISA coverage.

Version-11.9 focused oracle enumeration covers the new bounded classes. Intel
XED and pinned Capstone each accept all 324/324 canonical EVEX variable-rotate
forms. XED rejects all 432/432 reserved controls; Capstone rejects 216/432 and
accepts the other 216 permissively, split exactly between 108 `LL=3` and 108
zero-with-`k0` controls. XED's Diamond Rapids model accepts all 396/396 APX
forms (108 P0.B4/U1, 144 U0 no-SIB, and 144 U0/X4 SIB forms), while pinned
Capstone accepts 0/396. On ARM, Capstone 5 exhaustively agrees on all 524,288
words in the immediate-shift classifier (276,480 allocated and 247,808
reserved) and matches 1,080/1,080 canonical metadata probes. LLVM 21 accepts
the four baseline operations through an SVE-only route, all nine operations
through SVE2 or SME, accepts none without the required feature, and rejects all
23/23 canonical reserved controls.

The version-11.9 native release checks passed 49/49 direct semantic CTests with extra
opcodes and formatting enabled, 43/43 with extra opcodes disabled, and 47/47
with formatting disabled. Including the two subproject/overlay integrations in
each configuration gives 51/51, 45/45, and 49/49 non-package CTests. MSVC
19.44.35224 x64 shared Release passes the same 49 semantic tests plus both
integrations. Installed-package validation passes all 16/16 shared cells in
1,640.30 seconds and all 16/16 static cells in 1,777.09 seconds. Fresh WSL2
Clang 14 ASan+UBSan libFuzzer runs complete 10,000 executions for each x86 and
ARM harness in both extra-opcode variants, using unchanged inventories of 144
x86 and 84 ARM seeds, with no sanitizer, leak, timeout, assertion, or crash
finding.

Version-11.10 focused oracle enumeration covers both new bounded classes.
Intel XED v2026.08.23 accepts all 324/324 canonical immediate packed-rotate
controls, rejects all 432/432 reserved EVEX controls, and accepts all 396/396
enumerated APX forms with its Diamond Rapids model. Pinned Capstone accepts the
canonical 324/324 controls and all 82,944 imm8 wire values, accepts none of the
APX forms, and permissively accepts the 108 `LL=3` and 108 zero-with-`k0`
controls that cdisasm rejects at the architectural/XED boundary. XED also
confirms the exact neighboring opcode-`72` extension/W split: `/2` W0, `/4`
W0/W1, and `/6` W0 are allocated shift instructions outside this tranche;
`/2` W1, `/6` W1, and `/3`, `/5`, `/7` are reserved.

On ARM, pinned Capstone matches all 64 operation/width controls in the exact
SVE integer vector-compare classifier: 54 allocated and 10 reserved. It marks
all 54 allocated controls as updating flags. Clang 21 accepts representative
ordinary and wide-source forms with either SVE or SME. The focused suite
exhausts all 8,388,608 words. These results prove the stated classifiers, not
complete x86 or Arm ISA coverage.

Version-11.11 focused oracle enumeration covers both added bounded classes.
Intel XED v2026.08.23 (`0bcb6237345c5066726dcc08b3d87928df3b5b26`)
and pinned Capstone 6.0.0 (`862b59717d54769036f89fd9f780f634e030cf56`)
accept all 324/324 canonical EVEX immediate packed-shift controls and all
82,944 imm8 wire values. XED rejects all 432/432 focused structural-invalid
controls; Capstone rejects 216/432 but permissively accepts 108 `LL=3` and 108
zero-with-`k0` controls. XED's Diamond Rapids model accepts all 396/396 APX
P0.B4/U0/X4 forms, while Capstone accepts 0/396. The resulting full opcode-`72`
matrix is allocated only at W0 `/0`, `/1`, `/2`, `/4`, `/6` and W1 `/0`,
`/1`, `/4`; all neighboring extension/W combinations remain reserved.

For A64, pinned Capstone matches all 2,816 legal
operation/width/immediate combinations: 768 signed combinations spanning
six operations, four widths, and `#-16`--`#15`, plus 2,048 unsigned
combinations spanning four operations, four widths, and `#0`--`#127`.
Clang 21.1.6 accepts the forms under either `+sve` or `+sme`, rejects them
with neither feature, and confirms the exact immediate and `Pg` ranges. The
focused cdisasm suite sweeps all 12,582,912 owned words: 11,534,336 allocated
and 1,048,576 reserved. These are bounded oracle results, not claims of
complete x86 or Arm ISA coverage.

Version-11.10 native release validation passes 51/51 direct semantic CTests
with extra opcodes and formatting enabled, 45/45 with extra opcodes disabled,
and 49/49 with formatting disabled. Including the two subproject/overlay
integrations gives 53/53, 47/47, and 51/51. A fresh Clang 21.1.6 shared Release
build with `-Wall -Wextra -Wpedantic -Werror` and a fresh MSVC 19.44.35224 x64
shared Release build with `/W4` each pass 53/53. Installed-package validation
passes all 16/16 shared cells in 1,669.23 seconds and all 16/16 static cells in
1,812.81 seconds. WSL2 Clang 14 ASan+UBSan libFuzzer campaigns complete 10,000
executions for each x86 and ARM harness in both extra-opcode variants, staging
151 reviewed x86 seeds or 86 reviewed ARM seeds, with no sanitizer, leak,
timeout, assertion, or crash finding.

Version-11.11 native release validation passes 53/53 direct semantic CTests
with extra opcodes and formatting enabled, 47/47 with extra opcodes disabled,
and 51/51 with formatting disabled. Including the two subproject/overlay
integrations gives 55/55, 49/49, and 53/53. Fresh Clang 21.1.6 shared Release
with `-Wall -Wextra -Wpedantic -Werror` and MSVC 19.44.35224 x64 shared Release
with `/W4` each pass 55/55. Including the two installed-package tests, the
three top-level configurations pass 57/57, 51/51, and 55/55. Every package
test passes all 16 shared or 16 static architecture/formatter/extra-opcode
cells, including build-tree and relocated C/C++ consumers. WSL2 Clang 14
ASan+UBSan libFuzzer campaigns complete 10,000 executions for x86 extras ON,
x86 extras OFF, ARM extras ON, and ARM extras OFF from 157 reviewed x86 or 89
reviewed ARM source seeds, with no sanitizer, leak, timeout, assertion, or
crash finding.

Version-11.12 final validation passes 58/58 with extra opcodes enabled and
52/52 with them disabled under both MSVC and strict Clang; the totals include
the new readable-seed grammar/size audit and both CMake integration tests.
Independent Intel XED comparison has zero mismatches across the 32 new
opcode/W/extension controls and 13 APX P0.B4/U0/X4 routes. Pinned Capstone
matches all 18 legal A64 floating compare-with-zero operation/width controls
and rejects all 14 sampled reserved controls. WSL2 Clang 14 ASan+UBSan
libFuzzer campaigns complete 10,000 executions for x86 and ARM with extras ON
and OFF, using the full 192-byte x86 text cap and a freshly staged 91-seed ARM
corpus whose maximum is 24 bytes, with no finding. Installed-package tests pass
all 16/16 shared Release cells in 3,744.55 seconds and all 16/16 static cells
in 4,102.86 seconds, covering dual/x86/ARM/common-only packages, formatter and
extra-opcode toggles, relocation, C/C++ consumers, components, symbols, and
static embedding.

Version-11.13 focused x86 checks pass with extra opcodes enabled, formatting
disabled, and extra opcodes disabled. The suite locks all 16 exact
map/opcode/W controls, every immediate value, masks, memory/broadcast/disp8,
feature alternatives, APX routes, formatting, and truncation; the 1,185-row
corpus and seed audit pass, and all six new seeds replay under libFuzzer. A
final audit adds eight status-precedence regressions for mandatory-`66` EVEX
maps 2/3 opcodes `70`--`73`: forbidden legacy prefixes and non-long-mode APX
P0.B4 defer legality until the owned ModRM/SIB/displacement and applicable
imm8 bytes are consumed. Incomplete forms return `TRUNCATED`; complete forms
return `INVALID_INSTRUCTION`. These checks pass with extras ON, extras OFF,
formatting disabled, and MSVC. The legacy-prefix pairs agree with XED; no XED
parity is claimed for 32-bit B4 because XED rejects at the EVEX prefix. ARM
release validation is complete: strict focused selections pass 20/20 with
extras enabled and 20/20 disabled, the suite locks all 4,194,304 words and
their 2,752,512/1,441,792 split, and 36/36 canonical controls match pinned
Capstone. The strict Clang full CTest matrices now pass 60/60 with extras and
formatting enabled, 54/54 with extras disabled and formatting enabled, and
58/58 with extras enabled and formatting disabled. The native MSVC shared direct
functional/data selection passes 58/58. Intel XED v2026.08.23 reports zero
mismatches across 452/452 oracle cases: 412 complete inputs (300 accepted and
112 rejected) plus 40 truncation inputs. All four fresh WSL Clang 14
ASan+UBSan libFuzzer campaigns (x86/ARM × extras ON/OFF) complete 10,000 runs
each without a finding. The Clang 21.1.6 installed-package end-to-end matrices
pass all 16 shared Release cells in 3,586.82 seconds and all 16 static Debug
cells in 4,008.22 seconds, with zero failures in either matrix. Both cover
dual/x86/ARM/common-only × formatter ON/OFF × extras ON/OFF, including
build-tree and relocated C/C++ consumers plus component, symbol, and artifact
checks. Shared nested producers used the project's built-in
`-Wall -Wextra -Wpedantic` without a global `-Werror`; every static nested
producer cache contains `-Wall -Wextra -Wpedantic -Werror`. Shared and static
x86/formatter-ON/extras-ON producers were rebuilt and reinstalled into their
relocated prefixes; relinked build-tree and relocated consumers pass 7/7 in
each of the four suites. This targeted confirmation does not change the 16/16
matrix totals.

Version-11.14 strict Clang dual-architecture direct suites pass 62/62 with
extras and formatting enabled, 57/57 with extras disabled, and 60/60 with
formatting disabled. A Windows ABI-style Clang-CL `/W4 /WX` shared build also
passes 62/62. The opcode corpora pass all 1,221 x86 and 687 ARM rows in both
extra-opcode variants. Intel XED validates the bounded COMPRESS/EXPAND and
BITALG/VPOPCNT matrix, while pinned Capstone matches 42/42 selected ARM
controls. Four fresh WSL2 Clang 14 ASan+UBSan libFuzzer campaigns complete
10,000 executions each for x86/ARM × extras ON/OFF after replaying all 183 x86
and 100 ARM reviewed seeds, with no finding. Targeted installed shared/static,
dispatcher, and ARM-only consumers pass with the applicable option variants.

Version-11.15 strict Clang dual-architecture direct suites pass 64/64 with
extras and formatting enabled, 59/59 with extras disabled, and 62/62 with
formatting disabled. A Clang-CL `/W4 /WX` shared build passes 64/64. The
1,245-row x86 and 701-row ARM corpora pass in their applicable option variants,
and all 189 x86 and 102 ARM source seeds pass the deterministic audit. Intel XED
agrees with the focused AVX-512CD matrix on 140 accepted and 39 rejected inputs;
pinned Capstone agrees with all 262,144 ARM fast-reduction classifier outcomes,
and LLVM agrees with the canonical controls. Four fresh WSL2 Clang 14
ASan+UBSan campaigns complete 10,000 executions each for x86/ARM x extras
ON/OFF with no sanitizer finding. Targeted shared and static package consumers
also pass. These bounded checks do not imply exhaustive ISA coverage.

Version-11.16 strict Clang dual-architecture direct suites pass 65/65 with
extras and formatting enabled, 60/60 with extras disabled, and 63/63 with
formatting disabled. A Clang-CL `/W4 /WX` shared build passes 65/65. Both the
extras-ON and extras-OFF corpus runners pass all 1,266 x86 and 711 ARM rows,
and the source audit accepts exactly 191 x86 and 104 ARM seeds. Intel XED
agrees with 30/30 selected mask-broadcast controls; pinned Capstone agrees with
all 32,768 `FADDA` words and LLVM agrees with canonical H/S/D boundaries.
Four WSL2 Clang 14 ASan+UBSan campaigns complete 10,000 executions each for
x86/ARM x extras ON/OFF without a finding or artifact. Dual shared and static
package consumers pass 8/8 from both build-tree and relocated installations.
These remain bounded checks, not exhaustive ISA coverage.

Version-11.17 strict Clang dual-architecture direct suites pass 67/67 with
extras and formatting enabled, 62/62 with extras disabled, and 65/65 with
formatting disabled. A Clang-CL `/W4 /WX` shared build passes 67/67. Both
extra-opcode variants pass all 1,289 x86 and 736 ARM corpus rows, and the
deterministic source audit accepts exactly 197 x86 and 110 ARM seeds. Intel XED
validates the exact AVX-512 VNNI row and LLVM validates the canonical ARM
merging/zeroing controls derived from Arm's ISA XML. Four WSL2 Clang 14
ASan+UBSan campaigns complete 10,000 executions each for x86/ARM x extras
ON/OFF without a finding. Installed-package validation passes all 16 shared
Release cells in 3,754.29 seconds and all 16 static Release cells in 4,042.27
seconds. Both matrices cover dual/x86/ARM/common-only x formatter ON/OFF x
extras ON/OFF, exercise build-tree and relocated C/C++ consumers, and check the
new public IDs and both formatter paths. These are exact bounded-family checks
and do not imply complete x86 or ARM coverage.

Version-11.18 strict Clang dual-architecture matrices pass 71/71 tests with
extras and formatting enabled, 66/66 with extras disabled, and 69/69 with
formatting disabled. Their direct semantic subsets pass 69/69, 64/64, and
67/67; a Clang-CL `/W4 /WX` build passes all 69 direct tests. Both option
variants pass the complete 1,314-row x86 and 751-row ARM corpora, and the
source audit accepts exactly 214 x86 and 118 ARM seeds with no non-`.hex`
artifacts. Intel XED supplies the exact VBMI descriptor/APX boundaries, and
Arm's official 2025-12 XML supplies the SVE/SME estimate mask. Four fresh WSL2
Clang 14 ASan+UBSan campaigns complete 10,000 executions each for x86/ARM x
extras ON/OFF, starting from exactly 214/118 reviewed seeds, without a finding.
Installed-package validation passes all 16 shared Release cells in 3,849.50
seconds and all 16 static Release cells in 4,206.13 seconds; both matrices cover
dual/x86/ARM/common-only x formatter ON/OFF x extras ON/OFF with build-tree and
relocated C/C++ consumers. This evidence remains bounded and does not imply
exhaustive x86 or Arm coverage.

For version 11.19, strict Clang 21.1.6 dual-architecture configurations pass
72/72 tests with extra opcodes and formatting enabled, 67/67 with extra opcodes
disabled, and 70/70 with formatting disabled. The corresponding direct-test
counts, excluding the two nested CMake package integrations, are 70/70, 65/65,
and 68/68. Clang-CL also builds every enabled target under `/W4 /WX` and passes
70/70 direct tests. Four WSL2 Clang 14 ASan+UBSan libFuzzer campaigns complete
10,000 executions each for x86 and ARM with extra opcodes enabled and disabled,
without a finding. Installed-package validation passes all 16 shared Release
cells in 3,722.89 seconds and all 16 static Release cells in 4,080.82 seconds.
Both matrices cover dual/x86/ARM/common-only builds, formatter ON/OFF, extra
opcodes ON/OFF, build-tree consumers, relocated C/C++ consumers, components,
symbols, and artifacts. The checked-in corpus and seed audits pass the exact
1,327/779-row and 215/136-seed inventories.

Version 11.20 expands the checked-in inventories to 1,337 x86 rows, 791 ARM
rows, 221 x86 seeds, and 144 ARM seeds. Dedicated focused suites cover the
classic VEX AVX-VNNI four-opcode row and the 262,144-word F64MM Q-element
permute envelope, including CPU/runtime/build isolation, reserved neighbors,
formatter metadata, endian parity for ARM, and zeroed failure results. Strict
Clang 21.1.6 dual-architecture configurations pass 74/74 tests with extra
opcodes and formatting enabled, 69/69 with extra opcodes disabled, and 72/72
with formatting disabled. Their direct subsets, excluding the two nested CMake
integrations, pass 72/72, 67/67, and 70/70. Clang-CL builds every enabled target
under `/W4 /WX` and passes all 74 non-package tests. Four WSL2 Clang 14
ASan+UBSan libFuzzer campaigns complete 10,000 executions each for x86 and ARM
with extra opcodes enabled and disabled, without a finding. Installed-package
validation passes all 16 shared Release cells in 4,412.08 seconds and all 16
static Release cells in 4,560.61 seconds. Both matrices cover dual/x86/ARM/
common-only builds, formatter ON/OFF, extras ON/OFF, build-tree and relocated
C/C++ consumers, component discovery, symbol auditing, and artifact layout.

Version 11.21 expands the checked-in inventories to 1,349 x86 rows, 808 ARM
rows, 230 x86 seeds, and 152 ARM seeds. Its focused source suites exhaust the
3,072 allocated/3,072 reserved classic VEX AVX-VNNI-INT8 controls and the
49,152 allocated/16,384 reserved SVE/SME integer-to-FP16 words.
The x86 tranche contributes 13 rows while retiring one now-obsolete classic
pp-neighbor row, for a net increase of 12; the ARM tranche contributes 17 rows.
Strict Clang 21.1.6 Ninja dual-architecture configurations built with
`-Wall -Wextra -Wpedantic -Werror`, with installed-package tests excluded,
pass 76/76 tests with extras and formatting enabled in 227.54 seconds, 71/71
with extras disabled and formatting enabled in 223.05 seconds, and 74/74 with
extras enabled and formatting disabled in 411.20 seconds. Their direct subsets,
excluding the two nested CMake
integrations, pass 74/74, 69/69, and 72/72. Clang-CL 21.1.6 configuration under
`/W4 /WX` succeeds, all 162 targets build, and 76/76 non-package tests pass in
228.10 seconds. The six strict fuzz translation-unit checks also pass.
On WSL2, Clang 14 Unix Makefiles ASan+UBSan libFuzzer campaigns complete 10,000
runs each for x86 and ARM with extras enabled and disabled; all four exit zero
with no finding and no crash artifacts. Complete sequential installed-package
matrices pass all 16/16 shared cells in 3,831.53 seconds and all 16/16 static
cells in 3,986.38 seconds. They cover dual/x86/ARM/common-only builds,
formatter ON/OFF, extras ON/OFF, build-tree and relocated C/C++ consumers,
components, symbols, artifacts, and static definitions. This validation remains
bounded and does not claim exhaustive x86 or ARM ISA coverage.

Version 11.22 expands the checked-in inventories to 1,362 x86 rows, 825 ARM
rows, 240 x86 seeds, and 160 ARM seeds. The new focused source suites exhaust
3,072 allocated W=0 plus 3,072 reserved W=1 AVX-VNNI-INT16 controls and all
65,536 allocated signed/unsigned S-to-S, D-to-S, S-to-D, and D-to-D SVE/SME
conversion words. The x86 tranche contributes 13 rows and ten seeds; the ARM
tranche contributes 17 rows and eight seeds. Descriptor, CPU/runtime/build,
formatting, endian, truncation, neighbor, and extras-OFF checks cover these
bounded slices. Final strict Clang 21.1.6 dual-architecture validation passes
78/78 tests with extras and formatting enabled, 73/73 with extras disabled,
and 76/76 with extras enabled and formatting disabled. Clang-CL passes 78/78
under `/W4 /WX`. Four WSL2 Clang 14 ASan+UBSan libFuzzer campaigns for x86 and
ARM with extras enabled and disabled complete 10,000 runs each successfully.
Installed-package matrices pass 16/16 shared cells in 3,696.43 seconds and
16/16 static cells in 4,052.63 seconds. The compiled x86 modern-VEX table audit
reports 149 descriptors and zero lookup-key overlaps; the ARM modern mask audit
reports 94 patterns and zero overlaps. This validation remains bounded and does
not claim exhaustive x86 or ARM ISA coverage.

Version 11.23's checked-in inventories contained 1,377 x86 rows, 869 ARM
rows, 250 x86 seeds, and 186 ARM seeds. The new 4VNNIW focused material adds 15
x86 rows and ten one-vector seeds; its suite exhausts both opcodes across every
ModRM byte for W=0 and W=1, then separately checks vector length, U/B, masking,
source and destination extension, Tuple1_4X displacement scaling, CPU/runtime
admission, formatting, truncation, and extras-OFF ownership against Intel XED.
The new baseline ARM conversion focused material adds 31 rows and 22 seeds; its
suite exhausts all 204,800 owned words (163,840 allocated and 40,960 reserved),
plus BFCVT adjacency, CPU/build gates, endian parity, metadata, formatting, and
truncation. The current ARM total also contains other checked-in row/seed deltas,
so it must not be reconstructed by adding only that focused increment to the
documented 11.22 inventory. The full expanded EVEX descriptor audit reports 227
descriptors with zero lookup-key intersections, and the ARM modern-pattern
audit reports 101 patterns with zero mask overlaps. Final strict Clang 21.1.6
dual-architecture validation passes 80/80 tests with extras and formatting
enabled in 235.68 seconds, 75/75 with extras disabled in 233.31 seconds, and
78/78 with extras enabled and formatting disabled in 231.63 seconds. Clang-CL
21 passes 80/80 under `/W4 /WX` in 241.70 seconds. The four WSL2 Clang 14
ASan+UBSan x86/ARM by extras ON/OFF configurations each complete two fixed-seed
10,000-run libFuzzer passes: 80,000 total executions with no sanitizer finding
or crash artifact. Installed-package matrices pass 16/16 shared cells in
3,589.77 seconds and 16/16 static cells in 3,936.32 seconds. This validation
remains bounded and does not claim exhaustive x86 or ARM ISA coverage.

Version 11.24's checked-in inventories contained 1,400 x86 rows, 880 ARM rows,
266 x86 seeds, and 190 ARM seeds. The focused AVX512_4FMAPS suite
exhausts 8,192 controls: 1,536 allocated forms and 6,656 rejected controls,
including packed/scalar length policy, memory-only ModRM ownership, W/U/B,
masking, Tuple1_4X displacement scaling, source-group boundaries, exact Knights
Mill CPU/runtime admission, formatting, truncation, and extras-OFF ownership.
The focused ARM suite exhausts all 8,192 words in the exact merging `BFCVT`
class and all 32,768 words in its four-selector envelope; the existing baseline
`FCVT` sweep remains a separate 65,536-word check. Expanded audits report 231
EVEX descriptors and 102 ARM modern patterns with zero lookup-key or mask
intersections.

Final version-11.24 strict Clang 21.1.6 dual-architecture matrices pass 82/82
with extras and formatting enabled, 77/77 with extras disabled, and 80/80 with
formatting disabled; their overlay integration cells take 222.07, 222.04, and
222.01 seconds respectively. A fresh Clang-CL 21.1.6 x86-64 Release shared
build under `/W4 /WX` configures in 29.526 seconds, builds all 174 steps with
zero warnings in 196.306 seconds, and passes 82/82 CTests in 192.59 seconds,
including the 192.43-second overlay. Its 251,392-byte `cdisasm-11.dll` and
4,936-byte import library expose the required symbols and image version 11.24.
Fresh strict Clang shared and static installed-package matrices each pass all
16 feature cells: shared configures in 23.462 seconds, builds 170/170 in 205.562
seconds, and passes in 3,576.25 seconds (3,576.569 measured); static configures
in 21.80 seconds, builds 174/174 in 195.74 seconds, and passes in 3,922.01
seconds (3,922.36 measured). Fresh WSL Ubuntu Clang 14 ASan+UBSan/libFuzzer
campaigns replay every 266/190 reviewed x86/ARM seed in both extras variants,
then complete 25,000 units per x86/ARM-by-extras campaign: 100,000 total units,
99,084 generated after initialization, and zero sanitizer, runtime, invariant,
crash, timeout, OOM, or leak findings. The original REX2 RDSEED reproducer now
exits successfully and remains a permanent seed. These results remain bounded
and do not claim exhaustive x86 or ARM ISA coverage; the version-11.23 matrices
above remain historical evidence for that release.

Version 11.25's checked-in inventories contain 1,430 x86 rows, 889 ARM rows,
274 x86 seeds, and 193 ARM seeds. The focused VGETEXP suite exhausts an
8,192-cell structural lattice as 5,248 valid and 2,944 invalid controls, plus
mask and 32-value `vvvv`/extension sweeps. Its checked-in coverage contains 29
VGETEXP TSV cases and eight named seeds; the thirtieth new x86 row locks an
address-prefixed VEX3 regression. Focused x86 extras-ON, extras-OFF, and
formatter-OFF configurations each pass their three VGETEXP/corpus/seed-audit
tests; the ON x86 label passes 40/40, and all three corpus runners pass
1,430/1,430 rows. The expanded EVEX audit covers 235 descriptors with zero
lookup-key overlaps. The focused ARM BFCVT/BFCVTNT suite
checks 73,728 words: the retained 32,768-control envelope plus 24,576 newly
allocated and 16,384 newly reserved words. Fresh ARM-only strict Clang 21.1.6
extras-ON, extras-OFF, and formatter-OFF configurations each pass the four
modern/FCVT/BFCVT/corpus tests; the ARM modern mask audit covers 107 patterns
with zero overlaps. Corpus and seed audits confirm the inventories above.

Final version-11.25 release validation passes the full strict Clang 21.1.6
CTest variants 83/83 with extras and formatting enabled, 78/78 with extras
disabled, and 81/81 with formatting disabled. A fresh Clang-CL 21.1.6 build
with `/W4 /WX` completes all 176/176 steps and passes 83/83 CTests; its PE image
reports version 11.25 and exports the expected 16 public symbols. Four primary
WSL Clang 14 ASan+UBSan libFuzzer campaigns--x86 and ARM with extras ON and
OFF--replay the 274 x86 or 193 ARM reviewed seeds at initialization and each
complete 25,000 units, for 100,000 total, with zero findings. The shared
installed-package matrix passes all 16/16 cells, 32 consumer suites, and 204
nested runtime tests in 3,522.48 seconds. The static installed-package matrix
passes all 16/16 cells in 3,865.85 seconds, with zero failures. These are
bounded tranche and release-matrix results, not an exhaustive x86 or ARM ISA
claim.

Version 11.26's checked-in inventories contain 1,459 x86 rows, 909 ARM rows,
282 x86 seeds, and 200 ARM seeds. The release appends x86 IDs 1126--1128 for
the exact MAP6 PH/SH/BF16 GETEXP forms and ARM ID 438 for the exact pair
`BFCVTN` forms while reusing `BFCVT` (436). Its focused x86 suite enumerates a
12,288-cell W/LL/b/ModRM lattice, with 3,968 allocated and 8,320 reserved
controls, plus prefix, U, mask, `vvvv`, register-extension, mode, CPU/runtime,
formatting, truncation, and extras-OFF boundaries. The focused ARM suite
enumerates 18,432 words: the 16,384-word SME2 conversion selector domain and
the 2,048-word SVE2/SME2 FP8 narrowing domain. It distinguishes the four
implemented 512-word pair forms from 8,704 allocated but unsupported siblings
and 7,680 reserved SME2 controls, exercises endian/generic dispatch and exact
canonical text, and verifies that no pair form is named `BFCVTNT`. These are scoped
family inventories and test domains; they do not claim exhaustive x86 or ARM
ISA coverage or, by themselves, a completed release-wide validation matrix.

Final version-11.26 release validation passes the strict Clang 21.1.6 CTest
variants 85/85 with extras and formatting enabled, 80/80 with extras disabled,
and 83/83 with formatting disabled. A post-fix Clang-CL 21.1.6 `/W4 /WX`
rebuild is warning-free and passes 83/83 non-integration CTests. The 238-entry
x86 EVEX descriptor audit and 111-entry ARM modern-pattern audit report zero
overlaps. Four post-decoder-fix WSL Clang 14 ASan+UBSan libFuzzer campaigns
complete 25,000 units each, for 100,000 total, with zero findings. After the
x86 harness was corrected to choose named-profile modes through
`cdisasm_x86_cpu_mode_mask`, its extras-ON and extras-OFF campaigns complete an
additional 25,000 units each with no finding and empty artifact directories.
The binary audit confirms 16 public exports with formatting enabled, 12 with
formatting disabled, runtime version 11.26.0, and fixed x86/ARM result sizes of
248/168 bytes. Installed-package validation passes all 16 shared cells in
3,608.51 seconds and all 16 static cells in 3,964.57 seconds; their 408 nested
runtime tests (256 C and 152 C++17) all pass. These remain bounded release and
family results, not an exhaustive x86 or ARM ISA-coverage claim.

The K-mask suite covers
every public mnemonic, all 65 descriptor forms,
mode and width aliases, operand access/size metadata, Intel and AT&T output,
AVX-512/AVX10 CPU/runtime cross-gates, malformed controls, truncation, and the
extra-opcodes-OFF structural contract. The compare suite covers all eight
mnemonics at all three vector lengths, full-width and broadcast memory,
extended sources, 32-bit mode, K masking/access widths, Intel/AT&T text,
AVX-512/AVX10 alternate routes, reserved fields, and truncation. The ARM SVE
suite covers all 15 operations, formatter metadata, endian parity, CPU/mode
gates, reserved selection, truncation, and the same ON/OFF contract.

| Dimension | Values exercised | What is checked |
| --- | --- | --- |
| Architecture selection | dual, x86-only, ARM-only, common-only | Exact headers, exports, components, compatibility proxies, and generic dispatch behavior |
| Library form | shared and static | Runtime/import artifacts, static-definition propagation, and static embedding visibility |
| Formatter | requested ON and OFF | Effective availability, declarations, symbols, formatter behavior, and forged-result rejection |
| Extra opcodes | requested ON and OFF | Successful optional semantics versus zeroed unsupported results, with reserved and truncated forms kept distinct |
| Consumption | build tree and relocated install | C and C++17 consumers, component acceptance/rejection, linkage, and install fingerprinting |

The default shared-build files are in `build/Release/`:

- `cdisasm-12.dll` and `cdisasm.lib` — common services, generic dispatch, every
  enabled explicit architecture API, and the enabled x86 Intel/AT&T and/or
  canonical ARM formatter
- `cdisasm_cli.exe` and `cdisasm_arm_cli.exe` — x86 and ARM text examples,
  present for enabled architectures only when `USE_DISASM_FORMAT=ON`
- `cdisasm_common_tests.exe`, `cdisasm_decode_tests.exe`, `cdisasm_tests.exe`,
  `cdisasm_extra_opcode_contract_tests.exe`,
  `cdisasm_x86_flag_tests.exe`,
  `cdisasm_x86_modern_tests.exe`, `cdisasm_x86_cet_tests.exe`,
  `cdisasm_x86_waitpkg_tests.exe`, `cdisasm_x86_system_modern_tests.exe`,
  `cdisasm_x86_evex_fma_tests.exe`,
  `cdisasm_x86_expansion_tests.exe`,
  `cdisasm_x86_amd_expansion_tests.exe`,
  `cdisasm_x86_xop_map9_tests.exe`,
  `cdisasm_x86_xop_remaining_tests.exe`,
  `cdisasm_x86_crypto_modern_tests.exe`,
  `cdisasm_x86_avx_core_tests.exe`, `cdisasm_x86_avx_vnni_tests.exe`,
  `cdisasm_x86_avx_vnni_int8_tests.exe`,
  `cdisasm_x86_avx_vnni_int16_tests.exe`, `cdisasm_x86_kmask_tests.exe`,
  `cdisasm_x86_evex_compare_tests.exe`,
  `cdisasm_x86_evex_integer_minmax_tests.exe`,
  `cdisasm_x86_evex_integer_add_sub_tests.exe`,
  `cdisasm_x86_evex_integer_logical_tests.exe`,
  `cdisasm_x86_evex_average_tests.exe`,
  `cdisasm_x86_evex_integer_multiply_tests.exe`,
  `cdisasm_x86_saturating_add_sub_tests.exe`,
  `cdisasm_x86_variable_shift_tests.exe`,
  `cdisasm_x86_variable_word_shift_tests.exe`,
  `cdisasm_x86_variable_rotate_tests.exe`,
  `cdisasm_x86_immediate_rotate_tests.exe`,
  `cdisasm_x86_immediate_shift_tests.exe`,
  `cdisasm_x86_immediate_shift_group_tests.exe`,
  `cdisasm_x86_evex_vbmi2_double_shift_tests.exe`,
  `cdisasm_x86_evex_compress_expand_tests.exe`,
  `cdisasm_x86_vdbpsadbw_tests.exe`,
  `cdisasm_x86_vpternlog_tests.exe`,
  `cdisasm_x86_evex_bitalg_popcount_tests.exe`,
  `cdisasm_x86_evex_avx512cd_tests.exe`,
  `cdisasm_x86_evex_avx512vnni_tests.exe`,
  `cdisasm_x86_evex_avx512vbmi_tests.exe`,
  `cdisasm_x86_expanded_family_flag_tests.exe`,
  `cdisasm_x86_nextgen_tests.exe`, `cdisasm_x86_rao_int_tests.exe`,
  `cdisasm_x86_smap_tests.exe`, `cdisasm_x86_movntdqa_tests.exe`,
  `cdisasm_x86_lddqu_tests.exe`, `cdisasm_x86_vmovmsk_tests.exe`,
  `cdisasm_x86_vmovq_tests.exe`, `cdisasm_x86_vmovrs_tests.exe`,
  `cdisasm_x86_vmovsd_tests.exe`, `cdisasm_x86_vmovss_tests.exe`,
  `cdisasm_x86_vpcmpeqq_tests.exe`, `cdisasm_x86_vblend_tests.exe`,
  `cdisasm_x86_vblendv_tests.exe`, `cdisasm_x86_vbroadcast128_tests.exe`,
  `cdisasm_x86_lane_insert_extract_tests.exe`,
  `cdisasm_x86_vbroadcast_scalar_tests.exe`,
  `cdisasm_x86_vextractps_vinsertps_tests.exe`,
  `cdisasm_x86_vperm2_128_tests.exe`,
  `cdisasm_arm_tests.exe`, `cdisasm_arm_apple_tests.exe`,
  `cdisasm_arm_modern_tests.exe`,
  `cdisasm_arm_length_reverse_reduction_tests.exe`,
  `cdisasm_arm_crc32_tests.exe`,
  `cdisasm_arm_sve_unpredicated_logical_tests.exe`,
  `cdisasm_arm_architectural_hint_tests.exe`,
  `cdisasm_arm_neon_vector_permute_tests.exe`,
  `cdisasm_arm_sve_predicate_logical_tests.exe`,
  `cdisasm_arm_sve_punpk_tests.exe`, `cdisasm_arm_sve_unpack_tests.exe`,
  `cdisasm_arm_sve_shift_insert_tests.exe`,
  `cdisasm_arm_advsimd_bitwise_select_tests.exe`,
  `cdisasm_arm_advsimd_high_narrow_tests.exe`,
  `cdisasm_arm_advsimd_widening_add_sub_tests.exe`,
  `cdisasm_arm_pauth_branch_tests.exe`,
  `cdisasm_arm_sve_bitperm_tests.exe`,
  `cdisasm_arm_sve_integer_arithmetic_tests.exe`,
  `cdisasm_arm_sve_predicated_integer_tests.exe`,
  `cdisasm_arm_sve_vector_permute_tests.exe`,
  `cdisasm_arm_sve_table_lookup_tests.exe`,
  `cdisasm_arm_sve_tblq_tests.exe`,
  `cdisasm_arm_sve_predicated_unary_tests.exe`,
  `cdisasm_arm_sve_predicated_vector_shift_tests.exe`,
  `cdisasm_arm_sve_predicated_immediate_shift_tests.exe`,
  `cdisasm_arm_sve_predicated_shift_sat_round_tests.exe`,
  `cdisasm_arm_sve_integer_compare_tests.exe`,
  `cdisasm_arm_sve_integer_compare_immediate_tests.exe`,
  `cdisasm_arm_sve_floating_compare_zero_tests.exe`,
  `cdisasm_arm_sve_floating_compare_vectors_tests.exe`,
  `cdisasm_arm_sve_predicated_fp_binary_tests.exe`,
  `cdisasm_arm_sve_fp_fast_reduction_tests.exe`,
  `cdisasm_arm_sve_fp_serial_reduction_tests.exe`,
  `cdisasm_arm_sve_predicated_fp_unary_tests.exe`,
  `cdisasm_arm_sve_fp_estimate_tests.exe`,
  `cdisasm_arm_sve_ffr_tests.exe`,
  `cdisasm_arm_sve_saturating_predicate_count_tests.exe`,
  `cdisasm_arm_sve_first_last_tests.exe`,
  `cdisasm_arm_sve_cterm_tests.exe`,
  `cdisasm_arm_sve_while_single_tests.exe`,
  `cdisasm_arm_sve_while_pair_tests.exe`,
  `cdisasm_arm_sve_while_counter_tests.exe`,
  `cdisasm_arm_sve_counter_mask_tests.exe`,
  `cdisasm_arm_sve_whilewr_rw_tests.exe`,
  `cdisasm_arm_f64mm_permute_tests.exe`,
  `cdisasm_arm_sve_int_to_fp16_tests.exe`,
  `cdisasm_arm_sve_int_to_fp_tests.exe`,
  `cdisasm_t32_tests.exe`,
  `cdisasm_arm_opcode_corpus_tests.exe`, `cdisasm_format_tests.exe`,
  `cdisasm_arm_format_tests.exe`,
  `cdisasm_x86_group_tests.exe`, `cdisasm_3dnow_tests.exe`,
  `cdisasm_opcode_corpus_tests.exe`, and
  `cdisasm_virtualization_undocumented_tests.exe` — native test suites

The `cdisasm_package_shared_e2e` and `cdisasm_package_static_e2e` CTest cases
use separate trees below `build/package-test-build/`. Each one runs all 16
feature cells described above. Build-tree and relocated installed packages are
consumed through `find_package`; the exact applicable C and C++ smoke programs
must execute successfully. Shared Windows tests expose only that installation's
`bin` directory through `PATH`; static tests require no cdisasm DLL.

A static Windows configuration instead produces one `cdisasm.lib` static
archive containing the same selected APIs and no cdisasm DLL or import library.

The group suite enumerates every canonical ID and alias, tests public helper
membership, exercises representative decoder-emitted groups using real
instruction bytes, and verifies that unsupported retired encodings fail without
fabricated metadata. When formatting is enabled, it also validates formatter
handling across the published group catalog. The 3DNow! suite covers every defined
selector, both ModRM source forms, metadata, truncation, unknown selectors, and
the CPU availability matrix, plus formatting when enabled.
The checked-in `tests/data/x86_opcodes.tsv` and `tests/data/arm_opcodes.tsv`
corpora add data-driven regression coverage across opcode maps, modes, CPU
gates, malformed input, and retired encodings. Ignoring blank and comment
lines, the current inventories contain exactly 5,126 x86 rows and 3,541 ARM rows.
The packed-MIN/MAX/GFNI and fixed-crypto tranche contributes 144 packed-MIN/MAX
and 50 GFNI x86 rows, plus
44 SHA1/SHA256 and 29 fixed-crypto ARM rows.
Thirty-two x86 rows cover classic-VEX `VCOMISD`/`VCOMISS` forms
3629--3630/3633--3634, their scalar register/memory sources, mode aliases,
reserved controls, status metadata, formatting, truncation, and legacy/EVEX
sibling boundaries.
Forty-two x86 rows cover all 12 classic-VEX `VCMPPD`/`VCMPPS`/`VCMPSD`/
`VCMPSS` forms, every imm8 and W alias, packed-L/scalar-LIG behavior,
register/memory sources, non-long B-prime/`vvvv` aliases, long-mode high
registers, AVX/MXCSR metadata, formatting, truncation, and legacy/EVEX sibling
boundaries. Sixteen ARM rows cover scalar/vector Advanced SIMD `ADDP` forms
5808/6137, every legal arrangement, the reserved 1D cell, profiles, endian
transport, formatting, truncation, and extras-OFF ownership.
Thirty-nine x86 rows cover classic-VEX `VDPPD`/`VDPPS` forms
4507--4508/4515--4518, WIG and all imm8 values, XMM/YMM register and memory
sources, all modes, non-long aliases, high registers and addressing, reserved
controls, legacy siblings, formatting, truncation, and extras-OFF ownership.
Thirteen ARM rows cover Advanced SIMD `ADDV` form 6077, all five allocated
arrangements, the three reserved Q:size cells, profiles, endian transport,
formatting, truncation, and extras-OFF ownership.
Thirty-two x86 rows cover all 12 classic-VEX `VPSIGNB/W/D` forms, and 27 ARM
rows cover both scalar and fixed-vector Advanced SIMD `SSHL`/`USHL` forms.
Forty-two x86 rows cover all 12 classic-VEX `VPSHUFD/HW/LW` forms, and 23 ARM
rows cover fixed-vector Advanced SIMD `SABA`/`UABA` forms.
Forty-nine x86 rows cover all 24 classic-VEX `VPHADD*`/`VPHSUB*` forms and
their legacy/XOP, mode, feature, addressing, reserved, formatting, and
truncation boundaries. Thirty-five x86 rows cover `VPHMINPOSUW` forms
7040--7041 plus legacy, same-opcode, EVEX, mode, addressing, reserved,
formatting, and truncation boundaries. Fifty-two x86 rows cover all eight
classic-VEX `VPINSRB/D/Q/W` forms, C4/C5 spellings, scalar sizes, modes,
aliases, legacy/EVEX siblings, reserved controls, formatting, and truncation.
Sixty-six x86 rows cover all nine classic-VEX `VPEXTRB/D/Q/W` forms, C4/C5
spellings, scalar destination sizes, modes and aliases, legacy/EVEX siblings,
reserved controls, formatting, and payload-first truncation.
Sixty-two x86 rows cover all 24 classic-VEX `VPMOVSXBW/BD/BQ/WD/WQ/DQ`
forms, exact narrowed register/memory sources, both vector widths, every mode,
WIG and non-long aliases, legacy/EVEX siblings, reserved controls, formatting,
feature/profile gates, and payload-first truncation.
Sixty-two x86 rows cover all 24 classic-VEX `VPMOVZXBW/BD/BQ/WD/WQ/DQ`
forms with the same exact narrowed source widths, XMM/YMM destination split,
mode aliases, legacy/EVEX separation, reserved controls, feature/profile gates,
formatting, and payload-first truncation.
Twenty-three ARM rows cover
fixed-vector Advanced SIMD
`SABD`/`UABD`, every B/H/S arrangement at both widths, profiles, endian
transport, reserved size controls, truncation, and extras-OFF ownership.
Thirty-four ARM rows cover fixed-vector `MLA`/`MLS` forms 6132/6174 plus all
arrangements, registers, profiles, endian transport, same-name siblings,
reserved controls, formatting, truncation, and extras-OFF ownership.
Twenty-five ARM rows cover by-element `MLA`/`MLS` forms 6268/6270, every H/S
lane/register boundary at both widths, profiles, endian transport, sibling
isolation, reserved sizes, formatting, truncation, and extras-OFF ownership.
Twenty-two ARM rows cover indexed SVE2-or-SME `MLA`/`MLS` forms 2722--2727,
every H/S/D lane and width-dependent indexed-register boundary, destructive
accumulator access, profile and endian routes, adjacent-family isolation,
formatting, truncation, and extras-OFF ownership. Twenty ARM rows cover indexed
`SQRDMLAH`/`SQRDMLSH` forms 2728--2733, all H/S/D lane and indexed-register
boundaries, destructive accumulator access, profile/endian routes, the adjacent
`USDOT` boundary, formatting, truncation, and extras-OFF ownership.
Seventy-five ARM rows cover the complete widening by-element `SMLAL`/
`SQDMLAL`/`SMLSL`/`SQDMLSL`/`SMULL`/`SQDMULL`/`UMLAL`/`UMLSL`/`UMULL`
block, both H-to-S and S-to-D shapes, base/`2` source halves, indexed
register/lane boundaries, destination access, profiles, endian transport,
sibling isolation, reserved sizes, formatting, truncation, and extras-OFF
ownership.
Twenty-five x86 rows cover all four classic-VEX `VPTEST` forms, and 18 ARM
rows cover both scalar and fixed-vector Advanced SIMD `CMTST` forms.
Sixty-nine x86 rows cover all 32 classic-VEX integer `VPUNPCK*` forms,
VEX2/VEX3 and WIG aliases, every mode, registers and addresses, AVX versus
AVX2 admission, legacy/EVEX siblings, reserved controls, payload-first
truncation, both syntaxes, and extras-OFF ownership. Fifty-seven ARM rows
cover fixed-vector `CMGT`/`CMGE`/`CMHI`/`CMHS`/`CMEQ`, every legal
arrangement, the reserved Q=0 1D partition, profiles, endian transport,
scalar/compare-zero siblings, canonical formatting, truncation, and
extras-OFF ownership.
Thirty x86 rows cover exact VEX `VPBLENDD`/`VPBLENDW` forms, their four
operands, register/memory and address boundaries, prefix ownership, both text
syntaxes, truncation, and extras-OFF behavior. Fifteen ARM rows cover exact
`SCLAMP`/`UCLAMP` forms, all element widths, destructive access, profiles,
both byte orders, canonical formatting, malformed metadata, truncation, and
extras-OFF behavior.
Twenty-five x86 rows cover exact XOP `VPCMOV` forms 6410--6415, both vector
widths, W-swapped memory/selector placement, register W aliases, selector-byte
metadata, non-long aliases, addresses, profile/runtime gates, malformed
prefixes, truncation, both syntaxes, and extras-OFF behavior. Fifteen ARM rows
cover exact `.D`-only `MLAPT`/`MADPT` forms 2707--2708, destructive operand
order, the conjunctive SVE+CPA gate, every named-profile rejection, reserved
size quarters, endian transport, formatting, truncation, and extras-OFF
ownership.
Twenty-seven x86 rows cover exact XMM `VPPERM` forms 7686--7688, W-swapped
memory and selector-source placement, register-form collapse, selector-byte
metadata, non-long aliases, address and segment overrides, profile/runtime
gates, reserved L/pp/prefix controls, late truncation precedence, both
syntaxes, and extras-OFF ownership. Seventeen ARM rows cover exact B/H/S/D
`ZIPQ1`/`UZPQ1` forms 2711--2712, three typed scalable-register operands,
the SVE2.1-or-SME2.1 gate, named-profile rejection, sibling routing, reserved
parent controls, endian transport, formatting, truncation, and extras-OFF
ownership.
Thirty-four x86 rows cover exact VEX `VPBLENDVB` forms 6334--6337, XMM/YMM
register and memory shapes, selector-offset metadata, non-long XED aliases and
LES collisions, address overrides, AVX/AVX2 gates, malformed complete inputs,
truncation precedence, both syntaxes, and extras-OFF ownership. Fourteen ARM
rows cover exact B/H/S/D `ZIPQ2`/`UZPQ2` forms 2714--2715, three typed
scalable-register operands, the SVE2.1-or-SME2.1 gate, named-profile
rejection, TBLQ/reserved parent routing, endian transport, formatting,
truncation, and extras-OFF ownership.
Sixty-two x86 rows cover exact VEX `VPBROADCASTB`/`VPBROADCASTW` forms
6342/6343/6347/6348 and 6387/6388/6392/6393, both widths and source shapes,
byte/word-sized reads,
AVX/AVX2 metadata and admission, all three modes, non-long B' aliases and LES
collisions, addresses, reserved W/pp/`vvvv`/prefix controls, sibling routing,
late truncation, both syntaxes, and extras-OFF ownership. Eighteen ARM rows
cover indexed `USDOT`/`SUDOT` forms 2734--2735, low/high lanes and registers,
all named-profile gates, big-endian transport, canonical formatting,
truncation, sibling identity, and extras-OFF ownership. Thirteen additional
ARM rows cover SVE `AESMC`/`AESIMC`, FEAT_SVE_AES profile gates, all reserved
size controls, endian transport, truncation, and exact tied operands.
Sixty-two further x86 rows cover exact VEX `VPBROADCASTD`/`VPBROADCASTQ`
forms 6355/6356/6360/6361 and 6374/6375/6379/6380, dword/qword sources,
all modes and address shapes, AVX2 gates, malformed selectors, both syntaxes,
late truncation, and extras-OFF ownership. Nineteen ARM rows cover exact SVE
`AESE`/`AESD`/`SM4E` forms 2905--2907, independent SVE_AES/SVE_SM4 gates,
the reserved crypto-parent selectors, endian transport, truncation, and tied
operand metadata.
Thirty x86 rows cover exact VEX `VPCMPEQQ` forms 6454--6457, XMM/YMM
register and memory sources, WIG encodings, all modes, non-long aliases,
addresses, AVX/AVX2 gates, legacy/EVEX siblings, malformed pp and prefix
controls, both syntaxes, late truncation, and extras-OFF ownership. Twelve ARM
rows cover exact SVE `PUNPKLO`/`PUNPKHI` forms 2468--2469, low/high predicate
registers, SVE-or-SME profile admission, both byte orders, canonical
formatting, truncation, and extras-OFF ownership.
Thirty-two x86 rows cover exact VEX `VBLENDPD`/`VBLENDPS` forms 3527--3534,
XMM/YMM register and memory sources, W aliases, high registers and addresses,
all modes, non-long C4/LES and B-extension behavior, address/segment overrides,
AVX-only admission at both widths, reserved pp and legacy-prefix controls,
both syntaxes, complete-payload truncation precedence, formatter-schema
rejection, and extras-OFF ownership. Twenty-two ARM rows cover exact SVE/SME
`SUNPKLO`/`SUNPKHI`/`UUNPKLO`/`UUNPKHI` forms 2456--2459, all B-to-H,
H-to-S, and S-to-D widths, low/high registers, `size=00` reservations,
SVE-or-SME profile admission, both byte orders, canonical formatting and
forged-schema rejection, truncation, and extras-OFF ownership.
Thirty-eight x86 rows cover exact VEX `VBLENDVPD`/`VBLENDVPS` forms
3535--3542, XMM/YMM register and memory shapes, selector high-nibble register
semantics and ignored low nibble, W=0 and pp=66 ownership, every mode,
non-long C4/LES and extension aliases, complete-payload truncation precedence,
AVX-only admission, both syntaxes, forged-schema rejection, and extras-OFF
ownership. Twenty-one ARM rows cover exact SVE2/SME `SRI`/`SLI` forms
2846--2847, all B/H/S/D immediate bands and endpoints, tied destination
access, the reserved encoded-immediate range 0--7, named profiles, both byte
orders, generic transport, canonical formatting and forged-schema rejection,
truncation, and extras-OFF ownership.
Thirty-nine x86 rows cover memory-only VEX `VBROADCASTF128` form 3543 and
`VBROADCASTI128` form 3554 across all modes, addressing and non-long C4/LES
aliases, the complete L/W/pp/vvvv/ModRM boundary, independent AVX/AVX2 gates,
both syntaxes, truncation, formatter-schema rejection, and extras-OFF
ownership. Eighteen ARM rows cover exact Advanced SIMD `BSL`/`BIT`/`BIF`
forms 6188/6196/6198, Q-selected 8B/16B arrangements, tied Vd access,
adjacent logical-family isolation, NEON profiles, both byte orders, generic
transport, formatting, truncation, and extras-OFF ownership.
Forty-one x86 rows cover the six VEX `VBROADCASTSD`/`VBROADCASTSS` forms
3569--3570/3573--3574/3579--3580, L-selected destinations, scalar memory and
full-XMM register sources, every mode, non-long aliases, address and segment
overrides, AVX/AVX2 gates, malformed controls, complete-payload truncation,
both syntaxes, formatter-schema rejection, and extras-OFF ownership. Twenty-four
ARM rows cover SVE BitPerm `BEXT`/`BDEP`/`BGRP` forms 2829--2831, every
B/H/S/D arrangement, exact FEAT_SVE_BitPerm profile admission, the reserved
selector quarter, both byte orders, generic transport, canonical formatting,
truncation, and extras-OFF ownership.
Twenty-three x86 rows cover exact VEX `VEXTRACTF128`/`VEXTRACTI128` forms
4539--4540/4553--4554 and `VINSERTF128`/`VINSERTI128` forms
5551--5552/5565--5566, including register/memory shapes, imm8 metadata, all
modes, non-long aliases, AVX/AVX2 gates, reserved fields, EVEX neighbors, both
syntaxes, late truncation, and extras-OFF ownership. Twenty-two ARM rows cover
exact Advanced SIMD `ADDHN`/`SUBHN`/`RADDHN`/`RSUBHN` forms
6093/6095/6108/6110, base and `*HN2` arrangements, destination access,
NEON profiles, reserved size controls, both byte orders, canonical formatting,
truncation, and extras-OFF ownership.
Twenty-four x86 rows cover exact VEX `VEXTRACTPS` forms 4567/4569 and
`VINSERTPS` forms 5579--5580, r32/m32 and XMM/m32 splits, W aliases, every
mode, non-long aliases, AVX gates, reserved controls, EVEX separation, both
syntaxes, formatter-schema rejection, late truncation, and extras-OFF
ownership. Twenty-three ARM rows cover all eight FEAT_PAuth authenticated
register-branch forms 4510/4511/4513/4514/4525--4528, XZR/SP semantics,
jump/call/link metadata, profiles, reserved parent controls, both byte orders,
canonical formatting, truncation, RETAA/RETAB neighbors, and extras-OFF
ownership.
Twenty-three x86 rows cover exact VEX `VPERM2F128`/`VPERM2I128` forms
6770--6773, register and m256 sources, all modes, all NDS `vvvv` values,
AVX/AVX2 profile gates, reserved W/L/pp and prefix controls, both syntaxes,
formatter-schema rejection, late truncation, and extras-OFF ownership.
Thirty-four ARM rows cover all eight Advanced SIMD widening add/sub forms
6089--6092/6104--6107, base and `2` arrangements, exact long-versus-wide
operand widths, NEON profiles, reserved size controls, both byte orders,
canonical formatting, fixed neighbors, truncation, and extras-OFF ownership.
Twenty-five x86 rows cover exact VEX `VPERMD`/`VPERMPS` forms
6780--6781/6886--6887, register and m256 sources, all modes and NDS sources,
AVX2 gates, reserved W/L/pp and prefix controls, EVEX sibling separation,
both syntaxes, formatter-schema rejection, late truncation, and extras-OFF
ownership. Twenty-two ARM rows cover Advanced SIMD
`SABAL`/`SABDL`/`UABAL`/`UABDL` forms 6094/6096/6109/6111, base and `2`
arrangements, accumulating versus write-only destination access, NEON
profiles, reserved size controls, both byte orders, SVE-name collisions,
canonical formatting, truncation, and extras-OFF ownership.
Twenty-eight ARM rows cover Advanced SIMD `SMLAL`/`SMLSL`/`SMULL` forms
6097/6099/6101 and `UMLAL`/`UMLSL`/`UMULL` forms 6112--6114, every base/`2`
and B/H/S-to-H/S/D arrangement, accumulator versus write-only destination
access, NEON profiles, reserved size controls, both byte orders, fixed
neighbors, canonical formatting, truncation, extras-OFF ownership, and exact
separation from shared-name A32/T32, scalar-alias, and SME identities.
Seventeen x86 rows lock SMAP `CLAC`/`STAC` forms 707/3158 across mode,
profile/runtime, REX/REX2, prefix, formatting, and extras-OFF boundaries,
including the mandatory-F2/F3 `0F 01 CA` FRED collision. Sixteen ARM rows lock
SVE FFR forms 2562--2564/2617--2618, structured operands and flags, endian and
profile behavior, reserved controls, formatting, truncation, and extras-OFF
ownership.
Twenty-four x86 rows cover all six `MOVNTDQA`/`VMOVNTDQA` forms, legacy,
VEX, EVEX, REX/APX address transport, tuple scaling, exact runtime/profile
gates, malformed controls, formatting, truncation, and extras-OFF ownership.
Seventy-five ARM rows cover the original 62 saturating element-count and
predicate-count forms, representative operand shapes, feature/profile gates,
both byte orders, reserved parent controls, canonical formatting, truncation,
and extras-OFF ownership.
Twenty-three x86 rows cover `LDDQU`/`VLDDQU` forms 1574/5583--5584, ignored
legacy `66`, REX/REX2 address transport, VEX WIG and reserved `vvvv`, exact
SSE3/AVX/APX gates, memory-only controls, formatting, truncation, and
extras-OFF ownership. Twelve ARM rows cover `FIRSTP`/`LASTP` forms
2598--2599, all four element widths, XZR, SVE2.2-or-SME2.2 profile rejection,
both byte orders, canonical formatting, truncation, and extras-OFF ownership.
Sixteen ARM rows cover `CTERMEQ`/`CTERMNE` forms 2593--2594, W/X and zero-
register operands, NZCV metadata, SVE-or-SME profile paths, the reserved
`op=0` parent, adjacent controls, both byte orders, formatting, truncation,
and extras-OFF ownership.
Fifty x86 rows cover `VMOVQ` forms 5884--5896 across VEX and EVEX,
GPR/XMM/memory directions, all modes, extended registers, APX B4/U0 address
promotion, disp8 scaling, Knights Mill, and profile/runtime/formatter/
truncation boundaries. They also preserve three reachable W0 `VMOVD`
collisions, reject reserved pp/`vvvv`/VL/decorator controls, and lock exact
profile-invalid precedence for AVX, AVX512F-128N, and MOVZXC collisions.
Thirty-eight x86 rows cover all twelve `VMOVRSB/D/Q/W` forms 5897--5908,
all three vector widths, mask merge/zero, width-specific AVX10 MOVRS gates,
16/32/64-byte disp8 scaling, APX-promoted addressing, reserved controls,
formatting, truncation, and extras-OFF ownership.
Thirty-four x86 rows cover all seven `VMOVSD` forms 5909--5915, VEX and EVEX
load/store/register directions, all modes, masks, scalar disp8 scaling, vector
extensions, APX B4/X4 routes, profile/runtime gates, legacy and adjacent move
collisions, malformed controls, formatting, truncation, and extras-OFF ownership.
Sixty-nine x86 rows cover all 23 `VMOVSHDUP`/`VMOVSH`/`VMOVSLDUP` forms
5916--5938. They span VEX/EVEX duplicate moves at every allocated vector
width, scalar-half store/load/register directions, memory and register
sources, merge/zero masks, two- and 16/32/64-byte compressed disp8, APX B4/X4
routes, exact runtime/profile gates, non-long extension behavior,
legacy/mandatory-prefix collisions, malformed controls, both syntaxes,
truncation, and extras-OFF ownership.
Thirty-four x86 rows cover all seven `VMOVSS` forms 5939--5945, VEX and EVEX
load/store/register directions, PF3/W0 selection, all modes, masks, dword
memory and four-byte compressed disp8, APX B4/X4 routes, exact AVX versus
`AVX512F_SCALAR` gates, legacy/neighbor collisions, malformed controls,
formatting, truncation, and extras-OFF ownership.
Sixty-three x86 rows cover all 34 `VMOVUPD`/`VMOVUPS` forms 5946--5979.
They span both opcode directions, VEX XMM/YMM and EVEX XMM/YMM/ZMM forms,
register/full-memory operands, merge/zero masking, store-zeroing rejection,
Full-tuple disp8 scaling, APX B4/X4 addresses, exact AVX/AVX512F/AVX10
admission, legacy/scalar collision delegation, formatting, truncation, and
extras-OFF ownership.
Thirty-eight x86 rows cover all seven `VMOVW` form identities 5980--5986 and
both pinned records sharing form 5986. They preserve GPR32/XMM, m16/XMM, and
XMM/XMM directions; WIG `66` versus F3/W0 selection; exact
`AVX512_FP16_128N` versus `AVX512_MOVZXC_128` runtime/profile admission;
Tuple2 disp8 scaling; APX B4/X4, high-register, and non-long behavior;
reserved P1/P2 controls; map-1/map-2 neighbors; both syntaxes; truncation; and
extras-OFF ownership.
Fifty-one x86 rows cover all ten `VMPSADBW` forms 5987--5996. They span VEX
XMM/YMM and EVEX XMM/YMM/ZMM, register and Full-tuple memory sources, imm8,
merge/zero masks, 16/32/64-byte disp8 scaling, high registers, APX B4/X4,
non-long extension behavior, exact AVX/AVX2/AVX512-MEDIAX gates, legacy
`MPSADBW` and `VDBPSADBW` collisions, reserved prefix/decorator controls, both
syntaxes, truncation, and extras-OFF ownership.
Sixty-four x86 rows cover exact virtualization forms 5997--6005 and
6048--6053. They retain qword-memory `VMPTRLD`/`VMPTRST`, all four 32-/64-bit
register/memory `VMREAD` shapes, fixed `VMRESUME`, address-sized implicit-AX
`VMRUN`, and fixed `VMSAVE`, and add all four register/memory and 32-/64-bit
`VMWRITE` identities plus fixed `VMXOFF` and memory `VMXON`. They lock exact
VMX/SVM/VTX runtime and profile gates, operand access, status/privilege
metadata, REX/REX2/APX transport, VMCLEAR/EXTRQ/INSERTQ collisions, ignored
and reserved prefixes, both syntaxes, truncation, and extras-OFF ownership.
Thirty-seven x86 rows cover exact `VMULBF16` forms 6006--6011. They retain
all three vector widths, register/Full-memory and BF16-broadcast sources,
mask merge/zero, compressed disp8, high registers, APX B4/U0/X4 ownership,
exact width-specific runtime/profile admission, malformed P1/P2 controls,
PH/SH/F2 neighbors, both syntaxes, truncation, and extras-OFF ownership.
Fifty-nine x86 rows cover exact `VMULPH` forms 6022--6027 and `VMULSH` forms
6042--6043. They retain XMM/YMM/ZMM and scalar register/memory forms, masks,
FP16 broadcast, Full/Tuple2 disp8 scaling, all embedded-rounding controls,
high registers, APX B4/U0/X4, exact width/scalar runtime and profile routes,
the BF16/F2/W1/LL/decorator collision partitions, both syntaxes, truncation,
and extras-OFF ownership.
Fifty-nine x86 rows cover all 28 classic `VMULPD`/`VMULPS`/`VMULSD`/
`VMULSS` forms 6012--6021, 6028--6041, and 6044--6047. They retain VEX
XMM/YMM and EVEX XMM/YMM/ZMM/scalar register and memory forms, exact
width/scalar runtime selectors, AVX-512-versus-AVX10 routes, masks,
broadcast, Full/scalar tuple disp8 scaling, all embedded-rounding controls,
APX B4/U0/X4, Arrow Lake and Knights Mill profile
boundaries, legacy-prefix and malformed-control collisions, both syntaxes,
truncation precedence, and extras-OFF ownership.
Fifty-two x86 rows cover all twenty classic `VORPD`/`VORPS` forms
6054--6073. They retain VEX XMM/YMM and EVEX XMM/YMM/ZMM register and memory
shapes, exact AVX versus AVX512DQ/AVX10.1 runtime and profile routes,
merge/zero masking, scalar broadcast, Full-tuple disp8 scaling, high
registers, APX B4/U0/X4 addressing, ignored non-long extension fields,
reserved W/prefix/decorator controls, legacy collisions, both syntaxes,
truncation precedence, and extras-OFF ownership.
Twenty-nine x86 rows cover exact `VP2INTERSECTD/Q` forms 6074--6085. They
lock all three vector widths, register and memory sources, dword/qword lane
typing, the normalized even/odd K destination pair and `kN+1` spelling,
broadcast, Full-tuple disp8, high registers, APX address extensions, exact
runtime/profile gates, malformed EVEX controls, both syntaxes, truncation,
and extras-OFF ownership.
Twenty-one x86 rows cover `VMOVMSKPD`/`VMOVMSKPS` forms 5860--5863, both VEX
lengths and W values, extended and non-long B-ignored register selection,
wrong pp/`vvvv`/ModRM controls, AVX/profile gates, legacy/REX2, EVEX and VNNI
collisions, formatting, truncation, and extras-OFF ownership.
Twenty-two ARM rows cover the single-predicate `WHILEGE/HS/GT/HI/LT/LO/LE/LS`
forms 2585--2592, and another 22 cover paired-predicate forms 2574--2581. They
lock element typing, zero-register handling, NZCV metadata, the SVE/SME,
SVE2/SME, and SVE2.1/SME2 feature boundaries, endian transport, canonical
formatting, truncation, and extras-OFF ownership.
Another 22 ARM rows cover counter-predicate forms 2566--2573: typed
`PN8`--`PN15`, X/XZR sources, `VLx2`/`VLx4`, NZCV metadata, exact
SVE2.1-or-SME2 admission, endian transport, formatting, truncation, and
extras-OFF ownership. Twenty-four rows cover `PEXT`/`PTRUE` forms 2582--2584,
including untyped indexed `PNn[index]` sources, one- and two-predicate PEXT
destinations, the `p15, p0` pair wrap, typed PTRUE PN results, the same feature
alternative, endian transport, formatting, truncation, and disabled-build
ownership.
Twenty-three ARM rows cover all predicate-break forms 2546--2555. They retain
the four-operand BRKP and tied-source BRKN schemas, three-operand BRKA/BRKB,
byte predicate typing, zeroing and allocated merging controls, exact
destination access and NZCV metadata, SVE-or-SME profile admission, reserved
parent controls, both byte orders, formatting, truncation, and extras-OFF
ownership.
Thirty-three ARM rows cover predicate-control forms 2556--2561. They retain
the tied PFIRST/PNEXT destination reads, typed and governing predicates,
PTRUE/PTRUES pattern spelling including numeric selectors, exact NZCV and
predication flags, SVE-or-SME admission, all reserved parent residuals, both
byte orders, formatting, truncation, and extras-OFF ownership.
Eighteen ARM rows cover `PSEL` form 2565 across B/H/S/D type and lane
boundaries, W12--W15 index registers, P0--P15 operands, the exact SVE2.1-or-
baseline-SME feature alternative, both `tsz=0000` residuals, big-endian
transport, formatting, truncation, and extras-OFF ownership. LLVM 21 agrees
with all 30 legal `i1:tsz` controls.
Forty-four ARM rows cover the complete wide-immediate block 2619--2632:
thirty rows for the twelve destructive arithmetic forms and fourteen for
integer `DUP`/preferred `MOV` plus floating `FDUP`/preferred `FMOV`. They lock
typed and tied destinations, signed/unsigned/shifted immediates, exact IEEE
immediate expansion, scalable/floating flags, SVE-or-SME profile alternatives,
all reserved byte controls, both byte orders, canonical formatting,
truncation, and extras-OFF ownership.
Nineteen ARM rows cover exact unpredicated `SDOT`/`UDOT` forms 2633--2636.
They lock B-to-S, H-to-D, and SVE2p3/SME2p3 B-to-H arrangements; the tied
read/write accumulator and read-only sources; SVE-or-SME versus p3 profile
admission; all 65,536 reserved `size=00` words; endian transport; canonical
formatting; truncation; and extras-OFF ownership.
Thirty-one ARM rows cover exact `SQDMLALBT`, `SQDMLSLBT`, `CDOT`, `CMLA`,
and `SQRDCMLAH` forms 2637--2641. They retain every legal arrangement and
rotation, tied accumulator access, exact SVE2-or-SME admission, both byte
orders, reserved widths, adjacent delegation, canonical formatting,
truncation, and extras-OFF ownership.
Thirty-two ARM rows cover exact `SMLALB`/`SMLSLB`/`SMLALT`/`SMLSLT`, their
unsigned counterparts, `SQDMLALB`/`SQDMLSLB`/`SQDMLALT`/`SQDMLSLT`, and
`SQRDMLAH`/`SQRDMLSH` forms 2642--2655. They retain all legal arrangements,
tied accumulator access, SVE2-or-SME profile alternatives, reserved byte
widths for the widening forms, legal byte same-width rounding forms, exact
dispatch to the adjacent USDOT parent, endian transport, formatting,
truncation, and extras-OFF
ownership.
Eleven ARM rows cover exact mixed-sign `USDOT` form 2656. They lock low/high
registers, the tied read/write `.S` accumulator and read-only `.B` sources,
the `(SVE or SME) and I8MM` gate, four named-profile rejections, all three
reserved size siblings, big-endian transport, canonical formatting,
truncation, formatter-forgery rejection, and extras-OFF ownership.
Twenty-three ARM rows cover predicated merging shift/saturating-round forms
2657--2668. They lock all twelve names, B/H/S/D arrangements, low/high
registers, tied read/write destinations, governing merge predicates,
SVE2-or-SME profile alternatives, all four reserved selectors, both byte
orders, canonical formatting, truncation, formatter-forgery rejection, and
extras-OFF ownership.
Twenty-one ARM rows cover predicated `URECPE`/`URSQRTE`/`SQABS`/`SQNEG`
forms 2669--2676. They lock `.S`-only estimate forms, B/H/S/D saturating
forms, low/high registers, merge versus zero predicate metadata and destination
access, SVE2-or-SME versus SVE2.2-or-SME2.2 admission, all reserved estimate
widths, both byte orders, canonical formatting, truncation, formatter-forgery
rejection, and extras-OFF ownership.
Thirty ARM rows cover `SADALP`/`UADALP` forms 2677--2678 and `SHADD`/
`SHSUB`/`SRHADD`/`SHSUBR`/`UHADD`/`UHSUB`/`URHADD`/`UHSUBR` forms
2679--2686. They lock every legal arrangement, destructive access and
predicate granularity, the reserved accumulating-long `size=00` controls,
SVE2-or-SME profile alternatives, both byte orders, canonical formatting,
truncation, formatter-forgery rejection, and extras-OFF ownership.
When formatting is enabled, the
x86 corpus stores and verifies exact Intel and AT&T output for every successful
row; the runner also sweeps all 65,536 two-byte input values in each mode and
formats every successful result in both syntaxes. The ARM corpus runner
verifies numeric metadata and little-/big-endian parity for every successful
row, while
`cdisasm_arm_format_tests` covers canonical ARM text, size queries, truncation,
and invalid metadata. With `USE_DISASM_FORMAT=OFF`, CMake omits only the
dedicated formatter suites. The group, virtualization/undocumented, 3DNow!, and
x86 opcode-corpus suites continue running their decoder and metadata checks with
their formatter assertions compiled out.

## Fuzzing

Opt-in Clang libFuzzer targets instrument private static copies of enabled
decoders and formatters, leaving the normal shared or static library unchanged. An
x86-only fuzz build is:

```sh
cmake -S . -B build-fuzz-x86 \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTING=OFF \
  -DCDISASM_BUILD_EXAMPLES=OFF \
  -DCDISASM_BUILD_FUZZERS=ON \
  -DUSE_ARCH_X86=ON \
  -DUSE_ARCH_ARM=OFF \
  -DUSE_DISASM_FORMAT=ON
cmake --build build-fuzz-x86 --target cdisasm_decode_fuzzer
./build-fuzz-x86/cdisasm_decode_fuzzer -max_len=192 build-fuzz-x86/fuzz-corpus
```

The x86 harness accepts readable hexadecimal text before normalization, so
`-max_len` applies to the text rather than the decoded bytes. Its
`FUZZ_HEX_CAPACITY * 3` input bound is 192 bytes; the largest checked-in x86
seed is 189 bytes. The ARM seed maximum is 60 bytes, so its command remains at
64.

An ARM-only fuzz build selects the other module and target:

```sh
cmake -S . -B build-fuzz-arm \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTING=OFF \
  -DCDISASM_BUILD_EXAMPLES=OFF \
  -DCDISASM_BUILD_FUZZERS=ON \
  -DUSE_ARCH_X86=OFF \
  -DUSE_ARCH_ARM=ON \
  -DUSE_DISASM_FORMAT=ON
cmake --build build-fuzz-arm --target cdisasm_arm_decode_fuzzer
./build-fuzz-arm/cdisasm_arm_decode_fuzzer -max_len=64 build-fuzz-arm/fuzz-arm-corpus
```

The checked-in seeds are readable hexadecimal and are also accepted as raw
binary after mutation. With `USE_DISASM_FORMAT=ON`, both harnesses validate
their architecture formatter's determinism, size-query/write agreement,
truncation, NUL termination, and invalid-result behavior in addition to decoder
invariants. With it `OFF`, the same targets exercise decoder invariants without
compiling formatter sources into their private runtimes. AddressSanitizer
and UndefinedBehaviorSanitizer are enabled by default;
`CDISASM_FUZZ_SANITIZERS` customizes that list. See
`fuzz/README.md` for the harness invariants and corpus-maintenance rules.
The `cdisasm_fuzz_corpus_seed_tests` CTest independently rejects source-corpus
comments, non-hex artifacts, odd digit counts, decoded inputs over 64 bytes,
and readable files beyond the x86 192-byte or ARM 64-byte command-line caps.

The 2,395 reviewed x86 `.hex` seeds cover entropy/RTM, FMA3/FMA4, XOP, vector
crypto, EVEX arithmetic, AMX-FP16/COMPLEX/FP8/MOVRS/row forms, AVX10.2 BF16,
APX REX2/NDD/NF/MOVDIR/`JMPABS`, modern system collisions, classic VEX K-mask
operations, packed-integer EVEX compare-to-mask, complete VEX/EVEX MIN/MAX,
GFNI,
multiply/multiply-add, modular ADD/SUB valid/invalid forms, and VEX/EVEX
saturating ADD/SUB forms, CET
shadow-stack, and WAITPKG valid-width, invalid, collision, and truncation parser
paths. `evex_integer_logical.hex`, `evex_integer_logical_apx.hex`, and
`evex_average.hex` specifically reach the version-11.6 classic and APX P0.B4
paths. The variable-shift seeds independently reach VEX, canonical EVEX, and
reserved EVEX controls added in version 11.7, plus the word and APX-specific
routes added in version 11.8. Those family additions include 174
packed-MIN/MAX and 12 GFNI seeds. The corresponding checked-in x86 corpus
contains 5,126 rows. Twenty `x86_vcomi*.hex` seeds reach all four classic-VEX
`VCOMISD`/`VCOMISS` forms, scalar register/memory sources, WIG/LIG and NOVSR
controls, non-long aliases, status writes, legacy/EVEX siblings, and
payload-first truncation. Twenty-one `x86_vdpp*.hex` seeds reach all six
classic-VEX `VDPPD`/`VDPPS` forms, XMM/YMM register and memory paths, every
imm8 and W alias, all modes, non-long B-prime/`vvvv` aliases, long-mode high
registers and addressing, reserved controls, legacy siblings, formatting, and
payload-first truncation. Twenty `x86_vcmp*.hex` seeds reach all 12
classic-VEX `VCMPPD`/`VCMPPS`/`VCMPSD`/`VCMPSS` forms, packed and scalar
register/memory paths, all immediate predicates and aliases, WIG, L/LIG,
non-long B-prime/`vvvv` aliases, high registers, AVX/MXCSR metadata,
legacy/EVEX siblings, and payload-first truncation. Thirty-seven
horizontal-integer seeds reach every
classic-VEX `VPHADD*`/`VPHSUB*` form plus high-register/address, non-long, reserved,
legacy/XOP-sibling, and truncation boundaries. Seventeen `VPHMINPOSUW` seeds
reach both exact classic-VEX
forms plus WIG, non-long, high-register/address, legacy, same-opcode, EVEX,
reserved-control, and payload-first truncation boundaries. Seven version-11.9
one-vector seeds independently reach all four variable packed-rotate names,
APX P0.B4 and U0/X4 routes, and an `LL=3` reserved control. Seven version-11.10
seeds similarly reach all four immediate
packed-rotate names, APX P0.B4 and U0/X4 routes, and one reserved control.
Six version-11.11 seeds reach all four immediate packed-shift names, the APX
U0/X4 route, and a reserved W1 control.
Three version-11.12 seeds reach the opcode-`71` word, opcode-`73` qword
broadcast, and opcode-`73` byte-lane immediate-shift paths.
Six version-11.13 seeds separately reach variable, immediate-register,
immediate-memory, APX, reserved-control, and invalid-decorator AVX512VBMI2
double-shift paths.
Seventeen version-11.14 seeds cover COMPRESS/EXPAND and BITALG/VPOPCNT
register, memory, mask, broadcast, APX, reserved-control, and truncation paths.
Six version-11.15 seeds cover `VPCONFLICTD/Q`, `VPLZCNTD/Q`, an APX route, and
an invalid AVX-512CD control. Two version-11.16 seeds cover the register-only
`VPBROADCASTMB2Q/MW2D` rows. Six version-11.17 seeds cover all four VNNI
dot-product opcodes, broadcast, APX, and invalid-control paths. Seventeen
single-encoding version-11.18 seeds historically covered VBMI byte permutes,
multishift/broadcast, APX, then-unsupported allocated word siblings, and invalid
controls. Version 11.19 renames the four word seeds for AVX512BW and adds an APX
B4/U0 `VPERMT2W` seed. Five retained version-11.20 seeds reach the four classic
VEX AVX-VNNI names, full-memory/SIB addressing, and the W=1 boundary. Ten
version-11.21 AVX-VNNI-INT8 seeds cover all six names, full-memory/SIB forms,
W=1, opcode/map neighbors, and truncation. The now-obsolete classic AVX-VNNI
mandatory-prefix-neighbor seed was removed, giving nine net new x86 files; pp
disjointness remains covered by the focused suite and opcode corpus. Ten
version-11.22 AVX-VNNI-INT16 seeds cover all six names, full-memory/SIB forms,
the W=1 reserved boundary, an F2 prefix neighbor, a map neighbor, and
truncation. Ten version-11.23 AVX512_4VNNIW seeds reach both Knights Mill
opcodes, mask merge/zero, Tuple1_4X disp8 scaling, the ZMM31 source boundary,
reserved register/W/LL/B controls, and truncation. Fifteen version-11.24
AVX512_4FMAPS seeds reach all four packed/scalar names, mask merge/zero,
Tuple1_4X disp8 scaling, source-group and memory-only boundaries, reserved
W/U/B/length/register controls, and truncation. Eight version-11.25 VGETEXP
seeds reach packed/scalar register forms, full-width memory, broadcast, SAE,
address-size and segment prefixes, and reserved controls. Eight version-11.26
seeds reach MAP6 PH/SH/BF16 register, broadcast, SAE/length-alias, and reserved
controls. Seven post-12.0 seeds reach all six EVEX AVX10.2 VNNI-INT8 names and
the REX2 `MONITOR`/`MWAIT` system row. Sixteen additional ACE_1 seeds reach
all four `TILEMOVROW`/`TILEMOVCOL` GPR32/IMM8 forms, all ten TOP forms, and
reviewed APX B4 routes. Eleven RAO-INT seeds cover all eight legacy dword/qword
forms plus malformed and truncated ownership paths. Five APX-F RAO-INT seeds
cover all four operations, both widths and U states, EGPR/SIB and disp8
addressing, and reserved register/control boundaries.
Fifteen further seeds cover `BSRINIT`, every BSR register/memory direction,
legacy/VEX/APX `URDMSR` and `UWRMSR`, EGPR and imm32 routes, and their dispatch
boundaries.
Two collision seeds independently retain APX `ENQCMD` memory dispatch and the
raw-U=0/X4 indexed-address route beside the shared USER_MSR opcode.
Eight legacy ENQCMD seeds add both F2/F3 operations, ignored operand-size and
address-size/REX controls, rightmost mandatory-prefix selection, the legacy
USER_MSR register collision, LOCK rejection, and truncated displacement.
Nineteen Key Locker seeds reach all eight AES forms, both `ENCODEKEY` forms,
`LOADIWKEY`, REX extension/WIG paths, invalid memory/selector controls, and
the adjacent AES-NI opcode collision.
An earlier 60-seed x86 increment adds twelve HRESET cases spanning allocated,
prefix/profile, immediate, and truncation boundaries; six CLDEMOTE/NOP
collision cases; ten CLZERO fixed-opcode, prefix, REX2, collision, and
truncation cases; ten PCONFIG/PCONFIG64 legacy, prefix, REX2, collision,
and truncation cases; ten MONITORX/MWAITX/MCOMMIT cases; and twelve
AMD_INVLPGB/SNP FE/FF collision cases.
Fifteen more x86 seeds cover fixed F2/F3/NP `0F 01 C6`, VEX and APX
immediate-selector MSR forms, R16/R31 extension, reserved W1/register/P2
controls, REX2 payloads, prefix selection, and truncation.
Eight PBNDKB/PREFETCHIT x86 seeds cover legacy/REX2 and reserved-prefix controls,
PREFETCHIT0/1 RIP-relative promotion, address-size fallback to NOP, the REX2
route, LOCK rejection, and truncated displacement.
Five RDPRU seeds cover the canonical fixed allocation, redundant prefixes,
REX2/APX admission, LOCK rejection, and truncation. Fourteen
PREFETCHRST2/PREFETCHWT1 seeds cover both memory hints, CPU/runtime gates,
REX2, ignored prefixes, NOP collisions and fallback, LOCK rejection, and
truncated addressing. The latter include the three review-driven REX2 NOP,
PREFETCH, and PREFETCHW routes. The corresponding additions contribute 12
RDPRU and 20 prefetch rows to the x86 data corpus.
Seventeen PTWRITE seeds cover 32-/64-bit register and memory operands,
rightmost-F3 selection, any-66 and LOCK rejection, the unprefixed XSAVE
collision, truncation, REX.B/REX.R behavior, and REX2 B/B4/X/X4 extension
with ignored R/R4 opcode-field bits. The matching 35 corpus rows additionally
cover all three decode modes, dword/qword formatting, admitted and rejected
profiles, the independent PTWRITE/APX-F gates, address and segment overrides,
and malformed REX2 controls.
Five MOVNTI seeds—`x86_movnti_dword.hex`, `x86_movnti_rex_sib.hex`,
`x86_movnti_rex2_egpr.hex`, `x86_movnti_invalid_prefix.hex`, and
`x86_movnti_truncated.hex`—reach the legacy dword row, REX/SIB and REX2 EGPR
transport, malformed prefixes, and truncation. The matching 24 corpus rows
cover forms 1692--1693, both syntaxes, mode/profile/runtime gates, and strict
extras-ON/OFF ownership.
Eight SMAP seeds—`x86_smap_clac.hex`, `x86_smap_stac.hex`,
`x86_smap_rex.hex`, `x86_smap_rex2.hex`,
`x86_smap_address_segment.hex`, `x86_smap_66_invalid.hex`,
`x86_smap_fred_collision.hex`, and `x86_smap_rex2_truncated.hex`—reach both
fixed forms, ignored ordinary REX and map-1 REX2 payloads, accepted address and
segment overrides, operand-size rejection, the mandatory-F2/F3 FRED collision,
and truncation. The matching 17 corpus rows additionally cover all modes,
profile/runtime and APX-F gates, canonical formatting, and extras-OFF ownership.
Twenty-five `x86_ntstore_*.hex` seeds reach every legacy/VEX/EVEX
`MOVNTDQ`/`MOVNTPD`/`MOVNTPS` store form, the three MMX/SSE4a prefix
collisions, APX extended addressing, compressed disp8, malformed controls,
and truncation. The matching 32 corpus rows cover all 18 target forms plus
`MOVNTQ`/`MOVNTSD`/`MOVNTSS`, exact feature/profile gates, both syntaxes, and
extras-OFF ownership.
Twelve `x86_movntdqa_*.hex` seeds reach legacy SSE4, VEX XMM/YMM, EVEX
XMM/YMM/ZMM, REX/SIB, VEX WIG, APX B4/X4, compressed disp8, reserved controls,
and truncation. Their invariant fixes forms 1690/5864--5868, the write-vector/
read-memory schema, exact SSE4/AVX/AVX2/AVX512F width groups and runtime bits,
no-mask/no-broadcast controls, and the independent APX gate on promoted EVEX
addresses.
Fourteen `x86_*lddqu*.hex` seeds reach legacy SSE3 `LDDQU`, VEX.128/256
`VLDDQU`, ignored legacy `66`, REX/SIB and REX2 map-1 APX addressing, VEX WIG,
reserved `vvvv`, register-ModRM rejection, and truncation. Their invariant
fixes forms 1574/5583--5584, a write-only XMM/YMM destination and equal-width
read-only memory source, SSE3 versus AVX selection, and the independent APX
gate on REX2 encodings.
Twelve `x86_vmovmsk*.hex` seeds reach every move-mask form, VEX2/VEX3, WIG,
extended long-mode registers, ignored non-long VEX3.B, invalid pp/`vvvv` and
memory controls, and truncation. The invariant fixes the GPR32-write/vector-
read schema, exact form order and AVX gate. Compiled pinned-XED oracles compare
all 589,824 long-mode selector/ModRM cells (4,608 allocated and 585,216
reserved), all 262,144 C1/E1 selector/ModRM cells in 16/32-bit modes (2,048
allocated and 260,096 reserved), and 384 legacy LES boundaries. Focused
ASan+UBSan libFuzzer campaigns with extras ON and OFF each replay the complete
source corpus and finish 6,000 executions without a finding.
Twenty-five `x86_vmovrs*.hex` seeds reach every byte/dword/qword/word form and
vector width, mask merge/zero, 16/32/64-byte disp8 scaling, B4/X4 APX address
extensions, reserved EVEX controls, register-source rejection, and truncation.
The invariant fixes forms 5897--5908, memory-only operand access, exact AVX10
MOVRS width-group selection, mask semantics, and the independent APX gate.
Twenty-nine `x86_vmovsd_*.hex` seeds reach all seven VEX/EVEX scalar-double
forms, both opcode directions, masks, LL-ignore, extended registers, APX B4/X4
addressing, non-long ignored fields, every reserved control, and truncation
precedence. The invariant re-derives forms 5909--5915 and locks the XMM/m64
access schema, merge-destination read/write access, AVX versus AVX512F-scalar
selection, scalar disp8 scaling, mask state, and the independent APX gate.
Forty `x86_vmovsh*.hex`, `x86_vmovshdup*.hex`, `x86_vmovsldup*.hex`, and
shared-control `x86_vmovdup*.hex` seeds reach all 23 exact scalar-half and
duplicate-move forms. They span VEX/EVEX, 128/256/512-bit duplicate widths,
memory/register directions, masks, two- and 16/32/64-byte disp8, APX B4/X4,
reserved controls, non-long V', collisions, and truncation. The matching 69
corpus rows add profile/runtime, both syntaxes, malformed-neighbor, and
extras-OFF coverage; the focused suite exhausts 9,092,608 allocated,
3,337 target-owned invalid, and 2,308 delegated collision-selector cells.
Pinned XED agrees on all 42 valid and 18 reserved-control corpus witnesses.
Twenty-nine `x86_vmovss_*.hex` seeds reach all seven VEX/EVEX scalar-single
forms, both opcode directions, masks, LL-ignore, extended registers, APX B4/X4
addressing, non-long ignored fields, every reserved control, and truncation
precedence. The invariant re-derives forms 5939--5945 and locks the XMM/m32
access schema, merge-destination read/write access, AVX versus
`AVX512F_SCALAR` selection, four-byte disp8 scaling, mask state, and the
independent APX gate.
Twenty-eight `x86_vmovupd_*.hex`/`x86_vmovups_*.hex` seeds reach both VEX
widths, all three EVEX widths, both opcode directions, register and memory
forms, masks, APX addressing, malformed controls, delegated collisions, and
truncation. Their invariant re-derives forms 5946--5979, operand access,
feature/runtime selection, mask legality, and Full-tuple displacement scaling.
Twenty `x86_vmovw_*.hex` seeds reach all seven forms 5980--5986 and both
opcode directions of shared register form 5986. They cover the GPR32, m16,
and XMM shapes, WIG `66`/F3-W0 feature split, WIG W1, Tuple2 disp8, APX B4/X4,
high and non-long registers, reserved prefix/control states, neighbor
delegation, and truncation. Their invariant locks two-operand access, exact
`AVX512_FP16_128N` versus `AVX512_MOVZXC_128` admission, independent APX
gating, no-mask/no-decorator state, and the per-form allocation counts; 38
corpus rows retain profiles, both syntaxes, malformed controls, and extras-OFF
ownership.
Twenty-five `x86_vmpsadbw*.hex` seeds reach all ten exact forms, both VEX
widths and all three EVEX widths, register/memory sources, imm8, merge/zero
masks, Full-tuple disp8, APX B4/X4 and high-register routes, non-long controls,
reserved prefixes/decorators, family collisions, and truncation. Their
invariant re-derives form and operand identity, exact AVX/AVX2/
AVX512-MEDIAX admission, mask access, displacement scaling, and APX isolation;
51 corpus rows retain profiles, both syntaxes, malformed controls, and
extras-OFF ownership.
Twenty-seven `x86_virtualization_*.hex` seeds reach exact forms
5997--6005/6048--6053, REX2
high-register and high-address paths, ignored and reserved prefixes,
VMCLEAR/EXTRQ/INSERTQ collision ownership, profile rejection, and truncation.
Their invariant locks operand access, VMX/SVM/VTX and privileged groups,
status-flag metadata, address-size-sensitive VMRUN, independent APX-F
admission, and the focused VMREAD/VMWRITE, pointer/fixed, and VMXOFF sweeps;
64 corpus rows retain both syntaxes and extras-OFF behavior.
Twenty-three `x86_vmulbf16*.hex` seeds reach exact forms 6006--6011 at all
three widths, register, Full-memory, BF16-broadcast, mask, disp8, high-register,
APX B4/U0/X4, reserved-control, neighbor-collision, and truncation paths. Their
invariant locks width-specific form/group/runtime identity, operands, access,
broadcast and displacement scaling, APX ownership, and the full ModRM/P1/P2
partitions; 37 corpus rows retain profiles, both syntaxes, and extras-OFF
behavior.
Forty-two `x86_vmulph*.hex`, `x86_vmulsh*.hex`, and `x86_vmul_fp16*.hex`
seeds reach forms 6022--6027 and 6042--6043, including every form identity,
width, memory/register shape, mask, broadcast, disp8, embedded-rounding,
high-register and APX route, reserved control, BF16/F2 neighbor, and
truncation boundary. Their invariant re-derives exact form, group, operand,
decorator, feature-route, and APX semantics; 59 corpus rows retain profile,
formatting, malformed-control, and extras-OFF behavior.
Forty `x86_vmul*.hex` classic floating-multiply seeds reach every form
6012--6021, 6028--6041, and 6044--6047, plus mask, broadcast, tuple-disp8,
embedded-rounding, APX B4/U0/X4, prefixed-VEX,
reserved-control, profile, and truncation boundaries. Their invariant
re-derives the exact form, operands, access, decorators, width/scalar group,
feature route, prefix layout, and APX isolation; 59 corpus rows retain both
syntaxes and extras-OFF behavior.
Twenty-eight `x86_vorpd_*.hex`/`x86_vorps_*.hex`/`x86_vor_fp_*.hex` seeds
reach every form 6054--6073 plus mask, broadcast, compressed-displacement,
high-register, APX B4/U0/X4, reserved register-`EVEX.b`, LL, collision, and
truncation paths. Their invariant exhausts 9,216 VEX allocations, 8,064
ordinary EVEX allocations plus 4,224 reserved controls, and the bounded B4
and U0 extension spaces while locking form, operand, feature, formatter, and
extras-OFF behavior against pinned XED.
Twenty-one `x86_vp2intersect*.hex` seeds reach all twelve exact forms
6074--6085, odd/even destination aliases, register and memory sources,
broadcast, compressed displacement, high registers, APX addressing, reserved
EVEX controls, profile boundaries, and truncation. Their invariant exhausts
the 786,432-control lattice as 8,064 allocated and 778,368 reserved cells and
locks the two-write-operand ABI plus canonical `kN+1` formatting; 29 corpus
rows retain both syntaxes and extras-OFF ownership.
Sixty `x86_vpabs*.hex` seeds reach all 36 exact `VPABSB/D/Q/W` forms
6088--6123 in pinned-XED order, including every VEX/EVEX width, register and
memory sources, mask merge/zero, dword/qword broadcast, Full and scalar disp8,
high registers, non-long extension aliases, APX addressing, reserved controls,
collisions, profile gates, and truncation. Their invariant and focused suite
classify 9,216 VEX allocations plus 580,608 reserved controls and 259,200 EVEX
allocations plus 527,232 reserved controls; 82 corpus rows retain both
syntaxes and extras-OFF ownership.
Sixteen `x86_vpcmov_*.hex` seeds reach all six exact XMM/YMM forms 6410--6415,
both memory positions, the register W aliases, low/high selector-nibble
boundaries, high registers and addresses, non-long aliases, reserved prefixes
and pp, and truncation before SIB or selector completion. Their invariant and
focused suite require four vector operands, AVX+XOP groups, selector-offset
metadata with no immediate operand, exact form collapse, CPU/runtime gates,
canonical formatting, and extras-OFF ownership; 25 corpus rows retain the same
boundaries against pinned XED and LLVM 21.
Sixteen `x86_vpperm_*.hex` seeds reach all three exact XMM forms 7686--7688,
both memory positions, the register W alias, selector-nibble boundaries, high
registers and SIB addresses, non-long register/address aliases, reserved
prefix/L/pp controls, and truncation before SIB or selector completion. Their
invariant and focused suite require four vector operands, AVX+XOP groups,
selector-offset metadata with no immediate operand, exact form collapse,
runtime/profile gates, canonical formatting, and extras-OFF ownership; 27
corpus rows retain the same boundaries against pinned XED and LLVM 21.
Eighteen `x86_vpblendvb_*.hex` seeds reach all four exact XMM/YMM forms
6334--6337, register and memory inputs, every selector-nibble boundary, high
registers and SIB/RIP-relative addresses, non-long aliases, address/segment
overrides, reserved W/pp/prefix controls, and truncation before SIB or selector
completion. Their invariant and focused suite require four equal-width vector
operands, AVX for XMM and AVX2 for YMM, selector-offset metadata with no
immediate operand, exact form identity, runtime/profile gates, canonical
formatting, and extras-OFF ownership; 34 corpus rows retain the same boundaries
against pinned XED and LLVM 21.
Thirty-six `x86_vpbroadcast{b,w}_*.hex` seeds reach all eight exact forms
6342/6343/6347/6348 and 6387/6388/6392/6393, register and byte/word-memory
sources, both widths, high
registers and addresses, all modes, the non-long B' alias, LES collisions,
reserved W/pp/`vvvv` and legacy prefixes, sibling isolation, and incomplete
SIB/displacement truncation. Their invariant and exhaustive suite partition
12,288 allocated and 1,560,576 reserved controls, check all 53 profiles, and lock
AVX+AVX2 groups with most-specific AVX2 runtime admission, both syntaxes,
formatter forgery rejection, and extras-OFF ownership. Sixty-two corpus rows
retain the same contracts; pinned XED data/kit and XED/LLVM 21 samples
provide independent checks.
Thirty-six `x86_vpbroadcast{d,q}_*.hex` seeds reach exact forms
6355/6356/6360/6361 and 6374/6375/6379/6380 with dword/qword register and
memory sources. The invariant and exhaustive suite lock the same mode,
address, prefix, profile/runtime, late-truncation, formatter, and extras-OFF
contracts while partitioning 12,288 allocated and 1,560,576 reserved controls;
62 corpus rows and pinned XED/LLVM 21 samples retain the boundary.
Sixteen `x86_vpcmpeqq_*.hex` seeds reach all four exact VEX forms 6454--6457,
both vector lengths and source shapes, W=0/1 aliases, high registers and SIB/
RIP-relative addresses, every mode, non-long aliases, address/segment
overrides, reserved pp and legacy-prefix controls, the EVEX sibling, and
truncation. Their invariant and exhaustive suite lock write/read/read access,
AVX versus AVX2 admission, exact form identity, both syntaxes, formatter
forgery rejection, and extras-OFF ownership across 196,608 allocated and
589,824 reserved controls; 30 corpus rows retain the same boundary.
Sixteen `x86_vblend*.hex` seeds reach all eight exact VEX `VBLENDPD` and
`VBLENDPS` forms 3527--3534, W aliases, XMM/YMM register and memory sources,
high registers and addresses, non-long aliases, address overrides, reserved
pp/prefix controls, and truncation. Their invariant and exhaustive suite lock
four-operand access, AVX-only admission at both widths, exact form identity,
both syntaxes, formatter forgery rejection, and extras-OFF ownership across
393,216 allocated and 1,179,648 reserved controls; 32 corpus rows retain the
same boundary against pinned XED and LLVM 21.
Twenty-three `x86_vblendv*.hex` seeds reach all eight exact VEX `VBLENDVPD`
and `VBLENDVPS` forms 3535--3542, XMM/YMM register and memory sources,
selector-nibble endpoints, W/pp/prefix reservations, high registers and
addresses, every mode, non-long C4/LES and extension aliases, address
overrides, and truncation. Their invariant and exhaustive suite lock four
vector operands with selector-offset but no immediate metadata, AVX-only
admission at both widths, exact form identity, both syntaxes, formatter forgery
rejection, and extras-OFF ownership across 196,608 allocated and 1,376,256
reserved controls; 38 corpus rows retain the boundary against pinned XED and
LLVM 21.
Eighteen `x86_vbroadcast128*.hex` seeds reach both exact
`VBROADCASTF128`/`VBROADCASTI128` forms, memory/address endpoints, all modes,
non-long aliases, allocated and reserved controls, AVX/AVX2 gates, formatting,
truncation, and extras-OFF ownership. The exhaustive suite classifies 4,608
allocated and 1,568,256 reserved controls; 39 corpus rows retain the boundary
against pinned XED and LLVM 21.
Eighteen `x86_vbroadcast{sd,ss,scalar}*.hex` seeds reach all six exact VEX
`VBROADCASTSD`/`VBROADCASTSS` forms, scalar memory and full-XMM register
sources, XMM/YMM destinations, high registers and addresses, every mode,
non-long aliases, allocated and reserved controls, legacy-prefix and late-
truncation boundaries, AVX/AVX2 gates, formatting, and extras-OFF ownership.
The exhaustive suite partitions 1,572,864 controls into 9,216 allocated and
1,563,648 reserved; 41 corpus rows retain the XED/LLVM 21-verified boundary.
Fourteen `x86_{vextract,vinsert,lane}128_*.hex` seeds reach all eight exact VEX
`VEXTRACTF128`/`VEXTRACTI128` and `VINSERTF128`/`VINSERTI128` forms, their
register/memory shapes, imm8 lane controls, non-long B and insert-`vvvv`
aliases, reserved `vvvv`/W/L/pp/prefix controls, an EVEX neighbor, and late
truncation. Their invariant and focused suite lock exact three- versus
four-operand access, AVX/AVX2 admission, form identity, both syntaxes,
formatter forgery, and extras-OFF ownership across 104,448 allocated and
3,041,280 reserved controls; 23 corpus rows retain the XED/LLVM 21 boundary.
Fifteen `x86_{vextractps,vinsertps,ps_lane}_*.hex` seeds reach all four exact
VEX `VEXTRACTPS`/`VINSERTPS` forms 4567/4569/5579--5580, both register and
memory shapes, both W values, every mode, non-long aliases, reserved fields
and legacy prefixes, high-register EVEX neighbors, and late truncation. Their
invariant and focused suite lock exact operand access, AVX admission, VEX-only
identity, both syntaxes, formatter forgery rejection, and extras-OFF ownership
across 104,448 allocated and 1,468,416 reserved controls; 24 corpus rows retain
the XED/LLVM 21 boundary.
Fifteen `x86_vperm2*.hex` seeds reach all four exact VEX
`VPERM2F128`/`VPERM2I128` forms 6770--6773, register and m256 shapes, all 16
NDS `vvvv` sources, every mode, non-long aliases, reserved W/L/pp and legacy-
prefix controls, absence of an EVEX sibling, and late truncation. Their
invariant and focused suite lock exact operand access, AVX versus AVX2
admission, VEX-only identity, both syntaxes, formatter forgery rejection, and
extras-OFF ownership across 98,304 allocated and 1,474,560 reserved controls;
23 corpus rows retain the pinned-XED and LLVM 21 boundary.
Fifteen `x86_vpermd*.hex`/`x86_vpermps*.hex` seeds reach exact VEX
`VPERMD`/`VPERMPS` forms 6780--6781/6886--6887, register and m256 sources,
all modes, non-long B/`vvvv` aliases, address/segment overrides, reserved
W/L/pp, wrong-map and legacy-prefix controls, an EVEX sibling, and late
address truncation. Their invariant and focused suite lock exact operand
access, AVX2 admission, both syntaxes, formatter forgery rejection, and
extras-OFF ownership across 98,304 allocated and 1,474,560 reserved controls;
25 corpus rows retain the pinned-XED and LLVM 21 boundary.
The 1,679 reviewed ARM `.hex` seeds
separately reach
each new scalar-register route--shifted
arithmetic, carry arithmetic, conditional select, divide/variable shift, and
multiply-add/subtract--plus the logical-immediate route and reserved
shifted/logical encodings, SVE predicate-logical valid/reserved paths, SVE
unpredicated integer-arithmetic valid/reserved-width paths, SVE vector
ZIP/UZP/TRN valid/reserved-selector paths, and the SVE table-lookup/MOV block's
valid and adjacent-unowned paths. Thirty-four SHA1/SHA256 seeds and 20 fixed
A64 SHA3/SHA512/SM3/SM4 seeds cover the completed crypto blocks and their SVE
name collisions. `a64_sve_tblq.hex` independently reaches the
disjoint `TBLQ` descriptor; `a64_sve_predicated_integer.hex` and
`a64_neon_vector_permute.hex` reach the version-11.6 classes. The predicated
unary seeds separately reach an allocated merge form, an allocated zeroing
form, and a reserved width/control boundary added in version 11.7. The focused
suites separately cover the selector-15-invalid space and exhaust all 131,072
`TBLQ` words. Two version-11.8 seeds independently reach allocated and reserved
predicated vector-shift controls; the focused suite exhausts all 524,288 words
in that exact classifier. Two version-11.9 seeds independently reach allocated
and reserved predicated immediate-shift controls; its focused suite exhausts
all 524,288 words in the disjoint `0x04008000` classifier. Two version-11.10
seeds reach allocated and reserved SVE integer vector compares; the focused
suite exhausts all 8,388,608 words in the exact `0x24000000` classifier. The
three version-11.11 seeds reach signed, unsigned, and reserved SVE integer
compare-with-immediate controls; the focused suite exhausts all 12,582,912
words in the two exact envelopes. Two version-11.12 seeds reach allocated and
reserved SVE floating compare-with-zero controls; the focused suite exhausts
all 131,072 words in the exact classifier. Four version-11.13 seeds reach
`FCMUO`, `FACGE`, `FACGT`, and the reserved operation-six vector-compare path;
the focused suite exhausts all 4,194,304 words. At the version-11.13
checkpoint, the enabled ARM corpus contained 2,211 rows. Five version-11.14
seeds reach representative allocated and reserved
destructive predicated FP-binary controls. Two version-11.15 seeds reach an
allocated and a reserved baseline SVE/SME floating-point fast reduction. Two
version-11.16 seeds reach allocated `FADDA` and its reserved byte-width form.
Six version-11.17 seeds reach merging and zeroing FP-unary forms, both tail
operation masks, a reserved operation/width, and an adjacent unowned control.
Eight single-word version-11.18 ARM seeds reach the H/S/D forms of `FRECPE`
and `FRSQRTE` plus both reserved byte-width estimate controls.
Eighteen version-11.19 ARM seeds independently reach every fixed-width scalar
H/S/D and vector 4H/8H/2S/4S/2D estimate arrangement plus both reserved
one-lane-D controls. Eight version-11.20 ARM seeds reach every F64MM Q-element
ZIP/UZP/TRN selector and both reserved selector values. Eight version-11.21
ARM seeds reach all six allocated `SCVTF`/`UCVTF` H/S/D-to-H paths and both
reserved selectors.
Eight version-11.22 ARM seeds reach every signed and unsigned S-to-S, D-to-S,
S-to-D, and D-to-D `SCVTF`/`UCVTF` form in the four new exact envelopes.
Twenty-two version-11.23 ARM conversion seeds reach all six baseline merging
`FCVT` precision conversions, all fourteen allocated `FCVTZS`/`FCVTZU` forms,
the reserved selectors, and the then-unowned BFCVT neighbor. Version-11.24 ARM
BFCVT seeds reach the exact merging form, its feature boundary, and adjacent
allocated or reserved controls. Version-11.25 replaces the obsolete unowned
neighbors with five exact merging/zeroing BFCVT/BFCVTNT, feature-boundary, and
reserved-control seeds, a net increase of three ARM files. Seven version-11.26
seeds reach SME2 S-to-H `BFCVT`/`BFCVTN`, SME2+FP8 H-to-B `BFCVT`,
SVE2/SME2+FP8 H-to-B `BFCVTN`, and allocated/reserved selector boundaries.
Thirteen post-12.0 seeds reach zeroing S-to-H `FCVT`, all seven
FEAT_SVE_B16B16 predicated binary names plus their reserved operation selector,
and A64 `DCPS1`/`DCPS2`/`DCPS3` with a reserved exception selector. Six more
reviewed seeds cover SVE indexed `DUP`/preferred `MOV`, the four-form FP8
narrowing row, the complete SME2 pair-conversion row, T32 `DCPS1`--`DCPS3`,
and the scalar `FCVTZU` fixed-form oracle path.
Four additional seeds reach SVE/SME vector-length arithmetic, the complete
Advanced SIMD reversal arrangements, and both arithmetic and logical SVE/SME
integer-reduction rows. Four more independently reach the SME2 two-vector
`SQCVT`, `SQCVTU`, `UQCVT`, and FP8 `FCVT` forms that complete generated forms
4312--4324. Four adjacent seeds cover SME2 `SUNPK`/`UUNPK` and the SME2+FP8
two-vector widening forms 4325--4334, including an upper-register boundary.
Eleven further seeds reach all three SVE2.1-or-SME2 narrowing operations,
their unallocated bit-5 neighbor, all four SME2 two-vector FRINT operations
and reserved controls, plus SME_F16F16 `FCVT`/`FCVTL`.
Twenty-seven `a64_sme2_multi4_*.hex` seeds reach every SME2 four-vector form
4341--4362, upper/aligned list boundaries, FP8/profile paths, B/H/S/D/Q
permutations, and representative reserved size/operation controls.
Six reviewed `a64_advsimd_cls*`/`a64_advsimd_cnt*`/`a64_advsimd_clz*` seeds
pair one allocated and one reserved word for each exact Advanced SIMD
bit-count operation. Eight reviewed `a64_sme_fmul_*`/`a64_sme_bfmul_*` seeds
reach the two- and four-register list/list and list/scalar envelopes for forms
4363--4370. Their focused strict suites exhaust 24,576 Advanced SIMD words and
38,912 SME words, and additionally lock LLVM 21 legal/reserved or rejected
assembly evidence, canonical formatting, endian parity, and extras-ON/OFF
fuzz invariants. Five reviewed ZA load/store seeds reach zero- and nonzero-
`MUL VL` displacements, W12/W15, X/SP, LDR/STR, and a fixed-bit neighbor of
forms 4381--4382. Their focused suite exhausts all 4,096 allocated words and
locks runtime-sized memory metadata, the `VL_SCALED` flag contract, canonical
formatting, profile gates, endian/generic dispatch, fixed neighbors,
truncation, and extras-ON/OFF ownership. Four reviewed ZT0 load/store seeds
reach an allocated LDR,
an allocated STR using SP, a nonzero ZT-selector reserved word, and a reserved
operation under the 8,192-word forms-4383--4384 parent envelope. Its focused
suite classifies 64 allocated and 8,128 reserved words and locks operand
access, SME2/profile gates, formatting, endian/generic-dispatch parity,
fixed-bit neighbors, truncation, and extras-ON/OFF ownership.
Four reviewed A64 UDF seeds span immediate zero, a middle value, the maximum,
and a fixed-bit neighbor. The focused suite exhausts all 65,536 form-4387
immediates and locks its successful interrupt-group/no-instruction-flags
contract, every A64-capable profile, formatting, transport, truncation, and
extras-ON/OFF ownership against pinned AARCHMRS plus LLVM 21 and Capstone.
Five A64 WFxT seeds independently reach `WFET X0`, `WFET XZR`, `WFIT X17`,
`WFIT XZR`, and a fixed-bit neighbor. The focused suite exhausts both 32-word
leaves and locks XZR-versus-SP rendering, profile/runtime admission, endian
and generic transport, formatting, malformed neighbors, truncation, and
extras-ON/OFF ownership against LLVM 21 and Capstone.
Eleven baseline-SME MOVA seeds independently reach every B/H/S/D/Q predicated
insert and extract form plus the reserved Q-control boundary. Their focused
suite covers 10,880 field combinations and locks the preferred `MOV` alias,
tile/predicate/Z access, profile gates, endian transport, and formatter-schema
rejection against pinned AARCHMRS and LLVM 21.
Twenty-two SME2 multi-register MOVA seeds reach every pair/quad B/H/S/D insert
and extract leaf, both whole-ZA VGx forms, and the reserved quad-control
neighbors. The 26 matching ARM corpus rows also cover Apple A18 admission,
big-endian transport, and truncation; the focused suite checks 12,288 bounded
cases plus the reserved quad controls.
Seventeen SME2.1 MOVAZ seeds reach all five single-register B/H/S/D/Q leaves,
all pair/quad B/H/S/D leaves, both whole-ZA.D VGx2/VGx4 leaves, and the
reserved single-Q and quad control boundaries. The 20 matching ARM corpus rows
also lock `CPU_ANY` admission, Apple A18 rejection, canonical MOVAZ text,
big-endian transport, and truncation; the focused suite checks all 26,624
allocated control words plus the reserved controls.
Ten FlagM seeds independently reach fixed `CFINV`/`XAFLAG`/`AXFLAG`, minimum
and maximum `RMIF`, `SETF8`/`SETF16`, the reserved RMIF `o2` half, a reserved
SETF control, and the adjacent PSTATE/MSR neighbor. The matching 13 ARM corpus
rows cover forms 4499--4501/5696--5698, canonical operands, status-flag writes,
`CPU_ANY`-only admission, both byte orders, truncation, and extras-OFF
ownership.
Ten SVE FFR seeds—`a64_sve_ffr_rdffr_p15.hex`,
`a64_sve_ffr_rdffr_pred_p0.hex`, `a64_sve_ffr_rdffr_pred_p15.hex`,
`a64_sve_ffr_rdffr_pred_reserved.hex`, `a64_sve_ffr_rdffr_reserved.hex`,
`a64_sve_ffr_rdffrs_p15.hex`, `a64_sve_ffr_setffr.hex`,
`a64_sve_ffr_setffr_reserved.hex`, `a64_sve_ffr_wrffr_p15.hex`, and
`a64_sve_ffr_wrffr_reserved.hex`—reach all predicated and unpredicated
`RDFFR`, `RDFFRS`, `WRFFR`, and `SETFFR` forms plus representative reserved
parent-envelope controls. The matching 16 corpus rows cover forms
2562--2564/2617--2618, both byte orders, `CPU_ANY`/A64FX admission, canonical
text, truncation, and extras-OFF ownership; the focused suite exhausts 545
valid and 611 reserved words.
Twenty `a64_sve_element_count_*.hex` seeds reach every non-saturating vector
and scalar `INC*`/`DEC*`/`CNT*` form plus both reserved parent controls. The
matching 25 corpus rows cover forms 2374--2391, pattern and multiplier
boundaries, SVE-or-SME profile admission, both byte orders, canonical text,
truncation, and extras-OFF ownership; the focused suite exhausts 294,912
allocated and 98,304 reserved words.
Twenty `a64_sve_*count*.hex`/predicate-count seeds reach representative vector,
W, X, tied `Xd, Wd`, classic `CNTP`, PN-counter `CNTP`, allocated predicate
increment/decrement, and reserved controls across the original 62-form tranche. The
invariant fixes form/name identity, scalable and classic-CNTP predicated flags,
typed predicate reads, destination access, pattern/multiplier immediates, and
the SVE-or-SME versus SVE2.1-or-SME2 gates. The focused suite exhausts 787,456
allocated family words and 359,424 reserved words. Six additional
`a64_sve_firstp_*.hex`/`a64_sve_lastp_*.hex` seeds reach B/H/S/D operands,
XZR, and both operations. Their exact invariant and dedicated suite cover all
65,536 `FIRSTP`/`LASTP` allocations, the three-operand `Xd, Pg, Pn.<T>` schema,
write/read/read access, typed `Pn`, scalable/predicated flags, the
SVE2.2-or-SME2.2 gate, endian transport, canonical formatting, and
extras-OFF ownership.
Fourteen `a64_sve_brk*.hex`/`a64_sve_predicate_break_*.hex` seeds reach every
predicate-break operation, both allocated BRKA/BRKB governing modes, the
tied BRKN source, flag-setting forms, and representative reserved controls.
Their invariant fixes form identity, byte predicate metadata, operand count
and access, scalable/predicated/NZCV flags, exact SVE-or-SME admission, endian
transport, formatting, truncation, and extras-OFF ownership; 23 corpus rows
preserve the same boundaries.
Fifteen reviewed predicate-control `.hex` seeds reach all six predicate-control
forms, every element size and representative named, numeric, and default
patterns, tied destination boundaries, exact flag combinations, and all three
reserved parent classes. Their invariant fixes forms 2556--2561, operands,
typing/access, SVE-or-SME admission, endian transport, formatting, truncation,
and extras-OFF ownership; 33 corpus rows preserve the same contracts.
Fifteen `a64_sve2p1_psel_*.hex` seeds reach every B/H/S/D lane boundary,
W12--W15, high predicate registers, both untyped `tsz=0000` residuals, the
bit-4 neighbor, big-endian transport, and truncation. Their invariant
exhausts 491,520 allocated words, 32,768 invalid residual words, and 524,288
delegated neighbor words while locking form 2565,
`Pd, Pn, Pm.T[Wv, lane]`, access, scalable-only metadata,
SVE2.1-or-baseline-SME admission, canonical text, and
extras-OFF ownership; 18 corpus rows preserve the same boundaries.
Twenty-two `a64_sve_integer_immediate_*.hex` seeds reach arithmetic forms
2619--2630 and their parent residuals. Fifteen additional
`a64_sve_dup_immediate_*.hex`/`a64_sve_fdup_immediate_*.hex` seeds reach forms
2631--2632, preferred `MOV`/`FMOV`, signed shifted integers, expanded H/S/D
floating immediates, reserved byte controls, endian transport, and
truncation. The combined invariant classifies all 2,097,152 parent words; the
broadcast suite separately exhausts 57,344 valid and 8,192 reserved DUP words
plus 24,576 valid and 8,192 reserved FDUP words. The 44 matching corpus rows
retain profile, formatter, transport, and extras-OFF behavior, and LLVM 21
confirms 1,792 representative DUP plus 768 FDUP cases.
Twelve `a64_sve_dot_*.hex`/`a64_sve2p3_dot_*.hex` seeds reach both names and
all B-to-S, H-to-D, and B-to-H arrangements, high registers, named-profile
boundaries, both reserved `size=00` controls, big-endian transport, and
truncation. The invariant re-derives forms 2633--2636, tied accumulator
access, exact baseline versus p3 admission, scalable-only flags, and the full
196,608 allocated/65,536 reserved parent partition; 19 corpus rows retain
formatting and extras-OFF ownership.
Seventeen `a64_sve_{sqdmlalbt,sqdmlslbt,cdot,cmla,sqrdcmlah}*.hex` seeds
reach every new name, every legal arrangement and rotation, both byte orders,
reserved-width controls, adjacent delegation, and truncation. Their invariant
re-derives forms 2637--2641, tied accumulator access, exact SVE2-or-SME
admission, scalable-only flags, and the exhaustive 1,507,328 allocated plus
327,680 reserved word partition; 31 corpus rows retain formatting, profile,
transport, and extras-OFF ownership.
Eighteen `a64_sve_{sml,uml,sqdml,sqrdml}*.hex` seeds reach forms 2642--2655,
including every name, low/high registers, widening and same-width arrangements,
reserved `size=00`, SME-only profile admission, big-endian transport, and
exact adjacent USDOT dispatch. Their invariant locks the 1,441,792 allocated and
393,216 reserved partition; 32 corpus rows retain formatting, profile,
transport, truncation, and extras-OFF ownership.
Fifteen `a64_sve_{mla,mls}_indexed*.hex` seeds reach forms 2722--2727 across
all H/S/D widths, low/high lanes and registers, the width-dependent Zm limits,
truncation, and the adjacent indexed rounding family. Their invariant locks
the destructive read/write accumulator, read-only sources, scalable-only metadata, and exact
SVE2-or-SME admission for all 262,144 allocated words. Twenty-two corpus rows
retain profile, endian/generic, formatting, forgery, collision, and extras-OFF
behavior.
Fifteen total `a64_sve_sqrdml{ah,sh}_indexed*.hex` family seeds reach exact
indexed `SQRDMLAH`/`SQRDMLSH` forms 2728--2733 across H/S/D, both lane
extremes, each width-dependent Zm limit, endian transport, truncation, and the
adjacent indexed `USDOT` leaf. Their invariant locks destructive `Zda`,
read-only sources, scalable-only metadata, and exact SVE2-or-SME admission for
all 262,144 allocated words. Twenty corpus rows retain profile, formatting,
forgery, collision, and extras-OFF behavior; LLVM 21 and pinned AARCHMRS
confirm the encoding boundary.
Three `a64_sve_usdot*.hex` seeds reach low/high-register allocations and a
reserved size sibling. The exact invariant locks form 2656, its three operand
arrangements and access modes, the conjunctive SVE/SME-plus-I8MM gate, and the
complete 32,768 allocated/98,304 reserved parent partition; 11 corpus rows
retain named-profile, endian, formatting, truncation, forgery, and extras-OFF
behavior.
Eight `a64_sve_{u,s}dot_indexed_*.hex` seeds reach low, mixed, and high indexed
`USDOT`/`SUDOT` plus truncation. Their invariant exhausts all 65,536
form-2734/2735 words and locks read/write `Zda.S`,
read-only `Zn.B` and `Zm.B[lane]`, scalable-only metadata, the conjunctive
SVE/SME-plus-I8MM gate, all 38 profile checks, endian/generic transport,
formatting and forgery rejection, and extras-OFF ownership. Eighteen corpus
rows retain the same boundaries, and LLVM 21 matches every allocated word.
Six `a64_sve_aes*.hex` seeds reach `AESMC`/`AESIMC` low/high registers,
reserved size space, and truncation. Their invariant and focused suite lock
forms 2903--2904, the tied read/write `.B` operands, FEAT_SVE_AES admission,
all 64 allocated and 192 reserved words, formatting, and extras-OFF ownership;
13 corpus rows retain those contracts.
Nine `a64_sve_{aese,aesd,sm4e,crypto_binary}*.hex` seeds reach all three
crypto-binary forms, low/high registers, two reserved control classes, and
truncation. Their invariant and focused suite lock forms 2905--2907, tied
read/write destinations, read-only third sources, byte versus word elements,
the independent SVE_AES/SVE_SM4 gates, and all 3,072 allocated plus 13,312
reserved words; 19 corpus rows retain profile, endian, formatting, and
extras-OFF ownership.
Four `a64_sve_predicate_unpack_*.hex` seeds reach `PUNPKLO`/`PUNPKHI`, a
high-register allocation, and truncation. Their invariant and focused suite
exhaust all 512 words in forms 2468--2469, lock `Pd.H` write plus `Pn.B` read,
scalable-vector-only metadata, SVE-or-SME admission, endian/generic transport,
canonical formatting and forged-schema rejection, and extras-OFF ownership;
12 corpus rows retain the same boundary and LLVM 21 matches every word under
both SVE and SME.
Nine `a64_sve_{sunpk*,uunpk*,unpack_*}.hex` seeds reach all four vector-unpack
forms 2456--2459, every widening size, low/high registers, both reserved
`size=00` controls, and truncation. Their invariant and focused suite exhaust
12,288 allocated and 4,096 reserved words, lock exact typed write/read
operands, scalable-vector-only metadata, SVE-or-SME admission, endian/generic
transport, canonical formatting and forged-schema rejection, and extras-OFF
ownership. Twenty-two corpus rows retain the boundary; LLVM 21 matches every
allocated formula word and reports every reserved word unknown.
Ten `a64_sve_{sri,sli,shift_insert}*.hex` seeds reach both exact shift-insert
forms 2846--2847, B/H/S/D immediate endpoints, low/high registers, reserved
encoded-immediate controls, both byte orders, and truncation. Their invariant
and focused suite lock tied read/write `Zdn.T`, read-only `Zn.T`, the decoded
read immediate, scalable-vector-only metadata, SVE2-or-SME admission,
formatting and forged-schema rejection, and extras-OFF ownership across
245,760 allocated and 16,384 reserved words. Twenty-one corpus rows retain the
same boundary; LLVM 21 matches the complete allocated and reserved domain.
Seven `a64_advsimd_{bsl,bit,bif,bitwise}*.hex` seeds reach both vector widths,
low/high registers, the three exact Advanced SIMD select leaves, an adjacent
logical-family control, and truncation. Their invariant and focused suite lock
tied Vd plus read-only Vn/Vm, NEON admission, endian/generic transport,
formatting and extras-OFF ownership across 196,608 allocated words; 18 corpus
rows retain the LLVM 21-verified boundary.
Eleven `a64_advsimd_{addhn,subhn,raddhn,rsubhn,high_narrow}*.hex` seeds reach
all four exact high-narrow leaves, every base/`*HN2` arrangement, all element
sizes, named-profile boundaries, both reserved size-three halves, big-endian
transport, and truncation. Their invariant and focused suite lock write-only
low-half versus read/write high-half destinations, 16-byte source reads,
SIMD-only metadata, NEON admission, canonical formatting, forged-schema
rejection, and extras-OFF ownership across 786,432 allocated and 262,144
reserved words; 22 corpus rows retain the AARCHMRS/LLVM 21 boundary.
Thirteen `a64_advsimd_*` widening add/sub seeds reach exact Advanced SIMD
`SADDL`/`SADDW`/`SSUBL`/`SSUBW` and `UADDL`/`UADDW`/`USUBL`/`USUBW`
forms 6089--6092/6104--6107. They cover base and `2` spellings, every
B/H/S-to-H/S/D arrangement, low/high registers, both byte orders, the
reserved `size=3` quarter, fixed neighbors, and truncation. Their invariant
and focused suite lock write/read/read long-versus-wide operands, NEON
admission, canonical formatting with independent raw/form/name ownership,
forged-schema rejection, and extras-OFF ownership across 1,572,864 allocated
and 524,288 reserved words; 34 corpus rows retain the pinned-AARCHMRS and
LLVM 21 boundary.
Eight `a64_advsimd_*absolute_difference_long*.hex` and operation-specific
seeds reach exact Advanced SIMD `SABAL`/`SABDL`/`UABAL`/`UABDL` forms
6094/6096/6109/6111, every base/`2` and B/H/S-to-H/S/D arrangement, low/high
registers, both byte orders, the reserved size-three quarter, neighboring
encodings, and truncation. Their invariant and focused suite lock read/write
accumulators versus write-only long differences, NEON admission, canonical
formatting with independent raw/form/name ownership and exact SVE sibling
separation, forged-schema rejection, and extras-OFF ownership across 786,432
allocated and 262,144 reserved words; 22 corpus rows retain the pinned-
AARCHMRS and LLVM 21 boundary.
Ten `a64_advsimd_{smlal,smlsl,smull,umlal,umlsl,umull,widening_multiply}*.hex`
seeds reach all six exact baseline widening-multiply leaves, base and `2`
spellings, B/H/S-to-H/S/D arrangements, both accumulator access modes, the
reserved size-three quarter, neighboring saturating leaves, and truncation.
Their invariant and focused suite lock SIMD-only metadata, NEON admission,
canonical formatting with shared-name legacy/scalar/SME separation, and
extras-OFF ownership across 1,179,648 allocated and 393,216 reserved words;
28 corpus rows retain the pinned-AARCHMRS and LLVM 21 boundary.
Eleven `a64_pauth_*.hex` seeds reach all eight authenticated register-branch
forms 4510/4511/4513/4514/4525--4528, XZR targets, SP modifiers, low/high
registers, reserved parent controls, both byte orders, generic dispatch, and
truncation. Their invariant and focused suite lock exact read-only target and
modifier operands, JUMP versus CALL/LINK flags, PAuth admission, canonical
formatting with independent raw/form/name ownership, forged-schema rejection,
and extras-OFF ownership across 4,224 allocated and 3,968 reserved words; 23
corpus rows retain the pinned-AARCHMRS and LLVM 21 boundary.
Eight `a64_sve_{bext,bdep,bgrp,bitperm}*.hex` seeds reach all three SVE
BitPerm leaves, every B/H/S/D element width, the reserved selector quarter,
and truncation. Their invariant and focused suite lock write/read/read typed Z
operands, scalable-vector-only metadata, exact FEAT_SVE_BitPerm admission,
endian/generic transport, canonical formatting, forged-schema rejection, and
extras-OFF ownership across 393,216 allocated and 131,072 reserved words; 24
corpus rows retain the complete pinned AARCHMRS and LLVM 21 boundary.
Five `a64_sve_shift_sat_*.hex` seeds reach signed and unsigned low/high
allocations, the repaired `SQSHL`/`UQSHL` routes, and a reserved selector.
Their invariant locks forms 2657--2668, B/H/S/D typing, tied read/write
destination access, read-only `Pg/m` and `Zm`, scalable/predicated metadata,
the exact SVE2-or-SME gate, and the complete 393,216 allocated/131,072
reserved parent partition; 23 corpus rows retain profile, endian, formatting,
truncation, forgery, and extras-OFF behavior.
Nine `a64_sve_sat_unary_*.hex` seeds reach all eight merging/zeroing forms
2669--2676 and a reserved estimate width. Their invariant locks the complete
163,840 allocated/98,304 reserved parent partition, `.S`-only estimate versus
B/H/S/D saturating typing, destination and predicate access, exact SVE2/SME
and SVE2.2/SME2.2 gates, endian transport, formatting, truncation, forgery,
and extras-OFF behavior.
Seven `a64_sve_pointer_*.hex` seeds reach low/high `MLAPT`, representative and
high-register `MADPT`, two reserved size quarters, and truncation. Their
invariant and focused suite lock forms 2707--2708, `.D` typing, destructive
destination access, operation-specific source order, the conjunctive SVE+CPA
gate, all named-profile rejections, endian/generic transport, formatter
forgery rejection, fixed neighbors, and extras-OFF ownership. The parent
contains 65,536 allocated and 196,608 reserved words; 15 corpus rows preserve
the same contracts.
Twelve `a64_sve_quad_*.hex` seeds reach low/high `ZIPQ1`/`UZPQ1` and
`ZIPQ2`/`UZPQ2`, all three reserved parent controls, and truncation. The four
Q2 seeds complete that subset. Their invariant and focused suite lock forms
2711--2712/2714--2715, B/H/S/D typing, a write-only destination and two
read-only sources, scalable-vector metadata, the SVE2.1-or-SME2.1 gate, all
named-profile rejections, endian/generic transport, formatter forgery
rejection, TBLQ/reserved routing, and extras-OFF ownership. The complete
1,048,576-word parent contains 524,288 exact Q1/Q2 words, 131,072 allocated
TBLQ sibling words, and 393,216 reserved words; the 14 new Q2 corpus rows join
the 17 Q1 rows preserving those contracts.
Sixteen reviewed accumulating-long/halving seeds reach `SADALP`/`UADALP`
and all eight halving names, every legal width family, a reserved `size=00`
accumulating-long control, high registers, the SME profile route, big-endian
transport, and truncation. Their invariants classify 49,152 allocated plus
16,384 reserved accumulating-long words and all 262,144 allocated halving
words; 30 corpus rows retain exact operand access, formatting, profile,
forgery, and extras-OFF behavior.
Ten `a64_advsimd_addp*.hex` seeds reach exact Advanced SIMD scalar/vector
`ADDP` forms 5808/6137, both scalar register extremes, every legal vector
arrangement, the reserved 1D cell, high registers, named profiles,
big-endian transport, sibling separation, and truncation. Their invariant and
focused suite exhaust all 1,024 scalar allocations and 229,376 allocated plus
32,768 reserved vector words; 16 corpus rows retain exact operand access,
canonical formatting, formatter forgery rejection, and extras-OFF ownership.
Ten `a64_advsimd_addv*.hex` seeds reach exact Advanced SIMD `ADDV` form 6077.
They cover all five allocated B/H/S vector-to-scalar arrangements, all three
reserved Q:size cells, high registers, named profiles, big-endian transport,
sibling separation, and truncation. Their invariant and focused suite lock the
scalar destination write, vector source read, SIMD-only metadata, canonical
formatting, formatter forgery rejection, and extras-OFF ownership across 5,120
allocated and 3,072 reserved words; 13 corpus rows retain the pinned-AARCHMRS
and LLVM 21 boundary.
Eight `a64_sve_pairwise_*.hex` seeds reach all six destructive pairwise forms
2687--2692 and both reserved operation controls. Their invariant and focused
suite classify the complete parent as 196,608 allocated and 65,536 reserved
words while locking B/H/S/D typing, tied destination access, `/m` predicate,
SVE2p3-or-SME2p3 `SUBP` versus SVE2-or-SME admission for the other five,
endian transport, formatting, truncation, and extras-OFF ownership. Nineteen
corpus rows retain the same boundaries. Pinned AARCHMRS is authoritative for
all six leaves; LLVM 21 confirms the other five SVE2 encodings but does not yet
accept SVE2p3 `SUBP`.
Eight single-predicate WHILE seeds reach every
`WHILEGE/HS/GT/HI/LT/LO/LE/LS` relation across W/X, B/H/S/D, and zero-register
boundaries. Eight `a64_sve2p1_while*_pair*.hex` seeds reach every corresponding
typed even/odd predicate-pair form. Their invariants cover all 1,048,576 and
262,144 respective allocations, exact SVE/SME versus SVE2/SME and
SVE2.1/SME2 gates, NZCV metadata, formatting, endian transport, and
extras-OFF ownership.
Eight `a64_sve2p1_while*_pn.hex` seeds reach all counter-predicate
relations with typed PN destinations, X/XZR sources, and both `VLx2`/`VLx4`.
Their invariant exhausts 524,288 allocations and locks exact form identity,
NZCV/scalable/predicated metadata, SVE2.1-or-SME2 admission, formatting,
endian transport, and extras-OFF ownership. Eight counter-mask seeds reach
single and pair `PEXT`, including `p15, p0` wrapping, indexed untyped PN
sources, typed counter-predicate `PTRUE`, and representative size/index
boundaries. Their exact invariant exhausts all 3,104 allocations and locks
the same feature, formatter, transport, truncation, and disabled-build
contracts.
Exact `XEND`/`XTEST`, alias, CPU-gate, and ON/OFF
behavior remains locked by the unit and data-corpus suites.

There are no third-party disassembly include or link dependencies. Compiler and
operating-system runtime libraries are still used normally. Install the
selected target set as a CMake package with:

```powershell
cmake --install build --config Release --prefix install
```

One install prefix represents exactly one linkage/feature variant. A small
installed fingerprint records version, linkage, x86, ARM, and requested and
effective formatter and extra-opcode selections. Reinstalling the identical variant is allowed;
attempting to overlay a different variant fails before any target or header is
changed. A prefix containing older cdisasm headers/package files but no
fingerprint is rejected as well. Relative, absolute GNUInstallDirs, and staged
`DESTDIR` paths are resolved with the same rules as CMake's installer. Use a
clean, isolated prefix for each variant. The generated build
directory is also a valid `cdisasm_DIR`, and installed prefixes are relocatable.

CMake consumers link the core for every enabled API. The architecture and
formatter target names below remain accepted compatibility proxies; all point
to the same library:

```cmake
find_package(cdisasm 12.0 CONFIG REQUIRED)
target_link_libraries(generic_analyzer PRIVATE cdisasm::cdisasm)
# Compatibility spellings; each available target resolves to cdisasm::cdisasm.
target_link_libraries(x86_analyzer PRIVATE cdisasm::cdisasm_x86)
target_link_libraries(arm_analyzer PRIVATE cdisasm::cdisasm_arm)
target_link_libraries(text_printer PRIVATE cdisasm::cdisasm_format)
```

The installed package always provides the `common` component and
`cdisasm::cdisasm`. It provides the `x86` component and compatibility
`cdisasm::cdisasm_x86` proxy only when `USE_ARCH_X86=ON`, and the `arm`
component and compatibility `cdisasm::cdisasm_arm` proxy only when
`USE_ARCH_ARM=ON`. The `format` component and
`cdisasm::cdisasm_format` interface proxy are present only when
`USE_DISASM_FORMAT=ON` and at least one architecture is enabled.
`cdisasm_format.h` is installed in every variant so discovery is consistent;
when the effective feature is off, including it produces the documented
compile-time diagnostic and it declares no usable API.
All compatibility proxies resolve to the same core library; they do not
install additional binaries. Requesting a component omitted from that build
makes `find_package` fail instead of exposing an unavailable API. The generated
installed `<cdisasm/cdisasm_config.h>` records the same choices, and the CMake
package reports them as `cdisasm_USE_ARCH_X86`, `cdisasm_USE_ARCH_ARM`,
effective `cdisasm_USE_DISASM_FORMAT`, and effective
`cdisasm_USE_EXTRA_OPCODES`. It also reports the original requests as
`cdisasm_REQUESTED_USE_DISASM_FORMAT` and
`cdisasm_REQUESTED_USE_EXTRA_OPCODES`, and the physical library choice as
`cdisasm_BUILD_SHARED_LIBS`. CMake boolean spellings are canonicalized in this
metadata and the install fingerprint, so `ON`, `TRUE`, `YES`, and `1` describe
the same variant (as do `OFF`, `FALSE`, `NO`, and `0`). Because all four public feature macros are
always defined numerically, test them with
`#if USE_ARCH_X86`, `#if USE_ARCH_ARM`, `#if USE_DISASM_FORMAT`, or
`#if USE_EXTRA_OPCODES`, not
`#ifdef`. Installation always includes the version, common, umbrella, and
formatter headers, but omits disabled architecture headers,
fuzz harnesses/corpora, and opcode corpora.

Linking any installed CMake target above automatically selects the correct
declarations. A static package propagates `CDISASM_STATIC` through
`cdisasm::cdisasm` and all compatibility proxies; a shared package does not.
Non-CMake or otherwise manual Windows consumers of a static archive must define
`CDISASM_STATIC` themselves before including cdisasm headers, for example with
the compiler's `/DCDISASM_STATIC` or `-DCDISASM_STATIC` option.
On GCC/Clang platforms that macro also gives declarations hidden visibility,
so a position-independent static archive embedded in a larger shared object
does not accidentally add cdisasm entry points to the wrapper's public ABI.

Version 12 has no sibling cdisasm library graph. A default shared build places
generic dispatch, enabled explicit decoders, and enabled formatters inside the
single `cdisasm-12.dll`; programs deploy that one DLL whether they decode,
format, or do both. A static build places the same selected code in one archive
and deploys no cdisasm DLL. There are no separate formatter or architecture
libraries in either mode. System runtime DLLs remain platform dependencies.
For shared Windows builds, the real import-library name stays unsuffixed; the
runtime suffix prevents accidental cross-major binding.

## x86 C API example

This text-producing example requires `USE_DISASM_FORMAT=ON`:

```c
#include <cdisasm/cdisasm_x86.h>
#include <cdisasm/cdisasm_format.h>
#include <stdio.h>

int main(void)
{
    const uint8_t code[] = {0x55, 0x48, 0x89, 0xe5, 0xc3};
    size_t offset = 0;

    while (offset < sizeof(code)) {
        cdisasm_instruction output;
        char text[256];
        size_t text_size;
        uint32_t size = cdisasm_x86_decode(CDISASM_CPU_X86,
                                            CDISASM_MODE_64,
                                            code + offset,
                                            sizeof(code) - offset,
                                            UINT64_C(0x1000) + offset,
                                            NULL,
                                            &output);
        if (size == 0) {
            fprintf(stderr, "%s\n",
                    cdisasm_status_string((cdisasm_status)output.last_error_id));
            return 1;
        }

        text_size = cdisasm_x86_format(&output,
                                        CDISASM_FORMAT_SYNTAX_INTEL,
                                        text,
                                        sizeof(text));
        if (text_size == 0 || text_size >= sizeof(text)) {
            fputs("instruction could not be formatted\n", stderr);
            return 1;
        }
        printf("0x%llx: %s\n",
               (unsigned long long)output.address,
               text);
        offset += size;
    }
    return 0;
}
```

Run the command-line example with one hexadecimal byte per argument:

```powershell
build\Release\cdisasm_cli.exe 64 55 48 89 e5 c3
build\Release\cdisasm_cli.exe 64 --flags 0x100 c5 f8 77
build\Release\cdisasm_cli.exe 64 --flags 0xffffffffffffffff c5 f8 77
```

The optional numeric CLI value accepts decimal or C-style `0x` hexadecimal
text and initializes bitmap 0; the other seven words stay zero. Omitting it
passes the base policy, `0x100` admits AVX, and `0xffffffffffffffff` is the
bitmap-0 `CDISASM_X86_DECODE_FLAG_ALL`. The latter two calls require a
`USE_EXTRA_OPCODES=ON` library. An OFF library rejects either nonzero value with
`CDISASM_STATUS_INVALID_ARGUMENT`. The command prints each instruction in
canonical Intel syntax. It demonstrates the structured decoder and optional
formatter compiled into the same library.
A caller can
pass `CDISASM_FORMAT_SYNTAX_ATT` instead to request AT&T text without changing
the decoded instruction.

The ARM example uses the same optional formatting feature and prints canonical
A32, T32, or A64 assembly:

```powershell
build\Release\cdisasm_arm_cli.exe a64 20 04 00 91 c0 03 5f d6
build\Release\cdisasm_arm_cli.exe t32 00 bf 70 47
```

Source may include `<cdisasm/cdisasm.h>` and call `cdisasm_decode`; in version 12
it links `cdisasm::cdisasm` or `cdisasm.lib`. Pass a
`cdisasm_instruction *` with an x86 CPU ID or a
`cdisasm_arm_instruction *` with an ARM CPU ID. Version-8 formatter callers
must insert the new 32-bit formatter `flags` argument after the instruction pointer;
use `CDISASM_FORMAT_SYNTAX_INTEL` for the previous x86 output. They must also
link `cdisasm.lib` and stop deploying `cdisasm_format-8.dll`. All version-8
binaries must relink against the selected version-12 shared or static library.
Generic and explicit x86 decoder callers coming from version 8 must rebuild for
the 64-bit `cdisasm_decode_option`/`cdisasm_x86_decode_option` parameters
introduced in version 9. Version-9 explicit ARM callers must rebuild for the
new 64-bit `cdisasm_arm_decode_option` parameter. Both decoder result layouts
retain their widths.
Every version-11 decoder caller must also rebuild and relink for version 12:
the generic, x86, and ARM decode functions now take a pointer to their 64-byte
flags object. Pass `NULL` for the former zero/base value, or initialize bitmap
0 from an old word with the appropriate `*_DECODE_FLAGS_INITIALIZER(old_word)`
macro. The legacy singular option typedefs remain available for storing that
one word, but passing one directly is no longer valid.
Version-7 explicit-decoder
callers must additionally relink to `cdisasm.lib` because the architecture
import libraries no longer exist; the compatibility CMake targets perform that
target redirection for rebuilt CMake consumers. Code built for version 6 must
also account for the version-7 move of the generic symbol out of the x86
library. Code written for version 5 must rename `cdisasm_x86_decode2` to
`cdisasm_x86_decode`, or `cdisasm_decode2` to `cdisasm_decode`, before
rebuilding; version 6 and later export no fallback symbols for the old names.
ARM callers must likewise rename
`cdisasm_arm_decode2` to `cdisasm_arm_decode`; the old ARM symbol is not
declared or exported. Version-5 CPU numbers stored as raw integers also require
an architecture-aware conversion: OR x86 values 0--44 with
`CDISASM_CPU_GROUP_X86`, and OR ARM values 0--37 with
`CDISASM_CPU_GROUP_ARM`. For example, stored x86 ordinal 4 becomes
`0x00010004` (`CDISASM_CPU_80386`), while stored ARM ordinal 4 becomes
`0x00020004` (`CDISASM_ARM_CPU_CORTEX_A32`). A raw zero is ambiguous without
the separately stored architecture, so persisted formats should record the
cdisasm ABI major and architecture together with the CPU ID.

## ARM C API example

ARM decoding remains usable as structured numeric metadata without the text
layer. This example requires `USE_DISASM_FORMAT=ON` and also formats the
successful result:

```c
#include <cdisasm/cdisasm_arm.h>
#include <cdisasm/cdisasm_format.h>
#include <stdio.h>

int main(void)
{
    /* A64 NOP, encoded as little-endian bytes. */
    const uint8_t code[4] = {0x1f, 0x20, 0x03, 0xd5};
    cdisasm_arm_instruction output;
    char text[64];
    uint32_t size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_ARM_MODE_A64,
        code,
        sizeof(code),
        UINT64_C(0x4000),
        NULL,
        &output);

    if (size != 4 || output.name_id != CDISASM_ARM_NAME_NOP
            || cdisasm_arm_format(&output,
                                  CDISASM_FORMAT_SYNTAX_0,
                                  text,
                                  sizeof(text)) != 3) {
        fprintf(stderr, "%s\n",
                cdisasm_status_string((cdisasm_status)output.last_error_id));
        return 1;
    }
    printf("0x%llx: %s\n", (unsigned long long)output.address, text);
    return 0;
}
```

See [docs/API.md](docs/API.md) for status, ownership, CPU-profile, and structured
operand rules.
