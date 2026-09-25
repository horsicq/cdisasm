# cdisasm API notes

Version 12.0 publishes one library containing common services, the enabled x86
and/or ARM decoders, and optional formatting. It is shared by default and may
instead be built as one static archive:

| Header | CMake target / physical library | Public API |
| --- | --- | --- |
| `<cdisasm/cdisasm_common.h>` | `cdisasm::cdisasm` / selected shared library or static archive | CPU-group-dispatched `cdisasm_decode`, checked generic dispatch, generic decode-flag query, caller-visible CPU-profile detection, version/status services, CPU ID groups, and common IDs |
| `<cdisasm/cdisasm_x86.h>` | `cdisasm::cdisasm` / same physical library | Explicit `cdisasm_x86_decode`, CPU mode and decode-family queries, and x86 result types when x86 is enabled |
| `<cdisasm/cdisasm_arm.h>` | `cdisasm::cdisasm` / same physical library | Explicit `cdisasm_arm_decode`, physical/decoder mode and decode-flag queries, and ARM result types when ARM is enabled |
| `<cdisasm/cdisasm_format.h>` | `cdisasm::cdisasm` (or compatibility proxy `cdisasm::cdisasm_format`) / same physical library | `cdisasm_x86_format`, `cdisasm_x86_format_mode`, `cdisasm_arm_format`, and the x86-only compatibility wrapper `cdisasm_format`, when formatting and their corresponding architectures are enabled |

Coverage is intentionally non-exhaustive for both x86 and Arm. Public IDs and
CPU feature definitions are a stable vocabulary, not a promise that every
encoding in the named ISA family is decoded. Unimplemented allocated forms are
reported as unsupported; reserved and incomplete forms remain invalid and
truncated respectively.

With `USE_EXTRA_OPCODES=1`, generated numeric inventories augment the
hand-written decoders. Fallback is attempted only for an explicit unsupported
result and never replaces invalid or truncated input. The x86 inventory carries
every descriptor from the pinned XED export but retains documented late-validity
limits. The ARM inventory carries every canonical leaf from the pinned open
AARCHMRS input; a leaf for which exact public operands cannot be lowered is
reported as unsupported rather than returned as partial structured metadata.

Version 12.0 changes every decoder flag parameter to a pointer to the common
fixed-size `cdisasm_decode_flags` bitmap. The object is eight `uint64_t` words,
exactly 64 bytes, and supplies 512 logical positions without another calling-
convention change. `NULL` means all-zero/base/default. The x86 and ARM aliases
share the layout but use independent bit meanings. This is an ABI-major change;
Windows uses `cdisasm-12.dll` and Unix-like SONAMEs use major 12.

Version 11.28 added the best-effort `cdisasm_current_cpu()` catalog-profile
query. Version 11.27 separates Intel VMX, AMD SVM, and Intel SMX runtime-family
selection without changing their published numeric bits. Version 11.26 added
exact EVEX MAP6 `VGETEXPPH`, `VGETEXPSH`, and `VGETEXPBF16` forms and four
exact unpredicated A64 pair `BFCVT`/`BFCVTN`
forms. All are available only when `USE_EXTRA_OPCODES=1`; their independent
CPU-feature requirements are described below. No pair `BFCVTNT` allocation is
claimed, and these bounded additions do not make either decoder exhaustive.

The current post-12.0 tranche adds exact semantics without changing the
append-only name catalogs. On x86, the REX2 map-1 `MONITOR`/`MWAIT` forms and
the complete six-name EVEX AVX10.2 VNNI-INT8 row are structured. It also owns
all four ACE_1 `TILEMOVROW`/`TILEMOVCOL` GPR32/IMM8 forms 3299--3302, all ten
ACE TOP2/TOP4 forms 3310--3319, and both the eight legacy and eight APX-F
RAO-INT dword/qword forms for `AADD`/`AAND`/`AOR`/`AXOR`. It now also owns
all ACE BSR state forms 378--388 and all legacy/VEX `USER_MSR` plus EVEX
`APX_F_USER_MSR` `URDMSR`/`UWRMSR` forms 3353--3360, plus exact legacy
`ENQCMD`/`ENQCMDS` public forms 1144/1142. The fixed
`RDMSRLIST`/`WRMSRLIST`/`WRMSRNS` forms 2571/8892/8893 and the VEX/APX
immediate-selector `RDMSR`/`WRMSRNS` forms 2572--2573/8894--8895 are exact
too. The eleven pinned
Key Locker IFORMs are exact as well: eight narrow/wide AES memory forms,
`ENCODEKEY128`/`ENCODEKEY256`, and privileged `LOADIWKEY`. Exact x86 system
slices now also include HRESET 1319, CLDEMOTE 710, CLZERO 719, and
PCONFIG/PCONFIG64 2084--2085, fixed RDPRU 2578, PREFETCHRST2 2311, and
PREFETCHWT1 2315, plus exact PTWRITE register/memory forms 2438--2439 and
SSE2 `MOVNTI` forms 1692--1693. The complete legacy `0F 2B`/`0F E7`
non-temporal store rows are exact too: `MOVNTDQ`/`MOVNTPD`/`MOVNTPS`, their
VEX/EVEX `VMOVNT*` forms, and the legacy `MOVNTQ`/`MOVNTSD`/`MOVNTSS`
collision siblings. Exact SMAP `CLAC`/`STAC` forms 707/3158 are also
structured as zero-operand privileged instructions, with their
independent logical runtime selector and the APX requirement of REX2 map 1
kept separate. The exact VTX follow-on block adds four `VMWRITE` identities
6048--6051 plus fixed `VMXOFF` 6052 and memory-source `VMXON` 6053, with
privilege/status metadata, independent APX-F transport, and exact prefix and
collision ownership. Classic-VEX `VDPPD`/`VDPPS` forms
4507--4508/4515--4518 are exact as well. On A64, the tranche adds Advanced
SIMD `ADDV` form 6077, zeroing `FCVT Zd.H, Pg/z, Zn.S`, all seven predicated
destructive FEAT_SVE_B16B16 arithmetic/minmax forms, structured
`DCPS1`/`DCPS2`/`DCPS3`, SVE indexed `DUP` with preferred `MOV` alias form
2439, the FP8 `FCVTN`/`FCVTNB`/`BFCVTN`/`FCVTNT` row 3165--3168, and the
complete bounded SME2 two-vector conversion row 4312--4324, including
`SQCVT`, `SQCVTU`, `UQCVT`, and the non-BF16 FP8 `FCVT` sibling. SME2
`SUNPK`/`UUNPK` forms 4325--4326 and all eight SME2+FP8 `F1CVT`/`BF1CVT`/
`F2CVT`/`BF2CVT` widening forms 4327--4334 are exact as well. The adjacent
exact additions are SVE2.1-or-SME2 multi-extract `SQCVTN`/`SQCVTUN`/`UQCVTN`
forms 2881--2883, SME2 pair-to-pair `FRINTN`/`FRINTP`/`FRINTM`/`FRINTA`
forms 4335--4338, SME_F16F16 `FCVT`/`FCVTL` forms 4339--4340, and every
SME2 group-of-four form 4341--4362: conversion, saturating narrowing, FP8
narrowing, unpack, B/H/S/D/Q permutation, and single-precision rounding.
The adjacent SME multi-vector `FMUL`/`BFMUL` forms 4363--4370 and fixed-width
Advanced SIMD `CLS`/`CNT`/`CLZ` forms 6007/6008/6041 are exact as well.
SME2 multi-register `MOVA` inserts 3867--3876 and extracts 3882--3891 are
exact too, with preferred `MOV` formatting and aligned pair/quad Z lists.
SME2.1 `MOVAZ` zeroing extracts 3892--3906 are exact too: single B/H/S/D/Q,
aligned pair/quad B/H/S/D, and whole-ZA.D VGx2/VGx4 forms retain their
canonical mnemonic, have no predicate, write the Z destination, and read ZA.
Exact baseline-SME `LDR`/`STR ZA[W12-W15, off4], [Xn|SP, #off4, MUL VL]`
forms 4381--4382 each allocate 2,048 selector/base/offset combinations, for
4,096 words across the load/store pair. Their
runtime-sized memory operand uses `size == 0`; nonzero offsets store the
coefficient in `imm` with `HAS_DISPLACEMENT | VL_SCALED`.
Exact SME2 `LDR`/`STR ZT0, [Xn|SP]` forms 4383--4384 allocate all 32 base
registers and reject every other operation/ZT-selector cell in their bounded
parent class.
Baseline A64 `UDF #imm16` form 4387 is exact across its complete 65,536-word
leaf and retains the pinned generated interrupt-group metadata without adding
an `ILLEGAL` or execution-state flag.
FEAT_WFxT `WFET Xt`/`WFIT Xt` forms 4457--4458 are exact across their two
32-word leaves, including XZR rather than SP for register 31 and an independent
`CPU_ANY`-only capability policy.
FEAT_FlagM/FlagM2 forms 4499--4501 and 5696--5698 are exact as well:
`CFINV`/`XAFLAG`/`AXFLAG` have no operands, `RMIF` reads Xn/XZR plus imm6 and
imm4, and `SETF8`/`SETF16` read Wn/WZR. All six carry NZCV-write metadata,
reject their reserved control neighbors, and are conservatively admitted only by `CPU_ANY` because
no current named profile advertises FlagM or FlagM2.
The five FEAT_SVE first-fault-register forms are exact too: predicated
`RDFFR`/`RDFFRS` forms 2562--2563, unpredicated `RDFFR` form 2564,
`WRFFR` form 2617, and zero-operand `SETFFR` form 2618. They preserve typed
predicate access, distinguish governing `/Z` predication from predicate data,
and exhaust their bounded parents as 545 allocated and 611 reserved words.
The 18 non-saturating SVE element-count forms 2374--2391 are now exact as
well: vector `INC*`/`DEC*`, scalar `CNT*`, and scalar `INC*`/`DEC*` expose
their pattern and multiplier operands and exhaust three bounded parents as
294,912 allocated and 98,304 reserved words.
The adjacent predicated variable-shift block is exact too: `SRSHL`, `SRSHLR`,
`SQSHL`, `SQRSHL`, `SQSHLR`, `SQRSHLR`, `URSHL`, `URSHLR`, `UQSHL`,
`UQRSHL`, `UQSHLR`, and `UQRSHLR` forms 2657--2668 preserve destructive
merging access over B/H/S/D elements, require SVE2 or SME, and exhaust their
bounded parent as 393,216 allocated and 131,072 reserved words.
The adjacent predicated integer-unary forms 2669--2676 are exact too.
`URECPE`/`URSQRTE` allocate only `.S`; `SQABS`/`SQNEG` allocate B/H/S/D.
Merging `/m` forms require SVE2 or SME and read/write the destination, while
zeroing `/z` forms require SVE2.2 or SME2.2 and write it. Their shared parent
contains 163,840 allocated and 98,304 reserved words.
Predicated accumulating-long `SADALP`/`UADALP` forms 2677--2678 are exact
for B-to-H, H-to-S, and S-to-D. Their read/write destination and governing
`/m` predicate use destination granularity, while the half-width source is a
read. The parent contains 49,152 allocated words and 16,384 reserved
`size=00` controls. The adjacent destructive halving row implements `SHADD`,
`SHSUB`, `SRHADD`, `SHSUBR`, `UHADD`, `UHSUB`, `URHADD`, and `UHSUBR` forms
2679--2686 for all B/H/S/D arrangements, allocating 262,144 words. Both rows
carry scalable-vector and predicated metadata and require SVE2 or SME; Apple
A18/M4 admit the SME route and A64FX rejects it.
Destructive predicated pairwise `SUBP`/`ADDP`/`SMAXP`/`SMINP`/`UMAXP`/
`UMINP` forms 2687--2692 are exact for every B/H/S/D arrangement. They expose
a tied read/write `Zdn.T`, a read-only typed `Pg/m`, and a read-only `Zm.T`.
`SUBP` requires SVE2p3 or SME2p3; the other five require SVE2 or SME. Their
complete parent contains 196,608 allocated words and 65,536 reserved
operation-2/3 words. Pinned AARCHMRS is authoritative for all six forms; LLVM
21 reproduces the other five SVE2 encodings but does not yet accept SVE2p3
`SUBP`.
The adjacent destructive predicated saturating `SQADD`/`SQSUB`/`SUQADD`/
`USQADD`/`SQSUBR`/`UQADD`/`UQSUB`/`UQSUBR` forms 2693--2700 are exact for
B/H/S/D. They expose `Zdn.T, Pg/m, Zdn.T, Zm.T`, with a read/write
destination and read-only typed predicate, tied source, and second source,
and require SVE2 or SME. The focused suite exhausts their 262,144-word parent
as fully allocated with no reserved residual, including profiles, endian and
generic transport, canonical formatting and forgery rejection, truncation,
same-name neighbors, and extras-OFF ownership. Fifteen corpus rows and eight
`a64_sve_pred_sat_*.hex` seeds cover all eight leaves; LLVM 21 confirms their
representative encodings.
The adjacent destructive unpredicated `SCLAMP` form 2701 and `UCLAMP` form
2702 are exact under parent `(word & 0xff20f800) == 0x4400c000`. Every B/H/S/D
form exposes `Zd.T, Zn.T, Zm.T`, with a read/write destination and two
read-only sources. The two leaves allocate all 262,144 parent words, carry
scalable-vector metadata, and require SVE2.1 or SME. Fifteen corpus rows and
six `a64_sve_clamp_*.hex` seeds lock both leaves, profiles, endian transport,
formatting and forged-schema rejection, fixed neighbors, truncation, and
extras-OFF ownership against pinned AARCHMRS, LLVM 21, and an independent
operand oracle.
The pointer multiply-add transform `MLAPT` form 2707 and `MADPT` form 2708
exactly own parent `(word & 0xff20f400) == 0x4400d000`. Only `.D` is allocated:
32,768 words per leaf and 65,536 total, while the B/H/S size quarters reserve
196,608 words. Both have a destructive read/write destination and two
read-only Z sources; MLAPT exposes `Zda.D, Zn.D, Zm.D`, whereas MADPT exposes
`Zdn.D, Zm.D, Za.D`. Admission is the conjunction FEAT_SVE and FEAT_CPA.
`CDISASM_ARM_CPU_ANY` succeeds; every current named profile rejects the forms.
Fifteen corpus rows, seven readable seeds, the complete parent sweep, both
byte orders, generic dispatch, formatter-schema rejection, truncation, fixed
neighbors, and extras-OFF ownership preserve the boundary against pinned
AARCHMRS and LLVM 21.
The quad-permute `ZIPQ1`/`UZPQ1` forms 2711--2712 and `ZIPQ2`/`UZPQ2`
forms 2714--2715 are exact for every B/H/S/D arrangement. Each exposes
`Zd.T, Zn.T, Zm.T`, writes the destination, reads both sources, carries only
scalable-vector metadata, and requires SVE2.1 or SME2.1.
`CDISASM_ARM_CPU_ANY` succeeds while every current named profile rejects all
four forms. The complete 1,048,576-word parent routes controls 000--011 to
524,288 exact Q1/Q2 words, control 110 to the 131,072-word `TBLQ` sibling,
and residual controls 100, 101, and 111 to 393,216 invalid words. The Q2
allocations report `UNSUPPORTED_INSTRUCTION` with extras disabled, reserved
controls remain `INVALID_INSTRUCTION`, and short words report `TRUNCATED`.
The Q2 tranche adds 14 corpus rows and four readable seeds to the Q1 evidence;
the exhaustive parent sweep, both byte orders, generic dispatch, formatter-schema
rejection, truncation, and extras-OFF ownership preserve the boundary against
pinned AARCHMRS and LLVM 21.
Memory-source `MOVNTDQA` form 1690 and `VMOVNTDQA` forms 5864--5868 are exact
too. Legacy `66 0F 38 2A /r` uses the pinned SSE4 ISA-set group and logical
bit 270; VEX.128/256 uses AVX/AVX2, and EVEX.128/256/512 uses its exact
AVX512F width group and bit. Each form writes XMM/YMM/ZMM and reads equal-width
memory. Register ModRM, masks, broadcast, rounding, SAE, reserved `vvvv`, and
invalid EVEX W/LL/z/b/aaa controls are rejected. Full-tuple disp8 scales by
16/32/64 bytes; 64-bit EVEX B4/U0/X4 address promotion independently requires
APX/APX-F, and the non-66 `VPBROADCASTMB2Q` collision remains disjoint.
Memory-only `LDDQU` form 1574 and `VLDDQU` forms 5583--5584 are exact too.
Legacy F2-map-1 `LDDQU` requires SSE3, explicitly ignores `66` and REX.W, and
uses an independently APX-gated REX2 map-1 route. VEX.128/256 `VLDDQU` uses
AVX for both widths, requires encoded `vvvv=1111`, and treats W as ignored.
Every form writes XMM/YMM and reads equal-width memory; register ModRM and
malformed prefix/control combinations are rejected. EVEX map-1/F0 is unowned
and therefore reports `UNSUPPORTED_INSTRUCTION`, not an LDDQU-family invalid.
`VMOVMSKPD` forms 5860--5861 and `VMOVMSKPS` forms 5862--5863 exactly own VEX
map-1 opcode `50` in that pinned-XED order. NP versus `66` selects PS versus
PD, VL selects XMM versus YMM, W is ignored, and raw `vvvv` must be all ones.
Each form writes a GPR32 and reads one register-only XMM/YMM source under the
AVX group and runtime bit. VEX3.B is ignored for that source in 16/32-bit mode
without relaxing the C4/LES R/X disambiguation; long mode uses R/B extensions.
F2/F3 and memory controls are invalid. Legacy and REX2 map-1 opcode `50` keep
their `MOVMSKPS`/`MOVMSKPD` identities, EVEX map-1 opcode `50` is unowned, and
the VEX map-2 opcode-`50` VNNI allocation is not claimed.
`VMOVQ` forms 5884--5896 exactly cover the qword VEX/EVEX map-1
`6e`/`7e`/`d6` rows. The opcode and pp fields select GPR, memory, and XMM
directions; fixed-W `66/6e` and `66/7e` are 64-bit-only, while WIG `F3/7e`
and `66/d6` are valid in every mode. VEX is VL128 with raw `vvvv=1111`;
EVEX is W1/VL128/U1/V'=1 with z/b/aaa clear, plus narrowly APX-gated B4 and
raw-U0/X4 memory addressing in long mode. W0 and non-long fixed-W controls
remain distinct `VMOVD`/MOVZXC collisions. VEX requires AVX; EVEX uses the
no-VL AVX512F-128 or AVX10.1 foundation and admits Knights Mill.
`VMOVRSB`/`VMOVRSD`/`VMOVRSQ`/`VMOVRSW` forms 5897--5908 exactly cover the
64-bit EVEX map-5 opcode-`6f` memory-source rows at 128, 256, and 512 bits.
They support mask merging and zeroing, use width-specific AVX10 MOVRS groups
and runtime bits, scale disp8 by 16/32/64 bytes, and require APX independently
for promoted B4/X4 addressing. Register ModRM and reserved EVEX controls are
invalid.
`VMOVSD` forms 5909--5915 exactly cover scalar-double VEX/EVEX map-1 F2
opcodes `10` and `11`. The VEX forms require AVX and provide memory load,
memory store, and both three-register directions. The EVEX forms use W1 and
the AVX512F scalar group/runtime bit, accept ignored LL=0--2, implement
merge/zero masking where architecturally legal, use eight-byte compressed
displacements, and independently require APX for B4/X4 address promotion.
Legacy `MOVSD`, neighboring mandatory-prefix moves, reserved decorators, and
U0 register controls remain disjoint.
`VMOVSHDUP` forms 5916--5925 and `VMOVSLDUP` forms 5929--5938 exactly cover
the PF3 VEX/EVEX map-1 opcode-`16`/`12` duplicate moves. VEX XMM/YMM forms
require AVX, ignore W, and require encoded `vvvv=1111`. EVEX XMM/YMM/ZMM
forms use W0, fixed `vvvv`/V', b=0, merge/zero masks, full-vector memory and
16/32/64-byte tuple scaling, and their exact AVX512F-128/256/512 group and
runtime bit. Both encodings write a vector destination and read a same-width
register or memory source; an EVEX merge destination is read/write. B4/X4
address promotion independently requires APX/APX-F.
`VMOVSH` forms 5926--5928 exactly cover EVEX map-5 PF3/W0 scalar-half store,
load, and three-XMM register shapes. Memory is m16, compressed disp8 scales by
two, register destinations support merge/zero masks, stores support merge masks
only, and the exact AVX512-FP16 scalar group/runtime bit is required. APX
address promotion is independently gated. Across these 23 forms the exact
classifier owns 9,092,608 allocations; factored sweeps reject 3,337
target-owned controls and delegate 2,308 mandatory-prefix or legacy-neighbor
selector cells. Pinned XED agrees on all 42 valid and 18 reserved-control
corpus witnesses.
`VMOVSS` forms 5939--5945 exactly cover the corresponding scalar-single
VEX/EVEX map-1 PF3 opcode-`10`/`11` rows at W0. VEX forms require AVX; EVEX
forms use the `AVX512F_SCALAR` group/runtime bit, implement merge/zero masks on
register destinations and merge-only masked stores, accept ignored LL where
allocated, and independently require APX
for B4/X4 address promotion. Memory operands are dword and compressed disp8
scales by four. Legacy `MOVSS`, mandatory-prefix neighbors, U0 register
controls, and reserved decorators remain disjoint. The exact classifier owns
7,721,472 allocations across the seven forms.
`VMOVUPD` forms 5946--5962 and `VMOVUPS` forms 5963--5979 exactly cover the
packed unaligned VEX/EVEX map-1 opcode-`10`/`11` rows. NP/W0 selects UPS and
`66`/W1 selects UPD. VEX XMM/YMM forms require AVX and fixed `vvvv`; EVEX
XMM/YMM/ZMM forms use their exact AVX512F width group or AVX10.1 route,
support merge/zero masking on register destinations and merge-only masked
stores, and scale compressed displacement by 16/32/64 bytes. Long-mode B4/X4
address promotion independently requires APX/APX-F. The bounded classifier
owns 2,425,856 allocated encodings, rejects 3,190 reserved controls, and
delegates 1,544 legacy, scalar, or neighboring selector cells.
`VMOVW` forms 5980--5986 exactly cover all eight pinned-XED EVEX map-5
opcode-`6e`/`7e` records. The WIG `66` selector maps the GPR32, m16, and XMM
directions to `AVX512_FP16_128N`; F3/W0 maps the two m16 directions and both
register-direction records sharing form 5986 to `AVX512_MOVZXC_128`. Every
form is VL128 with fixed `vvvv`/V', U1 for register operands, no masks or
decorators, and Tuple2 compressed displacement for m16. Long-mode B4/X4
promotion independently requires APX/APX-F. The seven forms allocate
respectively 5,120, 27,648, 13,824, 5,120, 27,648, 13,824, and 5,120
encodings, for 98,304 total; factored P1/P2 sweeps reject 3,046 target-owned
controls without claiming map-1 VMOVD/VMOVQ or map-2 neighbors.
`VMPSADBW` forms 5987--5996 exactly cover the ten pinned-XED VEX/EVEX
records. VEX map-3 opcode `42` is mandatory-66, WIG, and VL128/VL256 under
AVX/AVX2. EVEX is F3/W0 at 128/256/512 bits with the exact
`AVX512_MEDIAX_128/256/512` group and runtime selector. Operands are a vector
destination write, the `vvvv` vector read, an equal-width register or
Full-tuple memory read, and imm8. EVEX supports k-mask merge/zero, makes merge
destinations read/write, and scales disp8 by 16/32/64 bytes. B4/X4 address
promotion independently requires APX/APX-F; register B4 and non-long
extension controls keep their exact ignored-or-invalid meaning. Legacy
`MPSADBW` and the EVEX `VDBPSADBW` selector remain disjoint. Focused
representative-immediate sweeps cover 196,608 VEX and 829,440 canonical EVEX
control/ModRM cells, supplemented by complete imm8 and factored P1/P2 checks.
The first exact virtualization block, forms 5997--6005, covers qword-memory
`VMPTRLD`/
`VMPTRST`, 32-/64-bit register and memory `VMREAD`, fixed `VMRESUME`,
address-sized implicit-AX `VMRUN`, and fixed `VMSAVE`. VMREAD writes its first
operand and reads its VMCS-field register; VMPTRLD reads memory and VMPTRST
writes it. Forms 5997--6003 publish the VMX umbrella plus the exact pinned VTX
ISA-set group and require exact VTX bitmap bit 267; VMRUN/VMSAVE preserve the
separate SVM route. The tranche also preserves runtime/profile gates,
privileged and status-flag metadata, ignored versus reserved prefixes,
APX-gated REX2 promotion, and VMCLEAR/EXTRQ/INSERTQ collision ownership.
Focused sweeps cover 768 legacy VMREAD mode/ModRM tuples, 32,768 REX2 VMREAD
tuples, and 2,432 REX2 pointer/fixed tuples.
Exact `VMULBF16` forms 6006--6011 cover EVEX XMM/YMM/ZMM register and
Full-tuple memory sources under the width-specific AVX10.2 BF16 groups and
runtime bits. Memory `EVEX.b` selects BF16 broadcast 1to8/1to16/1to32;
register `EVEX.b` is reserved. The destination is write-only unless masked
merge makes it read/write, while `vvvv` and the register/memory source are
read-only. Full-tuple disp8 scales by 16/32/64 bytes. APX B4 extends memory
bases and U0/X4 extends memory indexes; U0 is invalid for register sources.
Focused sweeps cover 4,032 allocated and 576 reserved ModRM cells, exact P1/P2
partitions, and 98,304 high-register tuples against pinned XED.
Exact `VMULPH` forms 6022--6027 and `VMULSH` forms 6042--6043 share EVEX
MAP5 opcode `59`, W0, and U1, with pp0 selecting packed PH and ppF3 selecting
scalar SH. VMULPH covers XMM/YMM/ZMM Full-tuple memory and register sources;
forms 6022/6023 are XMM memory/register, 6024/6025 are YMM memory/register,
and 6026/6027 are ZMM memory/register. VMULSH form 6042 is XMM plus m16 and
form 6043 is the three-XMM register form.
For a VMULPH memory source, `EVEX.b` selects FP16 broadcast
1to8/1to16/1to32 and Full-tuple disp8 scales by 16/32/64 bytes. VMULSH uses
an m16 Tuple2 source and two-byte disp8, with memory `EVEX.b` reserved.
Both support k-mask merge/zero, with a merge destination read/write; `vvvv`
and the third operand are reads. For a register source, `EVEX.b` selects
embedded rounding plus SAE: every VMULPH LL/RC value maps to fixed-ZMM form
6027, while every VMULSH LL/RC value maps to fixed-XMM form 6043. Only
VMULSH memory reserves `EVEX.b`; VMULPH memory uses it for broadcast.
Admission uses the exact width/scalar group and runtime-bit pairs
`AVX512_FP16_128` 197/145, `AVX512_FP16_256` 199/147,
`AVX512_FP16_512` 200/148, and `AVX512_FP16_SCALAR` 204/152 rather than an
umbrella-only bit. In long mode, B4 extends a memory base but is ignored for a
register source, while U0/X4 extends a SIB memory index. Any asserted
B4/U0/X4 control independently requires APX/APX-F, including an operand-wise
ignored register B4. U0 register sources and non-long extension controls
remain reserved. EVEX pp66 selects neighboring VMULBF16, ppF2 remains
unallocated, and legacy prefixes, W1, LL=3 without
embedded rounding, and zeroing without a mask retain their invalid ownership.
Classic `VMULPD`/`VMULPS`/`VMULSD`/`VMULSS` forms 6012--6021,
6028--6041, and 6044--6047 are exact. VEX MAP1 opcode `59` uses AVX,
XMM/YMM packed or XMM scalar operands, WIG, and scalar LIG semantics. EVEX
uses the exact `AVX512F_128/256/512/SCALAR` groups and runtime bits
128/130/131/133 through the applicable AVX-512F/AVX512VL or AVX10.1 route.
Packed memory supports Full-tuple disp8 and scalar broadcast; scalar memory
uses m32/m64 tuple scaling and reserves `EVEX.b`. Register `EVEX.b` selects
embedded rounding plus SAE with fixed-ZMM packed or fixed-XMM scalar form
identity. Mask merge/zero access, all standard high registers, APX B4/U0/X4,
prefix collisions, malformed W/LL/decorator controls, truncation precedence,
Arrow Lake rejection, and Knights Mill's scalar/ZMM-without-VL boundary are
preserved.
Exact VTX forms 6048--6053 complete the adjacent virtualization block.
`VMWRITE` forms 6048/6049 use GPR32 plus GPR32/dword-memory outside long mode;
forms 6050/6051 use GPR64 plus GPR64/qword-memory in long mode. Both operands
are reads. `VMXOFF` form 6052 is fixed NP `0F 01 C4` with no visible operands;
`VMXON` form 6053 is mandatory-F3 `0F C7 /6` with one qword-memory read.
All publish CPL0 and aggregate status-write metadata plus the VMX umbrella and
exact VTX group/runtime bit. Ordinary REX is accepted where architectural;
VMXOFF and VMXON additionally carry NOTSX, and VMXON requires protected mode.
REX2 map-1 promotion independently requires APX-F. The decoder keeps
`66` `EXTRQ`, F2 and both `66`+F2 orderings of `INSERTQ`, invalid F3
`VMWRITE`, `VMCLEAR`, malformed controls, and truncation distinct.
Classic packed logical-OR `VORPD` forms 6054--6063 and `VORPS` forms
6064--6073 are exact. VEX map-1 opcode `56` supplies XMM/YMM register and
equal-width memory inputs under AVX. EVEX supplies XMM/YMM/ZMM register,
Full-memory, and scalar-broadcast inputs under exact `AVX512DQ_128/256/512`
group/runtime admission through AVX-512DQ/VL or AVX10.1. Masks, Full-tuple
disp8, high registers, and APX B4/U0/X4 memory addressing are retained.
Register `EVEX.b` is reserved, so VOR never publishes embedded rounding or
SAE; W/prefix/LL/decorator controls, non-long ignored extensions, legacy
LES/LDS collisions, and truncation keep their exact status.
`VP2INTERSECTD`/`VP2INTERSECTQ` forms 6074--6085 exactly own EVEX map-2
opcode `68` across XMM/YMM/ZMM register and Full-memory sources. W selects
dword or qword elements. ModRM.reg's low bit is cleared to choose an even K
destination; the result publishes that register and its odd successor as two
write operands, marks the successor implicit, and formats the architectural
pair as `kN+1`. Memory forms preserve scalar broadcast and Full-tuple
16/32/64-byte disp8 scaling. The exact width groups and Tiger Lake feature
profile are required, while 64-bit B4/U0/X4 addressing independently requires
APX. The decoder rejects malformed R/R', `aaa`, `z`, LL=3, and extension
controls. The focused classifier exhausts 786,432 controls: 8,064 allocated
and 778,368 reserved.
`VPABSB` forms 6088--6097, `VPABSD` forms 6098--6107, `VPABSQ` forms
6108--6113, and `VPABSW` forms 6114--6123 are exact in the non-linear order
of the pinned XED catalog. VEX map-2 byte/word/dword forms write XMM or YMM
from an equal-width register or memory source, require encoded `vvvv=1111`,
and use AVX for XMM versus AVX2 for YMM. EVEX adds XMM/YMM/ZMM mask-merge and
zeroing forms with fixed `vvvv`/V': byte/word use exact AVX512BW width groups,
dword/qword use exact AVX512F width groups, and their allocated AVX10.1 routes
remain distinct. Full-memory disp8 scales by 16/32/64 bytes; only dword/qword
memory admits scalar broadcast with four-/eight-byte tuple scaling. High
registers, non-long extension aliases, APX B4/U0/X4 addresses, prefixes,
collisions, reserved W/LL/decorator controls, and truncation precedence retain
their exact ownership. The bounded classifier contains 9,216 allocated and
580,608 reserved VEX controls plus 259,200 allocated and 527,232 reserved EVEX
controls. Pinned XED validates all 36 form identities and feature routes.
`VPACKSSDW`/`VPACKSSWB`/`VPACKUSDW`/`VPACKUSWB` forms 6124--6163 are exact
across VEX XMM/YMM and EVEX XMM/YMM/ZMM register-or-memory sources. They
preserve the three-operand destination/source/source schema, AVX versus AVX2
VEX gates, exact AVX512BW_128/256/512 width routes and AVX10.1 alternatives,
EVEX merge/zero masks, Full-tuple disp8, dword-source-only broadcast, high
registers, and independently gated APX addressing. The focused suite and
pinned XED classify 196,608 allocated plus 589,824 reserved VEX cells and
40,320 allocated plus 746,112 reserved EVEX cells, while checking both
syntaxes, malformed controls, profiles, truncation, formatter forgery, and
extras-OFF ownership. Eighty corpus rows and 60 `x86_vpack*.hex` seeds reach
all 40 forms; LLVM 21 agrees on representative encodings.
`VPBLENDD` forms 6306--6309 and `VPBLENDW` forms 6338--6341 are exact
VEX.0F3A.66 NDS-plus-imm8 forms. They expose four operands: a written
XMM/YMM destination, a read-only `vvvv` source, an equal-width read-only
register or memory ModRM source, and a read-only imm8. `VPBLENDD` requires
AVX2 and W=0; `VPBLENDW` uses AVX for XMM and AVX2 for YMM and treats W as
ignored. The focused classifier contains 294,912 allocated and 1,277,952
reserved controls and locks address formation, mandatory-prefix and collision
ownership, truncation, both syntaxes, formatter-schema rejection, and
extras-OFF behavior. Thirty corpus rows and 16 `x86_vpblend*.hex` seeds cover
all eight forms against pinned XED and LLVM 21.
`VPBLENDVB` forms 6334--6337 exactly own VEX.0F3A.66.W0 opcode `4c`.
Forms 6334/6335 are the L=0 XMM memory/register pair; forms 6336/6337 are the
L=1 YMM memory/register pair. They expose a written destination,
read-only `vvvv` and ModRM sources, and a fourth read-only vector source named
by the high nibble of the trailing `SE_IMM8`; the low nibble is ignored. The
selector byte is encoding metadata, not an immediate operand, so
`encoding.selector_offset` records it and `encoding.immediate_count` is zero.
XMM requires AVX and YMM requires AVX2. A selected CPU profile missing that
feature reports `INVALID_INSTRUCTION`; a missing runtime-family bit reports
`UNSUPPORTED_INSTRUCTION`. Address-size and segment overrides are accepted.
Operand-size, repeat, LOCK, and REX legacy prefixes, W=1, and pp
other than 66 are invalid only after the complete ModRM/SIB/displacement/
selector payload is consumed; incomplete owned inputs therefore report
`TRUNCATED`, while wrong-map/opcode neighbors remain `UNSUPPORTED_INSTRUCTION`.
Extras-OFF builds likewise retain structural ownership and return
`UNSUPPORTED_INSTRUCTION` for allocated complete forms. In non-long modes,
C4 R/X collisions retain LES/invalid routing, while B, high `vvvv`, and the
selector high bit alias into the eight-register namespace. This follows
pinned XED; LLVM 21 and Capstone expose an impossible high selector register
for that spelling. The focused classifier contains 98,304 allocated and
688,128 reserved controls and sweeps all 1,536 mode/L/selector combinations.
Thirty-four corpus rows and 18 `x86_vpblendvb_*.hex` seeds preserve the same
form, operand, status, formatter, profile/runtime, and address boundaries.
VEX `VPBROADCASTB` forms 6342/6343/6347/6348 and `VPBROADCASTW` forms
6387/6388/6392/6393 exactly own C4 map-2 opcodes `78`/`79` with pp=66,
W=0, and encoded `vvvv=1111`. The destination is write-only. The read source
is m8/m16 or the low byte/word of an XMM register, including for a YMM
destination; no broadcast decorator is published. Results expose both AVX and
AVX2 groups, and the most-specific AVX2
runtime selector alone admits both widths. Missing runtime support reports
`UNSUPPORTED_INSTRUCTION`; a selected profile without AVX2 reports
`INVALID_INSTRUCTION`. Address-size and segment overrides are accepted.
Reserved W/pp/`vvvv` and legacy operand/repeat/LOCK/REX prefixes are rejected
only after consuming ModRM/SIB/displacement, preserving `TRUNCATED`
precedence; allocated extras-OFF forms remain unsupported. In 16/32-bit modes,
raw C4 R'/X' collisions remain LES while B' aliases into the eight-register
namespace. EVEX opcode `78`/`79` remains on its existing path. The combined
1,572,864-control partition contains 12,288 allocated and 1,560,576 reserved
cells. Sixty-two corpus rows and 36 readable seeds cover these boundaries;
pinned XED data/kit and XED/LLVM 21 samples provide independent evidence.
VEX `VPBROADCASTD` forms 6355/6356/6360/6361 and `VPBROADCASTQ` forms
6374/6375/6379/6380 apply the same exact contract to map-2 opcodes `58`/`59`.
They read m32/m64 or the low dword/qword of an XMM register, write XMM/YMM,
and require AVX2 while publishing both AVX and AVX2 groups. Their exhaustive
suite likewise classifies 12,288 allocated and 1,560,576 reserved controls;
62 corpus rows and 36 readable seeds retain mode, address, prefix, profile,
formatter, truncation, and extras-OFF boundaries against XED and LLVM 21.
VEX `VPCMPEQQ` forms 6454--6457 exactly own C4 map-2 opcode `29` with pp=66
and W ignored. L=0 selects XMM register/memory forms under AVX; L=1 selects
YMM register/memory forms under AVX2 and also publishes AVX. The destination
is write-only, while the NDS `vvvv` source and ModRM register/memory source are
read-only. All modes, high registers and addresses, non-long aliases,
address/segment overrides, legacy and EVEX siblings, reserved pp controls,
and complete-payload truncation precedence remain distinct. The exhaustive
suite classifies 196,608 allocated and 589,824 reserved controls; 30 corpus
rows and 16 readable seeds retain the boundary against pinned XED and LLVM 21.
VEX `VBLENDPD` forms 3527--3530 and `VBLENDPS` forms 3531--3534 exactly own
C4 map-3 opcodes `0D`/`0C` with pp=66 and W ignored. L selects XMM or YMM;
both widths require and publish AVX, never AVX2. The four operands are a
write-only destination, read-only NDS `vvvv` and ModRM sources, and a read-only
imm8. All modes, W aliases, high registers and addresses, non-long C4/LES and
B-extension behavior, address/segment overrides, reserved pp and legacy
prefixes, and complete-payload truncation precedence are distinct. The
`cdisasm_x86_vblend_tests` classifier exhausts 1,572,864 controls as 393,216
allocated and 1,179,648 reserved, with 73,728 encodings per memory form and
24,576 per register form. It also locks AVX CPU/runtime admission, Intel and
AT&T formatting, forged-schema rejection, and extras-OFF ownership. Thirty-two
corpus rows and 16 readable seeds retain the exact boundary against pinned XED
and LLVM 21.
VEX `VBLENDVPD` forms 3535--3538 and `VBLENDVPS` forms 3539--3542 exactly own
C4 map-3 opcodes `4B`/`4A` with pp=66, W=0, and L selecting XMM or YMM. Both
widths require and publish AVX. The four operands are a write-only destination
and read-only NDS `vvvv`, ModRM, and selector vector sources. The trailing
`SE_IMM8` high nibble selects that fourth vector register, the low nibble is
ignored, `encoding.selector_offset` records the byte, and no immediate operand
is exposed. Long-mode mask/value through the opcode is
`ff 1f 83 ff / c4 03 01 4b|4a`; non-long C4 ownership uses
`ff df 83 ff / c4 c3 01 4b|4a`, preserving LES collisions and B-extension
aliases. Reserved pp/W/prefix controls are classified after the complete
ModRM/address/selector payload, preserving truncation precedence. The
`cdisasm_x86_vblendv_tests` classifier exhausts 1,572,864 controls as 196,608
allocated and 1,376,256 reserved and locks all modes, profiles, runtime gates,
both syntaxes, forged-schema rejection, and extras-OFF ownership. Thirty-eight
corpus rows and 23 readable seeds retain the boundary against pinned XED and
LLVM 21.
VEX `VBROADCASTF128` form 3543 and `VBROADCASTI128` form 3554 exactly own
memory-only `VEX.256.66.0F38.W0 1A/5A /r`. Their long-mode opcode masks are
`ff 1f ff ff / c4 02 7d 1a|5a`, while non-long ownership uses
`ff df ff ff / c4 c2 7d 1a|5a`; encoded `vvvv` must be 1111, L must be one,
and register ModRM controls are reserved. Both write YMM and read m128 in all
16/32/64-bit modes. `VBROADCASTF128` requires AVX, whereas
`VBROADCASTI128` requires AVX2 while retaining the AVX group. The
`cdisasm_x86_vbroadcast128_tests` suite exhausts 1,572,864 controls as 4,608
allocated and 1,568,256 reserved, including complete-payload truncation,
non-long C4/LES and B-extension aliases, formatting-schema rejection, and
extras-OFF ownership. Thirty-nine corpus rows and 18 readable seeds preserve
the boundary against pinned XED and LLVM 21.
VEX `VBROADCASTSD` forms 3569--3570 and `VBROADCASTSS` forms 3573--3574 and
3579--3580 exactly own C4 map-2 opcodes `19`/`18` with pp=66, W=0, and
encoded `vvvv=1111`. SD requires L=1; SS accepts L=0/1. Memory forms read
m64/m32 and require AVX. Register forms read a full XMM source, add the AVX2
group and runtime/profile requirement, and write XMM/YMM according to L;
adjacent EVEX encodings remain separately owned. The
`cdisasm_x86_vbroadcast_scalar_tests` suite exhausts 1,572,864 controls as
9,216 allocated and 1,563,648 reserved while locking all modes, non-long
C4/LES and B-extension aliases, address/segment overrides, legacy-prefix and
late-truncation precedence, exact access, both syntaxes, formatter forgery,
and extras-OFF ownership. Forty-one corpus rows and 18 readable seeds preserve
the six-form boundary against pinned XED and LLVM 21.
VEX `VEXTRACTF128` forms 4539--4540, `VEXTRACTI128` forms 4553--4554,
`VINSERTF128` forms 5551--5552, and `VINSERTI128` forms 5565--5566 exactly
own 256-bit map-3, pp=66, W=0, L=1 opcode rows `19`/`39` and `18`/`38`.
Extract writes XMM or m128, reads YMM, and reserves noncanonical encoded
`vvvv`; insert writes YMM and reads a YMM NDS source plus XMM or m128. Every
form exposes the trailing imm8 as a read operand. Floating forms require AVX;
integer forms add AVX2. The `cdisasm_x86_lane_insert_extract_tests` suite
classifies 104,448 allocated and 3,041,280 reserved controls and locks all
modes, non-long aliases, high registers and addresses, prefix/field ownership,
late payload truncation, EVEX separation, both syntaxes, formatter forgery,
runtime/profile gates, and extras-OFF ownership. Twenty-three corpus rows and
14 readable seeds preserve the boundary against pinned XED and LLVM 21.
VEX `VEXTRACTPS` forms 4567/4569 and `VINSERTPS` forms 5579--5580 exactly
own map-3 opcodes `17`/`21` with pp=66, L=0, and ignored W. Extract requires
encoded `vvvv=1111`, writes r32 or m32, and reads XMM. Insert writes XMM and
reads an XMM NDS source plus XMM or m32. Every form exposes its imm8 as a read
operand and requires AVX. The focused suite exhausts 1,572,864 controls as
104,448 allocated and 1,468,416 reserved, locks all modes, W aliases,
complete-payload truncation, profiles, both syntaxes, formatter-schema
rejection, and extras-OFF ownership, and keeps EVEX forms
4568/4570/5581/5582 separate. Twenty-four corpus rows and 15 readable seeds
preserve the pinned-XED and LLVM 21 boundary.
VEX `VPERM2F128` forms 6770--6771 and `VPERM2I128` forms 6772--6773 exactly
own map-3 opcodes `06`/`46` with pp=66, W=0, and L=1. They write YMM, read
the YMM NDS source plus YMM or m256, and expose the full imm8 as a read
operand. Floating forms require AVX; integer forms add AVX2. The focused
suite partitions 1,572,864 controls into 98,304 allocated and 1,474,560
reserved while locking every mode, all 16 `vvvv` sources, non-long aliases,
prefix/field ownership, late payload truncation, both syntaxes, formatter
forgery rejection, profiles, and extras-OFF ownership. No EVEX sibling shares
either mnemonic. Twenty-three corpus rows and 15 readable seeds preserve the
pinned-XED and LLVM 21 boundary.
VEX `VPERMD` forms 6780--6781 and `VPERMPS` forms 6886--6887 exactly own
map-2 opcodes `36`/`16` with pp=66, W=0, and L=1. Both require AVX2, write
YMM, read the YMM NDS source, and read YMM or m256 through ModRM. The focused
suite partitions 1,572,864 controls into 98,304 allocated and 1,474,560
reserved while locking all modes and NDS sources, non-long aliases, prefix/
field ownership, late address-payload truncation, both syntaxes, formatter
forgery rejection, profiles, and extras-OFF ownership. Existing EVEX
`VPERMD` forms 6782--6785 and `VPERMPS` forms 6884--6885/6888--6889 remain
separately owned and formatable. Twenty-five corpus rows and 15 readable
seeds preserve the pinned-XED and LLVM 21 boundary.
VEX `VPERMPD` forms 6878--6879 and `VPERMQ` forms 6890--6891 exactly own
map-3 opcodes `01`/`00` with pp=66, W=1, L=1, and encoded `vvvv=1111`.
Both require AVX2, write YMM, read YMM or m256, and expose imm8 as a read
operand. The focused classifier partitions 1,572,864 controls into 6,144
allocated and 1,566,720 reserved while locking every mode, non-long aliases,
prefix/field ownership, complete-payload truncation, both syntaxes, formatter
forgery rejection, profiles, and extras-OFF behavior. The same-name EVEX
forms 6874--6877/6880--6883 and 6892--6899 retain separate exact schemas.
Twenty-six corpus rows and 15 readable seeds preserve the pinned-XED and LLVM
21 boundary.
Classic-VEX `VPERMILPD` forms 6834--6837/6846--6849 and `VPERMILPS` forms
6854--6857/6866--6869 are exact. Map-3 immediate forms use NOVSR with encoded
`vvvv=1111`; map-2 variable-control forms use NDS. L selects XMM/YMM, W is
zero, every form requires AVX, and register/memory sources are distinguished.
The focused suite partitions 3,145,728 header controls into 208,896 allocated
and 2,936,832 reserved while locking all modes, non-long aliases, complete-
payload truncation, both syntaxes, exact same-name EVEX schema separation, and
extras-OFF ownership. Thirty-six corpus rows and 26 readable seeds preserve
the pinned-XED and LLVM 21 boundary.
Classic-VEX `VROUNDPD` forms 8539--8542, `VROUNDPS` forms 8543--8546,
`VROUNDSD` forms 8547--8548, and `VROUNDSS` forms 8549--8550 exactly own
map-3 opcodes `09`, `08`, `0B`, and `0A` with pp=66. Packed forms use NOVSR
with encoded `vvvv=1111` and L-selected XMM/YMM results; scalar forms use NDS
with L ignored. W is ignored throughout, register and memory sources remain
distinct, every form exposes imm8 as a read operand, and all forms require AVX.
The focused suite partitions 3,145,728 controls into 417,792 allocated and
2,727,936 reserved while locking all modes, non-long C4/LES and extension
aliases, payload-first truncation, both syntaxes, legacy `ROUND*` and EVEX
`VRNDSCALE*` separation, formatter-schema rejection, profiles, and extras-OFF
ownership. Thirty-six corpus rows and 26 readable seeds preserve the pinned-XED
and LLVM 21 boundary.
Classic-VEX `VSHUFPD` forms 8664--8665/8670--8671 and `VSHUFPS` forms
8674--8675/8680--8681 exactly own map-1 opcode `C6`. pp=66 selects PD,
pp=none selects PS, pp=F3/F2 are reserved, W is ignored, L selects XMM/YMM,
and `vvvv` is the NDS source. Every allocated form reads two vector sources
and imm8, writes its destination, and requires AVX. The focused suite
partitions the recognized VEX3 envelope into 393,216 allocated and 393,216
reserved controls while also locking VEX2, every mode, non-long aliases,
prefix/address ownership, payload-first truncation, both syntaxes, formatter
schema rejection, profile/runtime gates, and extras-OFF ownership. Same-name
EVEX forms 8666--8669/8672--8673 and 8676--8679/8682--8683 remain separately
owned. Thirty-six corpus rows and 24 readable seeds preserve the pinned-XED
and LLVM 21 boundary.
Classic-VEX `VTESTPD` forms 8795--8798 and `VTESTPS` forms 8799--8802 exactly
own map-2 opcodes `0F` and `0E`. Both require pp=66, W=0, encoded
`vvvv=1111`, and AVX; L selects XMM/YMM and the ModRM source distinguishes
register from memory forms. Both explicit operands are read, and the result
publishes the fixed ABI's generic status-flags write. The focused suite
partitions the recognized VEX3 envelope into 12,288 allocated and 1,560,576
reserved controls while locking modes, non-long aliases, prefixes, addresses,
payload-first truncation, map-3 siblings, both syntaxes, formatter-schema
rejection, profile/runtime gates, and extras-OFF ownership. Thirty-one corpus
rows and 21 readable seeds preserve the pinned-XED and LLVM 21 boundary.
Classic-VEX `VPTEST` forms 8319--8322 exactly own VEX3 map-2 mandatory-66
opcode `17 /r`; map 2 has no two-byte VEX encoding. Encoded `vvvv` must be
1111b, W is ignored, and L selects XMM/m128 or YMM/m256. Both widths require
AVX, both explicit operands are read, and the result publishes the fixed ABI's
generic status-flags write. The focused suite partitions all 786,432 controls
into 12,288 allocated and 774,144 reserved while locking modes, non-long
aliases, high registers and addressing, payload-first truncation, both
syntaxes, formatter-schema rejection, profile/runtime gates, and extras-OFF
ownership. Legacy `PTEST`, `VTESTPD`/`VTESTPS`, map-3 `VEXTRACTPS`, and EVEX
`VPTESTM*`/`VPTESTNM*` remain separately owned. Twenty-five corpus rows and 15
readable seeds preserve the pinned-XED and LLVM 21 boundary.
Classic-VEX `VPMOVMSKB` forms 7334--7335 exactly own map-1 mandatory-66
opcode `D7 /r`. ModRM is register-only, encoded `vvvv` must be 1111b, W is
ignored, and L selects XMM or YMM. The XMM form requires AVX and the YMM form
requires AVX2; both write a GPR32 destination and read the vector source. The
focused suite covers 3,584 allocated encodings across all modes, 1,792 per
form. Its long-mode partitions are 256 allocated plus 65,280 reserved C5
cells and 2,048 allocated plus 522,240 reserved C4 cells. Non-long aliases,
high registers, WIG, profile/runtime gates, both syntaxes, schema rejection,
extras-OFF ownership, and payload-first truncation for incomplete prefixed
addresses are exact. Legacy `PMOVMSKB` and EVEX `VPMOV{B,W,D,Q}2M`/
`VPMOVM2{B,W,D,Q}` remain separately owned. Twenty-five corpus rows and 14
readable seeds preserve the pinned-XED and LLVM 21 boundary.
Classic-VEX `VPSIGNB`/`VPSIGND`/`VPSIGNW` forms 7921--7932 exactly own C4
map-2 mandatory-66 opcodes `08`/`0A`/`09`. W is ignored, NDS `vvvv` names
the first source, and L selects XMM or YMM; XMM requires AVX and YMM requires
AVX2. Each result writes its destination and reads both equal-width vector
sources without flag effects. The focused suite exhausts 2,359,296 controls
as 589,824 allocated and 1,769,472 reserved, with 73,728 hits per memory form
and 24,576 per register form. It locks all modes, non-long aliases, high
registers and addressing, payload-first truncation, WIG, profile/runtime
gates, both syntaxes, formatter-schema rejection, and extras-OFF ownership.
Legacy `PSIGN*` and unowned EVEX/VEX2 neighbors remain separately owned.
Thirty-two corpus rows and 20 readable seeds preserve the pinned-XED and
LLVM 21 boundary.
Classic-VEX `VPSHUFD` forms 7891--7892/7895--7896, `VPSHUFHW` forms
7901--7902/7905--7906, and `VPSHUFLW` forms 7911--7912/7915--7916 exactly
own map-1 opcode `70 /r ib`. Mandatory 66/F3/F2 selects D/HW/LW, encoded
`vvvv` must be 1111b, W is ignored, and L selects XMM/m128 or YMM/m256.
XMM requires AVX and YMM requires AVX2. Results write the destination and
read the vector source and imm8. The focused suite partitions 884,736
all-mode C4/C5 controls into 43,008 allocated and 841,728 reserved cells,
including 5,376 hits per memory form and 1,792 per register form. It locks
every imm8, modes, non-long aliases, high registers and addressing,
payload-first truncation, WIG, profiles/runtime masks, both syntaxes,
formatter-schema rejection, and extras-OFF ownership. Legacy `PSHUF*` and
generated EVEX same-name siblings remain separately owned. Their P0.B4 and
U0/X4 memory spellings require APX and carry the `APX_F` group as formatter
provenance for EGPR addresses. Forty-two corpus rows and 26 readable seeds
preserve the pinned-XED and LLVM 21 boundary.
Classic-VEX `VUCOMISD` forms 8803--8804 and `VUCOMISS` forms 8809--8810
exactly own map-1 opcode `2E`. pp=66 selects SD and pp=none selects SS;
pp=F3/F2 and encoded `vvvv` values other than 1111b are reserved. W and L are
ignored. Both
explicit operands are read, the result publishes the fixed ABI's generic
status-flags write, and AVX admits every allocated form. The focused suite
partitions the recognized VEX3 envelope into 24,576 allocated and 761,856
reserved controls while locking every mode, non-long aliases, prefixes,
addressing, payload-first truncation, both syntaxes, formatter-schema rejection,
profile/runtime gates, and extras-OFF ownership. Legacy `UCOMI*`, same-name
EVEX forms 8805--8806/8811--8812, and `VUCOMISH` forms 8807--8808 remain
separately owned. Thirty-two corpus rows and 20 readable seeds preserve the
pinned-XED and LLVM 21 boundary.
Classic-VEX `VCOMISD` forms 3629--3630 and `VCOMISS` forms 3633--3634 exactly
own map-1 opcode `2F`. pp=66 selects SD and pp=none selects SS; pp=F3/F2 are
reserved, encoded `vvvv` must be 1111b (`VEX.NOVSR`), and W and L are ignored.
The first XMM operand and scalar 64-bit or 32-bit second source are read, the
result publishes the fixed ABI's generic status-flags write, and AVX admits
every allocated form. The focused suite partitions the recognized VEX3
envelope into 24,576 allocated and 761,856 reserved controls while locking
every mode, non-long aliases, prefixes, addressing, payload-first truncation,
both syntaxes, formatter-schema rejection, profile/runtime gates, and
extras-OFF ownership. Legacy `COMI*`, same-name EVEX `VCOMISD`/`VCOMISS`, and
`VCOMISH` remain separately owned. Thirty-two corpus rows and 20 readable
seeds preserve the pinned-XED and LLVM 21 boundary.
Classic-VEX `VDPPD` forms 4507--4508 and `VDPPS` forms 4515--4518 exactly own
map-3 mandatory-66 opcodes `41 /r ib` and `40 /r ib`. Both are WIG NDS
encodings and allocate the complete imm8. `VDPPD` allocates only XMM/m128 and
reserves L=1; `VDPPS` uses L to select XMM/m128 or YMM/m256. Allocated forms
write the destination, read both vector sources and the immediate, and require
AVX. The focused suite partitions the C4 envelope into 294,912 allocated and
1,277,952 reserved controls and checks 196,608 C5 collision/exclusion controls
while locking every mode, non-long B-prime/`vvvv` aliases, WIG, high registers
and addressing, prefixes, payload-first truncation, profile/runtime gates,
both syntaxes, formatter-schema rejection, legacy `DPP*` siblings, and
extras-OFF ownership. Thirty-nine corpus rows and 21 readable seeds preserve
the pinned-XED and LLVM 21 boundary.
Classic-VEX `VCMPPD` forms 3595--3598, `VCMPPS` forms 3611--3614,
`VCMPSD` forms 3617--3618, and `VCMPSS` forms 3623--3624 exactly own map-1
opcode `C2 /r ib`. Mandatory none/66/F3/F2 selects PS/PD/SS/SD, W is ignored,
and `vvvv` is the NDS source. Packed forms use L for XMM/YMM; scalar forms are
LIG with 128-bit destination/source-1 and a 32- or 64-bit register/memory
source-2. Every imm8 is allocated, with a low-five-bit predicate and
high-three-bit aliases. The result writes the destination, reads both sources
and the immediate, requires AVX, and publishes MXCSR use. The focused suite
exhausts all 884,736 C4/C5 controls and locks every imm8, WIG,
packed-L/scalar-LIG behavior, all modes, non-long B-prime/`vvvv` aliases,
long-mode high registers, addressing, payload-first truncation, both syntaxes,
formatter-schema rejection, profile/runtime gates, and extras-OFF ownership.
Legacy `CMP*` and generated same-name EVEX siblings remain separately owned.
Forty-two corpus rows and 20 readable seeds preserve the pinned-XED and LLVM
21 boundary.
Classic-VEX `VUNPCKHPD` forms 8825--8826/8831--8832, `VUNPCKHPS` forms
8835--8836/8841--8842, `VUNPCKLPD` forms 8845--8846/8851--8852, and
`VUNPCKLPS` forms 8855--8856/8861--8862 exactly own map-1 opcodes `15`
(high) and `14` (low). pp=66 selects PD, pp=none selects PS, pp=F3/F2 are
reserved, W is ignored, `vvvv` is the NDS source, and L selects XMM/YMM.
Every allocated form writes its destination, reads both vector sources, and
requires AVX. The focused suite exhausts the VEX3 envelope as 786,432
allocated and 786,432 reserved controls and the VEX2 envelope as 98,304
allocated and 98,304 reserved controls, while locking every mode, non-long
aliases, address formation, payload-first truncation,
both syntaxes, formatter-schema rejection, profile/runtime gates, and
extras-OFF ownership. Legacy `UNPCK*` and same-name EVEX forms remain
separately owned. Fifty-six corpus rows and 24 readable seeds preserve the
pinned-XED and LLVM 21 boundary.
Classic-VEX integer `VPUNPCKHBW` forms 8323--8324/8327--8328,
`VPUNPCKHDQ` forms 8333--8334/8337--8338, `VPUNPCKHQDQ` forms
8343--8344/8347--8348, `VPUNPCKHWD` forms 8353--8354/8357--8358,
`VPUNPCKLBW` forms 8363--8364/8367--8368, `VPUNPCKLDQ` forms
8373--8374/8377--8378, `VPUNPCKLQDQ` forms 8383--8384/8387--8388, and
`VPUNPCKLWD` forms 8393--8394/8397--8398 exactly own map-1 mandatory-66
opcodes `68`/`6A`/`6D`/`69` and `60`/`62`/`6C`/`61`. All are WIG NDS;
L selects XMM or YMM, XMM requires AVX, and YMM requires AVX2. Allocated
forms write the destination and read both equal-width vector sources. The
focused suite partitions 6,291,456 C4 controls into 1,572,864 allocated and
4,718,592 reserved and 786,432 C5 controls into 196,608 allocated and 589,824
reserved. It locks all modes, non-long aliases, addressing, payload-first
truncation, exact register mapping, both syntaxes, formatter-schema rejection,
profile/runtime gates, and extras-OFF ownership while preserving legacy
`PUNPCK*` and generated EVEX siblings. Sixty-nine corpus rows and 40 readable
seeds preserve the pinned-XED and LLVM 21 boundary.
Classic-VEX horizontal integer `VPHADDD` forms 7012--7015, `VPHADDSW` forms
7016--7019, `VPHADDW` forms 7036--7039, `VPHSUBD` forms 7046--7049,
`VPHSUBSW` forms 7050--7053, and `VPHSUBW` forms 7056--7059 exactly own C4
map-2 mandatory-66 opcodes `02`/`03`/`01` and `06`/`07`/`05`. They are WIG
NDS encodings: L=0 selects XMM/m128 and requires AVX; L=1 selects YMM/m256 and
requires AVX2. Each form writes its destination and reads both sources. The
focused suite exhausts 4,718,592 all-mode controls as 1,179,648 allocated and
3,538,944 reserved, with 73,728 hits per memory form and 24,576 per register
form. It locks non-long aliases, high registers and addressing, payload-first
truncation, profile/runtime gates, both syntaxes, formatter-schema rejection,
and extras-OFF ownership while preserving legacy `PHADD*`/`PHSUB*` and
AMD-XOP horizontal siblings. Forty-nine corpus rows and 37 readable seeds
preserve the pinned-XED and LLVM 21 boundary.
Classic-VEX `VPHMINPOSUW` forms 7040--7041 exactly own C4 map-2 mandatory-66
opcode `41 /r`. Encoded `vvvv` must be 1111b, L must be zero, W is ignored,
and all three modes require AVX. The destination is a written XMM register and
the source is a read XMM register or m128. The focused suite partitions all
786,432 controls into 6,144 allocated and 780,288 reserved, with 4,608 memory
and 1,536 register hits. It locks non-long aliases, high registers and
addresses, payload-first truncation, profile/runtime gates, both syntaxes,
formatter-schema rejection, and extras-OFF ownership while preserving legacy
`PHMINPOSUW`, same-opcode `KANDB`/`KANDW`, and adjacent EVEX `VPMOVSSDB`.
Thirty-five corpus rows and 17 readable seeds preserve the pinned-XED and
LLVM 21 boundary.
Classic-VEX `VPINSRB`/`VPINSRD`/`VPINSRQ`/`VPINSRW` forms
7060--7061/7064--7065/7068--7069/7072--7073 exactly own fixed-width XMM NDS
inserts with an imm8 selector. B/D/W register sources are GPR32, Q is GPR64,
and their memory alternatives are m8/m32/m16/m64. B and W are WIG; map-3
opcode `22` selects D with W=0 and Q with W=1 in long mode, while non-long
W=1 aliases D. VPINSRW's map-1 opcode `C4` admits both C4 and C5 spellings.
Allocated forms write the destination and read the NDS vector source, scalar
source, and imm8, and require AVX. The focused selector/ModRM sweep partitions
2,359,296 C4 controls into 294,912 allocated and 2,064,384 reserved, and
98,304 C5 controls into 12,288 allocated and 86,016 reserved. It locks every
form, mode and non-long alias, high registers and addresses, payload-first
truncation, profile/runtime gates, both syntaxes, formatter-schema rejection,
and extras-OFF ownership while preserving legacy `PINSR*` and same-name EVEX
siblings. Fifty-two corpus rows and 24 readable seeds preserve the pinned-XED
and LLVM 21 boundary.
Classic-VEX `VPEXTRB`/`VPEXTRD`/`VPEXTRQ`/`VPEXTRW` forms 6966/6968,
6970/6972, 6974/6976, 6978/6983, and register-only map-1 form 6979 exactly own
fixed-width XMM extracts with an imm8 selector. B/D/W register destinations
are GPR32, Q is GPR64, and the memory alternatives are m8/m32/m16/m64;
map-1 `VPEXTRW` reverses the usual ModRM ownership and has no memory form.
Encoded `vvvv` must be 1111b, L must be zero, B/W are WIG, and map-3 opcode
`16` selects D with W=0 and Q with W=1 in long mode, while non-long W=1
aliases D. Allocated forms write their scalar destination, read the XMM source
and imm8, and require AVX. The exhaustive sweep partitions 3,145,728 C4
controls into 19,968 allocated and 3,125,760 reserved, and 98,304 C5 controls
into 256 allocated and 98,048 reserved. It locks all modes, C4/C5 spellings,
non-long aliases, registers and addresses, payload-first truncation, both
syntaxes, formatter-schema rejection, and extras-OFF ownership while
preserving legacy `PEXTR*` and all same-name EVEX siblings. Sixty-six corpus
rows and 30 readable seeds preserve the pinned-XED and LLVM 21 boundary.
Classic-VEX `VPMOVSXBW`/`VPMOVSXBD`/`VPMOVSXBQ`/`VPMOVSXWD`/`VPMOVSXWQ`/
`VPMOVSXDQ` forms 7419--7420/7425--7426, 7399--7400/7405--7406,
7409--7410/7415--7416, 7439--7440/7445--7446,
7449--7450/7455--7456, and 7429--7430/7435--7436 exactly own C4 map-2
mandatory-66 opcodes `20`--`25`. They are WIG NOVSR operations: encoded
`vvvv` must be 1111b, L=0 selects an AVX XMM destination, and L=1 selects an
AVX2 YMM destination. The XMM register or memory source has the exact low
width consumed by the widening ratio, from 16 through 128 bits. Results write
their destination and read their source. The exhaustive all-mode sweep
partitions 4,718,592 controls into 73,728 allocated and 4,644,864 reserved,
with 4,608 memory-form and 1,536 register-form hits per family/width pair. It
locks non-long aliases,
high registers and addresses, payload-first truncation, profile/runtime gates,
both syntaxes, formatter-schema rejection, and extras-OFF ownership while
preserving legacy `PMOVSX*` and generated EVEX siblings. Sixty-two corpus rows
and 36 readable seeds preserve the pinned-XED and LLVM 21 boundary.
Classic-VEX `VPMOVZXBW`/`VPMOVZXBD`/`VPMOVZXBQ`/`VPMOVZXWD`/`VPMOVZXWQ`/
`VPMOVZXDQ` forms 7524--7525/7530--7531, 7504--7505/7510--7511,
7514--7515/7520--7521, 7544--7545/7550--7551,
7554--7555/7560--7561, and 7534--7535/7540--7541 exactly own C4 map-2
mandatory-66 opcodes `30`--`35`. They mirror the signed WIG NOVSR shape: L=0
selects an AVX XMM destination and L=1 an AVX2 YMM destination, while the XMM
register or memory source consumes exactly 16 through 128 low bits. Results
write their destination and read their source. The exhaustive all-mode sweep
partitions 4,718,592 controls into 73,728 allocated and 4,644,864 reserved,
with 4,608 memory-form and 1,536 register-form hits per family/width pair. It
locks non-long aliases, high registers and addresses, payload-first
truncation, profile/runtime gates, both syntaxes, formatter-schema rejection,
and extras-OFF ownership while preserving legacy `PMOVZX*`, C5 non-siblings,
and generated EVEX siblings. Sixty-two corpus rows and 36 readable seeds
preserve the pinned-XED and LLVM 21 boundary.
AMD XOP `VPCMOV` forms 6410--6415 are exact for XMM/YMM register and memory
sources. W swaps the memory and selector-source operand positions; register
spellings collapse their W aliases to forms 6412 and 6415. The trailing
`SE_IMM8` is selector metadata rather than an immediate operand: its high
nibble selects the fourth vector register, its low nibble is ignored,
`encoding.selector_offset` records the byte, and `encoding.immediate_count`
is zero. Results carry AVX and XOP groups. Outside long mode, XOP extension
bits and the high bits of `vvvv` and the selector alias as pinned XED and LLVM
21 specify. The focused classifier contains 393,216 allocated and 1,179,648
reserved controls and locks address formation, prefix/pp ownership, payload-
complete truncation precedence, profile/runtime gates, formatting-schema
rejection, and extras-OFF behavior. Twenty-five corpus rows and 16
`x86_vpcmov_*.hex` seeds preserve the same boundaries.
AMD XOP `VPPERM` forms 7686--7688 are exact XMM forms. W moves the ModRM
memory source between operand slots three and four; both all-register W
spellings collapse to form 7688. The trailing `SE_IMM8` is selector metadata,
not an immediate operand: its high nibble selects the fourth XMM source, its
low nibble is ignored, `encoding.selector_offset` records the byte, and
`encoding.immediate_count` remains zero. L and nonzero pp are reserved;
operand-size, repeat, LOCK, and REX legacy prefixes are invalid, while
address-size and segment overrides are accepted. Reserved-control validity is
decided only after the complete ModRM/SIB/displacement/selector payload has
been consumed, retaining `TRUNCATED` precedence for incomplete owned inputs.
All three modes are supported. Outside long mode, XOP R/X/B, high `vvvv`, and
selector extensions alias into the eight-register namespace, following LLVM
21 and the existing exact XOP-selector policy; pinned XED's isolated `r12d`
result for one 32-bit SIB.X spelling is treated as anomalous. Results carry
AVX and XOP groups and require the XOP runtime selector plus a compatible CPU
profile. Twenty-seven corpus rows and 16 `x86_vpperm_*.hex` seeds preserve the
same boundaries.
ARM `CTERMEQ` form 2593 and `CTERMNE` form 2594 exactly implement the
SVE-or-SME conditional-termination pair. They read Wn/Wm or Xn/Xm according
to `sz`, map register 31 to WZR/XZR, and publish exact scalable-vector and
NZCV-write metadata without a predication flag or generic opcode group.
ARM predicate-break forms 2546--2555 exactly implement `BRKPA`/`BRKPAS`,
`BRKPB`/`BRKPBS`, `BRKA`/`BRKAS`, `BRKB`/`BRKBS`, and `BRKN`/`BRKNS`.
BRKP forms write typed `Pd.B` and read zeroing `Pg`, typed `Pn.B`, and typed
`Pm.B`. BRKA/BRKB have three operands: their `/m` controls read/write `Pd`,
whereas `/z` and every flag-setting form write it. BRKN writes `Pd` and
exposes its tied typed source as a fourth read operand. All ten carry exactly
scalable-vector and predicated metadata; the five `S` forms additionally set
NZCV. SVE or SME admits 294,912 allocated words, while 270,336 parent residual
controls are structurally invalid.
ARM predicate-control forms 2556--2561 exactly implement `PTEST`, `PFIRST`,
`PNEXT`, ordinary `PTRUE`, `PTRUES`, and `PFALSE`. They preserve typed data
predicates, untyped governing/control predicates, explicit tied destination
reads for PFIRST and PNEXT, and the raw PTRUE/PTRUES pattern selector. Only
PTEST and PTRUES set NZCV; only PTEST and PFIRST are predicated. All require
SVE or SME. The exact union contains 5,648 allocated and 16,944 reserved
words.
ARM `PSEL` form 2565 exactly owns mask/value `0xff20c210/0x25204000` and
formats `Pd, Pn, Pm.T[Wv, lane]`. The first two operands carry the selected
element granularity without a printed suffix; indexed `Pm.B/H/S/D` carries
W12--W15 and the size-dependent lane. Access is write/read/read, the only
instruction flag is `SCALABLE_VECTOR`, and admission is the exact alternative
SVE2.1 or baseline SME. Thirty of the 32 `i1:tsz` controls allocate 491,520 words;
the two `tsz=0000` controls make 32,768 words invalid, and all 524,288 bit-4
neighbors remain delegated.
ARM wide-immediate forms 2619--2632 are exact. Forms 2619--2630 implement
destructive `ADD`, `SUB`, `SUBR`, `SQADD`, `SQSUB`, `UQADD`, `UQSUB`, `SMAX`,
`SMIN`, `UMAX`, `UMIN`, and `MUL` with a typed `Zdn` write, tied `Zdn` read,
and immediate read. The first seven use unsigned imm8 with optional `lsl #8`
and reject byte-width shifting; SMAX/SMIN/MUL use signed imm8 and UMAX/UMIN
use unsigned imm8. Shifted nonzero values are stored semantically scaled;
shifted zero retains LSL metadata. Integer `DUP` form 2631 is exposed as its
preferred `MOV` with a signed imm8. `FDUP` form 2632 is exposed as preferred
`FMOV`; it expands imm8 to the exact H/S/D IEEE bit pattern and adds the
floating-point flag. Its immediate operand size is one byte because that field
describes the encoded imm8; destination `extend_type` records H/S/D. Every
form requires SVE or SME and carries scalable-vector metadata. The complete
2,097,152-word parent has 565,248 arithmetic, 57,344 DUP, and 24,576 FDUP
allocations; its 57,344 arithmetic leaf controls, 8,192 DUP controls, 8,192
FDUP controls, and remaining 1,376,256 words are invalid.
ARM unpredicated `SDOT`/`UDOT` forms 2633--2636 are exact. Baseline SVE-or-SME
forms widen B sources into a tied read/write S accumulator or H sources into a
D accumulator; SVE2p3-or-SME2p3 forms widen B sources into H. Zn and Zm are
read-only, every register field spans Z0--Z31, and the only instruction flag is
`SCALABLE_VECTOR`. The shared 262,144-word parent has 196,608 allocated words
and 65,536 reserved `size=00` words, with no delegated residual. A64FX reaches
the baseline through SVE and Apple A18/M4 through SME; the p3 forms are
`CPU_ANY`-only because no named profile advertises SVE2p3 or SME2p3. LLVM 21
confirms the baseline forms; pinned AARCHMRS supplies the p3 oracle that LLVM
21 does not yet assemble.
ARM SVE2-or-SME forms 2637--2641 are exact. `SQDMLALBT` and `SQDMLSLBT`
widen B/H/S sources into tied read/write H/S/D accumulators and reserve
`size=00`; `CDOT` widens B/H sources into S/D and reserves `size=00/01`;
`CMLA` and `SQRDCMLAH` accept B/H/S/D. The latter three expose semantic
`#0/#90/#180/#270` rotation immediates. Every source is read-only and the only
instruction flag is `SCALABLE_VECTOR`. The exact parents contain 1,507,328
allocated and 327,680 reserved words with no delegated residual. LLVM 21
confirms all 46 legal arrangement/rotation combinations and rejects the
reserved-width samples.
ARM SVE2-or-SME forms 2642--2655 are exact. `SMLALB`, `SMLSLB`, `SMLALT`,
`SMLSLT`, `UMLALB`, `UMLSLB`, `UMLALT`, `UMLSLT`, `SQDMLALB`, `SQDMLSLB`,
`SQDMLALT`, and `SQDMLSLT` widen B/H/S sources into tied read/write H/S/D
accumulators and reserve `size=00`. `SQRDMLAH` and `SQRDMLSH` instead use
tied, same-width B/H/S/D accumulators. Zn and Zm are read-only and every form
carries exactly `SCALABLE_VECTOR`. The exact parents contain 1,441,792
allocated and 393,216 reserved words, with no delegated residual; baseline
SVE alone is insufficient, while Apple A18/M4 are admitted through SME.
ARM indexed SVE2-or-SME `MLA`/`MLS` forms 2722--2727 are exact. H uses
mask/value `ffa0fc00/44200800` and `ffa0fc00/44200c00`, S uses
`ffe0fc00/44a00800` and `ffe0fc00/44a00c00`, and D uses
`ffe0fc00/44e00800` and `ffe0fc00/44e00c00`. All six leaves expose tied
read/write `Zda`, read-only `Zn`, and read-only indexed `Zm`: H permits
Zm0--Zm7/lane 0--7, S permits Zm0--Zm7/lane 0--3, and D permits
Zm0--Zm15/lane 0--1. Their 262,144 words are all allocated and carry only
`SCALABLE_VECTOR`. `CDISASM_ARM_CPU_ANY`, Apple A18, and Apple M4 succeed;
A64FX and Cortex-A53 reject the SVE2-or-SME requirement. The exhaustive suite,
LLVM 21, 22 corpus rows, and 15 MLA/MLS seeds lock formatting, feature and
profile gates, endian/generic transport, truncation, collision ownership, and
extras-OFF behavior against the adjacent indexed rounding family.
ARM indexed SVE2-or-SME `SQRDMLAH`/`SQRDMLSH` forms 2728--2733 are exact. H
uses mask `0xffa0fc00` with values `0x44201000`/`0x44201400`; S uses mask
`0xffe0fc00` with values `0x44a01000`/`0x44a01400`, and D uses the same mask
with values `0x44e01000`/`0x44e01400`. All six leaves expose tied read/write
`Zda`, read-only `Zn`, and read-only indexed `Zm`: H permits Zm0--Zm7/lane
0--7, S permits Zm0--Zm7/lane 0--3, and D permits Zm0--Zm15/lane 0--1. Their
262,144 words are all allocated, carry only `SCALABLE_VECTOR`, and require
SVE2 or SME. The adjacent indexed `USDOT` leaf remains separately owned. The
exhaustive suite, LLVM 21, pinned AARCHMRS, 20 corpus rows, and 15 total family
seeds lock formatting, feature and profile gates, endian/generic transport,
truncation, collision ownership, and extras-OFF behavior.
ARM `USDOT` form 2656 exactly owns mask/value `ffe0fc00/44807800` in parent
`ff20fc00/44007800`. Its 32,768 `size=10` words expose read/write `Zda.S`
plus read-only `Zn.B` and `Zm.B`; the remaining 98,304 size siblings are
reserved. It carries only scalable-vector metadata and requires
`(SVE or SME) and I8MM`. `CPU_ANY` admits it, while A64FX, Apple A18/M4, and
Cortex-A53 reject it because current named profiles do not advertise I8MM.
LLVM 21 confirms representative low/high encodings and pinned AARCHMRS fixes
the complete parent partition.
ARM indexed `USDOT`/`SUDOT` forms 2734--2735 exactly own the wholly allocated
`0xffe0fc00` leaves at `0x44a01800`/`0x44a01c00`. Their 65,536 words expose
read/write `Zda.S`, read-only `Zn.B`, and read-only `Zm.B[lane]`, with Z0--Z31
accumulator/first-source fields, Z0--Z7 indexed sources, and lanes 0--3. It
carries only `SCALABLE_VECTOR` and requires I8MM together with SVE or SME.
`CDISASM_ARM_CPU_ANY` succeeds; all 38 named profiles reject the feature or
reject A64 mode because no current A64-capable profile advertises I8MM.
Extras-OFF builds return `UNSUPPORTED_INSTRUCTION` and incomplete words return
`TRUNCATED`. LLVM 21 matches all 65,536 words. Eighteen corpus rows and eight
readable seeds lock the complete operand, feature,
profile, endian/generic, formatter, sibling, truncation, and ownership
contracts.
ARM SVE `AESMC`/`AESIMC` forms 2903--2904 exactly own 64 words under
`0xfffffbe0`/`0x4520e000`. Both explicit operands are the same read/write
`Zdn.B`; FEAT_SVE_AES is required and only `CPU_ANY` currently admits it.
The 192 other size controls in parent `0xff3ffbe0`/`0x4520e000` are invalid in
both extras variants. The focused suite exhausts the 64/192 partition; LLVM 21
`+sve2-aes`, 13 corpus rows, and six readable seeds preserve the schema.
ARM SVE `AESE`/`AESD` forms 2905--2906 and `SM4E` form 2907 occupy three
1,024-word leaves in parent `0xff3ef800`/`0x4522e000`. The AES pair uses tied
read/write `Zdn.B` plus read-only `Zm.B` under FEAT_SVE_AES; `SM4E` uses the
same access recipe with `.S` under FEAT_SVE_SM4. All other thirteen selector
rows are invalid, yielding 3,072 allocated and 13,312 reserved words. LLVM 21
matches the complete partition; 19 corpus rows and nine readable seeds retain
profile, endian, formatter, truncation, and extras-OFF contracts.
ARM SVE `PUNPKLO` form 2468 and `PUNPKHI` form 2469 exactly own all 512 words
in parent `0xfffefe10`/`0x05304000`; bit 16 selects low versus high. Each
result writes `Pd.H`, reads `Pn.B`, carries only scalable-vector metadata, and
requires SVE or SME. A64FX is admitted through SVE and Apple A18/M4 through
SME; Cortex-A53 rejects the family. The focused suite and LLVM 21 exhaust both
256-word leaves under SVE and SME. Twelve corpus rows and four readable seeds
retain profile, endian/generic, formatter, truncation, and extras-OFF contracts.
ARM SVE/SME `SUNPKLO`/`SUNPKHI`/`UUNPKLO`/`UUNPKHI` forms 2456--2459
exactly own parent `0xff3cfc00`/`0x05303800`. Control bits 17:16 select four
leaves under mask `0xff3ffc00` at values `0x05303800`, `0x05313800`,
`0x05323800`, and `0x05333800` in form/name order. `size=01/10/11` widens
B-to-H, H-to-S, or S-to-D, while `size=00` is reserved. Each result writes
`Zd.T`, reads `Zn` at half that element width, carries only scalable-vector
metadata, and requires SVE or SME.
A64FX is admitted through SVE and Apple A18/M4 through SME. The
`cdisasm_arm_sve_unpack_tests` suite exhausts 12,288 allocated and 4,096
reserved words and locks profiles, endian/generic transport, canonical
formatting and forged-schema rejection, truncation, and extras-OFF ownership.
LLVM 21 matches every allocated formula word and reports every reserved word
unknown; 22 corpus rows and nine readable seeds retain the boundary.
ARM SVE2/SME `SRI` form 2846 and `SLI` form 2847 exactly own parent
`0xff20f800`/`0x4500f000`; their leaves use mask `0xff20fc00` at
`0x4500f000` and `0x4500f400`. Encoded `tszh:tszl:imm3` values 8--127 select
B/H/S/D by highest-set-bit band; values 0--7 are reserved. `SRI` exposes
immediate `2*element_bits-encoded`, from #element_bits through #1, while `SLI`
exposes `encoded-element_bits`, from #0 through #element_bits-1. Both expose
tied read/write `Zdn.T`, read-only `Zn.T`, and a read immediate, carry only
scalable-vector metadata, and require SVE2 or SME. The
`cdisasm_arm_sve_shift_insert_tests` suite exhausts 245,760 allocated and
16,384 reserved words and locks profiles, both byte orders, generic transport,
formatting and forged-schema rejection, truncation, and extras-OFF ownership.
LLVM 21 matches the complete domain; 21 corpus rows and ten readable seeds
retain the boundary.
ARM Advanced SIMD `BSL`/`BIT`/`BIF` forms 6188/6196/6198 exactly own leaves
under mask `0xbfe0fc00` at values `0x2e601c00`, `0x2ea01c00`, and
`0x2ee01c00`. Q selects 8B or 16B; Vd is read/write and Vn/Vm are read-only.
All results carry SIMD metadata and require baseline Advanced SIMD/NEON. The
`cdisasm_arm_advsimd_bitwise_select_tests` suite exhausts 196,608 allocated
words with no reserved words inside the three exact leaves, while separately
locking adjacent AND/BIC/ORR/ORN/EOR ownership, profiles, both byte orders,
generic transport, formatting, truncation, and extras-OFF behavior. Eighteen
corpus rows and seven readable seeds retain the LLVM 21-verified boundary.
ARM Advanced SIMD `ADDHN`/`SUBHN`/`RADDHN`/`RSUBHN` forms
6093/6095/6108/6110 exactly own four `0xbf20fc00` leaves at values
`0x0e204000`, `0x0e206000`, `0x2e204000`, and `0x2e206000`. Size controls
zero through two narrow H/S/D sources to B/H/S results and size three is
reserved. Q=0 writes an 8-byte destination with the base mnemonic; Q=1
preserves its low half, writes the high half, and formats the `*HN2` spelling
with a read/write 16-byte destination. Both sources are read-only 16-byte
vectors. Results carry SIMD metadata and require baseline Advanced SIMD/NEON.
The `cdisasm_arm_advsimd_high_narrow_tests` suite exhausts 786,432 allocated
and 262,144 reserved words while locking profiles, endian/generic transport,
canonical formatting and forged-schema rejection, fixed neighbors,
truncation, and extras-OFF ownership. Twenty-two corpus rows and 11 readable
seeds retain the pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD `SADDL`/`SADDW`/`SSUBL`/`SSUBW` forms 6089--6092 and
`UADDL`/`UADDW`/`USUBL`/`USUBW` forms 6104--6107 exactly own eight
`0xbf20fc00` leaves at opcode nibbles zero through three. Size controls zero
through two widen B/H/S elements to H/S/D; size three is reserved. Q selects
the base or `2` spelling and the lower or upper half of each narrow source.
Long forms write a 16-byte wide destination and read two narrow sources; wide
forms read a wide first source plus a narrow second source. Results carry only
SIMD metadata and require baseline Advanced SIMD/NEON. The focused suite
partitions 2,097,152 words into 1,572,864 allocated and 524,288 reserved and
locks profiles, endian/generic transport, canonical formatting, independent
raw/form/name ownership, forged-schema rejection, fixed neighbors,
truncation, and extras-OFF ownership. Thirty-four corpus rows and 13 readable
seeds retain the pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD `SABAL`/`SABDL` forms 6094/6096 and `UABAL`/`UABDL`
forms 6109/6111 exactly own four `0xbf20fc00` leaves at values
`0x0e205000`, `0x0e207000`, `0x2e205000`, and `0x2e207000`. Size controls
zero through two widen B/H/S inputs to H/S/D results and size three is
reserved. Q selects the base or `2` spelling and lower or upper narrow source
halves. `SABAL`/`UABAL` read/write the 16-byte destination; `SABDL`/`UABDL`
write it, and all narrow inputs are read-only. Results carry only SIMD
metadata and require baseline Advanced SIMD/NEON. The focused suite partitions
1,048,576 words into 786,432 allocated and 262,144 reserved and locks
profiles, endian/generic transport, exact formatting with independent raw/
form/name ownership, fixed neighbors, truncation, and extras-OFF behavior.
The shared-name SVE2p3/SME2p3 forms 2709--2710 remain separately owned and
unsupported pending exact operand lowering. Twenty-two corpus rows and eight
readable seeds retain the pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD `SMLAL`/`SMLSL`/`SMULL` forms 6097/6099/6101 and
`UMLAL`/`UMLSL`/`UMULL` forms 6112--6114 exactly own six `0xbf20fc00`
leaves at values `0x0e208000`, `0x0e20a000`, `0x0e20c000`, `0x2e208000`,
`0x2e20a000`, and `0x2e20c000`. Size zero through two widens B/H/S inputs
to H/S/D results; size three is reserved. Q selects the base or `2` spelling
and lower or upper input halves. Multiply-add/subtract forms read/write the
16-byte destination, while multiply-long forms write it; both narrow inputs
are read-only. Results carry SIMD-only metadata and require baseline Advanced
SIMD/NEON. The focused suite partitions 1,572,864 words into 1,179,648
allocated and 393,216 reserved and locks profiles, endian/generic transport,
exact formatting, fixed neighbors, truncation, and extras-OFF ownership.
Exact collision validation preserves genuine A32/T32 long multiplies and
generated A64 scalar aliases/SME forms while rejecting cross-schema grafts.
Twenty-eight corpus rows and ten readable seeds retain the pinned-AARCHMRS
and LLVM 21 boundary.
ARM Advanced SIMD `SQDMLAL`/`SQDMLSL`/`SQDMULL` forms 6098/6100/6102 exactly
own three `0xbf20fc00` leaves at values `0x0e209000`, `0x0e20b000`, and
`0x0e20d000`. Sizes one and two widen H/S inputs to S/D results; sizes zero
and three are reserved. Q selects the base or `2` spelling and lower or upper
input halves. Add/subtract forms read/write the 16-byte destination, while
multiply-long writes it; both inputs are read-only. Results carry SIMD-only
metadata and require baseline Advanced SIMD/NEON. The focused suite exhausts
786,432 words as 393,216 allocated and 393,216 reserved, with exact fixed-
vector formatting and scalar/by-element collision isolation. Twenty-two
corpus rows and eight readable seeds preserve the pinned-AARCHMRS and LLVM 21
boundary.
ARM Advanced SIMD `SQDMULH` form 6136 and `SQRDMULH` form 6178 exactly own
`0xbf20fc00` leaves at values `0x0e20b400` and `0x2e20b400`. Sizes one and
two select Q-dependent 4H/8H and 2S/4S arrangements; byte and doubleword sizes
are reserved. Each form writes Vd and reads Vn and Vm, carries SIMD metadata,
and requires baseline Advanced SIMD/NEON. The focused suite exhausts 524,288
words as 262,144 allocated and 262,144 reserved while locking profiles, both
byte orders, generic transport, formatting and forged-schema rejection,
truncation, extras-OFF ownership, and independent scalar, by-element, SVE, and
SME siblings. Twenty-two corpus rows and eight readable seeds retain the
pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD `PMULL`/`PMULL2` form 6103 exactly owns mask/value
`0xbf20fc00`/`0x0e20e000`. Size zero selects byte-to-halfword polynomial
multiplication under baseline Advanced SIMD; size three selects D-to-Q and
additionally requires FEAT_PMULL. Sizes one and two are reserved. Q selects
the base or `2` spelling and low or high halves. Allocated forms write a
16-byte destination and read two 8- or 16-byte sources. `CPU_ANY` admits both
sizes; named profiles conservatively reject size three until authoritative
per-profile PMULL metadata is available. The focused suite exhausts 262,144
words as 131,072 allocated and 131,072 reserved and locks endian/generic
transport, profile and feature gates, formatting, truncation, sibling
separation, and extras-OFF ownership. Twenty corpus rows and eight readable
seeds retain the pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD `PMUL` form 6175 exactly owns mask/value
`0xbf20fc00`/`0x2e209c00`. Only size zero is allocated; Q selects 8B or 16B,
and sizes one through three are reserved. It writes Vd, reads Vn and Vm,
carries fixed-width SIMD metadata, and requires baseline Advanced SIMD/NEON.
The focused suite exhausts 262,144 words as 65,536 allocated and 196,608
reserved while locking profiles, endian/generic transport, exact formatting,
sibling separation, truncation, and extras-OFF ownership. Eighteen corpus rows
and eight readable seeds preserve the pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD pairwise `SMAXP`/`SMINP` forms 6134--6135 and
`UMAXP`/`UMINP` forms 6176--6177 exactly own four `0xbf20fc00` leaves at
values `0x0e20a400`, `0x0e20ac00`, `0x2e20a400`, and `0x2e20ac00`.
Sizes zero through two select B/H/S elements, size three is reserved, and Q
selects 64- or 128-bit vectors. Allocated forms write Vd, read Vn and Vm,
carry SIMD-only metadata, and require baseline Advanced SIMD/NEON. The focused
suite exhausts 1,048,576 words as 786,432 allocated and 262,144 reserved and
locks profiles, endian/generic transport, formatting and forged-schema
rejection, same-name SVE isolation, truncation, and extras-OFF ownership.
Forty-two corpus rows and eight readable seeds preserve the pinned-AARCHMRS
and LLVM 21 boundary.
ARM Advanced SIMD `ADDP` scalar form 5808 exactly owns mask/value
`0xfffffc00`/`0x5ef1b800`, writes `Dd`, and reads `Vn.2D`. Fixed-vector form
6137 owns `0xbf20fc00`/`0x0e20bc00`, writes Vd, and reads Vn and Vm in the
legal 8B/16B, 4H/8H, 2S/4S, and 2D arrangements; Q=0 with size=3 is the
reserved 1D cell. Both forms require baseline Advanced SIMD and retain exact
scalar/vector typing and canonical formatting. The focused suite exhausts all
1,024 scalar allocations and partitions the vector parent into 229,376
allocated and 32,768 reserved words while locking profiles, endian/generic
transport, truncation, sibling separation, formatter forgery rejection, and
extras-OFF ownership. Sixteen corpus rows and ten readable seeds preserve the
pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD `ADDV` form 6077 exactly owns mask/value
`0xbf3ffc00`/`0x0e31b800`. Q:size allocates `8B`/`16B` to a scalar B
destination, `4H`/`8H` to H, and `4S` to S; `2S`, `1D`, and `2D` are reserved.
The allocated form writes the scalar destination, reads the fixed-width vector
source, carries SIMD-only metadata, and requires baseline Advanced SIMD/NEON.
The focused suite exhausts the 8,192-word envelope as 5,120 allocated and 3,072
reserved words while locking profiles, endian/generic transport, canonical
formatting and forged-schema rejection, sibling separation, truncation, and
extras-OFF ownership. Thirteen corpus rows and ten readable seeds preserve the
pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD regular `SMAX`/`SMIN` forms 6126--6127 and `UMAX`/`UMIN`
forms 6168--6169 exactly own four `0xbf20fc00` leaves at values
`0x0e206400`, `0x0e206c00`, `0x2e206400`, and `0x2e206c00`. Sizes zero
through two select B/H/S elements, size three is reserved, and Q selects
64- or 128-bit vectors. Allocated forms write Vd, read Vn and Vm, carry
SIMD-only metadata, and require baseline Advanced SIMD/NEON. The focused
suite exhausts 1,048,576 words as 786,432 allocated and 262,144 reserved and
locks profiles, endian/generic transport, exact formatting and forged-schema
rejection, truncation, extras-OFF ownership, and independent SVE, SME2, and
CSSC same-name siblings. Forty-two corpus rows and eight readable seeds
preserve the pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD register `CMGT`/`CMGE` forms 6120--6121, `CMHI`/`CMHS`
forms 6162--6163, and `CMEQ` form 6173 exactly own five `0xbf20fc00` leaves
at values `0x0e203400`, `0x0e203c00`, `0x2e203400`, `0x2e203c00`, and
`0x2e208c00`. Q=0 allocates B/H/S arrangements and reserves 1D; Q=1
allocates B/H/S/D arrangements. Allocated forms write Vd, read Vn and Vm,
carry SIMD-only metadata, and require baseline Advanced SIMD/NEON. The
focused suite exhausts 1,310,720 words as 1,146,880 allocated and 163,840
reserved while locking profiles, endian/generic transport, canonical
formatting, forged-schema rejection, scalar and compare-with-zero sibling
isolation, truncation, and extras-OFF ownership. Fifty-seven corpus rows and
nine readable seeds preserve the pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD `CMTST` scalar form 5831 exactly owns
`0xffe0fc00`/`0x5ee08c00` and writes `Dd` while reading `Dn` and `Dm`.
Vector form 6131 owns `0xbf20fc00`/`0x0e208c00`; Q=0 allocates B/H/S and
reserves 1D, while Q=1 allocates B/H/S/D. Both forms carry SIMD-only metadata
and require baseline Advanced SIMD/NEON. The focused suite partitions 294,912
words into 262,144 allocated and 32,768 reserved while locking profiles,
endian/generic transport, canonical scalar/vector formatting, raw/form/name
forgery rejection, adjacent `CMEQ` and compare-with-zero siblings, truncation,
and extras-OFF ownership. Eighteen corpus rows and eight readable seeds
preserve the pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD `SSHL`/`USHL` scalar forms 5826/5841 exactly own
`0xffe0fc00` leaves `0x5ee04400`/`0x7ee04400`; vector forms 6122/6164 own
`0xbf20fc00` leaves `0x0e204400`/`0x2e204400`. Scalar forms use D registers.
Vector B/H/S arrangements exist at both Q widths, D exists only at Q=1, and
Q=0 1D is reserved. Allocated results write the destination, read both
sources, carry SIMD-only metadata, and require baseline Advanced SIMD/NEON.
The focused suite exhausts 589,824 words as 524,288 allocated and 65,536
reserved while locking profiles, endian/generic transport, canonical
scalar/vector formatting, raw/form/name forgery rejection, saturating and
rounding-shift sibling isolation, truncation, and extras-OFF ownership.
Twenty-seven corpus rows and 34 readable seeds preserve the pinned-AARCHMRS
and LLVM 21 boundary.
ARM Advanced SIMD fixed-vector `SABA`/`UABA` forms 6129/6171 exactly own
`0xbf20fc00` leaves `0x0e207c00`/`0x2e207c00`. Q selects 64- or 128-bit
vectors; B/H/S are allocated at both widths and size=3 is reserved. Every
allocated form reads and updates Vd, reads Vn and Vm, carries SIMD-only
metadata, and requires baseline Advanced SIMD/NEON. The focused suite
exhausts the 524,288-word parent as 393,216 allocated and 131,072 reserved,
locking registers and arrangements, profiles, endian/generic transport,
canonical formatting, raw/form/name forgery rejection, truncation, and
extras-OFF ownership. `SABD`/`UABD`, widening `SABAL`/`UABAL`, and generated
SVE same-name siblings remain separately owned. Twenty-three corpus rows and
30 readable seeds preserve the pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD fixed-vector `SABD`/`UABD` forms 6128/6170 exactly own
`0xbf20fc00` leaves `0x0e207400`/`0x2e207400`. Q selects 64- or 128-bit
vectors; B/H/S are allocated at both widths and size=3 is reserved. Every
allocated form writes Vd, reads Vn and Vm, carries SIMD-only metadata, and
requires baseline Advanced SIMD/NEON. The focused suite exhausts the
524,288-word parent as 393,216 allocated and 131,072 reserved while locking
registers, arrangements, profiles, endian/generic transport, canonical
formatting, raw/form/name forgery rejection, truncation, and extras-OFF
ownership. Accumulating `SABA`/`UABA`, widening `SABDL`/`UABDL`, and generated
SVE same-name forms remain separately owned. Twenty-three corpus rows and 24
readable seeds preserve the pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD fixed-vector `MLA`/`MLS` forms 6132/6174 exactly own
`0xbf20fc00` leaves `0x0e209400`/`0x2e209400`. Q selects 64- or 128-bit
vectors; B/H/S are allocated at both widths and size=3 is reserved. Every
allocated form reads and updates Vd, reads Vn and Vm, carries SIMD-only
metadata, and requires baseline Advanced SIMD/NEON. The focused suite
partitions all 524,288 words into 393,216 allocated and 131,072 reserved while
locking registers, arrangements, profiles, endian/generic transport,
canonical formatting, raw/form/name forgery rejection, truncation, and
extras-OFF ownership. Existing A32/T32, predicated SVE, indexed-SVE, and
Advanced SIMD by-element same-name forms remain separately classified.
Thirty-four corpus rows and 41 readable seeds preserve the pinned-AARCHMRS and
LLVM 21 boundary.
ARM Advanced SIMD by-element `MLA`/`MLS` forms 6268/6270 exactly own mask
`0xbf00f400` with leaves `0x2f000000`/`0x2f004000`. Only H and S elements are
allocated. H forms restrict Vm to V0--V15 and derive lanes 0--7 from H:L:M;
S forms admit V0--V31 and derive lanes 0--3 from H:L. Q selects the 64- or
128-bit destination and first-source arrangement. Every allocated form reads
and updates Vd, reads Vn and the indexed Vm element, carries SIMD-only
metadata, and requires baseline Advanced SIMD/NEON. The focused suite
partitions all 2,097,152 words into 1,048,576 allocated and 1,048,576
reserved, with 262,144 in each class per operation/Q partition. It locks
register and lane boundaries, profiles, endian/generic transport, canonical
formatting, raw/form/name forgery rejection, truncation, and extras-OFF
ownership while isolating fixed-vector, A32/T32, predicated SVE, indexed-SVE,
and adjacent widening siblings. Twenty-five corpus rows and 14 readable seeds
preserve the pinned-AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD widening by-element `SMLAL`/`SQDMLAL`/`SMLSL`/`SQDMLSL`/
`SMULL`/`SQDMULL`/`UMLAL`/`UMLSL`/`UMULL` forms
6243--6246/6248--6249/6269/6271--6272 exactly own nine leaves under mask
`0xbf00f400`. Only H-to-S and S-to-D forms are allocated. Q selects the base
or `2` spelling and the low or high half of Vn; Vd is always a 128-bit 4S or
2D result. Multiply-add/subtract-long destinations are read/write and
multiply-long destinations are write-only. H forms restrict Vm to V0--V15
and derive lanes 0--7 from H:L:M; S forms admit V0--V31 and derive lanes 0--3
from H:L. Every allocated form reads Vn and the indexed Vm element, carries
SIMD and NEON metadata, and requires baseline Advanced SIMD. The unified
focused suite partitions 9,437,184 controls into 4,718,592 allocated and
4,718,592 reserved. It locks destination access, operation identity, adjacent
multiply/dot-product siblings, profiles, endian/generic transport, canonical
formatting, raw/form/name forgery rejection, truncation, and extras-OFF
ownership. Seventy-five corpus rows and 32 readable seeds preserve the pinned-
AARCHMRS and LLVM 21 boundary.
ARM Advanced SIMD signed compare-with-zero `CMLT`/`CMLE` scalar forms
5777/5794 and vector forms 6013/6045 are exact. Scalar leaves use
`0xfffffc00`/`0x5ee0a800` and `0xfffffc00`/`0x7ee09800`; vector leaves use
`0xbf3ffc00`/`0x0e20a800` and `0xbf3ffc00`/`0x2e209800`. Scalar forms write
Dd, read Dn, and expose `#0`; vector forms allocate B/H/S at both Q widths
and D only at Q=1, reserving 1D. All carry SIMD-only metadata and require
baseline Advanced SIMD/NEON. The focused suite partitions all 18,432 words
into 16,384 allocated and 2,048 reserved while locking profiles, endian and
generic transport, formatting, schema rejection, fixed-bit neighbors,
truncation, and extras-OFF ownership. Scalar/vector `CMGT`/`CMEQ`/`CMGE` and
register-register compare siblings remain separately owned. Twenty-seven
corpus rows and eight readable seeds preserve the pinned-AARCHMRS and LLVM 21
boundary.
ARM FEAT_PAuth `BRAAZ`/`BRABZ`/`BLRAAZ`/`BLRABZ` forms
4510/4511/4513/4514 and `BRAA`/`BRAB`/`BLRAA`/`BLRAB` forms 4525--4528
exactly own parent `0xfedff800`/`0xd61f0800`. The zero-modifier forms contain
32 words each and read Xn or XZR. The explicit-modifier forms contain 1,024
words each and additionally read Xm or SP. Branch forms publish JUMP; link
forms publish CALL and LINK; all publish pointer-authentication metadata and
require PAuth. The focused suite partitions all 8,192 parent words into 4,224
allocated and 3,968 reserved and locks profiles, endian/generic transport,
formatting with independent raw/form/name ownership, truncation, and
extras-OFF behavior. RETAA/RETAB remain outside the tranche. Twenty-three
corpus rows and 11 readable seeds retain the pinned-AARCHMRS and LLVM 21
boundary.
ARM SVE BitPerm `BEXT`/`BDEP`/`BGRP` forms 2829--2831 exactly own parent
`0xff20f000`/`0x4500b000`. Selector values 0/1/2 choose the three leaves and
selector 3 is the sole reserved quarter. Each B/H/S/D result writes `Zd.T`,
reads `Zn.T` and `Zm.T`, carries scalable-vector metadata, and requires
FEAT_SVE_BitPerm. Only `CPU_ANY` currently admits the feature; all named
profiles reject it. The `cdisasm_arm_sve_bitperm_tests` suite exhausts all
524,288 parent words as 393,216 allocated and 131,072 reserved and locks both
byte orders, generic dispatch, formatting and forged-schema rejection,
truncation, profiles, and extras-OFF ownership. Twenty-four corpus rows and
eight readable seeds retain the pinned-AARCHMRS and LLVM 21-verified boundary.
ARM predicated merging shift/saturating-round forms 2657--2668 exactly own
mask/value parent `ff30e000/44008000`. Selector values 2/6/8/10/12/14 choose
`SRSHL`/`SRSHLR`/`SQSHL`/`SQRSHL`/`SQSHLR`/`SQRSHLR`, and
3/7/9/11/13/15 choose their unsigned counterparts. Selectors 0, 1, 4, and 5
are reserved. Each B/H/S/D result exposes four operands:
`Zdn.T, Pg/m, Zdn.T, Zm.T`; the first is read/write and the other three read,
with merge metadata on the governing predicate. The parent contains 393,216
allocated and 131,072 reserved words, all successful results carry exactly
scalable-vector and predicated flags, and admission is SVE2 or SME. Apple
A18/M4 use the SME route; baseline-SVE-only A64FX is rejected. LLVM 21
confirms all twelve leaf encodings and pinned AARCHMRS fixes the full partition.
ARM predicated integer-unary forms 2669--2676 exactly own parent mask/value
`ff34e000/4400a000`. `URECPE` and `URSQRTE` allocate only `.S`; their
B/H/D controls are reserved. `SQABS` and `SQNEG` allocate B/H/S/D. Every
result exposes `Zd.T, Pg/m|z, Zn.T` and scalable-vector/predicated metadata;
the merging destination is read/write and the zeroing destination is write.
Merging requires SVE2 or SME, admitting Apple A18/M4 through SME; zeroing
requires SVE2.2 or SME2.2 and is currently `CPU_ANY`-only. The complete
parent has 163,840 allocated and 98,304 reserved words. LLVM 21 confirms all
eight leaf identities and the pinned AARCHMRS input fixes the full partition.
ARM single-predicate `WHILEGE/HS/GT/HI/LT/LO/LE/LS` forms 2585--2592 write
typed Pd and read W/X sources, with SVE2-or-SME required for GE/HS/GT/HI and
SVE-or-SME for LT/LO/LE/LS. Paired-predicate forms 2574--2581 instead write a
typed consecutive even/odd predicate pair, read X sources, and require SVE2.1
or SME2. Both families set NZCV and carry scalable-vector and predicated
metadata.
Counter-predicate versions 2566--2573 write typed `PN8`--`PN15`, read X/XZR
sources, carry a `VLx2`/`VLx4` operand, set NZCV, and require SVE2.1 or SME2.
Their exact classifier owns 524,288 allocations. `PEXT` forms 2582--2583 read
an untyped indexed `PNn[index]` source and write one typed ordinary predicate
or a consecutive typed pair, including `p15, p0` wrap; `PTRUE` form 2584
writes a typed counter predicate. These three forms require the same
SVE2.1-or-SME2 alternative, carry scalable-vector metadata, and own 3,104
allocations in total.
The 64 saturating element-count and predicate-count/search forms 2362--2373,
2392--2423, and 2597--2616 are exact as well. They cover vector and
scalar `SQINC*`/`UQINC*`/`SQDEC*`/`UQDEC*`, classic and PN-counter `CNTP`,
`FIRSTP`/`LASTP`, and vector/scalar `SQINCP`/`UQINCP`/`SQDECP`/`UQDECP`/
`INCP`/`DECP`. All carry `SCALABLE_VECTOR`; classic two-predicate `CNTP`,
`FIRSTP`, and `LASTP` additionally carry `PREDICATED`. Ordinary forms require
SVE or SME, form 2600 requires SVE2.1 or SME2, and forms 2598--2599 require
SVE2.2 or SME2.2. Eligible allocated words are unsupported when extras are
off; reserved controls remain invalid.
T32 `DCPS1`/`DCPS2`/`DCPS3` forms 1853--1855 are now exact too. The A64
additions also include SVE/SME `ADDVL`/`ADDPL`/`RDVL` forms
2348/2349/2352, Advanced SIMD `REV16`/`REV32`/`REV64` forms
6004/6038/6003, and the nine baseline SVE/SME integer-reduction forms
2243/2244/2246--2249/2255--2257.

The x86 REX2 encodings `D5 xx 01 C8` and `D5 xx 01 C9` use generated forms
1639 and 1821. The EVEX VNNI-INT8 row reuses `VPDPBSSD`, `VPDPBSSDS`,
`VPDPBSUD`, `VPDPBSUDS`, `VPDPBUUD`, and `VPDPBUUDS`: W=0 map-2 opcodes
`50`/`51` use NP/F3/F2 selection and support XMM/YMM/ZMM register or Full-tuple
memory sources, m32 broadcast, merge/zero masks, compressed displacement, and
36 native XED IFORM identities. Ordinary forms use the AVX10 runtime selector;
reviewed B4/U0 address-extension forms additionally require APX and APX-F.

Legacy RAO-INT uses memory-only `0f 38 fc /r`, NP/66/F2/F3 operation
selection, and REX.W-selected width for IFORMs 2/3, 8/9, 257/258, and 263/264.
The corresponding APX-F IFORMs 4/5, 10/11, 259/260, and 265/266 use EVEX map
4 opcode `fc`, admit both defined U states, and extend addressing to EGPRs.
Both rows expose the memory destination as read/write and the GPR source as
read-only, reject register destinations, and use independent runtime-family
bits so enabling generic APX or legacy RAO-INT does not admit APX-F RAO-INT.

ACE BSR initialization is the fixed 64-bit VEX map-2/F2/W1/L0 opcode `49 c0`
(ModRM.mod=3, reg=0, r/m=0).
`BSRMOVF` is EVEX map 6 opcode `95`, NP/W1/512, and reads two ZMM or
ZMM-plus-m512 sources into the implicit-but-visible 128-byte `BSR0` state.
`BSRMOVH` and `BSRMOVL` select F2 and F3: W1 reads a ZMM or m512 into `BSR0`,
while W0 writes the selected BSR half to a ZMM or m512. All eleven forms
require ACE_1, reject masking, zeroing, broadcast, and non-512-bit EVEX
lengths, and retain signed unscaled disp8 addressing for memory.

The eight USER_MSR forms are 64-bit operations with no memory form. Legacy F2/F3
`0f 38 f8 /r` selects `URDMSR`/`UWRMSR`; VEX map 7 supplies the imm32
selector forms. APX-F uses EVEX map 4 for register selectors and map 7 for
imm32 selectors, with EGPR support and fixed U/ND/NF/mask controls. `URDMSR`
writes its destination and reads the selector; `UWRMSR` reads both displayed
operands. The legacy/VEX routes require exact `USER_MSR`, while the EVEX
routes require the independent `APX_F_USER_MSR` runtime bit. The APX map-4
register routes are separated by ModRM mode from the memory-only
`ENQCMD`/`ENQCMDS` encodings at the same opcode and mandatory prefixes. That
memory fallback preserves raw U=0 as the inverted X4 address-index extension,
including the corresponding `MOVDIR64B` map-4 path.

The privileged MSR system forms use four independent generated families.
Fixed `0F 01 C6` is no-operand `WRMSRNS` in all modes; F2/F3 select 64-bit
`RDMSRLIST`/`WRMSRLIST`. Their suppressed architectural registers are not
fabricated as public syntax operands. VEX map-7 and APX EVEX map-7
`F6 /0 id` select `RDMSR r64, imm32` with F2 and
`WRMSRNS imm32, r64` with F3. Both require 64-bit mode and Intel's published
W=0 control; APX B/B4 selects R0--R31. Complete malformed bodies are invalid,
while every incomplete owned ModRM/address/imm32 body remains truncated.
Runtime bit/group pairs are 233/286 for MSRLIST, 234/287 for MSR_IMM,
92/144 for APX_F_MSR_IMM, and 268/322 for WRMSRNS. The immediate forms admit
only unrestricted `CDISASM_CPU_X86`; the fixed forms also admit Diamond Rapids
according to the pinned profile snapshot. This deliberately overrides pinned
XED 2026.08's W1 over-acceptance with Intel ISE #319433-060's W=0 rule.

Legacy F2/F3 map-2 `ENQCMD`/`ENQCMDS` are exact in all modes as public
cdisasm forms 1144/1142; the pinned XED enum ordinals for the same named forms
are 1142/1144. They accept memory ModRM controls only, use effective address
size for `GPRa`, read a 64-byte memory block, ignore `66` and REX.W, and write
arithmetic status flags; only `ENQCMDS` is privileged. The disjoint 64-bit
legacy USER_MSR register controls also accept ignored `66` and `67`.

The complete pinned Key Locker set has eleven IFORMs. F3 map-2 opcodes
`DC`--`DF` select the four narrow AES encrypt/decrypt forms, while opcode
`D8` uses ModRM.reg 0--3 for their wide variants; memory widths are 384 bits
for 128-bit keys and 512 bits for 256-bit keys. Register-mode `DC` is instead
privileged `LOADIWKEY`. F3 map-2 `FA`/`FB` select register-only
`ENCODEKEY128`/`ENCODEKEY256`. The decoder preserves WIG REX.W and REX
register/address extension, consumes complete address payloads before deciding
malformed status, and rejects LOCK, REX2, wrong mandatory prefixes, invalid
ModRM modes, and wide selectors 4--7. All forms publish aggregate status-flag
write metadata. The ordinary forms require runtime bit 224/group 277 and the
wide forms bit 225/group 278; the exact CPU policy admits the unrestricted,
Tiger Lake, Alder Lake, Arrow Lake, AVX10, and APX profiles.

`HRESET` IFORM 1319 uses mandatory-F3 `0F 3A F0 C0 ib` in all modes. It
publishes one read imm8 and CPL0 metadata, treats REX.W as WIG, has no REX2
allocation, and requires runtime bit 218/group 271 plus the exact HRESET CPU
capability. `CLDEMOTE` IFORM 710 owns only NP `0F 1C /0` memory; its byte-sized
operand is address-only. The register and `/1`--`/7` tuples, mandatory-prefix
tuples, and the `/0` tuple on profiles without CLDEMOTE remain P6 multi-byte
`NOP`, while REX2 additionally requires APX. Its selector is bit 211/group
264. AMD `CLZERO` IFORM 719 is fixed `0F 01 FC`, has no visible operands,
accepts ignored repeat/operand/address/segment/ordinary-REX prefixes, rejects
LOCK, and admits only the unrestricted and Zen/Zen 4 profiles. Its REX2 route
also requires APX; the exact selector is bit 213/group 266.

`PCONFIG` is exposed by the two pinned no-visible-operand IFORMs 2084 and
2085. Both use the fixed NP/OSZ=0 `0F 01 C5` encoding; mode 64 selects the
`PCONFIG64` identity and modes 16/32 select `PCONFIG`. Results carry
`CDISASM_GROUP_PRIVILEGED`, aggregate status-flag-write metadata, and exact
group 289. Suppressed EAX/EBX/ECX/EDX or EAX/RBX/RCX/RDX state is not copied
into the syntax-oriented operand ABI. Address-size, segment, and regular REX
prefixes are accepted as ignored, while LOCK, F2/F3, and 66 are malformed.
REX2 is confined to the 64-bit map-1 route and independently requires the APX
runtime selector and APX-F CPU capability. Runtime bit 236 is the complete
CPL0 opt-in. The named CPU boundary is Tiger Lake, Alder Lake, Sapphire
Rapids, AVX10, APX, Granite Rapids, Arrow Lake, and Diamond Rapids; the
unrestricted `CDISASM_CPU_X86` profile remains available in every mode.

`PBNDKB` is the fixed NP/OSZ=0 `0F 01 C7` IFORM 2039. It requires mode 64,
is privileged, and publishes aggregate status-flag writes. Its XED-suppressed
EAX/RBX/RCX state is intentionally absent from the syntax-oriented public
operand array. Address-size, segment, and ordinary REX prefixes are ignored;
LOCK, F2/F3, and 66 are invalid. Exact runtime bit 235/group 288 is admitted
only by unrestricted `CDISASM_CPU_X86`, because cdisasm has no public profile
for the Panther Lake boundary in the pinned XED table. REX2 independently
requires APX-F.

SMAP `CLAC` and `STAC` are exact fixed NP `0F 01 CA` and `0F 01 CB`
allocations, using public forms 707 and 3158 and existing name IDs 1262 and
1445. Both are available in 16-, 32-, and 64-bit decode modes, have no visible
operands, carry `CDISASM_GROUP_PRIVILEGED` and exact
`CDISASM_X86_GROUP_SMAP` (306), and report an aggregate status-flag write for
the architectural AC flag without reporting a status-flag read. Runtime
admission uses logical `CDISASM_X86_DECODE_BIT_SMAP` (253); the broad SYSTEM
selector and APX alone do not admit the family.

Address-size, segment, and ordinary REX prefixes are accepted as ignored.
Operand-size `66` and LOCK are invalid. F2/F3 do not become SMAP prefixes:
on `0F 01 CA` the rightmost F2 or F3 selects the distinct FRED `ERETS` or
`ERETU` allocation in 64-bit mode, while F2/F3 on `0F 01 CB` are reserved.
The FRED path remains generated and keeps its own group, form, CPU, and runtime
policy; it is never relabeled as `CLAC` or `STAC`. In the current profile
table FRED is owned by unrestricted `CDISASM_CPU_X86` and Diamond Rapids,
while the same complete encoding is invalid on a non-FRED profile or outside
64-bit mode. This mandatory-prefix precedence also applies when a valid REX2
map-1 prefix precedes `0F 01 CA`.

REX2 map 1 admits both SMAP words only in 64-bit mode. Its payload bits are
ignored for these fixed operations, but admission independently requires the
APX runtime selector and an APX-F CPU capability in addition to SMAP. The
unrestricted, abstract APX, and Diamond Rapids profiles provide that combined
route; a REX followed by REX2 is malformed. Ordinary SMAP is admitted by the
unrestricted profile; Broadwell, Skylake, Goldmont, Skylake-SP, Ice Lake,
Tiger Lake, Alder Lake, Sapphire Rapids, Granite Rapids, Arrow Lake, Diamond
Rapids; AMD Zen and Zen 4; the abstract AVX10 and APX profiles; and the exact
G3900, N3350, N4020, G5900, and N6000 profiles. Haswell, G1840, Knights Mill,
and every other current named profile reject it. Allocated forms remain
structurally owned as `UNSUPPORTED_INSTRUCTION` with extra opcodes disabled;
reserved prefixes remain invalid and incomplete encodings remain truncated.

`RDPRU` is fixed IFORM 2578 at `0F 01 FD` in all three x86 modes. EDX:EAX and
ECX are suppressed architectural state, so no operands are exposed through the
syntax-oriented result ABI. Operand-size, address-size, segment, F2/F3,
ordinary REX, and map-1 REX2 spellings are redundant; LOCK is malformed.
Runtime bit 247 and exact group 300 are admitted only by unrestricted
`CDISASM_CPU_X86`, because pinned XED first maps RDPRU to Zen 2 and cdisasm has
no named Zen 2 profile. A REX2 spelling independently requires APX-F.

`PREFETCHIT0`/`PREFETCHIT1` are IFORMs 2308/2309 in the shared `0F 18`
collision row. Only memory `/7`/`/6` with mode 64, effective 64-bit addressing,
and a true RIP-relative address promote to those names on an admitting CPU.
Memory `/0`--`/3` remains the four SSE data-prefetch hints; every register
tuple and an ineligible `/6`--`/7` remains its P6 fat-NOP form. Memory `/4`
promotes to `PREFETCHRST2` IFORM 2311 only on Diamond Rapids or unrestricted
`CDISASM_CPU_X86` with exact MOVRS runtime bit 232/group 285; otherwise it
remains memory-NOP form 1860. Memory `/5` remains NOP. PREFETCHRST2 exposes
one byte-sized address-only read operand. Successful instruction-prefetch
results have the same byte-sized address-only read shape plus PC-relative
metadata and exact runtime bit 223/group 276.
Granite Rapids, Diamond Rapids, and unrestricted `CDISASM_CPU_X86` admit
PREFETCHIT0/1; only Diamond Rapids and unrestricted `CDISASM_CPU_X86` admit
PREFETCHRST2. Its `66`/F2/F3 prefixes are ignored. LOCK is malformed, ignored
repeat prefixes do not print as `rep`, and REX2 adds the independent APX-F
requirement.

`PREFETCHWT1` is memory-only IFORM 2315 at `0F 0D /2` in 16-, 32-, and 64-bit
modes; form 2317 is not this allocation. The adjacent register `/2` tuple
retains P6 NOP form 1851. Its exact runtime selector is bit 242/group 295 and
its CPU gate admits Knights Mill or unrestricted `CDISASM_CPU_X86`; another
named profile rejects a complete encoding. The single byte-sized memory
operand is address-only and read, `66`/F2/F3 are ignored, and LOCK is invalid.
REX2 map 1 preserves the NOP/prefetch collision while independently requiring
APX-F.

AMD `MONITORX` IFORM 1640 and `MWAITX` IFORM 1822 are the fixed NP/OSZ=0
`0F 01 FA` and `0F 01 FB` allocations in modes 16, 32, and 64. Their XED
AX/EAX/RAX and EAX/ECX/EDX suppressed state is deliberately omitted from the
public operand array, so both instructions format without operands even though
address size selects the architectural monitor address register. Mandatory-F3
`0F 01 FA` is instead `MCOMMIT` IFORM 1629; it has no operands and carries the
aggregate status-flag-write flag. All three accept ignored address-size,
segment, and regular REX prefixes and reject LOCK. MONITORX/MWAITX additionally
reject F2, F3, and 66; MCOMMIT allows redundant 66 and an earlier F2 provided
F3 is the rightmost repeat prefix. REX2 uses only the 64-bit map-1 route and
adds the independent APX runtime/CPU gate. MCOMMIT uses runtime bit 229/group
282, while MONITORX and MWAITX share bit 231/group 284. These are AMDONLY ISA
sets, but the pinned generated table assigns them to no public named profile;
only unrestricted `CDISASM_CPU_X86` admits them. Structurally owned encodings
remain unsupported, rather than falling through to another Group-7 owner, when
extras are disabled.

The neighboring fixed `0F 01 FE/FF` tuples are now partitioned exactly as
pinned XED specifies. NP `FE` is AMD `INVLPGB` IFORM 1410 and requires an
effective address size of 32 or 64 bits; NP `FF` is `TLBSYNC` IFORM 3309 in
all modes. Their EAX/RAX, ECX, and EDX inputs are XED-suppressed and therefore
do not appear in the syntax-oriented operand array. Mandatory F2 selects
`RMPUPDATE RAX, RCX` IFORM 2633 at `FE` and `PVALIDATE RAX, ECX, EDX` IFORM
2487 at `FF`; mandatory F3 selects `RMPADJUST RAX, RCX, RDX` IFORM 2632 and
`PSMASH RAX` IFORM 2370. The four SNP operands are published as implicit with
exact read/read-write access, and all four forms carry aggregate status-flag
write metadata. RMPUPDATE, RMPADJUST, and PSMASH require 64-bit mode;
PVALIDATE is valid in all modes. LOCK is always malformed, NP rejects 66,
while F2/F3 forms accept redundant 66 and use the rightmost repeat prefix as
their selector. Every result is privileged. Runtime bit/group 67/119 selects
AMD_INVLPGB and 254/307 selects SNP. Pinned XED maps both ISA sets only to its
AMD_FUTURE profile, for which cdisasm has no named equivalent, so only
unrestricted `CDISASM_CPU_X86` admits them. A 64-bit REX2 spelling additionally
requires APX and reports the APX-F group; extras-off builds retain structural
ownership and return unsupported.

The A64 DCPS lowering covers generated forms 4453--4455. It exposes the
optional imm16 in bits 20:5 as one structured read immediate while preserving
generated interrupt and privileged metadata; canonical text omits `#0` and
prints a nonzero immediate in decimal. The base Armv8 A64 named profiles admit
these forms. T32 DCPS is lowered independently: its forms 1853--1855 are
32-bit, no-operand T32 instructions with the same interrupt and privileged
groups, an Armv8 profile gate, endian parity, and extras-OFF structural
ownership.

`<cdisasm/cdisasm.h>` always includes the common header and conditionally
includes the x86 and ARM headers enabled in the configured build. It does not
restore function names removed in version 6. The generic declaration is in the
common header; new code using only an explicit decoder may include its specific
architecture header directly.

## Build-time feature selection

The feature options `USE_ARCH_X86`, `USE_ARCH_ARM`, `USE_DISASM_FORMAT`, and
`USE_EXTRA_OPCODES` all default to `ON`. Each architecture option controls
whether that decoder module is compiled into `cdisasm`, tested, installed, and
exposed by the CMake package. `USE_DISASM_FORMAT` controls whether formatter
sources and symbols for the enabled architectures are compiled into that same
library. `USE_EXTRA_OPCODES` selects extended opcode families beyond the
baseline decoders. For x86 it is also the build gate for every nonzero runtime
opcode-family allow bit; disabling it leaves only the scalar/base family
admissible. This does not change either architecture selection. Configuring
both architecture options
as `OFF` creates a common-only build
for applications that need version, status, CPU-group, and common-ID services
without a decoder. `cdisasm_decode` remains exported in that configuration but
returns zero without touching its result pointer because no dispatch target is
enabled.

In that common-only case, setting `USE_DISASM_FORMAT=ON` records the requested
configuration value but publishes effective `USE_DISASM_FORMAT=0` and adds no
formatter source, symbol, target, or package component because no formatter
implementation is applicable. `cdisasm_format.h` remains discoverable and
installed in every variant; including it when formatting is ineffective emits
a focused compile-time diagnostic.
The same requested/effective rule applies to extra opcodes: a common-only build
may record requested `USE_EXTRA_OPCODES=ON`, but its public effective macro and
`cdisasm_USE_EXTRA_OPCODES` package variable are zero because no decoder can
contain those families.

The controlled modern tranche is explicit and append-only. In addition to the
compact table, the current post-12.0 slice contains all ten ACE TOP2/TOP4 forms,
both legacy/APX-F RAO-INT rows, the complete ACE BSR state family, and all
legacy/VEX/APX-F USER_MSR routes plus the complete Key Locker family and exact
HRESET, CLDEMOTE, CLZERO, PCONFIG/PCONFIG64, PBNDKB,
PREFETCHIT0/PREFETCHIT1, MONITORX/MWAITX/MCOMMIT,
AMD_INVLPGB, SNP, RDPRU, PREFETCHRST2, and PREFETCHWT1 slices on x86.
Exact PTWRITE register/memory forms 2438--2439 and memory-only MOVNTI forms
1692--1693 are included as well, together with the complete legacy/VEX/EVEX
`MOVNTDQ`/`MOVNTPD`/`MOVNTPS` store cluster and its `MOVNTQ`/`MOVNTSD`/
`MOVNTSS` legacy collisions, plus exact zero-operand SMAP `CLAC`/`STAC`
forms 707/3158, exact memory-source `MOVNTDQA`/`VMOVNTDQA` forms
1690/5864--5868, exact `LDDQU`/`VLDDQU` forms 1574/5583--5584, the scalar and
packed move tranches through `VMOVUPD`/`VMOVUPS` forms 5946--5979, exact
EVEX map-5 `VMOVW` forms 5980--5986, and VEX/EVEX `VMPSADBW` forms
5987--5996, followed by exact VMX/SVM virtualization forms
5997--6005/6048--6053 and
AVX10.2 `VMULBF16` forms 6006--6011, plus AVX512-FP16 `VMULPH` forms
6022--6027 and `VMULSH` forms 6042--6043, plus classic
`VMULPD`/`VMULPS`/`VMULSD`/`VMULSS` forms 6012--6021, 6028--6041, and
6044--6047, classic `VORPD`/`VORPS` forms 6054--6073, exact
`VP2INTERSECTD/Q` forms 6074--6085, exact `VPABSB/D/Q/W` forms 6088--6123,
exact `VPACKSSDW/SSWB/USDW/USWB` forms 6124--6163, and exact VEX
`VPBLENDD`/`VPBLENDVB`/`VPBLENDW` forms 6306--6309/6334--6341,
`VBLENDPD`/`VBLENDPS` forms 3527--3534,
`VBLENDVPD`/`VBLENDVPS` forms 3535--3542, exact
`VBROADCASTF128`/`VBROADCASTI128` forms 3543/3554, VEX
`VBROADCASTSD`/`VBROADCASTSS` forms 3569--3570/3573--3574/3579--3580, and
`VEXTRACTF128`/`VEXTRACTI128` forms 4539--4540/4553--4554 plus
`VINSERTF128`/`VINSERTI128` forms 5551--5552/5565--5566, and
`VPBROADCASTB` forms 6342/6343/6347/6348, `VPBROADCASTD` forms
6355/6356/6360/6361, `VPBROADCASTQ` forms 6374/6375/6379/6380, and
`VPBROADCASTW` forms 6387/6388/6392/6393, plus VEX `VPCMPEQQ` forms
6454--6457 and VEX `VPERMD`/`VPERMPS` forms 6780--6781/6886--6887, and
exact AMD XOP
`VPCMOV` forms 6410--6415 and XMM `VPPERM` forms 7686--7688, plus
classic-VEX `VPMOVMSKB` forms 7334--7335, `VPSIGNB/W/D` forms
7921--7932, and `VPSHUFD/HW/LW` forms 7891--7916, and
classic-VEX `VCOMISD`/`VCOMISS` forms 3629--3630/3633--3634,
classic-VEX `VDPPD`/`VDPPS` forms 4507--4508/4515--4518, and
classic-VEX `VCMPPD`/`VCMPPS`/`VCMPSD`/`VCMPSS` forms
3595--3598/3611--3614/3617--3618/3623--3624, and
classic-VEX `VUNPCKHPD`/`VUNPCKHPS`/`VUNPCKLPD`/`VUNPCKLPS` forms
8825--8862, classic-VEX `VPHMINPOSUW` forms 7040--7041, and classic-VEX
`VPINSRB/D/Q/W` forms 7060--7061/7064--7065/7068--7069/7072--7073 and
	`VPEXTRB/D/Q/W` forms 6966/6968/6970/6972/6974/6976/6978--6979/6983,
	plus all 24 classic-VEX `VPMOVSXBW/BD/BQ/WD/WQ/DQ` and all 24 classic-VEX
	`VPMOVZXBW/BD/BQ/WD/WQ/DQ` forms listed above, the complete 144-form
	VEX/EVEX packed-integer MIN/MAX block 7160--7303, and all 36 legacy/VEX/EVEX
	GFNI forms 1308--1313/5505--5534.
On ARM it contains indexed
`DUP`/preferred `MOV`, FP8 narrowing, the complete SME2 two-vector conversion/
unpack/widening block 4312--4340, the complete SME2 four-vector block
4341--4362, the SME multi-vector `FMUL`/`BFMUL` block 4363--4370, exact
baseline-SME predicated ZA-slice `MOVA` forms 3862--3866/3877--3881, exact
SME2 pair/quad ZA-transfer forms 3867--3876/3882--3891, exact
SME2.1 `MOVAZ` zeroing ZA extracts 3892--3906, exact
baseline-SME ZA `LDR`/`STR` forms 4381--4382, exact SME2 ZT0 `LDR`/`STR`
forms 4383--4384, baseline A64 `UDF` form 4387, the separate
FEAT_WFxT forms 4457--4458, all six FEAT_FlagM/FlagM2 forms
4499--4501/5696--5698, all five FEAT_SVE FFR forms
2562--2564/2617--2618, exact `PSEL` form 2565, the complete SVE/SME
wide-immediate arithmetic and preferred `MOV`/`FMOV` broadcast block
2619--2632, exact unpredicated `SDOT`/`UDOT` forms 2633--2636, exact
`SQDMLALBT`/`SQDMLSLBT`/`CDOT`/`CMLA`/`SQRDCMLAH` forms 2637--2641, and
exact widening/rounding-high multiply-add forms 2642--2655, exact mixed-sign
`USDOT` form 2656, indexed `MLA`/`MLS` forms 2722--2727, indexed
`SQRDMLAH`/`SQRDMLSH` forms 2728--2733, indexed `USDOT`/`SUDOT` forms
2734--2735, and SVE
`AESMC`/`AESIMC` forms 2903--2904 and crypto-binary `AESE`/`AESD`/`SM4E`
forms 2905--2907, plus predicate-unpack `PUNPKLO`/`PUNPKHI` forms 2468--2469
and vector-unpack `SUNPKLO`/`SUNPKHI`/`UUNPKLO`/`UUNPKHI` forms 2456--2459,
plus SVE2/SME `SRI`/`SLI` forms 2846--2847, Advanced SIMD
`BSL`/`BIT`/`BIF` forms 6188/6196/6198,
`ADDHN`/`SUBHN`/`RADDHN`/`RSUBHN` forms 6093/6095/6108/6110, widening
add/sub forms 6089--6092/6104--6107, and absolute-difference-long forms
6094/6096/6109/6111, and SVE BitPerm
`BEXT`/`BDEP`/`BGRP` forms 2829--2831,
predicated merging
shift/saturating-round forms 2657--2668,
predicated `URECPE`/`URSQRTE`/`SQABS`/`SQNEG` forms 2669--2676,
predicated accumulating-long and halving forms 2677--2686, and predicated
pairwise `SUBP`/`ADDP`/`SMAXP`/`SMINP`/`UMAXP`/`UMINP` forms 2687--2692,
exact predicated saturating arithmetic forms 2693--2700, and destructive
unpredicated `SCLAMP`/`UCLAMP` forms 2701--2702, plus `.D` pointer
multiply-add transform `MLAPT`/`MADPT` forms 2707--2708 and B/H/S/D
quad-permute `ZIPQ1`/`UZPQ1`/`ZIPQ2`/`UZPQ2` forms
2711--2712/2714--2715,
all 18
non-saturating SVE
element-count forms
2374--2391, all 64 saturating element-count and predicate-count/search forms
2362--2373/2392--2423/2597--2616, including `FIRSTP`/`LASTP`, all counter-
predicate `WHILE` forms 2566--2573, paired and single `WHILE` forms
2574--2581/2585--2592, and `PEXT`/counter-predicate `PTRUE` forms 2582--2584,
and the separate
SVE2.1-or-SME2 multi-extract
narrowing row 2881--2883, `ADDVL`/`ADDPL`/`RDVL`, Advanced SIMD
scalar/vector `ADDP` forms 5808/6137, `ADDV` form 6077,
`REV16`/`REV32`/`REV64`,
`CLS`/`CNT`/`CLZ`, and regular
`SMAX`/`SMIN`/`UMAX`/`UMIN` forms 6126--6127/6168--6169 plus fixed-vector
`SABA`/`UABA` forms 6129/6171, fixed-vector `SABD`/`UABD` forms 6128/6170,
fixed-vector `MLA`/`MLS` forms 6132/6174, by-element forms 6268/6270, and
widening by-element `SMLAL`/`SQDMLAL`/`SMLSL`/`SQDMLSL`/`SMULL`/`SQDMULL`/
`UMLAL`/`UMLSL`/`UMULL` forms 6243--6246/6248--6249/6269/6271--6272,
and register
	`CMGT`/`CMGE`/`CMHI`/`CMHS`/`CMEQ` forms
	6120--6121/6162--6163/6173, and nine baseline SVE/SME
	integer reductions, plus all 30 A32/T32/A64 SHA1/SHA256 leaves and the fixed
	A64 SHA3/SHA512/SM3/SM4 crypto block 6287--6303:

| Decoder | `USE_EXTRA_OPCODES=1` coverage | Validation policy |
| --- | --- | --- |
| x86 | The 60-name VEX map-1 slice; representative map-2/map-3 and BMI1/2/F16C forms; complete VEX/EVEX FMA3 and FMA4 matrices; the release's cataloged XOP tranche; the complete classic 51-name VEX K-mask family; complete packed-integer EVEX compare-to-mask, MIN/MAX, multiply/multiply-add, modular/wrapping ADD/SUB, D/Q logical, byte/word average, word/dword/qword per-element variable-shift, dword/qword variable and immediate packed-rotate, opcode-`72` dword/qword immediate-shift, opcode-`71`/`73` word/qword/byte-lane immediate-shift, and AVX512VBMI2 map-2/map-3 double-shift matrices; the complete eight-name VEX/EVEX saturating packed ADD/SUB family; complete COMPRESS/EXPAND, BITALG/VPOPCNT, six-name AVX-512CD, four-operation EVEX AVX-512 VNNI, complete six-name EVEX AVX10.2 VNNI-INT8, the bounded classic VEX AVX-VNNI, AVX-VNNI-INT8, and AVX-VNNI-INT16 dot-product rows, the exact Knights Mill `VP4DPWSSD`/`VP4DPWSSDS` AVX512_4VNNIW pair, the complete four-name `V4FMADDPS`/`V4FMADDSS`/`V4FNMADDPS`/`V4FNMADDSS` AVX512_4FMAPS family, the exact AVX512F/AVX10.1 `VGETEXPPS`/`VGETEXPPD`/`VGETEXPSS`/`VGETEXPSD` tranche, and exact MAP6 `VGETEXPPH`/`VGETEXPSH`/`VGETEXPBF16` forms; classic AVX512_VBMI byte-permute/multishift and AVX512BW/AVX10 word-permute slices; exact scalar `VMOVSD`, `VMOVSH`, and `VMOVSS` plus `VMOVSHDUP`/`VMOVSLDUP`, exact `VMOVW`, VEX/EVEX `VMPSADBW`, and VMX/SVM/VTX forms 5997--6005/6048--6053; exact APX P0.B4 and selected U0/X4 ownership through the stated routes, including REX2 `MONITOR`/`MWAIT`; exact HRESET, CLDEMOTE, CLZERO, PCONFIG/PCONFIG64, MONITORX/MWAITX/MCOMMIT, AMD_INVLPGB, SNP, Key Locker, ACE BSR, USER_MSR, RDPRU, PREFETCHRST2, PREFETCHWT1, PTWRITE, MOVNTI, the legacy/VEX/EVEX non-temporal SIMD store cluster, and RAO-INT slices; and bounded AES/SHA/PCLMUL, VAES/VPCLMUL, other EVEX AVX-512/AVX10, AMX, APX, CET, WAITPKG, hardware-entropy, RTM, and system forms | Matching runtime family bit plus independent chronological/vendor CPU capability; classic VEX AVX-VNNI, AVX-VNNI-INT8, and AVX-VNNI-INT16 use narrow bits 61, 62, and 63 with distinct CPU gates; VMPSADBW uses AVX/AVX2 for VEX and exact AVX512-MEDIAX width routes for EVEX; AVX512_4VNNIW and AVX512_4FMAPS retain the AVX-512 runtime umbrella assigned when the version-11 scalar mask was saturated, plus independent Knights Mill CPU capabilities; PS/PD/SS/SD VGETEXP uses mutually exclusive AVX512F/AVX512VL and AVX10.1 CPU/runtime routes; PH/SH uses AVX512-FP16 (plus AVX512VL for packed 128/256-bit PH) or AVX10.1, while BF16 and EVEX VNNI-INT8 require AVX10.2 and the AVX10 runtime selector; RDPRU, MOVRS, PREFETCHWT1, and PTWRITE use independent exact runtime selectors and conservative profile gates; MOVNTI requires SSE2, and its REX2 route additionally requires APX/APX-F; the non-temporal SIMD rows use their SSE/MMX/SSE2/SSE4a, AVX, or AVX-512 family gates, and EVEX B4/X4 also requires APX/APX-F; reviewed B4/U0 address-extension routes, REX2 virtualization, REX2 `MONITOR`/`MWAIT`, and REX2 PTWRITE also require the independent APX/APX-F gate; exact no-AVX, WAITPKG/APX cross-gates, and retired-family profiles remain non-monotonic |
| ARM A32/T32 | Representative wider core, VFP, and NEON forms, plus exact no-operand T32 `DCPS1`/`DCPS2`/`DCPS3` forms 1853--1855 | Architecture/VFP/NEON and architectural-version capabilities per named profile; `CPU_ANY` enables implemented forms |
| ARM A64 | Common scalar-register arithmetic/select/divide/shift/multiply and logical-immediate forms, FEAT_LSE/LOR/LRCPC, complete bounded SVE predicate-logical, unpredicated and destructive-predicated integer-arithmetic, exact SVE/SME wide-immediate arithmetic and preferred `MOV`/`FMOV` broadcasts through form 2632, integer vector-compare and integer compare-with-immediate, exact integer and floating-point predicated SVE unary classifiers, exact predicated SVE vector-shift, SVE/SVE2 immediate-shift, and SVE2/SME merging variable shift/saturating-round classifiers, floating compare/binary including the seven-name FEAT_SVE_B16B16 destructive row, fast-reduction, `FADDA`, exact merging H/S/D-to-H plus S-to-S/D and D-to-S/D `SCVTF`/`UCVTF`, the complete baseline merging H/S/D `FCVT`/`FCVTZS`/`FCVTZU` class plus exact zeroing S-to-H `FCVT`, exact merging SVE/SME `BFCVT`/`BFCVTNT Zd.H, Pg/m, Zn.S`, exact SVE2.2/SME2.2 zeroing `BFCVT`/`BFCVTNT Zd.H, Pg/z, Zn.S`, and exact unpredicated SME2/SVE2 pair `BFCVT`/`BFCVTN` S-to-H and H-to-FP8 forms; structured A64 `DCPS1`/`DCPS2`/`DCPS3`; unpredicated SVE/SME and fixed-width Advanced SIMD `FRECPE`/`FRSQRTE` slices; exact Advanced SIMD `REV16`/`REV32`/`REV64` and `CLS`/`CNT`/`CLZ`; scalable SVE ZIP/UZP/TRN, the disjoint FEAT_F64MM Q-element ZIP/UZP/TRN class, fixed-width Advanced SIMD ZIP/UZP/TRN, selected unpredicated table-lookup/MOV-from-GPR classes, complete disjoint SVE2.1/SME2.1 `TBLQ`, exact non-saturating SVE vector/scalar element-count forms, exact SVE predicate-break forms 2546--2555, exact SME `FMUL`/`BFMUL`, baseline-SME predicated ZA `MOVA`, SME2 aligned-pair/quad ZA `MOVA`, SME2.1 zeroing ZA-extract `MOVAZ`, baseline-SME ZA load/store, SME2 ZT0 load/store, FEAT_WFxT, all six FEAT_FlagM/FlagM2 forms, and the five FEAT_SVE FFR forms, plus representative wider FP/NEON, other SVE/SVE2, SME/SME2, LSE128/RCpc3, BTI, PAuth, MTE, MOPS, LS64, and CSSC forms | Explicit capability tables; the wide-immediate block admits SVE or SME, including A64FX through SVE and A18/M4 through SME; the bounded merging conversion classes admit SVE or SME and record source granularity on the predicate; zeroing S-to-H `FCVT` requires SVE2p2 or SME2p2, and the BFloat16 binary row requires FEAT_SVE_B16B16; both are currently `CPU_ANY`-only; merging BFCVT and BFCVTNT additionally require BF16 and are admitted by `CPU_ANY`, A18, and M4, while zeroing BFCVT/BFCVTNT require SVE2p2 or SME2p2 and are currently `CPU_ANY`-only; pair S-to-H `BFCVT`/`BFCVTN` requires SME2 and is admitted by A18/M4, pair H-to-FP8 `BFCVT` requires SME2+FP8, and pair H-to-FP8 `BFCVTN` requires (SVE2 or SME2)+FP8; FP8 remains independently `CPU_ANY`-only and there is no pair `BFCVTNT`; the F64MM Q-element class is conservatively admitted only by `CPU_ANY`; ordinary SVE arithmetic/compare/reduction, FP estimates, unary `/m`, and non-saturating element-count forms admit SVE or SME; fixed-width FP estimates require Advanced SIMD and half-precision forms also require FP16; floating unary `/z` forms require SVE2p2 or SME2p2; `FADDA` strictly requires SVE; saturating/rounding immediate shifts and merging variable shift/saturating-round forms require SVE2 or SME; fixed-width permutation and bit count require NEON; baseline ZA transfer requires SME, while multi-register MOVA and ZT0 transfer require SME2; those are admitted by A18/M4. MOVAZ requires SME2.1 and is `CPU_ANY`-only because every named profile, including A18/M4, lacks SME2.1; WFxT, FlagM, and FlagM2 are independently `CPU_ANY`-only because no named profile advertises them; SVE FFR requires SVE and admits only `CPU_ANY` and A64FX; two-table `TBL` and `TBX` admit SVE2 or SME; `TBXQ` and `TBLQ` require SVE2.1 or SME2.1; `ADDPT`/`SUBPT` strictly require SVE plus CPA; named profiles do not inherit capabilities by ordinal |

The x86 row additionally includes exact `VPBLENDVB` forms 6334--6337 with
AVX/AVX2 metadata and selector-byte semantics, AVX2 VEX `VPBROADCASTB` forms
6342/6343/6347/6348, `VPBROADCASTD` forms 6355/6356/6360/6361,
`VPBROADCASTQ` forms 6374/6375/6379/6380, and `VPBROADCASTW` forms
6387/6388/6392/6393, plus VEX `VPCMPEQQ` forms 6454--6457,
`VBLENDPD`/`VBLENDPS` forms 3527--3534 and
`VBLENDVPD`/`VBLENDVPS` forms 3535--3542, plus
`VBROADCASTF128`/`VBROADCASTI128` forms 3543/3554, VEX
`VBROADCASTSD`/`VBROADCASTSS` forms 3569--3570/3573--3574/3579--3580, and
`VEXTRACTF128`/`VEXTRACTI128` forms 4539--4540/4553--4554 plus
`VINSERTF128`/`VINSERTI128` forms 5551--5552/5565--5566, and
`VPCMOV` forms 6410--6415 and `VPPERM` forms
7686--7688 with AVX+XOP groups, plus classic-VEX `VPTEST` forms 8319--8322
and classic-VEX `VPMOVMSKB` forms 7334--7335 and `VPSIGNB/W/D` forms
7921--7932
and classic-VEX `VUNPCKHPD`/`VUNPCKHPS`/
`VUNPCKLPD`/`VUNPCKLPS` forms 8825--8862, all 32 classic-VEX integer
`VPUNPCK*` forms 8323--8398, and all 24 classic-VEX horizontal integer
`VPHADD*`/`VPHSUB*` forms 7012--7059, plus classic-VEX `VPHMINPOSUW` forms
7040--7041. The x86 row also includes exact classic-VEX `VDPPD`/`VDPPS`
forms 4507--4508/4515--4518 and `VCMPPD`/`VCMPPS`/
`VCMPSD`/`VCMPSS` forms 3595--3598/3611--3614/3617--3618/3623--3624
under AVX with MXCSR metadata. The ARM A64 row additionally
includes exact
`.D`-only `MLAPT`/`MADPT` forms 2707--2708 under the conjunctive SVE+CPA
gate, B/H/S/D `ZIPQ1`/`UZPQ1`/`ZIPQ2`/`UZPQ2` forms
2711--2712/2714--2715 under the SVE2.1-or-SME2.1 gate, indexed
`MLA`/`MLS` forms 2722--2727 under the SVE2-or-SME gate, indexed
`USDOT`/`SUDOT` forms 2734--2735 under the SVE-or-SME-plus-I8MM gate, and
SVE `AESMC`/`AESIMC` forms 2903--2904 and `AESE`/`AESD` forms 2905--2906
under FEAT_SVE_AES, plus `SM4E` form 2907 under FEAT_SVE_SM4 and
`PUNPKLO`/`PUNPKHI` forms 2468--2469 plus
`SUNPKLO`/`SUNPKHI`/`UUNPKLO`/`UUNPKHI` forms 2456--2459 under SVE or SME,
and `SRI`/`SLI` forms 2846--2847 under SVE2 or SME, plus Advanced SIMD
`BSL`/`BIT`/`BIF` forms 6188/6196/6198 and
`ADDHN`/`SUBHN`/`RADDHN`/`RSUBHN` forms 6093/6095/6108/6110 under NEON,
Advanced SIMD widening add/sub forms 6089--6092/6104--6107 and absolute-
difference-long forms 6094/6096/6109/6111 under NEON,
and SVE BitPerm
`BEXT`/`BDEP`/`BGRP` forms 2829--2831 under FEAT_SVE_BitPerm, plus fixed
Advanced SIMD `SMAX`/`SMIN`/`UMAX`/`UMIN` forms 6126--6127/6168--6169
and register `CMGT`/`CMGE`/`CMHI`/`CMHS`/`CMEQ` forms
6120--6121/6162--6163/6173 plus scalar/vector `CMTST` forms 5831/6131,
scalar/vector `SSHL`/`USHL` forms 5826/5841/6122/6164, fixed-vector
`MLA`/`MLS` forms 6132/6174, and
scalar/vector compare-with-zero `CMLT`/`CMLE` forms
5777/5794/6013/6045 plus scalar/vector `ADDP` forms 5808/6137 and reduction
`ADDV` form 6077 under baseline NEON.
These are scoped additions;
neither decoder is ISA-complete.

The x86 row also includes exact `LDDQU`/`VLDDQU`: legacy form 1574 uses SSE3
and adds APX only for REX2 map 1, while VEX forms 5583--5584 use AVX at both
widths. It also includes `VMOVW` forms 5980--5986, whose `66` and F3 selectors
use independent `AVX512_FP16_128N` and `AVX512_MOVZXC_128` runtime/profile
routes, followed by exact `VMPSADBW` forms 5987--5996 and VMX/SVM
virtualization forms 5997--6005/6048--6053, `VMULBF16` forms 6006--6011,
`VMULPH` forms
6022--6027, `VMULSH` forms 6042--6043, and classic
`VMULPD`/`VMULPS`/`VMULSD`/`VMULSS` forms 6012--6021, 6028--6041, and
6044--6047, followed by `VORPD`/`VORPS` forms 6054--6073,
`VP2INTERSECTD/Q` forms 6074--6085, `VPABSB/D/Q/W` forms 6088--6123, and
`VPACKSSDW/SSWB/USDW/USWB` forms 6124--6163. VOR uses AVX for
VEX and exact AVX512DQ width routes through AVX-512DQ/VL or AVX10.1 for EVEX;
register `EVEX.b` remains reserved. In the ARM
row, predicate count/search
includes `FIRSTP`/`LASTP` forms
2598--2599; unlike the ordinary SVE-or-SME count forms, they require SVE2.2 or
SME2.2 and are currently admitted only by `CPU_ANY`. Exact `PSEL` form 2565
instead admits either SVE2.1 or baseline SME.
Wide-immediate forms 2619--2632 admit SVE or SME. The adjacent exact
`SDOT`/`UDOT` forms 2633--2636 use the same alternative for B-to-S and H-to-D
widening; B-to-H requires SVE2p3 or SME2p3 and is `CPU_ANY`-only.
Forms 2637--2641 then require SVE2 or SME for `SQDMLALBT`, `SQDMLSLBT`,
`CDOT`, `CMLA`, and `SQRDCMLAH`. Forms 2642--2655 use the same alternative
for the twelve widening bottom/top add/sub operations and the same-width
`SQRDMLAH`/`SQRDMLSH` pair. Form 2656 instead requires the conjunctive
`(SVE or SME) and I8MM` route for `USDOT`; it is currently `CPU_ANY`-only.
Forms 2657--2668 instead use the exact SVE2-or-SME alternative for all twelve
merging variable shift/saturating-round operations, admitting Apple A18/M4
through SME while rejecting baseline-SVE-only A64FX. Forms 2669--2676 add
`.S`-only `URECPE`/`URSQRTE` and B/H/S/D `SQABS`/`SQNEG` in both merging
SVE2-or-SME and zeroing SVE2.2-or-SME2.2 variants.

For the x86 transactional slice, `XBEGIN`, `XABORT`, and `XEND` require RTM,
while `XTEST` is admitted when either HLE or RTM is available. Redundant legacy
and REX prefixes follow Intel's instruction-specific rules and do not become
false REP actions. The named RTM presets are Haswell through Skylake-SP,
Sapphire Rapids, Granite Rapids, and Diamond Rapids.
`CDISASM_CPU_ICE_LAKE` is specifically the 2019 client
family; Ice Lake, Tiger Lake, Alder Lake, and Arrow Lake expose neither HLE nor RTM, while
the abstract AVX10 and APX presets conservatively infer neither feature.
Intel's [Ice Lake product specification](https://www.intel.com/content/www/us/en/products/sku/196597/intel-core-i71065g7-processor-8m-cache-up-to-3-90-ghz/specifications.html),
[Tiger Lake datasheet](https://cdrdv2-public.intel.com/631121/631121_TGL%20Datasheet%20Volume1of2%20rev012_PUBLIC.pdf), and
[Alder Lake deprecated-technologies list](https://edc.intel.com/content/www/us/en/design/ipla/software-development-platforms/client/platforms/alder-lake-desktop/12th-generation-intel-core-processors-datasheet-volume-1-of-2/011/deprecated-technologies/)
document the negative boundaries. Intel's
[Xeon Platinum 8490H specification](https://www.intel.com/content/www/us/en/products/sku/231747/intel-xeon-platinum-8490h-processor-112-5m-cache-1-90-ghz/specifications.html)
and [Sapphire Rapids overview](https://www.intel.com/content/www/us/en/developer/articles/technical/fourth-generation-xeon-scalable-family-overview.html)
document TSX and its new load-tracking commands for that server generation.
For group-9 `0F C7`, `LOCK` on register entropy/collision forms is invalid,
as are `66`/`F2`/`F3` prefixes on memory `/7`; unprefixed memory `/7` remains
`VMPTRST`. The 64-bit `F3 0F C7 /6` `SENDUIPI` collision is recognized as a
valid but currently unsupported family, never as `RDRAND`.

The extra mnemonic IDs exist in both builds, preserving ABI and serialized ID
stability. With the option off, a structurally valid controlled encoding fails
with `CDISASM_STATUS_UNSUPPORTED_INSTRUCTION`; malformed and truncated forms
keep their precise failure classes. Formatter name strings for the tranche are
also compiled out, so a synthetic optional name ID is not formattable in an
`OFF` build.
The append-only flag macros and result types are defined in both variants. An
x86 OFF build accepts only `NULL` or an all-zero flags object; any set x86 bit reports a
zeroed `CDISASM_STATUS_INVALID_ARGUMENT` result. With flags zero, complete
non-base x86 forms—including older x87, 3DNow!, legacy SSE, VMX/SVM, and
undocumented forms—are structurally classified but cannot decode successfully.
Baseline ARM NEON and Apple-private instructions retain their existing ARM
decode-flag and CPU-capability behavior; the x86 allow bitmap does not apply to
ARM.

```sh
# x86 only
cmake -S . -B build-x86 -DUSE_ARCH_X86=ON -DUSE_ARCH_ARM=OFF

# ARM only
cmake -S . -B build-arm -DUSE_ARCH_X86=OFF -DUSE_ARCH_ARM=ON

# x86 decoder without formatting
cmake -S . -B build-x86-decode \
  -DUSE_ARCH_X86=ON -DUSE_ARCH_ARM=OFF -DUSE_DISASM_FORMAT=OFF

# full static library
cmake -S . -B build-static -DBUILD_SHARED_LIBS=OFF
```

The architecture switches select decoders for the input being analyzed, not
the build host's instruction set. Neither architecture option is inferred from
`CMAKE_SYSTEM_PROCESSOR`; cross-host and native builds use the same explicit
selection. `cdisasm_current_cpu()` is a runtime query in the finished library,
not a configure-time architecture probe. It returns `CDISASM_CPU_UNKNOWN` when
the caller-visible architecture is disabled or lacks a reliable enabled named
profile.

`CDISASM_BUILD_PACKAGE_TESTS` defaults to `ON` when cdisasm is the top-level
project and to `OFF` when it is a subproject. With `BUILD_TESTING=ON`, it adds
isolated end-to-end tests for all 32 combinations of linkage, architecture
selection, requested formatting, and requested extra opcodes. Every cell
validates build-tree package
consumption, a moved installation, exact files and symbols, all positive and
negative components, C and C++17 runtime consumers, and compatibility-target
usage. Static ELF/Mach-O cells additionally prove that embedding the archive in
a shared wrapper does not export cdisasm symbols. Set the option to `OFF` to
retain the current build's native executables and two non-package CMake
integration tests. Runtime package tests are omitted while cross-compiling.

Standard CMake `BUILD_SHARED_LIBS` is independent of the feature switches and
defaults to `ON`:

| `BUILD_SHARED_LIBS` | Target type | Windows output | Typical non-Windows output |
| --- | --- | --- | --- |
| `ON` (default) | shared | `cdisasm-12.dll` plus `cdisasm.lib` import library | versioned `libcdisasm.so` or `libcdisasm.dylib` |
| `OFF` | static | `cdisasm.lib` archive; no DLL or import library | `libcdisasm.a` |

When used through `add_subdirectory`, cdisasm does not create or modify the
parent's global `BUILD_SHARED_LIBS` option. Its project-scoped
`CDISASM_BUILD_SHARED_LIBS` defaults from a value already supplied by the
parent, and cdisasm creates an explicitly shared or static target. A regression
fixture checks that later untyped sibling libraries keep the parent's intended
linkage.

The feature matrix is identical for either library type. Focused suites are
appended as coverage grows, so `ctest -N` for a configured tree is the
authoritative executable count. The stable matrix dimensions are:

| Dimension | Values exercised | Contract checked |
| --- | --- | --- |
| Architecture selection | dual, x86-only, ARM-only, common-only | Exact headers, exports, components, compatibility proxies, and generic dispatch |
| Library form | shared and static | Runtime/import artifacts, static-definition propagation, and static embedding visibility |
| Formatter | requested ON and OFF | Effective availability, declarations, symbols, formatting, and forged-result rejection |
| Extra opcodes | requested ON and OFF | Optional semantics versus zeroed unsupported results, while reserved and truncated forms remain distinct |
| Consumption | build tree and relocated install | C and C++17 consumers, component acceptance/rejection, linkage, and install fingerprinting |

`cdisasm_x86_flag_tests` runs in both x86 variants. It fixes every public bit
value and exercises base-only zero, exact family admission, combined
undocumented-x87 permissions, encoding-only undocumented aliases, the assigned
bit-63 AVX-VNNI-INT16 selector, the all-bits mask, CPU independence,
compatibility-umbrella behavior, narrow-family admission, and OFF-build
rejection of every nonzero mask.
The following focused-suite inventory is representative rather than exhaustive;
the configured `ctest -N` list remains the source of truth.
`cdisasm_x86_waitpkg_tests`, `cdisasm_x86_evex_fma_tests`,
`cdisasm_x86_nextgen_tests`, `cdisasm_x86_kmask_tests`,
`cdisasm_x86_evex_compare_tests`, `cdisasm_x86_evex_integer_minmax_tests`,
`cdisasm_x86_evex_integer_multiply_tests`,
`cdisasm_x86_evex_integer_add_sub_tests`,
`cdisasm_x86_evex_integer_logical_tests`, `cdisasm_x86_evex_average_tests`,
`cdisasm_x86_saturating_add_sub_tests`, and
`cdisasm_x86_variable_shift_tests`,
`cdisasm_x86_variable_word_shift_tests`,
`cdisasm_x86_variable_rotate_tests`,
`cdisasm_x86_immediate_rotate_tests`, and
`cdisasm_x86_immediate_shift_tests`, and
`cdisasm_x86_lddqu_tests`, `cdisasm_x86_vmovmsk_tests`,
`cdisasm_x86_vmovq_tests`, `cdisasm_x86_vmovrs_tests`, and
`cdisasm_x86_vmovsd_tests`, `cdisasm_x86_vmov_fp16_dup_tests`,
`cdisasm_x86_vmovss_tests`, and
`cdisasm_x86_evex_avx512vbmi_tests` and
`cdisasm_x86_avx_vnni_tests` and
`cdisasm_x86_avx_vnni_int8_tests` and
`cdisasm_x86_avx_vnni_int16_tests` also run in both variants, as do the
ARM `cdisasm_arm_neon_vector_permute_tests`,
`cdisasm_arm_sve_predicate_logical_tests`,
`cdisasm_arm_sve_integer_arithmetic_tests`,
`cdisasm_arm_sve_predicated_integer_tests`,
`cdisasm_arm_sve_vector_permute_tests`,
`cdisasm_arm_sve_table_lookup_tests`, `cdisasm_arm_sve_tblq_tests`,
`cdisasm_arm_sve_predicated_unary_tests`, and
`cdisasm_arm_sve_predicated_vector_shift_tests`,
`cdisasm_arm_sve_predicated_immediate_shift_tests`,
`cdisasm_arm_sve_predicated_shift_sat_round_tests`,
`cdisasm_arm_sve_integer_compare_tests`,
`cdisasm_arm_sve_integer_compare_immediate_tests`, and
`cdisasm_arm_sve_fp_estimate_tests` and
`cdisasm_arm_f64mm_permute_tests` and
`cdisasm_arm_sve_int_to_fp16_tests` and
`cdisasm_arm_sve_int_to_fp_tests` and
`cdisasm_arm_sve_first_last_tests` and
`cdisasm_arm_sve_cterm_tests` and
`cdisasm_arm_sve_predicate_break_tests` and
`cdisasm_arm_sve_while_single_tests` and
`cdisasm_arm_sve_while_pair_tests` and
`cdisasm_arm_sve_while_counter_tests` and
`cdisasm_arm_sve_counter_mask_tests` and
`cdisasm_arm_sve_whilewr_rw_tests` suites; ON builds check full metadata,
formatting, and independent CPU/flag gates, while OFF builds retain structural
ownership and zeroed failure results.
The K-mask suite enumerates all 51 public mnemonics and all 65 exact descriptor
rows, including KMOV direction/width aliases, AVX-512/AVX10 admission,
malformed controls, and truncation. The compare suite enumerates all eight
mnemonics at all three vector lengths and covers memory/broadcast, extended
sources, K-mask metadata, Intel/AT&T formatting, legacy AVX-512 versus AVX10.1
routes, reserved fields, and truncation. The ARM suite enumerates all 15 SVE
predicate-logical operations and covers formatter, endian, CPU/mode, reserved,
truncated, and ON/OFF behavior. The integer MIN/MAX suite enumerates all 48
register forms plus memory, broadcast, masking, and alternate AVX-512/AVX10
routes. The SVE arithmetic suite enumerates all 26 allocated operation/width
forms and rejects all six unallocated smaller-width CPA forms.
The multiply suite covers all ten mnemonics at all three vector lengths,
full-width memory, legal broadcasts, masking, WIG aliases, CPU/runtime routes,
and reserved controls. The SVE permute suite covers all 24 allocated forms and
all eight unallocated operation/width selectors, including endian parity and
SVE-only versus SME-only CPU profiles.
The F64MM Q-element permute suite exhausts its disjoint 262,144-word envelope:
196,608 `ZIP1`/`ZIP2`/`UZP1`/`UZP2`/`TRN1`/`TRN2` forms are allocated and
65,536 selector-4/5 forms are reserved. It checks `.q` operand metadata,
little-/big-endian parity, `CPU_ANY`-only conservative profile admission,
formatting, truncation, and OFF-build structural ownership. The classic VEX
AVX-VNNI suite covers all four opcodes at both vector lengths with register and
memory sources, W/prefix/map boundaries, exact read/write access, the bit-61
family gate, positive and negative CPU profiles, formatting, truncation, and
OFF-build ownership.
The AVX-VNNI-INT8 suite exhausts 3,072 allocated W=0 and 3,072 reserved W=1
controls across all six mnemonic/prefix rows, both vector lengths, and every
ModRM value. It also checks the distinct bit-62 runtime selector,
CPUID.7.1.EDX[4] CPU gate, classic-AVX-VNNI prefix ownership, unowned opcode/map
neighbors, Intel/AT&T formatting, truncation, and OFF-build ownership. The
SVE/SME integer-to-FP16 suite exhausts the exact 65,536-word classifier:
49,152 selector-2--7 conversions are allocated and 16,384 selector-0/1 words
are reserved. It checks H/S/D source typing, source-granularity predicate
metadata, SVE-or-SME CPU routes, endian and generic-dispatch parity, canonical
formatting, truncation, and OFF-build ownership.
The AVX-VNNI-INT16 suite independently exhausts 3,072 allocated W=0 and 3,072
reserved W=1 controls across the six D2/D3 and F3/66/none rows. It checks the
bit-63 runtime selector, CPUID.7.1.EDX[10] profile gate, prefix/map neighbors,
Intel/AT&T formatting, truncation, and OFF-build ownership. The companion
SVE/SME integer-to-FP suite exhausts all 65,536 allocated words across the four
S-to-S, D-to-S, S-to-D, and D-to-D signed/unsigned envelopes, including typed
predicate/vector metadata, endian parity, named CPU routes, formatting,
truncation, and OFF-build ownership.
The modular/wrapping ADD/SUB suite covers all 60 allocated descriptor shapes:
24 register forms, 24 full-width memory forms, and 12 legal dword/qword
broadcasts across the eight byte/word/dword/qword ADD/SUB names. It also fixes W/WIG rules,
masking and zeroing, compressed displacement, extended registers, legacy
modes, mutually alternative AVX-512/AVX10 routes, reserved controls,
truncation, formatting, and the OFF-build structural contract. The SVE
table-lookup suite enumerates all 16 lookup operation/width forms and the four
allocated MOV-from-GPR width forms, then verifies that the residual
124-control selector-14 space remains unowned and all 128 selector-15
controls remain invalid. It additionally fixes register-list shape,
read/write metadata, endian and generic-dispatch parity, exact alternative
SVE/SME feature routes, named-CPU rejection, adjacent unowned controls, and
the OFF-build contract.
The saturating ADD/SUB suite covers all eight signed/unsigned byte/word names,
32 VEX.128/256 register/full-memory operand shapes and 48
EVEX.128/256/512 register/full-memory operand shapes. It independently checks
the three VEX wire aliases and both W values, VEX AVX-versus-AVX2 admission,
EVEX AVX-512F/BW/VL-versus-AVX10.1 admission, merge/zero masking, compressed
displacement, extended registers, complete rejection of broadcast, reserved
controls, truncation, exact Intel/AT&T output, and OFF-build ownership. The
`TBLQ` suite exhausts all 131,072 words in the exact
`0xff20fc00/0x4400f800` class, checks B/H/S/D formatting and endian parity,
generic dispatch, write/read/read operand access with a singleton Z-register
list, every current named A64 CPU rejection, the SVE2.1-or-SME2.1 requirement,
adjacent unowned classes, truncation, and OFF-build ownership.
The dword/qword variable-shift suite enumerates all 60 canonical VEX and 486
canonical EVEX wire forms, reserved controls, register/full-memory/broadcast tuples, masks,
compressed displacement, AVX2 and AVX-512/AVX10 routes, APX P0.B4 and U0
ownership, exact Intel/AT&T text, truncation, and the OFF-build contract. The
predicated-unary suite exhausts the integer, bitwise/floating, and reverse
classifiers: 917,504 allocated words and 393,216 reserved words, with exact
element-width rules, `/m` versus `/z` operand metadata, floating-point flags,
endian parity, SVE/SME versus SVE2p2/SME2p2 feature gates, and OFF-build
ownership.
The word variable-shift suite covers all 162 canonical EVEX register and
full-memory forms, mask/zero and compressed-displacement metadata, the
no-broadcast boundary, AVX-512F/BW/VL versus AVX10.1 admission, exact APX
P0.B4 and U0/X4 ownership, formatting, truncation, and OFF-build behavior. The
predicated-vector-shift suite exhausts all 524,288 words in its exact A64
classifier: 270,336 allocated and 253,952 reserved. It checks all direct,
reverse, same-width, and wide-count operation/width controls, destructive `/m`
metadata, endian parity, SVE-or-SME admission, formatting, and OFF-build
ownership.
The immediate packed-rotate suite enumerates all 82,944 canonical imm8 wire
forms, 396 APX P0.B4/U0/X4 forms, 432 reserved EVEX controls, and the complete
16-control ModRM-extension/W matrix in full and truncated form. It also checks
register/full-memory/broadcast operands, masks, compressed displacement,
AVX-512/AVX10 admission, Intel/AT&T formatting, and OFF-build ownership. The
SVE integer vector-compare suite exhausts all 8,388,608 words in its exact A64
classifier: 7,077,888 allocated and 1,310,720 reserved. It checks ordinary
and wide-source operation/width controls, typed predicate/vector operands,
NZCV-setting metadata, endian parity, SVE-or-SME admission, formatting,
truncation, and OFF-build ownership.
The immediate packed-shift suite enumerates all 82,944 canonical imm8 wire
forms, 396 APX P0.B4/U0/X4 forms, 432 structural-invalid EVEX controls, and
every allocated or reserved extension/W neighbor in opcode `72`. It checks all
three vector lengths, register/full-memory/broadcast operands, masks,
compressed displacement, AVX-512/AVX10 admission, Intel/AT&T formatting,
truncation, and OFF-build ownership. The SVE integer compare-with-immediate
suite exhausts all 12,582,912 words across its signed and unsigned envelopes:
11,534,336 allocated and 1,048,576 reserved. It checks every operation, B/H/S/D
width, immediate, `Pd`/`Pg`/`Zn` field, NZCV-setting metadata, endian path,
SVE-or-SME admission, formatting, truncation, and OFF-build ownership.

The `cdisasm_x86_movntdqa_tests` suite checks all six forms and sweeps every
ModRM at all three legacy modes, both VEX widths, and all three EVEX widths:
576/384/576 memory allocations and 192/128/192 register-reserved controls.
It also exhausts VEX P1 and EVEX P0/P1/P2 controls, profiles, APX address
extensions, tuple scaling, collision ownership, formatting, truncation, and
extras-OFF precedence. The
`cdisasm_arm_sve_saturating_predicate_count_tests` suite exhausts 720,896
saturating and 66,560 predicate-count allocations plus 359,424 reserved
controls and checks operands, flags, feature/profile gates, endian transport,
formatting, truncation, and extras-OFF ownership. The separate
`cdisasm_arm_sve_first_last_tests` suite exhausts all 65,536 allocated
`FIRSTP`/`LASTP` words alongside the 32,768 classic-`CNTP` siblings and
163,840 reserved operation controls. It locks form identity, three-operand
access and typing, SVE2.2-or-SME2.2 admission, endian transport, formatting,
truncation, and extras-OFF ownership. The `cdisasm_x86_lddqu_tests` suite
exhausts legacy prefixes/ModRM, VEX controls/ModRM, and REX2 payloads for all
three forms, plus CPU/runtime gates, formatting, truncation, and extras-OFF
ownership.
The `cdisasm_x86_vmovmsk_tests` suite exhausts 7,168 allocated encodings across
16-, 32-, and 64-bit modes, exactly 1,792 per form, together with full long-mode
VEX selector/ModRM ownership. Compiled pinned-XED classifiers agree on all
589,824 long-mode cells (4,608 allocated and 585,216 reserved), all 262,144
C1/E1 cells in 16/32-bit modes (2,048 allocated and 260,096 reserved), and 384
legacy LES boundaries. Profiles, runtime selection, formatting, truncation,
collisions, and extras-OFF precedence are checked separately.

The `cdisasm_x86_vmovq_tests` suite exhausts 79,872 allocations across exact
forms 5884--5896: 18,432 VEX and 61,440 EVEX. Its VEX selector sweep also
classifies 10,240 `VMOVD` collisions and 2,625,536 reserved cells. The full
EVEX P0/U/W/ModRM domain splits into 61,440 allocations, 69,632
`VMOVD`/`MOVZXC` collisions, and 32,768 reserved controls; its W1 subset
contains 61,440 allocations, 4,096 collisions, and 16,384 invalid U0
controls. Pinned XED agrees across the bounded core and C5/P1/P2 sweeps;
profiles, APX address promotion, Knights Mill, formatting, truncation, and
extras-OFF precedence are checked.

The `cdisasm_x86_vmovrs_tests` suite exhausts 2,211,840 allocated encodings
across exact forms 5897--5908, 184,320 per form. It locks all four element
families and three vector widths, memory-only access, mask merge/zero, exact
AVX10 MOVRS width groups and bits, 16/32/64-byte disp8 scaling, APX-promoted
addresses, reserved controls, formatting, truncation, and extras-OFF ownership.

The `cdisasm_x86_vmovsd_tests` suite exhausts 7,721,472 allocated encodings
across exact forms 5909--5915: 132,096 VEX and 7,589,376 EVEX. Its factored
boundary sweeps additionally classify 1,235 reserved controls and 2,308
legacy/neighbor collision-selector cells. It locks both opcode directions,
NDS ordering, scalar merge access, mask/zero legality, ignored fields, APX
B4/X4 addressing, eight-byte disp8 scaling, profiles/runtime, formatting,
truncation, and extras-OFF ownership against pinned XED.

The `cdisasm_x86_vmov_fp16_dup_tests` suite exhausts 9,092,608 allocations
across exact `VMOVSHDUP` forms 5916--5925, `VMOVSH` forms 5926--5928, and
`VMOVSLDUP` forms 5929--5938. The duplicate-move portion covers VEX and EVEX,
all three EVEX vector widths, register/full-memory sources, merge/zero masks,
16/32/64-byte tuple scaling, and exact AVX versus width-specific AVX512F
admission. The scalar-half portion covers m16 store/load and three-register
directions, scalar merge access, the AVX512-FP16 scalar gate, and two-byte
tuple scaling. Both cover independently gated APX B4/X4 addressing,
non-long extension behavior, malformed controls, formatting, truncation, and
extras-OFF ownership. Factored boundary sweeps classify 1,574 duplicate and
1,763 scalar-half controls as invalid and retain 2,308 delegated
mandatory-prefix/legacy-neighbor selector cells. Pinned XED classifies every
one of the 42 valid and 18 reserved-control corpus witnesses as expected.

The `cdisasm_x86_vmovss_tests` suite exhausts 7,721,472 allocated encodings
across exact forms 5939--5945: 132,096 VEX and 7,589,376 EVEX. Its factored
boundary sweeps additionally classify 1,235 reserved controls and 2,308
legacy/neighbor collision-selector cells. They cover the PF3/W0 selector,
both opcode directions, NDS
ordering, dword memory, scalar merge access, mask/zero legality, ignored LL,
APX B4/X4 addressing, four-byte compressed disp8, profiles/runtime,
formatting, truncation, legacy/neighbor collisions, and extras-OFF ownership
against pinned XED.

The `cdisasm_x86_vmovupd_ups_tests` suite exhausts 2,425,856 allocated
encodings across forms 5946--5979, plus 3,190 reserved controls and 1,544
delegated collision-selector cells. It locks NP/66 and W selection, both
opcode directions, every VEX/EVEX vector width, operand access, masks and
store-zeroing rejection, Full-tuple disp8 scaling, exact AVX/AVX512F/AVX10
admission, APX B4/X4 addressing, formatting, truncation, and extras-OFF
ownership against pinned XED.

The `cdisasm_x86_vmovw_tests` suite exhausts 98,304 allocations across exact
forms 5980--5986, with per-form totals 5,120, 27,648, 13,824, 5,120, 27,648,
13,824, and 5,120. Its factored P1/P2 sweeps classify 3,046 target-owned
reserved controls while retaining all map-1 VMOVD/VMOVQ and map-2 neighbors.
It locks both opcode directions, GPR32/XMM/m16 access, WIG `66` versus F3/W0
selection, exact `AVX512_FP16_128N` and `AVX512_MOVZXC_128` runtime/profile
routes, Tuple2 disp8 scaling, APX B4/X4, high/non-long registers, formatting,
truncation, and extras-OFF ownership against pinned XED.

The `cdisasm_x86_vmpsadbw_tests` suite covers 196,608 VEX and 829,440
canonical EVEX control/ModRM cells at a representative imm8, then separately
checks all imm8 values and the complete P1/P2 boundaries. It locks forms
5987--5996, all five vector-width routes, register/Full-tuple memory operands,
merge/zero masks and access, 16/32/64-byte disp8, exact AVX/AVX2/
AVX512-MEDIAX gates, APX B4/X4, non-long behavior, family collisions,
formatting, truncation, and extras-OFF ownership against pinned XED.

The `cdisasm_x86_virtualization_form_tests` suite locks all 15 forms
5997--6005/6048--6053, their exact operands and access, VMX/SVM/VTX and
privileged groups, status-flag metadata, mode and address-size behavior,
runtime/profile admission, REX/REX2/APX-F transport, prefix actions, collision
ownership, formatting, truncation, and extras-OFF ownership. Its exhaustive
slices cover 1,536 legacy and 65,536 REX2 VMREAD/VMWRITE tuples, 3,584 REX2
pointer/fixed tuples, and 33,536 VMXOFF classifier cells against pinned XED.

The `cdisasm_x86_vmulbf16_tests` suite locks forms 6006--6011, width-specific
groups and runtime bits, register/Full-memory/BF16-broadcast sources,
merge/zero masking and access, 16/32/64-byte disp8 scaling, high registers,
APX B4/U0/X4 ownership, exact profile admission, reserved controls, family
neighbors, both syntaxes, truncation, and extras-OFF ownership. It exhausts
4,032 allocated plus 576 reserved ModRM cells, the factored P1/P2 spaces, and
98,304 high-register tuples against pinned XED.

The `cdisasm_x86_vmul_fp16_tests` suite locks `VMULPH` forms 6022--6027 and
`VMULSH` forms 6042--6043, exact MAP5/opcode-59 pp/W/U selection, all four
width/scalar groups and runtime bits, masks, Full/broadcast/Tuple2 memory,
embedded rounding, disp8 scaling, high registers, APX B4/U0/X4 ownership,
profile admission, reserved controls, VMULBF16 and unallocated-prefix
collisions, both syntaxes, truncation, and extras-OFF ownership. Its bounded
sweeps classify 4,608 packed plus 960 scalar allocated ModRM cells and 576
scalar reserved cells, exact P1/P2 partitions, and the high-register and P0
extension spaces against pinned XED.

The `cdisasm_x86_vmul_fp_tests` suite locks all 28 classic
`VMULPD`/`VMULPS`/`VMULSD`/`VMULSS` forms 6012--6021, 6028--6041, and
6044--6047. It exhausts 18,432 allocated VEX ModRM cells and 15,744 allocated
plus 8,832 reserved EVEX cells, checking exact identities and operands,
width/scalar groups, merge and zero masks, Full and element tuples,
broadcast, embedded rounding and SAE, compressed displacement scaling,
ordinary high registers, APX B4/U0/X4 ownership, profile/runtime admission,
prefix and truncation behavior, both syntaxes, and extras-OFF ownership
against pinned XED.

The `cdisasm_x86_vor_fp_tests` suite locks all twenty `VORPD`/`VORPS` forms
6054--6073. It exhausts 9,216 VEX allocations, 8,064 canonical EVEX
allocations plus 4,224 reserved controls, 2,688 allocated/1,408 reserved B4
cells, and 2,304 allocated/1,792 reserved U0 cells. It checks exact form and
operand identity, AVX versus AVX512DQ/AVX10.1 gates, masks, Full memory,
broadcast and disp8, high registers, APX B4/U0/X4 behavior, non-long ignored
extensions and LES/LDS collisions, reserved register `EVEX.b`, formatting,
truncation, and extras-OFF ownership against pinned XED.

The `cdisasm_x86_vp2intersect_tests` suite locks all twelve
`VP2INTERSECTD/Q` forms 6074--6085 and exhausts 786,432 controls as 8,064
allocated and 778,368 reserved. It checks odd/even ModRM.reg aliases and the
two-write-operand `kN+1` destination, every vector width, register/Full-memory
and broadcast inputs, disp8 scaling, high registers, APX B4/U0/X4 addressing,
exact width/profile gates, malformed EVEX controls, both syntaxes, truncation,
and extras-OFF ownership against pinned XED.

The `cdisasm_x86_vpabs_tests` suite locks all 36 `VPABSB/D/Q/W` forms
6088--6123 in pinned-XED order. Its VEX domain classifies 9,216 allocated and
580,608 reserved controls; its EVEX domain classifies 259,200 allocated and
527,232 reserved controls. It checks every vector width and source shape,
mask merge/zero, dword/qword broadcast, Full and scalar tuple disp8, exact
AVX/AVX2/AVX512F/AVX512BW/AVX10.1 groups and profiles, high registers,
non-long aliases, APX B4/U0/X4 addressing, malformed controls, collision and
truncation precedence, both syntaxes, formatter-schema rejection, and
extras-OFF ownership against pinned XED.

The `cdisasm_x86_vpblend_tests` suite locks `VPBLENDD` forms 6306--6309 and
`VPBLENDW` forms 6338--6341. It exhausts the shared VEX.0F3A.66
NDS-plus-imm8 lattice as 294,912 allocated and 1,277,952 reserved controls,
checking all four operands, register and memory sources, address formation,
W0 versus WIG, AVX/AVX2 gates, prefix/collision ownership, both syntaxes,
formatter-schema rejection, truncation, and extras-OFF behavior against
pinned XED and LLVM 21.

The `cdisasm_x86_vpblendvb_tests` suite locks `VPBLENDVB` forms 6334--6337
and exhausts 786,432 bounded mode/RXB/W/L/pp/`vvvv`/ModRM controls as 98,304
allocated and 688,128 reserved. It checks XMM/YMM register and memory forms,
all 1,536 mode/L/selector values, `SE_IMM8` selector metadata with no immediate
operand, high registers and addresses, non-long B/`vvvv`/selector aliases and
C4/LES collisions, exact AVX versus AVX2 gates, prefix/pp/W ownership, late
payload-truncation precedence, both syntaxes, formatter-schema rejection, and
extras-OFF behavior. Pinned XED supplies the selected non-long alias policy;
LLVM 21 and Capstone instead expose an impossible high selector register for
that spelling.

The `cdisasm_x86_vpbroadcastb_tests` suite locks forms
6342/6343/6347/6348 together with `VPBROADCASTW` forms 6387/6388/6392/6393,
and exhausts 1,572,864 mode/RXB/W/L/pp/`vvvv`/ModRM controls as 12,288
allocated and 1,560,576 reserved. It checks byte/word-sized
register/memory reads, XMM/YMM writes, all 53 profiles, AVX+AVX2 metadata and
AVX2 runtime admission, high registers and addresses, non-long B' aliases and
C4/LES collisions, prefix and late-truncation ownership, opcode-`79` and EVEX
sibling isolation, both syntaxes, formatter-schema rejection, and extras-OFF
behavior. Pinned XED database/kit checks and eight XED/LLVM 21 valid samples
provide independent form evidence.

The `cdisasm_x86_vpbroadcastdq_tests` suite locks forms
6355/6356/6360/6361/6374/6375/6379/6380 and exhausts 1,572,864 bounded
mode/RXB/W/L/pp/`vvvv`/ModRM controls as 12,288 allocated and 1,560,576
reserved. It checks dword/qword memory and low-XMM reads, XMM/YMM writes,
AVX2 admission, every mode/profile/address class, prefix and late-truncation
ownership, exact formatting and forgery rejection, sibling isolation, and
extras-OFF behavior against pinned XED and LLVM 21.

The `cdisasm_x86_vpcmpeqq_tests` suite locks forms 6454--6457 and exhausts
786,432 bounded mode/RXB/W/L/pp/`vvvv`/ModRM controls as 196,608 allocated
and 589,824 reserved. It checks XMM/YMM register and memory forms, WIG,
AVX-versus-AVX2 admission, every mode/profile/address class, non-long aliases
and C4/LES collisions, legacy/EVEX sibling isolation, prefix and late-
truncation ownership, exact formatting and forgery rejection, and extras-OFF
behavior against pinned XED and LLVM 21.

The `cdisasm_x86_vpcmov_tests` suite locks all six exact `VPCMOV` forms
6410--6415 and exhausts its bounded XOP controls as 393,216 allocated and
1,179,648 reserved. It checks both widths, W-dependent operand order,
register-form alias collapse, every selector byte, non-long extension aliases,
addresses, AVX/XOP metadata and gates, legacy-prefix/pp ownership, truncation,
both syntaxes, formatter-schema rejection, and extras-OFF behavior against
pinned XED and LLVM 21.

The `cdisasm_x86_vpperm_tests` suite locks exact XMM `VPPERM` forms
7686--7688 and exhausts 1,572,864 bounded mode/RXB/W/L/pp/`vvvv`/ModRM
controls as 196,608 allocated and 1,376,256 reserved. It checks W-dependent
memory and selector-source order, register-form W collapse, every `SE_IMM8`
selector byte with metadata in `encoding.selector_offset` and no immediate
operand, all modes and address forms, non-long aliases, exact AVX+XOP groups,
runtime/profile admission, prefix/pp/L ownership, late payload-truncation
precedence, both syntaxes, formatter-schema rejection, and extras-OFF behavior.
The non-long policy aliases XOP R/X/B, high `vvvv`, and selector extensions
into the eight-register namespace, matching LLVM 21 and the existing exact
XOP selector policy. Pinned XED otherwise confirms the family but anomalously
exposes `r12d` for one 32-bit SIB.X spelling; that isolated result is not used
to escape the architectural non-long register namespace.

The `cdisasm_arm_sve_cterm_tests` suite exhausts 4,096 allocated
`CTERMEQ`/`CTERMNE` words and the 4,096 reserved `op=0` parent words. It locks
forms 2593--2594, W/X and WZR/XZR operands, NZCV metadata, SVE-or-SME
admission, endian/generic transport, canonical formatting with forged-result
rejection, truncation, adjacency, and extras-OFF ownership.

The `cdisasm_arm_sve_predicate_break_tests` suite exhausts 294,912 allocated
words across forms 2546--2555 and 270,336 reserved parent controls. It locks
the four-operand BRKP and tied-source BRKN schemas, the three-operand
BRKA/BRKB schema, typed byte predicates, governing `/z` versus `/m`, exact
write versus read/write destination access, NZCV writes on the five `S`
forms, SVE-or-SME admission, endian/generic transport, canonical formatting
with forged-result rejection, truncation, adjacency, and extras-OFF
ownership.

The `cdisasm_arm_sve_predicate_control_tests` suite exhausts all 5,648
allocated words in forms 2556--2561 and all 16,944 reserved parent residuals.
It locks the PTEST, PFIRST, PNEXT, PTRUE, PTRUES, and PFALSE operand/access
schemas, B/H/S/D predicate typing where allocated, tied destination reads,
pattern immediates and canonical names, exact NZCV/predication flags,
SVE-or-SME admission, endian/generic transport, formatting, truncation, and
extras-OFF ownership against pinned AARCHMRS and LLVM 21.

The `cdisasm_arm_sve_psel_tests` suite exhausts all 491,520 allocated words in
form 2565, the 32,768 invalid words from both `tsz=0000` controls, and all
524,288 bit-4 neighbors. It locks `Pd, Pn, Pm.T[Wv, lane]`, write/read/read
access, B/H/S/D element and lane reconstruction, W12--W15, scalable-only metadata,
the exact SVE2.1-or-baseline-SME alternative, endian/generic transport,
canonical formatting and forgery rejection, truncation, and extras-OFF
ownership. LLVM 21 independently agrees on all 30 legal `i1:tsz` controls.

The `cdisasm_arm_sve_integer_immediate_tests` suite classifies all 2,097,152
words in the forms-2619--2632 parent: 565,248 arithmetic allocations, 57,344
arithmetic leaf-reserved controls, 81,920 allocated DUP/FDUP siblings, 16,384
sibling-reserved controls, and 1,376,256 other reserved words. The dedicated
`cdisasm_arm_sve_dup_immediate_tests` suite exhausts the broadcast leaves as
57,344 allocated plus 8,192 reserved DUP words and 24,576 allocated plus 8,192
reserved FDUP words. Together they lock preferred aliases, signed/unsigned/
shifted and expanded IEEE immediates, typed/tied access, exact flags and
SVE-or-SME admission, endian/generic transport, formatting and forgery
rejection, truncation, and extras-OFF ownership against AARCHMRS and LLVM 21.

The `cdisasm_arm_sve_dot_product_tests` suite exhausts the 262,144-word shared
parent for forms 2633--2636: 65,536 allocations in each baseline SDOT/UDOT
leaf, 32,768 in each SVE2p3/SME2p3 byte-to-half leaf, and 65,536 reserved
`size=00` words. It locks the tied read/write accumulator, read-only sources,
B-to-S/H-to-D/B-to-H arrangements, exact feature alternatives and named-profile
boundaries, endian/generic transport, canonical formatting and forgery
rejection, truncation, adjacency, and extras-OFF ownership. LLVM 21 supplies
the independent baseline oracle; the p3 arrangements rely on pinned AARCHMRS
because LLVM 21 does not yet accept them.

The `cdisasm_arm_sve_complex_muladd_tests` suite exhausts 1,507,328 allocated
and 327,680 reserved words across forms 2637--2641. It locks every legal
arrangement and rotation, tied accumulator access, read-only sources,
SVE2-or-SME admission, scalable-only flags, endian/generic transport,
canonical formatting and forgery rejection, truncation, adjacency, and
extras-OFF ownership. LLVM 21 independently confirms all 46 legal
arrangement/rotation combinations and rejects the reserved-width controls.

The `cdisasm_arm_sve_widening_muladd_tests` suite exhausts 1,441,792 allocated
and 393,216 reserved words across forms 2642--2655. It locks all twelve
widening bottom/top add/sub identities and both same-width rounding-high
identities, B/H/S/D typing, tied accumulator access, read-only Zn/Zm,
SVE2-or-SME admission, scalable-only flags, endian/generic transport,
canonical formatting and forgery rejection, truncation, adjacency, and
extras-OFF ownership against pinned AARCHMRS and LLVM 21.

The `cdisasm_arm_sve_usdot_tests` suite exhausts all 32,768 allocated
`USDOT Zda.S, Zn.B, Zm.B` words in form 2656 and all 98,304 reserved
`size=00/01/11` parent words. It locks tied read/write accumulator access,
read-only byte sources, the exact SVE-or-SME plus I8MM gate, named-profile
boundaries, endian and generic transport, canonical formatting with forged-
result rejection, truncation, fixed-bit neighbors, and extras-OFF ownership
against pinned AARCHMRS and LLVM 21.

The `cdisasm_arm_sve_sudot_indexed_tests` suite exhausts all 65,536 words
under the two exact indexed-dot masks. It locks forms 2734--2735, tied
`Zda.S`, read-only `Zn.B` and indexed `Zm.B[lane]`, the
SVE-or-SME-plus-I8MM gate, all 38 named profiles, endian/generic transport,
canonical formatting with forged-result rejection, fixed-bit and sibling
identity, truncation, and extras-OFF ownership. LLVM 21 matches every word in
both leaves.

The `cdisasm_arm_sve_aes_unary_tests` suite exhausts all 64 allocated
`AESMC`/`AESIMC` words and all 192 reserved size controls. It locks forms
2903--2904, the two explicit tied read/write `Zdn.B` operands, FEAT_SVE_AES
profile admission, endian/generic transport, formatting-schema rejection,
truncation, mode isolation, and extras-OFF ownership against LLVM 21.

The `cdisasm_arm_sve_crypto_binary_tests` suite exhausts the complete
16,384-word parent for `AESE`, `AESD`, and `SM4E`: 3,072 allocated and 13,312
reserved words. It locks forms 2905--2907, tied destination/source access,
byte versus word arrangements, independent FEAT_SVE_AES/FEAT_SVE_SM4 gates,
all named profiles, endian/generic transport, formatter forgery rejection,
truncation, fixed-bit neighbors, and extras-OFF ownership against LLVM 21.

The `cdisasm_arm_sve_punpk_tests` suite exhausts all 512 words in the
forms-2468--2469 parent, 256 each for `PUNPKLO` and `PUNPKHI`. It locks
`Pd.H` write and `Pn.B` read operands, scalable-vector-only metadata, exact
SVE-or-SME admission, all named profiles, endian/generic transport, canonical
formatting with forged-result rejection, truncation, fixed-bit neighbors, and
extras-OFF ownership. LLVM 21 matches every word under both `+sve` and `+sme`.

The `cdisasm_arm_sve_predicated_shift_sat_round_tests` suite exhausts all
524,288 words in the forms-2657--2668 parent: 393,216 allocated and 131,072
reserved. It locks all twelve names and four reserved selectors, B/H/S/D
typing, tied read/write destination access, governing merge-predicate and
source reads, scalable/predicated metadata, exact SVE2-or-SME admission,
endian/generic transport, canonical formatting with forged-result rejection,
truncation, fixed-bit neighbors, and extras-OFF ownership against pinned
AARCHMRS and LLVM 21.

The `cdisasm_arm_sve_predicated_sat_unary_tests` suite exhausts all 262,144
words in the forms-2669--2676 parent: 163,840 allocated and 98,304 reserved.
It locks `.S`-only `URECPE`/`URSQRTE`, B/H/S/D `SQABS`/`SQNEG`, merge versus
zero destination and predicate metadata, exact SVE2-or-SME versus
SVE2.2-or-SME2.2 admission, endian/generic transport, canonical formatting
with forged-result rejection, truncation, fixed-bit neighbors, and extras-OFF
ownership against pinned AARCHMRS and LLVM 21.

The focused A64 accumulating-long and halving suite classifies 65,536
`SADALP`/`UADALP` parent words as 49,152 allocated and 16,384 reserved, then
exhausts all 262,144 allocated `SHADD`/`SHSUB`/`SRHADD`/`SHSUBR`/`UHADD`/
`UHSUB`/`URHADD`/`UHSUBR` words. It locks forms 2677--2686, B/H/S/D source
and destination typing, destructive access, destination-granularity predicates,
SVE2-or-SME admission, endian/generic transport, canonical formatting with
forged-result rejection, truncation, fixed-bit neighbors, and extras-OFF
ownership against pinned AARCHMRS and LLVM 21.

The `cdisasm_arm_sve_predicated_pairwise_tests` suite exhausts the complete
262,144-word parent for forms 2687--2692: 196,608 allocated and 65,536
reserved operation-2/3 words. It locks all six names and B/H/S/D arrangements,
tied read/write destinations, typed `/m` predicates, read-only sources, the
SVE2p3-or-SME2p3 `SUBP` gate versus SVE2-or-SME for the other five, endian and
generic transport, canonical formatting with forged-schema rejection,
truncation, fixed-bit neighbors, and extras-OFF ownership. Pinned AARCHMRS
validates all six leaves; LLVM 21 independently matches the five SVE2 leaves
but lacks SVE2p3 `SUBP` support.

The `cdisasm_arm_sve_clamp_tests` suite exhausts all 262,144 words under
`(word & 0xff20f800) == 0x4400c000`. It locks `SCLAMP`/`UCLAMP` forms
2701--2702, all B/H/S/D arrangements and register fields, destructive
read/write `Zd` plus read-only `Zn`/`Zm`, exact SVE2.1-or-SME admission,
endian/generic transport, canonical formatting with forged-schema rejection,
fixed neighbors, truncation, and extras-OFF ownership against pinned
AARCHMRS, LLVM 21, and the independent operand oracle.

The `cdisasm_arm_sve_pointer_muladd_tests` suite exhausts all 262,144 words
under `(word & 0xff20f400) == 0x4400d000`: 32,768 allocations for each of
forms 2707--2708 and 196,608 reserved B/H/S controls. It locks destructive
`.D` operands and operation-specific source order, the strict SVE-and-CPA
gate, all named-profile rejections, endian/generic transport, canonical
formatting with forged-schema rejection, fixed neighbors, truncation, and
extras-OFF ownership against pinned AARCHMRS and LLVM 21.

The `cdisasm_arm_sve_quad_permute_tests` suite exhausts the complete
1,048,576-word parent. It locks the 524,288 `ZIPQ1`/`UZPQ1`/`ZIPQ2`/`UZPQ2`
words in forms 2711--2712/2714--2715 across B/H/S/D, verifies 131,072
allocated `TBLQ` sibling words remain routed to that leaf, and requires the
other 393,216 control-100/101/111 words to stay invalid. It checks three typed
scalable Z operands with write/read/read access, the SVE2.1-or-SME2.1 gate, all named-
profile rejections, endian/generic transport, canonical formatting with
forged-schema rejection, truncation, and extras-OFF ownership against pinned
AARCHMRS and LLVM 21.

The `cdisasm_arm_sve_while_single_tests` suite exhausts 1,048,576 allocated
words across forms 2585--2592. It locks B/H/S/D predicate typing, W/X and
zero-register operands, NZCV metadata, SVE/SME versus SVE2/SME admission,
endian/generic transport, formatting, truncation, and extras-OFF ownership.
The paired `cdisasm_arm_sve_while_pair_tests` suite exhausts all 262,144 words
in forms 2574--2581 and checks typed even/odd predicate pairs, X/XZR sources,
the SVE2.1-or-SME2 gate, and the same transport and formatter contracts.

The `cdisasm_arm_sve_while_counter_tests` suite exhausts all 524,288 words in
forms 2566--2573. It locks typed `PN8`--`PN15` destinations, X/XZR sources,
`VLx2`/`VLx4`, NZCV/scalable/predicated metadata, exact SVE2.1-or-SME2
admission, endian/generic transport, formatting, truncation, and extras-OFF
ownership. The `cdisasm_arm_sve_counter_mask_tests` suite exhausts all 3,104
words in forms 2582--2584: 2,048 one-result `PEXT`, 1,024 pair-result `PEXT`,
and 32 counter-predicate `PTRUE`, plus 1,024 reserved parent controls. It
checks untyped indexed `PNn[index]`
sources, typed ordinary predicate results, the `p15, p0` wrap, typed PN PTRUE
results, the same feature alternative, and all transport, formatter,
truncation, and disabled-build contracts.

The `cdisasm_arm_sve_whilewr_rw_tests` suite exhausts all 131,072 allocated
words across exact `WHILEWR`/`WHILERW` forms 2595--2596. It fixes typed
predicate writes, Xn/Xm reads and XZR handling, exact NZCV/scalable/predicated
flags, SVE2-or-SME profile admission, endian and generic transport, canonical
formatting with forged-result rejection, truncation, and extras-OFF ownership.

CMake generates `<cdisasm/cdisasm_config.h>`, which
`<cdisasm/cdisasm_common.h>` includes. It always defines `USE_ARCH_X86`,
`USE_ARCH_ARM`, `USE_DISASM_FORMAT`, and `USE_EXTRA_OPCODES` as numeric zero or
one. Application code must therefore use `#if USE_ARCH_X86`,
`#if USE_ARCH_ARM`, `#if USE_DISASM_FORMAT`, and `#if USE_EXTRA_OPCODES`, not
`#ifdef`. The umbrella header
uses the same checks. An in-tree include of an explicitly disabled architecture
header produces a compile-time diagnostic instead of declaring an API whose
library is absent; selective installation omits that disabled header entirely.
`cdisasm_format.h` is always installed and emits the same diagnostic in build
and install trees when formatting is disabled; formatter symbols are not
exported. For manual source-tree builds and editor indexing, the checked-in
config header defaults both architectures to one and derives the formatter and
extra-opcode defaults from whether an architecture is enabled. CMake puts its
generated, build-specific header under the binary tree's `generated/include`
directory, puts that directory first in the configured include path, and
installs that generated copy. Even an in-source configure therefore cannot
overwrite the checked-in fallback.

## Linking and deployment

Installed CMake packages expose the common target plus the targets selected at
configuration time:

```cmake
find_package(cdisasm 12.0 CONFIG REQUIRED)

target_link_libraries(generic_decoder PRIVATE cdisasm::cdisasm)
# Available compatibility spellings resolve to cdisasm::cdisasm.
target_link_libraries(x86_decoder PRIVATE cdisasm::cdisasm_x86)
target_link_libraries(arm_decoder PRIVATE cdisasm::cdisasm_arm)
target_link_libraries(text_tool PRIVATE cdisasm::cdisasm_format)
```

The package components follow the same selection. `common` is always present;
`x86` is present only for `USE_ARCH_X86=ON`, `arm` only for
`USE_ARCH_ARM=ON`, and `format` only when `USE_DISASM_FORMAT=ON` and at least
one architecture is enabled. For example, a formatter-enabled ARM-only consumer
can request `COMPONENTS common arm format`; requesting `x86` from that
installation causes `find_package` to fail. Version, common configuration,
umbrella, and formatter headers are always installed; the formatter header is
a diagnostic boundary when its feature is off. Architecture headers,
architecture-specific fuzz harnesses and seeds, and opcode regression corpora
are installed only for their enabled module. The
package reports
`cdisasm_USE_ARCH_X86`, `cdisasm_USE_ARCH_ARM`, effective
`cdisasm_USE_DISASM_FORMAT`, requested
`cdisasm_REQUESTED_USE_DISASM_FORMAT`, effective
`cdisasm_USE_EXTRA_OPCODES`, requested
`cdisasm_REQUESTED_USE_EXTRA_OPCODES`, and the physical library choice as
`cdisasm_BUILD_SHARED_LIBS`.

There is one real library target: `cdisasm::cdisasm`. When enabled, the package
also publishes `cdisasm::cdisasm_x86` and/or `cdisasm::cdisasm_arm` as
compatibility CMake interface proxies to that core target. They preserve older
`target_link_libraries` statements but do not create architecture runtime or
import libraries. A formatter-enabled package also publishes
`cdisasm::cdisasm_format` as an interface compatibility proxy to the same core;
it creates no runtime or import library.

The generated build directory itself is a supported `cdisasm_DIR` and contains
a matching exported target file. An installed tree may be relocated and found
only from its new prefix. One prefix is deliberately limited to one exact
version/linkage/feature tuple: an installed fingerprint permits an identical
reinstall but rejects a different overlay before changing any artifact. A
legacy cdisasm tree with recognizable headers/package files but no fingerprint
is also rejected instead of being upgraded in place. Guard lookup follows
CMake's relative, absolute GNUInstallDirs, and staged `DESTDIR` path rules.
CMake boolean aliases are normalized before serialization: `ON`, `TRUE`,
`YES`, and `1` are equivalent, as are `OFF`, `FALSE`, `NO`, and `0`.

The exported CMake target handles the declaration mode automatically. A static
`cdisasm::cdisasm` target publishes `CDISASM_STATIC` as an interface compile
definition, including through all compatibility proxies; a shared target does
not. Non-CMake or manual Windows consumers of the static archive must define
`CDISASM_STATIC` themselves before including any cdisasm header so declarations
do not use `__declspec(dllimport)`.
On GCC and Clang, `CDISASM_STATIC` also gives public declarations hidden
visibility. A PIC static archive can therefore be embedded in a larger ELF or
Mach-O shared object without silently adding cdisasm functions to that
wrapper's dynamic ABI.

Shared builds route all common, decoder, and formatter calls through
`cdisasm-12.dll` and its `cdisasm.lib` import library. Static builds place the
same selected APIs in one archive and require no cdisasm DLL. No version-12
`cdisasm_format`, `cdisasm_x86`, or `cdisasm_arm` physical library exists in
either mode. Compiler/OS runtime DLLs are ordinary platform dependencies.

## Decoder model

The decoder and formatter APIs have no context object and perform no
allocation. Each such call keeps all state on its own stack, so decoding and
formatting are reentrant and may run concurrently. Input bytes are never
retained or modified. The separate current-CPU query can consult operating-
system metadata and is intended as a setup-time convenience rather than a
per-instruction hot-path call.

The architecture decoders represent mnemonics, registers, groups, operands,
and decorators only as numeric IDs and metadata. Human-readable x86 Intel/AT&T
syntax and canonical ARM syntax remain a separate optional API, but their
implementations and spelling tables are compiled into `cdisasm` when
`USE_DISASM_FORMAT=1`.

The architecture result structures are deliberately distinct.
`cdisasm_instruction` and `cdisasm_opcode` are x86 types;
`cdisasm_arm_instruction` and `cdisasm_arm_operand` are ARM types. They must
not be interpreted as one another. The generic function's `void *` parameter
accepts either result type, but its CPU group must match the pointed-to object.
Common status, operand-kind, operand-access, and semantic group values are
shared through `cdisasm_common.h`.

### Generic CPU-group dispatch

`cdisasm_decode` is exported by `cdisasm`, alongside every enabled explicit
architecture entry point. Its scalar arguments and fixed-size flags pointer are
common at the ABI boundary, while `mode`, the bitmap contents, and the
pointed-to result are interpreted by the selected decoder. The relevant common
declarations are:

```c
typedef uint64_t cdisasm_decode_flag_bitmap;

#define CDISASM_DECODE_FLAGS_BITMAP_COUNT 8u
#define CDISASM_DECODE_FLAGS_BIT_CAPACITY 512u
#define CDISASM_DECODE_FLAGS_SIZE 64u

typedef struct cdisasm_decode_flags {
    uint64_t bitmap[CDISASM_DECODE_FLAGS_BITMAP_COUNT];
} cdisasm_decode_flags;

cdisasm_status CDISASM_CALL cdisasm_cpu_decode_flag_mask(
    cdisasm_cpu_id cpu_id,
    uint32_t mode,
    cdisasm_decode_flags *flags);

uint32_t CDISASM_CALL cdisasm_decode(
    cdisasm_cpu_id cpu_id,
    uint32_t mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    const cdisasm_decode_flags *flags,
    void *instruction);
```

`cdisasm_decode_flags` is exactly 64 bytes and has no fields other than its
eight 64-bit words. Logical bit `n` is bit `n % 64` of
`bitmap[n / 64]`. `CDISASM_DECODE_FLAGS_NONE_INITIALIZER` creates a zero
object, while `CDISASM_DECODE_FLAGS_INITIALIZER(word0)` initializes bitmap 0
and zeroes words 1--7. The inline `cdisasm_decode_flags_reset`,
`cdisasm_decode_flags_set_bit`, `cdisasm_decode_flags_clear_bit`, and
`cdisasm_decode_flags_test_bit` helpers operate across the complete 0--511
range; the set/clear helpers return zero for a NULL object or an out-of-range
logical ID, and test returns zero for either case. The in-memory words use the
host's ordinary `uint64_t` representation; this object is an ABI parameter, not
a byte-stream serialization format.

The facade examines only `CDISASM_CPU_GROUP_OF(cpu_id)`. In a build with
`USE_ARCH_X86=1`, the x86 group forwards to `cdisasm_x86_decode`; in a build
with `USE_ARCH_ARM=1`, the ARM group forwards to `cdisasm_arm_decode`. The
architecture decoder then validates the complete CPU ID, its mode, every flags
bitmap word,
input, and encoding and applies its normal result-initialization contract.
The facade forwards the pointer unchanged; `NULL` means that every bitmap word
is zero and therefore selects the architecture's base/default policy.
`cdisasm_x86_decode_flags` and `cdisasm_arm_decode_flags` alias the same common
layout, but each decoder validates an independent architecture-specific known
mask. Callers must choose logical IDs and bitmap-0 masks from the same
architecture as `cpu_id`: logical bit 0 means
`CDISASM_X86_DECODE_BIT_FPU` for x86 but
`CDISASM_ARM_DECODE_BIT_BIG_ENDIAN` for ARM. The legacy
`cdisasm_decode_option`, `cdisasm_x86_decode_option`, and
`cdisasm_arm_decode_option` typedefs remain aliases of one 64-bit bitmap word;
they are not decoder argument types in version 12.

`cdisasm_cpu_decode_flag_mask` applies the same CPU-group dispatch to the
architecture query. It requires a non-NULL output, clears the complete object
first, and returns `CDISASM_STATUS_INVALID_ARGUMENT` for an unknown or disabled
group, invalid CPU, invalid architecture-specific mode, or unavailable
CPU/mode pairing. On success, x86 returns its usable non-base family set; ARM
returns BIG_ENDIAN for every supported pair and additionally returns
IN_IT_BLOCK for T32. The explicit x86 and ARM query functions provide
identical behavior with typed output pointers.

The caller must provide the result type selected by the CPU group:

| CPU group | Mode constants | Result object | Delegated function |
| --- | --- | --- | --- |
| `CDISASM_CPU_GROUP_X86` | `CDISASM_MODE_16`, `_32`, or `_64` | `cdisasm_instruction` (also `cdisasm_x86_instruction`) | `cdisasm_x86_decode` |
| `CDISASM_CPU_GROUP_ARM` | `CDISASM_ARM_MODE_A32`, `_T32`, or `_A64` | `cdisasm_arm_instruction` | `cdisasm_arm_decode` |

For example:

```c
#include <cdisasm/cdisasm.h>

cdisasm_instruction x86_result;
uint32_t x86_size = cdisasm_decode(
    CDISASM_CPU_80386, CDISASM_MODE_32,
    x86_code, x86_code_size, x86_address,
    NULL, &x86_result);

cdisasm_arm_instruction arm_result;
uint32_t arm_size = cdisasm_decode(
    CDISASM_ARM_CPU_CORTEX_A53, CDISASM_ARM_MODE_A64,
    arm_code, arm_code_size, arm_address,
    NULL, &arm_result);

cdisasm_decode_flags available = CDISASM_DECODE_FLAGS_NONE_INITIALIZER;
cdisasm_status query_status = cdisasm_cpu_decode_flag_mask(
    CDISASM_CPU_80386, CDISASM_MODE_32, &available);
```

An unknown CPU group, or a known group whose `USE_ARCH_*` option is zero,
returns zero without accessing or modifying `instruction`. No status is written
in this undispatched case because the facade cannot assume an architecture
result layout. This differs from a forwarded call that fails validation: the
selected decoder initializes its correctly typed result and records its normal
`last_error_id`. Passing an ARM result for an x86 CPU ID, or the reverse, is a
caller error and can overwrite an object whose layout is too small.

New generic code should use the checked companion API:

```c
size_t required = cdisasm_instruction_size(cpu_id);
uint32_t decoded = cdisasm_decode_checked(
    cpu_id, mode, code, code_size, address, flags,
    &result, sizeof(result));
```

`cdisasm_instruction_size` returns `sizeof(cdisasm_instruction)` for an enabled
x86 group, `sizeof(cdisasm_arm_instruction)` for an enabled ARM group, and zero
for an unknown or disabled group. `cdisasm_decode_checked` requires a non-NULL
result pointer and an exact size match; on a mismatch it returns zero without
accessing the object. Exact rather than minimum size catches an ARM object
passed for x86 even on platforms where a larger allocation would otherwise
hide the mistake. The unchecked `cdisasm_decode` remains available, but
callers using an older ABI must rebuild for the version-12 flags-pointer
parameters.
Architecture-specific callers can avoid `void *` entirely by using the typed
decoder entry points. A size-valid checked call applies the selected decoder's
same complete decode-flags validation as `cdisasm_decode`.

### CPU ID namespaces

Version 6 CPU profile IDs use a shared 32-bit layout. The upper 16 bits are an
architecture group and the lower 16 bits are a stable, architecture-local
ordinal. `cdisasm_common.h` publishes both fields and their extraction helpers:

| Field or architecture | Public define | Value |
| --- | --- | ---: |
| Group field | `CDISASM_CPU_GROUP_MASK` | `0xffff0000` |
| Ordinal field | `CDISASM_CPU_ORDINAL_MASK` | `0x0000ffff` |
| x86 | `CDISASM_CPU_GROUP_X86` | `0x00010000` |
| ARM | `CDISASM_CPU_GROUP_ARM` | `0x00020000` |

Every public profile is defined as `group | ordinal`. Ordinal zero is reserved
for that architecture's unrestricted decoder profile, so it still carries an
architecture group:

| Profile | Definition | Full ID |
| --- | --- | ---: |
| No detected profile | `CDISASM_CPU_UNKNOWN` | `0x00000000` |
| x86 unrestricted | `CDISASM_CPU_X86 = CDISASM_CPU_GROUP_X86 \| 0x0000` | `0x00010000` |
| x86 8086 | `CDISASM_CPU_8086 = CDISASM_CPU_GROUP_X86 \| 0x0001` | `0x00010001` |
| x86 80386 | `CDISASM_CPU_80386 = CDISASM_CPU_GROUP_X86 \| 0x0004` | `0x00010004` |
| ARM unrestricted | `CDISASM_ARM_CPU_ANY = CDISASM_CPU_GROUP_ARM \| 0x0000` | `0x00020000` |
| ARM ARM7TDMI | `CDISASM_ARM_CPU_ARM7TDMI = CDISASM_CPU_GROUP_ARM \| 0x0001` | `0x00020001` |
| ARM Cortex-A32 | `CDISASM_ARM_CPU_CORTEX_A32 = CDISASM_CPU_GROUP_ARM \| 0x0004` | `0x00020004` |

`CDISASM_CPU_GROUP_OF(cpu_id)` and `CDISASM_CPU_ORDINAL_OF(cpu_id)` extract the
two fields. A decoder accepts only IDs from its own group and rejects legacy
raw ordinals, IDs from the other architecture, and unknown ordinals with
`CDISASM_STATUS_INVALID_ARGUMENT`; ARM mode-mask queries return
`CDISASM_ARM_MODE_MASK_NONE` for them. Relational comparisons, where explicitly
documented, are meaningful only between IDs in the same architecture group.

### Current CPU profile query

```c
cdisasm_cpu_id cpu_id = cdisasm_current_cpu();
```

`cdisasm_current_cpu()` performs a best-effort runtime query and returns the
closest named cdisasm catalog profile for the instruction environment visible
to the calling process. `CDISASM_CPU_UNKNOWN` is numeric zero and has no
architecture group; it is returned when the enabled build cannot establish a
reliable catalog match. The function never returns the unrestricted ordinal-
zero profiles `CDISASM_CPU_X86` or `CDISASM_ARM_CPU_ANY`.

This function has no decoder side effects. It does not select an architecture,
execution mode, byte order, or optional opcode-family bitmap, and it does not
change a later `cdisasm_decode` call. A caller that intentionally analyzes code
for the local environment passes the returned ID explicitly to the relevant
mode/flag query and decoder. A caller analyzing a dump, executable, or firmware
image for another machine should select that target's catalog profile directly.

The returned ID is a compatibility profile, not a guarantee of a retail CPU
name or of current instruction executability. A hypervisor can mask or
synthesize CPUID, a virtual machine can expose an older virtual CPU, and an OS
or compatibility environment can withhold required register state. Privilege,
control-register state, x86 XSAVE/XCR0 state, ARM streaming/vector state, and
similar execution conditions remain outside this stateless profile query.

ARM model identification is more constrained than x86 CPUID identification.
On Linux, cdisasm uses kernel-exposed per-CPU `MIDR_EL1` evidence when it is
available. Heterogeneous cores, restricted or absent sysfs data, and unknown
implementer/part values can make that evidence ambiguous. On Darwin, numeric
`sysctl` CPU-family evidence and available processor-brand information are
best effort; the family values are discrete identifiers, not an ordered
feature scale, and an older library cannot recognize every future Apple CPU.
Legacy Cortex-A8/A9 Darwin families map to Apple A4/A5, while the legacy
Cortex-A7 family remains the generic Cortex-A7 profile. Apple S-series IDs are
returned only from a validated `Apple S#` brand because the public family
values do not distinguish them.
For a family shared by A-series and M-series products, an unavailable brand
produces the conservative A-series compatibility profile so M-series-only
Apple AMX is not inferred. Other unresolved cases return
`CDISASM_CPU_UNKNOWN` rather than implicitly choosing an unrestricted generic
profile.

### x86 decoder internals

Opcode selection is data-driven. Five dense 256-entry descriptor tables cover
the primary byte, `0F`, `0F38`, `0F3A`, and the final 3DNow! selector. Three
additional per-map legacy-SIMD tables select implemented variants by opcode and
mandatory-prefix class. Numeric descriptor arrays separately cover the 60 NDS
map-1 VEX forms, other modern VEX forms, AMD XOP/FMA4, the classic VEX K-mask
family, EVEX/AVX10/AMX, APX REX2 and NDD/NF forms, modern system routes, and
the collision-sensitive `0F38` CET stores. Each descriptor contains only
numeric IDs, structural decode-form information, form-specific arguments, and
invariant semantic groups. CPU capability requirements are deliberately absent
from these tables: handlers accumulate requirements, aliases select their
effective mnemonic, and `decode_core` performs the single availability check
only after every required encoding byte has been consumed.
Structural form recognizers remain available in an extra-opcode-OFF build so
controlled encodings can still be fully consumed and classified as unsupported,
invalid, or truncated. Successful optional semantic paths remain available only
with `USE_EXTRA_OPCODES=1`.

The optional generated x86 fallback contains 10,994 pinned descriptors and
9,001 exact IFORM identities. It is consulted only after the hand decoder
returns `CDISASM_STATUS_UNSUPPORTED_INSTRUCTION`; a hand-decoder
`INVALID_INSTRUCTION` result has precedence. Generated matching supplies
structured operands and exact ISA-set admission, but the compact upstream
export does not encode every late register-relation, legacy-prefix, or
execution-state validity rule. Those limitations are tracked as semantic
coverage gaps rather than described as missing catalog entries.

Decoder behavior is also recorded in the checked-in, tab-separated
`tests/data/x86_opcodes.tsv` corpus. Each row supplies CPU profile, mode,
address, expected status and size, exact Intel and AT&T text oracles, and
bytes. The runner additionally sweeps all 65,536 two-byte input values in every
mode and formats each successful result in both syntaxes. The
`cdisasm_opcode_corpus_tests` CTest target reads this file at runtime, so adding
a row extends coverage without adding test control flow. The opt-in
`cdisasm_decode_fuzzer` target uses the seeds in `fuzz/corpus` and checks the
same public result and x86 formatter contracts under libFuzzer mutations. The
parallel `cdisasm_arm_decode_fuzzer` target uses `fuzz/arm_corpus` to exercise
all ARM CPU/state pairs, both input byte orders, both T32 widths, truncation
boundaries, numeric result invariants, and ARM formatter
size/write/truncation contracts. The ARM data-corpus runner likewise converts
every successful little-endian row and requires identical big-endian metadata.
Ignoring blank and comment lines, the current checked-in totals are exactly
5,126 x86 rows and 3,541 ARM rows. The x86 source fuzz corpus contains 2,395
reviewed `.hex` seeds, the ARM source fuzz corpus contains 1,679, and neither
directory contains non-hex files. The seed inventories independently reach
all four classic-VEX `VCOMISD`/`VCOMISS` forms, all six classic-VEX
`VDPPD`/`VDPPS` forms, all 12 classic-VEX
`VCMPPD`/`VCMPPS`/`VCMPSD`/`VCMPSS` forms, all four classic-VEX `VPTEST`
forms, both classic-VEX `VPMOVMSKB` forms, all
12 classic-VEX `VPSIGNB/W/D` forms, all 12 classic-VEX `VPSHUFD/HW/LW`
forms, all 32 classic-VEX integer `VPUNPCK*` forms, all 24 classic-VEX
`VPHADD*`/`VPHSUB*` forms, both classic-VEX `VPHMINPOSUW` forms, all eight
classic-VEX `VPINSRB/D/Q/W`, all nine `VPEXTRB/D/Q/W`, and all 24
`VPMOVSXBW/BD/BQ/WD/WQ/DQ` forms, all 24
`VPMOVZXBW/BD/BQ/WD/WQ/DQ` forms, both
scalar/vector Advanced SIMD `ADDP`, Advanced SIMD `ADDV`, `CMTST`, and
`SSHL`/`USHL` forms, fixed-vector `SABA`/`UABA` and `SABD`/`UABD`, all
fixed-vector and by-element `MLA`/`MLS` forms, all six indexed-SVE
`MLA`/`MLS` forms, all six indexed-SVE `SQRDMLAH`/`SQRDMLSH` forms, the
complete widening
by-element `SMLAL`/`SQDMLAL`/`SMLSL`/`SQDMLSL`/`SMULL`/`SQDMULL`/
`UMLAL`/`UMLSL`/`UMULL` block, all four scalar/vector compare-with-zero
	`CMLT`/`CMLE` forms, the complete VEX/EVEX packed MIN/MAX and GFNI families,
	all 30 fixed-width SHA1/SHA256 leaves, and the fixed A64 crypto block
	6287--6303,
and all five fixed-vector Advanced SIMD `CMGT`/`CMGE`/`CMHI`/`CMHS`/`CMEQ`
leaves, including their reserved, sibling, profile, transport, formatting,
and extras-OFF boundaries.
They also
reach
valid and reserved paths in the packed-integer EVEX compare-to-mask/MIN/MAX/multiply/
modular-ADD-SUB/logical/average parsers, their exact APX P0.B4 routes, both VEX
and EVEX saturating ADD/SUB paths, the VEX/EVEX dword/qword and EVEX word
variable-shift classes, the EVEX dword/qword variable and immediate
packed-rotate classes, the opcode-`72` immediate packed-shift class, their exact
APX routes, the opcode-`71`/`73` immediate packed-shift groups, the AVX512VBMI2
map-2/map-3 double-shift class, COMPRESS/EXPAND, BITALG/VPOPCNT, all six
AVX-512CD names, the four AVX-512 VNNI dot products, the Knights Mill
AVX512_4VNNIW pair, the complete AVX512_4FMAPS family, the exact
AVX512F/AVX10.1 VGETEXP PS/PD/SS/SD tranche, the exact MAP6
`VGETEXPPH`/`VGETEXPSH`/`VGETEXPBF16` forms, the classic AVX512_VBMI
byte-permute/multishift and AVX512BW/AVX10 word-permute slices, all four ACE_1
`TILEMOVROW`/`TILEMOVCOL` GPR32/IMM8 forms, all ten ACE TOP2/TOP4 forms, the
legacy and APX-F RAO-INT rows, the complete ACE BSR state family with public
`BSR0`, every legacy/VEX `USER_MSR` and EVEX `APX_F_USER_MSR`
`URDMSR`/`UWRMSR` route, all eleven Key Locker IFORMs and their AES-NI
collision boundary, the HRESET/CLDEMOTE/CLZERO/PCONFIG/PBNDKB/PREFETCHIT,
MONITORX/MWAITX/MCOMMIT, AMD_INVLPGB, SNP, MSRLIST, MSR_IMM, WRMSRNS,
RDPRU, PREFETCHRST2, and PREFETCHWT1
exact system slices,
the exact PTWRITE register/memory pair, MOVNTI memory/GPR pair, complete
legacy/VEX/EVEX non-temporal SIMD store cluster and its legacy collision
siblings, and fixed SMAP `CLAC`/`STAC` pair including its FRED and REX2
collision boundaries,
the exact scalar VEX/EVEX `VMOVSD` and `VMOVSS` families, exact EVEX
`VMOVSH`, exact VEX/EVEX `VMOVSHDUP`/`VMOVSLDUP`, packed unaligned
`VMOVUPD`/`VMOVUPS`, exact EVEX map-5 `VMOVW`, VEX/EVEX `VMPSADBW`, and
VMX/SVM/VTX virtualization forms 5997--6005/6048--6053, `VMULBF16` forms
6006--6011,
`VMULPH` forms 6022--6027, `VMULSH` forms 6042--6043, and all 28 classic
`VMULPD`/`VMULPS`/`VMULSD`/`VMULSS` forms 6012--6021, 6028--6041, and
6044--6047, all twenty `VORPD`/`VORPS` forms 6054--6073, all twelve
`VP2INTERSECTD/Q` forms 6074--6085, all 36 `VPABSB/D/Q/W` forms
6088--6123, all 40 `VPACKSSDW/SSWB/USDW/USWB` forms 6124--6163, all
eight `VPBLENDD`/`VPBLENDW` forms 6306--6309/6338--6341, all four exact
`VPBLENDVB` forms 6334--6337, all eight exact `VPBROADCASTB/W` forms
6342/6343/6347/6348/6387/6388/6392/6393, all eight exact
`VPBROADCASTD/Q` forms 6355/6356/6360/6361/6374/6375/6379/6380, all six exact `VPCMOV` forms
6410--6415, all four exact VEX `VPCMPEQQ` forms 6454--6457, all eight exact
VEX `VBLENDPD`/`VBLENDPS` forms 3527--3534, all eight exact VEX
`VBLENDVPD`/`VBLENDVPS` forms 3535--3542, `VBROADCASTF128` form 3543,
`VBROADCASTI128` form 3554, all six VEX `VBROADCASTSD`/`VBROADCASTSS` forms
3569--3570/3573--3574/3579--3580, all eight VEX
`VEXTRACTF128`/`VEXTRACTI128`/`VINSERTF128`/`VINSERTI128` forms
4539--4540/4553--4554/5551--5552/5565--5566, all four VEX
`VEXTRACTPS`/`VINSERTPS` forms 4567/4569/5579--5580, all four VEX
`VPERM2F128`/`VPERM2I128` forms 6770--6773, all four VEX
`VPERMD`/`VPERMPS` forms 6780--6781/6886--6887, and all three
exact `VPPERM` forms 7686--7688 on x86; and, on ARM,
SVE predicate-logical,
unpredicated/destructive-predicated integer-arithmetic, scalable vector-permute,
integer vector-compare, integer compare-with-immediate, floating
compare-with-zero, floating vector-compare, predicated-unary,
predicated-vector-shift,
predicated-immediate-shift, predicated merging shift/saturating-round forms
2657--2668, predicated integer-unary forms 2669--2676, predicated
accumulating-long and halving arithmetic forms 2677--2686, predicated pairwise
arithmetic forms 2687--2692, predicated saturating arithmetic forms
2693--2700, destructive unpredicated `SCLAMP`/`UCLAMP` forms 2701--2702,
`.D` pointer multiply-add transform `MLAPT`/`MADPT` forms 2707--2708 and
B/H/S/D quad-permute `ZIPQ1`/`UZPQ1`/`ZIPQ2`/`UZPQ2` forms
2711--2712/2714--2715,
destructive predicated
FP-binary, FP fast- and
serial-reduction, predicated FP-unary, baseline merging `FCVT`/`FCVTZS`/
`FCVTZU`, merging `BFCVT`/`BFCVTNT`, zeroing `BFCVT`/`BFCVTNT`, exact
indexed `DUP`/preferred `MOV`, the FP8 four-form narrowing row, the exact
SME2 pair-conversion, unpack, and FP8-widening rows through form 4334, the
complete SME2 four-vector block 4341--4362, the SME `FMUL`/`BFMUL` block
4363--4370, the baseline-SME predicated ZA-slice `MOVA` forms
3862--3866/3877--3881, the SME2 multi-register `MOVA` forms
3867--3876/3882--3891, the SME2.1 `MOVAZ` forms 3892--3906, the baseline-SME
ZA load/store forms 4381--4382, the SME2 ZT0 load/store forms 4383--4384,
baseline A64 UDF form
4387, FEAT_WFxT forms 4457--4458, FEAT_FlagM/FlagM2 forms
4499--4501/5696--5698, the five FEAT_SVE first-fault-register forms
2562--2564/2617--2618, all 18 non-saturating SVE element-count forms
2374--2391, all predicate-break forms 2546--2555, `PSEL` form 2565, the
wide-immediate arithmetic and preferred `MOV`/`FMOV` forms 2619--2632, exact
unpredicated `SDOT`/`UDOT` forms 2633--2636 and complex/widening multiply-add
forms 2637--2641, plus widening/rounding-high multiply-add forms 2642--2655,
exact I8MM `USDOT` form 2656, exact SVE2/SME merging variable shift forms
2657--2668, exact indexed SVE2/SME `MLA`/`MLS` forms 2722--2727, exact
indexed I8MM `USDOT`/`SUDOT` forms 2734--2735, SVE
`AESMC`/`AESIMC` forms 2903--2904, and SVE `AESE`/`AESD`/`SM4E` forms
2905--2907, plus SVE `PUNPKLO`/`PUNPKHI` forms 2468--2469 and SVE/SME
`SUNPKLO`/`SUNPKHI`/`UUNPKLO`/`UUNPKHI` forms 2456--2459, SVE2/SME
`SRI`/`SLI` forms 2846--2847, Advanced SIMD `BSL`/`BIT`/`BIF` forms
6188/6196/6198, Advanced SIMD high-narrow `ADDHN`/`SUBHN`/`RADDHN`/`RSUBHN`
forms 6093/6095/6108/6110, Advanced SIMD widening add/sub forms
6089--6092/6104--6107, Advanced SIMD absolute-difference-long forms
6094/6096/6109/6111, FEAT_PAuth authenticated register branches
4510/4511/4513/4514/4525--4528, and SVE BitPerm `BEXT`/`BDEP`/`BGRP` forms
2829--2831,
the
single, paired, and counter-predicate WHILE relations, and
`PEXT`/counter-predicate `PTRUE`, baseline `PTEST`/`PFIRST`/`PNEXT`/
`PTRUE`/`PTRUES`/`PFALSE`, and the
SVE2.1-or-SME2 `SQCVTN`/`SQCVTUN`/`UQCVTN` multi-extract row, SME2
two-vector `FRINTN`/`FRINTP`/`FRINTM`/`FRINTA`, and SME_F16F16
`FCVT`/`FCVTL`, SVE/SME vector-length arithmetic and integer
reductions, Advanced SIMD reversal and `CLS`/`CNT`/`CLZ`, unpredicated
SVE/SME FP-estimate,
fixed-width Advanced SIMD FP-estimate, and fixed-width Advanced SIMD
vector-permute parsers, plus T32 DCPS and valid and selector-14-adjacent paths in the SVE table-lookup
parser and the disjoint `TBLQ` path. Focused suites and data-corpus cases
separately lock selector 15 as invalid and exhaust all 131,072 valid `TBLQ`
words.
Earlier seed increments are twelve HRESET, six CLDEMOTE, ten CLZERO, ten
PCONFIG/PCONFIG64, ten MONITORX/MWAITX/MCOMMIT, twelve AMD_INVLPGB/SNP,
fifteen MSRLIST/MSR_IMM, and eight PBNDKB/PREFETCHIT x86 files, plus six
Advanced SIMD bit-count, eight SME FMUL/BFMUL, five SME ZA load/store, four
SME2 ZT0 load/store, four A64 UDF, five A64 WFxT, and eleven baseline-SME
predicated MOVA ARM files. They independently reach
allocated forms, reserved or collision neighbors, profile/runtime gates,
REX2/APX where applicable, formatting, and truncation.
That historical seed tranche includes five RDPRU x86 seeds, fourteen
PREFETCHRST2/PREFETCHWT1 x86 seeds, seventeen PTWRITE x86 seeds, five MOVNTI
x86 seeds, 25 non-temporal SIMD-store x86 seeds, twenty-two SME2
multi-register MOVA ARM seeds, seventeen SME2.1 MOVAZ ARM seeds, ten
FlagM/FlagM2 ARM seeds, eight SMAP x86 seeds, and ten
SVE FFR ARM seeds, plus 20 non-saturating SVE element-count ARM seeds,
12 MOVNTDQA/VMOVNTDQA x86 seeds, 20 saturating/predicate-count ARM seeds,
14 LDDQU/VLDDQU x86 seeds, six FIRSTP/LASTP ARM seeds, 29 VMOVSS x86 seeds,
40 VMOVSH/VMOVSHDUP/VMOVSLDUP x86 seeds, 28 VMOVUPD/VMOVUPS x86 seeds, 20
VMOVW x86 seeds, eight counter-WHILE ARM seeds, eight PEXT/PTRUE ARM seeds,
14 predicate-break
ARM seeds, 15 predicate-control ARM seeds, 15 PSEL ARM seeds, 25 VMPSADBW x86
seeds, 22 SVE integer-immediate arithmetic ARM seeds, 15 SVE DUP/FDUP
immediate-broadcast ARM seeds, 27 virtualization x86 seeds, 23 VMULBF16 x86
seeds, 42 VMULPH/VMULSH x86 seeds, 40 classic VMUL x86 seeds, 12 SVE
dot-product ARM seeds, 17 SVE complex/widening multiply-add ARM seeds, 18 SVE
widening/rounding-high multiply-add ARM seeds, three USDOT ARM seeds, and five
predicated shift/saturating-round ARM seeds, plus 16 VPBLEND x86 seeds, six
SCLAMP/UCLAMP ARM seeds, 16 VPCMOV x86 seeds, seven MLAPT/MADPT ARM seeds,
16 VPPERM x86 seeds, eight ZIPQ1/UZPQ1 ARM seeds, 18 VPBLENDVB x86 seeds,
four ZIPQ2/UZPQ2 ARM seeds, 36 VPBROADCASTB/W x86 seeds, 36
VPBROADCASTD/Q x86 seeds, eight indexed-dot ARM seeds, six SVE AES-unary ARM
seeds, nine SVE crypto-binary ARM seeds, 16 VPCMPEQQ x86 seeds, and four SVE
predicate-unpack ARM seeds, plus 16 VBLENDPD/VBLENDPS x86 seeds, nine
SVE/SME vector-unpack ARM seeds, 23 VBLENDVPD/VBLENDVPS x86 seeds, ten
SVE2/SME SRI/SLI ARM seeds, 18 VBROADCASTF128/VBROADCASTI128 x86 seeds,
seven Advanced SIMD BSL/BIT/BIF ARM seeds, 18 VBROADCASTSD/VBROADCASTSS x86
seeds, 14 VEX 128-bit lane insert/extract x86 seeds, eleven Advanced SIMD
high-narrow ARM seeds, eight SVE BitPerm BEXT/BDEP/BGRP ARM seeds, 15 VEX
VEXTRACTPS/VINSERTPS x86 seeds, eleven PAuth register-branch ARM seeds, 15
VPERM2F128/VPERM2I128 x86 seeds, 15 VPERMD/VPERMPS x86 seeds, 13 Advanced
SIMD widening add/sub ARM seeds, and eight Advanced SIMD absolute-difference-
long ARM seeds, plus 21 VDPP x86 seeds and ten total Advanced SIMD ADDV ARM
seeds.
The
prefetch set includes the three review-driven REX2 NOP, PREFETCH, and PREFETCHW
collision routes. Matching data-corpus additions are 12 RDPRU rows, 20
PREFETCHRST2/PREFETCHWT1 rows, 35 PTWRITE rows, 24 MOVNTI rows, 32
non-temporal SIMD-store rows, 26 SME2 MOVA rows, 20 MOVAZ rows, 13
FlagM/FlagM2 rows, 17 SMAP rows, 16 SVE FFR rows, and 25 SVE element-count
rows, plus 24 MOVNTDQA/VMOVNTDQA rows, 75 saturating/predicate-count rows,
23 LDDQU/VLDDQU rows, 12 FIRSTP/LASTP rows, 16 CTERMEQ/CTERMNE rows, 34 VMOVSS
rows, 69 VMOVSH/VMOVSHDUP/VMOVSLDUP rows, 63 VMOVUPD/VMOVUPS rows, 38 VMOVW
rows, 22 counter-WHILE rows, 24 PEXT/PTRUE rows, 23 predicate-break rows, and 33
predicate-control rows, plus 18 PSEL rows, 51 VMPSADBW rows, 30 SVE
integer-immediate arithmetic rows, 14 DUP/FDUP rows, 64 virtualization rows,
37 VMULBF16 rows, 59 VMULPH/VMULSH rows, 59 classic VMUL rows, 19 SVE
dot-product rows, 31 SVE complex/widening multiply-add rows, 32 SVE
widening/rounding-high multiply-add rows, 11 USDOT rows, and 23 predicated
shift/saturating-round rows, plus 30 VPBLEND rows, 15 SCLAMP/UCLAMP rows,
25 VPCMOV rows, 15 MLAPT/MADPT rows, 27 VPPERM rows, 17 ZIPQ1/UZPQ1 rows,
34 VPBLENDVB rows, 14 ZIPQ2/UZPQ2 rows, 62 VPBROADCASTB/W rows, 62
VPBROADCASTD/Q rows, 18 indexed-dot rows, 13 SVE AES-unary rows, 19 SVE
crypto-binary rows, 30 VPCMPEQQ rows, 12 SVE predicate-unpack rows, 32
VBLENDPD/VBLENDPS rows, 22 SVE/SME vector-unpack rows, 38
VBLENDVPD/VBLENDVPS rows, 21 SVE2/SME SRI/SLI rows, 39
VBROADCASTF128/VBROADCASTI128 rows, 18 Advanced SIMD BSL/BIT/BIF rows, 41
VBROADCASTSD/VBROADCASTSS rows, 23 VEX 128-bit lane insert/extract rows, 22
Advanced SIMD high-narrow rows, 24 SVE BitPerm BEXT/BDEP/BGRP rows, 24 VEX
VEXTRACTPS/VINSERTPS rows, 23 PAuth register-branch rows, 23
VPERM2F128/VPERM2I128 rows, 25 VPERMD/VPERMPS rows, 34 Advanced SIMD widening
add/sub rows, 22 Advanced SIMD absolute-difference-long rows, 39 VDPP rows,
and 13 total Advanced SIMD ADDV family rows; they
cover exact family gates, profile boundaries, reserved/collision controls,
canonical formatting, endian transport where applicable, and truncation.
`cdisasm_fuzz_corpus_seed_tests` audits this contract without requiring
libFuzzer: source entries must be comment-free whitespace-separated hex,
normalize to no more than 64 bytes, and remain within the documented raw-input
caps of 192 bytes for x86 and 64 bytes for ARM.
A separate VMOVQ tranche contributes 50 x86 corpus rows and 25 reviewed
`x86_vmovq*.hex` seeds. They cover all 13 pinned forms, VEX/EVEX and
GPR/XMM/memory directions, every mode, extended registers, APX B4/U0 address
promotion, disp8 scaling, Knights Mill, W0/non-long `VMOVD` collisions,
reserved controls, exact collision-profile precedence, formatting, truncation,
and extras-OFF ownership. Its fuzz
invariant locks exact form, width, access, family selection, and collision
identity; bounded pinned-XED comparison found no mismatch in the complete
allocation and adjacent-control sweeps.
A separate VMOVRS tranche contributes 38 x86 corpus rows and 25 reviewed
`x86_vmovrs*.hex` seeds. It covers all twelve byte/dword/qword/word forms,
three vector widths, mask merge/zero, memory-only controls, width-specific
AVX10 MOVRS admission, 16/32/64-byte disp8 scaling, APX B4/X4 addressing,
reserved controls, formatting, truncation, and extras-OFF ownership.
A separate VMOVSD tranche contributes 34 x86 corpus rows and 29 reviewed
`x86_vmovsd_*.hex` seeds. It covers all seven VEX/EVEX forms, both opcode
directions, all modes, masks, LL/W behavior, vector extensions, scalar disp8,
APX B4/X4 routes, feature/profile/runtime gates, legacy and adjacent move
collisions, malformed controls, formatting, truncation, and extras-OFF
ownership.
A separate scalar-half/duplicate-move tranche contributes 69 x86 corpus rows
and 40 reviewed `x86_vmovsh*.hex`, `x86_vmovshdup*.hex`,
`x86_vmovsldup*.hex`, and shared-control `x86_vmovdup*.hex` seeds. It covers
all 23 exact forms, VEX/EVEX and 128/256/512-bit duplicate widths,
memory/register directions, scalar-half store/load/register shapes,
merge/zero masks, two- and 16/32/64-byte compressed disp8, APX B4/X4,
non-long extension rules, profile/runtime gates, legacy and mandatory-prefix
collisions, reserved controls, formatting, truncation, and extras-OFF
ownership.
A separate VMOVSS tranche contributes 34 x86 corpus rows and 29 reviewed
`x86_vmovss_*.hex` seeds. It covers all seven VEX/EVEX forms, both opcode
directions, PF3/W0 selection, all modes, masks, dword memory, four-byte
compressed disp8, APX B4/X4 routes, AVX versus `AVX512F_SCALAR` gates,
legacy/neighbor collisions, malformed controls, formatting, truncation, and
extras-OFF ownership.
A separate packed-unaligned-move tranche contributes 63 x86 corpus rows and
28 reviewed `x86_vmovupd_*.hex`/`x86_vmovups_*.hex` seeds. It covers all 34
forms 5946--5979, VEX and EVEX, both opcode directions, every allocated vector
width, register/full-memory operands, masks, store-zeroing rejection,
16/32/64-byte disp8 scaling, APX B4/X4 address promotion, exact runtime and
profile gates, reserved controls, delegated legacy/scalar collisions,
formatting, truncation, and extras-OFF ownership.
A separate VMOVW tranche contributes 38 x86 corpus rows and 20 reviewed
`x86_vmovw_*.hex` seeds. It covers all seven forms 5980--5986 and eight pinned
records, GPR32/XMM and m16/XMM directions, WIG `66` versus F3/W0 selection,
WIG W1, exact `AVX512_FP16_128N` versus `AVX512_MOVZXC_128` runtime/profile
routes, Tuple2 disp8, APX B4/X4, high and non-long registers, 3,046 reserved
P1/P2 controls, delegated map neighbors, formatting, truncation, and
extras-OFF ownership.
A separate VMPSADBW tranche contributes 51 x86 corpus rows and 25 reviewed
`x86_vmpsadbw*.hex` seeds. It covers all ten forms 5987--5996, VEX XMM/YMM
and EVEX XMM/YMM/ZMM, register and Full-tuple memory sources, every imm8,
merge/zero masking, 16/32/64-byte compressed displacements, high registers,
APX B4/X4 addressing, non-long extension rules, exact AVX/AVX2/
AVX512-MEDIAX admission, legacy MPSADBW and VDBPSADBW collisions, reserved
prefix/decorator controls, formatting, truncation, and extras-OFF ownership.
A separate virtualization tranche contributes 64 x86 corpus rows and 27
reviewed `x86_virtualization_*.hex` seeds. It covers exact forms
5997--6005/6048--6053, all pointer/VMREAD/VMWRITE/fixed shapes, every mode and
address-size-sensitive VMRUN, REX/REX2/APX-F transport, exact VMX/SVM/VTX
runtime and profile gates, privilege and status-flag metadata, reserved and
ignored prefixes, neighboring VMCLEAR/EXTRQ/INSERTQ identities, formatting,
truncation, and extras-OFF ownership.
A separate VMULBF16 tranche contributes 37 x86 corpus rows and 23 reviewed
`x86_vmulbf16*.hex` seeds. It covers exact forms 6006--6011, XMM/YMM/ZMM
register and Full-memory sources, BF16 broadcast, merge/zero masking,
16/32/64-byte disp8, high registers, APX B4/U0/X4 ownership, exact
width-specific groups and runtime/profile gates, reserved controls, adjacent
collisions, both syntaxes, truncation, and extras-OFF ownership.
A separate FP16 multiply tranche contributes 59 x86 corpus rows and 42
reviewed `x86_vmulph*.hex`/`x86_vmulsh*.hex`/`x86_vmul_fp16*.hex` seeds. It
covers exact forms 6022--6027 and 6042--6043, packed XMM/YMM/ZMM and scalar
XMM sources, masks, Full and Tuple2 memory, FP16 broadcasts, embedded
rounding plus SAE, 16/32/64- and two-byte disp8 scaling, high registers, APX
B4/U0/X4 ownership, exact width/scalar groups and runtime bits, profile
boundaries, VMULBF16 and unallocated-prefix collisions, reserved controls,
both syntaxes, truncation, and extras-OFF ownership.
A separate classic floating-multiply tranche contributes 59 x86 corpus rows
and 40 reviewed `x86_vmulpd*.hex`/`x86_vmulps*.hex`/`x86_vmulsd*.hex`/
`x86_vmulss*.hex` seeds. It covers all 28 forms 6012--6021, 6028--6041, and
6044--6047; VEX XMM/YMM packed and XMM scalar shapes; EVEX
XMM/YMM/ZMM packed and XMM scalar shapes; register, Full-memory, and scalar
memory sources; merge/zero masking; broadcast; embedded rounding and SAE;
compressed displacement scaling; exact width/scalar runtime and profile
gates; APX address extensions; reserved decorators; family collisions; both
syntaxes; truncation; and extras-OFF ownership. Focused tests separately lock
ordinary EVEX high-register transport.
A separate packed logical-OR tranche contributes 52 x86 corpus rows and 28
reviewed `x86_vorpd_*.hex`/`x86_vorps_*.hex`/`x86_vor_fp_*.hex` seeds. It
covers forms 6054--6073, VEX XMM/YMM and EVEX XMM/YMM/ZMM register/memory
shapes, masks, broadcast, Full-tuple disp8, exact AVX and AVX512DQ/AVX10.1
gates, high registers, APX B4/U0/X4, non-long ignored extensions, reserved
register `EVEX.b`, collisions, formatting, truncation, and extras-OFF
ownership.
A separate VP2INTERSECT tranche contributes 29 x86 corpus rows and 21
reviewed seeds for forms 6074--6085. It covers XMM/YMM/ZMM register and
Full-memory sources, D/Q lane widths, normalized even/odd K destinations,
broadcast, 16/32/64-byte disp8, high registers, APX address extensions, exact
width and Tiger Lake profile gates, reserved controls, both syntaxes,
truncation, and extras-OFF ownership. The focused test exhausts 786,432
controls as 8,064 allocated and 778,368 reserved.
A separate VPABS tranche contributes 82 x86 corpus rows and 60 reviewed
`x86_vpabs*.hex` seeds for forms 6088--6123. It covers every non-linear
pinned-XED identity, VEX/EVEX width, register and memory source, mask
merge/zero, dword/qword broadcast, Full and scalar compressed displacement,
high register, non-long extension alias, APX B4/U0/X4 address, exact feature
and profile route, malformed control, collision, formatting, truncation, and
extras-OFF boundary. The focused test classifies 9,216 allocated plus 580,608
reserved VEX controls and 259,200 allocated plus 527,232 reserved EVEX
controls.
A pair of ARM WHILE tranches contributes 22 rows and eight seeds for the
single-predicate forms 2585--2592, plus 22 rows and eight seeds for the paired
forms 2574--2581. They cover all eight relations, B/H/S/D typing, W/X or X/XZR
sources, typed even/odd pairs, exact SVE/SME, SVE2/SME, and SVE2.1/SME2 gates,
NZCV metadata, endian transport, formatting, truncation, and extras-OFF
ownership.
A counter-WHILE tranche contributes 22 rows and eight seeds for forms
2566--2573. It covers typed `PN8`--`PN15`, X/XZR sources, `VLx2`/`VLx4`, all
eight relations and four element sizes, NZCV metadata, exact SVE2.1-or-SME2
admission, endian transport, formatting, truncation, and extras-OFF ownership.
The adjacent PEXT/PTRUE tranche contributes 24 rows and eight seeds for forms
2582--2584. It covers the untyped indexed `PNn[index]` source, typed one- and
two-predicate PEXT results including `p15, p0` wrap, typed PN PTRUE results,
the same feature alternative, endian transport, formatting, truncation, and
disabled-build ownership.
A predicate-break tranche contributes 23 rows and 14 reviewed
`a64_sve_predicate_break_*.hex`/`a64_sve_brk*.hex` seeds for forms
2546--2555. It covers every BRKP, BRK, and tied-source BRKN shape, `/z` and
the allocated `/m` controls, write versus read/write destinations, all five
NZCV-setting forms, exact SVE-or-SME profile admission, both byte orders,
reserved parent controls, canonical formatting, truncation, and extras-OFF
ownership.
A predicate-control tranche contributes 33 ARM rows and 15 reviewed
predicate-control `.hex` seeds for forms 2556--2561. It covers all
six operations, predicate typing/access, tied PFIRST/PNEXT reads, named and
numeric PTRUE patterns, exact flags and SVE-or-SME gates, all 16,944 reserved
parent controls, both byte orders, formatting, truncation, and extras-OFF
ownership.
A PSEL tranche contributes 18 ARM rows and 15 reviewed
`a64_sve2p1_psel_*.hex` seeds for form 2565. It covers every B/H/S/D lane
boundary, W12--W15, high predicate registers, exact write/read/read access,
the SVE2.1-or-baseline-SME alternative, both `tsz=0000` residuals, the bit-4
neighbor, both byte orders, canonical `Pd, Pn, Pm.T[Wv, lane]` text,
truncation, and extras-OFF ownership.
The adjacent wide-immediate tranche contributes 44 ARM rows and 37 reviewed
seeds: 30 rows and 22 `a64_sve_integer_immediate_*.hex` seeds for arithmetic
forms 2619--2630, then 14 rows and 15 new `a64_sve_dup_immediate_*.hex`/
`a64_sve_fdup_immediate_*.hex` seeds for forms 2631--2632. It covers all
signed, unsigned, shifted, and floating imm8 values; tied arithmetic
destinations; preferred `MOV`/`FMOV`; exact IEEE expansion; SVE-or-SME profile
routes; every reserved byte control; both byte orders; formatting; truncation;
and extras-OFF ownership. Focused tests classify all 2,097,152 parent words;
the dedicated broadcast suite exhausts 57,344 valid plus 8,192 reserved DUP
words and 24,576 valid plus 8,192 reserved FDUP words. LLVM 21 independently
confirms 1,792 representative DUP and 768 FDUP cases.
An adjacent SVE dot-product tranche contributes 19 ARM rows and 12 reviewed
`a64_sve_dot_*.hex`/`a64_sve2p3_dot_*.hex` seeds. It covers forms 2633--2636,
B-to-S and H-to-D baseline widening, B-to-H SVE2p3/SME2p3 widening, the tied
read/write accumulator, read-only sources, full Z-register range, exact
feature/profile boundaries, all 65,536 reserved `size=00` words, endian
transport, formatting, truncation, and extras-OFF ownership. LLVM 21 validates
the baseline forms; pinned AARCHMRS validates the p3 forms.
An adjacent SVE2/SME complex/widening multiply-add tranche contributes 31 ARM
rows and 17 reviewed
`a64_sve_{sqdmlalbt,sqdmlslbt,cdot,cmla,sqrdcmlah}*.hex` seeds. It covers
forms 2637--2641, every legal arrangement and rotation, tied accumulator
access, exact SVE2-or-SME admission, all reserved widths, endian transport,
formatting, truncation, adjacent delegation, and extras-OFF ownership. LLVM 21
validates all 46 legal arrangement/rotation combinations.
An adjacent SVE2/SME widening/rounding-high multiply-add tranche contributes
32 ARM rows and 18 reviewed seeds for forms 2642--2655. It covers all twelve
`SMLAL*`/`SMLSL*`/`UMLAL*`/`UMLSL*`/`SQDMLAL*`/`SQDMLSL*` bottom/top
identities and both `SQRDMLAH`/`SQRDMLSH` identities, H/S/D widening and
B/H/S/D same-width arrangements, tied accumulator access, exact SVE2-or-SME
admission, all reserved widths, endian transport, formatting, truncation,
adjacent delegation, and extras-OFF ownership.
An adjacent indexed SVE2/SME multiply-add tranche contributes 22 ARM rows and
15 reviewed `a64_sve_{mla,mls}_indexed*.hex` seeds for forms 2722--2727. It
covers every H/S/D width, both lane extremes, each width-dependent indexed
source-register limit, exact destructive accumulator access, named-profile
boundaries, both byte orders, generic dispatch, canonical formatting and
forgery rejection, truncation, the adjacent indexed-rounding collision, and
extras-OFF ownership. Its focused suite exhausts all 262,144 allocated words,
and LLVM 21 independently confirms the twelve low/high boundary encodings.
The adjacent indexed SVE2/SME rounding multiply-add/subtract tranche contributes
20 ARM rows and 15 total `a64_sve_sqrdml{ah,sh}_indexed*.hex` family seeds for
forms 2728--2733. It covers every H/S/D width, both lane extremes, each
width-dependent indexed-source-register limit, exact destructive accumulator
access, named-profile boundaries, both byte orders, generic dispatch,
canonical formatting and forgery rejection, truncation, the adjacent indexed
`USDOT` collision, and extras-OFF ownership. Its focused suite exhausts all
262,144 allocated words, and LLVM 21 plus pinned AARCHMRS independently confirm
the six leaf masks and boundary encodings.
The adjacent I8MM dot-product tranche contributes 11 ARM rows and three
reviewed `a64_sve_usdot_*.hex` seeds for form 2656. It covers low and high
registers, tied `Zda.S` read/write access, byte source reads, exact
SVE-or-SME plus I8MM admission, named-profile boundaries, every reserved
size control, fixed-bit neighbors, both byte orders, canonical formatting,
truncation, and extras-OFF ownership.
The adjacent predicated shift/saturating-round tranche contributes 23 ARM rows
and five reviewed `a64_sve_shift_sat_*.hex` seeds for forms 2657--2668. It
covers all twelve signed/unsigned operations, B/H/S/D typing, low/high
registers, tied read/write destinations, merge-predicate and source reads,
exact SVE2-or-SME admission, all four reserved selectors, fixed-bit neighbors,
both byte orders, canonical formatting, truncation, and extras-OFF ownership.
The adjacent predicated integer-unary tranche contributes 21 ARM rows and
nine reviewed `a64_sve_sat_unary_*.hex` seeds for forms 2669--2676. It covers
`.S`-only `URECPE`/`URSQRTE`, B/H/S/D `SQABS`/`SQNEG`, merging and zeroing
access, exact SVE2/SME and SVE2.2/SME2.2 gates, all reserved estimate widths,
both byte orders, formatting, truncation, and extras-OFF ownership.
The adjacent accumulating-long and halving tranche contributes 30 ARM rows
and 16 reviewed seeds for forms 2677--2686. It covers B-to-H, H-to-S, and
S-to-D `SADALP`/`UADALP`; all B/H/S/D arrangements of the eight halving
operations; exact destructive access and predicate granularity; SVE2-or-SME
admission; the 16,384 reserved accumulating-long `size=00` words; endian
transport, formatting, truncation, forgery rejection, and extras-OFF ownership.
The following predicated pairwise tranche contributes 19 ARM rows and eight
reviewed `a64_sve_pairwise_*.hex` seeds for forms 2687--2692. It covers all
six operations and B/H/S/D arrangements, exact destructive access and
predicate typing, SVE2p3-or-SME2p3 `SUBP` versus SVE2-or-SME admission,
65,536 reserved operation-2/3 controls, endian transport, canonical formatting,
truncation, forgery rejection, and extras-OFF ownership. Pinned AARCHMRS is
the complete oracle; LLVM 21 matches the other five SVE2 leaves but does not
yet accept SVE2p3 `SUBP`.
A separate VMOVMSK tranche contributes 21 x86 corpus rows and 12 reviewed
`x86_vmovmsk*.hex` seeds. They cover all four forms, VEX2/VEX3 and WIG,
long-mode extensions, non-long B-ignore, reserved pp/`vvvv`/memory controls,
legacy/REX2, EVEX and map-2 VNNI collisions, both syntaxes, truncation, and
extras-OFF ownership. Its fuzz invariant locks exact form identity, GPR32 write
and XMM/YMM read access, and AVX selection; focused ASan+UBSan campaigns with
extras ON and OFF each replay the complete source corpus and finish 6,000 runs
without a finding.
The version-11.8 word-shift tranche contributes 36 x86 rows and 21 reviewed,
independently reachable one-vector seeds; the predicated-vector-shift tranche
contributes 17 ARM rows and two reviewed seeds. The separate reviewed
`vex_modern_crypto.hex` x86 seed covers the existing vector-crypto decoder path.
The version-11.9 variable-rotate tranche contributes 40 x86 rows and seven
reviewed one-vector seeds; the predicated immediate-shift tranche contributes
18 ARM rows and two reviewed seeds.
The version-11.10 immediate-rotate tranche contributes 43 x86 rows and seven
reviewed one-vector seeds; the SVE integer vector-compare tranche contributes
27 ARM rows and two reviewed seeds.
The version-11.11 immediate-shift tranche contributes 32 x86 rows and six
reviewed seeds; the SVE integer compare-with-immediate tranche contributes 16
ARM rows and three reviewed seeds.
The version-11.12 immediate-shift-group tranche contributes seven x86 rows and
three reviewed seeds; the SVE floating compare-with-zero tranche contributes
14 ARM rows and two reviewed seeds.
The version-11.13 AVX512VBMI2 double-shift tranche contributes 27 x86 rows and
six reviewed seeds; the SVE floating vector-compare tranche contributes 17 ARM
rows and four reviewed seeds.
For the version-11.4 x86 tranche, out-of-tree builds of Intel XED v2026.08.23
and pinned Capstone accepted all 60 legal modular ADD/SUB descriptor shapes;
XED also rejected all 11 reserved controls exercised by the dedicated suite.
Pinned Capstone also accepted all 20 ARM lookup/MOV forms. An exhaustive
adjacent sweep showed that it accepts 54 of the 124 non-MOV selector-14
controls as other instruction classes, which is why cdisasm leaves that whole
residual unowned; it accepted none of the 128 selector-15 controls, matching
cdisasm's exact invalid classifier. These tools are independent comparison
oracles and are neither linked into cdisasm nor used to generate its decoder.
For version 11.5, Intel XED and pinned Capstone each accept all 96 VEX and all
96 EVEX saturating ADD/SUB wire variants, covering the 80 distinct operand
shapes plus W/prefix aliases. XED rejects all 72 focused invalid EVEX words:
48 register/memory EVEX.b controls and eight each for LL=3, U=0, and
zero-without-mask. Capstone rejects 56/72 but accepts the eight LL=3 and eight
zero-without-mask words; cdisasm follows the
architectural/XED legality boundary. Pinned Capstone also accepts all 16 unique
official `TBLQ` reference encodings, and LLVM 21 reproduces the exact B/H/S/D
encodings used by the focused suite. Fixed-bit neighbors can be allocated to
other SVE classes, so only the exact `0xff20fc00/0x4400f800` mask is claimed.
The completed final 11.5 matrix supplements those focused oracle checks: the
full strict top-level CTest passed 43/43. Final Clang 21.1.6 strict fast matrices
passed 39/39 with extra opcodes and formatting enabled, 33/33 with extra opcodes
disabled, and 37/37 with formatting disabled and extra opcodes enabled; MSVC
19.44 Release shared passed 39/39. Installed-package validation passed all 16
shared cells in 1730.31 seconds and all 16 static cells in 1889.55 seconds.
Windows overlay integration passed in 106.92 seconds, and the WSL Unix
`DESTDIR` overlay passed in 73.19 seconds. Refreshed WSL2 Clang 14 ASan+UBSan
libFuzzer campaigns completed 10,000 executions for each x86 and ARM harness
with extra opcodes enabled and 5,000 each with them disabled.

For version 11.6, current Intel XED and pinned Capstone each accept all 648
classic EVEX D/Q logical wire forms and all 216 classic EVEX `VPAVGB/W` wire
forms. XED rejects all 80 logical and all 20 average negative controls;
Capstone rejects 48/80 and 12/20 respectively, accepting the LL=3 and
zero-without-mask controls that cdisasm rejects at the architectural/XED
boundary. XED's Diamond Rapids model accepts the two checked APX P0.B4 controls
for each class; the pinned Capstone snapshot accepts 0/2 in each because it
does not implement those forms. Pinned Capstone independently matches all 74
valid destructive-predicated SVE operation/width pairs and rejects all 54
reserved pairs. It matches exact text for all 42 allocated fixed-width
Advanced SIMD ZIP/UZP/TRN arrangements and rejects all 22 reserved controls.

The completed version-11.6 validation matrix passed 45/45 CTests in a fresh
Clang 21.1.6 strict dual-architecture Release build with extra opcodes and
formatting enabled, including both integration tests. A strict ARM-only build
passed 18/18. Semantic matrices passed 37/37 with extra opcodes disabled and
41/41 with formatting disabled; an MSVC 19.44 Release shared build passed
43/43. The installed static package's external C and C++17 consumer passed
8/8, and Windows package-overlay integration completed in 124.51 seconds.
WSL2 Clang 14 ASan+UBSan libFuzzer campaigns passed 10,000 executions for x86
with extra opcodes ON and 10,000 OFF, plus 10,000 for ARM ON and 5,000 OFF.
Post-campaign replay covered all 797/724 mutated x86 and 321/255 ARM build-local
corpus files.

For version 11.7, Intel XED and pinned Capstone accept all 546/546 canonical
VEX/EVEX variable-shift encodings. XED rejects all 192/192 focused reserved
controls, while Capstone rejects 120/192; cdisasm follows the architectural/XED
legality boundary. XED's Diamond Rapids model also accepts all 162/162 APX
P0.B4 forms and all 216/216 U0 memory forms. Pinned Capstone accepts all 56/56
merge-predicated ARM unary operation/width controls and rejects all 24/24
reserved controls. LLVM 21 accepts all 56/56 zero-predicated controls, rejects
all 24/24 reserved controls, and confirms that `/m` admits either SVE or SME
while `/z` requires SVE2p2 or SME2p2. These are focused independent-oracle
results for the exact new classifiers; neither architecture is exhaustively
covered.

The final version-11.7 Clang 21.1.6 static dual-architecture extras-ON,
format-ON matrix passed 47/47 non-package CTests: 45 semantic tests plus the
21.08-second subproject and 107.11-second overlay integrations, 132.79 seconds
total. The static dual extras-OFF matrix passed 39/39 semantic tests and its
previously completed full run passed 41/41 including integrations. The static
dual format-OFF, extras-ON matrix passed 43/43 semantic tests and its previously
completed full run passed 45/45 including integrations. MSVC 19.44.35224 shared
Release passed 45/45 semantic tests. Installed-package validation passed all 16
shared cells in 1764.07 seconds and all 16 static cells in 1897.99 seconds.

Final WSL2 Clang 14 ASan+UBSan libFuzzer campaigns with extra opcodes ON ran
10,000 executions for x86 (`avg 277/s`, `new 781`, `RSS 112 MB`) and 10,000
for ARM (`avg 555/s`, `new 410`, `RSS 64 MB`); extras-OFF campaigns ran 10,000
for x86 (`avg 384/s`, `new 726`, `RSS 103 MB`) and 10,000 for ARM
(`avg 666/s`, `new 328`, `RSS 58 MB`). Saved regression inputs replayed and
clean reruns passed. Source seed inventories remained unchanged at 115 x86 and
80 ARM files.

For version 11.8, current Intel XED and pinned Capstone each accept all 162/162
canonical EVEX word variable-shift encodings. XED rejects all 513/513 focused
reserved controls, while Capstone rejects 405/513 and accepts 108 `LL=3` or
zero-with-`k0` controls; cdisasm follows the architectural/XED boundary. XED's
Diamond Rapids model accepts all 108/108 enumerated APX P0.B4 and U0/X4 forms,
while pinned Capstone accepts 0/108. Pinned Capstone 6 matches all 33 canonical
allocated ARM vector-shift controls and rejects all 31 canonical reserved
controls. Capstone 5 exhaustively agrees on all 270,336 allocated and 253,952
reserved words, and LLVM 14/21 feature probes confirm exact SVE-or-SME routes.

Final version-11.8 build evidence includes focused extra-opcode ON, OFF, and
formatter-disabled suites. A fresh Clang 21.1.6 Release package build passed
47/47 direct tests and all 2/2 subproject/overlay integrations; an MSVC
19.44.35224 x64 shared Release build passed 47/47 direct tests. Installed
packages passed all 16/16 shared feature-matrix cells in 1693.90 seconds and all
16/16 static cells in 1832.75 seconds. ARM ASan+UBSan libFuzzer campaigns ran
10,000 executions with extra opcodes ON and 5,000 with them OFF. Fresh WSL
Clang 14 ASan+UBSan x86 builds each stage
exactly 137 reviewed seeds (maximum 189 raw bytes). The 21 word-shift files plus
the crypto seed replay 22/22 with extras ON and OFF. Recommended
`-max_len=192` campaigns pass 10,000 executions in 32 and 28 seconds
respectively and retain 135/128 initial corpus entries, confirming that older
long hexadecimal seeds are normalized and reachable. The source corpus
contains no generated non-`.hex` artifact. These results complete the
stable-tree 11.8 package evidence without claiming exhaustive x86 or ARM ISA
coverage.

For version 11.9, Intel XED and pinned Capstone each accept all 324/324
canonical EVEX variable packed-rotate forms. XED rejects all 432/432 reserved
controls; Capstone rejects 216/432 and permissively accepts exactly 108 `LL=3`
and 108 zero-with-`k0` controls. XED's Diamond Rapids model accepts all 396/396
APX forms: 108 P0.B4/U1, 144 U0 no-SIB, and 144 U0/X4 SIB forms. Pinned
Capstone accepts 0/396 of those APX controls. Capstone 5 exhaustively agrees on
all 524,288 words in the A64 predicated immediate-shift classifier: 276,480
allocated and 247,808 reserved. It also matches 1,080/1,080 canonical metadata
probes. LLVM 21 accepts the four baseline operations through SVE alone, all
nine operations through SVE2 or SME, none without a required feature, and
rejects all 23/23 canonical reserved controls.

Version 11.9 native validation passed 49/49 direct semantic CTests with extra
opcodes and formatting enabled, 43/43 with extra opcodes disabled, and 47/47
with formatting disabled. With both CMake integrations, the corresponding
non-package totals are 51/51, 45/45, and 49/49. MSVC 19.44.35224 x64 shared
Release passes 49/49 semantic tests and both integrations. Installed packages
pass all 16/16 shared cells in 1,640.30 seconds and all 16/16 static cells in
1,777.09 seconds. WSL2 Clang 14 ASan+UBSan runs complete 10,000 executions per
architecture in each extra-opcode variant against unchanged 144-file x86 and
84-file ARM source-seed inventories, with no finding.

For version 11.10, Intel XED v2026.08.23 accepts all 324/324 canonical EVEX
immediate packed-rotate controls and rejects all 432/432 reserved EVEX
controls. Pinned Capstone accepts the canonical 324/324 controls and all
82,944 imm8 wire values, but permissively accepts the 108 `LL=3` and 108
zero-with-`k0` controls that cdisasm rejects at the architectural/XED
boundary. XED's Diamond Rapids model accepts all 396/396 enumerated APX
P0.B4/U0/X4 forms; pinned Capstone accepts none. The adjacent opcode-`72`
extension matrix is classified independently: `/2` with W=0, `/4` with either
W value, and `/6` with W=0 are allocated shift instructions outside this
tranche and therefore unsupported; `/2` and `/6` with W=1 plus every
`/3`, `/5`, and `/7` control are reserved and invalid. All consume imm8 before
classification so truncation wins for incomplete input.

For the A64 SVE integer vector-compare classifier, pinned Capstone matches all
64 operation/width controls: 54 allocated and 10 reserved. Extrapolation over
the register and predicate fields gives exact totals of 7,077,888 allocated
and 1,310,720 reserved words. Capstone detail reports flag updates for all 54
allocated controls, and Clang 21 accepts representative ordinary and wide
forms with either `+sve` or `+sme`. These are bounded independent-oracle
checks, not claims of complete x86 or Arm ISA coverage.

For version 11.11, Intel XED v2026.08.23 commit
`0bcb6237345c5066726dcc08b3d87928df3b5b26` and pinned Capstone 6.0.0 commit
`862b59717d54769036f89fd9f780f634e030cf56` accept all 324/324 canonical
EVEX immediate packed-shift controls and all 82,944 imm8 wire values. XED
rejects all 432/432 focused structural-invalid controls. Capstone rejects
216/432, accepting 108 `LL=3` and 108 zero-with-`k0` controls that cdisasm
rejects at the architectural/XED boundary. XED's Diamond Rapids model accepts
all 396/396 APX P0.B4/U0/X4 forms; Capstone accepts 0/396. The exact opcode-`72`
extension/W matrix allocates W0 `/0`, `/1`, `/2`, `/4`, `/6` and W1 `/0`,
`/1`, `/4`; the remaining extension/W controls are reserved.

Pinned Capstone matches all 2,816 legal A64 SVE integer
compare-with-immediate operation/width/immediate combinations: 768 signed and
2,048 unsigned. Clang 21.1.6 confirms that either `+sve` or `+sme` admits the
class, neither feature rejects it, signed immediates are exactly `-16`--`15`,
unsigned immediates are exactly `0`--`127`, and the governing predicate is
restricted to `P0`--`P7`. The focused cdisasm suite exhausts both envelopes:
12,582,912 owned words, of which 11,534,336 are allocated and 1,048,576 are
reserved. These are bounded independent-oracle checks, not claims of complete
x86 or Arm ISA coverage.

The version-11.12 focused suites classify all 32 opcode/W/extension controls
for each opcode-`71`/`73` imm8 value: 3,072 allocated control/immediate pairs
and 20 reserved controls per immediate, with separate feature, mask,
broadcast, truncation, and APX route checks. The ARM suite decodes every one of
the 131,072 words in the floating compare-with-zero classifier and requires
the exact 73,728 allocated/57,344 reserved split, typed operands, canonical
`#0.0` formatting, SVE-or-SME admission, and extras-OFF ownership. These are
bounded classifier checks, not claims of complete x86 or Arm ISA coverage.

The version-11.13 focused x86 suite passes with extra opcodes enabled,
formatting disabled, and extra opcodes disabled. It classifies all 16 EVEX
map/opcode/W controls as 12 allocated and four reserved, visits every imm8 for
the six immediate controls, and locks mask, memory, broadcast, compressed-
displacement, feature, APX, formatter, and truncation behavior. The 1,185-row
corpus and seed audit pass, and all six new seeds replay under libFuzzer. A
final audit adds eight status-precedence regressions for mandatory-`66` EVEX
maps 2/3 opcodes `70`--`73`: forbidden legacy prefixes and non-long-mode APX
P0.B4 defer legality until the owned ModRM/SIB/displacement and applicable
imm8 bytes are consumed. Incomplete forms return `TRUNCATED`; complete forms
return `INVALID_INSTRUCTION`. These checks pass with extras ON, extras OFF,
formatting disabled, and MSVC. The legacy-prefix pairs agree with XED; no XED
parity is claimed for 32-bit B4 because XED rejects at the EVEX prefix. ARM
release validation is complete: strict focused selections pass 20/20 with
extras enabled and 20/20 disabled, the suite exhausts all 4,194,304 words with
the exact 2,752,512/1,441,792 split, and 36/36 canonical controls match pinned
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

Version 11.14 strict Clang dual-architecture direct suites pass 62/62 with
extras and formatting enabled, 57/57 with extras disabled, and 60/60 with
formatting disabled. A Clang-CL `/W4 /WX` shared build passes 62/62. Both
checked-in opcode corpora pass in both extra-opcode variants: 1,221/1,221 x86
and 687/687 ARM rows. The bounded x86 oracle comparison uses Intel XED, and
pinned Capstone matches 42/42 selected ARM controls. Four WSL2 Clang 14
ASan+UBSan libFuzzer campaigns complete 10,000 runs each for x86/ARM × extras
ON/OFF after replaying all 183 x86 and 100 ARM reviewed seeds, with no finding.
Targeted installed shared/static, dispatcher, and ARM-only package consumers
also pass across the applicable formatter and extra-opcode variants.

Version 11.15 strict Clang dual-architecture direct suites pass 64/64 with
extras and formatting enabled, 59/59 with extras disabled, and 62/62 with
formatting disabled. A Clang-CL `/W4 /WX` shared build passes 64/64. The
version-11.15 1,245-row x86 and 701-row ARM corpora pass in the applicable option variants,
and the deterministic seed audit passes all 189/102 source inputs. Intel XED
agrees with the focused AVX-512CD matrix on 140 accepted and 39 rejected inputs;
pinned Capstone agrees with all 262,144 ARM fast-reduction classifications, and
LLVM agrees with the canonical controls. Four fresh WSL2 Clang 14 ASan+UBSan
campaigns complete 10,000 executions each for x86/ARM x extras ON/OFF with no
sanitizer finding. Targeted shared/static package consumers also pass. This is
bounded validation and is not an exhaustive ISA-coverage claim.

Version 11.16 strict Clang dual-architecture direct suites pass 65/65 with
extras and formatting enabled, 60/60 with extras disabled, and 63/63 with
formatting disabled. A Clang-CL `/W4 /WX` shared build passes 65/65. Both
extra-opcode variants pass the complete 1,266-row x86 and 711-row ARM corpora,
and exactly 191/104 reviewed source seeds pass the deterministic audit. Intel
XED agrees with 30/30 focused x86 mask-broadcast controls; pinned Capstone
agrees with every one of 32,768 `FADDA` classifications and LLVM agrees with
the canonical H/S/D boundaries. Four x86/ARM x extras ON/OFF WSL2 Clang 14
ASan+UBSan campaigns complete 10,000 executions apiece with no finding or
artifact. Dual shared/static package consumers pass 8/8 from build trees and
again from relocated installs. This evidence is still bounded.

Version 11.17 strict Clang dual-architecture direct suites pass 67/67 with
extras and formatting enabled, 62/62 with extras disabled, and 65/65 with
formatting disabled. A Clang-CL `/W4 /WX` shared build passes 67/67. Both
extra-opcode variants pass all 1,289 x86 and 736 ARM corpus rows, and exactly
197/110 reviewed source seeds pass the deterministic audit. Intel XED validates
the exact AVX-512 VNNI opcode row; LLVM validates canonical ARM controls from
the official Arm XML masks. Four x86/ARM x extras ON/OFF WSL2 Clang 14
ASan+UBSan campaigns complete 10,000 executions each without a finding.
Installed-package validation passes all 16 shared Release cells in 3,754.29
seconds and all 16 static Release cells in 4,042.27 seconds. Both matrices cover
dual/x86/ARM/common-only x formatter ON/OFF x extras ON/OFF and exercise
build-tree and relocated C/C++ consumers, including the new IDs and formatters.
This remains bounded evidence rather than an exhaustive ISA-coverage claim.

Version 11.18 strict Clang matrices pass 71/71 tests with extras and
formatting enabled, 66/66 with extras disabled, and 69/69 with formatting
disabled. Their direct subsets pass 69/69, 64/64, and 67/67; Clang-CL
`/W4 /WX` builds every target and passes 69/69 direct tests. Both option
variants pass all 1,314 x86 and 751 ARM corpus rows, and exactly 214/118
reviewed source seeds pass the deterministic audit with no non-`.hex`
artifacts. Intel XED supplies the exact VBMI and APX boundaries; Arm's official
2025-12 XML supplies the exact FP-estimate mask. Four fresh WSL2 Clang 14
ASan+UBSan campaigns complete 10,000 executions each for x86/ARM x extras
ON/OFF, starting from exactly 214/118 reviewed seeds, without a finding. These
checks remain bounded rather than exhaustive. Installed-package validation
passes all 16 shared Release cells in 3,849.50 seconds and all 16 static Release
cells in 4,206.13 seconds. Both matrices cover dual/x86/ARM/common-only x
formatter ON/OFF x extras ON/OFF with build-tree and relocated C/C++ consumers.

For version 11.19, strict Clang 21.1.6 dual-architecture configurations pass
72/72 tests with extra opcodes and formatting enabled, 67/67 with extra opcodes
disabled, and 70/70 with formatting disabled. Their direct-test counts,
excluding the two nested CMake package integrations, are 70/70, 65/65, and
68/68. Clang-CL builds every enabled target under `/W4 /WX` and passes 70/70
direct tests. Four WSL2 Clang 14 ASan+UBSan libFuzzer campaigns complete 10,000
executions each for x86 and ARM with extra opcodes enabled and disabled, without
a finding. Installed-package validation passes all 16 shared Release cells in
3,722.89 seconds and all 16 static Release cells in 4,080.82 seconds. Both
matrices cover dual/x86/ARM/common-only builds, formatter ON/OFF, extra opcodes
ON/OFF, build-tree consumers, relocated C/C++ consumers, components, symbols,
and artifacts. The checked-in corpus and source-seed audits pass the exact
1,327/779-row and 215/136-seed inventories.

Version 11.20 expands the checked-in inventories to 1,337 x86 rows, 791 ARM
rows, 221 x86 seeds, and 144 ARM seeds. Its focused tests cover every classic
VEX AVX-VNNI opcode at both vector lengths and exhaust the 262,144-word F64MM
Q-element permute envelope. Strict Clang 21.1.6 dual-architecture builds pass
74/74 tests with extras and formatting enabled, 69/69 with extras disabled,
and 72/72 with formatting disabled; their direct subsets pass 72/72, 67/67,
and 70/70. Clang-CL builds every enabled target under `/W4 /WX` and passes all
74 non-package tests. Four WSL2 Clang 14 ASan+UBSan libFuzzer campaigns complete
10,000 executions each for x86 and ARM with extras enabled and disabled,
without a finding. Installed-package validation passes all 16 shared Release
cells in 4,412.08 seconds and all 16 static Release cells in 4,560.61 seconds.
Both matrices cover dual/x86/ARM/common-only builds, formatter ON/OFF, extras
ON/OFF, build-tree and relocated C/C++ consumers, components, symbol auditing,
and artifact layout.

Version 11.21 expands the checked-in inventories to 1,349 x86 rows, 808 ARM
rows, 230 x86 seeds, and 152 ARM seeds. Focused source suites exhaust the 3,072
allocated/3,072 reserved AVX-VNNI-INT8 controls and the 49,152
allocated/16,384 reserved SVE/SME integer-to-FP16 words. The x86 tranche adds
13 rows and retires one obsolete classic pp-neighbor row (12 net), while the
ARM tranche adds 17 rows. Strict Clang 21.1.6 Ninja dual-architecture
configurations built with `-Wall -Wextra -Wpedantic -Werror`, with
installed-package tests excluded, pass 76/76 tests with extras and formatting
enabled in 227.54 seconds, 71/71 with extras disabled and formatting enabled in
223.05 seconds, and 74/74 with extras enabled and formatting disabled in 411.20
seconds. Their direct subsets, excluding the two nested CMake integrations,
pass 74/74, 69/69, and 72/72.
Clang-CL 21.1.6 configuration under `/W4 /WX` succeeds, all 162 targets build,
and 76/76 non-package tests pass in 228.10 seconds. The six strict fuzz
translation-unit checks also pass. On WSL2, Clang 14 Unix Makefiles ASan+UBSan
libFuzzer campaigns complete 10,000 runs each for x86 and ARM with extras
enabled and disabled; all four exit zero with no finding and no crash artifacts.
Complete sequential installed-package matrices pass 16/16 shared cells in
3,831.53 seconds and 16/16 static cells in 3,986.38 seconds. They cover
dual/x86/ARM/common-only builds, formatter ON/OFF, extras ON/OFF, build-tree
and relocated C/C++ consumers, components, symbols, artifacts, and static
definitions. These checks remain bounded rather than exhaustive.

Version 11.22 expands the checked-in inventories to 1,362 x86 rows, 825 ARM
rows, 240 x86 seeds, and 160 ARM seeds. Its new focused suites exhaust 3,072
allocated plus 3,072 reserved AVX-VNNI-INT16 controls and all 65,536 allocated
signed/unsigned S-to-S, D-to-S, S-to-D, and D-to-D SVE/SME conversion words.
The x86 tranche adds 13 rows and ten seeds; the ARM tranche adds 17 rows and
eight seeds. These focused source tests cover CPU/runtime/build isolation,
formatting, endian parity, exact neighbors, truncation, and extras-OFF
ownership. Final strict Clang 21.1.6 dual-architecture validation passes 78/78
tests with extras and formatting enabled, 73/73 with extras disabled, and 76/76
with extras enabled and formatting disabled. Clang-CL passes 78/78 under
`/W4 /WX`. Four WSL2 Clang 14 ASan+UBSan libFuzzer campaigns for x86 and ARM
with extras enabled and disabled complete 10,000 runs each successfully.
Installed-package matrices pass 16/16 shared cells in 3,696.43 seconds and
16/16 static cells in 4,052.63 seconds. The compiled x86 modern-VEX table audit
reports 149 descriptors and zero lookup-key overlaps; the ARM modern mask audit
reports 94 patterns and zero overlaps. These checks remain bounded rather than
exhaustive.

Version 11.23's checked-in inventories contained 1,377 x86 rows, 869 ARM
rows, 250 x86 seeds, and 186 ARM seeds. Its 4VNNIW focused material contributes
15 rows and ten seeds; its deterministic suite exhausts both opcodes across all
ModRM and W controls and separately locks fixed EVEX.512, U=1/B=0, memory-only
m128, mask/zero behavior, extended registers, Tuple1_4X disp8 scaling,
Knights Mill CPU/runtime admission, formatting, truncation, and extras-OFF
ownership against Intel XED. The new baseline ARM conversion focused material
contributes 31 rows and 22 seeds; its suite exhausts 163,840 allocated and
40,960 reserved words, with BFCVT adjacency, SVE-or-SME admission, typed
metadata, endian parity, formatting, truncation, and extras-OFF ownership. The
current ARM inventory also contains other checked-in deltas, so it must not be
reconstructed by adding only that focused increment to the documented 11.22
total. The expanded EVEX audit reports 227 descriptors with zero lookup-key
intersections, and the ARM modern table reports 101 patterns with zero mask
overlaps. Final strict Clang 21.1.6 dual-architecture validation passes 80/80
tests with extras and formatting enabled in 235.68 seconds, 75/75 with extras
disabled in 233.31 seconds, and 78/78 with extras enabled and formatting
disabled in 231.63 seconds. Clang-CL 21 passes 80/80 under `/W4 /WX` in 241.70
seconds. The four WSL2 Clang 14 ASan+UBSan x86/ARM by extras ON/OFF
configurations each complete two fixed-seed 10,000-run libFuzzer passes:
80,000 total executions with no sanitizer finding or crash artifact.
Installed-package matrices pass 16/16 shared cells in 3,589.77 seconds and
16/16 static cells in 3,936.32 seconds. These checks remain bounded rather than
exhaustive.

Version 11.24 focused validation exhausts the 8,192-control AVX512_4FMAPS
domain as 1,536 allocated and 6,656 rejected controls. The ARM checks exhaust
all 8,192 words in the exact merging `BFCVT` class, its 32,768-word selector
envelope, and retain the independent 65,536-word baseline `FCVT` sweep. The
expanded EVEX audit reports 231 descriptors with zero lookup-key intersections,
and the ARM modern table reports 102 patterns with zero mask overlaps.

Final version-11.24 strict Clang 21.1.6 dual-architecture matrices pass 82/82
with extras and formatting enabled, 77/77 with extras disabled, and 80/80 with
formatting disabled; their overlay cells take 222.07, 222.04, and 222.01 seconds.
A fresh Clang-CL 21.1.6 x86-64 Release shared build under `/W4 /WX` configures
in 29.526 seconds, builds 174/174 with zero warnings in 196.306 seconds, and
passes 82/82 CTests in 192.59 seconds, including the 192.43-second overlay. The
251,392-byte DLL and 4,936-byte import library have the required exports and
image version 11.24. Fresh strict Clang package matrices pass every one of 16
shared and 16 static feature cells. Shared configures in 23.462 seconds, builds
170/170 in 205.562 seconds, and passes in 3,576.25 seconds (3,576.569 measured);
static configures in 21.80 seconds, builds 174/174 in 195.74 seconds, and passes
in 3,922.01 seconds (3,922.36 measured). Fresh WSL Ubuntu Clang 14
ASan+UBSan/libFuzzer runs replay every 266/190 reviewed x86/ARM seed in both
extras variants, then complete 25,000 units in each of four campaigns: 100,000
total units, 99,084 generated after initialization, and zero sanitizer,
runtime, invariant, crash, timeout, OOM, or leak findings. The fixed REX2
RDSEED reproducer exits successfully and remains a permanent seed. These are
bounded release results, not exhaustive ISA-coverage claims.

Version 11.25's checked-in inventories contain 1,430 x86 rows, 889 ARM rows,
274 x86 seeds, and 193 ARM seeds. The focused VGETEXP suite exhausts 8,192
structural cells as 5,248 valid and 2,944 invalid controls and separately sweeps
mask state and all 32 combined `vvvv`/extension values. Its checked-in coverage
contains 29 VGETEXP cases and eight named seeds; the remaining new x86 row is
an address-prefixed VEX3 regression. Focused x86 extras-ON, extras-OFF, and
formatter-OFF configurations each pass three VGETEXP/corpus/seed-audit tests;
the ON x86 label passes 40/40, all three corpus runners pass 1,430/1,430 rows,
and the 235-entry EVEX descriptor audit reports zero lookup-key overlaps. The focused ARM
BFCVT/BFCVTNT suite checks 73,728 words: 32,768 retained controls plus 24,576
new allocated and 16,384 new reserved words. Fresh ARM-only strict Clang 21.1.6
extras-ON, extras-OFF, and formatter-OFF configurations each pass the four
modern/FCVT/BFCVT/corpus tests. The 107-entry ARM modern-pattern audit reports
zero overlaps, and corpus/seed audits confirm the inventories above.

Final version-11.25 release validation passes the full strict Clang 21.1.6
CTest variants 83/83 with extras and formatting enabled, 78/78 with extras
disabled, and 81/81 with formatting disabled. A fresh Clang-CL 21.1.6 build
with `/W4 /WX` completes all 176/176 steps and passes 83/83 CTests; its PE image
reports version 11.25 and exposes the expected 16 public exports. Four primary
WSL Clang 14 ASan+UBSan libFuzzer campaigns--x86 and ARM with extras ON and
OFF--replay the 274 x86 or 193 ARM reviewed seeds at initialization and each
complete 25,000 units, for 100,000 total, with zero findings. The shared
installed-package matrix passes all 16/16 cells, 32 consumer suites, and 204
nested runtime tests in 3,522.48 seconds. The static installed-package matrix
passes all 16/16 cells in 3,865.85 seconds, with zero failures. These are
bounded tranche and release-matrix results, not exhaustive ISA-coverage claims.

Version 11.26's checked-in inventories contain 1,459 x86 rows, 909 ARM rows,
282 x86 seeds, and 200 ARM seeds. That release appends x86 IDs 1126--1128 and
ARM ID 438, giving its name counts of 1129 and 439 respectively. The
focused x86 suite defines a 12,288-cell W/LL/b/ModRM lattice with 3,968
allocated and 8,320 reserved controls. The focused ARM suite defines an
18,432-word domain: 16,384 SME2 selector words plus 2,048 SVE2/SME2 FP8
narrowing words. It separates 2,048 implemented pair-form words from 8,704
allocated-but-unsupported siblings and 7,680 reserved words and asserts
that no pair form is named `BFCVTNT`. These are scoped inventory and test-domain
facts,
not an exhaustive ISA claim or, by themselves, a completed release-wide
validation matrix.

Final version-11.26 release validation passes the strict Clang 21.1.6 CTest
variants 85/85 with extras and formatting enabled, 80/80 with extras disabled,
and 83/83 with formatting disabled. A post-fix Clang-CL 21.1.6 `/W4 /WX`
rebuild is warning-free and passes 83/83 non-integration CTests. The 238-entry
x86 EVEX descriptor audit and 111-entry ARM modern-pattern audit report zero
overlaps. Four post-decoder-fix WSL Clang 14 ASan+UBSan libFuzzer campaigns
complete 25,000 units each, for 100,000 total, with zero findings. After the
x86 harness was corrected to select named-profile modes through
`cdisasm_x86_cpu_mode_mask`, its extras-ON and extras-OFF campaigns complete an
additional 25,000 units each with no finding and empty artifact directories.
The binary audit confirms 16 public exports with formatting enabled, 12 with
formatting disabled, runtime version 11.26.0, and fixed x86/ARM result sizes of
248/168 bytes. Installed-package validation passes all 16 shared cells in
3,608.51 seconds and all 16 static cells in 3,964.57 seconds; their 408 nested
runtime tests (256 C and 152 C++17) all pass. These remain bounded release and
family results, not an exhaustive x86 or ARM ISA-coverage claim.

Version 11.10 native validation passes 51/51 direct semantic CTests with extra
opcodes and formatting enabled, 45/45 with extra opcodes disabled, and 49/49
with formatting disabled. With both CMake integrations, the totals are 53/53,
47/47, and 51/51. Fresh Clang 21.1.6 `-Werror` and MSVC 19.44.35224 `/W4` x64
shared Release builds each pass 53/53. Installed packages pass every one of 16
shared cells in 1,669.23 seconds and 16 static cells in 1,812.81 seconds. WSL2
Clang 14 ASan+UBSan campaigns complete 10,000 executions for each x86 and ARM
harness in both extra-opcode variants against 151 x86 or 86 ARM reviewed
source seeds, with no finding.

Version 11.11 native validation passes 53/53 direct semantic CTests with extra
opcodes and formatting enabled, 47/47 with extra opcodes disabled, and 51/51
with formatting disabled. With both CMake integrations, the totals are 55/55,
49/49, and 53/53. Fresh Clang 21.1.6 `-Wall -Wextra -Wpedantic -Werror` and
MSVC 19.44.35224 `/W4` x64 shared Release builds each pass 55/55. Including
both installed-package tests, the corresponding top-level totals are 57/57,
51/51, and 55/55. Each package test passes every one of its 16 shared or 16
static architecture/formatter/extra-opcode cells, including relocated C and
C++ consumers. WSL2 Clang 14 ASan+UBSan campaigns complete 10,000 executions
for x86 extras ON, x86 extras OFF, ARM extras ON, and ARM extras OFF against
157 x86 or 89 ARM reviewed source seeds, with no finding.

Version 11.12 final validation passes 58/58 with extras enabled and 52/52
with extras disabled under both MSVC and strict Clang. Intel XED reports zero
mismatches across the 32 added opcode/W/extension controls and 13 APX
P0.B4/U0/X4 routes; pinned Capstone matches all 18 legal A64 floating
compare-with-zero operation/width controls and rejects all 14 sampled reserved
controls. Four WSL2 Clang 14 ASan+UBSan campaigns (x86/ARM × extras ON/OFF)
complete 10,000 executions each with no finding; x86 uses the full 192-byte
text limit and ARM starts from an exact fresh copy of all 91 reviewed seeds.
The shared and static installed-package tests each pass all 16 Release cells
in 3,744.55 and 4,102.86 seconds respectively, including relocated C/C++
consumers, component/symbol audits, and static embedding where applicable.

`cdisasm_mode` must be exactly `CDISASM_MODE_16`, `CDISASM_MODE_32`, or
`CDISASM_MODE_64`. Structured x86 operands are returned in Intel display order.

## ARM CPU families and decode contexts

ARM exposes the same direct-family model as x86, while keeping the execution
state (`A32`, `T32`, or `A64`) separate from the architectural family mask.
Family IDs are stable numeric values and each family has a corresponding
`CDISASM_ARM_FAMILY_MASK_*` bit. The available mask is derived independently
from the selected CPU profile and mode:

```c
cdisasm_arm_family_mask available = cdisasm_arm_cpu_family_mask(
    CDISASM_ARM_CPU_CORTEX_A53, CDISASM_ARM_MODE_A64);

cdisasm_arm_decode_context context;
cdisasm_arm_cpu_decode_context(
    CDISASM_ARM_CPU_CORTEX_A53, CDISASM_ARM_MODE_A64, &context);

cdisasm_arm_family_mask defaults =
    cdisasm_arm_decode_context_get_set_families(&context);
```

The family table covers the ARM ISA generations and extensions represented by
the decoder, including `NEON`, `VFP`, `SVE`, `SVE2`, `SME`, `LSE`/`LSE2`,
`RCPC`, `BTI`, `PAUTH`, `MTE`, `MOPS`, `LS64`, `CSSC`, `BF16`, `FP8`, crypto
families, and Apple-specific `MUL53`, `AMX`, and system families. A family is
available only when the CPU profile advertises its required capability, the
selected state permits that family, and (for generated feature families) the
feature bitmap is present. Apple-only families are excluded from
`CDISASM_ARM_FAMILY_MASK_DEFAULT`; they can still be enabled when available:

```c
int enabled = cdisasm_arm_decode_context_add_family(
    &context, CDISASM_ARM_FAMILY_APPLE_AMX);
int disabled = cdisasm_arm_decode_context_remove_family(
    &context, CDISASM_ARM_FAMILY_APPLE_AMX);
```

Both operations return nonzero only for a valid family present in
`context.family_mask`. `cdisasm_arm_decode_with_context` uses the context's
CPU, state, and decode flags for each instruction; the family projection is a
query/selection view and never replaces the exact byte-level legality checks.
The two accessor functions return the available and selected masks and return
`CDISASM_ARM_FAMILY_MASK_NONE` for a null context.

## x86 single-instruction decoding

`cdisasm_x86_decode` is the explicit x86 entry point exported by `cdisasm` when
`USE_ARCH_X86=1`. It decodes the first instruction in the supplied byte range into
stable mnemonic/register IDs and typed register, immediate, and memory
operands. It accepts a pointer to the runtime allow bitmap below and either the unrestricted
CPU-capability profile `CDISASM_CPU_X86` or one of the named CPU profiles. The generic
`cdisasm_decode` facade produces the same result after selecting x86 from the
CPU group and is exported by the same core library.

Two allocation-free queries expose the profile policy used by the x86
decoder:

```c
cdisasm_x86_mode_mask cdisasm_x86_cpu_mode_mask(
    cdisasm_x86_cpu_id cpu_id);

cdisasm_status cdisasm_x86_cpu_decode_flag_mask(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    cdisasm_x86_decode_flags *flags);
```

`cdisasm_x86_decode_flags` aliases the generic 64-byte
`cdisasm_decode_flags`; the query writes that type and `cdisasm_x86_decode`
accepts a pointer to it. The mode mask is a separate bit vocabulary from the
decode-mode argument:

| Value | Define | Decode mode represented |
| ---: | --- | --- |
| `0x00` | `CDISASM_X86_MODE_MASK_NONE` | No mode / invalid profile |
| `0x01` | `CDISASM_X86_MODE_MASK_16` | `CDISASM_X86_MODE_16` |
| `0x02` | `CDISASM_X86_MODE_MASK_32` | `CDISASM_X86_MODE_32` |
| `0x04` | `CDISASM_X86_MODE_MASK_64` | `CDISASM_X86_MODE_64` |

`cdisasm_x86_cpu_mode_mask` ORs every execution width supported by the named
profile. It returns `CDISASM_X86_MODE_MASK_NONE` for a wrong architecture
group, a raw legacy ordinal, or an unknown x86 ordinal. For example, 8086,
80386, and Athlon 64 profiles return `0x01`, `0x03`, and `0x07`, respectively.

For a valid CPU/mode pair, `cdisasm_x86_cpu_decode_flag_mask` writes the
implemented, build-enabled non-base family bits which that profile can use in
that mode and returns `CDISASM_STATUS_OK`. Base decoding is always implicit and
is represented by an all-zero object. A written family bit promises that the
decoder implements forms in that family for the profile, not that every
architectural encoding in the family is implemented or that required
operating-system state is active.

The output pointer is required. The function clears the complete object before
validation; a NULL output, invalid CPU, invalid mode value, or impossible
CPU/mode pair returns `CDISASM_STATUS_INVALID_ARGUMENT`. A non-NULL output is
therefore zero after any invalid CPU/mode request. With
`USE_EXTRA_OPCODES=0`, the query returns `CDISASM_STATUS_OK` and a zero object
for every valid pair because that variant accepts no non-base runtime family
bits.

```c
cdisasm_x86_decode_flags available =
    CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
cdisasm_status status = cdisasm_x86_cpu_decode_flag_mask(
    CDISASM_CPU_HASWELL, CDISASM_MODE_64, &available);
if (status == CDISASM_STATUS_OK) {
    /* &available is a valid flags argument for this profile and mode. */
}
```

For callers that decode several instructions with one CPU/mode policy,
`cdisasm_x86_cpu_decode_context` stores the same capability flags together
with two family projections:

```c
cdisasm_x86_decode_context context;
cdisasm_x86_cpu_decode_context(
    CDISASM_CPU_HASWELL, CDISASM_MODE_64, &context);

/* Every direct ISA or validation family available for this CPU and mode. */
cdisasm_x86_family_mask available = context.family_mask;

/* Ordinary default families; privileged/vendor-specific families are off. */
cdisasm_x86_family_mask defaults = context.family_value;
```

`family_value` is always a subset of `family_mask`. The available mask includes
direct ISA families such as `SSE2`, `AVX2`, `FMA3`, `AES`, `PCLMUL`, `SHA`,
`GFNI`, `BITMANIP`, `AVX10`, and `AMX`, as well as validation families such as
`AVX512_EVEX`, `APX_EVEX`, and `AVX2_GATHER`. FRED, TDX, Intel VMX, AMD SVM,
and VIA PadLock are off in the default selection; legacy AMD-only `3DNOW`,
`XOP`, and `FMA4` are also opt-in by default. Applications can opt any
available family in or out using the `CDISASM_X86_FAMILY_MASK_*` bits. The
complete CPU/mode capability bitmap remains in `context.flags` and is what
`cdisasm_x86_decode_with_context` passes to the decoder, so exact ISA-set,
operand, and byte-encoding legality is never lost by the family projection.

The selection can be changed without touching the CPU capability mask:

```c
int enabled = cdisasm_x86_decode_context_add_family(
    &context, CDISASM_X86_FAMILY_FRED);
int disabled = cdisasm_x86_decode_context_remove_family(
    &context, CDISASM_X86_FAMILY_FRED);
```

Both functions return nonzero only for a valid family that is present in
`family_mask`; unavailable or invalid families return zero.

The two masks can be read without exposing the context layout:

```c
cdisasm_x86_family_mask available =
    cdisasm_x86_decode_context_get_available_families(&context);
cdisasm_x86_family_mask selected =
    cdisasm_x86_decode_context_get_set_families(&context);
```

Both accessors return `CDISASM_X86_FAMILY_MASK_NONE` for a null context;
`selected` is intersected with `available`.

With extra opcodes enabled, the virtualization-related subset is exact:

| CPU profile | Included selector(s) | Excluded selector(s) |
| --- | --- | --- |
| `CDISASM_CPU_INTEL_VT_X` | `VMX` | `SMX`, `SVM` |
| `CDISASM_CPU_AMD_V` | `SVM` | `SMX`, `VMX` |
| `CDISASM_CPU_CORE_2` | `SMX`, `VMX` | `SVM` |
| `CDISASM_CPU_X86` | `SMX`, `VMX`, `SVM` | — |

The regression matrix checks this virtualization subset for all 53 unique x86
CPU profiles in every mode each profile supports, not only the four examples
shown above.

`flags` points to an allow bitmap, not a requested CPU feature set. `NULL` or
an all-zero object admits only ordinary scalar/base instructions. Base
instructions stay admitted when nonzero bits are present. The public values
are append-only ABI vocabulary and are defined regardless of the build option.
The current mask constants address bitmap 0. Each assigned family also has a
logical `CDISASM_X86_DECODE_BIT_*` ID with the same 0--63 number; those IDs
work with the common set/clear/test helpers and can extend into later words:

| Bitmap 0 bit | Bitmap 0 value | Mask define | Family selected for runtime admission |
| ---: | ---: | --- | --- |
| — | `0x00000000` | `CDISASM_X86_DECODE_FLAG_BASE` | Ordinary scalar/base instructions |
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
| 23 | `0x00800000` | `CDISASM_X86_DECODE_FLAG_SMX` | Intel SMX (`GETSEC`) only; legacy `VIRTUALIZATION` is the historical exact alias |
| 24 | `0x01000000` | `CDISASM_X86_DECODE_FLAG_SYSTEM` | System/privileged facilities, including implemented RDPID/SERIALIZE/MOVDIR/WBNOINVD forms |
| 25 | `0x02000000` | `CDISASM_X86_DECODE_FLAG_CET` | CET IBT and shadow stack |
| 26 | `0x04000000` | `CDISASM_X86_DECODE_FLAG_STATE` | FXSAVE/FXRSTOR and XSAVE families |
| 27 | `0x08000000` | `CDISASM_X86_DECODE_FLAG_TRANSACTIONAL` | HLE and RTM |
| 28 | `0x10000000` | `CDISASM_X86_DECODE_FLAG_SECURITY` | RDRAND, RDSEED, SGX, and MPX |
| 29 | `0x20000000` | `CDISASM_X86_DECODE_FLAG_MEMORY_HINTS` | PAUSE, prefetch, CLFLUSH, CLFLUSHOPT, and CLWB |
| 30 | `0x40000000` | `CDISASM_X86_DECODE_FLAG_UNDOCUMENTED` | Undocumented/compatibility forms |
| 31 | `0x0000000080000000` | `CDISASM_X86_DECODE_FLAG_SM3` | SM3 vector crypto |
| 32 | `0x0000000100000000` | `CDISASM_X86_DECODE_FLAG_SM4` | SM4 vector crypto |
| 33 | `0x0000000200000000` | `CDISASM_X86_DECODE_FLAG_AVX512_VBMI2` | Implemented AVX512VBMI2 forms |
| 34 | `0x0000000400000000` | `CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ` | Implemented AVX512VPOPCNTDQ forms |
| 35 | `0x0000000800000000` | `CDISASM_X86_DECODE_FLAG_AVX512_BITALG` | Implemented AVX512BITALG forms |
| 36 | `0x0000001000000000` | `CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND` | Exact EVEX COMPRESS/EXPAND class |
| 37 | `0x0000002000000000` | `CDISASM_X86_DECODE_FLAG_AVX512_IFMA` | Implemented AVX512IFMA forms |
| 38 | `0x0000004000000000` | `CDISASM_X86_DECODE_FLAG_AVX512_VBMI` | Implemented AVX512VBMI forms |
| 39 | `0x0000008000000000` | `CDISASM_X86_DECODE_FLAG_AVX512_VNNI` | Implemented AVX512VNNI forms |
| 40 | `0x0000010000000000` | `CDISASM_X86_DECODE_FLAG_VAES` | VAES forms |
| 41 | `0x0000020000000000` | `CDISASM_X86_DECODE_FLAG_VPCLMULQDQ` | Vector PCLMULQDQ forms |
| 42 | `0x0000040000000000` | `CDISASM_X86_DECODE_FLAG_SHA512` | Vector SHA-512 forms |
| 43 | `0x0000080000000000` | `CDISASM_X86_DECODE_FLAG_AMX_TILE` | AMX tile foundation forms |
| 44 | `0x0000100000000000` | `CDISASM_X86_DECODE_FLAG_AMX_INT8` | AMX INT8 forms |
| 45 | `0x0000200000000000` | `CDISASM_X86_DECODE_FLAG_AMX_BF16` | AMX BF16 forms |
| 46 | `0x0000400000000000` | `CDISASM_X86_DECODE_FLAG_AMX_FP16` | AMX FP16 forms |
| 47 | `0x0000800000000000` | `CDISASM_X86_DECODE_FLAG_AMX_COMPLEX` | AMX complex forms |
| 48 | `0x0001000000000000` | `CDISASM_X86_DECODE_FLAG_AMX_FP8` | AMX FP8 forms |
| 49 | `0x0002000000000000` | `CDISASM_X86_DECODE_FLAG_AMX_MOVRS` | AMX MOVRS forms |
| 50 | `0x0004000000000000` | `CDISASM_X86_DECODE_FLAG_AMX_AVX512` | AMX row/AVX-512 transfer forms |
| 51 | `0x0008000000000000` | `CDISASM_X86_DECODE_FLAG_AVX512_DQ` | Implemented AVX512DQ forms |
| 52 | `0x0010000000000000` | `CDISASM_X86_DECODE_FLAG_AVX512_BW` | Implemented AVX512BW forms |
| 53 | `0x0020000000000000` | `CDISASM_X86_DECODE_FLAG_VMX` | Intel VMX forms |
| 54 | `0x0040000000000000` | `CDISASM_X86_DECODE_FLAG_SVM` | AMD SVM forms |
| 55 | `0x0080000000000000` | `CDISASM_X86_DECODE_FLAG_SSE41` | SSE4.1 forms |
| 56 | `0x0100000000000000` | `CDISASM_X86_DECODE_FLAG_SSE42` | SSE4.2 forms |
| 57 | `0x0200000000000000` | `CDISASM_X86_DECODE_FLAG_SSE4A` | AMD SSE4a forms |
| 58 | `0x0400000000000000` | `CDISASM_X86_DECODE_FLAG_BMI1` | BMI1 forms |
| 59 | `0x0800000000000000` | `CDISASM_X86_DECODE_FLAG_BMI2` | BMI2 forms |
| 60 | `0x1000000000000000` | `CDISASM_X86_DECODE_FLAG_AVX512_CD` | Exact AVX-512CD conflict/leading-zero-count class |
| 61 | `0x2000000000000000` | `CDISASM_X86_DECODE_FLAG_AVX_VNNI` | Exact classic VEX AVX-VNNI dot-product row |
| 62 | `0x4000000000000000` | `CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8` | Exact classic VEX AVX-VNNI-INT8 dot-product row |
| 63 | `0x8000000000000000` | `CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16` | Exact classic VEX AVX-VNNI-INT16 dot-product row |

The flags object can be declared with any of these C/C++-compatible
initializers:

```c
cdisasm_x86_decode_flags base =
    CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
cdisasm_x86_decode_flags selected =
    CDISASM_X86_DECODE_FLAGS_INITIALIZER(
        CDISASM_X86_DECODE_FLAG_AVX
        | CDISASM_X86_DECODE_FLAG_FMA3);
cdisasm_x86_decode_flags all_known =
    CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;

cdisasm_decode_flags_reset(&selected);
cdisasm_decode_flags_set_bit(&selected, CDISASM_X86_DECODE_BIT_AVX);
cdisasm_decode_flags_clear_bit(&selected, CDISASM_X86_DECODE_BIT_AVX);
```

The generic `CDISASM_DECODE_FLAGS_INITIALIZER(word0)` and
`CDISASM_DECODE_FLAGS_NONE_INITIALIZER` provide the same common-layout
initialization without architecture-specific names. The singular
`cdisasm_x86_decode_option` and generic `cdisasm_decode_option` typedefs remain
64-bit aliases for one bitmap word, and the legacy `_OPTION_*` values remain
bitmap-0 values; neither singular type is accepted as the decoder's pointer
argument.

`CDISASM_X86_DECODE_FLAG_ALL` (also
`CDISASM_X86_DECODE_OPTION_ALL`) and the bitmap-0
`CDISASM_X86_DECODE_FLAG_KNOWN_MASK` are `0xffffffffffffffff`.
`CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER` supplies the complete all-known-bits
object. The current version-12 catalog assigns logical bits 0--270: words 0--3
are full and bits 0--14 of word 4 are known. The rest of word 4 and words 5--7
remain reserved for append-only x86 assignments. The old version-11 scalar
namespace was saturated and required a
compatibility-umbrella policy for AVX512_4VNNIW and AVX512_4FMAPS; the wider
object removes that 64-family ceiling without changing established
assignments. The original `AVX512`, `AES`, `PCLMUL`, `SHA`, `AMX`, `SSE4`, and
`BITMANIP` bits remain compatibility
umbrellas for their narrower selectors. A caller may instead pass one narrow
bit to admit only that implemented class on a compatible CPU.
`VIRTUALIZATION` retains bit 23 as an exact alias of `SMX`; it does not admit
VMX or SVM. Use `VMX` or `SVM` for hardware-virtualization instructions. The
readable `INTEL_VIRTUALIZATION` and `AMD_VIRTUALIZATION` aliases name those
same vendor-specific bits. Catalog-only opcode groups are not assigned a
narrow selector before an instruction is decoded.
An instruction normally selects its most-specific family, so an AES form needs
the `AES` bit rather than `AES | SSE2`, and an AVX2 form needs `AVX2` rather
than `AVX2 | AVX`. Architectural prerequisites stay in the independent CPU
profile. An undocumented x87 form is the combined exception and requires both
`FPU` and `UNDOCUMENTED`.

Nonzero family bits are accepted only when `USE_EXTRA_OPCODES=1`. In that
variant the decoder checks every word against
`CDISASM_X86_DECODE_FLAG_KNOWN_MASK_0` through `_7`; any reserved bit reports
`CDISASM_STATUS_INVALID_ARGUMENT`. A missing required known family bit reports
`CDISASM_STATUS_UNSUPPORTED_INSTRUCTION`
after structural decoding and CPU validation. With `USE_EXTRA_OPCODES=0`, only
`NULL` or an entirely zero object is valid and every set bit reports
`INVALID_ARGUMENT`
before the input is inspected. Flags do not override CPU policy: for example,
the `AES` bit cannot make an AES instruction valid on Nehalem, while Westmere
still needs the `AES` bit to admit that instruction.

- `CDISASM_STATUS_INVALID_ARGUMENT`: invalid CPU, mode, CPU/mode pairing, or
  flags object; in an OFF build this includes every object with a set bit.
- `CDISASM_STATUS_END_OF_INPUT`: the supplied byte count is zero.
- `CDISASM_STATUS_TRUNCATED`: the bytes begin a potentially supported
  instruction but end before its encoding is complete.
- `CDISASM_STATUS_INVALID_INSTRUCTION`: the bytes are not a valid x86 encoding
  in the selected mode, exceed x86's 15-byte instruction limit, or require a
  capability absent from the selected CPU profile.
- `CDISASM_STATUS_UNSUPPORTED_INSTRUCTION`: the encoding belongs to an
  unimplemented or conservatively unclassified instruction family, or its
  non-base family is not admitted by a valid runtime bitmap.

The return value is the decoded byte count (1 through 15), or zero on failure.
The result pointer is required and its structure is always initialized.
`last_error_id` is `CDISASM_STATUS_OK` on success; on failure it is the exact
status and every other byte is zero. On success, `opcode_size` equals the return
value and `address` is the address supplied by the caller.

New x86 source should use the architecture header and explicit entry point:

```c
#include <cdisasm/cdisasm_x86.h>

const uint8_t code[] = {0x90};
cdisasm_instruction instruction;
uint32_t size = cdisasm_x86_decode(
    CDISASM_CPU_80386,
    CDISASM_MODE_32,
    code,
    sizeof(code),
    UINT64_C(0x1000),
    NULL,
    &instruction);
```

Named x86 CPU ordinals are append-only. Ordinals 1--38 are chronological
ISA-introduction profiles; ordinals 39--44 are exact processor profiles;
ordinals 45--48 are pre-80486 CPU+external-x87 combinations; and ordinals
49--52 are the appended Granite Rapids, Arrow Lake, Diamond Rapids, and exact
Knights Mill physical profiles. Their full IDs are
`CDISASM_CPU_GROUP_X86 | ordinal`. A relational comparison is valid only inside
the original chronological 1--38 range: there, 32-bit mode starts at
`CDISASM_CPU_80386` and 64-bit mode at `CDISASM_CPU_ATHLON_64`. The decoder
never applies that shortcut to appended profiles; explicit per-profile mode
metadata keeps an ordinal-45 8086+8087 target in 16-bit mode.

Instruction availability does not use a simple numeric comparison. Intel and
AMD profiles branch and are not complete feature supersets; for example,
Pentium Pro has CMOV while Pentium MMX does not, and Barcelona has LZCNT while
Nehalem does not. The decoder therefore applies a capability mask for every
named profile. `CDISASM_CPU_X86` is
`CDISASM_CPU_GROUP_X86 | 0x0000` (`0x00010000`) and permits every instruction
family implemented by the library at the CPU-capability gate. It remains
subject to the independent runtime allow bitmap and build option.

`CDISASM_CPU_LATEST` is the chronological alias of
`CDISASM_CPU_DIAMOND_RAPIDS`, ordinal 51 and full ID `0x00010033`.
`CDISASM_CPU_LAST` is the distinct enumeration bound
`CDISASM_CPU_KNIGHTS_MILL`, ordinal 52 and full ID `0x00010034`, and must be
used as the upper bound when enumerating that group. Neither name implies
feature-set inclusion: profiles after the abstract APX level include no-AVX
modern processors, old CPU+coprocessor combinations, current-generation
presets, and the appended older Knights Mill specialist profile. Feature and mode tests must use the decoder's independent profile
metadata, never a raw `cpu_id >= feature_cpu` comparison over the full
namespace.

These are conservative decoder presets, not complete emulation of every vendor
CPUID bit, stepping, or undocumented silicon behavior. Most are documented
milestone families; version 5.4 adds six exact processor models, the appended
coprocessor profiles make optional pre-486 x87 hardware explicit, and version
10.1 adds Granite Rapids for the implemented AVX10.1 and AMX-FP16 forms.
Version 11 adds Arrow Lake and Diamond Rapids with explicit, non-inherited
capability sets for the implemented modern crypto, AVX10/APX, AMX, WAITPKG,
and system slices. Version 11.23 appends Knights Mill without changing
`CDISASM_CPU_LATEST`; only that exact named profile admits AVX512_4VNNIW, and
version 11.24 uses the same exact profile for AVX512_4FMAPS. A
separate late-80486 profile represents the 486 variants that implemented CPUID
without enabling the rest of Pentium.

3DNow! availability at the CPU gate is deliberately non-monotonic. It is not
inferred merely from CPU chronology or from MMX support. Successful decode also
requires `USE_EXTRA_OPCODES=1` and `CDISASM_X86_DECODE_FLAG_3DNOW`:

| Profile family | Base 3DNow! and `FEMMS` | Extended 3DNow! | `PREFETCH` (`0F 0D /0`) | `PREFETCHW` (`0F 0D /1`) |
| --- | :---: | :---: | :---: | :---: |
| `CDISASM_CPU_X86` unrestricted profile | yes | yes | yes | yes |
| AMD K6-2 | yes | no | yes | yes |
| AMD Athlon 64, AMD-V, and Barcelona | yes | yes | yes | yes |
| AMD Bulldozer, Zen, and Zen 4 | no | no | yes | yes |
| Intel Goldmont and Broadwell-or-later Intel profiles | no | no | no | yes |
| Exact N3350, N4020, and N6000 profiles | no | no | no | yes |
| Exact G1840, G3900, and G5900 profiles | no | no | no | no |
| Earlier Intel profiles | no | no | no | no |

The K6-2 preset intentionally does not stand in for later K6-2E/K6-III parts
that added Extended 3DNow!. The arithmetic extension was removed from later AMD
families, while the prefetch hints survived. Intel never gains the 3DNow!
arithmetic selector map; its supported `/1` hint is controlled independently.
`PREFETCH` and `PREFETCHW` require a memory ModRM operand, and `/2` through `/7`
of `0F 0D` are not accepted as aliases.

WAITPKG availability is also explicit rather than chronological. The exact
Tremont-based [Pentium Silver N6000](https://www.intel.com/content/www/us/en/products/sku/212330/intel-pentium-silver-n6000-processor-4m-cache-up-to-3-30-ghz/specifications.html),
Alder Lake, Sapphire Rapids, Granite Rapids, Arrow Lake, and Diamond Rapids
presets expose the implemented
`UMONITOR`, `UMWAIT`, and `TPAUSE` forms. Ice Lake, Tiger Lake, AMD Zen 4, and
the abstract AVX10/APX profiles deliberately do not infer WAITPKG. The
unrestricted `CDISASM_CPU_X86` profile accepts the implemented forms, but
successful decode still requires `USE_EXTRA_OPCODES=1` and
`CDISASM_X86_DECODE_FLAG_SYSTEM`.

The ordinary WAITPKG register forms are available in 16-, 32-, and 64-bit
decode modes. `UMONITOR` uses effective address width, whereas `UMWAIT` and
`TPAUSE` use a fixed 32-bit register operand. REX2 map 1 may extend those
registers through R31, but admission then independently requires APX-F as well
as WAITPKG. Diamond Rapids exposes both capabilities and is the named physical
route for those combined forms. The abstract APX preset still does not claim
WAITPKG; the unrestricted profile remains the profile-independent analysis
route.

WAITPKG, CET shadow stack, and CLWB share the `0F AE` selector space. Following
the [Intel Software Developer's Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
the rightmost `F2`/`F3` byte selects `UMWAIT`/`UMONITOR` and takes precedence
over a redundant `66`; plain `66` selects `TPAUSE`. Mandatory-`F3` memory and
`/5` forms remain CET `CLRSSBSY`/`INCSSP`, `66` memory selects the independently
gated CLWB path, and reserved F2 memory plus LOCKed
WAITPKG forms are invalid. F2/66 register extensions other than the defined
`/6` WAITPKG forms are invalid rather than unsupported. REX2 B4 does not
override the ModRM `mod=00` SIB `base=5` disp32/no-base exception; that rule is
applied before extended-register interpretation and keeps instruction length
and following-byte ownership correct. CPU, runtime-family, mode, and
build-option checks remain independent from this structural collision
resolution.

PTWRITE register form 2438 and memory form 2439 exactly own mandatory-F3
`0F AE /4` in all three decode modes. The one read operand is GPRy or MEMy:
dword unless effective W selects qword in 64-bit mode. Any `66`, a rightmost
`F2`, LOCK, or a malformed REX2 map control is invalid; unprefixed memory `/4`
remains XSAVE. REX.R and REX2.R/R4 are ignored for the `/4` opcode field,
while B/B4 and SIB X/X4 extend the source. REX2 admission independently
requires APX-F in addition to the PTWRITE runtime bit and PTWRITE-capable CPU.
The unrestricted, N4020, N6000, Alder Lake, Sapphire Rapids, Granite Rapids,
Arrow Lake, Diamond Rapids, AVX10, and APX profiles admit ordinary PTWRITE;
other named profiles reject it. Intel and AT&T register text has no suffix;
AT&T memory text uses `l` or `q`. The focused suite checks all 768 ModRM
controls across the three modes plus prefixes, profiles, REX2, truncation,
extras-off ownership, and formatter-off construction.

MOVNTI forms 1692--1693 exactly own NP/OSZ=0 `0F C3 /r` with a memory-only
destination. Form 1692 writes a dword and reads a GPR32 in every mode; form
1693 is selected only by effective W in 64-bit mode and writes a qword while
reading a GPR64. `66`, F2, F3, LOCK, and register ModRM encodings are invalid;
address-size and segment prefixes remain valid. REX transports R/B/X/W, while
REX2 map 1 transports R/R4/B/B4/X/X4/W and independently requires APX-F in
addition to SSE2. Ordinary encodings require the SSE2 runtime selector; REX2
requires both SSE2 and APX selectors. Extras-off builds preserve allocated
ownership as unsupported after mode/profile validation. Intel syntax prints
the memory destination first with an explicit dword/qword size; AT&T reverses
the operands without adding a mnemonic suffix. The focused suite covers all
768 mode/ModRM cells, all 16 REX controls, all 256 REX2 controls, prefix
ordering, profiles, truncation, both formatters, and formatter-off builds.

The complete legacy non-temporal SIMD store rows are exact. Legacy `0F E7`
selects MMX `MOVNTQ` form 1696 without `66`, or SSE2 `MOVNTDQ` form 1691
with `66`. Legacy `0F 2B` selects SSE `MOVNTPS` form 1695, SSE2 `MOVNTPD`
form 1694 with `66`, and the SSE4a scalar collision siblings `MOVNTSD` and
`MOVNTSS` forms 1697--1698 with F2 and F3. Every form requires a memory
destination with the exact 32-, 64-, or 128-bit width and exposes the MMX or
XMM source register identity; LOCK and register destinations are invalid.
REX2 preserves the legacy opcode-field limit while extending address registers
only through the independent APX-F route.

The VEX forms 5869--5870/5874/5878--5879/5883 add 128- and 256-bit
`VMOVNTDQ`/`VMOVNTPD`/`VMOVNTPS`. The EVEX forms
5871--5873/5875--5877/5880--5882 add their 128-, 256-, and 512-bit variants,
including tuple-scaled disp8 and the reviewed APX B4/X4 address extensions.
VEX requires an encoded all-ones `vvvv`; EVEX additionally rejects masks,
zeroing, broadcast, the reserved vector-length selector, and invalid W/prefix
combinations. AVX and the width-specific AVX-512 family gates remain
independent, and EVEX B4/X4 additionally requires APX-F. Extras-OFF builds
retain structural ownership as unsupported after malformed, mode, and profile
checks. The focused suite covers all 4,608 legacy mode/ModRM cells, exhaustive
EVEX control bytes, VEX/EVEX register and address extensions, profile/runtime
gates, truncation precedence, exact form identity, and Intel/AT&T formatting.

`LDDQU` form 1574 exactly owns memory-only `F2 0F F0 /r` in 16-, 32-, and
64-bit modes. It writes XMM from m128, requires the SSE3 runtime selector and
an SSE3-capable profile, and applies the architectural `IGNORE66` rule even
when `66` occurs after F2. Ordinary REX transports R/B/X while W is ignored.
In 64-bit mode, REX2 map 1 uses R for XMM0--15, ignores R4 and W, and exposes
B/B4/X/X4 to address decoding; that route retains SSE3 selection and
independently requires APX/APX-F. LOCK, a missing or superseded F2, register
ModRM, and malformed REX2 controls are invalid.

`VLDDQU` forms 5583--5584 exactly own `VEX.128/256.F2.0F.WIG F0 /r`.
They write XMM/YMM from m128/m256, require AVX at both widths, accept both W
values, and require raw encoded `vvvv=1111`. Register ModRM, another mandatory
prefix, or noncanonical `vvvv` is invalid. Other maps and EVEX map-1/F0 remain
unowned and therefore report `UNSUPPORTED_INSTRUCTION`.
The focused suite sweeps every legacy ModRM in every mode, every VEX P1/ModRM
combination in every mode, all REX and REX2 extensions, profile/runtime gates,
formatting, truncation, and extras-OFF ownership. Fourteen reviewed seeds and
23 data-corpus rows retain the allocated and malformed boundaries.

Virtualization capabilities and their runtime selectors are vendor-specific.
`CDISASM_X86_DECODE_FLAG_VMX` (also
`CDISASM_X86_DECODE_FLAG_INTEL_VIRTUALIZATION`) selects only Intel VMX, while
`CDISASM_X86_DECODE_FLAG_SVM` (also
`CDISASM_X86_DECODE_FLAG_AMD_VIRTUALIZATION`) selects only AMD SVM. SMX uses
its independent bit and cannot admit VMX or SVM. Baseline VMX begins at
`CDISASM_CPU_INTEL_VT_X`; INVEPT and INVVPID use Nehalem as the named-profile
proxy for their independent capability controls, and VMFUNC uses Haswell.
Baseline SVM begins at `CDISASM_CPU_AMD_V` and continues only through later AMD
profiles. The SEV-ES VMGEXIT spelling is selected for the Zen 4 proxy; on older
SVM profiles its F2/F3 byte sequence retains VMMCALL semantics. These presets
cannot replace per-SKU CPUID and VMX-MSR inspection.

`cdisasm_mode` describes instruction decoding, not live execution state. It
does not expose CPL, protected versus real or compatibility mode, EFER.SVME,
VMX root/non-root state, SMM, intercepts, or virtualization control MSRs.
Consequently, instructions whose runtime checks depend on that state still
decode, while `CDISASM_GROUP_PRIVILEGED` marks forms with a CPL0 architectural
requirement.

The explicit profile constants are listed by their low-16-bit ordinals. Each
full ID is `CDISASM_CPU_GROUP_X86 | ordinal`:

| Ordinal | Constant | Target / profile |
| ---: | --- | --- |
| 1 | `CDISASM_CPU_8086` | 8086; `CDISASM_CPU_8088` is an alias |
| 2 | `CDISASM_CPU_80186` | 80186 |
| 3 | `CDISASM_CPU_80286` | 80286 protected-mode family |
| 4 | `CDISASM_CPU_80386` | 80386 and 32-bit mode |
| 5 | `CDISASM_CPU_80486` | 80486 without CPUID |
| 6 | `CDISASM_CPU_80486_CPUID` | Late 80486 with CPUID |
| 7 | `CDISASM_CPU_PENTIUM` | Pentium |
| 8 | `CDISASM_CPU_PENTIUM_PRO` | Pentium Pro / P6 |
| 9 | `CDISASM_CPU_PENTIUM_MMX` | Pentium MMX |
| 10 | `CDISASM_CPU_PENTIUM_II` | Pentium II |
| 11 | `CDISASM_CPU_AMD_K6_2` | AMD K6-2 |
| 12 | `CDISASM_CPU_PENTIUM_III` | Pentium III |
| 13 | `CDISASM_CPU_PENTIUM_4` | Pentium 4 |
| 14 | `CDISASM_CPU_ATHLON_64` | AMD Opteron/Athlon 64 and 64-bit mode |
| 15 | `CDISASM_CPU_PRESCOTT` | Prescott / Intel 64 adoption |
| 16 | `CDISASM_CPU_INTEL_VT_X` | Intel VT-x generation |
| 17 | `CDISASM_CPU_AMD_V` | AMD-V generation |
| 18 | `CDISASM_CPU_CORE_2` | Core 2 / SSSE3 era |
| 19 | `CDISASM_CPU_PENRYN` | Penryn / SSE4.1 era |
| 20 | `CDISASM_CPU_AMD_BARCELONA` | Barcelona / SSE4a, LZCNT, POPCNT |
| 21 | `CDISASM_CPU_NEHALEM` | Nehalem / SSE4.2, POPCNT |
| 22 | `CDISASM_CPU_WESTMERE` | Westmere / AES-NI era |
| 23 | `CDISASM_CPU_SANDY_BRIDGE` | Sandy Bridge / AVX era |
| 24 | `CDISASM_CPU_AMD_BULLDOZER` | Bulldozer / XOP and FMA4 era |
| 25 | `CDISASM_CPU_IVY_BRIDGE` | Ivy Bridge |
| 26 | `CDISASM_CPU_HASWELL` | Haswell / AVX2, BMI1/BMI2 era |
| 27 | `CDISASM_CPU_BROADWELL` | Broadwell / ADX era |
| 28 | `CDISASM_CPU_SKYLAKE` | Skylake |
| 29 | `CDISASM_CPU_GOLDMONT` | Goldmont / SHA-NI era |
| 30 | `CDISASM_CPU_AMD_ZEN` | AMD Zen |
| 31 | `CDISASM_CPU_SKYLAKE_SP` | Intel Skylake-SP / AVX-512 era |
| 32 | `CDISASM_CPU_ICE_LAKE` | 2019 Ice Lake client family; no HLE/RTM |
| 33 | `CDISASM_CPU_TIGER_LAKE` | Tiger Lake / CET era; no HLE/RTM |
| 34 | `CDISASM_CPU_ALDER_LAKE` | Alder Lake; no HLE/RTM |
| 35 | `CDISASM_CPU_AMD_ZEN_4` | AMD Zen 4 / AVX-512 era |
| 36 | `CDISASM_CPU_SAPPHIRE_RAPIDS` | Sapphire Rapids / AMX era; HLE and RTM |
| 37 | `CDISASM_CPU_AVX10` | Abstract AVX10 level; no inferred HLE/RTM |
| 38 | `CDISASM_CPU_APX` | Abstract APX level; no inferred HLE/RTM |
| 39 | `CDISASM_CPU_CELERON_G1840` | Exact Haswell Celeron G1840: x86-64 and SSE4.2, without AVX |
| 40 | `CDISASM_CPU_CELERON_G3900` | Exact Skylake Celeron G3900: x86-64 and SSE4.2, without AVX |
| 41 | `CDISASM_CPU_CELERON_N3350` | Exact Apollo Lake Celeron N3350: x86-64 and SSE4.2, without AVX |
| 42 | `CDISASM_CPU_CELERON_N4020` | Exact Gemini Lake Refresh Celeron N4020: x86-64 and SSE4.2, without AVX |
| 43 | `CDISASM_CPU_CELERON_G5900` | Exact Comet Lake Celeron G5900: x86-64 and SSE4.2, without AVX |
| 44 | `CDISASM_CPU_PENTIUM_SILVER_N6000` | Exact Jasper Lake Pentium Silver N6000: x86-64 and SSE4.2, without AVX |
| 45 | `CDISASM_CPU_8086_8087` | 8086/8088 plus optional 8087; 16-bit host mode and base x87 |
| 46 | `CDISASM_CPU_80186_80187` | 80186 plus 80C187; 16-bit host mode and the full 80387-compatible coprocessor set |
| 47 | `CDISASM_CPU_80286_80287` | 80286 plus 80287; 16-bit host mode and 287-era x87 additions |
| 48 | `CDISASM_CPU_80386_80387` | 80386 plus 80387; 16/32-bit host modes and 387-era x87 additions |
| 49 | `CDISASM_CPU_GRANITE_RAPIDS` | Granite Rapids; explicit 16/32/64-bit decode modes, AVX10.1, implemented AMX-FP16/COMPLEX forms, HLE, and RTM |
| 50 | `CDISASM_CPU_ARROW_LAKE` | Arrow Lake / Core Ultra 200; explicit 16/32/64-bit modes, modern SHA-512/SM3/SM4 and WAITPKG slices, without inferred HLE/RTM |
| 51 | `CDISASM_CPU_DIAMOND_RAPIDS` | Diamond Rapids; explicit 16/32/64-bit modes, implemented AVX10.1/2, APX-F, modern crypto, AMX-FP16/COMPLEX/FP8/MOVRS/AVX512, WAITPKG, HLE, and RTM slices; current `CDISASM_CPU_LATEST` |
| 52 | `CDISASM_CPU_KNIGHTS_MILL` | Exact Knights Mill specialist profile; explicit 16/32/64-bit decode modes, the implemented AVX512_4VNNIW pair, and the complete AVX512_4FMAPS family; current numeric `CDISASM_CPU_LAST` enumeration bound |

The exact [Celeron J4125](https://www.intel.com/content/www/us/en/products/sku/197305/intel-celeron-processor-j4125-4m-cache-up-to-2-70-ghz/specifications.html),
[Celeron G5905](https://www.intel.com/content/www/us/en/products/sku/201899/intel-celeron-processor-g5905-4m-cache-3-50-ghz/specifications.html),
and [Celeron N5105](https://www.intel.com/content/www/us/en/products/sku/212328/intel-celeron-processor-n5105-4m-cache-up-to-2-90-ghz/specifications.html)
are exposed as the same-capability aliases `CDISASM_CPU_CELERON_J4125`
(ordinal 42), `CDISASM_CPU_CELERON_G5905` (ordinal 43), and
`CDISASM_CPU_CELERON_N5105` (ordinal 44).

Plain 8086, 80186, 80286, and 80386 profiles reject x87 because those CPUs do
not prove that the optional external coprocessor is installed. The appended
combination profiles carry independent host-CPU and coprocessor capabilities;
for example, `CDISASM_CPU_80186_80187` gains the 80C187's full
80387-compatible x87 set but does not gain 80286 or 80386 integer/system
instructions or modes. The 80486-and-later milestone profiles have their
integrated 80387-level FPU. `CDISASM_CPU_X86` remains the explicit unrestricted
analysis profile.

The exact-model choice is deliberate. Celeron is a product brand spanning
multiple microarchitectures and feature combinations, so there is no generic
`CDISASM_CPU_CELERON` profile. Intel's official specifications identify the
[G1840](https://www.intel.com/content/www/us/en/products/sku/80800/intel-celeron-processor-g1840-2m-cache-2-80-ghz/specifications.html),
[G3900](https://www.intel.com/content/www/us/en/products/sku/90741/intel-celeron-processor-g3900-2m-cache-2-80-ghz/specifications.html),
[N3350](https://www.intel.com/content/www/us/en/products/sku/95598/intel-celeron-processor-n3350-2m-cache-up-to-2-40-ghz/specifications.html),
[N4020](https://www.intel.com/content/www/us/en/products/sku/197310/intel-celeron-processor-n4020-4m-cache-up-to-2-80-ghz/specifications.html),
[G5900](https://www.intel.com/content/www/us/en/products/sku/199268/intel-celeron-processor-g5900-2m-cache-3-40-ghz/specifications.html),
and [N6000](https://www.intel.com/content/www/us/en/products/sku/212330/intel-pentium-silver-n6000-processor-4m-cache-up-to-3-30-ghz/specifications.html)
as 64-bit parts whose supported vector extension level stops at SSE4.2 rather
than AVX. Intel's own [extension lookup instructions](https://www.intel.com/content/www/us/en/support/articles/000057621/processors.html)
direct users to each product's **Instruction Set Extensions** field.

This distinction cannot be represented by a width-only decode option. For
example, `C5 F8 77` is a valid 64-bit `VZEROUPPER` encoding in Capstone's normal
x86-64 mode, but mode alone does not say whether the target processor has AVX.
cdisasm accepts it for `CDISASM_CPU_SANDY_BRIDGE` and rejects it with
`CDISASM_STATUS_INVALID_INSTRUCTION` for each exact no-AVX profile. Conversely,
the SSE4.2 form `F2 0F 38 F0 C1` (`CRC32 eax, cl`) remains accepted. Capstone's
broader mode-only decode is useful for identifying arbitrary encodings;
cdisasm's CPU gate is stronger when the question is whether bytes are legal for
a declared deployment CPU.

An unknown CPU ID, invalid mode, or CPU/mode mismatch fails with
`CDISASM_STATUS_INVALID_ARGUMENT`. A structurally recognized encoding that the
selected CPU cannot execute fails with `CDISASM_STATUS_INVALID_INSTRUCTION`.
An instruction family not implemented by this decoder remains
`CDISASM_STATUS_UNSUPPORTED_INSTRUCTION`, regardless of the selected profile.
Structural decoding takes precedence: incomplete input reports
`CDISASM_STATUS_TRUNCATED` even when its prefix or partial opcode was introduced
after the selected CPU.

Mandatory-prefix aliases use the meaning available on the selected CPU:
pre-Pentium-4 `F3 90` is NOP rather than PAUSE; `F3 0F BC` and `F3 0F BD` fall
back to BSF and BSR without BMI1/LZCNT; and CET ENDBR encodings are legacy hint
NOPs on applicable pre-CET profiles. The original prefix bits remain present in
`opcode_flags`. For legacy SIMD opcodes, cdisasm intentionally accepts at most
one distinct mandatory-selector class among `66`, `F2`, and `F3`. Conflicting
classes, such as both `66` and `F3`, produce
`CDISASM_STATUS_INVALID_INSTRUCTION`; cdisasm does not choose a selector by
prefix order even where another decoder does.

### Undefined-instruction encodings

`UD1` is the P6 `0F B9 /r` form and always consumes ModRM, including any SIB
and displacement. Its two displayed operands are read-only and fixed at 32
bits in 16-, 32-, and 64-bit modes.

`UD0` byte consumption follows the selected Intel CPU profile. Pentium Pro
uses the operand-free two-byte `0F FF` form. Pentium II and Pentium III do not
enable UD0, matching Intel XED's chip tables. Pentium 4 and later non-Atom
Intel profiles consume the modern `0F FF /r` form, while Goldmont and the exact
N3350, N4020, and N6000 Atom-derived profiles use the short form. The
unrestricted `CDISASM_CPU_X86`
profile deterministically chooses the modern long form. Conservative named
AMD profiles enable neither UD0 nor UD1. Both names emit the
`CDISASM_X86_GROUP_P6` tag. `UD2` remains the separate operand-free `0F 0B`
encoding.

### 3DNow! encodings

The arithmetic form is `0F 0F /r selector`. The ModRM `reg` field selects the
MMX destination, the ModRM `r/m` field supplies an MMX register or 64-bit memory
source, and the final byte selects the operation. The decoder consumes ModRM,
SIB, and displacement bytes before reading the selector, and records the
selector byte in `encoding.selector_offset`. A missing selector is truncated;
an unassigned selector does not decode as an instruction.

| Selector | Base 3DNow! mnemonic | Selector | Base 3DNow! mnemonic |
| ---: | --- | ---: | --- |
| `0D` | `PI2FD` | `1D` | `PF2ID` |
| `90` | `PFCMPGE` | `94` | `PFMIN` |
| `96` | `PFRCP` | `97` | `PFRSQRT` |
| `9A` | `PFSUB` | `9E` | `PFADD` |
| `A0` | `PFCMPGT` | `A4` | `PFMAX` |
| `A6` | `PFRCPIT1` | `A7` | `PFRSQIT1` |
| `AA` | `PFSUBR` | `AE` | `PFACC` |
| `B0` | `PFCMPEQ` | `B4` | `PFMUL` |
| `B6` | `PFRCPIT2` | `B7` | `PMULHRW` |
| `BF` | `PAVGUSB` |  |  |

| Selector | Extended 3DNow! mnemonic | Selector | Extended 3DNow! mnemonic |
| ---: | --- | ---: | --- |
| `0C` | `PI2FW` | `1C` | `PF2IW` |
| `8A` | `PFNACC` | `8E` | `PFPNACC` |
| `BB` | `PSWAPD` |  |  |

`0F 0E` decodes as `FEMMS`. `0F 0D /0` and `/1` decode as `PREFETCH` and
`PREFETCHW`, respectively, when the selected CPU profile has the independent
hint capability described above. These encodings use a byte-sized memory
operand rather than an MMX register operand.

`opcode_groups` contains the existing semantic instruction-classification
flags. It is not an ISA-extension mask; the version-4 meaning is retained by
the current x86 result. In `opcode_flags`, the low `CDISASM_PREFIX_LOCK`, `REP`,
and `REPNE` bits record every encountered group-1 prefix class, while exactly zero
or one of `CDISASM_PREFIX_EFFECTIVE_LOCK`, `EFFECTIVE_REP`, and
`EFFECTIVE_REPNE` records the ordinary effective action. LOCK remains effective
when an F2/F3 HLE hint is also present. `CDISASM_PREFIX_XACQUIRE` and
`CDISASM_PREFIX_XRELEASE` record the HLE meaning of the rightmost encountered
F2/F3 prefix and may coexist with `CDISASM_PREFIX_EFFECTIVE_LOCK`; successful
HLE results also carry `CDISASM_X86_GROUP_HLE`. A direct relative branch has
`CDISASM_GROUP_RELATIVE_BRANCH`, which also makes `branch_target` valid even
when its value is zero.

### x86 ISA group IDs

Successful results include a bounded list describing the ISA
families used by the effective encoding:

- `x86_group_count` is an 8-bit count from one through
  `CDISASM_MAX_X86_GROUPS` (15) on success; it is zero in a zeroed failure
  result.
- `x86_group_reserved` is an 8-bit reserved field and is always zero.
- The first `x86_group_count` entries of `x86_group_ids[15]` are sorted in
  ascending numeric order and contain no duplicates. Each entry is a 16-bit
  `cdisasm_x86_group_id`; unused entries are zero.

`cdisasm_instruction_has_x86_group()` performs a bounded membership query.
These tags describe the particular decoded form, not all transitive ancestor
ISAs and not every feature present in the selected processor. For example, a
mnemonic, register form, prefix, or addressing form can add its own required
group, and some forms therefore have more than one tag.

The catalog is deliberately broader than current decoder coverage. A defined
`CDISASM_X86_GROUP_*` value means the family can be represented; it does not
mean all of its encodings are implemented. Successfully decoded forms are
tagged accurately. The D8--DF x87 maps, Base and Extended 3DNow!, the
VEX2/VEX3 VZERO forms, the 60 map-1 VEX operations, and the published
VEX FMA3, EVEX FMA3, FMA4, cataloged XOP, and classic 51-name VEX K-mask
families, plus the complete packed-integer EVEX compare-to-mask, MIN/MAX,
multiply/multiply-add, modular/wrapping ADD/SUB, and signed/unsigned
saturating ADD/SUB matrices, the complete D/Q logical and byte/word average
classes, the word/dword/qword per-element variable-shift classes, and their
exact APX P0.B4 and variable-shift U0/X4 routes, plus the dword/qword variable
and immediate packed-rotate classes, the opcode-`72` immediate shifts, the
opcode-`71`/`73` word/qword/byte-lane groups, AVX512VBMI2 double shifts,
COMPRESS/EXPAND, BITALG/VPOPCNT, all six AVX-512CD operations, the four
AVX-512 VNNI dot products, the classic VEX AVX-VNNI, AVX-VNNI-INT8, and
AVX-VNNI-INT16 rows, the exact Knights Mill `VP4DPWSSD`/`VP4DPWSSDS`
AVX512_4VNNIW pair, the complete four-name AVX512_4FMAPS family, the exact
AVX512F/AVX10.1 VGETEXP PS/PD/SS/SD tranche, the exact MAP6
AVX512-FP16/AVX10.1 PH/SH and AVX10.2 BF16 GETEXP forms, the classic
AVX512_VBMI byte-permute/multishift slice, and the AVX512BW/AVX10
`VPERMI2W`/`VPERMT2W`/`VPERMW` rows with their
stated APX routes are implemented when
`USE_EXTRA_OPCODES=1` and their documented runtime gates are selected.
AVX512_4VNNIW and AVX512_4FMAPS reuse the AVX-512 runtime umbrella and retain
independent exact Knights Mill CPU gates.
The optional generated catalog additionally retains all 10,994 descriptors and
9,001 IFORM identities from the pinned XED export, including the formerly
unlisted VEX/AVX/AVX2, EVEX, AVX-512, AVX10, APX, and AMX records. A generated
form is considered only after the hand decoder reports unsupported and remains
subject to CPU and runtime-family admission. Generated inventory coverage does
not prove every late register relation, prefix action, or execution-state rule;
those remain semantic-validation gaps. Retired and dropped extensions keep
their IDs permanently so stored records remain interpretable.

`CDISASM_X86_GROUP_NONE` is zero and is never a list member. The established
values 1 through 109 are below; generated exact ISA-set groups are appended
through ID 322. Table names omit the common `CDISASM_X86_GROUP_` prefix, and
the current `CDISASM_X86_GROUP_COUNT` is 323 including the zero slot.
Alternative spellings exposed by the compatibility wrapper
`<cdisasm/cdisasm_ids.h>` are exact aliases and do not allocate additional
values or denote a union. In particular, `FMA` maps
only to `FMA3`, `BMI` to `BMI1`, `AVX512` to `AVX512F`, `AMX` to `AMX_TILE`,
and `AVX10` to `AVX10_1`; sibling feature IDs remain distinct.

| Era / scope | IDs and canonical suffixes | Lifecycle / scope note |
| --- | --- | --- |
| Base generations | `1=I86`, `2=I186`, `3=I286`, `4=I386`, `5=I486`, `6=X87`, `7=CPUID` | Baseline integer generations, x87, and the separately identifiable CPUID facility. |
| Pentium and P6 | `8=PENTIUM`, `9=P6`, `10=CMOV`, `11=FCMOV`, `12=FCOMI`, `13=MMX`, `14=SEP`, `15=FXSR` | P5/P6-era facilities; `SEP` covers SYSENTER/SYSEXIT and `FXSR` covers FXSAVE/FXRSTOR. |
| AMD late-1990s | `16=3DNOW`, `17=3DNOW_EXT`, `18=PREFETCHW` | 3DNow! and 3DNow! Extended were later dropped; their IDs remain. PREFETCHW is cataloged separately. |
| SSE and long mode | `19=SSE`, `20=SSE2`, `21=CLFLUSH`, `22=PAUSE`, `23=AMD64`, `24=SSE3`, `25=MONITOR_MWAIT` | Includes AMD64/x86-64 and the first three SSE generations. |
| Virtualization and Core-era SIMD | `26=VMX`, `27=SVM`, `28=SSSE3`, `29=SSE41`, `30=SSE4A`, `31=LZCNT`, `32=POPCNT`, `33=SSE42` | Intel VMX and AMD SVM are distinct; SSE4a and LZCNT also follow vendor-specific introduction paths. |
| Crypto, state, and AVX | `34=AESNI`, `35=PCLMULQDQ`, `36=XSAVE`, `37=AVX` | Independent feature groups rather than an implied bundle. |
| AMD Bulldozer-era extensions | `38=XOP`, `39=FMA4`, `40=TBM`, `41=LWP` | AMD-specific extensions that were dropped or retired; all IDs remain valid. |
| Ivy Bridge / Haswell era | `42=XSAVEOPT`, `43=RDRAND`, `44=F16C`, `45=FSGSBASE`, `46=AVX2`, `47=FMA3`, `48=BMI1`, `49=BMI2`, `50=HLE`, `51=RTM`, `52=MOVBE`, `53=INVPCID` | HLE/RTM availability and enablement vary by product and stepping; numeric ordering is not a support guarantee. |
| Broadwell / Skylake era | `54=ADX`, `55=RDSEED`, `56=SGX`, `57=MPX`, `58=CLFLUSHOPT`, `59=XSAVEC`, `60=XSAVES`, `61=SHA` | MPX was later dropped; SGX is product/platform-specific. Retired IDs are not reused. |
| AVX-512 foundation | `62=AVX512F`, `63=AVX512CD`, `64=AVX512ER`, `65=AVX512PF`, `66=AVX512DQ`, `67=AVX512BW`, `68=AVX512VL` | Subfeatures are separate; ER and PF were associated with discontinued Xeon Phi products. |
| AVX-512 and vector expansion | `69=AVX512IFMA`, `70=AVX512VBMI`, `71=AVX512_4VNNIW`, `72=AVX512_4FMAPS`, `73=AVX512VPOPCNTDQ`, `74=AVX512VNNI`, `75=AVX512VBMI2`, `76=GFNI`, `77=VAES`, `78=VPCLMULQDQ`, `79=AVX512BITALG`, `80=AVX512VP2INTERSECT` | The 4VNNIW/4FMAPS groups were specialized Xeon Phi facilities. Version 11.23 implements the exact two-name 4VNNIW pair; version 11.24 implements the complete four-name 4FMAPS family. The pinned 36-form GFNI inventory is complete; each other subfeature is independently identifiable. |
| CET and neural extensions | `81=CET_IBT`, `82=CET_SS`, `83=AVX_VNNI`, `84=AVX512BF16` | CET indirect-branch tracking and shadow stack are separate groups. |
| AMX and FP16 | `85=AMX_TILE`, `86=AMX_INT8`, `87=AMX_BF16`, `88=AVX512FP16` | AMX subfeatures and AVX-512 FP16 remain independently tagged. |
| Current specification families | `89=AVX10_1`, `90=AVX10_2`, `91=APX_F` | AVX10 and APX specifications continue to evolve. These IDs identify the named published feature levels, not blanket hardware, OS, or toolchain availability; future distinctions append new IDs. |
| Append-only additions | `92=SMX`, `93=AMX_FP16`, `94=WAITPKG` | Numeric positions reflect catalog addition order, not historical chronology. SMX covers Intel Safer Mode Extensions (`GETSEC`); AMX-FP16 is independent from AMX-BF16 and AMX-INT8; WAITPKG identifies the user monitor/wait package independently from the broad SYSTEM runtime-family bit. |
| Version-11 crypto and matrix additions | `95=SHA512`, `96=SM3`, `97=SM4`, `98=AMX_COMPLEX`, `99=AMX_FP8`, `100=AMX_MOVRS`, `101=AMX_AVX512` | Modern crypto and AMX subfeatures remain independently tagged; these IDs do not imply complete family coverage. |
| Version-11 cache and system additions | `102=CLWB`, `103=RDPID`, `104=SERIALIZE`, `105=MOVDIRI`, `106=MOVDIR64B`, `107=WBNOINVD` | Each facility has an independent CPU capability even where encodings share a selector map. CLWB uses the MEMORY_HINTS runtime bit; the listed system forms use SYSTEM. |
| Version-11.21 neural addition | `108=AVX_VNNI_INT8` | The classic VEX INT8 dot-product row has a separate runtime selector and CPU capability from `AVX_VNNI` and `AVX512VNNI`. |
| Version-11.22 neural addition | `109=AVX_VNNI_INT16` | The classic VEX INT16 dot-product row has independent runtime bit 63 and CPUID.7.1.EDX[10] admission; its catalog presence does not imply broader AVX-VNNI coverage. |

ISA group numbers are not CPU levels. CPU-profile availability remains a
separate vendor-aware, non-monotonic capability decision: Intel and AMD
branches are not supersets of one another, newer numeric CPU IDs do not imply
every earlier vendor extension, and current products can omit previously
offered features. The unrestricted `CDISASM_CPU_X86` profile bypasses profile
filtering only for instruction families the decoder actually implements.

`opcode[0..operand_count)` contains at most five explicit/display operands in
Intel order. Operand kinds use the stable values `NONE=0`, `REGISTER=1`,
`IMMEDIATE=2`, and `MEMORY=3`; unused records are zero. `size` is an operand
width in bytes (the encoded width for immediate operands). `access` is one of
`CDISASM_OPERAND_ACCESS_NONE`, `CDISASM_OPERAND_ACCESS_READ`,
`CDISASM_OPERAND_ACCESS_WRITE`, or `CDISASM_OPERAND_ACCESS_READ_WRITE`; it
describes the architectural use of that operand without changing its display
order. `broadcast` is `CDISASM_X86_BROADCAST_NONE` for an ordinary operand or
the destination element count for a memory broadcast. The nonzero constants
are `CDISASM_X86_BROADCAST_1_TO_2` through `_1_TO_64` for the supported powers
of two.

Instruction-level decorator fields remain separate from operands. `mask_reg`
is `CDISASM_X86_REG_NONE` or an active `K1` through `K7` register (`K0`
encodes the architectural no-mask case and is represented as `NONE`). `mask_mode` is
`CDISASM_X86_MASK_NONE`, `CDISASM_X86_MASK_MERGE`, or
`CDISASM_X86_MASK_ZERO`; a nonzero mode applies to the first display operand.
`rounding` is `CDISASM_X86_ROUNDING_NONE`, `_RN`, `_RD`, `_RU`, or `_RZ`, and
`sae` is `CDISASM_X86_SAE_NONE` or `CDISASM_X86_SAE_ENABLED`. All are numeric
fields. Zero is the undecorated value for every field, so a zero-initialized
result remains well formed.

### x86 register IDs

The `reg`, `base_reg`, `index_reg`, `segment_reg`, and instruction `mask_reg`
fields are
`cdisasm_x86_reg_id` values. Their canonical numeric preprocessor definitions
are `CDISASM_X86_REG_*` in `<cdisasm/cdisasm_x86_ids.h>`. IDs are width-specific, so
`AH`, `SPL`, `EAX`, and `RAX` remain distinguishable. The current definitions
cover the byte, word, doubleword, and quadword general registers through R31,
instruction pointers, segment registers, CR0-CR15, DR0-DR15, x87 stack and MMX
registers, XMM/YMM/ZMM vector registers, K mask registers, BND bound registers,
TMM tile registers, and the opaque ACE `BSR0` state register.

`CDISASM_X86_REG_NONE` is zero, `CDISASM_X86_REG_FIRST` is `AL`, and
`CDISASM_X86_REG_LAST` is `BSR0`. Published values are never renumbered. IDs 78
and 79 remain permanent reserved ABI holes between `GS=77` and `CR0=80`; they
are not registers and must not be used. The version 4 namespace appends new
ranges after the version 3 endpoint in this order: `ST0-ST7`, `MM0-MM7`,
`XMM0-XMM31`, `YMM0-YMM31`, `ZMM0-ZMM31`, `K0-K7`, `BND0-BND3`, `TMM0-TMM7`,
the byte, word, doubleword, and quadword forms of `R16-R31`, and `BSR0=308`.
`BSR0` is 128 bytes of opaque architectural state in public operand metadata;
it is marked implicit but remains visible in the ACE BSR syntax. The two
permanent holes leave 307 defined IDs in the 309-slot space.
`CDISASM_X86_REG_COUNT` is 309 and is the exclusive numeric bound, not the number of named
definitions. `cdisasm_x86_reg_id` is an unsigned 16-bit ABI type in version 4;
`CDISASM_REG_*` and `cdisasm_register_id` remain source-compatible aliases.

For an ordinary immediate, `imm` is its semantic value. Values architecturally
sign-extended by the instruction have `CDISASM_OPERAND_FLAG_SIGNED` and are
stored sign-extended to 64 bits. For a PC-relative branch operand, `imm` is the
resolved target and `address` is the signed encoded displacement; the operand
has `SIGNED`, `PC_RELATIVE`, and `HAS_ADDRESS` flags.

A memory operand uses `base_reg + index_reg * scale + displacement`:

- `base_reg`, `index_reg`, and `segment_reg` are zero when absent.
- `scale` is zero without an index, otherwise 1, 2, 4, or 8.
- `imm` contains the signed displacement bit pattern.
- `address` contains a resolved static address only with `HAS_ADDRESS`. This is
  available for absolute and instruction-pointer-relative references.
- `ADDRESS_ONLY` identifies an address calculation such as `lea` rather than a
  memory access. `IMPLICIT` identifies operands supplied by string, port-I/O,
  AMD SVM, and legacy variable-blend instructions rather than explicitly
  encoded operand fields.

### Encoding-field metadata

`encoding` describes where the effective x86 fields occur in the original
instruction. Every offset is relative to its first byte:

- `prefix_size` counts the consumed prefix bytes; `opcode_offset` and the
  nested `opcode_size` locate the contiguous primary opcode bytes. This nested
  size is distinct from `cdisasm_instruction.opcode_size`, which is the total
  instruction length returned by `cdisasm_decode`. For an implemented VEX2 or
  VEX3 form, the complete two- or three-byte VEX sequence is counted as the
  prefix and `CDISASM_PREFIX_VEX` is set; any preceding address-size or segment
  prefix is included in both `prefix_size` and `opcode_offset`.
- `modrm_offset`/`modrm` and `sib_offset`/`sib` locate and retain the raw ModRM
  and SIB bytes.
- `displacement_offset` and `displacement_size` locate the encoded
  displacement, independently of its sign-extended semantic value in an
  operand.
- `immediate_count` is zero, one, or two. The corresponding entries in
  `immediate_offset[2]` and `immediate_size[2]` locate each encoded immediate.
- `selector_offset` locates the trailing selector in a `0F 0F /r selector`
  3DNow! encoding. It is not reported as an immediate operand.

An absent ModRM, SIB, displacement, immediate, or selector has a zero
size/count and zero offset/value fields. Unused array entries and the reserved
byte are zero. The descriptor is numeric and does not retain a pointer to the
input bytes.

### x86 name IDs

`name_id` is a `cdisasm_x86_name_id` and uses the numeric preprocessor
definitions in `<cdisasm/cdisasm_x86_ids.h>`. The canonical spellings are
`CDISASM_X86_NAME_*`; for example, MOV is `CDISASM_X86_NAME_MOV`. The complete
header list is authoritative and can be consumed by C/C++ preprocessor checks
and simple FFI header parsers.

`CDISASM_X86_NAME_NONE` is zero, `CDISASM_X86_NAME_FIRST` is the first mnemonic,
and `CDISASM_X86_NAME_LAST` is the current last mnemonic. Values are append-only:
published IDs are never reordered or renumbered. `CDISASM_X86_NAME_COUNT` is the
exclusive upper bound and includes the zero `NONE` slot in its count. The older
`CDISASM_NAME_*` spellings remain source-compatible aliases of the x86 names.
Version 4.0 appends IDs for `FEMMS`, every base and Extended 3DNow! selector
listed above, `PREFETCH`, and `PREFETCHW`. Version 4.1 then appends `UD0` and
`UD1`; version 5.1 appends `VZEROALL` and `VZEROUPPER`; version 5.2 appends the
implemented legacy SSE-family mnemonic IDs. In version 5.2, that appended range
starts at `MOVUPS` (272) and ends at `INSERTQ` (509). Later releases append the
x87 range from `F2XM1` (510) through the undocumented
`FSTPNCE` compatibility mnemonic (609). The optional VEX tranche appends
`VADDPS` (610) through `VPSADBW` (669). Later optional families continue
append-only through `VPCLMULQDQ` (736), followed by `RDRAND` (737), `RDSEED`,
and the RTM control names through `XTEST` (742). Version 10.1 appends the
remaining FMA3 names through `VFNMSUB231SD` (796), expanded VAES names through
`VAESKEYGENASSIST` (801), `TDPFP16PS` (802), `JMPABS` (803), the remaining
FMA4 names (804--819), eight XOP variable-shift names (820--827), and twelve
CET shadow-stack names from `CLRSSBSY` (828) through `WRUSSQ` (839).
Version 10.2 appends `UMONITOR` (840), `UMWAIT` (841), and `TPAUSE` (842).
Version 11.0 then appends the bounded modern range 843--993:

- cataloged XOP map-9 names `VFRCZPS` (843) through `VPHSUBDQ` (861), followed
  by the remaining cataloged XOP map-8 and `/is4` names `VPMACSSWW` (862)
  through `VPERMIL2PD` (884);
- vector crypto `VSHA512MSG1` (885) through `VSM4RNDS4` (892), common VEX
  arithmetic/conversion additions `VADDSUBPD` (893) through `VCVTSS2SD` (916),
  and cache/system names `CLFLUSH` (917) through `WBNOINVD` (924);
- AMX-COMPLEX/FP8/MOVRS and AMX-to-vector row names `TCMMIMFP16PS` (925)
  through `TILEMOVROW` (938), followed by AVX10.2 BF16 arithmetic
  `VADDBF16` (939) through `VDIVBF16` (942); and
- the complete classic 51-name VEX K-mask family `KANDNW` (943) through
  `KXORQ` (993).

Version 11.1 appends the packed-integer EVEX compare-to-mask names `VPCMPB`
(994), `VPCMPW` (995), `VPCMPD` (996), `VPCMPQ` (997), `VPCMPUB` (998),
`VPCMPUW` (999), `VPCMPUD` (1000), and `VPCMPUQ` (1001). Consequently
`CDISASM_X86_NAME_COUNT` is 1002 in both option variants.
No release reuses a historical ID.

Version 11.2 reuses the existing `VPMAXSW` (665), `VPMAXUB` (666),
`VPMINSW` (667), and `VPMINUB` (668) names, then appends `VPMINSB` (1002)
through `VPMAXUQ` (1013). `CDISASM_X86_NAME_COUNT` is therefore 1014 in both
option variants. Together these 16 names realize all 48 XMM/YMM/ZMM register
forms in the bounded EVEX packed signed/unsigned MIN/MAX class, plus memory and
legal dword/qword broadcast forms. Existing numeric IDs are unchanged.

Version 11.3 reuses `VPMULLW` (660), `VPMULUDQ` (661), and `VPMADDWD`
(662), then appends `VPMULLD` (1014) through `VPMADDUBSW` (1020).
`CDISASM_X86_NAME_COUNT` is therefore 1021 in both option variants. These ten
names complete the classic EVEX packed-integer multiply/multiply-add class at
128, 256, and 512 bits: 30 register forms, 30 full-width memory forms, and 12
legal scalar-broadcast forms, with masking, zeroing, compressed displacement,
and exact AVX-512F/DQ/BW/VL versus AVX10.1 admission.

Version 11.4 reuses the established `VPADDB` (642), `VPADDW` (643),
`VPADDD` (644), `VPADDQ` (645), `VPSUBB` (646), `VPSUBW` (647),
`VPSUBD` (648), and `VPSUBQ` (649) IDs. The public x86 name count therefore
remains 1021. These eight names complete the EVEX.66.0F packed-integer
modular/wrapping ADD/SUB matrix at all three vector lengths: 24 register
forms, 24 full-width memory forms, and 12 legal dword/qword scalar-broadcast
forms.

Version 11.5 appends `VPADDSB` (1021), `VPADDSW` (1022), `VPADDUSB`
(1023), `VPADDUSW` (1024), `VPSUBSB` (1025), `VPSUBSW` (1026),
`VPSUBUSB` (1027), and `VPSUBUSW` (1028).
`CDISASM_X86_NAME_COUNT` is therefore 1029 in both option variants. These
eight names complete the signed/unsigned saturating packed byte/word ADD/SUB
family through VEX.128/256 and EVEX.128/256/512, without renumbering an
earlier ID or changing the result layout.

Version 11.6 appends `VPANDD` (1029), `VPANDQ` (1030), `VPANDND` (1031),
`VPANDNQ` (1032), `VPORD` (1033), `VPORQ` (1034), `VPXORD` (1035), and
`VPXORQ` (1036). `CDISASM_X86_NAME_COUNT` is therefore 1037 in both option
variants. These names complete the EVEX.66.0F packed D/Q logical class; the
same release reuses existing `VPAVGB` (663) and `VPAVGW` (664) for the
complete EVEX packed byte/word average class. No earlier ID or result layout
changes.

Version 11.7 appends `VPSLLVD` (1037), `VPSLLVQ` (1038), `VPSRLVD`
(1039), `VPSRLVQ` (1040), `VPSRAVD` (1041), and `VPSRAVQ` (1042).
`CDISASM_X86_NAME_COUNT` is therefore 1043 in both option variants. These six
names complete the dword/qword per-element variable packed-shift tranche through its
allocated VEX.128/256 and EVEX.128/256/512 forms without changing an earlier
ID or the fixed result layout.

Version 11.8 appends `VPSLLVW` (1043), `VPSRLVW` (1044), and `VPSRAVW`
(1045). `CDISASM_X86_NAME_COUNT` is therefore 1046 in both option variants.
These names complete the adjacent EVEX word variable-shift class without
changing an earlier ID or the fixed result layout.

Version 11.9 appends `VPROLVD` (1046), `VPROLVQ` (1047), `VPRORVD`
(1048), and `VPRORVQ` (1049). `CDISASM_X86_NAME_COUNT` is therefore 1050 in
both option variants. These names complete the exact EVEX dword/qword variable
packed-rotate class without changing an earlier ID or the fixed result layout.

Version 11.10 appends `VPROLD` (1050), `VPROLQ` (1051), `VPRORD` (1052),
and `VPRORQ` (1053). `CDISASM_X86_NAME_COUNT` is therefore 1054 in both
option variants. These names complete the exact EVEX dword/qword immediate
packed-rotate class without changing an earlier ID or the fixed result layout.

Version 11.11 appends `VPSRLD` (1054), `VPSRAD` (1055), `VPSRAQ` (1056),
and `VPSLLD` (1057). `CDISASM_X86_NAME_COUNT` is therefore 1058 in both
option variants. These names complete every allocated extension/W control in
the exact EVEX.66.0F opcode-`72` immediate packed rotate/shift group without
changing an earlier ID or the fixed result layout.

Version 11.12 appends `VPSRLW` (1058), `VPSRAW` (1059), `VPSLLW` (1060),
`VPSRLQ` (1061), `VPSRLDQ` (1062), `VPSLLQ` (1063), and `VPSLLDQ` (1064).
`CDISASM_X86_NAME_COUNT` is therefore 1065 in both option variants. These
names fill only the allocated controls in the exact EVEX.66.0F opcode-`71`
and opcode-`73` immediate-shift groups; the append does not change an earlier
ID or the fixed result layout.

Version 11.13 appends `VPSHLDW` (1065), `VPSHLDD` (1066), `VPSHLDQ` (1067),
`VPSHLDVW` (1068), `VPSHLDVD` (1069), `VPSHLDVQ` (1070), `VPSHRDW` (1071),
`VPSHRDD` (1072), `VPSHRDQ` (1073), `VPSHRDVW` (1074), `VPSHRDVD` (1075),
and `VPSHRDVQ` (1076). `CDISASM_X86_NAME_COUNT` is therefore 1077 in both
option variants. These names complete only the exact AVX512VBMI2 EVEX
map-2/map-3 double-shift slice without changing an earlier ID or the fixed
result layout.

Version 11.14 appends `VPCOMPRESSB` (1077), `VPCOMPRESSW` (1078),
`VPCOMPRESSD` (1079), `VPCOMPRESSQ` (1080), `VPEXPANDB` (1081),
`VPEXPANDW` (1082), `VPEXPANDD` (1083), and `VPEXPANDQ` (1084).
It then appends `VPOPCNTB` (1085), `VPOPCNTW` (1086), `VPOPCNTQ` (1087),
and `VPSHUFBITQMB` (1088), while reusing `VPOPCNTD` (716).
`CDISASM_X86_NAME_COUNT` is therefore 1089 in both option variants. These
names complete only the exact mandatory-`66` EVEX map-2 COMPRESS/EXPAND and
bounded BITALG/VPOPCNT rows; no earlier ID or fixed result layout changes.

Version 11.15 appends `VPCONFLICTD` (1089), `VPCONFLICTQ` (1090),
`VPLZCNTD` (1091), and `VPLZCNTQ` (1092).
`CDISASM_X86_NAME_COUNT` is therefore 1093 in both option variants. These
names complete only the exact mandatory-`66` EVEX map-2 AVX-512CD
conflict/leading-zero-count class; no earlier ID or fixed result layout
changes.

Version 11.16 appends `VPBROADCASTMB2Q` (1093) and `VPBROADCASTMW2D` (1094).
`CDISASM_X86_NAME_COUNT` is therefore 1095 in both option variants. Together
with the four version-11.15 names, these register-only rows complete the six
mnemonics in AVX-512CD without changing an earlier ID or fixed result layout.

Version 11.17 retains the existing `VPDPBUSD` ID 715 and appends
`VPDPBUSDS` (1095), `VPDPWSSD` (1096), and `VPDPWSSDS` (1097).
`CDISASM_X86_NAME_COUNT` is therefore 1098 in both option variants. These
names complete only the four-operation EVEX AVX-512 VNNI dot-product row;
they do not imply complete VNNI, AVX-512, or AVX10 coverage.

Version 11.18 retains the existing `VPERMB` ID 714 and appends `VPERMI2B`
(1098), `VPERMT2B` (1099), and `VPMULTISHIFTQB` (1100).
The 11.18 `CDISASM_X86_NAME_COUNT` was therefore 1101 in both option variants. These
four names complete the exact classic EVEX AVX512_VBMI byte
permute/multishift slice. At that release boundary the allocated W=1 word
siblings remained explicitly unsupported.

Version 11.19 appends `VPERMI2W` (1101), `VPERMT2W` (1102), and `VPERMW`
(1103), so `CDISASM_X86_NAME_COUNT` was 1104 in both option variants at that
release.
Legacy admission uses AVX512BW, while AVX10.1 is an independent alternative;
this scoped completion does not imply complete AVX-512, AVX10, or APX coverage.

Version 11.20 reuses `VPDPBUSD` (715), `VPDPBUSDS` (1095), `VPDPWSSD`
(1096), and `VPDPWSSDS` (1097), so the x86 name count remains 1104. It owns
the exact classic `VEX.NDS.128/256.66.0F38.W0` opcode-`50`--`53` AVX-VNNI
row. The destination is read/write, the encoded `vvvv` source and register or
full-width memory ModRM source are read, and W=1 is structurally invalid.
Other prefix and map neighbors remain unowned. Runtime admission requires the
narrow `CDISASM_X86_DECODE_FLAG_AVX_VNNI` bit 61 independently of CPU
capability. Alder Lake, Arrow Lake, Sapphire Rapids, Granite Rapids, and
Diamond Rapids are positive physical profiles; the abstract AVX10 and APX
profiles also expose the capability. Haswell, Ice Lake, Tiger Lake, and AMD
Zen 4 are negative boundaries. At the 11.20 boundary, AVX-VNNI-INT8/INT16
remained outside this exact row; version 11.21 implements the six-operation
INT8 subset and version 11.22 implements the bounded six-operation INT16 row,
while broader VEX and EVEX coverage remains incomplete.

Version 11.21 appends `VPDPBSSD` (1104), `VPDPBSSDS` (1105), `VPDPBSUD`
(1106), `VPDPBSUDS` (1107), `VPDPBUUD` (1108), and `VPDPBUUDS` (1109),
making `CDISASM_X86_NAME_COUNT` 1110. It also appends group 108,
`CDISASM_X86_GROUP_AVX_VNNI_INT8`, and runtime-family bit 62,
`CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8`. The exact classic
`VEX.NDS.128/256.0F38.W0` map-2 opcodes `50`/`51` use F2 for signed-by-signed,
F3 for signed-by-unsigned, and no mandatory prefix for unsigned-by-unsigned.
The destination is read/write; encoded `vvvv` and register or full-width
memory sources are read; no broadcast or masking is synthesized. Across both
lengths and every ModRM value, 3,072 forms are allocated and the corresponding
3,072 W=1 controls are reserved. Non-66 opcode-`52`/`53` and map-3 neighbors
remain unowned. Runtime and CPU admission are independent: the narrow bit is
necessary but CPUID leaf 7 subleaf 1 EDX bit 4 must also be available.
`CDISASM_CPU_X86`, Arrow Lake, and Diamond Rapids admit the class; every other current
named profile rejects it.

Version 11.22 appends `VPDPWSUD` (1110), `VPDPWSUDS` (1111), `VPDPWUSD`
(1112), `VPDPWUSDS` (1113), `VPDPWUUD` (1114), and `VPDPWUUDS` (1115),
making `CDISASM_X86_NAME_COUNT` 1116. It also appends group 109,
`CDISASM_X86_GROUP_AVX_VNNI_INT16`, and runtime-family bit 63,
`CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16`. The exact classic
`VEX.NDS.128/256.0F38.W0` map-2 opcodes `D2`/`D3` use F3 for signed-by-
unsigned, 66 for unsigned-by-signed, and no mandatory prefix for unsigned-by-
unsigned; `D2` is non-saturating and `D3` saturating. Across both lengths and
every ModRM value, 3,072 W=0 controls are allocated and 3,072 W=1 controls are
reserved. Runtime and CPU admission remain independent: bit 63 is necessary
but the CPU must expose CPUID leaf 7 subleaf 1 EDX bit 10. Intel XED supplies
that CPUID mapping and the focused encoding oracle. The unrestricted
`CDISASM_CPU_X86` profile and the Arrow Lake and Diamond Rapids named profiles
admit the class; Granite Rapids and every other current named profile reject
it. At the version-11 boundary, the use of bit 63 made the bitmap-0 `ALL` and
`KNOWN_MASK` values `UINT64_MAX` and exhausted that release's scalar
`uint64_t` family-selector namespace. Version 12 retains those bitmap-0 values
inside its extensible 512-bit object.

Version 11.23 appends `VP4DPWSSD` (1116) and `VP4DPWSSDS` (1117), making
`CDISASM_X86_NAME_COUNT` 1118. Both use the existing group 71,
`CDISASM_X86_GROUP_AVX512_4VNNIW`, and existing runtime bit 19,
`CDISASM_X86_DECODE_FLAG_AVX512`, because version 11 had already assigned all
bitmap-0 bits 0--63.
This compatibility-umbrella reuse does not weaken CPU selection: an independent
AVX512_4VNNIW capability admits the pair only for unrestricted
`CDISASM_CPU_X86` or exact `CDISASM_CPU_KNIGHTS_MILL`. The two memory-only
`EVEX.512.F2.0F38.W0` map-2 opcodes `52`/`53` require U=1 and B=0, consume an
m128 Tuple1_4X source with disp8 scale 16, and display the encoded four-ZMM
source block as `zmmN+3`. Register ModRM, W=1, other vector lengths, U=0, B=1,
and zeroing with k0 are reserved. The version-11 public runtime mask remained
`UINT64_MAX`; no bitmap-0 family bit was reassigned.

Version 11.24 appends `V4FMADDPS` (1118), `V4FMADDSS` (1119), `V4FNMADDPS`
(1120), and `V4FNMADDSS` (1121), making `CDISASM_X86_NAME_COUNT` 1122.
All four use existing group 72, `CDISASM_X86_GROUP_AVX512_4FMAPS`, and the
existing AVX-512 runtime umbrella bit 19; independent AVX512_4FMAPS CPU
capability still restricts exact named profiles to Knights Mill. Packed opcodes
`9A`/`AA` require EVEX.512, while scalar opcodes `9B`/`AB` use LLIG with
fixed 128-bit XMM operands. Every form requires F2, map 2, W=0, U=1, B=0, and
a memory-only m128 Tuple1_4X source with disp8 scale 16; the encoded source
group is displayed as register N+3. The exhaustive W/LL/ModRM domain contains
8,192 controls: 1,536 allocated and 6,656 rejected. The family is available in
16-, 32-, and 64-bit decode modes only when `USE_EXTRA_OPCODES=1`.

Version 11.25 appends `VGETEXPPS` (1122), `VGETEXPPD` (1123), `VGETEXPSS`
(1124), and `VGETEXPSD` (1125), making `CDISASM_X86_NAME_COUNT` 1126.
They use group `CDISASM_X86_GROUP_AVX512F` on the legacy route and
`CDISASM_X86_GROUP_AVX10_1` on the alternative AVX10 route. Packed opcode
`EVEX.66.0F38.42` uses W=0/1 for PS/PD, is unary, and requires reserved `vvvv`;
scalar opcode `43` uses W=0/1 for SS/SD and consumes `vvvv` as a passthrough
source. Packed 512-bit and scalar forms require AVX512F, while packed 128/256-
bit forms additionally require AVX512VL. The alternative route requires
AVX10.1. Runtime selection must match that CPU route: AVX-512 and AVX10 are not
silently interchangeable. The full 8,192-cell W/opcode/LL/ModRM lattice has
5,248 valid and 2,944 invalid controls; separate sweeps lock masks and all 32
combined `vvvv`/extension values. Register SAE, packed memory broadcast,
full-width memory tuple scaling, mask merge/zero, extended registers, Intel and
AT&T text, malformed controls, truncation, and extras-OFF ownership are covered.
That historical 11.25 completion did not include PH, SH, BF16 GETEXP, or
GETMANT; version 11.26 below adds the exact PH/SH/BF16 forms only.

Version 11.26 appends `VGETEXPPH` (1126), `VGETEXPSH` (1127), and
`VGETEXPBF16` (1128), making `CDISASM_X86_NAME_COUNT` 1129. All use EVEX MAP6
and W=0. Packed unary PH is `EVEX.66.MAP6.42`; scalar NDS SH is
`EVEX.66.MAP6.43` and consumes `vvvv` as its passthrough source; packed unary
BF16 is `EVEX.NP.MAP6.42` and reserves `vvvv`. PH/SH use either the legacy
AVX512-FP16 route (with AVX512VL additionally required for packed 128/256-bit
PH) and the AVX-512 runtime selector, or the independent AVX10.1 route and the
AVX10 runtime selector. BF16 has no AVX-512 route: it requires AVX10.2 and the
AVX10 runtime selector. Named legacy PH/SH admission includes Sapphire Rapids,
Granite Rapids, and Diamond Rapids. Dual-capable Granite/Diamond profiles are
canonicalized to that legacy route; the abstract AVX10/APX profiles admit
PH/SH through the alternate AVX10.1 route. Named BF16 admission starts at
Diamond Rapids and the abstract AVX10/APX profiles. Register `EVEX.b` enables SAE for
PH/SH and is reserved for BF16 register sources; packed PH/BF16 memory uses m16
broadcast, while scalar SH memory is an m16 source without broadcast. With
`EVEX.b=0`, LL=0--2 are allocated and LL=3 is reserved. With a register source
and `EVEX.b=1`, PH is forced to 512 bits and PH/SH accept every LL alias for
SAE; with a memory source and `EVEX.b=1`, only packed PH/BF16 LL=0--2 broadcast
forms are allocated. The exact W/LL/b/ModRM lattice contains 12,288
controls, 3,968 allocated and 8,320 reserved. Separate focused checks cover U,
mandatory-prefix and map neighbors, masks, all 32 `vvvv`/extension values,
register extensions, every decode mode, CPU/runtime route separation, tuple
scaling, Intel/AT&T text, truncation, and extras-OFF ownership. GETMANT and
other unlisted vector maps remain outside this bounded completion. In 64-bit
mode, APX EVEX.X4 memory forms may select R16--R31 as the SIB index for PH, SH,
and BF16; these results add `APX_F` and require the APX CPU/runtime route.
Register-source U=0 forms and non-64-bit X4 forms remain invalid.

For the CET shadow-stack slice, fixed-width and 32-bit forms are syntactically
available in 16-, 32-, and 64-bit decode modes; `Q` forms require 64-bit mode.
The decoder accepts a redundant operand-size prefix alongside the mandatory
`F3` selector and preserves all other `F3 0F 1E /r` encodings as P6 WIDENOPs.
CPU capability, the runtime CET flag, and execution privilege metadata remain
independent checks.

The version-10.2 EVEX FMA3 expansion reuses all 60 existing mnemonic IDs. Its
36 PS/PD forms cover the 132/213/231 add, add-subtract, subtract-add, subtract,
negative-add, and negative-subtract families at 128-, 256-, and 512-bit vector
lengths, with mask merge/zero, memory broadcast, and legal embedded
rounding/SAE. Its 24 SS/SD forms cover 132/213/231 add, subtract, negative-add,
and negative-subtract with XMM register operands, m32/m64 memory sources,
masking/zeroing, and register-source rounding/SAE; scalar memory does not use
broadcast. With scalar EVEX.b=0, LL=0--2 is length-ignored and LL=3 is
reserved. A register source with EVEX.b=1 maps LL=0--3 to RN/RD/RU/RZ plus
SAE; EVEX.b=1 with memory is reserved. AVX-512 decoding uses only the
most-specific AVX-512 runtime bit and emits FMA3 plus AVX512F and AVX512VL
where applicable;
the AVX10.1 route uses only the AVX10 runtime bit and emits FMA3 plus AVX10.1.
In both routes FMA3 remains an independent CPU/group prerequisite rather than
an additional caller allow bit. Scalar forms emit no AVX512VL group.

The 51 K-mask mnemonic IDs are realized by 65 exact VEX descriptor rows.
AVX-512F supplies the word foundation; AVX-512DQ and AVX-512BW add the
byte/dword/qword operations. KMOV forms retain mask/GPR/memory direction and
width aliases, shifts retain their imm8 metadata, and unpack forms retain
their source widths. Legacy profiles use the appropriate AVX-512F/DQ/BW
capability route. Abstract AVX10 and APX profiles instead promote these classic
encodings through AVX10.1 and require the AVX10 runtime bit, without inventing
a legacy AVX-512F capability. This scoped completeness does not imply complete
EVEX, AVX-512, AVX10, APX, or AMX coverage.

The eight version-11.1 compare IDs realize the complete packed-integer
EVEX.66.0F3A compare-to-mask matrix. Opcodes `3F`/`3E` select signed/unsigned
byte or word elements, opcodes `1F`/`1E` select signed/unsigned dword or qword
elements, and EVEX.W selects the smaller or larger width in each pair. XMM,
YMM, and ZMM register sources and full-width memory sources are supported;
dword/qword memory additionally supports broadcast. The structured result
retains the K destination, optional merge mask, active mask width, imm8
predicate, memory access, broadcast, compressed displacement, and exact
encoding offsets. EVEX zeroing, EVEX.R/EVEX.R' K-destination extensions, LL=3,
register-source EVEX.b, and byte/word broadcast are reserved.

Legacy CPU profiles select the AVX-512F route, plus AVX-512VL below 512 bits
and AVX-512BW for byte/word elements, and require the `AVX512` runtime bit.
Abstract AVX10 and APX profiles instead select only AVX10.1 and require the
`AVX10` bit; they do not acquire synthetic legacy F/BW/VL capabilities. The
unrestricted profile reports the established AVX-512 route canonically.
`USE_EXTRA_OPCODES=0` still consumes complete structural forms before
returning `UNSUPPORTED_INSTRUCTION`, while reserved and truncated controls
remain `INVALID_INSTRUCTION` and `TRUNCATED` respectively. Completing this
one matrix does not complete the other EVEX/AVX-512 or AVX10 maps.

The version-11.4 modular/wrapping ADD/SUB matrix applies WIG to byte/word
forms, W=0 to dword forms, and W=1 to qword forms. Dword and qword memory
sources support scalar broadcast; byte and word broadcast is reserved. Mask merge/zero, full-width
memory, compressed displacement, and XMM/YMM/ZMM operands are represented in
the numeric result. A legacy AVX-512 route requires AVX512F, additionally
AVX512BW for byte/word elements and AVX512VL below 512 bits, together with the
`AVX512` runtime bit. The mutually alternative AVX10.1 route requires the
`AVX10` bit and does not synthesize legacy AVX-512 groups. LL=3,
register-source EVEX.b, zeroing without a mask, incorrect dword/qword W,
legacy prefixes before EVEX, and other reserved controls remain invalid.
Complete valid forms remain structurally owned and return
`UNSUPPORTED_INSTRUCTION` when extra opcodes are disabled.

The version-11.5 saturating family uses VEX map 1 and EVEX map 1 with mandatory
`66`; W is ignored for every byte/word form. VEX.128 requires the AVX CPU
capability and runtime bit, while VEX.256 requires AVX2. The 32 VEX operand
shapes comprise eight names, two vector lengths, and a register or full-width
memory third operand; VEX2 and both VEX3 W aliases preserve the same semantics.
The 48 EVEX operand shapes comprise the same eight names at XMM, YMM, and ZMM
lengths with a register or full-width memory third operand. Their legacy route
requires AVX-512F and AVX-512BW, additionally AVX-512VL below 512 bits, plus
the `AVX512` runtime bit. The mutually alternative route requires AVX10.1 and
the `AVX10` runtime bit without synthesizing legacy AVX-512 groups.

EVEX merge and zero masks, full-width memory, compressed displacement, and
extended registers are represented in the numeric result. No saturating
byte/word form supports broadcast or embedded rounding/SAE. LL=3,
register-source EVEX.b, memory EVEX.b, zeroing without a mask, an invalid EVEX
U bit, conflicting mandatory-prefix classes, and a legacy prefix before
VEX/EVEX remain invalid; a complete mandatory-prefix sibling remains unowned.
Valid forms stay structurally owned as `UNSUPPORTED_INSTRUCTION` with extra
opcodes off, while malformed and truncated forms retain their exact statuses.

The version-11.6 packed D/Q logical class uses EVEX map 1 with mandatory `66`.
EVEX.W selects dword or qword elements for `VPAND`, `VPANDN`, `VPOR`, and
`VPXOR`; XMM, YMM, and ZMM forms support register or full-width memory sources,
mask merge/zero, compressed displacement, and legal scalar dword/qword
broadcast. Its legacy route requires AVX-512F and AVX-512VL below 512 bits;
the mutually alternative route requires AVX10.1. Both routes retain the AVX
foundation and their corresponding runtime-family bit without synthesizing the
other route's groups.

The `VPAVGB/W` class uses the same EVEX map/prefix, with W ignored and byte or
word selection supplied by the opcode. It covers all three vector lengths with
register or full-width memory sources, merge/zero masking, and compressed
displacement. Broadcast, SAE, and embedded rounding are invalid. Its legacy
route requires AVX-512F and AVX-512BW, plus AVX-512VL below 512 bits; AVX10.1
is the mutually alternative route.

For both classes, exact APX P0.B4 register and EGPR-memory ownership is active
only in 64-bit mode and requires APX-F. P0.B4 ownership does not weaken the
independent AVX-512-or-AVX10 and runtime checks, and unrelated P0.B4 encodings
remain unowned. LL=3, zeroing without a nonzero mask, illegal EVEX.b uses, and
conflicting legacy mandatory-prefix classes are rejected structurally. Valid
complete forms stay owned as `UNSUPPORTED_INSTRUCTION` when extra opcodes are
disabled; reserved and short forms remain `INVALID_INSTRUCTION` and
`TRUNCATED`.

The version-11.7 dword/qword variable packed-shift tranche uses VEX/EVEX map 2 with mandatory
`66`. Opcode `47` selects `VPSLLV`, opcode `45` selects `VPSRLV`, and opcode
`46` selects `VPSRAV`; W selects dword or qword elements. VEX owns both widths
for logical left/right shifts and the dword arithmetic-right form, but the
VEX.W1 arithmetic-right shape is reserved because there is no VEX `VPSRAVQ`.
All VEX forms require AVX2.

EVEX owns all six names at XMM, YMM, and ZMM lengths with register or
full-width memory sources, merge/zero masks, compressed displacement, and legal
dword/qword scalar broadcast. Legacy profiles use AVX-512F plus AVX-512VL
below 512 bits; AVX10.1 is the mutually alternative route. Exact APX P0.B4
register and EGPR-memory forms and U0 memory forms are owned only in 64-bit mode
with the independent APX-F capability. LL=3, zeroing without a mask,
register-source EVEX.b, wrong mandatory selectors, and the unallocated VEX
arithmetic-qword control remain structurally invalid. Complete valid forms stay
owned as `UNSUPPORTED_INSTRUCTION` when extra opcodes are disabled, while
reserved and short forms retain `INVALID_INSTRUCTION` and `TRUNCATED`.

The version-11.8 word variable-shift class uses EVEX map 2 with mandatory `66`
and W=1. Opcodes `12`, `10`, and `11` select `VPSLLVW`, `VPSRLVW`, and
`VPSRAVW`. All three names accept XMM, YMM, and ZMM register or full-width
memory count sources, merge/zero masks, compressed displacement, and extended
registers. Broadcast, LL=3, zeroing without a mask, and other reserved controls
are rejected structurally.

Legacy profiles require AVX-512F and AVX-512BW, plus AVX-512VL below 512 bits;
the mutually alternative route requires AVX10.1. Exact APX P0.B4 register and
EGPR-memory forms plus U0/X4 forms are owned only in 64-bit mode with APX-F,
without weakening the independent AVX-512-or-AVX10 and runtime-family gates.
Valid complete forms remain structurally owned as `UNSUPPORTED_INSTRUCTION`
when extra opcodes are disabled; reserved and short forms remain
`INVALID_INSTRUCTION` and `TRUNCATED`.

The version-11.9 variable packed-rotate class uses EVEX map 2 with mandatory
`66`. Opcodes `15` and `14` select `VPROLV` and `VPRORV`; W=0/1 selects dword
or qword elements. All four names accept XMM, YMM, and ZMM register or
full-width memory count sources, merge/zero masks, compressed displacement,
extended registers, and legal dword/qword scalar broadcast.

Legacy profiles require AVX-512F and AVX-512VL below 512 bits; the mutually
alternative route requires AVX10.1. Exact APX P0.B4/U1 register and EGPR-memory
forms, U0 no-SIB memory forms, and U0/X4 SIB memory forms are owned only in
64-bit mode with APX-F. APX admission does not replace the independent
AVX-512-or-AVX10 and runtime-family gates. LL=3, zeroing with `k0`, and other
reserved controls are invalid. Complete valid forms stay structurally owned as
`UNSUPPORTED_INSTRUCTION` when extra opcodes are disabled, while short forms
retain `TRUNCATED` precedence.

The version-11.10 immediate packed-rotate class uses EVEX map 1 with mandatory
`66`, opcode `72`, and an imm8 count. ModRM `/0` selects `VPRORD/Q`; `/1`
selects `VPROLD/Q`; W=0/1 selects dword/qword elements. EVEX.vvvv/V' is the
destination and ModRM r/m is the source. XMM, YMM, and ZMM forms support
register and full-width memory sources, masks/zeroing, compressed
displacement, extended registers, and legal dword/qword scalar broadcast.

Legacy profiles require AVX-512F and AVX-512VL below 512 bits; the mutually
alternative route requires AVX10.1. Exact APX P0.B4/U1 register and
EGPR-memory forms, U0 no-SIB memory forms, and U0/X4 SIB memory forms are owned
only in 64-bit mode with APX-F. APX admission does not replace the independent
AVX-512-or-AVX10 and runtime-family gates. LL=3, register-source EVEX.b,
zeroing with `k0`, and U0 register controls are invalid.

Version 11.11 implements the remaining allocated ModRM extensions after the
shared imm8 is consumed. `/2` W0 selects `VPSRLD`; `/4` W0/W1 selects
`VPSRAD`/`VPSRAQ`; and `/6` W0 selects `VPSLLD`. They use the same vector
lengths, operand shapes, masks, compressed displacement, feature alternatives,
and APX P0.B4/U0/X4 routes as the rotate class. `/2` and `/6` with W=1 and
every `/3`, `/5`, and `/7` control are reserved and return
`INVALID_INSTRUCTION`. Missing ModRM, displacement, or imm8 bytes return
`TRUNCATED`. Complete legal rotate or shift forms remain structurally owned as
`UNSUPPORTED_INSTRUCTION` when extra opcodes are disabled.

Version 11.12 owns the adjacent EVEX map-1 immediate groups only after the
mandatory `66` selector and imm8 have been identified. Opcode `71` is WIG:
ModRM `/2`, `/4`, and `/6` select `VPSRLW`, `VPSRAW`, and `VPSLLW` and require
AVX-512BW. Opcode `73` W=1 `/2` and `/6` select `VPSRLQ` and `VPSLLQ` and
require AVX-512F; WIG `/3` and `/7` select byte-lane `VPSRLDQ` and `VPSLLDQ`
and require AVX-512BW. XMM/YMM/ZMM lengths and register/full-memory sources
are supported. Word and qword forms carry their exact merge/zero masks; only
qword memory forms admit scalar broadcast. Byte-lane forms admit neither mask
nor broadcast.

Legacy profiles additionally require AVX-512VL below 512 bits; the alternative
admission route is AVX10.1. Exact APX P0.B4/U1 register and EGPR-memory forms,
U0 no-SIB memory forms, and U0/X4 SIB memory forms are owned only in 64-bit
mode with APX-F, without replacing the vector-family CPU/runtime gate. Across
the two opcodes, the 32 W-by-extension controls contain 12 W-expanded legal
controls and 20 reserved controls. Each legal control accepts every imm8;
the focused suite therefore covers 3,072 allocated control/immediate pairs.
Reserved complete forms are `INVALID_INSTRUCTION`, valid extra-opcode-OFF
forms are `UNSUPPORTED_INSTRUCTION`, and incomplete owned forms retain
`TRUNCATED` precedence.

Version 11.13 owns the exact mandatory-`66` AVX512VBMI2 double-shift slice.
EVEX map 3 carries imm8: opcode `70` W1 selects `VPSHLDW`, opcode `71` W0/W1
selects `VPSHLDD/Q`, opcode `72` W1 selects `VPSHRDW`, and opcode `73` W0/W1
selects `VPSHRDD/Q`. EVEX map 2 uses the same opcode/W controls for
`VPSHLDVW/DVD/DVQ` and `VPSHRDVW/DVD/DVQ`, with the third vector operand
supplying the per-element count. The four map-2/map-3 opcode-`70`/`72` W0
controls are reserved; the other 12 controls are allocated, and every map-3
allocated control accepts every imm8.

All three vector lengths support masks, register and full-memory sources, and
compressed disp8. Dword/qword memory sources admit exact scalar broadcast;
word broadcast, register EVEX.b, LL=3, and zeroing with `k0` are reserved.
The legacy route requires AVX-512F plus AVX512VBMI2 and AVX512VL below 512
bits; AVX10.1 is the alternative route. In 64-bit mode APX-F additionally owns
P0.B4 register and EGPR-memory forms plus U0 no-SIB/X4 memory forms, while U0
register controls stay reserved. CPU, runtime-family, APX, and build-option
gates remain independent, and incomplete owned forms retain truncation
precedence.

Version 11.14 owns the exact mandatory-`66` EVEX map-2 COMPRESS/EXPAND slice.
Opcodes `63` and `62` select byte/word `VPCOMPRESS` and `VPEXPAND` through
W=0/1; opcodes `8B` and `89` select dword/qword variants. LL=0--2, all mask
registers, and register or memory forms are allocated. COMPRESS reverses the
ordinary ModRM data flow: its `r/m` operand is the destination and ModRM.reg is
the vector source. EXPAND writes ModRM.reg and reads `r/m`. A compress memory
destination rejects zeroing, whereas an expand register destination accepts
merge or zero masking with either a register or memory source. EVEX.b, LL=3,
zeroing with `k0`, and noncanonical encoded `vvvv` are reserved.

Compressed disp8 uses the GSCAT element scale of one, two, four, or eight
bytes, not the full vector width. Byte/word forms require AVX-512F plus
AVX512VBMI2; dword/qword forms require AVX-512F; all sub-512-bit forms require
AVX512VL. AVX10.1 is the alternative foundation. In 64-bit mode APX-F owns the
reviewed P0.B4 memory/qualifier and U0/X4 memory-address routes, while U0
register forms remain reserved. Build, CPU, runtime-family, AVX-512/AVX10,
and APX gates remain independent; owned incomplete forms retain truncation
precedence.

The same release owns the exact mandatory-`66` EVEX map-2 popcount/BITALG
rows. Opcode `54` selects `VPOPCNTB/W`, opcode `55` selects the established
`VPOPCNTD` or appended `VPOPCNTQ`, and W=0 opcode `8F` selects
`VPSHUFBITQMB`. Popcount is unary and therefore requires canonical encoded
`vvvv`; `VPSHUFBITQMB` instead consumes `vvvv` as its first vector source and
writes the K register selected by ModRM.reg. LL=0--2, register/full-memory
sources, and merge/zero masks on popcount destinations are allocated.
`VPSHUFBITQMB` permits an optional merging K mask but never zeroing.

Only dword/qword memory popcount allocates EVEX.b broadcast, with
element-sized four/eight-byte compressed-displacement scaling; its ordinary
memory form and all byte/word/shuffle memory forms use full-vector scaling.
Byte/word popcount and shuffle require AVX512BITALG, dword/qword popcount
requires AVX512VPOPCNTDQ, and sub-512-bit forms additionally require
AVX512VL; AVX10.1 is an alternative foundation. The specific runtime bits
remain independently selectable, while the historical `AVX512` bit admits
both families for source compatibility. Exact APX P0.B4/U0 memory behavior,
reserved register U0, LL=3, malformed decorator, and truncation precedence
match the adjacent COMPRESS/EXPAND implementation.

Version 11.15 owns the exact mandatory-`66` EVEX map-2 AVX-512CD unary
class. Opcode `C4` selects `VPCONFLICTD/Q`, opcode `44` selects
`VPLZCNTD/Q`, and W selects dword or qword elements. LL=0--2, register and
full-vector memory sources, optional merge/zero masking, and scalar m32/m64
broadcast are allocated; LL=3, noncanonical encoded `vvvv`, register EVEX.b,
zeroing with `k0`, and reserved APX controls are invalid. Full memory uses the
vector-width compressed-disp8 scale while broadcast uses four or eight bytes.

The AVX-512 route requires AVX512F plus AVX512CD and AVX512VL below 512 bits;
AVX10.1 is the alternative foundation. The narrow runtime selector is
`CDISASM_X86_DECODE_FLAG_AVX512_CD`, while the historical `AVX512` bit remains
a compatibility umbrella. In 64-bit mode APX-F owns reviewed P0.B4 register
and memory routes plus U0 no-SIB/X4 memory addressing. CPU capabilities,
runtime selection, build option, AVX-512/AVX10 alternative, and APX remain
independent gates; owned incomplete inputs preserve truncation precedence.

Version 11.16 owns the two mandatory-`F3` EVEX map-2 AVX-512CD mask-broadcast
rows. `EVEX.F3.0F38.W1 2A /r` selects `VPBROADCASTMB2Q`; W=0 with opcode
`3A` selects `VPBROADCASTMW2D`. LL=0--2 select XMM/YMM/ZMM destinations and
ModRM.rm selects the K0--K7 source. The source is read as eight bytes for
`MB2Q` and four bytes for `MW2D`; there is no memory form or destination-mask
decorator. LL=3, ModRM.mod other than three, EVEX.b/z/aaa, U0, noncanonical
vvvv or V', and the opposite W value are invalid.

The AVX-512 route requires AVX512F plus AVX512CD and AVX512VL below 512 bits;
AVX10.1 is the alternative foundation. Canonical forms are valid in 32-bit
mode with destinations 0--7. Reviewed P0.B4 forms require 64-bit mode and
APX-F. The rows reuse `CDISASM_X86_DECODE_FLAG_AVX512_CD`, completing the
implemented AVX-512CD feature without expanding the known runtime mask.

Version 11.17 owns the mandatory-`66`, W=0 EVEX map-2 opcode row `50`--`53`:
`VPDPBUSD`, `VPDPBUSDS`, `VPDPWSSD`, and `VPDPWSSDS`. LL=0--2 select
XMM/YMM/ZMM widths. All four are destructive accumulates with a read/write
destination, a `vvvv` vector source, and a ModRM register or full-tuple memory
source. Memory EVEX.b selects legal `m32bcst`; register EVEX.b, LL=3, W=1,
zeroing with K0, and malformed legacy-prefix combinations are invalid.

The AVX-512 route requires AVX512F, AVX512VNNI, and AVX512VL below 512 bits;
AVX10.1 is the alternative vector foundation. The narrow runtime selector is
`CDISASM_X86_DECODE_FLAG_AVX512_VNNI`, while the historical AVX512 bit remains
an admission umbrella. Reviewed APX P0.B4 register/memory and U0 memory-address
forms additionally require 64-bit mode and APX-F. CPU capability, runtime
selection, build option, AVX-512/AVX10 foundation, and APX are independent.

Version 11.18 owns the classic mandatory-`66` EVEX map-2 AVX512_VBMI byte
slice: W=0 opcodes `75`, `7D`, and `8D` select `VPERMI2B`, `VPERMT2B`, and
`VPERMB`; W=1 opcode `83` selects `VPMULTISHIFTQB`. LL=0--2 select
XMM/YMM/ZMM. Every form has a destination, `vvvv` source, and register or
Full-tuple memory source. `VPERMI2B` and `VPERMT2B` always read/write their
destination; `VPERMB` and `VPMULTISHIFTQB` write it unless merge masking also
requires the old value. Only `VPMULTISHIFTQB` permits memory EVEX.b, selecting
an eight-byte source and `{1to2}`, `{1to4}`, or `{1to8}` broadcast.

LL=3, register EVEX.b, byte-permute memory EVEX.b, zeroing with K0, and W=0
opcode `83` are invalid. At the 11.18 boundary, W=1 at opcodes `75`, `7D`, and
`8D` was structurally owned but unsupported. The AVX-512 byte route requires
AVX512F, AVX512VBMI, and AVX512VL below 512 bits; AVX10.1 is the alternative
foundation. The narrow byte-family runtime selector is
`CDISASM_X86_DECODE_FLAG_AVX512_VBMI`; the AVX512 umbrella also admits it.

Version 11.19 implements those W=1 rows as `VPERMI2W`, `VPERMT2W`, and
`VPERMW`. They preserve the same vector lengths, masking, Full-tuple memory,
compressed displacement, and reserved-control boundaries, but never permit
broadcast. `VPERMI2W` and `VPERMT2W` always read/write their destination;
`VPERMW` writes it unless merge masking needs the old value. The legacy route
requires AVX512F, AVX512BW, and AVX512VL below 512 bits and uses
`CDISASM_X86_DECODE_FLAG_AVX512_BW`. AVX10.1 plus
`CDISASM_X86_DECODE_FLAG_AVX10` is a separate alternative and does not add a
legacy AVX512BW result group. Reviewed APX P0.B4/U0 addressing remains an
independent 64-bit APX-F gate for both byte and word rows. The legacy opcode,
tuple, and operand boundaries follow Intel's checked-in
[XED Skylake-X definitions](https://github.com/intelxed/xed/blob/main/datafiles/avx512-skx/skx-isa.xed.txt).

These completions remain bounded. Unlisted legacy SIMD/VEX entries, most other
EVEX and AVX-512 families outside the exact completed slices, and complete
AVX10, APX, AMX, crypto-variant, floating-point-compare, and uncommon
system/control coverage are still absent. A public name/group ID or a newer CPU
profile does not make an unimplemented encoding decodable.

WAITPKG appends names but does not overload prefix metadata: its mandatory
`F2`/`F3` selectors are not reported as effective repeat actions. Successful
instructions carry group 94 (`WAITPKG`) and use the SYSTEM runtime-family bit.
REX2 forms additionally carry `APX_F`; ordinary WAITPKG does not.

The result identifies the effective base mnemonic after CPU-specific alias
resolution. Thus `F3 90` can report either `CDISASM_X86_NAME_NOP` or
`CDISASM_X86_NAME_PAUSE`, depending on the CPU profile. Display prefixes do not
otherwise change the ID: `lock add` reports `CDISASM_X86_NAME_ADD` and
`rep movsb` reports `CDISASM_X86_NAME_MOVSB`.

Historical opcode collisions are resolved only for exact profiles: `0F 05`
is `LOADALL286` only on `CDISASM_CPU_80286`, and `0F 07` is `LOADALL` only on
`CDISASM_CPU_80386`; the unrestricted profile retains the modern
SYSCALL/SYSRET interpretation. `ICEBP`, `LOADALLD`, and `SETALC` are public ID
aliases of `INT1`, `LOADALL`, and `SALC`, respectively, so no duplicate string
or numeric identity is introduced.

### x87 D8--DF decoding

All x87 memory extensions and register encodings in the D8--DF primary maps
are classified by numeric descriptor tables. Register forms use the stable
`ST0`--`ST7` register IDs and exact read/write access. Memory forms report the
encoded 16-, 32-, 64-, or 80-bit data width; environment/state forms report
14/28-byte or 94/108-byte objects according to effective operand size.

Pre-80486 x87 hardware is not inferred from the host CPU. Plain 8086, 80186,
80286, and 80386 profiles reject these instructions; the appended
`*_8087`/`*_80187`/`*_80287`/`*_80387` profiles enable the appropriate
coprocessor level. The integrated 80486 and later profiles enable the 387-level
base at the CPU gate. Successful x87 decode also requires
`USE_EXTRA_OPCODES=1` and `CDISASM_X86_DECODE_FLAG_FPU`, while P6 conditional
moves/comparisons and SSE3 `FISTTP` retain their own
later CPU gates. This policy is independent of the 16/32/64-bit mode mask.

`9B` remains a standalone `WAIT` unless it forms a documented WAIT spelling of
an immediately following x87 operation. A fused spelling reports its distinct
waiting mnemonic ID and `CDISASM_PREFIX_WAIT`; the no-WAIT spelling retains its
`FN*` ID. LOCK is invalid, redundant F2/F3 bytes are retained without claiming
effective REP, and REX only affects address formation. Reserved slots remain
invalid. Intel compatibility encodings are accepted only where explicitly
listed. The nine behaviors documented in Intel's original 8087 encoding table
(`FSTPNCE`, `FFREEP`, and the redundant DC/DD/DE/DF register encodings) are
available on the 8087 profile. Genuine 80387 additions such as `FPREM1`,
`FSINCOS`, `FSIN`, and `FCOS` retain the 80387 gate.

The cutoff is based on Intel's 1981 *iAPX 86/88 User's Manual*, Appendix A,
Table A-2 (PDF page 797), rather than on modern assembler availability:
<https://bitsavers.trailing-edge.com/components/intel/8086/1981_iAPX_86_88_Users_Manual.pdf>.

## ARM single-instruction decoding

`cdisasm_arm_decode` is exported by `cdisasm` when `USE_ARCH_ARM=1` and decodes
one ARM instruction into a `cdisasm_arm_instruction`. Input is little-endian by
default. Passing an ARM flags object with bitmap-0
`CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN` set instead reads A32/A64 as a big-endian
32-bit word and T32 as a sequence of big-endian 16-bit halfwords;
for a 32-bit Thumb instruction the first stream halfword remains the first one
classified and decoded. A32 and A64 instructions are fixed at four bytes. T32
returns two or four after classifying the first halfword. `opcode_size` always
equals that successful return value, and equivalent byte orders produce
identical semantic metadata.

ARM decode flags are not the x86 family bitmap. `cdisasm_arm_decode_flags`
aliases the same 64-byte common layout as `cdisasm_decode_flags` and
`cdisasm_x86_decode_flags`, but its namespace is independent. ARM logical bit 0
is `CDISASM_ARM_DECODE_BIT_BIG_ENDIAN`, whereas x86 logical bit 0 is
`CDISASM_X86_DECODE_BIT_FPU`. ARM logical bit 1 is
`CDISASM_ARM_DECODE_BIT_IN_IT_BLOCK`. The corresponding
`CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK` option supplies the T32 execution state
needed by architectural `InITBlock()` alias rules; it is rejected for A32 and
A64. `cdisasm_arm_decode` rejects remaining reserved bitmap-0 bits and every
bit in words 1--7 with a zeroed `INVALID_ARGUMENT` result. Generic callers must
choose flags from the selected CPU group. `NULL` or an all-zero object selects
little-endian input and the outside-IT default.

Use `CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER`,
`CDISASM_ARM_DECODE_FLAGS_INITIALIZER(bitmap0)`, or
`CDISASM_ARM_DECODE_FLAGS_ALL_INITIALIZER` to initialize a complete object.
The common reset/set/clear/test helpers accept
`CDISASM_ARM_DECODE_BIT_BIG_ENDIAN` and
`CDISASM_ARM_DECODE_BIT_IN_IT_BLOCK`. The legacy
`cdisasm_arm_decode_option` typedef and `CDISASM_ARM_DECODE_OPTION_*` masks
remain 64-bit bitmap-0 vocabulary; the singular type is no longer the decoder
argument type.

The typed and generic availability queries are:

```c
cdisasm_status cdisasm_arm_cpu_decode_flag_mask(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    cdisasm_arm_decode_flags *flags);

cdisasm_status cdisasm_cpu_decode_flag_mask(
    cdisasm_cpu_id cpu_id,
    uint32_t mode,
    cdisasm_decode_flags *flags);
```

Both require a non-NULL output and clear the entire object before validating
the request. An invalid CPU, mode, or CPU/mode pair returns
`CDISASM_STATUS_INVALID_ARGUMENT`; every valid ARM CPU/mode pair returns
`CDISASM_STATUS_OK` with BIG_ENDIAN set because input representation is
independent of processor capabilities. T32 additionally returns IN_IT_BLOCK;
A32/A64 do not because they reject that context option.

ARM modes describe instruction-set state, not byte width:

| Value | Meaning | Decode behavior |
| --- | --- | --- |
| `CDISASM_ARM_MODE_A32` (`CDISASM_ARM_MODE_32`) | A32 in the AArch32 execution state | Implemented subset; consumes four bytes |
| `CDISASM_ARM_MODE_T32` | Thumb state in AArch32 | Implemented subset; consumes two or four bytes |
| `CDISASM_ARM_MODE_A64` (`CDISASM_ARM_MODE_64`) | A64 in the AArch64 execution state | Implemented subset; consumes four bytes |

`cdisasm_arm_cpu_mode_mask()` reports physical execution-state support.
`cdisasm_arm_decoder_mode_mask()` intersects that result with the states
implemented by this build. The current decoder implements subsets of all three
states, but the two-query contract keeps hardware capability distinct from
software coverage. A T32 bit also does not claim that all listed processors
implement the same Thumb ISA revision; per-instruction capability checks still
apply.

### ARM CPU mode profiles

ARM CPU IDs are stable lookup keys and are not a chronological feature order.
Their full values contain `CDISASM_CPU_GROUP_ARM` in the upper 16 bits; the
table below shows the low-16-bit ordinal. No relational comparison between two
ARM CPU IDs is part of the API.
In particular, Cortex-A32 is AArch32-only, Cortex-A34 is AArch64-only, and the
numerically later Cortex-A35 and Cortex-A53 support both. Code must query
the appropriate mode-mask function or request an exact CPU/mode pair; it must
not infer support with `cpu_id >= some_id`.

The complete mode-mask table is:

| Ordinal | CPU constant | A32 | T32 | A64 |
| ---: | --- | :---: | :---: | :---: |
| 0 | `CDISASM_ARM_CPU_ANY` | yes | yes | yes |
| 1 | `CDISASM_ARM_CPU_ARM7TDMI` | yes | yes | no |
| 2 | `CDISASM_ARM_CPU_CORTEX_A7` | yes | yes | no |
| 3 | `CDISASM_ARM_CPU_CORTEX_A9` | yes | yes | no |
| 4 | `CDISASM_ARM_CPU_CORTEX_A32` | yes | yes | no |
| 5 | `CDISASM_ARM_CPU_CORTEX_A34` | no | no | yes |
| 6 | `CDISASM_ARM_CPU_CORTEX_A35` | yes | yes | yes |
| 7 | `CDISASM_ARM_CPU_CORTEX_A53` | yes | yes | yes |
| 8 | `CDISASM_ARM_CPU_CORTEX_A9_NEON` | yes | yes | no |
| 9--11 | `CDISASM_ARM_CPU_APPLE_A4` ... `APPLE_A6` | yes | yes | no |
| 12--15 | `CDISASM_ARM_CPU_APPLE_A7` ... `APPLE_A10` | yes | yes | yes |
| 16--24 | `CDISASM_ARM_CPU_APPLE_A11` ... `APPLE_A19` | no | no | yes |
| 25--29 | `CDISASM_ARM_CPU_APPLE_M1` ... `APPLE_M5` | no | no | yes |
| 30 | `CDISASM_ARM_CPU_CORTEX_A7_NEON` | yes | yes | no |
| 31--37 | `CDISASM_ARM_CPU_APPLE_S4` ... `APPLE_S10` | no | no | yes |
| 38 | `CDISASM_ARM_CPU_FUJITSU_A64FX` | no | no | yes |

The three columns correspond exactly to the hardware mask returned by
`cdisasm_arm_cpu_mode_mask()` and to
`CDISASM_ARM_MODE_MASK_A32`, `CDISASM_ARM_MODE_MASK_T32`, and
`CDISASM_ARM_MODE_MASK_A64`. An unknown CPU ID returns
`CDISASM_ARM_MODE_MASK_NONE`. `CDISASM_ARM_CPU_ANY` is the unrestricted
ARM decoder profile at `CDISASM_CPU_GROUP_ARM | 0x0000` (`0x00020000`), not a
real processor and not a lower endpoint for ordered comparisons. The current
`cdisasm_arm_decoder_mode_mask()` result is the same table because this build
contains A32, T32, and A64 decoders.

The distinctions are consistent with Arm's primary
[Cortex-A comparison table](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Cortex-A%20R%20M%20datasheets/Arm%20Cortex-A%20Comparison%20Table_v4.pdf),
its [Cortex-A32 A32/T32-only description](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/introducing-cortex-a32-arm-s-smallest-lowest-power-armv8-a-processor-for-next-generation-32-bit-embedded-applications),
and its descriptions of dual-state
[Cortex-A35](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/introducing-cortex-a35-arm-s-most-efficient-application-processor)
and [Cortex-A53](https://developer.arm.com/compute-ip/cortex-a53).
Fujitsu's
[A64FX datasheet](https://www.fujitsu.com/downloads/SUPER/a64fx/a64fx_datasheet_en.pdf)
identifies Armv8.2-A plus SVE; the A64FX profile therefore exposes A64 and SVE
without inferring SVE2, SME, or CPA.

`CDISASM_ARM_CPU_CORTEX_A7` and `CDISASM_ARM_CPU_CORTEX_A9` deliberately do
not promise NEON because that block was configurable in implementations of
both cores. Select `CDISASM_ARM_CPU_CORTEX_A7_NEON` or
`CDISASM_ARM_CPU_CORTEX_A9_NEON` when it is known to be present. Apple A- and
M-family suffix constants such as `APPLE_A12X`, `APPLE_A19_PRO`,
`APPLE_M4_MAX`, and `APPLE_M5_ULTRA` are aliases of their base generation:
the suffix does not change the instruction-state profile. Apple CPU IDs remain
lookup keys, not a relational feature hierarchy. Because the append-only
Apple A/M and S ranges are separated by the later A7-NEON ID, use
`CDISASM_ARM_CPU_IS_APPLE(cpu_id)` rather than assuming that every value from
`APPLE_FIRST` through `APPLE_LAST` is an Apple profile.

Execution-state support is not Apple-extension support. `A64` only says that
the CPU can execute the A64 instruction set; private extensions are validated
by independent internal capability bits after the numeric descriptor has been
selected. Version 10.0 retains these conservative profile rules:

| Encoding family | Accepted named CPU profiles | `CPU_ANY` |
| --- | --- | :---: |
| Cyclone `CPM_IOACC_CTL_EL3` (`MRS`/`MSR`) | Apple A7 only | yes |
| `MUL53LO.2D`, `MUL53HI.2D` | Apple A11--A19, M1--M5 | yes |
| Apple AMX | M1--M4 | yes |
| AppleSys (`WKDM*`, `G*`, `AT_AS1ELX`, `SDSB`) | M1--M5 | yes |

Apple S4--S10 do not receive a private-opcode capability merely because they
are Apple profiles. AMX is intentionally not asserted for M5: the checked AMX
hardware work covers M1 through M4 and explicitly cautions that newer chips may
differ. AppleSys has no reliable A- or S-series cutoff in the public
reverse-engineering source, so those series are rejected. Applications
examining an unknown or future Apple dump can request the unrestricted
`CDISASM_ARM_CPU_ANY` profile without changing decoder options.

Capstone's `CS_MODE_APPLE_PROPRIETARY`/`+apple` is a single opt-in that enables
its AMX, MUL53, and AppleSys feature predicates together; it does not take a
processor generation. cdisasm deliberately keeps descriptor selection and CPU
validation independent. A recognized Apple instruction rejected by the chosen
profile reports `CDISASM_STATUS_INVALID_INSTRUCTION`; a hole in the Apple map
reports `CDISASM_STATUS_UNSUPPORTED_INSTRUCTION`.
The audited references are Capstone's
[Apple AArch64 change](https://github.com/capstone-engine/capstone/pull/2692),
the [Asahi opcode map](https://github.com/AsahiLinux/docs/blob/main/docs/hw/cpu/apple-instructions.md),
the [A11 MUL53 investigation](https://gist.github.com/TrungNguyen1909/5b323edda9a21550a1621af506e8ce5f),
and the [M1--M4 AMX study](https://github.com/corsix/amx).
The release evidence policy, M5 recheck, and criteria for promoting a cutoff
are recorded in [`APPLE_CPU_EVIDENCE.md`](APPLE_CPU_EVIDENCE.md).

An unknown CPU, unknown mode, CPU/mode mismatch, a T32 IT-state option used in
A32/A64, or reserved decode-flag bits in bitmap 0
reports `CDISASM_STATUS_INVALID_ARGUMENT`. A zero byte count reports
`CDISASM_STATUS_END_OF_INPUT`; a nonzero count below four reports
`CDISASM_STATUS_TRUNCATED` for A32/A64. T32 needs two bytes to classify the
first halfword and reports `TRUNCATED` when a classified 32-bit form has fewer
than four. A known encoding unavailable on the selected CPU reports
`CDISASM_STATUS_INVALID_INSTRUCTION`; an unimplemented encoding reports
`CDISASM_STATUS_UNSUPPORTED_INSTRUCTION`. On failure the result is zero except
for `last_error_id`, just like the x86 result. A NULL result pointer returns
zero because there is nowhere to store the status.

For example, A64 NOP on a dual-state Cortex-A53 is decoded without any text
table:

```c
#include <cdisasm/cdisasm_arm.h>

const uint8_t code[4] = {0x1f, 0x20, 0x03, 0xd5};
cdisasm_arm_instruction instruction;
uint32_t size = cdisasm_arm_decode(
    CDISASM_ARM_CPU_CORTEX_A53,
    CDISASM_ARM_MODE_A64,
    code,
    sizeof(code),
    UINT64_C(0x1000),
    NULL,
    &instruction);

if (size == 4 && instruction.name_id == CDISASM_ARM_NAME_NOP) {
    /* Consume the stable numeric result. */
}
```

### ARM result and IDs

`cdisasm_arm_instruction` records the supplied address, resolved
`branch_target`, semantic groups, the 32-bit `raw_instruction`, numeric
instruction flags, a 16-bit `CDISASM_ARM_NAME_*` ID, status, condition, ISA ID,
and up to four `cdisasm_arm_operand` records. `condition` uses the architectural
four-bit condition encoding. `isa_id` is `CDISASM_ARM_ISA_A32`,
`CDISASM_ARM_ISA_T32`, or `CDISASM_ARM_ISA_A64` on success. For a two-byte T32 result,
`raw_instruction` contains the first halfword in bits 15:0. For a four-byte T32
result, the first halfword is in bits 15:0 and the second is in bits 31:16.

Operands use the shared register/immediate/memory kinds and access values, plus
`CDISASM_ARM_OPERAND_REGISTER_LIST` for A32/T32 LDM/STM and PUSH/POP aliases
and `CDISASM_ARM_OPERAND_REGISTER_PAIR` for an A64 CASP register pair. ARM
register fields use 16-bit `CDISASM_ARM_REG_*` IDs. Encoded A64 register 31 is
resolved to the appropriate SP/WSP or XZR/WZR ID for the decoded form. The
operand also represents shifts, extensions, scale, register lists, signed
displacements, and resolved addresses without constructing text.

`CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL` is a type-specific SME tile flag.
For a selected ZA slice it distinguishes the vertical view from the default
horizontal view; the tile register ID carries the B/H/S/D/Q view number,
`base_reg` carries W12--W15, `imm` carries the slice offset, and
`extend_type` carries element width. It reuses bit 5 of the existing operand
flag byte and does not change the fixed result layout.

`CDISASM_ARM_OPERAND_FLAG_VL_SCALED` is a type-specific ARM memory flag that
reuses bit 6 of the existing operand flag byte; it does not change either
fixed result layout. It is always paired with
`CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT`. For such an operand, `imm` is an
unsigned coefficient and the represented address is `base + imm * VL`, where
VL is the architectural vector length in bytes, rather than a byte
displacement. Exact SME ZA load/store forms 4381--4382 currently use
coefficients 1--15. Their offset-zero spelling has `imm == 0` and neither
flag. These forms transfer one complete ZA array vector (runtime size SVL/8,
16--256 bytes), so the memory operand reports `size == 0` rather than
inventing a fixed width. The formatter emits `#imm, mul vl` and rejects the
flag on other forms, without `HAS_DISPLACEMENT`, or with an out-of-range
coefficient.

`CDISASM_ARM_OPERAND_FLAG_HAS_ROTATION` reuses bit 7 for a trailing
architectural rotation immediate packed into a scalable source operand's
`imm` field. This preserves the four-record ARM ABI for five-token forms such
as predicated SVE `FCMLA`: operand 3 is still the final Z source, while its
flag and `imm` expose the separate `#0/#90/#180/#270` rotation. The formatter
emits that trailing immediate and rejects the flag on other forms or values.

For an instruction carrying `CDISASM_ARM_INSTRUCTION_FLAG_SIMD`, a vector
register operand's `size` is its total width in bytes. Use
`CDISASM_ARM_VECTOR_ELEMENT_SIZE(&operand)` and
`CDISASM_ARM_VECTOR_ELEMENT_COUNT(&operand)` for lane width and lane count.
These accessors reuse two previously existing bytes in the fixed operand
record, so version 5.2 adds the metadata without changing its layout. A32/T32
vector registers use the appended `D0`--`D31` and `Q0`--`Q15` IDs; A64 uses
`V0`--`V31`.

For a relative branch, the immediate operand's `imm` is the resolved target,
`address` is the signed displacement bit pattern, and `SIGNED`, `PC_RELATIVE`,
and `HAS_ADDRESS` are set. `branch_target` is valid when
`CDISASM_GROUP_RELATIVE_BRANCH` is present. A32 PC-relative addressing applies
the architectural PC bias; ADRP records its page-relative target.

The ARM ABI is fixed at 32 bytes per `cdisasm_arm_operand` and 168 bytes per
`cdisasm_arm_instruction`. The four-operand array starts at byte offset 40.
Unused fields and reserved bytes are zero. The header contains C11 and C++11
compile-time size/layout checks. ARM name and register IDs are append-only and
declared in `<cdisasm/cdisasm_arm_ids.h>`; the decoder contains no mnemonic or
register spelling strings. Version 5.3 ends its Apple additions at `WKDMD`
(109). The current source appends the ARMv8.0 ordered/exclusive load-store
mnemonics from `LDARB` (110) through `STLXP` (131), making
the pre-extension count 132. The optional A64 atomic tranche appends `CASB`
(132) through `LDAPR` (216). The modern optional catalog continues through
`SQRDMLAH` (312), then appends A64 scalar-register names and canonical aliases
from `ADCS` (313) through `CNEG` (331). Version 11.1 then appends the SVE
predicate-logical spellings `BICS` (332), `EORS` (333), `NAND` (334), `NANDS`
(335), `NOR` (336), `NORS` (337), `ORN` (338), `ORNS` (339), `ORRS` (340),
and `SEL` (341). Version 11.2 appends `SQADD` (342), `UQADD` (343), `SQSUB`
(344), `UQSUB` (345), `ADDPT` (346), and `SUBPT` (347), while reusing existing
`ADD` and `SUB` names. Version 11.3 appends `ZIP1` (348), `ZIP2` (349),
`UZP1` (350), `UZP2` (351), `TRN1` (352), and `TRN2` (353).
Version 11.4 appends `TBL` (354), `TBX` (355), and `TBXQ` (356), while the
MOV-from-GPR subset reuses `MOV` (31). `CDISASM_ARM_NAME_COUNT` is therefore
357 in both option variants. Version 11.5 appends `TBLQ` (357), making the
count 358 in both option variants. Version 11.6 appends `SUBR` (358), `SABD`
(359), `UABD` (360), `SMULH` (361), `UMULH` (362), `SDIVR` (363), and
`UDIVR` (364), making that release's count 365. Version 11.7 appends `CLS`
(365), `CNOT` (366), `NOT` (367), `SXTB` (368), `SXTH` (369), `SXTW`
(370), `UXTB` (371), `UXTH` (372), `UXTW` (373), `REVB` (374), `REVH`
(375), `REVW` (376), and `RBIT` (377), making that release's count 378.
Version 11.8 appends `ASRR` (378), `LSRR` (379), and `LSLR` (380), while
reusing `ASR`, `LSR`, and `LSL`; that release's count is therefore 381 in both
option variants. Version 11.9 appends `ASRD` (381), `SQSHL` (382), `UQSHL`
(383), `SRSHR` (384), `URSHR` (385), and `SQSHLU` (386), while reusing `ASR`,
`LSR`, and `LSL`; that release's count is therefore 387 in both option
variants. Version 11.10 appends `CMPEQ` (387), `CMPNE` (388), `CMPGE` (389),
`CMPGT` (390), `CMPHS` (391), `CMPHI` (392), `CMPLT` (393), `CMPLE` (394),
`CMPLO` (395), and `CMPLS` (396); that release's count is therefore 397 in
both option variants. Version 11.11 reuses these ten IDs for SVE integer
compare-with-immediate and therefore leaves that release's count at 397.
Version 11.12 appends `FCMEQ` (397), `FCMNE` (398), `FCMGE` (399), `FCMGT`
(400), `FCMLE` (401), and `FCMLT` (402); that release's count is therefore 403
in both option variants. Version 11.13 appends `FCMUO` (403), `FACGE` (404),
and `FACGT` (405), while reusing the existing `FCMGE`, `FCMGT`, `FCMEQ`, and
`FCMNE` IDs; that release's count is therefore 406 in both option variants.
Version 11.14 appends `FSUBR` (406), `FMAXNM` (407), `FMINNM` (408), `FMAX`
(409), `FMIN` (410), `FABD` (411), `FSCALE` (412), `FMULX` (413), and
`FDIVR` (414), while reusing `FADD`, `FSUB`, `FMUL`, and `FDIV`; that release's
count is therefore 415 in both option variants. Version 11.15 appends `FADDV`
(415), `FMAXNMV` (416), `FMINNMV` (417), `FMAXV` (418), and `FMINV` (419);
that release's count is 420. Version 11.16 appends `FADDA` (420), so the
release count is 421. Version 11.17 appends `FRINTN` (421), `FRINTP` (422),
`FRINTM` (423), `FRINTZ` (424), `FRINTA` (425), `FRINTX` (426), `FRINTI`
(427), and `FRECPX` (428), while reusing `FSQRT` (234), so that release's count
is 429 in both option variants. Version 11.18 appends `FRECPE` (429) and
`FRSQRTE` (430). Version 11.19 reuses both IDs for the fixed-width Advanced
SIMD forms, so that release's count remains 431. Version 11.21 appends
`SCVTF` (431) and `UCVTF` (432), so the count becomes 433 in both option
variants. Version 11.22 reuses IDs 431/432 for the additional merging S-to-S,
D-to-S, S-to-D, and D-to-D forms and therefore leaves the count at 433.
Version 11.23 appends `FCVT` (433), `FCVTZS` (434), and `FCVTZU` (435), so
`CDISASM_ARM_NAME_COUNT` is 436 in both option variants.
Version 11.24 appends `BFCVT` (436), so `CDISASM_ARM_NAME_COUNT` is 437 in
both option variants. This ID covers the exact merging SVE/SME encoding
documented below, not every architectural BFCVT encoding.
Version 11.25 appends `BFCVTNT` (437), so `CDISASM_ARM_NAME_COUNT` is 438 in
both option variants. `BFCVT` (436) is reused for its zeroing encoding;
`BFCVTNT` identifies both its merging and zeroing encodings.
Version 11.26 appends `BFCVTN` (438), so `CDISASM_ARM_NAME_COUNT` is 439 in
both option variants. The new ID identifies the exact unpredicated pair
narrowing forms documented below; `BFCVT` (436) is reused for the matching pair
conversion forms. There is no pair `BFCVTNT` allocation in these maps.
Register
IDs continue append-only from
`CDISASM_ARM_REG_CPM_IOACC_CTL_EL3` (163) through `VG` (374), with
`CDISASM_ARM_REG_COUNT` 375. Existing IDs through `VBIC` (75) and `V31` (162)
retain their version-5.2 values.

`instruction_flags` also carries architectural quality and address-direction
metadata. `ILLEGAL` means the encoding was structurally decoded but violates a
rule that makes execution unreliable; `UNPREDICTABLE` identifies the
constrained-unpredictable subtype and always implies `ILLEGAL`. This preserves
operands for diagnostics while making the condition impossible to overlook.
`ADDRESS_INCREMENT` and `ADDRESS_DECREMENT` retain the direction of multiple
transfers, independently of pre/post indexing and writeback.
`APPLE_PROPRIETARY` identifies every Apple-specific result;
`APPLE_AMX`, `APPLE_MUL53`, and `APPLE_SYSTEM` classify the three independent
families. The normal `SIMD` flag is also present on MUL53 because both operands
are `Vn.2D` vectors; AMX command operands are scalar `Xn` registers and do not
claim ordinary SIMD lane metadata. Floating AMX operations additionally carry
`FLOATING_POINT`.

ARMv8.0 ordered/exclusive transfers use four independent flags:
`ATOMIC` identifies the synchronization family, `ACQUIRE` and `RELEASE`
describe ordering, and `EXCLUSIVE` identifies monitor-based exclusive access.
The flags combine exactly as the encoding requires. Load destinations and
memory sources, store-status destinations, store data sources, pair operands,
SP/ZR selection, and byte/halfword/word/doubleword sizes retain normal operand
access metadata.

### Initial ARM coverage and limits

The A32 subset covers NOP, B/BL, BX/BLX, SVC, BKPT, the supported conditional
data-processing operations with immediate or shifted-register operands,
LDR/STR byte and word transfers (including unprivileged T variants), LDM/STM,
and PUSH/POP aliases. The decoder
tracks conditions, flag writes, addressing/writeback state, branch targets,
and register-list access.

The A64 subset covers NOP; B/BL, B.cond, CBZ/CBNZ, and TBZ/TBNZ; BR/BLR/RET;
ADR/ADRP; ADD/SUB immediate and flag-setting aliases; shifted-register logical
operations and MOV/TST aliases; MOVN/MOVZ/MOVK; scaled/unscaled byte, halfword,
word, and doubleword loads/stores; load/store pairs; ARMv8.0 `LDAR`/`STLR`,
`LDXR`/`LDAXR`, `STXR`/`STLXR`, and their byte, halfword, and pair variants;
and SVC/HVC/SMC/BRK.

With `USE_EXTRA_OPCODES=1`, the common ARMv8 scalar-register slice additionally
decodes shifted-register `ADD`/`SUB`; `ADC`/`SBC`; conditional selects;
signed/unsigned division; variable `LSL`/`LSR`/`ASR`/`ROR`; and
multiply-add/subtract. Canonical aliases include `NEG`/`NEGS`, `NGC`/`NGCS`,
`CINC`/`CSET`/`CINV`/`CSETM`/`CNEG`, `MUL`, and `MNEG`. Reserved shift fields
and out-of-range W-form amounts are rejected before the optional-feature gate.

The same option enables A64 logical-immediate `AND`, `ORR`, `EOR`, and `ANDS`
for both W and X widths. `ANDS` with destination 31 is returned canonically as
`TST`; `ORR` from ZR is returned as bitmask-immediate `MOV` only when a single
`MOVZ` or `MOVN` is not the preferred spelling. Non-flag-setting destination 31
is WSP/SP, while source 31 and the flag-setting destination remain WZR/XZR.
Reserved `N:imms` shapes are invalid in both option variants; valid shapes are
structurally owned but unsupported when the option is off. These forms reuse
established mnemonic IDs and therefore allocate no additional IDs.

Version 11.1 completes the 15-operation SVE predicate-logical submap:
`AND/ANDS`, `BIC/BICS`, `EOR/EORS`, `NAND/NANDS`, `NOR/NORS`, `ORR/ORRS`,
`ORN/ORNS`, and `SEL`. The first five previously available spellings are
reused; the ten new names above keep the catalog append-only. Logical forms
return typed `.b` destination/source predicates and a zeroing guard predicate;
`SEL` retains its untyped select guard. The `S` forms set
`CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS`; all forms set the scalable-vector
and predicated flags, record read/write access, and require the independent SVE
CPU capability. Canonical formatting includes the predicate type and `/z`
qualifier exactly where represented by the numeric operand flags.

The structural selector remains active with `USE_EXTRA_OPCODES=0`, so a valid
complete form is `UNSUPPORTED_INSTRUCTION`, the reserved selector is
`INVALID_INSTRUCTION`, and a short word is `TRUNCATED`. The unit and corpus
coverage also pin little-/big-endian equivalence, CPU and mode failures, and
zeroed failure results. Completing this predicate-logical submap does not make
the remaining SVE, SVE2, SME, or SME2 maps exhaustive.

Version 11.2 also completes the selected SVE unpredicated integer-arithmetic
class. `ADD`, `SUB`, `SQADD`, `UQADD`, `SQSUB`, and `UQSUB` accept `.b`, `.h`,
`.s`, and `.d` elements and admit either SVE or SME; Armv9.5 `ADDPT` and
`SUBPT` accept only their allocated `.d` form and strictly require SVE plus
CPA. The decoder owns all operation/width
slots, so the six smaller-width CPA encodings are invalid before CPU/runtime
validation. The 26 allocated forms emit three exact Z-register operands and
retain endian, mode, CPU, formatter, truncation, and OFF-build contracts.

Version 11.3 completes the selected SVE vector ZIP/UZP/TRN class. `ZIP1`,
`ZIP2`, `UZP1`, `UZP2`, `TRN1`, and `TRN2` accept byte, halfword, word,
and doubleword elements, for 24 allocated forms with three exact Z-register
operands. Operation selectors six and seven are unallocated at every width and
are invalid before CPU validation. Valid forms require A64 and SVE or SME:
A64FX proves the SVE-only route, while Apple A18/M4 prove the SME-only route.
At the 11.3 boundary the adjacent F64MM Q-element encodings remained a
disjoint unsupported class; version 11.20 implements that class separately.

Version 11.4 completes selectors 10--13 of the selected A64 SVE
unpredicated table-lookup region and its exact adjacent MOV-from-GPR subset.
Across `.b`, `.h`, `.s`, and `.d`, selector
10 is two-table-list `TBL`, selector 11 is extending `TBX`, selector 12 is
one-table-list `TBL`, and selector 13 is `TBXQ`, for 16 allocated lookup
forms. `TBL` writes its destination; `TBX` and `TBXQ` read and write it. The
more-specific selector-14 subset with bits 20:16 equal to zero adds four
allocated `MOV` forms from a general-purpose register into a Z register:
byte/halfword/word elements read a W register, doubleword reads X, and encoded
register 31 denotes WSP/SP. The rest of selector 14 contains other allocated
or outside-scope encodings; cdisasm deliberately does not claim them, so they
remain `UNSUPPORTED_INSTRUCTION` rather than being misclassified as reserved.
Selector 15 is separately and exactly owned as `INVALID_INSTRUCTION`.

The alternative feature gates remain exact. One-table `TBL` and MOV-from-GPR
admit SVE or SME; two-table `TBL` and `TBX` admit SVE2 or SME; `TBXQ` admits
SVE2.1 or SME2.1. No named CPU profile currently asserts a 2.1 capability, so
`TBXQ` is accepted only by `CDISASM_ARM_CPU_ANY`. A64FX proves the SVE route
for one-table `TBL` and MOV but rejects the SVE2 forms. Apple A18/M4 prove the
SME route for both TBL variants, `TBX`, and MOV, but reject `TBXQ`; Cortex-A53
rejects the whole block. The adjacent selector-8 indexed `DUP` class is now
owned as generated form 2439 and uses the preferred `MOV` spelling; selector 9
is handled separately as `DUPQ`. With extra opcodes disabled, the lookup/MOV
and DUP classes remain structurally owned and return
`UNSUPPORTED_INSTRUCTION`; the unowned adjacent selector-14 controls remain
`UNSUPPORTED_INSTRUCTION` in both option variants, while selector 15 remains
`INVALID_INSTRUCTION`.

Version 11.5 separately owns the disjoint SVE2.1/SME2.1 `TBLQ` class with the
exact descriptor `(word & 0xff20fc00) == 0x4400f800`. Bits 23:22 select
byte, halfword, word, or doubleword elements; bits 20:16, 9:5, and 4:0 select
`Zm`, `Zn`, and `Zd`. Every value of those variable fields is allocated, for
4 × 32 × 32 × 32 = 131,072 valid words and no reserved subcontrol inside the
descriptor. The result writes `Zd`, reads a singleton scalable-register list
rooted at `Zn`, and reads index register `Zm`; all three operands carry the
selected element type. Canonical text retains braces around the singleton
table list.

`TBLQ` requires A64 plus SVE2.1 or SME2.1. `CDISASM_ARM_CPU_ANY` provides the
explicit unrestricted analysis route, but no current named CPU profile claims
either 2.1 capability, including A64FX and Apple A18/M4. The structural
descriptor remains active with extra opcodes off, so every complete valid word
is `UNSUPPORTED_INSTRUCTION`; truncation remains `TRUNCATED`. Fixed-bit changes
leave this exact class and may belong to other allocated SVE instructions, so
they remain unowned rather than being guessed as invalid `TBLQ` encodings.
The dedicated suite exhausts the complete descriptor in both option variants
and separately checks B/H/S/D formatting, little-/big-endian parity, generic
dispatch, named-CPU gates, and adjacent ownership.

Version 11.6 owns the exact destructive predicated SVE integer class
`(word & 0xff20e000) == 0x04000000`. It contains 74 allocated
operation/element-width pairs across 22 operations: `ADD`, `SUB`, and `SUBR`;
`ADDPT` and `SUBPT`; signed/unsigned MIN/MAX and absolute difference; `MUL`,
`SMULH`, and `UMULH`; `SDIV`, `UDIV`, `SDIVR`, and `UDIVR`; and `AND`,
`BIC`, `EOR`, and `ORR`. Ordinary operations admit byte, halfword, word, and
doubleword elements except the divide family, which admits word/doubleword.
`ADDPT`/`SUBPT` admit only doubleword and require SVE plus CPA; other allocated
forms require SVE or SME.

The exhaustive class sweep covers all 1,048,576 words selected by the mask:
606,208 are allocated and 442,368 are reserved. The result retains typed Z and
predicate operands, destructive destination access, predication, exact CPU
gates, and endian parity. Valid forms remain structurally owned as unsupported
with extra opcodes off, while reserved controls remain invalid.

Version 11.7 owns three exact predicated SVE unary classifiers. The integer
classifier `(word & 0xff28e000) == 0x0400a000` contains `SXTB`, `UXTB`,
`SXTH`, `UXTH`, `SXTW`, `UXTW`, `ABS`, and `NEG`; extension widths are
restricted by their source size while `ABS` and `NEG` accept B/H/S/D. The
bitwise classifier `(word & 0xff28e000) == 0x0408a000` contains `CLS`, `CLZ`,
`CNT`, `CNOT`, `NOT`, and H/S/D `FABS`/`FNEG`; its eighth operation selector
and byte floating forms are reserved. The reverse classifier
`(word & 0xff3cc000) == 0x05248000` contains H/S/D `REVB`, S/D `REVH`, D
`REVW`, and B/H/S/D `RBIT`.

Across all register and predicate fields, the three classifiers contain
917,504 allocated words and 393,216 reserved words. Allocated results write the
typed Z destination, read the typed Z source and guard predicate, and retain
the selected merge or zero predication metadata; `FABS` and `FNEG` additionally
carry the floating-point flag. Merge `/m` forms require A64 plus SVE or SME.
Zero `/z` forms require A64 plus SVE2p2 or SME2p2. Legality precedes CPU and
build-option validation, so reserved words are invalid in either option
variant, valid extra-opcode-OFF words are unsupported, and incomplete words are
truncated.

Version 11.8 owns the exact predicated SVE vector-shift classifier
`(word & 0xff30e000) == 0x04108000`. Controls zero, one, and three select
same-width `ASR`, `LSR`, and `LSL`; controls four, five, and seven select
`ASRR`, `LSRR`, and `LSLR`. Those forms accept B/H/S/D elements. Controls
eight, nine, and eleven select the wide-count direct `ASR`, `LSR`, and `LSL`
forms for B/H/S destinations with a `.d` count source; their doubleword
destination controls are reserved. Every other operation control is reserved.

Across all register and predicate fields, the classifier contains 524,288
words: 270,336 allocated and 253,952 reserved. Allocated results write and read
the destructive typed Z destination, read the typed Z count source and guard
predicate, retain merge `/m` metadata, and require A64 plus SVE or SME. Legality
precedes feature and build-option validation, so reserved words are invalid in
both option variants, valid extra-opcode-OFF words are unsupported, and short
inputs are truncated. This exact ownership does not imply coverage of adjacent
conversion, narrowing, or predicated-shift maps outside the separately exact
classifiers below.

Version 11.9 owns the disjoint predicated SVE/SVE2 immediate-shift classifier
`(word & 0xff30e000) == 0x04008000`. The combined seven-bit encoded immediate
from bits 23:22 and 9:5 is reserved below eight. Values 8--127 select the
element width B/H/S/D from their highest set bit. Right-shift forms report
`2 * element_bits - encoded_immediate`; left-shift forms report
`encoded_immediate - element_bits`. Operation controls zero, one, three, and
four select `ASR`, `LSR`, `LSL`, and `ASRD`; controls six, seven, twelve,
thirteen, and fifteen select `SQSHL`, `UQSHL`, `SRSHR`, `URSHR`, and
`SQSHLU`. Every other operation control is reserved.

Across all register and predicate fields, the classifier contains 524,288
words: 276,480 allocated and 247,808 reserved. Allocated results write and read
the destructive typed Z destination, read `Pg/m`, and carry the exact numeric
immediate. `ASR`, `LSR`, `LSL`, and `ASRD` require A64 plus SVE or SME; the
saturating and rounding operations require A64 plus SVE2 or SME. Legality
precedes feature and build-option validation, so reserved words are invalid in
both option variants, valid extra-opcode-OFF words are unsupported, and short
inputs are truncated. This exact ownership does not imply coverage of adjacent
conversion, narrowing, or predicated-shift maps outside the separately exact
classifier below.

The current tranche owns the separate predicated SVE2/SME variable
shift/saturating-round classifier
`(word & 0xff30e000) == 0x44008000`. Bits 19:16 select `SRSHL`, `SRSHLR`,
`SQSHL`, `SQRSHL`, `SQSHLR`, `SQRSHLR`, `URSHL`, `URSHLR`, `UQSHL`,
`UQRSHL`, `UQSHLR`, or `UQRSHLR`; selector values 0, 1, 4, and 5 are
reserved. Every one of the four size values selects matching B/H/S/D operands.

Across all register and predicate fields, this classifier contains 524,288
words: 393,216 allocated and 131,072 reserved. Allocated results expose the
four-operand `Zdn.T, Pg/m, Zdn.T, Zm.T` schema, with the first destination
read/write and all other operands read. They carry exactly scalable-vector and
predicated metadata and require A64 plus SVE2 or SME. Legality precedes feature
and build-option validation, so reserved words are invalid in both option
variants, valid extra-opcode-OFF words are unsupported, and short inputs are
truncated.

Version 11.10 owns the exact A64 SVE integer vector-compare classifier
`(word & 0xff200000) == 0x24000000`. Its six ordinary same-width controls are
`CMPEQ`, `CMPNE`, `CMPGE`, `CMPGT`, `CMPHS`, and `CMPHI`. Its ten wide-source
controls are `CMPEQ`, `CMPNE`, `CMPGE`, `CMPGT`, `CMPLT`, `CMPLE`, `CMPHS`,
`CMPHI`, `CMPLO`, and `CMPLS`. All 16 operation controls allocate byte,
halfword, and word destinations; only the six ordinary same-width controls
allocate doubleword. Wide forms use a `.d` second source and reject a
doubleword destination.

Across every destination predicate, governing predicate, and source-register
field, the classifier owns 8,388,608 words: 7,077,888 allocated and 1,310,720
reserved. An allocated result writes typed `Pd`, reads zeroing `Pg/z`, reads
two typed Z sources, and sets the scalable-vector, predicated, and
`SETS_FLAGS` metadata because these compares update NZCV. Valid forms require
A64 plus SVE or SME. Legality precedes CPU and build-option validation, so
reserved words are invalid in either option variant, valid extra-opcode-OFF
words are unsupported, and one-, two-, or three-byte inputs are truncated
(zero bytes report `END_OF_INPUT`). This
exact completion does not imply coverage of adjacent SVE compare, predicate,
floating-point, or reduction classes.

Version 11.11 owns two exact A64 SVE integer compare-with-immediate envelopes.
The signed envelope `(word & 0xff204000) == 0x25000000` encodes a signed
five-bit immediate (`-16`--`15`). Selector bits 15:13 allocate `000` for
`CMPGE`/`CMPGT`, `001` for `CMPLT`/`CMPLE`, and `100` for `CMPEQ`/`CMPNE`;
`101` is reserved, with bit 4 selecting the second mnemonic in each pair. Its
4,194,304 owned words split into 3,145,728 allocated and 1,048,576 reserved.
The unsigned envelope `(word & 0xff200000) == 0x24200000` encodes an unsigned
seven-bit immediate (`0`--`127`); bit 13 and bit 4 select `CMPHS`, `CMPHI`,
`CMPLO`, or `CMPLS`. All 8,388,608 words in that envelope are allocated.

Both envelopes allocate B/H/S/D element widths, `Pd` in P0--P15, zeroing
`Pg/z` in P0--P7, and `Zn` in Z0--Z31. The result writes `Pd`, reads `Pg` and
`Zn`, stores the signed or unsigned immediate numerically, and sets scalable,
predicated, and `SETS_FLAGS` metadata because the instruction updates NZCV.
Valid forms require A64 plus SVE or SME. Legality precedes CPU/build gating:
the signed reserved selector is invalid in either option variant, allocated
OFF-build words are unsupported, and incomplete inputs are truncated. Across
both envelopes, the decoder owns 12,582,912 words: 11,534,336 allocated and
1,048,576 reserved. This exact completion does not imply coverage of adjacent
SVE compare, predicate, floating-point, or reduction classes.

Version 11.12 owns the exact A64 SVE/SME floating compare-with-zero classifier
`(word & 0xff3ce000) == 0x65102000`. Size controls one, two, and three select
halfword, word, and doubleword floating elements; size zero is reserved.
Operation controls zero through four and six select `FCMGE`, `FCMGT`, `FCMLT`,
`FCMLE`, `FCMEQ`, and `FCMNE`; controls five and seven are reserved. Across
all `Pd`, `Pg`, and `Zn` fields, the classifier owns 131,072 words: 73,728
allocated and 57,344 reserved.

An allocated result writes typed `Pd` in P0--P15, reads zeroing `Pg/z` in
P0--P7 and typed `Zn` in Z0--Z31, and stores the floating zero operand as
numeric immediate metadata. It sets `SCALABLE_VECTOR`, `PREDICATED`, and
`FLOATING_POINT`; unlike the neighboring integer compare classes, it does not
set `SETS_FLAGS` because these forms do not update NZCV. Valid forms require
A64 plus SVE or SME. Reserved words are invalid in both option variants,
allocated words are unsupported when `USE_EXTRA_OPCODES=0`, and one-, two-,
or three-byte inputs are truncated. This exact classifier does not imply
coverage of other SVE/SME floating compares, reductions, conversions, or
adjacent predicate-producing maps.

Version 11.13 owns the exact A64 SVE/SME floating vector-compare classifier
`(word & 0xff204000) == 0x65004000`. Operation controls zero through five and
seven select `FCMGE`, `FCMGT`, `FCMEQ`, `FCMNE`, `FCMUO`, `FACGE`, and
`FACGT`; control six is reserved. H/S/D elements are allocated and byte width
is reserved. Across every `Pd`, `Pg`, `Zn`, and `Zm` field, the class owns
4,194,304 words: 2,752,512 allocated and 1,441,792 reserved.

Allocated results write typed `Pd` in P0--P15 and read zeroing `Pg/z` in
P0--P7 plus two typed Z sources. They set `SCALABLE_VECTOR`, `PREDICATED`, and
`FLOATING_POINT` without setting NZCV, and require A64 plus either SVE or SME.
Canonical disassembly retains the encoded source order for assembler aliases
such as `FCMLE`/`FCMLT` and `FACLE`/`FACLT`. Reserved words remain invalid in
both option variants, allocated OFF-build words are unsupported, and incomplete
inputs are truncated. This exact slice still does not imply complete SVE/SME
floating comparison, conversion, reduction, or predicate-producing coverage.

Version 11.14 owns the exact baseline A64 SVE/SME destructive predicated
floating-point binary class beneath `(word & 0xff30e000) == 0x65008000`, while
excluding separately featured B16B16 and FAMINMAX encodings. H/S/D operation
controls zero through ten and 12--13 select `FADD`, `FSUB`, `FMUL`, `FSUBR`,
`FMAXNM`, `FMINNM`, `FMAX`, `FMIN`, `FABD`, `FSCALE`, `FMULX`, `FDIVR`, and
`FDIV`; control 11 is reserved. Six exact disjoint descriptor masks own
344,064 words: 319,488 allocated and 24,576 reserved.

Allocated results read/write typed `Zdn`, read merging `Pg/m` in P0--P7 and a
typed `Zm`, and set `SCALABLE_VECTOR`, `PREDICATED`, and `FLOATING_POINT`.
They require A64 plus either SVE or SME. Reserved words remain invalid in both
option variants, allocated OFF-build words are unsupported, and incomplete
inputs are truncated. This baseline classifier remains disjoint from the
separately featured B16B16 row below and does not claim FAMINMAX, other
predicated FP maps, reductions, conversions, SVE2, or SME2.

The current post-12.0 tranche owns the seven exact FEAT_SVE_B16B16 halfword
classes `BFADD`, `BFSUB`, `BFMUL`, `BFMAXNM`, `BFMINNM`, `BFMAX`, and
`BFMIN`. Their respective masked values are `0x65008000`, `0x65018000`,
`0x65028000`, `0x65048000`, `0x65058000`, `0x65068000`, and `0x65078000`
under mask `0xffffe000`. Every allocated result exposes destructive
`Zdn.H, Pg/M, Zdn.H, Zm.H` operands and the scalable-vector, predicated, and
floating-point flags. The seven classes contain 57,344 allocated words; the
adjacent selector 3 class contains 8,192 invalid words. Generated feature ID
141 is the independent FEAT_SVE_B16B16 gate. No current named profile carries
that capability, so only `CPU_ANY` admits the allocated forms; an extras-OFF
build reports them unsupported.

Version 11.15 owns the exact baseline A64 SVE/SME floating-point fast-
reduction class under `(word & 0xff38e000) == 0x65002000`. H/S/D operation
selector zero is `FADDV`; selectors four through seven are `FMAXNMV`,
`FMINNMV`, `FMAXV`, and `FMINV`. Byte width and selectors one through three
are reserved. Across every scalar destination, P0--P7 governing predicate,
and scalable source field, the classifier owns 262,144 words: 122,880
allocated and 139,264 reserved.

Allocated results write a scalar H/S/D register and read an unqualified
predicate plus typed scalable Z source. They set `SCALABLE_VECTOR`,
`PREDICATED`, and `FLOATING_POINT`, and require A64 plus SVE or SME. Reserved
words stay invalid in both option variants; allocated OFF-build words are
unsupported and incomplete words are truncated. This exact slice does not
claim other SVE/SME reductions, conversions, or adjacent FP maps.

Version 11.16 owns the exact A64 SVE strictly ordered scalar-accumulating
floating-point add reduction classifier
`(word & 0xff3fe000) == 0x65182000`. Across every scalar accumulator,
P0--P7 governing predicate, and scalable source, it owns 32,768 words:
24,576 H/S/D encodings are allocated and all 8,192 byte-width encodings are
reserved.

Allocated results preserve the architectural four-operand representation:
read/write scalar `Vdn`, read predicate `Pg`, the same scalar `Vdn` again as a
read, and read typed scalable `Zm`. They set `SCALABLE_VECTOR`, `PREDICATED`,
and `FLOATING_POINT`, require A64 plus ARMv8 and specifically FEAT_SVE, and do
not admit an SME-only profile. Reserved words stay invalid in both option
variants; allocated extras-OFF words are unsupported and incomplete inputs are
truncated. Streaming-SVE/SME execution-state legality is outside the current
mode model.

Version 11.17 owns four disjoint A64 SVE predicated FP-unary classifiers:
merging controls 0--7 use mask/value `0xff38e000/0x6500a000`, merging
controls 12--13 use `0xff3ee000/0x650ca000`, zeroing controls 0--7 use
`0xff3e8000/0x64188000`, and zeroing controls 12--13 use
`0xff3fc000/0x641b8000`. Controls 0--4, 6--7, and 12--13 select the seven
`FRINT*` operations, `FRECPX`, and `FSQRT`; control 5 and size=00 are
reserved. Other adjacent controls remain unowned.

The exact union owns 655,360 words: 442,368 H/S/D encodings are allocated and
212,992 byte-width or control-5 encodings are reserved. Merging results carry
a read/write `Zd`, `Pg/m`, and read `Zn`, and require SVE or SME. Zeroing
results carry a write-only `Zd`, `Pg/z`, and read `Zn`, and require SVE2p2 or
SME2p2. All results retain scalable-vector, predicated, and floating-point
metadata; allocated extras-OFF inputs are unsupported and reserved inputs are
invalid.

Version 11.18 owns the exact unpredicated A64 SVE/SME floating-point estimate
classifier `(word & 0xff3efc00) == 0x650e3000`. Bit 16 selects `FRECPE` or
`FRSQRTE`; size fields 1, 2, and 3 select H, S, and D elements. Across every
`Zd` and `Zn`, the classifier owns 8,192 words: 6,144 are allocated and the
2,048 size-zero byte forms are reserved. Allocated results write typed `Zd`,
read typed `Zn`, set `SCALABLE_VECTOR` and `FLOATING_POINT`, and require A64
plus SVE or SME. They have no predicate operand or `PREDICATED` flag. Valid
extras-OFF forms are unsupported, reserved forms are invalid, and incomplete
inputs are truncated.

Version 11.19 owns the disjoint fixed-width Advanced SIMD scalar/vector
estimate union selected by `(word & 0xdffffc00) == 0x5ef9d800`,
`(word & 0xdfbffc00) == 0x5ea1d800`,
`(word & 0x9ffffc00) == 0x0ef9d800`, or
`(word & 0x9fbffc00) == 0x0ea1d800`. The U bit selects the reused `FRECPE` or
`FRSQRTE` ID. Scalar H/S/D and vector 4H/8H/2S/4S/2D forms are allocated;
vector `Q=0,sz=1`, which would describe a one-lane-D vector, is reserved.
Across both operations and every register pair, the exact union owns 18,432
words: 16,384 are allocated and 2,048 are reserved. Results write typed `Vd`,
read typed `Vn`, and carry Advanced SIMD plus floating-point metadata. Every
valid form requires A64 and NEON; H/4H/8H additionally require FP16. Allocated
extras-OFF forms are unsupported, reserved forms are invalid, incomplete inputs
are truncated, and successful little-/big-endian metadata is identical. The
masks and reserved controls follow Arm's official
[A64 XML package](https://developer.arm.com/-/cdn-downloads/permalink/Exploration-Tools-A64-ISA/ISA_A64/ISA_A64_xml_A_profile-2025-12.tar.gz).

Version 11.20 owns the disjoint FEAT_F64MM SVE Q-element permutation class
selected by `(word & 0xffe0e000) == 0x05a00000`. Selector values zero through
three map to `ZIP1`, `ZIP2`, `UZP1`, and `UZP2`; values six and seven map to
`TRN1` and `TRN2`; values four and five are reserved. Across every `Zd`, `Zn`,
and `Zm` field the exact envelope contains 262,144 words: 196,608 are
allocated and 65,536 are reserved. Successful results write `Zd.q`, read
`Zn.q` and `Zm.q`, carry scalable-vector metadata, and represent the `.q`
element as 16 bytes. Valid forms require A64, ARMv8, F64MM, and
`USE_EXTRA_OPCODES=1`. Only `CPU_ANY` currently advertises F64MM; all named
profiles, including A64FX and Apple M4, reject it conservatively. Allocated
OFF-build forms are unsupported, reserved selectors are invalid, incomplete
inputs are truncated, and little-/big-endian decoding produces identical
metadata.

Arm's execution pseudocode additionally makes these forms undefined when the
implemented SVE vector length is below 256 bits. The decoder API models the
static instruction mode and CPU feature profile, not live vector length, so it
does not enforce that execution-state condition.

Version 11.21 appends `SCVTF` (431) and `UCVTF` (432) for the exact
`(word & 0xfff8e000) == 0x6550a000` A64 SVE/SME integer-to-FP16 classifier.
Selectors zero and one are reserved. Selectors two through seven are
respectively `SCVTF H`, `UCVTF H`, `SCVTF S`, `UCVTF S`, `SCVTF D`, and
`UCVTF D`; the destination is always H. Across every `Pg`, `Zn`, and `Zd`
field, the
65,536-word envelope contains 49,152 allocated and 16,384 reserved words.
Allocated results read and write typed `Zd.h`, read merging `Pg/m`, and read
typed `Zn`; both the predicate and source record the encoded source element
size. Instruction flags identify scalable-vector, predicated, and floating-
point semantics. Valid forms require A64, ARMv8, and either SVE or SME. A64FX
proves the SVE route, while Apple A18/M4 prove the SME route. Allocated
extras-OFF forms are unsupported, reserved selectors are invalid, incomplete
inputs are truncated, and little-/big-endian results are identical.

Version 11.22 reuses the same IDs for four disjoint exact classifiers:
`(word & 0xfffee000)` equals `0x6594a000`, `0x65d4a000`, `0x65d0a000`, or
`0x65d6a000`. Together they allocate 65,536 merging words for the signed and
unsigned S-to-S, D-to-S, S-to-D, and D-to-D arrangements. Successful results
read and write typed `Zd`, read `Pg/m` at the source granularity, read typed
`Zn`, and retain scalable-vector, predicated, and floating-point metadata.
Valid forms require A64, ARMv8, and either SVE or SME. A64FX proves the SVE
route; Apple A18 and M4 prove the SME route. Every allocated word becomes a
zeroed unsupported result when extra opcodes are disabled; endian, generic-
dispatch, formatting, truncation, and fixed-neighbor behavior are covered by
the focused suite. This bounded completion does not imply complete SVE/SME
conversion coverage.

Version 11.23 appends the three floating-conversion IDs for the complete
baseline merging class. `FCVT` owns six precision-changing H/S/D forms in three
disjoint pairs. `FCVTZS` and `FCVTZU` each own seven H/S/D floating-to-integer
forms. Together the exact classifiers own 204,800 words: 163,840 are allocated
and 40,960 selector controls are reserved. Successful results read and write a
typed `Zd`, read `Pg/m` at source granularity, and read typed `Zn`; they carry
scalable-vector, predicated, and floating-point metadata. All valid forms
require A64, ARMv8, and either SVE or SME. A64FX proves the SVE route, while
Apple A18 and M4 prove the SME route. Version 11.23 did not claim the distinct
BFCVT encoding adjacent to the `FCVT` pairs; the other
reserved selector is owned and invalid. The focused suite also locks endian,
generic-dispatch, formatter, truncation, CPU, and extras-OFF behavior.

The current post-12.0 tranche additionally owns zeroing
`FCVT Zd.H, Pg/z, Zn.S` form 2952 under mask/value
`0xffffe000/0x649a8000`. All 8,192 register/predicate combinations are
allocated. The destination is write-only, the zeroing predicate is read at
single-precision source granularity, and `Zn.S` is read; successful results
carry scalable-vector, predicated, and floating-point metadata. Admission
requires A64, ARMv8, and either SVE2.2 or SME2.2. No current named profile
advertises those capabilities, so the form is `CPU_ANY`-only; extras-OFF
builds report it unsupported.

The same current tranche completes three neighboring unpredicated conversion
areas. SVE indexed `DUP` uses `(word & 0xff20fc00) == 0x05202000`; a nonzero
`tsz` selects B/H/S/D/Q element size and lane, and generated form 2439 is
formatted with Arm's preferred `MOV` alias. The FP8 pair-narrowing envelope
`(word & 0xfffff020) == 0x650a3000` uses bits 11:10 for `FCVTN`, `FCVTNB`,
`BFCVTN`, and `FCVTNT` forms 3165--3168. Each writes one byte-element Z
register and reads an even consecutive H- or S-element Z-register pair; all
four require FP8 plus SVE2 or SME2 and are currently `CPU_ANY`-only. The SME2
two-vector row now owns every form 4312--4324: `FCVT`, `BFCVT`, `FCVTN`,
`BFCVTN`, `FCVTZS`, `FCVTZU`, `SCVTF`, `UCVTF`, `SQCVT`, `SQCVTU`,
`UQCVT`, and the FP8 `BFCVT`/`FCVT` forms. Its floating/integer conversions use
exact two-register source and, when architecturally required, destination
lists. Exact adjacent classes add SME2 `SUNPK`/`UUNPK` forms 4325--4326 and
the SME2+FP8 `F1CVT`, `BF1CVT`, `F2CVT`, and `BF2CVT` widening row, including
the four `L` variants, forms 4327--4334. `SUNPK`/`UUNPK` encoded size zero is
reserved; sizes 01/10/11 select B-to-H, H-to-S, and S-to-D. Together these
focused two-vector classes classify 14,848 allocated and 7,680 reserved words. Other allocated
families remain unsupported, and the stateless API still does not model
streaming state or preceding-instruction MOVPRFX constraints.

The following exact post-12.0 forms extend that bounded area. Forms 2881--2883
use mask `0xfffffc20` and values `0x45314000`, `0x45315000`, and
`0x45314800` for `SQCVTN`, `SQCVTUN`, and `UQCVTN`. They write `Zd.H`, read an
even-aligned consecutive pair of `.S` source vectors, require SVE2.1 or SME2,
and reject the adjacent bit-5 half of each row. Forms 4335--4338 use mask
`0xfffffc21` at `0xc1a8e000`, `0xc1a9e000`, `0xc1aae000`, and `0xc1ace000`.
They write an even `.S` destination pair, read an even `.S` source pair, and
select SME2 `FRINTN`, `FRINTP`, `FRINTM`, and `FRINTA`; bit 5 or bit 0 set is
reserved. Forms 4339--4340 use mask `0xfffffc01` at `0xc1a0e000` and
`0xc1a0e001`. SME_F16F16 `FCVT`/`FCVTL` write an even `.S` destination pair
and read any single `Zn.H`. Their generated SME_F16F16 feature is independent
of the baseline SME2 gate, so named profiles without that exact feature reject
them. All three families preserve endian parity, extras-OFF structural
ownership, scalable-vector metadata, and canonical consecutive-list text; the
SME2 and SME_F16F16 forms additionally carry SME metadata.

Forms 4341--4362 complete the adjacent SME2 four-vector block. Forms
4341--4344 convert between aligned four-Z `.s` lists; 4345--4350 are the six
saturating narrowing variants, and FP8 forms 4351--4352 narrow a four-Z `.s`
list to one `.b` destination. `SUNPK`/`UUNPK` forms 4353--4354 widen an
aligned two-Z B/H/S list into four H/S/D vectors and reject encoded size zero.
Forms 4355--4356 perform four-list `ZIP`/`UZP` at B/H/S/D widths, while
4357--4358 are their fixed `.q` forms. Finally, forms 4359--4362 implement
four-list single-precision `FRINTN`/`FRINTP`/`FRINTM`/`FRINTA`; all other
size/operation selectors in that envelope are invalid. The focused suite
classifies all 5,504 allocated words and 3,072 reserved neighbors, checks
little-/big-endian parity, feature/profile and extras-OFF ownership, and
canonical aligned-list formatting. Every form requires SME2; 4351--4352 also
require FP8.

Forms 4363--4370 are one bounded SME three-operand multiply lattice under four
exact classifiers. Mask/value `0xff21fc21/0xc120e400` selects an aligned
two-Z destination list, aligned two-Z first source, and aligned two-Z second
source. `0xff23fc63/0xc121e400` is the corresponding aligned four-list form.
`0xff21fc21/0xc120e800` and `0xff21fc63/0xc121e800` retain the two- and
four-Z destination/first-source lists but use a scalar second source restricted
to `z0`--`z15`. Sizes one through three select `FMUL` H/S/D and require
SME2.2. Size zero is reserved from FMUL and instead selects fixed-H `BFMUL`,
which requires SME2 plus the generated FEAT_SVE_BFSCALE requirement.

The two-list/list, four-list/list, two-list/scalar, and four-list/scalar
classifiers respectively contain 12,288+4,096, 1,536+512, 12,288+4,096, and
3,072+1,024 FMUL+BFMUL words. Thus the exact union has 29,184 FMUL and 9,728
BFMUL allocations, 38,912 total, and no globally reserved word: all 9,728
size-zero cells excluded from FMUL are owned by BFMUL. Successful results
write the destination list, read the list first source, and read either a list
or scalar third operand at the selected element width. They carry SME,
scalable-vector, and floating-point flags. No current named profile exposes
the complete generated SME2.2 or SME2+SVE_BFSCALE requirement; all therefore
reject these forms, while `CDISASM_ARM_CPU_ANY` is the positive analysis route.
Allocated extras-OFF inputs remain structurally owned and return
`UNSUPPORTED_INSTRUCTION`.

The focused `cdisasm_arm_sme_fmul_tests` suite enumerates all 38,912 words and
checks operand access and alignment, the scalar-register ceiling, exact form
IDs and features, every named profile, fixed neighbors, truncation, endian and
generic-dispatch parity, and canonical braced-list text. Eight reviewed fuzz
seeds independently reach BFMUL and FMUL in each of the four envelopes. Pinned
AARCHMRS leaves and LLVM 21 legal and rejected assembly cases provide the
independent encoding oracle.

Forms 4373--4380 and 4385--4386 are the exact baseline-SME predicated
contiguous ZA-slice forms `LD1B/H/W/D/Q` and `ST1B/H/W/D/Q`. All ten use
mask `0xffe00010`; their fixed values are `0xe0000000` through `0xe0e00000`
in alternating load/store steps of `0x00200000`, plus `0xe1c00000` and
`0xe1e00000` for Q. Each leaf varies twenty bits and allocates 1,048,576
words, so the union has 10,485,760 allocated words and no reserved cell.
Rm=31 is the omitted XZR index; other indexes are X0--X30 and use no shift
for B or `LSL #1/#2/#3/#4` for H/W/D/Q. V selects horizontal/vertical,
Rs maps to W12--W15, Pg to P0--P7, and Rn to X0--X30/SP. Low bits divide
between ZA view number and offset as B 0:4, H 1:3, S 2:2, D 3:1, and Q 4:0.

The tile operand is written by a load and read by a store. Loads read a
zeroing predicate; stores read an unqualified predicate. Memory has reciprocal
read/write access and runtime `size == 0`, while tile and predicate
`extend_type` retain the element width, including 16 for Q. Successful results
carry exactly SME, matrix, scalable-vector, and predicated flags; execution-
state legality is intentionally not inferred as a streaming flag. SME admits
`CPU_ANY`, Apple A18, and Apple M4. The focused test checks 20,480
factorized-exhaustive field combinations plus boundaries, formatter schema,
profiles, endian/generic transport, truncation, and extras/formatter-off
behavior. Pinned AARCHMRS is the allocation oracle; LLVM 21 and Capstone 5
independently agree on all H/V endpoint encodings and index shifts.

Baseline-SME predicated ZA-slice `MOVA` insert forms 3862--3866 and extract
forms 3877--3881 are exact and format with the preferred `MOV` alias. Their
two disjoint classifiers expose B/H/S/D/Q ZA views, horizontal/vertical
selection, W12--W15 slice selectors, P0--P7 merge predicates, Z0--Z31, and
the element-width-specific tile-number/offset split. Insert reads Z and
read/writes ZA; extract reads ZA and read/writes Z. The Q selector is allocated
only when its dedicated control bit accompanies size three; the other three
control/size combinations are invalid. Results carry SME, matrix,
scalable-vector, and predicated flags. `CPU_ANY`, Apple A18, and Apple M4 admit
the baseline SME requirement. The focused suite checks 10,880 bounded field
combinations, all ten exact metadata layouts, reserved controls, profiles,
both byte orders, generic dispatch, canonical formatting, forged-result
rejection, truncation, and extras-off ownership against pinned AARCHMRS and
LLVM 21.

SME2 multi-register `MOVA` insert forms 3867--3876 and extract forms
3882--3891 are exact and format with the preferred `MOV` alias. Z operands are
explicit contiguous aligned pairs or quads. Ordinary ZA operands use B/H/S/D
horizontal or vertical slices with a two- or four-element range; the D-only
whole-array forms use `ZA.D[W8-W11, off, VGx2|VGx4]`. Together with the
baseline classifier above, the implemented ZA-transfer slice covers
B/H/S/D/Q views and both contiguous and explicit ZA slice layouts. Inserts
write the tile and read the Z list; extracts read the tile and write the list.
All twenty forms require SME2, carry SME, matrix, and scalable-vector metadata,
and are admitted by `CPU_ANY`, Apple A18, and Apple M4. Reserved high slice bits
in the byte/halfword/word quad leaves remain invalid. The focused suite
checks 12,288 bounded cases plus the reserved quad controls and verifies
reciprocal access, list alignment, form identity, canonical text, profiles,
endian/generic transport, truncation, and extras-off ownership against pinned
AARCHMRS.

SME2.1 zeroing ZA-extract `MOVAZ` forms 3892--3906 are exact. Forms
3892--3896 write one B/H/S/D/Q Z register from a horizontal or vertical ZA
slice selected by W12--W15. Forms 3897--3900 and 3901--3904 write encoded,
aligned pairs and quads of B/H/S/D registers. Forms 3905--3906 write a pair
or quad from whole `ZA.D[W8-W11, off, VGx2|VGx4]`. ZA is read, every visible
Z destination is write-only, no predicate is present, and the mnemonic stays
`MOVAZ` rather than using the `MOV` alias. Successful results carry SME,
matrix, and scalable-vector flags and require FEAT_SME2p1. Only `CPU_ANY`
currently admits them; every named profile, including Apple A18 and M4,
rejects them because those Apple profiles stop at SME2. Single-Q selector
neighbors and B/H/S quad high-slice controls remain invalid. The focused suite
checks all 26,624 allocated control words plus those reserved controls and
locks access, alignment, canonical text, profiles, endian/generic transport,
truncation, forged-schema rejection, and extras/formatter-off ownership.
Pinned AARCHMRS supplies the exact allocation; LLVM 21 confirms representative
encodings with `+sme2p1` and rejects them with `+sme2` alone.

Forms 4381--4382 are the exact baseline-SME ZA array-vector load/store leaves.
Mask/value `0xffff9c10/0xe1000000` selects
`LDR ZA[Wv, off], [Xn|SP, #off, MUL VL]`; value `0xe1200000` under the same
mask selects `STR`. Bits 14:13 select W12--W15, bits 9:5 select X0--X30 or
SP, and bits 3:0 provide one shared unsigned 0--15 ZA array-vector selector
offset and memory-displacement coefficient. Each leaf has 2,048 words, so all
4,096 words in the union are allocated. LDR writes the tile and reads memory; STR
reverses those accesses. Successful results carry SME, matrix, and scalable-
vector flags, require A64, ARMv8, and SME, and deliberately do not claim a
streaming execution state. `CPU_ANY`, Apple A18, and Apple M4 admit the
feature; all other current named profiles reject it.

One complete ZA array vector is transferred. Its runtime memory size is
SVL/8 bytes (16--256), represented exactly as `size == 0`. For nonzero
offsets the memory operand's `imm` is the coefficient and its flags are
exactly `CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT |
CDISASM_ARM_OPERAND_FLAG_VL_SCALED`, meaning `base + imm * VL`; offset zero
has no displacement flags. The focused `cdisasm_arm_sme_za_load_store_tests`
suite exhausts all 4,096 allocated words, all fixed-bit perturbations, every
named profile, endian and generic dispatch, truncation, canonical formatting,
forged flag/schema rejection, and extras-OFF ownership. Five reviewed seeds
and the fuzz invariant independently re-derive the encoded operands and family
metadata from the raw word.
Pinned AARCHMRS supplies the exact leaf allocation, field layout, and SME
feature gate; LLVM 21 legal/illegal operand and feature probes and an
exhaustive Capstone comparison provide independent executable oracles.

Forms 4383--4384 are the exact SME2 ZT0 load/store leaves. Mask/value
`0xfffffc1f/0xe11f8000` selects `LDR ZT0, [Xn|SP]`; value `0xe13f8000` under
the same mask selects `STR ZT0, [Xn|SP]`. Each leaf varies only `Rn`, so it
allocates 32 words and maps register 31 to SP. The containing class has
mask/value `0xffc0fc1c/0xe1008000` and varies the six-bit operation, `Rn`,
and a two-bit ZT selector. Only operation 31 or 63 with selector zero is legal:
the exhaustive parent sweep therefore contains 64 allocated words and 8,128
reserved words.

The first operand is the exact untyped ZT0 tile; the second is a 64-byte
memory operand with no displacement. LDR writes ZT0 and reads memory, while
STR reads ZT0 and writes memory. Successful results carry SME and matrix flags
and require A64, ARMv8, and SME2. `CDISASM_ARM_CPU_ANY`, Apple A18, and Apple
M4 admit the generated requirement; every other current named profile rejects
it. Allocated extras-OFF words remain owned and return
`UNSUPPORTED_INSTRUCTION`, whereas all 8,128 residual parent words remain
`INVALID_INSTRUCTION` before profile admission.

The focused `cdisasm_arm_sme2_zt0_load_store_tests` suite enumerates the full
8,192-word class and all 54 one-bit perturbations of fixed leaf bits. It locks
exact form/name/flag/operand/access metadata, X-register/SP formatting,
little-/big-endian and generic-dispatch parity, named profiles, truncation,
and extras-OFF ownership. Four reviewed fuzz seeds cover allocated LDR and
STR, nonzero-ZT-selector reservation, and reserved-operation ownership; the
dedicated invariant checks the same lattice. Pinned AARCHMRS masks and LLVM 21
legal, feature-rejected, and operand-rejected cases provide the independent
oracle.

Form 4387 is the exact baseline A64 permanently-undefined instruction. Its
mask/value pair is `0xffff0000/0x00000000`; bits 15:0 provide one unsigned
two-byte immediate operand, so all 65,536 words are allocated. Every
A64-capable named profile admits the Armv8 requirement. With extra opcodes
enabled, decoding succeeds with name `UDF`, form 4387, one read immediate,
and exactly `CDISASM_GROUP_INTERRUPT`. `instruction_flags` and
`branch_target` remain zero. This is deliberate: the encoding is allocated
and its execution raises the Undefined Instruction exception, while the
pinned operation is otherwise unspecified. Setting `ILLEGAL`,
`UNPREDICTABLE`, a privilege flag, or invented state effects would conflate
execution behavior with encoding validity.

The focused `cdisasm_arm_a64_udf_tests` suite enumerates all 65,536
immediates, perturbs every fixed bit, and verifies exact metadata, every
A64-capable profile, little-/big-endian and generic-dispatch parity,
truncation, canonical hexadecimal formatting, and extras-OFF ownership. Four
reviewed seeds and a dedicated fuzz invariant cover zero, middle, maximum,
and fixed-neighbor values. Pinned AARCHMRS provides the mask, form, baseline
requirement, interrupt group, and deliberately unspecified operation; LLVM
21 and Capstone independently agree on the legal encodings and immediate
syntax.

Forms 4457--4458 are the exact A64 FEAT_WFxT timeout waits. Under mask
`0xffffffe0`, values `0xd5031000` and `0xd5031020` select `WFET Xt` and
`WFIT Xt`; all 32 values of `Rt` are allocated for each leaf. The sole
operand is a read 64-bit X register, with encoded 31 rendered as XZR rather
than SP. Results carry no instruction flags or groups and format canonically
with the mnemonic and one register. The generated WFxT requirement has an
independent internal capability; `CDISASM_ARM_CPU_ANY` admits it and every
current named profile rejects it rather than inferring support by profile age.
The focused suite exhausts all 64 allocated words, fixed-bit neighbors,
profiles, endian and generic transport, formatter buffer contracts,
truncation, and extras-OFF ownership. Five reviewed seeds and dedicated fuzz
invariants preserve both names, ordinary and register-31 operands, and a
fixed-bit neighbor; LLVM 21 and Capstone supply independent comparisons.

Forms 4499--4501 and 5696--5698 complete the pinned A64
FEAT_FlagM/FlagM2 slice. Exact words `0xd500401f`, `0xd500403f`, and
`0xd500405f` select zero-operand `CFINV`, `XAFLAG`, and `AXFLAG`. RMIF uses
mask/value `0xffe07c10/0xba000400` and exposes a read Xn/XZR, imm6 shift, and
imm4 mask. SETF8 and SETF16 use mask `0xfffffc1f` with values `0x3a00080d`
and `0x3a00480d`, each exposing one read Wn/WZR. All six results carry
`CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS`. FEAT_FlagM gates CFINV, RMIF, and
both SETF forms; FEAT_FlagM2 separately gates XAFLAG and AXFLAG. No current
named profile advertises either feature, so `CPU_ANY` is the positive route.
Allocated extras-off words are unsupported, whereas RMIF `o2=1`, unallocated
SETF low controls, and other malformed neighbors stay invalid in both option
variants. The focused suite covers 32,835 allocated and 34,752 reserved
encodings, profiles, endian/generic transport, truncation, formatting, and
extras-off ownership. Ten reviewed seeds and a raw-word fuzz invariant retain
all six forms and their reserved/generic-MSR neighbors; LLVM 21 independently
agrees on encodings and spelling.

Five exact A64 FEAT_SVE forms expose first-fault-register access and control.
Predicated `RDFFR Pd.B, Pg/Z` form 2562 uses mask/value
`0xfffffe10/0x2518f000`; `RDFFRS Pd.B, Pg/Z` form 2563 uses the same mask
with value `0x2558f000`. Unpredicated `RDFFR Pd.B` form 2564 uses
`0xfffffff0/0x2519f000`, `WRFFR Pn.B` form 2617 uses
`0xfffffe1f/0x25289000`, and zero-operand `SETFFR` form 2618 is the exact word
`0x252c9000`. None has an alias; canonical formatting retains `RDFFR`,
`RDFFRS`, `WRFFR`, or `SETFFR` as appropriate.

All visible predicates range over P0--P15 and record byte element granularity.
An RDFFR destination carries `CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED` and
WRITE access. The governing predicate of forms 2562--2563 carries
`CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO` and READ access; the WRFFR source
instead carries `PREDICATE_TYPED` and READ access because it is predicate data,
not a governing control. Every successful result carries
`CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR` and
`CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK`. Only forms 2562--2563 carry
`CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED`, and only `RDFFRS` carries
`CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS`; unpredicated RDFFR, WRFFR, and
SETFFR must not acquire a predication flag merely because their data operands
are predicate registers. The family has no generic opcode group.

The four containing control envelopes are completely classified. The shared
predicated parent `0xff3ffe10/0x2518f000` has 512 allocated words for its two
operation controls and 512 reserved words. The unpredicated RDFFR parent
`0xff3ffff0/0x2519f000` has 16 allocated and 48 reserved words; the WRFFR
parent `0xff3ffe1f/0x25289000` has the same 16/48 split; and the SETFFR parent
`0xff3fffff/0x252c9000` has one allocated and three reserved words. The exact
bounded union is therefore 545 allocated and 611 reserved encodings.
Allocated words require FEAT_SVE and are admitted by
`CDISASM_ARM_CPU_ANY` and Fujitsu A64FX; every other current named A64 profile
rejects them. Allocated extras-OFF words remain owned as
`UNSUPPORTED_INSTRUCTION`, while all 611 residual controls remain
`INVALID_INSTRUCTION` in both option variants. The focused suite exhausts the
entire union and checks access, form identity, flags, profiles, canonical
formatting, endian/generic transport, truncation, and extras/formatter-off
behavior. Ten readable seeds and a raw-word fuzz invariant retain every form
and one reserved control from each parent. Pinned AARCHMRS supplies the exact
allocation, and LLVM 21 confirms canonical spellings under `+sve` while
rejecting the reserved neighbors.

Forms 2374--2391 are the exact non-saturating A64 SVE element-count family.
Forms 2374--2379 update typed `Zn.H/S/D` destinations with `INCH`/`DECH`,
`INCW`/`DECW`, or `INCD`/`DECD`. Forms 2380--2383 write Xd/XZR with
`CNTB`/`CNTH`/`CNTW`/`CNTD`, and forms 2384--2391 read/write Xd/XZR with
the scalar `INCB`/`DECB` through `INCD`/`DECD` variants. Every result exposes
the encoded five-bit predicate-pattern selector and the one-through-sixteen
multiplier as immediate operands; canonical formatting uses the symbolic
pattern names and omits default `all` and `mul #1` operands.

All 18 leaves use mask `0xfff0fc00`. Exhausting the three bounded parent
envelopes covers every destination, pattern, multiplier, size, and operation
control: 294,912 words are allocated and 98,304 residual controls are
reserved. Successful results carry scalable-vector metadata and require SVE
or SME. `CPU_ANY`, Fujitsu A64FX, Apple A18, and Apple M4 admit an available
feature route; other current named profiles reject the family conservatively.
Allocated extras-OFF words remain unsupported, while residual controls remain
invalid. The focused suite also locks exact form/access metadata, XZR handling,
little-/big-endian and generic-dispatch parity, every truncation boundary,
canonical formatting and forged-result rejection. Twenty reviewed fuzz seeds
and 25 data-corpus rows retain allocated, reserved, profile, formatting, and
transport boundaries. Pinned AARCHMRS provides the allocation and feature
requirements, and LLVM 21 supplies the independent assembler/disassembler
oracle.

`FIRSTP` form 2598 and `LASTP` form 2599 complete the classic predicate-count
parent alongside `CNTP` form 2597. Under mask `0xff3fc200`, values
`0x25218000` and `0x25228000` select `FIRSTP` and `LASTP`. Each form allocates
all B/H/S/D element widths, sixteen governing predicates, sixteen typed source
predicates, and 32 destination fields: 32,768 words per operation and 65,536
in total. The result writes `Xd`/XZR, reads untyped `Pg`, and reads typed
`Pn.B/H/S/D`. It carries exactly `SCALABLE_VECTOR | PREDICATED` and has no
generic opcode group.

Both forms require SVE2.2 or SME2.2. `CPU_ANY` admits them; every current named
profile rejects them because none advertises either capability. Allocated
extras-OFF words remain structurally owned as unsupported, while the five
unused operation selectors in the containing parent remain invalid. The
dedicated suite exhausts 65,536 `FIRSTP`/`LASTP` words, the 32,768 `CNTP`
siblings, and 163,840 reserved controls, and checks operand metadata, feature
gates, endian/generic transport, canonical formatting, truncation, and forged
result rejection. Six reviewed seeds and 12 data-corpus rows preserve those
boundaries against pinned AARCHMRS and LLVM 21.

`CTERMEQ` form 2593 and `CTERMNE` form 2594 use mask `0xffa0fc1f` with
values `0x25a02000` and `0x25a02010`. The eleven variable bits encode `sz`,
`Rm`, and `Rn`, allocating 2,048 words per form and 4,096 for the pair. `sz`
selects W or X operands; both are read-only and register 31 maps to WZR/XZR.
Successful results set no generic opcode group and carry exactly
`SCALABLE_VECTOR | SETS_FLAGS`.

Both forms require SVE or SME. A64FX exercises the SVE path, Apple A18/M4
exercise SME, and a baseline Cortex-A53 profile rejects them. The containing
parent's 4,096 `op=0` words are structurally invalid. The exhaustive suite
covers allocated and reserved words, endian/generic transport, truncation,
extras-OFF ownership, canonical text, and raw/form/name/flag/operand forgery.
Sixteen corpus rows and six reviewed seeds retain these boundaries; LLVM 21
accepts the W/X and zero-register forms with `+sve` or `+sme` and rejects
them without either feature. ASan+UBSan campaigns complete 6,000 ARM runs in
each extras configuration without a finding.

The exact baseline-SVE predicate-break family is forms 2546--2555:
`BRKPA`, `BRKPAS`, `BRKPB`, `BRKPBS`, `BRKA`, `BRKAS`, `BRKB`, `BRKBS`,
`BRKN`, and `BRKNS`. The four BRKP leaves use mask `0xfff0c210` at values
`0x2500c000`, `0x2540c000`, `0x2500c010`, and `0x2540c010`; their free
`Pm`, `Pg`, `Pn`, and `Pd` fields allocate 65,536 words per form. BRKA and
BRKB use mask `0xffffc200` at `0x25104000` and `0x25904000`, allocating
8,192 words each because both zeroing and merging controls are valid. BRKAS,
BRKBS, BRKN, and BRKNS each allocate 4,096 words under mask `0xffffc210` at
values `0x25504000`, `0x25d04000`, `0x25184000`, and `0x25584000`.

All predicate operands have byte granularity. BRKP writes typed `Pd.B` and
reads zeroing `Pg`, typed `Pn.B`, and typed `Pm.B`. BRKA/BRKB expose three
operands: zeroing forms write `Pd`, while merging forms mark it read/write;
both read their governing `Pg` and typed `Pn.B`. BRKN/BRKNS write `Pd`, read
zeroing `Pg` and typed `Pn.B`, and represent the architecturally tied old
`Pd.B` value as an explicit fourth read operand. Every form carries exactly
`SCALABLE_VECTOR | PREDICATED` with no generic opcode group; BRKPAS, BRKPBS,
BRKAS, BRKBS, and BRKNS additionally carry `SETS_FLAGS` for their NZCV write.

Either SVE or SME admits all 294,912 allocated words: A64FX exercises SVE,
Apple A18/M4 exercise SME, and a baseline Cortex-A53 rejects the family.
The exact parent ownership also marks 270,336 words invalid: 262,144 in the
unallocated BRKP `op=1` half and 8,192 flag-setting merge controls. Allocated
extras-OFF words remain unsupported. The exhaustive suite covers every
allocated/reserved word plus profile, endian/generic transport, formatting,
forged metadata, truncation, adjacency, and disabled-build behavior; 23
corpus rows and 14 reviewed seeds retain the same boundaries.

The adjacent baseline-SVE predicate-control family is canonical forms
2556--2561. Its exact mask/value pairs are `0xffffc21f/0x2550c000` for
`PTEST`, `0xfffffe10/0x2558c000` for `PFIRST`,
`0xff3ffe10/0x2519c400` for `PNEXT`, `0xff3ffc10/0x2518e000` for ordinary
`PTRUE`, `0xff3ffc10/0x2519e000` for `PTRUES`, and
`0xfffffff0/0x2518e400` for `PFALSE`. They allocate respectively 256, 256,
1,024, 2,048, 2,048, and 16 words: 5,648 total. Exact parent ownership marks
16,128 PTEST, 768 PFIRST, and 48 PFALSE residuals invalid, for 16,944 reserved
words; PNEXT and both PTRUE leaves fill their subparents.

PTEST reads untyped `Pg` and typed `Pn.B`. PFIRST writes typed `Pdn.B`, reads
untyped `Pg`, and represents the tied old `Pdn.B` as a final read operand.
PNEXT writes and rereads typed `Pdn.B/H/S/D` around an untyped `Pv` carrying
the selected size. PTRUE/PTRUES write typed `Pd.B/H/S/D` and expose the raw
five-bit pattern as a read immediate; PFALSE writes typed `Pd.B`. Only PTEST
and PTRUES carry `SETS_FLAGS`, and only PTEST and PFIRST carry `PREDICATED`;
all six carry `SCALABLE_VECTOR`, have no generic opcode group, and require SVE
or SME. Canonical text names allocated patterns, emits unnamed values as
numeric immediates, and omits default `all`. Thirty-three corpus rows and 15
reviewed seeds cover the complete allocation/residual ownership, profiles,
both byte orders, formatting, truncation, and extras-OFF behavior. This is a
bounded family completion, not exhaustive SVE, SME, or ARM opcode coverage.

The adjacent `PSEL` form 2565 uses exact mask/value
`0xff20c210/0x25204000`. Its three operands format as
`Pd, Pn, Pm.T[Wv, lane]`: `Pd` is written, `Pn` is read, and the indexed typed
`Pm.B/H/S/D` is read with W12--W15 and its size-dependent lane. The first two
predicate operands retain the selected element granularity in metadata while
canonical text omits their suffixes. The instruction carries exactly
`SCALABLE_VECTOR`, with no predication flag or generic opcode group.

Its architectural leaf exposes 32 `i1:tsz` controls. Thirty are typed and
allocate 491,520 words; the two `tsz=0000` controls have no assembly type and
make 32,768 words structurally invalid. Every one of the 524,288 bit-4
neighbors remains delegated, including the counter-predicate block beginning
with form 2566. Admission is the exact alternative FEAT_SVE2p1 or baseline
FEAT_SME: `CPU_ANY` and Apple A18/M4 admit the form, while A64FX and Cortex-A53
reject it. The focused suite and 18 corpus rows cover the complete leaf and
neighbor, feature/profile admission, endian/generic transport, formatting and
forgery rejection, truncation, and extras-OFF ownership; 15 reviewed seeds
retain the boundaries. LLVM 21 agrees on all 30 legal type/lane controls and
rejects both untyped controls.

Counter-predicate `WHILEGE`/`WHILEHS`/`WHILEGT`/`WHILEHI`/
`WHILELT`/`WHILELO`/`WHILELE`/`WHILELS` are exact forms 2566--2573. Their
eight leaves share mask `0xff20dc18`; each allocates all four B/H/S/D element
sizes, `PN8`--`PN15` destinations, both `VLx2`/`VLx4` controls, and all Xn/Xm
values, including XZR. The 65,536 words per form give 524,288 allocations in
total. Results write the typed counter predicate, read both X operands, expose
the VL multiplier as a read immediate, and carry exactly
`SCALABLE_VECTOR | PREDICATED | SETS_FLAGS` with no generic opcode group.

SVE2.1 or SME2 admits the family. The focused exhaustive suite checks every
allocation, feature/profile admission, endian/generic transport, canonical
formatting, truncation, and extras-OFF structural ownership. Twenty-two data-
corpus rows and eight reviewed seeds preserve all relations, sizes, PN and
zero-register boundaries, both VL values, flags, and malformed neighbors.

`PEXT` forms 2582--2583 and counter-predicate `PTRUE` form 2584 occupy the
adjacent SVE2.1-or-SME2 predicate-control block. Under masks
`0xff3ffc10`, `0xff3ffe10`, and `0xff3ffff8`, their values are respectively
`0x25207010`, `0x25207410`, and `0x25207810`. Single-result `PEXT` allocates
2,048 words and writes typed `Pd.B/H/S/D`; pair-result `PEXT` allocates 1,024
and writes a typed consecutive predicate pair, with destination 15 wrapping
to `{p15, p0}`. Both read an untyped indexed counter predicate rendered
`PNn[index]`; the single form permits indices zero through three and the pair
form zero through one. `PTRUE` allocates 32 words and writes typed
`PN8`--`PN15`. All three forms carry exactly `SCALABLE_VECTOR`.

The focused suite exhausts all 3,104 allocations and 1,024 reserved parent
controls and checks the feature
alternative, typed-versus-untyped predicate metadata, access, wrap behavior,
endian/generic transport, canonical formatting, truncation, and extras-OFF
ownership. Twenty-four corpus rows and eight reviewed seeds retain the same
boundaries.

`WHILEWR` form 2595 and `WHILERW` form 2596 are the exact non-counting loop
predicate pair. Both use mask `0xff20fc10`, with values `0x25203000` and
`0x25203010`. The sixteen variable bits encode all four B/H/S/D sizes, 32
values each for `Rm` and `Rn`, and sixteen `Pd` values, so each leaf allocates
65,536 words and the pair allocates 131,072 without a reserved residual.
Successful results write typed `Pd.B/H/S/D`, read `Xn` and `Xm`, map register
31 to XZR, set no generic opcode group, and carry exactly
`SCALABLE_VECTOR | PREDICATED | SETS_FLAGS`.

The feature condition is SVE2 or SME: unrestricted `CPU_ANY` supplies the
SVE2 route, Apple A18/M4 supply the SME route, and plain-SVE A64FX is rejected.
The focused exhaustive suite covers both leaves, endian/generic transport,
every truncation boundary, disabled-extra ownership, canonical text, and
raw/form/name forgery rejection. Fourteen data-corpus rows and six reviewed
fuzz seeds retain the family boundaries. LLVM 21 independently confirms all
size extremes and accepts `+sve2`/`+sme` while rejecting plain `+sve`; fresh
ASan+UBSan campaigns completed 6,000 ARM runs with extras both on and off.

Version 11.24 separately owns the exact merging SVE/SME `BFCVT Zd.H, Pg/m,
Zn.S` classifier `(word & 0xffffe000) == 0x658aa000`. All 8,192 combinations
of `Pg`, `Zn`, and `Zd` are allocated. Results read and write `Zd.h`, read the
merging predicate at source granularity four, and read `Zn.s`; they carry
scalable-vector, predicated, and floating-point metadata. Valid forms require
A64, ARMv8, BF16, and either SVE or SME. `CPU_ANY`, Apple A18, and Apple M4
admit the form; A64FX lacks BF16, M3 lacks SVE/SME, and A19/M5 remain
deliberately conservative. The focused four-selector envelope contains 16,384
baseline `FCVT` words, 8,192 merging `BFCVT` words, and 8,192 reserved words;
this is additive to the existing 65,536-word `FCVT` sweep. The exact merging
form is implemented only when `USE_EXTRA_OPCODES=1`.

Version 11.25 adds merging `BFCVTNT Zd.H, Pg/m, Zn.S` at masked value
`0x648aa000`, zeroing `BFCVT Zd.H, Pg/z, Zn.S` at `0x649ac000`, and zeroing
`BFCVTNT Zd.H, Pg/z, Zn.S` at `0x6482a000`, all under mask `0xffffe000`.
Each class allocates all 8,192 `Pg`/`Zn`/`Zd` combinations. Merging BFCVTNT,
like merging BFCVT, requires A64, ARMv8, BF16, and SVE or SME; `CPU_ANY`, Apple
A18, and Apple M4 admit it. The zeroing pair instead requires SVE2.2 or SME2.2
without an independent BF16 gate. No current named physical profile advertises
either capability, so only `CPU_ANY` admits those forms. Zeroing BFCVT writes
`Zd.h`; both BFCVTNT forms read and write `Zd.h` because they preserve its even
halfwords. All read `Pg` at single-precision source granularity and read `Zn.s`.
The adjacent merging and zeroing `opc=1011` rows are owned as 16,384 exact
invalid controls. The focused BFCVT/BFCVTNT test covers 73,728 words in total:
32,768 existing controls plus 24,576 newly allocated and 16,384 newly reserved
controls. All new classes are implemented only when `USE_EXTRA_OPCODES=1`.
Version 11.25 did not implement the separately encoded unpredicated pair forms.
The architecture's rule making the predicated forms unpredictable immediately
after selected MOVPRFX instructions is also not diagnosed because the public
decoder accepts one instruction without prior stream context.

Version 11.26 adds four exact unpredicated two-vector BFloat16/FP8 forms. Under
mask `0xfffffc20`, SME2 `BFCVT zD.h, {zN.s, zN+1.s}` and `BFCVTN zD.h,
{zN.s, zN+1.s}` are `0xc160e000` and `0xc160e020`; SME2+FP8 `BFCVT zD.b,
{zN.h, zN+1.h}` is `0xc164e000`. SVE2-or-SME2 plus FP8 admits `BFCVTN zD.b,
{zN.h, zN+1.h}` at `0x650a3800` under the same mask. Each exact form allocates
512 destination/source-pair combinations; the four-bit source field selects an
even consecutive Z-register pair. Apple A18 and M4 admit the two non-FP8 SME2
forms. The independent FP8 capability is currently exposed only by `CPU_ANY`,
so every named profile rejects both H-to-FP8 forms. There is no unpredicated
pair `BFCVTNT` allocation. The focused suite enumerates 18,432 words: all
16,384 words in the SME2 selector domain and all 2,048 words in the SVE2/SME2
FP8 narrowing domain. The exact split is 2,048 implemented form words, 8,704
allocated-but-unsupported siblings, and 7,680 reserved SME2 words. The SME2
domain contributes 1,536 implemented, 7,168 unsupported, and 7,680 reserved
words; the SVE2/SME2 domain contributes 512 implemented and 1,536 unsupported
words. The suite also checks endian, generic
dispatch, formatter, CPU, and extras-OFF behavior. These pair forms are
implemented only when `USE_EXTRA_OPCODES=1`.

Version 11.6 also owns the fixed-width A64 Advanced SIMD permutation class
`(word & 0xbf208c00) == 0x0e000800`. Sparse operation selectors one, two,
three, five, six, and seven select `UZP1`, `TRN1`, `ZIP1`, `UZP2`, `TRN2`,
and `ZIP2`. The seven allocated arrangements are `8B`, `16B`, `4H`, `8H`,
`2S`, `4S`, and `2D`, producing 42 legal forms with three typed V-register
operands. Selectors zero/four and Q=0,size=3 are invalid, giving 22 focused
reserved controls. Valid forms require A64, ARMv8, and NEON; they remain
structurally owned when extra opcodes are disabled.

The exact fixed-width A64 Advanced SIMD bit-count envelope uses mask
`0xbf3ffc00`: values `0x0e204800`, `0x0e205800`, and `0x2e204800` select
`CLS`, `CNT`, and `CLZ` forms 6007, 6008, and 6041. Q selects an 8- or
16-byte vector. CLS and CLZ accept size codes zero through two, producing
8B/16B, 4H/8H, and 2S/4S; size three is reserved. CNT accepts only size zero,
producing 8B/16B, and reserves H, S, and size-three arrangements. Every valid
result writes a typed `Vd`, reads a typed `Vn`, records the exact element,
lane-count, and total-vector widths, carries the SIMD flag, and requires A64,
ARMv8, and NEON.

Across both Q values and all register pairs, CLS and CLZ each contribute 6,144
allocated and 2,048 reserved words; CNT contributes 2,048 allocated and 6,144
reserved words. The combined exhaustive sweep therefore classifies 14,336
allocated and 10,240 reserved words out of 24,576. The focused
`cdisasm_arm_advsimd_bitcount_tests` suite locks exact metadata, named-profile
gates, fixed neighbors, truncation, endian and generic-dispatch parity,
canonical arrangement text, and extras-OFF structural ownership. Six reviewed
fuzz seeds provide an allocated/reserved pair for each operation, cross-checked
against pinned AARCHMRS definitions and LLVM 21 output.

The fixed-width SHA suite implements all 30 pinned A32, T32, and A64
SHA1/SHA256 leaves with exact feature admission, scalar/vector operand access,
endianness, formatting, and reserved-neighbor behavior. Its focused classifier
checks 291,328 allocated and 883,200 reserved encodings.

The adjacent A64 fixed-crypto suite owns forms 6287--6303: `SM3TT1A/B`,
`SM3TT2A/B`, `SHA512H/H2/SU0/SU1`, `RAX1`, `SM3PARTW1/W2`, `SM4EKEY`,
`EOR3`, `BCAX`, `SM3SS1`, `XAR`, and `SM4E`. It exhausts all 5,998,592
allocated encodings and validates exact SHA3/SHA512/SM3/SM4 gates, lane and
immediate fields, typed V-register operands, write-only `SM4EKEY`, canonical
text, endian/profile behavior, and fail-closed separation from same-name SVE
forms.

The Apple A64 descriptor table adds all 32 mnemonics enabled by the pinned
Capstone Apple-proprietary mode:

| Family | Numeric mnemonic IDs decoded |
| --- | --- |
| MUL53 | `MUL53LO`, `MUL53HI` |
| AMX load/store/extract | `LDX`, `LDY`, `STX`, `STY`, `LDZ`, `STZ`, `LDZI`, `STZI`, `EXTRX`, `EXTRY` |
| AMX arithmetic/control | `FMA16/32/64`, `FMS16/32/64`, `MAC16`, `SET`, `CLR`, `VECINT`, `VECFP`, `MATINT`, `MATFP`, `GENLUT` |
| AppleSys | `WKDMC`, `WKDMD`, `GEXIT`, `GENTER`, `AT_AS1ELX`, `SDSB` |

It also recognizes both standard `MRS`/`MSR` opcode forms when their system
register field is the Apple A7/Cyclone-specific `CPM_IOACC_CTL_EL3`. That
system register is represented by its own stable register ID, so no spelling is
stored in the decoder. Both forms carry `CDISASM_GROUP_PRIVILEGED`.

Apple operands follow the pinned Capstone detail contract. AMX has one explicit
read-only `Xn` command operand (or none for `SET`/`CLR`); address, row, mask, and
operation fields remain packed in that runtime register and are not fabricated
as a memory operand. MUL53 returns a read/write destination and read-only source
with 16-byte, 2-by-8-byte lane metadata. `WKDMC`/`WKDMD` return a read-only
high-field register followed by the tied read/write low-field register.
`GENTER` sign-extends its imm5 exactly as Capstone does. `SDSB` exposes the raw
imm4; constants `CDISASM_ARM_APPLE_SDSB_OSH`, `_NSH`, `_ISH`, and `_SY` name
values 0--3. Capstone structurally decodes values 4--15 as undefined, while the
hardware notes say they fault, so cdisasm preserves the immediate and adds
`CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL`.

The T32 subset covers NOP, BKPT/SVC, BX/BLX, conditional/unconditional branches,
CBZ/CBNZ, 32-bit BL, immediate and selected register data processing,
high-register operations, literal/immediate loads and stores, ADR/SP address
generation, PUSH/POP, and LDM/STM.

The A32/T32 Advanced SIMD subset covers packed integer `VADD`, `VSUB`, and
`VMUL`, packed floating-point `VADD`, `VSUB`, and `VMUL`, and `VAND`, `VBIC`,
`VORR`, and `VEOR`. The A64 subset covers packed `ADD`, `SUB`, `MUL`, `AND`,
`ORR`/`MOV`, `EOR`, `FADD`, `FSUB`, `FMUL`, and `FDIV`. The decoder records
total vector width and element size/count and applies a NEON capability gate.

With `USE_EXTRA_OPCODES=1`, A64 also decodes FEAT_LSE `CAS`/`CASP` and every
byte/halfword/word/doubleword acquire/release form of `LDADD`, `LDCLR`,
`LDEOR`, `LDSET`, and `SWP`; FEAT_LOR `LDLAR`/`STLLR`; and FEAT_LRCPC `LDAPR`.
`CDISASM_ARM_CPU_ANY` accepts all three families. Named Apple profiles follow
independent feature gates: A10/A10X has LOR, A11 adds LSE, and A12--A19,
M1--M5, and S4--S10 add RCpc. Other named profiles reject these optional
families. `CASP` represents each consecutive architectural register pair with
`CDISASM_ARM_OPERAND_REGISTER_PAIR`: `reg` is the even first register and
`index_reg` is the architectural second register (including WZR/XZR after
W30/X30), keeping the fixed result layout and four-operand limit unchanged.
For LSE read/modify/write and `SWP`, an encoded acquire bit has no acquire
semantic when the result is discarded in WZR/XZR; the name ID still reflects
the encoding while `CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE` is cleared.

The modern optional tables also implement representative wider A32/T32
core/VFP/NEON, A64 FP/NEON, SVE/SVE2, SME/SME2, LSE128/RCpc3, BTI, PAuth, MTE,
MOPS, LS64, and CSSC forms, plus the complete bounded SVE predicate-logical,
exact SVE `PUNPKLO`/`PUNPKHI` predicate-unpack forms 2468--2469 and exact
SVE/SME `SUNPKLO`/`SUNPKHI`/`UUNPKLO`/`UUNPKHI` vector-unpack forms
2456--2459 and SVE2/SME `SRI`/`SLI` shift-insert forms 2846--2847,
unpredicated and destructive-predicated integer-arithmetic, three exact
predicated-unary classifiers, exact predicated vector-, immediate-, and
SVE2/SME merging variable shift/saturating-round classifiers, integer vector-
and immediate-compare classes, floating
compare-with-zero and vector-compare classes, destructive predicated FP-binary
arithmetic, FP fast reductions, `FADDA`, merging/zeroing predicated FP-unary,
  the exact merging H/S/D-to-H and S-to-S/D and D-to-S/D `SCVTF`/`UCVTF`
  conversion classes, the complete baseline merging H/S/D `FCVT`/`FCVTZS`/
  `FCVTZU` class, exact merging `BFCVT`/`BFCVTNT Zd.H, Pg/m, Zn.S`, exact
  SVE2.2/SME2.2 zeroing `BFCVT`/`BFCVTNT Zd.H, Pg/z, Zn.S`, indexed
  `DUP`/preferred `MOV`, the four-form FP8 narrowing row, and the exact
  unpredicated SME2 two-vector conversion, unpack, and FP8-widening block
  4312--4340, including pair `FRINTN`/`FRINTP`/`FRINTM`/`FRINTA` and
  SME_F16F16 `FCVT`/`FCVTL`, the complete SME2 four-vector block 4341--4362,
  plus the separate SVE2.1-or-SME2
  `SQCVTN`/`SQCVTUN`/`UQCVTN` multi-extract row 2881--2883,
the unpredicated SVE/SME and fixed-width Advanced SIMD `FRECPE`/`FRSQRTE`
estimate classes, scalable and
fixed-width Advanced SIMD ZIP/UZP/TRN, and selected table-lookup/MOV-from-GPR
classes described above. Exact no-operand T32 `DCPS1`/`DCPS2`/`DCPS3` forms
1853--1855 are included independently from the A64 DCPS lowering. Coverage remains
representative outside those scoped
completions: broader A32/T32 maps, wider Advanced SIMD/FP outside the exact
fixed-width estimate union, most other
SVE/SVE2/SME maps (including other predicated arithmetic and shifts outside
the exact classifiers above, other multi-vector conversion encodings,
MOVPRFX-dependent stream diagnostics, and other conversion variants, reductions outside the completed
fast/serial scopes, gather/scatter, and streaming/matrix classes), LSE signed/unsigned
min/max and store aliases, remaining
RCpc/LSE2/LSE128 forms, most system instructions, and other unlisted encodings
are not implemented.
They fail explicitly rather
than being guessed. Successful implemented forms can be passed to
`cdisasm_arm_format`; applications that do not need text can consume the
numeric result from a build configured with `USE_DISASM_FORMAT=OFF`.

## Canonical instruction formatting

When `USE_DISASM_FORMAT=1`, `cdisasm` owns both architecture text
implementations. CMake consumers may link `cdisasm::cdisasm` directly or use
the `cdisasm::cdisasm_format` interface compatibility proxy.
`<cdisasm/cdisasm_format.h>` declares the APIs under the formatter and
architecture configuration guards: `cdisasm_x86_format` and the compatibility
`cdisasm_format` wrapper under `#if USE_DISASM_FORMAT && USE_ARCH_X86`, and
`cdisasm_arm_format` under `#if USE_DISASM_FORMAT && USE_ARCH_ARM`. Do not pass
one architecture's result structure to the other architecture's function.

```c
#include <cdisasm/cdisasm_common.h>

#if USE_DISASM_FORMAT
#  include <cdisasm/cdisasm_format.h>
#endif

#if USE_DISASM_FORMAT && USE_ARCH_X86
CDISASM_FORMAT_API size_t CDISASM_CALL cdisasm_x86_format(
    const cdisasm_x86_instruction *instruction,
    uint32_t flags,
    char *buffer,
    size_t buffer_size);

CDISASM_FORMAT_API size_t CDISASM_CALL cdisasm_x86_format_mode(
    const cdisasm_x86_instruction *instruction,
    cdisasm_mode mode,
    uint32_t flags,
    char *buffer,
    size_t buffer_size);

CDISASM_FORMAT_API size_t CDISASM_CALL cdisasm_format(
    const cdisasm_instruction *instruction,
    uint32_t flags,
    char *buffer,
    size_t buffer_size);
#endif
#if USE_DISASM_FORMAT && USE_ARCH_ARM
CDISASM_FORMAT_API size_t CDISASM_CALL cdisasm_arm_format(
    const cdisasm_arm_instruction *instruction,
    uint32_t flags,
    char *buffer,
    size_t buffer_size);
#endif
```

The `flags` argument has this version-9 layout:

| Bits/value | Public define | Effect |
| ---: | --- | --- |
| `0x00` | `CDISASM_FORMAT_SYNTAX_0`, `CDISASM_FORMAT_SYNTAX_INTEL` | Select Intel syntax for x86 and canonical syntax for ARM. Syntax 0 preserves the output used before version 9. |
| `0x01` | `CDISASM_FORMAT_SYNTAX_1`, `CDISASM_FORMAT_SYNTAX_ATT` | Select AT&T syntax for x86. ARM continues to emit canonical syntax. |
| `0x02`--`0x07` | `CDISASM_FORMAT_SYNTAX_2` through `CDISASM_FORMAT_SYNTAX_7` | Permanent compatibility aliases for Intel syntax on x86 and canonical syntax on ARM; their meanings will not be reassigned. |
| `0x08` | `CDISASM_FORMAT_UPPERCASE_OPCODE` | Uppercase only mnemonic/opcode text. This includes emitted x86 prefix tokens and attached ARM flag, condition, address-mode, NEON, and Apple vector suffixes, but not operands, registers, modifiers, or option words. |
| `0x10` and above | reserved | Unknown flags are rejected. The function returns zero and clears a writable nonempty output buffer. |

Use `CDISASM_FORMAT_SYNTAX_MASK` to isolate the low three syntax bits and
`CDISASM_FORMAT_KNOWN_FLAGS_MASK` to validate an entire flags value. Options
are combined with bitwise OR. Uppercase examples include
`XRELEASE LOCK ADD dword ptr [rax], ebx`, `MOVQ %rsp, %rbp`, `B.EQ 0x8`,
`VADD.I8 d16, d17, d16`, and `MUL53HI.2D v0, v1`; an operand option such as
`sy` remains lowercase. For example:

`cdisasm_x86_format_mode` has the same buffer and flag contract as
`cdisasm_x86_format`, but also takes the mode used for decoding. Intel output
is identical. AT&T output uses the mode to select otherwise unavailable
control-transfer and stack suffixes. An invalid mode is rejected and clears a
nonempty output buffer.

```c
#if USE_DISASM_FORMAT && USE_ARCH_X86
size_t x86_required = cdisasm_x86_format(
    &x86_instruction,
    CDISASM_FORMAT_SYNTAX_INTEL | CDISASM_FORMAT_UPPERCASE_OPCODE,
    NULL,
    0);
#endif
#if USE_DISASM_FORMAT && USE_ARCH_ARM
size_t arm_required = cdisasm_arm_format(
    &arm_instruction,
    CDISASM_FORMAT_SYNTAX_0,
    NULL,
    0);
#endif
```

Every formatter has the same buffer contract. The return value is the complete
number of characters excluding the terminating NUL, regardless of truncation.
A zero buffer size is a size query; the pointer may be NULL and is not accessed.
For a non-NULL buffer with nonzero size, the function writes as much as fits and
always appends a NUL. A NULL buffer with nonzero size is invalid. Invalid
instruction metadata or unknown formatter flags return zero and empty a
writable nonempty buffer.

### x86 Intel and AT&T syntax

`cdisasm_x86_format` formats one successful `cdisasm_instruction` as a
complete Intel- or AT&T-syntax instruction. Both syntaxes use lowercase opcode
text by default; `CDISASM_FORMAT_UPPERCASE_OPCODE` uppercases that text,
including emitted prefix tokens and an AT&T size suffix, without changing
operands.
`cdisasm_format` calls the same implementation with the same flags and exists
only as the x86 compatibility spelling.

The x86 formatter validates that the result represents a successful 1- through
15-byte decode, has a published mnemonic ID and at most five valid operands,
and contains internally consistent register, immediate, memory, effective
prefix, operand access/broadcast, decorator, encoding-field, and sorted x86
ISA-group metadata. It does not read instruction bytes or allocate memory.

#### Intel syntax

`CDISASM_FORMAT_SYNTAX_INTEL` and syntax slots 2 through 7 produce Intel text
with these rules:

- By default, mnemonics and register names use the lowercase spelling of their
  stable x86 IDs. The uppercase-opcode flag affects prefixes and the mnemonic,
  while operands and registers remain lowercase. Operands remain in
  decoder-provided Intel order, separated by `, `.
- `CDISASM_PREFIX_XACQUIRE` or `CDISASM_PREFIX_XRELEASE` prints before the
  ordinary effective prefix. Effective LOCK prints `lock`; cumulative
  encountered-class bits alone do not produce text.
  Effective REP prints `repe` for CMPS/SCAS and `rep` otherwise, except when F3
  is a consumed mandatory prefix. Effective REPNE similarly prints `repne`
  unless it is consumed. Thus both `F3 F0 ADD` and `F0 F3 ADD` format as
  `xrelease lock add` on an HLE profile, while F2 selects `xacquire`;
  `F2 F3 CMPSB` is `repe cmpsb`, while `F3 F2 CMPSB` is `repne cmpsb`.
- Mandatory F3 encodings such as PAUSE, POPCNT, TZCNT/LZCNT, ENDBR, and VMXON
  do not repeat the prefix in their text. VMGEXIT similarly consumes its F2 or
  F3 selector. Their NOP, BSF, BSR, or VMMCALL CPU-profile fallbacks likewise
  suppress it. Legacy SSE-family `66`, F2, and F3 bytes are structural opcode
  selectors and never print as repeat actions. Legacy F2/F3 prefixes on a
  multi-byte NOP are ignored.
- Unsigned immediates use lowercase hexadecimal with a `0x` prefix and no
  unnecessary leading zeroes. Signed negative values use `-0x`; PC-relative
  operands print the resolved target from `imm`. The implicit shift count one
  is the sole decimal immediate.
- Memory terms are written as `[base + index*scale +/- displacement]` with no
  spaces around `*`. Absolute memory uses `address`. An explicit segment is
  written immediately before the bracket, for example
  `qword ptr fs:[0x30]`; an implicit segment is not displayed.
- Memory-access sizes 1, 2, 4, 6, 8, 10, 16, 32, and 64 bytes use `byte`,
  `word`, `dword`, `fword`, `qword`, `tbyte`, `xmmword`, `ymmword`, and
  `zmmword ptr`, respectively. `ADDRESS_ONLY` operands such as LEA omit the
  pointer-size phrase.
- A nonzero memory broadcast is appended as `{1toN}`. A writemask follows the
  first operand as `{kN}`; zeroing appends `{z}`, while merge masking has no
  second text token. SAE and embedded rounding are appended after the ordinary
  operands as `{sae}` or `{rn-sae}`, `{rd-sae}`, `{ru-sae}`, or `{rz-sae}`.

#### AT&T syntax

`CDISASM_FORMAT_SYNTAX_ATT` selects AT&T spelling for x86 only. It formats the
same validated numeric result and follows these deterministic rules:

- Every register has a `%` prefix, including segment, base, index, vector, and
  mask registers. Non-control immediate data has a `$` prefix. Hexadecimal and
  register spelling remain lowercase.
- Explicit multi-operand instructions are emitted in reverse of the decoder's
  Intel display order, producing source-before-destination order. `ENTER`
  retains its architectural allocation-size, nesting-level order, while
  `INVLPGA` retains its fixed implicit address/ASID register order.
  One-operand instructions retain their only operand.
- Memory uses `displacement(base,index,scale)`, omitting absent fields. For
  example, Intel `qword ptr [rbx + rcx*4 - 0x10]` becomes
  `-0x10(%rbx,%rcx,4)`, index-only memory can be
  `0x12345678(,%ecx,4)`, and RIP-relative memory can be `0x10(%rip)`. Absolute
  memory is a bare address. An explicit segment precedes it as `%fs:`, for
  example `%fs:0x30`. AT&T output never emits an Intel `ptr` size phrase.
- Scalar instruction width is expressed with a `b`, `w`, `l`, or `q` mnemonic
  suffix when the structured operands identify it unambiguously. Examples are
  `movq %rsp, %rbp`, `addl %ebx, (%rax)`, and
  `leaq 0x10(%rax,%rcx,4), %rdx`. Standard width aliases include
  `movzbl`, `movsbq`, `movslq`, `cbtw`, `cwtl`, `cltq`, `cwtd`, `cltd`, and
  `cqto`. `CRC32` and `CVTSI2SS`/`CVTSI2SD` use the source width, and 32-bit
  string aliases use `l`. Other SIMD and 3DNow! mnemonics remain unsuffixed.
- A resolved PC-relative call or jump is direct: its target has neither `$`
  nor `*`, as in `call 0x1015`. A register- or memory-indirect `CALL`/`JMP`
  operand begins with `*`, as in `jmpq *%rax` or `callq *0x8(%rax)`. The
  indirect form receives a size suffix when its operand width supplies one.
  The legacy formatter does not retain decode mode, so direct PC-relative
  calls/jumps and immediate `PUSH`/`RET` remain unsuffixed for compatibility.
  `cdisasm_x86_format_mode` emits the exact 16/32/64-bit suffix for direct and
  indirect `CALL`/`JMP`, immediate `PUSH`, `RET`, and `RETF`.
- Broadcast, mask, zeroing, SAE, and rounding decorators retain their meaning.
  After operand reversal, a destination mask remains attached to the logical
  destination, for example `%zmm0{%k1}{z}`. SAE or embedded rounding follows
  the mnemonic and precedes the operands, for example
  `vaddps {rn-sae}, %zmm1, %zmm0`.

`CDISASM_FORMAT_UPPERCASE_OPCODE` composes with AT&T syntax. It uppercases
emitted instruction prefixes, the mnemonic or AT&T alias, and its size suffix,
but never registers, numbers, memory terms, or decorators. For example,
`movq %rsp, %rbp` becomes `MOVQ %rsp, %rbp`.

### ARM canonical syntax

`cdisasm_arm_format` formats successful A32, T32, and A64 results using these
deterministic rules. Syntax selectors 0 through 7 are permanent aliases of the
same canonical ARM output; the x86-only Intel and AT&T semantic names do not
imply different ARM dialects. A future ARM dialect must use new option space.

- By default, mnemonics, register names, conditions, shifts, extensions, and
  Apple option words are lowercase. The uppercase-opcode flag uppercases the
  mnemonic and any suffix attached to it; operand text remains lowercase. A32
  register IDs R13, R14, and R15 print as `sp`, `lr`, and `pc`.
- A32/T32 conditions are mnemonic suffixes such as `beq`; A64 conditional
  branch conditions follow a dot, such as `b.eq`. A flag-setting `s` precedes
  an A32/T32 condition when the base mnemonic does not already contain it.
- Ordinary immediates use `#0x...` or `#-0x...`. A PC-relative operand prints
  its resolved target without `#`. Shifts and extensions follow the operand,
  for example `r2, lsl #0x3` or `w2, sxtw #0x2`.
- Memory uses `[base, #offset]`; pre-index writeback appends `!`, and post-index
  syntax is `[base], #offset`. A register offset and its shift/extension use the
  same comma-separated form inside the brackets.
- Register lists enumerate their registers in braces, for example
  `{r4, r5, lr}`; user-register transfers append ` ^`. LDM/STM omit the default
  `ia` suffix and use `ib`, `da`, or `db` for the other directions. Base-register
  writeback appends `!`.
- A32/T32 NEON element type is attached to the mnemonic, for example
  `vadd.i8`; A64 vector lane-count/element-width metadata produces arrangements
  such as `v0.16b`. Apple MUL53 attaches its arrangement to the mnemonic, such
  as `mul53lo.2d`, and SDSB immediates 0--3 print `osh`, `nsh`, `ish`, or `sy`.

The ARM formatter accepts only a successful two- or four-byte result with a
known ISA/name, bounded operands and groups, valid scalar/vector registers and
lane metadata, coherent branch targets, indexing flags, conditions, and Apple
classification flags. Public decode never succeeds with operand-opaque
metadata. If an externally constructed opaque generated result is supplied,
formatting succeeds only when an exact generated recipe renders every operand;
otherwise it returns zero and clears a nonempty destination buffer. As with
x86, it does not allocate memory.

Formatting for both architectures is deterministic across platforms and does
not depend on locale.

The current version-12 x86 structured layout is fixed at 32 bytes per
`cdisasm_opcode`, 16 bytes per `cdisasm_x86_encoding`, and 248 bytes per
`cdisasm_instruction`. Version 11 raises `CDISASM_MAX_OPERANDS` from the four
slots used through version 10 to five so four-vector-plus-imm8 forms such as
`VPERMIL2` fit without discarding an explicit operand.
Within an operand, the four 16-bit register fields begin at offsets 4, 6, 8,
and 10; access and broadcast are at 12 and 13; `address` and `imm` begin at 16
and 24. Within the instruction, the five-operand array begins at offset 32, the
ISA group count and IDs begin at offsets 192 and 194, `mask_reg` begins at 224,
and `encoding` begins at 232. The mask mode, rounding, and SAE bytes occupy
offsets 226 through 228. All reserved bytes are required to be zero. The
declarations contain compile-time size and offset checks for C11 and C++11
consumers.

## x86 result classification

`opcode_groups` can combine call, jump, return, interrupt, privileged,
conditional, and relative-branch flags. The interrupt categories also include
the related system-call and system-return instructions. `CONDITIONAL` applies
to Jcc, CMOVcc, SETcc, and loop-family conditionals. `PRIVILEGED` describes the
usual architectural classification; actual permission can depend on mode and
system configuration. Direct relative branches have
`CDISASM_GROUP_RELATIVE_BRANCH` and a valid `branch_target`; indirect branches
do not.

The low `opcode_flags` bits record every encountered legacy, REX, and supported
VEX prefix class, including a class later superseded by another prefix. The effective
group-1 bits record the last LOCK/REP/REPNE class for deterministic formatting.
`operand_count` is the number of valid entries at the start of the `opcode`
array; remaining entries are zero.

## Versioning

`CDISASM_VERSION_MAJOR`, `CDISASM_VERSION_MINOR`, and
`CDISASM_VERSION_PATCH` are 12, 0, and 0. `cdisasm_version()` returns
`0x00MMmmpp`, where `MM`, `mm`, and `pp` are the public ABI major, minor, and
patch versions, so version 12.0.0 returns `0x000c0000`.
`cdisasm_version_string()` returns `"12.0.0"`. Returned version and status
strings have process lifetime and must not be freed.
The three simple decimal definitions in `cdisasm_version.h` are the single
release authority: CMake reads them before `project()`, derives the package and
SONAME versions, and rejects a component that cannot fit the packed 8-bit
runtime representation. The string macro and runtime string are derived from
the same values rather than maintained as independent literals.
Version 5.0 introduced the ABI-major architecture split:

- `cdisasm` owned only architecture-neutral version/status services;
- `cdisasm_x86` owned the version-5 explicit and umbrella-header x86 decode
  exports;
- `cdisasm_arm` owned the architecture-specific decoder and CPU-mode queries;
- `cdisasm_format` exposed the optional x86 text layer.

The version-5 x86 result kept the 216-byte version-4 layout, existing
instruction/register IDs, and the then-current raw CPU ordinals. Nevertheless,
an application built against version 4 must relink: the x86 decode symbol moved
from the old monolithic library to `cdisasm_x86`. The compatibility umbrella
header provided source compatibility, not binary compatibility.

Version 6.0 renames the public x86 exports from `cdisasm_x86_decode2` and
`cdisasm_decode2` to `cdisasm_x86_decode` and `cdisasm_decode`, and renames the
ARM export from `cdisasm_arm_decode2` to `cdisasm_arm_decode`. The old symbols
are not declared or exported. This intentionally requires version-5 source to
rename its calls and all consumers to rebuild and relink. The 216-byte x86 and
168-byte ARM instruction layouts and non-CPU numeric IDs are unchanged.

Version 6 also changes the numeric representation of CPU profiles. Version 5
stored an architecture-local raw ordinal; version 6 ORs that same low-16-bit
ordinal with an architecture group:

| Architecture | Version-5 raw range | Version-6 conversion | Example |
| --- | ---: | --- | --- |
| x86 | 0--44 | `CDISASM_CPU_GROUP_X86 \| old_id` | `4` becomes `0x00010004` (`CDISASM_CPU_80386`) |
| ARM | 0--37 | `CDISASM_CPU_GROUP_ARM \| old_id` | `4` becomes `0x00020004` (`CDISASM_ARM_CPU_CORTEX_A32`) |

This migration must know the architecture. In particular, version-5 raw zero
represented either unrestricted x86 or unrestricted ARM and cannot select a
version-6 group by itself. Persisted records and wire formats should store the
cdisasm ABI major and architecture alongside the CPU value, validate the old
range before conversion, and then store the full composite ID. Passing a raw
version-5 CPU number directly to a version-6 decoder is invalid; version 6 does
not silently reinterpret it.

Version 7.0 moves the `cdisasm_decode` export from `cdisasm_x86` to `cdisasm`
and changes its last parameter from `cdisasm_instruction *` to `void *`. The
scalar calling convention and the explicit `cdisasm_x86_decode` and
`cdisasm_arm_decode` APIs are unchanged. The generic entry point now dispatches
by the version-6 CPU-group field and accepts the corresponding x86 or ARM result
pointer. Unknown and build-disabled groups return zero without modifying that
pointer. The architecture decoders retain their ordinary error initialization
after a call has been dispatched.

Version-6 applications using `cdisasm_decode` must rebuild and relink against
`cdisasm` rather than `cdisasm_x86`; this is a binary compatibility break even
though an ordinary call passing an x86 result remains source-compatible with
the new `void *` parameter. In version 7, applications using an explicit
architecture entry point kept linking that architecture library. Neither the
216-byte x86 result nor the 168-byte ARM result layout changes in version 7.

A default full version-7 build used four Windows runtime files:
`cdisasm-7.dll`, `cdisasm_x86-7.dll`, `cdisasm_arm-7.dll`, and
`cdisasm_format-7.dll`. Import libraries and CMake targets remained unsuffixed:
`cdisasm`, `cdisasm_x86`, `cdisasm_arm`, and `cdisasm_format`, exported as the
corresponding `cdisasm::` targets.

Version 8.0 consolidates the common implementation and every decoder selected
by `USE_ARCH_X86` and `USE_ARCH_ARM` into `cdisasm`. The explicit
`cdisasm_x86_decode`, `cdisasm_arm_decode`, and ARM mode-query symbols therefore
move from their version-7 architecture import libraries to `cdisasm.lib`.
`cdisasm_decode`, version/status services, and their signatures remain in the
core. The formatter remains the one optional separate shared library.

Version-7 generic callers already named the correct CMake target, but every
consumer must rebuild for the new ABI major. Explicit-decoder callers must
relink to `cdisasm.lib` and stop deploying the removed architecture DLLs.
Enabled version-8 packages keep `cdisasm::cdisasm_x86` and
`cdisasm::cdisasm_arm` only as interface proxies to `cdisasm::cdisasm`, so an
existing CMake link line can redirect during a source rebuild; those proxies
are not binary compatibility libraries. No function signature, numeric ID, or
fixed x86/ARM result layout changes in version 8.

A default full version-8.1 Windows build has at most two runtime files:
`cdisasm-8.dll` and `cdisasm_format-8.dll`. Its real import libraries and CMake
targets are `cdisasm` and `cdisasm_format`, exported as the corresponding
`cdisasm::` targets. Any decoder-enabled build creates the formatter; a
common-only build has only the core runtime.

Version 9.0 inserts a 32-bit formatter `flags` parameter immediately after the
instruction pointer in `cdisasm_x86_format`, `cdisasm_arm_format`, and the x86
compatibility wrapper `cdisasm_format`. This is a source and binary
compatibility break for formatter callers; every call must supply a syntax
value and every consumer must rebuild and relink. Version 9 also moves the
formatter exports into `cdisasm`, adds the default-on `USE_DISASM_FORMAT`
selection, and retains `cdisasm::cdisasm_format` only as an interface proxy.
The generic and explicit x86 decoder option parameters also widen to the
64-bit `cdisasm_decode_option`/`cdisasm_x86_decode_option` ABI. Explicit ARM
decoding retains its 32-bit option type. The fixed x86 and ARM result layouts
do not change.
Existing numeric IDs remain stable while new x87/ARM values append. Standard
`BUILD_SHARED_LIBS` defaults to `ON`: a default full
version-9 Windows build has one runtime and import library, `cdisasm-9.dll` and
`cdisasm.lib`. Setting it to `OFF` creates one static `cdisasm.lib` archive and
no DLL; installed CMake targets propagate `CDISASM_STATIC` for that mode.
Applications must stop deploying or linking the version-8 formatter library
and use matching major-version headers and binaries.

For history, version 4.0 widened x86 register IDs and grew the x86 structures;
version 4.1 appended UD0/UD1 IDs and coverage without changing that layout.
Version 5.0 preserves those x86 records while separating symbol ownership and
adding the independent ARM ABI.
Version 5.1 appends T32 decoding, the decoder-mode query, ARM legality and
address-direction flags, x86 HLE metadata, and the two VZERO mnemonic IDs while
retaining both fixed instruction layouts.
Version 5.2 appends Apple A-, M-, and S-family ARM CPU profiles, explicit
Cortex-A7/A9 NEON variants, ARM vector IDs and lane metadata, and x86
SSE-family mnemonic IDs. It adds table-driven SSE through SSE4.2 and selected
A32/T32/A64 Advanced SIMD decoding while retaining both fixed instruction
layouts.
Version 5.3 appends the complete pinned-Capstone Apple-proprietary A64 mnemonic
set, Cyclone's named EL3 register, four Apple classification flags, CPU-specific
extension gates, descriptor/corpus/fuzz coverage, and no structure fields. Both
fixed instruction layouts and the ABI-major DLL names remain unchanged.
Version 5.4 appends six exact x86-64/SSE4.2/no-AVX Intel processor profiles,
defines `CDISASM_CPU_LAST` separately from the APX-level
`CDISASM_CPU_LATEST`, and adds CPU-gating regression coverage. Existing
version-5 CPU ordinals, numeric instruction/register IDs, fixed result layouts,
and ABI-major DLL names remain unchanged.
Version 6.0 renames both x86 decode entry points and the ARM decode entry point,
removes the version-5 symbol names, and advances the ABI-major DLL suffix to
`-6`. It does not change either fixed instruction layout or published
instruction, register, group, or operand IDs. CPU profile ordinals stay stable,
but their full numeric IDs gain the architecture-group bits described above.
Version 7.0 moves the generic decode export into the common facade, dispatches
both enabled architectures by those CPU-group bits, generalizes the result
parameter to `void *`, and advances the ABI-major DLL suffix to `-7`. Explicit
decoder exports, numeric IDs, and fixed result layouts remain unchanged.
Version 8.0 moves the explicit x86 and ARM APIs into that same core library,
removes the architecture runtime/import libraries, keeps compatibility CMake
target proxies, and advances the ABI-major DLL suffix to `-8`. The formatter
remains optional and separate; signatures, numeric IDs, and fixed result
layouts remain unchanged.
Version 8.1 adds architecture-explicit `cdisasm_x86_format` and
`cdisasm_arm_format` entry points to that formatter DLL and retains
`cdisasm_format` as the x86 compatibility wrapper. It enables the formatter
target/component for ARM-only installations without changing either decoder
result layout or the `-8` ABI-major DLL suffix.
Version 9.0 adds the formatter flags argument, syntax selectors 0 through 7,
assigns Intel and AT&T meaning to x86 syntax 0 and 1, adds opcode-only uppercase
output, rejects reserved formatter bits, and advances the ABI-major DLL suffix
to `-9`. It also folds optional formatting into `cdisasm`, introduces
`USE_DISASM_FORMAT`, removes the formatter DLL/import library, and keeps the
formatter CMake name as an interface compatibility proxy when available. It
honors standard `BUILD_SHARED_LIBS` with a default shared build and a static
alternative whose target propagates `CDISASM_STATIC`. X86 syntax 2 through 7
are permanent Intel compatibility aliases; all ARM syntax values are permanent
canonical aliases. It also appends the explicit pre-486 CPU-plus-x87 profiles,
the D8--DF x87 mnemonic range, and the ARMv8.0 ordered/exclusive load-store
mnemonics and flags. The default-on `USE_EXTRA_OPCODES` option adds the
append-only x86 VEX ID range 610--669 and ARM LSE/LOR/RCpc ID range 132--216,
with requested/effective package metadata and stable OFF-build ABI. It also
defines the append-only x86 runtime family-mask vocabulary: zero is base-only,
bits 0--30 are usable only in an ON build, and an OFF build rejects every
nonzero x86 mask as `INVALID_ARGUMENT`. CPU capability checks remain
independent. Generic dispatch preserves the complete 64-bit word for x86 and
validates that an ARM value fits its explicit 32-bit option type before
narrowing. Existing IDs and fixed result layouts remain unchanged.

Version 10.0 widens `cdisasm_arm_decode_option` and the explicit
`cdisasm_arm_decode` flags parameter from 32 to 64 bits, aliases it to the
generic option word, and advances the ABI-major DLL/SONAME suffix to `-10`.
Generic dispatch now forwards the complete word to ARM without a cast; the ARM
decoder validates bit 0 as big-endian and rejects reserved bits 1--63. Direct
ARM callers must rebuild and relink. Formatter flags remain 32-bit, and all
numeric IDs plus the fixed x86 and ARM result layouts remain unchanged.

Version 10.1 appends x86 mnemonic IDs 743--839, `AMX_FP16` group ID 93, and
the Granite Rapids CPU profile at ordinal 49. Its optional decoder expansion
completes the published FMA3/FMA4 mnemonic matrices and adds the bounded
XOP/VAES/VPCLMUL/EVEX arithmetic, AMX-FP16, APX `JMPABS`, and CET shadow-stack
forms documented above. It preserves both fixed result layouts, all earlier
numeric values, the 64-bit decode-option ABI, and the `-10` DLL/SONAME suffix.

Version 10.2 appends x86 mnemonic IDs 840--842 for `UMONITOR`, `UMWAIT`, and
`TPAUSE`, plus `WAITPKG` group ID 94. It implements the three register-form
WAITPKG operations with explicit SYSTEM and CPU capability gates, including
the independent APX-F requirement for REX2 map 1, and completes the EVEX
realization of all 60 existing FMA3 names: 36 packed PS/PD forms at all three
vector lengths and 24 scalar SS/SD forms. It also corrects CET/WIDENOP prefix
and mode collisions against Intel XED, preserves the `mod=00` SIB `base=5`
disp32/no-base exception under REX2
B4, and classifies reserved F2/66 `0F AE` register extensions as invalid. Both
fixed result layouts, every earlier numeric value, the 64-bit option
ABI, and the `-10` DLL/SONAME suffix remain unchanged.

Version 11.0 raises `CDISASM_MAX_OPERANDS` from four to five and grows
`cdisasm_instruction` from 216 to 248 bytes so the four vector operands plus
imm8 of `VPERMIL2` are all representable. This is an x86 result-layout ABI
break: consumers must rebuild and relink, and the DLL/SONAME suffix advances
to `-11`. The 32-byte operand record, 16-byte encoding record, 64-bit decode
option, ARM result layout, and every earlier numeric ID remain unchanged.

The same release appends x86 mnemonic IDs 843--993, group IDs 95--107, and the
Arrow Lake and Diamond Rapids CPU profiles at ordinals 50 and 51. Its bounded
optional expansion completes the release's cataloged XOP tranche; adds modern
SHA-512/SM3/SM4, common VEX arithmetic/conversions, cache/system, AMX
COMPLEX/FP8/MOVRS/row, AVX10.2 BF16, and broader APX forms; and realizes all
51 classic VEX K-mask mnemonics with 65 exact descriptor rows and independent
AVX-512-versus-AVX10 admission. Runtime-mask bits 31 and 32 are appended for
SM3 and SM4, making `0x1ffffffff` the known mask and leaving bits 33--63
reserved. These scoped completions do not claim complete
VEX, EVEX/AVX-512, AVX10, APX, AMX, crypto, or system-map coverage.

Version 11.1 appended x86 mnemonic IDs 994--1001 and ARM mnemonic IDs
332--341 without changing either result layout or the `-11` DLL/SONAME major.
The x86 decoder completes the packed-integer EVEX compare-to-mask family with
a conditional AVX-512F/BW/VL CPU/runtime route and a mutually alternative
AVX10.1 route, K-mask and memory metadata, structural OFF-build recognition,
and formatter/corpus/fuzz tests.
The ARM decoder completes the 15-operation SVE predicate-logical submap,
reusing five existing names and appending ten, with typed predicate, zeroing,
flag-setting, endian, CPU, formatter, corpus, and OFF-build contracts.
Version 11.2 appends x86 IDs 1002--1013 and ARM IDs 342--347, completing the
bounded 16-name EVEX packed-integer MIN/MAX class and 26-form SVE unpredicated
integer-arithmetic class without changing either result layout or ABI major.
Version 11.3 reuses three historical x86 names and appends IDs 1014--1020 to
complete the ten-name EVEX packed-integer multiply/multiply-add class. It also
appends ARM IDs 348--353 for the complete 24-form SVE vector ZIP/UZP/TRN class
and adds the A64-only, SVE-only Fujitsu A64FX CPU profile at ordinal 38.
Version 11.4 reuses x86 IDs 642--649 to complete the eight-name
EVEX.66.0F modular/wrapping packed-integer ADD/SUB matrix with 60 legal
register, full-memory, and broadcast shapes. It appends ARM IDs 354--356 for
`TBL`, `TBX`, and `TBXQ`, reuses `MOV` (31), and completes the selected SVE
table-lookup selector block's 16 lookup and four MOV-from-GPR forms. Neither
fixed result layout nor the `-11` DLL/SONAME major changes.
Version 11.5 appends x86 IDs 1021--1028 for the complete eight-name
signed/unsigned saturating byte/word ADD/SUB family across VEX.128/256 and
EVEX.128/256/512. It appends ARM `TBLQ` at ID 357 and completes the exact
131,072-word SVE2.1/SME2.1 class. Neither fixed result layout nor the `-11`
DLL/SONAME major changes.
Version 11.6 appends x86 IDs 1029--1036 for the complete EVEX D/Q logical
class, reuses `VPAVGB/W` for the complete EVEX byte/word average class, and
adds exact APX P0.B4 ownership to both. It appends ARM IDs 358--364 for the
complete 74-pair destructive predicated SVE integer class and reuses the six
permutation names for all 42 fixed-width A64 Advanced SIMD arrangements.
Neither fixed result layout nor the `-11` DLL/SONAME major changes.
Version 11.7 appends x86 IDs 1037--1042 for the VEX/EVEX dword/qword
`VPSLLVD/Q`, `VPSRLVD/Q`, and `VPSRAVD/Q` per-element variable-shift tranche,
including its exact APX P0.B4 and U0 ownership. It appends ARM IDs 365--377
and completes the integer, bitwise/floating, and reverse predicated SVE unary
classifiers, containing 917,504 allocated and 393,216 reserved words. Neither
fixed result layout nor the `-11` DLL/SONAME major changes.

Version 11.8 appends x86 IDs 1043--1045 for the remaining EVEX word forms
`VPSLLVW`, `VPSRLVW`, and `VPSRAVW`, including exact no-broadcast behavior,
AVX-512/AVX10 admission, and APX P0.B4 plus U0/X4 ownership. It appends ARM
IDs 378--380 for `ASRR`, `LSRR`, and `LSLR`, reuses `ASR`, `LSR`, and `LSL`,
and completes the exact 524,288-word predicated SVE vector-shift classifier
with 270,336 allocated and 253,952 reserved words. Neither fixed result layout
nor the `-11` DLL/SONAME major changes.

Version 11.9 appends x86 IDs 1046--1049 for `VPROLVD/Q` and `VPRORVD/Q`,
completing their exact EVEX.66.0F38 dword/qword variable packed-rotate class
with AVX-512/AVX10 admission and APX P0.B4/U0/X4 ownership. It appends ARM IDs
381--386 for `ASRD`, `SQSHL`, `UQSHL`, `SRSHR`, `URSHR`, and `SQSHLU`,
reuses `ASR`, `LSR`, and `LSL`, and completes the disjoint 524,288-word
predicated SVE/SVE2 immediate-shift classifier with 276,480 allocated and
247,808 reserved words. Neither fixed result layout nor the `-11` DLL/SONAME
major changes.

Version 11.10 appends x86 IDs 1050--1053 for `VPROLD/Q` and `VPRORD/Q`,
completing their exact EVEX.66.0F dword/qword immediate packed-rotate class
with AVX-512/AVX10 admission, APX P0.B4/U0/X4 ownership, and exact neighboring
allocated-versus-reserved extension classification. It appends ARM IDs
387--396 for the complete 10-name SVE integer vector-compare class and owns
the exact 8,388,608-word classifier with 7,077,888 allocated and 1,310,720
reserved encodings. Neither fixed result layout nor the `-11` DLL/SONAME major
changes.

Version 11.11 appends x86 IDs 1054--1057 for `VPSRLD`, `VPSRAD`, `VPSRAQ`,
and `VPSLLD`, completing every allocated extension/W control in the exact
EVEX.66.0F opcode-`72` immediate packed rotate/shift group with
AVX-512/AVX10 admission and APX P0.B4/U0/X4 ownership. It reuses ARM IDs
387--396 for the signed and unsigned SVE integer compare-with-immediate
envelopes, which together own 12,582,912 words with 11,534,336 allocated and
1,048,576 reserved encodings. Neither fixed result layout nor the `-11`
DLL/SONAME major changes.

Version 11.12 appends x86 IDs 1058--1064 for the allocated EVEX.66.0F
opcode-`71`/`73` word, qword, and byte-lane immediate-shift groups with exact
mask, broadcast, feature, and APX ownership. It appends ARM IDs 397--402 for
the exact 131,072-word SVE/SME floating compare-with-zero classifier, of which
73,728 words are allocated and 57,344 are reserved. Both additions require
`USE_EXTRA_OPCODES=1`; neither fixed result layout nor the `-11` DLL/SONAME
major changes.

Version 11.13 appends x86 IDs 1065--1076 for the exact AVX512VBMI2 EVEX
map-2/map-3 double-shift slice: 12 allocated and four reserved map/opcode/W
controls, with every imm8 for the six immediate forms, exact masks,
broadcast/disp8, AVX-512F+VBMI2(+VL) or AVX10.1 admission, and APX P0.B4/U0
memory ownership. It appends ARM IDs 403--405 for the exact
`0xff204000/0x65004000` seven-operation H/S/D floating vector-compare class,
whose 4,194,304 words split into 2,752,512 allocated and 1,441,792 reserved.
The focused x86 ON/no-formatter/OFF checks and completed ARM 20/20 ON/OFF
release selections pass; 36/36 ARM canonical controls match pinned Capstone.
Eight final-audit regressions also lock mandatory-`66` EVEX maps 2/3 opcodes
`70`--`73`: forbidden legacy prefixes and non-long-mode APX P0.B4 return
`TRUNCATED` while an owned ModRM/SIB/displacement or applicable imm8 remains
incomplete, then `INVALID_INSTRUCTION` once complete. They pass ON, OFF,
no-formatter, and MSVC. XED agrees on the legacy-prefix pairs; 32-bit B4 is not
an XED-parity claim because XED rejects at the EVEX prefix.
Strict Clang full CTest matrices pass 60/60 extras-ON/formatter-ON, 54/54
extras-OFF/formatter-ON, and 58/58 extras-ON/formatter-OFF. Native MSVC shared
direct functional/data tests pass 58/58. Intel XED v2026.08.23 has zero
mismatches across 452/452 oracle cases: 412 complete inputs (300 accepted and
112 rejected) plus 40 truncations. All four fresh WSL Clang 14 ASan+UBSan
libFuzzer campaigns (x86/ARM × extras ON/OFF) complete 10,000 runs each without
a finding.
The Clang 21.1.6 installed-package end-to-end matrices pass 16/16 shared
Release cells in 3,586.82 seconds and 16/16 static Debug cells in 4,008.22
seconds, with zero failures. Both cover dual/x86/ARM/common-only × formatter
ON/OFF × extras ON/OFF, including build-tree and relocated C/C++ consumers and
component, symbol, and artifact checks. Shared nested producers used the
project's built-in `-Wall -Wextra -Wpedantic` without a global `-Werror`;
every static nested producer cache contains
`-Wall -Wextra -Wpedantic -Werror`. Shared and static
x86/formatter-ON/extras-ON producers were rebuilt and reinstalled into their
relocated prefixes; relinked build-tree and relocated consumers pass 7/7 in
each of the four suites without changing the 16/16 matrix totals. Neither fixed
result layout nor the `-11` DLL/SONAME major changes.

Version 11.14 appends x86 IDs 1077--1088 for the exact COMPRESS/EXPAND,
VPOPCNTB/W/Q, and VPSHUFBITQMB rows, while reusing VPOPCNTD. It appends ARM
IDs 406--414 for the exact SVE/SME destructive predicated FP binary class.
At that release boundary, the x86 runtime allow mask grew from bits 0--32 to
descriptor-backed bits 0--59; the older
AVX512/AES/PCLMUL/SHA/AMX/VIRTUALIZATION/SSE4/BITMANIP bits remained
compatibility umbrellas, and bits 60--63 remained rejected. Dedicated
tests cover all 23 appended granular selectors, old-umbrella admission, narrow
isolation, CPU/mode queries, and the reserved-bit boundary. Intel XED
v2026.08.23 independently validates the 78 canonical new x86 register/memory
forms plus decorator, broadcast, displacement, APX, reserved, and truncation
controls. Pinned Capstone matches all 42 canonical/reserved ARM controls, and
the ARM focused suite exhausts all 344,064 words in its exact union.

Version 11.15 appends x86 IDs 1089--1092 for the exact EVEX.66.0F38
`VPCONFLICTD/Q` and `VPLZCNTD/Q` class. Bit 60 is the narrow
`CDISASM_X86_DECODE_FLAG_AVX512_CD` selector, `AVX512` remains its
compatibility umbrella, and bits 61--63 remain rejected. The same release
appends ARM IDs 415--419 for the exact baseline SVE/SME floating-point fast
reductions `FADDV`, `FMAXNMV`, `FMINNMV`, `FMAXV`, and `FMINV`. Their exact
classifier owns 262,144 words: 122,880 H/S/D allocated forms and 139,264
byte-width or reserved-operation controls.

Version 11.16 appends x86 IDs 1093--1094 for the exact register-only
`VPBROADCASTMB2Q` and `VPBROADCASTMW2D` rows, completing the six-mnemonic
AVX-512CD feature while reusing runtime bit 60. It appends ARM `FADDA` at ID
420 for the exact 32,768-word SVE serial-reduction classifier: 24,576 H/S/D
forms are allocated and 8,192 byte-width forms are reserved. The x86 rows keep
AVX-512/AVX10/APX gates independent; the ARM row requires FEAT_SVE rather than
accepting SME alone.

Version 11.17 retains x86 `VPDPBUSD` ID 715 and appends IDs 1095--1097 for
`VPDPBUSDS`, `VPDPWSSD`, and `VPDPWSSDS`, completing the exact four-operation
EVEX AVX-512 VNNI dot-product row with register, full-memory, broadcast,
masking, AVX-512/AVX10, and reviewed APX routes. It appends ARM IDs 421--428
for the seven `FRINT*` names and `FRECPX`, reuses `FSQRT`, and owns the exact
655,360-word merging/zeroing SVE FP-unary union: 442,368 allocated and
212,992 reserved words.

Version 11.18 retains x86 `VPERMB` ID 714 and appends IDs 1098--1100 for
`VPERMI2B`, `VPERMT2B`, and `VPMULTISHIFTQB`, completing the exact classic
EVEX AVX512_VBMI byte-permute/multishift slice with register, Full-memory,
`VPMULTISHIFTQB` broadcast, masking, AVX-512/AVX10, and reviewed APX routes.
It appends ARM `FRECPE` (429) and `FRSQRTE` (430) and owns the exact
8,192-word unpredicated SVE/SME FP-estimate classifier: 6,144 H/S/D forms are
allocated and 2,048 byte-width forms are reserved.

Version 11.19 appends x86 IDs 1101--1103 for `VPERMI2W`, `VPERMT2W`, and
`VPERMW`, completing the adjacent W=1 word-permute rows with AVX512BW and
separate AVX10 admission. It reuses ARM IDs 429/430 for the exact fixed-width
Advanced SIMD scalar/vector `FRECPE`/`FRSQRTE` union: 16,384 words are allocated
and 2,048 are reserved across its exact 18,432-word envelope.

Version 11.20 reuses the four existing VNNI IDs for the exact classic
VEX.128/256 AVX-VNNI opcode-`50`--`53` row and appends narrow x86 runtime bit
61, `CDISASM_X86_DECODE_FLAG_AVX_VNNI`. The known mask becomes
`0x3fffffffffffffff`, leaving bits 62--63 reserved. It also reuses ARM IDs
348--353 for the disjoint FEAT_F64MM Q-element SVE ZIP/UZP/TRN class, whose
262,144-word envelope contains 196,608 allocated and 65,536 reserved words.
Neither catalog count, fixed result layout, nor the `-11` DLL/SONAME major
changes.

Version 11.21 appends x86 IDs 1104--1109 and group 108 for the exact six-name
classic VEX AVX-VNNI-INT8 row. Runtime bit 62 is its independent selector, the
known mask becomes `0x7fffffffffffffff`, and bit 63 remains reserved. It also
appends ARM `SCVTF` (431) and `UCVTF` (432) for the exact merging SVE/SME
H/S/D-to-H conversion classifier, whose 65,536-word envelope contains 49,152
allocated and 16,384 reserved words. Neither fixed result layout nor the `-11`
DLL/SONAME major changes.

Version 11.22 appends x86 IDs 1110--1115 and group 109 for the exact six-name
classic VEX AVX-VNNI-INT16 row. Runtime bit 63 is its independent selector;
`ALL` and `KNOWN_MASK` become `0xffffffffffffffff`, saturating the current
`uint64_t` family namespace. It also reuses ARM `SCVTF` (431) and `UCVTF`
(432) for four exact S-to-S, D-to-S, S-to-D, and D-to-D merging conversion
envelopes containing 65,536 allocated words. Neither fixed result layout nor
the `-11` DLL/SONAME major changes.

Version 11.23 appends x86 IDs 1116/1117 for the exact memory-only Knights Mill
`VP4DPWSSD`/`VP4DPWSSDS` AVX512_4VNNIW pair. It reuses existing group 71 and
the AVX-512 runtime umbrella bit 19 because the 64-bit family mask is saturated,
while retaining an independent CPU capability. It appends the exact Knights
Mill CPU profile at ordinal 52: `CDISASM_CPU_LATEST` remains Diamond Rapids,
while `CDISASM_CPU_LAST` becomes Knights Mill. The release also appends ARM
`FCVT` (433), `FCVTZS` (434), and `FCVTZU` (435) for 20 complete baseline
merging forms whose classifiers own 163,840 allocated and 40,960 reserved
words. Neither fixed result layout nor the `-11` DLL/SONAME major changes.

Version 11.24 appends x86 IDs 1118--1121 for the complete memory-only Knights
Mill AVX512_4FMAPS family: packed `V4FMADDPS`/`V4FNMADDPS` and scalar
`V4FMADDSS`/`V4FNMADDSS`. Existing group 72 remains independent while the
family reuses the saturated-mask AVX-512 runtime umbrella bit 19. The release
also appends ARM `BFCVT` (436) for the exact merging SVE/SME encoding; that
release did not claim zeroing or multi-vector BFCVT forms. Neither fixed result
layout nor the `-11` DLL/SONAME major changes.

Version 11.25 appends x86 IDs 1122--1125 for the exact AVX512F/AVX10.1
`VGETEXPPS`/`VGETEXPPD`/`VGETEXPSS`/`VGETEXPSD` tranche. It appends ARM
`BFCVTNT` (437) for exact merging and zeroing forms and reuses `BFCVT` (436)
for the exact zeroing form. That historical 11.25 entry did not claim
PH/SH/BF16 GETEXP, GETMANT, multi-vector BFCVT, or MOVPRFX stream diagnostics;
version 11.26 below resolves only the exact PH/SH/BF16 and pair-BFCVT forms.
Neither fixed result layout nor the `-11` DLL/SONAME major changes.

Version 11.26 appends x86 IDs 1126--1128 for exact MAP6
`VGETEXPPH`/`VGETEXPSH`/`VGETEXPBF16` and ARM `BFCVTN` (438) for exact
unpredicated pair narrowing while reusing `BFCVT` (436) for the pair conversion
forms. PH/SH has AVX512-FP16 or AVX10.1 admission; BF16 requires AVX10.2. The
two non-FP8 ARM pair forms require SME2, and the two FP8 forms retain an
independent FP8 gate. There is no pair `BFCVTNT` allocation. Neither fixed
result layout nor the `-11` DLL/SONAME major changes.

Version 11.27 separates runtime policy for Intel VMX, AMD SVM, and Intel SMX.
Existing bits 53 and 54 remain the VMX and SVM selectors; bit 23 is canonically
named `CDISASM_X86_DECODE_FLAG_SMX`. The historical
`CDISASM_X86_DECODE_FLAG_VIRTUALIZATION` name remains numerically equal to bit
23 but no longer admits VMX or SVM. Vendor-readable aliases map directly to
VMX and SVM, and CPU flag queries report all three capabilities independently.
No catalog ID, fixed result layout, flag value, or the `-11` DLL/SONAME major
changes.

Version 11.28 adds the architecture-neutral `CDISASM_CPU_UNKNOWN` sentinel and
exports `cdisasm_current_cpu()`. The query returns the closest named catalog
profile that can be established for the process- or guest-visible instruction
environment, or `CDISASM_CPU_UNKNOWN` when no reliable enabled-architecture
match exists. It never returns either unrestricted ordinal-zero profile and
does not select decode mode or optional family flags. No existing catalog ID,
decoder signature, fixed result layout, or the `-11` DLL/SONAME major changes.

Version 12.0 replaces each by-value decoder option word with a pointer to the
fixed 64-byte `cdisasm_decode_flags` object. The explicit x86 and ARM aliases
use the same eight-word layout with independent meanings, `NULL` means an
all-zero base/default policy, and every reserved bit is validated. Existing
x86 bitmap-0 mask values remain unchanged, while append-only logical
`CDISASM_X86_DECODE_BIT_*` IDs and the common bit helpers allow future
assignments above bit 63. The singular `cdisasm_decode_option`,
`cdisasm_x86_decode_option`, and `cdisasm_arm_decode_option` types remain
64-bit bitmap-word aliases but are no longer decoder argument types.

The x86 flag query changes from a scalar return to
`cdisasm_status cdisasm_x86_cpu_decode_flag_mask(cpu, mode, out)`, and version
12 also exposes matching ARM and generic queries. Each query requires a
caller-owned output, clears it before validation, and distinguishes an invalid
request from a valid all-zero result through its status. These signature
changes require every version-11 decoder consumer to rebuild and relink.
Windows uses `cdisasm-12.dll`, Unix-like SONAMEs use major 12, and the fixed
248-byte x86 and 168-byte ARM instruction-result layouts remain unchanged.

Version-11.27 virtualization-change validation passed all 85/85 strict Clang
21.1.6 dual-architecture
CTest targets with extras and formatting enabled. The extras-disabled direct
suite passes 78/78 and the formatting-disabled suite passes 83/83; the affected
flag-matrix target was rebuilt under `-Wall -Wextra -Wpedantic -Werror` and
rerun in both variants after the exhaustive CPU table was added. Targeted
shared and static installed-package consumers each pass 8/8 tests. Two WSL2
Clang 14 ASan+UBSan x86 libFuzzer campaigns, with extra opcodes enabled and
disabled, complete 25,000 units each without a finding.

The previously recorded post-tranche strict Clang 21.1.8 validation matrix passed
257/257 non-package CTests with formatting and extras enabled, 252/252 with extras
disabled, and 255/255 with formatting disabled. A separate fresh package
configuration passed both end-to-end CTests and all 16 shared plus all 16
static feature cells.
At that snapshot, the ARM catalog check verified 3,191 rules, 5,164 direct
forms, 481 aliases, and 1,535 opaque records in every applicable cell. The
corresponding ASan+UBSan validation covered x86 and ARM under extras ON and OFF within
campaigns of 6,000 total libFuzzer runs in each of the four cells. All four
cells passed without a sanitizer, invariant, timeout, leak, or crash artifact;
the reviewed source inventories then contained 2,395 x86 and 1,679 ARM seeds.
Direct replay reported 2,396 x86 and 1,680 ARM libFuzzer runs because each replay
includes libFuzzer's empty unit in addition to the source files. These are
bounded validation campaigns, not exhaustive architectural coverage. The
current ARM assembly-recipe audit verifies 3,191 rules, 6,569 direct forms,
595 aliases, and 16 classified opaque records, with zero actionable unresolved
recipes. PSTATE-immediate `MSR` now has numeric field operands and CPU gating.
The 16 remaining records are eight byte-underdetermined `VRSHR`/`VSHR` source
aliases and eight assembly-only VORN-immediate source aliases; they are not
independently decodable opcode forms. This update has not yet rerun the
sanitizer/fuzzer matrix.

Current catalog totals are 2,028 x86 name IDs including `NONE`, 307 defined x86
register IDs in a 309-slot ID space, 323 x86 groups, 2,054 ARM name IDs
including `NONE`, and 375 ARM registers.
Current checked-in regression data contains 5,726 x86 rows, 4,164 ARM rows,
2,395 x86 fuzz seeds, and 1,679 ARM fuzz seeds. Across all 9,001 pinned x86
IFORMs, the generated-coverage audit classifies 2,440 as `corpus_reachable`,
three as `corpus_partial`, one as `profile_rejected_probe`, 3,922 as
`source_assignment_only`, and 2,635 as `catalog_only`; its
`exact_evidence_forms` rollup is 2,444. Across all 6,569 ARM leaves, it
classifies 1,886 as `corpus_reachable`, one as `profile_rejected_probe`, 1,484
as `source_assignment_only`, and 3,198 as `catalog_only`; its
`exact_evidence_forms` rollup is 1,887.
Generator/manifest v4
endian-normalizes A32/A64 words and T32
halfwords and invokes `xed-dec` in its default 32-bit mode rather than
passing the unsupported `-32` option; the endian correction removed eight
historical false-positive ARM form credits. SVE2/SME `XAR` form 2325 moved
from `verified_missing_encoding` to `corpus_reachable`; neither architecture
now has a `verified_missing_encoding` row. Advanced SIMD `ADDV` form 6077
previously moved to exact corpus-reachable coverage, as did classic-VEX
`VDPPD` forms 4507--4508 and
`VDPPS` forms 4515--4518, including the allocated 32-bit B-prime alias
`c4 c3 71 41 c2 01`. The latest exact tranche completes all 144 pinned
VEX/EVEX packed-integer MIN/MAX forms and all 36 pinned GFNI forms on x86,
plus all 30 fixed-width A32/T32/A64 SHA1/SHA256 leaves and the 17-form fixed
A64 SHA3/SHA512/SM3/SM4 block 6287--6303. These
are inventory and scoped family-completion counts, not claims of
exhaustive x86, ARM, AVX-512/AVX10/APX/AMX, Advanced SIMD, SVE/SVE2, or SME
coverage.

The latest x86 semantic tranche covers all 24 floating `VCOMPRESSPD/PS` and
`VEXPANDPD/PS` forms 3637--3648/4527--4538, all six `VDBPSADBW` forms
4453--4458, and all twelve `VPTERNLOGD/Q` forms 8259--8270. It validates exact
vector widths and ISA groups, masks, broadcasts, FullMem compressed
displacements, APX address promotion, malformed controls, truncation, both
syntaxes, and extras-OFF ownership. `VPTERNLOG` destinations are always
read/write because their previous contents are an input to the ternary truth
table.

The latest ARM semantic tranche covers all twenty FEAT_CRC32 leaves across
A32 forms 98--103, T32 forms 2169--2174, and A64 forms
5582--5587/5602--5603; SVE/SME `AND`/`ORR`/`EOR`/`BIC` forms 2321--2324;
SVE2/SME `XAR` form 2325; and fourteen A32/T32/A64 architectural
synchronization/debug hints. It validates the `MOV` alias, destructive tied
`XAR` register, width-dependent rotation immediate, A32 conditions, CRC
register restrictions, `DBG #imm4`, `TSB CSYNC`, endian transport, feature
alternatives, named profiles, and extras-OFF ownership.

The next exact semantic tranche covers all 48 EVEX mask-result vector-test
forms 8271--8318 (`VPTESTM*` and `VPTESTNM*`) and twelve ARM multiply leaves:
A32/T32 `MUL`, the A32 flag-setting alias leaf, and A32/T32
`UMULL`/`UMLAL`/`SMULL`/`SMLAL`. Native results expose exact K destinations,
merge-mask access, vector/memory/broadcast sizes, scalar-register access,
condition and flag metadata, IT-state behavior, feature/profile gates, and
reserved-control rejection.

The following ARM tranche makes all A32 extra-load/store forms 1--48 exact.
It covers `STRH`, `LDRH`, `LDRSB`, `LDRSH`, `LDRD`, `STRD`, `STRHT`,
`LDRHT`, `LDRSBT`, and `LDRSHT` with exact scalar or register-pair operands,
signed register/immediate offsets, PC-relative literal addresses, pre/post
writeback, conditional groups, unprivileged metadata, and malformed-register
rejection. Its focused target is `cdisasm_arm_extra_load_store_tests`.

That focused target also covers 34 wide T32 leaves: `LDRD`/`STRD` forms
1750--1756 and the halfword/signed-load forms 2049--2108. Exact results expose
ordered register pairs, scaled register offsets, signed immediates, resolved
literal addresses, writeback and unprivileged state. It additionally covers
the 26 byte/word transfer leaves 2045--2090 and all 24 T32 table-branch and
exclusive/acquire-release leaves 1726--1749. Those results preserve table
index scaling, status registers, pair ordering, atomic access/order flags,
immediate scaling, and ARMv7-versus-ARMv8 admission while continuing to
delegate unrelated neighboring encodings. All 11 wide T32 `PLD`/`PLDW`/`PLI`
prefetch leaves 2047--2107 are also exact, including register shifts, signed
and unsigned immediates, aligned PC-relative literals, zero-sized read-only
memory hints, ARMv7 admission, reserved-register rejection, and extras-OFF
ownership.
X87 `FPTAN`, `FPATAN`, `FXTRACT`, `FPREM`, and `FRNDINT` now have exact pinned
X87/no-integer-status evidence. A32 `YIELD`, `WFE`, `WFI`, and `SEV` now have
explicit exact zero-operand decoding, conditional execution, ARMv7 admission,
and extras-off ownership.
Both widths of x87 `FIADD`, `FIMUL`, `FICOM`, and `FICOMP` now have exact
integer-memory read access and X87-family evidence. A32 `SMUAD`, `SMUADX`,
`SMUSD`, `SMUSDX`, `SMMUL`, and `SMMULR` now have explicit three-register
decoding, PC legality, ARMv6 admission, condition metadata, and extras-off
ownership; their encodings were independently assembled with Clang.
The remaining canonical x87 `FCOM` and `FCOMP` memory/register forms now have
exact read access and X87-family evidence. A32 `SMLABB`, `SMLABT`, `SMLATB`,
`SMLATT`, `SMULBB`, `SMULBT`, `SMULTB`, `SMULTT`, and `UMAAL` now have explicit
multiply/accumulate and long-pair access, PC and pair legality, ARMv5/ARMv6
admission, condition metadata, and extras-off ownership; their encodings were
independently assembled with Clang.
The x87 `FLDENV`, `FNSTENV`, `FRSTOR`, and `FNSAVE` 16/32-bit operand-size
forms now have exact 14/28-byte and 94/108-byte state access plus X87-family
evidence; no pinned X87 form remains `source_assignment_only`. A32 `SXTAB16`,
`SXTB16`, `SXTAB`, `SXTAH`, `UXTAB16`, `UXTB16`, `UXTAB`, and `UXTAH` now have
explicit accumulate/extend alias operands, ROR metadata, PC legality, ARMv6
admission, condition metadata, and extras-off ownership.
x86 BMI2 `BZHI` now has exact 32/64-bit register/memory-source evidence,
three-operand access, and BMI2-family validation. A32 Advanced SIMD `VBIC` and
`VORR` D/Q leaves now have exact vector operands, even-register legality for Q
forms, SIMD metadata, NEON admission, and core ownership with extras disabled.
Legacy x86 `ADDPS` and `ADDPD` memory-source forms now have exact destructive
destination/source access and SSE/SSE2 family evidence. A32 `AESE`, `AESD`,
`AESMC`, and `AESIMC` now have explicit Q-register decoding, even-D legality,
SIMD metadata, destructive access where applicable, ARMv8+NEON plus AES feature
admission, normalized unconditional metadata, and extras-off ownership.
Legacy x86 `ADDSS` and `ADDSD` register and memory-source forms now have exact
destructive destination/source access and SSE/SSE2 family evidence. A32 `VAND`
D and `VEOR` D/Q forms now have explicit vector operands, Advanced SIMD family
metadata, even-register legality for Q forms, NEON admission, and extras-off
ownership.
Classic x86 `ADC` now has exact byte/word/dword/qword accumulator, register,
immediate, and memory-direction evidence with preserved arithmetic-flag
semantics. A32 `SMLALBB`, `SMLALBT`, `SMLALTB`, and `SMLALTT` now have explicit
four-register decoding, read/write long accumulator pairs, ARMv5 admission,
conditional metadata, register legality, and extras-off ownership.
Classic x86 `ADCX` and `ADOX` register and memory forms now have exact
destructive access and independent ADX-family evidence. A32 `AND`, `ANDS`,
`EOR`, and `EORS` shifted-register and `RRX` leaves now have exact operands,
shift metadata, conditional execution, canonical flag-setting names, and
`SETS_FLAGS` metadata where applicable.
The remaining classic non-APX x86 `ADC` memory-immediate encodings now have
exact byte/word/dword and sign-extended-immediate evidence, including the
legacy opcode-`82` alias. A32 `ADD/ADDS`, `SUB/SUBS`, and `RSB/RSBS`
shifted-register/RRX forms, including SP-source aliases, now have exact
canonical names, operand access, shifts, conditions, and flag metadata.
Legacy x86 `ADDSUBPD` and `ADDSUBPS` register/memory forms now have exact
destructive access and SSE3-family evidence. A32 `ADC/ADCS`, `SBC/SBCS`, and
`RSC/RSCS` shifted-register/RRX forms now have exact carry/borrow operands,
canonical flag-setting names, conditions, shifts, and `SETS_FLAGS` metadata.
The remaining legacy x86 AES-NI `AESENC`, `AESENCLAST`, `AESDEC`, `AESDECLAST`,
`AESIMC`, and `AESKEYGENASSIST` register/memory forms now have exact source and
destination access plus AES-family evidence. A32 `TST`, `TEQ`, `CMP`, and `CMN`
shifted-register/RRX forms now have exact two-input operands, conditions,
shifts, and unconditional `SETS_FLAGS` metadata.
Legacy x86 `ANDPS`/`ANDNPS` and `ANDPD`/`ANDNPD` register/memory forms now have
exact destructive access and their SSE/SSE2 family split. A32 `ORR/ORRS`,
`MOV/MOVS`, `BIC/BICS`, and `MVN/MVNS` shifted-register/RRX leaves now have
exact operand shapes, conditions, shifts, canonical flag-setting names, and
`SETS_FLAGS` metadata.
The remaining classic non-APX x86 `ADD` accumulator, byte-register, and
memory-immediate forms now have exact operand/access evidence, including the
legacy opcode-`82` alias. Nineteen A32 immediate `AND/ANDS`, `EOR/EORS`,
`ADD/ADDS`, `SUB/SUBS`, `RSB/RSBS`, `ADC/ADCS`, `SBC/SBCS`, and `RSC/RSCS`
leaves now have exact immediate values, conditions, operand access, and flag
metadata, including SP-source forms.
x86 `ANDN` now has exact 32/64-bit register/memory-source evidence, independent
write-only destination semantics, and its BMI1 family gate. Ten A32 immediate
`TST`, `TEQ`, `CMN`, `ORR/ORRS`, `MOVS`, `BIC/BICS`, and `MVN/MVNS` leaves now
have exact operand shapes, immediate values, conditions, canonical names, and
flag metadata.
The remaining classic non-APX x86 `AND` accumulator, byte/dword register,
memory, and immediate forms now have exact access evidence, including opcode
`82`. Thirteen A32 immediate `LDR/LDRB/STR/STRB/LDRBT/STRT` offset,
pre-writeback, post-writeback, literal, byte, and unprivileged leaves now have
exact memory access and addressing-mode flags.
x86 BMI1 `BEXTR` now has exact 32/64-bit register/memory-source evidence,
three-operand access, and BMI1-family validation. The A32 decoder now owns all
sixteen register-offset `LDR/LDRB/STR/STRB/LDRT/LDRBT/STRT/STRBT` leaves with
exact index shifts, signed direction, pre/post indexing, writeback, byte, and
unprivileged metadata; focused rows also cover LSL #2 and negative ASR #32.
x86 `BLENDPD`, `BLENDPS`, `BLENDVPD`, and `BLENDVPS` now have exact remaining
register/memory evidence, destructive destination access, immediate or
implicit-XMM0 controls, and SSE4.1-family validation. A32 `SSAT` and `USAT`
LSL/ASR leaves now have explicit signed/unsigned saturation immediates, exact
shift operands, register legality, ARMv6 admission, and extras-off ownership.
x86 BMI1 `BLSI`, `BLSMSK`, and `BLSR` now have complete classic 32/64-bit
register/memory-source evidence, exact write/read access, and BMI1-family
validation. A32 `SMMLA`, `SMMLAR`, `SMMLS`, and `SMMLSR` now have explicit
four-register decoding, rounded/non-rounded identity, PC legality, ARMv6
admission, condition metadata, and extras-off ownership.
All remaining x87 real-memory `FLD`, `FST`, and `FSTP` widths now have exact
read/write access and X87-family evidence. A32 `SMLAWB`, `SMLAWT`, `SMULWB`,
and `SMULWT` now have explicit multiply/accumulate access, PC legality, ARMv5
admission, condition metadata, and extras-off ownership; their encodings were
independently assembled with Clang.
The remaining x87 `FILD`, `FIST`, `FISTP`, and `FISTTP` integer-width forms
now have exact memory access, X87-family, and SSE3 evidence where applicable.
A32 `SMLAD`, `SMLADX`, `SMLSD`, `SMLSDX`, `SMLALD`, `SMLALDX`, `SMLSLD`,
and `SMLSLDX` now have explicit accumulator/long-pair access, PC and distinct-
destination legality, ARMv6 admission, condition metadata, and extras-off
ownership; their encodings were independently assembled with Clang.
Both widths of x87 `FISUB`, `FISUBR`, `FIDIV`, and `FIDIVR` now have exact
integer-memory read access and X87-family evidence. A32 `USAD8` and `USADA8`
now have explicit alias/accumulator decoding, exact three- or four-register
access, PC legality, ARMv6 admission, condition metadata, and extras-off
ownership; their encodings were independently assembled with Clang.
X87 `FTST`, `FXAM`, `FYL2X`, `FYL2XP1`, and `FSCALE` now have exact pinned
X87/no-integer-status evidence. A32 and narrow T32 `SEVL` now have explicit
exact zero-operand decoding, ARMv8 admission, conditional A32 handling, and
extras-off ownership.
X87 register-stack `FST ST(i)` and `FSTP ST(i)` now have exact pinned
destination-write and family evidence. A32 `SETEND` now has exact LE/BE
selector decoding, normalized unconditional condition metadata, ARMv6
admission, and extras-off ownership.
X87 register-stack `FADDP ST(i), ST(0)` now has exact read/write operand and
family evidence. A32 `CLREX` now has exact zero-operand decoding, normalized
unconditional condition metadata, ARMv7 admission, and extras-off ownership.
The remaining x87 pop-arithmetic forms `FMULP`, `FSUBP`, `FSUBRP`, `FDIVP`,
and `FDIVRP` now have exact register-access and X87-family evidence. The A32
`DSB`, `DMB`, and `ISB` barrier leaves have exact option operands, normalized
unconditional metadata, ARMv7 admission, and extras-off ownership.
All eight x87 `FCMOVcc` forms now have exact register access, conditional, P6,
and X87-family evidence. A32 `SETPAN` now has exact clear/set selectors,
privileged metadata, ARMv8 plus `FEAT_PAN` admission, a negative named-profile
probe, and extras-off ownership.
The x87 `FUCOM`, `FUCOMP`, `FUCOMPP`, `FCOMPP`, `FUCOMI`, `FCOMI`, `FUCOMIP`,
and `FCOMIP` forms now have exact stack-register access plus X87 and FCOMI
family evidence where applicable. A32 `SDIV` and `UDIV` now have explicit
three-register decoding, PC-register legality checks, ARMv7 admission,
condition metadata, and extras-off ownership.
X87 packed-BCD `FBLD` and `FBSTP` now have exact 80-bit memory access and
X87-family evidence. A32 `BFC` and `BFI` now have explicit destination/source,
least-significant-bit, and width operands; invalid ranges and PC registers are
rejected, with ARMv6 admission, conditional metadata, and extras-off ownership.
X87 `FLDCW`, `FNSTCW`, and `FNINIT` now have exact control-word/init operand
access and X87-family evidence. The remaining A32 `MOVT` leaf now has exact
read/write destination and immediate metadata, ARMv6 admission, condition and
extras-off behavior, plus explicit invalid-PC rejection shared with `MOVW`.
Both x87 `FNSTSW` destinations now have exact write access and X87-family
evidence. A32 `SADD16`, `SADD8`, `SSUB16`, `SSUB8`, `UADD16`, `UADD8`,
`USUB16`, and `USUB8` now have explicit three-register decoding, PC-register
legality, ARMv6 admission, condition metadata, and extras-off ownership.
All remaining x87 `FADD` and `FMUL` memory/register directions now have exact
operand access and X87-family evidence. A32 `QADD16`, `QADD8`, `QSUB16`,
`QSUB8`, `UQADD16`, `UQADD8`, `UQSUB16`, and `UQSUB8` now share the explicit
parallel-arithmetic classifier with PC legality, ARMv6 admission, condition
metadata, and extras-off ownership.
All x87 `FDIV` and `FDIVR` memory/register directions now have exact operand
access and X87-family evidence. The twelve A32 `ASX`/`SAX` parallel forms—
signed, saturating, halving, and unsigned—now use explicit selector mappings
with three-register access, PC legality, ARMv6 admission, condition metadata,
and extras-off ownership.
All remaining x87 `FSUB` and `FSUBR` memory/register directions now have exact
operand access and X87-family evidence. A32 `SHADD16`, `SHADD8`, `SHSUB16`,
`SHSUB8`, `UHADD16`, `UHADD8`, `UHSUB16`, and `UHSUB8` now share the explicit
parallel-arithmetic classifier with PC legality, ARMv6 admission, condition
metadata, and extras-off ownership.
X87 register-stack `FLD ST(i)` and `FXCH ST(i)` now have exact pinned access
and X87-family evidence. A32 `HVC #imm16` now has explicit exact split-
immediate decoding, interrupt/privileged metadata, ARMv7 admission, and
extras-off ownership.
X87 `FDECSTP` and `FINCSTP` now have exact pinned X87/no-integer-status
evidence. A32 `CLZ` now has exact destination/source access, ARMv5 admission,
conditional execution, PC rejection, and extras-off ownership.
X87 `FFREE ST(i)` now has exact pinned register-write access, X87 identity,
and no integer status-flag effects. A32 `SMC #imm4` now has explicit exact
interrupt/privileged decoding, conditional execution, ARMv7 admission, and
extras-off ownership.
The remaining five x87 load-constant forms `FLDL2T`, `FLDL2E`, `FLDPI`,
`FLDLG2`, and `FLDLN2` now have exact pinned X87/no-integer-status evidence.
Narrow T32 `YIELD`, `WFE`, and `WFI` now have explicit exact zero-operand
decoding, ARMv7 admission, and extras-off ownership.
X87 `F2XM1`, `FSQRT`, `FSINCOS`, `FSIN`, and `FCOS` now have exact pinned
zero-operand, X87-family, and no-integer-status evidence. Narrow T32 `SEV` now
has explicit exact zero-operand decoding, ARMv7 admission, and extras-off
ownership.
All eight wide T32 block-transfer leaves 1718--1725 are exact as well:
`SRSDB`/`SRS`, `RFEDB`/`RFE`, `STM`/`LDM`, and `STMDB`/`LDMDB`, including
register-list access, writeback and addressing direction, privileged and
exception-return groups, valid exception modes, malformed boundaries, and
extras-OFF ownership.
The 18 wide T32 shifted-register logical leaves 1757--1774 are exact too,
covering `AND`/`ANDS`/`TST`, `BIC`/`BICS`, `ORR`/`ORRS`, and `MOV`/`MOVS`,
including all immediate shift kinds, RRX, flag-setting identities, operand
elision, malformed PC boundaries, and extras-OFF ownership.
The adjacent 14 leaves 1775--1788 likewise make `ORN`/`ORNS`, `MVN`/`MVNS`,
`EOR`/`EORS`, and `TEQ` exact for shifted and RRX forms.
The packing pair 1789--1790 makes `PKHBT` and `PKHTB` exact, including LSL/ASR
immediates, encoded ASR #32, PC legality, ARMv6 admission, and extras-OFF
ownership.
The next four leaves 1791--1794 make shifted-register `ADD` and `ADDS` exact,
including RRX, shift metadata, flag-setting identity, PC/SP legality, ARMv7
admission, and extras-OFF ownership.
The adjacent six leaves 1795--1800 make the SP-source `ADD`/`ADDS` forms and
the destination-eliding `CMN` alias exact under the same contract.
The next eight leaves 1801--1808 make `ADC`/`ADCS` and `SBC`/`SBCS` exact,
including RRX, shift and flag metadata, register legality, ARMv7 admission,
and extras-OFF ownership.
The following fourteen leaves 1809--1822 make `SUB`/`SUBS`, their SP-source
forms, `CMP`, and `RSB`/`RSBS` exact under the same contract.
The six wide T32 hint leaves 1825--1830 make `NOP`, `YIELD`, `WFE`, `WFI`,
`SEV`, and `SEVL` exact with ARMv7/ARMv8 admission and extras-OFF ownership.
Six T32 system leaves 1841--1846 make `CLREX`, `DSB`, `SSBB`, `PSSBB`, `DMB`,
and `ISB` exact, including barrier options and alias operand elision. `SB`
remains deferred because the public capability model has no `FEAT_SB` bit.
T32 exception forms 1856--1858 are exact `HVC #imm16`, `SMC #imm4`, and
`UDF #imm16` decodes with interrupt/privilege metadata, ARMv7 admission,
big-endian transport, truncation, corpus, fuzz, and extras-OFF ownership.
T32 forms 1848--1850 are exact `BXJ Rm`, `SUBS PC, LR, #imm8`, and
zero-immediate `ERET` decodes. They retain indirect-jump and privileged
interrupt-return grouping, flag updates, reserved-register rejection,
ARMv7 admission, endian transport, truncation, and extras-OFF ownership.
T32 conditional `B.W` form 1859 and immediate `BLX` form 1861 use exact signed
target reconstruction. `B.W` retains its encoded condition; BLX uses an
aligned PC base and link/call metadata. Tests cover reserved conditions,
backward targets, endian transport, architecture admission, truncation, and
neighboring `B.W`/`BL` ownership.
T32 modified-immediate logical forms 1863--1867 add exact `AND`, `ANDS`, `TST`,
`BIC`, and `BICS`. Architectural Thumb immediate expansion covers replicated
and rotated constants; forbidden zero replication is invalid, `TST` is selected
from the destination-PC alias, flag writes are explicit, and SP/PC legality is
enforced.
Modified-immediate logical forms 1868--1878 add exact `ORR`, `ORRS`, `MOV`,
`MOVS`, `ORN`, `ORNS`, `MVN`, `MVNS`, `EOR`, `EORS`, and `TEQ`. Source-PC
and destination-PC aliases are selected before ordinary register validation;
expanded constants, flags, endian transport, and disabled ownership remain
exact.
Modified-immediate arithmetic forms 1879--1883 add exact `ADD`, `ADDS`, their
SP-source variants, and destination-eliding `CMN`, including expanded
constants, flag writes, and register legality. Catalog immediate `ADC/SBC`
forms remain uncredited because LLVM 21 rejects those spellings and there is
no independent oracle for them.
Plain-imm12 T32 forms 1895--1900 add exact `ADDW`, `SUBW`, their SP-source
variants, and positive/negative `ADR.W`. ADR uses the aligned PC base and
preserves its resolved address and signed displacement; arithmetic operands
retain the unexpanded imm12 value.
Modified-immediate forms 1888--1894 add exact `SUB`, `SUBS`, their SP-source
variants, destination-eliding `CMP`, and `RSB`/`RSBS`, with exact expanded
constants, flags, reverse-subtract SP restrictions, endian transport,
truncation, and extras-OFF ownership.
T32 signed halfword multiply forms 2179--2186 add exact `SMLABB`, `SMLABT`,
`SMLATB`, `SMLATT`, `SMULBB`, `SMULBT`, `SMULTB`, and `SMULTT` decoding.
The accumulator field selects the three-operand `SMUL*` aliases when encoded
as PC; all forms retain ARMv6 admission, forbidden-register validation, and
extras-OFF ownership.
The adjacent dual-halfword forms 2187--2190 make `SMLAD`, `SMLADX`, `SMUAD`,
and `SMUADX` exact under the same accumulator-alias, register-legality, ARMv6,
and optional-opcode contracts.
Word-by-halfword forms 2191--2194 likewise make `SMLAWB`, `SMLAWT`, `SMULWB`,
and `SMULWT` exact, including the three-operand multiply aliases selected by
an encoded PC accumulator.
Dual-halfword subtract forms 2195--2198 make `SMLSD`, `SMLSDX`, `SMUSD`, and
`SMUSDX` exact with the same accumulator alias, forbidden-register, ARMv6,
and optional-opcode behavior.
Scalar multiply-tail forms 2199--2206 make `SMMLA`, `SMMLAR`, `SMMUL`,
`SMMULR`, `SMMLS`, `SMMLSR`, `USADA8`, and `USAD8` exact. They distinguish
the valid multiply aliases from the reserved `SMMLS*` PC-accumulator forms
and retain exact four- versus three-register operand lists.
T32 halfword long-accumulate forms 2210--2213 make `SMLALBB`, `SMLALBT`,
`SMLALTB`, and `SMLALTT` exact with read/write low/high destinations, ARMv6
admission, forbidden SP/PC validation, and equal-destination rejection.
Long dual-halfword forms 2214--2217 make `SMLALD`, `SMLALDX`, `SMLSLD`, and
`SMLSLDX` exact with the same read/write pair and register-legality contracts,
plus exact add/subtract and exchange-bit selection.
T32 `UMAAL` form 2219 is exact with two read/write destination registers,
two read sources, ARMv6 admission, LR acceptance, and equal-pair/SP/PC
rejection.
Narrow T32 `HLT` form 1160 is exact across its complete six-bit immediate
range, carries interrupt metadata, requires ARMv8, and remains owned when
optional opcodes are disabled.
Narrow T32 `CPSID`/`CPSIE` forms 1158--1159 are exact across the encoded A/I/F
mask, carry privileged metadata, require ARMv6, and preserve optional-opcode
ownership and older-profile rejection.
Narrow T32 `SETEND` form 1157 is exact for both LE and BE selectors, including
canonical endian spelling, ARMv6 profile admission, and optional-opcode
ownership. The same formatter tranche renders `CPSID`/`CPSIE` masks as
`none` or ordered `aif` letters rather than numeric immediates.
Narrow T32 `UDF` form 1178 is now explicit exact core decoding rather than
generated-only recognition. It covers the full imm8 range, ARMv4T admission,
interrupt metadata, and extras-OFF ownership.
Narrow T32 `SETPAN` form 1156 is exact for both immediate values and requires
ARMv8 plus the stable internal `FEAT_PAN` identity. It carries privileged
metadata and conservatively rejects named profiles that do not explicitly
claim PAN while remaining available to unrestricted analysis.
The legacy x86 decimal-adjust quartet `DAA`, `DAS`, `AAA`, and `AAS` now has
exact pinned IFORM evidence in 32-bit mode plus explicit long-mode rejection,
moving four previously source-only forms to corpus-reachable coverage.
Single-byte x86 flag controls `CLC`, `STC`, `CMC`, `CLD`, and `STD` now have
exact pinned IFORM and Intel/AT&T formatting evidence in 64-bit mode. `CLI`
and `STI` are now credited by the exact privilege-policy evidence below.
Legacy x86 `INT3` and `INTO` now have exact pinned IFORM evidence. `INT3` is
valid in long mode, while `INTO` retains interrupt/conditional metadata and
explicit long-mode rejection.
Legacy x86 `INT imm8` now has exact pinned operand, formatting, and interrupt
metadata evidence in both 32-bit and 64-bit modes.
Legacy x86 `BOUND r16,m16&16` and `BOUND r32,m32&32` now have exact pinned
operand-width, paired-memory, formatting, and interrupt metadata evidence in
32-bit mode. They are not credited in long mode, where byte `0x62` is the EVEX
prefix.
The shared x86 opcode-byte `0x63` now has exact pinned evidence for both
`ARPL` register/memory forms in 32-bit mode and all three `MOVSXD`
register/memory width forms in long mode, including canonical AT&T `movslq`.
Legacy x86 `AAD imm8` and `AAM imm8` now have exact pinned immediate and
Intel/AT&T formatting evidence in 32-bit mode.
The x86 accumulator sign-extension family `CBW`, `CWDE`, `CDQE`, `CWD`, `CDQ`,
and `CQO` now has exact pinned operand-size/prefix evidence in long mode,
including all six canonical AT&T aliases.
Legacy x86 `BSF` and `BSR` now have exact pinned register-source and
memory-source IFORM evidence with REX.W, 64-bit operand widths, flag metadata,
and canonical AT&T size suffixes.
Legacy-family metadata now also marks status-flag reads/writes for the covered
decimal-adjust, `ARPL`, `BSF`/`BSR`, flag-control, and `INTO` forms; the corpus
asserts these semantics independently of prefix and ISA-family group flags.
Legacy x86 `BT` now has exact pinned register/memory and register/immediate
index IFORM evidence. Its operands are read-only, its carry-result metadata is
a status-flag write, and its `I386`/`AMD64` family groups remain explicit.
The modifying x86 bit-test family `BTC`/`BTR`/`BTS` now has exact pinned
register/memory and register/immediate index evidence. Each destination is
read-write, each index is read-only, and carry/status plus `I386`/`AMD64`
family metadata is enforced. Separate locked IFORM names remain uncredited.
Legacy x86 `BSWAP` now has exact 32-/64-bit evidence with read-write operand
access, no status-flag effects, canonical AT&T size suffixes, and explicit
`I486` plus long-mode `AMD64` family metadata.
The x86 string-compare family `CMPSB/W/D/Q` now has exact pinned width/prefix
evidence with two read-only implicit memory operands, status-flag writes, and
explicit `I86`/`I386`/`AMD64` family metadata. String `CMPSD` is distinguished
from its same-name scalar SSE instruction by operand form.
The x86 string-load family `LODSB/W/D/Q` now has exact pinned width/prefix
evidence with accumulator-write and implicit-memory-read access, no status-flag
effects, and explicit `I86`/`I386`/`AMD64` family metadata.
The x86 string-scan family `SCASB/W/D/Q` now has exact pinned width/prefix
evidence with two read-only implicit operands, status-flag writes, and explicit
`I86`/`I386`/`AMD64` family metadata.
The x86 string-move family `MOVSB/W/D/Q` now has exact pinned width/prefix
evidence with implicit-destination-write and implicit-source-read access, no
status-flag effects, and explicit `I86`/`I386`/`AMD64` family metadata. String
`MOVSD` is distinguished from scalar SSE `MOVSD` by operand form.
The x86 string-I/O family `INSB/W/D` and `OUTSB/W/D` now has exact pinned
width/prefix evidence. `INS` writes memory and reads the port, while `OUTS`
reads both operands; none changes status flags, and `I186`/`I386` family
metadata is enforced.
Legacy x86 `PUSHA`/`PUSHAD` and `POPA`/`POPAD` now have exact pinned
operand-size evidence with canonical AT&T aliases, no status-flag effects,
`I186`/`I386` family metadata, and explicit long-mode rejection.
The address-sized zero-counter branch family `JCXZ`/`JECXZ`/`JRCXZ` now has
exact pinned target evidence in 16-/32-/64-bit modes with conditional/jump
classification, no status-flag dependency, and `I386`/`AMD64` family metadata.
The counted-loop family `LOOP`/`LOOPE`/`LOOPNE` now has exact pinned target and
address-size evidence with explicit `I86` family identity. All are conditional
jumps; only `LOOPE` and `LOOPNE` report a status-flag read.
The eight scalar x86 port-I/O forms now have exact pinned immediate/`DX` port
and byte/accumulator-width evidence. `IN` writes its accumulator and reads the
port; `OUT` reads both operands. None affects status flags, and explicit `I86`
family metadata is enforced.
Legacy x86 `ENTER`/`LEAVE` now have exact pinned frame-control evidence in long
mode with `I186` family metadata, no status-flag effects, explicit immediate
reads for `ENTER`, and its canonical AT&T operand-order exception.
Legacy x86 `LAHF`/`SAHF` now have exact pinned long-mode evidence with their
`LAHF` ISA-family group. `LAHF` reports a status-flag read and `SAHF` a
status-flag write.
The x86 flags-stack family `PUSHF/D/Q` and `POPF/D/Q` now has exact pinned
operand-size and mode evidence with canonical AT&T aliases. Push forms report
status-flag reads, pop forms report writes, and `I86`/`I386`/`AMD64` family
metadata is enforced.
The x86 string-store family `STOSB/W/D/Q` now has exact pinned width/prefix
evidence with implicit-memory-write and accumulator-read access, no status-flag
effects, and explicit `I86`/`I386`/`AMD64` family metadata.
Legacy x86 `XCHG` now has exact pinned byte/dword register-register,
dword accumulator-special, and byte/dword memory-register evidence. Both
public operands are read-write, status flags are unaffected, and the original
`I86` family identity is explicit. Classic `IRET`/`IRETD`/`IRETQ` remain
unsupported because their variable stack-pop and architectural-state
transitions are not exactly representable by the fixed public result ABI.
Legacy x86 `HLT` now has exact pinned zero-operand evidence, explicit `I86`
family identity, privileged metadata, and no status-flag effects; it remains
correctly rejected when optional opcodes are disabled. A32 `UDF #imm16` now
has exact pinned split-immediate decoding with interrupt metadata, ARMv4
admission, and extras-off ownership rejection.
Legacy x86 `CLTS` now has exact pinned zero-operand evidence, privileged
metadata, no status-flag effects, and its precise `I286REAL` family identity.
The four A32 scalar signed-saturating forms `QADD`, `QSUB`, `QDADD`, and
`QDSUB` now have exact pinned three-register operand/access ordering,
condition handling, ARMv6 admission, PC rejection, and extras-off ownership.
Legacy x86 `CLI` and `STI` now have exact pinned zero-operand evidence,
privileged metadata, interrupt-status-flag writes, explicit `I86` identity,
and extras-off rejection. A32 `SSAT16` and `USAT16` now have exact pinned
destination/immediate/source operands, signed-versus-unsigned saturation
immediate adjustment, condition handling, ARMv6 admission, PC rejection, and
extras-off ownership.
Legacy x86 `INVD` now has exact pinned zero-operand evidence, privileged
metadata, no status-flag effects, and precise `I486REAL` family identity. A32
`SBFX` and `UBFX` now have exact pinned destination/source/lsb/width operands,
bitfield-bound validation, conditional execution, ARMv6 admission, PC
rejection, and extras-off ownership.
Legacy x86 `EMMS` now has exact pinned zero-operand evidence, no status-flag
effects, and precise `PENTIUMMMX` identity. A32 `PKHBT` and `PKHTB` now have
exact pinned three-register operands, LSL/ASR shift semantics including the
encoded `ASR #32` case, conditional execution, ARMv6 admission, PC rejection,
and extras-off ownership.
X86 `LFENCE` now has exact pinned zero-operand evidence, no status-flag
effects, and SSE2 family/capability identity. A32 `REV`, `REV16`, `RBIT`, and
`REVSH` now have exact pinned destination/source operands, conditional
execution, ARMv6 admission, PC rejection, and extras-off ownership.
X86 `SFENCE` now has exact pinned zero-operand evidence, no status-flag
effects, and SSE family/capability identity. A32 `SEL` now has exact pinned
destination/two-source access ordering, conditional execution, ARMv6
admission, PC rejection, and extras-off ownership.
X86 `FNOP` now has exact pinned zero-operand evidence, X87 family identity,
and no integer status-flag effects. Narrow T32 `REV`, `REV16`, and `REVSH` now
have exact pinned register operands and result-extension metadata, with
extras-off ownership verified.
X86 `FCHS` and `FABS` now have exact pinned zero-operand evidence, X87 family
identity, and no integer status-flag effects. Narrow T32 `SXTH`, `SXTB`,
`UXTH`, and `UXTB` now have explicit exact decoding with destination-write and
source-read operands, ARMv6 admission, and extras-off ownership.
X86 `FLD1` and `FLDZ` now have exact pinned zero-operand evidence, X87 family
identity, and no integer status-flag effects. A32 `SXTB`, `SXTH`, `UXTB`, and
`UXTH` now have exact destination/source access, optional `ROR` metadata,
conditional execution, ARMv6 admission, PC rejection, and extras-off
ownership.
Ten classic x86 register-source `CMOVcc` forms now have exact conditional-write
destination access, read-only sources, core ownership in extras-off builds, and
CMOV-family validation. Five A32 `STM`, user-bank `STM`/`LDM`, `LDMDB`, and
exception-return-list `LDM` leaves now have exact register lists, address
direction, pre/post indexing, user-register, jump, and condition metadata; the
decoder preserves canonical decrement-before `LDMDB` naming.
The corresponding memory-source forms of ten classic x86 `CMOVcc` conditions
now have exact evidence with conditional destination writes, read-only memory
sources, and CMOV-family validation. Exact ARM evidence now also covers A32
immediate `BLX`, T32 `IT` and wide `B`, plus A64 `CLREX`, `DMB`, `ISB`, 32-bit
`CBZ`, and 32-bit `CSEL`, including their optional-decoder ownership, branch,
barrier-option, IT-state, condition, and operand metadata.
Register and memory forms of ten further classic x86 `SETcc` conditions now
have exact evidence, destination-write access, and explicit `I386` family
validation. Exact ARM evidence now additionally covers narrow T32 `CBNZ`, A64
`DSB`, both 32- and 64-bit A64 `CBNZ`, and A64 `TBNZ`, including core/optional
ownership, branch targets, bit-index operands, and barrier-option metadata.
Ten classic x86 Jcc conditions now have exact short, 32-bit near, and 64-bit
near witnesses, with branch-operand access and the architectural `I86` short
versus `I386` near family split enforced. Fourteen predicated SVE integer and
floating unary leaves now have exact zeroing/merging, element-width, predicate,
operand-access, SVE-family, and optional-decoder evidence.
All five classic x86 `JMP` IFORMs now have exact register, memory, short, and
near witnesses, with the `I86` relative, `I386` 32-bit indirect, and `AMD64`
64-bit indirect family split enforced. Six unpredicated SVE multiply/high-half
multiply leaves now have exact destructive destination access, source access,
element-width, SVE-family, and optional-decoder evidence.
Four classic x86 `CMPXCHG` register/memory and byte/word-size-class IFORMs now
have exact read-write destination, read-only source, status-flag, and `I486`
family evidence. Twelve ARM leaves now have exact SVE `BCAX`/`BSL`, vector and
predicate `REV`, six predicate permutation, and scalar 32/64-bit `REV`
witnesses with destructive, predicate-result, result-write, SVE, and optional
ownership metadata.
Four classic x86 `NOT` register/memory IFORMs now have exact read-write access,
no-status-flag, and `I86` byte-register versus `I386` wider/addressing family
validation. Eight narrow T32 immediate/SP-relative load, store, ADD, and SUB
leaves now have exact operands, byte-width flags, addressing, access, and core
ownership evidence.
Four classic x86 unsigned `MUL` register/memory IFORMs now have exact source
access, status-flag, and `I86` byte-register versus `I386` wider/addressing
family validation. Fifteen narrow T32 arithmetic, logical, compare, and test
leaves now have exact implicit flag-setting names, operands, access, condition,
and core ownership evidence.
Four classic x86 unsigned `DIV` register/memory IFORMs now have exact source
access and `I86` byte-register versus `I386` wider/addressing family evidence.
Thirteen Thumb AdvSIMD VADD, VSUB, VMLA, VMLS, VAND, VBIC, and VORR leaves now
have exact D/Q width, integer/floating, AdvSIMD, operand, and core-versus-
optional ownership metadata.
Seven x86 `MOVSX`/opcode-63 witnesses now establish four further exact
register/memory sign-extension IFORMs with `I386` family and destination/source
access validation across operand widths. Six ARM leaves now have exact A64
`ERET`, streaming-vector-length `RDSVL`, and predicated SVE `REVB`, `REVH`,
`REVW`, and `RBIT` evidence, including exception-return, streaming, predicate,
zeroing/merging, element-width, access, and optional ownership metadata.
Four further x86 `MOVZX` register/memory IFORMs now have exact byte/word-source
evidence with `I386` family and destination/source access validation. Ten ARM
leaves now have exact A64 logical-immediate, shifted-register logical, and
baseline AdvSIMD logical witnesses, including immediate/shift operands,
AdvSIMD family flags, alias avoidance, and their core-versus-optional ownership.
Four classic x86 `NEG` register/memory and byte/general-width IFORMs now have
exact read-write destination and status-flag evidence, with `I86` byte-register
versus `I386` wider/addressing family validation. Eight ARM leaves now have
exact A64 ADD/SUB immediate and shifted-register, flag-setting ANDS, and
AdvSIMD SUB evidence, including status, AdvSIMD, operand, and core/optional
ownership metadata.
Four classic x86 signed `IDIV` register/memory IFORMs now have exact source
access and `I86` byte-register versus `I386` wider/addressing family evidence.
Ten Thumb AdvSIMD `VMUL`, `VEOR`, `VSUB`, and `VMLS` leaves now have exact D/Q
width, integer/floating, AdvSIMD, operand, and core-versus-optional ownership
metadata.
Ten classic x86 `INC`/`DEC` register, memory, and short-opcode IFORMs now have
exact read-write access, status-flag, and `I86` byte-register versus `I386`
wider/addressing family evidence. Four A32 flag-setting multiply leaves now
preserve their exact `MULS`, `UMULLS`, `UMLALS`, and `SMULLS` mnemonic IDs;
the existing `MLAS` and `SMLALS` witnesses were corrected at the same decoder
boundary.
Seventeen further classic x86 `SBB` IFORMs now have exact register, memory,
immediate, opcode-82, carry-read/status-write, operand-access, and legacy-family
evidence. A32 `RFEDA`, `RFEDB`, and `RFEIB` now decode with exact privileged
interrupt-return groups, addressing-direction/index flags, operands, and ARMv7
requirements.
The last classic x86 opcode-82 `ADC` IFORM and seventeen classic `SUB` IFORMs
now have exact immediate/register/memory, status-write, access, and legacy
family evidence. A32 `SRSDA`, `SRSDB`, and `SRSIB` now decode with exact mode,
stack-pointer, privileged, addressing-direction/index, and ARMv7 metadata.
Seventeen classic x86 `CMP` IFORMs now have exact register, memory, immediate,
opcode-82, read-only operand, status-write, and legacy-family evidence. A32
`STMDA`, `LDMDA`, `STMIB`, and `LDMIB` now retain exact addressing-mode
mnemonic identities alongside their index/direction and register-list metadata.
Seventeen classic x86 `XOR` IFORMs now have exact register, memory, immediate,
opcode-82, status-write, access, and legacy-family evidence. The remaining A32
increment-after exception-state forms `RFEIA` and `SRSIA` now have exact
interrupt-return/privileged, operand, addressing, and ARMv7 metadata.
Seventeen classic x86 `OR` IFORMs now have exact register, memory, immediate,
opcode-82, status-write, access, and legacy-family evidence. Twelve A32
`VSELEQ`/`VSELGE`/`VSELGT`/`VSELVS` half/single/double leaves now decode with
exact floating-point register widths, operand access, VFP family requirements,
and optional-extension ownership.
Twelve remaining classic x86 `TEST` IFORMs now have exact register, memory,
immediate, undocumented group-1, status-write, read-only access, and legacy
family evidence; the common status classifier now also covers legacy `AND`.
Six A32 `VMAXNM`/`VMINNM` half/single/double leaves now decode with exact
floating-point widths, access, VFP/ARMv8 requirements, and optional ownership.
Ten classic x86 `MOV` witnesses establish nine new exact register, memory, and
immediate IFORMs. Twelve A32 `VRINTA`/`VRINTN`/`VRINTP`/`VRINTM`
half/single/double leaves now decode with exact unary operands, floating-point
widths, VFP/ARMv8 requirements, and optional ownership.
The sign-extended immediate-to-64-bit classic x86 `MOV` IFORM and the A32
`BXJ` register leaf now have exact corpus evidence, including generated-family
identity for the optional ARM form.
The focused targets are `cdisasm_x86_vdbpsadbw_tests`,
`cdisasm_x86_vpternlog_tests`, `cdisasm_arm_crc32_tests`,
`cdisasm_arm_sve_unpredicated_logical_tests`, and
`cdisasm_arm_architectural_hint_tests`; floating compress/expand remains in
`cdisasm_x86_evex_compress_expand_tests`.
