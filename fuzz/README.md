# Decoder fuzzing

`fuzz_decode2.c` is a deterministic in-process libFuzzer harness for the x86
decoder and, when `USE_DISASM_FORMAT=ON`, `cdisasm_x86_format`. It decodes each
input in all three generic modes, in an
eligible mode for every named CPU profile, and at every possible truncation
boundary through the architectural 15-byte limit. Successful results are
checked for deterministic metadata and bounded/sorted IDs. Formatter-enabled
builds additionally check size-query, full-write, truncation, NUL-termination,
and invalid-metadata contracts. The seeds exercise legacy SSE mandatory-prefix
selection and the `0F`, `0F 38`, and `0F 3A` maps. Dedicated
`rdrand_r11.hex`, `rdseed_r11.hex`, `rtm_xabort.hex`, `rtm_xbegin.hex`,
`apx_rex2_integer_memory.hex`, and `apx_rex2_alu_families.hex` inputs keep
hardware-entropy, immediate-bearing RTM, and APX REX2 integer/memory and ALU
family paths in the starting corpus. The
`vex_fma3_expanded_*`, `vex_vaes_*`, `vex_vpclmulqdq_ymm.hex`,
`vex_modern_crypto.hex`,
`evex_vaes_avx10.hex`, `evex_vpclmulqdq.hex`,
`amx_fp16_tdpfp16ps.hex`, and `apx_jmpabs*` seeds cover the expanded FMA3,
vector-crypto, AMX-FP16, and APX absolute-branch routes, including malformed
and truncated JMPABS boundaries. The `cet_shadow_stack_*` seeds independently
enter all four CET shadow-stack parser routes and retain collision, invalid,
and truncation boundaries; every successful CET name is also required to have
the CET runtime bit and CPU-profile availability. The
`waitpkg_valid_widths.hex`, `waitpkg_collisions.hex`, and
`waitpkg_invalid_truncated.hex` seeds cover all three execution widths,
effective-address-width `UMONITOR`, prefix/CET/CLWB collisions, REX/REX2,
independent WAITPKG/APX-F gates, reserved forms, and truncation. The 36 packed
EVEX FMA3 forms and all 24 scalar SS/SD forms are locked by the dedicated
exhaustive unit suite, with representative exact opcode-corpus rows for the
packed routes. Fuzzed successes must carry FMA3 plus the
selected AVX-512 or AVX10 result group, while admission consumes only that
route's most-specific runtime bit. Exact `XEND` and `XTEST`
behavior is locked by deterministic unit and data-corpus cases. The
`evex_compare_mask.hex` and `evex_compare_mask_invalid.hex` seeds reach the
complete eight-mnemonic signed/unsigned packed-integer compare-to-mask class
and its illegal EVEX zeroing control. Failed results must contain only
`last_error_id`. Every input is decoded with a null/zero x86 flag set in
both variants, preserving structural coverage and the base-only contract. With
`USE_EXTRA_OPCODES=ON`, the harness additionally decodes with
an eight-word `cdisasm_x86_decode_flags` set whose word 0 is
`CDISASM_X86_DECODE_FLAG_ALL`, and with one deterministic hash-selected family
bit in word 0. This reaches admitted legacy and modern extension paths while checking
that a single unrelated bit cannot accidentally admit another family. The
single-family sweep now covers all 64 public bits, including bit 63 for
AVX-VNNI-INT16, and requires `ALL`/`KNOWN_MASK` to equal `UINT64_MAX`. The
fixed 64-byte ABI leaves seven architecture-scoped words for append-only
growth. The harness derives a nonzero value from the input for each reserved
word 1 through 7 in turn and requires a zeroed `INVALID_ARGUMENT` result, so
the decoder cannot silently narrow validation to the legacy word. With
the option `OFF`, the harness passes a known nonzero family bit and requires the
same zeroed `INVALID_ARGUMENT` result; complete non-base encodings reached with
the valid zero mask remain structurally owned and fail as unsupported. Exact
unsupported/invalid/truncated boundaries are also enforced by unit,
opcode-corpus, and installed-package tests.

The 174 focused packed-MIN/MAX seeds independently reach every form and key
boundary in the complete 144-form VEX/EVEX signed/unsigned byte/word/dword/
qword family. They cover all 48 VEX and 96 EVEX identities, memory/register
sources, masks, broadcast, APX address promotion, and reserved controls. The
12 `x86_gfni_*.hex` seeds reach legacy, VEX, canonical EVEX, APX U0/X4,
non-long alias, broadcast/zero-mask, reserved, and truncated paths for the
complete 36-form GFNI inventory. Fuzzer invariants pin exact forms, operands,
access, groups, runtime/ISA-set bits, and formatter behavior. The
`evex_integer_multiply.hex` and
`evex_integer_multiply_invalid.hex` seeds independently reach the complete
classic EVEX packed-integer multiply/multiply-add class and a reserved control.
The `evex_integer_add_sub.hex` and
`evex_integer_add_sub_invalid.hex` seeds independently reach the complete
eight-name modular/wrapping EVEX.66.0F packed-integer ADD/SUB matrix and its
reserved byte-broadcast boundary. The `vex_saturating_add_sub.hex` and
`evex_saturating_add_sub.hex` seeds independently reach the complete
eight-name signed/unsigned saturating byte/word ADD/SUB family through its VEX
and EVEX parser routes. Deterministic tests cover all 32 VEX and 48 EVEX
operand shapes, W/prefix aliases, masks, full-width memory, the no-broadcast
boundary, CPU/runtime gates, and OFF-build ownership. The
`vex_variable_shift.hex`, `evex_variable_shift.hex`, and
`evex_variable_shift_apx.hex` seeds independently reach the new AVX2 VEX,
canonical EVEX, and APX P0.B4/U0 variable-shift routes and their structural
boundaries. The 21 `evex_variable_word_shift*.hex` one-vector seeds independently
reach the adjacent EVEX word class, exact APX P0.B4/U0/X4 routes, reserved
controls and truncation paths as independently reachable inputs. The
`evex_vprolvd.hex`, `evex_vprolvq.hex`, `evex_vprorvd.hex`, and
`evex_vprorvq.hex` seeds independently reach all four variable packed-rotate
names. `evex_variable_rotate_apx_b4.hex` and
`evex_variable_rotate_apx_u0_x4.hex` reach the disjoint APX routes, while
`evex_variable_rotate_reserved_ll3.hex` reaches a reserved control. The four
`evex_vprol*_immediate.hex`/`evex_vpror*_immediate.hex` seeds reach every
immediate packed-rotate name; `evex_immediate_rotate_apx_b4.hex` and
`evex_immediate_rotate_apx_u0_x4.hex` reach its APX routes, and
`evex_immediate_rotate_reserved_ll3.hex` reaches a reserved control.
`evex_vpsrld_immediate.hex`, `evex_vpsrad_immediate.hex`,
`evex_vpsraq_immediate.hex`, and `evex_vpslld_immediate.hex` reach every
opcode-`72` immediate packed-shift name;
`evex_immediate_shift_apx_u0_x4.hex` reaches its APX route, and
`evex_immediate_shift_reserved_w1.hex` reaches a reserved extension/W control.
`evex_immediate_shift71.hex`, `evex_immediate_shift73_qword_broadcast.hex`,
and `evex_immediate_shift73_dq.hex` separately reach the version-11.12 word,
qword-broadcast, and byte-lane immediate-shift parser paths.
The six `evex_vbmi2_double_shift_*.hex` files independently reach variable,
immediate-register, immediate-memory, APX, reserved-control, and invalid-
decorator paths in the version-11.13 map-2/map-3 double-shift classifier.
The 17 `evex_vpcompress*`, `evex_vpexpand*`, `evex_vpopcnt*`,
`evex_vpshufbitqmb.hex`, and class-level APX/invalid seeds independently enter all
13 COMPRESS/EXPAND, BITALG-popcount, VPOPCNTDQ, and mask-destination names.
The four `evex_vpconflict*`/`evex_vplzcnt*` seeds plus the class-level
`evex_avx512cd_apx.hex` and `evex_avx512cd_invalid.hex` seeds independently
enter every name in the exact AVX-512CD unary class and its APX and reserved
boundaries. The `evex_vpbroadcastmb2q.hex` and
`evex_vpbroadcastmw2d.hex` seeds reach the two register-only mask-broadcast
rows that complete AVX-512CD. Six `evex_avx512vnni_*` seeds independently
reach all four dot-product opcodes, broadcast, APX, and invalid-control paths.
Five retained classic seeds--the four `vex_avx_vnni_vpdp*.hex` files plus
`vex_avx_vnni_w1_reserved.hex`--independently reach all four classic VEX
AVX-VNNI dot-product names, full-memory and SIB addressing, and W=1 rejection.
Ten `vex_avx_vnni_int8_*` seeds independently reach all six AVX-VNNI-INT8
names, full-memory and SIB addressing, W=1 rejection, unowned opcode/map
neighbors, and truncation. The now-obsolete classic AVX-VNNI
mandatory-prefix-neighbor seed was removed, for nine net new x86 files; pp
disjointness remains covered by the focused suite and opcode corpus.
The six `evex_avx10_vnni_int8_*` seeds independently reach every operation in
the exact AVX10.2 EVEX VNNI-INT8 row, including all six native IFORM families;
focused tests retain the vector-length, memory, broadcast, mask, compressed-
displacement, APX address-extension, and invalid-control boundaries. The
`apx_rex2_monitor_mwait.hex` seed reaches both exact REX2 map-1
`MONITOR`/`MWAIT` forms and their APX admission route.
Ten `vex_avx_vnni_int16_*` seeds independently reach all six AVX-VNNI-INT16
names, full-memory and SIB addressing, the W=1 reserved boundary, an F2 prefix
neighbor, a map neighbor, and truncation.
Ten `evex_avx512_4vnniw_*` seeds independently reach both Knights Mill
`VP4DPWSSD`/`VP4DPWSSDS` opcodes, mask zero, Tuple1_4X disp8, the ZMM31 source
boundary, reserved W/LL/B/register controls, and truncation.
Fifteen `evex_avx512_4fmaps_*` seeds independently reach all four packed and
scalar AVX512_4FMAPS names, mask zero, Tuple1_4X disp8, the source-group
boundary, and reserved W/U/B/length/register, map-neighbor, and truncation paths.
Eight `evex_vgetexp_*` seeds independently reach packed and scalar register forms,
full-width memory, broadcast, SAE, address-size and segment prefixes, and
reserved controls for the exact
AVX512F/AVX10.1 PS/PD/SS/SD tranche.
Eight version-11.26 MAP6 seeds--`evex_vgetexp16_reserved.hex` plus the
`evex_vgetexpph_*`, `evex_vgetexpsh_*`, and `evex_vgetexpbf16_*` files--
independently reach PH/SH/BF16 register, broadcast, SAE/length-alias, and
reserved controls.
The `rex2_rdseed_r16d.hex` regression seed independently locks the APX REX2
entropy route and its specific RDSEED group classification.
Thirteen single-encoding `evex_avx512vbmi_*` seeds independently reach byte
permutes, multishift/broadcast, APX addressing, and invalid controls. Five
`evex_avx512bw_*` seeds reach all three allocated word permutes plus U0 and
B4/U0 APX addressing. Five ACE_1 seeds additionally reach all four
`TILEMOVROW`/`TILEMOVCOL` GPR32/IMM8 forms and the reviewed APX B4 route.
Eleven ACE TOP2/TOP4 seeds and eleven legacy RAO-INT seeds cover those exact
post-12.0 families and their malformed boundaries. Five APX-F RAO-INT seeds
add all four operations, both widths and U states, EGPR/SIB and disp8 paths,
and reserved controls. Fifteen additional seeds cover fixed VEX `BSRINIT`,
every EVEX `BSRMOVF`/`BSRMOVH`/`BSRMOVL` direction and malformed state
control, plus the legacy, VEX-imm32, and APX-F register/imm32
`URDMSR`/`UWRMSR` routes. Two further seeds preserve the APX map-4
USER_MSR/ENQCMD collision and U=0/X4 address-index boundary. Nineteen
`x86_keylocker_*.hex` seeds reach every Key Locker form, REX/prefix and
memory/register splits, reserved controls, and the AES-NI collision. Twelve
`x86_hreset_*.hex`, six `x86_cldemote_*.hex`, ten `x86_clzero_*.hex`, ten
`x86_pconfig_*.hex`, and ten `x86_monitorx_*`/`x86_mwaitx_*`/`x86_mcommit_*`
seeds cover that exact system-form tranche, its
prefix/profile/REX2 gates, shared-opcode collisions, malformed neighbors, and
truncation. Eight legacy ENQCMD seeds additionally cover both operations,
ignored size controls, REX/address extension, rightmost selector choice, the
legacy USER_MSR collision, LOCK rejection, and truncation. Fifteen additional
MSRLIST/MSR_IMM/WRMSRNS seeds cover the fixed F2/F3/NP `0F 01 C6` row, VEX/APX
immediate forms, R16/R31, reserved W1/register/P2 controls, REX2 payloads,
prefix selection, and truncation. Eight PBNDKB/PREFETCHIT seeds add the fixed
`0F 01 C7` legacy/REX2 routes, the complete `0F 18` prefetch/NOP collision
row, RIP-relative promotion, profile/address-size fallback, invalid LOCK and
prefix controls, APX transport, and truncation. The x86 harness locks their
exact runtime bits, groups, form IDs, operands, flags, and REX2 ownership.
Five `x86_rdpru_*.hex` seeds cover the exact fixed `0F 01 FD` RDPRU form,
ignored legacy prefixes, LOCK rejection, REX2/APX admission, and a truncated
REX2 payload. They accompany 12 RDPRU corpus rows. Fourteen new
prefetch-family seeds cover the 20 PREFETCHRST2/PREFETCHWT1 corpus rows: the
original eleven reach their memory forms, profile and ordinary NOP fallbacks,
ignored prefixes, LOCK rejection, REX2/APX paths, register ownership, and
truncation; three review-driven seeds additionally pin the REX2
PREFETCHWT1-register NOP and REX2 PREFETCH/PREFETCHW memory routes.
Seventeen `x86_ptwrite_*.hex` seeds cover both exact PTWRITE forms 2438--2439,
dword/qword register and memory sources, rightmost-F3 selection, any-66 and
LOCK rejection, unprefixed XSAVE collision, truncation, REX.B/REX.R, and
REX2 B/B4/X/X4 extension with ignored R/R4 opcode-field bits. The matching
35 corpus rows add all modes, profile/runtime gates, formatting, address and
segment overrides, and malformed REX2 controls. The x86 invariant independently
requires one read GPRy/MEMy operand, the PTWRITE group/bit, exact form identity,
and APX-F only on REX2 routes.
Five `x86_movnti_*.hex` seeds reach the exact SSE2 dword form, REX qword/SIB
addressing, REX2 EGPR transport, an invalid mandatory prefix, and truncated
addressing. They accompany 24 corpus rows for forms 1692--1693. The x86
invariant requires a write-only memory destination, read-only GPR source,
SSE2 selection, and an additional APX gate on REX2 routes.
Twenty-five `x86_ntstore_*.hex` seeds reach every legacy, VEX, and EVEX
`MOVNTDQ`/`MOVNTPD`/`MOVNTPS` form, the legacy `MOVNTQ`/`MOVNTSD`/`MOVNTSS`
mandatory-prefix collisions, REX2 EGPR and EVEX B4/U0 APX addressing, reserved
controls, and truncation. The x86 invariant requires a write-only memory
destination and read-only MMX/XMM/YMM/ZMM source with exact form, width, and
family groups; SSE/SSE2/MMX/SSE4a, AVX, and width-specific AVX512F selection
remain distinct, with APX additionally required only by the promoted address
encodings.
Twelve `x86_movntdqa_*.hex` seeds reach legacy SSE4, VEX XMM/YMM, EVEX
XMM/YMM/ZMM, REX/SIB, VEX WIG, APX B4/X4, compressed disp8, reserved controls,
and truncation for exact forms 1690 and 5864--5868. The invariant requires a
write-only vector destination, equal-width read-only memory source, no mask or
broadcast, exact SSE4/AVX/AVX2/AVX512F width selection, and APX only for
promoted EVEX addresses. Focused ModRM sweeps cover 1,536 allocated memory
controls and 512 register-reserved controls, with complete VEX/EVEX control,
profile, collision, formatter, truncation, and extras-OFF checks.
Fourteen `x86_*lddqu*.hex` seeds reach exact `LDDQU` form 1574 and `VLDDQU`
forms 5583--5584: legacy SSE3, ignored `66`, REX/SIB, the independently
APX-gated REX2 map-1 route, VEX.128/256, WIG, raw `vvvv=1111`, register-ModRM
rejection, and truncation. The invariant requires a write-only XMM/YMM
destination and equal-width read-only memory source, exact SSE3 versus AVX
selection, and the extra APX gate only for REX2. The matching 23 corpus rows
also cover all modes, profile/runtime admission, Intel/AT&T formatting,
malformed prefixes/controls, EVEX non-allocation, and extras-OFF ownership.
Twenty-five `x86_vmovq*.hex` seeds reach all 13 exact VMOVQ forms across VEX
and EVEX, GPR/XMM/memory directions, extended-register and APX-address routes,
W0/non-long VMOVD collisions, reserved controls, and truncation. Their
invariant re-derives form selection and fixes operand widths/access plus exact
AVX versus AVX512F-128/AVX10.1 family admission. The matching 50 corpus rows
add all modes, Knights Mill, compressed disp8, profile/runtime, formatter,
collision-profile precedence, and extras-OFF boundaries. Compiled pinned-XED
classifiers agree on the 18,432
VEX and 61,440 EVEX VMOVQ allocations and their VMOVD/U0 neighbors.
Twenty-five `x86_vmovrs*.hex` seeds reach exact `VMOVRSB/D/Q/W` forms
5897--5908 at all three vector widths, mask merge/zero, full-width memory,
16/32/64-byte disp8 scaling, B4/X4 APX address promotion, register-ModRM and
reserved-EVEX rejection, and truncation boundaries. The invariant fixes the
memory-read/vector-write schema, merge-destination read access, exact AVX10
MOVRS width groups and runtime bits, mask state, and the independent APX gate.
The matching 38 corpus rows add profile admission, canonical Intel/AT&T text,
malformed controls, and extras-OFF ownership. The focused suite exhausts all
2,211,840 allocated encodings, 184,320 per form.
Twenty-nine `x86_vmovsd_*.hex` seeds reach all seven exact VMOVSD forms
5909--5915: four VEX load/store/register-direction forms and three EVEX forms.
They cover mask merge/zero, LL/W behavior, vector extensions, non-long ignored
fields, scalar disp8, APX B4/X4 routes, every reserved control, collisions, and
truncation precedence. The invariant fixes XMM/m64 access and NDS ordering,
merge-destination read/write access, exact AVX versus AVX512F-scalar admission,
mask state, and APX isolation. The matching 34 corpus rows add profiles,
runtime selection, both syntaxes, malformed neighbors, and extras-OFF behavior;
the focused suite exhausts 7,721,472 allocated encodings.
Forty `x86_vmovsh*.hex`, `x86_vmovshdup*.hex`, `x86_vmovsldup*.hex`, and
shared-control `x86_vmovdup*.hex` seeds reach all 23 exact forms 5916--5938.
They cover VEX/EVEX, 128/256/512-bit duplicate widths, register/full-memory
sources, scalar-half store/load/register directions, merge/zero masks,
two- and 16/32/64-byte compressed disp8, APX B4/X4, reserved controls,
non-long extension rules, delegated legacy/mandatory-prefix neighbors, and
truncation. The invariant locks operand sizes/access, form selection, exact
AVX, width-specific AVX512F, and AVX512-FP16 scalar gates, plus independent
APX admission. The matching 69 corpus rows add profiles, runtime selection,
both syntaxes, malformed controls, and extras-OFF behavior. The focused suite
exhausts 9,092,608 allocated encodings, 3,337 target-owned invalid controls,
and 2,308 delegated collision-selector cells. Pinned XED agrees on all 42
valid and 18 reserved-control corpus witnesses.
Twenty-nine `x86_vmovss_*.hex` seeds reach all seven exact VMOVSS forms
5939--5945: four VEX load/store/register-direction forms and three EVEX forms.
They cover PF3/W0 selection, masks, LL-ignore, extended registers, non-long
ignored fields, dword memory, four-byte compressed disp8, APX B4/X4 routes,
reserved controls, legacy/neighbor collisions, and truncation precedence. The
invariant fixes XMM/m32 access and NDS ordering, merge-destination read/write
access, exact AVX versus `AVX512F_SCALAR` admission, mask state, and APX
isolation. The matching 34 corpus rows add all modes, profiles, runtime
selection, both syntaxes, malformed controls, and extras-OFF behavior; the
focused suite exhausts 7,721,472 allocated encodings.
Twenty-eight `x86_vmovupd_*.hex`/`x86_vmovups_*.hex` seeds reach all 34 exact
packed unaligned-move forms 5946--5979. They cover both opcode directions,
VEX XMM/YMM and EVEX XMM/YMM/ZMM, register/full-memory operands, merge/zero
masks, store-zeroing rejection, 16/32/64-byte Full-tuple disp8, APX B4/X4,
reserved controls, delegated legacy/scalar collisions, and truncation. The
invariant locks exact form/access, AVX/AVX512F/AVX10 and APX admission, mask
state, and displacement scaling. The matching 63 corpus rows add all modes,
profiles, both syntaxes, formatter and extras-OFF boundaries; focused sweeps
cover 2,425,856 allocated, 3,190 reserved, and 1,544 delegated selector cells.
Twenty `x86_vmovw_*.hex` seeds reach all seven exact forms 5980--5986 and both
opcode directions of shared register form 5986. They cover GPR32/XMM, m16/XMM,
and XMM/XMM shapes, WIG `66` versus F3/W0 selection, WIG W1, Tuple2 disp8,
APX B4/X4, high and non-long registers, reserved P1/P2 controls, map-neighbor
delegation, and truncation. The invariant locks two-operand access, exact
`AVX512_FP16_128N` versus `AVX512_MOVZXC_128` runtime/profile admission,
independent APX gating, and no-mask/no-decorator state. The matching 38 corpus
rows add both syntaxes and extras-OFF ownership; focused sweeps cover 98,304
allocated encodings and 3,046 target-owned reserved controls.
Twenty-five `x86_vmpsadbw*.hex` seeds reach all ten exact forms 5987--5996.
They cover VEX XMM/YMM and EVEX XMM/YMM/ZMM, register and Full-tuple memory
sources, all imm8 values, merge/zero masks, 16/32/64-byte disp8, APX B4/X4,
high and non-long registers, reserved prefix/decorator controls, legacy
`MPSADBW` and `VDBPSADBW` collisions, and truncation. The matching 51 corpus
rows add all modes, profiles, runtime selection, both syntaxes, and extras-OFF
ownership. Focused representative-immediate sweeps cover 196,608 VEX and
829,440 canonical EVEX control/ModRM cells, with separate complete imm8 and
factored P1/P2 checks against pinned XED.
Twenty-seven `x86_virtualization_*.hex` seeds reach exact forms 5997--6005
and 6048--6053, REX2 high-register/address routes, ignored and reserved
prefixes, VMCLEAR/EXTRQ/INSERTQ collision ownership, profile rejection, and
truncation. The invariant locks pointer, VMREAD/VMWRITE, and fixed-form
operands; the VMX/SVM umbrellas and exact VTX group/bit 267; status-flag and
privilege metadata; address-sized VMRUN; VMXOFF/VMXON NOTSX ownership;
independent APX-F admission; and exact formatting. The matching 64 corpus
rows add all modes, both syntaxes, and extras-OFF ownership. Focused sweeps
cover 1,536 legacy and 65,536 REX2 VMREAD/VMWRITE mode/ModRM tuples, 3,584
REX2 pointer/fixed tuples, and 33,536 VMXOFF classifier cells against pinned
XED.
Twenty-three `x86_vmulbf16*.hex` seeds reach exact forms 6006--6011 at all
three widths, register, Full-memory, BF16-broadcast, mask, disp8, high-register,
APX B4/U0/X4, reserved-control, neighbor-collision, and truncation paths. The
invariant locks width-specific form/group/runtime identity, operand access,
broadcast and displacement scaling, APX ownership, and the full ModRM/P1/P2
partitions. The matching 37 corpus rows add profiles, both syntaxes, and
extras-OFF ownership.
Forty-two `x86_vmulph*.hex`/`x86_vmulsh*.hex`/`x86_vmul_fp16*.hex` seeds
reach exact `VMULPH` forms 6022--6027 and `VMULSH` forms 6042--6043. They
cover EVEX MAP5/opcode-59 pp0/ppF3 W0 U1, XMM/YMM/ZMM packed and XMM scalar
sources, merge/zero masks, Full and Tuple2 memory, FP16 broadcasts,
16/32/64- and two-byte disp8, all embedded-rounding modes, high registers,
APX B4/U0/X4, reserved controls, VMULBF16 and PF2 collisions, and truncation.
The invariant locks the exact `AVX512_FP16_128/256/512/SCALAR` groups
197/199/200/204 and runtime bits 145/147/148/152, operand access, tuple and
decorator semantics, APX ownership, and control-space partitions. The matching
59 corpus rows add profiles, both syntaxes, and extras-OFF ownership.
Forty `x86_vmul{pd,ps,sd,ss}_*.hex`/`x86_vmul_fp_*.hex` seeds reach all 28
exact classic `VMULPD`/`VMULPS`/`VMULSD`/`VMULSS` forms 6012--6021,
6028--6041, and 6044--6047. VEX paths use AVX for XMM/YMM packed forms and XMM
scalar forms; EVEX paths use AVX512F/AVX10.1 for XMM/YMM/ZMM packed forms and
XMM scalar forms, with the exact `AVX512F_128/256/512/SCALAR` width groups and
runtime bits 128/130/131/133. They cover merge/zero masks, packed broadcasts,
Full/scalar tuples and compressed disp8, ER/SAE, APX B4/U0/X4, legal prefixes,
reserved controls, neighbor collisions, and truncation. Arrow Lake remains a
negative named profile. Knights Mill rejects the AVX512VL-dependent XMM/YMM
forms while admitting ZMM and scalar forms. The matching 59 corpus rows add all
modes, profiles/runtime selection, both syntaxes, and extras-OFF ownership;
focused tests and pinned XED cover all 28 IFORMs.
Twenty-eight `x86_vorpd_*.hex`/`x86_vorps_*.hex`/`x86_vor_fp_*.hex` seeds
reach all twenty `VORPD`/`VORPS` forms 6054--6073. They cover VEX XMM/YMM and
EVEX XMM/YMM/ZMM register/memory forms, masks, broadcast, Full-tuple disp8,
high registers, APX B4/U0/X4, non-long ignored extensions, reserved register
`EVEX.b`, collisions, and truncation. The matching 52 corpus rows add exact
AVX versus AVX512DQ/AVX10.1 profile/runtime gates, both syntaxes, and
extras-OFF ownership; bounded tests classify 9,216 VEX allocations, 8,064
ordinary EVEX allocations, and 4,224 ordinary EVEX reserved controls.
Twenty-one `x86_vp2intersect*.hex` seeds reach all twelve exact forms
6074--6085, odd/even ModRM.reg aliases, XMM/YMM/ZMM register and memory
sources, broadcast, Full-tuple disp8, high registers, APX addressing,
reserved EVEX controls, profile boundaries, and truncation. The matching 29
corpus rows cover both syntaxes and extras-OFF ownership. The invariant locks
the two structured K-register writes and `kN+1` text while classifying all
786,432 controls as 8,064 allocated and 778,368 reserved.
Sixty `x86_vpabs*.hex` seeds reach every exact `VPABSB/D/Q/W` form
6088--6123 in the non-linear pinned-XED order. They cover all VEX/EVEX widths,
register and memory sources, mask merge/zero, dword/qword broadcast, Full and
scalar disp8, high registers, non-long extension aliases, APX B4/U0/X4
addresses, feature/profile gates, malformed controls, collisions, and
truncation. The matching 82 corpus rows add both syntaxes and extras-OFF
ownership. The invariant and focused suite classify 9,216 allocated plus
580,608 reserved VEX controls and 259,200 allocated plus 527,232 reserved
EVEX controls against pinned XED.
Sixty `x86_vpack*.hex` seeds reach all 40 exact `VPACKSSDW/SSWB/USDW/USWB`
forms 6124--6163. They cover VEX XMM/YMM and EVEX XMM/YMM/ZMM register and
memory sources, merge/zero masks, Full-tuple disp8, dword-source broadcast,
high registers, APX addressing, feature/profile routes, reserved controls,
collisions, and truncation. The matching 80 corpus rows add both syntaxes,
formatter-schema rejection, and extras-OFF ownership. The invariant and
focused suite classify 196,608 allocated plus 589,824 reserved VEX cells and
40,320 allocated plus 746,112 reserved EVEX cells against pinned XED; LLVM 21
agrees on representative forms.
Sixteen `x86_vpblend*.hex` seeds reach all eight exact `VPBLENDD` forms
6306--6309 and `VPBLENDW` forms 6338--6341. They cover XMM/YMM, register and
memory third sources, all four operand access records, address formation,
W=0 versus WIG, AVX/AVX2 gates, prefix and collision ownership, and
truncation. The matching 30 corpus rows add both syntaxes, formatter-schema
rejection, profile/runtime boundaries, and extras-OFF ownership. The focused
VEX.0F3A.66 NDS-plus-imm8 classifier exhausts 294,912 allocated and 1,277,952
reserved controls against pinned XED and LLVM 21.
Eighteen `x86_vpblendvb_*.hex` seeds reach exact `VPBLENDVB` forms
6334--6337: the L=0 XMM memory/register pair and L=1 YMM memory/register pair.
They cover every selector-
nibble boundary, high registers and SIB/RIP-relative addresses, non-long
aliases and C4/LES collisions, address/segment overrides, reserved W/pp/
legacy-prefix controls, and truncation before SIB or selector completion. The
result invariant requires four equal-width vector operands, AVX for XMM and
AVX2 for YMM, `SE_IMM8` metadata in `encoding.selector_offset` with no
immediate operand, exact form identity, profile-missing-feature rejection as
invalid, and missing-runtime-bit rejection as unsupported. The focused
classifier exhausts 98,304 allocated and 688,128 reserved controls and
all 1,536 mode/L/selector combinations; 34 corpus rows retain both syntaxes,
formatter-schema rejection, status precedence, and extras-OFF ownership.
Pinned XED masks non-long B, high `vvvv`, and the selector high bit into the
eight-register namespace; LLVM 21 and Capstone instead expose an impossible
high selector register for that spelling.
Thirty-six `x86_vpbroadcast{b,w}_*.hex` seeds reach exact VEX
`VPBROADCASTB`/`VPBROADCASTW` forms 6342/6343/6347/6348 and
6387/6388/6392/6393. They cover XMM/YMM destinations, XMM-register and
byte/word-memory sources, high registers and SIB/RIP-relative addresses, all modes,
the non-long B' alias and LES collisions, address/segment overrides, reserved
W/pp/`vvvv` and legacy prefixes, EVEX sibling isolation, and late truncation.
The result invariant locks write/read access, byte/word-sized
sources without decorator metadata, AVX+AVX2 groups, most-specific AVX2 runtime
admission, all 53 profiles, both syntaxes, and extras-OFF ownership. The
focused suite exhausts 12,288 allocated and 1,560,576 reserved controls across
both opcode rows; 62 corpus rows and pinned XED data/kit plus XED/LLVM 21
samples retain the same boundaries.
Thirty-six `x86_vpbroadcast{d,q}_*.hex` seeds reach exact VEX
`VPBROADCASTD`/`VPBROADCASTQ` forms 6355/6356/6360/6361 and
6374/6375/6379/6380. They extend the invariant to dword/qword sources while
retaining all mode, address, prefix, AVX2, formatter, late-truncation, and
extras-OFF checks. The focused suite classifies 12,288 allocated and 1,560,576
reserved controls; 62 corpus rows and XED/LLVM 21 retain the same boundaries.
Sixteen `x86_vpcmpeqq_*.hex` seeds reach exact VEX `VPCMPEQQ` forms
6454--6457. They cover both vector lengths and source shapes, W=0/1 aliases,
high registers and addresses, every mode, non-long aliases, address/segment
overrides, reserved pp and legacy-prefix controls, EVEX sibling isolation,
and truncation. The invariant locks write/read/read operands, exact form
identity, AVX for XMM and AVX2 for YMM, both syntaxes, formatter-schema
rejection, and extras-OFF ownership. The focused suite exhausts 196,608
allocated and 589,824 reserved controls; 30 corpus rows and XED/LLVM 21 retain
the same boundary.
Sixteen `x86_vblend*.hex` seeds reach exact VEX `VBLENDPD` forms 3527--3530
and `VBLENDPS` forms 3531--3534. They cover XMM/YMM register and memory
sources, W aliases, high registers and addresses, all modes, non-long C4/LES
and B-extension behavior, address/segment overrides, all reserved pp values,
legacy prefixes, and truncation. The invariant locks four-operand access,
AVX-only CPU/runtime admission at both widths, exact form identity, Intel and
AT&T text, formatter-schema rejection, and extras-OFF ownership. The focused
suite exhausts 393,216 allocated and 1,179,648 reserved controls; 32 corpus
rows retain the boundary against pinned XED and LLVM 21.
Twenty-three `x86_vblendv*.hex` seeds reach exact VEX `VBLENDVPD` forms
3535--3538 and `VBLENDVPS` forms 3539--3542. They cover XMM/YMM register and
memory sources, selector-nibble endpoints, high registers and addresses, all
modes, non-long C4/LES and B-extension aliases, address overrides, reserved
pp/W/prefix controls, and truncation. The invariant locks four vector operands,
selector-offset with no immediate metadata, AVX-only admission at both widths,
exact form identity, both syntaxes, formatter-schema rejection, and extras-OFF
ownership. The focused suite exhausts 196,608 allocated and 1,376,256 reserved
controls; 38 corpus rows retain the boundary against pinned XED and LLVM 21.
Eighteen `x86_vbroadcast128*.hex` seeds reach exact VEX
`VBROADCASTF128` form 3543 and `VBROADCASTI128` form 3554. They cover the
memory-only `VEX.256.66.0F38.W0 1A/5A /r` leaves, encoded-vvvv, L/W/pp and
ModRM reservations, every mode, non-long C4/LES and B-extension aliases,
addressing, truncation, independent AVX/AVX2 gates, both syntaxes, forged
schemas, and extras-OFF ownership. The focused suite classifies 4,608 of its
1,572,864 controls as allocated and 1,568,256 as reserved; 39 corpus rows
retain the boundary against pinned XED and LLVM 21.
Eighteen `x86_vbroadcast{sd,ss,scalar}*.hex` seeds reach all six exact VEX
`VBROADCASTSD`/`VBROADCASTSS` forms 3569--3570/3573--3574/3579--3580. They
cover scalar memory and full-XMM register sources, XMM/YMM destinations, every
mode, high registers and addresses, non-long aliases, reserved L/W/pp/`vvvv`
and legacy-prefix controls, and complete-payload truncation. The invariant
locks exact operand access, AVX/AVX2 gates, both syntaxes, forged-schema
rejection, and extras-OFF ownership. The focused suite partitions 1,572,864
controls into 9,216 allocated and 1,563,648 reserved; 41 corpus rows retain
the boundary against pinned XED and LLVM 21.
Fourteen `x86_{vextract,vinsert,lane}128_*.hex` seeds reach exact VEX
`VEXTRACTF128`/`VEXTRACTI128` forms 4539--4540/4553--4554 and
`VINSERTF128`/`VINSERTI128` forms 5551--5552/5565--5566. They cover both
extract destinations, both insert source positions, memory and register
forms, high registers and addresses, every mode, non-long aliases, reserved
`vvvv`/L/W/pp and legacy-prefix controls, EVEX-neighbor separation, and
truncation. The invariant locks exact operand access, VEX-only ownership,
AVX versus AVX2 admission, both syntaxes, forged-schema rejection, and
extras-OFF ownership. The focused `cdisasm_x86_lane_insert_extract_tests`
suite partitions 3,145,728 controls into 104,448 allocated and 3,041,280
reserved; 23 corpus rows retain the pinned-XED and LLVM 21 boundary.
Fifteen `x86_{vextractps,vinsertps,ps_lane}_*.hex` seeds reach the four exact
VEX forms 4567/4569/5579--5580, register and memory shapes, both W values,
non-long B/`vvvv` aliases, reserved L/pp/`vvvv` and legacy-prefix controls,
high-register EVEX siblings, and late truncation. The invariant and focused
suite lock exact write/read operands, AVX admission, VEX-only form identity,
both syntaxes, formatter forgery rejection, and extras-OFF ownership while
partitioning 1,572,864 controls into 104,448 allocated and 1,468,416 reserved;
24 corpus rows retain the pinned-XED and LLVM 21 boundary.
Fifteen `x86_vperm2*.hex` seeds reach exact VEX `VPERM2F128` forms
6770--6771 and `VPERM2I128` forms 6772--6773, register and m256 shapes, all
16 NDS `vvvv` sources, every mode, non-long register aliases, reserved W/L/pp
and legacy-prefix controls, absence of an EVEX sibling, and late truncation.
The invariant and focused suite lock exact four-operand access, AVX versus
AVX2 admission, VEX-only identity, both syntaxes, formatter forgery rejection,
and extras-OFF ownership while partitioning 1,572,864 controls into 98,304
allocated and 1,474,560 reserved; 23 corpus rows retain the pinned-XED and
LLVM 21 boundary.
Fifteen `x86_vpermd*.hex`/`x86_vpermps*.hex` seeds reach exact VEX
`VPERMD`/`VPERMPS` forms 6780--6781/6886--6887, register and m256 sources,
all modes, non-long aliases, address/segment overrides, reserved W/L/pp,
wrong-map and legacy-prefix controls, an EVEX sibling, and late address
truncation. The invariant and focused suite lock exact three-operand access,
AVX2 admission, both syntaxes, independent VEX/EVEX form ownership, formatter
forgery rejection, and extras-OFF ownership while partitioning 1,572,864
controls into 98,304 allocated and 1,474,560 reserved; 25 corpus rows retain
the pinned-XED and LLVM 21 boundary.
Fifteen `x86_vpermpd*.hex`/`x86_vpermq*.hex` seeds reach exact classic-VEX
`VPERMPD` forms 6878--6879 and `VPERMQ` forms 6890--6891, register and m256
sources, immediate selectors, all modes, non-long B aliases, address/segment
overrides, reserved W/L/pp/`vvvv`, an EVEX sibling, and late payload
truncation. The invariant and focused suite lock exact three-operand access,
AVX2 admission, both syntaxes, independent VEX/EVEX form ownership, complete
formatter-schema rejection, and extras-OFF ownership while partitioning
1,572,864 controls into 6,144 allocated and 1,566,720 reserved; 26 corpus
rows retain the pinned-XED and LLVM 21 boundary.
Twenty-six `x86_vpermil*.hex` seeds reach exact classic-VEX `VPERMILPD`
forms 6834--6837/6846--6849 and `VPERMILPS` forms
6854--6857/6866--6869. They cover XMM/YMM immediate- and variable-control
register/memory forms, profile and prefix boundaries, formatting, collisions,
and truncation. The focused suite exhaustively partitions 208,896 allocated
and 2,936,832 reserved controls; 36 corpus rows retain the pinned-XED and
LLVM 21 boundary.
ASan+UBSan extras-ON/OFF cells replay all 2,395 x86 source seeds as 2,396
executions and complete 6,000-run campaigns without a finding.
Twenty-six `x86_vround*.hex` seeds reach exact classic-VEX `VROUNDPD`/`VROUNDPS`/
`VROUNDSD`/`VROUNDSS` forms 8539--8550. They cover packed and scalar
register/memory forms, non-long aliases, reserved VEX controls, sibling
collisions, and complete-payload truncation.
Twenty-four `x86_vshuf*.hex` seeds reach exact classic-VEX `VSHUFPD`/`VSHUFPS`
forms 8664--8665/8670--8671 and 8674--8675/8680--8681. They cover VEX2/VEX3,
XMM/YMM register and memory sources, NDS `vvvv`, W aliases, every mode,
non-long aliases, addressing, pp/prefix reservations, same-name EVEX siblings,
and complete-payload truncation. The invariant and focused suite lock exact
operand access, AVX admission, both syntaxes, formatter-schema rejection, and
extras-OFF ownership across 393,216 allocated and 393,216 reserved VEX3
controls; 36 corpus rows retain the pinned-XED and LLVM 21 boundary.
Twenty-one `x86_vtest*.hex` seeds reach exact classic-VEX `VTESTPD`/`VTESTPS`
forms 8795--8802. They cover XMM/YMM register and memory sources, high
registers and SIB addressing, every mode, non-long extension aliases, reserved
W/pp/`vvvv` and legacy-prefix controls, map-3 siblings, and payload-first
truncation. The invariant and focused suite lock two read operands, generic
status-flags write metadata, AVX admission, both syntaxes, formatter-schema
rejection, and extras-OFF ownership across 12,288 allocated and 1,560,576
reserved VEX3 controls; 31 corpus rows retain the pinned-XED and LLVM 21
boundary.
Fifteen `x86_vptest*.hex` seeds reach all four exact classic-VEX `VPTEST`
forms 8319--8322. They cover XMM/YMM register and memory sources, W aliases,
high registers and SIB addressing, every mode, non-long B aliases, reserved
pp/`vvvv` and legacy-prefix controls, legacy `PTEST`, `VTESTPD`, map-3
`VEXTRACTPS`, EVEX siblings, and payload-first truncation. The invariant and
focused suite lock two read operands, generic status-flags write metadata, AVX
admission at both widths, both syntaxes, formatter-schema rejection, and
extras-OFF ownership across 12,288 allocated and 774,144 reserved VEX3
controls; 25 corpus rows retain the pinned-XED and LLVM 21 boundary.
Fourteen `x86_vpmovmskb*.hex` seeds reach both exact classic-VEX
`VPMOVMSKB` forms 7334--7335. They cover VEX2/VEX3, XMM/YMM sources, high
registers, every mode, non-long aliases, WIG controls, reserved pp/`vvvv`,
memory ModRM, legacy and EVEX siblings, and payload-first truncation. The
invariant and focused suite lock a GPR32 write plus vector read, AVX admission
for XMM and AVX2 for YMM, both syntaxes, formatter-schema rejection, and
extras-OFF ownership across 3,584 allocated encodings. The long-mode C5
parent contains 256 allocated and 65,280 reserved cells; C4 contains 2,048
allocated and 522,240 reserved cells. Twenty-five corpus rows retain the
pinned-XED and LLVM 21 boundary.
Twenty `x86_vpsign*.hex` seeds reach all 12 exact classic-VEX
`VPSIGNB`/`VPSIGND`/`VPSIGNW` forms 7921--7932 and independent legacy
`PSIGNB/W/D` starting paths. They cover XMM/YMM register and memory forms,
NDS `vvvv`, WIG, high registers, every mode, non-long aliases, reserved pp,
unowned EVEX/VEX2 neighbors, addressing, and payload-first truncation. The
invariant and focused suite lock write/read/read operands, AVX admission for
XMM and AVX2 for YMM, both syntaxes, formatter-schema rejection, and
extras-OFF ownership. The C4 classifier exhausts 2,359,296 controls as
589,824 allocated and 1,769,472 reserved, with 73,728 hits per memory form
and 24,576 per register form; 32 corpus rows retain the pinned-XED and LLVM 21
boundary.
Twenty-six `x86_vpshuf*.hex` seeds reach all 12 exact classic-VEX
`VPSHUFD`/`VPSHUFHW`/`VPSHUFLW` forms
7891--7892/7895--7896, 7901--7902/7905--7906, and
7911--7912/7915--7916. They cover C4/C5, XMM/YMM register and memory forms,
all three mandatory prefixes, WIG, high registers and SIB addressing,
non-long aliases, reserved pp/`vvvv`, separate legacy and EVEX siblings, and
payload-first truncation. The invariant and focused suite lock destination
write plus source/imm8 reads, AVX admission for XMM and AVX2 for YMM, both
syntaxes, formatter-schema rejection, and extras-OFF ownership. The all-mode
C4/C5 classifier exhausts 884,736 controls as 43,008 allocated and 841,728
reserved, with 5,376 hits per memory form and 1,792 per register form; 42
corpus rows retain the pinned-XED and LLVM 21 boundary.
Twenty `x86_vucomi*.hex` seeds reach exact classic-VEX `VUCOMISD`/
`VUCOMISS` forms 8803--8804/8809--8810. They cover register and scalar-memory
sources, high registers and SIB addressing, every mode, non-long aliases,
W/L aliases, reserved pp/`vvvv` and legacy-prefix controls, legacy `UCOMI*`,
same-name EVEX and `VUCOMISH` siblings, and payload-first truncation. The
invariant and focused suite lock two read operands, generic status-flags write
metadata, AVX admission, both syntaxes, formatter-schema rejection, and
extras-OFF ownership across 24,576 allocated and 761,856 reserved VEX3
controls; 32 corpus rows retain the pinned-XED and LLVM 21 boundary.
Twenty `x86_vcomi*.hex` seeds reach exact classic-VEX `VCOMISD`/`VCOMISS`
forms 3629--3630/3633--3634 at map-1 opcode `2F`; pp=66/none selects SD/SS,
encoded `vvvv=1111` is NOVSR, and W/L are ignored. They cover register and
scalar-memory sources,
high registers and SIB addressing, every mode, non-long aliases, WIG/LIG,
reserved pp/NOVSR and legacy-prefix controls, legacy `COMI*`, same-name EVEX
and `VCOMISH` siblings, and payload-first truncation. The invariant and
focused suite lock two read operands, generic status-flags write metadata, AVX
admission, both syntaxes, formatter-schema rejection, and extras-OFF ownership
across 24,576 allocated and 761,856 reserved VEX3 controls; 32 corpus rows
retain the pinned-XED and LLVM 21 boundary.
Twenty-one `x86_vdpp*.hex` seeds reach exact classic-VEX `VDPPD` forms
4507--4508 and `VDPPS` forms 4515--4518 at map-3 mandatory-66 opcodes `41`
and `40`. They cover XMM/YMM register and memory paths, every imm8 and W
alias, all modes, non-long B-prime/`vvvv` aliases, long-mode high registers
and addressing, reserved controls, legacy `DPP*` siblings, and payload-first
truncation. The invariant and focused suite lock destination write plus both
source and immediate reads, exact form identities, AVX admission, both
syntaxes, formatter-schema rejection, profile/runtime gates, and extras-OFF
ownership across 294,912 allocated and 1,277,952 reserved C4 controls plus
196,608 C5 collision/exclusion probes; 39 corpus rows retain the pinned-XED
and LLVM 21 boundary.
Twenty `x86_vcmp*.hex` seeds reach exact classic-VEX `VCMPPD` forms
3595--3598, `VCMPPS` forms 3611--3614, `VCMPSD` forms 3617--3618, and
`VCMPSS` forms 3623--3624 at map-1 opcode `C2 /r ib`. They cover packed and
scalar register/memory paths, every imm8 predicate and high-bit alias, WIG,
packed L and scalar LIG, all modes, non-long B-prime/`vvvv` aliases, long-mode
high registers, addressing, AVX/MXCSR metadata, legacy/EVEX siblings, and
payload-first truncation. The invariant and focused suite lock destination
write plus both source and immediate reads, exact widths and form identities,
both syntaxes, formatter-schema rejection, profile/runtime gates, and
extras-OFF ownership while exhausting all 884,736 C4/C5 controls; 42 corpus
rows retain the pinned-XED and LLVM 21 boundary.
Twenty-four `x86_vunpck*.hex` seeds reach exact classic-VEX `VUNPCKHPD`/
`VUNPCKHPS`/`VUNPCKLPD`/`VUNPCKLPS` forms 8825--8862. They cover VEX2/VEX3,
XMM/YMM register and memory sources, NDS `vvvv`, high registers and SIB
addressing, every mode, non-long aliases, WIG controls, reserved pp and
legacy-prefix controls, legacy and EVEX siblings, and payload-first
truncation. The invariant and focused suite lock write/read/read operands,
AVX admission, both syntaxes, formatter-schema rejection, and extras-OFF
ownership while exhaustively partitioning the VEX3 envelope into 786,432
allocated and 786,432 reserved controls and the VEX2 envelope into 98,304
allocated and 98,304 reserved controls; 56 corpus rows retain the pinned-XED
and LLVM 21 boundary.
Forty `x86_vpunpck*.hex` seeds reach all 32 exact classic-VEX
`VPUNPCKHBW/HWD/HDQ/HQDQ/LBW/LWD/LDQ/LQDQ` forms. They include one witness
per form plus C4 WIG, high NDS/register/address, non-long alias, reserved-pp,
EVEX-sibling, and truncated-address paths. The invariant, focused suite, and
69 corpus rows lock write/read/read operands, exact register mapping, AVX XMM
versus AVX2 YMM admission, both syntaxes, sibling isolation, payload-first
status precedence, and extras-OFF ownership. The C4 partition is 1,572,864
allocated plus 4,718,592 reserved; C5 is 196,608 allocated plus 589,824
reserved. Pinned XED and LLVM 21 agree.
Thirty-seven `x86_vphadd*.hex`, `x86_vphsub*.hex`, and
`x86_horizontal_*.hex` seeds reach all 24 exact classic-VEX horizontal
integer `VPHADDD`/`VPHADDSW`/`VPHADDW`/`VPHSUBD`/`VPHSUBSW`/`VPHSUBW`
forms 7012--7019/7036--7039/7046--7053/7056--7059. They cover XMM/YMM
register and memory forms, NDS `vvvv`, WIG, high registers and SIB addressing,
all modes and non-long aliases, reserved pp, legacy `PHADD*`/`PHSUB*` and XOP
siblings, and payload-first truncation. The invariant, focused suite, and 49
corpus rows lock exact write/read/read operands, AVX XMM versus AVX2 YMM
admission, both syntaxes, formatter-schema rejection, and extras-OFF
ownership. The all-mode C4 classifier partitions 4,718,592 controls into
1,179,648 allocated and 3,538,944 reserved, with 73,728 hits per memory form
and 24,576 per register form. Pinned XED and LLVM 21 agree.
Seventeen `x86_vphminposuw_*.hex` seeds reach exact classic-VEX
`VPHMINPOSUW` forms 7040--7041. They cover register and memory sources, all
modes, non-long aliases, WIG, high registers and SIB addressing, reserved
pp/L/`vvvv` controls, legacy `PHMINPOSUW`, same-opcode `KANDB`/`KANDW`, the
adjacent EVEX `VPMOVSSDB` route, and payload-first truncation. The invariant,
focused suite, and 35 corpus rows lock destination-write/source-read operands,
AVX admission, both syntaxes, formatter-schema rejection, and extras-OFF
ownership across 6,144 allocated and 780,288 reserved controls. Pinned XED
and LLVM 21 agree.
Twenty-four `x86_{vpinsr,pinsr}*.hex` seeds reach all eight exact classic-VEX
`VPINSRB/D/Q/W` forms 7060--7061/7064--7065/7068--7069/7072--7073. They
cover C4 and C5 spellings, register and m8/m16/m32/m64 sources, every mode,
non-long B/`vvvv`/W aliases, high registers and SIB addressing, WIG, reserved
pp/L and legacy-prefix controls, legacy and all eight EVEX siblings, and
payload-first truncation. The invariant and focused selector/ModRM suite lock
destination-write plus vector/scalar/immediate reads, exact form identity,
AVX admission, both syntaxes, formatter-schema rejection, and extras-OFF
ownership. The C4 partition is 294,912 allocated plus 2,064,384 reserved;
C5 is 12,288 allocated plus 86,016 reserved. Fifty-two corpus rows retain the
pinned-XED and LLVM 21 boundary.
Thirty `x86_{vpextr,pextr}*.hex` seeds reach all nine exact classic-VEX
`VPEXTRB/D/Q/W` forms 6966/6968, 6970/6972, 6974/6976, 6978/6983, and 6979.
They cover C4 and C5 spellings, register and m8/m16/m32/m64 destinations,
every mode, non-long B/W aliases, high registers and SIB addressing, WIG,
reserved pp/L/`vvvv` and legacy-prefix controls, legacy and all same-name EVEX
siblings, and payload-first truncation. The invariant and exhaustive
selector/ModRM suite lock destination-write plus XMM/immediate reads, exact
form identity, AVX admission, both syntaxes, formatter-schema rejection, and
extras-OFF ownership. The C4 partition is 19,968 allocated plus 3,125,760
reserved; C5 is 256 allocated plus 98,048 reserved. Sixty-six corpus rows
retain the pinned-XED and LLVM 21 boundary.
Thirty-six `x86_{vpmovsx,pmovsx}*.hex` seeds reach all 24 exact classic-VEX
`VPMOVSXBW/BD/BQ/WD/WQ/DQ` forms 7419--7420/7425--7426,
7399--7400/7405--7406, 7409--7410/7415--7416,
7439--7440/7445--7446, 7449--7450/7455--7456, and
7429--7430/7435--7436. They cover every XMM/YMM
register and exact narrowed-memory shape, all modes, WIG, non-long B aliases,
high registers and SIB addresses, address/segment prefixes, AVX/AVX2 profile
gates, reserved pp/`vvvv` and legacy-prefix controls, legacy and generated
EVEX siblings, and payload-first truncation. The invariant and exhaustive
all-mode suite lock destination-write/source-read access, exact form identity,
AVX versus AVX2 admission, both syntaxes, formatter-schema rejection, and
extras-OFF ownership. The partition contains 73,728 allocated and 4,644,864
reserved controls; 62 corpus rows retain the pinned-XED and LLVM 21 boundary.
Thirty-six `x86_{vpmovzx,pmovzx}*.hex` seeds reach all 24 exact classic-VEX
`VPMOVZXBW/BD/BQ/WD/WQ/DQ` forms 7524--7525/7530--7531,
7504--7505/7510--7511, 7514--7515/7520--7521,
7544--7545/7550--7551, 7554--7555/7560--7561, and
7534--7535/7540--7541. They cover every XMM/YMM register and exact narrowed
memory shape, all modes, WIG, non-long B aliases, high registers and SIB
addresses, address/segment prefixes, AVX/AVX2 profile gates, reserved
pp/`vvvv` and legacy-prefix controls, legacy, C5, and generated EVEX siblings,
and payload-first truncation. The invariant and exhaustive all-mode suite lock
destination-write/source-read access, exact form identity, AVX versus AVX2
admission, both syntaxes, formatter-schema rejection, and extras-OFF ownership.
The partition contains 73,728 allocated and 4,644,864 reserved controls; 62
corpus rows retain the pinned-XED and LLVM 21 boundary.
Sixteen `x86_vpcmov_*.hex` seeds reach all six exact AMD XOP `VPCMOV` forms
6410--6415. They cover XMM/YMM, W-swapped memory/selector placement, register
W aliases, every selector-nibble boundary, high registers and addresses,
non-long aliases, prefix/pp rejection, and truncation before SIB or selector
completion. The result invariant requires four vector operands, AVX+XOP
groups, selector-offset metadata with no immediate operand, and exact form
collapse. The focused classifier exhausts 393,216 allocated and 1,179,648
reserved controls; 25 corpus rows retain both syntaxes, profile/runtime gates,
formatter-schema rejection, and extras-OFF ownership against pinned XED and
LLVM 21.
Sixteen `x86_vpperm_*.hex` seeds reach exact XMM `VPPERM` forms 7686--7688.
They cover both W-selected memory positions, register-form W collapse, the
high and ignored low selector nibbles, high registers and SIB addresses,
non-long register/address aliases, reserved L/pp/legacy-prefix controls, and
truncation before SIB or selector completion. The result invariant requires
four XMM operands, AVX+XOP groups, `SE_IMM8` metadata in
`encoding.selector_offset` with no immediate operand, exact form identity,
and runtime/profile admission. The focused classifier exhausts 196,608
allocated and 1,376,256 reserved controls; 27 corpus rows retain both
syntaxes, formatter-schema rejection, and extras-OFF ownership against pinned
XED and LLVM 21. Non-long R/X/B, `vvvv`, and selector extensions alias into
the eight-register namespace. This matches LLVM; pinned XED's isolated
32-bit SIB.X exposure of `r12d` is treated as an anomalous result rather than
an escape from that namespace.
Twelve `x86_vmovmsk*.hex` seeds reach exact `VMOVMSKPD` forms 5860--5861 and
`VMOVMSKPS` forms 5862--5863 in pinned-XED order. They cover VEX2/VEX3, both
VLs and W values, long-mode extensions, ignored VEX3.B in 16/32-bit modes,
reserved pp/`vvvv` and memory controls, and truncation. The invariant requires
a GPR32 write, a register-only XMM/YMM read, exact form/width selection, and
AVX. The matching 21 corpus rows add profile/runtime, legacy/REX2, unowned EVEX,
map-2 VNNI, formatter, and extras-OFF boundaries. Focused decoding exhausts
7,168 allocated encodings (1,792 per form); compiled pinned-XED oracles match
589,824 long-mode cells, 262,144 C1/E1 cells in 16/32-bit modes, and 384 LES
boundaries. ASan+UBSan campaigns with extras ON and OFF each replay the full
source corpus and finish 6,000 executions without a finding.
Eight `x86_smap_*.hex` seeds reach fixed `CLAC` and `STAC`, ignored
address/segment and ordinary REX prefixes, REX2/APX transport, invalid `66`,
the F2/F3 `ERETS`/`ERETU` FRED collision, and truncation. They accompany 17
corpus rows for forms 707 and 3158. The x86 invariant requires the exact SMAP
runtime bit and group, CPL0 and AC-write metadata, zero operands, and an
independent APX-F gate only on REX2 routes; the FRED forms remain distinct
generated fallbacks and never acquire SMAP metadata.
The 2,395 reviewed
`.hex` files in `corpus/` are deliberately readable hexadecimal seeds. They
include classic VEX K-mask ALU, shift, and move paths
and the EVEX compare-to-mask boundary, the complete VEX/EVEX packed-MIN/MAX
block, and GFNI in addition to the modern XOP, EVEX, AMX, AVX10, APX, crypto,
saturating arithmetic, and system routes.
The harness recognizes
whitespace-separated hexadecimal input and converts it to bytes; any mutated
input that is not valid hexadecimal is treated as raw bytes. This keeps
reviewed seeds useful without restricting libFuzzer's binary mutations.
The always-available `cdisasm_fuzz_corpus_seed_tests` CTest audits both source
corpora before fuzzing: every entry must be a nonempty `.hex` file containing
only hexadecimal digits and whitespace, must normalize to at most 64 bytes,
and must fit the documented raw-text limit (192 bytes for x86 and 64 for ARM).
This prevents comments or oversized readable seeds from silently taking the
raw-binary fallback path.

`fuzz_arm_decode2.c` independently exercises little- and big-endian A32, T32,
and A64 input for every public ARM CPU ID, including every zero-to-four-byte
input-size boundary. It validates
determinism, failure zeroing, bounded operands/groups, raw encodings, ISA IDs,
relative targets, SIMD vector width/lane metadata, and Apple extension flags.
It passes the public 64-byte ARM flag-set pointer, including null/default and
big-endian word-0 forms. Fuzz-derived nonzero values are placed into reserved
words 1 through 7 one at a time and must be rejected, covering every bitmap
word without conflating ARM bit meanings with the independent x86 namespace.
With `USE_DISASM_FORMAT=ON`, successful results also check
`cdisasm_arm_format` determinism, size-query/write agreement,
truncation/NUL behavior, and rejection of invalid metadata. Five WFxT seeds
cover `WFET X0`, `WFET XZR`, `WFIT X17`, `WFIT XZR`, and a fixed-bit
neighbor. Ten `a64_flagm_*.hex` seeds cover all six FlagM/FlagM2 forms, minimum
and maximum RMIF operands, WZR SETF, reserved RMIF/SETF controls, and the
adjacent generic-MSR selector. The ARM invariant requires exact form/name,
read operands, and NZCV-write metadata. Ten `a64_sve_ffr_*.hex` seeds cover
predicated `RDFFR`/`RDFFRS`, unpredicated `RDFFR`, `WRFFR`, and `SETFFR`
forms 2562--2564/2617--2618, including maximum predicate registers and one
reserved control in each parent envelope. They accompany 16 corpus rows. The
focused family exhausts all 545 allocated encodings and all 611 reserved
controls, and the invariant locks typed predicate access, governing `/z`
metadata, SVE/profile admission, scalable/predicated flags, and the
RDFFRS-only NZCV write. The ARM harness's 1,533 reviewed readable seeds cover
A32, T32, A64 NEON, and Apple proprietary paths and live
in `arm_corpus/`.
Thirty-four fixed-width SHA1/SHA256 seeds cover all A32/T32/A64 leaves and
their transport/reserved boundaries. Twenty fixed A64 crypto seeds cover
SHA3/SHA512/SM3/SM4 forms 6287--6303 and their same-name SVE collision paths;
the invariant pins exact operands, feature gates, and write-only `SM4EKEY`.
Twenty `a64_sve_element_count_*.hex` seeds reach all 18 non-saturating
element-count forms 2374--2391: vector `INCH/W/D` and `DECH/W/D`, plus GPR
`CNTB/H/W/D`, `INCB/H/W/D`, and `DECB/H/W/D`, with allocated and reserved
parent controls. Their invariant preserves the raw pattern and multiplier as
separate read immediates, exact destination access and element typing,
scalable-vector metadata, and the alternative FEAT_SVE-or-FEAT_SME gate.
Twenty base saturating/predicate-count seeds reach the 62 forms 2362--2373,
2392--2423, 2597, and 2600--2616: representative Z/W/X/tied-X-W saturating
counts, classic and PN-counter `CNTP`, predicate increments/decrements, and
reserved controls. Their invariants fix form/name identity, destination and
typed-predicate access, raw pattern/multiplier immediates, `SCALABLE_VECTOR`,
classic-CNTP `PREDICATED`, and SVE-or-SME versus SVE2.1-or-SME2 admission.
The focused suite exhausts 787,456 allocated family words and 359,424 reserved
words. Six additional `a64_sve_firstp_*.hex`/`a64_sve_lastp_*.hex` seeds
reach both exact forms 2598--2599, B/H/S/D typing, ordinary X registers and
XZR. Their invariant locks write-only `Xd`, read-only untyped `Pg`, read-only
typed `Pn`, exact `SCALABLE_VECTOR | PREDICATED` flags, and SVE2.2-or-SME2.2
admission. The dedicated suite exhausts all 65,536 `FIRSTP`/`LASTP`
allocations, 32,768 classic-`CNTP` siblings, and 163,840 reserved operation
controls; 12 corpus rows add profile, endian, formatting, truncation, and
extras-OFF boundaries.

Six `a64_sve_cterm*.hex` seeds reach exact `CTERMEQ`/`CTERMNE` forms
2593--2594 with W/X and WZR/XZR sources, plus the reserved `op=0` parent and
an adjacent low-bit control. The invariant re-derives mask `0xffa0fc1f` and
values `0x25a02000`/`0x25a02010`, then fixes both read operands and exact
`SCALABLE_VECTOR | SETS_FLAGS` metadata. The focused suite exhausts 4,096
allocated and 4,096 reserved words and verifies SVE-or-SME admission,
endian/generic transport, formatting, truncation, forgery rejection, and
extras-OFF ownership; 16 corpus rows preserve the same boundaries. LLVM 21
and fresh 6,000-run ASan+UBSan campaigns in both extras configurations agree.

Fourteen `a64_sve_brk*.hex`/`a64_sve_predicate_break_*.hex` seeds reach all
ten predicate-break forms 2546--2555, zeroing and allocated merging controls,
the tied BRKN source, all five flag-setting variants, and both reserved parent
classes. The raw-word invariant re-derives exact form identity and fixes byte
predicate typing, operand counts/access, governing mode, scalable/predicated/
NZCV metadata, and SVE-or-SME admission. The focused suite exhausts 294,912
allocated and 270,336 reserved words; 23 corpus rows add profile, endian,
formatting, truncation, adjacency, and extras-OFF boundaries.

Fifteen reviewed predicate-control `.hex` seeds reach `PTEST`, `PFIRST`,
`PNEXT`, ordinary `PTRUE`, `PTRUES`, and `PFALSE` forms 2556--2561. They cover
typed and untyped predicates, tied destination reads, all element sizes,
named/numeric/default patterns, exact flag combinations, and every reserved
parent class. The raw-word invariant locks operands/access, SVE-or-SME gates,
endian transport, formatting, truncation, and extras-OFF ownership. The
focused suite exhausts 5,648 allocated and 16,944 reserved words; 33 corpus
rows preserve the same boundaries.

Fifteen `a64_sve2p1_psel_*.hex` seeds reach every B/H/S/D lane boundary,
W12--W15, high predicate registers, both `tsz=0000` residuals, the bit-4
neighbor, big-endian transport, and truncation. The invariant locks exact form
2565, `Pd, Pn, Pm.T[Wv, lane]`, write/read/read access, scalable-only metadata,
and the SVE2.1-or-baseline-SME alternative. The focused suite exhausts
491,520 allocated words, 32,768 invalid residual words, and 524,288 delegated
neighbor words; 18 corpus rows retain profile, endian, formatter, and extras-OFF
boundaries. LLVM 21 agrees on all 30 legal `i1:tsz` controls.

Twenty-two `a64_sve_integer_immediate_*.hex` seeds reach all arithmetic forms
2619--2630 and representative reserved parent controls. Fifteen additional
`a64_sve_dup_immediate_*.hex`/`a64_sve_fdup_immediate_*.hex` seeds reach exact
forms 2631--2632, preferred `MOV`/`FMOV`, signed and shifted integer imm8,
expanded H/S/D floating imm8, reserved byte controls, endian transport, and
truncation. The combined parent invariant classifies all 2,097,152 words. The
dedicated broadcast suite exhausts 57,344 allocated and 8,192 reserved DUP
words plus 24,576 allocated and 8,192 reserved FDUP words; 44 corpus rows and
2,560 LLVM 21 representative cases preserve the same boundaries.

Twelve `a64_sve_dot_*.hex`/`a64_sve2p3_dot_*.hex` seeds reach exact
`SDOT`/`UDOT` forms 2633--2636, every B-to-S, H-to-D, and B-to-H arrangement,
high registers, named-profile rejection, both reserved `size=00` controls,
big-endian transport, and truncation. The invariant locks tied read/write
accumulator access, read-only sources, scalable-only metadata, and baseline
SVE-or-SME versus SVE2p3-or-SME2p3 admission. The matching 19 corpus rows add
formatting and extras-OFF ownership; the focused suite exhausts 196,608
allocated and 65,536 reserved parent words. LLVM 21 confirms the baseline
forms, while pinned AARCHMRS supplies the p3 oracle.

Seventeen `a64_sve_{sqdmlalbt,sqdmlslbt,cdot,cmla,sqrdcmlah}*.hex` seeds
reach exact forms 2637--2641, every legal arrangement and rotation, both byte
orders, reserved widths, adjacent delegation, and truncation. The invariant
locks tied accumulator access, read-only sources, scalable-only metadata, and
exact SVE2-or-SME admission. The matching 31 corpus rows add formatting,
profile, transport, and extras-OFF ownership; the focused suite exhausts
1,507,328 allocated and 327,680 reserved words, and LLVM 21 confirms all 46
legal arrangement/rotation combinations.

Eighteen reviewed widening/rounding-high multiply-add seeds reach exact forms
2642--2655: `SMLALB`, `SMLSLB`, `SMLALT`, `SMLSLT`, `UMLALB`, `UMLSLB`,
`UMLALT`, `UMLSLT`, `SQDMLALB`, `SQDMLSLB`, `SQDMLALT`, `SQDMLSLT`,
`SQRDMLAH`, and `SQRDMLSH`. They cover H/S/D widening from B/H/S, same-width
B/H/S/D rounding-high operations, high registers, reserved `size=00`, both
byte orders, profile rejection, adjacency, and truncation. The invariant locks
tied read/write accumulator access, read-only Zn/Zm, scalable-only metadata,
and exact SVE2-or-SME admission. The matching 32 corpus rows add formatting,
transport, profile, and extras-OFF ownership; the focused suite exhausts
1,441,792 allocated and 393,216 reserved words.

Fifteen reviewed `a64_sve_{mla,mls}_indexed*.hex` seeds reach exact indexed
SVE2-or-SME `MLA`/`MLS` forms 2722--2727 across H/S/D widths, low/high lanes,
the width-dependent Zm restrictions, truncation, and the adjacent indexed
rounding boundary. The invariant locks destructive read/write `Zda`, read-only
`Zn` and `Zm.T[lane]`, scalable-only metadata, exact form identity, and
SVE2-or-SME admission. The focused suite exhausts all 262,144 allocated words
with no internal reserved controls; 22 corpus rows add Apple A18/M4 positive
routes, A64FX/Cortex-A53 rejection, endian/generic transport, formatting, and
extras-OFF ownership. LLVM 21 confirms all twelve low/high boundary encodings.

Fifteen total `a64_sve_sqrdml{ah,sh}_indexed*.hex` family seeds reach exact
indexed SVE2-or-SME `SQRDMLAH`/`SQRDMLSH` forms 2728--2733 across H/S/D,
low/high lanes, each width-dependent Zm restriction, truncation, and the
adjacent indexed `USDOT` boundary. H uses mask `0xffa0fc00` and values
`0x44201000`/`0x44201400`; S/D use mask `0xffe0fc00` and values
`0x44a01000`/`0x44a01400` or `0x44e01000`/`0x44e01400`. H and S restrict Zm
to Z0--Z7 with lanes 0--7 or 0--3; D permits Zm0--Zm15 with lanes 0--1. The
invariant locks destructive read/write `Zda`, read-only `Zn` and
`Zm.T[lane]`, scalable-only metadata, exact form
identity, and SVE2-or-SME admission. The focused suite exhausts all 262,144
allocated words with no internal reserved controls; 20 corpus rows add profile,
endian/generic transport, formatting, and extras-OFF ownership. LLVM 21 and
pinned AARCHMRS confirm the six masks and boundary encodings.

Three `a64_sve_usdot_*.hex` seeds reach exact `USDOT` form 2656, low/high
register boundaries, and a reserved size control. Its leaf mask/value is
`0xffe0fc00`/`0x44807800` inside parent mask/value
`0xff20fc00`/`0x44007800`: exactly 32,768 `size=10` words are allocated and
98,304 sibling words are reserved. The invariant locks `Zda.S` read/write and
`Zn.B`/`Zm.B` read-only operands, scalable-vector metadata, and exact
`(SVE or SME) and I8MM` admission. `CPU_ANY` is positive while every current
named profile is negative. The matching 11 corpus rows add profile, endian,
formatting, truncation, and extras-OFF ownership; LLVM 21 confirms the concrete
encodings and pinned AARCHMRS supplies the exact leaf.

Eight `a64_sve_{u,s}dot_indexed_*.hex` seeds reach low, mixed, and high indexed
`USDOT`/`SUDOT` forms 2734--2735 plus truncation.
The result invariant locks tied `Zda.S`, read-only `Zn.B` and
`Zm.B[lane]`, scalable-only metadata, and exact SVE-or-SME-plus-I8MM
admission. The focused suite exhausts all 65,536 words, checks all 38 named
profiles plus endian/generic transport and formatter forgery rejection, and
LLVM 21 matches both entire leaves. Eighteen corpus rows retain the same boundaries.
Six `a64_sve_aes*.hex` seeds cover `AESMC`/`AESIMC`, low/high tied `Zdn.B`,
reserved size space, and truncation. The invariant and focused suite exhaust
64 allocated and 192 reserved words, enforce two explicit read/write operands,
FEAT_SVE_AES, formatting, and extras-OFF ownership; 13 corpus rows retain the
same contracts.
Nine `a64_sve_{aese,aesd,sm4e,crypto_binary}*.hex` seeds cover all three
SVE crypto-binary forms, low/high registers, reserved selector/size controls,
and truncation. The invariant and focused suite lock forms 2905--2907, tied
read/write `Zdn`, read-only `Zm`, `.B`/`.S` typing, independent SVE_AES and
SVE_SM4 gates, and the 3,072 allocated/13,312 reserved partition; 19 corpus
rows retain profile, endian, formatter, and extras-OFF behavior.
Four `a64_sve_predicate_unpack_*.hex` seeds reach `PUNPKLO`, `PUNPKHI`, a
high-register allocation, and truncation. The invariant and focused suite
exhaust forms 2468--2469 as two fully allocated 256-word leaves and lock
`Pd.H` write, `Pn.B` read, scalable-vector-only metadata, SVE-or-SME
admission, endian/generic transport, canonical formatting, forged-schema
rejection, and extras-OFF ownership. Twelve corpus rows retain the boundary;
LLVM 21 matches every word under both SVE and SME.
Nine `a64_sve_{sunpk*,uunpk*,unpack_*}.hex` seeds reach exact SVE/SME
`SUNPKLO`/`SUNPKHI`/`UUNPKLO`/`UUNPKHI` forms 2456--2459, all three widening
sizes, low/high registers, both reserved `size=00` controls, and truncation.
The invariant and `cdisasm_arm_sve_unpack_tests` suite lock write-only `Zd.T`,
a read-only `Zn` at half that element width, scalable-vector-only metadata,
SVE-or-SME profiles, endian/generic transport, canonical formatting and
forged-schema rejection,
and extras-OFF ownership across 12,288 allocated and 4,096 reserved words.
Twenty-two corpus rows retain the boundary; LLVM 21 matches every allocated
formula word and reports every reserved word unknown.
Ten `a64_sve_{sri,sli,shift_insert}*.hex` seeds reach exact SVE2/SME `SRI`
and `SLI` forms 2846--2847, every B/H/S/D immediate band and endpoint,
low/high registers, encoded-immediate reservations, both byte orders, and
truncation. The invariant and `cdisasm_arm_sve_shift_insert_tests` suite lock
tied read/write `Zdn.T`, read-only `Zn.T`, the decoded read immediate,
scalable-vector-only metadata, SVE2-or-SME admission, canonical formatting and
forged-schema rejection, and extras-OFF ownership across 245,760 allocated and
16,384 reserved words. Twenty-one corpus rows retain the complete LLVM 21-
verified domain.
Seven `a64_advsimd_{bsl,bit,bif,bitwise}*.hex` seeds reach exact Advanced
SIMD `BSL`/`BIT`/`BIF` forms 6188/6196/6198. The invariant and
`cdisasm_arm_advsimd_bitwise_select_tests` suite lock the three
`0xbfe0fc00` leaves, Q-selected 8B/16B arrangements, tied Vd plus Vn/Vm reads,
NEON admission, adjacent logical-family isolation, endian/generic transport,
formatting, truncation, and extras-OFF ownership across 196,608 allocated
words. Eighteen corpus rows retain the LLVM 21-verified boundary.
Eleven `a64_advsimd_{addhn,subhn,raddhn,rsubhn,high_narrow}*.hex` seeds reach
exact Advanced SIMD `ADDHN`/`SUBHN`/`RADDHN`/`RSUBHN` forms
6093/6095/6108/6110. They cover base and `2` spellings, B/H/S destination
widths, low/high registers, both byte orders, the reserved `size=3` quarter,
profile rejection, adjacent-family controls, and truncation. The invariant
locks two full-width read sources, Q-selected write-only versus tied
read/write destination access, exact FEAT_AdvSIMD/NEON admission, formatting,
and extras-OFF ownership. The focused `cdisasm_arm_advsimd_high_narrow_tests`
suite partitions 1,048,576 words into 786,432 allocated and 262,144 reserved;
22 corpus rows retain the AARCHMRS and LLVM 21 boundary.
Thirteen `a64_advsimd_*` widening add/sub seeds reach all eight exact Advanced
SIMD widening add/sub
forms 6089--6092/6104--6107, base and `2` spellings, every B/H/S-to-H/S/D
arrangement, low/high registers, both byte orders, the reserved `size=3`
quarter, fixed neighbors, and truncation. The invariant and focused suite lock
write/read/read long-versus-wide operand widths, NEON admission, canonical
formatting with independent raw/form/name ownership, forged-schema rejection,
and extras-OFF ownership across 1,572,864 allocated and 524,288 reserved
words; 34 corpus rows retain the pinned-AARCHMRS and LLVM 21 boundary.
Eight Advanced SIMD absolute-difference-long seeds reach exact
`SABAL`/`SABDL`/`UABAL`/`UABDL` forms 6094/6096/6109/6111, base and `2`
spellings, every B/H/S-to-H/S/D arrangement, low/high registers, both byte
orders, the reserved size-three quarter, fixed neighbors, and truncation. The
invariant and focused suite lock read/write accumulators versus write-only
long differences, NEON admission, canonical formatting with independent raw/
form/name ownership and exact SVE sibling separation, forged-schema rejection,
and extras-OFF ownership across 786,432 allocated and 262,144 reserved words;
22 corpus rows retain the pinned-AARCHMRS and LLVM 21 boundary.
Ten `a64_advsimd_{smlal,smlsl,smull,umlal,umlsl,umull,widening_multiply}*.hex`
seeds reach exact Advanced SIMD `SMLAL`/`SMLSL`/`SMULL` forms
6097/6099/6101 and `UMLAL`/`UMLSL`/`UMULL` forms 6112--6114. They cover
base and `2` spellings, every B/H/S-to-H/S/D arrangement, low/high
registers, the reserved size-three quarter, fixed neighbors, and truncation.
The invariant and focused suite lock read/write multiply-add/subtract-long
destinations versus write-only multiply-long destinations, two read-only
narrow inputs, NEON admission, canonical formatting with exact legacy,
scalar-alias, and SME collision separation, and extras-OFF ownership across
1,179,648 allocated and 393,216 reserved words; 28 corpus rows retain the
pinned-AARCHMRS and LLVM 21 boundary.
Eight `a64_advsimd_{sqdmlal,sqdmlsl,sqdmull,saturating_widening_multiply}*.hex`
seeds reach exact Advanced SIMD `SQDMLAL`/`SQDMLSL`/`SQDMULL` forms
6098/6100/6102. They cover base and `2` spellings, H-to-S and S-to-D
arrangements, both reserved byte and size-three partitions, sibling
collisions, and truncation. The invariant and focused suite exhaustively
classify 393,216 allocated and 393,216 reserved words; 22 corpus rows retain
NEON admission, transport, formatting, and pinned-AARCHMRS/LLVM 21 ownership.
Eight `a64_advsimd_{sqdmulh,sqrdmulh,saturating_mulh}*.hex` seeds reach exact
Advanced SIMD `SQDMULH`/`SQRDMULH` forms 6136/6178. They cover every H/S
arrangement at both Q-selected vector widths, reserved byte/doubleword size
partitions, scalar/by-element/SVE/SME siblings, and truncation.
Eight `a64_advsimd_pmull*.hex` seeds reach exact Advanced SIMD `PMULL`/`PMULL2`
form 6103. They cover byte-to-halfword and D-to-Q arrangements, both Q-selected
source widths, sizes one and two as reserved controls, the independent
FEAT_PMULL gate, sibling isolation, endian transport, and truncation. The
invariant and focused suite lock the 16-byte destination, 8- or 16-byte source
reads, canonical formatting, conservative named-profile behavior, and
extras-OFF ownership across 131,072 allocated and 131,072 reserved words;
20 corpus rows retain the pinned-AARCHMRS and LLVM 21 boundary.
Eight `a64_advsimd_pmul*.hex` seeds reach exact baseline Advanced SIMD `PMUL`
form 6175. They cover Q-selected 8B/16B arrangements, zero and maximum
registers, all three reserved size partitions, fixed-vector/SVE sibling
isolation, endian transport, and truncation. The invariant and focused suite
lock the Vd write plus Vn/Vm reads, SIMD-only metadata, Advanced SIMD/NEON
admission, canonical formatting, and extras-OFF ownership across 65,536
allocated and 196,608 reserved words; 18 corpus rows retain the pinned-
AARCHMRS and LLVM 21 boundary.
Eight `a64_advsimd_pairwise_*.hex` seeds reach exact fixed-vector `SMAXP`/
`SMINP`/`UMAXP`/`UMINP` forms 6134/6135/6176/6177. They cover every B/H/S
arrangement at both Q-selected widths, high registers, the reserved
doubleword-size partition, same-name SVE siblings, endian transport, and
truncation. The invariant and focused suite lock Vd write plus Vn/Vm reads,
SIMD-only metadata, Advanced SIMD/NEON admission, canonical formatting,
forged-schema rejection, and extras-OFF ownership across 786,432 allocated
and 262,144 reserved words; 42 corpus rows retain the pinned-AARCHMRS and
LLVM 21 boundary.
Ten `a64_advsimd_addp*.hex` seeds reach exact Advanced SIMD scalar/vector
`ADDP` forms 5808/6137. They cover scalar register extremes, all legal
8B/16B, 4H/8H, 2S/4S, and 2D arrangements, the reserved Q=0 size=3 cell,
high registers, profiles, endian transport, sibling separation, and
truncation. The invariant and focused suite lock scalar `Dd` write plus
`Vn.2D` read, vector Vd write plus Vn/Vm reads, canonical formatting,
formatter forgery rejection, baseline Advanced SIMD admission, and extras-OFF
ownership across all 1,024 scalar allocations and 229,376 allocated plus
32,768 reserved vector words; 16 corpus rows retain the pinned-AARCHMRS and
LLVM 21 boundary.
Ten `a64_advsimd_addv*.hex` seeds reach exact Advanced SIMD `ADDV` form 6077
at mask/value `0xbf3ffc00`/`0x0e31b800`. They cover all five allocated
B/H/S vector-to-scalar arrangements, all three reserved Q:size cells, high
registers, profiles, endian transport, sibling separation, and truncation.
The invariant and focused suite lock the scalar destination write, vector
source read, SIMD-only metadata, canonical formatting, formatter forgery
rejection, baseline Advanced SIMD admission, and extras-OFF ownership across
5,120 allocated and 3,072 reserved words; 13 corpus rows retain the pinned-
AARCHMRS and LLVM 21 boundary.
Eight `a64_advsimd_minmax*.hex` seeds reach exact fixed-vector `SMAX`/`SMIN`/
`UMAX`/`UMIN` forms 6126/6127/6168/6169. They cover every B/H/S arrangement
at both Q-selected widths, high registers, the reserved doubleword-size
partition, same-name SVE/SME2/CSSC siblings, endian transport, and truncation.
The invariant and focused suite lock Vd write plus Vn/Vm reads, SIMD-only
metadata, Advanced SIMD/NEON admission, canonical formatting, forged-schema
rejection, and extras-OFF ownership across 786,432 allocated and 262,144
reserved words; 42 corpus rows retain the pinned-AARCHMRS and LLVM 21
boundary.
Nine `a64_advsimd_compare*.hex` seeds reach exact fixed-vector register
`CMGT`/`CMGE`/`CMHI`/`CMHS`/`CMEQ` forms 6120/6121/6162/6163/6173. They
cover every mnemonic and legal arrangement, high registers, the reserved
Q=0 1D arrangement, scalar and compare-with-zero siblings, big-endian
transport, and truncation. The invariant and focused suite lock the Vd write
plus Vn/Vm reads, SIMD-only metadata, baseline Advanced SIMD/NEON admission,
canonical formatting, forged-schema rejection, and extras-OFF ownership
across 1,146,880 allocated and 163,840 reserved words; 57 corpus rows retain
the pinned-AARCHMRS and LLVM 21 boundary.
Eight `a64_advsimd_cmtst*.hex` seeds reach exact scalar and fixed-vector
`CMTST` forms 5831/6131. They cover the scalar D-register form, every legal
vector B/H/S/D arrangement, high registers, reserved Q=0 1D, adjacent `CMEQ`
and compare-with-zero siblings, big-endian transport, and truncation. The
invariant and focused suite lock destination-write plus two source-read
operands, SIMD-only metadata, baseline Advanced SIMD/NEON admission, canonical
scalar/vector formatting, raw/form/name forgery rejection, and extras-OFF
ownership across 262,144 allocated and 32,768 reserved words; 18 corpus rows
retain the pinned-AARCHMRS and LLVM 21 boundary.
Thirty-four `a64_advsimd_variable_shift*.hex` seeds reach exact scalar and
fixed-vector `SSHL`/`USHL` forms 5826/5841/6122/6164. Every intended scalar,
vector-arrangement, high-register, reserved-Q0-1D, big-endian, and saturating
or rounding-shift sibling word is a distinct starting input; the truncation
path is separate too. The invariant and focused suite lock destination-write
plus two source-read operands, SIMD-only metadata, baseline Advanced
SIMD/NEON admission, canonical scalar/vector formatting, raw/form/name
forgery rejection, and extras-OFF ownership. The exact classifier partitions
589,824 words into 524,288 allocated and 65,536 reserved; 27 corpus rows
retain the pinned-AARCHMRS and LLVM 21 boundary.
Thirty seeds—24 `a64_advsimd_{saba,uaba}_*.hex`, four
`a64_advsimd_aba_sibling_*.hex`, and two
`a64_sve_{saba,uaba}_sibling.hex`—reach exact fixed-vector `SABA`/`UABA` forms
6129/6171 and their fixed, widening, and generated SVE siblings as distinct
starting inputs. They cover all legal B/H/S arrangements at both Q widths, low
and high registers, every size=3 reserved form, both byte orders, and
truncation. The invariant and focused suite lock Vd read/write plus Vn/Vm
reads, SIMD-only metadata, baseline Advanced SIMD/NEON admission, canonical
formatting, raw/form/name forgery rejection, and extras-OFF ownership. The
classifier partitions all 524,288 parent words into 393,216 allocated and
131,072 reserved; 23 corpus rows retain the pinned-AARCHMRS and LLVM 21
boundary.
Twenty-four `a64_advsimd_{sabd,uabd}_*.hex` seeds reach exact fixed-vector
`SABD`/`UABD` forms 6128/6170. They cover every B/H/S arrangement at both Q
widths, low and high registers, both size=3 reserved controls, both byte
orders, and truncation. The invariant and focused suite lock Vd write plus
Vn/Vm reads, SIMD-only metadata, baseline Advanced SIMD/NEON admission,
canonical formatting, raw/form/name forgery rejection, distinct accumulating,
widening, and SVE siblings, and extras-OFF ownership. The classifier
partitions all 524,288 words into 393,216 allocated and 131,072 reserved; 23
corpus rows retain the pinned-AARCHMRS and LLVM 21 boundary.
Forty-one Advanced SIMD multiply-accumulate and sibling seeds reach exact
fixed-vector `MLA`/`MLS` forms 6132/6174. They cover every B/H/S arrangement
at both Q widths, low and high registers, both size=3 reserved controls, both
byte orders, truncation, adjacent fixed-vector leaves, and independently
owned A32/T32, predicated SVE, indexed-SVE, and by-element same-name forms.
The invariant and focused suite lock Vd read/write plus Vn/Vm reads,
SIMD-only metadata, baseline Advanced SIMD/NEON admission, canonical
formatting, raw/form/name forgery rejection, and extras-OFF ownership. The
classifier partitions all 524,288 words into 393,216 allocated and 131,072
reserved; 34 corpus rows retain the pinned-AARCHMRS and LLVM 21 boundary.
Fourteen `a64_advsimd_{mla,mls}_element_*.hex` seeds reach exact by-element
`MLA`/`MLS` forms 6268/6270. They cover H/S arrangements at both Q widths,
the halfword V15/lane-7 and word V31/lane-3 boundaries, both byte orders,
all byte/doubleword reserved quarters, truncation, fixed-vector/A32/T32/SVE
same-name siblings, and adjacent `UMLAL`/`UMLSL` leaves. The invariant and
focused suite lock Vd read/write, typed Vn and indexed Vm reads, SIMD-only
metadata, baseline Advanced SIMD/NEON admission, canonical formatting,
raw/form/name forgery rejection, and extras-OFF ownership. The exhaustive
classifier partitions 2,097,152 words into 1,048,576 allocated and 1,048,576
reserved, with 262,144 in each class per operation/Q partition; 25 corpus
rows retain the pinned-AARCHMRS and LLVM 21 boundary.
Thirty-two `a64_advsimd_*_element_*.hex` seeds reach the complete widening
by-element `SMLAL`/`SQDMLAL`/`SMLSL`/`SQDMLSL`/`SMULL`/`SQDMULL`/`UMLAL`/
`UMLSL`/`UMULL` block, forms 6243--6246/6248--6249/6269/6271--6272. They
cover H-to-S and S-to-D, base/`2` source-half selection, the V15/lane-7 and
V31/lane-3 indexed-source boundaries, both byte orders, reserved element
sizes, truncation, and adjacent non-widening/multiply/dot-product siblings.
The invariant and exhaustive suite lock a 128-bit read/write accumulator or
write-only multiply-long result as appropriate, typed Vn and indexed Vm reads,
SIMD+NEON metadata, baseline Advanced SIMD admission, canonical formatting,
raw/form/name/access forgery rejection, and extras-OFF ownership. The unified
classifier partitions 9,437,184 controls into 4,718,592 allocated and
4,718,592 reserved; 75 corpus rows retain the pinned-AARCHMRS and LLVM 21
boundary.
Eight `a64_advsimd_compare_zero_*.hex` seeds reach the exact scalar and
fixed-vector signed compare-with-zero `CMLT`/`CMLE` forms
5777/5794/6013/6045. They cover scalar D registers, every legal vector B/H/S/D
arrangement, high registers, explicit `#0`, reserved Q=0 1D, neighboring
register and compare-with-zero leaves, both byte orders, and truncation. The
invariant and focused suite lock destination-write plus source-read access,
SIMD-only metadata, baseline Advanced SIMD/NEON admission, canonical scalar
and vector formatting, raw/form/name forgery rejection, and extras-OFF
ownership across 16,384 allocated and 2,048 reserved words. Twenty-seven
corpus rows retain the pinned-AARCHMRS and LLVM 21 boundary.
Eight `a64_sve_{bext,bdep,bgrp,bitperm}*.hex` seeds reach all three exact SVE
BitPerm forms 2829--2831, every B/H/S/D width, the reserved selector quarter,
and truncation. The invariant and `cdisasm_arm_sve_bitperm_tests` suite lock
write/read/read typed Z operands, scalable-vector-only metadata, exact
FEAT_SVE_BitPerm admission, endian/generic transport, canonical formatting,
forged-schema rejection, and extras-OFF ownership across 393,216 allocated
and 131,072 reserved words. Twenty-four corpus rows retain the complete pinned
AARCHMRS and LLVM 21 boundary.
Eleven `a64_pauth_*.hex` seeds reach all eight authenticated register-branch
forms 4510/4511/4513/4514/4525--4528, XZR targets, SP modifiers, allocated and
reserved parent controls, both byte orders, RETAA/RETAB neighbors, and
truncation. The invariant and focused suite lock JUMP versus CALL+LINK,
pointer-authentication metadata, exact PAuth admission, canonical formatting
with raw/form/name forgery rejection, and extras-OFF ownership across 4,224
allocated and 3,968 reserved words; 23 corpus rows retain the pinned-AARCHMRS
and LLVM 21 boundary.
ASan+UBSan extras-ON/OFF cells replay all 1,533 ARM files as 1,534 executions with
the empty unit and complete 6,000-run campaigns without a finding.

Five `a64_sve_shift_sat_*.hex` seeds reach all twelve exact destructive
merging variable-shift forms 2657--2668: `SRSHL`, `SRSHLR`, `SQSHL`,
`SQRSHL`, `SQSHLR`, `SQRSHLR`, `URSHL`, `URSHLR`, `UQSHL`, `UQRSHL`,
`UQSHLR`, and `UQRSHLR`. Their `0xff3fe000` leaves use selectors 2, 6, 8,
A, C, E and 3, 7, 9, B, D, F inside the `0xff30e000`/`0x44008000` parent;
selectors 0, 1, 4, and 5 are reserved. The invariant locks B/H/S/D element
typing, `Zdn.T` read/write, `Pg/m` and `Zm.T` reads, scalable/predicated
metadata, and SVE2-or-SME admission. Apple A18/M4 admit the forms through SME
while A64FX rejects them. The matching 23 corpus rows add profiles, endian,
formatting, reserved selectors, truncation, and extras-OFF ownership; the
focused suite exhausts all 393,216 allocated and 131,072 reserved parent
words.

Nine `a64_sve_sat_unary_*.hex` seeds reach all eight predicated
`URECPE`/`URSQRTE`/`SQABS`/`SQNEG` forms 2669--2676 plus a reserved estimate
width. The matching 21 corpus rows and exhaustive invariant lock `.S`-only
estimate versus B/H/S/D saturating typing, merge/zero access, SVE2-or-SME
versus SVE2.2-or-SME2.2 admission, endian transport, formatting, truncation,
and extras-OFF ownership across 163,840 allocated and 98,304 reserved words.

Sixteen reviewed accumulating-long/halving seeds reach `SADALP`/`UADALP`
forms 2677--2678 and all eight halving forms 2679--2686. The matching 30
corpus rows cover B-to-H, H-to-S, S-to-D and all same-width B/H/S/D
arrangements, destructive access, destination-granularity predicates,
SVE2-or-SME admission, endian transport, reserved accumulating-long
`size=00`, formatting, truncation, forgery, and extras-OFF ownership. The
focused invariant classifies 49,152 allocated plus 16,384 reserved
accumulating-long words and all 262,144 allocated halving words.

Eight `a64_sve_pairwise_*.hex` seeds reach all six destructive predicated
pairwise forms 2687--2692 and both reserved operation selectors. The matching
19 corpus rows cover B/H/S/D typing, tied destination access, typed `/m`
predicates, SVE2p3-or-SME2p3 `SUBP` versus SVE2-or-SME for the other five,
endian transport, formatting, truncation, forgery, and extras-OFF ownership.
The focused invariant exhausts the parent as 196,608 allocated and 65,536
reserved words. Pinned AARCHMRS validates all six leaves; LLVM 21 matches the
five SVE2 leaves but does not yet accept SVE2p3 `SUBP`.

Eight `a64_sve_pred_sat_*.hex` seeds reach all destructive predicated
`SQADD`/`SQSUB`/`SUQADD`/`USQADD`/`SQSUBR`/`UQADD`/`UQSUB`/`UQSUBR` forms
2693--2700. The matching 15 corpus rows cover B/H/S/D typing, tied read/write
destinations, typed `/m` predicates, read-only sources, exact SVE2-or-SME
admission, profiles, endian transport, formatting, truncation, forgery,
same-name neighbors, and extras-OFF ownership. The focused invariant exhausts
the 262,144-word parent as fully allocated with zero reserved residual; LLVM
21 confirms representative encodings for all eight leaves.

Six `a64_sve_clamp_*.hex` seeds reach exact destructive unpredicated
`SCLAMP`/`UCLAMP` forms 2701--2702 across B/H/S/D widths. The matching 15
corpus rows cover read/write `Zd`, read-only `Zn`/`Zm`, exact
SVE2.1-or-SME admission, profiles, both byte orders, canonical formatting,
forged-schema rejection, fixed neighbors, truncation, and extras-OFF
ownership. The focused invariant exhausts all 262,144 allocated words under
parent `0xff20f800`/`0x4400c000`; pinned AARCHMRS, LLVM 21, and an independent
operand oracle agree.

Seven `a64_sve_pointer_*.hex` seeds reach low/high `MLAPT`, representative and
high-register `MADPT`, two reserved size quarters, and truncation. The matching
15 corpus rows cover exact `.D`-only forms 2707--2708, destructive destination
access, operation-specific source order, the conjunctive SVE+CPA gate, every
named-profile rejection, both byte orders, canonical formatting, fixed
neighbors, and extras-OFF ownership. The focused invariant exhausts parent
`0xff20f400`/`0x4400d000` as 65,536 allocated and 196,608 reserved words;
pinned AARCHMRS and LLVM 21 provide independent encoding evidence.

Twelve `a64_sve_quad_*.hex` seeds reach low/high `ZIPQ1`/`UZPQ1` and
`ZIPQ2`/`UZPQ2`, the three reserved parent controls, and truncation. The four
Q2 files and matching 14 corpus rows complete that subset. Together they
cover exact forms 2711--2712/2714--2715 for all B/H/S/D arrangements, a
write-only `Zd.T` and read-only `Zn.T`/`Zm.T`, the SVE2.1-or-SME2.1 gate,
every named-profile rejection, both byte orders, canonical formatting,
sibling routing, and extras-OFF ownership. The focused invariant exhausts the
complete 1,048,576-word parent as 524,288 Q1/Q2 words, 131,072 allocated
TBLQ sibling words, and 393,216 reserved control-100/101/111
words against pinned AARCHMRS and LLVM 21.

Eight single-predicate WHILE seeds reach all
`WHILEGE/HS/GT/HI/LT/LO/LE/LS` forms 2585--2592 across W/X, B/H/S/D, and
zero-register boundaries. The invariant fixes typed predicate writes, GPR
reads, NZCV/scalable/predicated metadata, and the SVE2-or-SME gate for the
first four relations versus SVE-or-SME for the latter four. The focused suite
exhausts all 1,048,576 allocations; 22 corpus rows cover profiles, endian
transport, formatting, truncation, and extras-OFF ownership.

Eight `a64_sve2p1_while*_pair*.hex` seeds reach all paired-predicate versions,
exact forms 2574--2581. They cover B/H/S/D typed consecutive even/odd pairs,
X/XZR sources, every relation, and the SVE2.1-or-SME2 gate. The dedicated
suite exhausts all 262,144 allocations, 32,768 per form; 22 corpus rows lock
the same metadata, endian, formatter, truncation, and disabled-build contracts.

Eight `a64_sve2p1_while*_pn.hex` seeds reach all counter-predicate
relations in forms 2566--2573. They cover typed `PN8`--`PN15`, X/XZR sources,
both `VLx2`/`VLx4`, every B/H/S/D size, and the exact SVE2.1-or-SME2 gate. The
invariant locks NZCV/scalable/predicated metadata and exhausts all 524,288
allocations, 65,536 per form; 22 corpus rows preserve endian, formatter,
truncation, profile, and extras-OFF contracts.

Eight counter-mask seeds reach `PEXT` forms 2582--2583 and counter-predicate
`PTRUE` form 2584. They cover typed one- and two-predicate PEXT results,
including the `p15, p0` wrap, untyped indexed `PNn[index]` sources, typed PN
PTRUE results, every size and index boundary, and SVE2.1-or-SME2 admission.
The invariant exhausts 2,048 one-result PEXT, 1,024 pair-result PEXT, and 32
PTRUE allocations, 3,104 total, plus 1,024 reserved parent controls; 24 corpus
rows lock metadata, endian,
formatter, truncation, profiles, and disabled-build ownership.

Six `a64_sve_whilewr_*.hex`/`a64_sve_whilerw_*.hex` seeds reach exact forms
2595--2596 at B/H/S/D and ordinary/XZR register boundaries. The raw-word
invariant re-derives the `0xff20fc10` mask and `0x25203000`/`0x25203010`
values, then fixes typed `Pd` write access, Xn/Xm reads, and exact
`SCALABLE_VECTOR | PREDICATED | SETS_FLAGS` metadata. The dedicated suite
exhausts all 131,072 allocated words and verifies SVE2-or-SME admission,
endian/generic transport, formatting, truncation, and extras-OFF ownership;
14 corpus rows preserve the same boundaries. LLVM 21 confirms the encodings
and feature gates, and fresh ASan+UBSan campaigns completed 6,000 ARM runs in
each extras configuration without a finding.

Eleven earlier post-12.0 seeds cover the three SVE2.1-or-SME2 multi-extract narrowing
mnemonics and their reserved bit-5 half, all four SME2 pair `FRINT*` names and
reserved bit controls, and both SME_F16F16 `FCVT`/`FCVTL` selectors.
Twenty-seven `a64_sme2_multi4_*.hex` seeds cover all forms 4341--4362,
aligned-list boundaries, feature/profile admission, and representative
reserved widening/rounding controls.
Six reviewed Advanced SIMD bit-count seeds are
`a64_advsimd_cls.hex`, `a64_advsimd_cls_reserved.hex`,
`a64_advsimd_cnt.hex`, `a64_advsimd_cnt_reserved.hex`,
`a64_advsimd_clz.hex`, and `a64_advsimd_clz_reserved.hex`. They reach one
allocated and one reserved word for each of forms 6007/6008/6041. Eight SME
multiply seeds are `a64_sme_bfmul_2x2.hex`, `a64_sme_fmul_2x2.hex`,
`a64_sme_bfmul_4x4.hex`, `a64_sme_fmul_4x4.hex`,
`a64_sme_bfmul_2x1.hex`, `a64_sme_fmul_2x1.hex`,
`a64_sme_bfmul_4x1.hex`, and `a64_sme_fmul_4x1.hex`; they independently reach
fixed-H BFMUL and H/S/D FMUL across all four list/list and list/scalar forms
4363--4370.
Five baseline-SME ZA load/store seeds are `a64_sme_ldr_za_off0.hex`,
`a64_sme_ldr_za_mul_vl.hex`, `a64_sme_str_za_mul_vl.hex`,
`a64_sme_str_za_boundary.hex`, and `a64_sme_za_fixed_neighbor.hex`. They reach
both forms 4381--4382, zero and nonzero shared ZA/MUL-VL offsets, W12/W15,
X/SP bases, and a one-bit fixed neighbor. The invariant re-derives the exact
`0xffff9c10` leaves and requires runtime-sized memory plus the paired
`HAS_DISPLACEMENT | VL_SCALED` flags only for nonzero coefficients.
Twelve `a64_sme_*za_slice*.hex` seeds reach all ten predicated contiguous
forms 4373--4380/4385--4386, horizontal and vertical views, W/P/base/index
limits, omitted XZR index, every required element-width shift, and a fixed-bit
neighbor. Their invariant re-derives the low-bit tile/offset partition,
reciprocal tile/memory access, load-only `/z`, runtime-sized memory, and exact
SME/matrix/scalable/predicated metadata from the raw word.
Eleven `a64_sme_mova_*.hex` seeds independently reach all ten baseline-SME
predicated ZA-slice insert/extract forms 3862--3866/3877--3881 and the
reserved Q-control boundary. Their invariant checks preferred `MOV` identity,
tile/predicate/Z access, element width, horizontal/vertical selection, exact
SME/matrix/scalable/predicated flags, profile and endian transport, and
formatter-schema rejection.
Twenty-two `a64_sme2_mova_*.hex` seeds cover the SME2 multi-register MOVA
insert/extract family across pair and quad Z-register lists and ZA `VGx2`/
`VGx4` forms, including all B/H/S/D element widths and reserved quad-list
boundaries. They accompany 26 corpus rows covering the exact forms,
profile and endian transport, reserved high-list bits, and truncation.
Seventeen `a64_sme2p1_movaz_*.hex` seeds reach every exact MOVAZ form
3892--3906: single B/H/S/D/Q, aligned pair/quad B/H/S/D, whole-ZA.D VGx2/VGx4,
and the reserved single-Q and quad controls. They accompany 20 corpus rows.
The invariant re-derives the no-predicate, write-only Z/read-only ZA schema,
SME/matrix/scalable flags, FEAT_SME2p1 `CPU_ANY`-only gate, list alignment,
and exact `MOVAZ` identity; Apple A18/M4 must reject because they stop at SME2.
Four SME2 ZT0 load/store seeds are `a64_sme2_ldr_zt0.hex`,
`a64_sme2_str_zt0.hex`, `a64_sme2_zt0_register_reserved.hex`, and
`a64_sme2_zt0_operation_reserved.hex`. They reach both forms 4383--4384,
including SP, plus nonzero-ZT-selector and reserved-operation cells.
Four A64 UDF seeds are `a64_udf_imm0.hex`, `a64_udf_imm1234.hex`,
`a64_udf_immffff.hex`, and `a64_udf_fixed_neighbor.hex`. They reach the
zero, middle, and maximum immediate values of exact form 4387 plus a
one-bit fixed neighbor. The UDF invariant requires a successful
interrupt-group decode with one two-byte read immediate and no instruction
flags; it therefore distinguishes the allocated permanently-undefined
instruction from an invalid encoding.
The A64 seed set includes optional LSE, LOR, and RCpc encodings. The dedicated
`a64_extra_add_shifted.hex`, `a64_extra_carry.hex`,
`a64_extra_conditional_select.hex`, `a64_extra_two_source.hex`,
`a64_extra_multiply_add.hex`, and `a64_extra_shifted_invalid.hex` inputs cover
the five new scalar-register parser routes and a reserved shifted-register form.
`a64_extra_logical_immediate.hex` and
`a64_extra_logical_immediate_invalid.hex` separately reach the logical-bitmask
decoder and its reserved W-form `N` boundary. The
`a64_sve_predicate_logical.hex` and
`a64_sve_predicate_logical_reserved.hex` seeds reach the complete 15-operation
SVE predicate-logical class and its sole unallocated operation slot.
They exercise successful structured decoding when `USE_EXTRA_OPCODES=ON`,
reserved-form rejection, and zeroed failure results when it is `OFF`. Exact OFF
statuses are checked outside the mutation harness by deterministic regression
tests.
The `a64_sve_integer_arithmetic.hex` and
`a64_sve_integer_arithmetic_invalid.hex` seeds reach the completed
unpredicated integer-arithmetic class and an unallocated smaller-width CPA
slot.
The `a64_sve_vector_permute.hex` and
`a64_sve_vector_permute_invalid.hex` seeds reach the completed 24-form SVE
ZIP/UZP/TRN class and one of its eight unallocated selectors.
Six allocated `a64_f64mm_*_q.hex` seeds and two reserved-selector seeds reach
every operation in the disjoint FEAT_F64MM Q-element ZIP/UZP/TRN class and
both invalid selector values.
The six allocated `a64_sve_scvtf_*_to_h.hex` and
`a64_sve_ucvtf_*_to_h.hex` seeds plus two reserved-selector seeds reach every
H/S/D-to-H integer conversion path and both invalid selector values in the
exact SVE/SME class. Eight signed/unsigned S/D-to-S/D conversion seeds reach
every signed and unsigned S-to-S, D-to-S, S-to-D, and D-to-D merging form in
the four new exact SVE/SME envelopes.
Twenty-one `a64_sve_fcvt*` seeds reach all six baseline precision-changing
`FCVT` forms, all seven signed `FCVTZS` and seven unsigned `FCVTZU` forms, plus
the reserved selector control. BFCVT coverage is handled by the separate seeds
below.
The additional `a64_sve2p2_fcvt_s_to_h_zeroing.hex` seed reaches the exact
zeroing `FCVT Zd.H, Pg/z, Zn.S` form and its SVE2.2/SME2.2 admission path.
The seven allocated `a64_sve_b16b16_bf*.hex` seeds plus
`a64_sve_b16b16_reserved.hex` reach every FEAT_SVE_B16B16 destructive
halfword arithmetic/minmax operation and the invalid selector-3 class.
The three `a64_dcps*_imm16.hex` seeds and `a64_dcps_reserved.hex` cover
structured A64 `DCPS1`/`DCPS2`/`DCPS3` immediates and a reserved selector.
The separate `t32_dcps.hex` seed reaches exact no-operand T32
`DCPS1`/`DCPS2`/`DCPS3` forms 1853--1855 and their Armv8 profile boundary.
The `a64_sve_bfcvt*.hex` and `a64_sve2p2_bfcvt*.hex` seeds reach merging and
zeroing `BFCVT` and `BFCVTNT`, their distinct BF16 versus SVE2.2/SME2.2 feature
boundaries, and exact reserved-selector neighbors. Seven version-11.26 seeds
reach the pair-conversion tranche: the five
`a64_sme2_*bfcvt*`/`a64_sve2_fp8_bfcvtn_multi*` files plus
`a64_sme2_multi_cvt_reserved.hex` and
`a64_sve2_fp8_multi_cvt_sibling.hex`. Together they cover SME2 S-to-H
`BFCVT`/`BFCVTN`, SME2+FP8 H-to-B `BFCVT`, (SVE2 or SME2)+FP8 H-to-B
`BFCVTN`, and allocated/reserved boundaries. No pair form is `BFCVTNT`.
MOVPRFX-dependent stream diagnostics remain outside the implemented slice.
The current `a64_sme2_pair_cvt_family.hex` and
`a64_sme2_pair_intfp_cvt_family.hex` seeds extend that evidence through the
original SME2 pair forms 4312--4319 and form 4323. Four dedicated
`a64_sme2_*cvt_multi.hex` seeds cover the remaining `SQCVT`, `SQCVTU`,
`UQCVT`, and FP8 `FCVT` siblings, completing generated forms 4312--4324. Four
adjacent seeds cover SME2 `SUNPK`/`UUNPK` forms 4325--4326 and the eight
SME2+FP8 `F1CVT`/`BF1CVT`/`F2CVT`/`BF2CVT` widening forms 4327--4334,
including their `L` variants and an upper-register boundary. The
27 `a64_sme2_multi4_*.hex` seeds then cover every group-of-four conversion,
narrowing, unpack, B/H/S/D/Q permutation, and rounding form 4341--4362 plus
their reserved boundaries. The
six `a64_advsimd_{cls,cnt,clz}*.hex` seeds cover the allocated/reserved
Advanced SIMD bit-count split, and the eight `a64_sme_{bfmul,fmul}_*.hex`
seeds cover every two-/four-vector multiply envelope. Their dedicated fuzz
invariants assert exact structural ownership before feature admission,
including extras-OFF `UNSUPPORTED_INSTRUCTION`, and compare successful
metadata across little- and big-endian transport. The strict focused suites
enumerate all 24,576 bit-count words (14,336 allocated and 10,240 reserved)
and all 38,912 multiply words (29,184 FMUL and 9,728 BFMUL, with no reserved
cell in the combined SME lattice). Canonical formatter checks and pinned
AARCHMRS/LLVM 21 legal and rejected cases supply independent oracles. The five
`a64_sme_*za*.hex` seeds cover exact forms 4381--4382, shared offset zero and
nonzero `MUL VL` coefficients, selector/base boundaries, and a fixed-bit
neighbor. Their invariant checks the full `0xffff9c10` leaves, W12--W15 and
X/SP extraction, reciprocal tile/memory access, runtime `size == 0`, the
public `VL_SCALED` contract, and SME/matrix/scalable-vector metadata. The
focused suite exhausts all 4,096 allocated words and formatter/profile/build
routes. The four
`a64_sme2_*zt0*.hex` seeds cover exact allocated LDR/STR and both reserved
selector dimensions in the enclosing ZT0 load/store class. Its fuzz invariant
checks the exact `0xfffffc1f` leaves, ZT0 and 64-byte memory operand access,
SME/matrix metadata, SME2 ownership, SP selection, endian parity, and
extras-OFF behavior. The strict focused suite exhausts the parent
`0xffc0fc1c/0xe1008000` class: 64 allocated and 8,128 reserved words, plus 54
fixed-bit neighbors, canonical formatting, truncation, generic dispatch, and
all named profiles. Pinned AARCHMRS and LLVM 21 legal, feature-rejected, and
operand-rejected cases provide the independent oracle. The
`a64_sve2_fp8_fcvt_narrow_family.hex` seed reaches all four FP8
`FCVTN`/`FCVTNB`/`BFCVTN`/`FCVTNT` forms 3165--3168, while
`a64_sve_dup_mov.hex` covers indexed `DUP`/preferred `MOV` form 2439 and
`a64_scalar_fcvtzu_fixed.hex` supplies the scalar fixed-point `FCVTZU` oracle
path.
The `a64_sve_table_lookup.hex` and
`a64_sve_table_lookup_adjacent.hex` seeds reach the selected SVE unpredicated
table-lookup/MOV-from-GPR selector block and an allocated INSR selector-14
sibling deliberately left unowned.
The dedicated suite exhaustively checks all 16 lookup width forms,
all four allocated MOV-from-GPR widths, the unowned selector-14 residual,
the invalid selector-15 space,
exact SVE/SVE2/SME/SVE2.1/SME2.1 alternative gates, named CPU profiles,
endian parity, adjacent unowned controls, and OFF-build structural ownership.
The independent `a64_sve_tblq.hex` seed reaches the exact disjoint
SVE2.1/SME2.1 `TBLQ` descriptor. Its focused suite exhausts all 131,072
combinations of B/H/S/D and `Zd`/`Zn`/`Zm`, verifies the singleton table-list
operand, every named A64 CPU rejection, little-/big-endian and generic-dispatch
parity, adjacent allocated-but-unowned classes, truncation, formatting, and
valid extras-OFF `UNSUPPORTED_INSTRUCTION` behavior.
The `a64_sve_predicated_unary_merge.hex`,
`a64_sve_predicated_unary_zero.hex`, and
`a64_sve_predicated_unary_reserved.hex` seeds independently reach the new
merge, zeroing, and reserved predicated-unary paths. The exhaustive focused
suite covers all 917,504 allocated and 393,216 reserved words across the three
exact classifiers and their SVE/SME versus SVE2p2/SME2p2 feature gates.
The `a64_sve_predicated_vector_shift.hex` and
`a64_sve_predicated_vector_shift_reserved.hex` seeds independently reach an
allocated and a reserved control in the exact predicated vector-shift class.
Its focused suite exhausts all 524,288 words: 270,336 allocated and 253,952
reserved, with exact same-width/wide-count rules and SVE-or-SME admission.
The `a64_sve_predicated_immediate_shift.hex` and
`a64_sve_predicated_immediate_shift_reserved.hex` seeds independently reach
allocated and reserved controls in the disjoint immediate-shift classifier.
Its focused suite exhausts all 524,288 words: 276,480 allocated and 247,808
reserved, with exact immediate derivation and SVE/SVE2/SME feature routes.
The `a64_sve_integer_compare_vectors.hex` and
`a64_sve_integer_compare_vectors_reserved.hex` seeds independently reach
allocated and reserved controls in the exact SVE integer vector-compare
classifier. Its focused suite exhausts all 8,388,608 words: 7,077,888
allocated and 1,310,720 reserved, with ordinary/wide-source metadata,
NZCV-setting flags, SVE-or-SME admission, endian parity, formatting,
truncation, and extras-OFF ownership.
The `a64_sve_integer_compare_immediate_signed.hex`,
`a64_sve_integer_compare_immediate_unsigned.hex`, and
`a64_sve_integer_compare_immediate_reserved.hex` seeds independently reach the
signed, unsigned, and reserved SVE integer compare-with-immediate paths. Its
focused suite exhausts both exact envelopes: 11,534,336 allocated and
1,048,576 reserved words, including every B/H/S/D width, signed and unsigned
immediate boundary, predicate/register field, NZCV update, SVE-or-SME gate,
endian path, formatter path, truncation boundary, and extras-OFF ownership.
The `a64_sve_floating_compare_zero.hex` and
`a64_sve_floating_compare_zero_reserved.hex` seeds independently reach the
allocated and reserved SVE/SME floating compare-with-zero paths. Its focused
suite exhausts the exact 131,072-word classifier: 73,728 H/S/D operation
encodings are allocated and 57,344 B-width or operation-5/7 encodings are
reserved. It also locks typed predicates/vectors, numeric `#0.0`, absence of
NZCV updates, SVE-or-SME admission, endian parity, formatting, truncation, and
extras-OFF ownership.
The `a64_sve_floating_compare_vectors_fcmuo.hex`,
`a64_sve_floating_compare_vectors_facge.hex`,
`a64_sve_floating_compare_vectors_facgt.hex`, and
`a64_sve_floating_compare_vectors_reserved.hex` seeds reach all three newly
appended names and the reserved operation-six vector-compare path. The focused
suite exhausts the exact `0xff204000/0x65004000` classifier: seven H/S/D
operations allocate 2,752,512 words, while byte width and operation six account
for 1,441,792 reserved words. It also locks typed predicates and two vector
sources, no NZCV update, SVE-or-SME admission, endian parity, formatting,
truncation, and extras-OFF ownership.
The `a64_sve_fp_fast_reduction.hex` and
`a64_sve_fp_fast_reduction_reserved.hex` seeds independently reach the exact
baseline SVE/SME floating-point fast-reduction classifier and a reserved
control. Its five names are `FADDV`, `FMAXNMV`, `FMINNMV`, `FMAXV`, and
`FMINV` over H/S/D elements.
The `a64_sve_fp_serial_reduction.hex` and
`a64_sve_fp_serial_reduction_reserved.hex` seeds reach allocated H/S/D
`FADDA` forms and the reserved byte-width boundary of its exact FEAT_SVE-only
classifier.
The six `a64_sve_predicated_fp_unary_*.hex` seeds independently reach merging
and zeroing forms, both disjoint tail-operation masks, a reserved control, and
an adjacent unowned control in the `FRINT*`/`FRECPX`/`FSQRT` classifier.
The eight single-word `a64_sve_*estimate*.hex` seeds independently reach the
H/S/D forms of `FRECPE` and `FRSQRTE` plus both reserved byte-width controls
in the exact unpredicated SVE/SME floating-point estimate classifier.
The 18 `a64_advsimd_frecpe_*`/`a64_advsimd_frsqrte_*` seeds independently reach
every fixed-width scalar H/S/D and vector 4H/8H/2S/4S/2D arrangement plus both
reserved one-lane-D controls in the exact 18,432-word Advanced SIMD estimate
union (16,384 allocated plus 2,048 reserved).

When formatting is enabled, both harnesses derive valid formatter flags from
the fuzz input, so mutations exercise syntax selectors 0 through 7 with and without
`CDISASM_FORMAT_UPPERCASE_OPCODE`. For x86 this covers both the Intel path in
syntax 0 and the AT&T path in syntax 1; syntax 2 through 7 exercise the Intel
aliases. ARM continues to exercise its canonical formatter for every syntax
selector. Each harness also passes the first reserved
flag bit, `0x10`, and verifies that the formatter returns zero and clears a
writable output buffer.

Fuzzer targets follow the public build options. `USE_ARCH_X86`, `USE_ARCH_ARM`,
`USE_DISASM_FORMAT`, and `USE_EXTRA_OPCODES` default to `ON`, but a focused run
can compile and instrument only one decoder, with or without its formatter or
extended opcode families. The architecture options choose the decoder for
input bytes; they do not need to match the machine running the fuzzer. A normal common-only
build may set both to `OFF`; enabling `CDISASM_BUILD_FUZZERS` then requires at
least one architecture because otherwise there is no decoder harness to build.

Use Clang with compiler-rt's libFuzzer runtime for an x86-only run:

```sh
cmake -S . -B build-fuzz-x86 \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTING=OFF \
  -DCDISASM_BUILD_EXAMPLES=OFF \
  -DCDISASM_BUILD_FUZZERS=ON \
  -DUSE_ARCH_X86=ON \
  -DUSE_ARCH_ARM=OFF \
  -DUSE_DISASM_FORMAT=ON \
  -DUSE_EXTRA_OPCODES=ON
cmake --build build-fuzz-x86 --target cdisasm_decode_fuzzer
./build-fuzz-x86/cdisasm_decode_fuzzer \
  -max_len=192 -timeout=10 build-fuzz-x86/fuzz-corpus
```

libFuzzer applies `-max_len` before the harness recognizes and normalizes
readable hexadecimal text. The x86 text-input contract is
`FUZZ_HEX_CAPACITY * 3 = 192` bytes, and the largest checked-in x86 seed is 189
bytes. Using 64 here would truncate multiple aggregate and VBMI2 seeds before
normalization. The ARM corpus's largest seed is 60 bytes, so its command below
remains at 64.

For an ARM-only run:

```sh
cmake -S . -B build-fuzz-arm \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTING=OFF \
  -DCDISASM_BUILD_EXAMPLES=OFF \
  -DCDISASM_BUILD_FUZZERS=ON \
  -DUSE_ARCH_X86=OFF \
  -DUSE_ARCH_ARM=ON \
  -DUSE_DISASM_FORMAT=ON \
  -DUSE_EXTRA_OPCODES=ON
cmake --build build-fuzz-arm --target cdisasm_arm_decode_fuzzer
./build-fuzz-arm/cdisasm_arm_decode_fuzzer \
  -max_len=64 -timeout=10 build-fuzz-arm/fuzz-arm-corpus
```

With both architectures enabled, both fuzzer targets and both build-local
corpora are created and may be built in one command. A disabled architecture's
decoder and formatter sources, harness target, and copied corpus are omitted.
With `USE_DISASM_FORMAT=OFF`, both decoder harnesses remain available, but
formatter sources and formatter-specific invariants are omitted.
Run a second campaign with `-DUSE_EXTRA_OPCODES=OFF` against the same copied
corpora. This is intentional: the optional-family seeds then cover the
disabled-path failure-result zeroing and nonzero-mask rejection, while
deterministic unit/corpus/package tests cover the exact recognize-and-reject
statuses. Only ordinary scalar/base x86 seeds continue to decode with flags
zero; x87, MMX/3DNow!, SIMD, SMX, Intel VMX, AMD SVM, system, hint, and
undocumented families require an ON build and their respective runtime bits.

CMake performs a compile-and-link probe for libFuzzer and the requested
sanitizer runtimes. A Clang installation without the matching compiler-rt
libraries therefore fails at configuration time with a focused diagnostic.

AddressSanitizer and UndefinedBehaviorSanitizer are enabled by default. Set
`CDISASM_FUZZ_SANITIZERS` to another comma-separated Clang sanitizer list, or
to an empty value to use libFuzzer instrumentation alone. The fuzzer compiles
private static copies of the selected library sources so the normal shared
or static library and installed artifacts are unaffected. `BUILD_SHARED_LIBS`
therefore does not change the private fuzzer runtimes; `USE_DISASM_FORMAT`
still controls whether formatter sources are instrumented, and
`USE_EXTRA_OPCODES` controls which decoder and formatter branches are present
in those runtimes.

The larger regression corpora are `tests/data/x86_opcodes.tsv` and
`tests/data/arm_opcodes.tsv`. They record CPU, mode, address, expected
status/size/metadata, and opcode bytes in stable, reviewable formats. The x86
corpus additionally records canonical formatter text. The x86 opcode-corpus
runner is built whenever x86 is enabled, and the ARM runner whenever ARM is
enabled. Both check numeric decoder metadata, including structurally owned
`UNSUPPORTED_INSTRUCTION` results in extras-OFF builds, and their
formatter assertions are compiled out when formatting is disabled. The
dedicated formatter suites check canonical text, vector arrangements, Apple
spellings, buffer boundaries, and invalid metadata as applicable; the
cross-option contract suite additionally covers formatter behavior in compact
extras-OFF builds. Ignoring blank and comment lines, the current checked-in
corpora contain exactly 5,126 x86 rows and 3,319 ARM rows. The reviewed seed
inventories contain 2,395 x86 and 1,533 ARM `.hex` files. The append-only public
catalogs contain 2,028 x86 name IDs including `NONE`, 307 defined x86
register IDs in a 309-slot ID space, 323 x86 groups, 2,054 ARM name IDs
including `NONE`, and 375 ARM registers.
The current generated-coverage inventory covers all 9,001 x86 IFORMs: 1,861 are
`corpus_reachable`, three are `corpus_partial`, one is a
`profile_rejected_probe`, 4,501 are `source_assignment_only`, and 2,635 are
`catalog_only`; its `exact_evidence_forms` rollup is 1,865. It covers all 6,569
ARM leaves: 1,150 are `corpus_reachable`, one is a `profile_rejected_probe`,
1,798 are `source_assignment_only`, and 3,620 are `catalog_only`; its
`exact_evidence_forms` rollup is 1,151.
Generator/manifest v4 normalizes A32/A64 big-endian words and T32 big-endian
halfwords before mapping and invokes `xed-dec` in its default 32-bit mode
rather than passing its unsupported `-32` option; the endian correction
removes eight historical
false-positive ARM form credits. SVE2/SME `XAR` form 2325 moved from
`verified_missing_encoding` to `corpus_reachable`; neither architecture now
has a `verified_missing_encoding` row. Advanced SIMD `ADDV` form 6077
previously moved to exact corpus-reachable coverage, as did classic-VEX
`VDPPD` forms 4507--4508 and
`VDPPS` forms 4515--4518, including the allocated 32-bit B-prime alias
`c4 c3 71 41 c2 01`.
These are checked-in inventory counts, not exhaustive architectural
coverage measurements.

The latest reviewed x86 seeds add 24 floating `VCOMPRESSPD/PS` and
`VEXPANDPD/PS` entries, 13 `VDBPSADBW` entries, and 20 `VPTERNLOGD/Q`
entries. Their invariants cover all 42 exact forms, vector-width-specific ISA
groups, destination access, masks, broadcasts, FullMem disp8, APX address
promotion, malformed controls, truncation, and extras-OFF ownership. The
matching corpus additions are 24, 30, and 37 rows respectively.

The latest ARM seeds add 25 CRC entries, eight constructive SVE logical
entries, 18 architectural-hint entries, and six SVE2/SME `XAR` entries. Their
invariants cover all twenty CRC leaves, `AND`/`ORR`/`EOR`/`BIC` plus the
preferred `MOV` alias, all fourteen architectural-hint leaves, and all
122,880 allocated `XAR` words with their 128 reserved immediate controls.
The matching data rows retain profile, endian, formatting, malformed,
truncation, and extras-OFF boundaries.

Twelve new x86 seeds cover every `VPTESTM*`/`VPTESTNM*` family and selected
register, memory, broadcast, malformed-control, and truncation boundaries.
Ten ARM seeds cover A32/T32 `MUL`, `UMULL`, `UMLAL`, `SMULL`, and `SMLAL`,
including flag-setting, conditional, invalid-register-pair, endian, IT-state,
and truncation cases. Matching corpus additions make all 48 x86 forms and
twelve ARM leaves exact and replayable.

Twelve additional ARM seeds cover the complete A32 extra-load/store block:
halfword and signed-byte scalar transfers, doubleword register pairs,
register and split-immediate offsets, literal addressing, pre-index and
unprivileged forms, endian transport, truncation, invalid PC use, odd pairs,
and writeback overlap. The matching 48 corpus rows make forms 1--48 directly
reachable.

Twelve more ARM seeds exercise the 34 wide T32 halfword, signed-load, and
doubleword leaves, including shifted registers, positive/negative offsets,
literals, pre/post-indexing, unprivileged access, endian transport, pair
overlap, and truncation. The matching corpus rows make forms 1750--1756 and
the selected 2049--2108 block directly reachable.

The current post-tranche ASan+UBSan validation rebuilds both
extra-opcode variants and uses the current 2,395 x86 and 1,533 ARM source-seed
inventories, then completes 6,000 total runs in each of the four
x86/ARM-by-ON/OFF cells.
All four cells finish without a sanitizer, invariant,
timeout, leak, or crash artifact.
Direct replay reports 2,396 x86 and 1,534 ARM libFuzzer runs because each replay
includes libFuzzer's empty unit in addition to the source files. These are
bounded validation campaigns, not exhaustive architectural coverage.
The current strict Clang 21.1.8 validation matrix totals are 258/258 non-package CTests
with extras and formatting enabled, 253/253 with extras disabled, and 256/256
with formatting disabled. A separate package configuration passes both
end-to-end tests and all 16 shared plus all 16 static feature cells. All current
matrices pass.
The current tranche additionally covers all 144 pinned VEX/EVEX packed-integer
MIN/MAX forms, all 36 pinned GFNI forms, all 30 fixed-width A32/T32/A64
SHA1/SHA256 leaves, the fixed A64 SHA3/SHA512/SM3/SM4 block 6287--6303, and
exact classic-VEX `VCOMISD`/`VCOMISS`
forms 3629--3630/3633--3634, exact x86 VEX `VPBROADCASTB/W` forms
6342/6343/6347/6348/6387/6388/6392/6393 and `VPBROADCASTD/Q` forms
6355/6356/6360/6361/6374/6375/6379/6380, ARM indexed `MLA`/`MLS` forms
2722--2727, ARM indexed `SQRDMLAH`/`SQRDMLSH` forms 2728--2733, ARM indexed
`USDOT`/`SUDOT` forms 2734--2735, SVE
`AESMC`/`AESIMC` forms 2903--2904, SVE
`AESE`/`AESD`/`SM4E` forms 2905--2907, VEX `VPCMPEQQ` forms 6454--6457,
VEX `VBLENDPD`/`VBLENDPS` forms 3527--3534 and
`VBLENDVPD`/`VBLENDVPS` forms 3535--3542, SVE `PUNPKLO`/`PUNPKHI`
forms 2468--2469, and SVE/SME `SUNPKLO`/`SUNPKHI`/`UUNPKLO`/`UUNPKHI`
forms 2456--2459, SVE2/SME `SRI`/`SLI` forms 2846--2847,
VEX `VBROADCASTF128`/`VBROADCASTI128` forms 3543/3554, Advanced SIMD
`BSL`/`BIT`/`BIF` forms 6188/6196/6198, VEX
`VBROADCASTSD`/`VBROADCASTSS` forms 3569--3570/3573--3574/3579--3580, VEX
`VEXTRACTF128`/`VEXTRACTI128`/`VINSERTF128`/`VINSERTI128` forms
4539--4540/4553--4554/5551--5552/5565--5566, Advanced SIMD high-narrow
`ADDHN`/`SUBHN`/`RADDHN`/`RSUBHN` forms 6093/6095/6108/6110, VEX
`VEXTRACTPS`/`VINSERTPS` forms 4567/4569/5579--5580, VEX
`VPERM2F128`/`VPERM2I128` forms 6770--6773, VEX `VPERMD`/`VPERMPS` forms
6780--6781/6886--6887, Advanced SIMD widening add/sub forms
6089--6092/6104--6107, Advanced SIMD absolute-difference-long forms
6094/6096/6109/6111, FEAT_PAuth register
branches 4510/4511/4513/4514/4525--4528, and SVE BitPerm
`BEXT`/`BDEP`/`BGRP` forms 2829--2831, VEX `VPERMPD`/`VPERMQ` forms
6878--6879/6890--6891, VEX `VPERMILPD` forms
6834--6837/6846--6849 and `VPERMILPS` forms 6854--6857/6866--6869,
Advanced SIMD `SMLAL`/`SMLSL`/`SMULL` plus `UMLAL`/`UMLSL`/`UMULL` forms
6097/6099/6101/6112--6114, and Advanced SIMD
`SQDMLAL`/`SQDMLSL`/`SQDMULL` forms 6098/6100/6102, Advanced SIMD
`SQDMULH`/`SQRDMULH` forms 6136/6178, Advanced SIMD `PMULL`/`PMULL2`
form 6103, classic-VEX `VROUNDPD`/`VROUNDPS`/`VROUNDSD`/`VROUNDSS`
forms 8539--8550, classic-VEX `VSHUFPD`/`VSHUFPS` forms
8664--8665/8670--8671/8674--8675/8680--8681, classic-VEX
`VTESTPD`/`VTESTPS` forms 8795--8802, classic-VEX `VUCOMISD`/`VUCOMISS`
forms 8803--8804/8809--8810, classic-VEX `VCOMISD`/`VCOMISS` forms
3629--3630/3633--3634, classic-VEX `VDPPD`/`VDPPS` forms
4507--4508/4515--4518, classic-VEX `VCMPPD`/`VCMPPS`/`VCMPSD`/`VCMPSS`
forms 3595--3598/3611--3614/3617--3618/3623--3624, classic-VEX `VPTEST`
forms 8319--8322,
classic-VEX `VPMOVMSKB` forms 7334--7335, `VPSIGNB/W/D` forms
7921--7932, and `VPSHUFD/HW/LW` forms 7891--7916,
classic-VEX `VUNPCKHPD`/`VUNPCKHPS`/
`VUNPCKLPD`/`VUNPCKLPS` forms 8825--8862, classic-VEX integer `VPUNPCK*`
forms 8323--8398, classic-VEX `VPHMINPOSUW` forms 7040--7041,
`VPINSRB/D/Q/W` forms 7060--7061/7064--7065/7068--7069/7072--7073, and
`VPEXTRB/D/Q/W` forms 6966/6968/6970/6972/6974/6976/6978--6979/6983,
all 24 classic-VEX `VPMOVSXBW/BD/BQ/WD/WQ/DQ` forms listed above, all 24
classic-VEX `VPMOVZXBW/BD/BQ/WD/WQ/DQ` forms listed above,
Advanced SIMD `PMUL` form 6175,
Advanced SIMD pairwise `SMAXP`/`SMINP`/`UMAXP`/`UMINP` forms
6134--6135/6176--6177, scalar/vector `ADDP` forms 5808/6137, Advanced SIMD
`ADDV` form 6077, and regular
`SMAX`/`SMIN`/`UMAX`/`UMIN` forms
6126--6127/6168--6169 plus register `CMGT`/`CMGE`/`CMHI`/`CMHS`/`CMEQ`
forms 6120--6121/6162--6163/6173, scalar/vector `CMTST` forms 5831/6131,
scalar/vector `SSHL`/`USHL` forms 5826/5841/6122/6164, fixed-vector
`SABA`/`UABA` forms 6129/6171,
fixed-vector `MLA`/`MLS` forms 6132/6174, by-element `MLA`/`MLS` forms
6268/6270, and widening by-element `SMLAL`/`SQDMLAL`/`SMLSL`/`SQDMLSL`/
`SMULL`/`SQDMULL`/`UMLAL`/`UMLSL`/`UMULL` forms
6243--6246/6248--6249/6269/6271--6272,
and scalar/vector compare-with-zero `CMLT`/`CMLE` forms
5777/5794/6013/6045,
alongside the
earlier exact `VPBLENDVB`, `VPCMOV`, `VPPERM`, `ZIPQ1`/`UZPQ1`,
`ZIPQ2`/`UZPQ2`, and `MLAPT`/`MADPT` families. It does not make either
decoder ISA-complete.
These counts include the complete
bounded EVEX packed-integer compare-to-mask, MIN/MAX, multiply/multiply-add,
modular ADD/SUB, saturating ADD/SUB, D/Q logical, and byte/word average classes.
They also include the complete bounded VEX/EVEX dword/qword and EVEX word
per-element variable-shift classes, the EVEX dword/qword variable and immediate
packed-rotate classes, and the remaining allocated opcode-`72` dword/qword
immediate packed-shift class, plus the allocated opcode-`71`/`73` word,
qword, and byte-lane immediate-shift groups, the exact AVX512VBMI2 EVEX
map-2/map-3 word/dword/qword double-shift class, and the exact byte/word/
dword/qword COMPRESS/EXPAND plus BITALG/VPOPCNT rows, and all six exact
AVX-512CD names: `VPCONFLICTD/Q`, `VPLZCNTD/Q`, `VPBROADCASTMB2Q`, and
`VPBROADCASTMW2D`, plus the exact four-operation EVEX AVX-512 VNNI, the exact
six-operation EVEX AVX10.2 VNNI-INT8 row, classic VEX AVX-VNNI, and
six-operation classic VEX AVX-VNNI-INT8 and
AVX-VNNI-INT16 dot-product rows, the exact memory-only Knights Mill
`VP4DPWSSD`/`VP4DPWSSDS` AVX512_4VNNIW pair, and the complete memory-only
Knights Mill `V4FMADDPS`/`V4FMADDSS`/`V4FNMADDPS`/`V4FNMADDSS`
AVX512_4FMAPS family, the exact AVX512F/AVX10.1
`VGETEXPPS`/`VGETEXPPD`/`VGETEXPSS`/`VGETEXPSD` tranche, and exact MAP6
`VGETEXPPH`/`VGETEXPSH`/`VGETEXPBF16` forms,
and the classic EVEX AVX512_VBMI byte-permute/multishift
slice plus the AVX512BW/AVX10 word-permute rows and exact REX2 map-1
`MONITOR`/`MWAIT` forms, plus all four ACE_1 `TILEMOVROW`/`TILEMOVCOL`
GPR32/IMM8 forms 3299--3302, all ten ACE TOP2/TOP4 forms, and both the legacy
and APX-F RAO-INT rows. The current exact x86 tranche also includes all eleven
ACE `BSRINIT`/`BSRMOVF`/`BSRMOVH`/`BSRMOVL` forms 378--388, with visible
`BSR0`, register/m512 direction and unscaled disp8 boundaries, plus every
legacy/VEX `USER_MSR` and EVEX `APX_F_USER_MSR` `URDMSR`/`UWRMSR` form
3353--3360. Its APX map-4 register cases are tested alongside the same-opcode
memory-only `ENQCMD`/`ENQCMDS` routes so structural dispatch cannot shadow
either family, including U=0/X4 extended-index addressing in `ENQCMD` and
`MOVDIR64B`.
The legacy F2/F3 map-2 memory controls are independently exact in every mode,
including ignored `66`, address-sized `GPRa`, REX extension/WIG behavior,
64-byte reads, privilege/status metadata, and the register USER_MSR split.
It also includes the exact HRESET 1319, CLDEMOTE 710, CLZERO 719, and
PCONFIG/PCONFIG64 2084--2085 system slices with their fixed-selector,
prefix/profile, NOP/Group-7 collision, privilege/status, and REX2 boundaries.
PBNDKB 2039 adds the neighboring fixed C7 selector, suppressed-state and
privilege/status contract. PREFETCHIT0/1 2308--2309 add the complete `0F 18`
data-prefetch/fat-NOP collision lattice, exact RIP-relative promotion, and
profile/address-size fallback behavior.
The AMD fixed Group-7 inventory further includes MONITORX 1640, MWAITX 1822,
and mandatory-F3 MCOMMIT 1629, including suppressed address/control state,
rightmost-repeat selection, no-named-profile admission, aggregate MCOMMIT
status writes, extras-off ownership, and all 128 REX2 payload values.
PTWRITE forms 2438--2439 add the mandatory-F3 `0F AE /4` register/memory
split, dword/qword GPRy/MEMy semantics, exact runtime/profile gates, XSAVE and
WAITPKG/CET collision boundaries, and independently APX-F-gated REX2 routes.
MOVNTI forms 1692--1693 add the NP/OSZ=0 `0F C3 /r` memory-write/GPR-read
pair, dword/qword width selection, strict mandatory-prefix and register-ModRM
rejection, REX/REX2 transport, and conjunctive SSE2/APX gating for REX2.
Non-temporal SIMD stores add legacy `MOVNTDQ` 1691, `MOVNTPD` 1694, and
`MOVNTPS` 1695; their `MOVNTQ`/`MOVNTSD`/`MOVNTSS` selector siblings
1696--1698; VEX forms 5869--5870/5874/5878--5879/5883; and EVEX forms
5871--5873/5875--5877/5880--5882. All have a memory-only write destination
and read vector source. Legacy mandatory-prefix precedence, VEX WIG and
reserved `vvvv`, EVEX W/pp/LL and compressed-disp8 rules, REX/REX2 transport,
and the independent width-specific AVX512F and APX gates are exact.
SMAP forms `CLAC` 707 and `STAC` 3158 add the exact NP `0F 01 CA/CB`
zero-operand CPL0 controls, AC-write metadata, all-mode profile admission,
ignored ordinary REX payloads, and independently APX-gated REX2 map-1
transport. Mandatory F2/F3 on `0F 01 CA` remains the distinct FRED
`ERETS`/`ERETU` collision rather than aliasing SMAP.
The exact move inventory also includes the scalar and packed tranches through
`VMOVUPD`/`VMOVUPS` forms 5946--5979 and the seven `VMOVW` identities
5980--5986. VMOVW keeps its WIG-`66` `AVX512_FP16_128N` route separate from
F3/W0 `AVX512_MOVZXC_128`, with Tuple2 memory and independent APX promotion.
The next ten exact identities are `VMPSADBW` forms 5987--5996: VEX uses
AVX/AVX2, EVEX uses the exact AVX512-MEDIAX width route, and Full-tuple memory,
masking, imm8, collision, and APX address semantics are retained.
Exact virtualization forms 5997--6005 then add qword-memory
`VMPTRLD`/`VMPTRST`, four register/memory and 32-/64-bit `VMREAD` identities,
`VMRESUME`, address-sized implicit-AX `VMRUN`, and `VMSAVE`, with independent
VMX/SVM and APX-F admission plus exact collision and prefix ownership.
The VTX follow-on forms 6048--6053 add four 32-/64-bit register/memory
`VMWRITE` identities, zero-operand `VMXOFF`, and qword-memory `VMXON`.
`VMWRITE` reads both operands and writes status at CPL0; VMXOFF and VMXON
write status, require CPL0/NOTSX, and VMXON additionally requires protected
mode. REX2 routes independently require APX-F, and the F3 VMWRITE-invalid and
66/F2 EXTRQ/INSERTQ collision cells remain disjoint.
Exact `VMULBF16` forms 6006--6011 add EVEX XMM/YMM/ZMM register and
Full-memory inputs, BF16 broadcast, merge/zero masking, Full-tuple disp8,
width-specific AVX10.2 BF16 groups/runtime bits, and APX B4/U0/X4 ownership.
Exact `VMULPH` forms 6022--6027 and `VMULSH` forms 6042--6043 add EVEX
MAP5/opcode-59 pp0/ppF3 W0 packed and scalar FP16 multiplication. VMULPH has
XMM/YMM/ZMM register or Full-memory inputs, FP16 broadcast 1to8/1to16/1to32,
and 16/32/64-byte disp8; VMULSH has XMM or m16 Tuple2 input and two-byte
disp8. Both preserve merge/zero masking, embedded rounding plus SAE on their
fixed-width register forms, exact width/scalar groups and runtime bits, APX
B4/U0/X4 ownership, and the VMULBF16/PF2/legacy collision boundaries.
Exact classic `VMULPD`/`VMULPS`/`VMULSD`/`VMULSS` forms 6012--6021,
6028--6041, and 6044--6047 add VEX AVX XMM/YMM packed and XMM scalar paths
plus EVEX AVX512F/AVX10.1 XMM/YMM/ZMM packed and XMM scalar paths. Their exact
`AVX512F_128/256/512/SCALAR` width groups use runtime bits 128/130/131/133 and
retain masks, broadcast, Full/scalar tuple disp8, ER/SAE, and APX B4/U0/X4.
Arrow Lake remains negative, while Knights Mill admits ZMM/scalar but rejects
the AVX512VL-dependent XMM/YMM forms. Pinned XED covers all 28 IFORMs.
Exact `VORPD`/`VORPS` forms 6054--6073 add VEX AVX XMM/YMM and EVEX
AVX512DQ/AVX10.1 XMM/YMM/ZMM register and memory paths. They retain masks,
scalar broadcast, Full-tuple disp8, high registers, APX B4/U0/X4, exact
non-long extension behavior, and reserve register `EVEX.b` rather than
publishing ER/SAE.
Exact `VP2INTERSECTD/Q` forms 6074--6085 add all XMM/YMM/ZMM register and
Full-memory source shapes, dword/qword element selection, broadcast,
16/32/64-byte disp8, high-register and APX address routes, and exact width and
Tiger Lake profile gates. ModRM.reg is normalized to an even/odd K pair,
published as two writes and formatted as `kN+1`; malformed EVEX controls stay
reserved.
Exact VEX `VPCMPEQQ` forms 6454--6457 add C4 map-2 opcode `29`, mandatory 66,
WIG, and NDS `vvvv` semantics for XMM/YMM register and memory inputs. XMM
requires AVX; YMM requires AVX2 and publishes both AVX and AVX2. Their bounded
control space contains 196,608 allocations and 589,824 reserved pp cells, with
all-mode alias, prefix, address, sibling, formatter, and extras-OFF ownership.
Exact VEX `VBLENDPD`/`VBLENDPS` forms 3527--3534 add C4 map-3 opcodes
`0D`/`0C`, mandatory 66, WIG, NDS `vvvv`, XMM/YMM register/memory sources,
and a trailing imm8 operand. Both widths use AVX rather than AVX2. Their
bounded control space contains 393,216 allocations and 1,179,648 reserved
controls, with all-mode alias, non-long C4/LES, prefix, address, AVX gate,
formatter, complete-payload truncation, and extras-OFF ownership.
Exact VEX `VBLENDVPD`/`VBLENDVPS` forms 3535--3542 add C4 map-3 opcodes
`4B`/`4A`, mandatory 66, W=0, NDS `vvvv`, XMM/YMM register/memory sources,
and a trailing selector byte whose high nibble names the fourth vector source
and whose low nibble is ignored. Both widths use AVX; the byte is recorded as
selector metadata rather than an immediate. Their bounded control space
contains 196,608 allocations and 1,376,256 reserved controls, with all-mode
alias, non-long C4/LES, prefix, address, formatter, complete-payload
truncation, and extras-OFF ownership.
The bounded ARM inventory includes SVE predicate-logical, unpredicated and
destructive-predicated integer arithmetic, scalable and fixed-width Advanced
SIMD ZIP/UZP/TRN, selected table-lookup/MOV-from-GPR classes, the complete
disjoint `TBLQ` class, three exact predicated SVE unary classifiers, one exact
predicated SVE vector-shift classifier, one disjoint predicated SVE/SVE2
immediate-shift classifier, the exact SVE integer vector-compare classifier,
the signed/unsigned SVE integer compare-with-immediate envelopes, and the exact
SVE/SME floating compare-with-zero, floating vector-compare, and destructive
predicated floating-point binary classifiers, including the seven-operation
FEAT_SVE_B16B16 halfword row, plus the exact baseline
SVE/SME `FADDV`/`FMAXNMV`/`FMINNMV`/`FMAXV`/`FMINV` fast-reduction class and
the exact FEAT_SVE-only `FADDA` scalar-accumulating reduction, the exact
merging/zeroing predicated FP-unary `FRINT*`/`FRECPX`/`FSQRT` class, and the
unpredicated SVE/SME and fixed-width Advanced SIMD `FRECPE`/`FRSQRTE` estimate
classes, plus the disjoint FEAT_F64MM SVE Q-element ZIP/UZP/TRN and exact
merging H/S/D-to-H and S-to-S/D and D-to-S/D `SCVTF`/`UCVTF` classes. The
complete baseline merging H/S/D `FCVT`/`FCVTZS`/`FCVTZU` precision- and
integer-conversion class, exact zeroing `FCVT Zd.H, Pg/z, Zn.S`, exact merging
SVE/SME `BFCVT`/`BFCVTNT Zd.H, Pg/m,
Zn.S`, and exact SVE2.2/SME2.2 zeroing `BFCVT`/`BFCVTNT Zd.H, Pg/z, Zn.S` are
also included. The bounded unpredicated conversion slice includes the complete
SME2 two-vector conversion, unpack, FP8-widening, and pair-rounding block
4312--4338, SME_F16F16 `FCVT`/`FCVTL` forms 4339--4340, the complete SME2
four-vector block 4341--4362, the exact SME2 multi-register `MOV`/`MOVA`
insert/extract forms 3867--3876/3882--3891, the exact SME2.1 `MOVAZ` zeroing
extract forms 3892--3906, the SME multi-vector
`FMUL`/`BFMUL` block 4363--4370, the exact baseline-SME predicated ZA-slice `MOVA` insert/extract
forms 3862--3866/3877--3881, the exact baseline-SME ZA `LDR`/`STR` forms 4381--4382, the exact
SME2 ZT0 `LDR`/`STR` forms 4383--4384, baseline A64
`UDF #imm16` form 4387, FEAT_WFxT forms 4457--4458, and all six
FEAT_FlagM/FlagM2 forms 4499--4501/5696--5698. SVE first-fault-register forms
2562--2564/2617--2618 add predicated
`RDFFR`/`RDFFRS`, unpredicated `RDFFR`, `WRFFR`, and `SETFFR`, with 545
allocated encodings, exact typed-predicate access, RDFFRS-only NZCV writes,
and ownership of all 611 reserved U:S controls.
`PSEL` form 2565 adds the exact `Pd, Pn, Pm.T[Wv, lane]` schema, SVE2.1-or-
baseline-SME admission, 491,520 allocated words, and the 32,768 words from
both untyped `tsz=0000` controls. Wide-immediate forms 2619--2632 add twelve
tied-destination arithmetic
operations plus preferred `MOV`/`FMOV` broadcasts, exact signed, shifted, and
expanded floating immediates, and complete ownership of their shared
2,097,152-word parent under SVE-or-SME admission.
`SDOT`/`UDOT` forms 2633--2636 add tied-accumulator B-to-S and H-to-D
baseline widening under SVE or SME plus B-to-H widening under SVE2p3 or
SME2p3; their shared parent has 196,608 allocations and 65,536 reserved
`size=00` words.
`SQDMLALBT`/`SQDMLSLBT`/`CDOT`/`CMLA`/`SQRDCMLAH` forms 2637--2641 add
tied-accumulator complex/widening multiply-add, exact arrangements and
rotations, reserved-width ownership, and SVE2-or-SME admission.
Forms 2642--2655 add the twelve signed, unsigned, and saturating-doubling
bottom/top widening multiply-add/subtract identities plus same-width
`SQRDMLAH`/`SQRDMLSH`. They retain tied read/write accumulator access,
read-only sources, exact H/S/D or B/H/S/D arrangements, scalable-only
metadata, reserved-width ownership, and SVE2-or-SME admission.
Indexed `MLA`/`MLS` forms 2722--2727 add six wholly allocated H/S/D leaves,
destructive `Zda`, read-only `Zn` and width-restricted `Zm.T[lane]`, exact
SVE2-or-SME admission, and collision ownership against the adjacent indexed
rounding family.
Indexed `SQRDMLAH`/`SQRDMLSH` forms 2728--2733 add six wholly allocated H/S/D
leaves, destructive `Zda`, read-only `Zn`, width-restricted `Zm.T[lane]`, exact
SVE2-or-SME admission, and collision ownership against adjacent indexed
`USDOT`. Their masks/values are `0xffa0fc00` with
`0x44201000`/`0x44201400` for H and `0xffe0fc00` with
`0x44a01000`/`0x44a01400` or `0x44e01000`/`0x44e01400` for S or D.
`USDOT` form 2656 adds the exact `0xffe0fc00`/`0x44807800` leaf inside the
`0xff20fc00`/`0x44007800` mixed-dot parent. It owns 32,768 allocated `size=10`
words and 98,304 reserved siblings, with `Zda.S` read/write, `Zn.B`/`Zm.B`
reads, `(SVE or SME) and I8MM` admission, `CPU_ANY` positive, and all current
named profiles negative. LLVM 21 and pinned AARCHMRS provide independent
encoding evidence.
`USDOT`/`SUDOT` forms 2734--2735 add the exact, wholly allocated
`0xffe0fc00`/`0x44a01800` and `0x44a01c00` indexed leaves. All 65,536 words use tied
`Zda.S`, read-only `Zn.B`, and read-only `Zm.B[lane]`, carry only
scalable-vector metadata, and require I8MM together with SVE or SME. The
LLVM 21 matches both leaves, while focused profile, endian, formatter,
truncation, and extras-OFF tests retain its public boundary.
`AESMC`/`AESIMC` forms 2903--2904 add 64 allocated tied-`Zdn.B` words under
FEAT_SVE_AES. All 192 remaining size controls in their common parent are
invalid. LLVM 21 `+sve2-aes` plus focused profile, transport, formatter,
truncation, and extras-OFF tests retain the public boundary.
`AESE`/`AESD` forms 2905--2906 and `SM4E` form 2907 add three exact
1,024-word leaves in the SVE crypto-binary parent. AES uses `.B` and
FEAT_SVE_AES; SM4 uses `.S` and FEAT_SVE_SM4. The remaining thirteen selector
rows are invalid, for 3,072 allocated and 13,312 reserved words. LLVM 21 and
focused profile, transport, formatter, truncation, and extras-OFF tests retain
the complete boundary.
`PUNPKLO`/`PUNPKHI` forms 2468--2469 add the complete 512-word predicate-
unpack parent. Bit 16 selects the two fully allocated leaves; each writes
`Pd.H`, reads `Pn.B`, carries only scalable-vector metadata, and admits SVE or
SME. LLVM 21 matches all words under both feature routes, while focused
profile, transport, formatter, truncation, and extras-OFF tests retain the
public boundary.
`SUNPKLO`/`SUNPKHI`/`UUNPKLO`/`UUNPKHI` forms 2456--2459 add the exact
SVE/SME vector-unpack parent `0xff3cfc00`/`0x05303800`. The four control
values and three widening sizes allocate 12,288 words; all 4,096 `size=00`
words are reserved. Each form writes `Zd.T`, reads `Zn` at half that element
width, carries only scalable-vector metadata, and admits SVE or SME. LLVM 21
and focused profile, endian/generic transport, formatter, truncation, and
extras-OFF tests retain
the complete boundary.
`SRI`/`SLI` forms 2846--2847 add the exact SVE2/SME shift-insert parent
`0xff20f800`/`0x4500f000`, with leaves selected by bit 10. Encoded immediate
values 8--127 allocate 245,760 B/H/S/D words and values 0--7 reserve 16,384
words. Both expose tied read/write `Zdn.T`, read-only `Zn.T`, a decoded read
immediate, and scalable-vector-only metadata. LLVM 21 and focused profile,
endian/generic transport, formatter, truncation, and extras-OFF tests retain
the complete boundary.
Forms 2657--2668 add `SRSHL`/`SRSHLR`, `SQSHL`/`SQRSHL`/`SQSHLR`/
`SQRSHLR`, `URSHL`/`URSHLR`, and `UQSHL`/`UQRSHL`/`UQSHLR`/`UQRSHLR`.
Their twelve `0xff3fe000` leaves occupy selectors 2/6/8/A/C/E and
3/7/9/B/D/F inside parent `0xff30e000`/`0x44008000`, leaving selectors
0/1/4/5 reserved. Every B/H/S/D form uses destructive merging
`Zdn.T, Pg/m, Zdn.T, Zm.T`, carries scalable/predicated metadata, and admits
SVE2 or SME; the parent contains 393,216 allocated and 131,072 reserved words.
Forms 2669--2676 add `.S`-only `URECPE`/`URSQRTE` and B/H/S/D
`SQABS`/`SQNEG`, each in merging and zeroing variants. Merging requires SVE2
or SME and reads/writes `Zd`; zeroing requires SVE2.2 or SME2.2 and writes it.
Their exact parent contains 163,840 allocated and 98,304 reserved words.
Forms 2677--2678 add exact SVE2-or-SME `SADALP`/`UADALP` for B-to-H,
H-to-S, and S-to-D, with 49,152 allocated and 16,384 reserved `size=00`
words. Forms 2679--2686 add all B/H/S/D arrangements of `SHADD`, `SHSUB`,
`SRHADD`, `SHSUBR`, `UHADD`, `UHSUB`, `URHADD`, and `UHSUBR`, allocating
262,144 words under the same feature alternative.
The non-saturating SVE
element-count forms 2374--2391 add vector and GPR `INC*`/`DEC*` plus GPR
`CNT*` over their allocated B/H/S/D domains. They keep the architectural
pattern and `MUL` controls as separate immediates, require FEAT_SVE or
FEAT_SME, and own 294,912 allocated and 98,304 reserved encodings. The
fixed-width Advanced SIMD
`CLS`/`CNT`/`CLZ` forms
6007/6008/6041, the
SVE2.1-or-SME2 `SQCVTN`/`SQCVTUN`/`UQCVTN` multi-extract row 2881--2883,
and the SVE2-or-SME2 FP8 `FCVTN`/`FCVTNB`/`BFCVTN`/`FCVTNT` row 3165--3168. FP8 remains an independent
capability. SVE indexed `DUP`/preferred `MOV` form 2439, SVE/SME
`ADDVL`/`ADDPL`/`RDVL`, nine baseline integer reductions, Advanced SIMD
`REV16`/`REV32`/`REV64`, exact baseline A64 `UDF`, and structured A64 and T32
`DCPS1`/`DCPS2`/`DCPS3` are included; other conversion maps and contextual
MOVPRFX diagnostics remain outside this bounded slice.
The version-11.8 additions are 36
x86 rows and 21 independently reachable word-shift seeds plus 17 ARM rows and
two vector-shift seeds. The separate reviewed `vex_modern_crypto.hex` x86 seed
covers the existing
vector-crypto path. Those are preserved as historical 11.8 increments. Version
11.9 adds 40 x86 rows and seven rotate
seeds plus 18 ARM rows and two immediate-shift seeds. Version 11.10 adds 43
x86 rows and seven immediate-rotate seeds plus 27 ARM rows and two integer-
compare seeds. Version 11.11 adds 32 x86 rows and six immediate-shift seeds,
plus 16 ARM rows and three signed/unsigned/reserved integer
compare-with-immediate seeds. Version 11.12 adds seven x86 rows and three
immediate-shift-group seeds, plus 14 ARM rows and two floating-compare-zero
seeds. Version 11.13 adds 27 x86 rows and six double-shift seeds, plus 17 ARM
rows and four floating vector-compare seeds. Version 11.14 adds 36 x86 rows
and 17 COMPRESS/EXPAND/BITALG/VPOPCNT seeds, plus 22 ARM rows and five
predicated FP-binary seeds. Version 11.15 adds 24 x86 rows
and six AVX-512CD seeds, plus 14 ARM rows and two floating-point fast-reduction
seeds. Version 11.16 adds 21 x86 rows and two mask-broadcast seeds, plus ten
ARM rows and two serial-reduction seeds. Version 11.17 adds 23 x86 rows and
six VNNI seeds, plus 25 ARM rows and six predicated FP-unary seeds. Version
11.18 adds 25 x86 rows and 17 single-encoding VBMI seeds, plus 15 ARM rows and
eight FP-estimate seeds. Version 11.19 adds 13 x86 rows and one net new seed
(four word seeds were renamed), plus 28 ARM rows and 18 Advanced SIMD estimate
seeds. Version 11.20 adds ten x86 rows and six classic VEX AVX-VNNI seeds,
plus 12 ARM rows and eight F64MM Q-element permutation seeds. Version 11.21
adds a 13-row AVX-VNNI-INT8 tranche while removing the now-obsolete classic
pp-neighbor row, for a net increase of 12 x86 rows. It adds ten INT8 seeds
while removing the matching obsolete classic seed, for nine net new files,
plus 17 ARM rows and eight integer-to-FP16 seeds. These inventories do not
claim exhaustive x86 or Arm ISA coverage. Version 11.22 adds 13 x86 rows and
ten AVX-VNNI-INT16 seeds plus 17 ARM rows and eight S/D integer-to-floating
conversion seeds. Version 11.23 adds 15 x86 4VNNIW rows and ten seeds. Its new
baseline ARM conversion-focused material adds 31 rows and 22 seeds; current
totals also include other checked-in deltas, so these increments are not
computed solely by subtracting the documented 11.22 inventories. Version 11.24
adds the complete four-name AVX512_4FMAPS family and exact merging SVE/SME
`BFCVT` encoding. Version 11.25 adds 29 x86 rows and eight named seeds for the
exact AVX512F/AVX10.1 VGETEXP PS/PD/SS/SD tranche, plus one address-prefixed
VEX3 VPSLLVD regression row while reusing its existing seed. It adds a net nine
ARM rows and three seeds: five new BFCVT/BFCVTNT seeds replace two obsolete “unowned”
neighbors. Version 11.26 adds 29 x86 rows and eight seeds for MAP6 PH/SH/BF16
GETEXP, plus 20 ARM rows and seven seeds for the exact SME2/SVE2 pair
`BFCVT`/`BFCVTN` allocations and their allocated/reserved boundaries.
Remaining x86 gaps
include unlisted legacy SIMD/VEX forms, other EVEX and AVX-512 families, and
GETMANT, incomplete AVX10, APX, AMX, crypto, and uncommon
system/control maps. Remaining
ARM gaps include most A32/T32 maps, wider Advanced SIMD/FP outside the exact
fixed-width estimate union, other SVE/SVE2
arithmetic, shift, and comparison classes outside the exact completed masks,
contextual MOVPRFX diagnostics, other conversion variants,
reduction, gather/scatter, and permutation classes,
most SME/SME2 and LSE2/LSE128, and newer architectural extensions. Add a row whenever a decoder regression or new
encoding is fixed, and add a small `.hex` seed when the bytes reach a
substantially new parser path.

The version-11.4 deterministic matrices were replayed through independent
oracles. Intel XED v2026.08.23 and pinned Capstone accepted all 60 legal x86
modular ADD/SUB shapes, and XED rejected all 11 reserved controls in the unit
suite. Pinned Capstone accepted all 20 owned ARM lookup/MOV forms. Its
exhaustive adjacent sweep accepted 54 of the 124 non-MOV selector-14 controls
as other instruction classes, so cdisasm intentionally leaves that residual
unowned; Capstone accepted none of the 128 selector-15 controls, matching the
exact invalid classifier. Neither oracle is linked into cdisasm or generates
its decoder tables.

For version 11.5, Intel XED and pinned Capstone each accept all 96 VEX and all
96 EVEX saturating ADD/SUB wire variants, spanning the 80 distinct operand
shapes plus W/prefix aliases. XED rejects all 72 focused invalid EVEX words:
48 register/memory EVEX.b controls, eight LL=3 controls, eight U=0 controls,
and eight zero-without-mask controls. Capstone rejects 56/72, accepting LL=3
and zeroing with `aaa=0`, so deterministic cdisasm legality follows the
architectural/XED boundary. Pinned Capstone accepts all 16 unique official
`TBLQ` reference encodings, while LLVM 21 reproduces their exact B/H/S/D
bytes. These focused tranche checks are supplemented by the completed final
11.5 matrix: the full strict top-level CTest passed 43/43; final Clang 21.1.6
strict fast matrices passed 39/39 with extra opcodes and formatting enabled,
33/33 with extra opcodes disabled, and 37/37 with formatting disabled and extra
opcodes enabled; and MSVC 19.44 Release shared passed 39/39. The package matrix
passed all 16 shared cells in 1730.31 seconds and all 16 static cells in 1889.55
seconds. Windows overlay integration passed in 106.92 seconds, and the WSL Unix
`DESTDIR` overlay passed in 73.19 seconds. Refreshed WSL2 Clang 14 ASan+UBSan
libFuzzer runs completed 10,000 executions for each x86 and ARM harness with
extra opcodes enabled and 5,000 each with them disabled, using the then-current
109 x86 and 75 ARM reviewed seeds.

For version 11.6, current Intel XED and pinned Capstone each accept all 648
classic EVEX D/Q logical wire forms and all 216 classic EVEX `VPAVGB/W` wire
forms. XED rejects all 80 logical and all 20 average negative controls;
Capstone rejects 48/80 and 12/20 respectively, accepting the LL=3 and
zero-without-mask controls that cdisasm rejects at the architectural/XED
boundary. XED's Diamond Rapids model accepts the two checked APX P0.B4 controls
for each class; the pinned Capstone snapshot accepts 0/2 in each because it
does not implement those APX forms. Pinned Capstone also matches all 74 valid
destructive-predicated SVE operation/width pairs and rejects all 54 reserved
pairs, then matches all 42 fixed-width Advanced SIMD ZIP/UZP/TRN arrangements
and rejects all 22 reserved controls. Neither oracle is linked into cdisasm or
used to generate its tables.

The completed version-11.6 matrix passed 45/45 CTests in a fresh
strict Clang 21.1.6 dual-architecture build, 37/37 semantic tests with extra
opcodes disabled, 41/41 with formatting disabled, and 43/43 in an MSVC 19.44
Release shared build. The installed static package's external C and C++17
consumer passed 8/8, and Windows package-overlay integration completed in
124.51 seconds. WSL2 Clang 14 ASan+UBSan libFuzzer campaigns passed exactly
10,000 executions for x86 with extra opcodes ON and another 10,000 OFF, plus
10,000 for ARM ON and 5,000 OFF. Post-campaign replay covered all 797/724 x86
and 321/255 ARM build-local corpus files.

For version 11.7, Intel XED and pinned Capstone accept all 546/546 canonical
VEX/EVEX variable-shift encodings. XED rejects all 192/192 focused reserved
controls, while Capstone rejects 120/192; cdisasm follows the architectural/XED
legality boundary. XED's Diamond Rapids model accepts all 162/162 enumerated
APX P0.B4 forms and all 216/216 U0 memory forms. Pinned Capstone accepts all
56/56 merge-predicated ARM unary controls and rejects all 24/24 reserved
controls. LLVM 21 accepts all 56/56 zero-predicated controls, rejects all 24/24
reserved controls, and confirms the exact feature gates: `/m` admits SVE or
SME, while `/z` requires SVE2p2 or SME2p2. Neither oracle is linked into
cdisasm or used to generate its tables. These focused results do not imply
complete x86 or ARM coverage.

The final version-11.7 Clang 21.1.6 static dual-architecture extras-ON,
format-ON matrix passed 47/47 non-package CTests: 45 semantic tests plus the
21.08-second subproject and 107.11-second overlay integrations, 132.79 seconds
total. Static dual extras OFF passed 39/39 semantic tests and its previously
completed full run passed 41/41 including integrations; static dual format OFF
with extras ON passed 43/43 semantic tests and its previously completed full
run passed 45/45 including integrations. MSVC 19.44.35224 shared Release passed
45/45 semantic tests. Installed-package validation passed all 16 shared cells
in 1764.07 seconds and all 16 static cells in 1897.99 seconds.

The final WSL2 Clang 14 ASan+UBSan libFuzzer campaigns ran 10,000 executions
per architecture in each build. Extras ON produced x86 `avg 277/s`, `new 781`,
`RSS 112 MB` and ARM `avg 555/s`, `new 410`, `RSS 64 MB`; extras OFF produced
x86 `avg 384/s`, `new 726`, `RSS 103 MB` and ARM `avg 666/s`, `new 328`,
`RSS 58 MB`. Saved regression inputs replayed and clean reruns passed. The
checked-in source seeds remained unchanged at 115 x86 and 80 ARM files.

For version 11.8, current Intel XED and pinned Capstone each accept all 162/162
canonical EVEX word variable-shift encodings. XED rejects all 513/513 focused
reserved controls, while Capstone rejects 405/513 and accepts 108 `LL=3` or
zero-with-`k0` controls. XED's Diamond Rapids model accepts all 108/108
enumerated APX P0.B4 and U0/X4 forms; pinned Capstone accepts 0/108. Pinned
Capstone 6 matches all 33 canonical allocated ARM vector-shift controls and
rejects all 31 canonical reserved controls. Capstone 5 exhaustively agrees on
all 270,336 allocated and 253,952 reserved words, while LLVM 14/21 feature
probes confirm the exact SVE-or-SME routes.

Final version-11.8 runs include focused extra-opcode ON, OFF, and
formatter-disabled suites. A fresh Clang 21.1.6 Release package build passed
47/47 direct tests and all 2/2 subproject/overlay integrations; an MSVC
19.44.35224 x64 shared Release build passed 47/47 direct tests. Installed
packages passed all 16/16 shared feature-matrix cells in 1693.90 seconds and all
16/16 static cells in 1832.75 seconds. ARM ASan+UBSan libFuzzer campaigns ran
10,000 executions with extra opcodes ON and 5,000 with them OFF. Fresh WSL
Clang 14 ASan+UBSan builds each stage exactly 137 reviewed source seeds
(maximum 189 raw bytes). All 21 word-shift files plus the crypto seed replay
22/22 with extra opcodes ON and OFF. Recommended `-max_len=192` campaigns pass
10,000 executions in 32 and 28 seconds respectively and retain 135/128 initial
corpus entries, confirming that older long hexadecimal seeds are normalized and
reachable. The source corpus contains no generated non-`.hex` artifact. This
completes the stable-tree 11.8 package evidence without claiming exhaustive x86
or ARM ISA coverage.

For version 11.9, Intel XED and pinned Capstone each accept all 324/324
canonical EVEX variable packed-rotate forms. XED rejects all 432/432 reserved
controls; Capstone rejects 216/432 and accepts exactly 108 `LL=3` plus 108
zero-with-`k0` controls. XED's Diamond Rapids model accepts all 396/396 APX
forms (108 P0.B4/U1, 144 U0 no-SIB, and 144 U0/X4 SIB), while pinned Capstone
accepts 0/396. Capstone 5 exhaustively agrees on all 524,288 words in the A64
predicated immediate-shift classifier (276,480 allocated and 247,808 reserved)
and matches 1,080/1,080 canonical metadata probes. LLVM 21 accepts the four
baseline operations with SVE alone, all nine with SVE2 or SME, none without a
required feature, and rejects all 23/23 canonical reserved controls.

Native 11.9 validation passed 49/49 direct semantic CTests with extras
and formatting enabled, 43/43 with extras disabled, and 47/47 with formatting
disabled. The two integrations raise the non-package totals to 51/51, 45/45,
and 49/49. MSVC 19.44.35224 x64 shared Release passes 49/49 semantic tests plus
both integrations. Installed packages pass every one of 16 shared and 16
static feature cells in 1,640.30 and 1,777.09 seconds respectively. Fresh WSL2
Clang 14 ASan+UBSan campaigns complete 10,000 executions for x86 extras ON,
x86 extras OFF, ARM extras ON, and ARM extras OFF. They stage exactly 144 x86
or 84 ARM source seeds and report no sanitizer, leak, timeout, assertion, or
crash finding.

For version 11.10, Intel XED v2026.08.23 accepts all 324/324 canonical EVEX
immediate packed-rotate controls and rejects all 432/432 reserved EVEX
controls. Pinned Capstone accepts all 324 canonical controls and all 82,944
imm8 wire values, but permissively accepts 108 `LL=3` and 108 zero-with-`k0`
controls. XED's Diamond Rapids model accepts all 396/396 enumerated APX
P0.B4/U0/X4 forms; pinned Capstone accepts 0/396. XED also fixes the exact
neighboring opcode-`72` extension/W boundary: `/2` W0, `/4` W0/W1, and `/6`
W0 are allocated shift instructions outside this decoder tranche and remain
unsupported; `/2` W1, `/6` W1, and `/3`, `/5`, `/7` at either W value are
reserved and invalid. The focused suite checks every immediate value and all
16 extension/W controls, including truncation after every shared field.

Pinned Capstone matches all 64 operation/width controls in the A64 SVE integer
vector-compare classifier: 54 allocated and 10 reserved. All 54 report flag
updates. Clang 21 accepts representative ordinary and wide-source forms with
either `+sve` or `+sme`. The dedicated cdisasm suite exhausts the complete
8,388,608-word classifier. These are focused independent-oracle results and do
not imply complete x86 or Arm coverage.

For version 11.11, Intel XED v2026.08.23 commit
`0bcb6237345c5066726dcc08b3d87928df3b5b26` and pinned Capstone 6.0.0 commit
`862b59717d54769036f89fd9f780f634e030cf56` accept all 324/324 canonical EVEX
immediate packed-shift controls and all 82,944 imm8 wire values. XED rejects
all 432/432 focused structural-invalid controls. Capstone rejects 216/432 but
accepts 108 `LL=3` and 108 zero-with-`k0` controls. XED's Diamond Rapids model
accepts all 396/396 APX P0.B4/U0/X4 forms; Capstone accepts 0/396. The focused
cdisasm suite covers the full extension/W matrix, all vector lengths and
operand shapes, APX routes, reserved neighbors, every imm8, and truncation.

Pinned Capstone matches all 2,816 legal SVE integer
compare-with-immediate operation/width/immediate combinations. Clang 21.1.6
confirms the `-16`--`15` signed and `0`--`127` unsigned ranges, P0--P7
governing-predicate boundary, and alternative SVE/SME gates. The focused
cdisasm suite exhausts all 12,582,912 owned words: 11,534,336 allocated and
1,048,576 reserved. These are focused independent-oracle results and do not
imply complete x86 or Arm coverage.

For version 11.12, the x86 focused suite classifies all 32 W-by-extension
controls for opcodes `71` and `73` at every imm8: 12 W-expanded allocated
controls produce 3,072 control/immediate pairs, while the other 20 controls
remain reserved for every immediate. Separate cases lock vector lengths,
memory, exact mask/broadcast rules, feature gates, APX routes, and truncation.
The ARM focused suite exhausts all 131,072 words in the floating
compare-with-zero classifier, requiring 73,728 allocated and 57,344 reserved
results plus exact metadata and SVE-or-SME admission. These scoped sweeps do
not imply complete x86 or Arm coverage.

For version 11.13, the x86 focused suite classifies all 16 AVX512VBMI2
map/opcode/W controls as 12 allocated and four reserved. It visits every imm8
for map 3 and locks all vector lengths, masks, memory/broadcast/disp8 behavior,
AVX-512F+VBMI2(+VL) or AVX10.1 admission, APX P0.B4/U0-memory routes, reserved
decorators, formatting, truncation, and extras-OFF ownership. The ARM focused
suite exhausts all 4,194,304 words under `0xff204000/0x65004000`, requiring
2,752,512 allocated and 1,441,792 reserved results for the seven H/S/D
operations, byte/operation-six boundary, exact metadata, endian parity, and
SVE-or-SME admission. These remain bounded classifier claims.

Version-11.10 native validation passes 51/51 direct semantic CTests with extra
opcodes and formatting enabled, 45/45 with extra opcodes disabled, and 49/49
with formatting disabled; the two integrations raise those totals to 53/53,
47/47, and 51/51. Fresh Clang 21.1.6 `-Werror` and MSVC 19.44.35224 `/W4`
shared Release builds each pass 53/53. Installed packages pass all 16/16 shared
cells in 1,669.23 seconds and all 16/16 static cells in 1,812.81 seconds. WSL2
Clang 14 ASan+UBSan campaigns complete 10,000 executions for x86 extras ON,
x86 extras OFF, ARM extras ON, and ARM extras OFF, using 151 reviewed x86 seeds
or 86 reviewed ARM seeds with no sanitizer, leak, timeout, assertion, or crash
finding.

Version-11.11 native validation passes 53/53 direct semantic CTests with extra
opcodes and formatting enabled, 47/47 with extra opcodes disabled, and 51/51
with formatting disabled; the two integrations raise those totals to 55/55,
49/49, and 53/53. Fresh Clang 21.1.6 `-Wall -Wextra -Wpedantic -Werror` and
MSVC 19.44.35224 `/W4` shared Release builds each pass 55/55. Including both
installed-package tests, the three top-level totals are 57/57, 51/51, and
55/55. Every package test passes all 16 shared or 16 static feature cells.
Fresh WSL2 Clang 14 ASan+UBSan campaigns complete 10,000 executions for x86
extras ON, x86 extras OFF, ARM extras ON, and ARM extras OFF, using 157
reviewed x86 seeds or 89 reviewed ARM seeds with no sanitizer, leak, timeout,
assertion, or crash finding.

Version-11.12 final validation passes 58/58 with extras ON and 52/52 with
extras OFF under both MSVC and strict Clang. The new corpus audit confirms
160/91 readable source seeds with raw maxima of 189/24 bytes. Fresh WSL2
Clang 14 ASan+UBSan campaigns complete 10,000 executions for each x86/ARM ×
extras ON/OFF harness, using `-max_len=192` for x86 and `-max_len=64` for ARM,
with no finding. Intel XED comparison has zero mismatches over the 32 new x86
controls and 13 APX routes; pinned Capstone matches all 18 legal ARM controls
and rejects all 14 sampled reserved controls. Installed packages pass every
one of 16 shared cells in 3,744.55 seconds and 16 static cells in 4,102.86
seconds.

Version-11.13 focused x86 checks pass with extras ON, formatting disabled, and
extras OFF; the 1,185-row corpus and readable-seed audit pass, and all six new
double-shift seeds replay under libFuzzer. Eight final-audit regressions cover
mandatory-`66` EVEX maps 2/3 opcodes `70`--`73`: forbidden legacy prefixes and
non-long-mode APX P0.B4 defer legality through the owned
ModRM/SIB/displacement and applicable imm8 bytes, producing `TRUNCATED` for
incomplete forms and `INVALID_INSTRUCTION` for complete forms. They pass
extras ON, extras OFF, no-formatter, and MSVC. The legacy-prefix pairs agree
with XED; no XED parity is claimed for 32-bit B4 because XED rejects at the
EVEX prefix. ARM release validation is complete:
strict focused selections pass 20/20 with extras ON and 20/20 with extras OFF,
and all 36/36 canonical operation/width controls match pinned Capstone. The
strict Clang full CTest matrices pass 60/60 extras-ON/formatter-ON, 54/54
extras-OFF/formatter-ON, and 58/58 extras-ON/formatter-OFF. Native MSVC shared
direct functional/data tests pass 58/58. Intel XED v2026.08.23 has zero
mismatches across 452/452 oracle cases: 412 complete inputs (300 accepted and
112 rejected) plus 40 truncations. All four fresh WSL Clang 14 ASan+UBSan
libFuzzer campaigns (x86/ARM × extras ON/OFF) complete 10,000 runs each without
a finding. The Clang 21.1.6 installed-package end-to-end matrices pass all 16
shared Release cells in 3,586.82 seconds and all 16 static Debug cells in
4,008.22 seconds, with zero failures in either matrix. Both cover
dual/x86/ARM/common-only × formatter ON/OFF × extras ON/OFF, including
build-tree and relocated C/C++ consumers plus component, symbol, and artifact
checks. Shared nested producers used the project's built-in
`-Wall -Wextra -Wpedantic` without a global `-Werror`; every static nested
producer cache contains `-Wall -Wextra -Wpedantic -Werror`. Shared and static
x86/formatter-ON/extras-ON producers were rebuilt and reinstalled into their
relocated prefixes; relinked build-tree and relocated consumers pass 7/7 in
each of the four suites. This targeted confirmation does not change the 16/16
matrix totals.

Version-11.14 seed replay passes all 183 x86 and 100 ARM reviewed inputs with
extra opcodes both enabled and disabled. Four fresh WSL2 Clang 14 libFuzzer
campaigns, instrumented with AddressSanitizer and UndefinedBehaviorSanitizer,
complete 10,000 executions each for x86/ARM × extras ON/OFF. No sanitizer,
leak, timeout, assertion, crash, or generated failure artifact is reported.
The release corpus tests pass all 1,221 x86 and 687 ARM rows in both option
variants, including the new COMPRESS/EXPAND, BITALG/VPOPCNT, and destructive
predicated floating-point binary classes.

Version-11.15 contains 189 reviewed x86 seeds and 102 reviewed ARM seeds, with
1,245 x86 and 701 ARM checked-in opcode rows. Four fresh x86/ARM × extras
ON/OFF Clang 14 ASan+UBSan campaigns completed 10,000 executions each with no
sanitizer finding or failure artifact.

Version-11.16 contains 191 reviewed x86 seeds and 104 reviewed ARM seeds, with
1,266 x86 and 711 ARM opcode rows. The staged ON and OFF fuzz builds contain
those exact seed counts. Four fresh x86/ARM x extras ON/OFF Clang 14
ASan+UBSan campaigns complete 10,000 executions each with no sanitizer, leak,
timeout, assertion, crash, or generated artifact. The direct strict suites
pass 65/65 ON, 60/60 OFF, and 63/63 without formatting; Clang-CL `/W4 /WX`
passes 65/65. Both corpus runners pass every row in both option variants.

Version-11.17 contains 197 reviewed x86 seeds and 110 reviewed ARM seeds, with
1,289 x86 and 736 ARM opcode rows. The deterministic source audit confirms
those exact inventories and raw maxima of 189/60 bytes. Four fresh WSL2 Clang
14 ASan+UBSan campaigns complete 10,000 executions each for x86/ARM x extras
ON/OFF without a sanitizer, leak, timeout, assertion, or crash finding. The
new x86 seeds reach every AVX-512 VNNI dot-product opcode plus broadcast, APX,
and invalid-control paths; the ARM seeds reach both FP-unary predication forms,
both tail masks, reserved controls, and an adjacent unowned control. Strict
native direct suites pass 67/67 ON, 62/62 OFF, and 65/65 without formatting;
Clang-CL `/W4 /WX` passes 67/67.

Version-11.18 contains 214 reviewed x86 seeds and 118 reviewed ARM seeds, with
1,314 x86 and 751 ARM opcode rows. The deterministic source audit confirms
those exact inventories, zero non-`.hex` artifacts, raw maxima of 189/60
bytes, and a 63-byte maximum parsed x86 payload. Four fresh WSL2 Clang 14
ASan+UBSan campaigns complete 10,000 executions each for x86/ARM x extras
ON/OFF, starting from exactly 214/118 reviewed seeds, without a finding.
The new x86 seeds reach VBMI byte permutes, multishift/broadcast, APX,
then-unsupported allocated word siblings, and invalid controls; the ARM seeds
reach both scalable estimate operations and the reserved byte-width boundary.

Version 11.19 contains 215 reviewed x86 seeds and 136 reviewed ARM seeds, with
1,327 x86 and 779 ARM opcode rows. The four former word-sibling seeds are now
named for AVX512BW and reach implemented `VPERMI2W`, `VPERMT2W`, and `VPERMW`;
one new seed adds the APX B4/U0 word route. The 18 new ARM seeds reach every
fixed-width Advanced SIMD scalar/vector estimate arrangement and both reserved
one-lane-D controls. The deterministic source audit confirms the exact 215/136
inventories and no non-`.hex` artifacts. Strict Clang 21.1.6 configurations pass
72/72 with extras and formatting enabled, 67/67 with extras disabled, and 70/70
with formatting disabled. Four WSL2 Clang 14 ASan+UBSan campaigns complete
10,000 executions each for x86 and ARM with extras enabled and disabled, without
a finding. Installed-package validation passes every one of 16 shared Release
cells in 3,722.89 seconds and every one of 16 static Release cells in 4,080.82
seconds across dual/x86/ARM/common-only, formatter ON/OFF, and extras ON/OFF.

Version 11.20 contains 221 reviewed x86 seeds and 144 reviewed ARM seeds, with
1,337 x86 and 791 ARM opcode rows. Six new x86 seeds reach every classic VEX
AVX-VNNI mnemonic plus memory, W=1, and mandatory-prefix boundaries. Eight new
ARM seeds reach every allocated F64MM Q-element permutation selector and both
reserved selectors. The focused ARM suite exhausts the exact 262,144-word
class, split into 196,608 allocated and 65,536 reserved words. These additions
remain bounded coverage and do not make either decoder ISA-complete. Strict
Clang 21.1.6 configurations pass 74/74 tests with extras and formatting
enabled, 69/69 with extras disabled, and 72/72 with formatting disabled. Four
WSL2 Clang 14 ASan+UBSan campaigns complete 10,000 executions for each x86/ARM
x extras ON/OFF combination without a finding. Installed-package validation
also passes every one of 16 shared and 16 static Release feature-matrix cells.

Version 11.21 contains 230 reviewed x86 seeds and 152 reviewed ARM seeds, with
1,349 x86 and 808 ARM opcode rows. Ten AVX-VNNI-INT8 seeds reach all six
mnemonics and their memory, W, opcode/map-neighbor, and truncation boundaries.
The obsolete classic AVX-VNNI pp-neighbor seed was removed, so the x86 seed
inventory grows by nine. Eight ARM seeds reach all six allocated H/S/D-to-H
`SCVTF`/`UCVTF` paths and both reserved selectors. The focused source suites
exhaust 3,072
allocated plus 3,072 reserved x86 controls and 49,152 allocated plus 16,384
reserved ARM words. Strict Clang 21.1.6 Ninja dual-architecture configurations
built with `-Wall -Wextra -Wpedantic -Werror`, with installed-package tests
excluded, pass 76/76 tests with extras and formatting enabled in 227.54 seconds,
71/71 with extras disabled and formatting enabled in 223.05 seconds, and 74/74
with extras enabled and formatting disabled in 411.20 seconds. Their direct
subsets, excluding the two nested CMake integrations, pass 74/74, 69/69, and
72/72. Clang-CL 21.1.6 configuration under `/W4 /WX` succeeds, all 162 targets
build, and 76/76 non-package tests pass in
228.10 seconds. The six strict fuzz translation-unit checks pass. On WSL2,
Clang 14 Unix Makefiles ASan+UBSan libFuzzer campaigns complete 10,000 runs each
for x86 and ARM with extras enabled and disabled; all four exit zero with no
finding and no crash artifacts. Complete sequential installed-package matrices
pass 16/16 shared cells in 3,831.53 seconds and 16/16 static cells in 3,986.38
seconds across dual/x86/ARM/common-only builds, formatter ON/OFF, extras ON/OFF,
build-tree and relocated C/C++ consumers, components, symbols, artifacts, and
static definitions. These checks remain bounded rather than exhaustive.

Version 11.22 contains 240 reviewed x86 seeds and 160 reviewed ARM seeds, with
1,362 x86 and 825 ARM opcode rows. Ten AVX-VNNI-INT16 seeds reach all six
mnemonics, full-memory/SIB forms, W=1, prefix/map neighbors, and truncation.
Eight ARM seeds reach every signed and unsigned S-to-S, D-to-S, S-to-D, and
D-to-D `SCVTF`/`UCVTF` form. The focused source suites exhaust 3,072 allocated
plus 3,072 reserved x86 controls and all 65,536 allocated ARM words in the four
new exact envelopes. Final strict Clang 21.1.6 dual-architecture validation
passes 78/78 tests with extras and formatting enabled, 73/73 with extras
disabled, and 76/76 with extras enabled and formatting disabled. Clang-CL
passes 78/78 under `/W4 /WX`. Four WSL2 Clang 14 ASan+UBSan libFuzzer campaigns
for x86 and ARM with extras enabled and disabled complete 10,000 runs each
successfully. Installed-package matrices pass 16/16 shared cells in 3,696.43
seconds and 16/16 static cells in 4,052.63 seconds. The compiled x86 modern-VEX
table audit reports 149 descriptors and zero lookup-key overlaps; the ARM
modern mask audit reports 94 patterns and zero overlaps. These remain bounded
results, not exhaustive ISA coverage claims.

Version 11.23's source inventories contained 250 reviewed x86 seeds, 186
reviewed ARM seeds, 1,377 x86 rows, and 869 ARM rows. The focused 4VNNIW tranche
contributes 15 rows and ten seeds; the focused baseline ARM conversion tranche
contributes 31 rows and 22 seeds. Deterministic tests exhaust both 4VNNIW
opcodes across all ModRM/W controls and all 204,800 ARM conversion words
(163,840 allocated plus 40,960 reserved), while retaining the BFCVT neighbor as
unowned. The expanded EVEX audit reports 227 descriptors with zero lookup-key
intersections, and the ARM modern mask audit reports 101 patterns with zero
overlaps. Final strict Clang 21.1.6 dual-architecture validation passes 80/80
tests with extras and formatting enabled in 235.68 seconds, 75/75 with extras
disabled in 233.31 seconds, and 78/78 with extras enabled and formatting
disabled in 231.63 seconds. Clang-CL 21 passes 80/80 under `/W4 /WX` in 241.70
seconds. The four WSL2 Clang 14 ASan+UBSan x86/ARM by extras ON/OFF
configurations each complete two fixed-seed 10,000-run libFuzzer passes:
80,000 total executions with no sanitizer finding or crash artifact. Complete
installed-package matrices pass 16/16 shared cells in 3,589.77 seconds and
16/16 static cells in 3,936.32 seconds. These results remain bounded rather
than exhaustive ISA coverage claims.

Version 11.24 focused checks exhaust all 8,192 AVX512_4FMAPS controls as 1,536
allocated and 6,656 rejected controls. ARM checks exhaust all 8,192 words in
the exact merging `BFCVT` class and all 32,768 words in its four-selector
envelope, while retaining the independent 65,536-word baseline `FCVT` sweep.
The expanded EVEX audit reports 231 descriptors with zero lookup-key
intersections, and the ARM modern mask audit reports 102 patterns with zero
overlaps.

Final version-11.24 strict Clang 21.1.6 matrices pass 82/82 with extras and
formatting enabled, 77/77 with extras disabled, and 80/80 with formatting
disabled; their overlay cells take 222.07, 222.04, and 222.01 seconds. A fresh
Clang-CL 21.1.6 x86-64 Release shared build under `/W4 /WX` configures in
29.526 seconds, builds 174/174 without warnings in 196.306 seconds, and passes
82/82 CTests in 192.59 seconds, including the 192.43-second overlay. Its DLL and
import library have the required exports and image version 11.24. Fresh strict
Clang installed-package matrices pass 16/16 shared cells in 3,576.25 seconds
and 16/16 static cells in 3,922.01 seconds; their configure/build phases also
pass at 23.462/205.562 seconds and 21.80/195.74 seconds respectively. Fresh WSL
Ubuntu Clang 14 ASan+UBSan/libFuzzer campaigns replay all 266 x86 and 190 ARM
reviewed seeds in each applicable extras variant, then reach 25,000 units per
x86/ARM-by-extras campaign: 100,000 total units and 99,084 generated after
initialization, with zero sanitizer, runtime, invariant, crash, timeout, OOM,
or leak findings. The fixed REX2 RDSEED reproducer exits successfully and is a
permanent seed. These remain bounded release results, not exhaustive ISA
coverage claims.

Version 11.25 checked-in inventories contain 1,430 x86 rows, 889 ARM rows, 274
x86 seeds, and 193 ARM seeds. The focused VGETEXP suite exhausts 8,192
structural cells as 5,248 valid and 2,944 invalid controls, with separate mask
and 32-value `vvvv`/extension sweeps. Twenty-nine VGETEXP TSV cases and eight
named seeds cover the tranche. The x86 harness also removes thirteen false
exact-prefix-size assumptions (twelve EVEX and one VEX) and now positively
covers legal address-size and segment-prefixed VGETEXP inputs; both focused
seeds replay cleanly under the sanitizer libFuzzer build. Focused extras-ON,
extras-OFF, and formatter-OFF
configurations each pass their three VGETEXP/corpus/seed-audit tests, and the
235-entry EVEX descriptor audit reports zero overlaps. The focused ARM BFCVT/BFCVTNT suite checks
73,728 words: the retained 32,768-control envelope plus 24,576 new allocated and
16,384 new reserved words. The 107-entry ARM modern-pattern audit reports zero
overlaps. Corpus and seed audits confirm the inventories above.

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
passes all 16/16 cells in 3,865.85 seconds, with zero failures. These remain
bounded tranche and release-matrix results, not exhaustive ISA coverage claims.

Version 11.26 checked-in inventories contain 1,459 x86 rows, 909 ARM rows, 282
x86 seeds, and 200 ARM seeds. The focused x86 suite enumerates a 12,288-cell
W/LL/b/ModRM lattice for MAP6 PH/SH/BF16 GETEXP: 3,968 controls are allocated
and 8,320 are reserved. Its separate boundaries cover U, mandatory prefix,
mask, `vvvv`, extensions, CPU/runtime routes, text, truncation, and extras-OFF
ownership. The focused ARM pair-conversion suite enumerates 18,432 words:
16,384 in the SME2 selector domain and 2,048 in the SVE2/SME2 FP8 narrowing
domain. It distinguishes four implemented 512-word forms from
8,704 allocated-but-unsupported siblings and 7,680 reserved SME2 controls,
verifies the independent FP8 gate, and rejects any pair interpretation as
`BFCVTNT`. These
are scoped corpus and focused-test definitions; they do not by themselves
claim final release-wide validation or exhaustive x86/Arm ISA coverage.

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

For version 11.27's SMX/VMX/SVM runtime-family split, fresh WSL2 Clang 14
ASan+UBSan x86 campaigns with extra opcodes enabled and disabled each complete
25,000 units against a fresh copy of all 282 reviewed x86 seeds, with no
finding. The CPU-query regression additionally checks the exact virtualization
subset for all 53 unique x86 profiles in every supported mode.

CMake copies the checked-in seeds for each enabled architecture to that build's
`fuzz-corpus` or `fuzz-arm-corpus` directory when fuzzing is enabled. libFuzzer
adds coverage discoveries to its first corpus directory, so use these
build-local copies as shown above instead of passing a source seed directory as
a writable corpus. Only the reviewed `.hex` seed files are staged or installed;
extensionless libFuzzer discoveries are build-local artifacts, not source seeds.
