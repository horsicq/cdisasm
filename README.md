# cdisasm

`cdisasm` 12.2.0 is a C11 structured disassembler for x86, ARM, and MIPS. It
returns stable numeric instruction, register, operand, access, and
classification metadata, with optional text formatting. The API is stateless,
allocation-free, reentrant, and usable from C or C++.

## Features

- x86 decoding in 16-, 32-, and 64-bit modes
- ARM decoding in A32, T32/Thumb, and A64 modes
- MIPS I-V and MIPS32/64 Release 1/2/3/5/6, with standard, MIPS16, microMIPS and nanoMIPS encodings in either byte order
- Typed operands, data-flow access, branch targets, and instruction groups
- Named CPU profiles and architecture-specific decode flags
- Intel and AT&T x86 formatting and canonical ARM and MIPS formatting
- Shared or static library builds

> The decoders are not ISA-complete or exhaustively validated. Generated
> fallback decoding never replaces `CDISASM_STATUS_TRUNCATED`.
> MIPS uses exact generated encodings to resolve instruction spaces shared by
> different ISA revisions and explicitly selected processor families.

## Build and install

Requirements: CMake 3.16 or newer and a C11 compiler.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
cmake --install build --config Release --prefix /path/to/cdisasm
```

Main options:

| Option | Default | Purpose |
| --- | --- | --- |
| `BUILD_SHARED_LIBS` | `ON` | Build a shared library |
| `USE_ARCH_X86` | `ON` | Enable the x86 decoder |
| `USE_ARCH_ARM` | `ON` | Enable the ARM decoder |
| `USE_ARCH_MIPS` | `ON` | Enable the MIPS decoder |
| `USE_DISASM_FORMAT` | `ON` | Enable text formatting |
| `USE_EXTRA_OPCODES` | `ON` | Enable extended instruction families |

When embedded with `add_subdirectory()`, use `CDISASM_BUILD_SHARED_LIBS`
to select linkage without changing the parent project's
`BUILD_SHARED_LIBS`.

The architecture and opcode options are compile-time switches, shared by all
three backends. For example:

| Build | `USE_ARCH_X86` | `USE_ARCH_ARM` | `USE_ARCH_MIPS` | `USE_EXTRA_OPCODES` |
| --- | --- | --- | --- | --- |
| MIPS base instructions only | `OFF` | `OFF` | `ON` | `OFF` |
| MIPS with all implemented instructions | `OFF` | `OFF` | `ON` | `ON` |
| All architectures with base instructions | `ON` | `ON` | `ON` | `OFF` |
| All architectures with all implemented instructions | `ON` | `ON` | `ON` | `ON` |

Configure a MIPS-only base library from the cdisasm source directory:

```sh
cmake -S . -B build-mips-base -DUSE_ARCH_X86=OFF -DUSE_ARCH_ARM=OFF -DUSE_ARCH_MIPS=ON -DUSE_EXTRA_OPCODES=OFF
cmake --build build-mips-base --config Release --parallel
```

Use a separate build directory with `-DUSE_EXTRA_OPCODES=ON` for all implemented
MIPS coverage. `USE_DISASM_FORMAT=OFF` independently removes text formatting.
The generated public configuration exposes these switches as numeric `0`/`1`
preprocessor defines. Configure the library itself; changing a consumer's
defines cannot change an already compiled library's features. Disabled
architectures have no decoder code or exported decoder symbols.

For MIPS, the base build retains handwritten integer/system and scalar FPU
decoding and processor-specific legality checks. The extra build adds ASE,
compressed-encoding and vendor opcode tables, including DSP/DSP R2/R3, DSP64,
MIPS16e2, MT, MSA,
MIPS-3D, paired-single, VZ, EVA, XPA, CRC, GINV, SmartMIPS, MCU, MDMX,
Allegrex/VFPU, R5900/MMI and VU0/VU1, original Ingenic MXU, MXU2/MXU3/MXU3.1,
Octeon, Loongson, later MIPS LoongMMI and a bounded LoongASX context subset.
CPU profiles and runtime flags further restrict
the instructions accepted within the compiled coverage.

MIPS uses the same selectable-family model as x86: stable family IDs and masks,
immutable descriptors, CPU/context availability, and context add/remove helpers.
The 38 families include separate MXU, MXU2, MXU3 and MXU3.1 selectors; Loongson
generation selectors, LoongSIMD and LoongASX; and separate R5900 VU0/VU1 selectors.
Adding a family also selects its required parents. Conflicting generations or
VU units are rejected without changing the context. Removing a parent removes
its dependent families and any orphaned Loongson umbrella selection.

Query a decoded instruction with `cdisasm_mips_instruction_family()` or
`cdisasm_mips_instruction_family_mask()`. The `_v2` and `_vu` variants handle V2
records and paired VU issue records. The singular query reports the most specific
family; the mask includes its opcode-family prerequisites. MSA on 3A4000 reports
FPU/MSA; its Loongson processor replay policy stays in V2 `required_flags`.
Base integer instructions report
`CDISASM_MIPS_FAMILY_NONE`. Invalid or modified results return NONE/zero after
strict replay validation. These queries preserve the existing result layouts.
`cdisasm_mips_family_mask_from_flags()` projects capability/selection flags into
family IDs; capability masks can contain alternative generations, while an
active context must select a compatible subset. Runtime selection cannot enable
opcodes removed by the compile-time switches.

## Use with CMake

```cmake
find_package(cdisasm 12 CONFIG REQUIRED)
target_link_libraries(my_analyzer PRIVATE cdisasm::cdisasm)
```

Available package components are `common`, `x86`, `arm`, `mips`, and `format`.
Compatibility targets `cdisasm::cdisasm_x86`, `cdisasm::cdisasm_arm`, and
`cdisasm::cdisasm_mips`, plus `cdisasm::cdisasm_format`, are available when their features are enabled; all
resolve to the same physical library.

Use a separate install prefix for each linkage and feature combination. Static
CMake targets propagate `CDISASM_STATIC`; manual Windows consumers of a
static archive must define it themselves.

## C API

Include the narrowest header needed:

| Header | API |
| --- | --- |
| `<cdisasm/cdisasm_common.h>` | Status, version, CPU groups, generic dispatch, and decode flags |
| `<cdisasm/cdisasm_x86.h>` | x86 modes, profiles, results, and decoding |
| `<cdisasm/cdisasm_arm.h>` | ARM modes, profiles, results, and decoding |
| `<cdisasm/cdisasm_mips.h>` | MIPS revisions, processor profiles, 232-byte results and standard decoding |
| `<cdisasm/cdisasm_mips_v2.h>` | 256-byte results, variable-length decoding and register-effect queries |
| `<cdisasm/cdisasm_format.h>` | Optional x86, ARM, and MIPS formatting |
| `<cdisasm/cdisasm.h>` | Umbrella header for enabled decoders |

A decode returns the consumed byte count on success and `0` on failure. The
result's `last_error_id` contains the corresponding `CDISASM_STATUS_*`
value. `cdisasm_decode()` dispatches from the architecture group in its CPU
ID; use `cdisasm_decode_checked()` when result-size validation is also
required.

Version 12 decoder functions take a pointer to an architecture-specific
64-byte flags object. Passing `NULL` selects the all-zero base policy; it
does not enable every supported instruction family. Query accepted flags with
`cdisasm_x86_cpu_decode_flag_mask()`,
`cdisasm_arm_cpu_decode_flag_mask()`, or
`cdisasm_cpu_decode_flag_mask()`.

MIPS uses a processor-specific default: `NULL` or zero flags select little-endian
input and the implemented families available on the named processor. Use
`CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES` for a base-only allowlist, or add
family bits to select an exact subset. `CDISASM_MIPS_CPU_ANY` always requires
exactly one explicit ISA revision bit. Query accepted MIPS options with
`cdisasm_mips_cpu_decode_flag_mask()`.

Formatter calls return the required character count excluding the terminating
NUL. A `NULL` buffer with size `0` performs a size query.

## MIPS processors and coverage

### Opcode completeness plan

Completeness is measured against a versioned instruction inventory for each ISA,
ASE and named processor. A mnemonic count alone is insufficient: operand forms,
encoding variants, aliases and processor legality must be accounted for separately.
The denominator must come from the complete manufacturer instruction/allocation
tables, reconciled with a pinned independent toolchain. A compiler's supported
subset alone cannot define architectural completeness.

Implementation checkpoint, 2026-10-22: the checked-in MXU vector manifest has
364 MXU2 and 496 MXU3/3.1 typed forms. Of the latter, 489 are shared, four are
MXU3-only and three are MXU3.1-only. The later MIPS LoongMMI manifest has 80 forms,
and the VU manifest lists 134 macro forms, 95 upper forms and 69 lower forms,
with unit restrictions and typed LOI. Independent tests retain 17,945 MXU vendor
witnesses, 882 VU literal words and 80 externally assembled LoongMMI words.
Full and base MIPS configurations pass 19 suites each; the build without
formatting passes 18 applicable suites. The prior eight static/shared,
formatter/no-formatter, base/extra installed C/C++ package cells pass.
The standard audit also corrected WAIT's 19-bit code domain and Release 6
RDHWR's PerfCtr selector domain beyond the compiler's zero-filled witnesses.

Retained validation is now available for those two encoding-domain corrections.
The runner rebuilds and executes their native test, retains the library/test
binary hashes, and binds the results to the MIPS and shared runtime sources.
It checks 440 WAIT cases, 128 RDHWR cases and 890 rejected encodings/profiles.
A build without formatting records partial evidence; separate partial builds
cannot be combined to invent a complete run. From the library source directory:

```sh
python -B tools/coverage/run_mips_evidence.py --build-dir <standalone-cmake-build> --output <evidence.json>
python -B tools/coverage/mips_coverage.py --runtime-evidence <evidence.json> --output-dir <report-directory> --require-complete system_domains
```

This gate certifies the two bounded corrections. Other forms still need their
own retained validation reports and architectural inventory reconciliation.

These finite catalog checks do not establish complete architectural validation.
MXU3 has a bounded manufacturer compiler alias contract described below;
higher VWR selectors, VSR aliases and implicit floating-point control effects
still need architectural evidence.
Custom MIPS LoongSX and the complete LoongASX encoding inventory remain
unresolved; LoongArch LSX/LASX tables cannot fill that gap. Alongside the
documented 3A4000 MSA slice, a bounded MIPS LoongASX kernel-context subset is
available through an explicit family selection, described below.

The parallel vendor audit corrected 64 MXU3 register accesses: 63 destinations
consume or preserve their old value, and MXSUM exchanges its VSR operand.
The 496-row effect audit retains 1,011 primary signature constraints across
440 forms, with independent vendor compiler dataflow checks for the corrections.
Implicit control effects and physical aliases remain explicit verification
blockers. Passing numeric decode tests cannot clear those source-level gaps.

The 2026-10-22 follow-up establishes a bounded compiler contract for `VW0` through
`VW15`: manufacturer-generated transfers use word slots 0 through 15 of `VR31`.
Nine VWR forms now retain the encoded resource and add a conservative whole
`VR31` dependency: read for reads, read/write for partial writes. These effects
use the existing ABI; they do not claim exact lane masks in the effect record.
Independent numeric tests cover 199 alias and boundary words. Selectors 16–31
and VSR relationships remain unresolved, as do implicit FP controls.
The initial VWR effect audit constrained 442 forms; the backend audit below
extends that coverage to 455 forms.
An additional 154 manufacturer-derived kernel context words verify vector
halves, VSR transfers and the saved 32-bit control selector 31.

The original 61 excluded Allegrex patterns now have a classification ledger.
Published PSP 6.61 hardware observations support typed syntax for six forms:
`vdot.s`, `vhdp.s`, `vdet.s`, `vdet.t`, `vdet.q` and `vmmul.s`.
An independent source-schema review adds 29 further forms, including unusual
rotation, scaling, sorting, reduction and scalar-matrix widths. The typed
Allegrex catalog now contains 308 forms. Of the original 61 patterns, 35 have
typed syntax and 26 remain unresolved. Only six have the bounded hardware
observations above; source-defined syntax does not establish complete hardware
semantics. A further 30 captured matrix words
cover wrapping matrix origins and physical scalar footprints, including 26
previously rejected operand-domain cases. Their existing public form IDs remain
unchanged. Custom MIPS LoongSX1/LoongSX2/LoongASX
research has three separate family records with unknown opcode counts, pinned
sources and probe observations. LoongSX1/2 remain unallocated; five sourced
LoongASX context recipes use the appended family 38 without changing existing
family IDs.

The exact hardware-observed `vrnds.s` word `0xd0200004` is also accepted under
existing form 40173; other uncaptured unused-bit combinations are not inferred.
Two exact packed-conversion words, `0xd0388081` and `0xd0398081`, also decode
using the existing `vuc2i.s` and `vc2i.s` operand recipes. Their source wrappers,
four-input expected results and linked PRX instruction sequences agree. These
are source-bound test aliases with architectural signoff still open; adjacent
encodings and the broader `.q` patterns are not enabled.
There are 311 runtime recipes for 308 typed Allegrex catalog forms. The 55
patterns without hardware observations retain a physical-PSP capture program, three input scenarios
and a source-bound observation importer. Build it from `tests/hardware/allegrex`
with PSPSDK; run one selected case and scenario at a time. The host bridge and
independently assembled helpers are checked, but actual PSPSDK linking and
device execution have not been performed. Captures remain unreviewed evidence
until their semantics are assessed; collection does not automatically enable
opcodes.

The new pattern-inspection API exposes all 61 original source masks, candidate
identities and structural field slices. It is separate from typed decoding and
does not assign unknown architectural operands or effects. The 26 unresolved
patterns comprise 17 packed conversions, five butterfly widths, three VRNDS
widths and one LV.Q option. Exact conversion aliases remain bounded as above.
`cdisasm_mips_allegrex_pattern_count/get/find/field_value` require MIPS support;
their optional catalog is empty when `USE_EXTRA_OPCODES=0`. With formatting
enabled, `cdisasm_mips_allegrex_pattern_format` emits a `.word` directive with
the candidate name, encoded fields and confidence. CXDisasm exposes this through
`--show-mips-patterns` with standard MIPS32 and Allegrex explicitly selected.

For custom MIPS LoongSX/LoongASX, the follow-up retains an audit of 214 MIPS files
from official source drops and observations from the official binary toolchain.
The source declares extension identities without usable SX/ASX opcode entries;
the binary observations do not supply the missing operand definitions. These
facts and their hashes are linked into the LoongSIMD manifest. Raw probe words
also have ordinary meanings in other MIPS revisions, covered by namespace tests.

Three additional observation tools address the remaining vendor gaps. The
higher-alias generator `tools/isa_codegen/probe_mips_mxu_alias_capture.py`
builds a freestanding Linux O32 executable with 73 isolated baseline/VWR/VSR
cases and full VR/VSR snapshots. Its importer requires the exact generated
manifest and executable, transparent baseline snapshots and successful low16
controls. The target ELF and all 73 embedded words have been checked; it has
not been executed on hardware.

`tools/isa_codegen/probe_mips_mxu_fp.py` generates 26 existing MXU3 FP operation
wrappers and 11 raw input scenarios. It captures raw MCS31 and scalar FCSR31
before and after one selected operation, with ambient controls by default.
MCS31 has no inferred FP bit meanings. The freestanding target ELF has been
compiled, linked and checked for the target/snapshot ordering. See
`tests/hardware/mxu_fp/README.md` for generation, build and capture commands.
The custom Loongson kit in `tools/probes/mips_loong_vectors` observes only three
literal feature-probe words, each with two scalar initializations and a NOP
baseline. Its MIPS n64 sources have been target compiled in both byte orders;
vector upper lanes and custom banks remain unobserved. Candidate bit flips are
listed without execution. No target hardware run is claimed for either kit.

After a probe-specific importer has produced an observation report, retain it
beside the coverage ledger with its exact manifest:

```sh
python -B tools/coverage/mips_coverage.py --hardware-observations <capture.json> --hardware-manifest <capture-manifest.json> --output-dir <report-directory>
```

This checks generator/manifest identity and the permitted word list. Device
identity and executed-binary provenance remain operator-supplied. Retention
does not alter form counts, families, legality, validation status or unresolved
effects. Higher aliases, implicit FP semantics and custom SX/ASX encoding
definitions beyond the bounded kernel subset still require architectural evidence.

The primary Loongnix kernel sources establish five bounded MIPS LoongASX
recipes: `xvld.b`, `xvst.b`, `xinsert.d`, `xvseli.d` and `xvcopy.s.d`. Select
`CDISASM_MIPS_DECODE_FLAG_LOONGASX` with `FPU` and `LOONGSON`, or add
`CDISASM_MIPS_FAMILY_LOONGASX` to a decode context. It supports 64-bit MIPS64R2
with FR=1, explicitly selected on CPU_ANY or the 3A4000 profile. It is disabled
by default. The active MSA and LoongMMI families are independent selections.
`USE_EXTRA_OPCODES=0` excludes these recipes; `USE_ARCH_MIPS` retains its usual
architecture gate.

This subset exposes 32 logical 256-bit registers, formatted as `$lasx0` through
`$lasx31`. The spellings normalize kernel macro names and numeric registers;
they do not claim vendor assembler syntax. Memory forms retain base GPR1 and
32-byte-aligned signed 10-bit byte displacements. Insert forms retain source
GPR1 and upper doubleword lanes 2/3. Select forms retain source register 0,
destinations 1–31 and patterns `0xc`/`0xe`. The former preserves the lower128
bits and selects the upper128 from source0; the latter preserves the lower64
and selects the upper192. The `0xe` case follows a separate vendor kernel
compatible-mode initialization sequence. Other selector patterns remain unclassified.
Copy syntax uses a fixed GPR1 destination, all 32 vector sources and upper
doubleword lanes 2/3. It conservatively records a full vector read and an
eight-byte scalar write. Low lanes 0/1 retain ordinary MSA COPY_S.D decoding.
Other operand domains, macro-only `xvsd`, wider physical aliases and implicit
controls remain unverified. The XVSD mnemonic slot remains vocabulary rather
than an implemented form.

The compiler-source follow-up also binds the manufacturer GCC7.2 and GCC12.1
register models and all 26 FP operation patterns. Both compiler versions model
16 word resources and corroborate the existing VW0–15 compiler transfers; they
do not establish encoded VW16–31 hardware aliases. FP patterns omit implicit
control dependencies, which does not prove architectural independence. The FP
capture importer can additionally emit paired raw-control comparisons with
`--analysis-output`; observed bit/output differences never promote runtime
effects or infer control-bit meanings.

The backend effect audit now constrains 455 of the 496 MXU3/3.1 forms.
Three MXU3.1 shuffles and four basic LU loads preserve destination contents;
their destinations are read/write. Eight basic LU/SU forms postincrement a
32-bit base register, now exposed as a read/write register effect. Kernel
context words corroborate MFSUM/MTSUM transfer directions and widths. Forty
other update/scatter forms and NNCMD still lack explicit-effect definitions;
higher aliases and hidden controls retain their existing uncertainty.
The original-MXU D32ADD recipe also preserves the carry-control register through
a read/write effect: only selected LC/RC bits change, while other control fields
survive. Two XR0 destinations still produce no control-register effect.

The custom-vector source auditor pins eight current LoongASX kernel macros,
168 scoped calls and 2,270 numeric observations, plus the 2019 vendor pattern
`0xe` caller contract. XVSD has an unresolved field overlap:
32 register arguments produce only 16 different words. This ambiguity prevents
promotion of that macro-only record. Upper-lane XVCOPY has unambiguous source
fields, while its low lanes preserve the ordinary MSA identity. Allegrex source
review resolves 29 syntax recipes without promoting hardware or full-semantics
signoff; the 26 unresolved syntax patterns remain visible in the inspection API.

#### Immediate focus: three parallel workstreams

1. **MXU3/3.1 effects:** the known 114 original-MXU, 364 MXU2 and 496
   MXU3/3.1 source opcode rows already have typed decoding. Finish explicit
   effects for 40 update/scatter forms and NNCMD. Establish implicit controls
   for the 26 FP operations and higher VW/VSR aliases. Obtain primary
   definitions for VR/VWR/VSR/MCS physical relationships, accumulator preservation,
   saturation/exception state and implicit floating-point controls. Produce a
   sourced register-alias graph and per-form read/write/preserve table. Extend
   the existing facts, generator and native effects helper only where the
   semantics are established; keep unknown effects visible in verification
   metadata. Validate register overlap, lane selection, accumulators, control
   transfers, floating-point cases and generation differences with independent
   observations. Completion requires verified explicit and implicit effects for
   every form in the declared catalog.

2. **Custom MIPS Loongson vectors:** resolve XVSD's overlapping register bits
   and extend the five implemented ASX recipes where additional operand domains
   are established. Obtain exact numeric allocation tables or
   vendor encoder/disassembler evidence for LoongSX1, LoongSX2 and LoongASX.
   Freeze a separate instruction inventory and processor/generation matrix;
   then implement typed registers, lanes, immediates, memory operands, formatting
   and effects. Establish collisions and ownership against MSA, LoongMMI and
   ordinary coprocessor spaces. Add distinct public families and dependencies
   when supported by the references, preserving the existing 38 IDs and checking
   the remaining flag/form budget first. MIPS custom vectors require their own
   encoding evidence; LoongArch LSX/LASX encodings are a different backend.
   The reference inventory is a prerequisite for implementing these new forms.

3. **The remaining 26 Allegrex patterns:** resolve 17 packed conversions,
   five butterfly widths, three VRNDS widths and the `lv.q` cache-option variant,
   retaining original masks/values, sources and numeric witnesses. Resolve each as a
   supported form, canonical alias, reserved/restricted encoding, importer
   artifact or unresolved pattern using architectural references and independent
   observations. Implement any proven supported forms in the existing Allegrex
   family; add rejection tests for proven reserved encodings and canonical tests
   for aliases. GNU objdump currently rejects all 61 while positive controls
   decode; that observation alone leaves their hardware status unverified.
   Completion requires evidence-backed classification of all original 61, with every
   supported form implemented and all unresolved rows still blocking signoff.

All three tracks must attach source-bound evidence to the unified ledger and
test public family IDs/masks, parent dependencies, processor/revision legality,
enabled/disabled/unavailable statuses, both byte orders, formatting and effects.
Retain MIPS-only/base/full compile choices and installed C/C++ checks. Review
first the source facts and classification, then lowering/metadata changes, and
finally the per-form validation reports. Certify each named catalog separately
when its unsupported and unverified counts reach zero.

#### Follow-on roadmap

The next milestone starts from the integrated catalogs and family APIs above.
The ledger currently contains 6,773 records across 18 overlapping catalogs.
The 594 formerly unbound LLVM records are reconciled: 588 bind to exact
handwritten handlers, two microMIPS templates bind to all sixteen concrete
condition recipes, and four MIPS16 Save/Restore entries are compiler-only
placeholders with no architectural operand schema. The latter remain visible
as artifacts, separate from aliases and illegal encodings. All 2,134 concrete
LLVM catalog records now have source bindings; this is implementation inventory
coverage, not architectural completion. The LLVM binding suite retains 633
numeric probes in both byte orders as partial per-form evidence; it does not
certify complete operands, effects, formatting or legality. Full catalog
signoff remains open.
Allegrex's original 61 excluded source patterns comprise 60 width variants and
one `lv.q` cache-option variant. Six have hardware-observed typed syntax and 29
have independently reconciled source-defined syntax. The remaining 26 are
inspection-only; 55 still lack hardware observations. Confidence limits remain
explicit for every pattern.
Independent toolchain rejection alone does not establish hardware illegality.

| Priority | Next addition | Acceptance criterion |
| --- | --- | --- |
| 0 | Retained per-form validation reports | Test runners emit source-bound evidence for decode, operands, text, effects, legality, both byte orders and disabled-family behavior; import reports into the ledger without promoting partial observations to full signoff |
| 1 | Complete inventory reconciliation | Maintain the reviewed LLVM bindings/classifications; resolve remaining Allegrex legality/semantics gaps; pin manufacturer instruction/allocation indexes for each declared catalog; produce a reviewed list of actual missing forms |
| 2 | Standard encoding-domain completion | Audit MIPS I–V and MIPS32/64 R1/R2/R3/R5/R6 beyond zero-filled witnesses: COP0/COP1/COP2/COP3 fields, implementation codes, selectors, revision removals, register widths and reserved combinations; implement verified omissions |
| 3 | ASE form and family completion | Audit FPU/paired-single, MIPS-3D, MDMX, DSP R1/R2/R3/DSP64, MT, MSA, VZ, EVA, XPA, SmartMIPS, MCU, CRC and GINV; bind each form to its public family/mask, dependencies, processor/revision and compile class |
| 4 | Compressed encoding-domain completion | Reconcile MIPS16/e2, microMIPS and nanoMIPS manufacturer tables; validate length/prefix handling, endian parcels, register lists, stack effects, branch targets and malformed/truncated streams |
| 5 | Remaining vendor forms and semantics | Obtain primary numeric definitions for custom MIPS LoongSX/LoongASX, MXU3 physical aliases and implicit FP controls; reconcile vendor allocation tables with existing MXU/LoongMMI/R5900/VU/Octeon catalogs and implement proven omissions |
| 6 | Capacity for further catalogs | Centralize form-range allocation and dispatch, preserve published identities, and design versioned wider form/feature/replay metadata before existing limits are crossed |
| 7 | Automated family and release gates | Exercise all 38 families across supported processor/revision/mode/FR states, including dependency/conflict transactions and enabled/disabled/unavailable statuses; retain the existing build/package matrix and require complete evidence for each catalog claimed complete |

Run the immediate batch as four parallel tracks: Allegrex's 26 unresolved
patterns, MXU effects and aliases, custom Loongson inventories, and retained
validation plus capacity planning. Each vendor track must deliver an exact
source-backed definition or classification, native lowering where supported,
independent operand/domain witnesses and updated coverage records. The
validation track extends retained reports to all seven required dimensions
without equating structural pattern recognition with typed opcode support.

Then run the wider architecture audit as four parallel tracks:

- **Evidence and infrastructure:** implement priority 0, resolve source bindings,
  generate family/namespace audits and prepare the metadata capacity design.
  Deliver reproducible reports and CI gates first so the other tracks can attach
  evidence as they implement forms.
- **Standard and ASE:** reconcile manufacturer indexes, audit operand domains and
  implement omissions from priorities 2–3. Deliver reviewed numeric facts,
  independent boundary witnesses, typed lowering and exact family requirements.
- **Compressed encodings:** complete priority 4, validating the reconciled
  templates and retaining compiler-only Save/Restore artifacts separately.
  Deliver framing, operand, effect
  and malformed-input evidence for every concrete form.
- **Vendor catalogs:** resolve the remaining primary-reference questions,
  classify the 61 Allegrex patterns, audit vendor domains and add verified forms.
  Deliver explicit processor/generation restrictions and retain unresolved
  encodings or effects as research gaps.

Use three review milestones: first a reconciled catalog and missing-form list;
then implementation with independent operand/domain witnesses; finally retained
per-form validation and a passing catalog completion gate. Existing MXU3/VU
lowering, family APIs and package integration do not need to be recreated.

Before expanding the public vocabulary further, budget the numeric namespaces.
The current mnemonic appender reserves IDs below 4096, form IDs are 16-bit with
vendor ranges near 65000, and decode option word 0 has only bits 62 and 63
unallocated.
The current vocabulary uses 3,434 slots and the highest assigned form is 64,999.
Allocate remaining ranges centrally and check collisions automatically. A wider
feature design must also preserve complete replay requirements: V2 currently
retains one 64-bit `required_flags` word. Design versioned larger form/feature
descriptors and a compatible replay envelope before crossing those limits;
preserve existing numeric identities and V1/V2 structure layouts. Replace
hardcoded range dispatch with a common allocation/descriptor source as needed.

The generated `tools/data/mips/unified_coverage.tsv` ledger has one row per
catalog record, recording
its catalog/revision/processor, mask/value, operand recipe, required families,
compile class, implementation status, source hash, independent witness and
validation results. Track runtime family disabling separately from missing
implementation. Required tests include both byte orders, legal FR states,
register/immediate boundaries, revision collisions, reserved-bit rejection,
transactional failures, format replay, register effects and branch targets.
Existing `inventory_only` records are unmerged evidence, not a missing-opcode
count: the native inventory report currently credits generated supplements
without incorporating all handwritten decoders. Reconcile those records before
using them to prioritize implementation or calculate coverage percentages.
Regenerate it with `python tools/coverage/mips_coverage.py`; use `--check` in CI.
The `cdisasm_check_mips_coverage` CMake target is available when
`CDISASM_VERIFY_GENERATED=ON`. `--require-complete CATALOG` separately enforces
the release gate and fails while implementation or independent per-form
validation is incomplete. Counts from overlapping catalogs must not be added
to produce an ISA coverage percentage.

The standard and ASE audits can run independently of the three vendor tracks.
A catalog is opcode-complete only when its unsupported and unverified concrete
form counts are zero. Assembler macros, pseudos and canonical aliases are tracked
separately; they must not inflate the implemented opcode count.
Keep unverified numeric encodings visible in the inventory; do not infer them
from a mnemonic or accept experimental tables with overlapping operand fields.
LoongArch is a separate architecture and requires its own backend. Arbitrary
application-defined coprocessor operations need an explicitly supplied catalog.

| Profiles | ISA | Optional decoding families |
| --- | --- | --- |
| R3000 | MIPS I | Integer core |
| R4000 | MIPS III | Integer core and FPU |
| 4Kc | MIPS32 Release 1 | Integer core |
| 24Kc / 24Kf | MIPS32 Release 2 | FPU on 24Kf |
| 5Kc / 5Kf | MIPS64 Release 1 | FPU on 5Kf |
| 24KEc, 34Kc, 34Kn, 74Kc, 1004Kc | MIPS32 Release 2 | DSP on 24KEc/34Kc/74Kc/1004Kc; DSP R2 on 74Kc; MT on 34Kc/34Kn/1004Kc |
| P5600 | MIPS32 Release 5 | Explicit FPU and FPU+MSA variants |
| I6400, I6500, P6600 | MIPS64 Release 6 | Explicit FPU and FPU+MSA variants |
| Allegrex | MIPS32 Release 1 derivative | Single-precision FPU, VFPU and Allegrex scalar extensions |
| R5900 | MIPS III derivative | Single-precision FPU, MMI, 128-bit GPR views and bank-1 accumulators |
| Octeon / Octeon+ | MIPS64 Release 2 derivative | Separate CNMIPS and CNMIPSP selections |
| Loongson 2E / 2F | MIPS III derivative | Explicit generation selectors, MMI and paired-single |

These profiles apply instruction legality and register policies; they do not
emulate processors. Standard opcodes have typed registers, memory, immediates,
control-flow metadata and register-effect queries. Release 6 has separate
collision rules and rejects removed legacy forms. Vendor encoding spaces require
explicit selection, and generic defaults do not silently select a vendor.
Loongson 2E and 2F use distinct selectors because their opcodes differ.
Unsupported encodings never succeed as opaque operands.

The pinned LLVM standard catalog contains 1,351 concrete records; aliases and
compiler-only bundles are classified separately in the inventory. Additional
manufacturer-defined ASE and vendor instructions have independently recorded
numeric facts and witnesses. A matching record witness establishes coverage for
that encoding and configuration, not exhaustive legality or emulation semantics.
Generated inventories and per-form provenance live under `tools/data/mips` and
`tools/isa_codegen/generated`. Original Ingenic MXU uses 17 32-bit resources.
MXU2/MXU3, R5900 VU and later MIPS LoongSIMD have separate catalogs and register
models; their integration and validation status is recorded in the checkpoint
above. The native catalog summary references their individual manifests, and
the unified ledger retains their separate coverage boundaries.
Undocumented custom coprocessor operations are reported as unsupported.

The original API retains its four-byte limit and 232-byte result. Include
`cdisasm_mips_v2.h` and call `cdisasm_mips_decode_v2` for all encodings. Select
exactly one of `CDISASM_MIPS_DECODE_FLAG_MIPS16`, `_MICROMIPS` or `_NANOMIPS`;
with no encoding flag, standard MIPS is selected. The decoder never guesses an
encoding from bytes. nanoMIPS uses mode32/ISA32R6 and supports 16-, 32- and
48-bit instructions. V2 preserves input byte order in `raw_bytes`, keeps the
original result in `.instruction`, and reports minimal replay options in
`required_flags`. `cdisasm_mips_cpu_decode_context_v2` creates an encoding-aware
context. Both register-effect query APIs return the total number of effects,
write up to the caller's capacity and require no allocation. Formatters and
effect queries reject forged records by replaying the numeric decoder. Effects
describe modeled architectural registers; they do not emulate memory, exceptions,
MMU state transitions or processor execution.

GPR width and floating-point register state are independent. MIPS I/II and
MIPS32 Release 1 use paired 32-bit FPRs; later revisions default to 64-bit FPRs. Set
`CDISASM_MIPS_DECODE_FLAG_FPR32` when decoding a pre-Release 6 target running
with paired FPRs. Release 6 and MSA require 64-bit FPR state.

```c
#include <cdisasm/cdisasm_mips.h>
#include <cdisasm/cdisasm_format.h>

const unsigned char code[] = {0x21, 0x40, 0x2a, 0x01};
cdisasm_mips_instruction instruction;
char text[128];
if (cdisasm_mips_decode(CDISASM_MIPS_CPU_4KC, CDISASM_MIPS_MODE_32,
                       code, sizeof(code), 0x1000, NULL, &instruction)) {
    cdisasm_mips_format(&instruction, CDISASM_FORMAT_SYNTAX_MIPS_CANONICAL,
                        text, sizeof(text));
    /* addu $8, $9, $10 */
}
```

The result is a fixed 232-byte structure with six 32-byte operands. It records
numeric instruction/form IDs, normalized instruction bits, access information,
branch targets, delay/compact-branch state, and implicit HI/LO/link effects.
Formatting uses numeric registers and preserves individual instructions.
`cdisasm_mips_decode_with_context()` enforces a context's selected families.

## Generated data

Some generated numeric data is derived from Intel XED (Apache-2.0), Arm
AARCHMRS (BSD-3-Clause), and pinned LLVM MIPS encoding descriptions
(Apache-2.0 with LLVM exception). Their license texts are in [LICENSES](LICENSES/).
MIPS provenance and source hashes are recorded in
`tools/isa_codegen/mips_sources.json`. Check the append-only mnemonic catalog
and bounded DSP table deterministically with:

```sh
python tools/isa_codegen/generate_mips_catalog.py --check
python tools/generate_mips_dsp.py --check
```

The installed runtime has no LLVM or Capstone dependency. Independent fixed
encoding witnesses live in `tests/data/mips_oracles.tsv`.

## License

See [LICENSE](LICENSE).
