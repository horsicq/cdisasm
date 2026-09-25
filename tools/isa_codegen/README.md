# Native ISA inventory generator

This directory contains deterministic, offline ISA inventories and the
generators for cdisasm's optional native fallbacks. The generated decoders are
enabled only by `USE_EXTRA_OPCODES`; the hand-written decoders retain priority.

The revisions and licenses are inherited from `../coverage/baselines.json`:
Intel XED `v2026.08.23` (Apache-2.0) and open Arm AARCHMRS A-profile FAT
2026-03 (BSD-3-Clause). Generated data contains identifiers, encoding patterns,
masks and feature-expression ASTs, not architectural prose or pseudocode.

## Generate

The fastest reproducible path uses the official XED JSON exporter once:

```powershell
python C:\src\xed\pysrc\xed_to_db.py `
  --xed-dgen C:\src\xed\obj\dgen `
  --out C:\tmp\xed_db.json --compact

python tools\isa_codegen\generate_native_inventory.py `
  --xed-root C:\src\xed `
  --xed-db C:\tmp\xed_db.json `
  --arm-root C:\src\AARCHMRS
```

Alternatively omit `--xed-db` and pass `--xed-dgen`; the generator invokes the
pinned checkout's official `pysrc/xed_to_db.py`. Commit and metadata mismatches
are rejected unless `--allow-source-drift` is explicitly used for exploration.

Outputs under `generated/` are:

- `arm_leaves.tsv`: canonical A32, T32 and A64 leaves with inherited fixed
  masks/values, mnemonics, feature-condition IDs and provenance.
- `arm_aliases.tsv`: explicit architectural aliases and preference digests.
- `arm_feature_conditions.jsonl`: deduplicated feature-bearing condition ASTs.
- `x86_descriptors.tsv`: XED records sorted by
  `encoding_space/map/opcode`, retaining decode constraints and source pattern.
- `x86_buckets.tsv`: compact key-to-contiguous-descriptor ranges.
- `x86_iforms.tsv`: stable sorted 1-based IFORM IDs; zero is reserved.
- `manifest.json`: exact revisions, input/output hashes, counts, licensing and
  unsupported-compiler boundaries.

## x86 ICLASS/name catalog

The formatter and generated x86 fallback share a separate append-only
ICLASS allocation generated from the same official compact XED JSON export:

```powershell
python tools\isa_codegen\generate_x86_iclass_catalog.py `
  --xed-db C:\tmp\xed_db.json

python tools\isa_codegen\generate_x86_iclass_catalog.py `
  --xed-db C:\tmp\xed_db.json --check
```

The generator verifies the export version, record count, and SHA-256 against
`tools/coverage/baselines.json`. It preserves every pre-existing numeric ID and
alias, allocates missing exact ICLASS tokens after the current last ID, and
requires a one-to-one numeric mapping for all 1,987 pinned ICLASS values.

Its checked-in outputs are:

- `include/cdisasm/cdisasm_x86_iclass_ids.inc`: public append-only numeric IDs
  and their architecture-neutral compatibility macros;
- `src/x86/x86_iclass_mnemonics.inc`: formatter-only string data, never included
  by the decoder;
- `generated/x86_iclass_catalog.tsv`: exact ICLASS-to-token-to-numeric-ID map
  consumed by descriptor-family and fallback generation;
- `generated/x86_iclass_catalog.json`: source hashes, counts, normalization,
  collisions, and generation invariants.

Macro tokens normalize to uppercase C identifiers. A collision receives the
deterministic `_ICLASS` suffix and, only if needed, the shortest unique SHA-256
prefix. Existing aliases are never redefined. Decoder matching is intentionally
not emitted or enabled by this catalog generator.

## x86 ISA_SET/family catalog

The exact family and runtime-selector allocation is generated from the same
pinned JSON after the ICLASS catalog and native descriptor inventory:

```powershell
python tools\isa_codegen\generate_x86_isa_set_catalog.py `
  --xed-db C:\tmp\xed_db.json

python tools\isa_codegen\generate_x86_isa_set_catalog.py `
  --xed-db C:\tmp\xed_db.json --check
```

`generated/x86_isa_sets.tsv` is the authoritative one-row-per-ISA_SET map.
Exact canonical public groups and declared exact aliases retain their IDs;
every other ISA_SET receives an append-only group ID. Existing logical decode
bits retain their 0--63 assignments and new exact selectors occupy later words
of the fixed 512-bit flags object. Seven already-public scalar/core sets retain
the no-bit sentinel so an all-zero flags object keeps its documented meaning.

`generated/x86_descriptor_families.tsv` joins every native descriptor to its
numeric `name_id`, exact `group_id`, and required logical decode-bit ID. The
equivalent string-free X-macro rows are in
`src/x86/generated/cdisasm_x86_descriptor_families.inc`. Public appended constants
are emitted in `include/cdisasm/cdisasm_x86_isa_set_ids.inc` and
`include/cdisasm/cdisasm_x86_isa_set_bits.inc`; the catalog manifest records
source hashes, counts, capacity, and the no-bit sentinel. Generation does not
wire or relax decoder matching.

## x86 named-CPU ISA_SET profiles

The exact-family availability matrix is generated after the ISA_SET catalog
from XED's pinned, processed chip-model database:

```powershell
python tools\isa_codegen\generate_x86_cpu_isa_sets.py `
  --xed-chip-models C:\src\xed\obj\dgen\all-chip-models.txt

python tools\isa_codegen\generate_x86_cpu_isa_sets.py `
  --xed-chip-models C:\src\xed\obj\dgen\all-chip-models.txt --check
```

`src/x86/generated/cdisasm_x86_cpu_isa_set_masks.inc` is the string-free runtime
table indexed by public CPU ordinal, 16/32/64-bit mode slot, and bitmap words
1--7. `generated/x86_cpu_isa_set_profiles.tsv` is the complete auditable
CPU/mode/ISA_SET matrix, including rejected mode rows, and its JSON companion
records source hashes, model provenance, and counts. Existing bitmap-0 policy
remains independently reviewed. Synthetic AMD, abstract AVX10/APX, legacy
coprocessor, and modern low-end profiles are conservative; in particular, the
named Celeron/Pentium no-AVX profiles never inherit AVX merely from chronology.

The public availability query combines the reviewed bitmap-0 mask with this
matrix. Generated matching then checks both the caller's allow bitmap and the
CPU-availability bitmap independently, so selecting a family cannot grant a
CPU capability and selecting a newer CPU cannot bypass caller policy.

`generate_arm_tree.py` additionally emits the authoritative source topology,
deduplicated evaluator bytecode and inherited field bindings as
`arm_tree_*` files, plus two internal includes:

- `src/arm/generated/cdisasm_arm_isa_decode.inc` is consumed by
  `src/arm/arm_generated_decoder.c` behind `USE_EXTRA_OPCODES`. It is numeric-only,
  with source names, fields, mnemonics, features, special symbols and functions
  represented as numeric IDs. `Values.Value` entries are pre-parsed
  `(value, mask, width)` records, including `x` wildcard masks.
- `src/arm/generated/cdisasm_arm_isa_format.inc` holds optional formatter and
  provenance text for validation and tooling.

Check both C shapes with:

```powershell
clang -std=c11 -fsyntax-only tools/isa_codegen/validate_arm_inventory.c
clang -std=c11 -fsyntax-only tools/isa_codegen/validate_x86_inventory.c
```

No wall-clock timestamp is emitted. Identical pinned inputs produce byte-for-byte
identical artifacts.

## Integration and claim boundary

The x86 fallback compiles all 10,994 pinned XED descriptors (9,001 unique
IFORMs) into string-free numeric recognition, operand, control-flow and status
metadata. It runs only after the hand-written decoder returns unsupported;
definitive invalid or truncated results retain precedence. Successful
hand-written decodes can attach an exact generated IFORM identity without
replacing their richer result. Descriptor admission is still the intersection
of mode, named-CPU capability and caller-selected ISA_SET bits.

This is not a claim of complete architectural semantics. The compact XED export
does not carry every late register-relation assertion; suppressed internal
state is not exposed as display operands; a small set of state-sized memory and
tile operands remains variable; and legacy-prefix legality/action metadata is
not yet exhaustive. Generated canonical aliases and formatter spelling can
also differ from another disassembler while the IFORM identity is exact.

The checked-in native manifest records this split explicitly: the x86 descriptor
inventory is wired into the numeric fallback, while the Arm inventory is still
an input to the Arm tree generator. `tools/coverage/check_x86_coverage.py`
audits that status, verifies the descriptor/IFORM counts against the coverage
manifest, and confirms that every pinned x86 IFORM has a generated fallback
assignment. It intentionally reports `catalog_only` forms instead of treating
missing corpus witnesses as a generation failure.

Arm decode conditions and alias preferences are compiled to neutral numeric
bytecode, and the generated candidate selector plus the deterministic assembly
subset are connected behind `USE_EXTRA_OPCODES`. Unresolved operand choices
remain explicitly opaque internally instead of being guessed, and public decode
reports those forms as unsupported rather than returning partial metadata. All
6,569 canonical leaf `assertions` fields in the pinned source are explicitly
null; generation fails if a future non-null assertion cannot be compiled.
Constrained-unpredictable state, SVE vector length and SME streaming/ZA/ZT
state still need reviewed handling.

## ARM mnemonic catalog

`generate_arm_mnemonic_catalog.py` is the smaller, ARM-only catalog generator.
It reads canonical instruction leaves and their explicit architectural aliases
directly from the pinned `Instructions.json`. Existing public IDs and formatter
spellings are retained, including Apple/vendor entries; unseen mnemonics are
appended in bytewise lexical order.

```powershell
python tools\isa_codegen\generate_arm_mnemonic_catalog.py `
  --arm-root C:\src\AARCHMRS

# CI/review mode: fail if any checked-in output is stale.
python tools\isa_codegen\generate_arm_mnemonic_catalog.py `
  --arm-root C:\src\AARCHMRS --check
```

The generated public header and formatter include are compiled into the normal
catalog. `generated/arm_mnemonic_ids.tsv` is the machine-readable text-to-ID
mapping. `src/arm/arm_mnemonic_pool_ids_generated.inc` contains the corresponding
string-free numeric array for a generated decoder: `mnemonic_pool_id` is the
zero-based index of the exact AARCHMRS mnemonic token in bytewise-sorted order,
and `cdisasm_arm_gen_mnemonic_name_ids[CDISASM_ARM_GEN_MNEMONIC_COUNT]`
translates it to the stable public ID. The array is present only when
`USE_EXTRA_OPCODES` is enabled. Catalog generation alone does not make any
encoding decodable.

## ARM assembly grammar and formatter recipes

`generate_arm_assembly_catalog.py` compiles all 3,191 assembly-rule records,
6,569 canonical forms, and 611 explicit aliases from the same pinned source. It
keeps decoder inputs numeric and puts spellings only in the formatter include:

```powershell
python tools\isa_codegen\generate_arm_assembly_catalog.py `
  --arm-root C:\src\AARCHMRS

python tools\isa_codegen\generate_arm_assembly_catalog.py `
  --arm-root C:\src\AARCHMRS --check
```

Top-level test builds also run a source-only guard that compares the recipe
opcode map in the generator with the checked-in C enum. It needs no upstream
checkout and can be invoked directly or through CMake:

```powershell
python tools\isa_codegen\check_arm_recipe_opcodes.py
python tools\isa_codegen\check_arm_recipe_opcodes.py --self-test
cmake --build build --target cdisasm_check_generated
```

Set `CDISASM_ARM_AARCHMRS_ROOT` to the pinned checkout when configuring to add
the complete `cdisasm_check_arm_catalog` target and corresponding CTest. The
full check regenerates every assembly artifact in comparison mode:

```powershell
cmake -S . -B build `
  -DCDISASM_ARM_AARCHMRS_ROOT=C:\src\AARCHMRS
cmake --build build --target cdisasm_check_arm_catalog
```

The generated artifacts are:

- `src/arm/generated/cdisasm_arm_assembly_decode.inc`: numeric rule, binding,
  expression, recipe, alias, and form metadata;
- `src/arm/generated/cdisasm_arm_assembly_format.inc`: formatter-only spelling
  pool;
- `src/arm/generated/cdisasm_arm_leaf_requirements.inc`: conservative per-leaf
  architecture/feature requirements;
- `generated/arm_assembly_opaque.tsv`: exact forms and aliases without direct
  formatter recipes, including an `audit_class` that distinguishes genuinely
  unresolved recipes from assembly-only alias spellings;
- `generated/arm_leaf_requirements.tsv`: auditable requirement derivation;
- `generated/arm_assembly_manifest.json`: source/output hashes, coverage
  counts, and lowering policy.

Direct recipes cover literals, integer fields, reviewed ordered
`encoded_in` bit-fragment concatenations, A32 condition suffixes,
architectural register-31 choices, sign markers, register lists, Thumb expanded
immediates, A64 logical immediates, reviewed right-shift transforms, and
exhaustive fixed-spelling selections. Other concatenations, dynamic choices,
and PC-relative transforms remain opaque until independently implemented.
Published 2026-03
`Rule.disassemble` mappings are null, so partial or dynamic choices without an
independently proven selector remain opaque.
Manifest schema 2 retains `opaque_records` for all non-direct recipes and adds
`actionable_opaque_records` for `unresolved_recipe` entries. The 8 A32/T32
`VRSHR`/`VSHR #0` aliases are `non_invertible_assembly_alias`: their VORR-register
parent encoding has no datatype or shift field, so the typed source spelling
cannot be recovered from bytes. The 8 `VORN` immediate aliases are
`assembly_only_pseudoinstruction`: Arm documents them as source spellings whose
bytes disassemble as canonical VORR/VBIC with a complemented immediate
([Arm Compiler armasm Reference Guide, §4.28](https://documentation-service.arm.com/static/5f3fa899428f7a6b3328fd44)).
These aliases intentionally remain runtime-opaque and do not increase direct
recipe coverage; the byte-determined parent instruction or preferred alias
(for example VMOV) is formatted instead.
Requirements are intentionally strict: A64 requires Armv8-A plus every
`FEAT_*` atom inherited on the source path, which may underaccept an OR but does
not overaccept it. A32/T32 generated fallback remains disabled for named CPU
profiles until an authoritative per-leaf minimum architecture is available;
`CPU_ANY` can still expose the complete generated recognition inventory.

## ARM architectural-alias selector

`generate_arm_alias_catalog.py` compiles the pinned source's alias condition
and preferred-form ASTs into a separate decoder-side table. The runtime changes
`name_id` only when one alias is both valid and uniquely preferred and no
potential competitor depends on unavailable state:

```powershell
python tools\isa_codegen\generate_arm_alias_catalog.py `
  --arm-root C:\src\AARCHMRS

python tools\isa_codegen\generate_arm_alias_catalog.py `
  --arm-root C:\src\AARCHMRS --check
```

`src/arm/generated/cdisasm_arm_alias_decode.inc` is string-free.
`generated/arm_alias_selection.tsv` records predicate evaluation for every
alias, and its manifest pins hashes and counts. All predicates and
preferred-form helpers used by the pinned source are evaluated from numeric
decode fields and capability bits; `InITBlock` is supplied explicitly through
the T32 decode option. A future unsupported helper must remain unresolved rather
than being approximated.
