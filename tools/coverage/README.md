# Reproducible ISA coverage inventory

This directory measures cdisasm against frozen upstream allocation inventories.
It does **not** claim that a matching mnemonic implements every encoding of that
mnemonic. The TSV/JSON files in this directory are evidence and review data;
runtime tables are generated separately under `../isa_codegen`.

## Frozen inputs

`baselines.json` is the source of truth for revisions and licensing:

- Intel XED tag `v2026.08.23`, commit
  `0bcb6237345c5066726dcc08b3d87928df3b5b26`, Apache-2.0.
- Open AARCHMRS A-profile FAT 2026-03, commit
  `47b5446cf08ef6a46c86147c7deb0d56caf99d93`, BSD-3-Clause.

The available open Arm machine-readable baseline is 2026-03, while the reviewed
manual baseline is 2026-06. The `arm_2026_06_manual_delta.queue` in
`baselines.json` records the completed review: A64 adds FEAT_HINTE, AArch32 adds
no instruction XML file, and HINTE is maintained as an independently verified
manual delta. Automatic form inventory remains tied to the openly licensed
2026-03 AARCHMRS input; do not describe it as a generated 2026-06 inventory.

The generated inventory carries upstream identifiers, masks, feature names and
hashes, not upstream prose or pseudocode. Keep the upstream license notices with
the source checkouts used to regenerate it.

## Generate

Build the pinned XED checkout and create the official metadata export first,
then run from any directory:

```powershell
python C:\src\xed-v2026.08.23\pysrc\xed_to_db.py `
  --xed-dgen C:\src\xed-v2026.08.23\obj\dgen `
  --out C:\tmp\xed_db.json --compact

python tools/coverage/generate_manifest.py `
  --xed-root C:\src\xed-v2026.08.23 `
  --xed-kit C:\src\xed-v2026.08.23\obj\wkit `
  --xed-db C:\tmp\xed_db.json `
  --arm-root C:\src\AARCHMRS-2026-03
```

The script rejects a wrong Git commit or Arm metadata version. For deliberately
exploratory output from another revision, `--allow-source-drift` is available;
such output is marked and must not replace the checked-in baseline.

Only Python's standard library is required. The official `xed_to_db.py` export
supplies all XED decode descriptor records and `xed-dec` maps checked-in x86
byte probes to exact IFORM names. AARCHMRS `Instructions.json` supplies
canonical A32, T32 and A64 leaves, aliases, inherited masks and feature
conditions.

Generator v5 invokes the pinned `xed-dec` example with its native mode
contract: 32-bit legacy mode is the default, while only 16- and 64-bit modes
have explicit command-line switches. This prevents a nonexistent `-32`
argument from turning valid 32-bit corpus witnesses into parse anomalies.
For `EXTRA_OK` x86 rows, the generator also runs the default profile plus
XED's explicit `-mpx` and `-cet` profiles. XED disables those two optional
families by default, so this additional profile evidence is required to map
MPX and CET encodings to their exact IFORMs instead of their architectural
NOP/collision forms. Ordinary `OK` and profile-rejection rows remain
default-profile-only.
ARM witnesses must also match the canonical leaf mnemonic (or one of its
architectural aliases) in addition to its inherited fixed mask. This prevents
overlapping Advanced SIMD masks from crediting unrelated instruction leaves.

XED has more descriptor records than unique IFORM strings: several records can
share an IFORM while differing in pattern, mode or prefix constraints. The
manifest reports both counts. `x86_forms.tsv` is one row per unique IFORM and
its `xed_descriptor_rows` column records multiplicity; the separate
`../isa_codegen/generated/x86_descriptors.tsv` retains every descriptor.

Generated outputs are:

- `generated/manifest.json`: revisions, input hashes, methodology, counts,
  anomalies, ambiguity records, claim boundaries and the manual delta queue.
- `generated/x86_forms.tsv`: one row per XED IFORM.
- `generated/x86_catalog_evidence.tsv`: one deterministic evidence row per
  generated catalog-gap witness. Decode, operand, formatter and legality are
  separate columns; a structural witness never upgrades CPU/feature legality.
- `generated/arm_forms.tsv`: one row per canonical AARCHMRS instruction leaf.

The checked-in x86 inventory can be audited without an upstream checkout:

```powershell
python tools/coverage/check_x86_coverage.py
```

CI uses the strict form of the audit:

```powershell
python tools/coverage/check_x86_coverage.py --strict
```

Strict mode requires every currently catalog-only IFORM to have one matching
ledger row, an exact XED IFORM/length witness, and a passing decoder corpus
contract. It also rejects stale IFORM/extension identities and any ledger row
that claims legality beyond `structural_only`.

The audit checks that the numeric fallback and coverage manifests agree, that
the fallback is actually wired after the hand-written decoder, and that every
pinned IFORM has a generated assignment. It reports catalog-only forms for
review; a missing corpus witness is not silently promoted to exact semantic
coverage.

The report also applies a live corpus overlay. For each catalog-only IFORM,
the exact mode/bytes in `generated/x86_catalog_evidence.tsv` are matched against
successful `OK`/`EXTRA_OK` rows in `tests/data/x86_opcodes.tsv`. Matching forms
are reported as `corpus_reachable` for decoder/formatter accounting, while the
generated-manifest total is printed separately. This keeps the remaining count
moving when new checked-in witnesses are added even when the pinned XED checkout
is unavailable for regenerating `x86_forms.tsv`; the ledger's
`structural_only` legality contract is unchanged.

`x86_forms.tsv.generated_fallback_assignment` is a separate inventory bit. A
true value means the exact IFORM has at least one descriptor in the checked-in
numeric fallback table; it does not upgrade corpus/source evidence or assert
that omitted XED late-validity relations have been reproduced.

Catalog-only x86 families also have an executable structural-probe audit. It
generates one conservative witness for every form that remains unproven in the
static allocation snapshot (currently 2,063 forms spanning AVX-512/APX EVEX,
VEX gathers, legacy/system instructions, and vendor extensions), then runs
those rows through the normal decoder/corpus contract. The live checked-in
corpus overlay resolves all 9,001 pinned IFORMs, so this static probe list is
an audit/provenance input rather than a current missing-coverage count:

```powershell
python tools/generate_x86_gap_probe.py `
  --output $env:TEMP\cdisasm_x86_catalog_gap.tsv `
  --check .\build\cdisasm_opcode_corpus_tests.exe
```

For an independent byte-level witness check, point the same generator at the
pinned XED `xed-dec` executable:

```powershell
python tools/generate_x86_gap_probe.py `
  --output $env:TEMP\cdisasm_x86_catalog_xed.tsv `
  --xed-dec C:\path\to\xed-dec.exe `
  --check .\build\cdisasm_opcode_corpus_tests.exe
```

When the matching `xed.exe` client is available, the same run can add an
independent Intel-text witness check:

```powershell
python tools/generate_x86_gap_probe.py `
  --output $env:TEMP\cdisasm_x86_catalog_xed.tsv `
  --xed-dec C:\path\to\xed-dec.exe `
  --xed-format C:\path\to\xed.exe `
  --operand-output $env:TEMP\cdisasm_x86_operands.tsv `
  --operand-check .\build\cdisasm_x86_operand_contract_tests.exe `
  --format-output $env:TEMP\cdisasm_x86_formats.tsv `
  --format-check .\build\cdisasm_x86_formatter_contract_tests.exe `
  --check .\build\cdisasm_opcode_corpus_tests.exe
```

This verifies that every generated byte sequence decodes to the intended XED
IFORM and that XED reports the exact encoded length.  It is deliberately an
independent witness oracle: it does not claim that every operand relation,
CPU-feature legality rule, or formatter spelling has been proven for the
whole family.  When requested by CMake, the command also emits an operand
sidecar.  The companion C test compares broad explicit register/memory/
immediate kind and access, including mask decorators, VSIB indices, far
pointers, and representable REP-string operands. Other architecture-specific
shapes remain deferred rather than treated as false exactness. CMake exposes the same
opt-in check as `cdisasm_x86_catalog_xed_tests` through the
`CDISASM_XED_DEC` cache path.

The formatter sidecar compares canonicalized Intel text (case, whitespace,
decorator attachment, and VSIB scale-one presentation) for every row whose
operand contract is comparable. Relative branches, documented condition-code
aliases, legacy x87 and far-transfer aliases, reserved prefetch forms, IBHF,
scalar VCVT rounding/SAE placement, VCOM/VUCOM aliases, and EVEX decorator
placement are compared directly. APX DFV decorators are represented in
`cdisasm_instruction.default_flags` and are included in the exact formatter
comparison. CMake enables this additional test as
`cdisasm_x86_catalog_xed_formatter_tests` when both `CDISASM_XED_DEC` and
`CDISASM_XED` are supplied.

The probe is intentionally a separate evidence stream: it proves that the
numeric descriptor and operand path accepts a representative encoding, while
the XED-backed manifest remains the authoritative source for exact byte-level
claims and the optional formatter sidecar records only explicitly comparable
Intel spellings. CMake registers the same check as
`cdisasm_x86_catalog_gap_tests` when extra x86 opcodes and generated-source
verification are enabled.

Generation is deterministic for identical source files and executables. The
manifest intentionally has no wall-clock timestamp.

## Evidence states

| State | Meaning |
| --- | --- |
| `corpus_reachable` | A checked-in successful byte row maps to this exact upstream form. |
| `verified_missing_encoding` | A checked-in unsupported byte row maps uniquely to this allocated upstream form. |
| `corpus_partial` | Different checked-in rows for the same form include both success and unsupported results. |
| `COVERAGE_PROFILE` corpus status | A negative CPU-feature gate witness for bytes already proven by a successful row; it is retained by the runtime corpus but counted as profile evidence rather than a missing encoding. |
| `profile_rejected_probe` | The bytes are recognized but deliberately rejected for the selected CPU/profile. |
| `source_assignment_only` | Hand-written decoder source references the corresponding cdisasm name ID; exact form reachability is unproved. |
| `catalog_only` | Only a public name ID matches. A vocabulary entry is not an implementation. |
| `unmatched_upstream` | No conservative cdisasm name mapping or exact corpus evidence exists. |

XED occasionally uses separate ICLASS spellings for aliases, prefixes, sizes or
extensions. `classifications.json` contains the small reviewed alias and
normalization set; unreviewed fuzzy matching is intentionally forbidden.

Arm byte probes are first converted from their recorded transport order to the
canonical instruction word, honoring the corpus `BIG_ENDIAN` option. A32 and
A64 reverse the complete word; T32 reverses each halfword while retaining
architectural halfword order. The canonical word is then mapped by the
most-specific inherited fixed mask. Ties are recorded as ambiguous and provide
no exact-form evidence. Mask matching does not evaluate the full AARCHMRS
condition/assertion AST, CPU features, unpredictable behavior or
alias-preference expressions. Those limitations are why even an exact probe is
evidence for that byte sequence, not proof of an entire instruction family.

CPU ID, execution mode and cdisasm runtime family flags remain independent
validation axes. A form can be present in this inventory yet correctly rejected
for a particular profile.

The sibling x86 generator now carries every descriptor and exact IFORM from the
pinned XED export into the optional numeric fallback. That closes the allocation
inventory gap, not every semantic-validity gap: this coverage report's corpus
and hand-written-source states remain intentionally independent evidence.
