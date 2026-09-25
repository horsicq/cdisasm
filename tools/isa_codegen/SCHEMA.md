# Inventory schema and integration boundary

## Arm candidate leaf

`arm_leaves.tsv` normalizes input words as follows: A32 and A64 are 32-bit
little-endian words; T32 is either one 16-bit little-endian halfword or a 32-bit
word formed as `(first_halfword << 16) | second_halfword`. A candidate satisfies
`word & fixed_mask == fixed_value`.

Specific masks are inherited down the AARCHMRS decode tree. A width transition
from the abstract T32 root to a 16-bit subtree resets out-of-width parent bits.
The native lookup buckets candidates, retains source precedence, and then
evaluates condition/assertion metadata. Choosing only the highest
`fixed_bits` count is insufficient where conditions overlap.

The authoritative topology is `arm_tree_nodes.tsv` and the numeric-only
`src/arm/generated/cdisasm_arm_isa_decode.inc`. Each node carries its local and
resolved mask/value, first-child/next-sibling links, a deduplicated inherited
field-binding set and condition/assertion bytecode program IDs. Field operands
are compiled directly to `(start,width)`. The separate formatter include maps
numeric pools to text.

Canonical Arm form IDs are 1-based (`1..6569`); zero is reserved for a
manual/no-upstream-form instruction. Exact `form_to_leaf` and `leaf_to_form`
tables are emitted. Mnemonics use a separate sorted numeric pool so catalog
name-ID joining can happen without placing strings in the decoder core.

## x86 descriptor bucket

The lookup key is the tuple `(encoding_space, map, opcode)` where encoding space
is one of `legacy`, `vex`, `evex`, or `xop`. `x86_buckets.tsv` maps each tuple to
a contiguous range in `x86_descriptors.tsv`.

Each descriptor retains mandatory-prefix, mode, EASZ/EOSZ, ModRM, partial-opcode,
REX.W, REX2, EVEX pp/u/VL, APX ND/NF, CPUID and operand digests. The raw XED
pattern is retained because these fields alone do not resolve every collision.
Fallback generation rejects unclassified pattern tokens rather than defaulting
them to an instruction.

Unique XED IFORM IDs are sorted and 1-based (`1..9001`); zero is reserved for a
manual/no-upstream-form instruction. The numeric-only x86 include supplies an
exact descriptor-to-IFORM map and reverse IFORM spans over descriptor indexes.
IFORM/ICLASS strings exist only in the separate formatter/tooling include.

## Runtime integration and explicit semantic limits

- The x86 fallback compiles the pinned pattern tokens, operand lookup functions,
  ISA_SET admission and generic control/status metadata needed to recognize all
  10,994 descriptor records. It is numeric-only, manual-first and gated by
  `USE_EXTRA_OPCODES`. It is called only for a hand-decoder unsupported result;
  definitive invalid and truncated results retain precedence. The compact
  export omits some register-relation and other late validity assertions, so
  descriptor inventory coverage is not identical to exhaustive
  architectural-validity checking.
- XED `DEFAULT` operands and the syntax-visible `IMPLICIT` subset are lowered to
  the public five-operand ABI. Mask, zeroing, broadcast, rounding and SAE use
  instruction metadata. Suppressed execution-state operands remain omitted;
  syntax-visible BSR0 uses its append-only public register ID; state-sized
  memory/tile operands use the variable-size sentinel; MULTIREG groups retain
  one base-register operand.
- Arm condition and alias-preference ASTs have a wired runtime evaluator behind
  `USE_EXTRA_OPCODES`. Source-specific stateful choices and opaque assembly
  recipes are preserved as unresolved rather than approximated; forms without
  exact fixed-layout operands return unsupported from the public decoder. The
  pinned source has 6,569 null leaf assertion fields and zero non-null
  assertion programs; generation fails on a future AST construct it cannot
  encode.
- Architectural exceptions, constrained-unpredictable behavior, execution
  state, complete legacy-prefix action/ordering, SVE vector-length constraints
  and SME streaming/ZA/ZT state are not fully modeled.

## x86 ICLASS catalog row

`x86_iclass_catalog.tsv` is sorted by exact XED ICLASS token and contains one
row per pinned upstream ICLASS. `xed_index` is that stable sorted position;
`macro_token` and `name_id` are the public cdisasm allocation;
`formatter_mnemonic` is the lowercase `disasm_intel` value from the official
JSON export; `allocation` records whether the ID predates generation or was
appended; and `record_count` is the number of XED encoding records using the
ICLASS.

The ICLASS-to-ID relation is one-to-one even where formatter spellings are the
same. In particular, `PEXTRW` and `PEXTRW_SSE4` remain distinct numeric IDs.
The catalog is allocation metadata only and does not imply that an encoding is
accepted by the hand-written decoder.

## x86 ISA_SET and descriptor-family rows

`x86_isa_sets.tsv` is sorted by the exact, case-sensitive XED `isa_set` token.
`group_id` is the stable public exact-family ID. `decode_bit_id` addresses
`cdisasm_decode_flags.bitmap[decode_bit_id / 64]`, and the redundant bitmap
index/mask columns make the generated value directly auditable. `none` denotes
an existing scalar/core family that requires no optional runtime bit.
`group_allocation` and `bit_allocation` distinguish preserved, exact-alias,
base/no-bit, and appended assignments.

`x86_descriptor_families.tsv` is keyed by contiguous `descriptor_index` and
contains the numeric join needed by the generated fallback: `iform_id`,
`name_id`, `group_id`, and `decode_bit_id`. The trailing exact ICLASS and
ISA_SET text is tooling provenance only. Its C counterpart emits only numeric
`CDISASM_X86_DESCRIPTOR_FAMILY(index, name_id, group_id, bit_id)` rows and uses
`CDISASM_X86_DECODE_BIT_NONE` for the no-bit case.

## x86 CPU ISA_SET profile rows

`x86_cpu_isa_set_profiles.tsv` has one row for every public x86 CPU ordinal,
each of the three decode modes, and every appended exact ISA_SET selector.
`supported` is zero for an unavailable CPU/mode pair and otherwise reflects
the resolved XED chip model or the explicitly named conservative synthetic
profile. `provenance` identifies that source. The runtime include folds these
rows into `[cpu_ordinal][mode_slot][7]` 64-bit words; bitmap 0 remains the
separately reviewed legacy family mask. The dimensions and public CPU
ordinals are generation invariants, not implicit array assumptions.

Generated descriptor admission is an intersection: the descriptor's mode and
legacy scalar prerequisites, the selected caller bit, and the named-CPU bit
must all admit it. The no-bit sentinel is reserved for the seven established
scalar/core sets and does not mean that optional ISA sets bypass CPU checks.

These omissions are recorded in `generated/manifest.json` so downstream code
cannot reasonably mistake inventory presence for decoder completeness.
