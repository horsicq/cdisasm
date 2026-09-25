# AARCHMRS generated-decoder boundary

Current generated inventory, schema, and runtime integration are documented in
`../isa_codegen/README.md` and `../isa_codegen/SCHEMA.md`. This file records only
the semantic limits that remain after candidate selection, condition bytecode,
feature expressions, alias preferences, and reviewed operand recipes are wired
behind `USE_EXTRA_OPCODES`.

## Remaining semantic limits

- Source-specific stateful choices and opaque assembly recipes still require
  reviewed lowering before their forms can return complete public operands.
- A32 PC semantics and contextual T32 constraints need conservative handling
  wherever the fixed public inputs cannot represent the required state.
- SVE vector-length constraints, MOVPRFX context, SME streaming/ZA/ZT state,
  and constrained-unpredictable behavior are not fully modeled.
- The pinned source currently has no non-null leaf assertion programs;
  generation deliberately fails if a future assertion cannot be compiled.

The generated selector recognizes the complete pinned leaf inventory, but the
public decoder succeeds only for forms whose operands and validity can be
represented exactly. Opaque or state-dependent forms remain unsupported.
