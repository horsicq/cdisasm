# cdisasm

A C11 disassembler for x86, ARM and MIPS, with structured instruction data
and optional text formatting. The API is stateless and allocation-free.

- x86 16/32/64-bit, ARM A32/Thumb/A64, and MIPS32/64 decoding.
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

## Build

See [build instructions](docs/BUILD.md).

CMake consumers link `cdisasm::cdisasm`.

See the [public headers](include/cdisasm/),
[coverage tools](tools/coverage/README.md) and
[generated data guide](tools/isa_codegen/README.md).
Licensed under [MIT](LICENSE); generated data has additional
[third-party notices](THIRD_PARTY_NOTICES.md).
