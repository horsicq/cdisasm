# cdisasm

A C11 disassembler for x86, ARM and MIPS, with structured instruction data
and optional text formatting. The API is stateless and allocation-free.

- x86 16/32/64-bit, ARM A32/Thumb/A64, and MIPS32/64 decoding.
- Typed operands, register access, branch targets and CPU profiles.
- Selectable architectures and opcode families; static or shared builds.

Instruction coverage varies by architecture and CPU family.

## Build

See [build instructions](docs/BUILD.md).

CMake consumers link `cdisasm::cdisasm`.

See the [public headers](include/cdisasm/),
[coverage tools](tools/coverage/README.md) and
[generated data guide](tools/isa_codegen/README.md).
Licensed under [MIT](LICENSE); generated data has additional
[third-party notices](THIRD_PARTY_NOTICES.md).
