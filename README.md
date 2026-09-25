# cdisasm

`cdisasm` 12.0.0 is a C11 structured disassembler for x86 and ARM. It
returns stable numeric instruction, register, operand, access, and
classification metadata, with optional text formatting. The API is stateless,
allocation-free, reentrant, and usable from C or C++.

## Features

- x86 decoding in 16-, 32-, and 64-bit modes
- ARM decoding in A32, T32/Thumb, and A64 modes
- Typed operands, data-flow access, branch targets, and instruction groups
- Named CPU profiles and architecture-specific decode flags
- Intel and AT&T x86 formatting and canonical ARM formatting
- Shared or static library builds

> Neither decoder is ISA-complete or exhaustively validated. Generated
> fallback decoding is attempted only after
> `CDISASM_STATUS_UNSUPPORTED_INSTRUCTION`; it never replaces
> `CDISASM_STATUS_INVALID_INSTRUCTION` or
> `CDISASM_STATUS_TRUNCATED`.

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
| `USE_DISASM_FORMAT` | `ON` | Enable text formatting |
| `USE_EXTRA_OPCODES` | `ON` | Enable extended instruction families |

When embedded with `add_subdirectory()`, use `CDISASM_BUILD_SHARED_LIBS`
to select linkage without changing the parent project's
`BUILD_SHARED_LIBS`.

## Use with CMake

```cmake
find_package(cdisasm 12 CONFIG REQUIRED)
target_link_libraries(my_analyzer PRIVATE cdisasm::cdisasm)
```

Available package components are `common`, `x86`, `arm`, and `format`.
Compatibility targets `cdisasm::cdisasm_x86`, `cdisasm::cdisasm_arm`, and
`cdisasm::cdisasm_format` are available when their features are enabled; all
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
| `<cdisasm/cdisasm_format.h>` | Optional x86 and ARM formatting |
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

Formatter calls return the required character count excluding the terminating
NUL. A `NULL` buffer with size `0` performs a size query.

Some generated numeric data is derived from Intel XED (Apache-2.0) and Arm
AARCHMRS (BSD-3-Clause).

## License

See [LICENSE](LICENSE).
