# cdisasm

`cdisasm` 12.0.0 is a C11 structured disassembler for x86 and ARM. It
returns stable numeric instruction, register, operand, access, and
classification metadata, with optional text formatting. The API is stateless,
allocation-free, reentrant, and usable from C or C++.

The decoders and formatters are implemented in this project and do not link to
Capstone, LLVM, XED, or another disassembly engine at runtime. Some checked-in
numeric tables are generated from openly licensed Intel XED and Arm AARCHMRS
data; see [Third-party data](#third-party-data).

## Highlights

- x86 decoding in 16-, 32-, and 64-bit modes
- ARM decoding in A32, T32/Thumb, and A64 modes
- Typed operands, data-flow access, branch targets, and instruction groups
- Named CPU profiles and architecture-specific runtime decode flags
- Intel and AT&T x86 formatting, plus canonical ARM formatting
- One shared library or static archive for every enabled API
- Generic dispatch and size-checked generic decoding
- Command-line examples, deterministic corpora, tests, and fuzz harnesses

> Neither decoder is ISA-complete or exhaustively validated. Catalog entries
> and generated coverage data do not by themselves guarantee complete
> legality, operands, or semantics. Generated fallback decoding is attempted
> only after the native decoder reports
> `CDISASM_STATUS_UNSUPPORTED_INSTRUCTION`; it never replaces
> `CDISASM_STATUS_INVALID_INSTRUCTION` or `CDISASM_STATUS_TRUNCATED`.

## Build

Requirements are CMake 3.16 or newer and a C11 compiler. A compact release
build is:

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF \
  -DCDISASM_BUILD_PACKAGE_TESTS=OFF
cmake --build build --config Release --parallel
```

Install it with:

```sh
cmake --install build --config Release --prefix /path/to/cdisasm
```

For development, enable the test suite. Top-level tested builds also enable
generated-source verification by default and require Python 3.10 or newer.

```sh
cmake -S . -B build-test \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON \
  -DCDISASM_BUILD_PACKAGE_TESTS=OFF
cmake --build build-test --config Release --parallel
ctest --test-dir build-test -C Release --output-on-failure
```

### Main CMake options

| Option | Default | Purpose |
| --- | --- | --- |
| `BUILD_SHARED_LIBS` | `ON` | Build a shared library instead of a static archive |
| `USE_ARCH_X86` | `ON` | Build the x86 decoder |
| `USE_ARCH_ARM` | `ON` | Build the ARM decoder |
| `USE_DISASM_FORMAT` | `ON` | Build text formatting for enabled architectures |
| `USE_EXTRA_OPCODES` | `ON` | Build extended instruction families |
| `CDISASM_BUILD_EXAMPLES` | `ON` | Build the command-line examples |
| `BUILD_TESTING` | `ON` | Build the CTest suite |
| `CDISASM_BUILD_FUZZERS` | `OFF` | Build Clang libFuzzer targets |

When embedded with `add_subdirectory()`, use `CDISASM_BUILD_SHARED_LIBS` to
select linkage without changing the parent project's `BUILD_SHARED_LIBS`.
`USE_EXTRA_OPCODES` controls build-time availability; runtime flags and CPU
profiles still decide which instruction families a decode may accept.

## Use with CMake

```cmake
find_package(cdisasm 12 CONFIG REQUIRED)
target_link_libraries(my_analyzer PRIVATE cdisasm::cdisasm)
```

Available package components are `common` (always), `x86`, `arm`, and
`format`. The compatibility targets below exist when their feature is enabled,
but all resolve to the same physical library:

- `cdisasm::cdisasm_x86`
- `cdisasm::cdisasm_arm`
- `cdisasm::cdisasm_format`

Use a separate install prefix for each linkage/feature combination. The
installer records a variant fingerprint and refuses to overlay an incompatible
variant. Static CMake targets propagate `CDISASM_STATIC`; manual Windows
consumers of a static archive must define it themselves.

## Command-line examples

With examples and formatting enabled:

```sh
./build/cdisasm_cli 64 55 48 89 e5 c3
./build/cdisasm_cli 64 --flags 0x100 c5 f8 77
./build/cdisasm_arm_cli a64 1f 20 03 d5 c0 03 5f d6
./build/cdisasm_arm_cli t32 00 bf 70 47
```

Multi-config generators usually place the executables under `build/Release/`.
The complete example sources are
[`examples/cdisasm_cli.c`](examples/cdisasm_cli.c) and
[`examples/cdisasm_arm_cli.c`](examples/cdisasm_arm_cli.c).

## C API

Include the narrowest header needed by the caller:

| Header | API |
| --- | --- |
| `<cdisasm/cdisasm_common.h>` | Status, version, CPU groups, generic dispatch, and decode flags |
| `<cdisasm/cdisasm_x86.h>` | x86 modes, CPU profiles, results, and decoding |
| `<cdisasm/cdisasm_arm.h>` | ARM modes, CPU profiles, results, and decoding |
| `<cdisasm/cdisasm_format.h>` | Optional x86 and ARM formatting |
| `<cdisasm/cdisasm.h>` | Umbrella header for enabled decoders |

The generated `cdisasm_config.h` defines `USE_ARCH_X86`, `USE_ARCH_ARM`,
`USE_DISASM_FORMAT`, and `USE_EXTRA_OPCODES` numerically as `0` or `1`. Test
them with `#if`, not `#ifdef`.

### Decode and format x86

```c
#include <cdisasm/cdisasm_x86.h>
#include <cdisasm/cdisasm_format.h>
#include <stdio.h>

int main(void)
{
    const uint8_t code[] = {0x48, 0x89, 0xe5};
    cdisasm_x86_instruction instruction;
    char text[64];
    size_t length;
    uint32_t size = cdisasm_x86_decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        code, sizeof(code), UINT64_C(0x1000), NULL, &instruction);

    if (size == 0) {
        fprintf(stderr, "%s\n",
                cdisasm_status_string(
                    (cdisasm_status)instruction.last_error_id));
        return 1;
    }

    length = cdisasm_x86_format(
        &instruction, CDISASM_FORMAT_SYNTAX_INTEL, text, sizeof(text));
    if (length == 0 || length >= sizeof(text)) {
        return 1;
    }

    puts(text); /* mov rbp, rsp */
    return 0;
}
```

Use `CDISASM_FORMAT_SYNTAX_ATT` for AT&T syntax. ARM callers use
`cdisasm_arm_decode()` with `CDISASM_ARM_MODE_A32`,
`CDISASM_ARM_MODE_T32`, or `CDISASM_ARM_MODE_A64`, and may format successful
results with `cdisasm_arm_format()`.

A decode returns the consumed byte count on success and `0` on failure. A
typed result then exposes the `CDISASM_STATUS_*` value in `last_error_id`.
`cdisasm_decode()` dispatches from the architecture group in its CPU ID;
generic callers that also need result-size validation should prefer
`cdisasm_decode_checked()`.

### Decode flags and CPU profiles

Version 12 decoder functions take a pointer to an architecture-specific
64-byte flags object containing eight `uint64_t` bitmap words. Passing `NULL`
selects the all-zero base policy; it does **not** enable every supported
instruction family.

Use the published bit IDs and helpers, or query the accepted flags for a CPU
and mode with `cdisasm_x86_cpu_decode_flag_mask()`,
`cdisasm_arm_cpu_decode_flag_mask()`, or
`cdisasm_cpu_decode_flag_mask()`. Reserved bits are rejected.

`cdisasm_current_cpu()` performs best-effort detection of the closest named
profile visible to the calling process. It is advisory, may reflect a VM or
translation layer, and never changes the selected mode or flags automatically.

Formatter calls return the required character count excluding the terminating
NUL. A `NULL` buffer with size `0` performs a size query. Use
`cdisasm_x86_format_mode()` when exact mode-dependent AT&T suffixes matter.

## Documentation and validation

- [API reference](docs/API.md)
- [Apple CPU-profile evidence](docs/APPLE_CPU_EVIDENCE.md)
- [Fuzzing guide](fuzz/README.md)
- [Coverage tooling and evidence](tools/coverage/README.md)
- [ISA code generation](tools/isa_codegen/README.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

Detailed coverage inventories, release evidence, and corpus maintenance notes
live in those documents instead of this README so that this page remains a
user-facing introduction.

## License

cdisasm code is released under the [MIT License](LICENSE).

## Third-party data

Checked-in transformed data derived from Intel XED is licensed under
Apache-2.0. Data derived from the Arm AARCHMRS A-profile package is licensed
under BSD-3-Clause. cdisasm does not compile, link, load, or call either
project at runtime. Pinned revisions, attribution, and license texts are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [LICENSES/](LICENSES/).
