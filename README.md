# cdisasm

A C11 disassembler for x86, ARM, MIPS, Motorola 68000, PowerPC, and SPU. It
returns structured instructions and can format them as text. Coverage varies
by CPU and instruction set.

```sh
cmake -S . -B build
cmake --build build --config Release
```

Link `cdisasm::cdisasm`. See the [public headers](include/cdisasm/) for the API
and supported CPU profiles.

License: [MIT](LICENSE). See [additional notices](LICENSES/) for generated data.
