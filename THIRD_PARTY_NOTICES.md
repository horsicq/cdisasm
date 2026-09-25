# Third-party generated-data notices

cdisasm's decoder and formatter implementations are original C code and do
not link to a third-party disassembly engine. Some checked-in numeric tables,
catalog IDs, and formatter spellings are generated from the authoritative
machine-readable sources identified below.

## Intel XED instruction data

- Project: Intel XED
- Source revision: tag `v2026.08.23`, commit
  `0bcb6237345c5066726dcc08b3d87928df3b5b26`
- Repository: <https://github.com/intelxed/xed>
- License: Apache License 2.0; see `LICENSES/Apache-2.0.txt`

The generated cdisasm data is a transformed, string-separated representation
of XED's instruction database. cdisasm does not compile, link, load, or call
the XED library at runtime.

## Arm AARCHMRS A-profile instruction data

- Project: Arm Architecture Machine Readable Specification (AARCHMRS),
  A-profile FAT
- Source revision: `AARCHMRS_OPENSOURCE_A_profile_FAT-2026-03`, commit
  `47b5446cf08ef6a46c86147c7deb0d56caf99d93`
- Repository:
  <https://kernel.googlesource.com/pub/scm/linux/kernel/git/maz/AARCHMRS/>
- Copyright: 2010-2026 Arm Limited or its affiliates
- License: BSD 3-Clause; see `LICENSES/BSD-3-Clause-Arm.txt`

The checked-in Arm tables are generated only from this openly licensed
AARCHMRS package. The later FEAT_HINTE classifier is a small original
implementation based on publicly documented encoding facts and an independent
review against LLVM's upstream Armv9.6 implementation
(commit `ce787718c3c82255825ebe5f95740c24df55f7d0`); proprietary Arm XML is not
copied into this repository or used as a generated-data input. The official
2026-06 AArch32 release delta was also reviewed: it adds no instruction XML
file over 2026-03, so no A32/T32 allocation needed to be copied or generated.
