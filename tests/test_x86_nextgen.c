#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_NAME_TCMMIMFP16PS == UINT16_C(925),
               "next-generation x86 name range start changed");
_Static_assert(CDISASM_X86_NAME_VDIVBF16 == UINT16_C(942),
               "next-generation x86 name range end changed");
_Static_assert(CDISASM_X86_NAME_COUNT >= UINT16_C(943),
               "next-generation x86 name range is incomplete");
_Static_assert(CDISASM_X86_GROUP_AMX_COMPLEX == UINT16_C(98),
               "AMX-COMPLEX group ID changed");
_Static_assert(CDISASM_X86_GROUP_AMX_AVX512 == UINT16_C(101),
               "AMX-AVX512 group ID changed");
_Static_assert(CDISASM_X86_GROUP_ACE_1 == UINT16_C(116),
               "ACE 1 group ID changed");

static int failures;

#if USE_EXTRA_OPCODES
#define STRUCTURAL_FLAGS CDISASM_X86_DECODE_FLAG_ALL
#else
#define STRUCTURAL_FLAGS CDISASM_X86_DECODE_FLAG_BASE
#endif

#define EXPECT(expression)                                                     \
    do {                                                                       \
        if (!(expression)) {                                                   \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",             \
                    __FILE__, __LINE__, #expression);                          \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

typedef struct nextgen_case {
    const char *label;
    const char *mnemonic;
    uint8_t bytes[8];
    uint8_t size;
    cdisasm_cpu_id cpu;
    cdisasm_mode mode;
    cdisasm_x86_decode_option flags;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_group_id group_id;
    uint8_t operand_count;
} nextgen_case;

static cdisasm_instruction decode_mode(
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu, mode, bytes, size, UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void expect_error(
    const char *label,
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        cpu, mode, bytes, size, flags, &decoded_size);

    if (decoded_size != 0 || !is_error_only(&instruction, status)) {
        fprintf(stderr,
                "%s: expected status %u, got status %u and size %u\n",
                label, (unsigned int)status,
                (unsigned int)instruction.last_error_id,
                (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static void expect_format_mnemonic(
    const cdisasm_instruction *instruction,
    const char *mnemonic)
{
#if USE_DISASM_FORMAT
    char text[160];
    size_t length = cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        text, sizeof(text));
    const size_t mnemonic_length = strlen(mnemonic);

    EXPECT(length == strlen(text));
    EXPECT(length >= mnemonic_length);
    EXPECT(strncmp(text, mnemonic, mnemonic_length) == 0);
    EXPECT(text[mnemonic_length] == '\0'
           || text[mnemonic_length] == ' ');
#else
    (void)instruction;
    (void)mnemonic;
#endif
}

static cdisasm_instruction expect_success(const nextgen_case *test)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    if (test->name_id == CDISASM_X86_NAME_VMULBF16) {
        cdisasm_x86_decode_flags exact_flags =
            CDISASM_X86_DECODE_FLAGS_INITIALIZER(test->flags);

        EXPECT(cdisasm_decode_flags_set_bit(
            &exact_flags, CDISASM_X86_DECODE_BIT_AVX10_2_BF16_512));
        memset(&instruction, 0xa5, sizeof(instruction));
        decoded_size = cdisasm_test_x86_decode_exact_flags(
            test->cpu, test->mode, test->bytes, test->size,
            UINT64_C(0x1000), &exact_flags, &instruction);
    } else {
        instruction = decode_mode(
            test->cpu, test->mode, test->bytes, test->size,
            test->flags, &decoded_size);
    }

    if (decoded_size != test->size
        || instruction.last_error_id != CDISASM_STATUS_OK
        || instruction.name_id != test->name_id) {
        fprintf(stderr,
                "%s: expected name %u and size %u, got name %u, "
                "status %u and size %u\n",
                test->label, (unsigned int)test->name_id,
                (unsigned int)test->size, (unsigned int)instruction.name_id,
                (unsigned int)instruction.last_error_id,
                (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == test->size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == test->name_id);
    EXPECT(instruction.operand_count == test->operand_count);
    EXPECT(instruction.opcode_size == test->size);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, test->group_id));
    expect_format_mnemonic(&instruction, test->mnemonic);
    return instruction;
}
#endif

static const nextgen_case amx_vex_cases[] = {
    {"TCMMIMFP16PS", "tcmmimfp16ps", {0xc4, 0xe2, 0x69, 0x6c, 0xc1}, 5,
     CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TCMMIMFP16PS,
     CDISASM_X86_GROUP_AMX_COMPLEX, 3},
    {"TCMMRLFP16PS", "tcmmrlfp16ps", {0xc4, 0xe2, 0x68, 0x6c, 0xc1}, 5,
     CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TCMMRLFP16PS,
     CDISASM_X86_GROUP_AMX_COMPLEX, 3},
    {"TDPBF8PS", "tdpbf8ps", {0xc4, 0xe5, 0x68, 0xfd, 0xc1}, 5,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TDPBF8PS,
     CDISASM_X86_GROUP_AMX_FP8, 3},
    {"TDPBHF8PS", "tdpbhf8ps", {0xc4, 0xe5, 0x6b, 0xfd, 0xc1}, 5,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TDPBHF8PS,
     CDISASM_X86_GROUP_AMX_FP8, 3},
    {"TDPHBF8PS", "tdphbf8ps", {0xc4, 0xe5, 0x6a, 0xfd, 0xc1}, 5,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TDPHBF8PS,
     CDISASM_X86_GROUP_AMX_FP8, 3},
    {"TDPHF8PS", "tdphf8ps", {0xc4, 0xe5, 0x69, 0xfd, 0xc1}, 5,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TDPHF8PS,
     CDISASM_X86_GROUP_AMX_FP8, 3},
    {"TILELOADDRS", "tileloaddrs",
     {0xc4, 0xe2, 0x7b, 0x4a, 0x04, 0x10}, 6,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TILELOADDRS,
     CDISASM_X86_GROUP_AMX_MOVRS, 2},
    {"TILELOADDRST1", "tileloaddrst1",
     {0xc4, 0xe2, 0x79, 0x4a, 0x04, 0x10}, 6,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TILELOADDRST1,
     CDISASM_X86_GROUP_AMX_MOVRS, 2}
};

static const nextgen_case amx_row_cases[] = {
    {"TCVTROWD2PS GPR", "tcvtrowd2ps",
     {0x62, 0xf2, 0x7e, 0x48, 0x4a, 0xc1}, 6,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TCVTROWD2PS,
     CDISASM_X86_GROUP_AMX_AVX512, 3},
    {"TCVTROWPS2BF16H GPR", "tcvtrowps2bf16h",
     {0x62, 0xf2, 0x7f, 0x48, 0x6d, 0xc1}, 6,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TCVTROWPS2BF16H,
     CDISASM_X86_GROUP_AMX_AVX512, 3},
    {"TCVTROWPS2BF16L GPR", "tcvtrowps2bf16l",
     {0x62, 0xf2, 0x7e, 0x48, 0x6d, 0xc1}, 6,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TCVTROWPS2BF16L,
     CDISASM_X86_GROUP_AMX_AVX512, 3},
    {"TCVTROWPS2PHH GPR", "tcvtrowps2phh",
     {0x62, 0xf2, 0x7c, 0x48, 0x6d, 0xc1}, 6,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TCVTROWPS2PHH,
     CDISASM_X86_GROUP_AMX_AVX512, 3},
    {"TCVTROWPS2PHL GPR", "tcvtrowps2phl",
     {0x62, 0xf2, 0x7d, 0x48, 0x6d, 0xc1}, 6,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TCVTROWPS2PHL,
     CDISASM_X86_GROUP_AMX_AVX512, 3},
    {"TILEMOVROW GPR", "tilemovrow",
     {0x62, 0xf2, 0x7d, 0x48, 0x4a, 0xc1}, 6,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TILEMOVROW,
     CDISASM_X86_GROUP_AMX_AVX512, 3},
    {"TCVTROWD2PS imm", "tcvtrowd2ps",
     {0x62, 0xf3, 0x7e, 0x48, 0x07, 0xc1, 0x05}, 7,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TCVTROWD2PS,
     CDISASM_X86_GROUP_AMX_AVX512, 3},
    {"TCVTROWPS2BF16H imm", "tcvtrowps2bf16h",
     {0x62, 0xf3, 0x7f, 0x48, 0x07, 0xc1, 0x05}, 7,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TCVTROWPS2BF16H,
     CDISASM_X86_GROUP_AMX_AVX512, 3},
    {"TCVTROWPS2BF16L imm", "tcvtrowps2bf16l",
     {0x62, 0xf3, 0x7e, 0x48, 0x77, 0xc1, 0x05}, 7,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TCVTROWPS2BF16L,
     CDISASM_X86_GROUP_AMX_AVX512, 3},
    {"TCVTROWPS2PHH imm", "tcvtrowps2phh",
     {0x62, 0xf3, 0x7c, 0x48, 0x07, 0xc1, 0x05}, 7,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TCVTROWPS2PHH,
     CDISASM_X86_GROUP_AMX_AVX512, 3},
    {"TCVTROWPS2PHL imm", "tcvtrowps2phl",
     {0x62, 0xf3, 0x7f, 0x48, 0x77, 0xc1, 0x05}, 7,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TCVTROWPS2PHL,
     CDISASM_X86_GROUP_AMX_AVX512, 3},
    {"TILEMOVROW imm", "tilemovrow",
     {0x62, 0xf3, 0x7d, 0x48, 0x07, 0xc1, 0x05}, 7,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TILEMOVROW,
     CDISASM_X86_GROUP_AMX_AVX512, 3}
};

static const nextgen_case apx_amx_memory_cases[] = {
    {"APX LDTILECFG", "ldtilecfg", {0x62, 0xfa, 0x7c, 0x08, 0x49, 0x00}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_ALL,
     CDISASM_X86_NAME_LDTILECFG, CDISASM_X86_GROUP_APX_F_AMX_BASE, 1},
    {"APX STTILECFG", "sttilecfg", {0x62, 0xfa, 0x7d, 0x08, 0x49, 0x00}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_ALL,
     CDISASM_X86_NAME_STTILECFG, CDISASM_X86_GROUP_APX_F_AMX_BASE, 1},
    {"APX TILELOADD", "tileloadd",
     {0x62, 0xfa, 0x7f, 0x08, 0x4b, 0x04, 0x18}, 7,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_ALL,
     CDISASM_X86_NAME_TILELOADD, CDISASM_X86_GROUP_APX_F_AMX, 2},
    {"APX TILELOADDT1", "tileloaddt1",
     {0x62, 0xfa, 0x7d, 0x08, 0x4b, 0x04, 0x18}, 7,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_ALL,
     CDISASM_X86_NAME_TILELOADDT1, CDISASM_X86_GROUP_APX_F_AMX, 2},
    {"APX TILELOADDRS", "tileloaddrs",
     {0x62, 0xfa, 0x7f, 0x08, 0x4a, 0x04, 0x18}, 7,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_ALL,
     CDISASM_X86_NAME_TILELOADDRS,
     CDISASM_X86_GROUP_APX_F_AMX_MOVRS, 2},
    {"APX TILELOADDRST1", "tileloaddrst1",
     {0x62, 0xfa, 0x7d, 0x08, 0x4a, 0x04, 0x18}, 7,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_ALL,
     CDISASM_X86_NAME_TILELOADDRST1,
     CDISASM_X86_GROUP_APX_F_AMX_MOVRS, 2},
    {"APX TILESTORED", "tilestored",
     {0x62, 0xfa, 0x7e, 0x08, 0x4b, 0x04, 0x18}, 7,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_ALL,
     CDISASM_X86_NAME_TILESTORED, CDISASM_X86_GROUP_APX_F_AMX, 2}
};

static const nextgen_case ace_tilemov_cases[] = {
    {"ACE TILEMOVROW GPR", "tilemovrow",
     {0x62, 0xf2, 0xfd, 0x48, 0x4a, 0xc1}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TILEMOVROW,
     CDISASM_X86_GROUP_ACE_1, 3},
    {"ACE TILEMOVROW imm", "tilemovrow",
     {0x62, 0xf3, 0xfd, 0x48, 0x07, 0xc1, 0x05}, 7,
     CDISASM_CPU_X86, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TILEMOVROW,
     CDISASM_X86_GROUP_ACE_1, 3},
    {"ACE TILEMOVCOL GPR", "tilemovcol",
     {0x62, 0xf2, 0xfd, 0x48, 0x4b, 0xc1}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TILEMOVCOL,
     CDISASM_X86_GROUP_ACE_1, 3},
    {"ACE TILEMOVCOL imm", "tilemovcol",
     {0x62, 0xf3, 0xfd, 0x48, 0x2f, 0xc1, 0x05}, 7,
     CDISASM_CPU_X86, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TILEMOVCOL,
     CDISASM_X86_GROUP_ACE_1, 3},
    {"ACE TILEMOVROW APX B4", "tilemovrow",
     {0x62, 0xfa, 0xfd, 0x48, 0x4a, 0xc1}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX | CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_TILEMOVROW, CDISASM_X86_GROUP_ACE_1, 3},
    {"ACE TILEMOVCOL imm APX B4", "tilemovcol",
     {0x62, 0xfb, 0xfd, 0x48, 0x2f, 0xc1, 0x05}, 7,
     CDISASM_CPU_X86, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AMX | CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_TILEMOVCOL, CDISASM_X86_GROUP_ACE_1, 3}
};

static const nextgen_case ace_top_cases[] = {
    {"ACE TOP2BF16PS", "top2bf16ps",
     {0x62, 0xf2, 0x6e, 0x48, 0x5c, 0xc1}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_AMX,
     CDISASM_X86_NAME_TOP2BF16PS, CDISASM_X86_GROUP_ACE_1, 3},
    {"ACE TOP4BSSD", "top4bssd",
     {0x62, 0xf2, 0x6f, 0x48, 0x5e, 0xc1}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_AMX,
     CDISASM_X86_NAME_TOP4BSSD, CDISASM_X86_GROUP_ACE_1, 3},
    {"ACE TOP4BSUD", "top4bsud",
     {0x62, 0xf2, 0x6e, 0x48, 0x5e, 0xc1}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_AMX,
     CDISASM_X86_NAME_TOP4BSUD, CDISASM_X86_GROUP_ACE_1, 3},
    {"ACE TOP4BUSD", "top4busd",
     {0x62, 0xf2, 0x6d, 0x48, 0x5e, 0xc1}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_AMX,
     CDISASM_X86_NAME_TOP4BUSD, CDISASM_X86_GROUP_ACE_1, 3},
    {"ACE TOP4BUUD", "top4buud",
     {0x62, 0xf2, 0x6c, 0x48, 0x5e, 0xc1}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_AMX,
     CDISASM_X86_NAME_TOP4BUUD, CDISASM_X86_GROUP_ACE_1, 3},
    {"ACE TOP4MXBF8PS", "top4mxbf8ps",
     {0x62, 0xf3, 0x6c, 0x48, 0x8d, 0xc1, 0x05}, 7,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_AMX,
     CDISASM_X86_NAME_TOP4MXBF8PS, CDISASM_X86_GROUP_ACE_1, 4},
    {"ACE TOP4MXBHF8PS", "top4mxbhf8ps",
     {0x62, 0xf3, 0x6f, 0x48, 0x8d, 0xc1, 0x05}, 7,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_AMX,
     CDISASM_X86_NAME_TOP4MXBHF8PS, CDISASM_X86_GROUP_ACE_1, 4},
    {"ACE TOP4MXHBF8PS", "top4mxhbf8ps",
     {0x62, 0xf3, 0x6e, 0x48, 0x8d, 0xc1, 0x05}, 7,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_AMX,
     CDISASM_X86_NAME_TOP4MXHBF8PS, CDISASM_X86_GROUP_ACE_1, 4},
    {"ACE TOP4MXHF8PS", "top4mxhf8ps",
     {0x62, 0xf3, 0x6d, 0x48, 0x8d, 0xc1, 0x05}, 7,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_AMX,
     CDISASM_X86_NAME_TOP4MXHF8PS, CDISASM_X86_GROUP_ACE_1, 4},
    {"ACE TOP4MXBSSPS", "top4mxbssps",
     {0x62, 0xf3, 0x6f, 0x48, 0x8f, 0xc1, 0x05}, 7,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_AMX,
     CDISASM_X86_NAME_TOP4MXBSSPS, CDISASM_X86_GROUP_ACE_1, 4}
};

static const nextgen_case avx10_bf16_cases[] = {
    {"VADDBF16", "vaddbf16", {0x62, 0xf5, 0x75, 0x49, 0x58, 0xc2}, 6,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AVX10, CDISASM_X86_NAME_VADDBF16,
     CDISASM_X86_GROUP_AVX10_2, 3},
    {"VMULBF16", "vmulbf16", {0x62, 0xf5, 0x75, 0x49, 0x59, 0xc2}, 6,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AVX10, CDISASM_X86_NAME_VMULBF16,
     CDISASM_X86_GROUP_AVX10_2, 3},
    {"VSUBBF16", "vsubbf16", {0x62, 0xf5, 0x75, 0x49, 0x5c, 0xc2}, 6,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AVX10, CDISASM_X86_NAME_VSUBBF16,
     CDISASM_X86_GROUP_AVX10_2, 3},
    {"VDIVBF16", "vdivbf16", {0x62, 0xf5, 0x75, 0x49, 0x5e, 0xc2}, 6,
     CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_AVX10, CDISASM_X86_NAME_VDIVBF16,
     CDISASM_X86_GROUP_AVX10_2, 3}
};

static const nextgen_case apx_ndd_cases[] = {
    {"APX ADD", "add", {0x62, 0xec, 0xfc, 0x10, 0x01, 0xd1}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_ADD, CDISASM_X86_GROUP_APX_F, 3},
    {"APX OR", "or", {0x62, 0xec, 0xfc, 0x10, 0x09, 0xd1}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_OR, CDISASM_X86_GROUP_APX_F, 3},
    {"APX ADC", "adc", {0x62, 0xec, 0xfc, 0x10, 0x11, 0xd1}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_ADC, CDISASM_X86_GROUP_APX_F, 3},
    {"APX SBB", "sbb", {0x62, 0xec, 0xfc, 0x10, 0x19, 0xd1}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_SBB, CDISASM_X86_GROUP_APX_F, 3},
    {"APX AND", "and", {0x62, 0xec, 0xfc, 0x10, 0x21, 0xd1}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_AND, CDISASM_X86_GROUP_APX_F, 3},
    {"APX SUB", "sub", {0x62, 0xec, 0xfc, 0x10, 0x29, 0xd1}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_SUB, CDISASM_X86_GROUP_APX_F, 3},
    {"APX XOR", "xor", {0x62, 0xec, 0xfc, 0x10, 0x31, 0xd1}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_XOR, CDISASM_X86_GROUP_APX_F, 3}
};

static const nextgen_case apx_nf_cases[] = {
    {"APX OR NF", "or", {0x62, 0xec, 0xfc, 0x14, 0x09, 0xd1}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_OR, CDISASM_X86_GROUP_APX_F, 3},
    {"APX AND NF", "and", {0x62, 0xec, 0xfc, 0x14, 0x21, 0xd1}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_AND, CDISASM_X86_GROUP_APX_F, 3},
    {"APX SUB NF", "sub", {0x62, 0xec, 0xfc, 0x14, 0x29, 0xd1}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_SUB, CDISASM_X86_GROUP_APX_F, 3},
    {"APX XOR NF", "xor", {0x62, 0xec, 0xfc, 0x14, 0x31, 0xd1}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_XOR, CDISASM_X86_GROUP_APX_F, 3}
};

static const nextgen_case apx_not_cases[] = {
    {"APX NOT byte register", "not",
     {0x62, 0xfc, 0x7c, 0x08, 0xf6, 0xd0}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_NOT, CDISASM_X86_GROUP_APX_F, 1},
    {"APX NOT qword register", "not",
     {0x62, 0xfc, 0xfc, 0x08, 0xf7, 0xd0}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_NOT, CDISASM_X86_GROUP_APX_F, 1},
    {"APX NOT byte memory", "not",
     {0x62, 0xfc, 0x7c, 0x08, 0xf6, 0x11}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_NOT, CDISASM_X86_GROUP_APX_F, 1},
    {"APX NOT qword memory", "not",
     {0x62, 0xfc, 0xfc, 0x08, 0xf7, 0x11}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_NOT, CDISASM_X86_GROUP_APX_F, 1},
    {"APX NDD NOT byte register", "not",
     {0x62, 0xfc, 0x7c, 0x10, 0xf6, 0xd1}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_NOT, CDISASM_X86_GROUP_APX_F_N3, 2},
    {"APX NDD NOT qword register", "not",
     {0x62, 0xfc, 0xfc, 0x10, 0xf7, 0xd1}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_NOT, CDISASM_X86_GROUP_APX_F_N3, 2},
    {"APX NDD NOT byte memory", "not",
     {0x62, 0xfc, 0x7c, 0x10, 0xf6, 0x11}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_NOT, CDISASM_X86_GROUP_APX_F_N3, 2},
    {"APX NDD NOT qword memory", "not",
     {0x62, 0xfc, 0xfc, 0x10, 0xf7, 0x11}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_NOT, CDISASM_X86_GROUP_APX_F_N3, 2}
};

static const nextgen_case apx_group3_cases[] = {
    {"APX IMUL", "imul", {0x62, 0xfc, 0xfc, 0x08, 0xf7, 0xe8}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_IMUL, CDISASM_X86_GROUP_APX_F, 1},
    {"APX IMUL NF", "imul", {0x62, 0xfc, 0xfc, 0x0c, 0xf7, 0x29}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_IMUL, CDISASM_X86_GROUP_APX_F_N3, 1},
    {"APX MUL", "mul", {0x62, 0xfc, 0xfc, 0x08, 0xf7, 0xe0}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_MUL, CDISASM_X86_GROUP_APX_F, 1},
    {"APX MUL NF", "mul", {0x62, 0xfc, 0xfc, 0x0c, 0xf7, 0x21}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_MUL, CDISASM_X86_GROUP_APX_F_N3, 1},
    {"APX DIV", "div", {0x62, 0xfc, 0x7c, 0x08, 0xf6, 0xf0}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_DIV, CDISASM_X86_GROUP_APX_F, 1},
    {"APX DIV NF", "div", {0x62, 0xfc, 0x7c, 0x0c, 0xf6, 0x31}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_DIV, CDISASM_X86_GROUP_APX_F_N3, 1},
    {"APX IDIV", "idiv", {0x62, 0xfc, 0xfc, 0x08, 0xf7, 0xf8}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_IDIV, CDISASM_X86_GROUP_APX_F, 1},
    {"APX IDIV NF", "idiv", {0x62, 0xfc, 0xfc, 0x0c, 0xf7, 0x39}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_IDIV, CDISASM_X86_GROUP_APX_F_N3, 1}
};

static const nextgen_case apx_imul_af_cases[] = {
    {"APX IMUL2", "imul", {0x62, 0xec, 0xfc, 0x08, 0xaf, 0xca}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_IMUL, CDISASM_X86_GROUP_APX_F, 2},
    {"APX IMUL2 NF", "imul", {0x62, 0xec, 0xfc, 0x0c, 0xaf, 0x0a}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_IMUL, CDISASM_X86_GROUP_APX_F_N3, 2},
    {"APX IMUL3", "imul", {0x62, 0xec, 0xfc, 0x10, 0xaf, 0xca}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_IMUL, CDISASM_X86_GROUP_APX_F_N3, 3},
    {"APX IMUL3 NF", "imul", {0x62, 0xec, 0xfc, 0x14, 0xaf, 0x0a}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_IMUL, CDISASM_X86_GROUP_APX_F_N3, 3}
};

static const nextgen_case apx_imul_immediate_cases[] = {
    {"APX IMUL imm8", "imul",
     {0x62, 0xec, 0xfc, 0x08, 0x6b, 0xca, 0x12}, 7,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_IMUL, CDISASM_X86_GROUP_APX_F, 3},
    {"APX IMUL imm8 NF", "imul",
     {0x62, 0xec, 0xfc, 0x0c, 0x6b, 0x0a, 0x12}, 7,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_IMUL, CDISASM_X86_GROUP_APX_F_N3, 3},
    {"APX IMUL imm8 ZU", "imul",
     {0x62, 0xec, 0xfc, 0x18, 0x6b, 0xca, 0x12}, 7,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_IMUL, CDISASM_X86_GROUP_APX_F_N3, 3},
    {"APX IMUL imm8 NF ZU", "imul",
     {0x62, 0xec, 0xfc, 0x1c, 0x6b, 0xca, 0x12}, 7,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_IMUL, CDISASM_X86_GROUP_APX_F_N3, 3}
};

static const nextgen_case apx_neg_cases[] = {
    {"APX NEG", "neg", {0x62, 0xfc, 0xfc, 0x08, 0xf7, 0xd8}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_NEG, CDISASM_X86_GROUP_APX_F, 1},
    {"APX NEG NF", "neg", {0x62, 0xfc, 0xfc, 0x0c, 0xf7, 0x19}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_NEG, CDISASM_X86_GROUP_APX_F_N3, 1},
    {"APX NEG NDD", "neg", {0x62, 0xfc, 0xfc, 0x10, 0xf7, 0xd9}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_NEG, CDISASM_X86_GROUP_APX_F_N3, 2},
    {"APX NEG NDD NF", "neg", {0x62, 0xfc, 0xfc, 0x14, 0xf7, 0x19}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_APX,
     CDISASM_X86_NAME_NEG, CDISASM_X86_GROUP_APX_F_N3, 2}
};

static const nextgen_case apx_movdir_cases[] = {
    {"APX MOVDIRI", "movdiri",
     {0x62, 0xec, 0xfc, 0x08, 0xf9, 0x11}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_SYSTEM,
     CDISASM_X86_NAME_MOVDIRI, CDISASM_X86_GROUP_MOVDIRI, 2},
    {"APX MOVDIR64B", "movdir64b",
     {0x62, 0xec, 0xfd, 0x08, 0xf8, 0x11}, 6,
     CDISASM_CPU_APX, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_SYSTEM,
     CDISASM_X86_NAME_MOVDIR64B, CDISASM_X86_GROUP_MOVDIR64B, 3}
};

static const nextgen_case apx_system_cases[] = {
    {"APX INVEPT", "invept", {0x62, 0xec, 0x7e, 0x08, 0xf0, 0x01}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_ALL,
     CDISASM_X86_NAME_INVEPT, CDISASM_X86_GROUP_APX_F_VMX, 2},
    {"APX INVVPID", "invvpid", {0x62, 0xec, 0x7e, 0x08, 0xf1, 0x01}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_ALL,
     CDISASM_X86_NAME_INVVPID, CDISASM_X86_GROUP_APX_F_VMX, 2},
    {"APX INVPCID", "invpcid", {0x62, 0xec, 0x7e, 0x08, 0xf2, 0x01}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_ALL,
     CDISASM_X86_NAME_INVPCID, CDISASM_X86_GROUP_APX_F_INVPCID, 2},
    {"APX PUSH2", "push2", {0x62, 0xfc, 0x7c, 0x10, 0xff, 0xf1}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_ALL,
     CDISASM_X86_NAME_PUSH2, CDISASM_X86_GROUP_APX_F_N3, 2},
    {"APX POP2", "pop2", {0x62, 0xfc, 0x7c, 0x10, 0x8f, 0xc1}, 6,
     CDISASM_CPU_X86, CDISASM_MODE_64, CDISASM_X86_DECODE_FLAG_ALL,
     CDISASM_X86_NAME_POP2, CDISASM_X86_GROUP_APX_F_N3, 2}
};

static void test_positive_catalogs(void)
{
    size_t index;

    EXPECT(sizeof(amx_vex_cases) / sizeof(amx_vex_cases[0]) == 8u);
    EXPECT(sizeof(amx_row_cases) / sizeof(amx_row_cases[0]) == 12u);
    EXPECT(sizeof(ace_tilemov_cases) / sizeof(ace_tilemov_cases[0]) == 6u);
    EXPECT(sizeof(ace_top_cases) / sizeof(ace_top_cases[0]) == 10u);
    EXPECT(sizeof(avx10_bf16_cases) / sizeof(avx10_bf16_cases[0]) == 4u);
    EXPECT(sizeof(apx_ndd_cases) / sizeof(apx_ndd_cases[0]) == 7u);
    EXPECT(sizeof(apx_nf_cases) / sizeof(apx_nf_cases[0]) == 4u);
    EXPECT(sizeof(apx_not_cases) / sizeof(apx_not_cases[0]) == 8u);
    EXPECT(sizeof(apx_group3_cases) / sizeof(apx_group3_cases[0]) == 8u);
    EXPECT(sizeof(apx_imul_af_cases) / sizeof(apx_imul_af_cases[0]) == 4u);
    EXPECT(sizeof(apx_imul_immediate_cases)
        / sizeof(apx_imul_immediate_cases[0]) == 4u);
    EXPECT(sizeof(apx_neg_cases) / sizeof(apx_neg_cases[0]) == 4u);
    EXPECT(sizeof(apx_movdir_cases) / sizeof(apx_movdir_cases[0]) == 2u);

#define RUN_CASES(cases_)                                                      \
    do {                                                                       \
        for (index = 0;                                                        \
             index < sizeof(cases_) / sizeof((cases_)[0]);                    \
             ++index) {                                                        \
            const nextgen_case *test = &(cases_)[index];                       \
            (void)test;                                                        \
            /* The same structural corpus must remain owned by the decoder    \
             * when the optional implementation is compiled out. */           \
            /* NOLINTNEXTLINE(bugprone-macro-parentheses) */                   \
            TEST_ONE_CASE(test);                                               \
        }                                                                      \
    } while (0)

#if USE_EXTRA_OPCODES
#define TEST_ONE_CASE(test_)                                                   \
    do {                                                                       \
        cdisasm_instruction instruction = expect_success((test_));             \
        EXPECT((instruction.opcode_flags                                       \
                & ((test_)->bytes[0] == 0xc4                                  \
                       ? CDISASM_PREFIX_VEX : CDISASM_PREFIX_EVEX)) != 0);      \
        if ((test_)->group_id >= CDISASM_X86_GROUP_APX_F_AMX                  \
            && (test_)->group_id <= CDISASM_X86_GROUP_APX_F_AMX_MOVRS) {      \
            EXPECT(cdisasm_instruction_has_x86_group(                          \
                &instruction, CDISASM_X86_GROUP_APX_F));                       \
            EXPECT(cdisasm_instruction_has_x86_group(                          \
                &instruction, CDISASM_X86_GROUP_AMX_TILE));                    \
        }                                                                      \
        if ((test_)->group_id == CDISASM_X86_GROUP_APX_F_VMX                 \
            || (test_)->group_id == CDISASM_X86_GROUP_APX_F_INVPCID          \
            || (test_)->group_id == CDISASM_X86_GROUP_APX_F_N3) {            \
            EXPECT(cdisasm_instruction_has_x86_group(                          \
                &instruction, CDISASM_X86_GROUP_APX_F));                       \
        }                                                                      \
        if ((test_)->group_id == CDISASM_X86_GROUP_APX_F_N3                  \
            && (((test_)->bytes[3] & 0x04u) != 0u)                           \
            && ((test_)->name_id == CDISASM_X86_NAME_MUL                     \
                || (test_)->name_id == CDISASM_X86_NAME_IMUL                 \
                || (test_)->name_id == CDISASM_X86_NAME_NEG                  \
                || (test_)->name_id == CDISASM_X86_NAME_DIV                  \
                || (test_)->name_id == CDISASM_X86_NAME_IDIV)) {             \
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NF) != 0);  \
        }                                                                      \
        if (((test_)->bytes[4] == 0x69u || (test_)->bytes[4] == 0x6bu)        \
            && (((test_)->bytes[3] & 0x10u) != 0u)) {                         \
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_ZU) != 0);  \
        }                                                                      \
        if ((test_)->name_id == CDISASM_X86_NAME_NEG) {                       \
            EXPECT((instruction.opcode_flags                                  \
                    & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)       \
                == ((((test_)->bytes[3] & 0x04u) != 0u)                       \
                    ? 0u : CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS));\
        }                                                                      \
        if ((test_)->group_id == CDISASM_X86_GROUP_APX_F_VMX) {               \
            EXPECT(cdisasm_instruction_has_x86_group(                          \
                &instruction, CDISASM_X86_GROUP_VMX));                         \
        }                                                                      \
        if ((test_)->group_id == CDISASM_X86_GROUP_APX_F_INVPCID) {           \
            EXPECT(cdisasm_instruction_has_x86_group(                          \
                &instruction, CDISASM_X86_GROUP_INVPCID));                     \
        }                                                                      \
        expect_error((test_)->label, (test_)->cpu, (test_)->mode,              \
                     (test_)->bytes, (test_)->size,                            \
                     CDISASM_X86_DECODE_FLAG_BASE,                             \
                     CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);                  \
    } while (0)
#else
#define TEST_ONE_CASE(test_)                                                   \
    expect_error((test_)->label, CDISASM_CPU_X86, (test_)->mode,               \
                 (test_)->bytes, (test_)->size,                                \
                 CDISASM_X86_DECODE_FLAG_BASE,                                 \
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION)
#endif

    RUN_CASES(amx_vex_cases);
    RUN_CASES(amx_row_cases);
    RUN_CASES(apx_amx_memory_cases);
    RUN_CASES(ace_tilemov_cases);
    RUN_CASES(ace_top_cases);
    RUN_CASES(avx10_bf16_cases);
    RUN_CASES(apx_ndd_cases);
    RUN_CASES(apx_nf_cases);
    RUN_CASES(apx_not_cases);
    RUN_CASES(apx_group3_cases);
    RUN_CASES(apx_imul_af_cases);
    RUN_CASES(apx_imul_immediate_cases);
    RUN_CASES(apx_neg_cases);
    RUN_CASES(apx_movdir_cases);
    RUN_CASES(apx_system_cases);

#undef RUN_CASES
#undef TEST_ONE_CASE
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id expected_gpr32(unsigned int index)
{
    return index < 16u
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_EAX + index)
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_R16D + index - 16u);
}
#endif

static void test_ace_tilemov_register_space(void)
{
#if USE_EXTRA_OPCODES
    static const struct ace_case {
        cdisasm_x86_name_id name_id;
        cdisasm_x86_form_id gpr_form_id;
        cdisasm_x86_form_id immediate_form_id;
        uint8_t gpr_opcode;
        uint8_t immediate_opcode;
    } cases[] = {
        {CDISASM_X86_NAME_TILEMOVROW, UINT16_C(3301), UINT16_C(3302),
         UINT8_C(0x4a), UINT8_C(0x07)},
        {CDISASM_X86_NAME_TILEMOVCOL, UINT16_C(3299), UINT16_C(3300),
         UINT8_C(0x4b), UINT8_C(0x2f)}
    };
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        unsigned int destination;

        for (destination = 0; destination < 8u; ++destination) {
            unsigned int vector_source;

            for (vector_source = 0; vector_source < 32u; ++vector_source) {
                unsigned int gpr_source;
                uint8_t p0 = UINT8_C(0xf2);
                uint8_t modrm = (uint8_t)(UINT8_C(0xc0)
                    | (uint8_t)(destination << 3)
                    | (uint8_t)(vector_source & 7u));

                if ((vector_source & 8u) != 0) {
                    p0 &= (uint8_t)~UINT8_C(0x20);
                }
                if ((vector_source & 16u) != 0) {
                    p0 &= (uint8_t)~UINT8_C(0x40);
                }
                for (gpr_source = 0; gpr_source < 32u; ++gpr_source) {
                    uint8_t bytes[] = {
                        UINT8_C(0x62), p0,
                        (uint8_t)(UINT8_C(0x85)
                            | (uint8_t)(((~gpr_source) & 15u) << 3)),
                        (uint8_t)(UINT8_C(0x40)
                            | (gpr_source < 16u ? UINT8_C(0x08) : 0)),
                        cases[case_index].gpr_opcode, modrm
                    };
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode_mode(
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        bytes, sizeof(bytes), CDISASM_X86_DECODE_FLAG_AMX,
                        &decoded_size);

                    EXPECT(decoded_size == sizeof(bytes));
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id == cases[case_index].name_id);
                    EXPECT(instruction.form_id
                        == cases[case_index].gpr_form_id);
                    EXPECT(instruction.operand_count == 3u);
                    EXPECT(instruction.opcode[0].reg
                        == CDISASM_X86_REG_TMM0 + destination);
                    EXPECT(instruction.opcode[0].size == UINT8_MAX);
                    EXPECT(instruction.opcode[0].access
                        == CDISASM_OPERAND_ACCESS_WRITE);
                    EXPECT(instruction.opcode[1].reg
                        == CDISASM_X86_REG_ZMM0 + vector_source);
                    EXPECT(instruction.opcode[1].size == 64u);
                    EXPECT(instruction.opcode[1].access
                        == CDISASM_OPERAND_ACCESS_READ);
                    EXPECT(instruction.opcode[2].reg
                        == expected_gpr32(gpr_source));
                    EXPECT(instruction.opcode[2].size == 4u);
                    EXPECT(instruction.opcode[2].access
                        == CDISASM_OPERAND_ACCESS_READ);
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_ACE_1));
                    EXPECT(!cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AMX_AVX512));
                    EXPECT((instruction.opcode_flags
                        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK)
                        == 0u);
                }

                {
                    static const uint8_t immediates[] = {0, UINT8_MAX};
                    size_t immediate_index;

                    for (immediate_index = 0;
                         immediate_index < sizeof(immediates)
                             / sizeof(immediates[0]);
                         ++immediate_index) {
                        uint8_t bytes[] = {
                            UINT8_C(0x62),
                            (uint8_t)((p0 & UINT8_C(0xf8))
                                | UINT8_C(0x03)),
                            UINT8_C(0xfd), UINT8_C(0x48),
                            cases[case_index].immediate_opcode, modrm,
                            immediates[immediate_index]
                        };
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode_mode(
                            CDISASM_CPU_X86, CDISASM_MODE_64,
                            bytes, sizeof(bytes),
                            CDISASM_X86_DECODE_FLAG_AMX, &decoded_size);

                        EXPECT(decoded_size == sizeof(bytes));
                        EXPECT(instruction.last_error_id
                            == CDISASM_STATUS_OK);
                        EXPECT(instruction.name_id
                            == cases[case_index].name_id);
                        EXPECT(instruction.form_id
                            == cases[case_index].immediate_form_id);
                        EXPECT(instruction.operand_count == 3u);
                        EXPECT(instruction.opcode[0].reg
                            == CDISASM_X86_REG_TMM0 + destination);
                        EXPECT(instruction.opcode[1].reg
                            == CDISASM_X86_REG_ZMM0 + vector_source);
                        EXPECT(instruction.opcode[2].type
                            == CDISASM_OPERAND_IMMEDIATE);
                        EXPECT(instruction.opcode[2].size == 1u);
                        EXPECT(instruction.opcode[2].imm
                            == immediates[immediate_index]);
                        EXPECT(instruction.opcode[2].access
                            == CDISASM_OPERAND_ACCESS_READ);
                        EXPECT(cdisasm_instruction_has_x86_group(
                            &instruction, CDISASM_X86_GROUP_ACE_1));
                    }
                }
            }
        }
    }
#endif
}

static void test_ace_top_register_space(void)
{
#if USE_EXTRA_OPCODES
    enum {
        ACE_PP_NONE = 0,
        ACE_PP_P66 = 1,
        ACE_PP_PF3 = 2,
        ACE_PP_PF2 = 3
    };
    static const struct ace_top_case {
        cdisasm_x86_name_id name_id;
        cdisasm_x86_form_id form_id;
        uint8_t map;
        uint8_t opcode;
        uint8_t prefix;
        uint8_t immediate;
    } cases[] = {
        {CDISASM_X86_NAME_TOP2BF16PS, UINT16_C(3310), 2, 0x5c,
         ACE_PP_PF3, 0},
        {CDISASM_X86_NAME_TOP4BSSD, UINT16_C(3311), 2, 0x5e,
         ACE_PP_PF2, 0},
        {CDISASM_X86_NAME_TOP4BSUD, UINT16_C(3312), 2, 0x5e,
         ACE_PP_PF3, 0},
        {CDISASM_X86_NAME_TOP4BUSD, UINT16_C(3313), 2, 0x5e,
         ACE_PP_P66, 0},
        {CDISASM_X86_NAME_TOP4BUUD, UINT16_C(3314), 2, 0x5e,
         ACE_PP_NONE, 0},
        {CDISASM_X86_NAME_TOP4MXBF8PS, UINT16_C(3315), 3, 0x8d,
         ACE_PP_NONE, 1},
        {CDISASM_X86_NAME_TOP4MXBHF8PS, UINT16_C(3316), 3, 0x8d,
         ACE_PP_PF2, 1},
        {CDISASM_X86_NAME_TOP4MXBSSPS, UINT16_C(3317), 3, 0x8f,
         ACE_PP_PF2, 1},
        {CDISASM_X86_NAME_TOP4MXHBF8PS, UINT16_C(3318), 3, 0x8d,
         ACE_PP_PF3, 1},
        {CDISASM_X86_NAME_TOP4MXHF8PS, UINT16_C(3319), 3, 0x8d,
         ACE_PP_P66, 1}
    };
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        unsigned int destination;

        for (destination = 0; destination < 8u; ++destination) {
            unsigned int rm_source;

            for (rm_source = 0; rm_source < 32u; ++rm_source) {
                unsigned int n_source;
                uint8_t p0 = (uint8_t)(UINT8_C(0xf0)
                    | cases[case_index].map);
                uint8_t modrm = (uint8_t)(UINT8_C(0xc0)
                    | (uint8_t)(destination << 3)
                    | (uint8_t)(rm_source & 7u));

                if ((rm_source & 8u) != 0) {
                    p0 &= (uint8_t)~UINT8_C(0x20);
                }
                if ((rm_source & 16u) != 0) {
                    p0 &= (uint8_t)~UINT8_C(0x40);
                }
                for (n_source = 0; n_source < 32u; ++n_source) {
                    uint8_t immediate =
                        ((destination ^ rm_source ^ n_source) & 1u) != 0
                            ? UINT8_MAX : 0;
                    uint8_t bytes[] = {
                        UINT8_C(0x62), p0,
                        (uint8_t)(UINT8_C(0x04)
                            | cases[case_index].prefix
                            | (uint8_t)(((~n_source) & 15u) << 3)),
                        (uint8_t)(UINT8_C(0x40)
                            | (n_source < 16u ? UINT8_C(0x08) : 0)),
                        cases[case_index].opcode, modrm, immediate
                    };
                    size_t byte_count = cases[case_index].immediate != 0
                        ? sizeof(bytes) : sizeof(bytes) - 1u;
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode_mode(
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        bytes, byte_count, CDISASM_X86_DECODE_FLAG_AMX,
                        &decoded_size);

                    EXPECT(decoded_size == byte_count);
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id == cases[case_index].name_id);
                    EXPECT(instruction.form_id == cases[case_index].form_id);
                    EXPECT(instruction.operand_count
                        == 3u + cases[case_index].immediate);
                    EXPECT(instruction.opcode[0].type
                        == CDISASM_OPERAND_REGISTER);
                    EXPECT(instruction.opcode[0].reg
                        == CDISASM_X86_REG_TMM0 + destination);
                    EXPECT(instruction.opcode[0].size == UINT8_MAX);
                    EXPECT(instruction.opcode[0].access
                        == CDISASM_OPERAND_ACCESS_READ_WRITE);
                    EXPECT(instruction.opcode[1].reg
                        == CDISASM_X86_REG_ZMM0 + rm_source);
                    EXPECT(instruction.opcode[1].size == 64u);
                    EXPECT(instruction.opcode[1].access
                        == CDISASM_OPERAND_ACCESS_READ);
                    EXPECT(instruction.opcode[2].reg
                        == CDISASM_X86_REG_ZMM0 + n_source);
                    EXPECT(instruction.opcode[2].size == 64u);
                    EXPECT(instruction.opcode[2].access
                        == CDISASM_OPERAND_ACCESS_READ);
                    if (cases[case_index].immediate != 0) {
                        /* XED also records a suppressed BSR0 state operand;
                         * only the four public syntax operands are exposed. */
                        EXPECT(instruction.opcode[3].type
                            == CDISASM_OPERAND_IMMEDIATE);
                        EXPECT(instruction.opcode[3].size == 1u);
                        EXPECT(instruction.opcode[3].imm == immediate);
                        EXPECT(instruction.opcode[3].access
                            == CDISASM_OPERAND_ACCESS_READ);
                        EXPECT(instruction.encoding.immediate_count == 1u);
                        EXPECT(instruction.encoding.immediate_size[0] == 1u);
                    }
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_ACE_1));
                    EXPECT(!cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AMX_AVX512));
                    EXPECT(!cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_APX_F));
                    EXPECT((instruction.opcode_flags
                        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK)
                        == 0u);
                }
            }
        }
    }
#endif
}

static void test_operands_and_variants(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t tile_no_index[] = {
        0xc4, 0xe2, 0x7b, 0x4a, 0x04, 0x20
    };
    static const uint8_t amx_row_r16d[] = {
        0x62, 0xf2, 0x7e, 0x40, 0x4a, 0xc1
    };
    static const uint8_t bf16_memory[] = {
        0x62, 0xf5, 0x75, 0x49, 0x58, 0x00
    };
    static const uint8_t bf16_broadcast[] = {
        0x62, 0xf5, 0x75, 0x59, 0x58, 0x00
    };
    static const uint8_t bf16_ymm32[] = {
        0x62, 0xf5, 0x75, 0x29, 0x58, 0xc2
    };
    static const uint8_t bf16_xmm16[] = {
        0x62, 0xf5, 0x75, 0x09, 0x58, 0xc2
    };
    static const uint8_t apx_or_nf[] = {
        0x62, 0xec, 0xfc, 0x14, 0x09, 0xd1
    };
    static const uint8_t apx_or_memory[] = {
        0x62, 0xec, 0xfc, 0x10, 0x09, 0x11
    };
    static const uint8_t apx_or_word[] = {
        0x62, 0xec, 0x7d, 0x10, 0x09, 0xd1
    };
    static const uint8_t apx_or_dword[] = {
        0x62, 0xec, 0x7c, 0x10, 0x09, 0xd1
    };
    static const uint8_t apx_movdiri[] = {
        0x62, 0xec, 0xfc, 0x08, 0xf9, 0x11
    };
    static const uint8_t apx_movdir64b[] = {
        0x62, 0xec, 0xfd, 0x08, 0xf8, 0x11
    };
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        tile_no_index, sizeof(tile_no_index),
        CDISASM_X86_DECODE_FLAG_AMX, &decoded_size);

    EXPECT(decoded_size == sizeof(tile_no_index));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_TILELOADDRS);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_TMM0);
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_NONE);

    instruction = decode_mode(
        CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        amx_row_r16d, sizeof(amx_row_r16d),
        CDISASM_X86_DECODE_FLAG_AMX, &decoded_size);
    EXPECT(decoded_size == sizeof(amx_row_r16d));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_TCVTROWD2PS);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ZMM0);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_TMM1);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_R16D);
    EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AMX_TILE));

    instruction = decode_mode(
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        bf16_memory, sizeof(bf16_memory),
        CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == sizeof(bf16_memory));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VADDBF16);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ZMM0);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ZMM1);
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[2].size == 64u);
    EXPECT(instruction.mask_reg == CDISASM_X86_REG_K1);

    instruction = decode_mode(
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        bf16_broadcast, sizeof(bf16_broadcast),
        CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == sizeof(bf16_broadcast));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VADDBF16);
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[2].size == 2u);
    EXPECT(instruction.opcode[2].broadcast != CDISASM_X86_BROADCAST_NONE);

    instruction = decode_mode(
        CDISASM_CPU_AVX10, CDISASM_MODE_32,
        bf16_ymm32, sizeof(bf16_ymm32),
        CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == sizeof(bf16_ymm32));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VADDBF16);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM0);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM1);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_YMM2);

    instruction = decode_mode(
        CDISASM_CPU_AVX10, CDISASM_MODE_16,
        bf16_xmm16, sizeof(bf16_xmm16),
        CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == sizeof(bf16_xmm16));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VADDBF16);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM0);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM2);

    instruction = decode_mode(
        CDISASM_CPU_APX, CDISASM_MODE_64,
        apx_or_nf, sizeof(apx_or_nf),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(apx_or_nf));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_OR);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NF) != 0);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R16);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R17);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_R18);

    instruction = decode_mode(
        CDISASM_CPU_APX, CDISASM_MODE_64,
        apx_or_memory, sizeof(apx_or_memory),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(apx_or_memory));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_OR);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R16);
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R17);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_R18);

    instruction = decode_mode(
        CDISASM_CPU_APX, CDISASM_MODE_64,
        apx_or_word, sizeof(apx_or_word),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(apx_or_word));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R16W);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R17W);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_R18W);

    instruction = decode_mode(
        CDISASM_CPU_APX, CDISASM_MODE_64,
        apx_or_dword, sizeof(apx_or_dword),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(apx_or_dword));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R16D);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R17D);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_R18D);

    /* MOVDIR remains in the SYSTEM runtime family even when APX extends its
     * register/address fields; the CPU must independently provide APX-F. */
    instruction = decode_mode(
        CDISASM_CPU_APX, CDISASM_MODE_64,
        apx_movdiri, sizeof(apx_movdiri),
        CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);
    EXPECT(decoded_size == sizeof(apx_movdiri));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVDIRI);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R17);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R18);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_MOVDIRI));
    expect_error("APX MOVDIRI runtime family", CDISASM_CPU_APX,
        CDISASM_MODE_64, apx_movdiri, sizeof(apx_movdiri),
        CDISASM_X86_DECODE_FLAG_APX,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    instruction = decode_mode(
        CDISASM_CPU_APX, CDISASM_MODE_64,
        apx_movdir64b, sizeof(apx_movdir64b),
        CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);
    EXPECT(decoded_size == sizeof(apx_movdir64b));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVDIR64B);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R18);
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R17);
    EXPECT(instruction.opcode[1].size == 64u);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R18);
    EXPECT(instruction.opcode[2].size == 64u);
    EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT((instruction.opcode[2].flags
            & CDISASM_OPERAND_FLAG_IMPLICIT) != 0);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_MOVDIR64B));
#endif
}

static void test_cpu_mode_and_runtime_gates(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t amx_complex[] = {
        0xc4, 0xe2, 0x69, 0x6c, 0xc1
    };
    static const uint8_t amx_fp8[] = {
        0xc4, 0xe5, 0x68, 0xfd, 0xc1
    };
    static const uint8_t amx_movrs[] = {
        0xc4, 0xe2, 0x7b, 0x4a, 0x04, 0x10
    };
    static const uint8_t amx_row[] = {
        0x62, 0xf2, 0x7e, 0x48, 0x4a, 0xc1
    };
    static const uint8_t ace_tilemov[] = {
        0x62, 0xf2, 0xfd, 0x48, 0x4a, 0xc1
    };
    static const uint8_t ace_tilemov_b4[] = {
        0x62, 0xfa, 0xfd, 0x48, 0x4a, 0xc1
    };
    static const uint8_t ace_top[] = {
        0x62, 0xf2, 0x6e, 0x48, 0x5c, 0xc1
    };
    static const uint8_t ace_top_b4[] = {
        0x62, 0xfa, 0x6e, 0x48, 0x5c, 0xc1
    };
    static const uint8_t ace_top_mx_b4[] = {
        0x62, 0xfb, 0x6c, 0x48, 0x8d, 0xc1, 0x12
    };
    static const uint8_t bf16[] = {
        0x62, 0xf5, 0x75, 0x49, 0x58, 0xc2
    };
    static const uint8_t apx[] = {
        0x62, 0xec, 0xfc, 0x10, 0x09, 0xd1
    };
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    expect_error("AMX complex CPU gate", CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_MODE_64, amx_complex, sizeof(amx_complex),
        CDISASM_X86_DECODE_FLAG_AMX, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("AMX complex mode gate", CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_MODE_32, amx_complex, sizeof(amx_complex),
        CDISASM_X86_DECODE_FLAG_AMX, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("AMX FP8 CPU gate", CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_MODE_64, amx_fp8, sizeof(amx_fp8),
        CDISASM_X86_DECODE_FLAG_AMX, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("AMX MOVRS CPU gate", CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_MODE_64, amx_movrs, sizeof(amx_movrs),
        CDISASM_X86_DECODE_FLAG_AMX, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("AMX-AVX512 CPU gate", CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_MODE_64, amx_row, sizeof(amx_row),
        CDISASM_X86_DECODE_FLAG_AMX, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("AMX-AVX512 mode gate", CDISASM_CPU_DIAMOND_RAPIDS,
        CDISASM_MODE_32, amx_row, sizeof(amx_row),
        CDISASM_X86_DECODE_FLAG_AMX, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("ACE 1 named-profile gate", CDISASM_CPU_DIAMOND_RAPIDS,
        CDISASM_MODE_64, ace_tilemov, sizeof(ace_tilemov),
        CDISASM_X86_DECODE_FLAG_AMX, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("ACE 1 mode gate", CDISASM_CPU_X86,
        CDISASM_MODE_32, ace_tilemov, sizeof(ace_tilemov),
        CDISASM_X86_DECODE_FLAG_AMX, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("ACE 1 runtime family gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, ace_tilemov, sizeof(ace_tilemov),
        CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("ACE 1 B4 requires APX", CDISASM_CPU_X86,
        CDISASM_MODE_64, ace_tilemov_b4, sizeof(ace_tilemov_b4),
        CDISASM_X86_DECODE_FLAG_AMX,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("ACE 1 B4 still requires ACE", CDISASM_CPU_X86,
        CDISASM_MODE_64, ace_tilemov_b4, sizeof(ace_tilemov_b4),
        CDISASM_X86_DECODE_FLAG_APX,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        ace_tilemov_b4, sizeof(ace_tilemov_b4),
        CDISASM_X86_DECODE_FLAG_AMX | CDISASM_X86_DECODE_FLAG_APX,
        &decoded_size);
    EXPECT(decoded_size == sizeof(ace_tilemov_b4));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_TILEMOVROW);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ZMM1);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_ACE_1));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));

    expect_error("ACE TOP named-profile gate", CDISASM_CPU_DIAMOND_RAPIDS,
        CDISASM_MODE_64, ace_top, sizeof(ace_top),
        CDISASM_X86_DECODE_FLAG_AMX, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("ACE TOP mode gate", CDISASM_CPU_X86,
        CDISASM_MODE_32, ace_top, sizeof(ace_top),
        CDISASM_X86_DECODE_FLAG_AMX, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("ACE TOP runtime family gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, ace_top, sizeof(ace_top),
        CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("ACE TOP B4 requires APX", CDISASM_CPU_X86,
        CDISASM_MODE_64, ace_top_b4, sizeof(ace_top_b4),
        CDISASM_X86_DECODE_FLAG_AMX,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("ACE TOP B4 still requires ACE", CDISASM_CPU_X86,
        CDISASM_MODE_64, ace_top_b4, sizeof(ace_top_b4),
        CDISASM_X86_DECODE_FLAG_APX,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        ace_top_b4, sizeof(ace_top_b4),
        CDISASM_X86_DECODE_FLAG_AMX | CDISASM_X86_DECODE_FLAG_APX,
        &decoded_size);
    EXPECT(decoded_size == sizeof(ace_top_b4));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_TOP2BF16PS);
    EXPECT(instruction.form_id == UINT16_C(3310));
    EXPECT(instruction.opcode[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_ACE_1));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    expect_error("ACE TOP4MX B4 requires APX", CDISASM_CPU_X86,
        CDISASM_MODE_64, ace_top_mx_b4, sizeof(ace_top_mx_b4),
        CDISASM_X86_DECODE_FLAG_AMX,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("ACE TOP4MX B4 still requires ACE", CDISASM_CPU_X86,
        CDISASM_MODE_64, ace_top_mx_b4, sizeof(ace_top_mx_b4),
        CDISASM_X86_DECODE_FLAG_APX,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        ace_top_mx_b4, sizeof(ace_top_mx_b4),
        CDISASM_X86_DECODE_FLAG_AMX | CDISASM_X86_DECODE_FLAG_APX,
        &decoded_size);
    EXPECT(decoded_size == sizeof(ace_top_mx_b4));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_TOP4MXBF8PS);
    EXPECT(instruction.form_id == UINT16_C(3315));
    EXPECT(instruction.operand_count == 4u);
    EXPECT(instruction.opcode[3].imm == UINT64_C(0x12));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_ACE_1));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));

    instruction = decode_mode(
        CDISASM_CPU_AVX10, CDISASM_MODE_64, bf16, sizeof(bf16),
        CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == sizeof(bf16));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VADDBF16);
    instruction = decode_mode(
        CDISASM_CPU_APX, CDISASM_MODE_64, bf16, sizeof(bf16),
        CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == sizeof(bf16));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VADDBF16);
    expect_error("AVX10.2 CPU gate", CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_MODE_64, bf16, sizeof(bf16),
        CDISASM_X86_DECODE_FLAG_AVX10, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("AVX10.2 runtime gate", CDISASM_CPU_AVX10,
        CDISASM_MODE_64, bf16, sizeof(bf16),
        CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    instruction = decode_mode(
        CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        apx, sizeof(apx), CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(apx));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_OR);
    expect_error("APX CPU gate", CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_MODE_64, apx, sizeof(apx),
        CDISASM_X86_DECODE_FLAG_APX, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("APX mode gate", CDISASM_CPU_APX,
        CDISASM_MODE_32, apx, sizeof(apx),
        CDISASM_X86_DECODE_FLAG_APX, CDISASM_STATUS_INVALID_INSTRUCTION);

    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64)
            & CDISASM_X86_DECODE_FLAG_AMX) != 0);
    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64)
            & CDISASM_X86_DECODE_FLAG_APX) == 0);
    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64)
            & (CDISASM_X86_DECODE_FLAG_AMX
               | CDISASM_X86_DECODE_FLAG_AVX10
               | CDISASM_X86_DECODE_FLAG_APX))
           == (CDISASM_X86_DECODE_FLAG_AMX
               | CDISASM_X86_DECODE_FLAG_AVX10
               | CDISASM_X86_DECODE_FLAG_APX));
    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_32)
            & CDISASM_X86_DECODE_FLAG_AMX) == 0);
    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_AVX10, CDISASM_MODE_16)
            & CDISASM_X86_DECODE_FLAG_AVX10) != 0);
#endif
}

static void test_apx_audit_regressions(void)
{
    static const uint8_t movdir64b_w0[] = {
        0x62, 0xec, 0x7d, 0x08, 0xf8, 0x11
    };
    static const uint8_t apx_or_two_operand[] = {
        0x62, 0xec, 0xfc, 0x08, 0x09, 0xd1
    };
    static const uint8_t apx_or_nf_two_operand[] = {
        0x62, 0xec, 0xfc, 0x0c, 0x09, 0xd1
    };
    static const uint8_t apx_adc_nf_two_operand[] = {
        0x62, 0xec, 0xfc, 0x0c, 0x11, 0xd1
    };
    static const struct fixed_case {
        const char *label;
        uint8_t bytes[5];
        uint8_t size;
    } wbinvd_cases[] = {
        {"REX2 WBINVD", {0xd5, 0x80, 0x09}, 3},
        {"F3 REX2 WBINVD", {0xf3, 0xd5, 0x80, 0x09}, 4},
        {"F2 REX2 WBINVD", {0xf2, 0xd5, 0x80, 0x09}, 4},
        {"66 REX2 WBINVD", {0x66, 0xd5, 0x80, 0x09}, 4}
    };
    static const struct cet_case {
        const char *label;
        uint8_t bytes[5];
        cdisasm_x86_name_id name_id;
        uint8_t operand_count;
        uint8_t privileged;
    } cet_cases[] = {
        {"REX2 SETSSBSY", {0xf3, 0xd5, 0x80, 0x01, 0xe8},
         CDISASM_X86_NAME_SETSSBSY, 0, 1},
        {"REX2 SAVEPREVSSP", {0xf3, 0xd5, 0x80, 0x01, 0xea},
         CDISASM_X86_NAME_SAVEPREVSSP, 0, 0},
        {"REX2 RSTORSSP", {0xf3, 0xd5, 0x80, 0x01, 0x28},
         CDISASM_X86_NAME_RSTORSSP, 1, 0}
    };
    static const struct rex2_random_case {
        const char *label;
        uint8_t bytes[4];
        cdisasm_x86_name_id name_id;
        cdisasm_x86_group_id group_id;
    } rex2_random_cases[] = {
        {"REX2 RDRAND r16d", {0xd5, 0x90, 0xc7, 0xf0},
         CDISASM_X86_NAME_RDRAND, CDISASM_X86_GROUP_RDRAND},
        {"REX2 RDSEED r16d", {0xd5, 0x90, 0xc7, 0xf8},
         CDISASM_X86_NAME_RDSEED, CDISASM_X86_GROUP_RDSEED}
    };
    static const struct rex2_monitor_case {
        const char *label;
        uint8_t bytes[4];
        cdisasm_x86_name_id name_id;
        cdisasm_x86_form_id form_id;
        const char *mnemonic;
    } rex2_monitor_cases[] = {
        {"REX2 MONITOR", {0xd5, 0x80, 0x01, 0xc8},
         CDISASM_X86_NAME_MONITOR, UINT16_C(1639), "monitor"},
        {"REX2 MWAIT with ignored extension bits", {0xd5, 0xff, 0x01, 0xc9},
         CDISASM_X86_NAME_MWAIT, UINT16_C(1821), "mwait"}
    };
    static const uint8_t f2_group7_e8[] = {
        0xf2, 0xd5, 0x80, 0x01, 0xe8
    };
    size_t index;

    /* NF is forbidden for ADC independently of whether NDD requests a third
     * destination operand.  The F2 Group-7 row belongs to XSUSLDTRK and must
     * not be accepted as either SERIALIZE or SETSSBSY. */
    expect_error("APX two-operand ADC NF", CDISASM_CPU_X86,
        CDISASM_MODE_64, apx_adc_nf_two_operand,
        sizeof(apx_adc_nf_two_operand), STRUCTURAL_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("F2 REX2 Group-7 E8 collision", CDISASM_CPU_X86,
        CDISASM_MODE_64, f2_group7_e8, sizeof(f2_group7_e8),
        STRUCTURAL_FLAGS, CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_APX, CDISASM_MODE_64,
            movdir64b_w0, sizeof(movdir64b_w0),
            CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);

        /* MOVDIR64B is WIG in the APX encoding.  W=0 retains 64-bit address
         * GPRs and the architecturally implicit 64-byte destination memory. */
        EXPECT(decoded_size == sizeof(movdir64b_w0));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVDIR64B);
        EXPECT(instruction.operand_count == 3);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R18);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R17);
        EXPECT(instruction.opcode[1].size == 64u);
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R18);
        EXPECT(instruction.opcode[2].size == 64u);
        EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT((instruction.opcode[2].flags
                & CDISASM_OPERAND_FLAG_IMPLICIT) != 0);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_MOVDIR64B));
        expect_format_mnemonic(&instruction, "movdir64b");
        expect_error("APX MOVDIR64B WIG runtime family",
            CDISASM_CPU_APX, CDISASM_MODE_64,
            movdir64b_w0, sizeof(movdir64b_w0),
            CDISASM_X86_DECODE_FLAG_APX,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_APX, CDISASM_MODE_64,
            apx_or_two_operand, sizeof(apx_or_two_operand),
            CDISASM_X86_DECODE_FLAG_APX, &decoded_size);

        EXPECT(decoded_size == sizeof(apx_or_two_operand));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_OR);
        EXPECT(instruction.operand_count == 2);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R17);
        EXPECT(instruction.opcode[0].access
               == CDISASM_OPERAND_ACCESS_READ_WRITE);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R18);
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT((instruction.opcode_flags
                & (CDISASM_PREFIX_APX_NDD | CDISASM_PREFIX_APX_NF)) == 0);

        instruction = decode_mode(
            CDISASM_CPU_APX, CDISASM_MODE_64,
            apx_or_nf_two_operand, sizeof(apx_or_nf_two_operand),
            CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
        EXPECT(decoded_size == sizeof(apx_or_nf_two_operand));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_OR);
        EXPECT(instruction.operand_count == 2);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R17);
        EXPECT(instruction.opcode[0].access
               == CDISASM_OPERAND_ACCESS_READ_WRITE);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R18);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NDD) == 0);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NF) != 0);
    }

    for (index = 0;
         index < sizeof(wbinvd_cases) / sizeof(wbinvd_cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_APX, CDISASM_MODE_64,
            wbinvd_cases[index].bytes, wbinvd_cases[index].size,
            CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);

        EXPECT(decoded_size == wbinvd_cases[index].size);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_WBINVD);
        EXPECT(instruction.name_id != CDISASM_X86_NAME_WBNOINVD);
        EXPECT(instruction.operand_count == 0);
        EXPECT((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        expect_format_mnemonic(&instruction, "wbinvd");
    }

    for (index = 0;
         index < sizeof(rex2_random_cases)
             / sizeof(rex2_random_cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            rex2_random_cases[index].bytes,
            sizeof(rex2_random_cases[index].bytes),
            CDISASM_X86_DECODE_FLAG_SECURITY, &decoded_size);

        EXPECT(decoded_size == sizeof(rex2_random_cases[index].bytes));
        EXPECT(instruction.name_id == rex2_random_cases[index].name_id);
        EXPECT(instruction.operand_count == 1u);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R16D);
        EXPECT(instruction.opcode[0].size == 4u);
        EXPECT(instruction.opcode[0].access
            == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, rex2_random_cases[index].group_id));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
    }

    for (index = 0;
         index < sizeof(rex2_monitor_cases)
             / sizeof(rex2_monitor_cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_APX, CDISASM_MODE_64,
            rex2_monitor_cases[index].bytes,
            sizeof(rex2_monitor_cases[index].bytes),
            CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);

        EXPECT(decoded_size == sizeof(rex2_monitor_cases[index].bytes));
        EXPECT(instruction.name_id == rex2_monitor_cases[index].name_id);
        EXPECT(instruction.form_id == rex2_monitor_cases[index].form_id);
        EXPECT(instruction.operand_count == 0u);
        EXPECT((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_MONITOR_MWAIT));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        expect_format_mnemonic(
            &instruction, rex2_monitor_cases[index].mnemonic);

        expect_error("REX2 MONITOR/MWAIT CPU APX cross-gate",
            CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
            rex2_monitor_cases[index].bytes,
            sizeof(rex2_monitor_cases[index].bytes),
            CDISASM_X86_DECODE_FLAG_SYSTEM,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("REX2 MONITOR/MWAIT runtime family",
            CDISASM_CPU_APX, CDISASM_MODE_64,
            rex2_monitor_cases[index].bytes,
            sizeof(rex2_monitor_cases[index].bytes),
            CDISASM_X86_DECODE_FLAG_APX,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    for (index = 0;
         index < sizeof(cet_cases) / sizeof(cet_cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_APX, CDISASM_MODE_64,
            cet_cases[index].bytes, sizeof(cet_cases[index].bytes),
            CDISASM_X86_DECODE_FLAG_CET, &decoded_size);

        EXPECT(decoded_size == sizeof(cet_cases[index].bytes));
        EXPECT(instruction.name_id == cet_cases[index].name_id);
        EXPECT(instruction.operand_count == cet_cases[index].operand_count);
        EXPECT(((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0)
               == cet_cases[index].privileged);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_CET_SS));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        if (cet_cases[index].name_id == CDISASM_X86_NAME_RSTORSSP) {
            EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
            EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_RAX);
            EXPECT(instruction.opcode[0].size == 8u);
            EXPECT(instruction.opcode[0].access
                   == CDISASM_OPERAND_ACCESS_READ_WRITE);
        }

        /* REX2 requires APX-F from the CPU profile, while this instruction
         * family is selected at runtime by CET rather than APX. */
        expect_error("REX2 Group-7 CPU APX cross-gate",
            CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
            cet_cases[index].bytes, sizeof(cet_cases[index].bytes),
            CDISASM_X86_DECODE_FLAG_CET,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("REX2 Group-7 CET runtime gate",
            CDISASM_CPU_APX, CDISASM_MODE_64,
            cet_cases[index].bytes, sizeof(cet_cases[index].bytes),
            CDISASM_X86_DECODE_FLAG_APX,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#else
    {
        static const struct off_case {
            const char *label;
            const uint8_t *bytes;
            size_t size;
        } cases[] = {
            {"APX MOVDIR64B W=0 WIG", movdir64b_w0,
             sizeof(movdir64b_w0)},
            {"APX two-operand OR", apx_or_two_operand,
             sizeof(apx_or_two_operand)},
            {"APX two-operand OR NF", apx_or_nf_two_operand,
             sizeof(apx_or_nf_two_operand)}
        };

        for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
            expect_error(cases[index].label, CDISASM_CPU_X86,
                CDISASM_MODE_64, cases[index].bytes, cases[index].size,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
        for (index = 0;
             index < sizeof(wbinvd_cases) / sizeof(wbinvd_cases[0]); ++index) {
            expect_error(wbinvd_cases[index].label, CDISASM_CPU_X86,
                CDISASM_MODE_64, wbinvd_cases[index].bytes,
                wbinvd_cases[index].size, CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
        for (index = 0;
             index < sizeof(cet_cases) / sizeof(cet_cases[0]); ++index) {
            expect_error(cet_cases[index].label, CDISASM_CPU_X86,
                CDISASM_MODE_64, cet_cases[index].bytes,
                sizeof(cet_cases[index].bytes),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
        for (index = 0;
             index < sizeof(rex2_random_cases)
                 / sizeof(rex2_random_cases[0]); ++index) {
            expect_error(rex2_random_cases[index].label,
                CDISASM_CPU_X86, CDISASM_MODE_64,
                rex2_random_cases[index].bytes,
                sizeof(rex2_random_cases[index].bytes),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
        for (index = 0;
             index < sizeof(rex2_monitor_cases)
                 / sizeof(rex2_monitor_cases[0]); ++index) {
            expect_error(rex2_monitor_cases[index].label,
                CDISASM_CPU_X86, CDISASM_MODE_64,
                rex2_monitor_cases[index].bytes,
                sizeof(rex2_monitor_cases[index].bytes),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
    }
#endif
}

static void test_reserved_and_truncated(void)
{
    static const struct error_case {
        const char *label;
        uint8_t bytes[8];
        uint8_t size;
        cdisasm_status status;
    } cases[] = {
        {"AMX complex bad vvvv", {0xc4, 0xe2, 0x70, 0x6c, 0xc1}, 5,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AMX FP8 W=1", {0xc4, 0xe5, 0xe8, 0xfd, 0xc1}, 5,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AMX FP8 L=1", {0xc4, 0xe5, 0x6c, 0xfd, 0xc1}, 5,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AMX MOVRS register source",
         {0xc4, 0xe2, 0x7b, 0x4a, 0xc0}, 5,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AMX MOVRS W=1",
         {0xc4, 0xe2, 0xfb, 0x4a, 0x04, 0x10}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AMX row wrong LL", {0x62, 0xf2, 0x7e, 0x28, 0x4a, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AMX row broadcast", {0x62, 0xf2, 0x7e, 0x58, 0x4a, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AMX row zeroing", {0x62, 0xf2, 0x7e, 0xc8, 0x4a, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AMX row mask", {0x62, 0xf2, 0x7e, 0x49, 0x4a, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AMX row extended TMM", {0x62, 0xd2, 0x7e, 0x48, 0x4a, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AMX row immediate vvvv",
         {0x62, 0xf3, 0x76, 0x48, 0x07, 0xc1, 0x05}, 7,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AMX row memory TMM",
         {0x62, 0xf2, 0x7e, 0x48, 0x4a, 0x01}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE tile move wrong LL",
         {0x62, 0xf2, 0xfd, 0x28, 0x4a, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE tile move broadcast",
         {0x62, 0xf2, 0xfd, 0x58, 0x4b, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE tile move mask",
         {0x62, 0xf2, 0xfd, 0x49, 0x4a, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE tile move extended TMM R",
         {0x62, 0xe2, 0xfd, 0x48, 0x4a, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE tile move extended TMM R prime",
         {0x62, 0x72, 0xfd, 0x48, 0x4b, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE tile move memory ZMM",
         {0x62, 0xf2, 0xfd, 0x48, 0x4a, 0x01}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE tile move U=0",
         {0x62, 0xf2, 0xf9, 0x48, 0x4b, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE tile move wrong pp",
         {0x62, 0xf2, 0xfc, 0x48, 0x4a, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE tile move immediate vvvv",
         {0x62, 0xf3, 0xf5, 0x48, 0x2f, 0xc1, 0x05}, 7,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE tile move immediate V prime",
         {0x62, 0xf3, 0xfd, 0x40, 0x07, 0xc1, 0x05}, 7,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE TOP wrong LL",
         {0x62, 0xf2, 0x6e, 0x28, 0x5c, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE TOP broadcast",
         {0x62, 0xf2, 0x6f, 0x58, 0x5e, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE TOP zeroing",
         {0x62, 0xf2, 0x6e, 0xc8, 0x5c, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE TOP mask",
         {0x62, 0xf2, 0x6f, 0x49, 0x5e, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE TOP W=1",
         {0x62, 0xf2, 0xee, 0x48, 0x5c, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE TOP U=0",
         {0x62, 0xf2, 0x6a, 0x48, 0x5c, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE TOP extended TMM R",
         {0x62, 0xe2, 0x6e, 0x48, 0x5c, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE TOP extended TMM R prime",
         {0x62, 0x72, 0x6f, 0x48, 0x5e, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE TOP memory ZMM",
         {0x62, 0xf2, 0x6e, 0x48, 0x5c, 0x01}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE TOP2 wrong pp",
         {0x62, 0xf2, 0x6f, 0x48, 0x5c, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"ACE TOP4MXBSSPS wrong pp",
         {0x62, 0xf3, 0x6e, 0x48, 0x8f, 0xc1, 0x05}, 7,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AVX10 BF16 LL=3",
         {0x62, 0xf5, 0x75, 0x69, 0x58, 0xc2}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AVX10 BF16 W=1",
         {0x62, 0xf5, 0xf5, 0x49, 0x58, 0xc2}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AVX10 BF16 zeroing without mask",
         {0x62, 0xf5, 0x75, 0xc8, 0x58, 0xc2}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"AVX10 BF16 register broadcast",
         {0x62, 0xf5, 0x75, 0x59, 0x58, 0xc2}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX ADC NF", {0x62, 0xec, 0xfc, 0x14, 0x11, 0xd1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX SBB NF", {0x62, 0xec, 0xfc, 0x14, 0x19, 0xd1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX bad LL", {0x62, 0xec, 0xfc, 0x30, 0x09, 0xd1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX reserved pp", {0x62, 0xec, 0xfe, 0x10, 0x09, 0xd1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX MOVDIRI register destination",
         {0x62, 0xec, 0xfc, 0x08, 0xf9, 0xd1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX MOVDIR64B wrong pp",
         {0x62, 0xec, 0xfc, 0x08, 0xf8, 0x11}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX MOVDIR reserved ND",
         {0x62, 0xec, 0xfc, 0x18, 0xf9, 0x11}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX AMX load register form",
         {0x62, 0xfa, 0x7f, 0x08, 0x4b, 0xc0}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX AMX load zeroing",
         {0x62, 0xfa, 0x7f, 0x88, 0x4b, 0x04, 0x18}, 7,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX AMX cfg nonzero reg",
         {0x62, 0xfa, 0x7c, 0x08, 0x49, 0x08}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX INVEPT register form",
         {0x62, 0xec, 0x7e, 0x08, 0xf0, 0xc1}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX INVVPID reserved ND",
         {0x62, 0xec, 0x7e, 0x18, 0xf1, 0x01}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX INVPCID wrong pp",
         {0x62, 0xec, 0x7f, 0x08, 0xf2, 0x01}, 6,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"truncated AMX VEX", {0xc4, 0xe2, 0x69, 0x6c}, 4,
         CDISASM_STATUS_TRUNCATED},
        {"truncated AMX row", {0x62, 0xf3, 0x7e, 0x48, 0x07, 0xc1}, 6,
         CDISASM_STATUS_TRUNCATED},
        {"truncated ACE tile move",
         {0x62, 0xf3, 0xfd, 0x48, 0x2f, 0xc1}, 6,
         CDISASM_STATUS_TRUNCATED},
        {"truncated ACE TOP4MX",
         {0x62, 0xf3, 0x6c, 0x48, 0x8d, 0xc1}, 6,
         CDISASM_STATUS_TRUNCATED},
        {"truncated AVX10 BF16", {0x62, 0xf5, 0x75, 0x49, 0x58}, 5,
         CDISASM_STATUS_TRUNCATED},
        {"truncated APX", {0x62, 0xec, 0xfc, 0x10, 0x09}, 5,
         CDISASM_STATUS_TRUNCATED}
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error(cases[index].label, CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].bytes, cases[index].size,
            STRUCTURAL_FLAGS, cases[index].status);
    }
}

int main(void)
{
    test_positive_catalogs();
    test_operands_and_variants();
    test_ace_tilemov_register_space();
    test_ace_top_register_space();
    test_cpu_mode_and_runtime_gates();
    test_apx_audit_regressions();
    test_reserved_and_truncated();

    if (failures != 0) {
        fprintf(stderr,
                "x86 next-generation tests failed: %d "
                "(extra=%d, format=%d)\n",
                failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("x86 next-generation tests passed (extra=%d, format=%d)\n",
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
