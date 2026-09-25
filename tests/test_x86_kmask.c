#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_NAME_KANDNW == UINT16_C(943),
               "classic K-mask name range start changed");
_Static_assert(CDISASM_X86_NAME_KXORQ == UINT16_C(993),
               "classic K-mask name range end changed");
_Static_assert(CDISASM_X86_NAME_KXORQ - CDISASM_X86_NAME_KANDNW + 1 == 51,
               "classic K-mask public name range is incomplete");

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

enum kmask_form {
    KMASK_TERNARY,
    KMASK_UNARY,
    KMASK_TEST,
    KMASK_MOVE,
    KMASK_SHIFT,
    KMASK_UNPACK
};

enum kmask_prefix {
    KMASK_PP_NONE = 0,
    KMASK_PP_66 = 1,
    KMASK_PP_F3 = 2,
    KMASK_PP_F2 = 3
};

typedef struct kmask_case {
    const char *mnemonic;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_group_id feature_group;
    uint8_t map;
    uint8_t opcode;
    uint8_t prefix;
    uint8_t w;
    uint8_t length;
    uint8_t form;
    uint8_t bits;
} kmask_case;

#define K(name_, group_, map_, opcode_, pp_, w_, l_, form_, bits_)            \
    {#name_, CDISASM_X86_NAME_##name_, group_, map_, opcode_, pp_, w_, l_,   \
     form_, bits_}

/* Kept in public name-ID order so the table itself proves complete coverage. */
static const kmask_case cases[] = {
    K(KANDNW, CDISASM_X86_GROUP_AVX512F, 1, 0x42, KMASK_PP_NONE, 0, 1,
      KMASK_TERNARY, 16),
    K(KANDW, CDISASM_X86_GROUP_AVX512F, 1, 0x41, KMASK_PP_NONE, 0, 1,
      KMASK_TERNARY, 16),
    K(KMOVW, CDISASM_X86_GROUP_AVX512F, 1, 0x90, KMASK_PP_NONE, 0, 0,
      KMASK_MOVE, 16),
    K(KNOTW, CDISASM_X86_GROUP_AVX512F, 1, 0x44, KMASK_PP_NONE, 0, 0,
      KMASK_UNARY, 16),
    K(KORTESTW, CDISASM_X86_GROUP_AVX512F, 1, 0x98, KMASK_PP_NONE, 0, 0,
      KMASK_TEST, 16),
    K(KORW, CDISASM_X86_GROUP_AVX512F, 1, 0x45, KMASK_PP_NONE, 0, 1,
      KMASK_TERNARY, 16),
    K(KSHIFTLW, CDISASM_X86_GROUP_AVX512F, 3, 0x32, KMASK_PP_66, 1, 0,
      KMASK_SHIFT, 16),
    K(KSHIFTRW, CDISASM_X86_GROUP_AVX512F, 3, 0x30, KMASK_PP_66, 1, 0,
      KMASK_SHIFT, 16),
    K(KUNPCKBW, CDISASM_X86_GROUP_AVX512F, 1, 0x4b, KMASK_PP_66, 0, 1,
      KMASK_UNPACK, 16),
    K(KXNORW, CDISASM_X86_GROUP_AVX512F, 1, 0x46, KMASK_PP_NONE, 0, 1,
      KMASK_TERNARY, 16),
    K(KXORW, CDISASM_X86_GROUP_AVX512F, 1, 0x47, KMASK_PP_NONE, 0, 1,
      KMASK_TERNARY, 16),
    K(KADDB, CDISASM_X86_GROUP_AVX512DQ, 1, 0x4a, KMASK_PP_66, 0, 1,
      KMASK_TERNARY, 8),
    K(KADDD, CDISASM_X86_GROUP_AVX512BW, 1, 0x4a, KMASK_PP_66, 1, 1,
      KMASK_TERNARY, 32),
    K(KADDQ, CDISASM_X86_GROUP_AVX512BW, 1, 0x4a, KMASK_PP_NONE, 1, 1,
      KMASK_TERNARY, 64),
    K(KADDW, CDISASM_X86_GROUP_AVX512DQ, 1, 0x4a, KMASK_PP_NONE, 0, 1,
      KMASK_TERNARY, 16),
    K(KANDB, CDISASM_X86_GROUP_AVX512DQ, 1, 0x41, KMASK_PP_66, 0, 1,
      KMASK_TERNARY, 8),
    K(KANDD, CDISASM_X86_GROUP_AVX512BW, 1, 0x41, KMASK_PP_66, 1, 1,
      KMASK_TERNARY, 32),
    K(KANDNB, CDISASM_X86_GROUP_AVX512DQ, 1, 0x42, KMASK_PP_66, 0, 1,
      KMASK_TERNARY, 8),
    K(KANDND, CDISASM_X86_GROUP_AVX512BW, 1, 0x42, KMASK_PP_66, 1, 1,
      KMASK_TERNARY, 32),
    K(KANDNQ, CDISASM_X86_GROUP_AVX512BW, 1, 0x42, KMASK_PP_NONE, 1, 1,
      KMASK_TERNARY, 64),
    K(KANDQ, CDISASM_X86_GROUP_AVX512BW, 1, 0x41, KMASK_PP_NONE, 1, 1,
      KMASK_TERNARY, 64),
    K(KMOVB, CDISASM_X86_GROUP_AVX512DQ, 1, 0x90, KMASK_PP_66, 0, 0,
      KMASK_MOVE, 8),
    K(KMOVD, CDISASM_X86_GROUP_AVX512BW, 1, 0x90, KMASK_PP_66, 1, 0,
      KMASK_MOVE, 32),
    K(KMOVQ, CDISASM_X86_GROUP_AVX512BW, 1, 0x90, KMASK_PP_NONE, 1, 0,
      KMASK_MOVE, 64),
    K(KNOTB, CDISASM_X86_GROUP_AVX512DQ, 1, 0x44, KMASK_PP_66, 0, 0,
      KMASK_UNARY, 8),
    K(KNOTD, CDISASM_X86_GROUP_AVX512BW, 1, 0x44, KMASK_PP_66, 1, 0,
      KMASK_UNARY, 32),
    K(KNOTQ, CDISASM_X86_GROUP_AVX512BW, 1, 0x44, KMASK_PP_NONE, 1, 0,
      KMASK_UNARY, 64),
    K(KORB, CDISASM_X86_GROUP_AVX512DQ, 1, 0x45, KMASK_PP_66, 0, 1,
      KMASK_TERNARY, 8),
    K(KORD, CDISASM_X86_GROUP_AVX512BW, 1, 0x45, KMASK_PP_66, 1, 1,
      KMASK_TERNARY, 32),
    K(KORQ, CDISASM_X86_GROUP_AVX512BW, 1, 0x45, KMASK_PP_NONE, 1, 1,
      KMASK_TERNARY, 64),
    K(KORTESTB, CDISASM_X86_GROUP_AVX512DQ, 1, 0x98, KMASK_PP_66, 0, 0,
      KMASK_TEST, 8),
    K(KORTESTD, CDISASM_X86_GROUP_AVX512BW, 1, 0x98, KMASK_PP_66, 1, 0,
      KMASK_TEST, 32),
    K(KORTESTQ, CDISASM_X86_GROUP_AVX512BW, 1, 0x98, KMASK_PP_NONE, 1, 0,
      KMASK_TEST, 64),
    K(KSHIFTLB, CDISASM_X86_GROUP_AVX512DQ, 3, 0x32, KMASK_PP_66, 0, 0,
      KMASK_SHIFT, 8),
    K(KSHIFTLD, CDISASM_X86_GROUP_AVX512BW, 3, 0x33, KMASK_PP_66, 0, 0,
      KMASK_SHIFT, 32),
    K(KSHIFTLQ, CDISASM_X86_GROUP_AVX512BW, 3, 0x33, KMASK_PP_66, 1, 0,
      KMASK_SHIFT, 64),
    K(KSHIFTRB, CDISASM_X86_GROUP_AVX512DQ, 3, 0x30, KMASK_PP_66, 0, 0,
      KMASK_SHIFT, 8),
    K(KSHIFTRD, CDISASM_X86_GROUP_AVX512BW, 3, 0x31, KMASK_PP_66, 0, 0,
      KMASK_SHIFT, 32),
    K(KSHIFTRQ, CDISASM_X86_GROUP_AVX512BW, 3, 0x31, KMASK_PP_66, 1, 0,
      KMASK_SHIFT, 64),
    K(KTESTB, CDISASM_X86_GROUP_AVX512DQ, 1, 0x99, KMASK_PP_66, 0, 0,
      KMASK_TEST, 8),
    K(KTESTD, CDISASM_X86_GROUP_AVX512BW, 1, 0x99, KMASK_PP_66, 1, 0,
      KMASK_TEST, 32),
    K(KTESTQ, CDISASM_X86_GROUP_AVX512BW, 1, 0x99, KMASK_PP_NONE, 1, 0,
      KMASK_TEST, 64),
    K(KTESTW, CDISASM_X86_GROUP_AVX512DQ, 1, 0x99, KMASK_PP_NONE, 0, 0,
      KMASK_TEST, 16),
    K(KUNPCKDQ, CDISASM_X86_GROUP_AVX512BW, 1, 0x4b, KMASK_PP_NONE, 1, 1,
      KMASK_UNPACK, 64),
    K(KUNPCKWD, CDISASM_X86_GROUP_AVX512BW, 1, 0x4b, KMASK_PP_NONE, 0, 1,
      KMASK_UNPACK, 32),
    K(KXNORB, CDISASM_X86_GROUP_AVX512DQ, 1, 0x46, KMASK_PP_66, 0, 1,
      KMASK_TERNARY, 8),
    K(KXNORD, CDISASM_X86_GROUP_AVX512BW, 1, 0x46, KMASK_PP_66, 1, 1,
      KMASK_TERNARY, 32),
    K(KXNORQ, CDISASM_X86_GROUP_AVX512BW, 1, 0x46, KMASK_PP_NONE, 1, 1,
      KMASK_TERNARY, 64),
    K(KXORB, CDISASM_X86_GROUP_AVX512DQ, 1, 0x47, KMASK_PP_66, 0, 1,
      KMASK_TERNARY, 8),
    K(KXORD, CDISASM_X86_GROUP_AVX512BW, 1, 0x47, KMASK_PP_66, 1, 1,
      KMASK_TERNARY, 32),
    K(KXORQ, CDISASM_X86_GROUP_AVX512BW, 1, 0x47, KMASK_PP_NONE, 1, 1,
      KMASK_TERNARY, 64)
};

#undef K

_Static_assert(sizeof(cases) / sizeof(cases[0]) == 51,
               "one canonical vector is required per public K-mask name");

static cdisasm_instruction decode(
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

static int error_is_zeroed(
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
    cdisasm_instruction instruction = decode(
        cpu, mode, bytes, size, flags, &decoded_size);

    if (decoded_size != 0 || !error_is_zeroed(&instruction, status)) {
        fprintf(stderr,
                "%s: expected status %u, got status %u and size %u\n",
                label, (unsigned int)status,
                (unsigned int)instruction.last_error_id,
                (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == 0);
    EXPECT(error_is_zeroed(&instruction, status));
}

static size_t build_canonical(const kmask_case *test, uint8_t bytes[6])
{
    const unsigned int source =
        test->form == KMASK_TERNARY || test->form == KMASK_UNPACK ? 2u : 0u;

    bytes[0] = UINT8_C(0xc4);
    bytes[1] = (uint8_t)(UINT8_C(0xe0) | test->map);
    bytes[2] = (uint8_t)((test->w << 7)
        | (((~source) & 15u) << 3)
        | (test->length << 2) | test->prefix);
    bytes[3] = test->opcode;
    bytes[4] = UINT8_C(0xcb); /* REG=K1, r/m=K3. */
    if (test->form == KMASK_SHIFT) {
        bytes[5] = UINT8_C(5);
        return 6;
    }
    return 5;
}

#if USE_EXTRA_OPCODES
static void check_avx512_groups(
    const cdisasm_instruction *instruction,
    cdisasm_x86_group_id feature_group)
{
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512DQ)
           == (feature_group == CDISASM_X86_GROUP_AVX512DQ));
    EXPECT(cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512BW)
           == (feature_group == CDISASM_X86_GROUP_AVX512BW));
}

static void check_operands(
    const cdisasm_instruction *instruction,
    const kmask_case *test)
{
    const uint8_t mask_size = (uint8_t)(test->bits / 8u);
    const int three_mask_operands = test->form == KMASK_TERNARY
        || test->form == KMASK_UNPACK;
    const uint8_t operand_count = (uint8_t)(three_mask_operands
        || test->form == KMASK_SHIFT ? 3u : 2u);
    uint8_t source_size = mask_size;

    if (test->form == KMASK_UNPACK) {
        source_size = (uint8_t)(mask_size / 2u);
    }
    EXPECT(instruction->operand_count == operand_count);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg == CDISASM_X86_REG_K1);
    EXPECT(instruction->opcode[0].size == mask_size);
    EXPECT(instruction->opcode[0].access == (test->form == KMASK_TEST
        ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg == (three_mask_operands
        ? CDISASM_X86_REG_K2 : CDISASM_X86_REG_K3));
    EXPECT(instruction->opcode[1].size == source_size);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    if (three_mask_operands) {
        EXPECT(instruction->opcode[2].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction->opcode[2].reg == CDISASM_X86_REG_K3);
        EXPECT(instruction->opcode[2].size == source_size);
        EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    } else if (test->form == KMASK_SHIFT) {
        EXPECT(instruction->opcode[2].type == CDISASM_OPERAND_IMMEDIATE);
        EXPECT(instruction->opcode[2].size == 1u);
        EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction->opcode[2].imm == UINT64_C(5));
    }
}

#if USE_DISASM_FORMAT
static void expect_format_text(
    const cdisasm_instruction *instruction,
    const char *intel,
    const char *att)
{
    char text[128];
    size_t length = cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        text, sizeof(text));

    if (strcmp(text, intel) != 0) {
        fprintf(stderr, "Intel format '%s', expected '%s'\n", text, intel);
    }
    EXPECT(length == strlen(intel));
    EXPECT(strcmp(text, intel) == 0);

    length = cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        text, sizeof(text));
    if (strcmp(text, att) != 0) {
        fprintf(stderr, "AT&T format '%s', expected '%s'\n", text, att);
    }
    EXPECT(length == strlen(att));
    EXPECT(strcmp(text, att) == 0);
}

static void check_canonical_format(
    const cdisasm_instruction *instruction,
    const kmask_case *test)
{
    char mnemonic[32];
    char intel[96];
    char att[96];
    size_t index;

    for (index = 0;
         index + 1u < sizeof(mnemonic) && test->mnemonic[index] != '\0';
         ++index) {
        mnemonic[index] = (char)tolower((unsigned char)test->mnemonic[index]);
    }
    mnemonic[index] = '\0';

    if (test->form == KMASK_TERNARY || test->form == KMASK_UNPACK) {
        (void)snprintf(intel, sizeof(intel),
                       "%s k1, k2, k3", mnemonic);
        (void)snprintf(att, sizeof(att),
                       "%s %%k3, %%k2, %%k1", mnemonic);
    } else if (test->form == KMASK_SHIFT) {
        (void)snprintf(intel, sizeof(intel),
                       "%s k1, k3, 0x5", mnemonic);
        (void)snprintf(att, sizeof(att),
                       "%s $0x5, %%k3, %%k1", mnemonic);
    } else {
        (void)snprintf(intel, sizeof(intel),
                       "%s k1, k3", mnemonic);
        (void)snprintf(att, sizeof(att),
                       "%s %%k3, %%k1", mnemonic);
    }
    expect_format_text(instruction, intel, att);
}
#else
#define check_canonical_format(instruction_, test_) ((void)0)
#define expect_format_text(instruction_, intel_, att_) ((void)0)
#endif

static void check_canonical_success(
    const kmask_case *test,
    const uint8_t *bytes,
    size_t size,
    cdisasm_mode mode)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, mode, bytes, size,
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);

    if (decoded_size != size || instruction.name_id != test->name_id) {
        fprintf(stderr,
                "%s mode %u: got name %u, status %u and size %u\n",
                test->mnemonic, (unsigned int)mode,
                (unsigned int)instruction.name_id,
                (unsigned int)instruction.last_error_id,
                (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == test->name_id);
    EXPECT(instruction.opcode_size == size);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX) != 0);
    EXPECT((instruction.opcode_flags
            & (CDISASM_PREFIX_EVEX | CDISASM_PREFIX_XOP
               | CDISASM_PREFIX_REX2)) == 0);
    EXPECT(instruction.encoding.prefix_size == 3u);
    EXPECT(instruction.encoding.opcode_offset == 3u);
    EXPECT(instruction.encoding.opcode_size == 1u);
    EXPECT(instruction.encoding.modrm_offset == 4u);
    EXPECT(instruction.mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction.mask_mode == CDISASM_X86_MASK_NONE);
    check_avx512_groups(&instruction, test->feature_group);
    check_operands(&instruction, test);
    if (test->form == KMASK_SHIFT) {
        EXPECT(instruction.encoding.immediate_count == 1u);
        EXPECT(instruction.encoding.immediate_offset[0] == 5u);
        EXPECT(instruction.encoding.immediate_size[0] == 1u);
    } else {
        EXPECT(instruction.encoding.immediate_count == 0u);
    }
    check_canonical_format(&instruction, test);
}
#endif

static void test_public_catalog(void)
{
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const kmask_case *test = &cases[index];
        uint8_t bytes[6];
        const size_t size = build_canonical(test, bytes);
        size_t mode_index;

        EXPECT(test->name_id == CDISASM_X86_NAME_KANDNW + index);
        EXPECT(size == (test->form == KMASK_SHIFT ? 6u : 5u));
        for (mode_index = 0;
             mode_index < sizeof(modes) / sizeof(modes[0]); ++mode_index) {
#if USE_EXTRA_OPCODES
            check_canonical_success(test, bytes, size, modes[mode_index]);
#else
            expect_error(test->mnemonic, CDISASM_CPU_X86,
                modes[mode_index], bytes, size,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }

        expect_error(test->mnemonic, CDISASM_CPU_X86,
            CDISASM_MODE_64, bytes, size - 1u, STRUCTURAL_FLAGS,
            CDISASM_STATUS_TRUNCATED);

#if USE_EXTRA_OPCODES
        expect_error(test->mnemonic, CDISASM_CPU_SKYLAKE_SP,
            CDISASM_MODE_64, bytes, size,
            CDISASM_X86_DECODE_FLAG_AVX,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error(test->mnemonic, CDISASM_CPU_ALDER_LAKE,
            CDISASM_MODE_64, bytes, size,
            CDISASM_X86_DECODE_FLAG_AVX512,
            CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
    }
}

static void test_avx10_promotions(void)
{
    static const size_t route_indices[] = {
        CDISASM_X86_NAME_KANDW - CDISASM_X86_NAME_KANDNW,
        CDISASM_X86_NAME_KADDB - CDISASM_X86_NAME_KANDNW,
        CDISASM_X86_NAME_KANDD - CDISASM_X86_NAME_KANDNW
    };
    static const cdisasm_cpu_id abstract_cpus[] = {
        CDISASM_CPU_AVX10, CDISASM_CPU_APX
    };
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t route_index;

    for (route_index = 0;
         route_index < sizeof(route_indices) / sizeof(route_indices[0]);
         ++route_index) {
        const kmask_case *test = &cases[route_indices[route_index]];
        uint8_t bytes[6];
        const size_t size = build_canonical(test, bytes);
        size_t cpu_index;

        EXPECT(test->feature_group == (route_index == 0
            ? CDISASM_X86_GROUP_AVX512F
            : (route_index == 1
                ? CDISASM_X86_GROUP_AVX512DQ
                : CDISASM_X86_GROUP_AVX512BW)));

#if USE_EXTRA_OPCODES
        for (cpu_index = 0;
             cpu_index < sizeof(abstract_cpus) / sizeof(abstract_cpus[0]);
             ++cpu_index) {
            size_t mode_index;

            for (mode_index = 0;
                 mode_index < sizeof(modes) / sizeof(modes[0]);
                 ++mode_index) {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    abstract_cpus[cpu_index], modes[mode_index],
                    bytes, size, CDISASM_X86_DECODE_FLAG_AVX10,
                    &decoded_size);

                EXPECT(decoded_size == size);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == test->name_id);
                check_operands(&instruction, test);
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX10_1));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX10_2));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512F));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512DQ));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512BW));
                check_canonical_format(&instruction, test);
            }

            expect_error("AVX10 K-mask wrong AVX512 runtime bit",
                abstract_cpus[cpu_index], CDISASM_MODE_64,
                bytes, size, CDISASM_X86_DECODE_FLAG_AVX512,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error("AVX10 K-mask wrong AVX runtime bit",
                abstract_cpus[cpu_index], CDISASM_MODE_64,
                bytes, size, CDISASM_X86_DECODE_FLAG_AVX,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            if (abstract_cpus[cpu_index] == CDISASM_CPU_APX) {
                expect_error("AVX10 K-mask wrong APX runtime bit",
                    abstract_cpus[cpu_index], CDISASM_MODE_64,
                    bytes, size, CDISASM_X86_DECODE_FLAG_APX,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            }
        }

        /* A physical AVX-512 profile keeps the established F plus optional
         * DQ/BW classification and must not be reclassified as AVX10.1. */
        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                bytes, size, CDISASM_X86_DECODE_FLAG_AVX512,
                &decoded_size);

            EXPECT(decoded_size == size);
            EXPECT(instruction.name_id == test->name_id);
            check_avx512_groups(&instruction, test->feature_group);
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX10_1));
        }
        expect_error("legacy K-mask wrong AVX10 runtime bit",
            CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
            bytes, size, CDISASM_X86_DECODE_FLAG_AVX10,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        for (cpu_index = 0;
             cpu_index < sizeof(abstract_cpus) / sizeof(abstract_cpus[0]);
             ++cpu_index) {
            size_t mode_index;

            for (mode_index = 0;
                 mode_index < sizeof(modes) / sizeof(modes[0]);
                 ++mode_index) {
                expect_error("AVX10 K-mask extras OFF",
                    abstract_cpus[cpu_index], modes[mode_index],
                    bytes, size, CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            }
        }
#endif
    }
}

static void test_xed_extension_rules(void)
{
    static const uint8_t ignored_bx[] = {
        0xc4, 0x81, 0x6c, 0x41, 0xcb
    };
    static const uint8_t op92_b[] = {
        0xc4, 0xc1, 0x7b, 0x92, 0xcb
    };
    static const uint8_t op93_r[] = {
        0xc4, 0x61, 0x7b, 0x93, 0xcb
    };
    static const uint8_t f2_w1_op92[] = {
        0xc4, 0xe1, 0xfb, 0x92, 0xcb
    };
    static const uint8_t f2_w1_op93[] = {
        0xc4, 0xe1, 0xfb, 0x93, 0xcb
    };
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t index;

#if USE_EXTRA_OPCODES
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            ignored_bx, sizeof(ignored_bx),
            CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);

        EXPECT(decoded_size == sizeof(ignored_bx));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_KANDW);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_K1);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_K2);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_K3);
        check_avx512_groups(&instruction, CDISASM_X86_GROUP_AVX512F);
    }

    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            op92_b, sizeof(op92_b),
            CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);

        EXPECT(decoded_size == sizeof(op92_b));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_KMOVD);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_K1);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R11D);
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        check_avx512_groups(&instruction, CDISASM_X86_GROUP_AVX512BW);
        expect_format_text(&instruction, "kmovd k1, r11d", "kmovd %r11d, %k1");

        instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            op93_r, sizeof(op93_r),
            CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
        EXPECT(decoded_size == sizeof(op93_r));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_KMOVD);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R9D);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_K3);
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        check_avx512_groups(&instruction, CDISASM_X86_GROUP_AVX512BW);
        expect_format_text(&instruction, "kmovd r9d, k3", "kmovd %k3, %r9d");
    }

    for (index = 0; index < sizeof(modes) / sizeof(modes[0]); ++index) {
        const int long_mode = modes[index] == CDISASM_MODE_64;
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, modes[index],
            f2_w1_op92, sizeof(f2_w1_op92),
            CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);

        EXPECT(decoded_size == sizeof(f2_w1_op92));
        EXPECT(instruction.name_id == (long_mode
            ? CDISASM_X86_NAME_KMOVQ : CDISASM_X86_NAME_KMOVD));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_K1);
        EXPECT(instruction.opcode[1].reg == (long_mode
            ? CDISASM_X86_REG_RBX : CDISASM_X86_REG_EBX));
        check_avx512_groups(&instruction, CDISASM_X86_GROUP_AVX512BW);

        instruction = decode(
            CDISASM_CPU_X86, modes[index],
            f2_w1_op93, sizeof(f2_w1_op93),
            CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
        EXPECT(decoded_size == sizeof(f2_w1_op93));
        EXPECT(instruction.name_id == (long_mode
            ? CDISASM_X86_NAME_KMOVQ : CDISASM_X86_NAME_KMOVD));
        EXPECT(instruction.opcode[0].reg == (long_mode
            ? CDISASM_X86_REG_RCX : CDISASM_X86_REG_ECX));
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_K3);
        check_avx512_groups(&instruction, CDISASM_X86_GROUP_AVX512BW);
    }
#else
    expect_error("ignored VEX.B/X", CDISASM_CPU_X86, CDISASM_MODE_64,
        ignored_bx, sizeof(ignored_bx), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    for (index = 0; index < sizeof(modes) / sizeof(modes[0]); ++index) {
        expect_error("F2 W1 opcode 92 alias", CDISASM_CPU_X86, modes[index],
            f2_w1_op92, sizeof(f2_w1_op92), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("F2 W1 opcode 93 alias", CDISASM_CPU_X86, modes[index],
            f2_w1_op93, sizeof(f2_w1_op93), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    expect_error("opcode 92 VEX.B GPR extension", CDISASM_CPU_X86,
        CDISASM_MODE_64, op92_b, sizeof(op92_b),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("opcode 93 VEX.R GPR extension", CDISASM_CPU_X86,
        CDISASM_MODE_64, op93_r, sizeof(op93_r),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_apx_kmov_forms(void)
{
    static const struct {
        cdisasm_x86_name_id name;
        cdisasm_x86_group_id group;
        cdisasm_x86_decode_bit_id bit;
        uint8_t bits;
        uint8_t p1_memory;
        uint8_t p1_gpr;
    } widths[] = {
        {CDISASM_X86_NAME_KMOVB, CDISASM_X86_GROUP_APX_F_KOPB,
         CDISASM_X86_DECODE_BIT_APX_F_KOPB, 8, 0x7d, 0x7d},
        {CDISASM_X86_NAME_KMOVW, CDISASM_X86_GROUP_APX_F_KOPW,
         CDISASM_X86_DECODE_BIT_APX_F_KOPW, 16, 0x7c, 0x7c},
        {CDISASM_X86_NAME_KMOVD, CDISASM_X86_GROUP_APX_F_KOPD,
         CDISASM_X86_DECODE_BIT_APX_F_KOPD, 32, 0xfd, 0x7f},
        {CDISASM_X86_NAME_KMOVQ, CDISASM_X86_GROUP_APX_F_KOPQ,
         CDISASM_X86_DECODE_BIT_APX_F_KOPQ, 64, 0xfc, 0xff}
    };
    size_t width_index;

    for (width_index = 0;
         width_index < sizeof(widths) / sizeof(widths[0]); ++width_index) {
        uint8_t bytes[6] = {0x62, 0xf1, 0, 0x08, 0, 0};
        unsigned int form;
        for (form = 0; form < 5u; ++form) {
            cdisasm_x86_decode_flags flags =
                CDISASM_X86_DECODE_FLAGS_INITIALIZER(
                    CDISASM_X86_DECODE_FLAG_BASE);
            cdisasm_instruction instruction;
            uint32_t decoded_size;

#if USE_EXTRA_OPCODES
            EXPECT(cdisasm_decode_flags_set_bit(
                &flags, widths[width_index].bit));
            EXPECT(cdisasm_decode_flags_set_bit(
                &flags, CDISASM_X86_DECODE_BIT_APX));
#endif
            bytes[2] = form < 3u ? widths[width_index].p1_memory
                                : widths[width_index].p1_gpr;
            bytes[4] = (uint8_t)(form == 0u ? 0x90
                : form == 1u ? 0x90 : form == 2u ? 0x91
                : form == 3u ? 0x92 : 0x93);
            bytes[5] = (uint8_t)(form == 0u ? 0xcb
                : form == 1u || form == 2u ? 0x08 : 0xcb);
            memset(&instruction, 0, sizeof(instruction));
            decoded_size = cdisasm_test_x86_decode_exact_flags(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                bytes, sizeof(bytes), UINT64_C(0x1000),
                &flags, &instruction);
#if USE_EXTRA_OPCODES
            EXPECT(decoded_size == sizeof(bytes));
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id == widths[width_index].name);
            EXPECT(instruction.operand_count == 2u);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_APX_F));
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, widths[width_index].group));
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.opcode[form == 2u || form == 4u ? 1u : 0u].size
                == widths[width_index].bits / 8u);
            if (form >= 3u) {
                EXPECT(instruction.opcode[form == 3u ? 1u : 0u].size
                    == (widths[width_index].bits == 64u ? 8u : 4u));
            }
#else
            EXPECT(decoded_size == 0u);
            EXPECT(instruction.last_error_id
                == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }

    {
        static const uint8_t invalid[][6] = {
            {0x62,0xf1,0x7c,0x88,0x90,0xcb}, /* z */
            {0x62,0xf1,0x6c,0x08,0x90,0xcb}, /* non-1111 vvvv */
            {0x62,0x71,0x7c,0x08,0x90,0xcb}, /* extended mask REG */
            {0x62,0xf1,0x7c,0x08,0x91,0xcb}, /* store requires memory */
            {0x62,0xf1,0x7c,0x08,0x92,0x08}  /* GPR source requires reg */
        };
        cdisasm_x86_decode_flags flags =
            CDISASM_X86_DECODE_FLAGS_INITIALIZER(
                STRUCTURAL_FLAGS);
        size_t i;
#if USE_EXTRA_OPCODES
        EXPECT(cdisasm_decode_flags_set_bit(
            &flags, CDISASM_X86_DECODE_BIT_APX_F_KOPW));
#endif
        for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
            cdisasm_instruction instruction;
            uint32_t decoded_size;
            memset(&instruction, 0, sizeof(instruction));
            decoded_size = cdisasm_test_x86_decode_exact_flags(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                invalid[i], sizeof(invalid[i]), UINT64_C(0x1000),
                &flags, &instruction);
            EXPECT(decoded_size == 0u);
            EXPECT(instruction.last_error_id
                == CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
}

static void test_reserved_encodings(void)
{
    static const uint8_t non64_rex_r[] = {
        0xc4, 0x61, 0x7b, 0x93, 0xcb
    };
    static const struct invalid_case {
        const char *label;
        uint8_t bytes[6];
        uint8_t size;
        cdisasm_mode mode;
    } invalid[] = {
        {"VEX.R reserved for K REG", {0xc4, 0x61, 0x6c, 0x41, 0xcb}, 5,
         CDISASM_MODE_64},
        {"K source vvvv extension", {0xc4, 0xe1, 0x3c, 0x41, 0xcb}, 5,
         CDISASM_MODE_64},
        {"ternary K memory source", {0xc4, 0xe1, 0x6c, 0x41, 0x0b}, 5,
         CDISASM_MODE_64},
        {"unary nonzero vvvv", {0xc4, 0xe1, 0x68, 0x44, 0xcb}, 5,
         CDISASM_MODE_64},
        {"shift memory source", {0xc4, 0xe3, 0xf9, 0x32, 0x0b, 0x05}, 6,
         CDISASM_MODE_64},
        {"KMOV store register row", {0xc4, 0xe1, 0x78, 0x91, 0xcb}, 5,
         CDISASM_MODE_64},
        {"unary reserved L", {0xc4, 0xe1, 0x7c, 0x44, 0xcb}, 5,
         CDISASM_MODE_64},
        {"ternary reserved L", {0xc4, 0xe1, 0x78, 0x41, 0xcb}, 5,
         CDISASM_MODE_64},
        {"KMOV GPR memory row", {0xc4, 0xe1, 0x7b, 0x92, 0x0b}, 5,
         CDISASM_MODE_64},
        {"KMOV nonzero vvvv", {0xc4, 0xe1, 0x68, 0x90, 0xcb}, 5,
         CDISASM_MODE_64},
        {"shift reserved L", {0xc4, 0xe3, 0xfd, 0x32, 0xcb, 0x05}, 6,
         CDISASM_MODE_64}
    };
    size_t index;

    for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error(invalid[index].label, CDISASM_CPU_X86,
            invalid[index].mode, invalid[index].bytes, invalid[index].size,
            STRUCTURAL_FLAGS, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    /* Outside long mode C4 with an R-extension bit is not an unambiguous
     * VEX3 prefix; the first three bytes are the legacy LES instruction and
     * the apparent VEX opcode bytes belong to the following instruction. */
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_32,
            non64_rex_r, sizeof(non64_rex_r), STRUCTURAL_FLAGS,
            &decoded_size);

        EXPECT(decoded_size == 3u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        EXPECT(instruction.opcode_size == 3u);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ESP);
        EXPECT(instruction.opcode[0].size == 4u);
        EXPECT(instruction.opcode[0].access
            == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_ECX);
        EXPECT(instruction.opcode[1].size == 6u);
        EXPECT(instruction.opcode[1].access
            == CDISASM_OPERAND_ACCESS_READ);
        EXPECT((instruction.opcode[1].flags
                & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) != 0);
        EXPECT(instruction.opcode[1].imm == UINT64_C(0x7b));
        EXPECT(instruction.encoding.opcode_size == 1u);
        EXPECT(instruction.encoding.modrm_offset == 1u);
        EXPECT(instruction.encoding.displacement_offset == 2u);
        EXPECT(instruction.encoding.displacement_size == 1u);
    }
}

int main(void)
{
    test_public_catalog();
    test_avx10_promotions();
    test_xed_extension_rules();
    test_apx_kmov_forms();
    test_reserved_encodings();

    if (failures != 0) {
        fprintf(stderr,
                "x86 classic K-mask tests failed: %d "
                "(extra=%d, format=%d)\n",
                failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("x86 classic K-mask tests passed (extra=%d, format=%d)\n",
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
