#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_FRECPE == UINT16_C(429)
        && CDISASM_ARM_NAME_FRSQRTE == UINT16_C(430),
    "Advanced SIMD estimates must reuse the established ARM IDs");
_Static_assert(CDISASM_ARM_NAME_FRSQRTE < CDISASM_ARM_NAME_COUNT
        && CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
    "ARM mnemonic IDs must remain contiguous");

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 24) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",      \
                    __FILE__, __LINE__, #condition);                        \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static void word_to_le(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)word;
    bytes[1] = (uint8_t)(word >> 8);
    bytes[2] = (uint8_t)(word >> 16);
    bytes[3] = (uint8_t)(word >> 24);
}

static void word_to_be(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
}

static uint32_t decode_word(
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    size_t code_size,
    cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(cpu_id, mode, bytes, code_size,
        UINT64_C(0x119000), options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static uint32_t scalar_half_word(
    unsigned operation, unsigned rn, unsigned rd)
{
    return UINT32_C(0x5ef9d800)
        | ((uint32_t)operation << 29)
        | ((uint32_t)rn << 5) | (uint32_t)rd;
}

static uint32_t scalar_sd_word(
    unsigned operation, unsigned size, unsigned rn, unsigned rd)
{
    return UINT32_C(0x5ea1d800)
        | ((uint32_t)operation << 29)
        | ((uint32_t)size << 22)
        | ((uint32_t)rn << 5) | (uint32_t)rd;
}

static uint32_t vector_half_word(
    unsigned operation, unsigned q, unsigned rn, unsigned rd)
{
    return UINT32_C(0x0ef9d800)
        | ((uint32_t)q << 30)
        | ((uint32_t)operation << 29)
        | ((uint32_t)rn << 5) | (uint32_t)rd;
}

static uint32_t vector_sd_word(
    unsigned operation, unsigned size, unsigned q,
    unsigned rn, unsigned rd)
{
    return UINT32_C(0x0ea1d800)
        | ((uint32_t)q << 30)
        | ((uint32_t)operation << 29)
        | ((uint32_t)size << 22)
        | ((uint32_t)rn << 5) | (uint32_t)rd;
}

#if USE_EXTRA_OPCODES
static int operand_is_zeroed(const cdisasm_arm_operand *operand)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static cdisasm_arm_reg_id scalar_reg(unsigned encoded, uint8_t size)
{
    return (cdisasm_arm_reg_id)(
        (size == 2u ? CDISASM_ARM_REG_H0
            : size == 4u ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0)
        + encoded);
}

static int metadata_matches(
    const cdisasm_arm_instruction *instruction,
    uint32_t word,
    unsigned operation,
    unsigned rn,
    unsigned rd,
    int vector,
    uint8_t total_size,
    uint8_t element_size)
{
    const cdisasm_arm_operand *destination = &instruction->operand[0];
    const cdisasm_arm_operand *source = &instruction->operand[1];
    const uint32_t expected_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
        | (vector ? CDISASM_ARM_INSTRUCTION_FLAG_SIMD : 0u);
    const cdisasm_arm_reg_id destination_reg = vector
        ? (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rd)
        : scalar_reg(rd, element_size);
    const cdisasm_arm_reg_id source_reg = vector
        ? (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rn)
        : scalar_reg(rn, element_size);

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == (operation != 0u
            ? CDISASM_ARM_NAME_FRSQRTE : CDISASM_ARM_NAME_FRECPE)
        && instruction->address == UINT64_C(0x119000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags == expected_flags
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->operand_count == 2u
        && destination->type == CDISASM_OPERAND_REGISTER
        && destination->reg == destination_reg
        && destination->size == total_size
        && destination->access == CDISASM_OPERAND_ACCESS_WRITE
        && source->type == CDISASM_OPERAND_REGISTER
        && source->reg == source_reg
        && source->size == total_size
        && source->access == CDISASM_OPERAND_ACCESS_READ
        && destination->extend_type
            == (vector ? (cdisasm_arm_extend_type)element_size
                       : CDISASM_ARM_EXTEND_NONE)
        && source->extend_type
            == (vector ? (cdisasm_arm_extend_type)element_size
                       : CDISASM_ARM_EXTEND_NONE)
        && destination->scale
            == (vector ? total_size / element_size : 0u)
        && source->scale
            == (vector ? total_size / element_size : 0u)
        && operand_is_zeroed(&instruction->operand[2])
        && operand_is_zeroed(&instruction->operand[3]);
}
#endif

static void check_allocated(
    uint32_t word,
    unsigned operation,
    unsigned rn,
    unsigned rd,
    int vector,
    uint8_t total_size,
    uint8_t element_size)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded;

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(metadata_matches(&instruction, word, operation, rn, rd,
        vector, total_size, element_size));
#else
    (void)operation;
    (void)rn;
    (void)rd;
    (void)vector;
    (void)total_size;
    (void)element_size;
    EXPECT(decoded == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void check_reserved(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
}

static void test_exhaustive_exact_union(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned operation;

    for (operation = 0u; operation != 2u; ++operation) {
        unsigned rn;

        for (rn = 0u; rn != 32u; ++rn) {
            unsigned rd;

            for (rd = 0u; rd != 32u; ++rd) {
                unsigned size;
                unsigned q;

                ++allocated;
                check_allocated(scalar_half_word(operation, rn, rd),
                    operation, rn, rd, 0, 2u, 2u);
                for (size = 0u; size != 2u; ++size) {
                    uint8_t element_size = (uint8_t)(4u << size);

                    ++allocated;
                    check_allocated(
                        scalar_sd_word(operation, size, rn, rd),
                        operation, rn, rd, 0,
                        element_size, element_size);
                }
                for (q = 0u; q != 2u; ++q) {
                    uint8_t total_size = q != 0u ? 16u : 8u;

                    ++allocated;
                    check_allocated(
                        vector_half_word(operation, q, rn, rd),
                        operation, rn, rd, 1, total_size, 2u);
                    for (size = 0u; size != 2u; ++size) {
                        uint32_t word = vector_sd_word(
                            operation, size, q, rn, rd);
                        uint8_t element_size = (uint8_t)(4u << size);

                        if (size != 0u && q == 0u) {
                            ++reserved;
                            check_reserved(word);
                        } else {
                            ++allocated;
                            check_allocated(word, operation, rn, rd, 1,
                                total_size, element_size);
                        }
                    }
                }
            }
        }
    }
    EXPECT(allocated == UINT32_C(16384));
    EXPECT(reserved == UINT32_C(2048));
    EXPECT(allocated + reserved == UINT32_C(18432));
}

static void expect_cpu_status(
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_status enabled_status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_status expected;
    uint32_t decoded;

#if USE_EXTRA_OPCODES
    expected = enabled_status;
#else
    (void)enabled_status;
    expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_feature_routes(void)
{
    const uint32_t scalar_s = scalar_sd_word(0u, 0u, 13u, 7u);
    const uint32_t vector_d = vector_sd_word(1u, 1u, 1u, 13u, 7u);
    const uint32_t scalar_h = scalar_half_word(0u, 13u, 7u);
    const uint32_t vector_h = vector_half_word(1u, 1u, 13u, 7u);

    expect_cpu_status(scalar_s, CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_OK);
    expect_cpu_status(vector_d, CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_OK);
    expect_cpu_status(scalar_h, CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(vector_h, CDISASM_ARM_CPU_APPLE_A10,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(scalar_h, CDISASM_ARM_CPU_APPLE_A11,
        CDISASM_STATUS_OK);
    expect_cpu_status(vector_h, CDISASM_ARM_CPU_APPLE_A11,
        CDISASM_STATUS_OK);
}

static void test_fixed_bit_neighbors(void)
{
    static const uint32_t masks[] = {
        UINT32_C(0xdffffc00), UINT32_C(0xdfbffc00),
        UINT32_C(0x9ffffc00), UINT32_C(0x9fbffc00)
    };
    const uint32_t words[] = {
        scalar_half_word(0u, 13u, 7u),
        scalar_sd_word(0u, 0u, 13u, 7u),
        vector_half_word(0u, 1u, 13u, 7u),
        vector_sd_word(0u, 0u, 1u, 13u, 7u)
    };
    size_t class_index;

    for (class_index = 0u; class_index != 4u; ++class_index) {
        unsigned bit;

        for (bit = 0u; bit != 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((masks[class_index] & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                words[class_index] ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded == 0u
                || (instruction.name_id != CDISASM_ARM_NAME_FRECPE
                    && instruction.name_id != CDISASM_ARM_NAME_FRSQRTE)
                || ((instruction.instruction_flags
                        & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) != 0u)
                    != (class_index >= 2u));
        }
    }
}

static void test_endian_dispatch_modes_and_boundaries(void)
{
    const uint32_t word = vector_sd_word(1u, 1u, 1u, 31u, 31u);
    const uint32_t reserved = vector_sd_word(0u, 1u, 0u, 13u, 7u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned boundary;

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x119000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x119000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x119000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x119000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    for (boundary = 1u; boundary != 4u; ++boundary) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(
            &other, CDISASM_STATUS_TRUNCATED));
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(
            &other, CDISASM_STATUS_TRUNCATED));
    }

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_APPLE_A11,
        CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_APPLE_A11,
        CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[96];
    char short_text[8];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_7,
        text, sizeof(text)) == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
        NULL, 0u) == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
        short_text, sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void test_formatter(void)
{
    static const char *const mnemonics[] = { "frecpe", "frsqrte" };
    unsigned operation;

    for (operation = 0u; operation != 2u; ++operation) {
        char expected[96];
        int length;

        length = snprintf(expected, sizeof(expected), "%s h7, h13",
            mnemonics[operation]);
        EXPECT(length > 0 && (size_t)length < sizeof(expected));
        expect_format(scalar_half_word(operation, 13u, 7u), expected);
        length = snprintf(expected, sizeof(expected), "%s s7, s13",
            mnemonics[operation]);
        EXPECT(length > 0 && (size_t)length < sizeof(expected));
        expect_format(scalar_sd_word(operation, 0u, 13u, 7u), expected);
        length = snprintf(expected, sizeof(expected), "%s d7, d13",
            mnemonics[operation]);
        EXPECT(length > 0 && (size_t)length < sizeof(expected));
        expect_format(scalar_sd_word(operation, 1u, 13u, 7u), expected);

        length = snprintf(expected, sizeof(expected),
            "%s v7.4h, v13.4h", mnemonics[operation]);
        EXPECT(length > 0 && (size_t)length < sizeof(expected));
        expect_format(vector_half_word(operation, 0u, 13u, 7u), expected);
        length = snprintf(expected, sizeof(expected),
            "%s v7.8h, v13.8h", mnemonics[operation]);
        EXPECT(length > 0 && (size_t)length < sizeof(expected));
        expect_format(vector_half_word(operation, 1u, 13u, 7u), expected);
        length = snprintf(expected, sizeof(expected),
            "%s v7.2s, v13.2s", mnemonics[operation]);
        EXPECT(length > 0 && (size_t)length < sizeof(expected));
        expect_format(vector_sd_word(operation, 0u, 0u, 13u, 7u), expected);
        length = snprintf(expected, sizeof(expected),
            "%s v7.4s, v13.4s", mnemonics[operation]);
        EXPECT(length > 0 && (size_t)length < sizeof(expected));
        expect_format(vector_sd_word(operation, 0u, 1u, 13u, 7u), expected);
        length = snprintf(expected, sizeof(expected),
            "%s v7.2d, v13.2d", mnemonics[operation]);
        EXPECT(length > 0 && (size_t)length < sizeof(expected));
        expect_format(vector_sd_word(operation, 1u, 1u, 13u, 7u), expected);
    }

    {
        cdisasm_arm_instruction instruction;
        char text[96];
        static const char expected[] = "FRSQRTE v7.4s, v13.4s";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(vector_sd_word(1u, 0u, 1u, 13u, 7u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_exact_union();
    test_feature_routes();
    test_fixed_bit_neighbors();
    test_endian_dispatch_modes_and_boundaries();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM Advanced SIMD FP-estimate test(s) failed\n",
            failures);
        return 1;
    }
    printf("ARM Advanced SIMD FP-estimate tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=18432, allocated=16384, "
           "reserved=2048)\n", USE_EXTRA_OPCODES);
    return 0;
}
