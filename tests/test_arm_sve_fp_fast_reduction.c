#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_FDIVR == UINT16_C(414),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_FADDV == UINT16_C(415),
               "SVE FP fast-reduction IDs must be append-only");
_Static_assert(CDISASM_ARM_NAME_FMAXNMV == UINT16_C(416),
               "SVE FP fast-reduction ID order changed");
_Static_assert(CDISASM_ARM_NAME_FMINNMV == UINT16_C(417),
               "SVE FP fast-reduction ID order changed");
_Static_assert(CDISASM_ARM_NAME_FMAXV == UINT16_C(418),
               "SVE FP fast-reduction ID order changed");
_Static_assert(CDISASM_ARM_NAME_FMINV == UINT16_C(419),
               "SVE FP fast-reduction terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_FMINV < CDISASM_ARM_NAME_COUNT,
               "SVE FP fast-reduction terminal ID is outside the catalog");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(421),
               "SVE FP fast-reduction name count changed");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 20) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",      \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

#if USE_EXTRA_OPCODES
static const cdisasm_arm_name_id reduction_names[8] = {
    CDISASM_ARM_NAME_FADDV,
    CDISASM_ARM_NAME_NONE,
    CDISASM_ARM_NAME_NONE,
    CDISASM_ARM_NAME_NONE,
    CDISASM_ARM_NAME_FMAXNMV,
    CDISASM_ARM_NAME_FMINNMV,
    CDISASM_ARM_NAME_FMAXV,
    CDISASM_ARM_NAME_FMINV
};
#endif

static uint32_t reduction_word(unsigned operation, unsigned size_code,
                               unsigned zn, unsigned pg, unsigned vd)
{
    return UINT32_C(0x65002000)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)operation << 16)
        | ((uint32_t)pg << 10)
        | ((uint32_t)zn << 5)
        | (uint32_t)vd;
}

static int reduction_control_is_allocated(unsigned operation,
                                          unsigned size_code)
{
    return size_code != 0u && (operation == 0u || operation >= 4u);
}

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
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_arm_mode mode,
    size_t code_size, cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(cpu_id, mode, bytes, code_size,
        UINT64_C(0x115000), options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction, cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_reg_id scalar_reg(unsigned encoded, unsigned size_code)
{
    if (size_code == 1u) {
        return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_H0 + encoded);
    }
    if (size_code == 2u) {
        return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + encoded);
    }
    return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_D0 + encoded);
}

static int scalar_matches(const cdisasm_arm_operand *operand,
                          unsigned encoded, unsigned size_code)
{
    cdisasm_arm_operand expected;
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = scalar_reg(encoded, size_code);
    expected.size = element_size;
    expected.access = CDISASM_OPERAND_ACCESS_WRITE;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int predicate_matches(const cdisasm_arm_operand *operand,
                             unsigned encoded, uint8_t element_size)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_PREDICATE;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int zreg_matches(const cdisasm_arm_operand *operand,
                        unsigned encoded, uint8_t element_size)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            uint32_t word, unsigned operation,
                            unsigned size_code, unsigned zn,
                            unsigned pg, unsigned vd)
{
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == reduction_names[operation]
        && instruction->address == UINT64_C(0x115000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 3u
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        && scalar_matches(&instruction->operand[0], vd, size_code)
        && predicate_matches(&instruction->operand[1], pg, element_size)
        && zreg_matches(&instruction->operand[2], zn, element_size);
}
#endif

static void test_exhaustive_exact_envelope(void)
{
    uint32_t allocated_words = 0u;
    uint32_t reserved_words = 0u;
    unsigned size_code;

    for (size_code = 0u; size_code < 4u; ++size_code) {
        unsigned operation;

        for (operation = 0u; operation < 8u; ++operation) {
            int allocated = reduction_control_is_allocated(
                operation, size_code);
            unsigned pg;

            for (pg = 0u; pg < 8u; ++pg) {
                unsigned zn;

                for (zn = 0u; zn < 32u; ++zn) {
                    unsigned vd;

                    for (vd = 0u; vd < 32u; ++vd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = reduction_word(
                            operation, size_code, zn, pg, vd);
                        uint32_t decoded;

                        EXPECT((word & UINT32_C(0xff38e000))
                            == UINT32_C(0x65002000));
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                        if (!allocated) {
                            ++reserved_words;
                            EXPECT(decoded == 0u);
                            EXPECT(instruction_is_error_only(&instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                        } else {
                            ++allocated_words;
#if USE_EXTRA_OPCODES
                            EXPECT(decoded == 4u);
                            EXPECT(metadata_matches(&instruction, word,
                                operation, size_code, zn, pg, vd));
#else
                            EXPECT(decoded == 0u);
                            EXPECT(instruction_is_error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        }
                    }
                }
            }
        }
    }
    EXPECT(allocated_words == UINT32_C(122880));
    EXPECT(reserved_words == UINT32_C(139264));
    EXPECT(allocated_words + reserved_words == UINT32_C(262144));
}

static void expect_cpu_status(uint32_t word, cdisasm_arm_cpu_id cpu_id,
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

static void test_features_endian_dispatch_and_boundaries(void)
{
    uint32_t word = reduction_word(5u, 3u, 31u, 7u, 5u);
    uint32_t reserved = reduction_word(2u, 2u, 13u, 3u, 12u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t bytes[4];
    unsigned operation;
    unsigned size_code;
    unsigned boundary;

    for (size_code = 1u; size_code <= 3u; ++size_code) {
        for (operation = 0u; operation < 8u; ++operation) {
            uint32_t candidate;

            if (!reduction_control_is_allocated(operation, size_code)) {
                continue;
            }
            candidate = reduction_word(
                operation, size_code, 13u, 3u, 12u);
            expect_cpu_status(
                candidate, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
            expect_cpu_status(candidate, CDISASM_ARM_CPU_FUJITSU_A64FX,
                CDISASM_STATUS_OK);
            expect_cpu_status(candidate, CDISASM_ARM_CPU_APPLE_M4,
                CDISASM_STATUS_OK);
            expect_cpu_status(candidate, CDISASM_ARM_CPU_CORTEX_A53,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_cpu_status(candidate, CDISASM_ARM_CPU_APPLE_M3,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
    word_to_be(word, bytes);
    memset(&big, 0xa5, sizeof(big));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x115000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x115000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big) == 0u);
#endif
    EXPECT(memcmp(&big, &little, sizeof(big)) == 0);

    word_to_le(word, bytes);
    memset(&generic, 0xa5, sizeof(generic));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x115000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x115000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
#endif
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&big, 0xa5, sizeof(big));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &big) == 0u);
        EXPECT(instruction_is_error_only(&big, CDISASM_STATUS_TRUNCATED));
        memset(&big, 0xa5, sizeof(big));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &big) == 0u);
        EXPECT(instruction_is_error_only(&big, CDISASM_STATUS_TRUNCATED));
    }

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static const char *const mnemonics[8] = {
    "faddv", NULL, NULL, NULL, "fmaxnmv", "fminnmv", "fmaxv", "fminv"
};

static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[96];
    char short_text[8];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
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
    static const char suffixes[] = { 'h', 's', 'd' };
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        unsigned size_index;

        if (mnemonics[operation] == NULL) {
            continue;
        }
        for (size_index = 0u; size_index < 3u; ++size_index) {
            char expected[96];
            int expected_length = snprintf(expected, sizeof(expected),
                "%s %c12, p3, z13.%c", mnemonics[operation],
                suffixes[size_index], suffixes[size_index]);

            EXPECT(expected_length > 0);
            EXPECT((size_t)expected_length < sizeof(expected));
            expect_format(reduction_word(operation, size_index + 1u,
                13u, 3u, 12u), expected);
        }
    }

    {
        cdisasm_arm_instruction instruction;
        char text[96];
        uint32_t word = reduction_word(7u, 3u, 13u, 3u, 12u);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text))
            == sizeof("FMINV d12, p3, z13.d") - 1u);
        EXPECT(strcmp(text, "FMINV d12, p3, z13.d") == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_exact_envelope();
    test_features_endian_dispatch_and_boundaries();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif

    if (failures != 0) {
        fprintf(stderr,
            "%d ARM SVE FP fast-reduction test(s) failed\n", failures);
        return 1;
    }
    printf("ARM SVE FP fast-reduction tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=262144, allocated=122880, "
           "reserved=139264)\n", USE_EXTRA_OPCODES);
    return 0;
}
