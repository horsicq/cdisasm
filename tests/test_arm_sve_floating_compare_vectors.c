#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_FCMLT == UINT16_C(402),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_FCMUO == UINT16_C(403),
               "SVE vector floating-compare IDs must be append-only");
_Static_assert(CDISASM_ARM_NAME_FACGE == UINT16_C(404),
               "SVE vector floating-compare ID order changed");
_Static_assert(CDISASM_ARM_NAME_FACGT == UINT16_C(405),
               "SVE vector floating-compare terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(421),
               "SVE vector floating-compare name count changed");
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

static uint32_t floating_vector_word(
    unsigned operation, unsigned element_size, unsigned zm, unsigned pg,
    unsigned zn, unsigned pd)
{
    return UINT32_C(0x65004000)
        | ((uint32_t)element_size << 22)
        | ((uint32_t)zm << 16)
        | ((uint32_t)(operation & 4u) << 13)
        | ((uint32_t)(operation & 2u) << 12)
        | ((uint32_t)pg << 10)
        | ((uint32_t)zn << 5)
        | ((uint32_t)(operation & 1u) << 4)
        | (uint32_t)pd;
}

static int floating_vector_form_is_allocated(
    unsigned operation, unsigned element_size)
{
    return element_size != 0u && operation != 6u;
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
        UINT64_C(0x112000), options, instruction);
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
static const cdisasm_arm_name_id names[8] = {
    CDISASM_ARM_NAME_FCMGE, CDISASM_ARM_NAME_FCMGT,
    CDISASM_ARM_NAME_FCMEQ, CDISASM_ARM_NAME_FCMNE,
    CDISASM_ARM_NAME_FCMUO, CDISASM_ARM_NAME_FACGE,
    CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_FACGT
};

#if USE_DISASM_FORMAT
static const char *const mnemonics[8] = {
    "fcmge", "fcmgt", "fcmeq", "fcmne",
    "fcmuo", "facge", NULL, "facgt"
};
#endif

static int predicate_matches(const cdisasm_arm_operand *operand,
                             unsigned encoded, uint8_t element_size,
                             uint8_t flags, cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_PREDICATE;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.flags = flags;
    expected.access = access;
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
                            unsigned element_size_code, unsigned zm,
                            unsigned pg, unsigned zn, unsigned pd)
{
    uint8_t element_size = (uint8_t)(UINT32_C(1) << element_size_code);

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == names[operation]
        && instruction->address == UINT64_C(0x112000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 4u
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        && predicate_matches(&instruction->operand[0], pd, element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE)
        && predicate_matches(&instruction->operand[1], pg, element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && zreg_matches(&instruction->operand[2], zn, element_size)
        && zreg_matches(&instruction->operand[3], zm, element_size);
}
#endif

static void test_exhaustive_owned_class(void)
{
    uint32_t allocated_words = 0u;
    uint32_t reserved_words = 0u;
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        unsigned element_size;

        for (element_size = 0u; element_size < 4u; ++element_size) {
            int allocated = floating_vector_form_is_allocated(
                operation, element_size);
            unsigned zm;

            for (zm = 0u; zm < 32u; ++zm) {
                unsigned pg;

                for (pg = 0u; pg < 8u; ++pg) {
                    unsigned zn;

                    for (zn = 0u; zn < 32u; ++zn) {
                        unsigned pd;

                        for (pd = 0u; pd < 16u; ++pd) {
                            cdisasm_arm_instruction instruction;
                            uint32_t word = floating_vector_word(
                                operation, element_size, zm, pg, zn, pd);
                            uint32_t decoded;

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
                                    operation, element_size, zm, pg, zn, pd));
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
    }
    EXPECT(allocated_words == UINT32_C(2752512));
    EXPECT(reserved_words == UINT32_C(1441792));
    EXPECT(allocated_words + reserved_words == UINT32_C(4194304));
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

static void test_feature_cpu_and_boundary_routes(void)
{
    uint32_t word = floating_vector_word(4u, 2u, 13u, 3u, 12u, 6u);
    uint32_t reserved = floating_vector_word(6u, 2u, 13u, 3u, 12u, 6u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t bytes[4];
    unsigned boundary;

    {
        unsigned operation;

        for (operation = 0u; operation < 8u; ++operation) {
            unsigned element_size;

            if (operation == 6u) {
                continue;
            }
            for (element_size = 1u; element_size < 4u; ++element_size) {
                uint32_t candidate = floating_vector_word(
                    operation, element_size, 13u, 3u, 12u, 6u);

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
    }

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
    word_to_be(word, bytes);
    memset(&big, 0xa5, sizeof(big));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x112000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x112000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big) == 0u);
#endif
    EXPECT(memcmp(&big, &little, sizeof(big)) == 0);

    word_to_le(word, bytes);
    memset(&generic, 0xa5, sizeof(generic));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x112000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x112000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
#endif
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&big, 0xa5, sizeof(big));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &big) == 0u);
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
    EXPECT(instruction_is_error_only(&generic, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &generic) == 0u);
    EXPECT(instruction_is_error_only(&generic, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &generic) == 0u);
    EXPECT(instruction_is_error_only(&generic, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[96];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_7,
        text, sizeof(text)) == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
        NULL, 0u) == expected_length);
}

static void test_formatter_and_canonical_aliases(void)
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
                "%s p6.%c, p3/z, z12.%c, z13.%c", mnemonics[operation],
                suffixes[size_index], suffixes[size_index],
                suffixes[size_index]);

            EXPECT(expected_length > 0);
            EXPECT((size_t)expected_length < sizeof(expected));
            expect_format(floating_vector_word(operation, size_index + 1u,
                13u, 3u, 12u, 6u), expected);
        }
    }

    /* FCMLE/FCMLT and FACLE/FACLT are assembler aliases that exchange Zn/Zm.
     * Canonical disassembly retains the base operation and encoded order. */
    expect_format(UINT32_C(0x65404020),
        "fcmge p0.h, p0/z, z1.h, z0.h");
    expect_format(UINT32_C(0x65404030),
        "fcmgt p0.h, p0/z, z1.h, z0.h");
    expect_format(UINT32_C(0x6540c030),
        "facge p0.h, p0/z, z1.h, z0.h");
    expect_format(UINT32_C(0x6540e030),
        "facgt p0.h, p0/z, z1.h, z0.h");

    {
        cdisasm_arm_instruction instruction;
        char text[96];
        uint32_t word = floating_vector_word(7u, 3u, 13u, 3u, 12u, 6u);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text))
            == sizeof("FACGT p6.d, p3/z, z12.d, z13.d") - 1u);
        EXPECT(strcmp(text, "FACGT p6.d, p3/z, z12.d, z13.d") == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_owned_class();
    test_feature_cpu_and_boundary_routes();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter_and_canonical_aliases();
#endif

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM SVE vector floating-compare test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE vector floating-compare tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=4194304, allocated=2752512, "
           "reserved=1441792)\n", USE_EXTRA_OPCODES);
    return 0;
}
