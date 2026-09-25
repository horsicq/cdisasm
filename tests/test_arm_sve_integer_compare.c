#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_SQSHLU == UINT16_C(386),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_CMPEQ == UINT16_C(387),
               "SVE compare-vector IDs must be append-only");
_Static_assert(CDISASM_ARM_NAME_CMPLS == UINT16_C(396),
               "SVE compare-vector terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(421),
               "ARM mnemonic count changed after SVE floating append");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

#if USE_EXTRA_OPCODES
typedef struct compare_operation {
    cdisasm_arm_name_id name_id;
    const char *mnemonic;
} compare_operation;

static const compare_operation operations[2][8] = {
    {
        { CDISASM_ARM_NAME_CMPHS, "cmphs" },
        { CDISASM_ARM_NAME_CMPHI, "cmphi" },
        { CDISASM_ARM_NAME_CMPEQ, "cmpeq" },
        { CDISASM_ARM_NAME_CMPNE, "cmpne" },
        { CDISASM_ARM_NAME_CMPGE, "cmpge" },
        { CDISASM_ARM_NAME_CMPGT, "cmpgt" },
        { CDISASM_ARM_NAME_CMPEQ, "cmpeq" },
        { CDISASM_ARM_NAME_CMPNE, "cmpne" }
    },
    {
        { CDISASM_ARM_NAME_CMPGE, "cmpge" },
        { CDISASM_ARM_NAME_CMPGT, "cmpgt" },
        { CDISASM_ARM_NAME_CMPLT, "cmplt" },
        { CDISASM_ARM_NAME_CMPLE, "cmple" },
        { CDISASM_ARM_NAME_CMPHS, "cmphs" },
        { CDISASM_ARM_NAME_CMPHI, "cmphi" },
        { CDISASM_ARM_NAME_CMPLO, "cmplo" },
        { CDISASM_ARM_NAME_CMPLS, "cmpls" }
    }
};

#endif

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 20) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static uint32_t compare_word(
    unsigned wide_group,
    unsigned operation,
    unsigned element_size,
    unsigned zm,
    unsigned pg,
    unsigned zn,
    unsigned pd)
{
    return UINT32_C(0x24000000)
        | ((uint32_t)element_size << 22)
        | ((uint32_t)zm << 16)
        | ((uint32_t)(operation & 4u) << 13)
        | ((uint32_t)wide_group << 14)
        | ((uint32_t)(operation & 2u) << 12)
        | ((uint32_t)pg << 10)
        | ((uint32_t)zn << 5)
        | ((uint32_t)(operation & 1u) << 4)
        | (uint32_t)pd;
}

static int compare_form_is_allocated(
    unsigned wide_group,
    unsigned operation,
    unsigned element_size)
{
    if (wide_group != 0u || operation == 2u || operation == 3u) {
        return element_size != 3u;
    }
    return operation == 0u || operation == 1u || operation >= 4u;
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
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    size_t code_size,
    cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x111000),
        options, instruction);
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

#if USE_EXTRA_OPCODES
static int predicate_operand_matches(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    uint8_t element_size,
    uint8_t qualifier,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_PREDICATE;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.flags = qualifier;
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int z_operand_matches(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    uint8_t element_size)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int success_metadata_matches(
    const cdisasm_arm_instruction *instruction,
    uint32_t word,
    unsigned wide_group,
    unsigned operation,
    unsigned element_size_code,
    unsigned zm,
    unsigned pg,
    unsigned zn,
    unsigned pd)
{
    uint8_t element_size =
        (uint8_t)(UINT32_C(1) << element_size_code);
    int wide_source = wide_group != 0u
        || operation == 2u || operation == 3u;

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id
            == operations[wide_group][operation].name_id
        && instruction->address == UINT64_C(0x111000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 4u
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS)
        && predicate_operand_matches(
            &instruction->operand[0], pd, element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE)
        && predicate_operand_matches(
            &instruction->operand[1], pg, element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && z_operand_matches(
            &instruction->operand[2], zn, element_size)
        && z_operand_matches(
            &instruction->operand[3], zm,
            wide_source ? UINT8_C(8) : element_size);
}
#endif

static void test_exhaustive_owned_class(void)
{
    uint32_t allocated_words = 0u;
    uint32_t reserved_words = 0u;
    unsigned wide_group;

    for (wide_group = 0u; wide_group < 2u; ++wide_group) {
        unsigned operation;

        for (operation = 0u; operation < 8u; ++operation) {
            unsigned element_size;

            for (element_size = 0u; element_size < 4u; ++element_size) {
                int allocated = compare_form_is_allocated(
                    wide_group, operation, element_size);
                unsigned zm;

                for (zm = 0u; zm < 32u; ++zm) {
                    unsigned pg;

                    for (pg = 0u; pg < 8u; ++pg) {
                        unsigned zn;

                        for (zn = 0u; zn < 32u; ++zn) {
                            unsigned pd;

                            for (pd = 0u; pd < 16u; ++pd) {
                                cdisasm_arm_instruction instruction;
                                uint32_t word = compare_word(
                                    wide_group, operation, element_size,
                                    zm, pg, zn, pd);
                                uint32_t decoded;

                                memset(&instruction, 0xa5,
                                       sizeof(instruction));
                                decoded = decode_word(
                                    word, CDISASM_ARM_CPU_ANY,
                                    CDISASM_ARM_MODE_A64, 4u,
                                    CDISASM_ARM_DECODE_OPTION_NONE,
                                    &instruction);
                                if (!allocated) {
                                    ++reserved_words;
                                    EXPECT(decoded == 0u);
                                    EXPECT(instruction_is_error_only(
                                        &instruction,
                                        CDISASM_STATUS_INVALID_INSTRUCTION));
                                } else {
                                    ++allocated_words;
#if USE_EXTRA_OPCODES
                                    EXPECT(decoded == 4u);
                                    EXPECT(success_metadata_matches(
                                        &instruction, word, wide_group,
                                        operation, element_size,
                                        zm, pg, zn, pd));
#else
                                    EXPECT(decoded == 0u);
                                    EXPECT(instruction_is_error_only(
                                        &instruction,
                                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    EXPECT(allocated_words == UINT32_C(7077888));
    EXPECT(reserved_words == UINT32_C(1310720));
    EXPECT(allocated_words + reserved_words == UINT32_C(8388608));
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
    decoded = decode_word(
        word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(decoded == 4u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(decoded == 0u);
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_capability_routes(void)
{
    unsigned wide_group;

    for (wide_group = 0u; wide_group < 2u; ++wide_group) {
        unsigned operation;

        for (operation = 0u; operation < 8u; ++operation) {
            unsigned element_size;

            for (element_size = 0u; element_size < 4u; ++element_size) {
                uint32_t word;

                if (!compare_form_is_allocated(
                        wide_group, operation, element_size)) {
                    continue;
                }
                word = compare_word(
                    wide_group, operation, element_size,
                    19u, 3u, 11u, 7u);
                expect_cpu_status(
                    word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
                expect_cpu_status(
                    word, CDISASM_ARM_CPU_FUJITSU_A64FX,
                    CDISASM_STATUS_OK);
                expect_cpu_status(
                    word, CDISASM_ARM_CPU_APPLE_M4,
                    CDISASM_STATUS_OK);
                expect_cpu_status(
                    word, CDISASM_ARM_CPU_CORTEX_A53,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
                expect_cpu_status(
                    word, CDISASM_ARM_CPU_APPLE_M3,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }
    }
}

static void test_endian_truncation_mode_and_dispatch(void)
{
    uint32_t word = compare_word(1u, 7u, 2u, 19u, 3u, 11u, 7u);
    uint32_t reserved = compare_word(1u, 7u, 3u, 19u, 3u, 11u, 7u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t little_bytes[4];
    uint8_t big_bytes[4];
    unsigned boundary;
    uint32_t decoded;

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(word, big_bytes);
    memset(&big, 0xa5, sizeof(big));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        big_bytes, sizeof(big_bytes), UINT64_C(0x111000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&big, &little, sizeof(big)) == 0);

    word_to_le(word, little_bytes);
    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x111000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&generic, 0xa5, sizeof(generic));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE,
            &generic) == 0u);
        EXPECT(instruction_is_error_only(
            &generic, CDISASM_STATUS_TRUNCATED));

        memset(&generic, 0xa5, sizeof(generic));
        EXPECT(decode_word(
            reserved, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE,
            &generic) == 0u);
        EXPECT(instruction_is_error_only(
            &generic, CDISASM_STATUS_TRUNCATED));
    }

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_formatter_controls(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const char suffixes[] = { 'b', 'h', 's', 'd' };
    unsigned wide_group;

    for (wide_group = 0u; wide_group < 2u; ++wide_group) {
        unsigned operation;

        for (operation = 0u; operation < 8u; ++operation) {
            unsigned element_size;

            for (element_size = 0u; element_size < 4u; ++element_size) {
                cdisasm_arm_instruction instruction;
                const compare_operation *compare =
                    &operations[wide_group][operation];
                int wide_source = wide_group != 0u
                    || operation == 2u || operation == 3u;
                uint32_t word;
                char expected[96];
                char text[96];
                int expected_length;

                if (!compare_form_is_allocated(
                        wide_group, operation, element_size)) {
                    continue;
                }
                word = compare_word(
                    wide_group, operation, element_size,
                    19u, 3u, 11u, 7u);
                memset(&instruction, 0xa5, sizeof(instruction));
                EXPECT(decode_word(
                    word, CDISASM_ARM_CPU_ANY,
                    CDISASM_ARM_MODE_A64, 4u,
                    CDISASM_ARM_DECODE_OPTION_NONE,
                    &instruction) == 4u);
                expected_length = snprintf(
                    expected, sizeof(expected),
                    "%s p7.%c, p3/z, z11.%c, z19.%c",
                    compare->mnemonic, suffixes[element_size],
                    suffixes[element_size],
                    wide_source ? 'd' : suffixes[element_size]);
                EXPECT(expected_length > 0);
                EXPECT((size_t)expected_length < sizeof(expected));
                EXPECT(cdisasm_arm_format(
                    &instruction, CDISASM_FORMAT_SYNTAX_7,
                    text, sizeof(text)) == (size_t)expected_length);
                EXPECT(strcmp(text, expected) == 0);
                EXPECT(cdisasm_arm_format(
                    &instruction, CDISASM_FORMAT_SYNTAX_0,
                    NULL, 0u) == (size_t)expected_length);
            }
        }
    }

    {
        static const char expected[] =
            "CMPLS p7.s, p3/z, z11.s, z19.d";
        cdisasm_arm_instruction instruction;
        char text[96];

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            compare_word(1u, 7u, 2u, 19u, 3u, 11u, 7u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
    }
#endif
}


int main(void)
{
    test_exhaustive_owned_class();
    test_capability_routes();
    test_endian_truncation_mode_and_dispatch();
    test_formatter_controls();

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM SVE integer-compare test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE integer-compare tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=8388608, allocated=7077888, "
           "reserved=1310720)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
