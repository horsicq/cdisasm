#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define FAMILY_MASK UINT32_C(0xbf20fc00)

typedef struct difference_operation {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
} difference_operation;

static const difference_operation operations[2] = {
    { UINT32_C(0x0e207400), CDISASM_ARM_NAME_SABD,
      UINT16_C(6128), "sabd" },
    { UINT32_C(0x2e207400), CDISASM_ARM_NAME_UABD,
      UINT16_C(6170), "uabd" }
};

_Static_assert(CDISASM_ARM_NAME_SABD == UINT16_C(359),
               "SABD mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_UABD == UINT16_C(360),
               "UABD mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6170),
               "Advanced SIMD absolute-difference forms unavailable");

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 32) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static uint32_t make_word(unsigned operation, unsigned q,
                          unsigned size_code, unsigned rm,
                          unsigned rn, unsigned rd)
{
    return operations[operation].value | ((uint32_t)q << 30)
        | ((uint32_t)size_code << 22) | ((uint32_t)rm << 16)
        | ((uint32_t)rn << 5) | (uint32_t)rd;
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static uint32_t make_sve_word(unsigned operation, unsigned size_code,
                              unsigned pg, unsigned zd, unsigned zm)
{
    return (operation == 0u
            ? UINT32_C(0x040c0000) : UINT32_C(0x040d0000))
        | ((uint32_t)size_code << 22) | ((uint32_t)pg << 10)
        | ((uint32_t)zm << 5) | (uint32_t)zd;
}
#endif

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

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
                            cdisasm_arm_mode mode, size_t code_size,
                            cdisasm_arm_decode_option options,
                            cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(cpu, mode, bytes, code_size,
        UINT64_C(0x16a000), options, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
                      cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static int is_fixed_difference_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6128) || form_id == UINT16_C(6170);
}

#if USE_EXTRA_OPCODES
static int operand_matches(const cdisasm_arm_operand *operand,
                           unsigned encoded, uint8_t vector_size,
                           uint8_t element_size,
                           cdisasm_operand_access access)
{
    return operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + encoded)
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->imm == 0u
        && operand->size == vector_size
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == (cdisasm_arm_extend_type)element_size
        && operand->scale == (uint8_t)(vector_size / element_size)
        && CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == element_size
        && CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(vector_size / element_size)
        && operand->access == access;
}

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            uint32_t word, unsigned operation,
                            unsigned q, unsigned size_code,
                            unsigned rm, unsigned rn, unsigned rd)
{
    uint8_t vector_size = q != 0u ? 16u : 8u;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);

    return instruction->address == UINT64_C(0x16a000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == operations[operation].name_id
        && instruction->form_id == operations[operation].form_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == 3u
        && operand_matches(&instruction->operand[0], rd,
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && operand_matches(&instruction->operand[1], rn,
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && operand_matches(&instruction->operand[2], rm,
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_envelopes(void)
{
    uint32_t partitions[2][2][2] = { 0 };
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned operation;

    for (operation = 0u; operation < 2u; ++operation) {
        for (unsigned q = 0u; q < 2u; ++q) {
            for (unsigned size_code = 0u;
                 size_code < 4u; ++size_code) {
                int valid = size_code <= 2u;

                for (unsigned rm = 0u; rm < 32u; ++rm) {
                    for (unsigned rn = 0u; rn < 32u; ++rn) {
                        for (unsigned rd = 0u; rd < 32u; ++rd) {
                            cdisasm_arm_instruction instruction;
                            uint32_t word = make_word(operation, q,
                                size_code, rm, rn, rd);
                            uint32_t decoded;

                            ++partitions[operation][q][valid ? 0u : 1u];
                            if (valid) {
                                ++allocated;
                            } else {
                                ++reserved;
                            }
                            EXPECT((word & FAMILY_MASK)
                                == operations[operation].value);
                            memset(&instruction, 0xa5,
                                   sizeof(instruction));
                            decoded = decode_word(word,
                                CDISASM_ARM_CPU_ANY,
                                CDISASM_ARM_MODE_A64, 4u,
                                CDISASM_ARM_DECODE_OPTION_NONE,
                                &instruction);
                            if (!valid) {
                                EXPECT(decoded == 0u);
                                EXPECT(error_only(&instruction,
                                    CDISASM_STATUS_INVALID_INSTRUCTION));
                            } else {
#if USE_EXTRA_OPCODES
                                EXPECT(decoded == 4u);
                                EXPECT(metadata_matches(&instruction, word,
                                    operation, q, size_code,
                                    rm, rn, rd));
#else
                                EXPECT(decoded == 0u);
                                EXPECT(error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            }
                        }
                    }
                }
            }
        }
    }

    for (operation = 0u; operation < 2u; ++operation) {
        EXPECT(partitions[operation][0][0] == UINT32_C(98304));
        EXPECT(partitions[operation][0][1] == UINT32_C(32768));
        EXPECT(partitions[operation][1][0] == UINT32_C(98304));
        EXPECT(partitions[operation][1][1] == UINT32_C(32768));
    }
    EXPECT(allocated == UINT32_C(393216));
    EXPECT(reserved == UINT32_C(131072));
    EXPECT(allocated + reserved == UINT32_C(524288));
}

static void expect_cpu_status(uint32_t word, cdisasm_arm_cpu_id cpu,
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
    decoded = decode_word(word, cpu, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(error_only(&instruction, expected));
    }
}

static void test_profiles_and_neighbors(void)
{
    static const struct sibling_case {
        uint32_t word;
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
    } sibling_cases[] = {
        { UINT32_C(0x4ebd7da7), CDISASM_ARM_NAME_SABA,
          UINT16_C(6129) },
        { UINT32_C(0x6ebd7da7), CDISASM_ARM_NAME_UABA,
          UINT16_C(6171) },
        { UINT32_C(0x4ebd71a7), CDISASM_ARM_NAME_SABDL,
          UINT16_C(6096) },
        { UINT32_C(0x6ebd71a7), CDISASM_ARM_NAME_UABDL,
          UINT16_C(6111) },
        { UINT32_C(0x040c0000), CDISASM_ARM_NAME_SABD,
          UINT16_C(2228) },
        { UINT32_C(0x040d0000), CDISASM_ARM_NAME_UABD,
          UINT16_C(2231) }
    };
    unsigned operation;
    size_t index;

    for (operation = 0u; operation < 2u; ++operation) {
        uint32_t word = make_word(operation, 1u, 2u, 29u, 13u, 7u);
        unsigned bit;

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A34,
                          CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A53,
                          CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M3,
                          CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
                          CDISASM_STATUS_OK);
        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((FAMILY_MASK & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(word ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded != 4u
                || instruction.form_id != operations[operation].form_id);
        }
    }

    for (index = 0u;
         index < sizeof(sibling_cases) / sizeof(sibling_cases[0]);
         ++index) {
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(sibling_cases[index].word,
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == sibling_cases[index].name_id);
        EXPECT(instruction.form_id == sibling_cases[index].form_id);
#else
        EXPECT(decoded == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        EXPECT(!is_fixed_difference_form(instruction.form_id));
    }

    /* A32/T32 use the distinct VABD mnemonic; neither may be captured by
     * the A64 SABD/UABD form identities. */
    {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(UINT32_C(0xf2000700), CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(!is_fixed_difference_form(instruction.form_id));
    }
}

static void check_transport(uint32_t word)
{
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
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x16a000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x16a000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x16a000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x16a000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(error_only(&other, CDISASM_STATUS_TRUNCATED));
    }
}

static void test_transport_and_status_precedence(void)
{
    cdisasm_arm_instruction instruction;
    unsigned operation;

    for (operation = 0u; operation < 2u; ++operation) {
        uint32_t allocated = make_word(
            operation, 1u, 2u, 29u, 13u, 7u);
        uint32_t reserved = make_word(
            operation, operation, 3u, 29u, 13u, 7u);

        check_transport(allocated);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_INSTRUCTION));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 3u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_TRUNCATED));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, UINT64_C(1) << 63,
            &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_ARGUMENT));
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(0u, 1u, 2u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    (void)decode_word(make_word(1u, 1u, 2u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
        || !is_fixed_difference_form(instruction.form_id));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void reject_forgery(const cdisasm_arm_instruction *instruction,
                           const char *mutation)
{
    char text[160];
    size_t length;

    memset(text, 0xa5, sizeof(text));
    length = cdisasm_arm_format(instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text));
    if (length != 0u || text[0] != '\0') {
        if (failures < 32) {
            fprintf(stderr, "accepted formatter forgery: %s -> %s\n",
                    mutation, text);
        }
        ++failures;
    }
}

static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[160];
    char short_text[8];
    size_t expected_length = strlen(expected);
    size_t length;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    length = cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text));
    if (length != expected_length || strcmp(text, expected) != 0) {
        fprintf(stderr, "format mismatch: expected '%s', got '%s'\n",
                expected, text);
    }
    EXPECT(length == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, NULL, 0u)
        == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, short_text,
        sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void test_formatter_and_schema(void)
{
    static const char element_letters[3] = { 'b', 'h', 's' };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char expected[160];
    char text[160];
    unsigned operation;

    for (operation = 0u; operation < 2u; ++operation) {
        for (unsigned q = 0u; q < 2u; ++q) {
            for (unsigned size_code = 0u;
                 size_code < 3u; ++size_code) {
                unsigned total_size = q != 0u ? 16u : 8u;
                unsigned count = total_size >> size_code;
                int length = snprintf(expected, sizeof(expected),
                    "%s v7.%u%c, v13.%u%c, v29.%u%c",
                    operations[operation].mnemonic,
                    count, element_letters[size_code],
                    count, element_letters[size_code],
                    count, element_letters[size_code]);

                EXPECT(length > 0 && (size_t)length < sizeof(expected));
                expect_format(make_word(operation, q, size_code,
                    29u, 13u, 7u), expected);
            }
        }
    }

    expect_format(make_sve_word(0u, 0u, 3u, 7u, 13u),
                  "sabd z7.b, p3/m, z7.b, z13.b");
    expect_format(make_sve_word(1u, 3u, 3u, 7u, 13u),
                  "uabd z7.d, p3/m, z7.d, z13.d");
    expect_format(UINT32_C(0x4ebd7da7),
                  "saba v7.4s, v13.4s, v29.4s");
    expect_format(UINT32_C(0x6ebd7da7),
                  "uaba v7.4s, v13.4s, v29.4s");
    expect_format(UINT32_C(0x4ebd71a7),
                  "sabdl2 v7.2d, v13.4s, v29.4s");
    expect_format(UINT32_C(0x6ebd71a7),
                  "uabdl2 v7.2d, v13.4s, v29.4s");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(0u, 1u, 2u, 29u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("SABD v31.4s, v30.4s, v29.4s"));
    EXPECT(strcmp(text, "SABD v31.4s, v30.4s, v29.4s") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(6170));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_UABD);
    REJECT_MUTATION(forged.raw_instruction = make_word(
        1u, 1u, 2u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = make_word(
        0u, 1u, 3u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd503201f));
    REJECT_MUTATION(forged.opcode_size = 2u);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
    REJECT_MUTATION(forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_V30);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V29);
    REJECT_MUTATION(forged.operand[2].scale = 1u);

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_NOP;
    forged.form_id = UINT16_C(6128);
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "fixed-form-only claim");
    forged.form_id = CDISASM_ARM_FORM_NONE;
    forged.raw_instruction = make_word(0u, 1u, 0u, 2u, 1u, 0u);
    reject_forgery(&forged, "fixed-raw-only claim");

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_SABD;
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "same-name-only claim");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_sve_word(0u, 1u, 3u, 7u, 13u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2228));
    REJECT_MUTATION(forged.form_id = UINT16_C(6128));
    REJECT_MUTATION(forged.raw_instruction = make_word(
        0u, 1u, 1u, 13u, 7u, 7u));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_UABD);
    REJECT_MUTATION(forged.instruction_flags &=
        ~CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[1].flags =
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);

#undef REJECT_MUTATION
}
#else
static void test_formatter_and_schema(void)
{
}
#endif

int main(void)
{
    test_exhaustive_envelopes();
    test_profiles_and_neighbors();
    test_transport_and_status_precedence();
    test_formatter_and_schema();

    if (failures != 0) {
        fprintf(stderr,
                "%d Advanced SIMD SABD/UABD test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM Advanced SIMD SABD/UABD tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=393216, reserved=131072)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
