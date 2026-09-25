#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define SCALAR_MASK UINT32_C(0xfffffc00)
#define VECTOR_MASK UINT32_C(0xbf3ffc00)

typedef struct compare_zero_operation {
    uint32_t scalar_value;
    uint32_t vector_value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id scalar_form;
    cdisasm_arm_form_id vector_form;
    const char *mnemonic;
} compare_zero_operation;

static const compare_zero_operation operations[2] = {
    { UINT32_C(0x5ee0a800), UINT32_C(0x0e20a800),
      CDISASM_ARM_NAME_CMLT, UINT16_C(5777), UINT16_C(6013), "cmlt" },
    { UINT32_C(0x7ee09800), UINT32_C(0x2e209800),
      CDISASM_ARM_NAME_CMLE, UINT16_C(5794), UINT16_C(6045), "cmle" }
};

_Static_assert(CDISASM_ARM_NAME_CMLT == UINT16_C(681),
               "CMLT mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_CMLE == UINT16_C(680),
               "CMLE mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6045),
               "Advanced SIMD compare-zero form IDs unavailable");

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

static uint32_t make_scalar_word(unsigned operation,
                                 unsigned rn, unsigned rd)
{
    return operations[operation].scalar_value
        | ((uint32_t)rn << 5) | (uint32_t)rd;
}

static uint32_t make_vector_word(unsigned operation, unsigned q,
                                 unsigned size_code,
                                 unsigned rn, unsigned rd)
{
    return operations[operation].vector_value | ((uint32_t)q << 30)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)rn << 5) | (uint32_t)rd;
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

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
                            cdisasm_arm_mode mode, size_t code_size,
                            cdisasm_arm_decode_option options,
                            cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(cpu, mode, bytes, code_size,
        UINT64_C(0x169000), options, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
                      cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static int is_compare_zero_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(5777) || form_id == UINT16_C(5794)
        || form_id == UINT16_C(6013) || form_id == UINT16_C(6045);
}

#if USE_EXTRA_OPCODES
static int vector_operand_matches(const cdisasm_arm_operand *operand,
                                  cdisasm_arm_reg_id register_base,
                                  unsigned encoded, uint8_t total_size,
                                  uint8_t element_size,
                                  cdisasm_operand_access access)
{
    return operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg == (cdisasm_arm_reg_id)(register_base + encoded)
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->imm == 0u
        && operand->size == total_size
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type
            == (cdisasm_arm_extend_type)element_size
        && operand->scale == (uint8_t)(total_size / element_size)
        && CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == element_size
        && CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size)
        && operand->access == access;
}

static int zero_immediate_matches(const cdisasm_arm_operand *operand)
{
    return operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->imm == 0u
        && operand->size == 1u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u
        && operand->access == CDISASM_OPERAND_ACCESS_READ;
}

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            uint32_t word, unsigned operation,
                            int scalar, unsigned q,
                            unsigned size_code, unsigned rn, unsigned rd)
{
    uint8_t total_size = scalar ? 8u : q != 0u ? 16u : 8u;
    uint8_t element_size = scalar
        ? 8u : (uint8_t)(UINT8_C(1) << size_code);
    cdisasm_arm_reg_id register_base = scalar
        ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;

    return instruction->address == UINT64_C(0x169000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == operations[operation].name_id
        && instruction->form_id == (scalar
            ? operations[operation].scalar_form
            : operations[operation].vector_form)
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == 3u
        && vector_operand_matches(&instruction->operand[0], register_base,
            rd, total_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && vector_operand_matches(&instruction->operand[1], register_base,
            rn, total_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && zero_immediate_matches(&instruction->operand[2]);
}
#endif

static void test_exhaustive_envelopes(void)
{
    uint32_t scalar_allocated = 0u;
    uint32_t vector_partitions[2][2][2] = { 0 };
    uint32_t vector_allocated = 0u;
    uint32_t vector_reserved = 0u;
    unsigned operation;

    for (operation = 0u; operation < 2u; ++operation) {
        unsigned rn;

        for (rn = 0u; rn < 32u; ++rn) {
            unsigned rd;

            for (rd = 0u; rd < 32u; ++rd) {
                cdisasm_arm_instruction instruction;
                uint32_t word = make_scalar_word(operation, rn, rd);
                uint32_t decoded;

                ++scalar_allocated;
                EXPECT((word & SCALAR_MASK)
                    == operations[operation].scalar_value);
                memset(&instruction, 0xa5, sizeof(instruction));
                decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
                    CDISASM_ARM_MODE_A64, 4u,
                    CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
                EXPECT(decoded == 4u);
                EXPECT(metadata_matches(&instruction, word, operation,
                                        1, 0u, 3u, rn, rd));
#else
                EXPECT(decoded == 0u);
                EXPECT(error_only(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            }
        }

        for (unsigned q = 0u; q < 2u; ++q) {
            for (unsigned size_code = 0u;
                 size_code < 4u; ++size_code) {
                int valid = size_code <= 2u || q != 0u;

                for (rn = 0u; rn < 32u; ++rn) {
                    unsigned rd;

                    for (rd = 0u; rd < 32u; ++rd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = make_vector_word(operation, q,
                            size_code, rn, rd);
                        uint32_t decoded;

                        ++vector_partitions[operation][q]
                            [valid ? 0u : 1u];
                        if (valid) {
                            ++vector_allocated;
                        } else {
                            ++vector_reserved;
                        }
                        EXPECT((word & VECTOR_MASK)
                            == operations[operation].vector_value);
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
                                operation, 0, q, size_code, rn, rd));
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

    for (operation = 0u; operation < 2u; ++operation) {
        EXPECT(vector_partitions[operation][0][0] == UINT32_C(3072));
        EXPECT(vector_partitions[operation][0][1] == UINT32_C(1024));
        EXPECT(vector_partitions[operation][1][0] == UINT32_C(4096));
        EXPECT(vector_partitions[operation][1][1] == UINT32_C(0));
    }
    EXPECT(scalar_allocated == UINT32_C(2048));
    EXPECT(vector_allocated == UINT32_C(14336));
    EXPECT(vector_reserved == UINT32_C(2048));
    EXPECT(scalar_allocated + vector_allocated == UINT32_C(16384));
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
    static const uint32_t sibling_words[] = {
        UINT32_C(0x4ee089a7), /* vector CMGT #0 */
        UINT32_C(0x4ee099a7), /* vector CMEQ #0 */
        UINT32_C(0x6ee089a7), /* vector CMGE #0 */
        UINT32_C(0x5ee089a7), /* scalar CMGT #0 */
        UINT32_C(0x5ee099a7), /* scalar CMEQ #0 */
        UINT32_C(0x7ee089a7), /* scalar CMGE #0 */
        UINT32_C(0x6efd35a7), /* regular-register CMHI */
        UINT32_C(0x4efd8da7)  /* CMTST */
    };
    unsigned operation;
    size_t index;

    for (operation = 0u; operation < 2u; ++operation) {
        uint32_t words[2] = {
            make_scalar_word(operation, 13u, 7u),
            make_vector_word(operation, 1u, 3u, 13u, 7u)
        };
        uint32_t masks[2] = { SCALAR_MASK, VECTOR_MASK };
        cdisasm_arm_form_id forms[2] = {
            operations[operation].scalar_form,
            operations[operation].vector_form
        };

        for (index = 0u; index < 2u; ++index) {
            unsigned bit;

            expect_cpu_status(words[index], CDISASM_ARM_CPU_ANY,
                              CDISASM_STATUS_OK);
            expect_cpu_status(words[index], CDISASM_ARM_CPU_CORTEX_A34,
                              CDISASM_STATUS_OK);
            expect_cpu_status(words[index], CDISASM_ARM_CPU_CORTEX_A53,
                              CDISASM_STATUS_OK);
            expect_cpu_status(words[index], CDISASM_ARM_CPU_APPLE_M3,
                              CDISASM_STATUS_OK);
            expect_cpu_status(words[index], CDISASM_ARM_CPU_FUJITSU_A64FX,
                              CDISASM_STATUS_OK);
            for (bit = 0u; bit < 32u; ++bit) {
                cdisasm_arm_instruction instruction;
                uint32_t decoded;

                if ((masks[index] & (UINT32_C(1) << bit)) == 0u) {
                    continue;
                }
                memset(&instruction, 0xa5, sizeof(instruction));
                decoded = decode_word(
                    words[index] ^ (UINT32_C(1) << bit),
                    CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                    CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                EXPECT(decoded != 4u
                    || instruction.form_id != forms[index]);
            }
        }
    }

    for (index = 0u;
         index < sizeof(sibling_words) / sizeof(sibling_words[0]);
         ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(sibling_words[index], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(!is_compare_zero_form(instruction.form_id));
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
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x169000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x169000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x169000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x169000),
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
        uint32_t scalar = make_scalar_word(operation, 13u, 7u);
        uint32_t vector = make_vector_word(
            operation, 1u, 3u, 13u, 7u);
        uint32_t reserved = make_vector_word(
            operation, 0u, 3u, 13u, 7u);

        check_transport(scalar);
        check_transport(vector);

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
    EXPECT(decode_word(make_scalar_word(0u, 13u, 7u),
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    (void)decode_word(make_vector_word(1u, 1u, 2u, 13u, 7u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
        || !is_compare_zero_form(instruction.form_id));
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
    static const char element_letters[4] = { 'b', 'h', 's', 'd' };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char expected[128];
    char text[128];
    unsigned operation;

    for (operation = 0u; operation < 2u; ++operation) {
        int length = snprintf(expected, sizeof(expected),
            "%s d7, d13, #0", operations[operation].mnemonic);

        EXPECT(length > 0 && (size_t)length < sizeof(expected));
        expect_format(make_scalar_word(operation, 13u, 7u), expected);
        for (unsigned q = 0u; q < 2u; ++q) {
            unsigned maximum_size = q != 0u ? 3u : 2u;

            for (unsigned size_code = 0u;
                 size_code <= maximum_size; ++size_code) {
                unsigned total_size = q != 0u ? 16u : 8u;
                unsigned count = total_size >> size_code;

                length = snprintf(expected, sizeof(expected),
                    "%s v7.%u%c, v13.%u%c, #0",
                    operations[operation].mnemonic,
                    count, element_letters[size_code],
                    count, element_letters[size_code]);
                EXPECT(length > 0 && (size_t)length < sizeof(expected));
                expect_format(make_vector_word(operation, q, size_code,
                    13u, 7u), expected);
            }
        }
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_scalar_word(0u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text)) == strlen("CMLT d31, d30, #0"));
    EXPECT(strcmp(text, "CMLT d31, d30, #0") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(5794));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_CMLE);
    REJECT_MUTATION(forged.raw_instruction = make_scalar_word(
        1u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = make_vector_word(
        0u, 1u, 3u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd503201f));
    REJECT_MUTATION(forged.opcode_size = 2u);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
    REJECT_MUTATION(forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_D30);
    REJECT_MUTATION(forged.operand[0].size = 16u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_D29);
    REJECT_MUTATION(forged.operand[2].imm = 1u);
    REJECT_MUTATION(forged.operand[2].size = 2u);
    REJECT_MUTATION(forged.operand[2].type =
        CDISASM_OPERAND_REGISTER);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_vector_word(1u, 1u, 3u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    REJECT_MUTATION(forged.form_id = UINT16_C(5794));
    REJECT_MUTATION(forged.raw_instruction = make_scalar_word(
        1u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = make_vector_word(
        1u, 0u, 3u, 30u, 31u));
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_D31);
    REJECT_MUTATION(forged.operand[0].scale = 1u);

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_NOP;
    forged.form_id = UINT16_C(5777);
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "scalar-form-only claim");
    forged.form_id = CDISASM_ARM_FORM_NONE;
    forged.raw_instruction = make_scalar_word(0u, 1u, 0u);
    reject_forgery(&forged, "scalar-raw-only claim");
    forged.raw_instruction = make_vector_word(1u, 1u, 0u, 1u, 0u);
    reject_forgery(&forged, "vector-raw-only claim");

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_CMLT;
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "same-name-only claim");

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
        fprintf(stderr, "%d Advanced SIMD compare-zero test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM Advanced SIMD CMLT/CMLE compare-zero tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=16384, reserved=2048)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
