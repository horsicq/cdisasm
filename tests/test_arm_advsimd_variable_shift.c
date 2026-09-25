#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define SCALAR_MASK UINT32_C(0xffe0fc00)
#define VECTOR_MASK UINT32_C(0xbf20fc00)

typedef struct variable_shift_operation {
    uint32_t scalar_value;
    uint32_t vector_value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id scalar_form;
    cdisasm_arm_form_id vector_form;
    const char *mnemonic;
} variable_shift_operation;

static const variable_shift_operation operations[2] = {
    { UINT32_C(0x5ee04400), UINT32_C(0x0e204400),
      CDISASM_ARM_NAME_SSHL, UINT16_C(5826), UINT16_C(6122), "sshl" },
    { UINT32_C(0x7ee04400), UINT32_C(0x2e204400),
      CDISASM_ARM_NAME_USHL, UINT16_C(5841), UINT16_C(6164), "ushl" }
};

_Static_assert(CDISASM_ARM_NAME_SSHL == UINT16_C(1533),
               "SSHL mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_USHL == UINT16_C(1835),
               "USHL mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6164),
               "Advanced SIMD variable-shift form IDs unavailable");

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

static uint32_t make_scalar_word(unsigned operation, unsigned rm,
                                 unsigned rn, unsigned rd)
{
    return operations[operation].scalar_value | ((uint32_t)rm << 16)
        | ((uint32_t)rn << 5) | (uint32_t)rd;
}

static uint32_t make_vector_word(unsigned operation, unsigned q,
                                 unsigned size_code, unsigned rm,
                                 unsigned rn, unsigned rd)
{
    return operations[operation].vector_value | ((uint32_t)q << 30)
        | ((uint32_t)size_code << 22) | ((uint32_t)rm << 16)
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

static int is_variable_shift_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(5826) || form_id == UINT16_C(5841)
        || form_id == UINT16_C(6122) || form_id == UINT16_C(6164);
}

#if USE_EXTRA_OPCODES
static int operand_matches(const cdisasm_arm_operand *operand,
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

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            uint32_t word, unsigned operation,
                            int scalar, unsigned q,
                            unsigned size_code, unsigned rm,
                            unsigned rn, unsigned rd)
{
    uint8_t total_size = scalar ? 8u : q != 0u ? 16u : 8u;
    uint8_t element_size = scalar
        ? 8u : (uint8_t)(UINT8_C(1) << size_code);
    cdisasm_arm_reg_id register_base = scalar
        ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;

    return instruction->address == UINT64_C(0x16a000)
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
        && operand_matches(&instruction->operand[0], register_base, rd,
                           total_size, element_size,
                           CDISASM_OPERAND_ACCESS_WRITE)
        && operand_matches(&instruction->operand[1], register_base, rn,
                           total_size, element_size,
                           CDISASM_OPERAND_ACCESS_READ)
        && operand_matches(&instruction->operand[2], register_base, rm,
                           total_size, element_size,
                           CDISASM_OPERAND_ACCESS_READ);
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
        unsigned rm;

        for (rm = 0u; rm < 32u; ++rm) {
            unsigned rn;

            for (rn = 0u; rn < 32u; ++rn) {
                unsigned rd;

                for (rd = 0u; rd < 32u; ++rd) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = make_scalar_word(
                        operation, rm, rn, rd);
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
                                            1, 0u, 3u, rm, rn, rd));
#else
                    EXPECT(decoded == 0u);
                    EXPECT(error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                }
            }
        }

        for (unsigned q = 0u; q < 2u; ++q) {
            for (unsigned size_code = 0u;
                 size_code < 4u; ++size_code) {
                int valid = size_code <= 2u || q != 0u;

                for (rm = 0u; rm < 32u; ++rm) {
                    unsigned rn;

                    for (rn = 0u; rn < 32u; ++rn) {
                        unsigned rd;

                        for (rd = 0u; rd < 32u; ++rd) {
                            cdisasm_arm_instruction instruction;
                            uint32_t word = make_vector_word(operation,
                                q, size_code, rm, rn, rd);
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
                                    operation, 0, q, size_code,
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
        EXPECT(vector_partitions[operation][0][0] == UINT32_C(98304));
        EXPECT(vector_partitions[operation][0][1] == UINT32_C(32768));
        EXPECT(vector_partitions[operation][1][0] == UINT32_C(131072));
        EXPECT(vector_partitions[operation][1][1] == UINT32_C(0));
    }
    EXPECT(scalar_allocated == UINT32_C(65536));
    EXPECT(vector_allocated == UINT32_C(458752));
    EXPECT(vector_reserved == UINT32_C(65536));
    EXPECT(scalar_allocated + vector_allocated == UINT32_C(524288));
}

static void test_saturating_scalar_family(void)
{
    static const struct {
        uint32_t word;
        cdisasm_arm_name_id name;
        uint8_t rd, rn, rm, size;
    } cases[] = {
        {0x5e230c41, CDISASM_ARM_NAME_SQADD, 1, 2, 3, 1},
        {0x5e662ca4, CDISASM_ARM_NAME_SQSUB, 4, 5, 6, 2},
        {0x5ea94d07, CDISASM_ARM_NAME_SQSHL, 7, 8, 9, 4},
        {0x5eec556a, CDISASM_ARM_NAME_SRSHL, 10, 11, 12, 8},
        {0x5e2f5dcd, CDISASM_ARM_NAME_SQRSHL, 13, 14, 15, 1},
        {0x7e720e30, CDISASM_ARM_NAME_UQADD, 16, 17, 18, 2},
        {0x7eb52e93, CDISASM_ARM_NAME_UQSUB, 19, 20, 21, 4},
        {0x7ef84ef6, CDISASM_ARM_NAME_UQSHL, 22, 23, 24, 8},
        {0x7efb5759, CDISASM_ARM_NAME_URSHL, 25, 26, 27, 8},
        {0x7e7e5fbc, CDISASM_ARM_NAME_UQRSHL, 28, 29, 30, 2},
        {0x5ee33441, CDISASM_ARM_NAME_CMGT, 1, 2, 3, 8},
        {0x5ee63ca4, CDISASM_ARM_NAME_CMGE, 4, 5, 6, 8},
        {0x5ee98507, CDISASM_ARM_NAME_ADD, 7, 8, 9, 8},
        {0x5e6cb56a, CDISASM_ARM_NAME_SQDMULH, 10, 11, 12, 2},
        {0x7eef35cd, CDISASM_ARM_NAME_CMHI, 13, 14, 15, 8},
        {0x7ef23e30, CDISASM_ARM_NAME_CMHS, 16, 17, 18, 8},
        {0x7ef58693, CDISASM_ARM_NAME_SUB, 19, 20, 21, 8},
        {0x7ef88ef6, CDISASM_ARM_NAME_CMEQ, 22, 23, 24, 8},
        {0x7ebbb759, CDISASM_ARM_NAME_SQRDMULH, 25, 26, 27, 4}
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cdisasm_arm_instruction instruction;
        uint32_t decoded = decode_word(cases[i].word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
#if USE_EXTRA_OPCODES
        cdisasm_arm_reg_id base = cases[i].size == 1u
            ? CDISASM_ARM_REG_B0 : cases[i].size == 2u
                ? CDISASM_ARM_REG_H0 : cases[i].size == 4u
                    ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;

        EXPECT(decoded == 4u);
        EXPECT(instruction.name_id == cases[i].name);
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
        EXPECT(instruction.operand_count == 3u);
        for (unsigned operand_index = 0; operand_index < 3u;
             ++operand_index) {
            const cdisasm_arm_operand *operand =
                &instruction.operand[operand_index];
            unsigned encoded = operand_index == 0u ? cases[i].rd
                : operand_index == 1u ? cases[i].rn : cases[i].rm;

            EXPECT(operand->type == CDISASM_OPERAND_REGISTER);
            EXPECT(operand->reg == (cdisasm_arm_reg_id)(base + encoded));
            EXPECT(operand->size == cases[i].size);
            EXPECT(operand->extend_type == cases[i].size);
            EXPECT(operand->scale == 1u);
            EXPECT(operand->access == (operand_index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ));
        }
#else
        EXPECT(decoded == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
    {
        static const uint32_t reserved[] = {
            UINT32_C(0x5e20b400), UINT32_C(0x5ee0b400),
            UINT32_C(0x7e20b400), UINT32_C(0x7ee0b400)
        };

        for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); ++i) {
            cdisasm_arm_instruction instruction;

            EXPECT(decode_word(reserved[i], CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
            EXPECT(error_only(&instruction,
                CDISASM_STATUS_INVALID_INSTRUCTION));
        }
    }
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
        UINT32_C(0x5efd4da7), /* scalar SQSHL */
        UINT32_C(0x5efd55a7), /* scalar SRSHL */
        UINT32_C(0x7efd4da7), /* scalar UQSHL */
        UINT32_C(0x7efd55a7), /* scalar URSHL */
        UINT32_C(0x4efd4da7), /* vector SQSHL */
        UINT32_C(0x4efd55a7), /* vector SRSHL */
        UINT32_C(0x6efd4da7), /* vector UQSHL */
        UINT32_C(0x6efd55a7), /* vector URSHL */
        UINT32_C(0x5efd5da7), /* scalar SQRSHL */
        UINT32_C(0x7efd5da7), /* scalar UQRSHL */
        UINT32_C(0x4efd5da7), /* vector SQRSHL */
        UINT32_C(0x6efd5da7), /* vector UQRSHL */
        UINT32_C(0x4efd8da7)  /* vector CMTST */
    };
    unsigned operation;
    size_t index;

    for (operation = 0u; operation < 2u; ++operation) {
        uint32_t words[2] = {
            make_scalar_word(operation, 29u, 13u, 7u),
            make_vector_word(operation, 1u, 3u, 29u, 13u, 7u)
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
        EXPECT(!is_variable_shift_form(instruction.form_id));
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
        uint32_t scalar = make_scalar_word(operation, 29u, 13u, 7u);
        uint32_t vector = make_vector_word(
            operation, 1u, 3u, 29u, 13u, 7u);
        uint32_t reserved = make_vector_word(
            operation, 0u, 3u, 29u, 13u, 7u);

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
    EXPECT(decode_word(make_scalar_word(0u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    (void)decode_word(make_vector_word(1u, 1u, 2u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
        || !is_variable_shift_form(instruction.form_id));
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
    char expected[160];
    char text[160];
    unsigned operation;

    for (operation = 0u; operation < 2u; ++operation) {
        int length = snprintf(expected, sizeof(expected),
            "%s d7, d13, d29", operations[operation].mnemonic);

        EXPECT(length > 0 && (size_t)length < sizeof(expected));
        expect_format(make_scalar_word(operation, 29u, 13u, 7u),
                      expected);
        for (unsigned q = 0u; q < 2u; ++q) {
            unsigned maximum_size = q != 0u ? 3u : 2u;

            for (unsigned size_code = 0u;
                 size_code <= maximum_size; ++size_code) {
                unsigned total_size = q != 0u ? 16u : 8u;
                unsigned count = total_size >> size_code;

                length = snprintf(expected, sizeof(expected),
                    "%s v7.%u%c, v13.%u%c, v29.%u%c",
                    operations[operation].mnemonic,
                    count, element_letters[size_code],
                    count, element_letters[size_code],
                    count, element_letters[size_code]);
                EXPECT(length > 0 && (size_t)length < sizeof(expected));
                expect_format(make_vector_word(operation, q, size_code,
                    29u, 13u, 7u), expected);
            }
        }
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_scalar_word(0u, 29u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text)) == strlen("SSHL d31, d30, d29"));
    EXPECT(strcmp(text, "SSHL d31, d30, d29") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(5841));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_USHL);
    REJECT_MUTATION(forged.raw_instruction = make_scalar_word(
        1u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = make_vector_word(
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
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_D30);
    REJECT_MUTATION(forged.operand[0].size = 16u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_D29);
    REJECT_MUTATION(forged.operand[2].address = UINT64_C(1));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_vector_word(1u, 1u, 3u, 29u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    REJECT_MUTATION(forged.form_id = UINT16_C(5841));
    REJECT_MUTATION(forged.raw_instruction = make_scalar_word(
        1u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = make_vector_word(
        1u, 0u, 3u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_D31);
    REJECT_MUTATION(forged.operand[0].scale = 1u);

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_NOP;
    forged.form_id = UINT16_C(5826);
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "scalar-form-only claim");
    forged.form_id = CDISASM_ARM_FORM_NONE;
    forged.raw_instruction = make_scalar_word(0u, 2u, 1u, 0u);
    reject_forgery(&forged, "scalar-raw-only claim");
    forged.raw_instruction = make_vector_word(
        1u, 1u, 0u, 2u, 1u, 0u);
    reject_forgery(&forged, "vector-raw-only claim");

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_SSHL;
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
    test_saturating_scalar_family();
    test_profiles_and_neighbors();
    test_transport_and_status_precedence();
    test_formatter_and_schema();

    if (failures != 0) {
        fprintf(stderr,
                "%d Advanced SIMD variable-shift test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM Advanced SIMD SSHL/USHL tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=524288, reserved=65536)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
