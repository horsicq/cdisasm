#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define ADDLV_MASK UINT32_C(0xbf3ffc00)
#define SADDLV_VALUE UINT32_C(0x0e303800)
#define UADDLV_VALUE UINT32_C(0x2e303800)
#define SADDLV_FORM UINT16_C(6074)
#define UADDLV_FORM UINT16_C(6082)

_Static_assert(CDISASM_ARM_NAME_SADDLV == UINT16_C(1312),
               "SADDLV mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_UADDLV == UINT16_C(1742),
               "UADDLV mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UADDLV_FORM,
               "Advanced SIMD SADDLV/UADDLV form IDs unavailable");

typedef struct addlv_operation {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
} addlv_operation;

static const addlv_operation operations[2] = {
    { SADDLV_VALUE, CDISASM_ARM_NAME_SADDLV, SADDLV_FORM, "saddlv" },
    { UADDLV_VALUE, CDISASM_ARM_NAME_UADDLV, UADDLV_FORM, "uaddlv" }
};

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

static uint32_t make_word(const addlv_operation *operation,
                          unsigned q, unsigned size_code,
                          unsigned rn, unsigned rd)
{
    return operation->value | ((uint32_t)q << 30)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)rn << 5) | (uint32_t)rd;
}

static int allocated_control(unsigned q, unsigned size_code)
{
    return size_code <= 1u || (q != 0u && size_code == 2u);
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
        UINT64_C(0x16c000), options, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
                      cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static int vector_matches(const cdisasm_arm_operand *operand,
                          cdisasm_arm_reg_id base, unsigned encoded,
                          uint8_t total_size, uint8_t element_size,
                          cdisasm_operand_access access)
{
    return operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg == (cdisasm_arm_reg_id)(base + encoded)
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
                            const addlv_operation *operation,
                            uint32_t word, unsigned q,
                            unsigned size_code, unsigned rn, unsigned rd)
{
    uint8_t source_element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t result_element_size =
        (uint8_t)(source_element_size * 2u);
    uint8_t vector_size = q != 0u ? 16u : 8u;
    cdisasm_arm_reg_id result_base = result_element_size == 2u
        ? CDISASM_ARM_REG_H0 : result_element_size == 4u
            ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;

    return instruction->address == UINT64_C(0x16c000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == operation->name_id
        && instruction->form_id == operation->form_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == 2u
        && vector_matches(&instruction->operand[0], result_base, rd,
            result_element_size, result_element_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        && vector_matches(&instruction->operand[1], CDISASM_ARM_REG_V0,
            rn, vector_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_envelopes(void)
{
    uint32_t partitions[2][2][4][2] = {{{{0u}}}};
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned operation_index;

    for (operation_index = 0u; operation_index < 2u; ++operation_index) {
        const addlv_operation *operation = &operations[operation_index];
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 0u; size_code < 4u; ++size_code) {
                int is_allocated = allocated_control(q, size_code);
                unsigned rn;

                for (rn = 0u; rn < 32u; ++rn) {
                    unsigned rd;

                    for (rd = 0u; rd < 32u; ++rd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = make_word(
                            operation, q, size_code, rn, rd);
                        uint32_t decoded;

                        ++partitions[operation_index][q]
                            [size_code][is_allocated];
                        if (is_allocated) {
                            ++allocated;
                        } else {
                            ++reserved;
                        }
                        EXPECT((word & ADDLV_MASK) == operation->value);
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                        if (is_allocated) {
#if USE_EXTRA_OPCODES
                            EXPECT(decoded == 4u);
                            EXPECT(metadata_matches(&instruction, operation,
                                word, q, size_code, rn, rd));
#else
                            EXPECT(decoded == 0u);
                            EXPECT(error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        } else {
                            EXPECT(decoded == 0u);
                            EXPECT(error_only(&instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                        }
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(10240));
    EXPECT(reserved == UINT32_C(6144));
    for (operation_index = 0u; operation_index < 2u; ++operation_index) {
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 0u; size_code < 4u; ++size_code) {
                int is_allocated = allocated_control(q, size_code);

                EXPECT(partitions[operation_index][q]
                    [size_code][is_allocated] == UINT32_C(1024));
                EXPECT(partitions[operation_index][q]
                    [size_code][!is_allocated] == 0u);
            }
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

static void test_profiles_and_collision_boundaries(void)
{
    static const uint32_t sibling_words[] = {
        UINT32_C(0x0e31b800), /* Advanced SIMD ADDV */
        UINT32_C(0x0e30a800), /* Advanced SIMD SMAXV */
        UINT32_C(0x2e30a800), /* Advanced SIMD UMAXV */
        UINT32_C(0x04002000), /* SVE SADDV */
        UINT32_C(0x04012000), /* SVE UADDV */
        UINT32_C(0x0e20bc00), /* vector ADDP */
        UINT32_C(0x5ef1b800)  /* scalar ADDP */
    };
    unsigned operation_index;
    size_t index;

    for (operation_index = 0u; operation_index < 2u; ++operation_index) {
        const addlv_operation *operation = &operations[operation_index];
        uint32_t word = make_word(operation, 1u, 2u, 13u, 7u);
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

            if ((ADDLV_MASK & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            (void)decode_word(word ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
                || instruction.form_id != operation->form_id);
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
        EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
            || (instruction.form_id != SADDLV_FORM
                && instruction.form_id != UADDLV_FORM));
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
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x16c000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x16c000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x16c000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x16c000),
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
    unsigned operation_index;

    for (operation_index = 0u; operation_index < 2u; ++operation_index) {
        const addlv_operation *operation = &operations[operation_index];
        uint32_t allocated = make_word(operation, 1u, 2u, 13u, 7u);
        uint32_t reserved_2s = make_word(operation, 0u, 2u, 13u, 7u);
        uint32_t reserved_1d = make_word(operation, 0u, 3u, 13u, 7u);
        uint32_t reserved_2d = make_word(operation, 1u, 3u, 13u, 7u);

        check_transport(make_word(operation, 0u, 0u, 0u, 0u));
        check_transport(allocated);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved_2s, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_INSTRUCTION));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved_1d, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_INSTRUCTION));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved_2d, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_INSTRUCTION));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved_2s, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 3u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_TRUNCATED));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved_2s, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, UINT64_C(1) << 63,
            &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_ARGUMENT));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(allocated, CDISASM_ARM_CPU_CORTEX_A7,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_ARGUMENT));

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(allocated, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
            || instruction.form_id != operation->form_id);
    }
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

static void expect_format(const addlv_operation *operation,
                          unsigned q, unsigned size_code,
                          unsigned rn, unsigned rd,
                          const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[160];
    char short_text[8];
    size_t expected_length = strlen(expected);
    size_t length;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(operation, q, size_code, rn, rd),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
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
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    unsigned operation_index;

    expect_format(&operations[0], 0u, 0u, 0u, 0u,
                  "saddlv h0, v0.8b");
    expect_format(&operations[0], 1u, 0u, 30u, 31u,
                  "saddlv h31, v30.16b");
    expect_format(&operations[0], 0u, 1u, 13u, 7u,
                  "saddlv s7, v13.4h");
    expect_format(&operations[0], 1u, 1u, 13u, 7u,
                  "saddlv s7, v13.8h");
    expect_format(&operations[0], 1u, 2u, 13u, 7u,
                  "saddlv d7, v13.4s");
    expect_format(&operations[1], 0u, 0u, 0u, 0u,
                  "uaddlv h0, v0.8b");
    expect_format(&operations[1], 1u, 0u, 30u, 31u,
                  "uaddlv h31, v30.16b");
    expect_format(&operations[1], 0u, 1u, 13u, 7u,
                  "uaddlv s7, v13.4h");
    expect_format(&operations[1], 1u, 1u, 13u, 7u,
                  "uaddlv s7, v13.8h");
    expect_format(&operations[1], 1u, 2u, 13u, 7u,
                  "uaddlv d7, v13.4s");

    for (operation_index = 0u; operation_index < 2u; ++operation_index) {
        const addlv_operation *operation = &operations[operation_index];
        const addlv_operation *other = &operations[1u - operation_index];

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(make_word(operation, 1u, 2u, 30u, 31u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);

#define REJECT_MUTATION(statement)                                          \
        do {                                                                \
            forged = instruction;                                           \
            statement;                                                      \
            reject_forgery(&forged, #statement);                            \
        } while (0)

        REJECT_MUTATION(forged.form_id = other->form_id);
        REJECT_MUTATION(forged.name_id = other->name_id);
        REJECT_MUTATION(forged.raw_instruction = make_word(
            operation, 0u, 2u, 30u, 31u));
        REJECT_MUTATION(forged.raw_instruction = make_word(
            other, 1u, 2u, 30u, 31u));
        REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd503201f));
        REJECT_MUTATION(forged.opcode_size = 2u);
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
        REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
        REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
        REJECT_MUTATION(forged.instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
        REJECT_MUTATION(forged.branch_target = UINT64_C(4));
        REJECT_MUTATION(forged.operand_count = 1u);
        REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_D30);
        REJECT_MUTATION(forged.operand[0].size = 4u);
        REJECT_MUTATION(forged.operand[0].extend_type =
            (cdisasm_arm_extend_type)4u);
        REJECT_MUTATION(forged.operand[0].scale = 2u);
        REJECT_MUTATION(forged.operand[0].access =
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V29);
        REJECT_MUTATION(forged.operand[1].size = 8u);
        REJECT_MUTATION(forged.operand[1].extend_type =
            (cdisasm_arm_extend_type)2u);
        REJECT_MUTATION(forged.operand[1].scale = 2u);
        REJECT_MUTATION(forged.operand[1].access =
            CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[1].address = UINT64_C(1));

        memset(&forged, 0, sizeof(forged));
        forged.name_id = CDISASM_ARM_NAME_NOP;
        forged.form_id = operation->form_id;
        forged.raw_instruction = UINT32_C(0xd503201f);
        forged.opcode_size = 4u;
        forged.isa_id = CDISASM_ARM_ISA_A64;
        forged.condition = CDISASM_ARM_CONDITION_AL;
        reject_forgery(&forged, "form-only claim");
        forged.form_id = CDISASM_ARM_FORM_NONE;
        forged.raw_instruction = make_word(operation, 1u, 0u, 1u, 0u);
        reject_forgery(&forged, "raw-only claim");

        memset(&forged, 0, sizeof(forged));
        forged.name_id = operation->name_id;
        forged.raw_instruction = UINT32_C(0xd503201f);
        forged.opcode_size = 4u;
        forged.isa_id = CDISASM_ARM_ISA_A64;
        forged.condition = CDISASM_ARM_CONDITION_AL;
        reject_forgery(&forged, "name-only claim");

#undef REJECT_MUTATION
    }
}
#else
static void test_formatter_and_schema(void)
{
}
#endif

int main(void)
{
    test_exhaustive_envelopes();
    test_profiles_and_collision_boundaries();
    test_transport_and_status_precedence();
    test_formatter_and_schema();

    if (failures != 0) {
        fprintf(stderr,
                "%d Advanced SIMD SADDLV/UADDLV test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM Advanced SIMD SADDLV/UADDLV tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=10240, reserved=6144)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
