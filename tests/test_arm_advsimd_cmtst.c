#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define CMTST_SCALAR_MASK UINT32_C(0xffe0fc00)
#define CMTST_SCALAR_VALUE UINT32_C(0x5ee08c00)
#define CMTST_VECTOR_MASK UINT32_C(0xbf20fc00)
#define CMTST_VECTOR_VALUE UINT32_C(0x0e208c00)

_Static_assert(CDISASM_ARM_NAME_CMTST == UINT16_C(683),
               "CMTST mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6131),
               "Advanced SIMD CMTST form IDs unavailable");

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

static uint32_t make_scalar_word(unsigned rm, unsigned rn, unsigned rd)
{
    return CMTST_SCALAR_VALUE | ((uint32_t)rm << 16)
        | ((uint32_t)rn << 5) | (uint32_t)rd;
}

static uint32_t make_vector_word(unsigned q, unsigned size_code,
                                 unsigned rm, unsigned rn, unsigned rd)
{
    return CMTST_VECTOR_VALUE | ((uint32_t)q << 30)
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
        UINT64_C(0x168000), options, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
                      cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static int is_cmtst_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(5831) || form_id == UINT16_C(6131);
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
                            uint32_t word, int scalar, unsigned q,
                            unsigned size_code, unsigned rm,
                            unsigned rn, unsigned rd)
{
    uint8_t total_size = scalar ? 8u : q != 0u ? 16u : 8u;
    uint8_t element_size = scalar
        ? 8u : (uint8_t)(UINT8_C(1) << size_code);
    cdisasm_arm_reg_id register_base = scalar
        ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;

    return instruction->address == UINT64_C(0x168000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == CDISASM_ARM_NAME_CMTST
        && instruction->form_id
            == (scalar ? UINT16_C(5831) : UINT16_C(6131))
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
    uint32_t vector_partitions[2][2] = { { 0u, 0u }, { 0u, 0u } };
    uint32_t vector_allocated = 0u;
    uint32_t vector_reserved = 0u;
    unsigned rm;

    for (rm = 0u; rm < 32u; ++rm) {
        unsigned rn;

        for (rn = 0u; rn < 32u; ++rn) {
            unsigned rd;

            for (rd = 0u; rd < 32u; ++rd) {
                cdisasm_arm_instruction instruction;
                uint32_t word = make_scalar_word(rm, rn, rd);
                uint32_t decoded;

                ++scalar_allocated;
                EXPECT((word & CMTST_SCALAR_MASK)
                    == CMTST_SCALAR_VALUE);
                memset(&instruction, 0xa5, sizeof(instruction));
                decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
                    CDISASM_ARM_MODE_A64, 4u,
                    CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
                EXPECT(decoded == 4u);
                EXPECT(metadata_matches(&instruction, word, 1, 0u, 3u,
                                        rm, rn, rd));
#else
                EXPECT(decoded == 0u);
                EXPECT(error_only(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            }
        }
    }

    for (unsigned q = 0u; q < 2u; ++q) {
        for (unsigned size_code = 0u; size_code < 4u; ++size_code) {
            int valid = size_code <= 2u || q != 0u;

            for (rm = 0u; rm < 32u; ++rm) {
                unsigned rn;

                for (rn = 0u; rn < 32u; ++rn) {
                    unsigned rd;

                    for (rd = 0u; rd < 32u; ++rd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = make_vector_word(
                            q, size_code, rm, rn, rd);
                        uint32_t decoded;

                        ++vector_partitions[q][valid ? 0u : 1u];
                        if (valid) {
                            ++vector_allocated;
                        } else {
                            ++vector_reserved;
                        }
                        EXPECT((word & CMTST_VECTOR_MASK)
                            == CMTST_VECTOR_VALUE);
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
                            EXPECT(metadata_matches(&instruction, word, 0,
                                q, size_code, rm, rn, rd));
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

    EXPECT(scalar_allocated == UINT32_C(32768));
    EXPECT(vector_partitions[0][0] == UINT32_C(98304));
    EXPECT(vector_partitions[0][1] == UINT32_C(32768));
    EXPECT(vector_partitions[1][0] == UINT32_C(131072));
    EXPECT(vector_partitions[1][1] == UINT32_C(0));
    EXPECT(vector_allocated == UINT32_C(229376));
    EXPECT(vector_reserved == UINT32_C(32768));
    EXPECT(scalar_allocated + vector_allocated == UINT32_C(262144));
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
    static const uint32_t words[2] = {
        UINT32_C(0x5efd8da7), /* cmtst d7, d13, d29 */
        UINT32_C(0x4efd8da7)  /* cmtst v7.2d, v13.2d, v29.2d */
    };
    static const uint32_t masks[2] = {
        CMTST_SCALAR_MASK, CMTST_VECTOR_MASK
    };
    static const cdisasm_arm_form_id forms[2] = {
        UINT16_C(5831), UINT16_C(6131)
    };
    static const uint32_t sibling_words[] = {
        UINT32_C(0x6efd8da7), /* vector CMEQ register */
        UINT32_C(0x7efd8da7), /* scalar CMEQ register */
        UINT32_C(0x4ee089a7), /* vector CMGT #0 */
        UINT32_C(0x4ee099a7), /* vector CMEQ #0 */
        UINT32_C(0x5ee089a7), /* scalar CMGT #0 */
        UINT32_C(0x4ebd95a7)  /* vector MLA */
    };
    size_t index;

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
            decoded = decode_word(words[index] ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded != 4u || instruction.form_id != forms[index]);
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
        EXPECT(!is_cmtst_form(instruction.form_id));
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
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x168000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x168000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x168000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x168000),
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
    uint32_t scalar = make_scalar_word(29u, 13u, 7u);
    uint32_t vector = make_vector_word(1u, 3u, 29u, 13u, 7u);
    uint32_t reserved = make_vector_word(0u, 3u, 29u, 13u, 7u);

    check_transport(scalar);
    check_transport(vector);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 3u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_TRUNCATED));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, UINT64_C(1) << 63,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(scalar, CDISASM_ARM_CPU_CORTEX_A7,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    (void)decode_word(vector, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
    EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
        || !is_cmtst_form(instruction.form_id));
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
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[160];

    expect_format(make_scalar_word(29u, 13u, 7u),
                  "cmtst d7, d13, d29");
    expect_format(make_vector_word(0u, 0u, 29u, 13u, 7u),
                  "cmtst v7.8b, v13.8b, v29.8b");
    expect_format(make_vector_word(0u, 1u, 29u, 13u, 7u),
                  "cmtst v7.4h, v13.4h, v29.4h");
    expect_format(make_vector_word(0u, 2u, 29u, 13u, 7u),
                  "cmtst v7.2s, v13.2s, v29.2s");
    expect_format(make_vector_word(1u, 0u, 29u, 13u, 7u),
                  "cmtst v7.16b, v13.16b, v29.16b");
    expect_format(make_vector_word(1u, 1u, 29u, 13u, 7u),
                  "cmtst v7.8h, v13.8h, v29.8h");
    expect_format(make_vector_word(1u, 2u, 29u, 13u, 7u),
                  "cmtst v7.4s, v13.4s, v29.4s");
    expect_format(make_vector_word(1u, 3u, 29u, 13u, 7u),
                  "cmtst v7.2d, v13.2d, v29.2d");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_scalar_word(29u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text)) == strlen("CMTST d31, d30, d29"));
    EXPECT(strcmp(text, "CMTST d31, d30, d29") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(6131));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_CMEQ);
    REJECT_MUTATION(forged.raw_instruction = make_vector_word(
        1u, 3u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd503201f));
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
    EXPECT(decode_word(make_vector_word(1u, 3u, 29u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    REJECT_MUTATION(forged.form_id = UINT16_C(5831));
    REJECT_MUTATION(forged.raw_instruction = make_scalar_word(
        29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = make_vector_word(
        0u, 3u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_D31);
    REJECT_MUTATION(forged.operand[0].scale = 1u);

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_NOP;
    forged.form_id = UINT16_C(5831);
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "scalar-form-only claim");
    forged.form_id = CDISASM_ARM_FORM_NONE;
    forged.raw_instruction = make_scalar_word(2u, 1u, 0u);
    reject_forgery(&forged, "scalar-raw-only claim");
    forged.raw_instruction = make_vector_word(1u, 0u, 2u, 1u, 0u);
    reject_forgery(&forged, "vector-raw-only claim");

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_CMTST;
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
        fprintf(stderr, "%d Advanced SIMD CMTST test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM Advanced SIMD CMTST tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=262144, reserved=32768)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
