#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define NARROW_WIDEN_MOVE_MASK UINT32_C(0xbf3ffc00)

typedef struct narrow_widen_move_operation {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
    int widening;
} narrow_widen_move_operation;

/* Pinned AARCHMRS XTN_asimdmisc_N and SHLL_asimdmisc_S.  The saturating
 * siblings are deliberately absent: their FPSR.QC write has no exact public
 * representation in the fixed cdisasm_arm_instruction ABI. */
static const narrow_widen_move_operation operations[2] = {
    { UINT32_C(0x0e212800), CDISASM_ARM_NAME_XTN,
      UINT16_C(6015), "xtn", 0 },
    { UINT32_C(0x2e213800), CDISASM_ARM_NAME_SHLL,
      UINT16_C(6048), "shll", 1 }
};

_Static_assert(CDISASM_ARM_NAME_SHLL == UINT16_C(1383),
               "SHLL mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_XTN == UINT16_C(2048),
               "XTN mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6048),
               "Advanced SIMD narrowing/widening form IDs unavailable");

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

static uint32_t make_word(const narrow_widen_move_operation *operation,
                          unsigned q, unsigned size_code,
                          unsigned rn, unsigned rd)
{
    return operation->value | ((uint32_t)q << 30)
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
        UINT64_C(0x17a000), options, instruction);
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
                          unsigned encoded, uint8_t total_size,
                          uint8_t element_size,
                          cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded);
    expected.size = total_size;
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.scale = (uint8_t)(total_size / element_size);
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int immediate_matches(const cdisasm_arm_operand *operand,
                             uint64_t value)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_IMMEDIATE;
    expected.imm = value;
    expected.size = 1u;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            const narrow_widen_move_operation *operation,
                            uint32_t word, unsigned q,
                            unsigned size_code, unsigned rn, unsigned rd)
{
    uint8_t narrow_element_size =
        (uint8_t)(UINT8_C(1) << size_code);
    uint8_t wide_element_size =
        (uint8_t)(narrow_element_size * 2u);

    if (instruction->address != UINT64_C(0x17a000)
        || instruction->opcode_size != 4u
        || instruction->raw_instruction != word
        || instruction->name_id != operation->name_id
        || instruction->form_id != operation->form_id
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->isa_id != CDISASM_ARM_ISA_A64
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->last_error_id != CDISASM_STATUS_OK) {
        return 0;
    }
    if (!operation->widening) {
        return instruction->operand_count == 2u
            && vector_matches(&instruction->operand[0], rd,
                q != 0u ? 16u : 8u, narrow_element_size,
                q != 0u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                         : CDISASM_OPERAND_ACCESS_WRITE)
            && vector_matches(&instruction->operand[1], rn,
                16u, wide_element_size, CDISASM_OPERAND_ACCESS_READ);
    }
    return instruction->operand_count == 3u
        && vector_matches(&instruction->operand[0], rd,
            16u, wide_element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && vector_matches(&instruction->operand[1], rn,
            q != 0u ? 16u : 8u, narrow_element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && immediate_matches(&instruction->operand[2],
            (uint64_t)narrow_element_size * UINT64_C(8));
}
#endif

static void test_exhaustive_envelopes(void)
{
    uint32_t partitions[2][2][4][2] = {{{{0u}}}};
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned operation_index;

    for (operation_index = 0u; operation_index < 2u; ++operation_index) {
        const narrow_widen_move_operation *operation =
            &operations[operation_index];
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 0u; size_code < 4u; ++size_code) {
                int is_allocated = size_code <= 2u;
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
                        EXPECT((word & NARROW_WIDEN_MOVE_MASK)
                            == operation->value);
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

    EXPECT(allocated == UINT32_C(12288));
    EXPECT(reserved == UINT32_C(4096));
    for (operation_index = 0u; operation_index < 2u; ++operation_index) {
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 0u; size_code < 4u; ++size_code) {
                int is_allocated = size_code <= 2u;

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
    /* These six allocated saturating siblings require an FPSR.QC side-effect
     * representation and therefore must not be mistaken for XTN or SHLL. */
    static const uint32_t unrepresented_saturating[] = {
        UINT32_C(0x5e214800), /* scalar SQXTN */
        UINT32_C(0x7e212800), /* scalar SQXTUN */
        UINT32_C(0x7e214800), /* scalar UQXTN */
        UINT32_C(0x0e214800), /* vector SQXTN */
        UINT32_C(0x2e212800), /* vector SQXTUN */
        UINT32_C(0x2e214800)  /* vector UQXTN */
    };
    static const uint32_t other_siblings[] = {
        UINT32_C(0x0e204000), /* ADDHN */
        UINT32_C(0x0e202800), /* SADDLP */
        UINT32_C(0x2e203800), /* USQADD */
        UINT32_C(0x0e201800)  /* REV16 */
    };
    unsigned operation_index;
    size_t index;

    for (operation_index = 0u; operation_index < 2u; ++operation_index) {
        const narrow_widen_move_operation *operation =
            &operations[operation_index];
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

            if ((NARROW_WIDEN_MOVE_MASK
                    & (UINT32_C(1) << bit)) == 0u) {
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
         index < sizeof(unrepresented_saturating)
             / sizeof(unrepresented_saturating[0]);
         ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(unrepresented_saturating[index],
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
            || (instruction.form_id != UINT16_C(6015)
                && instruction.form_id != UINT16_C(6048)));
    }
    for (index = 0u;
         index < sizeof(other_siblings) / sizeof(other_siblings[0]);
         ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(other_siblings[index], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
            || (instruction.form_id != UINT16_C(6015)
                && instruction.form_id != UINT16_C(6048)));
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
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x17a000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x17a000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x17a000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x17a000),
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
        const narrow_widen_move_operation *operation =
            &operations[operation_index];
        uint32_t allocated = make_word(operation, 1u, 2u, 13u, 7u);
        uint32_t reserved_q0 = make_word(operation, 0u, 3u, 13u, 7u);
        uint32_t reserved_q1 = make_word(operation, 1u, 3u, 13u, 7u);

        check_transport(make_word(operation, 0u, 0u, 0u, 0u));
        check_transport(allocated);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved_q0, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_INSTRUCTION));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved_q1, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_INSTRUCTION));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved_q0, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 3u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_TRUNCATED));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved_q0, CDISASM_ARM_CPU_ANY,
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

static void expect_format(const narrow_widen_move_operation *operation,
                          unsigned q, unsigned size_code,
                          const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[160];
    char short_text[8];
    size_t expected_length = strlen(expected);
    size_t length;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(operation, q, size_code, 13u, 7u),
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
    static const char *const expected[2][2][3] = {
        {
            { "xtn v7.8b, v13.8h", "xtn v7.4h, v13.4s",
              "xtn v7.2s, v13.2d" },
            { "xtn2 v7.16b, v13.8h", "xtn2 v7.8h, v13.4s",
              "xtn2 v7.4s, v13.2d" }
        },
        {
            { "shll v7.8h, v13.8b, #8",
              "shll v7.4s, v13.4h, #16",
              "shll v7.2d, v13.2s, #32" },
            { "shll2 v7.8h, v13.16b, #8",
              "shll2 v7.4s, v13.8h, #16",
              "shll2 v7.2d, v13.4s, #32" }
        }
    };
    unsigned operation_index;

    for (operation_index = 0u; operation_index < 2u; ++operation_index) {
        const narrow_widen_move_operation *operation =
            &operations[operation_index];
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 0u; size_code < 3u; ++size_code) {
                expect_format(operation, q, size_code,
                    expected[operation_index][q][size_code]);
            }
        }
    }

    for (operation_index = 0u; operation_index < 2u; ++operation_index) {
        const narrow_widen_move_operation *operation =
            &operations[operation_index];
        const narrow_widen_move_operation *other =
            &operations[(operation_index + 1u) % 2u];
        cdisasm_arm_instruction instruction;
        cdisasm_arm_instruction forged;
        char text[160];
        const char *uppercase = operation->widening
            ? "SHLL2 v31.2d, v30.4s, #32"
            : "XTN2 v31.4s, v30.2d";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(make_word(operation, 1u, 2u, 30u, 31u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == strlen(uppercase));
        EXPECT(strcmp(text, uppercase) == 0);

#define REJECT_MUTATION(statement)                                          \
        do {                                                                \
            forged = instruction;                                           \
            statement;                                                      \
            reject_forgery(&forged, #statement);                            \
        } while (0)

        REJECT_MUTATION(forged.form_id = other->form_id);
        REJECT_MUTATION(forged.name_id = other->name_id);
        REJECT_MUTATION(forged.raw_instruction = make_word(
            operation, 1u, 3u, 30u, 31u));
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
        REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_V30);
        REJECT_MUTATION(forged.operand[0].size = 8u);
        REJECT_MUTATION(forged.operand[0].extend_type =
            (cdisasm_arm_extend_type)2u);
        REJECT_MUTATION(forged.operand[0].scale = 1u);
        REJECT_MUTATION(forged.operand[0].access =
            operation->widening ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                : CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V29);
        REJECT_MUTATION(forged.operand[1].size = 8u);
        REJECT_MUTATION(forged.operand[1].extend_type =
            (cdisasm_arm_extend_type)1u);
        REJECT_MUTATION(forged.operand[1].scale = 1u);
        REJECT_MUTATION(forged.operand[1].access =
            CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[1].address = UINT64_C(1));
        if (operation->widening) {
            REJECT_MUTATION(forged.operand[2].imm = UINT64_C(31));
            REJECT_MUTATION(forged.operand[2].size = 2u);
            REJECT_MUTATION(forged.operand[2].access =
                CDISASM_OPERAND_ACCESS_WRITE);
            REJECT_MUTATION(forged.operand[2].shift_type =
                CDISASM_ARM_SHIFT_LSL);
        }

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
                "%d ARM Advanced SIMD narrow/widen move test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM Advanced SIMD narrow/widen move tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=12288, reserved=4096)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
