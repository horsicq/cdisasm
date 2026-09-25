#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define PAIRWISE_MASK UINT32_C(0xbf20fc00)

typedef struct pairwise_operation {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
} pairwise_operation;

static const pairwise_operation operations[4] = {
    { UINT32_C(0x0e20a400), CDISASM_ARM_NAME_SMAXP,
      UINT16_C(6134), "smaxp" },
    { UINT32_C(0x0e20ac00), CDISASM_ARM_NAME_SMINP,
      UINT16_C(6135), "sminp" },
    { UINT32_C(0x2e20a400), CDISASM_ARM_NAME_UMAXP,
      UINT16_C(6176), "umaxp" },
    { UINT32_C(0x2e20ac00), CDISASM_ARM_NAME_UMINP,
      UINT16_C(6177), "uminp" }
};

_Static_assert(CDISASM_ARM_NAME_SMAXP == UINT16_C(1404),
               "SMAXP mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SMINP == UINT16_C(1407),
               "SMINP mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_UMAXP == UINT16_C(1765),
               "UMAXP mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_UMINP == UINT16_C(1768),
               "UMINP mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6177),
               "pairwise min/max form IDs unavailable");

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 24) {                                           \
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
        UINT64_C(0x166000), options, instruction);
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
        && operand->extend_type
            == (cdisasm_arm_extend_type)element_size
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

    return instruction->address == UINT64_C(0x166000)
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
        && vector_matches(&instruction->operand[0], rd, vector_size,
                          element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && vector_matches(&instruction->operand[1], rn, vector_size,
                          element_size, CDISASM_OPERAND_ACCESS_READ)
        && vector_matches(&instruction->operand[2], rm, vector_size,
                          element_size, CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_envelopes(void)
{
    uint32_t partitions[4][2][2] = { 0 };
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned operation;

    for (operation = 0u; operation < 4u; ++operation) {
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 0u; size_code < 4u; ++size_code) {
                unsigned rm;

                for (rm = 0u; rm < 32u; ++rm) {
                    unsigned rn;

                    for (rn = 0u; rn < 32u; ++rn) {
                        unsigned rd;

                        for (rd = 0u; rd < 32u; ++rd) {
                            cdisasm_arm_instruction instruction;
                            uint32_t word = make_word(operation, q,
                                size_code, rm, rn, rd);
                            uint32_t decoded;
                            int valid = size_code <= 2u;

                            ++partitions[operation][q][valid ? 0u : 1u];
                            if (valid) {
                                ++allocated;
                            } else {
                                ++reserved;
                            }
                            EXPECT((word & PAIRWISE_MASK)
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
                                EXPECT(metadata_matches(&instruction,
                                    word, operation, q, size_code,
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
    for (operation = 0u; operation < 4u; ++operation) {
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            EXPECT(partitions[operation][q][0] == UINT32_C(98304));
            EXPECT(partitions[operation][q][1] == UINT32_C(32768));
        }
    }
    EXPECT(allocated == UINT32_C(786432));
    EXPECT(reserved == UINT32_C(262144));
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

static int is_pairwise_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6134) || form_id == UINT16_C(6135)
        || form_id == UINT16_C(6176) || form_id == UINT16_C(6177);
}

static void test_profiles_and_neighbors(void)
{
    unsigned operation;

    for (operation = 0u; operation < 4u; ++operation) {
        uint32_t word = make_word(operation, operation & 1u,
            operation % 3u, 29u, 13u, 7u);
        unsigned bit;

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY,
                          CDISASM_STATUS_OK);
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

            if ((PAIRWISE_MASK & (UINT32_C(1) << bit)) == 0u) {
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

    {
        static const uint32_t sibling_words[] = {
            UINT32_C(0x2e209c00), /* PMUL */
            UINT32_C(0x0e20b400), /* SQDMULH */
            UINT32_C(0x2e20b400), /* SQRDMULH */
            UINT32_C(0x0e209c00), /* MUL */
            UINT32_C(0x2e20bc00)  /* ADDP */
        };
        size_t index;

        for (index = 0u;
             index < sizeof(sibling_words) / sizeof(sibling_words[0]);
             ++index) {
            cdisasm_arm_instruction instruction;
            uint32_t word = sibling_words[index]
                | UINT32_C(0x40000000) | (UINT32_C(29) << 16)
                | (UINT32_C(13) << 5) | UINT32_C(7);

            memset(&instruction, 0xa5, sizeof(instruction));
            (void)decode_word(word, CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(!is_pairwise_form(instruction.form_id));
        }
    }
}

static void test_transport_and_boundaries(void)
{
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned operation;

    for (operation = 0u; operation < 4u; ++operation) {
        uint32_t word = make_word(operation, operation & 1u,
            operation % 3u, 29u, 13u, 7u);
        unsigned boundary;

        memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &little) == 4u);
#else
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &little) == 0u);
#endif

        word_to_be(word, bytes);
        memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x166000),
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x166000),
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
        EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

        word_to_le(word, bytes);
        memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
        EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x166000),
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
        EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x166000),
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

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(make_word(operation, operation & 1u, 3u,
            2u, 1u, 0u), CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &other) == 0u);
        EXPECT(error_only(&other, CDISASM_STATUS_INVALID_INSTRUCTION));
    }

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(make_word(0u, 0u, 0u, 2u, 1u, 0u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(error_only(&other, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(make_word(0u, 0u, 0u, 2u, 1u, 0u),
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(error_only(&other, CDISASM_STATUS_INVALID_ARGUMENT));
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
        if (failures < 24) {
            fprintf(stderr, "accepted formatter forgery: %s -> %s\n",
                    mutation, text);
        }
        ++failures;
    }
}

static void expect_format(unsigned operation, unsigned q,
                          unsigned size_code, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[160];
    char short_text[8];
    size_t expected_length = strlen(expected);
    size_t length;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(operation, q, size_code,
        29u, 13u, 7u), CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
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
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, NULL, 0u) == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, short_text,
        sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void test_formatter_and_collisions(void)
{
    static const uint32_t sve_values[4] = {
        UINT32_C(0x4414a000), UINT32_C(0x4416a000),
        UINT32_C(0x4415a000), UINT32_C(0x4417a000)
    };
    static const cdisasm_arm_form_id sve_forms[4] = {
        UINT16_C(2689), UINT16_C(2690),
        UINT16_C(2691), UINT16_C(2692)
    };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[160];
    unsigned operation;

    expect_format(0u, 0u, 0u,
                  "smaxp v7.8b, v13.8b, v29.8b");
    expect_format(0u, 1u, 1u,
                  "smaxp v7.8h, v13.8h, v29.8h");
    expect_format(1u, 0u, 2u,
                  "sminp v7.2s, v13.2s, v29.2s");
    expect_format(2u, 1u, 0u,
                  "umaxp v7.16b, v13.16b, v29.16b");
    expect_format(3u, 0u, 1u,
                  "uminp v7.4h, v13.4h, v29.4h");
    expect_format(3u, 1u, 2u,
                  "uminp v7.4s, v13.4s, v29.4s");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(0u, 1u, 0u, 29u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("SMAXP v31.16b, v30.16b, v29.16b"));
    EXPECT(strcmp(text, "SMAXP v31.16b, v30.16b, v29.16b") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(6135));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_SMINP);
    REJECT_MUTATION(forged.raw_instruction = make_word(
        2u, 1u, 0u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = make_word(
        0u, 1u, 3u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd503201f));
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
    REJECT_MUTATION(forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_V30);
    REJECT_MUTATION(forged.operand[0].size = 8u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V29);
    REJECT_MUTATION(forged.operand[2].address = UINT64_C(1));

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_NOP;
    forged.form_id = UINT16_C(6134);
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "fixed-form-only claim");
    forged.form_id = CDISASM_ARM_FORM_NONE;
    forged.raw_instruction = make_word(0u, 0u, 0u, 2u, 1u, 0u);
    reject_forgery(&forged, "raw-only claim");

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_SMAXP;
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "same-name-only claim");

    /* SVE has four same-name siblings.  The fixed-vector validator must
     * admit their already-validated scalable schemas without claiming them. */
    for (operation = 0u; operation < 4u; ++operation) {
        uint32_t word = sve_values[operation] | (UINT32_C(2) << 22)
            | (UINT32_C(5) << 10) | (UINT32_C(29) << 5)
            | UINT32_C(7);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 4u);
        EXPECT(instruction.name_id == operations[operation].name_id);
        EXPECT(instruction.form_id == sve_forms[operation]);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) != 0u);
        forged = instruction;
        forged.form_id = operations[operation].form_id;
        reject_forgery(&forged, "SVE raw with fixed-vector form");
    }

#undef REJECT_MUTATION
}
#else
static void test_formatter_and_collisions(void)
{
}
#endif

int main(void)
{
    test_exhaustive_envelopes();
    test_profiles_and_neighbors();
    test_transport_and_boundaries();
    test_formatter_and_collisions();

    if (failures != 0) {
        fprintf(stderr, "%d pairwise min/max test(s) failed\n", failures);
        return 1;
    }
    printf("ARM Advanced SIMD pairwise min/max tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=786432, reserved=262144)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
