#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define MINMAX_MASK UINT32_C(0xbf20fc00)

typedef struct minmax_operation {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
} minmax_operation;

static const minmax_operation operations[4] = {
    { UINT32_C(0x0e206400), CDISASM_ARM_NAME_SMAX,
      UINT16_C(6126), "smax" },
    { UINT32_C(0x0e206c00), CDISASM_ARM_NAME_SMIN,
      UINT16_C(6127), "smin" },
    { UINT32_C(0x2e206400), CDISASM_ARM_NAME_UMAX,
      UINT16_C(6168), "umax" },
    { UINT32_C(0x2e206c00), CDISASM_ARM_NAME_UMIN,
      UINT16_C(6169), "umin" }
};

_Static_assert(CDISASM_ARM_NAME_SMAX == UINT16_C(239),
               "SMAX mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SMIN == UINT16_C(240),
               "SMIN mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_UMAX == UINT16_C(241),
               "UMAX mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_UMIN == UINT16_C(242),
               "UMIN mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6169),
               "Advanced SIMD min/max form IDs unavailable");

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
        UINT64_C(0x167000), options, instruction);
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
    return instruction->address == UINT64_C(0x167000)
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
                            EXPECT((word & MINMAX_MASK)
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

static int is_minmax_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6126) || form_id == UINT16_C(6127)
        || form_id == UINT16_C(6168) || form_id == UINT16_C(6169);
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

            if ((MINMAX_MASK & (UINT32_C(1) << bit)) == 0u) {
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
            UINT32_C(0x0e204c00), /* SQSHL */
            UINT32_C(0x0e205400), /* SRSHL */
            UINT32_C(0x0e207400), /* SABD */
            UINT32_C(0x0e20a400), /* SMAXP */
            UINT32_C(0x2e20ac00)  /* UMINP */
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
            EXPECT(!is_minmax_form(instruction.form_id));
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
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x167000),
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x167000),
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
        EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

        word_to_le(word, bytes);
        memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
        EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x167000),
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
        EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x167000),
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
    char text[192];
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

typedef struct minmax_sibling {
    uint32_t word;
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} minmax_sibling;

static void expect_decoded_sibling(const minmax_sibling *sibling)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[192];

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(sibling->word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.raw_instruction == sibling->word);
    EXPECT(instruction.name_id == sibling->name_id);
    EXPECT(instruction.form_id == sibling->form_id);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text)) != 0u);

    forged = instruction;
    forged.form_id = sibling->name_id == CDISASM_ARM_NAME_SMAX
        ? UINT16_C(6126)
        : sibling->name_id == CDISASM_ARM_NAME_SMIN
            ? UINT16_C(6127)
            : sibling->name_id == CDISASM_ARM_NAME_UMAX
                ? UINT16_C(6168) : UINT16_C(6169);
    reject_forgery(&forged, "sibling raw with fixed-vector form");
    forged = instruction;
    forged.instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
    reject_forgery(&forged, "sibling with forged SIMD flag");
}

static void expect_opaque_sibling(const minmax_sibling *sibling)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[192];

    memset(&instruction, 0, sizeof(instruction));
    instruction.opcode_size = 4u;
    instruction.raw_instruction = sibling->word;
    instruction.name_id = sibling->name_id;
    instruction.form_id = sibling->form_id;
    instruction.condition = CDISASM_ARM_CONDITION_AL;
    instruction.isa_id = CDISASM_ARM_ISA_A64;
    instruction.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text)) != 0u);

    forged = instruction;
    forged.form_id = sibling->name_id == CDISASM_ARM_NAME_SMAX
        ? UINT16_C(6126)
        : sibling->name_id == CDISASM_ARM_NAME_SMIN
            ? UINT16_C(6127)
            : sibling->name_id == CDISASM_ARM_NAME_UMAX
                ? UINT16_C(6168) : UINT16_C(6169);
    reject_forgery(&forged, "SME2 raw with fixed-vector form");
    forged = instruction;
    forged.instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
    reject_forgery(&forged, "SME2 sibling with forged SIMD flag");
}

static void test_formatter_and_collisions(void)
{
    static const minmax_sibling sve_siblings[] = {
        { UINT32_C(0x048814a7), UINT16_C(2226), CDISASM_ARM_NAME_SMAX },
        { UINT32_C(0x048a14a7), UINT16_C(2227), CDISASM_ARM_NAME_SMIN },
        { UINT32_C(0x048914a7), UINT16_C(2229), CDISASM_ARM_NAME_UMAX },
        { UINT32_C(0x048b14a7), UINT16_C(2230), CDISASM_ARM_NAME_UMIN },
        { UINT32_C(0x2528d009), UINT16_C(2626), CDISASM_ARM_NAME_SMAX },
        { UINT32_C(0x256adfea), UINT16_C(2627), CDISASM_ARM_NAME_SMIN },
        { UINT32_C(0x25a9dfeb), UINT16_C(2628), CDISASM_ARM_NAME_UMAX },
        { UINT32_C(0x25ebc00c), UINT16_C(2629), CDISASM_ARM_NAME_UMIN }
    };
    static const minmax_sibling cssc_siblings[] = {
        { UINT32_C(0x11c00000), UINT16_C(4404), CDISASM_ARM_NAME_SMAX },
        { UINT32_C(0x11c40000), UINT16_C(4405), CDISASM_ARM_NAME_UMAX },
        { UINT32_C(0x11c80000), UINT16_C(4406), CDISASM_ARM_NAME_SMIN },
        { UINT32_C(0x11cc0000), UINT16_C(4407), CDISASM_ARM_NAME_UMIN },
        { UINT32_C(0x91c00000), UINT16_C(4408), CDISASM_ARM_NAME_SMAX },
        { UINT32_C(0x91c40000), UINT16_C(4409), CDISASM_ARM_NAME_UMAX },
        { UINT32_C(0x91c80000), UINT16_C(4410), CDISASM_ARM_NAME_SMIN },
        { UINT32_C(0x91cc0000), UINT16_C(4411), CDISASM_ARM_NAME_UMIN },
        { UINT32_C(0x1ac06000), UINT16_C(5588), CDISASM_ARM_NAME_SMAX },
        { UINT32_C(0x1ac06400), UINT16_C(5589), CDISASM_ARM_NAME_UMAX },
        { UINT32_C(0x1ac06800), UINT16_C(5590), CDISASM_ARM_NAME_SMIN },
        { UINT32_C(0x1ac06c00), UINT16_C(5591), CDISASM_ARM_NAME_UMIN },
        { UINT32_C(0x9ac06000), UINT16_C(5604), CDISASM_ARM_NAME_SMAX },
        { UINT32_C(0x9ac06400), UINT16_C(5605), CDISASM_ARM_NAME_UMAX },
        { UINT32_C(0x9ac06800), UINT16_C(5606), CDISASM_ARM_NAME_SMIN },
        { UINT32_C(0x9ac06c00), UINT16_C(5607), CDISASM_ARM_NAME_UMIN }
    };
    static const minmax_sibling sme2_siblings[] = {
        { UINT32_C(0xc120a000), UINT16_C(4217), CDISASM_ARM_NAME_SMAX },
        { UINT32_C(0xc120a020), UINT16_C(4218), CDISASM_ARM_NAME_SMIN },
        { UINT32_C(0xc120a001), UINT16_C(4219), CDISASM_ARM_NAME_UMAX },
        { UINT32_C(0xc120a021), UINT16_C(4220), CDISASM_ARM_NAME_UMIN },
        { UINT32_C(0xc120a800), UINT16_C(4235), CDISASM_ARM_NAME_SMAX },
        { UINT32_C(0xc120a820), UINT16_C(4236), CDISASM_ARM_NAME_SMIN },
        { UINT32_C(0xc120a801), UINT16_C(4237), CDISASM_ARM_NAME_UMAX },
        { UINT32_C(0xc120a821), UINT16_C(4238), CDISASM_ARM_NAME_UMIN },
        { UINT32_C(0xc120b000), UINT16_C(4253), CDISASM_ARM_NAME_SMAX },
        { UINT32_C(0xc120b020), UINT16_C(4254), CDISASM_ARM_NAME_SMIN },
        { UINT32_C(0xc120b001), UINT16_C(4255), CDISASM_ARM_NAME_UMAX },
        { UINT32_C(0xc120b021), UINT16_C(4256), CDISASM_ARM_NAME_UMIN },
        { UINT32_C(0xc120b800), UINT16_C(4272), CDISASM_ARM_NAME_SMAX },
        { UINT32_C(0xc120b820), UINT16_C(4273), CDISASM_ARM_NAME_SMIN },
        { UINT32_C(0xc120b801), UINT16_C(4274), CDISASM_ARM_NAME_UMAX },
        { UINT32_C(0xc120b821), UINT16_C(4275), CDISASM_ARM_NAME_UMIN }
    };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[160];
    size_t index;

    expect_format(0u, 0u, 0u, "smax v7.8b, v13.8b, v29.8b");
    expect_format(0u, 1u, 1u, "smax v7.8h, v13.8h, v29.8h");
    expect_format(1u, 0u, 2u, "smin v7.2s, v13.2s, v29.2s");
    expect_format(2u, 1u, 0u, "umax v7.16b, v13.16b, v29.16b");
    expect_format(3u, 0u, 1u, "umin v7.4h, v13.4h, v29.4h");
    expect_format(3u, 1u, 2u, "umin v7.4s, v13.4s, v29.4s");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(0u, 1u, 0u, 29u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("SMAX v31.16b, v30.16b, v29.16b"));
    EXPECT(strcmp(text, "SMAX v31.16b, v30.16b, v29.16b") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(6127));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_SMIN);
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
    forged.form_id = UINT16_C(6126);
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "fixed-form-only claim");
    forged.form_id = CDISASM_ARM_FORM_NONE;
    forged.raw_instruction = make_word(0u, 0u, 0u, 2u, 1u, 0u);
    reject_forgery(&forged, "raw-only claim");

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_SMAX;
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "same-name-only claim");

    for (index = 0u;
         index < sizeof(sve_siblings) / sizeof(sve_siblings[0]); ++index) {
        expect_decoded_sibling(&sve_siblings[index]);
    }
    for (index = 0u;
         index < sizeof(cssc_siblings) / sizeof(cssc_siblings[0]); ++index) {
        expect_decoded_sibling(&cssc_siblings[index]);
    }
    for (index = 0u;
         index < sizeof(sme2_siblings) / sizeof(sme2_siblings[0]); ++index) {
        if (index < 16u) {
            expect_decoded_sibling(&sme2_siblings[index]);
        } else {
            expect_opaque_sibling(&sme2_siblings[index]);
        }
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
        fprintf(stderr, "%d Advanced SIMD min/max test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM Advanced SIMD min/max tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=786432, reserved=262144)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
