#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

typedef struct high_narrow_descriptor {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
} high_narrow_descriptor;

/* Pinned AARCHMRS forms ADDHN_asimddiff_N, SUBHN_asimddiff_N,
 * RADDHN_asimddiff_N, and RSUBHN_asimddiff_N.  LLVM 21 independently
 * emits the same fixed words and the Q-selected mnemonic suffix. */
static const high_narrow_descriptor descriptors[] = {
    { UINT32_C(0x0e204000), CDISASM_ARM_NAME_ADDHN,
      UINT16_C(6093), "addhn" },
    { UINT32_C(0x0e206000), CDISASM_ARM_NAME_SUBHN,
      UINT16_C(6095), "subhn" },
    { UINT32_C(0x2e204000), CDISASM_ARM_NAME_RADDHN,
      UINT16_C(6108), "raddhn" },
    { UINT32_C(0x2e206000), CDISASM_ARM_NAME_RSUBHN,
      UINT16_C(6110), "rsubhn" }
};

_Static_assert(CDISASM_ARM_NAME_ADDHN == UINT16_C(516),
               "established ADDHN ID changed");
_Static_assert(CDISASM_ARM_NAME_SUBHN == UINT16_C(1689),
               "established SUBHN ID changed");
_Static_assert(CDISASM_ARM_NAME_RADDHN == UINT16_C(1194),
               "established RADDHN ID changed");
_Static_assert(CDISASM_ARM_NAME_RSUBHN == UINT16_C(1294),
               "established RSUBHN ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6110),
               "pinned Advanced SIMD form IDs unavailable");

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

static uint32_t high_narrow_word(
    const high_narrow_descriptor *descriptor,
    unsigned q, unsigned size_code,
    unsigned rm, unsigned rn, unsigned rd)
{
    return descriptor->value | ((uint32_t)q << 30)
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

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_arm_mode mode,
    size_t code_size, cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(cpu_id, mode, bytes, code_size,
        UINT64_C(0x12f000), options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction, cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static int is_target_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6093) || form_id == UINT16_C(6095)
        || form_id == UINT16_C(6108) || form_id == UINT16_C(6110);
}

#if USE_EXTRA_OPCODES
static int vector_matches(
    const cdisasm_arm_operand *operand, unsigned encoded,
    uint8_t total_size, uint8_t element_size,
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

static int metadata_matches(
    const cdisasm_arm_instruction *instruction, uint32_t word,
    const high_narrow_descriptor *descriptor,
    unsigned q, unsigned size_code,
    unsigned rm, unsigned rn, unsigned rd)
{
    uint8_t result_element_size = (uint8_t)(UINT32_C(1) << size_code);
    uint8_t source_element_size = (uint8_t)(result_element_size * 2u);

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == descriptor->name_id
        && instruction->form_id == descriptor->form_id
        && instruction->address == UINT64_C(0x12f000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 3u
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && vector_matches(&instruction->operand[0], rd,
            q != 0u ? 16u : 8u, result_element_size,
            q != 0u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                    : CDISASM_OPERAND_ACCESS_WRITE)
        && vector_matches(&instruction->operand[1], rn,
            16u, source_element_size, CDISASM_OPERAND_ACCESS_READ)
        && vector_matches(&instruction->operand[2], rm,
            16u, source_element_size, CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_exact_envelopes(void)
{
    uint32_t partition_counts[4][2][2] = {{{ 0u }}};
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const high_narrow_descriptor *descriptor =
            &descriptors[descriptor_index];
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
                            uint32_t word = high_narrow_word(
                                descriptor, q, size_code, rm, rn, rd);
                            uint32_t decoded;

                            EXPECT((word & UINT32_C(0xbf20fc00))
                                == descriptor->value);
                            memset(&instruction, 0xa5,
                                sizeof(instruction));
                            decoded = decode_word(word,
                                CDISASM_ARM_CPU_ANY,
                                CDISASM_ARM_MODE_A64, 4u,
                                CDISASM_ARM_DECODE_OPTION_NONE,
                                &instruction);
                            if (size_code == 3u) {
                                ++reserved;
                                ++partition_counts[descriptor_index][q][1];
                                EXPECT(decoded == 0u);
                                EXPECT(instruction_is_error_only(
                                    &instruction,
                                    CDISASM_STATUS_INVALID_INSTRUCTION));
                            } else {
                                ++allocated;
                                ++partition_counts[descriptor_index][q][0];
#if USE_EXTRA_OPCODES
                                EXPECT(decoded == 4u);
                                EXPECT(metadata_matches(
                                    &instruction, word, descriptor,
                                    q, size_code, rm, rn, rd));
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
    for (descriptor_index = 0u; descriptor_index < 4u;
         ++descriptor_index) {
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            EXPECT(partition_counts[descriptor_index][q][0]
                == UINT32_C(98304));
            EXPECT(partition_counts[descriptor_index][q][1]
                == UINT32_C(32768));
        }
    }
    EXPECT(allocated == UINT32_C(786432));
    EXPECT(reserved == UINT32_C(262144));
}

static void expect_cpu_status(
    uint32_t word, cdisasm_arm_cpu_id cpu_id,
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

static void test_profiles_and_fixed_neighbors(void)
{
    static const uint32_t adjacent_values[] = {
        UINT32_C(0x0e203000), /* SSUBW */
        UINT32_C(0x0e205000), /* SABAL */
        UINT32_C(0x0e207000), /* SABDL */
        UINT32_C(0x2e203000), /* USUBW */
        UINT32_C(0x2e205000), /* UABAL */
        UINT32_C(0x2e207000)  /* UABDL */
    };
    size_t descriptor_index;
    size_t neighbor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const high_narrow_descriptor *descriptor =
            &descriptors[descriptor_index];
        uint32_t word = high_narrow_word(
            descriptor, 1u, 2u, 29u, 13u, 7u);
        unsigned bit;

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_A7,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M3,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);

        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((UINT32_C(0xbf20fc00)
                    & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(word ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded != 4u
                || instruction.form_id != descriptor->form_id);
        }
    }

    for (neighbor_index = 0u;
         neighbor_index < sizeof(adjacent_values)
            / sizeof(adjacent_values[0]);
         ++neighbor_index) {
        cdisasm_arm_instruction instruction;
        uint32_t word = adjacent_values[neighbor_index]
            | UINT32_C(0x40000000) | (UINT32_C(2) << 22)
            | (UINT32_C(29) << 16) | (UINT32_C(13) << 5)
            | UINT32_C(7);

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(!is_target_form(instruction.form_id));
    }
}

static void check_transport(uint32_t word, uint32_t reserved)
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
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x12f000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x12f000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_be(reserved, bytes);
    memset(&other, 0xa5, sizeof(other));
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x12f000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_INSTRUCTION));

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12f000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12f000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(
            &other, CDISASM_STATUS_TRUNCATED));
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(
            &other, CDISASM_STATUS_TRUNCATED));
    }
}

static void test_endian_dispatch_modes_and_boundaries(void)
{
    cdisasm_arm_instruction instruction;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        uint32_t word = high_narrow_word(
            &descriptors[descriptor_index], descriptor_index & 1u,
            (unsigned)(descriptor_index % 3u), 29u, 13u, 7u);
        uint32_t reserved = high_narrow_word(
            &descriptors[descriptor_index], descriptor_index & 1u,
            3u, 29u, 13u, 7u);

        check_transport(word, reserved);
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(high_narrow_word(
            &descriptors[0], 1u, 0u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(high_narrow_word(
            &descriptors[1], 1u, 1u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(high_narrow_word(
            &descriptors[2], 0u, 2u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[96];
    char short_text[8];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_7,
        text, sizeof(text)) == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
        NULL, 0u) == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
        short_text, sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void reject_forgery(
    const cdisasm_arm_instruction *instruction, const char *mutation)
{
    char text[96];
    size_t length;

    memset(text, 0xa5, sizeof(text));
    length = cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text));
    if (length != 0u || text[0] != '\0') {
        if (failures < 24) {
            fprintf(stderr, "accepted formatter forgery: %s\n", mutation);
        }
        ++failures;
    }
}

static void test_formatter_and_forgery(void)
{
    static const char result_suffixes[] = { 'b', 'h', 's' };
    static const char source_suffixes[] = { 'h', 's', 'd' };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char expected[96];
    char text[96];
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 0u; size_code < 3u; ++size_code) {
                unsigned result_count = (q != 0u ? 16u : 8u)
                    / (1u << size_code);
                unsigned source_count = 8u >> size_code;
                int length = snprintf(expected, sizeof(expected),
                    "%s%s v7.%u%c, v13.%u%c, v29.%u%c",
                    descriptors[descriptor_index].mnemonic,
                    q != 0u ? "2" : "", result_count,
                    result_suffixes[size_code], source_count,
                    source_suffixes[size_code], source_count,
                    source_suffixes[size_code]);

                EXPECT(length > 0 && (size_t)length < sizeof(expected));
                expect_format(high_narrow_word(
                    &descriptors[descriptor_index], q, size_code,
                    29u, 13u, 7u), expected);
            }
        }
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(high_narrow_word(
            &descriptors[3], 1u, 2u, 29u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction,
        CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("RSUBHN2 v31.4s, v30.2d, v29.2d"));
    EXPECT(strcmp(text, "RSUBHN2 v31.4s, v30.2d, v29.2d") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(6108));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_RADDHN);
    REJECT_MUTATION(forged.raw_instruction = high_narrow_word(
        &descriptors[3], 0u, 2u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = high_narrow_word(
        &descriptors[3], 1u, 3u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0x6e3d6fdf));
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_T32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand_count = 4u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_V30);
    REJECT_MUTATION(forged.operand[0].size = 8u);
    REJECT_MUTATION(forged.operand[0].extend_type =
        (cdisasm_arm_extend_type)2u);
    REJECT_MUTATION(forged.operand[0].scale = 8u);
    REJECT_MUTATION(forged.operand[0].flags =
        CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    REJECT_MUTATION(forged.operand[0].base_reg = CDISASM_ARM_REG_X0);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V29);
    REJECT_MUTATION(forged.operand[1].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[1].size = 8u);
    REJECT_MUTATION(forged.operand[1].extend_type =
        (cdisasm_arm_extend_type)4u);
    REJECT_MUTATION(forged.operand[1].scale = 4u);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_V28);
    REJECT_MUTATION(forged.operand[2].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[2].address = UINT64_C(1));

    /* These mnemonic IDs exist only for the A64 leaves in the pinned
     * catalog.  A name-only mutation of an otherwise valid A32/T32 object
     * must therefore enter this exact schema and be rejected too. */
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0xe2810005), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(!is_target_form(instruction.form_id));
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_ADDHN;
    reject_forgery(&forged, "A32 name-only ADDHN forgery");
    forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    reject_forgery(&forged, "A32 opaque name-only ADDHN forgery");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x00002001), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_T32, 2u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 2u);
    EXPECT(!is_target_form(instruction.form_id));
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_SUBHN;
    reject_forgery(&forged, "T32 name-only SUBHN forgery");

#undef REJECT_MUTATION
}
#else
static void test_formatter_and_forgery(void)
{
}
#endif

int main(void)
{
    test_exhaustive_exact_envelopes();
    test_profiles_and_fixed_neighbors();
    test_endian_dispatch_modes_and_boundaries();
    test_formatter_and_forgery();

    if (failures != 0) {
        fprintf(stderr,
            "%d ARM Advanced SIMD high-narrow test(s) failed\n",
            failures);
        return 1;
    }
    printf("ARM Advanced SIMD ADDHN/SUBHN/RADDHN/RSUBHN tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=786432, reserved=262144)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
