#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

typedef struct widening_multiply_descriptor {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
    uint8_t accumulate;
} widening_multiply_descriptor;

/* Pinned AARCHMRS *_asimddiff_L leaves.  LLVM 21 independently emits the
 * same fixed words, arrangements, and Q-selected mnemonic suffix. */
static const widening_multiply_descriptor descriptors[] = {
    { UINT32_C(0x0e208000), CDISASM_ARM_NAME_SMLAL,
      UINT16_C(6097), "smlal", 1u },
    { UINT32_C(0x0e20a000), CDISASM_ARM_NAME_SMLSL,
      UINT16_C(6099), "smlsl", 1u },
    { UINT32_C(0x0e20c000), CDISASM_ARM_NAME_SMULL,
      UINT16_C(6101), "smull", 0u },
    { UINT32_C(0x2e208000), CDISASM_ARM_NAME_UMLAL,
      UINT16_C(6112), "umlal", 1u },
    { UINT32_C(0x2e20a000), CDISASM_ARM_NAME_UMLSL,
      UINT16_C(6113), "umlsl", 1u },
    { UINT32_C(0x2e20c000), CDISASM_ARM_NAME_UMULL,
      UINT16_C(6114), "umull", 0u }
};

_Static_assert(CDISASM_ARM_NAME_SMLAL == UINT16_C(1414)
                   && CDISASM_ARM_NAME_SMLSL == UINT16_C(1431)
                   && CDISASM_ARM_NAME_SMULL == UINT16_C(1453)
                   && CDISASM_ARM_NAME_UMLAL == UINT16_C(1771)
                   && CDISASM_ARM_NAME_UMLSL == UINT16_C(1776)
                   && CDISASM_ARM_NAME_UMULL == UINT16_C(1787),
               "established widening-multiply mnemonic IDs changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6114),
               "pinned widening-multiply form IDs unavailable");

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

static uint32_t widening_multiply_word(
    const widening_multiply_descriptor *descriptor,
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
        UINT64_C(0x141000), options, instruction);
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
    return form_id == UINT16_C(6097) || form_id == UINT16_C(6099)
        || form_id == UINT16_C(6101) || form_id == UINT16_C(6112)
        || form_id == UINT16_C(6113) || form_id == UINT16_C(6114);
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
    const widening_multiply_descriptor *descriptor,
    unsigned q, unsigned size_code,
    unsigned rm, unsigned rn, unsigned rd)
{
    uint8_t source_element_size = (uint8_t)(UINT32_C(1) << size_code);
    uint8_t result_element_size = (uint8_t)(source_element_size * 2u);
    uint8_t narrow_total_size = q != 0u ? 16u : 8u;

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == descriptor->name_id
        && instruction->form_id == descriptor->form_id
        && instruction->address == UINT64_C(0x141000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && vector_matches(&instruction->operand[0], rd,
            16u, result_element_size,
            descriptor->accumulate != 0u
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE)
        && vector_matches(&instruction->operand[1], rn,
            narrow_total_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && vector_matches(&instruction->operand[2], rm,
            narrow_total_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_exact_envelopes(void)
{
    uint32_t partition_counts[6][2][2] = {{{ 0u }}};
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const widening_multiply_descriptor *descriptor =
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
                            uint32_t word = widening_multiply_word(
                                descriptor, q, size_code, rm, rn, rd);
                            uint32_t decoded;

                            EXPECT((word & UINT32_C(0xbf20fc00))
                                == descriptor->value);
                            memset(&instruction, 0xa5, sizeof(instruction));
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
    for (descriptor_index = 0u; descriptor_index < 6u;
         ++descriptor_index) {
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            EXPECT(partition_counts[descriptor_index][q][0]
                == UINT32_C(98304));
            EXPECT(partition_counts[descriptor_index][q][1]
                == UINT32_C(32768));
        }
    }
    EXPECT(allocated == UINT32_C(1179648));
    EXPECT(reserved == UINT32_C(393216));
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
        UINT32_C(0x0e207000), /* SABDL */
        UINT32_C(0x0e209000), /* SQDMLAL */
        UINT32_C(0x0e20b000), /* SQDMLSL */
        UINT32_C(0x0e20d000), /* SQDMULL */
        UINT32_C(0x0e20e000), /* PMULL */
        UINT32_C(0x2e207000)  /* UABDL */
    };
    size_t descriptor_index;
    size_t neighbor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const widening_multiply_descriptor *descriptor =
            &descriptors[descriptor_index];
        uint32_t word = widening_multiply_word(
            descriptor, 1u, 2u, 29u, 13u, 7u);
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

            if ((UINT32_C(0xbf20fc00)
                    & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            (void)decode_word(word ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(instruction.form_id != descriptor->form_id);
        }
    }

    for (neighbor_index = 0u;
         neighbor_index < sizeof(adjacent_values)
            / sizeof(adjacent_values[0]);
         ++neighbor_index) {
        cdisasm_arm_instruction instruction;
        uint32_t word = adjacent_values[neighbor_index]
            | UINT32_C(0x40000000) | (UINT32_C(1) << 22)
            | (UINT32_C(29) << 16) | (UINT32_C(13) << 5)
            | UINT32_C(7);

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(!is_target_form(instruction.form_id));
    }
}

static void test_transport_modes_and_boundaries(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        cdisasm_arm_instruction little;
        cdisasm_arm_instruction other;
        uint8_t bytes[4];
        uint32_t word = widening_multiply_word(
            &descriptors[descriptor_index], descriptor_index & 1u,
            (unsigned)(descriptor_index % 3u), 29u, 13u, 7u);
        uint32_t reserved = widening_multiply_word(
            &descriptors[descriptor_index], descriptor_index & 1u,
            3u, 29u, 13u, 7u);
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
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes),
            UINT64_C(0x141000), CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
            &other) == 4u);
#else
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes),
            UINT64_C(0x141000), CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
            &other) == 0u);
#endif
        EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

        word_to_be(reserved, bytes);
        memset(&other, 0xa5, sizeof(other));
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes),
            UINT64_C(0x141000), CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
            &other) == 0u);
        EXPECT(instruction_is_error_only(
            &other, CDISASM_STATUS_INVALID_INSTRUCTION));

        for (boundary = 1u; boundary < 4u; ++boundary) {
            memset(&other, 0xa5, sizeof(other));
            EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, boundary,
                CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
            EXPECT(instruction_is_error_only(
                &other, CDISASM_STATUS_TRUNCATED));
        }
    }

    {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(widening_multiply_word(
                &descriptors[0], 0u, 0u, 2u, 1u, 0u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            UINT64_C(1) << 63, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_ARGUMENT));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(widening_multiply_word(
                &descriptors[1], 0u, 1u, 2u, 1u, 0u),
            CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void reject_forgery(
    const cdisasm_arm_instruction *instruction, const char *mutation)
{
    char text[128];
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

static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[128];
    char short_text[8];
    size_t expected_length = strlen(expected);
    size_t actual_length;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    actual_length = cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_7, text, sizeof(text));
    if (actual_length != expected_length || strcmp(text, expected) != 0) {
        fprintf(stderr, "format mismatch %08x: expected '%s', got '%s'\n",
            (unsigned)word, expected, text);
    }
    EXPECT(actual_length == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
        NULL, 0u) == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
        short_text, sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void expect_generated_collision_formats(
    cdisasm_arm_instruction *instruction, const char *prefix)
{
    char text[160];
    size_t length = cdisasm_arm_format(instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text));

    if (length == 0u) {
        fprintf(stderr,
            "generated collision format rejected: prefix=%s name=%u form=%u raw=%08x\n",
            prefix, (unsigned)instruction->name_id,
            (unsigned)instruction->form_id,
            (unsigned)instruction->raw_instruction);
    }
    EXPECT(length != 0u);
    EXPECT(strncmp(text, prefix, strlen(prefix)) == 0);
}

static void test_formatter_and_collisions(void)
{
    static const char source_suffixes[] = { 'b', 'h', 's' };
    static const char result_suffixes[] = { 'h', 's', 'd' };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char expected[128];
    char text[128];
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 0u; size_code < 3u; ++size_code) {
                unsigned wide_count = 8u >> size_code;
                unsigned narrow_count = (q != 0u ? 16u : 8u)
                    >> size_code;
                int length = snprintf(expected, sizeof(expected),
                    "%s%s v7.%u%c, v13.%u%c, v29.%u%c",
                    descriptors[descriptor_index].mnemonic,
                    q != 0u ? "2" : "", wide_count,
                    result_suffixes[size_code], narrow_count,
                    source_suffixes[size_code], narrow_count,
                    source_suffixes[size_code]);

                EXPECT(length > 0 && (size_t)length < sizeof(expected));
                expect_format(widening_multiply_word(
                    &descriptors[descriptor_index], q, size_code,
                    29u, 13u, 7u), expected);
            }
        }
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(widening_multiply_word(
            &descriptors[5], 1u, 2u, 29u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("UMULL2 v31.2d, v30.4s, v29.4s"));
    EXPECT(strcmp(text, "UMULL2 v31.2d, v30.4s, v29.4s") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(6113));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_UMLSL);
    REJECT_MUTATION(forged.raw_instruction = widening_multiply_word(
        &descriptors[5], 0u, 2u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = widening_multiply_word(
        &descriptors[5], 1u, 3u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0x6ebd43df));
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_T32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
    REJECT_MUTATION(forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_V30);
    REJECT_MUTATION(forged.operand[0].size = 8u);
    REJECT_MUTATION(forged.operand[0].extend_type =
        (cdisasm_arm_extend_type)4u);
    REJECT_MUTATION(forged.operand[0].scale = 4u);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V29);
    REJECT_MUTATION(forged.operand[1].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_V28);
    REJECT_MUTATION(forged.operand[2].address = UINT64_C(1));

    /* Raw, form, and name-only A64 fixed-vector claims are independent. */
    memset(&forged, 0, sizeof(forged));
    forged.last_error_id = CDISASM_STATUS_OK;
    forged.name_id = CDISASM_ARM_NAME_NOP;
    forged.form_id = UINT16_C(6097);
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "form-only widening-multiply claim");

    forged.form_id = CDISASM_ARM_FORM_NONE;
    forged.raw_instruction = widening_multiply_word(
        &descriptors[0], 0u, 0u, 2u, 1u, 0u);
    reject_forgery(&forged, "raw-only widening-multiply claim");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(widening_multiply_word(
            &descriptors[0], 0u, 0u, 2u, 1u, 0u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    forged = instruction;
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.form_id = CDISASM_ARM_FORM_NONE;
    reject_forgery(&forged, "name-only fixed-vector SMLAL claim");

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_SMLAL;
    forged.form_id = UINT16_C(5000);
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    forged.operand_count = 3u;
    forged.operand[0].type = CDISASM_OPERAND_REGISTER;
    forged.operand[0].reg = CDISASM_ARM_REG_X0;
    forged.operand[0].size = 8u;
    forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    forged.operand[1].type = CDISASM_OPERAND_REGISTER;
    forged.operand[1].reg = CDISASM_ARM_REG_X1;
    forged.operand[1].size = 8u;
    forged.operand[1].access = CDISASM_OPERAND_ACCESS_READ;
    forged.operand[2].type = CDISASM_OPERAND_REGISTER;
    forged.operand[2].reg = CDISASM_ARM_REG_X2;
    forged.operand[2].size = 8u;
    forged.operand[2].access = CDISASM_OPERAND_ACCESS_READ;
    reject_forgery(&forged, "arbitrary A64 GPR-shaped SMLAL claim");

    /* Genuine same-name A32/T32 forms keep their generated formatter path.
     * Borrowing an A64 vector form ID remains rejected across ISA spaces. */
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0xe0e10392), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == strlen("smlal r0, r1, r2, r3"));
    EXPECT(strcmp(text, "smlal r0, r1, r2, r3") == 0);
    forged = instruction;
    forged.form_id = UINT16_C(6097);
    reject_forgery(&forged, "A32 object borrowing A64 vector form");
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_UMLSL;
    reject_forgery(&forged, "A32 cross-name collision");
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_ADD;
    reject_forgery(&forged, "A32 nonfamily-name form graft");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x00e10392), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SMLAL);
    EXPECT(instruction.form_id == UINT16_C(62));
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_EQ);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_CONDITIONAL);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == strlen("smlaleq r0, r1, r2, r3"));
    EXPECT(strcmp(text, "smlaleq r0, r1, r2, r3") == 0);
    forged = instruction;
    forged.raw_instruction = UINT32_C(0xf0e10392);
    forged.condition = CDISASM_ARM_CONDITION_NV;
    forged.opcode_groups = CDISASM_GROUP_NONE;
    reject_forgery(&forged, "A32 NV legacy envelope");
    memset(&forged, 0xa5, sizeof(forged));
    EXPECT(decode_word(UINT32_C(0xf0e10392), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &forged) == 0u);
    EXPECT(instruction_is_error_only(
        &forged, CDISASM_STATUS_INVALID_INSTRUCTION));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x0103fbc2), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == strlen("smlal r0, r1, r2, r3"));
    EXPECT(strcmp(text, "smlal r0, r1, r2, r3") == 0);
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_ADD;
    reject_forgery(&forged, "T32 nonfamily-name form graft");

    /* These generated objects exercise other A64 identities sharing SMULL.
     * They are intentionally not baseline SIMD candidates. */
    memset(&instruction, 0, sizeof(instruction));
    instruction.name_id = CDISASM_ARM_NAME_SMULL;
    instruction.form_id = UINT16_C(5719);
    instruction.raw_instruction = UINT32_C(0x9b227c20);
    instruction.opcode_size = 4u;
    instruction.isa_id = CDISASM_ARM_ISA_A64;
    instruction.condition = CDISASM_ARM_CONDITION_AL;
    instruction.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    expect_generated_collision_formats(&instruction, "smull ");
    forged = instruction;
    forged.raw_instruction = UINT32_C(0xd503201f);
    reject_forgery(&forged, "generated SMULL alias with mismatched raw");

    instruction.name_id = CDISASM_ARM_NAME_UMULL;
    instruction.form_id = UINT16_C(5724);
    instruction.raw_instruction = UINT32_C(0x9ba57c83);
    expect_generated_collision_formats(&instruction, "umull ");
    forged = instruction;
    forged.raw_instruction = UINT32_C(0xd503201f);
    reject_forgery(&forged, "generated UMULL alias with mismatched raw");

    /* The generated formatter itself applies the same identity guard to
     * unrelated opaque forms, not only to this shared-name family. */
    memset(&instruction, 0, sizeof(instruction));
    instruction.name_id = CDISASM_ARM_NAME_SMOPA;
    instruction.form_id = UINT16_C(3800);
    instruction.raw_instruction = UINT32_C(0xa0800000);
    instruction.opcode_size = 4u;
    instruction.isa_id = CDISASM_ARM_ISA_A64;
    instruction.condition = CDISASM_ARM_CONDITION_AL;
    instruction.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    expect_generated_collision_formats(&instruction, "smopa ");
    forged = instruction;
    forged.raw_instruction = UINT32_C(0xd503201f);
    reject_forgery(&forged, "generic generated form with mismatched raw");

    /* Forms 124 and 125 overlap in their resolved masks; their generated
     * leaf conditions split RRX from the general shifted-register form. */
    memset(&instruction, 0, sizeof(instruction));
    instruction.name_id = CDISASM_ARM_NAME_AND;
    instruction.form_id = UINT16_C(124);
    instruction.raw_instruction = UINT32_C(0xe0040065);
    instruction.opcode_size = 4u;
    instruction.isa_id = CDISASM_ARM_ISA_A32;
    instruction.condition = CDISASM_ARM_CONDITION_AL;
    instruction.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    expect_generated_collision_formats(&instruction, "and ");
    forged = instruction;
    forged.form_id = UINT16_C(125);
    reject_forgery(&forged, "generated form with false leaf condition");

    /* The broad HINT leaf shares NOP's raw mask but loses to the prioritized
     * NOP leaf in canonical generated-tree traversal. */
    memset(&instruction, 0, sizeof(instruction));
    instruction.name_id = CDISASM_ARM_NAME_NOP;
    instruction.form_id = UINT16_C(4459);
    instruction.raw_instruction = UINT32_C(0xd503201f);
    instruction.opcode_size = 4u;
    instruction.isa_id = CDISASM_ARM_ISA_A64;
    instruction.condition = CDISASM_ARM_CONDITION_AL;
    instruction.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    expect_generated_collision_formats(&instruction, "nop");
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_HINT;
    forged.form_id = UINT16_C(4491);
    reject_forgery(&forged, "generated broad leaf shadowed by NOP");

#undef REJECT_MUTATION
}
#else
static void test_formatter_and_collisions(void)
{
}
#endif

int main(void)
{
    test_exhaustive_exact_envelopes();
    test_profiles_and_fixed_neighbors();
    test_transport_modes_and_boundaries();
    test_formatter_and_collisions();

    if (failures != 0) {
        fprintf(stderr,
            "%d ARM Advanced SIMD widening-multiply test(s) failed\n",
            failures);
        return 1;
    }
    printf("ARM Advanced SIMD SMLAL/SMLSL/SMULL/UMLAL/UMLSL/UMULL "
           "tests passed (USE_EXTRA_OPCODES=%d, allocated=1179648, "
           "reserved=393216)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
