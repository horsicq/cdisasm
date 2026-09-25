#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

typedef struct descriptor {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
    uint8_t accumulate;
} descriptor;

/* Pinned AARCHMRS 2026-03 leaves, independently checked with LLVM 21. */
static const descriptor descriptors[] = {
    { UINT32_C(0x0e209000), CDISASM_ARM_NAME_SQDMLAL,
      UINT16_C(6098), "sqdmlal", 1u },
    { UINT32_C(0x0e20b000), CDISASM_ARM_NAME_SQDMLSL,
      UINT16_C(6100), "sqdmlsl", 1u },
    { UINT32_C(0x0e20d000), CDISASM_ARM_NAME_SQDMULL,
      UINT16_C(6102), "sqdmull", 0u }
};

_Static_assert(CDISASM_ARM_NAME_SQDMLAL == UINT16_C(1475)
                   && CDISASM_ARM_NAME_SQDMLSL == UINT16_C(1479)
                   && CDISASM_ARM_NAME_SQDMULL == UINT16_C(1484),
               "saturating widening-multiply mnemonic IDs changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6102),
               "saturating widening-multiply form IDs unavailable");

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

static uint32_t make_word(const descriptor *desc, unsigned q,
                          unsigned size_code, unsigned rm,
                          unsigned rn, unsigned rd)
{
    return desc->value | ((uint32_t)q << 30)
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
                            cdisasm_arm_mode mode, size_t size,
                            cdisasm_arm_decode_option options,
                            cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(cpu, mode, bytes, size, UINT64_C(0x152000),
                             options, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
                      cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static int target_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6098) || form_id == UINT16_C(6100)
        || form_id == UINT16_C(6102);
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

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            uint32_t word, const descriptor *desc,
                            unsigned q, unsigned size_code,
                            unsigned rm, unsigned rn, unsigned rd)
{
    uint8_t source_element_size = (uint8_t)(UINT32_C(1) << size_code);
    uint8_t result_element_size = (uint8_t)(source_element_size * 2u);
    uint8_t source_size = q != 0u ? 16u : 8u;

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == desc->name_id
        && instruction->form_id == desc->form_id
        && instruction->address == UINT64_C(0x152000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && vector_matches(&instruction->operand[0], rd, 16u,
            result_element_size, desc->accumulate != 0u
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE)
        && vector_matches(&instruction->operand[1], rn, source_size,
            source_element_size, CDISASM_OPERAND_ACCESS_READ)
        && vector_matches(&instruction->operand[2], rm, source_size,
            source_element_size, CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_envelopes(void)
{
    uint32_t partitions[3][2][2] = {{{ 0u }}};
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    size_t descriptor_index;

    for (descriptor_index = 0u; descriptor_index < 3u;
         ++descriptor_index) {
        const descriptor *desc = &descriptors[descriptor_index];
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
                            uint32_t word = make_word(desc, q, size_code,
                                                      rm, rn, rd);
                            uint32_t decoded;
                            int legal = size_code == 1u || size_code == 2u;

                            EXPECT((word & UINT32_C(0xbf20fc00))
                                == desc->value);
                            memset(&instruction, 0xa5, sizeof(instruction));
                            decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
                                CDISASM_ARM_MODE_A64, 4u,
                                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                            ++partitions[descriptor_index][q][legal ? 0 : 1];
                            if (!legal) {
                                ++reserved;
                                EXPECT(decoded == 0u);
                                EXPECT(error_only(&instruction,
                                    CDISASM_STATUS_INVALID_INSTRUCTION));
                            } else {
                                ++allocated;
#if USE_EXTRA_OPCODES
                                EXPECT(decoded == 4u);
                                EXPECT(metadata_matches(&instruction, word,
                                    desc, q, size_code, rm, rn, rd));
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
    for (descriptor_index = 0u; descriptor_index < 3u;
         ++descriptor_index) {
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            EXPECT(partitions[descriptor_index][q][0] == UINT32_C(65536));
            EXPECT(partitions[descriptor_index][q][1] == UINT32_C(65536));
        }
    }
    EXPECT(allocated == UINT32_C(393216));
    EXPECT(reserved == UINT32_C(393216));
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
    static const uint32_t adjacent[] = {
        UINT32_C(0x0e208000), UINT32_C(0x0e20a000),
        UINT32_C(0x0e20c000), UINT32_C(0x0e20e000),
        UINT32_C(0x2e209000), UINT32_C(0x2e20b000),
        UINT32_C(0x2e20d000)
    };
    size_t descriptor_index;
    size_t adjacent_index;

    for (descriptor_index = 0u; descriptor_index < 3u;
         ++descriptor_index) {
        const descriptor *desc = &descriptors[descriptor_index];
        uint32_t word = make_word(desc, 1u, 2u, 29u, 13u, 7u);
        unsigned bit;

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
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

            if ((UINT32_C(0xbf20fc00) & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(word ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded != 4u || instruction.form_id != desc->form_id);
        }
    }

    for (adjacent_index = 0u;
         adjacent_index < sizeof(adjacent) / sizeof(adjacent[0]);
         ++adjacent_index) {
        cdisasm_arm_instruction instruction;
        uint32_t word = adjacent[adjacent_index]
            | UINT32_C(0x40000000) | (UINT32_C(2) << 22)
            | (UINT32_C(29) << 16) | (UINT32_C(13) << 5)
            | UINT32_C(7);

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        EXPECT(!target_form(instruction.form_id));
    }
}

static void check_transport(uint32_t word, uint32_t reserved_byte,
                            uint32_t reserved_size3)
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
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x152000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x152000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x152000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x152000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_be(reserved_byte, bytes);
    memset(&other, 0xa5, sizeof(other));
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x152000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
    EXPECT(error_only(&other, CDISASM_STATUS_INVALID_INSTRUCTION));
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(reserved_size3, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &other) == 0u);
    EXPECT(error_only(&other, CDISASM_STATUS_INVALID_INSTRUCTION));

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(error_only(&other, CDISASM_STATUS_TRUNCATED));
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(reserved_byte, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(error_only(&other, CDISASM_STATUS_TRUNCATED));
    }
}

static void test_transport_and_boundaries(void)
{
    cdisasm_arm_instruction instruction;
    size_t descriptor_index;

    for (descriptor_index = 0u; descriptor_index < 3u;
         ++descriptor_index) {
        const descriptor *desc = &descriptors[descriptor_index];

        check_transport(make_word(desc, descriptor_index & 1u,
                                  1u + (unsigned)(descriptor_index & 1u),
                                  29u, 13u, 7u),
                        make_word(desc, descriptor_index & 1u, 0u,
                                  29u, 13u, 7u),
                        make_word(desc, descriptor_index & 1u, 3u,
                                  29u, 13u, 7u));
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(&descriptors[0], 0u, 1u, 2u, 1u, 0u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(&descriptors[1], 0u, 1u, 2u, 1u, 0u),
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(&descriptors[2], 0u, 2u, 2u, 1u, 0u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
        || !target_form(instruction.form_id));
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

static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[160];
    char short_text[8];
    size_t expected_length = strlen(expected);
    size_t length;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    length = cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text));
    if (length != expected_length || strcmp(text, expected) != 0) {
        fprintf(stderr, "format mismatch %08x: expected '%s', got '%s'\n",
                (unsigned)word, expected, text);
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

static void init_opaque(cdisasm_arm_instruction *instruction,
                        cdisasm_arm_name_id name_id,
                        cdisasm_arm_form_id form_id, uint32_t word)
{
    memset(instruction, 0, sizeof(*instruction));
    instruction->name_id = name_id;
    instruction->form_id = form_id;
    instruction->raw_instruction = word;
    instruction->opcode_size = 4u;
    instruction->isa_id = CDISASM_ARM_ISA_A64;
    instruction->condition = CDISASM_ARM_CONDITION_AL;
    instruction->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
}

static void test_formatter_and_collisions(void)
{
    static const char source_suffix[2] = { 'h', 's' };
    static const char result_suffix[2] = { 's', 'd' };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char expected[128];
    char text[128];
    size_t descriptor_index;

    for (descriptor_index = 0u; descriptor_index < 3u;
         ++descriptor_index) {
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 1u; size_code <= 2u; ++size_code) {
                unsigned source_count = (q != 0u ? 16u : 8u)
                    >> size_code;
                unsigned result_count = 8u >> size_code;
                int length = snprintf(expected, sizeof(expected),
                    "%s%s v7.%u%c, v13.%u%c, v29.%u%c",
                    descriptors[descriptor_index].mnemonic,
                    q != 0u ? "2" : "", result_count,
                    result_suffix[size_code - 1u], source_count,
                    source_suffix[size_code - 1u], source_count,
                    source_suffix[size_code - 1u]);

                EXPECT(length > 0 && (size_t)length < sizeof(expected));
                expect_format(make_word(&descriptors[descriptor_index], q,
                    size_code, 29u, 13u, 7u), expected);
            }
        }
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(&descriptors[2], 1u, 2u,
        29u, 30u, 31u), CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("SQDMULL2 v31.2d, v30.4s, v29.4s"));
    EXPECT(strcmp(text, "SQDMULL2 v31.2d, v30.4s, v29.4s") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(6100));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_SQDMLSL);
    REJECT_MUTATION(forged.raw_instruction = make_word(
        &descriptors[2], 0u, 2u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = make_word(
        &descriptors[2], 1u, 0u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = make_word(
        &descriptors[2], 1u, 3u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd503201f));
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_T32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
    REJECT_MUTATION(forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand[0].type = CDISASM_OPERAND_IMMEDIATE);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_V30);
    REJECT_MUTATION(forged.operand[0].size = 8u);
    REJECT_MUTATION(forged.operand[0].extend_type =
        (cdisasm_arm_extend_type)4u);
    REJECT_MUTATION(forged.operand[0].scale = 4u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V29);
    REJECT_MUTATION(forged.operand[1].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_V28);
    REJECT_MUTATION(forged.operand[2].address = UINT64_C(1));

    /* Raw, fixed-form, and same-name claims independently enter the exact
     * vector validator; none may fall through to a colliding formatter. */
    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_NOP;
    forged.form_id = UINT16_C(6098);
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "fixed-form-only claim");
    forged.form_id = CDISASM_ARM_FORM_NONE;
    forged.raw_instruction = make_word(&descriptors[0], 0u, 1u,
                                       2u, 1u, 0u);
    reject_forgery(&forged, "raw-only claim");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(&descriptors[0], 0u, 1u, 2u, 1u, 0u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    forged = instruction;
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.form_id = CDISASM_ARM_FORM_NONE;
    reject_forgery(&forged, "same-name-only fixed-vector claim");

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_SQDMLAL;
    forged.form_id = UINT16_C(5000);
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    forged.operand_count = 3u;
    forged.operand[0].type = CDISASM_OPERAND_REGISTER;
    forged.operand[0].reg = CDISASM_ARM_REG_X0;
    forged.operand[1].type = CDISASM_OPERAND_REGISTER;
    forged.operand[1].reg = CDISASM_ARM_REG_X1;
    forged.operand[2].type = CDISASM_OPERAND_REGISTER;
    forged.operand[2].reg = CDISASM_ARM_REG_X2;
    reject_forgery(&forged, "arbitrary structured same-name claim");
    forged.isa_id = CDISASM_ARM_ISA_A32;
    reject_forgery(&forged, "A32 same-name claim");
    forged.isa_id = CDISASM_ARM_ISA_T32;
    reject_forgery(&forged, "T32 same-name claim");

    /* Scalar siblings are now exact structured forms; legacy opaque claims
     * must not bypass their operand schema. */
    init_opaque(&instruction, CDISASM_ARM_NAME_SQDMLAL,
                UINT16_C(5819), UINT32_C(0x5e629020));
    reject_forgery(&instruction, "opaque scalar SQDMLAL claim");
    forged = instruction;
    forged.raw_instruction = UINT32_C(0xd503201f);
    reject_forgery(&forged, "scalar sibling raw graft");
    forged = instruction;
    forged.form_id = UINT16_C(6098);
    reject_forgery(&forged, "scalar raw with fixed-vector form");

    init_opaque(&instruction, CDISASM_ARM_NAME_SQDMLSL,
                UINT16_C(5820), UINT32_C(0x5ea5b083));
    reject_forgery(&instruction, "opaque scalar SQDMLSL claim");
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_SQDMLAL;
    reject_forgery(&forged, "scalar sibling cross-name graft");

    init_opaque(&instruction, CDISASM_ARM_NAME_SQDMULL,
                UINT16_C(5821), UINT32_C(0x5e68d0e6));
    reject_forgery(&instruction, "opaque scalar SQDMULL claim");

    init_opaque(&instruction, CDISASM_ARM_NAME_SQDMLAL,
                UINT16_C(6244), UINT32_C(0x0f723020));
    /* The generated table intentionally marks its split Vm concat recipe
     * opaque.  It must remain a safe rejection, never be misformatted as
     * the fixed-vector form introduced by this tranche. */
    reject_forgery(&instruction, "opaque vector by-element sibling");
    forged = instruction;
    forged.raw_instruction = make_word(&descriptors[0], 0u, 1u,
                                       2u, 1u, 0u);
    reject_forgery(&forged, "by-element form with fixed-vector raw");

    init_opaque(&instruction, CDISASM_ARM_NAME_SQDMULL,
                UINT16_C(6249), UINT32_C(0x0f68b0e6));
    reject_forgery(&instruction, "opaque vector by-element MULL sibling");

    init_opaque(&instruction, CDISASM_ARM_NAME_SQDMLAL,
                UINT16_C(5877), UINT32_C(0x5f723020));
    reject_forgery(&instruction, "opaque scalar by-element sibling");

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
        fprintf(stderr, "%d saturating widening-multiply test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM Advanced SIMD SQDMLAL/SQDMLSL/SQDMULL tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=393216, reserved=393216)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
