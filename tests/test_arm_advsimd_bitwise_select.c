#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

typedef struct bitwise_select_descriptor {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
} bitwise_select_descriptor;

/* Pinned open AARCHMRS forms BSL_asimdsame_only, BIT_asimdsame_only, and
 * BIF_asimdsame_only.  LLVM 21 independently emits the same fixed leaves. */
static const bitwise_select_descriptor descriptors[] = {
    { UINT32_C(0x2e601c00), CDISASM_ARM_NAME_BSL,
      UINT16_C(6188), "bsl" },
    { UINT32_C(0x2ea01c00), CDISASM_ARM_NAME_BIT,
      UINT16_C(6196), "bit" },
    { UINT32_C(0x2ee01c00), CDISASM_ARM_NAME_BIF,
      UINT16_C(6198), "bif" }
};

_Static_assert(CDISASM_ARM_NAME_BSL == UINT16_C(624),
               "established BSL ID changed");
_Static_assert(CDISASM_ARM_NAME_BIT == UINT16_C(602),
               "established BIT ID changed");
_Static_assert(CDISASM_ARM_NAME_BIF == UINT16_C(601),
               "established BIF ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6198),
               "pinned Advanced SIMD form IDs unavailable");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2328),
               "pinned SVE BSL form ID unavailable");

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

static uint32_t bitwise_select_word(
    const bitwise_select_descriptor *descriptor,
    unsigned q, unsigned rm, unsigned rn, unsigned rd)
{
    return descriptor->value | ((uint32_t)q << 30)
        | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
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
        UINT64_C(0x12e000), options, instruction);
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
    return form_id == UINT16_C(6188) || form_id == UINT16_C(6196)
        || form_id == UINT16_C(6198);
}

#if USE_EXTRA_OPCODES
static int vector_matches(
    const cdisasm_arm_operand *operand, unsigned encoded,
    uint8_t total_size, cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded);
    expected.size = total_size;
    expected.extend_type = (cdisasm_arm_extend_type)1u;
    expected.scale = total_size;
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_matches(
    const cdisasm_arm_instruction *instruction, uint32_t word,
    const bitwise_select_descriptor *descriptor,
    unsigned q, unsigned rm, unsigned rn, unsigned rd)
{
    uint8_t total_size = q != 0u ? 16u : 8u;

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == descriptor->name_id
        && instruction->form_id == descriptor->form_id
        && instruction->address == UINT64_C(0x12e000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 3u
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && vector_matches(&instruction->operand[0], rd, total_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && vector_matches(&instruction->operand[1], rn, total_size,
            CDISASM_OPERAND_ACCESS_READ)
        && vector_matches(&instruction->operand[2], rm, total_size,
            CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_exact_leaves(void)
{
    uint32_t partition_counts[3][2] = { { 0u, 0u }, { 0u, 0u },
                                        { 0u, 0u } };
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const bitwise_select_descriptor *descriptor =
            &descriptors[descriptor_index];
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned rm;

            for (rm = 0u; rm < 32u; ++rm) {
                unsigned rn;

                for (rn = 0u; rn < 32u; ++rn) {
                    unsigned rd;

                    for (rd = 0u; rd < 32u; ++rd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = bitwise_select_word(
                            descriptor, q, rm, rn, rd);
                        uint32_t decoded;

                        EXPECT((word & UINT32_C(0xbfe0fc00))
                            == descriptor->value);
                        memset(&instruction, 0xa5,
                            sizeof(instruction));
                        decoded = decode_word(word,
                            CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE,
                            &instruction);
                        ++allocated;
                        ++partition_counts[descriptor_index][q];
#if USE_EXTRA_OPCODES
                        EXPECT(decoded == 4u);
                        EXPECT(metadata_matches(
                            &instruction, word, descriptor,
                            q, rm, rn, rd));
#else
                        EXPECT(decoded == 0u);
                        EXPECT(instruction_is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    }
                }
            }
        }
    }
    for (descriptor_index = 0u; descriptor_index < 3u;
         ++descriptor_index) {
        EXPECT(partition_counts[descriptor_index][0] == UINT32_C(32768));
        EXPECT(partition_counts[descriptor_index][1] == UINT32_C(32768));
    }
    EXPECT(allocated == UINT32_C(196608));
    EXPECT(reserved == UINT32_C(0));
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
        UINT32_C(0x0e201c00), /* AND */
        UINT32_C(0x0e601c00), /* BIC */
        UINT32_C(0x0ea01c00), /* ORR */
        UINT32_C(0x0ee01c00), /* ORN */
        UINT32_C(0x2e201c00)  /* EOR */
    };
    size_t descriptor_index;
    size_t neighbor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const bitwise_select_descriptor *descriptor =
            &descriptors[descriptor_index];
        uint32_t word = bitwise_select_word(
            descriptor, 1u, 29u, 13u, 7u);
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

            if ((UINT32_C(0xbfe0fc00)
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
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            cdisasm_arm_instruction instruction;
            uint32_t word = adjacent_values[neighbor_index]
                | ((uint32_t)q << 30) | (UINT32_C(29) << 16)
                | (UINT32_C(13) << 5) | UINT32_C(7);

            memset(&instruction, 0xa5, sizeof(instruction));
            (void)decode_word(word, CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(!is_target_form(instruction.form_id));
        }
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
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x12e000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x12e000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12e000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12e000),
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
    }
}

static void test_endian_dispatch_modes_and_boundaries(void)
{
    cdisasm_arm_instruction instruction;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        check_transport(bitwise_select_word(
            &descriptors[descriptor_index], descriptor_index & 1u,
            29u, 13u, 7u));
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(bitwise_select_word(
            &descriptors[0], 1u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(bitwise_select_word(
            &descriptors[1], 1u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(bitwise_select_word(
            &descriptors[2], 1u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_CORTEX_A9, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(bitwise_select_word(
            &descriptors[0], 1u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(bitwise_select_word(
            &descriptors[0], 1u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_T32, 4u,
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
            int length = snprintf(expected, sizeof(expected),
                "%s v7.%ub, v13.%ub, v29.%ub",
                descriptors[descriptor_index].mnemonic,
                q != 0u ? 16u : 8u, q != 0u ? 16u : 8u,
                q != 0u ? 16u : 8u);

            EXPECT(length > 0 && (size_t)length < sizeof(expected));
            expect_format(bitwise_select_word(
                &descriptors[descriptor_index], q, 29u, 13u, 7u),
                expected);
        }
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(bitwise_select_word(
            &descriptors[2], 1u, 29u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction,
        CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("BIF v31.16b, v30.16b, v29.16b"));
    EXPECT(strcmp(text, "BIF v31.16b, v30.16b, v29.16b") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(6196));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_BIT);
    REJECT_MUTATION(forged.raw_instruction = bitwise_select_word(
        &descriptors[1], 1u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0x6e3d1fdf));
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
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
        CDISASM_ARM_EXTEND_NONE);
    REJECT_MUTATION(forged.operand[0].scale = 8u);
    REJECT_MUTATION(forged.operand[0].flags =
        CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    REJECT_MUTATION(forged.operand[0].base_reg = CDISASM_ARM_REG_X0);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V29);
    REJECT_MUTATION(forged.operand[1].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[1].size = 8u);
    REJECT_MUTATION(forged.operand[1].extend_type =
        (cdisasm_arm_extend_type)2u);
    REJECT_MUTATION(forged.operand[1].scale = 8u);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_V28);
    REJECT_MUTATION(forged.operand[2].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[2].address = UINT64_C(1));

    /* BSL is also the mnemonic of generated SVE2/SME form 2328.  Its exact
     * scalable-vector schema must not be captured by the AdvSIMD validator. */
    {
        static const uint8_t big_endian_bytes[4] = {
            UINT8_C(0x04), UINT8_C(0x26), UINT8_C(0x3f), UINT8_C(0x09)
        };
        const uint32_t sve_word = UINT32_C(0x04263f09);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, big_endian_bytes,
            sizeof(big_endian_bytes), UINT64_C(0x12e000),
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &instruction) == 4u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.raw_instruction == sve_word);
        EXPECT(instruction.form_id == UINT16_C(2328));
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_BSL);
        EXPECT(instruction.isa_id == CDISASM_ARM_ISA_A64);
        EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
        EXPECT(instruction.opcode_groups == CDISASM_GROUP_NONE);
        EXPECT(instruction.instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR));
        EXPECT(instruction.operand_count == 4u);
        EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_Z9);
        EXPECT(instruction.operand[0].extend_type
            == (cdisasm_arm_extend_type)8u);
        EXPECT(instruction.operand[0].access
            == CDISASM_OPERAND_ACCESS_READ_WRITE);
        EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_Z9);
        EXPECT(instruction.operand[1].extend_type
            == (cdisasm_arm_extend_type)8u);
        EXPECT(instruction.operand[1].access
            == CDISASM_OPERAND_ACCESS_READ_WRITE);
        EXPECT(instruction.operand[2].reg == CDISASM_ARM_REG_Z6);
        EXPECT(instruction.operand[2].extend_type
            == (cdisasm_arm_extend_type)8u);
        EXPECT(instruction.operand[2].access
            == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.operand[3].reg == CDISASM_ARM_REG_Z24);
        EXPECT(instruction.operand[3].extend_type
            == (cdisasm_arm_extend_type)8u);
        EXPECT(instruction.operand[3].access
            == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text))
            == strlen("bsl z9.d, z9.d, z6.d, z24.d"));
        EXPECT(strcmp(text, "bsl z9.d, z9.d, z6.d, z24.d") == 0);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text))
            == strlen("BSL z9.d, z9.d, z6.d, z24.d"));
        EXPECT(strcmp(text, "BSL z9.d, z9.d, z6.d, z24.d") == 0);

        REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(1) << 10);
        REJECT_MUTATION(forged.form_id = UINT16_C(6188));
        REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_BIT);
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
        REJECT_MUTATION(forged.instruction_flags
            &= ~CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK);
        REJECT_MUTATION(forged.instruction_flags
            |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
        REJECT_MUTATION(forged.operand_count = 3u);
        REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_Z8);
        REJECT_MUTATION(forged.operand[0].access
            = CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_Z8);
        REJECT_MUTATION(forged.operand[1].access
            = CDISASM_OPERAND_ACCESS_READ);
        REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_Z7);
        REJECT_MUTATION(forged.operand[2].extend_type
            = (cdisasm_arm_extend_type)4u);
        REJECT_MUTATION(forged.operand[3].reg = CDISASM_ARM_REG_Z23);
        REJECT_MUTATION(forged.operand[3].shift_type
            = CDISASM_ARM_SHIFT_LSL);
        REJECT_MUTATION(forged.operand[3].scale = 1u);
    }

#undef REJECT_MUTATION
}
#else
static void test_formatter_and_forgery(void)
{
}
#endif

int main(void)
{
    test_exhaustive_exact_leaves();
    test_profiles_and_fixed_neighbors();
    test_endian_dispatch_modes_and_boundaries();
    test_formatter_and_forgery();

    if (failures != 0) {
        fprintf(stderr,
            "%d ARM Advanced SIMD BSL/BIT/BIF test(s) failed\n",
            failures);
        return 1;
    }
    printf("ARM Advanced SIMD BSL/BIT/BIF tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=196608, reserved=0)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
