#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define PAUTH_BRANCH_PARENT_MASK UINT32_C(0xfedff800)
#define PAUTH_BRANCH_PARENT_VALUE UINT32_C(0xd61f0800)
#define TEST_ADDRESS UINT64_C(0x17a000)

typedef struct pauth_branch_descriptor {
    uint32_t mask;
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *text;
} pauth_branch_descriptor;

/* Pinned AARCHMRS branch_reg leaves at commit
 * 47b5446cf08ef6a46c86147c7deb0d56caf99d93.  LLVM 21 independently
 * confirms the encodings, XZR target spelling, and SP modifier spelling. */
static const pauth_branch_descriptor descriptors[] = {
    { UINT32_C(0xfffffc1f), UINT32_C(0xd61f081f),
      CDISASM_ARM_NAME_BRAAZ, UINT16_C(4510), "braaz x7" },
    { UINT32_C(0xfffffc1f), UINT32_C(0xd61f0c1f),
      CDISASM_ARM_NAME_BRABZ, UINT16_C(4511), "brabz x7" },
    { UINT32_C(0xfffffc1f), UINT32_C(0xd63f081f),
      CDISASM_ARM_NAME_BLRAAZ, UINT16_C(4513), "blraaz x7" },
    { UINT32_C(0xfffffc1f), UINT32_C(0xd63f0c1f),
      CDISASM_ARM_NAME_BLRABZ, UINT16_C(4514), "blrabz x7" },
    { UINT32_C(0xfffffc00), UINT32_C(0xd71f0800),
      CDISASM_ARM_NAME_BRAA, UINT16_C(4525), "braa x7, x13" },
    { UINT32_C(0xfffffc00), UINT32_C(0xd71f0c00),
      CDISASM_ARM_NAME_BRAB, UINT16_C(4526), "brab x7, x13" },
    { UINT32_C(0xfffffc00), UINT32_C(0xd73f0800),
      CDISASM_ARM_NAME_BLRAA, UINT16_C(4527), "blraa x7, x13" },
    { UINT32_C(0xfffffc00), UINT32_C(0xd73f0c00),
      CDISASM_ARM_NAME_BLRAB, UINT16_C(4528), "blrab x7, x13" }
};

_Static_assert(CDISASM_ARM_NAME_BLRAA == UINT16_C(603)
                   && CDISASM_ARM_NAME_BLRAAZ == UINT16_C(604)
                   && CDISASM_ARM_NAME_BLRAB == UINT16_C(605)
                   && CDISASM_ARM_NAME_BLRABZ == UINT16_C(606),
               "authenticated link-branch mnemonic IDs changed");
_Static_assert(CDISASM_ARM_NAME_BRAA == UINT16_C(609)
                   && CDISASM_ARM_NAME_BRAAZ == UINT16_C(610)
                   && CDISASM_ARM_NAME_BRAB == UINT16_C(611)
                   && CDISASM_ARM_NAME_BRABZ == UINT16_C(612),
               "authenticated branch mnemonic IDs changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(4528),
               "pinned authenticated branch form IDs unavailable");

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

static uint32_t pauth_branch_word(
    unsigned link, unsigned key_b, unsigned explicit_modifier,
    unsigned rn, unsigned rm)
{
    return PAUTH_BRANCH_PARENT_VALUE | ((uint32_t)link << 21)
        | ((uint32_t)key_b << 10)
        | ((uint32_t)explicit_modifier << 24)
        | ((uint32_t)rn << 5) | (uint32_t)rm;
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
        TEST_ADDRESS, options, instruction);
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
    return form_id == UINT16_C(4510) || form_id == UINT16_C(4511)
        || form_id == UINT16_C(4513) || form_id == UINT16_C(4514)
        || form_id == UINT16_C(4525) || form_id == UINT16_C(4526)
        || form_id == UINT16_C(4527) || form_id == UINT16_C(4528);
}

static int is_target_name(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_BRAAZ
        || name_id == CDISASM_ARM_NAME_BRABZ
        || name_id == CDISASM_ARM_NAME_BLRAAZ
        || name_id == CDISASM_ARM_NAME_BLRABZ
        || name_id == CDISASM_ARM_NAME_BRAA
        || name_id == CDISASM_ARM_NAME_BRAB
        || name_id == CDISASM_ARM_NAME_BLRAA
        || name_id == CDISASM_ARM_NAME_BLRAB;
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_reg_id expected_xreg(unsigned encoded, int use_sp)
{
    if (encoded == 31u) {
        return use_sp ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_XZR;
    }
    return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded);
}

static int register_matches(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = reg;
    expected.size = 8u;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_matches(
    const cdisasm_arm_instruction *instruction, uint32_t word,
    unsigned link, unsigned key_b, unsigned explicit_modifier,
    unsigned rn, unsigned rm)
{
    static const cdisasm_arm_name_id names[2][2][2] = {
        {
            { CDISASM_ARM_NAME_BRAAZ, CDISASM_ARM_NAME_BRAA },
            { CDISASM_ARM_NAME_BRABZ, CDISASM_ARM_NAME_BRAB }
        },
        {
            { CDISASM_ARM_NAME_BLRAAZ, CDISASM_ARM_NAME_BLRAA },
            { CDISASM_ARM_NAME_BLRABZ, CDISASM_ARM_NAME_BLRAB }
        }
    };
    static const cdisasm_arm_form_id forms[2][2][2] = {
        {
            { UINT16_C(4510), UINT16_C(4525) },
            { UINT16_C(4511), UINT16_C(4526) }
        },
        {
            { UINT16_C(4513), UINT16_C(4527) },
            { UINT16_C(4514), UINT16_C(4528) }
        }
    };

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->address == TEST_ADDRESS
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == names[link][key_b][explicit_modifier]
        && instruction->form_id == forms[link][key_b][explicit_modifier]
        && instruction->operand_count
            == (explicit_modifier != 0u ? 2u : 1u)
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->opcode_groups
            == (link != 0u ? CDISASM_GROUP_CALL : CDISASM_GROUP_JUMP)
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_POINTER_AUTH
                | (link != 0u ? CDISASM_ARM_INSTRUCTION_FLAG_LINK : 0u))
        && instruction->branch_target == 0u
        && register_matches(
            &instruction->operand[0], expected_xreg(rn, 0))
        && (explicit_modifier == 0u
            || register_matches(
                &instruction->operand[1], expected_xreg(rm, 1)));
}
#endif

static void test_exhaustive_parent_envelope(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    uint32_t partition[2][2][2] = {{{ 0u }}};
    unsigned link;

    for (link = 0u; link < 2u; ++link) {
        unsigned key_b;

        for (key_b = 0u; key_b < 2u; ++key_b) {
            unsigned explicit_modifier;

            for (explicit_modifier = 0u;
                 explicit_modifier < 2u; ++explicit_modifier) {
                unsigned rn;

                for (rn = 0u; rn < 32u; ++rn) {
                    unsigned rm;

                    for (rm = 0u; rm < 32u; ++rm) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = pauth_branch_word(
                            link, key_b, explicit_modifier, rn, rm);
                        uint32_t decoded;
                        int valid = explicit_modifier != 0u || rm == 31u;

                        EXPECT((word & PAUTH_BRANCH_PARENT_MASK)
                            == PAUTH_BRANCH_PARENT_VALUE);
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(
                            word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                        if (!valid) {
                            ++reserved;
                            EXPECT(decoded == 0u);
                            EXPECT(instruction_is_error_only(
                                &instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                            continue;
                        }
                        ++allocated;
                        ++partition[link][key_b][explicit_modifier];
#if USE_EXTRA_OPCODES
                        EXPECT(decoded == 4u);
                        EXPECT(metadata_matches(
                            &instruction, word, link, key_b,
                            explicit_modifier, rn, rm));
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
    EXPECT(allocated == UINT32_C(4224));
    EXPECT(reserved == UINT32_C(3968));
    for (link = 0u; link < 2u; ++link) {
        unsigned key_b;

        for (key_b = 0u; key_b < 2u; ++key_b) {
            EXPECT(partition[link][key_b][0] == UINT32_C(32));
            EXPECT(partition[link][key_b][1] == UINT32_C(1024));
        }
    }
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
        EXPECT(is_target_form(instruction.form_id));
        EXPECT(is_target_name(instruction.name_id));
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_profiles_and_neighbors(void)
{
    static const uint32_t outside_family[] = {
        UINT32_C(0xd61f00e0), /* BR X7 */
        UINT32_C(0xd63f00e0), /* BLR X7 */
        UINT32_C(0xd65f0bff), /* RETAA: deliberately outside tranche */
        UINT32_C(0xd65f0fff)  /* RETAB: deliberately outside tranche */
    };
    size_t descriptor_index;
    size_t neighbor_index;
    uint32_t representative = pauth_branch_word(1u, 1u, 1u,
        30u, 31u);

    expect_cpu_status(representative, CDISASM_ARM_CPU_ANY,
        CDISASM_STATUS_OK);
    expect_cpu_status(representative, CDISASM_ARM_CPU_APPLE_A12,
        CDISASM_STATUS_OK);
    expect_cpu_status(representative, CDISASM_ARM_CPU_APPLE_A19,
        CDISASM_STATUS_OK);
    expect_cpu_status(representative, CDISASM_ARM_CPU_APPLE_M1,
        CDISASM_STATUS_OK);
    expect_cpu_status(representative, CDISASM_ARM_CPU_APPLE_S4,
        CDISASM_STATUS_OK);
    expect_cpu_status(representative, CDISASM_ARM_CPU_APPLE_A11,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(representative, CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(representative, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        uint32_t word = descriptors[descriptor_index].value
            | (UINT32_C(7) << 5)
            | (descriptor_index >= 4u ? UINT32_C(13) : UINT32_C(0));
        unsigned bit;

        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((PAUTH_BRANCH_PARENT_MASK
                    & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(word ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            if (decoded == 4u) {
                EXPECT(!is_target_form(instruction.form_id));
                EXPECT(!is_target_name(instruction.name_id));
            }
        }
    }

    for (neighbor_index = 0u;
         neighbor_index < sizeof(outside_family)
            / sizeof(outside_family[0]); ++neighbor_index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(outside_family[neighbor_index],
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(!is_target_form(instruction.form_id));
        EXPECT(!is_target_name(instruction.name_id));
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
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_be(reserved, bytes);
    memset(&other, 0xa5, sizeof(other));
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_INSTRUCTION));

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

static void test_transport_modes_and_status_precedence(void)
{
    cdisasm_arm_instruction instruction;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        uint32_t word = descriptors[descriptor_index].value
            | (UINT32_C(7) << 5)
            | (descriptor_index >= 4u ? UINT32_C(13) : UINT32_C(0));
        uint32_t reserved = pauth_branch_word(
            descriptor_index >= 2u && descriptor_index < 4u
                ? 1u : descriptor_index >= 6u ? 1u : 0u,
            descriptor_index & 1u, 0u, 7u, 13u);

        check_transport(word, reserved);
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(pauth_branch_word(0u, 0u, 1u, 7u, 13u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(pauth_branch_word(0u, 0u, 1u, 7u, 13u),
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    (void)decode_word(pauth_branch_word(1u, 1u, 1u, 31u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(!is_target_form(instruction.form_id));
    EXPECT(!is_target_name(instruction.name_id));
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
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
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
    static const struct format_case {
        uint32_t word;
        const char *text;
    } cases[] = {
        { UINT32_C(0xd61f081f), "braaz x0" },
        { UINT32_C(0xd61f0fff), "brabz xzr" },
        { UINT32_C(0xd63f0bdf), "blraaz x30" },
        { UINT32_C(0xd63f0fff), "blrabz xzr" },
        { UINT32_C(0xd71f0801), "braa x0, x1" },
        { UINT32_C(0xd71f0cff), "brab x7, sp" },
        { UINT32_C(0xd73f0bdf), "blraa x30, sp" },
        { UINT32_C(0xd73f0fe5), "blrab xzr, x5" }
    };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[96];
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_format(cases[index].word, cases[index].text);
    }
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0xd73f0fff), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction,
        CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text)) == strlen("BLRAB xzr, sp"));
    EXPECT(strcmp(text, "BLRAB xzr, sp") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(4527));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_BLRAA);
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd73f0bff));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd63f0fff));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd63f0fed));
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_T32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_JUMP);
    REJECT_MUTATION(forged.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_POINTER_AUTH);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK);
    REJECT_MUTATION(forged.branch_target = UINT64_C(0x1234));
    REJECT_MUTATION(forged.operand_count = 1u);
    REJECT_MUTATION(forged.operand_count = 3u);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_SP);
    REJECT_MUTATION(forged.operand[0].size = 4u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[0].flags =
        CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT);
    REJECT_MUTATION(forged.operand[0].shift_type = CDISASM_ARM_SHIFT_LSL);
    REJECT_MUTATION(forged.operand[0].shift_amount = 1u);
    REJECT_MUTATION(forged.operand[0].scale = 1u);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_XZR);
    REJECT_MUTATION(forged.operand[1].size = 4u);
    REJECT_MUTATION(forged.operand[1].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[1].shift_type = CDISASM_ARM_SHIFT_LSL);
    REJECT_MUTATION(forged.operand[1].shift_amount = 1u);
    REJECT_MUTATION(forged.operand[1].scale = 1u);

    /* Raw-only ownership must reject an unrelated identity. */
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_BLR;
    forged.form_id = UINT16_C(4512);
    forged.instruction_flags = CDISASM_ARM_INSTRUCTION_FLAG_LINK;
    reject_forgery(&forged, "raw-only authenticated-branch forgery");

    memset(&forged, 0, sizeof(forged));
    forged.opcode_size = 4u;
    forged.raw_instruction = UINT32_C(0xd61f0800);
    forged.name_id = CDISASM_ARM_NAME_BR;
    forged.form_id = UINT16_C(4509);
    forged.operand_count = 1u;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.opcode_groups = CDISASM_GROUP_JUMP;
    forged.operand[0].type = CDISASM_OPERAND_REGISTER;
    forged.operand[0].reg = CDISASM_ARM_REG_X0;
    forged.operand[0].size = 8u;
    forged.operand[0].access = CDISASM_OPERAND_ACCESS_READ;
    reject_forgery(&forged, "reserved raw-envelope BR forgery");

    /* Form/name ownership is independent of ISA and opaque fallback flags. */
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0xe2810005), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    forged = instruction;
    forged.form_id = UINT16_C(4525);
    reject_forgery(&forged, "A32 form-only BRAA forgery");
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_BRAA;
    reject_forgery(&forged, "A32 name-only BRAA forgery");
    forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    reject_forgery(&forged, "A32 opaque name-only BRAA forgery");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x00002001), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_T32, 2u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 2u);
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_BLRAAZ;
    reject_forgery(&forged, "T32 name-only BLRAAZ forgery");

#undef REJECT_MUTATION
}
#else
static void test_formatter_and_forgery(void)
{
}
#endif

int main(void)
{
    test_exhaustive_parent_envelope();
    test_profiles_and_neighbors();
    test_transport_modes_and_status_precedence();
    test_formatter_and_forgery();
    if (failures != 0) {
        fprintf(stderr, "ARM authenticated branch failures: %d\n",
            failures);
        return 1;
    }
    return 0;
}
