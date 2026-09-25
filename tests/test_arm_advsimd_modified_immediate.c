#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

typedef enum immediate_kind {
    IMMEDIATE_LSL_S,
    IMMEDIATE_LSL_H,
    IMMEDIATE_MSL_S,
    IMMEDIATE_BYTE,
    IMMEDIATE_BITMASK
} immediate_kind;

typedef struct modified_leaf {
    uint32_t mask;
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    uint32_t expected_count;
    immediate_kind kind;
    uint8_t scalar;
    cdisasm_operand_access destination_access;
} modified_leaf;

/* Pinned AARCHMRS MOVI/MVNI/ORR/BIC Advanced SIMD modified immediates. */
static const modified_leaf leaves[] = {
    { UINT32_C(0xbff89c00), UINT32_C(0x0f000400),
      CDISASM_ARM_NAME_MOVI, UINT16_C(6199), UINT32_C(65536),
      IMMEDIATE_LSL_S, 0u, CDISASM_OPERAND_ACCESS_WRITE },
    { UINT32_C(0xbff89c00), UINT32_C(0x0f001400),
      CDISASM_ARM_NAME_ORR, UINT16_C(6200), UINT32_C(65536),
      IMMEDIATE_LSL_S, 0u, CDISASM_OPERAND_ACCESS_READ_WRITE },
    { UINT32_C(0xbff8dc00), UINT32_C(0x0f008400),
      CDISASM_ARM_NAME_MOVI, UINT16_C(6201), UINT32_C(32768),
      IMMEDIATE_LSL_H, 0u, CDISASM_OPERAND_ACCESS_WRITE },
    { UINT32_C(0xbff8dc00), UINT32_C(0x0f009400),
      CDISASM_ARM_NAME_ORR, UINT16_C(6202), UINT32_C(32768),
      IMMEDIATE_LSL_H, 0u, CDISASM_OPERAND_ACCESS_READ_WRITE },
    { UINT32_C(0xbff8ec00), UINT32_C(0x0f00c400),
      CDISASM_ARM_NAME_MOVI, UINT16_C(6203), UINT32_C(32768),
      IMMEDIATE_MSL_S, 0u, CDISASM_OPERAND_ACCESS_WRITE },
    { UINT32_C(0xbff8fc00), UINT32_C(0x0f00e400),
      CDISASM_ARM_NAME_MOVI, UINT16_C(6204), UINT32_C(16384),
      IMMEDIATE_BYTE, 0u, CDISASM_OPERAND_ACCESS_WRITE },
    { UINT32_C(0xbff89c00), UINT32_C(0x2f000400),
      CDISASM_ARM_NAME_MVNI, UINT16_C(6207), UINT32_C(65536),
      IMMEDIATE_LSL_S, 0u, CDISASM_OPERAND_ACCESS_WRITE },
    { UINT32_C(0xbff89c00), UINT32_C(0x2f001400),
      CDISASM_ARM_NAME_BIC, UINT16_C(6208), UINT32_C(65536),
      IMMEDIATE_LSL_S, 0u, CDISASM_OPERAND_ACCESS_READ_WRITE },
    { UINT32_C(0xbff8dc00), UINT32_C(0x2f008400),
      CDISASM_ARM_NAME_MVNI, UINT16_C(6209), UINT32_C(32768),
      IMMEDIATE_LSL_H, 0u, CDISASM_OPERAND_ACCESS_WRITE },
    { UINT32_C(0xbff8dc00), UINT32_C(0x2f009400),
      CDISASM_ARM_NAME_BIC, UINT16_C(6210), UINT32_C(32768),
      IMMEDIATE_LSL_H, 0u, CDISASM_OPERAND_ACCESS_READ_WRITE },
    { UINT32_C(0xbff8ec00), UINT32_C(0x2f00c400),
      CDISASM_ARM_NAME_MVNI, UINT16_C(6211), UINT32_C(32768),
      IMMEDIATE_MSL_S, 0u, CDISASM_OPERAND_ACCESS_WRITE },
    { UINT32_C(0xfff8fc00), UINT32_C(0x2f00e400),
      CDISASM_ARM_NAME_MOVI, UINT16_C(6212), UINT32_C(8192),
      IMMEDIATE_BITMASK, 1u, CDISASM_OPERAND_ACCESS_WRITE },
    { UINT32_C(0xfff8fc00), UINT32_C(0x6f00e400),
      CDISASM_ARM_NAME_MOVI, UINT16_C(6213), UINT32_C(8192),
      IMMEDIATE_BITMASK, 0u, CDISASM_OPERAND_ACCESS_WRITE }
};

_Static_assert(CDISASM_ARM_NAME_MOVI == UINT16_C(1118),
               "MOVI mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_MVNI == UINT16_C(1128),
               "MVNI mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_ORR == UINT16_C(37),
               "ORR mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_BIC == UINT16_C(9),
               "BIC mnemonic ID changed");
_Static_assert(CDISASM_ARM_SHIFT_MSL == UINT8_C(6),
               "MSL shift ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6213),
               "Advanced SIMD modified-immediate form IDs unavailable");

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

static uint32_t make_word(const modified_leaf *leaf, unsigned q,
                          unsigned cmode, unsigned imm8, unsigned rd)
{
    return (leaf->value & ~UINT32_C(0x4000f000))
        | ((uint32_t)q << 30)
        | ((uint32_t)cmode << 12)
        | ((uint32_t)(imm8 >> 5) << 16)
        | ((uint32_t)(imm8 & 31u) << 5) | (uint32_t)rd;
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
        UINT64_C(0x18c000), options, instruction);
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
static uint8_t element_size_for(const modified_leaf *leaf)
{
    switch (leaf->kind) {
        case IMMEDIATE_LSL_H:
            return 2u;
        case IMMEDIATE_LSL_S:
        case IMMEDIATE_MSL_S:
            return 4u;
        case IMMEDIATE_BITMASK:
            return 8u;
        default:
            return 1u;
    }
}

static uint8_t shift_amount_for(const modified_leaf *leaf, unsigned cmode)
{
    switch (leaf->kind) {
        case IMMEDIATE_LSL_S:
            return (uint8_t)(4u * (cmode & ~1u));
        case IMMEDIATE_LSL_H:
            return (cmode & 2u) != 0u ? 8u : 0u;
        case IMMEDIATE_MSL_S:
            return (cmode & 1u) != 0u ? 16u : 8u;
        default:
            return 0u;
    }
}

static cdisasm_arm_shift_type shift_type_for(
    const modified_leaf *leaf, unsigned cmode)
{
    uint8_t amount = shift_amount_for(leaf, cmode);

    if (leaf->kind == IMMEDIATE_MSL_S) {
        return CDISASM_ARM_SHIFT_MSL;
    }
    return amount != 0u ? CDISASM_ARM_SHIFT_LSL
        : CDISASM_ARM_SHIFT_NONE;
}

static uint64_t immediate_value_for(const modified_leaf *leaf,
                                    unsigned cmode, unsigned imm8)
{
    uint8_t shift = shift_amount_for(leaf, cmode);

    if (leaf->kind == IMMEDIATE_BITMASK) {
        uint64_t value = UINT64_C(0);

        for (unsigned bit = 0u; bit < 8u; ++bit) {
            if ((imm8 & (1u << bit)) != 0u) {
                value |= UINT64_C(0xff) << (8u * bit);
            }
        }
        return value;
    }
    if (leaf->kind == IMMEDIATE_MSL_S) {
        return ((uint64_t)imm8 << shift)
            | ((UINT64_C(1) << shift) - UINT64_C(1));
    }
    return (uint64_t)imm8 << shift;
}

static int register_matches(const cdisasm_arm_operand *operand,
                            cdisasm_arm_reg_id base, unsigned encoded,
                            uint8_t total_size, uint8_t element_size,
                            cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(base + encoded);
    expected.size = total_size;
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.scale = (uint8_t)(total_size / element_size);
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int immediate_matches(const cdisasm_arm_operand *operand,
                             uint64_t value,
                             cdisasm_arm_shift_type shift_type,
                             uint8_t shift_amount)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_IMMEDIATE;
    expected.imm = value;
    expected.size = 1u;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    expected.shift_type = shift_type;
    expected.shift_amount = shift_amount;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            const modified_leaf *leaf, uint32_t word,
                            unsigned q, unsigned cmode, unsigned imm8,
                            unsigned rd)
{
    uint8_t total_size = leaf->scalar != 0u ? 8u : q != 0u ? 16u : 8u;
    cdisasm_arm_reg_id base = leaf->scalar != 0u
        ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;

    return instruction->address == UINT64_C(0x18c000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == leaf->name_id
        && instruction->form_id == leaf->form_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == 2u
        && register_matches(&instruction->operand[0], base, rd,
            total_size, element_size_for(leaf), leaf->destination_access)
        && immediate_matches(&instruction->operand[1],
            immediate_value_for(leaf, cmode, imm8),
            shift_type_for(leaf, cmode), shift_amount_for(leaf, cmode));
}
#endif

static void test_exhaustive_leaves(void)
{
    uint32_t cells[sizeof(leaves) / sizeof(leaves[0])][2][16];
    uint32_t allocated = 0u;

    memset(cells, 0, sizeof(cells));
    for (size_t leaf_index = 0u;
         leaf_index < sizeof(leaves) / sizeof(leaves[0]); ++leaf_index) {
        const modified_leaf *leaf = &leaves[leaf_index];

        for (unsigned q = 0u; q < 2u; ++q) {
            for (unsigned cmode = 0u; cmode < 16u; ++cmode) {
                for (unsigned imm8 = 0u; imm8 < 256u; ++imm8) {
                    for (unsigned rd = 0u; rd < 32u; ++rd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = make_word(
                            leaf, q, cmode, imm8, rd);
                        uint32_t decoded;

                        if ((word & leaf->mask) != leaf->value) {
                            continue;
                        }
                        ++cells[leaf_index][q][cmode];
                        ++allocated;
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
                        EXPECT(decoded == 4u);
                        EXPECT(metadata_matches(&instruction, leaf, word,
                            q, cmode, imm8, rd));
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
    EXPECT(allocated == UINT32_C(491520));
    for (size_t leaf_index = 0u;
         leaf_index < sizeof(leaves) / sizeof(leaves[0]); ++leaf_index) {
        uint32_t leaf_count = 0u;

        for (unsigned q = 0u; q < 2u; ++q) {
            for (unsigned cmode = 0u; cmode < 16u; ++cmode) {
                uint32_t count = cells[leaf_index][q][cmode];

                EXPECT(count == 0u || count == UINT32_C(8192));
                leaf_count += count;
            }
        }
        EXPECT(leaf_count == leaves[leaf_index].expected_count);
    }
}

static void expect_cpu_status(uint32_t word, cdisasm_arm_cpu_id cpu)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, cpu, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
#else
    EXPECT(decode_word(word, cpu, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_profiles_boundaries_and_transport(void)
{
    static const uint32_t samples[] = {
        UINT32_C(0x0f000400), UINT32_C(0x4f0767e1),
        UINT32_C(0x0f008642), UINT32_C(0x4f01a683),
        UINT32_C(0x0f02c6c4), UINT32_C(0x4f03d705),
        UINT32_C(0x0f04e746), UINT32_C(0x4f05e787),
        UINT32_C(0x2f05e548), UINT32_C(0x6f02e6a9),
        UINT32_C(0x2f00064a), UINT32_C(0x6f01668b),
        UINT32_C(0x2f0286cc), UINT32_C(0x6f03a70d),
        UINT32_C(0x2f04c74e), UINT32_C(0x6f05d78f),
        UINT32_C(0x0f001640), UINT32_C(0x4f017681),
        UINT32_C(0x0f0296c2), UINT32_C(0x4f03b703),
        UINT32_C(0x2f041744), UINT32_C(0x6f057785),
        UINT32_C(0x2f0697c6), UINT32_C(0x6f07b607)
    };

    for (size_t index = 0u;
         index < sizeof(samples) / sizeof(samples[0]); ++index) {
        cdisasm_arm_instruction little;
        cdisasm_arm_instruction other;
        uint8_t bytes[4];

        expect_cpu_status(samples[index], CDISASM_ARM_CPU_ANY);
        expect_cpu_status(samples[index], CDISASM_ARM_CPU_CORTEX_A34);
        expect_cpu_status(samples[index], CDISASM_ARM_CPU_CORTEX_A53);
        expect_cpu_status(samples[index], CDISASM_ARM_CPU_APPLE_M3);
        expect_cpu_status(samples[index], CDISASM_ARM_CPU_FUJITSU_A64FX);

        memset(&little, 0xa5, sizeof(little));
        (void)decode_word(samples[index], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &little);
        word_to_be(samples[index], bytes);
        memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x18c000),
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x18c000),
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
        EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

        for (unsigned boundary = 1u; boundary < 4u; ++boundary) {
            memset(&other, 0xa5, sizeof(other));
            EXPECT(decode_word(samples[index], CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, boundary,
                CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
            EXPECT(error_only(&other, CDISASM_STATUS_TRUNCATED));
        }
    }

    {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(samples[0], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, UINT64_C(1) << 63,
            &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(samples[0], CDISASM_ARM_CPU_CORTEX_A7,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));
        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(samples[0], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
            || instruction.form_id != UINT16_C(6199));
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

typedef struct format_case {
    uint32_t word;
    const char *text;
} format_case;

static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[160];
    char short_text[8];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text))
        == expected_length);
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
    static const format_case cases[] = {
        { UINT32_C(0x0f000400), "movi v0.2s, #0x0" },
        { UINT32_C(0x4f0767e1), "movi v1.4s, #0xff, lsl #0x18" },
        { UINT32_C(0x0f008642), "movi v2.4h, #0x12" },
        { UINT32_C(0x4f01a683), "movi v3.8h, #0x34, lsl #0x8" },
        { UINT32_C(0x0f02c6c4), "movi v4.2s, #0x56, msl #0x8" },
        { UINT32_C(0x4f03d705), "movi v5.4s, #0x78, msl #0x10" },
        { UINT32_C(0x0f04e746), "movi v6.8b, #0x9a" },
        { UINT32_C(0x4f05e787), "movi v7.16b, #0xbc" },
        { UINT32_C(0x2f05e548), "movi d8, #0xff00ff00ff00ff00" },
        { UINT32_C(0x6f02e6a9), "movi v9.2d, #0xff00ff00ff00ff" },
        { UINT32_C(0x2f00064a), "mvni v10.2s, #0x12" },
        { UINT32_C(0x6f01668b), "mvni v11.4s, #0x34, lsl #0x18" },
        { UINT32_C(0x2f0286cc), "mvni v12.4h, #0x56" },
        { UINT32_C(0x6f03a70d), "mvni v13.8h, #0x78, lsl #0x8" },
        { UINT32_C(0x2f04c74e), "mvni v14.2s, #0x9a, msl #0x8" },
        { UINT32_C(0x6f05d78f), "mvni v15.4s, #0xbc, msl #0x10" },
        { UINT32_C(0x0f001640), "orr v0.2s, #0x12" },
        { UINT32_C(0x4f017681), "orr v1.4s, #0x34, lsl #0x18" },
        { UINT32_C(0x0f0296c2), "orr v2.4h, #0x56" },
        { UINT32_C(0x4f03b703), "orr v3.8h, #0x78, lsl #0x8" },
        { UINT32_C(0x2f041744), "bic v4.2s, #0x9a" },
        { UINT32_C(0x6f057785), "bic v5.4s, #0xbc, lsl #0x18" },
        { UINT32_C(0x2f0697c6), "bic v6.4h, #0xde" },
        { UINT32_C(0x6f07b607), "bic v7.8h, #0xf0, lsl #0x8" }
    };

    for (size_t index = 0u; index < sizeof(cases) / sizeof(cases[0]);
         ++index) {
        expect_format(cases[index].word, cases[index].text);
    }

    for (size_t leaf_index = 0u;
         leaf_index < sizeof(leaves) / sizeof(leaves[0]); ++leaf_index) {
        const modified_leaf *leaf = &leaves[leaf_index];
        cdisasm_arm_instruction instruction;
        cdisasm_arm_instruction forged;
        unsigned q = (leaf->value >> 30) & 1u;
        unsigned cmode = (leaf->value >> 12) & 15u;
        uint32_t word = make_word(leaf, q, cmode, 0x5au, 31u);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 4u);

#define REJECT_MUTATION(statement)                                          \
        do {                                                                \
            forged = instruction;                                           \
            statement;                                                      \
            reject_forgery(&forged, #statement);                            \
        } while (0)

        REJECT_MUTATION(forged.form_id = UINT16_C(5853));
        REJECT_MUTATION(forged.name_id = leaf->name_id
            == CDISASM_ARM_NAME_MOVI ? CDISASM_ARM_NAME_MVNI
                                     : CDISASM_ARM_NAME_MOVI);
        REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x01000000));
        REJECT_MUTATION(forged.opcode_size = 2u);
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
        REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
        REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
        REJECT_MUTATION(forged.instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
        REJECT_MUTATION(forged.branch_target = UINT64_C(4));
        REJECT_MUTATION(forged.operand_count = 1u);
        REJECT_MUTATION(forged.operand[0].reg = leaf->scalar != 0u
            ? CDISASM_ARM_REG_D30 : CDISASM_ARM_REG_V30);
        REJECT_MUTATION(forged.operand[0].access =
            leaf->destination_access == CDISASM_OPERAND_ACCESS_WRITE
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[0].extend_type =
            (cdisasm_arm_extend_type)(element_size_for(leaf) == 1u
                ? 2u : 1u));
        REJECT_MUTATION(forged.operand[1].imm ^= UINT64_C(1));
        REJECT_MUTATION(forged.operand[1].size = 2u);
        REJECT_MUTATION(forged.operand[1].access =
            CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[1].shift_type =
            instruction.operand[1].shift_type == CDISASM_ARM_SHIFT_MSL
                ? CDISASM_ARM_SHIFT_LSL : CDISASM_ARM_SHIFT_MSL);
        REJECT_MUTATION(forged.operand[1].shift_amount ^= UINT8_C(1));
        REJECT_MUTATION(forged.operand[2].type =
            CDISASM_OPERAND_IMMEDIATE);

#undef REJECT_MUTATION
    }

    {
        cdisasm_arm_instruction instruction;
        char text[160];
        const char expected[] = "MOVI v5.4s, #0x78, msl #0x10";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(UINT32_C(0x4f03d705), CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
    }
    {
        cdisasm_arm_instruction instruction;
        cdisasm_arm_instruction forged;

        /* The append-only MSL vocabulary is valid only on the exact
         * modified-immediate operand, never a generic register modifier. */
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(UINT32_C(0x8b020c20), CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 4u);
        forged = instruction;
        forged.operand[2].shift_type = CDISASM_ARM_SHIFT_MSL;
        forged.operand[2].shift_amount = 8u;
        reject_forgery(&forged, "MSL on unrelated register operand");
    }
}
#else
static void test_formatter_and_schema(void)
{
}
#endif

int main(void)
{
    test_exhaustive_leaves();
    test_profiles_boundaries_and_transport();
    test_formatter_and_schema();

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM Advanced SIMD modified-immediate test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM Advanced SIMD modified-immediate tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=491520, reserved=0)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
