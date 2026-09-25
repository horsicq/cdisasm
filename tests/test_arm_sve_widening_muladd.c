#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x1ae000)
#define LEAF_MASK UINT32_C(0xff20fc00)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

typedef struct test_family {
    uint32_t fixed_value;
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    int widening;
} test_family;

static const test_family families[14] = {
    { UINT32_C(0x44004000), UINT16_C(2642), CDISASM_ARM_NAME_SMLALB, 1 },
    { UINT32_C(0x44005000), UINT16_C(2643), CDISASM_ARM_NAME_SMLSLB, 1 },
    { UINT32_C(0x44004400), UINT16_C(2644), CDISASM_ARM_NAME_SMLALT, 1 },
    { UINT32_C(0x44005400), UINT16_C(2645), CDISASM_ARM_NAME_SMLSLT, 1 },
    { UINT32_C(0x44004800), UINT16_C(2646), CDISASM_ARM_NAME_UMLALB, 1 },
    { UINT32_C(0x44005800), UINT16_C(2647), CDISASM_ARM_NAME_UMLSLB, 1 },
    { UINT32_C(0x44004c00), UINT16_C(2648), CDISASM_ARM_NAME_UMLALT, 1 },
    { UINT32_C(0x44005c00), UINT16_C(2649), CDISASM_ARM_NAME_UMLSLT, 1 },
    { UINT32_C(0x44006000), UINT16_C(2650), CDISASM_ARM_NAME_SQDMLALB, 1 },
    { UINT32_C(0x44006800), UINT16_C(2651), CDISASM_ARM_NAME_SQDMLSLB, 1 },
    { UINT32_C(0x44006400), UINT16_C(2652), CDISASM_ARM_NAME_SQDMLALT, 1 },
    { UINT32_C(0x44006c00), UINT16_C(2653), CDISASM_ARM_NAME_SQDMLSLT, 1 },
    { UINT32_C(0x44007000), UINT16_C(2654), CDISASM_ARM_NAME_SQRDMLAH, 0 },
    { UINT32_C(0x44007400), UINT16_C(2655), CDISASM_ARM_NAME_SQRDMLSH, 0 }
};

static int failures;
static uint64_t family_counts[14];
static uint64_t reserved_count;

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

static void domain_expect(int condition, uint32_t word, const char *message)
{
    if (!condition) {
        if (failures < 24) {
            fprintf(stderr, "word %08x: %s\n", (unsigned)word, message);
        }
        ++failures;
    }
}

static void word_to_le(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)word;
    bytes[1] = (uint8_t)(word >> 8);
    bytes[2] = (uint8_t)(word >> 16);
    bytes[3] = (uint8_t)(word >> 24);
}

static uint32_t decode_word_mode(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_arm_mode mode,
    size_t size, cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, size, TEST_ADDRESS, options, instruction);
}

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, size_t size,
    cdisasm_arm_decode_option options, cdisasm_arm_instruction *instruction)
{
    return decode_word_mode(
        word, cpu_id, CDISASM_ARM_MODE_A64, size, options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction, cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static int identify_family(uint32_t word, unsigned *family_index)
{
    unsigned index;

    for (index = 0u; index < 14u; ++index) {
        if ((word & LEAF_MASK) == families[index].fixed_value) {
            *family_index = index;
            return 1;
        }
    }
    return 0;
}

#if USE_EXTRA_OPCODES
static void append_z_operand(
    cdisasm_arm_instruction *instruction, unsigned encoded,
    uint8_t element_size, cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand =
        &instruction->operand[instruction->operand_count++];

    operand->type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    operand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    operand->extend_type = (cdisasm_arm_extend_type)element_size;
    operand->access = access;
}

static void make_expected(
    uint32_t word, unsigned family_index,
    cdisasm_arm_instruction *expected)
{
    const test_family *family = &families[family_index];
    unsigned size_code = (word >> 22) & 3u;
    uint8_t destination_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t source_size = family->widening
        ? (uint8_t)(destination_size / 2u) : destination_size;

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = family->name_id;
    expected->form_id = family->form_id;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG;
    append_z_operand(expected, word & 31u, destination_size,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    append_z_operand(expected, (word >> 5) & 31u, source_size,
        CDISASM_OPERAND_ACCESS_READ);
    append_z_operand(expected, (word >> 16) & 31u, source_size,
        CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void expect_allocated(uint32_t word, unsigned family_index)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated widening multiply-add word did not decode");
        make_expected(word, family_index, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated widening multiply-add metadata mismatch");
    }
#else
    (void)family_index;
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded allocated widening multiply-add word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF widening multiply-add ownership mismatch");
#endif
}

static void expect_reserved(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved widening multiply-add word decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved widening multiply-add ownership mismatch");
}

static void test_complete_leaf_union(void)
{
    unsigned family_index;
    unsigned size_code;
    unsigned zm;
    unsigned zn;
    unsigned zda;

    for (family_index = 0u; family_index < 14u; ++family_index) {
        for (size_code = 0u; size_code < 4u; ++size_code) {
            for (zm = 0u; zm < 32u; ++zm) {
                for (zn = 0u; zn < 32u; ++zn) {
                    for (zda = 0u; zda < 32u; ++zda) {
                        uint32_t word = families[family_index].fixed_value
                            | ((uint32_t)size_code << 22)
                            | ((uint32_t)zm << 16)
                            | ((uint32_t)zn << 5) | zda;
                        unsigned identified = 99u;

                        domain_expect(identify_family(word, &identified)
                                && identified == family_index,
                            word, "leaf construction escaped exact identity");
                        if (families[family_index].widening
                            && size_code == 0u) {
                            expect_reserved(word);
                            ++reserved_count;
                        } else {
                            expect_allocated(word, family_index);
                            ++family_counts[family_index];
                        }
                    }
                }
            }
        }
    }
    for (family_index = 0u; family_index < 12u; ++family_index) {
        EXPECT(family_counts[family_index] == UINT64_C(98304));
    }
    EXPECT(family_counts[12] == UINT64_C(131072));
    EXPECT(family_counts[13] == UINT64_C(131072));
    EXPECT(reserved_count == UINT64_C(393216));
    {
        uint64_t allocated = 0u;

        for (family_index = 0u; family_index < 14u; ++family_index) {
            allocated += family_counts[family_index];
        }
        EXPECT(allocated == UINT64_C(1441792));
        EXPECT(allocated + reserved_count == UINT64_C(1835008));
    }
}

static void expect_profile(
    uint32_t word, cdisasm_arm_cpu_id cpu_id,
    cdisasm_status enabled_status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_status expected;

#if USE_EXTRA_OPCODES
    expected = enabled_status;
#else
    (void)enabled_status;
    expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, cpu_id, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction)
        == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
#if USE_EXTRA_OPCODES
        unsigned family_index;

        EXPECT(identify_family(word, &family_index));
        EXPECT(instruction.form_id == families[family_index].form_id);
        EXPECT(instruction.name_id == families[family_index].name_id);
#endif
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_features_transport_and_delegation(void)
{
    static const uint32_t words[] = {
        UINT32_C(0x44424020), /* smlalb z0.h, z1.b, z2.b */
        UINT32_C(0x44855083), /* smlslb z3.s, z4.h, z5.h */
        UINT32_C(0x44dd4fdf), /* umlalt z31.d, z30.s, z29.s */
        UINT32_C(0x44856883), /* sqdmlslb z3.s, z4.h, z5.h */
        UINT32_C(0x44027020), /* sqrdmlah z0.b, z1.b, z2.b */
        UINT32_C(0x44dd77df)  /* sqrdmlsh z31.d, z30.d, z29.d */
    };
    static const uint32_t delegated[] = {
        UINT32_C(0x44003000), /* preceding SQRDCMLAH group */
        UINT32_C(0x44007800), /* unallocated following control */
        UINT32_C(0x44807800), /* following USDOT leaf */
        UINT32_C(0x44008000)  /* following predicated integer space */
    };
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned index;
    unsigned boundary;

    for (index = 0u;
         index < sizeof(words) / sizeof(words[0]); ++index) {
        expect_profile(words[index], CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_profile(words[index], CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(words[5], CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(words[5], CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
    bytes[0] = (uint8_t)(words[5] >> 24);
    bytes[1] = (uint8_t)(words[5] >> 16);
    bytes[2] = (uint8_t)(words[5] >> 8);
    bytes[3] = (uint8_t)words[5];
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_le(words[5], bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    for (boundary = 0u; boundary < 4u; ++boundary) {
        cdisasm_status status = boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(words[0], CDISASM_ARM_CPU_ANY,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, status));
    }
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(words[0], CDISASM_ARM_CPU_ANY, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));

    for (index = 0u;
         index < sizeof(delegated) / sizeof(delegated[0]); ++index) {
        memset(&other, 0xa5, sizeof(other));
        (void)decode_word(delegated[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &other);
        EXPECT(other.form_id < UINT16_C(2642)
            || other.form_id > UINT16_C(2655));
    }
    memset(&other, 0xa5, sizeof(other));
    (void)decode_word_mode(words[0], CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id < UINT16_C(2642)
        || other.form_id > UINT16_C(2655));
    memset(&other, 0xa5, sizeof(other));
    (void)decode_word_mode(words[0], CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id < UINT16_C(2642)
        || other.form_id > UINT16_C(2655));
}

static void test_indexed_widening_multiply(void)
{
    static const struct indexed_case {
        uint32_t word;
        cdisasm_arm_name_id name;
        uint8_t destination_size, source_size, indexed_register, lane;
    } cases[] = {
        { UINT32_C(0x44afc820), CDISASM_ARM_NAME_SMULLB, 4u, 2u, 7u, 3u },
        { UINT32_C(0x44efc862), CDISASM_ARM_NAME_SMULLB, 8u, 4u, 15u, 1u },
        { UINT32_C(0x44aec4a4), CDISASM_ARM_NAME_SMULLT, 4u, 2u, 6u, 2u },
        { UINT32_C(0x44eec507), CDISASM_ARM_NAME_SMULLT, 8u, 4u, 14u, 0u },
        { UINT32_C(0x44a5d949), CDISASM_ARM_NAME_UMULLB, 4u, 2u, 5u, 1u },
        { UINT32_C(0x44edd98b), CDISASM_ARM_NAME_UMULLB, 8u, 4u, 13u, 1u },
        { UINT32_C(0x44acddee), CDISASM_ARM_NAME_UMULLT, 4u, 2u, 4u, 3u },
        { UINT32_C(0x44ecd630), CDISASM_ARM_NAME_UMULLT, 8u, 4u, 12u, 0u },
        { UINT32_C(0x44abe272), CDISASM_ARM_NAME_SQDMULLB, 4u, 2u, 3u, 2u },
        { UINT32_C(0x44ebeab4), CDISASM_ARM_NAME_SQDMULLB, 8u, 4u, 11u, 1u },
        { UINT32_C(0x44a2eef6), CDISASM_ARM_NAME_SQDMULLT, 4u, 2u, 2u, 1u },
        { UINT32_C(0x44eae738), CDISASM_ARM_NAME_SQDMULLT, 8u, 4u, 10u, 0u }
    };
    cdisasm_arm_instruction instruction;
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const struct indexed_case *test = &cases[index];

        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(test->word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(instruction.name_id == test->name);
        EXPECT(instruction.instruction_flags == SCALABLE_FLAG);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.operand[0].extend_type == test->destination_size);
        EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.operand[1].extend_type == test->source_size);
        EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.operand[2].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
                + test->indexed_register));
        EXPECT(instruction.operand[2].extend_type == test->source_size);
        EXPECT(instruction.operand[2].flags
            == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
        EXPECT(instruction.operand[2].imm == test->lane);
        EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#else
        EXPECT(decode_word(test->word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void reject_forgery(
    const cdisasm_arm_instruction *instruction, const char *mutation)
{
    char text[112];
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

static void test_formatter_contract(void)
{
    static const struct format_case {
        uint32_t word;
        const char *text;
    } cases[] = {
        { UINT32_C(0x44424020), "smlalb z0.h, z1.b, z2.b" },
        { UINT32_C(0x44425020), "smlslb z0.h, z1.b, z2.b" },
        { UINT32_C(0x44424420), "smlalt z0.h, z1.b, z2.b" },
        { UINT32_C(0x44425420), "smlslt z0.h, z1.b, z2.b" },
        { UINT32_C(0x44424820), "umlalb z0.h, z1.b, z2.b" },
        { UINT32_C(0x44425820), "umlslb z0.h, z1.b, z2.b" },
        { UINT32_C(0x44424c20), "umlalt z0.h, z1.b, z2.b" },
        { UINT32_C(0x44425c20), "umlslt z0.h, z1.b, z2.b" },
        { UINT32_C(0x44426020), "sqdmlalb z0.h, z1.b, z2.b" },
        { UINT32_C(0x44426820), "sqdmlslb z0.h, z1.b, z2.b" },
        { UINT32_C(0x44426420), "sqdmlalt z0.h, z1.b, z2.b" },
        { UINT32_C(0x44426c20), "sqdmlslt z0.h, z1.b, z2.b" },
        { UINT32_C(0x44027020), "sqrdmlah z0.b, z1.b, z2.b" },
        { UINT32_C(0x44dd77df), "sqrdmlsh z31.d, z30.d, z29.d" }
    };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[112];
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        EXPECT(decode_word(cases[index].word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == strlen(cases[index].text));
        EXPECT(strcmp(text, cases[index].text) == 0);
    }
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("SQRDMLSH z31.d, z30.d, z29.d"));
    EXPECT(strcmp(text, "SQRDMLSH z31.d, z30.d, z29.d") == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(cases[sizeof(cases) / sizeof(cases[0]) - 1u].text));

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(2654));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_SQRDMLAH);
    REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x00000400));
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.instruction_flags = CDISASM_GROUP_NONE);
    REJECT_MUTATION(forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[1].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[1].extend_type = CDISASM_ARM_EXTEND_SXTW);

    EXPECT(decode_word(cases[0].word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    forged = instruction;
    forged.form_id = UINT16_C(2641);
    reject_forgery(&forged, "preceding form ID");
    forged = instruction;
    forged.raw_instruction = UINT32_C(0x44003000);
    reject_forgery(&forged, "preceding raw family");

#undef REJECT_MUTATION
}
#else
static void test_formatter_contract(void)
{
}
#endif

int main(void)
{
    test_complete_leaf_union();
    test_features_transport_and_delegation();
    test_indexed_widening_multiply();
    test_formatter_contract();

    if (failures != 0) {
        fprintf(stderr, "%d SVE widening multiply-add test(s) failed\n",
            failures);
        return 1;
    }
    return 0;
}
