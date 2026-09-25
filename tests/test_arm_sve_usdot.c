#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x1af000)
#define PARENT_MASK UINT32_C(0xff20fc00)
#define PARENT_VALUE UINT32_C(0x44007800)
#define USDOT_MASK UINT32_C(0xffe0fc00)
#define USDOT_VALUE UINT32_C(0x44807800)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

static int failures;
static uint64_t allocated_count;
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
    uint32_t word, cdisasm_arm_instruction *expected)
{
    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = CDISASM_ARM_NAME_USDOT;
    expected->form_id = UINT16_C(2656);
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG;
    append_z_operand(expected, word & 31u, 4u,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    append_z_operand(expected, (word >> 5) & 31u, 1u,
        CDISASM_OPERAND_ACCESS_READ);
    append_z_operand(expected, (word >> 16) & 31u, 1u,
        CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void expect_allocated(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated USDOT word did not decode");
        make_expected(word, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated USDOT metadata mismatch");
    }
#else
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded allocated USDOT word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF USDOT ownership mismatch");
#endif
}

static void expect_reserved(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved mixed-dot word decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved mixed-dot ownership mismatch");
}

static void test_complete_parent_union(void)
{
    unsigned size_code;
    unsigned zm;
    unsigned zn;
    unsigned zda;

    for (size_code = 0u; size_code < 4u; ++size_code) {
        for (zm = 0u; zm < 32u; ++zm) {
            for (zn = 0u; zn < 32u; ++zn) {
                for (zda = 0u; zda < 32u; ++zda) {
                    uint32_t word = PARENT_VALUE
                        | ((uint32_t)size_code << 22)
                        | ((uint32_t)zm << 16)
                        | ((uint32_t)zn << 5) | zda;

                    domain_expect((word & PARENT_MASK) == PARENT_VALUE,
                        word, "mixed-dot construction escaped parent");
                    if (size_code == 2u) {
                        domain_expect((word & USDOT_MASK) == USDOT_VALUE,
                            word, "allocated word escaped USDOT leaf");
                        expect_allocated(word);
                        ++allocated_count;
                    } else {
                        domain_expect((word & USDOT_MASK) != USDOT_VALUE,
                            word, "reserved word entered USDOT leaf");
                        expect_reserved(word);
                        ++reserved_count;
                    }
                }
            }
        }
    }
    EXPECT(allocated_count == UINT64_C(32768));
    EXPECT(reserved_count == UINT64_C(98304));
    EXPECT(allocated_count + reserved_count == UINT64_C(131072));
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
        EXPECT(instruction.form_id == UINT16_C(2656));
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_USDOT);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_features_transport_and_boundaries(void)
{
    static const uint32_t oracle_words[] = {
        UINT32_C(0x44827820), /* usdot z0.s, z1.b, z2.b */
        UINT32_C(0x449d7bdf)  /* usdot z31.s, z30.b, z29.b */
    };
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned bit;
    unsigned boundary;

    expect_profile(oracle_words[0], CDISASM_ARM_CPU_ANY,
        CDISASM_STATUS_OK);
    /* These profiles independently supply the SVE/SME side of the
     * alternative but deliberately do not claim FEAT_I8MM. */
    expect_profile(oracle_words[0], CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(oracle_words[0], CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(oracle_words[0], CDISASM_ARM_CPU_APPLE_M4,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(oracle_words[0], CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(oracle_words[1], CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(oracle_words[1], CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
    bytes[0] = (uint8_t)(oracle_words[1] >> 24);
    bytes[1] = (uint8_t)(oracle_words[1] >> 16);
    bytes[2] = (uint8_t)(oracle_words[1] >> 8);
    bytes[3] = (uint8_t)oracle_words[1];
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

    word_to_le(oracle_words[1], bytes);
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
        EXPECT(decode_word(oracle_words[0], CDISASM_ARM_CPU_ANY,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, status));
    }
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(oracle_words[0], CDISASM_ARM_CPU_ANY, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));

    /* Every fixed bit in the enclosing parent is an ownership boundary.
     * Changing one may reach a sibling family, but never this exact form. */
    for (bit = 0u; bit < 32u; ++bit) {
        if ((PARENT_MASK & (UINT32_C(1) << bit)) != 0u) {
            uint32_t neighbor = oracle_words[0]
                ^ (UINT32_C(1) << bit);

            memset(&other, 0xa5, sizeof(other));
            (void)decode_word(neighbor, CDISASM_ARM_CPU_ANY, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &other);
            EXPECT(other.form_id != UINT16_C(2656));
        }
    }
    memset(&other, 0xa5, sizeof(other));
    (void)decode_word(UINT32_C(0x44827420), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other);
#if USE_EXTRA_OPCODES
    EXPECT(other.form_id == UINT16_C(2655));
#else
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    memset(&other, 0xa5, sizeof(other));
    (void)decode_word(UINT32_C(0x44828020), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id != UINT16_C(2656));

    memset(&other, 0xa5, sizeof(other));
    (void)decode_word_mode(oracle_words[0], CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id != UINT16_C(2656));
    memset(&other, 0xa5, sizeof(other));
    (void)decode_word_mode(oracle_words[0], CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id != UINT16_C(2656));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
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

static void test_formatter_contract(void)
{
    static const struct format_case {
        uint32_t word;
        const char *text;
    } cases[] = {
        { UINT32_C(0x44827820), "usdot z0.s, z1.b, z2.b" },
        { UINT32_C(0x449d7bdf), "usdot z31.s, z30.b, z29.b" }
    };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[96];
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
        == strlen("USDOT z31.s, z30.b, z29.b"));
    EXPECT(strcmp(text, "USDOT z31.s, z30.b, z29.b") == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(cases[1].text));

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(2655));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_UDOT);
    REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x00400000));
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.instruction_flags = CDISASM_GROUP_NONE);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[0].extend_type = CDISASM_ARM_EXTEND_SXTB);
    REJECT_MUTATION(forged.operand[1].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[1].extend_type = CDISASM_ARM_EXTEND_SXTW);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_Z0);

    forged = instruction;
    forged.form_id = UINT16_C(2657);
    reject_forgery(&forged, "following form ID");
    forged = instruction;
    forged.raw_instruction = UINT32_C(0x44827420);
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
    test_complete_parent_union();
    test_features_transport_and_boundaries();
    test_formatter_contract();

    if (failures != 0) {
        fprintf(stderr, "%d SVE USDOT test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
