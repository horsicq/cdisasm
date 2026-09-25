#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x175000)
#define FAMILY_FLAGS                                                       \
    (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR                          \
        | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED                          \
        | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS)

typedef struct while_descriptor {
    uint32_t value;
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    int requires_sve2;
} while_descriptor;

static const while_descriptor descriptors[8] = {
    { UINT32_C(0x25200000), UINT16_C(2585),
      CDISASM_ARM_NAME_WHILEGE, 1 },
    { UINT32_C(0x25200800), UINT16_C(2586),
      CDISASM_ARM_NAME_WHILEHS, 1 },
    { UINT32_C(0x25200010), UINT16_C(2587),
      CDISASM_ARM_NAME_WHILEGT, 1 },
    { UINT32_C(0x25200810), UINT16_C(2588),
      CDISASM_ARM_NAME_WHILEHI, 1 },
    { UINT32_C(0x25200400), UINT16_C(2589),
      CDISASM_ARM_NAME_WHILELT, 0 },
    { UINT32_C(0x25200c00), UINT16_C(2590),
      CDISASM_ARM_NAME_WHILELO, 0 },
    { UINT32_C(0x25200410), UINT16_C(2591),
      CDISASM_ARM_NAME_WHILELE, 0 },
    { UINT32_C(0x25200c10), UINT16_C(2592),
      CDISASM_ARM_NAME_WHILELS, 0 }
};

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

static uint32_t family_word(
    unsigned relation, unsigned size, unsigned wide, unsigned rm,
    unsigned rn, unsigned pd)
{
    return descriptors[relation].value
        | ((uint32_t)size << 22)
        | ((uint32_t)wide << 12)
        | ((uint32_t)rm << 16)
        | ((uint32_t)rn << 5) | pd;
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_reg_id expected_reg(unsigned encoded, int wide)
{
    if (wide) {
        return encoded == 31u ? CDISASM_ARM_REG_XZR
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded);
    }
    return encoded == 31u ? CDISASM_ARM_REG_WZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + encoded);
}

static void expected_instruction(
    uint32_t word, unsigned relation, cdisasm_arm_instruction *expected)
{
    int wide = (word & UINT32_C(0x00001000)) != 0u;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = descriptors[relation].name_id;
    expected->form_id = descriptors[relation].form_id;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = FAMILY_FLAGS;
    expected->operand_count = 3u;

    expected->operand[0].type = CDISASM_ARM_OPERAND_PREDICATE;
    expected->operand[0].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_P0 + (word & 15u));
    expected->operand[0].extend_type =
        (cdisasm_arm_extend_type)element_size;
    expected->operand[0].flags =
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;

    expected->operand[1].type = CDISASM_OPERAND_REGISTER;
    expected->operand[1].reg = expected_reg((word >> 5) & 31u, wide);
    expected->operand[1].size = wide ? 8u : 4u;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;

    expected->operand[2].type = CDISASM_OPERAND_REGISTER;
    expected->operand[2].reg = expected_reg((word >> 16) & 31u, wide);
    expected->operand[2].size = wide ? 8u : 4u;
    expected->operand[2].access = CDISASM_OPERAND_ACCESS_READ;
}
#endif

static void expect_allocated(uint32_t word, unsigned relation)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        expected_instruction(word, relation, &expected);
        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated single-predicate WHILE leaf did not decode");
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "single-predicate WHILE metadata mismatch");
    }
#else
    (void)relation;
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded single-predicate WHILE leaf");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF single-predicate WHILE ownership mismatch");
#endif
}

static void test_complete_family(void)
{
    uint32_t allocated_count = 0u;
    uint32_t per_form[8] = { 0u };
    unsigned relation;
    unsigned size;
    unsigned wide;
    unsigned rm;
    unsigned rn;
    unsigned pd;

    for (relation = 0u; relation < 8u; ++relation) {
        for (size = 0u; size < 4u; ++size) {
            for (wide = 0u; wide < 2u; ++wide) {
                for (rm = 0u; rm < 32u; ++rm) {
                    for (rn = 0u; rn < 32u; ++rn) {
                        for (pd = 0u; pd < 16u; ++pd) {
                            expect_allocated(family_word(
                                relation, size, wide, rm, rn, pd),
                                relation);
                            ++allocated_count;
                            ++per_form[relation];
                        }
                    }
                }
            }
        }
    }
    EXPECT(allocated_count == UINT32_C(1048576));
    for (relation = 0u; relation < 8u; ++relation) {
        EXPECT(per_form[relation] == UINT32_C(131072));
    }
}

static void expect_profile(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_status enabled_status)
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
    if (expected != CDISASM_STATUS_OK) {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_feature_alternatives(void)
{
    unsigned relation;

    for (relation = 0u; relation < 8u; ++relation) {
        uint32_t word = family_word(
            relation, relation & 3u, relation >> 2,
            relation * 3u, relation * 2u, relation);

        expect_profile(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_profile(word, CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_OK);
        expect_profile(word, CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_profile(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            descriptors[relation].requires_sve2
                ? CDISASM_STATUS_INVALID_INSTRUCTION
                : CDISASM_STATUS_OK);
        expect_profile(word, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static int is_target_identity(const cdisasm_arm_instruction *instruction)
{
    return instruction->form_id >= UINT16_C(2585)
        && instruction->form_id <= UINT16_C(2592);
}

static void test_transport_and_boundaries(void)
{
    static const uint32_t words[] = {
        UINT32_C(0x25200000), UINT32_C(0x25ff1fff)
    };
    static const uint32_t adjacent_words[] = {
        UINT32_C(0x25202000), UINT32_C(0x25204000),
        UINT32_C(0x25208000), UINT32_C(0x25000000)
    };
    unsigned index;

    for (index = 0u; index < sizeof(words) / sizeof(words[0]); ++index) {
        cdisasm_arm_instruction little;
        cdisasm_arm_instruction other;
        uint8_t bytes[4];
        unsigned boundary;

        memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
        EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
        bytes[0] = (uint8_t)(words[index] >> 24);
        bytes[1] = (uint8_t)(words[index] >> 16);
        bytes[2] = (uint8_t)(words[index] >> 8);
        bytes[3] = (uint8_t)words[index];
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

        word_to_le(words[index], bytes);
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
            EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, boundary,
                CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
            EXPECT(instruction_is_error_only(&other, status));
        }
    }

    for (index = 0u;
         index < sizeof(adjacent_words) / sizeof(adjacent_words[0]);
         ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(adjacent_words[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(!is_target_identity(&instruction));
    }
}

static void test_a64_ownership(void)
{
    static const cdisasm_arm_mode other_modes[] = {
        CDISASM_ARM_MODE_A32, CDISASM_ARM_MODE_T32
    };
    unsigned index;

    for (index = 0u;
         index < sizeof(other_modes) / sizeof(other_modes[0]); ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word_mode(
            UINT32_C(0x25ff1fff), CDISASM_ARM_CPU_ANY,
            other_modes[index], 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        EXPECT(!is_target_identity(&instruction));
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[80];

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(expected));
}

static void reject_forgery(cdisasm_arm_instruction *instruction)
{
    char text[80];

    memset(text, 0xa5, sizeof(text));
    EXPECT(cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == 0u);
    EXPECT(text[0] == '\0');
}

static void expect_shared_name_sibling_requires_own_schema(
    const cdisasm_arm_instruction *base, uint32_t raw_instruction,
    cdisasm_arm_form_id form_id)
{
    cdisasm_arm_instruction sibling = *base;
    char text[80];

    sibling.raw_instruction = raw_instruction;
    sibling.form_id = form_id;
    EXPECT(cdisasm_arm_format(
        &sibling, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == 0u);
    EXPECT(text[0] == '\0');
}

static void test_formatter(void)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;

    expect_format(UINT32_C(0x25200000), "whilege p0.b, w0, w0");
    expect_format(UINT32_C(0x25630841), "whilehs p1.h, w2, w3");
    expect_format(UINT32_C(0x25a610b4), "whilegt p4.s, x5, x6");
    expect_format(UINT32_C(0x25ff1bf7), "whilehi p7.d, xzr, xzr");
    expect_format(UINT32_C(0x252a0528), "whilelt p8.b, w9, w10");
    expect_format(UINT32_C(0x256d0d8b), "whilelo p11.h, w12, w13");
    expect_format(UINT32_C(0x25b015fe), "whilele p14.s, x15, x16");
    expect_format(UINT32_C(0x25ff1fff), "whilels p15.d, xzr, xzr");

    EXPECT(decode_word(UINT32_C(0x25a610b4),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_WHILEHI;
    reject_forgery(&forged);
    forged = instruction;
    forged.form_id = UINT16_C(2588);
    reject_forgery(&forged);
    forged = instruction;
    forged.raw_instruction ^= UINT32_C(0x00000010);
    reject_forgery(&forged);
    forged = instruction;
    forged.instruction_flags &=
        ~CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[0].flags = CDISASM_OPERAND_FLAG_NONE;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[1].reg = CDISASM_ARM_REG_W5;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[2].access = CDISASM_OPERAND_ACCESS_WRITE;
    reject_forgery(&forged);

    EXPECT(decode_word(UINT32_C(0x25200000), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    /* The now-implemented PN WHILEGE sibling must reject a stale copy of
     * this family's operand schema even though the mnemonic is shared. */
    expect_shared_name_sibling_requires_own_schema(
        &instruction, UINT32_C(0x25204010), UINT16_C(2566));

    /* The paired-predicate sibling has its own now-implemented exact schema. */
    expect_format(UINT32_C(0x25205010),
        "whilege {p0.b, p1.b}, x0, x0");

    EXPECT(decode_word(UINT32_C(0x8b010000), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_WHILEGE;
    reject_forgery(&forged);
}
#else
static void test_formatter(void)
{
}
#endif

int main(void)
{
    test_complete_family();
    test_feature_alternatives();
    test_transport_and_boundaries();
    test_a64_ownership();
    test_formatter();

    if (failures != 0) {
        fprintf(stderr, "%d single-predicate WHILE test(s) failed\n",
            failures);
        return 1;
    }
    printf("single-predicate WHILE tests passed "
           "(1048576 allocated encodings; 131072 per form)\n");
    return 0;
}
