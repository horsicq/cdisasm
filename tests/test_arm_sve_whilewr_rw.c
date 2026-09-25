#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x173000)
#define FAMILY_FLAGS                                                   \
    (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR                      \
        | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED                      \
        | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS)

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

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, size_t size,
    cdisasm_arm_decode_option options, cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, CDISASM_ARM_MODE_A64, bytes, size, TEST_ADDRESS,
        options, instruction);
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
    unsigned reverse, unsigned size, unsigned rm, unsigned rn, unsigned pd)
{
    return UINT32_C(0x25203000)
        | ((uint32_t)size << 22)
        | ((uint32_t)rm << 16)
        | ((uint32_t)rn << 5)
        | ((uint32_t)reverse << 4) | pd;
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_reg_id xreg(unsigned encoded)
{
    return encoded == 31u ? CDISASM_ARM_REG_XZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded);
}

static void expected_instruction(
    uint32_t word, cdisasm_arm_instruction *expected)
{
    unsigned reverse = (word >> 4) & 1u;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = reverse != 0u
        ? CDISASM_ARM_NAME_WHILERW : CDISASM_ARM_NAME_WHILEWR;
    expected->form_id = reverse != 0u ? UINT16_C(2596) : UINT16_C(2595);
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = FAMILY_FLAGS;
    expected->operand_count = 3u;

    expected->operand[0].type = CDISASM_ARM_OPERAND_PREDICATE;
    expected->operand[0].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_P0 + (word & 15u));
    expected->operand[0].extend_type = (cdisasm_arm_extend_type)element_size;
    expected->operand[0].flags =
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;

    expected->operand[1].type = CDISASM_OPERAND_REGISTER;
    expected->operand[1].reg = xreg((word >> 5) & 31u);
    expected->operand[1].size = 8u;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;

    expected->operand[2].type = CDISASM_OPERAND_REGISTER;
    expected->operand[2].reg = xreg((word >> 16) & 31u);
    expected->operand[2].size = 8u;
    expected->operand[2].access = CDISASM_OPERAND_ACCESS_READ;
}
#endif

static void expect_allocated(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        expected_instruction(word, &expected);
        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated leaf did not decode");
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated structured metadata mismatch");
    }
#else
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded allocated leaf");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF allocated ownership mismatch");
#endif
}

static void test_complete_family(void)
{
    uint32_t allocated_count = 0u;
    unsigned reverse;
    unsigned size;
    unsigned rm;
    unsigned rn;
    unsigned pd;

    for (reverse = 0u; reverse < 2u; ++reverse) {
        for (size = 0u; size < 4u; ++size) {
            for (rm = 0u; rm < 32u; ++rm) {
                for (rn = 0u; rn < 32u; ++rn) {
                    for (pd = 0u; pd < 16u; ++pd) {
                        expect_allocated(family_word(
                            reverse, size, rm, rn, pd));
                        ++allocated_count;
                    }
                }
            }
        }
    }
    EXPECT(allocated_count == UINT32_C(131072));
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

static void test_feature_alternative(void)
{
    static const uint32_t words[] = {
        UINT32_C(0x25203000), UINT32_C(0x25ff33ff)
    };
    unsigned index;

    for (index = 0u; index < sizeof(words) / sizeof(words[0]); ++index) {
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
}

static void test_transport(void)
{
    static const uint32_t words[] = {
        UINT32_C(0x256d3125), UINT32_C(0x25a33237)
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

static void test_formatter(void)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;

    expect_format(UINT32_C(0x25203000), "whilewr p0.b, x0, x0");
    expect_format(UINT32_C(0x256d3125), "whilewr p5.h, x9, x13");
    expect_format(UINT32_C(0x25e033ef), "whilewr p15.d, xzr, x0");
    expect_format(UINT32_C(0x25203010), "whilerw p0.b, x0, x0");
    expect_format(UINT32_C(0x25a33237), "whilerw p7.s, x17, x3");
    expect_format(UINT32_C(0x25ff33ff), "whilerw p15.d, xzr, xzr");

    EXPECT(decode_word(UINT32_C(0x256d3125), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_WHILERW;
    reject_forgery(&forged);
    forged = instruction;
    forged.form_id = UINT16_C(2596);
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
    forged.operand[1].access = CDISASM_OPERAND_ACCESS_WRITE;
    reject_forgery(&forged);

    EXPECT(decode_word(UINT32_C(0x25201c00), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_WHILEWR;
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
    test_feature_alternative();
    test_transport();
    test_formatter();

    if (failures != 0) {
        fprintf(stderr, "%d WHILEWR/WHILERW test(s) failed\n", failures);
        return 1;
    }
    printf("WHILEWR/WHILERW tests passed (131072 allocated encodings)\n");
    return 0;
}
