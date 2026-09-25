#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x16c000)
#define ELEMENT_COUNT_MASK UINT32_C(0xfff0fc00)
#define ELEMENT_COUNT_FLAGS                                             \
    CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

typedef struct element_count_descriptor {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    uint8_t element_size;
    cdisasm_operand_access access;
    int vector_destination;
} element_count_descriptor;

static const element_count_descriptor descriptors[18] = {
    { UINT32_C(0x0470c000), CDISASM_ARM_NAME_INCH, UINT16_C(2374),
      2u, CDISASM_OPERAND_ACCESS_READ_WRITE, 1 },
    { UINT32_C(0x0470c400), CDISASM_ARM_NAME_DECH, UINT16_C(2375),
      2u, CDISASM_OPERAND_ACCESS_READ_WRITE, 1 },
    { UINT32_C(0x04b0c000), CDISASM_ARM_NAME_INCW, UINT16_C(2376),
      4u, CDISASM_OPERAND_ACCESS_READ_WRITE, 1 },
    { UINT32_C(0x04b0c400), CDISASM_ARM_NAME_DECW, UINT16_C(2377),
      4u, CDISASM_OPERAND_ACCESS_READ_WRITE, 1 },
    { UINT32_C(0x04f0c000), CDISASM_ARM_NAME_INCD, UINT16_C(2378),
      8u, CDISASM_OPERAND_ACCESS_READ_WRITE, 1 },
    { UINT32_C(0x04f0c400), CDISASM_ARM_NAME_DECD, UINT16_C(2379),
      8u, CDISASM_OPERAND_ACCESS_READ_WRITE, 1 },
    { UINT32_C(0x0420e000), CDISASM_ARM_NAME_CNTB, UINT16_C(2380),
      0u, CDISASM_OPERAND_ACCESS_WRITE, 0 },
    { UINT32_C(0x0460e000), CDISASM_ARM_NAME_CNTH, UINT16_C(2381),
      0u, CDISASM_OPERAND_ACCESS_WRITE, 0 },
    { UINT32_C(0x04a0e000), CDISASM_ARM_NAME_CNTW, UINT16_C(2382),
      0u, CDISASM_OPERAND_ACCESS_WRITE, 0 },
    { UINT32_C(0x04e0e000), CDISASM_ARM_NAME_CNTD, UINT16_C(2383),
      0u, CDISASM_OPERAND_ACCESS_WRITE, 0 },
    { UINT32_C(0x0430e000), CDISASM_ARM_NAME_INCB, UINT16_C(2384),
      0u, CDISASM_OPERAND_ACCESS_READ_WRITE, 0 },
    { UINT32_C(0x0430e400), CDISASM_ARM_NAME_DECB, UINT16_C(2385),
      0u, CDISASM_OPERAND_ACCESS_READ_WRITE, 0 },
    { UINT32_C(0x0470e000), CDISASM_ARM_NAME_INCH, UINT16_C(2386),
      0u, CDISASM_OPERAND_ACCESS_READ_WRITE, 0 },
    { UINT32_C(0x0470e400), CDISASM_ARM_NAME_DECH, UINT16_C(2387),
      0u, CDISASM_OPERAND_ACCESS_READ_WRITE, 0 },
    { UINT32_C(0x04b0e000), CDISASM_ARM_NAME_INCW, UINT16_C(2388),
      0u, CDISASM_OPERAND_ACCESS_READ_WRITE, 0 },
    { UINT32_C(0x04b0e400), CDISASM_ARM_NAME_DECW, UINT16_C(2389),
      0u, CDISASM_OPERAND_ACCESS_READ_WRITE, 0 },
    { UINT32_C(0x04f0e000), CDISASM_ARM_NAME_INCD, UINT16_C(2390),
      0u, CDISASM_OPERAND_ACCESS_READ_WRITE, 0 },
    { UINT32_C(0x04f0e400), CDISASM_ARM_NAME_DECD, UINT16_C(2391),
      0u, CDISASM_OPERAND_ACCESS_READ_WRITE, 0 }
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

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_arm_mode mode,
    size_t size, cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, size, TEST_ADDRESS, options, instruction);
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
static void expected_immediate(cdisasm_arm_operand *operand, uint64_t value)
{
    operand->type = CDISASM_OPERAND_IMMEDIATE;
    operand->imm = value;
    operand->size = 1u;
    operand->access = CDISASM_OPERAND_ACCESS_READ;
}

static void expected_instruction(
    const element_count_descriptor *descriptor, uint32_t word,
    cdisasm_arm_instruction *expected)
{
    unsigned encoded_register = word & 31u;

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = descriptor->name_id;
    expected->form_id = descriptor->form_id;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = ELEMENT_COUNT_FLAGS;
    expected->operand_count = 3u;
    if (descriptor->vector_destination) {
        expected->operand[0].type =
            CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
        expected->operand[0].reg = (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_Z0 + encoded_register);
        expected->operand[0].extend_type = descriptor->element_size;
    } else {
        expected->operand[0].type = CDISASM_OPERAND_REGISTER;
        expected->operand[0].reg = encoded_register == 31u
            ? CDISASM_ARM_REG_XZR
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                + encoded_register);
        expected->operand[0].size = 8u;
    }
    expected->operand[0].access = descriptor->access;
    expected_immediate(
        &expected->operand[1], (word >> 5) & UINT32_C(31));
    expected_immediate(
        &expected->operand[2], ((word >> 16) & UINT32_C(15)) + 1u);
}
#endif

static void expect_allocated(
    const element_count_descriptor *descriptor, uint32_t word,
    uint32_t *decoded_count)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded;

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        expected_instruction(descriptor, word, &expected);
        domain_expect(decoded == 4u, word,
            "allocated element-count word did not decode");
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "element-count structured metadata mismatch");
        *decoded_count += decoded == 4u;
    }
#else
    (void)descriptor;
    (void)decoded_count;
    domain_expect(decoded == 0u, word,
        "extras-OFF decoded allocated element-count word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF allocated ownership mismatch");
#endif
}

static void expect_reserved(uint32_t word, uint32_t *reserved_count)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved element-count control decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved element-count control was not INVALID");
    ++*reserved_count;
}

static void test_complete_parent_envelopes(void)
{
    static const uint32_t parents[3] = {
        UINT32_C(0x0430c000), UINT32_C(0x0420e000),
        UINT32_C(0x0430e000)
    };
    uint32_t decoded_count = 0u;
    uint32_t reserved_count = 0u;
    unsigned family;
    unsigned size;
    unsigned operation;
    unsigned imm4;
    unsigned pattern;
    unsigned reg;

    for (family = 0u; family < 3u; ++family) {
        for (size = 0u; size < 4u; ++size) {
            for (operation = 0u; operation < 2u; ++operation) {
                for (imm4 = 0u; imm4 < 16u; ++imm4) {
                    for (pattern = 0u; pattern < 32u; ++pattern) {
                        for (reg = 0u; reg < 32u; ++reg) {
                            uint32_t word = parents[family]
                                | ((uint32_t)size << 22)
                                | ((uint32_t)imm4 << 16)
                                | ((uint32_t)operation << 10)
                                | ((uint32_t)pattern << 5) | reg;
                            int allocated = family == 2u
                                || (family == 0u && size != 0u)
                                || (family == 1u && operation == 0u);

                            if (allocated) {
                                unsigned index = family == 0u
                                    ? (size - 1u) * 2u + operation
                                    : family == 1u ? 6u + size
                                    : 10u + size * 2u + operation;

                                domain_expect(
                                    (word & ELEMENT_COUNT_MASK)
                                        == descriptors[index].value,
                                    word, "word escaped allocated leaf");
                                expect_allocated(
                                    &descriptors[index], word,
                                    &decoded_count);
                            } else {
                                expect_reserved(word, &reserved_count);
                            }
                        }
                    }
                }
            }
        }
    }
#if USE_EXTRA_OPCODES
    EXPECT(decoded_count == UINT32_C(294912));
#else
    EXPECT(decoded_count == 0u);
#endif
    EXPECT(reserved_count == UINT32_C(98304));
}

static void expect_profile(
    const element_count_descriptor *descriptor,
    cdisasm_arm_cpu_id cpu_id, cdisasm_status enabled_status)
{
    cdisasm_arm_instruction instruction;
    uint32_t word = descriptor->value | UINT32_C(0x3e0);
    cdisasm_status expected;
    uint32_t decoded;

#if USE_EXTRA_OPCODES
    expected = enabled_status;
#else
    (void)enabled_status;
    expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(
        word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.form_id == descriptor->form_id);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_feature_alternative_and_profiles(void)
{
    cdisasm_arm_cpu_id cpu_id;
    unsigned index;

    for (index = 0u; index < 18u; ++index) {
        expect_profile(
            &descriptors[index], CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_profile(
            &descriptors[index], CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);
        expect_profile(
            &descriptors[index], CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_OK);
        expect_profile(
            &descriptors[index], CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
    }
    for (cpu_id = CDISASM_ARM_CPU_FIRST;
         cpu_id <= CDISASM_ARM_CPU_LAST; ++cpu_id) {
        if (cpu_id == CDISASM_ARM_CPU_FUJITSU_A64FX
            || cpu_id == CDISASM_ARM_CPU_APPLE_A18
            || cpu_id == CDISASM_ARM_CPU_APPLE_M4
            || (cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) == 0u) {
            continue;
        }
        for (index = 0u; index < 18u; ++index) {
            expect_profile(
                &descriptors[index], cpu_id,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
}

static void test_transport_and_boundaries(void)
{
    static const uint32_t words[3] = {
        UINT32_C(0x0470c3e0), UINT32_C(0x042fe01f),
        UINT32_C(0x04ffe7ff)
    };
    unsigned index;

    for (index = 0u; index < 3u; ++index) {
        cdisasm_arm_instruction little;
        cdisasm_arm_instruction other;
        uint8_t bytes[4];
        unsigned boundary;

        memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(
            words[index], CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
        EXPECT(decode_word(
            words[index], CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
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
            cdisasm_status expected = boundary == 0u
                ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

            memset(&other, 0xa5, sizeof(other));
            EXPECT(decode_word(
                words[index], CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, boundary,
                CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
            EXPECT(instruction_is_error_only(&other, expected));
        }
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(
    uint32_t word, const char *expected, const char *uppercase)
{
    cdisasm_arm_instruction instruction;
    char text[64];
    char short_text[5];
    size_t length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u) == length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_0,
        short_text, sizeof(short_text)) == length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
    EXPECT(cdisasm_arm_format(
        &instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text)) == strlen(uppercase));
    EXPECT(strcmp(text, uppercase) == 0);
}

static void test_formatter(void)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[64];

    expect_format(UINT32_C(0x0420e3e0), "cntb x0", "CNTB x0");
    expect_format(UINT32_C(0x0460e01f),
        "cnth xzr, pow2", "CNTH xzr, pow2");
    expect_format(UINT32_C(0x04afe127),
        "cntw x7, vl16, mul #16", "CNTW x7, vl16, mul #16");
    expect_format(UINT32_C(0x0430e3bf),
        "incb xzr, mul4", "INCB xzr, mul4");
    expect_format(UINT32_C(0x0471e7c9),
        "dech x9, mul3, mul #2", "DECH x9, mul3, mul #2");
    expect_format(UINT32_C(0x04ffe3e0),
        "incd x0, all, mul #16", "INCD x0, all, mul #16");
    expect_format(UINT32_C(0x0470c3e0),
        "inch z0.h", "INCH z0.h");
    expect_format(UINT32_C(0x04b5c5df),
        "decw z31.s, #14, mul #6", "DECW z31.s, #14, mul #6");
    expect_format(UINT32_C(0x04f2c1b1),
        "incd z17.d, vl256, mul #3", "INCD z17.d, vl256, mul #3");

    EXPECT(decode_word(
        UINT32_C(0x04b5c5df), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
#define REJECT_FORGERY(statement)                                         \
    do {                                                                  \
        forged = instruction;                                             \
        statement;                                                        \
        memset(text, 0xa5, sizeof(text));                                 \
        EXPECT(cdisasm_arm_format(                                        \
            &forged, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,                 \
            text, sizeof(text)) == 0u);                                   \
        EXPECT(text[0] == '\0');                                          \
    } while (0)
    REJECT_FORGERY(forged.form_id = UINT16_C(2374));
    REJECT_FORGERY(forged.name_id = CDISASM_ARM_NAME_INCW);
    REJECT_FORGERY(forged.instruction_flags ^=
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    REJECT_FORGERY(forged.operand[0].reg = CDISASM_ARM_REG_Z30);
    REJECT_FORGERY(forged.operand[1].imm = 15u);
    REJECT_FORGERY(forged.operand[2].imm = 7u);
    REJECT_FORGERY(forged.raw_instruction ^= UINT32_C(0x00010000));
#undef REJECT_FORGERY
}
#else
static void test_formatter(void)
{
}
#endif

int main(void)
{
    test_complete_parent_envelopes();
    test_feature_alternative_and_profiles();
    test_transport_and_boundaries();
    test_formatter();

    if (failures != 0) {
        fprintf(stderr, "%d A64 SVE element-count test(s) failed\n",
                failures);
        return 1;
    }
    printf("A64 SVE element-count tests passed "
           "(294912 allocated; 98304 reserved encodings)\n");
    return 0;
}
