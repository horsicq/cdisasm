#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define UDF_MASK UINT32_C(0xffff0000)
#define UDF_VALUE UINT32_C(0x00000000)
#define UDF_FORM UINT16_C(4387)

_Static_assert(CDISASM_ARM_NAME_UDF == UINT16_C(1752),
               "generated UDF mnemonic ID changed");
_Static_assert(CDISASM_GROUP_INTERRUPT == UINT32_C(8),
               "generic interrupt-group ABI changed");

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
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x130000),
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

#if USE_EXTRA_OPCODES
static void expected_instruction(
    uint32_t immediate, cdisasm_arm_instruction *expected)
{
    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x130000);
    expected->opcode_size = 4u;
    expected->opcode_groups = CDISASM_GROUP_INTERRUPT;
    expected->raw_instruction = immediate;
    expected->name_id = CDISASM_ARM_NAME_UDF;
    expected->operand_count = 1u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->form_id = UDF_FORM;
    expected->operand[0].type = CDISASM_OPERAND_IMMEDIATE;
    expected->operand[0].imm = immediate;
    expected->operand[0].size = 2u;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_READ;
}
#endif

static void test_exhaustive_immediate_domain(void)
{
    uint32_t immediate;
    uint32_t decoded_count = 0u;

    for (immediate = 0u; immediate <= UINT32_C(0xffff); ++immediate) {
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        domain_expect(
            (immediate & UDF_MASK) == UDF_VALUE,
            immediate, "word escaped the exact UDF leaf");
        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(
            immediate, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        {
            cdisasm_arm_instruction expected;

            expected_instruction(immediate, &expected);
            domain_expect(decoded == 4u, immediate,
                "allocated UDF word did not decode");
            domain_expect(memcmp(
                &instruction, &expected, sizeof(expected)) == 0,
                immediate, "UDF metadata mismatch");
            decoded_count += decoded == 4u;
        }
#else
        domain_expect(decoded == 0u, immediate,
            "extras-OFF decoded a UDF word");
        domain_expect(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
            immediate, "extras-OFF UDF ownership mismatch");
#endif
    }
#if USE_EXTRA_OPCODES
    EXPECT(decoded_count == UINT32_C(65536));
#else
    EXPECT(decoded_count == 0u);
#endif
}

static void test_fixed_neighbors(void)
{
    const uint32_t word = UINT32_C(0x00005a5a);
    unsigned bit;

    for (bit = 16u; bit < 32u; ++bit) {
        cdisasm_arm_instruction instruction;
        uint32_t neighbor = word ^ (UINT32_C(1) << bit);
        uint32_t decoded;

        EXPECT((neighbor & UDF_MASK) != UDF_VALUE);
        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(
            neighbor, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(decoded != 4u
            || instruction.name_id != CDISASM_ARM_NAME_UDF
            || instruction.form_id != UDF_FORM);
#else
        (void)decoded;
#endif
    }
}

static void expect_cpu_status(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_status enabled_status)
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
    decoded = decode_word(
        word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_UDF);
        EXPECT(instruction.form_id == UDF_FORM);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_cpu_profiles(void)
{
    cdisasm_arm_cpu_id cpu_id;

    expect_cpu_status(
        UINT32_C(0x00001234), CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    for (cpu_id = CDISASM_ARM_CPU_FIRST;
         cpu_id <= CDISASM_ARM_CPU_LAST; ++cpu_id) {
        if ((cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) != 0u) {
            expect_cpu_status(
                UINT32_C(0x0000a55a), cpu_id, CDISASM_STATUS_OK);
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
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif

    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x130000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x130000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x130000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x130000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    for (boundary = 0u; boundary < 4u; ++boundary) {
        cdisasm_status expected = boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, expected));
    }
}

static void test_transport_and_modes(void)
{
    cdisasm_arm_instruction instruction;

    check_transport(UINT32_C(0x00000000));
    check_transport(UINT32_C(0x00001234));
    check_transport(UINT32_C(0x0000ffff));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        UINT32_C(0x00001234), CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        UINT32_C(0x00001234), CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[48];
    char short_text[8];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7,
        NULL, 0u) == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_0,
        short_text, sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void test_formatter(void)
{
    expect_format(UINT32_C(0x00000000), "udf #0x0");
    expect_format(UINT32_C(0x00000001), "udf #0x1");
    expect_format(UINT32_C(0x00001234), "udf #0x1234");
    expect_format(UINT32_C(0x0000ffff), "udf #0xffff");
}

static void expect_invalid_format(cdisasm_arm_instruction *instruction)
{
    char text[48];

    memset(text, 0xa5, sizeof(text));
    EXPECT(cdisasm_arm_format(instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == 0u);
    EXPECT(text[0] == '\0');
}

static void test_formatter_rejects_forged_schema(void)
{
    cdisasm_arm_instruction good;
    cdisasm_arm_instruction forged;

    memset(&good, 0xa5, sizeof(good));
    EXPECT(decode_word(
        UINT32_C(0x00001234), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &good) == 4u);

    forged = good;
    forged.form_id = UINT16_C(4388);
    expect_invalid_format(&forged);
    forged = good;
    forged.raw_instruction |= UINT32_C(0x00010000);
    expect_invalid_format(&forged);
    forged = good;
    forged.raw_instruction = UINT32_C(0x00004321);
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[0].imm = UINT64_C(0x10000);
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[0].size = 1u;
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[0].flags = CDISASM_OPERAND_FLAG_SIGNED;
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[0].shift_type = CDISASM_ARM_SHIFT_LSL;
    forged.operand[0].shift_amount = 1u;
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[0].shift_type = CDISASM_ARM_SHIFT_LSR;
    expect_invalid_format(&forged);
    forged = good;
    forged.opcode_groups = CDISASM_GROUP_NONE;
    expect_invalid_format(&forged);
    forged = good;
    forged.opcode_groups |= CDISASM_GROUP_PRIVILEGED;
    expect_invalid_format(&forged);
    forged = good;
    forged.instruction_flags = CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL;
    expect_invalid_format(&forged);
    forged = good;
    forged.operand_count = 0u;
    expect_invalid_format(&forged);
    forged = good;
    forged.isa_id = CDISASM_ARM_ISA_A32;
    expect_invalid_format(&forged);
}
#else
static void test_formatter(void)
{
}

static void test_formatter_rejects_forged_schema(void)
{
}
#endif

int main(void)
{
    test_exhaustive_immediate_domain();
    test_fixed_neighbors();
    test_cpu_profiles();
    test_transport_and_modes();
    test_formatter();
    test_formatter_rejects_forged_schema();

    if (failures != 0) {
        fprintf(stderr, "%d A64 UDF test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
