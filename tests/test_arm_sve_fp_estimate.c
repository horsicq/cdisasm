#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_FRECPX == UINT16_C(428),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_FRECPE == UINT16_C(429),
               "SVE FRECPE ID must be append-only");
_Static_assert(CDISASM_ARM_NAME_FRSQRTE == UINT16_C(430),
               "SVE FRSQRTE ID order changed");
_Static_assert(CDISASM_ARM_NAME_FRSQRTE < CDISASM_ARM_NAME_COUNT,
               "SVE FP-estimate IDs left the ARM catalog");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 20) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",      \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static uint32_t fp_estimate_word(unsigned operation, unsigned size_code,
                                 unsigned zn, unsigned zd)
{
    return UINT32_C(0x650e3000)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)operation << 16)
        | ((uint32_t)zn << 5)
        | (uint32_t)zd;
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
        UINT64_C(0x118000), options, instruction);
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
static int zreg_matches(const cdisasm_arm_operand *operand,
                        unsigned encoded, uint8_t element_size,
                        cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int operand_is_zeroed(const cdisasm_arm_operand *operand)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            uint32_t word, unsigned operation,
                            unsigned size_code, unsigned zn, unsigned zd)
{
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == (operation != 0u
            ? CDISASM_ARM_NAME_FRSQRTE : CDISASM_ARM_NAME_FRECPE)
        && instruction->address == UINT64_C(0x118000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 2u
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        && zreg_matches(&instruction->operand[0], zd, element_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        && zreg_matches(&instruction->operand[1], zn, element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && operand_is_zeroed(&instruction->operand[2])
        && operand_is_zeroed(&instruction->operand[3]);
}
#endif

static void test_exhaustive_exact_envelope(void)
{
    uint32_t allocated_words = 0u;
    uint32_t reserved_words = 0u;
    unsigned size_code;

    for (size_code = 0u; size_code < 4u; ++size_code) {
        unsigned operation;

        for (operation = 0u; operation < 2u; ++operation) {
            unsigned zn;

            for (zn = 0u; zn < 32u; ++zn) {
                unsigned zd;

                for (zd = 0u; zd < 32u; ++zd) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = fp_estimate_word(
                        operation, size_code, zn, zd);
                    uint32_t decoded;

                    EXPECT((word & UINT32_C(0xff3efc00))
                        == UINT32_C(0x650e3000));
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY,
                        CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    if (size_code == 0u) {
                        ++reserved_words;
                        EXPECT(decoded == 0u);
                        EXPECT(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                    } else {
                        ++allocated_words;
#if USE_EXTRA_OPCODES
                        EXPECT(decoded == 4u);
                        EXPECT(metadata_matches(
                            &instruction, word, operation,
                            size_code, zn, zd));
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
    EXPECT(allocated_words == UINT32_C(6144));
    EXPECT(reserved_words == UINT32_C(2048));
    EXPECT(allocated_words + reserved_words == UINT32_C(8192));
}

static void expect_cpu_status(uint32_t word, cdisasm_arm_cpu_id cpu_id,
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

static void test_capability_routes(void)
{
    unsigned operation;

    for (operation = 0u; operation < 2u; ++operation) {
        uint32_t word = fp_estimate_word(operation, 2u, 13u, 7u);

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);
        /* Apple M4 has SME but no SVE, proving the SME-only route. */
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M3,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_masked_bit_neighbors(void)
{
    const uint32_t fixed_mask = UINT32_C(0xff3efc00);
    const uint32_t canonical = fp_estimate_word(0u, 2u, 13u, 7u);
    unsigned bit;

    for (bit = 0u; bit < 32u; ++bit) {
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        if ((fixed_mask & (UINT32_C(1) << bit)) == 0u) {
            continue;
        }
        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(canonical ^ (UINT32_C(1) << bit),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(decoded == 0u
            || (instruction.name_id != CDISASM_ARM_NAME_FRECPE
                && instruction.name_id != CDISASM_ARM_NAME_FRSQRTE)
            || (instruction.instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) == 0u);
    }
}

static void test_endian_dispatch_modes_and_boundaries(void)
{
    uint32_t word = fp_estimate_word(1u, 3u, 31u, 31u);
    uint32_t reserved = fp_estimate_word(0u, 0u, 13u, 7u);
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
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x118000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x118000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x118000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x118000),
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
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(
            &other, CDISASM_STATUS_TRUNCATED));
    }

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
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

static void test_formatter(void)
{
    static const char *const mnemonics[] = { "frecpe", "frsqrte" };
    static const char suffixes[] = { 'h', 's', 'd' };
    unsigned operation;

    for (operation = 0u; operation < 2u; ++operation) {
        unsigned size_index;

        for (size_index = 0u; size_index < 3u; ++size_index) {
            char expected[96];
            int expected_length = snprintf(
                expected, sizeof(expected), "%s z7.%c, z13.%c",
                mnemonics[operation], suffixes[size_index],
                suffixes[size_index]);

            EXPECT(expected_length > 0);
            EXPECT((size_t)expected_length < sizeof(expected));
            expect_format(fp_estimate_word(
                operation, size_index + 1u, 13u, 7u), expected);
        }
    }

    {
        cdisasm_arm_instruction instruction;
        char text[96];
        static const char expected[] = "FRSQRTE z7.s, z13.s";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(fp_estimate_word(1u, 2u, 13u, 7u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_exact_envelope();
    test_capability_routes();
    test_masked_bit_neighbors();
    test_endian_dispatch_modes_and_boundaries();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE FP-estimate test(s) failed\n",
            failures);
        return 1;
    }
    printf("ARM SVE FP-estimate tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=8192, allocated=6144, "
           "reserved=2048)\n", USE_EXTRA_OPCODES);
    return 0;
}
