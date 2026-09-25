#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

typedef struct bitcount_descriptor {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
    unsigned maximum_size;
} bitcount_descriptor;

/* Pinned AARCHMRS forms CLS_asimdmisc_R, CNT_asimdmisc_R, and
 * CLZ_asimdmisc_R.  LLVM 21 independently emits the same fixed words. */
static const bitcount_descriptor descriptors[] = {
    { UINT32_C(0x0e204800), CDISASM_ARM_NAME_CLS,
      UINT16_C(6007), "cls", 2u },
    { UINT32_C(0x0e205800), CDISASM_ARM_NAME_CNT,
      UINT16_C(6008), "cnt", 0u },
    { UINT32_C(0x2e204800), CDISASM_ARM_NAME_CLZ,
      UINT16_C(6041), "clz", 2u }
};

_Static_assert(CDISASM_ARM_NAME_CLS == UINT16_C(365),
               "established CLS ID changed");
_Static_assert(CDISASM_ARM_NAME_CNT == UINT16_C(305),
               "established CNT ID changed");
_Static_assert(CDISASM_ARM_NAME_CLZ == UINT16_C(220),
               "established CLZ ID changed");

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

static uint32_t bitcount_word(const bitcount_descriptor *descriptor,
                              unsigned q, unsigned size_code,
                              unsigned rn, unsigned rd)
{
    return descriptor->value | ((uint32_t)q << 30)
        | ((uint32_t)size_code << 22) | ((uint32_t)rn << 5)
        | (uint32_t)rd;
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
        UINT64_C(0x12d000), options, instruction);
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
static int vector_matches(const cdisasm_arm_operand *operand,
                          unsigned encoded, uint8_t total_size,
                          uint8_t element_size,
                          cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded);
    expected.size = total_size;
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.scale = (uint8_t)(total_size / element_size);
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_matches(
    const cdisasm_arm_instruction *instruction, uint32_t word,
    const bitcount_descriptor *descriptor, unsigned q,
    unsigned size_code, unsigned rn, unsigned rd)
{
    uint8_t total_size = q != 0u ? 16u : 8u;
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == descriptor->name_id
        && instruction->form_id == descriptor->form_id
        && instruction->address == UINT64_C(0x12d000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 2u
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && vector_matches(&instruction->operand[0], rd,
            total_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && vector_matches(&instruction->operand[1], rn,
            total_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_envelopes(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const bitcount_descriptor *descriptor =
            &descriptors[descriptor_index];
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 0u; size_code < 4u; ++size_code) {
                unsigned rn;

                for (rn = 0u; rn < 32u; ++rn) {
                    unsigned rd;

                    for (rd = 0u; rd < 32u; ++rd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = bitcount_word(
                            descriptor, q, size_code, rn, rd);
                        uint32_t decoded;

                        EXPECT((word & UINT32_C(0xbf3ffc00))
                            == descriptor->value);
                        memset(&instruction, 0xa5,
                            sizeof(instruction));
                        decoded = decode_word(word,
                            CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE,
                            &instruction);
                        if (size_code > descriptor->maximum_size) {
                            ++reserved;
                            EXPECT(decoded == 0u);
                            EXPECT(instruction_is_error_only(&instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                        } else {
                            ++allocated;
#if USE_EXTRA_OPCODES
                            EXPECT(decoded == 4u);
                            EXPECT(metadata_matches(
                                &instruction, word, descriptor,
                                q, size_code, rn, rd));
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
    }
    EXPECT(allocated == UINT32_C(14336));
    EXPECT(reserved == UINT32_C(10240));
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

static void test_profiles_and_fixed_neighbors(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const bitcount_descriptor *descriptor =
            &descriptors[descriptor_index];
        uint32_t word = bitcount_word(descriptor, 1u, 0u, 13u, 7u);
        unsigned bit;

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY,
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

            if ((UINT32_C(0xbf3ffc00)
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
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x12d000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x12d000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_be(reserved, bytes);
    memset(&other, 0xa5, sizeof(other));
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x12d000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_INSTRUCTION));

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12d000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12d000),
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
}

static void test_endian_dispatch_modes_and_boundaries(void)
{
    cdisasm_arm_instruction instruction;
    uint32_t cls = bitcount_word(&descriptors[0], 1u, 2u, 13u, 7u);
    uint32_t cls_reserved = bitcount_word(
        &descriptors[0], 1u, 3u, 13u, 7u);
    uint32_t cnt = bitcount_word(&descriptors[1], 0u, 0u, 31u, 31u);
    uint32_t cnt_reserved = bitcount_word(
        &descriptors[1], 0u, 1u, 31u, 31u);
    uint32_t clz = bitcount_word(&descriptors[2], 0u, 1u, 0u, 31u);
    uint32_t clz_reserved = bitcount_word(
        &descriptors[2], 0u, 3u, 0u, 31u);

    check_transport(cls, cls_reserved);
    check_transport(cnt, cnt_reserved);
    check_transport(clz, clz_reserved);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(cls, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(cnt, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[80];
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
    static const char suffixes[] = { 'b', 'h', 's' };
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const bitcount_descriptor *descriptor =
            &descriptors[descriptor_index];
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 0u;
                 size_code <= descriptor->maximum_size;
                 ++size_code) {
                unsigned total_size = q != 0u ? 16u : 8u;
                unsigned count = total_size / (1u << size_code);
                char expected[80];
                int length = snprintf(expected, sizeof(expected),
                    "%s v7.%u%c, v13.%u%c", descriptor->mnemonic,
                    count, suffixes[size_code], count,
                    suffixes[size_code]);

                EXPECT(length > 0 && (size_t)length < sizeof(expected));
                expect_format(bitcount_word(
                    descriptor, q, size_code, 13u, 7u), expected);
            }
        }
    }
    {
        cdisasm_arm_instruction instruction;
        char text[80];
        static const char expected[] = "CLZ v31.4s, v0.4s";
        uint32_t word = bitcount_word(
            &descriptors[2], 1u, 2u, 0u, 31u);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
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
    test_exhaustive_envelopes();
    test_profiles_and_fixed_neighbors();
    test_endian_dispatch_modes_and_boundaries();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM Advanced SIMD bit/count test(s) failed\n",
            failures);
        return 1;
    }
    printf("ARM Advanced SIMD CLS/CNT/CLZ tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=14336, reserved=10240)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
