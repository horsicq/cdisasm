#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_FADDA == UINT16_C(420),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_FRINTN == UINT16_C(421),
               "SVE FP unary IDs must be append-only");
_Static_assert(CDISASM_ARM_NAME_FRINTP == UINT16_C(422),
               "SVE FP unary ID order changed");
_Static_assert(CDISASM_ARM_NAME_FRINTM == UINT16_C(423),
               "SVE FP unary ID order changed");
_Static_assert(CDISASM_ARM_NAME_FRINTZ == UINT16_C(424),
               "SVE FP unary ID order changed");
_Static_assert(CDISASM_ARM_NAME_FRINTA == UINT16_C(425),
               "SVE FP unary ID order changed");
_Static_assert(CDISASM_ARM_NAME_FRINTX == UINT16_C(426),
               "SVE FP unary ID order changed");
_Static_assert(CDISASM_ARM_NAME_FRINTI == UINT16_C(427),
               "SVE FP unary ID order changed");
_Static_assert(CDISASM_ARM_NAME_FRECPX == UINT16_C(428),
               "SVE FP unary terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_FSQRT == UINT16_C(234),
               "established FSQRT ID moved");
_Static_assert(CDISASM_ARM_NAME_FRECPX < CDISASM_ARM_NAME_COUNT,
               "SVE FP unary terminal ID is outside the catalog");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(431),
               "later ARM mnemonic IDs were lost");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

typedef struct fp_unary_operation {
    unsigned control;
    cdisasm_arm_name_id name_id;
#if USE_DISASM_FORMAT
    const char *mnemonic;
#endif
} fp_unary_operation;

static const fp_unary_operation fp_unary_operations[] = {
    { 0u, CDISASM_ARM_NAME_FRINTN,
#if USE_DISASM_FORMAT
      "frintn"
#endif
    },
    { 1u, CDISASM_ARM_NAME_FRINTP,
#if USE_DISASM_FORMAT
      "frintp"
#endif
    },
    { 2u, CDISASM_ARM_NAME_FRINTM,
#if USE_DISASM_FORMAT
      "frintm"
#endif
    },
    { 3u, CDISASM_ARM_NAME_FRINTZ,
#if USE_DISASM_FORMAT
      "frintz"
#endif
    },
    { 4u, CDISASM_ARM_NAME_FRINTA,
#if USE_DISASM_FORMAT
      "frinta"
#endif
    },
    { 6u, CDISASM_ARM_NAME_FRINTX,
#if USE_DISASM_FORMAT
      "frintx"
#endif
    },
    { 7u, CDISASM_ARM_NAME_FRINTI,
#if USE_DISASM_FORMAT
      "frinti"
#endif
    },
    { 12u, CDISASM_ARM_NAME_FRECPX,
#if USE_DISASM_FORMAT
      "frecpx"
#endif
    },
    { 13u, CDISASM_ARM_NAME_FSQRT,
#if USE_DISASM_FORMAT
      "fsqrt"
#endif
    }
};

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

static uint32_t fp_unary_word(unsigned control, unsigned size_code,
                              int zeroing, unsigned pg,
                              unsigned zn, unsigned zd)
{
    uint32_t word;

    if (zeroing) {
        word = UINT32_C(0x64188000)
            | ((uint32_t)(control >> 2) << 16)
            | ((uint32_t)(control & 3u) << 13);
    } else {
        word = UINT32_C(0x6500a000)
            | ((uint32_t)control << 16);
    }
    return word
        | ((uint32_t)size_code << 22)
        | ((uint32_t)pg << 10)
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

static int predicate_matches(const cdisasm_arm_operand *operand,
                             unsigned encoded, uint8_t element_size,
                             int zeroing)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_PREDICATE;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.flags = zeroing
        ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
        : CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            const fp_unary_operation *operation,
                            uint32_t word, unsigned size_code,
                            int zeroing, unsigned pg,
                            unsigned zn, unsigned zd)
{
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == operation->name_id
        && instruction->address == UINT64_C(0x118000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 3u
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        && zreg_matches(&instruction->operand[0], zd, element_size,
            zeroing ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ_WRITE)
        && predicate_matches(
            &instruction->operand[1], pg, element_size, zeroing)
        && zreg_matches(&instruction->operand[2], zn, element_size,
            CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void expect_classifier_mask(uint32_t word, unsigned control,
                                   int zeroing)
{
    uint32_t mask;
    uint32_t value;

    if (!zeroing && control < 8u) {
        mask = UINT32_C(0xff38e000);
        value = UINT32_C(0x6500a000);
    } else if (!zeroing) {
        mask = UINT32_C(0xff3ee000);
        value = UINT32_C(0x650ca000);
    } else if (control < 8u) {
        mask = UINT32_C(0xff3e8000);
        value = UINT32_C(0x64188000);
    } else {
        mask = UINT32_C(0xff3fc000);
        value = UINT32_C(0x641b8000);
    }
    EXPECT((word & mask) == value);
}

static void test_exhaustive_exact_envelope(void)
{
    static const unsigned controls[] = {
        0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 12u, 13u
    };
    uint32_t allocated_words[2] = { 0u, 0u };
    uint32_t reserved_words[2] = { 0u, 0u };
    int zeroing;

    for (zeroing = 0; zeroing <= 1; ++zeroing) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            size_t control_index;

            for (control_index = 0u;
                 control_index < sizeof(controls) / sizeof(controls[0]);
                 ++control_index) {
                unsigned control = controls[control_index];
                int allocated = size_code != 0u && control != 5u;
                unsigned pg;

                for (pg = 0u; pg < 8u; ++pg) {
                    unsigned zn;

                    for (zn = 0u; zn < 32u; ++zn) {
                        unsigned zd;

                        for (zd = 0u; zd < 32u; ++zd) {
                            cdisasm_arm_instruction instruction;
                            uint32_t word = fp_unary_word(
                                control, size_code, zeroing, pg, zn, zd);
                            uint32_t decoded;

                            expect_classifier_mask(word, control, zeroing);
                            memset(&instruction, 0xa5,
                                   sizeof(instruction));
                            decoded = decode_word(
                                word, CDISASM_ARM_CPU_ANY,
                                CDISASM_ARM_MODE_A64, 4u,
                                CDISASM_ARM_DECODE_OPTION_NONE,
                                &instruction);
                            if (!allocated) {
                                ++reserved_words[zeroing];
                                EXPECT(decoded == 0u);
                                EXPECT(instruction_is_error_only(
                                    &instruction,
                                    CDISASM_STATUS_INVALID_INSTRUCTION));
                            } else {
                                const fp_unary_operation *operation =
                                    control_index < 5u
                                        ? &fp_unary_operations[control_index]
                                        : &fp_unary_operations[
                                            control_index - 1u];

                                ++allocated_words[zeroing];
#if USE_EXTRA_OPCODES
                                EXPECT(decoded == 4u);
                                EXPECT(metadata_matches(
                                    &instruction, operation, word,
                                    size_code, zeroing, pg, zn, zd));
#else
                                (void)operation;
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
        }
    }
    EXPECT(allocated_words[0] == UINT32_C(221184));
    EXPECT(allocated_words[1] == UINT32_C(221184));
    EXPECT(reserved_words[0] == UINT32_C(106496));
    EXPECT(reserved_words[1] == UINT32_C(106496));
    EXPECT(allocated_words[0] + allocated_words[1]
        == UINT32_C(442368));
    EXPECT(reserved_words[0] + reserved_words[1]
        == UINT32_C(212992));
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
    size_t index;

    for (index = 0u;
         index < sizeof(fp_unary_operations) / sizeof(fp_unary_operations[0]);
         ++index) {
        uint32_t merging = fp_unary_word(
            fp_unary_operations[index].control, 2u, 0, 3u, 13u, 7u);
        uint32_t zeroing = fp_unary_word(
            fp_unary_operations[index].control, 2u, 1, 3u, 13u, 7u);

        expect_cpu_status(
            merging, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_cpu_status(merging, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);
        /* Apple M4 has SME but no SVE, so this proves SME-only admission. */
        expect_cpu_status(merging, CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_cpu_status(merging, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(merging, CDISASM_ARM_CPU_APPLE_M3,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        /* No named CPU profile currently claims SVE2p2 or SME2p2. */
        expect_cpu_status(
            zeroing, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_cpu_status(zeroing, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(zeroing, CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(zeroing, CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_neighbors_endian_dispatch_and_boundaries(void)
{
    static const unsigned adjacent_controls[] = { 8u, 11u, 14u };
    uint32_t word = fp_unary_word(13u, 3u, 0, 7u, 31u, 5u);
    uint32_t reserved = fp_unary_word(5u, 2u, 1, 3u, 13u, 7u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned boundary;
    int zeroing;
    size_t index;

    for (zeroing = 0; zeroing <= 1; ++zeroing) {
        for (index = 0u;
             index < sizeof(adjacent_controls)
                / sizeof(adjacent_controls[0]);
             ++index) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                fp_unary_word(adjacent_controls[index], 2u, zeroing,
                              3u, 13u, 7u),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
            /* Both merging and zeroing control-8 neighbors are allocated
             * S-to-H FCVT rows owned by the conversion decoder. */
            if (adjacent_controls[index] == 8u) {
                EXPECT(decoded == 4u);
                EXPECT(instruction.name_id == CDISASM_ARM_NAME_FCVT);
                continue;
            }
            EXPECT(decoded == 0u);
            EXPECT(instruction_is_error_only(
                &instruction,
                CDISASM_STATUS_INVALID_INSTRUCTION));
#else
            EXPECT(decoded == 0u);
            EXPECT(instruction_is_error_only(
                &instruction,
                !zeroing && adjacent_controls[index] == 11u
                    ? CDISASM_STATUS_INVALID_INSTRUCTION
                    : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }

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
        CDISASM_ARM_MODE_A64, 4u, UINT64_C(1) << 63,
        &other) == 0u);
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
    static const char suffixes[] = { 'h', 's', 'd' };
    size_t operation_index;

    for (operation_index = 0u;
         operation_index
            < sizeof(fp_unary_operations) / sizeof(fp_unary_operations[0]);
         ++operation_index) {
        unsigned size_index;

        for (size_index = 0u; size_index < 3u; ++size_index) {
            int zeroing;

            for (zeroing = 0; zeroing <= 1; ++zeroing) {
                char expected[96];
                int expected_length = snprintf(
                    expected, sizeof(expected),
                    "%s z7.%c, p3/%c, z13.%c",
                    fp_unary_operations[operation_index].mnemonic,
                    suffixes[size_index], zeroing ? 'z' : 'm',
                    suffixes[size_index]);

                EXPECT(expected_length > 0);
                EXPECT((size_t)expected_length < sizeof(expected));
                expect_format(fp_unary_word(
                    fp_unary_operations[operation_index].control,
                    size_index + 1u, zeroing, 3u, 13u, 7u), expected);
            }
        }
    }

    {
        cdisasm_arm_instruction instruction;
        char text[96];
        static const char expected[] = "FRECPX z7.s, p3/z, z13.s";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(fp_unary_word(12u, 2u, 1, 3u, 13u, 7u),
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
    test_neighbors_endian_dispatch_and_boundaries();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif

    if (failures != 0) {
        fprintf(stderr,
            "%d ARM SVE predicated FP unary test(s) failed\n",
            failures);
        return 1;
    }
    printf("ARM SVE predicated FP unary tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=655360, allocated=442368, "
           "reserved=212992)\n", USE_EXTRA_OPCODES);
    return 0;
}
