#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_SQABS == UINT16_C(1464),
               "predicated saturating-unary IDs moved");
_Static_assert(CDISASM_ARM_NAME_SQNEG == UINT16_C(1492),
               "predicated saturating-unary IDs moved");
_Static_assert(CDISASM_ARM_NAME_URECPE == UINT16_C(1823),
               "predicated estimate-unary IDs moved");
_Static_assert(CDISASM_ARM_NAME_URSQRTE == UINT16_C(1827),
               "predicated estimate-unary IDs moved");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2676),
               "AARCHMRS form inventory no longer covers this family");

typedef struct unary_operation {
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id merging_form;
    const char *mnemonic;
    uint8_t size_mask;
} unary_operation;

/* Pinned AARCHMRS 2026-03 path:
 * A64/sve/sve_intx_predicated/sve_intx_pred_arith_unary. */
static const unary_operation operations[2][2] = {
    {
        { CDISASM_ARM_NAME_URECPE, UINT16_C(2669),
          "urecpe", UINT8_C(0x04) },
        { CDISASM_ARM_NAME_URSQRTE, UINT16_C(2671),
          "ursqrte", UINT8_C(0x04) }
    },
    {
        { CDISASM_ARM_NAME_SQABS, UINT16_C(2673),
          "sqabs", UINT8_C(0x0f) },
        { CDISASM_ARM_NAME_SQNEG, UINT16_C(2675),
          "sqneg", UINT8_C(0x0f) }
    }
};

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",           \
                    __FILE__, __LINE__, #condition);                        \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static uint32_t unary_word(
    unsigned saturating,
    unsigned operation,
    unsigned size_code,
    int zeroing,
    unsigned pg,
    unsigned zn,
    unsigned zd)
{
    return UINT32_C(0x4400a000)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)saturating << 19)
        | ((uint32_t)zeroing << 17)
        | ((uint32_t)operation << 16)
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
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    size_t code_size,
    cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x11b000),
        options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static int z_operand_matches(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    uint8_t element_size,
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

static int predicate_operand_matches(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    uint8_t element_size,
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

static void expect_success_metadata(
    const cdisasm_arm_instruction *instruction,
    const unary_operation *operation,
    uint32_t word,
    unsigned size_code,
    int zeroing,
    unsigned pg,
    unsigned zn,
    unsigned zd)
{
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);

    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == operation->name_id);
    EXPECT(instruction->form_id
        == (cdisasm_arm_form_id)(operation->merging_form + zeroing));
    EXPECT(instruction->address == UINT64_C(0x11b000));
    EXPECT(instruction->raw_instruction == word);
    EXPECT(instruction->opcode_size == 4u);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->isa_id == CDISASM_ARM_ISA_A64);
    EXPECT(instruction->condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction->operand_count == 3u);
    EXPECT(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    EXPECT(z_operand_matches(
        &instruction->operand[0], zd, element_size,
        zeroing ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ_WRITE));
    EXPECT(predicate_operand_matches(
        &instruction->operand[1], pg, element_size, zeroing));
    EXPECT(z_operand_matches(
        &instruction->operand[2], zn, element_size,
        CDISASM_OPERAND_ACCESS_READ));
}
#endif

static void test_exhaustive_owned_parent(void)
{
    uint32_t allocated_words[2] = { 0u, 0u };
    uint32_t reserved_words[2] = { 0u, 0u };
    unsigned saturating;

    for (saturating = 0u; saturating < 2u; ++saturating) {
        unsigned operation;

        for (operation = 0u; operation < 2u; ++operation) {
            const unary_operation *descriptor =
                &operations[saturating][operation];
            int zeroing;

            for (zeroing = 0; zeroing <= 1; ++zeroing) {
                unsigned size_code;

                for (size_code = 0u; size_code < 4u; ++size_code) {
                    int allocated = (descriptor->size_mask
                        & (UINT8_C(1) << size_code)) != 0u;
                    unsigned pg;

                    for (pg = 0u; pg < 8u; ++pg) {
                        unsigned zn;

                        for (zn = 0u; zn < 32u; ++zn) {
                            unsigned zd;

                            for (zd = 0u; zd < 32u; ++zd) {
                                cdisasm_arm_instruction instruction;
                                uint32_t word = unary_word(
                                    saturating, operation, size_code,
                                    zeroing, pg, zn, zd);
                                uint32_t decoded;

                                EXPECT((word & UINT32_C(0xff34e000))
                                    == UINT32_C(0x4400a000));
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
                                    ++allocated_words[zeroing];
#if USE_EXTRA_OPCODES
                                    EXPECT(decoded == 4u);
                                    expect_success_metadata(
                                        &instruction, descriptor, word,
                                        size_code, zeroing, pg, zn, zd);
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
            }
        }
    }

    EXPECT(allocated_words[0] == UINT32_C(81920));
    EXPECT(allocated_words[1] == UINT32_C(81920));
    EXPECT(reserved_words[0] == UINT32_C(49152));
    EXPECT(reserved_words[1] == UINT32_C(49152));
    EXPECT(allocated_words[0] + allocated_words[1]
        == UINT32_C(163840));
    EXPECT(reserved_words[0] + reserved_words[1]
        == UINT32_C(98304));
}

static void expect_cpu_status(
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id,
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
    decoded = decode_word(
        word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(decoded == 4u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(decoded == 0u);
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_feature_and_profile_routes(void)
{
    unsigned saturating;

    for (saturating = 0u; saturating < 2u; ++saturating) {
        unsigned operation;

        for (operation = 0u; operation < 2u; ++operation) {
            uint32_t merging = unary_word(
                saturating, operation, 2u, 0, 3u, 13u, 7u);
            uint32_t zeroing = unary_word(
                saturating, operation, 2u, 1, 3u, 13u, 7u);

            expect_cpu_status(
                merging, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
            /* These profiles prove the independent baseline-SME route. */
            expect_cpu_status(
                merging, CDISASM_ARM_CPU_APPLE_A18,
                CDISASM_STATUS_OK);
            expect_cpu_status(
                merging, CDISASM_ARM_CPU_APPLE_M4,
                CDISASM_STATUS_OK);
            /* Baseline SVE alone is not sufficient for these SVE2 forms. */
            expect_cpu_status(
                merging, CDISASM_ARM_CPU_FUJITSU_A64FX,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_cpu_status(
                merging, CDISASM_ARM_CPU_CORTEX_A53,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_cpu_status(
                merging, CDISASM_ARM_CPU_APPLE_M3,
                CDISASM_STATUS_INVALID_INSTRUCTION);

            /* No named profile currently claims SVE2.2 or SME2.2. */
            expect_cpu_status(
                zeroing, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
            expect_cpu_status(
                zeroing, CDISASM_ARM_CPU_APPLE_A18,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_cpu_status(
                zeroing, CDISASM_ARM_CPU_APPLE_M4,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_cpu_status(
                zeroing, CDISASM_ARM_CPU_FUJITSU_A64FX,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
}

static void test_neighbors_endian_dispatch_and_boundaries(void)
{
    uint32_t word = unary_word(1u, 1u, 3u, 1, 7u, 31u, 31u);
    uint32_t reserved = unary_word(0u, 0u, 3u, 0, 0u, 0u, 0u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned boundary;
    uint32_t decoded;

    /* Exact preceding form 2668 and following form 2677 stay disjoint. */
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(
        UINT32_C(0x44cf9fff), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &other) == 4u);
    EXPECT(other.form_id == UINT16_C(2668));
#else
    EXPECT(decode_word(
        UINT32_C(0x44cf9fff), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(
        UINT32_C(0x4444a020), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &other) == 4u);
    EXPECT(other.form_id == UINT16_C(2677));
#else
    EXPECT(decode_word(
        UINT32_C(0x4444a020), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x11b000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x11b000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(
            &other, CDISASM_STATUS_TRUNCATED));

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(
            reserved, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(
            &other, CDISASM_STATUS_TRUNCATED));
    }

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_formatter_controls(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const char suffixes[4] = { 'b', 'h', 's', 'd' };
    unsigned saturating;

    for (saturating = 0u; saturating < 2u; ++saturating) {
        unsigned operation;

        for (operation = 0u; operation < 2u; ++operation) {
            const unary_operation *descriptor =
                &operations[saturating][operation];
            int zeroing;

            for (zeroing = 0; zeroing <= 1; ++zeroing) {
                unsigned size_code;

                for (size_code = 0u; size_code < 4u; ++size_code) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word;
                    char expected[96];
                    char text[96];
                    int expected_length;

                    if ((descriptor->size_mask
                            & (UINT8_C(1) << size_code)) == 0u) {
                        continue;
                    }
                    word = unary_word(
                        saturating, operation, size_code, zeroing,
                        3u, 13u, 7u);
                    memset(&instruction, 0xa5, sizeof(instruction));
                    EXPECT(decode_word(
                        word, CDISASM_ARM_CPU_ANY,
                        CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE,
                        &instruction) == 4u);
                    expected_length = snprintf(
                        expected, sizeof(expected),
                        "%s z7.%c, p3/%c, z13.%c",
                        descriptor->mnemonic, suffixes[size_code],
                        zeroing ? 'z' : 'm', suffixes[size_code]);
                    EXPECT(expected_length > 0);
                    EXPECT((size_t)expected_length < sizeof(expected));
                    EXPECT(cdisasm_arm_format(
                        &instruction, CDISASM_FORMAT_SYNTAX_7,
                        text, sizeof(text)) == (size_t)expected_length);
                    EXPECT(strcmp(text, expected) == 0);
                    EXPECT(cdisasm_arm_format(
                        &instruction, CDISASM_FORMAT_SYNTAX_0,
                        NULL, 0u) == (size_t)expected_length);
                }
            }
        }
    }

    {
        cdisasm_arm_instruction instruction;
        cdisasm_arm_instruction forged;
        char text[96];
        static const char expected[] =
            "SQNEG z31.d, p7/z, z31.d";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            unary_word(1u, 1u, 3u, 1, 7u, 31u, 31u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);

        forged = instruction;
        forged.form_id = UINT16_C(2674);
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.name_id = CDISASM_ARM_NAME_SQABS;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.raw_instruction = unary_word(
            0u, 1u, 3u, 1, 7u, 31u, 31u);
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[1].flags =
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[1].extend_type = (cdisasm_arm_extend_type)4u;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[2].reg = CDISASM_ARM_REG_Z30;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
    }
#endif
}

int main(void)
{
    test_exhaustive_owned_parent();
    test_feature_and_profile_routes();
    test_neighbors_endian_dispatch_and_boundaries();
    test_formatter_controls();

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM SVE predicated saturating/estimate-unary "
                "test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE predicated saturating/estimate-unary tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=262144, allocated=163840, "
           "reserved=98304)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
