#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_SQSHL == UINT16_C(382),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_SRSHL == UINT16_C(1525),
               "predicated shift/saturating-round IDs moved");
_Static_assert(CDISASM_ARM_NAME_UQRSHLR == UINT16_C(1807),
               "predicated shift/saturating-round IDs moved");
_Static_assert(CDISASM_ARM_NAME_URSHLR == UINT16_C(1826),
               "predicated shift/saturating-round IDs moved");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2668),
               "AARCHMRS form inventory no longer covers this family");

typedef struct shift_operation {
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
} shift_operation;

/* AARCHMRS 2026-03 path
 * A64/sve/sve_intx_predicated/sve_intx_bin_pred_shift_sat_round.
 * QRNU values 0, 1, 4, and 5 are the exact unallocated controls. */
static const shift_operation operations[16] = {
    { CDISASM_ARM_NAME_NONE, 0u, NULL },
    { CDISASM_ARM_NAME_NONE, 0u, NULL },
    { CDISASM_ARM_NAME_SRSHL, UINT16_C(2657), "srshl" },
    { CDISASM_ARM_NAME_URSHL, UINT16_C(2663), "urshl" },
    { CDISASM_ARM_NAME_NONE, 0u, NULL },
    { CDISASM_ARM_NAME_NONE, 0u, NULL },
    { CDISASM_ARM_NAME_SRSHLR, UINT16_C(2658), "srshlr" },
    { CDISASM_ARM_NAME_URSHLR, UINT16_C(2664), "urshlr" },
    { CDISASM_ARM_NAME_SQSHL, UINT16_C(2659), "sqshl" },
    { CDISASM_ARM_NAME_UQSHL, UINT16_C(2665), "uqshl" },
    { CDISASM_ARM_NAME_SQRSHL, UINT16_C(2660), "sqrshl" },
    { CDISASM_ARM_NAME_UQRSHL, UINT16_C(2666), "uqrshl" },
    { CDISASM_ARM_NAME_SQSHLR, UINT16_C(2661), "sqshlr" },
    { CDISASM_ARM_NAME_UQSHLR, UINT16_C(2667), "uqshlr" },
    { CDISASM_ARM_NAME_SQRSHLR, UINT16_C(2662), "sqrshlr" },
    { CDISASM_ARM_NAME_UQRSHLR, UINT16_C(2668), "uqrshlr" }
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

static uint32_t shift_word(
    unsigned operation,
    unsigned size_code,
    unsigned pg,
    unsigned zm,
    unsigned zdn)
{
    return UINT32_C(0x44008000)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)operation << 16)
        | ((uint32_t)pg << 10)
        | ((uint32_t)zm << 5)
        | (uint32_t)zdn;
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
        cpu_id, mode, bytes, code_size, UINT64_C(0x11a000),
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
    uint8_t element_size)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_PREDICATE;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.flags = CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static void expect_success_metadata(
    const cdisasm_arm_instruction *instruction,
    const shift_operation *operation,
    uint32_t word,
    unsigned size_code,
    unsigned pg,
    unsigned zm,
    unsigned zdn)
{
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == operation->name_id);
    EXPECT(instruction->form_id == operation->form_id);
    EXPECT(instruction->address == UINT64_C(0x11a000));
    EXPECT(instruction->raw_instruction == word);
    EXPECT(instruction->opcode_size == 4u);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->isa_id == CDISASM_ARM_ISA_A64);
    EXPECT(instruction->condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction->operand_count == 4u);
    EXPECT(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    EXPECT(z_operand_matches(
        &instruction->operand[0], zdn, element_size,
        CDISASM_OPERAND_ACCESS_READ_WRITE));
    EXPECT(predicate_operand_matches(
        &instruction->operand[1], pg, element_size));
    EXPECT(z_operand_matches(
        &instruction->operand[2], zdn, element_size,
        CDISASM_OPERAND_ACCESS_READ));
    EXPECT(z_operand_matches(
        &instruction->operand[3], zm, element_size,
        CDISASM_OPERAND_ACCESS_READ));
}
#endif

static void test_exhaustive_owned_parent(void)
{
    uint32_t allocated_words = 0u;
    uint32_t reserved_words = 0u;
    unsigned size_code;

    for (size_code = 0u; size_code < 4u; ++size_code) {
        unsigned operation;

        for (operation = 0u; operation < 16u; ++operation) {
            const shift_operation *descriptor = &operations[operation];
            int allocated = descriptor->name_id != CDISASM_ARM_NAME_NONE;
            unsigned pg;

            for (pg = 0u; pg < 8u; ++pg) {
                unsigned zm;

                for (zm = 0u; zm < 32u; ++zm) {
                    unsigned zdn;

                    for (zdn = 0u; zdn < 32u; ++zdn) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = shift_word(
                            operation, size_code, pg, zm, zdn);

                        memset(&instruction, 0xa5, sizeof(instruction));
                        if (!allocated) {
                            ++reserved_words;
                            EXPECT(decode_word(
                                word, CDISASM_ARM_CPU_ANY,
                                CDISASM_ARM_MODE_A64, 4u,
                                CDISASM_ARM_DECODE_OPTION_NONE,
                                &instruction) == 0u);
                            EXPECT(instruction_is_error_only(
                                &instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                        } else {
                            ++allocated_words;
#if USE_EXTRA_OPCODES
                            EXPECT(decode_word(
                                word, CDISASM_ARM_CPU_ANY,
                                CDISASM_ARM_MODE_A64, 4u,
                                CDISASM_ARM_DECODE_OPTION_NONE,
                                &instruction) == 4u);
                            expect_success_metadata(
                                &instruction, descriptor, word, size_code,
                                pg, zm, zdn);
#else
                            EXPECT(decode_word(
                                word, CDISASM_ARM_CPU_ANY,
                                CDISASM_ARM_MODE_A64, 4u,
                                CDISASM_ARM_DECODE_OPTION_NONE,
                                &instruction) == 0u);
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

    EXPECT(allocated_words == UINT32_C(393216));
    EXPECT(reserved_words == UINT32_C(131072));
    EXPECT(allocated_words + reserved_words == UINT32_C(524288));
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

static void test_capability_routes(void)
{
    uint32_t word = shift_word(15u, 3u, 7u, 31u, 31u);

    expect_cpu_status(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_A18, CDISASM_STATUS_OK);
    expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M4, CDISASM_STATUS_OK);
    expect_cpu_status(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(
        word, CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(
        word, CDISASM_ARM_CPU_APPLE_M3,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_endian_truncation_mode_and_dispatch(void)
{
    uint32_t word = shift_word(15u, 3u, 7u, 31u, 31u);
    uint32_t reserved = shift_word(0u, 0u, 0u, 0u, 0u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t little_bytes[4];
    uint8_t big_bytes[4];
    unsigned boundary;
    uint32_t decoded;

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(word, big_bytes);
    memset(&big, 0xa5, sizeof(big));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        big_bytes, sizeof(big_bytes), UINT64_C(0x11a000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&big, &little, sizeof(big)) == 0);

    word_to_le(word, little_bytes);
    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x11a000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&generic, 0xa5, sizeof(generic));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE,
            &generic) == 0u);
        EXPECT(instruction_is_error_only(
            &generic, CDISASM_STATUS_TRUNCATED));

        memset(&generic, 0xa5, sizeof(generic));
        EXPECT(decode_word(
            reserved, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE,
            &generic) == 0u);
        EXPECT(instruction_is_error_only(
            &generic, CDISASM_STATUS_TRUNCATED));
    }

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_fixed_neighbors(void)
{
    cdisasm_arm_instruction instruction;

    /* Exact preceding form 2656 (USDOT) remains independently owned. */
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(
        UINT32_C(0x44827820), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2656));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_USDOT);
#else
    EXPECT(decode_word(
        UINT32_C(0x44827820), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

    /* Exact following form 2669 (URECPE) remains independently owned. */
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(
        UINT32_C(0x4480a020), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2669));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_URECPE);
#else
    EXPECT(decode_word(
        UINT32_C(0x4480a020), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_formatter_controls(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const char suffixes[4] = { 'b', 'h', 's', 'd' };
    unsigned size_code;

    for (size_code = 0u; size_code < 4u; ++size_code) {
        unsigned operation;

        for (operation = 0u; operation < 16u; ++operation) {
            const shift_operation *descriptor = &operations[operation];
            cdisasm_arm_instruction instruction;
            uint32_t word;
            char expected[96];
            char text[96];
            int expected_length;

            if (descriptor->name_id == CDISASM_ARM_NAME_NONE) {
                continue;
            }
            word = shift_word(operation, size_code, 3u, 13u, 7u);
            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
            expected_length = snprintf(
                expected, sizeof(expected),
                "%s z7.%c, p3/m, z7.%c, z13.%c",
                descriptor->mnemonic, suffixes[size_code],
                suffixes[size_code], suffixes[size_code]);
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

    {
        cdisasm_arm_instruction instruction;
        cdisasm_arm_instruction forged;
        char text[96];
        static const char expected[] =
            "UQRSHLR z31.d, p7/m, z31.d, z31.d";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            shift_word(15u, 3u, 7u, 31u, 31u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);

        forged = instruction;
        forged.form_id = UINT16_C(2667);
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.name_id = CDISASM_ARM_NAME_UQSHLR;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.raw_instruction = shift_word(0u, 3u, 7u, 31u, 31u);
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[1].flags = CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[2].reg = CDISASM_ARM_REG_Z30;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[3].extend_type = (cdisasm_arm_extend_type)4u;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
    }
#endif
}

int main(void)
{
    test_exhaustive_owned_parent();
    test_capability_routes();
    test_endian_truncation_mode_and_dispatch();
    test_fixed_neighbors();
    test_formatter_controls();

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM SVE predicated shift/saturating-round "
                "test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE predicated shift/saturating-round tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=524288, allocated=393216, "
           "reserved=131072)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
