#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_SQADD == UINT16_C(342),
               "predicated saturating SQADD ID moved");
_Static_assert(CDISASM_ARM_NAME_UQADD == UINT16_C(343),
               "predicated saturating UQADD ID moved");
_Static_assert(CDISASM_ARM_NAME_SQSUB == UINT16_C(344),
               "predicated saturating SQSUB ID moved");
_Static_assert(CDISASM_ARM_NAME_UQSUB == UINT16_C(345),
               "predicated saturating UQSUB ID moved");
_Static_assert(CDISASM_ARM_NAME_SQSUBR == UINT16_C(1513),
               "predicated saturating SQSUBR ID moved");
_Static_assert(CDISASM_ARM_NAME_SUQADD == UINT16_C(1704),
               "predicated saturating SUQADD ID moved");
_Static_assert(CDISASM_ARM_NAME_UQSUBR == UINT16_C(1819),
               "predicated saturating UQSUBR ID moved");
_Static_assert(CDISASM_ARM_NAME_USQADD == UINT16_C(1846),
               "predicated saturating USQADD ID moved");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2700),
               "AARCHMRS form inventory no longer covers this family");

#if USE_EXTRA_OPCODES
typedef struct saturating_operation {
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
} saturating_operation;

/* Indexed by U:R:S in the pinned AARCHMRS 2026-03
 * sve_intx_pred_arith_binary_sat parent. */
static const saturating_operation operations[8] = {
    { CDISASM_ARM_NAME_SQADD,  UINT16_C(2693), "sqadd" },
    { CDISASM_ARM_NAME_UQADD,  UINT16_C(2698), "uqadd" },
    { CDISASM_ARM_NAME_SQSUB,  UINT16_C(2694), "sqsub" },
    { CDISASM_ARM_NAME_UQSUB,  UINT16_C(2699), "uqsub" },
    { CDISASM_ARM_NAME_SUQADD, UINT16_C(2695), "suqadd" },
    { CDISASM_ARM_NAME_USQADD, UINT16_C(2696), "usqadd" },
    { CDISASM_ARM_NAME_SQSUBR, UINT16_C(2697), "sqsubr" },
    { CDISASM_ARM_NAME_UQSUBR, UINT16_C(2700), "uqsubr" }
};
#endif

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 32) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static void domain_expect(int condition, uint32_t word, const char *message)
{
    if (!condition) {
        if (failures < 32) {
            fprintf(stderr, "word %08x: %s\n", (unsigned)word, message);
        }
        ++failures;
    }
}

static uint32_t saturating_word(
    unsigned operation,
    unsigned size_code,
    unsigned pg,
    unsigned zm,
    unsigned zdn)
{
    return UINT32_C(0x44188000)
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
        cpu_id, mode, bytes, code_size, UINT64_C(0x12b000),
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

static int success_metadata_matches(
    const cdisasm_arm_instruction *instruction,
    const saturating_operation *operation,
    uint32_t word,
    unsigned size_code,
    unsigned pg,
    unsigned zm,
    unsigned zdn)
{
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == operation->name_id
        && instruction->form_id == operation->form_id
        && instruction->address == UINT64_C(0x12b000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 4u
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && z_operand_matches(
            &instruction->operand[0], zdn, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && predicate_operand_matches(
            &instruction->operand[1], pg, element_size)
        && z_operand_matches(
            &instruction->operand[2], zdn, element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && z_operand_matches(
            &instruction->operand[3], zm, element_size,
            CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_owned_parent(void)
{
    uint32_t allocated_words = 0u;
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            unsigned pg;

            for (pg = 0u; pg < 8u; ++pg) {
                unsigned zm;

                for (zm = 0u; zm < 32u; ++zm) {
                    unsigned zdn;

                    for (zdn = 0u; zdn < 32u; ++zdn) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = saturating_word(
                            operation, size_code, pg, zm, zdn);
                        uint32_t decoded;

                        ++allocated_words;
                        domain_expect(
                            (word & UINT32_C(0xff38e000))
                                == UINT32_C(0x44188000),
                            word, "owned-parent construction mismatch");
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(
                            word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
                        domain_expect(decoded == 4u, word,
                            "allocated parent word did not decode");
                        if (decoded == 4u) {
                            domain_expect(success_metadata_matches(
                                &instruction, &operations[operation], word,
                                size_code, pg, zm, zdn), word,
                                "allocated parent metadata mismatch");
                        }
#else
                        domain_expect(decoded == 0u, word,
                            "extras-OFF parent word unexpectedly decoded");
                        domain_expect(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION), word,
                            "extras-OFF parent ownership mismatch");
#endif
                    }
                }
            }
        }
    }

    EXPECT(allocated_words == UINT32_C(262144));
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
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        uint32_t word = saturating_word(operation, 2u, 3u, 13u, 7u);

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_cpu_status(
            word, CDISASM_ARM_CPU_APPLE_A18, CDISASM_STATUS_OK);
        expect_cpu_status(
            word, CDISASM_ARM_CPU_APPLE_M4, CDISASM_STATUS_OK);
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
}

static void test_existing_name_neighbors(void)
{
    static const struct name_neighbor {
        uint32_t word;
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
    } neighbors[] = {
        { UINT32_C(0x04b511a5), CDISASM_ARM_NAME_SQADD, UINT16_C(2317) },
        { UINT32_C(0x04f615c6), CDISASM_ARM_NAME_UQADD, UINT16_C(2319) },
        { UINT32_C(0x043719e7), CDISASM_ARM_NAME_SQSUB, UINT16_C(2318) },
        { UINT32_C(0x04781e08), CDISASM_ARM_NAME_UQSUB, UINT16_C(2320) },
        { UINT32_C(0x25a4d005), CDISASM_ARM_NAME_SQADD, UINT16_C(2622) },
        { UINT32_C(0x2525dfe7), CDISASM_ARM_NAME_UQADD, UINT16_C(2624) },
        { UINT32_C(0x25e6efe6), CDISASM_ARM_NAME_SQSUB, UINT16_C(2623) },
        { UINT32_C(0x2567c028), CDISASM_ARM_NAME_UQSUB, UINT16_C(2625) }
    };
    unsigned index;

    for (index = 0u; index < sizeof(neighbors) / sizeof(neighbors[0]);
            ++index) {
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(
            neighbors[index].word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
        EXPECT(instruction.name_id == neighbors[index].name_id);
        EXPECT(instruction.form_id == neighbors[index].form_id);
        EXPECT(instruction.form_id < UINT16_C(2693)
            || instruction.form_id > UINT16_C(2700));
#else
        EXPECT(decoded == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_endian_dispatch_and_boundaries(void)
{
    uint32_t word = saturating_word(7u, 3u, 7u, 31u, 31u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned boundary;
    uint32_t decoded;

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(little.name_id == CDISASM_ARM_NAME_UQSUBR);
    EXPECT(little.form_id == UINT16_C(2700));
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12b000),
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
        bytes, sizeof(bytes), UINT64_C(0x12b000),
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
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            cdisasm_arm_instruction instruction;
            uint32_t word = saturating_word(
                operation, size_code, 3u, 13u, 7u);
            char expected[112];
            char text[112];
            int expected_length;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
            expected_length = snprintf(
                expected, sizeof(expected),
                "%s z7.%c, p3/m, z7.%c, z13.%c",
                operations[operation].mnemonic, suffixes[size_code],
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
        char text[112];
        static const char expected[] =
            "UQSUBR z31.d, p7/m, z31.d, z31.d";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            saturating_word(7u, 3u, 7u, 31u, 31u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);

#define REJECT_MUTATION(statement)                                         \
        do {                                                               \
            forged = instruction;                                          \
            statement;                                                     \
            EXPECT(cdisasm_arm_format(                                     \
                &forged, CDISASM_FORMAT_SYNTAX_0,                           \
                text, sizeof(text)) == 0u);                                \
        } while (0)

        REJECT_MUTATION(forged.form_id = UINT16_C(2697));
        REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_SQSUBR);
        REJECT_MUTATION(forged.raw_instruction =
            saturating_word(6u, 3u, 7u, 31u, 31u));
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_T32);
        REJECT_MUTATION(forged.operand[0].access =
            CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[1].flags =
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);
        REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_Z30);
        REJECT_MUTATION(forged.operand[3].reg = CDISASM_ARM_REG_Z30);
        REJECT_MUTATION(forged.instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);

#undef REJECT_MUTATION

        memset(&forged, 0, sizeof(forged));
        forged.last_error_id = CDISASM_STATUS_OK;
        forged.name_id = CDISASM_ARM_NAME_SQADD;
        forged.form_id = UINT16_C(2693);
        forged.raw_instruction = UINT32_C(0xe1a00000);
        forged.opcode_size = 4u;
        forged.isa_id = CDISASM_ARM_ISA_A32;
        forged.condition = CDISASM_ARM_CONDITION_AL;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);

        memset(&forged, 0, sizeof(forged));
        forged.last_error_id = CDISASM_STATUS_OK;
        forged.name_id = CDISASM_ARM_NAME_SQADD;
        forged.form_id = UINT16_C(2693);
        forged.raw_instruction = UINT32_C(0x0000bf00);
        forged.opcode_size = 2u;
        forged.isa_id = CDISASM_ARM_ISA_T32;
        forged.condition = CDISASM_ARM_CONDITION_AL;
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
    test_existing_name_neighbors();
    test_endian_dispatch_and_boundaries();
    test_formatter_controls();

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM SVE predicated saturating-arithmetic test(s) "
                "failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE predicated saturating-arithmetic tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=262144, allocated=262144, "
           "reserved=0)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
