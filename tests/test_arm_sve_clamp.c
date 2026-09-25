#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_SCLAMP == UINT16_C(1323),
               "SVE SCLAMP ID moved");
_Static_assert(CDISASM_ARM_NAME_UCLAMP == UINT16_C(1750),
               "SVE UCLAMP ID moved");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2702),
               "AARCHMRS form inventory no longer covers SVE clamp");

#if USE_EXTRA_OPCODES
typedef struct clamp_operation {
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
} clamp_operation;

static const clamp_operation operations[2] = {
    { CDISASM_ARM_NAME_SCLAMP, UINT16_C(2701), "sclamp" },
    { CDISASM_ARM_NAME_UCLAMP, UINT16_C(2702), "uclamp" }
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

static uint32_t clamp_word(
    unsigned unsigned_operation,
    unsigned size_code,
    unsigned zm,
    unsigned zn,
    unsigned zd)
{
    return UINT32_C(0x4400c000)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)zm << 16)
        | ((uint32_t)unsigned_operation << 10)
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
        cpu_id, mode, bytes, code_size, UINT64_C(0x12c000),
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

static int success_metadata_matches(
    const cdisasm_arm_instruction *instruction,
    const clamp_operation *operation,
    uint32_t word,
    unsigned size_code,
    unsigned zm,
    unsigned zn,
    unsigned zd)
{
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == operation->name_id
        && instruction->form_id == operation->form_id
        && instruction->address == UINT64_C(0x12c000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 3u
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && z_operand_matches(
            &instruction->operand[0], zd, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && z_operand_matches(
            &instruction->operand[1], zn, element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && z_operand_matches(
            &instruction->operand[2], zm, element_size,
            CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_owned_parent(void)
{
    uint32_t leaf_words[2] = { 0u, 0u };
    unsigned unsigned_operation;

    for (unsigned_operation = 0u; unsigned_operation < 2u;
            ++unsigned_operation) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            unsigned zm;

            for (zm = 0u; zm < 32u; ++zm) {
                unsigned zn;

                for (zn = 0u; zn < 32u; ++zn) {
                    unsigned zd;

                    for (zd = 0u; zd < 32u; ++zd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = clamp_word(
                            unsigned_operation, size_code, zm, zn, zd);
                        uint32_t decoded;

                        ++leaf_words[unsigned_operation];
                        domain_expect(
                            (word & UINT32_C(0xff20f800))
                                == UINT32_C(0x4400c000),
                            word, "owned-parent construction mismatch");
                        domain_expect(
                            (word & UINT32_C(0xff20fc00))
                                == (UINT32_C(0x4400c000)
                                    | ((uint32_t)unsigned_operation << 10)),
                            word, "leaf construction mismatch");
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
                                &instruction,
                                &operations[unsigned_operation], word,
                                size_code, zm, zn, zd), word,
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

    EXPECT(leaf_words[0] == UINT32_C(131072));
    EXPECT(leaf_words[1] == UINT32_C(131072));
    EXPECT(leaf_words[0] + leaf_words[1] == UINT32_C(262144));
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
    unsigned unsigned_operation;

    for (unsigned_operation = 0u; unsigned_operation < 2u;
            ++unsigned_operation) {
        uint32_t word = clamp_word(
            unsigned_operation, 2u, 29u, 13u, 7u);

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

static void test_fixed_neighbors_and_other_clamp_forms(void)
{
    static const uint32_t words[] = {
        UINT32_C(0x4422c020), /* owned parent with fixed bit 21 flipped */
        UINT32_C(0x4402c820), /* owned parent with fixed bit 11 flipped */
        UINT32_C(0xc120c400), /* SME2 two-register SCLAMP form */
        UINT32_C(0xc120c401), /* SME2 two-register UCLAMP form */
        UINT32_C(0xc120cc00), /* SME2 four-register SCLAMP form */
        UINT32_C(0xc120cc01)  /* SME2 four-register UCLAMP form */
    };
    unsigned index;

    for (index = 0u; index < sizeof(words) / sizeof(words[0]); ++index) {
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(
            words[index], CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        if (decoded == 4u) {
            EXPECT(instruction.form_id < UINT16_C(2701)
                || instruction.form_id > UINT16_C(2702));
        }
    }
}

static void test_endian_dispatch_and_boundaries(void)
{
    uint32_t word = clamp_word(1u, 3u, 29u, 30u, 31u);
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
    EXPECT(little.name_id == CDISASM_ARM_NAME_UCLAMP);
    EXPECT(little.form_id == UINT16_C(2702));
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12c000),
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
        bytes, sizeof(bytes), UINT64_C(0x12c000),
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
}

static void test_formatter_and_forgery(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const char suffixes[4] = { 'b', 'h', 's', 'd' };
    unsigned unsigned_operation;

    for (unsigned_operation = 0u; unsigned_operation < 2u;
            ++unsigned_operation) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            cdisasm_arm_instruction instruction;
            char expected[96];
            char text[96];
            int expected_length;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                clamp_word(unsigned_operation, size_code, 29u, 13u, 7u),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
            expected_length = snprintf(
                expected, sizeof(expected), "%s z7.%c, z13.%c, z29.%c",
                operations[unsigned_operation].mnemonic,
                suffixes[size_code], suffixes[size_code],
                suffixes[size_code]);
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
            "UCLAMP z31.d, z30.d, z29.d";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            clamp_word(1u, 3u, 29u, 30u, 31u),
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

        REJECT_MUTATION(forged.form_id = UINT16_C(2701));
        REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_SCLAMP);
        REJECT_MUTATION(forged.raw_instruction =
            clamp_word(0u, 3u, 29u, 30u, 31u));
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_T32);
        REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
        REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
        REJECT_MUTATION(forged.instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED);
        REJECT_MUTATION(forged.operand_count = 2u);
        REJECT_MUTATION(forged.operand_count = 4u);
        REJECT_MUTATION(forged.operand[0].access =
            CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_Z30);
        REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_Z29);
        REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_Z28);
        REJECT_MUTATION(forged.operand[2].extend_type =
            CDISASM_ARM_EXTEND_NONE);

#undef REJECT_MUTATION

        {
            cdisasm_arm_instruction structured;
            cdisasm_arm_form_id original_form;

            memset(&structured, 0xa5, sizeof(structured));
            EXPECT(decode_word(
                UINT32_C(0xe1a00000), CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A32, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &structured) == 4u);
            EXPECT(structured.name_id == CDISASM_ARM_NAME_MOV);
            EXPECT(structured.form_id < UINT16_C(2701)
                || structured.form_id > UINT16_C(2702));
            original_form = structured.form_id;
            structured.name_id = CDISASM_ARM_NAME_SCLAMP;
            EXPECT(structured.form_id == original_form);
            EXPECT(cdisasm_arm_format(
                &structured, CDISASM_FORMAT_SYNTAX_0,
                text, sizeof(text)) == 0u);

            memset(&structured, 0xa5, sizeof(structured));
            EXPECT(decode_word(
                UINT32_C(0x0000bf00), CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_T32, 2u,
                CDISASM_ARM_DECODE_OPTION_NONE, &structured) == 2u);
            EXPECT(structured.name_id == CDISASM_ARM_NAME_NOP);
            EXPECT(structured.form_id < UINT16_C(2701)
                || structured.form_id > UINT16_C(2702));
            original_form = structured.form_id;
            structured.name_id = CDISASM_ARM_NAME_UCLAMP;
            EXPECT(structured.form_id == original_form);
            EXPECT(cdisasm_arm_format(
                &structured, CDISASM_FORMAT_SYNTAX_0,
                text, sizeof(text)) == 0u);
        }

        memset(&forged, 0, sizeof(forged));
        forged.last_error_id = CDISASM_STATUS_OK;
        forged.name_id = CDISASM_ARM_NAME_SCLAMP;
        forged.form_id = UINT16_C(2701);
        forged.raw_instruction = UINT32_C(0xe1a00000);
        forged.opcode_size = 4u;
        forged.isa_id = CDISASM_ARM_ISA_A32;
        forged.condition = CDISASM_ARM_CONDITION_AL;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);

        memset(&forged, 0, sizeof(forged));
        forged.last_error_id = CDISASM_STATUS_OK;
        forged.name_id = CDISASM_ARM_NAME_UCLAMP;
        forged.form_id = UINT16_C(2702);
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
    test_fixed_neighbors_and_other_clamp_forms();
    test_endian_dispatch_and_boundaries();
    test_formatter_and_forgery();

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE clamp test(s) failed\n", failures);
        return 1;
    }
    printf("ARM SVE clamp tests passed (USE_EXTRA_OPCODES=%d, "
           "owned=262144, allocated=262144, reserved=0)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
