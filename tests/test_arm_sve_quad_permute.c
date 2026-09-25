#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_ZIPQ1 == UINT16_C(2051),
               "SVE ZIPQ1 ID moved");
_Static_assert(CDISASM_ARM_NAME_UZPQ1 == UINT16_C(1869),
               "SVE UZPQ1 ID moved");
_Static_assert(CDISASM_ARM_NAME_ZIPQ2 == UINT16_C(2052),
               "SVE ZIPQ2 ID moved");
_Static_assert(CDISASM_ARM_NAME_UZPQ2 == UINT16_C(1870),
               "SVE UZPQ2 ID moved");
_Static_assert(CDISASM_ARM_NAME_TBLQ == UINT16_C(357),
               "SVE TBLQ ID moved");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2715),
               "AARCHMRS form inventory no longer covers quad permutes");

#if USE_EXTRA_OPCODES
typedef struct quad_operation {
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
} quad_operation;

static const quad_operation operations[4] = {
    { CDISASM_ARM_NAME_ZIPQ1, UINT16_C(2711), "zipq1" },
    { CDISASM_ARM_NAME_ZIPQ2, UINT16_C(2714), "zipq2" },
    { CDISASM_ARM_NAME_UZPQ1, UINT16_C(2712), "uzpq1" },
    { CDISASM_ARM_NAME_UZPQ2, UINT16_C(2715), "uzpq2" }
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

static uint32_t quad_word(
    unsigned control,
    unsigned size_code,
    unsigned zm,
    unsigned zn,
    unsigned zd)
{
    return UINT32_C(0x4400e000)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)zm << 16)
        | ((uint32_t)control << 10)
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
        cpu_id, mode, bytes, code_size, UINT64_C(0x271100),
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

static int instruction_matches(
    const cdisasm_arm_instruction *instruction,
    const quad_operation *operation,
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
        && instruction->address == UINT64_C(0x271100)
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
            CDISASM_OPERAND_ACCESS_WRITE)
        && z_operand_matches(
            &instruction->operand[1], zn, element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && z_operand_matches(
            &instruction->operand[2], zm, element_size,
            CDISASM_OPERAND_ACCESS_READ);
}
#endif

static int control_is_reserved(unsigned control)
{
    return control == 4u || control == 5u || control == 7u;
}

static void test_exhaustive_parent(void)
{
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_ZIPQ1,
        CDISASM_ARM_NAME_ZIPQ2,
        CDISASM_ARM_NAME_UZPQ1,
        CDISASM_ARM_NAME_UZPQ2,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_TBLQ,
        CDISASM_ARM_NAME_NONE
    };
    static const cdisasm_arm_form_id forms[8] = {
        UINT16_C(2711), UINT16_C(2714), UINT16_C(2712), UINT16_C(2715),
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_FORM_NONE, UINT16_C(2713),
        CDISASM_ARM_FORM_NONE
    };
#endif
    uint32_t exact_words = 0u;
    uint32_t sibling_words = 0u;
    uint32_t reserved_words = 0u;
    unsigned control;

    for (control = 0u; control < 8u; ++control) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            unsigned zm;

            for (zm = 0u; zm < 32u; ++zm) {
                unsigned zn;

                for (zn = 0u; zn < 32u; ++zn) {
                    unsigned zd;

                    for (zd = 0u; zd < 32u; ++zd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = quad_word(
                            control, size_code, zm, zn, zd);
                        uint32_t decoded;

                        domain_expect(
                            (word & UINT32_C(0xff20e000))
                                == UINT32_C(0x4400e000),
                            word, "quad-parent construction mismatch");
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(
                            word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);

                        if (control_is_reserved(control)) {
                            ++reserved_words;
                            domain_expect(decoded == 0u, word,
                                "reserved quad control decoded");
                            domain_expect(instruction_is_error_only(
                                &instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION), word,
                                "reserved quad control lost ownership");
                            continue;
                        }

                        if (control < 4u) {
                            ++exact_words;
                        } else {
                            ++sibling_words;
                        }
#if USE_EXTRA_OPCODES
                        domain_expect(decoded == 4u, word,
                            "allocated quad control did not decode");
                        if (decoded != 4u) {
                            continue;
                        }
                        domain_expect(
                            instruction.name_id == names[control], word,
                            "allocated quad control reached wrong name");
                        domain_expect(
                            instruction.form_id == forms[control], word,
                            "allocated quad control reached wrong form");
                        if (control < 4u) {
                            domain_expect(instruction_matches(
                                &instruction,
                                &operations[control], word,
                                size_code, zm, zn, zd), word,
                                "quad-permute metadata mismatch");
                        }
#else
                        domain_expect(decoded == 0u, word,
                            "extras-OFF allocated quad word decoded");
                        domain_expect(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION), word,
                            "extras-OFF allocated quad ownership mismatch");
#endif
                    }
                }
            }
        }
    }

    EXPECT(exact_words == UINT32_C(524288));
    EXPECT(sibling_words == UINT32_C(131072));
    EXPECT(reserved_words == UINT32_C(393216));
    EXPECT(exact_words + sibling_words + reserved_words
        == UINT32_C(1048576));
}

static void expect_named_cpu_rejected(
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded;

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(
        word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == 0u);
#if USE_EXTRA_OPCODES
    EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION)
        || instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
#else
    EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION)
        || instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
#endif
}

static void test_feature_and_profile_routes(void)
{
    uint32_t profiles_tested = 0u;
    unsigned operation;

    for (operation = 0u; operation < 4u; ++operation) {
        cdisasm_arm_instruction instruction;
        uint32_t word = quad_word(
            operation, operation, 29u, 13u, 7u);
        uint32_t ordinal;

        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(instruction.name_id == operations[operation].name_id);
#else
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        for (ordinal = CDISASM_CPU_ORDINAL_OF(CDISASM_ARM_CPU_FIRST);
             ordinal <= CDISASM_CPU_ORDINAL_OF(CDISASM_ARM_CPU_LAST);
             ++ordinal) {
            expect_named_cpu_rejected(
                word, (cdisasm_arm_cpu_id)(
                    CDISASM_CPU_GROUP_ARM | ordinal));
            ++profiles_tested;
        }
    }
    EXPECT(profiles_tested == UINT32_C(152));
}

static void test_endian_dispatch_and_boundaries(void)
{
    uint32_t word = quad_word(3u, 2u, 29u, 13u, 7u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    uint32_t decoded;
    unsigned boundary;

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(little.name_id == CDISASM_ARM_NAME_UZPQ2);
    EXPECT(little.form_id == UINT16_C(2715));
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x271100),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_decode_checked(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x271100),
        CDISASM_ARM_DECODE_OPTION_NONE, &other, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(
            &other, CDISASM_STATUS_TRUNCATED));
    }

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_T32, 4u,
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

static void test_formatter_and_forgery(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const char suffixes[4] = { 'b', 'h', 's', 'd' };
    unsigned operation;

    for (operation = 0u; operation < 4u; ++operation) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            cdisasm_arm_instruction instruction;
            char expected[96];
            char text[96];
            int expected_length;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                quad_word(operation, size_code, 29u, 13u, 7u),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
            expected_length = snprintf(
                expected, sizeof(expected), "%s z7.%c, z13.%c, z29.%c",
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
        static const char expected[] =
            "UZPQ2 z7.s, z13.s, z29.s";
        cdisasm_arm_instruction instruction;
        cdisasm_arm_instruction forged;
        char text[96];
        char short_text[7];

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            quad_word(3u, 2u, 29u, 13u, 7u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_0,
            short_text, sizeof(short_text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(short_text, "uzpq2 ") == 0);

#define REJECT_MUTATION(statement)                                         \
        do {                                                               \
            forged = instruction;                                          \
            statement;                                                     \
            EXPECT(cdisasm_arm_format(                                     \
                &forged, CDISASM_FORMAT_SYNTAX_0,                           \
                text, sizeof(text)) == 0u);                                \
        } while (0)

        REJECT_MUTATION(forged.form_id = UINT16_C(2711));
        REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_ZIPQ1);
        REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x00000800));
        REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x00000400));
        REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x00001000));
        REJECT_MUTATION(forged.raw_instruction =
            quad_word(4u, 2u, 29u, 13u, 7u));
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_T32);
        REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
        REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
        REJECT_MUTATION(forged.instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED);
        REJECT_MUTATION(forged.instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK);
        REJECT_MUTATION(forged.instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE);
        REJECT_MUTATION(forged.operand_count = 2u);
        REJECT_MUTATION(forged.operand_count = 4u);
        REJECT_MUTATION(forged.operand[0].type =
            CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
        REJECT_MUTATION(forged.operand[0].access =
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_Z30);
        REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_Z12);
        REJECT_MUTATION(forged.operand[1].extend_type =
            CDISASM_ARM_EXTEND_NONE);
        REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_Z28);
        REJECT_MUTATION(forged.operand[2].access =
            CDISASM_OPERAND_ACCESS_READ_WRITE);

#undef REJECT_MUTATION

        {
            cdisasm_arm_instruction structured;
            cdisasm_arm_form_id original_form;

            memset(&structured, 0xa5, sizeof(structured));
            EXPECT(decode_word(
                UINT32_C(0xe1a00000), CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A32, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &structured) == 4u);
            original_form = structured.form_id;
            structured.name_id = CDISASM_ARM_NAME_ZIPQ2;
            EXPECT(structured.form_id == original_form);
            EXPECT(cdisasm_arm_format(
                &structured, CDISASM_FORMAT_SYNTAX_0,
                text, sizeof(text)) == 0u);

            memset(&structured, 0xa5, sizeof(structured));
            EXPECT(decode_word(
                UINT32_C(0x0000bf00), CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_T32, 2u,
                CDISASM_ARM_DECODE_OPTION_NONE, &structured) == 2u);
            original_form = structured.form_id;
            structured.name_id = CDISASM_ARM_NAME_UZPQ2;
            EXPECT(structured.form_id == original_form);
            EXPECT(cdisasm_arm_format(
                &structured, CDISASM_FORMAT_SYNTAX_0,
                text, sizeof(text)) == 0u);
        }
    }
#endif
}

int main(void)
{
    test_exhaustive_parent();
    test_feature_and_profile_routes();
    test_endian_dispatch_and_boundaries();
    test_formatter_and_forgery();

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE quad-permute test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE quad-permute tests passed "
           "(USE_EXTRA_OPCODES=%d, parent=1048576, exact=524288, "
           "siblings=131072, reserved=393216)\n", USE_EXTRA_OPCODES);
    return 0;
}
