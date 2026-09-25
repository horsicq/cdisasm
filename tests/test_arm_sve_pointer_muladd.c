#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_MLAPT == UINT16_C(1114),
               "SVE MLAPT ID moved");
_Static_assert(CDISASM_ARM_NAME_MADPT == UINT16_C(1110),
               "SVE MADPT ID moved");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2708),
               "AARCHMRS form inventory no longer covers pointer multiply-add");

#if USE_EXTRA_OPCODES
typedef struct pointer_operation {
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
} pointer_operation;

static const pointer_operation operations[2] = {
    { CDISASM_ARM_NAME_MLAPT, UINT16_C(2707), "mlapt" },
    { CDISASM_ARM_NAME_MADPT, UINT16_C(2708), "madpt" }
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

static uint32_t pointer_word(
    unsigned operation,
    unsigned size_code,
    unsigned zm,
    unsigned middle,
    unsigned zdn)
{
    return UINT32_C(0x4400d000)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)zm << 16)
        | ((uint32_t)operation << 11)
        | ((uint32_t)middle << 5)
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
        cpu_id, mode, bytes, code_size, UINT64_C(0x12d000),
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
    cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)UINT8_C(8);
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int success_metadata_matches(
    const cdisasm_arm_instruction *instruction,
    const pointer_operation *operation,
    uint32_t word,
    unsigned zm,
    unsigned middle,
    unsigned zdn)
{
    unsigned first_source = operation->form_id == UINT16_C(2708)
        ? zm : middle;
    unsigned second_source = operation->form_id == UINT16_C(2708)
        ? middle : zm;

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == operation->name_id
        && instruction->form_id == operation->form_id
        && instruction->address == UINT64_C(0x12d000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 3u
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && z_operand_matches(
            &instruction->operand[0], zdn,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && z_operand_matches(
            &instruction->operand[1], first_source,
            CDISASM_OPERAND_ACCESS_READ)
        && z_operand_matches(
            &instruction->operand[2], second_source,
            CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_owned_parent(void)
{
    uint32_t allocated_words[2] = { 0u, 0u };
    uint32_t reserved_words = 0u;
    unsigned operation;

    for (operation = 0u; operation < 2u; ++operation) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            unsigned zm;

            for (zm = 0u; zm < 32u; ++zm) {
                unsigned middle;

                for (middle = 0u; middle < 32u; ++middle) {
                    unsigned zdn;

                    for (zdn = 0u; zdn < 32u; ++zdn) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = pointer_word(
                            operation, size_code, zm, middle, zdn);
                        uint32_t decoded;

                        domain_expect(
                            (word & UINT32_C(0xff20f400))
                                == UINT32_C(0x4400d000),
                            word, "owned-parent construction mismatch");
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(
                            word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                        if (size_code == 3u) {
                            ++allocated_words[operation];
                            domain_expect(
                                (word & UINT32_C(0xffe0fc00))
                                    == (UINT32_C(0x44c0d000)
                                        | ((uint32_t)operation << 11)),
                                word, "allocated-leaf construction mismatch");
#if USE_EXTRA_OPCODES
                            domain_expect(decoded == 4u, word,
                                "allocated parent word did not decode");
                            if (decoded == 4u) {
                                domain_expect(success_metadata_matches(
                                    &instruction, &operations[operation],
                                    word, zm, middle, zdn), word,
                                    "allocated parent metadata mismatch");
                            }
#else
                            domain_expect(decoded == 0u, word,
                                "extras-OFF allocated word unexpectedly decoded");
                            domain_expect(instruction_is_error_only(
                                &instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION), word,
                                "extras-OFF allocated ownership mismatch");
#endif
                        } else {
                            ++reserved_words;
                            domain_expect(decoded == 0u, word,
                                "reserved size unexpectedly decoded");
                            domain_expect(instruction_is_error_only(
                                &instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION), word,
                                "reserved-size ownership mismatch");
                        }
                    }
                }
            }
        }
    }

    EXPECT(allocated_words[0] == UINT32_C(32768));
    EXPECT(allocated_words[1] == UINT32_C(32768));
    EXPECT(reserved_words == UINT32_C(196608));
    EXPECT(allocated_words[0] + allocated_words[1] + reserved_words
        == UINT32_C(262144));
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
    unsigned operation;
    uint32_t profiles_tested = 0u;

    for (operation = 0u; operation < 2u; ++operation) {
        uint32_t word = pointer_word(operation, 3u, 29u, 13u, 7u);
        uint32_t ordinal;

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        for (ordinal = CDISASM_CPU_ORDINAL_OF(CDISASM_ARM_CPU_FIRST);
             ordinal <= CDISASM_CPU_ORDINAL_OF(CDISASM_ARM_CPU_LAST);
             ++ordinal) {
            expect_named_cpu_rejected(
                word, (cdisasm_arm_cpu_id)(
                    CDISASM_CPU_GROUP_ARM | ordinal));
            ++profiles_tested;
        }
    }
    EXPECT(profiles_tested == UINT32_C(76));
}

static void test_fixed_neighbors(void)
{
    uint32_t sample = pointer_word(0u, 3u, 29u, 13u, 7u);
    static const uint32_t toggles[] = {
        UINT32_C(0x00200000),
        UINT32_C(0x00001000),
        UINT32_C(0x00000400),
        UINT32_C(0x01000000)
    };
    size_t index;

    for (index = 0u; index < sizeof(toggles) / sizeof(toggles[0]); ++index) {
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(
            sample ^ toggles[index], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        if (decoded == 4u) {
            EXPECT(instruction.form_id < UINT16_C(2707)
                || instruction.form_id > UINT16_C(2708));
        }
    }
}

static void test_endian_dispatch_and_boundaries(void)
{
    uint32_t word = pointer_word(1u, 3u, 29u, 13u, 7u);
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
    EXPECT(little.name_id == CDISASM_ARM_NAME_MADPT);
    EXPECT(little.form_id == UINT16_C(2708));
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12d000),
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
        bytes, sizeof(bytes), UINT64_C(0x12d000),
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
}

static void test_formatter_and_forgery(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    unsigned operation;

    for (operation = 0u; operation < 2u; ++operation) {
        cdisasm_arm_instruction instruction;
        char expected[96];
        char text[96];
        int expected_length;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            pointer_word(operation, 3u, 29u, 13u, 7u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        expected_length = snprintf(
            expected, sizeof(expected), operation == 0u
                ? "%s z7.d, z13.d, z29.d"
                : "%s z7.d, z29.d, z13.d",
            operations[operation].mnemonic);
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

    {
        cdisasm_arm_instruction instruction;
        cdisasm_arm_instruction forged;
        char text[96];
        static const char expected[] =
            "MADPT z7.d, z29.d, z13.d";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            pointer_word(1u, 3u, 29u, 13u, 7u),
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

        REJECT_MUTATION(forged.form_id = UINT16_C(2707));
        REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_MLAPT);
        REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x00000800));
        REJECT_MUTATION(forged.raw_instruction &= ~UINT32_C(0x00c00000));
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_T32);
        REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
        REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
        REJECT_MUTATION(forged.instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED);
        REJECT_MUTATION(forged.instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE);
        REJECT_MUTATION(forged.operand_count = 2u);
        REJECT_MUTATION(forged.operand_count = 4u);
        REJECT_MUTATION(forged.operand[0].access =
            CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_Z30);
        REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_Z28);
        REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_Z12);
        REJECT_MUTATION(forged.operand[2].extend_type =
            CDISASM_ARM_EXTEND_NONE);
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
            structured.name_id = CDISASM_ARM_NAME_MLAPT;
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
            structured.name_id = CDISASM_ARM_NAME_MADPT;
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
    test_exhaustive_owned_parent();
    test_feature_and_profile_routes();
    test_fixed_neighbors();
    test_endian_dispatch_and_boundaries();
    test_formatter_and_forgery();

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE pointer multiply-add test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE pointer multiply-add tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=262144, allocated=65536, "
           "reserved=196608)\n", USE_EXTRA_OPCODES);
    return 0;
}
