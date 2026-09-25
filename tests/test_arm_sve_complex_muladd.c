#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x1ad000)
#define QDML_PARENT_MASK UINT32_C(0xff20f800)
#define QDML_PARENT_VALUE UINT32_C(0x44000800)
#define CDOT_PARENT_MASK UINT32_C(0xff20f000)
#define CDOT_PARENT_VALUE UINT32_C(0x44001000)
#define CMLA_PARENT_MASK UINT32_C(0xff20e000)
#define CMLA_PARENT_VALUE UINT32_C(0x44002000)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

typedef enum test_family {
    TEST_SQDMLALBT,
    TEST_SQDMLSLBT,
    TEST_CDOT,
    TEST_CMLA,
    TEST_SQRDCMLAH
} test_family;

static int failures;
static uint64_t family_counts[5];
static uint64_t reserved_count;

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

static uint32_t decode_word_mode(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_arm_mode mode,
    size_t size, cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, size, TEST_ADDRESS, options, instruction);
}

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, size_t size,
    cdisasm_arm_decode_option options, cdisasm_arm_instruction *instruction)
{
    return decode_word_mode(
        word, cpu_id, CDISASM_ARM_MODE_A64, size, options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction, cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static int identify_family(uint32_t word, test_family *family)
{
    if ((word & UINT32_C(0xff20fc00)) == UINT32_C(0x44000800)) {
        *family = TEST_SQDMLALBT;
    } else if ((word & UINT32_C(0xff20fc00))
        == UINT32_C(0x44000c00)) {
        *family = TEST_SQDMLSLBT;
    } else if ((word & CDOT_PARENT_MASK) == CDOT_PARENT_VALUE) {
        *family = TEST_CDOT;
    } else if ((word & UINT32_C(0xff20f000))
        == UINT32_C(0x44002000)) {
        *family = TEST_CMLA;
    } else if ((word & UINT32_C(0xff20f000))
        == UINT32_C(0x44003000)) {
        *family = TEST_SQRDCMLAH;
    } else {
        return 0;
    }
    return 1;
}

static int family_size_is_allocated(test_family family, unsigned size_code)
{
    if (family == TEST_SQDMLALBT || family == TEST_SQDMLSLBT) {
        return size_code != 0u;
    }
    if (family == TEST_CDOT) {
        return size_code >= 2u;
    }
    return 1;
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_form_id expected_form_id(test_family family)
{
    return (cdisasm_arm_form_id)(UINT16_C(2637) + (unsigned)family);
}

static cdisasm_arm_name_id expected_name_id(test_family family)
{
    static const cdisasm_arm_name_id names[5] = {
        CDISASM_ARM_NAME_SQDMLALBT,
        CDISASM_ARM_NAME_SQDMLSLBT,
        CDISASM_ARM_NAME_CDOT,
        CDISASM_ARM_NAME_CMLA,
        CDISASM_ARM_NAME_SQRDCMLAH
    };

    return names[(unsigned)family];
}

static void append_z_operand(
    cdisasm_arm_instruction *instruction, unsigned encoded,
    uint8_t element_size, cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand =
        &instruction->operand[instruction->operand_count++];

    operand->type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    operand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    operand->extend_type = (cdisasm_arm_extend_type)element_size;
    operand->access = access;
}

static void append_rotation_operand(
    cdisasm_arm_instruction *instruction, uint32_t word)
{
    cdisasm_arm_operand *operand =
        &instruction->operand[instruction->operand_count++];

    operand->type = CDISASM_OPERAND_IMMEDIATE;
    operand->imm = ((word >> 10) & 3u) * 90u;
    operand->size = 2u;
    operand->access = CDISASM_OPERAND_ACCESS_READ;
}

static void make_expected(
    uint32_t word, test_family family, cdisasm_arm_instruction *expected)
{
    unsigned size_code = (word >> 22) & 3u;
    uint8_t destination_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t source_size = destination_size;

    if (family == TEST_SQDMLALBT || family == TEST_SQDMLSLBT) {
        source_size = (uint8_t)(destination_size / 2u);
    } else if (family == TEST_CDOT) {
        source_size = (uint8_t)(destination_size / 4u);
    }
    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = expected_name_id(family);
    expected->form_id = expected_form_id(family);
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG;
    append_z_operand(expected, word & 31u, destination_size,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    append_z_operand(expected, (word >> 5) & 31u, source_size,
        CDISASM_OPERAND_ACCESS_READ);
    append_z_operand(expected, (word >> 16) & 31u, source_size,
        CDISASM_OPERAND_ACCESS_READ);
    if (family >= TEST_CDOT) {
        append_rotation_operand(expected, word);
    }
}
#endif

static void expect_allocated(uint32_t word, test_family family)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated complex multiply-add word did not decode");
        make_expected(word, family, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated complex multiply-add metadata mismatch");
    }
#else
    (void)family;
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded allocated complex multiply-add word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF complex multiply-add ownership mismatch");
#endif
}

static void expect_reserved(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved complex multiply-add word decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved complex multiply-add ownership mismatch");
}

static void test_complete_parents(void)
{
    unsigned operation;
    unsigned rotation;
    unsigned size_code;
    unsigned zm;
    unsigned zn;
    unsigned zda;

    /* Exact SQDMLALBT/SQDMLSLBT group: bit 10 selects the leaf. */
    for (operation = 0u; operation < 2u; ++operation) {
        for (size_code = 0u; size_code < 4u; ++size_code) {
            for (zm = 0u; zm < 32u; ++zm) {
                for (zn = 0u; zn < 32u; ++zn) {
                    for (zda = 0u; zda < 32u; ++zda) {
                        uint32_t word = QDML_PARENT_VALUE
                            | ((uint32_t)size_code << 22)
                            | ((uint32_t)zm << 16)
                            | ((uint32_t)operation << 10)
                            | ((uint32_t)zn << 5) | zda;
                        test_family family = operation == 0u
                            ? TEST_SQDMLALBT : TEST_SQDMLSLBT;

                        domain_expect(
                            (word & QDML_PARENT_MASK) == QDML_PARENT_VALUE,
                            word, "SQDML*BT parent construction failed");
                        if (!family_size_is_allocated(family, size_code)) {
                            expect_reserved(word);
                            ++reserved_count;
                        } else {
                            expect_allocated(word, family);
                            ++family_counts[(unsigned)family];
                        }
                    }
                }
            }
        }
    }
    /* Exact CDOT group: rotation is encoded at bits 11:10. */
    for (size_code = 0u; size_code < 4u; ++size_code) {
        for (rotation = 0u; rotation < 4u; ++rotation) {
            for (zm = 0u; zm < 32u; ++zm) {
                for (zn = 0u; zn < 32u; ++zn) {
                    for (zda = 0u; zda < 32u; ++zda) {
                        uint32_t word = CDOT_PARENT_VALUE
                            | ((uint32_t)size_code << 22)
                            | ((uint32_t)zm << 16)
                            | ((uint32_t)rotation << 10)
                            | ((uint32_t)zn << 5) | zda;

                        if (!family_size_is_allocated(TEST_CDOT, size_code)) {
                            expect_reserved(word);
                            ++reserved_count;
                        } else {
                            expect_allocated(word, TEST_CDOT);
                            ++family_counts[TEST_CDOT];
                        }
                    }
                }
            }
        }
    }
    /* Exact CMLA/SQRDCMLAH group: bit 12 selects the leaf. */
    for (operation = 0u; operation < 2u; ++operation) {
        for (size_code = 0u; size_code < 4u; ++size_code) {
            for (rotation = 0u; rotation < 4u; ++rotation) {
                for (zm = 0u; zm < 32u; ++zm) {
                    for (zn = 0u; zn < 32u; ++zn) {
                        for (zda = 0u; zda < 32u; ++zda) {
                            uint32_t word = CMLA_PARENT_VALUE
                                | ((uint32_t)operation << 12)
                                | ((uint32_t)size_code << 22)
                                | ((uint32_t)zm << 16)
                                | ((uint32_t)rotation << 10)
                                | ((uint32_t)zn << 5) | zda;
                            test_family family = operation == 0u
                                ? TEST_CMLA : TEST_SQRDCMLAH;

                            domain_expect(
                                (word & CMLA_PARENT_MASK)
                                    == CMLA_PARENT_VALUE,
                                word, "CMLA parent construction failed");
                            expect_allocated(word, family);
                            ++family_counts[(unsigned)family];
                        }
                    }
                }
            }
        }
    }
    EXPECT(family_counts[TEST_SQDMLALBT] == UINT64_C(98304));
    EXPECT(family_counts[TEST_SQDMLSLBT] == UINT64_C(98304));
    EXPECT(family_counts[TEST_CDOT] == UINT64_C(262144));
    EXPECT(family_counts[TEST_CMLA] == UINT64_C(524288));
    EXPECT(family_counts[TEST_SQRDCMLAH] == UINT64_C(524288));
    EXPECT(reserved_count == UINT64_C(327680));
    EXPECT(family_counts[0] + family_counts[1] + family_counts[2]
        + family_counts[3] + family_counts[4] + reserved_count
        == UINT64_C(1835008));
}

static void expect_profile(
    uint32_t word, cdisasm_arm_cpu_id cpu_id,
    cdisasm_status enabled_status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_status expected;

#if USE_EXTRA_OPCODES
    expected = enabled_status;
#else
    (void)enabled_status;
    expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, cpu_id, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction)
        == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
#if USE_EXTRA_OPCODES
        test_family family;

        EXPECT(identify_family(word, &family));
        EXPECT(instruction.form_id == expected_form_id(family));
        EXPECT(instruction.name_id == expected_name_id(family));
#endif
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_features_transport_and_delegation(void)
{
    static const uint32_t words[5] = {
        UINT32_C(0x44820820), /* sqdmlalbt z0.s, z1.h, z2.h */
        UINT32_C(0x44c50c83), /* sqdmlslbt z3.d, z4.s, z5.s */
        UINT32_C(0x44821420), /* cdot z0.s, z1.b, z2.b, #90 */
        UINT32_C(0x44022c20), /* cmla z0.b, z1.b, z2.b, #270 */
        UINT32_C(0x44853c83)  /* sqrdcmlah z3.s, z4.s, z5.s, #270 */
    };
    static const uint32_t delegated[] = {
        UINT32_C(0x44800000), /* preceding SDOT leaf */
        UINT32_C(0x44404000), /* following SMLALB leaf */
        UINT32_C(0x44007000)  /* existing SQRDMLAH family */
    };
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned index;
    unsigned boundary;

    for (index = 0u; index < 5u; ++index) {
        test_family family;

        EXPECT(identify_family(words[index], &family));
        EXPECT((unsigned)family == index);
        expect_profile(words[index], CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_profile(words[index], CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(words[4], CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(words[4], CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
    bytes[0] = (uint8_t)(words[4] >> 24);
    bytes[1] = (uint8_t)(words[4] >> 16);
    bytes[2] = (uint8_t)(words[4] >> 8);
    bytes[3] = (uint8_t)words[4];
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_le(words[4], bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    for (boundary = 0u; boundary < 4u; ++boundary) {
        cdisasm_status status = boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(words[0], CDISASM_ARM_CPU_FUJITSU_A64FX,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, status));
    }
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(words[0], CDISASM_ARM_CPU_ANY, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));

    for (index = 0u;
         index < sizeof(delegated) / sizeof(delegated[0]); ++index) {
        memset(&other, 0xa5, sizeof(other));
        (void)decode_word(delegated[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &other);
        EXPECT(other.form_id < UINT16_C(2637)
            || other.form_id > UINT16_C(2641));
    }
    memset(&other, 0xa5, sizeof(other));
    (void)decode_word_mode(words[0], CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id < UINT16_C(2637)
        || other.form_id > UINT16_C(2641));
    memset(&other, 0xa5, sizeof(other));
    (void)decode_word_mode(words[0], CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id < UINT16_C(2637)
        || other.form_id > UINT16_C(2641));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void reject_forgery(
    const cdisasm_arm_instruction *instruction, const char *mutation)
{
    char text[112];
    size_t length;

    memset(text, 0xa5, sizeof(text));
    length = cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text));
    if (length != 0u || text[0] != '\0') {
        if (failures < 24) {
            fprintf(stderr, "accepted formatter forgery: %s\n", mutation);
        }
        ++failures;
    }
}

static void test_formatter_contract(void)
{
    static const struct format_case {
        uint32_t word;
        const char *text;
    } cases[] = {
        { UINT32_C(0x44420820),
          "sqdmlalbt z0.h, z1.b, z2.b" },
        { UINT32_C(0x44dd0bdf),
          "sqdmlalbt z31.d, z30.s, z29.s" },
        { UINT32_C(0x44850c83),
          "sqdmlslbt z3.s, z4.h, z5.h" },
        { UINT32_C(0x44821420),
          "cdot z0.s, z1.b, z2.b, #90" },
        { UINT32_C(0x44821820),
          "cdot z0.s, z1.b, z2.b, #180" },
        { UINT32_C(0x44dd1fdf),
          "cdot z31.d, z30.h, z29.h, #270" },
        { UINT32_C(0x44022c20),
          "cmla z0.b, z1.b, z2.b, #270" },
        { UINT32_C(0x44852483),
          "cmla z3.s, z4.s, z5.s, #90" },
        { UINT32_C(0x44423420),
          "sqrdcmlah z0.h, z1.h, z2.h, #90" },
        { UINT32_C(0x44da2f7c),
          "cmla z28.d, z27.d, z26.d, #270" },
        { UINT32_C(0x44da377c),
          "sqrdcmlah z28.d, z27.d, z26.d, #90" }
    };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction qdml;
    cdisasm_arm_instruction forged;
    char text[112];
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        EXPECT(decode_word(cases[index].word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == strlen(cases[index].text));
        EXPECT(strcmp(text, cases[index].text) == 0);
    }
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("SQRDCMLAH z28.d, z27.d, z26.d, #90"));
    EXPECT(strcmp(text, "SQRDCMLAH z28.d, z27.d, z26.d, #90") == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(cases[sizeof(cases) / sizeof(cases[0]) - 1u].text));

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0x44da277c));
    REJECT_MUTATION(forged.form_id = UINT16_C(2640));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_CMLA);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags = 0u);
    REJECT_MUTATION(forged.operand_count = 3u);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[0].extend_type = 4u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[2].flags =
        CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    REJECT_MUTATION(forged.operand[3].imm = 180u);
    REJECT_MUTATION(forged.operand[3].size = 1u);
#undef REJECT_MUTATION

    EXPECT(decode_word(UINT32_C(0x44420820), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &qdml) == 4u);
    forged = qdml;
    forged.operand_count = 4u;
    reject_forgery(&forged, "unexpected fourth SQDMLALBT operand");
    forged = qdml;
    forged.raw_instruction = UINT32_C(0x44020820);
    reject_forgery(&forged, "reserved size=00 SQDMLALBT raw word");
}
#endif

int main(void)
{
    test_complete_parents();
    test_features_transport_and_delegation();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter_contract();
#endif
    if (failures != 0) {
        fprintf(stderr,
            "ARM SVE complex multiply-add tests failed: %d\n", failures);
        return 1;
    }
    printf("ARM SVE complex multiply-add tests passed "
           "(%llu SQDMLALBT, %llu SQDMLSLBT, %llu CDOT, "
           "%llu CMLA, %llu SQRDCMLAH, %llu reserved)\n",
           (unsigned long long)family_counts[TEST_SQDMLALBT],
           (unsigned long long)family_counts[TEST_SQDMLSLBT],
           (unsigned long long)family_counts[TEST_CDOT],
           (unsigned long long)family_counts[TEST_CMLA],
           (unsigned long long)family_counts[TEST_SQRDCMLAH],
           (unsigned long long)reserved_count);
    return 0;
}
