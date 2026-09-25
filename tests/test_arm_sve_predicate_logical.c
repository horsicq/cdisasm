#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_CNEG == UINT16_C(331),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_BICS == UINT16_C(332),
               "SVE predicate-logical IDs must be append-only");
_Static_assert(CDISASM_ARM_NAME_SEL == UINT16_C(341),
               "SVE predicate-logical terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_SUBPT == UINT16_C(347),
               "later ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(421),
               "ARM mnemonic name count changed");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");
_Static_assert(sizeof(cdisasm_arm_decode_option) == sizeof(uint64_t),
               "ARM decode options must remain 64-bit");
_Static_assert(CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED == UINT8_C(16),
               "typed-predicate metadata flag changed");

typedef struct predicate_logical_case {
    const char *label;
    uint32_t word;
    cdisasm_arm_name_id name_id;
    const char *text;
} predicate_logical_case;

static const predicate_logical_case predicate_logical_cases[] = {
    { "and", UINT32_C(0x250954e3), CDISASM_ARM_NAME_AND,
      "and p3.b, p5/z, p7.b, p9.b" },
    { "ands", UINT32_C(0x254a5904), CDISASM_ARM_NAME_ANDS,
      "ands p4.b, p6/z, p8.b, p10.b" },
    { "bic", UINT32_C(0x250b5d35), CDISASM_ARM_NAME_BIC,
      "bic p5.b, p7/z, p9.b, p11.b" },
    { "bics", UINT32_C(0x254c6156), CDISASM_ARM_NAME_BICS,
      "bics p6.b, p8/z, p10.b, p12.b" },
    { "eor", UINT32_C(0x250d6767), CDISASM_ARM_NAME_EOR,
      "eor p7.b, p9/z, p11.b, p13.b" },
    { "eors", UINT32_C(0x254e6b88), CDISASM_ARM_NAME_EORS,
      "eors p8.b, p10/z, p12.b, p14.b" },
    { "nand", UINT32_C(0x258f6fb9), CDISASM_ARM_NAME_NAND,
      "nand p9.b, p11/z, p13.b, p15.b" },
    { "nands", UINT32_C(0x25c073da), CDISASM_ARM_NAME_NANDS,
      "nands p10.b, p12/z, p14.b, p0.b" },
    { "nor", UINT32_C(0x258177eb), CDISASM_ARM_NAME_NOR,
      "nor p11.b, p13/z, p15.b, p1.b" },
    { "nors", UINT32_C(0x25c27a0c), CDISASM_ARM_NAME_NORS,
      "nors p12.b, p14/z, p0.b, p2.b" },
    { "orr", UINT32_C(0x25837c2d), CDISASM_ARM_NAME_ORR,
      "orr p13.b, p15/z, p1.b, p3.b" },
    { "orrs", UINT32_C(0x25c4404e), CDISASM_ARM_NAME_ORRS,
      "orrs p14.b, p0/z, p2.b, p4.b" },
    { "orn", UINT32_C(0x2585447f), CDISASM_ARM_NAME_ORN,
      "orn p15.b, p1/z, p3.b, p5.b" },
    { "orns", UINT32_C(0x25c5447f), CDISASM_ARM_NAME_ORNS,
      "orns p15.b, p1/z, p3.b, p5.b" },
    { "sel", UINT32_C(0x25044a71), CDISASM_ARM_NAME_SEL,
      "sel p1.b, p2, p3.b, p4.b" }
};

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static void word_to_le(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)word;
    bytes[1] = (uint8_t)(word >> 8);
    bytes[2] = (uint8_t)(word >> 16);
    bytes[3] = (uint8_t)(word >> 24);
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

static uint32_t decode_word(
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    cdisasm_arm_decode_option options,
    size_t code_size,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x4000), options,
        instruction);
}

#if USE_EXTRA_OPCODES
static void expect_operand(
    const cdisasm_arm_operand *operand,
    cdisasm_arm_reg_id reg,
    cdisasm_operand_access access,
    uint8_t flags)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_PREDICATE;
    expected.reg = reg;
    expected.access = access;
    expected.flags = flags;
    expected.extend_type = UINT8_C(1);
    EXPECT(memcmp(operand, &expected, sizeof(expected)) == 0);
}

static void expect_decoded_case(const predicate_logical_case *test_case)
{
    cdisasm_arm_instruction instruction;
    unsigned pd = test_case->word & 15u;
    unsigned pn = (test_case->word >> 5) & 15u;
    unsigned pg = (test_case->word >> 10) & 15u;
    unsigned pm = (test_case->word >> 16) & 15u;
    unsigned operation = ((test_case->word >> 20) & 12u)
        | ((test_case->word >> 8) & 2u)
        | ((test_case->word >> 4) & 1u);
    uint32_t expected_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        test_case->word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 4u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == test_case->name_id);
    EXPECT(instruction.address == UINT64_C(0x4000));
    EXPECT(instruction.raw_instruction == test_case->word);
    EXPECT(instruction.opcode_size == 4u);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_A64);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.operand_count == 4u);
    if ((operation & 4u) != 0u) {
        expected_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    }
    EXPECT(instruction.instruction_flags == expected_flags);
    expect_operand(
        &instruction.operand[0],
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pd),
        CDISASM_OPERAND_ACCESS_WRITE,
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    expect_operand(
        &instruction.operand[1],
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg),
        CDISASM_OPERAND_ACCESS_READ,
        operation == 3u
            ? UINT8_C(0) : CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);
    expect_operand(
        &instruction.operand[2],
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pn),
        CDISASM_OPERAND_ACCESS_READ,
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    expect_operand(
        &instruction.operand[3],
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pm),
        CDISASM_OPERAND_ACCESS_READ,
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);

#if USE_DISASM_FORMAT
    {
        char text[128];
        size_t expected_size = strlen(test_case->text);

        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == expected_size);
        EXPECT(strcmp(text, test_case->text) == 0);
    }
#endif
}
#endif

static void test_all_forms_and_extra_gate(void)
{
    size_t index;

    for (index = 0u;
         index < sizeof(predicate_logical_cases)
            / sizeof(predicate_logical_cases[0]);
         ++index) {
#if USE_EXTRA_OPCODES
        expect_decoded_case(&predicate_logical_cases[index]);
#else
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            predicate_logical_cases[index].word,
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_reserved_truncated_cpu_mode_and_options(void)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded;
    static const uint8_t big_endian_and[4] = {
        UINT8_C(0x25), UINT8_C(0x09), UINT8_C(0x54), UINT8_C(0xe3)
    };

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        UINT32_C(0x25404210), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE, 4u,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        UINT32_C(0x250954e3), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE, 3u,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_TRUNCATED));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        UINT32_C(0x250954e3), CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE, 4u,
        &instruction) == 0u);
#if USE_EXTRA_OPCODES
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        UINT32_C(0x250954e3), CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_MODE_A32, CDISASM_ARM_DECODE_OPTION_NONE, 4u,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        UINT32_C(0x250954e3), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, UINT64_C(1) << 63, 4u,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        big_endian_and, sizeof(big_endian_and), UINT64_C(0x4000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &instruction);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_AND);
#else
    EXPECT(decoded == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

int main(void)
{
    test_all_forms_and_extra_gate();
    test_reserved_truncated_cpu_mode_and_options();

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE predicate-logical test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE predicate-logical tests passed "
           "(USE_EXTRA_OPCODES=%d)\n", USE_EXTRA_OPCODES);
    return 0;
}
