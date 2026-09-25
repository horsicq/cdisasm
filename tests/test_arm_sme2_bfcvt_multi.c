#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_BFCVT == UINT16_C(436),
               "multi-vector BFCVT must reuse its established mnemonic ID");
_Static_assert(CDISASM_ARM_NAME_BFCVTNT == UINT16_C(437),
               "the established BFCVTNT ID moved");
_Static_assert(CDISASM_ARM_NAME_BFCVTN == UINT16_C(438),
               "BFCVTN must be appended after BFCVTNT");
_Static_assert(CDISASM_ARM_NAME_BFCVTN < CDISASM_ARM_NAME_COUNT,
               "BFCVTN must remain in the ARM name catalog");
_Static_assert(CDISASM_ARM_NAME_FCVT == UINT16_C(433),
               "the established FCVT ID moved");
_Static_assert(CDISASM_ARM_NAME_SQCVT == UINT16_C(1466),
               "the established SQCVT ID moved");
_Static_assert(CDISASM_ARM_NAME_SQCVTU == UINT16_C(1468),
               "the established SQCVTU ID moved");
_Static_assert(CDISASM_ARM_NAME_UQCVT == UINT16_C(1794),
               "the established UQCVT ID moved");
_Static_assert(CDISASM_ARM_NAME_SUNPK == UINT16_C(1701),
               "the established SUNPK ID moved");
_Static_assert(CDISASM_ARM_NAME_UUNPK == UINT16_C(1859),
               "the established UUNPK ID moved");
_Static_assert(CDISASM_ARM_NAME_F1CVT == UINT16_C(814),
               "the established F1CVT ID moved");
_Static_assert(CDISASM_ARM_NAME_F1CVTL == UINT16_C(815),
               "the established F1CVTL ID moved");
_Static_assert(CDISASM_ARM_NAME_F2CVT == UINT16_C(817),
               "the established F2CVT ID moved");
_Static_assert(CDISASM_ARM_NAME_F2CVTL == UINT16_C(818),
               "the established F2CVTL ID moved");
_Static_assert(CDISASM_ARM_NAME_BF1CVT == UINT16_C(566),
               "the established BF1CVT ID moved");
_Static_assert(CDISASM_ARM_NAME_BF1CVTL == UINT16_C(567),
               "the established BF1CVTL ID moved");
_Static_assert(CDISASM_ARM_NAME_BF2CVT == UINT16_C(569),
               "the established BF2CVT ID moved");
_Static_assert(CDISASM_ARM_NAME_BF2CVTL == UINT16_C(570),
               "the established BF2CVTL ID moved");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + UINT16_C(1),
               "unexpected ARM mnemonic count");
_Static_assert(CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST == UINT8_C(8),
               "scalable-list operand ABI changed");

static int failures;

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

static uint32_t multi_cvt_word(
    unsigned selector, unsigned source_group, unsigned destination)
{
    return UINT32_C(0xc120e000)
        | ((uint32_t)((selector >> 4) & 1u) << 22)
        | ((uint32_t)((selector >> 1) & 7u) << 16)
        | ((uint32_t)(source_group & 15u) << 6)
        | ((uint32_t)(selector & 1u) << 5)
        | (uint32_t)(destination & 31u);
}

static uint32_t sve_fp8_downconvert_word(
    unsigned opc, unsigned source_group, unsigned destination)
{
    return UINT32_C(0x650a3000)
        | ((uint32_t)(opc & 3u) << 10)
        | ((uint32_t)(source_group & 15u) << 6)
        | (uint32_t)(destination & 31u);
}

static uint32_t multi_wide_integer_word(
    unsigned unsigned_conversion, unsigned size, unsigned source,
    unsigned destination_group)
{
    return UINT32_C(0xc125e000)
        | ((uint32_t)(size & 3u) << 22)
        | ((uint32_t)(source & 31u) << 5)
        | ((uint32_t)(destination_group & 15u) << 1)
        | (uint32_t)(unsigned_conversion & 1u);
}

static uint32_t multi_wide_fp8_word(
    unsigned operation, unsigned late, unsigned source,
    unsigned destination_group)
{
    return UINT32_C(0xc126e000)
        | ((uint32_t)(operation & 3u) << 22)
        | ((uint32_t)(source & 31u) << 5)
        | ((uint32_t)(destination_group & 15u) << 1)
        | (uint32_t)(late & 1u);
}

static int multi_cvt_word_is_allocated(uint32_t word)
{
    static const struct allocation_pattern {
        uint32_t mask;
        uint32_t value;
    } patterns[] = {
        /* sme2_cvt_vg2_single pairs selector rows that differ at bit 5. */
        { UINT32_C(0xfffffc00), UINT32_C(0xc120e000) },
        { UINT32_C(0xfffffc00), UINT32_C(0xc123e000) },
        { UINT32_C(0xfffffc20), UINT32_C(0xc124e000) },
        { UINT32_C(0xfffffc00), UINT32_C(0xc160e000) },
        { UINT32_C(0xfffffc20), UINT32_C(0xc163e000) },
        { UINT32_C(0xfffffc20), UINT32_C(0xc164e000) },
        /* sme2_frint_cvt_vg2_multi fixes bit 0 and pairs at bit 5. */
        { UINT32_C(0xfffffc01), UINT32_C(0xc121e000) },
        { UINT32_C(0xfffffc01), UINT32_C(0xc122e000) },
        /* FP8-upconvert layouts use all ten low bits. */
        { UINT32_C(0xfffffc00), UINT32_C(0xc126e000) },
        { UINT32_C(0xfffffc00), UINT32_C(0xc166e000) }
    };
    size_t index;

    if ((word & UINT32_C(0xff3ffc00)) == UINT32_C(0xc125e000)) {
        return ((word >> 22) & 3u) != 0u;
    }

    for (index = 0u;
         index < sizeof(patterns) / sizeof(patterns[0]); ++index) {
        if ((word & patterns[index].mask) == patterns[index].value) {
            return 1;
        }
    }
    return 0;
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
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x12a000),
        options, instruction);
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
typedef struct multi_cvt_operation {
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    uint8_t destination_element_size;
    uint8_t source_element_size;
    uint8_t destination_is_list;
    uint8_t floating_point;
} multi_cvt_operation;

static const multi_cvt_operation multi_cvt_operations[32] = {
    { CDISASM_ARM_NAME_FCVT, UINT16_C(4313), 2u, 4u, 0u, 1u },
    { CDISASM_ARM_NAME_FCVTN, UINT16_C(4315), 2u, 4u, 0u, 1u },
    { CDISASM_ARM_NAME_FCVTZS, UINT16_C(4316), 4u, 4u, 1u, 1u },
    { CDISASM_ARM_NAME_FCVTZU, UINT16_C(4317), 4u, 4u, 1u, 1u },
    { CDISASM_ARM_NAME_SCVTF, UINT16_C(4318), 4u, 4u, 1u, 1u },
    { CDISASM_ARM_NAME_UCVTF, UINT16_C(4319), 4u, 4u, 1u, 1u },
    { CDISASM_ARM_NAME_SQCVT, UINT16_C(4320), 2u, 4u, 0u, 0u },
    { CDISASM_ARM_NAME_UQCVT, UINT16_C(4322), 2u, 4u, 0u, 0u },
    { CDISASM_ARM_NAME_FCVT, UINT16_C(4324), 1u, 2u, 0u, 1u },
    [16] = { CDISASM_ARM_NAME_BFCVT, UINT16_C(4312), 2u, 4u, 0u, 1u },
    [17] = { CDISASM_ARM_NAME_BFCVTN, UINT16_C(4314), 2u, 4u, 0u, 1u },
    [22] = { CDISASM_ARM_NAME_SQCVTU, UINT16_C(4321), 2u, 4u, 0u, 0u },
    [24] = { CDISASM_ARM_NAME_BFCVT, UINT16_C(4323), 1u, 2u, 0u, 1u }
};

static const multi_cvt_operation sve_fp8_operations[4] = {
    { CDISASM_ARM_NAME_FCVTN, UINT16_C(3165), 1u, 2u, 0u, 1u },
    { CDISASM_ARM_NAME_FCVTNB, UINT16_C(3166), 1u, 4u, 0u, 1u },
    { CDISASM_ARM_NAME_BFCVTN, UINT16_C(3167), 1u, 2u, 0u, 1u },
    { CDISASM_ARM_NAME_FCVTNT, UINT16_C(3168), 1u, 4u, 0u, 1u }
};

static void build_expected_instruction(
    uint32_t word, const multi_cvt_operation *operation, int sme,
    unsigned source_group, unsigned destination,
    cdisasm_arm_instruction *expected)
{
    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x12a000);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;
    if (operation->floating_point) {
        expected->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
    }
    if (sme) {
        expected->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SME;
    }
    expected->name_id = operation->name_id;
    expected->operand_count = 2u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->form_id = operation->form_id;

    expected->operand[0].type = operation->destination_is_list
        ? CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        : CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[0].reg =
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
            + (operation->destination_is_list
                ? destination & ~1u : destination));
    if (operation->destination_is_list) {
        expected->operand[0].register_list = UINT16_C(0x0102);
    }
    expected->operand[0].extend_type =
        (cdisasm_arm_extend_type)operation->destination_element_size;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;

    expected->operand[1].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[1].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + source_group * 2u);
    expected->operand[1].register_list = UINT16_C(0x0102);
    expected->operand[1].extend_type =
        (cdisasm_arm_extend_type)operation->source_element_size;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
}

static void build_expected_wide_integer_instruction(
    uint32_t word, cdisasm_arm_instruction *expected)
{
    unsigned size = (word >> 22) & 3u;
    unsigned source_element_size = 1u << (size - 1u);

    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x12a000);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | CDISASM_ARM_INSTRUCTION_FLAG_SME;
    expected->name_id = (word & 1u) != 0u
        ? CDISASM_ARM_NAME_UUNPK : CDISASM_ARM_NAME_SUNPK;
    expected->operand_count = 2u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->form_id = (word & 1u) != 0u
        ? UINT16_C(4326) : UINT16_C(4325);

    expected->operand[0].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[0].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 30u));
    expected->operand[0].register_list = UINT16_C(0x0102);
    expected->operand[0].extend_type =
        (cdisasm_arm_extend_type)(source_element_size * 2u);
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;

    expected->operand[1].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[1].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u));
    expected->operand[1].extend_type =
        (cdisasm_arm_extend_type)source_element_size;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
}

static void build_expected_wide_fp8_instruction(
    uint32_t word, cdisasm_arm_instruction *expected)
{
    static const cdisasm_arm_name_id names[4][2] = {
        { CDISASM_ARM_NAME_F1CVT, CDISASM_ARM_NAME_F1CVTL },
        { CDISASM_ARM_NAME_BF1CVT, CDISASM_ARM_NAME_BF1CVTL },
        { CDISASM_ARM_NAME_F2CVT, CDISASM_ARM_NAME_F2CVTL },
        { CDISASM_ARM_NAME_BF2CVT, CDISASM_ARM_NAME_BF2CVTL }
    };
    static const cdisasm_arm_form_id forms[4][2] = {
        { UINT16_C(4327), UINT16_C(4331) },
        { UINT16_C(4328), UINT16_C(4332) },
        { UINT16_C(4329), UINT16_C(4333) },
        { UINT16_C(4330), UINT16_C(4334) }
    };
    unsigned operation = (word >> 22) & 3u;
    unsigned late = word & 1u;

    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x12a000);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
        | CDISASM_ARM_INSTRUCTION_FLAG_SME;
    expected->name_id = names[operation][late];
    expected->operand_count = 2u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->form_id = forms[operation][late];

    expected->operand[0].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[0].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 30u));
    expected->operand[0].register_list = UINT16_C(0x0102);
    expected->operand[0].extend_type = (cdisasm_arm_extend_type)2u;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;

    expected->operand[1].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[1].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u));
    expected->operand[1].extend_type = (cdisasm_arm_extend_type)1u;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
}
#endif

static void test_exhaustive_selector_domain(void)
{
    uint32_t implemented_allocated = 0u;
    uint32_t implemented_by_selector[32] = { 0u };
    uint32_t allocated_siblings = 0u;
    uint32_t reserved = 0u;
    unsigned selector;

    /* Exhaust every operation selector, encoded source-pair base, and
     * destination in the exact SME2 multi-vector conversion envelope. */
    for (selector = 0u; selector < 32u; ++selector) {
        unsigned source_group;

        for (source_group = 0u; source_group < 16u; ++source_group) {
            unsigned destination;

            for (destination = 0u; destination < 32u; ++destination) {
                cdisasm_arm_instruction instruction;
                uint32_t word = multi_cvt_word(
                    selector, source_group, destination);
                uint32_t decoded;

                domain_expect(
                    (word & UINT32_C(0xffb8fc00))
                        == UINT32_C(0xc120e000),
                    word, "word escaped the multi-vector CVT envelope");
                memset(&instruction, 0xa5, sizeof(instruction));
                decoded = decode_word(
                    word, CDISASM_ARM_CPU_ANY,
                    CDISASM_ARM_MODE_A64, 4u,
                    CDISASM_ARM_DECODE_OPTION_NONE, &instruction);

                if (multi_cvt_word_is_allocated(word)
                    && (selector <= 8u || selector == 10u
                        || selector == 11u
                        || selector == 12u || selector == 13u
                        || selector == 16u || selector == 17u
                        || selector == 22u
                        || selector == 24u || selector == 26u
                        || selector == 27u || selector == 28u
                        || selector == 29u)) {
                    ++implemented_allocated;
                    ++implemented_by_selector[selector];
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        if (selector == 10u || selector == 11u
                            || selector == 26u || selector == 27u) {
                            build_expected_wide_integer_instruction(
                                word, &expected);
                        } else if (selector == 12u || selector == 13u
                            || selector == 28u || selector == 29u) {
                            build_expected_wide_fp8_instruction(
                                word, &expected);
                        } else {
                            build_expected_instruction(
                                word, &multi_cvt_operations[selector], 1,
                                source_group, destination, &expected);
                        }
                        domain_expect(decoded == 4u, word,
                            "implemented multi-vector conversion did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected,
                            sizeof(expected)) == 0,
                            word, "multi-vector conversion metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF build decoded multi-vector conversion");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF conversion ownership mismatch");
#endif
                } else if (multi_cvt_word_is_allocated(word)) {
                    ++allocated_siblings;
                    domain_expect(decoded == 0u, word,
                        "unimplemented allocated CVT sibling decoded");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "allocated CVT sibling status mismatch");
                } else {
                    ++reserved;
                    domain_expect(decoded == 0u, word,
                        "reserved multi-vector CVT selector decoded");
                    domain_expect(instruction_is_error_only(
                        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
                        word, "reserved CVT selector status mismatch");
                }
            }
        }
    }

    EXPECT(implemented_allocated == UINT32_C(8704));
    EXPECT(implemented_by_selector[0] == UINT32_C(512));
    EXPECT(implemented_by_selector[1] == UINT32_C(512));
    EXPECT(implemented_by_selector[2] == UINT32_C(256));
    EXPECT(implemented_by_selector[3] == UINT32_C(256));
    EXPECT(implemented_by_selector[4] == UINT32_C(256));
    EXPECT(implemented_by_selector[5] == UINT32_C(256));
    EXPECT(implemented_by_selector[6] == UINT32_C(512));
    EXPECT(implemented_by_selector[7] == UINT32_C(512));
    EXPECT(implemented_by_selector[8] == UINT32_C(512));
    EXPECT(implemented_by_selector[10] == UINT32_C(0));
    EXPECT(implemented_by_selector[11] == UINT32_C(0));
    EXPECT(implemented_by_selector[12] == UINT32_C(512));
    EXPECT(implemented_by_selector[13] == UINT32_C(512));
    EXPECT(implemented_by_selector[16] == UINT32_C(512));
    EXPECT(implemented_by_selector[17] == UINT32_C(512));
    EXPECT(implemented_by_selector[22] == UINT32_C(512));
    EXPECT(implemented_by_selector[24] == UINT32_C(512));
    EXPECT(implemented_by_selector[26] == UINT32_C(512));
    EXPECT(implemented_by_selector[27] == UINT32_C(512));
    EXPECT(implemented_by_selector[28] == UINT32_C(512));
    EXPECT(implemented_by_selector[29] == UINT32_C(512));
    EXPECT(allocated_siblings == UINT32_C(0));
    EXPECT(reserved == UINT32_C(7680));
    EXPECT(implemented_allocated + allocated_siblings + reserved
        == UINT32_C(16384));
}

static void test_exhaustive_sve_fp8_downconvert_domain(void)
{
    uint32_t implemented_by_opcode[4] = { 0u };
    unsigned opc;

    /* Exhaust all four allocated opc rows and distinguish their exact
     * mnemonic, form identity, and H/S source element widths. */
    for (opc = 0u; opc < 4u; ++opc) {
        unsigned source_group;

        for (source_group = 0u; source_group < 16u; ++source_group) {
            unsigned destination;

            for (destination = 0u; destination < 32u; ++destination) {
                cdisasm_arm_instruction instruction;
                uint32_t word = sve_fp8_downconvert_word(
                    opc, source_group, destination);
                uint32_t decoded;

                domain_expect(
                    (word & UINT32_C(0xfffff020))
                        == UINT32_C(0x650a3000),
                    word, "word escaped the SVE2 FP8 narrowing envelope");
                memset(&instruction, 0xa5, sizeof(instruction));
                decoded = decode_word(
                    word, CDISASM_ARM_CPU_ANY,
                    CDISASM_ARM_MODE_A64, 4u,
                    CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                ++implemented_by_opcode[opc];
#if USE_EXTRA_OPCODES
                {
                    cdisasm_arm_instruction expected;

                    build_expected_instruction(
                        word, &sve_fp8_operations[opc], 0,
                        source_group, destination, &expected);
                    domain_expect(decoded == 4u, word,
                        "allocated SVE2 FP8 conversion did not decode");
                    domain_expect(memcmp(
                        &instruction, &expected,
                        sizeof(expected)) == 0,
                        word, "SVE2 FP8 conversion metadata mismatch");
                }
#else
                domain_expect(decoded == 0u, word,
                    "extras-OFF build decoded SVE2 FP8 conversion");
                domain_expect(instruction_is_error_only(
                    &instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                    word, "extras-OFF SVE2 FP8 ownership mismatch");
#endif
            }
        }
    }

    EXPECT(implemented_by_opcode[0] == UINT32_C(512));
    EXPECT(implemented_by_opcode[1] == UINT32_C(512));
    EXPECT(implemented_by_opcode[2] == UINT32_C(512));
    EXPECT(implemented_by_opcode[3] == UINT32_C(512));
}

static void test_exhaustive_wide_integer_domain(void)
{
    uint32_t words_by_operation_and_size[2][4] = { { 0u } };
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned unsigned_conversion;

    /* Exhaust both signedness rows, the reserved size=00 control, all three
     * widening element sizes, every source register, and every encoded even
     * destination pair. */
    for (unsigned_conversion = 0u;
         unsigned_conversion < 2u; ++unsigned_conversion) {
        unsigned size;

        for (size = 0u; size < 4u; ++size) {
            unsigned source;

            for (source = 0u; source < 32u; ++source) {
                unsigned destination_group;

                for (destination_group = 0u;
                     destination_group < 16u; ++destination_group) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = multi_wide_integer_word(
                        unsigned_conversion, size, source,
                        destination_group);
                    uint32_t decoded;

                    domain_expect(
                        (word & UINT32_C(0xff3ffc01))
                            == (UINT32_C(0xc125e000)
                                | (uint32_t)unsigned_conversion),
                        word, "word escaped the SME2 wide-integer envelope");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY,
                        CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    ++words_by_operation_and_size
                        [unsigned_conversion][size];
                    if (size == 0u) {
                        ++reserved;
                        domain_expect(decoded == 0u, word,
                            "reserved SME2 wide-integer size decoded");
                        domain_expect(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION),
                            word, "reserved wide-integer size status mismatch");
                        continue;
                    }
                    ++allocated;
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        build_expected_wide_integer_instruction(
                            word, &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated SME2 wide-integer form did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected,
                            sizeof(expected)) == 0,
                            word, "SME2 wide-integer metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF build decoded SME2 wide-integer form");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF wide-integer ownership mismatch");
#endif
                }
            }
        }
    }

    for (unsigned_conversion = 0u;
         unsigned_conversion < 2u; ++unsigned_conversion) {
        unsigned size;

        for (size = 0u; size < 4u; ++size) {
            EXPECT(words_by_operation_and_size
                [unsigned_conversion][size] == UINT32_C(512));
        }
    }
    EXPECT(allocated == UINT32_C(3072));
    EXPECT(reserved == UINT32_C(1024));
}

static void test_exhaustive_wide_fp8_domain(void)
{
    uint32_t implemented_by_operation_and_late[4][2] = { { 0u } };
    unsigned operation;

    /* Exhaust all eight allocated FP8 widening rows, every source register,
     * and all architecturally encoded even destination pairs. */
    for (operation = 0u; operation < 4u; ++operation) {
        unsigned late;

        for (late = 0u; late < 2u; ++late) {
            unsigned source;

            for (source = 0u; source < 32u; ++source) {
                unsigned destination_group;

                for (destination_group = 0u;
                     destination_group < 16u; ++destination_group) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = multi_wide_fp8_word(
                        operation, late, source, destination_group);
                    uint32_t expected_value = UINT32_C(0xc126e000)
                        | ((uint32_t)operation << 22)
                        | (uint32_t)late;
                    uint32_t decoded;

                    domain_expect(
                        (word & UINT32_C(0xfffffc01))
                            == expected_value,
                        word, "word escaped the SME2 FP8 widening row");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY,
                        CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    ++implemented_by_operation_and_late[operation][late];
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        build_expected_wide_fp8_instruction(word, &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated SME2 FP8 widening form did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected,
                            sizeof(expected)) == 0,
                            word, "SME2 FP8 widening metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF build decoded SME2 FP8 widening form");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF FP8 widening ownership mismatch");
#endif
                }
            }
        }
    }

    for (operation = 0u; operation < 4u; ++operation) {
        unsigned late;

        for (late = 0u; late < 2u; ++late) {
            EXPECT(implemented_by_operation_and_late[operation][late]
                == UINT32_C(512));
        }
    }
}

static void test_feature_and_profile_gates(void)
{
    static const struct gate_form {
        uint32_t word;
        cdisasm_arm_name_id name_id;
        uint8_t fp8_destination_element_size;
    } forms[] = {
        { UINT32_C(0xc120e155), CDISASM_ARM_NAME_FCVT, 0 },
        { UINT32_C(0xc120e175), CDISASM_ARM_NAME_FCVTN, 0 },
        { UINT32_C(0xc121e154), CDISASM_ARM_NAME_FCVTZS, 0 },
        { UINT32_C(0xc121e174), CDISASM_ARM_NAME_FCVTZU, 0 },
        { UINT32_C(0xc122e154), CDISASM_ARM_NAME_SCVTF, 0 },
        { UINT32_C(0xc122e174), CDISASM_ARM_NAME_UCVTF, 0 },
        { UINT32_C(0xc123e155), CDISASM_ARM_NAME_SQCVT, 0 },
        { UINT32_C(0xc123e175), CDISASM_ARM_NAME_UQCVT, 0 },
        { UINT32_C(0xc124e3df), CDISASM_ARM_NAME_FCVT, 1 },
        { UINT32_C(0xc160e155), CDISASM_ARM_NAME_BFCVT, 0 },
        { UINT32_C(0xc160e175), CDISASM_ARM_NAME_BFCVTN, 0 },
        { UINT32_C(0xc163e155), CDISASM_ARM_NAME_SQCVTU, 0 },
        { UINT32_C(0xc164e3df), CDISASM_ARM_NAME_BFCVT, 1 },
        { UINT32_C(0xc165e154), CDISASM_ARM_NAME_SUNPK, 0 },
        { UINT32_C(0xc1e5e3ff), CDISASM_ARM_NAME_UUNPK, 0 },
        { UINT32_C(0xc126e000), CDISASM_ARM_NAME_F1CVT, 2 },
        { UINT32_C(0xc126e3ff), CDISASM_ARM_NAME_F1CVTL, 2 },
        { UINT32_C(0xc166e0a6), CDISASM_ARM_NAME_BF1CVT, 2 },
        { UINT32_C(0xc166e0a7), CDISASM_ARM_NAME_BF1CVTL, 2 },
        { UINT32_C(0xc1a6e14e), CDISASM_ARM_NAME_F2CVT, 2 },
        { UINT32_C(0xc1a6e14f), CDISASM_ARM_NAME_F2CVTL, 2 },
        { UINT32_C(0xc1e6e3fe), CDISASM_ARM_NAME_BF2CVT, 2 },
        { UINT32_C(0xc1e6e3ff), CDISASM_ARM_NAME_BF2CVTL, 2 },
        { UINT32_C(0x650a33df), CDISASM_ARM_NAME_FCVTN, 1 },
        { UINT32_C(0x650a37df), CDISASM_ARM_NAME_FCVTNB, 1 },
        { UINT32_C(0x650a3bdf), CDISASM_ARM_NAME_BFCVTN, 1 },
        { UINT32_C(0x650a3fdf), CDISASM_ARM_NAME_FCVTNT, 1 }
    };
    uint32_t cpu_value;

    for (cpu_value = CDISASM_ARM_CPU_FIRST;
         cpu_value <= CDISASM_ARM_CPU_LAST;
         ++cpu_value) {
        cdisasm_arm_cpu_id cpu_id = (cdisasm_arm_cpu_id)cpu_value;
        size_t form_index;

        for (form_index = 0u;
             form_index < sizeof(forms) / sizeof(forms[0]);
             ++form_index) {
            cdisasm_arm_instruction instruction;
            cdisasm_status expected_status;
            uint32_t decoded;

            if ((cdisasm_arm_cpu_mode_mask(cpu_id)
                    & CDISASM_ARM_MODE_MASK_A64) == 0u) {
                expected_status = CDISASM_STATUS_INVALID_ARGUMENT;
#if USE_EXTRA_OPCODES
            } else if (forms[form_index].fp8_destination_element_size == 0u
                && (cpu_id == CDISASM_ARM_CPU_APPLE_A18
                    || cpu_id == CDISASM_ARM_CPU_APPLE_M4)) {
                expected_status = CDISASM_STATUS_OK;
            } else {
                expected_status = CDISASM_STATUS_INVALID_INSTRUCTION;
#else
            } else {
                expected_status = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                forms[form_index].word, cpu_id,
                CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            if (expected_status == CDISASM_STATUS_OK) {
                EXPECT(decoded == 4u);
                EXPECT(instruction.name_id == forms[form_index].name_id);
            } else {
                EXPECT(decoded == 0u);
                EXPECT(instruction_is_error_only(
                    &instruction, expected_status));
            }
        }
    }

    {
        size_t form_index;

        for (form_index = 0u;
             form_index < sizeof(forms) / sizeof(forms[0]);
             ++form_index) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                forms[form_index].word, CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
            EXPECT(decoded == 4u);
            EXPECT(instruction.name_id == forms[form_index].name_id);
            if (forms[form_index].fp8_destination_element_size != 0u) {
                EXPECT(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
                    &instruction.operand[0])
                    == forms[form_index].fp8_destination_element_size);
            }
#else
            EXPECT(decoded == 0u);
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static void test_endian_dispatch_and_errors(void)
{
    const uint32_t word = UINT32_C(0xc1e6e3ff);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t little_bytes[4];
    uint8_t big_bytes[4];
    uint32_t decoded;
    size_t code_size;

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
        big_bytes, sizeof(big_bytes), UINT64_C(0x12a000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &big, sizeof(little)) == 0);

    word_to_le(word, little_bytes);
    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x12a000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &generic, sizeof(little)) == 0);

    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode_checked(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x12a000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic, sizeof(generic));
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &generic, sizeof(little)) == 0);

    for (code_size = 1u; code_size < 4u; ++code_size) {
        memset(&generic, 0xa5, sizeof(generic));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            code_size, CDISASM_ARM_DECODE_OPTION_NONE,
            &generic) == 0u);
        EXPECT(instruction_is_error_only(
            &generic, CDISASM_STATUS_TRUNCATED));
    }

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        multi_cvt_word(18u, 0u, 0u), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_INSTRUCTION));

    memset(&generic, 0xa5, sizeof(generic));
    (void)decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_BFCVT);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_BFCVTNT);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_BFCVTN);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_SQCVT);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_SQCVTU);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_UQCVT);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_SUNPK);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_UUNPK);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_F1CVT);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_F1CVTL);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_BF1CVT);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_BF1CVTL);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_F2CVT);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_F2CVTL);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_BF2CVT);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_BF2CVTL);
    EXPECT(generic.isa_id != CDISASM_ARM_ISA_A64);
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void test_formatting(void)
{
    static const struct format_vector {
        uint32_t word;
        const char *text;
    } vectors[] = {
        { UINT32_C(0xc120e000), "fcvt z0.h, {z0.s, z1.s}" },
        { UINT32_C(0xc120e020), "fcvtn z0.h, {z0.s, z1.s}" },
        { UINT32_C(0xc121e000),
          "fcvtzs {z0.s, z1.s}, {z0.s, z1.s}" },
        { UINT32_C(0xc121e3de),
          "fcvtzs {z30.s, z31.s}, {z30.s, z31.s}" },
        { UINT32_C(0xc121e020),
          "fcvtzu {z0.s, z1.s}, {z0.s, z1.s}" },
        { UINT32_C(0xc122e000),
          "scvtf {z0.s, z1.s}, {z0.s, z1.s}" },
        { UINT32_C(0xc122e020),
          "ucvtf {z0.s, z1.s}, {z0.s, z1.s}" },
        { UINT32_C(0xc123e000), "sqcvt z0.h, {z0.s, z1.s}" },
        { UINT32_C(0xc123e175), "uqcvt z21.h, {z10.s, z11.s}" },
        { UINT32_C(0xc124e3df), "fcvt z31.b, {z30.h, z31.h}" },
        { UINT32_C(0xc160e000), "bfcvt z0.h, {z0.s, z1.s}" },
        { UINT32_C(0xc160e155), "bfcvt z21.h, {z10.s, z11.s}" },
        { UINT32_C(0xc160e3df), "bfcvt z31.h, {z30.s, z31.s}" },
        { UINT32_C(0xc160e020), "bfcvtn z0.h, {z0.s, z1.s}" },
        { UINT32_C(0xc160e175), "bfcvtn z21.h, {z10.s, z11.s}" },
        { UINT32_C(0xc160e3ff), "bfcvtn z31.h, {z30.s, z31.s}" },
        { UINT32_C(0xc163e155), "sqcvtu z21.h, {z10.s, z11.s}" },
        { UINT32_C(0xc164e000), "bfcvt z0.b, {z0.h, z1.h}" },
        { UINT32_C(0xc164e3df), "bfcvt z31.b, {z30.h, z31.h}" },
        { UINT32_C(0xc165e000), "sunpk {z0.h, z1.h}, z0.b" },
        { UINT32_C(0xc165e3ff), "uunpk {z30.h, z31.h}, z31.b" },
        { UINT32_C(0xc1a5e0a6), "sunpk {z6.s, z7.s}, z5.h" },
        { UINT32_C(0xc1a5e0a7), "uunpk {z6.s, z7.s}, z5.h" },
        { UINT32_C(0xc1e5e14e), "sunpk {z14.d, z15.d}, z10.s" },
        { UINT32_C(0xc1e5e14f), "uunpk {z14.d, z15.d}, z10.s" },
        { UINT32_C(0xc126e000), "f1cvt {z0.h, z1.h}, z0.b" },
        { UINT32_C(0xc126e3ff), "f1cvtl {z30.h, z31.h}, z31.b" },
        { UINT32_C(0xc166e0a6), "bf1cvt {z6.h, z7.h}, z5.b" },
        { UINT32_C(0xc166e0a7), "bf1cvtl {z6.h, z7.h}, z5.b" },
        { UINT32_C(0xc1a6e14e), "f2cvt {z14.h, z15.h}, z10.b" },
        { UINT32_C(0xc1a6e14f), "f2cvtl {z14.h, z15.h}, z10.b" },
        { UINT32_C(0xc1e6e3fe), "bf2cvt {z30.h, z31.h}, z31.b" },
        { UINT32_C(0xc1e6e3ff), "bf2cvtl {z30.h, z31.h}, z31.b" },
        { UINT32_C(0x650a3000), "fcvtn z0.b, {z0.h, z1.h}" },
        { UINT32_C(0x650a3400), "fcvtnb z0.b, {z0.s, z1.s}" },
        { UINT32_C(0x650a3800), "bfcvtn z0.b, {z0.h, z1.h}" },
        { UINT32_C(0x650a3bdf), "bfcvtn z31.b, {z30.h, z31.h}" },
        { UINT32_C(0x650a3c00), "fcvtnt z0.b, {z0.s, z1.s}" }
    };
    size_t index;

    for (index = 0u; index < sizeof(vectors) / sizeof(vectors[0]);
         ++index) {
        cdisasm_arm_instruction instruction;
        char text[80];
        size_t expected_length = strlen(vectors[index].text);

        EXPECT(decode_word(
            vectors[index].word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == expected_length);
        EXPECT(strcmp(text, vectors[index].text) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            NULL, 0u) == expected_length);
    }

    {
        cdisasm_arm_instruction instruction;
        char text[80];
        size_t operand_index;

        EXPECT(decode_word(
            UINT32_C(0xc1e5e14e), CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        for (operand_index = 0u; operand_index < 2u; ++operand_index) {
            cdisasm_arm_instruction invalid = instruction;

            invalid.operand[operand_index].extend_type =
                (cdisasm_arm_extend_type)16u;
            memset(text, 0xa5, sizeof(text));
            EXPECT(cdisasm_arm_format(
                &invalid, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
                text, sizeof(text)) == 0u);
            EXPECT(text[0] == '\0');
        }
    }

    {
        cdisasm_arm_instruction instruction;
        char text[80];
        char short_text[7];
        static const char expected[] =
            "BFCVTN z31.b, {z30.h, z31.h}";

        EXPECT(decode_word(
            UINT32_C(0x650a3bdf), CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_7,
            short_text, sizeof(short_text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(short_text, "bfcvtn") == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_selector_domain();
    test_exhaustive_sve_fp8_downconvert_domain();
    test_exhaustive_wide_integer_domain();
    test_exhaustive_wide_fp8_domain();
    test_feature_and_profile_gates();
    test_endian_dispatch_and_errors();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM SME2 multi-vector BFCVT test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM multi-vector conversion tests passed "
           "(22528 unique controls: implemented=14848, "
           "allocated siblings=0, reserved=7680; "
           "SUNPK/UUNPK=3072+1024 reserved, FP8 widening=4096; "
           "USE_EXTRA_OPCODES=%d)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
