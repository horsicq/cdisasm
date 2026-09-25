#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_FRINTN == UINT16_C(421),
               "the established FRINTN ID moved");
_Static_assert(CDISASM_ARM_NAME_FRINTP == UINT16_C(422),
               "the established FRINTP ID moved");
_Static_assert(CDISASM_ARM_NAME_FRINTM == UINT16_C(423),
               "the established FRINTM ID moved");
_Static_assert(CDISASM_ARM_NAME_FRINTA == UINT16_C(425),
               "the established FRINTA ID moved");
_Static_assert(CDISASM_ARM_NAME_FCVT == UINT16_C(433),
               "the established FCVT ID moved");
_Static_assert(CDISASM_ARM_NAME_FCVTL == UINT16_C(833),
               "the established FCVTL ID moved");
_Static_assert(CDISASM_ARM_NAME_SQCVTN == UINT16_C(1467),
               "the established SQCVTN ID moved");
_Static_assert(CDISASM_ARM_NAME_SQCVTUN == UINT16_C(1469),
               "the established SQCVTUN ID moved");
_Static_assert(CDISASM_ARM_NAME_UQCVTN == UINT16_C(1795),
               "the established UQCVTN ID moved");
_Static_assert(CDISASM_ARM_NAME_SQRSHRN == UINT16_C(1499),
               "the established SQRSHRN ID moved");
_Static_assert(CDISASM_ARM_NAME_SQRSHRUN == UINT16_C(1503),
               "the established SQRSHRUN ID moved");
_Static_assert(CDISASM_ARM_NAME_UQRSHRN == UINT16_C(1809),
               "the established UQRSHRN ID moved");

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
        cpu_id, mode, bytes, code_size, UINT64_C(0x12b000),
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

static uint32_t narrow_word(
    uint32_t base, unsigned source_group, unsigned destination,
    unsigned reserved_half)
{
    return base
        | ((uint32_t)(source_group & 15u) << 6)
        | (uint32_t)(destination & 31u)
        | ((uint32_t)(reserved_half & 1u) << 5);
}

static uint32_t frint_word(
    uint32_t base, unsigned source_group, unsigned destination_group,
    unsigned reserved_control)
{
    return base
        | ((uint32_t)(source_group & 15u) << 6)
        | ((uint32_t)(destination_group & 15u) << 1)
        | ((uint32_t)(reserved_control & 1u))
        | ((uint32_t)((reserved_control >> 1) & 1u) << 5);
}

static uint32_t narrowing_shift_word(
    uint32_t base, unsigned encoded_immediate, unsigned source_group,
    unsigned destination)
{
    return base | ((uint32_t)(encoded_immediate & 31u) << 16)
        | ((uint32_t)(source_group & 15u) << 6)
        | (uint32_t)(destination & 31u);
}

static uint32_t f16_word(
    unsigned late, unsigned source, unsigned destination_group)
{
    return UINT32_C(0xc1a0e000)
        | ((uint32_t)(source & 31u) << 5)
        | ((uint32_t)(destination_group & 15u) << 1)
        | (uint32_t)(late & 1u);
}

#if USE_EXTRA_OPCODES
static void expected_common(
    uint32_t word, cdisasm_arm_name_id name_id,
    cdisasm_arm_form_id form_id, uint32_t flags,
    cdisasm_arm_instruction *expected)
{
    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x12b000);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->instruction_flags = flags;
    expected->name_id = name_id;
    expected->operand_count = 2u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->form_id = form_id;
}

static void expected_narrow(
    uint32_t word, cdisasm_arm_name_id name_id,
    cdisasm_arm_form_id form_id, cdisasm_arm_instruction *expected)
{
    expected_common(
        word, name_id, form_id,
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR, expected);
    expected->operand[0].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[0].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u));
    expected->operand[0].extend_type = (cdisasm_arm_extend_type)2u;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    expected->operand[1].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[1].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (((word >> 6) & 15u) * 2u));
    expected->operand[1].register_list = UINT16_C(0x0102);
    expected->operand[1].extend_type = (cdisasm_arm_extend_type)4u;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
}

static void expected_frint(
    uint32_t word, cdisasm_arm_name_id name_id,
    cdisasm_arm_form_id form_id, cdisasm_arm_instruction *expected)
{
    expected_common(
        word, name_id, form_id,
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SME,
        expected);
    expected->operand[0].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[0].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 30u));
    expected->operand[0].register_list = UINT16_C(0x0102);
    expected->operand[0].extend_type = (cdisasm_arm_extend_type)4u;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    expected->operand[1].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[1].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (((word >> 6) & 15u) * 2u));
    expected->operand[1].register_list = UINT16_C(0x0102);
    expected->operand[1].extend_type = (cdisasm_arm_extend_type)4u;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
}

static void expected_f16(
    uint32_t word, cdisasm_arm_instruction *expected)
{
    expected_common(
        word,
        (word & 1u) != 0u
            ? CDISASM_ARM_NAME_FCVTL : CDISASM_ARM_NAME_FCVT,
        (word & 1u) != 0u ? UINT16_C(4340) : UINT16_C(4339),
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SME,
        expected);
    expected->operand[0].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[0].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 30u));
    expected->operand[0].register_list = UINT16_C(0x0102);
    expected->operand[0].extend_type = (cdisasm_arm_extend_type)4u;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    expected->operand[1].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[1].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u));
    expected->operand[1].extend_type = (cdisasm_arm_extend_type)2u;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
}
#endif

static void test_exhaustive_narrow_domain(void)
{
    static const struct operation {
        uint32_t base;
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
    } operations[] = {
        { UINT32_C(0x45314000), CDISASM_ARM_NAME_SQCVTN, UINT16_C(2881) },
        { UINT32_C(0x45315000), CDISASM_ARM_NAME_SQCVTUN, UINT16_C(2882) },
        { UINT32_C(0x45314800), CDISASM_ARM_NAME_UQCVTN, UINT16_C(2883) }
    };
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    size_t operation_index;

    for (operation_index = 0u;
         operation_index < sizeof(operations) / sizeof(operations[0]);
         ++operation_index) {
        unsigned reserved_half;

        for (reserved_half = 0u; reserved_half < 2u; ++reserved_half) {
            unsigned source_group;

            for (source_group = 0u; source_group < 16u; ++source_group) {
                unsigned destination;

                for (destination = 0u; destination < 32u; ++destination) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = narrow_word(
                        operations[operation_index].base,
                        source_group, destination, reserved_half);
                    uint32_t decoded;

                    domain_expect(
                        (word & UINT32_C(0xfffffc00))
                            == operations[operation_index].base,
                        word, "word escaped multi-extract envelope");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    if (reserved_half != 0u) {
                        ++reserved;
                        domain_expect(decoded == 0u, word,
                            "reserved multi-extract half decoded");
                        domain_expect(instruction_is_error_only(
                            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
                            word, "reserved multi-extract status mismatch");
                        continue;
                    }
                    ++allocated;
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        expected_narrow(
                            word, operations[operation_index].name_id,
                            operations[operation_index].form_id, &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated multi-extract form did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected, sizeof(expected)) == 0,
                            word, "multi-extract metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF decoded multi-extract form");
                    domain_expect(instruction_is_error_only(
                        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF multi-extract ownership mismatch");
#endif
                }
            }
        }
    }
    EXPECT(allocated == UINT32_C(1536));
    EXPECT(reserved == UINT32_C(1536));
}

static void test_exhaustive_frint_domain(void)
{
    static const struct operation {
        uint32_t base;
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
    } operations[] = {
        { UINT32_C(0xc1a8e000), CDISASM_ARM_NAME_FRINTN, UINT16_C(4335) },
        { UINT32_C(0xc1a9e000), CDISASM_ARM_NAME_FRINTP, UINT16_C(4336) },
        { UINT32_C(0xc1aae000), CDISASM_ARM_NAME_FRINTM, UINT16_C(4337) },
        { UINT32_C(0xc1ace000), CDISASM_ARM_NAME_FRINTA, UINT16_C(4338) }
    };
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    size_t operation_index;

    for (operation_index = 0u;
         operation_index < sizeof(operations) / sizeof(operations[0]);
         ++operation_index) {
        unsigned reserved_control;

        for (reserved_control = 0u;
             reserved_control < 4u; ++reserved_control) {
            unsigned source_group;

            for (source_group = 0u; source_group < 16u; ++source_group) {
                unsigned destination_group;

                for (destination_group = 0u;
                     destination_group < 16u; ++destination_group) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = frint_word(
                        operations[operation_index].base, source_group,
                        destination_group, reserved_control);
                    uint32_t decoded;

                    domain_expect(
                        (word & UINT32_C(0xfffffc00))
                            == operations[operation_index].base,
                        word, "word escaped two-vector FRINT envelope");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    if (reserved_control != 0u) {
                        ++reserved;
                        domain_expect(decoded == 0u, word,
                            "reserved two-vector FRINT control decoded");
                        domain_expect(instruction_is_error_only(
                            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
                            word, "reserved FRINT status mismatch");
                        continue;
                    }
                    ++allocated;
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        expected_frint(
                            word, operations[operation_index].name_id,
                            operations[operation_index].form_id, &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated two-vector FRINT did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected, sizeof(expected)) == 0,
                            word, "two-vector FRINT metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF decoded two-vector FRINT");
                    domain_expect(instruction_is_error_only(
                        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF FRINT ownership mismatch");
#endif
                }
            }
        }
    }
    EXPECT(allocated == UINT32_C(1024));
    EXPECT(reserved == UINT32_C(3072));
}

static void test_exhaustive_narrowing_shift_domain(void)
{
    static const struct operation {
        uint32_t base;
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
    } operations[] = {
        { UINT32_C(0x45b02800), CDISASM_ARM_NAME_SQRSHRN, UINT16_C(2866) },
        { UINT32_C(0x45b00800), CDISASM_ARM_NAME_SQRSHRUN, UINT16_C(2868) },
        { UINT32_C(0x45b03800), CDISASM_ARM_NAME_UQRSHRN, UINT16_C(2872) },
        { UINT32_C(0x45a82800), CDISASM_ARM_NAME_SQRSHRN, UINT16_C(2867) },
        { UINT32_C(0x45a80800), CDISASM_ARM_NAME_SQRSHRUN, UINT16_C(2869) },
        { UINT32_C(0x45a83800), CDISASM_ARM_NAME_UQRSHRN, UINT16_C(2873) }
    };
    size_t operation_index;

    for (operation_index = 0u;
         operation_index < sizeof(operations) / sizeof(operations[0]);
         ++operation_index) {
        unsigned encoded_immediate;
        for (encoded_immediate = 0u;
             encoded_immediate < (operation_index < 3u ? 16u : 8u);
             ++encoded_immediate) {
            unsigned source_group;
            for (source_group = 0u; source_group < 16u; ++source_group) {
                unsigned destination;
                for (destination = 0u; destination < 32u; ++destination) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = narrowing_shift_word(
                        operations[operation_index].base, encoded_immediate,
                        source_group, destination);
                    uint32_t decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
                    domain_expect(decoded == 4u, word,
                        "allocated multi narrowing shift did not decode");
                    domain_expect(instruction.name_id
                            == operations[operation_index].name_id,
                        word, "multi narrowing shift name mismatch");
                    domain_expect(instruction.form_id
                            == operations[operation_index].form_id,
                        word, "multi narrowing shift form mismatch");
                    domain_expect(instruction.instruction_flags
                            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR,
                        word, "multi narrowing shift family flags mismatch");
                    domain_expect(instruction.operand_count == 3u, word,
                        "multi narrowing shift operand count mismatch");
                    domain_expect(instruction.operand[2].imm
                            == (operation_index < 3u ? 16u : 8u)
                                - encoded_immediate,
                        word, "multi narrowing shift immediate mismatch");
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF decoded multi narrowing shift");
                    domain_expect(instruction_is_error_only(
                            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF multi narrowing ownership mismatch");
#endif
                }
            }
        }
    }
}

static void test_exhaustive_nonrounding_narrowing_shift_domain(void)
{
    static const struct operation {
        uint32_t base;
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
    } operations[] = {
        { UINT32_C(0x45a00000), CDISASM_ARM_NAME_SQSHRN, UINT16_C(2870) },
        { UINT32_C(0x45a02000), CDISASM_ARM_NAME_SQSHRUN, UINT16_C(2871) },
        { UINT32_C(0x45a01000), CDISASM_ARM_NAME_UQSHRN, UINT16_C(2874) }
    };
    size_t operation_index;

    for (operation_index = 0u;
         operation_index < sizeof(operations) / sizeof(operations[0]);
         ++operation_index) {
        unsigned encoded_immediate;
        for (encoded_immediate = 8u; encoded_immediate < 32u;
             ++encoded_immediate) {
            unsigned source_group;
            for (source_group = 0u; source_group < 16u; ++source_group) {
                unsigned destination;
                for (destination = 0u; destination < 32u; ++destination) {
                    cdisasm_arm_instruction instruction;
                    unsigned source_bits = encoded_immediate >= 16u ? 32u : 16u;
                    uint8_t source_size = (uint8_t)(source_bits / 8u);
                    uint8_t destination_size = (uint8_t)(source_size / 2u);
                    uint32_t word = narrowing_shift_word(
                        operations[operation_index].base, encoded_immediate,
                        source_group, destination);
                    uint32_t decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
                    domain_expect(decoded == 4u, word,
                        "allocated non-rounding narrowing shift did not decode");
                    domain_expect(instruction.name_id
                            == operations[operation_index].name_id
                            && instruction.form_id
                                == operations[operation_index].form_id,
                        word, "non-rounding narrowing identity mismatch");
                    domain_expect(instruction.instruction_flags
                            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                            && instruction.operand_count == 3u,
                        word, "non-rounding narrowing header mismatch");
                    domain_expect(instruction.operand[0].type
                            == CDISASM_ARM_OPERAND_SCALABLE_REGISTER
                            && instruction.operand[0].reg
                                == CDISASM_ARM_REG_Z0 + destination
                            && instruction.operand[0].extend_type
                                == destination_size
                            && instruction.operand[0].access
                                == CDISASM_OPERAND_ACCESS_WRITE,
                        word, "non-rounding narrowing destination mismatch");
                    domain_expect(instruction.operand[1].type
                            == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
                            && instruction.operand[1].reg
                                == CDISASM_ARM_REG_Z0 + source_group * 2u
                            && instruction.operand[1].register_list
                                == UINT16_C(0x0102)
                            && instruction.operand[1].extend_type == source_size
                            && instruction.operand[1].access
                                == CDISASM_OPERAND_ACCESS_READ,
                        word, "non-rounding narrowing source mismatch");
                    domain_expect(instruction.operand[2].type
                            == CDISASM_OPERAND_IMMEDIATE
                            && instruction.operand[2].imm
                                == source_bits - encoded_immediate
                            && instruction.operand[2].access
                                == CDISASM_OPERAND_ACCESS_READ,
                        word, "non-rounding narrowing immediate mismatch");
#else
                    (void)source_bits;
                    (void)source_size;
                    (void)destination_size;
                    domain_expect(decoded == 0u, word,
                        "extras-OFF decoded non-rounding narrowing shift");
                    domain_expect(instruction_is_error_only(
                            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF non-rounding ownership mismatch");
#endif
                }
            }
        }
        for (encoded_immediate = 0u; encoded_immediate < 8u;
             ++encoded_immediate) {
            cdisasm_arm_instruction instruction;
            uint32_t word = narrowing_shift_word(
                operations[operation_index].base, encoded_immediate, 0u, 0u);
            uint32_t decoded = decode_word(
                word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            domain_expect(decoded == 0u, word,
                "unallocated non-rounding narrowing shift decoded");
            domain_expect(instruction_is_error_only(
                    &instruction,
                    CDISASM_STATUS_INVALID_INSTRUCTION),
                word, "non-rounding narrowing reserved status mismatch");
        }
    }
}

static void test_exhaustive_f16_domain(void)
{
    uint32_t allocated = 0u;
    unsigned late;

    for (late = 0u; late < 2u; ++late) {
        unsigned source;

        for (source = 0u; source < 32u; ++source) {
            unsigned destination_group;

            for (destination_group = 0u;
                 destination_group < 16u; ++destination_group) {
                cdisasm_arm_instruction instruction;
                uint32_t word = f16_word(late, source, destination_group);
                uint32_t decoded;

                domain_expect(
                    (word & UINT32_C(0xfffffc01))
                        == (UINT32_C(0xc1a0e000) | late),
                    word, "word escaped SME_F16F16 widening row");
                memset(&instruction, 0xa5, sizeof(instruction));
                decoded = decode_word(
                    word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                    4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                ++allocated;
#if USE_EXTRA_OPCODES
                {
                    cdisasm_arm_instruction expected;

                    expected_f16(word, &expected);
                    domain_expect(decoded == 4u, word,
                        "allocated SME_F16F16 widening form did not decode");
                    domain_expect(memcmp(
                        &instruction, &expected, sizeof(expected)) == 0,
                        word, "SME_F16F16 widening metadata mismatch");
                }
#else
                domain_expect(decoded == 0u, word,
                    "extras-OFF decoded SME_F16F16 widening form");
                domain_expect(instruction_is_error_only(
                    &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                    word, "extras-OFF SME_F16F16 ownership mismatch");
#endif
            }
        }
    }
    EXPECT(allocated == UINT32_C(1024));
}

static void test_feature_and_profile_gates(void)
{
    static const struct gate_form {
        uint32_t word;
        cdisasm_arm_name_id name_id;
        uint8_t named_sme2_route;
    } forms[] = {
        { UINT32_C(0x45314000), CDISASM_ARM_NAME_SQCVTN, 1u },
        { UINT32_C(0x453153df), CDISASM_ARM_NAME_SQCVTUN, 1u },
        { UINT32_C(0x45314955), CDISASM_ARM_NAME_UQCVTN, 1u },
        { UINT32_C(0x45bf2800), CDISASM_ARM_NAME_SQRSHRN, 1u },
        { UINT32_C(0x45b00bc3), CDISASM_ARM_NAME_SQRSHRUN, 1u },
        { UINT32_C(0x45b03bc3), CDISASM_ARM_NAME_UQRSHRN, 1u },
        { UINT32_C(0x45af2800), CDISASM_ARM_NAME_SQRSHRN, 0u },
        { UINT32_C(0x45a808c3), CDISASM_ARM_NAME_SQRSHRUN, 0u },
        { UINT32_C(0x45ac3bdf), CDISASM_ARM_NAME_UQRSHRN, 0u },
        { UINT32_C(0x45bf0000), CDISASM_ARM_NAME_SQSHRN, 0u },
        { UINT32_C(0x45ae2000), CDISASM_ARM_NAME_SQSHRUN, 0u },
        { UINT32_C(0x45a81000), CDISASM_ARM_NAME_UQSHRN, 0u },
        { UINT32_C(0xc1a8e000), CDISASM_ARM_NAME_FRINTN, 1u },
        { UINT32_C(0xc1a9e146), CDISASM_ARM_NAME_FRINTP, 1u },
        { UINT32_C(0xc1aae28e), CDISASM_ARM_NAME_FRINTM, 1u },
        { UINT32_C(0xc1ace3de), CDISASM_ARM_NAME_FRINTA, 1u },
        { UINT32_C(0xc1a0e000), CDISASM_ARM_NAME_FCVT, 0u },
        { UINT32_C(0xc1a0e3ff), CDISASM_ARM_NAME_FCVTL, 0u }
    };
    uint32_t cpu_value;

    for (cpu_value = CDISASM_ARM_CPU_FIRST;
         cpu_value <= CDISASM_ARM_CPU_LAST; ++cpu_value) {
        cdisasm_arm_cpu_id cpu_id = (cdisasm_arm_cpu_id)cpu_value;
        size_t form_index;

        for (form_index = 0u;
             form_index < sizeof(forms) / sizeof(forms[0]); ++form_index) {
            cdisasm_arm_instruction instruction;
            cdisasm_status expected_status;
            uint32_t decoded;

            if ((cdisasm_arm_cpu_mode_mask(cpu_id)
                    & CDISASM_ARM_MODE_MASK_A64) == 0u) {
                expected_status = CDISASM_STATUS_INVALID_ARGUMENT;
#if USE_EXTRA_OPCODES
            } else if (forms[form_index].named_sme2_route != 0u
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
                forms[form_index].word, cpu_id, CDISASM_ARM_MODE_A64,
                4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
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
}

static void test_endian_truncation_and_mode(void)
{
    const uint32_t word = UINT32_C(0xc1ace3de);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction instruction;
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
        big_bytes, sizeof(big_bytes), UINT64_C(0x12b000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &big, sizeof(little)) == 0);

    for (code_size = 1u; code_size < 4u; ++code_size) {
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            code_size, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_TRUNCATED));
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    (void)decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(instruction.name_id != CDISASM_ARM_NAME_FRINTA);
    EXPECT(instruction.isa_id != CDISASM_ARM_ISA_A64);
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void test_formatting(void)
{
    static const struct format_vector {
        uint32_t word;
        const char *text;
    } vectors[] = {
        { UINT32_C(0x45314000), "sqcvtn z0.h, {z0.s, z1.s}" },
        { UINT32_C(0x453153df), "sqcvtun z31.h, {z30.s, z31.s}" },
        { UINT32_C(0x45314955), "uqcvtn z21.h, {z10.s, z11.s}" },
        { UINT32_C(0x45bf2800), "sqrshrn z0.h, {z0.s, z1.s}, #1" },
        { UINT32_C(0x45b00bc3), "sqrshrun z3.h, {z30.s, z31.s}, #16" },
        { UINT32_C(0x45b03bc3), "uqrshrn z3.h, {z30.s, z31.s}, #16" },
        { UINT32_C(0x45af2800), "sqrshrn z0.b, {z0.h, z1.h}, #1" },
        { UINT32_C(0x45a808c3), "sqrshrun z3.b, {z6.h, z7.h}, #8" },
        { UINT32_C(0x45ac3bdf), "uqrshrn z31.b, {z30.h, z31.h}, #4" },
        { UINT32_C(0x45bf0000), "sqshrn z0.h, {z0.s, z1.s}, #1" },
        { UINT32_C(0x45ae2000), "sqshrun z0.b, {z0.h, z1.h}, #2" },
        { UINT32_C(0x45a81000), "uqshrn z0.b, {z0.h, z1.h}, #8" },
        { UINT32_C(0xc1a8e000),
          "frintn {z0.s, z1.s}, {z0.s, z1.s}" },
        { UINT32_C(0xc1a9e146),
          "frintp {z6.s, z7.s}, {z10.s, z11.s}" },
        { UINT32_C(0xc1aae28e),
          "frintm {z14.s, z15.s}, {z20.s, z21.s}" },
        { UINT32_C(0xc1ace3de),
          "frinta {z30.s, z31.s}, {z30.s, z31.s}" },
        { UINT32_C(0xc1a0e000), "fcvt {z0.s, z1.s}, z0.h" },
        { UINT32_C(0xc1a0e3ff), "fcvtl {z30.s, z31.s}, z31.h" }
    };
    size_t index;

    for (index = 0u; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
        cdisasm_arm_instruction instruction;
        char text[96];
        size_t expected_length = strlen(vectors[index].text);

        EXPECT(decode_word(
            vectors[index].word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == expected_length);
        EXPECT(strcmp(text, vectors[index].text) == 0);
    }

    {
        cdisasm_arm_instruction instruction;
        cdisasm_arm_instruction invalid;
        char text[96];

        EXPECT(decode_word(
            UINT32_C(0xc1a8e000), CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        invalid = instruction;
        invalid.operand[0].register_list = UINT16_C(0x0105);
        memset(text, 0xa5, sizeof(text));
        EXPECT(cdisasm_arm_format(
            &invalid, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == 0u);
        EXPECT(text[0] == '\0');

        invalid = instruction;
        invalid.operand[1].extend_type = (cdisasm_arm_extend_type)16u;
        memset(text, 0xa5, sizeof(text));
        EXPECT(cdisasm_arm_format(
            &invalid, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == 0u);
        EXPECT(text[0] == '\0');
    }
}
#endif

int main(void)
{
    test_exhaustive_narrow_domain();
    test_exhaustive_narrowing_shift_domain();
    test_exhaustive_nonrounding_narrowing_shift_domain();
    test_exhaustive_frint_domain();
    test_exhaustive_f16_domain();
    test_feature_and_profile_gates();
    test_endian_truncation_and_mode();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM multi-narrow/FRINT test(s) failed\n", failures);
        return 1;
    }
    printf("ARM multi-narrow/FRINT tests passed "
           "(allocated=3584, reserved=4608; "
           "USE_EXTRA_OPCODES=%d)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
