#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_FCVT == UINT16_C(433),
               "the established FCVT ID moved");
_Static_assert(CDISASM_ARM_NAME_FCVTZS == UINT16_C(434),
               "the established FCVTZS ID moved");
_Static_assert(CDISASM_ARM_NAME_FCVTZU == UINT16_C(435),
               "the established FCVTZU ID moved");
_Static_assert(CDISASM_ARM_NAME_FCVTN == UINT16_C(837),
               "the established FCVTN ID moved");
_Static_assert(CDISASM_ARM_NAME_SCVTF == UINT16_C(431),
               "the established SCVTF ID moved");
_Static_assert(CDISASM_ARM_NAME_UCVTF == UINT16_C(432),
               "the established UCVTF ID moved");
_Static_assert(CDISASM_ARM_NAME_SQCVT == UINT16_C(1466),
               "the established SQCVT ID moved");
_Static_assert(CDISASM_ARM_NAME_SQCVTN == UINT16_C(1467),
               "the established SQCVTN ID moved");
_Static_assert(CDISASM_ARM_NAME_SQCVTU == UINT16_C(1468),
               "the established SQCVTU ID moved");
_Static_assert(CDISASM_ARM_NAME_SQCVTUN == UINT16_C(1469),
               "the established SQCVTUN ID moved");
_Static_assert(CDISASM_ARM_NAME_UQCVT == UINT16_C(1794),
               "the established UQCVT ID moved");
_Static_assert(CDISASM_ARM_NAME_UQCVTN == UINT16_C(1795),
               "the established UQCVTN ID moved");
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
        cpu_id, mode, bytes, code_size, UINT64_C(0x12c000),
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

static uint32_t list_to_list_word(
    uint32_t base, unsigned source_group, unsigned destination_group)
{
    return base
        | ((uint32_t)(source_group & 7u) << 7)
        | ((uint32_t)(destination_group & 7u) << 2);
}

static uint32_t narrow_word(
    unsigned operation, unsigned size, unsigned source_group,
    unsigned destination)
{
    return UINT32_C(0xc133e000)
        | ((uint32_t)(size & 1u) << 23)
        | ((uint32_t)((operation >> 2) & 1u) << 22)
        | ((uint32_t)(operation & 3u) << 5)
        | ((uint32_t)(source_group & 7u) << 7)
        | (uint32_t)(destination & 31u);
}

static uint32_t fp8_word(
    unsigned narrow, unsigned source_group, unsigned destination)
{
    return UINT32_C(0xc134e000)
        | ((uint32_t)(narrow & 1u) << 5)
        | ((uint32_t)(source_group & 7u) << 7)
        | (uint32_t)(destination & 31u);
}

static uint32_t wide_integer_word(
    unsigned unsigned_conversion, unsigned size, unsigned source_group,
    unsigned destination_group)
{
    return UINT32_C(0xc135e000)
        | ((uint32_t)(size & 3u) << 22)
        | ((uint32_t)(source_group & 15u) << 6)
        | ((uint32_t)(destination_group & 7u) << 2)
        | (uint32_t)(unsigned_conversion & 1u);
}

static uint32_t permute_word(
    int quadword, unsigned unzip, unsigned size, unsigned source_group,
    unsigned destination_group)
{
    return (quadword ? UINT32_C(0xc137e000) : UINT32_C(0xc136e000))
        | ((uint32_t)(size & 3u) << 22)
        | ((uint32_t)(source_group & 7u) << 7)
        | ((uint32_t)(destination_group & 7u) << 2)
        | ((uint32_t)(unzip & 1u) << 1);
}

static uint32_t frint4_word(
    unsigned operation, unsigned size, unsigned source_group,
    unsigned destination_group)
{
    return UINT32_C(0xc138e000)
        | ((uint32_t)(size & 3u) << 22)
        | ((uint32_t)(operation & 7u) << 16)
        | ((uint32_t)(source_group & 7u) << 7)
        | ((uint32_t)(destination_group & 7u) << 2);
}

#if USE_EXTRA_OPCODES
static void expected_common(
    uint32_t word, cdisasm_arm_name_id name_id,
    cdisasm_arm_form_id form_id, uint32_t flags,
    cdisasm_arm_instruction *expected)
{
    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x12c000);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->instruction_flags = flags
        | CDISASM_ARM_INSTRUCTION_FLAG_SME;
    expected->name_id = name_id;
    expected->operand_count = 2u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->form_id = form_id;
}

static void expected_list_to_list(
    uint32_t word, cdisasm_arm_name_id name_id,
    cdisasm_arm_form_id form_id, cdisasm_arm_instruction *expected)
{
    unsigned destination_base = ((word >> 2) & 7u) * 4u;
    unsigned source_base = ((word >> 7) & 7u) * 4u;

    expected_common(
        word, name_id, form_id,
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT,
        expected);
    expected->operand[0].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[0].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + destination_base);
    expected->operand[0].register_list = UINT16_C(0x0104);
    expected->operand[0].extend_type = (cdisasm_arm_extend_type)4u;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    expected->operand[1].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[1].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + source_base);
    expected->operand[1].register_list = UINT16_C(0x0104);
    expected->operand[1].extend_type = (cdisasm_arm_extend_type)4u;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
    domain_expect(destination_base % 4u == 0u
        && destination_base + 3u <= 31u,
        word, "destination list is not an aligned group of four");
    domain_expect(source_base % 4u == 0u && source_base + 3u <= 31u,
        word, "source list is not an aligned group of four");
}

static void expected_narrow(
    uint32_t word, cdisasm_arm_name_id name_id,
    cdisasm_arm_form_id form_id, cdisasm_arm_instruction *expected)
{
    unsigned size = (word >> 23) & 1u;
    unsigned source_base = ((word >> 7) & 7u) * 4u;

    expected_common(
        word, name_id, form_id,
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR, expected);
    expected->operand[0].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[0].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u));
    expected->operand[0].extend_type =
        (cdisasm_arm_extend_type)(1u << size);
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    expected->operand[1].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[1].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + source_base);
    expected->operand[1].register_list = UINT16_C(0x0104);
    expected->operand[1].extend_type =
        (cdisasm_arm_extend_type)(4u << size);
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
    domain_expect(source_base % 4u == 0u && source_base + 3u <= 31u,
        word, "narrowing source list is not an aligned group of four");
}

static void expected_fp8(
    uint32_t word, cdisasm_arm_name_id name_id,
    cdisasm_arm_form_id form_id, cdisasm_arm_instruction *expected)
{
    unsigned source_base = ((word >> 7) & 7u) * 4u;

    expected_common(
        word, name_id, form_id,
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT,
        expected);
    expected->operand[0].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[0].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u));
    expected->operand[0].extend_type = (cdisasm_arm_extend_type)1u;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    expected->operand[1].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[1].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + source_base);
    expected->operand[1].register_list = UINT16_C(0x0104);
    expected->operand[1].extend_type = (cdisasm_arm_extend_type)4u;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
    domain_expect(source_base % 4u == 0u && source_base + 3u <= 31u,
        word, "FP8 source list is not an aligned group of four");
}

static void expected_wide_integer(
    uint32_t word, cdisasm_arm_name_id name_id,
    cdisasm_arm_form_id form_id, cdisasm_arm_instruction *expected)
{
    unsigned size = (word >> 22) & 3u;
    unsigned destination_base = ((word >> 2) & 7u) * 4u;
    unsigned source_base = ((word >> 6) & 15u) * 2u;

    expected_common(
        word, name_id, form_id,
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR, expected);
    expected->operand[0].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[0].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + destination_base);
    expected->operand[0].register_list = UINT16_C(0x0104);
    expected->operand[0].extend_type =
        (cdisasm_arm_extend_type)(1u << size);
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    expected->operand[1].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[1].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + source_base);
    expected->operand[1].register_list = UINT16_C(0x0102);
    expected->operand[1].extend_type =
        (cdisasm_arm_extend_type)(1u << (size - 1u));
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
    domain_expect(destination_base % 4u == 0u
        && destination_base + 3u <= 31u,
        word, "widening destination is not an aligned group of four");
    domain_expect(source_base % 2u == 0u && source_base + 1u <= 31u,
        word, "widening source is not an aligned pair");
}

static void expected_permute(
    uint32_t word, cdisasm_arm_name_id name_id,
    cdisasm_arm_form_id form_id, uint8_t element_size,
    cdisasm_arm_instruction *expected)
{
    expected_common(
        word, name_id, form_id,
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR, expected);
    expected->operand[0].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[0].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (((word >> 2) & 7u) * 4u));
    expected->operand[0].register_list = UINT16_C(0x0104);
    expected->operand[0].extend_type =
        (cdisasm_arm_extend_type)element_size;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    expected->operand[1].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected->operand[1].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (((word >> 7) & 7u) * 4u));
    expected->operand[1].register_list = UINT16_C(0x0104);
    expected->operand[1].extend_type =
        (cdisasm_arm_extend_type)element_size;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
}

static void expected_frint4(
    uint32_t word, cdisasm_arm_name_id name_id,
    cdisasm_arm_form_id form_id, cdisasm_arm_instruction *expected)
{
    expected_permute(word, name_id, form_id, 4u, expected);
    expected->instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
}
#endif

static void test_exhaustive_list_to_list_domain(uint32_t *allocated)
{
    static const struct operation {
        uint32_t base;
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
    } operations[] = {
        { UINT32_C(0xc131e000), CDISASM_ARM_NAME_FCVTZS,
          UINT16_C(4341) },
        { UINT32_C(0xc131e020), CDISASM_ARM_NAME_FCVTZU,
          UINT16_C(4342) },
        { UINT32_C(0xc132e000), CDISASM_ARM_NAME_SCVTF,
          UINT16_C(4343) },
        { UINT32_C(0xc132e020), CDISASM_ARM_NAME_UCVTF,
          UINT16_C(4344) }
    };
    size_t operation_index;

    for (operation_index = 0u;
         operation_index < sizeof(operations) / sizeof(operations[0]);
         ++operation_index) {
        unsigned source_group;

        for (source_group = 0u; source_group < 8u; ++source_group) {
            unsigned destination_group;

            for (destination_group = 0u;
                 destination_group < 8u; ++destination_group) {
                cdisasm_arm_instruction instruction;
                uint32_t word = list_to_list_word(
                    operations[operation_index].base,
                    source_group, destination_group);
                uint32_t decoded;

                domain_expect(
                    (word & UINT32_C(0xfffffc63))
                        == operations[operation_index].base,
                    word, "word escaped four-vector conversion row");
                memset(&instruction, 0xa5, sizeof(instruction));
                decoded = decode_word(
                    word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                    4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                ++*allocated;
#if USE_EXTRA_OPCODES
                {
                    cdisasm_arm_instruction expected;

                    expected_list_to_list(
                        word, operations[operation_index].name_id,
                        operations[operation_index].form_id, &expected);
                    domain_expect(decoded == 4u, word,
                        "allocated four-vector conversion did not decode");
                    domain_expect(memcmp(
                        &instruction, &expected, sizeof(expected)) == 0,
                        word, "four-vector conversion metadata mismatch");
                }
#else
                domain_expect(decoded == 0u, word,
                    "extras-OFF decoded four-vector conversion");
                domain_expect(instruction_is_error_only(
                    &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                    word, "extras-OFF conversion ownership mismatch");
#endif
            }
        }
    }
}

static void test_exhaustive_narrow_domain(
    uint32_t *allocated, uint32_t *reserved)
{
    static const struct operation {
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
        uint8_t allocated;
    } operations[8] = {
        { CDISASM_ARM_NAME_SQCVT, UINT16_C(4345), 1u },
        { CDISASM_ARM_NAME_UQCVT, UINT16_C(4349), 1u },
        { CDISASM_ARM_NAME_SQCVTN, UINT16_C(4347), 1u },
        { CDISASM_ARM_NAME_UQCVTN, UINT16_C(4350), 1u },
        { CDISASM_ARM_NAME_SQCVTU, UINT16_C(4346), 1u },
        { CDISASM_ARM_NAME_NONE, UINT16_C(0), 0u },
        { CDISASM_ARM_NAME_SQCVTUN, UINT16_C(4348), 1u },
        { CDISASM_ARM_NAME_NONE, UINT16_C(0), 0u }
    };
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        unsigned size;

        for (size = 0u; size < 2u; ++size) {
            unsigned source_group;

            for (source_group = 0u; source_group < 8u; ++source_group) {
                unsigned destination;

                for (destination = 0u; destination < 32u; ++destination) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = narrow_word(
                        operation, size, source_group, destination);
                    uint32_t decoded;

                    domain_expect(
                        (word & UINT32_C(0xff3ffc00))
                            == UINT32_C(0xc133e000),
                        word, "word escaped integer-narrowing envelope");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    if (operations[operation].allocated == 0u) {
                        ++*reserved;
                        domain_expect(decoded == 0u, word,
                            "reserved four-vector narrowing control decoded");
                        domain_expect(instruction_is_error_only(
                            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
                            word, "reserved narrowing status mismatch");
                        continue;
                    }
                    ++*allocated;
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        expected_narrow(
                            word, operations[operation].name_id,
                            operations[operation].form_id, &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated four-vector narrowing did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected, sizeof(expected)) == 0,
                            word, "four-vector narrowing metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF decoded four-vector narrowing");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF narrowing ownership mismatch");
#endif
                }
            }
        }
    }
}

static void test_exhaustive_fp8_domain(uint32_t *allocated)
{
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_name_id names[2] = {
        CDISASM_ARM_NAME_FCVT, CDISASM_ARM_NAME_FCVTN
    };
#endif
    unsigned narrow;

    for (narrow = 0u; narrow < 2u; ++narrow) {
        unsigned source_group;

        for (source_group = 0u; source_group < 8u; ++source_group) {
            unsigned destination;

            for (destination = 0u; destination < 32u; ++destination) {
                cdisasm_arm_instruction instruction;
                uint32_t word = fp8_word(
                    narrow, source_group, destination);
                uint32_t decoded;

                domain_expect(
                    (word & UINT32_C(0xfffffc60))
                        == (UINT32_C(0xc134e000)
                            | ((uint32_t)narrow << 5)),
                    word, "word escaped FP8 narrowing row");
                memset(&instruction, 0xa5, sizeof(instruction));
                decoded = decode_word(
                    word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                    4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                ++*allocated;
#if USE_EXTRA_OPCODES
                {
                    cdisasm_arm_instruction expected;

                    expected_fp8(
                        word, names[narrow],
                        (cdisasm_arm_form_id)(UINT16_C(4351) + narrow),
                        &expected);
                    domain_expect(decoded == 4u, word,
                        "allocated four-vector FP8 form did not decode");
                    domain_expect(memcmp(
                        &instruction, &expected, sizeof(expected)) == 0,
                        word, "four-vector FP8 metadata mismatch");
                }
#else
                domain_expect(decoded == 0u, word,
                    "extras-OFF decoded four-vector FP8 form");
                domain_expect(instruction_is_error_only(
                    &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                    word, "extras-OFF FP8 ownership mismatch");
#endif
            }
        }
    }
}

static void test_exhaustive_wide_integer_domain(
    uint32_t *allocated, uint32_t *reserved)
{
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_name_id names[2] = {
        CDISASM_ARM_NAME_SUNPK, CDISASM_ARM_NAME_UUNPK
    };
#endif
    unsigned unsigned_conversion;

    for (unsigned_conversion = 0u;
         unsigned_conversion < 2u; ++unsigned_conversion) {
        unsigned size;

        for (size = 0u; size < 4u; ++size) {
            unsigned source_group;

            for (source_group = 0u; source_group < 16u; ++source_group) {
                unsigned destination_group;

                for (destination_group = 0u;
                     destination_group < 8u; ++destination_group) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = wide_integer_word(
                        unsigned_conversion, size, source_group,
                        destination_group);
                    uint32_t decoded;

                    domain_expect(
                        (word & UINT32_C(0xff3ffc23))
                            == (UINT32_C(0xc135e000)
                                | unsigned_conversion),
                        word, "word escaped four-vector widening row");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    if (size == 0u) {
                        ++*reserved;
                        domain_expect(decoded == 0u, word,
                            "reserved four-vector widening size decoded");
                        domain_expect(instruction_is_error_only(
                            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
                            word, "reserved widening status mismatch");
                        continue;
                    }
                    ++*allocated;
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        expected_wide_integer(
                            word, names[unsigned_conversion],
                            (cdisasm_arm_form_id)(
                                UINT16_C(4353) + unsigned_conversion),
                            &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated four-vector widening did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected, sizeof(expected)) == 0,
                            word, "four-vector widening metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF decoded four-vector widening");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF widening ownership mismatch");
#endif
                }
            }
        }
    }
}

static void test_exhaustive_permute_domain(uint32_t *allocated)
{
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_name_id names[2] = {
        CDISASM_ARM_NAME_ZIP, CDISASM_ARM_NAME_UZP
    };
#endif
    unsigned unzip;

    for (unzip = 0u; unzip < 2u; ++unzip) {
        unsigned size;

        for (size = 0u; size < 4u; ++size) {
            unsigned source_group;

            for (source_group = 0u; source_group < 8u; ++source_group) {
                unsigned destination_group;

                for (destination_group = 0u;
                     destination_group < 8u; ++destination_group) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = permute_word(
                        0, unzip, size, source_group, destination_group);
                    uint32_t decoded;

                    domain_expect(
                        (word & UINT32_C(0xff3ffc63))
                            == (UINT32_C(0xc136e000)
                                | ((uint32_t)unzip << 1)),
                        word, "word escaped four-vector permute row");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    ++*allocated;
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        expected_permute(
                            word, names[unzip],
                            (cdisasm_arm_form_id)(UINT16_C(4355) + unzip),
                            (uint8_t)(1u << size), &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated four-vector permute did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected, sizeof(expected)) == 0,
                            word, "four-vector permute metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF decoded four-vector permute");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF permute ownership mismatch");
#endif
                }
            }
        }

        {
            unsigned source_group;

            for (source_group = 0u; source_group < 8u; ++source_group) {
                unsigned destination_group;

                for (destination_group = 0u;
                     destination_group < 8u; ++destination_group) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = permute_word(
                        1, unzip, 0u, source_group, destination_group);
                    uint32_t decoded;

                    domain_expect(
                        (word & UINT32_C(0xfffffc63))
                            == (UINT32_C(0xc137e000)
                                | ((uint32_t)unzip << 1)),
                        word, "word escaped quadword permute row");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    ++*allocated;
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        expected_permute(
                            word, names[unzip],
                            (cdisasm_arm_form_id)(UINT16_C(4357) + unzip),
                            16u, &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated quadword permute did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected, sizeof(expected)) == 0,
                            word, "quadword permute metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF decoded quadword permute");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF quadword ownership mismatch");
#endif
                }
            }
        }
    }
}

static void test_exhaustive_frint4_domain(
    uint32_t *allocated, uint32_t *reserved)
{
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_FRINTN,
        CDISASM_ARM_NAME_FRINTP,
        CDISASM_ARM_NAME_FRINTM,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_FRINTA,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_NONE
    };
    static const cdisasm_arm_form_id forms[8] = {
        UINT16_C(4359), UINT16_C(4360), UINT16_C(4361), UINT16_C(0),
        UINT16_C(4362), UINT16_C(0), UINT16_C(0), UINT16_C(0)
    };
#endif
    unsigned size;

    for (size = 0u; size < 4u; ++size) {
        unsigned operation;

        for (operation = 0u; operation < 8u; ++operation) {
            unsigned source_group;

            for (source_group = 0u; source_group < 8u; ++source_group) {
                unsigned destination_group;

                for (destination_group = 0u;
                     destination_group < 8u; ++destination_group) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = frint4_word(
                        operation, size, source_group, destination_group);
                    int is_allocated = size == 2u
                        && (operation <= 2u || operation == 4u);
                    uint32_t decoded;

                    domain_expect(
                        (word & UINT32_C(0xff38fc63))
                            == UINT32_C(0xc138e000),
                        word, "word escaped four-vector FRINT envelope");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    if (!is_allocated) {
                        ++*reserved;
                        domain_expect(decoded == 0u, word,
                            "reserved four-vector FRINT control decoded");
                        domain_expect(instruction_is_error_only(
                            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
                            word, "reserved FRINT4 status mismatch");
                        continue;
                    }
                    ++*allocated;
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        expected_frint4(
                            word, names[operation], forms[operation],
                            &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated four-vector FRINT did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected, sizeof(expected)) == 0,
                            word, "four-vector FRINT metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF decoded four-vector FRINT");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF FRINT4 ownership mismatch");
#endif
                }
            }
        }
    }
}

static void test_exhaustive_domain(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;

    test_exhaustive_list_to_list_domain(&allocated);
    test_exhaustive_narrow_domain(&allocated, &reserved);
    test_exhaustive_fp8_domain(&allocated);
    test_exhaustive_wide_integer_domain(&allocated, &reserved);
    test_exhaustive_permute_domain(&allocated);
    test_exhaustive_frint4_domain(&allocated, &reserved);
    EXPECT(allocated == UINT32_C(5504));
    EXPECT(reserved == UINT32_C(3072));
}

static void test_feature_and_profile_gates(void)
{
    static const struct gate_form {
        uint32_t word;
        cdisasm_arm_name_id name_id;
        uint8_t requires_fp8;
    } forms[] = {
        { UINT32_C(0xc131e080), CDISASM_ARM_NAME_FCVTZS, 0u },
        { UINT32_C(0xc131e03c), CDISASM_ARM_NAME_FCVTZU, 0u },
        { UINT32_C(0xc132e380), CDISASM_ARM_NAME_SCVTF, 0u },
        { UINT32_C(0xc132e124), CDISASM_ARM_NAME_UCVTF, 0u },
        { UINT32_C(0xc133e080), CDISASM_ARM_NAME_SQCVT, 0u },
        { UINT32_C(0xc173e101), CDISASM_ARM_NAME_SQCVTU, 0u },
        { UINT32_C(0xc133e1c2), CDISASM_ARM_NAME_SQCVTN, 0u },
        { UINT32_C(0xc1f3e243), CDISASM_ARM_NAME_SQCVTUN, 0u },
        { UINT32_C(0xc133e2a4), CDISASM_ARM_NAME_UQCVT, 0u },
        { UINT32_C(0xc1b3e365), CDISASM_ARM_NAME_UQCVTN, 0u },
        { UINT32_C(0xc134e386), CDISASM_ARM_NAME_FCVT, 1u },
        { UINT32_C(0xc134e027), CDISASM_ARM_NAME_FCVTN, 1u },
        { UINT32_C(0xc175e080), CDISASM_ARM_NAME_SUNPK, 0u },
        { UINT32_C(0xc1f5e3dd), CDISASM_ARM_NAME_UUNPK, 0u },
        { UINT32_C(0xc136e080), CDISASM_ARM_NAME_ZIP, 0u },
        { UINT32_C(0xc1f6e01e), CDISASM_ARM_NAME_UZP, 0u },
        { UINT32_C(0xc137e080), CDISASM_ARM_NAME_ZIP, 0u },
        { UINT32_C(0xc137e01e), CDISASM_ARM_NAME_UZP, 0u },
        { UINT32_C(0xc1b8e080), CDISASM_ARM_NAME_FRINTN, 0u },
        { UINT32_C(0xc1b9e104), CDISASM_ARM_NAME_FRINTP, 0u },
        { UINT32_C(0xc1bae188), CDISASM_ARM_NAME_FRINTM, 0u },
        { UINT32_C(0xc1bce39c), CDISASM_ARM_NAME_FRINTA, 0u }
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
            } else if (forms[form_index].requires_fp8 == 0u
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

static void test_endian_dispatch_and_errors(void)
{
    const uint32_t word = UINT32_C(0xc1b3e39f);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t big_bytes[4];
    uint8_t little_bytes[4];
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
        big_bytes, sizeof(big_bytes), UINT64_C(0x12c000),
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
        little_bytes, sizeof(little_bytes), UINT64_C(0x12c000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic);
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
        narrow_word(5u, 0u, 0u, 0u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_INSTRUCTION));

    memset(&generic, 0xa5, sizeof(generic));
    (void)decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_SQCVT);
    EXPECT(generic.isa_id != CDISASM_ARM_ISA_A64);

    memset(&generic, 0xa5, sizeof(generic));
    (void)decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic);
    EXPECT(generic.name_id != CDISASM_ARM_NAME_SQCVT);
    EXPECT(generic.isa_id != CDISASM_ARM_ISA_A64);
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void test_formatting(void)
{
    static const struct format_vector {
        uint32_t word;
        const char *text;
    } vectors[] = {
        { UINT32_C(0xc131e080),
          "fcvtzs {z0.s, z1.s, z2.s, z3.s}, {z4.s, z5.s, z6.s, z7.s}" },
        { UINT32_C(0xc131e03c),
          "fcvtzu {z28.s, z29.s, z30.s, z31.s}, {z0.s, z1.s, z2.s, z3.s}" },
        { UINT32_C(0xc132e380),
          "scvtf {z0.s, z1.s, z2.s, z3.s}, {z28.s, z29.s, z30.s, z31.s}" },
        { UINT32_C(0xc132e124),
          "ucvtf {z4.s, z5.s, z6.s, z7.s}, {z8.s, z9.s, z10.s, z11.s}" },
        { UINT32_C(0xc133e080),
          "sqcvt z0.b, {z4.s, z5.s, z6.s, z7.s}" },
        { UINT32_C(0xc173e101),
          "sqcvtu z1.b, {z8.s, z9.s, z10.s, z11.s}" },
        { UINT32_C(0xc133e1c2),
          "sqcvtn z2.b, {z12.s, z13.s, z14.s, z15.s}" },
        { UINT32_C(0xc1f3e243),
          "sqcvtun z3.h, {z16.d, z17.d, z18.d, z19.d}" },
        { UINT32_C(0xc133e2a4),
          "uqcvt z4.b, {z20.s, z21.s, z22.s, z23.s}" },
        { UINT32_C(0xc1b3e365),
          "uqcvtn z5.h, {z24.d, z25.d, z26.d, z27.d}" },
        { UINT32_C(0xc134e386),
          "fcvt z6.b, {z28.s, z29.s, z30.s, z31.s}" },
        { UINT32_C(0xc134e027),
          "fcvtn z7.b, {z0.s, z1.s, z2.s, z3.s}" },
        { UINT32_C(0xc175e080),
          "sunpk {z0.h, z1.h, z2.h, z3.h}, {z4.b, z5.b}" },
        { UINT32_C(0xc1f5e3dd),
          "uunpk {z28.d, z29.d, z30.d, z31.d}, {z30.s, z31.s}" },
        { UINT32_C(0xc136e080),
          "zip {z0.b, z1.b, z2.b, z3.b}, {z4.b, z5.b, z6.b, z7.b}" },
        { UINT32_C(0xc1f6e01e),
          "uzp {z28.d, z29.d, z30.d, z31.d}, {z0.d, z1.d, z2.d, z3.d}" },
        { UINT32_C(0xc137e080),
          "zip {z0.q, z1.q, z2.q, z3.q}, {z4.q, z5.q, z6.q, z7.q}" },
        { UINT32_C(0xc137e01e),
          "uzp {z28.q, z29.q, z30.q, z31.q}, {z0.q, z1.q, z2.q, z3.q}" },
        { UINT32_C(0xc1b8e080),
          "frintn {z0.s, z1.s, z2.s, z3.s}, {z4.s, z5.s, z6.s, z7.s}" },
        { UINT32_C(0xc1b9e104),
          "frintp {z4.s, z5.s, z6.s, z7.s}, {z8.s, z9.s, z10.s, z11.s}" },
        { UINT32_C(0xc1bae188),
          "frintm {z8.s, z9.s, z10.s, z11.s}, {z12.s, z13.s, z14.s, z15.s}" },
        { UINT32_C(0xc1bce39c),
          "frinta {z28.s, z29.s, z30.s, z31.s}, {z28.s, z29.s, z30.s, z31.s}" }
    };
    size_t index;

    for (index = 0u; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
        cdisasm_arm_instruction instruction;
        char text[112];
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
        char text[112];

        EXPECT(decode_word(
            UINT32_C(0xc131e03c), CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        instruction.operand[0].register_list = UINT16_C(0x0105);
        memset(text, 0xa5, sizeof(text));
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == 0u);
        EXPECT(text[0] == '\0');
    }
}
#endif

int main(void)
{
    test_exhaustive_domain();
    test_feature_and_profile_gates();
    test_endian_dispatch_and_errors();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM SME2 four-vector conversion test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SME2 four-vector conversion tests passed "
           "(allocated=5504, reserved=3072; USE_EXTRA_OPCODES=%d)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
