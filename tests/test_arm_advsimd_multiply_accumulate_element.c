#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define FAMILY_MASK UINT32_C(0xbf00f400)

typedef struct element_operation {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
    uint8_t accumulate;
} element_operation;

static const element_operation operations[2] = {
    { UINT32_C(0x2f000000), CDISASM_ARM_NAME_MLA,
      UINT16_C(6268), "mla", 1u },
    { UINT32_C(0x2f004000), CDISASM_ARM_NAME_MLS,
      UINT16_C(6270), "mls", 1u }
};

static const element_operation widening_operations[9] = {
    { UINT32_C(0x0f002000), CDISASM_ARM_NAME_SMLAL,
      UINT16_C(6243), "smlal", 1u },
    { UINT32_C(0x0f003000), CDISASM_ARM_NAME_SQDMLAL,
      UINT16_C(6244), "sqdmlal", 1u },
    { UINT32_C(0x0f006000), CDISASM_ARM_NAME_SMLSL,
      UINT16_C(6245), "smlsl", 1u },
    { UINT32_C(0x0f007000), CDISASM_ARM_NAME_SQDMLSL,
      UINT16_C(6246), "sqdmlsl", 1u },
    { UINT32_C(0x0f00a000), CDISASM_ARM_NAME_SMULL,
      UINT16_C(6248), "smull", 0u },
    { UINT32_C(0x0f00b000), CDISASM_ARM_NAME_SQDMULL,
      UINT16_C(6249), "sqdmull", 0u },
    { UINT32_C(0x2f002000), CDISASM_ARM_NAME_UMLAL,
      UINT16_C(6269), "umlal", 1u },
    { UINT32_C(0x2f006000), CDISASM_ARM_NAME_UMLSL,
      UINT16_C(6271), "umlsl", 1u },
    { UINT32_C(0x2f00a000), CDISASM_ARM_NAME_UMULL,
      UINT16_C(6272), "umull", 0u }
};

_Static_assert(CDISASM_ARM_NAME_MLA == UINT16_C(217),
               "MLA mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_MLS == UINT16_C(310),
               "MLS mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_UMLAL == UINT16_C(1771),
               "UMLAL mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_UMLSL == UINT16_C(1776),
               "UMLSL mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SMLAL == UINT16_C(1414)
                   && CDISASM_ARM_NAME_SMLSL == UINT16_C(1431)
                   && CDISASM_ARM_NAME_SMULL == UINT16_C(1453)
                   && CDISASM_ARM_NAME_SQDMLAL == UINT16_C(1475)
                   && CDISASM_ARM_NAME_SQDMLSL == UINT16_C(1479)
                   && CDISASM_ARM_NAME_SQDMULL == UINT16_C(1484)
                   && CDISASM_ARM_NAME_UMULL == UINT16_C(1787),
               "widening by-element mnemonic IDs changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6272),
               "Advanced SIMD by-element multiply-accumulate forms "
               "unavailable");

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

static uint32_t make_word(unsigned operation, unsigned q,
                          unsigned size_code, unsigned h, unsigned l,
                          unsigned m, unsigned rm, unsigned rn,
                          unsigned rd)
{
    return operations[operation].value | ((uint32_t)q << 30)
        | ((uint32_t)size_code << 22) | ((uint32_t)l << 21)
        | ((uint32_t)m << 20) | ((uint32_t)rm << 16)
        | ((uint32_t)h << 11) | ((uint32_t)rn << 5)
        | (uint32_t)rd;
}

static uint32_t make_widening_word(unsigned operation, unsigned q,
                                   unsigned size_code, unsigned h,
                                   unsigned l, unsigned m, unsigned rm,
                                   unsigned rn, unsigned rd)
{
    return widening_operations[operation].value | ((uint32_t)q << 30)
        | ((uint32_t)size_code << 22) | ((uint32_t)l << 21)
        | ((uint32_t)m << 20) | ((uint32_t)rm << 16)
        | ((uint32_t)h << 11) | ((uint32_t)rn << 5)
        | (uint32_t)rd;
}

#if USE_EXTRA_OPCODES
static unsigned indexed_register(uint32_t word, unsigned size_code)
{
    unsigned rm = (word >> 16) & 15u;

    return size_code == 1u ? rm : (((word >> 20) & 1u) << 4) | rm;
}

static uint64_t lane_index(uint32_t word, unsigned size_code)
{
    unsigned h = (word >> 11) & 1u;
    unsigned l = (word >> 21) & 1u;
    unsigned m = (word >> 20) & 1u;

    return size_code == 1u
        ? (uint64_t)((h << 2) | (l << 1) | m)
        : (uint64_t)((h << 1) | l);
}
#endif

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

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
                            cdisasm_arm_mode mode, size_t code_size,
                            cdisasm_arm_decode_option options,
                            cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(cpu, mode, bytes, code_size,
        UINT64_C(0x16e000), options, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
                      cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static int is_element_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6243) || form_id == UINT16_C(6244)
        || form_id == UINT16_C(6245) || form_id == UINT16_C(6246)
        || form_id == UINT16_C(6247) || form_id == UINT16_C(6250)
        || form_id == UINT16_C(6251) || form_id == UINT16_C(6252)
        || form_id == UINT16_C(6248) || form_id == UINT16_C(6249)
        || form_id == UINT16_C(6268) || form_id == UINT16_C(6269)
        || form_id == UINT16_C(6270) || form_id == UINT16_C(6271)
        || form_id == UINT16_C(6272) || form_id == UINT16_C(6273)
        || form_id == UINT16_C(6274) || form_id == UINT16_C(6275);
}

#if USE_EXTRA_OPCODES
static int vector_operand_matches(const cdisasm_arm_operand *operand,
                                  unsigned encoded, uint8_t vector_size,
                                  uint8_t element_size,
                                  cdisasm_operand_access access)
{
    return operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + encoded)
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->imm == 0u
        && operand->size == vector_size
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type
            == (cdisasm_arm_extend_type)element_size
        && operand->scale == (uint8_t)(vector_size / element_size)
        && operand->access == access;
}

static int lane_operand_matches(const cdisasm_arm_operand *operand,
                                unsigned encoded, uint8_t element_size,
                                uint64_t lane)
{
    return operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + encoded)
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->imm == lane
        && operand->size == 16u
        && operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type
            == (cdisasm_arm_extend_type)element_size
        && operand->scale == (uint8_t)(16u / element_size)
        && operand->access == CDISASM_OPERAND_ACCESS_READ;
}

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            uint32_t word, unsigned operation,
                            unsigned q, unsigned size_code,
                            unsigned rn, unsigned rd)
{
    uint8_t vector_size = q != 0u ? 16u : 8u;
    uint8_t element_size = size_code == 1u ? 2u : 4u;

    return instruction->address == UINT64_C(0x16e000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == operations[operation].name_id
        && instruction->form_id == operations[operation].form_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == 3u
        && vector_operand_matches(&instruction->operand[0], rd,
            vector_size, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && vector_operand_matches(&instruction->operand[1], rn,
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && lane_operand_matches(&instruction->operand[2],
            indexed_register(word, size_code), element_size,
            lane_index(word, size_code));
}

static int widening_metadata_matches(
    const cdisasm_arm_instruction *instruction, uint32_t word,
    unsigned operation, unsigned q, unsigned size_code,
    unsigned rn, unsigned rd)
{
    uint8_t source_vector_size = q != 0u ? 16u : 8u;
    uint8_t source_element_size = size_code == 1u ? 2u : 4u;
    uint8_t result_element_size =
        (uint8_t)(source_element_size * 2u);

    return instruction->address == UINT64_C(0x16e000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == widening_operations[operation].name_id
        && instruction->form_id == widening_operations[operation].form_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == 3u
        && vector_operand_matches(&instruction->operand[0], rd,
            16u, result_element_size,
            widening_operations[operation].accumulate != 0u
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE)
        && vector_operand_matches(&instruction->operand[1], rn,
            source_vector_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && lane_operand_matches(&instruction->operand[2],
            indexed_register(word, size_code), source_element_size,
            lane_index(word, size_code));
}
#endif

static void test_exhaustive_envelopes(void)
{
    uint32_t partitions[2][2][2] = { 0 };
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned operation;

    for (operation = 0u; operation < 2u; ++operation) {
        for (unsigned q = 0u; q < 2u; ++q) {
            for (unsigned size_code = 0u;
                 size_code < 4u; ++size_code) {
                int valid = size_code == 1u || size_code == 2u;

                for (unsigned h = 0u; h < 2u; ++h) {
                    for (unsigned l = 0u; l < 2u; ++l) {
                        for (unsigned m = 0u; m < 2u; ++m) {
                            for (unsigned rm = 0u; rm < 16u; ++rm) {
                                for (unsigned rn = 0u; rn < 32u; ++rn) {
                                    for (unsigned rd = 0u; rd < 32u;
                                         ++rd) {
                                        cdisasm_arm_instruction instruction;
                                        uint32_t word = make_word(operation,
                                            q, size_code, h, l, m, rm,
                                            rn, rd);
                                        uint32_t decoded;

                                        ++partitions[operation][q]
                                            [valid ? 0u : 1u];
                                        if (valid) {
                                            ++allocated;
                                        } else {
                                            ++reserved;
                                        }
                                        EXPECT((word & FAMILY_MASK)
                                            == operations[operation].value);
                                        memset(&instruction, 0xa5,
                                            sizeof(instruction));
                                        decoded = decode_word(word,
                                            CDISASM_ARM_CPU_ANY,
                                            CDISASM_ARM_MODE_A64, 4u,
                                            CDISASM_ARM_DECODE_OPTION_NONE,
                                            &instruction);
                                        if (!valid) {
                                            EXPECT(decoded == 0u);
                                            EXPECT(error_only(&instruction,
                                                CDISASM_STATUS_INVALID_INSTRUCTION));
                                        } else {
#if USE_EXTRA_OPCODES
                                            EXPECT(decoded == 4u);
                                            EXPECT(metadata_matches(
                                                &instruction, word,
                                                operation, q, size_code,
                                                rn, rd));
#else
                                            EXPECT(decoded == 0u);
                                            EXPECT(error_only(&instruction,
                                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    for (operation = 0u; operation < 2u; ++operation) {
        EXPECT(partitions[operation][0][0] == UINT32_C(262144));
        EXPECT(partitions[operation][0][1] == UINT32_C(262144));
        EXPECT(partitions[operation][1][0] == UINT32_C(262144));
        EXPECT(partitions[operation][1][1] == UINT32_C(262144));
    }
    EXPECT(allocated == UINT32_C(1048576));
    EXPECT(reserved == UINT32_C(1048576));
    EXPECT(allocated + reserved == UINT32_C(2097152));
}

static void test_exhaustive_widening_envelopes(void)
{
    uint32_t partitions[9][2][2] = { 0 };
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned operation;

    for (operation = 0u;
         operation < sizeof(widening_operations)
             / sizeof(widening_operations[0]);
         ++operation) {
        for (unsigned q = 0u; q < 2u; ++q) {
            for (unsigned size_code = 0u;
                 size_code < 4u; ++size_code) {
                int valid = size_code == 1u || size_code == 2u;

                for (unsigned h = 0u; h < 2u; ++h) {
                    for (unsigned l = 0u; l < 2u; ++l) {
                        for (unsigned m = 0u; m < 2u; ++m) {
                            for (unsigned rm = 0u; rm < 16u; ++rm) {
                                for (unsigned rn = 0u; rn < 32u; ++rn) {
                                    for (unsigned rd = 0u; rd < 32u;
                                         ++rd) {
                                        cdisasm_arm_instruction instruction;
                                        uint32_t word =
                                            make_widening_word(operation,
                                                q, size_code, h, l, m,
                                                rm, rn, rd);
                                        uint32_t decoded;

                                        ++partitions[operation][q]
                                            [valid ? 0u : 1u];
                                        if (valid) {
                                            ++allocated;
                                        } else {
                                            ++reserved;
                                        }
                                        EXPECT((word & FAMILY_MASK)
                                            == widening_operations
                                                [operation].value);
                                        memset(&instruction, 0xa5,
                                            sizeof(instruction));
                                        decoded = decode_word(word,
                                            CDISASM_ARM_CPU_ANY,
                                            CDISASM_ARM_MODE_A64, 4u,
                                            CDISASM_ARM_DECODE_OPTION_NONE,
                                            &instruction);
                                        if (!valid) {
                                            EXPECT(decoded == 0u);
                                            EXPECT(error_only(&instruction,
                                                CDISASM_STATUS_INVALID_INSTRUCTION));
                                        } else {
#if USE_EXTRA_OPCODES
                                            EXPECT(decoded == 4u);
                                            EXPECT(
                                                widening_metadata_matches(
                                                    &instruction, word,
                                                    operation, q,
                                                    size_code, rn, rd));
#else
                                            EXPECT(decoded == 0u);
                                            EXPECT(error_only(&instruction,
                                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    for (operation = 0u;
         operation < sizeof(widening_operations)
             / sizeof(widening_operations[0]);
         ++operation) {
        EXPECT(partitions[operation][0][0] == UINT32_C(262144));
        EXPECT(partitions[operation][0][1] == UINT32_C(262144));
        EXPECT(partitions[operation][1][0] == UINT32_C(262144));
        EXPECT(partitions[operation][1][1] == UINT32_C(262144));
    }
    EXPECT(allocated == UINT32_C(4718592));
    EXPECT(reserved == UINT32_C(4718592));
    EXPECT(allocated + reserved == UINT32_C(9437184));
}

static void expect_cpu_status(uint32_t word, cdisasm_arm_cpu_id cpu,
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
    decoded = decode_word(word, cpu, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(error_only(&instruction, expected));
    }
}

static void test_profiles_and_neighbors(void)
{
    static const struct sibling_case {
        uint32_t word;
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
        int structured;
    } siblings[] = {
        { UINT32_C(0x4eb1960f), CDISASM_ARM_NAME_MLA,
          UINT16_C(6132), 1 }, /* fixed-vector MLA */
        { UINT32_C(0x2e7a9738), CDISASM_ARM_NAME_MLS,
          UINT16_C(6174), 1 }, /* fixed-vector MLS */
        { UINT32_C(0x04105961), CDISASM_ARM_NAME_MLA,
          UINT16_C(2309), 1 }, /* predicated SVE MLA */
        { UINT32_C(0x04107961), CDISASM_ARM_NAME_MLS,
          UINT16_C(2310), 1 }, /* predicated SVE MLS */
        { UINT32_C(0x443a08e6), CDISASM_ARM_NAME_MLA,
          UINT16_C(2722), 1 }, /* indexed SVE MLA */
        { UINT32_C(0x44bc0e30), CDISASM_ARM_NAME_MLS,
          UINT16_C(2726), 1 }, /* indexed SVE MLS */
        { UINT32_C(0x2f420020), CDISASM_ARM_NAME_MLA,
          UINT16_C(6268), 1 },
        { UINT32_C(0x2f6e41ac), CDISASM_ARM_NAME_MLS,
          UINT16_C(6270), 1 },
        { UINT32_C(0x2f422020), CDISASM_ARM_NAME_UMLAL,
          UINT16_C(6269), 1 }, /* widening by-element UMLAL */
        { UINT32_C(0x2f6e61ac), CDISASM_ARM_NAME_UMLSL,
          UINT16_C(6271), 1 }  /* widening by-element UMLSL */
    };
    uint32_t profile_words[2] = {
        make_word(0u, 1u, 1u, 1u, 1u, 1u, 15u, 30u, 31u),
        make_word(1u, 1u, 2u, 1u, 1u, 1u, 15u, 29u, 28u)
    };
    unsigned operation;
    size_t index;

    for (operation = 0u; operation < 2u; ++operation) {
        uint32_t word = profile_words[operation];
        unsigned bit;

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A34,
                          CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A53,
                          CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M3,
                          CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
                          CDISASM_STATUS_OK);
        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((FAMILY_MASK & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(word ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded != 4u
                || instruction.form_id != operations[operation].form_id);
        }
    }

    for (index = 0u;
         index < sizeof(siblings) / sizeof(siblings[0]); ++index) {
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(siblings[index].word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        if (siblings[index].structured) {
            EXPECT(decoded == 4u);
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id == siblings[index].name_id);
            EXPECT(instruction.form_id == siblings[index].form_id);
        } else {
            EXPECT(decoded == 0u);
            EXPECT(error_only(&instruction,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
        }
#else
        (void)decoded;
        (void)siblings[index].name_id;
        (void)siblings[index].form_id;
        (void)siblings[index].structured;
#endif
        if (index < 6u) {
            EXPECT(!is_element_form(instruction.form_id));
        }
    }
}

static void test_widening_profiles_and_neighbors(void)
{
    static const struct widening_sibling_case {
        uint32_t word;
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
        int structured;
    } siblings[] = {
        { UINT32_C(0x0f422020), CDISASM_ARM_NAME_SMLAL,
          UINT16_C(6243), 1 },
        { UINT32_C(0x0f423020), CDISASM_ARM_NAME_SQDMLAL,
          UINT16_C(6244), 1 },
        { UINT32_C(0x0f426020), CDISASM_ARM_NAME_SMLSL,
          UINT16_C(6245), 1 },
        { UINT32_C(0x0f427020), CDISASM_ARM_NAME_SQDMLSL,
          UINT16_C(6246), 1 },
        { UINT32_C(0x0f42a020), CDISASM_ARM_NAME_SMULL,
          UINT16_C(6248), 1 },
        { UINT32_C(0x0f42b020), CDISASM_ARM_NAME_SQDMULL,
          UINT16_C(6249), 1 },
        { UINT32_C(0x2f422020), CDISASM_ARM_NAME_UMLAL,
          UINT16_C(6269), 1 },
        { UINT32_C(0x2f6e61ac), CDISASM_ARM_NAME_UMLSL,
          UINT16_C(6271), 1 },
        { UINT32_C(0x2f42a020), CDISASM_ARM_NAME_UMULL,
          UINT16_C(6272), 1 },
        { UINT32_C(0x2e628020), CDISASM_ARM_NAME_UMLAL,
          UINT16_C(6112), 1 }, /* fixed-vector UMLAL */
        { UINT32_C(0x6ea2a020), CDISASM_ARM_NAME_UMLSL,
          UINT16_C(6113), 1 }, /* fixed-vector UMLSL2 */
        { UINT32_C(0x2f420020), CDISASM_ARM_NAME_MLA,
          UINT16_C(6268), 1 },
        { UINT32_C(0x2f6e41ac), CDISASM_ARM_NAME_MLS,
          UINT16_C(6270), 1 },
        { UINT32_C(0x0f428020), CDISASM_ARM_NAME_MUL,
          UINT16_C(6247), 1 }, /* adjacent MUL by-element leaf */
        { UINT32_C(0x0f42c020), CDISASM_ARM_NAME_SQDMULH,
          UINT16_C(6250), 1 }, /* adjacent SQDMULH leaf */
        { UINT32_C(0x0f42d020), CDISASM_ARM_NAME_SQRDMULH,
          UINT16_C(6251), 1 }, /* adjacent SQRDMULH leaf */
        { UINT32_C(0x4f82e020), CDISASM_ARM_NAME_SDOT,
          UINT16_C(6252), 1 }, /* adjacent signed dot-product leaf */
        { UINT32_C(0x2f42d020), CDISASM_ARM_NAME_SQRDMLAH,
          UINT16_C(6273), 1 }, /* adjacent RDM add-high leaf */
        { UINT32_C(0x6f82e020), CDISASM_ARM_NAME_UDOT,
          UINT16_C(6274), 1 }, /* adjacent unsigned dot-product leaf */
        { UINT32_C(0x2f42f020), CDISASM_ARM_NAME_SQRDMLSH,
          UINT16_C(6275), 1 }  /* adjacent RDM subtract-high leaf */
    };
    unsigned operation;
    size_t index;

    for (operation = 0u;
         operation < sizeof(widening_operations)
             / sizeof(widening_operations[0]);
         ++operation) {
        uint32_t word = make_widening_word(operation, operation & 1u,
            1u + (operation & 1u), 1u, 1u, 1u, 15u,
            30u - (operation & 1u), 31u - (operation & 1u));

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A34,
                          CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A53,
                          CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M3,
                          CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
                          CDISASM_STATUS_OK);

        for (unsigned bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((FAMILY_MASK & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(word ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded != 4u
                || instruction.form_id
                    != widening_operations[operation].form_id);
        }
    }

    for (index = 0u;
         index < sizeof(siblings) / sizeof(siblings[0]); ++index) {
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(siblings[index].word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        if (siblings[index].structured) {
            EXPECT(decoded == 4u);
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id == siblings[index].name_id);
            EXPECT(instruction.form_id == siblings[index].form_id);
        } else {
            EXPECT(decoded == 0u);
            EXPECT(error_only(&instruction,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
        }
#else
        EXPECT(decoded == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
        (void)siblings[index].name_id;
        (void)siblings[index].form_id;
        (void)siblings[index].structured;
#endif
        if (index >= 9u && index < 11u) {
            EXPECT(!is_element_form(instruction.form_id));
        }
    }
}

static void check_transport(uint32_t word)
{
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned boundary;

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif

    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x16e000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x16e000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x16e000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x16e000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(error_only(&other, CDISASM_STATUS_TRUNCATED));
    }
}

static void test_transport_and_status_precedence(void)
{
    cdisasm_arm_instruction instruction;
    unsigned operation;

    for (operation = 0u; operation < 2u; ++operation) {
        uint32_t allocated = make_word(operation, 1u,
            operation == 0u ? 1u : 2u, 1u, 1u, 1u, 15u, 30u, 31u);
        uint32_t reserved = make_word(operation, operation, 3u,
            1u, 1u, 1u, 15u, 30u, 31u);

        check_transport(allocated);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_INSTRUCTION));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 3u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_TRUNCATED));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, UINT64_C(1) << 63,
            &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_ARGUMENT));
    }

    for (operation = 0u;
        operation < sizeof(widening_operations)
             / sizeof(widening_operations[0]);
         ++operation) {
        uint32_t allocated = make_widening_word(operation, 1u,
            1u + (operation & 1u), 1u, 1u, 1u,
            15u, 30u, 31u);
        uint32_t reserved = make_widening_word(operation,
            operation & 1u, 0u, 1u, 1u, 1u, 15u, 30u, 31u);

        check_transport(allocated);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_INSTRUCTION));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 3u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_TRUNCATED));
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(0u, 1u, 1u, 1u, 1u, 1u,
        15u, 30u, 31u), CDISASM_ARM_CPU_CORTEX_A7,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    (void)decode_word(make_word(1u, 1u, 2u, 1u, 1u, 1u,
        15u, 30u, 31u), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
    EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
        || !is_element_form(instruction.form_id));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void reject_forgery(const cdisasm_arm_instruction *instruction,
                           const char *mutation)
{
    char text[160];
    size_t length;

    memset(text, 0xa5, sizeof(text));
    length = cdisasm_arm_format(instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text));
    if (length != 0u || text[0] != '\0') {
        if (failures < 32) {
            fprintf(stderr, "accepted formatter forgery: %s -> %s\n",
                    mutation, text);
        }
        ++failures;
    }
}

static void expect_instruction_format(
    const cdisasm_arm_instruction *instruction, const char *expected)
{
    char text[160];
    size_t expected_length = strlen(expected);
    size_t length = cdisasm_arm_format(instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text));

    if (length != expected_length || strcmp(text, expected) != 0) {
        fprintf(stderr, "format mismatch: expected '%s', got '%s'\n",
                expected, text);
    }
    EXPECT(length == expected_length);
    EXPECT(strcmp(text, expected) == 0);
}

static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char short_text[8];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    expect_instruction_format(&instruction, expected);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, NULL, 0u)
        == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, short_text,
        sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void init_opaque(cdisasm_arm_instruction *instruction,
                        uint32_t word, cdisasm_arm_form_id form_id,
                        cdisasm_arm_name_id name_id)
{
    memset(instruction, 0, sizeof(*instruction));
    instruction->address = UINT64_C(0x16e000);
    instruction->opcode_size = 4u;
    instruction->raw_instruction = word;
    instruction->name_id = name_id;
    instruction->form_id = form_id;
    instruction->condition = CDISASM_ARM_CONDITION_AL;
    instruction->isa_id = CDISASM_ARM_ISA_A64;
    instruction->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
}

static void test_formatter_and_schema(void)
{
    static const char element_letters[2] = { 'h', 's' };
    static const char widening_result_letters[2] = { 's', 'd' };
    static const uint8_t a32_mla[4] = { 0x91, 0x32, 0x20, 0xe0 };
    static const uint8_t t32_mls[4] = { 0x05, 0xfb, 0x16, 0x74 };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char expected[160];
    char text[160];
    unsigned operation;

    for (operation = 0u; operation < 2u; ++operation) {
        for (unsigned q = 0u; q < 2u; ++q) {
            for (unsigned relative_size = 0u;
                 relative_size < 2u; ++relative_size) {
                unsigned size_code = relative_size + 1u;
                unsigned total_size = q != 0u ? 16u : 8u;
                unsigned count = total_size >> size_code;
                unsigned rm = size_code == 1u ? 15u : 7u;
                unsigned m = 1u;
                uint32_t word = make_word(operation, q, size_code,
                    1u, 1u, m, rm, 30u, 31u);
                unsigned encoded_indexed =
                    indexed_register(word, size_code);
                unsigned lane = (unsigned)lane_index(word, size_code);
                int length = snprintf(expected, sizeof(expected),
                    "%s v31.%u%c, v30.%u%c, v%u.%c[%u]",
                    operations[operation].mnemonic,
                    count, element_letters[relative_size],
                    count, element_letters[relative_size],
                    encoded_indexed, element_letters[relative_size], lane);

                EXPECT(length > 0 && (size_t)length < sizeof(expected));
                expect_format(word, expected);
            }
        }
    }

    for (operation = 0u;
         operation < sizeof(widening_operations)
             / sizeof(widening_operations[0]);
         ++operation) {
        for (unsigned q = 0u; q < 2u; ++q) {
            for (unsigned relative_size = 0u;
                 relative_size < 2u; ++relative_size) {
                unsigned size_code = relative_size + 1u;
                unsigned source_total_size = q != 0u ? 16u : 8u;
                unsigned source_count = source_total_size >> size_code;
                unsigned result_count = 8u >> size_code;
                unsigned rm = 15u;
                unsigned m = 1u;
                uint32_t word = make_widening_word(operation, q,
                    size_code, 1u, 1u, m, rm, 30u, 31u);
                unsigned encoded_indexed =
                    indexed_register(word, size_code);
                unsigned lane = (unsigned)lane_index(word, size_code);
                int length = snprintf(expected, sizeof(expected),
                    "%s%s v31.%u%c, v30.%u%c, v%u.%c[%u]",
                    widening_operations[operation].mnemonic,
                    q != 0u ? "2" : "",
                    result_count, widening_result_letters[relative_size],
                    source_count, element_letters[relative_size],
                    encoded_indexed, element_letters[relative_size], lane);

                EXPECT(length > 0 && (size_t)length < sizeof(expected));
                expect_format(word, expected);
            }
        }
    }

    expect_format(UINT32_C(0x2f420020),
                  "mla v0.4h, v1.4h, v2.h[0]");
    expect_format(UINT32_C(0x6f7f0883),
                  "mla v3.8h, v4.8h, v15.h[7]");
    expect_format(UINT32_C(0x2f8700c5),
                  "mla v5.2s, v6.2s, v7.s[0]");
    expect_format(UINT32_C(0x6fbf0928),
                  "mla v8.4s, v9.4s, v31.s[3]");
    expect_format(UINT32_C(0x2f504bdf),
                  "mls v31.4h, v30.4h, v0.h[5]");
    expect_format(UINT32_C(0x6f914ad5),
                  "mls v21.4s, v22.4s, v17.s[2]");
    expect_format(UINT32_C(0x2f422020),
                  "umlal v0.4s, v1.4h, v2.h[0]");
    expect_format(UINT32_C(0x6f7f2883),
                  "umlal2 v3.4s, v4.8h, v15.h[7]");
    expect_format(UINT32_C(0x2f8720c5),
                  "umlal v5.2d, v6.2s, v7.s[0]");
    expect_format(UINT32_C(0x6fbf2928),
                  "umlal2 v8.2d, v9.4s, v31.s[3]");
    expect_format(UINT32_C(0x2f506bdf),
                  "umlsl v31.4s, v30.4h, v0.h[5]");
    expect_format(UINT32_C(0x6f916ad5),
                  "umlsl2 v21.2d, v22.4s, v17.s[2]");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x6fbf0928), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("MLA v8.4s, v9.4s, v31.s[3]"));
    EXPECT(strcmp(text, "MLA v8.4s, v9.4s, v31.s[3]") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(6270));
    REJECT_MUTATION(forged.form_id = UINT16_C(6132));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_MLS);
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0x6fff0928));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0x6fbf4928));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd503201f));
    REJECT_MUTATION(forged.opcode_size = 2u);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
    REJECT_MUTATION(forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_V7);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V8);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_V30);
    REJECT_MUTATION(forged.operand[2].size = 8u);
    REJECT_MUTATION(forged.operand[2].extend_type = 2u);
    REJECT_MUTATION(forged.operand[2].scale = 8u);
    REJECT_MUTATION(forged.operand[2].flags =
        CDISASM_OPERAND_FLAG_NONE);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x6fbfa928), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("UMULL2 v8.2d, v9.4s, v31.s[3]"));
    EXPECT(strcmp(text, "UMULL2 v8.2d, v9.4s, v31.s[3]") == 0);

    REJECT_MUTATION(forged.form_id = UINT16_C(6248));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_SMULL);
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0x4fbfa928));
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[0].size = 8u);
    REJECT_MUTATION(forged.operand[1].size = 8u);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_V30);
    REJECT_MUTATION(forged.operand[2].imm = 2u);
    REJECT_MUTATION(forged.operand[2].flags =
        CDISASM_OPERAND_FLAG_NONE);
    REJECT_MUTATION(forged.operand[2].imm = 2u);
    REJECT_MUTATION(forged.operand[2].access =
        CDISASM_OPERAND_ACCESS_WRITE);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x6fbf2928), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("UMLAL2 v8.2d, v9.4s, v31.s[3]"));
    EXPECT(strcmp(text, "UMLAL2 v8.2d, v9.4s, v31.s[3]") == 0);

    REJECT_MUTATION(forged.form_id = UINT16_C(6271));
    REJECT_MUTATION(forged.form_id = UINT16_C(6112));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_UMLSL);
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0x6fbf6928));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0x6fbf0928));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd503201f));
    REJECT_MUTATION(forged.opcode_size = 2u);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[0].size = 8u);
    REJECT_MUTATION(forged.operand[0].extend_type =
        (cdisasm_arm_extend_type)4u);
    REJECT_MUTATION(forged.operand[1].size = 8u);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_V30);
    REJECT_MUTATION(forged.operand[2].imm = 2u);
    REJECT_MUTATION(forged.operand[2].flags =
        CDISASM_OPERAND_FLAG_NONE);

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_NOP;
    forged.form_id = UINT16_C(6269);
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "widening element form-only claim");
    forged.form_id = CDISASM_ARM_FORM_NONE;
    forged.raw_instruction = UINT32_C(0x2f422020);
    reject_forgery(&forged, "widening element raw-only claim");
    forged.name_id = CDISASM_ARM_NAME_UMLAL;
    forged.raw_instruction = UINT32_C(0xd503201f);
    reject_forgery(&forged, "widening element name-only claim");

    init_opaque(&forged, UINT32_C(0x2f422020),
                UINT16_C(6269), CDISASM_ARM_NAME_UMLAL);
    reject_forgery(&forged,
        "obsolete opaque widening by-element representation");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x2e628020), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    expect_instruction_format(&instruction,
        "umlal v0.4s, v1.4h, v2.4h");
    REJECT_MUTATION(forged.form_id = UINT16_C(6269));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0x2f422020));

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_NOP;
    forged.form_id = UINT16_C(6268);
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "by-element-form-only claim");
    forged.form_id = CDISASM_ARM_FORM_NONE;
    forged.raw_instruction = UINT32_C(0x2f420020);
    reject_forgery(&forged, "by-element-raw-only claim");
    forged.name_id = CDISASM_ARM_NAME_MLA;
    forged.raw_instruction = UINT32_C(0xd503201f);
    reject_forgery(&forged, "by-element-name-only claim");

    init_opaque(&forged, UINT32_C(0x2f420020),
                UINT16_C(6268), CDISASM_ARM_NAME_MLA);
    reject_forgery(&forged, "obsolete opaque by-element representation");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x4eb1960f), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    expect_instruction_format(&instruction,
        "mla v15.4s, v16.4s, v17.4s");
    REJECT_MUTATION(forged.form_id = UINT16_C(6268));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0x2f420020));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x04024020), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    expect_instruction_format(&instruction,
        "mla z0.b, p0/m, z1.b, z2.b");
    REJECT_MUTATION(forged.form_id = UINT16_C(6268));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0x2f420020));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, a32_mla, sizeof(a32_mla),
        UINT64_C(0x16e000), CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    expect_instruction_format(&instruction, "mla r0, r1, r2, r3");
    EXPECT(instruction.form_id == UINT16_C(52));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_T32, t32_mls, sizeof(t32_mls),
        UINT64_C(0x16e000), CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    expect_instruction_format(&instruction, "mls r4, r5, r6, r7");
    EXPECT(instruction.form_id == UINT16_C(2176));

    expect_format(UINT32_C(0x443a08e6),
                  "mla z6.h, z7.h, z2.h[3]");
    init_opaque(&instruction, UINT32_C(0x443a08e6),
                UINT16_C(2722), CDISASM_ARM_NAME_MLA);
    reject_forgery(&instruction,
        "obsolete opaque indexed SVE MLA sibling");

#undef REJECT_MUTATION
}
#else
static void test_formatter_and_schema(void)
{
}
#endif

int main(void)
{
    test_exhaustive_envelopes();
    test_exhaustive_widening_envelopes();
    test_profiles_and_neighbors();
    test_widening_profiles_and_neighbors();
    test_transport_and_status_precedence();
    test_formatter_and_schema();

    if (failures != 0) {
        fprintf(stderr,
                "%d Advanced SIMD by-element multiply-accumulate "
                "test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM Advanced SIMD by-element MLA/MLS and widening multiply "
           "tests passed (USE_EXTRA_OPCODES=%d, MLA/MLS "
           "allocated=1048576 reserved=1048576, widening "
           "allocated=4718592 reserved=4718592)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
