#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

typedef struct length_descriptor {
    uint32_t mask;
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    int has_source;
} length_descriptor;

typedef struct reverse_descriptor {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    unsigned maximum_size;
} reverse_descriptor;

typedef struct reduction_descriptor {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    int fixed_d_result;
    int rejects_d_source;
} reduction_descriptor;

static const length_descriptor length_descriptors[] = {
    { UINT32_C(0xffe0f800), UINT32_C(0x04205000),
      CDISASM_ARM_NAME_ADDVL, UINT16_C(2348), 1 },
    { UINT32_C(0xffe0f800), UINT32_C(0x04605000),
      CDISASM_ARM_NAME_ADDPL, UINT16_C(2349), 1 },
    { UINT32_C(0xfffff800), UINT32_C(0x04bf5000),
      CDISASM_ARM_NAME_RDVL, UINT16_C(2352), 0 }
};

static const reverse_descriptor reverse_descriptors[] = {
    { UINT32_C(0x0e201800), CDISASM_ARM_NAME_REV16,
      UINT16_C(6004), 0u },
    { UINT32_C(0x2e200800), CDISASM_ARM_NAME_REV32,
      UINT16_C(6038), 1u },
    { UINT32_C(0x0e200800), CDISASM_ARM_NAME_REV64,
      UINT16_C(6003), 2u }
};

static const reduction_descriptor reduction_descriptors[] = {
    { UINT32_C(0x04002000), CDISASM_ARM_NAME_SADDV,
      UINT16_C(2243), 1, 1 },
    { UINT32_C(0x04012000), CDISASM_ARM_NAME_UADDV,
      UINT16_C(2244), 1, 0 },
    { UINT32_C(0x04082000), CDISASM_ARM_NAME_SMAXV,
      UINT16_C(2246), 0, 0 },
    { UINT32_C(0x04092000), CDISASM_ARM_NAME_UMAXV,
      UINT16_C(2248), 0, 0 },
    { UINT32_C(0x040a2000), CDISASM_ARM_NAME_SMINV,
      UINT16_C(2247), 0, 0 },
    { UINT32_C(0x040b2000), CDISASM_ARM_NAME_UMINV,
      UINT16_C(2249), 0, 0 },
    { UINT32_C(0x04182000), CDISASM_ARM_NAME_ORV,
      UINT16_C(2255), 0, 0 },
    { UINT32_C(0x04192000), CDISASM_ARM_NAME_EORV,
      UINT16_C(2256), 0, 0 },
    { UINT32_C(0x041a2000), CDISASM_ARM_NAME_ANDV,
      UINT16_C(2257), 0, 0 }
};

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 20) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",      \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static uint32_t length_word(const length_descriptor *descriptor,
                            unsigned rn, unsigned imm6, unsigned rd)
{
    return descriptor->value
        | (descriptor->has_source ? (uint32_t)rn << 16 : UINT32_C(0))
        | ((uint32_t)imm6 << 5) | (uint32_t)rd;
}

static uint32_t reverse_word(const reverse_descriptor *descriptor,
                             unsigned q, unsigned size_code,
                             unsigned rn, unsigned rd)
{
    return descriptor->value | ((uint32_t)q << 30)
        | ((uint32_t)size_code << 22) | ((uint32_t)rn << 5)
        | (uint32_t)rd;
}

static uint32_t reduction_word(const reduction_descriptor *descriptor,
                               unsigned size_code, unsigned pg,
                               unsigned zn, unsigned vd)
{
    return descriptor->value | ((uint32_t)size_code << 22)
        | ((uint32_t)pg << 10) | ((uint32_t)zn << 5)
        | (uint32_t)vd;
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
    return cdisasm_arm_decode(cpu_id, mode, bytes, code_size,
        UINT64_C(0x11c000), options, instruction);
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
static int instruction_header_matches(
    const cdisasm_arm_instruction *instruction, uint32_t word,
    cdisasm_arm_name_id name_id, cdisasm_arm_form_id form_id,
    uint32_t flags, unsigned operand_count)
{
    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == name_id
        && instruction->form_id == form_id
        && instruction->address == UINT64_C(0x11c000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == operand_count
        && instruction->instruction_flags == flags;
}

static cdisasm_arm_reg_id expected_xreg(unsigned encoded, int use_sp)
{
    if (encoded == 31u) {
        return use_sp ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_XZR;
    }
    return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded);
}

static int register_matches(const cdisasm_arm_operand *operand,
                            cdisasm_arm_reg_id reg, uint8_t size,
                            cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = reg;
    expected.size = size;
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int immediate_matches(const cdisasm_arm_operand *operand,
                             unsigned encoded)
{
    cdisasm_arm_operand expected;
    int64_t value = encoded < 32u
        ? (int64_t)encoded : (int64_t)encoded - INT64_C(64);

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_IMMEDIATE;
    expected.imm = (uint64_t)value;
    expected.size = 1u;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    if (value < 0) {
        expected.flags = CDISASM_OPERAND_FLAG_SIGNED;
    }
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static cdisasm_arm_reg_id scalar_reg(unsigned encoded, uint8_t size)
{
    if (size == 1u) {
        return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_B0 + encoded);
    }
    if (size == 2u) {
        return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_H0 + encoded);
    }
    if (size == 4u) {
        return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + encoded);
    }
    return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_D0 + encoded);
}

static int vector_matches(const cdisasm_arm_operand *operand,
                          unsigned encoded, uint8_t total_size,
                          uint8_t element_size,
                          cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded);
    expected.size = total_size;
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.scale = (uint8_t)(total_size / element_size);
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int predicate_matches(const cdisasm_arm_operand *operand,
                             unsigned encoded, uint8_t element_size)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_PREDICATE;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int zreg_matches(const cdisasm_arm_operand *operand,
                        unsigned encoded, uint8_t element_size)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int length_metadata_matches(
    const cdisasm_arm_instruction *instruction, uint32_t word,
    const length_descriptor *descriptor, unsigned rn,
    unsigned imm6, unsigned rd)
{
    unsigned immediate_index = descriptor->has_source ? 2u : 1u;

    return instruction_header_matches(instruction, word,
            descriptor->name_id, descriptor->form_id,
            CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR,
            descriptor->has_source ? 3u : 2u)
        && register_matches(&instruction->operand[0],
            expected_xreg(rd, descriptor->has_source), 8u,
            CDISASM_OPERAND_ACCESS_WRITE)
        && (!descriptor->has_source
            || register_matches(&instruction->operand[1],
                expected_xreg(rn, 1), 8u,
                CDISASM_OPERAND_ACCESS_READ))
        && immediate_matches(
            &instruction->operand[immediate_index], imm6);
}

static int reverse_metadata_matches(
    const cdisasm_arm_instruction *instruction, uint32_t word,
    const reverse_descriptor *descriptor, unsigned q,
    unsigned size_code, unsigned rn, unsigned rd)
{
    uint8_t total_size = q != 0u ? 16u : 8u;
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    return instruction_header_matches(instruction, word,
            descriptor->name_id, descriptor->form_id,
            CDISASM_ARM_INSTRUCTION_FLAG_SIMD, 2u)
        && vector_matches(&instruction->operand[0], rd,
            total_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && vector_matches(&instruction->operand[1], rn,
            total_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}

static int reduction_metadata_matches(
    const cdisasm_arm_instruction *instruction, uint32_t word,
    const reduction_descriptor *descriptor, unsigned size_code,
    unsigned pg, unsigned zn, unsigned vd)
{
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);
    uint8_t result_size = descriptor->fixed_d_result
        ? 8u : element_size;

    return instruction_header_matches(instruction, word,
            descriptor->name_id, descriptor->form_id,
            CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED, 3u)
        && register_matches(&instruction->operand[0],
            scalar_reg(vd, result_size), result_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        && predicate_matches(
            &instruction->operand[1], pg, element_size)
        && zreg_matches(&instruction->operand[2], zn, element_size);
}
#endif

static void test_exhaustive_length_envelopes(void)
{
    uint32_t allocated = 0u;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(length_descriptors)
            / sizeof(length_descriptors[0]);
         ++descriptor_index) {
        const length_descriptor *descriptor =
            &length_descriptors[descriptor_index];
        unsigned rn_limit = descriptor->has_source ? 32u : 1u;
        unsigned rn;

        for (rn = 0u; rn < rn_limit; ++rn) {
            unsigned imm6;

            for (imm6 = 0u; imm6 < 64u; ++imm6) {
                unsigned rd;

                for (rd = 0u; rd < 32u; ++rd) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = length_word(
                        descriptor, rn, imm6, rd);
                    uint32_t decoded;

                    ++allocated;
                    EXPECT((word & descriptor->mask)
                        == descriptor->value);
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
                        CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
                    EXPECT(decoded == 4u);
                    EXPECT(length_metadata_matches(&instruction, word,
                        descriptor, rn, imm6, rd));
#else
                    EXPECT(decoded == 0u);
                    EXPECT(instruction_is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                }
            }
        }
    }
    EXPECT(allocated == UINT32_C(133120));
}

static void test_exhaustive_reverse_envelopes(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(reverse_descriptors)
            / sizeof(reverse_descriptors[0]);
         ++descriptor_index) {
        const reverse_descriptor *descriptor =
            &reverse_descriptors[descriptor_index];
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 0u; size_code < 4u; ++size_code) {
                unsigned rn;

                for (rn = 0u; rn < 32u; ++rn) {
                    unsigned rd;

                    for (rd = 0u; rd < 32u; ++rd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = reverse_word(
                            descriptor, q, size_code, rn, rd);
                        uint32_t decoded;

                        EXPECT((word & UINT32_C(0xbf3ffc00))
                            == descriptor->value);
                        memset(&instruction, 0xa5,
                            sizeof(instruction));
                        decoded = decode_word(word,
                            CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE,
                            &instruction);
                        if (size_code > descriptor->maximum_size) {
                            ++reserved;
                            EXPECT(decoded == 0u);
                            EXPECT(instruction_is_error_only(&instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                        } else {
                            ++allocated;
#if USE_EXTRA_OPCODES
                            EXPECT(decoded == 4u);
                            EXPECT(reverse_metadata_matches(
                                &instruction, word, descriptor,
                                q, size_code, rn, rd));
#else
                            EXPECT(decoded == 0u);
                            EXPECT(instruction_is_error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        }
                    }
                }
            }
        }
    }
    EXPECT(allocated == UINT32_C(12288));
    EXPECT(reserved == UINT32_C(12288));
}

static void test_exhaustive_reduction_envelopes(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(reduction_descriptors)
            / sizeof(reduction_descriptors[0]);
         ++descriptor_index) {
        const reduction_descriptor *descriptor =
            &reduction_descriptors[descriptor_index];
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            int is_allocated = !descriptor->rejects_d_source
                || size_code != 3u;
            unsigned pg;

            for (pg = 0u; pg < 8u; ++pg) {
                unsigned zn;

                for (zn = 0u; zn < 32u; ++zn) {
                    unsigned vd;

                    for (vd = 0u; vd < 32u; ++vd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = reduction_word(
                            descriptor, size_code, pg, zn, vd);
                        uint32_t decoded;

                        EXPECT((word & UINT32_C(0xff3fe000))
                            == descriptor->value);
                        memset(&instruction, 0xa5,
                            sizeof(instruction));
                        decoded = decode_word(word,
                            CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE,
                            &instruction);
                        if (!is_allocated) {
                            ++reserved;
                            EXPECT(decoded == 0u);
                            EXPECT(instruction_is_error_only(&instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                        } else {
                            ++allocated;
#if USE_EXTRA_OPCODES
                            EXPECT(decoded == 4u);
                            EXPECT(reduction_metadata_matches(
                                &instruction, word, descriptor,
                                size_code, pg, zn, vd));
#else
                            EXPECT(decoded == 0u);
                            EXPECT(instruction_is_error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        }
                    }
                }
            }
        }
    }
    EXPECT(allocated == UINT32_C(286720));
    EXPECT(reserved == UINT32_C(8192));
}

static void expect_cpu_status(uint32_t word, cdisasm_arm_cpu_id cpu_id,
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
    decoded = decode_word(word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_feature_profiles(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(length_descriptors)
            / sizeof(length_descriptors[0]);
         ++descriptor_index) {
        uint32_t word = length_word(
            &length_descriptors[descriptor_index], 13u, 63u, 7u);

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M3,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (descriptor_index = 0u;
         descriptor_index < sizeof(reduction_descriptors)
            / sizeof(reduction_descriptors[0]);
         ++descriptor_index) {
        uint32_t word = reduction_word(
            &reduction_descriptors[descriptor_index], 2u, 3u, 13u, 7u);

        expect_cpu_status(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M3,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (descriptor_index = 0u;
         descriptor_index < sizeof(reverse_descriptors)
            / sizeof(reverse_descriptors[0]);
         ++descriptor_index) {
        uint32_t word = reverse_word(
            &reverse_descriptors[descriptor_index], 1u,
            reverse_descriptors[descriptor_index].maximum_size,
            13u, 7u);

        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M3,
            CDISASM_STATUS_OK);
    }
}

static void test_fixed_bit_neighbors(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(length_descriptors)
            / sizeof(length_descriptors[0]);
         ++descriptor_index) {
        const length_descriptor *descriptor =
            &length_descriptors[descriptor_index];
        uint32_t word = length_word(descriptor, 13u, 1u, 7u);
        unsigned bit;

        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((descriptor->mask & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(word ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded != 4u
                || instruction.form_id != descriptor->form_id);
        }
    }
    for (descriptor_index = 0u;
         descriptor_index < sizeof(reverse_descriptors)
            / sizeof(reverse_descriptors[0]);
         ++descriptor_index) {
        const reverse_descriptor *descriptor =
            &reverse_descriptors[descriptor_index];
        uint32_t word = reverse_word(descriptor, 1u, 0u, 13u, 7u);
        unsigned bit;

        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((UINT32_C(0xbf3ffc00)
                    & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(word ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded != 4u
                || instruction.form_id != descriptor->form_id);
        }
    }
    for (descriptor_index = 0u;
         descriptor_index < sizeof(reduction_descriptors)
            / sizeof(reduction_descriptors[0]);
         ++descriptor_index) {
        const reduction_descriptor *descriptor =
            &reduction_descriptors[descriptor_index];
        uint32_t word = reduction_word(
            descriptor, 2u, 3u, 13u, 7u);
        unsigned bit;

        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((UINT32_C(0xff3fe000)
                    & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(word ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded != 4u
                || instruction.form_id != descriptor->form_id);
        }
    }
}

static void check_transport(uint32_t word, uint32_t reserved)
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
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x11c000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x11c000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x11c000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x11c000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(
            &other, CDISASM_STATUS_TRUNCATED));
        if (reserved != 0u) {
            memset(&other, 0xa5, sizeof(other));
            EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, boundary,
                CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
            EXPECT(instruction_is_error_only(
                &other, CDISASM_STATUS_TRUNCATED));
        }
    }
}

static void test_endian_dispatch_modes_and_boundaries(void)
{
    uint32_t length = length_word(&length_descriptors[0], 31u, 32u, 31u);
    uint32_t reverse = reverse_word(
        &reverse_descriptors[2], 1u, 2u, 31u, 31u);
    uint32_t reverse_reserved = reverse_word(
        &reverse_descriptors[0], 1u, 1u, 13u, 7u);
    uint32_t reduction = reduction_word(
        &reduction_descriptors[8], 3u, 7u, 31u, 31u);
    uint32_t reduction_reserved = reduction_word(
        &reduction_descriptors[0], 3u, 3u, 13u, 7u);
    cdisasm_arm_instruction instruction;

    check_transport(length, 0u);
    check_transport(reverse, reverse_reserved);
    check_transport(reduction, reduction_reserved);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(length, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(reverse, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[96];
    char short_text[8];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_7,
        text, sizeof(text)) == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
        NULL, 0u) == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
        short_text, sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void test_formatter(void)
{
    static const char *const length_names[] = {
        "addvl", "addpl", "rdvl"
    };
    static const char *const reverse_names[] = {
        "rev16", "rev32", "rev64"
    };
    static const char *const reduction_names[] = {
        "saddv", "uaddv", "smaxv", "umaxv", "sminv", "uminv",
        "orv", "eorv", "andv"
    };
    static const int immediates[] = { -32, -1, 0, 1, 31 };
    static const char suffixes[] = { 'b', 'h', 's', 'd' };
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(length_descriptors)
            / sizeof(length_descriptors[0]);
         ++descriptor_index) {
        size_t immediate_index;

        for (immediate_index = 0u;
             immediate_index < sizeof(immediates) / sizeof(immediates[0]);
             ++immediate_index) {
            int immediate = immediates[immediate_index];
            unsigned encoded = (unsigned)immediate & 63u;
            char expected[96];
            int length;

            if (length_descriptors[descriptor_index].has_source) {
                length = snprintf(expected, sizeof(expected),
                    "%s x7, x13, #%s0x%x",
                    length_names[descriptor_index],
                    immediate < 0 ? "-" : "",
                    immediate < 0 ? (unsigned)-immediate
                                  : (unsigned)immediate);
            } else {
                length = snprintf(expected, sizeof(expected),
                    "%s x7, #%s0x%x", length_names[descriptor_index],
                    immediate < 0 ? "-" : "",
                    immediate < 0 ? (unsigned)-immediate
                                  : (unsigned)immediate);
            }
            EXPECT(length > 0 && (size_t)length < sizeof(expected));
            expect_format(length_word(
                &length_descriptors[descriptor_index], 13u,
                encoded, 7u), expected);
        }
    }
    expect_format(length_word(&length_descriptors[0], 31u, 32u, 31u),
        "addvl sp, sp, #-0x20");
    expect_format(length_word(&length_descriptors[1], 31u, 31u, 31u),
        "addpl sp, sp, #0x1f");
    expect_format(length_word(&length_descriptors[2], 0u, 32u, 31u),
        "rdvl xzr, #-0x20");

    for (descriptor_index = 0u;
         descriptor_index < sizeof(reverse_descriptors)
            / sizeof(reverse_descriptors[0]);
         ++descriptor_index) {
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 0u;
                 size_code <= reverse_descriptors[descriptor_index]
                    .maximum_size;
                 ++size_code) {
                unsigned total_size = q != 0u ? 16u : 8u;
                unsigned count = total_size / (1u << size_code);
                char expected[96];
                int length = snprintf(expected, sizeof(expected),
                    "%s v7.%u%c, v13.%u%c",
                    reverse_names[descriptor_index], count,
                    suffixes[size_code], count, suffixes[size_code]);

                EXPECT(length > 0 && (size_t)length < sizeof(expected));
                expect_format(reverse_word(
                    &reverse_descriptors[descriptor_index], q,
                    size_code, 13u, 7u), expected);
            }
        }
    }

    for (descriptor_index = 0u;
         descriptor_index < sizeof(reduction_descriptors)
            / sizeof(reduction_descriptors[0]);
         ++descriptor_index) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            char expected[96];
            char result_suffix = reduction_descriptors[descriptor_index]
                    .fixed_d_result
                ? 'd' : suffixes[size_code];
            int length;

            if (reduction_descriptors[descriptor_index].rejects_d_source
                && size_code == 3u) {
                continue;
            }
            length = snprintf(expected, sizeof(expected),
                "%s %c7, p3, z13.%c", reduction_names[descriptor_index],
                result_suffix, suffixes[size_code]);
            EXPECT(length > 0 && (size_t)length < sizeof(expected));
            expect_format(reduction_word(
                &reduction_descriptors[descriptor_index], size_code,
                3u, 13u, 7u), expected);
        }
    }
    {
        cdisasm_arm_instruction instruction;
        char text[96];
        static const char expected[] = "ANDV d7, p3, z13.d";
        uint32_t word = reduction_word(
            &reduction_descriptors[8], 3u, 3u, 13u, 7u);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_length_envelopes();
    test_exhaustive_reverse_envelopes();
    test_exhaustive_reduction_envelopes();
    test_feature_profiles();
    test_fixed_bit_neighbors();
    test_endian_dispatch_modes_and_boundaries();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif

    if (failures != 0) {
        fprintf(stderr,
            "%d ARM length/reverse/reduction test(s) failed\n", failures);
        return 1;
    }
    printf("ARM length/reverse/reduction tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=432128, reserved=20480)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
