#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 24) fprintf(stderr, \
    "%s:%d: expectation failed: %s\n", __FILE__, __LINE__, #c); \
    ++failures; } } while (0)

struct operation {
    uint32_t base;
    cdisasm_arm_name_id name;
    cdisasm_arm_form_id form;
};

static const struct operation scalar_operations[2] = {
    { UINT32_C(0x5e20fc00), CDISASM_ARM_NAME_FRECPS, 5835 },
    { UINT32_C(0x5ea0fc00), CDISASM_ARM_NAME_FRSQRTS, 5836 }
};
static const struct operation half_operations[2] = {
    { UINT32_C(0x0e403c00), CDISASM_ARM_NAME_FRECPS, 5925 },
    { UINT32_C(0x0ec03c00), CDISASM_ARM_NAME_FRSQRTS, 5931 }
};
static const struct operation vector_operations[2] = {
    { UINT32_C(0x0e20fc00), CDISASM_ARM_NAME_FRECPS, 6144 },
    { UINT32_C(0x0ea0fc00), CDISASM_ARM_NAME_FRSQRTS, 6153 }
};

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, bytes, 4u,
        UINT64_C(0x5e20fc00), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static void check_word(uint32_t word, const struct operation *operation,
    int vector, uint8_t total_size, uint8_t element_size,
    unsigned rd, unsigned rn, unsigned rm)
{
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == operation->name);
    EXPECT(instruction.form_id == operation->form);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | (vector ? CDISASM_ARM_INSTRUCTION_FLAG_SIMD : 0u)));
    EXPECT(instruction.operand_count == 3u);
    if (vector) {
        EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_V0 + rd);
        EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_V0 + rn);
        EXPECT(instruction.operand[2].reg == CDISASM_ARM_REG_V0 + rm);
        EXPECT(instruction.operand[0].extend_type == element_size);
        EXPECT(instruction.operand[1].extend_type == element_size);
        EXPECT(instruction.operand[2].extend_type == element_size);
    } else {
        cdisasm_arm_reg_id first = element_size == 8u
            ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_S0;
        EXPECT(instruction.operand[0].reg == first + rd);
        EXPECT(instruction.operand[1].reg == first + rn);
        EXPECT(instruction.operand[2].reg == first + rm);
    }
    EXPECT(instruction.operand[0].size == total_size);
    EXPECT(instruction.operand[1].size == total_size);
    EXPECT(instruction.operand[2].size == total_size);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#else
    {
        cdisasm_arm_instruction expected;
        (void)operation;
        (void)vector;
        (void)total_size;
        (void)element_size;
        (void)rd;
        (void)rn;
        (void)rm;
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
    }
#endif
}

static void test_complete_domain(void)
{
    unsigned operation, arrangement, rm, rn, rd;
    for (operation = 0u; operation < 2u; ++operation) {
        for (arrangement = 0u; arrangement < 2u; ++arrangement) {
            uint32_t bit = arrangement ? UINT32_C(0x00400000) : 0u;
            uint8_t size = arrangement ? 8u : 4u;
            for (rm = 0u; rm < 32u; ++rm)
                for (rn = 0u; rn < 32u; ++rn)
                    for (rd = 0u; rd < 32u; ++rd)
                        check_word(scalar_operations[operation].base | bit
                            | (rm << 16) | (rn << 5) | rd,
                            &scalar_operations[operation], 0, size, size,
                            rd, rn, rm);
        }
        for (arrangement = 0u; arrangement < 2u; ++arrangement) {
            uint32_t bit = arrangement ? UINT32_C(0x40000000) : 0u;
            uint8_t total = arrangement ? 16u : 8u;
            for (rm = 0u; rm < 32u; ++rm)
                for (rn = 0u; rn < 32u; ++rn)
                    for (rd = 0u; rd < 32u; ++rd)
                        check_word(half_operations[operation].base | bit
                            | (rm << 16) | (rn << 5) | rd,
                            &half_operations[operation], 1, total, 2u,
                            rd, rn, rm);
        }
        for (arrangement = 0u; arrangement < 3u; ++arrangement) {
            uint32_t bits = arrangement == 0u ? 0u
                : arrangement == 1u ? UINT32_C(0x40000000)
                                    : UINT32_C(0x40400000);
            uint8_t total = arrangement == 0u ? 8u : 16u;
            uint8_t element = arrangement == 2u ? 8u : 4u;
            for (rm = 0u; rm < 32u; ++rm)
                for (rn = 0u; rn < 32u; ++rn)
                    for (rd = 0u; rd < 32u; ++rd)
                        check_word(vector_operations[operation].base | bits
                            | (rm << 16) | (rn << 5) | rd,
                            &vector_operations[operation], 1, total, element,
                            rd, rn, rm);
        }
    }
}

static void test_legality_and_profiles(void)
{
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(UINT32_C(0x0e60fc00), CDISASM_ARM_CPU_ANY,
        &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    EXPECT(decode_word(UINT32_C(0x0e403c00), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    EXPECT(decode_word(UINT32_C(0x0e403c00), CDISASM_ARM_CPU_APPLE_A11,
        &instruction) == 4u);
    EXPECT(decode_word(UINT32_C(0x5e20fc00), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 4u);
#else
    EXPECT(decode_word(UINT32_C(0x0e403c00), CDISASM_ARM_CPU_ANY,
        &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

int main(void)
{
    test_complete_domain();
    test_legality_and_profiles();
    if (failures != 0) return 1;
    puts("Advanced SIMD floating reciprocal-step tests passed");
    return 0;
}
