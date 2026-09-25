#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 24) fprintf(stderr, \
    "%s:%d: expectation failed: %s\n", __FILE__, __LINE__, #c); \
    ++failures; } } while (0)

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, bytes, 4u,
        UINT64_C(0x7e616800), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static void check_scalar(unsigned rn, unsigned rd)
{
    cdisasm_arm_instruction instruction;
    uint32_t word = UINT32_C(0x7e616800) | (rn << 5) | rd;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_FCVTXN);
    EXPECT(instruction.form_id == 5798u);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_S0 + rd);
    EXPECT(instruction.operand[0].size == 4u);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_D0 + rn);
    EXPECT(instruction.operand[1].size == 8u);
    EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void check_vector(unsigned q, unsigned rn, unsigned rd)
{
    cdisasm_arm_instruction instruction;
    uint32_t word = UINT32_C(0x2e616800) | (q << 30) | (rn << 5) | rd;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_FCVTXN);
    EXPECT(instruction.form_id == 6050u);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_V0 + rd);
    EXPECT(instruction.operand[0].size == (q ? 16u : 8u));
    EXPECT(instruction.operand[0].extend_type == 4u);
    EXPECT(instruction.operand[0].access == (q
        ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_V0 + rn);
    EXPECT(instruction.operand[1].size == 16u);
    EXPECT(instruction.operand[1].extend_type == 8u);
    EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_complete_domain(void)
{
    unsigned q, rn, rd;
    for (rn = 0u; rn < 32u; ++rn) {
        for (rd = 0u; rd < 32u; ++rd) {
            check_scalar(rn, rd);
            for (q = 0u; q < 2u; ++q) check_vector(q, rn, rd);
        }
    }
}

static void test_profile(void)
{
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(UINT32_C(0x7e616820), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 4u);
    EXPECT(decode_word(UINT32_C(0x6e6168a4), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 4u);
#else
    EXPECT(decode_word(UINT32_C(0x7e616820), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
#endif
}

int main(void)
{
    test_complete_domain();
    test_profile();
    if (failures != 0) return 1;
    puts("Advanced SIMD FCVTXN tests passed");
    return 0;
}
