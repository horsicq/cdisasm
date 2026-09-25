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
        UINT64_C(0x0e000c00), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static void check(unsigned q, unsigned imm5, unsigned rn, unsigned rd)
{
    cdisasm_arm_instruction instruction, expected;
    uint32_t word = UINT32_C(0x0e000c00) | (q << 30)
        | (imm5 << 16) | (rn << 5) | rd;
    int allocated = imm5 == 1u || imm5 == 2u || imm5 == 4u
        || (q && imm5 == 8u);
#if USE_EXTRA_OPCODES
    unsigned size_code = imm5 == 1u ? 0u : imm5 == 2u ? 1u
        : imm5 == 4u ? 2u : 3u;
    uint8_t element_size = (uint8_t)(1u << size_code);
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    if (!allocated) {
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_INVALID_INSTRUCTION;
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
        return;
    }
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_DUP);
    EXPECT(instruction.form_id == 5912u);
    EXPECT(instruction.instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_V0 + rd);
    EXPECT(instruction.operand[0].size == (q ? 16u : 8u));
    EXPECT(instruction.operand[0].extend_type == element_size);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].reg == (rn == 31u
        ? (element_size == 8u ? CDISASM_ARM_REG_XZR : CDISASM_ARM_REG_WZR)
        : (element_size == 8u ? CDISASM_ARM_REG_X0 : CDISASM_ARM_REG_W0) + rn));
    EXPECT(instruction.operand[1].size == (element_size == 8u ? 8u : 4u));
    EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
#else
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
}

int main(void)
{
    unsigned q, imm5, rn, rd;
    for (q = 0u; q < 2u; ++q)
        for (imm5 = 0u; imm5 < 32u; ++imm5)
            for (rn = 0u; rn < 32u; ++rn)
                for (rd = 0u; rd < 32u; ++rd)
                    check(q, imm5, rn, rd);
    {
        cdisasm_arm_instruction instruction;
        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(UINT32_C(0x4e080dac), CDISASM_ARM_CPU_CORTEX_A53,
            &instruction) == 4u);
#else
        EXPECT(decode_word(UINT32_C(0x4e080dac), CDISASM_ARM_CPU_CORTEX_A53,
            &instruction) == 0u);
#endif
    }
    if (failures != 0) return 1;
    puts("Advanced SIMD DUP GPR tests passed");
    return 0;
}
