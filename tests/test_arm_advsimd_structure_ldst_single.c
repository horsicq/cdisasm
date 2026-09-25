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
        UINT64_C(0x0c007000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static void check(unsigned load, unsigned q, unsigned size, unsigned rn,
    unsigned rt)
{
    cdisasm_arm_instruction instruction;
#if !USE_EXTRA_OPCODES
    cdisasm_arm_instruction expected;
#endif
    uint32_t word = UINT32_C(0x0c007000) | (load << 22) | (q << 30)
        | (size << 10) | (rn << 5) | rt;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    uint8_t total_size = q ? 16u : 8u;
    uint8_t element_size = (uint8_t)(1u << size);
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == (load ? CDISASM_ARM_NAME_LD1
                                       : CDISASM_ARM_NAME_ST1));
    EXPECT(instruction.form_id == (load ? 4584u : 4577u));
    EXPECT(instruction.instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_V0 + rt);
    EXPECT(instruction.operand[0].register_list == 1u);
    EXPECT(instruction.operand[0].size == total_size);
    EXPECT(instruction.operand[0].extend_type == element_size);
    EXPECT(instruction.operand[0].scale == total_size / element_size);
    EXPECT(instruction.operand[0].access == (load
        ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ));
    EXPECT(instruction.operand[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[1].base_reg == (rn == 31u
        ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_X0 + rn));
    EXPECT(instruction.operand[1].size == total_size);
    EXPECT(instruction.operand[1].access == (load
        ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE));
#else
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
}

int main(void)
{
    unsigned load, q, size, rn, rt;
    for (load = 0u; load < 2u; ++load)
        for (q = 0u; q < 2u; ++q)
            for (size = 0u; size < 4u; ++size)
                for (rn = 0u; rn < 32u; ++rn)
                    for (rt = 0u; rt < 32u; ++rt)
                        check(load, q, size, rn, rt);
    {
        cdisasm_arm_instruction instruction;
        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(UINT32_C(0x4c4073e2), CDISASM_ARM_CPU_CORTEX_A53,
            &instruction) == 4u);
#else
        EXPECT(decode_word(UINT32_C(0x4c4073e2), CDISASM_ARM_CPU_CORTEX_A53,
            &instruction) == 0u);
#endif
    }
    if (failures != 0) return 1;
    puts("Advanced SIMD single-structure LD1/ST1 tests passed");
    return 0;
}
