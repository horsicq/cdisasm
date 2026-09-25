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
        UINT64_C(0x5e000400), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static unsigned trailing_zeroes(unsigned value)
{
    unsigned result = 0u;
    while (((value >> result) & 1u) == 0u) ++result;
    return result;
}

static void check(unsigned vector, unsigned q, unsigned imm5,
    unsigned rn, unsigned rd)
{
    cdisasm_arm_instruction instruction, expected;
    uint32_t base = vector ? UINT32_C(0x0e000400) : UINT32_C(0x5e000400);
    uint32_t word = base | (q << 30) | (imm5 << 16) | (rn << 5) | rd;
    int allocated = imm5 != 0u;
    unsigned size_code = allocated ? trailing_zeroes(imm5) : 0u;
#if USE_EXTRA_OPCODES
    uint8_t element_size = (uint8_t)(1u << size_code);
#endif

    if (size_code > 3u || (vector && size_code == 3u && q == 0u))
        allocated = 0;
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
    EXPECT(instruction.form_id == (vector ? 5911u : 5741u));
    EXPECT(instruction.instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    EXPECT(instruction.operand_count == 2u);
    if (vector) {
        EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_V0 + rd);
        EXPECT(instruction.operand[0].size == (q ? 16u : 8u));
        EXPECT(instruction.operand[0].extend_type == element_size);
    } else {
        static const cdisasm_arm_reg_id first[4] = {
            CDISASM_ARM_REG_B0, CDISASM_ARM_REG_H0,
            CDISASM_ARM_REG_S0, CDISASM_ARM_REG_D0
        };
        EXPECT(instruction.operand[0].reg == first[size_code] + rd);
        EXPECT(instruction.operand[0].size == element_size);
        EXPECT(instruction.operand[0].extend_type == element_size);
        EXPECT(instruction.operand[0].scale == 1u);
    }
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_V0 + rn);
    EXPECT(instruction.operand[1].size == 16u);
    EXPECT(instruction.operand[1].extend_type == element_size);
    EXPECT(instruction.operand[1].flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    EXPECT(instruction.operand[1].imm == (imm5 >> (size_code + 1u)));
    EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
#else
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
}

static void test_complete_envelopes(void)
{
    unsigned vector, q, imm5, rn, rd;
    for (vector = 0u; vector < 2u; ++vector)
        for (q = 0u; q < (vector ? 2u : 1u); ++q)
            for (imm5 = 0u; imm5 < 32u; ++imm5)
                for (rn = 0u; rn < 32u; ++rn)
                    for (rd = 0u; rd < 32u; ++rd)
                        check(vector, q, imm5, rn, rd);
}

static void test_profile(void)
{
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(UINT32_C(0x5e1f0420), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 4u);
#else
    EXPECT(decode_word(UINT32_C(0x5e1f0420), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
#endif
}

int main(void)
{
    test_complete_envelopes();
    test_profile();
    if (failures != 0) return 1;
    puts("Advanced SIMD DUP element tests passed");
    return 0;
}
