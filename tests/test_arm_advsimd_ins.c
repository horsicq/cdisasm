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
        UINT64_C(0x4e001c00), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static unsigned ctz5(unsigned value)
{
    unsigned n = 0u;
    while (((value >> n) & 1u) == 0u) ++n;
    return n;
}

static void check(unsigned vector_source, unsigned imm5, unsigned imm4,
    unsigned rn, unsigned rd)
{
    cdisasm_arm_instruction instruction, expected;
    uint32_t base = vector_source ? UINT32_C(0x6e000400)
                                  : UINT32_C(0x4e001c00);
    uint32_t word = base | (imm5 << 16) | (imm4 << 11) | (rn << 5) | rd;
    unsigned size_code = imm5 ? ctz5(imm5) : 0u;
    int allocated = imm5 != 0u && size_code <= 3u
        && (!vector_source || (imm4 & ((1u << size_code) - 1u)) == 0u);
    memset(&instruction, 0xa5, sizeof(instruction));
    if (!allocated) {
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_INVALID_INSTRUCTION;
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
        return;
    }
#if USE_EXTRA_OPCODES
    {
        uint8_t element_size = (uint8_t)(1u << size_code);
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_INS);
        EXPECT(instruction.form_id == (vector_source ? 5918u : 5915u));
        EXPECT(instruction.instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_V0 + rd);
        EXPECT(instruction.operand[0].size == 16u);
        EXPECT(instruction.operand[0].extend_type == element_size);
        EXPECT(instruction.operand[0].flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
        EXPECT(instruction.operand[0].imm == (imm5 >> (size_code + 1u)));
        EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_READ_WRITE);
        if (vector_source) {
            EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_V0 + rn);
            EXPECT(instruction.operand[1].size == 16u);
            EXPECT(instruction.operand[1].extend_type == element_size);
            EXPECT(instruction.operand[1].flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
            EXPECT(instruction.operand[1].imm == (imm4 >> size_code));
        } else {
            cdisasm_arm_reg_id first = element_size == 8u
                ? CDISASM_ARM_REG_X0 : CDISASM_ARM_REG_W0;
            cdisasm_arm_reg_id zr = element_size == 8u
                ? CDISASM_ARM_REG_XZR : CDISASM_ARM_REG_WZR;
            EXPECT(instruction.operand[1].reg == (rn == 31u ? zr : first + rn));
            EXPECT(instruction.operand[1].size == (element_size == 8u ? 8u : 4u));
        }
        EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    }
#else
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
}

int main(void)
{
    unsigned vector_source, imm5, imm4, rn, rd;
    for (vector_source = 0u; vector_source < 2u; ++vector_source)
        for (imm5 = 0u; imm5 < 32u; ++imm5)
            for (imm4 = 0u; imm4 < (vector_source ? 16u : 1u); ++imm4)
                for (rn = 0u; rn < 32u; ++rn)
                    for (rd = 0u; rd < 32u; ++rd)
                        check(vector_source, imm5, imm4, rn, rd);
    if (failures != 0) return 1;
    puts("Advanced SIMD INS tests passed");
    return 0;
}
