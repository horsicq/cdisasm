#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 24) fprintf(stderr, \
    "%s:%d: expectation failed: %s\n", __FILE__, __LINE__, #c); \
    ++failures; } } while (0)

struct operation { uint32_t base; cdisasm_arm_name_id name;
    cdisasm_arm_form_id form; unsigned max_size; int wide; };
static const struct operation operations[4] = {
    { UINT32_C(0x0e002c00), CDISASM_ARM_NAME_SMOV, 5913, 1u, 0 },
    { UINT32_C(0x0e003c00), CDISASM_ARM_NAME_UMOV, 5914, 2u, 0 },
    { UINT32_C(0x4e002c00), CDISASM_ARM_NAME_SMOV, 5916, 2u, 1 },
    { UINT32_C(0x4e003c00), CDISASM_ARM_NAME_UMOV, 5917, 3u, 1 }
};

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, bytes, 4u,
        UINT64_C(0x0e002c00), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static unsigned ctz5(unsigned value)
{
    unsigned n = 0u;
    while (((value >> n) & 1u) == 0u) ++n;
    return n;
}

static void check(unsigned op, unsigned imm5, unsigned rn, unsigned rd)
{
    const struct operation *operation = &operations[op];
    cdisasm_arm_instruction instruction, expected;
    uint32_t word = operation->base | (imm5 << 16) | (rn << 5) | rd;
    unsigned size_code = imm5 ? ctz5(imm5) : 0u;
    int allocated = imm5 != 0u && size_code <= operation->max_size;
    if (op == 3u) allocated = imm5 == 8u || imm5 == 24u;
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
        cdisasm_arm_reg_id first = operation->wide
            ? CDISASM_ARM_REG_X0 : CDISASM_ARM_REG_W0;
        cdisasm_arm_reg_id zr = operation->wide
            ? CDISASM_ARM_REG_XZR : CDISASM_ARM_REG_WZR;
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
        EXPECT(instruction.name_id == operation->name);
        EXPECT(instruction.form_id == operation->form);
        EXPECT(instruction.instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.operand[0].reg == (rd == 31u ? zr : first + rd));
        EXPECT(instruction.operand[0].size == (operation->wide ? 8u : 4u));
        EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_V0 + rn);
        EXPECT(instruction.operand[1].size == 16u);
        EXPECT(instruction.operand[1].extend_type == element_size);
        EXPECT(instruction.operand[1].flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
        EXPECT(instruction.operand[1].imm == (imm5 >> (size_code + 1u)));
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
    unsigned op, imm5, rn, rd;
    for (op = 0u; op < 4u; ++op)
        for (imm5 = 0u; imm5 < 32u; ++imm5)
            for (rn = 0u; rn < 32u; ++rn)
                for (rd = 0u; rd < 32u; ++rd)
                    check(op, imm5, rn, rd);
    {
        cdisasm_arm_instruction instruction;
        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(UINT32_C(0x4e183e72), CDISASM_ARM_CPU_CORTEX_A53,
            &instruction) == 4u);
#else
        EXPECT(decode_word(UINT32_C(0x4e183e72), CDISASM_ARM_CPU_CORTEX_A53,
            &instruction) == 0u);
#endif
    }
    if (failures != 0) return 1;
    puts("Advanced SIMD lane-to-GPR tests passed");
    return 0;
}
