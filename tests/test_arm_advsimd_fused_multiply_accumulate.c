#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

typedef struct fused_case {
    cdisasm_arm_mode mode;
    uint8_t bytes[4];
    cdisasm_arm_name_id name;
    cdisasm_arm_reg_id vd;
    cdisasm_arm_reg_id vn;
    cdisasm_arm_reg_id vm;
    uint8_t vector_size;
} fused_case;

static const fused_case cases[] = {
    { CDISASM_ARM_MODE_A32, {0x14,0x2c,0x03,0xf2}, CDISASM_ARM_NAME_VFMA,
      CDISASM_ARM_REG_D2, CDISASM_ARM_REG_D3, CDISASM_ARM_REG_D4, 8 },
    { CDISASM_ARM_MODE_A32, {0x5a,0x6c,0x08,0xf2}, CDISASM_ARM_NAME_VFMA,
      CDISASM_ARM_REG_Q3, CDISASM_ARM_REG_Q4, CDISASM_ARM_REG_Q5, 16 },
    { CDISASM_ARM_MODE_A32, {0x18,0x6c,0x27,0xf2}, CDISASM_ARM_NAME_VFMS,
      CDISASM_ARM_REG_D6, CDISASM_ARM_REG_D7, CDISASM_ARM_REG_D8, 8 },
    { CDISASM_ARM_MODE_A32, {0xf6,0x2c,0x64,0xf2}, CDISASM_ARM_NAME_VFMS,
      CDISASM_ARM_REG_Q9, CDISASM_ARM_REG_Q10, CDISASM_ARM_REG_Q11, 16 },
    { CDISASM_ARM_MODE_T32, {0x0b,0xef,0x1c,0xac}, CDISASM_ARM_NAME_VFMA,
      CDISASM_ARM_REG_D10, CDISASM_ARM_REG_D11, CDISASM_ARM_REG_D12, 8 },
    { CDISASM_ARM_MODE_T32, {0x0e,0xef,0x70,0xcc}, CDISASM_ARM_NAME_VFMA,
      CDISASM_ARM_REG_Q6, CDISASM_ARM_REG_Q7, CDISASM_ARM_REG_Q8, 16 },
    { CDISASM_ARM_MODE_T32, {0x2f,0xef,0x30,0xec}, CDISASM_ARM_NAME_VFMS,
      CDISASM_ARM_REG_D14, CDISASM_ARM_REG_D15, CDISASM_ARM_REG_D16, 8 },
    { CDISASM_ARM_MODE_T32, {0x66,0xef,0xf8,0x4c}, CDISASM_ARM_NAME_VFMS,
      CDISASM_ARM_REG_Q10, CDISASM_ARM_REG_Q11, CDISASM_ARM_REG_Q12, 16 }
};

static int failures;
#define EXPECT(x) do { if (!(x)) { ++failures; fprintf(stderr, \
    "%s:%d: %s\n", __FILE__, __LINE__, #x); } } while (0)

#if USE_EXTRA_OPCODES
static int operand_matches(const cdisasm_arm_operand *operand,
                           cdisasm_arm_reg_id reg, uint8_t vector_size,
                           cdisasm_operand_access access)
{
    return operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg == reg && operand->size == vector_size
        && operand->extend_type == (cdisasm_arm_extend_type)4u
        && operand->scale == vector_size / 4u && operand->access == access;
}
#endif

int main(void)
{
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, cases[i].mode,
            cases[i].bytes, 4u, UINT64_C(0x180000),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
        EXPECT(instruction.name_id == cases[i].name);
        EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
        EXPECT(instruction.instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
        EXPECT(instruction.operand_count == 3u);
        EXPECT(operand_matches(&instruction.operand[0], cases[i].vd,
            cases[i].vector_size, CDISASM_OPERAND_ACCESS_READ_WRITE));
        EXPECT(operand_matches(&instruction.operand[1], cases[i].vn,
            cases[i].vector_size, CDISASM_OPERAND_ACCESS_READ));
        EXPECT(operand_matches(&instruction.operand[2], cases[i].vm,
            cases[i].vector_size, CDISASM_OPERAND_ACCESS_READ));
#else
        cdisasm_arm_instruction expected;
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        EXPECT(decoded == 0u);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
    }
    if (failures != 0) {
        fprintf(stderr, "%d fused multiply-accumulate failure(s)\n", failures);
        return 1;
    }
    puts("ARM Advanced SIMD VFMA/VFMS tests passed");
    return 0;
}
