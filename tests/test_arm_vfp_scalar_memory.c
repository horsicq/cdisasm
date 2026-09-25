#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "%s:%d: expectation failed: %s\n", \
            __FILE__, __LINE__, #expr); \
        ++failures; \
    } \
} while (0)

static uint32_t decode(uint32_t word, cdisasm_arm_mode mode,
    cdisasm_arm_instruction *out)
{
    uint8_t code[4] = {
        (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24)
    };

    memset(out, 0, sizeof(*out));
    return cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, mode, code, sizeof(code),
        UINT64_C(0x1000), CDISASM_ARM_DECODE_OPTION_NONE, out);
}

static void check(cdisasm_arm_instruction *instruction,
    cdisasm_arm_name_id name, cdisasm_arm_reg_id reg, uint8_t size,
    cdisasm_operand_access access, cdisasm_operand_access memory_access)
{
    const cdisasm_arm_operand *register_operand = &instruction->operand[0];
    const cdisasm_arm_operand *memory = &instruction->operand[1];

    EXPECT(instruction->name_id == name);
    EXPECT(instruction->opcode_size == 4u);
    EXPECT(instruction->operand_count == 2u);
    EXPECT((instruction->instruction_flags
        & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) != 0u);
    EXPECT(register_operand->type == CDISASM_OPERAND_REGISTER
        && register_operand->reg == reg);
    EXPECT(register_operand->size == size
        && register_operand->access == access);
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY && memory->size == size);
    EXPECT(memory->base_reg == CDISASM_ARM_REG_R0);
    EXPECT(memory->access == memory_access);
    EXPECT(memory->imm == (uint64_t)-(int64_t)16);
    EXPECT((memory->flags & CDISASM_OPERAND_FLAG_SIGNED) != 0u);
    EXPECT((memory->flags & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) != 0u);
#if USE_DISASM_FORMAT
    {
        char text[128];
        EXPECT(cdisasm_arm_format(instruction, 0u, text, sizeof(text)) > 0u);
    }
#endif
}

int main(void)
{
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    /* A32 VLDR/VSTR S and D forms, positive displacement. */
    EXPECT(decode(UINT32_C(0xed100a04), CDISASM_ARM_MODE_A32,
        &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_VLDR, CDISASM_ARM_REG_S0, 4u,
        CDISASM_OPERAND_ACCESS_WRITE, CDISASM_OPERAND_ACCESS_READ);
    EXPECT(decode(UINT32_C(0xed000b04), CDISASM_ARM_MODE_A32,
        &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_VSTR, CDISASM_ARM_REG_D0, 8u,
        CDISASM_OPERAND_ACCESS_READ, CDISASM_OPERAND_ACCESS_WRITE);

    /* T32 transports retain the same canonical fields but use AL condition. */
    EXPECT(decode(UINT32_C(0x3affed97), CDISASM_ARM_MODE_T32,
        &instruction) == 4u);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_T32);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_VLDR);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(decode(UINT32_C(0x8bffed19), CDISASM_ARM_MODE_T32,
        &instruction) == 4u);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_T32);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_VLDR);
    EXPECT(instruction.operand_count == 2u);

    /* Half precision is ARMv8+ and remains represented as H registers. */
    EXPECT(decode(UINT32_C(0xed100904), CDISASM_ARM_MODE_A32,
        &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_VLDR);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_H0);
    EXPECT(instruction.operand[0].size == 2u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
#else
    EXPECT(decode(UINT32_C(0xed100a04), CDISASM_ARM_MODE_A32,
        &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    return failures == 0 ? 0 : 1;
}
