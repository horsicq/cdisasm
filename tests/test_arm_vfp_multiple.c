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

static uint32_t decode_a32(uint32_t word, cdisasm_arm_instruction *out)
{
    uint8_t code[4] = {
        (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24)
    };

    memset(out, 0, sizeof(*out));
    return cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32,
        code, sizeof(code), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, out);
}

static uint32_t decode_t32(uint16_t first, uint16_t second,
    cdisasm_arm_instruction *out)
{
    uint8_t code[4] = {
        (uint8_t)first, (uint8_t)(first >> 8),
        (uint8_t)second, (uint8_t)(second >> 8)
    };

    memset(out, 0, sizeof(*out));
    return cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32,
        code, sizeof(code), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, out);
}

static void check(
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_name_id name,
    cdisasm_arm_reg_id first_reg,
    unsigned count,
    unsigned element_size,
    uint32_t addressing_flags)
{
    const cdisasm_arm_operand *base = &instruction->operand[0];
    const cdisasm_arm_operand *list = &instruction->operand[1];

    EXPECT(instruction->opcode_size == 4u);
    EXPECT(instruction->name_id == name);
    EXPECT(instruction->condition == CDISASM_ARM_CONDITION_AL);
    EXPECT((instruction->instruction_flags
        & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) != 0u);
    EXPECT((instruction->instruction_flags
        & (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT))
        == addressing_flags);
    EXPECT(instruction->operand_count == 2u);
    EXPECT(base->type == CDISASM_OPERAND_REGISTER);
    EXPECT(base->reg >= CDISASM_ARM_REG_R0
        && base->reg <= CDISASM_ARM_REG_R12);
    EXPECT(list->type == CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST);
    EXPECT(list->reg == first_reg);
    EXPECT(list->register_list == count);
    EXPECT(list->size == element_size);
    EXPECT(list->extend_type == element_size);
    EXPECT(list->scale == 1u);
    EXPECT(list->access == (name == CDISASM_ARM_NAME_VLDM
            || name == CDISASM_ARM_NAME_VLDMDB
        ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ));
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
    EXPECT(decode_a32(UINT32_C(0xeca00a04), &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_VSTM,
        CDISASM_ARM_REG_S0, 4u, 4u,
        CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT);

    EXPECT(decode_a32(UINT32_C(0xed214b04), &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_VSTMDB,
        CDISASM_ARM_REG_D4, 2u, 8u,
        CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT);

    EXPECT(decode_a32(UINT32_C(0xec928b08), &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_VLDM,
        CDISASM_ARM_REG_D8, 4u, 8u,
        CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT);

    EXPECT(decode_a32(UINT32_C(0xed336a04), &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_VLDMDB,
        CDISASM_ARM_REG_S12, 4u, 4u,
        CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT);

    EXPECT(decode_t32(UINT16_C(0xeca0), UINT16_C(0x0a04),
        &instruction) == 4u);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_T32);
    check(&instruction, CDISASM_ARM_NAME_VSTM,
        CDISASM_ARM_REG_S0, 4u, 4u,
        CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT);

    EXPECT(decode_t32(UINT16_C(0xed21), UINT16_C(0x4b04),
        &instruction) == 4u);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_T32);
    check(&instruction, CDISASM_ARM_NAME_VSTMDB,
        CDISASM_ARM_REG_D4, 2u, 8u,
        CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT);
#else
    EXPECT(decode_a32(UINT32_C(0xeca00a04), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    return failures == 0 ? 0 : 1;
}
