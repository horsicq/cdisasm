#include "cdisasm/cdisasm_arm.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "expectation failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expr); \
        ++failures; \
    } \
} while (0)

static uint32_t decode_word(uint32_t word, cdisasm_arm_instruction *out)
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

static void check_structure(
    uint32_t word,
    cdisasm_arm_name_id name,
    unsigned count,
    unsigned element_size,
    cdisasm_operand_access list_access,
    cdisasm_operand_access memory_access)
{
    cdisasm_arm_instruction instruction;
    uint32_t size = decode_word(word, &instruction);
    const cdisasm_arm_operand *list = &instruction.operand[0];
    const cdisasm_arm_operand *memory = &instruction.operand[1];
    EXPECT(size == 4u);
    EXPECT(instruction.name_id == name);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_A32);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT((instruction.instruction_flags
        & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) != 0u);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(list->type == CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST);
    EXPECT(list->reg == CDISASM_ARM_REG_D0);
    EXPECT(list->register_list == count);
    EXPECT(list->size == 8u);
    EXPECT(list->extend_type == element_size);
    EXPECT(list->scale == 8u / element_size);
    EXPECT(list->access == list_access);
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
    EXPECT(memory->base_reg == CDISASM_ARM_REG_R0);
    EXPECT(memory->index_reg == CDISASM_ARM_REG_NONE);
    EXPECT(memory->size == element_size);
    EXPECT(memory->access == memory_access);
}

int main(void)
{
#if USE_EXTRA_OPCODES
    check_structure(
        UINT32_C(0xf420070f), CDISASM_ARM_NAME_VLD1, 1u, 1u,
        CDISASM_OPERAND_ACCESS_WRITE, CDISASM_OPERAND_ACCESS_READ);
    check_structure(
        UINT32_C(0xf4200a4f), CDISASM_ARM_NAME_VLD1, 2u, 2u,
        CDISASM_OPERAND_ACCESS_WRITE, CDISASM_OPERAND_ACCESS_READ);
    check_structure(
        UINT32_C(0xf400080f), CDISASM_ARM_NAME_VST2, 2u, 1u,
        CDISASM_OPERAND_ACCESS_READ, CDISASM_OPERAND_ACCESS_WRITE);
    check_structure(
        UINT32_C(0xf420040f), CDISASM_ARM_NAME_VLD3, 3u, 1u,
        CDISASM_OPERAND_ACCESS_WRITE, CDISASM_OPERAND_ACCESS_READ);
    check_structure(
        UINT32_C(0xf400000f), CDISASM_ARM_NAME_VST4, 4u, 1u,
        CDISASM_OPERAND_ACCESS_READ, CDISASM_OPERAND_ACCESS_WRITE);
    check_structure(
        UINT32_C(0xf4a00c0f), CDISASM_ARM_NAME_VLD1, 1u, 8u,
        CDISASM_OPERAND_ACCESS_WRITE, CDISASM_OPERAND_ACCESS_READ);

    {
        cdisasm_arm_instruction instruction;

        EXPECT(decode_word(UINT32_C(0xf4a0080f), &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_VLD1);
        EXPECT(instruction.operand[0].type
            == CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST);
        EXPECT(instruction.operand[0].register_list == 1u);
        EXPECT(instruction.operand[0].extend_type == 4u);
        EXPECT(instruction.operand[0].flags
            == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
        EXPECT(instruction.operand[0].imm == 0u);

        EXPECT(decode_word(UINT32_C(0xf4a0088f), &instruction) == 4u);
        EXPECT(instruction.operand[0].imm == 1u);
    }

    {
        cdisasm_arm_instruction instruction;

        EXPECT(decode_word(UINT32_C(0xf420070d), &instruction) == 4u);
        EXPECT((instruction.instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK))
            == (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK));
        EXPECT(instruction.operand[1].imm == 0u);
        EXPECT(instruction.operand[1].flags == 0u);

        EXPECT(decode_word(UINT32_C(0xf4000701), &instruction) == 4u);
        EXPECT(instruction.operand[1].index_reg == CDISASM_ARM_REG_R1);
    }
#endif
    return failures == 0 ? 0 : 1;
}
