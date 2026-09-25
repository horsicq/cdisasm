#include "cdisasm/cdisasm.h"

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
        code, sizeof(code), UINT64_C(0x2000),
        CDISASM_ARM_DECODE_OPTION_NONE, out);
}

static void check(
    const cdisasm_arm_instruction *instruction,
    cdisasm_arm_name_id name,
    cdisasm_arm_form_id form,
    uint8_t memory_size,
    cdisasm_operand_access memory_access)
{
    const cdisasm_arm_operand *selectors = &instruction->operand[0];
    const cdisasm_arm_operand *memory = &instruction->operand[1];

    EXPECT(instruction->opcode_size == 4u);
    EXPECT(instruction->name_id == name);
    EXPECT(instruction->form_id == form);
    EXPECT(instruction->operand_count == 2u);
    EXPECT(selectors->type == CDISASM_OPERAND_IMMEDIATE);
    /* The fixed encoding used by this test spells p14, c5. */
    EXPECT(selectors->imm == UINT64_C(0x5e));
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
    EXPECT(memory->base_reg >= CDISASM_ARM_REG_R0
        && memory->base_reg <= CDISASM_ARM_REG_R12);
    EXPECT(memory->size == memory_size);
    EXPECT(memory->access == memory_access);
}

static void check_legacy_vfp(
    const cdisasm_arm_instruction *instruction,
    cdisasm_arm_name_id name,
    cdisasm_arm_form_id form,
    cdisasm_arm_reg_id first,
    unsigned count,
    cdisasm_operand_access access)
{
    const cdisasm_arm_operand *base = &instruction->operand[0];
    const cdisasm_arm_operand *list = &instruction->operand[1];

    EXPECT(instruction->name_id == name);
    EXPECT(instruction->form_id == form);
    EXPECT(instruction->operand_count == 2u);
    EXPECT((instruction->instruction_flags
        & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) != 0u);
    EXPECT(base->type == CDISASM_OPERAND_REGISTER);
    EXPECT(list->type == CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST);
    EXPECT(list->reg == first);
    EXPECT(list->register_list == count);
    EXPECT(list->size == 8u);
    EXPECT(list->access == access);
}

int main(void)
{
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    /* A32 STC offset, post-index, pre-index, and unindexed. */
    EXPECT(decode_a32(UINT32_C(0x0d805e05), &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_STC, UINT16_C(521), 4u,
        CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT((instruction.instruction_flags
        & (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT))
        == (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT));

    EXPECT(decode_a32(UINT32_C(0x0c225e06), &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_STC, UINT16_C(522), 4u,
        CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT((instruction.instruction_flags
        & (CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK))
        == (CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK));

    EXPECT(decode_a32(UINT32_C(0x0d235e07), &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_STC, UINT16_C(523), 4u,
        CDISASM_OPERAND_ACCESS_WRITE);

    EXPECT(decode_a32(UINT32_C(0x0c845e00), &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_STC, UINT16_C(524), 4u,
        CDISASM_OPERAND_ACCESS_WRITE);

    /* A32 LDC immediate forms plus the long literal form. */
    EXPECT(decode_a32(UINT32_C(0x0d115e08), &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_LDC, UINT16_C(525), 4u,
        CDISASM_OPERAND_ACCESS_READ);
    EXPECT(decode_a32(UINT32_C(0x0c325e09), &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_LDC, UINT16_C(526), 4u,
        CDISASM_OPERAND_ACCESS_READ);
    EXPECT(decode_a32(UINT32_C(0x0d345e0a), &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_LDC, UINT16_C(527), 4u,
        CDISASM_OPERAND_ACCESS_READ);
    EXPECT(decode_a32(UINT32_C(0x0c965e00), &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_LDC, UINT16_C(528), 4u,
        CDISASM_OPERAND_ACCESS_READ);
    EXPECT(decode_a32(UINT32_C(0x0c1f5e04), &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDC);
    EXPECT(instruction.form_id == UINT16_C(520));
    EXPECT(instruction.operand[1].base_reg == CDISASM_ARM_REG_R15);
    EXPECT(instruction.operand[1].size == 8u);
    EXPECT((instruction.operand[1].flags
        & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0u);

    EXPECT(decode_a32(UINT32_C(0xed200b05), &instruction) == 4u);
    check_legacy_vfp(&instruction, CDISASM_ARM_NAME_FSTMDBX,
        UINT16_C(503), CDISASM_ARM_REG_D0, 2u,
        CDISASM_OPERAND_ACCESS_READ);
    EXPECT((instruction.instruction_flags
        & (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT))
        == (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT));

    EXPECT(decode_a32(UINT32_C(0xec812b05), &instruction) == 4u);
    check_legacy_vfp(&instruction, CDISASM_ARM_NAME_FSTMIAX,
        UINT16_C(504), CDISASM_ARM_REG_D2, 2u,
        CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_a32(UINT32_C(0xed324b05), &instruction) == 4u);
    check_legacy_vfp(&instruction, CDISASM_ARM_NAME_FLDMDBX,
        UINT16_C(509), CDISASM_ARM_REG_D4, 2u,
        CDISASM_OPERAND_ACCESS_WRITE);

    EXPECT(decode_a32(UINT32_C(0xec936b05), &instruction) == 4u);
    check_legacy_vfp(&instruction, CDISASM_ARM_NAME_FLDMIAX,
        UINT16_C(510), CDISASM_ARM_REG_D6, 2u,
        CDISASM_OPERAND_ACCESS_WRITE);

    /* Thumb-2 carries the same fields in a swapped halfword transport. */
    EXPECT(decode_t32(UINT16_C(0xed00), UINT16_C(0x5e05),
        &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_STC, UINT16_C(1506), 4u,
        CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_T32);

    EXPECT(decode_t32(UINT16_C(0xed10), UINT16_C(0x5e08),
        &instruction) == 4u);
    check(&instruction, CDISASM_ARM_NAME_LDC, UINT16_C(1510), 4u,
        CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_T32);

    EXPECT(decode_t32(UINT16_C(0xed20), UINT16_C(0x0b05),
        &instruction) == 4u);
    check_legacy_vfp(&instruction, CDISASM_ARM_NAME_FSTMDBX,
        UINT16_C(1488), CDISASM_ARM_REG_D0, 2u,
        CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_T32);

    EXPECT(decode_t32(UINT16_C(0xec93), UINT16_C(0x6b05),
        &instruction) == 4u);
    check_legacy_vfp(&instruction, CDISASM_ARM_NAME_FLDMIAX,
        UINT16_C(1495), CDISASM_ARM_REG_D6, 2u,
        CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_T32);
#else
    EXPECT(decode_a32(UINT32_C(0x0d805e05), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    return failures == 0 ? 0 : 1;
}
