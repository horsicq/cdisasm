#include "arm_generated_operands.h"

#include <string.h>

static void initialize(
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_form_id form_id,
    uint32_t word)
{
    memset(instruction, 0, sizeof(*instruction));
    instruction->opcode_size = 4u;
    instruction->raw_instruction = word;
    instruction->condition = CDISASM_ARM_CONDITION_AL;
    instruction->isa_id = CDISASM_ARM_ISA_A64;
    instruction->form_id = form_id;
    instruction->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
}

static int check_relative(
    cdisasm_arm_form_id form_id,
    uint32_t word,
    cdisasm_arm_isa_id isa_id,
    uint8_t opcode_size,
    uint64_t address,
    int64_t displacement,
    uint64_t target,
    uint8_t operand_count)
{
    cdisasm_arm_instruction instruction;
    const cdisasm_arm_operand *operand;

    initialize(&instruction, form_id, word);
    instruction.isa_id = isa_id;
    instruction.opcode_size = opcode_size;
    instruction.address = address;
    instruction.branch_target = target;
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != operand_count) {
        return 0;
    }
    operand = &instruction.operand[operand_count - 1u];
    return operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->access == CDISASM_OPERAND_ACCESS_READ
        && operand->size == (isa_id == CDISASM_ARM_ISA_T32 ? 4u : 8u)
        && operand->imm == target
        && operand->address == (uint64_t)displacement
        && operand->flags
            == (CDISASM_OPERAND_FLAG_SIGNED
                | CDISASM_OPERAND_FLAG_PC_RELATIVE
                | CDISASM_OPERAND_FLAG_HAS_ADDRESS)
        && (instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u;
}

int main(void)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction before;

    initialize(&instruction, UINT16_C(4457), UINT32_C(0xd5031001));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 1u
        || instruction.operand[0].type != CDISASM_OPERAND_REGISTER
        || instruction.operand[0].reg != CDISASM_ARM_REG_X1
        || instruction.operand[0].access != CDISASM_OPERAND_ACCESS_READ
        || instruction.operand[0].size != 8u
        || (instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE) != 0u) {
        return 1;
    }

    initialize(&instruction, UINT16_C(5576), UINT32_C(0x1acb08c1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 3u
        || instruction.operand[0].reg != CDISASM_ARM_REG_W1
        || instruction.operand[0].access != CDISASM_OPERAND_ACCESS_WRITE
        || instruction.operand[1].reg != CDISASM_ARM_REG_W6
        || instruction.operand[1].access != CDISASM_OPERAND_ACCESS_READ
        || instruction.operand[2].reg != CDISASM_ARM_REG_W11
        || instruction.operand[2].access != CDISASM_OPERAND_ACCESS_READ) {
        return 2;
    }

    initialize(&instruction, UINT16_C(6328), UINT32_C(0x1e2000c1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 2u
        || instruction.operand[0].reg != CDISASM_ARM_REG_W1
        || instruction.operand[1].reg != CDISASM_ARM_REG_S6
        || (instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) == 0u) {
        return 3;
    }

    initialize(&instruction, UINT16_C(51), UINT32_C(0x00310b96));
    instruction.isa_id = CDISASM_ARM_ISA_A32;
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 4u
        || instruction.operand[0].reg != CDISASM_ARM_REG_R1
        || instruction.operand[0].access != CDISASM_OPERAND_ACCESS_WRITE
        || instruction.operand[1].reg != CDISASM_ARM_REG_R6
        || instruction.operand[2].reg != CDISASM_ARM_REG_R11
        || instruction.operand[3].reg != CDISASM_ARM_REG_R0) {
        return 4;
    }

    initialize(&instruction, UINT16_C(1100), UINT32_C(0x18f1));
    instruction.isa_id = CDISASM_ARM_ISA_T32;
    instruction.opcode_size = 2u;
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 3u
        || instruction.operand[0].reg != CDISASM_ARM_REG_R1
        || instruction.operand[1].reg != CDISASM_ARM_REG_R6
        || instruction.operand[2].reg != CDISASM_ARM_REG_R3) {
        return 5;
    }

    initialize(&instruction, UINT16_C(1848), UINT32_C(0x8f00f3c1));
    instruction.isa_id = CDISASM_ARM_ISA_T32;
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 1u
        || instruction.operand[0].reg != CDISASM_ARM_REG_R1
        || instruction.operand[0].access != CDISASM_OPERAND_ACCESS_READ) {
        return 6;
    }

    initialize(&instruction, UINT16_C(4402), UINT32_C(0x918104c1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 4u
        || instruction.operand[0].reg != CDISASM_ARM_REG_X1
        || instruction.operand[0].access != CDISASM_OPERAND_ACCESS_WRITE
        || instruction.operand[1].reg != CDISASM_ARM_REG_X6
        || instruction.operand[1].access != CDISASM_OPERAND_ACCESS_READ
        || instruction.operand[2].type != CDISASM_OPERAND_IMMEDIATE
        || instruction.operand[2].imm != 16u
        || instruction.operand[2].size != 2u
        || instruction.operand[3].imm != 1u
        || instruction.operand[3].size != 1u) {
        return 7;
    }

    initialize(&instruction, UINT16_C(4404), UINT32_C(0x11c3fcc1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 3u
        || instruction.operand[0].reg != CDISASM_ARM_REG_W1
        || instruction.operand[1].reg != CDISASM_ARM_REG_W6
        || instruction.operand[2].type != CDISASM_OPERAND_IMMEDIATE
        || instruction.operand[2].imm != UINT64_MAX
        || instruction.operand[2].size != 4u
        || instruction.operand[2].flags != CDISASM_OPERAND_FLAG_SIGNED) {
        return 8;
    }

    initialize(&instruction, UINT16_C(6316), UINT32_C(0x9e0204c1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 3u
        || instruction.operand[0].reg != CDISASM_ARM_REG_S1
        || instruction.operand[1].reg != CDISASM_ARM_REG_X6
        || instruction.operand[2].imm != 63u
        || instruction.operand[2].size != 1u
        || (instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) == 0u) {
        return 9;
    }

    initialize(&instruction, UINT16_C(4533), UINT32_C(0x14000000));
    instruction.address = UINT64_C(0x1000);
    instruction.branch_target = UINT64_C(0x1000);
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 1u
        || instruction.operand[0].type != CDISASM_OPERAND_IMMEDIATE
        || instruction.operand[0].imm != UINT64_C(0x1000)
        || instruction.operand[0].address != 0u
        || instruction.operand[0].size != 8u
        || instruction.operand[0].flags
            != (CDISASM_OPERAND_FLAG_SIGNED
                | CDISASM_OPERAND_FLAG_PC_RELATIVE
                | CDISASM_OPERAND_FLAG_HAS_ADDRESS)) {
        return 10;
    }

    initialize(&instruction, UINT16_C(4563), UINT32_C(0xb6080001));
    instruction.address = UINT64_C(0x1800);
    instruction.branch_target = UINT64_C(0x1800);
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 3u
        || instruction.operand[0].reg != CDISASM_ARM_REG_X1
        || instruction.operand[0].size != 8u
        || instruction.operand[1].type != CDISASM_OPERAND_IMMEDIATE
        || instruction.operand[1].imm != 33u
        || instruction.operand[1].size != 1u
        || instruction.operand[2].imm != UINT64_C(0x1800)) {
        return 11;
    }

    initialize(&instruction, UINT16_C(1859), UINT32_C(0x8000f000));
    instruction.isa_id = CDISASM_ARM_ISA_T32;
    instruction.address = UINT64_C(0x2000);
    instruction.branch_target = UINT64_C(0x2004);
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 1u
        || instruction.operand[0].imm != UINT64_C(0x2004)
        || instruction.operand[0].address != 0u
        || instruction.operand[0].size != 4u) {
        return 12;
    }

    initialize(&instruction, UINT16_C(407), UINT32_C(0xfa000000));
    instruction.isa_id = CDISASM_ARM_ISA_A32;
    instruction.address = UINT64_C(0x3000);
    instruction.branch_target = UINT64_C(0x3008);
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 1u
        || instruction.operand[0].imm != UINT64_C(0x3008)
        || instruction.operand[0].address != 0u
        || instruction.operand[0].size != 8u) {
        return 13;
    }

    initialize(&instruction, UINT16_C(4533), UINT32_C(0x14000000));
    instruction.address = UINT64_C(0x4000);
    instruction.branch_target = UINT64_C(0x4004);
    before = instruction;
    if (cdisasm_arm_lower_generated_operands(&instruction)
        || memcmp(&instruction, &before, sizeof(instruction)) != 0) {
        return 14;
    }

    initialize(&instruction, UINT16_C(1), UINT32_C(0));
    before = instruction;
    if (cdisasm_arm_lower_generated_operands(&instruction)
        || memcmp(&instruction, &before, sizeof(instruction)) != 0) {
        return 15;
    }

    initialize(&instruction, UINT16_C(5158), UINT32_C(0xf85ff0c1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 2u
        || instruction.operand[0].type != CDISASM_OPERAND_REGISTER
        || instruction.operand[0].reg != CDISASM_ARM_REG_X1
        || instruction.operand[0].access != CDISASM_OPERAND_ACCESS_WRITE
        || instruction.operand[1].type != CDISASM_OPERAND_MEMORY
        || instruction.operand[1].base_reg != CDISASM_ARM_REG_X6
        || instruction.operand[1].imm != UINT64_MAX
        || instruction.operand[1].size != 8u
        || instruction.operand[1].access != CDISASM_OPERAND_ACCESS_READ
        || instruction.operand[1].flags
            != (CDISASM_OPERAND_FLAG_SIGNED
                | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT)) {
        return 16;
    }

    initialize(&instruction, UINT16_C(5572), UINT32_C(0xf94004c1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 2u
        || instruction.operand[1].base_reg != CDISASM_ARM_REG_X6
        || instruction.operand[1].imm != 8u
        || instruction.operand[1].flags
            != CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) {
        return 17;
    }

    initialize(&instruction, UINT16_C(5182), UINT32_C(0xf84017e1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand[1].base_reg != CDISASM_ARM_REG_SP
        || instruction.operand[1].imm != 1u
        || (instruction.instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK))
            != (CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK)
        || (instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX) != 0u) {
        return 18;
    }

    initialize(&instruction, UINT16_C(5218), UINT32_C(0xf85ffcc1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand[1].imm != UINT64_MAX
        || (instruction.instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK))
            != (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK)
        || (instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX) != 0u) {
        return 19;
    }

    initialize(&instruction, UINT16_C(5197), UINT32_C(0xf84018c1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand[1].imm != 1u
        || (instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED) == 0u
        || (instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK) != 0u) {
        return 20;
    }

    initialize(&instruction, UINT16_C(2309), UINT32_C(0x04d05961));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 4u
        || instruction.operand[0].type
            != CDISASM_ARM_OPERAND_SCALABLE_REGISTER
        || instruction.operand[0].reg != CDISASM_ARM_REG_Z1
        || instruction.operand[0].access
            != CDISASM_OPERAND_ACCESS_READ_WRITE
        || instruction.operand[0].extend_type != 8u
        || instruction.operand[1].type != CDISASM_ARM_OPERAND_PREDICATE
        || instruction.operand[1].reg != CDISASM_ARM_REG_P6
        || instruction.operand[1].flags
            != CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE
        || instruction.operand[1].extend_type != 8u
        || instruction.operand[2].reg != CDISASM_ARM_REG_Z11
        || instruction.operand[3].reg != CDISASM_ARM_REG_Z16
        || (instruction.instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED))
            != (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)) {
        return 21;
    }

    initialize(&instruction, UINT16_C(2536), UINT32_C(0x25005b71));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 4u
        || instruction.operand[0].type != CDISASM_ARM_OPERAND_PREDICATE
        || instruction.operand[0].reg != CDISASM_ARM_REG_P1
        || instruction.operand[0].flags
            != CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED
        || instruction.operand[1].reg != CDISASM_ARM_REG_P6
        || instruction.operand[1].flags != 0u
        || instruction.operand[2].reg != CDISASM_ARM_REG_P11
        || instruction.operand[3].reg != CDISASM_ARM_REG_P0) {
        return 22;
    }

    initialize(&instruction, UINT16_C(2326), UINT32_C(0x04263961));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 4u
        || instruction.operand[0].reg != CDISASM_ARM_REG_Z1
        || instruction.operand[0].access
            != CDISASM_OPERAND_ACCESS_READ_WRITE
        || instruction.operand[1].reg != CDISASM_ARM_REG_Z1
        || instruction.operand[1].access
            != CDISASM_OPERAND_ACCESS_READ_WRITE
        || instruction.operand[2].reg != CDISASM_ARM_REG_Z6
        || instruction.operand[3].reg != CDISASM_ARM_REG_Z11
        || instruction.operand[3].extend_type != 8u) {
        return 23;
    }

    /* Exercise every independently implemented relative-target transform at
     * its negative/high endpoint, including the architectural PC biases. */
    if (!check_relative(
            UINT16_C(405), UINT32_C(0x0affffff),
            CDISASM_ARM_ISA_A32, 4u, UINT64_C(0x5000),
            -INT64_C(4), UINT64_C(0x5004), 1u)) {
        return 24;
    }
    if (!check_relative(
            UINT16_C(407), UINT32_C(0xfbffffff),
            CDISASM_ARM_ISA_A32, 4u, UINT64_C(0x5000),
            -INT64_C(2), UINT64_C(0x5006), 1u)) {
        return 25;
    }
    if (!check_relative(
            UINT16_C(1173), UINT32_C(0x0000b3f9),
            CDISASM_ARM_ISA_T32, 2u, UINT64_C(0x5000),
            INT64_C(126), UINT64_C(0x5082), 2u)) {
        return 26;
    }
    if (!check_relative(
            UINT16_C(1181), UINT32_C(0x0000d0ff),
            CDISASM_ARM_ISA_T32, 2u, UINT64_C(0x5000),
            -INT64_C(2), UINT64_C(0x5002), 1u)) {
        return 27;
    }
    if (!check_relative(
            UINT16_C(1182), UINT32_C(0x0000e7ff),
            CDISASM_ARM_ISA_T32, 2u, UINT64_C(0x5000),
            -INT64_C(2), UINT64_C(0x5002), 1u)) {
        return 28;
    }
    if (!check_relative(
            UINT16_C(1859), UINT32_C(0xaffff43f),
            CDISASM_ARM_ISA_T32, 4u, UINT64_C(0x5000),
            -INT64_C(2), UINT64_C(0x5002), 1u)) {
        return 29;
    }
    if (!check_relative(
            UINT16_C(1860), UINT32_C(0xbffff7ff),
            CDISASM_ARM_ISA_T32, 4u, UINT64_C(0x5000),
            -INT64_C(2), UINT64_C(0x5002), 1u)) {
        return 30;
    }
    if (!check_relative(
            UINT16_C(1862), UINT32_C(0xfffff7ff),
            CDISASM_ARM_ISA_T32, 4u, UINT64_C(0x5000),
            -INT64_C(2), UINT64_C(0x5002), 1u)) {
        return 31;
    }
    if (!check_relative(
            UINT16_C(1861), UINT32_C(0xeffff7ff),
            CDISASM_ARM_ISA_T32, 4u, UINT64_C(0x5000),
            -INT64_C(4), UINT64_C(0x5000), 1u)) {
        return 32;
    }
    if (!check_relative(
            UINT16_C(4432), UINT32_C(0x54ffffe0),
            CDISASM_ARM_ISA_A64, 4u, UINT64_C(0x5000),
            -INT64_C(4), UINT64_C(0x4ffc), 1u)) {
        return 33;
    }
    if (!check_relative(
            UINT16_C(4533), UINT32_C(0x17ffffff),
            CDISASM_ARM_ISA_A64, 4u, UINT64_C(0x5000),
            -INT64_C(4), UINT64_C(0x4ffc), 1u)) {
        return 34;
    }
    if (!check_relative(
            UINT16_C(4535), UINT32_C(0x34ffffe1),
            CDISASM_ARM_ISA_A64, 4u, UINT64_C(0x5000),
            -INT64_C(4), UINT64_C(0x4ffc), 2u)) {
        return 35;
    }
    if (!check_relative(
            UINT16_C(4563), UINT32_C(0x360fffe1),
            CDISASM_ARM_ISA_A64, 4u, UINT64_C(0x5000),
            -INT64_C(4), UINT64_C(0x4ffc), 3u)) {
        return 36;
    }
    if (!check_relative(
            UINT16_C(4436), UINT32_C(0x7406bfe1),
            CDISASM_ARM_ISA_A64, 4u, UINT64_C(0x5000),
            -INT64_C(4), UINT64_C(0x4ffc), 3u)) {
        return 37;
    }

    initialize(&instruction, UINT16_C(655), UINT32_C(0xf1100200));
    instruction.isa_id = CDISASM_ARM_ISA_A32;
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 1u
        || instruction.operand[0].type != CDISASM_OPERAND_IMMEDIATE
        || instruction.operand[0].imm != 1u
        || instruction.operand[0].size != 1u) {
        return 38;
    }

    initialize(&instruction, UINT16_C(1157), UINT32_C(0x0000b618));
    instruction.isa_id = CDISASM_ARM_ISA_T32;
    instruction.opcode_size = 2u;
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 1u
        || instruction.operand[0].imm != 1u) {
        return 39;
    }

    initialize(&instruction, UINT16_C(4427), UINT32_C(0x33051cc1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 4u
        || instruction.operand[0].reg != CDISASM_ARM_REG_W1
        || instruction.operand[0].access
            != CDISASM_OPERAND_ACCESS_READ_WRITE
        || instruction.operand[1].reg != CDISASM_ARM_REG_W6
        || instruction.operand[1].access != CDISASM_OPERAND_ACCESS_READ
        || instruction.operand[2].imm != 5u
        || instruction.operand[3].imm != 7u) {
        return 40;
    }

    initialize(&instruction, UINT16_C(6304), UINT32_C(0x1e0280c1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 3u
        || instruction.operand[0].reg != CDISASM_ARM_REG_S1
        || instruction.operand[1].reg != CDISASM_ARM_REG_W6
        || instruction.operand[2].imm != 32u
        || instruction.operand[2].size != 1u
        || (instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) == 0u) {
        return 41;
    }

    initialize(&instruction, UINT16_C(4882), UINT32_C(0x191ff0c1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 2u
        || instruction.operand[0].reg != CDISASM_ARM_REG_W1
        || instruction.operand[0].access != CDISASM_OPERAND_ACCESS_READ
        || instruction.operand[1].type != CDISASM_OPERAND_MEMORY
        || instruction.operand[1].base_reg != CDISASM_ARM_REG_X6
        || instruction.operand[1].imm != UINT64_MAX
        || instruction.operand[1].size != 1u
        || instruction.operand[1].access != CDISASM_OPERAND_ACCESS_WRITE
        || instruction.operand[1].flags
            != (CDISASM_OPERAND_FLAG_SIGNED
                | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT)) {
        return 42;
    }

    initialize(&instruction, UINT16_C(4893), UINT32_C(0xd90013e1));
    if (!cdisasm_arm_lower_generated_operands(&instruction)
        || instruction.operand_count != 2u
        || instruction.operand[0].reg != CDISASM_ARM_REG_X1
        || instruction.operand[1].base_reg != CDISASM_ARM_REG_SP
        || instruction.operand[1].imm != 1u
        || instruction.operand[1].size != 8u
        || instruction.operand[1].access != CDISASM_OPERAND_ACCESS_WRITE) {
        return 43;
    }
    return 0;
}
