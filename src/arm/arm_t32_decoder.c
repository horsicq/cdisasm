#include "arm_t32_decoder.h"

#include <stddef.h>

static int64_t t32_sign_extend(uint64_t value, unsigned bits)
{
    uint64_t sign = UINT64_C(1) << (bits - 1u);
    return (int64_t)((value ^ sign) - sign);
}

static uint32_t t32_rotate_right32(uint32_t value, unsigned amount)
{
    amount &= 31u;
    return amount == 0u ? value
        : (value >> amount) | (value << (32u - amount));
}

static int t32_expand_modified_immediate(
    uint16_t encoded, uint32_t *value)
{
    uint32_t imm8 = encoded & UINT16_C(0x00ff);

    if ((encoded & UINT16_C(0x0c00)) == 0u) {
        switch ((encoded >> 8) & 3u) {
            case 0u:
                *value = imm8;
                return 1;
            case 1u:
                *value = (imm8 << 16) | imm8;
                break;
            case 2u:
                *value = (imm8 << 24) | (imm8 << 8);
                break;
            default:
                *value = (imm8 << 24) | (imm8 << 16)
                    | (imm8 << 8) | imm8;
                break;
        }
        return imm8 != 0u;
    }
    *value = t32_rotate_right32(
        UINT32_C(0x80) | (encoded & UINT16_C(0x007f)),
        (encoded >> 7) & 31u);
    return 1;
}

static cdisasm_arm_reg_id t32_reg(unsigned encoded)
{
    return encoded < 16u
        ? (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + encoded)
        : CDISASM_ARM_REG_NONE;
}

static cdisasm_arm_operand *t32_append_operand(
    cdisasm_arm_instruction *instruction)
{
    if (instruction->operand_count >= CDISASM_ARM_MAX_OPERANDS) {
        return NULL;
    }
    return &instruction->operand[instruction->operand_count++];
}

static cdisasm_arm_operand *t32_append_sized_register(
    cdisasm_arm_instruction *instruction,
    unsigned encoded,
    uint8_t size,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand = t32_append_operand(instruction);

    if (operand != NULL) {
        operand->type = CDISASM_OPERAND_REGISTER;
        operand->reg = t32_reg(encoded);
        operand->size = size;
        operand->access = access;
    }
    return operand;
}

static cdisasm_arm_operand *t32_append_register(
    cdisasm_arm_instruction *instruction,
    unsigned encoded,
    cdisasm_operand_access access)
{
    return t32_append_sized_register(instruction, encoded, 4u, access);
}

static cdisasm_arm_operand *t32_append_immediate(
    cdisasm_arm_instruction *instruction,
    uint64_t value,
    uint8_t size)
{
    cdisasm_arm_operand *operand = t32_append_operand(instruction);

    if (operand != NULL) {
        operand->type = CDISASM_OPERAND_IMMEDIATE;
        operand->imm = value;
        operand->size = size;
        operand->access = CDISASM_OPERAND_ACCESS_READ;
    }
    return operand;
}

static void t32_append_relative_target(
    cdisasm_arm_instruction *instruction,
    uint64_t target,
    int64_t displacement)
{
    cdisasm_arm_operand *operand =
        t32_append_immediate(instruction, target, 4);

    if (operand != NULL) {
        operand->address = (uint64_t)displacement;
        operand->flags = CDISASM_OPERAND_FLAG_SIGNED
            | CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
    }
    instruction->branch_target = target;
    instruction->opcode_groups |= CDISASM_GROUP_RELATIVE_BRANCH;
}

static cdisasm_arm_operand *t32_append_memory(
    cdisasm_arm_instruction *instruction,
    unsigned base,
    uint32_t displacement,
    uint8_t data_size,
    cdisasm_operand_access access,
    uint64_t resolved_address,
    int pc_relative)
{
    cdisasm_arm_operand *operand = t32_append_operand(instruction);

    if (operand == NULL) {
        return NULL;
    }
    operand->type = CDISASM_OPERAND_MEMORY;
    operand->base_reg = t32_reg(base);
    operand->size = data_size;
    operand->imm = displacement;
    operand->access = access;
    if (displacement != 0u) {
        operand->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
    }
    if (pc_relative) {
        operand->address = resolved_address;
        operand->flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
    }
    return operand;
}

static cdisasm_status t32_decode_branch_exchange(
    uint16_t halfword,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned rm = (halfword >> 3) & 15u;
    int link = (halfword & UINT16_C(0x0080)) != 0;

    if ((halfword & UINT16_C(0xff07)) != UINT16_C(0x4700)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (link && rm == 15u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    instruction->name_id = link ? CDISASM_ARM_NAME_BLX : CDISASM_ARM_NAME_BX;
    instruction->opcode_groups |= link ? CDISASM_GROUP_CALL
                                        : CDISASM_GROUP_JUMP;
    if (link) {
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_LINK;
    } else if (rm == 14u) {
        instruction->opcode_groups |= CDISASM_GROUP_RETURN;
    }
    t32_append_register(instruction, rm, CDISASM_OPERAND_ACCESS_READ);
    cdisasm_arm_requirements_set_legacy(required_capabilities, link ? CDISASM_ARM_CAP_V5 : CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_push_pop(
    uint16_t halfword,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    uint16_t form = halfword & UINT16_C(0xfe00);
    int load;
    uint16_t register_list;
    cdisasm_arm_operand *operand;

    if (form != UINT16_C(0xb400) && form != UINT16_C(0xbc00)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    load = form == UINT16_C(0xbc00);
    register_list = halfword & UINT16_C(0x00ff);
    if ((halfword & UINT16_C(0x0100)) != 0) {
        register_list |= load ? UINT16_C(0x8000) : UINT16_C(0x4000);
    }
    if (register_list == 0) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    instruction->name_id = load ? CDISASM_ARM_NAME_POP
                                : CDISASM_ARM_NAME_PUSH;
    instruction->instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
        | (load ? CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                : CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX)
        | (load ? CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
                : CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT);
    operand = t32_append_operand(instruction);
    if (operand != NULL) {
        operand->type = CDISASM_ARM_OPERAND_REGISTER_LIST;
        operand->size = 4;
        operand->register_list = register_list;
        operand->access = load ? CDISASM_OPERAND_ACCESS_WRITE
                               : CDISASM_OPERAND_ACCESS_READ;
    }
    if (load && (register_list & UINT16_C(0x8000)) != 0) {
        instruction->opcode_groups |= CDISASM_GROUP_JUMP
            | CDISASM_GROUP_RETURN;
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_immediate_data(
    uint16_t halfword,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_MOV,
        CDISASM_ARM_NAME_CMP,
        CDISASM_ARM_NAME_ADDS,
        CDISASM_ARM_NAME_SUBS
    };
    unsigned operation;
    unsigned rd;
    uint8_t immediate;

    if ((halfword & UINT16_C(0xe000)) != UINT16_C(0x2000)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    operation = (halfword >> 11) & 3u;
    rd = (halfword >> 8) & 7u;
    immediate = (uint8_t)halfword;
    instruction->name_id = names[operation];
    instruction->instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    t32_append_register(
        instruction,
        rd,
        operation == 1u ? CDISASM_OPERAND_ACCESS_READ
        : operation >= 2u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                          : CDISASM_OPERAND_ACCESS_WRITE);
    t32_append_immediate(instruction, immediate, 1);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_add_sub_three_operand(
    uint16_t halfword,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned rd;
    unsigned rn;
    unsigned value;
    int immediate;

    if ((halfword & UINT16_C(0xf800)) != UINT16_C(0x1800)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    immediate = (halfword & UINT16_C(0x0400)) != 0;
    rd = halfword & 7u;
    rn = (halfword >> 3) & 7u;
    value = (halfword >> 6) & 7u;
    instruction->name_id = (halfword & UINT16_C(0x0200)) != 0
        ? CDISASM_ARM_NAME_SUBS
        : CDISASM_ARM_NAME_ADDS;
    instruction->instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    t32_append_register(instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
    t32_append_register(instruction, rn, CDISASM_OPERAND_ACCESS_READ);
    if (immediate) {
        t32_append_immediate(instruction, value, 1);
    } else {
        t32_append_register(instruction, value, CDISASM_OPERAND_ACCESS_READ);
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_alu_register(
    uint16_t halfword,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    static const cdisasm_arm_name_id names[16] = {
        CDISASM_ARM_NAME_AND, CDISASM_ARM_NAME_EOR,
        CDISASM_ARM_NAME_LSLS, CDISASM_ARM_NAME_LSRS,
        CDISASM_ARM_NAME_ASRS, CDISASM_ARM_NAME_ADC,
        CDISASM_ARM_NAME_SBC, CDISASM_ARM_NAME_RORS,
        CDISASM_ARM_NAME_TST, CDISASM_ARM_NAME_RSB,
        CDISASM_ARM_NAME_CMP, CDISASM_ARM_NAME_CMN,
        CDISASM_ARM_NAME_ORR, CDISASM_ARM_NAME_MUL,
        CDISASM_ARM_NAME_BIC, CDISASM_ARM_NAME_MVN
    };
    unsigned operation;
    unsigned rdn;
    unsigned rm;
    cdisasm_arm_name_id name;

    if ((halfword & UINT16_C(0xfc00)) != UINT16_C(0x4000)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    operation = (halfword >> 6) & 15u;
    rdn = halfword & 7u;
    rm = (halfword >> 3) & 7u;
    name = names[operation];
    if (name == CDISASM_ARM_NAME_NONE) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    if (operation == 2u || operation == 3u || operation == 4u
        || operation == 7u || operation == 13u) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
#endif
    instruction->name_id = name;
    instruction->instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    if (operation == 8u || operation == 10u || operation == 11u) {
        t32_append_register(instruction, rdn, CDISASM_OPERAND_ACCESS_READ);
    } else {
        t32_append_register(
            instruction,
            rdn,
            operation == 9u || operation == 15u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ_WRITE);
    }
    t32_append_register(instruction, rm, CDISASM_OPERAND_ACCESS_READ);
    if (operation == 9u) {
        t32_append_immediate(instruction, 0, 1);
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_high_register(
    uint16_t halfword,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned operation;
    unsigned rd;
    unsigned rm;

    if ((halfword & UINT16_C(0xfc00)) != UINT16_C(0x4400)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    operation = (halfword >> 8) & 3u;
    if (operation == 3u) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    rd = (halfword & 7u) | ((halfword >> 4) & 8u);
    rm = (halfword >> 3) & 15u;
    instruction->name_id = operation == 0u ? CDISASM_ARM_NAME_ADD
        : operation == 1u ? CDISASM_ARM_NAME_CMP
                          : CDISASM_ARM_NAME_MOV;
    t32_append_register(
        instruction,
        rd,
        operation == 0u ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : operation == 1u ? CDISASM_OPERAND_ACCESS_READ
                          : CDISASM_OPERAND_ACCESS_WRITE);
    t32_append_register(instruction, rm, CDISASM_OPERAND_ACCESS_READ);
    if (operation == 1u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    }
    if (rd == 15u && operation != 1u) {
        instruction->opcode_groups |= CDISASM_GROUP_JUMP;
        if (operation == 2u && rm == 14u) {
            instruction->opcode_groups |= CDISASM_GROUP_RETURN;
        }
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_literal_load(
    uint16_t halfword,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned rt;
    uint32_t displacement;
    uint64_t base;

    if ((halfword & UINT16_C(0xf800)) != UINT16_C(0x4800)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    rt = (halfword >> 8) & 7u;
    displacement = (uint32_t)(halfword & UINT16_C(0x00ff)) << 2;
    base = (address + UINT64_C(4)) & ~UINT64_C(3);
    instruction->name_id = CDISASM_ARM_NAME_LDR;
    t32_append_register(instruction, rt, CDISASM_OPERAND_ACCESS_WRITE);
    t32_append_memory(
        instruction,
        15,
        displacement,
        4,
        CDISASM_OPERAND_ACCESS_READ,
        base + displacement,
        1);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_immediate_memory(
    uint16_t halfword,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    uint16_t top = halfword & UINT16_C(0xf000);
    unsigned rt;
    unsigned rn;
    uint32_t displacement;
    uint8_t data_size;
    int load;
    int byte;

    if ((halfword & UINT16_C(0xe000)) == UINT16_C(0x6000)) {
        byte = (halfword & UINT16_C(0x1000)) != 0;
        load = (halfword & UINT16_C(0x0800)) != 0;
        rt = halfword & 7u;
        rn = (halfword >> 3) & 7u;
        data_size = byte ? 1u : 4u;
        displacement = ((halfword >> 6) & 31u) * data_size;
    } else if (top == UINT16_C(0x8000)) {
        byte = 0;
        load = (halfword & UINT16_C(0x0800)) != 0;
        rt = halfword & 7u;
        rn = (halfword >> 3) & 7u;
        data_size = 2;
        displacement = ((halfword >> 6) & 31u) << 1;
    } else if (top == UINT16_C(0x9000)) {
        byte = 0;
        load = (halfword & UINT16_C(0x0800)) != 0;
        rt = (halfword >> 8) & 7u;
        rn = 13;
        data_size = 4;
        displacement = (uint32_t)(halfword & UINT16_C(0x00ff)) << 2;
    } else {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    instruction->name_id = load
        ? (data_size == 1u ? CDISASM_ARM_NAME_LDRB
            : data_size == 2u ? CDISASM_ARM_NAME_LDRH
                              : CDISASM_ARM_NAME_LDR)
        : (data_size == 1u ? CDISASM_ARM_NAME_STRB
            : data_size == 2u ? CDISASM_ARM_NAME_STRH
                              : CDISASM_ARM_NAME_STR);
    if (byte) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_BYTE;
    }
    t32_append_register(
        instruction,
        rt,
        load ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
    t32_append_memory(
        instruction,
        rn,
        displacement,
        data_size,
        load ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE,
        0,
        0);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_register_memory(
    uint16_t halfword,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_STR, CDISASM_ARM_NAME_STRH,
        CDISASM_ARM_NAME_STRB, CDISASM_ARM_NAME_LDRSB,
        CDISASM_ARM_NAME_LDR, CDISASM_ARM_NAME_LDRH,
        CDISASM_ARM_NAME_LDRB, CDISASM_ARM_NAME_LDRSH
    };
    static const uint8_t data_sizes[8] = { 4u, 2u, 1u, 1u, 4u, 2u, 1u, 2u };
    unsigned operation;
    unsigned rm;
    unsigned rn;
    unsigned rt;
    int load;
    cdisasm_arm_operand *memory;

    if ((halfword & UINT16_C(0xf000)) != UINT16_C(0x5000)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    operation = (halfword >> 9) & 7u;
    rm = (halfword >> 6) & 7u;
    rn = (halfword >> 3) & 7u;
    rt = halfword & 7u;
    load = operation >= 3u && operation != 0u;
    instruction->name_id = names[operation];
    if (operation == 2u || operation == 3u || operation == 6u) {
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_BYTE;
    }
    t32_append_register(instruction, rt,
        load ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
    memory = t32_append_memory(instruction, rn, 0u, data_sizes[operation],
        load ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE,
        0u, 0);
    if (memory != NULL) {
        memory->index_reg = t32_reg(rm);
    }
    cdisasm_arm_requirements_set_legacy(
        required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_address_generation(
    uint16_t halfword,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned rd;
    uint32_t immediate;
    int from_sp;

    if ((halfword & UINT16_C(0xf000)) != UINT16_C(0xa000)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    from_sp = (halfword & UINT16_C(0x0800)) != 0;
    rd = (halfword >> 8) & 7u;
    immediate = (uint32_t)(halfword & UINT16_C(0x00ff)) << 2;
    instruction->name_id = from_sp ? CDISASM_ARM_NAME_ADD
                                   : CDISASM_ARM_NAME_ADR;
    t32_append_register(instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
    if (from_sp) {
        t32_append_register(instruction, 13, CDISASM_OPERAND_ACCESS_READ);
        t32_append_immediate(instruction, immediate, 2);
    } else {
        uint64_t base = (address + UINT64_C(4)) & ~UINT64_C(3);
        cdisasm_arm_operand *operand =
            t32_append_immediate(instruction, base + immediate, 4);
        if (operand != NULL) {
            operand->address = immediate;
            operand->flags = CDISASM_OPERAND_FLAG_PC_RELATIVE
                | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
        }
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_sp_adjust(
    uint16_t halfword,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    uint32_t immediate;

    if ((halfword & UINT16_C(0xff00)) != UINT16_C(0xb000)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    instruction->name_id = (halfword & UINT16_C(0x0080)) != 0
        ? CDISASM_ARM_NAME_SUB
        : CDISASM_ARM_NAME_ADD;
    immediate = (uint32_t)(halfword & UINT16_C(0x007f)) << 2;
    t32_append_register(instruction, 13, CDISASM_OPERAND_ACCESS_READ_WRITE);
    t32_append_immediate(instruction, immediate, 2);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_cbz(
    uint16_t halfword,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    uint32_t displacement;
    uint64_t target;

    if ((halfword & UINT16_C(0xf500)) != UINT16_C(0xb100)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    displacement = ((uint32_t)(halfword & UINT16_C(0x0200)) >> 3)
        | ((uint32_t)(halfword & UINT16_C(0x00f8)) >> 2);
    target = address + UINT64_C(4) + displacement;
    instruction->name_id = (halfword & UINT16_C(0x0800)) != 0
        ? CDISASM_ARM_NAME_CBNZ
        : CDISASM_ARM_NAME_CBZ;
    instruction->opcode_groups |= CDISASM_GROUP_JUMP
        | CDISASM_GROUP_CONDITIONAL;
    t32_append_register(
        instruction, halfword & 7u, CDISASM_OPERAND_ACCESS_READ);
    t32_append_relative_target(instruction, target, displacement);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V6);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_multiple(
    uint16_t halfword,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned rn;
    uint16_t register_list;
    int load;
    int writeback;
    cdisasm_arm_operand *operand;

    if ((halfword & UINT16_C(0xf000)) != UINT16_C(0xc000)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    load = (halfword & UINT16_C(0x0800)) != 0;
    rn = (halfword >> 8) & 7u;
    register_list = halfword & UINT16_C(0x00ff);
    if (register_list == 0) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    instruction->name_id = load ? CDISASM_ARM_NAME_LDM
                                : CDISASM_ARM_NAME_STM;
    writeback = !load || (register_list & (UINT16_C(1) << rn)) == 0;
    instruction->instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
        | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT;
    if (writeback) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    }
    t32_append_register(
        instruction,
        rn,
        writeback ? CDISASM_OPERAND_ACCESS_READ_WRITE
                  : CDISASM_OPERAND_ACCESS_READ);
    operand = t32_append_operand(instruction);
    if (operand != NULL) {
        operand->type = CDISASM_ARM_OPERAND_REGISTER_LIST;
        operand->size = 4;
        operand->register_list = register_list;
        operand->access = load ? CDISASM_OPERAND_ACCESS_WRITE
                               : CDISASM_OPERAND_ACCESS_READ;
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_conditional_branch(
    uint16_t halfword,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned condition;
    int64_t displacement;
    uint64_t target;

    if ((halfword & UINT16_C(0xf000)) != UINT16_C(0xd000)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    condition = (halfword >> 8) & 15u;
    if (condition >= 14u) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    displacement = t32_sign_extend(
        (uint64_t)(halfword & UINT16_C(0x00ff)) << 1,
        9);
    target = address + UINT64_C(4) + (uint64_t)displacement;
    instruction->name_id = CDISASM_ARM_NAME_B;
    instruction->condition = (cdisasm_arm_condition)condition;
    instruction->opcode_groups |= CDISASM_GROUP_JUMP
        | CDISASM_GROUP_CONDITIONAL;
    t32_append_relative_target(instruction, target, displacement);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_unconditional_branch(
    uint16_t halfword,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    int64_t displacement;
    uint64_t target;

    if ((halfword & UINT16_C(0xf800)) != UINT16_C(0xe000)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    displacement = t32_sign_extend(
        (uint64_t)(halfword & UINT16_C(0x07ff)) << 1,
        12);
    target = address + UINT64_C(4) + (uint64_t)displacement;
    instruction->name_id = CDISASM_ARM_NAME_B;
    instruction->opcode_groups |= CDISASM_GROUP_JUMP;
    t32_append_relative_target(instruction, target, displacement);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_16_extra(
    uint16_t halfword,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized)
{
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
#endif
    *recognized = 0;
    if (halfword == UINT16_C(0xbf10)
        || halfword == UINT16_C(0xbf20)
        || halfword == UINT16_C(0xbf30)
        || halfword == UINT16_C(0xbf40)
        || halfword == UINT16_C(0xbf50)) {
        unsigned operation = (halfword >> 4) & 7u;

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)operation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        static const cdisasm_arm_name_id names[6] = {
            CDISASM_ARM_NAME_NOP, CDISASM_ARM_NAME_YIELD,
            CDISASM_ARM_NAME_WFE, CDISASM_ARM_NAME_WFI,
            CDISASM_ARM_NAME_SEV, CDISASM_ARM_NAME_SEVL
        };
        instruction->name_id = names[operation];
        cdisasm_arm_requirements_set_legacy(
            required_capabilities,
            operation == 5u ? CDISASM_ARM_CAP_V8 : CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((halfword & UINT16_C(0xff00)) == UINT16_C(0xb200)) {
        static const cdisasm_arm_name_id names[4] = {
            CDISASM_ARM_NAME_SXTH, CDISASM_ARM_NAME_SXTB,
            CDISASM_ARM_NAME_UXTH, CDISASM_ARM_NAME_UXTB
        };
        unsigned operation = (halfword >> 6) & 3u;
        unsigned rm = (halfword >> 3) & 7u;
        unsigned rd = halfword & 7u;

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)operation;
        (void)rm;
        (void)rd;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = names[operation];
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((halfword & UINT16_C(0xff00)) == UINT16_C(0xde00)) {
        unsigned immediate = halfword & UINT16_C(0x00ff);

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_UDF;
        instruction->opcode_groups |= CDISASM_GROUP_INTERRUPT;
        t32_append_immediate(instruction, immediate, 1);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V4);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((halfword & UINT16_C(0xe000)) == 0u
        && ((halfword >> 11) & 3u) != 3u) {
        unsigned operation = (halfword >> 11) & 3u;
        unsigned immediate = (halfword >> 6) & 31u;
        unsigned rm = (halfword >> 3) & 7u;
        unsigned rd = halfword & 7u;

        *recognized = 1;
        if (operation != 0u && immediate == 0u) {
            immediate = 32u;
        }
#if !USE_EXTRA_OPCODES
        (void)rm;
        (void)rd;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = operation == 0u && immediate == 0u
            ? CDISASM_ARM_NAME_MOV
            : operation == 0u ? CDISASM_ARM_NAME_LSL
            : operation == 1u ? CDISASM_ARM_NAME_LSR
                              : CDISASM_ARM_NAME_ASR;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        if (instruction->name_id != CDISASM_ARM_NAME_MOV) {
            t32_append_immediate(instruction, immediate, 1);
        }
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((halfword & UINT16_C(0xff00)) == UINT16_C(0xbf00)
        && (halfword & 15u) != 0u) {
        unsigned first_condition = (halfword >> 4) & 15u;

        *recognized = 1;
        if (first_condition >= CDISASM_ARM_CONDITION_AL) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_IT;
        t32_append_immediate(instruction, first_condition, 1);
        t32_append_immediate(instruction, halfword & 15u, 1);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((halfword & UINT16_C(0xfff7)) == UINT16_C(0xb610)) {
        unsigned pan = (halfword >> 3) & 1u;

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)pan;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_SETPAN;
        instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
        t32_append_immediate(instruction, pan, 1);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_PAN);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((halfword & UINT16_C(0xfff7)) == UINT16_C(0xb650)) {
        unsigned big_endian = (halfword >> 3) & 1u;

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)big_endian;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_SETEND;
        t32_append_immediate(instruction, big_endian, 1);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((halfword & UINT16_C(0xffe8)) == UINT16_C(0xb660)) {
        unsigned disable = (halfword >> 4) & 1u;
        unsigned mask = halfword & 7u;

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)disable;
        (void)mask;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = disable != 0u
            ? CDISASM_ARM_NAME_CPSID : CDISASM_ARM_NAME_CPSIE;
        instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
        t32_append_immediate(instruction, mask, 1);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((halfword & UINT16_C(0xffc0)) == UINT16_C(0xba80)) {
        *recognized = 1;
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_HLT;
        instruction->opcode_groups |= CDISASM_GROUP_INTERRUPT;
        t32_append_immediate(
            instruction, halfword & UINT16_C(0x003f), 1);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((halfword & UINT16_C(0xffc0)) == UINT16_C(0xba00)) {
        unsigned rm = (halfword >> 3) & 7u;
        unsigned rd = halfword & 7u;

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)rm;
        (void)rd;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_REV;
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

static cdisasm_status t32_decode_16(
    uint16_t halfword,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    cdisasm_status status;
    int extra_recognized = 0;

    if (halfword == UINT16_C(0xbf00)) {
        instruction->name_id = CDISASM_ARM_NAME_NOP;
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
    }
    if ((halfword & UINT16_C(0xff00)) == UINT16_C(0xbe00)) {
        instruction->name_id = CDISASM_ARM_NAME_BKPT;
        instruction->opcode_groups |= CDISASM_GROUP_INTERRUPT;
        t32_append_immediate(instruction, halfword & UINT16_C(0x00ff), 1);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V5);
        return CDISASM_STATUS_OK;
    }
    if ((halfword & UINT16_C(0xff00)) == UINT16_C(0xdf00)) {
        instruction->name_id = CDISASM_ARM_NAME_SVC;
        instruction->opcode_groups |= CDISASM_GROUP_INTERRUPT;
        t32_append_immediate(instruction, halfword & UINT16_C(0x00ff), 1);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
        return CDISASM_STATUS_OK;
    }
    status = t32_decode_16_extra(
        halfword, instruction, required_capabilities, &extra_recognized);
    if (extra_recognized
        || status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }

#define T32_TRY(function_call) \
    do { \
        status = (function_call); \
        if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) { \
            return status; \
        } \
    } while (0)

    T32_TRY(t32_decode_branch_exchange(
        halfword, instruction, required_capabilities));
    T32_TRY(t32_decode_push_pop(
        halfword, instruction, required_capabilities));
    T32_TRY(t32_decode_cbz(
        halfword, address, instruction, required_capabilities));
    T32_TRY(t32_decode_sp_adjust(
        halfword, instruction, required_capabilities));
    T32_TRY(t32_decode_add_sub_three_operand(
        halfword, instruction, required_capabilities));
    T32_TRY(t32_decode_immediate_data(
        halfword, instruction, required_capabilities));
    T32_TRY(t32_decode_alu_register(
        halfword, instruction, required_capabilities));
    T32_TRY(t32_decode_high_register(
        halfword, instruction, required_capabilities));
    T32_TRY(t32_decode_literal_load(
        halfword, address, instruction, required_capabilities));
    T32_TRY(t32_decode_register_memory(
        halfword, instruction, required_capabilities));
    T32_TRY(t32_decode_immediate_memory(
        halfword, instruction, required_capabilities));
    T32_TRY(t32_decode_address_generation(
        halfword, address, instruction, required_capabilities));
    T32_TRY(t32_decode_multiple(
        halfword, instruction, required_capabilities));
    T32_TRY(t32_decode_conditional_branch(
        halfword, address, instruction, required_capabilities));
    T32_TRY(t32_decode_unconditional_branch(
        halfword, address, instruction, required_capabilities));

#undef T32_TRY

    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

static cdisasm_status t32_decode_bl(
    uint16_t first,
    uint16_t second,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    uint32_t sign;
    uint32_t j1;
    uint32_t j2;
    uint32_t i1;
    uint32_t i2;
    uint32_t encoded;
    int64_t displacement;
    uint64_t target;

    if ((first & UINT16_C(0xf800)) != UINT16_C(0xf000)
        || (second & UINT16_C(0xd000)) != UINT16_C(0xd000)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    sign = (first >> 10) & 1u;
    j1 = (second >> 13) & 1u;
    j2 = (second >> 11) & 1u;
    i1 = (j1 ^ sign) ^ 1u;
    i2 = (j2 ^ sign) ^ 1u;
    encoded = (sign << 24)
        | (i1 << 23)
        | (i2 << 22)
        | ((uint32_t)(first & UINT16_C(0x03ff)) << 12)
        | ((uint32_t)(second & UINT16_C(0x07ff)) << 1);
    displacement = t32_sign_extend(encoded, 25);
    target = address + UINT64_C(4) + (uint64_t)displacement;
    instruction->name_id = CDISASM_ARM_NAME_BL;
    instruction->opcode_groups |= CDISASM_GROUP_CALL;
    instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_LINK;
    t32_append_relative_target(instruction, target, displacement);
    cdisasm_arm_requirements_set_legacy(required_capabilities, (second & UINT16_C(0xf800))
            == UINT16_C(0xf800)
        ? CDISASM_ARM_CAP_V4
        : CDISASM_ARM_CAP_V6);
    return CDISASM_STATUS_OK;
}

static cdisasm_status t32_decode_extra_load_store(
    uint32_t word,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized)
{
#if USE_EXTRA_OPCODES
    unsigned rn;
    unsigned rt;
    unsigned load;
    unsigned pre_index;
    unsigned writeback;
    unsigned add;
    uint32_t offset;
    cdisasm_arm_operand *memory;
#endif

    if ((word & UINT32_C(0xff700000)) == UINT32_C(0xe8600000)
        || (word & UINT32_C(0xff700000)) == UINT32_C(0xe8700000)
        || (word & UINT32_C(0xff700000)) == UINT32_C(0xe9400000)
        || (word & UINT32_C(0xff700000)) == UINT32_C(0xe9500000)
        || (word & UINT32_C(0xff700000)) == UINT32_C(0xe9600000)
        || (word & UINT32_C(0xff700000)) == UINT32_C(0xe9700000)
        || (word & UINT32_C(0xfe5f0000)) == UINT32_C(0xe85f0000)) {
        unsigned rt2 = (word >> 8) & 15u;

        if (((word >> 12) & 15u) == 15u) {
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)address;
        (void)instruction;
        (void)required_capabilities;
        (void)rt2;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        rn = (word >> 16) & 15u;
        rt = (word >> 12) & 15u;
        load = (word >> 20) & 1u;
        pre_index = (word >> 24) & 1u;
        writeback = (word >> 21) & 1u;
        add = (word >> 23) & 1u;
        offset = (word & 255u) << 2;
        if (rt == 15u || rt2 == 15u || rt == rt2
            || (rn == 15u && (!load || writeback != 0u))
            || (writeback != 0u && (rn == rt || rn == rt2))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = load != 0u
            ? CDISASM_ARM_NAME_LDRD : CDISASM_ARM_NAME_STRD;
        t32_append_sized_register(
            instruction, rt, 4u,
            load != 0u ? CDISASM_OPERAND_ACCESS_WRITE
                       : CDISASM_OPERAND_ACCESS_READ);
        t32_append_sized_register(
            instruction, rt2, 4u,
            load != 0u ? CDISASM_OPERAND_ACCESS_WRITE
                       : CDISASM_OPERAND_ACCESS_READ);
        memory = t32_append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = t32_reg(rn);
            memory->size = 8u;
            memory->access = load != 0u
                ? CDISASM_OPERAND_ACCESS_READ
                : CDISASM_OPERAND_ACCESS_WRITE;
            if (offset != 0u) {
                memory->imm = add != 0u
                    ? offset : (uint64_t)(-(int64_t)offset);
                memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                if (add == 0u) {
                    memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            }
            if (rn == 15u) {
                uint64_t base = (address + UINT64_C(4)) & ~UINT64_C(3);

                memory->address = add != 0u
                    ? base + offset : base - offset;
                memory->flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE
                    | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
            }
        }
        if (pre_index == 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
        } else if (writeback != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    {
        uint32_t top = word & UINT32_C(0xfff00000);
        unsigned operation;
        unsigned positive_immediate;

        switch (top) {
            case UINT32_C(0xf8000000): operation = 4u; positive_immediate = 0u; break;
            case UINT32_C(0xf8100000): operation = 5u; positive_immediate = 0u; break;
            case UINT32_C(0xf8200000): operation = 0u; positive_immediate = 0u; break;
            case UINT32_C(0xf8300000): operation = 1u; positive_immediate = 0u; break;
            case UINT32_C(0xf8400000): operation = 6u; positive_immediate = 0u; break;
            case UINT32_C(0xf8500000): operation = 7u; positive_immediate = 0u; break;
            case UINT32_C(0xf8800000): operation = 4u; positive_immediate = 1u; break;
            case UINT32_C(0xf8900000): operation = 5u; positive_immediate = 1u; break;
            case UINT32_C(0xf8a00000): operation = 0u; positive_immediate = 1u; break;
            case UINT32_C(0xf8b00000): operation = 1u; positive_immediate = 1u; break;
            case UINT32_C(0xf8c00000): operation = 6u; positive_immediate = 1u; break;
            case UINT32_C(0xf8d00000): operation = 7u; positive_immediate = 1u; break;
            case UINT32_C(0xf9100000): operation = 2u; positive_immediate = 0u; break;
            case UINT32_C(0xf9300000): operation = 3u; positive_immediate = 0u; break;
            case UINT32_C(0xf9900000): operation = 2u; positive_immediate = 1u; break;
            case UINT32_C(0xf9b00000): operation = 3u; positive_immediate = 1u; break;
            default: return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        if (((word >> 12) & 15u) == 15u) {
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)address;
        (void)instruction;
        (void)required_capabilities;
        (void)operation;
        (void)positive_immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned register_form = 0u;
        unsigned index_reg = 0u;
        unsigned index_shift = 0u;

        rn = (word >> 16) & 15u;
        rt = (word >> 12) & 15u;
        load = operation == 1u || operation == 2u || operation == 3u
            || operation == 5u || operation == 7u;
        pre_index = 1u;
        writeback = 0u;
        add = 1u;
        offset = 0u;
        if (rt == 15u || (rn == 15u && !load)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = operation == 0u
            ? CDISASM_ARM_NAME_STRH
            : operation == 1u ? CDISASM_ARM_NAME_LDRH
            : operation == 2u ? CDISASM_ARM_NAME_LDRSB
            : operation == 3u ? CDISASM_ARM_NAME_LDRSH
            : operation == 4u ? CDISASM_ARM_NAME_STRB
            : operation == 5u ? CDISASM_ARM_NAME_LDRB
            : operation == 6u ? CDISASM_ARM_NAME_STR
                              : CDISASM_ARM_NAME_LDR;
        if (operation == 4u || operation == 5u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_BYTE;
        }
        memory = NULL;
        if (positive_immediate != 0u) {
            offset = word & UINT32_C(0x0fff);
        } else if ((word & UINT32_C(0x00000fc0)) == 0u) {
            unsigned rm = word & 15u;

            if (rn == 15u || rm == 15u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
            register_form = 1u;
            index_reg = rm;
            index_shift = (word >> 4) & 3u;
        } else {
            uint32_t mode = word & UINT32_C(0x00000f00);

            offset = word & 255u;
            if (mode == UINT32_C(0x00000900)) {
                pre_index = 0u;
                writeback = 1u;
                add = 0u;
            } else if (mode == UINT32_C(0x00000c00)) {
                add = 0u;
            } else if (mode == UINT32_C(0x00000d00)) {
                writeback = 1u;
                add = 0u;
            } else if (mode == UINT32_C(0x00000e00)) {
                instruction->instruction_flags |=
                    CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED;
                instruction->name_id = operation == 0u
                    ? CDISASM_ARM_NAME_STRHT
                    : operation == 1u ? CDISASM_ARM_NAME_LDRHT
                    : operation == 2u ? CDISASM_ARM_NAME_LDRSBT
                    : operation == 3u ? CDISASM_ARM_NAME_LDRSHT
                    : operation == 4u ? CDISASM_ARM_NAME_STRBT
                    : operation == 5u ? CDISASM_ARM_NAME_LDRBT
                    : operation == 6u ? CDISASM_ARM_NAME_STRT
                                      : CDISASM_ARM_NAME_LDRT;
            } else {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
        }
        if (writeback != 0u && rn == rt) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        {
            unsigned access_size = operation == 2u || operation == 4u
                    || operation == 5u
                ? 1u : operation == 6u || operation == 7u ? 4u : 2u;

            t32_append_sized_register(
                instruction, rt, access_size,
                load ? CDISASM_OPERAND_ACCESS_WRITE
                     : CDISASM_OPERAND_ACCESS_READ);
        }
        if (memory == NULL) {
            memory = t32_append_operand(instruction);
        }
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = t32_reg(rn);
            memory->size = operation == 2u || operation == 4u
                    || operation == 5u
                ? 1u : operation == 6u || operation == 7u ? 4u : 2u;
            memory->access = load ? CDISASM_OPERAND_ACCESS_READ
                                  : CDISASM_OPERAND_ACCESS_WRITE;
            if (register_form != 0u) {
                memory->index_reg = t32_reg(index_reg);
                memory->shift_type = CDISASM_ARM_SHIFT_LSL;
                memory->shift_amount = (uint8_t)index_shift;
            }
            if (offset != 0u) {
                memory->imm = add != 0u
                    ? offset : (uint64_t)(-(int64_t)offset);
                memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                if (add == 0u) {
                    memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            }
            if (rn == 15u) {
                uint64_t base = (address + UINT64_C(4)) & ~UINT64_C(3);

                memory->address = add != 0u
                    ? base + offset : base - offset;
                memory->flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE
                    | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
            }
        }
        if (pre_index == 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
        } else if (writeback != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
}

static cdisasm_status t32_decode_prefetch(
    uint32_t word,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized)
{
    cdisasm_arm_name_id name;
    unsigned rn = (word >> 16) & 15u;
    unsigned register_form = 0u;
    unsigned negative = 0u;
    unsigned rm = 0u;
    unsigned shift = 0u;
    uint32_t offset;

    if ((word & UINT32_C(0xfff0ffc0)) == UINT32_C(0xf810f000)) {
        name = CDISASM_ARM_NAME_PLD;
        register_form = 1u;
    } else if ((word & UINT32_C(0xfff0ffc0))
            == UINT32_C(0xf830f000)) {
        name = CDISASM_ARM_NAME_PLDW;
        register_form = 1u;
    } else if ((word & UINT32_C(0xfff0ffc0))
            == UINT32_C(0xf910f000)) {
        name = CDISASM_ARM_NAME_PLI;
        register_form = 1u;
    } else if ((word & UINT32_C(0xfff0ff00))
            == UINT32_C(0xf810fc00)) {
        name = CDISASM_ARM_NAME_PLD;
        negative = 1u;
    } else if ((word & UINT32_C(0xfff0ff00))
            == UINT32_C(0xf830fc00)) {
        name = CDISASM_ARM_NAME_PLDW;
        negative = 1u;
    } else if ((word & UINT32_C(0xfff0ff00))
            == UINT32_C(0xf910fc00)) {
        name = CDISASM_ARM_NAME_PLI;
        negative = 1u;
    } else if ((word & UINT32_C(0xfff0f000))
            == UINT32_C(0xf890f000)) {
        name = CDISASM_ARM_NAME_PLD;
    } else if ((word & UINT32_C(0xfff0f000))
            == UINT32_C(0xf8b0f000)) {
        name = CDISASM_ARM_NAME_PLDW;
    } else if ((word & UINT32_C(0xfff0f000))
            == UINT32_C(0xf990f000)) {
        name = CDISASM_ARM_NAME_PLI;
    } else {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    *recognized = 1;
    offset = negative != 0u ? word & 255u : word & UINT32_C(0x0fff);
    if (register_form != 0u) {
        rm = word & 15u;
        shift = (word >> 4) & 3u;
    }
    if ((register_form != 0u && (rn == 15u || rm == 15u))
        || (name == CDISASM_ARM_NAME_PLDW && rn == 15u)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    (void)address;
    (void)instruction;
    (void)required_capabilities;
    (void)name;
    (void)offset;
    (void)shift;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    {
        cdisasm_arm_operand *memory = t32_append_operand(instruction);

        instruction->name_id = name;
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = t32_reg(rn);
            memory->size = 0u;
            memory->access = CDISASM_OPERAND_ACCESS_READ;
            if (register_form != 0u) {
                memory->index_reg = t32_reg(rm);
                memory->shift_type = CDISASM_ARM_SHIFT_LSL;
                memory->shift_amount = (uint8_t)shift;
            } else if (offset != 0u) {
                memory->imm = negative != 0u
                    ? (uint64_t)(-(int64_t)offset) : offset;
                memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                if (negative != 0u) {
                    memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            }
            if (rn == 15u) {
                uint64_t base = (address + UINT64_C(4)) & ~UINT64_C(3);

                memory->address = negative != 0u
                    ? base - offset : base + offset;
                memory->flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE
                    | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
            }
        }
    }
    cdisasm_arm_requirements_set_legacy(
        required_capabilities, CDISASM_ARM_CAP_V7);
    return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status t32_decode_exclusive_and_table(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized)
{
    cdisasm_arm_name_id name = CDISASM_ARM_NAME_NONE;
    unsigned rn = (word >> 16) & 15u;
    unsigned rt = (word >> 12) & 15u;
    unsigned rt2 = (word >> 8) & 15u;
    unsigned rd = word & 15u;
    unsigned size = 4u;
    unsigned load = 0u;
    unsigned exclusive = 0u;
    unsigned acquire = 0u;
    unsigned release = 0u;
    unsigned pair = 0u;
    unsigned status = 0u;
    uint32_t offset = 0u;

    if ((word & UINT32_C(0xfff0fff0)) == UINT32_C(0xe8d0f000)
        || (word & UINT32_C(0xfff0fff0)) == UINT32_C(0xe8d0f010)) {
        unsigned rm = word & 15u;

        *recognized = 1;
        if (rn == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        cdisasm_arm_operand *memory;
        unsigned halfword = (word >> 4) & 1u;

        instruction->name_id = halfword != 0u
            ? CDISASM_ARM_NAME_TBH : CDISASM_ARM_NAME_TBB;
        instruction->opcode_groups |= CDISASM_GROUP_JUMP;
        memory = t32_append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = t32_reg(rn);
            memory->index_reg = t32_reg(rm);
            memory->size = halfword != 0u ? 2u : 1u;
            memory->access = CDISASM_OPERAND_ACCESS_READ;
            if (halfword != 0u) {
                memory->shift_type = CDISASM_ARM_SHIFT_LSL;
                memory->shift_amount = 1u;
            }
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((word & UINT32_C(0xfff00000)) == UINT32_C(0xe8400000)) {
        name = CDISASM_ARM_NAME_STREX;
        status = (word >> 8) & 15u;
        exclusive = 1u;
        offset = (word & 255u) << 2;
    } else if ((word & UINT32_C(0xfff00f00))
            == UINT32_C(0xe8500f00)) {
        name = CDISASM_ARM_NAME_LDREX;
        load = 1u;
        exclusive = 1u;
        offset = (word & 255u) << 2;
    } else if ((word & UINT32_C(0xfff00ff0))
            == UINT32_C(0xe8c00f40)) {
        name = CDISASM_ARM_NAME_STREXB; size = 1u; status = rd; exclusive = 1u;
    } else if ((word & UINT32_C(0xfff00ff0))
            == UINT32_C(0xe8c00f50)) {
        name = CDISASM_ARM_NAME_STREXH; size = 2u; status = rd; exclusive = 1u;
    } else if ((word & UINT32_C(0xfff000f0))
            == UINT32_C(0xe8c00070)) {
        name = CDISASM_ARM_NAME_STREXD; status = rd; exclusive = 1u; pair = 1u;
    } else if ((word & UINT32_C(0xfff00fff))
            == UINT32_C(0xe8d00f4f)) {
        name = CDISASM_ARM_NAME_LDREXB; size = 1u; load = 1u; exclusive = 1u;
    } else if ((word & UINT32_C(0xfff00fff))
            == UINT32_C(0xe8d00f5f)) {
        name = CDISASM_ARM_NAME_LDREXH; size = 2u; load = 1u; exclusive = 1u;
    } else if ((word & UINT32_C(0xfff000ff))
            == UINT32_C(0xe8d0007f)) {
        name = CDISASM_ARM_NAME_LDREXD; load = 1u; exclusive = 1u; pair = 1u;
    } else if ((word & UINT32_C(0xfff00fff))
            == UINT32_C(0xe8c00f8f)) {
        name = CDISASM_ARM_NAME_STLB; size = 1u; release = 1u;
    } else if ((word & UINT32_C(0xfff00fff))
            == UINT32_C(0xe8c00f9f)) {
        name = CDISASM_ARM_NAME_STLH; size = 2u; release = 1u;
    } else if ((word & UINT32_C(0xfff00fff))
            == UINT32_C(0xe8c00faf)) {
        name = CDISASM_ARM_NAME_STL; release = 1u;
    } else if ((word & UINT32_C(0xfff00ff0))
            == UINT32_C(0xe8c00fc0)) {
        name = CDISASM_ARM_NAME_STLEXB; size = 1u; status = rd;
        exclusive = 1u; release = 1u;
    } else if ((word & UINT32_C(0xfff00ff0))
            == UINT32_C(0xe8c00fd0)) {
        name = CDISASM_ARM_NAME_STLEXH; size = 2u; status = rd;
        exclusive = 1u; release = 1u;
    } else if ((word & UINT32_C(0xfff00ff0))
            == UINT32_C(0xe8c00fe0)) {
        name = CDISASM_ARM_NAME_STLEX; status = rd;
        exclusive = 1u; release = 1u;
    } else if ((word & UINT32_C(0xfff000f0))
            == UINT32_C(0xe8c000f0)) {
        name = CDISASM_ARM_NAME_STLEXD; status = rd; pair = 1u;
        exclusive = 1u; release = 1u;
    } else if ((word & UINT32_C(0xfff00fff))
            == UINT32_C(0xe8d00f8f)) {
        name = CDISASM_ARM_NAME_LDAB; size = 1u; load = 1u; acquire = 1u;
    } else if ((word & UINT32_C(0xfff00fff))
            == UINT32_C(0xe8d00f9f)) {
        name = CDISASM_ARM_NAME_LDAH; size = 2u; load = 1u; acquire = 1u;
    } else if ((word & UINT32_C(0xfff00fff))
            == UINT32_C(0xe8d00faf)) {
        name = CDISASM_ARM_NAME_LDA; load = 1u; acquire = 1u;
    } else if ((word & UINT32_C(0xfff00fff))
            == UINT32_C(0xe8d00fcf)) {
        name = CDISASM_ARM_NAME_LDAEXB; size = 1u; load = 1u;
        exclusive = 1u; acquire = 1u;
    } else if ((word & UINT32_C(0xfff00fff))
            == UINT32_C(0xe8d00fdf)) {
        name = CDISASM_ARM_NAME_LDAEXH; size = 2u; load = 1u;
        exclusive = 1u; acquire = 1u;
    } else if ((word & UINT32_C(0xfff00fff))
            == UINT32_C(0xe8d00fef)) {
        name = CDISASM_ARM_NAME_LDAEX; load = 1u;
        exclusive = 1u; acquire = 1u;
    } else if ((word & UINT32_C(0xfff000ff))
            == UINT32_C(0xe8d000ff)) {
        name = CDISASM_ARM_NAME_LDAEXD; load = 1u; pair = 1u;
        exclusive = 1u; acquire = 1u;
    } else {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    *recognized = 1;
    if (rn == 15u || rt == 15u || (pair != 0u && rt2 == 15u)
        || (load == 0u && exclusive != 0u && status >= 13u)
        || (pair != 0u && rt == rt2)
        || (load == 0u && exclusive != 0u
            && (status == rn || status == rt
                || (pair != 0u && status == rt2)))) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
    (void)name;
    (void)size;
    (void)acquire;
    (void)release;
    (void)offset;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    instruction->name_id = name;
    instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
        | (exclusive != 0u ? CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE : 0u)
        | (acquire != 0u ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE : 0u)
        | (release != 0u ? CDISASM_ARM_INSTRUCTION_FLAG_RELEASE : 0u);
    if (load == 0u && exclusive != 0u) {
        t32_append_sized_register(
            instruction, status, 4u, CDISASM_OPERAND_ACCESS_WRITE);
    }
    t32_append_sized_register(
        instruction, rt, (uint8_t)size,
        load != 0u ? CDISASM_OPERAND_ACCESS_WRITE
                   : CDISASM_OPERAND_ACCESS_READ);
    if (pair != 0u) {
        t32_append_sized_register(
            instruction, rt2, 4u,
            load != 0u ? CDISASM_OPERAND_ACCESS_WRITE
                       : CDISASM_OPERAND_ACCESS_READ);
    }
    t32_append_memory(
        instruction, rn, offset, (uint8_t)(pair != 0u ? 8u : size),
        load != 0u ? CDISASM_OPERAND_ACCESS_READ
                   : CDISASM_OPERAND_ACCESS_WRITE,
        0u, 0);
    cdisasm_arm_requirements_set_legacy(
        required_capabilities,
        acquire != 0u || release != 0u
            ? CDISASM_ARM_CAP_V8 : CDISASM_ARM_CAP_V7);
    return CDISASM_STATUS_OK;
#endif
}

static unsigned t32_register_count(uint16_t registers)
{
    unsigned count = 0u;

    while (registers != 0u) {
        count += registers & 1u;
        registers >>= 1;
    }
    return count;
}

static cdisasm_status t32_decode_block_transfer(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized)
{
    unsigned rn = (word >> 16) & 15u;
    unsigned writeback = (word >> 21) & 1u;
    unsigned operation = (word >> 23) & 3u;
    unsigned load = (word >> 20) & 1u;
    uint16_t registers = (uint16_t)(word & UINT32_C(0xffff));
    cdisasm_arm_name_id name;
    cdisasm_arm_operand *list;
    unsigned pre;
    unsigned increment;

#if !USE_EXTRA_OPCODES
    (void)name;
    (void)list;
    (void)pre;
    (void)increment;
#endif

    if ((word & UINT32_C(0xfe400000)) != UINT32_C(0xe8000000)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    /* The exception-state forms occupy the otherwise reserved P=M=1,
     * register-list-zero encodings. */
    if ((word & UINT32_C(0x0000ffe0)) == UINT32_C(0x0000c000)) {
        unsigned srs = load == 0u && rn == 13u;
        unsigned rfe = load != 0u;

        if (!srs && !rfe) {
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        *recognized = 1;
        if (srs) {
            unsigned mode = word & 31u;

            if (mode != 0x11u && mode != 0x12u && mode != 0x13u
                && mode != 0x16u && mode != 0x17u && mode != 0x1au
                && mode != 0x1bu) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        increment = operation == 3u;
        pre = operation == 0u;
        instruction->name_id = srs
            ? (operation == 0u ? CDISASM_ARM_NAME_SRSDB
                               : CDISASM_ARM_NAME_SRS)
            : (operation == 0u ? CDISASM_ARM_NAME_RFEDB
                               : CDISASM_ARM_NAME_RFE);
        instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
        if (rfe) {
            instruction->opcode_groups |= CDISASM_GROUP_RETURN
                | CDISASM_GROUP_INTERRUPT_RETURN;
            t32_append_register(
                instruction, rn,
                writeback != 0u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                : CDISASM_OPERAND_ACCESS_READ);
        } else {
            t32_append_register(
                instruction, 13u,
                writeback != 0u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                : CDISASM_OPERAND_ACCESS_READ);
            t32_append_immediate(instruction, word & 31u, 1u);
        }
        if (writeback != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
        }
        instruction->instruction_flags |= pre != 0u
            ? CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            : CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX;
        instruction->instruction_flags |= increment != 0u
            ? CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
            : CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT;
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }

    if (operation != 1u && operation != 2u) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    *recognized = 1;
    registers &= load != 0u ? UINT16_C(0xffff) : UINT16_C(0x7fff);
    if (rn == 15u || t32_register_count(registers) < 2u
        || (load != 0u && (registers & UINT16_C(0xc000))
                == UINT16_C(0xc000))
        || (writeback != 0u
            && (registers & (UINT16_C(1) << rn)) != 0u)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    name = operation == 1u
        ? (load != 0u ? CDISASM_ARM_NAME_LDM : CDISASM_ARM_NAME_STM)
        : (load != 0u ? CDISASM_ARM_NAME_LDMDB : CDISASM_ARM_NAME_STMDB);
    instruction->name_id = name;
    if (writeback != 0u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    }
    instruction->instruction_flags |= operation == 1u
        ? CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
        : CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX;
    instruction->instruction_flags |= operation == 1u
        ? CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
        : CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT;
    t32_append_register(
        instruction, rn,
        writeback != 0u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_READ);
    list = t32_append_operand(instruction);
    if (list != NULL) {
        list->type = CDISASM_ARM_OPERAND_REGISTER_LIST;
        list->size = 4u;
        list->register_list = registers;
        list->access = load != 0u ? CDISASM_OPERAND_ACCESS_WRITE
                                 : CDISASM_OPERAND_ACCESS_READ;
    }
    if (load != 0u && (registers & UINT16_C(0x8000)) != 0u) {
        instruction->opcode_groups |= CDISASM_GROUP_JUMP;
    }
    cdisasm_arm_requirements_set_legacy(
        required_capabilities, CDISASM_ARM_CAP_V7);
    return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status t32_decode_32_extra(
    uint16_t first,
    uint16_t second,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized)
{
    const uint32_t canonical = ((uint32_t)first << 16) | second;

    uint32_t canonical_word = ((uint32_t)first << 16) | second;
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
#endif
    *recognized = 0;
    {
        cdisasm_status status = t32_decode_block_transfer(
            canonical, instruction, required_capabilities, recognized);

        if (*recognized || status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return status;
        }
    }
    {
        cdisasm_status status = t32_decode_prefetch(
            canonical, address, instruction, required_capabilities,
            recognized);

        if (*recognized || status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return status;
        }
    }
    {
        cdisasm_status status = t32_decode_exclusive_and_table(
            canonical, instruction, required_capabilities, recognized);

        if (*recognized || status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return status;
        }
    }
    {
        cdisasm_status status = t32_decode_extra_load_store(
            canonical, address, instruction, required_capabilities,
            recognized);

        if (*recognized || status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return status;
        }
    }
    if ((canonical & UINT32_C(0xff000000)) == UINT32_C(0xea000000)) {
        unsigned operation = (canonical >> 21) & 15u;
        unsigned set_flags = (canonical >> 20) & 1u;
        unsigned rn = (canonical >> 16) & 15u;
        unsigned rd = (canonical >> 8) & 15u;
        unsigned rm = canonical & 15u;
        unsigned shift_kind = (canonical >> 4) & 3u;
        unsigned shift_amount = ((canonical >> 10) & 28u)
            | ((canonical >> 6) & 3u);
        unsigned test = (operation == 0u || operation == 4u)
            && set_flags != 0u && rd == 15u;
        unsigned move = (operation == 2u || operation == 3u) && rn == 15u;
        cdisasm_arm_name_id name;
        cdisasm_arm_operand *shifted;

        if (operation > 4u) {
            goto t32_after_shifted_logical;
        }
        *recognized = 1;
        if (rm == 15u || (!test && rd == 15u) || (!move && rn == 15u)
            || (test && rn == 15u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)name;
        (void)shifted;
        (void)shift_kind;
        (void)shift_amount;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        if (test) {
            name = operation == 4u ? CDISASM_ARM_NAME_TEQ
                                   : CDISASM_ARM_NAME_TST;
        } else if (move) {
            if (operation == 3u) {
                name = set_flags != 0u ? CDISASM_ARM_NAME_MVNS
                                       : CDISASM_ARM_NAME_MVN;
            } else {
                name = set_flags != 0u ? CDISASM_ARM_NAME_MOVS
                                       : CDISASM_ARM_NAME_MOV;
            }
        } else if (operation == 0u) {
            name = set_flags != 0u ? CDISASM_ARM_NAME_ANDS
                                   : CDISASM_ARM_NAME_AND;
        } else if (operation == 1u) {
            name = set_flags != 0u ? CDISASM_ARM_NAME_BICS
                                   : CDISASM_ARM_NAME_BIC;
        } else if (operation == 2u) {
            name = set_flags != 0u ? CDISASM_ARM_NAME_ORRS
                                   : CDISASM_ARM_NAME_ORR;
        } else if (operation == 3u) {
            name = set_flags != 0u ? CDISASM_ARM_NAME_ORNS
                                   : CDISASM_ARM_NAME_ORN;
        } else {
            name = set_flags != 0u ? CDISASM_ARM_NAME_EORS
                                   : CDISASM_ARM_NAME_EOR;
        }
        instruction->name_id = name;
        if (set_flags != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        if (!test) {
            t32_append_register(
                instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        }
        if (!move) {
            t32_append_register(
                instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        }
        shifted = t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        if (shifted != NULL) {
            if (shift_kind == 3u && shift_amount == 0u) {
                shifted->shift_type = CDISASM_ARM_SHIFT_RRX;
                shifted->shift_amount = 1u;
            } else if (shift_kind != 0u || shift_amount != 0u) {
                static const uint8_t shifts[4] = {
                    CDISASM_ARM_SHIFT_LSL, CDISASM_ARM_SHIFT_LSR,
                    CDISASM_ARM_SHIFT_ASR, CDISASM_ARM_SHIFT_ROR
                };

                shifted->shift_type = shifts[shift_kind];
                shifted->shift_amount = (uint8_t)(shift_amount != 0u
                    ? shift_amount : 32u);
            }
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
t32_after_shifted_logical:
    if ((canonical & UINT32_C(0xfff08030)) == UINT32_C(0xeac00000)
        || (canonical & UINT32_C(0xfff08030))
            == UINT32_C(0xeac00020)) {
        unsigned top = (canonical >> 5) & 1u;
        unsigned rn = (canonical >> 16) & 15u;
        unsigned rd = (canonical >> 8) & 15u;
        unsigned rm = canonical & 15u;
        unsigned amount = ((canonical >> 10) & 28u)
            | ((canonical >> 6) & 3u);

        *recognized = 1;
        if (rn == 15u || rd == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)top;
        (void)amount;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        cdisasm_arm_operand *shifted;

        instruction->name_id = top != 0u ? CDISASM_ARM_NAME_PKHTB
                                         : CDISASM_ARM_NAME_PKHBT;
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        shifted = t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        if (shifted != NULL && (top != 0u || amount != 0u)) {
            shifted->shift_type = top != 0u ? CDISASM_ARM_SHIFT_ASR
                                           : CDISASM_ARM_SHIFT_LSL;
            shifted->shift_amount = (uint8_t)(amount != 0u ? amount : 32u);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((canonical & UINT32_C(0xffe00000)) == UINT32_C(0xeb000000)) {
        unsigned set_flags = (canonical >> 20) & 1u;
        unsigned rn = (canonical >> 16) & 15u;
        unsigned rd = (canonical >> 8) & 15u;
        unsigned rm = canonical & 15u;
        unsigned shift_kind = (canonical >> 4) & 3u;
        unsigned shift_amount = ((canonical >> 10) & 28u)
            | ((canonical >> 6) & 3u);

        *recognized = 1;
        if (rn == 15u || rd == 13u || rm == 15u
            || (rd == 15u && set_flags == 0u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)set_flags;
        (void)shift_kind;
        (void)shift_amount;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        cdisasm_arm_operand *shifted;

        instruction->name_id = rd == 15u ? CDISASM_ARM_NAME_CMN
            : (set_flags != 0u ? CDISASM_ARM_NAME_ADDS
                               : CDISASM_ARM_NAME_ADD);
        if (set_flags != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        if (rd != 15u) {
            t32_append_register(
                instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        }
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        shifted = t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        if (shifted != NULL) {
            if (shift_kind == 3u && shift_amount == 0u) {
                shifted->shift_type = CDISASM_ARM_SHIFT_RRX;
                shifted->shift_amount = 1u;
            } else if (shift_kind != 0u || shift_amount != 0u) {
                static const uint8_t shifts[4] = {
                    CDISASM_ARM_SHIFT_LSL, CDISASM_ARM_SHIFT_LSR,
                    CDISASM_ARM_SHIFT_ASR, CDISASM_ARM_SHIFT_ROR
                };

                shifted->shift_type = shifts[shift_kind];
                shifted->shift_amount = (uint8_t)(shift_amount != 0u
                    ? shift_amount : 32u);
            }
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((canonical & UINT32_C(0xffe00000)) == UINT32_C(0xeb400000)
        || (canonical & UINT32_C(0xffe00000))
            == UINT32_C(0xeb600000)) {
        unsigned subtract = (canonical >> 21) & 1u;
        unsigned set_flags = (canonical >> 20) & 1u;
        unsigned rn = (canonical >> 16) & 15u;
        unsigned rd = (canonical >> 8) & 15u;
        unsigned rm = canonical & 15u;
        unsigned shift_kind = (canonical >> 4) & 3u;
        unsigned shift_amount = ((canonical >> 10) & 28u)
            | ((canonical >> 6) & 3u);

        *recognized = 1;
        if (rn >= 13u || rd >= 13u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)subtract;
        (void)set_flags;
        (void)shift_kind;
        (void)shift_amount;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        cdisasm_arm_operand *shifted;

        instruction->name_id = subtract != 0u
            ? (set_flags != 0u ? CDISASM_ARM_NAME_SBCS
                               : CDISASM_ARM_NAME_SBC)
            : (set_flags != 0u ? CDISASM_ARM_NAME_ADCS
                               : CDISASM_ARM_NAME_ADC);
        if (set_flags != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        shifted = t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        if (shifted != NULL) {
            if (shift_kind == 3u && shift_amount == 0u) {
                shifted->shift_type = CDISASM_ARM_SHIFT_RRX;
                shifted->shift_amount = 1u;
            } else if (shift_kind != 0u || shift_amount != 0u) {
                static const uint8_t shifts[4] = {
                    CDISASM_ARM_SHIFT_LSL, CDISASM_ARM_SHIFT_LSR,
                    CDISASM_ARM_SHIFT_ASR, CDISASM_ARM_SHIFT_ROR
                };

                shifted->shift_type = shifts[shift_kind];
                shifted->shift_amount = (uint8_t)(shift_amount != 0u
                    ? shift_amount : 32u);
            }
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((canonical & UINT32_C(0xffe00000)) == UINT32_C(0xeba00000)
        || (canonical & UINT32_C(0xffe00000))
            == UINT32_C(0xebc00000)) {
        unsigned reverse = ((canonical >> 21) & 7u) == 6u;
        unsigned set_flags = (canonical >> 20) & 1u;
        unsigned rn = (canonical >> 16) & 15u;
        unsigned rd = (canonical >> 8) & 15u;
        unsigned rm = canonical & 15u;
        unsigned shift_kind = (canonical >> 4) & 3u;
        unsigned shift_amount = ((canonical >> 10) & 28u)
            | ((canonical >> 6) & 3u);

        *recognized = 1;
        if (rn == 15u || rd == 13u || rm == 15u
            || (rd == 15u && (set_flags == 0u || reverse != 0u))
            || (reverse != 0u && rn == 13u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)set_flags;
        (void)shift_kind;
        (void)shift_amount;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        cdisasm_arm_operand *shifted;

        instruction->name_id = rd == 15u ? CDISASM_ARM_NAME_CMP
            : (reverse != 0u
                ? (set_flags != 0u ? CDISASM_ARM_NAME_RSBS
                                   : CDISASM_ARM_NAME_RSB)
                : (set_flags != 0u ? CDISASM_ARM_NAME_SUBS
                                   : CDISASM_ARM_NAME_SUB));
        if (set_flags != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        if (rd != 15u) {
            t32_append_register(
                instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        }
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        shifted = t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        if (shifted != NULL) {
            if (shift_kind == 3u && shift_amount == 0u) {
                shifted->shift_type = CDISASM_ARM_SHIFT_RRX;
                shifted->shift_amount = 1u;
            } else if (shift_kind != 0u || shift_amount != 0u) {
                static const uint8_t shifts[4] = {
                    CDISASM_ARM_SHIFT_LSL, CDISASM_ARM_SHIFT_LSR,
                    CDISASM_ARM_SHIFT_ASR, CDISASM_ARM_SHIFT_ROR
                };

                shifted->shift_type = shifts[shift_kind];
                shifted->shift_amount = (uint8_t)(shift_amount != 0u
                    ? shift_amount : 32u);
            }
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((canonical & UINT32_C(0xfff0f0f0))
            == UINT32_C(0xfb00f000)) {
        unsigned rn = (canonical >> 16) & 15u;
        unsigned rd = (canonical >> 8) & 15u;
        unsigned rm = canonical & 15u;

        *recognized = 1;
        if (rn == 15u || rd == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_MUL;
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((canonical & UINT32_C(0xfff000c0))
            == UINT32_C(0xfbc00080)) {
        static const cdisasm_arm_name_id names[4] = {
            CDISASM_ARM_NAME_SMLALBB, CDISASM_ARM_NAME_SMLALBT,
            CDISASM_ARM_NAME_SMLALTB, CDISASM_ARM_NAME_SMLALTT
        };
        unsigned rd_lo = (canonical >> 12) & 15u;
        unsigned rd_hi = (canonical >> 8) & 15u;
        unsigned rn = (canonical >> 16) & 15u;
        unsigned operation = (canonical >> 4) & 3u;
        unsigned rm = canonical & 15u;

        *recognized = 1;
        if (rd_lo == 13u || rd_lo == 15u
            || rd_hi == 13u || rd_hi == 15u
            || rn == 13u || rn == 15u || rm == 13u || rm == 15u
            || rd_lo == rd_hi) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)operation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = names[operation];
        t32_append_register(
            instruction, rd_lo, CDISASM_OPERAND_ACCESS_READ_WRITE);
        t32_append_register(
            instruction, rd_hi, CDISASM_OPERAND_ACCESS_READ_WRITE);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((canonical & UINT32_C(0xffe000e0))
            == UINT32_C(0xfbc000c0)) {
        static const cdisasm_arm_name_id names[2][2] = {
            {CDISASM_ARM_NAME_SMLALD, CDISASM_ARM_NAME_SMLALDX},
            {CDISASM_ARM_NAME_SMLSLD, CDISASM_ARM_NAME_SMLSLDX}
        };
        unsigned rd_lo = (canonical >> 12) & 15u;
        unsigned rd_hi = (canonical >> 8) & 15u;
        unsigned rn = (canonical >> 16) & 15u;
        unsigned subtract = (canonical >> 20) & 1u;
        unsigned exchange = (canonical >> 4) & 1u;
        unsigned rm = canonical & 15u;

        *recognized = 1;
        if (rd_lo == 13u || rd_lo == 15u
            || rd_hi == 13u || rd_hi == 15u
            || rn == 13u || rn == 15u || rm == 13u || rm == 15u
            || rd_lo == rd_hi) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)subtract;
        (void)exchange;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = names[subtract][exchange];
        t32_append_register(
            instruction, rd_lo, CDISASM_OPERAND_ACCESS_READ_WRITE);
        t32_append_register(
            instruction, rd_hi, CDISASM_OPERAND_ACCESS_READ_WRITE);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((canonical & UINT32_C(0xfff000f0))
            == UINT32_C(0xfbe00060)) {
        unsigned rd_lo = (canonical >> 12) & 15u;
        unsigned rd_hi = (canonical >> 8) & 15u;
        unsigned rn = (canonical >> 16) & 15u;
        unsigned rm = canonical & 15u;

        *recognized = 1;
        if (rd_lo == 13u || rd_lo == 15u
            || rd_hi == 13u || rd_hi == 15u
            || rn == 13u || rn == 15u || rm == 13u || rm == 15u
            || rd_lo == rd_hi) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_UMAAL;
        t32_append_register(
            instruction, rd_lo, CDISASM_OPERAND_ACCESS_READ_WRITE);
        t32_append_register(
            instruction, rd_hi, CDISASM_OPERAND_ACCESS_READ_WRITE);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((canonical & UINT32_C(0xff8000f0))
            == UINT32_C(0xfb800000)) {
        static const cdisasm_arm_name_id names[2][2] = {
            {CDISASM_ARM_NAME_SMULL, CDISASM_ARM_NAME_UMULL},
            {CDISASM_ARM_NAME_SMLAL, CDISASM_ARM_NAME_UMLAL}
        };
        unsigned operation = (canonical >> 21) & 3u;
        unsigned rd_lo = (canonical >> 12) & 15u;
        unsigned rd_hi = (canonical >> 8) & 15u;
        unsigned rn = (canonical >> 16) & 15u;
        unsigned rm = canonical & 15u;
        unsigned accumulate = operation >> 1;
        unsigned unsigned_result = operation & 1u;
        cdisasm_operand_access destination_access = accumulate != 0u
            ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_WRITE;

        *recognized = 1;
        if (rd_lo == 15u || rd_hi == 15u || rn == 15u || rm == 15u
            || rd_lo == rd_hi) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)unsigned_result;
        (void)destination_access;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = names[accumulate][unsigned_result];
        t32_append_register(instruction, rd_lo, destination_access);
        t32_append_register(instruction, rd_hi, destination_access);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((canonical_word & UINT32_C(0xffffffF8))
            == UINT32_C(0xf3af8000)
        && (canonical_word & 7u) <= 5u) {
        unsigned operation = canonical_word & 7u;

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)operation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        static const cdisasm_arm_name_id names[6] = {
            CDISASM_ARM_NAME_NOP, CDISASM_ARM_NAME_YIELD,
            CDISASM_ARM_NAME_WFE, CDISASM_ARM_NAME_WFI,
            CDISASM_ARM_NAME_SEV, CDISASM_ARM_NAME_SEVL
        };

        instruction->name_id = names[operation];
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            operation == 5u ? CDISASM_ARM_CAP_V8 : CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((canonical_word & UINT32_C(0xfffffc00))
            == UINT32_C(0xf3af8400)) {
        unsigned control = (canonical_word >> 8) & 3u;
        unsigned mask = (canonical_word >> 5) & 7u;
        unsigned mode = canonical_word & 31u;
        int disable = (control & 2u) != 0u;
        int change_mode = (control & 1u) != 0u;

        *recognized = 1;
        if (!change_mode && mode != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)mask; (void)mode; (void)disable;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = disable ? CDISASM_ARM_NAME_CPSID
                                       : CDISASM_ARM_NAME_CPSIE;
        instruction->form_id = (cdisasm_arm_form_id)(
            disable ? (change_mode ? 1838u : 1837u)
                    : (change_mode ? 1840u : 1839u));
        instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
        t32_append_immediate(instruction, mask, 1u);
        if (change_mode) t32_append_immediate(instruction, mode, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if (canonical_word == UINT32_C(0xf3af8010)
        || canonical_word == UINT32_C(0xf3af8012)
        || canonical_word == UINT32_C(0xf3af8014)
        || canonical_word == UINT32_C(0xf3af8016)
        || (canonical_word & UINT32_C(0xfffffff0))
            == UINT32_C(0xf3af80f0)) {
        *recognized = 1;
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = canonical_word == UINT32_C(0xf3af8010)
            ? CDISASM_ARM_NAME_ESB
            : canonical_word == UINT32_C(0xf3af8012)
                ? CDISASM_ARM_NAME_TSB
                : canonical_word == UINT32_C(0xf3af8014)
                    ? CDISASM_ARM_NAME_CSDB
                    : canonical_word == UINT32_C(0xf3af8016)
                        ? CDISASM_ARM_NAME_CLRBHB
                        : CDISASM_ARM_NAME_DBG;
        if (instruction->name_id == CDISASM_ARM_NAME_DBG) {
            t32_append_immediate(instruction, canonical_word & 15u, 1u);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        if (instruction->name_id == CDISASM_ARM_NAME_ESB) {
            (void)cdisasm_arm_requirements_add_feature(
                required_capabilities, CDISASM_ARM_FEATURE_RAS);
        } else if (instruction->name_id == CDISASM_ARM_NAME_TSB) {
            (void)cdisasm_arm_requirements_add_feature(
                required_capabilities, CDISASM_ARM_FEATURE_TRF);
        } else if (instruction->name_id == CDISASM_ARM_NAME_CLRBHB) {
            (void)cdisasm_arm_requirements_add_feature(
                required_capabilities, CDISASM_ARM_FEATURE_CLRBHB);
        }
        return CDISASM_STATUS_OK;
#endif
    }
    {
        static const uint32_t crc_values[6] = {
            UINT32_C(0xfac0f080), UINT32_C(0xfac0f090),
            UINT32_C(0xfac0f0a0), UINT32_C(0xfad0f080),
            UINT32_C(0xfad0f090), UINT32_C(0xfad0f0a0)
        };
#if USE_EXTRA_OPCODES
        static const cdisasm_arm_name_id crc_names[6] = {
            CDISASM_ARM_NAME_CRC32B, CDISASM_ARM_NAME_CRC32H,
            CDISASM_ARM_NAME_CRC32W, CDISASM_ARM_NAME_CRC32CB,
            CDISASM_ARM_NAME_CRC32CH, CDISASM_ARM_NAME_CRC32CW
        };
#endif
        uint32_t fixed = canonical_word & UINT32_C(0xfff0f0f0);
        size_t operation;

        for (operation = 0u; operation < 6u; ++operation) {
            if (fixed == crc_values[operation]) {
                break;
            }
        }
        if (operation < 6u) {
            unsigned rn = (canonical_word >> 16) & 15u;
            unsigned rd = (canonical_word >> 8) & 15u;
            unsigned rm = canonical_word & 15u;

            *recognized = 1;
            /* PC is architecturally UNPREDICTABLE in every T32 CRC32
             * operand position.  SP and LR retain their ordinary R13/R14
             * encodings and are accepted. */
            if (rd == 15u || rn == 15u || rm == 15u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
#if !USE_EXTRA_OPCODES
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            instruction->name_id = crc_names[operation];
            t32_append_sized_register(
                instruction, rd, 4u, CDISASM_OPERAND_ACCESS_WRITE);
            t32_append_sized_register(
                instruction, rn, 4u, CDISASM_OPERAND_ACCESS_READ);
            t32_append_sized_register(
                instruction, rm,
                (uint8_t)(UINT32_C(1) << (operation % 3u)),
                CDISASM_OPERAND_ACCESS_READ);
            cdisasm_arm_requirements_set_legacy(
                required_capabilities, CDISASM_ARM_CAP_V8);
            (void)cdisasm_arm_requirements_add_feature(
                required_capabilities, CDISASM_ARM_FEATURE_CRC32);
            return CDISASM_STATUS_OK;
#endif
        }
    }
    if (first == UINT16_C(0xf78f)
        && second >= UINT16_C(0x8001)
        && second <= UINT16_C(0x8003)) {
        *recognized = 1;
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = second == UINT16_C(0x8001)
            ? CDISASM_ARM_NAME_DCPS1
            : second == UINT16_C(0x8002)
                ? CDISASM_ARM_NAME_DCPS2 : CDISASM_ARM_NAME_DCPS3;
        instruction->opcode_groups |=
            CDISASM_GROUP_INTERRUPT | CDISASM_GROUP_PRIVILEGED;
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xf3c0)
        && second == UINT16_C(0x8f00)) {
        unsigned rm = first & 15u;

        *recognized = 1;
        if (rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)rm;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_BXJ;
        instruction->opcode_groups |= CDISASM_GROUP_JUMP;
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xf3d0)
        && (second & UINT16_C(0xff00)) == UINT16_C(0x8f00)) {
        unsigned rn = first & 15u;
        uint8_t immediate = (uint8_t)(second & 255u);

        *recognized = 1;
        if (rn != 14u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->opcode_groups |= CDISASM_GROUP_RETURN
            | CDISASM_GROUP_INTERRUPT_RETURN
            | CDISASM_GROUP_PRIVILEGED;
        if (immediate == 0u) {
            instruction->name_id = CDISASM_ARM_NAME_ERET;
        } else {
            instruction->name_id = CDISASM_ARM_NAME_SUBS;
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
            t32_append_register(
                instruction, 15u, CDISASM_OPERAND_ACCESS_WRITE);
            t32_append_register(
                instruction, 14u, CDISASM_OPERAND_ACCESS_READ);
            t32_append_immediate(instruction, immediate, 1u);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xf7e0)
        && (second & UINT16_C(0xf000)) == UINT16_C(0x8000)) {
        uint16_t immediate = (uint16_t)(((first & 15u) << 12)
            | (second & UINT16_C(0x0fff)));

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_HVC;
        instruction->opcode_groups |=
            CDISASM_GROUP_INTERRUPT | CDISASM_GROUP_PRIVILEGED;
        t32_append_immediate(instruction, immediate, 2u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xf7f0)
        && second == UINT16_C(0x8000)) {
        uint8_t immediate = (uint8_t)(first & 15u);

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_SMC;
        instruction->opcode_groups |=
            CDISASM_GROUP_INTERRUPT | CDISASM_GROUP_PRIVILEGED;
        t32_append_immediate(instruction, immediate, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xf7f0)
        && (second & UINT16_C(0xf000)) == UINT16_C(0xa000)) {
        uint16_t immediate = (uint16_t)(((first & 15u) << 12)
            | (second & UINT16_C(0x0fff)));

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_UDF;
        instruction->opcode_groups |= CDISASM_GROUP_INTERRUPT;
        t32_append_immediate(instruction, immediate, 2u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((first & UINT16_C(0xfbf0)) == UINT16_C(0xf240)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf2c0))) {
        unsigned rd;
        uint16_t immediate;

        *recognized = 1;
        if ((second & UINT16_C(0x8000)) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        rd = (second >> 8) & 15u;
        if (rd == 13u || rd == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        immediate = (uint16_t)(((first & 15u) << 12)
            | (((first >> 10) & 1u) << 11)
            | (((second >> 12) & 7u) << 8)
            | (second & 255u));
#if !USE_EXTRA_OPCODES
        (void)rd;
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = (first & UINT16_C(0x0080)) != 0u
            ? CDISASM_ARM_NAME_MOVT : CDISASM_ARM_NAME_MOVW;
        t32_append_register(
            instruction, rd,
            instruction->name_id == CDISASM_ARM_NAME_MOVT
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_immediate(instruction, immediate, 2);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xff80)) == UINT16_C(0xfa00)
        && (second & UINT16_C(0xf0f0)) == UINT16_C(0xf000)) {
        static const cdisasm_arm_name_id names[2][4] = {
            {CDISASM_ARM_NAME_LSL, CDISASM_ARM_NAME_LSR,
                CDISASM_ARM_NAME_ASR, CDISASM_ARM_NAME_ROR},
            {CDISASM_ARM_NAME_LSLS, CDISASM_ARM_NAME_LSRS,
                CDISASM_ARM_NAME_ASRS, CDISASM_ARM_NAME_RORS}
        };
        unsigned set_flags = (first >> 4) & 1u;
        unsigned operation = (first >> 5) & 3u;
        unsigned rd = (second >> 8) & 15u;
        unsigned rm = first & 15u;
        unsigned rs = second & 15u;

        *recognized = 1;
        if (rd == 13u || rd == 15u || rm == 13u || rm == 15u
            || rs == 13u || rs == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)set_flags;
        (void)operation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = names[set_flags][operation];
        instruction->form_id = set_flags
            ? UINT16_C(2109) : UINT16_C(2110);
        if (set_flags != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(
            instruction, rs, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xff80)) == UINT16_C(0xfa00)
        && (second & UINT16_C(0xf0c0)) == UINT16_C(0xf080)) {
        static const cdisasm_arm_name_id accumulate_names[6] = {
            CDISASM_ARM_NAME_SXTAH, CDISASM_ARM_NAME_UXTAH,
            CDISASM_ARM_NAME_SXTAB16, CDISASM_ARM_NAME_UXTAB16,
            CDISASM_ARM_NAME_SXTAB, CDISASM_ARM_NAME_UXTAB
        };
        static const cdisasm_arm_name_id extend_names[6] = {
            CDISASM_ARM_NAME_SXTH, CDISASM_ARM_NAME_UXTH,
            CDISASM_ARM_NAME_SXTB16, CDISASM_ARM_NAME_UXTB16,
            CDISASM_ARM_NAME_SXTB, CDISASM_ARM_NAME_UXTB
        };
        unsigned operation = (first >> 4) & 7u;
        unsigned rn = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned rm = second & 15u;
        unsigned rotation = ((second >> 4) & 3u) * 8u;
        int extend_alias = rn == 15u;

        if (operation < 6u) {
            *recognized = 1;
            if (rd == 13u || rd == 15u || rn == 13u
                || rm == 13u || rm == 15u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
#if !USE_EXTRA_OPCODES
            (void)accumulate_names;
            (void)extend_names;
            (void)rotation;
            (void)extend_alias;
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            cdisasm_arm_operand *rotated;

            instruction->name_id = extend_alias
                ? extend_names[operation] : accumulate_names[operation];
            t32_append_register(
                instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
            if (!extend_alias) {
                t32_append_register(
                    instruction, rn, CDISASM_OPERAND_ACCESS_READ);
            }
            rotated = t32_append_register(
                instruction, rm, CDISASM_OPERAND_ACCESS_READ);
            if (rotated != NULL && rotation != 0u) {
                rotated->shift_type = CDISASM_ARM_SHIFT_ROR;
                rotated->shift_amount = (uint8_t)rotation;
            }
            cdisasm_arm_requirements_set_legacy(
                required_capabilities, CDISASM_ARM_CAP_V6);
            return CDISASM_STATUS_OK;
#endif
        }
    }
    if ((first & UINT16_C(0xffe0)) == UINT16_C(0xfa80)
        && (second & UINT16_C(0xf080)) == UINT16_C(0xf000)) {
        static const cdisasm_arm_name_id byte_names[8] = {
            CDISASM_ARM_NAME_SADD8, CDISASM_ARM_NAME_QADD8,
            CDISASM_ARM_NAME_SHADD8, CDISASM_ARM_NAME_NONE,
            CDISASM_ARM_NAME_UADD8, CDISASM_ARM_NAME_UQADD8,
            CDISASM_ARM_NAME_UHADD8, CDISASM_ARM_NAME_NONE
        };
        static const cdisasm_arm_name_id halfword_names[8] = {
            CDISASM_ARM_NAME_SADD16, CDISASM_ARM_NAME_QADD16,
            CDISASM_ARM_NAME_SHADD16, CDISASM_ARM_NAME_NONE,
            CDISASM_ARM_NAME_UADD16, CDISASM_ARM_NAME_UQADD16,
            CDISASM_ARM_NAME_UHADD16, CDISASM_ARM_NAME_NONE
        };
        const cdisasm_arm_name_id *names =
            (first & UINT16_C(0x0010)) != 0u
                ? halfword_names : byte_names;
        unsigned operation = (second >> 4) & 7u;

        if (names[operation] != CDISASM_ARM_NAME_NONE) {
            unsigned rn = first & 15u;
            unsigned rd = (second >> 8) & 15u;
            unsigned rm = second & 15u;

            *recognized = 1;
            if (rd == 13u || rd == 15u || rn == 13u || rn == 15u
                || rm == 13u || rm == 15u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
#if !USE_EXTRA_OPCODES
            (void)byte_names;
            (void)halfword_names;
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            instruction->name_id = names[operation];
            t32_append_register(
                instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
            t32_append_register(
                instruction, rn, CDISASM_OPERAND_ACCESS_READ);
            t32_append_register(
                instruction, rm, CDISASM_OPERAND_ACCESS_READ);
            cdisasm_arm_requirements_set_legacy(
                required_capabilities, CDISASM_ARM_CAP_V6);
            return CDISASM_STATUS_OK;
#endif
        }
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfaa0)
        && (second & UINT16_C(0xf080)) == UINT16_C(0xf000)) {
        static const cdisasm_arm_name_id names[8] = {
            CDISASM_ARM_NAME_SASX, CDISASM_ARM_NAME_QASX,
            CDISASM_ARM_NAME_SHASX, CDISASM_ARM_NAME_NONE,
            CDISASM_ARM_NAME_UASX, CDISASM_ARM_NAME_UQASX,
            CDISASM_ARM_NAME_UHASX, CDISASM_ARM_NAME_NONE
        };
        unsigned operation = (second >> 4) & 7u;

        if (names[operation] != CDISASM_ARM_NAME_NONE) {
            unsigned rn = first & 15u;
            unsigned rd = (second >> 8) & 15u;
            unsigned rm = second & 15u;

            *recognized = 1;
            if (rd == 13u || rd == 15u || rn == 13u || rn == 15u
                || rm == 13u || rm == 15u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
#if !USE_EXTRA_OPCODES
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            instruction->name_id = names[operation];
            t32_append_register(
                instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
            t32_append_register(
                instruction, rn, CDISASM_OPERAND_ACCESS_READ);
            t32_append_register(
                instruction, rm, CDISASM_OPERAND_ACCESS_READ);
            cdisasm_arm_requirements_set_legacy(
                required_capabilities, CDISASM_ARM_CAP_V6);
            return CDISASM_STATUS_OK;
#endif
        }
    }
    if ((first & UINT16_C(0xffe0)) == UINT16_C(0xfac0)
        && (second & UINT16_C(0xf080)) == UINT16_C(0xf000)) {
        static const cdisasm_arm_name_id byte_names[8] = {
            CDISASM_ARM_NAME_SSUB8, CDISASM_ARM_NAME_QSUB8,
            CDISASM_ARM_NAME_SHSUB8, CDISASM_ARM_NAME_NONE,
            CDISASM_ARM_NAME_USUB8, CDISASM_ARM_NAME_UQSUB8,
            CDISASM_ARM_NAME_UHSUB8, CDISASM_ARM_NAME_NONE
        };
        static const cdisasm_arm_name_id halfword_names[8] = {
            CDISASM_ARM_NAME_SSUB16, CDISASM_ARM_NAME_QSUB16,
            CDISASM_ARM_NAME_SHSUB16, CDISASM_ARM_NAME_NONE,
            CDISASM_ARM_NAME_USUB16, CDISASM_ARM_NAME_UQSUB16,
            CDISASM_ARM_NAME_UHSUB16, CDISASM_ARM_NAME_NONE
        };
        const cdisasm_arm_name_id *names =
            (first & UINT16_C(0x0010)) != 0u
                ? halfword_names : byte_names;
        unsigned operation = (second >> 4) & 7u;

        if (names[operation] != CDISASM_ARM_NAME_NONE) {
            unsigned rn = first & 15u;
            unsigned rd = (second >> 8) & 15u;
            unsigned rm = second & 15u;

            *recognized = 1;
            if (rd == 13u || rd == 15u || rn == 13u || rn == 15u
                || rm == 13u || rm == 15u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
#if !USE_EXTRA_OPCODES
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            instruction->name_id = names[operation];
            t32_append_register(
                instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
            t32_append_register(
                instruction, rn, CDISASM_OPERAND_ACCESS_READ);
            t32_append_register(
                instruction, rm, CDISASM_OPERAND_ACCESS_READ);
            cdisasm_arm_requirements_set_legacy(
                required_capabilities, CDISASM_ARM_CAP_V6);
            return CDISASM_STATUS_OK;
#endif
        }
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfae0)
        && (second & UINT16_C(0xf080)) == UINT16_C(0xf000)) {
        static const cdisasm_arm_name_id names[8] = {
            CDISASM_ARM_NAME_SSAX, CDISASM_ARM_NAME_QSAX,
            CDISASM_ARM_NAME_SHSAX, CDISASM_ARM_NAME_NONE,
            CDISASM_ARM_NAME_USAX, CDISASM_ARM_NAME_UQSAX,
            CDISASM_ARM_NAME_UHSAX, CDISASM_ARM_NAME_NONE
        };
        unsigned operation = (second >> 4) & 7u;

        if (names[operation] != CDISASM_ARM_NAME_NONE) {
            unsigned rn = first & 15u;
            unsigned rd = (second >> 8) & 15u;
            unsigned rm = second & 15u;

            *recognized = 1;
            if (rd == 13u || rd == 15u || rn == 13u || rn == 15u
                || rm == 13u || rm == 15u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
#if !USE_EXTRA_OPCODES
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            instruction->name_id = names[operation];
            t32_append_register(
                instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
            t32_append_register(
                instruction, rn, CDISASM_OPERAND_ACCESS_READ);
            t32_append_register(
                instruction, rm, CDISASM_OPERAND_ACCESS_READ);
            cdisasm_arm_requirements_set_legacy(
                required_capabilities, CDISASM_ARM_CAP_V6);
            return CDISASM_STATUS_OK;
#endif
        }
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfa80)
        && (second & UINT16_C(0xf0c0)) == UINT16_C(0xf080)) {
        static const cdisasm_arm_name_id names[4] = {
            CDISASM_ARM_NAME_QADD, CDISASM_ARM_NAME_QDADD,
            CDISASM_ARM_NAME_QSUB, CDISASM_ARM_NAME_QDSUB
        };
        unsigned operation = (second >> 4) & 3u;
        unsigned rn = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned rm = second & 15u;

        *recognized = 1;
        if (rd == 13u || rd == 15u || rn == 13u || rn == 15u
            || rm == 13u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)operation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = names[operation];
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfa90)
        && (second & UINT16_C(0xf0c0)) == UINT16_C(0xf080)) {
        static const cdisasm_arm_name_id names[4] = {
            CDISASM_ARM_NAME_REV, CDISASM_ARM_NAME_REV16,
            CDISASM_ARM_NAME_RBIT, CDISASM_ARM_NAME_REVSH
        };
        unsigned operation = (second >> 4) & 3u;
        unsigned encoded_rm = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned rm = second & 15u;

        *recognized = 1;
        if (encoded_rm != rm || rd == 13u || rd == 15u
            || rm == 13u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)operation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = names[operation];
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfaa0)
        && (second & UINT16_C(0xf0f0)) == UINT16_C(0xf080)) {
        unsigned rn = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned rm = second & 15u;

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)rn;
        (void)rd;
        (void)rm;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_SEL;
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfab0)
        && (second & UINT16_C(0xf0f0)) == UINT16_C(0xf080)) {
        unsigned encoded_rm = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned rm = second & 15u;

        *recognized = 1;
        if (encoded_rm != rm || rd == 13u || rd == 15u
            || rm == 13u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_CLZ;
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfb10)
        && (second & UINT16_C(0x00c0)) == 0u) {
        static const cdisasm_arm_name_id names[4] = {
            CDISASM_ARM_NAME_SMLABB, CDISASM_ARM_NAME_SMLABT,
            CDISASM_ARM_NAME_SMLATB, CDISASM_ARM_NAME_SMLATT
        };
        static const cdisasm_arm_name_id multiply_names[4] = {
            CDISASM_ARM_NAME_SMULBB, CDISASM_ARM_NAME_SMULBT,
            CDISASM_ARM_NAME_SMULTB, CDISASM_ARM_NAME_SMULTT
        };
        unsigned rn = first & 15u;
        unsigned ra = (second >> 12) & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned operation = (second >> 4) & 3u;
        unsigned rm = second & 15u;

        *recognized = 1;
        if (rd == 13u || rd == 15u || rn == 13u || rn == 15u
            || rm == 13u || rm == 15u || ra == 13u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)multiply_names;
        (void)operation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = ra == 15u
            ? multiply_names[operation] : names[operation];
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        if (ra != 15u) {
            t32_append_register(
                instruction, ra, CDISASM_OPERAND_ACCESS_READ);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfb20)
        && (second & UINT16_C(0x00e0)) == 0u) {
        static const cdisasm_arm_name_id accumulate_names[2] = {
            CDISASM_ARM_NAME_SMLAD, CDISASM_ARM_NAME_SMLADX
        };
        static const cdisasm_arm_name_id multiply_names[2] = {
            CDISASM_ARM_NAME_SMUAD, CDISASM_ARM_NAME_SMUADX
        };
        unsigned rn = first & 15u;
        unsigned ra = (second >> 12) & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned exchange = (second >> 4) & 1u;
        unsigned rm = second & 15u;

        *recognized = 1;
        if (rd == 13u || rd == 15u || rn == 13u || rn == 15u
            || rm == 13u || rm == 15u || ra == 13u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)accumulate_names;
        (void)multiply_names;
        (void)exchange;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = ra == 15u
            ? multiply_names[exchange] : accumulate_names[exchange];
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        if (ra != 15u) {
            t32_append_register(
                instruction, ra, CDISASM_OPERAND_ACCESS_READ);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfb30)
        && (second & UINT16_C(0x00e0)) == 0u) {
        static const cdisasm_arm_name_id accumulate_names[2] = {
            CDISASM_ARM_NAME_SMLAWB, CDISASM_ARM_NAME_SMLAWT
        };
        static const cdisasm_arm_name_id multiply_names[2] = {
            CDISASM_ARM_NAME_SMULWB, CDISASM_ARM_NAME_SMULWT
        };
        unsigned rn = first & 15u;
        unsigned ra = (second >> 12) & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned top_half = (second >> 4) & 1u;
        unsigned rm = second & 15u;

        *recognized = 1;
        if (rd == 13u || rd == 15u || rn == 13u || rn == 15u
            || rm == 13u || rm == 15u || ra == 13u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)accumulate_names;
        (void)multiply_names;
        (void)top_half;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = ra == 15u
            ? multiply_names[top_half] : accumulate_names[top_half];
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        if (ra != 15u) {
            t32_append_register(
                instruction, ra, CDISASM_OPERAND_ACCESS_READ);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfb40)
        && (second & UINT16_C(0x00e0)) == 0u) {
        static const cdisasm_arm_name_id accumulate_names[2] = {
            CDISASM_ARM_NAME_SMLSD, CDISASM_ARM_NAME_SMLSDX
        };
        static const cdisasm_arm_name_id multiply_names[2] = {
            CDISASM_ARM_NAME_SMUSD, CDISASM_ARM_NAME_SMUSDX
        };
        unsigned rn = first & 15u;
        unsigned ra = (second >> 12) & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned exchange = (second >> 4) & 1u;
        unsigned rm = second & 15u;

        *recognized = 1;
        if (rd == 13u || rd == 15u || rn == 13u || rn == 15u
            || rm == 13u || rm == 15u || ra == 13u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)accumulate_names;
        (void)multiply_names;
        (void)exchange;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = ra == 15u
            ? multiply_names[exchange] : accumulate_names[exchange];
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        if (ra != 15u) {
            t32_append_register(
                instruction, ra, CDISASM_OPERAND_ACCESS_READ);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfb50)
        && (second & UINT16_C(0x00e0)) == 0u) {
        static const cdisasm_arm_name_id accumulate_names[2] = {
            CDISASM_ARM_NAME_SMMLA, CDISASM_ARM_NAME_SMMLAR
        };
        static const cdisasm_arm_name_id multiply_names[2] = {
            CDISASM_ARM_NAME_SMMUL, CDISASM_ARM_NAME_SMMULR
        };
        unsigned rn = first & 15u;
        unsigned ra = (second >> 12) & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned round = (second >> 4) & 1u;
        unsigned rm = second & 15u;

        *recognized = 1;
        if (rd == 13u || rd == 15u || rn == 13u || rn == 15u
            || rm == 13u || rm == 15u || ra == 13u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)accumulate_names;
        (void)multiply_names;
        (void)round;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = ra == 15u
            ? multiply_names[round] : accumulate_names[round];
        t32_append_register(instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        if (ra != 15u) {
            t32_append_register(instruction, ra, CDISASM_OPERAND_ACCESS_READ);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfb60)
        && (second & UINT16_C(0x00e0)) == 0u) {
        static const cdisasm_arm_name_id names[2] = {
            CDISASM_ARM_NAME_SMMLS, CDISASM_ARM_NAME_SMMLSR
        };
        unsigned rn = first & 15u;
        unsigned ra = (second >> 12) & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned round = (second >> 4) & 1u;
        unsigned rm = second & 15u;

        *recognized = 1;
        if (rd == 13u || rd == 15u || rn == 13u || rn == 15u
            || rm == 13u || rm == 15u || ra == 13u || ra == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)round;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = names[round];
        t32_append_register(instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(instruction, ra, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfb70)
        && (second & UINT16_C(0x00f0)) == 0u) {
        unsigned rn = first & 15u;
        unsigned ra = (second >> 12) & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned rm = second & 15u;

        *recognized = 1;
        if (rd == 13u || rd == 15u || rn == 13u || rn == 15u
            || rm == 13u || rm == 15u || ra == 13u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = ra == 15u
            ? CDISASM_ARM_NAME_USAD8 : CDISASM_ARM_NAME_USADA8;
        t32_append_register(instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        if (ra != 15u) {
            t32_append_register(instruction, ra, CDISASM_OPERAND_ACCESS_READ);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((first & UINT16_C(0xfff0)) == UINT16_C(0xfb90)
            || (first & UINT16_C(0xfff0)) == UINT16_C(0xfbb0))
        && (second & UINT16_C(0xf0f0)) == UINT16_C(0xf0f0)) {
        unsigned rn = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned rm = second & 15u;

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)rn;
        (void)rd;
        (void)rm;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = (first & UINT16_C(0x0020)) != 0u
            ? CDISASM_ARM_NAME_UDIV : CDISASM_ARM_NAME_SDIV;
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xfff0)) == UINT16_C(0xfab0)
        && (second & UINT16_C(0xf0f0)) == UINT16_C(0xf080)) {
        unsigned rm = first & 15u;
        unsigned rd = (second >> 8) & 15u;

        *recognized = 1;
        if ((second & 15u) != rm) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)rd;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_CLZ;
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rm, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (canonical_word == UINT32_C(0xf3bf8f2f)) {
        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_CLREX;
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if (first == UINT16_C(0xf3bf)
        && ((second & UINT16_C(0xfff0)) == UINT16_C(0x8f40)
            || (second & UINT16_C(0xfff0)) == UINT16_C(0x8f50)
            || (second & UINT16_C(0xfff0)) == UINT16_C(0x8f60))) {
        unsigned option = second & 15u;

        *recognized = 1;
        if ((second & UINT16_C(0xfff0)) == UINT16_C(0x8f60)
            && option != 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = (second & UINT16_C(0xfff0))
                == UINT16_C(0x8f40)
            ? (option == 0u ? CDISASM_ARM_NAME_SSBB
                : option == 4u ? CDISASM_ARM_NAME_PSSBB
                               : CDISASM_ARM_NAME_DSB)
            : (second & UINT16_C(0xfff0)) == UINT16_C(0x8f50)
                ? CDISASM_ARM_NAME_DMB : CDISASM_ARM_NAME_ISB;
        if (instruction->name_id != CDISASM_ARM_NAME_SSBB
            && instruction->name_id != CDISASM_ARM_NAME_PSSBB) {
            t32_append_immediate(instruction, option, 1);
        }
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((first & UINT16_C(0xfbf0)) == UINT16_C(0xf000)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf010)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf020)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf030))
        && (second & UINT16_C(0x8000)) == 0u) {
        unsigned operation = (first >> 4) & 15u;
        unsigned rn = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        uint16_t encoded = (uint16_t)((((first >> 10) & 1u) << 11)
            | (((second >> 12) & 7u) << 8) | (second & 255u));
        uint32_t immediate = 0u;
        int test_alias = operation == 1u && rd == 15u;

        *recognized = 1;
        if (!t32_expand_modified_immediate(encoded, &immediate)
            || rn == 13u || rn == 15u
            || (!test_alias && (rd == 13u || rd == 15u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = test_alias ? CDISASM_ARM_NAME_TST
            : operation == 0u ? CDISASM_ARM_NAME_AND
            : operation == 1u ? CDISASM_ARM_NAME_ANDS
            : operation == 2u ? CDISASM_ARM_NAME_BIC
                              : CDISASM_ARM_NAME_BICS;
        if (test_alias) {
            t32_append_register(
                instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        } else {
            t32_append_register(
                instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
            t32_append_register(
                instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        }
        t32_append_immediate(instruction, immediate, 4u);
        if ((operation & 1u) != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((first & UINT16_C(0xfbf0)) == UINT16_C(0xf040)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf050)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf060)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf070)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf080)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf090))
        && (second & UINT16_C(0x8000)) == 0u) {
        unsigned operation = (first >> 4) & 15u;
        unsigned rn = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        uint16_t encoded = (uint16_t)((((first >> 10) & 1u) << 11)
            | (((second >> 12) & 7u) << 8) | (second & 255u));
        uint32_t immediate = 0u;
        int move_alias = rn == 15u && operation <= 7u;
        int test_alias = operation == 9u && rd == 15u;

        *recognized = 1;
        if (!t32_expand_modified_immediate(encoded, &immediate)
            || rn == 13u || (!move_alias && rn == 15u)
            || (!test_alias && (rd == 13u || rd == 15u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = move_alias
            ? (operation == 4u ? CDISASM_ARM_NAME_MOV
                : operation == 5u ? CDISASM_ARM_NAME_MOVS
                : operation == 6u ? CDISASM_ARM_NAME_MVN
                                  : CDISASM_ARM_NAME_MVNS)
            : test_alias ? CDISASM_ARM_NAME_TEQ
            : operation == 4u ? CDISASM_ARM_NAME_ORR
            : operation == 5u ? CDISASM_ARM_NAME_ORRS
            : operation == 6u ? CDISASM_ARM_NAME_ORN
            : operation == 7u ? CDISASM_ARM_NAME_ORNS
            : operation == 8u ? CDISASM_ARM_NAME_EOR
                              : CDISASM_ARM_NAME_EORS;
        if (test_alias) {
            t32_append_register(
                instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        } else {
            t32_append_register(
                instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
            if (!move_alias) {
                t32_append_register(
                    instruction, rn, CDISASM_OPERAND_ACCESS_READ);
            }
        }
        t32_append_immediate(instruction, immediate, 4u);
        if ((operation & 1u) != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((first & UINT16_C(0xfbf0)) == UINT16_C(0xf100)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf110))
        && (second & UINT16_C(0x8000)) == 0u) {
        unsigned set_flags = (first >> 4) & 1u;
        unsigned rn = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        uint16_t encoded = (uint16_t)((((first >> 10) & 1u) << 11)
            | (((second >> 12) & 7u) << 8) | (second & 255u));
        uint32_t immediate = 0u;
        int compare_alias = set_flags != 0u && rd == 15u;

        *recognized = 1;
        if (!t32_expand_modified_immediate(encoded, &immediate)
            || rn == 15u
            || (!compare_alias && (rd == 13u || rd == 15u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = compare_alias ? CDISASM_ARM_NAME_CMN
            : set_flags != 0u ? CDISASM_ARM_NAME_ADDS
                              : CDISASM_ARM_NAME_ADD;
        if (!compare_alias) {
            t32_append_register(
                instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        }
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_immediate(instruction, immediate, 4u);
        if (set_flags != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((first & UINT16_C(0xfbf0)) == UINT16_C(0xf140)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf150)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf160)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf170))
        && (second & UINT16_C(0x8000)) == 0u) {
        unsigned operation = (first >> 4) & 3u;
        unsigned rn = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        uint16_t encoded = (uint16_t)((((first >> 10) & 1u) << 11)
            | (((second >> 12) & 7u) << 8) | (second & 255u));
        uint32_t immediate = 0u;

        *recognized = 1;
        if (!t32_expand_modified_immediate(encoded, &immediate)
            || rn >= 13u || rd >= 13u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)immediate;
        (void)operation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = operation == 0u ? CDISASM_ARM_NAME_ADC
            : operation == 1u ? CDISASM_ARM_NAME_ADCS
            : operation == 2u ? CDISASM_ARM_NAME_SBC
                              : CDISASM_ARM_NAME_SBCS;
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_immediate(instruction, immediate, 4u);
        if ((operation & 1u) != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((first & UINT16_C(0xfbf0)) == UINT16_C(0xf1a0)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf1b0)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf1c0)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf1d0))
        && (second & UINT16_C(0x8000)) == 0u) {
        unsigned operation = (first >> 4) & 15u;
        unsigned rn = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        uint16_t encoded = (uint16_t)((((first >> 10) & 1u) << 11)
            | (((second >> 12) & 7u) << 8) | (second & 255u));
        uint32_t immediate = 0u;
        int compare_alias = operation == 11u && rd == 15u;

        *recognized = 1;
        if (!t32_expand_modified_immediate(encoded, &immediate)
            || rn == 15u || (operation >= 12u && rn == 13u)
            || (!compare_alias && (rd == 13u || rd == 15u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = compare_alias ? CDISASM_ARM_NAME_CMP
            : operation == 10u ? CDISASM_ARM_NAME_SUB
            : operation == 11u ? CDISASM_ARM_NAME_SUBS
            : operation == 12u ? CDISASM_ARM_NAME_RSB
                              : CDISASM_ARM_NAME_RSBS;
        if (!compare_alias) {
            t32_append_register(
                instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        }
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        t32_append_immediate(instruction, immediate, 4u);
        if ((operation & 1u) != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((first & UINT16_C(0xfbf0)) == UINT16_C(0xf200)
            || (first & UINT16_C(0xfbf0)) == UINT16_C(0xf2a0))
        && (second & UINT16_C(0x8000)) == 0u) {
        unsigned subtract = (first & UINT16_C(0x0080)) != 0u;
        unsigned rn = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        uint16_t immediate = (uint16_t)((((first >> 10) & 1u) << 11)
            | (((second >> 12) & 7u) << 8) | (second & 255u));
        int address_alias = rn == 15u;

        *recognized = 1;
        if (rd == 13u || rd == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)address;
        (void)immediate;
        (void)subtract;
        (void)address_alias;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = address_alias ? CDISASM_ARM_NAME_ADR
            : subtract != 0u ? CDISASM_ARM_NAME_SUB
                             : CDISASM_ARM_NAME_ADD;
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        if (address_alias) {
            uint64_t base = (address + UINT64_C(4)) & ~UINT64_C(3);
            int64_t displacement = subtract != 0u
                ? -(int64_t)immediate : (int64_t)immediate;
            cdisasm_arm_operand *operand = t32_append_immediate(
                instruction, base + (uint64_t)displacement, 4u);

            if (operand != NULL) {
                operand->address = (uint64_t)displacement;
                operand->flags = CDISASM_OPERAND_FLAG_PC_RELATIVE
                    | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
            }
        } else {
            t32_append_register(
                instruction, rn, CDISASM_OPERAND_ACCESS_READ);
            t32_append_immediate(instruction, immediate, 2u);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((first & UINT16_C(0xfff0)) == UINT16_C(0xf320)
            || (first & UINT16_C(0xfff0)) == UINT16_C(0xf3a0))
        && (second & UINT16_C(0xf0f0)) == 0u) {
        unsigned is_unsigned = (first & UINT16_C(0x0080)) != 0u;
        unsigned rn = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned saturation = second & 15u;

        *recognized = 1;
        if (rd == 13u || rd == 15u || rn == 13u || rn == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)is_unsigned;
        (void)saturation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = is_unsigned != 0u
            ? CDISASM_ARM_NAME_USAT16 : CDISASM_ARM_NAME_SSAT16;
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_immediate(
            instruction, saturation + (is_unsigned == 0u), 1u);
        t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((first & UINT16_C(0xffe0)) == UINT16_C(0xf300)
            || (first & UINT16_C(0xffe0)) == UINT16_C(0xf320)
            || (first & UINT16_C(0xffe0)) == UINT16_C(0xf380)
            || (first & UINT16_C(0xffe0)) == UINT16_C(0xf3a0))
        && (second & UINT16_C(0x8020)) == 0u) {
        unsigned is_unsigned = (first & UINT16_C(0x0080)) != 0u;
        unsigned asr = (first & UINT16_C(0x0020)) != 0u;
        unsigned rn = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned shift = (((second >> 12) & 7u) << 2)
            | ((second >> 6) & 3u);
        unsigned saturation = second & 31u;

        *recognized = 1;
        if (rd == 13u || rd == 15u || rn == 13u || rn == 15u
            || (asr != 0u && shift == 0u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)is_unsigned;
        (void)saturation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        cdisasm_arm_operand *shifted;

        instruction->name_id = is_unsigned != 0u
            ? CDISASM_ARM_NAME_USAT : CDISASM_ARM_NAME_SSAT;
        t32_append_register(
            instruction, rd, CDISASM_OPERAND_ACCESS_WRITE);
        t32_append_immediate(
            instruction, saturation + (is_unsigned == 0u), 1u);
        shifted = t32_append_register(
            instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        if (shifted != NULL && (asr != 0u || shift != 0u)) {
            shifted->shift_type = asr != 0u
                ? CDISASM_ARM_SHIFT_ASR : CDISASM_ARM_SHIFT_LSL;
            shifted->shift_amount = (uint8_t)shift;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((first & UINT16_C(0xffe0)) == UINT16_C(0xf340)
            || (first & UINT16_C(0xffe0)) == UINT16_C(0xf360)
            || (first & UINT16_C(0xffe0)) == UINT16_C(0xf3c0))
        && (second & UINT16_C(0x8020)) == 0u) {
        unsigned operation = first & UINT16_C(0x00e0);
        unsigned rn = first & 15u;
        unsigned rd = (second >> 8) & 15u;
        unsigned lsb = (((second >> 12) & 7u) << 2)
            | ((second >> 6) & 3u);
        unsigned encoded_width = second & 31u;
        unsigned width = operation == UINT16_C(0x0060)
            ? encoded_width - lsb + 1u : encoded_width + 1u;
        int clear_alias = operation == UINT16_C(0x0060) && rn == 15u;

        *recognized = 1;
        if (rd == 13u || rd == 15u
            || (rn == 13u || (rn == 15u && !clear_alias))
            || (operation == UINT16_C(0x0060)
                ? encoded_width < lsb : lsb + width > 32u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)width;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = clear_alias ? CDISASM_ARM_NAME_BFC
            : operation == UINT16_C(0x0040) ? CDISASM_ARM_NAME_SBFX
            : operation == UINT16_C(0x0060) ? CDISASM_ARM_NAME_BFI
                                            : CDISASM_ARM_NAME_UBFX;
        t32_append_register(
            instruction, rd,
            operation == UINT16_C(0x0060)
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE);
        if (!clear_alias) {
            t32_append_register(
                instruction, rn, CDISASM_OPERAND_ACCESS_READ);
        }
        t32_append_immediate(instruction, lsb, 1u);
        t32_append_immediate(instruction, width, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xf800)) == UINT16_C(0xf000)
        && (second & UINT16_C(0xd000)) == UINT16_C(0x8000)) {
        unsigned condition = (first >> 6) & 15u;
        uint32_t encoded = ((uint32_t)((first >> 10) & 1u) << 20)
            | ((uint32_t)((second >> 11) & 1u) << 19)
            | ((uint32_t)((second >> 13) & 1u) << 18)
            | ((uint32_t)(first & 63u) << 12)
            | ((uint32_t)(second & UINT16_C(0x07ff)) << 1);
        int64_t displacement = t32_sign_extend(encoded, 21u);

        *recognized = 1;
        if (condition >= CDISASM_ARM_CONDITION_AL) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)address;
        (void)displacement;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_B;
        instruction->condition = (cdisasm_arm_condition)condition;
        instruction->opcode_groups |= CDISASM_GROUP_JUMP
            | CDISASM_GROUP_CONDITIONAL;
        t32_append_relative_target(
            instruction,
            address + UINT64_C(4) + (uint64_t)displacement,
            displacement);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xf800)) == UINT16_C(0xf000)
        && (second & UINT16_C(0xd000)) == UINT16_C(0xc000)) {
        uint32_t sign = (first >> 10) & 1u;
        uint32_t j1 = (second >> 13) & 1u;
        uint32_t j2 = (second >> 11) & 1u;
        uint32_t i1 = (j1 ^ sign) ^ 1u;
        uint32_t i2 = (j2 ^ sign) ^ 1u;
        uint32_t encoded = (sign << 24) | (i1 << 23) | (i2 << 22)
            | ((uint32_t)(first & UINT16_C(0x03ff)) << 12)
            | ((uint32_t)(second & UINT16_C(0x07ff)) << 1);
        int64_t displacement = t32_sign_extend(encoded, 25u);
        uint64_t base = (address + UINT64_C(4)) & ~UINT64_C(3);

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)base;
        (void)displacement;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_BLX;
        instruction->opcode_groups |= CDISASM_GROUP_CALL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_LINK;
        t32_append_relative_target(
            instruction, base + (uint64_t)displacement, displacement);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((first & UINT16_C(0xf800)) == UINT16_C(0xf000)
        && (second & UINT16_C(0xd000)) == UINT16_C(0x9000)) {
        uint32_t sign = (first >> 10) & 1u;
        uint32_t j1 = (second >> 13) & 1u;
        uint32_t j2 = (second >> 11) & 1u;
        uint32_t i1 = (j1 ^ sign) ^ 1u;
        uint32_t i2 = (j2 ^ sign) ^ 1u;
        uint32_t encoded = (sign << 24) | (i1 << 23) | (i2 << 22)
            | ((uint32_t)(first & UINT16_C(0x03ff)) << 12)
            | ((uint32_t)(second & UINT16_C(0x07ff)) << 1);
        int64_t displacement = t32_sign_extend(encoded, 25);

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)address;
        (void)displacement;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_B;
        instruction->opcode_groups |= CDISASM_GROUP_JUMP;
        t32_append_relative_target(
            instruction,
            address + UINT64_C(4) + (uint64_t)displacement,
            displacement);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

uint32_t cdisasm_arm_t32_instruction_size(uint16_t first_halfword)
{
    uint16_t prefix = first_halfword & UINT16_C(0xf800);

    return prefix == UINT16_C(0xe800)
            || prefix == UINT16_C(0xf000)
            || prefix == UINT16_C(0xf800)
        ? UINT32_C(4)
        : UINT32_C(2);
}

static cdisasm_status t32_decode_psr_transfer(
    uint16_t first,
    uint16_t second,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized)
{
    int read_psr = (first & UINT16_C(0xffef)) == UINT16_C(0xf3ef)
        && (second & UINT16_C(0xf0ff)) == UINT16_C(0x8000);
    int write_psr = (first & UINT16_C(0xffe0)) == UINT16_C(0xf380)
        && (second & UINT16_C(0xf0ff)) == UINT16_C(0x8000);
    unsigned saved;
    unsigned mask;
    unsigned reg;
#if USE_EXTRA_OPCODES
    cdisasm_arm_operand *psr;
#endif

    if (!read_psr && !write_psr) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    *recognized = 1;
    saved = (first >> 4) & 1u;
    mask = (second >> 8) & 15u;
    reg = read_psr ? mask : first & 15u;
    if (reg == 15u || (write_psr && mask == 0u)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    (void)saved;
    (void)instruction;
    (void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    instruction->name_id = read_psr
        ? CDISASM_ARM_NAME_MRS : CDISASM_ARM_NAME_MSR;
    instruction->form_id = read_psr ? UINT16_C(1851) : UINT16_C(1823);
    if (saved || (write_psr && (mask & 7u) != 0u)) {
        instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
    }
    if (read_psr) {
        t32_append_register(instruction, reg,
            CDISASM_OPERAND_ACCESS_WRITE);
        psr = t32_append_operand(instruction);
        if (psr != NULL) {
            psr->type = CDISASM_ARM_OPERAND_SYSTEM_REGISTER;
            psr->imm = saved << 4;
            psr->access = CDISASM_OPERAND_ACCESS_READ;
        }
    } else {
        psr = t32_append_operand(instruction);
        if (psr != NULL) {
            psr->type = CDISASM_ARM_OPERAND_SYSTEM_REGISTER;
            psr->imm = (saved << 4) | mask;
            psr->access = CDISASM_OPERAND_ACCESS_WRITE;
        }
        t32_append_register(instruction, reg,
            CDISASM_OPERAND_ACCESS_READ);
    }
    cdisasm_arm_requirements_set_legacy(
        required_capabilities, CDISASM_ARM_CAP_V7);
    return CDISASM_STATUS_OK;
#endif
}

cdisasm_status cdisasm_arm_decode_t32_core(
    uint32_t raw_instruction,
    uint32_t opcode_size,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    uint16_t first = (uint16_t)raw_instruction;
    uint16_t second;
    cdisasm_status status;
    int extra_recognized = 0;

    if (instruction == NULL || required_capabilities == NULL
        || (opcode_size != 2u && opcode_size != 4u)) {
        return CDISASM_STATUS_INTERNAL_ERROR;
    }
    instruction->address = address;
    instruction->opcode_size = opcode_size;
    instruction->raw_instruction = raw_instruction;
    instruction->condition = CDISASM_ARM_CONDITION_AL;
    instruction->isa_id = CDISASM_ARM_ISA_T32;
    if (opcode_size == 2u) {
        return t32_decode_16(
            first, address, instruction, required_capabilities);
    }
    second = (uint16_t)(raw_instruction >> 16);

    status = t32_decode_psr_transfer(
        first, second, instruction, required_capabilities,
        &extra_recognized);
    if (extra_recognized) {
        return status;
    }

    /* Coprocessor register transfers use the EE/EC Thumb-2 envelope, which
     * overlaps the broader scalar VFP classifier below.  Resolve the exact
     * MCR/MRC/MCRR/MRRC layouts first so a classifier that recognizes the
     * envelope but rejects a different scalar form cannot mask this decode. */
    status = cdisasm_arm_decode_a32_coprocessor_transfer(
        ((uint32_t)first << 16) | second,
        instruction, required_capabilities);
    if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }

    /* Resolve the fixed VFP multiple-register forms before the broad
     * Thumb-2 extra classifier.  EC/ED envelopes also contain scalar VFP
     * encodings whose classifier may report a legality failure before the
     * shared A32 lowering gets a chance to inspect the precise list fields. */
    if ((first & UINT16_C(0xff00)) == UINT16_C(0xec00)
        || (first & UINT16_C(0xff00)) == UINT16_C(0xed00)) {
        status = cdisasm_arm_decode_a32_neon(
            ((uint32_t)first << 16) | second,
            instruction, required_capabilities);
        if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return status;
        }
    }

    status = t32_decode_32_extra(
        first,
        second,
        address,
        instruction,
        required_capabilities,
        &extra_recognized);
    if (extra_recognized
        || status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }
    /* T32 paired core/VFP transfers retain their EC first halfword when
     * transported into the shared A32/VFP decoder. */
    if ((first & UINT16_C(0xff00)) == UINT16_C(0xec00)) {
        uint32_t canonical_word = ((uint32_t)first << 16) | second;

        status = cdisasm_arm_decode_a32_neon(
            canonical_word, instruction, required_capabilities);
        if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return status;
        }
    }

    /* Thumb-2 complex-number AdvSIMD encodings retain their FC/FD first
     * halfword when transported into the shared A32/Thumb NEON decoder. */
    if ((first & UINT16_C(0xfe00)) == UINT16_C(0xfc00)) {
        uint32_t canonical_word = ((uint32_t)first << 16) | second;

        status = cdisasm_arm_decode_a32_neon(
            canonical_word, instruction, required_capabilities);
        if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return status;
        }
    }
    if ((first & UINT16_C(0xef00)) == UINT16_C(0xef00)) {
        uint32_t canonical_word = UINT32_C(0xf2000000)
            | ((uint32_t)(first & UINT16_C(0x1000)) << 12)
            | ((uint32_t)(first & UINT16_C(0x00ff)) << 16)
            | second;

        status = cdisasm_arm_decode_a32_neon(
            canonical_word, instruction, required_capabilities);
        if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return status;
        }
    }
    /* Thumb-2 AdvSIMD structure transfers use the same second halfword and
     * field layout as A32, with the first halfword's bit 11 toggled.  Map
     * the f9xx transport envelope to the shared f4xx decoder so VLD/VST1-4
     * (including single-element and post-index forms) retain one exact
     * operand implementation in both instruction sets. */
    if ((first & UINT16_C(0xff00)) == UINT16_C(0xf900)) {
        uint32_t canonical_word = ((uint32_t)(first - UINT16_C(0x0500)) << 16)
            | second;

        status = cdisasm_arm_decode_a32_neon(
            canonical_word, instruction, required_capabilities);
        if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return status;
        }
    }
    /* T32 VFP load/store encodings retain their ED first halfword when
     * transported into the shared scalar VFP decoder. */
    if ((first & UINT16_C(0xff00)) == UINT16_C(0xec00)
        || (first & UINT16_C(0xff00)) == UINT16_C(0xed00)) {
        uint32_t canonical_word = ((uint32_t)first << 16) | second;

        status = cdisasm_arm_decode_a32_neon(
            canonical_word, instruction, required_capabilities);
        if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return status;
        }
    }
    /* T32 scalar VFP/coproc encodings use both EE and FE first halfwords.
     * Bit 12 is part of the operation field, not a routing discriminator. */
    if ((first & UINT16_C(0xef00)) == UINT16_C(0xee00)) {
        uint32_t canonical_word = ((uint32_t)first << 16) | second;

        status = cdisasm_arm_decode_a32_neon(
            canonical_word, instruction, required_capabilities);
        if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return status;
        }
    }
    return t32_decode_bl(
        first,
        second,
        address,
        instruction,
        required_capabilities);
}
