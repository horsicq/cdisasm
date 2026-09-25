#include "arm_generated_operands.h"
#include "arm_pstate_msr.h"

#if USE_ARCH_ARM && USE_EXTRA_OPCODES

#include "generated/cdisasm_arm_open_operands.inc"
#include "generated/cdisasm_arm_open_immediates.inc"

#include <stddef.h>
#include <string.h>

#define ARM_OPEN_REG_R UINT8_C(1)
#define ARM_OPEN_REG_W UINT8_C(2)
#define ARM_OPEN_REG_X UINT8_C(3)
#define ARM_OPEN_REG_H UINT8_C(4)
#define ARM_OPEN_REG_S UINT8_C(5)
#define ARM_OPEN_REG_D UINT8_C(6)
#define ARM_OPEN_REG_WX UINT8_C(7)

#define ARM_OPEN_SPECIAL_NONE UINT8_C(0)
#define ARM_OPEN_SPECIAL_PC UINT8_C(1)
#define ARM_OPEN_SPECIAL_WZR UINT8_C(2)
#define ARM_OPEN_SPECIAL_WSP UINT8_C(3)
#define ARM_OPEN_SPECIAL_XZR UINT8_C(4)
#define ARM_OPEN_SPECIAL_SP UINT8_C(5)
#define ARM_OPEN_SPECIAL_W_OR_X_ZR UINT8_C(6)

#define ARM_OPEN_MIXED_REGISTER UINT8_C(1)
#define ARM_OPEN_MIXED_IMMEDIATE UINT8_C(2)
#define ARM_OPEN_MIXED_RELATIVE UINT8_C(3)
#define ARM_OPEN_MIXED_DYNAMIC_GPR UINT8_C(4)
#define ARM_OPEN_MIXED_MEMORY UINT8_C(5)
#define ARM_OPEN_MIXED_SCALABLE_REGISTER UINT8_C(6)
#define ARM_OPEN_MIXED_PREDICATE UINT8_C(7)

#define ARM_OPEN_TRANSFORM_SIGNED UINT8_C(1)
#define ARM_OPEN_TRANSFORM_SECOND_HIGH UINT8_C(2)

#define ARM_OPEN_FORM_DCPS1 UINT16_C(4453)
#define ARM_OPEN_FORM_DCPS2 UINT16_C(4454)
#define ARM_OPEN_FORM_DCPS3 UINT16_C(4455)
#define ARM_OPEN_FORM_CFINV UINT16_C(4499)
#define ARM_OPEN_FORM_MSR_PSTATE UINT16_C(4498)
#define ARM_OPEN_FORM_XAFLAG UINT16_C(4500)
#define ARM_OPEN_FORM_AXFLAG UINT16_C(4501)
#define ARM_OPEN_FORM_SETFFR UINT16_C(2618)
#define ARM_OPEN_FORM_RCWCAS_FIRST UINT16_C(4725)
#define ARM_OPEN_FORM_RCWCAS_LAST UINT16_C(4732)

/* FEAT_THE compare-and-swap has two explicit X registers and one 64-bit
 * memory operand.  The source-tree leaf supplies the exact encoding and
 * feature check; this function only lowers its otherwise opaque operands. */
static int arm_open_lower_a64_rcw_cas(
    cdisasm_arm_instruction *instruction,
    uint32_t word)
{
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_RCWCAS, CDISASM_ARM_NAME_RCWCASL,
        CDISASM_ARM_NAME_RCWCASA, CDISASM_ARM_NAME_RCWCASAL,
        CDISASM_ARM_NAME_RCWSCAS, CDISASM_ARM_NAME_RCWSCASL,
        CDISASM_ARM_NAME_RCWSCASA, CDISASM_ARM_NAME_RCWSCASAL
    };
    uint32_t index;
    uint32_t rs;
    uint32_t rt;
    uint32_t rn;
    cdisasm_arm_operand *expected;
    cdisasm_arm_operand *desired;
    cdisasm_arm_operand *memory;

    if (instruction->form_id < ARM_OPEN_FORM_RCWCAS_FIRST
        || instruction->form_id > ARM_OPEN_FORM_RCWCAS_LAST
        || instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return 0;
    }
    index = instruction->form_id - ARM_OPEN_FORM_RCWCAS_FIRST;
    if (instruction->name_id != names[index]
        || (word & UINT32_C(0xffe0fc00))
            != (UINT32_C(0x19200800)
                | ((index >> 2) << 30)
                | ((index & 3u) << 22))) {
        return 0;
    }

    rs = (word >> 16) & 31u;
    rt = word & 31u;
    rn = (word >> 5) & 31u;
    memset(instruction->operand, 0, sizeof(instruction->operand));
    expected = &instruction->operand[0];
    expected->type = CDISASM_OPERAND_REGISTER;
    expected->reg = rs == 31u ? CDISASM_ARM_REG_XZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rs);
    expected->size = 8u;
    expected->access = CDISASM_OPERAND_ACCESS_READ_WRITE;

    desired = &instruction->operand[1];
    desired->type = CDISASM_OPERAND_REGISTER;
    desired->reg = rt == 31u ? CDISASM_ARM_REG_XZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rt);
    desired->size = 8u;
    desired->access = CDISASM_OPERAND_ACCESS_READ;

    memory = &instruction->operand[2];
    memory->type = CDISASM_OPERAND_MEMORY;
    memory->base_reg = rn == 31u ? CDISASM_ARM_REG_SP
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn);
    memory->size = 8u;
    memory->access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    instruction->operand_count = 3u;
    instruction->instruction_flags &=
        ~(CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
            | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
            | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE);
    instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC;
    if ((index & 1u) != 0u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
    }
    if ((index & 2u) != 0u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
    }
    return 1;
}

static int arm_open_lower_a64_dcps(
    cdisasm_arm_instruction *instruction,
    uint32_t word)
{
    uint32_t expected_encoding;
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_operand *operand;

    switch (instruction->form_id) {
        case ARM_OPEN_FORM_DCPS1:
            expected_encoding = UINT32_C(0xd4a00001);
            expected_name = CDISASM_ARM_NAME_DCPS1;
            break;
        case ARM_OPEN_FORM_DCPS2:
            expected_encoding = UINT32_C(0xd4a00002);
            expected_name = CDISASM_ARM_NAME_DCPS2;
            break;
        case ARM_OPEN_FORM_DCPS3:
            expected_encoding = UINT32_C(0xd4a00003);
            expected_name = CDISASM_ARM_NAME_DCPS3;
            break;
        default:
            return 0;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || instruction->name_id != expected_name
        || (word & UINT32_C(0xffe0001f)) != expected_encoding) {
        return 0;
    }

    memset(instruction->operand, 0, sizeof(instruction->operand));
    operand = &instruction->operand[0];
    operand->type = CDISASM_OPERAND_IMMEDIATE;
    operand->imm = (word >> 5) & UINT32_C(0xffff);
    operand->size = 2u;
    operand->access = CDISASM_OPERAND_ACCESS_READ;
    instruction->operand_count = 1u;
    instruction->instruction_flags &=
        ~CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    return 1;
}

static int arm_open_lower_a64_flagm_pstate(
    cdisasm_arm_instruction *instruction,
    uint32_t word)
{
    uint32_t expected_encoding;
    cdisasm_arm_name_id expected_name;

    switch (instruction->form_id) {
        case ARM_OPEN_FORM_CFINV:
            expected_encoding = UINT32_C(0xd500401f);
            expected_name = CDISASM_ARM_NAME_CFINV;
            break;
        case ARM_OPEN_FORM_XAFLAG:
            expected_encoding = UINT32_C(0xd500403f);
            expected_name = CDISASM_ARM_NAME_XAFLAG;
            break;
        case ARM_OPEN_FORM_AXFLAG:
            expected_encoding = UINT32_C(0xd500405f);
            expected_name = CDISASM_ARM_NAME_AXFLAG;
            break;
        default:
            return 0;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || instruction->name_id != expected_name
        || word != expected_encoding) {
        return 0;
    }

    memset(instruction->operand, 0, sizeof(instruction->operand));
    instruction->operand_count = 0u;
    instruction->instruction_flags &=
        ~CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    return 1;
}

static int arm_open_lower_a64_msr_pstate(
    cdisasm_arm_instruction *instruction,
    uint32_t word)
{
    uint8_t field;
    uint8_t immediate;

    if (instruction->form_id != ARM_OPEN_FORM_MSR_PSTATE
        || instruction->isa_id != CDISASM_ARM_ISA_A64
        || instruction->name_id != CDISASM_ARM_NAME_MSR
        || !arm_pstate_msr_decode_word(word, &field, &immediate)) {
        return 0;
    }
    memset(instruction->operand, 0, sizeof(instruction->operand));
    instruction->operand[0].type = CDISASM_ARM_OPERAND_PSTATE_FIELD;
    instruction->operand[0].imm = field;
    instruction->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    instruction->operand[1].type = CDISASM_OPERAND_IMMEDIATE;
    instruction->operand[1].imm = immediate;
    instruction->operand[1].size = 1u;
    instruction->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
    instruction->operand_count = 2u;
    instruction->instruction_flags &=
        ~CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    return 1;
}

static int arm_open_lower_a64_setffr(
    cdisasm_arm_instruction *instruction,
    uint32_t word)
{
    if (instruction->form_id != ARM_OPEN_FORM_SETFFR) {
        return 0;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || instruction->name_id != CDISASM_ARM_NAME_SETFFR
        || word != UINT32_C(0x252c9000)) {
        return 0;
    }

    memset(instruction->operand, 0, sizeof(instruction->operand));
    instruction->operand_count = 0u;
    instruction->instruction_flags &=
        ~CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    return 1;
}


static const cdisasm_arm_open_form_desc *arm_open_find_form(
    cdisasm_arm_form_id form_id)
{
    size_t low = 0u;
    size_t high = sizeof(cdisasm_arm_open_forms)
        / sizeof(cdisasm_arm_open_forms[0]);

    while (low < high) {
        size_t middle = low + (high - low) / 2u;
        cdisasm_arm_form_id current =
            cdisasm_arm_open_forms[middle].form_id;

        if (current < form_id) {
            low = middle + 1u;
        } else {
            high = middle;
        }
    }
    if (low >= sizeof(cdisasm_arm_open_forms)
            / sizeof(cdisasm_arm_open_forms[0])
        || cdisasm_arm_open_forms[low].form_id != form_id) {
        return NULL;
    }
    return &cdisasm_arm_open_forms[low];
}

static const cdisasm_arm_open_mixed_form_desc *arm_open_find_mixed_form(
    cdisasm_arm_form_id form_id)
{
    size_t low = 0u;
    size_t high = sizeof(cdisasm_arm_open_mixed_forms)
        / sizeof(cdisasm_arm_open_mixed_forms[0]);

    while (low < high) {
        size_t middle = low + (high - low) / 2u;
        cdisasm_arm_form_id current =
            cdisasm_arm_open_mixed_forms[middle].form_id;

        if (current < form_id) {
            low = middle + 1u;
        } else {
            high = middle;
        }
    }
    if (low >= sizeof(cdisasm_arm_open_mixed_forms)
            / sizeof(cdisasm_arm_open_mixed_forms[0])
        || cdisasm_arm_open_mixed_forms[low].form_id != form_id) {
        return NULL;
    }
    return &cdisasm_arm_open_mixed_forms[low];
}

static cdisasm_arm_reg_id arm_open_register(
    uint8_t reg_class,
    uint8_t special31,
    uint8_t encoded_width,
    uint32_t encoded)
{
    if (encoded_width != 0u
        && encoded == (UINT32_C(1) << encoded_width) - UINT32_C(1)) {
        switch (special31) {
            case ARM_OPEN_SPECIAL_PC:
                return CDISASM_ARM_REG_PC;
            case ARM_OPEN_SPECIAL_WZR:
                return CDISASM_ARM_REG_WZR;
            case ARM_OPEN_SPECIAL_WSP:
                return CDISASM_ARM_REG_WSP;
            case ARM_OPEN_SPECIAL_XZR:
                return CDISASM_ARM_REG_XZR;
            case ARM_OPEN_SPECIAL_SP:
                return CDISASM_ARM_REG_SP;
            default:
                break;
        }
    }
    switch (reg_class) {
        case ARM_OPEN_REG_R:
            return encoded <= 15u
                ? (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + encoded)
                : CDISASM_ARM_REG_NONE;
        case ARM_OPEN_REG_W:
            return encoded <= 30u
                ? (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + encoded)
                : CDISASM_ARM_REG_NONE;
        case ARM_OPEN_REG_X:
            return encoded <= 30u
                ? (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded)
                : CDISASM_ARM_REG_NONE;
        case ARM_OPEN_REG_H:
            return encoded <= 31u
                ? (cdisasm_arm_reg_id)(CDISASM_ARM_REG_H0 + encoded)
                : CDISASM_ARM_REG_NONE;
        case ARM_OPEN_REG_S:
            return encoded <= 31u
                ? (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + encoded)
                : CDISASM_ARM_REG_NONE;
        case ARM_OPEN_REG_D:
            return encoded <= 31u
                ? (cdisasm_arm_reg_id)(CDISASM_ARM_REG_D0 + encoded)
                : CDISASM_ARM_REG_NONE;
        default:
            return CDISASM_ARM_REG_NONE;
    }
}

static int64_t arm_open_sign_extend(uint64_t value, unsigned int width)
{
    uint64_t sign;
    uint64_t mask;

    if (width == 0u || width >= 64u) {
        return (int64_t)value;
    }
    sign = UINT64_C(1) << (width - 1u);
    mask = (UINT64_C(1) << width) - UINT64_C(1);
    value &= mask;
    return (value & sign) != 0u
        ? -(int64_t)(((~value) + UINT64_C(1)) & mask)
        : (int64_t)value;
}

static int arm_open_relative(
    const cdisasm_arm_instruction *instruction,
    uint8_t target_kind,
    int64_t *displacement_out,
    uint64_t *target_out)
{
    uint32_t raw_instruction;
    uint64_t target_base;
    int64_t displacement = 0;
    uint16_t first;
    uint16_t second;
    uint32_t sign;
    uint32_t j1;
    uint32_t j2;
    uint32_t i1;
    uint32_t i2;
    uint32_t encoded;

    if (instruction == NULL || displacement_out == NULL
        || target_out == NULL) {
        return 0;
    }
    raw_instruction = instruction->raw_instruction;
    target_base = instruction->address;
    first = (uint16_t)raw_instruction;
    second = (uint16_t)(raw_instruction >> 16);
    switch (target_kind) {
        case 1u: /* A32 imm24 branch. */
            displacement = arm_open_sign_extend(
                ((uint64_t)raw_instruction & UINT64_C(0x00ffffff)) << 2,
                26u);
            target_base += UINT64_C(8);
            break;
        case 2u: /* A32 BLX imm24:H. */
            encoded = ((raw_instruction & UINT32_C(0x00ffffff)) << 2)
                | ((raw_instruction >> 23) & UINT32_C(2));
            displacement = arm_open_sign_extend(encoded, 26u);
            target_base += UINT64_C(8);
            break;
        case 3u: /* T16 CBZ/CBNZ. */
            displacement = (int64_t)(
                ((uint32_t)(first & UINT16_C(0x0200)) >> 3)
                | ((uint32_t)(first & UINT16_C(0x00f8)) >> 2));
            target_base += UINT64_C(4);
            break;
        case 4u: /* T16 conditional branch. */
            displacement = arm_open_sign_extend(
                (uint64_t)(first & UINT16_C(0x00ff)) << 1, 9u);
            target_base += UINT64_C(4);
            break;
        case 5u: /* T16 unconditional branch. */
            displacement = arm_open_sign_extend(
                (uint64_t)(first & UINT16_C(0x07ff)) << 1, 12u);
            target_base += UINT64_C(4);
            break;
        case 6u: /* T32 conditional branch. */
            sign = (first >> 10) & 1u;
            j1 = (second >> 13) & 1u;
            j2 = (second >> 11) & 1u;
            encoded = (sign << 20)
                | (j2 << 19)
                | (j1 << 18)
                | ((uint32_t)(first & UINT16_C(0x003f)) << 12)
                | ((uint32_t)(second & UINT16_C(0x07ff)) << 1);
            displacement = arm_open_sign_extend(encoded, 21u);
            target_base += UINT64_C(4);
            break;
        case 7u: /* T32 unconditional branch. */
        case 8u: /* T32 BL. */
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
            displacement = arm_open_sign_extend(encoded, 25u);
            target_base += UINT64_C(4);
            break;
        case 9u: /* T32 BLX. */
            sign = (first >> 10) & 1u;
            j1 = (second >> 13) & 1u;
            j2 = (second >> 11) & 1u;
            i1 = (j1 ^ sign) ^ 1u;
            i2 = (j2 ^ sign) ^ 1u;
            encoded = (sign << 24)
                | (i1 << 23)
                | (i2 << 22)
                | ((uint32_t)(first & UINT16_C(0x03ff)) << 12)
                | ((uint32_t)(second & UINT16_C(0x07fe)) << 1);
            displacement = arm_open_sign_extend(encoded, 25u);
            target_base = (instruction->address + UINT64_C(4))
                & ~UINT64_C(3);
            break;
        case 10u: /* A64 B.cond/BC.cond imm19. */
        case 12u: /* A64 compare branch imm19. */
            displacement = arm_open_sign_extend(
                ((uint64_t)(raw_instruction >> 5) & UINT64_C(0x7ffff))
                    << 2,
                21u);
            break;
        case 11u: /* A64 B/BL imm26. */
            displacement = arm_open_sign_extend(
                ((uint64_t)raw_instruction & UINT64_C(0x03ffffff)) << 2,
                28u);
            break;
        case 13u: /* A64 test branch imm14. */
            displacement = arm_open_sign_extend(
                ((uint64_t)(raw_instruction >> 5) & UINT64_C(0x3fff))
                    << 2,
                16u);
            break;
        case 14u: /* A64 compare branch imm9. */
            displacement = arm_open_sign_extend(
                ((uint64_t)(raw_instruction >> 5) & UINT64_C(0x1ff))
                    << 2,
                11u);
            break;
        default:
            return 0;
    }
    *displacement_out = displacement;
    *target_out = target_base + (uint64_t)displacement;
    return 1;
}

static int arm_open_lower_register_form(
    cdisasm_arm_instruction *instruction,
    const cdisasm_arm_open_form_desc *form,
    uint32_t word)
{
    cdisasm_arm_operand lowered[CDISASM_ARM_MAX_OPERANDS];
    uint32_t index;

    if (form == NULL || form->operand_count == 0u
        || form->operand_count > CDISASM_ARM_MAX_OPERANDS
        || (uint32_t)form->first_operand + form->operand_count
            > sizeof(cdisasm_arm_open_operands)
                / sizeof(cdisasm_arm_open_operands[0])) {
        return 0;
    }
    memset(lowered, 0, sizeof(lowered));
    for (index = 0u; index < form->operand_count; ++index) {
        const cdisasm_arm_open_operand_desc *descriptor =
            &cdisasm_arm_open_operands[form->first_operand + index];
        cdisasm_arm_operand *operand = &lowered[index];
        uint32_t encoded;
        cdisasm_arm_reg_id reg;

        if (descriptor->bit_width == 0u || descriptor->bit_width > 5u
            || descriptor->bit_start >= 32u
            || descriptor->bit_start + descriptor->bit_width > 32u
            || descriptor->access < CDISASM_OPERAND_ACCESS_READ
            || descriptor->access > CDISASM_OPERAND_ACCESS_READ_WRITE) {
            return 0;
        }
        encoded = (word >> descriptor->bit_start)
            & ((UINT32_C(1) << descriptor->bit_width) - UINT32_C(1));
        reg = arm_open_register(
            descriptor->reg_class, descriptor->special31,
            descriptor->bit_width, encoded);
        if (reg == CDISASM_ARM_REG_NONE) {
            return 0;
        }
        operand->type = CDISASM_OPERAND_REGISTER;
        operand->reg = reg;
        operand->size = descriptor->size;
        operand->access = descriptor->access;
    }
    memcpy(instruction->operand, lowered, sizeof(lowered));
    instruction->operand_count = form->operand_count;
    if ((form->flags
            & CDISASM_ARM_OPEN_OPERAND_FLAG_FLOATING_POINT) != 0u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
    }
    instruction->instruction_flags &=
        ~CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    return 1;
}

static int arm_open_lower_mixed_form(
    cdisasm_arm_instruction *instruction,
    const cdisasm_arm_open_mixed_form_desc *form,
    uint32_t word)
{
    cdisasm_arm_operand lowered[CDISASM_ARM_MAX_OPERANDS];
    uint32_t index;

    if (form == NULL || form->operand_count == 0u
        || form->operand_count > CDISASM_ARM_MAX_OPERANDS
        || (uint32_t)form->first_operand + form->operand_count
            > sizeof(cdisasm_arm_open_mixed_operands)
                / sizeof(cdisasm_arm_open_mixed_operands[0])) {
        return 0;
    }
    memset(lowered, 0, sizeof(lowered));
    for (index = 0u; index < form->operand_count; ++index) {
        const cdisasm_arm_open_mixed_operand_desc *descriptor =
            &cdisasm_arm_open_mixed_operands[form->first_operand + index];
        cdisasm_arm_operand *operand = &lowered[index];
        uint32_t encoded;

        if (descriptor->access < CDISASM_OPERAND_ACCESS_READ
            || descriptor->access > CDISASM_OPERAND_ACCESS_READ_WRITE) {
            return 0;
        }
        operand->access = descriptor->access;
        operand->size = descriptor->size;
        if (descriptor->kind == ARM_OPEN_MIXED_REGISTER) {
            cdisasm_arm_reg_id reg;

            if (descriptor->bit_width == 0u
                || descriptor->bit_width > 5u
                || descriptor->bit_start + descriptor->bit_width > 32u) {
                return 0;
            }
            encoded = (word >> descriptor->bit_start)
                & ((UINT32_C(1) << descriptor->bit_width) - UINT32_C(1));
            reg = arm_open_register(
                descriptor->reg_class, descriptor->special31,
                descriptor->bit_width, encoded);
            if (reg == CDISASM_ARM_REG_NONE || descriptor->size == 0u) {
                return 0;
            }
            operand->type = CDISASM_OPERAND_REGISTER;
            operand->reg = reg;
        } else if (descriptor->kind == ARM_OPEN_MIXED_DYNAMIC_GPR) {
            int is_x;

            if (descriptor->reg_class != ARM_OPEN_REG_WX
                || descriptor->special31 != ARM_OPEN_SPECIAL_W_OR_X_ZR
                || descriptor->bit_width != 5u
                || descriptor->bit_start + 5u > 32u
                || descriptor->second_width != 1u
                || descriptor->second_start >= 32u) {
                return 0;
            }
            encoded = (word >> descriptor->bit_start) & 31u;
            is_x = ((word >> descriptor->second_start) & 1u) != 0u;
            operand->type = CDISASM_OPERAND_REGISTER;
            operand->reg = encoded == 31u
                ? (is_x ? CDISASM_ARM_REG_XZR : CDISASM_ARM_REG_WZR)
                : (cdisasm_arm_reg_id)(
                    (is_x ? CDISASM_ARM_REG_X0 : CDISASM_ARM_REG_W0)
                    + encoded);
            operand->size = is_x ? 8u : 4u;
        } else if (descriptor->kind == ARM_OPEN_MIXED_IMMEDIATE) {
            uint64_t raw;
            unsigned int raw_width;
            int64_t source;
            int64_t semantic;

            if (descriptor->bit_width == 0u
                || descriptor->bit_width >= 32u
                || descriptor->bit_start + descriptor->bit_width > 32u
                || descriptor->size == 0u
                || (descriptor->transform
                    & (uint8_t)~(ARM_OPEN_TRANSFORM_SIGNED
                        | ARM_OPEN_TRANSFORM_SECOND_HIGH)) != 0u) {
                return 0;
            }
            raw = (word >> descriptor->bit_start)
                & ((UINT32_C(1) << descriptor->bit_width) - UINT32_C(1));
            raw_width = descriptor->bit_width;
            if ((descriptor->transform
                    & ARM_OPEN_TRANSFORM_SECOND_HIGH) != 0u) {
                if (descriptor->second_width == 0u
                    || descriptor->second_width >= 32u
                    || descriptor->second_start
                        + descriptor->second_width > 32u
                    || raw_width + descriptor->second_width >= 32u) {
                    return 0;
                }
                raw |= (uint64_t)((word >> descriptor->second_start)
                    & ((UINT32_C(1) << descriptor->second_width)
                        - UINT32_C(1))) << raw_width;
                raw_width += descriptor->second_width;
            }
            source = (descriptor->transform
                    & ARM_OPEN_TRANSFORM_SIGNED) != 0u
                ? arm_open_sign_extend(raw, raw_width) : (int64_t)raw;
            semantic = source * (int64_t)descriptor->multiplier
                + (int64_t)descriptor->addend;
            operand->type = CDISASM_OPERAND_IMMEDIATE;
            operand->imm = (uint64_t)semantic;
            if ((descriptor->transform
                    & ARM_OPEN_TRANSFORM_SIGNED) != 0u) {
                operand->flags |= CDISASM_OPERAND_FLAG_SIGNED;
            }
        } else if (descriptor->kind == ARM_OPEN_MIXED_RELATIVE) {
            int64_t displacement;
            uint64_t target;

            if (descriptor->size == 0u
                || !arm_open_relative(
                    instruction, descriptor->transform,
                    &displacement, &target)
                || target != instruction->branch_target) {
                return 0;
            }
            operand->type = CDISASM_OPERAND_IMMEDIATE;
            operand->imm = target;
            operand->address = (uint64_t)displacement;
            operand->flags = CDISASM_OPERAND_FLAG_SIGNED
                | CDISASM_OPERAND_FLAG_PC_RELATIVE
                | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
        } else if (descriptor->kind == ARM_OPEN_MIXED_MEMORY) {
            uint64_t raw;
            int64_t source;
            int64_t displacement;
            cdisasm_arm_reg_id base_reg;

            if (descriptor->reg_class != ARM_OPEN_REG_X
                || descriptor->special31 != ARM_OPEN_SPECIAL_SP
                || descriptor->bit_width != 5u
                || descriptor->bit_start + descriptor->bit_width > 32u
                || descriptor->second_width == 0u
                || descriptor->second_width >= 32u
                || descriptor->second_start
                    + descriptor->second_width > 32u
                || descriptor->size == 0u
                || (descriptor->transform
                    & (uint8_t)~ARM_OPEN_TRANSFORM_SIGNED) != 0u) {
                return 0;
            }
            encoded = (word >> descriptor->bit_start) & UINT32_C(31);
            base_reg = arm_open_register(
                descriptor->reg_class, descriptor->special31,
                descriptor->bit_width, encoded);
            if (base_reg == CDISASM_ARM_REG_NONE) {
                return 0;
            }
            raw = (word >> descriptor->second_start)
                & ((UINT32_C(1) << descriptor->second_width)
                    - UINT32_C(1));
            source = (descriptor->transform
                    & ARM_OPEN_TRANSFORM_SIGNED) != 0u
                ? arm_open_sign_extend(raw, descriptor->second_width)
                : (int64_t)raw;
            displacement = source * (int64_t)descriptor->multiplier
                + (int64_t)descriptor->addend;
            operand->type = CDISASM_OPERAND_MEMORY;
            operand->base_reg = base_reg;
            operand->imm = (uint64_t)displacement;
            if (displacement != 0) {
                operand->flags |=
                    CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                if (displacement < 0) {
                    operand->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            }
        } else if (descriptor->kind == ARM_OPEN_MIXED_SCALABLE_REGISTER
            || descriptor->kind == ARM_OPEN_MIXED_PREDICATE) {
            uint32_t element_selector = 0u;
            int32_t element_exponent;
            int is_predicate =
                descriptor->kind == ARM_OPEN_MIXED_PREDICATE;

            if ((is_predicate
                    ? descriptor->reg_class != UINT8_C(9)
                        || descriptor->bit_width < 3u
                        || descriptor->bit_width > 4u
                    : descriptor->reg_class != UINT8_C(8)
                        || descriptor->bit_width != 5u)
                || descriptor->bit_start + descriptor->bit_width > 32u
                || descriptor->size != 0u
                || descriptor->special31 != ARM_OPEN_SPECIAL_NONE
                || descriptor->addend < 0
                || descriptor->addend > 3
                || descriptor->multiplier < 0
                || descriptor->multiplier > 1
                || (!is_predicate && descriptor->transform != 0u)
                || (is_predicate
                    && descriptor->transform != 0u
                    && descriptor->transform
                        != CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE
                    && descriptor->transform
                        != CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
                    && descriptor->transform
                        != CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED)) {
                return 0;
            }
            if (descriptor->second_width != 0u) {
                if (descriptor->second_width != 2u
                    || descriptor->second_start + 2u > 32u
                    || descriptor->multiplier != 1) {
                    return 0;
                }
                element_selector = (word >> descriptor->second_start) & 3u;
            } else if (descriptor->multiplier != 0) {
                return 0;
            }
            element_exponent = (int32_t)element_selector
                * descriptor->multiplier + descriptor->addend;
            if (element_exponent < 0 || element_exponent > 3) {
                return 0;
            }
            encoded = (word >> descriptor->bit_start)
                & ((UINT32_C(1) << descriptor->bit_width) - UINT32_C(1));
            operand->type = is_predicate
                ? CDISASM_ARM_OPERAND_PREDICATE
                : CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
            operand->reg = (cdisasm_arm_reg_id)(
                (is_predicate ? CDISASM_ARM_REG_P0 : CDISASM_ARM_REG_Z0)
                + encoded);
            operand->extend_type = (uint8_t)(UINT8_C(1) << element_exponent);
            operand->flags = descriptor->transform;
        } else {
            return 0;
        }
    }
    memcpy(instruction->operand, lowered, sizeof(lowered));
    instruction->operand_count = form->operand_count;
    if ((form->flags
            & CDISASM_ARM_OPEN_MIXED_FLAG_FLOATING_POINT) != 0u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
    }
    if ((form->flags & CDISASM_ARM_OPEN_MIXED_FLAG_PRE_INDEX) != 0u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    }
    if ((form->flags & CDISASM_ARM_OPEN_MIXED_FLAG_POST_INDEX) != 0u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    }
    if ((form->flags
            & CDISASM_ARM_OPEN_MIXED_FLAG_UNPRIVILEGED) != 0u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED;
    }
    if ((form->flags
            & CDISASM_ARM_OPEN_MIXED_FLAG_SCALABLE_VECTOR) != 0u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;
    }
    if ((form->flags & CDISASM_ARM_OPEN_MIXED_FLAG_PREDICATED) != 0u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;
    }
    instruction->instruction_flags &=
        ~CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    return 1;
}

int cdisasm_arm_lower_generated_operands(
    cdisasm_arm_instruction *instruction)
{
    const cdisasm_arm_open_form_desc *form;
    const cdisasm_arm_open_mixed_form_desc *mixed_form;
    uint32_t word;

    if (instruction == NULL
        || (instruction->isa_id == CDISASM_ARM_ISA_A32
            ? instruction->opcode_size != 4u
            : instruction->isa_id == CDISASM_ARM_ISA_T32
                ? (instruction->opcode_size != 2u
                    && instruction->opcode_size != 4u)
                : instruction->isa_id != CDISASM_ARM_ISA_A64
                    || instruction->opcode_size != 4u)
        || instruction->form_id == CDISASM_ARM_FORM_NONE
        || instruction->operand_count != 0u
        || (instruction->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE))
            != (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) {
        return 0;
    }
    form = arm_open_find_form(instruction->form_id);
    word = instruction->raw_instruction;
    if (instruction->isa_id == CDISASM_ARM_ISA_T32
        && instruction->opcode_size == 4u) {
        word = (word << 16) | (word >> 16);
    }
    if (arm_open_lower_a64_dcps(instruction, word)) {
        return 1;
    }
    if (arm_open_lower_a64_flagm_pstate(instruction, word)) {
        return 1;
    }
    if (arm_open_lower_a64_msr_pstate(instruction, word)) {
        return 1;
    }
    if (arm_open_lower_a64_setffr(instruction, word)) {
        return 1;
    }
    if (arm_open_lower_a64_rcw_cas(instruction, word)) {
        return 1;
    }
    if (form != NULL) {
        return arm_open_lower_register_form(instruction, form, word);
    }
    mixed_form = arm_open_find_mixed_form(instruction->form_id);
    return mixed_form != NULL
        ? arm_open_lower_mixed_form(instruction, mixed_form, word) : 0;
}

#else

int cdisasm_arm_lower_generated_operands(
    cdisasm_arm_instruction *instruction)
{
    (void)instruction;
    return 0;
}

#endif
