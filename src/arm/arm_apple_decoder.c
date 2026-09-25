#include "arm_apple_decoder.h"

#include <stddef.h>

typedef uint8_t arm_apple_operand_form;
enum {
    ARM_APPLE_FORM_NONE = 0,
    ARM_APPLE_FORM_X_READ = 1,
    ARM_APPLE_FORM_VECTOR_READ_WRITE_READ = 2,
    ARM_APPLE_FORM_X_READ_READ_WRITE = 3,
    ARM_APPLE_FORM_SIGNED_IMM5 = 4,
    ARM_APPLE_FORM_X_READ_WRITE = 5,
    ARM_APPLE_FORM_SDSB_IMM4 = 6,
    ARM_APPLE_FORM_MRS_A7_SYSREG = 7,
    ARM_APPLE_FORM_MSR_A7_SYSREG = 8
};

typedef struct arm_apple_opcode_descriptor {
    uint32_t mask;
    uint32_t value;
    cdisasm_arm_name_id name_id;
    uint32_t required_capabilities;
    uint32_t instruction_flags;
    arm_apple_operand_form operand_form;
} arm_apple_opcode_descriptor;

#define APPLE_FLAG \
    CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY
#define AMX_FLAG \
    (APPLE_FLAG | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_AMX)
#define AMX_FP_FLAG \
    (AMX_FLAG | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
#define MUL53_FLAG \
    (APPLE_FLAG | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_MUL53 \
        | CDISASM_ARM_INSTRUCTION_FLAG_SIMD)
#define APPLE_SYS_FLAG \
    (APPLE_FLAG | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_SYSTEM)
#define APPLE_AMX_CAPS \
    (CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_APPLE_AMX)
#define APPLE_MUL53_CAPS \
    (CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON \
        | CDISASM_ARM_CAP_APPLE_MUL53)
#define APPLE_SYS_CAPS \
    (CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_APPLE_SYS)
#define APPLE_A7_SYSREG_CAPS \
    (CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_APPLE_A7_SYSREG)

/* Numeric only: spelling remains outside the decode engine. */
static const arm_apple_opcode_descriptor apple_opcodes[] = {
    { UINT32_C(0xfffffc00), UINT32_C(0x00200000),
      CDISASM_ARM_NAME_MUL53LO, APPLE_MUL53_CAPS, MUL53_FLAG,
      ARM_APPLE_FORM_VECTOR_READ_WRITE_READ },
    { UINT32_C(0xfffffc00), UINT32_C(0x00200400),
      CDISASM_ARM_NAME_MUL53HI, APPLE_MUL53_CAPS, MUL53_FLAG,
      ARM_APPLE_FORM_VECTOR_READ_WRITE_READ },
    { UINT32_C(0xfffffc00), UINT32_C(0x00200800),
      CDISASM_ARM_NAME_WKDMC, APPLE_SYS_CAPS, APPLE_SYS_FLAG,
      ARM_APPLE_FORM_X_READ_READ_WRITE },
    { UINT32_C(0xfffffc00), UINT32_C(0x00200c00),
      CDISASM_ARM_NAME_WKDMD, APPLE_SYS_CAPS, APPLE_SYS_FLAG,
      ARM_APPLE_FORM_X_READ_READ_WRITE },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201000),
      CDISASM_ARM_NAME_LDX, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201020),
      CDISASM_ARM_NAME_LDY, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201040),
      CDISASM_ARM_NAME_STX, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201060),
      CDISASM_ARM_NAME_STY, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201080),
      CDISASM_ARM_NAME_LDZ, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x002010a0),
      CDISASM_ARM_NAME_STZ, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x002010c0),
      CDISASM_ARM_NAME_LDZI, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x002010e0),
      CDISASM_ARM_NAME_STZI, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201100),
      CDISASM_ARM_NAME_EXTRX, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201120),
      CDISASM_ARM_NAME_EXTRY, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201140),
      CDISASM_ARM_NAME_FMA64, APPLE_AMX_CAPS, AMX_FP_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201160),
      CDISASM_ARM_NAME_FMS64, APPLE_AMX_CAPS, AMX_FP_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201180),
      CDISASM_ARM_NAME_FMA32, APPLE_AMX_CAPS, AMX_FP_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x002011a0),
      CDISASM_ARM_NAME_FMS32, APPLE_AMX_CAPS, AMX_FP_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x002011c0),
      CDISASM_ARM_NAME_MAC16, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x002011e0),
      CDISASM_ARM_NAME_FMA16, APPLE_AMX_CAPS, AMX_FP_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201200),
      CDISASM_ARM_NAME_FMS16, APPLE_AMX_CAPS, AMX_FP_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffff), UINT32_C(0x00201220),
      CDISASM_ARM_NAME_SET, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_NONE },
    { UINT32_C(0xffffffff), UINT32_C(0x00201221),
      CDISASM_ARM_NAME_CLR, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_NONE },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201240),
      CDISASM_ARM_NAME_VECINT, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201260),
      CDISASM_ARM_NAME_VECFP, APPLE_AMX_CAPS, AMX_FP_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201280),
      CDISASM_ARM_NAME_MATINT, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x002012a0),
      CDISASM_ARM_NAME_MATFP, APPLE_AMX_CAPS, AMX_FP_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffe0), UINT32_C(0x002012c0),
      CDISASM_ARM_NAME_GENLUT, APPLE_AMX_CAPS, AMX_FLAG,
      ARM_APPLE_FORM_X_READ },
    { UINT32_C(0xffffffff), UINT32_C(0x00201400),
      CDISASM_ARM_NAME_GEXIT, APPLE_SYS_CAPS, APPLE_SYS_FLAG,
      ARM_APPLE_FORM_NONE },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201420),
      CDISASM_ARM_NAME_GENTER, APPLE_SYS_CAPS, APPLE_SYS_FLAG,
      ARM_APPLE_FORM_SIGNED_IMM5 },
    { UINT32_C(0xffffffe0), UINT32_C(0x00201440),
      CDISASM_ARM_NAME_AT_AS1ELX, APPLE_SYS_CAPS, APPLE_SYS_FLAG,
      ARM_APPLE_FORM_X_READ_WRITE },
    { UINT32_C(0xfffffff0), UINT32_C(0x00201460),
      CDISASM_ARM_NAME_SDSB, APPLE_SYS_CAPS, APPLE_SYS_FLAG,
      ARM_APPLE_FORM_SDSB_IMM4 },
    { UINT32_C(0xffffffe0), UINT32_C(0xd53ff200),
      CDISASM_ARM_NAME_MRS, APPLE_A7_SYSREG_CAPS, APPLE_SYS_FLAG,
      ARM_APPLE_FORM_MRS_A7_SYSREG },
    { UINT32_C(0xffffffe0), UINT32_C(0xd51ff200),
      CDISASM_ARM_NAME_MSR, APPLE_A7_SYSREG_CAPS, APPLE_SYS_FLAG,
      ARM_APPLE_FORM_MSR_A7_SYSREG }
};

_Static_assert(
    sizeof(apple_opcodes) / sizeof(apple_opcodes[0]) == 34u,
    "Apple opcode descriptor table must remain complete");

static cdisasm_arm_reg_id x_reg(unsigned encoded)
{
    if (encoded == 31u) {
        return CDISASM_ARM_REG_XZR;
    }
    return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded);
}

static cdisasm_arm_reg_id vector_reg(unsigned encoded)
{
    return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded);
}

static cdisasm_arm_operand *append_operand(
    cdisasm_arm_instruction *instruction)
{
    if (instruction->operand_count >= CDISASM_ARM_MAX_OPERANDS) {
        return NULL;
    }
    return &instruction->operand[instruction->operand_count++];
}

static cdisasm_arm_operand *append_register(
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_reg_id reg,
    uint8_t size,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand = append_operand(instruction);

    if (operand != NULL) {
        operand->type = CDISASM_OPERAND_REGISTER;
        operand->reg = reg;
        operand->size = size;
        operand->access = access;
    }
    return operand;
}

static void append_vector_register(
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_reg_id reg,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand = append_register(
        instruction, reg, 16u, access);

    if (operand != NULL) {
        operand->extend_type = (cdisasm_arm_extend_type)8u;
        operand->scale = 2u;
    }
}

static cdisasm_arm_operand *append_immediate(
    cdisasm_arm_instruction *instruction,
    uint64_t value)
{
    cdisasm_arm_operand *operand = append_operand(instruction);

    if (operand != NULL) {
        operand->type = CDISASM_OPERAND_IMMEDIATE;
        operand->imm = value;
        operand->size = 1u;
        operand->access = CDISASM_OPERAND_ACCESS_READ;
    }
    return operand;
}

static int64_t sign_extend_5(unsigned value)
{
    return value >= 16u ? (int64_t)value - 32 : (int64_t)value;
}

static void decode_operands(
    uint32_t word,
    arm_apple_operand_form form,
    cdisasm_arm_instruction *instruction)
{
    unsigned low = word & 31u;
    unsigned high = (word >> 5) & 31u;
    cdisasm_arm_operand *operand;

    switch (form) {
        case ARM_APPLE_FORM_NONE:
            break;
        case ARM_APPLE_FORM_X_READ:
            append_register(
                instruction, x_reg(low), 8u, CDISASM_OPERAND_ACCESS_READ);
            break;
        case ARM_APPLE_FORM_VECTOR_READ_WRITE_READ:
            append_vector_register(
                instruction,
                vector_reg(low),
                CDISASM_OPERAND_ACCESS_READ_WRITE);
            append_vector_register(
                instruction,
                vector_reg(high),
                CDISASM_OPERAND_ACCESS_READ);
            break;
        case ARM_APPLE_FORM_X_READ_READ_WRITE:
            append_register(
                instruction, x_reg(high), 8u, CDISASM_OPERAND_ACCESS_READ);
            append_register(
                instruction,
                x_reg(low),
                8u,
                CDISASM_OPERAND_ACCESS_READ_WRITE);
            break;
        case ARM_APPLE_FORM_SIGNED_IMM5: {
            int64_t value = sign_extend_5(low);

            operand = append_immediate(instruction, (uint64_t)value);
            if (operand != NULL && value < 0) {
                operand->flags |= CDISASM_OPERAND_FLAG_SIGNED;
            }
            break;
        }
        case ARM_APPLE_FORM_X_READ_WRITE:
            append_register(
                instruction,
                x_reg(low),
                8u,
                CDISASM_OPERAND_ACCESS_READ_WRITE);
            break;
        case ARM_APPLE_FORM_SDSB_IMM4:
            append_immediate(instruction, word & 15u);
            if ((word & 15u) > CDISASM_ARM_APPLE_SDSB_SY) {
                instruction->instruction_flags |=
                    CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL;
            }
            break;
        case ARM_APPLE_FORM_MRS_A7_SYSREG:
            append_register(
                instruction, x_reg(low), 8u, CDISASM_OPERAND_ACCESS_WRITE);
            append_register(
                instruction,
                CDISASM_ARM_REG_CPM_IOACC_CTL_EL3,
                8u,
                CDISASM_OPERAND_ACCESS_READ);
            instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
            break;
        case ARM_APPLE_FORM_MSR_A7_SYSREG:
            append_register(
                instruction,
                CDISASM_ARM_REG_CPM_IOACC_CTL_EL3,
                8u,
                CDISASM_OPERAND_ACCESS_WRITE);
            append_register(
                instruction, x_reg(low), 8u, CDISASM_OPERAND_ACCESS_READ);
            instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
            break;
        default:
            break;
    }
}

cdisasm_status cdisasm_arm_decode_a64_apple(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    size_t index;

    if ((word & UINT32_C(0xffff0000)) != UINT32_C(0x00200000)
        && (word & UINT32_C(0xffdfffe0)) != UINT32_C(0xd51ff200)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    for (index = 0;
         index < sizeof(apple_opcodes) / sizeof(apple_opcodes[0]);
         ++index) {
        const arm_apple_opcode_descriptor *descriptor =
            &apple_opcodes[index];

        if ((word & descriptor->mask) != descriptor->value) {
            continue;
        }
        instruction->name_id = descriptor->name_id;
        instruction->instruction_flags |= descriptor->instruction_flags;
        decode_operands(word, descriptor->operand_form, instruction);
        cdisasm_arm_requirements_set_legacy(required_capabilities, descriptor->required_capabilities);
        return CDISASM_STATUS_OK;
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

#undef APPLE_FLAG
#undef AMX_FLAG
#undef AMX_FP_FLAG
#undef MUL53_FLAG
#undef APPLE_SYS_FLAG
#undef APPLE_AMX_CAPS
#undef APPLE_MUL53_CAPS
#undef APPLE_SYS_CAPS
#undef APPLE_A7_SYSREG_CAPS
