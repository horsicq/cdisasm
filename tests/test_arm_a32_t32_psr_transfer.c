#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)

static uint32_t decode(uint32_t word, cdisasm_arm_instruction *instruction)
{
    uint8_t code[4] = {
        (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24)
    };

    memset(instruction, 0, sizeof(*instruction));
    return cdisasm_arm_decode(CDISASM_ARM_CPU_ARM7TDMI,
        CDISASM_ARM_MODE_A32, code, sizeof(code), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static uint32_t decode_t32(uint16_t first, uint16_t second,
    cdisasm_arm_instruction *instruction)
{
    uint8_t code[4] = {
        (uint8_t)first, (uint8_t)(first >> 8),
        (uint8_t)second, (uint8_t)(second >> 8)
    };

    memset(instruction, 0, sizeof(*instruction));
    return cdisasm_arm_decode(CDISASM_ARM_CPU_CORTEX_A9,
        CDISASM_ARM_MODE_T32, code, sizeof(code), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_text(const cdisasm_arm_instruction *instruction,
    const char *expected)
{
    char text[128];

    CHECK(cdisasm_arm_format(instruction, 0u, text, sizeof(text)) != 0u);
    CHECK(strcmp(text, expected) == 0);
}
#endif

int main(void)
{
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    CHECK(decode(UINT32_C(0xe10f0000), &instruction) == 4u);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_MRS);
    CHECK(instruction.form_id == 94u);
    CHECK(instruction.operand_count == 2u);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_R0);
    CHECK(instruction.operand[1].type == CDISASM_ARM_OPERAND_SYSTEM_REGISTER);
    CHECK(instruction.operand[1].imm == 0u);
#if USE_DISASM_FORMAT
    expect_text(&instruction, "mrs r0, cpsr");
#endif

    CHECK(decode(UINT32_C(0x110f0000), &instruction) == 4u);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_MRS);
    CHECK(instruction.condition == CDISASM_ARM_CONDITION_NE);
    CHECK((instruction.opcode_groups & CDISASM_GROUP_CONDITIONAL) != 0u);

    CHECK(decode(UINT32_C(0xe14f1000), &instruction) == 4u);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_MRS);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_R1);
    CHECK(instruction.operand[1].imm == 16u);
    CHECK((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
#if USE_DISASM_FORMAT
    expect_text(&instruction, "mrs r1, spsr");
#endif

    CHECK(decode(UINT32_C(0xe12ff002), &instruction) == 4u);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_MSR);
    CHECK(instruction.form_id == 96u);
    CHECK(instruction.operand_count == 2u);
    CHECK(instruction.operand[0].imm == 15u);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_R2);
#if USE_DISASM_FORMAT
    expect_text(&instruction, "msr cpsr_fsxc, r2");
#endif

    CHECK(decode(UINT32_C(0xe121f003), &instruction) == 4u);
    CHECK(instruction.operand[0].imm == 1u);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_R3);
#if USE_DISASM_FORMAT
    expect_text(&instruction, "msr cpsr_c, r3");
#endif

    CHECK(decode(UINT32_C(0xe16ff004), &instruction) == 4u);
    CHECK(instruction.operand[0].imm == 31u);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_R4);
#if USE_DISASM_FORMAT
    expect_text(&instruction, "msr spsr_fsxc, r4");
#endif

    CHECK(decode(UINT32_C(0xe328f102), &instruction) == 4u);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_MSR);
    CHECK(instruction.form_id == 240u);
    CHECK(instruction.operand[0].imm == 8u);
    CHECK(instruction.operand[1].type == CDISASM_OPERAND_IMMEDIATE);
    CHECK(instruction.operand[1].imm == UINT32_C(0x80000000));
    CHECK((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) == 0u);

    CHECK(decode(UINT32_C(0xe361f013), &instruction) == 4u);
    CHECK(instruction.operand[0].imm == 17u);
    CHECK(instruction.operand[1].imm == 19u);

    CHECK(decode_t32(UINT16_C(0xf3ef), UINT16_C(0x8000),
        &instruction) == 4u);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_MRS);
    CHECK(instruction.form_id == 1851u);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_R0);
    CHECK(instruction.operand[1].imm == 0u);
#if USE_DISASM_FORMAT
    expect_text(&instruction, "mrs r0, cpsr");
#endif

    CHECK(decode_t32(UINT16_C(0xf3ff), UINT16_C(0x8100),
        &instruction) == 4u);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_R1);
    CHECK(instruction.operand[1].imm == 16u);
#if USE_DISASM_FORMAT
    expect_text(&instruction, "mrs r1, spsr");
#endif

    CHECK(decode_t32(UINT16_C(0xf382), UINT16_C(0x8800),
        &instruction) == 4u);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_MSR);
    CHECK(instruction.form_id == 1823u);
    CHECK(instruction.operand[0].imm == 8u);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_R2);
#if USE_DISASM_FORMAT
    expect_text(&instruction, "msr cpsr_f, r2");
#endif

    CHECK(decode_t32(UINT16_C(0xf394), UINT16_C(0x8f00),
        &instruction) == 4u);
    CHECK(instruction.operand[0].imm == 31u);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_R4);
#if USE_DISASM_FORMAT
    expect_text(&instruction, "msr spsr_fsxc, r4");
#endif

    CHECK(decode(UINT32_C(0xe10ff000), &instruction) == 0u);
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    CHECK(decode(UINT32_C(0xe12ff00f), &instruction) == 0u);
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    CHECK(decode(UINT32_C(0xe120f002), &instruction) == 0u);
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    CHECK(decode_t32(UINT16_C(0xf38f), UINT16_C(0x8100),
        &instruction) == 0u);
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    CHECK(decode_t32(UINT16_C(0xf383), UINT16_C(0x8000),
        &instruction) == 0u);
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    CHECK(decode(UINT32_C(0xe10f0000), &instruction) == 0u);
    CHECK(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    CHECK(decode_t32(UINT16_C(0xf3ef), UINT16_C(0x8000),
        &instruction) == 0u);
    CHECK(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    if (failures == 0) {
        puts("A32/T32 PSR transfer tests passed");
    }
    return failures == 0 ? 0 : 1;
}
