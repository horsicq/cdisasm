#include "cdisasm/cdisasm_arm.h"

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
        code, sizeof(code), UINT64_C(0x1000), NULL, out);
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
        code, sizeof(code), UINT64_C(0x1000), NULL, out);
}

static void check_transfer(uint32_t word, cdisasm_arm_name_id name,
    unsigned operand_count, int long_form)
{
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode_a32(word, &instruction) == 4u);
    EXPECT(instruction.name_id == name);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_A32);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
    EXPECT(instruction.operand_count == operand_count);
    EXPECT(instruction.operand[0].type == CDISASM_OPERAND_IMMEDIATE);
    if (long_form) {
        EXPECT(instruction.operand[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.operand[2].type == CDISASM_OPERAND_REGISTER);
    } else {
        EXPECT(instruction.operand[1].type == CDISASM_OPERAND_REGISTER);
    }
#else
    EXPECT(decode_a32(word, &instruction) == 0u);
    EXPECT(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void check_t32(uint16_t first, uint16_t second,
    cdisasm_arm_name_id name, unsigned operand_count)
{
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode_t32(first, second, &instruction) == 4u);
    EXPECT(instruction.name_id == name);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_T32);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.operand_count == operand_count);
    EXPECT(instruction.operand[0].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction.operand[1].type == CDISASM_OPERAND_REGISTER);
    if (operand_count == 3u) {
        EXPECT(instruction.operand[2].type == CDISASM_OPERAND_REGISTER);
    }
#else
    EXPECT(decode_t32(first, second, &instruction) == 0u);
    EXPECT(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

int main(void)
{
    check_transfer(UINT32_C(0xee000e10), CDISASM_ARM_NAME_MCR, 2u, 0);
    check_transfer(UINT32_C(0xee100e10), CDISASM_ARM_NAME_MRC, 2u, 0);
    check_transfer(UINT32_C(0xec400e00), CDISASM_ARM_NAME_MCRR, 3u, 1);
    check_transfer(UINT32_C(0xec500e00), CDISASM_ARM_NAME_MRRC, 3u, 1);

    check_t32(UINT16_C(0xee00), UINT16_C(0x0e10),
        CDISASM_ARM_NAME_MCR, 2u);
    check_t32(UINT16_C(0xee10), UINT16_C(0x0e10),
        CDISASM_ARM_NAME_MRC, 2u);
    check_t32(UINT16_C(0xec40), UINT16_C(0x0e00),
        CDISASM_ARM_NAME_MCRR, 3u);
    check_t32(UINT16_C(0xec50), UINT16_C(0x0e00),
        CDISASM_ARM_NAME_MRRC, 3u);
    return failures == 0 ? 0 : 1;
}
