#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = {
        (uint8_t)word,
        (uint8_t)(word >> 8),
        (uint8_t)(word >> 16),
        (uint8_t)(word >> 24)
    };

    return cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        bytes,
        sizeof(bytes),
        UINT64_C(0x1000),
        NULL,
        instruction);
}

static int test_luti6_byte(void)
{
    /* LUTI6 z1.b, {z2.b, z3.b}, z4 */
    const uint32_t word = UINT32_C(0x4520ac00)
        | UINT32_C(1)
        | (UINT32_C(2) << 5)
        | (UINT32_C(4) << 16);
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    if (decode_word(word, &instruction) != 4u
        || instruction.name_id != CDISASM_ARM_NAME_LUTI6
        || instruction.operand_count != 3u
        || instruction.operand[0].reg != CDISASM_ARM_REG_Z1
        || instruction.operand[1].type
            != CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        || instruction.operand[1].reg != CDISASM_ARM_REG_Z2
        || instruction.operand[1].register_list != UINT16_C(0x0102)
        || instruction.operand[2].reg != CDISASM_ARM_REG_Z4
        || (instruction.operand[2].flags
            & CDISASM_ARM_OPERAND_FLAG_HAS_LANE) != 0u
        || (instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) == 0u) {
        fprintf(stderr, "LUTI6 byte structured decode mismatch\n");
        return 0;
    }
#else
    if (decode_word(word, &instruction) != 0u
        || instruction.last_error_id
            != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        fprintf(stderr, "LUTI6 byte extras-off gate mismatch\n");
        return 0;
    }
#endif
    return 1;
}

static int test_luti6_halfword(void)
{
    /* LUTI6 z5.h, {z6.h, z7.h}, z8[1]. */
    const uint32_t word = UINT32_C(0x4560ac00)
        | UINT32_C(5)
        | (UINT32_C(6) << 5)
        | (UINT32_C(8) << 16)
        | (UINT32_C(1) << 23);
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    if (decode_word(word, &instruction) != 4u
        || instruction.name_id != CDISASM_ARM_NAME_LUTI6
        || instruction.operand_count != 3u
        || instruction.operand[0].reg != CDISASM_ARM_REG_Z5
        || instruction.operand[1].type
            != CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        || instruction.operand[1].reg != CDISASM_ARM_REG_Z6
        || instruction.operand[1].register_list != UINT16_C(0x0102)
        || instruction.operand[2].reg != CDISASM_ARM_REG_Z8
        || (instruction.operand[2].flags
            & CDISASM_ARM_OPERAND_FLAG_HAS_LANE) == 0u
        || instruction.operand[2].imm != UINT64_C(1)) {
        fprintf(stderr, "LUTI6 halfword structured decode mismatch\n");
        return 0;
    }
#else
    if (decode_word(word, &instruction) != 0u
        || instruction.last_error_id
            != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        fprintf(stderr, "LUTI6 halfword extras-off gate mismatch\n");
        return 0;
    }
#endif
    return 1;
}

static int test_luti6_alignment_rejection(void)
{
    /* The pair source must begin at an even Z register. */
    const uint32_t word = UINT32_C(0x4520ac00)
        | UINT32_C(1)
        | (UINT32_C(3) << 5)
        | (UINT32_C(4) << 16);
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    if (decode_word(word, &instruction) != 0u
        || instruction.last_error_id != CDISASM_STATUS_INVALID_INSTRUCTION) {
        fprintf(stderr, "LUTI6 odd source-pair legality mismatch\n");
        return 0;
    }
#else
    if (decode_word(word, &instruction) != 0u
        || instruction.last_error_id
            != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        fprintf(stderr, "LUTI6 odd source-pair extras-off gate mismatch\n");
        return 0;
    }
#endif
    return 1;
}

int main(void)
{
    if (!test_luti6_byte()
        || !test_luti6_halfword()
        || !test_luti6_alignment_rejection()) {
        return 1;
    }
    puts("ARM SVE2.3 LUTI6 tests passed");
    return 0;
}
