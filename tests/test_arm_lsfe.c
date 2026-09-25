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
        UINT64_C(0x2000),
        NULL,
        instruction);
}

static int check_memory(const cdisasm_arm_operand *operand,
    cdisasm_arm_reg_id base, uint8_t size)
{
    return operand->type == CDISASM_OPERAND_MEMORY
        && operand->base_reg == base
        && operand->size == size
        && operand->imm == 0u;
}

static int test_load_bf16_acquire(void)
{
    /* LDBFADDA H0, H1, [X2]. */
    const uint32_t word = UINT32_C(0x3c200000)
        | UINT32_C(0x00800000)
        | (UINT32_C(1) << 16)
        | (UINT32_C(2) << 5);
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    if (decode_word(word, &instruction) != 4u
        || instruction.name_id != CDISASM_ARM_NAME_LDBFADDA
        || instruction.form_id != UINT16_C(5416)
        || instruction.operand_count != 3u
        || instruction.operand[0].reg != CDISASM_ARM_REG_H0
        || instruction.operand[1].reg != CDISASM_ARM_REG_H1
        || !check_memory(&instruction.operand[2], CDISASM_ARM_REG_X2, 2u)
        || (instruction.instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
                | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE))
            != (CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
                | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE)
        || (instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_RELEASE) != 0u) {
        fprintf(stderr, "LSFE BF16 acquire load mismatch\n");
        return 0;
    }
#else
    if (decode_word(word, &instruction) != 0u
        || instruction.last_error_id != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        fprintf(stderr, "LSFE BF16 extras-off mismatch\n");
        return 0;
    }
#endif
    return 1;
}

static int test_store_bf16_release(void)
{
    /* STBFMAXL H3, [X4]. */
    const uint32_t word = UINT32_C(0x3c60c01f)
        | (UINT32_C(3) << 16)
        | (UINT32_C(4) << 5);
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    if (decode_word(word, &instruction) != 4u
        || instruction.name_id != CDISASM_ARM_NAME_STBFMAXL
        || instruction.form_id != UINT16_C(5407)
        || instruction.operand_count != 2u
        || instruction.operand[0].reg != CDISASM_ARM_REG_H3
        || !check_memory(&instruction.operand[1], CDISASM_ARM_REG_X4, 2u)
        || (instruction.instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE))
            != (CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE)
        || (instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE) != 0u) {
        fprintf(stderr, "LSFE BF16 release store mismatch\n");
        return 0;
    }
#else
    if (decode_word(word, &instruction) != 0u
        || instruction.last_error_id != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        fprintf(stderr, "LSFE BF16 store extras-off mismatch\n");
        return 0;
    }
#endif
    return 1;
}

static int test_fp_widths_and_orders(void)
{
    /* LDFMINA H5, H7, [X6]. */
    const uint32_t halfword = UINT32_C(0x7ca05000)
        | UINT32_C(5)
        | (UINT32_C(6) << 5)
        | (UINT32_C(7) << 16);
    /* LDFMAXNMAL S8, S10, [X9]. */
    const uint32_t single = UINT32_C(0xbce06000)
        | UINT32_C(8)
        | (UINT32_C(9) << 5)
        | (UINT32_C(10) << 16);
    /* STFMINNM D11, [X12]. */
    const uint32_t doubleword = UINT32_C(0xfc20f01f)
        | (UINT32_C(11) << 16)
        | (UINT32_C(12) << 5);
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    if (decode_word(halfword, &instruction) != 4u
        || instruction.name_id != CDISASM_ARM_NAME_LDFMINA
        || instruction.form_id != UINT16_C(5448)
        || instruction.operand_count != 3u
        || instruction.operand[0].reg != CDISASM_ARM_REG_H5
        || instruction.operand[1].reg != CDISASM_ARM_REG_H7
        || !check_memory(&instruction.operand[2], CDISASM_ARM_REG_X6, 2u)
        || (instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE) == 0u) {
        fprintf(stderr, "LSFE FP16 acquire load mismatch\n");
        return 0;
    }
    if (decode_word(single, &instruction) != 4u
        || instruction.name_id != CDISASM_ARM_NAME_LDFMAXNMAL
        || instruction.form_id != UINT16_C(5484)
        || instruction.operand_count != 3u
        || instruction.operand[0].reg != CDISASM_ARM_REG_S8
        || instruction.operand[1].reg != CDISASM_ARM_REG_S10
        || !check_memory(&instruction.operand[2], CDISASM_ARM_REG_X9, 4u)
        || (instruction.instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE))
            != (CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE)) {
        fprintf(stderr, "LSFE FP32 acquire-release load mismatch\n");
        return 0;
    }
    if (decode_word(doubleword, &instruction) != 4u
        || instruction.name_id != CDISASM_ARM_NAME_STFMINNM
        || instruction.form_id != UINT16_C(5495)
        || instruction.operand_count != 2u
        || instruction.operand[0].reg != CDISASM_ARM_REG_D11
        || !check_memory(&instruction.operand[1], CDISASM_ARM_REG_X12, 8u)) {
        fprintf(stderr, "LSFE FP64 relaxed store mismatch\n");
        return 0;
    }
#else
    if (decode_word(halfword, &instruction) != 0u
        || instruction.last_error_id != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
        || decode_word(single, &instruction) != 0u
        || instruction.last_error_id != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
        || decode_word(doubleword, &instruction) != 0u
        || instruction.last_error_id != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        fprintf(stderr, "LSFE FP width extras-off mismatch\n");
        return 0;
    }
#endif
    return 1;
}

static int test_reserved_selectors(void)
{
    /* Operation selector 1 is reserved.  Stores also reject acquire order. */
    const uint32_t reserved = UINT32_C(0x3c201000)
        | (UINT32_C(1) << 16)
        | (UINT32_C(2) << 5);
    const uint32_t store_acquire = UINT32_C(0x3c20801f)
        | UINT32_C(0x00800000)
        | (UINT32_C(1) << 16)
        | (UINT32_C(2) << 5);
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    if (decode_word(reserved, &instruction) != 0u
        || instruction.last_error_id != CDISASM_STATUS_INVALID_INSTRUCTION
        || decode_word(store_acquire, &instruction) != 0u
        || instruction.last_error_id != CDISASM_STATUS_INVALID_INSTRUCTION) {
        fprintf(stderr, "LSFE reserved encoding legality mismatch\n");
        return 0;
    }
#else
    if (decode_word(reserved, &instruction) != 0u
        || instruction.last_error_id != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
        || decode_word(store_acquire, &instruction) != 0u
        || instruction.last_error_id != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        fprintf(stderr, "LSFE reserved extras-off mismatch\n");
        return 0;
    }
#endif
    return 1;
}

int main(void)
{
    if (!test_load_bf16_acquire()
        || !test_store_bf16_release()
        || !test_fp_widths_and_orders()
        || !test_reserved_selectors()) {
        return 1;
    }
    puts("ARM FEAT_LSFE tests passed");
    return 0;
}
