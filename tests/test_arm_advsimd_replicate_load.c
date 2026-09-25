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
    const uint8_t code[4] = {
        (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24)
    };

    memset(out, 0, sizeof(*out));
    return cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        code, sizeof(code), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, out);
}

static void check_load(
    uint32_t word,
    cdisasm_arm_name_id name,
    cdisasm_arm_form_id form,
    unsigned count,
    unsigned vector_size,
    unsigned element_size,
    unsigned vd,
    unsigned rn)
{
    cdisasm_arm_instruction instruction;
    const cdisasm_arm_operand *list;
    const cdisasm_arm_operand *memory;

#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, &instruction) == 4u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
#else
    EXPECT(decode_word(word, &instruction) == 0u);
    EXPECT(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    return;
#endif
    EXPECT(instruction.name_id == name);
    EXPECT(instruction.form_id == form);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_A64);
    EXPECT(instruction.operand_count == 2u);
    EXPECT((instruction.instruction_flags
        & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) != 0u);
    list = &instruction.operand[0];
    EXPECT(list->type == CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST);
    EXPECT(list->reg == CDISASM_ARM_REG_V0 + vd);
    EXPECT(list->register_list == count);
    EXPECT(list->size == vector_size);
    EXPECT(list->extend_type == element_size);
    EXPECT(list->scale == vector_size / element_size);
    EXPECT(list->access == CDISASM_OPERAND_ACCESS_WRITE);
    memory = &instruction.operand[1];
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
    EXPECT(memory->base_reg == CDISASM_ARM_REG_X0 + rn);
    EXPECT(memory->index_reg == CDISASM_ARM_REG_NONE);
    EXPECT(memory->size == element_size);
    EXPECT(memory->access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_invalid_register_range(void)
{
    cdisasm_arm_instruction instruction;
    uint32_t word = UINT32_C(0x0d60c000) | UINT32_C(31);

#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    EXPECT(decode_word(word, &instruction) == 0u);
    EXPECT(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

int main(void)
{
    /* LD1R {v3.8b}, [x5]. */
    check_load(
        UINT32_C(0x0d40c000) | UINT32_C(3) | (UINT32_C(5) << 5),
        CDISASM_ARM_NAME_LD1R, UINT16_C(4639), 1u, 8u, 1u, 3u, 5u);
    /* LD2R {v4.8h, v5.8h}, [x7]. */
    check_load(
        UINT32_C(0x0d60c000) | (UINT32_C(1) << 10)
            | UINT32_C(4) | (UINT32_C(7) << 5)
            | (UINT32_C(1) << 30),
        CDISASM_ARM_NAME_LD2R, UINT16_C(4650), 2u, 16u, 2u, 4u, 7u);
    /* LD3R {v2.4s, v3.4s, v4.4s}, [sp]. */
    check_load(
        UINT32_C(0x0d40e000) | (UINT32_C(2) << 10)
            | UINT32_C(2) | (UINT32_C(31) << 5),
        CDISASM_ARM_NAME_LD3R, UINT16_C(4640), 3u, 8u, 4u, 2u, 31u);
    /* LD4R {v8.2d, v9.2d, v10.2d, v11.2d}, [x1]. */
    check_load(
        UINT32_C(0x0d60e000) | (UINT32_C(3) << 10)
            | UINT32_C(8) | (UINT32_C(1) << 5)
            | (UINT32_C(1) << 30),
        CDISASM_ARM_NAME_LD4R, UINT16_C(4651), 4u, 16u, 8u, 8u, 1u);
    check_invalid_register_range();

    if (failures == 0) {
        puts("ARM AdvSIMD replicate-load tests passed");
    }
    return failures == 0 ? 0 : 1;
}
