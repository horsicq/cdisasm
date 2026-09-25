#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: expectation failed: %s\n", \
            __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)

static uint32_t decode_t32(uint16_t first, uint16_t second,
    cdisasm_arm_instruction *instruction)
{
    uint8_t code[4] = {
        (uint8_t)first, (uint8_t)(first >> 8),
        (uint8_t)second, (uint8_t)(second >> 8)
    };

    return cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32,
        code, sizeof(code), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static void check(uint16_t first, uint16_t second,
    cdisasm_arm_name_id name, unsigned count, unsigned element_size)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_t32(first, second, &instruction) == 4u);
    EXPECT(instruction.name_id == name);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_T32);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_D0);
    EXPECT(instruction.operand[0].register_list == count);
    EXPECT(instruction.operand[0].extend_type == element_size);
    EXPECT(instruction.operand[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[1].base_reg == CDISASM_ARM_REG_R0);
#else
    EXPECT(decode_t32(first, second, &instruction) == 0u);
    EXPECT(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

int main(void)
{
    check(UINT16_C(0xf920), UINT16_C(0x070f),
        CDISASM_ARM_NAME_VLD1, 1u, 1u);
    check(UINT16_C(0xf900), UINT16_C(0x080f),
        CDISASM_ARM_NAME_VST2, 2u, 1u);
    check(UINT16_C(0xf9a0), UINT16_C(0x044f),
        CDISASM_ARM_NAME_VLD1, 1u, 2u);
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    {
        cdisasm_arm_instruction instruction;
        char text[96];

        EXPECT(decode_t32(UINT16_C(0xf920), UINT16_C(0x070f),
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("vld1.8 {d0}, [r0]"));
        EXPECT(strcmp(text, "vld1.8 {d0}, [r0]") == 0);
    }
#endif
    return failures == 0 ? 0 : 1;
}
