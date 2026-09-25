#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

typedef struct rcw_case {
    uint32_t base;
    cdisasm_arm_name_id name;
    uint16_t form;
    uint32_t flags;
} rcw_case;

static const rcw_case cases[] = {
    { UINT32_C(0x38209000), CDISASM_ARM_NAME_RCWCLR, 1205u, 0u },
    { UINT32_C(0x3860a000), CDISASM_ARM_NAME_RCWSWPL, 1256u,
      CDISASM_ARM_INSTRUCTION_FLAG_RELEASE },
    { UINT32_C(0x38a0b000), CDISASM_ARM_NAME_RCWSETA, 1230u,
      CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE },
    { UINT32_C(0x38e09000), CDISASM_ARM_NAME_RCWCLRAL, 1207u,
      CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
        | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE },
    { UINT32_C(0x7820b000), CDISASM_ARM_NAME_RCWSSET, 1237u, 0u },
    { UINT32_C(0x78e0a000), CDISASM_ARM_NAME_RCWSSWPAL, 1247u,
      CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
        | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE }
};

static uint32_t decode(uint32_t word, cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = {
        (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24)
    };

    return cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

int main(void)
{
    size_t i;
    int failures = 0;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cdisasm_arm_instruction instruction;
        uint32_t word = cases[i].base
            | (UINT32_C(1) << 16) | (UINT32_C(2) << 5) | UINT32_C(3);

        memset(&instruction, 0, sizeof(instruction));
        if (decode(word, &instruction) != 4u
            || instruction.last_error_id != CDISASM_STATUS_OK
            || instruction.name_id != cases[i].name
            || instruction.form_id != cases[i].form
            || instruction.operand_count != 3u
            || instruction.operand[0].reg != CDISASM_ARM_REG_X1
            || instruction.operand[1].reg != CDISASM_ARM_REG_X3
            || instruction.operand[2].base_reg != CDISASM_ARM_REG_X2
            || instruction.operand[2].size != 8u
            || (instruction.instruction_flags &
                (CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                    | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE))
                != cases[i].flags) {
            fprintf(stderr, "RCW case %zu mismatch: size=%u status=%u name=%u form=%u operands=%u flags=%08x\n",
                    i, (unsigned)decode(word, &instruction),
                    (unsigned)instruction.last_error_id,
                    (unsigned)instruction.name_id,
                    (unsigned)instruction.form_id,
                    (unsigned)instruction.operand_count,
                    (unsigned)instruction.instruction_flags);
            fprintf(stderr, "  regs=%u,%u,%u sizes=%u,%u,%u expected-flags=%08x\n",
                    (unsigned)instruction.operand[0].reg,
                    (unsigned)instruction.operand[1].reg,
                    (unsigned)instruction.operand[2].reg,
                    (unsigned)instruction.operand[0].size,
                    (unsigned)instruction.operand[1].size,
                    (unsigned)instruction.operand[2].size,
                    (unsigned)cases[i].flags);
            ++failures;
        }
    }

#if !USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction instruction;
        memset(&instruction, 0, sizeof(instruction));
        (void)decode(cases[0].base, &instruction);
        if (instruction.last_error_id != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            fprintf(stderr, "RCW extras-off gate mismatch\n");
            ++failures;
        }
    }
#endif
    if (failures != 0) return 1;
    puts("ARM FEAT_THE RCW tests passed");
    return 0;
}
