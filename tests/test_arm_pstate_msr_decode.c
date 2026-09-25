#include "cdisasm/cdisasm_arm.h"
#include "cdisasm/cdisasm_format.h"

#include <stdio.h>
#include <string.h>

typedef struct pstate_decode_case {
    uint32_t word;
    uint8_t field;
    uint8_t immediate;
    const char *formatted;
} pstate_decode_case;

/* LLVM 21 AArch64 assembler/objdump and .inst/objdump witnesses. */
static const pstate_decode_case cases[] = {
    { UINT32_C(0xd500457f), CDISASM_ARM_PSTATE_FIELD_UAO, 5u,
      "msr uao, #0x5" },
    { UINT32_C(0xd500459f), CDISASM_ARM_PSTATE_FIELD_PAN, 5u,
      "msr pan, #0x5" },
    { UINT32_C(0xd50045bf), CDISASM_ARM_PSTATE_FIELD_SPSEL, 5u,
      "msr spsel, #0x5" },
    { UINT32_C(0xd501411f), CDISASM_ARM_PSTATE_FIELD_ALLINT, 1u,
      "msr allint, #0x1" },
    { UINT32_C(0xd501431f), CDISASM_ARM_PSTATE_FIELD_PM, 1u,
      "msr pm, #0x1" },
    { UINT32_C(0xd503453f), CDISASM_ARM_PSTATE_FIELD_SSBS, 5u,
      "msr ssbs, #0x5" },
    { UINT32_C(0xd503455f), CDISASM_ARM_PSTATE_FIELD_DIT, 5u,
      "msr dit, #0x5" },
    { UINT32_C(0xd503419f), CDISASM_ARM_PSTATE_FIELD_TCO, 1u,
      "msr tco, #0x1" },
    { UINT32_C(0xd50345df), CDISASM_ARM_PSTATE_FIELD_DAIFSET, 5u,
      "msr daifset, #0x5" },
    { UINT32_C(0xd50341ff), CDISASM_ARM_PSTATE_FIELD_DAIFCLR, 1u,
      "msr daifclr, #0x1" },
};

static uint32_t decode_word(
    cdisasm_arm_cpu_id cpu, uint32_t word,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = {
        (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24)
    };

    return cdisasm_arm_decode(
        cpu, CDISASM_ARM_MODE_A64, bytes, sizeof(bytes),
        UINT64_C(0x1000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;
        char formatted[80];
        size_t length;

        memset(&instruction, 0, sizeof(instruction));
        if (decode_word(CDISASM_ARM_CPU_ANY, cases[index].word,
                &instruction) != 4u
            || instruction.form_id != UINT16_C(4498)
            || instruction.name_id != CDISASM_ARM_NAME_MSR
            || instruction.operand_count != 2u
            || instruction.operand[0].type
                != CDISASM_ARM_OPERAND_PSTATE_FIELD
            || instruction.operand[0].imm != cases[index].field
            || instruction.operand[1].type != CDISASM_OPERAND_IMMEDIATE
            || instruction.operand[1].imm != cases[index].immediate) {
            fprintf(stderr, "PSTATE decode case %zu failed: status=%u "
                "form=%u name=%u operands=%u\n", index,
                (unsigned)instruction.last_error_id,
                (unsigned)instruction.form_id,
                (unsigned)instruction.name_id,
                (unsigned)instruction.operand_count);
            return 1;
        }
        length = cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_0,
            formatted, sizeof(formatted));
        if (length != strlen(cases[index].formatted)
            || strcmp(formatted, cases[index].formatted) != 0) {
            fprintf(stderr, "PSTATE format case %zu failed: '%s'\n",
                index, length == 0u ? "<unavailable>" : formatted);
            return 1;
        }
    }
    {
        static const uint32_t blocked_on_a53[] = {
            UINT32_C(0xd500459f), /* PAN not in the A53 profile */
            UINT32_C(0xd500457f), /* UAO not modeled for named CPUs */
            UINT32_C(0xd501411f), /* NMI not modeled for named CPUs */
            UINT32_C(0xd503419f), /* MTE not in the A53 profile */
        };
        for (index = 0u;
             index < sizeof(blocked_on_a53) / sizeof(blocked_on_a53[0]);
             ++index) {
            cdisasm_arm_instruction instruction;

            if (decode_word(CDISASM_ARM_CPU_CORTEX_A53,
                    blocked_on_a53[index], &instruction) != 0u) {
                fprintf(stderr, "PSTATE unsupported CPU case %zu admitted\n",
                    index);
                return 1;
            }
        }
    }
    {
        cdisasm_arm_instruction instruction;

        if (decode_word(CDISASM_ARM_CPU_CORTEX_A53,
                UINT32_C(0xd50045bf), &instruction) != 4u
            || instruction.operand[0].imm
                != CDISASM_ARM_PSTATE_FIELD_SPSEL) {
            fputs("PSTATE baseline SPSel unexpectedly rejected\n", stderr);
            return 1;
        }
    }
    {
        cdisasm_arm_instruction instruction;
        char formatted[80];

        if (decode_word(CDISASM_ARM_CPU_ANY,
                UINT32_C(0xd50045bf), &instruction) != 4u) {
            fputs("PSTATE mutation seed failed\n", stderr);
            return 1;
        }
        instruction.operand[0].imm = CDISASM_ARM_PSTATE_FIELD_PAN;
        if (cdisasm_arm_format(
                &instruction, 0u, formatted, sizeof(formatted)) != 0u) {
            fputs("PSTATE forged field was formatted\n", stderr);
            return 1;
        }
        instruction.operand[0].imm = CDISASM_ARM_PSTATE_FIELD_SPSEL;
        instruction.operand[1].imm = 4u;
        if (cdisasm_arm_format(
                &instruction, 0u, formatted, sizeof(formatted)) != 0u) {
            fputs("PSTATE forged immediate was formatted\n", stderr);
            return 1;
        }
        if (decode_word(CDISASM_ARM_CPU_ANY,
                UINT32_C(0xd501441f), &instruction) != 0u) {
            fputs("PSTATE unallocated PM CRm was decoded\n", stderr);
            return 1;
        }
    }
    return 0;
}
