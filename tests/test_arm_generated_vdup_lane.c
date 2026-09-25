#include "../src/arm/arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct vdup_lane_case {
    uint32_t word;
    uint16_t form_id;
    const char *expected;
} vdup_lane_case;

/* Independently assembled with LLVM 21 for ARM mode. */
static const vdup_lane_case cases[] = {
    { UINT32_C(0xf3bf0c02), 863u, "vdup.8 d0, d2[7]" },
    { UINT32_C(0xf3be0c62), 864u, "vdup.16 q0, d18[3]" },
    { UINT32_C(0xf3bc0c02), 863u, "vdup.32 d0, d2[1]" },
};

int main(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
        size_t length;

        instruction.raw_instruction = cases[index].word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A32;
        instruction.form_id = cases[index].form_id;
        instruction.name_id = CDISASM_ARM_NAME_VDUP;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length != strlen(cases[index].expected)
            || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "VDUP lane case %zu: got '%s', expected '%s'\n",
                index, length ? buffer : "<no exact recipe>",
                cases[index].expected);
            return 1;
        }
    }
    {
        cdisasm_arm_instruction invalid = {0};
        char buffer[128];

        invalid.raw_instruction = UINT32_C(0xf3b80c02); /* imm4=8 */
        invalid.opcode_size = 4u;
        invalid.isa_id = CDISASM_ARM_ISA_A32;
        invalid.form_id = 863u;
        invalid.name_id = CDISASM_ARM_NAME_VDUP;
        invalid.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        if (cdisasm_arm_format_generated(
                &invalid, 0u, buffer, sizeof(buffer)) != 0u) {
            fputs("invalid VDUP imm4 lane selector was accepted\n", stderr);
            return 1;
        }
    }
#endif
    puts("ARM generated VDUP-lane tests passed");
    return 0;
}
