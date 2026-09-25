#include "../src/arm/arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct vmov_pair_case {
    uint32_t word;
    uint16_t form_id;
    const char *expected;
} vmov_pair_case;

/* Independent LLVM 21 ARM-mode assembly witnesses. */
static const vmov_pair_case cases[] = {
    { UINT32_C(0xec510a10), 494u, "vmov r0, r1, s0, s1" },
    { UINT32_C(0xec510a30), 494u, "vmov r0, r1, s1, s2" },
    { UINT32_C(0xec410a1f), 493u, "vmov s30, s31, r0, r1" },
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
        instruction.name_id = CDISASM_ARM_NAME_VMOV;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length != strlen(cases[index].expected)
            || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "VMOV S-pair case %zu: got '%s', expected '%s'\n",
                index, length ? buffer : "<no exact recipe>",
                cases[index].expected);
            return 1;
        }
    }
    {
        cdisasm_arm_instruction invalid = {0};
        char buffer[128];

        invalid.raw_instruction = UINT32_C(0xec510a3f); /* Sm=31 */
        invalid.opcode_size = 4u;
        invalid.isa_id = CDISASM_ARM_ISA_A32;
        invalid.form_id = 494u;
        invalid.name_id = CDISASM_ARM_NAME_VMOV;
        invalid.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        if (cdisasm_arm_format_generated(
                &invalid, 0u, buffer, sizeof(buffer)) != 0u) {
            fputs("out-of-range VMOV S-register pair was accepted\n", stderr);
            return 1;
        }
    }
#endif
    puts("ARM generated VMOV S-pair tests passed");
    return 0;
}
