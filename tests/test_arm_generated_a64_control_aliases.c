#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct control_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} control_case;

/* SHUH bytes: LLVM AArch64 armv9.7a-memsys.s and GNU binutils CMH tests.
 * SME state bytes: independently assembled with LLVM 21, -march=armv9-a+sme. */
static const control_case cases[] = {
    { UINT32_C(0xd503265f), 4489u, CDISASM_ARM_NAME_SHUH, "shuh" },
    { UINT32_C(0xd503267f), 4489u, CDISASM_ARM_NAME_SHUH, "shuh ph" },
    { UINT32_C(0xd503269f), 4489u, CDISASM_ARM_NAME_SHUH, NULL },
    { UINT32_C(0xd503477f), 4498u, CDISASM_ARM_NAME_SMSTART, "smstart" },
    { UINT32_C(0xd503437f), 4498u, CDISASM_ARM_NAME_SMSTART, "smstart sm" },
    { UINT32_C(0xd503457f), 4498u, CDISASM_ARM_NAME_SMSTART, "smstart za" },
    { UINT32_C(0xd503467f), 4498u, CDISASM_ARM_NAME_SMSTOP, "smstop" },
    { UINT32_C(0xd503427f), 4498u, CDISASM_ARM_NAME_SMSTOP, "smstop sm" },
    { UINT32_C(0xd503447f), 4498u, CDISASM_ARM_NAME_SMSTOP, "smstop za" },
    { UINT32_C(0xd503427f), 4498u, CDISASM_ARM_NAME_SMSTART, NULL },
    { UINT32_C(0xd503437f), 4498u, CDISASM_ARM_NAME_SMSTOP, NULL },
    { UINT32_C(0xd503407f), 4498u, CDISASM_ARM_NAME_SMSTOP, NULL },
};

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const control_case *entry = &cases[index];
        cdisasm_arm_instruction instruction = {0};
        char buffer[64] = {0};
        size_t length;

        instruction.raw_instruction = entry->word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A64;
        instruction.form_id = entry->form_id;
        instruction.name_id = entry->name_id;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if ((entry->expected == NULL && length != 0u)
            || (entry->expected != NULL
                && (length == 0u
                    || strcmp(buffer, entry->expected) != 0))) {
            fprintf(stderr, "A64 control case %zu: got '%s', expected '%s'\n",
                index, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            return 1;
        }
    }
    puts("ARM generated A64 control aliases passed");
    return 0;
}
