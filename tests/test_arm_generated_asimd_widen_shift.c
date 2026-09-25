#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct widen_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} widen_case;

/* Independently assembled from tests/data/arm_asimd_widen_shift.s. */
static const widen_case cases[] = {
    { UINT32_C(0x0f08a420), 6225u, CDISASM_ARM_NAME_SSHLL,
      "sshll v0.8h, v1.8b, #0" },
    { UINT32_C(0x4f0fa462), 6225u, CDISASM_ARM_NAME_SSHLL,
      "sshll2 v2.8h, v3.16b, #7" },
    { UINT32_C(0x2f11a4a4), 6240u, CDISASM_ARM_NAME_USHLL,
      "ushll v4.4s, v5.4h, #1" },
    { UINT32_C(0x6f3fa4e6), 6240u, CDISASM_ARM_NAME_USHLL,
      "ushll2 v6.2d, v7.4s, #31" },
    { UINT32_C(0x0f08a528), 6225u, CDISASM_ARM_NAME_SXTL,
      "sxtl v8.8h, v9.8b" },
    { UINT32_C(0x6f10a56a), 6240u, CDISASM_ARM_NAME_UXTL,
      "uxtl2 v10.4s, v11.8h" },
    { UINT32_C(0x0f00a420), 6225u, CDISASM_ARM_NAME_SSHLL, NULL },
    { UINT32_C(0x0f40a420), 6225u, CDISASM_ARM_NAME_SSHLL, NULL },
};

int main(void)
{
    size_t i;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const widen_case *entry = &cases[i];
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
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
            fprintf(stderr, "widen case %zu: got '%s', expected '%s'\n",
                i, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            return 1;
        }
    }
    puts("ARM generated ASIMD widening tests passed");
    return 0;
}
