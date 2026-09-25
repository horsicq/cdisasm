#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct offset_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} offset_case;

/* Independently assembled from data/arm_pauth_ldst_offset.s by LLVM. */
static const offset_case cases[] = {
    { UINT32_C(0xf8200420), 5548u, CDISASM_ARM_NAME_LDRAA,
      "ldraa x0, [x1]" },
    { UINT32_C(0xf83ff420), 5548u, CDISASM_ARM_NAME_LDRAA,
      "ldraa x0, [x1, #4088]" },
    { UINT32_C(0xf8600420), 5548u, CDISASM_ARM_NAME_LDRAA,
      "ldraa x0, [x1, #-4096]" },
    { UINT32_C(0xf87ffc20), 5549u, CDISASM_ARM_NAME_LDRAA,
      "ldraa x0, [x1, #-8]!" },
    { UINT32_C(0xf8a017e2), 5550u, CDISASM_ARM_NAME_LDRAB,
      "ldrab x2, [sp, #8]" },
    { UINT32_C(0xf8ffffe2), 5551u, CDISASM_ARM_NAME_LDRAB,
      "ldrab x2, [sp, #-8]!" },
};

int main(void)
{
    size_t i;
    int failures = 0;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const offset_case *entry = &cases[i];
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
        if (length == 0u || strcmp(buffer, entry->expected) != 0) {
            fprintf(stderr, "PAUTH load case %zu: got '%s', expected '%s'\n",
                i, buffer, entry->expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated PAUTH load-offset tests passed");
    return 0;
}
