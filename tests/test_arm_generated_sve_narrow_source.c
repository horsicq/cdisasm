#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct narrow_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} narrow_case;

/* Independently assembled from data/arm_sve_narrow_source.s by LLVM. */
static const narrow_case cases[] = {
    { UINT32_C(0x45626020), 2884u, CDISASM_ARM_NAME_ADDHNB,
      "addhnb z0.b, z1.h, z2.h" },
    { UINT32_C(0x45a56883), 2885u, CDISASM_ARM_NAME_RADDHNB,
      "raddhnb z3.h, z4.s, z5.s" },
    { UINT32_C(0x45e870e6), 2886u, CDISASM_ARM_NAME_SUBHNB,
      "subhnb z6.s, z7.d, z8.d" },
    { UINT32_C(0x456b7949), 2887u, CDISASM_ARM_NAME_RSUBHNB,
      "rsubhnb z9.b, z10.h, z11.h" },
    { UINT32_C(0x45226020), 2884u, CDISASM_ARM_NAME_ADDHNB,
      NULL },
};

int main(void)
{
    size_t i;
    int failures = 0;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const narrow_case *entry = &cases[i];
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
            fprintf(stderr, "SVE narrow case %zu: got '%s', expected '%s'\n",
                i, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SVE narrow-source tests passed");
    return 0;
}
