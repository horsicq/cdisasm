#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct fadda_case {
    uint32_t word;
    const char *expected;
} fadda_case;

/* LLVM-assembled positive words from tests/data/arm_sve_fadda_scalar.s. */
static const fadda_case cases[] = {
    { UINT32_C(0x65582020), "fadda h0, p0, h0, z1.h" },
    { UINT32_C(0x65982c82), "fadda s2, p3, s2, z4.s" },
    { UINT32_C(0x65d83cc5), "fadda d5, p7, d5, z6.d" },
    { UINT32_C(0x65182020), NULL },
};

int main(void)
{
    size_t i;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cdisasm_arm_instruction instruction = {0};
        char buffer[96] = {0};
        size_t length;

        instruction.raw_instruction = cases[i].word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A64;
        instruction.form_id = 3183u;
        instruction.name_id = CDISASM_ARM_NAME_FADDA;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if ((cases[i].expected == NULL && length != 0u)
            || (cases[i].expected != NULL
                && (length == 0u
                    || strcmp(buffer, cases[i].expected) != 0))) {
            fprintf(stderr, "SVE FADDA case %zu: got '%s', expected '%s'\n",
                i, buffer,
                cases[i].expected == NULL ? "<rejected>" : cases[i].expected);
            return 1;
        }
    }
    puts("ARM generated SVE FADDA scalar tests passed");
    return 0;
}
