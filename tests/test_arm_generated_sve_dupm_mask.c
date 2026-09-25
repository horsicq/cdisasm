#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct dupm_case {
    uint32_t word;
    const char *expected;
} dupm_case;

/* LLVM-assembled positive words from tests/data/arm_sve_dupm_mask.s. */
static const dupm_case cases[] = {
    { UINT32_C(0x05c00620), "dupm z0.b, #0x3" },
    { UINT32_C(0x05c004e1), "dupm z1.h, #0xff" },
    { UINT32_C(0x05c003c2), "dupm z2.s, #0x7fffffff" },
    { UINT32_C(0x05c00783), "dupm z3.b, #0x55" },
    { UINT32_C(0x05c007e0), NULL },
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
        instruction.form_id = 2427u;
        instruction.name_id = CDISASM_ARM_NAME_DUPM;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if ((cases[i].expected == NULL && length != 0u)
            || (cases[i].expected != NULL
                && (length == 0u
                    || strcmp(buffer, cases[i].expected) != 0))) {
            fprintf(stderr, "SVE DUPM case %zu: got '%s', expected '%s'\n",
                i, buffer,
                cases[i].expected == NULL ? "<rejected>" : cases[i].expected);
            return 1;
        }
    }
    {
        const cdisasm_arm_asmgen_alias *alias =
            &cdisasm_arm_asmgen_aliases[323u];
        char buffer[96] = {0};
        size_t length = arm_asmgen_render_recipe(
            alias->recipe_first, alias->recipe_count,
            UINT32_C(0x05c004e1), CDISASM_ARM_ISA_A64,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, "mov z1.h, #0xff") != 0) {
            fprintf(stderr, "SVE DUPM MOV alias: got '%s'\n", buffer);
            return 1;
        }
    }
    puts("ARM generated SVE DUPM mask tests passed");
    return 0;
}
