#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct pmov_case {
    uint32_t word;
    uint32_t form_index;
    const char *expected;
} pmov_case;

/* Independent LLVM AArch64 armv9.5-a+sme2 assembler/objdump witnesses. */
static const pmov_case cases[] = {
    { UINT32_C(0x05a83820), 2450u, "pmov p0.d, z1[0]" },
    { UINT32_C(0x05ee3862), 2450u, "pmov p2.d, z3[7]" },
    { UINT32_C(0x05a938a4), 2454u, "pmov z4[0], p5.d" },
    { UINT32_C(0x05ef38e6), 2454u, "pmov z6[7], p7.d" },
};

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cdisasm_arm_asmgen_form *form =
            &cdisasm_arm_asmgen_forms[cases[index].form_index];
        char buffer[128] = {0};
        size_t length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            cases[index].word, CDISASM_ARM_ISA_A64,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "A64 PMOV case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            return 1;
        }
    }
    puts("ARM generated A64 PMOV passed");
    return 0;
}
