#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct orn_case {
    uint32_t word;
    uint32_t form_index;
    const char *expected;
} orn_case;

/* LLVM 21 assembles f061 00ff and f473 7280. These are architectural
 * 32-bit words passed directly to the recipe renderer. */
static const orn_case cases[] = {
    { UINT32_C(0xf06100ff), 1872u, "orn r0, r1, #255" },
    { UINT32_C(0xf4737280), 1871u, "orns r2, r3, #256" },
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
            cases[index].word, CDISASM_ARM_ISA_T32,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "Thumb ORN case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            return 1;
        }
    }
    puts("ARM generated Thumb ORN immediate tests passed");
    return 0;
}
