#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct luti_case {
    uint32_t word;
    uint32_t form_index;
    const char *expected;
} luti_case;

static const luti_case cases[] = {
    { UINT32_C(0xc08c4040), 3919u,
        "luti2 { z0.b-z1.b }, zt0, z2[0]" },
    { UINT32_C(0xc08c5040), 3919u,
        "luti2 { z0.h-z1.h }, zt0, z2[0]" },
    { UINT32_C(0xc08c6040), 3919u,
        "luti2 { z0.s-z1.s }, zt0, z2[0]" },
    { UINT32_C(0xc08a4040), 3920u,
        "luti4 { z0.b-z1.b }, zt0, z2[0]" },
    { UINT32_C(0xc08dd0e4), 3919u,
        "luti2 { z4.h-z5.h }, zt0, z7[3]" },
    { UINT32_C(0xc08c805c), 3921u,
        "luti2 { z28.b-z31.b }, zt0, z2[0]" },
    { UINT32_C(0xc0cc0040), 3923u,
        "luti2 z0.b, zt0, z2[0]" },
    { UINT32_C(0xc0ca0040), 3924u,
        "luti4 z0.b, zt0, z2[0]" }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cdisasm_arm_asmgen_form *form =
            &cdisasm_arm_asmgen_forms[cases[index].form_index];
        char buffer[128] = {0};
        size_t length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            cases[index].word, CDISASM_ARM_ISA_A64,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "SME LUTI case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SME LUTI tests passed");
    return 0;
}
