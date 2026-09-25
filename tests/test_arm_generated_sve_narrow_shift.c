#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct narrow_case {
    uint32_t word;
    uint32_t form_index;
    const char *expected;
} narrow_case;

static const narrow_case cases[] = {
    { UINT32_C(0x452f1020), 2851u, "shrnb z0.b, z1.h, #1" },
    { UINT32_C(0x45281020), 2851u, "shrnb z0.b, z1.h, #8" },
    { UINT32_C(0x453f1020), 2851u, "shrnb z0.h, z1.s, #1" },
    { UINT32_C(0x45301020), 2851u, "shrnb z0.h, z1.s, #16" },
    { UINT32_C(0x457f1020), 2851u, "shrnb z0.s, z1.d, #1" },
    { UINT32_C(0x45601020), 2851u, "shrnb z0.s, z1.d, #32" },
    { UINT32_C(0x452f1420), 2857u, "shrnt z0.b, z1.h, #1" },
    { UINT32_C(0x45601420), 2857u, "shrnt z0.s, z1.d, #32" }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cdisasm_arm_asmgen_form *form =
            &cdisasm_arm_asmgen_forms[cases[index].form_index];
        char buffer[96] = {0};
        size_t length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            cases[index].word, CDISASM_ARM_ISA_A64,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "SVE narrow shift case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SVE narrow-shift tests passed");
    return 0;
}
