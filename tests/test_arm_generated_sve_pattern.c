#include <stdio.h>
#include <string.h>

/* Directly exercise the canonical SQINCH recipe, including the optional
 * pattern and multiplier. Generated-form matching is tested elsewhere. */
#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct pattern_case {
    uint32_t word;
    const char *expected;
} pattern_case;

static const pattern_case cases[] = {
    { UINT32_C(0x0460c3e0), "sqinch z0.h" },
    { UINT32_C(0x0460c020), "sqinch z0.h, vl1" },
    { UINT32_C(0x0460c000), "sqinch z0.h, pow2" },
    { UINT32_C(0x0460c3a0), "sqinch z0.h, mul4" },
    { UINT32_C(0x0460c3c0), "sqinch z0.h, mul3" },
    { UINT32_C(0x0462c120), "sqinch z0.h, vl16, mul #3" },
    { UINT32_C(0x046fc3e0), "sqinch z0.h, all, mul #16" },
    { UINT32_C(0x0460c1c0), "sqinch z0.h, #14" }
};

int main(void)
{
    const cdisasm_arm_asmgen_form *form = &cdisasm_arm_asmgen_forms[2361u];
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char buffer[96] = {0};
        size_t length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            cases[index].word, CDISASM_ARM_ISA_A64,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "SVE pattern case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SVE pattern tests passed");
    return 0;
}
