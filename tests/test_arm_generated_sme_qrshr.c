#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct qrshr_case {
    uint32_t word;
    const char *expected;
} qrshr_case;

static const qrshr_case cases[] = {
    { UINT32_C(0xc17fd800),
        "sqrshr z0.b, { z0.s-z3.s }, #1" },
    { UINT32_C(0xc1ffd800),
        "sqrshr z0.h, { z0.d-z3.d }, #1" },
    { UINT32_C(0xc160d800),
        "sqrshr z0.b, { z0.s-z3.s }, #32" },
    { UINT32_C(0xc1e0d800),
        "sqrshr z0.h, { z0.d-z3.d }, #32" },
    { UINT32_C(0xc1a0d800),
        "sqrshr z0.h, { z0.d-z3.d }, #64" },
    { UINT32_C(0xc17fd885),
        "sqrshr z5.b, { z4.s-z7.s }, #1" },
    { UINT32_C(0xc1a0db87),
        "sqrshr z7.h, { z28.d-z31.d }, #64" }
};

int main(void)
{
    const cdisasm_arm_asmgen_form *form = &cdisasm_arm_asmgen_forms[4305u];
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char buffer[128] = {0};
        size_t length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            cases[index].word, CDISASM_ARM_ISA_A64,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "SME QRSHR case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SME QRSHR tests passed");
    return 0;
}
