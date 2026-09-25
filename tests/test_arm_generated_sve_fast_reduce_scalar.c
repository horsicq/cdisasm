#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct reduce_case {
    uint32_t word;
    const char *expected;
} reduce_case;

static const reduce_case cases[] = {
    { UINT32_C(0x65402020), "faddv h0, p0, z1.h" },
    { UINT32_C(0x65802020), "faddv s0, p0, z1.s" },
    { UINT32_C(0x65c02020), "faddv d0, p0, z1.d" }
};

int main(void)
{
    const cdisasm_arm_asmgen_form *form = &cdisasm_arm_asmgen_forms[3062u];
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char buffer[96] = {0};
        size_t length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            cases[index].word, CDISASM_ARM_ISA_A64,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "SVE scalar reduce case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SVE scalar-reduction tests passed");
    return 0;
}
