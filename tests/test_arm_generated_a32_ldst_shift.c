#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct shift_case {
    uint32_t word;
    const char *expected;
} shift_case;

static const shift_case cases[] = {
    { UINT32_C(0xe7810002), "str r0, [r1, r2]" },
    { UINT32_C(0xe7810082), "str r0, [r1, r2, lsl #1]" },
    { UINT32_C(0xe7810f82), "str r0, [r1, r2, lsl #31]" },
    { UINT32_C(0xe78100a2), "str r0, [r1, r2, lsr #1]" },
    { UINT32_C(0xe7810022), "str r0, [r1, r2, lsr #32]" },
    { UINT32_C(0xe7810042), "str r0, [r1, r2, asr #32]" },
    { UINT32_C(0xe78100e2), "str r0, [r1, r2, ror #1]" },
    { UINT32_C(0xe7810062), "str r0, [r1, r2, rrx]" }
};

int main(void)
{
    const cdisasm_arm_asmgen_form *form = &cdisasm_arm_asmgen_forms[281u];
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char buffer[96] = {0};
        size_t length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            cases[index].word, CDISASM_ARM_ISA_A32,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "A32 load/store shift case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated A32 load/store shift tests passed");
    return 0;
}
