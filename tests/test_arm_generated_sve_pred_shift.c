#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct pred_shift_case {
    uint32_t word;
    uint32_t form_index;
    const char *expected;
} pred_shift_case;

static const pred_shift_case cases[] = {
    { UINT32_C(0x040081e0), 2260u,
        "asr z0.b, p0/m, z0.b, #1" },
    { UINT32_C(0x04008100), 2260u,
        "asr z0.b, p0/m, z0.b, #8" },
    { UINT32_C(0x040083e0), 2260u,
        "asr z0.h, p0/m, z0.h, #1" },
    { UINT32_C(0x044083e0), 2260u,
        "asr z0.s, p0/m, z0.s, #1" },
    { UINT32_C(0x04c083e0), 2260u,
        "asr z0.d, p0/m, z0.d, #1" },
    { UINT32_C(0x04038120), 2261u,
        "lsl z0.b, p0/m, z0.b, #1" },
    { UINT32_C(0x040383e0), 2261u,
        "lsl z0.h, p0/m, z0.h, #15" },
    { UINT32_C(0x04c383e0), 2261u,
        "lsl z0.d, p0/m, z0.d, #63" }
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
            fprintf(stderr, "SVE predicated shift case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SVE predicated-shift tests passed");
    return 0;
}
