#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct prfop_case {
    uint32_t word;
    const char *expected;
} prfop_case;

static const prfop_case cases[] = {
    { UINT32_C(0x85c00000), "prfb pldl1keep, p0, [x0, #0, mul vl]" },
    { UINT32_C(0x85c00005), "prfb pldl3strm, p0, [x0, #0, mul vl]" },
    { UINT32_C(0x85c00008), "prfb pstl1keep, p0, [x0, #0, mul vl]" },
    { UINT32_C(0x85c0000d), "prfb pstl3strm, p0, [x0, #0, mul vl]" },
    { UINT32_C(0x85c00006), "prfb #6, p0, [x0, #0, mul vl]" },
    { UINT32_C(0x85c0000f), "prfb #15, p0, [x0, #0, mul vl]" }
};

int main(void)
{
    const cdisasm_arm_asmgen_form *form = &cdisasm_arm_asmgen_forms[3215u];
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char buffer[96] = {0};
        size_t length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            cases[index].word, CDISASM_ARM_ISA_A64,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "SVE prfop case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SVE prefetch-operation tests passed");
    return 0;
}
