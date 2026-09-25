#include <stdio.h>
#include <string.h>

/* Canonical recipes must agree with independently assembled NEON shifts. */
#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct neon_size_case {
    uint32_t word;
    uint16_t form_id;
    const char *expected;
} neon_size_case;

static const neon_size_case cases[] = {
    { UINT32_C(0xf28f0011), 923u, "vshr.s8 d0, d1, #1" },
    { UINT32_C(0xf29f0011), 923u, "vshr.s16 d0, d1, #1" },
    { UINT32_C(0xf2bf0011), 923u, "vshr.s32 d0, d1, #1" },
    { UINT32_C(0xf2bf0091), 923u, "vshr.s64 d0, d1, #1" },
    { UINT32_C(0xf2890511), 943u, "vshl.i8 d0, d1, #1" },
    { UINT32_C(0xf2910511), 943u, "vshl.i16 d0, d1, #1" },
    { UINT32_C(0xf2a10511), 943u, "vshl.i32 d0, d1, #1" },
    { UINT32_C(0xf2810591), 943u, "vshl.i64 d0, d1, #1" },
    { UINT32_C(0xf2880011), 923u, "vshr.s8 d0, d1, #8" },
    { UINT32_C(0xf2880511), 943u, "vshl.i8 d0, d1, #0" },
    { UINT32_C(0xef8f0011), 1450u, "vshr.s8 d0, d1, #1" },
    { UINT32_C(0xefbf0091), 1450u, "vshr.s64 d0, d1, #1" },
    { UINT32_C(0xef890511), 1470u, "vshl.i8 d0, d1, #1" },
    { UINT32_C(0xef810591), 1470u, "vshl.i64 d0, d1, #1" }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cdisasm_arm_asmgen_form *form =
            &cdisasm_arm_asmgen_forms[cases[index].form_id - 1u];
        char buffer[96] = {0};
        size_t length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            cases[index].word,
            cases[index].form_id >= 1000u
                ? CDISASM_ARM_ISA_T32 : CDISASM_ARM_ISA_A32,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "NEON shift-size case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    {
        const cdisasm_arm_asmgen_form *form = &cdisasm_arm_asmgen_forms[922u];
        char buffer[96] = {0};

        if (arm_asmgen_render_recipe(
                form->recipe_first, form->recipe_count,
                UINT32_C(0xf2870011), CDISASM_ARM_ISA_A32,
                0u, 0u, 0u, buffer, sizeof(buffer)) != 0u) {
            fputs("invalid zero-width NEON size rendered\n", stderr);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated NEON shift-size tests passed");
    return 0;
}
