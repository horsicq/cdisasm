#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct worx_case {
    uint32_t word;
    uint32_t form_index;
    const char *expected;
} worx_case;

static const worx_case cases[] = {
    { UINT32_C(0x38224820), 5516u, "strb w0, [x1, w2, uxtw]" },
    { UINT32_C(0x38226820), 5516u, "strb w0, [x1, x2]" },
    { UINT32_C(0x3822c820), 5516u, "strb w0, [x1, w2, sxtw]" },
    { UINT32_C(0x3822e820), 5516u, "strb w0, [x1, x2, sxtx]" },
    { UINT32_C(0x383f4820), 5516u, "strb w0, [x1, wzr, uxtw]" },
    { UINT32_C(0x383f6820), 5516u, "strb w0, [x1, xzr]" },
    { UINT32_C(0x38225820), 5516u,
        "strb w0, [x1, w2, uxtw #0]" },
    { UINT32_C(0xb8625820), 5537u,
        "ldr w0, [x1, w2, uxtw #2]" },
    { UINT32_C(0xf8627820), 5542u,
        "ldr x0, [x1, x2, lsl #3]" },
    { UINT32_C(0x3ce27820), 5529u,
        "ldr q0, [x1, x2, lsl #4]" }
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
            fprintf(stderr, "A64 WorX case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated A64 register-offset width tests passed");
    return 0;
}
