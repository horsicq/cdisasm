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
    uint32_t isa_id;
    const char *expected;
} narrow_case;

static const narrow_case cases[] = {
    { UINT32_C(0xf28f0812), 944u, CDISASM_ARM_ISA_A32,
        "vshrn.i16 d0, q1, #1" },
    { UINT32_C(0xf2880812), 944u, CDISASM_ARM_ISA_A32,
        "vshrn.i16 d0, q1, #8" },
    { UINT32_C(0xf29f0812), 944u, CDISASM_ARM_ISA_A32,
        "vshrn.i32 d0, q1, #1" },
    { UINT32_C(0xf2900812), 944u, CDISASM_ARM_ISA_A32,
        "vshrn.i32 d0, q1, #16" },
    { UINT32_C(0xf2bf0812), 944u, CDISASM_ARM_ISA_A32,
        "vshrn.i64 d0, q1, #1" },
    { UINT32_C(0xf2a00812), 944u, CDISASM_ARM_ISA_A32,
        "vshrn.i64 d0, q1, #32" },
    { UINT32_C(0xef8f0812), 1471u, CDISASM_ARM_ISA_T32,
        "vshrn.i16 d0, q1, #1" },
    { UINT32_C(0xef900812), 1471u, CDISASM_ARM_ISA_T32,
        "vshrn.i32 d0, q1, #16" },
    { UINT32_C(0xefa00812), 1471u, CDISASM_ARM_ISA_T32,
        "vshrn.i64 d0, q1, #32" }
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
            cases[index].word, cases[index].isa_id,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "NEON narrow shift case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated NEON narrow-shift tests passed");
    return 0;
}
