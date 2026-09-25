#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct gpr_case {
    uint32_t word;
    uint32_t form_index;
    const char *expected;
} gpr_case;

static const gpr_case cases[] = {
    { UINT32_C(0x25221020), 2584u, "whilege p0.b, x1, x2" },
    { UINT32_C(0x252213e0), 2584u, "whilege p0.b, xzr, x2" },
    { UINT32_C(0x253f1020), 2584u, "whilege p0.b, x1, xzr" },
    { UINT32_C(0x252203e0), 2584u, "whilege p0.b, wzr, w2" },
    { UINT32_C(0x25e22020), 2592u, "ctermeq x1, x2" },
    { UINT32_C(0x25e223e0), 2592u, "ctermeq xzr, x2" }
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
            fprintf(stderr, "SVE GPR suffix case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SVE GPR suffix tests passed");
    return 0;
}
