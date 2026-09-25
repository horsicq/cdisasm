#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct concat_case {
    uint32_t word;
    uint32_t form_index;
    const char *expected;
} concat_case;

static const concat_case cases[] = {
    /* LLVM 21 SME2.1 LUTI2/LUTI4 stride-eight pair witnesses. */
    { UINT32_C(0xc09c4040), 3932u,
        "luti2 { z0.b, z8.b }, zt0, z2[0]" },
    { UINT32_C(0xc09c4047), 3932u,
        "luti2 { z7.b, z15.b }, zt0, z2[0]" },
    { UINT32_C(0xc09c4050), 3932u,
        "luti2 { z16.b, z24.b }, zt0, z2[0]" },
    { UINT32_C(0xc09a4040), 3933u,
        "luti4 { z0.b, z8.b }, zt0, z2[0]" },
    /* LLVM 21 AArch64 AdvSIMD FMOV witnesses; imm8 is FPExpandImm. */
    { UINT32_C(0x0f03f600), 6204u, "fmov v0.2s, #1.0" },
    { UINT32_C(0x4f04f401), 6204u, "fmov v1.4s, #-2.0" },
    { UINT32_C(0x0f03fc02), 6205u, "fmov v2.4h, #0.5" },
    { UINT32_C(0x4f07fe03), 6205u, "fmov v3.8h, #-1.0" },
    { UINT32_C(0x6f00f404), 6213u, "fmov v4.2d, #2.0" },
};

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cdisasm_arm_asmgen_form *form =
            &cdisasm_arm_asmgen_forms[cases[index].form_index];
        char buffer[128] = {0};
        size_t length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            cases[index].word, CDISASM_ARM_ISA_A64,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "concat case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            return 1;
        }
    }
    puts("ARM generated concatenation round-five tests passed");
    return 0;
}
