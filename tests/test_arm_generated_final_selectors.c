#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct selector_case {
    uint32_t word;
    uint32_t form_index;
    const char *expected;
} selector_case;

static const selector_case cases[] = {
    { UINT32_C(0x042f9020), 2334u, "asr z0.b, z1.b, #1" },
    { UINT32_C(0x04309062), 2334u, "asr z2.h, z3.h, #16" },
    { UINT32_C(0x04609ca4), 2335u, "lsl z4.s, z5.s, #0" },
    { UINT32_C(0x04ff9ce6), 2335u, "lsl z6.d, z7.d, #63" },
    { UINT32_C(0x04289528), 2336u, "lsr z8.b, z9.b, #8" },
    { UINT32_C(0x046f956a), 2336u, "lsr z10.s, z11.s, #17" },
    { UINT32_C(0x5f097420), 5857u, "sqshl b0, b1, #1" },
    { UINT32_C(0x5f177462), 5857u, "sqshl h2, h3, #7" },
    { UINT32_C(0x5f3174a4), 5857u, "sqshl s4, s5, #17" },
    { UINT32_C(0x5f7f74e6), 5857u, "sqshl d6, d7, #63" },
    { UINT32_C(0x7f086528), 5868u, "sqshlu b8, b9, #0" },
    { UINT32_C(0x7f1f756a), 5869u, "uqshl h10, h11, #15" },
    { UINT32_C(0x0ea2dc20), 6150u,
        "famax v0.2s, v1.2s, v2.2s" },
    { UINT32_C(0x4ea5dc83), 6150u,
        "famax v3.4s, v4.4s, v5.4s" },
    { UINT32_C(0x6ee8dce6), 6190u,
        "famin v6.2d, v7.2d, v8.2d" },
    { UINT32_C(0x6eabfd49), 6194u,
        "fscale v9.4s, v10.4s, v11.4s" }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cdisasm_arm_asmgen_form *form =
            &cdisasm_arm_asmgen_forms[cases[index].form_index];
        char buffer[128] = {0};
        size_t length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            cases[index].word, CDISASM_ARM_ISA_A64,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "ARM selector case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated final selectors tests passed");
    return 0;
}
