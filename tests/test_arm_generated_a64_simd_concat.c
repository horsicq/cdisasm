#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct simd_case {
    uint32_t word;
    uint32_t form_index;
    const char *expected;
} simd_case;

/* Independent LLVM 21 AArch64 assembler/objdump witnesses (+lut for LUTI2). */
static const simd_case cases[] = {
    { UINT32_C(0x2f04e420), 6211u,
      "movi d0, #0xff000000000000ff" },
    { UINT32_C(0x6f02e6a1), 6212u,
      "movi v1.2d, #0xff00ff00ff00ff" },
    { UINT32_C(0x2e043862), 5909u,
      "ext v2.8b, v3.8b, v4.8b, #7" },
    { UINT32_C(0x6e0778c5), 5909u,
      "ext v5.16b, v6.16b, v7.16b, #15" },
    { UINT32_C(0x4ec50083), 5902u,
      "luti2 v3.8h, { v4.8h }, v5[0]" },
    { UINT32_C(0x4ec51083), 5902u,
      "luti2 v3.8h, { v4.8h }, v5[1]" },
    { UINT32_C(0x4ec57083), 5902u,
      "luti2 v3.8h, { v4.8h }, v5[7]" },
    { UINT32_C(0x2f421020), 6276u,
      "fcmla v0.4h, v1.4h, v2.h[0], #0" },
    { UINT32_C(0x2f621020), 6276u,
      "fcmla v0.4h, v1.4h, v2.h[1], #0" },
    { UINT32_C(0x6f653883), 6276u,
      "fcmla v3.8h, v4.8h, v5.h[3], #90" },
    { UINT32_C(0x6f8b7949), 6276u,
      "fcmla v9.4s, v10.4s, v11.s[1], #270" },
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
            fprintf(stderr, "A64 SIMD concat case %zu: got '%s', "
                "expected '%s'\n", index, buffer, cases[index].expected);
            return 1;
        }
    }
    puts("ARM generated A64 SIMD concatenation passed");
    return 0;
}
