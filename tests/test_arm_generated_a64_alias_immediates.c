#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct alias_case {
    uint32_t word;
    uint32_t record_index;
    int alias;
    const char *expected;
} alias_case;

/* Independent LLVM 21 AArch64 assembler/objdump words. */
static const alias_case cases[] = {
    { UINT32_C(0x12800000), 394u, 1, "mov w0, #4294967295" },
    { UINT32_C(0x52a00021), 395u, 1, "mov w1, #65536" },
    { UINT32_C(0x92800002), 396u, 1,
      "mov x2, #18446744073709551615" },
    { UINT32_C(0xd2c00023), 397u, 1, "mov x3, #4294967296" },
    { UINT32_C(0x32009fe4), 390u, 1, "mov w4, #16711935" },
    { UINT32_C(0xb2009fe5), 392u, 1,
      "mov x5, #71777214294589695" },
    { UINT32_C(0xf2401cdf), 393u, 1, "tst x6, #255" },
    { UINT32_C(0xf2401d07), 4418u, 0, "ands x7, x8, #255" },
};

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t recipe_first;
        uint16_t recipe_count;
        char buffer[128] = {0};
        size_t length;

        if (cases[index].alias) {
            const cdisasm_arm_asmgen_alias *alias =
                &cdisasm_arm_asmgen_aliases[cases[index].record_index];
            recipe_first = alias->recipe_first;
            recipe_count = alias->recipe_count;
        } else {
            const cdisasm_arm_asmgen_form *form =
                &cdisasm_arm_asmgen_forms[cases[index].record_index];
            recipe_first = form->recipe_first;
            recipe_count = form->recipe_count;
        }
        length = arm_asmgen_render_recipe(
            recipe_first, recipe_count, cases[index].word,
            CDISASM_ARM_ISA_A64, 0u, 0u, 0u, buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "A64 alias immediate case %zu: got '%s', "
                "expected '%s'\n", index, buffer, cases[index].expected);
            return 1;
        }
    }
    puts("ARM generated A64 alias immediates passed");
    return 0;
}
