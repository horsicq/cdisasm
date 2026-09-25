#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct mov_dup_case {
    uint32_t word;
    const char *expected;
} mov_dup_case;

/* LLVM-assembled words from tests/data/arm_mov_dup_scalar_alias.s. */
static const mov_dup_case cases[] = {
    { UINT32_C(0x5e010420), "mov b0, v1.b[0]" },
    { UINT32_C(0x5e060462), "mov h2, v3.h[1]" },
    { UINT32_C(0x5e1404a4), "mov s4, v5.s[2]" },
    { UINT32_C(0x5e1804e6), "mov d6, v7.d[1]" },
    { UINT32_C(0x5e000420), NULL },
};

int main(void)
{
    const cdisasm_arm_asmgen_alias *alias = &cdisasm_arm_asmgen_aliases[602u];
    size_t i;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char buffer[96] = {0};
        size_t length = arm_asmgen_render_recipe(
            alias->recipe_first, alias->recipe_count,
            cases[i].word, CDISASM_ARM_ISA_A64,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if ((cases[i].expected == NULL && length != 0u)
            || (cases[i].expected != NULL
                && (length == 0u
                    || strcmp(buffer, cases[i].expected) != 0))) {
            fprintf(stderr, "MOV scalar DUP alias case %zu: got '%s', expected '%s'\n",
                i, buffer,
                cases[i].expected == NULL ? "<rejected>" : cases[i].expected);
            return 1;
        }
    }
    puts("ARM generated MOV scalar DUP alias tests passed");
    return 0;
}
