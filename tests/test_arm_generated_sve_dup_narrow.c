#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct sve_case {
    uint32_t word;
    uint32_t index;
    int is_alias;
    const char *expected;
} sve_case;

static const sve_case cases[] = {
    { UINT32_C(0x45284020), 2874u, 0, "sqxtnb z0.b, z1.h" },
    { UINT32_C(0x45304062), 2874u, 0, "sqxtnb z2.h, z3.s" },
    { UINT32_C(0x456040a4), 2874u, 0, "sqxtnb z4.s, z5.d" },
    { UINT32_C(0x452844e6), 2876u, 0, "sqxtnt z6.b, z7.h" },
    { UINT32_C(0x45304528), 2876u, 0, "sqxtnt z8.h, z9.s" },
    { UINT32_C(0x4560456a), 2876u, 0, "sqxtnt z10.s, z11.d" },
    { UINT32_C(0x453051ac), 2875u, 0, "sqxtunb z12.h, z13.s" },
    { UINT32_C(0x456055ee), 2877u, 0, "sqxtunt z14.s, z15.d" },
    { UINT32_C(0x45284a30), 2878u, 0, "uqxtnb z16.b, z17.h" },
    { UINT32_C(0x45604e72), 2879u, 0, "uqxtnt z18.s, z19.d" },
    { UINT32_C(0x05212020), 2438u, 0, "dup z0.b, z1.b[0]" },
    { UINT32_C(0x05212020), 328u, 1, "mov z0.b, b1" },
    { UINT32_C(0x05262062), 2438u, 0, "dup z2.h, z3.h[1]" },
    { UINT32_C(0x05262062), 329u, 1, "mov z2.h, z3.h[1]" },
    { UINT32_C(0x053420a4), 2438u, 0, "dup z4.s, z5.s[2]" },
    { UINT32_C(0x053820e6), 2438u, 0, "dup z6.d, z7.d[1]" },
    { UINT32_C(0x05702128), 2438u, 0, "dup z8.q, z9.q[1]" }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t recipe_first;
        uint16_t recipe_count;
        char buffer[128] = {0};
        size_t length;

        if (cases[index].is_alias) {
            const cdisasm_arm_asmgen_alias *alias =
                &cdisasm_arm_asmgen_aliases[cases[index].index];
            recipe_first = alias->recipe_first;
            recipe_count = alias->recipe_count;
        } else {
            const cdisasm_arm_asmgen_form *form =
                &cdisasm_arm_asmgen_forms[cases[index].index];
            recipe_first = form->recipe_first;
            recipe_count = form->recipe_count;
        }
        length = arm_asmgen_render_recipe(
            recipe_first, recipe_count, cases[index].word,
            CDISASM_ARM_ISA_A64, 0u, 0u, 0u,
            buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "SVE DUP/narrow case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SVE DUP/narrow tests passed");
    return 0;
}
