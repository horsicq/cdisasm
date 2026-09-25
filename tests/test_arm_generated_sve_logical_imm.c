#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct logical_case {
    uint32_t word;
    uint32_t form_or_alias_index;
    int is_alias;
    const char *expected;
} logical_case;

static const logical_case cases[] = {
    { UINT32_C(0x05000660), 2423u, 0,
        "orr z0.b, z0.b, #0xf" },
    { UINT32_C(0x05000460), 2423u, 0,
        "orr z0.h, z0.h, #0xf" },
    { UINT32_C(0x05000060), 2423u, 0,
        "orr z0.s, z0.s, #0xf" },
    { UINT32_C(0x05020060), 2423u, 0,
        "orr z0.d, z0.d, #0xf" },
    { UINT32_C(0x05000f80), 2423u, 0,
        "orr z0.b, z0.b, #0xaa" },
    { UINT32_C(0x050004e0), 2423u, 0,
        "orr z0.h, z0.h, #0xff" },
    { UINT32_C(0x050001e0), 2423u, 0,
        "orr z0.s, z0.s, #0xffff" },
    { UINT32_C(0x050203e0), 2423u, 0,
        "orr z0.d, z0.d, #0xffffffff" },
    { UINT32_C(0x05002660), 320u, 1,
        "orn z0.b, z0.b, #0xf" },
    { UINT32_C(0x05406560), 321u, 1,
        "eon z0.h, z0.h, #0xf" },
    { UINT32_C(0x0580e360), 322u, 1,
        "bic z0.s, z0.s, #0xf" }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cdisasm_arm_asmgen_form *form = NULL;
        const cdisasm_arm_asmgen_alias *alias = NULL;
        uint32_t recipe_first;
        uint16_t recipe_count;
        char buffer[96] = {0};
        size_t length;

        if (cases[index].is_alias) {
            alias = &cdisasm_arm_asmgen_aliases[
                cases[index].form_or_alias_index];
            recipe_first = alias->recipe_first;
            recipe_count = alias->recipe_count;
        } else {
            form = &cdisasm_arm_asmgen_forms[
                cases[index].form_or_alias_index];
            recipe_first = form->recipe_first;
            recipe_count = form->recipe_count;
        }
        length = arm_asmgen_render_recipe(
            recipe_first, recipe_count, cases[index].word,
            CDISASM_ARM_ISA_A64, 0u, 0u, 0u,
            buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "SVE logical immediate case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SVE logical-immediate tests passed");
    return 0;
}
