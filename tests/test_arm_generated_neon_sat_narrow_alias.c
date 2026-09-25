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
    uint32_t alias_index;
    uint8_t isa_id;
    const char *expected;
} narrow_case;

static const narrow_case cases[] = {
    { UINT32_C(0xf3b20282), 80u, CDISASM_ARM_ISA_A32,
        "vqrshrn.s16 d0, q1, #0" },
    { UINT32_C(0xf3b622c6), 81u, CDISASM_ARM_ISA_A32,
        "vqshrn.u32 d2, q3, #0" },
    { UINT32_C(0xf3ba428a), 80u, CDISASM_ARM_ISA_A32,
        "vqrshrn.s64 d4, q5, #0" },
    { UINT32_C(0xffb20282), 164u, CDISASM_ARM_ISA_T32,
        "vqrshrn.s16 d0, q1, #0" },
    { UINT32_C(0xffb622c6), 165u, CDISASM_ARM_ISA_T32,
        "vqshrn.u32 d2, q3, #0" }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cdisasm_arm_asmgen_alias *alias =
            &cdisasm_arm_asmgen_aliases[cases[index].alias_index];
        char buffer[128] = {0};
        size_t length = arm_asmgen_render_recipe(
            alias->recipe_first, alias->recipe_count,
            cases[index].word, cases[index].isa_id,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "NEON narrow alias case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated NEON narrow alias tests passed");
    return 0;
}
