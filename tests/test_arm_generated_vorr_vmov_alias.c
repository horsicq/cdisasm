#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct vmov_case {
    uint16_t alias_index;
    uint8_t isa_id;
    uint32_t word;
    const char *expected;
} vmov_case;

/* Assembled independently with Clang's ARM integrated assembler. VORR,
   VMOV and VMOV.I8 each produce the same word for each row. */
static const vmov_case cases[] = {
    { 62u, CDISASM_ARM_ISA_A32, UINT32_C(0xf2210111), "vmov d0, d1" },
    { 65u, CDISASM_ARM_ISA_A32, UINT32_C(0xf2220152), "vmov q0, q1" },
    { 146u, CDISASM_ARM_ISA_T32, UINT32_C(0xef210111), "vmov d0, d1" },
    { 149u, CDISASM_ARM_ISA_T32, UINT32_C(0xef220152), "vmov q0, q1" }
};

static const uint16_t nonrecoverable_aliases[] = {
    60u, 61u, 63u, 64u, 144u, 145u, 147u, 148u
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cdisasm_arm_asmgen_alias *alias =
            &cdisasm_arm_asmgen_aliases[cases[index].alias_index];
        char buffer[64] = {0};
        size_t length = arm_asmgen_render_recipe(
            alias->recipe_first, alias->recipe_count,
            cases[index].word, cases[index].isa_id,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (alias->render_status != 1u
            || length != strlen(cases[index].expected)
            || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "VMOV alias %u: got '%s', expected '%s'\n",
                cases[index].alias_index, buffer, cases[index].expected);
            ++failures;
        }
    }
    for (index = 0u; index < sizeof(nonrecoverable_aliases)
            / sizeof(nonrecoverable_aliases[0]); ++index) {
        uint16_t alias_index = nonrecoverable_aliases[index];
        if (cdisasm_arm_asmgen_aliases[alias_index].render_status != 0u) {
            fprintf(stderr, "VRSHR/VSHR alias %u unexpectedly direct\n",
                alias_index);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated VORR/VMOV alias tests passed");
    return 0;
}
