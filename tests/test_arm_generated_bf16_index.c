#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct bf16_case {
    uint32_t word;
    uint32_t form_index;
    uint32_t isa_id;
    const char *expected;
} bf16_case;

/* Independent LLVM 21 objdump --mattr=+bf16 byte witnesses. */
static const bf16_case cases[] = {
    { UINT32_C(0xfe3ec81b), 481u, CDISASM_ARM_ISA_A32,
      "vfmab.bf16 q6, q7, d3[1]" },
    { UINT32_C(0xfe3ec83b), 481u, CDISASM_ARM_ISA_A32,
      "vfmab.bf16 q6, q7, d3[3]" },
    { UINT32_C(0xfe3ec81a), 481u, CDISASM_ARM_ISA_A32,
      "vfmab.bf16 q6, q7, d2[1]" },
    { UINT32_C(0xfe7208d4), 1706u, CDISASM_ARM_ISA_T32,
      "vfmat.bf16 q8, q9, d4[0]" },
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
            cases[index].word, cases[index].isa_id,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "BF16 indexed case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            return 1;
        }
    }
    puts("ARM generated BF16 indexed tests passed");
    return 0;
}
