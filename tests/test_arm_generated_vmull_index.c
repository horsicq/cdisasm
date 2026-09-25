#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct vmull_case {
    uint32_t word;
    uint32_t form_index;
    uint32_t isa_id;
    const char *expected;
} vmull_case;

/* LLVM 21 assembler/objdump byte witnesses. */
static const vmull_case cases[] = {
    { UINT32_C(0xf2910a42), 891u, CDISASM_ARM_ISA_A32,
      "vmull.s16 q0, d1, d2[0]" },
    { UINT32_C(0xf2910a6a), 891u, CDISASM_ARM_ISA_A32,
      "vmull.s16 q0, d1, d2[3]" },
    { UINT32_C(0xf2a10a42), 891u, CDISASM_ARM_ISA_A32,
      "vmull.s32 q0, d1, d2[0]" },
    { UINT32_C(0xf2a10a62), 891u, CDISASM_ARM_ISA_A32,
      "vmull.s32 q0, d1, d2[1]" },
    { UINT32_C(0xef910a6a), 1418u, CDISASM_ARM_ISA_T32,
      "vmull.s16 q0, d1, d2[3]" },
    { UINT32_C(0xefa10a62), 1418u, CDISASM_ARM_ISA_T32,
      "vmull.s32 q0, d1, d2[1]" },
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
            fprintf(stderr, "VMULL case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            return 1;
        }
    }
    puts("ARM generated VMULL indexed tests passed");
    return 0;
}
