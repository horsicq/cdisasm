#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct vmov_case {
    uint32_t word;
    uint32_t form_index;
    uint32_t isa_id;
    const char *expected;
} vmov_case;

/* LLVM 21 A32/T32 assembler and objdump witnesses. */
static const vmov_case cases[] = {
    { UINT32_C(0xf2811c12), 916u, CDISASM_ARM_ISA_A32,
      "vmov.i32 d1, #0x12ff" },
    { UINT32_C(0xf2812d12), 916u, CDISASM_ARM_ISA_A32,
      "vmov.i32 d2, #0x12ffff" },
    { UINT32_C(0xf2814c52), 917u, CDISASM_ARM_ISA_A32,
      "vmov.i32 q2, #0x12ff" },
    { UINT32_C(0xf2816d52), 917u, CDISASM_ARM_ISA_A32,
      "vmov.i32 q3, #0x12ffff" },
    { UINT32_C(0xef811c12), 1443u, CDISASM_ARM_ISA_T32,
      "vmov.i32 d1, #0x12ff" },
    { UINT32_C(0xef812d12), 1443u, CDISASM_ARM_ISA_T32,
      "vmov.i32 d2, #0x12ffff" },
    { UINT32_C(0xef814c52), 1444u, CDISASM_ARM_ISA_T32,
      "vmov.i32 q2, #0x12ff" },
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
            fprintf(stderr, "VMOV A4/T4 case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            return 1;
        }
    }
    puts("ARM generated VMOV A4/T4 immediate tests passed");
    return 0;
}
