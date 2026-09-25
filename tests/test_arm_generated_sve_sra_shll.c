#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct shift_case {
    uint32_t word;
    uint32_t form_index;
    const char *expected;
} shift_case;

static const shift_case cases[] = {
    { UINT32_C(0x450fe020), 2841u, "ssra z0.b, z1.b, #1" },
    { UINT32_C(0x4508e020), 2841u, "ssra z0.b, z1.b, #8" },
    { UINT32_C(0x451fe020), 2841u, "ssra z0.h, z1.h, #1" },
    { UINT32_C(0x455fe020), 2841u, "ssra z0.s, z1.s, #1" },
    { UINT32_C(0x45dfe020), 2841u, "ssra z0.d, z1.d, #1" },
    { UINT32_C(0x4508a020), 2824u, "sshllb z0.h, z1.b, #0" },
    { UINT32_C(0x450fa020), 2824u, "sshllb z0.h, z1.b, #7" },
    { UINT32_C(0x451fa020), 2824u, "sshllb z0.s, z1.h, #15" },
    { UINT32_C(0x455fa020), 2824u, "sshllb z0.d, z1.s, #31" },
    { UINT32_C(0x4517e862), 2842u, "srsra z2.h, z3.h, #9" },
    { UINT32_C(0x454fe4a4), 2843u, "usra z4.s, z5.s, #17" },
    { UINT32_C(0x459fece6), 2844u, "ursra z6.d, z7.d, #33" },
    { UINT32_C(0x450aa462), 2825u, "sshllt z2.h, z3.b, #2" },
    { UINT32_C(0x4513a8a4), 2826u, "ushllb z4.s, z5.h, #3" },
    { UINT32_C(0x4551ace6), 2827u, "ushllt z6.d, z7.s, #17" }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cdisasm_arm_asmgen_form *form =
            &cdisasm_arm_asmgen_forms[cases[index].form_index];
        char buffer[128] = {0};
        size_t length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            cases[index].word, CDISASM_ARM_ISA_A64,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "SVE SRA/SHLL case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SVE SRA/SHLL tests passed");
    return 0;
}
