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
    { UINT32_C(0xea010002), 1757u, "and r0, r1, r2" },
    { UINT32_C(0xea010042), 1757u, "and r0, r1, r2, lsl #1" },
    { UINT32_C(0xea0170c2), 1757u, "and r0, r1, r2, lsl #31" },
    { UINT32_C(0xea010052), 1757u, "and r0, r1, r2, lsr #1" },
    { UINT32_C(0xea010012), 1757u, "and r0, r1, r2, lsr #32" },
    { UINT32_C(0xea010022), 1757u, "and r0, r1, r2, asr #32" },
    { UINT32_C(0xea010072), 1757u, "and r0, r1, r2, ror #1" },
    { UINT32_C(0xea010032), 1757u, "and r0, r1, r2, rrx" },
    { UINT32_C(0xea4f1344), 1771u, "mov r3, r4, lsl #5" },
    { UINT32_C(0xea6f0526), 1779u, "mvn r5, r6, asr #32" }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cdisasm_arm_asmgen_form *form =
            &cdisasm_arm_asmgen_forms[cases[index].form_index];
        char buffer[96] = {0};
        size_t length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            cases[index].word, CDISASM_ARM_ISA_T32,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "T32 modified shift case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated T32 modified-register shift tests passed");
    return 0;
}
