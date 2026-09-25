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

/* LLVM 21 Thumb architectural words (objdump byte witnesses). */
static const shift_case cases[] = {
    { UINT32_C(0xebb00f41), 1817u, "cmp r0, r1, lsl #1" },
    { UINT32_C(0xebb00f11), 1817u, "cmp r0, r1, lsr #32" },
    { UINT32_C(0xebb00f21), 1817u, "cmp r0, r1, asr #32" },
    { UINT32_C(0xebb00f71), 1817u, "cmp r0, r1, ror #1" },
    { UINT32_C(0xf32372c7), 1902u, "ssat r2, #8, r3, asr #31" },
    { UINT32_C(0xf3a50447), 1908u, "usat r4, #7, r5, asr #1" },
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
            cases[index].word, CDISASM_ARM_ISA_T32,
            0u, 0u, 0u, buffer, sizeof(buffer));

        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "Thumb shift case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            return 1;
        }
    }
    {
        static const struct {
            uint32_t word;
            uint32_t form_index;
        } invalid[] = {
            { UINT32_C(0xebb00f31), 1817u }, /* RRX, not ROR #0 */
            { UINT32_C(0xf3230207), 1902u }, /* SSAT ASR #0 forbidden */
        };

        for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]);
             ++index) {
            const cdisasm_arm_asmgen_form *form =
                &cdisasm_arm_asmgen_forms[invalid[index].form_index];
            char buffer[128] = {0};

            if (arm_asmgen_render_recipe(
                    form->recipe_first, form->recipe_count,
                    invalid[index].word, CDISASM_ARM_ISA_T32,
                    0u, 0u, 0u, buffer, sizeof(buffer)) != 0u) {
                fprintf(stderr, "invalid Thumb shift case %zu accepted\n",
                    index);
                return 1;
            }
        }
    }
    puts("ARM generated Thumb shift amounts passed");
    return 0;
}
