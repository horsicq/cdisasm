#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct qshrn_case {
    uint16_t form_index;
    uint32_t word;
    const char *expected;
} qshrn_case;

/* Independent machine words from LLVM MC's SVE2p3/qshrn.s test. */
static const qshrn_case positive_cases[] = {
    { 2869u, UINT32_C(0x45af0000),
        "sqshrn z0.b, { z0.h-z1.h }, #1" },
    { 2869u, UINT32_C(0x45a80000),
        "sqshrn z0.b, { z0.h-z1.h }, #8" },
    { 2869u, UINT32_C(0x45bf0000),
        "sqshrn z0.h, { z0.s-z1.s }, #1" },
    { 2869u, UINT32_C(0x45b00000),
        "sqshrn z0.h, { z0.s-z1.s }, #16" },
    { 2869u, UINT32_C(0x45af03df),
        "sqshrn z31.b, { z30.h-z31.h }, #1" },
    { 2870u, UINT32_C(0x45af2000),
        "sqshrun z0.b, { z0.h-z1.h }, #1" },
    { 2870u, UINT32_C(0x45b02000),
        "sqshrun z0.h, { z0.s-z1.s }, #16" },
    { 2873u, UINT32_C(0x45af1000),
        "uqshrn z0.b, { z0.h-z1.h }, #1" },
    { 2873u, UINT32_C(0x45b01000),
        "uqshrn z0.h, { z0.s-z1.s }, #16" }
};

static const qshrn_case negative_cases[] = {
    /* tsize=00 cannot select a legal B<-H or H<-S lane width. */
    { 2869u, UINT32_C(0x45a70000), NULL },
    { 2870u, UINT32_C(0x45a02000), NULL },
    { 2873u, UINT32_C(0x45a01000), NULL }
};

static int check_case(const qshrn_case *item)
{
    const cdisasm_arm_asmgen_form *form =
        &cdisasm_arm_asmgen_forms[item->form_index];
    char buffer[128] = {0};
    size_t length = arm_asmgen_render_recipe(
        form->recipe_first, form->recipe_count,
        item->word, CDISASM_ARM_ISA_A64,
        0u, 0u, 0u, buffer, sizeof(buffer));

    if (item->expected != NULL) {
        if (length != strlen(item->expected)
            || strcmp(buffer, item->expected) != 0) {
            fprintf(stderr, "form %u, word %08x: got '%s', expected '%s'\n",
                item->form_index, item->word, buffer, item->expected);
            return 0;
        }
    } else if (length != 0u) {
        fprintf(stderr, "form %u, illegal word %08x rendered '%s'\n",
            item->form_index, item->word, buffer);
        return 0;
    }
    return 1;
}

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(positive_cases)
            / sizeof(positive_cases[0]); ++index) {
        failures += !check_case(&positive_cases[index]);
    }
    for (index = 0u; index < sizeof(negative_cases)
            / sizeof(negative_cases[0]); ++index) {
        failures += !check_case(&negative_cases[index]);
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SVE2p3 QSHRN tests passed");
    return 0;
}
