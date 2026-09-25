#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct simd_case {
    uint32_t word;
    uint32_t form_index;
    const char *expected;
} simd_case;

/* Independent LLVM AArch64 assembler/objdump byte witnesses. LLVM prefers
 * MOV aliases for the scalar DUP and UMOV(S) spellings; the pinned canonical
 * source forms below intentionally retain their own DUP/UMOV mnemonics. */
static const simd_case cases[] = {
    { UINT32_C(0x5e0f0420), 5740u, "dup b0, v1.b[7]" },
    { UINT32_C(0x5e0e0462), 5740u, "dup h2, v3.h[3]" },
    { UINT32_C(0x5e0c04a4), 5740u, "dup s4, v5.s[1]" },
    { UINT32_C(0x5e1804e6), 5740u, "dup d6, v7.d[1]" },
    { UINT32_C(0x0e0f0528), 5910u, "dup v8.8b, v9.b[7]" },
    { UINT32_C(0x4e1f056a), 5910u, "dup v10.16b, v11.b[15]" },
    { UINT32_C(0x4e1e05ac), 5910u, "dup v12.8h, v13.h[7]" },
    { UINT32_C(0x4e1805ee), 5910u, "dup v14.2d, v15.d[1]" },
    { UINT32_C(0x0e020e30), 5911u, "dup v16.4h, w17" },
    { UINT32_C(0x4e080e72), 5911u, "dup v18.2d, x19" },
    { UINT32_C(0x4e010ff4), 5911u, "dup v20.16b, wzr" },
    { UINT32_C(0x4e080ff5), 5911u, "dup v21.2d, xzr" },
    { UINT32_C(0x0e1f2eb4), 5912u, "smov w20, v21.b[15]" },
    { UINT32_C(0x0e1e2ef6), 5912u, "smov w22, v23.h[7]" },
    { UINT32_C(0x0e1c3f38), 5913u, "umov w24, v25.s[3]" },
    { UINT32_C(0x4e1c2f7a), 5915u, "smov x26, v27.s[3]" },
    { UINT32_C(0x0f00c640), 6202u, "movi v0.2s, #18, msl #8" },
    { UINT32_C(0x6f01d681), 6210u, "mvni v1.4s, #52, msl #16" },
};

static int verify_case(const simd_case *item, size_t index)
{
    const cdisasm_arm_asmgen_form *form =
        &cdisasm_arm_asmgen_forms[item->form_index];
    char buffer[128] = {0};
    size_t length = arm_asmgen_render_recipe(
        form->recipe_first, form->recipe_count,
        item->word, CDISASM_ARM_ISA_A64,
        0u, 0u, 0u, buffer, sizeof(buffer));

    if (length == 0u || strcmp(buffer, item->expected) != 0) {
        fprintf(stderr, "A64 SIMD lane choice case %zu: got '%s', "
            "expected '%s'\n", index, buffer, item->expected);
        return 1;
    }
    return 0;
}

static int verify_rejected(uint32_t word, uint32_t form_index,
    const char *description)
{
    const cdisasm_arm_asmgen_form *form =
        &cdisasm_arm_asmgen_forms[form_index];
    char buffer[128] = {0};
    size_t length = arm_asmgen_render_recipe(
        form->recipe_first, form->recipe_count,
        word, CDISASM_ARM_ISA_A64,
        0u, 0u, 0u, buffer, sizeof(buffer));

    if (length != 0u) {
        fprintf(stderr, "A64 SIMD invalid %s rendered '%s'\n",
            description, buffer);
        return 1;
    }
    return 0;
}

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        if (verify_case(&cases[index], index) != 0) {
            return 1;
        }
    }
    if (verify_rejected(UINT32_C(0x0e000528), 5910u,
            "DUP imm5=0") != 0
        || verify_rejected(UINT32_C(0x0e1805ee), 5910u,
            "DUP .1d") != 0
        || verify_rejected(UINT32_C(0x0e1c2eb4), 5912u,
            "SMOV W with S element") != 0
        || verify_rejected(UINT32_C(0x0e180e72), 5911u,
            "DUP GPR .1d") != 0
        || verify_rejected(UINT32_C(0x0f00e640), 6202u,
            "MOVI MSL cmode outside 110x") != 0) {
        return 1;
    }
    puts("ARM generated A64 SIMD lane choices passed");
    return 0;
}
