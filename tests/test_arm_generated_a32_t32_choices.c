#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct choice_case {
    uint32_t word;
    uint32_t index;
    uint8_t isa_id;
    int alias;
    const char *expected;
} choice_case;

static const choice_case cases[] = {
    { UINT32_C(0xe8c00006), 397u, CDISASM_ARM_ISA_A32, 0,
        "stm r0, {r1, r2}^" },
    { UINT32_C(0xe8430030), 397u, CDISASM_ARM_ISA_A32, 0,
        "stmda r3, {r4, r5}^" },
    { UINT32_C(0xe9460180), 397u, CDISASM_ARM_ISA_A32, 0,
        "stmdb r6, {r7, r8}^" },
    { UINT32_C(0xe9c90c00), 397u, CDISASM_ARM_ISA_A32, 0,
        "stmib r9, {r10, r11}^" },
    { UINT32_C(0xe8d00006), 400u, CDISASM_ARM_ISA_A32, 0,
        "ldm r0, {r1, r2}^" },
    { UINT32_C(0xe8530030), 400u, CDISASM_ARM_ISA_A32, 0,
        "ldmda r3, {r4, r5}^" },
    { UINT32_C(0xe9560180), 400u, CDISASM_ARM_ISA_A32, 0,
        "ldmdb r6, {r7, r8}^" },
    { UINT32_C(0xe9d90c00), 400u, CDISASM_ARM_ISA_A32, 0,
        "ldmib r9, {r10, r11}^" },
    { UINT32_C(0xe8d48020), 403u, CDISASM_ARM_ISA_A32, 0,
        "ldm r4, {r5, pc}^" },
    { UINT32_C(0xe8f48020), 403u, CDISASM_ARM_ISA_A32, 0,
        "ldm r4!, {r5, pc}^" },
    { UINT32_C(0x0000c806), 1177u, CDISASM_ARM_ISA_T32, 0,
        "ldm r0!, {r1, r2}" },
    { UINT32_C(0x0000c803), 1177u, CDISASM_ARM_ISA_T32, 0,
        "ldm r0, {r0, r1}" },
    { UINT32_C(0x0000ca0a), 139u, CDISASM_ARM_ISA_T32, 1,
        "ldmfd r2!, {r1, r3}" },
    { UINT32_C(0xeac10002), 1788u, CDISASM_ARM_ISA_T32, 0,
        "pkhbt r0, r1, r2" },
    { UINT32_C(0xeac413c5), 1788u, CDISASM_ARM_ISA_T32, 0,
        "pkhbt r3, r4, r5, lsl #7" },
    { UINT32_C(0xeaca396b), 1789u, CDISASM_ARM_ISA_T32, 0,
        "pkhtb r9, r10, r11, asr #13" },
    { UINT32_C(0xeac00c21), 1789u, CDISASM_ARM_ISA_T32, 0,
        "pkhtb r12, r0, r1, asr #32" },
    { UINT32_C(0xf3010007), 1903u, CDISASM_ARM_ISA_T32, 0,
        "ssat r0, #8, r1" },
    { UINT32_C(0xf303124f), 1903u, CDISASM_ARM_ISA_T32, 0,
        "ssat r2, #16, r3, lsl #5" },
    { UINT32_C(0xf3850407), 1909u, CDISASM_ARM_ISA_T32, 0,
        "usat r4, #7, r5" },
    { UINT32_C(0xf38776cc), 1909u, CDISASM_ARM_ISA_T32, 0,
        "usat r6, #12, r7, lsl #31" },
    { UINT32_C(0xf3b20282), 827u, CDISASM_ARM_ISA_A32, 0,
        "vqmovn.s16 d0, q1" },
    { UINT32_C(0xf3b622c6), 827u, CDISASM_ARM_ISA_A32, 0,
        "vqmovn.u32 d2, q3" },
    { UINT32_C(0xf3ba428a), 827u, CDISASM_ARM_ISA_A32, 0,
        "vqmovn.s64 d4, q5" },
    { UINT32_C(0xffb20282), 1354u, CDISASM_ARM_ISA_T32, 0,
        "vqmovn.s16 d0, q1" },
    { UINT32_C(0xffb622c6), 1354u, CDISASM_ARM_ISA_T32, 0,
        "vqmovn.u32 d2, q3" },
    { UINT32_C(0xee400b10), 534u, CDISASM_ARM_ISA_A32, 0,
        "vmov.8 d0[0], r0" },
    { UINT32_C(0xee012b70), 534u, CDISASM_ARM_ISA_A32, 0,
        "vmov.16 d1[1], r2" },
    { UINT32_C(0xee223b10), 534u, CDISASM_ARM_ISA_A32, 0,
        "vmov.32 d2[1], r3" },
    { UINT32_C(0xeed34b50), 535u, CDISASM_ARM_ISA_A32, 0,
        "vmov.u8 r4, d3[2]" },
    { UINT32_C(0xee145b70), 535u, CDISASM_ARM_ISA_A32, 0,
        "vmov.s16 r5, d4[1]" },
    { UINT32_C(0xee356b10), 535u, CDISASM_ARM_ISA_A32, 0,
        "vmov.32 r6, d5[1]" },
    { UINT32_C(0xee667b70), 534u, CDISASM_ARM_ISA_A32, 0,
        "vmov.8 d6[7], r7" },
    { UINT32_C(0xee278b70), 534u, CDISASM_ARM_ISA_A32, 0,
        "vmov.16 d7[3], r8" },
    { UINT32_C(0xee089b10), 534u, CDISASM_ARM_ISA_A32, 0,
        "vmov.32 d8[0], r9" },
    { UINT32_C(0xeef9ab70), 535u, CDISASM_ARM_ISA_A32, 0,
        "vmov.u8 r10, d9[7]" },
    { UINT32_C(0xee3abb70), 535u, CDISASM_ARM_ISA_A32, 0,
        "vmov.s16 r11, d10[3]" },
    { UINT32_C(0xee1bcb10), 535u, CDISASM_ARM_ISA_A32, 0,
        "vmov.32 r12, d11[0]" },
    { UINT32_C(0xee400b10), 1519u, CDISASM_ARM_ISA_T32, 0,
        "vmov.8 d0[0], r0" },
    { UINT32_C(0xee012b70), 1519u, CDISASM_ARM_ISA_T32, 0,
        "vmov.16 d1[1], r2" },
    { UINT32_C(0xee223b10), 1519u, CDISASM_ARM_ISA_T32, 0,
        "vmov.32 d2[1], r3" },
    { UINT32_C(0xeed34b50), 1520u, CDISASM_ARM_ISA_T32, 0,
        "vmov.u8 r4, d3[2]" },
    { UINT32_C(0xee145b70), 1520u, CDISASM_ARM_ISA_T32, 0,
        "vmov.s16 r5, d4[1]" },
    { UINT32_C(0xee356b10), 1520u, CDISASM_ARM_ISA_T32, 0,
        "vmov.32 r6, d5[1]" },
    { UINT32_C(0x0000bf08), 1171u, CDISASM_ARM_ISA_T32, 0,
        "it eq" },
    { UINT32_C(0x0000bf04), 1171u, CDISASM_ARM_ISA_T32, 0,
        "itt eq" },
    { UINT32_C(0x0000bf0c), 1171u, CDISASM_ARM_ISA_T32, 0,
        "ite eq" },
    { UINT32_C(0x0000bf06), 1171u, CDISASM_ARM_ISA_T32, 0,
        "itte eq" },
    { UINT32_C(0x0000bf16), 1171u, CDISASM_ARM_ISA_T32, 0,
        "itet ne" },
    { UINT32_C(0x0000bf07), 1171u, CDISASM_ARM_ISA_T32, 0,
        "ittee eq" }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t recipe_first;
        uint16_t recipe_count;
        char buffer[128] = {0};
        size_t length;

        if (cases[index].alias) {
            const cdisasm_arm_asmgen_alias *alias =
                &cdisasm_arm_asmgen_aliases[cases[index].index];
            recipe_first = alias->recipe_first;
            recipe_count = alias->recipe_count;
        } else {
            const cdisasm_arm_asmgen_form *form =
                &cdisasm_arm_asmgen_forms[cases[index].index];
            recipe_first = form->recipe_first;
            recipe_count = form->recipe_count;
        }
        length = arm_asmgen_render_recipe(
            recipe_first, recipe_count, cases[index].word,
            cases[index].isa_id, 0u, 0u, 0u,
            buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "A32/T32 choice case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    {
        const cdisasm_arm_asmgen_form *without_pc =
            &cdisasm_arm_asmgen_forms[400u];
        const cdisasm_arm_asmgen_form *with_pc =
            &cdisasm_arm_asmgen_forms[403u];
        char buffer[128] = {0};

        if (arm_asmgen_render_recipe(without_pc->recipe_first,
                without_pc->recipe_count, UINT32_C(0xe8d48020),
                CDISASM_ARM_ISA_A32, 0u, 0u, 0u,
                buffer, sizeof(buffer)) != 0u
            || arm_asmgen_render_recipe(with_pc->recipe_first,
                with_pc->recipe_count, UINT32_C(0xe8d00006),
                CDISASM_ARM_ISA_A32, 0u, 0u, 0u,
                buffer, sizeof(buffer)) != 0u
            || arm_asmgen_render_recipe(without_pc->recipe_first,
                without_pc->recipe_count, UINT32_C(0xe8d00000),
                CDISASM_ARM_ISA_A32, 0u, 0u, 0u,
                buffer, sizeof(buffer)) != 0u) {
            fputs("A32 LDM register-list legality test failed\n", stderr);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated A32/T32 choice tests passed");
    return 0;
}
