#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct alias_case {
    uint32_t word;
    uint32_t alias_index;
    uint8_t isa_id;
    const char *expected;
} alias_case;

/* LLVM AArch32/Thumb-2 assembler accepts the complemented VAND immediate and
 * emits VBIC bytes. LLVM's objdump confirms the encoded VBIC immediate. */
static const alias_case cases[] = {
    { UINT32_C(0xf387013f), 86u, CDISASM_ARM_ISA_A32,
      "vand.i32 d0, #0xffffff00" },
    { UINT32_C(0xf387237f), 87u, CDISASM_ARM_ISA_A32,
      "vand.i32 q1, #0xffff00ff" },
    { UINT32_C(0xf387293f), 90u, CDISASM_ARM_ISA_A32,
      "vand.i16 d2, #0xff00" },
    { UINT32_C(0xf3876b7f), 91u, CDISASM_ARM_ISA_A32,
      "vand.i16 q3, #0xff" },
    { UINT32_C(0xff87013f), 170u, CDISASM_ARM_ISA_T32,
      "vand.i32 d0, #0xffffff00" },
    { UINT32_C(0xff87237f), 171u, CDISASM_ARM_ISA_T32,
      "vand.i32 q1, #0xffff00ff" },
    { UINT32_C(0xff872b3f), 174u, CDISASM_ARM_ISA_T32,
      "vand.i16 d2, #0xff" },
    { UINT32_C(0xff87697f), 175u, CDISASM_ARM_ISA_T32,
      "vand.i16 q3, #0xff00" },
};

static size_t render(uint32_t word, uint32_t alias_index, uint8_t isa_id,
    char *buffer, size_t capacity)
{
    const cdisasm_arm_asmgen_alias *alias =
        &cdisasm_arm_asmgen_aliases[alias_index];
    return arm_asmgen_render_recipe(alias->recipe_first,
        alias->recipe_count, word, isa_id,
        0u, 0u, 0u, buffer, capacity);
}

int main(void)
{
    size_t index;
    char buffer[128];

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const alias_case *item = &cases[index];
        size_t length;

        memset(buffer, 0, sizeof(buffer));
        length = render(item->word, item->alias_index, item->isa_id,
            buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, item->expected) != 0) {
            fprintf(stderr, "VAND alias case %zu: got '%s', expected '%s'\n",
                index, buffer, item->expected);
            return 1;
        }
    }
    memset(buffer, 0, sizeof(buffer));
    if (render(UINT32_C(0xf387003f), 86u, CDISASM_ARM_ISA_A32,
            buffer, sizeof(buffer)) != 0u) {
        fputs("VAND accepted invalid i32 cmode\n", stderr);
        return 1;
    }
    memset(buffer, 0, sizeof(buffer));
    if (render(UINT32_C(0xf387213f), 90u, CDISASM_ARM_ISA_A32,
            buffer, sizeof(buffer)) != 0u) {
        fputs("VAND accepted invalid i16 cmode\n", stderr);
        return 1;
    }
    memset(buffer, 0, sizeof(buffer));
    if (render(UINT32_C(0xf387011f), 86u, CDISASM_ARM_ISA_A32,
            buffer, sizeof(buffer)) != 0u) {
        fputs("VAND accepted non-VBIC op bit\n", stderr);
        return 1;
    }
    puts("ARM generated NEON VAND aliases passed");
    return 0;
}
