#include <stdio.h>
#include <string.h>

/* Include the implementation to exercise canonical form recipes directly.
 * Public formatting may choose a same-name address-syntax alias instead. */
#include "../src/arm/arm_generated_formatter.c"

/* The generated matcher is tested independently. */
int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct pc_label_case {
    uint32_t raw_word;
    uint16_t form_id;
    uint8_t opcode_size;
    cdisasm_arm_isa_id isa_id;
    cdisasm_arm_name_id name_id;
    uint64_t address;
    const char *expected;
} pc_label_case;

static const pc_label_case cases[] = {
    { UINT32_C(0xe1cf00dc), 23u, 4u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_LDRD, UINT64_C(12), "ldrd r0, r1, 0x20" },
    { UINT32_C(0xe59f0010), 264u, 4u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_LDR, UINT64_C(0), "ldr r0, 0x18" },
    { UINT32_C(0xe51f1010), 264u, 4u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_LDR, UINT64_C(4), "ldr r1, 0xfffffffc" },
    { UINT32_C(0xe1df00b6), 24u, 4u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_LDRH, UINT64_C(8), "ldrh r0, 0x16" },
    { UINT32_C(0xe28f0004), 231u, 4u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_ADR, UINT64_C(24), "adr r0, 0x24" },
    { UINT32_C(0xe24f100c), 224u, 4u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_ADR, UINT64_C(28), "adr r1, 0x18" },
    { UINT32_C(0x4803), 1132u, 2u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_LDR, UINT64_C(2), "ldr r0, 0x10" },
    { UINT32_C(0x200cf85f), 2090u, 4u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_LDR, UINT64_C(8), "ldr.w r2, 0x0" },
    { UINT32_C(0x300cf8bf), 2089u, 4u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_LDRH, UINT64_C(12), "ldrh r3, 0x1c" },
    { UINT32_C(0x0108f20f), 1897u, 4u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_ADR, UINT64_C(4), "adr r1, 0x10" },
    { UINT32_C(0x0410f2af), 1900u, 4u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_ADR, UINT64_C(24), "adr r4, 0xc" }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cdisasm_arm_asmgen_form *form =
            &cdisasm_arm_asmgen_forms[cases[index].form_id - 1u];
        char buffer[96] = {0};
        size_t length;
        uint32_t word = cases[index].raw_word;

        if (cases[index].isa_id == CDISASM_ARM_ISA_T32
                && cases[index].opcode_size == 4u) {
            word = (word << 16) | (word >> 16);
        }
        length = arm_asmgen_render_recipe(
            form->recipe_first, form->recipe_count,
            word, cases[index].isa_id, cases[index].address, 0u, 0u,
            buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "A32/T32 PC label case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    {
        const cdisasm_arm_asmgen_form *form = &cdisasm_arm_asmgen_forms[22u];
        char buffer[96] = {0};
        uint32_t invalid_rt = UINT32_C(0xe1cfe0dc);

        if (arm_asmgen_render_recipe(
                form->recipe_first, form->recipe_count,
                invalid_rt, CDISASM_ARM_ISA_A32, 12u, 0u, 0u,
                buffer, sizeof(buffer)) != 0u) {
            fputs("A32 LDRD invalid Rt=14 pair was formatted\n", stderr);
            ++failures;
        }
    }
    {
        cdisasm_arm_instruction instruction = {0};
        char buffer[96] = {0};
        size_t length;

        instruction.raw_instruction = UINT32_C(0xe1cf00dc);
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A32;
        instruction.form_id = 23u;
        instruction.name_id = CDISASM_ARM_NAME_LDRD;
        instruction.address = 12u;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length == 0u || strstr(buffer, "r0, r1") == NULL) {
            fprintf(stderr, "A32 LDRD alias lost implicit Rt2: %s\n", buffer);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM A32/T32 generated PC-label tests passed");
    return 0;
}
