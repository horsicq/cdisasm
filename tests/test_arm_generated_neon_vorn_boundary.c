#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct vorn_boundary_case {
    uint32_t raw_word;
    uint32_t alias_index;
    uint16_t form_id;
    uint8_t isa_id;
    const char *canonical;
} vorn_boundary_case;

/* Arm Compiler armasm Reference Guide, section 4.28: VORN (immediate) is
 * assembly-only.  Its bytes disassemble as VORR with a complemented immediate.
 * https://documentation-service.arm.com/static/5f3fa899428f7a6b3328fd44
 * The eight pinned AARCHMRS aliases are non-preferred, not eight missing
 * independently encoded instructions. */
static const vorn_boundary_case cases[] = {
    { UINT32_C(0xf2810112), 84u, 905u, CDISASM_ARM_ISA_A32,
      "vorr.i32 d0, #0x12" },
    { UINT32_C(0xf2810152), 85u, 906u, CDISASM_ARM_ISA_A32,
      "vorr.i32 q0, #0x12" },
    { UINT32_C(0xf2810912), 88u, 913u, CDISASM_ARM_ISA_A32,
      "vorr.i16 d0, #0x12" },
    { UINT32_C(0xf2810952), 89u, 914u, CDISASM_ARM_ISA_A32,
      "vorr.i16 q0, #0x12" },
    { UINT32_C(0x0312ef81), 168u, 1432u, CDISASM_ARM_ISA_T32,
      "vorr.i32 d0, #0x1200" },
    { UINT32_C(0x0352ef81), 169u, 1433u, CDISASM_ARM_ISA_T32,
      "vorr.i32 q0, #0x1200" },
    { UINT32_C(0x0912ef81), 172u, 1440u, CDISASM_ARM_ISA_T32,
      "vorr.i16 d0, #0x12" },
    { UINT32_C(0x0952ef81), 173u, 1441u, CDISASM_ARM_ISA_T32,
      "vorr.i16 q0, #0x12" },
};

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const vorn_boundary_case *item = &cases[index];
        const cdisasm_arm_asmgen_alias *alias =
            &cdisasm_arm_asmgen_aliases[item->alias_index];
        const cdisasm_arm_asmgen_form *form =
            &cdisasm_arm_asmgen_forms[item->form_id - 1u];
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
        size_t length;

        if (alias->render_status != 0u || alias->recipe_count != 0u
            || alias->public_name_id != CDISASM_ARM_NAME_VORN
            || form->render_status == 0u
            || form->public_name_id != CDISASM_ARM_NAME_VORR) {
            fprintf(stderr, "VORN/VORR catalog boundary failed at %zu\n",
                index);
            return 1;
        }
        instruction.raw_instruction = item->raw_word;
        instruction.opcode_size = 4u;
        instruction.isa_id = item->isa_id;
        instruction.form_id = item->form_id;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;

        instruction.name_id = CDISASM_ARM_NAME_VORN;
        if (cdisasm_arm_format_generated(
                &instruction, 0u, buffer, sizeof(buffer)) != 0u) {
            fprintf(stderr, "assembly-only VORN formatted at %zu\n", index);
            return 1;
        }
        instruction.name_id = CDISASM_ARM_NAME_VORR;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length != strlen(item->canonical)
            || strcmp(buffer, item->canonical) != 0) {
            fprintf(stderr, "canonical VORR at %zu: got '%s', expected '%s'\n",
                index, length == 0u ? "<no recipe>" : buffer,
                item->canonical);
            return 1;
        }
    }
    puts("ARM VORN pseudo-instruction boundary passed");
    return 0;
}
