#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct sve_gpr_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
    int alias;
} sve_gpr_case;

/* Independently assembled from data/arm_sve_gpr_size.s by LLVM. */
static const sve_gpr_case cases[] = {
    { UINT32_C(0x05203820), 2446u, CDISASM_ARM_NAME_DUP,
      "dup z0.b, w1", 0 },
    { UINT32_C(0x05603be1), 2446u, CDISASM_ARM_NAME_DUP,
      "dup z1.h, wsp", 0 },
    { UINT32_C(0x05a03862), 2446u, CDISASM_ARM_NAME_DUP,
      "dup z2.s, w3", 0 },
    { UINT32_C(0x05e03883), 2446u, CDISASM_ARM_NAME_DUP,
      "dup z3.d, x4", 0 },
    { UINT32_C(0x0528a0c5), 2498u, CDISASM_ARM_NAME_CPY,
      "cpy z5.b, p0/m, w6", 0 },
    { UINT32_C(0x05e8a507), 2498u, CDISASM_ARM_NAME_CPY,
      "cpy z7.d, p1/m, x8", 0 },
    { UINT32_C(0x05a03949), 2446u, CDISASM_ARM_NAME_MOV,
      "mov z9.s, w10", 1 },
    { UINT32_C(0x05e8a98b), 2498u, CDISASM_ARM_NAME_MOV,
      "mov z11.d, p2/m, x12", 1 },
};

static const cdisasm_arm_asmgen_alias *find_alias(
    uint16_t form_id, cdisasm_arm_name_id name_id)
{
    size_t i;

    for (i = 0u; i < sizeof(cdisasm_arm_asmgen_aliases)
            / sizeof(cdisasm_arm_asmgen_aliases[0]); ++i) {
        const cdisasm_arm_asmgen_alias *alias =
            &cdisasm_arm_asmgen_aliases[i];

        if (alias->leaf_index == (uint32_t)form_id - 1u
            && alias->public_name_id == name_id) {
            return alias;
        }
    }
    return NULL;
}

int main(void)
{
    size_t i;
    int failures = 0;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const sve_gpr_case *entry = &cases[i];
        char buffer[128] = {0};
        size_t length;

        if (entry->alias) {
            const cdisasm_arm_asmgen_alias *alias =
                find_alias(entry->form_id, entry->name_id);

            if (alias == NULL || alias->render_status == 0u) {
                fprintf(stderr, "missing SVE GPR alias %zu\n", i);
                ++failures;
                continue;
            }
            length = arm_asmgen_render_recipe(
                alias->recipe_first, alias->recipe_count,
                entry->word, CDISASM_ARM_ISA_A64, 0u, 0u, 0u,
                buffer, sizeof(buffer));
        } else {
            cdisasm_arm_instruction instruction = {0};

            instruction.raw_instruction = entry->word;
            instruction.opcode_size = 4u;
            instruction.isa_id = CDISASM_ARM_ISA_A64;
            instruction.form_id = entry->form_id;
            instruction.name_id = entry->name_id;
            instruction.instruction_flags =
                CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
            length = cdisasm_arm_format_generated(
                &instruction, 0u, buffer, sizeof(buffer));
        }
        if (length == 0u || strcmp(buffer, entry->expected) != 0) {
            fprintf(stderr, "SVE GPR case %zu: got '%s', expected '%s'\n",
                i, buffer, entry->expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated SVE GPR-size tests passed");
    return 0;
}
