#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct addsub_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
    int alias;
} addsub_case;

/* Independently assembled from data/arm_addsub_extended.s by LLVM. */
static const addsub_case cases[] = {
    { UINT32_C(0x8b220020), 5682u, CDISASM_ARM_NAME_ADD,
      "add x0, x1, w2, uxtb #0", 0 },
    { UINT32_C(0x8b222420), 5682u, CDISASM_ARM_NAME_ADD,
      "add x0, x1, w2, uxth #1", 0 },
    { UINT32_C(0x8b224820), 5682u, CDISASM_ARM_NAME_ADD,
      "add x0, x1, w2, uxtw #2", 0 },
    { UINT32_C(0x8b226c20), 5682u, CDISASM_ARM_NAME_ADD,
      "add x0, x1, x2, uxtx #3", 0 },
    { UINT32_C(0x8b229020), 5682u, CDISASM_ARM_NAME_ADD,
      "add x0, x1, w2, sxtb #4", 0 },
    { UINT32_C(0x8b22a020), 5682u, CDISASM_ARM_NAME_ADD,
      "add x0, x1, w2, sxth #0", 0 },
    { UINT32_C(0x8b22c420), 5682u, CDISASM_ARM_NAME_ADD,
      "add x0, x1, w2, sxtw #1", 0 },
    { UINT32_C(0x8b22e820), 5682u, CDISASM_ARM_NAME_ADD,
      "add x0, x1, x2, sxtx #2", 0 },
    { UINT32_C(0xab224420), 5683u, CDISASM_ARM_NAME_ADDS,
      "adds x0, x1, w2, uxtw #1", 0 },
    { UINT32_C(0xcb22f020), 5684u, CDISASM_ARM_NAME_SUB,
      "sub x0, x1, x2, sxtx #4", 0 },
    { UINT32_C(0xeb22c83f), 5685u, CDISASM_ARM_NAME_SUBS,
      "subs xzr, x1, w2, sxtw #2", 0 },
    { UINT32_C(0xab22c83f), 5683u, CDISASM_ARM_NAME_CMN,
      "cmn x1, w2, sxtw #2", 1 },
    { UINT32_C(0xeb22703f), 5685u, CDISASM_ARM_NAME_CMP,
      "cmp x1, x2, uxtx #4", 1 },
    { UINT32_C(0x0b220020), 5678u, CDISASM_ARM_NAME_ADD,
      "add w0, w1, w2, uxtb #0", 0 },
    { UINT32_C(0x2b222420), 5679u, CDISASM_ARM_NAME_ADDS,
      "adds w0, w1, w2, uxth #1", 0 },
    { UINT32_C(0x4b224820), 5680u, CDISASM_ARM_NAME_SUB,
      "sub w0, w1, w2, uxtw #2", 0 },
    { UINT32_C(0x6b228c3f), 5681u, CDISASM_ARM_NAME_SUBS,
      "subs wzr, w1, w2, sxtb #3", 0 },
    { UINT32_C(0x2b22b03f), 5679u, CDISASM_ARM_NAME_CMN,
      "cmn w1, w2, sxth #4", 1 },
    { UINT32_C(0x6b22c83f), 5681u, CDISASM_ARM_NAME_CMP,
      "cmp w1, w2, sxtw #2", 1 },
    { UINT32_C(0x8b223820), 5682u, CDISASM_ARM_NAME_ADD,
      NULL, 0 },
    { UINT32_C(0x0b226c20), 5678u, CDISASM_ARM_NAME_ADD,
      NULL, 0 },
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
        const addsub_case *entry = &cases[i];
        char buffer[128] = {0};
        size_t length;

        if (entry->alias) {
            const cdisasm_arm_asmgen_alias *alias =
                find_alias(entry->form_id, entry->name_id);

            if (alias == NULL || alias->render_status == 0u) {
                fprintf(stderr, "missing add/sub alias %zu\n", i);
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
        if ((entry->expected == NULL && length != 0u)
            || (entry->expected != NULL
                && (length == 0u
                    || strcmp(buffer, entry->expected) != 0))) {
            fprintf(stderr, "add/sub case %zu: got '%s', expected '%s'\n",
                i, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated add/sub extended tests passed");
    return 0;
}
