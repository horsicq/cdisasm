#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct fixed_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} fixed_case;

/* Independent LLVM AArch64 assembly: tests/data/arm_fp16_fixed_convert.s. */
static const fixed_case cases[] = {
    { UINT32_C(0x5f1fe420), 5861u, CDISASM_ARM_NAME_SCVTF,
      "scvtf h0, h1, #1" },
    { UINT32_C(0x5f18fc62), 5862u, CDISASM_ARM_NAME_FCVTZS,
      "fcvtzs h2, h3, #8" },
    { UINT32_C(0x7f30e4a4), 5875u, CDISASM_ARM_NAME_UCVTF,
      "ucvtf s4, s5, #16" },
    { UINT32_C(0x7f60fce6), 5876u, CDISASM_ARM_NAME_FCVTZU,
      "fcvtzu d6, d7, #32" },
    { UINT32_C(0x0f1fe528), 6226u, CDISASM_ARM_NAME_SCVTF,
      "scvtf v8.4h, v9.4h, #1" },
    { UINT32_C(0x4f18fd6a), 6227u, CDISASM_ARM_NAME_FCVTZS,
      "fcvtzs v10.8h, v11.8h, #8" },
    { UINT32_C(0x2f30e5ac), 6241u, CDISASM_ARM_NAME_UCVTF,
      "ucvtf v12.2s, v13.2s, #16" },
    { UINT32_C(0x6f60fdee), 6242u, CDISASM_ARM_NAME_FCVTZU,
      "fcvtzu v14.2d, v15.2d, #32" },
    { UINT32_C(0x0f00e528), 6226u, CDISASM_ARM_NAME_SCVTF, NULL },
    { UINT32_C(0x2f60fdee), 6242u, CDISASM_ARM_NAME_FCVTZU, NULL },
};

int main(void)
{
    size_t i;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const fixed_case *entry = &cases[i];
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
        size_t length;

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
        if ((entry->expected == NULL && length != 0u)
            || (entry->expected != NULL
                && (length == 0u
                    || strcmp(buffer, entry->expected) != 0))) {
            fprintf(stderr, "FP fixed case %zu: got '%s', expected '%s'\n",
                i, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            return 1;
        }
    }
    puts("ARM generated FP fixed-conversion tests passed");
    return 0;
}
