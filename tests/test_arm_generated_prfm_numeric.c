#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct prfm_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} prfm_case;

/* Each numeric source in tests/data/arm_prfm_numeric.s was LLVM-assembled. */
static const prfm_case cases[] = {
    { UINT32_C(0xd8000020), 4923u, CDISASM_ARM_NAME_PRFM,
      "prfm #0, 0x1004" },
    { UINT32_C(0xf89f8026), 5159u, CDISASM_ARM_NAME_PRFUM,
      "prfum #6, [x1, #-8]" },
    { UINT32_C(0xf8a46868), 5544u, CDISASM_ARM_NAME_PRFM,
      "prfm #8, [x3, x4, lsl #0]" },
    { UINT32_C(0xf98008bf), 5573u, CDISASM_ARM_NAME_PRFM,
      "prfm #31, [x5, #16]" },
};

int main(void)
{
    size_t i;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const prfm_case *entry = &cases[i];
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
        size_t length;

        instruction.raw_instruction = entry->word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A64;
        instruction.form_id = entry->form_id;
        instruction.name_id = entry->name_id;
        instruction.address = UINT64_C(0x1000) + 4u * i;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, entry->expected) != 0) {
            fprintf(stderr, "PRFM case %zu: got '%s', expected '%s'\n",
                i, buffer, entry->expected);
            return 1;
        }
    }
    puts("ARM generated numeric PRFM tests passed");
    return 0;
}
