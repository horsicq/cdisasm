#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct bti_case {
    uint32_t word;
    const char *expected;
} bti_case;

/* LLVM-assembled words from tests/data/arm_bti_targets.s. */
static const bti_case cases[] = {
    { UINT32_C(0xd503241f), "bti" },
    { UINT32_C(0xd503245f), "bti c" },
    { UINT32_C(0xd503249f), "bti j" },
    { UINT32_C(0xd50324df), "bti jc" },
    { UINT32_C(0xd503243f), NULL },
};

int main(void)
{
    size_t i;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cdisasm_arm_instruction instruction = {0};
        char buffer[64] = {0};
        size_t length;

        instruction.raw_instruction = cases[i].word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A64;
        instruction.form_id = 4485u;
        instruction.name_id = CDISASM_ARM_NAME_BTI;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if ((cases[i].expected == NULL && length != 0u)
            || (cases[i].expected != NULL
                && (length == 0u
                    || strcmp(buffer, cases[i].expected) != 0))) {
            fprintf(stderr, "BTI case %zu: got '%s', expected '%s'\n",
                i, buffer,
                cases[i].expected == NULL ? "<rejected>" : cases[i].expected);
            return 1;
        }
    }
    puts("ARM generated BTI target tests passed");
    return 0;
}
