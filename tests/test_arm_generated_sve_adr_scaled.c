#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct adr_case {
    uint32_t word;
    const char *expected;
} adr_case;

/* LLVM-assembled words from tests/data/arm_sve_adr_scaled.s. */
static const adr_case cases[] = {
    { UINT32_C(0x04e2a020), "adr z0.d, [z1.d, z2.d]" },
    { UINT32_C(0x04e5a483), "adr z3.d, [z4.d, z5.d, lsl #1]" },
    { UINT32_C(0x04e8a8e6), "adr z6.d, [z7.d, z8.d, lsl #2]" },
    { UINT32_C(0x04ebad49), "adr z9.d, [z10.d, z11.d, lsl #3]" },
};

int main(void)
{
    size_t i;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cdisasm_arm_instruction instruction = {0};
        char buffer[96] = {0};
        size_t length;

        instruction.raw_instruction = cases[i].word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A64;
        instruction.form_id = 2340u;
        instruction.name_id = CDISASM_ARM_NAME_ADR;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, cases[i].expected) != 0) {
            fprintf(stderr, "SVE ADR case %zu: got '%s', expected '%s'\n",
                i, buffer, cases[i].expected);
            return 1;
        }
    }
    puts("ARM generated SVE ADR scaled tests passed");
    return 0;
}
