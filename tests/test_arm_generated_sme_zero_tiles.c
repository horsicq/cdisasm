#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct zero_case {
    uint32_t word;
    const char *expected;
} zero_case;

/* LLVM-assembled words from tests/data/arm_sme_zero_tiles.s. */
static const zero_case cases[] = {
    { UINT32_C(0xc0080000), "zero {}" },
    { UINT32_C(0xc00800ff), "zero {za}" },
    { UINT32_C(0xc0080055), "zero {za0.h}" },
    { UINT32_C(0xc00800aa), "zero {za1.h}" },
    { UINT32_C(0xc0080011), "zero {za0.s}" },
    { UINT32_C(0xc0080033), "zero {za0.s, za1.s}" },
    { UINT32_C(0xc0080001), "zero {za0.d}" },
    { UINT32_C(0xc0080003), "zero {za0.d, za1.d}" },
    { UINT32_C(0xc0080085), "zero {za0.d, za2.d, za7.d}" },
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
        instruction.form_id = 3907u;
        instruction.name_id = CDISASM_ARM_NAME_ZERO;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, cases[i].expected) != 0) {
            fprintf(stderr, "SME ZERO case %zu: got '%s', expected '%s'\n",
                i, buffer, cases[i].expected);
            return 1;
        }
    }
    puts("ARM generated SME ZERO tile tests passed");
    return 0;
}
