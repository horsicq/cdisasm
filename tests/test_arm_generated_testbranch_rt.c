#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct testbranch_case {
    uint32_t word;
    uint16_t form_id;
    uint16_t name_id;
    const char *expected;
} testbranch_case;

/* Assembled from tests/data/arm_testbranch_rt.s with LLVM AArch64. */
static const testbranch_case cases[] = {
    { UINT32_C(0x36000000), 4563u, CDISASM_ARM_NAME_TBZ,
        "tbz w0, #0, #0x1000" },
    { UINT32_C(0x36f8001f), 4563u, CDISASM_ARM_NAME_TBZ,
        "tbz wzr, #31, #0x1000" },
    { UINT32_C(0xb7400005), 4564u, CDISASM_ARM_NAME_TBNZ,
        "tbnz x5, #40, #0x1000" },
    { UINT32_C(0xb7f8001f), 4564u, CDISASM_ARM_NAME_TBNZ,
        "tbnz xzr, #63, #0x1000" },
};

int main(void)
{
    size_t i;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cdisasm_arm_instruction instruction = {0};
        char buffer[80] = {0};
        size_t length;

        instruction.address = UINT64_C(0x1000);
        instruction.branch_target = UINT64_C(0x1000);
        instruction.raw_instruction = cases[i].word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A64;
        instruction.form_id = cases[i].form_id;
        instruction.name_id = cases[i].name_id;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, cases[i].expected) != 0) {
            fprintf(stderr, "testbranch case %zu: got '%s', expected '%s'\n",
                i, buffer, cases[i].expected);
            return 1;
        }
    }
    puts("ARM generated testbranch Rt tests passed");
    return 0;
}
