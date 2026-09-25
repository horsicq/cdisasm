#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct ror_case {
    uint32_t word;
    uint32_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} ror_case;

/* LLVM 21 Thumb bytes: 4f ea 71 00 and 5f ea f3 72. */
static const ror_case cases[] = {
    { UINT32_C(0x0071ea4f), 1772u, CDISASM_ARM_NAME_ROR,
      "ror r0, r1, #1" },
    { UINT32_C(0x72f3ea5f), 1774u, CDISASM_ARM_NAME_RORS,
      "rors r2, r3, #31" },
};

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
        size_t length;

        instruction.raw_instruction = cases[index].word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_T32;
        instruction.form_id = cases[index].form_id;
        instruction.name_id = cases[index].name_id;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "Thumb ROR case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            return 1;
        }
    }
    puts("ARM generated Thumb ROR aliases passed");
    return 0;
}
