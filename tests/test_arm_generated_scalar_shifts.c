#include "../src/arm/arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct shift_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} shift_case;

/* Byte witnesses assembled independently with LLVM 21 for AArch64. */
static const shift_case cases[] = {
    { UINT32_C(0x5f7f0420), 5853u, CDISASM_ARM_NAME_SSHR,
      "sshr d0, d1, #1" },
    { UINT32_C(0x5f400420), 5853u, CDISASM_ARM_NAME_SSHR,
      "sshr d0, d1, #64" },
    { UINT32_C(0x5f405420), 5857u, CDISASM_ARM_NAME_SHL,
      "shl d0, d1, #0" },
    { UINT32_C(0x5f7f5420), 5857u, CDISASM_ARM_NAME_SHL,
      "shl d0, d1, #63" },
};

int main(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
        size_t length;

        instruction.raw_instruction = cases[index].word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A64;
        instruction.form_id = cases[index].form_id;
        instruction.name_id = cases[index].name_id;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length != strlen(cases[index].expected)
            || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "scalar shift case %zu: got '%s', expected '%s'\n",
                index, length ? buffer : "<no exact recipe>",
                cases[index].expected);
            return 1;
        }
    }
    {
        cdisasm_arm_instruction invalid = {0};
        char buffer[128];

        invalid.raw_instruction = UINT32_C(0x5f000420); /* immh=0 */
        invalid.opcode_size = 4u;
        invalid.isa_id = CDISASM_ARM_ISA_A64;
        invalid.form_id = 5853u;
        invalid.name_id = CDISASM_ARM_NAME_SSHR;
        invalid.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        if (cdisasm_arm_format_generated(
                &invalid, 0u, buffer, sizeof(buffer)) != 0u) {
            fputs("invalid scalar shift immh was accepted\n", stderr);
            return 1;
        }
    }
#endif
    puts("ARM generated scalar-shift tests passed");
    return 0;
}
