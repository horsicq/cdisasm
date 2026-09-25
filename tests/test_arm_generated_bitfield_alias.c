#include "../src/arm/arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct alias_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} alias_case;

/* Independent LLVM 21 AArch64 assembly witnesses. */
static const alias_case cases[] = {
    { UINT32_C(0x131c1020), 4426u, CDISASM_ARM_NAME_SBFIZ,
      "sbfiz w0, w1, #4, #5" },
    { UINT32_C(0x13042020), 4426u, CDISASM_ARM_NAME_SBFX,
      "sbfx w0, w1, #4, #5" },
    { UINT32_C(0xb3782c20), 4430u, CDISASM_ARM_NAME_BFI,
      "bfi x0, x1, #8, #12" },
    { UINT32_C(0xd3484c20), 4431u, CDISASM_ARM_NAME_UBFX,
      "ubfx x0, x1, #8, #12" },
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
            fprintf(stderr, "bitfield alias case %zu: got '%s', expected '%s'\n",
                index, length ? buffer : "<no exact recipe>",
                cases[index].expected);
            return 1;
        }
    }
    {
        cdisasm_arm_instruction invalid = {0};
        char buffer[128];

        invalid.raw_instruction = UINT32_C(0x131c1020) | UINT32_C(1 << 22);
        invalid.opcode_size = 4u;
        invalid.isa_id = CDISASM_ARM_ISA_A64;
        invalid.form_id = 4426u;
        invalid.name_id = CDISASM_ARM_NAME_SBFIZ;
        invalid.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        if (cdisasm_arm_format_generated(
                &invalid, 0u, buffer, sizeof(buffer)) != 0u) {
            fputs("invalid 32-bit bitfield N bit was accepted\n", stderr);
            return 1;
        }
    }
#endif
    puts("ARM generated bitfield-alias tests passed");
    return 0;
}
