#include "../src/arm/arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct tmop_case {
    uint32_t word;
    uint16_t form_id;
    const char *expected;
} tmop_case;

static const tmop_case cases[] = {
    { UINT32_C(0x80400800), 3773u,
      "ftmopa za0.s, { z0.s-z1.s }, z0.s, z22[0]" },
    { UINT32_C(0x80401800), 3773u,
      "ftmopa za0.s, { z0.s-z1.s }, z0.s, z30[0]" },
    { UINT32_C(0x80400bc0), 3773u,
      "ftmopa za0.s, { z30.s-z31.s }, z0.s, z22[0]" },
    { UINT32_C(0x80600800), 3774u,
      "ftmopa za0.s, { z0.b-z1.b }, z0.b, z22[0]" },
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
        instruction.name_id = CDISASM_ARM_NAME_FTMOPA;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length != strlen(cases[index].expected)
            || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "TMOP case %zu: got '%s', expected '%s'\n",
                index, length ? buffer : "<no exact recipe>",
                cases[index].expected);
            return 1;
        }
    }
#endif
    puts("ARM generated TMOP-control tests passed");
    return 0;
}
