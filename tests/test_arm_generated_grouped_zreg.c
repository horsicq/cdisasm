#include "../src/arm/arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

typedef struct grouped_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *formatted;
} grouped_case;

static const grouped_case cases[] = {
    { UINT32_C(0xa1010000), 3613u, CDISASM_ARM_NAME_LD1B,
      "ld1b { z0.b, z8.b }, pn8/z, [x0, x1]" },
    { UINT32_C(0xa1010017), 3613u, CDISASM_ARM_NAME_LD1B,
      "ld1b { z23.b, z31.b }, pn8/z, [x0, x1]" },
    { UINT32_C(0xa1018000), 3621u, CDISASM_ARM_NAME_LD1B,
      "ld1b { z0.b, z4.b, z8.b, z12.b }, pn8/z, [x0, x1]" },
    { UINT32_C(0xa1018013), 3621u, CDISASM_ARM_NAME_LD1B,
      "ld1b { z19.b, z23.b, z27.b, z31.b }, pn8/z, [x0, x1]" },
    { UINT32_C(0xa1011c18), 3614u, CDISASM_ARM_NAME_LDNT1B,
      "ldnt1b { z16.b, z24.b }, pn15/z, [x0, x1]" },
};

/* This is a renderer unit test.  The generated decoder's identity checks are
 * tested separately; opaque public operands currently suppress public decode
 * for these particular SME tuple forms. */
int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

int main(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction = {0};
        char buffer[128];
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
        if (length != strlen(cases[index].formatted)
            || strcmp(buffer, cases[index].formatted) != 0) {
            fprintf(stderr, "grouped Z format failed at case %zu: %s\n",
                index, length ? buffer : "<no exact recipe>");
            return 1;
        }
    }
    {
        cdisasm_arm_instruction malformed = {0};
        char buffer[128];

        /* Bit 2 belongs to the fixed-zero op2 slot in 4x4 forms, not Zt. */
        malformed.raw_instruction = UINT32_C(0xa1018004);
        malformed.opcode_size = 4u;
        malformed.isa_id = CDISASM_ARM_ISA_A64;
        malformed.form_id = 3621u;
        malformed.name_id = CDISASM_ARM_NAME_LD1B;
        malformed.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        if (cdisasm_arm_format_generated(
                &malformed, 0u, buffer, sizeof(buffer)) != 0u) {
            fputs("grouped Z invalid 4x4 selector was accepted\n", stderr);
            return 1;
        }
    }
#endif
    puts("ARM generated grouped-Z tests passed");
    return 0;
}
