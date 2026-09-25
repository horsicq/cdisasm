#include "../src/arm/arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct split_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} split_case;

/* Independent LLVM 21 ARM-mode assembly witnesses. */
static const split_case cases[] = {
    { UINT32_C(0xfe01087a), 479u, CDISASM_ARM_NAME_VFMAL,
      "vfmal.f16 q0, d1, d2[3]" },
    { UINT32_C(0xfe11087a), 481u, CDISASM_ARM_NAME_VFMSL,
      "vfmsl.f16 q0, d1, d2[3]" },
    { UINT32_C(0xf291036a), 883u, CDISASM_ARM_NAME_VQDMLAL,
      "vqdmlal.s16 q0, d1, d2[3]" },
    { UINT32_C(0xf2a1036a), 883u, CDISASM_ARM_NAME_VQDMLAL,
      "vqdmlal.s32 q0, d1, d10[1]" },
    { UINT32_C(0xf291086a), 890u, CDISASM_ARM_NAME_VMUL,
      "vmul.i16 d0, d1, d2[3]" },
    { UINT32_C(0xf2a1086a), 890u, CDISASM_ARM_NAME_VMUL,
      "vmul.i32 d0, d1, d10[1]" },
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
        instruction.isa_id = CDISASM_ARM_ISA_A32;
        instruction.form_id = cases[index].form_id;
        instruction.name_id = cases[index].name_id;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length != strlen(cases[index].expected)
            || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "split indexed case %zu: got '%s', expected '%s'\n",
                index, length ? buffer : "<no exact recipe>",
                cases[index].expected);
            return 1;
        }
    }
    {
        cdisasm_arm_instruction invalid = {0};
        char buffer[128];

        invalid.raw_instruction = UINT32_C(0xf281036a); /* size=0 */
        invalid.opcode_size = 4u;
        invalid.isa_id = CDISASM_ARM_ISA_A32;
        invalid.form_id = 883u;
        invalid.name_id = CDISASM_ARM_NAME_VQDMLAL;
        invalid.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        if (cdisasm_arm_format_generated(
                &invalid, 0u, buffer, sizeof(buffer)) != 0u) {
            fputs("illegal split indexed element size was accepted\n", stderr);
            return 1;
        }
    }
#endif
    puts("ARM generated split-indexed tests passed");
    return 0;
}
