#include "../src/arm/arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct indexed_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_isa_id isa_id;
    const char *expected;
} indexed_case;

static const indexed_case cases[] = {
    { UINT32_C(0x5f423020), 5877u, CDISASM_ARM_NAME_SQDMLAL,
      CDISASM_ARM_ISA_A64, "sqdmlal s0, h1, v2.h[0]" },
    { UINT32_C(0x5f723820), 5877u, CDISASM_ARM_NAME_SQDMLAL,
      CDISASM_ARM_ISA_A64, "sqdmlal s0, h1, v2.h[7]" },
    { UINT32_C(0x5f923020), 5877u, CDISASM_ARM_NAME_SQDMLAL,
      CDISASM_ARM_ISA_A64, "sqdmlal d0, s1, v18.s[0]" },
    { UINT32_C(0x5fb23820), 5877u, CDISASM_ARM_NAME_SQDMLAL,
      CDISASM_ARM_ISA_A64, "sqdmlal d0, s1, v18.s[3]" },
    { UINT32_C(0x0f72a820), 6248u, CDISASM_ARM_NAME_SMULL,
      CDISASM_ARM_ISA_A64, "smull v0.4s, v1.4h, v2.h[7]" },
    { UINT32_C(0x0fb2a820), 6248u, CDISASM_ARM_NAME_SMULL,
      CDISASM_ARM_ISA_A64, "smull v0.2d, v1.2s, v18.s[3]" },
    { UINT32_C(0x5fa21820), 5885u, CDISASM_ARM_NAME_FMLA,
      CDISASM_ARM_ISA_A64, "fmla s0, s1, v2.s[3]" },
    { UINT32_C(0x5fd21820), 5885u, CDISASM_ARM_NAME_FMLA,
      CDISASM_ARM_ISA_A64, "fmla d0, d1, v18.d[1]" },
    { UINT32_C(0x0fa21820), 6261u, CDISASM_ARM_NAME_FMLA,
      CDISASM_ARM_ISA_A64, "fmla v0.2s, v1.2s, v2.s[3]" },
    { UINT32_C(0x4fd21820), 6261u, CDISASM_ARM_NAME_FMLA,
      CDISASM_ARM_ISA_A64, "fmla v0.2d, v1.2d, v18.d[1]" },
    { UINT32_C(0xf2910b42), 888u, CDISASM_ARM_NAME_VQDMULL,
      CDISASM_ARM_ISA_A32, "vqdmull.s16 q0, d1, d2[0]" },
    { UINT32_C(0xf2910b6a), 888u, CDISASM_ARM_NAME_VQDMULL,
      CDISASM_ARM_ISA_A32, "vqdmull.s16 q0, d1, d2[3]" },
    { UINT32_C(0xf2a10b4a), 888u, CDISASM_ARM_NAME_VQDMULL,
      CDISASM_ARM_ISA_A32, "vqdmull.s32 q0, d1, d10[0]" },
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
        instruction.isa_id = cases[index].isa_id;
        instruction.form_id = cases[index].form_id;
        instruction.name_id = cases[index].name_id;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length != strlen(cases[index].expected)
            || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "indexed SIMD case %zu: got '%s', expected '%s'\n",
                index, length ? buffer : "<no exact recipe>",
                cases[index].expected);
            return 1;
        }
    }
    {
        cdisasm_arm_instruction invalid = {0};
        char buffer[128];

        invalid.raw_instruction = UINT32_C(0x5f023020); /* size=0 */
        invalid.opcode_size = 4u;
        invalid.isa_id = CDISASM_ARM_ISA_A64;
        invalid.form_id = 5877u;
        invalid.name_id = CDISASM_ARM_NAME_SQDMLAL;
        invalid.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        if (cdisasm_arm_format_generated(
                &invalid, 0u, buffer, sizeof(buffer)) != 0u) {
            fputs("invalid indexed SIMD size was accepted\n", stderr);
            return 1;
        }
    }
#endif
    puts("ARM generated indexed-SIMD tests passed");
    return 0;
}
