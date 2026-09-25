#include "../src/arm/arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct concat_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_isa_id isa_id;
    const char *expected;
} concat_case;

/* Independent LLVM 21 ARM/Thumb assembly witnesses. */
static const concat_case cases[] = {
    { UINT32_C(0xeeb70900), 607u, CDISASM_ARM_NAME_VMOV,
      CDISASM_ARM_ISA_A32, "vmov.f16 s0, #1.0" },
    { UINT32_C(0xeeb70a00), 608u, CDISASM_ARM_NAME_VMOV,
      CDISASM_ARM_ISA_A32, "vmov.f32 s0, #1.0" },
    { UINT32_C(0xeeb60a00), 608u, CDISASM_ARM_NAME_VMOV,
      CDISASM_ARM_ISA_A32, "vmov.f32 s0, #0.5" },
    { UINT32_C(0xeeb80b00), 609u, CDISASM_ARM_NAME_VMOV,
      CDISASM_ARM_ISA_A32, "vmov.f64 d0, #-2.0" },
    { UINT32_C(0x0a00eeb7), 1593u, CDISASM_ARM_NAME_VMOV,
      CDISASM_ARM_ISA_T32, "vmov.f32 s0, #1.0" },
    { UINT32_C(0xeeba0bc8), 593u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_A32, "vcvt.f64.s32 d0, d0, #16" },
    { UINT32_C(0xeebe0bc8), 594u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_A32, "vcvt.s32.f64 d0, d0, #16" },
    { UINT32_C(0xeefafbc8), 593u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_A32, "vcvt.f64.s32 d31, d31, #16" },
    { UINT32_C(0xf291026a), 884u, CDISASM_ARM_NAME_VMLAL,
      CDISASM_ARM_ISA_A32, "vmlal.s16 q0, d1, d2[3]" },
    { UINT32_C(0xf2a1026a), 884u, CDISASM_ARM_NAME_VMLAL,
      CDISASM_ARM_ISA_A32, "vmlal.s32 q0, d1, d10[1]" },
    { UINT32_C(0xf291066a), 889u, CDISASM_ARM_NAME_VMLSL,
      CDISASM_ARM_ISA_A32, "vmlsl.s16 q0, d1, d2[3]" },
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
            fprintf(stderr, "VFP concat case %zu: got '%s', expected '%s'\n",
                index, length ? buffer : "<no exact recipe>",
                cases[index].expected);
            return 1;
        }
    }
    {
        cdisasm_arm_instruction invalid = {0};
        char buffer[128];

        invalid.raw_instruction = UINT32_C(0xeeb70a00) & ~UINT32_C(3 << 8);
        invalid.opcode_size = 4u;
        invalid.isa_id = CDISASM_ARM_ISA_A32;
        invalid.form_id = 608u;
        invalid.name_id = CDISASM_ARM_NAME_VMOV;
        invalid.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        if (cdisasm_arm_format_generated(
                &invalid, 0u, buffer, sizeof(buffer)) != 0u) {
            fputs("mismatched VFP immediate size was accepted\n", stderr);
            return 1;
        }
    }
#endif
    puts("ARM generated VFP-concat tests passed");
    return 0;
}
