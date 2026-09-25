#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct datatype_case {
    uint32_t word;
    uint16_t form_id;
    uint8_t isa_id;
    const char *expected;
} datatype_case;

/* Independently assembled from data/arm_vcvt_datatype.s by LLVM. */
static const datatype_case cases[] = {
    { UINT32_C(0xf3bb06c2), 860u, CDISASM_ARM_ISA_A32,
      "vcvt.f32.u32 q0, q1" },
    { UINT32_C(0xf3bb47c6), 860u, CDISASM_ARM_ISA_A32,
      "vcvt.u32.f32 q2, q3" },
    { UINT32_C(0xf2b80f11), 941u, CDISASM_ARM_ISA_A32,
      "vcvt.s32.f32 d0, d1, #8" },
    { UINT32_C(0xf2b82e13), 941u, CDISASM_ARM_ISA_A32,
      "vcvt.f32.s32 d2, d3, #8" },
    { UINT32_C(0x06c2ffbb), 1387u, CDISASM_ARM_ISA_T32,
      "vcvt.f32.u32 q0, q1" },
    { UINT32_C(0x47c6ffbb), 1387u, CDISASM_ARM_ISA_T32,
      "vcvt.u32.f32 q2, q3" },
    { UINT32_C(0x0f11efb8), 1468u, CDISASM_ARM_ISA_T32,
      "vcvt.s32.f32 d0, d1, #8" },
    { UINT32_C(0x2e13efb8), 1468u, CDISASM_ARM_ISA_T32,
      "vcvt.f32.s32 d2, d3, #8" },
};

int main(void)
{
    size_t i;
    int failures = 0;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const datatype_case *entry = &cases[i];
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
        size_t length;

        instruction.raw_instruction = entry->word;
        instruction.opcode_size = 4u;
        instruction.isa_id = entry->isa_id;
        instruction.form_id = entry->form_id;
        instruction.name_id = CDISASM_ARM_NAME_VCVT;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, entry->expected) != 0) {
            fprintf(stderr, "VCVT datatype case %zu: got '%s', expected '%s'\n",
                i, buffer, entry->expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated VCVT datatype tests passed");
    return 0;
}
