#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

/* The decoder's generated-form identity matching is tested separately. */
int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct scalar_lane_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    uint8_t isa_id;
    const char *expected;
} scalar_lane_case;

/* Every word was independently disassembled by LLVM llvm-objdump for Armv8-A.
 * T32 words are in architectural halfword order here. */
static const scalar_lane_case cases[] = {
    { UINT32_C(0xf293204c), 881u, CDISASM_ARM_NAME_VMLA,
      CDISASM_ARM_ISA_A32, "vmla.i16 d2, d3, d4[1]" },
    { UINT32_C(0xf3a42045), 882u, CDISASM_ARM_NAME_VMLA,
      CDISASM_ARM_ISA_A32, "vmla.i32 q1, q2, d5[0]" },
    { UINT32_C(0xf2976463), 886u, CDISASM_ARM_NAME_VMLS,
      CDISASM_ARM_ISA_A32, "vmls.i16 d6, d7, d3[2]" },
    { UINT32_C(0xf3aa8467), 887u, CDISASM_ARM_NAME_VMLS,
      CDISASM_ARM_ISA_A32, "vmls.i32 q4, q5, d7[1]" },
    { UINT32_C(0xef93204c), 1408u, CDISASM_ARM_NAME_VMLA,
      CDISASM_ARM_ISA_T32, "vmla.i16 d2, d3, d4[1]" },
    { UINT32_C(0xffa42045), 1409u, CDISASM_ARM_NAME_VMLA,
      CDISASM_ARM_ISA_T32, "vmla.i32 q1, q2, d5[0]" },
    { UINT32_C(0xef976463), 1413u, CDISASM_ARM_NAME_VMLS,
      CDISASM_ARM_ISA_T32, "vmls.i16 d6, d7, d3[2]" },
    { UINT32_C(0xffaa8467), 1414u, CDISASM_ARM_NAME_VMLS,
      CDISASM_ARM_ISA_T32, "vmls.i32 q4, q5, d7[1]" },
    { UINT32_C(0xeeba1964), 589u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_A32, "vcvt.f16.s16 s2, s2, #7" },
    { UINT32_C(0xeebf2944), 590u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_A32, "vcvt.u16.f16 s4, s4, #8" },
    { UINT32_C(0xeeba0ac8), 591u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_A32, "vcvt.f32.s32 s0, s0, #16" },
    { UINT32_C(0xeebe1aec), 592u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_A32, "vcvt.s32.f32 s2, s2, #7" },
    { UINT32_C(0xeebb3965), 1574u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_T32, "vcvt.f16.u16 s6, s6, #5" },
    { UINT32_C(0xeebe4942), 1575u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_T32, "vcvt.s16.f16 s8, s8, #12" },
    { UINT32_C(0xeefb2a44), 1576u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_T32, "vcvt.f32.u16 s5, s5, #8" },
    { UINT32_C(0xeebf3ae0), 1577u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_T32, "vcvt.u32.f32 s6, s6, #31" },
    /* D=1 selects the odd S register rather than extending Vd's number. */
    { UINT32_C(0xeefa0a40), 591u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_A32, "vcvt.f32.s16 s1, s1, #16" },
    { UINT32_C(0xeefa0a40), 1576u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_T32, "vcvt.f32.s16 s1, s1, #16" },
    /* M is the high lane bit for 16-bit elements, Vm[3] the low bit. */
    { UINT32_C(0xf293206c), 881u, CDISASM_ARM_NAME_VMLA,
      CDISASM_ARM_ISA_A32, "vmla.i16 d2, d3, d4[3]" },
    { UINT32_C(0xef93206c), 1408u, CDISASM_ARM_NAME_VMLA,
      CDISASM_ARM_ISA_T32, "vmla.i16 d2, d3, d4[3]" },
    /* The same lane transform is shared with the older Dmx__4 rule. */
    { UINT32_C(0xf29eab6f), 888u, CDISASM_ARM_NAME_VQDMULL,
      CDISASM_ARM_ISA_A32, "vqdmull.s16 q5, d14, d7[3]" },
    { UINT32_C(0xef9eab6f), 1415u, CDISASM_ARM_NAME_VQDMULL,
      CDISASM_ARM_ISA_T32, "vqdmull.s16 q5, d14, d7[3]" },
    /* Illegal size is rejected by the shared Dm[x] operand renderer. */
    { UINT32_C(0xf283204c), 881u, CDISASM_ARM_NAME_VMLA,
      CDISASM_ARM_ISA_A32, NULL },
    /* FP16 fractional width is 16, but this encoding's scale is 25. */
    { UINT32_C(0xeeba196c), 589u, CDISASM_ARM_NAME_VCVT,
      CDISASM_ARM_ISA_A32, NULL },
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const scalar_lane_case *entry = &cases[index];
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
        size_t length;

        instruction.raw_instruction =
            entry->isa_id == CDISASM_ARM_ISA_T32
            ? (entry->word << 16) | (entry->word >> 16)
            : entry->word;
        instruction.opcode_size = 4u;
        instruction.isa_id = entry->isa_id;
        instruction.form_id = entry->form_id;
        instruction.name_id = entry->name_id;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if ((entry->expected == NULL && length != 0u)
            || (entry->expected != NULL
                && (length == 0u
                    || strcmp(buffer, entry->expected) != 0))) {
            fprintf(stderr,
                "ARM scalar-lane case %zu: got '%s', expected '%s'\n",
                index, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            failures += 1;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated VCVT/scalar-lane tests passed");
    return 0;
}
