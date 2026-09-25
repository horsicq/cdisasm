#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

/* Generated-form identity is tested independently with the real decoder. */
int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct extend_ins_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} extend_ins_case;

/* Merge encodings and all INS forms have LLVM byte witnesses. Zeroing SVE2p2
 * encodings use the pinned Arm A-profile reference: this LLVM build predates
 * that extension, so it reports those words as unknown. */
static const extend_ins_case cases[] = {
    { UINT32_C(0x0492ada7), 2285u, CDISASM_ARM_NAME_SXTH,
      "sxth z7.s, p3/m, z13.s" },
    { UINT32_C(0x0482a000), 2286u, CDISASM_ARM_NAME_SXTH,
      "sxth z0.s, p0/z, z0.s" },
    { UINT32_C(0x0450ada7), 2287u, CDISASM_ARM_NAME_SXTB,
      "sxtb z7.h, p3/m, z13.h" },
    { UINT32_C(0x0440a000), 2288u, CDISASM_ARM_NAME_SXTB,
      "sxtb z0.h, p0/z, z0.h" },
    { UINT32_C(0x04d3a000), 2291u, CDISASM_ARM_NAME_UXTH,
      "uxth z0.d, p0/m, z0.d" },
    { UINT32_C(0x04c3ada7), 2292u, CDISASM_ARM_NAME_UXTH,
      "uxth z7.d, p3/z, z13.d" },
    { UINT32_C(0x04d1a000), 2293u, CDISASM_ARM_NAME_UXTB,
      "uxtb z0.d, p0/m, z0.d" },
    { UINT32_C(0x04c1ada7), 2294u, CDISASM_ARM_NAME_UXTB,
      "uxtb z7.d, p3/z, z13.d" },
    { UINT32_C(0x0410ada7), 2287u, CDISASM_ARM_NAME_SXTB,
      NULL },
    { UINT32_C(0x0412ada7), 2285u, CDISASM_ARM_NAME_SXTH,
      NULL },
    { UINT32_C(0x4e011c20), 5915u, CDISASM_ARM_NAME_INS,
      "ins v0.b[0], w1" },
    { UINT32_C(0x4e061c62), 5915u, CDISASM_ARM_NAME_INS,
      "ins v2.h[1], w3" },
    { UINT32_C(0x4e141ca4), 5915u, CDISASM_ARM_NAME_INS,
      "ins v4.s[2], w5" },
    { UINT32_C(0x4e181ce6), 5915u, CDISASM_ARM_NAME_INS,
      "ins v6.d[1], x7" },
    { UINT32_C(0x6e011420), 5918u, CDISASM_ARM_NAME_INS,
      "ins v0.b[0], v1.b[2]" },
    { UINT32_C(0x6e062462), 5918u, CDISASM_ARM_NAME_INS,
      "ins v2.h[1], v3.h[2]" },
    { UINT32_C(0x6e1424a4), 5918u, CDISASM_ARM_NAME_INS,
      "ins v4.s[2], v5.s[1]" },
    { UINT32_C(0x6e1804e6), 5918u, CDISASM_ARM_NAME_INS,
      "ins v6.d[1], v7.d[0]" },
    { UINT32_C(0x4e011c20), 5915u, CDISASM_ARM_NAME_MOV,
      "mov v0.b[0], w1" },
    { UINT32_C(0x6e062462), 5918u, CDISASM_ARM_NAME_MOV,
      "mov v2.h[1], v3.h[2]" },
    { UINT32_C(0x4e011fe0), 5915u, CDISASM_ARM_NAME_MOV,
      "mov v0.b[0], wzr" },
    { UINT32_C(0x4e181fe0), 5915u, CDISASM_ARM_NAME_MOV,
      "mov v0.d[1], xzr" },
    { UINT32_C(0x4e001c20), 5915u, CDISASM_ARM_NAME_INS,
      NULL },
    { UINT32_C(0x6e062c62), 5918u, CDISASM_ARM_NAME_INS,
      NULL },
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const extend_ins_case *entry = &cases[index];
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
        size_t length;

        instruction.raw_instruction = entry->word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A64;
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
                "ARM extend/INS case %zu: got '%s', expected '%s'\n",
                index, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            failures += 1;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated extend/INS tests passed");
    return 0;
}
