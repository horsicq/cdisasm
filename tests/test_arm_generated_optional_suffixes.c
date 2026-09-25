#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

/* The generated-form matcher is covered by decoder tests. */
int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct optional_suffix_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} optional_suffix_case;

/* Words independently witnessed with LLVM's AArch64 disassembler.
 * This formatter uses decimal integer immediates rather than LLVM's hex. */
static const optional_suffix_case cases[] = {
    { UINT32_C(0x0f000400), 6199u, CDISASM_ARM_NAME_MOVI,
      "movi v0.2s, #0" },
    { UINT32_C(0x4f0767e1), 6199u, CDISASM_ARM_NAME_MOVI,
      "movi v1.4s, #255, lsl #24" },
    { UINT32_C(0x0f008642), 6201u, CDISASM_ARM_NAME_MOVI,
      "movi v2.4h, #18" },
    { UINT32_C(0x4f01a683), 6201u, CDISASM_ARM_NAME_MOVI,
      "movi v3.8h, #52, lsl #8" },
    { UINT32_C(0x0f001640), 6200u, CDISASM_ARM_NAME_ORR,
      "orr v0.2s, #18" },
    { UINT32_C(0x4f017681), 6200u, CDISASM_ARM_NAME_ORR,
      "orr v1.4s, #52, lsl #24" },
    { UINT32_C(0x0f0296c2), 6202u, CDISASM_ARM_NAME_ORR,
      "orr v2.4h, #86" },
    { UINT32_C(0x4f03b703), 6202u, CDISASM_ARM_NAME_ORR,
      "orr v3.8h, #120, lsl #8" },
    { UINT32_C(0x2f00064a), 6207u, CDISASM_ARM_NAME_MVNI,
      "mvni v10.2s, #18" },
    { UINT32_C(0x6f01668b), 6207u, CDISASM_ARM_NAME_MVNI,
      "mvni v11.4s, #52, lsl #24" },
    { UINT32_C(0x2f0286cc), 6209u, CDISASM_ARM_NAME_MVNI,
      "mvni v12.4h, #86" },
    { UINT32_C(0x6f03a70d), 6209u, CDISASM_ARM_NAME_MVNI,
      "mvni v13.8h, #120, lsl #8" },
    { UINT32_C(0x2f041744), 6208u, CDISASM_ARM_NAME_BIC,
      "bic v4.2s, #154" },
    { UINT32_C(0x6f057785), 6208u, CDISASM_ARM_NAME_BIC,
      "bic v5.4s, #188, lsl #24" },
    { UINT32_C(0x2f0697c6), 6210u, CDISASM_ARM_NAME_BIC,
      "bic v6.4h, #222" },
    { UINT32_C(0x6f07b607), 6210u, CDISASM_ARM_NAME_BIC,
      "bic v7.8h, #240, lsl #8" },
    { UINT32_C(0x85800020), 3214u, CDISASM_ARM_NAME_LDR,
      "ldr p0, [x1]" },
    { UINT32_C(0x85a003e7), 3214u, CDISASM_ARM_NAME_LDR,
      "ldr p7, [sp, #-256, mul vl]" },
    { UINT32_C(0x859f5fd1), 3215u, CDISASM_ARM_NAME_LDR,
      "ldr z17, [x30, #255, mul vl]" },
    { UINT32_C(0xe59f1fc7), 3469u, CDISASM_ARM_NAME_STR,
      "str p7, [x30, #255, mul vl]" },
    { UINT32_C(0xe5a043ff), 3476u, CDISASM_ARM_NAME_STR,
      "str z31, [sp, #-256, mul vl]" },
    /* A cmode with the wrong low bit is outside the MOVI form. */
    { UINT32_C(0x0f001400), 6199u, CDISASM_ARM_NAME_MOVI,
      NULL },
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const optional_suffix_case *entry = &cases[index];
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
                "ARM optional suffix case %zu: got '%s', expected '%s'\n",
                index, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            failures += 1;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated optional suffix tests passed");
    return 0;
}
