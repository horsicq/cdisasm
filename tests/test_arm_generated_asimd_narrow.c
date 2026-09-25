#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct narrow_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} narrow_case;

/* Raw words independently assembled from data/arm_asimd_narrow.s by LLVM. */
static const narrow_case cases[] = {
    { UINT32_C(0x0f0f8420), 6221u, CDISASM_ARM_NAME_SHRN,
      "shrn v0.8b, v1.8h, #1" },
    { UINT32_C(0x0f108c20), 6222u, CDISASM_ARM_NAME_RSHRN,
      "rshrn v0.4h, v1.4s, #16" },
    { UINT32_C(0x0f209420), 6223u, CDISASM_ARM_NAME_SQSHRN,
      "sqshrn v0.2s, v1.2d, #32" },
    { UINT32_C(0x4f089c20), 6224u, CDISASM_ARM_NAME_SQRSHRN,
      "sqrshrn2 v0.16b, v1.8h, #8" },
    { UINT32_C(0x2f0f8420), 6236u, CDISASM_ARM_NAME_SQSHRUN,
      "sqshrun v0.8b, v1.8h, #1" },
    { UINT32_C(0x2f108c20), 6237u, CDISASM_ARM_NAME_SQRSHRUN,
      "sqrshrun v0.4h, v1.4s, #16" },
    { UINT32_C(0x2f209420), 6238u, CDISASM_ARM_NAME_UQSHRN,
      "uqshrn v0.2s, v1.2d, #32" },
    { UINT32_C(0x6f089c20), 6239u, CDISASM_ARM_NAME_UQRSHRN,
      "uqrshrn2 v0.16b, v1.8h, #8" },
    { UINT32_C(0x5f0f9420), 5859u, CDISASM_ARM_NAME_SQSHRN,
      "sqshrn b0, h1, #1" },
    { UINT32_C(0x5f109c20), 5860u, CDISASM_ARM_NAME_SQRSHRN,
      "sqrshrn h0, s1, #16" },
    { UINT32_C(0x7f208420), 5871u, CDISASM_ARM_NAME_SQSHRUN,
      "sqshrun s0, d1, #32" },
    { UINT32_C(0x7f088c20), 5872u, CDISASM_ARM_NAME_SQRSHRUN,
      "sqrshrun b0, h1, #8" },
    { UINT32_C(0x7f1f9420), 5873u, CDISASM_ARM_NAME_UQSHRN,
      "uqshrn h0, s1, #1" },
    { UINT32_C(0x7f209c20), 5874u, CDISASM_ARM_NAME_UQRSHRN,
      "uqrshrn s0, d1, #32" },
    { UINT32_C(0x0f008420), 6221u, CDISASM_ARM_NAME_SHRN, NULL },
    { UINT32_C(0x0f408420), 6221u, CDISASM_ARM_NAME_SHRN, NULL },
};

int main(void)
{
    size_t i;
    int failures = 0;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const narrow_case *entry = &cases[i];
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
            fprintf(stderr, "narrow case %zu: got '%s', expected '%s'\n",
                i, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated ASIMD narrowing tests passed");
    return 0;
}
