#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

/* Generated form identity is tested in the decoder; isolate the recipes. */
int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct shift_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} shift_case;

static const shift_case cases[] = {
    { UINT32_C(0x0f080400), 6215u, CDISASM_ARM_NAME_SSHR,
      "sshr v0.8b, v0.8b, #8" },
    { UINT32_C(0x0f081400), 6216u, CDISASM_ARM_NAME_SSRA,
      "ssra v0.8b, v0.8b, #8" },
    { UINT32_C(0x0f082400), 6217u, CDISASM_ARM_NAME_SRSHR,
      "srshr v0.8b, v0.8b, #8" },
    { UINT32_C(0x0f083400), 6218u, CDISASM_ARM_NAME_SRSRA,
      "srsra v0.8b, v0.8b, #8" },
    { UINT32_C(0x0f085400), 6219u, CDISASM_ARM_NAME_SHL,
      "shl v0.8b, v0.8b, #0" },
    { UINT32_C(0x0f087400), 6220u, CDISASM_ARM_NAME_SQSHL,
      "sqshl v0.8b, v0.8b, #0" },
    { UINT32_C(0x2f080400), 6228u, CDISASM_ARM_NAME_USHR,
      "ushr v0.8b, v0.8b, #8" },
    { UINT32_C(0x2f081400), 6229u, CDISASM_ARM_NAME_USRA,
      "usra v0.8b, v0.8b, #8" },
    { UINT32_C(0x2f082400), 6230u, CDISASM_ARM_NAME_URSHR,
      "urshr v0.8b, v0.8b, #8" },
    { UINT32_C(0x2f083400), 6231u, CDISASM_ARM_NAME_URSRA,
      "ursra v0.8b, v0.8b, #8" },
    { UINT32_C(0x2f084400), 6232u, CDISASM_ARM_NAME_SRI,
      "sri v0.8b, v0.8b, #8" },
    { UINT32_C(0x2f085400), 6233u, CDISASM_ARM_NAME_SLI,
      "sli v0.8b, v0.8b, #0" },
    { UINT32_C(0x2f086400), 6234u, CDISASM_ARM_NAME_SQSHLU,
      "sqshlu v0.8b, v0.8b, #0" },
    { UINT32_C(0x2f087400), 6235u, CDISASM_ARM_NAME_UQSHL,
      "uqshl v0.8b, v0.8b, #0" },
    { UINT32_C(0x4f080400), 6215u, CDISASM_ARM_NAME_SSHR,
      "sshr v0.16b, v0.16b, #8" },
    { UINT32_C(0x0f100400), 6215u, CDISASM_ARM_NAME_SSHR,
      "sshr v0.4h, v0.4h, #16" },
    { UINT32_C(0x4f100400), 6215u, CDISASM_ARM_NAME_SSHR,
      "sshr v0.8h, v0.8h, #16" },
    { UINT32_C(0x0f200400), 6215u, CDISASM_ARM_NAME_SSHR,
      "sshr v0.2s, v0.2s, #32" },
    { UINT32_C(0x4f200400), 6215u, CDISASM_ARM_NAME_SSHR,
      "sshr v0.4s, v0.4s, #32" },
    { UINT32_C(0x4f400400), 6215u, CDISASM_ARM_NAME_SSHR,
      "sshr v0.2d, v0.2d, #64" },
    { UINT32_C(0x4f7f0400), 6215u, CDISASM_ARM_NAME_SSHR,
      "sshr v0.2d, v0.2d, #1" },
    { UINT32_C(0x4f7f5400), 6219u, CDISASM_ARM_NAME_SHL,
      "shl v0.2d, v0.2d, #63" },
    { UINT32_C(0x0f080441), 6215u, CDISASM_ARM_NAME_SSHR,
      "sshr v1.8b, v2.8b, #8" },
    { UINT32_C(0x0f000400), 6215u, CDISASM_ARM_NAME_SSHR,
      NULL },
    { UINT32_C(0x0f400400), 6215u, CDISASM_ARM_NAME_SSHR,
      NULL },
    { UINT32_C(0x0f405400), 6219u, CDISASM_ARM_NAME_SHL,
      NULL }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const shift_case *entry = &cases[index];
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
            fprintf(stderr, "ASIMD shift case %zu: got '%s', expected '%s'\n",
                index, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            failures += 1;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated ASIMD shift arrangement tests passed");
    return 0;
}
