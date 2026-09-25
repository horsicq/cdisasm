#include "arm_generated_formatter.h"
#include "arm_pstate_msr.h"

#include <stdio.h>
#include <string.h>

/* Focused recipe test: the generated tree's exact form matcher is tested
 * separately by the public decode/corpus tests. */
int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct pstate_case {
    uint32_t word;
    uint8_t field;
    uint8_t immediate;
    const char *formatted;
} pstate_case;

/* LLVM 21 assembler/objdump witnesses for common fields and .inst/objdump
 * witnesses for newer ALLINT, PM and SME encodings. */
static const pstate_case cases[] = {
    { UINT32_C(0xd500457f), CDISASM_ARM_PSTATE_FIELD_UAO, 5u,
      "msr uao, #0x5" },
    { UINT32_C(0xd500459f), CDISASM_ARM_PSTATE_FIELD_PAN, 5u,
      "msr pan, #0x5" },
    { UINT32_C(0xd50045bf), CDISASM_ARM_PSTATE_FIELD_SPSEL, 5u,
      "msr spsel, #0x5" },
    { UINT32_C(0xd501411f), CDISASM_ARM_PSTATE_FIELD_ALLINT, 1u,
      "msr allint, #0x1" },
    { UINT32_C(0xd501431f), CDISASM_ARM_PSTATE_FIELD_PM, 1u,
      "msr pm, #0x1" },
    { UINT32_C(0xd503453f), CDISASM_ARM_PSTATE_FIELD_SSBS, 5u,
      "msr ssbs, #0x5" },
    { UINT32_C(0xd503455f), CDISASM_ARM_PSTATE_FIELD_DIT, 5u,
      "msr dit, #0x5" },
    { UINT32_C(0xd503437f), CDISASM_ARM_PSTATE_FIELD_SVCRSM, 1u,
      NULL }, /* preferred SMSTART alias */
    { UINT32_C(0xd503457f), CDISASM_ARM_PSTATE_FIELD_SVCRZA, 1u,
      NULL }, /* preferred SMSTART alias */
    { UINT32_C(0xd503477f), CDISASM_ARM_PSTATE_FIELD_SVCRSMZA, 1u,
      NULL }, /* preferred SMSTART alias */
    { UINT32_C(0xd503419f), CDISASM_ARM_PSTATE_FIELD_TCO, 1u,
      "msr tco, #0x1" },
    { UINT32_C(0xd50345df), CDISASM_ARM_PSTATE_FIELD_DAIFSET, 5u,
      "msr daifset, #0x5" },
    { UINT32_C(0xd50341ff), CDISASM_ARM_PSTATE_FIELD_DAIFCLR, 1u,
      "msr daifclr, #0x1" },
};

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction = { 0 };
        uint8_t field = 0u;
        uint8_t immediate = 0u;
        char output[80];
        size_t length;

        if (!arm_pstate_msr_decode_word(
                cases[index].word, &field, &immediate)
            || field != cases[index].field
            || immediate != cases[index].immediate) {
            fprintf(stderr, "PSTATE map case %zu failed\n", index);
            return 1;
        }
        if (cases[index].formatted == NULL) {
            continue;
        }
        instruction.raw_instruction = cases[index].word;
        instruction.opcode_size = 4u;
        instruction.form_id = UINT16_C(4498);
        instruction.name_id = CDISASM_ARM_NAME_MSR;
        instruction.isa_id = CDISASM_ARM_ISA_A64;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u,
            output, sizeof(output));
        if (length != strlen(cases[index].formatted)
            || strcmp(output, cases[index].formatted) != 0) {
            fprintf(stderr, "PSTATE format case %zu: '%s'\n", index,
                length == 0u ? "<unavailable>" : output);
            return 1;
        }
    }
    {
        static const uint32_t invalid_words[] = {
            UINT32_C(0xd501441f), /* unallocated PM CRm */
            UINT32_C(0xd503407f), /* unallocated SVCR CRm */
            UINT32_C(0xd500401f), /* source condition excludes op2=0 */
            UINT32_C(0xd503419e), /* Rt is not 31 */
        };
        for (index = 0u;
             index < sizeof(invalid_words) / sizeof(invalid_words[0]);
             ++index) {
            uint8_t field = 0u;
            uint8_t immediate = 0u;
            if (arm_pstate_msr_decode_word(
                    invalid_words[index], &field, &immediate)) {
                fprintf(stderr, "PSTATE invalid case %zu admitted\n", index);
                return 1;
            }
        }
    }
    return 0;
}
