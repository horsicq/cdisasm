#include "../src/arm/arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct modified_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_isa_id isa_id;
    const char *expected;
} modified_case;

static const modified_case cases[] = {
    { UINT32_C(0xf2810012), 901u, CDISASM_ARM_NAME_VMOV,
      CDISASM_ARM_ISA_A32, "vmov.i32 d0, #0x12" },
    { UINT32_C(0xf2810612), 901u, CDISASM_ARM_NAME_VMOV,
      CDISASM_ARM_ISA_A32, "vmov.i32 d0, #0x12000000" },
    { UINT32_C(0xf2810a12), 909u, CDISASM_ARM_NAME_VMOV,
      CDISASM_ARM_ISA_A32, "vmov.i16 d0, #0x1200" },
    { UINT32_C(0xf2850e35), 921u, CDISASM_ARM_NAME_VMOV,
      CDISASM_ARM_ISA_A32, "vmov.i64 d0, #0xff00ff00ff00ff" },
    { UINT32_C(0xf3800e30), 921u, CDISASM_ARM_NAME_VMOV,
      CDISASM_ARM_ISA_A32, "vmov.i64 d0, #0xff00000000000000" },
    { UINT32_C(0x0a12ef81), 1436u, CDISASM_ARM_NAME_VMOV,
      CDISASM_ARM_ISA_T32, "vmov.i16 d0, #0x1200" },
    { UINT32_C(0x0e35ef85), 1448u, CDISASM_ARM_NAME_VMOV,
      CDISASM_ARM_ISA_T32, "vmov.i64 d0, #0xff00ff00ff00ff" },
    { UINT32_C(0xf2810112), 905u, CDISASM_ARM_NAME_VORR,
      CDISASM_ARM_ISA_A32, "vorr.i32 d0, #0x12" },
    { UINT32_C(0xf2810312), 905u, CDISASM_ARM_NAME_VORR,
      CDISASM_ARM_ISA_A32, "vorr.i32 d0, #0x1200" },
    { UINT32_C(0xf387011f), 905u, CDISASM_ARM_NAME_VORR,
      CDISASM_ARM_ISA_A32, "vorr.i32 d0, #0xff" },
    { UINT32_C(0xf2810912), 913u, CDISASM_ARM_NAME_VORR,
      CDISASM_ARM_ISA_A32, "vorr.i16 d0, #0x12" },
    { UINT32_C(0xf2810b12), 913u, CDISASM_ARM_NAME_VORR,
      CDISASM_ARM_ISA_A32, "vorr.i16 d0, #0x1200" },
    { UINT32_C(0xf2810c32), 919u, CDISASM_ARM_NAME_VMVN,
      CDISASM_ARM_ISA_A32, "vmvn.i32 d0, #0x12ff" },
    { UINT32_C(0xf2810d32), 919u, CDISASM_ARM_NAME_VMVN,
      CDISASM_ARM_ISA_A32, "vmvn.i32 d0, #0x12ffff" },
    { UINT32_C(0x0312ef81), 1432u, CDISASM_ARM_NAME_VORR,
      CDISASM_ARM_ISA_T32, "vorr.i32 d0, #0x1200" },
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
            fprintf(stderr, "modified immediate case %zu: got '%s', expected '%s'\n",
                index, length ? buffer : "<no exact recipe>",
                cases[index].expected);
            return 1;
        }
    }
    {
        cdisasm_arm_instruction invalid = {0};
        char buffer[128];

        invalid.raw_instruction = UINT32_C(0xf2810f12); /* cmode=15 */
        invalid.opcode_size = 4u;
        invalid.isa_id = CDISASM_ARM_ISA_A32;
        invalid.form_id = 919u;
        invalid.name_id = CDISASM_ARM_NAME_VMVN;
        invalid.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        if (cdisasm_arm_format_generated(
                &invalid, 0u, buffer, sizeof(buffer)) != 0u) {
            fputs("illegal modified-immediate cmode was accepted\n", stderr);
            return 1;
        }
    }
#endif
    puts("ARM generated modified-immediate tests passed");
    return 0;
}
