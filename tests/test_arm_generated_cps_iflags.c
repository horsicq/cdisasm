#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

/* Test numeric flag projection independently from generated leaf matching. */
int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct cps_case {
    uint32_t architecture_word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    uint8_t isa_id;
    uint8_t opcode_size;
    const char *expected;
} cps_case;

static const cps_case cases[] = {
    { UINT32_C(0xf10c0100), 651u, CDISASM_ARM_NAME_CPSID,
      CDISASM_ARM_ISA_A32, 4u, "cpsid a" },
    { UINT32_C(0xf10c01c0), 651u, CDISASM_ARM_NAME_CPSID,
      CDISASM_ARM_ISA_A32, 4u, "cpsid aif" },
    { UINT32_C(0xf10e01d3), 652u, CDISASM_ARM_NAME_CPSID,
      CDISASM_ARM_ISA_A32, 4u, "cpsid aif, #19" },
    { UINT32_C(0xf10800c0), 653u, CDISASM_ARM_NAME_CPSIE,
      CDISASM_ARM_ISA_A32, 4u, "cpsie if" },
    { UINT32_C(0xf10a0113), 654u, CDISASM_ARM_NAME_CPSIE,
      CDISASM_ARM_ISA_A32, 4u, "cpsie a, #19" },
    { UINT32_C(0xb677), 1159u, CDISASM_ARM_NAME_CPSID,
      CDISASM_ARM_ISA_T32, 2u, "cpsid aif" },
    { UINT32_C(0xb662), 1160u, CDISASM_ARM_NAME_CPSIE,
      CDISASM_ARM_ISA_T32, 2u, "cpsie i" },
    { UINT32_C(0xf3af86e0), 1837u, CDISASM_ARM_NAME_CPSID,
      CDISASM_ARM_ISA_T32, 4u, "cpsid.w aif" },
    { UINT32_C(0xf3af87f3), 1838u, CDISASM_ARM_NAME_CPSID,
      CDISASM_ARM_ISA_T32, 4u, "cpsid aif, #19" },
    { UINT32_C(0xf3af8480), 1839u, CDISASM_ARM_NAME_CPSIE,
      CDISASM_ARM_ISA_T32, 4u, "cpsie.w a" },
    { UINT32_C(0xf3af8533), 1840u, CDISASM_ARM_NAME_CPSIE,
      CDISASM_ARM_ISA_T32, 4u, "cpsie f, #19" },
    { UINT32_C(0xf10c0000), 651u, CDISASM_ARM_NAME_CPSID,
      CDISASM_ARM_ISA_A32, 4u, NULL },
    { UINT32_C(0xb670), 1159u, CDISASM_ARM_NAME_CPSID,
      CDISASM_ARM_ISA_T32, 2u, NULL },
    { UINT32_C(0xf3af8600), 1837u, CDISASM_ARM_NAME_CPSID,
      CDISASM_ARM_ISA_T32, 4u, NULL }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cps_case *entry = &cases[index];
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
        size_t length;

        instruction.raw_instruction =
            entry->isa_id == CDISASM_ARM_ISA_T32
                && entry->opcode_size == 4u
            ? (entry->architecture_word << 16)
                | (entry->architecture_word >> 16)
            : entry->architecture_word;
        instruction.opcode_size = entry->opcode_size;
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
            fprintf(stderr, "CPS iflags case %zu: got '%s', expected '%s'\n",
                index, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            failures += 1;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated CPS iflags tests passed");
    return 0;
}
