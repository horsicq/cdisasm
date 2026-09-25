#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

/* Keep this focused on rendering; generated form matching has separate tests. */
int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct fpx_case {
    uint32_t architecture_word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    uint8_t isa_id;
    const char *expected;
} fpx_case;

static const fpx_case cases[] = {
    { UINT32_C(0xed200b03), 503u, CDISASM_ARM_NAME_FSTMDBX,
      CDISASM_ARM_ISA_A32, "fstmdbx r0!, {d0}" },
    { UINT32_C(0xec800b05), 504u, CDISASM_ARM_NAME_FSTMIAX,
      CDISASM_ARM_ISA_A32, "fstmiax r0, {d0, d1}" },
    { UINT32_C(0xed300b07), 509u, CDISASM_ARM_NAME_FLDMDBX,
      CDISASM_ARM_ISA_A32, "fldmdbx r0!, {d0, d1, d2}" },
    { UINT32_C(0xec900b09), 510u, CDISASM_ARM_NAME_FLDMIAX,
      CDISASM_ARM_ISA_A32, "fldmiax r0, {d0, d1, d2, d3}" },
    { UINT32_C(0xed200b03), 1488u, CDISASM_ARM_NAME_FSTMDBX,
      CDISASM_ARM_ISA_T32, "fstmdbx r0!, {d0}" },
    { UINT32_C(0xec800b05), 1489u, CDISASM_ARM_NAME_FSTMIAX,
      CDISASM_ARM_ISA_T32, "fstmiax r0, {d0, d1}" },
    { UINT32_C(0xed300b07), 1494u, CDISASM_ARM_NAME_FLDMDBX,
      CDISASM_ARM_ISA_T32, "fldmdbx r0!, {d0, d1, d2}" },
    { UINT32_C(0xec900b09), 1495u, CDISASM_ARM_NAME_FLDMIAX,
      CDISASM_ARM_ISA_T32, "fldmiax r0, {d0, d1, d2, d3}" },
    /* Highest predictable X-list length is 16 D registers. */
    { UINT32_C(0xed200b21), 503u, CDISASM_ARM_NAME_FSTMDBX,
      CDISASM_ARM_ISA_A32,
      "fstmdbx r0!, {d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15}" },
    { UINT32_C(0xec80fb03), 504u, CDISASM_ARM_NAME_FSTMIAX,
      CDISASM_ARM_ISA_A32, "fstmiax r0, {d15}" },
    { UINT32_C(0xec8f0b03), 504u, CDISASM_ARM_NAME_FSTMIAX,
      CDISASM_ARM_ISA_A32, "fstmiax r15, {d0}" },
    { UINT32_C(0xed200b21), 1488u, CDISASM_ARM_NAME_FSTMDBX,
      CDISASM_ARM_ISA_T32,
      "fstmdbx r0!, {d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15}" },
    { UINT32_C(0xed200b01), 503u, CDISASM_ARM_NAME_FSTMDBX,
      CDISASM_ARM_ISA_A32, NULL },
    { UINT32_C(0xed200b23), 503u, CDISASM_ARM_NAME_FSTMDBX,
      CDISASM_ARM_ISA_A32, NULL },
    { UINT32_C(0xed20fb05), 503u, CDISASM_ARM_NAME_FSTMDBX,
      CDISASM_ARM_ISA_A32, NULL },
    { UINT32_C(0xed600b03), 503u, CDISASM_ARM_NAME_FSTMDBX,
      CDISASM_ARM_ISA_A32, NULL },
    { UINT32_C(0xed200b01), 1488u, CDISASM_ARM_NAME_FSTMDBX,
      CDISASM_ARM_ISA_T32, NULL },
    { UINT32_C(0xed200b23), 1488u, CDISASM_ARM_NAME_FSTMDBX,
      CDISASM_ARM_ISA_T32, NULL },
    { UINT32_C(0xed20fb05), 1488u, CDISASM_ARM_NAME_FSTMDBX,
      CDISASM_ARM_ISA_T32, NULL },
    { UINT32_C(0xec8f0b03), 1489u, CDISASM_ARM_NAME_FSTMIAX,
      CDISASM_ARM_ISA_T32, NULL }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const fpx_case *entry = &cases[index];
        cdisasm_arm_instruction instruction = {0};
        char buffer[256] = {0};
        size_t length;

        instruction.raw_instruction =
            entry->isa_id == CDISASM_ARM_ISA_T32
            ? (entry->architecture_word << 16)
                | (entry->architecture_word >> 16)
            : entry->architecture_word;
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
            fprintf(stderr, "FPX case %zu: got '%s', expected '%s'\n",
                index, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            failures += 1;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated FPX D-list tests passed");
    return 0;
}
