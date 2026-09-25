#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

/* Exercise numeric recipes independently of generated leaf matching. */
int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct vector_case {
    uint32_t architecture_word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    uint8_t isa_id;
    const char *expected;
} vector_case;

static const vector_case cases[] = {
    { UINT32_C(0xf3b00800), 861u, CDISASM_ARM_NAME_VTBL,
      CDISASM_ARM_ISA_A32, "vtbl.8 d0, {d0}, d0" },
    { UINT32_C(0xf3b00b00), 861u, CDISASM_ARM_NAME_VTBL,
      CDISASM_ARM_ISA_A32, "vtbl.8 d0, {d0, d1, d2, d3}, d0" },
    { UINT32_C(0xffb00800), 1388u, CDISASM_ARM_NAME_VTBL,
      CDISASM_ARM_ISA_T32, "vtbl.8 d0, {d0}, d0" },
    { UINT32_C(0xf400080f), 986u, CDISASM_ARM_NAME_VST2,
      CDISASM_ARM_ISA_A32, "vst2.8 {d0, d1}, [r0]" },
    { UINT32_C(0xf400090f), 986u, CDISASM_ARM_NAME_VST2,
      CDISASM_ARM_ISA_A32, "vst2.8 {d0, d2}, [r0]" },
    { UINT32_C(0xf900080f), 1931u, CDISASM_ARM_NAME_VST2,
      CDISASM_ARM_ISA_T32, "vst2.8 {d0, d1}, [r0]" },
    { UINT32_C(0xf400001f), 968u, CDISASM_ARM_NAME_VST4,
      CDISASM_ARM_ISA_A32,
      "vst4.8 {d0, d1, d2, d3}, [r0:64]" },
    { UINT32_C(0xf480050f), 1043u, CDISASM_ARM_NAME_VST2,
      CDISASM_ARM_ISA_A32, "vst2.16 {d0[0], d1[0]}, [r0]" },
    { UINT32_C(0xf480053f), 1043u, CDISASM_ARM_NAME_VST2,
      CDISASM_ARM_ISA_A32, "vst2.16 {d0[0], d2[0]}, [r0:32]" },
    { UINT32_C(0xf980050f), 1988u, CDISASM_ARM_NAME_VST2,
      CDISASM_ARM_ISA_T32, "vst2.16 {d0[0], d1[0]}, [r0]" },
    { UINT32_C(0xf480021f), 1034u, CDISASM_ARM_NAME_VST3,
      CDISASM_ARM_ISA_A32, "vst3.8 {d0[0], d2[0], d4[0]}, [r0]" },
    { UINT32_C(0xf4a00f0f), 1025u, CDISASM_ARM_NAME_VLD4,
      CDISASM_ARM_ISA_A32,
      "vld4.8 {d0[], d1[], d2[], d3[]}, [r0]" },
    { UINT32_C(0xf4a00fdf), 1025u, CDISASM_ARM_NAME_VLD4,
      CDISASM_ARM_ISA_A32,
      "vld4.32 {d0[], d1[], d2[], d3[]}, [r0:128]" },
    { UINT32_C(0xf4a00c0f), 1016u, CDISASM_ARM_NAME_VLD1,
      CDISASM_ARM_ISA_A32, "vld1.8 {d0[]}, [r0]" },
    { UINT32_C(0xf4a00c2f), 1016u, CDISASM_ARM_NAME_VLD1,
      CDISASM_ARM_ISA_A32, "vld1.8 {d0[], d1[]}, [r0]" },
    { UINT32_C(0xf4a00c5f), 1016u, CDISASM_ARM_NAME_VLD1,
      CDISASM_ARM_ISA_A32, "vld1.16 {d0[]}, [r0:16]" },
    { UINT32_C(0xf4a00d2f), 1019u, CDISASM_ARM_NAME_VLD2,
      CDISASM_ARM_ISA_A32, "vld2.8 {d0[], d2[]}, [r0]" },
    { UINT32_C(0xf9a00c2f), 1961u, CDISASM_ARM_NAME_VLD1,
      CDISASM_ARM_ISA_T32, "vld1.8 {d0[], d1[]}, [r0]" },
    { UINT32_C(0xf9a00f0f), 1970u, CDISASM_ARM_NAME_VLD4,
      CDISASM_ARM_ISA_T32,
      "vld4.8 {d0[], d1[], d2[], d3[]}, [r0]" }
};

static const vector_case invalid_cases[] = {
    /* Last D register cannot begin a two-register table list. */
    { UINT32_C(0xf3bf0980), 861u, CDISASM_ARM_NAME_VTBL,
      CDISASM_ARM_ISA_A32, NULL },
    /* A two-register VST2 list beginning at D31 overruns the file. */
    { UINT32_C(0xf440f80f), 986u, CDISASM_ARM_NAME_VST2,
      CDISASM_ARM_ISA_A32, NULL },
    /* VLD4 size=11 requires its mandatory 128-bit alignment bit. */
    { UINT32_C(0xf4a00fcf), 1025u, CDISASM_ARM_NAME_VLD4,
      CDISASM_ARM_ISA_A32, NULL },
    /* VLD1.8 all-lanes does not permit an alignment bit. */
    { UINT32_C(0xf4a00c1f), 1016u, CDISASM_ARM_NAME_VLD1,
      CDISASM_ARM_ISA_A32, NULL }
};

static int run_case(const vector_case *entry, size_t index)
{
    cdisasm_arm_instruction instruction = {0};
    char buffer[128] = {0};
    size_t length;

    instruction.raw_instruction = entry->isa_id == CDISASM_ARM_ISA_T32
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
        fprintf(stderr, "ARM vector case %zu: got '%s', expected '%s'\n",
            index, buffer,
            entry->expected == NULL ? "<rejected>" : entry->expected);
        return 1;
    }
    return 0;
}

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        failures += run_case(&cases[index], index);
    }
    for (index = 0u;
         index < sizeof(invalid_cases) / sizeof(invalid_cases[0]); ++index) {
        failures += run_case(&invalid_cases[index], index +
            sizeof(cases) / sizeof(cases[0]));
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated vector-list tests passed");
    return 0;
}
