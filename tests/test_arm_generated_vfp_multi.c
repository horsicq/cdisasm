#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

/* The decoder's generated-form identity matching is tested separately. */
int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct vfp_multi_case {
    uint32_t architecture_word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    uint8_t isa_id;
    const char *expected;
} vfp_multi_case;

static const vfp_multi_case cases[] = {
    { UINT32_C(0xed200a01), 499u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_A32, "vstmdb.32 r0!, {s0}" },
    { UINT32_C(0xec800a02), 500u, CDISASM_ARM_NAME_VSTM,
      CDISASM_ARM_ISA_A32, "vstm.32 r0, {s0, s1}" },
    { UINT32_C(0xed200b02), 501u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_A32, "vstmdb.64 r0!, {d0}" },
    { UINT32_C(0xec800b04), 502u, CDISASM_ARM_NAME_VSTM,
      CDISASM_ARM_ISA_A32, "vstm.64 r0, {d0, d1}" },
    { UINT32_C(0xed300a01), 505u, CDISASM_ARM_NAME_VLDMDB,
      CDISASM_ARM_ISA_A32, "vldmdb.32 r0!, {s0}" },
    { UINT32_C(0xec900a02), 506u, CDISASM_ARM_NAME_VLDM,
      CDISASM_ARM_ISA_A32, "vldm.32 r0, {s0, s1}" },
    { UINT32_C(0xed300b02), 507u, CDISASM_ARM_NAME_VLDMDB,
      CDISASM_ARM_ISA_A32, "vldmdb.64 r0!, {d0}" },
    { UINT32_C(0xec900b04), 508u, CDISASM_ARM_NAME_VLDM,
      CDISASM_ARM_ISA_A32, "vldm.64 r0, {d0, d1}" },
    { UINT32_C(0xed200a01), 1484u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_T32, "vstmdb.32 r0!, {s0}" },
    { UINT32_C(0xec800a02), 1485u, CDISASM_ARM_NAME_VSTM,
      CDISASM_ARM_ISA_T32, "vstm.32 r0, {s0, s1}" },
    { UINT32_C(0xed200b02), 1486u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_T32, "vstmdb.64 r0!, {d0}" },
    { UINT32_C(0xec800b04), 1487u, CDISASM_ARM_NAME_VSTM,
      CDISASM_ARM_ISA_T32, "vstm.64 r0, {d0, d1}" },
    { UINT32_C(0xed300a01), 1490u, CDISASM_ARM_NAME_VLDMDB,
      CDISASM_ARM_ISA_T32, "vldmdb.32 r0!, {s0}" },
    { UINT32_C(0xec900a02), 1491u, CDISASM_ARM_NAME_VLDM,
      CDISASM_ARM_ISA_T32, "vldm.32 r0, {s0, s1}" },
    { UINT32_C(0xed300b02), 1492u, CDISASM_ARM_NAME_VLDMDB,
      CDISASM_ARM_ISA_T32, "vldmdb.64 r0!, {d0}" },
    { UINT32_C(0xec900b04), 1493u, CDISASM_ARM_NAME_VLDM,
      CDISASM_ARM_ISA_T32, "vldm.64 r0, {d0, d1}" },
    { UINT32_C(0xed2d0a01), 499u, CDISASM_ARM_NAME_VPUSH,
      CDISASM_ARM_ISA_A32, "vpush.32 {s0}" },
    { UINT32_C(0xed2d0b02), 501u, CDISASM_ARM_NAME_VPUSH,
      CDISASM_ARM_ISA_A32, "vpush.64 {d0}" },
    { UINT32_C(0xecbd0a01), 506u, CDISASM_ARM_NAME_VPOP,
      CDISASM_ARM_ISA_A32, "vpop.32 {s0}" },
    { UINT32_C(0xecbd0b02), 508u, CDISASM_ARM_NAME_VPOP,
      CDISASM_ARM_ISA_A32, "vpop.64 {d0}" },
    /* S-register start = Vd:D, so D changes S0 to S1. */
    { UINT32_C(0xed600a01), 499u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_A32, "vstmdb.32 r0!, {s1}" },
    /* D-register start = D:Vd; extended banks may address D31. */
    { UINT32_C(0xed60fb02), 501u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_A32, "vstmdb.64 r0!, {d31}" },
    { UINT32_C(0xed200a20), 499u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_A32,
      "vstmdb.32 r0!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31}" },
    { UINT32_C(0xed200b20), 1486u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_T32,
      "vstmdb.64 r0!, {d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15}" },
    { UINT32_C(0xed600b20), 501u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_A32,
      "vstmdb.64 r0!, {d16, d17, d18, d19, d20, d21, d22, d23, d24, d25, d26, d27, d28, d29, d30, d31}" },
    { UINT32_C(0xec8f0a01), 500u, CDISASM_ARM_NAME_VSTM,
      CDISASM_ARM_ISA_A32, "vstm.32 r15, {s0}" },
    { UINT32_C(0xed200a00), 499u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_A32, NULL },
    { UINT32_C(0xed200b00), 501u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_A32, NULL },
    { UINT32_C(0xed200b03), 501u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_A32, NULL },
    { UINT32_C(0xed200b22), 501u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_A32, NULL },
    { UINT32_C(0xed60fa02), 499u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_A32, NULL },
    { UINT32_C(0xed60fb04), 501u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_A32, NULL },
    { UINT32_C(0xed200a00), 1484u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_T32, NULL },
    { UINT32_C(0xed200b03), 1486u, CDISASM_ARM_NAME_VSTMDB,
      CDISASM_ARM_ISA_T32, NULL },
    { UINT32_C(0xec8f0a01), 1485u, CDISASM_ARM_NAME_VSTM,
      CDISASM_ARM_ISA_T32, NULL }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const vfp_multi_case *entry = &cases[index];
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
            fprintf(stderr, "VFP multiple case %zu: got '%s', expected '%s'\n",
                index, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            failures += 1;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated VFP multiple tests passed");
    return 0;
}
