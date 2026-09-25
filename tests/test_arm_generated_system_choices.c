#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct choice_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_isa_id isa_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} choice_case;

/* Words and spellings are independently witnessed by LLVM's Arm disassembler.
 * Thumb-2 words are listed in architectural order, then halfword-swapped for
 * the library's raw_instruction byte-order convention. */
static const choice_case cases[] = {
    { UINT32_C(0xe10f0000), 94u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_MRS, "mrs r0, apsr" },
    { UINT32_C(0xe14f0000), 94u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_MRS, "mrs r0, spsr" },
    { UINT32_C(0xf3ef8000), 1851u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_MRS, "mrs r0, apsr" },
    { UINT32_C(0xf3ff8000), 1851u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_MRS, "mrs r0, spsr" },
    { UINT32_C(0xeee00a10), 533u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_VMSR, "vmsr fpsid, r0" },
    { UINT32_C(0xeee10a10), 533u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_VMSR, "vmsr fpscr, r0" },
    { UINT32_C(0xeee80a10), 533u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_VMSR, "vmsr fpexc, r0" },
    { UINT32_C(0xeef00a10), 534u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_VMRS, "vmrs r0, fpsid" },
    { UINT32_C(0xeef50a10), 534u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_VMRS, "vmrs r0, mvfr2" },
    { UINT32_C(0xeef60a10), 534u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_VMRS, "vmrs r0, mvfr1" },
    { UINT32_C(0xeef70a10), 534u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_VMRS, "vmrs r0, mvfr0" },
    { UINT32_C(0xeef80a10), 534u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_VMRS, "vmrs r0, fpexc" },
    { UINT32_C(0xeee11a10), 1518u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_VMSR, "vmsr fpscr, r1" },
    { UINT32_C(0xeef12a10), 1519u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_VMRS, "vmrs r2, fpscr" },
    { UINT32_C(0xf2890a11), 940u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_VSHLL, "vshll.s8 q0, d1, #1" },
    { UINT32_C(0xf39f6a14), 940u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_VSHLL, "vshll.u16 q3, d4, #15" },
    { UINT32_C(0xef890a11), 1467u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_VSHLL, "vshll.s8 q0, d1, #1" },
    { UINT32_C(0xff9f6a14), 1467u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_VSHLL, "vshll.u16 q3, d4, #15" },
    { UINT32_C(0xeef20a10), 534u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_VMRS, NULL },
    { UINT32_C(0xeee50a10), 533u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_VMSR, NULL },
    { UINT32_C(0xf2810a11), 940u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_VSHLL, NULL },
    { UINT32_C(0xf57ff04f), 952u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_DSB, "dsb sy" },
    { UINT32_C(0xf57ff04e), 952u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_DSB, "dsb st" },
    { UINT32_C(0xf57ff04b), 952u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_DSB, "dsb ish" },
    { UINT32_C(0xf57ff05f), 955u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_DMB, "dmb sy" },
    { UINT32_C(0xf57ff051), 955u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_DMB, "dmb oshld" },
    { UINT32_C(0xf3bf8f4f), 1842u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_DSB, "dsb sy" },
    { UINT32_C(0xf3bf8f4b), 1842u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_DSB, "dsb ish" },
    { UINT32_C(0xf3bf8f5f), 1845u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_DMB, "dmb sy" },
    { UINT32_C(0xf3bf8f51), 1845u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_DMB, "dmb oshld" },
    { UINT32_C(0xf57ff04c), 952u, CDISASM_ARM_ISA_A32,
      CDISASM_ARM_NAME_DSB, NULL },
    { UINT32_C(0xf3bf8f58), 1845u, CDISASM_ARM_ISA_T32,
      CDISASM_ARM_NAME_DMB, NULL },
};

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const choice_case *entry = &cases[index];
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
        size_t length;

        instruction.raw_instruction = entry->isa_id == CDISASM_ARM_ISA_T32
            ? (entry->word << 16) | (entry->word >> 16)
            : entry->word;
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
            fprintf(stderr,
                "ARM system choice case %zu: got '%s', expected '%s'\n",
                index, buffer,
                entry->expected == NULL ? "<rejected>" : entry->expected);
            return 1;
        }
    }
    puts("ARM generated system choice tests passed");
    return 0;
}
