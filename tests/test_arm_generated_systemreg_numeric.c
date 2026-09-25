#include <stdio.h>
#include <string.h>

#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct sysreg_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} sysreg_case;

/* LLVM-assembled with +d128 from tests/data/arm_systemreg_numeric.s. */
static const sysreg_case cases[] = {
    { UINT32_C(0xd5181000), 4504u, CDISASM_ARM_NAME_MSR,
      "msr s3_0_c1_c0_0, x0" },
    { UINT32_C(0xd5381001), 4505u, CDISASM_ARM_NAME_MRS,
      "mrs x1, s3_0_c1_c0_0" },
    { UINT32_C(0xd5581002), 4507u, CDISASM_ARM_NAME_MSRR,
      "msrr s3_0_c1_c0_0, x2, x3" },
    { UINT32_C(0xd5781004), 4508u, CDISASM_ARM_NAME_MRRS,
      "mrrs x4, x5, s3_0_c1_c0_0" },
    { UINT32_C(0xd558101e), 4507u, CDISASM_ARM_NAME_MSRR,
      "msrr s3_0_c1_c0_0, x30, xzr" },
    { UINT32_C(0xd578101e), 4508u, CDISASM_ARM_NAME_MRRS,
      "mrrs x30, xzr, s3_0_c1_c0_0" },
    { UINT32_C(0xd5581003), 4507u, CDISASM_ARM_NAME_MSRR, NULL },
};

int main(void)
{
    size_t i;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
        size_t length;

        instruction.raw_instruction = cases[i].word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A64;
        instruction.form_id = cases[i].form_id;
        instruction.name_id = cases[i].name_id;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if ((cases[i].expected == NULL && length != 0u)
            || (cases[i].expected != NULL
                && (length == 0u
                    || strcmp(buffer, cases[i].expected) != 0))) {
            fprintf(stderr, "system register case %zu: got '%s', expected '%s'\n",
                i, buffer,
                cases[i].expected == NULL ? "<rejected>" : cases[i].expected);
            return 1;
        }
    }
    puts("ARM generated numeric system-register tests passed");
    return 0;
}
