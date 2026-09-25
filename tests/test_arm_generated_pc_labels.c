#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

/* Isolate the generated recipe renderer.  Identity matching has its own
 * decoder tests; these cases exercise the address transforms and spelling. */
int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct pc_label_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    uint64_t address;
    const char *expected;
} pc_label_case;

static const pc_label_case cases[] = {
    { UINT32_C(0x10000020), 4392u, CDISASM_ARM_NAME_ADR,
      UINT64_C(0x1000), "adr x0, 0x1004" },
    { UINT32_C(0x90000001), 4393u, CDISASM_ARM_NAME_ADRP,
      UINT64_C(0x1234), "adrp x1, 0x1000" },
    { UINT32_C(0x18000022), 4917u, CDISASM_ARM_NAME_LDR,
      UINT64_C(0x1000), "ldr w2, 0x1004" },
    { UINT32_C(0x1c000025), 4918u, CDISASM_ARM_NAME_LDR,
      UINT64_C(0x1000), "ldr s5, 0x1004" },
    { UINT32_C(0x58000023), 4919u, CDISASM_ARM_NAME_LDR,
      UINT64_C(0x1000), "ldr x3, 0x1004" },
    { UINT32_C(0x5c000026), 4920u, CDISASM_ARM_NAME_LDR,
      UINT64_C(0x1000), "ldr d6, 0x1004" },
    { UINT32_C(0x98000024), 4921u, CDISASM_ARM_NAME_LDRSW,
      UINT64_C(0x1000), "ldrsw x4, 0x1004" },
    { UINT32_C(0x9c000027), 4922u, CDISASM_ARM_NAME_LDR,
      UINT64_C(0x1000), "ldr q7, 0x1004" },
    { UINT32_C(0x18ffffc2), 4917u, CDISASM_ARM_NAME_LDR,
      UINT64_C(0x1000), "ldr w2, 0xff8" },
    /* FEAT_PAuth_LR encodes an unsigned backwards offset, imm16 * 4. */
    { UINT32_C(0xf380001f), 4388u, CDISASM_ARM_NAME_AUTIASPPC,
      UINT64_C(0x10000000), "autiasppc 0x10000000" },
    { UINT32_C(0xf3a0009f), 4389u, CDISASM_ARM_NAME_AUTIBSPPC,
      UINT64_C(0x10000000), "autibsppc 0xffffff0" },
    { UINT32_C(0x5500001f), 4434u, CDISASM_ARM_NAME_RETAASPPC,
      UINT64_C(0x10000000), "retaasppc 0x10000000" },
    { UINT32_C(0x5520009f), 4435u, CDISASM_ARM_NAME_RETABSPPC,
      UINT64_C(0x10000000), "retabsppc 0xffffff0" },
    { UINT32_C(0xf39fffff), 4388u, CDISASM_ARM_NAME_AUTIASPPC,
      UINT64_C(0x10000000), "autiasppc 0xffc0004" },
    { UINT32_C(0x553fffff), 4435u, CDISASM_ARM_NAME_RETABSPPC,
      UINT64_C(0x10000000), "retabsppc 0xffc0004" },
    { UINT32_C(0xf380003f), 4388u, CDISASM_ARM_NAME_AUTIASPPC,
      UINT64_C(0), "autiasppc 0xfffffffffffffffc" }
};

typedef struct fp_imm_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} fp_imm_case;

static const fp_imm_case fp_cases[] = {
    { UINT32_C(0x2579ce00), 2632u, CDISASM_ARM_NAME_FDUP,
      "fdup z0.h, #1.0" },
    { UINT32_C(0x2579ce00), 2632u, CDISASM_ARM_NAME_FMOV,
      "fmov z0.h, #1.0" },
    { UINT32_C(0x25b9dc01), 2632u, CDISASM_ARM_NAME_FDUP,
      "fdup z1.s, #-0.5" },
    { UINT32_C(0x0550ce02), 2430u, CDISASM_ARM_NAME_FCPY,
      "fcpy z2.h, p0/m, #1.0" },
    { UINT32_C(0x0550ce02), 2430u, CDISASM_ARM_NAME_FMOV,
      "fmov z2.h, p0/m, #1.0" }
};

typedef struct vshll_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_isa_id isa_id;
    const char *expected;
} vshll_case;

static const vshll_case vshll_cases[] = {
    { UINT32_C(0xf3b20301), 830u, CDISASM_ARM_ISA_A32,
      "vshll.i8 q0, d1, #8" },
    { UINT32_C(0x0301ffb2), 1357u, CDISASM_ARM_ISA_T32,
      "vshll.i8 q0, d1, #8" }
};

typedef struct vext_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_isa_id isa_id;
    const char *expected;
} vext_case;

static const vext_case vext_cases[] = {
    { UINT32_C(0xf2b10302), 775u, CDISASM_ARM_ISA_A32,
      "vext.8 d0, d1, d2, #3" },
    { UINT32_C(0xf2b20344), 776u, CDISASM_ARM_ISA_A32,
      "vext.8 q0, q1, q2, #3" },
    { UINT32_C(0x0302efb1), 1302u, CDISASM_ARM_ISA_T32,
      "vext.8 d0, d1, d2, #3" },
    { UINT32_C(0x0344efb2), 1303u, CDISASM_ARM_ISA_T32,
      "vext.8 q0, q1, q2, #3" }
};

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction = {0};
        char buffer[96] = {0};
        size_t length;

        instruction.address = cases[index].address;
        instruction.raw_instruction = cases[index].word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A64;
        instruction.form_id = cases[index].form_id;
        instruction.name_id = cases[index].name_id;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, cases[index].expected) != 0) {
            fprintf(stderr, "PC label case %zu: got '%s', expected '%s'\n",
                index, buffer, cases[index].expected);
            ++failures;
        }
    }
    for (index = 0u; index < sizeof(fp_cases) / sizeof(fp_cases[0]);
         ++index) {
        cdisasm_arm_instruction instruction = {0};
        char buffer[96] = {0};
        size_t length;

        instruction.address = UINT64_C(0x1000);
        instruction.raw_instruction = fp_cases[index].word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A64;
        instruction.form_id = fp_cases[index].form_id;
        instruction.name_id = fp_cases[index].name_id;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, fp_cases[index].expected) != 0) {
            fprintf(stderr, "FP imm case %zu: got '%s', expected '%s'\n",
                index, buffer, fp_cases[index].expected);
            ++failures;
        }
    }
    for (index = 0u;
         index < sizeof(vshll_cases) / sizeof(vshll_cases[0]);
         ++index) {
        cdisasm_arm_instruction instruction = {0};
        char buffer[96] = {0};
        size_t length;

        instruction.address = UINT64_C(0x1000);
        instruction.raw_instruction = vshll_cases[index].word;
        instruction.opcode_size = 4u;
        instruction.isa_id = vshll_cases[index].isa_id;
        instruction.form_id = vshll_cases[index].form_id;
        instruction.name_id = CDISASM_ARM_NAME_VSHLL;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, vshll_cases[index].expected) != 0) {
            fprintf(stderr, "VSHLL case %zu: got '%s', expected '%s'\n",
                index, buffer, vshll_cases[index].expected);
            ++failures;
        }
    }
    for (index = 0u;
         index < sizeof(vext_cases) / sizeof(vext_cases[0]);
         ++index) {
        cdisasm_arm_instruction instruction = {0};
        char buffer[96] = {0};
        size_t length;

        instruction.address = UINT64_C(0x1000);
        instruction.raw_instruction = vext_cases[index].word;
        instruction.opcode_size = 4u;
        instruction.isa_id = vext_cases[index].isa_id;
        instruction.form_id = vext_cases[index].form_id;
        instruction.name_id = CDISASM_ARM_NAME_VEXT;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (length == 0u || strcmp(buffer, vext_cases[index].expected) != 0) {
            fprintf(stderr, "VEXT case %zu: got '%s', expected '%s'\n",
                index, buffer, vext_cases[index].expected);
            ++failures;
        }
    }
    if (failures != 0) {
        return 1;
    }
    puts("ARM generated recipe-transform tests passed");
    return 0;
}
