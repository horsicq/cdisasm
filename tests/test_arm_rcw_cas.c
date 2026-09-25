#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

typedef struct rcw_cas_case {
    uint32_t base;
    cdisasm_arm_name_id name;
    cdisasm_arm_form_id form;
    uint32_t order_flags;
    const char *text;
} rcw_cas_case;

static const rcw_cas_case cases[] = {
    { UINT32_C(0x19200800), CDISASM_ARM_NAME_RCWCAS, 4725u, 0u,
      "rcwcas x1, x3, [x2]" },
    { UINT32_C(0x19600800), CDISASM_ARM_NAME_RCWCASL, 4726u,
      CDISASM_ARM_INSTRUCTION_FLAG_RELEASE,
      "rcwcasl x1, x3, [x2]" },
    { UINT32_C(0x19a00800), CDISASM_ARM_NAME_RCWCASA, 4727u,
      CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE,
      "rcwcasa x1, x3, [x2]" },
    { UINT32_C(0x19e00800), CDISASM_ARM_NAME_RCWCASAL, 4728u,
      CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
        | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE,
      "rcwcasal x1, x3, [x2]" },
    { UINT32_C(0x59200800), CDISASM_ARM_NAME_RCWSCAS, 4729u, 0u,
      "rcwscas x1, x3, [x2]" },
    { UINT32_C(0x59600800), CDISASM_ARM_NAME_RCWSCASL, 4730u,
      CDISASM_ARM_INSTRUCTION_FLAG_RELEASE,
      "rcwscasl x1, x3, [x2]" },
    { UINT32_C(0x59a00800), CDISASM_ARM_NAME_RCWSCASA, 4731u,
      CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE,
      "rcwscasa x1, x3, [x2]" },
    { UINT32_C(0x59e00800), CDISASM_ARM_NAME_RCWSCASAL, 4732u,
      CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
        | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE,
      "rcwscasal x1, x3, [x2]" }
};

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = {
        (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24)
    };

    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x1000), NULL, instruction);
}

int main(void)
{
    size_t index;
    int failures = 0;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;
        uint32_t word = cases[index].base
            | (UINT32_C(1) << 16) | (UINT32_C(2) << 5) | UINT32_C(3);
        uint32_t length = decode_word(
            word, CDISASM_ARM_CPU_ANY, &instruction);

#if USE_EXTRA_OPCODES
        uint32_t atomic_flags = CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
            | cases[index].order_flags;

        if (length != 4u || instruction.name_id != cases[index].name
            || instruction.form_id != cases[index].form
            || instruction.operand_count != 3u
            || (instruction.instruction_flags
                & (CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                    | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                    | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE))
                != atomic_flags
            || instruction.operand[0].reg != CDISASM_ARM_REG_X1
            || instruction.operand[0].access
                != CDISASM_OPERAND_ACCESS_READ_WRITE
            || instruction.operand[1].reg != CDISASM_ARM_REG_X3
            || instruction.operand[1].access
                != CDISASM_OPERAND_ACCESS_READ
            || instruction.operand[2].base_reg != CDISASM_ARM_REG_X2
            || instruction.operand[2].size != 8u
            || instruction.operand[2].access
                != CDISASM_OPERAND_ACCESS_READ_WRITE) {
            fprintf(stderr, "RCW CAS case %zu decode failed: len=%u status=%u name=%u form=%u\n",
                index, (unsigned)length,
                (unsigned)instruction.last_error_id,
                (unsigned)instruction.name_id,
                (unsigned)instruction.form_id);
            ++failures;
        }
#if USE_DISASM_FORMAT
        if (length == 4u) {
            char buffer[80];

            if (cdisasm_arm_format(
                    &instruction, 0u, buffer, sizeof(buffer)) == 0u
                || strcmp(buffer, cases[index].text) != 0) {
                fprintf(stderr, "RCW CAS case %zu format failed: %s\n",
                    index, buffer);
                ++failures;
            }
        }
#endif
#else
        if (length != 0u) {
            fprintf(stderr, "RCW CAS extra-opcode gate failed: %zu\n", index);
            ++failures;
        }
#endif
    }

#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction instruction;
        uint32_t word = cases[0].base
            | (UINT32_C(1) << 16) | (UINT32_C(2) << 5) | UINT32_C(3);

        if (decode_word(word, CDISASM_ARM_CPU_CORTEX_A53,
                &instruction) != 0u) {
            fputs("RCW CAS CPU gate failed\n", stderr);
            ++failures;
        }
    }
#endif
    if (failures != 0) {
        return 1;
    }
    puts("ARM FEAT_THE RCW CAS tests passed");
    return 0;
}
