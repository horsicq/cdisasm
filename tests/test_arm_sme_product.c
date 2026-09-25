#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

typedef struct product_case {
    uint32_t fixed;
    uint32_t mask;
    uint16_t form;
    cdisasm_arm_name_id name;
    uint8_t floating_point;
} product_case;

static const product_case cases[] = {
    { UINT32_C(0x80800008), UINT32_C(0xffe0001c), 3792u,
      CDISASM_ARM_NAME_BMOPA, 1u },
    { UINT32_C(0x81800010), UINT32_C(0xffe0001c), 3788u,
      CDISASM_ARM_NAME_BFMOPS, 1u },
    { UINT32_C(0xa0800000), UINT32_C(0xffe0001c), 3799u,
      CDISASM_ARM_NAME_SMOPA, 0u },
    { UINT32_C(0xa0800008), UINT32_C(0xffe0001c), 3807u,
      CDISASM_ARM_NAME_SMOPA, 0u },
    { UINT32_C(0xa0a00010), UINT32_C(0xffe0001c), 3804u,
      CDISASM_ARM_NAME_SUMOPS, 0u },
    { UINT32_C(0xa1800018), UINT32_C(0xffe0001c), 3810u,
      CDISASM_ARM_NAME_UMOPS, 0u },
    { UINT32_C(0xa1c00000), UINT32_C(0xffe00018), 3815u,
      CDISASM_ARM_NAME_USMOPA, 0u },
    { UINT32_C(0xa1e00010), UINT32_C(0xffe00018), 3820u,
      CDISASM_ARM_NAME_UMOPS, 0u }
};

static int failures;
#define CHECK(expr) do { \
    if (!(expr)) { \
        if (failures < 20) fprintf(stderr, "%d: %s\n", __LINE__, #expr); \
        ++failures; \
    } \
} while (0)

static uint32_t decode(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = {
        (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24)
    };
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), 0u, 0u, instruction);
}

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;
        uint32_t word = cases[index].fixed
            | UINT32_C(1) /* ZA tile */
            | (UINT32_C(2) << 5) /* Zn */
            | (UINT32_C(3) << 10) /* Pn */
            | (UINT32_C(4) << 13) /* Pm */
            | (UINT32_C(6) << 16); /* Zm */
#if USE_EXTRA_OPCODES
        CHECK(decode(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
        CHECK(instruction.name_id == cases[index].name);
        CHECK(instruction.form_id == cases[index].form);
        CHECK(instruction.operand_count == 4u);
        CHECK((instruction.instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_SME
                | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED))
            == (CDISASM_ARM_INSTRUCTION_FLAG_SME
                | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
        CHECK(((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) != 0u)
            == (cases[index].floating_point != 0u));
#if USE_DISASM_FORMAT
        {
            char text[128];
            CHECK(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
                != 0u);
        }
#endif
        CHECK(decode(word, CDISASM_ARM_CPU_CORTEX_A53, &instruction) == 0u);
        CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CHECK(decode(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        CHECK(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

    if (failures != 0) {
        fprintf(stderr, "%d SME product failures\n", failures);
        return 1;
    }
    puts("ARM SME product tests passed");
    return 0;
}
