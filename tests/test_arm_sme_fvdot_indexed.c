#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

typedef struct fvdot_case {
    uint32_t word;
    cdisasm_arm_name_id name;
    uint16_t form;
    const char *text;
} fvdot_case;

static const fvdot_case cases[] = {
    { UINT32_C(0xc1500008) | (4u << 16),
      CDISASM_ARM_NAME_FVDOT, 6500u,
      "fvdot za.s[w8, 0, vgx2], {z0.h, z1.h}, z4.h[0]" },
    { UINT32_C(0xc1500018) | (6u << 16),
      CDISASM_ARM_NAME_BFVDOT, 6501u,
      "bfvdot za.s[w8, 0, vgx2], {z0.h, z1.h}, z6.h[0]" },
    { UINT32_C(0xc1d00800) | (3u << 16),
      CDISASM_ARM_NAME_FVDOTB, 6502u,
      "fvdotb za.s[w8, 0, vgx4], {z0.b, z1.b}, z3.b[2]" },
    { UINT32_C(0xc1d00810) | (3u << 16),
      CDISASM_ARM_NAME_FVDOTT, 6503u,
      "fvdott za.s[w8, 0, vgx4], {z0.b, z1.b}, z3.b[2]" },
    { UINT32_C(0xc1d01020) | (3u << 16),
      CDISASM_ARM_NAME_FVDOT, 6504u,
      "fvdot za.h[w8, 0, vgx2], {z0.b, z1.b}, z3.b[0]" }
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
        const fvdot_case *test = &cases[index];
#if USE_EXTRA_OPCODES
        CHECK(decode(test->word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
        CHECK(instruction.name_id == test->name);
        CHECK(instruction.form_id == test->form);
        CHECK(instruction.operand_count == 3u);
        CHECK((instruction.instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_SME
                | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT))
            == (CDISASM_ARM_INSTRUCTION_FLAG_SME
                | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
#if USE_DISASM_FORMAT
        {
            char text[160];
            CHECK(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
                == strlen(test->text));
            CHECK(strcmp(text, test->text) == 0);
        }
#endif
        CHECK(decode(test->word, CDISASM_ARM_CPU_CORTEX_A53,
            &instruction) == 0u);
        CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CHECK(decode(test->word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        CHECK(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

    if (failures != 0) {
        fprintf(stderr, "%d SME FVDOT failures\n", failures);
        return 1;
    }
    puts("ARM SME FVDOT indexed tests passed");
    return 0;
}
