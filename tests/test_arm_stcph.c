#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "%d: %s\n", __LINE__, #expr); \
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
    cdisasm_arm_instruction instruction;
#if USE_EXTRA_OPCODES
    CHECK(decode(UINT32_C(0xd503269f), CDISASM_ARM_CPU_ANY,
        &instruction) == 4u);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_STCPH);
    CHECK(instruction.form_id == UINT16_C(4489));
    CHECK(instruction.operand_count == 0u);
#if USE_DISASM_FORMAT
    {
        char formatted[32];
        CHECK(cdisasm_arm_format(&instruction, 0u,
            formatted, sizeof(formatted)) != 0u);
        CHECK(strcmp(formatted, "stcph") == 0);
    }
#endif
    CHECK(decode(UINT32_C(0xd503269f), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    CHECK(decode(UINT32_C(0xd503269f), CDISASM_ARM_CPU_ANY,
        &instruction) == 0u);
    CHECK(instruction.last_error_id ==
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    if (failures != 0) return 1;
    puts("ARM STCPH tests passed");
    return 0;
}
