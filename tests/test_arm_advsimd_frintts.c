#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 24) fprintf(stderr, \
    "%s:%d: expectation failed: %s\n", __FILE__, __LINE__, #c); \
    ++failures; } } while (0)

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, bytes, 4u,
        UINT64_C(0x602500), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

#if USE_EXTRA_OPCODES
static void check_vector(const cdisasm_arm_operand *operand, unsigned reg,
    uint8_t size, uint8_t element, cdisasm_operand_access access)
{
    EXPECT(operand->type == CDISASM_OPERAND_REGISTER);
    EXPECT(operand->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + reg));
    EXPECT(operand->size == size);
    EXPECT(operand->extend_type == (cdisasm_arm_extend_type)element);
    EXPECT(operand->scale == size / element);
    EXPECT(operand->access == access);
}
#endif

static void test_all_forms_and_registers(void)
{
    static const struct operation {
        uint32_t base;
        cdisasm_arm_name_id name;
        cdisasm_arm_form_id form;
    } operations[] = {
        { UINT32_C(0x0e21e800), CDISASM_ARM_NAME_FRINT32Z, 6025 },
        { UINT32_C(0x0e21f800), CDISASM_ARM_NAME_FRINT64Z, 6026 },
        { UINT32_C(0x2e21e800), CDISASM_ARM_NAME_FRINT32X, 6057 },
        { UINT32_C(0x2e21f800), CDISASM_ARM_NAME_FRINT64X, 6058 }
    };
    static const struct arrangement {
        uint32_t bits;
        uint8_t size;
        uint8_t element;
    } arrangements[] = {
        { 0u, 8u, 4u },
        { UINT32_C(0x40000000), 16u, 4u },
        { UINT32_C(0x40400000), 16u, 8u }
    };
    size_t operation, arrangement;

    for (operation = 0u; operation < 4u; ++operation) {
        for (arrangement = 0u; arrangement < 3u; ++arrangement) {
            unsigned rn, rd;
            for (rn = 0u; rn < 32u; ++rn) {
                for (rd = 0u; rd < 32u; ++rd) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = operations[operation].base
                        | arrangements[arrangement].bits
                        | ((uint32_t)rn << 5) | rd;
                    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                        &instruction) == 4u);
                    EXPECT(instruction.name_id == operations[operation].name);
                    EXPECT(instruction.form_id == operations[operation].form);
                    EXPECT(instruction.instruction_flags
                        == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
                    EXPECT(instruction.operand_count == 2u);
                    check_vector(&instruction.operand[0], rd,
                        arrangements[arrangement].size,
                        arrangements[arrangement].element,
                        CDISASM_OPERAND_ACCESS_WRITE);
                    check_vector(&instruction.operand[1], rn,
                        arrangements[arrangement].size,
                        arrangements[arrangement].element,
                        CDISASM_OPERAND_ACCESS_READ);
#else
                    {
                        cdisasm_arm_instruction expected;
                        memset(&expected, 0, sizeof(expected));
                        expected.last_error_id =
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
                        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                            &instruction) == 0u);
                        EXPECT(memcmp(&instruction, &expected,
                            sizeof(expected)) == 0);
                    }
#endif
                }
            }
        }
    }
}

static void test_reserved_and_profile(void)
{
    cdisasm_arm_instruction instruction, expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = CDISASM_STATUS_INVALID_INSTRUCTION;
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x0e61e883), CDISASM_ARM_CPU_ANY,
        &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
    memset(&expected, 0, sizeof(expected));
#if USE_EXTRA_OPCODES
    expected.last_error_id = CDISASM_STATUS_INVALID_INSTRUCTION;
#else
    expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x4e21e883),
        CDISASM_ARM_CPU_CORTEX_A53, &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
}

int main(void)
{
    test_all_forms_and_registers();
    test_reserved_and_profile();
    if (failures != 0) return 1;
    puts("Advanced SIMD FRINTTS tests passed");
    return 0;
}
