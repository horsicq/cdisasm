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
        UINT64_C(0x0ea0f800), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static void test_complete_domain(void)
{
    static const struct operation {
        uint32_t base;
        cdisasm_arm_name_id name;
        cdisasm_arm_form_id form;
    } operations[3] = {
        { UINT32_C(0x0ea0f800), CDISASM_ARM_NAME_FABS, 6030 },
        { UINT32_C(0x2ea0f800), CDISASM_ARM_NAME_FNEG, 6065 },
        { UINT32_C(0x2ea1f800), CDISASM_ARM_NAME_FSQRT, 6071 }
    };
    unsigned operation, arrangement, rn, rd;

    for (operation = 0u; operation < 3u; ++operation) {
        for (arrangement = 0u; arrangement < 3u; ++arrangement) {
            uint32_t arrangement_bits = arrangement == 0u ? 0u
                : arrangement == 1u ? UINT32_C(0x40000000)
                                    : UINT32_C(0x40400000);
#if USE_EXTRA_OPCODES
            uint8_t total_size = arrangement == 0u ? 8u : 16u;
            uint8_t element_size = arrangement == 2u ? 8u : 4u;
#endif
            for (rn = 0u; rn < 32u; ++rn) {
                for (rd = 0u; rd < 32u; ++rd) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = operations[operation].base
                        | arrangement_bits | (rn << 5) | rd;
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
                    EXPECT(instruction.operand[0].type
                        == CDISASM_OPERAND_REGISTER);
                    EXPECT(instruction.operand[0].reg
                        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rd));
                    EXPECT(instruction.operand[0].size == total_size);
                    EXPECT(instruction.operand[0].extend_type == element_size);
                    EXPECT(instruction.operand[0].access
                        == CDISASM_OPERAND_ACCESS_WRITE);
                    EXPECT(instruction.operand[1].reg
                        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rn));
                    EXPECT(instruction.operand[1].size == total_size);
                    EXPECT(instruction.operand[1].extend_type == element_size);
                    EXPECT(instruction.operand[1].access
                        == CDISASM_OPERAND_ACCESS_READ);
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
    unsigned operation;
    static const uint32_t bases[3] = {
        UINT32_C(0x0ea0f800), UINT32_C(0x2ea0f800), UINT32_C(0x2ea1f800)
    };
    for (operation = 0u; operation < 3u; ++operation) {
        cdisasm_arm_instruction instruction, expected;
        memset(&instruction, 0xa5, sizeof(instruction));
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_INVALID_INSTRUCTION;
        EXPECT(decode_word(bases[operation] | UINT32_C(0x00400000),
            CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
    }
    {
        cdisasm_arm_instruction instruction;
        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(UINT32_C(0x4ea0f841), CDISASM_ARM_CPU_CORTEX_A53,
            &instruction) == 4u);
#else
        EXPECT(decode_word(UINT32_C(0x4ea0f841), CDISASM_ARM_CPU_CORTEX_A53,
            &instruction) == 0u);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

int main(void)
{
    test_complete_domain();
    test_reserved_and_profile();
    if (failures != 0) return 1;
    puts("Advanced SIMD S/D floating unary tests passed");
    return 0;
}
