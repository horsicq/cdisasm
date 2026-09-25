#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 24) fprintf(stderr, \
    "%s:%d: expectation failed: %s\n", __FILE__, __LINE__, #c); \
    ++failures; } } while (0)

struct operation {
    uint32_t base;
    cdisasm_arm_name_id name;
    cdisasm_arm_form_id form;
};

static const struct operation operations[7] = {
    { UINT32_C(0x5e20dc00), CDISASM_ARM_NAME_FMULX, 5833 },
    { UINT32_C(0x5e20e400), CDISASM_ARM_NAME_FCMEQ, 5834 },
    { UINT32_C(0x7e20e400), CDISASM_ARM_NAME_FCMGE, 5848 },
    { UINT32_C(0x7e20ec00), CDISASM_ARM_NAME_FACGE, 5849 },
    { UINT32_C(0x7ea0d400), CDISASM_ARM_NAME_FABD, 5850 },
    { UINT32_C(0x7ea0e400), CDISASM_ARM_NAME_FCMGT, 5851 },
    { UINT32_C(0x7ea0ec00), CDISASM_ARM_NAME_FACGT, 5852 }
};

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, bytes, 4u,
        UINT64_C(0x5e20dc00), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static void test_complete_domain(void)
{
    unsigned operation, precision, rm, rn, rd;

    for (operation = 0u; operation < 7u; ++operation) {
        for (precision = 0u; precision < 2u; ++precision) {
            uint32_t precision_bit = precision != 0u
                ? UINT32_C(0x00400000) : 0u;
#if USE_EXTRA_OPCODES
            uint8_t size = precision != 0u ? 8u : 4u;
            cdisasm_arm_reg_id first_reg = precision != 0u
                ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_S0;
#endif
            for (rm = 0u; rm < 32u; ++rm) {
                for (rn = 0u; rn < 32u; ++rn) {
                    for (rd = 0u; rd < 32u; ++rd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = operations[operation].base
                            | precision_bit | (rm << 16) | (rn << 5) | rd;
                        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                            &instruction) == 4u);
                        EXPECT(instruction.name_id == operations[operation].name);
                        EXPECT(instruction.form_id == operations[operation].form);
                        EXPECT(instruction.instruction_flags
                            == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
                        EXPECT(instruction.operand_count == 3u);
                        EXPECT(instruction.operand[0].type
                            == CDISASM_OPERAND_REGISTER);
                        EXPECT(instruction.operand[0].reg
                            == (cdisasm_arm_reg_id)(first_reg + rd));
                        EXPECT(instruction.operand[0].size == size);
                        EXPECT(instruction.operand[0].access
                            == CDISASM_OPERAND_ACCESS_WRITE);
                        EXPECT(instruction.operand[1].reg
                            == (cdisasm_arm_reg_id)(first_reg + rn));
                        EXPECT(instruction.operand[1].size == size);
                        EXPECT(instruction.operand[1].access
                            == CDISASM_OPERAND_ACCESS_READ);
                        EXPECT(instruction.operand[2].reg
                            == (cdisasm_arm_reg_id)(first_reg + rm));
                        EXPECT(instruction.operand[2].size == size);
                        EXPECT(instruction.operand[2].access
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
}

static void test_profile(void)
{
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(UINT32_C(0x5e22dc20), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 4u);
#else
    EXPECT(decode_word(UINT32_C(0x5e22dc20), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

int main(void)
{
    test_complete_domain();
    test_profile();
    if (failures != 0) return 1;
    puts("Advanced SIMD scalar S/D floating three-same tests passed");
    return 0;
}
