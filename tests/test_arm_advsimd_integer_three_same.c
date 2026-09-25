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
    int halving;
};

static const struct operation operations[16] = {
    { UINT32_C(0x0e200400), CDISASM_ARM_NAME_SHADD, 6115, 1 },
    { UINT32_C(0x0e200c00), CDISASM_ARM_NAME_SQADD, 6116, 0 },
    { UINT32_C(0x0e201400), CDISASM_ARM_NAME_SRHADD, 6117, 1 },
    { UINT32_C(0x0e202400), CDISASM_ARM_NAME_SHSUB, 6118, 1 },
    { UINT32_C(0x0e202c00), CDISASM_ARM_NAME_SQSUB, 6119, 0 },
    { UINT32_C(0x0e204c00), CDISASM_ARM_NAME_SQSHL, 6123, 0 },
    { UINT32_C(0x0e205400), CDISASM_ARM_NAME_SRSHL, 6124, 0 },
    { UINT32_C(0x0e205c00), CDISASM_ARM_NAME_SQRSHL, 6125, 0 },
    { UINT32_C(0x2e200400), CDISASM_ARM_NAME_UHADD, 6157, 1 },
    { UINT32_C(0x2e200c00), CDISASM_ARM_NAME_UQADD, 6158, 0 },
    { UINT32_C(0x2e201400), CDISASM_ARM_NAME_URHADD, 6159, 1 },
    { UINT32_C(0x2e202400), CDISASM_ARM_NAME_UHSUB, 6160, 1 },
    { UINT32_C(0x2e202c00), CDISASM_ARM_NAME_UQSUB, 6161, 0 },
    { UINT32_C(0x2e204c00), CDISASM_ARM_NAME_UQSHL, 6165, 0 },
    { UINT32_C(0x2e205400), CDISASM_ARM_NAME_URSHL, 6166, 0 },
    { UINT32_C(0x2e205c00), CDISASM_ARM_NAME_UQRSHL, 6167, 0 }
};

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, bytes, 4u,
        UINT64_C(0x0e200400), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static void test_complete_legal_domain(void)
{
    unsigned operation, q, size, rm, rn, rd;

    for (operation = 0u; operation < 16u; ++operation) {
        for (q = 0u; q < 2u; ++q) {
            for (size = 0u; size < 4u; ++size) {
                if (size == 3u && (operations[operation].halving || q == 0u))
                    continue;
#if USE_EXTRA_OPCODES
                uint8_t total_size, element_size;
                total_size = q != 0u ? 16u : 8u;
                element_size = (uint8_t)(1u << size);
#endif
                for (rm = 0u; rm < 32u; ++rm) {
                    for (rn = 0u; rn < 32u; ++rn) {
                        for (rd = 0u; rd < 32u; ++rd) {
                            cdisasm_arm_instruction instruction;
                            uint32_t word = operations[operation].base
                                | (q << 30) | (size << 22)
                                | (rm << 16) | (rn << 5) | rd;
                            memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                            EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                                &instruction) == 4u);
                            EXPECT(instruction.name_id
                                == operations[operation].name);
                            EXPECT(instruction.form_id
                                == operations[operation].form);
                            EXPECT(instruction.instruction_flags
                                == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
                            EXPECT(instruction.operand_count == 3u);
                            EXPECT(instruction.operand[0].type
                                == CDISASM_OPERAND_REGISTER);
                            EXPECT(instruction.operand[0].reg
                                == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rd));
                            EXPECT(instruction.operand[0].size == total_size);
                            EXPECT(instruction.operand[0].extend_type
                                == element_size);
                            EXPECT(instruction.operand[0].access
                                == CDISASM_OPERAND_ACCESS_WRITE);
                            EXPECT(instruction.operand[1].reg
                                == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rn));
                            EXPECT(instruction.operand[1].size == total_size);
                            EXPECT(instruction.operand[1].extend_type
                                == element_size);
                            EXPECT(instruction.operand[1].access
                                == CDISASM_OPERAND_ACCESS_READ);
                            EXPECT(instruction.operand[2].reg
                                == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rm));
                            EXPECT(instruction.operand[2].size == total_size);
                            EXPECT(instruction.operand[2].extend_type
                                == element_size);
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
}

static void expect_invalid(uint32_t word)
{
    cdisasm_arm_instruction instruction, expected;
    memset(&instruction, 0xa5, sizeof(instruction));
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = CDISASM_STATUS_INVALID_INSTRUCTION;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
}

static void test_reserved_and_profile(void)
{
    unsigned operation;
    for (operation = 0u; operation < 16u; ++operation) {
        expect_invalid(operations[operation].base | UINT32_C(0x00c00000));
        if (operations[operation].halving)
            expect_invalid(operations[operation].base | UINT32_C(0x40c00000));
    }
    {
        cdisasm_arm_instruction instruction;
        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(UINT32_C(0x0e220420), CDISASM_ARM_CPU_CORTEX_A53,
            &instruction) == 4u);
#else
        EXPECT(decode_word(UINT32_C(0x0e220420), CDISASM_ARM_CPU_CORTEX_A53,
            &instruction) == 0u);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

int main(void)
{
    test_complete_legal_domain();
    test_reserved_and_profile();
    if (failures != 0) return 1;
    puts("Advanced SIMD integer three-same tests passed");
    return 0;
}
