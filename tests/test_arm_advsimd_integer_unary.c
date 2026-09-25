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
    int compare_zero;
};

static const struct operation operations[9] = {
    { UINT32_C(0x0e203800), CDISASM_ARM_NAME_SUQADD, 6006, 0 },
    { UINT32_C(0x0e207800), CDISASM_ARM_NAME_SQABS, 6010, 0 },
    { UINT32_C(0x0e208800), CDISASM_ARM_NAME_CMGT, 6011, 1 },
    { UINT32_C(0x0e209800), CDISASM_ARM_NAME_CMEQ, 6012, 1 },
    { UINT32_C(0x0e20b800), CDISASM_ARM_NAME_ABS, 6014, 0 },
    { UINT32_C(0x2e203800), CDISASM_ARM_NAME_USQADD, 6040, 0 },
    { UINT32_C(0x2e207800), CDISASM_ARM_NAME_SQNEG, 6043, 0 },
    { UINT32_C(0x2e208800), CDISASM_ARM_NAME_CMGE, 6044, 1 },
    { UINT32_C(0x2e20b800), CDISASM_ARM_NAME_NEG, 6046, 0 }
};

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, bytes, 4u,
        UINT64_C(0x0e203800), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static void test_complete_legal_domain(void)
{
    unsigned operation, q, size, rn, rd;

    for (operation = 0u; operation < 9u; ++operation) {
        for (q = 0u; q < 2u; ++q) {
            for (size = 0u; size < 4u; ++size) {
                if (q == 0u && size == 3u) continue;
#if USE_EXTRA_OPCODES
                uint8_t total_size, element_size;
                total_size = q != 0u ? 16u : 8u;
                element_size = (uint8_t)(1u << size);
#endif
                for (rn = 0u; rn < 32u; ++rn) {
                    for (rd = 0u; rd < 32u; ++rd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = operations[operation].base
                            | (q << 30) | (size << 22) | (rn << 5) | rd;
                        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                            &instruction) == 4u);
                        EXPECT(instruction.name_id == operations[operation].name);
                        EXPECT(instruction.form_id == operations[operation].form);
                        EXPECT(instruction.instruction_flags
                            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
                        EXPECT(instruction.operand_count
                            == (operations[operation].compare_zero ? 3u : 2u));
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
                        if (operations[operation].compare_zero) {
                            EXPECT(instruction.operand[2].type
                                == CDISASM_OPERAND_IMMEDIATE);
                            EXPECT(instruction.operand[2].imm == 0u);
                        }
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

static void test_reserved_and_profile(void)
{
    unsigned operation;
    for (operation = 0u; operation < 9u; ++operation) {
        cdisasm_arm_instruction instruction, expected;
        memset(&instruction, 0xa5, sizeof(instruction));
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_INVALID_INSTRUCTION;
        EXPECT(decode_word(operations[operation].base | UINT32_C(0x00c00000),
            CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
    }
    {
        cdisasm_arm_instruction instruction;
        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(UINT32_C(0x0e20b820), CDISASM_ARM_CPU_CORTEX_A53,
            &instruction) == 4u);
#else
        EXPECT(decode_word(UINT32_C(0x0e20b820), CDISASM_ARM_CPU_CORTEX_A53,
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
    puts("Advanced SIMD integer unary tests passed");
    return 0;
}
