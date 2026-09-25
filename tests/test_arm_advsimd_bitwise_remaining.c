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
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64,
        bytes, 4u, UINT64_C(0x2e205800), CDISASM_ARM_DECODE_OPTION_NONE,
        instruction);
}

#if USE_EXTRA_OPCODES
static void check_common(const cdisasm_arm_instruction *instruction,
    cdisasm_arm_name_id name, cdisasm_arm_form_id form, unsigned q,
    unsigned rd, unsigned rn)
{
    uint8_t total_size = q != 0u ? 16u : 8u;
    EXPECT(instruction->name_id == name);
    EXPECT(instruction->form_id == form);
    EXPECT(instruction->instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    EXPECT(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rd));
    EXPECT(instruction->operand[0].size == total_size);
    EXPECT(instruction->operand[0].extend_type == 1u);
    EXPECT(instruction->operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rn));
    EXPECT(instruction->operand[1].size == total_size);
    EXPECT(instruction->operand[1].extend_type == 1u);
    EXPECT(instruction->operand[1].access == CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_unary_domain(void)
{
    static const uint32_t bases[2] = {
        UINT32_C(0x2e205800), UINT32_C(0x2e605800)
    };
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_name_id names[2] = {
        CDISASM_ARM_NAME_NOT, CDISASM_ARM_NAME_RBIT
    };
    static const cdisasm_arm_form_id forms[2] = { 6059, 6061 };
#endif
    unsigned operation, q, rn, rd;

    for (operation = 0u; operation < 2u; ++operation) {
        for (q = 0u; q < 2u; ++q) {
            for (rn = 0u; rn < 32u; ++rn) {
                for (rd = 0u; rd < 32u; ++rd) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = bases[operation] | (q << 30)
                        | (rn << 5) | rd;
                    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                        &instruction) == 4u);
                    EXPECT(instruction.operand_count == 2u);
                    check_common(&instruction, names[operation],
                        forms[operation], q, rd, rn);
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

static void test_binary_domain(void)
{
    static const uint32_t bases[2] = {
        UINT32_C(0x0e601c00), UINT32_C(0x0ee01c00)
    };
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_name_id names[2] = {
        CDISASM_ARM_NAME_BIC, CDISASM_ARM_NAME_ORN
    };
    static const cdisasm_arm_form_id forms[2] = { 6147, 6156 };
#endif
    unsigned operation, q, rm, rn, rd;

    for (operation = 0u; operation < 2u; ++operation) {
        for (q = 0u; q < 2u; ++q) {
            for (rm = 0u; rm < 32u; ++rm) {
                for (rn = 0u; rn < 32u; ++rn) {
                    for (rd = 0u; rd < 32u; ++rd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = bases[operation] | (q << 30)
                            | (rm << 16) | (rn << 5) | rd;
                        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                            &instruction) == 4u);
                        EXPECT(instruction.operand_count == 3u);
                        check_common(&instruction, names[operation],
                            forms[operation], q, rd, rn);
                        EXPECT(instruction.operand[2].reg
                            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rm));
                        EXPECT(instruction.operand[2].size
                            == (q != 0u ? 16u : 8u));
                        EXPECT(instruction.operand[2].extend_type == 1u);
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

int main(void)
{
    cdisasm_arm_instruction instruction;
    test_unary_domain();
    test_binary_domain();
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(UINT32_C(0x2e205820), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 4u);
#else
    EXPECT(decode_word(UINT32_C(0x2e205820), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    if (failures != 0) return 1;
    puts("Advanced SIMD remaining bitwise tests passed");
    return 0;
}
