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
        UINT64_C(0x1e200400), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static void test_complete_domain(void)
{
    static const uint32_t bases[3] = {
        UINT32_C(0x1e200400), UINT32_C(0x1e600400), UINT32_C(0x1ee00400)
    };
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_reg_id first_regs[3] = {
        CDISASM_ARM_REG_S0, CDISASM_ARM_REG_D0, CDISASM_ARM_REG_H0
    };
    static const uint8_t sizes[3] = { 4u, 8u, 2u };
    static const cdisasm_arm_form_id forms[3][2] = {
        { 6522, 6523 }, { 6524, 6525 }, { 6526, 6527 }
    };
#endif
    unsigned precision, signaling, rn, rm, nzcv, condition;

    for (precision = 0u; precision < 3u; ++precision) {
        for (signaling = 0u; signaling <= 1u; ++signaling) {
            for (condition = 0u; condition < 16u; ++condition) {
                for (nzcv = 0u; nzcv < 16u; ++nzcv) {
                    for (rm = 0u; rm < 32u; ++rm) {
                        for (rn = 0u; rn < 32u; ++rn) {
                            cdisasm_arm_instruction instruction;
                            uint32_t word = bases[precision]
                                | ((uint32_t)rm << 16)
                                | ((uint32_t)condition << 12)
                                | ((uint32_t)rn << 5) | nzcv
                                | (signaling != 0u ? UINT32_C(0x10) : 0u);
                            memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                            EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                                &instruction) == 4u);
                            EXPECT(instruction.name_id == (signaling != 0u
                                ? CDISASM_ARM_NAME_FCCMPE
                                : CDISASM_ARM_NAME_FCCMP));
                            EXPECT(instruction.form_id
                                == forms[precision][signaling]);
                            EXPECT(instruction.instruction_flags
                                == (CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
                                    | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS));
                            EXPECT(instruction.opcode_groups
                                == CDISASM_GROUP_CONDITIONAL);
                            EXPECT(instruction.operand_count == 4u);
                            EXPECT(instruction.operand[0].type
                                == CDISASM_OPERAND_REGISTER);
                            EXPECT(instruction.operand[0].reg
                                == (cdisasm_arm_reg_id)(first_regs[precision]
                                    + rn));
                            EXPECT(instruction.operand[0].size
                                == sizes[precision]);
                            EXPECT(instruction.operand[0].access
                                == CDISASM_OPERAND_ACCESS_READ);
                            EXPECT(instruction.operand[1].type
                                == CDISASM_OPERAND_REGISTER);
                            EXPECT(instruction.operand[1].reg
                                == (cdisasm_arm_reg_id)(first_regs[precision]
                                    + rm));
                            EXPECT(instruction.operand[1].size
                                == sizes[precision]);
                            EXPECT(instruction.operand[1].access
                                == CDISASM_OPERAND_ACCESS_READ);
                            EXPECT(instruction.operand[2].type
                                == CDISASM_OPERAND_IMMEDIATE);
                            EXPECT(instruction.operand[2].imm == nzcv);
                            EXPECT(instruction.operand[3].type
                                == CDISASM_OPERAND_IMMEDIATE);
                            EXPECT(instruction.operand[3].imm == condition);
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

static void test_legality_and_profile(void)
{
    cdisasm_arm_instruction instruction, expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = CDISASM_STATUS_INVALID_INSTRUCTION;
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x1ea20410), CDISASM_ARM_CPU_ANY,
        &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#if !USE_EXTRA_OPCODES
    expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x1ee20410), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
}

int main(void)
{
    test_complete_domain();
    test_legality_and_profile();
    if (failures != 0) return 1;
    puts("A64 scalar floating-point conditional compare tests passed");
    return 0;
}
