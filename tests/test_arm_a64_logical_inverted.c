#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 24) fprintf(stderr, \
    "%s:%d: expectation failed: %s\n", __FILE__, __LINE__, #c); \
    ++failures; } } while (0)

static uint32_t decode_word(uint32_t word, cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    return cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, 4u, UINT64_C(0x0a200000),
        CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static cdisasm_arm_reg_id reg_for(unsigned reg, int is_64)
{
    if (reg == 31u) return is_64 ? CDISASM_ARM_REG_XZR : CDISASM_ARM_REG_WZR;
    return (cdisasm_arm_reg_id)((is_64 ? CDISASM_ARM_REG_X0
                                      : CDISASM_ARM_REG_W0) + reg);
}

static void check_regular(uint32_t word, int is_64, unsigned opcode,
    unsigned invert, unsigned shift, unsigned amount,
    unsigned rd, unsigned rn, unsigned rm)
{
    static const cdisasm_arm_name_id names[4][2] = {
        { CDISASM_ARM_NAME_AND, CDISASM_ARM_NAME_BIC },
        { CDISASM_ARM_NAME_ORR, CDISASM_ARM_NAME_ORN },
        { CDISASM_ARM_NAME_EOR, CDISASM_ARM_NAME_EON },
        { CDISASM_ARM_NAME_ANDS, CDISASM_ARM_NAME_BICS }
    };
    static const cdisasm_arm_form_id forms[2][4][2] = {
        {{5654,5655},{5656,5657},{5658,5659},{5660,5661}},
        {{5662,5663},{5664,5665},{5666,5667},{5668,5669}}
    };
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, &instruction) == 4u);
    EXPECT(instruction.name_id == names[opcode][invert]);
    EXPECT(instruction.form_id == forms[is_64][opcode][invert]);
    EXPECT(instruction.instruction_flags == (opcode == 3u
        ? CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS : 0u));
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.operand[0].reg == reg_for(rd, is_64));
    EXPECT(instruction.operand[0].size == (is_64 ? 8u : 4u));
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].reg == reg_for(rn, is_64));
    EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[2].reg == reg_for(rm, is_64));
    EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[2].shift_type == (shift == 0u && amount == 0u
        ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL + shift));
    EXPECT(instruction.operand[2].shift_amount == amount);
}

static void test_register_domain(void)
{
    unsigned is_64, opcode, invert, rd, rn, rm;
    for (is_64 = 0u; is_64 <= 1u; ++is_64)
        for (opcode = 0u; opcode < 4u; ++opcode)
            for (invert = 0u; invert <= 1u; ++invert)
                for (rm = 0u; rm < 31u; ++rm)
                    for (rn = 0u; rn < 31u; ++rn)
                        for (rd = 0u; rd < 31u; ++rd) {
                            uint32_t word = UINT32_C(0x0a000000)
                                | (is_64 << 31) | (opcode << 29)
                                | (invert << 21) | (rm << 16)
                                | (rn << 5) | rd;
                            check_regular(word, is_64, opcode, invert,
                                0u, 0u, rd, rn, rm);
                        }
}

static void test_shift_domain_and_aliases(void)
{
    unsigned is_64, opcode, invert, shift, amount;
    for (is_64 = 0u; is_64 <= 1u; ++is_64)
        for (opcode = 0u; opcode < 4u; ++opcode)
            for (invert = 0u; invert <= 1u; ++invert)
                for (shift = 0u; shift < 4u; ++shift)
                    for (amount = 0u; amount < (is_64 ? 64u : 32u); ++amount) {
                        uint32_t word = UINT32_C(0x0a000000)
                            | (is_64 << 31) | (opcode << 29)
                            | (shift << 22) | (invert << 21)
                            | UINT32_C(3) << 16 | (amount << 10)
                            | UINT32_C(2) << 5 | UINT32_C(1);
                        check_regular(word, is_64, opcode, invert,
                            shift, amount, 1u, 2u, 3u);
                    }
    {
        cdisasm_arm_instruction instruction;
        EXPECT(decode_word(UINT32_C(0xaa0203e1), &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_MOV);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(decode_word(UINT32_C(0xaaa21fe1), &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_MVN);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.operand[1].shift_type == CDISASM_ARM_SHIFT_ASR);
        EXPECT(instruction.operand[1].shift_amount == 7u);
        EXPECT(decode_word(UINT32_C(0xea02003f), &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_TST);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(decode_word(UINT32_C(0xea22003f), &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_BICS);
        EXPECT(instruction.operand_count == 3u);
    }
    {
        cdisasm_arm_instruction instruction, expected;
        memset(&instruction, 0xa5, sizeof(instruction));
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_INVALID_INSTRUCTION;
        EXPECT(decode_word(UINT32_C(0x0a038041), &instruction) == 0u);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
    }
}

int main(void)
{
    test_register_domain();
    test_shift_domain_and_aliases();
    if (failures != 0) return 1;
    puts("A64 logical inverted-register tests passed");
    return 0;
}
