#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif
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
        UINT64_C(0x45200000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static void expect_list(const cdisasm_arm_operand *operand, unsigned first,
    unsigned count, unsigned element_size, cdisasm_operand_access access)
{
    EXPECT(operand->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    EXPECT(operand->reg == CDISASM_ARM_REG_Z0 + first);
    EXPECT(CDISASM_ARM_SCALABLE_LIST_COUNT(operand) == count);
    EXPECT(CDISASM_ARM_SCALABLE_LIST_STRIDE(operand) == 1u);
    EXPECT(operand->extend_type == element_size);
    EXPECT(operand->access == access);
}

static void expect_zreg(const cdisasm_arm_operand *operand, unsigned reg,
    unsigned element_size, cdisasm_operand_access access)
{
    EXPECT(operand->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    EXPECT(operand->reg == CDISASM_ARM_REG_Z0 + reg);
    EXPECT(operand->extend_type == element_size);
    EXPECT(operand->access == access);
}
#endif

static void check_round(unsigned four, unsigned selector, unsigned lane,
    unsigned zm, unsigned zd_group)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_AESE, CDISASM_ARM_NAME_AESD,
        CDISASM_ARM_NAME_AESEMC, CDISASM_ARM_NAME_AESDIMC
    };
    unsigned count = four ? 4u : 2u;
    unsigned zd = zd_group * count;
    uint32_t word = UINT32_C(0x4522e800) | (four << 18)
        | ((selector >> 1) << 16) | ((selector & 1u) << 10)
        | (lane << 19) | (zm << 5) | zd;
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == names[selector]);
    EXPECT(instruction.form_id == (cdisasm_arm_form_id)(
        2908u + selector + four * 4u));
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    EXPECT(instruction.operand_count == 3u);
    expect_list(&instruction.operand[0], zd, count, 1u,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    expect_list(&instruction.operand[1], zd, count, 1u,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    expect_zreg(&instruction.operand[2], zm, 16u,
        CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[2].flags
        == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    EXPECT(instruction.operand[2].imm == lane);
#else
    (void)names;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void check_pmull(unsigned accumulate, unsigned zm, unsigned zn,
    unsigned zd_pair)
{
    unsigned zd = zd_pair * 2u;
    uint32_t word = UINT32_C(0x4520f800) | (accumulate << 10)
        | (zm << 16) | (zn << 5) | zd;
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == (accumulate
        ? CDISASM_ARM_NAME_PMLAL : CDISASM_ARM_NAME_PMULL));
    EXPECT(instruction.form_id == (cdisasm_arm_form_id)(2918u + accumulate));
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    EXPECT(instruction.operand_count == 3u);
    expect_list(&instruction.operand[0], zd, 2u, 16u, accumulate
        ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE);
    expect_zreg(&instruction.operand[1], zn, 8u,
        CDISASM_OPERAND_ACCESS_READ);
    expect_zreg(&instruction.operand[2], zm, 8u,
        CDISASM_OPERAND_ACCESS_READ);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_complete_domains(void)
{
    unsigned four, selector, lane, zm, zd, accumulate, zn;
    for (four = 0u; four < 2u; ++four)
        for (selector = 0u; selector < 4u; ++selector)
            for (lane = 0u; lane < 4u; ++lane)
                for (zm = 0u; zm < 32u; ++zm)
                    for (zd = 0u; zd < (four ? 8u : 16u); ++zd)
                        check_round(four, selector, lane, zm, zd);
    for (accumulate = 0u; accumulate < 2u; ++accumulate)
        for (zm = 0u; zm < 32u; ++zm)
            for (zn = 0u; zn < 32u; ++zn)
                for (zd = 0u; zd < 16u; ++zd)
                    check_pmull(accumulate, zm, zn, zd);
}

static void test_profiles_and_format(void)
{
    cdisasm_arm_instruction instruction;
    uint32_t word = UINT32_C(0x452aece2);
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(decode_word(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_APPLE_M4,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#  if USE_DISASM_FORMAT
    {
        char text[160];
        static const char expected[] =
            "aesd {z2.b, z3.b}, {z2.b, z3.b}, z7.q[1]";
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
    }
#  endif
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

int main(void)
{
    test_complete_domains();
    test_profiles_and_format();
    if (failures != 0) return 1;
    puts("SVE AES2 multi-vector tests passed");
    return 0;
}
