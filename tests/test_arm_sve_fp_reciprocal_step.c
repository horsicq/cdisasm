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

static uint32_t step_word(unsigned operation, unsigned size,
    unsigned zm, unsigned zn, unsigned zd)
{
    return UINT32_C(0x65001800) | (operation << 10) | (size << 22)
        | (zm << 16) | (zn << 5) | zd;
}

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, bytes, 4u,
        UINT64_C(0x65001800), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void check(unsigned operation, unsigned size, unsigned zm,
    unsigned zn, unsigned zd)
{
    uint32_t word = step_word(operation, size, zm, zn, zd);
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
    if (size == 0u) {
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        return;
    }
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == (operation == 0u
        ? CDISASM_ARM_NAME_FRECPS : CDISASM_ARM_NAME_FRSQRTS));
    EXPECT(instruction.form_id == (cdisasm_arm_form_id)(3061u + operation));
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_Z0 + zd);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_Z0 + zn);
    EXPECT(instruction.operand[2].reg == CDISASM_ARM_REG_Z0 + zm);
    EXPECT(instruction.operand[0].extend_type == (1u << size));
    EXPECT(instruction.operand[1].extend_type == (1u << size));
    EXPECT(instruction.operand[2].extend_type == (1u << size));
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_complete_domain(void)
{
    unsigned operation, size, zm, zn, zd;
    for (operation = 0u; operation < 2u; ++operation)
        for (size = 0u; size < 4u; ++size)
            for (zm = 0u; zm < 32u; ++zm)
                for (zn = 0u; zn < 32u; ++zn)
                    for (zd = 0u; zd < 32u; ++zd)
                        check(operation, size, zm, zn, zd);
}

static void test_profiles_and_format(void)
{
    uint32_t word = step_word(1u, 2u, 14u, 13u, 12u);
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        &instruction) == 4u);
    EXPECT(decode_word(word, CDISASM_ARM_CPU_APPLE_M4,
        &instruction) == 4u);
    EXPECT(decode_word(word, CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_APPLE_M3,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#  if USE_DISASM_FORMAT
    {
        char text[96];
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("frsqrts z12.s, z13.s, z14.s"));
        EXPECT(strcmp(text, "frsqrts z12.s, z13.s, z14.s") == 0);
    }
#  endif
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

int main(void)
{
    test_complete_domain();
    test_profiles_and_format();
    if (failures != 0) return 1;
    puts("SVE floating reciprocal-step tests passed");
    return 0;
}
