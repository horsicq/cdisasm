#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
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
        UINT64_C(0x2e00c400), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
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
static void check_result(const cdisasm_arm_instruction *instruction,
    cdisasm_arm_form_id form, unsigned total, unsigned element,
    unsigned rm, unsigned rn, unsigned rd, unsigned rotation, int lane)
{
    EXPECT(instruction->name_id == CDISASM_ARM_NAME_FCMLA);
    EXPECT(instruction->form_id == form);
    EXPECT(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    EXPECT(instruction->operand_count == 4u);
    EXPECT(instruction->operand[0].reg == CDISASM_ARM_REG_V0 + rd);
    EXPECT(instruction->operand[0].size == total);
    EXPECT(instruction->operand[0].extend_type == element);
    EXPECT(instruction->operand[0].access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    EXPECT(instruction->operand[1].reg == CDISASM_ARM_REG_V0 + rn);
    EXPECT(instruction->operand[1].size == total);
    EXPECT(instruction->operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->operand[2].reg == CDISASM_ARM_REG_V0 + rm);
    EXPECT(instruction->operand[2].size == (lane >= 0 ? 16u : total));
    EXPECT(instruction->operand[2].extend_type == element);
    EXPECT(instruction->operand[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->operand[2].flags == (lane >= 0
        ? CDISASM_ARM_OPERAND_FLAG_HAS_LANE : CDISASM_OPERAND_FLAG_NONE));
    if (lane >= 0) EXPECT(instruction->operand[2].imm == (uint64_t)lane);
    EXPECT(instruction->operand[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->operand[3].imm == rotation * 90u);
}
#endif

static void check_vector(unsigned q, unsigned size, unsigned rotation,
    unsigned rm, unsigned rn, unsigned rd)
{
    uint32_t word = UINT32_C(0x2e00c400) | (q << 30) | (size << 22)
        | (rm << 16) | (rotation << 11) | (rn << 5) | rd;
    cdisasm_arm_instruction instruction;
    int valid = size != 0u && (size != 3u || q != 0u);
    memset(&instruction, 0xa5, sizeof(instruction));
    if (!valid) {
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        return;
    }
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    check_result(&instruction, 5985u, q ? 16u : 8u, 1u << size,
        rm, rn, rd, rotation, -1);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void check_fcadd(unsigned q, unsigned size, unsigned rotation,
    unsigned rm, unsigned rn, unsigned rd)
{
    uint32_t word = UINT32_C(0x2e00e400) | (q << 30) | (size << 22)
        | (rm << 16) | (rotation << 12) | (rn << 5) | rd;
    cdisasm_arm_instruction instruction;
    int valid = size != 0u && (size != 3u || q != 0u);
    memset(&instruction, 0xa5, sizeof(instruction));
    if (!valid) {
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        return;
    }
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_FCADD);
    EXPECT(instruction.form_id == 5986u);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    EXPECT(instruction.operand_count == 4u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_V0 + rd);
    EXPECT(instruction.operand[0].size == (q ? 16u : 8u));
    EXPECT(instruction.operand[0].extend_type == (1u << size));
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_V0 + rn);
    EXPECT(instruction.operand[2].reg == CDISASM_ARM_REG_V0 + rm);
    EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction.operand[3].imm == 90u + rotation * 180u);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void check_indexed(unsigned q, unsigned size, unsigned l,
    unsigned m, unsigned rm, unsigned rotation, unsigned h,
    unsigned rn, unsigned rd)
{
    uint32_t word = UINT32_C(0x2f001000) | (q << 30) | (size << 22)
        | (l << 21) | (m << 20) | (rm << 16) | (rotation << 13)
        | (h << 11) | (rn << 5) | rd;
    cdisasm_arm_instruction instruction;
    int valid = m == 0u
        && ((size == 1u && (q != 0u || h == 0u))
            || (size == 2u && q != 0u && l == 0u));
    memset(&instruction, 0xa5, sizeof(instruction));
    if (!valid) {
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        return;
    }
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    check_result(&instruction, 6277u, q ? 16u : 8u, 1u << size, rm, rn, rd,
        rotation, size == 1u ? (int)((h << 1) | l) : (int)h);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_complete_domains(void)
{
    unsigned q, size, rotation, rm, rn, rd, l, m, h;
    for (q = 0u; q < 2u; ++q) for (size = 0u; size < 4u; ++size)
        for (rotation = 0u; rotation < 4u; ++rotation)
            for (rm = 0u; rm < 32u; ++rm) for (rn = 0u; rn < 32u; ++rn)
                for (rd = 0u; rd < 32u; ++rd)
                    check_vector(q, size, rotation, rm, rn, rd);
    for (q = 0u; q < 2u; ++q) for (size = 0u; size < 4u; ++size)
        for (rotation = 0u; rotation < 2u; ++rotation)
            for (rm = 0u; rm < 32u; ++rm) for (rn = 0u; rn < 32u; ++rn)
                for (rd = 0u; rd < 32u; ++rd)
                    check_fcadd(q, size, rotation, rm, rn, rd);
    for (q = 0u; q < 2u; ++q) for (size = 0u; size < 4u; ++size)
        for (l = 0u; l < 2u; ++l) for (m = 0u; m < 2u; ++m)
            for (rm = 0u; rm < 16u; ++rm)
                for (rotation = 0u; rotation < 4u; ++rotation)
                    for (h = 0u; h < 2u; ++h)
                        for (rn = 0u; rn < 32u; ++rn)
                            for (rd = 0u; rd < 32u; ++rd)
                                check_indexed(q, size, l, m, rm, rotation,
                                    h, rn, rd);
}

static void test_profiles_and_format(void)
{
    cdisasm_arm_instruction instruction;
    uint32_t word = UINT32_C(0x6f871ad5);
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_APPLE_M1, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_CORTEX_A53, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
# if USE_DISASM_FORMAT
    {
        uint32_t add_word = UINT32_C(0x6e8bf549);
        char text[96];
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("fcmla v21.4s, v22.4s, v7.s[1], #0"));
        EXPECT(strcmp(text, "fcmla v21.4s, v22.4s, v7.s[1], #0") == 0);
        EXPECT(decode_word(add_word, CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("fcadd v9.4s, v10.4s, v11.4s, #270"));
        EXPECT(strcmp(text, "fcadd v9.4s, v10.4s, v11.4s, #270") == 0);
    }
# endif
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
    puts("Advanced SIMD FCMLA tests passed");
    return 0;
}
