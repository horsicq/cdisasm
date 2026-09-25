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
        UINT64_C(0x0d000000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static void check(unsigned even, unsigned upper, unsigned element_log2,
    unsigned load, unsigned lane, unsigned rn, unsigned rt,
    unsigned post_index, unsigned rm)
{
    cdisasm_arm_instruction instruction;
#if !USE_EXTRA_OPCODES
    cdisasm_arm_instruction expected;
#endif
    uint8_t element_size = (uint8_t)(1u << element_log2);
#if USE_EXTRA_OPCODES
    uint8_t count = even ? (upper ? 4u : 2u) : (upper ? 3u : 1u);
#endif
    unsigned low_lanes = 8u / element_size;
    uint32_t element_bits = element_log2 == 0u ? 0u
        : element_log2 == 1u ? UINT32_C(0x4000)
        : element_log2 == 2u ? UINT32_C(0x8000) : UINT32_C(0x8400);
    uint32_t word = UINT32_C(0x0d000000) | (even << 21) | (upper << 13)
        | element_bits | (load << 22) | ((lane / low_lanes) << 30)
        | ((lane % low_lanes) * element_size << 10) | (rn << 5) | rt
        | (post_index << 23) | (post_index ? rm << 16 : 0u);
#if USE_EXTRA_OPCODES
    unsigned slot = element_log2 < 2u
        ? element_log2 * 2u + upper
        : 4u + (element_log2 - 2u) + upper * 2u;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    cdisasm_arm_form_id form = (post_index
        ? (load
            ? (even ? (rm == 31u ? 4715u : 4705u)
                      : (rm == 31u ? 4695u : 4685u))
            : (even ? (rm == 31u ? 4677u : 4669u)
                    : (rm == 31u ? 4661u : 4653u)))
        : (load ? (even ? 4643u : 4632u)
                : (even ? 4624u : 4615u))) + slot;
    cdisasm_arm_name_id name = load
        ? count == 1u ? CDISASM_ARM_NAME_LD1
            : count == 2u ? CDISASM_ARM_NAME_LD2
            : count == 3u ? CDISASM_ARM_NAME_LD3 : CDISASM_ARM_NAME_LD4
        : count == 1u ? CDISASM_ARM_NAME_ST1
            : count == 2u ? CDISASM_ARM_NAME_ST2
            : count == 3u ? CDISASM_ARM_NAME_ST3 : CDISASM_ARM_NAME_ST4;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == name);
    EXPECT(instruction.form_id == form);
    EXPECT(instruction.instruction_flags == (uint32_t)
        (CDISASM_ARM_INSTRUCTION_FLAG_SIMD | (post_index
            ? CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK : 0u)));
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_V0 + rt);
    EXPECT(instruction.operand[0].register_list == count);
    EXPECT(instruction.operand[0].size == 16u);
    EXPECT(instruction.operand[0].extend_type == element_size);
    EXPECT(instruction.operand[0].scale == 16u / element_size);
    EXPECT(instruction.operand[0].flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    EXPECT(instruction.operand[0].imm == lane);
    EXPECT(instruction.operand[0].access == (load
        ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ));
    EXPECT(instruction.operand[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[1].base_reg == (rn == 31u
        ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_X0 + rn));
    EXPECT(instruction.operand[1].size == element_size * count);
    EXPECT(instruction.operand[1].access == (load
        ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT(instruction.operand[1].flags == (post_index
        ? CDISASM_ARM_OPERAND_FLAG_WRITEBACK | (rm == 31u
            ? CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT : 0u)
        : CDISASM_OPERAND_FLAG_NONE));
    EXPECT(instruction.operand[1].index_reg == (post_index && rm != 31u
        ? CDISASM_ARM_REG_X0 + rm : CDISASM_ARM_REG_NONE));
    EXPECT(instruction.operand[1].imm == (post_index && rm == 31u
        ? element_size * count : 0u));
#else
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
}

int main(void)
{
    unsigned even, upper, element, load, lane, rn, rt;
    for (even = 0u; even < 2u; ++even)
        for (upper = 0u; upper < 2u; ++upper)
            for (element = 0u; element < 4u; ++element)
                for (load = 0u; load < 2u; ++load)
                    for (lane = 0u; lane < 16u / (1u << element); ++lane)
                        for (rn = 0u; rn < 32u; ++rn)
                            for (rt = 0u; rt < 32u; ++rt)
                                check(even, upper, element, load, lane, rn, rt,
                                    0u, 0u);
    for (even = 0u; even < 2u; ++even)
        for (upper = 0u; upper < 2u; ++upper)
            for (element = 0u; element < 4u; ++element)
                for (load = 0u; load < 2u; ++load)
                    for (lane = 0u; lane < 16u / (1u << element); ++lane)
                        for (rn = 0u; rn < 32u; ++rn)
                            for (rt = 0u; rt < 32u; ++rt) {
                                check(even, upper, element, load, lane, rn, rt,
                                    1u, 5u);
                                check(even, upper, element, load, lane, rn, rt,
                                    1u, 31u);
                            }
    {
        cdisasm_arm_instruction instruction;
        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(UINT32_C(0x4d60a4ff),
            CDISASM_ARM_CPU_CORTEX_A53, &instruction) == 4u);
        EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_V31);
        EXPECT(instruction.operand[0].register_list == 4u);
        EXPECT(instruction.operand[0].imm == 1u);
#else
        EXPECT(decode_word(UINT32_C(0x4d60a4ff),
            CDISASM_ARM_CPU_CORTEX_A53, &instruction) == 0u);
#endif
    }
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    {
        cdisasm_arm_instruction instruction;
        char text[96];
        EXPECT(decode_word(UINT32_C(0x4d0078c3), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("st3 {v3.h, v4.h, v5.h}[7], [x6]"));
        EXPECT(strcmp(text, "st3 {v3.h, v4.h, v5.h}[7], [x6]") == 0);
        EXPECT(decode_word(UINT32_C(0x4d9f78c3), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("st3 {v3.h, v4.h, v5.h}[7], [x6], #0x6"));
        EXPECT(strcmp(text,
            "st3 {v3.h, v4.h, v5.h}[7], [x6], #0x6") == 0);
        EXPECT(decode_word(UINT32_C(0x0d820020), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("st1 {v0.b}[0], [x1], x2"));
        EXPECT(strcmp(text, "st1 {v0.b}[0], [x1], x2") == 0);
    }
#endif
    if (failures != 0) return 1;
    puts("Advanced SIMD single-lane structure tests passed");
    return 0;
}
