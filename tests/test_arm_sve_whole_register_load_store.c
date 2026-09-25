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
        UINT64_C(0x85800000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void check_one(int load, int predicate, unsigned imm9,
    unsigned rn, unsigned rt)
{
    uint32_t word = (load ? UINT32_C(0x85800000) : UINT32_C(0xe5800000))
        | (predicate ? 0u : UINT32_C(0x00004000))
        | ((imm9 >> 3) << 16) | ((imm9 & 7u) << 10)
        | (rn << 5) | rt;
    int64_t displacement = imm9 < 256u
        ? (int64_t)imm9 : (int64_t)imm9 - INT64_C(512);
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == (load ? CDISASM_ARM_NAME_LDR
                                        : CDISASM_ARM_NAME_STR));
    EXPECT(instruction.form_id == (predicate
        ? (load ? 3214u : 3469u) : (load ? 3215u : 3476u)));
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.operand[0].type == (predicate
        ? CDISASM_ARM_OPERAND_PREDICATE
        : CDISASM_ARM_OPERAND_SCALABLE_REGISTER));
    EXPECT(instruction.operand[0].reg == (predicate
        ? CDISASM_ARM_REG_P0 + rt : CDISASM_ARM_REG_Z0 + rt));
    EXPECT(instruction.operand[0].extend_type == (predicate ? 1u : 0u));
    EXPECT(instruction.operand[0].access == (load
        ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ));
    EXPECT(instruction.operand[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[1].base_reg == (rn == 31u
        ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_X0 + rn));
    EXPECT((int64_t)instruction.operand[1].imm == displacement);
    EXPECT(instruction.operand[1].flags == (displacement == 0
        ? 0u : CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
            | (displacement < 0 ? CDISASM_OPERAND_FLAG_SIGNED : 0u)));
    EXPECT(instruction.operand[1].access == (load
        ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE));
#else
    (void)displacement;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_complete_domains(void)
{
    unsigned load, predicate, imm9, rn, rt;
    for (load = 0; load < 2; ++load)
        for (predicate = 0; predicate < 2; ++predicate)
            for (imm9 = 0; imm9 < 512; ++imm9)
                for (rn = 0; rn < 32; ++rn)
                    for (rt = 0; rt < (predicate ? 16u : 32u); ++rt)
                        check_one((int)load, (int)predicate, imm9, rn, rt);
}

static void test_evidence_profiles_and_format(void)
{
    static const uint32_t words[] = {
        UINT32_C(0x85800020), UINT32_C(0x85a003e7),
        UINT32_C(0x859f1fca), UINT32_C(0xe5800020),
        UINT32_C(0xe5a043ff), UINT32_C(0xe59f5fd1)
    };
    cdisasm_arm_instruction instruction;
    unsigned i;
    for (i = 0; i < sizeof(words) / sizeof(words[0]); ++i) {
        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(words[i], CDISASM_ARM_CPU_ANY, &instruction) == 4u);
#else
        EXPECT(decode_word(words[i], CDISASM_ARM_CPU_ANY, &instruction) == 0u);
#endif
    }
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(words[0], CDISASM_ARM_CPU_FUJITSU_A64FX,
        &instruction) == 4u);
    EXPECT(decode_word(words[0], CDISASM_ARM_CPU_APPLE_M4,
        &instruction) == 4u);
    EXPECT(decode_word(words[0], CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
# if USE_DISASM_FORMAT
    {
        char text[96];
        EXPECT(decode_word(UINT32_C(0x85a043ff), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("ldr z31, [sp, #-0x100, mul vl]"));
        EXPECT(strcmp(text, "ldr z31, [sp, #-0x100, mul vl]") == 0);
    }
# endif
#endif
}

int main(void)
{
    test_complete_domains();
    test_evidence_profiles_and_format();
    if (failures) {
        fprintf(stderr, "%d SVE whole-register load/store test(s) failed\n",
            failures);
        return 1;
    }
    puts("ARM SVE whole-register LDR/STR tests passed (4 exact leaves; exhaustive imm9/register domains)");
    return 0;
}
