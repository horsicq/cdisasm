#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

typedef struct load_desc {
    uint32_t value;
    cdisasm_arm_name_id name;
    cdisasm_arm_form_id form;
    uint8_t destination_size;
    uint8_t memory_size;
} load_desc;

static const load_desc loads[] = {
    { UINT32_C(0xa400a000), CDISASM_ARM_NAME_LD1B, 3314u, 1u, 1u },
    { UINT32_C(0xa420a000), CDISASM_ARM_NAME_LD1B, 3315u, 2u, 1u },
    { UINT32_C(0xa440a000), CDISASM_ARM_NAME_LD1B, 3316u, 4u, 1u },
    { UINT32_C(0xa460a000), CDISASM_ARM_NAME_LD1B, 3317u, 8u, 1u },
    { UINT32_C(0xa480a000), CDISASM_ARM_NAME_LD1SW, 3318u, 8u, 4u },
    { UINT32_C(0xa4a0a000), CDISASM_ARM_NAME_LD1H, 3319u, 2u, 2u },
    { UINT32_C(0xa4c0a000), CDISASM_ARM_NAME_LD1H, 3320u, 4u, 2u },
    { UINT32_C(0xa4e0a000), CDISASM_ARM_NAME_LD1H, 3321u, 8u, 2u },
    { UINT32_C(0xa500a000), CDISASM_ARM_NAME_LD1SH, 3322u, 8u, 2u },
    { UINT32_C(0xa520a000), CDISASM_ARM_NAME_LD1SH, 3323u, 4u, 2u },
    { UINT32_C(0xa540a000), CDISASM_ARM_NAME_LD1W, 3324u, 4u, 4u },
    { UINT32_C(0xa560a000), CDISASM_ARM_NAME_LD1W, 3325u, 8u, 4u },
    { UINT32_C(0xa580a000), CDISASM_ARM_NAME_LD1SB, 3326u, 8u, 1u },
    { UINT32_C(0xa5a0a000), CDISASM_ARM_NAME_LD1SB, 3327u, 4u, 1u },
    { UINT32_C(0xa5c0a000), CDISASM_ARM_NAME_LD1SB, 3328u, 2u, 1u },
    { UINT32_C(0xa5e0a000), CDISASM_ARM_NAME_LD1D, 3329u, 8u, 8u }
};

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
        UINT64_C(0xa400a000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void check_one(const load_desc *desc, unsigned imm4,
    unsigned pg, unsigned rn, unsigned zt)
{
    uint32_t word = desc->value | (imm4 << 16) | (pg << 10)
        | (rn << 5) | zt;
    int64_t displacement = imm4 < 8u
        ? (int64_t)imm4 : (int64_t)imm4 - INT64_C(16);
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == desc->name);
    EXPECT(instruction.form_id == desc->form);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_Z0 + zt);
    EXPECT(CDISASM_ARM_SCALABLE_LIST_COUNT(&instruction.operand[0]) == 1u);
    EXPECT(instruction.operand[0].extend_type == desc->destination_size);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].type == CDISASM_ARM_OPERAND_PREDICATE);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_P0 + pg);
    EXPECT(instruction.operand[1].extend_type == desc->destination_size);
    EXPECT(instruction.operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);
    EXPECT(instruction.operand[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[2].base_reg == (rn == 31u
        ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_X0 + rn));
    EXPECT(instruction.operand[2].size == desc->memory_size);
    EXPECT((int64_t)instruction.operand[2].imm == displacement);
    EXPECT(instruction.operand[2].flags == (displacement == 0
        ? 0u : CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
            | (displacement < 0 ? CDISASM_OPERAND_FLAG_SIGNED : 0u)));
#else
    (void)displacement;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_complete_domains(void)
{
    unsigned operation, imm4, pg, rn, zt;
    for (operation = 0; operation < sizeof(loads) / sizeof(loads[0]); ++operation)
        for (imm4 = 0; imm4 < 16; ++imm4)
            for (pg = 0; pg < 8; ++pg)
                for (rn = 0; rn < 32; ++rn)
                    for (zt = 0; zt < 32; ++zt)
                        check_one(&loads[operation], imm4, pg, rn, zt);
}

static void test_profiles_and_format(void)
{
    cdisasm_arm_instruction instruction;
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(UINT32_C(0xa428afe2), CDISASM_ARM_CPU_FUJITSU_A64FX,
        &instruction) == 4u);
    EXPECT(decode_word(UINT32_C(0xa428afe2), CDISASM_ARM_CPU_APPLE_M4,
        &instruction) == 4u);
    EXPECT(decode_word(UINT32_C(0xa428afe2), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
# if USE_DISASM_FORMAT
    {
        char text[96];
        EXPECT(decode_word(UINT32_C(0xa428afe2), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        (void)cdisasm_arm_format(&instruction, 0u, text, sizeof(text));
        EXPECT(strcmp(text, "ld1b {z2.h}, p3/z, [sp, #-0x8, mul vl]") == 0);
        instruction.form_id = 3314u;
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text)) == 0u);
        EXPECT(decode_word(UINT32_C(0xa428afe2), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        instruction.operand[2].flags &=
            (uint8_t)~CDISASM_ARM_OPERAND_FLAG_VL_SCALED;
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text)) == 0u);
        EXPECT(decode_word(UINT32_C(0xa428afe2), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        instruction.instruction_flags &=
            ~CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text)) == 0u);
        EXPECT(decode_word(UINT32_C(0xa488a861), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        (void)cdisasm_arm_format(&instruction, 0u, text, sizeof(text));
        EXPECT(strcmp(text, "ld1sw {z1.d}, p2/z, [x3, #-0x8, mul vl]") == 0);
    }
# endif
#else
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0xa428afe2), CDISASM_ARM_CPU_ANY,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

int main(void)
{
    test_complete_domains();
    test_profiles_and_format();
    if (failures) {
        fprintf(stderr, "%d SVE contiguous load test(s) failed\n", failures);
        return 1;
    }
    puts("ARM SVE contiguous immediate load tests passed (16 exact leaves; exhaustive imm4/predicate/base/register domains)");
    return 0;
}
