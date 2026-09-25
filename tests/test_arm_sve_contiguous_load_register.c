#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

typedef struct load_desc { uint32_t value; cdisasm_arm_name_id name;
    cdisasm_arm_form_id form; uint8_t destination_size, memory_size; } load_desc;
static const load_desc loads[] = {
    { UINT32_C(0xa4004000), CDISASM_ARM_NAME_LD1B, 3277u, 1u, 1u },
    { UINT32_C(0xa4204000), CDISASM_ARM_NAME_LD1B, 3278u, 2u, 1u },
    { UINT32_C(0xa4404000), CDISASM_ARM_NAME_LD1B, 3279u, 4u, 1u },
    { UINT32_C(0xa4604000), CDISASM_ARM_NAME_LD1B, 3280u, 8u, 1u },
    { UINT32_C(0xa4804000), CDISASM_ARM_NAME_LD1SW, 3281u, 8u, 4u },
    { UINT32_C(0xa4a04000), CDISASM_ARM_NAME_LD1H, 3282u, 2u, 2u },
    { UINT32_C(0xa4c04000), CDISASM_ARM_NAME_LD1H, 3283u, 4u, 2u },
    { UINT32_C(0xa4e04000), CDISASM_ARM_NAME_LD1H, 3284u, 8u, 2u },
    { UINT32_C(0xa5004000), CDISASM_ARM_NAME_LD1SH, 3285u, 8u, 2u },
    { UINT32_C(0xa5204000), CDISASM_ARM_NAME_LD1SH, 3286u, 4u, 2u },
    { UINT32_C(0xa5404000), CDISASM_ARM_NAME_LD1W, 3287u, 4u, 4u },
    { UINT32_C(0xa5604000), CDISASM_ARM_NAME_LD1W, 3288u, 8u, 4u },
    { UINT32_C(0xa5804000), CDISASM_ARM_NAME_LD1SB, 3289u, 8u, 1u },
    { UINT32_C(0xa5a04000), CDISASM_ARM_NAME_LD1SB, 3290u, 4u, 1u },
    { UINT32_C(0xa5c04000), CDISASM_ARM_NAME_LD1SB, 3291u, 2u, 1u },
    { UINT32_C(0xa5e04000), CDISASM_ARM_NAME_LD1D, 3292u, 8u, 8u }
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
        UINT64_C(0xa4004000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}
static int error_only(const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected)); expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}
static void check_one(const load_desc *desc, unsigned xm,
    unsigned pg, unsigned rn, unsigned zt)
{
    uint32_t word = desc->value | (xm << 16) | (pg << 10) | (rn << 5) | zt;
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
    if (xm == 31u) {
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        return;
    }
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
    EXPECT(instruction.operand[2].index_reg == CDISASM_ARM_REG_X0 + xm);
    EXPECT(instruction.operand[2].size == desc->memory_size);
    EXPECT(instruction.operand[2].shift_type == (desc->memory_size == 1u
        ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL));
    EXPECT(instruction.operand[2].shift_amount == (desc->memory_size == 1u
        ? 0u : desc->memory_size == 2u ? 1u
            : desc->memory_size == 4u ? 2u : 3u));
    EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
static void test_complete_domains(void)
{
    unsigned operation, xm, pg, rn, zt;
    for (operation = 0; operation < sizeof(loads) / sizeof(loads[0]); ++operation)
        for (xm = 0; xm < 32; ++xm) for (pg = 0; pg < 8; ++pg)
            for (rn = 0; rn < 32; ++rn) for (zt = 0; zt < 32; ++zt)
                check_one(&loads[operation], xm, pg, rn, zt);
}
static void test_profiles_and_format(void)
{
    cdisasm_arm_instruction instruction;
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(UINT32_C(0xa4ad518b), CDISASM_ARM_CPU_FUJITSU_A64FX,
        &instruction) == 4u);
    EXPECT(decode_word(UINT32_C(0xa4ad518b), CDISASM_ARM_CPU_APPLE_M4,
        &instruction) == 4u);
    EXPECT(decode_word(UINT32_C(0xa4ad518b), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
# if USE_DISASM_FORMAT
    {
        char text[96];
        EXPECT(decode_word(UINT32_C(0xa4ad518b), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        (void)cdisasm_arm_format(&instruction, 0u, text, sizeof(text));
        EXPECT(strcmp(text, "ld1h {z11.h}, p4/z, [x12, x13, lsl #0x1]") == 0);
        instruction.form_id = 3283u;
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text)) == 0u);
        EXPECT(decode_word(UINT32_C(0xa4ad518b), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        instruction.operand[2].shift_amount = 0u;
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text)) == 0u);
        EXPECT(decode_word(UINT32_C(0xa4844861), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        (void)cdisasm_arm_format(&instruction, 0u, text, sizeof(text));
        EXPECT(strcmp(text, "ld1sw {z1.d}, p2/z, [x3, x4, lsl #0x2]") == 0);
        EXPECT(decode_word(UINT32_C(0xa49f4000), CDISASM_ARM_CPU_ANY,
            &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    }
# endif
#else
    EXPECT(decode_word(UINT32_C(0xa4ad518b), CDISASM_ARM_CPU_ANY,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
int main(void)
{
    test_complete_domains(); test_profiles_and_format();
    if (failures) { fprintf(stderr, "%d SVE register-offset load test(s) failed\n",
        failures); return 1; }
    puts("ARM SVE register-offset contiguous load tests passed (16 exact leaves; exhaustive payload domains)");
    return 0;
}
