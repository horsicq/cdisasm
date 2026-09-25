#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

typedef struct desc { uint32_t value; cdisasm_arm_name_id name;
    cdisasm_arm_form_id form; uint8_t source_size, memory_size; } desc;
static const desc forms[] = {
    { UINT32_C(0xe4004000), CDISASM_ARM_NAME_ST1B, 3470u, 1u, 1u },
    { UINT32_C(0xe4204000), CDISASM_ARM_NAME_ST1B, 3470u, 2u, 1u },
    { UINT32_C(0xe4404000), CDISASM_ARM_NAME_ST1B, 3470u, 4u, 1u },
    { UINT32_C(0xe4604000), CDISASM_ARM_NAME_ST1B, 3470u, 8u, 1u },
    { UINT32_C(0xe4a04000), CDISASM_ARM_NAME_ST1H, 3471u, 2u, 2u },
    { UINT32_C(0xe4c04000), CDISASM_ARM_NAME_ST1H, 3471u, 4u, 2u },
    { UINT32_C(0xe4e04000), CDISASM_ARM_NAME_ST1H, 3471u, 8u, 2u },
    { UINT32_C(0xe5404000), CDISASM_ARM_NAME_ST1W, 3473u, 4u, 4u },
    { UINT32_C(0xe5604000), CDISASM_ARM_NAME_ST1W, 3473u, 8u, 4u },
    { UINT32_C(0xe5e04000), CDISASM_ARM_NAME_ST1D, 3475u, 8u, 8u }
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
        UINT64_C(0xe4004000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}
static int error_only(const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected)); expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}
static void check_one(const desc *form, unsigned xm, unsigned pg,
    unsigned rn, unsigned zt)
{
    uint32_t word = form->value | (xm << 16) | (pg << 10) | (rn << 5) | zt;
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
    if (xm == 31u) {
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        return;
    }
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == form->name && instruction.form_id == form->form);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_Z0 + zt);
    EXPECT(instruction.operand[0].extend_type == form->source_size);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[1].type == CDISASM_ARM_OPERAND_PREDICATE);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_P0 + pg);
    EXPECT(instruction.operand[1].extend_type == form->source_size);
    EXPECT(instruction.operand[1].flags == 0u);
    EXPECT(instruction.operand[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[2].base_reg == (rn == 31u
        ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_X0 + rn));
    EXPECT(instruction.operand[2].index_reg == CDISASM_ARM_REG_X0 + xm);
    EXPECT(instruction.operand[2].size == form->memory_size);
    EXPECT(instruction.operand[2].shift_type == (form->memory_size == 1u
        ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL));
    EXPECT(instruction.operand[2].shift_amount == (form->memory_size == 1u
        ? 0u : form->memory_size == 2u ? 1u
            : form->memory_size == 4u ? 2u : 3u));
    EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_WRITE);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
static void test_domains(void)
{
    unsigned f, xm, pg, rn, zt;
    for (f = 0; f < sizeof(forms) / sizeof(forms[0]); ++f)
        for (xm = 0; xm < 32; ++xm) for (pg = 0; pg < 8; ++pg)
            for (rn = 0; rn < 32; ++rn) for (zt = 0; zt < 32; ++zt)
                check_one(&forms[f], xm, pg, rn, zt);
}
static void test_edges(void)
{
    cdisasm_arm_instruction instruction;
#if USE_EXTRA_OPCODES
    static const uint32_t reserved[] = { UINT32_C(0xe4804000),
        UINT32_C(0xe5204000) };
    unsigned i;
    EXPECT(decode_word(UINT32_C(0xe4ad518b), CDISASM_ARM_CPU_FUJITSU_A64FX,
        &instruction) == 4u);
    EXPECT(decode_word(UINT32_C(0xe4ad518b), CDISASM_ARM_CPU_APPLE_M4,
        &instruction) == 4u);
    EXPECT(decode_word(UINT32_C(0xe4ad518b), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    for (i = 0; i < sizeof(reserved) / sizeof(reserved[0]); ++i) {
        EXPECT(decode_word(reserved[i], CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    }
# if USE_DISASM_FORMAT
    {
        char text[96];
        EXPECT(decode_word(UINT32_C(0xe4ad518b), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        (void)cdisasm_arm_format(&instruction, 0u, text, sizeof(text));
        EXPECT(strcmp(text, "st1h {z11.h}, p4, [x12, x13, lsl #0x1]") == 0);
        instruction.form_id = 3473u;
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text)) == 0u);
        EXPECT(decode_word(UINT32_C(0xe4ad518b), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        instruction.operand[2].shift_amount = 0u;
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text)) == 0u);
    }
# endif
#else
    EXPECT(decode_word(UINT32_C(0xe4ad518b), CDISASM_ARM_CPU_ANY,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
int main(void)
{
    test_domains(); test_edges();
    if (failures) { fprintf(stderr, "%d SVE register-offset store test(s) failed\n",
        failures); return 1; }
    puts("ARM SVE register-offset contiguous store tests passed (4 exact forms; 10 arrangements; exhaustive domains)");
    return 0;
}
