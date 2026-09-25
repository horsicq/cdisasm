#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

typedef struct desc { uint32_t value; cdisasm_arm_name_id name;
    cdisasm_arm_form_id form; uint8_t memory_size, load, immediate; } desc;
static const desc forms[] = {
    { UINT32_C(0xa5102000), CDISASM_ARM_NAME_LD1W, 3275u, 4u, 1u, 1u },
    { UINT32_C(0xa5902000), CDISASM_ARM_NAME_LD1D, 3276u, 8u, 1u, 1u },
    { UINT32_C(0xa5008000), CDISASM_ARM_NAME_LD1W, 3309u, 4u, 1u, 0u },
    { UINT32_C(0xa5808000), CDISASM_ARM_NAME_LD1D, 3310u, 8u, 1u, 0u },
    { UINT32_C(0xe500e000), CDISASM_ARM_NAME_ST1W, 3529u, 4u, 0u, 1u },
    { UINT32_C(0xe5c0e000), CDISASM_ARM_NAME_ST1D, 3531u, 8u, 0u, 1u },
    { UINT32_C(0xe5004000), CDISASM_ARM_NAME_ST1W, 3472u, 4u, 0u, 0u },
    { UINT32_C(0xe5c04000), CDISASM_ARM_NAME_ST1D, 3474u, 8u, 0u, 0u }
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
        UINT64_C(0xa5102000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}
static int error_only(const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected)); expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}
static void check_one(const desc *form, unsigned payload, unsigned pg,
    unsigned rn, unsigned zt)
{
    uint32_t word = form->value | (payload << 16) | (pg << 10)
        | (rn << 5) | zt;
    int64_t displacement = payload < 8u ? (int64_t)payload
                                        : (int64_t)payload - INT64_C(16);
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    cdisasm_operand_access data_access = form->load
        ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
    cdisasm_operand_access memory_access = form->load
        ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == form->name && instruction.form_id == form->form);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_Z0 + zt);
    EXPECT(instruction.operand[0].extend_type == 16u);
    EXPECT(instruction.operand[0].access == data_access);
    EXPECT(instruction.operand[1].type == CDISASM_ARM_OPERAND_PREDICATE);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_P0 + pg);
    EXPECT(instruction.operand[1].extend_type == 16u);
    EXPECT(instruction.operand[1].flags == (form->load
        ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO : 0u));
    EXPECT(instruction.operand[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[2].base_reg == (rn == 31u
        ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_X0 + rn));
    EXPECT(instruction.operand[2].size == form->memory_size);
    EXPECT(instruction.operand[2].access == memory_access);
    if (form->immediate) {
        EXPECT((int64_t)instruction.operand[2].imm == displacement);
        EXPECT(instruction.operand[2].flags == (displacement == 0 ? 0u
            : CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
                | (displacement < 0 ? CDISASM_OPERAND_FLAG_SIGNED : 0u)));
    } else {
        EXPECT(instruction.operand[2].index_reg == (payload == 31u
            ? CDISASM_ARM_REG_XZR : CDISASM_ARM_REG_X0 + payload));
        EXPECT(instruction.operand[2].shift_type == CDISASM_ARM_SHIFT_LSL);
        EXPECT(instruction.operand[2].shift_amount
            == (form->memory_size == 4u ? 2u : 3u));
    }
#else
    (void)displacement;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
static void test_domains(void)
{
    unsigned f, payload, pg, rn, zt;
    for (f = 0; f < sizeof(forms) / sizeof(forms[0]); ++f)
        for (payload = 0; payload < (forms[f].immediate ? 16u : 32u); ++payload)
            for (pg = 0; pg < 8; ++pg) for (rn = 0; rn < 32; ++rn)
                for (zt = 0; zt < 32; ++zt)
                    check_one(&forms[f], payload, pg, rn, zt);
}
static void test_gates_and_format(void)
{
    cdisasm_arm_instruction instruction;
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(UINT32_C(0xa5982fe2), CDISASM_ARM_CPU_ANY,
        &instruction) == 4u);
    EXPECT(decode_word(UINT32_C(0xa5982fe2), CDISASM_ARM_CPU_FUJITSU_A64FX,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    EXPECT(decode_word(UINT32_C(0xa5982fe2), CDISASM_ARM_CPU_APPLE_M4,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
# if USE_DISASM_FORMAT
    {
        char text[96];
        EXPECT(decode_word(UINT32_C(0xa5982fe2), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        (void)cdisasm_arm_format(&instruction, 0u, text, sizeof(text));
        EXPECT(strcmp(text, "ld1d {z2.q}, p3/z, [sp, #-0x8, mul vl]") == 0);
        EXPECT(decode_word(UINT32_C(0xe5125a30), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        (void)cdisasm_arm_format(&instruction, 0u, text, sizeof(text));
        EXPECT(strcmp(text, "st1w {z16.q}, p6, [x17, x18, lsl #0x2]") == 0);
        instruction.form_id = 3474u;
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text)) == 0u);
        EXPECT(decode_word(UINT32_C(0xe5125a30), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        instruction.operand[0].extend_type = 8u;
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text)) == 0u);
    }
# endif
#else
    EXPECT(decode_word(UINT32_C(0xa5982fe2), CDISASM_ARM_CPU_ANY,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
int main(void)
{
    test_domains(); test_gates_and_format();
    if (failures) { fprintf(stderr, "%d SVE2.1 Q load/store test(s) failed\n",
        failures); return 1; }
    puts("ARM SVE2.1 Q-element load/store tests passed (8 exact leaves; exhaustive address payloads)");
    return 0;
}
