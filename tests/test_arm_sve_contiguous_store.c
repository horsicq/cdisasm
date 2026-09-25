#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

typedef struct store_desc { uint32_t value; cdisasm_arm_name_id name;
    cdisasm_arm_form_id form; uint8_t source_size, memory_size; } store_desc;
static const store_desc stores[] = {
    { UINT32_C(0xe400e000), CDISASM_ARM_NAME_ST1B, 3527u, 1u, 1u },
    { UINT32_C(0xe420e000), CDISASM_ARM_NAME_ST1B, 3527u, 2u, 1u },
    { UINT32_C(0xe440e000), CDISASM_ARM_NAME_ST1B, 3527u, 4u, 1u },
    { UINT32_C(0xe460e000), CDISASM_ARM_NAME_ST1B, 3527u, 8u, 1u },
    { UINT32_C(0xe4a0e000), CDISASM_ARM_NAME_ST1H, 3528u, 2u, 2u },
    { UINT32_C(0xe4c0e000), CDISASM_ARM_NAME_ST1H, 3528u, 4u, 2u },
    { UINT32_C(0xe4e0e000), CDISASM_ARM_NAME_ST1H, 3528u, 8u, 2u },
    { UINT32_C(0xe540e000), CDISASM_ARM_NAME_ST1W, 3530u, 4u, 4u },
    { UINT32_C(0xe560e000), CDISASM_ARM_NAME_ST1W, 3530u, 8u, 4u },
    { UINT32_C(0xe5e0e000), CDISASM_ARM_NAME_ST1D, 3532u, 8u, 8u }
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
        UINT64_C(0xe400e000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}
static int error_only(const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}
static void check_one(const store_desc *desc, unsigned imm4,
    unsigned pg, unsigned rn, unsigned zt)
{
    uint32_t word = desc->value | (imm4 << 16) | (pg << 10)
        | (rn << 5) | zt;
    int64_t displacement = imm4 < 8u ? (int64_t)imm4
                                     : (int64_t)imm4 - INT64_C(16);
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
    EXPECT(instruction.operand[0].extend_type == desc->source_size);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[1].type == CDISASM_ARM_OPERAND_PREDICATE);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_P0 + pg);
    EXPECT(instruction.operand[1].extend_type == desc->source_size);
    EXPECT(instruction.operand[1].flags == 0u);
    EXPECT(instruction.operand[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[2].base_reg == (rn == 31u
        ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_X0 + rn));
    EXPECT(instruction.operand[2].size == desc->memory_size);
    EXPECT((int64_t)instruction.operand[2].imm == displacement);
    EXPECT(instruction.operand[2].flags == (displacement == 0 ? 0u
        : CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
            | (displacement < 0 ? CDISASM_OPERAND_FLAG_SIGNED : 0u)));
    EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_WRITE);
#else
    (void)displacement;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
static void test_complete_domains(void)
{
    unsigned operation, imm4, pg, rn, zt;
    for (operation = 0; operation < sizeof(stores) / sizeof(stores[0]); ++operation)
        for (imm4 = 0; imm4 < 16; ++imm4)
            for (pg = 0; pg < 8; ++pg)
                for (rn = 0; rn < 32; ++rn)
                    for (zt = 0; zt < 32; ++zt)
                        check_one(&stores[operation], imm4, pg, rn, zt);
}
static void test_profiles_reserved_and_format(void)
{
    cdisasm_arm_instruction instruction;
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(UINT32_C(0xe428efe2), CDISASM_ARM_CPU_FUJITSU_A64FX,
        &instruction) == 4u);
    EXPECT(decode_word(UINT32_C(0xe428efe2), CDISASM_ARM_CPU_APPLE_M4,
        &instruction) == 4u);
    EXPECT(decode_word(UINT32_C(0xe428efe2), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    /* ST1H.B, ST1W.B/H and ST1D.B/H/S are not allocated. */
    {
        static const uint32_t reserved[] = { UINT32_C(0xe480e000),
            UINT32_C(0xe520e000), UINT32_C(0xe580e000),
            UINT32_C(0xe5a0e000) };
        unsigned i;
        for (i = 0; i < sizeof(reserved) / sizeof(reserved[0]); ++i) {
            EXPECT(decode_word(reserved[i], CDISASM_ARM_CPU_ANY,
                &instruction) == 0u);
            EXPECT(error_only(&instruction,
                CDISASM_STATUS_INVALID_INSTRUCTION));
        }
    }
# if USE_DISASM_FORMAT
    {
        char text[96];
        EXPECT(decode_word(UINT32_C(0xe428efe2), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        (void)cdisasm_arm_format(&instruction, 0u, text, sizeof(text));
        EXPECT(strcmp(text, "st1b {z2.h}, p3, [sp, #-0x8, mul vl]") == 0);
        instruction.form_id = 3528u;
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text)) == 0u);
        EXPECT(decode_word(UINT32_C(0xe428efe2), CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        instruction.operand[2].access = CDISASM_OPERAND_ACCESS_READ;
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text)) == 0u);
    }
# endif
#else
    EXPECT(decode_word(UINT32_C(0xe428efe2), CDISASM_ARM_CPU_ANY,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
int main(void)
{
    test_complete_domains();
    test_profiles_reserved_and_format();
    if (failures) { fprintf(stderr, "%d SVE contiguous store test(s) failed\n",
        failures); return 1; }
    puts("ARM SVE contiguous immediate store tests passed (4 exact forms; 10 arrangements; exhaustive domains)");
    return 0;
}
