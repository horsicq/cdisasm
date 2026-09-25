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
        UINT64_C(0x64a01000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void check_indexed(int single, unsigned encoded_zm,
    unsigned rotation, unsigned zn, unsigned zda)
{
    uint32_t word = (single ? UINT32_C(0x64e01000) : UINT32_C(0x64a01000))
        | (encoded_zm << 16) | (rotation << 10) | (zn << 5) | zda;
    cdisasm_arm_instruction instruction;
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    unsigned reg = single ? (encoded_zm & 15u) : (encoded_zm & 7u);
    unsigned lane = single ? (encoded_zm >> 4) : (encoded_zm >> 3);
    unsigned element_size = single ? 4u : 2u;
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_FCMLA);
    EXPECT(instruction.form_id == (single ? 3003u : 3002u));
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    EXPECT(instruction.operand_count == 4u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_Z0 + zda);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_Z0 + zn);
    EXPECT(instruction.operand[2].reg == CDISASM_ARM_REG_Z0 + reg);
    EXPECT(instruction.operand[0].extend_type == element_size);
    EXPECT(instruction.operand[1].extend_type == element_size);
    EXPECT(instruction.operand[2].extend_type == element_size);
    EXPECT(instruction.operand[2].flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    EXPECT(instruction.operand[2].imm == lane);
    EXPECT(instruction.operand[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction.operand[3].imm == rotation * 90u);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_complete_domains(void)
{
    unsigned single, zm, rotation, zn, zd;
    for (single = 0u; single < 2u; ++single)
        for (zm = 0u; zm < 32u; ++zm)
            for (rotation = 0u; rotation < 4u; ++rotation)
                for (zn = 0u; zn < 32u; ++zn)
                    for (zd = 0u; zd < 32u; ++zd)
                        check_indexed((int)single, zm, rotation, zn, zd);
}

static void test_profiles_and_format(void)
{
    cdisasm_arm_instruction instruction;
    uint32_t word = UINT32_C(0x64ff1dcd);
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        &instruction) == 4u);
    EXPECT(decode_word(word, CDISASM_ARM_CPU_APPLE_M4,
        &instruction) == 4u);
    EXPECT(decode_word(word, CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
# if USE_DISASM_FORMAT
    {
        char text[96];
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("fcmla z13.s, z14.s, z15.s[1], #270"));
        EXPECT(strcmp(text, "fcmla z13.s, z14.s, z15.s[1], #270") == 0);
    }
# endif
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_predicated_complete_domains(void)
{
    cdisasm_arm_instruction instruction;
    unsigned size_code, rotation, pg, zd, zn, zm;
    for (size_code = 1u; size_code < 4u; ++size_code)
        for (rotation = 0u; rotation < 4u; ++rotation)
            for (pg = 0u; pg < 8u; ++pg)
                for (zd = 0u; zd < 32u; ++zd)
                    for (zn = 0u; zn < 32u; ++zn)
                        for (zm = 0u; zm < 32u; ++zm) {
                            uint32_t word = UINT32_C(0x64000000)
                                | ((uint32_t)size_code << 22)
                                | ((uint32_t)zm << 16)
                                | ((uint32_t)rotation << 13)
                                | ((uint32_t)pg << 10)
                                | ((uint32_t)zn << 5) | zd;
                            memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                            EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                                &instruction) == 4u);
                            EXPECT(instruction.name_id == CDISASM_ARM_NAME_FCMLA);
                            EXPECT(instruction.form_id == 2920u);
                            EXPECT(instruction.instruction_flags
                                == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                                    | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
                            EXPECT(instruction.operand_count == 4u);
                            EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_Z0 + zd);
                            EXPECT(instruction.operand[0].access
                                == CDISASM_OPERAND_ACCESS_READ_WRITE);
                            EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_P0 + pg);
                            EXPECT(instruction.operand[1].flags
                                == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
                            EXPECT(instruction.operand[2].reg == CDISASM_ARM_REG_Z0 + zn);
                            EXPECT(instruction.operand[3].reg == CDISASM_ARM_REG_Z0 + zm);
                            EXPECT(instruction.operand[3].flags
                                == CDISASM_ARM_OPERAND_FLAG_HAS_ROTATION);
                            EXPECT(instruction.operand[3].imm == rotation * 90u);
#else
                            EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                                &instruction) == 0u);
                            EXPECT(error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        }
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x64000000), CDISASM_ARM_CPU_ANY,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(UINT32_C(0x64852483), CDISASM_ARM_CPU_FUJITSU_A64FX,
        &instruction) == 4u);
    EXPECT(decode_word(UINT32_C(0x64852483), CDISASM_ARM_CPU_APPLE_M4,
        &instruction) == 4u);
    EXPECT(decode_word(UINT32_C(0x64852483), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
# if USE_DISASM_FORMAT
    EXPECT(decode_word(UINT32_C(0x64852483), CDISASM_ARM_CPU_ANY,
        &instruction) == 4u);
    { char text[96]; EXPECT(cdisasm_arm_format(&instruction, 0u, text,
        sizeof(text)) == strlen("fcmla z3.s, p1/m, z4.s, z5.s, #90"));
      EXPECT(strcmp(text, "fcmla z3.s, p1/m, z4.s, z5.s, #90") == 0);
      instruction.operand[3].imm = 45u;
      EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text)) == 0u); }
# endif
#endif
}

int main(void)
{
    test_complete_domains();
    test_profiles_and_format();
    test_predicated_complete_domains();
    if (failures != 0) return 1;
    puts("SVE indexed FCMLA tests passed");
    return 0;
}
