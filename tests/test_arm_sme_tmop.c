#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

typedef struct tmop_case {
    uint32_t value;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    uint8_t destination_size;
    uint8_t source_size;
} tmop_case;

static const tmop_case cases[] = {
    { UINT32_C(0x80400000), 3772u, CDISASM_ARM_NAME_FTMOPA, 4u, 4u },
    { UINT32_C(0x80408000), 3776u, CDISASM_ARM_NAME_STMOPA, 4u, 1u },
    { UINT32_C(0x80408008), 3783u, CDISASM_ARM_NAME_STMOPA, 4u, 2u },
    { UINT32_C(0x80600000), 3773u, CDISASM_ARM_NAME_FTMOPA, 4u, 1u },
    { UINT32_C(0x80600008), 3780u, CDISASM_ARM_NAME_FTMOPA, 2u, 1u },
    { UINT32_C(0x80608000), 3777u, CDISASM_ARM_NAME_SUTMOPA, 4u, 1u },
    { UINT32_C(0x81400000), 3774u, CDISASM_ARM_NAME_BFTMOPA, 4u, 2u },
    { UINT32_C(0x81400008), 3781u, CDISASM_ARM_NAME_FTMOPA, 2u, 2u },
    { UINT32_C(0x81408000), 3778u, CDISASM_ARM_NAME_USTMOPA, 4u, 1u },
    { UINT32_C(0x81408008), 3784u, CDISASM_ARM_NAME_UTMOPA, 4u, 2u },
    { UINT32_C(0x81600000), 3775u, CDISASM_ARM_NAME_FTMOPA, 4u, 2u },
    { UINT32_C(0x81600008), 3782u, CDISASM_ARM_NAME_BFTMOPA, 2u, 2u },
    { UINT32_C(0x81608000), 3779u, CDISASM_ARM_NAME_UTMOPA, 4u, 1u }
};

static int failures;
#define CHECK(expr) do { \
    if (!(expr)) { \
        if (failures < 20) fprintf(stderr, "%d: %s\n", __LINE__, #expr); \
        ++failures; \
    } \
} while (0)

static uint32_t decode(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = {
        (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24)
    };
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), 0u, 0u, instruction);
}

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;
        uint32_t word = cases[index].value
            | (UINT32_C(6) << 16) /* Zm */
            | (UINT32_C(1) << 12) /* K */
            | (UINT32_C(2) << 10) /* Zk */
            | (UINT32_C(3) << 6)  /* Zn: Z6-Z7 */
            | (UINT32_C(2) << 4)  /* control segment */
            | UINT32_C(1);       /* ZA tile */
#if USE_EXTRA_OPCODES
        CHECK(decode(word, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
        CHECK(instruction.name_id == cases[index].name_id);
        CHECK(instruction.form_id == cases[index].form_id);
        CHECK(instruction.operand_count == 4u);
        CHECK(instruction.operand[0].type == CDISASM_ARM_OPERAND_TILE);
        CHECK(instruction.operand[0].reg ==
            (cdisasm_arm_reg_id)((cases[index].destination_size == 2u
                ? CDISASM_ARM_REG_ZAH0 : CDISASM_ARM_REG_ZAS0) + 1u));
        CHECK(instruction.operand[1].type ==
            CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
        CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_Z6);
        CHECK(instruction.operand[1].register_list == UINT16_C(0x0102));
        CHECK(instruction.operand[1].extend_type == cases[index].source_size);
        CHECK(instruction.operand[2].reg == CDISASM_ARM_REG_Z6);
        CHECK(instruction.operand[2].extend_type == cases[index].source_size);
        CHECK(instruction.operand[3].reg == CDISASM_ARM_REG_Z30);
        CHECK(instruction.operand[3].extend_type == 0u);
        CHECK(instruction.operand[3].flags ==
            CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
        CHECK(instruction.operand[3].imm == 2u);
#if USE_DISASM_FORMAT
        {
            char formatted[128];
            CHECK(cdisasm_arm_format(&instruction, 0u,
                formatted, sizeof(formatted)) != 0u);
            if (index == 0u) {
                cdisasm_arm_instruction malformed = instruction;

                CHECK(strcmp(formatted,
                    "ftmopa za1.s, {z6.s, z7.s}, z6.s, z30[2]") == 0);
                malformed.operand[3].reg = CDISASM_ARM_REG_Z29;
                CHECK(cdisasm_arm_format(&malformed, 0u,
                    formatted, sizeof(formatted)) == 0u);
                malformed = instruction;
                malformed.operand[1].extend_type = 2u;
                CHECK(cdisasm_arm_format(&malformed, 0u,
                    formatted, sizeof(formatted)) == 0u);
            }
        }
#endif
        CHECK(decode(word, CDISASM_ARM_CPU_CORTEX_A53, &instruction) == 0u);
        CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CHECK(decode(word, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
        CHECK(instruction.last_error_id ==
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
    if (failures != 0) {
        fprintf(stderr, "%d SME TMOP failures\n", failures);
        return 1;
    }
    puts("ARM SME TMOP tests passed");
    return 0;
}
