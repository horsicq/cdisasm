#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

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
        UINT64_C(0x296100), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

#if USE_EXTRA_OPCODES
static int zreg_matches(const cdisasm_arm_operand *operand, unsigned reg,
    uint8_t element, cdisasm_operand_access access)
{
    return operand->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER
        && operand->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + reg)
        && operand->extend_type == (cdisasm_arm_extend_type)element
        && operand->access == access;
}
#endif

static void test_complete_domain(void)
{
    static const struct operation {
        uint32_t zero_base, merge_base;
        cdisasm_arm_name_id name;
        cdisasm_arm_form_id zero_form, merge_form;
    } operations[] = {
        { 0x641c8000, 0x6510a000, CDISASM_ARM_NAME_FRINT32Z, 2961, 3124 },
        { 0x641ca000, 0x6511a000, CDISASM_ARM_NAME_FRINT32X, 2962, 3125 },
        { 0x641d8000, 0x6514a000, CDISASM_ARM_NAME_FRINT64Z, 2963, 3126 },
        { 0x641da000, 0x6515a000, CDISASM_ARM_NAME_FRINT64X, 2964, 3127 }
    };
    size_t operation;

    for (operation = 0u; operation < 4u; ++operation) {
        int zeroing;
        for (zeroing = 0; zeroing <= 1; ++zeroing) {
            unsigned is_double, pg, zn, zd;
            for (is_double = 0u; is_double <= 1u; ++is_double) {
                uint8_t element = is_double != 0u ? 8u : 4u;
#if !USE_EXTRA_OPCODES
                (void)element;
#endif
                uint32_t type = is_double == 0u ? 0u
                    : zeroing ? UINT32_C(0x00004000)
                              : UINT32_C(0x00020000);
                for (pg = 0u; pg < 8u; ++pg) {
                    for (zn = 0u; zn < 32u; ++zn) {
                        for (zd = 0u; zd < 32u; ++zd) {
                            cdisasm_arm_instruction instruction;
                            uint32_t word = (zeroing
                                ? operations[operation].zero_base
                                : operations[operation].merge_base)
                                | type | ((uint32_t)pg << 10)
                                | ((uint32_t)zn << 5) | zd;
                            memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                            EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                                &instruction) == 4u);
                            EXPECT(instruction.name_id
                                == operations[operation].name);
                            EXPECT(instruction.form_id == (zeroing
                                ? operations[operation].zero_form
                                : operations[operation].merge_form));
                            EXPECT(instruction.instruction_flags
                                == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                                    | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
                            EXPECT(instruction.operand_count == 3u);
                            EXPECT(zreg_matches(&instruction.operand[0], zd,
                                element, zeroing
                                    ? CDISASM_OPERAND_ACCESS_WRITE
                                    : CDISASM_OPERAND_ACCESS_READ_WRITE));
                            EXPECT(instruction.operand[1].type
                                == CDISASM_ARM_OPERAND_PREDICATE);
                            EXPECT(instruction.operand[1].reg
                                == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
                            EXPECT(instruction.operand[1].flags == (zeroing
                                ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
                                : CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE));
                            EXPECT(zreg_matches(&instruction.operand[2], zn,
                                element, CDISASM_OPERAND_ACCESS_READ));
#else
                            {
                                cdisasm_arm_instruction expected;
                                memset(&expected, 0, sizeof(expected));
                                expected.last_error_id =
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
                                EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                                    &instruction) == 0u);
                                EXPECT(memcmp(&instruction, &expected,
                                    sizeof(expected)) == 0);
                            }
#endif
                        }
                    }
                }
            }
        }
    }
}

static void test_profile_gate(void)
{
    cdisasm_arm_instruction instruction, expected;
    memset(&instruction, 0xa5, sizeof(instruction));
    memset(&expected, 0, sizeof(expected));
#if USE_EXTRA_OPCODES
    expected.last_error_id = CDISASM_STATUS_INVALID_INSTRUCTION;
#else
    expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    EXPECT(decode_word(UINT32_C(0x641c8883),
        CDISASM_ARM_CPU_CORTEX_A53, &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
}

int main(void)
{
    test_complete_domain();
    test_profile_gate();
    if (failures != 0) return 1;
    puts("SVE FRINTTS tests passed");
    return 0;
}
