#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(c) do { if (!(c)) { if (failures < 24) fprintf(stderr, \
    "%s:%d: expectation failed: %s\n", __FILE__, __LINE__, #c); \
    ++failures; } } while (0)

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };

    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x599500),
        CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

#if USE_EXTRA_OPCODES
static void check_vector(
    const cdisasm_arm_operand *operand, unsigned reg,
    uint8_t element_size, cdisasm_operand_access access)
{
    EXPECT(operand->type == CDISASM_OPERAND_REGISTER);
    EXPECT(operand->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + reg));
    EXPECT(operand->size == 16u);
    EXPECT(operand->extend_type == (cdisasm_arm_extend_type)element_size);
    EXPECT(operand->scale == 16u / element_size);
    EXPECT(operand->access == access);
}
#endif

static void test_complete_register_domain(void)
{
    static const struct operation {
        uint32_t base;
        cdisasm_arm_name_id name;
        cdisasm_arm_form_id form;
        const char *mnemonic;
    } operations[] = {
        { UINT32_C(0x4e80a400), CDISASM_ARM_NAME_SMMLA, UINT16_C(5994), "smmla" },
        { UINT32_C(0x4e80ac00), CDISASM_ARM_NAME_USMMLA, UINT16_C(5995), "usmmla" },
        { UINT32_C(0x6e80a400), CDISASM_ARM_NAME_UMMLA, UINT16_C(6002), "ummla" }
    };
    size_t operation;

    for (operation = 0u;
         operation < sizeof(operations) / sizeof(operations[0]);
         ++operation) {
        unsigned rm;
        for (rm = 0u; rm < 32u; ++rm) {
            unsigned rn;
            for (rn = 0u; rn < 32u; ++rn) {
                unsigned rd;
                for (rd = 0u; rd < 32u; ++rd) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = operations[operation].base
                        | ((uint32_t)rm << 16)
                        | ((uint32_t)rn << 5) | rd;

                    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                        &instruction) == 4u);
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id == operations[operation].name);
                    EXPECT(instruction.form_id == operations[operation].form);
                    EXPECT(instruction.instruction_flags
                        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
                    EXPECT(instruction.operand_count == 3u);
                    check_vector(&instruction.operand[0], rd, 4u,
                        CDISASM_OPERAND_ACCESS_READ_WRITE);
                    check_vector(&instruction.operand[1], rn, 1u,
                        CDISASM_OPERAND_ACCESS_READ);
                    check_vector(&instruction.operand[2], rm, 1u,
                        CDISASM_OPERAND_ACCESS_READ);
#if USE_DISASM_FORMAT
                    if (rd == 0u && rn == 1u && rm == 2u) {
                        char text[96], expected_text[96];
                        (void)snprintf(expected_text, sizeof(expected_text),
                            "%s v0.4s, v1.16b, v2.16b",
                            operations[operation].mnemonic);
                        EXPECT(cdisasm_arm_format(&instruction, 0u,
                            text, sizeof(text)) == strlen(expected_text));
                        EXPECT(strcmp(text, expected_text) == 0);
                    }
#endif
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

static void test_feature_gate(void)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction expected;

    memset(&instruction, 0xa5, sizeof(instruction));
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id =
#if USE_EXTRA_OPCODES
        CDISASM_STATUS_INVALID_INSTRUCTION;
#else
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    EXPECT(decode_word(UINT32_C(0x4e85ac83),
        CDISASM_ARM_CPU_CORTEX_A53, &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
}

int main(void)
{
    test_complete_register_domain();
    test_feature_gate();
    if (failures != 0) {
        fprintf(stderr, "Advanced SIMD I8MM MMLA failures: %d\n", failures);
        return 1;
    }
    puts("Advanced SIMD I8MM MMLA tests passed");
    return 0;
}
