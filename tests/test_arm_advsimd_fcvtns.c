#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_FCVTNS == UINT16_C(839),
               "FCVTNS name ID moved");

static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 32) fprintf(stderr, \
    "%s:%d: expectation failed: %s\n", __FILE__, __LINE__, #c); \
    ++failures; } } while (0)

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x578000),
        CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static int error_only(
    const cdisasm_arm_instruction *instruction, cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static void check_register(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint8_t size, uint8_t element_size, cdisasm_operand_access access)
{
    EXPECT(operand->type == CDISASM_OPERAND_REGISTER);
    EXPECT(operand->reg == reg);
    EXPECT(operand->size == size);
    EXPECT(operand->extend_type == (cdisasm_arm_extend_type)element_size);
    EXPECT(operand->scale == size / element_size);
    EXPECT(operand->access == access);
}
#endif

static void test_all_arrangements(void)
{
    static const struct arrangement {
        uint32_t base;
        cdisasm_arm_form_id form;
        cdisasm_arm_reg_id register_base;
        uint8_t size;
        uint8_t element_size;
    } arrangements[] = {
        { UINT32_C(0x5e21a800), UINT16_C(5780), CDISASM_ARM_REG_S0, 4u, 4u },
        { UINT32_C(0x5e61a800), UINT16_C(5780), CDISASM_ARM_REG_D0, 8u, 8u },
        { UINT32_C(0x0e21a800), UINT16_C(6021), CDISASM_ARM_REG_V0, 8u, 4u },
        { UINT32_C(0x4e21a800), UINT16_C(6021), CDISASM_ARM_REG_V0, 16u, 4u },
        { UINT32_C(0x4e61a800), UINT16_C(6021), CDISASM_ARM_REG_V0, 16u, 8u },
        { UINT32_C(0x0e79a800), UINT16_C(5948), CDISASM_ARM_REG_V0, 8u, 2u },
        { UINT32_C(0x4e79a800), UINT16_C(5948), CDISASM_ARM_REG_V0, 16u, 2u }
    };
    size_t arrangement;

    for (arrangement = 0u;
         arrangement < sizeof(arrangements) / sizeof(arrangements[0]);
         ++arrangement) {
        unsigned rn;
        for (rn = 0u; rn < 32u; ++rn) {
            unsigned rd;
            for (rd = 0u; rd < 32u; ++rd) {
                cdisasm_arm_instruction instruction;
                uint32_t word = arrangements[arrangement].base
                    | ((uint32_t)rn << 5) | rd;
                memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                    &instruction) == 4u);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == CDISASM_ARM_NAME_FCVTNS);
                EXPECT(instruction.form_id == arrangements[arrangement].form);
                EXPECT(instruction.operand_count == 2u);
                EXPECT(instruction.instruction_flags
                    == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                        | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
                check_register(&instruction.operand[0],
                    (cdisasm_arm_reg_id)(arrangements[arrangement].register_base + rd),
                    arrangements[arrangement].size,
                    arrangements[arrangement].element_size,
                    CDISASM_OPERAND_ACCESS_WRITE);
                check_register(&instruction.operand[1],
                    (cdisasm_arm_reg_id)(arrangements[arrangement].register_base + rn),
                    arrangements[arrangement].size,
                    arrangements[arrangement].element_size,
                    CDISASM_OPERAND_ACCESS_READ);
#else
                EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                    &instruction) == 0u);
                EXPECT(error_only(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            }
        }
    }
}

static void test_complete_rounding_family(void)
{
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_FCVTNS, CDISASM_ARM_NAME_FCVTMS,
        CDISASM_ARM_NAME_FCVTAS, CDISASM_ARM_NAME_FCVTPS,
        CDISASM_ARM_NAME_FCVTNU, CDISASM_ARM_NAME_FCVTMU,
        CDISASM_ARM_NAME_FCVTAU, CDISASM_ARM_NAME_FCVTPU
    };
    static const uint32_t scalar_bases[8] = {
        UINT32_C(0x5e61a800), UINT32_C(0x5e61b800),
        UINT32_C(0x5e61c800), UINT32_C(0x5ee1a800),
        UINT32_C(0x7e61a800), UINT32_C(0x7e61b800),
        UINT32_C(0x7e61c800), UINT32_C(0x7ee1a800)
    };
    static const uint32_t half_bases[8] = {
        UINT32_C(0x4e79a800), UINT32_C(0x4e79b800),
        UINT32_C(0x4e79c800), UINT32_C(0x4ef9a800),
        UINT32_C(0x6e79a800), UINT32_C(0x6e79b800),
        UINT32_C(0x6e79c800), UINT32_C(0x6ef9a800)
    };
    static const uint32_t vector_bases[8] = {
        UINT32_C(0x4e21a800), UINT32_C(0x4e21b800),
        UINT32_C(0x4e21c800), UINT32_C(0x4ea1a800),
        UINT32_C(0x6e21a800), UINT32_C(0x6e21b800),
        UINT32_C(0x6e21c800), UINT32_C(0x6ea1a800)
    };
    static const cdisasm_arm_form_id forms[3][8] = {
        { 5780, 5781, 5782, 5787, 5799, 5800, 5801, 5805 },
        { 5948, 5949, 5950, 5958, 5963, 5964, 5965, 5971 },
        { 6021, 6022, 6023, 6033, 6053, 6054, 6055, 6067 }
    };
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        const uint32_t bases[3] = {
            scalar_bases[operation], half_bases[operation],
            vector_bases[operation]
        };
        unsigned kind;

        for (kind = 0u; kind < 3u; ++kind) {
            cdisasm_arm_instruction instruction;
            uint32_t word = bases[kind] | UINT32_C(0xa3);

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                &instruction) == 4u);
            EXPECT(instruction.name_id == names[operation]);
            EXPECT(instruction.form_id == forms[kind][operation]);
            EXPECT(instruction.operand_count == 2u);
        }
    }
#endif
}

static void test_legality_profile_and_format(void)
{
    cdisasm_arm_instruction instruction;
    uint32_t invalid_1d = UINT32_C(0x0e61a8a3);
    uint32_t half = UINT32_C(0x4e79a8a3);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(invalid_1d, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(half, CDISASM_ARM_CPU_ANY, &instruction) == 4u);
#  if USE_DISASM_FORMAT
    {
        char text[64];
        EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) != 0u);
        EXPECT(strcmp(text, "fcvtns v3.8h, v5.8h") == 0);
    }
#  endif
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(half, CDISASM_ARM_CPU_CORTEX_A35,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
    EXPECT(decode_word(half, CDISASM_ARM_CPU_ANY, &instruction) == 0u);
    EXPECT(error_only(&instruction,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

int main(void)
{
    test_all_arrangements();
    test_complete_rounding_family();
    test_legality_profile_and_format();
    if (failures != 0) {
        fprintf(stderr, "%d Advanced SIMD FCVTNS test(s) failed\n", failures);
        return 1;
    }
    printf("Advanced SIMD FCVTNS tests passed (USE_EXTRA_OPCODES=%d)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
