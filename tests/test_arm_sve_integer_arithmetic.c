#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_SEL == UINT16_C(341),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_SQADD == UINT16_C(342),
               "SVE arithmetic IDs must be append-only");
_Static_assert(CDISASM_ARM_NAME_SUBPT == UINT16_C(347),
               "SVE arithmetic terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(421),
               "SVE arithmetic name count changed");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

typedef struct arithmetic_operation {
    cdisasm_arm_name_id name_id;
    const char *mnemonic;
    uint8_t size_mask;
} arithmetic_operation;

static const arithmetic_operation arithmetic_operations[8] = {
    { CDISASM_ARM_NAME_ADD, "add", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_SUB, "sub", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_ADDPT, "addpt", UINT8_C(0x08) },
    { CDISASM_ARM_NAME_SUBPT, "subpt", UINT8_C(0x08) },
    { CDISASM_ARM_NAME_SQADD, "sqadd", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_UQADD, "uqadd", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_SQSUB, "sqsub", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_UQSUB, "uqsub", UINT8_C(0x0f) }
};

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static uint32_t arithmetic_word(
    unsigned operation, unsigned size_code,
    unsigned zd, unsigned zn, unsigned zm)
{
    return UINT32_C(0x04200000)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)operation << 10)
        | ((uint32_t)zm << 16)
        | ((uint32_t)zn << 5)
        | (uint32_t)zd;
}

static void word_to_le(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)word;
    bytes[1] = (uint8_t)(word >> 8);
    bytes[2] = (uint8_t)(word >> 16);
    bytes[3] = (uint8_t)(word >> 24);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static uint32_t decode_word(
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    cdisasm_arm_decode_option options,
    size_t code_size,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x5000), options,
        instruction);
}

#if USE_EXTRA_OPCODES
static void expect_z_operand(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    uint8_t element_size,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.access = access;
    EXPECT(memcmp(operand, &expected, sizeof(expected)) == 0);
}

static void expect_success(
    unsigned operation,
    unsigned size_code,
    unsigned zd,
    unsigned zn,
    unsigned zm)
{
#if USE_DISASM_FORMAT
    static const char element_suffixes[4] = { 'b', 'h', 's', 'd' };
#endif
    cdisasm_arm_instruction instruction;
    uint32_t word = arithmetic_word(operation, size_code, zd, zn, zm);
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 4u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == arithmetic_operations[operation].name_id);
    EXPECT(instruction.address == UINT64_C(0x5000));
    EXPECT(instruction.raw_instruction == word);
    EXPECT(instruction.opcode_size == 4u);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_A64);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    expect_z_operand(
        &instruction.operand[0], zd, element_size,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_z_operand(
        &instruction.operand[1], zn, element_size,
        CDISASM_OPERAND_ACCESS_READ);
    expect_z_operand(
        &instruction.operand[2], zm, element_size,
        CDISASM_OPERAND_ACCESS_READ);

#if USE_DISASM_FORMAT
    {
        char expected[96];
        char text[96];
        int expected_size = snprintf(
            expected, sizeof(expected), "%s z%u.%c, z%u.%c, z%u.%c",
            arithmetic_operations[operation].mnemonic,
            zd, element_suffixes[size_code],
            zn, element_suffixes[size_code],
            zm, element_suffixes[size_code]);

        EXPECT(expected_size > 0);
        EXPECT((size_t)expected_size < sizeof(expected));
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == (size_t)expected_size);
        EXPECT(strcmp(text, expected) == 0);
    }
#endif
}
#endif

static void test_all_allocated_forms(void)
{
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            unsigned zd;
            unsigned zn;
            unsigned zm;

            if ((arithmetic_operations[operation].size_mask
                    & (UINT8_C(1) << size_code)) == 0u) {
                continue;
            }
            zd = operation + 1u;
            zn = operation + 9u;
            zm = operation + 17u;
#if USE_EXTRA_OPCODES
            expect_success(operation, size_code, zd, zn, zm);
#else
            cdisasm_arm_instruction instruction;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                arithmetic_word(operation, size_code, zd, zn, zm),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                CDISASM_ARM_DECODE_OPTION_NONE, 4u,
                &instruction) == 0u);
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static void test_reserved_widths_and_boundaries(void)
{
    cdisasm_arm_instruction instruction;
    unsigned operation;
    unsigned size_code;
    static const uint8_t big_endian_sqadd[4] = {
        UINT8_C(0x04), UINT8_C(0xa8), UINT8_C(0x10), UINT8_C(0xe6)
    };

    for (operation = 2u; operation <= 3u; ++operation) {
        for (size_code = 0u; size_code < 3u; ++size_code) {
            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                arithmetic_word(operation, size_code, 0u, 1u, 2u),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                CDISASM_ARM_DECODE_OPTION_NONE, 4u,
                &instruction) == 0u);
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        }
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        arithmetic_word(4u, 2u, 6u, 7u, 8u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 3u, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_TRUNCATED));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        arithmetic_word(4u, 2u, 6u, 7u, 8u),
        CDISASM_ARM_CPU_CORTEX_A53, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
#if USE_EXTRA_OPCODES
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        arithmetic_word(4u, 2u, 6u, 7u, 8u),
        CDISASM_ARM_CPU_CORTEX_A34, CDISASM_ARM_MODE_A32,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        arithmetic_word(4u, 2u, 6u, 7u, 8u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        UINT64_C(1) << 63, 4u, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        big_endian_sqadd, sizeof(big_endian_sqadd), UINT64_C(0x5000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SQADD);
#else
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        big_endian_sqadd, sizeof(big_endian_sqadd), UINT64_C(0x5000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_sve_or_sme_cpu_gates(void)
{
    static const cdisasm_arm_cpu_id sme_only_cpus[] = {
        CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_ARM_CPU_APPLE_M4
    };
    static const unsigned sve_or_sme_operations[] = {
        0u, 1u, 4u, 5u, 6u, 7u
    };
    cdisasm_arm_instruction instruction;
    size_t cpu_index;

    for (cpu_index = 0u;
         cpu_index < sizeof(sme_only_cpus) / sizeof(sme_only_cpus[0]);
         ++cpu_index) {
        size_t operation_index;

        for (operation_index = 0u;
             operation_index < sizeof(sve_or_sme_operations)
                 / sizeof(sve_or_sme_operations[0]);
             ++operation_index) {
            unsigned operation = sve_or_sme_operations[operation_index];

            memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
            EXPECT(decode_word(
                arithmetic_word(operation, operation & 3u, 1u, 2u, 3u),
                sme_only_cpus[cpu_index], CDISASM_ARM_MODE_A64,
                CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 4u);
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id
                == arithmetic_operations[operation].name_id);
#else
            EXPECT(decode_word(
                arithmetic_word(operation, operation & 3u, 1u, 2u, 3u),
                sme_only_cpus[cpu_index], CDISASM_ARM_MODE_A64,
                CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }

        for (operation_index = 2u; operation_index <= 3u;
             ++operation_index) {
            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                arithmetic_word(
                    (unsigned)operation_index, 3u, 4u, 5u, 6u),
                sme_only_cpus[cpu_index], CDISASM_ARM_MODE_A64,
                CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
#if USE_EXTRA_OPCODES
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static uint32_t address_word(unsigned variant, unsigned amount,
    unsigned zd, unsigned zn, unsigned zm)
{
    static const uint32_t bases[4] = {
        UINT32_C(0x0420a000), UINT32_C(0x0460a000),
        UINT32_C(0x04a0a000), UINT32_C(0x04e0a000)
    };
    return bases[variant] | ((uint32_t)zm << 16)
        | ((uint32_t)amount << 10) | ((uint32_t)zn << 5) | zd;
}

static void test_sve_address_generation(void)
{
    cdisasm_arm_instruction instruction;
    unsigned variant, amount, zd, zn, zm;

    for (variant = 0u; variant < 4u; ++variant)
        for (amount = 0u; amount < 4u; ++amount)
            for (zd = 0u; zd < 32u; ++zd)
                for (zn = 0u; zn < 32u; ++zn)
                    for (zm = 0u; zm < 32u; ++zm) {
                        uint32_t word = address_word(variant, amount, zd, zn, zm);
                        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE,
                            4u, &instruction) == 4u);
                        EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADR);
                        EXPECT(instruction.form_id == (variant == 0u ? 2338u
                            : variant == 1u ? 2339u : 2340u));
                        EXPECT(instruction.instruction_flags
                            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
                        EXPECT(instruction.operand_count == 2u);
                        EXPECT(instruction.operand[0].type
                            == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
                        EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_Z0 + zd);
                        EXPECT(instruction.operand[0].extend_type
                            == (variant < 2u || variant == 3u ? 8u : 4u));
                        EXPECT(instruction.operand[0].access
                            == CDISASM_OPERAND_ACCESS_WRITE);
                        EXPECT(instruction.operand[1].type == CDISASM_OPERAND_MEMORY);
                        EXPECT(instruction.operand[1].base_reg == CDISASM_ARM_REG_Z0 + zn);
                        EXPECT(instruction.operand[1].index_reg == CDISASM_ARM_REG_Z0 + zm);
                        EXPECT(instruction.operand[1].size
                            == (variant < 2u || variant == 3u ? 8u : 4u));
                        EXPECT(instruction.operand[1].access
                            == CDISASM_OPERAND_ACCESS_READ);
                        if (variant < 2u) {
                            EXPECT(instruction.operand[1].extend_type
                                == (variant == 0u ? CDISASM_ARM_EXTEND_SXTW
                                                 : CDISASM_ARM_EXTEND_UXTW));
                            EXPECT(instruction.operand[1].scale == amount);
                        } else {
                            EXPECT(instruction.operand[1].extend_type
                                == CDISASM_ARM_EXTEND_NONE);
                            EXPECT(instruction.operand[1].shift_type == (amount == 0u
                                ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL));
                            EXPECT(instruction.operand[1].shift_amount == amount);
                        }
#else
                        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE,
                            4u, &instruction) == 0u);
                        EXPECT(instruction_is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    }
#if USE_EXTRA_OPCODES
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(address_word(0u, 0u, 0u, 1u, 2u),
        CDISASM_ARM_CPU_CORTEX_A53, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
#if USE_DISASM_FORMAT
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(address_word(1u, 3u, 3u, 4u, 5u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 4u);
    { char text[96]; EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_0, text, sizeof(text)) != 0u);
      EXPECT(strcmp(text, "adr z3.d, [z4.d, z5.d, uxtw #0x3]") == 0); }
#endif
#endif
}

int main(void)
{
    test_all_allocated_forms();
    test_reserved_widths_and_boundaries();
    test_sve_or_sme_cpu_gates();
    test_sve_address_generation();

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE arithmetic test(s) failed\n", failures);
        return 1;
    }
    printf("ARM SVE integer-arithmetic tests passed "
           "(USE_EXTRA_OPCODES=%d)\n", USE_EXTRA_OPCODES);
    return 0;
}
