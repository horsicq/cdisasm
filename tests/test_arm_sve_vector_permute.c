#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_CPU_APPLE_S10
                   == (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0025)),
               "existing Apple CPU IDs moved");
_Static_assert(CDISASM_ARM_CPU_FUJITSU_A64FX
                   == (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0026)),
               "A64FX CPU ID changed");
_Static_assert(CDISASM_ARM_NAME_SUBPT == UINT16_C(347),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_ZIP1 == UINT16_C(348),
               "SVE permute IDs must be append-only");
_Static_assert(CDISASM_ARM_NAME_TRN2 == UINT16_C(353),
               "SVE permute terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(421),
               "SVE permute name count changed");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

#if USE_EXTRA_OPCODES
typedef struct permute_operation {
    cdisasm_arm_name_id name_id;
    const char *mnemonic;
} permute_operation;

static const permute_operation permute_operations[6] = {
    { CDISASM_ARM_NAME_ZIP1, "zip1" },
    { CDISASM_ARM_NAME_ZIP2, "zip2" },
    { CDISASM_ARM_NAME_UZP1, "uzp1" },
    { CDISASM_ARM_NAME_UZP2, "uzp2" },
    { CDISASM_ARM_NAME_TRN1, "trn1" },
    { CDISASM_ARM_NAME_TRN2, "trn2" }
};
#endif

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static uint32_t permute_word(
    unsigned operation, unsigned size_code,
    unsigned zd, unsigned zn, unsigned zm)
{
    return UINT32_C(0x05206000)
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

static void word_to_be(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
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
        cpu_id, mode, bytes, code_size, UINT64_C(0x6000), options,
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
    cdisasm_arm_cpu_id cpu_id,
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
    uint32_t word = permute_word(operation, size_code, zd, zn, zm);
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        word, cpu_id, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 4u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == permute_operations[operation].name_id);
    EXPECT(instruction.address == UINT64_C(0x6000));
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
            permute_operations[operation].mnemonic,
            zd, element_suffixes[size_code],
            zn, element_suffixes[size_code],
            zm, element_suffixes[size_code]);

        EXPECT(expected_size > 0);
        EXPECT((size_t)expected_size < sizeof(expected));
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == (size_t)expected_size);
        EXPECT(strcmp(text, expected) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            NULL, 0u) == (size_t)expected_size);
    }
#endif
}
#endif

static void test_all_allocated_and_reserved_controls(void)
{
    unsigned operation;

    for (operation = 0u; operation < 6u; ++operation) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            unsigned zd = (operation * 5u + size_code) & 31u;
            unsigned zn = (operation * 5u + size_code + 11u) & 31u;
            unsigned zm = (operation * 5u + size_code + 23u) & 31u;
#if USE_EXTRA_OPCODES
            expect_success(
                CDISASM_ARM_CPU_ANY, operation, size_code, zd, zn, zm);
#else
            cdisasm_arm_instruction instruction;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                permute_word(operation, size_code, zd, zn, zm),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                CDISASM_ARM_DECODE_OPTION_NONE, 4u,
                &instruction) == 0u);
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }

    for (operation = 6u; operation < 8u; ++operation) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            cdisasm_arm_instruction instruction;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                permute_word(operation, size_code, 0u, 31u, 1u),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                CDISASM_ARM_DECODE_OPTION_NONE, 4u,
                &instruction) == 0u);
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        }
    }
}

static void test_capability_profiles(void)
{
    static const cdisasm_arm_cpu_id sme_only_cpus[] = {
        CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_ARM_CPU_APPLE_M4
    };
    cdisasm_arm_instruction instruction;
    unsigned operation;
    size_t cpu_index;

    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_FUJITSU_A64FX)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_FUJITSU_A64FX)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(!CDISASM_ARM_CPU_IS_APPLE(CDISASM_ARM_CPU_FUJITSU_A64FX));

    for (operation = 0u; operation < 6u; ++operation) {
#if USE_EXTRA_OPCODES
        expect_success(
            CDISASM_ARM_CPU_FUJITSU_A64FX, operation, operation & 3u,
            operation, operation + 8u, operation + 16u);
#else
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            permute_word(
                operation, operation & 3u,
                operation, operation + 8u, operation + 16u),
            CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    for (cpu_index = 0u;
         cpu_index < sizeof(sme_only_cpus) / sizeof(sme_only_cpus[0]);
         ++cpu_index) {
#if USE_EXTRA_OPCODES
        expect_success(
            sme_only_cpus[cpu_index], 5u, 3u,
            31u, (unsigned)cpu_index, 30u);
#else
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            permute_word(5u, 3u, 31u, (unsigned)cpu_index, 30u),
            sme_only_cpus[cpu_index], CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        permute_word(0u, 0u, 0u, 1u, 2u),
        CDISASM_ARM_CPU_CORTEX_A53, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
#if USE_EXTRA_OPCODES
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_boundaries_endian_and_generic_dispatch(void)
{
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t little_bytes[4];
    uint8_t big_bytes[4];
    uint32_t boundary_word = permute_word(5u, 3u, 31u, 0u, 31u);
    uint32_t decoded;

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        boundary_word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE,
        4u, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(boundary_word, big_bytes);
    memset(&big, 0xa5, sizeof(big));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A64,
        big_bytes, sizeof(big_bytes), UINT64_C(0x6000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(memcmp(&big, &little, sizeof(big)) == 0);
    EXPECT(little.name_id == CDISASM_ARM_NAME_TRN2);
    EXPECT(little.operand[0].reg == CDISASM_ARM_REG_Z31);
    EXPECT(little.operand[1].reg == CDISASM_ARM_REG_Z0);
    EXPECT(little.operand[2].reg == CDISASM_ARM_REG_Z31);
#else
    EXPECT(decoded == 0u);
    EXPECT(instruction_is_error_only(
        &little, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    EXPECT(memcmp(&big, &little, sizeof(big)) == 0);
#endif

    word_to_le(boundary_word, little_bytes);
    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(cdisasm_instruction_size(CDISASM_ARM_CPU_FUJITSU_A64FX)
        == sizeof(generic));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x6000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);
#else
    EXPECT(decoded == 0u);
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);
#endif

    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode_checked(
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x6000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic, sizeof(generic));
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);
#else
    EXPECT(decoded == 0u);
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);
#endif

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        boundary_word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE,
        3u, &generic) == 0u);
    EXPECT(instruction_is_error_only(&generic, CDISASM_STATUS_TRUNCATED));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        boundary_word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A32, CDISASM_ARM_DECODE_OPTION_NONE,
        4u, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        boundary_word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A64, UINT64_C(1) << 63,
        4u, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    {
        char text[96];
        char short_text[5];
        static const char expected[] = "trn2 z31.d, z0.d, z31.d";
        static const char expected_upper[] = "TRN2 z31.d, z0.d, z31.d";

        EXPECT(cdisasm_arm_format(
            &little, CDISASM_FORMAT_SYNTAX_7,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
        EXPECT(cdisasm_arm_format(
            &little, CDISASM_FORMAT_SYNTAX_0,
            short_text, sizeof(short_text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(short_text, "trn2") == 0);
        EXPECT(cdisasm_arm_format(
            &little, CDISASM_FORMAT_SYNTAX_0
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected_upper) - 1u);
        EXPECT(strcmp(text, expected_upper) == 0);
    }
#endif
}

int main(void)
{
    test_all_allocated_and_reserved_controls();
    test_capability_profiles();
    test_boundaries_endian_and_generic_dispatch();

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE vector-permute test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE vector-permute tests passed "
           "(USE_EXTRA_OPCODES=%d)\n", USE_EXTRA_OPCODES);
    return 0;
}
