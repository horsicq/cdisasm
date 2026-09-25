#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_ZIP1 == UINT16_C(348),
               "ZIP1 public ID moved");
_Static_assert(CDISASM_ARM_NAME_ZIP2 == UINT16_C(349),
               "ZIP2 public ID moved");
_Static_assert(CDISASM_ARM_NAME_UZP1 == UINT16_C(350),
               "UZP1 public ID moved");
_Static_assert(CDISASM_ARM_NAME_UZP2 == UINT16_C(351),
               "UZP2 public ID moved");
_Static_assert(CDISASM_ARM_NAME_TRN1 == UINT16_C(352),
               "TRN1 public ID moved");
_Static_assert(CDISASM_ARM_NAME_TRN2 == UINT16_C(353),
               "TRN2 public ID moved");

typedef struct permute_operation {
    unsigned selector;
    cdisasm_arm_name_id name_id;
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    const char *mnemonic;
#endif
} permute_operation;

typedef struct vector_arrangement {
    unsigned q;
    unsigned size_code;
    uint8_t total_size;
    uint8_t element_size;
    uint8_t element_count;
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    char suffix;
#endif
} vector_arrangement;

static const permute_operation operations[6] = {
    { 1u, CDISASM_ARM_NAME_UZP1,
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
      "uzp1"
#endif
    },
    { 2u, CDISASM_ARM_NAME_TRN1,
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
      "trn1"
#endif
    },
    { 3u, CDISASM_ARM_NAME_ZIP1,
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
      "zip1"
#endif
    },
    { 5u, CDISASM_ARM_NAME_UZP2,
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
      "uzp2"
#endif
    },
    { 6u, CDISASM_ARM_NAME_TRN2,
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
      "trn2"
#endif
    },
    { 7u, CDISASM_ARM_NAME_ZIP2,
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
      "zip2"
#endif
    }
};

static const vector_arrangement arrangements[7] = {
    { 0u, 0u,  8u, 1u,  8u,
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
      'b'
#endif
    },
    { 1u, 0u, 16u, 1u, 16u,
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
      'b'
#endif
    },
    { 0u, 1u,  8u, 2u,  4u,
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
      'h'
#endif
    },
    { 1u, 1u, 16u, 2u,  8u,
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
      'h'
#endif
    },
    { 0u, 2u,  8u, 4u,  2u,
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
      's'
#endif
    },
    { 1u, 2u, 16u, 4u,  4u,
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
      's'
#endif
    },
    { 1u, 3u, 16u, 8u,  2u,
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
      'd'
#endif
    }
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

static uint32_t permute_word(
    unsigned selector,
    unsigned q,
    unsigned size_code,
    unsigned vd,
    unsigned vn,
    unsigned vm)
{
    return UINT32_C(0x0e000800)
        | ((uint32_t)q << 30)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)vm << 16)
        | ((uint32_t)selector << 12)
        | ((uint32_t)vn << 5)
        | (uint32_t)vd;
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

static uint32_t decode_bytes(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    const uint8_t *bytes,
    size_t byte_count,
    cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, byte_count, UINT64_C(0x7000), options,
        instruction);
}

static uint32_t decode_word(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    uint32_t word,
    size_t byte_count,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return decode_bytes(
        cpu_id, mode, bytes, byte_count,
        CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static int is_error_only(
    const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void expect_error(uint32_t word, cdisasm_status status)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        word, 4u, &instruction) == 0u);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static void expect_vector_operand(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    const vector_arrangement *arrangement,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded);
    expected.size = arrangement->total_size;
    expected.access = access;
    expected.extend_type =
        (cdisasm_arm_extend_type)arrangement->element_size;
    expected.scale = arrangement->element_count;
    EXPECT(memcmp(operand, &expected, sizeof(expected)) == 0);
}

static void expect_success(
    cdisasm_arm_cpu_id cpu_id,
    const permute_operation *operation,
    const vector_arrangement *arrangement,
    unsigned vd,
    unsigned vn,
    unsigned vm)
{
    cdisasm_arm_instruction instruction;
    uint32_t word = permute_word(
        operation->selector, arrangement->q, arrangement->size_code,
        vd, vn, vm);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        cpu_id, CDISASM_ARM_MODE_A64, word, 4u, &instruction) == 4u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.address == UINT64_C(0x7000));
    EXPECT(instruction.raw_instruction == word);
    EXPECT(instruction.opcode_size == 4u);
    EXPECT(instruction.name_id == operation->name_id);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_A64);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    EXPECT(instruction.operand_count == 3u);
    expect_vector_operand(
        &instruction.operand[0], vd, arrangement,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_vector_operand(
        &instruction.operand[1], vn, arrangement,
        CDISASM_OPERAND_ACCESS_READ);
    expect_vector_operand(
        &instruction.operand[2], vm, arrangement,
        CDISASM_OPERAND_ACCESS_READ);

#if USE_DISASM_FORMAT
    {
        char expected[96];
        char text[96];
        int length = snprintf(
            expected, sizeof(expected),
            "%s v%u.%u%c, v%u.%u%c, v%u.%u%c",
            operation->mnemonic,
            vd, arrangement->element_count, arrangement->suffix,
            vn, arrangement->element_count, arrangement->suffix,
            vm, arrangement->element_count, arrangement->suffix);

        EXPECT(length > 0);
        EXPECT((size_t)length < sizeof(expected));
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == (size_t)length);
        EXPECT(strcmp(text, expected) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            NULL, 0u) == (size_t)length);
    }
#endif
}
#endif

static void test_complete_shape_matrix(void)
{
    size_t operation_index;

    for (operation_index = 0u;
         operation_index < sizeof(operations) / sizeof(operations[0]);
         ++operation_index) {
        size_t arrangement_index;

        for (arrangement_index = 0u;
             arrangement_index
                 < sizeof(arrangements) / sizeof(arrangements[0]);
             ++arrangement_index) {
            const permute_operation *operation =
                &operations[operation_index];
            const vector_arrangement *arrangement =
                &arrangements[arrangement_index];
            unsigned vd = (unsigned)(operation_index * 7u
                + arrangement_index) & 31u;
            unsigned vn = (vd + 11u) & 31u;
            unsigned vm = (vd + 23u) & 31u;
#if USE_EXTRA_OPCODES
            expect_success(
                CDISASM_ARM_CPU_ANY, operation, arrangement, vd, vn, vm);
#else
            cdisasm_arm_instruction instruction;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                permute_word(
                    operation->selector, arrangement->q,
                    arrangement->size_code, vd, vn, vm),
                4u, &instruction) == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static void test_reserved_encodings(void)
{
    size_t operation_index;
    unsigned selector;

    for (operation_index = 0u;
         operation_index < sizeof(operations) / sizeof(operations[0]);
         ++operation_index) {
        expect_error(
            permute_word(
                operations[operation_index].selector,
                0u, 3u, 31u, 0u, 31u),
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    for (selector = 0u; selector <= 4u; selector += 4u) {
        unsigned q;

        for (q = 0u; q < 2u; ++q) {
            unsigned size_code;

            for (size_code = 0u; size_code < 4u; ++size_code) {
                expect_error(
                    permute_word(
                        selector, q, size_code, 0u, 1u, 2u),
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }
    }
}

static void test_oracle_boundaries_profiles_and_endian(void)
{
    const uint32_t uzp1_8b = UINT32_C(0x0e021820);
    const uint32_t zip1_2d = UINT32_C(0x4ec23820);
    const uint32_t trn2_boundary = permute_word(
        6u, 1u, 3u, 31u, 0u, 31u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t little_bytes[4];
    uint8_t big_bytes[4];
    uint32_t decoded;

    EXPECT(uzp1_8b == permute_word(1u, 0u, 0u, 0u, 1u, 2u));
    EXPECT(zip1_2d == permute_word(3u, 1u, 3u, 0u, 1u, 2u));

#if USE_EXTRA_OPCODES
    expect_success(
        CDISASM_ARM_CPU_CORTEX_A53, &operations[0], &arrangements[0],
        0u, 1u, 2u);
    expect_success(
        CDISASM_ARM_CPU_FUJITSU_A64FX, &operations[2], &arrangements[6],
        31u, 0u, 31u);
    expect_success(
        CDISASM_ARM_CPU_APPLE_A18, &operations[5], &arrangements[5],
        30u, 29u, 28u);
#endif

    word_to_le(trn2_boundary, little_bytes);
    memset(&little, 0xa5, sizeof(little));
    decoded = decode_bytes(
        CDISASM_ARM_CPU_CORTEX_A53, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes),
        CDISASM_ARM_DECODE_OPTION_NONE, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(trn2_boundary, big_bytes);
    memset(&big, 0xa5, sizeof(big));
    decoded = decode_bytes(
        CDISASM_ARM_CPU_CORTEX_A53, CDISASM_ARM_MODE_A64,
        big_bytes, sizeof(big_bytes),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(memcmp(&little, &big, sizeof(little)) == 0);
#else
    EXPECT(decoded == 0u);
    EXPECT(is_error_only(
        &little, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    EXPECT(memcmp(&little, &big, sizeof(little)) == 0);
#endif

    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_CORTEX_A53, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x7000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);
#else
    EXPECT(decoded == 0u);
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);
#endif

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        CDISASM_ARM_CPU_CORTEX_A53, CDISASM_ARM_MODE_A64,
        trn2_boundary, 3u, &generic) == 0u);
    EXPECT(is_error_only(&generic, CDISASM_STATUS_TRUNCATED));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        CDISASM_ARM_CPU_CORTEX_A34, CDISASM_ARM_MODE_A32,
        trn2_boundary, 4u, &generic) == 0u);
    EXPECT(is_error_only(&generic, CDISASM_STATUS_INVALID_ARGUMENT));
}

int main(void)
{
    test_complete_shape_matrix();
    test_reserved_encodings();
    test_oracle_boundaries_profiles_and_endian();

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM AdvSIMD vector-permute test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM AdvSIMD vector-permute tests passed "
           "(USE_EXTRA_OPCODES=%d)\n", USE_EXTRA_OPCODES);
    return 0;
}
