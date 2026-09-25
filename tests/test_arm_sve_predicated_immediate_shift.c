#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_LSLR == UINT16_C(380),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_ASRD == UINT16_C(381),
               "SVE immediate-shift IDs must be append-only");
_Static_assert(CDISASM_ARM_NAME_SQSHLU == UINT16_C(386),
               "SVE immediate-shift terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(421),
               "SVE immediate-shift name count changed");

typedef struct immediate_shift_operation {
    cdisasm_arm_name_id name_id;
    const char *mnemonic;
    uint8_t allocated;
    uint8_t left_shift;
    uint8_t sve2;
} immediate_shift_operation;

static const immediate_shift_operation operations[16] = {
    { CDISASM_ARM_NAME_ASR, "asr", 1u, 0u, 0u },
    { CDISASM_ARM_NAME_LSR, "lsr", 1u, 0u, 0u },
    { CDISASM_ARM_NAME_NONE, NULL, 0u, 0u, 0u },
    { CDISASM_ARM_NAME_LSL, "lsl", 1u, 1u, 0u },
    { CDISASM_ARM_NAME_ASRD, "asrd", 1u, 0u, 0u },
    { CDISASM_ARM_NAME_NONE, NULL, 0u, 0u, 0u },
    { CDISASM_ARM_NAME_SQSHL, "sqshl", 1u, 1u, 1u },
    { CDISASM_ARM_NAME_UQSHL, "uqshl", 1u, 1u, 1u },
    { CDISASM_ARM_NAME_NONE, NULL, 0u, 0u, 0u },
    { CDISASM_ARM_NAME_NONE, NULL, 0u, 0u, 0u },
    { CDISASM_ARM_NAME_NONE, NULL, 0u, 0u, 0u },
    { CDISASM_ARM_NAME_NONE, NULL, 0u, 0u, 0u },
    { CDISASM_ARM_NAME_SRSHR, "srshr", 1u, 0u, 1u },
    { CDISASM_ARM_NAME_URSHR, "urshr", 1u, 0u, 1u },
    { CDISASM_ARM_NAME_NONE, NULL, 0u, 0u, 0u },
    { CDISASM_ARM_NAME_SQSHLU, "sqshlu", 1u, 1u, 1u }
};

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",           \
                    __FILE__, __LINE__, #condition);                        \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static uint32_t shift_word(
    unsigned operation,
    unsigned encoded_immediate,
    unsigned pg,
    unsigned zd)
{
    return UINT32_C(0x04008000)
        | ((uint32_t)operation << 16)
        | ((uint32_t)(encoded_immediate & 0x60u) << 17)
        | ((uint32_t)(encoded_immediate & 0x1fu) << 5)
        | ((uint32_t)pg << 10)
        | (uint32_t)zd;
}

#if USE_EXTRA_OPCODES
static unsigned element_bits_from_encoded(unsigned encoded_immediate)
{
    return encoded_immediate >= 64u ? 64u
        : encoded_immediate >= 32u ? 32u
        : encoded_immediate >= 16u ? 16u : 8u;
}

static unsigned semantic_immediate(
    const immediate_shift_operation *operation,
    unsigned encoded_immediate)
{
    unsigned element_bits = element_bits_from_encoded(encoded_immediate);

    return operation->left_shift
        ? encoded_immediate - element_bits
        : 2u * element_bits - encoded_immediate;
}
#endif

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

static uint32_t decode_word(
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    size_t code_size,
    cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x119000),
        options, instruction);
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

#if USE_EXTRA_OPCODES
static int z_operand_matches(
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
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int predicate_operand_matches(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    uint8_t element_size)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_PREDICATE;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.flags = CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int immediate_operand_matches(
    const cdisasm_arm_operand *operand,
    unsigned value)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_IMMEDIATE;
    expected.imm = value;
    expected.size = 1u;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static void expect_success_metadata(
    const cdisasm_arm_instruction *instruction,
    const immediate_shift_operation *operation,
    uint32_t word,
    unsigned encoded_immediate,
    unsigned pg,
    unsigned zd)
{
    uint8_t element_size =
        (uint8_t)(element_bits_from_encoded(encoded_immediate) / 8u);

    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == operation->name_id);
    EXPECT(instruction->address == UINT64_C(0x119000));
    EXPECT(instruction->raw_instruction == word);
    EXPECT(instruction->opcode_size == 4u);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->isa_id == CDISASM_ARM_ISA_A64);
    EXPECT(instruction->condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction->operand_count == 4u);
    EXPECT(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    EXPECT(z_operand_matches(
        &instruction->operand[0], zd, element_size,
        CDISASM_OPERAND_ACCESS_READ_WRITE));
    EXPECT(predicate_operand_matches(
        &instruction->operand[1], pg, element_size));
    EXPECT(z_operand_matches(
        &instruction->operand[2], zd, element_size,
        CDISASM_OPERAND_ACCESS_READ));
    EXPECT(immediate_operand_matches(
        &instruction->operand[3],
        semantic_immediate(operation, encoded_immediate)));
}
#endif

static void test_exhaustive_owned_class(void)
{
    uint32_t allocated_words = 0u;
    uint32_t reserved_words = 0u;
    unsigned operation_index;

    for (operation_index = 0u; operation_index < 16u; ++operation_index) {
        const immediate_shift_operation *operation =
            &operations[operation_index];
        unsigned encoded_immediate;

        for (encoded_immediate = 0u;
             encoded_immediate < 128u;
             ++encoded_immediate) {
            int allocated = operation->allocated
                && encoded_immediate >= 8u;
            unsigned pg;

            for (pg = 0u; pg < 8u; ++pg) {
                unsigned zd;

                for (zd = 0u; zd < 32u; ++zd) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = shift_word(
                        operation_index, encoded_immediate, pg, zd);

                    memset(&instruction, 0xa5, sizeof(instruction));
                    if (!allocated) {
                        ++reserved_words;
                        EXPECT(decode_word(
                            word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE,
                            &instruction) == 0u);
                        EXPECT(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                    } else {
                        ++allocated_words;
#if USE_EXTRA_OPCODES
                        EXPECT(decode_word(
                            word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE,
                            &instruction) == 4u);
                        expect_success_metadata(
                            &instruction, operation, word,
                            encoded_immediate, pg, zd);
#else
                        EXPECT(decode_word(
                            word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE,
                            &instruction) == 0u);
                        EXPECT(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    }
                }
            }
        }
    }

    EXPECT(allocated_words == UINT32_C(276480));
    EXPECT(reserved_words == UINT32_C(247808));
    EXPECT(allocated_words + reserved_words == UINT32_C(524288));
}

static void expect_cpu_status(
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_status enabled_status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_status expected;
    uint32_t decoded;

#if USE_EXTRA_OPCODES
    expected = enabled_status;
#else
    (void)enabled_status;
    expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(
        word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(decoded == 4u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(decoded == 0u);
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_capability_routes(void)
{
    unsigned operation_index;

    for (operation_index = 0u; operation_index < 16u; ++operation_index) {
        const immediate_shift_operation *operation =
            &operations[operation_index];
        uint32_t word;

        if (!operation->allocated) {
            continue;
        }
        word = shift_word(operation_index, 127u, 3u, 7u);
        expect_cpu_status(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_cpu_status(
            word, CDISASM_ARM_CPU_APPLE_M4, CDISASM_STATUS_OK);
        expect_cpu_status(
            word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            operation->sve2 ? CDISASM_STATUS_INVALID_INSTRUCTION
                            : CDISASM_STATUS_OK);
        expect_cpu_status(
            word, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(
            word, CDISASM_ARM_CPU_APPLE_M3,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    /* Apple A18 exposes the alternative SME route for the SVE2 controls. */
    expect_cpu_status(
        shift_word(15u, 127u, 3u, 7u),
        CDISASM_ARM_CPU_APPLE_A18, CDISASM_STATUS_OK);
}

static void test_endian_truncation_mode_and_dispatch(void)
{
    uint32_t word = shift_word(15u, 127u, 3u, 7u);
    uint32_t reserved = shift_word(2u, 0u, 3u, 7u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t little_bytes[4];
    uint8_t big_bytes[4];
    unsigned boundary;
    uint32_t decoded;

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(word, big_bytes);
    memset(&big, 0xa5, sizeof(big));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        big_bytes, sizeof(big_bytes), UINT64_C(0x119000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&big, &little, sizeof(big)) == 0);

    word_to_le(word, little_bytes);
    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x119000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&generic, 0xa5, sizeof(generic));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE,
            &generic) == 0u);
        EXPECT(instruction_is_error_only(
            &generic, CDISASM_STATUS_TRUNCATED));

        memset(&generic, 0xa5, sizeof(generic));
        EXPECT(decode_word(
            reserved, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE,
            &generic) == 0u);
        EXPECT(instruction_is_error_only(
            &generic, CDISASM_STATUS_TRUNCATED));
    }

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_formatter_controls(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const char suffixes[] = { 'b', 'h', 's', 'd' };
    unsigned operation_index;

    for (operation_index = 0u; operation_index < 16u; ++operation_index) {
        const immediate_shift_operation *operation =
            &operations[operation_index];
        unsigned encoded_immediate;

        if (!operation->allocated) {
            continue;
        }
        for (encoded_immediate = 8u;
             encoded_immediate < 128u;
             ++encoded_immediate) {
            cdisasm_arm_instruction instruction;
            unsigned element_bits =
                element_bits_from_encoded(encoded_immediate);
            unsigned size_code = element_bits == 8u ? 0u
                : element_bits == 16u ? 1u
                : element_bits == 32u ? 2u : 3u;
            unsigned immediate =
                semantic_immediate(operation, encoded_immediate);
            uint32_t word = shift_word(
                operation_index, encoded_immediate, 3u, 7u);
            char expected[96];
            char text[96];
            int expected_length;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
            expected_length = snprintf(
                expected, sizeof(expected),
                "%s z7.%c, p3/m, z7.%c, #0x%x",
                operation->mnemonic, suffixes[size_code],
                suffixes[size_code], immediate);
            EXPECT(expected_length > 0);
            EXPECT((size_t)expected_length < sizeof(expected));
            EXPECT(cdisasm_arm_format(
                &instruction, CDISASM_FORMAT_SYNTAX_7,
                text, sizeof(text)) == (size_t)expected_length);
            EXPECT(strcmp(text, expected) == 0);
            EXPECT(cdisasm_arm_format(
                &instruction, CDISASM_FORMAT_SYNTAX_0,
                NULL, 0u) == (size_t)expected_length);
        }
    }

    {
        cdisasm_arm_instruction instruction;
        char text[96];
        static const char expected[] =
            "SQSHLU z7.d, p3/m, z7.d, #0x3f";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            shift_word(15u, 127u, 3u, 7u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
    }
#endif
}

int main(void)
{
    test_exhaustive_owned_class();
    test_capability_routes();
    test_endian_truncation_mode_and_dispatch();
    test_formatter_controls();

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM SVE predicated-immediate-shift test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE predicated-immediate-shift tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=524288, allocated=276480, "
           "reserved=247808)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
