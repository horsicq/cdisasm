#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_UDIVR == UINT16_C(364),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_CLS == UINT16_C(365),
               "SVE unary IDs must be append-only");
_Static_assert(CDISASM_ARM_NAME_RBIT == UINT16_C(377),
               "SVE unary terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(421),
               "ARM name count changed");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

typedef enum unary_class {
    UNARY_CLASS_INTEGER,
    UNARY_CLASS_BITWISE,
    UNARY_CLASS_REVERSE
} unary_class;

typedef struct unary_operation {
    cdisasm_arm_name_id name_id;
    const char *mnemonic;
    uint8_t size_mask;
    uint8_t implemented;
} unary_operation;

static const unary_operation integer_operations[8] = {
    { CDISASM_ARM_NAME_SXTB, "sxtb", UINT8_C(0x0e), 1u },
    { CDISASM_ARM_NAME_UXTB, "uxtb", UINT8_C(0x0e), 1u },
    { CDISASM_ARM_NAME_SXTH, "sxth", UINT8_C(0x0c), 1u },
    { CDISASM_ARM_NAME_UXTH, "uxth", UINT8_C(0x0c), 1u },
    { CDISASM_ARM_NAME_SXTW, "sxtw", UINT8_C(0x08), 1u },
    { CDISASM_ARM_NAME_UXTW, "uxtw", UINT8_C(0x08), 1u },
    { CDISASM_ARM_NAME_ABS, "abs", UINT8_C(0x0f), 1u },
    { CDISASM_ARM_NAME_NEG, "neg", UINT8_C(0x0f), 1u }
};

static const unary_operation bitwise_operations[8] = {
    { CDISASM_ARM_NAME_CLS, "cls", UINT8_C(0x0f), 1u },
    { CDISASM_ARM_NAME_CLZ, "clz", UINT8_C(0x0f), 1u },
    { CDISASM_ARM_NAME_CNT, "cnt", UINT8_C(0x0f), 1u },
    { CDISASM_ARM_NAME_CNOT, "cnot", UINT8_C(0x0f), 1u },
    { CDISASM_ARM_NAME_FABS, "fabs", UINT8_C(0x0e), 1u },
    { CDISASM_ARM_NAME_FNEG, "fneg", UINT8_C(0x0e), 1u },
    { CDISASM_ARM_NAME_NOT, "not", UINT8_C(0x0f), 1u },
    { CDISASM_ARM_NAME_NONE, NULL, UINT8_C(0x00), 0u }
};

static const unary_operation reverse_operations[4] = {
    { CDISASM_ARM_NAME_REVB, "revb", UINT8_C(0x0e), 1u },
    { CDISASM_ARM_NAME_REVH, "revh", UINT8_C(0x0c), 1u },
    { CDISASM_ARM_NAME_REVW, "revw", UINT8_C(0x08), 1u },
    { CDISASM_ARM_NAME_RBIT, "rbit", UINT8_C(0x0f), 1u }
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

static const unary_operation *operation_descriptor(
    unary_class class_id,
    unsigned operation)
{
    if (class_id == UNARY_CLASS_INTEGER) {
        return &integer_operations[operation];
    }
    if (class_id == UNARY_CLASS_BITWISE) {
        return &bitwise_operations[operation];
    }
    return &reverse_operations[operation];
}

static unsigned operation_count(unary_class class_id)
{
    return class_id == UNARY_CLASS_REVERSE ? 4u : 8u;
}

static uint32_t unary_word(
    unary_class class_id,
    unsigned operation,
    unsigned size_code,
    int zeroing,
    unsigned pg,
    unsigned zn,
    unsigned zd)
{
    uint32_t word;

    if (class_id == UNARY_CLASS_INTEGER) {
        word = UINT32_C(0x0400a000);
        if (!zeroing) {
            word |= UINT32_C(0x00100000);
        }
    } else if (class_id == UNARY_CLASS_BITWISE) {
        word = UINT32_C(0x0408a000);
        if (!zeroing) {
            word |= UINT32_C(0x00100000);
        }
    } else {
        word = UINT32_C(0x05248000);
        if (zeroing) {
            word |= UINT32_C(0x00002000);
        }
    }
    return word
        | ((uint32_t)size_code << 22)
        | ((uint32_t)operation << 16)
        | ((uint32_t)pg << 10)
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
        cpu_id, mode, bytes, code_size, UINT64_C(0x117000),
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
    uint8_t element_size,
    int zeroing)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_PREDICATE;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.flags = zeroing
        ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
        : CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static void expect_success_metadata(
    const cdisasm_arm_instruction *instruction,
    const unary_operation *operation,
    uint32_t word,
    unsigned size_code,
    int zeroing,
    unsigned pg,
    unsigned zn,
    unsigned zd)
{
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == operation->name_id);
    EXPECT(instruction->address == UINT64_C(0x117000));
    EXPECT(instruction->raw_instruction == word);
    EXPECT(instruction->opcode_size == 4u);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->isa_id == CDISASM_ARM_ISA_A64);
    EXPECT(instruction->condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction->operand_count == 3u);
    EXPECT(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | ((operation->name_id == CDISASM_ARM_NAME_FABS
                    || operation->name_id == CDISASM_ARM_NAME_FNEG)
                ? CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT : 0u)));
    EXPECT(z_operand_matches(
        &instruction->operand[0], zd, element_size,
        zeroing ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ_WRITE));
    EXPECT(predicate_operand_matches(
        &instruction->operand[1], pg, element_size, zeroing));
    EXPECT(z_operand_matches(
        &instruction->operand[2], zn, element_size,
        CDISASM_OPERAND_ACCESS_READ));
}
#endif

static void test_exhaustive_owned_classes(void)
{
    uint32_t integer_words = 0u;
    uint32_t floating_words = 0u;
    uint32_t reserved_words = 0u;
    unary_class class_id;

    for (class_id = UNARY_CLASS_INTEGER;
         class_id <= UNARY_CLASS_REVERSE;
         class_id = (unary_class)(class_id + 1)) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            int zeroing;

            for (zeroing = 0; zeroing <= 1; ++zeroing) {
                unsigned operation;

                for (operation = 0u;
                     operation < operation_count(class_id);
                     ++operation) {
                    const unary_operation *descriptor =
                        operation_descriptor(class_id, operation);
                    int allocated = (descriptor->size_mask
                        & (UINT8_C(1) << size_code)) != 0u;
                    unsigned pg;

                    for (pg = 0u; pg < 8u; ++pg) {
                        unsigned zn;

                        for (zn = 0u; zn < 32u; ++zn) {
                            unsigned zd;

                            for (zd = 0u; zd < 32u; ++zd) {
                                cdisasm_arm_instruction instruction;
                                uint32_t word = unary_word(
                                    class_id, operation, size_code,
                                    zeroing, pg, zn, zd);

                                memset(&instruction, 0xa5,
                                       sizeof(instruction));
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
                                    if (descriptor->name_id
                                            == CDISASM_ARM_NAME_FABS
                                        || descriptor->name_id
                                            == CDISASM_ARM_NAME_FNEG) {
                                        ++floating_words;
                                    } else {
                                        ++integer_words;
                                    }
#if USE_EXTRA_OPCODES
                                    EXPECT(decode_word(
                                        word, CDISASM_ARM_CPU_ANY,
                                        CDISASM_ARM_MODE_A64, 4u,
                                        CDISASM_ARM_DECODE_OPTION_NONE,
                                        &instruction) == 4u);
                                    expect_success_metadata(
                                        &instruction, descriptor, word,
                                        size_code, zeroing, pg, zn, zd);
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
            }
        }
    }

    EXPECT(integer_words == UINT32_C(819200));
    EXPECT(floating_words == UINT32_C(98304));
    EXPECT(reserved_words == UINT32_C(393216));
    EXPECT(integer_words + floating_words + reserved_words
        == UINT32_C(1310720));
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
    uint32_t merging = unary_word(
        UNARY_CLASS_INTEGER, 6u, 0u, 0, 3u, 13u, 7u);
    uint32_t zeroing = unary_word(
        UNARY_CLASS_REVERSE, 3u, 0u, 1, 3u, 13u, 7u);

    /* FEAT_SVE and FEAT_SME are independent alternatives for /m. */
    expect_cpu_status(
        merging, CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_STATUS_OK);
    expect_cpu_status(
        merging, CDISASM_ARM_CPU_APPLE_A18, CDISASM_STATUS_OK);
    expect_cpu_status(
        merging, CDISASM_ARM_CPU_APPLE_M4, CDISASM_STATUS_OK);
    expect_cpu_status(
        merging, CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(
        merging, CDISASM_ARM_CPU_APPLE_A17,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(
        merging, CDISASM_ARM_CPU_APPLE_M3,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    /* /z is FEAT_SVE2p2 || FEAT_SME2p2, not baseline SVE/SME. */
    expect_cpu_status(zeroing, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_cpu_status(
        zeroing, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(
        zeroing, CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(
        zeroing, CDISASM_ARM_CPU_APPLE_M4,
        CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction integer_instruction;
        cdisasm_arm_instruction floating_instruction;

        memset(&integer_instruction, 0xa5, sizeof(integer_instruction));
        EXPECT(decode_word(
            unary_word(UNARY_CLASS_INTEGER, 4u, 3u, 0,
                       3u, 13u, 7u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE,
            &integer_instruction) == 4u);
        EXPECT(integer_instruction.name_id == CDISASM_ARM_NAME_SXTW);
        EXPECT((integer_instruction.instruction_flags
                   & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) == 0u);

        memset(&floating_instruction, 0xa5, sizeof(floating_instruction));
        EXPECT(decode_word(
            unary_word(UNARY_CLASS_BITWISE, 4u, 1u, 0,
                       3u, 13u, 7u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE,
            &floating_instruction) == 4u);
        EXPECT(floating_instruction.name_id == CDISASM_ARM_NAME_FABS);
        EXPECT((floating_instruction.instruction_flags
                   & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) != 0u);
    }
#endif
}

static void test_endian_truncation_mode_and_dispatch(void)
{
    uint32_t word = unary_word(
        UNARY_CLASS_REVERSE, 3u, 3u, 1, 3u, 13u, 7u);
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
        big_bytes, sizeof(big_bytes), UINT64_C(0x117000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(memcmp(&big, &little, sizeof(big)) == 0);
#else
    EXPECT(decoded == 0u);
    EXPECT(memcmp(&big, &little, sizeof(big)) == 0);
#endif

    word_to_le(word, little_bytes);
    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x117000),
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
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_formatter_controls(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const char suffixes[4] = { 'b', 'h', 's', 'd' };
    unary_class class_id;

    for (class_id = UNARY_CLASS_INTEGER;
         class_id <= UNARY_CLASS_REVERSE;
         class_id = (unary_class)(class_id + 1)) {
        unsigned operation;

        for (operation = 0u;
             operation < operation_count(class_id);
             ++operation) {
            const unary_operation *descriptor =
                operation_descriptor(class_id, operation);
            unsigned size_code;

            if (!descriptor->implemented) {
                continue;
            }
            for (size_code = 0u; size_code < 4u; ++size_code) {
                int zeroing;

                if ((descriptor->size_mask
                        & (UINT8_C(1) << size_code)) == 0u) {
                    continue;
                }
                for (zeroing = 0; zeroing <= 1; ++zeroing) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = unary_word(
                        class_id, operation, size_code,
                        zeroing, 3u, 13u, 7u);
                    char expected[96];
                    char text[96];
                    int expected_length;

                    memset(&instruction, 0xa5, sizeof(instruction));
                    EXPECT(decode_word(
                        word, CDISASM_ARM_CPU_ANY,
                        CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE,
                        &instruction) == 4u);
                    expected_length = snprintf(
                        expected, sizeof(expected),
                        "%s z7.%c, p3/%c, z13.%c",
                        descriptor->mnemonic, suffixes[size_code],
                        zeroing ? 'z' : 'm', suffixes[size_code]);
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
        }
    }

    {
        cdisasm_arm_instruction instruction;
        char text[96];
        static const char expected[] = "RBIT z7.b, p3/z, z13.b";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            unary_word(UNARY_CLASS_REVERSE, 3u, 0u, 1,
                       3u, 13u, 7u),
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
    test_exhaustive_owned_classes();
    test_capability_routes();
    test_endian_truncation_mode_and_dispatch();
    test_formatter_controls();

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE predicated-unary test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE predicated-unary tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=1310720, allocated=917504, "
           "integer=819200, floating=98304, reserved=393216)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
