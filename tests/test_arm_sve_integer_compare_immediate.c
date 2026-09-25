#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_CMPEQ == UINT16_C(387),
               "established SVE compare IDs moved");
_Static_assert(CDISASM_ARM_NAME_CMPLS == UINT16_C(396),
               "established SVE compare terminal ID moved");

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 20) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static const unsigned signed_controls[4] = { 0u, 1u, 4u, 5u };

#if USE_EXTRA_OPCODES
static const cdisasm_arm_name_id signed_names[3][2] = {
    { CDISASM_ARM_NAME_CMPGE, CDISASM_ARM_NAME_CMPGT },
    { CDISASM_ARM_NAME_CMPLT, CDISASM_ARM_NAME_CMPLE },
    { CDISASM_ARM_NAME_CMPEQ, CDISASM_ARM_NAME_CMPNE }
};

static const cdisasm_arm_name_id unsigned_names[2][2] = {
    { CDISASM_ARM_NAME_CMPHS, CDISASM_ARM_NAME_CMPHI },
    { CDISASM_ARM_NAME_CMPLO, CDISASM_ARM_NAME_CMPLS }
};

#  if USE_DISASM_FORMAT
static const char *const signed_mnemonics[3][2] = {
    { "cmpge", "cmpgt" }, { "cmplt", "cmple" },
    { "cmpeq", "cmpne" }
};

static const char *const unsigned_mnemonics[2][2] = {
    { "cmphs", "cmphi" }, { "cmplo", "cmpls" }
};
#  endif
#endif

static uint32_t signed_word(
    unsigned control_index,
    unsigned element_size,
    unsigned encoded_immediate,
    unsigned pg,
    unsigned zn,
    unsigned relation,
    unsigned pd)
{
    return UINT32_C(0x25000000)
        | ((uint32_t)element_size << 22)
        | ((uint32_t)encoded_immediate << 16)
        | ((uint32_t)signed_controls[control_index] << 13)
        | ((uint32_t)pg << 10)
        | ((uint32_t)zn << 5)
        | ((uint32_t)relation << 4)
        | (uint32_t)pd;
}

static uint32_t unsigned_word(
    unsigned inverse,
    unsigned element_size,
    unsigned encoded_immediate,
    unsigned pg,
    unsigned zn,
    unsigned relation,
    unsigned pd)
{
    return UINT32_C(0x24200000)
        | ((uint32_t)element_size << 22)
        | ((uint32_t)encoded_immediate << 14)
        | ((uint32_t)inverse << 13)
        | ((uint32_t)pg << 10)
        | ((uint32_t)zn << 5)
        | ((uint32_t)relation << 4)
        | (uint32_t)pd;
}

#if USE_EXTRA_OPCODES
static int64_t sign_extend_5(unsigned value)
{
    return (int64_t)(int)(value ^ 16u) - INT64_C(16);
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
        cpu_id, mode, bytes, code_size, UINT64_C(0x111000),
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
static int predicate_operand_matches(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    uint8_t element_size,
    uint8_t qualifier,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_PREDICATE;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.flags = qualifier;
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int z_operand_matches(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    uint8_t element_size)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int immediate_operand_matches(
    const cdisasm_arm_operand *operand,
    int64_t value)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_IMMEDIATE;
    expected.imm = (uint64_t)value;
    expected.size = 1u;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    if (value < 0) {
        expected.flags = CDISASM_OPERAND_FLAG_SIGNED;
    }
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int success_metadata_matches(
    const cdisasm_arm_instruction *instruction,
    uint32_t word,
    cdisasm_arm_name_id name_id,
    unsigned element_size_code,
    unsigned pg,
    unsigned zn,
    unsigned pd,
    int64_t immediate)
{
    uint8_t element_size =
        (uint8_t)(UINT32_C(1) << element_size_code);

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == name_id
        && instruction->address == UINT64_C(0x111000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 4u
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS)
        && predicate_operand_matches(
            &instruction->operand[0], pd, element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE)
        && predicate_operand_matches(
            &instruction->operand[1], pg, element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && z_operand_matches(
            &instruction->operand[2], zn, element_size)
        && immediate_operand_matches(
            &instruction->operand[3], immediate);
}
#endif

static void test_exhaustive_signed_class(void)
{
    uint32_t allocated_words = 0u;
    uint32_t reserved_words = 0u;
    unsigned control_index;

    for (control_index = 0u; control_index < 4u; ++control_index) {
        unsigned element_size;

        for (element_size = 0u; element_size < 4u; ++element_size) {
            unsigned encoded_immediate;

            for (encoded_immediate = 0u;
                 encoded_immediate < 32u;
                 ++encoded_immediate) {
                unsigned pg;

                for (pg = 0u; pg < 8u; ++pg) {
                    unsigned zn;

                    for (zn = 0u; zn < 32u; ++zn) {
                        unsigned relation;

                        for (relation = 0u; relation < 2u; ++relation) {
                            unsigned pd;

                            for (pd = 0u; pd < 16u; ++pd) {
                                cdisasm_arm_instruction instruction;
                                uint32_t word = signed_word(
                                    control_index, element_size,
                                    encoded_immediate, pg, zn, relation, pd);
                                uint32_t decoded;

                                memset(&instruction, 0xa5,
                                       sizeof(instruction));
                                decoded = decode_word(
                                    word, CDISASM_ARM_CPU_ANY,
                                    CDISASM_ARM_MODE_A64, 4u,
                                    CDISASM_ARM_DECODE_OPTION_NONE,
                                    &instruction);
                                if (control_index == 3u) {
                                    ++reserved_words;
                                    EXPECT(decoded == 0u);
                                    EXPECT(instruction_is_error_only(
                                        &instruction,
                                        CDISASM_STATUS_INVALID_INSTRUCTION));
                                } else {
                                    ++allocated_words;
#if USE_EXTRA_OPCODES
                                    EXPECT(decoded == 4u);
                                    EXPECT(success_metadata_matches(
                                        &instruction, word,
                                        signed_names[control_index][relation],
                                        element_size, pg, zn, pd,
                                        sign_extend_5(encoded_immediate)));
#else
                                    EXPECT(decoded == 0u);
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

    EXPECT(allocated_words == UINT32_C(3145728));
    EXPECT(reserved_words == UINT32_C(1048576));
}

static void test_exhaustive_unsigned_class(void)
{
    uint32_t allocated_words = 0u;
    unsigned inverse;

    for (inverse = 0u; inverse < 2u; ++inverse) {
        unsigned element_size;

        for (element_size = 0u; element_size < 4u; ++element_size) {
            unsigned encoded_immediate;

            for (encoded_immediate = 0u;
                 encoded_immediate < 128u;
                 ++encoded_immediate) {
                unsigned pg;

                for (pg = 0u; pg < 8u; ++pg) {
                    unsigned zn;

                    for (zn = 0u; zn < 32u; ++zn) {
                        unsigned relation;

                        for (relation = 0u; relation < 2u; ++relation) {
                            unsigned pd;

                            for (pd = 0u; pd < 16u; ++pd) {
                                cdisasm_arm_instruction instruction;
                                uint32_t word = unsigned_word(
                                    inverse, element_size,
                                    encoded_immediate, pg, zn, relation, pd);
                                uint32_t decoded;

                                memset(&instruction, 0xa5,
                                       sizeof(instruction));
                                decoded = decode_word(
                                    word, CDISASM_ARM_CPU_ANY,
                                    CDISASM_ARM_MODE_A64, 4u,
                                    CDISASM_ARM_DECODE_OPTION_NONE,
                                    &instruction);
                                ++allocated_words;
#if USE_EXTRA_OPCODES
                                EXPECT(decoded == 4u);
                                EXPECT(success_metadata_matches(
                                    &instruction, word,
                                    unsigned_names[inverse][relation],
                                    element_size, pg, zn, pd,
                                    (int64_t)encoded_immediate));
#else
                                EXPECT(decoded == 0u);
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

    EXPECT(allocated_words == UINT32_C(8388608));
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
    uint32_t words[2];
    unsigned index;

    words[0] = signed_word(2u, 2u, 16u, 3u, 11u, 0u, 7u);
    words[1] = unsigned_word(1u, 3u, 127u, 3u, 11u, 1u, 7u);
    for (index = 0u; index < 2u; ++index) {
        expect_cpu_status(
            words[index], CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_cpu_status(
            words[index], CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);
        expect_cpu_status(
            words[index], CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_cpu_status(
            words[index], CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(
            words[index], CDISASM_ARM_CPU_APPLE_M3,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_endian_truncation_mode_dispatch_and_adjacency(void)
{
    uint32_t word = signed_word(2u, 1u, 16u, 3u, 11u, 0u, 7u);
    uint32_t reserved = signed_word(3u, 1u, 16u, 3u, 11u, 0u, 7u);
    uint32_t adjacent_predicate_logical = UINT32_C(0x25004440);
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
        big_bytes, sizeof(big_bytes), UINT64_C(0x111000),
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
        little_bytes, sizeof(little_bytes), UINT64_C(0x111000),
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
        reserved, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_INSTRUCTION));

    /* Signed controls with bit 14 set are separate predicate/break maps.
     * This allocated AND representative proves the immediate descriptor
     * does not steal its neighboring predicate-logical class. */
    memset(&generic, 0xa5, sizeof(generic));
    decoded = decode_word(
        adjacent_predicate_logical, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(generic.name_id == CDISASM_ARM_NAME_AND);
#else
    EXPECT(decoded == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

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
    static const unsigned signed_immediates[] = { 0u, 15u, 16u, 31u };
    static const unsigned unsigned_immediates[] = { 0u, 1u, 126u, 127u };
    unsigned control_index;

    for (control_index = 0u; control_index < 3u; ++control_index) {
        unsigned relation;

        for (relation = 0u; relation < 2u; ++relation) {
            unsigned element_size;

            for (element_size = 0u; element_size < 4u; ++element_size) {
                unsigned immediate_index;

                for (immediate_index = 0u;
                     immediate_index < 4u;
                     ++immediate_index) {
                    unsigned encoded = signed_immediates[immediate_index];
                    int immediate = (int)sign_extend_5(encoded);
                    cdisasm_arm_instruction instruction;
                    char expected[96];
                    char text[96];
                    int expected_length;

                    EXPECT(decode_word(
                        signed_word(
                            control_index, element_size, encoded,
                            3u, 11u, relation, 7u),
                        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE,
                        &instruction) == 4u);
                    expected_length = immediate < 0
                        ? snprintf(
                            expected, sizeof(expected),
                            "%s p7.%c, p3/z, z11.%c, #-0x%x",
                            signed_mnemonics[control_index][relation],
                            suffixes[element_size], suffixes[element_size],
                            (unsigned)-immediate)
                        : snprintf(
                            expected, sizeof(expected),
                            "%s p7.%c, p3/z, z11.%c, #0x%x",
                            signed_mnemonics[control_index][relation],
                            suffixes[element_size], suffixes[element_size],
                            (unsigned)immediate);
                    EXPECT(expected_length > 0);
                    EXPECT((size_t)expected_length < sizeof(expected));
                    EXPECT(cdisasm_arm_format(
                        &instruction, CDISASM_FORMAT_SYNTAX_7,
                        text, sizeof(text)) == (size_t)expected_length);
                    EXPECT(strcmp(text, expected) == 0);
                }
            }
        }
    }

    for (control_index = 0u; control_index < 2u; ++control_index) {
        unsigned relation;

        for (relation = 0u; relation < 2u; ++relation) {
            unsigned element_size;

            for (element_size = 0u; element_size < 4u; ++element_size) {
                unsigned immediate_index;

                for (immediate_index = 0u;
                     immediate_index < 4u;
                     ++immediate_index) {
                    unsigned immediate =
                        unsigned_immediates[immediate_index];
                    cdisasm_arm_instruction instruction;
                    char expected[96];
                    char text[96];
                    int expected_length;

                    EXPECT(decode_word(
                        unsigned_word(
                            control_index, element_size, immediate,
                            3u, 11u, relation, 7u),
                        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE,
                        &instruction) == 4u);
                    expected_length = snprintf(
                        expected, sizeof(expected),
                        "%s p7.%c, p3/z, z11.%c, #0x%x",
                        unsigned_mnemonics[control_index][relation],
                        suffixes[element_size], suffixes[element_size],
                        immediate);
                    EXPECT(expected_length > 0);
                    EXPECT((size_t)expected_length < sizeof(expected));
                    EXPECT(cdisasm_arm_format(
                        &instruction, CDISASM_FORMAT_SYNTAX_0,
                        text, sizeof(text)) == (size_t)expected_length);
                    EXPECT(strcmp(text, expected) == 0);
                }
            }
        }
    }

    {
        static const char expected[] =
            "CMPLS p7.d, p3/z, z11.d, #0x7f";
        cdisasm_arm_instruction instruction;
        char text[96];

        EXPECT(decode_word(
            unsigned_word(1u, 3u, 127u, 3u, 11u, 1u, 7u),
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
    test_exhaustive_signed_class();
    test_exhaustive_unsigned_class();
    test_capability_routes();
    test_endian_truncation_mode_dispatch_and_adjacency();
    test_formatter_controls();

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM SVE integer-compare-immediate test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE integer-compare-immediate tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=12582912, "
           "allocated=11534336, reserved=1048576)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
