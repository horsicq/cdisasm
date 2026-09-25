#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_TBLQ == UINT16_C(357),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_SUBR == UINT16_C(358),
               "predicated SVE IDs must be append-only");
_Static_assert(CDISASM_ARM_NAME_SABD == UINT16_C(359),
               "predicated SVE SABD ID changed");
_Static_assert(CDISASM_ARM_NAME_UABD == UINT16_C(360),
               "predicated SVE UABD ID changed");
_Static_assert(CDISASM_ARM_NAME_SMULH == UINT16_C(361),
               "predicated SVE SMULH ID changed");
_Static_assert(CDISASM_ARM_NAME_UMULH == UINT16_C(362),
               "predicated SVE UMULH ID changed");
_Static_assert(CDISASM_ARM_NAME_SDIVR == UINT16_C(363),
               "predicated SVE SDIVR ID changed");
_Static_assert(CDISASM_ARM_NAME_UDIVR == UINT16_C(364),
               "predicated SVE terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(421),
               "predicated SVE name count changed");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

typedef struct predicated_operation {
    cdisasm_arm_name_id name_id;
    const char *mnemonic;
    uint8_t size_mask;
} predicated_operation;

static const predicated_operation predicated_operations[32] = {
    { CDISASM_ARM_NAME_ADD, "add", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_SUB, "sub", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_NONE, NULL, UINT8_C(0) },
    { CDISASM_ARM_NAME_SUBR, "subr", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_ADDPT, "addpt", UINT8_C(0x08) },
    { CDISASM_ARM_NAME_SUBPT, "subpt", UINT8_C(0x08) },
    { CDISASM_ARM_NAME_NONE, NULL, UINT8_C(0) },
    { CDISASM_ARM_NAME_NONE, NULL, UINT8_C(0) },
    { CDISASM_ARM_NAME_SMAX, "smax", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_UMAX, "umax", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_SMIN, "smin", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_UMIN, "umin", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_SABD, "sabd", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_UABD, "uabd", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_NONE, NULL, UINT8_C(0) },
    { CDISASM_ARM_NAME_NONE, NULL, UINT8_C(0) },
    { CDISASM_ARM_NAME_MUL, "mul", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_NONE, NULL, UINT8_C(0) },
    { CDISASM_ARM_NAME_SMULH, "smulh", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_UMULH, "umulh", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_SDIV, "sdiv", UINT8_C(0x0c) },
    { CDISASM_ARM_NAME_UDIV, "udiv", UINT8_C(0x0c) },
    { CDISASM_ARM_NAME_SDIVR, "sdivr", UINT8_C(0x0c) },
    { CDISASM_ARM_NAME_UDIVR, "udivr", UINT8_C(0x0c) },
    { CDISASM_ARM_NAME_ORR, "orr", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_EOR, "eor", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_AND, "and", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_BIC, "bic", UINT8_C(0x0f) },
    { CDISASM_ARM_NAME_NONE, NULL, UINT8_C(0) },
    { CDISASM_ARM_NAME_NONE, NULL, UINT8_C(0) },
    { CDISASM_ARM_NAME_NONE, NULL, UINT8_C(0) },
    { CDISASM_ARM_NAME_NONE, NULL, UINT8_C(0) }
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

static uint32_t predicated_word(
    unsigned operation,
    unsigned size_code,
    unsigned pg,
    unsigned zd,
    unsigned zm)
{
    return UINT32_C(0x04000000)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)operation << 16)
        | ((uint32_t)pg << 10)
        | ((uint32_t)zm << 5)
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
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x7000),
        CDISASM_ARM_DECODE_OPTION_NONE, instruction);
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

static int operation_is_valid(unsigned operation, unsigned size_code)
{
    return (predicated_operations[operation].size_mask
        & (UINT8_C(1) << size_code)) != 0u;
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

static void expect_success_metadata(
    const cdisasm_arm_instruction *instruction,
    uint32_t word,
    unsigned operation,
    unsigned size_code,
    unsigned pg,
    unsigned zd,
    unsigned zm)
{
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id
        == predicated_operations[operation].name_id);
    EXPECT(instruction->address == UINT64_C(0x7000));
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
    EXPECT(z_operand_matches(
        &instruction->operand[3], zm, element_size,
        CDISASM_OPERAND_ACCESS_READ));
}
#endif

static void test_exhaustive_class(void)
{
    unsigned size_code;
    uint32_t valid_words = 0u;
    uint32_t reserved_words = 0u;

    for (size_code = 0u; size_code < 4u; ++size_code) {
        unsigned operation;

        for (operation = 0u; operation < 32u; ++operation) {
            unsigned pg;

            for (pg = 0u; pg < 8u; ++pg) {
                unsigned zm;

                for (zm = 0u; zm < 32u; ++zm) {
                    unsigned zd;

                    for (zd = 0u; zd < 32u; ++zd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = predicated_word(
                            operation, size_code, pg, zd, zm);

                        memset(&instruction, 0xa5, sizeof(instruction));
                        if (operation_is_valid(operation, size_code)) {
                            ++valid_words;
#if USE_EXTRA_OPCODES
                            EXPECT(decode_word(
                                word, CDISASM_ARM_CPU_ANY,
                                CDISASM_ARM_MODE_A64, 4u,
                                &instruction) == 4u);
                            expect_success_metadata(
                                &instruction, word, operation, size_code,
                                pg, zd, zm);
#else
                            EXPECT(decode_word(
                                word, CDISASM_ARM_CPU_ANY,
                                CDISASM_ARM_MODE_A64, 4u,
                                &instruction) == 0u);
                            EXPECT(instruction_is_error_only(
                                &instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        } else {
                            ++reserved_words;
                            EXPECT(decode_word(
                                word, CDISASM_ARM_CPU_ANY,
                                CDISASM_ARM_MODE_A64, 4u,
                                &instruction) == 0u);
                            EXPECT(instruction_is_error_only(
                                &instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                        }
                    }
                }
            }
        }
    }
    EXPECT(valid_words == UINT32_C(606208));
    EXPECT(reserved_words == UINT32_C(442368));
    EXPECT(valid_words + reserved_words == UINT32_C(1048576));
}

static void test_profiles_and_feature_alternatives(void)
{
    static const cdisasm_arm_cpu_id ordinary_supported[] = {
        CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_ARM_CPU_APPLE_M4
    };
    static const cdisasm_arm_cpu_id ordinary_rejected[] = {
        CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_ARM_CPU_APPLE_A17,
        CDISASM_ARM_CPU_APPLE_M3,
        CDISASM_ARM_CPU_APPLE_M5
    };
    static const cdisasm_arm_cpu_id cpa_rejected[] = {
        CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_ARM_CPU_APPLE_M4
    };
    uint32_t ordinary = predicated_word(8u, 2u, 3u, 7u, 13u);
    uint32_t cpa = predicated_word(4u, 3u, 3u, 7u, 13u);
    size_t index;

    for (index = 0u;
         index < sizeof(ordinary_supported) / sizeof(ordinary_supported[0]);
         ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(
            ordinary, ordinary_supported[index], CDISASM_ARM_MODE_A64,
            4u, &instruction) == 4u);
        expect_success_metadata(
            &instruction, ordinary, 8u, 2u, 3u, 7u, 13u);
#else
        EXPECT(decode_word(
            ordinary, ordinary_supported[index], CDISASM_ARM_MODE_A64,
            4u, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    for (index = 0u;
         index < sizeof(ordinary_rejected) / sizeof(ordinary_rejected[0]);
         ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            ordinary, ordinary_rejected[index], CDISASM_ARM_MODE_A64,
            4u, &instruction) == 0u);
#if USE_EXTRA_OPCODES
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(
            cpa, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            4u, &instruction) == 4u);
        expect_success_metadata(
            &instruction, cpa, 4u, 3u, 3u, 7u, 13u);
#else
        EXPECT(decode_word(
            cpa, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            4u, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    for (index = 0u;
         index < sizeof(cpa_rejected) / sizeof(cpa_rejected[0]);
         ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            cpa, cpa_rejected[index], CDISASM_ARM_MODE_A64,
            4u, &instruction) == 0u);
#if USE_EXTRA_OPCODES
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_endian_truncation_and_mode(void)
{
    uint32_t word = predicated_word(27u, 3u, 7u, 31u, 0u);
    uint8_t big_bytes[4];
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    size_t code_size;
    uint32_t decoded;

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A64, 4u, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(word, big_bytes);
    memset(&big, 0xa5, sizeof(big));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A64,
        big_bytes, sizeof(big_bytes), UINT64_C(0x7000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(memcmp(&little, &big, sizeof(little)) == 0);
    expect_success_metadata(&little, word, 27u, 3u, 7u, 31u, 0u);
#else
    EXPECT(decoded == 0u);
    EXPECT(instruction_is_error_only(
        &little, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    EXPECT(memcmp(&little, &big, sizeof(little)) == 0);
#endif

    for (code_size = 1u; code_size < 4u; ++code_size) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            code_size, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_TRUNCATED));
    }

    memset(&big, 0xa5, sizeof(big));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A32, 4u, &big) == 0u);
    EXPECT(instruction_is_error_only(
        &big, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void test_formatter(void)
{
    static const char element_suffixes[4] = { 'b', 'h', 's', 'd' };
    unsigned size_code;

    for (size_code = 0u; size_code < 4u; ++size_code) {
        unsigned operation;

        for (operation = 0u; operation < 32u; ++operation) {
            cdisasm_arm_instruction instruction;
            char expected[96];
            char text[96];
            uint32_t word;
            int expected_size;

            if (!operation_is_valid(operation, size_code)) {
                continue;
            }
            word = predicated_word(operation, size_code, 3u, 7u, 13u);
            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                4u, &instruction) == 4u);
            expected_size = snprintf(
                expected, sizeof(expected),
                "%s z7.%c, p3/m, z7.%c, z13.%c",
                predicated_operations[operation].mnemonic,
                element_suffixes[size_code], element_suffixes[size_code],
                element_suffixes[size_code]);
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
    }

    {
        cdisasm_arm_instruction instruction;
        char text[96];
        static const char expected[] =
            "SUBR z7.h, p3/m, z7.h, z13.h";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            predicated_word(3u, 1u, 3u, 7u, 13u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            4u, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_class();
    test_profiles_and_feature_alternatives();
    test_endian_truncation_and_mode();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM predicated SVE integer test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM predicated SVE integer tests passed "
           "(allocated=606208, reserved=442368, extra=%d, format=%d)\n",
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
