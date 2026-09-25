#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x447100)

_Static_assert(CDISASM_ARM_NAME_CLRBHB == UINT16_C(673),
               "established CLRBHB mnemonic ID moved");
_Static_assert(CDISASM_ARM_NAME_CSDB == UINT16_C(785),
               "established CSDB mnemonic ID moved");
_Static_assert(CDISASM_ARM_NAME_DBG == UINT16_C(788),
               "established DBG mnemonic ID moved");
_Static_assert(CDISASM_ARM_NAME_ESB == UINT16_C(810),
               "established ESB mnemonic ID moved");
_Static_assert(CDISASM_ARM_NAME_TSB == UINT16_C(1727),
               "established TSB mnemonic ID moved");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(4476),
               "generated ARM form catalog lost architectural hints");

enum hint_operation {
    HINT_ESB = 0,
    HINT_TSB,
    HINT_CSDB,
    HINT_CLRBHB,
    HINT_DBG,
    HINT_OPERATION_COUNT
};

static const cdisasm_arm_name_id hint_names[HINT_OPERATION_COUNT] = {
    CDISASM_ARM_NAME_ESB,
    CDISASM_ARM_NAME_TSB,
    CDISASM_ARM_NAME_CSDB,
    CDISASM_ARM_NAME_CLRBHB,
    CDISASM_ARM_NAME_DBG
};

static int failures;
static uint64_t a32_count;
static uint64_t t32_count;
static uint64_t a64_count;
static uint64_t neighbor_count;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 24) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static void domain_expect(int condition, uint32_t word, const char *message)
{
    if (!condition) {
        if (failures < 24) {
            fprintf(stderr, "word %08x: %s\n", (unsigned)word, message);
        }
        ++failures;
    }
}

static uint32_t hint_word(
    cdisasm_arm_mode mode, unsigned operation,
    unsigned immediate, cdisasm_arm_condition condition)
{
    static const uint32_t a32_values[5] = {
        UINT32_C(0x0320f010), UINT32_C(0x0320f012),
        UINT32_C(0x0320f014), UINT32_C(0x0320f016),
        UINT32_C(0x0320f0f0)
    };
    static const uint32_t t32_values[5] = {
        UINT32_C(0xf3af8010), UINT32_C(0xf3af8012),
        UINT32_C(0xf3af8014), UINT32_C(0xf3af8016),
        UINT32_C(0xf3af80f0)
    };
    static const uint32_t a64_values[4] = {
        UINT32_C(0xd503221f), UINT32_C(0xd503225f),
        UINT32_C(0xd503229f), UINT32_C(0xd50322df)
    };

    if (mode == CDISASM_ARM_MODE_A32) {
        return ((uint32_t)condition << 28) | a32_values[operation]
            | (operation == HINT_DBG ? immediate : 0u);
    }
    if (mode == CDISASM_ARM_MODE_T32) {
        return t32_values[operation]
            | (operation == HINT_DBG ? immediate : 0u);
    }
    return a64_values[operation];
}

#if USE_EXTRA_OPCODES
static uint32_t expected_raw(cdisasm_arm_mode mode, uint32_t word)
{
    return mode == CDISASM_ARM_MODE_T32
        ? (word << 16) | (word >> 16) : word;
}
#endif

static void encode_word(
    cdisasm_arm_mode mode, uint32_t word, int big_endian, uint8_t bytes[4])
{
    if (mode == CDISASM_ARM_MODE_T32) {
        uint16_t first = (uint16_t)(word >> 16);
        uint16_t second = (uint16_t)word;

        bytes[0] = (uint8_t)(big_endian ? first >> 8 : first);
        bytes[1] = (uint8_t)(big_endian ? first : first >> 8);
        bytes[2] = (uint8_t)(big_endian ? second >> 8 : second);
        bytes[3] = (uint8_t)(big_endian ? second : second >> 8);
    } else {
        bytes[0] = (uint8_t)(big_endian ? word >> 24 : word);
        bytes[1] = (uint8_t)(big_endian ? word >> 16 : word >> 8);
        bytes[2] = (uint8_t)(big_endian ? word >> 8 : word >> 16);
        bytes[3] = (uint8_t)(big_endian ? word : word >> 24);
    }
}

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_arm_mode mode,
    int big_endian, size_t size, cdisasm_arm_decode_option extra_options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];
    cdisasm_arm_decode_option options = extra_options
        | (big_endian ? CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN : 0u);

    encode_word(mode, word, big_endian, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, size, TEST_ADDRESS, options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction, cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_form_id hint_form(
    cdisasm_arm_mode mode, unsigned operation)
{
    static const cdisasm_arm_form_id a64_forms[4] = {
        UINT16_C(4471), UINT16_C(4473),
        UINT16_C(4475), UINT16_C(4476)
    };

    if (mode == CDISASM_ARM_MODE_A32) {
        return (cdisasm_arm_form_id)(UINT16_C(247) + operation);
    }
    if (mode == CDISASM_ARM_MODE_T32) {
        return (cdisasm_arm_form_id)(UINT16_C(1831) + operation);
    }
    return a64_forms[operation];
}

static void make_expected(
    cdisasm_arm_mode mode, unsigned operation,
    unsigned immediate, cdisasm_arm_condition condition,
    uint32_t word, cdisasm_arm_instruction *expected)
{
    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = expected_raw(mode, word);
    expected->name_id = hint_names[operation];
    expected->form_id = hint_form(mode, operation);
    expected->condition = mode == CDISASM_ARM_MODE_A32
        ? condition : CDISASM_ARM_CONDITION_AL;
    expected->isa_id = mode == CDISASM_ARM_MODE_A32
        ? CDISASM_ARM_ISA_A32
        : mode == CDISASM_ARM_MODE_T32
            ? CDISASM_ARM_ISA_T32 : CDISASM_ARM_ISA_A64;
    if (mode == CDISASM_ARM_MODE_A32
        && condition <= CDISASM_ARM_CONDITION_LE) {
        expected->opcode_groups = CDISASM_GROUP_CONDITIONAL;
    }
    if (operation == HINT_DBG) {
        cdisasm_arm_operand *operand =
            &expected->operand[expected->operand_count++];

        operand->type = CDISASM_OPERAND_IMMEDIATE;
        operand->imm = immediate;
        operand->size = 1u;
        operand->access = CDISASM_OPERAND_ACCESS_READ;
    }
}
#endif

static void expect_allocated(
    cdisasm_arm_mode mode, unsigned operation,
    unsigned immediate, cdisasm_arm_condition condition)
{
    uint32_t word = hint_word(mode, operation, immediate, condition);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;

    memset(&little, 0xa5, sizeof(little));
    memset(&big, 0xa5, sizeof(big));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, mode, 0, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u,
            word, "allocated architectural hint did not decode");
        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, mode, 1, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &big) == 4u,
            word, "big-endian architectural hint did not decode");
        make_expected(
            mode, operation, immediate, condition, word, &expected);
        domain_expect(memcmp(&little, &expected, sizeof(expected)) == 0,
            word, "architectural hint metadata mismatch");
        domain_expect(memcmp(&big, &expected, sizeof(expected)) == 0,
            word, "architectural hint endian transport mismatch");
    }
#else
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, mode, 0, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u,
        word, "extras-OFF decoded architectural hint");
    domain_expect(instruction_is_error_only(
        &little, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF architectural-hint ownership mismatch");
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, mode, 1, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &big) == 0u,
        word, "extras-OFF decoded big-endian architectural hint");
    domain_expect(instruction_is_error_only(
        &big, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF big-endian hint ownership mismatch");
#endif
}

static void test_complete_allocations(void)
{
    unsigned condition;

    for (condition = 0u; condition <= CDISASM_ARM_CONDITION_AL;
         ++condition) {
        unsigned operation;

        for (operation = HINT_ESB; operation <= HINT_CLRBHB;
             ++operation) {
            expect_allocated(
                CDISASM_ARM_MODE_A32, operation, 0u,
                (cdisasm_arm_condition)condition);
            ++a32_count;
        }
        for (operation = 0u; operation < 16u; ++operation) {
            expect_allocated(
                CDISASM_ARM_MODE_A32, HINT_DBG, operation,
                (cdisasm_arm_condition)condition);
            ++a32_count;
        }
    }
    for (condition = HINT_ESB; condition <= HINT_CLRBHB; ++condition) {
        expect_allocated(
            CDISASM_ARM_MODE_T32, condition, 0u,
            CDISASM_ARM_CONDITION_AL);
        ++t32_count;
    }
    for (condition = 0u; condition < 16u; ++condition) {
        expect_allocated(
            CDISASM_ARM_MODE_T32, HINT_DBG, condition,
            CDISASM_ARM_CONDITION_AL);
        ++t32_count;
    }
    for (condition = HINT_ESB; condition <= HINT_CLRBHB; ++condition) {
        expect_allocated(
            CDISASM_ARM_MODE_A64, condition, 0u,
            CDISASM_ARM_CONDITION_AL);
        ++a64_count;
    }
    EXPECT(a32_count == UINT64_C(300));
    EXPECT(t32_count == UINT64_C(20));
    EXPECT(a64_count == UINT64_C(4));
}

static void expect_profile(
    cdisasm_arm_mode mode, unsigned operation,
    cdisasm_arm_cpu_id cpu_id, cdisasm_status enabled_status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_status expected;
    uint32_t word = hint_word(
        mode, operation, operation == HINT_DBG ? 15u : 0u,
        CDISASM_ARM_CONDITION_AL);

#if USE_EXTRA_OPCODES
    expected = enabled_status;
#else
    (void)enabled_status;
    expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        word, cpu_id, mode, 0, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction)
        == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
#if USE_EXTRA_OPCODES
        EXPECT(instruction.form_id == hint_form(mode, operation));
#endif
        EXPECT(instruction.name_id == hint_names[operation]);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_profiles(void)
{
    expect_profile(CDISASM_ARM_MODE_A64, HINT_ESB,
        CDISASM_ARM_CPU_APPLE_A11, CDISASM_STATUS_OK);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_ESB,
        CDISASM_ARM_CPU_APPLE_A18, CDISASM_STATUS_OK);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_ESB,
        CDISASM_ARM_CPU_APPLE_M4, CDISASM_STATUS_OK);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_ESB,
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_STATUS_OK);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_ESB,
        CDISASM_ARM_CPU_APPLE_A10, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_ESB,
        CDISASM_ARM_CPU_CORTEX_A53, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_ESB,
        CDISASM_ARM_CPU_APPLE_A19, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_ESB,
        CDISASM_ARM_CPU_APPLE_M5, CDISASM_STATUS_INVALID_INSTRUCTION);

    expect_profile(CDISASM_ARM_MODE_A64, HINT_TSB,
        CDISASM_ARM_CPU_APPLE_A13, CDISASM_STATUS_OK);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_TSB,
        CDISASM_ARM_CPU_APPLE_A18, CDISASM_STATUS_OK);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_TSB,
        CDISASM_ARM_CPU_APPLE_M1, CDISASM_STATUS_OK);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_TSB,
        CDISASM_ARM_CPU_APPLE_S6, CDISASM_STATUS_OK);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_TSB,
        CDISASM_ARM_CPU_APPLE_A12, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_TSB,
        CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    expect_profile(CDISASM_ARM_MODE_A64, HINT_CLRBHB,
        CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_CLRBHB,
        CDISASM_ARM_CPU_APPLE_A18, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(CDISASM_ARM_MODE_A32, HINT_ESB,
        CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_profile(CDISASM_ARM_MODE_A32, HINT_ESB,
        CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(CDISASM_ARM_MODE_T32, HINT_TSB,
        CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(CDISASM_ARM_MODE_T32, HINT_CLRBHB,
        CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    expect_profile(CDISASM_ARM_MODE_A32, HINT_CSDB,
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_STATUS_OK);
    expect_profile(CDISASM_ARM_MODE_A32, HINT_CSDB,
        CDISASM_ARM_CPU_ARM7TDMI, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(CDISASM_ARM_MODE_A32, HINT_DBG,
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_STATUS_OK);
    expect_profile(CDISASM_ARM_MODE_A32, HINT_DBG,
        CDISASM_ARM_CPU_ARM7TDMI, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(CDISASM_ARM_MODE_T32, HINT_DBG,
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_STATUS_OK);
    expect_profile(CDISASM_ARM_MODE_A64, HINT_CSDB,
        CDISASM_ARM_CPU_CORTEX_A34, CDISASM_STATUS_OK);
}

static int form_is_family(cdisasm_arm_form_id form_id)
{
    return (form_id >= UINT16_C(247) && form_id <= UINT16_C(251))
        || (form_id >= UINT16_C(1831) && form_id <= UINT16_C(1835))
        || form_id == UINT16_C(4471) || form_id == UINT16_C(4473)
        || form_id == UINT16_C(4475) || form_id == UINT16_C(4476);
}

static void expect_neighbor(cdisasm_arm_mode mode, uint32_t word)
{
    cdisasm_arm_instruction instruction;
    uint32_t size;

    memset(&instruction, 0xa5, sizeof(instruction));
    size = decode_word(
        word, CDISASM_ARM_CPU_ANY, mode, 0, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    if (size != 0u) {
        domain_expect(!form_is_family(instruction.form_id),
            word, "neighbor decoded as requested hint leaf");
    } else {
        domain_expect(instruction.last_error_id != CDISASM_STATUS_OK,
            word, "neighbor failure omitted status");
    }
    ++neighbor_count;
}

static void test_boundaries_and_transport(void)
{
    static const uint32_t a32_neighbors[6] = {
        UINT32_C(0xe320f011), UINT32_C(0xe320f013),
        UINT32_C(0xe320f015), UINT32_C(0xe320f017),
        UINT32_C(0xf320f010), UINT32_C(0xf320f0ff)
    };
    static const uint32_t t32_neighbors[5] = {
        UINT32_C(0xf3af8011), UINT32_C(0xf3af8013),
        UINT32_C(0xf3af8015), UINT32_C(0xf3af8017),
        UINT32_C(0xf3af8100)
    };
    static const uint32_t a64_neighbors[5] = {
        UINT32_C(0xd503223f), UINT32_C(0xd503227f),
        UINT32_C(0xd50322bf), UINT32_C(0xd50322ff),
        UINT32_C(0xd503231f)
    };
    cdisasm_arm_instruction plain;
    cdisasm_arm_instruction other;
    uint32_t t32_word = hint_word(
        CDISASM_ARM_MODE_T32, HINT_DBG, 15u,
        CDISASM_ARM_CONDITION_AL);
    size_t index;
    unsigned boundary;

    for (index = 0u; index < sizeof(a32_neighbors) / sizeof(a32_neighbors[0]);
         ++index) {
        expect_neighbor(CDISASM_ARM_MODE_A32, a32_neighbors[index]);
    }
    for (index = 0u; index < sizeof(t32_neighbors) / sizeof(t32_neighbors[0]);
         ++index) {
        expect_neighbor(CDISASM_ARM_MODE_T32, t32_neighbors[index]);
    }
    for (index = 0u; index < sizeof(a64_neighbors) / sizeof(a64_neighbors[0]);
         ++index) {
        expect_neighbor(CDISASM_ARM_MODE_A64, a64_neighbors[index]);
    }
    EXPECT(neighbor_count == UINT64_C(16));

    for (boundary = 0u; boundary < 4u; ++boundary) {
        cdisasm_status status = boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(
            t32_word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32,
            0, boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, status));
    }

    memset(&plain, 0xa5, sizeof(plain));
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(
        t32_word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32,
        0, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &plain) == 4u);
    EXPECT(decode_word(
        t32_word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32,
        0, 4u, CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK, &other) == 4u);
    EXPECT(memcmp(&plain, &other, sizeof(plain)) == 0);
#else
    EXPECT(decode_word(
        t32_word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32,
        0, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &plain) == 0u);
    EXPECT(decode_word(
        t32_word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32,
        0, 4u, CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK, &other) == 0u);
#endif

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        t32_word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32,
        0, 4u, UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        UINT32_C(0xe320f014), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 0, 4u,
        CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(
    cdisasm_arm_mode mode, unsigned operation,
    unsigned immediate, cdisasm_arm_condition condition,
    const char *expected)
{
    cdisasm_arm_instruction instruction;
    char uppercase_expected[80];
    char text[80];
    size_t opcode_end = strcspn(expected, " ");
    size_t index;
    uint32_t word = hint_word(mode, operation, immediate, condition);

    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, mode, 0, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
    memcpy(uppercase_expected, expected, strlen(expected) + 1u);
    for (index = 0u; index < opcode_end; ++index) {
        if (uppercase_expected[index] >= 'a'
            && uppercase_expected[index] <= 'z') {
            uppercase_expected[index] = (char)(uppercase_expected[index]
                - 'a' + 'A');
        }
    }
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text)) == strlen(uppercase_expected));
    EXPECT(strcmp(text, uppercase_expected) == 0);
}

static void reject_forgery(const cdisasm_arm_instruction *instruction)
{
    char text[80];

    memset(text, 0xa5, sizeof(text));
    EXPECT(cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == 0u);
    EXPECT(text[0] == '\0');
}

static void test_formatter_contract(void)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction dbg;
    cdisasm_arm_instruction forged;

    expect_format(CDISASM_ARM_MODE_A32, HINT_ESB, 0u,
        CDISASM_ARM_CONDITION_EQ, "esbeq");
    expect_format(CDISASM_ARM_MODE_A32, HINT_TSB, 0u,
        CDISASM_ARM_CONDITION_NE, "tsbne csync");
    expect_format(CDISASM_ARM_MODE_A32, HINT_CSDB, 0u,
        CDISASM_ARM_CONDITION_AL, "csdb");
    expect_format(CDISASM_ARM_MODE_A32, HINT_DBG, 15u,
        CDISASM_ARM_CONDITION_GT, "dbggt #0xf");
    expect_format(CDISASM_ARM_MODE_T32, HINT_ESB, 0u,
        CDISASM_ARM_CONDITION_AL, "esb");
    expect_format(CDISASM_ARM_MODE_T32, HINT_TSB, 0u,
        CDISASM_ARM_CONDITION_AL, "tsb csync");
    expect_format(CDISASM_ARM_MODE_T32, HINT_DBG, 15u,
        CDISASM_ARM_CONDITION_AL, "dbg #0xf");
    expect_format(CDISASM_ARM_MODE_A64, HINT_ESB, 0u,
        CDISASM_ARM_CONDITION_AL, "esb");
    expect_format(CDISASM_ARM_MODE_A64, HINT_TSB, 0u,
        CDISASM_ARM_CONDITION_AL, "tsb csync");
    expect_format(CDISASM_ARM_MODE_A64, HINT_CLRBHB, 0u,
        CDISASM_ARM_CONDITION_AL, "clrbhb");

    EXPECT(decode_word(
        hint_word(CDISASM_ARM_MODE_A64, HINT_ESB, 0u,
            CDISASM_ARM_CONDITION_AL),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(decode_word(
        hint_word(CDISASM_ARM_MODE_T32, HINT_DBG, 15u,
            CDISASM_ARM_CONDITION_AL),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32, 0, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &dbg) == 4u);

#define REJECT_MUTATION(source, statement)                                  \
    do {                                                                    \
        forged = source;                                                    \
        statement;                                                          \
        reject_forgery(&forged);                                            \
    } while (0)

    REJECT_MUTATION(instruction,
        forged.raw_instruction = UINT32_C(0xd503223f));
    REJECT_MUTATION(instruction, forged.form_id = UINT16_C(4473));
    REJECT_MUTATION(instruction, forged.name_id = CDISASM_ARM_NAME_CSDB);
    REJECT_MUTATION(instruction, forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(instruction, forged.opcode_size = 2u);
    REJECT_MUTATION(instruction,
        forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(instruction,
        forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(instruction,
        forged.instruction_flags = CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    REJECT_MUTATION(instruction, forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(instruction, forged.operand_count = 1u);
    REJECT_MUTATION(instruction,
        forged.operand[0].type = CDISASM_OPERAND_IMMEDIATE);
    REJECT_MUTATION(dbg, forged.operand_count = 0u);
    REJECT_MUTATION(dbg, forged.operand[0].imm = UINT64_C(14));
    REJECT_MUTATION(dbg, forged.operand[0].size = 2u);
    REJECT_MUTATION(dbg,
        forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(dbg,
        forged.operand[1].type = CDISASM_OPERAND_REGISTER);

#undef REJECT_MUTATION
}
#endif

int main(void)
{
    test_complete_allocations();
    test_profiles();
    test_boundaries_and_transport();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter_contract();
#endif
    if (failures != 0) {
        fprintf(stderr,
            "ARM architectural-hint tests failed: %d\n", failures);
        return 1;
    }
    printf("ARM architectural-hint tests passed "
           "(%llu A32, %llu T32, %llu A64 allocated; "
           "%llu neighbors; extras=%d, format=%d)\n",
           (unsigned long long)a32_count,
           (unsigned long long)t32_count,
           (unsigned long long)a64_count,
           (unsigned long long)neighbor_count,
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
