#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x178000)
#define FAMILY_FLAGS CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

typedef enum counter_mask_kind {
    COUNTER_MASK_PEXT_ONE,
    COUNTER_MASK_PEXT_PAIR,
    COUNTER_MASK_PTRUE
} counter_mask_kind;

static int failures;

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

static void word_to_le(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)word;
    bytes[1] = (uint8_t)(word >> 8);
    bytes[2] = (uint8_t)(word >> 16);
    bytes[3] = (uint8_t)(word >> 24);
}

static uint32_t decode_word_mode(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_arm_mode mode,
    size_t size, cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, size, TEST_ADDRESS, options, instruction);
}

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, size_t size,
    cdisasm_arm_decode_option options, cdisasm_arm_instruction *instruction)
{
    return decode_word_mode(
        word, cpu_id, CDISASM_ARM_MODE_A64, size, options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction, cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static uint32_t pext_one_word(
    unsigned size, unsigned pn, unsigned lane, unsigned pd)
{
    return UINT32_C(0x25207010)
        | ((uint32_t)size << 22)
        | ((uint32_t)lane << 8)
        | ((uint32_t)pn << 5)
        | (uint32_t)pd;
}

static uint32_t pext_pair_word(
    unsigned size, unsigned pn, unsigned lane, unsigned pd)
{
    return UINT32_C(0x25207410)
        | ((uint32_t)size << 22)
        | ((uint32_t)lane << 8)
        | ((uint32_t)pn << 5)
        | (uint32_t)pd;
}

static uint32_t ptrue_word(unsigned size, unsigned pd)
{
    return UINT32_C(0x25207810)
        | ((uint32_t)size << 22)
        | (uint32_t)pd;
}

static uint32_t reserved_word(
    unsigned size, unsigned pn, unsigned lane, unsigned pd)
{
    return UINT32_C(0x25207610)
        | ((uint32_t)size << 22)
        | ((uint32_t)lane << 8)
        | ((uint32_t)pn << 5)
        | (uint32_t)pd;
}

#if USE_EXTRA_OPCODES
static void append_expected_predicate(
    cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint8_t element_size, uint8_t flags, uint64_t lane,
    cdisasm_operand_access access)
{
    operand->type = CDISASM_ARM_OPERAND_PREDICATE;
    operand->reg = reg;
    operand->extend_type = (cdisasm_arm_extend_type)element_size;
    operand->flags = flags;
    operand->imm = lane;
    operand->access = access;
}

static void expected_instruction(
    uint32_t word, counter_mask_kind kind,
    cdisasm_arm_instruction *expected)
{
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = kind == COUNTER_MASK_PTRUE
        ? CDISASM_ARM_NAME_PTRUE : CDISASM_ARM_NAME_PEXT;
    expected->form_id = kind == COUNTER_MASK_PEXT_ONE
        ? UINT16_C(2582) : kind == COUNTER_MASK_PEXT_PAIR
            ? UINT16_C(2583) : UINT16_C(2584);
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = FAMILY_FLAGS;
    expected->operand_count = kind == COUNTER_MASK_PTRUE ? 1u : 2u;

    if (kind == COUNTER_MASK_PTRUE) {
        append_expected_predicate(
            &expected->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_PN8 + (word & 7u)), element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED, 0u,
            CDISASM_OPERAND_ACCESS_WRITE);
        return;
    }
    if (kind == COUNTER_MASK_PEXT_ONE) {
        append_expected_predicate(
            &expected->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + (word & 15u)), element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED, 0u,
            CDISASM_OPERAND_ACCESS_WRITE);
    } else {
        unsigned first = word & 15u;

        expected->operand[0].type =
            CDISASM_ARM_OPERAND_PREDICATE_PAIR;
        expected->operand[0].reg = (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_P0 + first);
        expected->operand[0].index_reg = (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_P0 + ((first + 1u) & 15u));
        expected->operand[0].extend_type =
            (cdisasm_arm_extend_type)element_size;
        expected->operand[0].flags =
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED;
        expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    }
    append_expected_predicate(
        &expected->operand[1], (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_PN8 + ((word >> 5) & 7u)), 0u,
        CDISASM_ARM_OPERAND_FLAG_HAS_LANE,
        kind == COUNTER_MASK_PEXT_ONE
            ? ((word >> 8) & 3u) : ((word >> 8) & 1u),
        CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void expect_allocated(uint32_t word, counter_mask_kind kind)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        expected_instruction(word, kind, &expected);
        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated PEXT/PTRUE leaf did not decode");
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "PEXT/PTRUE metadata mismatch");
    }
#else
    (void)kind;
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded PEXT/PTRUE leaf");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF PEXT/PTRUE ownership mismatch");
#endif
}

static void expect_reserved(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved counter-to-mask control decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved counter-to-mask ownership mismatch");
}

static void test_complete_families(void)
{
    uint32_t one_count = 0u;
    uint32_t pair_count = 0u;
    uint32_t ptrue_count = 0u;
    uint32_t reserved_count = 0u;
    unsigned size;
    unsigned pn;
    unsigned lane;
    unsigned pd;

    for (size = 0u; size < 4u; ++size) {
        for (pn = 0u; pn < 8u; ++pn) {
            for (lane = 0u; lane < 4u; ++lane) {
                for (pd = 0u; pd < 16u; ++pd) {
                    expect_allocated(
                        pext_one_word(size, pn, lane, pd),
                        COUNTER_MASK_PEXT_ONE);
                    ++one_count;
                }
            }
            for (lane = 0u; lane < 2u; ++lane) {
                for (pd = 0u; pd < 16u; ++pd) {
                    expect_allocated(
                        pext_pair_word(size, pn, lane, pd),
                        COUNTER_MASK_PEXT_PAIR);
                    ++pair_count;
                    expect_reserved(reserved_word(size, pn, lane, pd));
                    ++reserved_count;
                }
            }
        }
        for (pd = 0u; pd < 8u; ++pd) {
            expect_allocated(ptrue_word(size, pd), COUNTER_MASK_PTRUE);
            ++ptrue_count;
        }
    }
    EXPECT(one_count == UINT32_C(2048));
    EXPECT(pair_count == UINT32_C(1024));
    EXPECT(ptrue_count == UINT32_C(32));
    EXPECT(reserved_count == UINT32_C(1024));
}

static void expect_profile(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_status enabled_status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_status expected;

#if USE_EXTRA_OPCODES
    expected = enabled_status;
#else
    (void)enabled_status;
    expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, cpu_id, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction)
        == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected != CDISASM_STATUS_OK) {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_feature_alternative(void)
{
    static const uint32_t words[] = {
        UINT32_C(0x25e073ff), UINT32_C(0x25e075ff),
        UINT32_C(0x25e07817)
    };
    unsigned index;

    for (index = 0u; index < sizeof(words) / sizeof(words[0]); ++index) {
        expect_profile(words[index], CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_profile(words[index], CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static int is_target_identity(const cdisasm_arm_instruction *instruction)
{
    return instruction->form_id >= UINT16_C(2582)
        && instruction->form_id <= UINT16_C(2584);
}

static void test_transport_and_boundaries(void)
{
    static const uint32_t words[] = {
        UINT32_C(0x25207010), UINT32_C(0x25e075ff),
        UINT32_C(0x25e07817)
    };
    static const uint32_t adjacent_words[] = {
        UINT32_C(0x2518e3e0), UINT32_C(0x25204010),
        UINT32_C(0x25205010), UINT32_C(0x25200000)
    };
    unsigned index;

    for (index = 0u; index < sizeof(words) / sizeof(words[0]); ++index) {
        cdisasm_arm_instruction little;
        cdisasm_arm_instruction other;
        uint8_t bytes[4];
        unsigned boundary;

        memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
        EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
        bytes[0] = (uint8_t)(words[index] >> 24);
        bytes[1] = (uint8_t)(words[index] >> 16);
        bytes[2] = (uint8_t)(words[index] >> 8);
        bytes[3] = (uint8_t)words[index];
        memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
        EXPECT(cdisasm_arm_decode(
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            bytes, sizeof(bytes), TEST_ADDRESS,
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
        EXPECT(cdisasm_arm_decode(
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            bytes, sizeof(bytes), TEST_ADDRESS,
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
        EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

        word_to_le(words[index], bytes);
        memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
        EXPECT(cdisasm_decode(
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            bytes, sizeof(bytes), TEST_ADDRESS,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
        EXPECT(cdisasm_decode(
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            bytes, sizeof(bytes), TEST_ADDRESS,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
        EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

        for (boundary = 0u; boundary < 4u; ++boundary) {
            cdisasm_status status = boundary == 0u
                ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

            memset(&other, 0xa5, sizeof(other));
            EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, boundary,
                CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
            EXPECT(instruction_is_error_only(&other, status));
        }
    }

    for (index = 0u;
         index < sizeof(adjacent_words) / sizeof(adjacent_words[0]);
         ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(adjacent_words[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(!is_target_identity(&instruction));
    }
}

static void test_a64_ownership(void)
{
    static const cdisasm_arm_mode other_modes[] = {
        CDISASM_ARM_MODE_A32, CDISASM_ARM_MODE_T32
    };
    unsigned index;

    for (index = 0u;
         index < sizeof(other_modes) / sizeof(other_modes[0]); ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word_mode(
            UINT32_C(0x25e075ff), CDISASM_ARM_CPU_ANY,
            other_modes[index], 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        EXPECT(!is_target_identity(&instruction));
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[96];

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(expected));
}

static void reject_forgery(cdisasm_arm_instruction *instruction)
{
    char text[96];

    memset(text, 0xa5, sizeof(text));
    EXPECT(cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == 0u);
    EXPECT(text[0] == '\0');
}

static void test_formatter(void)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;

    expect_format(UINT32_C(0x25207010), "pext p0.b, pn8[0]");
    expect_format(UINT32_C(0x25607137), "pext p7.h, pn9[1]");
    expect_format(UINT32_C(0x25a072d8), "pext p8.s, pn14[2]");
    expect_format(UINT32_C(0x25e073ff), "pext p15.d, pn15[3]");
    expect_format(UINT32_C(0x25207410),
        "pext {p0.b, p1.b}, pn8[0]");
    expect_format(UINT32_C(0x25607436),
        "pext {p6.h, p7.h}, pn9[0]");
    expect_format(UINT32_C(0x25a075d8),
        "pext {p8.s, p9.s}, pn14[1]");
    expect_format(UINT32_C(0x25e075fe),
        "pext {p14.d, p15.d}, pn15[1]");
    expect_format(UINT32_C(0x2520741f),
        "pext {p15.b, p0.b}, pn8[0]");
    expect_format(UINT32_C(0x25207810), "ptrue pn8.b");
    expect_format(UINT32_C(0x25607813), "ptrue pn11.h");
    expect_format(UINT32_C(0x25a07816), "ptrue pn14.s");
    expect_format(UINT32_C(0x25e07817), "ptrue pn15.d");
    expect_format(UINT32_C(0x2518e3e0), "ptrue p0.b");

    EXPECT(decode_word(UINT32_C(0x25e073ff),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_PTRUE;
    reject_forgery(&forged);
    forged = instruction;
    forged.form_id = UINT16_C(2583);
    reject_forgery(&forged);
    forged = instruction;
    forged.raw_instruction ^= UINT32_C(0x00000400);
    reject_forgery(&forged);
    forged = instruction;
    forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[0].access = CDISASM_OPERAND_ACCESS_READ;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[1].reg = CDISASM_ARM_REG_PN7;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[1].extend_type = 8u;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[1].flags =
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[1].imm = 4u;
    reject_forgery(&forged);

    EXPECT(decode_word(UINT32_C(0x2520741f),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    forged = instruction;
    forged.operand[0].index_reg = CDISASM_ARM_REG_P1;
    reject_forgery(&forged);

    EXPECT(decode_word(UINT32_C(0x25e07817),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    forged = instruction;
    forged.form_id = UINT16_C(2559);
    reject_forgery(&forged);

    EXPECT(decode_word(UINT32_C(0x8b010000), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_PEXT;
    reject_forgery(&forged);
}
#else
static void test_formatter(void)
{
}
#endif

int main(void)
{
    test_complete_families();
    test_feature_alternative();
    test_transport_and_boundaries();
    test_a64_ownership();
    test_formatter();

    if (failures != 0) {
        fprintf(stderr, "%d counter-mask PEXT/PTRUE test(s) failed\n",
            failures);
        return 1;
    }
    printf("counter-mask PEXT/PTRUE tests passed "
           "(3104 allocated, 1024 reserved)\n");
    return 0;
}
