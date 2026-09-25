#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x174000)
#define FAMILY_FLAGS                                                       \
    (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR                          \
        | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS)

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

static uint32_t parent_word(
    unsigned operation, unsigned wide, unsigned rm, unsigned rn,
    unsigned not_equal)
{
    return UINT32_C(0x25202000)
        | ((uint32_t)operation << 23)
        | ((uint32_t)wide << 22)
        | ((uint32_t)rm << 16)
        | ((uint32_t)rn << 5)
        | ((uint32_t)not_equal << 4);
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_reg_id expected_reg(unsigned encoded, int wide)
{
    if (wide) {
        return encoded == 31u ? CDISASM_ARM_REG_XZR
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded);
    }
    return encoded == 31u ? CDISASM_ARM_REG_WZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + encoded);
}

static void expected_instruction(
    uint32_t word, cdisasm_arm_instruction *expected)
{
    int wide = (word & UINT32_C(0x00400000)) != 0u;
    int not_equal = (word & UINT32_C(0x00000010)) != 0u;

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = not_equal
        ? CDISASM_ARM_NAME_CTERMNE : CDISASM_ARM_NAME_CTERMEQ;
    expected->form_id = not_equal ? UINT16_C(2594) : UINT16_C(2593);
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = FAMILY_FLAGS;
    expected->operand_count = 2u;

    expected->operand[0].type = CDISASM_OPERAND_REGISTER;
    expected->operand[0].reg = expected_reg((word >> 5) & 31u, wide);
    expected->operand[0].size = wide ? 8u : 4u;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_READ;

    expected->operand[1].type = CDISASM_OPERAND_REGISTER;
    expected->operand[1].reg = expected_reg((word >> 16) & 31u, wide);
    expected->operand[1].size = wide ? 8u : 4u;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
}
#endif

static void expect_allocated(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        expected_instruction(word, &expected);
        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated CTERM leaf did not decode");
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated CTERM metadata mismatch");
    }
#else
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded allocated CTERM leaf");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF allocated CTERM ownership mismatch");
#endif
}

static void expect_reserved(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved CTERM control decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved CTERM control was not INVALID");
}

static void test_complete_parent(void)
{
    uint32_t equal_count = 0u;
    uint32_t not_equal_count = 0u;
    uint32_t reserved_count = 0u;
    unsigned operation;
    unsigned wide;
    unsigned rm;
    unsigned rn;
    unsigned not_equal;

    for (operation = 0u; operation < 2u; ++operation) {
        for (wide = 0u; wide < 2u; ++wide) {
            for (rm = 0u; rm < 32u; ++rm) {
                for (rn = 0u; rn < 32u; ++rn) {
                    for (not_equal = 0u; not_equal < 2u; ++not_equal) {
                        uint32_t word = parent_word(
                            operation, wide, rm, rn, not_equal);

                        if (operation == 0u) {
                            expect_reserved(word);
                            ++reserved_count;
                        } else {
                            expect_allocated(word);
                            if (not_equal != 0u) {
                                ++not_equal_count;
                            } else {
                                ++equal_count;
                            }
                        }
                    }
                }
            }
        }
    }
    EXPECT(equal_count == UINT32_C(2048));
    EXPECT(not_equal_count == UINT32_C(2048));
    EXPECT(reserved_count == UINT32_C(4096));
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
        UINT32_C(0x25a02000), UINT32_C(0x25ff23f0)
    };
    unsigned index;

    for (index = 0u; index < sizeof(words) / sizeof(words[0]); ++index) {
        expect_profile(words[index], CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_transport_and_adjacent(void)
{
    static const uint32_t words[] = {
        UINT32_C(0x25ad2130), UINT32_C(0x25e12000)
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

    {
        cdisasm_arm_instruction adjacent;

        memset(&adjacent, 0xa5, sizeof(adjacent));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(UINT32_C(0x25a03000), CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &adjacent) == 4u);
        EXPECT(adjacent.form_id == UINT16_C(2595));
        EXPECT(adjacent.name_id == CDISASM_ARM_NAME_WHILEWR);
#else
        EXPECT(decode_word(UINT32_C(0x25a03000), CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &adjacent) == 0u);
        EXPECT(instruction_is_error_only(
            &adjacent, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

        memset(&adjacent, 0xa5, sizeof(adjacent));
        EXPECT(decode_word(UINT32_C(0x25a02001), CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &adjacent) == 0u);
#if USE_EXTRA_OPCODES
        EXPECT(instruction_is_error_only(
            &adjacent, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
        EXPECT(instruction_is_error_only(
            &adjacent, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
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
            UINT32_C(0x25e12000), CDISASM_ARM_CPU_ANY,
            other_modes[index], 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        EXPECT(instruction.name_id != CDISASM_ARM_NAME_CTERMEQ);
        EXPECT(instruction.name_id != CDISASM_ARM_NAME_CTERMNE);
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[80];

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
    char text[80];

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

    expect_format(UINT32_C(0x25a02000), "ctermeq w0, w0");
    expect_format(UINT32_C(0x25bf23e0), "ctermeq wzr, wzr");
    expect_format(UINT32_C(0x25e12000), "ctermeq x0, x1");
    expect_format(UINT32_C(0x25a02010), "ctermne w0, w0");
    expect_format(UINT32_C(0x25ad2130), "ctermne w9, w13");
    expect_format(UINT32_C(0x25ff23f0), "ctermne xzr, xzr");

    EXPECT(decode_word(UINT32_C(0x25e12000), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_CTERMNE;
    reject_forgery(&forged);
    forged = instruction;
    forged.form_id = UINT16_C(2594);
    reject_forgery(&forged);
    forged = instruction;
    forged.raw_instruction ^= UINT32_C(0x00000010);
    reject_forgery(&forged);
    forged = instruction;
    forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;
    reject_forgery(&forged);
    forged = instruction;
    forged.instruction_flags &=
        ~CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[0].reg = CDISASM_ARM_REG_W0;
    reject_forgery(&forged);

    EXPECT(decode_word(UINT32_C(0x8b010000), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_CTERMEQ;
    reject_forgery(&forged);
}
#else
static void test_formatter(void)
{
}
#endif

int main(void)
{
    test_complete_parent();
    test_feature_alternative();
    test_transport_and_adjacent();
    test_a64_ownership();
    test_formatter();

    if (failures != 0) {
        fprintf(stderr, "%d CTERMEQ/CTERMNE test(s) failed\n", failures);
        return 1;
    }
    printf("CTERMEQ/CTERMNE tests passed (4096 allocated, "
           "4096 reserved encodings)\n");
    return 0;
}
