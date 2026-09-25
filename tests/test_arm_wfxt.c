#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define WFXT_MASK UINT32_C(0xffffffe0)
#define WFET_VALUE UINT32_C(0xd5031000)
#define WFIT_VALUE UINT32_C(0xd5031020)
#define WFET_FORM UINT16_C(4457)
#define WFIT_FORM UINT16_C(4458)
#define TEST_ADDRESS UINT64_C(0x161000)

_Static_assert(CDISASM_ARM_NAME_WFET == UINT16_C(2032),
               "generated WFET mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_WFIT == UINT16_C(2033),
               "generated WFIT mnemonic ID changed");

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

static void word_to_be(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
}

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_arm_mode mode,
    size_t code_size, cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, TEST_ADDRESS,
        options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction, cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static int instruction_is_wfxt(const cdisasm_arm_instruction *instruction)
{
    return instruction->name_id == CDISASM_ARM_NAME_WFET
        || instruction->name_id == CDISASM_ARM_NAME_WFIT
        || instruction->form_id == WFET_FORM
        || instruction->form_id == WFIT_FORM;
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_reg_id expected_xreg(unsigned encoded)
{
    return encoded == 31u ? CDISASM_ARM_REG_XZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded);
}

static void expected_instruction(
    uint32_t word, cdisasm_arm_instruction *expected)
{
    int interrupt = (word & UINT32_C(0x20)) != 0u;
    unsigned rt = word & 31u;

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = interrupt
        ? CDISASM_ARM_NAME_WFIT : CDISASM_ARM_NAME_WFET;
    expected->form_id = interrupt ? WFIT_FORM : WFET_FORM;
    expected->operand_count = 1u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->operand[0].type = CDISASM_OPERAND_REGISTER;
    expected->operand[0].reg = expected_xreg(rt);
    expected->operand[0].size = 8u;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_READ;
}
#endif

static void test_exhaustive_allocated_domain(void)
{
    static const uint32_t values[2] = { WFET_VALUE, WFIT_VALUE };
    uint32_t decoded_count = 0u;
    unsigned operation;
    unsigned rt;

    for (operation = 0u; operation < 2u; ++operation) {
        for (rt = 0u; rt < 32u; ++rt) {
            uint32_t word = values[operation] | rt;
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            domain_expect((word & WFXT_MASK) == values[operation],
                word, "allocated word escaped exact WFxT leaf");
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
            {
                cdisasm_arm_instruction expected;

                expected_instruction(word, &expected);
                domain_expect(decoded == 4u, word,
                    "allocated WFxT word did not decode");
                domain_expect(memcmp(
                    &instruction, &expected, sizeof(expected)) == 0,
                    word, "WFxT structured metadata mismatch");
                decoded_count += decoded == 4u;
            }
#else
            domain_expect(decoded == 0u, word,
                "extras-OFF decoded allocated WFxT word");
            domain_expect(instruction_is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                word, "extras-OFF WFxT ownership mismatch");
#endif
        }
    }
#if USE_EXTRA_OPCODES
    EXPECT(decoded_count == UINT32_C(64));
#else
    EXPECT(decoded_count == 0u);
#endif
}

static void test_fixed_bit_neighbors(void)
{
    static const uint32_t representatives[2] = {
        WFET_VALUE | UINT32_C(7), WFIT_VALUE | UINT32_C(23)
    };
    unsigned representative;
    unsigned bit;

    for (representative = 0u; representative < 2u; ++representative) {
        for (bit = 6u; bit < 32u; ++bit) {
            uint32_t neighbor = representatives[representative]
                ^ (UINT32_C(1) << bit);
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            EXPECT((neighbor & WFXT_MASK) != WFET_VALUE);
            EXPECT((neighbor & WFXT_MASK) != WFIT_VALUE);
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                neighbor, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            if (decoded == 4u) {
                EXPECT(!instruction_is_wfxt(&instruction));
            }
        }
    }

    /* Bit 5 is the allocated operation selector, not a reserved neighbor. */
    {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(
            (WFET_VALUE | UINT32_C(9)) ^ UINT32_C(0x20),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_WFIT);
        EXPECT(instruction.form_id == WFIT_FORM);
#else
        EXPECT(decode_word(
            (WFET_VALUE | UINT32_C(9)) ^ UINT32_C(0x20),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
#endif
    }
}

static void expect_cpu_status(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_status enabled_status)
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
    EXPECT(decoded == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction_is_wfxt(&instruction));
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_cpu_profile_policy(void)
{
    cdisasm_arm_cpu_id cpu_id;

    expect_cpu_status(
        WFET_VALUE, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_cpu_status(
        WFIT_VALUE | UINT32_C(31),
        CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    /* No named product profile currently advertises the independent WFxT
     * generated feature bit.  Unrestricted analysis remains the opt-in. */
    for (cpu_id = CDISASM_ARM_CPU_FIRST;
         cpu_id <= CDISASM_ARM_CPU_LAST; ++cpu_id) {
        if ((cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) != 0u) {
            expect_cpu_status(
                WFET_VALUE | (cpu_id & UINT32_C(31)), cpu_id,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_cpu_status(
                WFIT_VALUE | (cpu_id & UINT32_C(31)), cpu_id,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
}

static void check_transport(uint32_t word)
{
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned boundary;

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif

    word_to_be(word, bytes);
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

    word_to_le(word, bytes);
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
        cdisasm_status expected = boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, expected));
    }
}

static void test_transport_modes_and_options(void)
{
    static const cdisasm_arm_mode wrong_modes[2] = {
        CDISASM_ARM_MODE_A32, CDISASM_ARM_MODE_T32
    };
    cdisasm_arm_instruction instruction;
    uint8_t bytes[4];
    unsigned index;

    check_transport(WFET_VALUE);
    check_transport(WFET_VALUE | UINT32_C(31));
    check_transport(WFIT_VALUE | UINT32_C(17));
    check_transport(WFIT_VALUE | UINT32_C(31));

    for (index = 0u; index < 2u; ++index) {
        uint32_t decoded;

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(
            WFET_VALUE | UINT32_C(3), CDISASM_ARM_CPU_ANY,
            wrong_modes[index], 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        if (decoded != 0u) {
            EXPECT(!instruction_is_wfxt(&instruction));
        }
    }

    word_to_le(WFIT_VALUE, bytes);
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        NULL, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        (cdisasm_arm_decode_option)UINT64_C(2), &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[48];
    char short_text[6];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7,
        NULL, 0u) == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_0,
        short_text, sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
    EXPECT(cdisasm_arm_format(
        &instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text)) == expected_length);
    EXPECT(text[0] == 'W' && text[1] == 'F');
}

static void test_formatter(void)
{
    static const uint32_t values[2] = { WFET_VALUE, WFIT_VALUE };
    static const char *const mnemonics[2] = { "wfet", "wfit" };
    unsigned operation;
    unsigned rt;

    for (operation = 0u; operation < 2u; ++operation) {
        for (rt = 0u; rt < 32u; ++rt) {
            char expected[16];
            int length;

            if (rt == 31u) {
                length = snprintf(
                    expected, sizeof(expected), "%s xzr",
                    mnemonics[operation]);
            } else {
                length = snprintf(
                    expected, sizeof(expected), "%s x%u",
                    mnemonics[operation], rt);
            }
            EXPECT(length > 0 && (size_t)length < sizeof(expected));
            expect_format(values[operation] | rt, expected);
        }
    }
}

static void expect_invalid_format(cdisasm_arm_instruction *instruction)
{
    char text[48];

    memset(text, 0xa5, sizeof(text));
    EXPECT(cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == 0u);
    EXPECT(text[0] == '\0');
}

#define REJECT_FORGED(expression_)                                         \
    do {                                                                    \
        forged = good;                                                      \
        expression_;                                                        \
        expect_invalid_format(&forged);                                     \
    } while (0)

static void test_formatter_rejects_forged_schema(void)
{
    cdisasm_arm_instruction good;
    cdisasm_arm_instruction forged;

    memset(&good, 0xa5, sizeof(good));
    EXPECT(decode_word(
        WFET_VALUE | UINT32_C(7), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &good) == 4u);

    REJECT_FORGED(forged.name_id = CDISASM_ARM_NAME_WFIT);
    REJECT_FORGED(forged.name_id = CDISASM_ARM_NAME_WFE);
    REJECT_FORGED(forged.form_id = WFIT_FORM);
    REJECT_FORGED(forged.form_id = CDISASM_ARM_FORM_NONE);
    REJECT_FORGED(forged.raw_instruction ^= UINT32_C(1));
    REJECT_FORGED(forged.raw_instruction = UINT32_C(0xd5031047));
    REJECT_FORGED(forged.operand[0].reg = CDISASM_ARM_REG_X8);
    REJECT_FORGED(forged.operand[0].reg = CDISASM_ARM_REG_SP);
    REJECT_FORGED(forged.operand[0].size = 4u);
    REJECT_FORGED(forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_FORGED(forged.operand[0].flags = CDISASM_OPERAND_FLAG_SIGNED);
    REJECT_FORGED(forged.operand[0].shift_type = CDISASM_ARM_SHIFT_LSL;
                  forged.operand[0].shift_amount = 1u);
    REJECT_FORGED(forged.operand[0].extend_type = CDISASM_ARM_EXTEND_UXTX);
    REJECT_FORGED(forged.operand[0].scale = 1u);
    REJECT_FORGED(forged.operand_count = 0u);
    REJECT_FORGED(forged.operand_count = 2u);
    REJECT_FORGED(forged.operand[1].type = CDISASM_OPERAND_IMMEDIATE);
    REJECT_FORGED(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_FORGED(forged.instruction_flags
                  = CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK);
    REJECT_FORGED(forged.condition = CDISASM_ARM_CONDITION_NE);
    REJECT_FORGED(forged.isa_id = CDISASM_ARM_ISA_A32);
}

#undef REJECT_FORGED
#else
static void test_formatter(void)
{
}

static void test_formatter_rejects_forged_schema(void)
{
}
#endif

int main(void)
{
    test_exhaustive_allocated_domain();
    test_fixed_bit_neighbors();
    test_cpu_profile_policy();
    test_transport_modes_and_options();
    test_formatter();
    test_formatter_rejects_forged_schema();

    if (failures != 0) {
        fprintf(stderr, "%d A64 WFxT test(s) failed\n", failures);
        return 1;
    }
    printf("A64 WFxT tests passed (64 allocated encodings)\n");
    return 0;
}
