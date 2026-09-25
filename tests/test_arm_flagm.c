#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define CFINV_VALUE UINT32_C(0xd500401f)
#define XAFLAG_VALUE UINT32_C(0xd500403f)
#define AXFLAG_VALUE UINT32_C(0xd500405f)
#define RMIF_MASK UINT32_C(0xffe07c10)
#define RMIF_VALUE UINT32_C(0xba000400)
#define RMIF_PARENT_MASK UINT32_C(0xffe07c00)
#define SETF_MASK UINT32_C(0xfffffc1f)
#define SETF8_VALUE UINT32_C(0x3a00080d)
#define SETF16_VALUE UINT32_C(0x3a00480d)
#define SETF_PARENT_MASK UINT32_C(0xffffbc00)
#define SETF_PARENT_VALUE UINT32_C(0x3a000800)
#define CFINV_FORM UINT16_C(4499)
#define XAFLAG_FORM UINT16_C(4500)
#define AXFLAG_FORM UINT16_C(4501)
#define RMIF_FORM UINT16_C(5696)
#define SETF8_FORM UINT16_C(5697)
#define SETF16_FORM UINT16_C(5698)
#define TEST_ADDRESS UINT64_C(0x164000)
#define FLAGM_FLAGS                                                    \
    (CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS                           \
        | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK)

_Static_assert(CDISASM_ARM_NAME_CFINV == UINT16_C(668),
               "generated CFINV mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_XAFLAG == UINT16_C(2044),
               "generated XAFLAG mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_AXFLAG == UINT16_C(561),
               "generated AXFLAG mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_RMIF == UINT16_C(1283),
               "generated RMIF mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SETF8 == UINT16_C(1331),
               "generated SETF8 mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SETF16 == UINT16_C(1330),
               "generated SETF16 mnemonic ID changed");

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
        cpu_id, mode, bytes, code_size, TEST_ADDRESS, options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction, cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static int instruction_is_flagm(const cdisasm_arm_instruction *instruction)
{
    return instruction->name_id == CDISASM_ARM_NAME_CFINV
        || instruction->name_id == CDISASM_ARM_NAME_XAFLAG
        || instruction->name_id == CDISASM_ARM_NAME_AXFLAG
        || instruction->name_id == CDISASM_ARM_NAME_RMIF
        || instruction->name_id == CDISASM_ARM_NAME_SETF8
        || instruction->name_id == CDISASM_ARM_NAME_SETF16
        || instruction->form_id == CFINV_FORM
        || instruction->form_id == XAFLAG_FORM
        || instruction->form_id == AXFLAG_FORM
        || instruction->form_id == RMIF_FORM
        || instruction->form_id == SETF8_FORM
        || instruction->form_id == SETF16_FORM;
}

static int word_is_allocated_flagm(uint32_t word)
{
    return word == CFINV_VALUE || word == XAFLAG_VALUE
        || word == AXFLAG_VALUE
        || (word & RMIF_MASK) == RMIF_VALUE
        || (word & SETF_MASK) == SETF8_VALUE
        || (word & SETF_MASK) == SETF16_VALUE;
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_reg_id expected_xreg(unsigned encoded)
{
    return encoded == 31u ? CDISASM_ARM_REG_XZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded);
}

static cdisasm_arm_reg_id expected_wreg(unsigned encoded)
{
    return encoded == 31u ? CDISASM_ARM_REG_WZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + encoded);
}

static void expected_instruction(
    uint32_t word, cdisasm_arm_instruction *expected)
{
    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = FLAGM_FLAGS;

    if (word == CFINV_VALUE) {
        expected->name_id = CDISASM_ARM_NAME_CFINV;
        expected->form_id = CFINV_FORM;
        return;
    }
    if (word == XAFLAG_VALUE) {
        expected->name_id = CDISASM_ARM_NAME_XAFLAG;
        expected->form_id = XAFLAG_FORM;
        return;
    }
    if (word == AXFLAG_VALUE) {
        expected->name_id = CDISASM_ARM_NAME_AXFLAG;
        expected->form_id = AXFLAG_FORM;
        return;
    }
    if ((word & RMIF_MASK) == RMIF_VALUE) {
        expected->name_id = CDISASM_ARM_NAME_RMIF;
        expected->form_id = RMIF_FORM;
        expected->operand_count = 3u;
        expected->operand[0].type = CDISASM_OPERAND_REGISTER;
        expected->operand[0].reg = expected_xreg((word >> 5) & 31u);
        expected->operand[0].size = 8u;
        expected->operand[0].access = CDISASM_OPERAND_ACCESS_READ;
        expected->operand[1].type = CDISASM_OPERAND_IMMEDIATE;
        expected->operand[1].imm = (word >> 15) & 63u;
        expected->operand[1].size = 1u;
        expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;
        expected->operand[2].type = CDISASM_OPERAND_IMMEDIATE;
        expected->operand[2].imm = word & 15u;
        expected->operand[2].size = 1u;
        expected->operand[2].access = CDISASM_OPERAND_ACCESS_READ;
        return;
    }

    expected->name_id = (word & UINT32_C(0x4000)) != 0u
        ? CDISASM_ARM_NAME_SETF16 : CDISASM_ARM_NAME_SETF8;
    expected->form_id = (word & UINT32_C(0x4000)) != 0u
        ? SETF16_FORM : SETF8_FORM;
    expected->operand_count = 1u;
    expected->operand[0].type = CDISASM_OPERAND_REGISTER;
    expected->operand[0].reg = expected_wreg((word >> 5) & 31u);
    expected->operand[0].size = 4u;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_READ;
}
#endif

static int expect_allocated(uint32_t word)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded;

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        expected_instruction(word, &expected);
        domain_expect(decoded == 4u, word,
            "allocated FlagM word did not decode");
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "FlagM structured metadata mismatch");
        return decoded == 4u;
    }
#else
    domain_expect(decoded == 0u, word,
        "extras-OFF decoded allocated FlagM word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF FlagM ownership mismatch");
    return 0;
#endif
}

static void test_exhaustive_allocated_domain(void)
{
    static const uint32_t fixed_words[3] = {
        CFINV_VALUE, XAFLAG_VALUE, AXFLAG_VALUE
    };
    uint32_t decoded_count = 0u;
    unsigned index;
    unsigned shift;
    unsigned rn;
    unsigned mask;
    unsigned size;

    for (index = 0u; index < 3u; ++index) {
        decoded_count += (uint32_t)expect_allocated(fixed_words[index]);
    }
    for (shift = 0u; shift < 64u; ++shift) {
        for (rn = 0u; rn < 32u; ++rn) {
            for (mask = 0u; mask < 16u; ++mask) {
                uint32_t word = RMIF_VALUE | ((uint32_t)shift << 15)
                    | ((uint32_t)rn << 5) | mask;

                domain_expect((word & RMIF_MASK) == RMIF_VALUE,
                    word, "allocated word escaped RMIF leaf");
                decoded_count += (uint32_t)expect_allocated(word);
            }
        }
    }
    for (size = 0u; size < 2u; ++size) {
        for (rn = 0u; rn < 32u; ++rn) {
            uint32_t word = SETF8_VALUE | ((uint32_t)size << 14)
                | ((uint32_t)rn << 5);

            domain_expect((word & SETF_MASK)
                    == (size != 0u ? SETF16_VALUE : SETF8_VALUE),
                word, "allocated word escaped SETF leaf");
            decoded_count += (uint32_t)expect_allocated(word);
        }
    }
#if USE_EXTRA_OPCODES
    EXPECT(decoded_count == UINT32_C(32835));
#else
    EXPECT(decoded_count == 0u);
#endif
}

static void expect_reserved(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved FlagM control decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved FlagM control was not INVALID");
}

static void test_exhaustive_reserved_domain(void)
{
    uint32_t reserved_count = 0u;
    unsigned shift;
    unsigned rn;
    unsigned mask;
    unsigned size;
    unsigned control;

    for (shift = 0u; shift < 64u; ++shift) {
        for (rn = 0u; rn < 32u; ++rn) {
            for (mask = 0u; mask < 16u; ++mask) {
                uint32_t word = RMIF_VALUE | UINT32_C(0x10)
                    | ((uint32_t)shift << 15)
                    | ((uint32_t)rn << 5) | mask;

                domain_expect((word & RMIF_PARENT_MASK) == RMIF_VALUE,
                    word, "reserved word escaped RMIF parent");
                expect_reserved(word);
                ++reserved_count;
            }
        }
    }
    for (size = 0u; size < 2u; ++size) {
        for (rn = 0u; rn < 32u; ++rn) {
            for (control = 0u; control < 32u; ++control) {
                uint32_t word;

                if (control == 13u) {
                    continue;
                }
                word = SETF_PARENT_VALUE | ((uint32_t)size << 14)
                    | ((uint32_t)rn << 5) | control;
                domain_expect((word & SETF_PARENT_MASK)
                        == SETF_PARENT_VALUE,
                    word, "reserved word escaped SETF parent");
                expect_reserved(word);
                ++reserved_count;
            }
        }
    }
    EXPECT(reserved_count == UINT32_C(34752));
}

static void test_fixed_bit_neighbors_and_collision(void)
{
    static const uint32_t representatives[6] = {
        CFINV_VALUE, XAFLAG_VALUE, AXFLAG_VALUE,
        RMIF_VALUE | UINT32_C(0x001a8065),
        SETF8_VALUE | UINT32_C(0x160),
        SETF16_VALUE | UINT32_C(0x3e0)
    };
    static const uint32_t masks[6] = {
        UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), RMIF_MASK, SETF_MASK, SETF_MASK
    };
    unsigned representative;
    unsigned bit;

    for (representative = 0u; representative < 6u; ++representative) {
        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t neighbor;
            uint32_t decoded;

            if ((masks[representative]
                    & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            neighbor = representatives[representative]
                ^ (UINT32_C(1) << bit);
            if (word_is_allocated_flagm(neighbor)) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                neighbor, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            if (decoded == 4u) {
                EXPECT(!instruction_is_flagm(&instruction));
            }
        }
    }

    /* op1=000,op2=011 is the adjacent generic MSR selector, not FlagM. */
    {
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(
            UINT32_C(0xd500407f), CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        if (decoded == 4u) {
            EXPECT(!instruction_is_flagm(&instruction));
        }
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
        EXPECT(instruction_is_flagm(&instruction));
        EXPECT(instruction.instruction_flags == FLAGM_FLAGS);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_cpu_profile_policy(void)
{
    static const uint32_t words[6] = {
        CFINV_VALUE, XAFLAG_VALUE, AXFLAG_VALUE,
        RMIF_VALUE | UINT32_C(0x001f83ef),
        SETF8_VALUE | UINT32_C(0x220),
        SETF16_VALUE | UINT32_C(0x3e0)
    };
    cdisasm_arm_cpu_id cpu_id;
    unsigned index;

    for (index = 0u; index < 6u; ++index) {
        expect_cpu_status(
            words[index], CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    }
    /* No named profile advertises FEAT_FlagM or FEAT_FlagM2. */
    for (cpu_id = CDISASM_ARM_CPU_FIRST;
         cpu_id <= CDISASM_ARM_CPU_LAST; ++cpu_id) {
        if ((cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) == 0u) {
            continue;
        }
        for (index = 0u; index < 6u; ++index) {
            expect_cpu_status(
                words[index], cpu_id, CDISASM_STATUS_INVALID_INSTRUCTION);
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
    static const uint32_t words[8] = {
        CFINV_VALUE, XAFLAG_VALUE, AXFLAG_VALUE,
        RMIF_VALUE, RMIF_VALUE | UINT32_C(0x001f83ef),
        SETF8_VALUE, SETF16_VALUE, SETF16_VALUE | UINT32_C(0x3e0)
    };
    static const cdisasm_arm_mode wrong_modes[2] = {
        CDISASM_ARM_MODE_A32, CDISASM_ARM_MODE_T32
    };
    cdisasm_arm_instruction instruction;
    uint8_t bytes[4];
    unsigned index;
    unsigned mode_index;

    for (index = 0u; index < 8u; ++index) {
        check_transport(words[index]);
    }
    for (mode_index = 0u; mode_index < 2u; ++mode_index) {
        memset(&instruction, 0xa5, sizeof(instruction));
        if (decode_word(
                CFINV_VALUE, CDISASM_ARM_CPU_ANY,
                wrong_modes[mode_index], 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) != 0u) {
            EXPECT(!instruction_is_flagm(&instruction));
        }
    }

    word_to_le(CFINV_VALUE, bytes);
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
        (cdisasm_arm_decode_option)UINT64_C(4), &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(
    uint32_t word, const char *expected, const char *uppercase)
{
    cdisasm_arm_instruction instruction;
    char text[64];
    char short_text[5];
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
        text, sizeof(text)) == strlen(uppercase));
    EXPECT(strcmp(text, uppercase) == 0);
}

static void test_formatter(void)
{
    expect_format(CFINV_VALUE, "cfinv", "CFINV");
    expect_format(XAFLAG_VALUE, "xaflag", "XAFLAG");
    expect_format(AXFLAG_VALUE, "axflag", "AXFLAG");
    expect_format(RMIF_VALUE, "rmif x0, #0x0, #0x0",
        "RMIF x0, #0x0, #0x0");
    expect_format(RMIF_VALUE | UINT32_C(0x001f83ef),
        "rmif xzr, #0x3f, #0xf", "RMIF xzr, #0x3f, #0xf");
    expect_format(SETF8_VALUE, "setf8 w0", "SETF8 w0");
    expect_format(SETF8_VALUE | UINT32_C(0x3e0),
        "setf8 wzr", "SETF8 wzr");
    expect_format(SETF16_VALUE, "setf16 w0", "SETF16 w0");
    expect_format(SETF16_VALUE | UINT32_C(0x3e0),
        "setf16 wzr", "SETF16 wzr");
}

#else
static void test_formatter(void)
{
}
#endif

int main(void)
{
    test_exhaustive_allocated_domain();
    test_exhaustive_reserved_domain();
    test_fixed_bit_neighbors_and_collision();
    test_cpu_profile_policy();
    test_transport_modes_and_options();
    test_formatter();

    if (failures != 0) {
        fprintf(stderr, "%d A64 FlagM/FlagM2 test(s) failed\n", failures);
        return 1;
    }
    printf("A64 FlagM/FlagM2 tests passed "
           "(32,835 allocated; 34,752 reserved encodings)\n");
    return 0;
}
