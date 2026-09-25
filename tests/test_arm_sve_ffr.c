#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define RDFFR_PRED_PARENT_MASK UINT32_C(0xff3ffe10)
#define RDFFR_PRED_VALUE UINT32_C(0x2518f000)
#define RDFFRS_PRED_VALUE UINT32_C(0x2558f000)
#define RDFFR_PRED_MASK UINT32_C(0xfffffe10)
#define RDFFR_PARENT_MASK UINT32_C(0xff3ffff0)
#define RDFFR_VALUE UINT32_C(0x2519f000)
#define RDFFR_MASK UINT32_C(0xfffffff0)
#define WRFFR_PARENT_MASK UINT32_C(0xff3ffe1f)
#define WRFFR_VALUE UINT32_C(0x25289000)
#define WRFFR_MASK UINT32_C(0xfffffe1f)
#define SETFFR_PARENT_MASK UINT32_C(0xff3fffff)
#define SETFFR_VALUE UINT32_C(0x252c9000)
#define RDFFR_PRED_FORM UINT16_C(2562)
#define RDFFRS_PRED_FORM UINT16_C(2563)
#define RDFFR_FORM UINT16_C(2564)
#define WRFFR_FORM UINT16_C(2617)
#define SETFFR_FORM UINT16_C(2618)
#define TEST_ADDRESS UINT64_C(0x168000)
#define FFR_BASE_FLAGS                                                  \
    (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR                       \
        | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK)

_Static_assert(CDISASM_ARM_NAME_RDFFR == UINT16_C(1261),
               "generated RDFFR mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_RDFFRS == UINT16_C(1262),
               "generated RDFFRS mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_WRFFR == UINT16_C(2043),
               "generated WRFFR mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SETFFR == UINT16_C(1332),
               "generated SETFFR mnemonic ID changed");

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

static int instruction_is_ffr(const cdisasm_arm_instruction *instruction)
{
    return instruction->name_id == CDISASM_ARM_NAME_RDFFR
        || instruction->name_id == CDISASM_ARM_NAME_RDFFRS
        || instruction->name_id == CDISASM_ARM_NAME_WRFFR
        || instruction->name_id == CDISASM_ARM_NAME_SETFFR
        || instruction->form_id == RDFFR_PRED_FORM
        || instruction->form_id == RDFFRS_PRED_FORM
        || instruction->form_id == RDFFR_FORM
        || instruction->form_id == WRFFR_FORM
        || instruction->form_id == SETFFR_FORM;
}

static int word_is_allocated_ffr(uint32_t word)
{
    return (word & RDFFR_PRED_MASK) == RDFFR_PRED_VALUE
        || (word & RDFFR_PRED_MASK) == RDFFRS_PRED_VALUE
        || (word & RDFFR_MASK) == RDFFR_VALUE
        || (word & WRFFR_MASK) == WRFFR_VALUE
        || word == SETFFR_VALUE;
}

#if USE_EXTRA_OPCODES
static void expected_predicate(
    cdisasm_arm_operand *operand, unsigned encoded, uint8_t flags,
    cdisasm_operand_access access)
{
    operand->type = CDISASM_ARM_OPERAND_PREDICATE;
    operand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + encoded);
    operand->extend_type = 1u;
    operand->flags = flags;
    operand->access = access;
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
    expected->instruction_flags = FFR_BASE_FLAGS;

    if ((word & RDFFR_PRED_MASK) == RDFFR_PRED_VALUE
        || (word & RDFFR_PRED_MASK) == RDFFRS_PRED_VALUE) {
        int sets_flags = (word & UINT32_C(0x00400000)) != 0u;

        expected->name_id = sets_flags
            ? CDISASM_ARM_NAME_RDFFRS : CDISASM_ARM_NAME_RDFFR;
        expected->form_id = sets_flags
            ? RDFFRS_PRED_FORM : RDFFR_PRED_FORM;
        expected->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;
        if (sets_flags) {
            expected->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        expected->operand_count = 2u;
        expected_predicate(
            &expected->operand[0], word & 15u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE);
        expected_predicate(
            &expected->operand[1], (word >> 5) & 15u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ);
        return;
    }
    if ((word & RDFFR_MASK) == RDFFR_VALUE) {
        expected->name_id = CDISASM_ARM_NAME_RDFFR;
        expected->form_id = RDFFR_FORM;
        expected->operand_count = 1u;
        expected_predicate(
            &expected->operand[0], word & 15u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE);
        return;
    }
    if ((word & WRFFR_MASK) == WRFFR_VALUE) {
        expected->name_id = CDISASM_ARM_NAME_WRFFR;
        expected->form_id = WRFFR_FORM;
        expected->operand_count = 1u;
        expected_predicate(
            &expected->operand[0], (word >> 5) & 15u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_READ);
        return;
    }
    expected->name_id = CDISASM_ARM_NAME_SETFFR;
    expected->form_id = SETFFR_FORM;
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
            "allocated FFR word did not decode");
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "FFR structured metadata mismatch");
        return decoded == 4u;
    }
#else
    domain_expect(decoded == 0u, word,
        "extras-OFF decoded allocated FFR word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF FFR ownership mismatch");
    return 0;
#endif
}

static void test_exhaustive_allocated_domain(void)
{
    uint32_t decoded_count = 0u;
    unsigned operation;
    unsigned pd;
    unsigned pg;
    unsigned pn;

    for (operation = 0u; operation < 2u; ++operation) {
        for (pd = 0u; pd < 16u; ++pd) {
            for (pg = 0u; pg < 16u; ++pg) {
                uint32_t word = RDFFR_PRED_VALUE
                    | ((uint32_t)operation << 22)
                    | ((uint32_t)pg << 5) | pd;

                domain_expect(
                    (word & RDFFR_PRED_MASK)
                        == (operation != 0u
                            ? RDFFRS_PRED_VALUE : RDFFR_PRED_VALUE),
                    word, "allocated word escaped predicated FFR leaf");
                decoded_count += (uint32_t)expect_allocated(word);
            }
        }
    }
    for (pd = 0u; pd < 16u; ++pd) {
        decoded_count += (uint32_t)expect_allocated(RDFFR_VALUE | pd);
    }
    for (pn = 0u; pn < 16u; ++pn) {
        decoded_count += (uint32_t)expect_allocated(
            WRFFR_VALUE | ((uint32_t)pn << 5));
    }
    decoded_count += (uint32_t)expect_allocated(SETFFR_VALUE);
#if USE_EXTRA_OPCODES
    EXPECT(decoded_count == UINT32_C(545));
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
        word, "reserved FFR control decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved FFR control was not INVALID");
}

static void test_exhaustive_reserved_domain(void)
{
    uint32_t reserved_count = 0u;
    unsigned control;
    unsigned pd;
    unsigned pg;
    unsigned pn;

    for (control = 2u; control < 4u; ++control) {
        for (pd = 0u; pd < 16u; ++pd) {
            for (pg = 0u; pg < 16u; ++pg) {
                uint32_t word = RDFFR_PRED_VALUE
                    | ((uint32_t)control << 22)
                    | ((uint32_t)pg << 5) | pd;

                domain_expect((word & RDFFR_PRED_PARENT_MASK)
                        == RDFFR_PRED_VALUE,
                    word, "reserved word escaped predicated FFR parent");
                expect_reserved(word);
                ++reserved_count;
            }
        }
    }
    for (control = 1u; control < 4u; ++control) {
        for (pd = 0u; pd < 16u; ++pd) {
            uint32_t word = RDFFR_VALUE
                | ((uint32_t)control << 22) | pd;

            domain_expect((word & RDFFR_PARENT_MASK) == RDFFR_VALUE,
                word, "reserved word escaped RDFFR parent");
            expect_reserved(word);
            ++reserved_count;
        }
        for (pn = 0u; pn < 16u; ++pn) {
            uint32_t word = WRFFR_VALUE
                | ((uint32_t)control << 22) | ((uint32_t)pn << 5);

            domain_expect((word & WRFFR_PARENT_MASK) == WRFFR_VALUE,
                word, "reserved word escaped WRFFR parent");
            expect_reserved(word);
            ++reserved_count;
        }
        {
            uint32_t word = SETFFR_VALUE | ((uint32_t)control << 22);

            domain_expect((word & SETFFR_PARENT_MASK) == SETFFR_VALUE,
                word, "reserved word escaped SETFFR parent");
            expect_reserved(word);
            ++reserved_count;
        }
    }
    EXPECT(reserved_count == UINT32_C(611));
}

static void test_fixed_bit_neighbors(void)
{
    static const uint32_t words[5] = {
        RDFFR_PRED_VALUE | UINT32_C(0x1ef),
        RDFFRS_PRED_VALUE | UINT32_C(0x1ef),
        RDFFR_VALUE | UINT32_C(15),
        WRFFR_VALUE | UINT32_C(0x1e0),
        SETFFR_VALUE
    };
    static const uint32_t masks[5] = {
        RDFFR_PRED_MASK, RDFFR_PRED_MASK, RDFFR_MASK, WRFFR_MASK,
        UINT32_C(0xffffffff)
    };
    unsigned index;
    unsigned bit;

    for (index = 0u; index < 5u; ++index) {
        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t neighbor;
            uint32_t decoded;

            if ((masks[index] & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            neighbor = words[index] ^ (UINT32_C(1) << bit);
            if (word_is_allocated_ffr(neighbor)) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                neighbor, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            if (decoded == 4u) {
                EXPECT(!instruction_is_ffr(&instruction));
            }
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
        EXPECT(instruction_is_ffr(&instruction));
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_cpu_profile_policy(void)
{
    static const uint32_t words[5] = {
        RDFFR_PRED_VALUE, RDFFRS_PRED_VALUE,
        RDFFR_VALUE, WRFFR_VALUE, SETFFR_VALUE
    };
    cdisasm_arm_cpu_id cpu_id;
    unsigned index;

    for (index = 0u; index < 5u; ++index) {
        expect_cpu_status(
            words[index], CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_cpu_status(
            words[index], CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);
    }
    for (cpu_id = CDISASM_ARM_CPU_FIRST;
         cpu_id <= CDISASM_ARM_CPU_LAST; ++cpu_id) {
        if (cpu_id == CDISASM_ARM_CPU_FUJITSU_A64FX
            || (cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) == 0u) {
            continue;
        }
        for (index = 0u; index < 5u; ++index) {
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
    static const uint32_t words[7] = {
        RDFFR_PRED_VALUE, RDFFRS_PRED_VALUE | UINT32_C(0x1ef),
        RDFFR_VALUE, RDFFR_VALUE | UINT32_C(15),
        WRFFR_VALUE, WRFFR_VALUE | UINT32_C(0x1e0), SETFFR_VALUE
    };
    static const cdisasm_arm_mode wrong_modes[2] = {
        CDISASM_ARM_MODE_A32, CDISASM_ARM_MODE_T32
    };
    cdisasm_arm_instruction instruction;
    uint8_t bytes[4];
    unsigned index;
    unsigned mode_index;

    for (index = 0u; index < 7u; ++index) {
        check_transport(words[index]);
    }
    for (mode_index = 0u; mode_index < 2u; ++mode_index) {
        memset(&instruction, 0xa5, sizeof(instruction));
        if (decode_word(
                SETFFR_VALUE, CDISASM_ARM_CPU_ANY,
                wrong_modes[mode_index], 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) != 0u) {
            EXPECT(!instruction_is_ffr(&instruction));
        }
    }

    word_to_le(SETFFR_VALUE, bytes);
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
    char text[48];
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
    expect_format(RDFFR_PRED_VALUE,
        "rdffr p0.b, p0/z", "RDFFR p0.b, p0/z");
    expect_format(RDFFR_PRED_VALUE | UINT32_C(0x1ef),
        "rdffr p15.b, p15/z", "RDFFR p15.b, p15/z");
    expect_format(RDFFRS_PRED_VALUE | UINT32_C(0x1ef),
        "rdffrs p15.b, p15/z", "RDFFRS p15.b, p15/z");
    expect_format(RDFFR_VALUE,
        "rdffr p0.b", "RDFFR p0.b");
    expect_format(RDFFR_VALUE | UINT32_C(15),
        "rdffr p15.b", "RDFFR p15.b");
    expect_format(WRFFR_VALUE,
        "wrffr p0.b", "WRFFR p0.b");
    expect_format(WRFFR_VALUE | UINT32_C(0x1e0),
        "wrffr p15.b", "WRFFR p15.b");
    expect_format(SETFFR_VALUE, "setffr", "SETFFR");
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
    test_fixed_bit_neighbors();
    test_cpu_profile_policy();
    test_transport_modes_and_options();
    test_formatter();

    if (failures != 0) {
        fprintf(stderr, "%d A64 SVE FFR test(s) failed\n", failures);
        return 1;
    }
    printf("A64 SVE FFR tests passed "
           "(545 allocated; 611 reserved encodings)\n");
    return 0;
}
