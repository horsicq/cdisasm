#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x19a000)
#define PARENT_MASK UINT32_C(0xff20c000)
#define PARENT_VALUE UINT32_C(0x2520c000)
#define DUP_MASK UINT32_C(0xff3fc000)
#define DUP_VALUE UINT32_C(0x2538c000)
#define FDUP_MASK UINT32_C(0xff3fe000)
#define FDUP_VALUE UINT32_C(0x2539c000)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

_Static_assert(CDISASM_ARM_NAME_MUL == UINT16_C(74),
               "established MUL mnemonic ID moved");
_Static_assert(CDISASM_ARM_NAME_SQADD == UINT16_C(342),
               "established SQADD mnemonic ID moved");
_Static_assert(CDISASM_ARM_NAME_SUBR == UINT16_C(358),
               "established SUBR mnemonic ID moved");

typedef struct integer_immediate_form {
    uint32_t mask;
    uint32_t value;
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    const char *mnemonic;
    uint8_t signed_immediate;
    uint8_t shiftable;
} integer_immediate_form;

static const integer_immediate_form forms[12] = {
    { UINT32_C(0xff3fc000), UINT32_C(0x2520c000), UINT16_C(2619),
      CDISASM_ARM_NAME_ADD, "add", 0u, 1u },
    { UINT32_C(0xff3fc000), UINT32_C(0x2521c000), UINT16_C(2620),
      CDISASM_ARM_NAME_SUB, "sub", 0u, 1u },
    { UINT32_C(0xff3fc000), UINT32_C(0x2523c000), UINT16_C(2621),
      CDISASM_ARM_NAME_SUBR, "subr", 0u, 1u },
    { UINT32_C(0xff3fc000), UINT32_C(0x2524c000), UINT16_C(2622),
      CDISASM_ARM_NAME_SQADD, "sqadd", 0u, 1u },
    { UINT32_C(0xff3fc000), UINT32_C(0x2526c000), UINT16_C(2623),
      CDISASM_ARM_NAME_SQSUB, "sqsub", 0u, 1u },
    { UINT32_C(0xff3fc000), UINT32_C(0x2525c000), UINT16_C(2624),
      CDISASM_ARM_NAME_UQADD, "uqadd", 0u, 1u },
    { UINT32_C(0xff3fc000), UINT32_C(0x2527c000), UINT16_C(2625),
      CDISASM_ARM_NAME_UQSUB, "uqsub", 0u, 1u },
    { UINT32_C(0xff3fe000), UINT32_C(0x2528c000), UINT16_C(2626),
      CDISASM_ARM_NAME_SMAX, "smax", 1u, 0u },
    { UINT32_C(0xff3fe000), UINT32_C(0x252ac000), UINT16_C(2627),
      CDISASM_ARM_NAME_SMIN, "smin", 1u, 0u },
    { UINT32_C(0xff3fe000), UINT32_C(0x2529c000), UINT16_C(2628),
      CDISASM_ARM_NAME_UMAX, "umax", 0u, 0u },
    { UINT32_C(0xff3fe000), UINT32_C(0x252bc000), UINT16_C(2629),
      CDISASM_ARM_NAME_UMIN, "umin", 0u, 0u },
    { UINT32_C(0xff3fe000), UINT32_C(0x2530c000), UINT16_C(2630),
      CDISASM_ARM_NAME_MUL, "mul", 1u, 0u }
};

static int failures;
static uint64_t allocated_count;
static uint64_t leaf_reserved_count;
static uint64_t parent_reserved_count;
static uint64_t sibling_reserved_count;
static uint64_t sibling_allocated_count;

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

static int form_for_word(uint32_t word, unsigned *form_index)
{
    unsigned index;

    for (index = 0u; index < 12u; ++index) {
        if ((word & forms[index].mask) == forms[index].value) {
            *form_index = index;
            return 1;
        }
    }
    return 0;
}

#if USE_EXTRA_OPCODES
static int64_t semantic_immediate(
    const integer_immediate_form *form, uint32_t word)
{
    unsigned encoded = (word >> 5) & 255u;

    if (form->signed_immediate != 0u) {
        return encoded >= 128u
            ? (int64_t)encoded - INT64_C(256) : (int64_t)encoded;
    }
    return (int64_t)((uint64_t)encoded
        << (form->shiftable != 0u
            && (word & UINT32_C(0x00002000)) != 0u ? 8u : 0u));
}

static void append_z_operand(
    cdisasm_arm_instruction *instruction, unsigned encoded,
    uint8_t element_size, cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand =
        &instruction->operand[instruction->operand_count++];

    operand->type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    operand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    operand->extend_type = (cdisasm_arm_extend_type)element_size;
    operand->access = access;
}

static void make_expected(
    uint32_t word, const integer_immediate_form *form,
    cdisasm_arm_instruction *expected)
{
    unsigned encoded = (word >> 5) & 255u;
    unsigned zd = word & 31u;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    int64_t immediate_value = semantic_immediate(form, word);
    cdisasm_arm_operand *immediate;

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = form->name_id;
    expected->form_id = form->form_id;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG;
    append_z_operand(expected, zd, element_size,
        CDISASM_OPERAND_ACCESS_WRITE);
    append_z_operand(expected, zd, element_size,
        CDISASM_OPERAND_ACCESS_READ);
    immediate = &expected->operand[expected->operand_count++];
    immediate->type = CDISASM_OPERAND_IMMEDIATE;
    immediate->imm = (uint64_t)immediate_value;
    immediate->size = 1u;
    immediate->access = CDISASM_OPERAND_ACCESS_READ;
    if (form->signed_immediate != 0u && immediate_value < 0) {
        immediate->flags = CDISASM_OPERAND_FLAG_SIGNED;
    }
    if (form->shiftable != 0u
        && (word & UINT32_C(0x00002000)) != 0u && encoded == 0u) {
        immediate->shift_type = CDISASM_ARM_SHIFT_LSL;
        immediate->shift_amount = 8u;
    }
}

#  if USE_DISASM_FORMAT
static char suffix_for_size(unsigned size_code)
{
    static const char suffixes[4] = { 'b', 'h', 's', 'd' };

    return suffixes[size_code];
}

static void expect_exact_format(
    const cdisasm_arm_instruction *instruction,
    const integer_immediate_form *form, uint32_t word)
{
    char expected[112];
    char text[112];
    char immediate_text[48];
    int64_t value = semantic_immediate(form, word);
    unsigned encoded = (word >> 5) & 255u;
    unsigned zd = word & 31u;
    unsigned size_code = (word >> 22) & 3u;
    int immediate_length;
    int expected_length;

    if (value < 0) {
        immediate_length = snprintf(
            immediate_text, sizeof(immediate_text), "#-0x%llx",
            (unsigned long long)(UINT64_C(0) - (uint64_t)value));
    } else {
        immediate_length = snprintf(
            immediate_text, sizeof(immediate_text), "#0x%llx",
            (unsigned long long)value);
    }
    domain_expect(immediate_length > 0
            && (size_t)immediate_length < sizeof(immediate_text),
        word, "expected immediate construction failed");
    expected_length = snprintf(expected, sizeof(expected),
        "%s z%u.%c, z%u.%c, %s%s",
        form->mnemonic, zd, suffix_for_size(size_code),
        zd, suffix_for_size(size_code), immediate_text,
        form->shiftable != 0u
                && (word & UINT32_C(0x00002000)) != 0u
                && encoded == 0u
            ? ", lsl #0x8" : "");
    domain_expect(expected_length > 0
            && (size_t)expected_length < sizeof(expected),
        word, "expected text construction failed");
    domain_expect(cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == (size_t)expected_length,
        word, "formatter length mismatch");
    domain_expect(strcmp(text, expected) == 0,
        word, "formatter text mismatch");
}
#  endif
#endif

static void expect_allocated(
    uint32_t word, const integer_immediate_form *form)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated integer-immediate word did not decode");
        make_expected(word, form, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated integer-immediate metadata mismatch");
#  if USE_DISASM_FORMAT
        expect_exact_format(&instruction, form, word);
#  endif
    }
#else
    (void)form;
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded allocated integer-immediate word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF integer-immediate ownership mismatch");
#endif
    ++allocated_count;
}

static void expect_invalid(uint32_t word, uint64_t *counter)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved wide-immediate word decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved wide-immediate ownership mismatch");
    ++*counter;
}

static void expect_sibling_allocated(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        int dup = (word & DUP_MASK) == DUP_VALUE;

        domain_expect(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated DUP/FDUP neighbor did not decode");
        domain_expect(instruction.form_id
                == (dup ? UINT16_C(2631) : UINT16_C(2632)),
            word, "allocated DUP/FDUP neighbor form mismatch");
        domain_expect(instruction.name_id
                == (dup ? CDISASM_ARM_NAME_MOV : CDISASM_ARM_NAME_FMOV),
            word, "allocated DUP/FDUP neighbor alias mismatch");
    }
#else
    domain_expect(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF DUP/FDUP neighbor unexpectedly succeeded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF DUP/FDUP neighbor ownership mismatch");
#endif
    ++sibling_allocated_count;
}

static void test_complete_parent(void)
{
    uint32_t payload;

    for (payload = 0u; payload < UINT32_C(0x00200000); ++payload) {
        uint32_t word = PARENT_VALUE
            | (payload & UINT32_C(0x00003fff))
            | ((payload & UINT32_C(0x0007c000)) << 2)
            | ((payload & UINT32_C(0x00180000)) << 3);
        unsigned form_index;

        domain_expect((word & PARENT_MASK) == PARENT_VALUE,
            word, "parent payload construction failed");
        if (form_for_word(word, &form_index)) {
            const integer_immediate_form *form = &forms[form_index];
            int leaf_reserved = form->shiftable != 0u
                && ((word >> 22) & 3u) == 0u
                && (word & UINT32_C(0x00002000)) != 0u;

            if (leaf_reserved) {
                expect_invalid(word, &leaf_reserved_count);
            } else {
                expect_allocated(word, form);
            }
        } else if ((word & DUP_MASK) == DUP_VALUE
            || (word & FDUP_MASK) == FDUP_VALUE) {
            int dup = (word & DUP_MASK) == DUP_VALUE;
            unsigned size_code = (word >> 22) & 3u;
            int sibling_reserved = size_code == 0u
                && (!dup || (word & UINT32_C(0x00002000)) != 0u);

            if (sibling_reserved) {
                expect_invalid(word, &sibling_reserved_count);
            } else {
                expect_sibling_allocated(word);
            }
        } else {
            expect_invalid(word, &parent_reserved_count);
        }
    }
    EXPECT(allocated_count == UINT64_C(565248));
    EXPECT(leaf_reserved_count == UINT64_C(57344));
    EXPECT(parent_reserved_count == UINT64_C(1376256));
    EXPECT(sibling_reserved_count == UINT64_C(16384));
    EXPECT(sibling_allocated_count == UINT64_C(81920));
    EXPECT(allocated_count + leaf_reserved_count
            + parent_reserved_count + sibling_reserved_count
            + sibling_allocated_count
        == UINT64_C(2097152));
}

static uint32_t sample_word(
    unsigned form_index, unsigned size_code,
    unsigned shift, unsigned encoded_immediate, unsigned zd)
{
    return forms[form_index].value
        | ((uint32_t)size_code << 22)
        | ((uint32_t)shift << 13)
        | ((uint32_t)encoded_immediate << 5)
        | (uint32_t)zd;
}

static void expect_profile(
    uint32_t word, cdisasm_arm_cpu_id cpu_id,
    cdisasm_status enabled_status)
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

static void test_profiles_transport_and_precedence(void)
{
    uint32_t word = sample_word(3u, 1u, 1u, 0x7fu, 31u);
    uint32_t reserved = sample_word(3u, 0u, 1u, 1u, 0u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned boundary;

    expect_profile(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_profile(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_STATUS_OK);
    expect_profile(word, CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_STATUS_OK);
    expect_profile(word, CDISASM_ARM_CPU_APPLE_M4,
        CDISASM_STATUS_OK);
    expect_profile(word, CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
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
        cdisasm_status status = boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_CORTEX_A53,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, status));
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, status));
    }
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&other, 0xa5, sizeof(other));
    (void)decode_word_mode(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id < UINT16_C(2619)
        || other.form_id > UINT16_C(2630));
    memset(&other, 0xa5, sizeof(other));
    (void)decode_word_mode(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id < UINT16_C(2619)
        || other.form_id > UINT16_C(2630));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char upper_expected[112];
    char text[112];
    size_t opcode_end = strcspn(expected, " ");

    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
    memcpy(upper_expected, expected, strlen(expected) + 1u);
    {
        size_t index;

        for (index = 0u; index < opcode_end; ++index) {
            if (upper_expected[index] >= 'a'
                && upper_expected[index] <= 'z') {
                upper_expected[index] = (char)(upper_expected[index]
                    - 'a' + 'A');
            }
        }
    }
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text)) == strlen(upper_expected));
    EXPECT(strcmp(text, upper_expected) == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(expected));
}

static void reject_forgery(const cdisasm_arm_instruction *instruction)
{
    char text[112];

    memset(text, 0xa5, sizeof(text));
    EXPECT(cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == 0u);
    EXPECT(text[0] == '\0');
}

static void test_formatter_contract(void)
{
    uint32_t zero = sample_word(0u, 1u, 0u, 0u, 0u);
    uint32_t shifted_zero = sample_word(0u, 1u, 1u, 0u, 0u);
    uint32_t shifted_nonzero = sample_word(0u, 2u, 1u, 1u, 1u);
    uint32_t word = sample_word(11u, 3u, 0u, 0xffu, 31u);
    cdisasm_arm_instruction plain;
    cdisasm_arm_instruction shifted;
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;

    expect_format(zero, "add z0.h, z0.h, #0x0");
    expect_format(shifted_zero,
        "add z0.h, z0.h, #0x0, lsl #0x8");
    expect_format(shifted_nonzero, "add z1.s, z1.s, #0x100");
    expect_format(sample_word(7u, 0u, 0u, 0x80u, 2u),
        "smax z2.b, z2.b, #-0x80");
    expect_format(sample_word(8u, 3u, 0u, 0x7fu, 3u),
        "smin z3.d, z3.d, #0x7f");
    expect_format(sample_word(9u, 1u, 0u, 0xffu, 4u),
        "umax z4.h, z4.h, #0xff");
    expect_format(word, "mul z31.d, z31.d, #-0x1");

    EXPECT(decode_word(zero, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &plain) == 4u);
    EXPECT(decode_word(shifted_zero, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &shifted) == 4u);
    EXPECT(plain.operand[2].imm == 0u);
    EXPECT(plain.operand[2].shift_type == CDISASM_ARM_SHIFT_NONE);
    EXPECT(shifted.operand[2].imm == 0u);
    EXPECT(shifted.operand[2].shift_type == CDISASM_ARM_SHIFT_LSL);
    EXPECT(shifted.operand[2].shift_amount == 8u);
    EXPECT(decode_word(shifted_nonzero, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &shifted) == 4u);
    EXPECT(shifted.operand[2].imm == UINT64_C(256));
    EXPECT(shifted.operand[2].shift_type == CDISASM_ARM_SHIFT_NONE);

    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged);                                            \
    } while (0)

    REJECT_MUTATION(forged.raw_instruction = DUP_VALUE);
    REJECT_MUTATION(forged.raw_instruction = sample_word(
        0u, 0u, 1u, 1u, 0u));
    REJECT_MUTATION(forged.form_id = UINT16_C(2629));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_UMIN);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED);
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[0].extend_type = 4u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[1].extend_type = 4u);
    REJECT_MUTATION(forged.operand[1].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[2].imm = UINT64_C(1));
    REJECT_MUTATION(forged.operand[2].flags =
        CDISASM_OPERAND_FLAG_NONE);
    REJECT_MUTATION(forged.operand[2].size = 2u);
    REJECT_MUTATION(forged.operand[2].shift_type =
        CDISASM_ARM_SHIFT_LSL; forged.operand[2].shift_amount = 8u);
    REJECT_MUTATION(forged.operand[2].base_reg = CDISASM_ARM_REG_X0);
    REJECT_MUTATION(forged.operand[3].type =
        CDISASM_OPERAND_REGISTER);

#undef REJECT_MUTATION
}
#endif

int main(void)
{
    test_complete_parent();
    test_profiles_transport_and_precedence();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter_contract();
#endif
    if (failures != 0) {
        fprintf(stderr,
            "ARM SVE integer-immediate tests failed: %d\n", failures);
        return 1;
    }
    printf("ARM SVE integer-immediate tests passed "
           "(%llu allocated, %llu leaf-reserved, "
           "%llu parent-reserved, %llu sibling-reserved, "
           "%llu sibling-allocated)\n",
           (unsigned long long)allocated_count,
           (unsigned long long)leaf_reserved_count,
           (unsigned long long)parent_reserved_count,
           (unsigned long long)sibling_reserved_count,
           (unsigned long long)sibling_allocated_count);
    return 0;
}
