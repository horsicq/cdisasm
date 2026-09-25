#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x1a4000)
#define DUP_MASK UINT32_C(0xff3fc000)
#define DUP_VALUE UINT32_C(0x2538c000)
#define FDUP_MASK UINT32_C(0xff3fe000)
#define FDUP_VALUE UINT32_C(0x2539c000)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
#define FLOAT_FLAG CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT

static int failures;
static uint64_t dup_allocated_count;
static uint64_t dup_reserved_count;
static uint64_t fdup_allocated_count;
static uint64_t fdup_reserved_count;

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

#if USE_EXTRA_OPCODES
static int64_t dup_integer_value(unsigned encoded, unsigned shifted)
{
    uint64_t sign = UINT64_C(1) << 7u;
    int64_t value = (int64_t)(((uint64_t)encoded ^ sign) - sign);

    return value * (shifted != 0u ? INT64_C(256) : INT64_C(1));
}

static uint64_t vfp_expand_imm(unsigned encoded, uint8_t element_size)
{
    unsigned total_bits = 8u * element_size;
    unsigned exponent_bits = element_size == 2u ? 5u
        : element_size == 4u ? 8u : 11u;
    unsigned fraction_bits = total_bits - exponent_bits - 1u;
    unsigned selector = (encoded >> 6) & 1u;
    uint64_t exponent = (uint64_t)(selector ^ 1u)
        << (exponent_bits - 1u);

    if (selector != 0u) {
        exponent |= ((UINT64_C(1) << (exponent_bits - 3u))
                - UINT64_C(1))
            << 2u;
    }
    exponent |= (encoded >> 4) & 3u;
    return ((uint64_t)((encoded >> 7) & 1u) << (total_bits - 1u))
        | (exponent << fraction_bits)
        | ((uint64_t)(encoded & 15u) << (fraction_bits - 4u));
}

static void make_expected(
    uint32_t word, int floating, cdisasm_arm_instruction *expected)
{
    unsigned encoded = (word >> 5) & 255u;
    unsigned shifted = (word & UINT32_C(0x00002000)) != 0u;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    cdisasm_arm_operand *destination;
    cdisasm_arm_operand *immediate;

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = floating
        ? CDISASM_ARM_NAME_FMOV : CDISASM_ARM_NAME_MOV;
    expected->form_id = floating ? UINT16_C(2632) : UINT16_C(2631);
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG
        | (floating ? FLOAT_FLAG : 0u);
    destination = &expected->operand[expected->operand_count++];
    destination->type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    destination->reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u));
    destination->extend_type = (cdisasm_arm_extend_type)element_size;
    destination->access = CDISASM_OPERAND_ACCESS_WRITE;
    immediate = &expected->operand[expected->operand_count++];
    immediate->type = CDISASM_OPERAND_IMMEDIATE;
    immediate->imm = floating
        ? vfp_expand_imm(encoded, element_size)
        : (uint64_t)dup_integer_value(encoded, shifted);
    immediate->size = 1u;
    immediate->access = CDISASM_OPERAND_ACCESS_READ;
    if (!floating && dup_integer_value(encoded, shifted) < 0) {
        immediate->flags = CDISASM_OPERAND_FLAG_SIGNED;
    }
    if (!floating && shifted != 0u && encoded == 0u) {
        immediate->shift_type = CDISASM_ARM_SHIFT_LSL;
        immediate->shift_amount = 8u;
    }
}
#endif

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static char suffix_for_size(unsigned size_code)
{
    static const char suffixes[4] = { 'b', 'h', 's', 'd' };

    return suffixes[size_code];
}

static void fp_immediate_text(unsigned encoded, char text[32])
{
    unsigned numerator = 16u + (encoded & 15u);
    int exponent = ((encoded >> 6) & 1u) != 0u ? -3 : 1;
    uint64_t scaled;

    exponent += (int)((encoded >> 4) & 3u);
    scaled = (uint64_t)numerator * UINT64_C(100000000);
    if (exponent >= 0) {
        scaled = (scaled << (unsigned)exponent) / UINT64_C(16);
    } else {
        scaled /= UINT64_C(16) << (unsigned)(-exponent);
    }
    (void)snprintf(text, 32u, "#%s%llu.%08llu",
        (encoded & 128u) != 0u ? "-" : "",
        (unsigned long long)(scaled / UINT64_C(100000000)),
        (unsigned long long)(scaled % UINT64_C(100000000)));
}

static void expect_exact_format(
    const cdisasm_arm_instruction *instruction, uint32_t word, int floating)
{
    char expected[112];
    char immediate_text[40];
    char text[112];
    unsigned encoded = (word >> 5) & 255u;
    unsigned shifted = (word & UINT32_C(0x00002000)) != 0u;
    unsigned size_code = (word >> 22) & 3u;
    unsigned zd = word & 31u;
    int expected_length;

    if (floating) {
        fp_immediate_text(encoded, immediate_text);
    } else {
        int64_t value = dup_integer_value(encoded, shifted);

        if (value < 0) {
            (void)snprintf(immediate_text, sizeof(immediate_text),
                "#-0x%llx", (unsigned long long)(
                    UINT64_C(0) - (uint64_t)value));
        } else {
            (void)snprintf(immediate_text, sizeof(immediate_text),
                "#0x%llx", (unsigned long long)value);
        }
    }
    expected_length = snprintf(expected, sizeof(expected),
        "%s z%u.%c, %s%s", floating ? "fmov" : "mov", zd,
        suffix_for_size(size_code), immediate_text,
        !floating && shifted != 0u && encoded == 0u
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
#endif

static void expect_allocated(uint32_t word, int floating)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated DUP/FDUP word did not decode");
        make_expected(word, floating, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated DUP/FDUP metadata mismatch");
#  if USE_DISASM_FORMAT
        expect_exact_format(&instruction, word, floating);
#  endif
    }
#else
    (void)floating;
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded allocated DUP/FDUP word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF DUP/FDUP ownership mismatch");
#endif
}

static void expect_invalid(uint32_t word, uint64_t *counter)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved DUP/FDUP word decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved DUP/FDUP ownership mismatch");
    ++*counter;
}

static void test_complete_leaves(void)
{
    unsigned size_code;
    unsigned shifted;
    unsigned encoded;
    unsigned zd;

    for (size_code = 0u; size_code < 4u; ++size_code) {
        for (shifted = 0u; shifted < 2u; ++shifted) {
            for (encoded = 0u; encoded < 256u; ++encoded) {
                for (zd = 0u; zd < 32u; ++zd) {
                    uint32_t word = DUP_VALUE
                        | ((uint32_t)size_code << 22)
                        | ((uint32_t)shifted << 13)
                        | ((uint32_t)encoded << 5) | zd;

                    domain_expect((word & DUP_MASK) == DUP_VALUE,
                        word, "DUP payload construction failed");
                    if (size_code == 0u && shifted != 0u) {
                        expect_invalid(word, &dup_reserved_count);
                    } else {
                        expect_allocated(word, 0);
                        ++dup_allocated_count;
                    }
                }
            }
        }
    }
    for (size_code = 0u; size_code < 4u; ++size_code) {
        for (encoded = 0u; encoded < 256u; ++encoded) {
            for (zd = 0u; zd < 32u; ++zd) {
                uint32_t word = FDUP_VALUE
                    | ((uint32_t)size_code << 22)
                    | ((uint32_t)encoded << 5) | zd;

                domain_expect((word & FDUP_MASK) == FDUP_VALUE,
                    word, "FDUP payload construction failed");
                if (size_code == 0u) {
                    expect_invalid(word, &fdup_reserved_count);
                } else {
                    expect_allocated(word, 1);
                    ++fdup_allocated_count;
                }
            }
        }
    }
    EXPECT(dup_allocated_count == UINT64_C(57344));
    EXPECT(dup_reserved_count == UINT64_C(8192));
    EXPECT(fdup_allocated_count == UINT64_C(24576));
    EXPECT(fdup_reserved_count == UINT64_C(8192));
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
    uint32_t word = FDUP_VALUE | UINT32_C(0x00801fe0) | UINT32_C(31);
    uint32_t reserved = FDUP_VALUE | UINT32_C(0x00000020);
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
    EXPECT(other.form_id != UINT16_C(2632));
    memset(&other, 0xa5, sizeof(other));
    (void)decode_word_mode(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id != UINT16_C(2632));
}

static void test_predicated_cpy_leaves(void)
{
    static const uint32_t words[] = {
        UINT32_C(0x05100020), /* cpy z0.b, p0/z, #1 */
        UINT32_C(0x05925fa2), /* cpy z2.s, p2/m, #-3 */
        UINT32_C(0x05e09d6a)  /* cpy z10.d, p7/m, d11 */
    };
    cdisasm_arm_instruction instruction;
    size_t index;

    for (index = 0u; index < sizeof(words) / sizeof(words[0]); ++index) {
        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_CPY);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.instruction_flags
            == (SCALABLE_FLAG | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
        EXPECT(instruction.operand[0].type
            == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
        EXPECT(instruction.operand[1].type
            == CDISASM_ARM_OPERAND_PREDICATE);
        EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
#else
        EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

#if USE_EXTRA_OPCODES
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_Z10);
    EXPECT(instruction.operand[0].extend_type == 8u);
    EXPECT(instruction.operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_P7);
    EXPECT(instruction.operand[1].extend_type == 8u);
    EXPECT(instruction.operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    EXPECT(instruction.operand[2].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.operand[2].reg == CDISASM_ARM_REG_D11);
    EXPECT(instruction.operand[2].size == 8u);
    EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_word(UINT32_C(0x05100020), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);
    EXPECT(instruction.operand[2].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction.operand[2].imm == UINT64_C(1));

    EXPECT(decode_word(UINT32_C(0x05925fa2), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.operand[2].imm == (uint64_t)-INT64_C(3));
    EXPECT(instruction.operand[2].flags == CDISASM_OPERAND_FLAG_SIGNED);
#endif

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x05102000), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x05106000), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
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
    uint32_t dup_zero = DUP_VALUE | UINT32_C(0x00402000);
    uint32_t dup_negative = DUP_VALUE | UINT32_C(0x00801000) | 31u;
    uint32_t fdup_word = FDUP_VALUE | UINT32_C(0x00c01fe0) | 31u;
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[112];

    EXPECT(decode_word(dup_zero, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text)) == sizeof("MOV z0.h, #0x0, lsl #0x8") - 1u);
    EXPECT(strcmp(text, "MOV z0.h, #0x0, lsl #0x8") == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == sizeof("mov z0.h, #0x0, lsl #0x8") - 1u);

    EXPECT(decode_word(dup_negative, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.operand[1].imm
        == (uint64_t)-INT64_C(128));
    EXPECT(instruction.operand[1].flags == CDISASM_OPERAND_FLAG_SIGNED);

    EXPECT(decode_word(fdup_word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged);                                            \
    } while (0)

    REJECT_MUTATION(forged.raw_instruction = FDUP_VALUE);
    REJECT_MUTATION(forged.form_id = UINT16_C(2631));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_FDUP);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags &= ~FLOAT_FLAG);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED);
    REJECT_MUTATION(forged.operand_count = 1u);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[0].extend_type = 2u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ);
    REJECT_MUTATION(forged.operand[1].imm ^= UINT64_C(1));
    REJECT_MUTATION(forged.operand[1].size = 2u);
    REJECT_MUTATION(forged.operand[1].flags =
        CDISASM_OPERAND_FLAG_SIGNED);
    REJECT_MUTATION(forged.operand[1].shift_type =
        CDISASM_ARM_SHIFT_LSL; forged.operand[1].shift_amount = 8u);
    REJECT_MUTATION(forged.operand[1].base_reg = CDISASM_ARM_REG_X0);
    REJECT_MUTATION(forged.operand[2].type = CDISASM_OPERAND_REGISTER);

#undef REJECT_MUTATION
}
#endif

int main(void)
{
    test_complete_leaves();
    test_profiles_transport_and_precedence();
    test_predicated_cpy_leaves();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter_contract();
#endif
    if (failures != 0) {
        fprintf(stderr, "ARM SVE DUP/FDUP immediate tests failed: %d\n",
            failures);
        return 1;
    }
    printf("ARM SVE DUP/FDUP immediate tests passed "
           "(%llu DUP allocated, %llu DUP reserved, "
           "%llu FDUP allocated, %llu FDUP reserved)\n",
           (unsigned long long)dup_allocated_count,
           (unsigned long long)dup_reserved_count,
           (unsigned long long)fdup_allocated_count,
           (unsigned long long)fdup_reserved_count);
    return 0;
}
