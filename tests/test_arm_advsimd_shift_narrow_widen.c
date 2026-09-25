#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define SHIFT_NARROW_WIDEN_MASK UINT32_C(0xbf80fc00)
#define OPERATION_COUNT 4u

typedef struct shift_narrow_widen_operation {
    uint32_t value;
    cdisasm_arm_name_id base_name;
    cdisasm_arm_name_id alias_name;
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id collision_name;
    cdisasm_arm_form_id collision_form;
    const char *mnemonic;
    uint8_t widening;
} shift_narrow_widen_operation;

/* Pinned AARCHMRS SHRN_asimdshf_N, RSHRN_asimdshf_N,
 * SSHLL_asimdshf_L, and USHLL_asimdshf_L.  AARCHMRS preferred aliases
 * SXTL/UXTL apply exactly when SSHLL/USHLL's encoded shift is zero. */
static const shift_narrow_widen_operation operations[OPERATION_COUNT] = {
    { UINT32_C(0x0f008400), CDISASM_ARM_NAME_SHRN,
      CDISASM_ARM_NAME_NONE, UINT16_C(6221), CDISASM_ARM_NAME_MOVI,
      UINT16_C(6201), "shrn", 0u },
    { UINT32_C(0x0f008c00), CDISASM_ARM_NAME_RSHRN,
      CDISASM_ARM_NAME_NONE, UINT16_C(6222), CDISASM_ARM_NAME_NONE,
      CDISASM_ARM_FORM_NONE, "rshrn", 0u },
    { UINT32_C(0x0f00a400), CDISASM_ARM_NAME_SSHLL,
      CDISASM_ARM_NAME_SXTL, UINT16_C(6225), CDISASM_ARM_NAME_MOVI,
      UINT16_C(6201), "sshll", 1u },
    { UINT32_C(0x2f00a400), CDISASM_ARM_NAME_USHLL,
      CDISASM_ARM_NAME_UXTL, UINT16_C(6240), CDISASM_ARM_NAME_MVNI,
      UINT16_C(6209), "ushll", 1u }
};

_Static_assert(CDISASM_ARM_NAME_RSHRN == UINT16_C(1291),
               "RSHRN mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SHRN == UINT16_C(1384),
               "SHRN mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SSHLL == UINT16_C(1534),
               "SSHLL mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SXTL == UINT16_C(1716),
               "SXTL mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_USHLL == UINT16_C(1836),
               "USHLL mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_UXTL == UINT16_C(1867),
               "UXTL mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6240),
               "Advanced SIMD shift narrow/widen form IDs unavailable");

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 32) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static uint32_t make_word(const shift_narrow_widen_operation *operation,
                          unsigned q, unsigned immh, unsigned immb,
                          unsigned rn, unsigned rd)
{
    return operation->value | ((uint32_t)q << 30)
        | ((uint32_t)immh << 19) | ((uint32_t)immb << 16)
        | ((uint32_t)rn << 5) | (uint32_t)rd;
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

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
                            cdisasm_arm_mode mode, size_t code_size,
                            cdisasm_arm_decode_option options,
                            cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(cpu, mode, bytes, code_size,
        UINT64_C(0x17d000), options, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
                      cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static unsigned narrow_bits_for_immh(unsigned immh)
{
    return (immh & 4u) != 0u ? 32u : (immh & 2u) != 0u ? 16u : 8u;
}

static unsigned shift_for_encoding(
    const shift_narrow_widen_operation *operation,
    unsigned immh, unsigned immb)
{
    unsigned narrow_bits = narrow_bits_for_immh(immh);
    unsigned encoded = (immh << 3) | immb;

    return operation->widening != 0u
        ? encoded - narrow_bits : 2u * narrow_bits - encoded;
}

static int vector_matches(const cdisasm_arm_operand *operand,
                          unsigned encoded, uint8_t total_size,
                          uint8_t element_size,
                          cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded);
    expected.size = total_size;
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.scale = (uint8_t)(total_size / element_size);
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int immediate_matches(const cdisasm_arm_operand *operand,
                             uint64_t value,
                             cdisasm_arm_shift_type shift_type,
                             uint8_t shift_amount)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_IMMEDIATE;
    expected.imm = value;
    expected.size = 1u;
    expected.shift_type = shift_type;
    expected.shift_amount = shift_amount;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_matches(
    const cdisasm_arm_instruction *instruction,
    const shift_narrow_widen_operation *operation,
    uint32_t word, unsigned q, unsigned immh, unsigned immb,
    unsigned rn, unsigned rd)
{
    unsigned shift = shift_for_encoding(operation, immh, immb);
    uint8_t narrow_size = (uint8_t)(narrow_bits_for_immh(immh) / 8u);
    uint8_t wide_size = (uint8_t)(narrow_size * 2u);
    int alias = operation->widening != 0u && shift == 0u;
    cdisasm_arm_name_id expected_name = alias
        ? operation->alias_name : operation->base_name;

    if (instruction->address != UINT64_C(0x17d000)
        || instruction->opcode_size != 4u
        || instruction->raw_instruction != word
        || instruction->name_id != expected_name
        || instruction->form_id != operation->form_id
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->isa_id != CDISASM_ARM_ISA_A64
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->last_error_id != CDISASM_STATUS_OK
        || instruction->operand_count != (alias ? 2u : 3u)) {
        return 0;
    }
    if (operation->widening != 0u) {
        if (!vector_matches(&instruction->operand[0], rd, 16u, wide_size,
                CDISASM_OPERAND_ACCESS_WRITE)
            || !vector_matches(&instruction->operand[1], rn,
                q != 0u ? 16u : 8u, narrow_size,
                CDISASM_OPERAND_ACCESS_READ)) {
            return 0;
        }
    } else if (!vector_matches(&instruction->operand[0], rd,
            q != 0u ? 16u : 8u, narrow_size,
            q != 0u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                     : CDISASM_OPERAND_ACCESS_WRITE)
        || !vector_matches(&instruction->operand[1], rn, 16u, wide_size,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return alias || immediate_matches(&instruction->operand[2], shift,
        CDISASM_ARM_SHIFT_NONE, 0u);
}

static int collision_metadata_matches(
    const cdisasm_arm_instruction *instruction,
    const shift_narrow_widen_operation *operation,
    uint32_t word, unsigned q, unsigned immb, unsigned rn, unsigned rd)
{
    unsigned imm8 = (immb << 5) | rn;
    uint8_t shift_amount = operation->widening != 0u ? 8u : 0u;
    uint8_t total_size = q != 0u ? 16u : 8u;

    return instruction->address == UINT64_C(0x17d000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == operation->collision_name
        && instruction->form_id == operation->collision_form
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == 2u
        && vector_matches(&instruction->operand[0], rd, total_size, 2u,
            CDISASM_OPERAND_ACCESS_WRITE)
        && immediate_matches(&instruction->operand[1],
            (uint64_t)imm8 << shift_amount,
            shift_amount == 0u ? CDISASM_ARM_SHIFT_NONE
                               : CDISASM_ARM_SHIFT_LSL,
            shift_amount);
}
#endif

static void test_exhaustive_envelopes(void)
{
    uint32_t cells[OPERATION_COUNT][2][16][3] = {{{{0u}}}};
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    uint32_t collisions = 0u;

    for (unsigned operation_index = 0u;
         operation_index < OPERATION_COUNT; ++operation_index) {
        const shift_narrow_widen_operation *operation =
            &operations[operation_index];

        for (unsigned q = 0u; q < 2u; ++q) {
            for (unsigned immh = 0u; immh < 16u; ++immh) {
                int is_collision = immh == 0u
                    && operation->collision_form != CDISASM_ARM_FORM_NONE;
                int is_allocated = immh >= 1u && immh <= 7u;
                unsigned partition = is_collision ? 0u
                    : is_allocated ? 1u : 2u;

                for (unsigned immb = 0u; immb < 8u; ++immb) {
                    for (unsigned rn = 0u; rn < 32u; ++rn) {
                        for (unsigned rd = 0u; rd < 32u; ++rd) {
                            cdisasm_arm_instruction instruction;
                            uint32_t word = make_word(
                                operation, q, immh, immb, rn, rd);
                            uint32_t decoded;

                            ++cells[operation_index][q][immh][partition];
                            if (is_collision) {
                                ++collisions;
                            } else if (is_allocated) {
                                ++allocated;
                            } else {
                                ++reserved;
                            }
                            EXPECT((word & SHIFT_NARROW_WIDEN_MASK)
                                == operation->value);
                            memset(&instruction, 0xa5,
                                   sizeof(instruction));
                            decoded = decode_word(word,
                                CDISASM_ARM_CPU_ANY,
                                CDISASM_ARM_MODE_A64, 4u,
                                CDISASM_ARM_DECODE_OPTION_NONE,
                                &instruction);
                            if (is_allocated) {
#if USE_EXTRA_OPCODES
                                EXPECT(decoded == 4u);
                                EXPECT(metadata_matches(&instruction,
                                    operation, word, q, immh, immb,
                                    rn, rd));
#else
                                EXPECT(decoded == 0u);
                                EXPECT(error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            } else if (is_collision) {
#if USE_EXTRA_OPCODES
                                EXPECT(decoded == 4u);
                                EXPECT(collision_metadata_matches(
                                    &instruction, operation, word, q,
                                    immb, rn, rd));
#else
                                EXPECT(decoded == 0u);
                                EXPECT(error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            } else {
                                EXPECT(decoded == 0u);
                                EXPECT(error_only(&instruction,
                                    CDISASM_STATUS_INVALID_INSTRUCTION));
                            }
                        }
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(458752));
    EXPECT(reserved == UINT32_C(540672));
    EXPECT(collisions == UINT32_C(49152));
    for (unsigned operation_index = 0u;
         operation_index < OPERATION_COUNT; ++operation_index) {
        for (unsigned q = 0u; q < 2u; ++q) {
            for (unsigned immh = 0u; immh < 16u; ++immh) {
                int is_collision = immh == 0u
                    && operations[operation_index].collision_form
                        != CDISASM_ARM_FORM_NONE;
                int is_allocated = immh >= 1u && immh <= 7u;
                unsigned partition = is_collision ? 0u
                    : is_allocated ? 1u : 2u;

                EXPECT(cells[operation_index][q][immh][partition]
                    == UINT32_C(8192));
                for (unsigned other = 0u; other < 3u; ++other) {
                    if (other != partition) {
                        EXPECT(cells[operation_index][q][immh][other]
                            == 0u);
                    }
                }
            }
        }
    }
}

static void expect_cpu_status(uint32_t word, cdisasm_arm_cpu_id cpu,
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
    decoded = decode_word(word, cpu, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(error_only(&instruction, expected));
    }
}

static void test_profiles_and_boundaries(void)
{
    static const uint32_t sve_siblings[] = {
        UINT32_C(0x452f1020), /* SHRNB z0.b, z1.h, #1 */
        UINT32_C(0x45301862), /* RSHRNB z2.h, z3.s, #16 */
        UINT32_C(0x450fa0a4), /* SSHLLB z4.h, z5.b, #7 */
        UINT32_C(0x451fa8e6)  /* USHLLB z6.s, z7.h, #15 */
    };

    for (unsigned operation_index = 0u;
         operation_index < OPERATION_COUNT; ++operation_index) {
        const shift_narrow_widen_operation *operation =
            &operations[operation_index];
        uint32_t word = make_word(operation, 1u, 4u, 7u, 13u, 7u);

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A34,
                          CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A53,
                          CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M3,
                          CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
                          CDISASM_STATUS_OK);

        for (unsigned bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;

            if ((SHIFT_NARROW_WIDEN_MASK
                    & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            (void)decode_word(word ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
                || instruction.form_id != operation->form_id);
        }
    }

    for (size_t index = 0u;
         index < sizeof(sve_siblings) / sizeof(sve_siblings[0]); ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(sve_siblings[index], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
            || (instruction.form_id != UINT16_C(6221)
                && instruction.form_id != UINT16_C(6222)
                && instruction.form_id != UINT16_C(6225)
                && instruction.form_id != UINT16_C(6240)));
    }
}

static void check_transport(uint32_t word)
{
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif

    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x17d000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x17d000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x17d000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x17d000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    for (unsigned boundary = 0u; boundary < 4u; ++boundary) {
        cdisasm_status expected = boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(error_only(&other, expected));
    }
}

static void test_transport_and_status_precedence(void)
{
    for (unsigned operation_index = 0u;
         operation_index < OPERATION_COUNT; ++operation_index) {
        const shift_narrow_widen_operation *operation =
            &operations[operation_index];
        cdisasm_arm_instruction instruction;
        uint32_t allocated = make_word(operation, 1u, 4u, 7u, 13u, 7u);
        uint32_t reserved = make_word(operation, 1u, 8u, 0u, 13u, 7u);

        check_transport(make_word(operation, 0u, 1u, 0u, 0u, 0u));
        check_transport(allocated);
        if (operation->collision_form != CDISASM_ARM_FORM_NONE) {
            check_transport(make_word(
                operation, 1u, 0u, 7u, 13u, 7u));
        }

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_INSTRUCTION));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 3u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_TRUNCATED));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(allocated, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, UINT64_C(1) << 63,
            &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(allocated, CDISASM_ARM_CPU_CORTEX_A7,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(allocated, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
            || instruction.form_id != operation->form_id);
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void reject_forgery(const cdisasm_arm_instruction *instruction,
                           const char *mutation)
{
    char text[160];
    size_t length;

    memset(text, 0xa5, sizeof(text));
    length = cdisasm_arm_format(instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text));
    if (length != 0u || text[0] != '\0') {
        if (failures < 32) {
            fprintf(stderr, "accepted formatter forgery: %s -> %s\n",
                    mutation, text);
        }
        ++failures;
    }
}

static void expect_format(
    const shift_narrow_widen_operation *operation,
    unsigned q, unsigned immh, unsigned immb, unsigned rn, unsigned rd,
    const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[160];
    char short_text[8];
    size_t expected_length = strlen(expected);
    size_t length;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(operation, q, immh, immb, rn, rd),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    length = cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text));
    if (length != expected_length || strcmp(text, expected) != 0) {
        fprintf(stderr, "format mismatch: expected '%s', got '%s'\n",
                expected, text);
    }
    EXPECT(length == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, NULL, 0u)
        == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        short_text, sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void test_formatter_and_schema(void)
{
    expect_format(&operations[0], 0u, 1u, 7u, 1u, 0u,
                  "shrn v0.8b, v1.8h, #1");
    expect_format(&operations[0], 1u, 1u, 0u, 3u, 2u,
                  "shrn2 v2.16b, v3.8h, #8");
    expect_format(&operations[0], 0u, 2u, 0u, 5u, 4u,
                  "shrn v4.4h, v5.4s, #16");
    expect_format(&operations[0], 1u, 7u, 7u, 7u, 6u,
                  "shrn2 v6.4s, v7.2d, #1");
    expect_format(&operations[1], 0u, 1u, 7u, 15u, 14u,
                  "rshrn v14.8b, v15.8h, #1");
    expect_format(&operations[1], 1u, 2u, 0u, 17u, 16u,
                  "rshrn2 v16.8h, v17.4s, #16");
    expect_format(&operations[1], 0u, 4u, 0u, 19u, 18u,
                  "rshrn v18.2s, v19.2d, #32");

    expect_format(&operations[2], 0u, 1u, 0u, 5u, 4u,
                  "sxtl v4.8h, v5.8b");
    expect_format(&operations[2], 1u, 2u, 0u, 7u, 6u,
                  "sxtl2 v6.4s, v7.8h");
    expect_format(&operations[2], 0u, 4u, 1u, 9u, 8u,
                  "sshll v8.2d, v9.2s, #1");
    expect_format(&operations[2], 1u, 7u, 7u, 11u, 10u,
                  "sshll2 v10.2d, v11.4s, #31");
    expect_format(&operations[3], 0u, 2u, 0u, 21u, 20u,
                  "uxtl v20.4s, v21.4h");
    expect_format(&operations[3], 1u, 4u, 0u, 23u, 22u,
                  "uxtl2 v22.2d, v23.4s");
    expect_format(&operations[3], 0u, 1u, 1u, 25u, 24u,
                  "ushll v24.8h, v25.8b, #1");

    for (unsigned operation_index = 0u;
         operation_index < OPERATION_COUNT; ++operation_index) {
        const shift_narrow_widen_operation *operation =
            &operations[operation_index];
        const shift_narrow_widen_operation *other =
            &operations[(operation_index + 1u) % OPERATION_COUNT];
        cdisasm_arm_instruction instruction;
        cdisasm_arm_instruction forged;
        char text[160];
        unsigned immh = operation->widening != 0u ? 4u : 7u;
        unsigned immb = operation->widening != 0u ? 1u : 7u;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(make_word(operation, 1u, immh, immb,
            30u, 31u), CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) != 0u);

#define REJECT_MUTATION(statement)                                          \
        do {                                                                \
            forged = instruction;                                           \
            statement;                                                      \
            reject_forgery(&forged, #statement);                            \
        } while (0)

        REJECT_MUTATION(forged.form_id = other->form_id);
        REJECT_MUTATION(forged.name_id = other->base_name);
        REJECT_MUTATION(forged.raw_instruction = make_word(
            operation, 1u, 8u, 0u, 30u, 31u));
        REJECT_MUTATION(forged.raw_instruction = make_word(
            other, 1u, immh, immb, 30u, 31u));
        REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd503201f));
        REJECT_MUTATION(forged.opcode_size = 2u);
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
        REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
        REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
        REJECT_MUTATION(forged.instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
        REJECT_MUTATION(forged.branch_target = UINT64_C(4));
        REJECT_MUTATION(forged.operand_count = 1u);
        REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_V30);
        REJECT_MUTATION(forged.operand[0].size = 8u);
        REJECT_MUTATION(forged.operand[0].extend_type =
            (cdisasm_arm_extend_type)2u);
        REJECT_MUTATION(forged.operand[0].scale = 1u);
        REJECT_MUTATION(forged.operand[0].access =
            operation->widening != 0u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                      : CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[0].imm = UINT64_C(1));
        REJECT_MUTATION(forged.operand[0].base_reg = CDISASM_ARM_REG_X0);
        REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V29);
        REJECT_MUTATION(forged.operand[1].size = 8u);
        REJECT_MUTATION(forged.operand[1].extend_type =
            (cdisasm_arm_extend_type)1u);
        REJECT_MUTATION(forged.operand[1].scale = 1u);
        REJECT_MUTATION(forged.operand[1].access =
            CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[1].address = UINT64_C(1));
        REJECT_MUTATION(forged.operand[2].imm ^= UINT64_C(1));
        REJECT_MUTATION(forged.operand[2].size = 2u);
        REJECT_MUTATION(forged.operand[2].access =
            CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[2].shift_type =
            CDISASM_ARM_SHIFT_LSL);
        REJECT_MUTATION(forged.operand[2].base_reg = CDISASM_ARM_REG_X0);
        REJECT_MUTATION(forged.operand[2].extend_type =
            CDISASM_ARM_EXTEND_UXTB);

        if (operation->widening != 0u) {
            cdisasm_arm_instruction alias;

            REJECT_MUTATION(forged.name_id = operation->alias_name;
                forged.operand_count = 2u);
            memset(&alias, 0xa5, sizeof(alias));
            EXPECT(decode_word(make_word(operation, 1u, 4u, 0u,
                30u, 31u), CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                4u, CDISASM_ARM_DECODE_OPTION_NONE, &alias) == 4u);
            forged = alias;
            forged.name_id = operation->base_name;
            reject_forgery(&forged, "base spelling on preferred alias");
            forged = alias;
            forged.operand_count = 3u;
            forged.operand[2].type = CDISASM_OPERAND_IMMEDIATE;
            forged.operand[2].size = 1u;
            forged.operand[2].access = CDISASM_OPERAND_ACCESS_READ;
            reject_forgery(&forged, "shift operand on preferred alias");
            forged = alias;
            forged.raw_instruction = make_word(
                operation, 1u, 4u, 1u, 30u, 31u);
            reject_forgery(&forged, "alias name on nonzero shift");
        }

        memset(&forged, 0, sizeof(forged));
        forged.name_id = CDISASM_ARM_NAME_NOP;
        forged.form_id = operation->form_id;
        forged.raw_instruction = UINT32_C(0xd503201f);
        forged.opcode_size = 4u;
        forged.isa_id = CDISASM_ARM_ISA_A64;
        forged.condition = CDISASM_ARM_CONDITION_AL;
        reject_forgery(&forged, "form-only claim");
        forged.form_id = CDISASM_ARM_FORM_NONE;
        forged.raw_instruction = make_word(
            operation, 1u, immh, immb, 30u, 31u);
        reject_forgery(&forged, "raw-only claim");

        memset(&forged, 0, sizeof(forged));
        forged.name_id = operation->base_name;
        forged.raw_instruction = UINT32_C(0xd503201f);
        forged.opcode_size = 4u;
        forged.isa_id = CDISASM_ARM_ISA_A64;
        forged.condition = CDISASM_ARM_CONDITION_AL;
        reject_forgery(&forged, "name-only claim");

#undef REJECT_MUTATION
    }
}
#else
static void test_formatter_and_schema(void)
{
}
#endif

static void test_saturating_rounded_narrowing(void)
{
    static const struct sat_operation { uint32_t base; cdisasm_arm_name_id name; cdisasm_arm_form_id form; uint8_t scalar; } sat[] = {
        {UINT32_C(0x5f009400),CDISASM_ARM_NAME_SQSHRN,UINT16_C(5859),1u},
        {UINT32_C(0x7f008400),CDISASM_ARM_NAME_SQSHRUN,UINT16_C(5871),1u},
        {UINT32_C(0x7f009400),CDISASM_ARM_NAME_UQSHRN,UINT16_C(5873),1u},
        {UINT32_C(0x5f009c00),CDISASM_ARM_NAME_SQRSHRN,UINT16_C(5860),1u},
        {UINT32_C(0x7f008c00),CDISASM_ARM_NAME_SQRSHRUN,UINT16_C(5872),1u},
        {UINT32_C(0x7f009c00),CDISASM_ARM_NAME_UQRSHRN,UINT16_C(5874),1u},
        {UINT32_C(0x0f009c00),CDISASM_ARM_NAME_SQRSHRN,UINT16_C(6224),0u},
        {UINT32_C(0x2f008c00),CDISASM_ARM_NAME_SQRSHRUN,UINT16_C(6237),0u},
        {UINT32_C(0x2f009c00),CDISASM_ARM_NAME_UQRSHRN,UINT16_C(6239),0u},
        {UINT32_C(0x0f009400),CDISASM_ARM_NAME_SQSHRN,UINT16_C(6223),0u},
        {UINT32_C(0x2f008400),CDISASM_ARM_NAME_SQSHRUN,UINT16_C(6236),0u},
        {UINT32_C(0x2f009400),CDISASM_ARM_NAME_UQSHRN,UINT16_C(6238),0u}
    };
    for (unsigned k=0u;k<sizeof(sat)/sizeof(sat[0]);++k) for(unsigned q=0u;q<(sat[k].scalar?1u:2u);++q) for(unsigned immh=1u;immh<=7u;++immh) for(unsigned immb=0u;immb<8u;++immb) for(unsigned rn=0u;rn<32u;++rn) for(unsigned rd=0u;rd<32u;++rd) {
        cdisasm_arm_instruction i;uint32_t word=sat[k].base|((uint32_t)q<<30)|((uint32_t)immh<<19)|((uint32_t)immb<<16)|((uint32_t)rn<<5)|rd;uint32_t decoded=decode_word(word,CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,4u,CDISASM_ARM_DECODE_OPTION_NONE,&i);
#if USE_EXTRA_OPCODES
        unsigned bits=(immh&4u)?32u:(immh&2u)?16u:8u;
        EXPECT(decoded==4u);EXPECT(i.name_id==sat[k].name);EXPECT(i.form_id==sat[k].form);EXPECT(i.instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_SIMD);EXPECT(i.operand_count==3u);EXPECT(i.operand[0].access==(sat[k].scalar||q==0u?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ_WRITE));EXPECT(i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);EXPECT(i.operand[2].imm==2u*bits-((immh<<3)|immb));
#else
        EXPECT(decoded==0u);EXPECT(error_only(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const struct { uint32_t word; const char *text; } vectors[] = {
        {UINT32_C(0x5f0f9420),"sqshrn b0, h1, #1"},{UINT32_C(0x7f108462),"sqshrun h2, s3, #16"},{UINT32_C(0x7f3994a4),"uqshrn s4, d5, #7"},{UINT32_C(0x0f0f9420),"sqshrn v0.8b, v1.8h, #1"},{UINT32_C(0x6f108462),"sqshrun2 v2.8h, v3.4s, #16"},{UINT32_C(0x2f3994a4),"uqshrn v4.2s, v5.2d, #7"},
        {UINT32_C(0x5f0f9c20),"sqrshrn b0, h1, #1"},{UINT32_C(0x7f088ce6),"sqrshrun b6, h7, #8"},{UINT32_C(0x7f1f9d28),"uqrshrn h8, s9, #1"},{UINT32_C(0x0f0f9c20),"sqrshrn v0.8b, v1.8h, #1"},{UINT32_C(0x4f089c62),"sqrshrn2 v2.16b, v3.8h, #8"},{UINT32_C(0x2f108ca4),"sqrshrun v4.4h, v5.4s, #16"},{UINT32_C(0x6f3f9ce6),"uqrshrn2 v6.4s, v7.2d, #1"}
    };
    for(unsigned k=0u;k<sizeof(vectors)/sizeof(vectors[0]);++k){cdisasm_arm_instruction i;char text[96];EXPECT(decode_word(vectors[k].word,CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,4u,CDISASM_ARM_DECODE_OPTION_NONE,&i)==4u);EXPECT(cdisasm_arm_format(&i,CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,text,sizeof(text))==strlen(vectors[k].text));if(strcmp(text,vectors[k].text)!=0)fprintf(stderr,"format %u: got '%s', expected '%s'\n",k,text,vectors[k].text);EXPECT(strcmp(text,vectors[k].text)==0);}
#endif
}

int main(void)
{
    test_exhaustive_envelopes();
    test_profiles_and_boundaries();
    test_transport_and_status_precedence();
    test_formatter_and_schema();
    test_saturating_rounded_narrowing();

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM Advanced SIMD shift narrow/widen test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM Advanced SIMD shift narrow/widen tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=458752, reserved=540672, "
           "collisions=49152)\n", USE_EXTRA_OPCODES);
    return 0;
}
