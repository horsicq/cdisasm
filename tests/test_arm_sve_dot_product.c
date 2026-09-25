#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x1ac000)
#define PARENT_MASK UINT32_C(0xff20f800)
#define PARENT_VALUE UINT32_C(0x44000000)
#define SDOT_BASE_MASK UINT32_C(0xffa0fc00)
#define SDOT_BASE_VALUE UINT32_C(0x44800000)
#define SDOT_P3_MASK UINT32_C(0xffe0fc00)
#define SDOT_P3_VALUE UINT32_C(0x44400000)
#define UDOT_BASE_MASK UINT32_C(0xffa0fc00)
#define UDOT_BASE_VALUE UINT32_C(0x44800400)
#define UDOT_P3_MASK UINT32_C(0xffe0fc00)
#define UDOT_P3_VALUE UINT32_C(0x44400400)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

static int failures;
static uint64_t sdot_base_count;
static uint64_t sdot_p3_count;
static uint64_t udot_base_count;
static uint64_t udot_p3_count;
static uint64_t reserved_count;

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
static cdisasm_arm_form_id expected_form_id(uint32_t word)
{
    int p3 = ((word >> 22) & 3u) == 1u;
    int is_unsigned = (word & UINT32_C(0x00000400)) != 0u;

    return is_unsigned
        ? (p3 ? UINT16_C(2636) : UINT16_C(2635))
        : (p3 ? UINT16_C(2634) : UINT16_C(2633));
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
    uint32_t word, cdisasm_arm_instruction *expected)
{
    unsigned size_code = (word >> 22) & 3u;
    uint8_t destination_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t source_size = size_code == 1u
        ? 1u : (uint8_t)(destination_size / 4u);

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = (word & UINT32_C(0x00000400)) != 0u
        ? CDISASM_ARM_NAME_UDOT : CDISASM_ARM_NAME_SDOT;
    expected->form_id = expected_form_id(word);
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG;
    append_z_operand(expected, word & 31u, destination_size,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    append_z_operand(expected, (word >> 5) & 31u, source_size,
        CDISASM_OPERAND_ACCESS_READ);
    append_z_operand(expected, (word >> 16) & 31u, source_size,
        CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void expect_allocated(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated dot-product word did not decode");
        make_expected(word, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated dot-product metadata mismatch");
    }
#else
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded allocated dot-product word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF dot-product ownership mismatch");
#endif
}

static void expect_reserved(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved dot-product word decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved dot-product ownership mismatch");
}

static void test_complete_parent(void)
{
    unsigned size_code;
    unsigned is_unsigned;
    unsigned zm;
    unsigned zn;
    unsigned zda;

    for (size_code = 0u; size_code < 4u; ++size_code) {
        for (is_unsigned = 0u; is_unsigned < 2u; ++is_unsigned) {
            for (zm = 0u; zm < 32u; ++zm) {
                for (zn = 0u; zn < 32u; ++zn) {
                    for (zda = 0u; zda < 32u; ++zda) {
                        uint32_t word = PARENT_VALUE
                            | ((uint32_t)size_code << 22)
                            | ((uint32_t)zm << 16)
                            | ((uint32_t)is_unsigned << 10)
                            | ((uint32_t)zn << 5) | zda;

                        domain_expect((word & PARENT_MASK) == PARENT_VALUE,
                            word, "dot-product parent construction failed");
                        if (size_code == 0u) {
                            expect_reserved(word);
                            ++reserved_count;
                        } else {
                            expect_allocated(word);
                            if (is_unsigned != 0u) {
                                if (size_code == 1u) {
                                    ++udot_p3_count;
                                } else {
                                    ++udot_base_count;
                                }
                            } else if (size_code == 1u) {
                                ++sdot_p3_count;
                            } else {
                                ++sdot_base_count;
                            }
                        }
                    }
                }
            }
        }
    }
    EXPECT(sdot_base_count == UINT64_C(65536));
    EXPECT(sdot_p3_count == UINT64_C(32768));
    EXPECT(udot_base_count == UINT64_C(65536));
    EXPECT(udot_p3_count == UINT64_C(32768));
    EXPECT(reserved_count == UINT64_C(65536));
    EXPECT(sdot_base_count + sdot_p3_count
        + udot_base_count + udot_p3_count + reserved_count
        == UINT64_C(262144));
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

static void test_features_profiles_transport_and_precedence(void)
{
    uint32_t baseline = SDOT_BASE_VALUE | UINT32_C(0x005d03df);
    uint32_t p3 = UDOT_P3_VALUE | UINT32_C(0x001f03df);
    uint32_t reserved = PARENT_VALUE | UINT32_C(0x001f03df);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned boundary;

    EXPECT((baseline & SDOT_BASE_MASK) == SDOT_BASE_VALUE);
    EXPECT((p3 & UDOT_P3_MASK) == UDOT_P3_VALUE);
    expect_profile(baseline, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_profile(baseline, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_STATUS_OK);
    expect_profile(baseline, CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_STATUS_OK);
    expect_profile(baseline, CDISASM_ARM_CPU_APPLE_M4,
        CDISASM_STATUS_OK);
    expect_profile(baseline, CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    /* No named product profile currently advertises SVE2p3 or SME2p3.
     * Lower SVE/SME revisions must not accidentally admit the p3 leaf. */
    expect_profile(p3, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_profile(p3, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(p3, CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(p3, CDISASM_ARM_CPU_APPLE_M4,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(p3, CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(p3, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(p3, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
    bytes[0] = (uint8_t)(p3 >> 24);
    bytes[1] = (uint8_t)(p3 >> 16);
    bytes[2] = (uint8_t)(p3 >> 8);
    bytes[3] = (uint8_t)p3;
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

    word_to_le(p3, bytes);
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
        EXPECT(decode_word(p3, CDISASM_ARM_CPU_APPLE_M4,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, status));
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, status));
    }
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(p3, CDISASM_ARM_CPU_ANY, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&other, 0xa5, sizeof(other));
    (void)decode_word_mode(p3, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id < UINT16_C(2633)
        || other.form_id > UINT16_C(2636));
    memset(&other, 0xa5, sizeof(other));
    (void)decode_word_mode(p3, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id < UINT16_C(2633)
        || other.form_id > UINT16_C(2636));
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
    static const struct format_case {
        uint32_t word;
        const char *text;
    } cases[] = {
        { UINT32_C(0x44800000), "sdot z0.s, z0.b, z0.b" },
        { UINT32_C(0x44dd03df), "sdot z31.d, z30.h, z29.h" },
        { UINT32_C(0x44850483), "udot z3.s, z4.b, z5.b" },
        { UINT32_C(0x44c804e6), "udot z6.d, z7.h, z8.h" },
        { UINT32_C(0x445f03df), "sdot z31.h, z30.b, z31.b" },
        { UINT32_C(0x445f07df), "udot z31.h, z30.b, z31.b" }
    };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[112];
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        EXPECT(decode_word(cases[index].word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == strlen(cases[index].text));
        EXPECT(strcmp(text, cases[index].text) == 0);
    }
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text)) == strlen("UDOT z31.h, z30.b, z31.b"));
    EXPECT(strcmp(text, "UDOT z31.h, z30.b, z31.b") == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(cases[sizeof(cases) / sizeof(cases[0]) - 1u].text));

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged);                                            \
    } while (0)

    REJECT_MUTATION(forged.raw_instruction = UDOT_BASE_VALUE);
    REJECT_MUTATION(forged.form_id = UINT16_C(2635));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_SDOT);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags = 0u);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED);
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[0].extend_type = 4u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[1].extend_type = 2u);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[2].flags =
        CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    REJECT_MUTATION(forged.operand[3].type = CDISASM_OPERAND_REGISTER);

#undef REJECT_MUTATION
}
#endif

int main(void)
{
    test_complete_parent();
    test_features_profiles_transport_and_precedence();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter_contract();
#endif
    if (failures != 0) {
        fprintf(stderr, "ARM SVE dot-product tests failed: %d\n", failures);
        return 1;
    }
    printf("ARM SVE dot-product tests passed "
           "(%llu baseline SDOT, %llu p3 SDOT, "
           "%llu baseline UDOT, %llu p3 UDOT, %llu reserved)\n",
           (unsigned long long)sdot_base_count,
           (unsigned long long)sdot_p3_count,
           (unsigned long long)udot_base_count,
           (unsigned long long)udot_p3_count,
           (unsigned long long)reserved_count);
    return 0;
}
