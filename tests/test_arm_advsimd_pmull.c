#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"
#include "../src/arm/arm_decoder.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define PMULL_MASK UINT32_C(0xbf20fc00)
#define PMULL_VALUE UINT32_C(0x0e20e000)
#define PMULL_FORM UINT16_C(6103)

_Static_assert(CDISASM_ARM_NAME_PMULL == UINT16_C(1167),
               "PMULL mnemonic ID changed");
_Static_assert(CDISASM_ARM_FEATURE_PMULL == UINT16_C(169),
               "PMULL feature ID changed or collided");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= PMULL_FORM,
               "PMULL form ID unavailable");

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

static uint32_t make_word(unsigned q, unsigned size_code,
                          unsigned rm, unsigned rn, unsigned rd)
{
    return PMULL_VALUE | ((uint32_t)q << 30)
        | ((uint32_t)size_code << 22) | ((uint32_t)rm << 16)
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
        UINT64_C(0x163000), options, instruction);
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
static int vector_matches(const cdisasm_arm_operand *operand,
                          unsigned encoded, uint8_t total_size,
                          uint8_t element_size,
                          cdisasm_operand_access access)
{
    return operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + encoded)
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->imm == 0u
        && operand->size == total_size
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == (cdisasm_arm_extend_type)element_size
        && operand->scale == (uint8_t)(total_size / element_size)
        && CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == element_size
        && CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size)
        && operand->access == access;
}

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            uint32_t word, unsigned q,
                            unsigned size_code,
                            unsigned rm, unsigned rn, unsigned rd)
{
    uint8_t source_element_size = size_code == 0u ? 1u : 8u;
    uint8_t result_element_size =
        (uint8_t)(source_element_size * 2u);
    uint8_t source_total_size = q != 0u ? 16u : 8u;

    return instruction->address == UINT64_C(0x163000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == CDISASM_ARM_NAME_PMULL
        && instruction->form_id == PMULL_FORM
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == 3u
        && vector_matches(&instruction->operand[0], rd, 16u,
            result_element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && vector_matches(&instruction->operand[1], rn,
            source_total_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && vector_matches(&instruction->operand[2], rm,
            source_total_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_envelope(void)
{
    uint32_t partitions[2][2] = {{0u, 0u}, {0u, 0u}};
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned q;

    for (q = 0u; q < 2u; ++q) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            unsigned rm;

            for (rm = 0u; rm < 32u; ++rm) {
                unsigned rn;

                for (rn = 0u; rn < 32u; ++rn) {
                    unsigned rd;

                    for (rd = 0u; rd < 32u; ++rd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = make_word(
                            q, size_code, rm, rn, rd);
                        uint32_t decoded;
                        int valid = size_code == 0u || size_code == 3u;

                        ++partitions[q][valid ? 0u : 1u];
                        if (valid) {
                            ++allocated;
                        } else {
                            ++reserved;
                        }
                        EXPECT((word & PMULL_MASK) == PMULL_VALUE);
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                        if (!valid) {
                            EXPECT(decoded == 0u);
                            EXPECT(error_only(&instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                        } else {
#if USE_EXTRA_OPCODES
                            EXPECT(decoded == 4u);
                            EXPECT(metadata_matches(&instruction, word,
                                q, size_code, rm, rn, rd));
#else
                            EXPECT(decoded == 0u);
                            EXPECT(error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        }
                    }
                }
            }
        }
    }
    for (q = 0u; q < 2u; ++q) {
        EXPECT(partitions[q][0] == UINT32_C(65536));
        EXPECT(partitions[q][1] == UINT32_C(65536));
    }
    EXPECT(allocated == UINT32_C(131072));
    EXPECT(reserved == UINT32_C(131072));
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

static void test_profiles_and_neighbors(void)
{
    static const uint32_t adjacent[] = {
        UINT32_C(0x0e20dc00), UINT32_C(0x0e20e400),
        UINT32_C(0x0e20e800), UINT32_C(0x0e20ec00),
        UINT32_C(0x0e20f000), UINT32_C(0x2e20e000)
    };
    uint32_t byte_word = make_word(1u, 0u, 29u, 13u, 7u);
    uint32_t dword_word = make_word(0u, 3u, 29u, 13u, 7u);
    size_t adjacent_index;
    unsigned bit;

    expect_cpu_status(byte_word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_cpu_status(byte_word, CDISASM_ARM_CPU_CORTEX_A34,
                      CDISASM_STATUS_OK);
    expect_cpu_status(byte_word, CDISASM_ARM_CPU_CORTEX_A53,
                      CDISASM_STATUS_OK);
    expect_cpu_status(byte_word, CDISASM_ARM_CPU_APPLE_M3,
                      CDISASM_STATUS_OK);
    expect_cpu_status(byte_word, CDISASM_ARM_CPU_FUJITSU_A64FX,
                      CDISASM_STATUS_OK);

    /* Named profiles currently advertise AdvSIMD but no explicit
     * FEAT_PMULL atom; unrestricted analysis owns that feature. */
    expect_cpu_status(dword_word, CDISASM_ARM_CPU_ANY,
                      CDISASM_STATUS_OK);
    expect_cpu_status(dword_word, CDISASM_ARM_CPU_CORTEX_A34,
                      CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(dword_word, CDISASM_ARM_CPU_CORTEX_A53,
                      CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(dword_word, CDISASM_ARM_CPU_APPLE_M3,
                      CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(dword_word, CDISASM_ARM_CPU_FUJITSU_A64FX,
                      CDISASM_STATUS_INVALID_INSTRUCTION);

    for (bit = 0u; bit < 32u; ++bit) {
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        if ((PMULL_MASK & (UINT32_C(1) << bit)) == 0u) {
            continue;
        }
        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(byte_word ^ (UINT32_C(1) << bit),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(decoded != 4u || instruction.form_id != PMULL_FORM);
    }

    for (adjacent_index = 0u;
         adjacent_index < sizeof(adjacent) / sizeof(adjacent[0]);
         ++adjacent_index) {
        cdisasm_arm_instruction instruction;
        uint32_t word = adjacent[adjacent_index]
            | UINT32_C(0x40000000) | (UINT32_C(29) << 16)
            | (UINT32_C(13) << 5) | UINT32_C(7);

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        EXPECT(instruction.form_id != PMULL_FORM);
    }
}

static void test_transport_and_boundaries(void)
{
    uint32_t words[2] = {
        make_word(1u, 0u, 29u, 13u, 7u),
        make_word(0u, 3u, 29u, 13u, 7u)
    };
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned word_index;
    unsigned boundary;

    for (word_index = 0u; word_index < 2u; ++word_index) {
        memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(words[word_index], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &little) == 4u);
#else
        EXPECT(decode_word(words[word_index], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &little) == 0u);
#endif

        word_to_be(words[word_index], bytes);
        memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x163000),
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x163000),
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
        EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

        word_to_le(words[word_index], bytes);
        memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
        EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x163000),
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
        EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x163000),
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
        EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

        for (boundary = 1u; boundary < 4u; ++boundary) {
            memset(&other, 0xa5, sizeof(other));
            EXPECT(decode_word(words[word_index], CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, boundary,
                CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
            EXPECT(error_only(&other, CDISASM_STATUS_TRUNCATED));
        }
    }

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(make_word(0u, 1u, 2u, 1u, 0u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(error_only(&other, CDISASM_STATUS_INVALID_INSTRUCTION));
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(make_word(1u, 2u, 2u, 1u, 0u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(error_only(&other, CDISASM_STATUS_INVALID_INSTRUCTION));

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(words[0], CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, UINT64_C(1) << 63, &other) == 0u);
    EXPECT(error_only(&other, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(words[0], CDISASM_ARM_CPU_CORTEX_A7,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &other) == 0u);
    EXPECT(error_only(&other, CDISASM_STATUS_INVALID_ARGUMENT));
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
        if (failures < 24) {
            fprintf(stderr, "accepted formatter forgery: %s -> %s\n",
                    mutation, text);
        }
        ++failures;
    }
}

static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[160];
    char short_text[8];
    size_t expected_length = strlen(expected);
    size_t length;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    length = cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text));
    if (length != expected_length || strcmp(text, expected) != 0) {
        fprintf(stderr, "format mismatch %08x: expected '%s', got '%s'\n",
                (unsigned)word, expected, text);
    }
    EXPECT(length == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, NULL, 0u) == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, short_text,
        sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void test_formatter_and_collisions(void)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[160];

    expect_format(make_word(0u, 0u, 29u, 13u, 7u),
                  "pmull v7.8h, v13.8b, v29.8b");
    expect_format(make_word(1u, 0u, 29u, 13u, 7u),
                  "pmull2 v7.8h, v13.16b, v29.16b");
    expect_format(make_word(0u, 3u, 29u, 13u, 7u),
                  "pmull v7.1q, v13.1d, v29.1d");
    expect_format(make_word(1u, 3u, 29u, 13u, 7u),
                  "pmull2 v7.1q, v13.2d, v29.2d");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(1u, 3u, 29u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("PMULL2 v31.1q, v30.2d, v29.2d"));
    EXPECT(strcmp(text, "PMULL2 v31.1q, v30.2d, v29.2d") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(6102));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_PMULLB);
    REJECT_MUTATION(forged.raw_instruction = make_word(
        0u, 3u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = make_word(
        1u, 1u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd503201f));
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
    REJECT_MUTATION(forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_V30);
    REJECT_MUTATION(forged.operand[0].size = 8u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V29);
    REJECT_MUTATION(forged.operand[1].size = 8u);
    REJECT_MUTATION(forged.operand[2].address = UINT64_C(1));

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_NOP;
    forged.form_id = PMULL_FORM;
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "fixed-form-only claim");
    forged.form_id = CDISASM_ARM_FORM_NONE;
    forged.raw_instruction = make_word(0u, 0u, 2u, 1u, 0u);
    reject_forgery(&forged, "raw-only claim");

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_PMULL;
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "same-name-only claim");

    /* The distinct scalable multi-vector PMULL leaf remains generated and
     * must not be claimed by the fixed-vector schema. */
    memset(&instruction, 0, sizeof(instruction));
    instruction.name_id = CDISASM_ARM_NAME_PMULL;
    instruction.form_id = UINT16_C(2918);
    instruction.raw_instruction = UINT32_C(0x4520f800);
    instruction.opcode_size = 4u;
    instruction.isa_id = CDISASM_ARM_ISA_A64;
    instruction.condition = CDISASM_ARM_CONDITION_AL;
    instruction.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text)) != 0u);
    forged = instruction;
    forged.form_id = PMULL_FORM;
    reject_forgery(&forged, "scalable raw with fixed-vector form");

#undef REJECT_MUTATION
}
#else
static void test_formatter_and_collisions(void)
{
}
#endif

int main(void)
{
    test_exhaustive_envelope();
    test_profiles_and_neighbors();
    test_transport_and_boundaries();
    test_formatter_and_collisions();

    if (failures != 0) {
        fprintf(stderr, "%d PMULL/PMULL2 test(s) failed\n", failures);
        return 1;
    }
    printf("ARM Advanced SIMD PMULL/PMULL2 tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=131072, reserved=131072)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
