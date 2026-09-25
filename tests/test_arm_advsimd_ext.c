#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define EXT_MASK UINT32_C(0xbfe08400)
#define EXT_VALUE UINT32_C(0x2e000000)
#define EXT_FORM UINT16_C(5910)

_Static_assert(CDISASM_ARM_NAME_EXT == UINT16_C(812),
               "EXT mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= EXT_FORM,
               "Advanced SIMD EXT form ID unavailable");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2432),
               "SVE EXT sibling form IDs unavailable");

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

static uint32_t make_word(unsigned q, unsigned imm4, unsigned rm,
                          unsigned rn, unsigned rd)
{
    return EXT_VALUE | ((uint32_t)q << 30)
        | ((uint32_t)rm << 16) | ((uint32_t)imm4 << 11)
        | ((uint32_t)rn << 5) | (uint32_t)rd;
}

static int allocated_control(unsigned q, unsigned imm4)
{
    return q != 0u || imm4 < 8u;
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
        UINT64_C(0x18a000), options, instruction);
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
                          cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded);
    expected.size = total_size;
    expected.access = access;
    expected.extend_type = (cdisasm_arm_extend_type)1u;
    expected.scale = total_size;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int immediate_matches(const cdisasm_arm_operand *operand,
                             unsigned value)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_IMMEDIATE;
    expected.imm = value;
    expected.size = 1u;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            uint32_t word, unsigned q, unsigned imm4,
                            unsigned rm, unsigned rn, unsigned rd)
{
    uint8_t total_size = q != 0u ? 16u : 8u;

    return instruction->address == UINT64_C(0x18a000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == CDISASM_ARM_NAME_EXT
        && instruction->form_id == EXT_FORM
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == 4u
        && vector_matches(&instruction->operand[0], rd, total_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        && vector_matches(&instruction->operand[1], rn, total_size,
            CDISASM_OPERAND_ACCESS_READ)
        && vector_matches(&instruction->operand[2], rm, total_size,
            CDISASM_OPERAND_ACCESS_READ)
        && immediate_matches(&instruction->operand[3], imm4);
}
#endif

static void test_exhaustive_envelope(void)
{
    uint32_t partitions[2][16][2] = {{{0u}}};
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;

    for (unsigned q = 0u; q < 2u; ++q) {
        for (unsigned imm4 = 0u; imm4 < 16u; ++imm4) {
            int is_allocated = allocated_control(q, imm4);

            for (unsigned rm = 0u; rm < 32u; ++rm) {
                for (unsigned rn = 0u; rn < 32u; ++rn) {
                    for (unsigned rd = 0u; rd < 32u; ++rd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = make_word(q, imm4, rm, rn, rd);
                        uint32_t decoded;

                        EXPECT((word & EXT_MASK) == EXT_VALUE);
                        ++partitions[q][imm4][is_allocated];
                        if (is_allocated) {
                            ++allocated;
                        } else {
                            ++reserved;
                        }
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                        if (is_allocated) {
#if USE_EXTRA_OPCODES
                            EXPECT(decoded == 4u);
                            EXPECT(metadata_matches(&instruction, word,
                                q, imm4, rm, rn, rd));
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

    EXPECT(allocated == UINT32_C(786432));
    EXPECT(reserved == UINT32_C(262144));
    for (unsigned q = 0u; q < 2u; ++q) {
        for (unsigned imm4 = 0u; imm4 < 16u; ++imm4) {
            int is_allocated = allocated_control(q, imm4);

            EXPECT(partitions[q][imm4][is_allocated]
                == UINT32_C(32768));
            EXPECT(partitions[q][imm4][!is_allocated] == 0u);
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

static void test_profiles_and_neighbors(void)
{
    static const uint32_t sve_siblings[] = {
        UINT32_C(0x05200c40), /* ext z0.b, z0.b, z2.b, #3. */
        UINT32_C(0x05600c00)  /* ext z0.b, {z0.b,z1.b}, #3. */
    };
    uint32_t word = make_word(1u, 15u, 29u, 30u, 31u);

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

        if ((EXT_MASK & (UINT32_C(1) << bit)) == 0u) {
            continue;
        }
        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(word ^ (UINT32_C(1) << bit),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
            || instruction.form_id != EXT_FORM);
    }

    for (size_t index = 0u;
         index < sizeof(sve_siblings) / sizeof(sve_siblings[0]); ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(sve_siblings[index], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
            || instruction.form_id != EXT_FORM);
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
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x18a000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x18a000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x18a000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x18a000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    for (unsigned boundary = 0u; boundary < 4u; ++boundary) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(error_only(&other, boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED));
    }
}

static void test_transport_and_status_precedence(void)
{
    cdisasm_arm_instruction instruction;
    uint32_t allocated = make_word(1u, 15u, 29u, 30u, 31u);
    uint32_t reserved = make_word(0u, 8u, 2u, 1u, 0u);
    uint8_t bytes[4];

    check_transport(make_word(0u, 0u, 2u, 1u, 0u));
    check_transport(allocated);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));

    word_to_be(reserved, bytes);
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x18a000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 3u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_TRUNCATED));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, UINT64_C(1) << 63,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(allocated, CDISASM_ARM_CPU_CORTEX_A7,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    (void)decode_word(allocated, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
    EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
        || instruction.form_id != EXT_FORM);

    memset(&instruction, 0xa5, sizeof(instruction));
    (void)decode_word(allocated, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
    EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
        || instruction.form_id != EXT_FORM);
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

static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[160];
    char short_text[8];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text))
        == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, NULL, 0u)
        == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, short_text,
        sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void test_formatter_and_schema(void)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[160];

    expect_format(make_word(0u, 0u, 2u, 1u, 0u),
        "ext v0.8b, v1.8b, v2.8b, #0");
    expect_format(make_word(0u, 7u, 29u, 30u, 31u),
        "ext v31.8b, v30.8b, v29.8b, #7");
    expect_format(make_word(1u, 0u, 2u, 1u, 0u),
        "ext v0.16b, v1.16b, v2.16b, #0");
    expect_format(make_word(1u, 15u, 29u, 30u, 31u),
        "ext v31.16b, v30.16b, v29.16b, #15");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(make_word(1u, 15u, 29u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("EXT v31.16b, v30.16b, v29.16b, #15"));
    EXPECT(strcmp(text,
        "EXT v31.16b, v30.16b, v29.16b, #15") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(5909));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_EXTQ);
    REJECT_MUTATION(forged.raw_instruction = make_word(
        0u, 15u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd503201f));
    REJECT_MUTATION(forged.opcode_size = 2u);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
    REJECT_MUTATION(forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(forged.operand_count = 3u);
    REJECT_MUTATION(forged.operand[0].type = CDISASM_OPERAND_IMMEDIATE);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_V30);
    REJECT_MUTATION(forged.operand[0].size = 8u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[0].flags =
        CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    REJECT_MUTATION(forged.operand[0].base_reg = CDISASM_ARM_REG_X0);
    REJECT_MUTATION(forged.operand[0].shift_type = CDISASM_ARM_SHIFT_LSL);
    REJECT_MUTATION(forged.operand[0].extend_type =
        (cdisasm_arm_extend_type)2u);
    REJECT_MUTATION(forged.operand[0].scale = 15u);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V29);
    REJECT_MUTATION(forged.operand[1].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[1].address = UINT64_C(1));
    REJECT_MUTATION(forged.operand[1].index_reg = CDISASM_ARM_REG_X1);
    REJECT_MUTATION(forged.operand[1].imm = UINT64_C(1));
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_V28);
    REJECT_MUTATION(forged.operand[2].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[2].register_list = UINT16_C(1));
    REJECT_MUTATION(forged.operand[2].shift_amount = UINT8_C(1));
    REJECT_MUTATION(forged.operand[3].type = CDISASM_OPERAND_REGISTER);
    REJECT_MUTATION(forged.operand[3].imm = UINT64_C(14));
    REJECT_MUTATION(forged.operand[3].reg = CDISASM_ARM_REG_X0);
    REJECT_MUTATION(forged.operand[3].base_reg = CDISASM_ARM_REG_X0);
    REJECT_MUTATION(forged.operand[3].index_reg = CDISASM_ARM_REG_X1);
    REJECT_MUTATION(forged.operand[3].register_list = UINT16_C(1));
    REJECT_MUTATION(forged.operand[3].address = UINT64_C(1));
    REJECT_MUTATION(forged.operand[3].size = 2u);
    REJECT_MUTATION(forged.operand[3].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[3].flags =
        CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    REJECT_MUTATION(forged.operand[3].shift_type = CDISASM_ARM_SHIFT_LSL);
    REJECT_MUTATION(forged.operand[3].shift_amount = UINT8_C(1));
    REJECT_MUTATION(forged.operand[3].extend_type =
        (cdisasm_arm_extend_type)1u);
    REJECT_MUTATION(forged.operand[3].scale = UINT8_C(1));

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_NOP;
    forged.form_id = EXT_FORM;
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "form-only claim");
    forged.form_id = CDISASM_ARM_FORM_NONE;
    forged.raw_instruction = make_word(1u, 0u, 2u, 1u, 0u);
    reject_forgery(&forged, "raw-only claim");

    memset(&forged, 0, sizeof(forged));
    forged.name_id = CDISASM_ARM_NAME_EXT;
    forged.raw_instruction = UINT32_C(0xd503201f);
    forged.opcode_size = 4u;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.condition = CDISASM_ARM_CONDITION_AL;
    reject_forgery(&forged, "name-only claim");

    /* A scalable-vector EXT name/form is not owned by this fixed-width
     * validator.  This synthetic public-ABI object represents the destructive
     * SVE spelling and exercises that formatter boundary directly. */
    memset(&forged, 0, sizeof(forged));
    /* LLVM 21: ext z0.b, z0.b, z2.b, #3 -> 40 0c 20 05. */
    forged.raw_instruction = UINT32_C(0x05200c40);
    forged.opcode_size = 4u;
    forged.name_id = CDISASM_ARM_NAME_EXT;
    forged.form_id = UINT16_C(2431);
    forged.condition = CDISASM_ARM_CONDITION_AL;
    forged.isa_id = CDISASM_ARM_ISA_A64;
    forged.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;
    forged.operand_count = 4u;
    forged.operand[0].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    forged.operand[0].reg = CDISASM_ARM_REG_Z0;
    forged.operand[0].extend_type = (cdisasm_arm_extend_type)1u;
    forged.operand[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    forged.operand[1] = forged.operand[0];
    forged.operand[2].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    forged.operand[2].reg = CDISASM_ARM_REG_Z2;
    forged.operand[2].extend_type = (cdisasm_arm_extend_type)1u;
    forged.operand[2].access = CDISASM_OPERAND_ACCESS_READ;
    forged.operand[3].type = CDISASM_OPERAND_IMMEDIATE;
    forged.operand[3].imm = UINT64_C(3);
    forged.operand[3].size = 1u;
    forged.operand[3].access = CDISASM_OPERAND_ACCESS_READ;
    EXPECT(cdisasm_arm_format(&forged,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text))
        == strlen("ext z0.b, z0.b, z2.b, #0x3"));
    EXPECT(strcmp(text, "ext z0.b, z0.b, z2.b, #0x3") == 0);

#undef REJECT_MUTATION
}
#else
static void test_formatter_and_schema(void)
{
}
#endif

int main(void)
{
    test_exhaustive_envelope();
    test_profiles_and_neighbors();
    test_transport_and_status_precedence();
    test_formatter_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d Advanced SIMD EXT test(s) failed\n", failures);
        return 1;
    }
    printf("ARM Advanced SIMD EXT tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=786432, reserved=262144)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
