#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

typedef struct sha_descriptor {
    uint32_t a32_value;
    uint32_t t32_value;
    uint32_t a64_value;
    cdisasm_arm_form_id a32_form;
    cdisasm_arm_form_id t32_form;
    cdisasm_arm_form_id a64_form;
    cdisasm_arm_name_id name;
    const char *mnemonic;
} sha_descriptor;

static const sha_descriptor sha3[] = {
    { UINT32_C(0xf2000c00), UINT32_C(0xef000c00), UINT32_C(0x5e000000),
      UINT16_C(676), UINT16_C(1203), UINT16_C(5731),
      CDISASM_ARM_NAME_SHA1C, "sha1c" },
    { UINT32_C(0xf2100c00), UINT32_C(0xef100c00), UINT32_C(0x5e001000),
      UINT16_C(687), UINT16_C(1214), UINT16_C(5732),
      CDISASM_ARM_NAME_SHA1P, "sha1p" },
    { UINT32_C(0xf2200c00), UINT32_C(0xef200c00), UINT32_C(0x5e002000),
      UINT16_C(716), UINT16_C(1243), UINT16_C(5733),
      CDISASM_ARM_NAME_SHA1M, "sha1m" },
    { UINT32_C(0xf2300c00), UINT32_C(0xef300c00), UINT32_C(0x5e003000),
      UINT16_C(728), UINT16_C(1255), UINT16_C(5734),
      CDISASM_ARM_NAME_SHA1SU0, "sha1su0" },
    { UINT32_C(0xf3000c00), UINT32_C(0xff000c00), UINT32_C(0x5e004000),
      UINT16_C(743), UINT16_C(1270), UINT16_C(5735),
      CDISASM_ARM_NAME_SHA256H, "sha256h" },
    { UINT32_C(0xf3100c00), UINT32_C(0xff100c00), UINT32_C(0x5e005000),
      UINT16_C(748), UINT16_C(1275), UINT16_C(5736),
      CDISASM_ARM_NAME_SHA256H2, "sha256h2" },
    { UINT32_C(0xf3200c00), UINT32_C(0xff200c00), UINT32_C(0x5e006000),
      UINT16_C(768), UINT16_C(1295), UINT16_C(5737),
      CDISASM_ARM_NAME_SHA256SU1, "sha256su1" }
};

static const sha_descriptor sha2[] = {
    { UINT32_C(0xf3b102c0), UINT32_C(0xffb102c0), UINT32_C(0x5e280800),
      UINT16_C(819), UINT16_C(1346), UINT16_C(5738),
      CDISASM_ARM_NAME_SHA1H, "sha1h" },
    { UINT32_C(0xf3b20380), UINT32_C(0xffb20380), UINT32_C(0x5e281800),
      UINT16_C(831), UINT16_C(1358), UINT16_C(5739),
      CDISASM_ARM_NAME_SHA1SU1, "sha1su1" },
    { UINT32_C(0xf3b203c0), UINT32_C(0xffb203c0), UINT32_C(0x5e282800),
      UINT16_C(832), UINT16_C(1359), UINT16_C(5740),
      CDISASM_ARM_NAME_SHA256SU0, "sha256su0" }
};

_Static_assert(CDISASM_ARM_NAME_SHA1C == UINT16_C(1364),
               "SHA1C mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SHA256SU1 == UINT16_C(1373),
               "SHA256SU1 mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(5740),
               "fixed Advanced SIMD SHA form IDs unavailable");

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 32) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",      \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static uint32_t set_dreg(uint32_t word, unsigned encoded)
{
    return word | ((uint32_t)(encoded & 16u) << 18)
        | ((uint32_t)(encoded & 15u) << 12);
}

static uint32_t set_nreg(uint32_t word, unsigned encoded)
{
    return word | ((uint32_t)(encoded & 16u) << 3)
        | ((uint32_t)(encoded & 15u) << 16);
}

static uint32_t set_mreg(uint32_t word, unsigned encoded)
{
    return word | ((uint32_t)(encoded & 16u) << 1)
        | (uint32_t)(encoded & 15u);
}

static uint32_t make_a32_sha3(uint32_t value, unsigned q,
                              unsigned vd, unsigned vn, unsigned vm)
{
    return set_mreg(set_nreg(set_dreg(value, vd), vn), vm)
        | ((uint32_t)q << 6);
}

static uint32_t make_a32_sha2(uint32_t value, unsigned size,
                              unsigned vd, unsigned vm)
{
    return set_mreg(set_dreg(value, vd), vm)
        | ((uint32_t)size << 18);
}

static uint32_t make_a64_sha3(uint32_t value, unsigned rd,
                              unsigned rn, unsigned rm)
{
    return value | ((uint32_t)rm << 16)
        | ((uint32_t)rn << 5) | (uint32_t)rd;
}

static uint32_t make_a64_sha2(uint32_t value, unsigned rd, unsigned rn)
{
    return value | ((uint32_t)rn << 5) | (uint32_t)rd;
}

static void canonical_to_bytes(uint32_t word, cdisasm_arm_mode mode,
                               int big_endian, uint8_t bytes[4])
{
    if (mode == CDISASM_ARM_MODE_T32) {
        if (big_endian) {
            bytes[0] = (uint8_t)(word >> 24);
            bytes[1] = (uint8_t)(word >> 16);
            bytes[2] = (uint8_t)(word >> 8);
            bytes[3] = (uint8_t)word;
        } else {
            bytes[0] = (uint8_t)(word >> 16);
            bytes[1] = (uint8_t)(word >> 24);
            bytes[2] = (uint8_t)word;
            bytes[3] = (uint8_t)(word >> 8);
        }
        return;
    }
    if (big_endian) {
        bytes[0] = (uint8_t)(word >> 24);
        bytes[1] = (uint8_t)(word >> 16);
        bytes[2] = (uint8_t)(word >> 8);
        bytes[3] = (uint8_t)word;
    } else {
        bytes[0] = (uint8_t)word;
        bytes[1] = (uint8_t)(word >> 8);
        bytes[2] = (uint8_t)(word >> 16);
        bytes[3] = (uint8_t)(word >> 24);
    }
}

#if USE_EXTRA_OPCODES
static uint32_t expected_raw(uint32_t word, cdisasm_arm_mode mode)
{
    return mode == CDISASM_ARM_MODE_T32
        ? (word << 16) | (word >> 16) : word;
}
#endif

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
                            cdisasm_arm_mode mode, size_t code_size,
                            cdisasm_arm_decode_option options,
                            cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    canonical_to_bytes(word, mode, 0, bytes);
    return cdisasm_arm_decode(cpu, mode, bytes, code_size,
        UINT64_C(0x1d4000), options, instruction);
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
static int exact_operand(const cdisasm_arm_operand *operand,
                         cdisasm_arm_reg_id reg, uint8_t size,
                         uint8_t element_size, uint8_t element_count,
                         cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = reg;
    expected.size = size;
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.scale = element_count;
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_a32(const cdisasm_arm_instruction *instruction,
                        uint32_t word, cdisasm_arm_mode mode,
                        const sha_descriptor *descriptor, int three,
                        unsigned vd, unsigned vn, unsigned vm)
{
    cdisasm_arm_form_id form = mode == CDISASM_ARM_MODE_A32
        ? descriptor->a32_form : descriptor->t32_form;
    cdisasm_operand_access destination_access =
        descriptor->name == CDISASM_ARM_NAME_SHA1H
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ_WRITE;

    return instruction->address == UINT64_C(0x1d4000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == expected_raw(word, mode)
        && instruction->name_id == descriptor->name
        && instruction->form_id == form
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == (mode == CDISASM_ARM_MODE_A32
            ? CDISASM_ARM_ISA_A32 : CDISASM_ARM_ISA_T32)
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == (three ? 3u : 2u)
        && exact_operand(&instruction->operand[0],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Q0 + vd / 2u),
            16u, 4u, 4u, destination_access)
        && exact_operand(&instruction->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Q0
                + (three ? vn : vm) / 2u),
            16u, 4u, 4u, CDISASM_OPERAND_ACCESS_READ)
        && (!three || exact_operand(&instruction->operand[2],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Q0 + vm / 2u),
            16u, 4u, 4u, CDISASM_OPERAND_ACCESS_READ));
}

static int metadata_a64(const cdisasm_arm_instruction *instruction,
                        uint32_t word, const sha_descriptor *descriptor,
                        int three, unsigned rd, unsigned rn, unsigned rm,
                        unsigned operation)
{
    cdisasm_operand_access destination_access =
        descriptor->name == CDISASM_ARM_NAME_SHA1H
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ_WRITE;
    uint8_t destination_element = 4u;
    uint8_t source_element = 4u;
    cdisasm_arm_reg_id destination_reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_V0 + rd);
    cdisasm_arm_reg_id source_reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_V0 + rn);

    if (three && (operation <= 2u || operation == 4u
        || operation == 5u)) {
        destination_element = 16u;
    }
    if (three && operation <= 2u) {
        source_reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + rn);
        source_element = 0u;
    } else if (three && (operation == 4u || operation == 5u)) {
        source_element = 16u;
    } else if (!three && operation == 0u) {
        destination_reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + rd);
        source_reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + rn);
        destination_element = 0u;
        source_element = 0u;
    }
    return instruction->address == UINT64_C(0x1d4000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == descriptor->name
        && instruction->form_id == descriptor->a64_form
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == (three ? 3u : 2u)
        && exact_operand(&instruction->operand[0], destination_reg,
            destination_element == 0u ? 4u : 16u,
            destination_element,
            destination_element == 0u ? 0u
                : (uint8_t)(16u / destination_element),
            destination_access)
        && exact_operand(&instruction->operand[1], source_reg,
            source_element == 0u ? 4u : 16u, source_element,
            source_element == 0u ? 0u
                : (uint8_t)(16u / source_element),
            CDISASM_OPERAND_ACCESS_READ)
        && (!three || exact_operand(&instruction->operand[2],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rm),
            16u, 4u, 4u, CDISASM_OPERAND_ACCESS_READ));
}
#endif

static void check_expected(uint32_t word, cdisasm_arm_mode mode,
                           int allocated,
                           const sha_descriptor *descriptor, int three,
                           unsigned rd, unsigned rn, unsigned rm,
                           unsigned operation)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded;

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(word, CDISASM_ARM_CPU_ANY, mode, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    if (!allocated) {
        EXPECT(decoded == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        return;
    }
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    if (mode == CDISASM_ARM_MODE_A64) {
        EXPECT(metadata_a64(&instruction, word, descriptor, three,
            rd, rn, rm, operation));
    } else {
        EXPECT(metadata_a32(&instruction, word, mode, descriptor, three,
            rd, rn, rm));
    }
#else
    (void)descriptor;
    (void)three;
    (void)rd;
    (void)rn;
    (void)rm;
    (void)operation;
    EXPECT(decoded == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_exhaustive_a64(void)
{
    uint32_t allocated = 0u;

    for (size_t operation = 0u;
         operation < sizeof(sha3) / sizeof(sha3[0]); ++operation) {
        for (unsigned rm = 0u; rm < 32u; ++rm) {
            for (unsigned rn = 0u; rn < 32u; ++rn) {
                for (unsigned rd = 0u; rd < 32u; ++rd) {
                    uint32_t word = make_a64_sha3(
                        sha3[operation].a64_value, rd, rn, rm);

                    EXPECT((word & UINT32_C(0xffe0fc00))
                        == sha3[operation].a64_value);
                    check_expected(word, CDISASM_ARM_MODE_A64, 1,
                        &sha3[operation], 1, rd, rn, rm,
                        (unsigned)operation);
                    ++allocated;
                }
            }
        }
    }
    for (size_t operation = 0u;
         operation < sizeof(sha2) / sizeof(sha2[0]); ++operation) {
        for (unsigned rn = 0u; rn < 32u; ++rn) {
            for (unsigned rd = 0u; rd < 32u; ++rd) {
                uint32_t word = make_a64_sha2(
                    sha2[operation].a64_value, rd, rn);

                EXPECT((word & UINT32_C(0xfffffc00))
                    == sha2[operation].a64_value);
                check_expected(word, CDISASM_ARM_MODE_A64, 1,
                    &sha2[operation], 0, rd, rn, 0u,
                    (unsigned)operation);
                ++allocated;
            }
        }
    }
    EXPECT(allocated == UINT32_C(232448));
}

static void test_exhaustive_a32_t32(void)
{
    static const cdisasm_arm_mode modes[] = {
        CDISASM_ARM_MODE_A32, CDISASM_ARM_MODE_T32
    };
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;

    for (size_t mode_index = 0u;
         mode_index < sizeof(modes) / sizeof(modes[0]); ++mode_index) {
        cdisasm_arm_mode mode = modes[mode_index];

        for (size_t operation = 0u;
             operation < sizeof(sha3) / sizeof(sha3[0]); ++operation) {
            uint32_t value = mode == CDISASM_ARM_MODE_A32
                ? sha3[operation].a32_value : sha3[operation].t32_value;

            for (unsigned q = 0u; q < 2u; ++q) {
                for (unsigned vm = 0u; vm < 32u; ++vm) {
                    for (unsigned vn = 0u; vn < 32u; ++vn) {
                        for (unsigned vd = 0u; vd < 32u; ++vd) {
                            int valid = q != 0u
                                && ((vd | vn | vm) & 1u) == 0u;
                            uint32_t word = make_a32_sha3(
                                value, q, vd, vn, vm);

                            check_expected(word, mode, valid,
                                &sha3[operation], 1, vd, vn, vm,
                                (unsigned)operation);
                            if (valid) {
                                ++allocated;
                            } else {
                                ++reserved;
                            }
                        }
                    }
                }
            }
        }
        for (size_t operation = 0u;
             operation < sizeof(sha2) / sizeof(sha2[0]); ++operation) {
            uint32_t value = mode == CDISASM_ARM_MODE_A32
                ? sha2[operation].a32_value : sha2[operation].t32_value;

            for (unsigned size = 0u; size < 4u; ++size) {
                for (unsigned vm = 0u; vm < 32u; ++vm) {
                    for (unsigned vd = 0u; vd < 32u; ++vd) {
                        int valid = size == 2u
                            && ((vd | vm) & 1u) == 0u;
                        uint32_t word = make_a32_sha2(
                            value, size, vd, vm);

                        check_expected(word, mode, valid,
                            &sha2[operation], 0, vd, 0u, vm,
                            (unsigned)operation);
                        if (valid) {
                            ++allocated;
                        } else {
                            ++reserved;
                        }
                    }
                }
            }
        }
    }
    EXPECT(allocated == UINT32_C(58880));
    EXPECT(reserved == UINT32_C(883200));
}

static void expect_cpu_status(uint32_t word, cdisasm_arm_mode mode,
                              cdisasm_arm_cpu_id cpu,
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
    decoded = decode_word(word, cpu, mode, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected != CDISASM_STATUS_OK) {
        EXPECT(error_only(&instruction, expected));
    }
}

static void test_profiles_transport_and_precedence(void)
{
    static const cdisasm_arm_mode modes[] = {
        CDISASM_ARM_MODE_A32, CDISASM_ARM_MODE_T32,
        CDISASM_ARM_MODE_A64
    };

    for (size_t index = 0u;
         index < sizeof(modes) / sizeof(modes[0]); ++index) {
        cdisasm_arm_mode mode = modes[index];
        uint32_t word = mode == CDISASM_ARM_MODE_A64
            ? make_a64_sha3(sha3[6].a64_value, 31u, 30u, 29u)
            : make_a32_sha3(mode == CDISASM_ARM_MODE_A32
                    ? sha3[6].a32_value : sha3[6].t32_value,
                1u, 30u, 28u, 26u);
        cdisasm_arm_instruction little;
        cdisasm_arm_instruction big;
        uint8_t bytes[4];
#if USE_EXTRA_OPCODES
        const uint32_t expected_decoded = 4u;
#else
        const uint32_t expected_decoded = 0u;
#endif

        expect_cpu_status(word, mode, CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, mode, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        memset(&little, 0xa5, sizeof(little));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, mode, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &little) == expected_decoded);
        canonical_to_bytes(word, mode, 1, bytes);
        memset(&big, 0xa5, sizeof(big));
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, mode,
            bytes, sizeof(bytes), UINT64_C(0x1d4000),
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big)
            == expected_decoded);
        EXPECT(memcmp(&little, &big, sizeof(little)) == 0);

        for (unsigned boundary = 0u; boundary < 4u; ++boundary) {
            cdisasm_arm_instruction instruction;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, mode,
                boundary, CDISASM_ARM_DECODE_OPTION_NONE,
                &instruction) == 0u);
            EXPECT(error_only(&instruction, boundary == 0u
                ? CDISASM_STATUS_END_OF_INPUT
                : CDISASM_STATUS_TRUNCATED));
        }
        {
            cdisasm_arm_instruction instruction;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, mode, 4u,
                UINT64_C(1) << 63, &instruction) == 0u);
            EXPECT(error_only(&instruction,
                CDISASM_STATUS_INVALID_ARGUMENT));
        }
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, cdisasm_arm_mode mode,
                          const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[128];
    char short_text[7];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, mode, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == expected_length);
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

static void reject_forgery(const cdisasm_arm_instruction *instruction)
{
    char text[128];

    memset(text, 0xa5, sizeof(text));
    EXPECT(cdisasm_arm_format(instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == 0u);
    EXPECT(text[0] == '\0');
}

static void test_formatter(void)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[128];
    uint32_t a64 = make_a64_sha3(
        sha3[0].a64_value, 31u, 30u, 29u);

    expect_format(make_a64_sha3(sha3[0].a64_value, 0u, 1u, 2u),
        CDISASM_ARM_MODE_A64, "sha1c q0, s1, v2.4s");
    expect_format(make_a64_sha3(sha3[4].a64_value, 31u, 30u, 29u),
        CDISASM_ARM_MODE_A64, "sha256h q31, q30, v29.4s");
    expect_format(make_a64_sha3(sha3[6].a64_value, 3u, 4u, 5u),
        CDISASM_ARM_MODE_A64, "sha256su1 v3.4s, v4.4s, v5.4s");
    expect_format(make_a64_sha2(sha2[0].a64_value, 31u, 30u),
        CDISASM_ARM_MODE_A64, "sha1h s31, s30");
    expect_format(make_a64_sha2(sha2[2].a64_value, 3u, 4u),
        CDISASM_ARM_MODE_A64, "sha256su0 v3.4s, v4.4s");
    expect_format(make_a32_sha3(sha3[0].a32_value,
            1u, 0u, 2u, 4u),
        CDISASM_ARM_MODE_A32, "sha1c.32 q0, q1, q2");
    expect_format(make_a32_sha2(sha2[1].a32_value, 2u, 30u, 28u),
        CDISASM_ARM_MODE_A32, "sha1su1.32 q15, q14");
    expect_format(make_a32_sha3(sha3[5].t32_value,
            1u, 30u, 28u, 26u),
        CDISASM_ARM_MODE_T32, "sha256h2.32 q15, q14, q13");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(a64, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("SHA1C q31, s30, v29.4s"));
    EXPECT(strcmp(text, "SHA1C q31, s30, v29.4s") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged);                                            \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(5732));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_SHA1P);
    REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x1000));
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.opcode_size = 2u);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK);
    REJECT_MUTATION(forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_V30);
    REJECT_MUTATION(forged.operand[0].size = 8u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[0].extend_type =
        (cdisasm_arm_extend_type)4u);
    REJECT_MUTATION(forged.operand[0].scale = 4u);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_S29);
    REJECT_MUTATION(forged.operand[1].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_V28);
    REJECT_MUTATION(forged.operand[2].flags =
        CDISASM_ARM_OPERAND_FLAG_HAS_LANE);

    forged = instruction;
    memset(&forged.operand[3], 0xa5, sizeof(forged.operand[3]));
    reject_forgery(&forged);
#undef REJECT_MUTATION
}
#endif

int main(void)
{
    test_exhaustive_a64();
    test_exhaustive_a32_t32();
    test_profiles_transport_and_precedence();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif
    if (failures != 0) {
        fprintf(stderr, "%d Advanced SIMD SHA test(s) failed\n", failures);
        return 1;
    }
    puts("Advanced SIMD SHA exact-family tests passed");
    return 0;
}
