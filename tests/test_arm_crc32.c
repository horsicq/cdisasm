#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x1e4000)

typedef struct aa32_crc_descriptor {
    uint32_t a32_value;
    uint32_t t32_value;
    cdisasm_arm_form_id a32_form;
    cdisasm_arm_form_id t32_form;
    cdisasm_arm_name_id name;
    const char *mnemonic;
    uint8_t source_size;
} aa32_crc_descriptor;

#if USE_EXTRA_OPCODES
typedef struct a64_crc_descriptor {
    cdisasm_arm_form_id form;
    cdisasm_arm_name_id name;
    const char *mnemonic;
    uint8_t source_size;
} a64_crc_descriptor;
#endif

static const aa32_crc_descriptor aa32_crc[6] = {
    { UINT32_C(0x01000040), UINT32_C(0xfac0f080),
      UINT16_C(98), UINT16_C(2169),
      CDISASM_ARM_NAME_CRC32B, "crc32b", 1u },
    { UINT32_C(0x01200040), UINT32_C(0xfac0f090),
      UINT16_C(99), UINT16_C(2170),
      CDISASM_ARM_NAME_CRC32H, "crc32h", 2u },
    { UINT32_C(0x01400040), UINT32_C(0xfac0f0a0),
      UINT16_C(100), UINT16_C(2171),
      CDISASM_ARM_NAME_CRC32W, "crc32w", 4u },
    { UINT32_C(0x01000240), UINT32_C(0xfad0f080),
      UINT16_C(101), UINT16_C(2172),
      CDISASM_ARM_NAME_CRC32CB, "crc32cb", 1u },
    { UINT32_C(0x01200240), UINT32_C(0xfad0f090),
      UINT16_C(102), UINT16_C(2173),
      CDISASM_ARM_NAME_CRC32CH, "crc32ch", 2u },
    { UINT32_C(0x01400240), UINT32_C(0xfad0f0a0),
      UINT16_C(103), UINT16_C(2174),
      CDISASM_ARM_NAME_CRC32CW, "crc32cw", 4u }
};

#if USE_EXTRA_OPCODES
static const a64_crc_descriptor a64_crc[8] = {
    { UINT16_C(5582), CDISASM_ARM_NAME_CRC32B, "crc32b", 1u },
    { UINT16_C(5583), CDISASM_ARM_NAME_CRC32H, "crc32h", 2u },
    { UINT16_C(5584), CDISASM_ARM_NAME_CRC32W, "crc32w", 4u },
    { UINT16_C(5602), CDISASM_ARM_NAME_CRC32X, "crc32x", 8u },
    { UINT16_C(5585), CDISASM_ARM_NAME_CRC32CB, "crc32cb", 1u },
    { UINT16_C(5586), CDISASM_ARM_NAME_CRC32CH, "crc32ch", 2u },
    { UINT16_C(5587), CDISASM_ARM_NAME_CRC32CW, "crc32cw", 4u },
    { UINT16_C(5603), CDISASM_ARM_NAME_CRC32CX, "crc32cx", 8u }
};
#endif

_Static_assert(CDISASM_ARM_NAME_CRC32B == UINT16_C(445),
               "CRC32B mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_CRC32CX == UINT16_C(452),
               "CRC32CX mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(5603),
               "fixed-width CRC32 form IDs unavailable");

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

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
                            cdisasm_arm_mode mode, size_t code_size,
                            cdisasm_arm_decode_option options,
                            cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    canonical_to_bytes(word, mode, 0, bytes);
    return cdisasm_arm_decode(cpu, mode, bytes, code_size,
        TEST_ADDRESS, options, instruction);
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
static cdisasm_arm_reg_id a64_reg(unsigned encoded, int is_64)
{
    if (encoded == 31u) {
        return is_64 ? CDISASM_ARM_REG_XZR : CDISASM_ARM_REG_WZR;
    }
    return (cdisasm_arm_reg_id)(
        (is_64 ? CDISASM_ARM_REG_X0 : CDISASM_ARM_REG_W0) + encoded);
}

static int exact_register(const cdisasm_arm_operand *operand,
                          cdisasm_arm_reg_id reg, uint8_t size,
                          cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = reg;
    expected.size = size;
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int exact_common(const cdisasm_arm_instruction *instruction,
                        uint32_t word, cdisasm_arm_mode mode,
                        cdisasm_arm_name_id name,
                        cdisasm_arm_form_id form,
                        cdisasm_arm_condition condition,
                        unsigned rd, unsigned rn, unsigned rm,
                        uint8_t source_size)
{
    uint32_t expected_raw = mode == CDISASM_ARM_MODE_T32
        ? (word << 16) | (word >> 16) : word;
    cdisasm_arm_reg_id rd_reg;
    cdisasm_arm_reg_id rn_reg;
    cdisasm_arm_reg_id rm_reg;

    if (mode == CDISASM_ARM_MODE_A64) {
        rd_reg = a64_reg(rd, 0);
        rn_reg = a64_reg(rn, 0);
        rm_reg = a64_reg(rm, source_size == 8u);
    } else {
        rd_reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rd);
        rn_reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rn);
        rm_reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rm);
    }
    return instruction->address == TEST_ADDRESS
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == expected_raw
        && instruction->name_id == name
        && instruction->form_id == form
        && instruction->condition == condition
        && instruction->isa_id == (mode == CDISASM_ARM_MODE_A32
            ? CDISASM_ARM_ISA_A32
            : mode == CDISASM_ARM_MODE_T32
                ? CDISASM_ARM_ISA_T32 : CDISASM_ARM_ISA_A64)
        && instruction->opcode_groups
            == (mode == CDISASM_ARM_MODE_A32
                    && condition <= CDISASM_ARM_CONDITION_LE
                ? CDISASM_GROUP_CONDITIONAL : CDISASM_GROUP_NONE)
        && instruction->instruction_flags == 0u
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && exact_register(&instruction->operand[0], rd_reg, 4u,
            CDISASM_OPERAND_ACCESS_WRITE)
        && exact_register(&instruction->operand[1], rn_reg, 4u,
            CDISASM_OPERAND_ACCESS_READ)
        && exact_register(&instruction->operand[2], rm_reg, source_size,
            CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void expect_allocated_aa32(
    const aa32_crc_descriptor *descriptor, cdisasm_arm_mode mode,
    unsigned condition, unsigned rd, unsigned rn, unsigned rm)
{
    cdisasm_arm_instruction instruction;
    uint32_t base = mode == CDISASM_ARM_MODE_A32
        ? descriptor->a32_value : descriptor->t32_value;
    uint32_t word = base | ((uint32_t)rn << 16)
        | ((uint32_t)rd << (mode == CDISASM_ARM_MODE_A32 ? 12u : 8u))
        | (uint32_t)rm;
    uint32_t decoded;

    if (mode == CDISASM_ARM_MODE_A32) {
        word |= (uint32_t)condition << 28;
    }
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(word, CDISASM_ARM_CPU_ANY, mode, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(exact_common(&instruction, word, mode, descriptor->name,
        mode == CDISASM_ARM_MODE_A32
            ? descriptor->a32_form : descriptor->t32_form,
        mode == CDISASM_ARM_MODE_A32
            ? (cdisasm_arm_condition)condition : CDISASM_ARM_CONDITION_AL,
        rd, rn, rm, descriptor->source_size));
#else
    EXPECT(decoded == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void expect_reserved_aa32(
    const aa32_crc_descriptor *descriptor, cdisasm_arm_mode mode,
    unsigned condition, unsigned rd, unsigned rn, unsigned rm)
{
    cdisasm_arm_instruction instruction;
    uint32_t word = (mode == CDISASM_ARM_MODE_A32
            ? descriptor->a32_value : descriptor->t32_value)
        | ((uint32_t)rn << 16)
        | ((uint32_t)rd << (mode == CDISASM_ARM_MODE_A32 ? 12u : 8u))
        | (uint32_t)rm;

    if (mode == CDISASM_ARM_MODE_A32) {
        word |= (uint32_t)condition << 28;
    }
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, mode, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
}

static void test_exhaustive_aa32(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    size_t operation;

    for (operation = 0u; operation < 6u; ++operation) {
        unsigned condition;
        unsigned rd;
        unsigned rn;
        unsigned rm;

        for (condition = 0u; condition < 15u; ++condition) {
            for (rd = 0u; rd < 16u; ++rd) {
                for (rn = 0u; rn < 16u; ++rn) {
                    for (rm = 0u; rm < 16u; ++rm) {
                        if (rd == 15u || rn == 15u || rm == 15u) {
                            expect_reserved_aa32(&aa32_crc[operation],
                                CDISASM_ARM_MODE_A32,
                                condition, rd, rn, rm);
                            ++reserved;
                        } else {
                            expect_allocated_aa32(&aa32_crc[operation],
                                CDISASM_ARM_MODE_A32,
                                condition, rd, rn, rm);
                            ++allocated;
                        }
                    }
                }
            }
        }
        for (rd = 0u; rd < 16u; ++rd) {
            for (rn = 0u; rn < 16u; ++rn) {
                for (rm = 0u; rm < 16u; ++rm) {
                    if (rd == 15u || rn == 15u || rm == 15u) {
                        expect_reserved_aa32(&aa32_crc[operation],
                            CDISASM_ARM_MODE_T32, 14u, rd, rn, rm);
                        ++reserved;
                    } else {
                        expect_allocated_aa32(&aa32_crc[operation],
                            CDISASM_ARM_MODE_T32, 14u, rd, rn, rm);
                        ++allocated;
                    }
                }
            }
        }
    }
    EXPECT(allocated == UINT32_C(324000));
    EXPECT(reserved == UINT32_C(69216));
}

static void expect_a64(uint32_t word, unsigned operation,
                       unsigned rd, unsigned rn, unsigned rm,
                       int allocated)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded;

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
    if (!allocated) {
        EXPECT(decoded == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        return;
    }
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(exact_common(&instruction, word, CDISASM_ARM_MODE_A64,
        a64_crc[operation].name, a64_crc[operation].form,
        CDISASM_ARM_CONDITION_AL, rd, rn, rm,
        a64_crc[operation].source_size));
#else
    (void)operation;
    (void)rd;
    (void)rn;
    (void)rm;
    EXPECT(decoded == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_exhaustive_a64(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned castagnoli;
    unsigned sf;
    unsigned size;
    unsigned rd;
    unsigned rn;
    unsigned rm;

    for (castagnoli = 0u; castagnoli < 2u; ++castagnoli) {
        for (sf = 0u; sf < 2u; ++sf) {
            for (size = 0u; size < 4u; ++size) {
                int valid = sf == (size == 3u ? 1u : 0u);
                unsigned operation = castagnoli * 4u + size;

                for (rd = 0u; rd < 32u; ++rd) {
                    for (rn = 0u; rn < 32u; ++rn) {
                        for (rm = 0u; rm < 32u; ++rm) {
                            uint32_t word = UINT32_C(0x1ac04000)
                                | ((uint32_t)castagnoli << 12)
                                | ((uint32_t)sf << 31)
                                | ((uint32_t)size << 10)
                                | ((uint32_t)rm << 16)
                                | ((uint32_t)rn << 5) | rd;


                            expect_a64(word, operation, rd, rn, rm, valid);
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
    }
    EXPECT(allocated == UINT32_C(262144));
    EXPECT(reserved == UINT32_C(262144));
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

static void test_profiles_transport_and_boundaries(void)
{
    static const cdisasm_arm_cpu_id a32_positive[] = {
        CDISASM_ARM_CPU_CORTEX_A32, CDISASM_ARM_CPU_CORTEX_A35,
        CDISASM_ARM_CPU_CORTEX_A53
    };
    static const cdisasm_arm_cpu_id a64_positive[] = {
        CDISASM_ARM_CPU_CORTEX_A34, CDISASM_ARM_CPU_CORTEX_A35,
        CDISASM_ARM_CPU_CORTEX_A53, CDISASM_ARM_CPU_APPLE_A10,
        CDISASM_ARM_CPU_APPLE_A12, CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_ARM_CPU_APPLE_M1, CDISASM_ARM_CPU_APPLE_M4,
        CDISASM_ARM_CPU_FUJITSU_A64FX
    };
    static const cdisasm_arm_mode modes[] = {
        CDISASM_ARM_MODE_A32, CDISASM_ARM_MODE_T32,
        CDISASM_ARM_MODE_A64
    };
    uint32_t a32_word = UINT32_C(0xe14e224d);
    uint32_t t32_word = UINT32_C(0xfad0feaD);
    uint32_t a64_word = UINT32_C(0x9ade5fdf);
#if USE_EXTRA_OPCODES
    const uint32_t expected_decoded = 4u;
#else
    const uint32_t expected_decoded = 0u;
#endif
    size_t index;

    for (index = 0u;
         index < sizeof(a32_positive) / sizeof(a32_positive[0]); ++index) {
        expect_cpu_status(a32_word, CDISASM_ARM_MODE_A32,
            a32_positive[index], CDISASM_STATUS_OK);
        expect_cpu_status(t32_word, CDISASM_ARM_MODE_T32,
            a32_positive[index], CDISASM_STATUS_OK);
    }
    expect_cpu_status(a32_word, CDISASM_ARM_MODE_A32,
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(t32_word, CDISASM_ARM_MODE_T32,
        CDISASM_ARM_CPU_CORTEX_A9, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_cpu_status(a32_word, CDISASM_ARM_MODE_A32,
        CDISASM_ARM_CPU_APPLE_A9, CDISASM_STATUS_INVALID_INSTRUCTION);
    for (index = 0u;
         index < sizeof(a64_positive) / sizeof(a64_positive[0]); ++index) {
        expect_cpu_status(a64_word, CDISASM_ARM_MODE_A64,
            a64_positive[index], CDISASM_STATUS_OK);
    }
    expect_cpu_status(a64_word, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_CPU_APPLE_A9, CDISASM_STATUS_INVALID_INSTRUCTION);

    for (index = 0u; index < sizeof(modes) / sizeof(modes[0]); ++index) {
        cdisasm_arm_mode mode = modes[index];
        uint32_t word = mode == CDISASM_ARM_MODE_A32 ? a32_word
            : mode == CDISASM_ARM_MODE_T32 ? t32_word : a64_word;
        cdisasm_arm_instruction little;
        cdisasm_arm_instruction big;
        uint8_t bytes[4];
        size_t boundary;

        memset(&little, 0xa5, sizeof(little));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, mode, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &little) == expected_decoded);
        canonical_to_bytes(word, mode, 1, bytes);
        memset(&big, 0xa5, sizeof(big));
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, mode,
            bytes, sizeof(bytes), TEST_ADDRESS,
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big)
            == expected_decoded);
        EXPECT(memcmp(&little, &big, sizeof(little)) == 0);

        for (boundary = 0u; boundary < 4u; ++boundary) {
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

    /* cond=1111 is the neighboring unconditional CPS namespace, not CRC32.
     * Keep it outside this family's ownership. */
    for (index = 0u; index < 6u; ++index) {
        cdisasm_arm_instruction instruction;
        uint32_t word = UINT32_C(0xf0000000) | aa32_crc[index].a32_value;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_NONE);
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
    uint32_t word = UINT32_C(0x9ade5fdf);

    expect_format(UINT32_C(0xe1002041), CDISASM_ARM_MODE_A32,
        "crc32b r2, r0, r1");
    expect_format(UINT32_C(0x11432044), CDISASM_ARM_MODE_A32,
        "crc32wne r2, r3, r4");
    expect_format(UINT32_C(0xfacdfd8e), CDISASM_ARM_MODE_T32,
        "crc32b sp, sp, lr");
    expect_format(UINT32_C(0xfad0fead), CDISASM_ARM_MODE_T32,
        "crc32cw lr, r0, sp");
    expect_format(UINT32_C(0x1ac14020), CDISASM_ARM_MODE_A64,
        "crc32b w0, w1, w1");
    expect_format(UINT32_C(0x1adf57ff), CDISASM_ARM_MODE_A64,
        "crc32ch wzr, wzr, wzr");
    expect_format(word, CDISASM_ARM_MODE_A64,
        "crc32cx wzr, w30, x30");

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text)) == strlen("CRC32CX wzr, w30, x30"));
    EXPECT(strcmp(text, "CRC32CX wzr, w30, x30") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged);                                            \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(5602));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_CRC32X);
    REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(1));
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.opcode_size = 2u);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_CONDITIONAL);
    REJECT_MUTATION(forged.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK);
    REJECT_MUTATION(forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_W30);
    REJECT_MUTATION(forged.operand[0].size = 8u);
    REJECT_MUTATION(forged.operand[1].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_W30);
    REJECT_MUTATION(forged.operand[2].size = 4u);
    REJECT_MUTATION(forged.operand[2].flags =
        CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT);

    forged = instruction;
    memset(&forged.operand[3], 0xa5, sizeof(forged.operand[3]));
    reject_forgery(&forged);
#undef REJECT_MUTATION
}
#endif

int main(void)
{
    test_exhaustive_aa32();
    test_exhaustive_a64();
    test_profiles_transport_and_boundaries();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif
    if (failures != 0) {
        fprintf(stderr, "%d fixed-width CRC32 test(s) failed\n", failures);
        return 1;
    }
    puts("fixed-width A32/T32/A64 CRC32 exact-family tests passed");
    return 0;
}
