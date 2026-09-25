#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

typedef enum crypto_layout {
    CRYPTO_TT,
    CRYPTO_QQV2D,
    CRYPTO_VVV2D,
    CRYPTO_VVV2D_WRITE,
    CRYPTO_VVV4S,
    CRYPTO_VVV4S_WRITE,
    CRYPTO_VVVV4S,
    CRYPTO_VVVV16B,
    CRYPTO_VVV2D_IMM6,
    CRYPTO_VV2D,
    CRYPTO_VV4S
} crypto_layout;

typedef struct crypto_descriptor {
    uint32_t mask;
    uint32_t value;
    cdisasm_arm_form_id form;
    cdisasm_arm_name_id name;
    const char *mnemonic;
    crypto_layout layout;
} crypto_descriptor;

static const crypto_descriptor descriptors[] = {
    { UINT32_C(0xffe0cc00), UINT32_C(0xce408000), UINT16_C(6287),
      CDISASM_ARM_NAME_SM3TT1A, "sm3tt1a", CRYPTO_TT },
    { UINT32_C(0xffe0cc00), UINT32_C(0xce408400), UINT16_C(6288),
      CDISASM_ARM_NAME_SM3TT1B, "sm3tt1b", CRYPTO_TT },
    { UINT32_C(0xffe0cc00), UINT32_C(0xce408800), UINT16_C(6289),
      CDISASM_ARM_NAME_SM3TT2A, "sm3tt2a", CRYPTO_TT },
    { UINT32_C(0xffe0cc00), UINT32_C(0xce408c00), UINT16_C(6290),
      CDISASM_ARM_NAME_SM3TT2B, "sm3tt2b", CRYPTO_TT },
    { UINT32_C(0xffe0fc00), UINT32_C(0xce608000), UINT16_C(6291),
      CDISASM_ARM_NAME_SHA512H, "sha512h", CRYPTO_QQV2D },
    { UINT32_C(0xffe0fc00), UINT32_C(0xce608400), UINT16_C(6292),
      CDISASM_ARM_NAME_SHA512H2, "sha512h2", CRYPTO_QQV2D },
    { UINT32_C(0xffe0fc00), UINT32_C(0xce608800), UINT16_C(6293),
      CDISASM_ARM_NAME_SHA512SU1, "sha512su1", CRYPTO_VVV2D },
    { UINT32_C(0xffe0fc00), UINT32_C(0xce608c00), UINT16_C(6294),
      CDISASM_ARM_NAME_RAX1, "rax1", CRYPTO_VVV2D_WRITE },
    { UINT32_C(0xffe0fc00), UINT32_C(0xce60c000), UINT16_C(6295),
      CDISASM_ARM_NAME_SM3PARTW1, "sm3partw1", CRYPTO_VVV4S },
    { UINT32_C(0xffe0fc00), UINT32_C(0xce60c400), UINT16_C(6296),
      CDISASM_ARM_NAME_SM3PARTW2, "sm3partw2", CRYPTO_VVV4S },
    { UINT32_C(0xffe0fc00), UINT32_C(0xce60c800), UINT16_C(6297),
      CDISASM_ARM_NAME_SM4EKEY, "sm4ekey", CRYPTO_VVV4S_WRITE },
    { UINT32_C(0xffe08000), UINT32_C(0xce000000), UINT16_C(6298),
      CDISASM_ARM_NAME_EOR3, "eor3", CRYPTO_VVVV16B },
    { UINT32_C(0xffe08000), UINT32_C(0xce200000), UINT16_C(6299),
      CDISASM_ARM_NAME_BCAX, "bcax", CRYPTO_VVVV16B },
    { UINT32_C(0xffe08000), UINT32_C(0xce400000), UINT16_C(6300),
      CDISASM_ARM_NAME_SM3SS1, "sm3ss1", CRYPTO_VVVV4S },
    { UINT32_C(0xffe00000), UINT32_C(0xce800000), UINT16_C(6301),
      CDISASM_ARM_NAME_XAR, "xar", CRYPTO_VVV2D_IMM6 },
    { UINT32_C(0xfffffc00), UINT32_C(0xcec08000), UINT16_C(6302),
      CDISASM_ARM_NAME_SHA512SU0, "sha512su0", CRYPTO_VV2D },
    { UINT32_C(0xfffffc00), UINT32_C(0xcec08400), UINT16_C(6303),
      CDISASM_ARM_NAME_SM4E, "sm4e", CRYPTO_VV4S }
};

_Static_assert(CDISASM_ARM_NAME_SHA512H == UINT16_C(1374),
               "SHA512H mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SM3TT1A == UINT16_C(1397),
               "SM3TT1A mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SM4EKEY == UINT16_C(1402),
               "SM4EKEY mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6303),
               "fixed crypto form IDs unavailable");

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

static uint32_t make_word(const crypto_descriptor *descriptor,
                          unsigned rd, unsigned rn, unsigned rm,
                          unsigned ra, unsigned lane)
{
    uint32_t word = descriptor->value | (uint32_t)rd
        | ((uint32_t)rn << 5);

    if (descriptor->layout != CRYPTO_VV2D
        && descriptor->layout != CRYPTO_VV4S) {
        word |= (uint32_t)rm << 16;
    }
    if (descriptor->layout == CRYPTO_TT) {
        word |= (uint32_t)lane << 12;
    } else if (descriptor->layout == CRYPTO_VVVV4S
               || descriptor->layout == CRYPTO_VVVV16B) {
        word |= (uint32_t)ra << 10;
    } else if (descriptor->layout == CRYPTO_VVV2D_IMM6) {
        word |= (uint32_t)lane << 10;
    }
    return word;
}

static void word_bytes(uint32_t word, int big_endian, uint8_t bytes[4])
{
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
                            size_t code_size,
                            cdisasm_arm_decode_option options,
                            cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_bytes(word, 0, bytes);
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64,
        bytes, code_size, UINT64_C(0x1e5000), options, instruction);
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
                         unsigned encoded, uint8_t element_size,
                         uint8_t flags, uint64_t lane,
                         cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded);
    expected.size = 16u;
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.scale = (uint8_t)(16u / element_size);
    expected.flags = flags;
    expected.imm = lane;
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int exact_immediate(const cdisasm_arm_operand *operand,
                           uint64_t value)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_IMMEDIATE;
    expected.imm = value;
    expected.size = 1u;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int exact_metadata(const cdisasm_arm_instruction *instruction,
                          uint32_t word,
                          const crypto_descriptor *descriptor,
                          unsigned rd, unsigned rn, unsigned rm,
                          unsigned ra, unsigned lane)
{
    cdisasm_operand_access destination_access =
        descriptor->layout == CRYPTO_VVV2D_WRITE
            || descriptor->layout == CRYPTO_VVV4S_WRITE
            || descriptor->layout == CRYPTO_VVVV4S
            || descriptor->layout == CRYPTO_VVVV16B
            || descriptor->layout == CRYPTO_VVV2D_IMM6
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ_WRITE;
    uint8_t element_size = descriptor->layout == CRYPTO_QQV2D
            || descriptor->layout == CRYPTO_VVV2D
            || descriptor->layout == CRYPTO_VVV2D_WRITE
            || descriptor->layout == CRYPTO_VVV2D_IMM6
            || descriptor->layout == CRYPTO_VV2D
        ? 8u : descriptor->layout == CRYPTO_VVVV16B ? 1u : 4u;
    uint8_t operand_count = descriptor->layout == CRYPTO_VV2D
            || descriptor->layout == CRYPTO_VV4S
        ? 2u
        : descriptor->layout == CRYPTO_VVVV4S
            || descriptor->layout == CRYPTO_VVVV16B
            || descriptor->layout == CRYPTO_VVV2D_IMM6
        ? 4u : 3u;
    uint8_t destination_element =
        descriptor->layout == CRYPTO_QQV2D ? 16u : element_size;

    return instruction->address == UINT64_C(0x1e5000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == descriptor->name
        && instruction->form_id == descriptor->form
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == operand_count
        && exact_operand(&instruction->operand[0], rd,
            destination_element, CDISASM_OPERAND_FLAG_NONE, 0u,
            destination_access)
        && exact_operand(&instruction->operand[1], rn,
            destination_element, CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_READ)
        && (operand_count < 3u || exact_operand(&instruction->operand[2], rm,
            element_size,
            descriptor->layout == CRYPTO_TT
                ? CDISASM_ARM_OPERAND_FLAG_HAS_LANE
                : CDISASM_OPERAND_FLAG_NONE,
            descriptor->layout == CRYPTO_TT ? lane : 0u,
            CDISASM_OPERAND_ACCESS_READ))
        && (operand_count < 4u
            || (descriptor->layout == CRYPTO_VVV2D_IMM6
                ? exact_immediate(&instruction->operand[3], lane)
                : exact_operand(&instruction->operand[3], ra,
                    element_size, CDISASM_OPERAND_FLAG_NONE, 0u,
                    CDISASM_OPERAND_ACCESS_READ)));
}
#endif

static void check_word(uint32_t word, const crypto_descriptor *descriptor,
                       unsigned rd, unsigned rn, unsigned rm,
                       unsigned ra, unsigned lane)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded;

    EXPECT((word & descriptor->mask) == descriptor->value);
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(exact_metadata(&instruction, word, descriptor,
        rd, rn, rm, ra, lane));
#else
    (void)descriptor;
    (void)rd;
    (void)rn;
    (void)rm;
    (void)ra;
    (void)lane;
    EXPECT(decoded == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_exhaustive(void)
{
    uint32_t count = 0u;

    for (size_t index = 0u;
         index < sizeof(descriptors) / sizeof(descriptors[0]); ++index) {
        const crypto_descriptor *descriptor = &descriptors[index];

        if (descriptor->layout == CRYPTO_TT) {
            for (unsigned lane = 0u; lane < 4u; ++lane) {
                for (unsigned rm = 0u; rm < 32u; ++rm) {
                    for (unsigned rn = 0u; rn < 32u; ++rn) {
                        for (unsigned rd = 0u; rd < 32u; ++rd) {
                            check_word(make_word(descriptor,
                                rd, rn, rm, 0u, lane), descriptor,
                                rd, rn, rm, 0u, lane);
                            ++count;
                        }
                    }
                }
            }
        } else if (descriptor->layout == CRYPTO_VVVV4S
                   || descriptor->layout == CRYPTO_VVVV16B) {
            for (unsigned ra = 0u; ra < 32u; ++ra) {
                for (unsigned rm = 0u; rm < 32u; ++rm) {
                    for (unsigned rn = 0u; rn < 32u; ++rn) {
                        for (unsigned rd = 0u; rd < 32u; ++rd) {
                            check_word(make_word(descriptor,
                                rd, rn, rm, ra, 0u), descriptor,
                                rd, rn, rm, ra, 0u);
                            ++count;
                        }
                    }
                }
            }
        } else if (descriptor->layout == CRYPTO_VVV2D_IMM6) {
            for (unsigned immediate = 0u; immediate < 64u; ++immediate) {
                for (unsigned rm = 0u; rm < 32u; ++rm) {
                    for (unsigned rn = 0u; rn < 32u; ++rn) {
                        for (unsigned rd = 0u; rd < 32u; ++rd) {
                            check_word(make_word(descriptor,
                                rd, rn, rm, 0u, immediate), descriptor,
                                rd, rn, rm, 0u, immediate);
                            ++count;
                        }
                    }
                }
            }
        } else if (descriptor->layout == CRYPTO_VV2D
                   || descriptor->layout == CRYPTO_VV4S) {
            for (unsigned rn = 0u; rn < 32u; ++rn) {
                for (unsigned rd = 0u; rd < 32u; ++rd) {
                    check_word(make_word(descriptor,
                        rd, rn, 0u, 0u, 0u), descriptor,
                        rd, rn, 0u, 0u, 0u);
                    ++count;
                }
            }
        } else {
            for (unsigned rm = 0u; rm < 32u; ++rm) {
                for (unsigned rn = 0u; rn < 32u; ++rn) {
                    for (unsigned rd = 0u; rd < 32u; ++rd) {
                        check_word(make_word(descriptor,
                            rd, rn, rm, 0u, 0u), descriptor,
                            rd, rn, rm, 0u, 0u);
                        ++count;
                    }
                }
            }
        }
    }
    EXPECT(count == UINT32_C(5998592));
}

static void test_transport_profiles_and_precedence(void)
{
    static const size_t feature_cases[] = { 0u, 4u, 7u, 10u };
#if USE_EXTRA_OPCODES
    const uint32_t expected_any_decoded = 4u;
    const cdisasm_status expected_named_status =
        CDISASM_STATUS_INVALID_INSTRUCTION;
#else
    const uint32_t expected_any_decoded = 0u;
    const cdisasm_status expected_named_status =
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif

    for (size_t index = 0u;
         index < sizeof(descriptors) / sizeof(descriptors[0]); ++index) {
        const crypto_descriptor *descriptor = &descriptors[index];
        uint32_t word = make_word(descriptor,
            31u, 30u,
            descriptor->layout == CRYPTO_VV2D
                    || descriptor->layout == CRYPTO_VV4S
                ? 0u : 29u,
            descriptor->layout == CRYPTO_VVVV4S
                    || descriptor->layout == CRYPTO_VVVV16B
                ? 28u : 0u,
            descriptor->layout == CRYPTO_TT ? 3u
                : descriptor->layout == CRYPTO_VVV2D_IMM6 ? 63u : 0u);
        cdisasm_arm_instruction little;
        cdisasm_arm_instruction big;
        uint8_t bytes[4];
#if USE_EXTRA_OPCODES
        const uint32_t expected_decoded = 4u;
#else
        const uint32_t expected_decoded = 0u;
#endif

        memset(&little, 0xa5, sizeof(little));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &little) == expected_decoded);
        word_bytes(word, 1, bytes);
        memset(&big, 0xa5, sizeof(big));
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x1e5000),
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big) == expected_decoded);
        EXPECT(memcmp(&little, &big, sizeof(little)) == 0);

        for (unsigned boundary = 0u; boundary < 4u; ++boundary) {
            cdisasm_arm_instruction instruction;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, boundary,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
            EXPECT(error_only(&instruction, boundary == 0u
                ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED));
        }
    }

    for (size_t index = 0u;
         index < sizeof(feature_cases) / sizeof(feature_cases[0]); ++index) {
        const crypto_descriptor *descriptor =
            &descriptors[feature_cases[index]];
        uint32_t word = make_word(descriptor, 0u, 1u,
            descriptor->layout == CRYPTO_VV2D
                    || descriptor->layout == CRYPTO_VV4S
                ? 0u : 2u, 3u,
            descriptor->layout == CRYPTO_VVV2D_IMM6 ? 63u : 0u);
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction)
            == expected_any_decoded);
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_CORTEX_A53, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(error_only(&instruction, expected_named_status));
    }
    {
        cdisasm_arm_instruction instruction;
        uint32_t word = make_word(&descriptors[0], 0u, 1u, 2u, 0u, 3u);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
            UINT64_C(1) << 63, &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[128];
    char short_text[8];
    size_t length = strlen(expected);
    size_t formatted;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    formatted = cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text));
    if (formatted != length || strcmp(text, expected) != 0) {
        fprintf(stderr, "format 0x%08x: got '%s' (%zu), expected '%s' (%zu)\n",
            word, text, formatted, expected, length);
    }
    EXPECT(formatted == length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, NULL, 0u) == length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        short_text, sizeof(short_text)) == length);
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

static int shared_sve_name(cdisasm_arm_name_id name)
{
    return name == CDISASM_ARM_NAME_EOR3
        || name == CDISASM_ARM_NAME_BCAX
        || name == CDISASM_ARM_NAME_XAR
        || name == CDISASM_ARM_NAME_RAX1
        || name == CDISASM_ARM_NAME_SM4E
        || name == CDISASM_ARM_NAME_SM4EKEY;
}

static void sve_graft_identity(cdisasm_arm_name_id name,
                               cdisasm_arm_form_id *form,
                               uint32_t *word)
{
    if (name == CDISASM_ARM_NAME_EOR3) {
        *form = UINT16_C(2326);
        *word = UINT32_C(0x04203800);
    } else if (name == CDISASM_ARM_NAME_BCAX) {
        *form = UINT16_C(2327);
        *word = UINT32_C(0x04603800);
    } else if (name == CDISASM_ARM_NAME_XAR) {
        *form = UINT16_C(2325);
        *word = UINT32_C(0x04203400);
    } else if (name == CDISASM_ARM_NAME_RAX1) {
        *form = UINT16_C(2917);
        *word = UINT32_C(0x4520f400);
    } else if (name == CDISASM_ARM_NAME_SM4E) {
        *form = UINT16_C(2907);
        *word = UINT32_C(0x4523e000);
    } else {
        *form = UINT16_C(2916);
        *word = UINT32_C(0x4520f000);
    }
}

static void test_formatter(void)
{
    static const char *expected[] = {
        "sm3tt1a v0.4s, v1.4s, v2.s[0]",
        "sm3tt1b v3.4s, v4.4s, v5.s[1]",
        "sm3tt2a v6.4s, v7.4s, v8.s[2]",
        "sm3tt2b v9.4s, v10.4s, v11.s[3]",
        "sha512h q12, q13, v14.2d",
        "sha512h2 q15, q16, v17.2d",
        "sha512su1 v18.2d, v19.2d, v20.2d",
        "rax1 v0.2d, v1.2d, v2.2d",
        "sm3partw1 v21.4s, v22.4s, v23.4s",
        "sm3partw2 v24.4s, v25.4s, v26.4s",
        "sm4ekey v27.4s, v28.4s, v29.4s",
        "eor3 v3.16b, v4.16b, v5.16b, v6.16b",
        "bcax v7.16b, v8.16b, v9.16b, v10.16b",
        "sm3ss1 v30.4s, v31.4s, v0.4s, v1.4s",
        "xar v11.2d, v12.2d, v13.2d, #0x25",
        "sha512su0 v2.2d, v3.2d",
        "sm4e v17.4s, v18.4s"
    };
    static const unsigned rd[] = {
        0u, 3u, 6u, 9u, 12u, 15u, 18u, 0u, 21u, 24u, 27u,
        3u, 7u, 30u, 11u, 2u, 17u
    };
    static const unsigned rn[] = {
        1u, 4u, 7u, 10u, 13u, 16u, 19u, 1u, 22u, 25u, 28u,
        4u, 8u, 31u, 12u, 3u, 18u
    };
    static const unsigned rm[] = {
        2u, 5u, 8u, 11u, 14u, 17u, 20u, 2u, 23u, 26u, 29u,
        5u, 9u, 0u, 13u, 0u, 0u
    };
    static const unsigned ra[] = {
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        6u, 10u, 1u, 0u, 0u, 0u
    };
    static const unsigned immediate[] = {
        0u, 1u, 2u, 3u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 37u, 0u, 0u
    };

    for (size_t index = 0u;
         index < sizeof(descriptors) / sizeof(descriptors[0]); ++index) {
        uint32_t word = make_word(&descriptors[index],
            rd[index], rn[index], rm[index], ra[index], immediate[index]);
        cdisasm_arm_instruction instruction;
        cdisasm_arm_instruction forged;

        expect_format(word, expected[index]);
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);

#define REJECT_MUTATION(statement)                                          \
        do {                                                                \
            forged = instruction;                                           \
            statement;                                                      \
            reject_forgery(&forged);                                        \
        } while (0)

        REJECT_MUTATION(forged.form_id = CDISASM_ARM_FORM_NONE);
        REJECT_MUTATION(forged.name_id = index == 0u
            ? CDISASM_ARM_NAME_SHA512H : CDISASM_ARM_NAME_SM3TT1A);
        REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd503201f));
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
        REJECT_MUTATION(forged.opcode_size = 2u);
        REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
        REJECT_MUTATION(forged.instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK);
        REJECT_MUTATION(forged.branch_target = UINT64_C(4));
        REJECT_MUTATION(forged.operand_count = 1u);
        REJECT_MUTATION(forged.operand[0].access =
            CDISASM_OPERAND_ACCESS_READ);
        REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V0);
        if (descriptors[index].layout == CRYPTO_TT) {
            REJECT_MUTATION(forged.operand[2].imm ^= UINT64_C(1));
        }
        if (descriptors[index].layout == CRYPTO_VVV2D_IMM6) {
            REJECT_MUTATION(forged.operand[3].imm ^= UINT64_C(1));
            REJECT_MUTATION(forged.operand[3].size = 8u);
        }
        if (shared_sve_name(instruction.name_id)) {
            forged = instruction;
            forged.form_id = CDISASM_ARM_FORM_NONE;
            forged.raw_instruction = UINT32_C(0xd503201f);
            reject_forgery(&forged);

            forged = instruction;
            sve_graft_identity(instruction.name_id,
                &forged.form_id, &forged.raw_instruction);
            reject_forgery(&forged);
        }
        if (instruction.operand_count < CDISASM_ARM_MAX_OPERANDS) {
            forged = instruction;
            memset(&forged.operand[instruction.operand_count],
                0xa5, sizeof(forged.operand[instruction.operand_count]));
            reject_forgery(&forged);
        }
#undef REJECT_MUTATION
    }
    /* Shared SVE/SVE2 mnemonics must not be captured by the fixed-width
     * fail-closed schema. */
    expect_format(UINT32_C(0x04213840),
        "eor3 z0.d, z0.d, z1.d, z2.d");
    expect_format(UINT32_C(0x046438a3),
        "bcax z3.d, z3.d, z4.d, z5.d");
    expect_format(UINT32_C(0x452af528),
        "rax1 z8.d, z9.d, z10.d");
    expect_format(UINT32_C(0x4523e18b),
        "sm4e z11.s, z11.s, z12.s");
    expect_format(UINT32_C(0x4522f020),
        "sm4ekey z0.s, z1.s, z2.s");
}
#endif

int main(void)
{
    test_exhaustive();
    test_transport_profiles_and_precedence();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif
    if (failures != 0) {
        fprintf(stderr, "%d fixed Advanced SIMD crypto test(s) failed\n",
            failures);
        return 1;
    }
    puts("fixed Advanced SIMD SHA512/SM3/SM4 tests passed");
    return 0;
}
