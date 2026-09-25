#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

typedef struct bitperm_descriptor {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
} bitperm_descriptor;

/* Pinned open AARCHMRS forms bext_z_zz_, bdep_z_zz_, and bgrp_z_zz_.
 * LLVM 21 independently emits these same exact leaves. */
static const bitperm_descriptor descriptors[3] = {
    { UINT32_C(0x4500b000), CDISASM_ARM_NAME_BEXT,
      UINT16_C(2829), "bext" },
    { UINT32_C(0x4500b400), CDISASM_ARM_NAME_BDEP,
      UINT16_C(2830), "bdep" },
    { UINT32_C(0x4500b800), CDISASM_ARM_NAME_BGRP,
      UINT16_C(2831), "bgrp" }
};

_Static_assert(CDISASM_ARM_NAME_BEXT == UINT16_C(565),
               "established BEXT ID changed");
_Static_assert(CDISASM_ARM_NAME_BDEP == UINT16_C(564),
               "established BDEP ID changed");
_Static_assert(CDISASM_ARM_NAME_BGRP == UINT16_C(600),
               "established BGRP ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2831),
               "pinned SVE BitPerm form IDs unavailable");

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

static void domain_expect(int condition, uint32_t word, const char *message)
{
    if (!condition) {
        if (failures < 32) {
            fprintf(stderr, "word %08x: %s\n", (unsigned)word, message);
        }
        ++failures;
    }
}

static uint32_t bitperm_word(
    unsigned operation, unsigned size, unsigned zm, unsigned zn,
    unsigned zd)
{
    return UINT32_C(0x4500b000) | ((uint32_t)size << 22)
        | ((uint32_t)zm << 16) | ((uint32_t)operation << 10)
        | ((uint32_t)zn << 5) | (uint32_t)zd;
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
    return cdisasm_arm_decode(cpu_id, mode, bytes, code_size,
        UINT64_C(0x12f000), options, instruction);
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
static int z_operand_matches(
    const cdisasm_arm_operand *operand, unsigned encoded,
    uint8_t element_size, cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_matches(
    const cdisasm_arm_instruction *instruction, uint32_t word,
    const bitperm_descriptor *descriptor, unsigned size,
    unsigned zm, unsigned zn, unsigned zd)
{
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size);

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == descriptor->name_id
        && instruction->form_id == descriptor->form_id
        && instruction->address == UINT64_C(0x12f000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 3u
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && z_operand_matches(&instruction->operand[0], zd, element_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        && z_operand_matches(&instruction->operand[1], zn, element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && z_operand_matches(&instruction->operand[2], zm, element_size,
            CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_owned_parent(void)
{
    uint32_t allocated[3][4] = {
        { 0u, 0u, 0u, 0u }, { 0u, 0u, 0u, 0u },
        { 0u, 0u, 0u, 0u }
    };
    uint32_t reserved[4] = { 0u, 0u, 0u, 0u };
    unsigned operation;

    for (operation = 0u; operation < 4u; ++operation) {
        unsigned size;

        for (size = 0u; size < 4u; ++size) {
            unsigned zm;

            for (zm = 0u; zm < 32u; ++zm) {
                unsigned zn;

                for (zn = 0u; zn < 32u; ++zn) {
                    unsigned zd;

                    for (zd = 0u; zd < 32u; ++zd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = bitperm_word(
                            operation, size, zm, zn, zd);
                        uint32_t decoded;

                        domain_expect(
                            (word & UINT32_C(0xff20f000))
                                == UINT32_C(0x4500b000),
                            word, "parent construction mismatch");
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                        if (operation == 3u) {
                            ++reserved[size];
                            domain_expect(decoded == 0u, word,
                                "reserved selector unexpectedly decoded");
                            domain_expect(instruction_is_error_only(
                                &instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION), word,
                                "reserved selector lost INVALID ownership");
                        } else {
                            ++allocated[operation][size];
                            domain_expect(
                                (word & UINT32_C(0xff20fc00))
                                    == descriptors[operation].value,
                                word, "leaf construction mismatch");
#if USE_EXTRA_OPCODES
                            domain_expect(decoded == 4u, word,
                                "allocated leaf did not decode");
                            if (decoded == 4u) {
                                domain_expect(metadata_matches(
                                    &instruction, word,
                                    &descriptors[operation], size,
                                    zm, zn, zd), word,
                                    "allocated leaf metadata mismatch");
                            }
#else
                            domain_expect(decoded == 0u, word,
                                "extras-OFF leaf unexpectedly decoded");
                            domain_expect(instruction_is_error_only(
                                &instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                                word, "extras-OFF ownership mismatch");
#endif
                        }
                    }
                }
            }
        }
    }
    for (operation = 0u; operation < 3u; ++operation) {
        unsigned size;

        for (size = 0u; size < 4u; ++size) {
            EXPECT(allocated[operation][size] == UINT32_C(32768));
        }
    }
    for (operation = 0u; operation < 4u; ++operation) {
        EXPECT(reserved[operation] == UINT32_C(32768));
    }
}

static void expect_cpu_status(
    uint32_t word, cdisasm_arm_cpu_id cpu_id,
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
    decoded = decode_word(word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_feature_profiles_and_neighbors(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        uint32_t word = bitperm_word(
            (unsigned)descriptor_index, 3u, 29u, 13u, 7u);
        unsigned bit;

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        /* No concrete profile currently advertises FEAT_SVE_BitPerm. */
        expect_cpu_status(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((UINT32_C(0xff20fc00)
                    & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(word ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded != 4u
                || instruction.form_id != descriptors[descriptor_index].form_id);
        }
    }

    for (descriptor_index = 0u; descriptor_index < 4u;
         ++descriptor_index) {
        cdisasm_arm_instruction instruction;
        uint32_t word = bitperm_word(
            3u, (unsigned)descriptor_index, 29u, 13u, 7u);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
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
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x12f000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x12f000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12f000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12f000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(
            &other, CDISASM_STATUS_TRUNCATED));
    }
}

static void test_endian_dispatch_modes_and_boundaries(void)
{
    cdisasm_arm_instruction instruction;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        check_transport(bitperm_word((unsigned)descriptor_index,
            (unsigned)(descriptor_index + 1u), 29u, 13u, 7u));
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(bitperm_word(0u, 3u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(bitperm_word(1u, 3u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(bitperm_word(2u, 3u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(bitperm_word(2u, 3u, 29u, 13u, 7u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[96];
    char short_text[8];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_7,
        text, sizeof(text)) == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
        NULL, 0u) == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
        short_text, sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void reject_forgery(
    const cdisasm_arm_instruction *instruction, const char *mutation)
{
    char text[96];
    size_t length;

    memset(text, 0xa5, sizeof(text));
    length = cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text));
    if (length != 0u || text[0] != '\0') {
        if (failures < 32) {
            fprintf(stderr, "accepted formatter forgery: %s\n", mutation);
        }
        ++failures;
    }
}

static void test_formatter_and_forgery(void)
{
    static const char suffixes[4] = { 'b', 'h', 's', 'd' };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char expected[96];
    char text[96];
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        unsigned size;

        for (size = 0u; size < 4u; ++size) {
            int length = snprintf(expected, sizeof(expected),
                "%s z7.%c, z13.%c, z29.%c",
                descriptors[descriptor_index].mnemonic,
                suffixes[size], suffixes[size], suffixes[size]);

            EXPECT(length > 0 && (size_t)length < sizeof(expected));
            expect_format(bitperm_word((unsigned)descriptor_index,
                size, 29u, 13u, 7u), expected);
        }
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(bitperm_word(2u, 3u, 29u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction,
        CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("BGRP z31.d, z30.d, z29.d"));
    EXPECT(strcmp(text, "BGRP z31.d, z30.d, z29.d") == 0);

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(2830));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_BDEP);
    REJECT_MUTATION(forged.raw_instruction =
        bitperm_word(1u, 3u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.raw_instruction =
        bitperm_word(3u, 3u, 29u, 30u, 31u));
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand_count = 4u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_Z30);
    REJECT_MUTATION(forged.operand[0].extend_type =
        (cdisasm_arm_extend_type)4u);
    REJECT_MUTATION(forged.operand[0].flags =
        CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    REJECT_MUTATION(forged.operand[0].base_reg = CDISASM_ARM_REG_X0);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_Z29);
    REJECT_MUTATION(forged.operand[1].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[1].size = 8u);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_Z28);
    REJECT_MUTATION(forged.operand[2].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[2].address = UINT64_C(1));

#undef REJECT_MUTATION
}
#else
static void test_formatter_and_forgery(void)
{
}
#endif

int main(void)
{
    test_exhaustive_owned_parent();
    test_feature_profiles_and_neighbors();
    test_endian_dispatch_modes_and_boundaries();
    test_formatter_and_forgery();

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE BitPerm test(s) failed\n", failures);
        return 1;
    }
    printf("ARM SVE BitPerm tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=393216, reserved=131072)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
