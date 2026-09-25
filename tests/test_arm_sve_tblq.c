#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_TBXQ == UINT16_C(356),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_TBLQ == UINT16_C(357),
               "TBLQ must retain its append-only mnemonic ID");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(421),
               "TBLQ mnemonic count changed");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static uint32_t tblq_word(
    unsigned size_code, unsigned zd, unsigned zn, unsigned zm)
{
    return UINT32_C(0x4400f800)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)zm << 16)
        | ((uint32_t)zn << 5)
        | (uint32_t)zd;
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
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    cdisasm_arm_decode_option options,
    size_t code_size,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x9000), options,
        instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static int z_operand_matches(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    uint8_t element_size,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int zlist_operand_matches(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    uint8_t element_size)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    expected.register_list = UINT16_C(0x0101);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int tblq_instruction_matches(
    const cdisasm_arm_instruction *instruction,
    uint32_t word,
    unsigned size_code,
    unsigned zd,
    unsigned zn,
    unsigned zm)
{
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == CDISASM_ARM_NAME_TBLQ
        && instruction->address == UINT64_C(0x9000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 3u
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && z_operand_matches(
            &instruction->operand[0], zd, element_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        && zlist_operand_matches(
            &instruction->operand[1], zn, element_size)
        && z_operand_matches(
            &instruction->operand[2], zm, element_size,
            CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_complete_allocated_space(void)
{
    unsigned size_code;

    /*
     * Bits 23:22, 20:16, 9:5, and 4:0 are all unconstrained.  Exhaust the
     * full 4 * 32 * 32 * 32 = 131072-word architectural TBLQ class.
     */
    for (size_code = 0u; size_code < 4u; ++size_code) {
        unsigned zd;

        for (zd = 0u; zd < 32u; ++zd) {
            unsigned zn;

            for (zn = 0u; zn < 32u; ++zn) {
                unsigned zm;

                for (zm = 0u; zm < 32u; ++zm) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = tblq_word(
                        size_code, zd, zn, zm);
                    uint32_t decoded;

                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY,
                        CDISASM_ARM_MODE_A64,
                        CDISASM_ARM_DECODE_OPTION_NONE, 4u,
                        &instruction);
#if USE_EXTRA_OPCODES
                    if (decoded != 4u
                        || !tblq_instruction_matches(
                            &instruction, word, size_code,
                            zd, zn, zm)) {
                        fprintf(
                            stderr,
                            "TBLQ exhaustive failure at %08x "
                            "(size=%u zd=%u zn=%u zm=%u)\n",
                            (unsigned)word, size_code, zd, zn, zm);
                        ++failures;
                        return;
                    }
#else
                    if (decoded != 0u
                        || !instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION)) {
                        fprintf(
                            stderr,
                            "TBLQ OFF-build ownership failure at %08x\n",
                            (unsigned)word);
                        ++failures;
                        return;
                    }
#endif
                }
            }
        }
    }
}

static void test_feature_profiles(void)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_cpu_id cpu_id;
    uint32_t word = tblq_word(2u, 23u, 13u, 8u);
#if USE_EXTRA_OPCODES
    const cdisasm_status named_profile_status =
        CDISASM_STATUS_INVALID_INSTRUCTION;
#else
    const cdisasm_status named_profile_status =
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_TBLQ);
#else
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

    /* No current named CPU profile claims SVE2.1 or SME2.1. */
    for (cpu_id = CDISASM_ARM_CPU_FIRST;
         cpu_id <= CDISASM_ARM_CPU_LAST;
         ++cpu_id) {
        if ((cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) == 0u) {
            continue;
        }
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            word, cpu_id, CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, named_profile_status));
    }
}

static void test_boundaries_endian_and_dispatch(void)
{
    static const unsigned unowned_fixed_bit_flips[] = {
        10u, 11u, 13u, 14u, 15u, 25u, 26u, 27u, 29u
    };
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t little_bytes[4];
    uint8_t big_bytes[4];
    uint32_t word = tblq_word(3u, 31u, 31u, 31u);
    uint32_t decoded;
    size_t index;
    unsigned size_code;

    for (size_code = 0u; size_code < 4u; ++size_code) {
        uint32_t endian_word = tblq_word(
            size_code, 31u, 31u, 31u);

        memset(&little, 0xa5, sizeof(little));
        decoded = decode_word(
            endian_word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u, &little);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
#else
        EXPECT(decoded == 0u);
#endif

        word_to_be(endian_word, big_bytes);
        memset(&big, 0xa5, sizeof(big));
        decoded = cdisasm_arm_decode(
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            big_bytes, sizeof(big_bytes), UINT64_C(0x9000),
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
#else
        EXPECT(decoded == 0u);
#endif
        EXPECT(memcmp(&big, &little, sizeof(big)) == 0);
    }

    word_to_le(word, little_bytes);
    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode_checked(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x9000),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &generic, sizeof(generic));
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 3u, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_TRUNCATED));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A32, CDISASM_ARM_DECODE_OPTION_NONE,
        4u, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        UINT64_C(1) << 63, 4u, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

    /*
     * These one-bit changes leave the exact 0xff20fc00/0x4400f800
     * descriptor.  Some belong to separate allocated classes: bit 13 reaches
     * exact MADPT, bits 10 and 11 reach reserved controls 111 and 100 of the
     * binary quad-permute parent, bit 15 reaches a reserved size quarter of
     * the exact USDOT parent, and bit 29 reaches the exact SVE2.2 zeroing
     * FCVTZU leaf.  All stay unowned by TBLQ rather than being absorbed into
     * its encoding space.
     */
    for (index = 0u;
         index < sizeof(unowned_fixed_bit_flips)
            / sizeof(unowned_fixed_bit_flips[0]);
         ++index) {
        uint32_t adjacent = word
            ^ (UINT32_C(1) << unowned_fixed_bit_flips[index]);

        memset(&generic, 0xa5, sizeof(generic));
        decoded = decode_word(
            adjacent, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u, &generic);
#if USE_EXTRA_OPCODES
        if (unowned_fixed_bit_flips[index] == 13u) {
            EXPECT(decoded == 4u);
            EXPECT(generic.name_id == CDISASM_ARM_NAME_MADPT);
            EXPECT(generic.form_id == UINT16_C(2708));
        } else if (unowned_fixed_bit_flips[index] == 29u) {
            EXPECT(decoded == 4u);
            EXPECT(generic.name_id == CDISASM_ARM_NAME_FCVTZU);
            EXPECT(generic.form_id == UINT16_C(2990));
        } else {
            EXPECT(decoded == 0u);
            EXPECT(instruction_is_error_only(
                &generic, CDISASM_STATUS_INVALID_INSTRUCTION));
        }
#else
        EXPECT(decoded == 0u);
        EXPECT(instruction_is_error_only(
            &generic,
            unowned_fixed_bit_flips[index] == 10u
                    || unowned_fixed_bit_flips[index] == 11u
                    || unowned_fixed_bit_flips[index] == 15u
                ? CDISASM_STATUS_INVALID_INSTRUCTION
                : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void test_formatting(void)
{
    static const char suffixes[4] = { 'b', 'h', 's', 'd' };
    unsigned size_code;

    for (size_code = 0u; size_code < 4u; ++size_code) {
        cdisasm_arm_instruction instruction;
        char expected[96];
        char text[96];
        int expected_size;
        unsigned zd = size_code == 3u ? 31u : size_code + 1u;
        unsigned zn = size_code == 3u ? 31u : size_code + 10u;
        unsigned zm = size_code == 3u ? 31u : size_code + 20u;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            tblq_word(size_code, zd, zn, zm),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 4u);
        expected_size = snprintf(
            expected, sizeof(expected),
            "tblq z%u.%c, {z%u.%c}, z%u.%c",
            zd, suffixes[size_code], zn, suffixes[size_code],
            zm, suffixes[size_code]);
        EXPECT(expected_size > 0);
        EXPECT((size_t)expected_size < sizeof(expected));
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == (size_t)expected_size);
        EXPECT(strcmp(text, expected) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            NULL, 0u) == (size_t)expected_size);
    }

    {
        static const char expected[] =
            "TBLQ z31.d, {z31.d}, z31.d";
        cdisasm_arm_instruction instruction;
        char text[96];
        char short_text[6];

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            tblq_word(3u, 31u, 31u, 31u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            short_text, sizeof(short_text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(short_text, "tblq ") == 0);
    }
}
#endif

int main(void)
{
    test_complete_allocated_space();
    test_feature_profiles();
    test_boundaries_endian_and_dispatch();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE2.1 TBLQ test(s) failed\n", failures);
        return 1;
    }
    printf(
        "ARM SVE2.1 TBLQ tests passed "
        "(131072 encodings, USE_EXTRA_OPCODES=%d)\n",
        USE_EXTRA_OPCODES);
    return 0;
}
