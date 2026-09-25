#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_FACGT == UINT16_C(405),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_FSUBR == UINT16_C(406),
               "predicated FP binary IDs must be append-only");
_Static_assert(CDISASM_ARM_NAME_FMAXNM == UINT16_C(407),
               "predicated FP binary ID order changed");
_Static_assert(CDISASM_ARM_NAME_FMINNM == UINT16_C(408),
               "predicated FP binary ID order changed");
_Static_assert(CDISASM_ARM_NAME_FMAX == UINT16_C(409),
               "predicated FP binary ID order changed");
_Static_assert(CDISASM_ARM_NAME_FMIN == UINT16_C(410),
               "predicated FP binary ID order changed");
_Static_assert(CDISASM_ARM_NAME_FABD == UINT16_C(411),
               "predicated FP binary ID order changed");
_Static_assert(CDISASM_ARM_NAME_FSCALE == UINT16_C(412),
               "predicated FP binary ID order changed");
_Static_assert(CDISASM_ARM_NAME_FMULX == UINT16_C(413),
               "predicated FP binary ID order changed");
_Static_assert(CDISASM_ARM_NAME_FDIVR == UINT16_C(414),
               "predicated FP binary terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(421),
               "predicated FP binary name count changed");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");
_Static_assert(CDISASM_ARM_NAME_BFADD == UINT16_C(572),
               "generated BFADD ID moved");
_Static_assert(CDISASM_ARM_NAME_BFMAX == UINT16_C(577),
               "generated BFMAX ID moved");
_Static_assert(CDISASM_ARM_NAME_BFMAXNM == UINT16_C(578),
               "generated BFMAXNM ID moved");
_Static_assert(CDISASM_ARM_NAME_BFMIN == UINT16_C(579),
               "generated BFMIN ID moved");
_Static_assert(CDISASM_ARM_NAME_BFMINNM == UINT16_C(580),
               "generated BFMINNM ID moved");
_Static_assert(CDISASM_ARM_NAME_BFMUL == UINT16_C(594),
               "generated BFMUL ID moved");
_Static_assert(CDISASM_ARM_NAME_BFSUB == UINT16_C(596),
               "generated BFSUB ID moved");

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 20) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",      \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

#if USE_EXTRA_OPCODES
static const cdisasm_arm_name_id names[14] = {
    CDISASM_ARM_NAME_FADD,
    CDISASM_ARM_NAME_FSUB,
    CDISASM_ARM_NAME_FMUL,
    CDISASM_ARM_NAME_FSUBR,
    CDISASM_ARM_NAME_FMAXNM,
    CDISASM_ARM_NAME_FMINNM,
    CDISASM_ARM_NAME_FMAX,
    CDISASM_ARM_NAME_FMIN,
    CDISASM_ARM_NAME_FABD,
    CDISASM_ARM_NAME_FSCALE,
    CDISASM_ARM_NAME_FMULX,
    CDISASM_ARM_NAME_NONE,
    CDISASM_ARM_NAME_FDIVR,
    CDISASM_ARM_NAME_FDIV
};
#endif

typedef struct bfloat_binary_form {
    uint8_t operation;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
} bfloat_binary_form;

static const bfloat_binary_form bfloat_binary_forms[7] = {
    { 0u, CDISASM_ARM_NAME_BFADD, UINT16_C(3076), "bfadd" },
    { 1u, CDISASM_ARM_NAME_BFSUB, UINT16_C(3078), "bfsub" },
    { 2u, CDISASM_ARM_NAME_BFMUL, UINT16_C(3080), "bfmul" },
    { 4u, CDISASM_ARM_NAME_BFMAXNM, UINT16_C(3083), "bfmaxnm" },
    { 5u, CDISASM_ARM_NAME_BFMINNM, UINT16_C(3085), "bfminnm" },
    { 6u, CDISASM_ARM_NAME_BFMAX, UINT16_C(3087), "bfmax" },
    { 7u, CDISASM_ARM_NAME_BFMIN, UINT16_C(3089), "bfmin" }
};

static const bfloat_binary_form *bfloat_form_for_operation(
    unsigned operation)
{
    size_t index;

    for (index = 0u;
         index < sizeof(bfloat_binary_forms)
            / sizeof(bfloat_binary_forms[0]);
         ++index) {
        if (bfloat_binary_forms[index].operation == operation) {
            return &bfloat_binary_forms[index];
        }
    }
    return NULL;
}

static uint32_t binary_word(unsigned operation, unsigned size_code,
                            unsigned zm, unsigned pg, unsigned zd)
{
    return UINT32_C(0x65008000)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)operation << 16)
        | ((uint32_t)pg << 10)
        | ((uint32_t)zm << 5)
        | (uint32_t)zd;
}

static int word_is_in_exact_union(uint32_t word)
{
    static const uint32_t masks[6] = {
        UINT32_C(0xfff8e000), UINT32_C(0xffb8e000),
        UINT32_C(0xfffce000), UINT32_C(0xffbce000),
        UINT32_C(0xfffee000), UINT32_C(0xffbee000)
    };
    static const uint32_t values[6] = {
        UINT32_C(0x65408000), UINT32_C(0x65808000),
        UINT32_C(0x65488000), UINT32_C(0x65888000),
        UINT32_C(0x654c8000), UINT32_C(0x658c8000)
    };
    unsigned index;

    for (index = 0u; index < 6u; ++index) {
        if ((word & masks[index]) == values[index]) {
            return 1;
        }
    }
    return 0;
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
        UINT64_C(0x114000), options, instruction);
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
static int zreg_matches(const cdisasm_arm_operand *operand,
                        unsigned encoded, uint8_t element_size,
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

static int predicate_matches(const cdisasm_arm_operand *operand,
                             unsigned encoded, uint8_t element_size)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_PREDICATE;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.flags = CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            uint32_t word, unsigned operation,
                            unsigned size_code, unsigned zm,
                            unsigned pg, unsigned zd)
{
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    return instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == names[operation]
        && instruction->address == UINT64_C(0x114000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 4u
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        && zreg_matches(&instruction->operand[0], zd, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && predicate_matches(&instruction->operand[1], pg, element_size)
        && zreg_matches(&instruction->operand[2], zd, element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && zreg_matches(&instruction->operand[3], zm, element_size,
            CDISASM_OPERAND_ACCESS_READ);
}

static int bfloat_metadata_matches(
    const cdisasm_arm_instruction *instruction, uint32_t word,
    const bfloat_binary_form *form, unsigned zm, unsigned pg, unsigned zd)
{
    return form != NULL
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->name_id == form->name_id
        && instruction->form_id == form->form_id
        && instruction->address == UINT64_C(0x114000)
        && instruction->raw_instruction == word
        && instruction->opcode_size == 4u
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->operand_count == 4u
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        && zreg_matches(&instruction->operand[0], zd, 2u,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && predicate_matches(&instruction->operand[1], pg, 2u)
        && zreg_matches(&instruction->operand[2], zd, 2u,
            CDISASM_OPERAND_ACCESS_READ)
        && zreg_matches(&instruction->operand[3], zm, 2u,
            CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void test_exhaustive_exact_union(void)
{
    uint32_t allocated_words = 0u;
    uint32_t reserved_words = 0u;
    unsigned operation;

    for (operation = 0u; operation <= 13u; ++operation) {
        unsigned size_code;

        for (size_code = 1u; size_code <= 3u; ++size_code) {
            unsigned zm;

            for (zm = 0u; zm < 32u; ++zm) {
                unsigned pg;

                for (pg = 0u; pg < 8u; ++pg) {
                    unsigned zd;

                    for (zd = 0u; zd < 32u; ++zd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = binary_word(
                            operation, size_code, zm, pg, zd);
                        uint32_t decoded;

                        EXPECT(word_is_in_exact_union(word));
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                        if (operation == 11u) {
                            ++reserved_words;
                            EXPECT(decoded == 0u);
                            EXPECT(instruction_is_error_only(&instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                        } else {
                            ++allocated_words;
#if USE_EXTRA_OPCODES
                            EXPECT(decoded == 4u);
                            EXPECT(metadata_matches(&instruction, word,
                                operation, size_code, zm, pg, zd));
#else
                            EXPECT(decoded == 0u);
                            EXPECT(instruction_is_error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        }
                    }
                }
            }
        }
    }
    EXPECT(allocated_words == UINT32_C(319488));
    EXPECT(reserved_words == UINT32_C(24576));
    EXPECT(allocated_words + reserved_words == UINT32_C(344064));
}

static void test_exhaustive_bfloat_binary_family(void)
{
    uint32_t allocated_words = 0u;
    uint32_t reserved_words = 0u;
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        unsigned zm;

        for (zm = 0u; zm < 32u; ++zm) {
            unsigned pg;

            for (pg = 0u; pg < 8u; ++pg) {
                unsigned zd;

                for (zd = 0u; zd < 32u; ++zd) {
                    const bfloat_binary_form *form =
                        bfloat_form_for_operation(operation);
                    cdisasm_arm_instruction instruction;
                    uint32_t word = binary_word(
                        operation, 0u, zm, pg, zd);
                    uint32_t decoded;

                    EXPECT((word & UINT32_C(0xffffe000))
                        == (UINT32_C(0x65008000)
                            | ((uint32_t)operation << 16)));
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY,
                        CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    if (form == NULL) {
                        ++reserved_words;
                        EXPECT(operation == 3u);
                        EXPECT(decoded == 0u);
                        EXPECT(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                        continue;
                    }
                    ++allocated_words;
#if USE_EXTRA_OPCODES
                    EXPECT(decoded == 4u);
                    EXPECT(bfloat_metadata_matches(
                        &instruction, word, form, zm, pg, zd));
#else
                    EXPECT(decoded == 0u);
                    EXPECT(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                }
            }
        }
    }

    EXPECT(allocated_words == UINT32_C(57344));
    EXPECT(reserved_words == UINT32_C(8192));
    EXPECT(allocated_words + reserved_words == UINT32_C(65536));
}

static void expect_cpu_status(uint32_t word, cdisasm_arm_cpu_id cpu_id,
                              cdisasm_status enabled_status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_status expected;
    uint32_t decoded;

#if USE_EXTRA_OPCODES
    expected = enabled_status;
#else
    expected = enabled_status == CDISASM_STATUS_INVALID_ARGUMENT
        ? CDISASM_STATUS_INVALID_ARGUMENT
        : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
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

#if !USE_EXTRA_OPCODES
static void expect_currently_unowned(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    EXPECT(!word_is_in_exact_union(word));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
}
#endif

#if USE_EXTRA_OPCODES
static void expect_faminmax_neighbor(
    uint32_t word, cdisasm_arm_name_id name_id,
    cdisasm_arm_form_id form_id)
{
    cdisasm_arm_instruction instruction;
    unsigned size_code = (word >> 22) & 3u;
    unsigned zm = (word >> 5) & 31u;
    unsigned pg = (word >> 10) & 7u;
    unsigned zd = word & 31u;
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    EXPECT(!word_is_in_exact_union(word));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == name_id);
    EXPECT(instruction.form_id == form_id);
    EXPECT(instruction.operand_count == 4u);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    EXPECT(zreg_matches(&instruction.operand[0], zd, element_size,
        CDISASM_OPERAND_ACCESS_READ_WRITE));
    EXPECT(predicate_matches(&instruction.operand[1], pg, element_size));
    EXPECT(zreg_matches(&instruction.operand[2], zd, element_size,
        CDISASM_OPERAND_ACCESS_READ));
    EXPECT(zreg_matches(&instruction.operand[3], zm, element_size,
        CDISASM_OPERAND_ACCESS_READ));
}
#endif

static void test_features_endian_and_boundaries(void)
{
    uint32_t word = binary_word(12u, 3u, 13u, 3u, 12u);
    uint32_t reserved = binary_word(11u, 2u, 13u, 3u, 12u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t bytes[4];
    unsigned operation;
    unsigned boundary;

    for (operation = 0u; operation <= 13u; ++operation) {
        unsigned size_code;

        if (operation == 11u) {
            continue;
        }
        for (size_code = 1u; size_code <= 3u; ++size_code) {
            uint32_t candidate = binary_word(
                operation, size_code, 13u, 3u, 12u);

            expect_cpu_status(
                candidate, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
            expect_cpu_status(candidate, CDISASM_ARM_CPU_FUJITSU_A64FX,
                CDISASM_STATUS_OK);
            expect_cpu_status(candidate, CDISASM_ARM_CPU_APPLE_M4,
                CDISASM_STATUS_OK);
            expect_cpu_status(candidate, CDISASM_ARM_CPU_CORTEX_A53,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_cpu_status(candidate, CDISASM_ARM_CPU_APPLE_M3,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    /* The op14/15 FEAT_FAMINMAX maps are independently featured. */
#if USE_EXTRA_OPCODES
    expect_faminmax_neighbor(
        binary_word(14u, 1u, 1u, 0u, 0u),
        CDISASM_ARM_NAME_FAMAX, UINT16_C(3096));
    expect_faminmax_neighbor(
        binary_word(15u, 3u, 1u, 0u, 0u),
        CDISASM_ARM_NAME_FAMIN, UINT16_C(3097));
#else
    expect_currently_unowned(binary_word(14u, 1u, 1u, 0u, 0u));
    expect_currently_unowned(binary_word(15u, 3u, 1u, 0u, 0u));
#endif

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
    word_to_be(word, bytes);
    memset(&big, 0xa5, sizeof(big));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x114000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x114000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big) == 0u);
#endif
    EXPECT(memcmp(&big, &little, sizeof(big)) == 0);

    word_to_le(word, bytes);
    memset(&generic, 0xa5, sizeof(generic));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x114000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x114000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
#endif
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);

    for (boundary = 1u; boundary < 4u; ++boundary) {
        memset(&big, 0xa5, sizeof(big));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &big) == 0u);
        EXPECT(instruction_is_error_only(&big, CDISASM_STATUS_TRUNCATED));
        memset(&big, 0xa5, sizeof(big));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &big) == 0u);
        EXPECT(instruction_is_error_only(&big, CDISASM_STATUS_TRUNCATED));
    }

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_bfloat_feature_gates_neighbors_and_dispatch(void)
{
    const uint32_t fixed_mask = UINT32_C(0xffffe000);
    const uint32_t word = binary_word(0u, 0u, 13u, 3u, 12u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    uint32_t decoded;
    uint32_t cpu_value;
    size_t index;
    size_t code_size;

    for (index = 0u;
         index < sizeof(bfloat_binary_forms)
            / sizeof(bfloat_binary_forms[0]);
         ++index) {
        const bfloat_binary_form *form = &bfloat_binary_forms[index];
        uint32_t canonical = binary_word(
            form->operation, 0u, 13u, 3u, 12u);
        unsigned bit;

        expect_cpu_status(
            canonical, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        for (bit = 0u; bit < 32u; ++bit) {
            if ((fixed_mask & (UINT32_C(1) << bit)) != 0u) {
                memset(&other, 0xa5, sizeof(other));
                decoded = decode_word(
                    canonical ^ (UINT32_C(1) << bit),
                    CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                    CDISASM_ARM_DECODE_OPTION_NONE, &other);
                EXPECT(decoded != 4u || other.form_id != form->form_id);
            }
        }
    }

    /* Generated feature 141 is intentionally absent from every named CPU
     * profile.  CPU_ANY remains the unrestricted analysis route above. */
    for (cpu_value = CDISASM_ARM_CPU_FIRST;
         cpu_value <= CDISASM_ARM_CPU_LAST;
         ++cpu_value) {
        cdisasm_arm_cpu_id cpu_id = (cdisasm_arm_cpu_id)cpu_value;
        cdisasm_status status =
            (cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) != 0u
                ? CDISASM_STATUS_INVALID_INSTRUCTION
                : CDISASM_STATUS_INVALID_ARGUMENT;

        expect_cpu_status(word, cpu_id, status);
    }

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x114000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_decode_checked(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x114000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    for (code_size = 1u; code_size < 4u; ++code_size) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, code_size,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(
            &other, CDISASM_STATUS_TRUNCATED));
    }

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_END_OF_INPUT));

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        binary_word(3u, 0u, 13u, 3u, 12u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_INSTRUCTION));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static const char *const mnemonics[14] = {
    "fadd", "fsub", "fmul", "fsubr", "fmaxnm", "fminnm", "fmax",
    "fmin", "fabd", "fscale", "fmulx", NULL, "fdivr", "fdiv"
};

static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[96];
    char short_text[8];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
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

static void test_formatter(void)
{
    static const char suffixes[] = { 'h', 's', 'd' };
    unsigned operation;

    for (operation = 0u; operation <= 13u; ++operation) {
        unsigned size_index;

        if (operation == 11u) {
            continue;
        }
        for (size_index = 0u; size_index < 3u; ++size_index) {
            char expected[96];
            int expected_length = snprintf(expected, sizeof(expected),
                "%s z12.%c, p3/m, z12.%c, z13.%c",
                mnemonics[operation], suffixes[size_index],
                suffixes[size_index], suffixes[size_index]);

            EXPECT(expected_length > 0);
            EXPECT((size_t)expected_length < sizeof(expected));
            expect_format(binary_word(operation, size_index + 1u,
                13u, 3u, 12u), expected);
        }
    }

    {
        size_t index;

        for (index = 0u;
             index < sizeof(bfloat_binary_forms)
                / sizeof(bfloat_binary_forms[0]);
             ++index) {
            const bfloat_binary_form *form = &bfloat_binary_forms[index];
            char expected[96];
            int expected_length = snprintf(expected, sizeof(expected),
                "%s z12.h, p3/m, z12.h, z13.h", form->mnemonic);

            EXPECT(expected_length > 0);
            EXPECT((size_t)expected_length < sizeof(expected));
            expect_format(binary_word(
                form->operation, 0u, 13u, 3u, 12u), expected);
        }
    }

    /* These encodings are destructive.  MOVPRFX compatibility does not
     * change canonical disassembly into a source-swapped alias. */
    expect_format(binary_word(3u, 2u, 13u, 3u, 12u),
        "fsubr z12.s, p3/m, z12.s, z13.s");

    {
        cdisasm_arm_instruction instruction;
        char text[96];
        uint32_t word = binary_word(12u, 3u, 13u, 3u, 12u);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text))
            == sizeof("FDIVR z12.d, p3/m, z12.d, z13.d") - 1u);
        EXPECT(strcmp(text, "FDIVR z12.d, p3/m, z12.d, z13.d") == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_exact_union();
    test_exhaustive_bfloat_binary_family();
    test_features_endian_and_boundaries();
    test_bfloat_feature_gates_neighbors_and_dispatch();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif

    if (failures != 0) {
        fprintf(stderr,
            "%d ARM SVE predicated FP binary test(s) failed\n", failures);
        return 1;
    }
    printf("ARM SVE predicated FP binary tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=409600, allocated=376832, "
           "reserved=32768)\n", USE_EXTRA_OPCODES);
    return 0;
}
