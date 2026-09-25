#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_ADDP == UINT16_C(519),
               "predicated pairwise ADDP ID moved");
_Static_assert(CDISASM_ARM_NAME_SMAXP == UINT16_C(1404),
               "predicated pairwise SMAXP ID moved");
_Static_assert(CDISASM_ARM_NAME_SMINP == UINT16_C(1407),
               "predicated pairwise SMINP ID moved");
_Static_assert(CDISASM_ARM_NAME_SUBP == UINT16_C(1692),
               "predicated pairwise SUBP ID moved");
_Static_assert(CDISASM_ARM_NAME_UMAXP == UINT16_C(1765),
               "predicated pairwise UMAXP ID moved");
_Static_assert(CDISASM_ARM_NAME_UMINP == UINT16_C(1768),
               "predicated pairwise UMINP ID moved");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2692),
               "AARCHMRS form inventory no longer covers this family");

typedef struct pairwise_operation {
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    const char *mnemonic;
    int allocated;
} pairwise_operation;

/* Indexed by bits 18:16 of the pinned AARCHMRS 2026-03
 * sve_intx_arith_binary_pairs parent.  LLVM 21 recognizes the five SVE2
 * rows but not FEAT_SVE2p3 or SUBP, so SUBP identity and requirements are
 * intentionally pinned to AARCHMRS rather than weakened to LLVM's view. */
static const pairwise_operation operations[8] = {
    { CDISASM_ARM_NAME_SUBP,  UINT16_C(2687), "subp",  1 },
    { CDISASM_ARM_NAME_ADDP,  UINT16_C(2688), "addp",  1 },
    { CDISASM_ARM_NAME_NONE,  CDISASM_ARM_FORM_NONE, NULL, 0 },
    { CDISASM_ARM_NAME_NONE,  CDISASM_ARM_FORM_NONE, NULL, 0 },
    { CDISASM_ARM_NAME_SMAXP, UINT16_C(2689), "smaxp", 1 },
    { CDISASM_ARM_NAME_UMAXP, UINT16_C(2691), "umaxp", 1 },
    { CDISASM_ARM_NAME_SMINP, UINT16_C(2690), "sminp", 1 },
    { CDISASM_ARM_NAME_UMINP, UINT16_C(2692), "uminp", 1 }
};

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",           \
                    __FILE__, __LINE__, #condition);                        \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static uint32_t pairwise_word(
    unsigned operation,
    unsigned size_code,
    unsigned pg,
    unsigned zm,
    unsigned zdn)
{
    return UINT32_C(0x4410a000)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)operation << 16)
        | ((uint32_t)pg << 10)
        | ((uint32_t)zm << 5)
        | (uint32_t)zdn;
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
    size_t code_size,
    cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x126000),
        options, instruction);
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

static int predicate_operand_matches(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    uint8_t element_size)
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

static void expect_success_metadata(
    const cdisasm_arm_instruction *instruction,
    const pairwise_operation *operation,
    uint32_t word,
    unsigned size_code,
    unsigned pg,
    unsigned zm,
    unsigned zdn)
{
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);

    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == operation->name_id);
    EXPECT(instruction->form_id == operation->form_id);
    EXPECT(instruction->address == UINT64_C(0x126000));
    EXPECT(instruction->raw_instruction == word);
    EXPECT(instruction->opcode_size == 4u);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->isa_id == CDISASM_ARM_ISA_A64);
    EXPECT(instruction->condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction->operand_count == 4u);
    EXPECT(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    EXPECT(z_operand_matches(
        &instruction->operand[0], zdn, element_size,
        CDISASM_OPERAND_ACCESS_READ_WRITE));
    EXPECT(predicate_operand_matches(
        &instruction->operand[1], pg, element_size));
    EXPECT(z_operand_matches(
        &instruction->operand[2], zdn, element_size,
        CDISASM_OPERAND_ACCESS_READ));
    EXPECT(z_operand_matches(
        &instruction->operand[3], zm, element_size,
        CDISASM_OPERAND_ACCESS_READ));
}
#endif

static void test_exhaustive_owned_parent(void)
{
    uint32_t owned_words = 0u;
    uint32_t allocated_words = 0u;
    uint32_t reserved_words = 0u;
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            unsigned pg;

            for (pg = 0u; pg < 8u; ++pg) {
                unsigned zm;

                for (zm = 0u; zm < 32u; ++zm) {
                    unsigned zdn;

                    for (zdn = 0u; zdn < 32u; ++zdn) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = pairwise_word(
                            operation, size_code, pg, zm, zdn);
                        uint32_t decoded;

                        ++owned_words;
                        EXPECT((word & UINT32_C(0xff38e000))
                            == UINT32_C(0x4410a000));
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(
                            word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                        if (!operations[operation].allocated) {
                            ++reserved_words;
                            EXPECT(decoded == 0u);
                            EXPECT(instruction_is_error_only(
                                &instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                            continue;
                        }
                        ++allocated_words;
#if USE_EXTRA_OPCODES
                        EXPECT(decoded == 4u);
                        expect_success_metadata(
                            &instruction, &operations[operation], word,
                            size_code, pg, zm, zdn);
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
    }

    EXPECT(owned_words == UINT32_C(262144));
    EXPECT(allocated_words == UINT32_C(196608));
    EXPECT(reserved_words == UINT32_C(65536));
}

static void expect_cpu_status(
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id,
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
    decoded = decode_word(
        word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(decoded == 4u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(decoded == 0u);
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_feature_and_profile_routes(void)
{
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        uint32_t word;

        if (!operations[operation].allocated) {
            continue;
        }
        word = pairwise_word(operation, 2u, 3u, 13u, 7u);
        expect_cpu_status(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        if (operation == 0u) {
            /* No concrete pinned product profile advertises SVE2p3/SME2p3. */
            expect_cpu_status(
                word, CDISASM_ARM_CPU_APPLE_A18,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_cpu_status(
                word, CDISASM_ARM_CPU_APPLE_M4,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        } else {
            expect_cpu_status(
                word, CDISASM_ARM_CPU_APPLE_A18, CDISASM_STATUS_OK);
            expect_cpu_status(
                word, CDISASM_ARM_CPU_APPLE_M4, CDISASM_STATUS_OK);
        }
        expect_cpu_status(
            word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(
            word, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(
            word, CDISASM_ARM_CPU_APPLE_M3,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void expect_truncated(uint32_t word, cdisasm_arm_cpu_id cpu_id)
{
    unsigned boundary;

    for (boundary = 0u; boundary < 4u; ++boundary) {
        cdisasm_arm_instruction instruction;
        cdisasm_status status = boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            word, cpu_id, CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(&instruction, status));
    }
}

static void test_neighbors_endian_dispatch_and_boundaries(void)
{
    uint32_t word = pairwise_word(7u, 3u, 7u, 31u, 31u);
    uint32_t reserved = pairwise_word(3u, 3u, 7u, 31u, 31u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    uint32_t decoded;

    /* Exact adjacent identities remain delegated to their own parents. */
    memset(&other, 0xa5, sizeof(other));
    decoded = decode_word(
        UINT32_C(0x44d79fff), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(other.form_id == UINT16_C(2686));
#else
    EXPECT(decoded == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    memset(&other, 0xa5, sizeof(other));
    decoded = decode_word(
        UINT32_C(0x44188020), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(other.form_id == UINT16_C(2693));
#else
    EXPECT(decoded == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

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
        bytes, sizeof(bytes), UINT64_C(0x126000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x126000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    /* Length status owns the incomplete word before feature or reserved
     * classification. */
    expect_truncated(word, CDISASM_ARM_CPU_ANY);
    expect_truncated(word, CDISASM_ARM_CPU_FUJITSU_A64FX);
    expect_truncated(reserved, CDISASM_ARM_CPU_ANY);

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_formatter_controls(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const char suffixes[4] = { 'b', 'h', 's', 'd' };
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        unsigned size_code;

        if (!operations[operation].allocated) {
            continue;
        }
        for (size_code = 0u; size_code < 4u; ++size_code) {
            cdisasm_arm_instruction instruction;
            uint32_t word = pairwise_word(
                operation, size_code, 3u, 13u, 7u);
            char expected[112];
            char text[112];
            char tiny[8];
            int expected_length;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
            expected_length = snprintf(
                expected, sizeof(expected),
                "%s z7.%c, p3/m, z7.%c, z13.%c",
                operations[operation].mnemonic, suffixes[size_code],
                suffixes[size_code], suffixes[size_code]);
            EXPECT(expected_length > 0);
            EXPECT((size_t)expected_length < sizeof(expected));
            EXPECT(cdisasm_arm_format(
                &instruction, CDISASM_FORMAT_SYNTAX_7,
                text, sizeof(text)) == (size_t)expected_length);
            EXPECT(strcmp(text, expected) == 0);
            EXPECT(cdisasm_arm_format(
                &instruction, CDISASM_FORMAT_SYNTAX_0,
                NULL, 0u) == (size_t)expected_length);
            memset(tiny, 0xa5, sizeof(tiny));
            EXPECT(cdisasm_arm_format(
                &instruction, CDISASM_FORMAT_SYNTAX_0,
                tiny, sizeof(tiny)) == (size_t)expected_length);
            EXPECT(tiny[sizeof(tiny) - 1u] == '\0');
        }
    }

    {
        cdisasm_arm_instruction instruction;
        cdisasm_arm_instruction forged;
        char text[112];
        static const char expected[] =
            "UMINP z31.d, p7/m, z31.d, z31.d";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            pairwise_word(7u, 3u, 7u, 31u, 31u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);

        forged = instruction;
        forged.form_id = UINT16_C(2691);
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.name_id = CDISASM_ARM_NAME_UMAXP;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.raw_instruction = pairwise_word(
            6u, 3u, 7u, 31u, 31u);
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand_count = 3u;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[1].flags =
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[2].reg = CDISASM_ARM_REG_Z30;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[3].reg = CDISASM_ARM_REG_Z30;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
        forged = instruction;
        forged.operand[3].extend_type = 4u;
        EXPECT(cdisasm_arm_format(
            &forged, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == 0u);
    }
#endif
}

int main(void)
{
    test_exhaustive_owned_parent();
    test_feature_and_profile_routes();
    test_neighbors_endian_dispatch_and_boundaries();
    test_formatter_controls();

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM SVE predicated pairwise-arithmetic test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE predicated pairwise-arithmetic tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=262144, allocated=196608, "
           "reserved=65536)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
