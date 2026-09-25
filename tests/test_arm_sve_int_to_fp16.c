#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_FRSQRTE == UINT16_C(430),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_SCVTF == UINT16_C(431),
               "SCVTF must be appended to the ARM catalog");
_Static_assert(CDISASM_ARM_NAME_UCVTF == UINT16_C(432),
               "UCVTF must follow SCVTF");
_Static_assert(CDISASM_ARM_NAME_FCVT == UINT16_C(433),
               "append-only FCVT ID moved");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 24) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",      \
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

static uint32_t conversion_word(
    unsigned selector, unsigned pg, unsigned zn, unsigned zd)
{
    return UINT32_C(0x6550a000)
        | ((uint32_t)selector << 16)
        | ((uint32_t)pg << 10)
        | ((uint32_t)zn << 5)
        | (uint32_t)zd;
}

#if USE_EXTRA_OPCODES
static const cdisasm_arm_form_id conversion_form_ids[8] = {
    0u, 0u, UINT16_C(3132), UINT16_C(3139),
    UINT16_C(3133), UINT16_C(3140), UINT16_C(3134), UINT16_C(3141)
};

static uint8_t source_element_size(unsigned selector)
{
    return (uint8_t)(selector < 4u ? 2u : selector < 6u ? 4u : 8u);
}
#endif

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
        UINT64_C(0x124000), options, instruction);
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
static void build_expected_instruction(
    uint32_t word, unsigned selector, unsigned pg, unsigned zn, unsigned zd,
    cdisasm_arm_instruction *expected)
{
    uint8_t source_size = source_element_size(selector);

    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x124000);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
        | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
    expected->name_id = (selector & 1u) != 0u
        ? CDISASM_ARM_NAME_UCVTF : CDISASM_ARM_NAME_SCVTF;
    expected->operand_count = 3u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->form_id = conversion_form_ids[selector];

    expected->operand[0].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[0].reg =
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd);
    expected->operand[0].extend_type = (cdisasm_arm_extend_type)2u;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;

    expected->operand[1].type = CDISASM_ARM_OPERAND_PREDICATE;
    expected->operand[1].reg =
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg);
    expected->operand[1].flags =
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE;
    expected->operand[1].extend_type =
        (cdisasm_arm_extend_type)source_size;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;

    expected->operand[2].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[2].reg =
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn);
    expected->operand[2].extend_type =
        (cdisasm_arm_extend_type)source_size;
    expected->operand[2].access = CDISASM_OPERAND_ACCESS_READ;
}
#endif

static void test_exhaustive_exact_domain(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned selector;

    for (selector = 0u; selector < 8u; ++selector) {
        unsigned pg;

        for (pg = 0u; pg < 8u; ++pg) {
            unsigned zn;

            for (zn = 0u; zn < 32u; ++zn) {
                unsigned zd;

                for (zd = 0u; zd < 32u; ++zd) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = conversion_word(selector, pg, zn, zd);
                    uint32_t decoded;

                    domain_expect(
                        (word & UINT32_C(0xfff8e000))
                            == UINT32_C(0x6550a000),
                        word, "word escaped exact classifier");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    if (selector < 2u) {
                        ++reserved;
                        domain_expect(decoded == 0u, word,
                            "reserved selector decoded");
                        domain_expect(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION),
                            word, "reserved selector status mismatch");
                    } else {
                        ++allocated;
#if USE_EXTRA_OPCODES
                        cdisasm_arm_instruction expected;

                        build_expected_instruction(
                            word, selector, pg, zn, zd, &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated conversion did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected, sizeof(expected)) == 0,
                            word, "allocated conversion metadata mismatch");
#else
                        domain_expect(decoded == 0u, word,
                            "extras-OFF build decoded conversion");
                        domain_expect(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                            word, "extras-OFF ownership status mismatch");
#endif
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(49152));
    EXPECT(reserved == UINT32_C(16384));
    EXPECT(allocated + reserved == UINT32_C(65536));
}

static void expect_cpu_status(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_status enabled_status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_status expected_status;
    uint32_t decoded;

#if USE_EXTRA_OPCODES
    expected_status = enabled_status;
#else
    (void)enabled_status;
    expected_status = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(
        word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == (expected_status == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected_status == CDISASM_STATUS_OK) {
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected_status));
    }
}

static void test_capability_routes(void)
{
    unsigned selector;

    for (selector = 2u; selector < 8u; ++selector) {
        uint32_t word = conversion_word(selector, 3u, 13u, 7u);

        expect_cpu_status(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);
        /* These independently exercise the SME-only side of SVE || SME. */
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_cpu_status(word, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(word, CDISASM_ARM_CPU_APPLE_M3,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_named_cpu_profile_boundary(void)
{
    const uint32_t word = conversion_word(4u, 3u, 13u, 7u);
    uint32_t cpu_value;

    for (cpu_value = CDISASM_ARM_CPU_FIRST;
         cpu_value <= CDISASM_ARM_CPU_LAST;
         ++cpu_value) {
        cdisasm_arm_cpu_id cpu_id = (cdisasm_arm_cpu_id)cpu_value;
        cdisasm_arm_instruction instruction;
        cdisasm_status expected_status;
        uint32_t decoded;

        if ((cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) == 0u) {
            expected_status = CDISASM_STATUS_INVALID_ARGUMENT;
#if USE_EXTRA_OPCODES
        } else if (cpu_id == CDISASM_ARM_CPU_APPLE_A18
            || cpu_id == CDISASM_ARM_CPU_APPLE_M4
            || cpu_id == CDISASM_ARM_CPU_FUJITSU_A64FX) {
            expected_status = CDISASM_STATUS_OK;
        } else {
            expected_status = CDISASM_STATUS_INVALID_INSTRUCTION;
#else
        } else {
            expected_status = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
        }

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(
            word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(decoded == (expected_status == CDISASM_STATUS_OK ? 4u : 0u));
        if (expected_status == CDISASM_STATUS_OK) {
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        } else {
            EXPECT(instruction_is_error_only(
                &instruction, expected_status));
        }
    }
}

static void test_fixed_bit_neighbors(void)
{
    const uint32_t fixed_mask = UINT32_C(0xfff8e000);
    const uint32_t canonical = conversion_word(6u, 3u, 13u, 7u);
    unsigned bit;

    for (bit = 0u; bit < 32u; ++bit) {
        cdisasm_arm_instruction instruction;
        uint32_t neighbor;
        uint32_t decoded;
        int same_conversion;

        if ((fixed_mask & (UINT32_C(1) << bit)) == 0u) {
            continue;
        }
        neighbor = canonical ^ (UINT32_C(1) << bit);
        /* Bit 23 reaches the separately tested D-to-D conversion envelope
         * added after this exact FP16 classifier. */
        if ((neighbor & UINT32_C(0xfffee000))
            == UINT32_C(0x65d6a000)) {
            continue;
        }
        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(
            neighbor, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        same_conversion = decoded == 4u
            && (instruction.name_id == CDISASM_ARM_NAME_SCVTF
                || instruction.name_id == CDISASM_ARM_NAME_UCVTF)
            && (instruction.instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u;
        EXPECT(!same_conversion);
    }
}

static void test_endian_dispatch_modes_and_boundaries(void)
{
    const uint32_t word = conversion_word(7u, 7u, 31u, 31u);
    const uint32_t reserved = conversion_word(1u, 7u, 31u, 31u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    size_t code_size;
    uint32_t decoded;

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
        bytes, sizeof(bytes), UINT64_C(0x124000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x124000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_decode_checked(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x124000),
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
        EXPECT(instruction_is_error_only(&other, CDISASM_STATUS_TRUNCATED));

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(
            reserved, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            code_size, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, CDISASM_STATUS_TRUNCATED));
    }

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(&other, CDISASM_STATUS_END_OF_INPUT));

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

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[96];
    char short_text[5];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7,
        NULL, 0u) == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_0,
        short_text, sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void test_formatter(void)
{
    static const char *const expected[6] = {
        "scvtf z7.h, p3/m, z13.h",
        "ucvtf z7.h, p3/m, z13.h",
        "scvtf z7.h, p3/m, z13.s",
        "ucvtf z7.h, p3/m, z13.s",
        "scvtf z7.h, p3/m, z13.d",
        "ucvtf z7.h, p3/m, z13.d"
    };
    unsigned selector;

    for (selector = 2u; selector < 8u; ++selector) {
        expect_format(
            conversion_word(selector, 3u, 13u, 7u),
            expected[selector - 2u]);
    }

    {
        cdisasm_arm_instruction instruction;
        char text[96];
        static const char expected_upper[] =
            "UCVTF z31.h, p7/m, z31.d";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            conversion_word(7u, 7u, 31u, 31u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected_upper) - 1u);
        EXPECT(strcmp(text, expected_upper) == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_exact_domain();
    test_capability_routes();
    test_named_cpu_profile_boundary();
    test_fixed_bit_neighbors();
    test_endian_dispatch_modes_and_boundaries();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE integer-to-FP16 test(s) failed\n",
            failures);
        return 1;
    }
    printf("ARM SVE integer-to-FP16 tests passed "
           "(USE_EXTRA_OPCODES=%d, owned=65536, allocated=49152, "
           "reserved=16384)\n", USE_EXTRA_OPCODES);
    return 0;
}
