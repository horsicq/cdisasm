#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define ZA_MASK UINT32_C(0xffff9c10)

typedef struct za_descriptor {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    cdisasm_operand_access tile_access;
    cdisasm_operand_access memory_access;
    const char *mnemonic;
} za_descriptor;

/* Pinned AARCHMRS ldr_za_ri_ and str_za_ri_ leaves. */
static const za_descriptor descriptors[] = {
    { UINT32_C(0xe1000000), CDISASM_ARM_NAME_LDR, UINT16_C(4381),
      CDISASM_OPERAND_ACCESS_WRITE, CDISASM_OPERAND_ACCESS_READ, "ldr" },
    { UINT32_C(0xe1200000), CDISASM_ARM_NAME_STR, UINT16_C(4382),
      CDISASM_OPERAND_ACCESS_READ, CDISASM_OPERAND_ACCESS_WRITE, "str" }
};

_Static_assert(CDISASM_ARM_NAME_LDR == UINT16_C(25),
               "established LDR ID changed");
_Static_assert(CDISASM_ARM_NAME_STR == UINT16_C(47),
               "established STR ID changed");
_Static_assert(CDISASM_ARM_REG_ZA == UINT16_C(341),
               "generated ZA register ID changed");
_Static_assert(CDISASM_ARM_OPERAND_TILE == UINT8_C(9),
               "tile operand ABI changed");
_Static_assert(CDISASM_ARM_OPERAND_FLAG_VL_SCALED == UINT8_C(64),
               "VL-scaled operand flag ABI changed");

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

static void domain_expect(int condition, uint32_t word, const char *message)
{
    if (!condition) {
        if (failures < 24) {
            fprintf(stderr, "word %08x: %s\n", (unsigned)word, message);
        }
        ++failures;
    }
}

static uint32_t za_word(
    const za_descriptor *descriptor, unsigned rv, unsigned rn, unsigned off4)
{
    return descriptor->value | ((uint32_t)rv << 13)
        | ((uint32_t)rn << 5) | (uint32_t)off4;
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
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x131000),
        options, instruction);
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
static cdisasm_arm_reg_id expected_base(unsigned rn)
{
    return rn == 31u
        ? CDISASM_ARM_REG_SP
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn);
}

static void expected_instruction(
    uint32_t word, const za_descriptor *descriptor,
    cdisasm_arm_instruction *expected)
{
    unsigned rv = (word >> 13) & 3u;
    unsigned rn = (word >> 5) & 31u;
    unsigned off4 = word & 15u;

    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x131000);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = descriptor->name_id;
    expected->form_id = descriptor->form_id;
    expected->operand_count = 2u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SME
        | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
        | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;

    expected->operand[0].type = CDISASM_ARM_OPERAND_TILE;
    expected->operand[0].reg = CDISASM_ARM_REG_ZA;
    expected->operand[0].base_reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_W12 + rv);
    expected->operand[0].imm = off4;
    expected->operand[0].access = descriptor->tile_access;

    expected->operand[1].type = CDISASM_OPERAND_MEMORY;
    expected->operand[1].base_reg = expected_base(rn);
    expected->operand[1].imm = off4;
    expected->operand[1].access = descriptor->memory_access;
    if (off4 != 0u) {
        expected->operand[1].flags =
            CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_ARM_OPERAND_FLAG_VL_SCALED;
    }
}
#endif

static void test_exhaustive_allocated_leaves(void)
{
    uint32_t allocated = 0u;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const za_descriptor *descriptor = &descriptors[descriptor_index];
        unsigned rv;

        for (rv = 0u; rv < 4u; ++rv) {
            unsigned rn;

            for (rn = 0u; rn < 32u; ++rn) {
                unsigned off4;

                for (off4 = 0u; off4 < 16u; ++off4) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = za_word(descriptor, rv, rn, off4);
                    uint32_t decoded;

                    ++allocated;
                    domain_expect((word & ZA_MASK) == descriptor->value,
                        word, "allocated word escaped exact ZA leaf");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        expected_instruction(word, descriptor, &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated ZA transfer did not decode");
                        domain_expect(memcmp(&instruction, &expected,
                            sizeof(expected)) == 0, word,
                            "ZA transfer metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF decoded allocated ZA transfer");
                    domain_expect(instruction_is_error_only(
                        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF ZA ownership mismatch");
#endif
                }
            }
        }
    }
    EXPECT(allocated == UINT32_C(4096));
}

static void test_fixed_neighbors(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const za_descriptor *descriptor = &descriptors[descriptor_index];
        uint32_t word = za_word(descriptor, 2u, 17u, 9u);
        unsigned bit;

        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((ZA_MASK & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                word ^ (UINT32_C(1) << bit), CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
            EXPECT(decoded != 4u
                || instruction.form_id != descriptor->form_id);
#else
            (void)decoded;
#endif
        }
    }
}

static void expect_cpu_status(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_status enabled_status)
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
    EXPECT(decoded == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_cpu_profiles(void)
{
    uint32_t load = za_word(&descriptors[0], 0u, 2u, 0u);
    uint32_t store = za_word(&descriptors[1], 3u, 31u, 15u);
    cdisasm_arm_cpu_id cpu_id;

    expect_cpu_status(load, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_cpu_status(store, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    for (cpu_id = CDISASM_ARM_CPU_FIRST;
         cpu_id <= CDISASM_ARM_CPU_LAST; ++cpu_id) {
        cdisasm_status expected;

        if ((cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) == 0u) {
            continue;
        }
        expected = cpu_id == CDISASM_ARM_CPU_APPLE_A18
                || cpu_id == CDISASM_ARM_CPU_APPLE_M4
            ? CDISASM_STATUS_OK : CDISASM_STATUS_INVALID_INSTRUCTION;
        expect_cpu_status(load, cpu_id, expected);
        expect_cpu_status(store, cpu_id, expected);
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
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, bytes, sizeof(bytes),
        UINT64_C(0x131000), CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
        &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, bytes, sizeof(bytes),
        UINT64_C(0x131000), CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
        &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, bytes, sizeof(bytes),
        UINT64_C(0x131000), CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, bytes, sizeof(bytes),
        UINT64_C(0x131000), CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    for (boundary = 0u; boundary < 4u; ++boundary) {
        cdisasm_status expected = boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, expected));
    }
}

static void test_transport_and_modes(void)
{
    cdisasm_arm_instruction instruction;

    check_transport(za_word(&descriptors[0], 0u, 0u, 0u));
    check_transport(za_word(&descriptors[1], 3u, 31u, 15u));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(za_word(&descriptors[0], 1u, 2u, 4u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(za_word(&descriptors[1], 1u, 2u, 4u),
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
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_7,
        NULL, 0u) == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
        short_text, sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void test_formatting(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const za_descriptor *descriptor = &descriptors[descriptor_index];
        unsigned rv;

        for (rv = 0u; rv < 4u; ++rv) {
            unsigned rn;

            for (rn = 0u; rn < 32u; ++rn) {
                unsigned off4;

                for (off4 = 0u; off4 < 16u; ++off4) {
                    char expected[96];
                    char base[8];
                    int length;

                    if (rn == 31u) {
                        memcpy(base, "sp", 3u);
                    } else {
                        (void)snprintf(base, sizeof(base), "x%u", rn);
                    }
                    if (off4 == 0u) {
                        length = snprintf(expected, sizeof(expected),
                            "%s za[w%u, 0], [%s]", descriptor->mnemonic,
                            12u + rv, base);
                    } else {
                        length = snprintf(expected, sizeof(expected),
                            "%s za[w%u, %u], [%s, #0x%x, mul vl]",
                            descriptor->mnemonic, 12u + rv, off4,
                            base, off4);
                    }
                    EXPECT(length > 0 && (size_t)length < sizeof(expected));
                    expect_format(
                        za_word(descriptor, rv, rn, off4), expected);
                }
            }
        }
    }
    {
        cdisasm_arm_instruction instruction;
        char text[96];
        static const char expected[] =
            "LDR za[w15, 9], [sp, #0x9, mul vl]";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(za_word(&descriptors[0], 3u, 31u, 9u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
    }
}

static void expect_invalid_format(cdisasm_arm_instruction *instruction)
{
    char text[96];

    memset(text, 0xa5, sizeof(text));
    EXPECT(cdisasm_arm_format(instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == 0u);
    EXPECT(text[0] == '\0');
}

static void test_formatter_rejects_forged_vl_metadata(void)
{
    cdisasm_arm_instruction good;
    cdisasm_arm_instruction forged;
    cdisasm_arm_instruction zero_offset;
    uint32_t word = za_word(&descriptors[0], 2u, 17u, 9u);

    memset(&good, 0xa5, sizeof(good));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &good) == 4u);

    forged = good;
    forged.operand[1].flags = CDISASM_ARM_OPERAND_FLAG_VL_SCALED;
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[1].flags |= CDISASM_OPERAND_FLAG_SIGNED;
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[1].imm = 10u;
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[0].imm = 16u;
    expect_invalid_format(&forged);
    forged = good;
    forged.instruction_flags &=
        ~CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;
    expect_invalid_format(&forged);
    forged = good;
    forged.form_id = UINT16_C(4383);
    expect_invalid_format(&forged);
    forged = good;
    forged.raw_instruction ^= UINT32_C(0x00010000);
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[1].base_reg = CDISASM_ARM_REG_X0;
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[0].base_reg = CDISASM_ARM_REG_W12;
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[0].extend_type = 1u;
    expect_invalid_format(&forged);
    forged = good;
    forged.name_id = CDISASM_ARM_NAME_STR;
    forged.form_id = UINT16_C(4382);
    forged.operand[0].access = CDISASM_OPERAND_ACCESS_READ;
    forged.operand[1].access = CDISASM_OPERAND_ACCESS_WRITE;
    expect_invalid_format(&forged);

    memset(&zero_offset, 0xa5, sizeof(zero_offset));
    EXPECT(decode_word(za_word(&descriptors[0], 0u, 0u, 0u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &zero_offset) == 4u);
    forged = zero_offset;
    forged.form_id = UINT16_C(4383);
    expect_invalid_format(&forged);
    forged = zero_offset;
    forged.raw_instruction ^= UINT32_C(0x00010000);
    expect_invalid_format(&forged);
    forged = zero_offset;
    forged.operand[1].base_reg = CDISASM_ARM_REG_X1;
    expect_invalid_format(&forged);
    forged = zero_offset;
    forged.operand[1].index_reg = CDISASM_ARM_REG_X1;
    expect_invalid_format(&forged);
    forged = zero_offset;
    forged.operand[0].extend_type = 1u;
    expect_invalid_format(&forged);
}
#endif

int main(void)
{
    test_exhaustive_allocated_leaves();
    test_fixed_neighbors();
    test_cpu_profiles();
    test_transport_and_modes();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
    test_formatter_rejects_forged_vl_metadata();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM SME ZA load/store test(s) failed\n",
            failures);
        return 1;
    }
    printf("ARM SME ZA LDR/STR tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=4096)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
