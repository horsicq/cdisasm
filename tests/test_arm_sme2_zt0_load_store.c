#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define ZT0_GROUP_MASK UINT32_C(0xffc0fc1c)
#define ZT0_GROUP_VALUE UINT32_C(0xe1008000)
#define ZT0_LEAF_MASK UINT32_C(0xfffffc1f)

typedef struct zt0_descriptor {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    cdisasm_operand_access tile_access;
    cdisasm_operand_access memory_access;
    const char *mnemonic;
} zt0_descriptor;

/* Pinned AARCHMRS ldr_zt_br_ and str_zt_br_ leaves. */
static const zt0_descriptor descriptors[] = {
    { UINT32_C(0xe11f8000), CDISASM_ARM_NAME_LDR, UINT16_C(4383),
      CDISASM_OPERAND_ACCESS_WRITE, CDISASM_OPERAND_ACCESS_READ, "ldr" },
    { UINT32_C(0xe13f8000), CDISASM_ARM_NAME_STR, UINT16_C(4384),
      CDISASM_OPERAND_ACCESS_READ, CDISASM_OPERAND_ACCESS_WRITE, "str" }
};

_Static_assert(CDISASM_ARM_NAME_LDR == UINT16_C(25),
               "established LDR ID changed");
_Static_assert(CDISASM_ARM_NAME_STR == UINT16_C(47),
               "established STR ID changed");
_Static_assert(CDISASM_ARM_REG_ZT0 == UINT16_C(373),
               "generated ZT0 register ID changed");
_Static_assert(CDISASM_ARM_OPERAND_TILE == UINT8_C(9),
               "tile operand ABI changed");

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

static uint32_t zt0_word(const zt0_descriptor *descriptor, unsigned rn)
{
    return descriptor->value | ((uint32_t)rn << 5);
}

static uint32_t zt0_group_word(unsigned operation, unsigned zt,
                               unsigned rn)
{
    return ZT0_GROUP_VALUE | ((uint32_t)operation << 16)
        | ((uint32_t)rn << 5) | (uint32_t)zt;
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
        cpu_id, mode, bytes, code_size, UINT64_C(0x12f000),
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
    uint32_t word, const zt0_descriptor *descriptor,
    cdisasm_arm_instruction *expected)
{
    unsigned rn = (word >> 5) & 31u;

    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x12f000);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = descriptor->name_id;
    expected->form_id = descriptor->form_id;
    expected->operand_count = 2u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SME
        | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX;

    expected->operand[0].type = CDISASM_ARM_OPERAND_TILE;
    expected->operand[0].reg = CDISASM_ARM_REG_ZT0;
    expected->operand[0].access = descriptor->tile_access;

    expected->operand[1].type = CDISASM_OPERAND_MEMORY;
    expected->operand[1].base_reg = expected_base(rn);
    expected->operand[1].size = 64u;
    expected->operand[1].access = descriptor->memory_access;
}
#endif

static void test_exhaustive_parent_envelope(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned operation;

    for (operation = 0u; operation < 64u; ++operation) {
        unsigned zt;

        for (zt = 0u; zt < 4u; ++zt) {
            unsigned rn;

            for (rn = 0u; rn < 32u; ++rn) {
                cdisasm_arm_instruction instruction;
                uint32_t word = zt0_group_word(operation, zt, rn);
                uint32_t decoded;
                int allocated_word = zt == 0u
                    && (operation == 31u || operation == 63u);

                domain_expect(
                    (word & ZT0_GROUP_MASK) == ZT0_GROUP_VALUE,
                    word, "word escaped ZT0 parent envelope");
                memset(&instruction, 0xa5, sizeof(instruction));
                decoded = decode_word(
                    word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                    4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                if (allocated_word) {
                    const zt0_descriptor *descriptor = operation == 31u
                        ? &descriptors[0] : &descriptors[1];

                    ++allocated;
                    domain_expect(
                        (word & ZT0_LEAF_MASK) == descriptor->value,
                        word, "allocated word escaped exact leaf");
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        expected_instruction(word, descriptor, &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated ZT0 transfer did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected,
                            sizeof(expected)) == 0,
                            word, "ZT0 transfer metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF decoded allocated ZT0 transfer");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF ZT0 ownership mismatch");
#endif
                } else {
                    ++reserved;
                    domain_expect(decoded == 0u, word,
                        "reserved ZT0 parent word decoded");
                    domain_expect(instruction_is_error_only(
                        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
                        word, "reserved ZT0 parent status mismatch");
                }
            }
        }
    }
    EXPECT(allocated == UINT32_C(64));
    EXPECT(reserved == UINT32_C(8128));
}

static void test_fixed_neighbors(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const zt0_descriptor *descriptor = &descriptors[descriptor_index];
        uint32_t word = zt0_word(descriptor, 17u);
        unsigned bit;

        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((ZT0_LEAF_MASK & (UINT32_C(1) << bit)) == 0u) {
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
    uint32_t load = zt0_word(&descriptors[0], 2u);
    uint32_t store = zt0_word(&descriptors[1], 31u);
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
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif

    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12f000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12f000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12f000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x12f000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    for (boundary = 0u; boundary < 4u; ++boundary) {
        cdisasm_status expected = boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, expected));
    }
}

static void test_transport_modes_and_reserved(void)
{
    cdisasm_arm_instruction instruction;
    uint32_t reserved = zt0_group_word(31u, 1u, 2u);

    check_transport(zt0_word(&descriptors[0], 0u));
    check_transport(zt0_word(&descriptors[1], 31u));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        reserved, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        zt0_word(&descriptors[0], 2u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        zt0_word(&descriptors[1], 2u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[80];
    char short_text[8];
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

static void test_formatting(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const zt0_descriptor *descriptor = &descriptors[descriptor_index];
        unsigned rn;

        for (rn = 0u; rn < 32u; ++rn) {
            char expected[80];
            int length;

            if (rn == 31u) {
                length = snprintf(expected, sizeof(expected),
                    "%s zt0, [sp]", descriptor->mnemonic);
            } else {
                length = snprintf(expected, sizeof(expected),
                    "%s zt0, [x%u]", descriptor->mnemonic, rn);
            }
            EXPECT(length > 0 && (size_t)length < sizeof(expected));
            expect_format(zt0_word(descriptor, rn), expected);
        }
    }
    {
        cdisasm_arm_instruction instruction;
        char text[80];
        static const char expected[] = "LDR zt0, [sp]";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            zt0_word(&descriptors[0], 31u), CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_parent_envelope();
    test_fixed_neighbors();
    test_cpu_profiles();
    test_transport_modes_and_reserved();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM SME2 ZT0 load/store test(s) failed\n",
            failures);
        return 1;
    }
    printf("ARM SME2 ZT0 LDR/STR tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=64, reserved=8128)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
