#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define ZA_CONTIGUOUS_MASK UINT32_C(0xffe00010)

typedef struct za_contiguous_descriptor {
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    cdisasm_arm_reg_id tile_base;
    uint8_t element_log2;
    uint8_t load;
    const char *mnemonic;
} za_contiguous_descriptor;

/* Pinned 2026-03 AARCHMRS mortlach_contig_{load,store,qload,qstore}. */
static const za_contiguous_descriptor descriptors[] = {
    { UINT32_C(0xe0000000), CDISASM_ARM_NAME_LD1B, UINT16_C(4373),
      CDISASM_ARM_REG_ZAB0, 0u, 1u, "ld1b" },
    { UINT32_C(0xe0200000), CDISASM_ARM_NAME_ST1B, UINT16_C(4377),
      CDISASM_ARM_REG_ZAB0, 0u, 0u, "st1b" },
    { UINT32_C(0xe0400000), CDISASM_ARM_NAME_LD1H, UINT16_C(4374),
      CDISASM_ARM_REG_ZAH0, 1u, 1u, "ld1h" },
    { UINT32_C(0xe0600000), CDISASM_ARM_NAME_ST1H, UINT16_C(4378),
      CDISASM_ARM_REG_ZAH0, 1u, 0u, "st1h" },
    { UINT32_C(0xe0800000), CDISASM_ARM_NAME_LD1W, UINT16_C(4375),
      CDISASM_ARM_REG_ZAS0, 2u, 1u, "ld1w" },
    { UINT32_C(0xe0a00000), CDISASM_ARM_NAME_ST1W, UINT16_C(4379),
      CDISASM_ARM_REG_ZAS0, 2u, 0u, "st1w" },
    { UINT32_C(0xe0c00000), CDISASM_ARM_NAME_LD1D, UINT16_C(4376),
      CDISASM_ARM_REG_ZAD0, 3u, 1u, "ld1d" },
    { UINT32_C(0xe0e00000), CDISASM_ARM_NAME_ST1D, UINT16_C(4380),
      CDISASM_ARM_REG_ZAD0, 3u, 0u, "st1d" },
    { UINT32_C(0xe1c00000), CDISASM_ARM_NAME_LD1Q, UINT16_C(4385),
      CDISASM_ARM_REG_ZAQ0, 4u, 1u, "ld1q" },
    { UINT32_C(0xe1e00000), CDISASM_ARM_NAME_ST1Q, UINT16_C(4386),
      CDISASM_ARM_REG_ZAQ0, 4u, 0u, "st1q" }
};

_Static_assert(CDISASM_ARM_OPERAND_TILE == UINT8_C(9),
               "tile operand ABI changed");
_Static_assert(CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL == UINT8_C(32),
               "tile orientation flag ABI changed");
_Static_assert(CDISASM_ARM_REG_ZAB0 == UINT16_C(342),
               "generated ZA view register IDs changed");
_Static_assert(CDISASM_ARM_REG_ZAQ15 == UINT16_C(372),
               "generated ZA view register IDs changed");

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
    const za_contiguous_descriptor *descriptor,
    unsigned rm, unsigned vertical, unsigned selector,
    unsigned predicate, unsigned rn, unsigned low)
{
    return descriptor->value | ((uint32_t)rm << 16)
        | ((uint32_t)vertical << 15) | ((uint32_t)selector << 13)
        | ((uint32_t)predicate << 10) | ((uint32_t)rn << 5)
        | (uint32_t)low;
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
        cpu_id, mode, bytes, code_size, UINT64_C(0x15a000),
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
static int is_contiguous_form(cdisasm_arm_form_id form_id)
{
    return (form_id >= UINT16_C(4373) && form_id <= UINT16_C(4380))
        || form_id == UINT16_C(4385) || form_id == UINT16_C(4386);
}
#endif

static const za_contiguous_descriptor *descriptor_for_word(uint32_t word)
{
    uint32_t fixed = word & ZA_CONTIGUOUS_MASK;
    size_t index;

    for (index = 0u;
         index < sizeof(descriptors) / sizeof(descriptors[0]); ++index) {
        if (fixed == descriptors[index].value) {
            return &descriptors[index];
        }
    }
    return NULL;
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_reg_id expected_base(unsigned rn)
{
    return rn == 31u ? CDISASM_ARM_REG_SP
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn);
}

static void expected_instruction(
    uint32_t word, const za_contiguous_descriptor *descriptor,
    cdisasm_arm_instruction *expected)
{
    unsigned rm = (word >> 16) & 31u;
    unsigned vertical = (word >> 15) & 1u;
    unsigned selector = (word >> 13) & 3u;
    unsigned predicate = (word >> 10) & 7u;
    unsigned rn = (word >> 5) & 31u;
    unsigned low = word & 15u;
    unsigned offset_bits = 4u - descriptor->element_log2;
    unsigned tile_number = low >> offset_bits;
    unsigned slice_offset = offset_bits == 0u
        ? 0u : low & ((1u << offset_bits) - 1u);
    uint8_t element_size = (uint8_t)(1u << descriptor->element_log2);

    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x15a000);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = descriptor->name_id;
    expected->form_id = descriptor->form_id;
    expected->operand_count = 3u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = CDISASM_ARM_INSTRUCTION_FLAG_SME
        | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
        | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;

    expected->operand[0].type = CDISASM_ARM_OPERAND_TILE;
    expected->operand[0].reg = (cdisasm_arm_reg_id)(
        descriptor->tile_base + tile_number);
    expected->operand[0].base_reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_W12 + selector);
    expected->operand[0].imm = slice_offset;
    expected->operand[0].flags = vertical
        ? CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL
        : CDISASM_OPERAND_FLAG_NONE;
    expected->operand[0].extend_type = element_size;
    expected->operand[0].access = descriptor->load
        ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;

    expected->operand[1].type = CDISASM_ARM_OPERAND_PREDICATE;
    expected->operand[1].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_P0 + predicate);
    expected->operand[1].flags = descriptor->load
        ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
        : CDISASM_OPERAND_FLAG_NONE;
    expected->operand[1].extend_type = element_size;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;

    expected->operand[2].type = CDISASM_OPERAND_MEMORY;
    expected->operand[2].base_reg = expected_base(rn);
    expected->operand[2].index_reg = rm == 31u
        ? CDISASM_ARM_REG_NONE
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rm);
    if (rm != 31u && descriptor->element_log2 != 0u) {
        expected->operand[2].shift_type = CDISASM_ARM_SHIFT_LSL;
        expected->operand[2].shift_amount = descriptor->element_log2;
    }
    expected->operand[2].access = descriptor->load
        ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE;
}
#endif

static void check_allocated_word(
    uint32_t word, const za_contiguous_descriptor *descriptor)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded;

    domain_expect((word & ZA_CONTIGUOUS_MASK) == descriptor->value,
        word, "allocated word escaped exact ZA contiguous leaf");
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        expected_instruction(word, descriptor, &expected);
        domain_expect(decoded == 4u, word,
            "allocated ZA contiguous transfer did not decode");
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "ZA contiguous structured metadata mismatch");
    }
#else
    domain_expect(decoded == 0u, word,
        "extras-OFF decoded allocated ZA contiguous transfer");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF ZA contiguous ownership mismatch");
#endif
}

static void test_bounded_exhaustive_fields(void)
{
    uint32_t checked = 0u;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const za_contiguous_descriptor *descriptor =
            &descriptors[descriptor_index];
        unsigned vertical;

        /* Exhaust the complete H/V, W12-W15, P0-P7 and low ZAt:offset
         * product while holding the independent address pair fixed. */
        for (vertical = 0u; vertical < 2u; ++vertical) {
            unsigned selector;

            for (selector = 0u; selector < 4u; ++selector) {
                unsigned predicate;

                for (predicate = 0u; predicate < 8u; ++predicate) {
                    unsigned low;

                    for (low = 0u; low < 16u; ++low) {
                        check_allocated_word(za_word(
                            descriptor, 31u, vertical, selector,
                            predicate, 0u, low), descriptor);
                        ++checked;
                    }
                }
            }
        }
        /* Separately exhaust all X0-X30/XZR-by-X0-X30/SP address pairs. */
        {
            unsigned rm;

            for (rm = 0u; rm < 32u; ++rm) {
                unsigned rn;

                for (rn = 0u; rn < 32u; ++rn) {
                    check_allocated_word(za_word(
                        descriptor, rm, 1u, 3u, 7u, rn, 15u),
                        descriptor);
                    ++checked;
                }
            }
        }
    }
    EXPECT(checked == UINT32_C(20480));
}

static void test_exact_mask_boundaries(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        uint32_t word = za_word(
            &descriptors[descriptor_index], 17u, 1u, 2u, 5u, 9u, 11u);
        unsigned bit;

        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            const za_contiguous_descriptor *neighbor;
            uint32_t changed;
            uint32_t decoded;

            if ((ZA_CONTIGUOUS_MASK & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            changed = word ^ (UINT32_C(1) << bit);
            neighbor = descriptor_for_word(changed);
            if (neighbor != NULL) {
                check_allocated_word(changed, neighbor);
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                changed, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
            domain_expect(decoded != 4u
                    || !is_contiguous_form(instruction.form_id),
                changed, "fixed-bit neighbor retained a contiguous form");
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
    uint32_t load = za_word(&descriptors[0], 0u, 0u, 0u, 0u, 0u, 0u);
    uint32_t store = za_word(&descriptors[9], 30u, 1u, 3u, 7u, 31u, 15u);
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
        UINT64_C(0x15a000), CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
        &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, bytes, sizeof(bytes),
        UINT64_C(0x15a000), CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
        &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, bytes, sizeof(bytes),
        UINT64_C(0x15a000), CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, bytes, sizeof(bytes),
        UINT64_C(0x15a000), CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
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

    check_transport(za_word(
        &descriptors[0], 31u, 0u, 0u, 0u, 0u, 0u));
    check_transport(za_word(
        &descriptors[9], 30u, 1u, 3u, 7u, 31u, 15u));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(za_word(&descriptors[2], 4u, 0u, 1u, 3u, 2u, 15u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(za_word(&descriptors[8], 4u, 1u, 1u, 3u, 2u, 15u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expected_format(
    char text[128], const za_contiguous_descriptor *descriptor,
    unsigned rm, unsigned vertical, unsigned selector,
    unsigned predicate, unsigned rn, unsigned low)
{
    static const char suffixes[5] = { 'b', 'h', 's', 'd', 'q' };
    unsigned offset_bits = 4u - descriptor->element_log2;
    unsigned tile_number = low >> offset_bits;
    unsigned slice_offset = offset_bits == 0u
        ? 0u : low & ((1u << offset_bits) - 1u);
    char base[8];
    char index[8];

    if (rn == 31u) {
        memcpy(base, "sp", 3u);
    } else {
        (void)snprintf(base, sizeof(base), "x%u", rn);
    }
    if (rm != 31u) {
        (void)snprintf(index, sizeof(index), "x%u", rm);
    }
    if (rm == 31u) {
        (void)snprintf(text, 128u,
            "%s {za%u%c.%c[w%u, %u]}, p%u%s, [%s]",
            descriptor->mnemonic, tile_number, vertical ? 'v' : 'h',
            suffixes[descriptor->element_log2], 12u + selector,
            slice_offset, predicate, descriptor->load ? "/z" : "", base);
    } else if (descriptor->element_log2 == 0u) {
        (void)snprintf(text, 128u,
            "%s {za%u%c.%c[w%u, %u]}, p%u%s, [%s, %s]",
            descriptor->mnemonic, tile_number, vertical ? 'v' : 'h',
            suffixes[descriptor->element_log2], 12u + selector,
            slice_offset, predicate, descriptor->load ? "/z" : "",
            base, index);
    } else {
        (void)snprintf(text, 128u,
            "%s {za%u%c.%c[w%u, %u]}, p%u%s, [%s, %s, lsl #0x%x]",
            descriptor->mnemonic, tile_number, vertical ? 'v' : 'h',
            suffixes[descriptor->element_log2], 12u + selector,
            slice_offset, predicate, descriptor->load ? "/z" : "",
            base, index, descriptor->element_log2);
    }
}

static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[128];
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
        unsigned vertical;

        for (vertical = 0u; vertical < 2u; ++vertical) {
            unsigned selector;

            for (selector = 0u; selector < 4u; ++selector) {
                unsigned low;

                for (low = 0u; low < 16u; ++low) {
                    char expected[128];
                    unsigned rm = low == 0u ? 31u : 30u;
                    unsigned rn = selector == 3u ? 31u : 17u;
                    unsigned predicate = low & 7u;

                    expected_format(expected, &descriptors[descriptor_index],
                        rm, vertical, selector, predicate, rn, low);
                    expect_format(za_word(&descriptors[descriptor_index],
                        rm, vertical, selector, predicate, rn, low),
                        expected);
                }
            }
        }
    }
}

static void expect_invalid_format(cdisasm_arm_instruction *instruction)
{
    char text[128];

    memset(text, 0xa5, sizeof(text));
    EXPECT(cdisasm_arm_format(instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == 0u);
    EXPECT(text[0] == '\0');
}

static void test_formatter_rejects_forged_metadata(void)
{
    cdisasm_arm_instruction good;
    cdisasm_arm_instruction forged;
    uint32_t word = za_word(
        &descriptors[6], 11u, 1u, 2u, 6u, 10u, 15u);

    memset(&good, 0xa5, sizeof(good));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &good) == 4u);

#define REJECT_FORGED(statement)                                            \
    do {                                                                    \
        forged = good;                                                      \
        statement;                                                          \
        expect_invalid_format(&forged);                                     \
    } while (0)

    REJECT_FORGED(forged.raw_instruction ^= UINT32_C(1));
    REJECT_FORGED(forged.form_id = UINT16_C(4375));
    REJECT_FORGED(forged.name_id = CDISASM_ARM_NAME_ST1D);
    REJECT_FORGED(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_FORGED(forged.instruction_flags &=
        ~CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED);
    REJECT_FORGED(forged.operand_count = 2u);
    REJECT_FORGED(forged.operand[0].reg = CDISASM_ARM_REG_ZAD6);
    REJECT_FORGED(forged.operand[0].base_reg = CDISASM_ARM_REG_W13);
    REJECT_FORGED(forged.operand[0].imm = 0u);
    REJECT_FORGED(forged.operand[0].flags = 0u);
    REJECT_FORGED(forged.operand[0].extend_type = 4u);
    REJECT_FORGED(forged.operand[0].access = CDISASM_OPERAND_ACCESS_READ);
    REJECT_FORGED(forged.operand[1].reg = CDISASM_ARM_REG_P5);
    REJECT_FORGED(forged.operand[1].flags = 0u);
    REJECT_FORGED(forged.operand[1].extend_type = 4u);
    REJECT_FORGED(forged.operand[1].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_FORGED(forged.operand[2].base_reg = CDISASM_ARM_REG_X9);
    REJECT_FORGED(forged.operand[2].index_reg = CDISASM_ARM_REG_X12);
    REJECT_FORGED(forged.operand[2].shift_amount = 2u);
    REJECT_FORGED(forged.operand[2].access = CDISASM_OPERAND_ACCESS_WRITE);

#undef REJECT_FORGED
}
#endif

int main(void)
{
    test_bounded_exhaustive_fields();
    test_exact_mask_boundaries();
    test_cpu_profiles();
    test_transport_and_modes();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
    test_formatter_rejects_forged_metadata();
#endif

    if (failures != 0) {
        fprintf(stderr,
            "%d ARM SME ZA contiguous load/store test(s) failed\n",
            failures);
        return 1;
    }
    printf("ARM SME ZA contiguous LD1/ST1 tests passed "
           "(USE_EXTRA_OPCODES=%d, checked=20480)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
