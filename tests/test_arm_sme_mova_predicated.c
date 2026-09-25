#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MOVA_INSERT_MASK UINT32_C(0xff3e0010)
#define MOVA_INSERT_VALUE UINT32_C(0xc0000000)
#define MOVA_EXTRACT_MASK UINT32_C(0xff3e0200)
#define MOVA_EXTRACT_VALUE UINT32_C(0xc0020000)

typedef struct mova_descriptor {
    uint32_t value;
    uint32_t mask;
    cdisasm_arm_form_id form_id;
    cdisasm_arm_reg_id tile_base;
    uint8_t element_log2;
    uint8_t size;
    uint8_t quadword;
    uint8_t extract;
    char suffix;
} mova_descriptor;

/* Pinned 2026-03 AARCHMRS mortlach_{insert,extract}_pred leaves. */
static const mova_descriptor descriptors[] = {
    {MOVA_INSERT_VALUE, MOVA_INSERT_MASK, UINT16_C(3862),
     CDISASM_ARM_REG_ZAB0, 0u, 0u, 0u, 0u, 'b'},
    {MOVA_INSERT_VALUE, MOVA_INSERT_MASK, UINT16_C(3863),
     CDISASM_ARM_REG_ZAH0, 1u, 1u, 0u, 0u, 'h'},
    {MOVA_INSERT_VALUE, MOVA_INSERT_MASK, UINT16_C(3864),
     CDISASM_ARM_REG_ZAS0, 2u, 2u, 0u, 0u, 's'},
    {MOVA_INSERT_VALUE, MOVA_INSERT_MASK, UINT16_C(3865),
     CDISASM_ARM_REG_ZAD0, 3u, 3u, 0u, 0u, 'd'},
    {MOVA_INSERT_VALUE, MOVA_INSERT_MASK, UINT16_C(3866),
     CDISASM_ARM_REG_ZAQ0, 4u, 3u, 1u, 0u, 'q'},
    {MOVA_EXTRACT_VALUE, MOVA_EXTRACT_MASK, UINT16_C(3877),
     CDISASM_ARM_REG_ZAB0, 0u, 0u, 0u, 1u, 'b'},
    {MOVA_EXTRACT_VALUE, MOVA_EXTRACT_MASK, UINT16_C(3878),
     CDISASM_ARM_REG_ZAH0, 1u, 1u, 0u, 1u, 'h'},
    {MOVA_EXTRACT_VALUE, MOVA_EXTRACT_MASK, UINT16_C(3879),
     CDISASM_ARM_REG_ZAS0, 2u, 2u, 0u, 1u, 's'},
    {MOVA_EXTRACT_VALUE, MOVA_EXTRACT_MASK, UINT16_C(3880),
     CDISASM_ARM_REG_ZAD0, 3u, 3u, 0u, 1u, 'd'},
    {MOVA_EXTRACT_VALUE, MOVA_EXTRACT_MASK, UINT16_C(3881),
     CDISASM_ARM_REG_ZAQ0, 4u, 3u, 1u, 1u, 'q'}
};

_Static_assert(CDISASM_ARM_NAME_MOV == UINT16_C(31),
    "MOV name ID changed");
_Static_assert(CDISASM_ARM_OPERAND_TILE == UINT8_C(9),
    "tile operand ABI changed");
_Static_assert(CDISASM_ARM_REG_ZAB0 == UINT16_C(342),
    "generated ZA view register IDs changed");
_Static_assert(CDISASM_ARM_REG_ZAQ15 == UINT16_C(372),
    "generated ZA view register IDs changed");

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            if (failures < 32) {                                            \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
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

static uint32_t mova_word(
    const mova_descriptor *descriptor,
    unsigned vertical,
    unsigned selector,
    unsigned predicate,
    unsigned zreg,
    unsigned encoded_slice)
{
    uint32_t word = descriptor->value
        | ((uint32_t)descriptor->size << 22)
        | ((uint32_t)descriptor->quadword << 16)
        | ((uint32_t)vertical << 15)
        | ((uint32_t)selector << 13)
        | ((uint32_t)predicate << 10);

    if (descriptor->extract) {
        word |= (uint32_t)encoded_slice << 5;
        word |= (uint32_t)zreg;
    } else {
        word |= (uint32_t)zreg << 5;
        word |= (uint32_t)encoded_slice;
    }
    return word;
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
        cpu_id, mode, bytes, code_size, UINT64_C(0x15b000),
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
static int is_mova_form(cdisasm_arm_form_id form_id)
{
    return (form_id >= UINT16_C(3862) && form_id <= UINT16_C(3866))
        || (form_id >= UINT16_C(3877) && form_id <= UINT16_C(3881));
}
#endif

static const mova_descriptor *descriptor_for_word(uint32_t word)
{
    unsigned size = (word >> 22) & 3u;
    unsigned quadword = (word >> 16) & 1u;
    unsigned element_log2;
    unsigned first;

    if ((word & MOVA_INSERT_MASK) == MOVA_INSERT_VALUE) {
        first = 0u;
    } else if ((word & MOVA_EXTRACT_MASK) == MOVA_EXTRACT_VALUE) {
        first = 5u;
    } else {
        return NULL;
    }
    if (quadword != 0u && size != 3u) {
        return NULL;
    }
    element_log2 = quadword != 0u ? 4u : size;
    return &descriptors[first + element_log2];
}

#if USE_EXTRA_OPCODES
static void expected_instruction(
    uint32_t word,
    const mova_descriptor *descriptor,
    cdisasm_arm_instruction *expected)
{
    unsigned encoded_slice = descriptor->extract
        ? (word >> 5) & 15u : word & 15u;
    unsigned zreg = descriptor->extract
        ? word & 31u : (word >> 5) & 31u;
    unsigned offset_bits = 4u - descriptor->element_log2;
    unsigned tile_number = encoded_slice >> offset_bits;
    unsigned slice_offset = offset_bits == 0u ? 0u
        : encoded_slice & ((1u << offset_bits) - 1u);
    unsigned vertical = (word >> 15) & 1u;
    unsigned selector = (word >> 13) & 3u;
    unsigned predicate = (word >> 10) & 7u;
    uint8_t element_size = (uint8_t)(1u << descriptor->element_log2);
    cdisasm_arm_operand *tile;
    cdisasm_arm_operand *zoperand;

    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x15b000);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = CDISASM_ARM_NAME_MOV;
    expected->form_id = descriptor->form_id;
    expected->operand_count = 3u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = CDISASM_ARM_INSTRUCTION_FLAG_SME
        | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
        | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;

    tile = &expected->operand[descriptor->extract ? 2u : 0u];
    tile->type = CDISASM_ARM_OPERAND_TILE;
    tile->reg = (cdisasm_arm_reg_id)(
        descriptor->tile_base + tile_number);
    tile->base_reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_W12 + selector);
    tile->imm = slice_offset;
    tile->flags = vertical
        ? CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL
        : CDISASM_OPERAND_FLAG_NONE;
    tile->extend_type = element_size;
    tile->access = descriptor->extract
        ? CDISASM_OPERAND_ACCESS_READ
        : CDISASM_OPERAND_ACCESS_READ_WRITE;

    expected->operand[1].type = CDISASM_ARM_OPERAND_PREDICATE;
    expected->operand[1].reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_P0 + predicate);
    expected->operand[1].flags =
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE;
    expected->operand[1].extend_type = element_size;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;

    zoperand = &expected->operand[descriptor->extract ? 0u : 2u];
    zoperand->type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    zoperand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zreg);
    zoperand->extend_type = element_size;
    zoperand->access = descriptor->extract
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_READ;
}
#endif

static void check_allocated_word(
    uint32_t word,
    const mova_descriptor *descriptor)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded;

    domain_expect(descriptor_for_word(word) == descriptor,
        word, "word escaped its exact predicated MOVA leaf");
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        expected_instruction(word, descriptor, &expected);
        domain_expect(decoded == 4u, word,
            "allocated predicated MOVA did not decode");
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "predicated MOVA structured metadata mismatch");
    }
#else
    domain_expect(decoded == 0u, word,
        "extras-OFF decoded allocated predicated MOVA");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF predicated MOVA ownership mismatch");
#endif
}

static void test_bounded_exhaustive_fields(void)
{
    uint32_t checked = 0u;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const mova_descriptor *descriptor = &descriptors[descriptor_index];
        unsigned vertical;

        /* Exhaust H/V, W12-W15, P0-P7 and the complete encoded ZA slice
         * while holding the independent Z register fixed. */
        for (vertical = 0u; vertical < 2u; ++vertical) {
            unsigned selector;

            for (selector = 0u; selector < 4u; ++selector) {
                unsigned predicate;

                for (predicate = 0u; predicate < 8u; ++predicate) {
                    unsigned slice;

                    for (slice = 0u; slice < 16u; ++slice) {
                        check_allocated_word(mova_word(
                            descriptor, vertical, selector, predicate,
                            17u, slice), descriptor);
                        ++checked;
                    }
                }
            }
        }
        /* Exhaust Z0-Z31 independently at both slice extremes. */
        {
            unsigned zreg;

            for (zreg = 0u; zreg < 32u; ++zreg) {
                check_allocated_word(mova_word(
                    descriptor, 1u, 3u, 7u, zreg, 0u), descriptor);
                check_allocated_word(mova_word(
                    descriptor, 0u, 0u, 0u, zreg, 15u), descriptor);
                checked += 2u;
            }
        }
    }
    EXPECT(checked == UINT32_C(10880));
}

static void test_reserved_q_controls(void)
{
    unsigned extract;

    for (extract = 0u; extract < 2u; ++extract) {
        unsigned size;

        for (size = 0u; size < 3u; ++size) {
            const mova_descriptor *base = &descriptors[extract ? 5u : 0u];
            uint32_t word = base->value | ((uint32_t)size << 22)
                | UINT32_C(1) << 16 | UINT32_C(1) << 15
                | UINT32_C(3) << 13 | UINT32_C(7) << 10;
            cdisasm_arm_instruction instruction;

            if (extract) {
                word |= UINT32_C(15) << 5 | UINT32_C(31);
            } else {
                word |= UINT32_C(31) << 5 | UINT32_C(15);
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
                &instruction) == 0u);
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        }
    }
}

static void test_exact_mask_boundaries(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const mova_descriptor *descriptor = &descriptors[descriptor_index];
        uint32_t word = mova_word(
            descriptor, 1u, 2u, 5u, 19u, 11u);
        unsigned bit;

        for (bit = 0u; bit < 32u; ++bit) {
            const mova_descriptor *neighbor;
            cdisasm_arm_instruction instruction;
            uint32_t changed;
            uint32_t decoded;

            if ((descriptor->mask & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            changed = word ^ (UINT32_C(1) << bit);
            neighbor = descriptor_for_word(changed);
            if (neighbor != NULL) {
                check_allocated_word(changed, neighbor);
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(changed, CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
            domain_expect(decoded != 4u || !is_mova_form(instruction.form_id),
                changed, "fixed-bit neighbor retained a predicated MOVA form");
#else
            (void)decoded;
#endif
        }
    }
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
    decoded = decode_word(word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
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
    uint32_t insert = mova_word(
        &descriptors[0], 0u, 0u, 0u, 0u, 0u);
    uint32_t extract = mova_word(
        &descriptors[9], 1u, 3u, 7u, 31u, 15u);
    cdisasm_arm_cpu_id cpu_id;

    expect_cpu_status(insert, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_cpu_status(extract, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
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
        expect_cpu_status(insert, cpu_id, expected);
        expect_cpu_status(extract, cpu_id, expected);
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
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x15b000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x15b000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x15b000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x15b000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
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

    check_transport(mova_word(
        &descriptors[0], 0u, 0u, 0u, 0u, 0u));
    check_transport(mova_word(
        &descriptors[9], 1u, 3u, 7u, 31u, 15u));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(mova_word(
        &descriptors[2], 0u, 1u, 3u, 7u, 9u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(mova_word(
        &descriptors[7], 1u, 2u, 4u, 23u, 6u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expected_format(
    char text[128],
    const mova_descriptor *descriptor,
    unsigned vertical,
    unsigned selector,
    unsigned predicate,
    unsigned zreg,
    unsigned encoded_slice)
{
    unsigned offset_bits = 4u - descriptor->element_log2;
    unsigned tile_number = encoded_slice >> offset_bits;
    unsigned slice_offset = offset_bits == 0u ? 0u
        : encoded_slice & ((1u << offset_bits) - 1u);

    if (descriptor->extract) {
        (void)snprintf(text, 128u,
            "mov z%u.%c, p%u/m, za%u%c.%c[w%u, %u]",
            zreg, descriptor->suffix, predicate, tile_number,
            vertical ? 'v' : 'h', descriptor->suffix,
            12u + selector, slice_offset);
    } else {
        (void)snprintf(text, 128u,
            "mov za%u%c.%c[w%u, %u], p%u/m, z%u.%c",
            tile_number, vertical ? 'v' : 'h', descriptor->suffix,
            12u + selector, slice_offset, predicate,
            zreg, descriptor->suffix);
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
        const mova_descriptor *descriptor = &descriptors[descriptor_index];
        unsigned vertical;

        for (vertical = 0u; vertical < 2u; ++vertical) {
            unsigned selector;

            for (selector = 0u; selector < 4u; ++selector) {
                unsigned slice;

                for (slice = 0u; slice < 16u; ++slice) {
                    unsigned predicate = slice & 7u;
                    unsigned zreg = (slice * 7u + selector) & 31u;
                    uint32_t word = mova_word(descriptor, vertical,
                        selector, predicate, zreg, slice);
                    char expected[128];

                    expected_format(expected, descriptor, vertical,
                        selector, predicate, zreg, slice);
                    expect_format(word, expected);
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
    uint32_t word = mova_word(
        &descriptors[8], 1u, 2u, 6u, 27u, 13u);

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
    REJECT_FORGED(forged.form_id = UINT16_C(3879));
    REJECT_FORGED(forged.name_id = CDISASM_ARM_NAME_MOVA);
    REJECT_FORGED(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_FORGED(forged.instruction_flags &=
        ~CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED);
    REJECT_FORGED(forged.operand_count = 2u);
    REJECT_FORGED(forged.operand[0].reg = CDISASM_ARM_REG_Z26);
    REJECT_FORGED(forged.operand[0].extend_type = 2u);
    REJECT_FORGED(forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_FORGED(forged.operand[1].reg = CDISASM_ARM_REG_P5);
    REJECT_FORGED(forged.operand[1].flags = 0u);
    REJECT_FORGED(forged.operand[1].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_FORGED(forged.operand[2].reg = CDISASM_ARM_REG_ZAD5);
    REJECT_FORGED(forged.operand[2].base_reg = CDISASM_ARM_REG_W13);
    REJECT_FORGED(forged.operand[2].imm = 0u);
    REJECT_FORGED(forged.operand[2].flags = 0u);
    REJECT_FORGED(forged.operand[2].access
        = CDISASM_OPERAND_ACCESS_READ_WRITE);

#undef REJECT_FORGED
}
#endif

int main(void)
{
    test_bounded_exhaustive_fields();
    test_reserved_q_controls();
    test_exact_mask_boundaries();
    test_cpu_profiles();
    test_transport_and_modes();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
    test_formatter_rejects_forged_metadata();
#endif

    if (failures != 0) {
        fprintf(stderr,
            "%d ARM SME predicated MOVA test(s) failed\n", failures);
        return 1;
    }
    printf("ARM SME predicated MOV/MOVA tests passed "
           "(USE_EXTRA_OPCODES=%d, checked=10880)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
