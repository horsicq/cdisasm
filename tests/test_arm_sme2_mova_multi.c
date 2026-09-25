#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct mova_descriptor {
    uint32_t value;
    uint32_t mask;
    cdisasm_arm_form_id form_id;
    uint8_t count;
    uint8_t size;
    uint8_t slice_values;
    uint8_t extract;
    uint8_t whole_array;
    char suffix;
} mova_descriptor;

/* Pinned 2026-03 AARCHMRS mortlach multi-register MOVA leaves. */
static const mova_descriptor descriptors[] = {
    {UINT32_C(0xc0040000), UINT32_C(0xffff1c38), UINT16_C(3867),
     2u, 0u, 8u, 0u, 0u, 'b'},
    {UINT32_C(0xc0440000), UINT32_C(0xffff1c38), UINT16_C(3868),
     2u, 1u, 8u, 0u, 0u, 'h'},
    {UINT32_C(0xc0840000), UINT32_C(0xffff1c38), UINT16_C(3869),
     2u, 2u, 8u, 0u, 0u, 's'},
    {UINT32_C(0xc0c40000), UINT32_C(0xffff1c38), UINT16_C(3870),
     2u, 3u, 8u, 0u, 0u, 'd'},
    {UINT32_C(0xc0040400), UINT32_C(0xffff1c7c), UINT16_C(3871),
     4u, 0u, 4u, 0u, 0u, 'b'},
    {UINT32_C(0xc0440400), UINT32_C(0xffff1c7c), UINT16_C(3872),
     4u, 1u, 4u, 0u, 0u, 'h'},
    {UINT32_C(0xc0840400), UINT32_C(0xffff1c7c), UINT16_C(3873),
     4u, 2u, 4u, 0u, 0u, 's'},
    {UINT32_C(0xc0c40400), UINT32_C(0xffff1c78), UINT16_C(3874),
     4u, 3u, 8u, 0u, 0u, 'd'},
    {UINT32_C(0xc0040800), UINT32_C(0xffff9c38), UINT16_C(3875),
     2u, 3u, 8u, 0u, 1u, 'd'},
    {UINT32_C(0xc0040c00), UINT32_C(0xffff9c78), UINT16_C(3876),
     4u, 3u, 8u, 0u, 1u, 'd'},
    {UINT32_C(0xc0060000), UINT32_C(0xffff1f01), UINT16_C(3882),
     2u, 0u, 8u, 1u, 0u, 'b'},
    {UINT32_C(0xc0460000), UINT32_C(0xffff1f01), UINT16_C(3883),
     2u, 1u, 8u, 1u, 0u, 'h'},
    {UINT32_C(0xc0860000), UINT32_C(0xffff1f01), UINT16_C(3884),
     2u, 2u, 8u, 1u, 0u, 's'},
    {UINT32_C(0xc0c60000), UINT32_C(0xffff1f01), UINT16_C(3885),
     2u, 3u, 8u, 1u, 0u, 'd'},
    {UINT32_C(0xc0060400), UINT32_C(0xffff1f83), UINT16_C(3886),
     4u, 0u, 4u, 1u, 0u, 'b'},
    {UINT32_C(0xc0460400), UINT32_C(0xffff1f83), UINT16_C(3887),
     4u, 1u, 4u, 1u, 0u, 'h'},
    {UINT32_C(0xc0860400), UINT32_C(0xffff1f83), UINT16_C(3888),
     4u, 2u, 4u, 1u, 0u, 's'},
    {UINT32_C(0xc0c60400), UINT32_C(0xffff1f03), UINT16_C(3889),
     4u, 3u, 8u, 1u, 0u, 'd'},
    {UINT32_C(0xc0060800), UINT32_C(0xffff9f01), UINT16_C(3890),
     2u, 3u, 8u, 1u, 1u, 'd'},
    {UINT32_C(0xc0060c00), UINT32_C(0xffff9f03), UINT16_C(3891),
     4u, 3u, 8u, 1u, 1u, 'd'}
};

_Static_assert(CDISASM_ARM_NAME_MOV == UINT16_C(31),
    "MOV name ID changed");
_Static_assert(CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST == UINT8_C(8),
    "scalable register-list operand ABI changed");
_Static_assert(CDISASM_ARM_OPERAND_TILE == UINT8_C(9),
    "tile operand ABI changed");
_Static_assert(CDISASM_ARM_REG_ZAB0 == UINT16_C(342),
    "generated ZA view register IDs changed");
_Static_assert(CDISASM_ARM_REG_ZAD7 == UINT16_C(356),
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
        cpu_id, mode, bytes, code_size, UINT64_C(0x15c000),
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
static int is_multi_mova_form(cdisasm_arm_form_id form_id)
{
    return (form_id >= UINT16_C(3867) && form_id <= UINT16_C(3876))
        || (form_id >= UINT16_C(3882) && form_id <= UINT16_C(3891));
}
#endif

static uint32_t mova_word(
    const mova_descriptor *descriptor,
    unsigned vertical,
    unsigned selector,
    unsigned list_group,
    unsigned slice_group)
{
    uint32_t word = descriptor->value
        | ((uint32_t)selector << 13);

    if (!descriptor->whole_array) {
        word |= (uint32_t)vertical << 15;
    }
    if (descriptor->extract) {
        word |= (uint32_t)slice_group << 5;
        word |= (uint32_t)list_group
            << (descriptor->count == 4u ? 2u : 1u);
    } else {
        word |= (uint32_t)list_group
            << (descriptor->count == 4u ? 7u : 6u);
        word |= (uint32_t)slice_group;
    }
    return word;
}

static const mova_descriptor *descriptor_for_word(uint32_t word)
{
    size_t index;

    for (index = 0u;
         index < sizeof(descriptors) / sizeof(descriptors[0]); ++index) {
        if ((word & descriptors[index].mask) == descriptors[index].value) {
            return &descriptors[index];
        }
    }
    return NULL;
}

#if USE_EXTRA_OPCODES
static void expected_instruction(
    uint32_t word,
    const mova_descriptor *descriptor,
    cdisasm_arm_instruction *expected)
{
    static const cdisasm_arm_reg_id tile_bases[4] = {
        CDISASM_ARM_REG_ZAB0, CDISASM_ARM_REG_ZAH0,
        CDISASM_ARM_REG_ZAS0, CDISASM_ARM_REG_ZAD0
    };
    unsigned list_group = descriptor->extract
        ? (word >> (descriptor->count == 4u ? 2u : 1u))
            & (descriptor->count == 4u ? 7u : 15u)
        : (word >> (descriptor->count == 4u ? 7u : 6u))
            & (descriptor->count == 4u ? 7u : 15u);
    unsigned slice_group = descriptor->extract
        ? (word >> 5) & 7u : word & 7u;
    unsigned count_log2 = descriptor->count == 4u ? 2u : 1u;
    unsigned group_offset_bits = 4u
            > (unsigned)descriptor->size + count_log2
        ? 4u - descriptor->size - count_log2 : 0u;
    uint8_t element_size = descriptor->whole_array
        ? 8u : (uint8_t)(UINT32_C(1) << descriptor->size);
    cdisasm_arm_operand *tile;
    cdisasm_arm_operand *list;

    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x15c000);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = CDISASM_ARM_NAME_MOV;
    expected->form_id = descriptor->form_id;
    expected->operand_count = 2u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = CDISASM_ARM_INSTRUCTION_FLAG_SME
        | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
        | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;

    tile = &expected->operand[descriptor->extract ? 1u : 0u];
    tile->type = CDISASM_ARM_OPERAND_TILE;
    tile->reg = descriptor->whole_array
        ? CDISASM_ARM_REG_ZA
        : (cdisasm_arm_reg_id)(tile_bases[descriptor->size]
            + (slice_group >> group_offset_bits));
    tile->base_reg = (cdisasm_arm_reg_id)(
        (descriptor->whole_array ? CDISASM_ARM_REG_W8
                                 : CDISASM_ARM_REG_W12)
            + ((word >> 13) & 3u));
    tile->register_list = descriptor->count;
    tile->imm = descriptor->whole_array ? slice_group
        : group_offset_bits == 0u ? 0u
        : (slice_group & ((1u << group_offset_bits) - 1u))
            * descriptor->count;
    tile->flags = !descriptor->whole_array
            && (word & UINT32_C(0x00008000)) != 0u
        ? CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL
        : CDISASM_OPERAND_FLAG_NONE;
    tile->extend_type = element_size;
    tile->access = descriptor->extract
        ? CDISASM_OPERAND_ACCESS_READ
        : CDISASM_OPERAND_ACCESS_WRITE;

    list = &expected->operand[descriptor->extract ? 0u : 1u];
    list->type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    list->reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + list_group * descriptor->count);
    list->register_list = (uint16_t)(
        UINT16_C(0x0100) | descriptor->count);
    list->extend_type = element_size;
    list->access = descriptor->extract
        ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
}
#endif

static void check_allocated_word(
    uint32_t word,
    const mova_descriptor *descriptor)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded;

    domain_expect(descriptor_for_word(word) == descriptor,
        word, "word escaped its exact SME2 MOVA leaf");
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        expected_instruction(word, descriptor, &expected);
        domain_expect(decoded == 4u, word,
            "allocated SME2 MOVA did not decode");
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "SME2 MOVA structured metadata mismatch");
    }
#else
    domain_expect(decoded == 0u, word,
        "extras-OFF decoded allocated SME2 MOVA");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF SME2 MOVA ownership mismatch");
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
        unsigned vertical_limit = descriptor->whole_array ? 1u : 2u;
        unsigned list_groups = 32u / descriptor->count;
        unsigned vertical;

        for (vertical = 0u; vertical < vertical_limit; ++vertical) {
            unsigned selector;

            for (selector = 0u; selector < 4u; ++selector) {
                unsigned list_group;

                for (list_group = 0u;
                     list_group < list_groups; ++list_group) {
                    unsigned slice;

                    for (slice = 0u;
                         slice < descriptor->slice_values; ++slice) {
                        check_allocated_word(mova_word(
                            descriptor, vertical, selector,
                            list_group, slice), descriptor);
                        ++checked;
                    }
                }
            }
        }
    }
    EXPECT(checked == UINT32_C(12288));
}

static void test_reserved_quad_slice_bits(void)
{
    size_t index;

    for (index = 0u;
         index < sizeof(descriptors) / sizeof(descriptors[0]); ++index) {
        const mova_descriptor *descriptor = &descriptors[index];
        cdisasm_arm_instruction instruction;
        uint32_t word;

        if (descriptor->whole_array || descriptor->count != 4u
            || descriptor->size == 3u) {
            continue;
        }
        word = mova_word(descriptor, 1u, 3u,
            32u / descriptor->count - 1u,
            descriptor->slice_values - 1u);
        word |= descriptor->extract ? UINT32_C(0x80) : UINT32_C(4);
        EXPECT(descriptor_for_word(word) == NULL);
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    }
}

static void test_exact_mask_boundaries(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const mova_descriptor *descriptor = &descriptors[descriptor_index];
        uint32_t word = mova_word(descriptor,
            descriptor->whole_array ? 0u : 1u, 2u,
            (32u / descriptor->count) / 2u,
            descriptor->slice_values / 2u);
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
            domain_expect(decoded != 4u
                    || !is_multi_mova_form(instruction.form_id),
                changed, "fixed-bit neighbor retained an SME2 MOVA form");
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
    uint32_t insert = mova_word(&descriptors[0], 0u, 0u, 0u, 0u);
    uint32_t extract = mova_word(&descriptors[19], 0u, 3u, 7u, 7u);
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
        bytes, sizeof(bytes), UINT64_C(0x15c000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x15c000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x15c000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x15c000),
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

    check_transport(mova_word(&descriptors[4], 1u, 3u, 7u, 3u));
    check_transport(mova_word(&descriptors[18], 0u, 0u, 0u, 0u));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(mova_word(&descriptors[2], 0u, 1u, 7u, 4u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(mova_word(&descriptors[17], 1u, 2u, 4u, 6u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void append_zlist_text(
    char *text,
    size_t capacity,
    unsigned base,
    unsigned count,
    char suffix)
{
    unsigned index;
    size_t used = strlen(text);

    if (used < capacity) {
        (void)snprintf(text + used, capacity - used, "{");
    }
    for (index = 0u; index < count; ++index) {
        used = strlen(text);
        if (used < capacity) {
            (void)snprintf(text + used, capacity - used,
                "%sz%u.%c", index == 0u ? "" : ", ",
                base + index, suffix);
        }
    }
    used = strlen(text);
    if (used < capacity) {
        (void)snprintf(text + used, capacity - used, "}");
    }
}

static void expected_format(
    char text[192],
    const mova_descriptor *descriptor,
    unsigned vertical,
    unsigned selector,
    unsigned list_group,
    unsigned slice_group)
{
    char tile[80];
    char list[80] = "";
    unsigned count_log2 = descriptor->count == 4u ? 2u : 1u;
    unsigned group_offset_bits = 4u
            > (unsigned)descriptor->size + count_log2
        ? 4u - descriptor->size - count_log2 : 0u;
    unsigned tile_number = group_offset_bits == 0u ? slice_group
        : slice_group >> group_offset_bits;
    unsigned offset = descriptor->whole_array ? slice_group
        : group_offset_bits == 0u ? 0u
        : (slice_group & ((1u << group_offset_bits) - 1u))
            * descriptor->count;

    append_zlist_text(list, sizeof(list),
        list_group * descriptor->count,
        descriptor->count, descriptor->suffix);
    if (descriptor->whole_array) {
        (void)snprintf(tile, sizeof(tile),
            "za.d[w%u, %u, vgx%u]", 8u + selector,
            offset, descriptor->count);
    } else {
        (void)snprintf(tile, sizeof(tile),
            "za%u%c.%c[w%u, %u:%u]", tile_number,
            vertical ? 'v' : 'h', descriptor->suffix,
            12u + selector, offset, offset + descriptor->count - 1u);
    }
    (void)snprintf(text, 192u, "mov %s, %s",
        descriptor->extract ? list : tile,
        descriptor->extract ? tile : list);
}

static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[192];
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
        unsigned vertical_limit = descriptor->whole_array ? 1u : 2u;
        unsigned vertical;

        for (vertical = 0u; vertical < vertical_limit; ++vertical) {
            unsigned selector;

            for (selector = 0u; selector < 4u; ++selector) {
                unsigned slice;

                for (slice = 0u;
                     slice < descriptor->slice_values; ++slice) {
                    unsigned list_group = (slice + selector)
                        % (32u / descriptor->count);
                    uint32_t word = mova_word(descriptor, vertical,
                        selector, list_group, slice);
                    char expected[192];

                    expected_format(expected, descriptor, vertical,
                        selector, list_group, slice);
                    expect_format(word, expected);
                }
            }
        }
    }
}

static void expect_invalid_format(cdisasm_arm_instruction *instruction)
{
    char text[192];

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
    uint32_t word = mova_word(&descriptors[15], 1u, 2u, 5u, 3u);

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
    REJECT_FORGED(forged.form_id = UINT16_C(3888));
    REJECT_FORGED(forged.name_id = CDISASM_ARM_NAME_MOVA);
    REJECT_FORGED(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_FORGED(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED);
    REJECT_FORGED(forged.operand_count = 1u);
    REJECT_FORGED(forged.operand[0].reg = CDISASM_ARM_REG_Z16);
    REJECT_FORGED(forged.operand[0].register_list = UINT16_C(0x0102));
    REJECT_FORGED(forged.operand[0].extend_type = 8u);
    REJECT_FORGED(forged.operand[0].access = CDISASM_OPERAND_ACCESS_READ);
    REJECT_FORGED(forged.operand[1].reg = CDISASM_ARM_REG_ZAH0);
    REJECT_FORGED(forged.operand[1].base_reg = CDISASM_ARM_REG_W15);
    REJECT_FORGED(forged.operand[1].register_list = 2u);
    REJECT_FORGED(forged.operand[1].imm = 0u);
    REJECT_FORGED(forged.operand[1].flags = 0u);
    REJECT_FORGED(forged.operand[1].access
        = CDISASM_OPERAND_ACCESS_READ_WRITE);

#undef REJECT_FORGED

    word = mova_word(&descriptors[9], 0u, 3u, 7u, 7u);
    memset(&good, 0xa5, sizeof(good));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &good) == 4u);
    forged = good;
    forged.operand[0].base_reg = CDISASM_ARM_REG_W10;
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[0].register_list = 2u;
    expect_invalid_format(&forged);
    forged = good;
    forged.operand[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    expect_invalid_format(&forged);
}
#endif

int main(void)
{
    test_bounded_exhaustive_fields();
    test_reserved_quad_slice_bits();
    test_exact_mask_boundaries();
    test_cpu_profiles();
    test_transport_and_modes();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
    test_formatter_rejects_forged_metadata();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM SME2 multi-register MOVA test(s) failed\n",
            failures);
        return 1;
    }
    printf("ARM SME2 multi-register MOV/MOVA tests passed "
           "(USE_EXTRA_OPCODES=%d, checked=12288)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
