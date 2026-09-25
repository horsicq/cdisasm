#include "cdisasm/cdisasm_x86.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            if (failures < 64) {                                             \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",          \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VPSHUFD == UINT16_C(1909)
        && CDISASM_X86_NAME_VPSHUFHW == UINT16_C(1910)
        && CDISASM_X86_NAME_VPSHUFLW == UINT16_C(1911),
    "VPSHUF integer name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "VPSHUF integer capability IDs changed");

typedef struct shuffle_family {
    uint8_t prefix;
    cdisasm_x86_name_id name;
    cdisasm_x86_form_id base;
} shuffle_family;

static const shuffle_family families[3] = {
    {1u, CDISASM_X86_NAME_VPSHUFD, 7891},
    {2u, CDISASM_X86_NAME_VPSHUFHW, 7901},
    {3u, CDISASM_X86_NAME_VPSHUFLW, 7911}};

static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static cdisasm_instruction decode(
    cdisasm_cpu_id cpu,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu, mode, code, size, UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static void expect_error(
    const char *label,
    cdisasm_cpu_id cpu,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu, mode, code, size, flags, &decoded_size);

    if (decoded_size != 0u || !is_error_only(&instruction, status)) {
        fprintf(stderr, "%s: got size/status %u/%u, expected 0/%u\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id, (unsigned int)status);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags all_flags(cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, mode, &flags) == CDISASM_STATUS_OK);
    return flags;
}

static cdisasm_x86_decode_flags selected_flags(int avx, int avx2)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    if (avx) {
        EXPECT(cdisasm_decode_flags_set_bit(
            &flags, CDISASM_X86_DECODE_BIT_AVX));
    }
    if (avx2) {
        EXPECT(cdisasm_decode_flags_set_bit(
            &flags, CDISASM_X86_DECODE_BIT_AVX2));
    }
    return flags;
}

static void check_shuffle(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    const shuffle_family *family,
    unsigned int vector_bits,
    int register_form)
{
    const unsigned int vector_bytes = vector_bits / 8u;
    const cdisasm_x86_reg_id register_base = vector_bits == 256u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    const cdisasm_x86_form_id form = (cdisasm_x86_form_id)(family->base
        + (vector_bits == 256u ? 4u : 0u)
        + (register_form ? 1u : 0u));

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == family->name);
    EXPECT(instruction->form_id == form);
    EXPECT(instruction->operand_count == 3u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
        == CDISASM_PREFIX_VEX);
    EXPECT(instruction->encoding.prefix_size >= 2u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 1u);
    EXPECT(instruction->encoding.immediate_size[0] == 1u);
    EXPECT(instruction->encoding.immediate_offset[0]
        == instruction->opcode_size - 1u);
    EXPECT(instruction->encoding.selector_offset == 0u);

    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].size == vector_bytes);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[0].reg >= register_base
        && instruction->opcode[0].reg <= register_base + 15u);
    EXPECT(instruction->opcode[0].flags == 0u);
    EXPECT(instruction->opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[1].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[1].size == vector_bytes);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
    if (register_form) {
        EXPECT(instruction->opcode[1].reg >= register_base
            && instruction->opcode[1].reg <= register_base + 15u);
        EXPECT(instruction->opcode[1].flags == 0u);
    } else {
        EXPECT((instruction->opcode[1].flags
            & (CDISASM_OPERAND_FLAG_IMPLICIT
                | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
    }
    if (mode != CDISASM_MODE_64) {
        EXPECT(instruction->opcode[0].reg <= register_base + 7u);
        if (register_form) {
            EXPECT(instruction->opcode[1].reg <= register_base + 7u);
        }
    }
    EXPECT(instruction->opcode[2].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[2].size == 1u);
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].flags == 0u);
    EXPECT(instruction->opcode[2].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[2].imm <= UINT8_MAX);
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->branch_target == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT((vector_bits == 256u)
        == cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX2));
}
#endif

static void test_c4_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    uint64_t form_counts[12] = {0u};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        const unsigned int p0_count = long_mode ? 8u : 2u;
        unsigned int p0_index;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

        for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
            const uint8_t p0 = long_mode
                ? (uint8_t)((p0_index << 5) | 1u)
                : (uint8_t)(0xc1u | (p0_index << 5));
            unsigned int p1;

            for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                const unsigned int source = ((~p1) >> 3) & 15u;
                const uint8_t pp = (uint8_t)p1 & UINT8_C(3);
                const int valid = source == 0u && pp != 0u;
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const uint8_t code[15] = {
                        0xc4,p0,(uint8_t)p1,0x70,(uint8_t)modrm,
                        0x24,0x10,0x20,0x30,0x40,
                        0x50,0x60,0x70,0x80,0x90};
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, modes[mode_index],
                        code, sizeof(code),
#if USE_EXTRA_OPCODES
                        &flags,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (valid) {
#if USE_EXTRA_OPCODES
                        const unsigned int vector_bits =
                            (p1 & UINT8_C(4)) != 0u ? 256u : 128u;
                        const cdisasm_x86_reg_id register_base =
                            vector_bits == 256u
                                ? CDISASM_X86_REG_YMM0
                                : CDISASM_X86_REG_XMM0;
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                        const unsigned int family_index = pp - 1u;
                        const unsigned int slot = family_index * 4u
                            + (vector_bits == 256u ? 2u : 0u)
                            + (register_form ? 1u : 0u);

                        check_shuffle(&instruction, decoded_size,
                            modes[mode_index], &families[family_index],
                            vector_bits, register_form);
                        EXPECT(instruction.encoding.opcode_offset == 3u);
                        EXPECT(instruction.opcode[0].reg
                            == register_base
                                + ((modrm >> 3) & UINT8_C(7))
                                + (long_mode
                                    && (p0 & UINT8_C(0x80)) == 0u
                                    ? 8u : 0u));
                        if (register_form) {
                            EXPECT(instruction.opcode[1].reg
                                == register_base
                                    + (modrm & UINT8_C(7))
                                    + (long_mode
                                        && (p0 & UINT8_C(0x20)) == 0u
                                        ? 8u : 0u));
                        }
                        ++form_counts[slot];
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++allocated;
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++reserved;
                    }
                }
            }
        }
    }
    EXPECT(allocated == UINT64_C(36864));
    EXPECT(reserved == UINT64_C(749568));
#if USE_EXTRA_OPCODES
    for (mode_index = 0u; mode_index < 12u; ++mode_index) {
        EXPECT(form_counts[mode_index]
            == (mode_index % 2u == 0u
                ? UINT64_C(4608) : UINT64_C(1536)));
    }
#else
    (void)form_counts;
#endif
}

static void test_c5_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    uint64_t form_counts[12] = {0u};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        const unsigned int p1_first = long_mode ? 0u : UINT8_C(0xc0);
        unsigned int p1;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

        for (p1 = p1_first; p1 <= UINT8_MAX; ++p1) {
            const unsigned int source = ((~p1) >> 3) & 15u;
            const uint8_t pp = (uint8_t)p1 & UINT8_C(3);
            const int valid = source == 0u && pp != 0u;
            unsigned int modrm;

            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                const uint8_t code[15] = {
                    0xc5,(uint8_t)p1,0x70,(uint8_t)modrm,
                    0x24,0x10,0x20,0x30,0x40,0x50,
                    0x60,0x70,0x80,0x90,0xa0};
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, modes[mode_index],
                    code, sizeof(code),
#if USE_EXTRA_OPCODES
                    &flags,
#else
                    NULL,
#endif
                    &decoded_size);

                if (valid) {
#if USE_EXTRA_OPCODES
                    const unsigned int vector_bits =
                        (p1 & UINT8_C(4)) != 0u ? 256u : 128u;
                    const cdisasm_x86_reg_id register_base =
                        vector_bits == 256u
                            ? CDISASM_X86_REG_YMM0
                            : CDISASM_X86_REG_XMM0;
                    const int register_form =
                        (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                    const unsigned int family_index = pp - 1u;
                    const unsigned int slot = family_index * 4u
                        + (vector_bits == 256u ? 2u : 0u)
                        + (register_form ? 1u : 0u);

                    check_shuffle(&instruction, decoded_size,
                        modes[mode_index], &families[family_index],
                        vector_bits, register_form);
                    EXPECT(instruction.encoding.opcode_offset == 2u);
                    EXPECT(instruction.opcode[0].reg
                        == register_base
                            + ((modrm >> 3) & UINT8_C(7))
                            + (long_mode
                                && (p1 & UINT8_C(0x80)) == 0u
                                ? 8u : 0u));
                    if (register_form) {
                        EXPECT(instruction.opcode[1].reg
                            == register_base + (modrm & UINT8_C(7)));
                    }
                    ++form_counts[slot];
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    ++allocated;
                } else {
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_INVALID_INSTRUCTION));
                    ++reserved;
                }
            }
        }
    }
    EXPECT(allocated == UINT64_C(6144));
    EXPECT(reserved == UINT64_C(92160));
#if USE_EXTRA_OPCODES
    for (mode_index = 0u; mode_index < 12u; ++mode_index) {
        EXPECT(form_counts[mode_index]
            == (mode_index % 2u == 0u
                ? UINT64_C(768) : UINT64_C(256)));
    }
#else
    (void)form_counts;
#endif
}

static void test_exact_forms_immediates_and_gates(void)
{
    size_t family_index;

    for (family_index = 0u; family_index < 3u; ++family_index) {
        unsigned int width;

        for (width = 0u; width < 2u; ++width) {
            unsigned int register_form;

            for (register_form = 0u; register_form < 2u; ++register_form) {
                unsigned int value;

                for (value = 0u; value <= UINT8_MAX; ++value) {
                    const uint8_t code[6] = {
                        0xc4,0xe1,
                        (uint8_t)(0xf8u | (width << 2)
                            | families[family_index].prefix),
                        0x70,
                        register_form != 0u ? UINT8_C(0xc2) : UINT8_C(0x00),
                        (uint8_t)value};
#if USE_EXTRA_OPCODES
                    cdisasm_x86_decode_flags flags =
                        all_flags(CDISASM_MODE_64);
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, sizeof(code), &flags, &decoded_size);

                    EXPECT(decoded_size == sizeof(code));
                    EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
                        families[family_index].base + width * 4u
                        + register_form));
                    EXPECT(instruction.opcode[2].imm == value);
#else
                    expect_error("VPSHUF integer extras off",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, sizeof(code), NULL,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
            }
        }
    }

#if USE_EXTRA_OPCODES
    {
        const cdisasm_x86_decode_flags none = selected_flags(0, 0);
        const cdisasm_x86_decode_flags avx = selected_flags(1, 0);
        const cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);
        const uint8_t xmm[] = {0xc5,0xf9,0x70,0xc2,0x1b};
        const uint8_t ymm[] = {0xc5,0xfd,0x70,0xc2,0x1b};
        cdisasm_x86_decode_flags available;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        expect_error("XMM VPSHUFD needs AVX", CDISASM_CPU_X86,
            CDISASM_MODE_64, xmm, sizeof(xmm), &none,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX2 alone does not admit XMM VPSHUFD",
            CDISASM_CPU_X86, CDISASM_MODE_64, xmm, sizeof(xmm), &avx2,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("YMM VPSHUFD needs AVX2", CDISASM_CPU_X86,
            CDISASM_MODE_64, ymm, sizeof(ymm), &avx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            xmm, sizeof(xmm), &avx, &decoded_size);
        EXPECT(decoded_size == sizeof(xmm));
        EXPECT(instruction.form_id == UINT16_C(7892));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            ymm, sizeof(ymm), &avx2, &decoded_size);
        EXPECT(decoded_size == sizeof(ymm));
        EXPECT(instruction.form_id == UINT16_C(7896));
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
            xmm, sizeof(xmm), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(xmm));
        EXPECT(instruction.form_id == UINT16_C(7892));
        expect_error("Sandy Bridge YMM VPSHUFD",
            CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
            ymm, sizeof(ymm), NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_HASWELL, CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_HASWELL, CDISASM_MODE_64,
            ymm, sizeof(ymm), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(ymm));
    }
#endif
}

static void test_payload_aliases_and_siblings(void)
{
    static const struct {
        const char *label;
        uint8_t code[8];
    } reserved_u0_controls[] = {
        {"EVEX U0 VPSHUF LL=3",
         {0x62,0xf1,0x79,0x68,0x70,0x04,0x03,0x1b}},
        {"EVEX U0 VPSHUF z with k0",
         {0x62,0xf1,0x79,0x88,0x70,0x04,0x03,0x1b}},
        {"EVEX U0 VPSHUF reserved vvvv",
         {0x62,0xf1,0x71,0x08,0x70,0x04,0x03,0x1b}},
        {"EVEX U0 VPSHUF reserved V-prime",
         {0x62,0xf1,0x79,0x00,0x70,0x04,0x03,0x1b}},
        {"EVEX U0 VPSHUFD W=1",
         {0x62,0xf1,0xf9,0x08,0x70,0x04,0x03,0x1b}},
        {"EVEX U0 VPSHUFHW broadcast control",
         {0x62,0xf1,0x7a,0x18,0x70,0x04,0x03,0xa5}},
        {"EVEX U0 VPSHUFLW broadcast control",
         {0x62,0xf1,0x7b,0x18,0x70,0x04,0x03,0x7f}}
    };
    const uint8_t c5[] = {0xc5,0xf9,0x70,0xc2,0x1b};
    const uint8_t c4[] = {0xc4,0xe1,0xf9,0x70,0xc2,0x1b};
    const uint8_t evex_b4_memory[] = {
        0x62,0xf9,0x7d,0x08,0x70,0x01,0x1b};
    const uint8_t evex_u0_memory[] = {
        0x62,0xf1,0x79,0x08,0x70,0x04,0x03,0x1b};
    const uint8_t evex_u0_register[] = {
        0x62,0xf1,0x79,0x08,0x70,0xc1,0x1b};
    const uint8_t evex_u0_legacy_prefix[] = {
        0x66,0x62,0xf1,0x79,0x08,0x70,0x04,0x03,0x1b};
    size_t control_index;
    size_t size;

    for (size = 1u; size < sizeof(c5); ++size) {
        expect_error("truncated C5 VPSHUF integer", CDISASM_CPU_X86,
            CDISASM_MODE_64, c5, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    for (size = 1u; size < sizeof(c4); ++size) {
        expect_error("truncated C4 VPSHUF integer", CDISASM_CPU_X86,
            CDISASM_MODE_64, c4, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    expect_error("reserved pp missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf8,0x70,0x04}, 4u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp missing immediate", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf8,0x70,0x04,0x24}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf8,0x70,0x04,0x24,0x1b}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved vvvv missing immediate", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf1,0x70,0xc2}, 4u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("reserved vvvv complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf1,0x70,0xc2,0x1b}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy prefix missing immediate", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc4,0xe1,0xf9,0x70,0xc2}, 6u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("legacy prefix complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc4,0xe1,0xf9,0x70,0xc2,0x1b}, 7u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

    for (size = 1u; size < sizeof(evex_u0_memory); ++size) {
        expect_error("truncated EVEX/APX U0 VPSHUF memory",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_u0_memory, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    for (size = 1u; size < sizeof(evex_u0_register); ++size) {
        expect_error("truncated EVEX/APX U0 VPSHUF register",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_u0_register, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    expect_error("reserved EVEX U0 VPSHUF register",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        evex_u0_register, sizeof(evex_u0_register), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    for (size = 1u; size < sizeof(evex_b4_memory); ++size) {
        expect_error("truncated EVEX/APX B4 VPSHUF memory",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_b4_memory, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    for (control_index = 0u;
            control_index < sizeof(reserved_u0_controls)
                / sizeof(reserved_u0_controls[0]);
            ++control_index) {
        expect_error(reserved_u0_controls[control_index].label,
            CDISASM_CPU_X86, CDISASM_MODE_64,
            reserved_u0_controls[control_index].code,
            sizeof(reserved_u0_controls[control_index].code) - 1u,
            NULL, CDISASM_STATUS_TRUNCATED);
        expect_error(reserved_u0_controls[control_index].label,
            CDISASM_CPU_X86, CDISASM_MODE_64,
            reserved_u0_controls[control_index].code,
            sizeof(reserved_u0_controls[control_index].code),
            NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("legacy-prefix EVEX/APX VPSHUF missing immediate",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        evex_u0_legacy_prefix, sizeof(evex_u0_legacy_prefix) - 1u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("legacy-prefix EVEX/APX VPSHUF complete",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        evex_u0_legacy_prefix, sizeof(evex_u0_legacy_prefix),
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        const uint8_t c4_alias[] = {0xc4,0xc1,0xf9,0x70,0xc1,0x1b};
        const uint8_t high[] = {0xc4,0x41,0xfd,0x70,0xcb,0xa5};
        const uint8_t legacy_d[] = {0x66,0x0f,0x70,0xc1,0x1b};
        const uint8_t legacy_hw[] = {0xf3,0x0f,0x70,0xc1,0x1b};
        const uint8_t legacy_lw[] = {0xf2,0x0f,0x70,0xc1,0x1b};
        const uint8_t evex_d[] = {0x62,0xf1,0x7d,0x08,0x70,0xc1,0x1b};
        const uint8_t evex_hw[] = {0x62,0xf1,0x7e,0x08,0x70,0xc1,0x1b};
        const uint8_t evex_lw[] = {0x62,0xf1,0x7f,0x08,0x70,0xc1,0x1b};
        cdisasm_x86_decode_flags flags16 = all_flags(CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
        cdisasm_x86_decode_flags no_apx = flags64;
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_16, c4_alias, sizeof(c4_alias),
            &flags16, &decoded_size);

        EXPECT(decoded_size == sizeof(c4_alias));
        EXPECT(instruction.form_id == UINT16_C(7892));
        EXPECT(cdisasm_decode_flags_clear_bit(
            &no_apx, CDISASM_X86_DECODE_BIT_APX));
        expect_error("EVEX U0 VPSHUF memory requires APX",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_u0_memory, sizeof(evex_u0_memory), &no_apx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("EVEX B4 VPSHUF memory requires APX",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_b4_memory, sizeof(evex_b4_memory), &no_apx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_u0_memory, sizeof(evex_u0_memory),
            &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(evex_u0_memory));
        EXPECT(instruction.form_id == UINT16_C(7893));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            high, sizeof(high), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(high));
        EXPECT(instruction.form_id == UINT16_C(7896));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM9);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM11);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_d, sizeof(legacy_d), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_d));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PSHUFD);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_hw, sizeof(legacy_hw), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_hw));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PSHUFHW);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_lw, sizeof(legacy_lw), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_lw));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PSHUFLW);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_d, sizeof(evex_d), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(evex_d));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPSHUFD);
        EXPECT(instruction.form_id == UINT16_C(7894));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_hw, sizeof(evex_hw), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(evex_hw));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPSHUFHW);
        EXPECT(instruction.form_id == UINT16_C(7904));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_lw, sizeof(evex_lw), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(evex_lw));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPSHUFLW);
        EXPECT(instruction.form_id == UINT16_C(7914));
    }
#else
    expect_error("EVEX U0 VPSHUF memory extras off",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        evex_u0_memory, sizeof(evex_u0_memory), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("EVEX B4 VPSHUF memory extras off",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        evex_b4_memory, sizeof(evex_b4_memory), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format_rejected(const cdisasm_instruction *instruction)
{
    char output[160] = {'x'};

    EXPECT(cdisasm_x86_format(instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
    output[0] = 'x';
    EXPECT(cdisasm_x86_format(instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
}

static void test_generated_evex_formatter_preservation(void)
{
    static const cdisasm_x86_group_id groups[3][3] = {
        {CDISASM_X86_GROUP_AVX512F_128,
         CDISASM_X86_GROUP_AVX512F_256,
         CDISASM_X86_GROUP_AVX512F_512},
        {CDISASM_X86_GROUP_AVX512BW_128,
         CDISASM_X86_GROUP_AVX512BW_256,
         CDISASM_X86_GROUP_AVX512BW_512},
        {CDISASM_X86_GROUP_AVX512BW_128,
         CDISASM_X86_GROUP_AVX512BW_256,
         CDISASM_X86_GROUP_AVX512BW_512}};
    static const uint8_t evex_offsets[3] = {2u, 6u, 8u};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t family_index;

    /* Exercise all 18 generated same-name EVEX siblings, including each
     * architecturally legal masking mode.  These rows must remain printable
     * even though the classic-VEX names are now owned by an exact schema. */
    for (family_index = 0u; family_index < 3u; ++family_index) {
        unsigned int width;

        for (width = 0u; width < 3u; ++width) {
            unsigned int register_form;

            for (register_form = 0u; register_form < 2u; ++register_form) {
                unsigned int mask;

                for (mask = 0u; mask < 3u; ++mask) {
                    const uint8_t mask_bits = mask == 0u
                        ? UINT8_C(0) : (mask == 1u
                            ? UINT8_C(1) : UINT8_C(0x81));
                    const uint8_t code[7] = {
                        0x62,0xf1,
                        (uint8_t)(0x7du + family_index),
                        (uint8_t)(0x08u | (width << 5) | mask_bits),
                        0x70,
                        register_form != 0u ? UINT8_C(0xc1) : UINT8_C(0x00),
                        0x1b};
                    const unsigned int vector_size = 16u << width;
                    const cdisasm_x86_reg_id register_base = width == 0u
                        ? CDISASM_X86_REG_XMM0 : (width == 1u
                            ? CDISASM_X86_REG_YMM0
                            : CDISASM_X86_REG_ZMM0);
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, sizeof(code), &flags, &decoded_size);
                    char output[160];

                    EXPECT(decoded_size == sizeof(code));
                    EXPECT(instruction.name_id == families[family_index].name);
                    EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
                        families[family_index].base + evex_offsets[width]
                        + register_form));
                    EXPECT(instruction.opcode_flags
                        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK);
                    EXPECT(instruction.operand_count == 3u);
                    EXPECT(instruction.opcode[0].size == vector_size);
                    EXPECT(instruction.opcode[0].reg == register_base);
                    EXPECT(instruction.opcode[1].type == (register_form != 0u
                        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
                    EXPECT(instruction.x86_group_count == 1u);
                    EXPECT(instruction.x86_group_ids[0]
                        == groups[family_index][width]);
                    EXPECT(instruction.mask_mode == (mask == 0u
                        ? CDISASM_X86_MASK_NONE : (mask == 1u
                            ? CDISASM_X86_MASK_MERGE
                            : CDISASM_X86_MASK_ZERO)));
                    EXPECT(cdisasm_x86_format(&instruction,
                        CDISASM_FORMAT_SYNTAX_INTEL,
                        output, sizeof(output)) != 0u);
                    EXPECT(cdisasm_x86_format(&instruction,
                        CDISASM_FORMAT_SYNTAX_ATT,
                        output, sizeof(output)) != 0u);
                }
            }
        }
    }
}

static void test_generated_evex_apx_formatter(void)
{
    static const struct {
        uint8_t code[8];
        uint8_t size;
        uint8_t family_index;
        uint8_t u0;
    } cases[] = {
        {{0x62,0xf9,0x7d,0x08,0x70,0x01,0x1b}, 7u, 0u, 0u},
        {{0x62,0xf9,0x7e,0x08,0x70,0x01,0xa5}, 7u, 1u, 0u},
        {{0x62,0xf9,0x7f,0x08,0x70,0x01,0x7f}, 7u, 2u, 0u},
        {{0x62,0xf9,0xfe,0x08,0x70,0x01,0xa5}, 7u, 1u, 0u},
        {{0x62,0xf1,0x79,0x08,0x70,0x04,0x03,0x1b}, 8u, 0u, 1u},
        {{0x62,0xf1,0x7a,0x08,0x70,0x04,0x03,0xa5}, 8u, 1u, 1u},
        {{0x62,0xf1,0x7b,0x08,0x70,0x04,0x03,0x7f}, 8u, 2u, 1u},
        {{0x62,0xf1,0xfb,0x08,0x70,0x04,0x03,0x7f}, 8u, 2u, 1u}
    };
    static const struct {
        uint8_t code[8];
        uint8_t size;
        uint8_t u0;
    } broadcasts[] = {
        {{0x62,0xf9,0x7d,0x18,0x70,0x01,0x1b}, 7u, 0u},
        {{0x62,0xf1,0x79,0x18,0x70,0x04,0x03,0x1b}, 8u, 1u}
    };
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    /* P0.B4 and raw U=0/X4 are APX extensions of the generated EVEX
     * siblings.  Their APX_F group is the formatter's provenance for the
     * otherwise-unrepresentable EGPR address bits. */
    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const cdisasm_x86_group_id width_group =
            cases[index].family_index == 0u
                ? CDISASM_X86_GROUP_AVX512F_128
                : CDISASM_X86_GROUP_AVX512BW_128;
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        cdisasm_instruction forged;
        char output[160];

        EXPECT(decoded_size == cases[index].size);
        EXPECT(instruction.name_id
            == families[cases[index].family_index].name);
        EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
            families[cases[index].family_index].base + 2u));
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[1].size == 16u);
        EXPECT(instruction.opcode[1].broadcast
            == CDISASM_X86_BROADCAST_NONE);
        if (cases[index].u0 != 0u) {
            EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RBX);
            EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R16);
            EXPECT(instruction.opcode[1].scale == 1u);
        } else {
            EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R17);
            EXPECT(instruction.opcode[1].index_reg
                == CDISASM_X86_REG_NONE);
        }
        EXPECT(instruction.x86_group_count == 2u);
        EXPECT(instruction.x86_group_ids[0] == CDISASM_X86_GROUP_APX_F);
        EXPECT(instruction.x86_group_ids[1] == width_group);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) != 0u);

        forged = instruction;
        forged.x86_group_ids[0] = forged.x86_group_ids[1];
        forged.x86_group_ids[1] = CDISASM_X86_GROUP_NONE;
        forged.x86_group_count = 1u;
        expect_format_rejected(&forged);
    }

    for (index = 0u;
            index < sizeof(broadcasts) / sizeof(broadcasts[0]);
            ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            broadcasts[index].code, broadcasts[index].size,
            &flags, &decoded_size);
        cdisasm_instruction forged;
        char output[160];

        EXPECT(decoded_size == broadcasts[index].size);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPSHUFD);
        EXPECT(instruction.form_id == UINT16_C(7893));
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[1].size == 4u);
        EXPECT(instruction.opcode[1].broadcast
            == CDISASM_X86_BROADCAST_1_TO_4);
        if (broadcasts[index].u0 != 0u) {
            EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RBX);
            EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R16);
        } else {
            EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R17);
            EXPECT(instruction.opcode[1].index_reg
                == CDISASM_X86_REG_NONE);
        }
        EXPECT(instruction.x86_group_count == 2u);
        EXPECT(instruction.x86_group_ids[0] == CDISASM_X86_GROUP_APX_F);
        EXPECT(instruction.x86_group_ids[1]
            == CDISASM_X86_GROUP_AVX512F_128);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) != 0u);

        forged = instruction;
        forged.x86_group_ids[0] = forged.x86_group_ids[1];
        forged.x86_group_ids[1] = CDISASM_X86_GROUP_NONE;
        forged.x86_group_count = 1u;
        expect_format_rejected(&forged);
    }
}

static void test_formatting_and_schema(void)
{
    const uint8_t code[] = {0xc5,0xfe,0x70,0xc2,0xa5};
    const uint8_t memory[] = {0xc4,0xe1,0xff,0x70,0x00,0x7f};
    const uint8_t evex[] = {0x62,0xf1,0x7d,0x08,0x70,0xc1,0x1b};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &flags, &decoded_size);
    cdisasm_instruction forged;
    char output[160];

    EXPECT(decoded_size == sizeof(code));
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) != 0u);
    EXPECT(strcmp(output, "vpshufhw ymm0, ymm2, 0xa5") == 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output)) != 0u);
    EXPECT(strcmp(output, "vpshufhw $0xa5, %ymm2, %ymm0") == 0);

    forged = instruction;
    forged.name_id = CDISASM_X86_NAME_VPSHUFLW;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.form_id = UINT16_C(7902);
    expect_format_rejected(&forged);
    forged = instruction;
    forged.opcode_flags |= CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.opcode_flags |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.operand_count = 2u;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.opcode[1].size = 16u;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.opcode[2].size = 2u;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.encoding.modrm ^= UINT8_C(0x08);
    expect_format_rejected(&forged);
    forged = instruction;
    forged.encoding.immediate_count = 0u;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.mask_reg = CDISASM_X86_REG_K1;
    expect_format_rejected(&forged);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        memory, sizeof(memory), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(memory));
    EXPECT(instruction.form_id == UINT16_C(7915));
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) != 0u);
    EXPECT(strcmp(output,
        "vpshuflw ymm0, ymmword ptr [rax], 0x7f") == 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        evex, sizeof(evex), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(evex));
    EXPECT(instruction.form_id == UINT16_C(7894));
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) != 0u);
    forged = instruction;
    forged.form_id = UINT16_C(7892);
    expect_format_rejected(&forged);
    forged = instruction;
    forged.opcode_flags &=
        ~CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.operand_count = 0u;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.encoding.immediate_count = 0u;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.x86_group_ids[0] = CDISASM_X86_GROUP_AVX512BW_128;
    expect_format_rejected(&forged);

    {
        const uint8_t broadcast[] = {
            0x62,0xf1,0x7d,0x18,0x70,0x00,0x1b};

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            broadcast, sizeof(broadcast), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(broadcast));
        EXPECT(instruction.form_id == UINT16_C(7893));
        EXPECT(instruction.opcode[1].size == 4u);
        EXPECT(instruction.opcode[1].broadcast
            == CDISASM_X86_BROADCAST_1_TO_4);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);

        /* Canonical single-width-group metadata cannot claim an APX EGPR
         * address.  EGPR is admitted only when the decoder publishes APX_F;
         * the ModRM low bits alone are insufficient provenance. */
        forged = instruction;
        forged.opcode[1].base_reg = CDISASM_X86_REG_R16;
        expect_format_rejected(&forged);
    }

    test_generated_evex_formatter_preservation();
    test_generated_evex_apx_formatter();
}
#else
static void test_formatting_and_schema(void)
{
}
#endif

int main(void)
{
    test_c4_control_partition();
    test_c5_control_partition();
    test_exact_forms_immediates_and_gates();
    test_payload_aliases_and_siblings();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VPSHUF integer test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
