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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",         \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VBLENDPD == UINT16_C(1476)
        && CDISASM_X86_NAME_VBLENDPS == UINT16_C(1477),
    "VBLEND name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37),
    "VBLEND ISA-set group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VBLEND runtime-bit ID changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VBLEND profile sweep");

static const uint8_t blend_opcodes[2] = {UINT8_C(0x0d), UINT8_C(0x0c)};
#if USE_EXTRA_OPCODES
static const cdisasm_x86_name_id blend_names[2] = {
    CDISASM_X86_NAME_VBLENDPD, CDISASM_X86_NAME_VBLENDPS
};
static const cdisasm_x86_form_id blend_bases[2] = {
    UINT16_C(3527), UINT16_C(3531)
};
#endif

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
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu_id, mode, code, size, UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static void expect_error(
    const char *label,
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu_id, mode, code, size, flags, &decoded_size);

    if (decoded_size != 0u || !is_error_only(&instruction, status)) {
        fprintf(stderr, "%s: got size/status %u/%u, expected 0/%u\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id,
            (unsigned int)status);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

static cdisasm_x86_decode_flags all_flags(cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, mode, &flags) == CDISASM_STATUS_OK);
    return flags;
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags avx_flags(void)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_AVX));
    return flags;
}
#endif

#if USE_EXTRA_OPCODES
static cdisasm_x86_form_id expected_form(
    unsigned int family,
    unsigned int l,
    int register_form)
{
    return (cdisasm_x86_form_id)(blend_bases[family] + 2u * l
        + (register_form ? 1u : 0u));
}

static cdisasm_x86_reg_id vector_reg(
    unsigned int l,
    unsigned int index)
{
    return (cdisasm_x86_reg_id)(
        (l != 0u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0)
        + index);
}

static void check_vblend(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    unsigned int family,
    unsigned int l,
    int register_form,
    unsigned int destination,
    unsigned int source1,
    unsigned int source2,
    uint64_t immediate)
{
    const unsigned int vector_size = l != 0u ? 32u : 16u;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == blend_names[family]);
    EXPECT(instruction->form_id
        == expected_form(family, l, register_form));
    EXPECT(instruction->operand_count == 4u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
        == CDISASM_PREFIX_VEX);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 1u);
    EXPECT(instruction->encoding.immediate_offset[0]
        == decoded_size - UINT32_C(1));
    EXPECT(instruction->encoding.selector_offset == 0u);

    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg == vector_reg(l, destination));
    EXPECT(instruction->opcode[0].size == vector_size);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[0].flags == 0u);
    EXPECT(instruction->opcode[0].broadcast
        == CDISASM_X86_BROADCAST_NONE);

    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg == vector_reg(l, source1));
    EXPECT(instruction->opcode[1].size == vector_size);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].flags == 0u);
    EXPECT(instruction->opcode[1].broadcast
        == CDISASM_X86_BROADCAST_NONE);

    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[2].size == vector_size);
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].broadcast
        == CDISASM_X86_BROADCAST_NONE);
    if (register_form) {
        EXPECT(instruction->opcode[2].reg == vector_reg(l, source2));
        EXPECT(instruction->opcode[2].flags == 0u);
    } else {
        EXPECT((instruction->opcode[2].flags
            & (CDISASM_OPERAND_FLAG_IMPLICIT
                | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
    }

    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[3].size == 1u);
    EXPECT(instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[3].flags == 0u);
    EXPECT(instruction->opcode[3].imm == immediate);
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2));
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    unsigned int family,
    unsigned int l,
    int register_form)
{
#if USE_EXTRA_OPCODES
    const unsigned int vector_size = l != 0u ? 32u : 16u;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == blend_names[family]);
    EXPECT(instruction->form_id
        == expected_form(family, l, register_form));
    EXPECT(instruction->operand_count == 4u);
    EXPECT(instruction->opcode[0].size == vector_size);
    EXPECT(instruction->opcode[1].size == vector_size);
    EXPECT(instruction->opcode[2].size == vector_size);
    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[3].size == 1u);
    EXPECT(instruction->encoding.immediate_count == 1u);
    EXPECT(instruction->encoding.immediate_offset[0]
        == decoded_size - UINT32_C(1));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2));
#else
    (void)family;
    (void)l;
    (void)register_form;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint64_t expected_form_counts[8] = {
        UINT64_C(73728), UINT64_C(24576),
        UINT64_C(73728), UINT64_C(24576),
        UINT64_C(73728), UINT64_C(24576),
        UINT64_C(73728), UINT64_C(24576)
    };
    uint64_t form_counts[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        const unsigned int p0_count = long_mode ? 8u : 2u;
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
        unsigned int p0_index;

        for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
            const uint8_t p0 = long_mode
                ? (uint8_t)((p0_index << 5) | 3u)
                : (uint8_t)(0xc3u | (p0_index << 5));
            unsigned int family;

            for (family = 0u; family < 2u; ++family) {
                unsigned int w;

                for (w = 0u; w < 2u; ++w) {
                    unsigned int l;

                    for (l = 0u; l < 2u; ++l) {
                        unsigned int pp;

                        for (pp = 0u; pp < 4u; ++pp) {
                            unsigned int vvvv;

                            for (vvvv = 0u; vvvv < 16u; ++vvvv) {
                                unsigned int modrm;

                                for (modrm = 0u; modrm <= UINT8_MAX;
                                     ++modrm) {
                                    const int register_form =
                                        (modrm & UINT8_C(0xc0))
                                            == UINT8_C(0xc0);
                                    const int valid = pp == 1u;
                                    const uint8_t code[15] = {
                                        0xc4, p0,
                                        (uint8_t)((w << 7)
                                            | (((~vvvv) & 15u) << 3)
                                            | (l << 2) | pp),
                                        blend_opcodes[family],
                                        (uint8_t)modrm, 0x24, 0x10, 0x20,
                                        0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                                        0x90
                                    };
                                    uint32_t decoded_size;
                                    cdisasm_instruction instruction = decode(
                                        CDISASM_CPU_X86, modes[mode_index],
                                        code, sizeof(code), &flags,
                                        &decoded_size);

                                    if (valid) {
                                        const unsigned int form_index =
                                            family * 4u + l * 2u
                                            + (register_form ? 1u : 0u);

                                        ++allocated;
                                        ++form_counts[form_index];
                                        check_allocated(
                                            &instruction, decoded_size,
                                            family, l, register_form);
                                    } else {
                                        ++reserved;
                                        EXPECT(decoded_size == 0u);
                                        EXPECT(is_error_only(
                                            &instruction,
                                            CDISASM_STATUS_INVALID_INSTRUCTION));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT64_C(393216));
    EXPECT(reserved == UINT64_C(1179648));
    EXPECT(allocated + reserved == UINT64_C(1572864));
    for (mode_index = 0u; mode_index < 8u; ++mode_index) {
        EXPECT(form_counts[mode_index] == expected_form_counts[mode_index]);
    }
}

static void test_exact_metadata(void)
{
    static const struct blend_case {
        uint8_t code[11];
        uint8_t size;
        uint8_t family;
        uint8_t l;
        uint8_t register_form;
        uint8_t destination;
        uint8_t source1;
        uint8_t source2;
        uint8_t immediate;
    } cases[] = {
        {{0xc4, 0xe3, 0x71, 0x0d, 0x00, 0x5a}, 6, 0, 0, 0,
            0, 1, 0, 0x5a},
        {{0xc4, 0xe3, 0x69, 0x0d, 0xcb, 0xa5}, 6, 0, 0, 1,
            1, 2, 3, 0xa5},
        {{0xc4, 0xe3, 0x75, 0x0d, 0x40, 0x7f, 0xc3}, 7, 0, 1, 0,
            0, 1, 0, 0xc3},
        {{0xc4, 0xe3, 0xed, 0x0d, 0xcb, 0x3c}, 6, 0, 1, 1,
            1, 2, 3, 0x3c},
        {{0xc4, 0xe3, 0x71, 0x0c, 0x00, 0x5a}, 6, 1, 0, 0,
            0, 1, 0, 0x5a},
        {{0xc4, 0xe3, 0xe9, 0x0c, 0xcb, 0xa5}, 6, 1, 0, 1,
            1, 2, 3, 0xa5},
        {{0xc4, 0xe3, 0x75, 0x0c, 0x40, 0x7f, 0xc3}, 7, 1, 1, 0,
            0, 1, 0, 0xc3},
        {{0xc4, 0xe3, 0xed, 0x0c, 0xcb, 0x3c}, 6, 1, 1, 1,
            1, 2, 3, 0x3c},
        {{0xc4, 0x43, 0x69, 0x0d, 0xfb, 0xc3}, 6, 0, 0, 1,
            15, 2, 11, 0xc3},
        {{0xc4, 0x03, 0x35, 0x0c, 0x44, 0xa5, 0x80, 0x7e}, 8,
            1, 1, 0, 8, 9, 0, 0x7e}
    };
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);

#if USE_EXTRA_OPCODES
        check_vblend(&instruction, decoded_size,
            cases[index].family, cases[index].l,
            cases[index].register_form, cases[index].destination,
            cases[index].source1, cases[index].source2,
            cases[index].immediate);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_feature_and_profile_gates(void)
{
    static const uint8_t xmm[] = {0xc4, 0xe3, 0x69, 0x0c, 0xcb, 0x5a};
    static const uint8_t ymm[] = {0xc4, 0xe3, 0x6d, 0x0d, 0xcb, 0xa5};
    cdisasm_x86_decode_flags none =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags avx = avx_flags();
#endif
    cdisasm_x86_cpu_id cpu_id;

#if USE_EXTRA_OPCODES
    for (cpu_id = CDISASM_CPU_FIRST; cpu_id <= CDISASM_CPU_LAST; ++cpu_id) {
        cdisasm_x86_decode_flags flags =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        uint32_t decoded_size;
        cdisasm_instruction instruction;
        int has_avx;

        if (cdisasm_x86_cpu_decode_flag_mask(
                cpu_id, CDISASM_MODE_64, &flags) != CDISASM_STATUS_OK) {
            continue;
        }
        has_avx = cdisasm_decode_flags_test_bit(
            &flags, CDISASM_X86_DECODE_BIT_AVX);
        instruction = decode(cpu_id, CDISASM_MODE_64,
            ymm, sizeof(ymm), &flags, &decoded_size);
        if (has_avx) {
            EXPECT(decoded_size == sizeof(ymm));
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VBLENDPD);
            EXPECT(instruction.form_id == UINT16_C(3530));
        } else {
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        }
    }

    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            xmm, sizeof(xmm), &avx, &decoded_size);

        EXPECT(decoded_size == sizeof(xmm));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VBLENDPS);
        EXPECT(instruction.form_id == UINT16_C(3532));
    }
    expect_error("VBLEND requires AVX", CDISASM_CPU_X86,
        CDISASM_MODE_64, xmm, sizeof(xmm), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    (void)cpu_id;
    expect_error("VBLEND extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, xmm, sizeof(xmm), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("YMM VBLEND extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, ymm, sizeof(ymm), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VBLEND without feature extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, xmm, sizeof(xmm), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_structure_and_truncation(void)
{
    static const struct invalid_case {
        const char *label;
        uint8_t code[9];
        uint8_t size;
        cdisasm_status status;
    } cases[] = {
        {"VBLENDPS pp0", {0xc4, 0xe3, 0x68, 0x0c, 0xc2, 0x5a}, 6,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"VBLENDPS pp2", {0xc4, 0xe3, 0x6a, 0x0c, 0xc2, 0x5a}, 6,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"VBLENDPD pp3", {0xc4, 0xe3, 0x6b, 0x0d, 0xc2, 0x5a}, 6,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"prefixed VBLEND", {0x66, 0xc4, 0xe3, 0x69, 0x0c, 0xc2, 0x5a}, 7,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"truncated ModRM", {0xc4, 0xe3, 0x69, 0x0c}, 4,
            CDISASM_STATUS_TRUNCATED},
        {"truncated imm8", {0xc4, 0xe3, 0x69, 0x0d, 0xc2}, 5,
            CDISASM_STATUS_TRUNCATED},
        {"reserved pp truncated SIB", {0xc4, 0xe3, 0x68, 0x0c, 0x04}, 5,
            CDISASM_STATUS_TRUNCATED},
        {"prefixed truncated imm8", {0x66, 0xc4, 0xe3, 0x69, 0x0d, 0xc2}, 6,
            CDISASM_STATUS_TRUNCATED}
    };
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error(cases[index].label, CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, cases[index].size,
            &flags, cases[index].status);
    }
}

static void test_nonlong_vex_and_les(void)
{
    static const uint8_t vex_b0[] =
        {0xc4, 0xc3, 0x69, 0x0c, 0xcb, 0x5a};
    static const uint8_t vex_b1[] =
        {0xc4, 0xe3, 0xe9, 0x0d, 0xcb, 0xa5};
    static const uint8_t les[] = {0xc4, 0x03, 0x69, 0x0c, 0xcb, 0x5a};
    static const cdisasm_x86_mode modes[2] = {
        CDISASM_MODE_16, CDISASM_MODE_32
    };
    size_t index;

    for (index = 0u; index < 2u; ++index) {
        cdisasm_x86_decode_flags flags = all_flags(modes[index]);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, modes[index], vex_b0, sizeof(vex_b0),
            &flags, &decoded_size);

#if USE_EXTRA_OPCODES
        check_vblend(&instruction, decoded_size, 1u, 0u, 1,
            1u, 2u, 3u, UINT64_C(0x5a));
        instruction = decode(CDISASM_CPU_X86, modes[index],
            vex_b1, sizeof(vex_b1), &flags, &decoded_size);
        check_vblend(&instruction, decoded_size, 0u, 0u, 1,
            1u, 2u, 3u, UINT64_C(0xa5));
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
        instruction = decode(CDISASM_CPU_X86, modes[index],
            vex_b1, sizeof(vex_b1), &flags, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

        instruction = decode(CDISASM_CPU_X86, modes[index], les, sizeof(les),
            &flags, &decoded_size);
        EXPECT(decoded_size == 2u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        EXPECT(instruction.operand_count == 2u);
    }
}

#if USE_DISASM_FORMAT && USE_EXTRA_OPCODES
static void expect_forged_format_rejected(
    const cdisasm_instruction *instruction)
{
    char output[96] = {'x', 'x', 'x', 'x'};

    EXPECT(cdisasm_x86_format(instruction,
        CDISASM_FORMAT_SYNTAX_INTEL, NULL, 0u) == 0u);
    EXPECT(cdisasm_x86_format(instruction,
        CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
}

static void test_formatting_and_schema(void)
{
    static const struct format_case {
        uint8_t code[11];
        uint8_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4, 0xe3, 0x71, 0x0c, 0xc2, 0x5a}, 6,
            "vblendps xmm0, xmm1, xmm2, 0x5a",
            "vblendps $0x5a, %xmm2, %xmm1, %xmm0"},
        {{0xc4, 0xe3, 0x75, 0x0d, 0x40, 0x80, 0xc3}, 7,
            "vblendpd ymm0, ymm1, ymmword ptr [rax - 0x80], 0xc3",
            "vblendpd $0xc3, -0x80(%rax), %ymm1, %ymm0"},
        {{0xc4, 0x03, 0x35, 0x0c, 0x44, 0xa5, 0x80, 0x7e}, 8,
            "vblendps ymm8, ymm9, ymmword ptr [r13 + r12*4 - 0x80], 0x7e",
            "vblendps $0x7e, -0x80(%r13,%r12,4), %ymm9, %ymm8"}
    };
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        char output[192];
        size_t required;

        EXPECT(decoded_size == cases[index].size);
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output));
        EXPECT(required == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT, output, sizeof(output));
        EXPECT(required == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);
    }

    {
        static const uint8_t code[] =
            {0xc4, 0xe3, 0x71, 0x0c, 0xc2, 0x5a};
        uint32_t decoded_size;
        cdisasm_instruction valid = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(code));
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VBLENDPD;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(3527);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.operand_count = 3u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |= CDISASM_PREFIX_XOP;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |= CDISASM_PREFIX_LOCK;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_AVX2;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.immediate_count = 0u;
        forged.encoding.immediate_offset[0] = 0u;
        forged.encoding.immediate_size[0] = 0u;
        --forged.opcode_size;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.modrm_offset = 0u;
        forged.encoding.modrm = 0u;
        forged.encoding.immediate_offset[0] = 4u;
        forged.opcode_size = 5u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].size = 32u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[3].imm = UINT64_C(0x100);
        expect_forged_format_rejected(&forged);
    }

    {
        static const uint8_t code[] =
            {0xc4, 0xe3, 0x71, 0x0c, 0x00, 0x5a};
        uint32_t decoded_size;
        cdisasm_instruction forged = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(code));
        forged.opcode[2].flags |= CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
        expect_forged_format_rejected(&forged);
    }
}
#endif

int main(void)
{
    test_control_partition();
    test_exact_metadata();
    test_feature_and_profile_gates();
    test_structure_and_truncation();
    test_nonlong_vex_and_les();
#if USE_DISASM_FORMAT && USE_EXTRA_OPCODES
    test_formatting_and_schema();
#endif

    if (failures != 0) {
        fprintf(stderr, "x86 VBLEND tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 VBLEND tests passed");
    return 0;
}
