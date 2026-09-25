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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",        \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VUNPCKHPD == UINT16_C(2018)
        && CDISASM_X86_NAME_VUNPCKHPS == UINT16_C(2019)
        && CDISASM_X86_NAME_VUNPCKLPD == UINT16_C(2020)
        && CDISASM_X86_NAME_VUNPCKLPS == UINT16_C(2021),
    "VUNPCK name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VUNPCK AVX IDs changed");

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
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86, mode, code, size, UINT64_C(0x1000),
        flags, &instruction);
    return instruction;
}

static void expect_error(
    const char *label,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        mode, code, size, flags, &decoded_size);

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

static cdisasm_x86_name_id expected_name(uint8_t opcode, uint8_t pp)
{
    if (opcode == UINT8_C(0x15)) {
        return pp == UINT8_C(1)
            ? CDISASM_X86_NAME_VUNPCKHPD
            : CDISASM_X86_NAME_VUNPCKHPS;
    }
    return pp == UINT8_C(1)
        ? CDISASM_X86_NAME_VUNPCKLPD
        : CDISASM_X86_NAME_VUNPCKLPS;
}

static cdisasm_x86_form_id expected_form(
    uint8_t opcode,
    uint8_t pp,
    unsigned int vector_bits,
    int register_form)
{
    cdisasm_x86_form_id base;

    if (opcode == UINT8_C(0x15)) {
        base = pp == UINT8_C(1)
            ? (vector_bits == 256u ? UINT16_C(8831) : UINT16_C(8825))
            : (vector_bits == 256u ? UINT16_C(8841) : UINT16_C(8835));
    } else {
        base = pp == UINT8_C(1)
            ? (vector_bits == 256u ? UINT16_C(8851) : UINT16_C(8845))
            : (vector_bits == 256u ? UINT16_C(8861) : UINT16_C(8855));
    }
    return (cdisasm_x86_form_id)(base + (register_form ? 1u : 0u));
}

static void check_unpack(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t opcode,
    uint8_t pp,
    unsigned int vector_bits,
    int register_form)
{
    const unsigned int vector_bytes = vector_bits / 8u;
    const cdisasm_x86_reg_id register_base = vector_bits == 256u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    size_t index;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == expected_name(opcode, pp));
    EXPECT(instruction->form_id == expected_form(
        opcode, pp, vector_bits, register_form));
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
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset == 0u);

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = !register_form && index == 2u;

        EXPECT(operand->type == (memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(operand->size == vector_bytes);
        EXPECT(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
        EXPECT(operand->broadcast == CDISASM_X86_BROADCAST_NONE);
        if (memory) {
            EXPECT((operand->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
        } else {
            EXPECT(operand->reg >= register_base
                && operand->reg <= register_base + 15u);
            EXPECT(operand->flags == 0u);
            if (mode != CDISASM_MODE_64) {
                EXPECT(operand->reg <= register_base + 7u);
            }
        }
    }
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->branch_target == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2));
}
#endif

static void test_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const uint64_t expected_counts[16] = {
        73728, 24576, 73728, 24576,
        73728, 24576, 73728, 24576,
        73728, 24576, 73728, 24576,
        73728, 24576, 73728, 24576};
    uint64_t form_counts[16] = {0u};
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
                const uint8_t pp = (uint8_t)p1 & UINT8_C(3);
                const int valid = pp <= UINT8_C(1);
                unsigned int opcode_index;

                for (opcode_index = 0u; opcode_index < 2u;
                     ++opcode_index) {
                    const uint8_t opcode = opcode_index == 0u
                        ? UINT8_C(0x14) : UINT8_C(0x15);
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const uint8_t code[15] = {
                            0xc4, p0, (uint8_t)p1, opcode, (uint8_t)modrm,
                            0x24, 0x10, 0x20, 0x30, 0x40,
                            0x50, 0x60, 0x70, 0x80, 0x90};
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            modes[mode_index], code, sizeof(code),
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
                            const int register_form =
                                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                            const unsigned int family =
                                (opcode == UINT8_C(0x15) ? 0u : 2u)
                                + (pp == UINT8_C(1) ? 0u : 1u);
                            const unsigned int form_slot = family * 4u
                                + (vector_bits == 256u ? 2u : 0u)
                                + (register_form ? 1u : 0u);

                            check_unpack(&instruction, decoded_size,
                                modes[mode_index], opcode, pp,
                                vector_bits, register_form);
                            ++form_counts[form_slot];
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
    }
    EXPECT(allocated == UINT64_C(786432));
    EXPECT(reserved == UINT64_C(786432));
#if USE_EXTRA_OPCODES
    for (mode_index = 0u; mode_index < 16u; ++mode_index) {
        EXPECT(form_counts[mode_index] == expected_counts[mode_index]);
    }
#else
    (void)form_counts;
    (void)expected_counts;
#endif
}

static void test_c5_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const uint64_t expected_counts[16] = {
        9216, 3072, 9216, 3072,
        9216, 3072, 9216, 3072,
        9216, 3072, 9216, 3072,
        9216, 3072, 9216, 3072};
    uint64_t form_counts[16] = {0u};
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
            const uint8_t pp = (uint8_t)p1 & UINT8_C(3);
            const int valid = pp <= UINT8_C(1);
            unsigned int opcode_index;

            for (opcode_index = 0u; opcode_index < 2u;
                 ++opcode_index) {
                const uint8_t opcode = opcode_index == 0u
                    ? UINT8_C(0x14) : UINT8_C(0x15);
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const uint8_t code[15] = {
                        0xc5, (uint8_t)p1, opcode, (uint8_t)modrm,
                        0x24, 0x10, 0x20, 0x30, 0x40, 0x50,
                        0x60, 0x70, 0x80, 0x90, 0xa0};
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        modes[mode_index], code, sizeof(code),
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
                        const unsigned int family =
                            (opcode == UINT8_C(0x15) ? 0u : 2u)
                            + (pp == UINT8_C(1) ? 0u : 1u);
                        const unsigned int form_slot = family * 4u
                            + (vector_bits == 256u ? 2u : 0u)
                            + (register_form ? 1u : 0u);
                        const unsigned int destination =
                            ((modrm >> 3) & UINT8_C(7))
                            | (long_mode
                                ? (((~p1 >> 7) & 1u) << 3)
                                : 0u);
                        const unsigned int source1 =
                            (~p1 >> 3) & (long_mode ? 15u : 7u);

                        check_unpack(&instruction, decoded_size,
                            modes[mode_index], opcode, pp,
                            vector_bits, register_form);
                        EXPECT(instruction.encoding.prefix_size == 2u);
                        EXPECT(instruction.encoding.opcode_offset == 2u);
                        EXPECT(instruction.opcode[0].reg
                            == register_base + destination);
                        EXPECT(instruction.opcode[1].reg
                            == register_base + source1);
                        if (register_form) {
                            EXPECT(instruction.opcode[2].reg
                                == register_base
                                    + (modrm & UINT8_C(7)));
                        }
#if USE_DISASM_FORMAT
                        {
                            char output[192];

                            EXPECT(cdisasm_x86_format(&instruction,
                                CDISASM_FORMAT_SYNTAX_INTEL,
                                output, sizeof(output)) != 0u);
                            EXPECT(cdisasm_x86_format(&instruction,
                                CDISASM_FORMAT_SYNTAX_ATT,
                                output, sizeof(output)) != 0u);
                        }
#endif
                        ++form_counts[form_slot];
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
    EXPECT(allocated == UINT64_C(98304));
    EXPECT(reserved == UINT64_C(98304));
#if USE_EXTRA_OPCODES
    for (mode_index = 0u; mode_index < 16u; ++mode_index) {
        EXPECT(form_counts[mode_index] == expected_counts[mode_index]);
    }
#else
    (void)form_counts;
    (void)expected_counts;
#endif
}

static void test_exact_forms_and_gates(void)
{
    static const struct exact_case {
        uint8_t code[5];
        uint16_t form;
    } cases[] = {
        {{0xc4,0xe1,0x71,0x15,0x00},8825},
        {{0xc4,0xe1,0x71,0x15,0xc2},8826},
        {{0xc4,0xe1,0x75,0x15,0x00},8831},
        {{0xc4,0xe1,0x75,0x15,0xc2},8832},
        {{0xc4,0xe1,0x70,0x15,0x00},8835},
        {{0xc4,0xe1,0x70,0x15,0xc2},8836},
        {{0xc4,0xe1,0x74,0x15,0x00},8841},
        {{0xc4,0xe1,0x74,0x15,0xc2},8842},
        {{0xc4,0xe1,0x71,0x14,0x00},8845},
        {{0xc4,0xe1,0x71,0x14,0xc2},8846},
        {{0xc4,0xe1,0x75,0x14,0x00},8851},
        {{0xc4,0xe1,0x75,0x14,0xc2},8852},
        {{0xc4,0xe1,0x70,0x14,0x00},8855},
        {{0xc4,0xe1,0x70,0x14,0xc2},8856},
        {{0xc4,0xe1,0x74,0x14,0x00},8861},
        {{0xc4,0xe1,0x74,0x14,0xc2},8862}};
    size_t index;

#if USE_EXTRA_OPCODES
    const cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    const cdisasm_x86_decode_flags none = selected_flags(0, 0);
    const cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    const cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, cases[index].code,
            sizeof(cases[index].code), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(cases[index].code));
        EXPECT(instruction.form_id == cases[index].form);
    }
    expect_error("VUNPCK needs AVX", CDISASM_MODE_64,
        cases[0].code, sizeof(cases[0].code), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX2 alone does not admit VUNPCK", CDISASM_MODE_64,
        cases[15].code, sizeof(cases[15].code), &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, cases[15].code, sizeof(cases[15].code),
            &avx, &decoded_size);

        EXPECT(decoded_size == sizeof(cases[15].code));
        EXPECT(instruction.form_id == UINT16_C(8862));
    }
#else
    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error("VUNPCK extras off", CDISASM_MODE_64,
            cases[index].code, sizeof(cases[index].code), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif
}

static void test_aliases_truncation_and_collisions(void)
{
    static const uint8_t vex2[] = {0xc5,0xf1,0x14,0xc2};
    static const uint8_t vex3[] = {0xc4,0xe1,0xf0,0x15,0xc2};
    size_t size;

    for (size = 1u; size < sizeof(vex2); ++size) {
        expect_error("truncated C5 VUNPCK", CDISASM_MODE_64,
            vex2, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    for (size = 1u; size < sizeof(vex3); ++size) {
        expect_error("truncated C4 VUNPCK", CDISASM_MODE_64,
            vex3, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    expect_error("reserved pp missing SIB", CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf2,0x14,0x04}, 4u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp complete", CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf2,0x14,0x04,0x24}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy prefix missing disp8", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc5,0xf1,0x15,0x45}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("legacy prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc5,0xf1,0x15,0x45,0x10}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("LOCK prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0xf0,0xc4,0xe1,0x70,0x14,0xc2}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("REX prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0x48,0xc5,0xf1,0x15,0xc2}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        static const cdisasm_x86_mode modes[3] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
        static const uint8_t c5_pd[] = {0xc5,0xf5,0x14,0xc2};
        static const uint8_t c5_ps[] = {0xc5,0xf4,0x15,0xc2};
        size_t index;

        for (index = 0u; index < 3u; ++index) {
            cdisasm_x86_decode_flags flags = all_flags(modes[index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                modes[index], c5_pd, sizeof(c5_pd), &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(c5_pd));
            EXPECT(instruction.form_id == UINT16_C(8852));
            instruction = decode(modes[index], c5_ps, sizeof(c5_ps),
                &flags, &decoded_size);
            EXPECT(decoded_size == sizeof(c5_ps));
            EXPECT(instruction.form_id == UINT16_C(8842));
        }
    }
    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        static const uint8_t nonlong_alias[] = {
            0xc4,0xc1,0x31,0x14,0xc2};
        size_t index;

        for (index = 0u; index < 2u; ++index) {
            cdisasm_x86_decode_flags flags = all_flags(modes[index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                modes[index], nonlong_alias, sizeof(nonlong_alias),
                &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(nonlong_alias));
            EXPECT(instruction.form_id == UINT16_C(8846));
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
            EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM2);
        }
    }
    {
        static const uint8_t wig_high[] = {
            0xc4,0x01,0xb5,0x15,0x54,0x8b,0x20};
        static const uint8_t high_registers[] = {
            0xc4,0x41,0x31,0x14,0xcb};
        static const uint8_t address_segment[] = {
            0x64,0x67,0xc5,0xf4,0x15,0x04,0x24};
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, wig_high, sizeof(wig_high),
            &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(wig_high));
        EXPECT(instruction.form_id == UINT16_C(8831));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM10);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM9);
        EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
        instruction = decode(CDISASM_MODE_64, high_registers,
            sizeof(high_registers), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(high_registers));
        EXPECT(instruction.form_id == UINT16_C(8846));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM9);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM9);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM11);
        instruction = decode(CDISASM_MODE_64, address_segment,
            sizeof(address_segment), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(address_segment));
        EXPECT(instruction.form_id == UINT16_C(8841));
        EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_FS);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_ESP);
    }
    {
        static const uint8_t les_collision[] = {
            0xc4,0x61,0x71,0x14,0xc2};
        static const uint8_t lds_collision[] = {
            0xc5,0x71,0x14,0xc2};
        static const struct legacy_case {
            uint8_t code[4];
            size_t size;
            uint16_t name;
        } legacy[] = {
            {{0x66,0x0f,0x15,0xc2},4u,CDISASM_X86_NAME_UNPCKHPD},
            {{0x0f,0x15,0xc2,0x00},3u,CDISASM_X86_NAME_UNPCKHPS},
            {{0x66,0x0f,0x14,0xc2},4u,CDISASM_X86_NAME_UNPCKLPD},
            {{0x0f,0x14,0xc2,0x00},3u,CDISASM_X86_NAME_UNPCKLPS}};
        cdisasm_x86_decode_flags flags16 = all_flags(CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_16, les_collision, sizeof(les_collision),
            &flags16, &decoded_size);
        size_t index;

        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_MODE_16, lds_collision,
            sizeof(lds_collision), &flags16, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LDS);
        for (index = 0u; index < sizeof(legacy) / sizeof(legacy[0]);
             ++index) {
            instruction = decode(CDISASM_MODE_64, legacy[index].code,
                legacy[index].size, &flags64, &decoded_size);
            EXPECT(decoded_size == legacy[index].size);
            EXPECT(instruction.name_id == legacy[index].name);
        }
    }
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format_rejected(const cdisasm_instruction *instruction)
{
    char output[192] = {'x'};

    EXPECT(cdisasm_x86_format(instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
    output[0] = 'x';
    EXPECT(cdisasm_x86_format(instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
}

static void test_formatting_and_schema(void)
{
    static const struct format_case {
        uint8_t code[7];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc5,0xf1,0x15,0xc2},4u,
            "vunpckhpd xmm0, xmm1, xmm2",
            "vunpckhpd %xmm2, %xmm1, %xmm0"},
        {{0xc5,0xf4,0x15,0x00},4u,
            "vunpckhps ymm0, ymm1, ymmword ptr [rax]",
            "vunpckhps (%rax), %ymm1, %ymm0"},
        {{0xc5,0xf1,0x14,0x00},4u,
            "vunpcklpd xmm0, xmm1, xmmword ptr [rax]",
            "vunpcklpd (%rax), %xmm1, %xmm0"},
        {{0xc4,0x41,0x34,0x14,0xcb},5u,
            "vunpcklps ymm9, ymm9, ymm11",
            "vunpcklps %ymm11, %ymm9, %ymm9"}};
    static const struct evex_case {
        uint8_t code[6];
        uint16_t form;
        uint16_t name;
    } evex[] = {
        {{0x62,0xf1,0xf5,0x09,0x15,0xc2},8828,2018},
        {{0x62,0xf1,0xf5,0x39,0x15,0x00},8829,2018},
        {{0x62,0xf1,0x74,0x49,0x15,0xc2},8844,2019},
        {{0x62,0xf1,0x74,0x19,0x15,0x00},8837,2019},
        {{0x62,0xf1,0xf5,0x49,0x14,0xc2},8854,2020},
        {{0x62,0xf1,0xf5,0x19,0x14,0x00},8847,2020},
        {{0x62,0xf1,0x74,0x29,0x14,0xc2},8860,2021},
        {{0x62,0xf1,0x74,0x39,0x14,0x00},8859,2021}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, cases[index].code, cases[index].size,
            &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == cases[index].size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);

        forged = instruction;
        forged.name_id = CDISASM_X86_NAME_VUNPCKHPS;
        if (forged.name_id == instruction.name_id) {
            forged.name_id = CDISASM_X86_NAME_VUNPCKLPD;
        }
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.form_id = (cdisasm_x86_form_id)(instruction.form_id + 1u);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.operand_count = 2u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[1].size = 8u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[1].reg = CDISASM_X86_REG_RAX;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.modrm ^= UINT8_C(8);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.immediate_count = 1u;
        expect_format_rejected(&forged);
    }

    for (index = 0u; index < sizeof(evex) / sizeof(evex[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, evex[index].code, sizeof(evex[index].code),
            &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(evex[index].code));
        EXPECT(instruction.name_id == evex[index].name);
        EXPECT(instruction.form_id == evex[index].form);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);
        forged = instruction;
        forged.form_id = expected_form(
            evex[index].code[4],
            evex[index].name == CDISASM_X86_NAME_VUNPCKHPD
                    || evex[index].name == CDISASM_X86_NAME_VUNPCKLPD
                ? UINT8_C(1) : UINT8_C(0),
            128u, 1);
        expect_format_rejected(&forged);
    }
}
#else
static void test_formatting_and_schema(void)
{
}
#endif

int main(void)
{
    test_control_partition();
    test_c5_control_partition();
    test_exact_forms_and_gates();
    test_aliases_truncation_and_collisions();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VUNPCK test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
