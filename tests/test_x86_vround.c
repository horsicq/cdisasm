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

_Static_assert(CDISASM_X86_NAME_VROUNDPD == UINT16_C(1963)
        && CDISASM_X86_NAME_VROUNDPS == UINT16_C(1964)
        && CDISASM_X86_NAME_VROUNDSD == UINT16_C(1965)
        && CDISASM_X86_NAME_VROUNDSS == UINT16_C(1966),
    "VROUND name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VROUND AVX IDs changed");

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

static void expect_error_cpu(
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
            (unsigned int)instruction.last_error_id, (unsigned int)status);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

static void expect_error(
    const char *label,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_status status)
{
    expect_error_cpu(label, CDISASM_CPU_X86, mode, code, size, flags, status);
}

#if USE_EXTRA_OPCODES
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

static cdisasm_x86_decode_flags all_flags(cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, mode, &flags) == CDISASM_STATUS_OK);
    return flags;
}

static cdisasm_x86_form_id expected_form(
    uint8_t opcode,
    unsigned int vector_bits,
    int register_form)
{
    const int scalar = opcode >= UINT8_C(0x0a);
    const int is_double = (opcode & UINT8_C(1)) != 0u;

    if (scalar) {
        return (cdisasm_x86_form_id)(
            (is_double ? UINT16_C(8547) : UINT16_C(8549))
            + (register_form ? 1u : 0u));
    }
    return (cdisasm_x86_form_id)(
        (is_double ? UINT16_C(8539) : UINT16_C(8543))
        + (vector_bits == 256u ? 2u : 0u)
        + (register_form ? 1u : 0u));
}

static cdisasm_x86_name_id expected_name(uint8_t opcode)
{
    switch (opcode) {
        case 0x08:
            return CDISASM_X86_NAME_VROUNDPS;
        case 0x09:
            return CDISASM_X86_NAME_VROUNDPD;
        case 0x0a:
            return CDISASM_X86_NAME_VROUNDSS;
        default:
            return CDISASM_X86_NAME_VROUNDSD;
    }
}

static void check_round(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t opcode,
    unsigned int vector_bits,
    int register_form)
{
    const int scalar = opcode >= UINT8_C(0x0a);
    const unsigned int scalar_bytes = (opcode & UINT8_C(1)) != 0u ? 8u : 4u;
    const unsigned int vector_bytes = vector_bits / 8u;
    const cdisasm_x86_reg_id vector_base = vector_bits == 256u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    const size_t source_index = scalar ? 2u : 1u;
    const size_t immediate_index = scalar ? 3u : 2u;
    size_t index;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == expected_name(opcode));
    EXPECT(instruction->form_id == expected_form(
        opcode, vector_bits, register_form));
    EXPECT(instruction->operand_count == (scalar ? 4u : 3u));
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
        == CDISASM_PREFIX_VEX);
    EXPECT(instruction->encoding.prefix_size >= 3u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 1u);
    EXPECT(instruction->encoding.immediate_size[0] == 1u);
    EXPECT(instruction->encoding.immediate_offset[0]
        == instruction->opcode_size - 1u);
    EXPECT(instruction->encoding.selector_offset == 0u);

    for (index = 0u; index < immediate_index; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = !register_form && index == source_index;
        const unsigned int expected_size = scalar && index == source_index
            ? scalar_bytes : vector_bytes;
        const cdisasm_x86_reg_id register_base = scalar
            ? CDISASM_X86_REG_XMM0 : vector_base;

        EXPECT(operand->type == (memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(operand->size == expected_size);
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
    EXPECT(instruction->opcode[immediate_index].type
        == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[immediate_index].size == 1u);
    EXPECT(instruction->opcode[immediate_index].access
        == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[immediate_index].flags == 0u);
    EXPECT(instruction->opcode[immediate_index].broadcast
        == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[immediate_index].imm <= UINT8_MAX);
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
    static const uint8_t opcodes[4] = {0x09, 0x08, 0x0b, 0x0a};
    static const uint64_t expected_counts[12] = {
        4608, 1536, 4608, 1536,
        4608, 1536, 4608, 1536,
        147456, 49152, 147456, 49152};
    uint64_t form_counts[12] = {0u};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;
    size_t family;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        const unsigned int p0_count = long_mode ? 8u : 2u;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

        for (family = 0u; family < 4u; ++family) {
            const int scalar = opcodes[family] >= UINT8_C(0x0a);
            unsigned int p0_index;

            for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
                const uint8_t p0 = long_mode
                    ? (uint8_t)((p0_index << 5) | 3u)
                    : (uint8_t)(0xc3u | (p0_index << 5));
                unsigned int p1;

                for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                    const int valid = (p1 & UINT8_C(3)) == UINT8_C(1)
                        && (scalar
                            || (p1 & UINT8_C(0x78)) == UINT8_C(0x78));
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
#if USE_EXTRA_OPCODES
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                        const unsigned int vector_bits = scalar ? 128u
                            : ((p1 & UINT8_C(4)) != 0u ? 256u : 128u);
#endif
                        const uint8_t code[15] = {
                            0xc4, p0, (uint8_t)p1, opcodes[family],
                            (uint8_t)modrm, 0x24, 0x10, 0x20, 0x30, 0x40,
                            0x50, 0x60, 0x70, 0x80, 0x90};
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
                            const cdisasm_x86_form_id form = expected_form(
                                opcodes[family], vector_bits, register_form);

                            check_round(&instruction, decoded_size,
                                modes[mode_index], opcodes[family],
                                vector_bits, register_form);
                            ++form_counts[form - UINT16_C(8539)];
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

    EXPECT(allocated == UINT64_C(417792));
    EXPECT(reserved == UINT64_C(2727936));
#if USE_EXTRA_OPCODES
    for (family = 0u; family < 12u; ++family) {
        EXPECT(form_counts[family] == expected_counts[family]);
    }
#else
    (void)form_counts;
    (void)expected_counts;
#endif
}

static void test_exact_forms_gates_and_immediates(void)
{
    static const struct exact_case {
        uint8_t code[6];
        uint16_t form;
    } cases[] = {
        {{0xc4,0xe3,0x79,0x09,0x00,0x1b},8539},
        {{0xc4,0xe3,0x79,0x09,0xc1,0x1b},8540},
        {{0xc4,0xe3,0x7d,0x09,0x00,0x1b},8541},
        {{0xc4,0xe3,0x7d,0x09,0xc1,0x1b},8542},
        {{0xc4,0xe3,0x79,0x08,0x00,0x1b},8543},
        {{0xc4,0xe3,0x79,0x08,0xc1,0x1b},8544},
        {{0xc4,0xe3,0x7d,0x08,0x00,0x1b},8545},
        {{0xc4,0xe3,0x7d,0x08,0xc1,0x1b},8546},
        {{0xc4,0xe3,0x71,0x0b,0x00,0x1b},8547},
        {{0xc4,0xe3,0x71,0x0b,0xc2,0x1b},8548},
        {{0xc4,0xe3,0x71,0x0a,0x00,0x1b},8549},
        {{0xc4,0xe3,0x71,0x0a,0xc2,0x1b},8550}};
    size_t index;

#if USE_EXTRA_OPCODES
    const cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
    const cdisasm_x86_decode_flags none = selected_flags(0, 0);
    const cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    const cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, cases[index].code,
            sizeof(cases[index].code), &flags64, &decoded_size);

        EXPECT(decoded_size == sizeof(cases[index].code));
        EXPECT(instruction.form_id == cases[index].form);
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
    }

    expect_error("VROUND needs AVX", CDISASM_MODE_64,
        cases[0].code, sizeof(cases[0].code), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX2 alone does not admit VROUND", CDISASM_MODE_64,
        cases[11].code, sizeof(cases[11].code), &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, cases[11].code,
            sizeof(cases[11].code), &avx, &decoded_size);

        EXPECT(decoded_size == sizeof(cases[11].code));
        EXPECT(instruction.form_id == UINT16_C(8550));
    }

    for (index = 0u; index < 3u; ++index) {
        static const cdisasm_x86_mode modes[3] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
        cdisasm_x86_decode_flags flags = all_flags(modes[index]);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, modes[index], cases[0].code,
            sizeof(cases[0].code), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(cases[0].code));
        EXPECT(instruction.form_id == UINT16_C(8539));
    }

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        unsigned int immediate;

        for (immediate = 0u; immediate <= UINT8_MAX; ++immediate) {
            uint8_t code[6];
            uint32_t decoded_size;
            cdisasm_instruction instruction;
            const size_t immediate_index = cases[index].form >= 8547u
                ? 3u : 2u;

            memcpy(code, cases[index].code, sizeof(code));
            code[5] = (uint8_t)immediate;
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), &flags64, &decoded_size);
            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.form_id == cases[index].form);
            EXPECT(instruction.opcode[immediate_index].imm == immediate);
        }
    }
#else
    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error("VROUND extras off", CDISASM_MODE_64,
            cases[index].code, sizeof(cases[index].code), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif
}

static void test_aliases_addresses_truncation_and_collisions(void)
{
    static const uint8_t packed[] = {0xc4,0xe3,0x79,0x09,0xc1,0x1b};
    static const uint8_t scalar[] = {0xc4,0xe3,0x71,0x0b,0xc2,0x1b};
    size_t size;

    for (size = 1u; size < sizeof(packed); ++size) {
        expect_error("truncated packed VROUND", CDISASM_MODE_64,
            packed, size, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("truncated scalar VROUND", CDISASM_MODE_64,
            scalar, size, NULL, CDISASM_STATUS_TRUNCATED);
    }

    expect_error("packed reserved vvvv missing SIB", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x71,0x09,0x04}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("packed reserved vvvv missing immediate", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x71,0x09,0x04,0x24}, 6u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("packed reserved vvvv complete", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x71,0x09,0x04,0x24,0x1b}, 7u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("scalar wrong pp missing displacement", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x70,0x0b,0x45}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("scalar wrong pp missing immediate", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x70,0x0b,0x45,0x10}, 6u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("scalar wrong pp complete", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x70,0x0b,0x45,0x10,0x1b}, 7u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy prefix missing immediate", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc4,0xe3,0x79,0x09,0xc1}, 6u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("legacy prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc4,0xe3,0x79,0x09,0xc1,0x1b}, 7u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("LOCK prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0xf0,0xc4,0xe3,0x71,0x0b,0xc2,0x1b}, 7u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        static const uint8_t packed_b_alias[] = {
            0xc4,0xc3,0xf9,0x09,0xc1,0xa5};
        static const uint8_t scalar_vvvv_alias[] = {
            0xc4,0xe3,0x35,0x0b,0xc2,0x7f};
        size_t index;

        for (index = 0u; index < 2u; ++index) {
            cdisasm_x86_decode_flags flags = all_flags(modes[index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[index], packed_b_alias,
                sizeof(packed_b_alias), &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(packed_b_alias));
            EXPECT(instruction.form_id == UINT16_C(8540));
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
            instruction = decode(CDISASM_CPU_X86, modes[index],
                scalar_vvvv_alias, sizeof(scalar_vvvv_alias),
                &flags, &decoded_size);
            EXPECT(decoded_size == sizeof(scalar_vvvv_alias));
            EXPECT(instruction.form_id == UINT16_C(8548));
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
        }
    }
    {
        static const uint8_t wig_lig[] = {
            0xc4,0xe3,0xf5,0x0b,0x44,0x88,0x10,0xff};
        static const uint8_t address_segment[] = {
            0x64,0x67,0xc4,0xe3,0xfd,0x08,0x04,0x24,0xa5};
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, wig_lig,
            sizeof(wig_lig), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(wig_lig));
        EXPECT(instruction.form_id == UINT16_C(8547));
        EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[2].size == 8u);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            address_segment, sizeof(address_segment), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(address_segment));
        EXPECT(instruction.form_id == UINT16_C(8545));
        EXPECT(instruction.opcode[1].segment_reg == CDISASM_X86_REG_FS);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_ESP);
    }
    {
        static const uint8_t les_collision[] = {
            0xc4,0x63,0x79,0x09,0xc1,0x1b};
        static const uint8_t legacy_roundps[] = {
            0x66,0x0f,0x3a,0x08,0xc1,0x1b};
        static const uint8_t evex_vrndscalepd[] = {
            0x62,0xf3,0xfd,0x48,0x09,0xc1,0x1b};
        cdisasm_x86_decode_flags flags16 = all_flags(CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_16, les_collision,
            sizeof(les_collision), &flags16, &decoded_size);

        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_roundps, sizeof(legacy_roundps), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_roundps));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_ROUNDPS);
        EXPECT(instruction.form_id < UINT16_C(8539)
            || instruction.form_id > UINT16_C(8550));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_vrndscalepd, sizeof(evex_vrndscalepd),
            &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(evex_vrndscalepd));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VRNDSCALEPD);
        EXPECT(instruction.form_id < UINT16_C(8539)
            || instruction.form_id > UINT16_C(8550));
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

static void mutate_memory_layout(const cdisasm_instruction *instruction)
{
    cdisasm_instruction forged;

    EXPECT((instruction->encoding.modrm & UINT8_C(0xc7)) == 0u);
    forged = *instruction;
    forged.encoding.modrm |= UINT8_C(4);
    expect_format_rejected(&forged);
    forged = *instruction;
    forged.encoding.modrm |= UINT8_C(0x40);
    expect_format_rejected(&forged);
    forged = *instruction;
    forged.encoding.sib_offset = forged.encoding.modrm_offset + 1u;
    forged.encoding.sib = UINT8_C(0x24);
    ++forged.encoding.immediate_offset[0];
    ++forged.opcode_size;
    expect_format_rejected(&forged);
    forged = *instruction;
    forged.encoding.displacement_offset = forged.encoding.modrm_offset + 1u;
    forged.encoding.displacement_size = 1u;
    ++forged.encoding.immediate_offset[0];
    ++forged.opcode_size;
    expect_format_rejected(&forged);
}

static void test_formatting_and_schema(void)
{
    static const struct format_case {
        uint8_t code[8];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4,0xe3,0x79,0x09,0x00,0x1b},6u,
            "vroundpd xmm0, xmmword ptr [rax], 0x1b",
            "vroundpd $0x1b, (%rax), %xmm0"},
        {{0xc4,0xe3,0xfd,0x08,0xc1,0xa5},6u,
            "vroundps ymm0, ymm1, 0xa5",
            "vroundps $0xa5, %ymm1, %ymm0"},
        {{0xc4,0xe3,0x71,0x0b,0x00,0x7f},6u,
            "vroundsd xmm0, xmm1, qword ptr [rax], 0x7f",
            "vroundsd $0x7f, (%rax), %xmm1, %xmm0"},
        {{0xc4,0xe3,0xf5,0x0a,0xc2,0xff},6u,
            "vroundss xmm0, xmm1, xmm2, 0xff",
            "vroundss $0xff, %xmm2, %xmm1, %xmm0"}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        cdisasm_instruction forged;
        const int scalar = instruction.form_id >= UINT16_C(8547);
        const size_t source_index = scalar ? 2u : 1u;
        const size_t immediate_index = scalar ? 3u : 2u;

        EXPECT(decoded_size == cases[index].size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);

        forged = instruction;
        forged.name_id = instruction.name_id == CDISASM_X86_NAME_VROUNDPD
            ? CDISASM_X86_NAME_VROUNDPS : CDISASM_X86_NAME_VROUNDPD;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.form_id = instruction.form_id == UINT16_C(8550)
            ? UINT16_C(8549) : (cdisasm_x86_form_id)(instruction.form_id + 1u);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.operand_count = 1u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.prefix_size = 0u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.branch_target = UINT64_C(0x1234);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
        forged.mask_reg = CDISASM_X86_REG_K1;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.rounding = CDISASM_X86_ROUNDING_RN;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.x86_group_count = 0u;
        memset(forged.x86_group_ids, 0, sizeof(forged.x86_group_ids));
        expect_format_rejected(&forged);
        forged = instruction;
        ++forged.opcode[0].reg;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.modrm ^= UINT8_C(8);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[source_index].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_format_rejected(&forged);
        forged = instruction;
        ++forged.opcode[immediate_index].imm;
        if (instruction.opcode[immediate_index].imm == UINT8_MAX) {
            expect_format_rejected(&forged);
        } else {
            EXPECT(cdisasm_x86_format(&forged,
                CDISASM_FORMAT_SYNTAX_INTEL,
                output, sizeof(output)) != 0u);
        }
        forged = instruction;
        forged.opcode[immediate_index].size = 2u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.immediate_count = 0u;
        expect_format_rejected(&forged);

        if (instruction.opcode[source_index].type
            == CDISASM_OPERAND_MEMORY) {
            mutate_memory_layout(&instruction);
            forged = instruction;
            forged.opcode[source_index].base_reg = CDISASM_X86_REG_R16;
            expect_format_rejected(&forged);
        } else {
            forged = instruction;
            ++forged.opcode[source_index].reg;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.encoding.modrm ^= UINT8_C(1);
            expect_format_rejected(&forged);
            forged = instruction;
            forged.encoding.sib_offset = forged.encoding.modrm_offset + 1u;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.encoding.displacement_offset =
                forged.encoding.modrm_offset + 1u;
            forged.encoding.displacement_size = 1u;
            expect_format_rejected(&forged);
        }
    }

    {
        static const uint8_t legacy_roundps[] = {
            0x66,0x0f,0x3a,0x08,0xc1,0x1b};
        uint32_t decoded_size;
        cdisasm_instruction legacy = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, legacy_roundps,
            sizeof(legacy_roundps), &flags, &decoded_size);
        cdisasm_instruction forged;
        char output[192];

        EXPECT(decoded_size == sizeof(legacy_roundps));
        EXPECT(cdisasm_x86_format(&legacy, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);
        forged = legacy;
        forged.name_id = CDISASM_X86_NAME_VROUNDPS;
        expect_format_rejected(&forged);
        forged = legacy;
        forged.form_id = UINT16_C(8544);
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
    test_exact_forms_gates_and_immediates();
    test_aliases_addresses_truncation_and_collisions();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VROUND test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
