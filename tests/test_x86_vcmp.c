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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VCMPPD == UINT16_C(1495)
        && CDISASM_X86_NAME_VCMPPS == UINT16_C(1497)
        && CDISASM_X86_NAME_VCMPSD == UINT16_C(1498)
        && CDISASM_X86_NAME_VCMPSS == UINT16_C(1500),
    "VCMP name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VCMP AVX IDs changed");

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
    expect_error_cpu(label, CDISASM_CPU_X86, mode,
        code, size, flags, status);
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

static cdisasm_x86_name_id expected_name(uint8_t prefix)
{
    switch (prefix) {
        case 0:
            return CDISASM_X86_NAME_VCMPPS;
        case 1:
            return CDISASM_X86_NAME_VCMPPD;
        case 2:
            return CDISASM_X86_NAME_VCMPSS;
        default:
            return CDISASM_X86_NAME_VCMPSD;
    }
}

static cdisasm_x86_form_id expected_form(
    uint8_t prefix,
    unsigned int vector_bits,
    int register_form)
{
    cdisasm_x86_form_id base;

    switch (prefix) {
        case 0:
            base = UINT16_C(3611);
            break;
        case 1:
            base = UINT16_C(3595);
            break;
        case 2:
            base = UINT16_C(3623);
            break;
        default:
            base = UINT16_C(3617);
            break;
    }
    return (cdisasm_x86_form_id)(base
        + (prefix <= 1u && vector_bits == 256u ? 2u : 0u)
        + (register_form ? 1u : 0u));
}

static unsigned int form_count_index(cdisasm_x86_form_id form)
{
    if (form >= UINT16_C(3595) && form <= UINT16_C(3598)) {
        return form - UINT16_C(3595);
    }
    if (form >= UINT16_C(3611) && form <= UINT16_C(3614)) {
        return 4u + form - UINT16_C(3611);
    }
    if (form >= UINT16_C(3617) && form <= UINT16_C(3618)) {
        return 8u + form - UINT16_C(3617);
    }
    return 10u + form - UINT16_C(3623);
}

static void check_cmp(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t p1,
    int register_form)
{
    const uint8_t prefix = p1 & UINT8_C(3);
    const int scalar = prefix >= 2u;
    const int is_double = prefix == 1u || prefix == 3u;
    const unsigned int vector_bits = scalar ? 128u
        : ((p1 & UINT8_C(4)) != 0u ? 256u : 128u);
    const unsigned int vector_bytes = vector_bits / 8u;
    const unsigned int scalar_bytes = is_double ? 8u : 4u;
    const cdisasm_x86_reg_id vector_base = vector_bits == 256u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    size_t index;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == expected_name(prefix));
    EXPECT(instruction->form_id == expected_form(
        prefix, vector_bits, register_form));
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
    EXPECT(instruction->encoding.prefix_size >= 2u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 1u);
    EXPECT(instruction->encoding.immediate_size[0] == 1u);
    EXPECT(instruction->encoding.immediate_offset[0]
        == instruction->opcode_size - 1u);
    EXPECT(instruction->encoding.selector_offset == 0u);

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = !register_form && index == 2u;
        const unsigned int size = scalar && index == 2u
            ? scalar_bytes : vector_bytes;
        const cdisasm_x86_reg_id register_base = scalar
            ? CDISASM_X86_REG_XMM0 : vector_base;

        EXPECT(operand->type == (memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(operand->size == size);
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
    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[3].size == 1u);
    EXPECT(instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[3].flags == 0u);
    EXPECT(instruction->opcode[3].broadcast
        == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[3].imm <= UINT8_MAX);
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

static void test_complete_c4_c5_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const uint64_t expected_counts[12] = {
        82944, 27648, 82944, 27648,
        82944, 27648, 82944, 27648,
        165888, 55296, 165888, 55296};
    uint64_t form_counts[12] = {0u};
    uint64_t allocated = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        const unsigned int c4_p0_count = long_mode ? 8u : 2u;
        unsigned int p0_index;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

        for (p0_index = 0u; p0_index < c4_p0_count; ++p0_index) {
            const uint8_t p0 = long_mode
                ? (uint8_t)((p0_index << 5) | 1u)
                : (uint8_t)(0xc1u | (p0_index << 5));
            unsigned int p1;

            for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const uint8_t code[15] = {
                        0xc4, p0, (uint8_t)p1, 0xc2, (uint8_t)modrm,
                        0x24, 0x10, 0x20, 0x30, 0x40,
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

#if USE_EXTRA_OPCODES
                    const int register_form =
                        (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                    const uint8_t prefix = (uint8_t)p1 & UINT8_C(3);
                    const unsigned int vector_bits = prefix >= 2u ? 128u
                        : (((p1 & UINT8_C(4)) != 0u) ? 256u : 128u);
                    const cdisasm_x86_form_id form = expected_form(
                        prefix, vector_bits, register_form);

                    check_cmp(&instruction, decoded_size,
                        modes[mode_index], (uint8_t)p1, register_form);
                    ++form_counts[form_count_index(form)];
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    ++allocated;
                }
            }
        }

        {
            const unsigned int p1_start = long_mode ? 0u : 0xc0u;
            unsigned int p1;

            for (p1 = p1_start; p1 <= UINT8_MAX; ++p1) {
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const uint8_t code[15] = {
                        0xc5, (uint8_t)p1, 0xc2, (uint8_t)modrm,
                        0x24, 0x10, 0x20, 0x30, 0x40,
                        0x50, 0x60, 0x70, 0x80, 0x90, 0xa0};
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

#if USE_EXTRA_OPCODES
                    const int register_form =
                        (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                    const uint8_t prefix = (uint8_t)p1 & UINT8_C(3);
                    const unsigned int vector_bits = prefix >= 2u ? 128u
                        : (((p1 & UINT8_C(4)) != 0u) ? 256u : 128u);
                    const cdisasm_x86_form_id form = expected_form(
                        prefix, vector_bits, register_form);

                    check_cmp(&instruction, decoded_size,
                        modes[mode_index], (uint8_t)p1, register_form);
                    ++form_counts[form_count_index(form)];
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    ++allocated;
                }
            }
        }
    }

    EXPECT(allocated == UINT64_C(884736));
#if USE_EXTRA_OPCODES
    for (mode_index = 0u; mode_index < 12u; ++mode_index) {
        EXPECT(form_counts[mode_index] == expected_counts[mode_index]);
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
        {{0xc4,0xe1,0x69,0xc2,0x00,0x1b},3595},
        {{0xc4,0xe1,0x69,0xc2,0xc1,0x1b},3596},
        {{0xc4,0xe1,0x6d,0xc2,0x00,0x1b},3597},
        {{0xc4,0xe1,0x6d,0xc2,0xc1,0x1b},3598},
        {{0xc4,0xe1,0x68,0xc2,0x00,0x1b},3611},
        {{0xc4,0xe1,0x68,0xc2,0xc1,0x1b},3612},
        {{0xc4,0xe1,0x6c,0xc2,0x00,0x1b},3613},
        {{0xc4,0xe1,0x6c,0xc2,0xc1,0x1b},3614},
        {{0xc4,0xe1,0x6b,0xc2,0x00,0x1b},3617},
        {{0xc4,0xe1,0x6b,0xc2,0xc1,0x1b},3618},
        {{0xc4,0xe1,0x6a,0xc2,0x00,0x1b},3623},
        {{0xc4,0xe1,0x6a,0xc2,0xc1,0x1b},3624}};
    size_t index;

#if USE_EXTRA_OPCODES
    const cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
    const cdisasm_x86_decode_flags none = selected_flags(0, 0);
    const cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    const cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        unsigned int immediate;

        for (immediate = 0u; immediate <= UINT8_MAX; ++immediate) {
            uint8_t code[6];
            uint32_t decoded_size;
            cdisasm_instruction instruction;

            memcpy(code, cases[index].code, sizeof(code));
            code[5] = (uint8_t)immediate;
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), &flags64, &decoded_size);
            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.form_id == cases[index].form);
            EXPECT(instruction.opcode[3].imm == immediate);
        }
    }

    expect_error("VCMP needs AVX", CDISASM_MODE_64,
        cases[0].code, sizeof(cases[0].code), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX2 alone does not admit VCMP", CDISASM_MODE_64,
        cases[11].code, sizeof(cases[11].code), &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, cases[11].code,
            sizeof(cases[11].code), &avx, &decoded_size);

        EXPECT(decoded_size == sizeof(cases[11].code));
        EXPECT(instruction.form_id == UINT16_C(3624));
    }
    {
        cdisasm_x86_decode_flags profile;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_SANDY_BRIDGE,
            CDISASM_MODE_64, &profile) == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
            cases[0].code, sizeof(cases[0].code), &profile, &decoded_size);
        EXPECT(decoded_size == sizeof(cases[0].code));
        EXPECT(instruction.form_id == UINT16_C(3595));
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_WESTMERE,
            CDISASM_MODE_64, &profile) == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_WESTMERE, CDISASM_MODE_64,
            cases[0].code, sizeof(cases[0].code), &profile, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    }
#else
    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error("VCMP extras off", CDISASM_MODE_64,
            cases[index].code, sizeof(cases[index].code), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif
}

static void test_aliases_addresses_truncation_and_collisions(void)
{
    static const uint8_t c4[] = {0xc4,0xe1,0x69,0xc2,0xc1,0x1b};
    static const uint8_t c5[] = {0xc5,0xe9,0xc2,0xc1,0x1b};
    size_t size;

    for (size = 1u; size < sizeof(c4); ++size) {
        expect_error("truncated C4 VCMP", CDISASM_MODE_64,
            c4, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    for (size = 1u; size < sizeof(c5); ++size) {
        expect_error("truncated C5 VCMP", CDISASM_MODE_64,
            c5, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    expect_error("VCMP missing SIB", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x69,0xc2,0x04}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("VCMP missing disp32", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x69,0xc2,0x05,0x11,0x22,0x33}, 8u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("legacy prefix missing immediate", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc4,0xe1,0x69,0xc2,0xc1}, 6u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("legacy prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc4,0xe1,0x69,0xc2,0xc1,0x1b}, 7u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("LOCK prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0xf0,0xc5,0xe9,0xc2,0xc1,0x1b}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        static const uint8_t b_alias[] = {
            0xc4,0xc1,0x69,0xc2,0xc1,0x00};
        static const uint8_t vvvv_alias[] = {
            0xc4,0xe1,0x29,0xc2,0xc1,0x00};
        size_t index;

        for (index = 0u; index < 2u; ++index) {
            cdisasm_x86_decode_flags flags = all_flags(modes[index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[index], b_alias,
                sizeof(b_alias), &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(b_alias));
            EXPECT(instruction.form_id == UINT16_C(3596));
            EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM1);
            instruction = decode(CDISASM_CPU_X86, modes[index],
                vvvv_alias, sizeof(vvvv_alias), &flags, &decoded_size);
            EXPECT(decoded_size == sizeof(vvvv_alias));
            EXPECT(instruction.form_id == UINT16_C(3596));
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM2);
        }
        {
            cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64, b_alias,
                sizeof(b_alias), &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(b_alias));
            EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM9);
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                vvvv_alias, sizeof(vvvv_alias), &flags, &decoded_size);
            EXPECT(decoded_size == sizeof(vvvv_alias));
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM10);
        }
    }
    {
        static const uint8_t wig_lig[] = {
            0xc4,0xe1,0xef,0xc2,0x44,0x88,0x10,0xff};
        static const uint8_t address_segment[] = {
            0x64,0x67,0xc5,0xec,0xc2,0x04,0x24,0xa5};
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, wig_lig,
            sizeof(wig_lig), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(wig_lig));
        EXPECT(instruction.form_id == UINT16_C(3617));
        EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[2].size == 8u);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            address_segment, sizeof(address_segment), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(address_segment));
        EXPECT(instruction.form_id == UINT16_C(3613));
        EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_FS);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_ESP);
    }
    {
        static const uint8_t les_collision[] = {
            0xc4,0x61,0x69,0xc2,0xc1,0x00};
        static const uint8_t legacy_cmpps[] = {0x0f,0xc2,0xc1,0x00};
        static const uint8_t evex_vcmppd[] = {
            0x62,0xf1,0xed,0x08,0xc2,0xc1,0x00};
        cdisasm_x86_decode_flags flags16 = all_flags(CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_16, les_collision,
            sizeof(les_collision), &flags16, &decoded_size);

        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_cmpps, sizeof(legacy_cmpps), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_cmpps));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_CMPPS);
        EXPECT(instruction.form_id < UINT16_C(3595)
            || instruction.form_id > UINT16_C(3624));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_vcmppd, sizeof(evex_vcmppd), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(evex_vcmppd));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VCMPPD);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
        EXPECT(instruction.form_id < UINT16_C(3595));
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
        uint8_t code[8];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4,0xe1,0x69,0xc2,0x00,0x1b},6u,
            "vcmppd xmm0, xmm2, xmmword ptr [rax], 0x1b",
            "vcmppd $0x1b, (%rax), %xmm2, %xmm0"},
        {{0xc5,0xec,0xc2,0xc1,0xa5},5u,
            "vcmpps ymm0, ymm2, ymm1, 0xa5",
            "vcmpps $0xa5, %ymm1, %ymm2, %ymm0"},
        {{0xc4,0xe1,0x6b,0xc2,0x00,0x7f},6u,
            "vcmpsd xmm0, xmm2, qword ptr [rax], 0x7f",
            "vcmpsd $0x7f, (%rax), %xmm2, %xmm0"},
        {{0xc4,0xe1,0xea,0xc2,0xc1,0xff},6u,
            "vcmpss xmm0, xmm2, xmm1, 0xff",
            "vcmpss $0xff, %xmm1, %xmm2, %xmm0"}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == cases[index].size);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);

        forged = instruction;
        forged.name_id = instruction.name_id == CDISASM_X86_NAME_VCMPPD
            ? CDISASM_X86_NAME_VCMPPS : CDISASM_X86_NAME_VCMPPD;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.form_id = instruction.form_id == UINT16_C(3624)
            ? UINT16_C(3623)
            : (cdisasm_x86_form_id)(instruction.form_id + 1u);
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
        forged.operand_count = 3u;
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
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[3].size = 2u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.immediate_count = 0u;
        expect_format_rejected(&forged);

        if (instruction.opcode[2].type == CDISASM_OPERAND_MEMORY) {
            forged = instruction;
            forged.opcode[2].base_reg = CDISASM_X86_REG_R16;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.encoding.sib_offset = forged.encoding.modrm_offset + 1u;
            ++forged.encoding.immediate_offset[0];
            ++forged.opcode_size;
            expect_format_rejected(&forged);
        } else {
            forged = instruction;
            ++forged.opcode[2].reg;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.encoding.modrm ^= UINT8_C(1);
            expect_format_rejected(&forged);
        }
    }

    {
        static const uint8_t legacy_cmpps[] = {0x0f,0xc2,0xc1,0x00};
        static const uint8_t evex_vcmppd[] = {
            0x62,0xf1,0xed,0x08,0xc2,0xc1,0x00};
        uint32_t decoded_size;
        char output[192];
        cdisasm_instruction legacy = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_cmpps, sizeof(legacy_cmpps), &flags, &decoded_size);
        cdisasm_instruction evex;
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(legacy_cmpps));
        EXPECT(cdisasm_x86_format(&legacy, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);
        forged = legacy;
        forged.name_id = CDISASM_X86_NAME_VCMPPS;
        expect_format_rejected(&forged);
        forged = legacy;
        forged.name_id = CDISASM_X86_NAME_VCMPPS;
        forged.form_id = UINT16_C(3612);
        expect_format_rejected(&forged);

        evex = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_vcmppd, sizeof(evex_vcmppd), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(evex_vcmppd));
        EXPECT(evex.name_id == CDISASM_X86_NAME_VCMPPD);
        EXPECT(evex.form_id >= UINT16_C(3589)
            && evex.form_id <= UINT16_C(3594));
        EXPECT((evex.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
        EXPECT(cdisasm_x86_format(&evex, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);
        EXPECT(cdisasm_x86_format(&evex, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) != 0u);

        forged = evex;
        forged.name_id = CDISASM_X86_NAME_VCMPPS;
        expect_format_rejected(&forged);
        forged = evex;
        forged.form_id = UINT16_C(3605);
        expect_format_rejected(&forged);
        forged = evex;
        forged.opcode_flags &=
            ~CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_format_rejected(&forged);
        forged = evex;
        forged.form_id = UINT16_C(1);
        expect_format_rejected(&forged);
        forged = evex;
        forged.opcode_flags &= ~CDISASM_PREFIX_EVEX;
        forged.opcode_flags |= CDISASM_PREFIX_VEX;
        expect_format_rejected(&forged);
    }

    {
        static const struct evex_case {
            uint8_t code[7];
            cdisasm_x86_name_id name_id;
            cdisasm_x86_form_id form_id;
        } cases[] = {
            {{0x62,0xf1,0xed,0x08,0xc2,0x00,0x00},
                CDISASM_X86_NAME_VCMPPD, UINT16_C(3589)},
            {{0x62,0xf1,0xed,0x0f,0xc2,0xc1,0x01},
                CDISASM_X86_NAME_VCMPPD, UINT16_C(3590)},
            {{0x62,0xf1,0xed,0x38,0xc2,0x00,0x02},
                CDISASM_X86_NAME_VCMPPD, UINT16_C(3591)},
            {{0x62,0xf1,0xed,0x28,0xc2,0xc1,0x03},
                CDISASM_X86_NAME_VCMPPD, UINT16_C(3592)},
            {{0x62,0xf1,0xed,0x48,0xc2,0x00,0x04},
                CDISASM_X86_NAME_VCMPPD, UINT16_C(3593)},
            {{0x62,0xf1,0xed,0x1d,0xc2,0xc1,0x05},
                CDISASM_X86_NAME_VCMPPD, UINT16_C(3594)},
            {{0x62,0xf1,0x6c,0x18,0xc2,0x00,0x06},
                CDISASM_X86_NAME_VCMPPS, UINT16_C(3605)},
            {{0x62,0xf1,0x6c,0x09,0xc2,0xc1,0x07},
                CDISASM_X86_NAME_VCMPPS, UINT16_C(3606)},
            {{0x62,0xf1,0x6c,0x28,0xc2,0x00,0x08},
                CDISASM_X86_NAME_VCMPPS, UINT16_C(3607)},
            {{0x62,0xf1,0x6c,0x28,0xc2,0xc1,0x09},
                CDISASM_X86_NAME_VCMPPS, UINT16_C(3608)},
            {{0x62,0xf1,0x6c,0x58,0xc2,0x00,0x0a},
                CDISASM_X86_NAME_VCMPPS, UINT16_C(3609)},
            {{0x62,0xf1,0x6c,0x18,0xc2,0xc1,0x0b},
                CDISASM_X86_NAME_VCMPPS, UINT16_C(3610)},
            {{0x62,0xf1,0xef,0x08,0xc2,0x00,0x0c},
                CDISASM_X86_NAME_VCMPSD, UINT16_C(3615)},
            {{0x62,0xf1,0xef,0x1b,0xc2,0xc1,0x0d},
                CDISASM_X86_NAME_VCMPSD, UINT16_C(3616)},
            {{0x62,0xf1,0x6e,0x08,0xc2,0x00,0x0e},
                CDISASM_X86_NAME_VCMPSS, UINT16_C(3621)},
            {{0x62,0xf1,0x6e,0x1d,0xc2,0xc1,0x0f},
                CDISASM_X86_NAME_VCMPSS, UINT16_C(3622)}};
        size_t case_index;

        for (case_index = 0u;
             case_index < sizeof(cases) / sizeof(cases[0]);
             ++case_index) {
            uint32_t decoded_size;
            char output[192];
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                cases[case_index].code, sizeof(cases[case_index].code),
                &flags, &decoded_size);
            cdisasm_instruction forged;

            EXPECT(decoded_size == sizeof(cases[case_index].code));
            EXPECT(instruction.name_id == cases[case_index].name_id);
            EXPECT(instruction.form_id == cases[case_index].form_id);
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
            EXPECT((instruction.opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
            EXPECT(cdisasm_x86_format(&instruction,
                CDISASM_FORMAT_SYNTAX_INTEL,
                output, sizeof(output)) != 0u);
            EXPECT(cdisasm_x86_format(&instruction,
                CDISASM_FORMAT_SYNTAX_ATT,
                output, sizeof(output)) != 0u);

            forged = instruction;
            forged.opcode_flags |=
                CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode_flags |=
                CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode_flags |=
                CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode_groups = UINT32_C(1);
            expect_format_rejected(&forged);
            forged = instruction;
            forged.branch_target = UINT64_C(1);
            expect_format_rejected(&forged);
            forged = instruction;
            forged.operand_count = 3u;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.x86_group_ids[0] = CDISASM_X86_GROUP_AVX;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.mask_mode = CDISASM_X86_MASK_ZERO;
            forged.mask_reg = CDISASM_X86_REG_K1;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.rounding = CDISASM_X86_ROUNDING_RN;
            forged.sae = CDISASM_X86_SAE_ENABLED;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.encoding.prefix_size = 3u;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.encoding.immediate_count = 0u;
            expect_format_rejected(&forged);

            forged = instruction;
            forged.opcode[0].type = CDISASM_OPERAND_MEMORY;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[0].size = 4u;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[0].reg = CDISASM_X86_REG_K1;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[0].flags = CDISASM_OPERAND_FLAG_IMPLICIT;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[0].broadcast =
                CDISASM_X86_BROADCAST_1_TO_2;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[1].type = CDISASM_OPERAND_IMMEDIATE;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[1].reg = CDISASM_X86_REG_K0;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[1].size = 8u;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[1].flags = CDISASM_OPERAND_FLAG_IMPLICIT;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[1].broadcast =
                CDISASM_X86_BROADCAST_1_TO_2;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[2].type = instruction.opcode[2].type
                == CDISASM_OPERAND_MEMORY
                    ? CDISASM_OPERAND_REGISTER
                    : CDISASM_OPERAND_MEMORY;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[2].size = 3u;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[2].access = CDISASM_OPERAND_ACCESS_WRITE;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[2].broadcast =
                CDISASM_X86_BROADCAST_1_TO_64;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[3].type = CDISASM_OPERAND_REGISTER;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[3].size = 2u;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[3].imm = UINT64_C(0x100);
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[3].access = CDISASM_OPERAND_ACCESS_WRITE;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[3].flags = CDISASM_OPERAND_FLAG_SIGNED;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[3].broadcast =
                CDISASM_X86_BROADCAST_1_TO_2;
            expect_format_rejected(&forged);

            if (instruction.opcode[2].type == CDISASM_OPERAND_MEMORY) {
                forged = instruction;
                forged.opcode[2].flags |=
                    CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
                expect_format_rejected(&forged);
                forged = instruction;
                forged.opcode[2].base_reg = CDISASM_X86_REG_R16;
                expect_format_rejected(&forged);
                forged = instruction;
                forged.sae = CDISASM_X86_SAE_ENABLED;
                expect_format_rejected(&forged);
            } else {
                forged = instruction;
                ++forged.opcode[2].reg;
                expect_format_rejected(&forged);
                if (instruction.form_id != UINT16_C(3594)
                    && instruction.form_id != UINT16_C(3610)
                    && instruction.form_id != UINT16_C(3616)
                    && instruction.form_id != UINT16_C(3622)) {
                    forged = instruction;
                    forged.sae = CDISASM_X86_SAE_ENABLED;
                    expect_format_rejected(&forged);
                }
            }
        }
    }
}
#else
static void test_formatting_and_schema(void)
{
}
#endif

int main(void)
{
    test_complete_c4_c5_partition();
    test_exact_forms_gates_and_immediates();
    test_aliases_addresses_truncation_and_collisions();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VCMP test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
