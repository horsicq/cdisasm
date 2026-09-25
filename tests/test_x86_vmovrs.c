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

_Static_assert(CDISASM_X86_NAME_VMOVRSB == UINT16_C(1784)
        && CDISASM_X86_NAME_VMOVRSD == UINT16_C(1785)
        && CDISASM_X86_NAME_VMOVRSQ == UINT16_C(1786)
        && CDISASM_X86_NAME_VMOVRSW == UINT16_C(1787),
    "VMOVRS name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX10_MOVRS_128 == UINT16_C(155)
        && CDISASM_X86_GROUP_AVX10_MOVRS_256 == UINT16_C(156)
        && CDISASM_X86_GROUP_AVX10_MOVRS_512 == UINT16_C(157),
    "AVX10 MOVRS group IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX10_MOVRS_128 == UINT32_C(103)
        && CDISASM_X86_DECODE_BIT_AVX10_MOVRS_256 == UINT32_C(104)
        && CDISASM_X86_DECODE_BIT_AVX10_MOVRS_512 == UINT32_C(105),
    "AVX10 MOVRS decode bits changed");

typedef struct movrs_row {
    uint8_t p1;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id first_form;
} movrs_row;

static const movrs_row rows[] = {
    {UINT8_C(0x7f), CDISASM_X86_NAME_VMOVRSB, UINT16_C(5897)},
    {UINT8_C(0x7e), CDISASM_X86_NAME_VMOVRSD, UINT16_C(5900)},
    {UINT8_C(0xfe), CDISASM_X86_NAME_VMOVRSQ, UINT16_C(5903)},
    {UINT8_C(0xff), CDISASM_X86_NAME_VMOVRSW, UINT16_C(5906)}
};

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

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags one_bit(cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit_id));
    return flags;
}

static cdisasm_x86_decode_flags two_bits(
    cdisasm_x86_decode_bit_id first,
    cdisasm_x86_decode_bit_id second)
{
    cdisasm_x86_decode_flags flags = one_bit(first);

    EXPECT(cdisasm_decode_flags_set_bit(&flags, second));
    return flags;
}

static cdisasm_x86_decode_flags all_flags(void)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, CDISASM_MODE_64, &flags) == CDISASM_STATUS_OK);
    return flags;
}

static cdisasm_x86_reg_id vector_id(unsigned int index, unsigned int bits)
{
    const cdisasm_x86_reg_id first = bits == 128u
        ? CDISASM_X86_REG_XMM0
        : bits == 256u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_ZMM0;

    return (cdisasm_x86_reg_id)(first + index);
}

static void check_movrs(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    const movrs_row *row,
    unsigned int ll,
    uint8_t p0,
    uint8_t p1,
    uint8_t p2,
    uint8_t modrm)
{
    const unsigned int vector_bits = 128u << ll;
    const unsigned int destination_index =
        ((unsigned int)modrm >> 3 & 7u)
        + ((p0 & UINT8_C(0x80)) == 0 ? 8u : 0u)
        + ((p0 & UINT8_C(0x10)) == 0 ? 16u : 0u);
    const unsigned int aaa = p2 & UINT8_C(7);
    const int zero = (p2 & UINT8_C(0x80)) != 0;
    const int apx = (p0 & UINT8_C(8)) != 0
        || (p1 & UINT8_C(4)) == 0;
    unsigned int width;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == row->name_id);
    EXPECT(instruction->form_id
        == (cdisasm_x86_form_id)(row->first_form + ll));
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    for (width = 0u; width < 3u; ++width) {
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction,
            (cdisasm_x86_group_id)(
                CDISASM_X86_GROUP_AVX10_MOVRS_128 + width))
            == (width == ll));
    }
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == apx);
    EXPECT(instruction->operand_count == 2u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg
        == vector_id(destination_index, vector_bits));
    EXPECT(instruction->opcode[0].size == vector_bits / 8u);
    EXPECT(instruction->opcode[0].access
        == (aaa != 0u && !zero ? CDISASM_OPERAND_ACCESS_READ_WRITE
                               : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction->opcode[1].size == vector_bits / 8u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->mask_reg == (aaa == 0u
        ? CDISASM_X86_REG_NONE
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
    EXPECT(instruction->mask_mode == (aaa == 0u
        ? CDISASM_X86_MASK_NONE
        : zero ? CDISASM_X86_MASK_ZERO : CDISASM_X86_MASK_MERGE));
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->encoding.modrm == modrm);
    EXPECT(instruction->encoding.immediate_count == 0u);
}
#endif

static int p2_is_allocated(uint8_t p2)
{
    const unsigned int ll = (p2 >> 5) & 3u;
    const unsigned int aaa = p2 & 7u;

    return ll < 3u
        && (p2 & UINT8_C(0x18)) == UINT8_C(0x08)
        && !((p2 & UINT8_C(0x80)) != 0 && aaa == 0u);
}

static void test_all_twelve_forms(void)
{
    size_t row_index;

    for (row_index = 0u; row_index < sizeof(rows) / sizeof(rows[0]);
         ++row_index) {
        unsigned int ll;

        for (ll = 0u; ll < 3u; ++ll) {
            uint8_t code[] = {
                0x62,0xf5,rows[row_index].p1,
                (uint8_t)(0x08u | (ll << 5)),0x6f,0x00
            };
            uint32_t decoded_size;
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags flags = one_bit(
                (cdisasm_x86_decode_bit_id)(
                    CDISASM_X86_DECODE_BIT_AVX10_MOVRS_128 + ll));
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), &flags, &decoded_size);

            check_movrs(&instruction, decoded_size, &rows[row_index],
                ll, code[1], code[2], code[3], code[5]);
            EXPECT(decoded_size == sizeof(code));
#else
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), NULL, &decoded_size);

            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static void test_complete_allocated_domain(void)
{
    uint32_t per_form[12] = {0};
    uint32_t allocated = 0u;
    size_t row_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags();
#endif

    for (row_index = 0u; row_index < sizeof(rows) / sizeof(rows[0]);
         ++row_index) {
        unsigned int ll;

        for (ll = 0u; ll < 3u; ++ll) {
            unsigned int p0_index;

            for (p0_index = 0u; p0_index < 32u; ++p0_index) {
                const uint8_t p0 = (uint8_t)((p0_index << 3) | 5u);
                unsigned int u;

                for (u = 0u; u < 2u; ++u) {
                    const uint8_t p1 = (uint8_t)(
                        (rows[row_index].p1 & UINT8_C(0xfb)) | (u << 2));
                    unsigned int zero;

                    for (zero = 0u; zero < 2u; ++zero) {
                        unsigned int aaa;

                        for (aaa = zero != 0u ? 1u : 0u; aaa < 8u; ++aaa) {
                            const uint8_t p2 = (uint8_t)(
                                0x08u | (ll << 5) | (zero << 7) | aaa);
                            unsigned int modrm;

                            for (modrm = 0u; modrm < 192u; ++modrm) {
                                uint8_t code[12] = {
                                    0x62,p0,p1,p2,0x6f,(uint8_t)modrm,
                                    0x24,0x10,0x20,0x30,0x40,0x50
                                };
                                uint32_t decoded_size;
                                cdisasm_instruction instruction = decode(
                                    CDISASM_CPU_X86, CDISASM_MODE_64,
                                    code, sizeof(code),
#if USE_EXTRA_OPCODES
                                    &flags,
#else
                                    NULL,
#endif
                                    &decoded_size);

#if USE_EXTRA_OPCODES
                                check_movrs(&instruction, decoded_size,
                                    &rows[row_index], ll, p0, p1, p2,
                                    (uint8_t)modrm);
#else
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                ++per_form[row_index * 3u + ll];
                                ++allocated;
                            }
                        }
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(2211840));
    for (row_index = 0u; row_index < 12u; ++row_index) {
        EXPECT(per_form[row_index] == UINT32_C(184320));
    }
}

static void test_factored_reserved_spaces(void)
{
    uint32_t p1_allocated = 0u;
    uint32_t p1_reserved = 0u;
    uint32_t p2_allocated = 0u;
    uint32_t p2_reserved = 0u;
    uint32_t address_allocated = 0u;
    uint32_t address_reserved = 0u;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags();
#endif
    unsigned int value;

    for (value = 0u; value <= UINT8_MAX; ++value) {
        unsigned int representative;

        for (representative = 0u; representative < 2u; ++representative) {
            const uint8_t modrm = representative == 0u ? 0x00 : 0xc0;
            const int valid = representative == 0u
                && (value & UINT8_C(0x78)) == UINT8_C(0x78)
                && ((value & UINT8_C(3)) == UINT8_C(2)
                    || (value & UINT8_C(3)) == UINT8_C(3));
            uint8_t code[] = {0x62,0xf5,(uint8_t)value,0x08,0x6f,modrm};
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code),
#if USE_EXTRA_OPCODES
                &flags,
#else
                NULL,
#endif
                &decoded_size);

            if (valid) {
#if USE_EXTRA_OPCODES
                const movrs_row *row =
                    (value & UINT8_C(3)) == UINT8_C(3)
                    ? ((value & UINT8_C(0x80)) == 0 ? &rows[0] : &rows[3])
                    : ((value & UINT8_C(0x80)) == 0 ? &rows[1] : &rows[2]);

                check_movrs(&instruction, decoded_size, row, 0u,
                    code[1], code[2], code[3], code[5]);
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                ++p1_allocated;
            } else {
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                ++p1_reserved;
            }
        }
    }

    for (value = 0u; value <= UINT8_MAX; ++value) {
        size_t row_index;

        for (row_index = 0u; row_index < sizeof(rows) / sizeof(rows[0]);
             ++row_index) {
            unsigned int representative;

            for (representative = 0u; representative < 2u;
                 ++representative) {
                const uint8_t modrm = representative == 0u ? 0x00 : 0xc0;
                const int valid = representative == 0u
                    && p2_is_allocated((uint8_t)value);
                uint8_t code[] = {
                    0x62,0xf5,rows[row_index].p1,(uint8_t)value,0x6f,modrm
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code),
#if USE_EXTRA_OPCODES
                    &flags,
#else
                    NULL,
#endif
                    &decoded_size);

                if (valid) {
#if USE_EXTRA_OPCODES
                    check_movrs(&instruction, decoded_size, &rows[row_index],
                        (value >> 5) & 3u, code[1], code[2], code[3],
                        code[5]);
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    ++p2_allocated;
                } else {
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(
                        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                    ++p2_reserved;
                }
            }
        }
    }

    {
        size_t row_index;

        for (row_index = 0u; row_index < sizeof(rows) / sizeof(rows[0]);
             ++row_index) {
            unsigned int p0_index;

            for (p0_index = 0u; p0_index < 32u; ++p0_index) {
                const uint8_t p0 = (uint8_t)((p0_index << 3) | 5u);
                unsigned int u;

                for (u = 0u; u < 2u; ++u) {
                    const uint8_t p1 = (uint8_t)(
                        (rows[row_index].p1 & UINT8_C(0xfb)) | (u << 2));
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const int valid = modrm < 192u;
                        uint8_t code[12] = {
                            0x62,p0,p1,0x08,0x6f,(uint8_t)modrm,
                            0x24,0x10,0x20,0x30,0x40,0x50
                        };
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_X86, CDISASM_MODE_64,
                            code, sizeof(code),
#if USE_EXTRA_OPCODES
                            &flags,
#else
                            NULL,
#endif
                            &decoded_size);

                        if (valid) {
#if USE_EXTRA_OPCODES
                            check_movrs(&instruction, decoded_size,
                                &rows[row_index], 0u, p0, p1, code[3],
                                code[5]);
#else
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            ++address_allocated;
                        } else {
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(&instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                            ++address_reserved;
                        }
                    }
                }
            }
        }
    }

    EXPECT(p1_allocated == UINT32_C(8));
    EXPECT(p1_reserved == UINT32_C(504));
    EXPECT(p2_allocated == UINT32_C(180));
    EXPECT(p2_reserved == UINT32_C(1868));
    EXPECT(address_allocated == UINT32_C(49152));
    EXPECT(address_reserved == UINT32_C(16384));
}

static void test_profiles_runtime_extensions_and_disp8(void)
{
    static const uint8_t normal[] = {0x62,0xf5,0x7f,0x08,0x6f,0x00};
    static const uint8_t b4[] = {0x62,0xfd,0x7f,0x08,0x6f,0x00};
#if USE_EXTRA_OPCODES
    static const uint8_t x4[] = {0x62,0xf5,0x7b,0x08,0x6f,0x04,0xa4};
    static const uint8_t vector_ext[] = {0x62,0x05,0x7f,0x48,0x6f,0x38};
    static const uint8_t disp8[] = {0x62,0xf5,0xff,0xa9,0x6f,0x40,0xff};

    static const cdisasm_x86_cpu_id positive_profiles[] = {
        CDISASM_CPU_AVX10, CDISASM_CPU_APX, CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const cdisasm_x86_cpu_id negative_profiles[] = {
        CDISASM_CPU_SKYLAKE_SP, CDISASM_CPU_GRANITE_RAPIDS
    };
    cdisasm_x86_decode_flags exact128 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX10_MOVRS_128);
    cdisasm_x86_decode_flags exact256 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX10_MOVRS_256);
    cdisasm_x86_decode_flags exact512 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX10_MOVRS_512);
    cdisasm_x86_decode_flags exact128_apx = two_bits(
        CDISASM_X86_DECODE_BIT_AVX10_MOVRS_128,
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags family = one_bit(CDISASM_X86_DECODE_BIT_AVX10);
    cdisasm_x86_decode_flags available;
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    for (index = 0u;
         index < sizeof(positive_profiles) / sizeof(positive_profiles[0]);
         ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            positive_profiles[index], CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        instruction = decode(positive_profiles[index], CDISASM_MODE_64,
            normal, sizeof(normal), &available, &decoded_size);
        check_movrs(&instruction, decoded_size, &rows[0], 0u,
            normal[1], normal[2], normal[3], normal[5]);
    }
    for (index = 0u;
         index < sizeof(negative_profiles) / sizeof(negative_profiles[0]);
         ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            negative_profiles[index], CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        expect_error("MOVRS negative profile", negative_profiles[index],
            CDISASM_MODE_64, normal, sizeof(normal), &available,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    expect_error("family flag does not replace exact bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, normal, sizeof(normal), &family,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("wrong width exact bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, normal, sizeof(normal), &exact256,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("APX extension runtime gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, b4, sizeof(b4), &exact128,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 profile rejects APX extension", CDISASM_CPU_AVX10,
        CDISASM_MODE_64, b4, sizeof(b4), &exact128_apx,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b4, sizeof(b4), &exact128_apx, &decoded_size);
    check_movrs(&instruction, decoded_size, &rows[0], 0u,
        b4[1], b4[2], b4[3], b4[5]);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R16);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        x4, sizeof(x4), &exact128_apx, &decoded_size);
    check_movrs(&instruction, decoded_size, &rows[0], 0u,
        x4[1], x4[2], x4[3], x4[5]);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RSP);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R20);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vector_ext, sizeof(vector_ext), &exact512, &decoded_size);
    check_movrs(&instruction, decoded_size, &rows[0], 2u,
        vector_ext[1], vector_ext[2], vector_ext[3], vector_ext[5]);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ZMM31);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R8);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        disp8, sizeof(disp8), &exact256, &decoded_size);
    check_movrs(&instruction, decoded_size, &rows[3], 1u,
        disp8[1], disp8[2], disp8[3], disp8[5]);
    EXPECT(instruction.opcode[1].imm == (uint64_t)INT64_C(-32));
#else
    expect_error("VMOVRS extras off", CDISASM_CPU_X86, CDISASM_MODE_64,
        normal, sizeof(normal), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VMOVRS APX extras off", CDISASM_CPU_X86, CDISASM_MODE_64,
        b4, sizeof(b4), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_invalid_and_truncated(void)
{
    static const uint8_t invalid[][7] = {
        {0x62,0xf5,0x6f,0x08,0x6f,0x00,0x00},
        {0x62,0xf5,0x7f,0x00,0x6f,0x00,0x00},
        {0x62,0xf5,0x7f,0x18,0x6f,0x00,0x00},
        {0x62,0xf5,0x7f,0x68,0x6f,0x00,0x00},
        {0x62,0xf5,0x7f,0x88,0x6f,0x00,0x00},
        {0x62,0xf5,0x7f,0x08,0x6f,0xc0,0x00},
        {0x62,0xf5,0x7d,0x08,0x6f,0x00,0x00},
        {0x62,0xf5,0x7c,0x08,0x6f,0x00,0x00}
    };
    static const uint8_t missing_modrm[] = {0x62,0xf5,0x7f,0x08,0x6f};
    static const uint8_t bad_control_missing_sib[] = {
        0x62,0xf5,0x6f,0x08,0x6f,0x04
    };
    static const uint8_t normal[] = {0x62,0xf5,0x7f,0x08,0x6f,0x00};
    size_t index;

    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error("reserved VMOVRS selector", CDISASM_CPU_X86,
            CDISASM_MODE_64, invalid[index], sizeof(invalid[index]), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("VMOVRS mode16", CDISASM_CPU_X86, CDISASM_MODE_16,
        normal, sizeof(normal), NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VMOVRS mode32", CDISASM_CPU_X86, CDISASM_MODE_32,
        normal, sizeof(normal), NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VMOVRS missing ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, missing_modrm, sizeof(missing_modrm), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("VMOVRS bad control missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64, bad_control_missing_sib,
        sizeof(bad_control_missing_sib), NULL, CDISASM_STATUS_TRUNCATED);
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const uint8_t code[] = {0x62,0xf5,0xff,0xa9,0x6f,0x40,0xff};
    cdisasm_x86_decode_flags flags =
        one_bit(CDISASM_X86_DECODE_BIT_AVX10_MOVRS_256);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    char output[128];

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        code, sizeof(code), &flags, &decoded_size);
    check_movrs(&instruction, decoded_size, &rows[3], 1u,
        code[1], code[2], code[3], code[5]);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output))
        == strlen("vmovrsw ymm0 {k1}{z}, ymmword ptr [rax - 0x20]"));
    EXPECT(strcmp(output,
        "vmovrsw ymm0 {k1}{z}, ymmword ptr [rax - 0x20]") == 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output))
        == strlen("vmovrsw -0x20(%rax), %ymm0{%k1}{z}"));
    EXPECT(strcmp(output, "vmovrsw -0x20(%rax), %ymm0{%k1}{z}") == 0);
#endif
}

int main(void)
{
#define RUN_TEST(function)                                                   \
    do {                                                                     \
        int before = failures;                                               \
        function();                                                          \
        if (failures != before) {                                            \
            fprintf(stderr, #function ": %d new failure(s)\n",             \
                failures - before);                                          \
        }                                                                    \
    } while (0)

    RUN_TEST(test_all_twelve_forms);
    RUN_TEST(test_complete_allocated_domain);
    RUN_TEST(test_factored_reserved_spaces);
    RUN_TEST(test_profiles_runtime_extensions_and_disp8);
    RUN_TEST(test_invalid_and_truncated);
    RUN_TEST(test_formatting);

#undef RUN_TEST

    if (failures != 0) {
        fprintf(stderr, "%d VMOVRS test(s) failed\n", failures);
        return 1;
    }
    puts("x86 VMOVRS tests passed (12 forms; allocated=2,211,840; "
         "factored reserved=18,756; collisions=0)");
    return 0;
}
