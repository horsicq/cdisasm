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

_Static_assert(CDISASM_X86_NAME_VDBPSADBW == UINT16_C(1635),
    "VDBPSADBW name ID changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX512BW_128 == UINT16_C(162)
        && CDISASM_X86_GROUP_AVX512BW_256 == UINT16_C(164)
        && CDISASM_X86_GROUP_AVX512BW_512 == UINT16_C(165),
    "VDBPSADBW ISA-set IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512BW_128 == UINT32_C(110)
        && CDISASM_X86_DECODE_BIT_AVX512BW_256 == UINT32_C(112)
        && CDISASM_X86_DECODE_BIT_AVX512BW_512 == UINT32_C(113),
    "VDBPSADBW runtime-bit IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VDBPSADBW profile sweeps");

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

static cdisasm_x86_decode_flags all_flags(cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, mode, &flags) == CDISASM_STATUS_OK);
    return flags;
}

static cdisasm_x86_group_id width_group(unsigned int ll)
{
    static const cdisasm_x86_group_id groups[3] = {
        CDISASM_X86_GROUP_AVX512BW_128,
        CDISASM_X86_GROUP_AVX512BW_256,
        CDISASM_X86_GROUP_AVX512BW_512
    };

    return groups[ll];
}

static void check_vdbpsadbw(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    unsigned int ll,
    int register_form,
    unsigned int aaa,
    int zero,
    int apx)
{
    const unsigned int vector_bytes = 16u << ll;
    const cdisasm_x86_form_id form_id = (cdisasm_x86_form_id)(
        UINT16_C(4453) + 2u * ll + (register_form ? 1u : 0u));

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_VDBPSADBW);
    EXPECT(instruction->form_id == form_id);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
    EXPECT(instruction->operand_count == 4u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].size == vector_bytes);
    EXPECT(instruction->opcode[0].access == (aaa != 0u && !zero
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].size == vector_bytes);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[2].size == vector_bytes);
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[3].size == 1u);
    EXPECT(instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[2].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[3].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, width_group(ll)));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == apx);
    EXPECT(instruction->mask_reg == (aaa == 0u
        ? CDISASM_X86_REG_NONE
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
    EXPECT(instruction->mask_mode == (aaa == 0u
        ? CDISASM_X86_MASK_NONE
        : zero ? CDISASM_X86_MASK_ZERO : CDISASM_X86_MASK_MERGE));
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->encoding.immediate_count == 1u);
    EXPECT(instruction->encoding.immediate_size[0] == 1u);
    EXPECT(instruction->encoding.immediate_offset[0]
        == decoded_size - UINT32_C(1));
}
#endif

#if USE_EXTRA_OPCODES
static cdisasm_x86_form_id expected_form(unsigned int ll, int reg)
{
    return (cdisasm_x86_form_id)(
        UINT16_C(4453) + 2u * ll + (reg ? 1u : 0u));
}
#endif

static void test_allocation_and_exact_forms(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint64_t form_counts[6] = {0,0,0,0,0,0};
    uint64_t allocated = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        const unsigned int p0_count = long_mode ? 32u : 4u;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        unsigned int p0_index;

        for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
            const uint8_t p0 = long_mode
                ? (uint8_t)((p0_index << 3) | 3u)
                : (uint8_t)(0xc3u | (p0_index << 4));
            unsigned int ll;

            for (ll = 0u; ll < 3u; ++ll) {
                unsigned int vprime_raw;

                for (vprime_raw = long_mode ? 0u : 1u;
                     vprime_raw <= 1u; ++vprime_raw) {
                    unsigned int zero;

                    for (zero = 0u; zero <= 1u; ++zero) {
                        unsigned int aaa;

                        for (aaa = zero ? 1u : 0u; aaa < 8u; ++aaa) {
                            const uint8_t p2 = (uint8_t)((zero << 7)
                                | (ll << 5) | (vprime_raw << 3) | aaa);
                            unsigned int modrm;

                            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                                const int reg = (modrm & 0xc0u) == 0xc0u;
                                const int apx = long_mode
                                    && (p0 & UINT8_C(0x08)) != 0u;
                                uint8_t code[15] = {
                                    0x62,p0,0x7d,p2,0x42,(uint8_t)modrm,
                                    0x24,0x10,0x20,0x30,0x40,0x50,0x60,
                                    0x70,0x80
                                };
                                uint32_t decoded_size;
                                cdisasm_instruction instruction = decode(
                                    CDISASM_CPU_X86,modes[mode_index],
                                    code,sizeof(code),
#if USE_EXTRA_OPCODES
                                    &flags,
#else
                                    NULL,
#endif
                                    &decoded_size);

#if USE_EXTRA_OPCODES
                                check_vdbpsadbw(&instruction,decoded_size,
                                    ll,reg,aaa,zero != 0u,apx);
                                EXPECT(instruction.form_id
                                    == expected_form(ll,reg));
                                EXPECT(instruction.opcode[3].imm == (uint64_t)
                                    code[decoded_size - UINT32_C(1)]);
#else
                                (void)apx;
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                ++form_counts[ll * 2u + (reg ? 1u : 0u)];
                                ++allocated;
                            }
                        }
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT64_C(829440));
    EXPECT(form_counts[0] == UINT64_C(207360));
    EXPECT(form_counts[1] == UINT64_C(69120));
    EXPECT(form_counts[2] == UINT64_C(207360));
    EXPECT(form_counts[3] == UINT64_C(69120));
    EXPECT(form_counts[4] == UINT64_C(207360));
    EXPECT(form_counts[5] == UINT64_C(69120));
}

static void test_owned_control_spaces(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint32_t p1_allocated = 0u;
    uint32_t p1_reserved = 0u;
    uint32_t p2_allocated = 0u;
    uint32_t p2_reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        unsigned int selector;

        for (selector = 0u; selector < 64u; ++selector) {
            const unsigned int w = (selector >> 5) & 1u;
            const unsigned int u = (selector >> 4) & 1u;
            const unsigned int vvvv_raw = selector & 15u;
            const uint8_t p1 = (uint8_t)((w << 7)
                | (vvvv_raw << 3) | (u << 2) | 1u);
            unsigned int rep;

            for (rep = 0u; rep < 2u; ++rep) {
                const int reg = rep != 0u;
                const int valid = w == 0u
                    && (u != 0u || (long_mode && !reg));
                const uint8_t code[] = {
                    0x62,0xf3,p1,0x08,0x42,
                    (uint8_t)(reg ? 0xc1 : 0x00),0x7f
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86,modes[mode_index],code,sizeof(code),
#if USE_EXTRA_OPCODES
                    &flags,
#else
                    NULL,
#endif
                    &decoded_size);

                if (!valid) {
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_INVALID_INSTRUCTION));
                    ++p1_reserved;
                } else {
#if USE_EXTRA_OPCODES
                    check_vdbpsadbw(&instruction,decoded_size,
                        0u,reg,0u,0,long_mode && u == 0u);
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    ++p1_allocated;
                }
            }
        }

        for (selector = 0u; selector <= UINT8_MAX; ++selector) {
            const uint8_t p2 = (uint8_t)selector;
            const unsigned int ll = (p2 >> 5) & 3u;
            const unsigned int aaa = p2 & 7u;
            const int valid = ll < 3u
                && (p2 & UINT8_C(0x10)) == 0u
                && ((p2 & UINT8_C(0x80)) == 0u || aaa != 0u)
                && (long_mode || (p2 & UINT8_C(0x08)) != 0u);
            unsigned int rep;

            for (rep = 0u; rep < 2u; ++rep) {
                const int reg = rep != 0u;
                const uint8_t code[] = {
                    0x62,0xf3,0x7d,p2,0x42,
                    (uint8_t)(reg ? 0xc1 : 0x00),0x7f
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86,modes[mode_index],code,sizeof(code),
#if USE_EXTRA_OPCODES
                    &flags,
#else
                    NULL,
#endif
                    &decoded_size);

                if (!valid) {
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_INVALID_INSTRUCTION));
                    ++p2_reserved;
                } else {
#if USE_EXTRA_OPCODES
                    check_vdbpsadbw(&instruction,decoded_size,ll,reg,aaa,
                        (p2 & UINT8_C(0x80)) != 0u,0);
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    ++p2_allocated;
                }
            }
        }
    }

    EXPECT(p1_allocated == UINT32_C(112));
    EXPECT(p1_reserved == UINT32_C(272));
    EXPECT(p2_allocated == UINT32_C(360));
    EXPECT(p2_reserved == UINT32_C(1176));
}

static void test_features_profiles_extensions_and_disp8(void)
{
    static const uint8_t forms[3][7] = {
        {0x62,0xf3,0x7d,0x08,0x42,0xc1,0x7f},
        {0x62,0xf3,0x7d,0x28,0x42,0xc1,0x7f},
        {0x62,0xf3,0x7d,0x48,0x42,0xc1,0x7f}
    };
    static const uint8_t b4_reg[] =
        {0x62,0xfb,0x7d,0x08,0x42,0xc1,0x7f};
    static const uint8_t b4_mem[] =
        {0x62,0xfb,0x7d,0x08,0x42,0x00,0x7f};
    static const uint8_t x4_mem[] =
        {0x62,0xf3,0x79,0x08,0x42,0x04,0xa4,0x7f};
    static const uint8_t high_regs[] =
        {0x62,0x03,0x3d,0x00,0x42,0xc1,0x7f};
    static const uint8_t nonlong[] =
        {0x62,0xc3,0x3d,0x08,0x42,0xc1,0x7f};
    static const uint8_t disp8[3][8] = {
        {0x62,0xf3,0x7d,0x08,0x42,0x40,0xff,0x7f},
        {0x62,0xf3,0x7d,0x28,0x42,0x40,0xff,0x7f},
        {0x62,0xf3,0x7d,0x48,0x42,0x40,0xff,0x7f}
    };
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_cpu_id positive_profiles[] = {
        CDISASM_CPU_SKYLAKE_SP,CDISASM_CPU_ICE_LAKE,
        CDISASM_CPU_TIGER_LAKE,CDISASM_CPU_AMD_ZEN_4,
        CDISASM_CPU_SAPPHIRE_RAPIDS,CDISASM_CPU_AVX10,
        CDISASM_CPU_APX,CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const cdisasm_x86_cpu_id negative_profiles[] = {
        CDISASM_CPU_HASWELL,CDISASM_CPU_KNIGHTS_MILL
    };
    static const cdisasm_x86_cpu_id apx_profiles[] = {
        CDISASM_CPU_APX,CDISASM_CPU_DIAMOND_RAPIDS
    };
    cdisasm_x86_decode_flags exact[3] = {
        one_bit(CDISASM_X86_DECODE_BIT_AVX512BW_128),
        one_bit(CDISASM_X86_DECODE_BIT_AVX512BW_256),
        one_bit(CDISASM_X86_DECODE_BIT_AVX512BW_512)
    };
    cdisasm_x86_decode_flags umbrella =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512);
    cdisasm_x86_decode_flags b4_flags = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512BW_128,
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags available;
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;
    unsigned int ll;

    for (ll = 0u; ll < 3u; ++ll) {
        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            forms[ll],sizeof(forms[ll]),&exact[ll],&decoded_size);
        check_vdbpsadbw(&instruction,decoded_size,ll,1,0u,0,0);
        expect_error("width mismatch",CDISASM_CPU_X86,CDISASM_MODE_64,
            forms[ll],sizeof(forms[ll]),&exact[(ll + 1u) % 3u],
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    expect_error("AVX512 umbrella is not exact",CDISASM_CPU_X86,
        CDISASM_MODE_64,forms[0],sizeof(forms[0]),&umbrella,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    for (index = 0u;
         index < sizeof(positive_profiles) / sizeof(positive_profiles[0]);
         ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(positive_profiles[index],
            CDISASM_MODE_64,&available) == CDISASM_STATUS_OK);
        for (ll = 0u; ll < 3u; ++ll) {
            instruction = decode(positive_profiles[index],CDISASM_MODE_64,
                forms[ll],sizeof(forms[ll]),&available,&decoded_size);
            EXPECT(decoded_size == sizeof(forms[ll]));
            EXPECT(instruction.form_id == expected_form(ll,1));
        }
    }
    for (index = 0u;
         index < sizeof(negative_profiles) / sizeof(negative_profiles[0]);
         ++index) {
        expect_error("profile lacks VDBPSADBW",negative_profiles[index],
            CDISASM_MODE_64,forms[0],sizeof(forms[0]),NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_SKYLAKE_SP,
        CDISASM_MODE_64,&available) == CDISASM_STATUS_OK);
    instruction = decode(CDISASM_CPU_SKYLAKE_SP,CDISASM_MODE_64,
        forms[0],sizeof(forms[0]),&available,&decoded_size);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction,CDISASM_X86_GROUP_AVX512F));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction,CDISASM_X86_GROUP_AVX512BW));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction,CDISASM_X86_GROUP_AVX512VL));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction,CDISASM_X86_GROUP_AVX10_1));
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_AVX10,
        CDISASM_MODE_64,&available) == CDISASM_STATUS_OK);
    instruction = decode(CDISASM_CPU_AVX10,CDISASM_MODE_64,
        forms[0],sizeof(forms[0]),&available,&decoded_size);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction,CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction,CDISASM_X86_GROUP_AVX512F));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction,CDISASM_X86_GROUP_AVX512BW));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction,CDISASM_X86_GROUP_AVX512VL));

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        b4_reg,sizeof(b4_reg),&b4_flags,&decoded_size);
    check_vdbpsadbw(&instruction,decoded_size,0u,1,0u,0,1);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM1);
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        b4_mem,sizeof(b4_mem),&b4_flags,&decoded_size);
    check_vdbpsadbw(&instruction,decoded_size,0u,0,0u,0,1);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R16);
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        x4_mem,sizeof(x4_mem),&b4_flags,&decoded_size);
    check_vdbpsadbw(&instruction,decoded_size,0u,0,0u,0,1);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R20);
    expect_error("APX runtime bit",CDISASM_CPU_X86,CDISASM_MODE_64,
        b4_reg,sizeof(b4_reg),&exact[0],
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 profile rejects B4",CDISASM_CPU_AVX10,
        CDISASM_MODE_64,b4_reg,sizeof(b4_reg),&b4_flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    for (index = 0u;
         index < sizeof(apx_profiles) / sizeof(apx_profiles[0]); ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(apx_profiles[index],
            CDISASM_MODE_64,&available) == CDISASM_STATUS_OK);
        instruction = decode(apx_profiles[index],CDISASM_MODE_64,
            b4_reg,sizeof(b4_reg),&available,&decoded_size);
        EXPECT(decoded_size == sizeof(b4_reg));
    }

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        high_regs,sizeof(high_regs),&exact[0],&decoded_size);
    check_vdbpsadbw(&instruction,decoded_size,0u,1,0u,0,0);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM24);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM24);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM25);
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_32,
        nonlong,sizeof(nonlong),&exact[0],&decoded_size);
    check_vdbpsadbw(&instruction,decoded_size,0u,1,0u,0,0);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM0);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM0);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM1);

    for (ll = 0u; ll < 3u; ++ll) {
        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            disp8[ll],sizeof(disp8[ll]),&exact[ll],&decoded_size);
        check_vdbpsadbw(&instruction,decoded_size,ll,0,0u,0,0);
        EXPECT(instruction.opcode[2].imm
            == (uint64_t)-(int64_t)(16u << ll));
    }
#else
    expect_error("owned extras off",CDISASM_CPU_X86,CDISASM_MODE_64,
        forms[0],sizeof(forms[0]),NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    (void)b4_reg;
    (void)b4_mem;
    (void)x4_mem;
    (void)high_regs;
    (void)nonlong;
    (void)disp8;
#endif
}

static void test_reserved_truncation_and_neighbors(void)
{
    static const struct {
        uint8_t code[7];
        cdisasm_x86_mode mode;
    } invalid[] = {
        {{0x62,0xf3,0xfd,0x08,0x42,0xc1,0x7f},CDISASM_MODE_64},
        {{0x62,0xf3,0x7d,0x68,0x42,0xc1,0x7f},CDISASM_MODE_64},
        {{0x62,0xf3,0x7d,0x18,0x42,0xc1,0x7f},CDISASM_MODE_64},
        {{0x62,0xf3,0x7d,0x10,0x42,0x00,0x7f},CDISASM_MODE_64},
        {{0x62,0xf3,0x7d,0x88,0x42,0xc1,0x7f},CDISASM_MODE_64},
        {{0x62,0xf3,0x79,0x08,0x42,0xc1,0x7f},CDISASM_MODE_64},
        {{0x62,0xcb,0x7d,0x08,0x42,0xc1,0x7f},CDISASM_MODE_32},
        {{0x62,0xc3,0x7d,0x00,0x42,0xc1,0x7f},CDISASM_MODE_32}
    };
    static const uint8_t pp_none[] =
        {0x62,0xf3,0x7c,0x08,0x42,0xc1,0x7f};
    static const uint8_t pp_f2[] =
        {0x62,0xf3,0x7f,0x08,0x42,0xc1,0x7f};
    static const uint8_t pp_f3_neighbor[] =
        {0x62,0xf3,0x7e,0x08,0x42,0xc1,0x7f};
    static const uint8_t legacy_prefix[] =
        {0x66,0x62,0xf3,0x7d,0x08,0x42,0xc1,0x7f};
    static const uint8_t missing_modrm[] =
        {0x62,0xf3,0x7d,0x08,0x42};
    static const uint8_t missing_sib[] =
        {0x62,0xf3,0xfd,0x68,0x42,0x04};
    static const uint8_t missing_imm[] =
        {0x62,0xf3,0x7d,0x08,0x42,0xc1};
    static const uint8_t reserved_missing_imm[] =
        {0x62,0xf3,0xfd,0x68,0x42,0xc1};
    static const uint8_t prefixed_missing_imm[] =
        {0x66,0x62,0xf3,0x7d,0x08,0x42,0xc1};
    size_t index;

    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error("reserved control",CDISASM_CPU_X86,
            invalid[index].mode,invalid[index].code,
            sizeof(invalid[index].code),NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("reserved pp none",CDISASM_CPU_X86,CDISASM_MODE_64,
        pp_none,sizeof(pp_none),NULL,CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved pp F2",CDISASM_CPU_X86,CDISASM_MODE_64,
        pp_f2,sizeof(pp_f2),NULL,CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy prefix",CDISASM_CPU_X86,CDISASM_MODE_64,
        legacy_prefix,sizeof(legacy_prefix),NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("missing ModRM",CDISASM_CPU_X86,CDISASM_MODE_64,
        missing_modrm,sizeof(missing_modrm),NULL,CDISASM_STATUS_TRUNCATED);
    expect_error("missing SIB beats controls",CDISASM_CPU_X86,
        CDISASM_MODE_64,missing_sib,sizeof(missing_sib),NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("missing immediate",CDISASM_CPU_X86,CDISASM_MODE_64,
        missing_imm,sizeof(missing_imm),NULL,CDISASM_STATUS_TRUNCATED);
    expect_error("reserved missing immediate",CDISASM_CPU_X86,
        CDISASM_MODE_64,reserved_missing_imm,sizeof(reserved_missing_imm),
        NULL,CDISASM_STATUS_TRUNCATED);
    expect_error("prefixed missing immediate",CDISASM_CPU_X86,
        CDISASM_MODE_64,prefixed_missing_imm,sizeof(prefixed_missing_imm),
        NULL,CDISASM_STATUS_TRUNCATED);

    {
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86,CDISASM_MODE_64,
            pp_f3_neighbor,sizeof(pp_f3_neighbor),
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        EXPECT(decoded_size == sizeof(pp_f3_neighbor));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VMPSADBW);
        EXPECT(instruction.form_id == UINT16_C(5990));
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_forged_format_rejected(
    const cdisasm_instruction *instruction)
{
    char output[64] = "not empty";

    EXPECT(cdisasm_x86_format(instruction,CDISASM_FORMAT_SYNTAX_INTEL,
        output,sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
    strcpy(output,"not empty");
    EXPECT(cdisasm_x86_format(instruction,CDISASM_FORMAT_SYNTAX_ATT,
        output,sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
}
#endif

static void test_formatting_and_fail_closed_schema(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const struct {
        uint8_t code[8];
        size_t size;
        cdisasm_x86_decode_bit_id bit;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0x62,0xf3,0x65,0x8a,0x42,0xcc,0x5a,0},7,
            CDISASM_X86_DECODE_BIT_AVX512BW_128,
            "vdbpsadbw xmm1 {k2}{z}, xmm3, xmm4, 0x5a",
            "vdbpsadbw $0x5a, %xmm4, %xmm3, %xmm1{%k2}{z}"},
        {{0x62,0xf3,0x45,0x2e,0x42,0x68,0x01,0xa5},8,
            CDISASM_X86_DECODE_BIT_AVX512BW_256,
            "vdbpsadbw ymm5 {k6}, ymm7, ymmword ptr [rax + 0x20], 0xa5",
            "vdbpsadbw $0xa5, 0x20(%rax), %ymm7, %ymm5{%k6}"},
        {{0x62,0xa3,0x65,0xc2,0x42,0xcc,0x3c,0},7,
            CDISASM_X86_DECODE_BIT_AVX512BW_512,
            "vdbpsadbw zmm17 {k2}{z}, zmm19, zmm20, 0x3c",
            "vdbpsadbw $0x3c, %zmm20, %zmm19, %zmm17{%k2}{z}"}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags = one_bit(cases[index].bit);
        cdisasm_instruction instruction;
        uint32_t decoded_size;
        char output[192];
        char tiny[4] = {'x','x','x','x'};
        size_t required;

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            cases[index].code,cases[index].size,&flags,&decoded_size);
        EXPECT(decoded_size == cases[index].size);
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,NULL,0u);
        EXPECT(required == strlen(cases[index].intel));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,output,sizeof(output)) == required);
        if (strcmp(output,cases[index].intel) != 0) {
            fprintf(stderr,"Intel format: got '%s', expected '%s'\n",
                output,cases[index].intel);
            EXPECT(0);
        }
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,tiny,sizeof(tiny)) == required);
        EXPECT(tiny[sizeof(tiny) - 1u] == '\0');
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,NULL,0u);
        EXPECT(required == strlen(cases[index].att));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,output,sizeof(output)) == required);
        if (strcmp(output,cases[index].att) != 0) {
            fprintf(stderr,"AT&T format: got '%s', expected '%s'\n",
                output,cases[index].att);
            EXPECT(0);
        }
    }

    {
        static const uint8_t code[] =
            {0x62,0xfb,0x7d,0x08,0x42,0x00,0x7f};
        cdisasm_x86_decode_flags flags = two_bits(
            CDISASM_X86_DECODE_BIT_AVX512BW_128,
            CDISASM_X86_DECODE_BIT_APX);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86,CDISASM_MODE_64,
            code,sizeof(code),&flags,&decoded_size);
        char output[192];

        EXPECT(decoded_size == sizeof(code));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,output,sizeof(output))
            == strlen("vdbpsadbw xmm0, xmm0, xmmword ptr [r16], 0x7f"));
        EXPECT(strcmp(output,
            "vdbpsadbw xmm0, xmm0, xmmword ptr [r16], 0x7f") == 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,output,sizeof(output))
            == strlen("vdbpsadbw $0x7f, (%r16), %xmm0, %xmm0"));
        EXPECT(strcmp(output,
            "vdbpsadbw $0x7f, (%r16), %xmm0, %xmm0") == 0);
    }

    {
        static const uint8_t code[] =
            {0x62,0xf3,0x65,0x8a,0x42,0xcc,0x5a};
        cdisasm_x86_decode_flags flags =
            one_bit(CDISASM_X86_DECODE_BIT_AVX512BW_128);
        uint32_t decoded_size;
        cdisasm_instruction valid = decode(
            CDISASM_CPU_X86,CDISASM_MODE_64,
            code,sizeof(code),&flags,&decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(code));
        forged = valid;
        forged.form_id = UINT16_C(4453);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VMPSADBW;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.operand_count = 3u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].size = 32u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].type = CDISASM_OPERAND_MEMORY;
        forged.opcode[2].reg = CDISASM_X86_REG_NONE;
        forged.opcode[2].base_reg = CDISASM_X86_REG_RAX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].broadcast = CDISASM_X86_BROADCAST_1_TO_4;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[3].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.rounding = CDISASM_X86_ROUNDING_RN;
        forged.sae = CDISASM_X86_SAE_ENABLED;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_forged_format_rejected(&forged);
    }
#endif
}

int main(void)
{
#define RUN_TEST(function)                                                   \
    do {                                                                     \
        int before = failures;                                               \
        function();                                                          \
        if (failures != before) {                                            \
            fprintf(stderr,#function ": %d new failure(s)\n",             \
                failures - before);                                          \
        }                                                                    \
    } while (0)

    RUN_TEST(test_allocation_and_exact_forms);
    RUN_TEST(test_owned_control_spaces);
    RUN_TEST(test_features_profiles_extensions_and_disp8);
    RUN_TEST(test_reserved_truncation_and_neighbors);
    RUN_TEST(test_formatting_and_fail_closed_schema);
#undef RUN_TEST

    if (failures != 0) {
        fprintf(stderr,"x86 VDBPSADBW tests: %d failure(s)\n",failures);
        return 1;
    }
    puts("x86 VDBPSADBW tests passed");
    return 0;
}
