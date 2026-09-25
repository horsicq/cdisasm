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

_Static_assert(CDISASM_X86_NAME_VPABSB == UINT16_C(1799)
        && CDISASM_X86_NAME_VPABSD == UINT16_C(1800)
        && CDISASM_X86_NAME_VPABSQ == UINT16_C(1801)
        && CDISASM_X86_NAME_VPABSW == UINT16_C(1802),
    "VPABS name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX512BW_128 == UINT16_C(162)
        && CDISASM_X86_GROUP_AVX512BW_256 == UINT16_C(164)
        && CDISASM_X86_GROUP_AVX512BW_512 == UINT16_C(165)
        && CDISASM_X86_GROUP_AVX512F_128 == UINT16_C(180)
        && CDISASM_X86_GROUP_AVX512F_256 == UINT16_C(182)
        && CDISASM_X86_GROUP_AVX512F_512 == UINT16_C(183),
    "VPABS exact-width ISA-set IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512BW_128 == UINT32_C(110)
        && CDISASM_X86_DECODE_BIT_AVX512BW_256 == UINT32_C(112)
        && CDISASM_X86_DECODE_BIT_AVX512BW_512 == UINT32_C(113)
        && CDISASM_X86_DECODE_BIT_AVX512F_128 == UINT32_C(128)
        && CDISASM_X86_DECODE_BIT_AVX512F_256 == UINT32_C(130)
        && CDISASM_X86_DECODE_BIT_AVX512F_512 == UINT32_C(131),
    "VPABS exact-width runtime-bit IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VPABS profile sweeps");

#if USE_EXTRA_OPCODES
static const cdisasm_x86_name_id vpabs_names[4] = {
    CDISASM_X86_NAME_VPABSB,
    CDISASM_X86_NAME_VPABSW,
    CDISASM_X86_NAME_VPABSD,
    CDISASM_X86_NAME_VPABSQ
};
#endif

static const cdisasm_x86_form_id vex_bases[4] = {
    UINT16_C(6088), UINT16_C(6114), UINT16_C(6098), UINT16_C(0)
};

static const cdisasm_x86_form_id evex_bases[4] = {
    UINT16_C(6090), UINT16_C(6116), UINT16_C(6100), UINT16_C(6108)
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

static cdisasm_x86_form_id expected_form(
    unsigned int family,
    int evex,
    unsigned int ll,
    int register_form)
{
    cdisasm_x86_form_id base = evex
        ? evex_bases[family] : vex_bases[family];
    unsigned int width_offset = evex
        ? (family == 3u ? 2u * ll : ll == 2u ? 6u : 2u * ll)
        : (ll != 0u ? 6u : 0u);

    return (cdisasm_x86_form_id)(
        base + width_offset + (register_form ? 1u : 0u));
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

static cdisasm_x86_decode_flags one_bit(
    cdisasm_x86_decode_bit_id bit_id)
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

static cdisasm_x86_group_id width_group(
    unsigned int family,
    unsigned int ll)
{
    static const cdisasm_x86_group_id bw[3] = {
        CDISASM_X86_GROUP_AVX512BW_128,
        CDISASM_X86_GROUP_AVX512BW_256,
        CDISASM_X86_GROUP_AVX512BW_512
    };
    static const cdisasm_x86_group_id f[3] = {
        CDISASM_X86_GROUP_AVX512F_128,
        CDISASM_X86_GROUP_AVX512F_256,
        CDISASM_X86_GROUP_AVX512F_512
    };

    return family <= 1u ? bw[ll] : f[ll];
}

static cdisasm_x86_decode_bit_id width_bit(
    unsigned int family,
    unsigned int ll)
{
    static const cdisasm_x86_decode_bit_id bw[3] = {
        CDISASM_X86_DECODE_BIT_AVX512BW_128,
        CDISASM_X86_DECODE_BIT_AVX512BW_256,
        CDISASM_X86_DECODE_BIT_AVX512BW_512
    };
    static const cdisasm_x86_decode_bit_id f[3] = {
        CDISASM_X86_DECODE_BIT_AVX512F_128,
        CDISASM_X86_DECODE_BIT_AVX512F_256,
        CDISASM_X86_DECODE_BIT_AVX512F_512
    };

    return family <= 1u ? bw[ll] : f[ll];
}

static cdisasm_x86_reg_id vector_reg(
    unsigned int ll,
    unsigned int index)
{
    const cdisasm_x86_reg_id base = ll == 0u ? CDISASM_X86_REG_XMM0
        : ll == 1u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_ZMM0;

    return (cdisasm_x86_reg_id)(base + index);
}

static void check_vpabs(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    unsigned int family,
    int evex,
    unsigned int ll,
    int register_form,
    int broadcast,
    unsigned int destination,
    unsigned int source,
    unsigned int aaa,
    int zero,
    int apx)
{
    const unsigned int vector_bytes = 16u << ll;
    const unsigned int element_bytes = 1u << family;
    const cdisasm_x86_mask_mode mask_mode = aaa == 0u
        ? CDISASM_X86_MASK_NONE
        : zero ? CDISASM_X86_MASK_ZERO : CDISASM_X86_MASK_MERGE;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == vpabs_names[family]);
    EXPECT(instruction->form_id == expected_form(
        family, evex, ll, register_form));
    EXPECT(instruction->operand_count == 2u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX))
        == (evex ? CDISASM_PREFIX_EVEX : CDISASM_PREFIX_VEX));
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg == vector_reg(ll, destination));
    EXPECT(instruction->opcode[0].size == vector_bytes);
    EXPECT(instruction->opcode[0].access == (mask_mode
            == CDISASM_X86_MASK_MERGE
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT(instruction->opcode[0].flags == 0u);
    EXPECT(instruction->opcode[0].broadcast
        == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[1].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[1].size == (broadcast
        ? element_bytes : vector_bytes));
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].broadcast
        == (cdisasm_x86_broadcast)(broadcast
            ? vector_bytes / element_bytes : 0u));
    if (register_form) {
        EXPECT(instruction->opcode[1].reg == vector_reg(ll, source));
        EXPECT(instruction->opcode[1].flags == 0u);
    }
    EXPECT(instruction->mask_reg == (aaa == 0u
        ? CDISASM_X86_REG_NONE
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
    EXPECT(instruction->mask_mode == mask_mode);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == apx);
    if (!evex) {
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX2) == (ll != 0u));
    } else {
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512F));
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512VL) == (ll < 2u));
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512BW) == (family <= 1u));
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, width_group(family, ll)));
    }
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    unsigned int family,
    int evex,
    unsigned int ll,
    int register_form,
    int broadcast,
    unsigned int destination,
    unsigned int source,
    unsigned int aaa,
    int zero,
    int apx)
{
#if USE_EXTRA_OPCODES
    check_vpabs(instruction, decoded_size, family, evex, ll,
        register_form, broadcast, destination, source, aaa, zero, apx);
#else
    (void)family;
    (void)evex;
    (void)ll;
    (void)register_form;
    (void)broadcast;
    (void)destination;
    (void)source;
    (void)aaa;
    (void)zero;
    (void)apx;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_vex_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint64_t forms[36] = {0};
    uint64_t allocated = 0;
    uint64_t reserved = 0;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        unsigned int family;

        for (family = 0u; family < 3u; ++family) {
            unsigned int w;

            for (w = 0u; w < 2u; ++w) {
                unsigned int ll;

                for (ll = 0u; ll < 2u; ++ll) {
                    unsigned int pp;

                    for (pp = 0u; pp < 4u; ++pp) {
                        unsigned int vvvv;

                        for (vvvv = 0u; vvvv < 16u; ++vvvv) {
                            unsigned int modrm;

                            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                                const int register_form =
                                    (modrm & UINT8_C(0xc0))
                                        == UINT8_C(0xc0);
                                const int valid = pp == 1u && vvvv == 0u;
                                const uint8_t code[14] = {
                                    0xc4,0xe2,
                                    (uint8_t)((w << 7)
                                        | (((~vvvv) & 15u) << 3)
                                        | (ll << 2) | pp),
                                    (uint8_t)(0x1c + family),
                                    (uint8_t)modrm,0x24,0x10,0x20,0x30,
                                    0x40,0x50,0x60,0x70,0x80
                                };
                                uint32_t decoded_size;
                                cdisasm_instruction instruction = decode(
                                    CDISASM_CPU_X86, modes[mode_index],
                                    code, sizeof(code),
#if USE_EXTRA_OPCODES
                                    &flags, &decoded_size);
#else
                                    NULL, &decoded_size);
#endif

                                if (valid) {
                                    cdisasm_x86_form_id form = expected_form(
                                        family, 0, ll, register_form);

                                    check_allocated(&instruction,
                                        decoded_size,family,0,ll,
                                        register_form,0,(modrm >> 3) & 7u,
                                        modrm & 7u,0u,0,0);
                                    ++forms[form - UINT16_C(6088)];
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
        }
    }
    EXPECT(allocated == UINT64_C(9216));
    EXPECT(reserved == UINT64_C(580608));
    EXPECT(forms[0] != 0u && forms[1] != 0u);
    EXPECT(forms[6] != 0u && forms[7] != 0u);
    EXPECT(forms[10] != 0u && forms[11] != 0u);
    EXPECT(forms[16] != 0u && forms[17] != 0u);
    EXPECT(forms[26] != 0u && forms[27] != 0u);
    EXPECT(forms[32] != 0u && forms[33] != 0u);
}

static void test_evex_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint64_t forms[36] = {0};
    uint64_t allocated = 0;
    uint64_t reserved = 0;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        unsigned int family;

        for (family = 0u; family < 4u; ++family) {
            unsigned int w;

            for (w = 0u; w < 2u; ++w) {
                unsigned int ll;

                for (ll = 0u; ll < 4u; ++ll) {
                    unsigned int b;

                    for (b = 0u; b < 2u; ++b) {
                        unsigned int aaa;

                        for (aaa = 0u; aaa < 8u; ++aaa) {
                            unsigned int z;

                            for (z = 0u; z < 2u; ++z) {
                                unsigned int modrm;

                                for (modrm = 0u; modrm <= UINT8_MAX;
                                     ++modrm) {
                                    const int register_form =
                                        (modrm & UINT8_C(0xc0))
                                            == UINT8_C(0xc0);
                                    const int valid_w = family <= 1u
                                        || w == family - 2u;
                                    const int valid_b = b == 0u
                                        || (!register_form && family >= 2u);
                                    const int valid = valid_w && ll < 3u
                                        && valid_b && (z == 0u || aaa != 0u);
                                    const uint8_t code[15] = {
                                        0x62,0xf2,
                                        (uint8_t)((w << 7) | 0x7d),
                                        (uint8_t)((z << 7) | (ll << 5)
                                            | (b << 4) | 0x08 | aaa),
                                        (uint8_t)(0x1c + family),
                                        (uint8_t)modrm,0x24,0x10,0x20,0x30,
                                        0x40,0x50,0x60,0x70,0x80
                                    };
                                    uint32_t decoded_size;
                                    cdisasm_instruction instruction = decode(
                                        CDISASM_CPU_X86,
                                        modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                                        &flags, &decoded_size);
#else
                                        NULL, &decoded_size);
#endif

                                    if (valid) {
                                        cdisasm_x86_form_id form =
                                            expected_form(family,1,ll,
                                                register_form);

                                        check_allocated(&instruction,
                                            decoded_size,family,1,ll,
                                            register_form,b != 0u,
                                            (modrm >> 3) & 7u,modrm & 7u,
                                            aaa,z != 0u,0);
                                        ++forms[form - UINT16_C(6088)];
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
            }
        }
    }
    EXPECT(allocated == UINT64_C(259200));
    EXPECT(reserved == UINT64_C(527232));
    for (mode_index = 0u; mode_index < 36u; ++mode_index) {
        if (mode_index == 0u || mode_index == 1u
            || mode_index == 6u || mode_index == 7u
            || mode_index == 10u || mode_index == 11u
            || mode_index == 16u || mode_index == 17u
            || mode_index == 26u || mode_index == 27u
            || mode_index == 32u || mode_index == 33u) {
            continue;
        }
        EXPECT(forms[mode_index] != 0u);
    }
}

static void test_evex_pp_vvvv_and_nonlong_aliases(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        unsigned int family;

        for (family = 0u; family < 4u; ++family) {
            unsigned int pp;

            for (pp = 0u; pp < 4u; ++pp) {
                unsigned int vvvv;

                for (vvvv = 0u; vvvv < 32u; ++vvvv) {
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                        const int valid = pp == 1u && vvvv == 0u;
                        const unsigned int w = family == 3u;
                        const uint8_t code[15] = {
                            0x62,0xf2,
                            (uint8_t)((w << 7)
                                | (((~vvvv) & 15u) << 3) | 0x04 | pp),
                            (uint8_t)(((vvvv < 16u) ? 0x08 : 0x00)),
                            (uint8_t)(0x1c + family),(uint8_t)modrm,
                            0x24,0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80
                        };
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_X86, modes[mode_index],
                            code, sizeof(code),
#if USE_EXTRA_OPCODES
                            &flags, &decoded_size);
#else
                            NULL, &decoded_size);
#endif

                        if (valid) {
                            check_allocated(&instruction,decoded_size,
                                family,1,0u,register_form,0,
                                (modrm >> 3) & 7u,modrm & 7u,0u,0,0);
                        } else {
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(&instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                        }
                    }
                }
            }
        }
    }

    for (mode_index = 0u; mode_index < 2u; ++mode_index) {
        static const uint8_t evex_b_alias[] = {
            0x62,0xd2,0x7d,0x08,0x1c,0xc1
        };
        static const uint8_t evex_rprime_alias[] = {
            0x62,0xe2,0x7d,0x08,0x1c,0xc1
        };
        static const uint8_t vex_b_alias[] = {
            0xc4,0xc2,0x79,0x1c,0xc1
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

        instruction = decode(CDISASM_CPU_X86, modes[mode_index],
            evex_b_alias, sizeof(evex_b_alias),
#if USE_EXTRA_OPCODES
            &flags, &decoded_size);
#else
            NULL, &decoded_size);
#endif
        check_allocated(&instruction,decoded_size,0u,1,0u,1,0,0u,1u,
            0u,0,0);
        instruction = decode(CDISASM_CPU_X86, modes[mode_index],
            evex_rprime_alias, sizeof(evex_rprime_alias),
#if USE_EXTRA_OPCODES
            &flags, &decoded_size);
#else
            NULL, &decoded_size);
#endif
        check_allocated(&instruction,decoded_size,0u,1,0u,1,0,0u,1u,
            0u,0,0);
        instruction = decode(CDISASM_CPU_X86, modes[mode_index],
            vex_b_alias, sizeof(vex_b_alias),
#if USE_EXTRA_OPCODES
            &flags, &decoded_size);
#else
            NULL, &decoded_size);
#endif
        check_allocated(&instruction,decoded_size,0u,0,0u,1,0,0u,1u,
            0u,0,0);
    }
    expect_error("non-long EVEX V prime", CDISASM_CPU_X86,
        CDISASM_MODE_32,
        (const uint8_t[]){0x62,0xf2,0x7d,0x00,0x1c,0xc1},6u,NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("non-long VEX high vvvv", CDISASM_CPU_X86,
        CDISASM_MODE_32,
        (const uint8_t[]){0xc4,0xe2,0x39,0x1c,0xc1},5u,NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_tuples_high_registers_masks_and_apx(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t high[] = {
        0x62,0x02,0x7d,0x48,0x1c,0xfd
    };
    static const uint8_t merge[] = {
        0x62,0xf2,0x7d,0x29,0x1d,0xc2
    };
    static const uint8_t zero[] = {
        0x62,0xf2,0x7d,0xc9,0x1e,0xc2
    };
    static const uint8_t b_full[] = {
        0x62,0xf2,0x7d,0x48,0x1c,0x40,0xff
    };
    static const uint8_t d_full[] = {
        0x62,0xf2,0x7d,0x48,0x1e,0x40,0xff
    };
    static const uint8_t d_broadcast[] = {
        0x62,0xf2,0x7d,0x58,0x1e,0x40,0xff
    };
    static const uint8_t q_broadcast[] = {
        0x62,0xf2,0xfd,0x38,0x1f,0x40,0xff
    };
    static const uint8_t apx_b4_register[] = {
        0x62,0xfa,0x7d,0x08,0x1c,0xc2
    };
    static const uint8_t apx_b4_memory[] = {
        0x62,0xfa,0x7d,0x08,0x1c,0x02
    };
    static const uint8_t apx_x4_memory[] = {
        0x62,0xf2,0x79,0x08,0x1c,0x04,0xa4
    };
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    cdisasm_x86_decode_flags apx_flags = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512BW_128,
        CDISASM_X86_DECODE_BIT_APX);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        high, sizeof(high), &flags, &decoded_size);
    check_vpabs(&instruction,decoded_size,0u,1,2u,1,0,31u,29u,0u,0,0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        merge, sizeof(merge), &flags, &decoded_size);
    check_vpabs(&instruction,decoded_size,1u,1,1u,1,0,0u,2u,1u,0,0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        zero, sizeof(zero), &flags, &decoded_size);
    check_vpabs(&instruction,decoded_size,2u,1,2u,1,0,0u,2u,1u,1,0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b_full, sizeof(b_full), &flags, &decoded_size);
    check_vpabs(&instruction,decoded_size,0u,1,2u,0,0,0u,0u,0u,0,0);
    EXPECT(instruction.opcode[1].imm == (uint64_t)-INT64_C(64));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        d_full, sizeof(d_full), &flags, &decoded_size);
    check_vpabs(&instruction,decoded_size,2u,1,2u,0,0,0u,0u,0u,0,0);
    EXPECT(instruction.opcode[1].imm == (uint64_t)-INT64_C(64));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        d_broadcast, sizeof(d_broadcast), &flags, &decoded_size);
    check_vpabs(&instruction,decoded_size,2u,1,2u,0,1,0u,0u,0u,0,0);
    EXPECT(instruction.opcode[1].imm == (uint64_t)-INT64_C(4));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        q_broadcast, sizeof(q_broadcast), &flags, &decoded_size);
    check_vpabs(&instruction,decoded_size,3u,1,1u,0,1,0u,0u,0u,0,0);
    EXPECT(instruction.opcode[1].imm == (uint64_t)-INT64_C(8));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        apx_b4_register, sizeof(apx_b4_register), &apx_flags,
        &decoded_size);
    check_vpabs(&instruction,decoded_size,0u,1,0u,1,0,0u,2u,0u,0,1);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        apx_b4_memory, sizeof(apx_b4_memory), &apx_flags, &decoded_size);
    check_vpabs(&instruction,decoded_size,0u,1,0u,0,0,0u,0u,0u,0,1);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R18);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        apx_x4_memory, sizeof(apx_x4_memory), &apx_flags, &decoded_size);
    check_vpabs(&instruction,decoded_size,0u,1,0u,0,0,0u,0u,0u,0,1);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R20);
#endif
}

static void test_legal_address_and_segment_prefixes(void)
{
    static const uint8_t vex_address[] = {
        0x67,0xc4,0xe2,0x79,0x1c,0x00
    };
    static const uint8_t vex_segment[] = {
        0x64,0xc4,0xe2,0x79,0x1c,0x00
    };
    static const uint8_t evex_address[] = {
        0x67,0x62,0xf2,0x7d,0x08,0x1c,0x00
    };
    static const uint8_t evex_segment[] = {
        0x64,0x62,0xf2,0x7d,0x08,0x1c,0x00
    };
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
        CDISASM_MODE_64,vex_address,sizeof(vex_address),
#if USE_EXTRA_OPCODES
        &flags,&decoded_size);
#else
        NULL,&decoded_size);
#endif

    check_allocated(&instruction,decoded_size,0u,0,0u,0,0,
        0u,0u,0u,0,0);
#if USE_EXTRA_OPCODES
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_EAX);
#endif
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        vex_segment,sizeof(vex_segment),
#if USE_EXTRA_OPCODES
        &flags,&decoded_size);
#else
        NULL,&decoded_size);
#endif
    check_allocated(&instruction,decoded_size,0u,0,0u,0,0,
        0u,0u,0u,0,0);
#if USE_EXTRA_OPCODES
    EXPECT(instruction.opcode[1].segment_reg == CDISASM_X86_REG_FS);
#endif
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        evex_address,sizeof(evex_address),
#if USE_EXTRA_OPCODES
        &flags,&decoded_size);
#else
        NULL,&decoded_size);
#endif
    check_allocated(&instruction,decoded_size,0u,1,0u,0,0,
        0u,0u,0u,0,0);
#if USE_EXTRA_OPCODES
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_EAX);
#endif
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        evex_segment,sizeof(evex_segment),
#if USE_EXTRA_OPCODES
        &flags,&decoded_size);
#else
        NULL,&decoded_size);
#endif
    check_allocated(&instruction,decoded_size,0u,1,0u,0,0,
        0u,0u,0u,0,0);
#if USE_EXTRA_OPCODES
    EXPECT(instruction.opcode[1].segment_reg == CDISASM_X86_REG_FS);
#endif
}

static void test_runtime_bits_and_profiles(void)
{
#if USE_EXTRA_OPCODES
    unsigned int family;

    for (family = 0u; family < 4u; ++family) {
        unsigned int ll;

        for (ll = 0u; ll < 3u; ++ll) {
            uint8_t code[] = {0x62,0xf2,0x7d,0x08,0x1c,0xc1};
            cdisasm_x86_decode_flags exact = one_bit(
                width_bit(family,ll));
            cdisasm_x86_decode_flags wrong = one_bit(
                width_bit(family,(ll + 1u) % 3u));
            uint32_t decoded_size;
            cdisasm_instruction instruction;

            code[2] = (uint8_t)((family == 3u ? 0x80 : 0) | 0x7d);
            code[3] = (uint8_t)(0x08 | (ll << 5));
            code[4] = (uint8_t)(0x1c + family);
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), &exact, &decoded_size);
            check_vpabs(&instruction,decoded_size,family,1,ll,1,0,
                0u,1u,0u,0,0);
            expect_error("VPABS exact-width mismatch", CDISASM_CPU_X86,
                CDISASM_MODE_64, code, sizeof(code), &wrong,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
    }
    {
        static const uint8_t vex_xmm[] = {0xc4,0xe2,0x79,0x1c,0xc1};
        static const uint8_t vex_ymm[] = {0xc4,0xe2,0x7d,0x1c,0xc1};
        static const uint8_t evex_bw[] = {0x62,0xf2,0x7d,0x48,0x1c,0xc1};
        static const uint8_t evex_q[] = {0x62,0xf2,0xfd,0x48,0x1f,0xc1};
        static const uint8_t apx[] = {0x62,0xfa,0x7d,0x08,0x1c,0xc1};
        const cdisasm_x86_cpu_id cpus[] = {
            CDISASM_CPU_SANDY_BRIDGE, CDISASM_CPU_HASWELL,
            CDISASM_CPU_SKYLAKE_SP, CDISASM_CPU_KNIGHTS_MILL,
            CDISASM_CPU_AVX10, CDISASM_CPU_APX,
            CDISASM_CPU_DIAMOND_RAPIDS
        };
        cdisasm_x86_decode_flags masks[sizeof(cpus) / sizeof(cpus[0])];
        uint32_t decoded_size;
        cdisasm_instruction instruction;
        size_t index;

        for (index = 0u; index < sizeof(cpus) / sizeof(cpus[0]); ++index) {
            EXPECT(cdisasm_x86_cpu_decode_flag_mask(cpus[index],
                CDISASM_MODE_64, &masks[index]) == CDISASM_STATUS_OK);
        }
        instruction = decode(cpus[0],CDISASM_MODE_64,vex_xmm,
            sizeof(vex_xmm),&masks[0],&decoded_size);
        EXPECT(decoded_size == sizeof(vex_xmm));
        expect_error("Sandy Bridge AVX2 gate",cpus[0],CDISASM_MODE_64,
            vex_ymm,sizeof(vex_ymm),&masks[0],
            CDISASM_STATUS_INVALID_INSTRUCTION);
        instruction = decode(cpus[1],CDISASM_MODE_64,vex_ymm,
            sizeof(vex_ymm),&masks[1],&decoded_size);
        EXPECT(decoded_size == sizeof(vex_ymm));
        instruction = decode(cpus[2],CDISASM_MODE_64,evex_bw,
            sizeof(evex_bw),&masks[2],&decoded_size);
        EXPECT(decoded_size == sizeof(evex_bw));
        instruction = decode(cpus[3],CDISASM_MODE_64,evex_q,
            sizeof(evex_q),&masks[3],&decoded_size);
        EXPECT(decoded_size == sizeof(evex_q));
        expect_error("Knights Mill AVX512BW gate",cpus[3],CDISASM_MODE_64,
            evex_bw,sizeof(evex_bw),&masks[3],
            CDISASM_STATUS_INVALID_INSTRUCTION);
        instruction = decode(cpus[4],CDISASM_MODE_64,evex_bw,
            sizeof(evex_bw),&masks[4],&decoded_size);
        EXPECT(decoded_size == sizeof(evex_bw));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction,CDISASM_X86_GROUP_AVX10_1));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction,CDISASM_X86_GROUP_AVX512BW));
        expect_error("AVX10 lacks APX-F",cpus[4],CDISASM_MODE_64,
            apx,sizeof(apx),&masks[4],CDISASM_STATUS_INVALID_INSTRUCTION);
        instruction = decode(cpus[5],CDISASM_MODE_64,apx,sizeof(apx),
            &masks[5],&decoded_size);
        EXPECT(decoded_size == sizeof(apx));
        instruction = decode(cpus[6],CDISASM_MODE_64,apx,sizeof(apx),
            &masks[6],&decoded_size);
        EXPECT(decoded_size == sizeof(apx));
    }
#else
    expect_error("VPABS extras off", CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0x62,0xf2,0x7d,0x08,0x1c,0xc1},6u,NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_truncation_and_legacy(void)
{
    static const struct invalid_case {
        const char *label;
        uint8_t code[7];
        size_t size;
        cdisasm_x86_mode mode;
    } invalid[] = {
        {"EVEX wrong pp",{0x62,0xf2,0x7c,0x08,0x1c,0xc1,0},6,CDISASM_MODE_64},
        {"EVEX D W1",{0x62,0xf2,0xfd,0x08,0x1e,0xc1,0},6,CDISASM_MODE_64},
        {"EVEX Q W0",{0x62,0xf2,0x7d,0x08,0x1f,0xc1,0},6,CDISASM_MODE_64},
        {"EVEX LL3",{0x62,0xf2,0x7d,0x68,0x1c,0xc1,0},6,CDISASM_MODE_64},
        {"EVEX register b",{0x62,0xf2,0x7d,0x18,0x1e,0xc1,0},6,CDISASM_MODE_64},
        {"EVEX BW memory b",{0x62,0xf2,0x7d,0x18,0x1c,0x00,0},6,CDISASM_MODE_64},
        {"EVEX z without mask",{0x62,0xf2,0x7d,0x88,0x1c,0xc1,0},6,CDISASM_MODE_64},
        {"EVEX vvvv",{0x62,0xf2,0x75,0x08,0x1c,0xc1,0},6,CDISASM_MODE_64},
        {"EVEX V prime",{0x62,0xf2,0x7d,0x00,0x1c,0xc1,0},6,CDISASM_MODE_64},
        {"EVEX U0 register",{0x62,0xf2,0x79,0x08,0x1c,0xc1,0},6,CDISASM_MODE_64},
        {"EVEX non-long B4",{0x62,0xfa,0x7d,0x08,0x1c,0xc1,0},6,CDISASM_MODE_32},
        {"EVEX non-long U0",{0x62,0xf2,0x79,0x08,0x1c,0x01,0},6,CDISASM_MODE_32},
        {"VEX wrong pp",{0xc4,0xe2,0x78,0x1c,0xc1,0,0},5,CDISASM_MODE_64},
        {"VEX vvvv",{0xc4,0xe2,0x71,0x1c,0xc1,0,0},5,CDISASM_MODE_64}
    };
    static const uint8_t vex[] = {0xc4,0xe2,0x79,0x1c,0xc1};
    static const uint8_t evex[] = {0x62,0xf2,0x7d,0x08,0x1c,0xc1};
    static const uint8_t legacy_prefixes[][7] = {
        {0x66,0x62,0xf2,0x7d,0x08,0x1c,0xc1},
        {0xf2,0x62,0xf2,0x7d,0x08,0x1c,0xc1},
        {0xf3,0x62,0xf2,0x7d,0x08,0x1c,0xc1},
        {0xf0,0x62,0xf2,0x7d,0x08,0x1c,0xc1},
        {0x48,0x62,0xf2,0x7d,0x08,0x1c,0xc1}
    };
    static const uint8_t vex_legacy_prefixes[][6] = {
        {0x66,0xc4,0xe2,0x79,0x1c,0xc1},
        {0xf2,0xc4,0xe2,0x79,0x1c,0xc1},
        {0xf3,0xc4,0xe2,0x79,0x1c,0xc1},
        {0xf0,0xc4,0xe2,0x79,0x1c,0xc1},
        {0x48,0xc4,0xe2,0x79,0x1c,0xc1}
    };
    static const uint8_t vex_prefixed_truncations[][6] = {
        {0x66,0xc4,0xe2,0x79,0x1c,0x04},
        {0xf2,0xc4,0xe2,0x79,0x1c,0x04},
        {0xf3,0xc4,0xe2,0x79,0x1c,0x04},
        {0xf0,0xc4,0xe2,0x79,0x1c,0x04},
        {0x48,0xc4,0xe2,0x79,0x1c,0x04}
    };
    size_t index;

    for (index = 1u; index < sizeof(vex); ++index) {
        expect_error("truncated VEX VPABS",CDISASM_CPU_X86,
            CDISASM_MODE_64,vex,index,NULL,CDISASM_STATUS_TRUNCATED);
    }
    for (index = 1u; index < sizeof(evex); ++index) {
        expect_error("truncated EVEX VPABS",CDISASM_CPU_X86,
            CDISASM_MODE_64,evex,index,NULL,CDISASM_STATUS_TRUNCATED);
    }
    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error(invalid[index].label,CDISASM_CPU_X86,
            invalid[index].mode,invalid[index].code,invalid[index].size,
            NULL,CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 0u;
         index < sizeof(legacy_prefixes) / sizeof(legacy_prefixes[0]);
         ++index) {
        expect_error("legacy prefix collision",CDISASM_CPU_X86,
            CDISASM_MODE_64,legacy_prefixes[index],
            sizeof(legacy_prefixes[index]),NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 0u;
         index < sizeof(vex_legacy_prefixes)
             / sizeof(vex_legacy_prefixes[0]);
         ++index) {
        expect_error("VEX legacy prefix collision",CDISASM_CPU_X86,
            CDISASM_MODE_64,vex_legacy_prefixes[index],
            sizeof(vex_legacy_prefixes[index]),NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 0u;
         index < sizeof(vex_prefixed_truncations)
             / sizeof(vex_prefixed_truncations[0]);
         ++index) {
        expect_error("prefixed VEX VPABS missing SIB",CDISASM_CPU_X86,
            CDISASM_MODE_64,vex_prefixed_truncations[index],
            sizeof(vex_prefixed_truncations[index]),NULL,
            CDISASM_STATUS_TRUNCATED);
    }
    expect_error("reserved EVEX pp missing SIB",CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x62,0xf2,0x7c,0x08,0x1c,0x04},6u,NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved VEX vvvv missing disp32",CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x71,0x1c,0x05},5u,NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("no VEX VPABSQ",CDISASM_CPU_X86,CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x79,0x1f,0xc1},5u,NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        static const cdisasm_x86_name_id legacy_names[3] = {
            CDISASM_X86_NAME_PABSB,
            CDISASM_X86_NAME_PABSW,
            CDISASM_X86_NAME_PABSD
        };
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);

        for (index = 0u; index < 3u; ++index) {
            const uint8_t code[] = {
                0x66,0x0f,0x38,(uint8_t)(0x1c + index),0xc1
            };
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                CDISASM_MODE_64,code,sizeof(code),&flags,&decoded_size);

            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.name_id == legacy_names[index]);
            EXPECT((instruction.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX)) == 0u);
        }
    }
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_forged_format_rejected(
    const cdisasm_instruction *instruction)
{
    char output[96] = {'x'};

    EXPECT(cdisasm_x86_format(instruction,CDISASM_FORMAT_SYNTAX_INTEL,
        output,sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
    output[0] = 'x';
    EXPECT(cdisasm_x86_format(instruction,CDISASM_FORMAT_SYNTAX_ATT,
        output,sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
}
#endif

static void test_formatting_and_schema(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const struct format_case {
        uint8_t code[7];
        size_t size;
        cdisasm_x86_decode_bit_id bit;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4,0xe2,0x79,0x1c,0xc1,0,0},5,
            CDISASM_X86_DECODE_BIT_AVX,
            "vpabsb xmm0, xmm1","vpabsb %xmm1, %xmm0"},
        {{0x62,0xf2,0x7d,0x89,0x1d,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX512BW_128,
            "vpabsw xmm0 {k1}{z}, xmm2","vpabsw %xmm2, %xmm0{%k1}{z}"},
        {{0x62,0xf2,0x7d,0x58,0x1e,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512F_512,
            "vpabsd zmm0, dword ptr [rax - 0x4]{1to16}",
            "vpabsd -0x4(%rax){1to16}, %zmm0"},
        {{0x62,0xf2,0xfd,0x48,0x1f,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX512F_512,
            "vpabsq zmm0, zmm2","vpabsq %zmm2, %zmm0"}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags = one_bit(cases[index].bit);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64,cases[index].code,cases[index].size,
            &flags,&decoded_size);
        char output[192];
        char tiny[4] = {'x','x','x','x'};
        size_t required;

        EXPECT(decoded_size == cases[index].size);
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,NULL,0u);
        EXPECT(required == strlen(cases[index].intel));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,output,sizeof(output)) == required);
        EXPECT(strcmp(output,cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,tiny,sizeof(tiny)) == required);
        EXPECT(tiny[sizeof(tiny) - 1u] == '\0');
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,NULL,0u);
        EXPECT(required == strlen(cases[index].att));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,output,sizeof(output)) == required);
        EXPECT(strcmp(output,cases[index].att) == 0);
    }
    {
        static const uint8_t code[] = {
            0x62,0xf2,0x7d,0x89,0x1d,0xc2
        };
        cdisasm_x86_decode_flags flags = one_bit(
            CDISASM_X86_DECODE_BIT_AVX512BW_128);
        uint32_t decoded_size;
        cdisasm_instruction valid = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64,code,sizeof(code),&flags,&decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(code));
        forged = valid;
        forged.form_id = UINT16_C(6116);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VPABSB;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags &= ~CDISASM_PREFIX_EVEX;
        forged.opcode_flags |= CDISASM_PREFIX_VEX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].size = 4u;
        forged.opcode[1].broadcast = CDISASM_X86_BROADCAST_1_TO_4;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].type = CDISASM_OPERAND_MEMORY;
        forged.opcode[1].reg = CDISASM_X86_REG_NONE;
        forged.opcode[1].base_reg = CDISASM_X86_REG_RAX;
        expect_forged_format_rejected(&forged);
    }
#endif
}

int main(void)
{
    test_vex_control_partition();
    test_evex_control_partition();
    test_evex_pp_vvvv_and_nonlong_aliases();
    test_tuples_high_registers_masks_and_apx();
    test_legal_address_and_segment_prefixes();
    test_runtime_bits_and_profiles();
    test_reserved_truncation_and_legacy();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "x86 VPABS tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 VPABS tests passed");
    return 0;
}
