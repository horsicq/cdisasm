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

_Static_assert(CDISASM_X86_NAME_VMPSADBW == UINT16_C(1794),
    "VMPSADBW name ID changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46),
    "AVX group identity changed");
_Static_assert(CDISASM_X86_GROUP_AVX512_MEDIAX_128 == UINT16_C(214)
        && CDISASM_X86_GROUP_AVX512_MEDIAX_256 == UINT16_C(215)
        && CDISASM_X86_GROUP_AVX512_MEDIAX_512 == UINT16_C(216),
    "AVX512_MEDIAX group identity changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_128 == UINT32_C(162)
        && CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_256 == UINT32_C(163)
        && CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_512 == UINT32_C(164),
    "AVX512_MEDIAX runtime-bit identity changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VMPSADBW profile sweeps");

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

static unsigned int form_vector_bits(cdisasm_x86_form_id form_id)
{
    if (form_id <= UINT16_C(5990)) {
        return 128u;
    }
    if (form_id <= UINT16_C(5994)) {
        return 256u;
    }
    return 512u;
}

static void check_vmpsadbw(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_form_id form_id,
    int evex,
    int apx,
    unsigned int aaa,
    int zero)
{
    const unsigned int vector_bits = form_vector_bits(form_id);
    const int memory = (form_id & UINT16_C(1)) != 0u;
    const int merge = evex && aaa != 0u && !zero;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_VMPSADBW);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->operand_count == 4u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT(((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u)
        == evex);
    EXPECT(((instruction->opcode_flags & CDISASM_PREFIX_VEX) != 0u)
        == !evex);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].size == vector_bits / 8u);
    EXPECT(instruction->opcode[0].access == (merge
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].size == vector_bits / 8u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].type == (memory
        ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
    EXPECT(instruction->opcode[2].size == vector_bits / 8u);
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[3].size == 1u);
    EXPECT(instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[2].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2)
        == (!evex && vector_bits == 256u));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512_MEDIAX_128)
        == (evex && vector_bits == 128u));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512_MEDIAX_256)
        == (evex && vector_bits == 256u));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512_MEDIAX_512)
        == (evex && vector_bits == 512u));
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
    EXPECT(instruction->encoding.immediate_offset[0]
        == decoded_size - UINT32_C(1));
}
#endif

static cdisasm_x86_form_id vex_form(unsigned int vector_bits, int reg)
{
    if (vector_bits == 128u) {
        return reg ? UINT16_C(5988) : UINT16_C(5987);
    }
    return reg ? UINT16_C(5992) : UINT16_C(5991);
}

static cdisasm_x86_form_id evex_form(unsigned int ll, int reg)
{
    static const cdisasm_x86_form_id memory_forms[3] = {
        UINT16_C(5989), UINT16_C(5993), UINT16_C(5995)
    };
    static const cdisasm_x86_form_id register_forms[3] = {
        UINT16_C(5990), UINT16_C(5994), UINT16_C(5996)
    };

    return reg ? register_forms[ll] : memory_forms[ll];
}

static void test_vex_allocation_and_forms(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint64_t form_counts[4] = {0,0,0,0};
    uint64_t allocated = 0;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        const unsigned int p0_count = long_mode ? 8u : 2u;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        unsigned int p0_index;

        for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
            const uint8_t p0 = long_mode
                ? (uint8_t)((p0_index << 5) | 3u)
                : (uint8_t)(0xc3u | (p0_index << 5));
            unsigned int selector;

            for (selector = 0u; selector < 64u; ++selector) {
                const unsigned int l = (selector >> 5) & 1u;
                const unsigned int w = (selector >> 4) & 1u;
                const unsigned int vvvv = selector & 15u;
                const uint8_t p1 = (uint8_t)((w << 7)
                    | (((~vvvv) & 15u) << 3) | (l << 2) | 1u);
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const int reg = (modrm & 0xc0u) == 0xc0u;
                    const unsigned int vector_bits = l ? 256u : 128u;
                    const cdisasm_x86_form_id form_id =
                        vex_form(vector_bits, reg);
                    uint8_t code[15] = {
                        0xc4,p0,p1,0x42,(uint8_t)modrm,
                        0x24,0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,0x90
                    };
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, modes[mode_index], code,
                        sizeof(code),
#if USE_EXTRA_OPCODES
                        &flags,
#else
                        NULL,
#endif
                        &decoded_size);

#if USE_EXTRA_OPCODES
                    check_vmpsadbw(&instruction, decoded_size, form_id,
                        0, 0, 0u, 0);
                    EXPECT(instruction.opcode[3].imm == (uint64_t)
                        code[decoded_size - UINT32_C(1)]);
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    ++form_counts[form_id == UINT16_C(5987) ? 0u
                        : form_id == UINT16_C(5988) ? 1u
                        : form_id == UINT16_C(5991) ? 2u : 3u];
                    ++allocated;
                }
            }
        }
    }

    EXPECT(allocated == UINT64_C(196608));
    EXPECT(form_counts[0] == UINT64_C(73728));
    EXPECT(form_counts[1] == UINT64_C(24576));
    EXPECT(form_counts[2] == UINT64_C(73728));
    EXPECT(form_counts[3] == UINT64_C(24576));
}

static void test_evex_allocation_and_forms(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint64_t form_counts[6] = {0,0,0,0,0,0};
    uint64_t allocated = 0;
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
                                const cdisasm_x86_form_id form_id =
                                    evex_form(ll, reg);
                                const int apx = long_mode
                                    && (p0 & UINT8_C(0x08)) != 0u;
                                uint8_t code[15] = {
                                    0x62,p0,0x7e,p2,0x42,(uint8_t)modrm,
                                    0x24,0x10,0x20,0x30,0x40,0x50,0x60,
                                    0x70,0x80
                                };
                                uint32_t decoded_size;
                                cdisasm_instruction instruction = decode(
                                    CDISASM_CPU_X86, modes[mode_index], code,
                                    sizeof(code),
#if USE_EXTRA_OPCODES
                                    &flags,
#else
                                    NULL,
#endif
                                    &decoded_size);

#if USE_EXTRA_OPCODES
                                check_vmpsadbw(&instruction, decoded_size,
                                    form_id, 1, apx, aaa, zero != 0u);
                                EXPECT(instruction.opcode[3].imm == (uint64_t)
                                    code[decoded_size - UINT32_C(1)]);
#else
                                (void)apx;
                                (void)form_id;
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

static void test_owned_vex_p1_space(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        unsigned int p1;

        for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
            unsigned int rep;

            for (rep = 0u; rep < 2u; ++rep) {
                const int reg = rep != 0u;
                const int valid = (p1 & 3u) == 1u;
                const unsigned int vector_bits =
                    (p1 & UINT8_C(0x04)) != 0u ? 256u : 128u;
                const uint8_t code[] = {
                    0xc4,0xe3,(uint8_t)p1,0x42,
                    (uint8_t)(reg ? 0xc1 : 0x00),0x7f
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, modes[mode_index], code, sizeof(code),
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
                    ++reserved;
                } else {
#if USE_EXTRA_OPCODES
                    check_vmpsadbw(&instruction, decoded_size,
                        vex_form(vector_bits, reg), 0,0,0u,0);
#else
                    (void)vector_bits;
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    ++allocated;
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(384));
    EXPECT(reserved == UINT32_C(1152));
}

static void test_owned_evex_control_spaces(void)
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
                | (vvvv_raw << 3) | (u << 2) | 2u);
            unsigned int rep;

            for (rep = 0u; rep < 2u; ++rep) {
                const int reg = rep != 0u;
                const int valid = w == 0u && (u != 0u || (long_mode && !reg));
                const uint8_t code[] = {
                    0x62,0xf3,p1,0x08,0x42,
                    (uint8_t)(reg ? 0xc1 : 0x00),0x7f
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, modes[mode_index], code, sizeof(code),
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
                    check_vmpsadbw(&instruction, decoded_size,
                        evex_form(0u, reg), 1, u == 0u, 0u, 0);
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
                    0x62,0xf3,0x7e,p2,0x42,
                    (uint8_t)(reg ? 0xc1 : 0x00),0x7f
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, modes[mode_index], code, sizeof(code),
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
                    check_vmpsadbw(&instruction, decoded_size,
                        evex_form(ll, reg), 1, 0, aaa,
                        (p2 & UINT8_C(0x80)) != 0u);
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
    static const uint8_t vex128[] = {0xc4,0xe3,0x79,0x42,0xc1,0x7f};
    static const uint8_t vex256[] = {0xc4,0xe3,0x7d,0x42,0xc1,0x7f};
    static const uint8_t evex128[] = {0x62,0xf3,0x7e,0x08,0x42,0xc1,0x7f};
    static const uint8_t evex256[] = {0x62,0xf3,0x7e,0x28,0x42,0xc1,0x7f};
    static const uint8_t evex512[] = {0x62,0xf3,0x7e,0x48,0x42,0xc1,0x7f};
    static const uint8_t b4_reg[] = {0x62,0xfb,0x7e,0x08,0x42,0xc1,0x7f};
    static const uint8_t b4_mem[] = {0x62,0xfb,0x7e,0x08,0x42,0x00,0x7f};
    static const uint8_t x4_mem[] = {
        0x62,0xf3,0x7a,0x08,0x42,0x04,0xa4,0x7f
    };
    static const uint8_t high_evex[] = {
        0x62,0x03,0x3e,0x00,0x42,0xc1,0x7f
    };
    static const uint8_t nonlong_evex[] = {
        0x62,0xc3,0x3e,0x08,0x42,0xc1,0x7f
    };
    static const uint8_t nonlong_vex[] = {
        0xc4,0xc3,0x39,0x42,0xc1,0x7f
    };
    static const uint8_t disp128[] = {
        0x62,0xf3,0x7e,0x08,0x42,0x40,0xff,0x7f
    };
    static const uint8_t disp256[] = {
        0x62,0xf3,0x7e,0x28,0x42,0x40,0xff,0x7f
    };
    static const uint8_t disp512[] = {
        0x62,0xf3,0x7e,0x48,0x42,0x40,0xff,0x7f
    };
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_cpu_id mediax_positive[] = {
        CDISASM_CPU_AVX10, CDISASM_CPU_APX, CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const cdisasm_x86_cpu_id mediax_negative[] = {
        CDISASM_CPU_ICE_LAKE, CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_CPU_GRANITE_RAPIDS
    };
    static const cdisasm_x86_cpu_id apx_positive[] = {
        CDISASM_CPU_APX, CDISASM_CPU_DIAMOND_RAPIDS
    };
    cdisasm_x86_decode_flags avx = one_bit(CDISASM_X86_DECODE_BIT_AVX);
    cdisasm_x86_decode_flags avx2 = one_bit(CDISASM_X86_DECODE_BIT_AVX2);
    cdisasm_x86_decode_flags m128 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_128);
    cdisasm_x86_decode_flags m256 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_256);
    cdisasm_x86_decode_flags m512 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_512);
    cdisasm_x86_decode_flags umbrella =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512);
    cdisasm_x86_decode_flags m128_apx = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_128,
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags available;
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vex128, sizeof(vex128), &avx, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5988), 0,0,0u,0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vex256, sizeof(vex256), &avx2, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5992), 0,0,0u,0);
    expect_error("VEX128 needs AVX", CDISASM_CPU_X86, CDISASM_MODE_64,
        vex128, sizeof(vex128), &avx2, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VEX256 needs AVX2", CDISASM_CPU_X86, CDISASM_MODE_64,
        vex256, sizeof(vex256), &avx, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_SANDY_BRIDGE,
        CDISASM_MODE_64, &available) == CDISASM_STATUS_OK);
    instruction = decode(CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
        vex128, sizeof(vex128), &available, &decoded_size);
    EXPECT(decoded_size == sizeof(vex128));
    expect_error("Sandy Bridge lacks AVX2", CDISASM_CPU_SANDY_BRIDGE,
        CDISASM_MODE_64, vex256, sizeof(vex256), &available,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_HASWELL,
        CDISASM_MODE_64, &available) == CDISASM_STATUS_OK);
    instruction = decode(CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        vex256, sizeof(vex256), &available, &decoded_size);
    EXPECT(decoded_size == sizeof(vex256));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        evex128, sizeof(evex128), &m128, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5990), 1,0,0u,0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        evex256, sizeof(evex256), &m256, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5994), 1,0,0u,0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        evex512, sizeof(evex512), &m512, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5996), 1,0,0u,0);
    expect_error("MEDIAX width mismatch", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex128, sizeof(evex128), &m256,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX512 umbrella is not exact", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex128, sizeof(evex128), &umbrella,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    for (index = 0u;
         index < sizeof(mediax_positive) / sizeof(mediax_positive[0]);
         ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(mediax_positive[index],
            CDISASM_MODE_64, &available) == CDISASM_STATUS_OK);
        instruction = decode(mediax_positive[index], CDISASM_MODE_64,
            evex128, sizeof(evex128), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(evex128));
        instruction = decode(mediax_positive[index], CDISASM_MODE_64,
            evex256, sizeof(evex256), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(evex256));
        instruction = decode(mediax_positive[index], CDISASM_MODE_64,
            evex512, sizeof(evex512), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(evex512));
    }
    for (index = 0u;
         index < sizeof(mediax_negative) / sizeof(mediax_negative[0]);
         ++index) {
        expect_error("profile lacks MEDIAX", mediax_negative[index],
            CDISASM_MODE_64, evex128, sizeof(evex128), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_reg, sizeof(b4_reg), &m128_apx, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5990), 1,1,0u,0);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM1);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_mem, sizeof(b4_mem), &m128_apx, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5989), 1,1,0u,0);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R16);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        x4_mem, sizeof(x4_mem), &m128_apx, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5989), 1,1,0u,0);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R20);
    expect_error("APX runtime", CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_reg, sizeof(b4_reg), &m128,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 rejects APX B4", CDISASM_CPU_AVX10,
        CDISASM_MODE_64, b4_reg, sizeof(b4_reg), &m128_apx,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    for (index = 0u;
         index < sizeof(apx_positive) / sizeof(apx_positive[0]); ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(apx_positive[index],
            CDISASM_MODE_64, &available) == CDISASM_STATUS_OK);
        instruction = decode(apx_positive[index], CDISASM_MODE_64,
            b4_reg, sizeof(b4_reg), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(b4_reg));
    }

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        high_evex, sizeof(high_evex), &m128, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5990), 1,0,0u,0);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM24);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM24);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM25);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
        nonlong_evex, sizeof(nonlong_evex), &m128, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5990), 1,0,0u,0);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM0);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM0);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM1);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
        nonlong_vex, sizeof(nonlong_vex), &avx, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5988), 0,0,0u,0);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM0);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM0);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM1);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        disp128, sizeof(disp128), &m128, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5989), 1,0,0u,0);
    EXPECT(instruction.opcode[2].imm == (uint64_t)INT64_C(-16));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        disp256, sizeof(disp256), &m256, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5993), 1,0,0u,0);
    EXPECT(instruction.opcode[2].imm == (uint64_t)INT64_C(-32));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        disp512, sizeof(disp512), &m512, &decoded_size);
    check_vmpsadbw(&instruction, decoded_size, UINT16_C(5995), 1,0,0u,0);
    EXPECT(instruction.opcode[2].imm == (uint64_t)INT64_C(-64));
#else
    expect_error("VEX owned extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex128, sizeof(vex128), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("EVEX owned extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex128, sizeof(evex128), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    (void)vex256;
    (void)evex256;
    (void)evex512;
    (void)b4_reg;
    (void)b4_mem;
    (void)x4_mem;
    (void)high_evex;
    (void)nonlong_evex;
    (void)nonlong_vex;
    (void)disp128;
    (void)disp256;
    (void)disp512;
#endif
}

static void test_reserved_truncated_and_delegated(void)
{
    static const uint8_t invalid[][7] = {
        {0x62,0xf3,0xfe,0x08,0x42,0xc1,0x7f}, /* W1 */
        {0x62,0xf3,0x7e,0x68,0x42,0xc1,0x7f}, /* LL3 */
        {0x62,0xf3,0x7e,0x18,0x42,0xc1,0x7f}, /* b */
        {0x62,0xf3,0x7e,0x88,0x42,0xc1,0x7f}, /* z without k */
        {0x62,0xf3,0x7a,0x08,0x42,0xc1,0x7f}, /* U0 register */
        {0x62,0xfb,0x7e,0x08,0x42,0xc1,0x7f}  /* non-long B4 */
    };
    static const uint8_t vex_bad_pp[][6] = {
        {0xc4,0xe3,0x78,0x42,0xc1,0x7f}, /* none */
        {0xc4,0xe3,0x7a,0x42,0xc1,0x7f}, /* F3 */
        {0xc4,0xe3,0x7b,0x42,0xc1,0x7f}  /* F2 */
    };
    static const uint8_t evex_bad_pp[] = {
        0x62,0xf3,0x7f,0x08,0x42,0xc1,0x7f
    };
    static const uint8_t evex_no_pp[] = {
        0x62,0xf3,0x7c,0x08,0x42,0xc1,0x7f
    };
    static const uint8_t vex_missing_modrm[] = {0xc4,0xe3,0x78,0x42};
    static const uint8_t vex_missing_sib[] = {0xc4,0xe3,0x78,0x42,0x04};
    static const uint8_t vex_missing_imm[] = {0xc4,0xe3,0x79,0x42,0xc1};
    static const uint8_t evex_missing_modrm[] = {
        0x62,0xf3,0xff,0x68,0x42
    };
    static const uint8_t evex_missing_sib[] = {
        0x62,0xf3,0xff,0x68,0x42,0x04
    };
    static const uint8_t evex_missing_imm[] = {
        0x62,0xf3,0x7e,0x08,0x42,0xc1
    };
    static const uint8_t legacy_prefix[] = {
        0x66,0x62,0xf3,0x7e,0x08,0x42,0xc1,0x7f
    };
    static const uint8_t p66_neighbor[] = {
        0x62,0xf3,0x7d,0x08,0x42,0xc1,0x7f
    };
    size_t index;

    for (index = 0u;
         index < sizeof(vex_bad_pp) / sizeof(vex_bad_pp[0]); ++index) {
        expect_error("VEX reserved pp", CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_bad_pp[index], sizeof(vex_bad_pp[index]), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("EVEX raw F2 reserved", CDISASM_CPU_X86, CDISASM_MODE_64,
        evex_bad_pp, sizeof(evex_bad_pp), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("EVEX raw none reserved", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex_no_pp, sizeof(evex_no_pp), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error("reserved EVEX control", CDISASM_CPU_X86,
            index + 1u == sizeof(invalid) / sizeof(invalid[0])
                ? CDISASM_MODE_32 : CDISASM_MODE_64,
            invalid[index], sizeof(invalid[index]), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("legacy-prefix collision", CDISASM_CPU_X86,
        CDISASM_MODE_64, legacy_prefix, sizeof(legacy_prefix), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VEX missing ModRM beats pp", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex_missing_modrm, sizeof(vex_missing_modrm), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("VEX missing SIB beats pp", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex_missing_sib, sizeof(vex_missing_sib), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("VEX missing immediate", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex_missing_imm, sizeof(vex_missing_imm), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("EVEX missing ModRM beats controls", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex_missing_modrm, sizeof(evex_missing_modrm), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("EVEX missing SIB beats controls", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex_missing_sib, sizeof(evex_missing_sib), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("EVEX missing immediate", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex_missing_imm, sizeof(evex_missing_imm), NULL,
        CDISASM_STATUS_TRUNCATED);

    {
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            p66_neighbor, sizeof(p66_neighbor),
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        EXPECT(decoded_size == sizeof(p66_neighbor));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VDBPSADBW);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const struct {
        uint8_t code[8];
        size_t size;
        cdisasm_x86_decode_bit_id bit;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4,0xe3,0x79,0x42,0xc1,0x7f,0,0},6,
            CDISASM_X86_DECODE_BIT_AVX,
            "vmpsadbw xmm0, xmm0, xmm1, 0x7f",
            "vmpsadbw $0x7f, %xmm1, %xmm0, %xmm0"},
        {{0xc4,0xe3,0x7d,0x42,0x40,0x10,0x04,0},7,
            CDISASM_X86_DECODE_BIT_AVX2,
            "vmpsadbw ymm0, ymm0, ymmword ptr [rax + 0x10], 0x4",
            "vmpsadbw $0x4, 0x10(%rax), %ymm0, %ymm0"},
        {{0x62,0xf3,0x7e,0x09,0x42,0xc1,0x7f,0},7,
            CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_128,
            "vmpsadbw xmm0 {k1}, xmm0, xmm1, 0x7f",
            "vmpsadbw $0x7f, %xmm1, %xmm0, %xmm0{%k1}"},
        {{0x62,0xf3,0x7e,0x89,0x42,0xc1,0x7f,0},7,
            CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_128,
            "vmpsadbw xmm0 {k1}{z}, xmm0, xmm1, 0x7f",
            "vmpsadbw $0x7f, %xmm1, %xmm0, %xmm0{%k1}{z}"},
        {{0x62,0xf3,0x7e,0x28,0x42,0x40,0xff,0x04},8,
            CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_256,
            "vmpsadbw ymm0, ymm0, ymmword ptr [rax - 0x20], 0x4",
            "vmpsadbw $0x4, -0x20(%rax), %ymm0, %ymm0"},
        {{0x62,0xf3,0x7e,0x48,0x42,0xc1,0x7f,0},7,
            CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_512,
            "vmpsadbw zmm0, zmm0, zmm1, 0x7f",
            "vmpsadbw $0x7f, %zmm1, %zmm0, %zmm0"}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags = one_bit(cases[index].bit);
        cdisasm_instruction instruction;
        uint32_t decoded_size;
        char output[192];

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        EXPECT(decoded_size == cases[index].size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(cases[index].intel));
        if (strcmp(output, cases[index].intel) != 0) {
            fprintf(stderr, "Intel format: got '%s', expected '%s'\n",
                output, cases[index].intel);
            EXPECT(0);
        }
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(cases[index].att));
        if (strcmp(output, cases[index].att) != 0) {
            fprintf(stderr, "AT&T format: got '%s', expected '%s'\n",
                output, cases[index].att);
            EXPECT(0);
        }
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
            fprintf(stderr, #function ": %d new failure(s)\n",             \
                failures - before);                                          \
        }                                                                    \
    } while (0)

    RUN_TEST(test_vex_allocation_and_forms);
    RUN_TEST(test_evex_allocation_and_forms);
    RUN_TEST(test_owned_vex_p1_space);
    RUN_TEST(test_owned_evex_control_spaces);
    RUN_TEST(test_features_profiles_extensions_and_disp8);
    RUN_TEST(test_reserved_truncated_and_delegated);
    RUN_TEST(test_formatting);
#undef RUN_TEST

    if (failures != 0) {
        fprintf(stderr, "x86 VMPSADBW tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 VMPSADBW tests passed");
    return 0;
}
