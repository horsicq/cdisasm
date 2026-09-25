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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",           \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VPACKSSDW == UINT16_C(1803)
        && CDISASM_X86_NAME_VPACKSSWB == UINT16_C(1804)
        && CDISASM_X86_NAME_VPACKUSDW == UINT16_C(1805)
        && CDISASM_X86_NAME_VPACKUSWB == UINT16_C(1806),
    "VPACK name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX512BW_128 == UINT16_C(162)
        && CDISASM_X86_GROUP_AVX512BW_256 == UINT16_C(164)
        && CDISASM_X86_GROUP_AVX512BW_512 == UINT16_C(165),
    "VPACK exact-width ISA-set IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512BW_128 == UINT32_C(110)
        && CDISASM_X86_DECODE_BIT_AVX512BW_256 == UINT32_C(112)
        && CDISASM_X86_DECODE_BIT_AVX512BW_512 == UINT32_C(113),
    "VPACK exact-width runtime-bit IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VPACK profile sweeps");

static const uint8_t vpack_maps[4] = {1u, 1u, 2u, 1u};
static const uint8_t vpack_opcodes[4] = {0x6b, 0x63, 0x2b, 0x67};
static const cdisasm_x86_form_id vex_xmm_forms[4] = {
    UINT16_C(6124), UINT16_C(6134), UINT16_C(6144), UINT16_C(6154)
};
static const cdisasm_x86_form_id vex_ymm_forms[4] = {
    UINT16_C(6130), UINT16_C(6140), UINT16_C(6148), UINT16_C(6158)
};
static const cdisasm_x86_form_id evex_bases[4] = {
    UINT16_C(6126), UINT16_C(6136), UINT16_C(6146), UINT16_C(6156)
};

#if USE_EXTRA_OPCODES
static const cdisasm_x86_name_id vpack_names[4] = {
    CDISASM_X86_NAME_VPACKSSDW,
    CDISASM_X86_NAME_VPACKSSWB,
    CDISASM_X86_NAME_VPACKUSDW,
    CDISASM_X86_NAME_VPACKUSWB
};
#endif

static int dword_source(unsigned int family)
{
    return family == 0u || family == 2u;
}

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
    unsigned int offset;

    if (!evex) {
        return (cdisasm_x86_form_id)(
            (ll == 0u ? vex_xmm_forms[family] : vex_ymm_forms[family])
            + (register_form ? 1u : 0u));
    }
    if (family < 2u) {
        offset = ll == 2u ? 6u : 2u * ll;
    } else {
        offset = ll == 0u ? 0u : ll == 1u ? 4u : 6u;
    }
    return (cdisasm_x86_form_id)(
        evex_bases[family] + offset + (register_form ? 1u : 0u));
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

static cdisasm_x86_group_id width_group(unsigned int ll)
{
    static const cdisasm_x86_group_id groups[3] = {
        CDISASM_X86_GROUP_AVX512BW_128,
        CDISASM_X86_GROUP_AVX512BW_256,
        CDISASM_X86_GROUP_AVX512BW_512
    };

    return groups[ll];
}

static cdisasm_x86_decode_bit_id width_bit(unsigned int ll)
{
    static const cdisasm_x86_decode_bit_id bits[3] = {
        CDISASM_X86_DECODE_BIT_AVX512BW_128,
        CDISASM_X86_DECODE_BIT_AVX512BW_256,
        CDISASM_X86_DECODE_BIT_AVX512BW_512
    };

    return bits[ll];
}

static cdisasm_x86_reg_id vector_reg(
    unsigned int ll,
    unsigned int index)
{
    const cdisasm_x86_reg_id base = ll == 0u ? CDISASM_X86_REG_XMM0
        : ll == 1u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_ZMM0;

    return (cdisasm_x86_reg_id)(base + index);
}

static void check_vpack(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    unsigned int family,
    int evex,
    unsigned int ll,
    int register_form,
    int broadcast,
    unsigned int destination,
    unsigned int source1,
    unsigned int source2,
    unsigned int aaa,
    int zero,
    int apx)
{
    const unsigned int vector_bytes = 16u << ll;
    const unsigned int element_bytes = dword_source(family) ? 4u : 2u;
    const cdisasm_x86_mask_mode mask_mode = aaa == 0u
        ? CDISASM_X86_MASK_NONE
        : zero ? CDISASM_X86_MASK_ZERO : CDISASM_X86_MASK_MERGE;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == vpack_names[family]);
    EXPECT(instruction->form_id == expected_form(
        family, evex, ll, register_form));
    EXPECT(instruction->operand_count == 3u);
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

    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg == vector_reg(ll, source1));
    EXPECT(instruction->opcode[1].size == vector_bytes);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].flags == 0u);
    EXPECT(instruction->opcode[1].broadcast
        == CDISASM_X86_BROADCAST_NONE);

    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[2].size == (broadcast
        ? element_bytes : vector_bytes));
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].broadcast
        == (cdisasm_x86_broadcast)(broadcast
            ? vector_bytes / element_bytes : 0u));
    if (register_form) {
        EXPECT(instruction->opcode[2].reg == vector_reg(ll, source2));
        EXPECT(instruction->opcode[2].flags == 0u);
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
            instruction, CDISASM_X86_GROUP_AVX512BW));
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, width_group(ll)));
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
    unsigned int source1,
    unsigned int source2,
    unsigned int aaa,
    int zero,
    int apx)
{
#if USE_EXTRA_OPCODES
    check_vpack(instruction, decoded_size, family, evex, ll,
        register_form, broadcast, destination, source1, source2,
        aaa, zero, apx);
#else
    (void)family;
    (void)evex;
    (void)ll;
    (void)register_form;
    (void)broadcast;
    (void)destination;
    (void)source1;
    (void)source2;
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
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
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
                                const int valid = pp == 1u;
                                const uint8_t code[15] = {
                                    0xc4,
                                    (uint8_t)(0xe0u | vpack_maps[family]),
                                    (uint8_t)((w << 7)
                                        | (((~vvvv) & 15u) << 3)
                                        | (ll << 2) | pp),
                                    vpack_opcodes[family],
                                    (uint8_t)modrm,0x24,0x10,0x20,0x30,
                                    0x40,0x50,0x60,0x70,0x80,0x90
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
                                    check_allocated(
                                        &instruction, decoded_size,
                                        family, 0, ll, register_form, 0,
                                        (modrm >> 3) & 7u,
                                        modes[mode_index] == CDISASM_MODE_64
                                            ? vvvv : vvvv & 7u,
                                        modrm & 7u, 0u, 0, 0);
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
    EXPECT(allocated == UINT64_C(196608));
    EXPECT(reserved == UINT64_C(589824));
}

static void test_evex_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint8_t seen[40] = {0};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
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
                                unsigned int pp;

                                for (pp = 0u; pp < 4u; ++pp) {
                                    unsigned int vvvv;

                                    for (vvvv = 0u; vvvv < 32u; ++vvvv) {
                                        unsigned int register_form;

                                        for (register_form = 0u;
                                             register_form < 2u;
                                             ++register_form) {
                                            const int valid =
                                                pp == 1u
                                                && (!dword_source(family)
                                                    || w == 0u)
                                                && ll < 3u
                                                && (b == 0u
                                                    || (!register_form
                                                        && dword_source(
                                                            family)))
                                                && (z == 0u || aaa != 0u)
                                                && (modes[mode_index]
                                                        == CDISASM_MODE_64
                                                    || vvvv < 16u);
                                            const uint8_t code[7] = {
                                                0x62,
                                                (uint8_t)(0xf0u
                                                    | vpack_maps[family]),
                                                (uint8_t)((w << 7)
                                                    | (((~vvvv) & 15u) << 3)
                                                    | 0x04u | pp),
                                                (uint8_t)((z << 7)
                                                    | (ll << 5) | (b << 4)
                                                    | (vvvv < 16u ? 0x08u
                                                                 : 0u)
                                                    | aaa),
                                                vpack_opcodes[family],
                                                (uint8_t)(
                                                    register_form
                                                        ? 0xc2u : 0x02u),
                                                0u
                                            };
                                            uint32_t decoded_size;
                                            cdisasm_instruction instruction =
                                                decode(
                                                    CDISASM_CPU_X86,
                                                    modes[mode_index],
                                                    code, 6u,
#if USE_EXTRA_OPCODES
                                                    &flags, &decoded_size);
#else
                                                    NULL, &decoded_size);
#endif

                                            if (valid) {
                                                cdisasm_x86_form_id form =
                                                    expected_form(
                                                        family, 1, ll,
                                                        register_form != 0u);

                                                check_allocated(
                                                    &instruction,
                                                    decoded_size,
                                                    family, 1, ll,
                                                    register_form != 0u,
                                                    b != 0u,
                                                    0u,
                                                    modes[mode_index]
                                                            == CDISASM_MODE_64
                                                        ? vvvv : vvvv & 7u,
                                                    2u,aaa,z != 0u,0);
                                                seen[form - UINT16_C(6124)] =
                                                    1u;
                                                ++allocated;
                                            } else {
                                                EXPECT(decoded_size == 0u);
                                                EXPECT(is_error_only(
                                                    &instruction,
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
        }
    }
    EXPECT(allocated == UINT64_C(40320));
    EXPECT(reserved == UINT64_C(746112));
    for (mode_index = 0u; mode_index < 40u; ++mode_index) {
        const cdisasm_x86_form_id form = (cdisasm_x86_form_id)(
            UINT16_C(6124) + mode_index);
        unsigned int family;
        int vex_form = 0;

        for (family = 0u; family < 4u; ++family) {
            vex_form |= form == vex_xmm_forms[family]
                || form == vex_xmm_forms[family] + UINT16_C(1)
                || form == vex_ymm_forms[family]
                || form == vex_ymm_forms[family] + UINT16_C(1);
        }
        if (!vex_form) {
            EXPECT(seen[mode_index] != 0u);
        }
    }
}

static void test_high_registers_tuples_masks_and_apx(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t high[] = {
        0x62,0x01,0x0d,0x40,0x6b,0xfd
    };
    static const uint8_t merge[] = {
        0x62,0xf1,0x75,0x29,0x63,0xc2
    };
    static const uint8_t zero[] = {
        0x62,0xf2,0x75,0xc9,0x2b,0xc2
    };
    static const uint8_t wb_full[] = {
        0x62,0xf1,0x75,0x48,0x63,0x40,0xff
    };
    static const uint8_t dw_full[] = {
        0x62,0xf1,0x75,0x48,0x6b,0x40,0xff
    };
    static const uint8_t dw_broadcast[] = {
        0x62,0xf2,0x75,0x58,0x2b,0x40,0xff
    };
    static const uint8_t apx_b4_register[] = {
        0x62,0xf9,0x75,0x08,0x63,0xc2
    };
    static const uint8_t apx_b4_memory[] = {
        0x62,0xf9,0x75,0x08,0x63,0x02
    };
    static const uint8_t apx_x4_memory[] = {
        0x62,0xf1,0x71,0x08,0x63,0x04,0xa4
    };
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    cdisasm_x86_decode_flags apx_flags = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512BW_128,
        CDISASM_X86_DECODE_BIT_APX);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        high,sizeof(high),&flags,&decoded_size);
    check_vpack(&instruction,decoded_size,0u,1,2u,1,0,
        31u,30u,29u,0u,0,0);

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        merge,sizeof(merge),&flags,&decoded_size);
    check_vpack(&instruction,decoded_size,1u,1,1u,1,0,
        0u,1u,2u,1u,0,0);
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        zero,sizeof(zero),&flags,&decoded_size);
    check_vpack(&instruction,decoded_size,2u,1,2u,1,0,
        0u,1u,2u,1u,1,0);

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        wb_full,sizeof(wb_full),&flags,&decoded_size);
    check_vpack(&instruction,decoded_size,1u,1,2u,0,0,
        0u,1u,0u,0u,0,0);
    EXPECT(instruction.opcode[2].imm == (uint64_t)-INT64_C(64));
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        dw_full,sizeof(dw_full),&flags,&decoded_size);
    check_vpack(&instruction,decoded_size,0u,1,2u,0,0,
        0u,1u,0u,0u,0,0);
    EXPECT(instruction.opcode[2].imm == (uint64_t)-INT64_C(64));
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        dw_broadcast,sizeof(dw_broadcast),&flags,&decoded_size);
    check_vpack(&instruction,decoded_size,2u,1,2u,0,1,
        0u,1u,0u,0u,0,0);
    EXPECT(instruction.opcode[2].imm == (uint64_t)-INT64_C(4));

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        apx_b4_register,sizeof(apx_b4_register),&apx_flags,&decoded_size);
    check_vpack(&instruction,decoded_size,1u,1,0u,1,0,
        0u,1u,2u,0u,0,1);
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        apx_b4_memory,sizeof(apx_b4_memory),&apx_flags,&decoded_size);
    check_vpack(&instruction,decoded_size,1u,1,0u,0,0,
        0u,1u,0u,0u,0,1);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R18);
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        apx_x4_memory,sizeof(apx_x4_memory),&apx_flags,&decoded_size);
    check_vpack(&instruction,decoded_size,1u,1,0u,0,0,
        0u,1u,0u,0u,0,1);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R20);
#endif
}

static void test_legal_prefixes_and_aliases(void)
{
    static const cdisasm_x86_mode modes[2] = {
        CDISASM_MODE_16, CDISASM_MODE_32
    };
    size_t index;

    for (index = 0u; index < 2u; ++index) {
        static const uint8_t vex_b[] =
            {0xc4,0xc1,0x31,0x63,0xc2};
        static const uint8_t evex_b[] =
            {0x62,0xd1,0x35,0x08,0x63,0xc2};
        static const uint8_t evex_rprime[] =
            {0x62,0xe1,0x35,0x08,0x63,0xc2};
        uint32_t decoded_size;
        cdisasm_instruction instruction;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[index]);
#endif

        instruction = decode(CDISASM_CPU_X86,modes[index],
            vex_b,sizeof(vex_b),
#if USE_EXTRA_OPCODES
            &flags,&decoded_size);
#else
            NULL,&decoded_size);
#endif
        check_allocated(&instruction,decoded_size,1u,0,0u,1,0,
            0u,1u,2u,0u,0,0);
        instruction = decode(CDISASM_CPU_X86,modes[index],
            evex_b,sizeof(evex_b),
#if USE_EXTRA_OPCODES
            &flags,&decoded_size);
#else
            NULL,&decoded_size);
#endif
        check_allocated(&instruction,decoded_size,1u,1,0u,1,0,
            0u,1u,2u,0u,0,0);
        instruction = decode(CDISASM_CPU_X86,modes[index],
            evex_rprime,sizeof(evex_rprime),
#if USE_EXTRA_OPCODES
            &flags,&decoded_size);
#else
            NULL,&decoded_size);
#endif
        check_allocated(&instruction,decoded_size,1u,1,0u,1,0,
            0u,1u,2u,0u,0,0);
    }

    {
        static const uint8_t address[] =
            {0x67,0x62,0xf1,0x75,0x08,0x63,0x00};
        static const uint8_t segment[] =
            {0x64,0xc4,0xe1,0x71,0x63,0x00};
        uint32_t decoded_size;
        cdisasm_instruction instruction;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            address,sizeof(address),
#if USE_EXTRA_OPCODES
            &flags,&decoded_size);
#else
            NULL,&decoded_size);
#endif
        check_allocated(&instruction,decoded_size,1u,1,0u,0,0,
            0u,1u,0u,0u,0,0);
#if USE_EXTRA_OPCODES
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_EAX);
#endif
        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            segment,sizeof(segment),
#if USE_EXTRA_OPCODES
            &flags,&decoded_size);
#else
            NULL,&decoded_size);
#endif
        check_allocated(&instruction,decoded_size,1u,0,0u,0,0,
            0u,1u,0u,0u,0,0);
#if USE_EXTRA_OPCODES
        EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_FS);
#endif
    }
}

static void test_runtime_bits_and_profiles(void)
{
#if USE_EXTRA_OPCODES
    unsigned int family;

    for (family = 0u; family < 4u; ++family) {
        unsigned int ll;

        for (ll = 0u; ll < 3u; ++ll) {
            uint8_t code[] = {0x62,0xf1,0x75,0x08,0x63,0xc2};
            cdisasm_x86_decode_flags exact = one_bit(width_bit(ll));
            cdisasm_x86_decode_flags wrong =
                one_bit(width_bit((ll + 1u) % 3u));
            uint32_t decoded_size;
            cdisasm_instruction instruction;

            code[1] = (uint8_t)(0xf0u | vpack_maps[family]);
            code[2] = (uint8_t)((dword_source(family) ? 0u : 0x80u)
                | 0x75u);
            code[3] = (uint8_t)(0x08u | (ll << 5));
            code[4] = vpack_opcodes[family];
            instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                code,sizeof(code),&exact,&decoded_size);
            check_vpack(&instruction,decoded_size,family,1,ll,1,0,
                0u,1u,2u,0u,0,0);
            expect_error("VPACK exact-width mismatch",CDISASM_CPU_X86,
                CDISASM_MODE_64,code,sizeof(code),&wrong,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
    }

    {
        static const uint8_t vex_xmm[] =
            {0xc4,0xe1,0x71,0x63,0xc2};
        static const uint8_t vex_ymm[] =
            {0xc4,0xe1,0x75,0x63,0xc2};
        static const uint8_t evex[] =
            {0x62,0xf1,0x75,0x48,0x63,0xc2};
        static const uint8_t apx[] =
            {0x62,0xf9,0x75,0x08,0x63,0xc2};
        const cdisasm_x86_cpu_id cpus[] = {
            CDISASM_CPU_SANDY_BRIDGE,
            CDISASM_CPU_HASWELL,
            CDISASM_CPU_SKYLAKE_SP,
            CDISASM_CPU_KNIGHTS_MILL,
            CDISASM_CPU_AVX10,
            CDISASM_CPU_APX,
            CDISASM_CPU_DIAMOND_RAPIDS
        };
        cdisasm_x86_decode_flags masks[
            sizeof(cpus) / sizeof(cpus[0])];
        uint32_t decoded_size;
        cdisasm_instruction instruction;
        size_t index;

        for (index = 0u; index < sizeof(cpus) / sizeof(cpus[0]); ++index) {
            EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                cpus[index],CDISASM_MODE_64,&masks[index])
                == CDISASM_STATUS_OK);
        }
        instruction = decode(cpus[0],CDISASM_MODE_64,
            vex_xmm,sizeof(vex_xmm),&masks[0],&decoded_size);
        EXPECT(decoded_size == sizeof(vex_xmm));
        expect_error("Sandy Bridge AVX2 gate",cpus[0],CDISASM_MODE_64,
            vex_ymm,sizeof(vex_ymm),&masks[0],
            CDISASM_STATUS_INVALID_INSTRUCTION);
        instruction = decode(cpus[1],CDISASM_MODE_64,
            vex_ymm,sizeof(vex_ymm),&masks[1],&decoded_size);
        EXPECT(decoded_size == sizeof(vex_ymm));
        instruction = decode(cpus[2],CDISASM_MODE_64,
            evex,sizeof(evex),&masks[2],&decoded_size);
        EXPECT(decoded_size == sizeof(evex));
        expect_error("Knights Mill AVX512BW gate",cpus[3],
            CDISASM_MODE_64,evex,sizeof(evex),&masks[3],
            CDISASM_STATUS_INVALID_INSTRUCTION);
        instruction = decode(cpus[4],CDISASM_MODE_64,
            evex,sizeof(evex),&masks[4],&decoded_size);
        EXPECT(decoded_size == sizeof(evex));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction,CDISASM_X86_GROUP_AVX10_1));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction,CDISASM_X86_GROUP_AVX512BW));
        expect_error("AVX10 lacks APX-F",cpus[4],CDISASM_MODE_64,
            apx,sizeof(apx),&masks[4],
            CDISASM_STATUS_INVALID_INSTRUCTION);
        instruction = decode(cpus[5],CDISASM_MODE_64,
            apx,sizeof(apx),&masks[5],&decoded_size);
        EXPECT(decoded_size == sizeof(apx));
        instruction = decode(cpus[6],CDISASM_MODE_64,
            apx,sizeof(apx),&masks[6],&decoded_size);
        EXPECT(decoded_size == sizeof(apx));
    }
#else
    expect_error("VPACK extras off",CDISASM_CPU_X86,CDISASM_MODE_64,
        (const uint8_t[]){0x62,0xf1,0x75,0x08,0x63,0xc2},6u,NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_truncation_and_legacy(void)
{
    static const uint8_t legacy_prefixes[5] =
        {0x66,0xf2,0xf3,0xf0,0x48};
    static const struct invalid_case {
        const char *label;
        uint8_t code[7];
        size_t size;
        cdisasm_x86_mode mode;
    } invalid[] = {
        {"EVEX wrong pp",{0x62,0xf1,0x74,0x08,0x63,0xc2,0},6,CDISASM_MODE_64},
        {"EVEX DW W1",{0x62,0xf1,0xf5,0x08,0x6b,0xc2,0},6,CDISASM_MODE_64},
        {"EVEX LL3",{0x62,0xf1,0x75,0x68,0x63,0xc2,0},6,CDISASM_MODE_64},
        {"EVEX register b",{0x62,0xf1,0x75,0x18,0x6b,0xc2,0},6,CDISASM_MODE_64},
        {"EVEX WB memory b",{0x62,0xf1,0x75,0x18,0x63,0x00,0},6,CDISASM_MODE_64},
        {"EVEX z without mask",{0x62,0xf1,0x75,0x88,0x63,0xc2,0},6,CDISASM_MODE_64},
        {"EVEX U0 register",{0x62,0xf1,0x71,0x08,0x63,0xc2,0},6,CDISASM_MODE_64},
        {"EVEX non-long V prime",{0x62,0xf1,0x75,0x00,0x63,0xc2,0},6,CDISASM_MODE_32},
        {"EVEX non-long B4",{0x62,0xf9,0x75,0x08,0x63,0xc2,0},6,CDISASM_MODE_32},
        {"EVEX non-long U0",{0x62,0xf1,0x71,0x08,0x63,0x00,0},6,CDISASM_MODE_32},
        {"VEX wrong pp",{0xc4,0xe1,0x70,0x63,0xc2,0,0},5,CDISASM_MODE_64}
    };
    size_t index;
    unsigned int family;

    for (family = 0u; family < 4u; ++family) {
        uint8_t vex[] = {
            0xc4,(uint8_t)(0xe0u | vpack_maps[family]),
            0x71,vpack_opcodes[family],0xc2
        };
        uint8_t evex[] = {
            0x62,(uint8_t)(0xf0u | vpack_maps[family]),
            0x75,0x08,vpack_opcodes[family],0xc2
        };

        for (index = 1u; index < sizeof(vex); ++index) {
            expect_error("truncated VEX VPACK",CDISASM_CPU_X86,
                CDISASM_MODE_64,vex,index,NULL,CDISASM_STATUS_TRUNCATED);
        }
        for (index = 1u; index < sizeof(evex); ++index) {
            expect_error("truncated EVEX VPACK",CDISASM_CPU_X86,
                CDISASM_MODE_64,evex,index,NULL,CDISASM_STATUS_TRUNCATED);
        }
        for (index = 0u; index < sizeof(legacy_prefixes); ++index) {
            uint8_t prefixed_vex[] = {
                legacy_prefixes[index],0xc4,
                (uint8_t)(0xe0u | vpack_maps[family]),
                0x71,vpack_opcodes[family],0x04,0x24
            };
            uint8_t prefixed_evex[] = {
                legacy_prefixes[index],0x62,
                (uint8_t)(0xf0u | vpack_maps[family]),
                0x75,0x08,vpack_opcodes[family],0x04,0x24
            };

            expect_error("prefixed VEX missing SIB",CDISASM_CPU_X86,
                CDISASM_MODE_64,prefixed_vex,
                sizeof(prefixed_vex) - 1u,NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed VEX complete",CDISASM_CPU_X86,
                CDISASM_MODE_64,prefixed_vex,sizeof(prefixed_vex),NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("prefixed EVEX missing SIB",CDISASM_CPU_X86,
                CDISASM_MODE_64,prefixed_evex,
                sizeof(prefixed_evex) - 1u,NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed EVEX complete",CDISASM_CPU_X86,
                CDISASM_MODE_64,prefixed_evex,sizeof(prefixed_evex),NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error(invalid[index].label,CDISASM_CPU_X86,
            invalid[index].mode,invalid[index].code,invalid[index].size,
            NULL,CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("reserved VEX pp missing SIB",CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x70,0x63,0x04},5u,NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved EVEX pp missing SIB",CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x62,0xf1,0x74,0x08,0x63,0x04},6u,NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved EVEX W missing SIB",CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x62,0xf1,0xf5,0x08,0x6b,0x04},6u,NULL,
        CDISASM_STATUS_TRUNCATED);

#if USE_EXTRA_OPCODES
    {
        static const struct legacy_case {
            uint8_t code[5];
            size_t size;
            cdisasm_x86_name_id name;
        } cases[] = {
            {{0x66,0x0f,0x6b,0xc1,0},4,CDISASM_X86_NAME_PACKSSDW},
            {{0x66,0x0f,0x63,0xc1,0},4,CDISASM_X86_NAME_PACKSSWB},
            {{0x66,0x0f,0x38,0x2b,0xc1},5,CDISASM_X86_NAME_PACKUSDW},
            {{0x66,0x0f,0x67,0xc1,0},4,CDISASM_X86_NAME_PACKUSWB}
        };
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);

        for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86,CDISASM_MODE_64,
                cases[index].code,cases[index].size,
                &flags,&decoded_size);

            EXPECT(decoded_size == cases[index].size);
            EXPECT(instruction.name_id == cases[index].name);
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
        {{0xc4,0xe1,0x71,0x6b,0xc2,0,0},5,
            CDISASM_X86_DECODE_BIT_AVX,
            "vpackssdw xmm0, xmm1, xmm2",
            "vpackssdw %xmm2, %xmm1, %xmm0"},
        {{0x62,0xf1,0x75,0x89,0x63,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX512BW_128,
            "vpacksswb xmm0 {k1}{z}, xmm1, xmm2",
            "vpacksswb %xmm2, %xmm1, %xmm0{%k1}{z}"},
        {{0x62,0xf2,0x75,0x58,0x2b,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512BW_512,
            "vpackusdw zmm0, zmm1, dword ptr [rax - 0x4]{1to16}",
            "vpackusdw -0x4(%rax){1to16}, %zmm1, %zmm0"},
        {{0x62,0xf1,0xf5,0x48,0x67,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX512BW_512,
            "vpackuswb zmm0, zmm1, zmm2",
            "vpackuswb %zmm2, %zmm1, %zmm0"}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags = one_bit(cases[index].bit);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86,CDISASM_MODE_64,
            cases[index].code,cases[index].size,
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
        static const uint8_t code[] =
            {0x62,0xf1,0x75,0x89,0x63,0xc2};
        cdisasm_x86_decode_flags flags =
            one_bit(CDISASM_X86_DECODE_BIT_AVX512BW_128);
        uint32_t decoded_size;
        cdisasm_instruction valid = decode(
            CDISASM_CPU_X86,CDISASM_MODE_64,
            code,sizeof(code),&flags,&decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(code));
        forged = valid;
        forged.form_id = UINT16_C(6136);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VPACKUSWB;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.operand_count = 2u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].size = 32u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].size = 2u;
        forged.opcode[2].broadcast = CDISASM_X86_BROADCAST_1_TO_8;
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
        forged.opcode[2].type = CDISASM_OPERAND_MEMORY;
        forged.opcode[2].reg = CDISASM_X86_REG_NONE;
        forged.opcode[2].base_reg = CDISASM_X86_REG_RAX;
        expect_forged_format_rejected(&forged);
    }
#endif
}

int main(void)
{
    test_vex_control_partition();
    test_evex_control_partition();
    test_high_registers_tuples_masks_and_apx();
    test_legal_prefixes_and_aliases();
    test_runtime_bits_and_profiles();
    test_reserved_truncation_and_legacy();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "x86 VPACK tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 VPACK tests passed");
    return 0;
}
