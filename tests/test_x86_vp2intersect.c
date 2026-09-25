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

_Static_assert(CDISASM_X86_NAME_VP2INTERSECTD == UINT16_C(1797)
        && CDISASM_X86_NAME_VP2INTERSECTQ == UINT16_C(1798),
    "VP2INTERSECTD/Q name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX512_VP2INTERSECT_128 == UINT16_C(250)
        && CDISASM_X86_GROUP_AVX512_VP2INTERSECT_256 == UINT16_C(251)
        && CDISASM_X86_GROUP_AVX512_VP2INTERSECT_512 == UINT16_C(252),
    "VP2INTERSECT width ISA-set IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_128
            == UINT32_C(198)
        && CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_256
            == UINT32_C(199)
        && CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_512
            == UINT32_C(200),
    "VP2INTERSECT width runtime-bit IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VP2INTERSECT profile sweeps");

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
        CDISASM_X86_GROUP_AVX512_VP2INTERSECT_128,
        CDISASM_X86_GROUP_AVX512_VP2INTERSECT_256,
        CDISASM_X86_GROUP_AVX512_VP2INTERSECT_512
    };

    return groups[ll];
}

static cdisasm_x86_decode_bit_id width_bit(unsigned int ll)
{
    static const cdisasm_x86_decode_bit_id bits[3] = {
        CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_128,
        CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_256,
        CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_512
    };

    return bits[ll];
}

static cdisasm_x86_reg_id vector_reg(unsigned int ll, unsigned int index)
{
    const cdisasm_x86_reg_id base = ll == 0u ? CDISASM_X86_REG_XMM0
        : ll == 1u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_ZMM0;

    return (cdisasm_x86_reg_id)(base + index);
}

static void check_vp2intersect(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    unsigned int w,
    unsigned int ll,
    int register_form,
    int broadcast,
    unsigned int encoded_pair,
    unsigned int source1,
    unsigned int source2,
    int apx)
{
    const unsigned int vector_bytes = 16u << ll;
    const unsigned int element_bytes = w != 0u ? 8u : 4u;
    const unsigned int lanes = vector_bytes / element_bytes;
    const unsigned int mask_bytes = (lanes + 7u) / 8u;
    const unsigned int pair = encoded_pair & ~1u;
    const cdisasm_x86_form_id base = w != 0u
        ? UINT16_C(6080) : UINT16_C(6074);

    if (decoded_size == 0u) {
        fprintf(stderr,
            "VP2 check failed: status=%u w=%u ll=%u reg=%d bcast=%d "
            "pair=%u src1=%u src2=%u apx=%d\n",
            (unsigned int)instruction->last_error_id,w,ll,register_form,
            broadcast,encoded_pair,source1,source2,apx);
    }
    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (w != 0u
        ? CDISASM_X86_NAME_VP2INTERSECTQ
        : CDISASM_X86_NAME_VP2INTERSECTD));
    EXPECT(instruction->form_id == (cdisasm_x86_form_id)(
        base + 2u * ll + (register_form ? 1u : 0u)));
    EXPECT(instruction->operand_count == 4u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
    EXPECT(instruction->encoding.prefix_size == 4u);
    EXPECT(instruction->encoding.opcode_offset == 4u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset == 5u);
    EXPECT(instruction->encoding.immediate_count == 0u);

    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg
        == (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + pair));
    EXPECT(instruction->opcode[0].size == mask_bytes);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[0].flags == 0u);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg
        == (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + pair + 1u));
    EXPECT(instruction->opcode[1].size == mask_bytes);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[1].flags == CDISASM_OPERAND_FLAG_IMPLICIT);
    EXPECT(instruction->opcode[2].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[2].reg == vector_reg(ll, source1));
    EXPECT(instruction->opcode[2].size == vector_bytes);
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].flags == 0u);
    EXPECT(instruction->opcode[3].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[3].size == (broadcast
        ? element_bytes : vector_bytes));
    EXPECT(instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[3].broadcast
        == (cdisasm_x86_broadcast)(broadcast ? lanes : 0u));
    if (register_form) {
        EXPECT(instruction->opcode[3].reg == vector_reg(ll, source2));
        EXPECT(instruction->opcode[3].flags == 0u);
    }

    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512VP2INTERSECT));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, width_group(ll)));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == apx);
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    unsigned int w,
    unsigned int ll,
    int register_form,
    int broadcast,
    unsigned int encoded_pair,
    unsigned int source1,
    unsigned int source2,
    int apx)
{
#if USE_EXTRA_OPCODES
    check_vp2intersect(instruction, decoded_size, w, ll,
        register_form, broadcast, encoded_pair, source1, source2, apx);
#else
    (void)w;
    (void)ll;
    (void)register_form;
    (void)broadcast;
    (void)encoded_pair;
    (void)source1;
    (void)source2;
    (void)apx;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_exact_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint64_t forms[12] = {0};
    uint64_t allocated = 0;
    uint64_t reserved = 0;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        unsigned int w;

        for (w = 0u; w < 2u; ++w) {
            unsigned int pp;

            for (pp = 0u; pp < 4u; ++pp) {
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
                                    const int valid = pp == 3u && ll < 3u
                                        && aaa == 0u && z == 0u
                                        && (!register_form || b == 0u);
                                    const uint8_t code[15] = {
                                        0x62,0xf2,
                                        (uint8_t)((w << 7)
                                            | UINT8_C(0x6c) | pp),
                                        (uint8_t)((z << 7) | (ll << 5)
                                            | (b << 4) | UINT8_C(0x08)
                                            | aaa),
                                        0x68,(uint8_t)modrm,0x24,0x10,
                                        0x20,0x30,0x40,0x50,0x60,0x70,0x80
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
                                        const cdisasm_x86_form_id form_id =
                                            (cdisasm_x86_form_id)(
                                                (w ? UINT16_C(6080)
                                                   : UINT16_C(6074))
                                                + 2u * ll
                                                + (register_form ? 1u : 0u));

                                        check_allocated(&instruction,
                                            decoded_size,w,ll,register_form,
                                            b != 0u, (modrm >> 3) & 7u,
                                            2u,modrm & 7u,0);
                                        ++forms[form_id - UINT16_C(6074)];
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
    EXPECT(allocated == UINT64_C(8064));
    EXPECT(reserved == UINT64_C(778368));
    for (mode_index = 0u; mode_index < 12u; ++mode_index) {
        EXPECT(forms[mode_index] != 0u);
    }
}

static void test_pairs_registers_tuples_and_apx(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t odd_pair[] = {
        0x62,0xf2,0x6f,0x08,0x68,0xcb
    };
    static const uint8_t last_pair_high_sources[] = {
        0x62,0x92,0x0f,0x40,0x68,0xfd
    };
    static const uint8_t full_disp8[] = {
        0x62,0xf2,0x6f,0x48,0x68,0x40,0xff
    };
    static const uint8_t d_broadcast_disp8[] = {
        0x62,0xf2,0x6f,0x58,0x68,0x40,0xff
    };
    static const uint8_t q_broadcast_disp8[] = {
        0x62,0xf2,0xef,0x38,0x68,0x40,0xff
    };
    static const uint8_t apx_b4_register[] = {
        0x62,0xfa,0x6f,0x08,0x68,0xc3
    };
    static const uint8_t apx_x4_memory[] = {
        0x62,0xf2,0x6b,0x08,0x68,0x04,0xa4
    };
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    cdisasm_x86_decode_flags apx_flags = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_128,
        CDISASM_X86_DECODE_BIT_APX);
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
        CDISASM_MODE_64, odd_pair, sizeof(odd_pair), &flags,
        &decoded_size);

    check_vp2intersect(&instruction, decoded_size,0u,0u,1,0,1u,2u,3u,0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        last_pair_high_sources, sizeof(last_pair_high_sources), &flags,
        &decoded_size);
    check_vp2intersect(&instruction, decoded_size,0u,2u,1,0,7u,30u,29u,0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        full_disp8, sizeof(full_disp8), &flags, &decoded_size);
    check_vp2intersect(&instruction, decoded_size,0u,2u,0,0,0u,2u,0u,0);
    EXPECT(instruction.opcode[3].imm == (uint64_t)-INT64_C(64));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        d_broadcast_disp8, sizeof(d_broadcast_disp8), &flags,
        &decoded_size);
    check_vp2intersect(&instruction, decoded_size,0u,2u,0,1,0u,2u,0u,0);
    EXPECT(instruction.opcode[3].imm == (uint64_t)-INT64_C(4));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        q_broadcast_disp8, sizeof(q_broadcast_disp8), &flags,
        &decoded_size);
    check_vp2intersect(&instruction, decoded_size,1u,1u,0,1,0u,2u,0u,0);
    EXPECT(instruction.opcode[3].imm == (uint64_t)-INT64_C(8));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        apx_b4_register, sizeof(apx_b4_register), &apx_flags,
        &decoded_size);
    check_vp2intersect(&instruction, decoded_size,0u,0u,1,0,0u,2u,3u,1);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        apx_x4_memory, sizeof(apx_x4_memory), &apx_flags, &decoded_size);
    check_vp2intersect(&instruction, decoded_size,0u,0u,0,0,0u,2u,0u,1);
    EXPECT(instruction.opcode[3].index_reg == CDISASM_X86_REG_R20);
#endif
}

static void test_runtime_bits_and_profiles(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t base_code[] = {
        0x62,0xf2,0x6f,0x08,0x68,0xc3
    };
    unsigned int ll;

    for (ll = 0u; ll < 3u; ++ll) {
        uint8_t code[sizeof(base_code)];
        cdisasm_x86_decode_flags exact = one_bit(width_bit(ll));
        cdisasm_x86_decode_flags wrong = one_bit(width_bit((ll + 1u) % 3u));
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        memcpy(code, base_code, sizeof(code));
        code[3] = (uint8_t)(UINT8_C(0x08) | (ll << 5));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &exact, &decoded_size);
        check_vp2intersect(&instruction, decoded_size,0u,ll,1,0,0u,2u,3u,0);
        expect_error("VP2INTERSECT exact-width mismatch", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, sizeof(code), &wrong,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    {
        cdisasm_x86_decode_flags tiger;
        cdisasm_x86_decode_flags ice;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_TIGER_LAKE,
            CDISASM_MODE_64, &tiger) == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_TIGER_LAKE, CDISASM_MODE_64,
            base_code, sizeof(base_code), &tiger, &decoded_size);
        check_vp2intersect(&instruction, decoded_size,0u,0u,1,0,0u,2u,3u,0);

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_ICE_LAKE,
            CDISASM_MODE_64, &ice) == CDISASM_STATUS_OK);
        expect_error("Ice Lake lacks VP2INTERSECT", CDISASM_CPU_ICE_LAKE,
            CDISASM_MODE_64, base_code, sizeof(base_code), &ice,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#else
    static const uint8_t code[] = {
        0x62,0xf2,0x6f,0x08,0x68,0xc3
    };

    expect_error("VP2INTERSECT extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_controls_and_truncation(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const struct invalid_case {
        const char *label;
        uint8_t code[7];
        size_t size;
        cdisasm_x86_mode mode;
    } invalid[] = {
        {"wrong pp",{0x62,0xf2,0x6e,0x08,0x68,0xc3,0},6,CDISASM_MODE_64},
        {"LL3",{0x62,0xf2,0x6f,0x68,0x68,0xc3,0},6,CDISASM_MODE_64},
        {"register b",{0x62,0xf2,0x6f,0x18,0x68,0xc3,0},6,CDISASM_MODE_64},
        {"aaa",{0x62,0xf2,0x6f,0x09,0x68,0xc3,0},6,CDISASM_MODE_64},
        {"z",{0x62,0xf2,0x6f,0x88,0x68,0xc3,0},6,CDISASM_MODE_64},
        {"R prime",{0x62,0x72,0x6f,0x08,0x68,0xc3,0},6,CDISASM_MODE_64},
        {"R",{0x62,0xe2,0x6f,0x08,0x68,0xc3,0},6,CDISASM_MODE_64},
        {"V prime non-long",{0x62,0xf2,0x6f,0x00,0x68,0xc3,0},6,
            CDISASM_MODE_32},
        {"B4 non-long",{0x62,0xfa,0x6f,0x08,0x68,0xc3,0},6,
            CDISASM_MODE_32},
        {"U0 register",{0x62,0xf2,0x6b,0x08,0x68,0xc3,0},6,
            CDISASM_MODE_64}
    };
    static const uint8_t valid[] = {
        0x62,0xf2,0x6f,0x08,0x68,0xc3
    };
    static const uint8_t legacy_prefixes[][7] = {
        {0x66,0x62,0xf2,0x6f,0x08,0x68,0xc3},
        {0xf2,0x62,0xf2,0x6f,0x08,0x68,0xc3},
        {0xf3,0x62,0xf2,0x6f,0x08,0x68,0xc3},
        {0xf0,0x62,0xf2,0x6f,0x08,0x68,0xc3},
        {0x48,0x62,0xf2,0x6f,0x08,0x68,0xc3}
    };
    size_t index;

    for (index = 1u; index < sizeof(valid); ++index) {
        expect_error("truncated VP2INTERSECT", CDISASM_CPU_X86,
            CDISASM_MODE_64, valid, index, NULL,
            CDISASM_STATUS_TRUNCATED);
    }
    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error(invalid[index].label, CDISASM_CPU_X86,
            invalid[index].mode, invalid[index].code, invalid[index].size,
            NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 0u; index < 3u; ++index) {
        static const uint8_t bad_r[] = {
            0x62,0xe2,0x6f,0x08,0x68,0xc3
        };

        expect_error("fixed R in every mode", CDISASM_CPU_X86,
            modes[index], bad_r, sizeof(bad_r), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 0u; index < 2u; ++index) {
        static const uint8_t bound_collision[] = {
            0x62,0x72,0x6f,0x08,0x68,0xc3
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            modes[index], bound_collision, sizeof(bound_collision), NULL,
            &decoded_size);

        EXPECT(decoded_size == 3u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_BOUND);
    }
    for (index = 0u;
         index < sizeof(legacy_prefixes) / sizeof(legacy_prefixes[0]);
         ++index) {
        expect_error("legacy-prefix collision", CDISASM_CPU_X86,
            CDISASM_MODE_64, legacy_prefixes[index],
            sizeof(legacy_prefixes[index]), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    expect_error("reserved R missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x62,0xe2,0x6f,0x08,0x68,0x04},6u,NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved R missing disp32", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x62,0xe2,0x6f,0x08,0x68,0x04,0x25},7u,NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved controls missing disp8", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x62,0xf2,0x6e,0x89,0x68,0x40},6u,NULL,
        CDISASM_STATUS_TRUNCATED);
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_forged_format_rejected(
    const cdisasm_instruction *instruction)
{
    char output[64] = {'x'};

    EXPECT(cdisasm_x86_format(instruction,
        CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
    output[0] = 'x';
    EXPECT(cdisasm_x86_format(instruction,
        CDISASM_FORMAT_SYNTAX_ATT, output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
}
#endif

static void test_forged_formatter_schema(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const uint8_t code[] = {
        0x62,0xf2,0x6f,0x08,0x68,0xc3
    };
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_128);
    uint32_t decoded_size;
    cdisasm_instruction valid = decode(CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &flags, &decoded_size);
    cdisasm_instruction forged;

    EXPECT(decoded_size == sizeof(code));

    forged = valid;
    forged.opcode[1].reg = CDISASM_X86_REG_K3;
    expect_forged_format_rejected(&forged);

    forged = valid;
    forged.opcode[1].flags = 0u;
    expect_forged_format_rejected(&forged);

    forged = valid;
    forged.opcode[0].reg = CDISASM_X86_REG_K1;
    forged.opcode[1].reg = CDISASM_X86_REG_K2;
    expect_forged_format_rejected(&forged);

    forged = valid;
    forged.form_id = UINT16_C(6074);
    expect_forged_format_rejected(&forged);

    forged = valid;
    forged.name_id = CDISASM_X86_NAME_VP2INTERSECTQ;
    expect_forged_format_rejected(&forged);

    forged = valid;
    forged.mask_mode = CDISASM_X86_MASK_MERGE;
    forged.mask_reg = CDISASM_X86_REG_K1;
    expect_forged_format_rejected(&forged);

    forged = valid;
    forged.opcode[3].broadcast = CDISASM_X86_BROADCAST_1_TO_4;
    expect_forged_format_rejected(&forged);
#endif
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const struct format_case {
        uint8_t code[7];
        size_t size;
        cdisasm_x86_decode_bit_id bit;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0x62,0xf2,0x6f,0x08,0x68,0xc3,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_128,
            "vp2intersectd k0+1, xmm2, xmm3",
            "vp2intersectd %xmm3, %xmm2, %k0+1"},
        {{0x62,0xf2,0xef,0x28,0x68,0xfb,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_256,
            "vp2intersectq k6+1, ymm2, ymm3",
            "vp2intersectq %ymm3, %ymm2, %k6+1"},
        {{0x62,0xf2,0x6f,0x48,0x68,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_512,
            "vp2intersectd k0+1, zmm2, zmmword ptr [rax - 0x40]",
            "vp2intersectd -0x40(%rax), %zmm2, %k0+1"},
        {{0x62,0xf2,0xef,0x58,0x68,0x00,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_512,
            "vp2intersectq k0+1, zmm2, qword ptr [rax]{1to8}",
            "vp2intersectq (%rax){1to8}, %zmm2, %k0+1"},
        {{0x62,0x92,0x0f,0x40,0x68,0xfd,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_512,
            "vp2intersectd k6+1, zmm30, zmm29",
            "vp2intersectd %zmm29, %zmm30, %k6+1"}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags = one_bit(cases[index].bit);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, cases[index].size,
            &flags, &decoded_size);
        char output[192];
        char tiny[4] = {'x','x','x','x'};
        size_t required;

        EXPECT(decoded_size == cases[index].size);
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, NULL, 0u);
        EXPECT(required == strlen(cases[index].intel));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output))
            == required);
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, tiny, sizeof(tiny)) == required);
        EXPECT(tiny[sizeof(tiny) - 1u] == '\0');

        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT, NULL, 0u);
        EXPECT(required == strlen(cases[index].att));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT, output, sizeof(output)) == required);
        EXPECT(strcmp(output, cases[index].att) == 0);
    }
#endif
}

int main(void)
{
    test_exact_control_partition();
    test_pairs_registers_tuples_and_apx();
    test_runtime_bits_and_profiles();
    test_reserved_controls_and_truncation();
    test_formatting();
    test_forged_formatter_schema();

    if (failures != 0) {
        fprintf(stderr, "x86 VP2INTERSECT tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 VP2INTERSECT tests passed");
    return 0;
}
