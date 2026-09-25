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

_Static_assert(CDISASM_X86_NAME_VMULBF16 == UINT16_C(940),
    "VMULBF16 name ID changed");
_Static_assert(CDISASM_X86_GROUP_AVX10_2_BF16_128 == UINT16_C(151)
        && CDISASM_X86_GROUP_AVX10_2_BF16_256 == UINT16_C(152)
        && CDISASM_X86_GROUP_AVX10_2_BF16_512 == UINT16_C(153),
    "AVX10.2 BF16 group identity changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX10_2_BF16_128 == UINT32_C(99)
        && CDISASM_X86_DECODE_BIT_AVX10_2_BF16_256 == UINT32_C(100)
        && CDISASM_X86_DECODE_BIT_AVX10_2_BF16_512 == UINT32_C(101),
    "AVX10.2 BF16 runtime-bit identity changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VMULBF16 profile sweeps");

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

static cdisasm_x86_form_id vmulbf16_form(unsigned int ll, int reg)
{
    return (cdisasm_x86_form_id)(
        UINT16_C(6006) + 2u * ll + (reg ? 1u : 0u));
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
    return (cdisasm_x86_group_id)(
        CDISASM_X86_GROUP_AVX10_2_BF16_128 + ll);
}

static cdisasm_x86_decode_bit_id width_bit(unsigned int ll)
{
    return (cdisasm_x86_decode_bit_id)(
        CDISASM_X86_DECODE_BIT_AVX10_2_BF16_128 + ll);
}

static cdisasm_x86_reg_id vector_reg(unsigned int ll, unsigned int index)
{
    const cdisasm_x86_reg_id base = ll == 0u ? CDISASM_X86_REG_XMM0
        : ll == 1u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_ZMM0;

    return (cdisasm_x86_reg_id)(base + index);
}

static void check_vmulbf16(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_form_id form_id,
    int apx,
    unsigned int aaa,
    int zero,
    unsigned int broadcast)
{
    const unsigned int ll = (form_id - UINT16_C(6006)) / 2u;
    const unsigned int vector_bytes = 16u << ll;
    const int memory = (form_id & UINT16_C(1)) == 0u;
    const int merge = aaa != 0u && !zero;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_VMULBF16);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->operand_count == 3u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].size == vector_bytes);
    EXPECT(instruction->opcode[0].access == (merge
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT(instruction->opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].size == vector_bytes);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[2].type == (memory
        ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
    EXPECT(instruction->opcode[2].size == (broadcast != 0u
        ? 2u : vector_bytes));
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].broadcast
        == (cdisasm_x86_broadcast)broadcast);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX10_2));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, width_group(ll)));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX10_2_BF16_128) == (ll == 0u));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX10_2_BF16_256) == (ll == 1u));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX10_2_BF16_512) == (ll == 2u));
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
    EXPECT(instruction->encoding.immediate_count == 0u);
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_form_id form_id,
    int apx,
    unsigned int aaa,
    int zero,
    unsigned int broadcast)
{
#if USE_EXTRA_OPCODES
    check_vmulbf16(instruction, decoded_size, form_id, apx,
        aaa, zero, broadcast);
#else
    (void)form_id;
    (void)apx;
    (void)aaa;
    (void)zero;
    (void)broadcast;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_modrm_allocation(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint64_t form_counts[6] = {0,0,0,0,0,0};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        unsigned int ll;

        for (ll = 0u; ll < 3u; ++ll) {
            unsigned int b;

            for (b = 0u; b <= 1u; ++b) {
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const int reg = (modrm & UINT8_C(0xc0))
                        == UINT8_C(0xc0);
                    const int valid = b == 0u || !reg;
                    const unsigned int broadcast = b != 0u
                        ? 8u << ll : 0u;
                    const uint8_t code[15] = {
                        0x62,0xf5,0x75,
                        (uint8_t)(0x08u | (ll << 5) | (b << 4)),
                        0x59,(uint8_t)modrm,0x24,0x10,0x20,0x30,0x40,
                        0x50,0x60,0x70,0x80
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

                    if (!valid) {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++reserved;
                        continue;
                    }
                    check_allocated(&instruction, decoded_size,
                        vmulbf16_form(ll, reg), 0,0u,0,broadcast);
                    ++form_counts[ll * 2u + (reg ? 1u : 0u)];
                    ++allocated;
                }
            }
        }
    }

    EXPECT(allocated == UINT64_C(4032));
    EXPECT(reserved == UINT64_C(576));
    EXPECT(form_counts[0] == UINT64_C(1152));
    EXPECT(form_counts[1] == UINT64_C(192));
    EXPECT(form_counts[2] == UINT64_C(1152));
    EXPECT(form_counts[3] == UINT64_C(192));
    EXPECT(form_counts[4] == UINT64_C(1152));
    EXPECT(form_counts[5] == UINT64_C(192));
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
            const unsigned int source = (~vvvv_raw) & 15u;
            const uint8_t p1 = (uint8_t)((w << 7)
                | (vvvv_raw << 3) | (u << 2) | 1u);
            unsigned int rep;

            for (rep = 0u; rep < 2u; ++rep) {
                const int reg = rep != 0u;
                const int valid = w == 0u
                    && (u != 0u || (long_mode && !reg))
                    && (long_mode || source < 8u);
                const uint8_t code[] = {
                    0x62,0xf5,p1,0x08,0x59,
                    (uint8_t)(reg ? 0xc2 : 0x00),0x24,0,0,0,0
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
                    continue;
                }
                check_allocated(&instruction, decoded_size,
                    vmulbf16_form(0u,reg),u == 0u,0u,0,0u);
#if USE_EXTRA_OPCODES
                EXPECT(instruction.opcode[1].reg
                    == vector_reg(0u, source));
#endif
                ++p1_allocated;
            }
        }

        for (selector = 0u; selector <= UINT8_MAX; ++selector) {
            const uint8_t p2 = (uint8_t)selector;
            const unsigned int ll = (p2 >> 5) & 3u;
            const unsigned int aaa = p2 & 7u;
            const int zero = (p2 & UINT8_C(0x80)) != 0u;
            const int b = (p2 & UINT8_C(0x10)) != 0u;
            unsigned int rep;

            for (rep = 0u; rep < 2u; ++rep) {
                const int reg = rep != 0u;
                const int valid = ll < 3u
                    && (!zero || aaa != 0u)
                    && (!reg || !b)
                    && (long_mode || (p2 & UINT8_C(0x08)) != 0u);
                const uint8_t code[] = {
                    0x62,0xf5,0x75,p2,0x59,
                    (uint8_t)(reg ? 0xc2 : 0x00),0x24,0,0,0,0
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
                    continue;
                }
                check_allocated(&instruction, decoded_size,
                    vmulbf16_form(ll,reg),0,aaa,zero,
                    b ? 8u << ll : 0u);
#if USE_EXTRA_OPCODES
                EXPECT(instruction.opcode[1].reg == vector_reg(
                    ll, (p2 & UINT8_C(0x08)) != 0u ? 1u : 17u));
#endif
                ++p2_allocated;
            }
        }
    }

    EXPECT(p1_allocated == UINT32_C(80));
    EXPECT(p1_reserved == UINT32_C(304));
    EXPECT(p2_allocated == UINT32_C(540));
    EXPECT(p2_reserved == UINT32_C(996));
}

static void test_high_register_space(void)
{
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    unsigned int ll;

    for (ll = 0u; ll < 3u; ++ll) {
        unsigned int destination;

        for (destination = 0u; destination < 32u; ++destination) {
            unsigned int source1;

            for (source1 = 0u; source1 < 32u; ++source1) {
                unsigned int source2;

                for (source2 = 0u; source2 < 32u; ++source2) {
                    uint8_t p0 = UINT8_C(5);
                    uint8_t code[6];
                    uint32_t decoded_size;
                    cdisasm_instruction instruction;

                    if ((destination & 8u) == 0u) {
                        p0 |= UINT8_C(0x80);
                    }
                    if ((source2 & 16u) == 0u) {
                        p0 |= UINT8_C(0x40);
                    }
                    if ((source2 & 8u) == 0u) {
                        p0 |= UINT8_C(0x20);
                    }
                    if ((destination & 16u) == 0u) {
                        p0 |= UINT8_C(0x10);
                    }
                    code[0] = UINT8_C(0x62);
                    code[1] = p0;
                    code[2] = (uint8_t)((((~source1) & 15u) << 3) | 5u);
                    code[3] = (uint8_t)((ll << 5)
                        | (source1 < 16u ? 8u : 0u));
                    code[4] = UINT8_C(0x59);
                    code[5] = (uint8_t)(UINT8_C(0xc0)
                        | ((destination & 7u) << 3) | (source2 & 7u));
                    instruction = decode(CDISASM_CPU_X86,
                        CDISASM_MODE_64, code, sizeof(code), &flags,
                        &decoded_size);
                    check_vmulbf16(&instruction, decoded_size,
                        vmulbf16_form(ll,1),0,0u,0,0u);
                    EXPECT(instruction.opcode[0].reg
                        == vector_reg(ll,destination));
                    EXPECT(instruction.opcode[1].reg
                        == vector_reg(ll,source1));
                    EXPECT(instruction.opcode[2].reg
                        == vector_reg(ll,source2));
                }
            }
        }
    }
#endif
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id gpr64(unsigned int index)
{
    return index < 16u
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_RAX + index)
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_R16 + index - 16u);
}
#endif

static void test_p0_extension_space(void)
{
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    unsigned int control;

    for (control = 0u; control < 32u; ++control) {
        const uint8_t p0 = (uint8_t)((control << 3) | 5u);
        const int apx = (p0 & UINT8_C(0x08)) != 0u;
        unsigned int rep;

        for (rep = 0u; rep < 2u; ++rep) {
            const int reg = rep != 0u;
            const uint8_t code[] = {
                0x62,p0,0x75,0x08,0x59,(uint8_t)(reg ? 0xc2 : 0x02)
            };
            const unsigned int destination =
                ((p0 & UINT8_C(0x80)) == 0u ? 8u : 0u)
                + ((p0 & UINT8_C(0x10)) == 0u ? 16u : 0u);
            const unsigned int source2 = 2u
                + ((p0 & UINT8_C(0x20)) == 0u ? 8u : 0u)
                + (reg && (p0 & UINT8_C(0x40)) == 0u ? 16u : 0u);
            const unsigned int base = 2u
                + ((p0 & UINT8_C(0x20)) == 0u ? 8u : 0u)
                + (!reg && apx ? 16u : 0u);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
                &flags, &decoded_size);

            check_vmulbf16(&instruction, decoded_size,
                vmulbf16_form(0u,reg),apx,0u,0,0u);
            EXPECT(instruction.opcode[0].reg
                == vector_reg(0u,destination));
            if (reg) {
                EXPECT(instruction.opcode[2].reg
                    == vector_reg(0u,source2));
            } else {
                EXPECT(instruction.opcode[2].base_reg == gpr64(base));
            }
        }
    }
#endif
}

static void test_features_profiles_addresses_and_disp8(void)
{
    static const uint8_t reg_forms[][6] = {
        {0x62,0xf5,0x75,0x08,0x59,0xc2},
        {0x62,0xf5,0x75,0x28,0x59,0xc2},
        {0x62,0xf5,0x75,0x48,0x59,0xc2}
    };
    static const uint8_t b4_reg[] = {0x62,0xfd,0x75,0x08,0x59,0xc2};
    static const uint8_t b4_mem[] = {0x62,0xfd,0x75,0x08,0x59,0x02};
    static const uint8_t x4_mem[] = {
        0x62,0xf5,0x71,0x08,0x59,0x04,0xa4
    };
    static const uint8_t disp8_full[][7] = {
        {0x62,0xf5,0x75,0x08,0x59,0x40,0xff},
        {0x62,0xf5,0x75,0x28,0x59,0x40,0xff},
        {0x62,0xf5,0x75,0x48,0x59,0x40,0xff}
    };
    static const uint8_t disp8_broadcast[][7] = {
        {0x62,0xf5,0x75,0x18,0x59,0x40,0xff},
        {0x62,0xf5,0x75,0x38,0x59,0x40,0xff},
        {0x62,0xf5,0x75,0x58,0x59,0x40,0xff}
    };
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_cpu_id positive_profiles[] = {
        CDISASM_CPU_AVX10, CDISASM_CPU_APX, CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const cdisasm_x86_cpu_id negative_profiles[] = {
        CDISASM_CPU_ICE_LAKE, CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_CPU_GRANITE_RAPIDS
    };
    static const cdisasm_x86_cpu_id apx_profiles[] = {
        CDISASM_CPU_APX, CDISASM_CPU_DIAMOND_RAPIDS
    };
    cdisasm_x86_decode_flags exact[3];
    cdisasm_x86_decode_flags umbrella =
        one_bit(CDISASM_X86_DECODE_BIT_AVX10);
    cdisasm_x86_decode_flags exact_apx;
    cdisasm_x86_decode_flags available;
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    for (index = 0u; index < 3u; ++index) {
        exact[index] = one_bit(width_bit((unsigned int)index));
    }
    for (index = 0u; index < 3u; ++index) {
        size_t profile;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            reg_forms[index], sizeof(reg_forms[index]), &exact[index],
            &decoded_size);
        check_vmulbf16(&instruction, decoded_size,
            vmulbf16_form((unsigned int)index,1),0,0u,0,0u);
        expect_error("width bit mismatch", CDISASM_CPU_X86,
            CDISASM_MODE_64, reg_forms[index], sizeof(reg_forms[index]),
            &exact[(index + 1u) % 3u],
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX10 umbrella is not exact", CDISASM_CPU_X86,
            CDISASM_MODE_64, reg_forms[index], sizeof(reg_forms[index]),
            &umbrella, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        for (profile = 0u;
             profile < sizeof(positive_profiles)
                / sizeof(positive_profiles[0]); ++profile) {
            EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                positive_profiles[profile], CDISASM_MODE_64,
                &available) == CDISASM_STATUS_OK);
            instruction = decode(positive_profiles[profile],
                CDISASM_MODE_64, reg_forms[index], sizeof(reg_forms[index]),
                &available, &decoded_size);
            EXPECT(decoded_size == sizeof(reg_forms[index]));
            EXPECT(instruction.form_id
                == vmulbf16_form((unsigned int)index,1));
        }
        for (profile = 0u;
             profile < sizeof(negative_profiles)
                / sizeof(negative_profiles[0]); ++profile) {
            EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                negative_profiles[profile], CDISASM_MODE_64,
                &available) == CDISASM_STATUS_OK);
            expect_error("profile lacks AVX10.2 BF16",
                negative_profiles[profile], CDISASM_MODE_64,
                reg_forms[index], sizeof(reg_forms[index]), &available,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            disp8_full[index], sizeof(disp8_full[index]), &exact[index],
            &decoded_size);
        check_vmulbf16(&instruction, decoded_size,
            vmulbf16_form((unsigned int)index,0),0,0u,0,0u);
        EXPECT(instruction.opcode[2].imm
            == (uint64_t)(-(INT64_C(16) << index)));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            disp8_broadcast[index], sizeof(disp8_broadcast[index]),
            &exact[index], &decoded_size);
        check_vmulbf16(&instruction, decoded_size,
            vmulbf16_form((unsigned int)index,0),0,0u,0,8u << index);
        EXPECT(instruction.opcode[2].imm == (uint64_t)INT64_C(-2));
    }

    exact_apx = two_bits(CDISASM_X86_DECODE_BIT_AVX10_2_BF16_128,
        CDISASM_X86_DECODE_BIT_APX);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_reg, sizeof(b4_reg), &exact_apx, &decoded_size);
    check_vmulbf16(&instruction, decoded_size, UINT16_C(6007),1,0u,0,0u);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM2);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_mem, sizeof(b4_mem), &exact_apx, &decoded_size);
    check_vmulbf16(&instruction, decoded_size, UINT16_C(6006),1,0u,0,0u);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R18);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        x4_mem, sizeof(x4_mem), &exact_apx, &decoded_size);
    check_vmulbf16(&instruction, decoded_size, UINT16_C(6006),1,0u,0,0u);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R20);
    expect_error("APX runtime bit", CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_reg, sizeof(b4_reg), &exact[0],
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 profile rejects APX", CDISASM_CPU_AVX10,
        CDISASM_MODE_64, b4_reg, sizeof(b4_reg), &exact_apx,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    for (index = 0u;
         index < sizeof(apx_profiles) / sizeof(apx_profiles[0]); ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            apx_profiles[index], CDISASM_MODE_64,
            &available) == CDISASM_STATUS_OK);
        instruction = decode(apx_profiles[index], CDISASM_MODE_64,
            b4_reg, sizeof(b4_reg), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(b4_reg));
    }
#else
    expect_error("VMULBF16 extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, reg_forms[0], sizeof(reg_forms[0]), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    (void)b4_reg;
    (void)b4_mem;
    (void)x4_mem;
    (void)disp8_full;
    (void)disp8_broadcast;
#endif
}

static void test_reserved_truncated_and_neighbors(void)
{
    static const uint8_t valid[] = {0x62,0xf5,0x75,0x08,0x59,0xc2};
    static const struct {
        const char *label;
        uint8_t code[7];
        size_t size;
        cdisasm_x86_mode mode;
    } invalid[] = {
        {"W1",{0x62,0xf5,0xf5,0x08,0x59,0xc2,0},6,CDISASM_MODE_64},
        {"W1 U0 memory",{0x62,0xf5,0xf1,0x08,0x59,0x00,0},6,
            CDISASM_MODE_64},
        {"LL3",{0x62,0xf5,0x75,0x68,0x59,0xc2,0},6,CDISASM_MODE_64},
        {"b register",{0x62,0xf5,0x75,0x18,0x59,0xc2,0},6,
            CDISASM_MODE_64},
        {"z without mask",{0x62,0xf5,0x75,0x88,0x59,0xc2,0},6,
            CDISASM_MODE_64},
        {"U0 register",{0x62,0xf5,0x71,0x08,0x59,0xc2,0},6,
            CDISASM_MODE_64},
        {"B4 non-long",{0x62,0xfd,0x75,0x08,0x59,0xc2,0},6,
            CDISASM_MODE_32},
        {"V prime non-long",{0x62,0xf5,0x75,0x00,0x59,0xc2,0},6,
            CDISASM_MODE_32}
    };
    static const uint8_t missing_sib[] = {
        0x62,0xf5,0x75,0x08,0x59,0x04
    };
    static const uint8_t missing_disp8[] = {
        0x62,0xf5,0x75,0x08,0x59,0x40
    };
    static const struct {
        const char *label;
        uint8_t p1;
        uint8_t p2;
    } deferred_controls[] = {
        {"W1",0xf5,0x08},
        {"z without mask",0x75,0x88},
        {"W1 U0",0xf1,0x08}
    };
    static const uint8_t legacy_prefixes[][7] = {
        {0x66,0x62,0xf5,0x75,0x08,0x59,0xc2},
        {0xf2,0x62,0xf5,0x75,0x08,0x59,0xc2},
        {0xf3,0x62,0xf5,0x75,0x08,0x59,0xc2},
        {0xf0,0x62,0xf5,0x75,0x08,0x59,0xc2},
        {0x48,0x62,0xf5,0x75,0x08,0x59,0xc2}
    };
    static const uint8_t neighbors[][6] = {
        {0x62,0xf5,0x74,0x08,0x59,0xc2}, /* VMULPH */
        {0x62,0xf5,0x76,0x08,0x59,0xc2}, /* VMULSH */
        {0x62,0xf5,0x77,0x08,0x59,0xc2}  /* reserved pp=F2 */
    };
    size_t index;

    for (index = 1u; index < sizeof(valid); ++index) {
        expect_error("truncated VMULBF16", CDISASM_CPU_X86,
            CDISASM_MODE_64, valid, index, NULL, CDISASM_STATUS_TRUNCATED);
    }
    expect_error("missing SIB", CDISASM_CPU_X86, CDISASM_MODE_64,
        missing_sib, sizeof(missing_sib), NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("missing disp8", CDISASM_CPU_X86, CDISASM_MODE_64,
        missing_disp8, sizeof(missing_disp8), NULL,
        CDISASM_STATUS_TRUNCATED);
    for (index = 0u;
         index < sizeof(deferred_controls) / sizeof(deferred_controls[0]);
         ++index) {
        uint8_t code[] = {
            0x62,0xf5,deferred_controls[index].p1,
            deferred_controls[index].p2,0x59,0
        };

        expect_error(deferred_controls[index].label, CDISASM_CPU_X86,
            CDISASM_MODE_64, code, 5u, NULL, CDISASM_STATUS_TRUNCATED);
        code[5] = 0x04;
        expect_error(deferred_controls[index].label, CDISASM_CPU_X86,
            CDISASM_MODE_64, code, sizeof(code), NULL,
            CDISASM_STATUS_TRUNCATED);
        code[5] = 0x40;
        expect_error(deferred_controls[index].label, CDISASM_CPU_X86,
            CDISASM_MODE_64, code, sizeof(code), NULL,
            CDISASM_STATUS_TRUNCATED);
    }
    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error(invalid[index].label, CDISASM_CPU_X86,
            invalid[index].mode, invalid[index].code, invalid[index].size,
            NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 0u;
         index < sizeof(legacy_prefixes) / sizeof(legacy_prefixes[0]);
         ++index) {
        expect_error("legacy prefix collision", CDISASM_CPU_X86,
            CDISASM_MODE_64, legacy_prefixes[index],
            sizeof(legacy_prefixes[index]), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if USE_EXTRA_OPCODES
    {
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        cdisasm_instruction instruction;
        uint32_t decoded_size;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            neighbors[0], sizeof(neighbors[0]), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(neighbors[0]));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VMULPH);
        EXPECT(instruction.form_id == UINT16_C(6023));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            neighbors[1], sizeof(neighbors[1]), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(neighbors[1]));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VMULSH);
        EXPECT(instruction.form_id == UINT16_C(6043));
    }
#endif
    expect_error("reserved pp=F2 neighbor", CDISASM_CPU_X86,
        CDISASM_MODE_64, neighbors[2], sizeof(neighbors[2]), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const struct {
        uint8_t code[7];
        size_t size;
        cdisasm_x86_decode_bit_id bit;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0x62,0xf5,0x75,0x09,0x59,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX10_2_BF16_128,
            "vmulbf16 xmm0 {k1}, xmm1, xmm2",
            "vmulbf16 %xmm2, %xmm1, %xmm0{%k1}"},
        {{0x62,0xf5,0x75,0xa9,0x59,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX10_2_BF16_256,
            "vmulbf16 ymm0 {k1}{z}, ymm1, ymm2",
            "vmulbf16 %ymm2, %ymm1, %ymm0{%k1}{z}"},
        {{0x62,0xf5,0x75,0x48,0x59,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX10_2_BF16_512,
            "vmulbf16 zmm0, zmm1, zmmword ptr [rax - 0x40]",
            "vmulbf16 -0x40(%rax), %zmm1, %zmm0"},
        {{0x62,0xf5,0x75,0x59,0x59,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX10_2_BF16_512,
            "vmulbf16 zmm0 {k1}, zmm1, word ptr [rax - 0x2]{1to32}",
            "vmulbf16 -0x2(%rax){1to32}, %zmm1, %zmm0{%k1}"}
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

    RUN_TEST(test_modrm_allocation);
    RUN_TEST(test_owned_control_spaces);
    RUN_TEST(test_high_register_space);
    RUN_TEST(test_p0_extension_space);
    RUN_TEST(test_features_profiles_addresses_and_disp8);
    RUN_TEST(test_reserved_truncated_and_neighbors);
    RUN_TEST(test_formatting);
#undef RUN_TEST

    if (failures != 0) {
        fprintf(stderr, "x86 VMULBF16 tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 VMULBF16 tests passed");
    return 0;
}
