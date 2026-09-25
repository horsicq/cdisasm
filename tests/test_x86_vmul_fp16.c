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

_Static_assert(CDISASM_X86_NAME_VMULPH == UINT16_C(1795)
        && CDISASM_X86_NAME_VMULSH == UINT16_C(1796),
    "VMULPH/VMULSH name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX512_FP16_128 == UINT16_C(197)
        && CDISASM_X86_GROUP_AVX512_FP16_256 == UINT16_C(199)
        && CDISASM_X86_GROUP_AVX512_FP16_512 == UINT16_C(200)
        && CDISASM_X86_GROUP_AVX512_FP16_SCALAR == UINT16_C(204),
    "VMULPH/VMULSH ISA-set IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512_FP16_128 == UINT32_C(145)
        && CDISASM_X86_DECODE_BIT_AVX512_FP16_256 == UINT32_C(147)
        && CDISASM_X86_DECODE_BIT_AVX512_FP16_512 == UINT32_C(148)
        && CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR == UINT32_C(152),
    "VMULPH/VMULSH runtime-bit IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VMULPH/VMULSH profile sweeps");

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

static cdisasm_x86_form_id ph_form(
    unsigned int ll,
    int reg,
    int embedded_rounding)
{
    return embedded_rounding
        ? UINT16_C(6027)
        : (cdisasm_x86_form_id)(
            UINT16_C(6022) + 2u * ll + (reg ? 1u : 0u));
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

static cdisasm_x86_group_id ph_width_group(unsigned int ll)
{
    static const cdisasm_x86_group_id groups[3] = {
        CDISASM_X86_GROUP_AVX512_FP16_128,
        CDISASM_X86_GROUP_AVX512_FP16_256,
        CDISASM_X86_GROUP_AVX512_FP16_512
    };

    return groups[ll];
}

static cdisasm_x86_decode_bit_id ph_width_bit(unsigned int ll)
{
    static const cdisasm_x86_decode_bit_id bits[3] = {
        CDISASM_X86_DECODE_BIT_AVX512_FP16_128,
        CDISASM_X86_DECODE_BIT_AVX512_FP16_256,
        CDISASM_X86_DECODE_BIT_AVX512_FP16_512
    };

    return bits[ll];
}

static cdisasm_x86_reg_id vector_reg(unsigned int ll, unsigned int index)
{
    const cdisasm_x86_reg_id base = ll == 0u ? CDISASM_X86_REG_XMM0
        : ll == 1u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_ZMM0;

    return (cdisasm_x86_reg_id)(base + index);
}

static cdisasm_x86_reg_id gpr64(unsigned int index)
{
    return index < 16u
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_RAX + index)
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_R16 + index - 16u);
}

static void check_vmul_fp16(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    int scalar,
    cdisasm_x86_form_id form_id,
    unsigned int ll,
    int apx,
    unsigned int aaa,
    int zero,
    unsigned int broadcast,
    cdisasm_x86_rounding_mode rounding)
{
    const unsigned int operand_ll = scalar ? 0u : ll;
    const unsigned int vector_bytes = 16u << operand_ll;
    const int memory = scalar
        ? form_id == UINT16_C(6042)
        : (form_id & UINT16_C(1)) == 0u;
    const int merge = aaa != 0u && !zero;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (scalar
        ? CDISASM_X86_NAME_VMULSH : CDISASM_X86_NAME_VMULPH));
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->operand_count == 3u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
    EXPECT(instruction->encoding.prefix_size == 4u);
    EXPECT(instruction->encoding.opcode_offset == 4u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset == 5u);
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
    EXPECT(instruction->opcode[2].size
        == (memory && (scalar || broadcast != 0u) ? 2u : vector_bytes));
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].broadcast
        == (cdisasm_x86_broadcast)broadcast);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512FP16));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, scalar ? CDISASM_X86_GROUP_AVX512_FP16_SCALAR
                            : ph_width_group(ll)));
    if (!scalar) {
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512_FP16_128)
            == (ll == 0u));
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512_FP16_256)
            == (ll == 1u));
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512_FP16_512)
            == (ll == 2u));
    }
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == apx);
    EXPECT(instruction->mask_reg == (aaa == 0u
        ? CDISASM_X86_REG_NONE
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
    EXPECT(instruction->mask_mode == (aaa == 0u
        ? CDISASM_X86_MASK_NONE
        : zero ? CDISASM_X86_MASK_ZERO : CDISASM_X86_MASK_MERGE));
    EXPECT(instruction->rounding == rounding);
    EXPECT(instruction->sae == (rounding == CDISASM_X86_ROUNDING_NONE
        ? CDISASM_X86_SAE_NONE : CDISASM_X86_SAE_ENABLED));
    EXPECT(instruction->encoding.immediate_count == 0u);
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    int scalar,
    cdisasm_x86_form_id form_id,
    unsigned int ll,
    int apx,
    unsigned int aaa,
    int zero,
    unsigned int broadcast,
    cdisasm_x86_rounding_mode rounding)
{
#if USE_EXTRA_OPCODES
    check_vmul_fp16(instruction, decoded_size, scalar, form_id, ll,
        apx, aaa, zero, broadcast, rounding);
#else
    (void)scalar;
    (void)form_id;
    (void)ll;
    (void)apx;
    (void)aaa;
    (void)zero;
    (void)broadcast;
    (void)rounding;
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
    uint64_t ph_forms[6] = {0,0,0,0,0,0};
    uint64_t ph_allocated = 0u;
    uint64_t sh_allocated = 0u;
    uint64_t sh_reserved = 0u;
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
                    const int er = b != 0u && reg;
                    const unsigned int effective_ll = er ? 2u : ll;
                    const uint8_t code[15] = {
                        0x62,0xf5,0x74,
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

                    check_allocated(&instruction, decoded_size, 0,
                        ph_form(ll, reg, er), effective_ll, 0,0u,0,
                        b != 0u && !reg ? 8u << ll : 0u,
                        er ? (cdisasm_x86_rounding_mode)(ll + 1u)
                           : CDISASM_X86_ROUNDING_NONE);
                    ++ph_forms[(ph_form(ll, reg, er)
                        - UINT16_C(6022))];
                    ++ph_allocated;
                }
            }
        }

        {
            unsigned int b;

            for (b = 0u; b <= 1u; ++b) {
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const int reg = (modrm & UINT8_C(0xc0))
                        == UINT8_C(0xc0);
                    const int valid = b == 0u || reg;
                    const uint8_t code[15] = {
                        0x62,0xf5,0x76,
                        (uint8_t)(0x08u | (b << 4)),0x59,
                        (uint8_t)modrm,0x24,0x10,0x20,0x30,0x40,
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
                        ++sh_reserved;
                        continue;
                    }
                    check_allocated(&instruction, decoded_size, 1,
                        (cdisasm_x86_form_id)(UINT16_C(6042)
                            + (reg ? 1u : 0u)),0u,0,0u,0,0u,
                        b != 0u ? CDISASM_X86_ROUNDING_RN
                               : CDISASM_X86_ROUNDING_NONE);
                    ++sh_allocated;
                }
            }
        }
    }

    EXPECT(ph_allocated == UINT64_C(4608));
    EXPECT(ph_forms[0] == UINT64_C(1152));
    EXPECT(ph_forms[1] == UINT64_C(192));
    EXPECT(ph_forms[2] == UINT64_C(1152));
    EXPECT(ph_forms[3] == UINT64_C(192));
    EXPECT(ph_forms[4] == UINT64_C(1152));
    EXPECT(ph_forms[5] == UINT64_C(768));
    EXPECT(sh_allocated == UINT64_C(960));
    EXPECT(sh_reserved == UINT64_C(576));
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
    unsigned int family;

    for (family = 0u; family < 2u; ++family) {
        size_t mode_index;

        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            const int scalar = family != 0u;
            const int long_mode = modes[mode_index] == CDISASM_MODE_64;
            const uint8_t pp = scalar ? UINT8_C(2) : UINT8_C(0);
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
                    | (vvvv_raw << 3) | (u << 2) | pp);
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
                        ++p1_reserved;
                        continue;
                    }
                    check_allocated(&instruction, decoded_size, scalar,
                        scalar
                            ? (cdisasm_x86_form_id)(UINT16_C(6042) + reg)
                            : ph_form(0u,reg,0),0u,u == 0u,0u,0,0u,
                        CDISASM_X86_ROUNDING_NONE);
#if USE_EXTRA_OPCODES
                    EXPECT(instruction.opcode[1].reg
                        == vector_reg(0u,source));
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
                    const int valid_ll_b = scalar
                        ? ((!b && ll < 3u) || (b && reg))
                        : (b && reg) || ll < 3u;
                    const int valid = valid_ll_b
                        && (!zero || aaa != 0u)
                        && (!scalar || !b || reg)
                        && (long_mode || (p2 & UINT8_C(0x08)) != 0u);
                    const int er = b && reg;
                    const unsigned int effective_ll = scalar
                        ? 0u : er ? 2u : ll;
                    const uint8_t code[] = {
                        0x62,0xf5,(uint8_t)(0x74u | pp),p2,0x59,
                        (uint8_t)(reg ? 0xc2 : 0x00),0x24,0,0,0,0
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
                        ++p2_reserved;
                        continue;
                    }
                    check_allocated(&instruction, decoded_size, scalar,
                        scalar
                            ? (cdisasm_x86_form_id)(UINT16_C(6042) + reg)
                            : ph_form(ll,reg,er),effective_ll,0,aaa,zero,
                        b && !reg ? 8u << ll : 0u,
                        er ? (cdisasm_x86_rounding_mode)(ll + 1u)
                           : CDISASM_X86_ROUNDING_NONE);
#if USE_EXTRA_OPCODES
                    EXPECT(instruction.opcode[1].reg == vector_reg(
                        effective_ll,
                        (p2 & UINT8_C(0x08)) != 0u ? 1u : 17u));
#endif
                    ++p2_allocated;
                }
            }
        }
    }

    EXPECT(p1_allocated == UINT32_C(160));
    EXPECT(p1_reserved == UINT32_C(608));
    EXPECT(p2_allocated == UINT32_C(1380));
    EXPECT(p2_reserved == UINT32_C(1692));
}

static void test_high_register_space(void)
{
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    unsigned int family;

    for (family = 0u; family < 2u; ++family) {
        const int scalar = family != 0u;
        const unsigned int widths = scalar ? 1u : 3u;
        unsigned int ll;

        for (ll = 0u; ll < widths; ++ll) {
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
                        code[2] = (uint8_t)((((~source1) & 15u) << 3)
                            | (scalar ? 2u : 0u) | 4u);
                        code[3] = (uint8_t)((ll << 5)
                            | (source1 < 16u ? 8u : 0u));
                        code[4] = UINT8_C(0x59);
                        code[5] = (uint8_t)(UINT8_C(0xc0)
                            | ((destination & 7u) << 3)
                            | (source2 & 7u));
                        instruction = decode(CDISASM_CPU_X86,
                            CDISASM_MODE_64, code, sizeof(code), &flags,
                            &decoded_size);
                        check_vmul_fp16(&instruction, decoded_size, scalar,
                            scalar ? UINT16_C(6043) : ph_form(ll,1,0),
                            ll,0,0u,0,0u,CDISASM_X86_ROUNDING_NONE);
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
    }
#endif
}

static void test_p0_extension_space(void)
{
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    unsigned int family;

    for (family = 0u; family < 2u; ++family) {
        const int scalar = family != 0u;
        unsigned int control;

        for (control = 0u; control < 32u; ++control) {
            const uint8_t p0 = (uint8_t)((control << 3) | 5u);
            const int apx = (p0 & UINT8_C(0x08)) != 0u;
            unsigned int rep;

            for (rep = 0u; rep < 2u; ++rep) {
                const int reg = rep != 0u;
                const uint8_t code[] = {
                    0x62,p0,(uint8_t)(scalar ? 0x76 : 0x74),0x08,
                    0x59,(uint8_t)(reg ? 0xc2 : 0x02)
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

                check_vmul_fp16(&instruction, decoded_size, scalar,
                    scalar
                        ? (cdisasm_x86_form_id)(UINT16_C(6042) + reg)
                        : ph_form(0u,reg,0),0u,apx,0u,0,0u,
                    CDISASM_X86_ROUNDING_NONE);
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
    }
#endif
}

static void test_features_profiles_addresses_disp8_and_rounding(void)
{
    static const uint8_t ph_reg[][6] = {
        {0x62,0xf5,0x74,0x08,0x59,0xc2},
        {0x62,0xf5,0x74,0x28,0x59,0xc2},
        {0x62,0xf5,0x74,0x48,0x59,0xc2}
    };
    static const uint8_t sh_reg[] = {0x62,0xf5,0x76,0x08,0x59,0xc2};
    static const uint8_t ph_b4_reg[] = {0x62,0xfd,0x74,0x08,0x59,0xc2};
    static const uint8_t ph_b4_mem[] = {0x62,0xfd,0x74,0x08,0x59,0x02};
    static const uint8_t ph_x4_mem[] = {
        0x62,0xf5,0x70,0x08,0x59,0x04,0xa4
    };
    static const uint8_t sh_b4_reg[] = {0x62,0xfd,0x76,0x08,0x59,0xc2};
    static const uint8_t sh_b4_mem[] = {0x62,0xfd,0x76,0x08,0x59,0x02};
    static const uint8_t sh_x4_mem[] = {
        0x62,0xf5,0x72,0x08,0x59,0x04,0xa4
    };
    static const uint8_t ph_disp8_full[][7] = {
        {0x62,0xf5,0x74,0x08,0x59,0x40,0xff},
        {0x62,0xf5,0x74,0x28,0x59,0x40,0xff},
        {0x62,0xf5,0x74,0x48,0x59,0x40,0xff}
    };
    static const uint8_t ph_disp8_broadcast[][7] = {
        {0x62,0xf5,0x74,0x18,0x59,0x40,0xff},
        {0x62,0xf5,0x74,0x38,0x59,0x40,0xff},
        {0x62,0xf5,0x74,0x58,0x59,0x40,0xff}
    };
    static const uint8_t sh_disp8[] = {
        0x62,0xf5,0x76,0x08,0x59,0x40,0xff
    };
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_cpu_id positive_profiles[] = {
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_CPU_AVX10,
        CDISASM_CPU_APX, CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const cdisasm_x86_cpu_id negative_profiles[] = {
        CDISASM_CPU_SKYLAKE_SP, CDISASM_CPU_ICE_LAKE,
        CDISASM_CPU_AMD_ZEN_4, CDISASM_CPU_KNIGHTS_MILL
    };
    cdisasm_x86_decode_flags exact[3];
    cdisasm_x86_decode_flags scalar =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR);
    cdisasm_x86_decode_flags umbrella =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512);
    cdisasm_x86_decode_flags avx10 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX10);
    cdisasm_x86_decode_flags available;
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    for (index = 0u; index < 3u; ++index) {
        exact[index] = one_bit(ph_width_bit((unsigned int)index));
    }
    for (index = 0u; index < 3u; ++index) {
        size_t profile;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            ph_reg[index], sizeof(ph_reg[index]), &exact[index],
            &decoded_size);
        check_vmul_fp16(&instruction, decoded_size, 0,
            ph_form((unsigned int)index,1,0),(unsigned int)index,
            0,0u,0,0u,CDISASM_X86_ROUNDING_NONE);
        expect_error("packed width mismatch", CDISASM_CPU_X86,
            CDISASM_MODE_64, ph_reg[index], sizeof(ph_reg[index]),
            &exact[(index + 1u) % 3u],
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX512 umbrella is not exact", CDISASM_CPU_X86,
            CDISASM_MODE_64, ph_reg[index], sizeof(ph_reg[index]),
            &umbrella, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX10 umbrella is not exact", CDISASM_CPU_X86,
            CDISASM_MODE_64, ph_reg[index], sizeof(ph_reg[index]),
            &avx10, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        for (profile = 0u;
             profile < sizeof(positive_profiles)
                / sizeof(positive_profiles[0]); ++profile) {
            EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                positive_profiles[profile], CDISASM_MODE_64,
                &available) == CDISASM_STATUS_OK);
            instruction = decode(positive_profiles[profile],
                CDISASM_MODE_64, ph_reg[index], sizeof(ph_reg[index]),
                &available, &decoded_size);
            EXPECT(decoded_size == sizeof(ph_reg[index]));
            EXPECT(instruction.form_id
                == ph_form((unsigned int)index,1,0));
        }
        for (profile = 0u;
             profile < sizeof(negative_profiles)
                / sizeof(negative_profiles[0]); ++profile) {
            EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                negative_profiles[profile], CDISASM_MODE_64,
                &available) == CDISASM_STATUS_OK);
            expect_error("profile lacks AVX512-FP16",
                negative_profiles[profile], CDISASM_MODE_64,
                ph_reg[index], sizeof(ph_reg[index]), &available,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            ph_disp8_full[index], sizeof(ph_disp8_full[index]),
            &exact[index], &decoded_size);
        check_vmul_fp16(&instruction, decoded_size, 0,
            ph_form((unsigned int)index,0,0),(unsigned int)index,
            0,0u,0,0u,CDISASM_X86_ROUNDING_NONE);
        EXPECT(instruction.opcode[2].imm
            == (uint64_t)(-(INT64_C(16) << index)));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            ph_disp8_broadcast[index],
            sizeof(ph_disp8_broadcast[index]), &exact[index],
            &decoded_size);
        check_vmul_fp16(&instruction, decoded_size, 0,
            ph_form((unsigned int)index,0,0),(unsigned int)index,
            0,0u,0,8u << index,CDISASM_X86_ROUNDING_NONE);
        EXPECT(instruction.opcode[2].imm == (uint64_t)INT64_C(-2));
    }

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        sh_reg, sizeof(sh_reg), &scalar, &decoded_size);
    check_vmul_fp16(&instruction, decoded_size, 1,UINT16_C(6043),0u,
        0,0u,0,0u,CDISASM_X86_ROUNDING_NONE);
    expect_error("scalar width mismatch", CDISASM_CPU_X86,
        CDISASM_MODE_64, sh_reg, sizeof(sh_reg), &exact[0],
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("scalar AVX512 umbrella is not exact", CDISASM_CPU_X86,
        CDISASM_MODE_64, sh_reg, sizeof(sh_reg), &umbrella,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    {
        cdisasm_x86_decode_flags ph_apx = two_bits(
            CDISASM_X86_DECODE_BIT_AVX512_FP16_128,
            CDISASM_X86_DECODE_BIT_APX);
        cdisasm_x86_decode_flags sh_apx = two_bits(
            CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR,
            CDISASM_X86_DECODE_BIT_APX);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            ph_b4_reg, sizeof(ph_b4_reg), &ph_apx, &decoded_size);
        check_vmul_fp16(&instruction, decoded_size, 0,UINT16_C(6023),0u,
            1,0u,0,0u,CDISASM_X86_ROUNDING_NONE);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM2);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            ph_b4_mem, sizeof(ph_b4_mem), &ph_apx, &decoded_size);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R18);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            ph_x4_mem, sizeof(ph_x4_mem), &ph_apx, &decoded_size);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R20);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            sh_b4_reg, sizeof(sh_b4_reg), &sh_apx, &decoded_size);
        check_vmul_fp16(&instruction, decoded_size, 1,UINT16_C(6043),0u,
            1,0u,0,0u,CDISASM_X86_ROUNDING_NONE);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM2);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            sh_b4_mem, sizeof(sh_b4_mem), &sh_apx, &decoded_size);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R18);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            sh_x4_mem, sizeof(sh_x4_mem), &sh_apx, &decoded_size);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R20);

        expect_error("packed APX runtime bit", CDISASM_CPU_X86,
            CDISASM_MODE_64, ph_b4_reg, sizeof(ph_b4_reg), &exact[0],
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("scalar APX runtime bit", CDISASM_CPU_X86,
            CDISASM_MODE_64, sh_b4_reg, sizeof(sh_b4_reg), &scalar,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX10 profile rejects packed APX",
            CDISASM_CPU_AVX10, CDISASM_MODE_64,
            ph_b4_reg, sizeof(ph_b4_reg), &ph_apx,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        sh_disp8, sizeof(sh_disp8), &scalar, &decoded_size);
    check_vmul_fp16(&instruction, decoded_size, 1,UINT16_C(6042),0u,
        0,0u,0,0u,CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction.opcode[2].imm == (uint64_t)INT64_C(-2));

    for (index = 0u; index < 4u; ++index) {
        uint8_t ph_round[] = {0x62,0xf5,0x74,0x18,0x59,0xc2};
        uint8_t sh_round[] = {0x62,0xf5,0x76,0x18,0x59,0xc2};

        ph_round[3] = (uint8_t)(0x18u | (index << 5));
        sh_round[3] = (uint8_t)(0x18u | (index << 5));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            ph_round, sizeof(ph_round), &exact[2], &decoded_size);
        check_vmul_fp16(&instruction, decoded_size, 0,UINT16_C(6027),2u,
            0,0u,0,0u,(cdisasm_x86_rounding_mode)(index + 1u));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            sh_round, sizeof(sh_round), &scalar, &decoded_size);
        check_vmul_fp16(&instruction, decoded_size, 1,UINT16_C(6043),0u,
            0,0u,0,0u,(cdisasm_x86_rounding_mode)(index + 1u));
    }
#else
    expect_error("VMULPH extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, ph_reg[0], sizeof(ph_reg[0]), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VMULSH extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, sh_reg, sizeof(sh_reg), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    (void)ph_b4_reg;
    (void)ph_b4_mem;
    (void)ph_x4_mem;
    (void)sh_b4_reg;
    (void)sh_b4_mem;
    (void)sh_x4_mem;
    (void)ph_disp8_full;
    (void)ph_disp8_broadcast;
    (void)sh_disp8;
#endif
}

static void test_reserved_truncated_and_collisions(void)
{
    static const uint8_t valid_ph[] = {0x62,0xf5,0x74,0x08,0x59,0xc2};
    static const uint8_t valid_sh[] = {0x62,0xf5,0x76,0x08,0x59,0xc2};
    static const struct {
        const char *label;
        uint8_t code[7];
        size_t size;
        cdisasm_x86_mode mode;
    } invalid[] = {
        {"PH W1",{0x62,0xf5,0xf4,0x08,0x59,0xc2,0},6,CDISASM_MODE_64},
        {"SH W1",{0x62,0xf5,0xf6,0x08,0x59,0xc2,0},6,CDISASM_MODE_64},
        {"PH W1 U0 memory",{0x62,0xf5,0xf0,0x08,0x59,0x00,0},6,
            CDISASM_MODE_64},
        {"SH W1 U0 memory",{0x62,0xf5,0xf2,0x08,0x59,0x00,0},6,
            CDISASM_MODE_64},
        {"PH LL3 without ER",{0x62,0xf5,0x74,0x68,0x59,0xc2,0},6,
            CDISASM_MODE_64},
        {"SH LL3 without ER",{0x62,0xf5,0x76,0x68,0x59,0xc2,0},6,
            CDISASM_MODE_64},
        {"SH memory b",{0x62,0xf5,0x76,0x18,0x59,0x00,0},6,
            CDISASM_MODE_64},
        {"PH z without mask",{0x62,0xf5,0x74,0x88,0x59,0xc2,0},6,
            CDISASM_MODE_64},
        {"SH z without mask",{0x62,0xf5,0x76,0x88,0x59,0xc2,0},6,
            CDISASM_MODE_64},
        {"PH U0 register",{0x62,0xf5,0x70,0x08,0x59,0xc2,0},6,
            CDISASM_MODE_64},
        {"SH U0 register",{0x62,0xf5,0x72,0x08,0x59,0xc2,0},6,
            CDISASM_MODE_64},
        {"PH B4 non-long",{0x62,0xfd,0x74,0x08,0x59,0xc2,0},6,
            CDISASM_MODE_32},
        {"SH B4 non-long",{0x62,0xfd,0x76,0x08,0x59,0xc2,0},6,
            CDISASM_MODE_32},
        {"PH V prime non-long",{0x62,0xf5,0x74,0x00,0x59,0xc2,0},6,
            CDISASM_MODE_32},
        {"SH V prime non-long",{0x62,0xf5,0x76,0x00,0x59,0xc2,0},6,
            CDISASM_MODE_32}
    };
    static const uint8_t missing_sib_ph[] = {
        0x62,0xf5,0x74,0x08,0x59,0x04
    };
    static const uint8_t missing_sib_sh[] = {
        0x62,0xf5,0x76,0x08,0x59,0x04
    };
    static const uint8_t missing_disp8_ph[] = {
        0x62,0xf5,0x74,0x08,0x59,0x40
    };
    static const uint8_t missing_disp8_sh[] = {
        0x62,0xf5,0x76,0x08,0x59,0x40
    };
    static const struct {
        const char *label;
        uint8_t p1;
        uint8_t p2;
    } deferred_controls[] = {
        {"VMULPH W1",0xf4,0x08},
        {"VMULPH z without mask",0x74,0x88},
        {"VMULPH W1 U0",0xf0,0x08},
        {"VMULSH W1",0xf6,0x08},
        {"VMULSH z without mask",0x76,0x88},
        {"VMULSH W1 U0",0xf2,0x08}
    };
    static const uint8_t legacy_prefixes[][7] = {
        {0x66,0x62,0xf5,0x74,0x08,0x59,0xc2},
        {0xf2,0x62,0xf5,0x74,0x08,0x59,0xc2},
        {0xf3,0x62,0xf5,0x76,0x08,0x59,0xc2},
        {0xf0,0x62,0xf5,0x76,0x08,0x59,0xc2},
        {0x48,0x62,0xf5,0x74,0x08,0x59,0xc2}
    };
#if USE_EXTRA_OPCODES
    static const uint8_t bf16[] = {0x62,0xf5,0x75,0x08,0x59,0xc2};
#endif
    static const uint8_t pp_f2[] = {0x62,0xf5,0x77,0x08,0x59,0xc2};
    size_t index;

    for (index = 1u; index < sizeof(valid_ph); ++index) {
        expect_error("truncated VMULPH", CDISASM_CPU_X86,
            CDISASM_MODE_64, valid_ph, index, NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("truncated VMULSH", CDISASM_CPU_X86,
            CDISASM_MODE_64, valid_sh, index, NULL,
            CDISASM_STATUS_TRUNCATED);
    }
    expect_error("VMULPH missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64, missing_sib_ph, sizeof(missing_sib_ph), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("VMULSH missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64, missing_sib_sh, sizeof(missing_sib_sh), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("VMULPH missing disp8", CDISASM_CPU_X86,
        CDISASM_MODE_64, missing_disp8_ph, sizeof(missing_disp8_ph), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("VMULSH missing disp8", CDISASM_CPU_X86,
        CDISASM_MODE_64, missing_disp8_sh, sizeof(missing_disp8_sh), NULL,
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
            bf16, sizeof(bf16), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(bf16));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VMULBF16);
        EXPECT(instruction.form_id == UINT16_C(6007));
    }
#endif
    expect_error("unallocated PF2 collision", CDISASM_CPU_X86,
        CDISASM_MODE_64, pp_f2, sizeof(pp_f2), NULL,
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
        {{0x62,0xf5,0x74,0x09,0x59,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_128,
            "vmulph xmm0 {k1}, xmm1, xmm2",
            "vmulph %xmm2, %xmm1, %xmm0{%k1}"},
        {{0x62,0xf5,0x74,0xa9,0x59,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_256,
            "vmulph ymm0 {k1}{z}, ymm1, ymm2",
            "vmulph %ymm2, %ymm1, %ymm0{%k1}{z}"},
        {{0x62,0xf5,0x74,0x58,0x59,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_512,
            "vmulph zmm0, zmm1, word ptr [rax - 0x2]{1to32}",
            "vmulph -0x2(%rax){1to32}, %zmm1, %zmm0"},
        {{0x62,0xf5,0x74,0x39,0x59,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_512,
            "vmulph zmm0 {k1}, zmm1, zmm2, {rd-sae}",
            "vmulph {rd-sae}, %zmm2, %zmm1, %zmm0{%k1}"},
        {{0x62,0xf5,0x76,0x89,0x59,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR,
            "vmulsh xmm0 {k1}{z}, xmm1, word ptr [rax - 0x2]",
            "vmulsh -0x2(%rax), %xmm1, %xmm0{%k1}{z}"},
        {{0x62,0xf5,0x76,0x59,0x59,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR,
            "vmulsh xmm0 {k1}, xmm1, xmm2, {ru-sae}",
            "vmulsh {ru-sae}, %xmm2, %xmm1, %xmm0{%k1}"}
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
    RUN_TEST(test_features_profiles_addresses_disp8_and_rounding);
    RUN_TEST(test_reserved_truncated_and_collisions);
    RUN_TEST(test_formatting);
#undef RUN_TEST

    if (failures != 0) {
        fprintf(stderr, "x86 VMULPH/VMULSH tests: %d failure(s)\n",
            failures);
        return 1;
    }
    puts("x86 VMULPH/VMULSH tests passed");
    return 0;
}
