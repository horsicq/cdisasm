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

_Static_assert(CDISASM_X86_NAME_VPBLENDD == UINT16_C(1807)
        && CDISASM_X86_NAME_VPBLENDW == UINT16_C(1813),
    "VPBLEND name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46),
    "VPBLEND ISA-set group IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "VPBLEND runtime-bit IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VPBLEND profile sweeps");

static const uint8_t blend_opcodes[2] = {0x02,0x0e};
#if USE_EXTRA_OPCODES
static const cdisasm_x86_form_id blend_bases[2] = {
    UINT16_C(6306),UINT16_C(6338)
};
#endif

static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected,0,sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction,&expected,sizeof(expected)) == 0;
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

    memset(&instruction,0xa5,sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu_id,mode,code,size,UINT64_C(0x1000),flags,&instruction);
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
        cpu_id,mode,code,size,flags,&decoded_size);

    if (decoded_size != 0u || !is_error_only(&instruction,status)) {
        fprintf(stderr,"%s: got size/status %u/%u, expected 0/%u\n",
            label,(unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id,(unsigned int)status);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction,status));
}

#if USE_EXTRA_OPCODES
static const cdisasm_x86_name_id blend_names[2] = {
    CDISASM_X86_NAME_VPBLENDD,CDISASM_X86_NAME_VPBLENDW
};

static cdisasm_x86_decode_flags all_flags(cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86,mode,&flags) == CDISASM_STATUS_OK);
    return flags;
}

static cdisasm_x86_decode_flags one_bit(
    cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags,bit_id));
    return flags;
}

static cdisasm_x86_decode_flags two_bits(
    cdisasm_x86_decode_bit_id first,
    cdisasm_x86_decode_bit_id second)
{
    cdisasm_x86_decode_flags flags = one_bit(first);

    EXPECT(cdisasm_decode_flags_set_bit(&flags,second));
    return flags;
}

static cdisasm_x86_reg_id vector_reg(
    unsigned int vector_bits,
    unsigned int index)
{
    const cdisasm_x86_reg_id base = vector_bits == 128u
        ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;

    return (cdisasm_x86_reg_id)(base + index);
}

static void check_blend(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    unsigned int family,
    unsigned int vector_bits,
    int register_form,
    unsigned int destination,
    unsigned int source1,
    unsigned int source2,
    uint64_t immediate)
{
    const cdisasm_x86_form_id form_id = (cdisasm_x86_form_id)(
        blend_bases[family] + (vector_bits == 256u ? 2u : 0u)
        + (register_form ? 1u : 0u));

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == blend_names[family]);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->operand_count == 4u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX))
        == CDISASM_PREFIX_VEX);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 1u);
    EXPECT(instruction->encoding.immediate_offset[0]
        == decoded_size - UINT32_C(1));

    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg
        == vector_reg(vector_bits,destination));
    EXPECT(instruction->opcode[0].size == vector_bits / 8u);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[0].flags == 0u);
    EXPECT(instruction->opcode[0].broadcast
        == CDISASM_X86_BROADCAST_NONE);

    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg == vector_reg(vector_bits,source1));
    EXPECT(instruction->opcode[1].size == vector_bits / 8u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].flags == 0u);
    EXPECT(instruction->opcode[1].broadcast
        == CDISASM_X86_BROADCAST_NONE);

    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[2].size == vector_bits / 8u);
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].broadcast
        == CDISASM_X86_BROADCAST_NONE);
    if (register_form) {
        EXPECT(instruction->opcode[2].reg
            == vector_reg(vector_bits,source2));
        EXPECT(instruction->opcode[2].flags == 0u);
    }

    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[3].size == 1u);
    EXPECT(instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[3].flags == 0u);
    EXPECT(instruction->opcode[3].imm == immediate);
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction,CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction,CDISASM_X86_GROUP_AVX2)
        == (family == 0u || vector_bits == 256u));
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    unsigned int family,
    unsigned int vector_bits,
    int register_form)
{
#if USE_EXTRA_OPCODES
    const cdisasm_x86_form_id form_id = (cdisasm_x86_form_id)(
        blend_bases[family] + (vector_bits == 256u ? 2u : 0u)
        + (register_form ? 1u : 0u));

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == blend_names[family]);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->operand_count == 4u);
    EXPECT(instruction->opcode[0].size == vector_bits / 8u);
    EXPECT(instruction->opcode[1].size == vector_bits / 8u);
    EXPECT(instruction->opcode[2].size == vector_bits / 8u);
    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[3].size == 1u);
    EXPECT(instruction->encoding.immediate_count == 1u);
    EXPECT(instruction->encoding.immediate_offset[0]
        == decoded_size - UINT32_C(1));
#else
    (void)family;
    (void)vector_bits;
    (void)register_form;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_vex_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16,CDISASM_MODE_32,CDISASM_MODE_64
    };
    static const uint64_t expected_form_counts[8] = {
        UINT64_C(36864),UINT64_C(12288),
        UINT64_C(36864),UINT64_C(12288),
        UINT64_C(73728),UINT64_C(24576),
        UINT64_C(73728),UINT64_C(24576)
    };
    uint64_t form_counts[8] = {0,0,0,0,0,0,0,0};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
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
            unsigned int family;

            for (family = 0u; family < 2u; ++family) {
                unsigned int w;

                for (w = 0u; w < 2u; ++w) {
                    unsigned int l;

                    for (l = 0u; l < 2u; ++l) {
                        unsigned int pp;

                        for (pp = 0u; pp < 4u; ++pp) {
                            unsigned int vvvv;

                            for (vvvv = 0u; vvvv < 16u; ++vvvv) {
                                unsigned int modrm;

                                for (modrm = 0u; modrm <= UINT8_MAX;
                                     ++modrm) {
                                    const int register_form =
                                        (modrm & UINT8_C(0xc0))
                                            == UINT8_C(0xc0);
                                    const int valid = pp == 1u
                                        && (family != 0u || w == 0u);
                                    const unsigned int vector_bits = l != 0u
                                        ? 256u : 128u;
                                    const uint8_t code[15] = {
                                        0xc4,p0,
                                        (uint8_t)((w << 7)
                                            | (((~vvvv) & 15u) << 3)
                                            | (l << 2) | pp),
                                        blend_opcodes[family],
                                        (uint8_t)modrm,0x24,0x10,0x20,
                                        0x30,0x40,0x50,0x60,0x70,0x80,0x90
                                    };
                                    uint32_t decoded_size;
                                    cdisasm_instruction instruction = decode(
                                        CDISASM_CPU_X86,modes[mode_index],
                                        code,sizeof(code),
#if USE_EXTRA_OPCODES
                                        &flags,&decoded_size);
#else
                                        NULL,&decoded_size);
#endif

                                    if (valid) {
                                        const unsigned int form_index =
                                            family * 4u + l * 2u
                                            + (register_form ? 1u : 0u);

                                        check_allocated(&instruction,
                                            decoded_size,family,vector_bits,
                                            register_form);
#if USE_EXTRA_OPCODES
                                        EXPECT(instruction.opcode[3].imm
                                            == code[decoded_size - 1u]);
#endif
                                        ++form_counts[form_index];
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
    EXPECT(allocated == UINT64_C(294912));
    EXPECT(reserved == UINT64_C(1277952));
    for (mode_index = 0u; mode_index < 8u; ++mode_index) {
        EXPECT(form_counts[mode_index] == expected_form_counts[mode_index]);
    }
}

static void test_forms_operands_addressing_and_aliases(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t d_xmm_reg[] =
        {0xc4,0xe3,0x71,0x02,0xc2,0x5a};
    static const uint8_t d_ymm_mem[] =
        {0xc4,0xe3,0x75,0x02,0x40,0x7f,0xa5};
    static const uint8_t w_high_reg[] =
        {0xc4,0x43,0xb1,0x0e,0xfa,0xff};
    static const uint8_t w_high_mem[] =
        {0xc4,0x03,0x31,0x0e,0x44,0xa5,0x80,0x00};
    static const uint8_t rip_relative[] =
        {0xc4,0xe3,0x71,0x02,0x05,0x78,0x56,0x34,0x12,0x7e};
    static const uint8_t address_override[] =
        {0x67,0xc4,0xe3,0x71,0x0e,0x00,0x3c};
    static const uint8_t segment_override[] =
        {0x64,0xc4,0xe3,0x71,0x02,0x00,0xc3};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        d_xmm_reg,sizeof(d_xmm_reg),&flags,&decoded_size);
    check_blend(&instruction,decoded_size,0u,128u,1,0u,1u,2u,0x5au);

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        d_ymm_mem,sizeof(d_ymm_mem),&flags,&decoded_size);
    check_blend(&instruction,decoded_size,0u,256u,0,0u,1u,0u,0xa5u);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[2].imm == UINT64_C(0x7f));

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        w_high_reg,sizeof(w_high_reg),&flags,&decoded_size);
    check_blend(&instruction,decoded_size,1u,128u,1,15u,9u,10u,0xffu);

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        w_high_mem,sizeof(w_high_mem),&flags,&decoded_size);
    check_blend(&instruction,decoded_size,1u,128u,0,8u,9u,0u,0u);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R13);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R12);
    EXPECT(instruction.opcode[2].scale == 4u);
    EXPECT(instruction.opcode[2].imm == (uint64_t)-INT64_C(128));

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        rip_relative,sizeof(rip_relative),&flags,&decoded_size);
    check_blend(&instruction,decoded_size,0u,128u,0,0u,1u,0u,0x7eu);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RIP);
    EXPECT(instruction.opcode[2].imm == UINT64_C(0x12345678));

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        address_override,sizeof(address_override),&flags,&decoded_size);
    check_blend(&instruction,decoded_size,1u,128u,0,0u,1u,0u,0x3cu);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_EAX);

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        segment_override,sizeof(segment_override),&flags,&decoded_size);
    check_blend(&instruction,decoded_size,0u,128u,0,0u,1u,0u,0xc3u);
    EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_FS);

    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16,CDISASM_MODE_32
        };
        static const uint8_t b_and_vvvv_alias[] =
            {0xc4,0xc3,0x31,0x0e,0xc2,0x5a};
        size_t index;

        for (index = 0u; index < 2u; ++index) {
            cdisasm_x86_decode_flags mode_flags = all_flags(modes[index]);

            instruction = decode(CDISASM_CPU_X86,modes[index],
                b_and_vvvv_alias,sizeof(b_and_vvvv_alias),
                &mode_flags,&decoded_size);
            check_blend(
                &instruction,decoded_size,1u,128u,1,0u,1u,2u,0x5au);
        }
    }
#endif
}

static void test_runtime_and_profile_gates(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t d_xmm[] =
        {0xc4,0xe3,0x71,0x02,0xc2,0x5a};
    static const uint8_t d_ymm[] =
        {0xc4,0xe3,0x75,0x02,0xc2,0x5a};
    static const uint8_t w_xmm[] =
        {0xc4,0xe3,0x71,0x0e,0xc2,0x5a};
    static const uint8_t w_ymm[] =
        {0xc4,0xe3,0x75,0x0e,0xc2,0x5a};
    cdisasm_x86_decode_flags avx =
        one_bit(CDISASM_X86_DECODE_BIT_AVX);
    cdisasm_x86_decode_flags avx2 =
        two_bits(CDISASM_X86_DECODE_BIT_AVX,CDISASM_X86_DECODE_BIT_AVX2);
    cdisasm_x86_decode_flags sandy;
    cdisasm_x86_decode_flags haswell;
    cdisasm_x86_decode_flags apx;
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        w_xmm,sizeof(w_xmm),&avx,&decoded_size);
    check_blend(&instruction,decoded_size,1u,128u,1,0u,1u,2u,0x5au);
    expect_error("VPBLENDD requires AVX2",CDISASM_CPU_X86,
        CDISASM_MODE_64,d_xmm,sizeof(d_xmm),&avx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("YMM VPBLENDW requires AVX2",CDISASM_CPU_X86,
        CDISASM_MODE_64,w_ymm,sizeof(w_ymm),&avx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        d_xmm,sizeof(d_xmm),&avx2,&decoded_size);
    check_blend(&instruction,decoded_size,0u,128u,1,0u,1u,2u,0x5au);
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        d_ymm,sizeof(d_ymm),&avx2,&decoded_size);
    check_blend(&instruction,decoded_size,0u,256u,1,0u,1u,2u,0x5au);
    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
        w_ymm,sizeof(w_ymm),&avx2,&decoded_size);
    check_blend(&instruction,decoded_size,1u,256u,1,0u,1u,2u,0x5au);

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_SANDY_BRIDGE,CDISASM_MODE_64,&sandy)
        == CDISASM_STATUS_OK);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_HASWELL,CDISASM_MODE_64,&haswell)
        == CDISASM_STATUS_OK);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_APX,CDISASM_MODE_64,&apx) == CDISASM_STATUS_OK);
    instruction = decode(CDISASM_CPU_SANDY_BRIDGE,CDISASM_MODE_64,
        w_xmm,sizeof(w_xmm),&sandy,&decoded_size);
    EXPECT(decoded_size == sizeof(w_xmm));
    expect_error("Sandy Bridge VPBLENDD gate",CDISASM_CPU_SANDY_BRIDGE,
        CDISASM_MODE_64,d_xmm,sizeof(d_xmm),&sandy,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("Sandy Bridge YMM VPBLENDW gate",
        CDISASM_CPU_SANDY_BRIDGE,CDISASM_MODE_64,
        w_ymm,sizeof(w_ymm),&sandy,CDISASM_STATUS_INVALID_INSTRUCTION);
    instruction = decode(CDISASM_CPU_HASWELL,CDISASM_MODE_64,
        d_ymm,sizeof(d_ymm),&haswell,&decoded_size);
    EXPECT(decoded_size == sizeof(d_ymm));
    instruction = decode(CDISASM_CPU_APX,CDISASM_MODE_64,
        d_ymm,sizeof(d_ymm),&apx,&decoded_size);
    EXPECT(decoded_size == sizeof(d_ymm));
#else
    expect_error("VPBLENDD extras off",CDISASM_CPU_X86,CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x71,0x02,0xc2,0x5a},6u,NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VPBLENDW extras off",CDISASM_CPU_X86,CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x71,0x0e,0xc2,0x5a},6u,NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_prefixes_truncation_and_legacy(void)
{
    static const uint8_t legacy_prefixes[5] = {0x66,0xf2,0xf3,0xf0,0x48};
    static const struct invalid_case {
        const char *label;
        uint8_t code[8];
        size_t size;
        cdisasm_x86_mode mode;
    } invalid[] = {
        {"VPBLENDD W1",{0xc4,0xe3,0xf1,0x02,0xc2,0x5a,0,0},6,
            CDISASM_MODE_64},
        {"VPBLENDD wrong pp",{0xc4,0xe3,0x70,0x02,0xc2,0x5a,0,0},6,
            CDISASM_MODE_64},
        {"VPBLENDW wrong pp",{0xc4,0xe3,0x72,0x0e,0xc2,0x5a,0,0},6,
            CDISASM_MODE_64},
        {"VPBLENDW wrong map",{0xc4,0xe2,0x71,0x0e,0xc2,0x5a,0,0},6,
            CDISASM_MODE_64},
        {"VPBLENDD EVEX collision",{0x62,0xf3,0x75,0x08,0x02,0xc2,0x5a,0},
            7,CDISASM_MODE_64}
    };
    size_t index;
    unsigned int family;

    for (family = 0u; family < 2u; ++family) {
        uint8_t complete[] = {
            0xc4,0xe3,0x71,blend_opcodes[family],0xc2,0x5a
        };

        for (index = 1u; index < sizeof(complete); ++index) {
            expect_error("truncated VPBLEND",CDISASM_CPU_X86,
                CDISASM_MODE_64,complete,index,NULL,
                CDISASM_STATUS_TRUNCATED);
        }
        for (index = 0u; index < sizeof(legacy_prefixes); ++index) {
            uint8_t prefixed[] = {
                legacy_prefixes[index],0xc4,0xe3,0x71,
                blend_opcodes[family],0x04,0x24,0x5a
            };

            expect_error("prefixed VPBLEND missing SIB",CDISASM_CPU_X86,
                CDISASM_MODE_64,prefixed,6u,NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed VPBLEND missing imm8",CDISASM_CPU_X86,
                CDISASM_MODE_64,prefixed,7u,NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed complete VPBLEND",CDISASM_CPU_X86,
                CDISASM_MODE_64,prefixed,sizeof(prefixed),NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    expect_error("reserved pp missing SIB",CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x70,0x02,0x04},5u,NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp missing imm8",CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x70,0x0e,0x04,0x24},6u,NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved W missing imm8",CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0xf1,0x02,0xc2},5u,NULL,
        CDISASM_STATUS_TRUNCATED);

    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        const cdisasm_status status = index >= 4u
            ? CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
            : CDISASM_STATUS_INVALID_INSTRUCTION;

        expect_error(invalid[index].label,CDISASM_CPU_X86,
            invalid[index].mode,invalid[index].code,invalid[index].size,
            NULL,status);
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t r_collision[] =
            {0xc4,0x63,0x71,0x02,0xc2,0x5a,0,0,0,0};
        static const uint8_t x_collision[] =
            {0xc4,0xa3,0x71,0x0e,0xc2,0x5a,0,0,0,0};
        static const uint8_t legacy[] =
            {0x66,0x0f,0x3a,0x0e,0xc2,0x5a};
        cdisasm_x86_decode_flags flags16 = all_flags(CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags32 = all_flags(CDISASM_MODE_32);
        cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_16,
            r_collision,sizeof(r_collision),&flags16,&decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_32,
            x_collision,sizeof(x_collision),&flags32,&decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            legacy,sizeof(legacy),&flags64,&decoded_size);
        EXPECT(decoded_size == sizeof(legacy));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PBLENDW);
        EXPECT((instruction.opcode_flags
            & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX)) == 0u);
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
        uint8_t code[10];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4,0xe3,0x71,0x02,0xc2,0x5a,0,0,0,0},6,
            "vpblendd xmm0, xmm1, xmm2, 0x5a",
            "vpblendd $0x5a, %xmm2, %xmm1, %xmm0"},
        {{0xc4,0xe3,0xf5,0x0e,0xc2,0xc3,0,0,0,0},6,
            "vpblendw ymm0, ymm1, ymm2, 0xc3",
            "vpblendw $0xc3, %ymm2, %ymm1, %ymm0"},
        {{0xc4,0xe3,0x71,0x0e,0x40,0x80,0x3c,0,0,0},7,
            "vpblendw xmm0, xmm1, xmmword ptr [rax - 0x80], 0x3c",
            "vpblendw $0x3c, -0x80(%rax), %xmm1, %xmm0"},
        {{0xc4,0xe3,0x75,0x02,0x05,0x78,0x56,0x34,0x12,0x7e},10,
            "vpblendd ymm0, ymm1, ymmword ptr [rip + 0x12345678], 0x7e",
            "vpblendd $0x7e, 0x12345678(%rip), %ymm1, %ymm0"}
    };
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86,CDISASM_MODE_64,
            cases[index].code,cases[index].size,&flags,&decoded_size);
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
            {0xc4,0xe3,0x71,0x02,0xc2,0x5a};
        uint32_t decoded_size;
        cdisasm_instruction valid = decode(
            CDISASM_CPU_X86,CDISASM_MODE_64,
            code,sizeof(code),&flags,&decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(code));
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VPBLENDW;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VPADDD;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(6306);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.operand_count = 3u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
        forged.mask_reg = CDISASM_X86_REG_K1;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
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
        forged.opcode[2].broadcast = CDISASM_X86_BROADCAST_1_TO_8;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[3].size = 2u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[3].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[3].flags = CDISASM_OPERAND_FLAG_SIGNED;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[3].imm = UINT64_C(0x100);
        expect_forged_format_rejected(&forged);
    }
#endif
}

#if USE_EXTRA_OPCODES
static void test_evex_vpblendm_merge_access(void)
{
    /* VPBLENDMD ZMM, k1, ZMM, ZMM.  The same encoding is a useful
     * regression for the generated EVEX path because its MASK_AS_CONTROL
     * form still preserves the old destination when k1 is in merge mode. */
    static const uint8_t reg_code[] = {
        0x62, 0xf2, 0x75, 0x49, 0x64, 0xc2
    };
    static const uint8_t zero_code[] = {
        0x62, 0xf2, 0x75, 0xc9, 0x64, 0xc2
    };
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        reg_code, sizeof(reg_code), &flags, &decoded_size);

    EXPECT(decoded_size == sizeof(reg_code));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPBLENDMD);
    EXPECT(instruction.form_id == UINT16_C(6321));
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.mask_reg == CDISASM_X86_REG_K1);
    EXPECT(instruction.mask_mode == CDISASM_X86_MASK_MERGE);
    EXPECT(instruction.opcode[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);

    instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        zero_code, sizeof(zero_code), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(zero_code));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPBLENDMD);
    EXPECT(instruction.form_id == UINT16_C(6321));
    EXPECT(instruction.mask_reg == CDISASM_X86_REG_K1);
    EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
}
#endif

int main(void)
{
    test_vex_control_partition();
    test_forms_operands_addressing_and_aliases();
    test_runtime_and_profile_gates();
    test_reserved_prefixes_truncation_and_legacy();
    test_formatting_and_schema();
#if USE_EXTRA_OPCODES
    test_evex_vpblendm_merge_access();
#endif

    if (failures != 0) {
        fprintf(stderr,"x86 VPBLEND tests: %d failure(s)\n",failures);
        return 1;
    }
    puts("x86 VPBLEND tests passed");
    return 0;
}
