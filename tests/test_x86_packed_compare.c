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

_Static_assert(CDISASM_X86_NAME_VPCMPEQB == UINT16_C(654)
        && CDISASM_X86_NAME_VPCMPEQW == UINT16_C(655)
        && CDISASM_X86_NAME_VPCMPEQD == UINT16_C(656)
        && CDISASM_X86_NAME_VPCMPGTB == UINT16_C(657)
        && CDISASM_X86_NAME_VPCMPGTD == UINT16_C(659),
    "packed-compare name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "packed-compare AVX IDs changed");

typedef struct compare_family {
    cdisasm_x86_name_id name;
    cdisasm_x86_name_id legacy_name;
    cdisasm_x86_form_id evex_base;
    cdisasm_x86_form_id vex_base;
    uint8_t opcode;
    uint8_t element_size;
    uint8_t needs_bw;
    const char *text;
} compare_family;

static const compare_family families[] = {
    {CDISASM_X86_NAME_VPCMPEQB,CDISASM_X86_NAME_PCMPEQB,
        6428,6434,0x74,1,1,"vpcmpeqb"},
    {CDISASM_X86_NAME_VPCMPEQD,CDISASM_X86_NAME_PCMPEQD,
        6438,6444,0x76,4,0,"vpcmpeqd"},
    {CDISASM_X86_NAME_VPCMPEQW,CDISASM_X86_NAME_PCMPEQW,
        6458,6464,0x75,2,1,"vpcmpeqw"},
    {CDISASM_X86_NAME_VPCMPGTB,CDISASM_X86_NAME_PCMPGTB,
        6476,6482,0x64,1,1,"vpcmpgtb"},
    {CDISASM_X86_NAME_VPCMPGTD,CDISASM_X86_NAME_PCMPGTD,
        6486,6492,0x66,4,0,"vpcmpgtd"}
};

static const compare_family existing_apx_families[] = {
    {CDISASM_X86_NAME_VPCMPGTW,CDISASM_X86_NAME_PCMPGTW,
        6506,6512,0x65,2,1,"vpcmpgtw"},
    {CDISASM_X86_NAME_VPCMPGTQ,CDISASM_X86_NAME_PCMPGTQ,
        6496,6502,0x37,8,0,"vpcmpgtq"}
};

static const compare_family *apx_family_at(size_t index)
{
    const size_t new_count = sizeof(families) / sizeof(families[0]);

    return index < new_count
        ? &families[index] : &existing_apx_families[index - new_count];
}

static void make_apx_compare(
    const compare_family *family,
    int b4,
    int x4,
    uint8_t modrm,
    uint8_t sib,
    uint8_t code[7])
{
    const int gtq = family->name == CDISASM_X86_NAME_VPCMPGTQ;

    code[0] = UINT8_C(0x62);
    code[1] = (uint8_t)((gtq ? UINT8_C(0xf2) : UINT8_C(0xf1))
        | (b4 ? UINT8_C(0x08) : 0u));
    code[2] = (uint8_t)((gtq ? UINT8_C(0xed) : UINT8_C(0x6d))
        & (x4 ? UINT8_C(0xfb) : UINT8_C(0xff)));
    code[3] = UINT8_C(0x08);
    code[4] = family->opcode;
    code[5] = modrm;
    code[6] = sib;
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

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags cpu_flags(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(cpu_id, mode, &flags)
        == CDISASM_STATUS_OK);
    return flags;
}

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

static cdisasm_x86_decode_flags one_bit(cdisasm_x86_decode_bit_id bit)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags,bit));
    return flags;
}

static cdisasm_x86_reg_id vector_reg(unsigned int l, unsigned int index)
{
    return (cdisasm_x86_reg_id)(
        (l != 0u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0)
        + index);
}

static void check_classic(
    const compare_family *family,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t p0,
    unsigned int l,
    unsigned int vvvv,
    uint8_t modrm)
{
    const int long_mode = mode == CDISASM_MODE_64;
    const int register_form =
        (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
    const unsigned int vector_bytes = 16u << l;
    const unsigned int destination = ((unsigned int)modrm >> 3) & 7u;
    const unsigned int source1 = long_mode ? vvvv : vvvv & 7u;
    const unsigned int source2 = (unsigned int)modrm & 7u;
    const unsigned int extended_destination = destination
        + (long_mode && (p0 & UINT8_C(0x80)) == 0u ? 8u : 0u);
    const unsigned int extended_source2 = source2
        + (long_mode && (p0 & UINT8_C(0x20)) == 0u ? 8u : 0u);

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == family->name);
    EXPECT(instruction->form_id == (cdisasm_x86_form_id)(
        family->vex_base + 2u * l + (register_form ? 1u : 0u)));
    EXPECT(instruction->operand_count == 3u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
        == CDISASM_PREFIX_VEX);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset == 0u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg
        == vector_reg(l, extended_destination));
    EXPECT(instruction->opcode[0].size == vector_bytes);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[0].flags == 0u);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg == vector_reg(l, source1));
    EXPECT(instruction->opcode[1].size == vector_bytes);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].flags == 0u);
    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[2].size == vector_bytes);
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].broadcast == CDISASM_X86_BROADCAST_NONE);
    if (register_form) {
        EXPECT(instruction->opcode[2].reg
            == vector_reg(l, extended_source2));
        EXPECT(instruction->opcode[2].flags == 0u);
    } else {
        EXPECT((instruction->opcode[2].flags
            & (CDISASM_OPERAND_FLAG_IMPLICIT
                | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                | CDISASM_OPERAND_FLAG_SIGNED)) == 0u);
    }
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->branch_target == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2) == (l != 0u));
}

static void check_evex(
    const compare_family *family,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    unsigned int width,
    int memory_form,
    int broadcast)
{
    const unsigned int vector_bytes = 16u << width;
    const cdisasm_x86_group_id width_group = family->needs_bw
        ? (width == 0u ? CDISASM_X86_GROUP_AVX512BW_128
            : width == 1u ? CDISASM_X86_GROUP_AVX512BW_256
                          : CDISASM_X86_GROUP_AVX512BW_512)
        : (width == 0u ? CDISASM_X86_GROUP_AVX512F_128
            : width == 1u ? CDISASM_X86_GROUP_AVX512F_256
                          : CDISASM_X86_GROUP_AVX512F_512);

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == family->name);
    EXPECT(instruction->form_id == (cdisasm_x86_form_id)(
        family->evex_base + 2u * width + (memory_form ? 0u : 1u)));
    EXPECT(instruction->opcode_flags == (CDISASM_PREFIX_EVEX
        | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK));
    EXPECT(instruction->operand_count == 3u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg == CDISASM_X86_REG_K1);
    EXPECT(instruction->opcode[0].size == 8u);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].size == vector_bytes);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].type == (memory_form
        ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].size == (broadcast
        ? family->element_size : vector_bytes));
    EXPECT(instruction->opcode[2].broadcast == (broadcast
        ? (cdisasm_x86_broadcast)(vector_bytes / family->element_size)
        : CDISASM_X86_BROADCAST_NONE));
    EXPECT(instruction->x86_group_count == 1u);
    EXPECT(instruction->x86_group_ids[0] == width_group);
}
#endif

static void check_allocated(
    const compare_family *family,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t p0,
    unsigned int l,
    unsigned int vvvv,
    uint8_t modrm)
{
#if USE_EXTRA_OPCODES
    check_classic(family, instruction, decoded_size,
        mode, p0, l, vvvv, modrm);
#else
    (void)family;
    (void)mode;
    (void)p0;
    (void)l;
    (void)vvvv;
    (void)modrm;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16,CDISASM_MODE_32,CDISASM_MODE_64
    };
    static const uint64_t expected_forms[4] = {
        UINT64_C(82944),UINT64_C(27648),
        UINT64_C(82944),UINT64_C(27648)
    };
    uint64_t form_counts[5][4] = {{0u}};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t family_index;

    for (family_index = 0u;
         family_index < sizeof(families) / sizeof(families[0]);
         ++family_index) {
        size_t mode_index;

        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            const int long_mode = modes[mode_index] == CDISASM_MODE_64;
            const unsigned int p0_count = long_mode ? 8u : 2u;
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags flags =
                cpu_flags(CDISASM_CPU_X86, modes[mode_index]);
#endif
            unsigned int p0_index;

            for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
                const uint8_t p0 = long_mode
                    ? (uint8_t)((p0_index << 5) | 1u)
                    : (uint8_t)(0xc1u | (p0_index << 5));
                unsigned int control;

                for (control = 0u; control <= UINT8_MAX; ++control) {
                    const unsigned int pp = control & 3u;
                    const unsigned int l = (control >> 2) & 1u;
                    const unsigned int vvvv = ((~control) >> 3) & 15u;
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                        const uint8_t code[15] = {
                            0xc4,p0,(uint8_t)control,
                            families[family_index].opcode,(uint8_t)modrm,
                            0x24,0x10,0x20,0x30,0x40,
                            0x50,0x60,0x70,0x80,0x90
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

                        if (pp == 1u) {
                            const unsigned int form_index =
                                2u * l + (register_form ? 1u : 0u);

                            check_allocated(&families[family_index],
                                &instruction,decoded_size,modes[mode_index],
                                p0,l,vvvv,(uint8_t)modrm);
                            ++form_counts[family_index][form_index];
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

        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            const cdisasm_x86_mode mode = modes[mode_index];
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags flags =
                cpu_flags(CDISASM_CPU_X86, mode);
#endif
            unsigned int p1;

            for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                const unsigned int pp = p1 & 3u;
                const unsigned int l = (p1 >> 2) & 1u;
                const unsigned int vvvv = ((~p1) >> 3) & 15u;
                const uint8_t synthetic_p0 = (uint8_t)(
                    ((p1 & UINT8_C(0x80)) != 0u
                        ? UINT8_C(0xe0) : UINT8_C(0x60)) | UINT8_C(1));
                unsigned int modrm;

                if (mode != CDISASM_MODE_64 && p1 < UINT8_C(0xc0)) {
                    continue;
                }
                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const int register_form =
                        (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                    const uint8_t code[14] = {
                        0xc5,(uint8_t)p1,families[family_index].opcode,
                        (uint8_t)modrm,0x24,0x10,0x20,0x30,0x40,
                        0x50,0x60,0x70,0x80,0x90
                    };
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86,mode,code,sizeof(code),
#if USE_EXTRA_OPCODES
                        &flags,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (pp == 1u) {
                        const unsigned int form_index =
                            2u * l + (register_form ? 1u : 0u);

                        check_allocated(&families[family_index],
                            &instruction,decoded_size,mode,
                            synthetic_p0,l,vvvv,(uint8_t)modrm);
                        ++form_counts[family_index][form_index];
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

    EXPECT(allocated == UINT64_C(1105920));
    EXPECT(reserved == UINT64_C(3317760));
    for (family_index = 0u; family_index < 5u; ++family_index) {
        size_t form_index;

        for (form_index = 0u; form_index < 4u; ++form_index) {
            EXPECT(form_counts[family_index][form_index]
                == expected_forms[form_index]);
        }
    }
}

static void test_forms_gates_and_neighbors(void)
{
    size_t family_index;

    for (family_index = 0u;
         family_index < sizeof(families) / sizeof(families[0]);
         ++family_index) {
        const uint8_t xmm[] = {0xc5,0xe9,families[family_index].opcode,0xcb};
        const uint8_t ymm[] = {0xc5,0xed,families[family_index].opcode,0xcb};
#if USE_EXTRA_OPCODES
        const uint8_t w1[] = {0xc4,0xe1,0xe9,
            families[family_index].opcode,0xcb};
        const uint8_t high[] = {0xc4,0x01,0x09,
            families[family_index].opcode,0xfd};
        const uint8_t high_memory[] = {0xc4,0x21,0x69,
            families[family_index].opcode,0x44,0x58,0x20};
        const uint8_t legacy[] = {0x66,0x0f,
            families[family_index].opcode,0xcb};
#endif
        const uint8_t bad_pp[] = {0xc4,0xe1,0x68,
            families[family_index].opcode,0xcb};
        const uint8_t bad_prefix[] = {0x66,0xc4,0xe1,0x69,
            families[family_index].opcode,0x04,0x24};
        const uint8_t truncated_sib[] = {0xc4,0xe1,0x68,
            families[family_index].opcode,0x04};

#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags =
            cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
        cdisasm_x86_decode_flags avx = selected_flags(1,0);
        cdisasm_x86_decode_flags avx2 = selected_flags(0,1);
        cdisasm_instruction instruction;
        uint32_t decoded_size;

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            xmm,sizeof(xmm),&avx,&decoded_size);
        check_classic(&families[family_index],&instruction,decoded_size,
            CDISASM_MODE_64,0xe1,0,2,0xcb);
        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            ymm,sizeof(ymm),&flags,&decoded_size);
        check_classic(&families[family_index],&instruction,decoded_size,
            CDISASM_MODE_64,0xe1,1,2,0xcb);
        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            w1,sizeof(w1),&flags,&decoded_size);
        check_classic(&families[family_index],&instruction,decoded_size,
            CDISASM_MODE_64,0xe1,0,2,0xcb);
        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            high,sizeof(high),&flags,&decoded_size);
        check_classic(&families[family_index],&instruction,decoded_size,
            CDISASM_MODE_64,0x01,0,14,0xfd);
        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            high_memory,sizeof(high_memory),&flags,&decoded_size);
        check_classic(&families[family_index],&instruction,decoded_size,
            CDISASM_MODE_64,0x21,0,2,0x44);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R11);
        EXPECT(instruction.opcode[2].scale == 2u);
        EXPECT(instruction.opcode[2].imm == UINT64_C(0x20));
        expect_error("AVX2 alone does not admit XMM compare",
            CDISASM_CPU_X86,CDISASM_MODE_64,xmm,sizeof(xmm),&avx2,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX alone does not admit YMM compare",
            CDISASM_CPU_X86,CDISASM_MODE_64,ymm,sizeof(ymm),&avx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            legacy,sizeof(legacy),&flags,&decoded_size);
        EXPECT(decoded_size == sizeof(legacy));
        EXPECT(instruction.name_id == families[family_index].legacy_name);
#else
        expect_error("packed compare extras off",CDISASM_CPU_X86,
            CDISASM_MODE_64,xmm,sizeof(xmm),NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("packed compare YMM extras off",CDISASM_CPU_X86,
            CDISASM_MODE_64,ymm,sizeof(ymm),NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        expect_error("packed compare pp reserved",CDISASM_CPU_X86,
            CDISASM_MODE_64,bad_pp,sizeof(bad_pp),NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("packed compare prefixed reserved",CDISASM_CPU_X86,
            CDISASM_MODE_64,bad_prefix,sizeof(bad_prefix),NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("packed compare payload first",CDISASM_CPU_X86,
            CDISASM_MODE_64,truncated_sib,sizeof(truncated_sib),NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("prefixed packed compare payload first",
            CDISASM_CPU_X86,CDISASM_MODE_64,bad_prefix,
            sizeof(bad_prefix) - 1u,NULL,CDISASM_STATUS_TRUNCATED);
    }

#if USE_EXTRA_OPCODES
    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16,CDISASM_MODE_32
        };
        size_t mode_index;

        for (mode_index = 0u; mode_index < 2u; ++mode_index) {
            cdisasm_x86_decode_flags flags =
                cpu_flags(CDISASM_CPU_X86,modes[mode_index]);

            for (family_index = 0u; family_index < 5u; ++family_index) {
                const uint8_t alias[] = {0xc4,0xc1,0x29,
                    families[family_index].opcode,0xfa};
                cdisasm_instruction instruction;
                uint32_t decoded_size;

                instruction = decode(CDISASM_CPU_X86,modes[mode_index],
                    alias,sizeof(alias),&flags,&decoded_size);
                check_classic(&families[family_index],&instruction,
                    decoded_size,modes[mode_index],0xc1,0,10,0xfa);
            }
        }
    }
#endif
}

static void test_evex_siblings(void)
{
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
    size_t family_index;

    for (family_index = 0u; family_index < 5u; ++family_index) {
        unsigned int width;

        for (width = 0u; width < 3u; ++width) {
            unsigned int memory_form;

            for (memory_form = 0u; memory_form < 2u; ++memory_form) {
                const uint8_t code[] = {
                    0x62,0xf1,0x6d,(uint8_t)(0x08u | (width << 5)),
                    families[family_index].opcode,
                    (uint8_t)(memory_form != 0u ? 0x08u : 0xcbu)
                };
                cdisasm_instruction instruction;
                uint32_t decoded_size;

                instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                    code,sizeof(code),&flags,&decoded_size);
                check_evex(&families[family_index],&instruction,decoded_size,
                    width,memory_form != 0u,0);
            }
        }

        {
            const uint8_t w1[] = {0x62,0xf1,0xed,0x08,
                families[family_index].opcode,0xcb};
            const uint8_t z[] = {0x62,0xf1,0x6d,0x89,
                families[family_index].opcode,0xcb};
            const uint8_t ll3[] = {0x62,0xf1,0x6d,0x68,
                families[family_index].opcode,0xcb};
            const uint8_t bad_b[] = {0x62,0xf1,0x6d,0x18,
                families[family_index].opcode,
                (uint8_t)(families[family_index].needs_bw ? 0x04 : 0xcb)};
            cdisasm_instruction instruction;
            uint32_t decoded_size;

            if (families[family_index].needs_bw) {
                instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                    w1,sizeof(w1),&flags,&decoded_size);
                check_evex(&families[family_index],&instruction,decoded_size,
                    0,0,0);
            } else {
                const uint8_t w1_missing_sib[] = {0x62,0xf1,0xed,0x08,
                    families[family_index].opcode,0x04};

                expect_error("EVEX dword W1 reserved",CDISASM_CPU_X86,
                    CDISASM_MODE_64,w1,sizeof(w1),&flags,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
                expect_error("EVEX dword W1 payload first",CDISASM_CPU_X86,
                    CDISASM_MODE_64,w1_missing_sib,sizeof(w1_missing_sib),
                    &flags,CDISASM_STATUS_TRUNCATED);
            }
            expect_error("EVEX packed compare z reserved",CDISASM_CPU_X86,
                CDISASM_MODE_64,z,sizeof(z),&flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("EVEX packed compare LL3 reserved",CDISASM_CPU_X86,
                CDISASM_MODE_64,ll3,sizeof(ll3),&flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("EVEX packed compare b reserved",CDISASM_CPU_X86,
                CDISASM_MODE_64,bad_b,sizeof(bad_b),&flags,
                families[family_index].needs_bw
                    ? CDISASM_STATUS_TRUNCATED
                    : CDISASM_STATUS_INVALID_INSTRUCTION);
            if (families[family_index].needs_bw) {
                const uint8_t complete_b[] = {0x62,0xf1,0x6d,0x18,
                    families[family_index].opcode,0x04,0x24};

                expect_error("EVEX byte/word b complete",CDISASM_CPU_X86,
                    CDISASM_MODE_64,complete_b,sizeof(complete_b),&flags,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            } else {
                const uint8_t broadcast[] = {0x62,0xf1,0x6d,0x58,
                    families[family_index].opcode,0x08};

                instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                    broadcast,sizeof(broadcast),&flags,&decoded_size);
                check_evex(&families[family_index],&instruction,decoded_size,
                    2,1,1);
            }
        }
    }

    {
        static const uint8_t opcodes[6] = {0x64,0x65,0x66,0x74,0x75,0x76};
        static const uint8_t selectors[3] = {0x00,0x02,0x03};
        size_t opcode_index;

        for (opcode_index = 0u; opcode_index < 6u; ++opcode_index) {
            size_t selector_index;

            for (selector_index = 0u; selector_index < 3u;
                 ++selector_index) {
                const uint8_t reg[] = {0x62,0xf1,
                    (uint8_t)(0x6cu | selectors[selector_index]),0x08,
                    opcodes[opcode_index],0xcb};
                const uint8_t missing_sib[] = {0x62,0xf1,
                    (uint8_t)(0x6cu | selectors[selector_index]),0x08,
                    opcodes[opcode_index],0x04};
                const uint8_t complete_sib[] = {0x62,0xf1,
                    (uint8_t)(0x6cu | selectors[selector_index]),0x08,
                    opcodes[opcode_index],0x04,0x24};

                expect_error("EVEX packed compare pp reserved",
                    CDISASM_CPU_X86,CDISASM_MODE_64,reg,sizeof(reg),&flags,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
                expect_error("EVEX pp payload first",CDISASM_CPU_X86,
                    CDISASM_MODE_64,missing_sib,sizeof(missing_sib),&flags,
                    CDISASM_STATUS_TRUNCATED);
                expect_error("EVEX pp complete memory",CDISASM_CPU_X86,
                    CDISASM_MODE_64,complete_sib,sizeof(complete_sib),&flags,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }
    }

    {
        static const uint8_t bw_xmm[] = {0x62,0xf1,0x6d,0x08,0x74,0xcb};
        static const uint8_t bw_ymm[] = {0x62,0xf1,0x6d,0x28,0x74,0xcb};
        static const uint8_t d_xmm[] = {0x62,0xf1,0x6d,0x08,0x76,0xcb};
        static const uint8_t d_zmm[] = {0x62,0xf1,0x6d,0x48,0x76,0xcb};
        cdisasm_x86_decode_flags bw128 =
            one_bit(CDISASM_X86_DECODE_BIT_AVX512BW_128);
        cdisasm_x86_decode_flags bw256 =
            one_bit(CDISASM_X86_DECODE_BIT_AVX512BW_256);
        cdisasm_x86_decode_flags f128 =
            one_bit(CDISASM_X86_DECODE_BIT_AVX512F_128);
        cdisasm_x86_decode_flags avx2 = selected_flags(1,1);
        cdisasm_x86_decode_flags none = selected_flags(0,0);
        cdisasm_x86_decode_flags skx =
            cpu_flags(CDISASM_CPU_SKYLAKE_SP,CDISASM_MODE_64);
        cdisasm_x86_decode_flags haswell =
            cpu_flags(CDISASM_CPU_HASWELL,CDISASM_MODE_64);
        cdisasm_x86_decode_flags knights_mill =
            cpu_flags(CDISASM_CPU_KNIGHTS_MILL,CDISASM_MODE_64);
        cdisasm_instruction instruction;
        uint32_t decoded_size;

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            bw_xmm,sizeof(bw_xmm),&bw128,&decoded_size);
        check_evex(&families[0],&instruction,decoded_size,0,0,0);
        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            d_xmm,sizeof(d_xmm),&f128,&decoded_size);
        check_evex(&families[1],&instruction,decoded_size,0,0,0);
        expect_error("AVX2 is not AVX512BW",CDISASM_CPU_X86,
            CDISASM_MODE_64,bw_xmm,sizeof(bw_xmm),&avx2,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX512F is not AVX512BW",CDISASM_CPU_X86,
            CDISASM_MODE_64,bw_xmm,sizeof(bw_xmm),&f128,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX512BW is not AVX512F",CDISASM_CPU_X86,
            CDISASM_MODE_64,d_xmm,sizeof(d_xmm),&bw128,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_SKYLAKE_SP,CDISASM_MODE_64,
            bw_ymm,sizeof(bw_ymm),&skx,&decoded_size);
        check_evex(&families[0],&instruction,decoded_size,1,0,0);
        expect_error("SKX profile still needs runtime selector",
            CDISASM_CPU_SKYLAKE_SP,CDISASM_MODE_64,bw_ymm,sizeof(bw_ymm),
            &none,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("Haswell lacks AVX512BW/VL",CDISASM_CPU_HASWELL,
            CDISASM_MODE_64,bw_ymm,sizeof(bw_ymm),&haswell,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("Haswell rejects selected AVX512BW/VL",
            CDISASM_CPU_HASWELL,CDISASM_MODE_64,bw_ymm,sizeof(bw_ymm),
            &bw256,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_KNIGHTS_MILL,CDISASM_MODE_64,
            d_zmm,sizeof(d_zmm),&knights_mill,&decoded_size);
        check_evex(&families[1],&instruction,decoded_size,2,0,0);
        expect_error("Knights Mill lacks AVX512VL",CDISASM_CPU_KNIGHTS_MILL,
            CDISASM_MODE_64,d_xmm,sizeof(d_xmm),&knights_mill,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif
}

static void test_evex_apx_memory(void)
{
#if USE_EXTRA_OPCODES
    static const struct apx_address_case {
        uint8_t b4;
        uint8_t x4;
        uint8_t modrm;
        uint8_t sib;
        uint8_t size;
        cdisasm_x86_reg_id base;
        cdisasm_x86_reg_id index;
    } addresses[] = {
        {0,1,0x08,0x00,6,CDISASM_X86_REG_RAX,
            CDISASM_X86_REG_NONE},
        {0,1,0x0c,0x08,7,CDISASM_X86_REG_RAX,
            CDISASM_X86_REG_R17},
        {1,0,0x08,0x00,6,CDISASM_X86_REG_R16,
            CDISASM_X86_REG_NONE},
        {1,1,0x0c,0x08,7,CDISASM_X86_REG_R16,
            CDISASM_X86_REG_R17}
    };
#endif
    const size_t apx_family_count =
        sizeof(families) / sizeof(families[0])
        + sizeof(existing_apx_families)
            / sizeof(existing_apx_families[0]);
    size_t family_index;

#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86,CDISASM_MODE_64);
    cdisasm_x86_decode_flags no_apx = flags;
    cdisasm_x86_decode_flags dmr = cpu_flags(
        CDISASM_CPU_DIAMOND_RAPIDS,CDISASM_MODE_64);

    EXPECT(cdisasm_decode_flags_clear_bit(
        &no_apx,CDISASM_X86_DECODE_BIT_APX));
    for (family_index = 0u; family_index < apx_family_count;
         ++family_index) {
        const compare_family *family = apx_family_at(family_index);
        size_t address_index;

        for (address_index = 0u;
             address_index < sizeof(addresses) / sizeof(addresses[0]);
             ++address_index) {
            uint8_t code[7];
            cdisasm_instruction instruction;
            uint32_t decoded_size;

            make_apx_compare(family,addresses[address_index].b4,
                addresses[address_index].x4,
                addresses[address_index].modrm,
                addresses[address_index].sib,code);
            instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                code,addresses[address_index].size,&flags,&decoded_size);
            EXPECT(decoded_size == addresses[address_index].size);
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id == family->name);
            EXPECT(instruction.form_id == family->evex_base);
            EXPECT(instruction.opcode_flags == (CDISASM_PREFIX_EVEX
                | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK));
            EXPECT(instruction.operand_count == 3u);
            EXPECT(instruction.opcode[0].type
                == CDISASM_OPERAND_REGISTER);
            EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_K1);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.opcode[1].type
                == CDISASM_OPERAND_REGISTER);
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM2);
            EXPECT(instruction.opcode[1].size == 16u);
            EXPECT(instruction.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
            EXPECT(instruction.opcode[2].base_reg
                == addresses[address_index].base);
            EXPECT(instruction.opcode[2].index_reg
                == addresses[address_index].index);
            EXPECT(instruction.opcode[2].size == 16u);
            EXPECT(instruction.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.opcode[2].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction,CDISASM_X86_GROUP_APX_F));
            EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                family->needs_bw
                    ? CDISASM_X86_GROUP_AVX512BW_128
                    : CDISASM_X86_GROUP_AVX512F_128));
            EXPECT(instruction.x86_group_count == 2u);
            EXPECT(instruction.encoding.prefix_size == 4u);
            EXPECT(instruction.encoding.opcode_offset == 4u);
            EXPECT(instruction.encoding.modrm_offset == 5u);
#if USE_DISASM_FORMAT
            EXPECT(cdisasm_x86_format(&instruction,
                CDISASM_FORMAT_SYNTAX_INTEL,NULL,0u) != 0u);
            EXPECT(cdisasm_x86_format(&instruction,
                CDISASM_FORMAT_SYNTAX_ATT,NULL,0u) != 0u);
            if (family_index == 0u && address_index == 3u) {
                static const char intel[] =
                    "vpcmpeqb k1, xmm2, xmmword ptr [r16 + r17]";
                static const char att[] =
                    "vpcmpeqb (%r16,%r17), %xmm2, %k1";
                char output[96];

                EXPECT(cdisasm_x86_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_INTEL,output,sizeof(output))
                    == strlen(intel));
                EXPECT(strcmp(output,intel) == 0);
                EXPECT(cdisasm_x86_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_ATT,output,sizeof(output))
                    == strlen(att));
                EXPECT(strcmp(output,att) == 0);
            }
#endif
        }
        {
            uint8_t u0_memory[7];
            cdisasm_instruction instruction;
            uint32_t decoded_size;

            make_apx_compare(family,0,1,0x08,0,u0_memory);
            expect_error("packed compare U0 runtime APX gate",
                CDISASM_CPU_X86,CDISASM_MODE_64,u0_memory,6u,&no_apx,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error("packed compare U0 CPU APX gate",
            CDISASM_CPU_SKYLAKE_SP,CDISASM_MODE_64,
                u0_memory,6u,&flags,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS,
                CDISASM_MODE_64,u0_memory,6u,&dmr,&decoded_size);
            EXPECT(decoded_size == 6u);
            EXPECT(instruction.name_id == family->name);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction,CDISASM_X86_GROUP_APX_F));
        }
    }
#endif

    for (family_index = 0u; family_index < apx_family_count;
         ++family_index) {
        const compare_family *family = apx_family_at(family_index);
        uint8_t u0_memory[7];
        uint8_t u0_register[7];
        uint8_t u0_missing_sib[7];

        make_apx_compare(family,0,1,0x08,0,u0_memory);
        make_apx_compare(family,0,1,0xcb,0,u0_register);
        make_apx_compare(family,0,1,0x04,0,u0_missing_sib);
#if !USE_EXTRA_OPCODES
        expect_error("packed compare U0 extras off",CDISASM_CPU_X86,
            CDISASM_MODE_64,u0_memory,6u,NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        expect_error("packed compare U0 register reserved",CDISASM_CPU_X86,
            CDISASM_MODE_64,u0_register,6u,NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("packed compare U0 mode16 reserved",CDISASM_CPU_X86,
            CDISASM_MODE_16,u0_memory,6u,NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("packed compare U0 mode32 reserved",CDISASM_CPU_X86,
            CDISASM_MODE_32,u0_memory,6u,NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("packed compare U0 payload first",CDISASM_CPU_X86,
            CDISASM_MODE_64,u0_missing_sib,6u,NULL,
            CDISASM_STATUS_TRUNCATED);
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void reject_format(const cdisasm_instruction *instruction)
{
    char output[96] = {'x'};

    EXPECT(cdisasm_x86_format(instruction,CDISASM_FORMAT_SYNTAX_INTEL,
        output,sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
}
#endif

static void test_formatting_and_schema(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const char *const classic_intel[5] = {
        "vpcmpeqb xmm1, xmm2, xmm3",
        "vpcmpeqd xmm1, xmm2, xmm3",
        "vpcmpeqw xmm1, xmm2, xmm3",
        "vpcmpgtb xmm1, xmm2, xmm3",
        "vpcmpgtd xmm1, xmm2, xmm3"
    };
    static const char *const classic_att[5] = {
        "vpcmpeqb %xmm3, %xmm2, %xmm1",
        "vpcmpeqd %xmm3, %xmm2, %xmm1",
        "vpcmpeqw %xmm3, %xmm2, %xmm1",
        "vpcmpgtb %xmm3, %xmm2, %xmm1",
        "vpcmpgtd %xmm3, %xmm2, %xmm1"
    };
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
    size_t family_index;

    for (family_index = 0u; family_index < 5u; ++family_index) {
        const uint8_t classic[] = {0xc5,0xe9,
            families[family_index].opcode,0xcb};
        const uint8_t evex[] = {0x62,0xf1,0x6d,0x08,
            families[family_index].opcode,0xcb};
        cdisasm_instruction instruction;
        cdisasm_instruction forged;
        uint32_t decoded_size;
        char output[160];
        char expected[96];

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            classic,sizeof(classic),&flags,&decoded_size);
        EXPECT(decoded_size == sizeof(classic));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,output,sizeof(output))
            == strlen(classic_intel[family_index]));
        EXPECT(strcmp(output,classic_intel[family_index]) == 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,output,sizeof(output))
            == strlen(classic_att[family_index]));
        EXPECT(strcmp(output,classic_att[family_index]) == 0);

        forged = instruction;
        forged.name_id = families[(family_index + 1u) % 5u].name;
        reject_format(&forged);
        forged = instruction;
        forged.form_id = families[(family_index + 1u) % 5u].vex_base + 1u;
        reject_format(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS;
        reject_format(&forged);
        forged = instruction;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        reject_format(&forged);
        forged = instruction;
        forged.encoding.modrm ^= UINT8_C(8);
        reject_format(&forged);

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            evex,sizeof(evex),&flags,&decoded_size);
        EXPECT(decoded_size == sizeof(evex));
        (void)snprintf(expected,sizeof(expected),"%s k1, xmm2, xmm3",
            families[family_index].text);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,output,sizeof(output))
            == strlen(expected));
        EXPECT(strcmp(output,expected) == 0);
        (void)snprintf(expected,sizeof(expected),"%s %%xmm3, %%xmm2, %%k1",
            families[family_index].text);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,output,sizeof(output))
            == strlen(expected));
        EXPECT(strcmp(output,expected) == 0);
        forged = instruction;
        forged.name_id = families[(family_index + 1u) % 5u].name;
        reject_format(&forged);
        forged = instruction;
        forged.form_id = families[(family_index + 1u) % 5u].evex_base + 1u;
        reject_format(&forged);
        forged = instruction;
        forged.opcode_flags &=
            ~CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        reject_format(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        reject_format(&forged);
        forged = instruction;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ;
        reject_format(&forged);
        forged = instruction;
        forged.mask_reg = CDISASM_X86_REG_K2;
        forged.mask_mode = CDISASM_X86_MASK_ZERO;
        reject_format(&forged);
        forged = instruction;
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_AVX;
        reject_format(&forged);
    }

    {
        static const uint8_t bw_memory[] = {
            0x64,0x62,0xf1,0x6d,0x08,0x74,0x00};
        static const uint8_t dword_broadcast[] = {
            0x62,0xf1,0x6d,0x5a,0x76,0x08};
        cdisasm_instruction instruction;
        cdisasm_instruction forged;
        uint32_t decoded_size;

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            bw_memory,sizeof(bw_memory),&flags,&decoded_size);
        EXPECT(decoded_size == sizeof(bw_memory));
        forged = instruction;
        forged.opcode[2].flags |= CDISASM_OPERAND_FLAG_SIGNED;
        reject_format(&forged);
        forged = instruction;
        forged.opcode[2].broadcast = CDISASM_X86_BROADCAST_1_TO_16;
        forged.opcode[2].size = 1u;
        reject_format(&forged);
        forged = instruction;
        forged.opcode[2].segment_reg = CDISASM_X86_REG_NONE;
        reject_format(&forged);

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            dword_broadcast,sizeof(dword_broadcast),&flags,&decoded_size);
        EXPECT(decoded_size == sizeof(dword_broadcast));
        EXPECT(instruction.form_id == UINT16_C(6442));
        EXPECT(instruction.opcode[2].size == 4u);
        EXPECT(instruction.opcode[2].broadcast
            == CDISASM_X86_BROADCAST_1_TO_16);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,NULL,0u) != 0u);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,NULL,0u) != 0u);
        forged = instruction;
        forged.opcode[2].size = 16u;
        reject_format(&forged);
        forged = instruction;
        forged.opcode[2].broadcast = CDISASM_X86_BROADCAST_NONE;
        reject_format(&forged);
        forged = instruction;
        forged.encoding.prefix_size = 3u;
        forged.encoding.opcode_offset = 3u;
        forged.encoding.modrm_offset = 4u;
        reject_format(&forged);
    }
#endif
}

int main(void)
{
    test_control_partition();
    test_forms_gates_and_neighbors();
    test_evex_siblings();
    test_evex_apx_memory();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr,"x86 packed-compare tests: %d failure(s)\n",failures);
        return 1;
    }
    puts("x86 packed-compare tests passed");
    return 0;
}
