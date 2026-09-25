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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",          \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VPADDB == UINT16_C(642)
        && CDISASM_X86_NAME_VPADDW == UINT16_C(643)
        && CDISASM_X86_NAME_VPADDD == UINT16_C(644)
        && CDISASM_X86_NAME_VPADDQ == UINT16_C(645)
        && CDISASM_X86_NAME_VPSUBB == UINT16_C(646)
        && CDISASM_X86_NAME_VPSUBW == UINT16_C(647)
        && CDISASM_X86_NAME_VPSUBD == UINT16_C(648)
        && CDISASM_X86_NAME_VPSUBQ == UINT16_C(649),
    "modular packed-add/sub name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "modular packed-add/sub AVX IDs changed");

typedef struct add_sub_family {
    cdisasm_x86_name_id name;
    cdisasm_x86_name_id legacy_name;
    cdisasm_x86_form_id xmm_base;
    cdisasm_x86_form_id ymm_base;
    cdisasm_x86_form_id evex_xmm_memory;
    uint8_t opcode;
    uint8_t evex_w;
    uint8_t needs_bw;
    const char *text;
} add_sub_family;

static const add_sub_family families[] = {
    {CDISASM_X86_NAME_VPADDB,CDISASM_X86_NAME_PADDB,
        6164,6168,6166,0xfc,0,1,"vpaddb"},
    {CDISASM_X86_NAME_VPADDW,CDISASM_X86_NAME_PADDW,
        6234,6238,6236,0xfd,0,1,"vpaddw"},
    {CDISASM_X86_NAME_VPADDD,CDISASM_X86_NAME_PADDD,
        6174,6178,6176,0xfe,0,0,"vpaddd"},
    {CDISASM_X86_NAME_VPADDQ,CDISASM_X86_NAME_PADDQ,
        6184,6188,6186,0xd4,1,0,"vpaddq"},
    {CDISASM_X86_NAME_VPSUBB,CDISASM_X86_NAME_PSUBB,
        8179,8183,8181,0xf8,0,1,"vpsubb"},
    {CDISASM_X86_NAME_VPSUBW,CDISASM_X86_NAME_PSUBW,
        8249,8253,8251,0xf9,0,1,"vpsubw"},
    {CDISASM_X86_NAME_VPSUBD,CDISASM_X86_NAME_PSUBD,
        8189,8193,8191,0xfa,0,0,"vpsubd"},
    {CDISASM_X86_NAME_VPSUBQ,CDISASM_X86_NAME_PSUBQ,
        8199,8203,8201,0xfb,1,0,"vpsubq"}
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

static cdisasm_x86_reg_id vector_reg(unsigned int l, unsigned int index)
{
    return (cdisasm_x86_reg_id)(
        (l != 0u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0)
        + index);
}

static void check_classic(
    const add_sub_family *family,
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
    const cdisasm_x86_form_id form_base = l != 0u
        ? family->ymm_base : family->xmm_base;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == family->name);
    EXPECT(instruction->form_id == (cdisasm_x86_form_id)(
        form_base + (register_form ? 1u : 0u)));
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
#endif

static void check_allocated(
    const add_sub_family *family,
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
    uint64_t form_counts[8][4] = {{0u}};
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

    EXPECT(allocated == UINT64_C(1769472));
    EXPECT(reserved == UINT64_C(5308416));
    for (family_index = 0u; family_index < 8u; ++family_index) {
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
        const uint8_t xmm[] = {
            0xc5,0xe9,families[family_index].opcode,0xcb
        };
        const uint8_t ymm[] = {
            0xc5,0xed,families[family_index].opcode,0xcb
        };
#if USE_EXTRA_OPCODES
        const uint8_t w1[] = {
            0xc4,0xe1,0xe9,families[family_index].opcode,0xcb
        };
        const uint8_t high[] = {
            0xc4,0x01,0x09,families[family_index].opcode,0xfd
        };
        const uint8_t high_memory[] = {
            0xc4,0x21,0x69,families[family_index].opcode,
            0x44,0x58,0x20
        };
        const uint8_t legacy[] = {
            0x66,0x0f,families[family_index].opcode,0xcb
        };
#endif
        const uint8_t bad_pp[] = {
            0xc4,0xe1,0x68,families[family_index].opcode,0xcb
        };
        const uint8_t bad_prefix[] = {
            0x66,0xc4,0xe1,0x69,families[family_index].opcode,0x04,0x24
        };
        const uint8_t truncated_sib[] = {
            0xc4,0xe1,0x68,families[family_index].opcode,0x04
        };

#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags =
            cpu_flags(CDISASM_CPU_X86,CDISASM_MODE_64);
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
        expect_error("AVX2 alone does not admit XMM modular add/sub",
            CDISASM_CPU_X86,CDISASM_MODE_64,xmm,sizeof(xmm),&avx2,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX alone does not admit YMM modular add/sub",
            CDISASM_CPU_X86,CDISASM_MODE_64,ymm,sizeof(ymm),&avx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            legacy,sizeof(legacy),&flags,&decoded_size);
        EXPECT(decoded_size == sizeof(legacy));
        EXPECT(instruction.name_id == families[family_index].legacy_name);
#else
        expect_error("modular add/sub extras off",CDISASM_CPU_X86,
            CDISASM_MODE_64,xmm,sizeof(xmm),NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("modular add/sub YMM extras off",CDISASM_CPU_X86,
            CDISASM_MODE_64,ymm,sizeof(ymm),NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        expect_error("modular add/sub pp reserved",CDISASM_CPU_X86,
            CDISASM_MODE_64,bad_pp,sizeof(bad_pp),NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("modular add/sub prefixed reserved",CDISASM_CPU_X86,
            CDISASM_MODE_64,bad_prefix,sizeof(bad_prefix),NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("modular add/sub payload first",CDISASM_CPU_X86,
            CDISASM_MODE_64,truncated_sib,sizeof(truncated_sib),NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("prefixed modular add/sub payload first",
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
            cdisasm_x86_decode_flags flags = cpu_flags(
                CDISASM_CPU_X86,modes[mode_index]);
            const uint8_t c4_alias[] = {0xc4,0xc1,0x29,0xfc,0xfa};
            const uint8_t c5_alias[] = {0xc5,0xe9,0xfc,0xfa};
            cdisasm_instruction instruction;
            uint32_t decoded_size;

            instruction = decode(CDISASM_CPU_X86,modes[mode_index],
                c4_alias,sizeof(c4_alias),&flags,&decoded_size);
            check_classic(&families[0],&instruction,decoded_size,
                modes[mode_index],0xc1,0,10,0xfa);
            instruction = decode(CDISASM_CPU_X86,modes[mode_index],
                c5_alias,sizeof(c5_alias),&flags,&decoded_size);
            check_classic(&families[0],&instruction,decoded_size,
                modes[mode_index],0xe1,0,2,0xfa);
        }
    }
    {
        static const uint8_t les[] = {0xc4,0x01};
        static const uint8_t lds[] = {0xc5,0x01};
        cdisasm_x86_decode_flags flags =
            cpu_flags(CDISASM_CPU_X86,CDISASM_MODE_32);
        cdisasm_instruction instruction;
        uint32_t decoded_size;

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_32,
            les,sizeof(les),&flags,&decoded_size);
        EXPECT(decoded_size == sizeof(les));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_32,
            lds,sizeof(lds),&flags,&decoded_size);
        EXPECT(decoded_size == sizeof(lds));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LDS);
    }
#endif
}

static void make_apx_encoding(
    const add_sub_family *family,
    int b4,
    int x4,
    uint8_t modrm,
    uint8_t sib,
    uint8_t code[7])
{
    const uint8_t canonical_p1 = family->evex_w != 0u
        ? UINT8_C(0xed) : UINT8_C(0x6d);

    code[0] = UINT8_C(0x62);
    code[1] = (uint8_t)(UINT8_C(0xf1) | (b4 ? UINT8_C(0x08) : 0u));
    code[2] = (uint8_t)(canonical_p1
        & (x4 ? UINT8_C(0xfb) : UINT8_C(0xff)));
    code[3] = UINT8_C(0x08);
    code[4] = family->opcode;
    code[5] = modrm;
    code[6] = sib;
}

static void test_evex_apx_preservation(void)
{
    size_t family_index;

    for (family_index = 0u;
         family_index < sizeof(families) / sizeof(families[0]);
         ++family_index) {
        uint8_t u0_memory[7];
        uint8_t u0_register[7];
        uint8_t u0_missing_sib[7];
        uint8_t b4_register[7];

        make_apx_encoding(&families[family_index],0,1,0x08,0,u0_memory);
        make_apx_encoding(&families[family_index],0,1,0xcb,0,u0_register);
        make_apx_encoding(&families[family_index],0,1,0x04,0,
            u0_missing_sib);
        make_apx_encoding(&families[family_index],1,0,0xcb,0,b4_register);
#if USE_EXTRA_OPCODES
        {
            static const struct address_case {
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
            cdisasm_x86_decode_flags flags =
                cpu_flags(CDISASM_CPU_X86,CDISASM_MODE_64);
            cdisasm_x86_decode_flags no_apx = flags;
            size_t address_index;

            EXPECT(cdisasm_decode_flags_clear_bit(
                &no_apx,CDISASM_X86_DECODE_BIT_APX));
            for (address_index = 0u;
                 address_index < sizeof(addresses) / sizeof(addresses[0]);
                 ++address_index) {
                uint8_t code[7];
                cdisasm_instruction instruction;
                uint32_t decoded_size;

                make_apx_encoding(&families[family_index],
                    addresses[address_index].b4,
                    addresses[address_index].x4,
                    addresses[address_index].modrm,
                    addresses[address_index].sib,code);
                instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                    code,addresses[address_index].size,&flags,&decoded_size);
                EXPECT(decoded_size == addresses[address_index].size);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == families[family_index].name);
                EXPECT(instruction.form_id
                    == families[family_index].evex_xmm_memory);
                EXPECT(instruction.opcode[2].type
                    == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[2].base_reg
                    == addresses[address_index].base);
                EXPECT(instruction.opcode[2].index_reg
                    == addresses[address_index].index);
                EXPECT(instruction.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction,CDISASM_X86_GROUP_APX_F));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction,CDISASM_X86_GROUP_AVX512F));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction,CDISASM_X86_GROUP_AVX512VL));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction,CDISASM_X86_GROUP_AVX512BW)
                    == families[family_index].needs_bw);
#if USE_DISASM_FORMAT
                EXPECT(cdisasm_x86_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_INTEL,NULL,0u) != 0u);
                EXPECT(cdisasm_x86_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_ATT,NULL,0u) != 0u);
#endif
            }
            expect_error("modular add/sub U0 runtime APX gate",
                CDISASM_CPU_X86,CDISASM_MODE_64,
                u0_memory,6u,&no_apx,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error("modular add/sub U0 CPU APX gate",
                CDISASM_CPU_SKYLAKE_SP,CDISASM_MODE_64,
                u0_memory,6u,&flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86,CDISASM_MODE_64,
                    b4_register,6u,&flags,&decoded_size);

                EXPECT(decoded_size == 6u);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == families[family_index].name);
                EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
                    families[family_index].evex_xmm_memory + 1u));
                EXPECT(instruction.opcode[2].type
                    == CDISASM_OPERAND_REGISTER);
                EXPECT(instruction.opcode[2].reg
                    == CDISASM_X86_REG_XMM3);
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction,CDISASM_X86_GROUP_APX_F));
#if USE_DISASM_FORMAT
                EXPECT(cdisasm_x86_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_INTEL,NULL,0u) != 0u);
                EXPECT(cdisasm_x86_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_ATT,NULL,0u) != 0u);
#endif
            }
            expect_error("modular add/sub B4 register runtime APX gate",
                CDISASM_CPU_X86,CDISASM_MODE_64,
                b4_register,6u,&no_apx,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error("modular add/sub B4 register CPU APX gate",
                CDISASM_CPU_SKYLAKE_SP,CDISASM_MODE_64,
                b4_register,6u,&flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#else
        expect_error("modular add/sub U0 extras off",CDISASM_CPU_X86,
            CDISASM_MODE_64,u0_memory,6u,NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("modular add/sub B4 register extras off",
            CDISASM_CPU_X86,CDISASM_MODE_64,b4_register,6u,NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        expect_error("modular add/sub U0 register reserved",
            CDISASM_CPU_X86,CDISASM_MODE_64,
            u0_register,6u,NULL,CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("modular add/sub U0 mode16 reserved",
            CDISASM_CPU_X86,CDISASM_MODE_16,
            u0_memory,6u,NULL,CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("modular add/sub U0 mode32 reserved",
            CDISASM_CPU_X86,CDISASM_MODE_32,
            u0_memory,6u,NULL,CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("modular add/sub U0 payload first",
            CDISASM_CPU_X86,CDISASM_MODE_64,
            u0_missing_sib,6u,NULL,CDISASM_STATUS_TRUNCATED);
        expect_error("modular add/sub B4 register mode16 reserved",
            CDISASM_CPU_X86,CDISASM_MODE_16,
            b4_register,6u,NULL,CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("modular add/sub B4 register mode32 reserved",
            CDISASM_CPU_X86,CDISASM_MODE_32,
            b4_register,6u,NULL,CDISASM_STATUS_INVALID_INSTRUCTION);
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
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86,CDISASM_MODE_64);
    size_t family_index;

    for (family_index = 0u;
         family_index < sizeof(families) / sizeof(families[0]);
         ++family_index) {
        const uint8_t code[] = {
            0xc5,0xe9,families[family_index].opcode,0xcb
        };
        cdisasm_instruction instruction;
        cdisasm_instruction forged;
        uint32_t decoded_size;
        char expected[96];
        char output[96];

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            code,sizeof(code),&flags,&decoded_size);
        EXPECT(decoded_size == sizeof(code));
        (void)snprintf(expected,sizeof(expected),"%s xmm1, xmm2, xmm3",
            families[family_index].text);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,output,sizeof(output))
            == strlen(expected));
        EXPECT(strcmp(output,expected) == 0);
        (void)snprintf(expected,sizeof(expected),"%s %%xmm3, %%xmm2, %%xmm1",
            families[family_index].text);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,output,sizeof(output))
            == strlen(expected));
        EXPECT(strcmp(output,expected) == 0);

        forged = instruction;
        forged.name_id = families[(family_index + 1u) % 8u].name;
        reject_format(&forged);
        forged = instruction;
        forged.form_id = families[(family_index + 1u) % 8u].xmm_base + 1u;
        reject_format(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        reject_format(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        reject_format(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS;
        reject_format(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        reject_format(&forged);
        forged = instruction;
        forged.operand_count = 2u;
        reject_format(&forged);
        forged = instruction;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ;
        reject_format(&forged);
        forged = instruction;
        forged.opcode[1].size = 32u;
        reject_format(&forged);
        forged = instruction;
        forged.opcode[2].reg = CDISASM_X86_REG_XMM8;
        reject_format(&forged);
        forged = instruction;
        forged.x86_group_count = 0u;
        reject_format(&forged);
        forged = instruction;
        forged.mask_reg = CDISASM_X86_REG_K1;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
        reject_format(&forged);
        forged = instruction;
        forged.encoding.prefix_size = 1u;
        forged.encoding.opcode_offset = 1u;
        forged.encoding.modrm_offset = 2u;
        reject_format(&forged);
        forged = instruction;
        forged.encoding.prefix_size += 2u;
        forged.encoding.opcode_offset += 2u;
        forged.encoding.modrm_offset += 2u;
        forged.opcode_size += 2u;
        reject_format(&forged);
        forged = instruction;
        forged.encoding.immediate_count = 1u;
        forged.encoding.immediate_size[0] = 1u;
        forged.encoding.immediate_offset[0] = forged.opcode_size;
        reject_format(&forged);
    }

    {
        static const uint8_t memory[] = {0xc5,0xe9,0xfc,0x00};
        static const uint8_t high_memory[] = {
            0xc4,0x21,0x69,0xfc,0x44,0x58,0x20
        };
        cdisasm_instruction instruction;
        cdisasm_instruction forged;
        uint32_t decoded_size;

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            memory,sizeof(memory),&flags,&decoded_size);
        EXPECT(decoded_size == sizeof(memory));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,NULL,0u) != 0u);
        forged = instruction;
        forged.opcode[2].flags |= CDISASM_OPERAND_FLAG_SIGNED;
        reject_format(&forged);
        forged = instruction;
        forged.opcode_flags |= CDISASM_PREFIX_SEGMENT;
        forged.opcode[2].flags |= CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT;
        forged.opcode[2].segment_reg = CDISASM_X86_REG_FS;
        reject_format(&forged);
        forged = instruction;
        forged.opcode[2].base_reg = CDISASM_X86_REG_R8;
        reject_format(&forged);

        instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
            high_memory,sizeof(high_memory),&flags,&decoded_size);
        EXPECT(decoded_size == sizeof(high_memory));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,NULL,0u) != 0u);
    }

    {
        static const uint8_t form_offsets[3][2] = {
            {0,1},{4,5},{6,7}
        };
        size_t width;

        /* All 48 pre-existing EVEX siblings remain formatter-valid, while
         * every identity is bound to its exact form, shape, provenance,
         * groups, decorators, and byte-layout metadata. */
        for (family_index = 0u;
             family_index < sizeof(families) / sizeof(families[0]);
             ++family_index) {
            for (width = 0u; width < 3u; ++width) {
                size_t register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    uint8_t code[] = {0x62,0xf1,
                        (uint8_t)(families[family_index].evex_w
                            ? 0xed : 0x6d),
                        (uint8_t)(0x08u | (width << 5)),
                        families[family_index].opcode,
                        (uint8_t)(register_form ? 0xcb : 0x00)};
                    cdisasm_instruction instruction;
                    cdisasm_instruction forged;
                    uint32_t decoded_size;

                    instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                        code,sizeof(code),&flags,&decoded_size);
                    EXPECT(decoded_size == sizeof(code));
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id
                        == families[family_index].name);
                    EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
                        families[family_index].evex_xmm_memory
                        + form_offsets[width][register_form]));
                    EXPECT((instruction.opcode_flags
                        & CDISASM_PREFIX_EVEX) != 0u);
                    EXPECT((instruction.opcode_flags
                        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK)
                        == 0u);
                    EXPECT(cdisasm_x86_format(&instruction,
                        CDISASM_FORMAT_SYNTAX_INTEL,NULL,0u) != 0u);
                    EXPECT(cdisasm_x86_format(&instruction,
                        CDISASM_FORMAT_SYNTAX_ATT,NULL,0u) != 0u);

                    forged = instruction;
                    forged.name_id = families[(family_index + 1u) % 8u].name;
                    reject_format(&forged);
                    forged = instruction;
                    forged.form_id ^= UINT16_C(1);
                    reject_format(&forged);
                    forged = instruction;
                    forged.opcode_flags |=
                        CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
                    reject_format(&forged);
                    forged = instruction;
                    forged.opcode_flags |=
                        CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
                    reject_format(&forged);
                    forged = instruction;
                    forged.opcode_flags |=
                        CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS;
                    reject_format(&forged);
                    forged = instruction;
                    forged.opcode_flags |=
                        CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
                    reject_format(&forged);
                    forged = instruction;
                    forged.operand_count = 2u;
                    reject_format(&forged);
                    forged = instruction;
                    forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ;
                    reject_format(&forged);
                    forged = instruction;
                    forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
                    reject_format(&forged);
                    forged = instruction;
                    ++forged.opcode[1].size;
                    reject_format(&forged);
                    forged = instruction;
                    forged.opcode[2].type = CDISASM_OPERAND_IMMEDIATE;
                    reject_format(&forged);
                    forged = instruction;
                    forged.opcode[2].flags |= CDISASM_OPERAND_FLAG_SIGNED;
                    reject_format(&forged);
                    forged = instruction;
                    forged.mask_reg = CDISASM_X86_REG_K2;
                    reject_format(&forged);
                    forged = instruction;
                    forged.mask_mode = CDISASM_X86_MASK_ZERO;
                    reject_format(&forged);
                    forged = instruction;
                    forged.rounding = CDISASM_X86_ROUNDING_RN;
                    forged.sae = CDISASM_X86_SAE_ENABLED;
                    reject_format(&forged);
                    forged = instruction;
                    forged.x86_group_ids[0] = CDISASM_X86_GROUP_I86;
                    reject_format(&forged);
                    forged = instruction;
                    ++forged.encoding.prefix_size;
                    ++forged.encoding.opcode_offset;
                    ++forged.encoding.modrm_offset;
                    ++forged.opcode_size;
                    reject_format(&forged);
                    forged = instruction;
                    forged.encoding.modrm ^= UINT8_C(8);
                    reject_format(&forged);
                    forged = instruction;
                    forged.encoding.immediate_count = 1u;
                    forged.encoding.immediate_size[0] = 1u;
                    forged.encoding.immediate_offset[0] =
                        forged.opcode_size;
                    reject_format(&forged);

                    if (!register_form) {
                        forged = instruction;
                        forged.opcode_flags |= CDISASM_PREFIX_SEGMENT;
                        forged.opcode[2].flags |=
                            CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT;
                        forged.opcode[2].segment_reg =
                            CDISASM_X86_REG_FS;
                        reject_format(&forged);
                        forged = instruction;
                        forged.opcode[2].base_reg =
                            CDISASM_X86_REG_R16;
                        reject_format(&forged);
                        forged = instruction;
                        forged.opcode[2].broadcast =
                            CDISASM_X86_BROADCAST_1_TO_16;
                        forged.opcode[2].size = 4u;
                        if (families[family_index].needs_bw
                            || width != 2u) {
                            reject_format(&forged);
                        }
                    }
                }
            }
        }
    }

    {
        static const uint8_t merge[] = {0x62,0xf1,0x6d,0x0a,0xfc,0xcb};
        static const uint8_t zero[] = {0x62,0xf1,0x6d,0x8a,0xfe,0xcb};
        static const uint8_t broadcast[] = {
            0x62,0xf1,0xe9,0x5a,0xd4,0x08};
        static const uint8_t avx10[] = {0x62,0xf1,0x6d,0x48,0xfc,0xcb};
        static const uint8_t extended[] = {
            0x62,0xa1,0x6d,0x40,0xfe,0xcb};
        cdisasm_x86_decode_flags avx10_flags =
            cpu_flags(CDISASM_CPU_AVX10,CDISASM_MODE_64);
        const uint8_t *const samples[] = {
            merge,zero,broadcast,extended
        };
        size_t sample;

        for (sample = 0u; sample < 4u; ++sample) {
            cdisasm_instruction instruction;
            uint32_t decoded_size;

            instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                samples[sample],6u,&flags,&decoded_size);
            EXPECT(decoded_size == 6u);
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(cdisasm_x86_format(&instruction,
                CDISASM_FORMAT_SYNTAX_INTEL,NULL,0u) != 0u);
            EXPECT(cdisasm_x86_format(&instruction,
                CDISASM_FORMAT_SYNTAX_ATT,NULL,0u) != 0u);
        }
        {
            cdisasm_instruction instruction;
            uint32_t decoded_size;

            instruction = decode(CDISASM_CPU_AVX10,CDISASM_MODE_64,
                avx10,sizeof(avx10),&avx10_flags,&decoded_size);
            EXPECT(decoded_size == sizeof(avx10));
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction,CDISASM_X86_GROUP_AVX10_1));
            EXPECT(cdisasm_x86_format(&instruction,
                CDISASM_FORMAT_SYNTAX_INTEL,NULL,0u) != 0u);
        }
    }
#endif
}

int main(void)
{
    test_control_partition();
    test_forms_gates_and_neighbors();
    test_evex_apx_preservation();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr,"x86 VPADD/VPSUB tests: %d failure(s)\n",failures);
        return 1;
    }
    puts("x86 VPADD/VPSUB tests passed");
    return 0;
}
