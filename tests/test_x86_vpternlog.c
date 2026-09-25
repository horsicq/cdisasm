#include "cdisasm/cdisasm.h"

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

_Static_assert(CDISASM_X86_NAME_VPTERNLOGD == UINT16_C(1915)
        && CDISASM_X86_NAME_VPTERNLOGQ == UINT16_C(1916),
    "VPTERNLOG name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX512F == UINT16_C(62)
        && CDISASM_X86_GROUP_AVX512VL == UINT16_C(68)
        && CDISASM_X86_GROUP_APX_F == UINT16_C(91)
        && CDISASM_X86_GROUP_AVX512F_128 == UINT16_C(180)
        && CDISASM_X86_GROUP_AVX512F_256 == UINT16_C(182)
        && CDISASM_X86_GROUP_AVX512F_512 == UINT16_C(183),
    "VPTERNLOG ISA-set IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512F_128 == UINT32_C(128)
        && CDISASM_X86_DECODE_BIT_AVX512F_256 == UINT32_C(130)
        && CDISASM_X86_DECODE_BIT_AVX512F_512 == UINT32_C(131),
    "VPTERNLOG runtime-bit IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VPTERNLOG profile sweeps");

static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static cdisasm_instruction decode_exact(
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

#if USE_EXTRA_OPCODES
static cdisasm_instruction decode_family(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    cdisasm_x86_decode_option word0,
    cdisasm_x86_decode_bit_id exact_bit,
    uint32_t *decoded_size)
{
    cdisasm_decode_flags flags =
        CDISASM_DECODE_FLAGS_INITIALIZER(word0);
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(cdisasm_decode_flags_set_bit(&flags, exact_bit));
    *decoded_size = cdisasm_decode(
        cpu_id, mode, code, size, UINT64_C(0x1000),
        word0 == 0u ? NULL : &flags, &instruction);
    return instruction;
}
#endif

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
    cdisasm_instruction instruction = decode_exact(
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

static size_t make_encoding(
    unsigned int w,
    unsigned int ll,
    int register_form,
    int broadcast,
    unsigned int aaa,
    int zero,
    uint8_t code[8])
{
    code[0] = UINT8_C(0x62);
    code[1] = UINT8_C(0xf3);
    code[2] = (uint8_t)(UINT8_C(0x65) | (w << 7));
    code[3] = (uint8_t)(UINT8_C(0x08) | (ll << 5) | aaa
        | (broadcast ? UINT8_C(0x10) : 0u)
        | (zero ? UINT8_C(0x80) : 0u));
    code[4] = UINT8_C(0x25);
    code[5] = register_form ? UINT8_C(0xcc) : UINT8_C(0x48);
    if (register_form) {
        code[6] = UINT8_C(0x5a);
        return 7u;
    }
    code[6] = UINT8_C(0xff);
    code[7] = UINT8_C(0x5a);
    return 8u;
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
        CDISASM_X86_GROUP_AVX512F_128,
        CDISASM_X86_GROUP_AVX512F_256,
        CDISASM_X86_GROUP_AVX512F_512
    };

    return groups[ll];
}

static void check_vpternlog(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    unsigned int w,
    unsigned int ll,
    int register_form,
    int broadcast,
    unsigned int aaa,
    int zero,
    int apx)
{
    const unsigned int vector_bytes = 16u << ll;
    const unsigned int element_bytes = w != 0u ? 8u : 4u;
    const cdisasm_x86_form_id form_id = (cdisasm_x86_form_id)(
        (w != 0u ? UINT16_C(8265) : UINT16_C(8259))
        + 2u * ll + (register_form ? 1u : 0u));

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (w != 0u
        ? CDISASM_X86_NAME_VPTERNLOGQ : CDISASM_X86_NAME_VPTERNLOGD));
    EXPECT(instruction->form_id == form_id);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
    EXPECT(instruction->operand_count == 4u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].size == vector_bytes);
    EXPECT(instruction->opcode[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].size == vector_bytes);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[2].size == (broadcast
        ? element_bytes : vector_bytes));
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].broadcast == (broadcast
        ? (cdisasm_x86_broadcast)(vector_bytes / element_bytes)
        : CDISASM_X86_BROADCAST_NONE));
    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[3].size == 1u);
    EXPECT(instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[3].imm == UINT64_C(0x5a));
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
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, width_group(ll)));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == apx);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512F)
        != cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX10_1));
}
#endif

static void test_exact_forms_operands_masks_broadcast_and_disp8(void)
{
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
    uint64_t form_counts[12] = {0};
    unsigned int w;

    for (w = 0u; w <= 1u; ++w) {
        unsigned int ll;

        for (ll = 0u; ll < 3u; ++ll) {
            int register_form;

            for (register_form = 0; register_form <= 1; ++register_form) {
                int broadcast;

                for (broadcast = 0;
                     broadcast <= (!register_form ? 1 : 0); ++broadcast) {
                    unsigned int mask_kind;

                    for (mask_kind = 0u; mask_kind < 3u; ++mask_kind) {
                        const unsigned int aaa = mask_kind == 0u ? 0u : 2u;
                        const int zero = mask_kind == 2u;
                        uint8_t code[8];
                        size_t size = make_encoding(w,ll,register_form,
                            broadcast,aaa,zero,code);
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode_exact(
                            CDISASM_CPU_X86,CDISASM_MODE_64,code,size,
#if USE_EXTRA_OPCODES
                            &flags,
#else
                            NULL,
#endif
                            &decoded_size);

#if USE_EXTRA_OPCODES
                        const unsigned int vector_bytes = 16u << ll;
                        const unsigned int element_bytes = w != 0u ? 8u : 4u;
                        const unsigned int form_index = 6u * w + 2u * ll
                            + (register_form ? 1u : 0u);

                        EXPECT(decoded_size == size);
                        check_vpternlog(&instruction,decoded_size,w,ll,
                            register_form,broadcast,aaa,zero,0);
                        EXPECT(instruction.opcode[0].reg
                            == (cdisasm_x86_reg_id)(
                                (ll == 0u ? CDISASM_X86_REG_XMM0
                                 : ll == 1u ? CDISASM_X86_REG_YMM0
                                            : CDISASM_X86_REG_ZMM0) + 1u));
                        EXPECT(instruction.opcode[1].reg
                            == (cdisasm_x86_reg_id)(
                                (ll == 0u ? CDISASM_X86_REG_XMM0
                                 : ll == 1u ? CDISASM_X86_REG_YMM0
                                            : CDISASM_X86_REG_ZMM0) + 3u));
                        if (register_form) {
                            EXPECT(instruction.opcode[2].reg
                                == (cdisasm_x86_reg_id)(
                                    (ll == 0u ? CDISASM_X86_REG_XMM0
                                     : ll == 1u ? CDISASM_X86_REG_YMM0
                                                : CDISASM_X86_REG_ZMM0)
                                    + 4u));
                        } else {
                            EXPECT(instruction.opcode[2].base_reg
                                == CDISASM_X86_REG_RAX);
                            EXPECT(instruction.opcode[2].imm
                                == (uint64_t)-(int64_t)(broadcast
                                    ? element_bytes : vector_bytes));
                        }
                        ++form_counts[form_index];
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    }
                }
            }
        }
    }
#if USE_EXTRA_OPCODES
    for (w = 0u; w < 12u; ++w) {
        EXPECT(form_counts[w] == (w & 1u ? UINT64_C(3) : UINT64_C(6)));
    }
#else
    (void)form_counts;
#endif
}

static void test_owned_p1_p2_and_map_spaces(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_32,CDISASM_MODE_64
    };
    size_t mode_index;

    for (mode_index = 0u; mode_index < 2u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        unsigned int w;

        for (w = 0u; w <= 1u; ++w) {
            unsigned int accepted = 0u;
            unsigned int rejected = 0u;
            unsigned int p2;

            for (p2 = 0u; p2 <= UINT8_MAX; ++p2) {
                unsigned int rep;

                for (rep = 0u; rep < 2u; ++rep) {
                    const int register_form = rep != 0u;
                    const unsigned int ll = (p2 >> 5) & 3u;
                    const unsigned int aaa = p2 & 7u;
                    const int valid = ll < 3u
                        && (!register_form
                            || (p2 & UINT8_C(0x10)) == 0u)
                        && ((p2 & UINT8_C(0x80)) == 0u || aaa != 0u)
                        && (long_mode || (p2 & UINT8_C(0x08)) != 0u);
                    const uint8_t code[] = {
                        0x62,0xf3,(uint8_t)(0x65u | (w << 7)),
                        (uint8_t)p2,0x25,
                        (uint8_t)(register_form ? 0xcc : 0x00),0x5a
                    };
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode_exact(
                        CDISASM_CPU_X86,modes[mode_index],code,sizeof(code),
#if USE_EXTRA_OPCODES
                        &flags,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (valid) {
#if USE_EXTRA_OPCODES
                        EXPECT(decoded_size == sizeof(code));
                        check_vpternlog(&instruction,decoded_size,w,ll,
                            register_form,
                            !register_form
                                && (p2 & UINT8_C(0x10)) != 0u,
                            aaa,(p2 & UINT8_C(0x80)) != 0u,0);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++accepted;
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++rejected;
                    }
                }
            }
            EXPECT(accepted == (long_mode ? 270u : 135u));
            EXPECT(rejected == (long_mode ? 242u : 377u));
        }

        {
            unsigned int accepted = 0u;
            unsigned int p1;

            for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                const int valid = (p1 & UINT8_C(3)) == UINT8_C(1)
                    && (p1 & UINT8_C(4)) != 0u;
                const uint8_t code[] = {
                    0x62,0xf3,(uint8_t)p1,0x08,0x25,0xcc,0x5a
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode_exact(
                    CDISASM_CPU_X86,modes[mode_index],code,sizeof(code),
#if USE_EXTRA_OPCODES
                    &flags,
#else
                    NULL,
#endif
                    &decoded_size);

                if (valid) {
#if USE_EXTRA_OPCODES
                    EXPECT(decoded_size == sizeof(code));
                    EXPECT(instruction.name_id == ((p1 & UINT8_C(0x80))
                        != 0u ? CDISASM_X86_NAME_VPTERNLOGQ
                              : CDISASM_X86_NAME_VPTERNLOGD));
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    ++accepted;
                } else {
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_INVALID_INSTRUCTION));
                }
            }
            EXPECT(accepted == 32u);
        }
    }

    {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
        unsigned int p0;
        unsigned int accepted = 0u;

        for (p0 = 3u; p0 <= UINT8_MAX; p0 += 8u) {
            const uint8_t code[] = {
                0x62,(uint8_t)p0,0x65,0x08,0x25,0xcc,0x5a
            };
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode_exact(
                CDISASM_CPU_X86,CDISASM_MODE_64,code,sizeof(code),
#if USE_EXTRA_OPCODES
                &flags,
#else
                NULL,
#endif
                &decoded_size);

#if USE_EXTRA_OPCODES
            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VPTERNLOGD);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(&instruction,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            ++accepted;
        }
        EXPECT(accepted == 32u);
    }

    {
        static const uint8_t nonlong_p0[] = {0xc3,0xd3,0xe3,0xf3};
        cdisasm_x86_mode mode;

        for (mode = CDISASM_MODE_16; mode <= CDISASM_MODE_32; mode += 16u) {
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags flags = all_flags(mode);
#endif
            size_t index;

            for (index = 0u; index < sizeof(nonlong_p0); ++index) {
                const uint8_t code[] = {
                    0x62,nonlong_p0[index],0x65,0x08,0x25,0xcc,0x5a
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode_exact(
                    CDISASM_CPU_X86,mode,code,sizeof(code),
#if USE_EXTRA_OPCODES
                    &flags,
#else
                    NULL,
#endif
                    &decoded_size);

#if USE_EXTRA_OPCODES
                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.name_id == CDISASM_X86_NAME_VPTERNLOGD);
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            }
        }
    }

    {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
        unsigned int map;

        for (map = 0u; map < 8u; ++map) {
            const uint8_t code[] = {
                0x62,(uint8_t)(0xf0u | map),0x65,0x08,0x25,0xcc,0x5a
            };
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode_exact(
                CDISASM_CPU_X86,CDISASM_MODE_64,code,sizeof(code),
#if USE_EXTRA_OPCODES
                &flags,
#else
                NULL,
#endif
                &decoded_size);

#if USE_EXTRA_OPCODES
            if (map == 3u) {
                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.name_id == CDISASM_X86_NAME_VPTERNLOGD);
            } else if (decoded_size != 0u) {
                EXPECT(instruction.name_id != CDISASM_X86_NAME_VPTERNLOGD);
                EXPECT(instruction.name_id != CDISASM_X86_NAME_VPTERNLOGQ);
            }
#else
            if (map == 3u) {
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
            }
#endif
        }
    }
}

static void test_reserved_controls_and_payload_precedence(void)
{
    static const uint8_t invalid[][8] = {
        {0x62,0xf3,0x64,0x08,0x25,0xcc,0x5a,0x00},
        {0x62,0xf3,0x66,0x08,0x25,0xcc,0x5a,0x00},
        {0x62,0xf3,0x67,0x08,0x25,0xcc,0x5a,0x00},
        {0x62,0xf3,0x65,0x68,0x25,0xcc,0x5a,0x00},
        {0x62,0xf3,0x65,0x18,0x25,0xcc,0x5a,0x00},
        {0x62,0xf3,0x65,0x80,0x25,0xcc,0x5a,0x00},
        {0x62,0xf3,0x61,0x08,0x25,0xcc,0x5a,0x00}
    };
    static const uint8_t legacy_complete[] =
        {0x66,0x62,0xf3,0x65,0x08,0x25,0xcc,0x5a};
    static const uint8_t missing_modrm[] =
        {0x62,0xf3,0x65,0x08,0x25};
    static const uint8_t missing_sib[] =
        {0x62,0xf3,0x65,0x08,0x25,0x04};
    static const uint8_t missing_disp[] =
        {0x62,0xf3,0x65,0x08,0x25,0x48};
    static const uint8_t missing_imm[] =
        {0x62,0xf3,0x65,0x08,0x25,0xcc};
    static const uint8_t reserved_missing_imm[] =
        {0x62,0xf3,0x64,0x08,0x25,0xcc};
    static const uint8_t prefixed_missing_modrm[] =
        {0x66,0x62,0xf3,0x65,0x08,0x25};
    static const uint8_t prefixed_missing_sib[] =
        {0x66,0x62,0xf3,0x65,0x08,0x25,0x04};
    static const uint8_t prefixed_missing_imm[] =
        {0x66,0x62,0xf3,0x65,0x08,0x25,0xcc};
    size_t index;

    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error("reserved VPTERNLOG control",CDISASM_CPU_X86,
            CDISASM_MODE_64,invalid[index],7u,NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("complete forbidden legacy prefix",CDISASM_CPU_X86,
        CDISASM_MODE_64,legacy_complete,sizeof(legacy_complete),NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("missing ModRM",CDISASM_CPU_X86,CDISASM_MODE_64,
        missing_modrm,sizeof(missing_modrm),NULL,CDISASM_STATUS_TRUNCATED);
    expect_error("missing SIB",CDISASM_CPU_X86,CDISASM_MODE_64,
        missing_sib,sizeof(missing_sib),NULL,CDISASM_STATUS_TRUNCATED);
    expect_error("missing displacement",CDISASM_CPU_X86,CDISASM_MODE_64,
        missing_disp,sizeof(missing_disp),NULL,CDISASM_STATUS_TRUNCATED);
    expect_error("missing immediate",CDISASM_CPU_X86,CDISASM_MODE_64,
        missing_imm,sizeof(missing_imm),NULL,CDISASM_STATUS_TRUNCATED);
    expect_error("reserved selector missing immediate",CDISASM_CPU_X86,
        CDISASM_MODE_64,reserved_missing_imm,
        sizeof(reserved_missing_imm),NULL,CDISASM_STATUS_TRUNCATED);
    expect_error("prefixed missing ModRM",CDISASM_CPU_X86,
        CDISASM_MODE_64,prefixed_missing_modrm,
        sizeof(prefixed_missing_modrm),NULL,CDISASM_STATUS_TRUNCATED);
    expect_error("prefixed missing SIB",CDISASM_CPU_X86,
        CDISASM_MODE_64,prefixed_missing_sib,
        sizeof(prefixed_missing_sib),NULL,CDISASM_STATUS_TRUNCATED);
    expect_error("prefixed missing immediate",CDISASM_CPU_X86,
        CDISASM_MODE_64,prefixed_missing_imm,
        sizeof(prefixed_missing_imm),NULL,CDISASM_STATUS_TRUNCATED);

    {
        static const uint8_t nonlong_b4[] =
            {0x62,0xcb,0x65,0x08,0x25,0xcc,0x5a};
        static const uint8_t nonlong_vprime[] =
            {0x62,0xc3,0x65,0x00,0x25,0xcc,0x5a};

        expect_error("non-long B4",CDISASM_CPU_X86,CDISASM_MODE_32,
            nonlong_b4,sizeof(nonlong_b4),NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("non-long V-prime",CDISASM_CPU_X86,CDISASM_MODE_32,
            nonlong_vprime,sizeof(nonlong_vprime),NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_cpu_runtime_routes_and_apx(void)
{
    static const uint8_t forms[3][7] = {
        {0x62,0xf3,0x65,0x08,0x25,0xcc,0x5a},
        {0x62,0xf3,0x65,0x28,0x25,0xcc,0x5a},
        {0x62,0xf3,0x65,0x48,0x25,0xcc,0x5a}
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
        CDISASM_CPU_HASWELL,CDISASM_CPU_ALDER_LAKE
    };
    static const uint8_t b4_reg[] =
        {0x62,0xfb,0x65,0x08,0x25,0xcc,0x5a};
    static const uint8_t b4_mem[] =
        {0x62,0xfb,0x65,0x08,0x25,0x08,0x5a};
    static const uint8_t u0_mem[] =
        {0x62,0xf3,0x61,0x08,0x25,0x04,0x20,0x5a};
    static const uint8_t b4_u0_mem[] =
        {0x62,0xfb,0x61,0x08,0x25,0x04,0x18,0x5a};
    static const uint8_t u0_reg[] =
        {0x62,0xf3,0x61,0x08,0x25,0xcc,0x5a};
    cdisasm_x86_decode_flags exact[3] = {
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_128),
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_256),
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_512)
    };
    cdisasm_x86_decode_flags apx_flags = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512F_128,
        CDISASM_X86_DECODE_BIT_APX);
    size_t index;
    unsigned int ll;

    for (ll = 0u; ll < 3u; ++ll) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_exact(
            CDISASM_CPU_X86,CDISASM_MODE_64,forms[ll],sizeof(forms[ll]),
            &exact[ll],&decoded_size);

        check_vpternlog(&instruction,decoded_size,0u,ll,1,0,0u,0,0);
        expect_error("exact width mismatch",CDISASM_CPU_X86,
            CDISASM_MODE_64,forms[ll],sizeof(forms[ll]),
            &exact[(ll + 1u) % 3u],CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    for (index = 0u;
         index < sizeof(positive_profiles) / sizeof(positive_profiles[0]);
         ++index) {
        cdisasm_x86_decode_flags available =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            positive_profiles[index],CDISASM_MODE_64,&available)
            == CDISASM_STATUS_OK);
        for (ll = 0u; ll < 3u; ++ll) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode_exact(
                positive_profiles[index],CDISASM_MODE_64,
                forms[ll],sizeof(forms[ll]),&available,&decoded_size);

            EXPECT(decoded_size == sizeof(forms[ll]));
            EXPECT(instruction.form_id == UINT16_C(8260) + 2u * ll);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction,width_group(ll)));
        }
    }
    for (index = 0u;
         index < sizeof(negative_profiles) / sizeof(negative_profiles[0]);
         ++index) {
        expect_error("profile lacks VPTERNLOG",negative_profiles[index],
            CDISASM_MODE_64,forms[0],sizeof(forms[0]),NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    {
        cdisasm_x86_decode_flags available =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_KNIGHTS_MILL,
            CDISASM_MODE_64,&available) == CDISASM_STATUS_OK);
        expect_error("KNM has no VL",CDISASM_CPU_KNIGHTS_MILL,
            CDISASM_MODE_64,forms[0],sizeof(forms[0]),&available,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        instruction = decode_exact(CDISASM_CPU_KNIGHTS_MILL,
            CDISASM_MODE_64,forms[2],sizeof(forms[2]),&available,
            &decoded_size);
        EXPECT(decoded_size == sizeof(forms[2]));
        EXPECT(instruction.form_id == UINT16_C(8264));
    }

    {
        cdisasm_x86_decode_flags available =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_SKYLAKE_SP,
            CDISASM_MODE_64,&available) == CDISASM_STATUS_OK);
        instruction = decode_exact(CDISASM_CPU_SKYLAKE_SP,
            CDISASM_MODE_64,forms[0],sizeof(forms[0]),&available,
            &decoded_size);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction,CDISASM_X86_GROUP_AVX512F));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction,CDISASM_X86_GROUP_AVX512VL));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction,CDISASM_X86_GROUP_AVX10_1));
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_AVX10,
            CDISASM_MODE_64,&available) == CDISASM_STATUS_OK);
        instruction = decode_exact(CDISASM_CPU_AVX10,CDISASM_MODE_64,
            forms[0],sizeof(forms[0]),&available,&decoded_size);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction,CDISASM_X86_GROUP_AVX10_1));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction,CDISASM_X86_GROUP_AVX512F));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction,CDISASM_X86_GROUP_AVX512VL));
    }

    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_exact(
            CDISASM_CPU_X86,CDISASM_MODE_64,b4_reg,sizeof(b4_reg),
            &apx_flags,&decoded_size);

        check_vpternlog(&instruction,decoded_size,0u,0u,1,0,0u,0,1);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM4);
        instruction = decode_exact(CDISASM_CPU_X86,CDISASM_MODE_64,
            b4_mem,sizeof(b4_mem),&apx_flags,&decoded_size);
        check_vpternlog(&instruction,decoded_size,0u,0u,0,0,0u,0,1);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R16);
        instruction = decode_exact(CDISASM_CPU_X86,CDISASM_MODE_64,
            u0_mem,sizeof(u0_mem),&apx_flags,&decoded_size);
        check_vpternlog(&instruction,decoded_size,0u,0u,0,0,0u,0,1);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R20);
        instruction = decode_exact(CDISASM_CPU_X86,CDISASM_MODE_64,
            b4_u0_mem,sizeof(b4_u0_mem),&apx_flags,&decoded_size);
        check_vpternlog(&instruction,decoded_size,0u,0u,0,0,0u,0,1);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R16);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R19);
        expect_error("U0 register reserved",CDISASM_CPU_X86,
            CDISASM_MODE_64,u0_reg,sizeof(u0_reg),&apx_flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("APX runtime bit required",CDISASM_CPU_X86,
            CDISASM_MODE_64,b4_reg,sizeof(b4_reg),&exact[0],
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("Skylake rejects B4",CDISASM_CPU_SKYLAKE_SP,
            CDISASM_MODE_64,b4_reg,sizeof(b4_reg),&apx_flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_family(
            CDISASM_CPU_SKYLAKE_SP,CDISASM_MODE_64,
            forms[0],sizeof(forms[0]),CDISASM_X86_DECODE_FLAG_AVX512,
            CDISASM_X86_DECODE_BIT_AVX512F_128,
            &decoded_size);

        EXPECT(decoded_size == sizeof(forms[0]));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPTERNLOGD);
        instruction = decode_family(CDISASM_CPU_AVX10,CDISASM_MODE_64,
            forms[0],sizeof(forms[0]),CDISASM_X86_DECODE_FLAG_AVX10,
            CDISASM_X86_DECODE_BIT_AVX512F_128,
            &decoded_size);
        EXPECT(decoded_size == sizeof(forms[0]));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPTERNLOGD);
        instruction = decode_family(CDISASM_CPU_X86,CDISASM_MODE_64,
            b4_reg,sizeof(b4_reg),
            CDISASM_X86_DECODE_FLAG_AVX512 | CDISASM_X86_DECODE_FLAG_APX,
            CDISASM_X86_DECODE_BIT_AVX512F_128,
            &decoded_size);
        EXPECT(decoded_size == sizeof(b4_reg));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPTERNLOGD);
        instruction = decode_family(CDISASM_CPU_X86,CDISASM_MODE_64,
            b4_reg,sizeof(b4_reg),CDISASM_X86_DECODE_FLAG_AVX512,
            CDISASM_X86_DECODE_BIT_AVX512F_128,
            &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    }
#else
    expect_error("owned extras off",CDISASM_CPU_X86,CDISASM_MODE_64,
        forms[0],sizeof(forms[0]),NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void reject_format(const cdisasm_instruction *instruction)
{
    static const uint32_t syntaxes[] = {
        CDISASM_FORMAT_SYNTAX_INTEL,CDISASM_FORMAT_SYNTAX_ATT
    };
    size_t index;

    for (index = 0u; index < sizeof(syntaxes) / sizeof(syntaxes[0]); ++index) {
        char output[64] = "not empty";

        EXPECT(cdisasm_x86_format(instruction,syntaxes[index],
            output,sizeof(output)) == 0u);
        EXPECT(output[0] == '\0');
    }
}

static void expect_format(
    const cdisasm_instruction *instruction,
    uint32_t syntax,
    const char *expected)
{
    char output[192];
    size_t required = cdisasm_x86_format(
        instruction,syntax,output,sizeof(output));

    if (strcmp(output,expected) != 0) {
        fprintf(stderr,"format mismatch: got '%s', expected '%s'\n",
            output,expected);
    }
    EXPECT(required == strlen(expected));
    EXPECT(strcmp(output,expected) == 0);
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
        {{0x62,0xf3,0x65,0x8a,0x25,0xcc,0x5a,0},7,
            CDISASM_X86_DECODE_BIT_AVX512F_128,
            "vpternlogd xmm1 {k2}{z}, xmm3, xmm4, 0x5a",
            "vpternlogd $0x5a, %xmm4, %xmm3, %xmm1{%k2}{z}"},
        {{0x62,0xf3,0x65,0x3a,0x25,0x48,0xff,0x5a},8,
            CDISASM_X86_DECODE_BIT_AVX512F_256,
            "vpternlogd ymm1 {k2}, ymm3, dword ptr [rax - 0x4]{1to8}, 0x5a",
            "vpternlogd $0x5a, -0x4(%rax){1to8}, %ymm3, %ymm1{%k2}"},
        {{0x62,0xf3,0xe5,0x5a,0x25,0x48,0xff,0xa5},8,
            CDISASM_X86_DECODE_BIT_AVX512F_512,
            "vpternlogq zmm1 {k2}, zmm3, qword ptr [rax - 0x8]{1to8}, 0xa5",
            "vpternlogq $0xa5, -0x8(%rax){1to8}, %zmm3, %zmm1{%k2}"}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags = one_bit(cases[index].bit);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_exact(
            CDISASM_CPU_X86,CDISASM_MODE_64,cases[index].code,
            cases[index].size,&flags,&decoded_size);

        EXPECT(decoded_size == cases[index].size);
        expect_format(&instruction,CDISASM_FORMAT_SYNTAX_INTEL,
            cases[index].intel);
        expect_format(&instruction,CDISASM_FORMAT_SYNTAX_ATT,
            cases[index].att);
    }

    {
        cdisasm_x86_decode_flags flags =
            one_bit(CDISASM_X86_DECODE_BIT_AVX512F_128);
        uint32_t decoded_size;
        cdisasm_instruction valid = decode_exact(
            CDISASM_CPU_X86,CDISASM_MODE_64,cases[0].code,cases[0].size,
            &flags,&decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == cases[0].size);
        forged = valid;
        forged.form_id = UINT16_C(8259);
        reject_format(&forged);
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VPTERNLOGQ;
        reject_format(&forged);
        forged = valid;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_WRITE;
        reject_format(&forged);
        forged = valid;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        reject_format(&forged);
        forged = valid;
        forged.opcode[2].broadcast = CDISASM_X86_BROADCAST_1_TO_4;
        reject_format(&forged);
        forged = valid;
        forged.opcode[3].access = CDISASM_OPERAND_ACCESS_WRITE;
        reject_format(&forged);
        forged = valid;
        forged.encoding.immediate_size[0] = 2u;
        reject_format(&forged);
        forged = valid;
        forged.x86_group_ids[forged.x86_group_count - 1u]
            = CDISASM_X86_GROUP_AVX512F_256;
        reject_format(&forged);
        forged = valid;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        reject_format(&forged);
    }

    {
        cdisasm_x86_decode_flags flags =
            one_bit(CDISASM_X86_DECODE_BIT_AVX512F_256);
        uint32_t decoded_size;
        cdisasm_instruction valid = decode_exact(
            CDISASM_CPU_X86,CDISASM_MODE_64,cases[1].code,cases[1].size,
            &flags,&decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == cases[1].size);
        forged = valid;
        forged.opcode[2].size = 32u;
        reject_format(&forged);
        forged = valid;
        forged.opcode[2].broadcast = CDISASM_X86_BROADCAST_NONE;
        reject_format(&forged);
        forged = valid;
        forged.encoding.modrm ^= UINT8_C(0x40);
        reject_format(&forged);
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
            fprintf(stderr,#function ": %d new failure(s)\n",            \
                failures - before);                                          \
        }                                                                    \
    } while (0)

    RUN_TEST(test_exact_forms_operands_masks_broadcast_and_disp8);
    RUN_TEST(test_owned_p1_p2_and_map_spaces);
    RUN_TEST(test_reserved_controls_and_payload_precedence);
    RUN_TEST(test_cpu_runtime_routes_and_apx);
    RUN_TEST(test_formatting_and_fail_closed_schema);
#undef RUN_TEST

    if (failures != 0) {
        fprintf(stderr,"x86 VPTERNLOG tests: %d failure(s)\n",failures);
        return 1;
    }
    puts("x86 VPTERNLOG tests passed");
    return 0;
}
