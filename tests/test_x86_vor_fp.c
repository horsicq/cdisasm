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

_Static_assert(CDISASM_X86_NAME_VORPS == UINT16_C(638)
        && CDISASM_X86_NAME_VORPD == UINT16_C(639),
    "classic VOR name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX512DQ_128 == UINT16_C(171)
        && CDISASM_X86_GROUP_AVX512DQ_256 == UINT16_C(173)
        && CDISASM_X86_GROUP_AVX512DQ_512 == UINT16_C(174),
    "classic VOR ISA-set IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512DQ_128 == UINT32_C(119)
        && CDISASM_X86_DECODE_BIT_AVX512DQ_256 == UINT32_C(121)
        && CDISASM_X86_DECODE_BIT_AVX512DQ_512 == UINT32_C(122),
    "classic VOR runtime-bit IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update classic VOR profile sweeps");

typedef struct vor_family {
    cdisasm_x86_name_id name_id;
    uint8_t pp;
    uint8_t w;
    uint8_t element_bytes;
    cdisasm_x86_form_id vex_xmm_base;
    cdisasm_x86_form_id vex_ymm_base;
    cdisasm_x86_form_id evex_base;
} vor_family;

static const vor_family families[] = {
    {CDISASM_X86_NAME_VORPD,1,1,8,6054,6058,6056},
    {CDISASM_X86_NAME_VORPS,0,0,4,6064,6068,6066}
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
#endif

static cdisasm_x86_form_id vex_form(
    const vor_family *family,
    unsigned int l,
    int register_form)
{
    return (cdisasm_x86_form_id)(
        (l == 0u ? family->vex_xmm_base : family->vex_ymm_base)
        + (register_form ? 1u : 0u));
}

static cdisasm_x86_form_id evex_form(
    const vor_family *family,
    unsigned int ll,
    int register_form)
{
    return (cdisasm_x86_form_id)(family->evex_base
        + (ll == 0u ? 0u : ll == 1u ? 4u : 6u)
        + (register_form ? 1u : 0u));
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_group_id width_group(unsigned int ll)
{
    return ll == 0u ? CDISASM_X86_GROUP_AVX512DQ_128
        : ll == 1u ? CDISASM_X86_GROUP_AVX512DQ_256
                   : CDISASM_X86_GROUP_AVX512DQ_512;
}

static cdisasm_x86_decode_bit_id width_bit(unsigned int ll)
{
    return ll == 0u ? CDISASM_X86_DECODE_BIT_AVX512DQ_128
        : ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512DQ_256
                   : CDISASM_X86_DECODE_BIT_AVX512DQ_512;
}

static void check_vor(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    const vor_family *family,
    cdisasm_x86_form_id form_id,
    int evex,
    unsigned int ll,
    int register_form,
    int broadcast,
    unsigned int aaa,
    int zero,
    int apx)
{
    const unsigned int vector_bytes = 16u << ll;
    const unsigned int memory_bytes = broadcast
        ? family->element_bytes : vector_bytes;
    const int merge = evex && aaa != 0u && !zero;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == family->name_id);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->operand_count == 3u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (evex ? CDISASM_PREFIX_EVEX : CDISASM_PREFIX_VEX)) != 0u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].size == vector_bytes);
    EXPECT(instruction->opcode[0].access == (merge
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].size == vector_bytes);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[2].size == (register_form
        ? vector_bytes : memory_bytes));
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[2].broadcast
        == (cdisasm_x86_broadcast)(broadcast
            ? vector_bytes / family->element_bytes : 0u));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
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
    if (evex) {
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512DQ));
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, width_group(ll)));
    } else {
        EXPECT(!cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512DQ));
        EXPECT(!cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512DQ_128));
        EXPECT(!cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512DQ_256));
        EXPECT(!cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512DQ_512));
    }
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    const vor_family *family,
    cdisasm_x86_form_id form_id,
    int evex,
    unsigned int ll,
    int register_form,
    int broadcast,
    unsigned int aaa,
    int zero,
    int apx)
{
#if USE_EXTRA_OPCODES
    check_vor(instruction, decoded_size, family, form_id, evex, ll,
        register_form, broadcast, aaa, zero, apx);
#else
    (void)family;
    (void)form_id;
    (void)evex;
    (void)ll;
    (void)register_form;
    (void)broadcast;
    (void)aaa;
    (void)zero;
    (void)apx;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_vex_exhaustive(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint64_t forms[6074] = {0};
    uint64_t allocated = 0;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        size_t family_index;

        for (family_index = 0u;
             family_index < sizeof(families) / sizeof(families[0]);
             ++family_index) {
            const vor_family *family = &families[family_index];
            unsigned int l;

            for (l = 0u; l < 2u; ++l) {
                unsigned int vex_size;

                for (vex_size = 2u; vex_size <= 3u; ++vex_size) {
                    const unsigned int w_limit = vex_size == 3u ? 2u : 1u;
                    unsigned int encoded_w;

                    for (encoded_w = 0u; encoded_w < w_limit;
                         ++encoded_w) {
                        unsigned int modrm;

                        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                            uint8_t code[15] = {0};
                            const int reg = (modrm & UINT8_C(0xc0))
                                == UINT8_C(0xc0);
                            const cdisasm_x86_form_id form_id = vex_form(
                                family, l, reg);
                            uint32_t decoded_size;
                            cdisasm_instruction instruction;

                            if (vex_size == 2u) {
                                code[0] = UINT8_C(0xc5);
                                code[1] = (uint8_t)(UINT8_C(0xf0)
                                    | (l << 2) | family->pp);
                                code[2] = UINT8_C(0x56);
                                code[3] = (uint8_t)modrm;
                            } else {
                                code[0] = UINT8_C(0xc4);
                                code[1] = UINT8_C(0xe1);
                                code[2] = (uint8_t)((encoded_w << 7)
                                    | UINT8_C(0x70) | (l << 2)
                                    | family->pp);
                                code[3] = UINT8_C(0x56);
                                code[4] = (uint8_t)modrm;
                            }
                            code[vex_size + 2u] = UINT8_C(0x24);
                            code[vex_size + 3u] = UINT8_C(0x10);
                            code[vex_size + 4u] = UINT8_C(0x20);
                            code[vex_size + 5u] = UINT8_C(0x30);
                            code[vex_size + 6u] = UINT8_C(0x40);

                            instruction = decode(CDISASM_CPU_X86,
                                modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                                &flags, &decoded_size);
#else
                                NULL, &decoded_size);
#endif
                            check_allocated(&instruction, decoded_size, family,
                                form_id,0,l,reg,0,0u,0,0);
                            ++forms[form_id];
                            ++allocated;
                        }
                    }
                }
            }
        }
    }
    EXPECT(allocated == UINT64_C(9216));
    EXPECT(forms[6054] && forms[6055] && forms[6058] && forms[6059]);
    EXPECT(forms[6064] && forms[6065] && forms[6068] && forms[6069]);
}

static void test_evex_exhaustive(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint64_t forms[6074] = {0};
    uint64_t allocated = 0;
    uint64_t reserved = 0;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        size_t family_index;

        for (family_index = 0u;
             family_index < sizeof(families) / sizeof(families[0]);
             ++family_index) {
            const vor_family *family = &families[family_index];
            unsigned int ll;

            for (ll = 0u; ll < 4u; ++ll) {
                unsigned int b;

                for (b = 0u; b < 2u; ++b) {
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const int reg = (modrm & UINT8_C(0xc0))
                            == UINT8_C(0xc0);
                        const int valid = ll < 3u && (!b || !reg);
                        const uint8_t code[15] = {
                            0x62,0xf1,
                            (uint8_t)((family->w << 7)
                                | UINT8_C(0x74) | family->pp),
                            (uint8_t)(UINT8_C(0x08) | (ll << 5)
                                | (b << 4)),
                            0x56,(uint8_t)modrm,0x24,0x10,0x20,
                            0x30,0x40,0x50,0x60,0x70,0x80
                        };
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_X86, modes[mode_index], code,
#if USE_EXTRA_OPCODES
                            sizeof(code), &flags, &decoded_size);
#else
                            sizeof(code), NULL, &decoded_size);
#endif

                        if (!valid) {
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(&instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                            ++reserved;
                            continue;
                        }
                        check_allocated(&instruction, decoded_size, family,
                            evex_form(family,ll,reg),1,ll,reg,
                            b && !reg,0u,0,0);
                        ++forms[evex_form(family,ll,reg)];
                        ++allocated;
                    }
                }
            }
        }
    }
    EXPECT(allocated == UINT64_C(8064));
    EXPECT(reserved == UINT64_C(4224));
    EXPECT(forms[6056] && forms[6057] && forms[6060]
        && forms[6061] && forms[6062] && forms[6063]);
    EXPECT(forms[6066] && forms[6067] && forms[6070]
        && forms[6071] && forms[6072] && forms[6073]);
}

static void test_apx_exhaustive(void)
{
    uint64_t b4_allocated = 0;
    uint64_t b4_reserved = 0;
    uint64_t u0_allocated = 0;
    uint64_t u0_reserved = 0;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
    size_t family_index;

    for (family_index = 0u;
         family_index < sizeof(families) / sizeof(families[0]);
         ++family_index) {
        const vor_family *family = &families[family_index];
        unsigned int ll;

        for (ll = 0u; ll < 4u; ++ll) {
            unsigned int b;

            for (b = 0u; b < 2u; ++b) {
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const int reg = (modrm & UINT8_C(0xc0))
                        == UINT8_C(0xc0);
                    const int b4_valid = ll < 3u && (!b || !reg);
                    const int u0_valid = ll < 3u && !reg;
                    uint8_t b4_code[15] = {
                        0x62,0xf9,
                        (uint8_t)((family->w << 7)
                            | UINT8_C(0x74) | family->pp),
                        (uint8_t)(UINT8_C(0x08) | (ll << 5)
                            | (b << 4)),
                        0x56,(uint8_t)modrm,0x24,0x10,0x20,
                        0x30,0x40,0x50,0x60,0x70,0x80
                    };
                    uint8_t u0_code[15];
                    uint32_t decoded_size;
                    cdisasm_instruction instruction;

                    memcpy(u0_code, b4_code, sizeof(u0_code));
                    u0_code[1] = UINT8_C(0xf1);
                    u0_code[2] &= (uint8_t)~UINT8_C(0x04);

                    instruction = decode(CDISASM_CPU_X86,
                        CDISASM_MODE_64, b4_code, sizeof(b4_code),
#if USE_EXTRA_OPCODES
                        &flags, &decoded_size);
#else
                        NULL, &decoded_size);
#endif
                    if (b4_valid) {
                        check_allocated(&instruction, decoded_size, family,
                            evex_form(family,ll,reg),1,ll,reg,
                            b && !reg,0u,0,1);
                        ++b4_allocated;
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++b4_reserved;
                    }

                    instruction = decode(CDISASM_CPU_X86,
                        CDISASM_MODE_64, u0_code, sizeof(u0_code),
#if USE_EXTRA_OPCODES
                        &flags, &decoded_size);
#else
                        NULL, &decoded_size);
#endif
                    if (u0_valid) {
                        check_allocated(&instruction, decoded_size, family,
                            evex_form(family,ll,0),1,ll,0,b != 0u,
                            0u,0,1);
                        ++u0_allocated;
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++u0_reserved;
                    }
                }
            }
        }
    }
    EXPECT(b4_allocated == UINT64_C(2688));
    EXPECT(b4_reserved == UINT64_C(1408));
    EXPECT(u0_allocated == UINT64_C(2304));
    EXPECT(u0_reserved == UINT64_C(1792));
}

static void test_non64_ignored_extensions_and_collisions(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32
    };
    static const uint8_t vex_ignored[] = {
        0xc4,0xc1,0x30,0x56,0xc2
    };
    static const uint8_t evex_ignored[] = {
        0x62,0xc1,0x34,0x08,0x56,0xc2
    };
    static const uint8_t les_collision[] = {
        0xc4,0x61,0x70,0x56,0xc2
    };
    static const uint8_t lds_collision[] = {
        0xc5,0x70,0x56,0xc2
    };
    static const uint8_t bound_collision[] = {
        0x62,0x71,0x74,0x08,0x56,0xc2
    };
    size_t index;

    for (index = 0u; index < sizeof(modes) / sizeof(modes[0]); ++index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[index]);
#endif
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            modes[index], vex_ignored, sizeof(vex_ignored),
#if USE_EXTRA_OPCODES
            &flags, &decoded_size);
#else
            NULL, &decoded_size);
#endif

        check_allocated(&instruction, decoded_size, &families[1],
            UINT16_C(6065),0,0u,1,0,0u,0,0);
#if USE_EXTRA_OPCODES
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM0);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM2);
#endif
        instruction = decode(CDISASM_CPU_X86, modes[index],
            evex_ignored, sizeof(evex_ignored),
#if USE_EXTRA_OPCODES
            &flags, &decoded_size);
#else
            NULL, &decoded_size);
#endif
        check_allocated(&instruction, decoded_size, &families[1],
            UINT16_C(6067),1,0u,1,0,0u,0,0);
#if USE_EXTRA_OPCODES
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM0);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM2);
#endif
    }

    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_32, les_collision, sizeof(les_collision),
            NULL, &decoded_size);

        EXPECT(decoded_size == 3u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
            lds_collision, sizeof(lds_collision), NULL, &decoded_size);
        EXPECT(decoded_size == 3u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LDS);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
            bound_collision, sizeof(bound_collision), NULL, &decoded_size);
        EXPECT(decoded_size == 3u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_BOUND);
    }
}

static void test_prefixes_high_registers_masks_tuples_and_apx(void)
{
    static const uint8_t address_size[] = {
        0x67,0xc5,0xf0,0x56,0xc2
    };
    static const uint8_t segment[] = {
        0x2e,0xc4,0xe1,0xf5,0x56,0x00
    };
#if USE_EXTRA_OPCODES
    static const uint8_t high[] = {
        0x62,0x01,0x0c,0x40,0x56,0xfd
    };
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        address_size, sizeof(address_size),
#if USE_EXTRA_OPCODES
        &flags, &decoded_size);
#else
        NULL, &decoded_size);
#endif

    check_allocated(&instruction, decoded_size, &families[1],
        UINT16_C(6065),0,0u,1,0,0u,0,0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        segment, sizeof(segment),
#if USE_EXTRA_OPCODES
        &flags, &decoded_size);
#else
        NULL, &decoded_size);
#endif
    check_allocated(&instruction, decoded_size, &families[0],
        UINT16_C(6058),0,1u,0,0,0u,0,0);

#if USE_EXTRA_OPCODES
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        high, sizeof(high), &flags, &decoded_size);
    check_vor(&instruction, decoded_size, &families[1],
        UINT16_C(6073),1,2u,1,0,0u,0,0);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ZMM31);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ZMM30);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_ZMM29);

    {
        size_t family_index;

        for (family_index = 0u;
             family_index < sizeof(families) / sizeof(families[0]);
             ++family_index) {
            const vor_family *family = &families[family_index];
            const unsigned int ll = (unsigned int)family_index + 1u;
            uint8_t merge[] = {0x62,0xf1,0,0x09,0x56,0xc2};
            uint8_t zero[] = {0x62,0xf1,0,0x89,0x56,0xc2};
            uint8_t full[] = {0x62,0xf1,0,0x08,0x56,0x40,0xff};
            uint8_t tuple[] = {0x62,0xf1,0,0x18,0x56,0x40,0xff};
            uint8_t b4_reg[] = {0x62,0xf9,0,0x08,0x56,0xc2};
            uint8_t b4_mem[] = {0x62,0xf9,0,0x08,0x56,0x02};
            uint8_t x4_mem[] = {0x62,0xf1,0,0x08,0x56,0x04,0xa4};
            cdisasm_x86_decode_flags apx_flags = two_bits(
                width_bit(ll), CDISASM_X86_DECODE_BIT_APX);

            merge[2] = zero[2] = full[2] = tuple[2] = b4_reg[2]
                = b4_mem[2] = x4_mem[2] = (uint8_t)((family->w << 7)
                    | UINT8_C(0x74) | family->pp);
            merge[3] = (uint8_t)(merge[3] | (ll << 5));
            zero[3] = (uint8_t)(zero[3] | (ll << 5));
            full[3] = (uint8_t)(full[3] | (ll << 5));
            tuple[3] = (uint8_t)(tuple[3] | (ll << 5));
            b4_reg[3] = (uint8_t)(b4_reg[3] | (ll << 5));
            b4_mem[3] = (uint8_t)(b4_mem[3] | (ll << 5));
            x4_mem[3] = (uint8_t)(x4_mem[3] | (ll << 5));
            x4_mem[2] &= (uint8_t)~UINT8_C(0x04);

            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                merge, sizeof(merge), &flags, &decoded_size);
            check_vor(&instruction, decoded_size, family,
                evex_form(family,ll,1),1,ll,1,0,1u,0,0);
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                zero, sizeof(zero), &flags, &decoded_size);
            check_vor(&instruction, decoded_size, family,
                evex_form(family,ll,1),1,ll,1,0,1u,1,0);

            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                full, sizeof(full), &flags, &decoded_size);
            check_vor(&instruction, decoded_size, family,
                evex_form(family,ll,0),1,ll,0,0,0u,0,0);
            EXPECT(instruction.opcode[2].imm
                == (uint64_t)(-(INT64_C(16) << ll)));
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                tuple, sizeof(tuple), &flags, &decoded_size);
            check_vor(&instruction, decoded_size, family,
                evex_form(family,ll,0),1,ll,0,1,0u,0,0);
            EXPECT(instruction.opcode[2].imm
                == (uint64_t)(-(int64_t)family->element_bytes));

            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                b4_reg, sizeof(b4_reg), &apx_flags, &decoded_size);
            check_vor(&instruction, decoded_size, family,
                evex_form(family,ll,1),1,ll,1,0,0u,0,1);
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                b4_mem, sizeof(b4_mem), &apx_flags, &decoded_size);
            check_vor(&instruction, decoded_size, family,
                evex_form(family,ll,0),1,ll,0,0,0u,0,1);
            EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R18);
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                x4_mem, sizeof(x4_mem), &apx_flags, &decoded_size);
            check_vor(&instruction, decoded_size, family,
                evex_form(family,ll,0),1,ll,0,0,0u,0,1);
            EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R20);
        }
    }
#endif
}

static void test_runtime_bits_and_profiles(void)
{
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_cpu_id avx_positive[] = {
        CDISASM_CPU_SANDY_BRIDGE, CDISASM_CPU_IVY_BRIDGE,
        CDISASM_CPU_HASWELL, CDISASM_CPU_BROADWELL,
        CDISASM_CPU_AMD_ZEN, CDISASM_CPU_AMD_ZEN_4
    };
    static const cdisasm_x86_cpu_id evex_positive[] = {
        CDISASM_CPU_SKYLAKE_SP, CDISASM_CPU_ICE_LAKE,
        CDISASM_CPU_TIGER_LAKE, CDISASM_CPU_AMD_ZEN_4,
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_CPU_AVX10,
        CDISASM_CPU_APX, CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const cdisasm_x86_cpu_id evex_negative[] = {
        CDISASM_CPU_HASWELL, CDISASM_CPU_BROADWELL,
        CDISASM_CPU_SKYLAKE, CDISASM_CPU_ALDER_LAKE,
        CDISASM_CPU_AMD_ZEN, CDISASM_CPU_ARROW_LAKE,
        CDISASM_CPU_KNIGHTS_MILL
    };
    static const uint8_t vex[] = {0xc5,0xf0,0x56,0xc2};
    static const uint8_t evex[] = {0x62,0xf1,0x74,0x08,0x56,0xc2};
    cdisasm_x86_decode_flags avx = one_bit(CDISASM_X86_DECODE_BIT_AVX);
    cdisasm_x86_decode_flags exact =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512DQ_128);
    cdisasm_x86_decode_flags wrong =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512DQ_256);
    cdisasm_x86_decode_flags umbrella =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512_DQ);
    size_t index;

    for (index = 0u;
         index < sizeof(avx_positive) / sizeof(avx_positive[0]); ++index) {
        cdisasm_x86_decode_flags available;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(avx_positive[index],
            CDISASM_MODE_64, &available) == CDISASM_STATUS_OK);
        instruction = decode(avx_positive[index], CDISASM_MODE_64,
            vex, sizeof(vex), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(vex));
        EXPECT(instruction.form_id == UINT16_C(6065));
    }
    expect_error("Westmere lacks AVX", CDISASM_CPU_WESTMERE,
        CDISASM_MODE_64, vex, sizeof(vex), &avx,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    for (index = 0u;
         index < sizeof(evex_positive) / sizeof(evex_positive[0]); ++index) {
        cdisasm_x86_decode_flags available;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(evex_positive[index],
            CDISASM_MODE_64, &available) == CDISASM_STATUS_OK);
        instruction = decode(evex_positive[index], CDISASM_MODE_64,
            evex, sizeof(evex), &available, &decoded_size);
        if (decoded_size != sizeof(evex)) {
            fprintf(stderr, "EVEX VOR positive profile %u returned %u/%u\n",
                (unsigned int)evex_positive[index],
                (unsigned int)decoded_size,
                (unsigned int)instruction.last_error_id);
        }
        EXPECT(decoded_size == sizeof(evex));
        EXPECT(instruction.form_id == UINT16_C(6067));
    }
    for (index = 0u;
         index < sizeof(evex_negative) / sizeof(evex_negative[0]); ++index) {
        cdisasm_x86_decode_flags available;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(evex_negative[index],
            CDISASM_MODE_64, &available) == CDISASM_STATUS_OK);
        expect_error("profile lacks EVEX VOR", evex_negative[index],
            CDISASM_MODE_64, evex, sizeof(evex), &available,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("EVEX DQ width mismatch", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex, sizeof(evex), &wrong,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("EVEX DQ umbrella is not exact", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex, sizeof(evex), &umbrella,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, evex, sizeof(evex), &exact, &decoded_size);

        EXPECT(decoded_size == sizeof(evex));
        EXPECT(instruction.form_id == UINT16_C(6067));
    }
#else
    static const uint8_t vex[] = {0xc5,0xf0,0x56,0xc2};
    static const uint8_t evex[] = {0x62,0xf1,0x74,0x08,0x56,0xc2};

    expect_error("VEX extras off", CDISASM_CPU_X86, CDISASM_MODE_64,
        vex, sizeof(vex), NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("EVEX extras off", CDISASM_CPU_X86, CDISASM_MODE_64,
        evex, sizeof(evex), NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_collisions_and_truncated(void)
{
    static const struct invalid_case {
        const char *label;
        uint8_t code[7];
        size_t size;
        cdisasm_x86_mode mode;
    } invalid[] = {
        {"PS W1",{0x62,0xf1,0xf4,0x08,0x56,0xc2,0},6,CDISASM_MODE_64},
        {"PD W0",{0x62,0xf1,0x75,0x08,0x56,0xc2,0},6,CDISASM_MODE_64},
        {"LL3",{0x62,0xf1,0x74,0x68,0x56,0xc2,0},6,CDISASM_MODE_64},
        {"register b",{0x62,0xf1,0x74,0x18,0x56,0xc2,0},6,CDISASM_MODE_64},
        {"z without mask",{0x62,0xf1,0x74,0x88,0x56,0xc2,0},6,CDISASM_MODE_64},
        {"U0 register",{0x62,0xf1,0x70,0x08,0x56,0xc2,0},6,CDISASM_MODE_64},
        {"B4 non-long",{0x62,0xf9,0x74,0x08,0x56,0xc2,0},6,CDISASM_MODE_32},
        {"V prime non-long",{0x62,0xf1,0x74,0x00,0x56,0xc2,0},6,CDISASM_MODE_32}
    };
    static const uint8_t valid[] = {0x62,0xf1,0x74,0x08,0x56,0xc2};
    static const uint8_t missing_sib[] = {
        0x62,0xf1,0x74,0x08,0x56,0x04
    };
    static const uint8_t missing_disp8[] = {
        0x62,0xf1,0x74,0x08,0x56,0x40
    };
    static const uint8_t legacy_prefixes[][7] = {
        {0x66,0x62,0xf1,0x74,0x08,0x56,0xc2},
        {0xf2,0x62,0xf1,0x74,0x08,0x56,0xc2},
        {0xf3,0x62,0xf1,0x74,0x08,0x56,0xc2},
        {0xf0,0x62,0xf1,0x74,0x08,0x56,0xc2},
        {0x48,0x62,0xf1,0x74,0x08,0x56,0xc2}
    };
    static const uint8_t vex_prefixes[][5] = {
        {0x66,0xc5,0xf0,0x56,0xc2},
        {0xf2,0xc5,0xf0,0x56,0xc2},
        {0xf3,0xc5,0xf0,0x56,0xc2},
        {0xf0,0xc5,0xf0,0x56,0xc2},
        {0x48,0xc5,0xf0,0x56,0xc2}
    };
    static const struct deferred_case {
        uint8_t p1;
        uint8_t p2;
    } deferred[] = {
        {0xf4,0x08},{0x75,0x08},{0x74,0x68},
        {0x74,0x18},{0x74,0x88},{0x70,0x08}
    };
    static const uint8_t pp_reserved[][6] = {
        {0x62,0xf1,0x76,0x08,0x56,0xc2},
        {0x62,0xf1,0x77,0x08,0x56,0xc2}
    };
    size_t index;

    for (index = 1u; index < sizeof(valid); ++index) {
        expect_error("truncated classic EVEX VOR", CDISASM_CPU_X86,
            CDISASM_MODE_64, valid, index, NULL,
            CDISASM_STATUS_TRUNCATED);
    }
    expect_error("missing SIB", CDISASM_CPU_X86, CDISASM_MODE_64,
        missing_sib, sizeof(missing_sib), NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("missing disp8", CDISASM_CPU_X86, CDISASM_MODE_64,
        missing_disp8, sizeof(missing_disp8), NULL,
        CDISASM_STATUS_TRUNCATED);
    for (index = 0u; index < sizeof(deferred) / sizeof(deferred[0]);
         ++index) {
        uint8_t code[] = {
            0x62,0xf1,deferred[index].p1,deferred[index].p2,0x56,0
        };

        expect_error("deferred VOR ModRM", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, 5u, NULL, CDISASM_STATUS_TRUNCATED);
        code[5] = UINT8_C(0x04);
        expect_error("deferred VOR SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, sizeof(code), NULL,
            CDISASM_STATUS_TRUNCATED);
        code[5] = UINT8_C(0x40);
        expect_error("deferred VOR disp8", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, sizeof(code), NULL,
            CDISASM_STATUS_TRUNCATED);
    }
    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]);
         ++index) {
        expect_error(invalid[index].label, CDISASM_CPU_X86,
            invalid[index].mode, invalid[index].code, invalid[index].size,
            NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 0u;
         index < sizeof(legacy_prefixes) / sizeof(legacy_prefixes[0]);
         ++index) {
        expect_error("EVEX legacy prefix collision", CDISASM_CPU_X86,
            CDISASM_MODE_64, legacy_prefixes[index],
            sizeof(legacy_prefixes[index]), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("VEX legacy prefix collision", CDISASM_CPU_X86,
            CDISASM_MODE_64, vex_prefixes[index],
            sizeof(vex_prefixes[index]), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 0u; index < sizeof(pp_reserved) / sizeof(pp_reserved[0]);
         ++index) {
        expect_error("reserved scalar-prefix selector", CDISASM_CPU_X86,
            CDISASM_MODE_64, pp_reserved[index], sizeof(pp_reserved[index]),
            NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("reserved VEX pp truncated", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf2,0x56},3u,NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("legacy-prefixed VEX truncated", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc5,0xf0,0x56},4u,NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved EVEX pp truncated", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x62,0xf1,0x76,0x08,0x56},5u,NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("legacy-prefixed EVEX truncated", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x66,0x62,0xf1,0x74,0x08,0x56},6u,NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated VEX2 ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex_prefixes[0] + 1u,3u,NULL,
        CDISASM_STATUS_TRUNCATED);
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
        {{0xc5,0xf0,0x56,0xc2,0,0,0},4,
            CDISASM_X86_DECODE_BIT_AVX,
            "vorps xmm0, xmm1, xmm2",
            "vorps %xmm2, %xmm1, %xmm0"},
        {{0xc5,0xf5,0x56,0x48,0x7f,0,0},5,
            CDISASM_X86_DECODE_BIT_AVX,
            "vorpd ymm1, ymm1, ymmword ptr [rax + 0x7f]",
            "vorpd 0x7f(%rax), %ymm1, %ymm1"},
        {{0x62,0xf1,0x74,0x09,0x56,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX512DQ_128,
            "vorps xmm0 {k1}, xmm1, xmm2",
            "vorps %xmm2, %xmm1, %xmm0{%k1}"},
        {{0x62,0xf1,0xbd,0xbb,0x56,0x38,0},6,
            CDISASM_X86_DECODE_BIT_AVX512DQ_256,
            "vorpd ymm7 {k3}{z}, ymm8, qword ptr [rax]{1to4}",
            "vorpd (%rax){1to4}, %ymm8, %ymm7{%k3}{z}"},
        {{0x62,0xf1,0x74,0x48,0x56,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512DQ_512,
            "vorps zmm0, zmm1, zmmword ptr [rax - 0x40]",
            "vorps -0x40(%rax), %zmm1, %zmm0"},
        {{0x62,0x01,0x0c,0x40,0x56,0xfd,0},6,
            CDISASM_X86_DECODE_BIT_AVX512DQ_512,
            "vorps zmm31, zmm30, zmm29",
            "vorps %zmm29, %zmm30, %zmm31"}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags = one_bit(cases[index].bit);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
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
            CDISASM_FORMAT_SYNTAX_ATT, output, sizeof(output))
            == required);
        EXPECT(strcmp(output, cases[index].att) == 0);
    }
#endif
}

int main(void)
{
    test_vex_exhaustive();
    test_evex_exhaustive();
    test_apx_exhaustive();
    test_non64_ignored_extensions_and_collisions();
    test_prefixes_high_registers_masks_tuples_and_apx();
    test_runtime_bits_and_profiles();
    test_reserved_collisions_and_truncated();
    test_formatting();

    if (failures != 0) {
        fprintf(stderr, "x86 classic VOR tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 classic VOR tests passed");
    return 0;
}
