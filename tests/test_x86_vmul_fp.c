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

_Static_assert(CDISASM_X86_NAME_VMULPS == UINT16_C(618)
        && CDISASM_X86_NAME_VMULPD == UINT16_C(619)
        && CDISASM_X86_NAME_VMULSS == UINT16_C(620)
        && CDISASM_X86_NAME_VMULSD == UINT16_C(621),
    "classic VMUL name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX512F_128 == UINT16_C(180)
        && CDISASM_X86_GROUP_AVX512F_256 == UINT16_C(182)
        && CDISASM_X86_GROUP_AVX512F_512 == UINT16_C(183)
        && CDISASM_X86_GROUP_AVX512F_SCALAR == UINT16_C(185),
    "classic VMUL ISA-set IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512F_128 == UINT32_C(128)
        && CDISASM_X86_DECODE_BIT_AVX512F_256 == UINT32_C(130)
        && CDISASM_X86_DECODE_BIT_AVX512F_512 == UINT32_C(131)
        && CDISASM_X86_DECODE_BIT_AVX512F_SCALAR == UINT32_C(133),
    "classic VMUL runtime-bit IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update classic VMUL profile sweeps");

typedef struct vmul_family {
    cdisasm_x86_name_id name_id;
    uint8_t pp;
    uint8_t w;
    uint8_t element_bytes;
    uint8_t scalar;
    cdisasm_x86_form_id vex_xmm_base;
    cdisasm_x86_form_id vex_ymm_base;
    cdisasm_x86_form_id evex_base;
} vmul_family;

static const vmul_family families[] = {
    {CDISASM_X86_NAME_VMULPD,1,1,8,0,6012,6018,6014},
    {CDISASM_X86_NAME_VMULPS,0,0,4,0,6028,6034,6030},
    {CDISASM_X86_NAME_VMULSD,3,1,8,1,6038,6038,6040},
    {CDISASM_X86_NAME_VMULSS,2,0,4,1,6044,6044,6046}
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
    const vmul_family *family,
    unsigned int l,
    int register_form)
{
    const cdisasm_x86_form_id base = family->scalar || l == 0u
        ? family->vex_xmm_base : family->vex_ymm_base;

    return (cdisasm_x86_form_id)(base + (register_form ? 1u : 0u));
}

static cdisasm_x86_form_id evex_form(
    const vmul_family *family,
    unsigned int ll,
    int register_form,
    int embedded_rounding)
{
    if (family->scalar) {
        return (cdisasm_x86_form_id)(family->evex_base
            + (register_form ? 1u : 0u));
    }
    if (embedded_rounding) {
        return (cdisasm_x86_form_id)(family->evex_base + 7u);
    }
    return (cdisasm_x86_form_id)(family->evex_base
        + (ll == 2u ? 6u : 2u * ll)
        + (register_form ? 1u : 0u));
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_group_id width_group(
    const vmul_family *family,
    unsigned int effective_ll)
{
    if (family->scalar) {
        return CDISASM_X86_GROUP_AVX512F_SCALAR;
    }
    return effective_ll == 0u ? CDISASM_X86_GROUP_AVX512F_128
        : effective_ll == 1u ? CDISASM_X86_GROUP_AVX512F_256
                             : CDISASM_X86_GROUP_AVX512F_512;
}

static cdisasm_x86_decode_bit_id width_bit(
    const vmul_family *family,
    unsigned int effective_ll)
{
    if (family->scalar) {
        return CDISASM_X86_DECODE_BIT_AVX512F_SCALAR;
    }
    return effective_ll == 0u ? CDISASM_X86_DECODE_BIT_AVX512F_128
        : effective_ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512F_256
                             : CDISASM_X86_DECODE_BIT_AVX512F_512;
}

static void check_vmul(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    const vmul_family *family,
    cdisasm_x86_form_id form_id,
    int evex,
    unsigned int encoded_ll,
    int register_form,
    int broadcast,
    unsigned int aaa,
    int zero,
    int apx,
    cdisasm_x86_rounding_mode rounding)
{
    const int embedded_rounding = evex && register_form
        && rounding != CDISASM_X86_ROUNDING_NONE;
    const unsigned int effective_ll = family->scalar ? 0u
        : embedded_rounding ? 2u : encoded_ll;
    const unsigned int vector_bytes = 16u << effective_ll;
    const unsigned int memory_bytes = family->scalar || broadcast
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
    EXPECT(instruction->rounding == rounding);
    EXPECT(instruction->sae == (rounding == CDISASM_X86_ROUNDING_NONE
        ? CDISASM_X86_SAE_NONE : CDISASM_X86_SAE_ENABLED));
    EXPECT(instruction->encoding.immediate_count == 0u);
    if (evex) {
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, width_group(family, effective_ll)));
    } else {
        EXPECT(!cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512F_128));
        EXPECT(!cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512F_256));
        EXPECT(!cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512F_512));
        EXPECT(!cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512F_SCALAR));
    }
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    const vmul_family *family,
    cdisasm_x86_form_id form_id,
    int evex,
    unsigned int encoded_ll,
    int register_form,
    int broadcast,
    unsigned int aaa,
    int zero,
    int apx,
    cdisasm_x86_rounding_mode rounding)
{
#if USE_EXTRA_OPCODES
    check_vmul(instruction, decoded_size, family, form_id, evex,
        encoded_ll, register_form, broadcast, aaa, zero, apx, rounding);
#else
    (void)family;
    (void)form_id;
    (void)evex;
    (void)encoded_ll;
    (void)register_form;
    (void)broadcast;
    (void)aaa;
    (void)zero;
    (void)apx;
    (void)rounding;
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
    uint64_t forms[6048] = {0};
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
            const vmul_family *family = &families[family_index];
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
                            size_t size;
                            uint32_t decoded_size;
                            cdisasm_instruction instruction;

                            if (vex_size == 2u) {
                                code[0] = UINT8_C(0xc5);
                                code[1] = (uint8_t)(UINT8_C(0xf0)
                                    | (l << 2) | family->pp);
                                code[2] = UINT8_C(0x59);
                                code[3] = (uint8_t)modrm;
                                size = sizeof(code);
                            } else {
                                code[0] = UINT8_C(0xc4);
                                code[1] = UINT8_C(0xe1);
                                code[2] = (uint8_t)((encoded_w << 7)
                                    | UINT8_C(0x70) | (l << 2)
                                    | family->pp);
                                code[3] = UINT8_C(0x59);
                                code[4] = (uint8_t)modrm;
                                size = sizeof(code);
                            }
                            code[vex_size + 2u] = UINT8_C(0x24);
                            code[vex_size + 3u] = UINT8_C(0x10);
                            code[vex_size + 4u] = UINT8_C(0x20);
                            code[vex_size + 5u] = UINT8_C(0x30);
                            code[vex_size + 6u] = UINT8_C(0x40);

                            instruction = decode(CDISASM_CPU_X86,
                                modes[mode_index], code, size,
#if USE_EXTRA_OPCODES
                                &flags, &decoded_size);
#else
                                NULL, &decoded_size);
#endif
                            check_allocated(&instruction, decoded_size, family,
                                form_id, 0, family->scalar ? 0u : l,
                                reg, 0,0u,0,0,
                                CDISASM_X86_ROUNDING_NONE);
                            ++forms[form_id];
                            ++allocated;
                        }
                    }
                }
            }
        }
    }
    EXPECT(allocated == UINT64_C(18432));
    EXPECT(forms[6012] != 0u && forms[6013] != 0u);
    EXPECT(forms[6018] != 0u && forms[6019] != 0u);
    EXPECT(forms[6028] != 0u && forms[6029] != 0u);
    EXPECT(forms[6034] != 0u && forms[6035] != 0u);
    EXPECT(forms[6038] != 0u && forms[6039] != 0u);
    EXPECT(forms[6044] != 0u && forms[6045] != 0u);
}

static void test_evex_exhaustive(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint64_t forms[6048] = {0};
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
            const vmul_family *family = &families[family_index];
            unsigned int ll;

            for (ll = 0u; ll < 4u; ++ll) {
                unsigned int b;

                for (b = 0u; b < 2u; ++b) {
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const int reg = (modrm & UINT8_C(0xc0))
                            == UINT8_C(0xc0);
                        const int er = reg && b != 0u;
                        const int valid = er || (ll < 3u
                            && (!family->scalar || b == 0u));
                        const cdisasm_x86_form_id form_id = evex_form(
                            family, ll, reg, er);
                        const uint8_t code[15] = {
                            0x62,0xf1,
                            (uint8_t)((family->w << 7)
                                | UINT8_C(0x74) | family->pp),
                            (uint8_t)(UINT8_C(0x08) | (ll << 5)
                                | (b << 4)),
                            0x59,(uint8_t)modrm,0x24,0x10,0x20,
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
                            form_id,1,ll,reg,
                            !family->scalar && !reg && b != 0u,
                            0u,0,0,er
                                ? (cdisasm_x86_rounding_mode)(ll + 1u)
                                : CDISASM_X86_ROUNDING_NONE);
                        ++forms[form_id];
                        ++allocated;
                    }
                }
            }
        }
    }
    EXPECT(allocated == UINT64_C(15744));
    EXPECT(reserved == UINT64_C(8832));
    EXPECT(forms[6014] != 0u && forms[6015] != 0u);
    EXPECT(forms[6016] != 0u && forms[6017] != 0u);
    EXPECT(forms[6020] != 0u && forms[6021] != 0u);
    EXPECT(forms[6030] != 0u && forms[6031] != 0u);
    EXPECT(forms[6032] != 0u && forms[6033] != 0u);
    EXPECT(forms[6036] != 0u && forms[6037] != 0u);
    EXPECT(forms[6040] != 0u && forms[6041] != 0u);
    EXPECT(forms[6046] != 0u && forms[6047] != 0u);
}

static void test_legal_prefixes_before_vex(void)
{
    static const uint8_t address_size[] = {
        0x67,0xc5,0xf0,0x59,0xc2
    };
    static const uint8_t segment[] = {
        0x2e,0xc4,0xe1,0x70,0x59,0x00
    };
#if USE_EXTRA_OPCODES
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
        UINT16_C(6029),0,0u,1,0,0u,0,0,
        CDISASM_X86_ROUNDING_NONE);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        segment, sizeof(segment),
#if USE_EXTRA_OPCODES
        &flags, &decoded_size);
#else
        NULL, &decoded_size);
#endif
    check_allocated(&instruction, decoded_size, &families[1],
        UINT16_C(6028),0,0u,0,0,0u,0,0,
        CDISASM_X86_ROUNDING_NONE);
}

static void test_evex_high_registers(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t packed[] = {
        0x62,0x01,0x0c,0x40,0x59,0xfd
    };
    static const uint8_t scalar[] = {
        0x62,0x01,0x8f,0x00,0x59,0xfd
    };
    cdisasm_x86_decode_flags flags =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_512);
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        packed, sizeof(packed), &flags, &decoded_size);

    check_vmul(&instruction, decoded_size, &families[1],
        UINT16_C(6037),1,2u,1,0,0u,0,0,
        CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ZMM31);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ZMM30);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_ZMM29);

    flags = one_bit(CDISASM_X86_DECODE_BIT_AVX512F_SCALAR);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        scalar, sizeof(scalar), &flags, &decoded_size);
    check_vmul(&instruction, decoded_size, &families[2],
        UINT16_C(6041),1,0u,1,0,0u,0,0,
        CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM31);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM30);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM29);
#endif
}

static void test_masks_tuples_apx_and_rounding(void)
{
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t family_index;

    for (family_index = 0u;
         family_index < sizeof(families) / sizeof(families[0]);
         ++family_index) {
        const vmul_family *family = &families[family_index];
        const unsigned int ll = family->scalar ? 0u : 1u;
        uint8_t merge[] = {0x62,0xf1,0,0x09,0x59,0xc2};
        uint8_t zero[] = {0x62,0xf1,0,0x89,0x59,0xc2};
        uint8_t full[] = {0x62,0xf1,0,0x08,0x59,0x40,0xff};
        uint8_t tuple[] = {0x62,0xf1,0,0x18,0x59,0x40,0xff};
        uint8_t b4_reg[] = {0x62,0xf9,0,0x08,0x59,0xc2};
        uint8_t b4_mem[] = {0x62,0xf9,0,0x08,0x59,0x02};
        uint8_t x4_mem[] = {0x62,0xf1,0,0x08,0x59,0x04,0xa4};
        cdisasm_x86_decode_flags apx_flags = two_bits(
            width_bit(family, family->scalar ? 0u : ll),
            CDISASM_X86_DECODE_BIT_APX);
        uint32_t decoded_size;
        cdisasm_instruction instruction;
        unsigned int rc;

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
        check_vmul(&instruction, decoded_size, family,
            evex_form(family,ll,1,0),1,ll,1,0,1u,0,0,
            CDISASM_X86_ROUNDING_NONE);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            zero, sizeof(zero), &flags, &decoded_size);
        check_vmul(&instruction, decoded_size, family,
            evex_form(family,ll,1,0),1,ll,1,0,1u,1,0,
            CDISASM_X86_ROUNDING_NONE);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            full, sizeof(full), &flags, &decoded_size);
        check_vmul(&instruction, decoded_size, family,
            evex_form(family,ll,0,0),1,ll,0,0,0u,0,0,
            CDISASM_X86_ROUNDING_NONE);
        EXPECT(instruction.opcode[2].imm == (uint64_t)(
            family->scalar ? -(int64_t)family->element_bytes
                           : -(INT64_C(16) << ll)));
        if (!family->scalar) {
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                tuple, sizeof(tuple), &flags, &decoded_size);
            check_vmul(&instruction, decoded_size, family,
                evex_form(family,ll,0,0),1,ll,0,1,0u,0,0,
                CDISASM_X86_ROUNDING_NONE);
            EXPECT(instruction.opcode[2].imm
                == (uint64_t)(-(int64_t)family->element_bytes));
        } else {
            expect_error("scalar memory EVEX.b", CDISASM_CPU_X86,
                CDISASM_MODE_64, tuple, sizeof(tuple), &flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            b4_reg, sizeof(b4_reg), &apx_flags, &decoded_size);
        check_vmul(&instruction, decoded_size, family,
            evex_form(family,ll,1,0),1,ll,1,0,0u,0,1,
            CDISASM_X86_ROUNDING_NONE);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM2
            || instruction.opcode[2].reg == CDISASM_X86_REG_YMM2);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            b4_mem, sizeof(b4_mem), &apx_flags, &decoded_size);
        EXPECT(decoded_size == sizeof(b4_mem));
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R18);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            x4_mem, sizeof(x4_mem), &apx_flags, &decoded_size);
        EXPECT(decoded_size == sizeof(x4_mem));
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R20);

        for (rc = 0u; rc < 4u; ++rc) {
            uint8_t round[] = {0x62,0xf1,0,0x18,0x59,0xc2};
            const unsigned int round_ll = rc;

            round[2] = (uint8_t)((family->w << 7)
                | UINT8_C(0x74) | family->pp);
            round[3] = (uint8_t)(UINT8_C(0x18) | (round_ll << 5));
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                round, sizeof(round), &flags, &decoded_size);
            check_vmul(&instruction, decoded_size, family,
                evex_form(family,round_ll,1,1),1,round_ll,1,0,
                0u,0,0,(cdisasm_x86_rounding_mode)(rc + 1u));
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
        CDISASM_CPU_AMD_ZEN, CDISASM_CPU_ARROW_LAKE
    };
    static const uint8_t vex[] = {0xc5,0xf0,0x59,0xc2};
    static const uint8_t evex[] = {0x62,0xf1,0x74,0x08,0x59,0xc2};
    static const uint8_t evex_512[] = {
        0x62,0xf1,0x74,0x48,0x59,0xc2
    };
    static const uint8_t evex_scalar[] = {
        0x62,0xf1,0x76,0x08,0x59,0xc2
    };
    cdisasm_x86_decode_flags avx = one_bit(CDISASM_X86_DECODE_BIT_AVX);
    cdisasm_x86_decode_flags exact =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_128);
    cdisasm_x86_decode_flags wrong =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_256);
    cdisasm_x86_decode_flags umbrella =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512);
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
        EXPECT(instruction.form_id == UINT16_C(6029));
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
        EXPECT(decoded_size == sizeof(evex));
        EXPECT(instruction.form_id == UINT16_C(6031));
    }
    for (index = 0u;
         index < sizeof(evex_negative) / sizeof(evex_negative[0]); ++index) {
        cdisasm_x86_decode_flags available;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(evex_negative[index],
            CDISASM_MODE_64, &available) == CDISASM_STATUS_OK);
        expect_error("profile lacks EVEX VMUL", evex_negative[index],
            CDISASM_MODE_64, evex, sizeof(evex), &available,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    {
        cdisasm_x86_decode_flags available;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_KNIGHTS_MILL,
            CDISASM_MODE_64, &available) == CDISASM_STATUS_OK);
        expect_error("Knights Mill lacks AVX512VL VMUL width",
            CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
            evex, sizeof(evex), &available,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        instruction = decode(CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
            evex_512, sizeof(evex_512), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(evex_512));
        EXPECT(instruction.form_id == UINT16_C(6037));
        instruction = decode(CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
            evex_scalar, sizeof(evex_scalar), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(evex_scalar));
        EXPECT(instruction.form_id == UINT16_C(6047));
    }
    expect_error("EVEX width mismatch", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex, sizeof(evex), &wrong,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("EVEX umbrella is not exact", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex, sizeof(evex), &umbrella,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, evex, sizeof(evex), &exact, &decoded_size);

        EXPECT(decoded_size == sizeof(evex));
        EXPECT(instruction.form_id == UINT16_C(6031));
    }
#else
    static const uint8_t vex[] = {0xc5,0xf0,0x59,0xc2};
    static const uint8_t evex[] = {0x62,0xf1,0x74,0x08,0x59,0xc2};

    expect_error("VEX extras off", CDISASM_CPU_X86, CDISASM_MODE_64,
        vex, sizeof(vex), NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("EVEX extras off", CDISASM_CPU_X86, CDISASM_MODE_64,
        evex, sizeof(evex), NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_and_truncated(void)
{
    static const struct invalid_case {
        const char *label;
        uint8_t code[7];
        size_t size;
        cdisasm_x86_mode mode;
    } invalid[] = {
        {"PS W1",{0x62,0xf1,0xf4,0x08,0x59,0xc2,0},6,CDISASM_MODE_64},
        {"PD W0",{0x62,0xf1,0x75,0x08,0x59,0xc2,0},6,CDISASM_MODE_64},
        {"SS W1",{0x62,0xf1,0xf6,0x08,0x59,0xc2,0},6,CDISASM_MODE_64},
        {"SD W0",{0x62,0xf1,0x77,0x08,0x59,0xc2,0},6,CDISASM_MODE_64},
        {"packed LL3",{0x62,0xf1,0x74,0x68,0x59,0xc2,0},6,CDISASM_MODE_64},
        {"scalar LL3 memory",{0x62,0xf1,0x76,0x68,0x59,0x00,0},6,CDISASM_MODE_64},
        {"scalar memory b",{0x62,0xf1,0x76,0x18,0x59,0x00,0},6,CDISASM_MODE_64},
        {"z without mask",{0x62,0xf1,0x74,0x88,0x59,0xc2,0},6,CDISASM_MODE_64},
        {"U0 register",{0x62,0xf1,0x70,0x08,0x59,0xc2,0},6,CDISASM_MODE_64},
        {"B4 non-long",{0x62,0xf9,0x74,0x08,0x59,0xc2,0},6,CDISASM_MODE_32},
        {"V prime non-long",{0x62,0xf1,0x74,0x00,0x59,0xc2,0},6,CDISASM_MODE_32}
    };
    static const uint8_t valid[] = {0x62,0xf1,0x74,0x08,0x59,0xc2};
    static const uint8_t missing_sib[] = {
        0x62,0xf1,0x74,0x08,0x59,0x04
    };
    static const uint8_t missing_disp8[] = {
        0x62,0xf1,0x74,0x08,0x59,0x40
    };
    static const uint8_t legacy_prefixes[][7] = {
        {0x66,0x62,0xf1,0x74,0x08,0x59,0xc2},
        {0xf2,0x62,0xf1,0xf7,0x08,0x59,0xc2},
        {0xf3,0x62,0xf1,0x76,0x08,0x59,0xc2},
        {0xf0,0x62,0xf1,0x74,0x08,0x59,0xc2},
        {0x48,0x62,0xf1,0x74,0x08,0x59,0xc2}
    };
    static const struct deferred_case {
        uint8_t p1;
        uint8_t p2;
    } deferred[] = {
        {0xf4,0x08},{0x75,0x08},{0xf6,0x08},{0x77,0x08},
        {0x74,0x88},{0x70,0x08}
    };
    size_t index;

    for (index = 1u; index < sizeof(valid); ++index) {
        expect_error("truncated classic EVEX VMUL", CDISASM_CPU_X86,
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
            0x62,0xf1,deferred[index].p1,deferred[index].p2,0x59,0
        };

        expect_error("deferred VMUL control", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, 5u, NULL, CDISASM_STATUS_TRUNCATED);
        code[5] = UINT8_C(0x04);
        expect_error("deferred VMUL SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, sizeof(code), NULL,
            CDISASM_STATUS_TRUNCATED);
        code[5] = UINT8_C(0x40);
        expect_error("deferred VMUL disp8", CDISASM_CPU_X86,
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
        expect_error("legacy prefix collision", CDISASM_CPU_X86,
            CDISASM_MODE_64, legacy_prefixes[index],
            sizeof(legacy_prefixes[index]), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
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
        {{0xc5,0xf0,0x59,0xc2,0,0,0},4,
            CDISASM_X86_DECODE_BIT_AVX,
            "vmulps xmm0, xmm1, xmm2",
            "vmulps %xmm2, %xmm1, %xmm0"},
        {{0xc5,0xf5,0x59,0x48,0x7f,0,0},5,
            CDISASM_X86_DECODE_BIT_AVX,
            "vmulpd ymm1, ymm1, ymmword ptr [rax + 0x7f]",
            "vmulpd 0x7f(%rax), %ymm1, %ymm1"},
        {{0xc5,0xf2,0x59,0x00,0,0,0},4,
            CDISASM_X86_DECODE_BIT_AVX,
            "vmulss xmm0, xmm1, dword ptr [rax]",
            "vmulss (%rax), %xmm1, %xmm0"},
        {{0xc5,0xf3,0x59,0xc2,0,0,0},4,
            CDISASM_X86_DECODE_BIT_AVX,
            "vmulsd xmm0, xmm1, xmm2",
            "vmulsd %xmm2, %xmm1, %xmm0"},
        {{0x62,0xf1,0x74,0x09,0x59,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX512F_128,
            "vmulps xmm0 {k1}, xmm1, xmm2",
            "vmulps %xmm2, %xmm1, %xmm0{%k1}"},
        {{0x62,0xf1,0xbd,0xbb,0x59,0x38,0},6,
            CDISASM_X86_DECODE_BIT_AVX512F_256,
            "vmulpd ymm7 {k3}{z}, ymm8, qword ptr [rax]{1to4}",
            "vmulpd (%rax){1to4}, %ymm8, %ymm7{%k3}{z}"},
        {{0x62,0xf1,0x74,0x59,0x59,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX512F_512,
            "vmulps zmm0 {k1}, zmm1, zmm2, {ru-sae}",
            "vmulps {ru-sae}, %zmm2, %zmm1, %zmm0{%k1}"},
        {{0x62,0xf1,0xf7,0x89,0x59,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512F_SCALAR,
            "vmulsd xmm0 {k1}{z}, xmm1, qword ptr [rax - 0x8]",
            "vmulsd -0x8(%rax), %xmm1, %xmm0{%k1}{z}"},
        {{0x62,0xf1,0x76,0x79,0x59,0xc2,0},6,
            CDISASM_X86_DECODE_BIT_AVX512F_SCALAR,
            "vmulss xmm0 {k1}, xmm1, xmm2, {rz-sae}",
            "vmulss {rz-sae}, %xmm2, %xmm1, %xmm0{%k1}"}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags = one_bit(cases[index].bit);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        char output[192];
        size_t required;

        EXPECT(decoded_size == cases[index].size);
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, NULL, 0u);
        EXPECT(required == strlen(cases[index].intel));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output))
            == required);
        if (strcmp(output, cases[index].intel) != 0) {
            fprintf(stderr, "Intel format: got '%s', expected '%s'\n",
                output, cases[index].intel);
            EXPECT(0);
        }
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT, NULL, 0u);
        EXPECT(required == strlen(cases[index].att));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT, output, sizeof(output))
            == required);
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
    test_vex_exhaustive();
    test_evex_exhaustive();
    test_legal_prefixes_before_vex();
    test_evex_high_registers();
    test_masks_tuples_apx_and_rounding();
    test_runtime_bits_and_profiles();
    test_reserved_and_truncated();
    test_formatting();

    if (failures != 0) {
        fprintf(stderr, "x86 classic VMUL tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 classic VMUL tests passed");
    return 0;
}
