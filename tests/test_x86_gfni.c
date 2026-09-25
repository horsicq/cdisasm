#include "cdisasm/cdisasm_x86.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct gfni_family {
    uint8_t map;
    uint8_t opcode;
    uint8_t w;
    uint8_t affine;
    cdisasm_x86_name_id legacy_name;
    cdisasm_x86_name_id vector_name;
    cdisasm_x86_form_id legacy_base;
    cdisasm_x86_form_id vector_base;
    const char *mnemonic;
} gfni_family;

static const gfni_family families[] = {
    {3,0xcf,1,1,CDISASM_X86_NAME_GF2P8AFFINEINVQB,
        CDISASM_X86_NAME_VGF2P8AFFINEINVQB,1308,5505,
        "vgf2p8affineinvqb"},
    {3,0xce,1,1,CDISASM_X86_NAME_GF2P8AFFINEQB,
        CDISASM_X86_NAME_VGF2P8AFFINEQB,1310,5515,
        "vgf2p8affineqb"},
    {2,0xcf,0,0,CDISASM_X86_NAME_GF2P8MULB,
        CDISASM_X86_NAME_VGF2P8MULB,1312,5525,
        "vgf2p8mulb"}
};

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

_Static_assert(CDISASM_X86_NAME_GF2P8AFFINEINVQB == UINT16_C(1322)
        && CDISASM_X86_NAME_GF2P8AFFINEQB == UINT16_C(1323)
        && CDISASM_X86_NAME_GF2P8MULB == UINT16_C(1324)
        && CDISASM_X86_NAME_VGF2P8AFFINEINVQB == UINT16_C(1737)
        && CDISASM_X86_NAME_VGF2P8AFFINEQB == UINT16_C(1738)
        && CDISASM_X86_NAME_VGF2P8MULB == UINT16_C(1739),
    "GFNI name IDs changed");

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
    cdisasm_x86_cpu_id cpu,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu, mode, code, size, UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static void expect_error(
    const char *label,
    cdisasm_x86_cpu_id cpu,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu, mode, code, size, flags, &decoded_size);

    if (decoded_size != 0u || !is_error_only(&instruction, status)) {
        fprintf(stderr, "%s: got size/status %u/%u, expected 0/%u\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id,
            (unsigned int)status);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

static cdisasm_x86_decode_flags cpu_flags(
    cdisasm_x86_cpu_id cpu,
    cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(cpu, mode, &flags)
        == CDISASM_STATUS_OK);
    return flags;
}

static size_t make_legacy(
    const gfni_family *family,
    uint8_t modrm,
    uint8_t code[8])
{
    size_t size = 0u;

    code[size++] = UINT8_C(0x66);
    code[size++] = UINT8_C(0x0f);
    code[size++] = (uint8_t)(family->map == 2u ? 0x38u : 0x3au);
    code[size++] = family->opcode;
    code[size++] = modrm;
    if (family->affine) {
        code[size++] = UINT8_C(0x5a);
    }
    return size;
}

static size_t make_vex(
    const gfni_family *family,
    unsigned int l,
    uint8_t modrm,
    uint8_t code[8])
{
    size_t size = 0u;

    code[size++] = UINT8_C(0xc4);
    code[size++] = (uint8_t)(UINT8_C(0xe0) | family->map);
    code[size++] = (uint8_t)(UINT8_C(0x69)
        | (family->w << 7) | (l << 2));
    code[size++] = family->opcode;
    code[size++] = modrm;
    if (family->affine) {
        code[size++] = UINT8_C(0x5a);
    }
    return size;
}

static size_t make_evex(
    const gfni_family *family,
    unsigned int ll,
    uint8_t p2_low,
    uint8_t modrm,
    uint8_t code[9])
{
    size_t size = 0u;

    code[size++] = UINT8_C(0x62);
    code[size++] = (uint8_t)(UINT8_C(0xf0) | family->map);
    code[size++] = (uint8_t)(UINT8_C(0x6d) | (family->w << 7));
    code[size++] = (uint8_t)((ll << 5) | p2_low);
    code[size++] = family->opcode;
    code[size++] = modrm;
    if (family->affine) {
        code[size++] = UINT8_C(0x5a);
    }
    return size;
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id vector_reg(
    unsigned int ll,
    unsigned int index)
{
    const cdisasm_x86_reg_id base = ll == 0u ? CDISASM_X86_REG_XMM0
        : ll == 1u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_ZMM0;

    return (cdisasm_x86_reg_id)(base + index);
}

static cdisasm_x86_group_id width_group(unsigned int ll)
{
    return ll == 0u ? CDISASM_X86_GROUP_AVX512_GFNI_128
        : ll == 1u ? CDISASM_X86_GROUP_AVX512_GFNI_256
                   : CDISASM_X86_GROUP_AVX512_GFNI_512;
}

static cdisasm_x86_decode_bit_id width_bit(unsigned int ll)
{
    return ll == 0u ? CDISASM_X86_DECODE_BIT_AVX512_GFNI_128
        : ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512_GFNI_256
                   : CDISASM_X86_DECODE_BIT_AVX512_GFNI_512;
}

static void check_operands(
    const gfni_family *family,
    const cdisasm_instruction *instruction,
    int encoding,
    unsigned int ll,
    int register_form)
{
    const unsigned int bytes = 16u << ll;
    const unsigned int sources = encoding == 0 ? 1u : 2u;
    const unsigned int rm_index = sources;

    EXPECT(instruction->operand_count
        == 1u + sources + (family->affine ? 1u : 0u));
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg == vector_reg(ll, 1u));
    EXPECT(instruction->opcode[0].size == bytes);
    EXPECT(instruction->opcode[0].access
        == ((encoding == 0
                || (encoding == 2
                    && instruction->mask_mode == CDISASM_X86_MASK_MERGE))
            ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_WRITE));
    if (encoding != 0) {
        EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction->opcode[1].reg == vector_reg(ll, 2u));
        EXPECT(instruction->opcode[1].size == bytes);
        EXPECT(instruction->opcode[1].access
            == CDISASM_OPERAND_ACCESS_READ);
    }
    EXPECT(instruction->opcode[rm_index].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[rm_index].size == bytes);
    EXPECT(instruction->opcode[rm_index].access
        == CDISASM_OPERAND_ACCESS_READ);
    if (register_form) {
        EXPECT(instruction->opcode[rm_index].reg == vector_reg(ll, 3u));
    } else {
        EXPECT(instruction->opcode[rm_index].base_reg
            == CDISASM_X86_REG_RAX);
        EXPECT(instruction->opcode[rm_index].broadcast
            == CDISASM_X86_BROADCAST_NONE);
    }
    if (family->affine) {
        const cdisasm_opcode *immediate =
            &instruction->opcode[1u + sources];

        EXPECT(immediate->type == CDISASM_OPERAND_IMMEDIATE);
        EXPECT(immediate->size == 1u);
        EXPECT(immediate->imm == UINT64_C(0x5a));
        EXPECT(immediate->access == CDISASM_OPERAND_ACCESS_READ);
    }
}

static void check_form(
    const gfni_family *family,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    int encoding,
    unsigned int ll,
    int register_form)
{
    cdisasm_x86_form_id form;

    if (encoding == 0) {
        form = (cdisasm_x86_form_id)(family->legacy_base
            + (register_form ? 1u : 0u));
    } else if (encoding == 1) {
        form = (cdisasm_x86_form_id)(family->vector_base
            + (ll == 0u ? 2u : 6u) + (register_form ? 1u : 0u));
    } else {
        form = (cdisasm_x86_form_id)(family->vector_base
            + 4u * ll + (register_form ? 1u : 0u));
    }

    EXPECT(decoded_size == expected_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (encoding == 0
        ? family->legacy_name : family->vector_name));
    EXPECT(instruction->form_id == form);
    EXPECT(instruction->encoding.opcode_size
        == (encoding == 0 ? 3u : 1u));
    EXPECT(instruction->encoding.immediate_count
        == (family->affine ? 1u : 0u));
    EXPECT(instruction->mask_mode == (encoding == 2
        ? CDISASM_X86_MASK_MERGE : CDISASM_X86_MASK_NONE));
    EXPECT(instruction->mask_reg == (encoding == 2
        ? CDISASM_X86_REG_K2 : CDISASM_X86_REG_NONE));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_GFNI));
    if (encoding == 0) {
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_I386));
    } else {
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX));
    }
    if (encoding == 1) {
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX_GFNI));
        EXPECT(!cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX2));
    } else if (encoding == 2) {
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512F));
        EXPECT(cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512VL)
            == (ll < 2u));
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, width_group(ll)));
    }
    check_operands(family, instruction, encoding, ll, register_form);
}
#endif

static void check_allocated(
    const gfni_family *family,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    int encoding,
    unsigned int ll,
    int register_form)
{
#if USE_EXTRA_OPCODES
    check_form(family, instruction, decoded_size, expected_size,
        encoding, ll, register_form);
#else
    (void)family;
    (void)expected_size;
    (void)encoding;
    (void)ll;
    (void)register_form;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_all_36_forms(void)
{
    cdisasm_x86_decode_flags flags = cpu_flags(
        CDISASM_CPU_X86, CDISASM_MODE_64);
    size_t family_index;
    unsigned int count = 0u;

    for (family_index = 0u;
         family_index < sizeof(families) / sizeof(families[0]);
         ++family_index) {
        const gfni_family *family = &families[family_index];
        unsigned int register_form;

        for (register_form = 0u; register_form < 2u; ++register_form) {
            uint8_t code[9] = {0};
            const size_t size = make_legacy(
                family, register_form ? UINT8_C(0xcb) : UINT8_C(0x08),
                code);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, size, &flags, &decoded_size);

            check_allocated(family, &instruction, decoded_size,
                size, 0, 0u, register_form != 0u);
            ++count;
        }
        for (register_form = 0u; register_form < 2u; ++register_form) {
            unsigned int ll;

            for (ll = 0u; ll < 2u; ++ll) {
                uint8_t code[9] = {0};
                const size_t size = make_vex(family, ll,
                    register_form ? UINT8_C(0xcb) : UINT8_C(0x08), code);
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, size, &flags, &decoded_size);

                check_allocated(family, &instruction, decoded_size,
                    size, 1, ll, register_form != 0u);
                ++count;
            }
        }
        for (register_form = 0u; register_form < 2u; ++register_form) {
            unsigned int ll;

            for (ll = 0u; ll < 3u; ++ll) {
                uint8_t code[9] = {0};
                const size_t size = make_evex(family, ll,
                    UINT8_C(0x0a),
                    register_form ? UINT8_C(0xcb) : UINT8_C(0x08), code);
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, size, &flags, &decoded_size);

                check_allocated(family, &instruction, decoded_size,
                    size, 2, ll, register_form != 0u);
                ++count;
            }
        }
    }
    EXPECT(count == 36u);
}

static void test_vex_selector_partition(void)
{
    cdisasm_x86_decode_flags flags = cpu_flags(
        CDISASM_CPU_X86, CDISASM_MODE_64);
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t family_index;

    for (family_index = 0u;
         family_index < sizeof(families) / sizeof(families[0]);
         ++family_index) {
        const gfni_family *family = &families[family_index];
        unsigned int control;

        for (control = 0u; control <= UINT8_MAX; ++control) {
            static const uint8_t modrms[2] = {0x08,0xcb};
            const int selected = (control & 3u) == 1u
                && ((control >> 7) & 1u) == family->w;
            size_t form_index;

            for (form_index = 0u; form_index < 2u; ++form_index) {
                uint8_t code[7] = {
                    0xc4,(uint8_t)(0xe0u | family->map),
                    (uint8_t)control,family->opcode,modrms[form_index],
                    0x5a,0
                };
                const size_t size = family->affine ? 6u : 5u;
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, size, &flags, &decoded_size);

                if (selected) {
#if USE_EXTRA_OPCODES
                    EXPECT(decoded_size == size);
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id == family->vector_name);
                    EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
                        family->vector_base
                        + ((control & 4u) != 0u ? 6u : 2u)
                        + (form_index != 0u ? 1u : 0u)));
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
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
    EXPECT(allocated == UINT64_C(192));
    EXPECT(reserved == UINT64_C(1344));
}

static void test_evex_selector_partition(void)
{
    cdisasm_x86_decode_flags flags = cpu_flags(
        CDISASM_CPU_X86, CDISASM_MODE_64);
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t family_index;

    for (family_index = 0u;
         family_index < sizeof(families) / sizeof(families[0]);
         ++family_index) {
        const gfni_family *family = &families[family_index];
        unsigned int p1;

        for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
            unsigned int p2;

            for (p2 = 0u; p2 <= UINT8_MAX; ++p2) {
                const unsigned int ll = (p2 >> 5) & 3u;
                const unsigned int aaa = p2 & 7u;
                const int selected = (p1 & 3u) == 1u
                    && ((p1 >> 7) & 1u) == family->w
                    && (p1 & 4u) != 0u
                    && ll != 3u
                    && (p2 & UINT8_C(0x10)) == 0u
                    && ((p2 & UINT8_C(0x80)) == 0u || aaa != 0u);
                uint8_t code[7] = {
                    0x62,(uint8_t)(0xf0u | family->map),(uint8_t)p1,
                    (uint8_t)p2,family->opcode,0xcb,0x5a
                };
                const size_t size = family->affine ? 7u : 6u;
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, size, &flags, &decoded_size);

                if (selected) {
#if USE_EXTRA_OPCODES
                    EXPECT(decoded_size == size);
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id == family->vector_name);
                    EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
                        family->vector_base + 4u * ll + 1u));
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
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
    EXPECT(allocated == UINT64_C(4320));
    EXPECT(reserved == UINT64_C(192288));
}

static void test_runtime_bits_and_profiles(void)
{
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_cpu_id gfni_cpus[] = {
        CDISASM_CPU_ICE_LAKE, CDISASM_CPU_TIGER_LAKE,
        CDISASM_CPU_ALDER_LAKE, CDISASM_CPU_AMD_ZEN_4,
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_CPU_AVX10,
        CDISASM_CPU_APX, CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_ARROW_LAKE, CDISASM_CPU_DIAMOND_RAPIDS
    };
    const gfni_family *family = &families[1];
    uint8_t legacy[9] = {0};
    uint8_t vex[9] = {0};
    uint8_t evex[9] = {0};
    const size_t legacy_size = make_legacy(family, UINT8_C(0xcb), legacy);
    const size_t vex_size = make_vex(family, 0u, UINT8_C(0xcb), vex);
    const size_t evex_size = make_evex(
        family, 2u, UINT8_C(0x0a), UINT8_C(0xcb), evex);
    cdisasm_x86_decode_flags all = cpu_flags(
        CDISASM_CPU_X86, CDISASM_MODE_64);
    cdisasm_x86_decode_flags missing;
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    size_t index;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vex, vex_size, &all, &decoded_size);
    EXPECT(decoded_size == vex_size);

    missing = all;
    missing.bitmap[0] &= ~CDISASM_X86_DECODE_FLAG_GFNI;
    expect_error("VEX independent GFNI runtime gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex, vex_size, &missing,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    missing = all;
    missing.bitmap[0] &= ~CDISASM_X86_DECODE_FLAG_AVX;
    expect_error("VEX AVX runtime gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex, vex_size, &missing,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    missing = all;
    EXPECT(cdisasm_decode_flags_clear_bit(
        &missing, CDISASM_X86_DECODE_BIT_AVX_GFNI));
    expect_error("VEX exact AVX_GFNI runtime gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex, vex_size, &missing,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    missing = all;
    missing.bitmap[0] &= ~CDISASM_X86_DECODE_FLAG_GFNI;
    expect_error("EVEX independent GFNI runtime gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex, evex_size, &missing,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    missing = all;
    missing.bitmap[0] &= ~CDISASM_X86_DECODE_FLAG_AVX512;
    expect_error("EVEX AVX-512 runtime gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex, evex_size, &missing,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    missing = all;
    EXPECT(cdisasm_decode_flags_clear_bit(&missing, width_bit(2u)));
    expect_error("EVEX exact GFNI width runtime gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex, evex_size, &missing,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    expect_error("pre-GFNI CPU profile", CDISASM_CPU_SKYLAKE,
        CDISASM_MODE_64, legacy, legacy_size, &all,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    for (index = 0u;
         index < sizeof(gfni_cpus) / sizeof(gfni_cpus[0]); ++index) {
        const cdisasm_x86_cpu_id cpu = gfni_cpus[index];
        cdisasm_x86_decode_flags flags = cpu_flags(cpu, CDISASM_MODE_64);

        EXPECT((flags.bitmap[0] & CDISASM_X86_DECODE_FLAG_GFNI) != 0u);
        instruction = decode(cpu, CDISASM_MODE_64,
            legacy, legacy_size, &flags, &decoded_size);
        EXPECT(decoded_size == legacy_size);
        EXPECT(instruction.name_id == family->legacy_name);
        instruction = decode(cpu, CDISASM_MODE_64,
            vex, vex_size, &flags, &decoded_size);
        EXPECT(decoded_size == vex_size);
        EXPECT(instruction.name_id == family->vector_name);
    }
    {
        cdisasm_x86_decode_flags n6000 = cpu_flags(
            CDISASM_CPU_PENTIUM_SILVER_N6000, CDISASM_MODE_64);

        EXPECT((n6000.bitmap[0] & CDISASM_X86_DECODE_FLAG_GFNI) != 0u);
        instruction = decode(CDISASM_CPU_PENTIUM_SILVER_N6000,
            CDISASM_MODE_64, legacy, legacy_size, &n6000, &decoded_size);
        EXPECT(decoded_size == legacy_size);
        expect_error("Tremont profile has no AVX", 
            CDISASM_CPU_PENTIUM_SILVER_N6000, CDISASM_MODE_64,
            vex, vex_size, &all, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    {
        static const cdisasm_x86_cpu_id evex_cpus[] = {
            CDISASM_CPU_ICE_LAKE, CDISASM_CPU_TIGER_LAKE,
            CDISASM_CPU_AMD_ZEN_4, CDISASM_CPU_SAPPHIRE_RAPIDS,
            CDISASM_CPU_AVX10, CDISASM_CPU_APX,
            CDISASM_CPU_GRANITE_RAPIDS, CDISASM_CPU_DIAMOND_RAPIDS
        };

        for (index = 0u;
             index < sizeof(evex_cpus) / sizeof(evex_cpus[0]); ++index) {
            const cdisasm_x86_cpu_id cpu = evex_cpus[index];
            cdisasm_x86_decode_flags flags = cpu_flags(
                cpu, CDISASM_MODE_64);

            instruction = decode(cpu, CDISASM_MODE_64,
                evex, evex_size, &flags, &decoded_size);
            EXPECT(decoded_size == evex_size);
            EXPECT(instruction.name_id == family->vector_name);
            if (cpu == CDISASM_CPU_AVX10 || cpu == CDISASM_CPU_APX) {
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX10_1));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512F));
            } else {
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512F));
            }
        }
    }
    {
        cdisasm_x86_decode_flags avx10 = cpu_flags(
            CDISASM_CPU_AVX10, CDISASM_MODE_64);

        avx10.bitmap[0] &= ~CDISASM_X86_DECODE_FLAG_AVX10;
        expect_error("EVEX AVX10 alternate runtime gate",
            CDISASM_CPU_AVX10, CDISASM_MODE_64,
            evex, evex_size, &avx10,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif
}

static void test_apx_u0_memory(void)
{
    static const uint8_t u0[] = {0x62,0xf3,0xe9,0x4a,0xce,0x08,0x5a};
    static const uint8_t u0_register[] = {
        0x62,0xf3,0xe9,0x4a,0xce,0xcb,0x5a
    };

#if USE_EXTRA_OPCODES
    static const uint8_t u0_broadcast[] = {
        0x62,0xf3,0xe9,0x5a,0xce,0x08,0x5a
    };
    static const uint8_t u0_x4[] = {
        0x62,0xf3,0xe9,0x4a,0xce,0x04,0x18,0x5a
    };
    static const uint8_t b4_u0_x4[] = {
        0x62,0xfb,0xe9,0x4a,0xce,0x04,0x18,0x5a
    };
    cdisasm_x86_decode_flags flags = cpu_flags(
        CDISASM_CPU_APX, CDISASM_MODE_64);
    cdisasm_x86_decode_flags no_apx = flags;
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_APX, CDISASM_MODE_64,
        u0, sizeof(u0), &flags, &decoded_size);

    EXPECT(decoded_size == sizeof(u0));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VGF2P8AFFINEQB);
    EXPECT(instruction.form_id == UINT16_C(5523));
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[2].size == 64u);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));

    instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
        u0_broadcast, sizeof(u0_broadcast), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(u0_broadcast));
    EXPECT(instruction.opcode[2].size == 8u);
    EXPECT(instruction.opcode[2].broadcast
        == CDISASM_X86_BROADCAST_1_TO_8);

    instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
        u0_x4, sizeof(u0_x4), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(u0_x4));
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R19);
    instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
        b4_u0_x4, sizeof(b4_u0_x4), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(b4_u0_x4));
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R16);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R19);

    no_apx.bitmap[0] &= ~CDISASM_X86_DECODE_FLAG_APX;
    expect_error("U0 APX runtime gate", CDISASM_CPU_APX,
        CDISASM_MODE_64, u0, sizeof(u0), &no_apx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("U0 APX CPU gate", CDISASM_CPU_AVX10,
        CDISASM_MODE_64, u0, sizeof(u0), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    cdisasm_x86_decode_flags flags = cpu_flags(
        CDISASM_CPU_X86, CDISASM_MODE_64);

    expect_error("GFNI extras OFF U0", CDISASM_CPU_X86,
        CDISASM_MODE_64, u0, sizeof(u0), &flags,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    {
        cdisasm_x86_decode_flags flags = cpu_flags(
            CDISASM_CPU_X86, CDISASM_MODE_64);

        expect_error("U0 register reserved", CDISASM_CPU_X86,
            CDISASM_MODE_64, u0_register, sizeof(u0_register), &flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("U0 non-long reserved", CDISASM_CPU_X86,
            CDISASM_MODE_32, u0, sizeof(u0), &flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_nonlong_aliases(void)
{
    static const cdisasm_x86_mode modes[2] = {
        CDISASM_MODE_16, CDISASM_MODE_32
    };
    static const uint8_t p0_aliases[4] = {0xf0,0xd0,0xe0,0xc0};
    size_t mode_index;

    for (mode_index = 0u; mode_index < 2u; ++mode_index) {
        cdisasm_x86_decode_flags flags = cpu_flags(
            CDISASM_CPU_X86, modes[mode_index]);
        size_t family_index;

        for (family_index = 0u;
             family_index < sizeof(families) / sizeof(families[0]);
             ++family_index) {
            const gfni_family *family = &families[family_index];
            unsigned int high_vvvv;
            size_t alias_index;

            for (alias_index = 0u;
                 alias_index < sizeof(p0_aliases) / sizeof(p0_aliases[0]);
                 ++alias_index) {
                for (high_vvvv = 0u; high_vvvv < 2u; ++high_vvvv) {
                    static const uint8_t modrms[2] = {0x08,0xcb};
                    size_t form_index;

                    for (form_index = 0u; form_index < 2u; ++form_index) {
                        uint8_t code[8] = {
                            0x62,
                            (uint8_t)(p0_aliases[alias_index] | family->map),
                            (uint8_t)(0x6d | (family->w << 7)
                                | (high_vvvv ? 0u : 0x40u)),
                            0x48,family->opcode,modrms[form_index],0x5a,0
                        };
                        const size_t size = family->affine ? 7u : 6u;
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_X86, modes[mode_index],
                            code, size, &flags, &decoded_size);

#if USE_EXTRA_OPCODES
                        EXPECT(decoded_size == size);
                        EXPECT(instruction.name_id == family->vector_name);
                        EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
                            family->vector_base + 8u
                            + (form_index != 0u ? 1u : 0u)));
                        EXPECT(instruction.opcode[0].reg
                            == CDISASM_X86_REG_ZMM1);
                        EXPECT(instruction.opcode[1].reg
                            == CDISASM_X86_REG_ZMM2);
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
    {
        static const uint8_t bad_r[] = {
            0x62,0x73,0xed,0x48,0xce,0xcb,0x5a
        };
        static const uint8_t bad_x[] = {
            0x62,0xb3,0xed,0x48,0xce,0xcb,0x5a
        };
        static const uint8_t bad_vprime[] = {
            0x62,0xf3,0xed,0x40,0xce,0xcb,0x5a
        };
        static const uint8_t bad_b4[] = {
            0x62,0xfb,0xed,0x48,0xce,0xcb,0x5a
        };
        cdisasm_x86_decode_flags flags = cpu_flags(
            CDISASM_CPU_X86, CDISASM_MODE_32);
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        /* If either discriminator bit is clear, 62 is the legacy BOUND
         * opcode in non-long modes; it must never enter the GFNI path. */
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
            bad_r, sizeof(bad_r), &flags, &decoded_size);
        EXPECT(instruction.name_id != CDISASM_X86_NAME_VGF2P8AFFINEQB);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
            bad_x, sizeof(bad_x), &flags, &decoded_size);
        EXPECT(instruction.name_id != CDISASM_X86_NAME_VGF2P8AFFINEQB);
        expect_error("non-long V-prime", CDISASM_CPU_X86,
            CDISASM_MODE_32, bad_vprime, sizeof(bad_vprime), &flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("non-long B4", CDISASM_CPU_X86,
            CDISASM_MODE_32, bad_b4, sizeof(bad_b4), &flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_memory_masks_and_broadcast(void)
{
    cdisasm_x86_decode_flags flags = cpu_flags(
        CDISASM_CPU_X86, CDISASM_MODE_64);
    size_t family_index;

    for (family_index = 0u;
         family_index < sizeof(families) / sizeof(families[0]);
         ++family_index) {
        const gfni_family *family = &families[family_index];
        unsigned int ll;

        for (ll = 0u; ll < 3u; ++ll) {
            unsigned int broadcast;

            for (broadcast = 0u; broadcast < 2u; ++broadcast) {
                uint8_t code[9] = {
                    0x62,(uint8_t)(0xf0u | family->map),
                    (uint8_t)(0x6du | (family->w << 7)),
                    (uint8_t)(0x0au | (ll << 5)
                        | (broadcast ? 0x10u : 0u)),
                    family->opcode,0x48,0x02,0x5a,0
                };
                const size_t size = family->affine ? 8u : 7u;
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, size, &flags, &decoded_size);

                if (broadcast && !family->affine) {
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_INVALID_INSTRUCTION));
                    continue;
                }
#if USE_EXTRA_OPCODES
                const unsigned int vector_bytes = 16u << ll;

                EXPECT(decoded_size == size);
                EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
                    family->vector_base + 4u * ll));
                EXPECT(instruction.opcode[2].type
                    == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[2].size
                    == (broadcast ? 8u : vector_bytes));
                EXPECT(instruction.opcode[2].imm
                    == UINT64_C(2) * (broadcast ? 8u : vector_bytes));
                EXPECT(instruction.opcode[2].broadcast == (broadcast
                    ? (cdisasm_x86_broadcast)(2u << ll)
                    : CDISASM_X86_BROADCAST_NONE));
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            }
        }
    }
    {
        static const uint8_t z_k0[] = {
            0x62,0xf3,0xed,0x88,0xce,0xcb,0x5a
        };
        static const uint8_t b_register[] = {
            0x62,0xf3,0xed,0x1a,0xce,0xcb,0x5a
        };
#if USE_EXTRA_OPCODES
        static const uint8_t zero[] = {
            0x62,0xf3,0xed,0x8a,0xce,0xcb,0x5a
        };
        static const uint8_t none[] = {
            0x62,0xf3,0xed,0x08,0xce,0xcb,0x5a
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            zero, sizeof(zero), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(zero));
        EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
        EXPECT(instruction.mask_reg == CDISASM_X86_REG_K2);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            none, sizeof(none), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(none));
        EXPECT(instruction.mask_mode == CDISASM_X86_MASK_NONE);
        EXPECT(instruction.mask_reg == CDISASM_X86_REG_NONE);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
#endif
        expect_error("EVEX z with k0", CDISASM_CPU_X86,
            CDISASM_MODE_64, z_k0, sizeof(z_k0), &flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("EVEX.b register", CDISASM_CPU_X86,
            CDISASM_MODE_64, b_register, sizeof(b_register), &flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_reserved_prefixes_and_truncation(void)
{
    cdisasm_x86_decode_flags flags = cpu_flags(
        CDISASM_CPU_X86, CDISASM_MODE_64);
    static const uint8_t legacy_repeat[] = {
        0xf3,0x66,0x0f,0x3a,0xce,0xcb,0x5a
    };
    static const uint8_t legacy_lock[] = {
        0xf0,0x66,0x0f,0x38,0xcf,0xcb
    };
    static const uint8_t vex_bad_pp[] = {
        0xc4,0xe3,0xe8,0xce,0xcb,0x5a
    };
    static const uint8_t vex_bad_w[] = {
        0xc4,0xe2,0xe9,0xcf,0xcb
    };
    static const uint8_t evex_bad_pp[] = {
        0x62,0xf3,0xec,0x08,0xce,0xcb,0x5a
    };
    static const uint8_t evex_bad_w[] = {
        0x62,0xf2,0xed,0x08,0xcf,0xcb
    };
    static const uint8_t evex_ll3[] = {
        0x62,0xf3,0xed,0x68,0xce,0xcb,0x5a
    };
    static const uint8_t prefixed_vex[] = {
        0x66,0xc4,0xe3,0xe9,0xce,0xcb,0x5a
    };
    static const uint8_t prefixed_evex[] = {
        0x66,0x62,0xf3,0xed,0x08,0xce,0xcb,0x5a
    };
    static const uint8_t legacy_sib_truncated[] = {
        0xf3,0x66,0x0f,0x3a,0xce,0x04
    };
    static const uint8_t vex_sib_truncated[] = {
        0xc4,0xe3,0xe8,0xce,0x04
    };
    static const uint8_t evex_sib_truncated[] = {
        0x62,0xf3,0x6d,0x68,0xce,0x04
    };
    static const uint8_t legacy_imm_truncated[] = {
        0x66,0x0f,0x3a,0xce,0xcb
    };
    static const uint8_t vex_imm_truncated[] = {
        0xc4,0xe3,0xe9,0xce,0xcb
    };
    static const uint8_t evex_imm_truncated[] = {
        0x62,0xf3,0xed,0x08,0xce,0xcb
    };
    static const uint8_t evex_modrm_truncated[] = {
        0x62,0xf2,0x6d,0x08,0xcf
    };

    expect_error("legacy repeat reserved", CDISASM_CPU_X86,
        CDISASM_MODE_64, legacy_repeat, sizeof(legacy_repeat), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy LOCK reserved", CDISASM_CPU_X86,
        CDISASM_MODE_64, legacy_lock, sizeof(legacy_lock), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VEX pp reserved", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex_bad_pp, sizeof(vex_bad_pp), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VEX exact W reserved", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex_bad_w, sizeof(vex_bad_w), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("EVEX pp reserved", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex_bad_pp, sizeof(evex_bad_pp), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("EVEX exact W reserved", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex_bad_w, sizeof(evex_bad_w), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("EVEX LL3 reserved", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex_ll3, sizeof(evex_ll3), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy prefix before VEX", CDISASM_CPU_X86,
        CDISASM_MODE_64, prefixed_vex, sizeof(prefixed_vex), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy prefix before EVEX", CDISASM_CPU_X86,
        CDISASM_MODE_64, prefixed_evex, sizeof(prefixed_evex), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    expect_error("legacy address before selector", CDISASM_CPU_X86,
        CDISASM_MODE_64, legacy_sib_truncated,
        sizeof(legacy_sib_truncated), &flags, CDISASM_STATUS_TRUNCATED);
    expect_error("VEX address before selector", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex_sib_truncated, sizeof(vex_sib_truncated),
        &flags, CDISASM_STATUS_TRUNCATED);
    expect_error("EVEX address before selector", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex_sib_truncated, sizeof(evex_sib_truncated),
        &flags, CDISASM_STATUS_TRUNCATED);
    expect_error("legacy affine immediate", CDISASM_CPU_X86,
        CDISASM_MODE_64, legacy_imm_truncated,
        sizeof(legacy_imm_truncated), &flags, CDISASM_STATUS_TRUNCATED);
    expect_error("VEX affine immediate", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex_imm_truncated, sizeof(vex_imm_truncated),
        &flags, CDISASM_STATUS_TRUNCATED);
    expect_error("EVEX affine immediate", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex_imm_truncated, sizeof(evex_imm_truncated),
        &flags, CDISASM_STATUS_TRUNCATED);
    expect_error("EVEX multiply ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex_modrm_truncated,
        sizeof(evex_modrm_truncated), &flags, CDISASM_STATUS_TRUNCATED);

#if USE_EXTRA_OPCODES
    {
        static const uint8_t legacy_rexw[] = {
            0x66,0x48,0x0f,0x3a,0xce,0xcb,0x5a
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_rexw, sizeof(legacy_rexw), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(legacy_rexw));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_GF2P8AFFINEQB);
        EXPECT(instruction.form_id == UINT16_C(1311));
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX_W) != 0u);
    }
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(
    const cdisasm_instruction *instruction,
    uint32_t syntax,
    const char *expected)
{
    char output[192];
    char tiny[4] = {'x','x','x','x'};
    const size_t required = cdisasm_x86_format(
        instruction, syntax, output, sizeof(output));

    if (strcmp(output, expected) != 0) {
        fprintf(stderr, "format mismatch: expected='%s' actual='%s'\n",
            expected, output);
    }
    EXPECT(required == strlen(expected));
    EXPECT(strcmp(output, expected) == 0);
    EXPECT(cdisasm_x86_format(
        instruction, syntax, NULL, 0u) == required);
    EXPECT(cdisasm_x86_format(
        instruction, syntax, tiny, sizeof(tiny)) == required);
    EXPECT(tiny[sizeof(tiny) - 1u] == '\0');
}

static void expect_forged_format_rejected(
    const cdisasm_instruction *instruction)
{
    char output[64] = "not empty";

    EXPECT(cdisasm_x86_format(instruction,
        CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
    output[0] = 'x';
    EXPECT(cdisasm_x86_format(instruction,
        CDISASM_FORMAT_SYNTAX_ATT, output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
}
#endif

static void test_formatting_and_schema(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const struct format_case {
        uint8_t code[8];
        size_t size;
        const char *intel;
        const char *att;
    } format_cases[] = {
        {{0x66,0x0f,0x3a,0xce,0xcb,0x5a,0,0},6,
            "gf2p8affineqb xmm1, xmm3, 0x5a",
            "gf2p8affineqb $0x5a, %xmm3, %xmm1"},
        {{0xc4,0xe3,0xe9,0xce,0xcb,0x5a,0,0},6,
            "vgf2p8affineqb xmm1, xmm2, xmm3, 0x5a",
            "vgf2p8affineqb $0x5a, %xmm3, %xmm2, %xmm1"},
        {{0xc4,0xe2,0x6d,0xcf,0xcb,0,0,0},5,
            "vgf2p8mulb ymm1, ymm2, ymm3",
            "vgf2p8mulb %ymm3, %ymm2, %ymm1"},
        {{0x62,0xf3,0xed,0x5a,0xce,0x48,0x02,0x5a},8,
            "vgf2p8affineqb zmm1 {k2}, zmm2, "
                "qword ptr [rax + 0x10]{1to8}, 0x5a",
            "vgf2p8affineqb $0x5a, 0x10(%rax){1to8}, "
                "%zmm2, %zmm1{%k2}"}
    };
    cdisasm_x86_decode_flags flags = cpu_flags(
        CDISASM_CPU_X86, CDISASM_MODE_64);
    size_t index;

    for (index = 0u;
         index < sizeof(format_cases) / sizeof(format_cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            format_cases[index].code, format_cases[index].size,
            &flags, &decoded_size);

        EXPECT(decoded_size == format_cases[index].size);
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            format_cases[index].intel);
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            format_cases[index].att);
    }
    {
        static const uint8_t code[] = {
            0x62,0xf3,0xed,0x8a,0xce,0xcb,0x5a
        };
        uint32_t decoded_size;
        cdisasm_instruction valid = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(code));
        expect_format(&valid, CDISASM_FORMAT_SYNTAX_INTEL,
            "vgf2p8affineqb xmm1 {k2}{z}, xmm2, xmm3, 0x5a");
        expect_format(&valid, CDISASM_FORMAT_SYNTAX_ATT,
            "vgf2p8affineqb $0x5a, %xmm3, %xmm2, %xmm1{%k2}{z}");

        forged = valid;
        forged.form_id = UINT16_C(5506);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VGF2P8AFFINEINVQB;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].broadcast = CDISASM_X86_BROADCAST_1_TO_2;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[3].size = 2u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags &= ~CDISASM_PREFIX_EVEX;
        forged.opcode_flags |= CDISASM_PREFIX_VEX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.immediate_offset[0]--;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.x86_group_count--;
        expect_forged_format_rejected(&forged);
    }
#endif
}

int main(void)
{
    test_all_36_forms();
    test_vex_selector_partition();
    test_evex_selector_partition();
    test_runtime_bits_and_profiles();
    test_apx_u0_memory();
    test_nonlong_aliases();
    test_memory_masks_and_broadcast();
    test_reserved_prefixes_and_truncation();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "x86 GFNI tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 GFNI tests passed");
    return 0;
}
