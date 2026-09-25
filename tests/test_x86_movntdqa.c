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
            if (failures < 48) {                                            \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_MOVNTDQA == UINT16_C(466),
    "MOVNTDQA name ID changed");
_Static_assert(CDISASM_X86_NAME_VMOVNTDQA == UINT16_C(1782),
    "VMOVNTDQA name ID changed");
_Static_assert(CDISASM_X86_GROUP_SSE4 == UINT16_C(310),
    "pinned SSE4 ISA-set group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_SSE4_ISA_SET == UINT32_C(270),
    "pinned SSE4 ISA-set decode bit changed");
_Static_assert(CDISASM_X86_GROUP_AVX512F_128 == UINT16_C(180)
        && CDISASM_X86_GROUP_AVX512F_256 == UINT16_C(182)
        && CDISASM_X86_GROUP_AVX512F_512 == UINT16_C(183),
    "AVX512F width group IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512F_128 == UINT32_C(128),
    "AVX512F width decode bits changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update MOVNTDQA profile sweeps");

typedef struct form_case {
    const char *label;
    uint8_t code[6];
    uint8_t size;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    cdisasm_x86_group_id group_id;
    cdisasm_x86_decode_bit_id decode_bit;
    unsigned int vector_bits;
    uint8_t prefix_size;
    uint8_t opcode_size;
} form_case;

static const form_case forms[] = {
    {"MOVNTDQA", {0x66, 0x0f, 0x38, 0x2a, 0x00}, 5,
     CDISASM_X86_NAME_MOVNTDQA, 1690, CDISASM_X86_GROUP_SSE4,
     CDISASM_X86_DECODE_BIT_SSE4_ISA_SET, 128, 1, 3},
    {"VEX VMOVNTDQA xmm", {0xc4, 0xe2, 0x79, 0x2a, 0x00}, 5,
     CDISASM_X86_NAME_VMOVNTDQA, 5864, CDISASM_X86_GROUP_AVX,
     CDISASM_X86_DECODE_BIT_AVX, 128, 3, 1},
    {"EVEX VMOVNTDQA xmm", {0x62, 0xf2, 0x7d, 0x08, 0x2a, 0x00}, 6,
     CDISASM_X86_NAME_VMOVNTDQA, 5865, CDISASM_X86_GROUP_AVX512F_128,
     CDISASM_X86_DECODE_BIT_AVX512F_128, 128, 4, 1},
    {"VEX VMOVNTDQA ymm", {0xc4, 0xe2, 0x7d, 0x2a, 0x00}, 5,
     CDISASM_X86_NAME_VMOVNTDQA, 5866, CDISASM_X86_GROUP_AVX2,
     CDISASM_X86_DECODE_BIT_AVX2, 256, 3, 1},
    {"EVEX VMOVNTDQA ymm", {0x62, 0xf2, 0x7d, 0x28, 0x2a, 0x00}, 6,
     CDISASM_X86_NAME_VMOVNTDQA, 5867, CDISASM_X86_GROUP_AVX512F_256,
     CDISASM_X86_DECODE_BIT_AVX512F_256, 256, 4, 1},
    {"EVEX VMOVNTDQA zmm", {0x62, 0xf2, 0x7d, 0x48, 0x2a, 0x00}, 6,
     CDISASM_X86_NAME_VMOVNTDQA, 5868, CDISASM_X86_GROUP_AVX512F_512,
     CDISASM_X86_DECODE_BIT_AVX512F_512, 512, 4, 1}
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

static cdisasm_x86_reg_id vector_id(unsigned int index, unsigned int bits)
{
    return (cdisasm_x86_reg_id)((bits == 128u
        ? CDISASM_X86_REG_XMM0
        : bits == 256u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_ZMM0)
        + index);
}

static cdisasm_x86_reg_id address_reg(unsigned int index)
{
    return index < 16u
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_RAX + index)
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_R16 + index - 16u);
}

static void check_load(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    cdisasm_x86_name_id name_id,
    cdisasm_x86_form_id form_id,
    unsigned int vector_bits,
    cdisasm_x86_reg_id destination,
    cdisasm_x86_reg_id base,
    cdisasm_x86_reg_id index,
    unsigned int scale,
    cdisasm_x86_group_id family_group,
    int expect_apx)
{
    (void)label;
    EXPECT(decoded_size == expected_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == name_id);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(instruction, family_group));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == expect_apx);
    EXPECT(instruction->operand_count == 2u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg == destination);
    EXPECT(instruction->opcode[0].size == vector_bits / 8u);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction->opcode[1].base_reg == base);
    EXPECT(instruction->opcode[1].index_reg == index);
    EXPECT(instruction->opcode[1].scale == scale);
    EXPECT(instruction->opcode[1].size == vector_bits / 8u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->encoding.immediate_count == 0u);
}
#endif

#if USE_EXTRA_OPCODES
static cdisasm_x86_group_id width_group(unsigned int ll)
{
    return ll == 0u ? CDISASM_X86_GROUP_AVX512F_128
        : ll == 1u ? CDISASM_X86_GROUP_AVX512F_256
                   : CDISASM_X86_GROUP_AVX512F_512;
}
#endif

static cdisasm_x86_decode_bit_id width_bit(unsigned int ll)
{
    return ll == 0u ? CDISASM_X86_DECODE_BIT_AVX512F_128
        : ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512F_256
                   : CDISASM_X86_DECODE_BIT_AVX512F_512;
}

static void test_all_forms_and_modes(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_reg_id bases[] = {
        CDISASM_X86_REG_BX, CDISASM_X86_REG_EAX, CDISASM_X86_REG_RAX
    };
    static const cdisasm_x86_reg_id indexes[] = {
        CDISASM_X86_REG_SI, CDISASM_X86_REG_NONE, CDISASM_X86_REG_NONE
    };
#endif
    size_t form_index;

    for (form_index = 0u;
         form_index < sizeof(forms) / sizeof(forms[0]);
         ++form_index) {
        size_t mode_index;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(forms[form_index].decode_bit);
#endif

        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[mode_index],
                forms[form_index].code, forms[form_index].size,
#if USE_EXTRA_OPCODES
                &flags,
#else
                NULL,
#endif
                &decoded_size);

#if USE_EXTRA_OPCODES
            check_load(forms[form_index].label, &instruction, decoded_size,
                forms[form_index].size, forms[form_index].name_id,
                forms[form_index].form_id, forms[form_index].vector_bits,
                vector_id(0u, forms[form_index].vector_bits),
                bases[mode_index], indexes[mode_index],
                mode_index == 0u ? 1u : 0u,
                forms[form_index].group_id, 0);
            EXPECT(instruction.encoding.prefix_size
                == forms[form_index].prefix_size);
            EXPECT(instruction.encoding.opcode_size
                == forms[form_index].opcode_size);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static void test_legacy_space_and_prefixes(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint8_t no_66[] = {0x0f, 0x38, 0x2a, 0x00};
    static const uint8_t f2_66[] = {0xf2, 0x66, 0x0f, 0x38, 0x2a, 0x00};
    static const uint8_t lock[] = {0xf0, 0x66, 0x0f, 0x38, 0x2a, 0x00};
    static const uint8_t bad_short_sib[] = {
        0xf2, 0x66, 0x0f, 0x38, 0x2a, 0x04
    };
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        unsigned int modrm;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags sse4 =
            one_bit(CDISASM_X86_DECODE_BIT_SSE4_ISA_SET);
#endif

        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
            uint8_t code[15] = {
                0x66, 0x0f, 0x38, 0x2a, (uint8_t)modrm,
                0x24, 0x10, 0x20, 0x30, 0x40
            };
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                &sse4,
#else
                NULL,
#endif
                &decoded_size);

            if ((modrm & UINT8_C(0xc0)) == UINT8_C(0xc0)) {
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                continue;
            }
#if USE_EXTRA_OPCODES
            EXPECT(decoded_size >= 5u && decoded_size <= sizeof(code));
            EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVNTDQA);
            EXPECT(instruction.form_id == UINT16_C(1690));
            EXPECT(instruction.operand_count == 2u);
            EXPECT(instruction.opcode[0].reg
                == vector_id((modrm >> 3u) & 7u, 128u));
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
            EXPECT(instruction.opcode[1].size == 16u);
            EXPECT(instruction.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }

    expect_error("legacy missing 66", CDISASM_CPU_X86, CDISASM_MODE_64,
        no_66, sizeof(no_66), NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy repeat plus 66", CDISASM_CPU_X86, CDISASM_MODE_64,
        f2_66, sizeof(f2_66), NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy LOCK", CDISASM_CPU_X86, CDISASM_MODE_64,
        lock, sizeof(lock), NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy bad selector truncated address", CDISASM_CPU_X86,
        CDISASM_MODE_64, bad_short_sib, sizeof(bad_short_sib), NULL,
        CDISASM_STATUS_TRUNCATED);

    {
        unsigned int payload;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags sse4 =
            one_bit(CDISASM_X86_DECODE_BIT_SSE4_ISA_SET);
#endif

        for (payload = 0u; payload < 16u; ++payload) {
            uint8_t code[] = {
                0x66, (uint8_t)(UINT8_C(0x40) + payload),
                0x0f, 0x38, 0x2a, 0x5c, 0x58, 0x7f
            };
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
                &sse4,
#else
                NULL,
#endif
                &decoded_size);

#if USE_EXTRA_OPCODES
            {
                const unsigned int destination = 3u
                    + ((payload & 4u) != 0u ? 8u : 0u);
                const unsigned int base = (payload & 1u) != 0u ? 8u : 0u;
                const unsigned int index = 3u
                    + ((payload & 2u) != 0u ? 8u : 0u);

                check_load("legacy REX sweep", &instruction, decoded_size,
                    sizeof(code), CDISASM_X86_NAME_MOVNTDQA, 1690, 128u,
                    vector_id(destination, 128u), address_reg(base),
                    address_reg(index), 2u, CDISASM_X86_GROUP_SSE4, 0);
            }
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t early_rex[] = {
            0x44, 0x66, 0x0f, 0x38, 0x2a, 0x00
        };
        cdisasm_x86_decode_flags sse4 =
            one_bit(CDISASM_X86_DECODE_BIT_SSE4_ISA_SET);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            early_rex, sizeof(early_rex), &sse4, &decoded_size);

        EXPECT(decoded_size == sizeof(early_rex));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM0);
    }
#endif

    {
        static const uint8_t profile_code[] = {
            0x66, 0x0f, 0x38, 0x2a, 0x00
        };
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags sse4 =
            one_bit(CDISASM_X86_DECODE_BIT_SSE4_ISA_SET);
#endif

        expect_error("legacy SSE4.1 profile", CDISASM_CPU_CORE_2,
            CDISASM_MODE_64, profile_code, sizeof(profile_code),
#if USE_EXTRA_OPCODES
            &sse4,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_vex_control_and_modrm_space(void)
{
    unsigned int value;

    for (value = 0u; value <= UINT8_MAX; ++value) {
        uint8_t code[] = {0xc4, 0xe2, (uint8_t)value, 0x2a, 0x00};
        const int valid = ((uint8_t)value & UINT8_C(0x7b))
            == UINT8_C(0x79);
        const unsigned int vector_bits =
            ((uint8_t)value & UINT8_C(4)) != 0 ? 256u : 128u;
#if !USE_EXTRA_OPCODES
        (void)vector_bits;
#endif
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(vector_bits == 256u
            ? CDISASM_X86_DECODE_BIT_AVX2 : CDISASM_X86_DECODE_BIT_AVX);
#endif
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);

        if (!valid) {
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
            continue;
        }
#if USE_EXTRA_OPCODES
        check_load("VEX P1 sweep", &instruction, decoded_size, sizeof(code),
            CDISASM_X86_NAME_VMOVNTDQA,
            vector_bits == 256u ? UINT16_C(5866) : UINT16_C(5864),
            vector_bits, vector_id(0u, vector_bits), CDISASM_X86_REG_RAX,
            CDISASM_X86_REG_NONE, 0u,
            vector_bits == 256u ? CDISASM_X86_GROUP_AVX2
                                : CDISASM_X86_GROUP_AVX,
            0);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    {
        unsigned int ll;

        for (ll = 0u; ll < 2u; ++ll) {
            unsigned int modrm;
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags flags = one_bit(ll != 0u
                ? CDISASM_X86_DECODE_BIT_AVX2
                : CDISASM_X86_DECODE_BIT_AVX);
#endif

            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                uint8_t code[12] = {
                    0xc4, 0xe2, (uint8_t)(0x79u | (ll << 2u)),
                    0x2a, (uint8_t)modrm, 0x24, 0x10, 0x20, 0x30, 0x40
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code),
#if USE_EXTRA_OPCODES
                    &flags,
#else
                    NULL,
#endif
                    &decoded_size);

                if ((modrm & UINT8_C(0xc0)) == UINT8_C(0xc0)) {
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(
                        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                    continue;
                }
#if USE_EXTRA_OPCODES
                EXPECT(decoded_size >= 5u && decoded_size <= sizeof(code));
                EXPECT(instruction.form_id
                    == (ll != 0u ? UINT16_C(5866) : UINT16_C(5864)));
                EXPECT(instruction.opcode[0].reg
                    == vector_id((modrm >> 3u) & 7u, 128u << ll));
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            }
        }
    }

    {
        unsigned int fields;

        for (fields = 0u; fields < 8u; ++fields) {
            uint8_t p0 = (uint8_t)(UINT8_C(0xe2)
                ^ ((fields & 4u) != 0u ? UINT8_C(0x80) : 0u)
                ^ ((fields & 2u) != 0u ? UINT8_C(0x40) : 0u)
                ^ ((fields & 1u) != 0u ? UINT8_C(0x20) : 0u));
            uint8_t code[] = {0xc4, p0, 0x79, 0x2a, 0x5c, 0x58, 0x20};
            uint32_t decoded_size;
#if USE_EXTRA_OPCODES
            const unsigned int destination = 3u
                + ((fields & 4u) != 0u ? 8u : 0u);
            const unsigned int index = 3u
                + ((fields & 2u) != 0u ? 8u : 0u);
            const unsigned int base = (fields & 1u) != 0u ? 8u : 0u;
            cdisasm_x86_decode_flags avx =
                one_bit(CDISASM_X86_DECODE_BIT_AVX);
#endif
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
                &avx,
#else
                NULL,
#endif
                &decoded_size);

#if USE_EXTRA_OPCODES
            check_load("VEX extension sweep", &instruction, decoded_size,
                sizeof(code), CDISASM_X86_NAME_VMOVNTDQA, 5864, 128u,
                vector_id(destination, 128u), address_reg(base),
                address_reg(index), 2u, CDISASM_X86_GROUP_AVX, 0);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }

    {
        static const uint8_t canonical_32[] = {
            0xc4, 0xe2, 0x79, 0x2a, 0x00
        };
        static const uint8_t bad_short[] = {
            0xc4, 0xe2, 0x69, 0x2a
        };
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags avx =
            one_bit(CDISASM_X86_DECODE_BIT_AVX);
#endif

        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_32,
                canonical_32, sizeof(canonical_32),
#if USE_EXTRA_OPCODES
                &avx,
#else
                NULL,
#endif
                &decoded_size);
#if USE_EXTRA_OPCODES
            EXPECT(decoded_size == sizeof(canonical_32));
            EXPECT(instruction.form_id == UINT16_C(5864));
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
        expect_error("VEX reserved vvvv truncated ModRM", CDISASM_CPU_X86,
            CDISASM_MODE_64, bad_short, sizeof(bad_short),
#if USE_EXTRA_OPCODES
            &avx,
#else
            NULL,
#endif
            CDISASM_STATUS_TRUNCATED);
    }
}

static int profile_has_evex(
    cdisasm_x86_cpu_id cpu_id,
    unsigned int vector_bits)
{
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_SKYLAKE_SP:
        case CDISASM_CPU_ICE_LAKE:
        case CDISASM_CPU_TIGER_LAKE:
        case CDISASM_CPU_AMD_ZEN_4:
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
        case CDISASM_CPU_AVX10:
        case CDISASM_CPU_APX:
        case CDISASM_CPU_GRANITE_RAPIDS:
        case CDISASM_CPU_DIAMOND_RAPIDS:
            return 1;
        case CDISASM_CPU_KNIGHTS_MILL:
            return vector_bits == 512u;
        default:
            return 0;
    }
}

static void test_evex_control_space(void)
{
    unsigned int value;

    for (value = 0u; value <= UINT8_MAX; ++value) {
        uint8_t code[] = {0x62, 0xf2, (uint8_t)value, 0x08, 0x2a, 0x00};
        const int valid = ((uint8_t)value & UINT8_C(0xfb))
            == UINT8_C(0x79);
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        const int apx = ((uint8_t)value & UINT8_C(4)) == 0;
        cdisasm_x86_decode_flags flags = apx
            ? two_bits(CDISASM_X86_DECODE_BIT_AVX512F_128,
                CDISASM_X86_DECODE_BIT_APX)
            : one_bit(CDISASM_X86_DECODE_BIT_AVX512F_128);
#endif
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);

        /* Non-66 selectors belong to other map-2/2A rows or generated
         * fallback coverage.  This helper owns and exhaustively classifies
         * the complete pp66 control space only. */
        if (((uint8_t)value & UINT8_C(3)) != UINT8_C(1)) {
            EXPECT(decoded_size == 0u
                || instruction.name_id != CDISASM_X86_NAME_VMOVNTDQA);
            continue;
        }
        if (!valid) {
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
            continue;
        }
#if USE_EXTRA_OPCODES
        check_load("EVEX P1 sweep", &instruction, decoded_size, sizeof(code),
            CDISASM_X86_NAME_VMOVNTDQA, 5865, 128u,
            CDISASM_X86_REG_XMM0, CDISASM_X86_REG_RAX,
            CDISASM_X86_REG_NONE, 0u, CDISASM_X86_GROUP_AVX512F_128, apx);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    for (value = 0u; value <= UINT8_MAX; ++value) {
        uint8_t code[] = {0x62, 0xf2, 0x7d, (uint8_t)value, 0x2a, 0x00};
        const unsigned int ll = ((uint8_t)value >> 5) & 3u;
        const int valid = ((uint8_t)value & UINT8_C(0x9f))
                == UINT8_C(0x08)
            && ll != 3u;
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags =
            one_bit(width_bit(ll < 3u ? ll : 0u));
#endif
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);

        if (!valid) {
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
            continue;
        }
#if USE_EXTRA_OPCODES
        check_load("EVEX P2 sweep", &instruction, decoded_size, sizeof(code),
            CDISASM_X86_NAME_VMOVNTDQA,
            ll == 0u ? UINT16_C(5865)
                     : (cdisasm_x86_form_id)(UINT16_C(5866) + ll),
            128u << ll, vector_id(0u, 128u << ll), CDISASM_X86_REG_RAX,
            CDISASM_X86_REG_NONE, 0u, width_group(ll), 0);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    {
        unsigned int ll;

        for (ll = 0u; ll < 3u; ++ll) {
            unsigned int modrm;
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags flags = one_bit(width_bit(ll));
#endif

            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                uint8_t code[12] = {
                    0x62, 0xf2, 0x7d,
                    (uint8_t)(0x08u | (ll << 5u)),
                    0x2a, (uint8_t)modrm,
                    0x24, 0x10, 0x20, 0x30, 0x40
                };
                const unsigned int vector_bits = 128u << ll;
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code),
#if USE_EXTRA_OPCODES
                    &flags,
#else
                    NULL,
#endif
                    &decoded_size);

                if ((modrm & UINT8_C(0xc0)) == UINT8_C(0xc0)) {
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(
                        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                    continue;
                }
#if USE_EXTRA_OPCODES
                EXPECT(decoded_size >= 6u && decoded_size <= sizeof(code));
                EXPECT(instruction.name_id == CDISASM_X86_NAME_VMOVNTDQA);
                EXPECT(instruction.form_id == (ll == 0u
                    ? UINT16_C(5865)
                    : (cdisasm_x86_form_id)(UINT16_C(5866) + ll)));
                EXPECT(instruction.opcode[0].reg
                    == vector_id((modrm >> 3u) & 7u, vector_bits));
                EXPECT(instruction.opcode[0].size == vector_bits / 8u);
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[1].size == vector_bits / 8u);
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
#else
                (void)vector_bits;
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            }
        }
    }
}

static int profile_has_sse4_isa_set(cdisasm_x86_cpu_id cpu_id)
{
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_PENRYN:
        case CDISASM_CPU_NEHALEM:
        case CDISASM_CPU_WESTMERE:
        case CDISASM_CPU_SANDY_BRIDGE:
        case CDISASM_CPU_AMD_BULLDOZER:
        case CDISASM_CPU_IVY_BRIDGE:
        case CDISASM_CPU_HASWELL:
        case CDISASM_CPU_BROADWELL:
        case CDISASM_CPU_SKYLAKE:
        case CDISASM_CPU_GOLDMONT:
        case CDISASM_CPU_AMD_ZEN:
        case CDISASM_CPU_SKYLAKE_SP:
        case CDISASM_CPU_ICE_LAKE:
        case CDISASM_CPU_TIGER_LAKE:
        case CDISASM_CPU_ALDER_LAKE:
        case CDISASM_CPU_AMD_ZEN_4:
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
        case CDISASM_CPU_AVX10:
        case CDISASM_CPU_APX:
        case CDISASM_CPU_CELERON_G1840:
        case CDISASM_CPU_CELERON_G3900:
        case CDISASM_CPU_CELERON_N3350:
        case CDISASM_CPU_CELERON_N4020:
        case CDISASM_CPU_CELERON_G5900:
        case CDISASM_CPU_PENTIUM_SILVER_N6000:
        case CDISASM_CPU_GRANITE_RAPIDS:
        case CDISASM_CPU_ARROW_LAKE:
        case CDISASM_CPU_DIAMOND_RAPIDS:
        case CDISASM_CPU_KNIGHTS_MILL:
            return 1;
        default:
            return 0;
    }
}

static void test_evex_extensions_collision_and_tuple(void)
{
    unsigned int fields;

    for (fields = 0u; fields < 32u; ++fields) {
        uint8_t p0 = (uint8_t)((fields << 3u) | 2u);
        uint8_t code[] = {
            0x62, p0, 0x7d, 0x08, 0x2a, 0x5c, 0x58, 0x01
        };
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        const int apx = (p0 & UINT8_C(0x08)) != 0;
        const unsigned int destination = 3u
            + ((p0 & UINT8_C(0x80)) == 0 ? 8u : 0u)
            + ((p0 & UINT8_C(0x10)) == 0 ? 16u : 0u);
        const unsigned int base = (p0 & UINT8_C(0x20)) == 0 ? 8u : 0u;
        const unsigned int index = 3u
            + ((p0 & UINT8_C(0x40)) == 0 ? 8u : 0u);
        cdisasm_x86_decode_flags flags = apx
            ? two_bits(CDISASM_X86_DECODE_BIT_AVX512F_128,
                CDISASM_X86_DECODE_BIT_APX)
            : one_bit(CDISASM_X86_DECODE_BIT_AVX512F_128);
#endif
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        check_load("EVEX P0 sweep", &instruction, decoded_size, sizeof(code),
            CDISASM_X86_NAME_VMOVNTDQA, 5865, 128u,
            vector_id(destination, 128u),
            address_reg(base + (apx ? 16u : 0u)), address_reg(index), 2u,
            CDISASM_X86_GROUP_AVX512F_128, apx);
        EXPECT(instruction.opcode[1].imm == UINT64_C(16));
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    {
        static const uint8_t both_apx[] = {
            0x62, 0xfa, 0x79, 0x08, 0x2a, 0x04, 0x58
        };
        static const uint8_t scaled[] = {
            0x62, 0x72, 0x7d, 0x48, 0x2a, 0x64, 0x58, 0xff
        };
        static const uint8_t collision[] = {
            0x62, 0xf2, 0xfe, 0x48, 0x2a, 0xcb
        };
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags both = two_bits(
            CDISASM_X86_DECODE_BIT_AVX512F_128,
            CDISASM_X86_DECODE_BIT_APX);
        cdisasm_x86_decode_flags avx512 =
            one_bit(CDISASM_X86_DECODE_BIT_AVX512F_512);
        cdisasm_x86_decode_flags cd =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        uint32_t decoded_size;

        cd.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
            CDISASM_X86_DECODE_FLAG_AVX512_CD;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            both_apx, sizeof(both_apx), &both, &decoded_size);

        check_load("EVEX B4/X4", &instruction, decoded_size,
            sizeof(both_apx), CDISASM_X86_NAME_VMOVNTDQA, 5865, 128u,
            CDISASM_X86_REG_XMM0, CDISASM_X86_REG_R16,
            CDISASM_X86_REG_R19, 2u,
            CDISASM_X86_GROUP_AVX512F_128, 1);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            scaled, sizeof(scaled), &avx512, &decoded_size);
        check_load("EVEX disp8 tuple", &instruction, decoded_size,
            sizeof(scaled), CDISASM_X86_NAME_VMOVNTDQA, 5868, 512u,
            CDISASM_X86_REG_ZMM12, CDISASM_X86_REG_RAX,
            CDISASM_X86_REG_RBX, 2u,
            CDISASM_X86_GROUP_AVX512F_512, 0);
        EXPECT(instruction.opcode[1].imm == (uint64_t)(int64_t)-64);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            collision, sizeof(collision), &cd, &decoded_size);
        EXPECT(decoded_size == sizeof(collision));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPBROADCASTMB2Q);
        EXPECT(instruction.name_id != CDISASM_X86_NAME_VMOVNTDQA);
#else
        expect_error("EVEX B4/X4 extras off", CDISASM_CPU_X86,
            CDISASM_MODE_64, both_apx, sizeof(both_apx), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("EVEX tuple extras off", CDISASM_CPU_X86,
            CDISASM_MODE_64, scaled, sizeof(scaled), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("EVEX collision extras off", CDISASM_CPU_X86,
            CDISASM_MODE_64, collision, sizeof(collision), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        expect_error("EVEX B4 outside 64-bit", CDISASM_CPU_X86,
            CDISASM_MODE_32, both_apx, sizeof(both_apx),
#if USE_EXTRA_OPCODES
            &both,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_profiles_and_runtime(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const cdisasm_x86_mode_mask mode_bits[] = {
        CDISASM_X86_MODE_MASK_16,
        CDISASM_X86_MODE_MASK_32,
        CDISASM_X86_MODE_MASK_64
    };
    unsigned int ll;

    {
        static const uint8_t legacy[] = {
            0x66, 0x0f, 0x38, 0x2a, 0x00
        };
        uint32_t cpu_value;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags exact =
            one_bit(CDISASM_X86_DECODE_BIT_SSE4_ISA_SET);
#endif

        for (cpu_value = (uint32_t)CDISASM_CPU_X86;
             cpu_value <= (uint32_t)CDISASM_CPU_LAST;
             ++cpu_value) {
            cdisasm_x86_cpu_id cpu_id = (cdisasm_x86_cpu_id)cpu_value;
            size_t mode_index;

            for (mode_index = 0u; mode_index < 3u; ++mode_index) {
                cdisasm_x86_decode_flags available;
                const cdisasm_x86_mode_mask available_modes =
                    cdisasm_x86_cpu_mode_mask(cpu_id);

                if ((available_modes & mode_bits[mode_index]) == 0u) {
                    continue;
                }
                EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                    cpu_id, modes[mode_index], &available)
                    == CDISASM_STATUS_OK);
                EXPECT(cdisasm_decode_flags_test_bit(
                    &available, CDISASM_X86_DECODE_BIT_SSE4_ISA_SET)
                    == (USE_EXTRA_OPCODES
                        && profile_has_sse4_isa_set(cpu_id)));
                if (!profile_has_sse4_isa_set(cpu_id)) {
                    expect_error("SSE4 ISA-set profile rejection", cpu_id,
                        modes[mode_index], legacy, sizeof(legacy),
#if USE_EXTRA_OPCODES
                        &exact,
#else
                        NULL,
#endif
                        CDISASM_STATUS_INVALID_INSTRUCTION);
                } else {
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        cpu_id, modes[mode_index], legacy, sizeof(legacy),
#if USE_EXTRA_OPCODES
                        &exact,
#else
                        NULL,
#endif
                        &decoded_size);
#if USE_EXTRA_OPCODES
                    EXPECT(decoded_size == sizeof(legacy));
                    EXPECT(instruction.form_id == UINT16_C(1690));
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_SSE4));
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                }
            }
        }
    }

    for (ll = 0u; ll < 3u; ++ll) {
        uint8_t code[] = {
            0x62, 0xf2, 0x7d,
            (uint8_t)(0x08u + (ll << 5u)), 0x2a, 0x00
        };
        uint32_t cpu_value;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags exact = one_bit(width_bit(ll));
#endif

        for (cpu_value = (uint32_t)CDISASM_CPU_X86;
             cpu_value <= (uint32_t)CDISASM_CPU_LAST;
             ++cpu_value) {
            cdisasm_x86_cpu_id cpu_id = (cdisasm_x86_cpu_id)cpu_value;
            size_t mode_index;

            for (mode_index = 0u; mode_index < 3u; ++mode_index) {
                cdisasm_x86_decode_flags available;
                const cdisasm_x86_mode_mask available_modes =
                    cdisasm_x86_cpu_mode_mask(cpu_id);

                if ((available_modes & mode_bits[mode_index]) == 0u) {
                    continue;
                }
                EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                    cpu_id, modes[mode_index], &available)
                    == CDISASM_STATUS_OK);
                EXPECT(cdisasm_decode_flags_test_bit(
                    &available, width_bit(ll))
                    == (USE_EXTRA_OPCODES
                        && profile_has_evex(cpu_id, 128u << ll)));
                if (!profile_has_evex(cpu_id, 128u << ll)) {
                    expect_error("EVEX profile rejection", cpu_id,
                        modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                        &exact,
#else
                        NULL,
#endif
                        CDISASM_STATUS_INVALID_INSTRUCTION);
                } else {
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        cpu_id, modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                        &exact,
#else
                        NULL,
#endif
                        &decoded_size);
#if USE_EXTRA_OPCODES
                    EXPECT(decoded_size == sizeof(code));
                    EXPECT(instruction.form_id == (ll == 0u
                        ? UINT16_C(5865)
                        : (cdisasm_x86_form_id)(UINT16_C(5866) + ll)));
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                }
            }
        }
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t legacy[] = {
            0x66, 0x0f, 0x38, 0x2a, 0x00
        };
        static const uint8_t vex128[] = {0xc4, 0xe2, 0x79, 0x2a, 0x00};
        static const uint8_t vex256[] = {0xc4, 0xe2, 0x7d, 0x2a, 0x00};
        static const uint8_t evex128[] = {
            0x62, 0xf2, 0x7d, 0x08, 0x2a, 0x00
        };
        static const uint8_t evex_apx[] = {
            0x62, 0xfa, 0x7d, 0x08, 0x2a, 0x00
        };
        cdisasm_x86_decode_flags avx =
            one_bit(CDISASM_X86_DECODE_BIT_AVX);
        cdisasm_x86_decode_flags avx2 =
            one_bit(CDISASM_X86_DECODE_BIT_AVX2);
        cdisasm_x86_decode_flags umbrella =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        cdisasm_x86_decode_flags exact =
            one_bit(CDISASM_X86_DECODE_BIT_AVX512F_128);
        cdisasm_x86_decode_flags apx = one_bit(CDISASM_X86_DECODE_BIT_APX);
        cdisasm_x86_decode_flags both = two_bits(
            CDISASM_X86_DECODE_BIT_AVX512F_128,
            CDISASM_X86_DECODE_BIT_APX);
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        {
            cdisasm_x86_decode_flags sse41 =
                one_bit(CDISASM_X86_DECODE_BIT_SSE41);
            cdisasm_x86_decode_flags sse4 =
                one_bit(CDISASM_X86_DECODE_BIT_SSE4_ISA_SET);

            expect_error("legacy exact SSE4 bit required", CDISASM_CPU_X86,
                CDISASM_MODE_64, legacy, sizeof(legacy), &sse41,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                legacy, sizeof(legacy), &sse4, &decoded_size);
            EXPECT(decoded_size == sizeof(legacy));
            EXPECT(instruction.form_id == UINT16_C(1690));
        }

        umbrella.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
            CDISASM_X86_DECODE_FLAG_AVX512;
        expect_error("VEX128 needs AVX", CDISASM_CPU_X86,
            CDISASM_MODE_64, vex128, sizeof(vex128), &avx2,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("VEX256 needs AVX2", CDISASM_CPU_X86,
            CDISASM_MODE_64, vex256, sizeof(vex256), &avx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("EVEX exact width required", CDISASM_CPU_X86,
            CDISASM_MODE_64, evex128, sizeof(evex128), &umbrella,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("EVEX APX needs exact width", CDISASM_CPU_X86,
            CDISASM_MODE_64, evex_apx, sizeof(evex_apx), &apx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("EVEX B4 needs APX", CDISASM_CPU_X86,
            CDISASM_MODE_64, evex_apx, sizeof(evex_apx), &exact,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_apx, sizeof(evex_apx), &both, &decoded_size);
        EXPECT(decoded_size == sizeof(evex_apx));
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R16);
    }
#endif
}

static void test_truncation_and_formatting(void)
{
    static const uint8_t legacy_modrm[] = {0x66, 0x0f, 0x38, 0x2a};
    static const uint8_t legacy_sib[] = {0x66, 0x0f, 0x38, 0x2a, 0x04};
    static const uint8_t vex_modrm[] = {0xc4, 0xe2, 0x79, 0x2a};
    static const uint8_t evex_modrm[] = {0x62, 0xf2, 0x7d, 0x08, 0x2a};
    static const uint8_t evex_sib[] = {
        0x62, 0xf2, 0x7d, 0x08, 0x2a, 0x04
    };
    static const struct trunc_case {
        const uint8_t *code;
        size_t size;
        cdisasm_x86_decode_bit_id bit;
    } cases[] = {
        {legacy_modrm, sizeof(legacy_modrm),
            CDISASM_X86_DECODE_BIT_SSE4_ISA_SET},
        {legacy_sib, sizeof(legacy_sib),
            CDISASM_X86_DECODE_BIT_SSE4_ISA_SET},
        {vex_modrm, sizeof(vex_modrm), CDISASM_X86_DECODE_BIT_AVX},
        {evex_modrm, sizeof(evex_modrm), CDISASM_X86_DECODE_BIT_AVX512F_128},
        {evex_sib, sizeof(evex_sib), CDISASM_X86_DECODE_BIT_AVX512F_128}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(cases[index].bit);
#endif
        expect_error("owned truncation", CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, cases[index].size,
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            CDISASM_STATUS_TRUNCATED);
    }

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    {
        static const uint8_t legacy[] = {
            0x66, 0x44, 0x0f, 0x38, 0x2a, 0x54, 0x58, 0x20
        };
        static const uint8_t vex[] = {
            0xc4, 0x62, 0x7d, 0x2a, 0x64, 0x58, 0xc0
        };
        static const uint8_t evex[] = {
            0x62, 0x72, 0x7d, 0x48, 0x2a, 0x64, 0x58, 0xff
        };
        cdisasm_x86_decode_flags sse4 =
            one_bit(CDISASM_X86_DECODE_BIT_SSE4_ISA_SET);
        cdisasm_x86_decode_flags avx2 =
            one_bit(CDISASM_X86_DECODE_BIT_AVX2);
        cdisasm_x86_decode_flags avx512 =
            one_bit(CDISASM_X86_DECODE_BIT_AVX512F_512);
        uint32_t decoded_size;
        cdisasm_instruction instruction;
        char output[128];

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy, sizeof(legacy), &sse4, &decoded_size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output))
            == strlen("movntdqa xmm10, xmmword ptr [rax + rbx*2 + 0x20]"));
        EXPECT(strcmp(output,
            "movntdqa xmm10, xmmword ptr [rax + rbx*2 + 0x20]") == 0);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex, sizeof(vex), &avx2, &decoded_size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output))
            == strlen("vmovntdqa -0x40(%rax,%rbx,2), %ymm12"));
        EXPECT(strcmp(output,
            "vmovntdqa -0x40(%rax,%rbx,2), %ymm12") == 0);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex, sizeof(evex), &avx512, &decoded_size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output))
            == strlen("vmovntdqa zmm12, zmmword ptr [rax + rbx*2 - 0x40]"));
        EXPECT(strcmp(output,
            "vmovntdqa zmm12, zmmword ptr [rax + rbx*2 - 0x40]") == 0);
    }
#endif
}

int main(void)
{
    test_all_forms_and_modes();
    test_legacy_space_and_prefixes();
    test_vex_control_and_modrm_space();
    test_evex_control_space();
    test_evex_extensions_collision_and_tuple();
    test_profiles_and_runtime();
    test_truncation_and_formatting();

    if (failures != 0) {
        fprintf(stderr, "%d MOVNTDQA test(s) failed\n", failures);
        return 1;
    }
    puts("x86 MOVNTDQA tests passed (6 forms; exhaustive legacy/VEX/EVEX controls)");
    return 0;
}
