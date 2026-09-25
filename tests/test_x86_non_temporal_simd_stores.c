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

_Static_assert(CDISASM_X86_NAME_MOVNTDQ == UINT16_C(1346),
    "MOVNTDQ name ID changed");
_Static_assert(CDISASM_X86_NAME_VMOVNTPS == UINT16_C(1192),
    "VMOVNTPS name ID changed");
_Static_assert(CDISASM_X86_NAME_VMOVNTPD == UINT16_C(1193),
    "VMOVNTPD name ID changed");
_Static_assert(CDISASM_X86_NAME_VMOVNTDQ == UINT16_C(1194),
    "VMOVNTDQ name ID changed");
_Static_assert(CDISASM_X86_GROUP_AVX512F_128 == UINT16_C(180),
    "AVX512F_128 group ID changed");
_Static_assert(CDISASM_X86_GROUP_AVX512F_256 == UINT16_C(182),
    "AVX512F_256 group ID changed");
_Static_assert(CDISASM_X86_GROUP_AVX512F_512 == UINT16_C(183),
    "AVX512F_512 group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512F_128 == UINT32_C(128),
    "AVX512F_128 decode bit changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update non-temporal SIMD store profile sweeps");

typedef struct form_case {
    const char *label;
    uint8_t code[6];
    uint8_t size;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    cdisasm_x86_group_id family_group;
    cdisasm_x86_decode_bit_id decode_bit;
    unsigned int vector_bits;
    uint8_t prefix_size;
    uint8_t opcode_size;
    uint8_t evex;
} form_case;

static const form_case forms[] = {
    {"MOVNTDQ", {0x66, 0x0f, 0xe7, 0x00}, 4,
     CDISASM_X86_NAME_MOVNTDQ, 1691, CDISASM_X86_GROUP_SSE2,
     CDISASM_X86_DECODE_BIT_SSE2, 128, 1, 2, 0},
    {"MOVNTPD", {0x66, 0x0f, 0x2b, 0x00}, 4,
     CDISASM_X86_NAME_MOVNTPD, 1694, CDISASM_X86_GROUP_SSE2,
     CDISASM_X86_DECODE_BIT_SSE2, 128, 1, 2, 0},
    {"MOVNTPS", {0x0f, 0x2b, 0x00}, 3,
     CDISASM_X86_NAME_MOVNTPS, 1695, CDISASM_X86_GROUP_SSE,
     CDISASM_X86_DECODE_BIT_SSE, 128, 0, 2, 0},
    {"VMOVNTDQ xmm", {0xc5, 0xf9, 0xe7, 0x00}, 4,
     CDISASM_X86_NAME_VMOVNTDQ, 5869, CDISASM_X86_GROUP_AVX,
     CDISASM_X86_DECODE_BIT_AVX, 128, 2, 1, 0},
    {"VMOVNTDQ ymm", {0xc5, 0xfd, 0xe7, 0x00}, 4,
     CDISASM_X86_NAME_VMOVNTDQ, 5870, CDISASM_X86_GROUP_AVX,
     CDISASM_X86_DECODE_BIT_AVX, 256, 2, 1, 0},
    {"EVEX VMOVNTDQ xmm", {0x62, 0xf1, 0x7d, 0x08, 0xe7, 0x00}, 6,
     CDISASM_X86_NAME_VMOVNTDQ, 5871, CDISASM_X86_GROUP_AVX512F_128,
     CDISASM_X86_DECODE_BIT_AVX512F_128, 128, 4, 1, 1},
    {"EVEX VMOVNTDQ ymm", {0x62, 0xf1, 0x7d, 0x28, 0xe7, 0x00}, 6,
     CDISASM_X86_NAME_VMOVNTDQ, 5872, CDISASM_X86_GROUP_AVX512F_256,
     CDISASM_X86_DECODE_BIT_AVX512F_256, 256, 4, 1, 1},
    {"EVEX VMOVNTDQ zmm", {0x62, 0xf1, 0x7d, 0x48, 0xe7, 0x00}, 6,
     CDISASM_X86_NAME_VMOVNTDQ, 5873, CDISASM_X86_GROUP_AVX512F_512,
     CDISASM_X86_DECODE_BIT_AVX512F_512, 512, 4, 1, 1},
    {"VMOVNTPD xmm", {0xc5, 0xf9, 0x2b, 0x00}, 4,
     CDISASM_X86_NAME_VMOVNTPD, 5874, CDISASM_X86_GROUP_AVX,
     CDISASM_X86_DECODE_BIT_AVX, 128, 2, 1, 0},
    {"EVEX VMOVNTPD xmm", {0x62, 0xf1, 0xfd, 0x08, 0x2b, 0x00}, 6,
     CDISASM_X86_NAME_VMOVNTPD, 5875, CDISASM_X86_GROUP_AVX512F_128,
     CDISASM_X86_DECODE_BIT_AVX512F_128, 128, 4, 1, 1},
    {"EVEX VMOVNTPD ymm", {0x62, 0xf1, 0xfd, 0x28, 0x2b, 0x00}, 6,
     CDISASM_X86_NAME_VMOVNTPD, 5876, CDISASM_X86_GROUP_AVX512F_256,
     CDISASM_X86_DECODE_BIT_AVX512F_256, 256, 4, 1, 1},
    {"EVEX VMOVNTPD zmm", {0x62, 0xf1, 0xfd, 0x48, 0x2b, 0x00}, 6,
     CDISASM_X86_NAME_VMOVNTPD, 5877, CDISASM_X86_GROUP_AVX512F_512,
     CDISASM_X86_DECODE_BIT_AVX512F_512, 512, 4, 1, 1},
    {"VMOVNTPD ymm", {0xc5, 0xfd, 0x2b, 0x00}, 4,
     CDISASM_X86_NAME_VMOVNTPD, 5878, CDISASM_X86_GROUP_AVX,
     CDISASM_X86_DECODE_BIT_AVX, 256, 2, 1, 0},
    {"VMOVNTPS xmm", {0xc5, 0xf8, 0x2b, 0x00}, 4,
     CDISASM_X86_NAME_VMOVNTPS, 5879, CDISASM_X86_GROUP_AVX,
     CDISASM_X86_DECODE_BIT_AVX, 128, 2, 1, 0},
    {"EVEX VMOVNTPS xmm", {0x62, 0xf1, 0x7c, 0x08, 0x2b, 0x00}, 6,
     CDISASM_X86_NAME_VMOVNTPS, 5880, CDISASM_X86_GROUP_AVX512F_128,
     CDISASM_X86_DECODE_BIT_AVX512F_128, 128, 4, 1, 1},
    {"EVEX VMOVNTPS ymm", {0x62, 0xf1, 0x7c, 0x28, 0x2b, 0x00}, 6,
     CDISASM_X86_NAME_VMOVNTPS, 5881, CDISASM_X86_GROUP_AVX512F_256,
     CDISASM_X86_DECODE_BIT_AVX512F_256, 256, 4, 1, 1},
    {"EVEX VMOVNTPS zmm", {0x62, 0xf1, 0x7c, 0x48, 0x2b, 0x00}, 6,
     CDISASM_X86_NAME_VMOVNTPS, 5882, CDISASM_X86_GROUP_AVX512F_512,
     CDISASM_X86_DECODE_BIT_AVX512F_512, 512, 4, 1, 1},
    {"VMOVNTPS ymm", {0xc5, 0xfc, 0x2b, 0x00}, 4,
     CDISASM_X86_NAME_VMOVNTPS, 5883, CDISASM_X86_GROUP_AVX,
     CDISASM_X86_DECODE_BIT_AVX, 256, 2, 1, 0}
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
#endif

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id vector_id(unsigned int index, unsigned int bits)
{
    return (cdisasm_x86_reg_id)((bits == 128u
        ? CDISASM_X86_REG_XMM0
        : bits == 256u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_ZMM0)
        + index);
}

static cdisasm_x86_reg_id address_reg(unsigned int index, unsigned int bits)
{
    if (bits == 16u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_AX + index);
    }
    if (bits == 32u) {
        return index < 16u
            ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_EAX + index)
            : (cdisasm_x86_reg_id)(CDISASM_X86_REG_R16D + index - 16u);
    }
    return index < 16u
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_RAX + index)
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_R16 + index - 16u);
}

static void check_store(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    cdisasm_x86_name_id name_id,
    cdisasm_x86_form_id form_id,
    unsigned int vector_bits,
    cdisasm_x86_reg_id source,
    cdisasm_x86_reg_id base,
    cdisasm_x86_reg_id index,
    uint8_t scale,
    cdisasm_x86_group_id family_group,
    int expect_apx)
{
    if (decoded_size != expected_size
        || instruction->last_error_id != CDISASM_STATUS_OK) {
        fprintf(stderr, "%s: got size/status %u/%u, expected %u/0\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction->last_error_id,
            (unsigned int)expected_size);
    }
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
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction->opcode[0].base_reg == base);
    EXPECT(instruction->opcode[0].index_reg == index);
    EXPECT(instruction->opcode[0].scale == scale);
    EXPECT(instruction->opcode[0].size == vector_bits / 8u);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg == source);
    EXPECT(instruction->opcode[1].size == vector_bits / 8u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].flags == CDISASM_OPERAND_FLAG_NONE);
    EXPECT(instruction->encoding.immediate_count == 0u);
}
#endif

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
            check_store(forms[form_index].label, &instruction, decoded_size,
                forms[form_index].size, forms[form_index].name_id,
                forms[form_index].form_id, forms[form_index].vector_bits,
                vector_id(0u, forms[form_index].vector_bits),
                bases[mode_index], indexes[mode_index],
                mode_index == 0u ? 1u : 0u,
                forms[form_index].family_group, 0);
            EXPECT(instruction.encoding.prefix_size
                == forms[form_index].prefix_size);
            EXPECT(instruction.encoding.opcode_size
                == forms[form_index].opcode_size);
            EXPECT(((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0u)
                == forms[form_index].evex);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

typedef struct legacy_row {
    uint8_t prefixes[2];
    uint8_t prefix_count;
    uint8_t opcode;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    cdisasm_x86_group_id group_id;
    cdisasm_x86_decode_bit_id decode_bit;
    unsigned int bits;
    int mmx;
} legacy_row;

static const legacy_row legacy_rows[] = {
    {{0x66, 0}, 1, 0xe7, CDISASM_X86_NAME_MOVNTDQ, 1691,
     CDISASM_X86_GROUP_SSE2, CDISASM_X86_DECODE_BIT_SSE2, 128, 0},
    {{0x66, 0}, 1, 0x2b, CDISASM_X86_NAME_MOVNTPD, 1694,
     CDISASM_X86_GROUP_SSE2, CDISASM_X86_DECODE_BIT_SSE2, 128, 0},
    {{0, 0}, 0, 0x2b, CDISASM_X86_NAME_MOVNTPS, 1695,
     CDISASM_X86_GROUP_SSE, CDISASM_X86_DECODE_BIT_SSE, 128, 0},
    {{0, 0}, 0, 0xe7, CDISASM_X86_NAME_MOVNTQ, 1696,
     CDISASM_X86_GROUP_MMX, CDISASM_X86_DECODE_BIT_MMX, 64, 1},
    {{0x66, 0xf2}, 2, 0x2b, CDISASM_X86_NAME_MOVNTSD, 1697,
     CDISASM_X86_GROUP_SSE4A, CDISASM_X86_DECODE_BIT_SSE4A, 64, 0},
    {{0xf3, 0x66}, 2, 0x2b, CDISASM_X86_NAME_MOVNTSS, 1698,
     CDISASM_X86_GROUP_SSE4A, CDISASM_X86_DECODE_BIT_SSE4A, 32, 0}
};

static void test_complete_legacy_modrm_space(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t row_index;

    for (row_index = 0u;
         row_index < sizeof(legacy_rows) / sizeof(legacy_rows[0]);
         ++row_index) {
        size_t mode_index;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags =
            one_bit(legacy_rows[row_index].decode_bit);
#endif

        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            unsigned int modrm;

            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                uint8_t code[15] = {0};
                size_t offset = 0u;
                uint32_t decoded_size;
                cdisasm_instruction instruction;
#if USE_EXTRA_OPCODES
                unsigned int reg_index = (modrm >> 3u) & 7u;
#endif

                if (legacy_rows[row_index].prefix_count != 0u) {
                    code[offset++] = legacy_rows[row_index].prefixes[0];
                }
                if (legacy_rows[row_index].prefix_count == 2u) {
                    code[offset++] = legacy_rows[row_index].prefixes[1];
                }
                code[offset++] = 0x0f;
                code[offset++] = legacy_rows[row_index].opcode;
                code[offset++] = (uint8_t)modrm;
                code[offset++] = 0x24;
                code[offset++] = 0x10;
                code[offset++] = 0x20;
                code[offset++] = 0x30;
                code[offset++] = 0x40;

                instruction = decode(
                    CDISASM_CPU_X86, modes[mode_index], code, sizeof(code),
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
                EXPECT(decoded_size
                    >= legacy_rows[row_index].prefix_count + 3u);
                EXPECT(decoded_size <= offset);
                EXPECT(instruction.name_id == legacy_rows[row_index].name_id);
                EXPECT(instruction.form_id == legacy_rows[row_index].form_id);
                EXPECT(instruction.operand_count == 2u);
                EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[0].size
                    == legacy_rows[row_index].bits / 8u);
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(instruction.opcode[1].reg
                    == (legacy_rows[row_index].mmx
                        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_MM0 + reg_index)
                        : vector_id(reg_index, 128u)));
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            }
        }
    }
}

static void test_legacy_prefixes_and_rex(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t f2_66[] = {0xf2, 0x66, 0x0f, 0x2b, 0x00};
    static const uint8_t f3_f2[] = {0xf3, 0xf2, 0x0f, 0x2b, 0x00};
    static const uint8_t f2_f3[] = {0xf2, 0xf3, 0x0f, 0x2b, 0x00};
#endif
    static const uint8_t f2_e7[] = {0xf2, 0x66, 0x0f, 0xe7, 0x00};
    static const uint8_t lock[] = {0xf0, 0x66, 0x0f, 0xe7, 0x00};
    unsigned int payload;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags sse2 = one_bit(CDISASM_X86_DECODE_BIT_SSE2);
    cdisasm_x86_decode_flags sse4a = one_bit(CDISASM_X86_DECODE_BIT_SSE4A);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        f2_66, sizeof(f2_66), &sse4a, &decoded_size);
    EXPECT(decoded_size == sizeof(f2_66));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVNTSD);
    EXPECT(instruction.form_id == UINT16_C(1697));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        f3_f2, sizeof(f3_f2), &sse4a, &decoded_size);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVNTSD);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        f2_f3, sizeof(f2_f3), &sse4a, &decoded_size);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVNTSS);
#endif
    expect_error("F2/F3 E7 reserved", CDISASM_CPU_X86, CDISASM_MODE_64,
        f2_e7, sizeof(f2_e7),
#if USE_EXTRA_OPCODES
        &sse2,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("LOCK reserved", CDISASM_CPU_X86, CDISASM_MODE_64,
        lock, sizeof(lock),
#if USE_EXTRA_OPCODES
        &sse2,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);

    for (payload = 0u; payload < 16u; ++payload) {
        uint8_t code[] = {
            0x66, (uint8_t)(UINT8_C(0x40) + payload),
            0x0f, 0xe7, 0x5c, 0x58, 0x7f
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            &sse2,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        {
            const unsigned int source = 3u
                + ((payload & 4u) != 0u ? 8u : 0u);
            const unsigned int base = (payload & 1u) != 0u ? 8u : 0u;
            const unsigned int index = 3u
                + ((payload & 2u) != 0u ? 8u : 0u);

            check_store("legacy REX sweep", &instruction, decoded_size,
                sizeof(code), CDISASM_X86_NAME_MOVNTDQ, 1691, 128u,
                vector_id(source, 128u), address_reg(base, 64u),
                address_reg(index, 64u), 2u,
                CDISASM_X86_GROUP_SSE2, 0);
        }
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_rex2_transport_and_runtime(void)
{
    unsigned int payload;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags both = two_bits(
        CDISASM_X86_DECODE_BIT_SSE2, CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags sse2 = one_bit(CDISASM_X86_DECODE_BIT_SSE2);
    cdisasm_x86_decode_flags apx = one_bit(CDISASM_X86_DECODE_BIT_APX);
#endif

    for (payload = UINT8_C(0x80); payload <= UINT8_MAX; ++payload) {
        uint8_t code[] = {
            0x66, 0xd5, (uint8_t)payload,
            0xe7, 0x5c, 0x58, 0x7f
        };
        uint8_t reg_code[] = {
            0x66, 0xd5, (uint8_t)payload, 0xe7, 0xc0
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            &both,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        {
            const unsigned int source = 3u
                + ((payload & 4u) != 0u ? 8u : 0u);
            const unsigned int base = ((payload & 1u) != 0u ? 8u : 0u)
                + ((payload & 0x10u) != 0u ? 16u : 0u);
            const unsigned int index = 3u
                + ((payload & 2u) != 0u ? 8u : 0u)
                + ((payload & 0x20u) != 0u ? 16u : 0u);

            check_store("REX2 payload sweep", &instruction, decoded_size,
                sizeof(code), CDISASM_X86_NAME_MOVNTDQ, 1691, 128u,
                vector_id(source, 128u), address_reg(base, 64u),
                address_reg(index, 64u), 2u,
                CDISASM_X86_GROUP_SSE2, 1);
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0u);
        }
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        expect_error("REX2 register destination", CDISASM_CPU_X86,
            CDISASM_MODE_64, reg_code, sizeof(reg_code),
#if USE_EXTRA_OPCODES
            &both,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t canonical[] = {0x66, 0xd5, 0x80, 0xe7, 0x00};

        expect_error("REX2 needs APX", CDISASM_CPU_X86, CDISASM_MODE_64,
            canonical, sizeof(canonical), &sse2,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("REX2 needs SSE2", CDISASM_CPU_X86, CDISASM_MODE_64,
            canonical, sizeof(canonical), &apx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("REX2 APX profile boundary", CDISASM_CPU_ARROW_LAKE,
            CDISASM_MODE_64, canonical, sizeof(canonical), &both,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#endif
}

static void test_vex_controls(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t c4_w1[] = {0xc4, 0xe1, 0xf9, 0xe7, 0x00};
#endif
    static const uint8_t bad_vvvv[] = {0xc5, 0xe9, 0xe7, 0x00};
    static const uint8_t bad_pp[] = {0xc5, 0xfa, 0x2b, 0x00};
    static const uint8_t reg[] = {0xc5, 0xf9, 0xe7, 0xc0};
    static const uint8_t prefixed[] = {0x66, 0xc5, 0xf9, 0xe7, 0x00};
    static const uint8_t truncated_bad_vvvv[] = {0xc5, 0xe9, 0xe7};
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags avx = one_bit(CDISASM_X86_DECODE_BIT_AVX);
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        c4_w1, sizeof(c4_w1), &avx, &decoded_size);

    check_store("three-byte VEX WIG", &instruction, decoded_size,
        sizeof(c4_w1), CDISASM_X86_NAME_VMOVNTDQ, 5869, 128u,
        CDISASM_X86_REG_XMM0, CDISASM_X86_REG_RAX,
        CDISASM_X86_REG_NONE, 0u, CDISASM_X86_GROUP_AVX, 0);
#endif
    expect_error("VEX.vvvv reserved", CDISASM_CPU_X86, CDISASM_MODE_64,
        bad_vvvv, sizeof(bad_vvvv),
#if USE_EXTRA_OPCODES
        &avx,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VEX pp reserved", CDISASM_CPU_X86, CDISASM_MODE_64,
        bad_pp, sizeof(bad_pp),
#if USE_EXTRA_OPCODES
        &avx,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VEX register destination", CDISASM_CPU_X86,
        CDISASM_MODE_64, reg, sizeof(reg),
#if USE_EXTRA_OPCODES
        &avx,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy prefix before VEX", CDISASM_CPU_X86,
        CDISASM_MODE_64, prefixed, sizeof(prefixed),
#if USE_EXTRA_OPCODES
        &avx,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("short VEX outranks bad vvvv", CDISASM_CPU_X86,
        CDISASM_MODE_64, truncated_bad_vvvv,
        sizeof(truncated_bad_vvvv),
#if USE_EXTRA_OPCODES
        &avx,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
}

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

static void test_evex_control_space(void)
{
    unsigned int value;

    for (value = 0u; value <= UINT8_MAX; ++value) {
        uint8_t code[] = {0x62, 0xf1, (uint8_t)value, 0x08, 0x2b, 0x00};
        const uint8_t prefix = (uint8_t)value & UINT8_C(3);
        const int w = ((uint8_t)value & UINT8_C(0x80)) != 0;
        const int vvvv_ok = ((uint8_t)value & UINT8_C(0x78))
            == UINT8_C(0x78);
        const int valid = vvvv_ok
            && ((prefix == 0u && !w) || (prefix == 1u && w));
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

        if (!valid) {
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
            continue;
        }
#if USE_EXTRA_OPCODES
        check_store("EVEX P1 sweep", &instruction, decoded_size,
            sizeof(code), prefix == 0u ? CDISASM_X86_NAME_VMOVNTPS
                                      : CDISASM_X86_NAME_VMOVNTPD,
            prefix == 0u ? UINT16_C(5880) : UINT16_C(5875), 128u,
            CDISASM_X86_REG_XMM0, CDISASM_X86_REG_RAX,
            CDISASM_X86_REG_NONE, 0u, CDISASM_X86_GROUP_AVX512F_128,
            apx);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    for (value = 0u; value <= UINT8_MAX; ++value) {
        uint8_t code[] = {0x62, 0xf1, 0x7c, (uint8_t)value, 0x2b, 0x00};
        const unsigned int ll = ((uint8_t)value >> 5) & 3u;
        const int valid = ((uint8_t)value & UINT8_C(0x9f))
                == UINT8_C(0x08)
            && ll != 3u;
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(width_bit(ll < 3u ? ll : 0u));
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
        check_store("EVEX P2 sweep", &instruction, decoded_size,
            sizeof(code), CDISASM_X86_NAME_VMOVNTPS,
            (cdisasm_x86_form_id)(UINT16_C(5880) + ll),
            128u << ll, vector_id(0u, 128u << ll),
            CDISASM_X86_REG_RAX, CDISASM_X86_REG_NONE, 0u,
            width_group(ll), 0);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_evex_extensions_and_disp8(void)
{
    unsigned int fields;

    for (fields = 0u; fields < 32u; ++fields) {
        uint8_t p0 = (uint8_t)((fields << 3u) | 1u);
        uint8_t code[] = {0x62, p0, 0x7c, 0x08, 0x2b,
            0x5c, 0x58, 0x01};
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        const int apx = (p0 & UINT8_C(0x08)) != 0;
        const unsigned int source = 3u
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
        check_store("EVEX P0 extension sweep", &instruction, decoded_size,
            sizeof(code), CDISASM_X86_NAME_VMOVNTPS, 5880, 128u,
            vector_id(source, 128u),
            address_reg(base + (apx ? 16u : 0u), 64u),
            address_reg(index, 64u), 2u,
            CDISASM_X86_GROUP_AVX512F_128, apx);
        EXPECT(instruction.opcode[0].imm == UINT64_C(16));
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    {
        static const uint8_t both_apx[] = {
            0x62, 0xf9, 0x78, 0x08, 0x2b, 0x04, 0x58
        };
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = two_bits(
            CDISASM_X86_DECODE_BIT_AVX512F_128,
            CDISASM_X86_DECODE_BIT_APX);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            both_apx, sizeof(both_apx), &flags, &decoded_size);

        check_store("EVEX B4/X4", &instruction, decoded_size,
            sizeof(both_apx), CDISASM_X86_NAME_VMOVNTPS, 5880, 128u,
            CDISASM_X86_REG_XMM0, CDISASM_X86_REG_R16,
            CDISASM_X86_REG_R19, 2u,
            CDISASM_X86_GROUP_AVX512F_128, 1);
#else
        expect_error("EVEX B4/X4 extras off", CDISASM_CPU_X86,
            CDISASM_MODE_64, both_apx, sizeof(both_apx), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        expect_error("EVEX B4 outside 64-bit", CDISASM_CPU_X86,
            CDISASM_MODE_32, both_apx, sizeof(both_apx),
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
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

static void test_evex_profiles_and_runtime(void)
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

    for (ll = 0u; ll < 3u; ++ll) {
        uint8_t code[] = {
            0x62, 0xf1, 0x7c, (uint8_t)(0x08u + (ll << 5u)), 0x2b, 0x00
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
                    EXPECT(instruction.form_id
                        == (cdisasm_x86_form_id)(UINT16_C(5880) + ll));
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
        static const uint8_t evex128[] = {
            0x62, 0xf1, 0x7c, 0x08, 0x2b, 0x00
        };
        static const uint8_t evex_apx[] = {
            0x62, 0xf9, 0x7c, 0x08, 0x2b, 0x00
        };
        cdisasm_x86_decode_flags umbrella =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        cdisasm_x86_decode_flags exact =
            one_bit(CDISASM_X86_DECODE_BIT_AVX512F_128);
        cdisasm_x86_decode_flags apx = one_bit(CDISASM_X86_DECODE_BIT_APX);
        cdisasm_x86_decode_flags both = two_bits(
            CDISASM_X86_DECODE_BIT_AVX512F_128,
            CDISASM_X86_DECODE_BIT_APX);

        umbrella.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
            CDISASM_X86_DECODE_FLAG_AVX512;

        expect_error("EVEX exact width required", CDISASM_CPU_X86,
            CDISASM_MODE_64, evex128, sizeof(evex128), &umbrella,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("EVEX APX needs exact width", CDISASM_CPU_X86,
            CDISASM_MODE_64, evex_apx, sizeof(evex_apx), &apx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("EVEX B4 needs APX", CDISASM_CPU_X86,
            CDISASM_MODE_64, evex_apx, sizeof(evex_apx), &exact,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                evex_apx, sizeof(evex_apx), &both, &decoded_size);

            EXPECT(decoded_size == sizeof(evex_apx));
            EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R16);
        }
    }
#endif
}

static void test_truncation_and_formatting(void)
{
    static const uint8_t legacy_modrm[] = {0x66, 0x0f, 0xe7};
    static const uint8_t legacy_sib[] = {0x66, 0x0f, 0xe7, 0x04};
    static const uint8_t vex_modrm[] = {0xc5, 0xf9, 0xe7};
    static const uint8_t evex_modrm[] = {0x62, 0xf1, 0x7d, 0x08, 0xe7};
    static const uint8_t evex_sib[] = {
        0x62, 0xf1, 0x7d, 0x08, 0xe7, 0x04
    };
    static const uint8_t invalid_evex_sib[] = {
        0x62, 0xf1, 0x7d, 0x98, 0xe7, 0x04
    };
    static const struct trunc_case {
        const uint8_t *code;
        size_t size;
        cdisasm_x86_decode_bit_id bit;
    } cases[] = {
        {legacy_modrm, sizeof(legacy_modrm), CDISASM_X86_DECODE_BIT_SSE2},
        {legacy_sib, sizeof(legacy_sib), CDISASM_X86_DECODE_BIT_SSE2},
        {vex_modrm, sizeof(vex_modrm), CDISASM_X86_DECODE_BIT_AVX},
        {evex_modrm, sizeof(evex_modrm), CDISASM_X86_DECODE_BIT_AVX512F_128},
        {evex_sib, sizeof(evex_sib), CDISASM_X86_DECODE_BIT_AVX512F_128},
        {invalid_evex_sib, sizeof(invalid_evex_sib),
         CDISASM_X86_DECODE_BIT_AVX512F_128}
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
            0x66, 0x44, 0x0f, 0xe7, 0x54, 0x58, 0x20
        };
        static const uint8_t vex[] = {
            0xc4, 0x61, 0xfd, 0x2b, 0x64, 0x58, 0xc0
        };
        static const uint8_t evex[] = {
            0x62, 0x71, 0x7c, 0x48, 0x2b, 0x64, 0x58, 0xff
        };
        cdisasm_x86_decode_flags sse2 =
            one_bit(CDISASM_X86_DECODE_BIT_SSE2);
        cdisasm_x86_decode_flags avx =
            one_bit(CDISASM_X86_DECODE_BIT_AVX);
        cdisasm_x86_decode_flags avx512 =
            one_bit(CDISASM_X86_DECODE_BIT_AVX512F_512);
        uint32_t decoded_size;
        cdisasm_instruction instruction;
        char output[128];

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy, sizeof(legacy), &sse2, &decoded_size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output))
            == strlen("movntdq xmmword ptr [rax + rbx*2 + 0x20], xmm10"));
        EXPECT(strcmp(output,
            "movntdq xmmword ptr [rax + rbx*2 + 0x20], xmm10") == 0);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex, sizeof(vex), &avx, &decoded_size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output))
            == strlen("vmovntpd ymmword ptr [rax + rbx*2 - 0x40], ymm12"));
        EXPECT(strcmp(output,
            "vmovntpd ymmword ptr [rax + rbx*2 - 0x40], ymm12") == 0);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex, sizeof(evex), &avx512, &decoded_size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output))
            == strlen("vmovntps zmmword ptr [rax + rbx*2 - 0x40], zmm12"));
        EXPECT(strcmp(output,
            "vmovntps zmmword ptr [rax + rbx*2 - 0x40], zmm12") == 0);
    }
#endif
}

int main(void)
{
    test_all_forms_and_modes();
    test_complete_legacy_modrm_space();
    test_legacy_prefixes_and_rex();
    test_rex2_transport_and_runtime();
    test_vex_controls();
    test_evex_control_space();
    test_evex_extensions_and_disp8();
    test_evex_profiles_and_runtime();
    test_truncation_and_formatting();

    if (failures != 0) {
        fprintf(stderr, "%d non-temporal SIMD store test(s) failed\n",
            failures);
        return 1;
    }
    puts("x86 non-temporal SIMD store tests passed "
         "(18 forms; 4,608 legacy ModRM and exhaustive EVEX controls)");
    return 0;
}
