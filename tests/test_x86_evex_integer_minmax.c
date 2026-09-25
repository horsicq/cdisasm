#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct minmax_case {
    uint8_t map;
    uint8_t opcode;
    uint8_t w;
    uint8_t w_ignored;
    uint8_t element_bits;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_name_id legacy_name_id;
    cdisasm_x86_group_id feature_group;
    cdisasm_x86_form_id classic_xmm_memory;
    cdisasm_x86_form_id classic_ymm_memory;
    cdisasm_x86_form_id evex_xmm_memory;
    cdisasm_x86_form_id evex_ymm_memory;
    cdisasm_x86_form_id evex_zmm_memory;
    const char *mnemonic;
} minmax_case;

static const minmax_case cases[] = {
    {1,0xda,0,1, 8,CDISASM_X86_NAME_VPMINUB,CDISASM_X86_NAME_PMINUB,
        CDISASM_X86_GROUP_AVX512BW,7268,7272,7270,7274,7276,"vpminub"},
    {1,0xde,0,1, 8,CDISASM_X86_NAME_VPMAXUB,CDISASM_X86_NAME_PMAXUB,
        CDISASM_X86_GROUP_AVX512BW,7196,7200,7198,7202,7204,"vpmaxub"},
    {1,0xea,0,1,16,CDISASM_X86_NAME_VPMINSW,CDISASM_X86_NAME_PMINSW,
        CDISASM_X86_GROUP_AVX512BW,7258,7264,7260,7262,7266,"vpminsw"},
    {1,0xee,0,1,16,CDISASM_X86_NAME_VPMAXSW,CDISASM_X86_NAME_PMAXSW,
        CDISASM_X86_GROUP_AVX512BW,7186,7192,7188,7190,7194,"vpmaxsw"},
    {2,0x38,0,1, 8,CDISASM_X86_NAME_VPMINSB,CDISASM_X86_NAME_PMINSB,
        CDISASM_X86_GROUP_AVX512BW,7232,7238,7234,7236,7240,"vpminsb"},
    {2,0x39,0,0,32,CDISASM_X86_NAME_VPMINSD,CDISASM_X86_NAME_PMINSD,
        CDISASM_X86_GROUP_AVX512F,7242,7248,7244,7246,7250,"vpminsd"},
    {2,0x39,1,0,64,CDISASM_X86_NAME_VPMINSQ,CDISASM_X86_NAME_NONE,
        CDISASM_X86_GROUP_AVX512F,0,0,7252,7254,7256,"vpminsq"},
    {2,0x3a,0,1,16,CDISASM_X86_NAME_VPMINUW,CDISASM_X86_NAME_PMINUW,
        CDISASM_X86_GROUP_AVX512BW,7294,7298,7296,7300,7302,"vpminuw"},
    {2,0x3b,0,0,32,CDISASM_X86_NAME_VPMINUD,CDISASM_X86_NAME_PMINUD,
        CDISASM_X86_GROUP_AVX512F,7278,7282,7280,7284,7286,"vpminud"},
    {2,0x3b,1,0,64,CDISASM_X86_NAME_VPMINUQ,CDISASM_X86_NAME_NONE,
        CDISASM_X86_GROUP_AVX512F,0,0,7288,7290,7292,"vpminuq"},
    {2,0x3c,0,1, 8,CDISASM_X86_NAME_VPMAXSB,CDISASM_X86_NAME_PMAXSB,
        CDISASM_X86_GROUP_AVX512BW,7160,7166,7162,7164,7168,"vpmaxsb"},
    {2,0x3d,0,0,32,CDISASM_X86_NAME_VPMAXSD,CDISASM_X86_NAME_PMAXSD,
        CDISASM_X86_GROUP_AVX512F,7170,7176,7172,7174,7178,"vpmaxsd"},
    {2,0x3d,1,0,64,CDISASM_X86_NAME_VPMAXSQ,CDISASM_X86_NAME_NONE,
        CDISASM_X86_GROUP_AVX512F,0,0,7180,7182,7184,"vpmaxsq"},
    {2,0x3e,0,1,16,CDISASM_X86_NAME_VPMAXUW,CDISASM_X86_NAME_PMAXUW,
        CDISASM_X86_GROUP_AVX512BW,7222,7226,7224,7228,7230,"vpmaxuw"},
    {2,0x3f,0,0,32,CDISASM_X86_NAME_VPMAXUD,CDISASM_X86_NAME_PMAXUD,
        CDISASM_X86_GROUP_AVX512F,7206,7210,7208,7212,7214,"vpmaxud"},
    {2,0x3f,1,0,64,CDISASM_X86_NAME_VPMAXUQ,CDISASM_X86_NAME_NONE,
        CDISASM_X86_GROUP_AVX512F,0,0,7216,7218,7220,"vpmaxuq"}
};

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

static cdisasm_instruction decode(
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu, mode, bytes, size, UINT64_C(0x1000), flags, &instruction);
    return instruction;
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

static void expect_error(
    const char *label,
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction =
        decode(cpu, mode, bytes, size, flags, &decoded_size);

    if (decoded_size != 0 || !is_error_only(&instruction, status)) {
        fprintf(stderr,
            "%s: expected status=%u, actual=%u, decoded=%u\n",
            label, (unsigned int)status,
            (unsigned int)instruction.last_error_id,
            (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, status));
}

static void make_register_encoding(
    const minmax_case *test,
    unsigned int length,
    unsigned int w,
    uint8_t code[6])
{
    code[0] = UINT8_C(0x62);
    code[1] = (uint8_t)(UINT8_C(0xf0) | test->map);
    code[2] = (uint8_t)(w != 0 ? UINT8_C(0xed) : UINT8_C(0x6d));
    code[3] = (uint8_t)(UINT8_C(0x0a) | (length << 5));
    code[4] = test->opcode;
    code[5] = UINT8_C(0xcb);
}

static void make_classic_encoding(
    const minmax_case *test,
    unsigned int length,
    unsigned int w,
    uint8_t modrm,
    uint8_t code[6],
    size_t *size)
{
    code[0] = UINT8_C(0xc4);
    code[1] = (uint8_t)(UINT8_C(0xe0) | test->map);
    code[2] = (uint8_t)(UINT8_C(0x69) | (length << 2)
        | (w << 7));
    code[3] = test->opcode;
    code[4] = modrm;
    code[5] = 0u;
    *size = 5u;
}

static void make_apx_encoding(
    const minmax_case *test,
    int b4,
    int u0,
    uint8_t modrm,
    uint8_t sib,
    uint8_t code[7])
{
    const uint8_t canonical_p1 = test->w != 0u
        ? UINT8_C(0xed) : UINT8_C(0x6d);

    code[0] = UINT8_C(0x62);
    code[1] = (uint8_t)(UINT8_C(0xf0) | test->map
        | (b4 ? UINT8_C(0x08) : 0u));
    code[2] = (uint8_t)(canonical_p1
        & (u0 ? UINT8_C(0xfb) : UINT8_C(0xff)));
    code[3] = UINT8_C(0x08);
    code[4] = test->opcode;
    code[5] = modrm;
    code[6] = sib;
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id vector_register(unsigned int index, unsigned int bits)
{
    if (bits == 128u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + index);
    }
    if (bits == 256u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_YMM0 + index);
    }
    return (cdisasm_x86_reg_id)(CDISASM_X86_REG_ZMM0 + index);
}

static void check_classic(
    const minmax_case *test,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_mode mode,
    uint8_t p0,
    unsigned int length,
    unsigned int source1,
    uint8_t modrm)
{
    const int long_mode = mode == CDISASM_MODE_64;
    const int register_form =
        (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
    const unsigned int vector_bits = 128u << length;
    const unsigned int destination = ((unsigned int)modrm >> 3) & 7u;
    const unsigned int source2 = (unsigned int)modrm & 7u;
    const unsigned int extended_destination = destination
        + (long_mode && (p0 & UINT8_C(0x80)) == 0u ? 8u : 0u);
    const unsigned int extended_source1 = long_mode
        ? source1 : source1 & 7u;
    const unsigned int extended_source2 = source2
        + (long_mode && (p0 & UINT8_C(0x20)) == 0u ? 8u : 0u);
    const cdisasm_x86_form_id form = (cdisasm_x86_form_id)(
        (length != 0u
            ? test->classic_ymm_memory : test->classic_xmm_memory)
        + (register_form ? 1u : 0u));

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == test->name_id);
    EXPECT(instruction->form_id == form);
    EXPECT(instruction->operand_count == 3u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
        == CDISASM_PREFIX_VEX);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset == 0u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg
        == vector_register(extended_destination, vector_bits));
    EXPECT(instruction->opcode[0].size == vector_bits / 8u);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[0].flags == 0u);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg
        == vector_register(extended_source1, vector_bits));
    EXPECT(instruction->opcode[1].size == vector_bits / 8u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].flags == 0u);
    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[2].size == vector_bits / 8u);
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].broadcast == CDISASM_X86_BROADCAST_NONE);
    if (register_form) {
        EXPECT(instruction->opcode[2].reg
            == vector_register(extended_source2, vector_bits));
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
        instruction, CDISASM_X86_GROUP_AVX2) == (length != 0u));
}

#if USE_DISASM_FORMAT
static void expect_format(
    const cdisasm_instruction *instruction,
    uint32_t syntax,
    const char *expected)
{
    char buffer[160];
    size_t length = cdisasm_x86_format(
        instruction, syntax, buffer, sizeof(buffer));

    if (strcmp(buffer, expected) != 0) {
        fprintf(stderr, "format mismatch: expected='%s' actual='%s'\n",
            expected, buffer);
    }
    EXPECT(length == strlen(expected));
    EXPECT(strcmp(buffer, expected) == 0);
}
#endif
#endif

static void check_classic_allocated(
    const minmax_case *test,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_mode mode,
    uint8_t p0,
    unsigned int length,
    unsigned int source1,
    uint8_t modrm)
{
#if USE_EXTRA_OPCODES
    check_classic(test, instruction, decoded_size,
        mode, p0, length, source1, modrm);
#else
    (void)test;
    (void)mode;
    (void)p0;
    (void)length;
    (void)source1;
    (void)modrm;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_name_catalog(void)
{
    EXPECT(sizeof(cases) / sizeof(cases[0]) == 16u);
    EXPECT(CDISASM_X86_NAME_VPMAXSW == UINT16_C(665));
    EXPECT(CDISASM_X86_NAME_VPMAXUB == UINT16_C(666));
    EXPECT(CDISASM_X86_NAME_VPMINSW == UINT16_C(667));
    EXPECT(CDISASM_X86_NAME_VPMINUB == UINT16_C(668));
    EXPECT(CDISASM_X86_NAME_VPMINSB == UINT16_C(1002));
    EXPECT(CDISASM_X86_NAME_VPMAXUQ == UINT16_C(1013));
    EXPECT(CDISASM_X86_NAME_VPMADDUBSW == UINT16_C(1020));
    EXPECT(CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1));
}

static void test_classic_control_partition(void)
{
    static const cdisasm_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint64_t form_counts[16][4] = {{0u}};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t case_index;

    for (case_index = 0u;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        const minmax_case *test = &cases[case_index];
        size_t mode_index;

        if (test->classic_xmm_memory == 0u) {
            continue;
        }
        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            const int long_mode = modes[mode_index] == CDISASM_MODE_64;
            const unsigned int p0_count = long_mode ? 8u : 2u;
            const cdisasm_x86_decode_option flags =
                cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_X86, modes[mode_index]);
            unsigned int p0_index;

            for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
                const uint8_t p0 = long_mode
                    ? (uint8_t)((p0_index << 5) | test->map)
                    : (uint8_t)(UINT8_C(0xc0) | test->map
                        | (p0_index << 5));
                unsigned int control;

                for (control = 0u; control <= UINT8_MAX; ++control) {
                    const unsigned int pp = control & 3u;
                    const unsigned int length = (control >> 2) & 1u;
                    const unsigned int source1 = ((~control) >> 3) & 15u;
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                        const uint8_t code[15] = {
                            0xc4,p0,(uint8_t)control,test->opcode,
                            (uint8_t)modrm,0x24,0x10,0x20,0x30,0x40,
                            0x50,0x60,0x70,0x80,0x90
                        };
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_X86,modes[mode_index],
                            code,sizeof(code),flags,&decoded_size);

                        if (pp == 1u) {
                            const unsigned int form_index =
                                2u * length + (register_form ? 1u : 0u);

                            check_classic_allocated(test,&instruction,
                                decoded_size,modes[mode_index],p0,
                                length,source1,(uint8_t)modrm);
                            ++form_counts[case_index][form_index];
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

        if (test->map == 1u) {
            for (mode_index = 0u; mode_index < 3u; ++mode_index) {
                const cdisasm_mode mode = modes[mode_index];
                const cdisasm_x86_decode_option flags =
                    cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_X86,mode);
                unsigned int p1;

                for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                    const unsigned int pp = p1 & 3u;
                    const unsigned int length = (p1 >> 2) & 1u;
                    const unsigned int source1 = ((~p1) >> 3) & 15u;
                    const uint8_t synthetic_p0 = (uint8_t)(
                        ((p1 & UINT8_C(0x80)) != 0u
                            ? UINT8_C(0xe0) : UINT8_C(0x60)) | 1u);
                    unsigned int modrm;

                    if (mode != CDISASM_MODE_64 && p1 < UINT8_C(0xc0)) {
                        continue;
                    }
                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                        const uint8_t code[14] = {
                            0xc5,(uint8_t)p1,test->opcode,(uint8_t)modrm,
                            0x24,0x10,0x20,0x30,0x40,0x50,0x60,0x70,
                            0x80,0x90
                        };
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_X86,mode,code,sizeof(code),
                            flags,&decoded_size);

                        if (pp == 1u) {
                            const unsigned int form_index =
                                2u * length + (register_form ? 1u : 0u);

                            check_classic_allocated(test,&instruction,
                                decoded_size,mode,synthetic_p0,
                                length,source1,(uint8_t)modrm);
                            ++form_counts[case_index][form_index];
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

        {
            static const uint64_t c4_expected[4] = {
                UINT64_C(73728),UINT64_C(24576),
                UINT64_C(73728),UINT64_C(24576)
            };
            static const uint64_t c4_c5_expected[4] = {
                UINT64_C(82944),UINT64_C(27648),
                UINT64_C(82944),UINT64_C(27648)
            };
            const uint64_t *expected = test->map == 1u
                ? c4_c5_expected : c4_expected;
            size_t form_index;

            for (form_index = 0u; form_index < 4u; ++form_index) {
                EXPECT(form_counts[case_index][form_index]
                    == expected[form_index]);
            }
        }
    }

    EXPECT(allocated == UINT64_C(2457600));
    EXPECT(reserved == UINT64_C(7372800));
}

static void test_classic_forms_gates_and_neighbors(void)
{
    size_t case_index;

    for (case_index = 0u;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        const minmax_case *test = &cases[case_index];
        uint8_t xmm[6];
        uint8_t ymm[6];
        uint8_t w1[6];
        size_t xmm_size;
        size_t ymm_size;
        size_t w1_size;

        if (test->classic_xmm_memory == 0u) {
            continue;
        }
        make_classic_encoding(test,0u,0u,UINT8_C(0xcb),xmm,&xmm_size);
        make_classic_encoding(test,1u,0u,UINT8_C(0xcb),ymm,&ymm_size);
        make_classic_encoding(test,0u,1u,UINT8_C(0xcb),w1,&w1_size);

#if USE_EXTRA_OPCODES
        {
            const cdisasm_x86_decode_option all_flags =
                cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_X86,CDISASM_MODE_64);
            const cdisasm_x86_decode_option avx =
                CDISASM_X86_DECODE_FLAG_AVX;
            const cdisasm_x86_decode_option avx_and_avx2 =
                CDISASM_X86_DECODE_FLAG_AVX
                | CDISASM_X86_DECODE_FLAG_AVX2;
            uint8_t memory[6];
            size_t memory_size;
            cdisasm_instruction instruction;
            uint32_t decoded_size;

            instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                xmm,xmm_size,avx,&decoded_size);
            check_classic(test,&instruction,decoded_size,
                CDISASM_MODE_64,xmm[1],0u,2u,xmm[4]);
            instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                ymm,ymm_size,avx_and_avx2,&decoded_size);
            check_classic(test,&instruction,decoded_size,
                CDISASM_MODE_64,ymm[1],1u,2u,ymm[4]);
            instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                w1,w1_size,all_flags,&decoded_size);
            check_classic(test,&instruction,decoded_size,
                CDISASM_MODE_64,w1[1],0u,2u,w1[4]);

            make_classic_encoding(
                test,0u,0u,UINT8_C(0x00),memory,&memory_size);
            instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                memory,memory_size,all_flags,&decoded_size);
            check_classic(test,&instruction,decoded_size,
                CDISASM_MODE_64,memory[1],0u,2u,memory[4]);
            EXPECT(instruction.form_id == test->classic_xmm_memory);
            EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);

            expect_error("AVX alone does not admit YMM packed MIN/MAX",
                CDISASM_CPU_X86,CDISASM_MODE_64,
                ymm,ymm_size,avx,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error("AVX2 without AVX does not admit XMM MIN/MAX",
                CDISASM_CPU_X86,CDISASM_MODE_64,
                xmm,xmm_size,CDISASM_X86_DECODE_FLAG_AVX2,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

            instruction = decode(
                CDISASM_CPU_SANDY_BRIDGE,CDISASM_MODE_64,
                xmm,xmm_size,avx_and_avx2,&decoded_size);
            check_classic(test,&instruction,decoded_size,
                CDISASM_MODE_64,xmm[1],0u,2u,xmm[4]);
            expect_error("Sandy Bridge lacks AVX2 YMM packed MIN/MAX",
                CDISASM_CPU_SANDY_BRIDGE,CDISASM_MODE_64,
                ymm,ymm_size,avx_and_avx2,
                CDISASM_STATUS_INVALID_INSTRUCTION);

            {
                uint8_t legacy[5] = {0x66,0x0f,0,0,0xcb};
                size_t legacy_size;

                if (test->map == 2u) {
                    legacy[2] = UINT8_C(0x38);
                    legacy[3] = test->opcode;
                    legacy_size = 5u;
                } else {
                    legacy[2] = test->opcode;
                    legacy[3] = UINT8_C(0xcb);
                    legacy_size = 4u;
                }
                instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                    legacy,legacy_size,all_flags,&decoded_size);
                EXPECT(decoded_size == legacy_size);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == test->legacy_name_id);
                EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX) == 0u);
            }

            if (test->map == 1u) {
                const uint8_t c5_xmm[] = {
                    0xc5,0xe9,test->opcode,0xcb
                };
                const uint8_t c5_ymm[] = {
                    0xc5,0xed,test->opcode,0xcb
                };

                instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                    c5_xmm,sizeof(c5_xmm),all_flags,&decoded_size);
                check_classic(test,&instruction,decoded_size,
                    CDISASM_MODE_64,0xe1,0u,2u,0xcb);
                instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                    c5_ymm,sizeof(c5_ymm),all_flags,&decoded_size);
                check_classic(test,&instruction,decoded_size,
                    CDISASM_MODE_64,0xe1,1u,2u,0xcb);
            }
        }
#else
        expect_error("packed MIN/MAX extras off XMM",
            CDISASM_CPU_X86,CDISASM_MODE_64,xmm,xmm_size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("packed MIN/MAX extras off YMM",
            CDISASM_CPU_X86,CDISASM_MODE_64,ymm,ymm_size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

        {
            uint8_t bad_pp[8];
            uint8_t prefixed[9];
            uint8_t truncated[8];
            size_t base_size;

            make_classic_encoding(
                test,0u,0u,UINT8_C(0x04),bad_pp,&base_size);
            bad_pp[2] &= (uint8_t)~UINT8_C(0x03);
            bad_pp[5] = UINT8_C(0x24);
            bad_pp[6] = UINT8_C(0x11);
            bad_pp[7] = UINT8_C(0x22);
            expect_error("packed MIN/MAX pp reserved",
                CDISASM_CPU_X86,CDISASM_MODE_64,bad_pp,8u,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);

            prefixed[0] = UINT8_C(0x66);
            memcpy(prefixed + 1,bad_pp,8u);
            prefixed[3] |= UINT8_C(0x01);
            expect_error("prefixed packed MIN/MAX reserved",
                CDISASM_CPU_X86,CDISASM_MODE_64,prefixed,9u,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);

            memcpy(truncated,bad_pp,8u);
            truncated[2] |= UINT8_C(0x01);
            expect_error("packed MIN/MAX payload first",
                CDISASM_CPU_X86,CDISASM_MODE_64,truncated,5u,
                CDISASM_X86_DECODE_FLAG_BASE,CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed packed MIN/MAX payload first",
                CDISASM_CPU_X86,CDISASM_MODE_64,prefixed,6u,
                CDISASM_X86_DECODE_FLAG_BASE,CDISASM_STATUS_TRUNCATED);
        }
    }

#if USE_EXTRA_OPCODES
    {
        static const cdisasm_mode modes[2] = {
            CDISASM_MODE_16,CDISASM_MODE_32
        };
        size_t mode_index;

        for (mode_index = 0u; mode_index < 2u; ++mode_index) {
            const cdisasm_x86_decode_option flags =
                cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_X86,modes[mode_index]);

            for (case_index = 0u;
                 case_index < sizeof(cases) / sizeof(cases[0]);
                 ++case_index) {
                const minmax_case *test = &cases[case_index];
                const uint8_t c4_alias[] = {
                    0xc4,(uint8_t)(0xc0u | test->map),
                    0x29,test->opcode,0xfa
                };
                cdisasm_instruction instruction;
                uint32_t decoded_size;

                if (test->classic_xmm_memory == 0u) {
                    continue;
                }
                instruction = decode(CDISASM_CPU_X86,modes[mode_index],
                    c4_alias,sizeof(c4_alias),flags,&decoded_size);
                check_classic(test,&instruction,decoded_size,
                    modes[mode_index],c4_alias[1],0u,10u,0xfa);

                if (test->map == 1u) {
                    const uint8_t c5_alias[] = {
                        0xc5,0xe9,test->opcode,0xfa
                    };

                    instruction = decode(
                        CDISASM_CPU_X86,modes[mode_index],
                        c5_alias,sizeof(c5_alias),flags,&decoded_size);
                    check_classic(test,&instruction,decoded_size,
                        modes[mode_index],0xe1,0u,2u,0xfa);
                }
            }
        }
    }
#endif
}

static void test_register_matrix(void)
{
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        unsigned int length;
        const minmax_case *test = &cases[index];

        for (length = 0; length != 3; ++length) {
            const unsigned int vector_bits = 128u << length;
            uint8_t code[6];

            make_register_encoding(test, length, test->w, code);
#if USE_EXTRA_OPCODES
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                    &decoded_size);

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == test->name_id);
                EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
                    (length == 0u ? test->evex_xmm_memory
                        : length == 1u ? test->evex_ymm_memory
                        : test->evex_zmm_memory) + 1u));
                EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0);
                EXPECT(instruction.operand_count == 3u);
                EXPECT(instruction.opcode[0].reg
                    == vector_register(1u, vector_bits));
                EXPECT(instruction.opcode[1].reg
                    == vector_register(2u, vector_bits));
                EXPECT(instruction.opcode[2].reg
                    == vector_register(3u, vector_bits));
                EXPECT(instruction.opcode[0].size == vector_bits / 8u);
                EXPECT(instruction.opcode[1].size == vector_bits / 8u);
                EXPECT(instruction.opcode[2].size == vector_bits / 8u);
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(instruction.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(instruction.mask_reg == CDISASM_X86_REG_K2);
                EXPECT(instruction.mask_mode == CDISASM_X86_MASK_MERGE);
                EXPECT(instruction.rounding == CDISASM_X86_ROUNDING_NONE);
                EXPECT(instruction.sae == CDISASM_X86_SAE_NONE);
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512F));
                EXPECT(cdisasm_instruction_has_x86_group(
                           &instruction, CDISASM_X86_GROUP_AVX512VL)
                    == (vector_bits < 512u));
                EXPECT(cdisasm_instruction_has_x86_group(
                           &instruction, CDISASM_X86_GROUP_AVX512BW)
                    == (test->feature_group
                        == CDISASM_X86_GROUP_AVX512BW));
                EXPECT(instruction.encoding.prefix_size == 4u);
                EXPECT(instruction.encoding.opcode_offset == 4u);
                EXPECT(instruction.encoding.opcode_size == 1u);
                EXPECT(instruction.encoding.modrm_offset == 5u);
                EXPECT(instruction.encoding.immediate_count == 0u);

#if USE_DISASM_FORMAT
                {
                    const char *reg = length == 0 ? "xmm"
                        : length == 1 ? "ymm" : "zmm";
                    char intel[128];
                    char att[128];

                    snprintf(intel, sizeof(intel),
                        "%s %s1 {k2}, %s2, %s3",
                        test->mnemonic, reg, reg, reg);
                    snprintf(att, sizeof(att),
                        "%s %%%s3, %%%s2, %%%s1{%%k2}",
                        test->mnemonic, reg, reg, reg);
                    expect_format(&instruction,
                        CDISASM_FORMAT_SYNTAX_X86_INTEL, intel);
                    expect_format(&instruction,
                        CDISASM_FORMAT_SYNTAX_X86_ATT, att);
                }
#endif
            }
#else
            (void)vector_bits;
            expect_error("extra-opcodes OFF register form",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

static void test_w_ignored_rows(void)
{
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const minmax_case *test = &cases[index];
        uint8_t code[6];

        if (!test->w_ignored) {
            continue;
        }
        make_register_encoding(test, 2u, 1u, code);
#if USE_EXTRA_OPCODES
        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                &decoded_size);

            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.name_id == test->name_id);
            EXPECT(instruction.opcode[0].size == 64u);
        }
#else
        expect_error("extra-opcodes OFF WIG form",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_memory_matrix(void)
{
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const minmax_case *test = &cases[index];
        const unsigned int form_count =
            test->element_bits >= 32u ? 2u : 1u;
        unsigned int form;

        for (form = 0; form < form_count; ++form) {
            const int broadcast = form != 0;
            uint8_t code[] = {
                0x62, (uint8_t)(0xf0u | test->map),
                (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                (uint8_t)(broadcast ? 0x5a : 0x4a),
                test->opcode, 0x48, 0x02
            };

#if USE_EXTRA_OPCODES
            {
                const unsigned int memory_bytes = broadcast
                    ? test->element_bits / 8u : 64u;
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                    &decoded_size);

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.name_id == test->name_id);
                EXPECT(instruction.form_id == test->evex_zmm_memory);
                EXPECT(instruction.operand_count == 3u);
                EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ZMM1);
                EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ZMM2);
                EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[2].base_reg
                    == CDISASM_X86_REG_RAX);
                EXPECT(instruction.opcode[2].index_reg
                    == CDISASM_X86_REG_NONE);
                EXPECT(instruction.opcode[2].size == memory_bytes);
                EXPECT(instruction.opcode[2].imm
                    == UINT64_C(2) * memory_bytes);
                EXPECT(instruction.opcode[2].broadcast
                    == (broadcast
                        ? (cdisasm_x86_broadcast)(
                            512u / test->element_bits)
                        : CDISASM_X86_BROADCAST_NONE));
                EXPECT(instruction.encoding.displacement_offset == 6u);
                EXPECT(instruction.encoding.displacement_size == 1u);
            }
#else
            expect_error("extra-opcodes OFF memory form",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

static void test_zeroing_and_unmasked(void)
{
    static const uint8_t zeroing[] = {
        0x62, 0xf2, 0x6d, 0xca, 0x38, 0xcb
    };
    static const uint8_t unmasked[] = {
        0x62, 0xf2, 0x6d, 0x48, 0x38, 0xcb
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        zeroing, sizeof(zeroing), CDISASM_X86_DECODE_FLAG_AVX512,
        &decoded_size);

    EXPECT(decoded_size == sizeof(zeroing));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPMINSB);
    EXPECT(instruction.mask_reg == CDISASM_X86_REG_K2);
    EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
#if USE_DISASM_FORMAT
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpminsb zmm1 {k2}{z}, zmm2, zmm3");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpminsb %zmm3, %zmm2, %zmm1{%k2}{z}");
#endif

    instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        unmasked, sizeof(unmasked), CDISASM_X86_DECODE_FLAG_AVX512,
        &decoded_size);
    EXPECT(decoded_size == sizeof(unmasked));
    EXPECT(instruction.mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction.mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
#else
    expect_error("extra-opcodes OFF zeroing form",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        zeroing, sizeof(zeroing), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("extra-opcodes OFF unmasked form",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        unmasked, sizeof(unmasked), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_feature_gates(void)
{
    static const uint8_t vpminsb[] = {
        0x62, 0xf2, 0x6d, 0x4a, 0x38, 0xcb
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    expect_error("runtime AVX-512 flag gate",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vpminsb, sizeof(vpminsb), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("pre-AVX-512 CPU gate",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        vpminsb, sizeof(vpminsb), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy profile does not use AVX10 runtime route",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vpminsb, sizeof(vpminsb), CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 profile does not use legacy runtime route",
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        vpminsb, sizeof(vpminsb), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    instruction = decode(
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        vpminsb, sizeof(vpminsb), CDISASM_X86_DECODE_FLAG_AVX10,
        &decoded_size);
    EXPECT(decoded_size == sizeof(vpminsb));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPMINSB);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512BW));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512VL));

    instruction = decode(
        CDISASM_CPU_APX, CDISASM_MODE_64,
        vpminsb, sizeof(vpminsb), CDISASM_X86_DECODE_FLAG_AVX10,
        &decoded_size);
    EXPECT(decoded_size == sizeof(vpminsb));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPMINSB);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512BW));
#else
    expect_error("extra-opcodes build gate",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        vpminsb, sizeof(vpminsb), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_apx_preservation(void)
{
    size_t case_index;

    for (case_index = 0u;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        const minmax_case *test = &cases[case_index];
        uint8_t u0_memory[7];
        uint8_t u0_register[7];
        uint8_t u0_missing_sib[7];
        uint8_t b4_register[7];

        make_apx_encoding(test,0,1,UINT8_C(0x08),0u,u0_memory);
        make_apx_encoding(test,0,1,UINT8_C(0xcb),0u,u0_register);
        make_apx_encoding(test,0,1,UINT8_C(0x04),0u,u0_missing_sib);
        make_apx_encoding(test,1,0,UINT8_C(0xcb),0u,b4_register);
#if USE_EXTRA_OPCODES
        {
            static const struct address_case {
                uint8_t b4;
                uint8_t u0;
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
            const cdisasm_x86_decode_option flags =
                cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_X86,CDISASM_MODE_64);
            const cdisasm_x86_decode_option no_apx =
                flags & ~CDISASM_X86_DECODE_FLAG_APX;
            size_t address_index;

            for (address_index = 0u;
                 address_index < sizeof(addresses) / sizeof(addresses[0]);
                 ++address_index) {
                uint8_t code[7];
                uint32_t decoded_size;
                cdisasm_instruction instruction;

                make_apx_encoding(test,addresses[address_index].b4,
                    addresses[address_index].u0,
                    addresses[address_index].modrm,
                    addresses[address_index].sib,code);
                instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                    code,addresses[address_index].size,
                    flags,&decoded_size);
                EXPECT(decoded_size == addresses[address_index].size);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == test->name_id);
                EXPECT(instruction.form_id == test->evex_xmm_memory);
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
                    == (test->feature_group
                        == CDISASM_X86_GROUP_AVX512BW));
#if USE_DISASM_FORMAT
                EXPECT(cdisasm_x86_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_X86_INTEL,NULL,0u) != 0u);
                EXPECT(cdisasm_x86_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_X86_ATT,NULL,0u) != 0u);
#endif
            }
            expect_error("packed MIN/MAX U0 runtime APX gate",
                CDISASM_CPU_X86,CDISASM_MODE_64,
                u0_memory,6u,no_apx,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error("packed MIN/MAX U0 CPU APX gate",
                CDISASM_CPU_SKYLAKE_SP,CDISASM_MODE_64,
                u0_memory,6u,flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86,CDISASM_MODE_64,
                    b4_register,6u,flags,&decoded_size);

                EXPECT(decoded_size == 6u);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == test->name_id);
                EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
                    test->evex_xmm_memory + 1u));
                EXPECT(instruction.opcode[2].type
                    == CDISASM_OPERAND_REGISTER);
                EXPECT(instruction.opcode[2].reg
                    == CDISASM_X86_REG_XMM3);
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction,CDISASM_X86_GROUP_APX_F));
            }
            expect_error("packed MIN/MAX B4 register runtime APX gate",
                CDISASM_CPU_X86,CDISASM_MODE_64,
                b4_register,6u,no_apx,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error("packed MIN/MAX B4 register CPU APX gate",
                CDISASM_CPU_SKYLAKE_SP,CDISASM_MODE_64,
                b4_register,6u,flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
#else
        expect_error("packed MIN/MAX U0 extras off",
            CDISASM_CPU_X86,CDISASM_MODE_64,u0_memory,6u,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("packed MIN/MAX B4 register extras off",
            CDISASM_CPU_X86,CDISASM_MODE_64,b4_register,6u,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        expect_error("packed MIN/MAX U0 register reserved",
            CDISASM_CPU_X86,CDISASM_MODE_64,u0_register,6u,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("packed MIN/MAX U0 mode16 reserved",
            CDISASM_CPU_X86,CDISASM_MODE_16,u0_memory,6u,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("packed MIN/MAX U0 mode32 reserved",
            CDISASM_CPU_X86,CDISASM_MODE_32,u0_memory,6u,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("packed MIN/MAX U0 payload first",
            CDISASM_CPU_X86,CDISASM_MODE_64,u0_missing_sib,6u,
            CDISASM_X86_DECODE_FLAG_BASE,CDISASM_STATUS_TRUNCATED);
        expect_error("packed MIN/MAX B4 register mode16 reserved",
            CDISASM_CPU_X86,CDISASM_MODE_16,b4_register,6u,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("packed MIN/MAX B4 register mode32 reserved",
            CDISASM_CPU_X86,CDISASM_MODE_32,b4_register,6u,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_reserved_and_truncated(void)
{
    static const struct invalid_case {
        const char *label;
        uint8_t bytes[7];
        uint8_t size;
    } invalid[] = {
        {"reserved LL=3",
            {0x62, 0xf2, 0x6d, 0x6a, 0x38, 0xcb}, 6},
        {"register source with EVEX.b",
            {0x62, 0xf2, 0x6d, 0x5a, 0x38, 0xcb}, 6},
        {"byte memory broadcast",
            {0x62, 0xf2, 0x6d, 0x5a, 0x38, 0x08}, 6},
        {"zeroing without a mask",
            {0x62, 0xf2, 0x6d, 0xc8, 0x38, 0xcb}, 6},
        {"U0 register source reserved",
            {0x62, 0xf2, 0x69, 0x4a, 0x38, 0xcb}, 6},
        {"legacy operand-size prefix before EVEX",
            {0x66, 0x62, 0xf2, 0x6d, 0x4a, 0x38, 0xcb}, 7}
    };
    static const uint8_t truncated_modrm[] = {
        0x62, 0xf2, 0x6d, 0x4a, 0x38
    };
    static const uint8_t truncated_disp8[] = {
        0x62, 0xf2, 0x6d, 0x4a, 0x38, 0x48
    };
    size_t index;

    for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error(invalid[index].label,
            CDISASM_CPU_X86, CDISASM_MODE_64,
            invalid[index].bytes, invalid[index].size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("truncated register form",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_modrm, sizeof(truncated_modrm),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_error("truncated compressed displacement",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_disp8, sizeof(truncated_disp8),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
}

static void test_legacy_32bit_mode(void)
{
    static const uint8_t low_registers[] = {
        0x62, 0xf2, 0x6d, 0x0a, 0x38, 0xcb
    };
    static const uint8_t extended_source[] = {
        0x62, 0xf2, 0x6d, 0x02, 0x38, 0xcb
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_32,
        low_registers, sizeof(low_registers),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);

    EXPECT(decoded_size == sizeof(low_registers));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPMINSB);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM2);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM3);
#else
    expect_error("extra-opcodes OFF 32-bit form",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        low_registers, sizeof(low_registers),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    expect_error("EVEX V-prime extension outside long mode",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        extended_source, sizeof(extended_source),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void reject_format(const cdisasm_instruction *instruction)
{
    static const uint32_t syntaxes[2] = {
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        CDISASM_FORMAT_SYNTAX_X86_ATT
    };
    size_t syntax_index;

    for (syntax_index = 0u; syntax_index < 2u; ++syntax_index) {
        char output[96] = {'x'};

        EXPECT(cdisasm_x86_format(instruction,syntaxes[syntax_index],
            output,sizeof(output)) == 0u);
        EXPECT(output[0] == '\0');
    }
}
#endif

static void test_formatter_schema(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    const cdisasm_x86_decode_option flags =
        cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_X86,CDISASM_MODE_64);
    size_t case_index;

    for (case_index = 0u;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        const minmax_case *test = &cases[case_index];

        if (test->classic_xmm_memory != 0u) {
            uint8_t code[6];
            size_t code_size;
            uint32_t decoded_size;
            cdisasm_instruction instruction;
            cdisasm_instruction forged;
            char intel[96];
            char att[96];

            make_classic_encoding(
                test,0u,0u,UINT8_C(0xcb),code,&code_size);
            instruction = decode(CDISASM_CPU_X86,CDISASM_MODE_64,
                code,code_size,flags,&decoded_size);
            EXPECT(decoded_size == code_size);
            (void)snprintf(intel,sizeof(intel),
                "%s xmm1, xmm2, xmm3",test->mnemonic);
            (void)snprintf(att,sizeof(att),
                "%s %%xmm3, %%xmm2, %%xmm1",test->mnemonic);
            expect_format(&instruction,
                CDISASM_FORMAT_SYNTAX_X86_INTEL,intel);
            expect_format(&instruction,
                CDISASM_FORMAT_SYNTAX_X86_ATT,att);

            forged = instruction;
            forged.name_id = cases[(case_index + 1u)
                % (sizeof(cases) / sizeof(cases[0]))].name_id;
            reject_format(&forged);
            forged = instruction;
            forged.form_id ^= UINT16_C(1);
            reject_format(&forged);
            forged = instruction;
            forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
            forged.opcode_flags |= CDISASM_PREFIX_EVEX;
            reject_format(&forged);
            forged = instruction;
            forged.operand_count = 2u;
            reject_format(&forged);
            forged = instruction;
            forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ;
            reject_format(&forged);
            forged = instruction;
            ++forged.opcode[1].size;
            reject_format(&forged);
            forged = instruction;
            forged.x86_group_count = 0u;
            reject_format(&forged);
            forged = instruction;
            forged.mask_reg = CDISASM_X86_REG_K1;
            forged.mask_mode = CDISASM_X86_MASK_MERGE;
            reject_format(&forged);
            forged = instruction;
            forged.encoding.immediate_count = 1u;
            forged.encoding.immediate_size[0] = 1u;
            forged.encoding.immediate_offset[0] = forged.opcode_size;
            reject_format(&forged);
        }

        {
            unsigned int length;

            for (length = 0u; length < 3u; ++length) {
                unsigned int register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    uint8_t code[] = {
                        0x62,(uint8_t)(0xf0u | test->map),
                        (uint8_t)(test->w != 0u ? 0xed : 0x6d),
                        (uint8_t)(0x08u | (length << 5)),
                        test->opcode,
                        (uint8_t)(register_form ? 0xcb : 0x00)
                    };
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86,CDISASM_MODE_64,
                        code,sizeof(code),flags,&decoded_size);
                    cdisasm_instruction forged;

                    EXPECT(decoded_size == sizeof(code));
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
                        (length == 0u ? test->evex_xmm_memory
                            : length == 1u ? test->evex_ymm_memory
                            : test->evex_zmm_memory)
                        + register_form));
                    EXPECT(cdisasm_x86_format(&instruction,
                        CDISASM_FORMAT_SYNTAX_X86_INTEL,NULL,0u) != 0u);
                    EXPECT(cdisasm_x86_format(&instruction,
                        CDISASM_FORMAT_SYNTAX_X86_ATT,NULL,0u) != 0u);

                    forged = instruction;
                    forged.name_id = cases[(case_index + 1u)
                        % (sizeof(cases) / sizeof(cases[0]))].name_id;
                    reject_format(&forged);
                    forged = instruction;
                    forged.form_id ^= UINT16_C(1);
                    reject_format(&forged);
                    forged = instruction;
                    forged.opcode_flags |=
                        CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
                    reject_format(&forged);
                    forged = instruction;
                    forged.opcode[0].access =
                        CDISASM_OPERAND_ACCESS_READ;
                    reject_format(&forged);
                    forged = instruction;
                    ++forged.opcode[2].size;
                    reject_format(&forged);
                    forged = instruction;
                    forged.x86_group_count = 0u;
                    reject_format(&forged);
                    forged = instruction;
                    forged.encoding.prefix_size = 1u;
                    reject_format(&forged);
                    forged = instruction;
                    forged.encoding.immediate_count = 1u;
                    forged.encoding.immediate_size[0] = 1u;
                    forged.encoding.immediate_offset[0] =
                        forged.opcode_size;
                    reject_format(&forged);
                    if (register_form != 0u) {
                        forged = instruction;
                        forged.opcode[2].broadcast =
                            CDISASM_X86_BROADCAST_1_TO_16;
                        reject_format(&forged);
                    } else {
                        forged = instruction;
                        forged.opcode[2].base_reg = CDISASM_X86_REG_R16;
                        reject_format(&forged);
                    }
                }
            }
        }
    }
#endif
}

int main(void)
{
    test_name_catalog();
    test_classic_control_partition();
    test_classic_forms_gates_and_neighbors();
    test_register_matrix();
    test_w_ignored_rows();
    test_memory_matrix();
    test_zeroing_and_unmasked();
    test_feature_gates();
    test_apx_preservation();
    test_reserved_and_truncated();
    test_legacy_32bit_mode();
    test_formatter_schema();

    if (failures != 0) {
        fprintf(stderr,
            "x86 packed integer MIN/MAX tests failed: %d "
            "(extra=%d, format=%d)\n",
            failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("x86 packed integer MIN/MAX tests passed "
           "(extra=%d, format=%d)\n",
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
