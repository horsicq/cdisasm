#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_NAME_VADDSUBPD == UINT16_C(893),
               "AVX core name range start changed");
_Static_assert(CDISASM_X86_NAME_VCVTSS2SD == UINT16_C(916),
               "AVX core name range end changed");
_Static_assert(CDISASM_X86_NAME_COUNT >= UINT16_C(917),
               "AVX core name range is incomplete");

enum test_shape {
    TEST_NDS_PACKED,
    TEST_NDS_SCALAR,
    TEST_UNARY_EQUAL,
    TEST_UNARY_WIDEN,
    TEST_UNARY_NARROW
};

typedef struct avx_case {
    uint8_t opcode;
    uint8_t prefix;
    uint8_t w;
    uint8_t shape;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} avx_case;

static const avx_case vex_cases[] = {
    {0xd0, 1, 0, TEST_NDS_PACKED, CDISASM_X86_NAME_VADDSUBPD, "vaddsubpd"},
    {0xd0, 3, 0, TEST_NDS_PACKED, CDISASM_X86_NAME_VADDSUBPS, "vaddsubps"},
    {0x7c, 1, 0, TEST_NDS_PACKED, CDISASM_X86_NAME_VHADDPD, "vhaddpd"},
    {0x7c, 3, 0, TEST_NDS_PACKED, CDISASM_X86_NAME_VHADDPS, "vhaddps"},
    {0x7d, 1, 0, TEST_NDS_PACKED, CDISASM_X86_NAME_VHSUBPD, "vhsubpd"},
    {0x7d, 3, 0, TEST_NDS_PACKED, CDISASM_X86_NAME_VHSUBPS, "vhsubps"},
    {0x53, 0, 0, TEST_UNARY_EQUAL, CDISASM_X86_NAME_VRCPPS, "vrcpps"},
    {0x53, 2, 0, TEST_NDS_SCALAR, CDISASM_X86_NAME_VRCPSS, "vrcpss"},
    {0x52, 0, 0, TEST_UNARY_EQUAL, CDISASM_X86_NAME_VRSQRTPS, "vrsqrtps"},
    {0x52, 2, 0, TEST_NDS_SCALAR, CDISASM_X86_NAME_VRSQRTSS, "vrsqrtss"},
    {0x51, 1, 0, TEST_UNARY_EQUAL, CDISASM_X86_NAME_VSQRTPD, "vsqrtpd"},
    {0x51, 0, 0, TEST_UNARY_EQUAL, CDISASM_X86_NAME_VSQRTPS, "vsqrtps"},
    {0x51, 3, 0, TEST_NDS_SCALAR, CDISASM_X86_NAME_VSQRTSD, "vsqrtsd"},
    {0x51, 2, 0, TEST_NDS_SCALAR, CDISASM_X86_NAME_VSQRTSS, "vsqrtss"},
    {0xe6, 2, 0, TEST_UNARY_WIDEN, CDISASM_X86_NAME_VCVTDQ2PD, "vcvtdq2pd"},
    {0x5b, 0, 0, TEST_UNARY_EQUAL, CDISASM_X86_NAME_VCVTDQ2PS, "vcvtdq2ps"},
    {0xe6, 3, 0, TEST_UNARY_NARROW, CDISASM_X86_NAME_VCVTPD2DQ, "vcvtpd2dq"},
    {0xe6, 1, 0, TEST_UNARY_NARROW, CDISASM_X86_NAME_VCVTTPD2DQ, "vcvttpd2dq"},
    {0x5a, 1, 0, TEST_UNARY_NARROW, CDISASM_X86_NAME_VCVTPD2PS, "vcvtpd2ps"},
    {0x5b, 1, 0, TEST_UNARY_EQUAL, CDISASM_X86_NAME_VCVTPS2DQ, "vcvtps2dq"},
    {0x5b, 2, 0, TEST_UNARY_EQUAL, CDISASM_X86_NAME_VCVTTPS2DQ, "vcvttps2dq"},
    {0x5a, 0, 0, TEST_UNARY_WIDEN, CDISASM_X86_NAME_VCVTPS2PD, "vcvtps2pd"},
    {0x5a, 3, 0, TEST_NDS_SCALAR, CDISASM_X86_NAME_VCVTSD2SS, "vcvtsd2ss"},
    {0x5a, 2, 0, TEST_NDS_SCALAR, CDISASM_X86_NAME_VCVTSS2SD, "vcvtss2sd"}
};

static const avx_case evex_cases[] = {
    {0x51, 1, 1, TEST_UNARY_EQUAL, CDISASM_X86_NAME_VSQRTPD, "vsqrtpd"},
    {0x51, 0, 0, TEST_UNARY_EQUAL, CDISASM_X86_NAME_VSQRTPS, "vsqrtps"},
    {0x51, 3, 1, TEST_NDS_SCALAR, CDISASM_X86_NAME_VSQRTSD, "vsqrtsd"},
    {0x51, 2, 0, TEST_NDS_SCALAR, CDISASM_X86_NAME_VSQRTSS, "vsqrtss"},
    {0xe6, 2, 0, TEST_UNARY_WIDEN, CDISASM_X86_NAME_VCVTDQ2PD, "vcvtdq2pd"},
    {0x5b, 0, 0, TEST_UNARY_EQUAL, CDISASM_X86_NAME_VCVTDQ2PS, "vcvtdq2ps"},
    {0xe6, 3, 1, TEST_UNARY_NARROW, CDISASM_X86_NAME_VCVTPD2DQ, "vcvtpd2dq"},
    {0xe6, 1, 1, TEST_UNARY_NARROW, CDISASM_X86_NAME_VCVTTPD2DQ, "vcvttpd2dq"},
    {0x5a, 1, 1, TEST_UNARY_NARROW, CDISASM_X86_NAME_VCVTPD2PS, "vcvtpd2ps"},
    {0x5b, 1, 0, TEST_UNARY_EQUAL, CDISASM_X86_NAME_VCVTPS2DQ, "vcvtps2dq"},
    {0x5b, 2, 0, TEST_UNARY_EQUAL, CDISASM_X86_NAME_VCVTTPS2DQ, "vcvttps2dq"},
    {0x5a, 0, 0, TEST_UNARY_WIDEN, CDISASM_X86_NAME_VCVTPS2PD, "vcvtps2pd"},
    {0x5a, 3, 1, TEST_NDS_SCALAR, CDISASM_X86_NAME_VCVTSD2SS, "vcvtsd2ss"},
    {0x5a, 2, 0, TEST_NDS_SCALAR, CDISASM_X86_NAME_VCVTSS2SD, "vcvtss2sd"}
};

static int failures;

#if USE_EXTRA_OPCODES
#define STRUCTURAL_FLAGS CDISASM_X86_DECODE_FLAG_ALL
#else
#define STRUCTURAL_FLAGS CDISASM_X86_DECODE_FLAG_BASE
#endif

#define EXPECT(expression)                                                     \
    do {                                                                       \
        if (!(expression)) {                                                   \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",             \
                    __FILE__, __LINE__, #expression);                          \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

static cdisasm_instruction decode(
    cdisasm_cpu_id cpu,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu, CDISASM_MODE_64, bytes, size, UINT64_C(0x1000), flags,
        &instruction);
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
    cdisasm_cpu_id cpu,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu, bytes, size, flags, &decoded_size);

    if (decoded_size != 0 || !is_error_only(&instruction, status)) {
        fprintf(stderr,
            "unexpected result: opcode=%02x expected=%u actual=%u decoded=%u\n",
            size > 4u ? bytes[4] : size > 2u ? bytes[2] : 0u,
            (unsigned int)status,
            (unsigned int)instruction.last_error_id,
            (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id vector_reg(unsigned int index, unsigned int bits)
{
    if (bits == 128u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + index);
    }
    if (bits == 256u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_YMM0 + index);
    }
    return (cdisasm_x86_reg_id)(CDISASM_X86_REG_ZMM0 + index);
}

static unsigned int destination_bits(const avx_case *test, unsigned int vl)
{
    if (test->shape == TEST_NDS_SCALAR) {
        return 128u;
    }
    if (test->shape == TEST_UNARY_NARROW) {
        return vl == 512u ? 256u : 128u;
    }
    return vl;
}

static unsigned int source_bits(const avx_case *test, unsigned int vl)
{
    if (test->shape == TEST_NDS_SCALAR) {
        return 128u;
    }
    if (test->shape == TEST_UNARY_WIDEN) {
        return vl == 128u ? 128u : vl / 2u;
    }
    return vl;
}

static void expect_register(
    const cdisasm_instruction *instruction,
    unsigned int operand,
    unsigned int reg_index,
    unsigned int bits,
    cdisasm_operand_access access)
{
    EXPECT(operand < instruction->operand_count);
    EXPECT(instruction->opcode[operand].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[operand].reg == vector_reg(reg_index, bits));
    EXPECT(instruction->opcode[operand].size == bits / 8u);
    EXPECT(instruction->opcode[operand].access == access);
}

#if USE_DISASM_FORMAT
static const char *reg_text(unsigned int bits, unsigned int index, int att)
{
    static char buffers[6][12];
    static unsigned int cursor;
    char *buffer = buffers[cursor++ % 6u];

    snprintf(buffer, 12, "%s%s%u", att ? "%" : "",
        bits == 128u ? "xmm" : bits == 256u ? "ymm" : "zmm", index);
    return buffer;
}

static void expect_format(
    const cdisasm_instruction *instruction,
    const avx_case *test,
    unsigned int dest_bits,
    unsigned int src_bits)
{
    char expected[128];
    char actual[128];
    size_t length;
    const int nds = test->shape == TEST_NDS_PACKED
        || test->shape == TEST_NDS_SCALAR;

    if (nds) {
        snprintf(expected, sizeof(expected), "%s %s, %s, %s",
            test->mnemonic, reg_text(dest_bits, 1, 0),
            reg_text(src_bits, 2, 0), reg_text(src_bits, 3, 0));
    } else {
        snprintf(expected, sizeof(expected), "%s %s, %s",
            test->mnemonic, reg_text(dest_bits, 1, 0),
            reg_text(src_bits, 3, 0));
    }
    length = cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        actual, sizeof(actual));
    EXPECT(length == strlen(expected));
    EXPECT(strcmp(actual, expected) == 0);

    if (nds) {
        snprintf(expected, sizeof(expected), "%s %s, %s, %s",
            test->mnemonic, reg_text(src_bits, 3, 1),
            reg_text(src_bits, 2, 1), reg_text(dest_bits, 1, 1));
    } else {
        snprintf(expected, sizeof(expected), "%s %s, %s",
            test->mnemonic, reg_text(src_bits, 3, 1),
            reg_text(dest_bits, 1, 1));
    }
    length = cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        actual, sizeof(actual));
    EXPECT(length == strlen(expected));
    EXPECT(strcmp(actual, expected) == 0);
}
#endif
#endif

static int has_nds_source(const avx_case *test)
{
    return test->shape == TEST_NDS_PACKED
        || test->shape == TEST_NDS_SCALAR;
}

static void test_all_vex_names(void)
{
    size_t index;

    EXPECT(sizeof(vex_cases) / sizeof(vex_cases[0]) == 24u);
    for (index = 0; index < sizeof(vex_cases) / sizeof(vex_cases[0]); ++index) {
        const avx_case *test = &vex_cases[index];
        unsigned int l;

        for (l = 0; l != 2; ++l) {
            const unsigned int vl = test->shape == TEST_NDS_SCALAR
                ? 128u : 128u << l;
            const unsigned int source = has_nds_source(test) ? 2u : 0u;
            uint8_t code[] = {
                0xc5,
                (uint8_t)(0x80u | (((~source) & 15u) << 3)
                    | (l << 2) | test->prefix),
                test->opcode,
                0xcb
            };

#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_SANDY_BRIDGE, code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_AVX, &decoded_size);
            const unsigned int dest = destination_bits(test, vl);
            const unsigned int src = source_bits(test, vl);

            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id == test->name_id);
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX) != 0);
            EXPECT(instruction.operand_count == (has_nds_source(test) ? 3u : 2u));
            expect_register(&instruction, 0, 1, dest,
                            CDISASM_OPERAND_ACCESS_WRITE);
            if (has_nds_source(test)) {
                expect_register(&instruction, 1, 2, src,
                                CDISASM_OPERAND_ACCESS_READ);
                expect_register(&instruction, 2, 3, src,
                                CDISASM_OPERAND_ACCESS_READ);
            } else {
                expect_register(&instruction, 1, 3, src,
                                CDISASM_OPERAND_ACCESS_READ);
            }
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX));
            EXPECT(instruction.encoding.prefix_size == 2u);
            EXPECT(instruction.encoding.opcode_offset == 2u);
            EXPECT(instruction.encoding.modrm_offset == 3u);
#if USE_DISASM_FORMAT
            expect_format(&instruction, test, dest, src);
#endif
#else
            (void)vl;
            expect_error(CDISASM_CPU_X86, code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

static void test_all_evex_names_and_widths(void)
{
    size_t index;

    EXPECT(sizeof(evex_cases) / sizeof(evex_cases[0]) == 14u);
    for (index = 0; index < sizeof(evex_cases) / sizeof(evex_cases[0]); ++index) {
        const avx_case *test = &evex_cases[index];
        unsigned int ll;

        for (ll = 0; ll != 3; ++ll) {
            const unsigned int source = has_nds_source(test) ? 2u : 0u;
            const unsigned int vl = test->shape == TEST_NDS_SCALAR
                ? 128u : 128u << ll;
            uint8_t code[] = {
                0x62, 0xf1,
                (uint8_t)((test->w << 7) | (((~source) & 15u) << 3)
                    | 0x04u | test->prefix),
                (uint8_t)(0x08u | (ll << 5)),
                test->opcode, 0xcb
            };

#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
            const unsigned int dest = destination_bits(test, vl);
            const unsigned int src = source_bits(test, vl);

            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id == test->name_id);
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0);
            EXPECT(instruction.operand_count == (has_nds_source(test) ? 3u : 2u));
            expect_register(&instruction, 0, 1, dest,
                            CDISASM_OPERAND_ACCESS_WRITE);
            if (has_nds_source(test)) {
                expect_register(&instruction, 1, 2, src,
                                CDISASM_OPERAND_ACCESS_READ);
                expect_register(&instruction, 2, 3, src,
                                CDISASM_OPERAND_ACCESS_READ);
            } else {
                expect_register(&instruction, 1, 3, src,
                                CDISASM_OPERAND_ACCESS_READ);
            }
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512F));
            EXPECT(cdisasm_instruction_has_x86_group(
                       &instruction, CDISASM_X86_GROUP_AVX512VL)
                == (test->shape != TEST_NDS_SCALAR && vl < 512u));
            EXPECT(instruction.encoding.prefix_size == 4u);
            EXPECT(instruction.encoding.opcode_offset == 4u);
            EXPECT(instruction.encoding.modrm_offset == 5u);
#if USE_DISASM_FORMAT
            expect_format(&instruction, test, dest, src);
#endif
#else
            (void)vl;
            expect_error(CDISASM_CPU_X86, code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

static void test_evex_controls_and_tuples(void)
{
    static const uint8_t widen_register[] =
        {0x62, 0xf1, 0x7e, 0x48, 0xe6, 0xca};
    static const uint8_t narrow_register[] =
        {0x62, 0xf1, 0xff, 0x48, 0xe6, 0xca};
    static const uint8_t scalar_sae[] =
        {0x62, 0xf1, 0x6e, 0x18, 0x5a, 0xcb};
    static const uint8_t ignored_control[] =
        {0x62, 0xf1, 0x7e, 0x18, 0xe6, 0xca};
    static const uint8_t widen_memory[] =
        {0x62, 0xf1, 0x7e, 0x48, 0xe6, 0x4a, 0x02};
    static const uint8_t widen_broadcast[] =
        {0x62, 0xf1, 0x7e, 0x58, 0xe6, 0x4a, 0x02};
    static const uint8_t narrow_memory[] =
        {0x62, 0xf1, 0xff, 0x48, 0xe6, 0x4a, 0x02};
    static const uint8_t narrow_broadcast[] =
        {0x62, 0xf1, 0xff, 0x58, 0xe6, 0x4a, 0x02};

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, widen_register, sizeof(widen_register),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);

    EXPECT(decoded_size == sizeof(widen_register));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VCVTDQ2PD);
    expect_register(&instruction, 0, 1, 512u, CDISASM_OPERAND_ACCESS_WRITE);
    expect_register(&instruction, 1, 2, 256u, CDISASM_OPERAND_ACCESS_READ);

    instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, narrow_register, sizeof(narrow_register),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
    EXPECT(decoded_size == sizeof(narrow_register));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VCVTPD2DQ);
    expect_register(&instruction, 0, 1, 256u, CDISASM_OPERAND_ACCESS_WRITE);
    expect_register(&instruction, 1, 2, 512u, CDISASM_OPERAND_ACCESS_READ);

    instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, scalar_sae, sizeof(scalar_sae),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
    EXPECT(decoded_size == sizeof(scalar_sae));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VCVTSS2SD);
    EXPECT(instruction.sae == CDISASM_X86_SAE_ENABLED);
    EXPECT(instruction.rounding == CDISASM_X86_ROUNDING_NONE);

    instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, ignored_control, sizeof(ignored_control),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
    EXPECT(decoded_size == sizeof(ignored_control));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VCVTDQ2PD);
    expect_register(&instruction, 0, 1, 512u, CDISASM_OPERAND_ACCESS_WRITE);
    expect_register(&instruction, 1, 2, 256u, CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction.rounding == CDISASM_X86_ROUNDING_NONE);

    instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, widen_memory, sizeof(widen_memory),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
    EXPECT(decoded_size == sizeof(widen_memory));
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[1].size == 32u);
    EXPECT(instruction.opcode[1].imm == UINT64_C(64));
    EXPECT(instruction.opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);

    instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, widen_broadcast, sizeof(widen_broadcast),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
    EXPECT(decoded_size == sizeof(widen_broadcast));
    EXPECT(instruction.opcode[1].size == 4u);
    EXPECT(instruction.opcode[1].imm == UINT64_C(8));
    EXPECT(instruction.opcode[1].broadcast == CDISASM_X86_BROADCAST_1_TO_8);

    instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, narrow_memory, sizeof(narrow_memory),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
    EXPECT(decoded_size == sizeof(narrow_memory));
    EXPECT(instruction.opcode[1].size == 64u);
    EXPECT(instruction.opcode[1].imm == UINT64_C(128));

    instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, narrow_broadcast, sizeof(narrow_broadcast),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
    EXPECT(decoded_size == sizeof(narrow_broadcast));
    EXPECT(instruction.opcode[1].size == 8u);
    EXPECT(instruction.opcode[1].imm == UINT64_C(16));
    EXPECT(instruction.opcode[1].broadcast == CDISASM_X86_BROADCAST_1_TO_8);

#if USE_DISASM_FORMAT
    {
        char text[128];
        size_t length = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text));
        if (strcmp(text,
                "vcvtpd2dq ymm1, qword ptr [rdx + 0x10]{1to8}") != 0) {
            fprintf(stderr, "format mismatch: '%s'\n", text);
        }
        EXPECT(length == strlen(
            "vcvtpd2dq ymm1, qword ptr [rdx + 0x10]{1to8}"));
        EXPECT(strcmp(text,
            "vcvtpd2dq ymm1, qword ptr [rdx + 0x10]{1to8}") == 0);
    }
    instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, scalar_sae, sizeof(scalar_sae),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
    {
        char text[128];
        cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text));
        EXPECT(strcmp(text, "vcvtss2sd xmm1, xmm2, xmm3, {sae}") == 0);
        cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            text, sizeof(text));
        EXPECT(strcmp(text, "vcvtss2sd {sae}, %xmm3, %xmm2, %xmm1") == 0);
    }
#endif
#else
    expect_error(CDISASM_CPU_X86, widen_register, sizeof(widen_register),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, narrow_register, sizeof(narrow_register),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, scalar_sae, sizeof(scalar_sae),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, ignored_control, sizeof(ignored_control),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, widen_memory, sizeof(widen_memory),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, widen_broadcast, sizeof(widen_broadcast),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, narrow_memory, sizeof(narrow_memory),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, narrow_broadcast, sizeof(narrow_broadcast),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_policy_reserved_and_unimplemented(void)
{
    static const uint8_t vex[] = {0xc5, 0xe9, 0xd0, 0xcb};
    static const uint8_t evex[] = {0x62, 0xf1, 0x7c, 0x48, 0x51, 0xca};
    static const uint8_t vex_bad_vvvv[] = {0xc5, 0xe8, 0x51, 0xca};
    static const uint8_t vex_bad_pp[] = {0xc5, 0xe8, 0x7c, 0xcb};
    static const uint8_t evex_bad_w[] =
        {0x62, 0xf1, 0xfc, 0x48, 0x51, 0xca};
    static const uint8_t evex_bad_ll[] =
        {0x62, 0xf1, 0x7c, 0x68, 0x51, 0xca};
    static const uint8_t evex_zero_no_mask[] =
        {0x62, 0xf1, 0x7c, 0xc8, 0x51, 0xca};
    static const uint8_t evex_scalar_b_memory[] =
        {0x62, 0xf1, 0x6e, 0x18, 0x51, 0x08};
    static const uint8_t evex_bad_vvvv[] =
        {0x62, 0xf1, 0x6c, 0x48, 0x51, 0xca};
    static const uint8_t conversion_sibling[] =
        {0x62, 0xf1, 0xfe, 0x48, 0xe6, 0xca};
    static const uint8_t truncated[] =
        {0x62, 0xf1, 0x7c, 0x48, 0x51};

    expect_error(CDISASM_CPU_X86, vex_bad_vvvv, sizeof(vex_bad_vvvv),
        STRUCTURAL_FLAGS, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, vex_bad_pp, sizeof(vex_bad_pp),
        STRUCTURAL_FLAGS, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, evex_bad_w, sizeof(evex_bad_w),
        STRUCTURAL_FLAGS, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, evex_bad_ll, sizeof(evex_bad_ll),
        STRUCTURAL_FLAGS, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, evex_zero_no_mask,
        sizeof(evex_zero_no_mask), STRUCTURAL_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, evex_scalar_b_memory,
        sizeof(evex_scalar_b_memory), STRUCTURAL_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, evex_bad_vvvv, sizeof(evex_bad_vvvv),
        STRUCTURAL_FLAGS, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, conversion_sibling,
        sizeof(conversion_sibling), STRUCTURAL_FLAGS,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, truncated, sizeof(truncated),
        STRUCTURAL_FLAGS, CDISASM_STATUS_TRUNCATED);

#if USE_EXTRA_OPCODES
    expect_error(CDISASM_CPU_CORE_2, vex, sizeof(vex),
        CDISASM_X86_DECODE_FLAG_AVX, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_SANDY_BRIDGE, vex, sizeof(vex),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_HASWELL, evex, sizeof(evex),
        CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_SKYLAKE_SP, evex, sizeof(evex),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_AVX10, evex, sizeof(evex),
            CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);

        EXPECT(decoded_size == sizeof(evex));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VSQRTPS);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512F));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512VL));
    }
#else
    expect_error(CDISASM_CPU_X86, vex, sizeof(vex),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, evex, sizeof(evex),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

int main(void)
{
    test_all_vex_names();
    test_all_evex_names_and_widths();
    test_evex_controls_and_tuples();
    test_policy_reserved_and_unimplemented();

    if (failures != 0) {
        fprintf(stderr, "x86 AVX core tests failed: %d (extra=%d format=%d)\n",
            failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("x86 AVX core tests passed (extra=%d format=%d)\n",
        USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
