#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct add_sub_case {
    uint8_t opcode;
    uint8_t w;
    uint8_t w_ignored;
    uint8_t element_bits;
    uint8_t broadcast;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_group_id feature_group;
    const char *mnemonic;
} add_sub_case;

/* Complete modular EVEX.66.0F packed-integer ADD/SUB matrix. */
static const add_sub_case cases[] = {
    {0xfc, 0, 1,  8, 0, CDISASM_X86_NAME_VPADDB,
        CDISASM_X86_GROUP_AVX512BW, "vpaddb"},
    {0xfd, 0, 1, 16, 0, CDISASM_X86_NAME_VPADDW,
        CDISASM_X86_GROUP_AVX512BW, "vpaddw"},
    {0xfe, 0, 0, 32, 1, CDISASM_X86_NAME_VPADDD,
        CDISASM_X86_GROUP_AVX512F, "vpaddd"},
    {0xd4, 1, 0, 64, 1, CDISASM_X86_NAME_VPADDQ,
        CDISASM_X86_GROUP_AVX512F, "vpaddq"},
    {0xf8, 0, 1,  8, 0, CDISASM_X86_NAME_VPSUBB,
        CDISASM_X86_GROUP_AVX512BW, "vpsubb"},
    {0xf9, 0, 1, 16, 0, CDISASM_X86_NAME_VPSUBW,
        CDISASM_X86_GROUP_AVX512BW, "vpsubw"},
    {0xfa, 0, 0, 32, 1, CDISASM_X86_NAME_VPSUBD,
        CDISASM_X86_GROUP_AVX512F, "vpsubd"},
    {0xfb, 1, 0, 64, 1, CDISASM_X86_NAME_VPSUBQ,
        CDISASM_X86_GROUP_AVX512F, "vpsubq"}
};

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",             \
                __FILE__, __LINE__, #expression);                            \
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
    const add_sub_case *test,
    unsigned int length,
    unsigned int w,
    uint8_t code[6])
{
    code[0] = UINT8_C(0x62);
    code[1] = UINT8_C(0xf1);
    code[2] = (uint8_t)(w != 0 ? UINT8_C(0xed) : UINT8_C(0x6d));
    code[3] = (uint8_t)(UINT8_C(0x0a) | (length << 5));
    code[4] = test->opcode;
    code[5] = UINT8_C(0xcb);
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id vector_register(unsigned int index,
                                           unsigned int bits)
{
    if (bits == 128u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + index);
    }
    if (bits == 256u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_YMM0 + index);
    }
    return (cdisasm_x86_reg_id)(CDISASM_X86_REG_ZMM0 + index);
}

#if USE_DISASM_FORMAT
static void expect_format(
    const cdisasm_instruction *instruction,
    uint32_t syntax,
    const char *expected)
{
    char buffer[192];
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

static void test_name_catalog(void)
{
    EXPECT(sizeof(cases) / sizeof(cases[0]) == 8u);
    EXPECT(CDISASM_X86_NAME_VPADDB == UINT16_C(642));
    EXPECT(CDISASM_X86_NAME_VPADDW == UINT16_C(643));
    EXPECT(CDISASM_X86_NAME_VPADDD == UINT16_C(644));
    EXPECT(CDISASM_X86_NAME_VPADDQ == UINT16_C(645));
    EXPECT(CDISASM_X86_NAME_VPSUBB == UINT16_C(646));
    EXPECT(CDISASM_X86_NAME_VPSUBW == UINT16_C(647));
    EXPECT(CDISASM_X86_NAME_VPSUBD == UINT16_C(648));
    EXPECT(CDISASM_X86_NAME_VPSUBQ == UINT16_C(649));
    EXPECT(CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1));
    EXPECT(CDISASM_NAME_VPSUBQ == CDISASM_X86_NAME_VPSUBQ);
}

/* Eight names times three vector lengths: all 24 register shapes. */
static void test_register_matrix(void)
{
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const add_sub_case *test = &cases[index];
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            uint8_t code[6];

            make_register_encoding(test, length, test->w, code);
#if USE_EXTRA_OPCODES
            {
                const unsigned int vector_bits = 128u << length;
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                    &decoded_size);

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == test->name_id);
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
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512DQ));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX10_1));
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
            expect_error("extra-opcodes OFF register form",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

/* Eight names times three full-memory lengths plus the twelve legal D/Q
 * scalar-broadcast lengths: all 36 memory shapes. */
static void test_memory_matrix(void)
{
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const add_sub_case *test = &cases[index];
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            const unsigned int form_count = test->broadcast != 0 ? 2u : 1u;
            unsigned int form;

            for (form = 0; form < form_count; ++form) {
                const int broadcast = form != 0;
                uint8_t code[] = {
                    0x62, 0xf1,
                    (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                    (uint8_t)(0x0a | (length << 5)
                        | (broadcast ? 0x10 : 0x00)),
                    test->opcode, 0x48, 0x02
                };

#if USE_EXTRA_OPCODES
                {
                    const unsigned int vector_bits = 128u << length;
                    const unsigned int memory_bytes = broadcast
                        ? test->element_bits / 8u : vector_bits / 8u;
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                        &decoded_size);

                    EXPECT(decoded_size == sizeof(code));
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id == test->name_id);
                    EXPECT(instruction.operand_count == 3u);
                    EXPECT(instruction.opcode[0].reg
                        == vector_register(1u, vector_bits));
                    EXPECT(instruction.opcode[1].reg
                        == vector_register(2u, vector_bits));
                    EXPECT(instruction.opcode[2].type
                        == CDISASM_OPERAND_MEMORY);
                    EXPECT(instruction.opcode[2].base_reg
                        == CDISASM_X86_REG_RAX);
                    EXPECT(instruction.opcode[2].index_reg
                        == CDISASM_X86_REG_NONE);
                    EXPECT(instruction.opcode[2].size == memory_bytes);
                    EXPECT(instruction.opcode[2].imm
                        == UINT64_C(2) * memory_bytes);
                    EXPECT(instruction.opcode[2].access
                        == CDISASM_OPERAND_ACCESS_READ);
                    EXPECT(instruction.opcode[2].broadcast
                        == (broadcast
                            ? (cdisasm_x86_broadcast)(
                                vector_bits / test->element_bits)
                            : CDISASM_X86_BROADCAST_NONE));
                    EXPECT(instruction.encoding.displacement_offset == 6u);
                    EXPECT(instruction.encoding.displacement_size == 1u);

#if USE_DISASM_FORMAT
                    {
                        const char *reg = length == 0 ? "xmm"
                            : length == 1 ? "ymm" : "zmm";
                        const char *pointer = length == 0 ? "xmmword"
                            : length == 1 ? "ymmword" : "zmmword";
                        char intel[192];
                        char att[192];

                        if (broadcast) {
                            const char *scalar = test->element_bits == 32u
                                ? "dword" : "qword";
                            const unsigned int count =
                                vector_bits / test->element_bits;

                            snprintf(intel, sizeof(intel),
                                "%s %s1 {k2}, %s2, %s ptr "
                                "[rax + 0x%x]{1to%u}",
                                test->mnemonic, reg, reg, scalar,
                                memory_bytes * 2u, count);
                            snprintf(att, sizeof(att),
                                "%s 0x%x(%%rax){1to%u}, %%%s2, "
                                "%%%s1{%%k2}",
                                test->mnemonic, memory_bytes * 2u, count,
                                reg, reg);
                        } else {
                            snprintf(intel, sizeof(intel),
                                "%s %s1 {k2}, %s2, %s ptr "
                                "[rax + 0x%x]",
                                test->mnemonic, reg, reg, pointer,
                                memory_bytes * 2u);
                            snprintf(att, sizeof(att),
                                "%s 0x%x(%%rax), %%%s2, %%%s1{%%k2}",
                                test->mnemonic, memory_bytes * 2u,
                                reg, reg);
                        }
                        expect_format(&instruction,
                            CDISASM_FORMAT_SYNTAX_X86_INTEL, intel);
                        expect_format(&instruction,
                            CDISASM_FORMAT_SYNTAX_X86_ATT, att);
                    }
#endif
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
}

static void test_wig_masking_and_extended_registers(void)
{
    size_t index;
    static const uint8_t zeroing[] = {
        0x62, 0xf1, 0x6d, 0xca, 0xfe, 0xcb
    };
    static const uint8_t unmasked[] = {
        0x62, 0xf1, 0x6d, 0x48, 0xfe, 0xcb
    };
    static const uint8_t extended[] = {
        0x62, 0xa1, 0x6d, 0x40, 0xfe, 0xcb
    };

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const add_sub_case *test = &cases[index];
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
        expect_error("extra-opcodes OFF WIG W=1 form",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

#if USE_EXTRA_OPCODES
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
            zeroing, sizeof(zeroing), CDISASM_X86_DECODE_FLAG_AVX512,
            &decoded_size);

        EXPECT(decoded_size == sizeof(zeroing));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPADDD);
        EXPECT(instruction.mask_reg == CDISASM_X86_REG_K2);
        EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
#if USE_DISASM_FORMAT
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            "vpaddd zmm1 {k2}{z}, zmm2, zmm3");
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            "vpaddd %zmm3, %zmm2, %zmm1{%k2}{z}");
#endif

        instruction = decode(
            CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
            unmasked, sizeof(unmasked), CDISASM_X86_DECODE_FLAG_AVX512,
            &decoded_size);
        EXPECT(decoded_size == sizeof(unmasked));
        EXPECT(instruction.mask_reg == CDISASM_X86_REG_NONE);
        EXPECT(instruction.mask_mode == CDISASM_X86_MASK_NONE);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);

        instruction = decode(
            CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
            extended, sizeof(extended), CDISASM_X86_DECODE_FLAG_AVX512,
            &decoded_size);
        EXPECT(decoded_size == sizeof(extended));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPADDD);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ZMM17);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ZMM18);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_ZMM19);
#if USE_DISASM_FORMAT
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            "vpaddd zmm17, zmm18, zmm19");
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            "vpaddd %zmm19, %zmm18, %zmm17");
#endif
    }
#else
    expect_error("extra-opcodes OFF zeroing form",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        zeroing, sizeof(zeroing), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("extra-opcodes OFF unmasked form",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        unmasked, sizeof(unmasked), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("extra-opcodes OFF extended-register form",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        extended, sizeof(extended), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_feature_gates(void)
{
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const add_sub_case *test = &cases[index];
        uint8_t code[6];

        make_register_encoding(test, 2u, test->w, code);
#if USE_EXTRA_OPCODES
        {
            unsigned int length;

            expect_error("runtime AVX-512 flag gate",
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error("pre-AVX-512 CPU gate",
                CDISASM_CPU_HASWELL, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("legacy profile rejects AVX10 runtime route",
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX10,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error("AVX10 profile rejects legacy runtime route",
                CDISASM_CPU_AVX10, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

            for (length = 0; length != 3; ++length) {
                uint32_t decoded_size;
                cdisasm_instruction instruction;

                make_register_encoding(test, length, test->w, code);
                instruction = decode(
                    CDISASM_CPU_AVX10, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX10,
                    &decoded_size);
                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.name_id == test->name_id);
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX10_1));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512F));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512BW));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512DQ));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512VL));
            }
        }
#else
        expect_error("extra-opcodes build gate",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

#if USE_EXTRA_OPCODES
    {
        uint8_t code[6];
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        make_register_encoding(&cases[0], 2u, cases[0].w, code);
        instruction = decode(
            CDISASM_CPU_APX, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX10,
            &decoded_size);
        EXPECT(decoded_size == sizeof(code));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPADDB);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512BW));
    }
#endif
}

static void test_reserved_unsupported_and_truncated(void)
{
    static const struct invalid_case {
        const char *label;
        uint8_t bytes[7];
        uint8_t size;
    } invalid[] = {
        {"reserved LL=3",
            {0x62, 0xf1, 0x6d, 0x6a, 0xfe, 0xcb}, 6},
        {"register source with EVEX.b",
            {0x62, 0xf1, 0x6d, 0x5a, 0xfe, 0xcb}, 6},
        {"byte memory broadcast",
            {0x62, 0xf1, 0x6d, 0x5a, 0xfc, 0x08}, 6},
        {"word memory broadcast",
            {0x62, 0xf1, 0x6d, 0x5a, 0xfd, 0x08}, 6},
        {"zeroing without a mask",
            {0x62, 0xf1, 0x6d, 0xc8, 0xfe, 0xcb}, 6},
        {"reserved EVEX U bit",
            {0x62, 0xf1, 0x69, 0x4a, 0xfe, 0xcb}, 6},
        {"VPADDD reserved W=1",
            {0x62, 0xf1, 0xed, 0x4a, 0xfe, 0xcb}, 6},
        {"VPADDQ reserved W=0",
            {0x62, 0xf1, 0x6d, 0x4a, 0xd4, 0xcb}, 6},
        {"VPSUBD reserved W=1",
            {0x62, 0xf1, 0xed, 0x4a, 0xfa, 0xcb}, 6},
        {"VPSUBQ reserved W=0",
            {0x62, 0xf1, 0x6d, 0x4a, 0xfb, 0xcb}, 6},
        {"legacy operand-size prefix before EVEX",
            {0x66, 0x62, 0xf1, 0x6d, 0x4a, 0xfe, 0xcb}, 7}
    };
    static const uint8_t unsupported_pp[] = {
        0x62, 0xf1, 0x6c, 0x4a, 0xfe, 0xcb
    };
    static const uint8_t truncated_modrm[] = {
        0x62, 0xf1, 0x6d, 0x4a, 0xfe
    };
    static const uint8_t truncated_disp8[] = {
        0x62, 0xf1, 0x6d, 0x4a, 0xfe, 0x48
    };
    size_t index;

    for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error(invalid[index].label,
            CDISASM_CPU_X86, CDISASM_MODE_64,
            invalid[index].bytes, invalid[index].size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("unowned mandatory-prefix sibling",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        unsupported_pp, sizeof(unsupported_pp),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("truncated register form",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_modrm, sizeof(truncated_modrm),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_error("truncated compressed displacement",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_disp8, sizeof(truncated_disp8),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
}

static void test_legacy_modes(void)
{
    static const uint8_t low_registers[] = {
        0x62, 0xf1, 0x6d, 0x0a, 0xfe, 0xcb
    };
    static const uint8_t extended_source[] = {
        0x62, 0xf1, 0x6d, 0x02, 0xfe, 0xcb
    };
    static const uint8_t extended_destination[] = {
        0x62, 0xe1, 0x6d, 0x0a, 0xfe, 0xcb
    };

#if USE_EXTRA_OPCODES
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_16,
            low_registers, sizeof(low_registers),
            CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);

        EXPECT(decoded_size == sizeof(low_registers));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPADDD);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM2);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM3);

        instruction = decode(
            CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_32,
            low_registers, sizeof(low_registers),
            CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
        EXPECT(decoded_size == sizeof(low_registers));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPADDD);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM2);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM3);
    }
#else
    expect_error("extra-opcodes OFF 16-bit form",
        CDISASM_CPU_X86, CDISASM_MODE_16,
        low_registers, sizeof(low_registers),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
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
    expect_error("EVEX R-prime extension outside long mode",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        extended_destination, sizeof(extended_destination),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

int main(void)
{
    test_name_catalog();
    test_register_matrix();
    test_memory_matrix();
    test_wig_masking_and_extended_registers();
    test_feature_gates();
    test_reserved_unsupported_and_truncated();
    test_legacy_modes();

    if (failures != 0) {
        fprintf(stderr,
            "x86 EVEX integer ADD/SUB tests failed: %d "
            "(extra=%d, format=%d)\n",
            failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("x86 EVEX integer ADD/SUB tests passed "
           "(extra=%d, format=%d)\n",
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
