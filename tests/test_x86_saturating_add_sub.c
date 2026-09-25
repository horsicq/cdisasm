#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct saturating_case {
    uint8_t opcode;
    uint8_t element_bits;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} saturating_case;

/* Complete signed/unsigned saturating packed byte/word ADD/SUB family. */
static const saturating_case cases[] = {
    {0xec,  8, CDISASM_X86_NAME_VPADDSB,   "vpaddsb"},
    {0xed, 16, CDISASM_X86_NAME_VPADDSW,   "vpaddsw"},
    {0xdc,  8, CDISASM_X86_NAME_VPADDUSB,  "vpaddusb"},
    {0xdd, 16, CDISASM_X86_NAME_VPADDUSW,  "vpaddusw"},
    {0xe8,  8, CDISASM_X86_NAME_VPSUBSB,   "vpsubsb"},
    {0xe9, 16, CDISASM_X86_NAME_VPSUBSW,   "vpsubsw"},
    {0xd8,  8, CDISASM_X86_NAME_VPSUBUSB,  "vpsubusb"},
    {0xd9, 16, CDISASM_X86_NAME_VPSUBUSW,  "vpsubusw"}
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

/* variant 0 is VEX2, variant 1 is VEX3.W=0, variant 2 is VEX3.W=1. */
static size_t make_vex_encoding(
    const saturating_case *test,
    unsigned int length,
    unsigned int variant,
    int memory,
    uint8_t code[6])
{
    const uint8_t vex = (uint8_t)(
        (variant == 2u ? UINT8_C(0xe9) : UINT8_C(0x69))
        | (length != 0 ? UINT8_C(0x04) : UINT8_C(0x00)));
    size_t cursor = 0;

    if (variant == 0u) {
        code[cursor++] = UINT8_C(0xc5);
        code[cursor++] = (uint8_t)(UINT8_C(0xe9)
            | (length != 0 ? UINT8_C(0x04) : UINT8_C(0x00)));
    } else {
        code[cursor++] = UINT8_C(0xc4);
        code[cursor++] = UINT8_C(0xe1);
        code[cursor++] = vex;
    }
    code[cursor++] = test->opcode;
    code[cursor++] = memory ? UINT8_C(0x48) : UINT8_C(0xcb);
    if (memory) {
        code[cursor++] = UINT8_C(0x20);
    }
    return cursor;
}

static size_t make_evex_encoding(
    const saturating_case *test,
    unsigned int length,
    unsigned int w,
    int memory,
    uint8_t code[7])
{
    code[0] = UINT8_C(0x62);
    code[1] = UINT8_C(0xf1);
    code[2] = w != 0 ? UINT8_C(0xed) : UINT8_C(0x6d);
    code[3] = (uint8_t)(UINT8_C(0x0a) | (length << 5));
    code[4] = test->opcode;
    code[5] = memory ? UINT8_C(0x48) : UINT8_C(0xcb);
    if (memory) {
        code[6] = UINT8_C(0x02);
        return 7u;
    }
    return 6u;
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id vector_register(
    unsigned int index,
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
    EXPECT(CDISASM_X86_NAME_VPADDSB == UINT16_C(1021));
    EXPECT(CDISASM_X86_NAME_VPADDSW == UINT16_C(1022));
    EXPECT(CDISASM_X86_NAME_VPADDUSB == UINT16_C(1023));
    EXPECT(CDISASM_X86_NAME_VPADDUSW == UINT16_C(1024));
    EXPECT(CDISASM_X86_NAME_VPSUBSB == UINT16_C(1025));
    EXPECT(CDISASM_X86_NAME_VPSUBSW == UINT16_C(1026));
    EXPECT(CDISASM_X86_NAME_VPSUBUSB == UINT16_C(1027));
    EXPECT(CDISASM_X86_NAME_VPSUBUSW == UINT16_C(1028));
    EXPECT(CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1));
    EXPECT(CDISASM_NAME_VPADDSB == CDISASM_X86_NAME_VPADDSB);
    EXPECT(CDISASM_NAME_VPSUBUSW == CDISASM_X86_NAME_VPSUBUSW);
}

/* Eight names, two lengths, register/full-memory, and all three VEX wire
 * variants: 96 legal encodings spanning all 32 operand shapes. */
static void test_vex_matrix(void)
{
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const saturating_case *test = &cases[index];
        unsigned int length;

        for (length = 0; length != 2; ++length) {
            unsigned int variant;

            for (variant = 0; variant != 3; ++variant) {
                unsigned int memory;

                for (memory = 0; memory != 2; ++memory) {
                    uint8_t code[6];
                    size_t code_size = make_vex_encoding(
                        test, length, variant, memory != 0, code);
#if USE_EXTRA_OPCODES
                    const unsigned int vector_bits = 128u << length;
                    const cdisasm_cpu_id cpu = length == 0
                        ? CDISASM_CPU_SANDY_BRIDGE : CDISASM_CPU_HASWELL;
                    const cdisasm_x86_decode_option flags = length == 0
                        ? CDISASM_X86_DECODE_FLAG_AVX
                        : CDISASM_X86_DECODE_FLAG_AVX2;
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        cpu, CDISASM_MODE_64,
                        code, code_size, flags, &decoded_size);

                    EXPECT(decoded_size == code_size);
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id == test->name_id);
                    EXPECT((instruction.opcode_flags
                        & CDISASM_PREFIX_VEX) != 0);
                    EXPECT((instruction.opcode_flags
                        & CDISASM_PREFIX_EVEX) == 0);
                    EXPECT(instruction.operand_count == 3u);
                    EXPECT(instruction.opcode[0].reg
                        == vector_register(1u, vector_bits));
                    EXPECT(instruction.opcode[1].reg
                        == vector_register(2u, vector_bits));
                    EXPECT(instruction.opcode[0].size == vector_bits / 8u);
                    EXPECT(instruction.opcode[1].size == vector_bits / 8u);
                    EXPECT(instruction.opcode[2].size == vector_bits / 8u);
                    EXPECT(instruction.opcode[0].access
                        == CDISASM_OPERAND_ACCESS_WRITE);
                    EXPECT(instruction.opcode[1].access
                        == CDISASM_OPERAND_ACCESS_READ);
                    EXPECT(instruction.opcode[2].access
                        == CDISASM_OPERAND_ACCESS_READ);
                    if (memory == 0) {
                        EXPECT(instruction.opcode[2].type
                            == CDISASM_OPERAND_REGISTER);
                        EXPECT(instruction.opcode[2].reg
                            == vector_register(3u, vector_bits));
                    } else {
                        EXPECT(instruction.opcode[2].type
                            == CDISASM_OPERAND_MEMORY);
                        EXPECT(instruction.opcode[2].base_reg
                            == CDISASM_X86_REG_RAX);
                        EXPECT(instruction.opcode[2].imm == UINT64_C(0x20));
                        EXPECT(instruction.encoding.displacement_size == 1u);
                    }
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX));
                    EXPECT(cdisasm_instruction_has_x86_group(
                            &instruction, CDISASM_X86_GROUP_AVX2)
                        == (length != 0));
                    EXPECT(!cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX512F));
                    EXPECT(!cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX10_1));
                    EXPECT(instruction.encoding.prefix_size
                        == (variant == 0 ? 2u : 3u));
                    EXPECT(instruction.encoding.opcode_offset
                        == instruction.encoding.prefix_size);
                    EXPECT(instruction.encoding.opcode_size == 1u);
                    EXPECT(instruction.encoding.immediate_count == 0u);

#if USE_DISASM_FORMAT
                    {
                        const char *reg = length == 0 ? "xmm" : "ymm";
                        const char *pointer = length == 0
                            ? "xmmword" : "ymmword";
                        char intel[160];
                        char att[160];

                        if (memory == 0) {
                            snprintf(intel, sizeof(intel),
                                "%s %s1, %s2, %s3",
                                test->mnemonic, reg, reg, reg);
                            snprintf(att, sizeof(att),
                                "%s %%%s3, %%%s2, %%%s1",
                                test->mnemonic, reg, reg, reg);
                        } else {
                            snprintf(intel, sizeof(intel),
                                "%s %s1, %s2, %s ptr [rax + 0x20]",
                                test->mnemonic, reg, reg, pointer);
                            snprintf(att, sizeof(att),
                                "%s 0x20(%%rax), %%%s2, %%%s1",
                                test->mnemonic, reg, reg);
                        }
                        expect_format(&instruction,
                            CDISASM_FORMAT_SYNTAX_X86_INTEL, intel);
                        expect_format(&instruction,
                            CDISASM_FORMAT_SYNTAX_X86_ATT, att);
                    }
#endif
#else
                    expect_error("extra-opcodes OFF VEX form",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, code_size, CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
            }
        }
    }
}

/* Eight names, three lengths, register/full-memory, and both W values:
 * 96 legal EVEX encodings spanning all 48 operand shapes. */
static void test_evex_matrix(void)
{
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const saturating_case *test = &cases[index];
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            unsigned int w;

            for (w = 0; w != 2; ++w) {
                unsigned int memory;

                for (memory = 0; memory != 2; ++memory) {
                    uint8_t code[7];
                    size_t code_size = make_evex_encoding(
                        test, length, w, memory != 0, code);
#if USE_EXTRA_OPCODES
                    const unsigned int vector_bits = 128u << length;
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                        code, code_size, CDISASM_X86_DECODE_FLAG_AVX512,
                        &decoded_size);

                    EXPECT(decoded_size == code_size);
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id == test->name_id);
                    EXPECT((instruction.opcode_flags
                        & CDISASM_PREFIX_EVEX) != 0);
                    EXPECT(instruction.operand_count == 3u);
                    EXPECT(instruction.opcode[0].reg
                        == vector_register(1u, vector_bits));
                    EXPECT(instruction.opcode[1].reg
                        == vector_register(2u, vector_bits));
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
                    EXPECT(instruction.rounding
                        == CDISASM_X86_ROUNDING_NONE);
                    EXPECT(instruction.sae == CDISASM_X86_SAE_NONE);
                    EXPECT(instruction.opcode[2].broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                    if (memory == 0) {
                        EXPECT(instruction.opcode[2].type
                            == CDISASM_OPERAND_REGISTER);
                        EXPECT(instruction.opcode[2].reg
                            == vector_register(3u, vector_bits));
                    } else {
                        EXPECT(instruction.opcode[2].type
                            == CDISASM_OPERAND_MEMORY);
                        EXPECT(instruction.opcode[2].base_reg
                            == CDISASM_X86_REG_RAX);
                        EXPECT(instruction.opcode[2].imm
                            == UINT64_C(2) * (vector_bits / 8u));
                        EXPECT(instruction.encoding.displacement_size == 1u);
                    }
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX));
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX512F));
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX512BW));
                    EXPECT(cdisasm_instruction_has_x86_group(
                            &instruction, CDISASM_X86_GROUP_AVX512VL)
                        == (length != 2));
                    EXPECT(!cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX10_1));
                    EXPECT(instruction.encoding.prefix_size == 4u);
                    EXPECT(instruction.encoding.opcode_offset == 4u);
                    EXPECT(instruction.encoding.opcode_size == 1u);
                    EXPECT(instruction.encoding.immediate_count == 0u);

#if USE_DISASM_FORMAT
                    {
                        const char *reg = length == 0 ? "xmm"
                            : length == 1 ? "ymm" : "zmm";
                        const char *pointer = length == 0 ? "xmmword"
                            : length == 1 ? "ymmword" : "zmmword";
                        char intel[176];
                        char att[176];

                        if (memory == 0) {
                            snprintf(intel, sizeof(intel),
                                "%s %s1 {k2}, %s2, %s3",
                                test->mnemonic, reg, reg, reg);
                            snprintf(att, sizeof(att),
                                "%s %%%s3, %%%s2, %%%s1{%%k2}",
                                test->mnemonic, reg, reg, reg);
                        } else {
                            snprintf(intel, sizeof(intel),
                                "%s %s1 {k2}, %s2, %s ptr "
                                "[rax + 0x%x]",
                                test->mnemonic, reg, reg, pointer,
                                vector_bits / 4u);
                            snprintf(att, sizeof(att),
                                "%s 0x%x(%%rax), %%%s2, %%%s1{%%k2}",
                                test->mnemonic, vector_bits / 4u,
                                reg, reg);
                        }
                        expect_format(&instruction,
                            CDISASM_FORMAT_SYNTAX_X86_INTEL, intel);
                        expect_format(&instruction,
                            CDISASM_FORMAT_SYNTAX_X86_ATT, att);
                    }
#endif
#else
                    expect_error("extra-opcodes OFF EVEX form",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, code_size, CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
            }
        }
    }
}

static void test_feature_gates(void)
{
    uint8_t vex_xmm[6];
    uint8_t vex_ymm[6];
    uint8_t evex[7];
    size_t vex_xmm_size = make_vex_encoding(
        &cases[0], 0u, 0u, 0, vex_xmm);
    size_t vex_ymm_size = make_vex_encoding(
        &cases[0], 1u, 0u, 0, vex_ymm);
    size_t evex_size = make_evex_encoding(
        &cases[0], 2u, 0u, 0, evex);

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    expect_error("VEX.128 runtime AVX gate",
        CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
        vex_xmm, vex_xmm_size, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VEX.128 CPU AVX gate",
        CDISASM_CPU_NEHALEM, CDISASM_MODE_64,
        vex_xmm, vex_xmm_size, CDISASM_X86_DECODE_FLAG_AVX,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VEX.256 runtime AVX2 gate",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        vex_ymm, vex_ymm_size, CDISASM_X86_DECODE_FLAG_AVX,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VEX.256 CPU AVX2 gate",
        CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
        vex_ymm, vex_ymm_size, CDISASM_X86_DECODE_FLAG_AVX2,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    expect_error("EVEX runtime AVX-512 gate",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        evex, evex_size, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("EVEX CPU AVX-512BW gate",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        evex, evex_size, CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy profile rejects AVX10 runtime route",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        evex, evex_size, CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 profile rejects legacy runtime route",
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        evex, evex_size, CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    {
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            evex_size = make_evex_encoding(
                &cases[0], length, length & 1u, 0, evex);
            instruction = decode(
                CDISASM_CPU_AVX10, CDISASM_MODE_64,
                evex, evex_size, CDISASM_X86_DECODE_FLAG_AVX10,
                &decoded_size);
            EXPECT(decoded_size == evex_size);
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VPADDSB);
            EXPECT(instruction.opcode[0].size
                == (size_t)(UINT32_C(16) << length));
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX10_1));
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512F));
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512BW));
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512VL));
        }
    }
#else
    expect_error("extra-opcodes OFF VEX.128 gate",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        vex_xmm, vex_xmm_size, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("extra-opcodes OFF VEX.256 gate",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        vex_ymm, vex_ymm_size, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("extra-opcodes OFF EVEX gate",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        evex, evex_size, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_masking_and_extended_registers(void)
{
    static const uint8_t zeroing[] = {
        0x62, 0xf1, 0x6d, 0xca, 0xec, 0xcb
    };
    static const uint8_t unmasked[] = {
        0x62, 0xf1, 0x6d, 0x48, 0xec, 0xcb
    };
    static const uint8_t extended[] = {
        0x62, 0xa1, 0x6d, 0x40, 0xec, 0xcb
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        zeroing, sizeof(zeroing), CDISASM_X86_DECODE_FLAG_AVX512,
        &decoded_size);

    EXPECT(decoded_size == sizeof(zeroing));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPADDSB);
    EXPECT(instruction.mask_reg == CDISASM_X86_REG_K2);
    EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
#if USE_DISASM_FORMAT
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpaddsb zmm1 {k2}{z}, zmm2, zmm3");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpaddsb %zmm3, %zmm2, %zmm1{%k2}{z}");
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
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPADDSB);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ZMM17);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ZMM18);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_ZMM19);
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

static void test_reserved_unsupported_and_truncated(void)
{
    static const struct error_case {
        const char *label;
        uint8_t bytes[7];
        uint8_t size;
        cdisasm_status status;
    } errors[] = {
        {"VEX reserved pp=none",
            {0xc5, 0xe8, 0xec, 0xcb}, 4,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"VEX reserved pp=F3",
            {0xc5, 0xea, 0xec, 0xcb}, 4,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"VEX reserved pp=F2",
            {0xc5, 0xeb, 0xec, 0xcb}, 4,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"legacy prefix before VEX",
            {0x66, 0xc5, 0xe9, 0xec, 0xcb}, 5,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"truncated VEX ModRM",
            {0xc5, 0xe9, 0xec}, 3,
            CDISASM_STATUS_TRUNCATED},
        {"truncated VEX displacement",
            {0xc5, 0xe9, 0xec, 0x48}, 4,
            CDISASM_STATUS_TRUNCATED},
        {"EVEX reserved LL=3",
            {0x62, 0xf1, 0x6d, 0x6a, 0xec, 0xcb}, 6,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"EVEX register source with b=1",
            {0x62, 0xf1, 0x6d, 0x5a, 0xec, 0xcb}, 6,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"EVEX memory broadcast",
            {0x62, 0xf1, 0x6d, 0x5a, 0xec, 0x08}, 6,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"EVEX zeroing without mask",
            {0x62, 0xf1, 0x6d, 0xc8, 0xec, 0xcb}, 6,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"EVEX reserved U bit",
            {0x62, 0xf1, 0x69, 0x4a, 0xec, 0xcb}, 6,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"legacy prefix before EVEX",
            {0x66, 0x62, 0xf1, 0x6d, 0x4a, 0xec, 0xcb}, 7,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {"EVEX unowned mandatory-prefix sibling",
            {0x62, 0xf1, 0x6c, 0x4a, 0xec, 0xcb}, 6,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {"truncated EVEX ModRM",
            {0x62, 0xf1, 0x6d, 0x4a, 0xec}, 5,
            CDISASM_STATUS_TRUNCATED},
        {"truncated EVEX displacement",
            {0x62, 0xf1, 0x6d, 0x4a, 0xec, 0x48}, 6,
            CDISASM_STATUS_TRUNCATED}
    };
    size_t index;

    for (index = 0; index < sizeof(errors) / sizeof(errors[0]); ++index) {
        expect_error(errors[index].label,
            CDISASM_CPU_X86, CDISASM_MODE_64,
            errors[index].bytes, errors[index].size,
            CDISASM_X86_DECODE_FLAG_BASE, errors[index].status);
    }
}

static void test_legacy_modes(void)
{
    static const uint8_t vex_low[] = {0xc5, 0xe9, 0xec, 0xcb};
    static const uint8_t evex_low[] = {
        0x62, 0xf1, 0x6d, 0x0a, 0xec, 0xcb
    };
    static const uint8_t evex_extended_source[] = {
        0x62, 0xf1, 0x6d, 0x02, 0xec, 0xcb
    };
    static const uint8_t evex_extended_destination[] = {
        0x62, 0xe1, 0x6d, 0x0a, 0xec, 0xcb
    };

#if USE_EXTRA_OPCODES
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32
    };
    size_t mode_index;

    for (mode_index = 0;
         mode_index < sizeof(modes) / sizeof(modes[0]);
         ++mode_index) {
        const cdisasm_mode mode = modes[mode_index];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, mode,
            vex_low, sizeof(vex_low), CDISASM_X86_DECODE_FLAG_AVX,
            &decoded_size);

        EXPECT(decoded_size == sizeof(vex_low));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPADDSB);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
        instruction = decode(
            CDISASM_CPU_X86, mode,
            evex_low, sizeof(evex_low), CDISASM_X86_DECODE_FLAG_AVX512,
            &decoded_size);
        EXPECT(decoded_size == sizeof(evex_low));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPADDSB);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
    }
#else
    expect_error("extra-opcodes OFF VEX 16-bit form",
        CDISASM_CPU_X86, CDISASM_MODE_16,
        vex_low, sizeof(vex_low), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("extra-opcodes OFF EVEX 32-bit form",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        evex_low, sizeof(evex_low), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    expect_error("EVEX V-prime extension outside long mode",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        evex_extended_source, sizeof(evex_extended_source),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("EVEX R-prime extension outside long mode",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        evex_extended_destination, sizeof(evex_extended_destination),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

int main(void)
{
    test_name_catalog();
    test_vex_matrix();
    test_evex_matrix();
    test_feature_gates();
    test_masking_and_extended_registers();
    test_reserved_unsupported_and_truncated();
    test_legacy_modes();

    if (failures != 0) {
        fprintf(stderr,
            "x86 VEX/EVEX saturating ADD/SUB tests failed: %d "
            "(extra=%d, format=%d)\n",
            failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("x86 VEX/EVEX saturating ADD/SUB tests passed "
           "(extra=%d, format=%d)\n",
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
