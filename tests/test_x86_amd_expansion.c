#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_NAME_VFMADDSUBPS == UINT16_C(804),
               "FMA4 expansion start changed");
_Static_assert(CDISASM_X86_NAME_VFNMSUBSD == UINT16_C(819),
               "FMA4 expansion end changed");
_Static_assert(CDISASM_X86_NAME_VPSHLB == UINT16_C(820),
               "XOP shift expansion start changed");
_Static_assert(CDISASM_X86_NAME_VPSHAQ == UINT16_C(827),
               "XOP shift expansion end changed");
_Static_assert(CDISASM_X86_NAME_COUNT >= UINT16_C(828),
               "AMD expansion mnemonic range disappeared");

static int failures;

#define EXPECT(expression)                                                     \
    do {                                                                       \
        if (!(expression)) {                                                   \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",              \
                    __FILE__, __LINE__, #expression);                          \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

static cdisasm_instruction decode_mode(
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

static void expect_error_mode(
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        cpu, mode, bytes, size, flags, &decoded_size);

    if (decoded_size != 0 || !is_error_only(&instruction, status)) {
        fprintf(stderr,
                "unexpected status: cpu=0x%08x mode=%u size=%u "
                "bytes=%02x%02x%02x%02x expected=%u actual=%u decoded=%u\n",
                (unsigned int)cpu,
                (unsigned int)mode,
                (unsigned int)size,
                size > 0 ? (unsigned int)bytes[0] : 0u,
                size > 1 ? (unsigned int)bytes[1] : 0u,
                size > 2 ? (unsigned int)bytes[2] : 0u,
                size > 3 ? (unsigned int)bytes[3] : 0u,
                (unsigned int)status,
                (unsigned int)instruction.last_error_id,
                (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, status));
}

static void expect_error(
    const uint8_t *bytes,
    size_t size,
    cdisasm_status status)
{
    expect_error_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64, bytes, size,
        CDISASM_X86_DECODE_FLAG_BASE, status);
}

#if USE_EXTRA_OPCODES
static cdisasm_instruction decode64(
    cdisasm_cpu_id cpu,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    return decode_mode(
        cpu, CDISASM_MODE_64, bytes, size, flags, decoded_size);
}
#endif

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(
    const cdisasm_instruction *instruction,
    uint32_t syntax,
    const char *expected)
{
    char text[192];
    size_t length = cdisasm_x86_format(
        instruction, syntax, text, sizeof(text));

    EXPECT(length == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
}
#endif

typedef enum fma4_shape {
    FMA4_PACKED = 0,
    FMA4_SCALAR32 = 1,
    FMA4_SCALAR64 = 2
} fma4_shape;

typedef struct fma4_case {
    uint8_t opcode;
    uint8_t shape;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} fma4_case;

static const fma4_case fma4_cases[] = {
    {0x5c, FMA4_PACKED, CDISASM_X86_NAME_VFMADDSUBPS, "vfmaddsubps"},
    {0x5d, FMA4_PACKED, CDISASM_X86_NAME_VFMADDSUBPD, "vfmaddsubpd"},
    {0x5e, FMA4_PACKED, CDISASM_X86_NAME_VFMSUBADDPS, "vfmsubaddps"},
    {0x5f, FMA4_PACKED, CDISASM_X86_NAME_VFMSUBADDPD, "vfmsubaddpd"},
    {0x68, FMA4_PACKED, CDISASM_X86_NAME_VFMADDPS, "vfmaddps"},
    {0x69, FMA4_PACKED, CDISASM_X86_NAME_VFMADDPD, "vfmaddpd"},
    {0x6a, FMA4_SCALAR32, CDISASM_X86_NAME_VFMADDSS, "vfmaddss"},
    {0x6b, FMA4_SCALAR64, CDISASM_X86_NAME_VFMADDSD, "vfmaddsd"},
    {0x6c, FMA4_PACKED, CDISASM_X86_NAME_VFMSUBPS, "vfmsubps"},
    {0x6d, FMA4_PACKED, CDISASM_X86_NAME_VFMSUBPD, "vfmsubpd"},
    {0x6e, FMA4_SCALAR32, CDISASM_X86_NAME_VFMSUBSS, "vfmsubss"},
    {0x6f, FMA4_SCALAR64, CDISASM_X86_NAME_VFMSUBSD, "vfmsubsd"},
    {0x78, FMA4_PACKED, CDISASM_X86_NAME_VFNMADDPS, "vfnmaddps"},
    {0x79, FMA4_PACKED, CDISASM_X86_NAME_VFNMADDPD, "vfnmaddpd"},
    {0x7a, FMA4_SCALAR32, CDISASM_X86_NAME_VFNMADDSS, "vfnmaddss"},
    {0x7b, FMA4_SCALAR64, CDISASM_X86_NAME_VFNMADDSD, "vfnmaddsd"},
    {0x7c, FMA4_PACKED, CDISASM_X86_NAME_VFNMSUBPS, "vfnmsubps"},
    {0x7d, FMA4_PACKED, CDISASM_X86_NAME_VFNMSUBPD, "vfnmsubpd"},
    {0x7e, FMA4_SCALAR32, CDISASM_X86_NAME_VFNMSUBSS, "vfnmsubss"},
    {0x7f, FMA4_SCALAR64, CDISASM_X86_NAME_VFNMSUBSD, "vfnmsubsd"}
};

static void test_fma4_matrix(void)
{
    size_t case_index;

    EXPECT(sizeof(fma4_cases) / sizeof(fma4_cases[0]) == 20u);
    for (case_index = 0;
         case_index < sizeof(fma4_cases) / sizeof(fma4_cases[0]);
         ++case_index) {
        unsigned int w;

        for (w = 0; w != 2; ++w) {
            unsigned int l;
            uint8_t truncated_modrm[4] = {
                0xc4, 0xe3, (uint8_t)(0x69u | (w << 7)),
                fma4_cases[case_index].opcode
            };

            expect_error(
                truncated_modrm, sizeof(truncated_modrm),
                CDISASM_STATUS_TRUNCATED);

            for (l = 0; l != 2; ++l) {
                uint8_t code[6] = {
                    0xc4,
                    0xe3,
                    (uint8_t)(0x69u | (w << 7) | (l << 2)),
                    fma4_cases[case_index].opcode,
                    (uint8_t)(w != 0 ? 0xcc : 0xcb),
                    (uint8_t)(w != 0 ? 0x3f : 0x4f)
                };
                uint8_t truncated_imm[5];

                memcpy(truncated_imm, code, sizeof(truncated_imm));
                expect_error(
                    truncated_imm, sizeof(truncated_imm),
                    CDISASM_STATUS_TRUNCATED);

#if USE_EXTRA_OPCODES
                {
                    const int ymm = l != 0
                        && fma4_cases[case_index].shape == FMA4_PACKED;
                    const cdisasm_x86_reg_id register_base = ymm
                        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
                    const unsigned int register_size = ymm ? 32u : 16u;
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode64(
                        CDISASM_CPU_AMD_BULLDOZER,
                        code,
                        sizeof(code),
                        CDISASM_X86_DECODE_FLAG_FMA4,
                        &decoded_size);
                    unsigned int operand_index;

                    EXPECT(decoded_size == sizeof(code));
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id
                           == fma4_cases[case_index].name_id);
                    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX)
                           != 0);
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX));
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_FMA4));
                    EXPECT(instruction.operand_count == 4);
                    for (operand_index = 0; operand_index != 4;
                         ++operand_index) {
                        EXPECT(instruction.opcode[operand_index].type
                               == CDISASM_OPERAND_REGISTER);
                        EXPECT(instruction.opcode[operand_index].reg
                               == register_base + operand_index + 1u);
                        EXPECT(instruction.opcode[operand_index].size
                               == register_size);
                        EXPECT(instruction.opcode[operand_index].access
                               == (operand_index == 0
                                   ? CDISASM_OPERAND_ACCESS_WRITE
                                   : CDISASM_OPERAND_ACCESS_READ));
                    }
                    EXPECT(instruction.encoding.prefix_size == 3);
                    EXPECT(instruction.encoding.opcode_offset == 3);
                    EXPECT(instruction.encoding.opcode_size == 1);
                    EXPECT(instruction.encoding.modrm_offset == 4);
                    EXPECT(instruction.encoding.modrm == code[4]);
                    EXPECT(instruction.encoding.immediate_count == 1);
                    EXPECT(instruction.encoding.immediate_offset[0] == 5);
                    EXPECT(instruction.encoding.immediate_size[0] == 1);

#if USE_DISASM_FORMAT
                    {
                        char intel[128];
                        char att[128];
                        const char *reg = ymm ? "ymm" : "xmm";

                        (void)snprintf(
                            intel, sizeof(intel), "%s %s1, %s2, %s3, %s4",
                            fma4_cases[case_index].mnemonic,
                            reg, reg, reg, reg);
                        (void)snprintf(
                            att, sizeof(att), "%s %%%s4, %%%s3, %%%s2, %%%s1",
                            fma4_cases[case_index].mnemonic,
                            reg, reg, reg, reg);
                        expect_format(
                            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
                            intel);
                        expect_format(
                            &instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
                            att);
                    }
#endif
                }
#else
                expect_error(
                    code, sizeof(code),
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            }
        }
    }
}

typedef struct fma4_memory_case {
    uint8_t vex;
    uint8_t opcode;
    uint8_t immediate;
    uint8_t memory_index;
    uint8_t memory_size;
    uint8_t vector_size;
} fma4_memory_case;

static const fma4_memory_case fma4_memory_cases[] = {
    {0x69, 0x6c, 0x4f, 2, 16, 16},
    {0xed, 0x6c, 0x3f, 3, 32, 32},
    {0x69, 0x6e, 0x4f, 2, 4, 16},
    {0xe9, 0x6f, 0x3f, 3, 8, 16}
};

static void test_fma4_memory_policy_and_malformed(void)
{
    static const uint8_t sample[] = {
        0xc4, 0xe3, 0xe9, 0x6c, 0xcc, 0x30
    };
    static const uint8_t wrong_pp[] = {
        0xc4, 0xe3, 0xe8, 0x6c, 0xcc, 0x30
    };
    static const uint8_t mode32_xmm8[] = {
        0xc4, 0xe3, 0x69, 0x6c, 0xcb, 0x80
    };
    size_t index;

    expect_error(wrong_pp, sizeof(wrong_pp),
                 CDISASM_STATUS_INVALID_INSTRUCTION);
#if USE_EXTRA_OPCODES
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_AMD_BULLDOZER,
            CDISASM_MODE_32,
            mode32_xmm8,
            sizeof(mode32_xmm8),
            CDISASM_X86_DECODE_FLAG_FMA4,
            &decoded_size);

        EXPECT(decoded_size == sizeof(mode32_xmm8));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VFMSUBPS);
        EXPECT(instruction.operand_count == 4);
        EXPECT(instruction.opcode[3].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[3].reg == CDISASM_X86_REG_XMM0);
    }
#else
    expect_error_mode(
        CDISASM_CPU_X86,
        CDISASM_MODE_32,
        mode32_xmm8,
        sizeof(mode32_xmm8),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    for (index = 0;
         index < sizeof(fma4_memory_cases) / sizeof(fma4_memory_cases[0]);
         ++index) {
        const fma4_memory_case *test = &fma4_memory_cases[index];
        uint8_t code[6] = {
            0xc4, 0xe3, test->vex, test->opcode, 0x08, test->immediate
        };

#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode64(
            CDISASM_CPU_AMD_BULLDOZER,
            code,
            sizeof(code),
            CDISASM_X86_DECODE_FLAG_FMA4,
            &decoded_size);
        const cdisasm_opcode *memory =
            &instruction.opcode[test->memory_index];

        EXPECT(decoded_size == sizeof(code));
        EXPECT(instruction.operand_count == 4);
        EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
        EXPECT(memory->base_reg == CDISASM_X86_REG_RAX);
        EXPECT(memory->size == test->memory_size);
        EXPECT(memory->access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.opcode[0].size == test->vector_size);
        EXPECT(instruction.opcode[0].reg
               == (test->vector_size == 32
                   ? CDISASM_X86_REG_YMM1 : CDISASM_X86_REG_XMM1));
        EXPECT(instruction.opcode[test->memory_index == 2 ? 3 : 2].type
               == CDISASM_OPERAND_REGISTER);
#else
        expect_error(
            code, sizeof(code), CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

#if USE_EXTRA_OPCODES
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        expect_error_mode(
            CDISASM_CPU_HASWELL,
            CDISASM_MODE_64,
            sample,
            sizeof(sample),
            CDISASM_X86_DECODE_FLAG_FMA4,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error_mode(
            CDISASM_CPU_AMD_ZEN,
            CDISASM_MODE_64,
            sample,
            sizeof(sample),
            CDISASM_X86_DECODE_FLAG_FMA4,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error_mode(
            CDISASM_CPU_AMD_BULLDOZER,
            CDISASM_MODE_64,
            sample,
            sizeof(sample),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error_mode(
            CDISASM_CPU_AMD_BULLDOZER,
            CDISASM_MODE_64,
            sample,
            sizeof(sample),
            CDISASM_X86_DECODE_FLAG_XOP,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_AMD_BULLDOZER, CDISASM_MODE_64)
                & (CDISASM_X86_DECODE_FLAG_AVX
                   | CDISASM_X86_DECODE_FLAG_FMA4))
               == (CDISASM_X86_DECODE_FLAG_AVX
                   | CDISASM_X86_DECODE_FLAG_FMA4));
        EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_AMD_ZEN, CDISASM_MODE_64)
                & CDISASM_X86_DECODE_FLAG_FMA4) == 0);

        instruction = decode64(
            CDISASM_CPU_X86,
            sample,
            sizeof(sample),
            CDISASM_X86_DECODE_FLAG_FMA4,
            &decoded_size);
        EXPECT(decoded_size == sizeof(sample));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VFMSUBPS);

#if USE_DISASM_FORMAT
        expect_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            "vfmsubps xmm1, xmm2, xmm3, xmm4");
        expect_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            "vfmsubps %xmm4, %xmm3, %xmm2, %xmm1");
#endif
    }
#else
    expect_error(
        sample, sizeof(sample), CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

typedef struct xop_shift_case {
    uint8_t opcode;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} xop_shift_case;

static const xop_shift_case xop_shift_cases[] = {
    {0x94, CDISASM_X86_NAME_VPSHLB, "vpshlb"},
    {0x95, CDISASM_X86_NAME_VPSHLW, "vpshlw"},
    {0x96, CDISASM_X86_NAME_VPSHLD, "vpshld"},
    {0x97, CDISASM_X86_NAME_VPSHLQ, "vpshlq"},
    {0x98, CDISASM_X86_NAME_VPSHAB, "vpshab"},
    {0x99, CDISASM_X86_NAME_VPSHAW, "vpshaw"},
    {0x9a, CDISASM_X86_NAME_VPSHAD, "vpshad"},
    {0x9b, CDISASM_X86_NAME_VPSHAQ, "vpshaq"}
};

static void test_xop_shift_matrix(void)
{
    size_t case_index;

    EXPECT(sizeof(xop_shift_cases) / sizeof(xop_shift_cases[0]) == 8u);
    for (case_index = 0;
         case_index < sizeof(xop_shift_cases) / sizeof(xop_shift_cases[0]);
         ++case_index) {
        unsigned int w;
        uint8_t vvvv_xmm0[5] = {
            0x8f, 0xe9, 0x78, xop_shift_cases[case_index].opcode, 0xca
        };
        uint8_t bad_l[5] = {
            0x8f, 0xe9, 0x64, xop_shift_cases[case_index].opcode, 0xca
        };
        uint8_t bad_pp[5] = {
            0x8f, 0xe9, 0x61, xop_shift_cases[case_index].opcode, 0xca
        };

        expect_error(bad_l, sizeof(bad_l),
                     CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error(bad_pp, sizeof(bad_pp),
                     CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode64(
                CDISASM_CPU_AMD_BULLDOZER,
                vvvv_xmm0,
                sizeof(vvvv_xmm0),
                CDISASM_X86_DECODE_FLAG_XOP,
                &decoded_size);

            EXPECT(decoded_size == sizeof(vvvv_xmm0));
            EXPECT(instruction.name_id
                   == xop_shift_cases[case_index].name_id);
            EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM0);
        }
#else
        expect_error(
            vvvv_xmm0, sizeof(vvvv_xmm0),
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

        for (w = 0; w != 2; ++w) {
            uint8_t code[5] = {
                0x8f,
                0xe9,
                (uint8_t)(w != 0 ? 0xe8 : 0x60),
                xop_shift_cases[case_index].opcode,
                (uint8_t)(w != 0 ? 0xcb : 0xca)
            };
            uint8_t truncated[4];
            uint8_t memory[5] = {
                0x8f,
                0xe9,
                (uint8_t)(w != 0 ? 0xe8 : 0x60),
                xop_shift_cases[case_index].opcode,
                0x08
            };

            memcpy(truncated, code, sizeof(truncated));
            expect_error(
                truncated, sizeof(truncated), CDISASM_STATUS_TRUNCATED);

#if USE_EXTRA_OPCODES
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode64(
                    CDISASM_CPU_AMD_BULLDOZER,
                    code,
                    sizeof(code),
                    CDISASM_X86_DECODE_FLAG_XOP,
                    &decoded_size);
                unsigned int operand_index;

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id
                       == xop_shift_cases[case_index].name_id);
                EXPECT((instruction.opcode_flags & CDISASM_PREFIX_XOP) != 0);
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_XOP));
                EXPECT(instruction.operand_count == 3);
                for (operand_index = 0; operand_index != 3;
                     ++operand_index) {
                    EXPECT(instruction.opcode[operand_index].type
                           == CDISASM_OPERAND_REGISTER);
                    EXPECT(instruction.opcode[operand_index].reg
                           == CDISASM_X86_REG_XMM0 + operand_index + 1u);
                    EXPECT(instruction.opcode[operand_index].size == 16);
                    EXPECT(instruction.opcode[operand_index].access
                           == (operand_index == 0
                               ? CDISASM_OPERAND_ACCESS_WRITE
                               : CDISASM_OPERAND_ACCESS_READ));
                }
                EXPECT(instruction.encoding.prefix_size == 3);
                EXPECT(instruction.encoding.opcode_offset == 3);
                EXPECT(instruction.encoding.opcode_size == 1);
                EXPECT(instruction.encoding.modrm_offset == 4);
                EXPECT(instruction.encoding.modrm == code[4]);
                EXPECT(instruction.encoding.immediate_count == 0);

#if USE_DISASM_FORMAT
                {
                    char intel[96];
                    char att[96];

                    (void)snprintf(
                        intel, sizeof(intel), "%s xmm1, xmm2, xmm3",
                        xop_shift_cases[case_index].mnemonic);
                    (void)snprintf(
                        att, sizeof(att), "%s %%xmm3, %%xmm2, %%xmm1",
                        xop_shift_cases[case_index].mnemonic);
                    expect_format(
                        &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
                        intel);
                    expect_format(
                        &instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
                        att);
                }
#endif

                instruction = decode64(
                    CDISASM_CPU_AMD_BULLDOZER,
                    memory,
                    sizeof(memory),
                    CDISASM_X86_DECODE_FLAG_XOP,
                    &decoded_size);
                EXPECT(decoded_size == sizeof(memory));
                EXPECT(instruction.operand_count == 3);
                EXPECT(instruction.opcode[w == 0 ? 1 : 2].type
                       == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[w == 0 ? 1 : 2].base_reg
                       == CDISASM_X86_REG_RAX);
                EXPECT(instruction.opcode[w == 0 ? 1 : 2].size == 16);
                EXPECT(instruction.opcode[w == 0 ? 2 : 1].type
                       == CDISASM_OPERAND_REGISTER);
                EXPECT(instruction.opcode[w == 0 ? 2 : 1].reg
                       == (w == 0
                           ? CDISASM_X86_REG_XMM3
                           : CDISASM_X86_REG_XMM2));
            }
#else
            expect_error(
                code, sizeof(code), CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error(
                memory, sizeof(memory),
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

static void test_xop_policy_and_vpcmov(void)
{
    static const uint8_t shift[] = {0x8f, 0xe9, 0x60, 0x94, 0xca};
    unsigned int w;
    unsigned int l;

#if USE_EXTRA_OPCODES
    expect_error_mode(
        CDISASM_CPU_HASWELL,
        CDISASM_MODE_64,
        shift,
        sizeof(shift),
        CDISASM_X86_DECODE_FLAG_XOP,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_AMD_ZEN,
        CDISASM_MODE_64,
        shift,
        sizeof(shift),
        CDISASM_X86_DECODE_FLAG_XOP,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_AMD_BULLDOZER,
        CDISASM_MODE_64,
        shift,
        sizeof(shift),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_AMD_BULLDOZER,
        CDISASM_MODE_64,
        shift,
        sizeof(shift),
        CDISASM_X86_DECODE_FLAG_FMA4,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_AMD_BULLDOZER, CDISASM_MODE_64)
            & (CDISASM_X86_DECODE_FLAG_AVX
               | CDISASM_X86_DECODE_FLAG_XOP))
           == (CDISASM_X86_DECODE_FLAG_AVX
               | CDISASM_X86_DECODE_FLAG_XOP));
    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_AMD_ZEN, CDISASM_MODE_64)
            & CDISASM_X86_DECODE_FLAG_XOP) == 0);
#else
    expect_error(
        shift, sizeof(shift), CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    for (w = 0; w != 2; ++w) {
        for (l = 0; l != 2; ++l) {
            uint8_t code[6] = {
                0x8f,
                0xe8,
                (uint8_t)(0x68u | (w << 7) | (l << 2)),
                0xa2,
                (uint8_t)(w != 0 ? 0xcc : 0xcb),
                (uint8_t)(w != 0 ? 0x3f : 0x4f)
            };
            uint8_t truncated[5];

            memcpy(truncated, code, sizeof(truncated));
            expect_error(
                truncated, sizeof(truncated), CDISASM_STATUS_TRUNCATED);

#if USE_EXTRA_OPCODES
            {
                const cdisasm_x86_reg_id register_base = l != 0
                    ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
                const unsigned int register_size = l != 0 ? 32u : 16u;
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode64(
                    CDISASM_CPU_AMD_BULLDOZER,
                    code,
                    sizeof(code),
                    CDISASM_X86_DECODE_FLAG_XOP,
                    &decoded_size);
                unsigned int operand_index;

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.name_id == CDISASM_X86_NAME_VPCMOV);
                EXPECT(instruction.operand_count == 4);
                for (operand_index = 0; operand_index != 4;
                     ++operand_index) {
                    EXPECT(instruction.opcode[operand_index].type
                           == CDISASM_OPERAND_REGISTER);
                    EXPECT(instruction.opcode[operand_index].reg
                           == register_base + operand_index + 1u);
                    EXPECT(instruction.opcode[operand_index].size
                           == register_size);
                    EXPECT(instruction.opcode[operand_index].access
                           == (operand_index == 0
                               ? CDISASM_OPERAND_ACCESS_WRITE
                               : CDISASM_OPERAND_ACCESS_READ));
                }
                EXPECT(instruction.encoding.immediate_count == 0);
                EXPECT(instruction.encoding.selector_offset == 5);

#if USE_DISASM_FORMAT
                if (l != 0) {
                    expect_format(
                        &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
                        "vpcmov ymm1, ymm2, ymm3, ymm4");
                    expect_format(
                        &instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
                        "vpcmov %ymm4, %ymm3, %ymm2, %ymm1");
                } else {
                    expect_format(
                        &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
                        "vpcmov xmm1, xmm2, xmm3, xmm4");
                    expect_format(
                        &instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
                        "vpcmov %xmm4, %xmm3, %xmm2, %xmm1");
                }
#endif
            }
#else
            expect_error(
                code, sizeof(code), CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

int main(void)
{
    test_fma4_matrix();
    test_fma4_memory_policy_and_malformed();
    test_xop_shift_matrix();
    test_xop_policy_and_vpcmov();

    if (failures != 0) {
        fprintf(stderr,
                "x86 AMD expansion tests failed: %d (extra=%d, format=%d)\n",
                failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("x86 AMD expansion tests passed (extra=%d, format=%d)\n",
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
