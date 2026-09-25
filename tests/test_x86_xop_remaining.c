#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_MAX_OPERANDS >= 5,
               "VPERMIL2 requires five public operand slots");
_Static_assert(CDISASM_X86_NAME_VPMACSSWW == UINT16_C(862),
               "remaining XOP catalog start changed");
_Static_assert(CDISASM_X86_NAME_VPERMIL2PD == UINT16_C(884),
               "remaining XOP catalog end changed");
_Static_assert(CDISASM_X86_NAME_COUNT >= UINT16_C(885),
               "remaining XOP catalog is incomplete");
_Static_assert(CDISASM_NAME_VPMACSSWW == CDISASM_X86_NAME_VPMACSSWW,
               "legacy VPMACSSWW alias changed");
_Static_assert(CDISASM_NAME_VPERMIL2PD == CDISASM_X86_NAME_VPERMIL2PD,
               "legacy VPERMIL2PD alias changed");

static int failures;

#if USE_EXTRA_OPCODES
#define XOP_STRUCTURAL_FLAGS CDISASM_X86_DECODE_FLAG_XOP
#else
#define XOP_STRUCTURAL_FLAGS CDISASM_X86_DECODE_FLAG_BASE
#endif

#define EXPECT(expression)                                                     \
    do {                                                                       \
        if (!(expression)) {                                                   \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",              \
                    __FILE__, __LINE__, #expression);                          \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

typedef enum map8_shape {
    MAP8_MAC = 0,
    MAP8_COMPARE = 1,
    MAP8_PERMUTE = 2
} map8_shape;

typedef struct map8_case {
    uint8_t opcode;
    uint8_t shape;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} map8_case;

static const map8_case map8_cases[] = {
    {0x85, MAP8_MAC, CDISASM_X86_NAME_VPMACSSWW, "vpmacssww"},
    {0x86, MAP8_MAC, CDISASM_X86_NAME_VPMACSSWD, "vpmacsswd"},
    {0x87, MAP8_MAC, CDISASM_X86_NAME_VPMACSSDQL, "vpmacssdql"},
    {0x8e, MAP8_MAC, CDISASM_X86_NAME_VPMACSSDD, "vpmacssdd"},
    {0x8f, MAP8_MAC, CDISASM_X86_NAME_VPMACSSDQH, "vpmacssdqh"},
    {0x95, MAP8_MAC, CDISASM_X86_NAME_VPMACSWW, "vpmacsww"},
    {0x96, MAP8_MAC, CDISASM_X86_NAME_VPMACSWD, "vpmacswd"},
    {0x97, MAP8_MAC, CDISASM_X86_NAME_VPMACSDQL, "vpmacsdql"},
    {0x9e, MAP8_MAC, CDISASM_X86_NAME_VPMACSDD, "vpmacsdd"},
    {0x9f, MAP8_MAC, CDISASM_X86_NAME_VPMACSDQH, "vpmacsdqh"},
    {0xa6, MAP8_MAC, CDISASM_X86_NAME_VPMADCSSWD, "vpmadcsswd"},
    {0xb6, MAP8_MAC, CDISASM_X86_NAME_VPMADCSWD, "vpmadcswd"},
    {0xcc, MAP8_COMPARE, CDISASM_X86_NAME_VPCOMB, "vpcomb"},
    {0xcd, MAP8_COMPARE, CDISASM_X86_NAME_VPCOMW, "vpcomw"},
    {0xce, MAP8_COMPARE, CDISASM_X86_NAME_VPCOMD, "vpcomd"},
    {0xcf, MAP8_COMPARE, CDISASM_X86_NAME_VPCOMQ, "vpcomq"},
    {0xec, MAP8_COMPARE, CDISASM_X86_NAME_VPCOMUB, "vpcomub"},
    {0xed, MAP8_COMPARE, CDISASM_X86_NAME_VPCOMUW, "vpcomuw"},
    {0xee, MAP8_COMPARE, CDISASM_X86_NAME_VPCOMUD, "vpcomud"},
    {0xef, MAP8_COMPARE, CDISASM_X86_NAME_VPCOMUQ, "vpcomuq"},
    {0xa3, MAP8_PERMUTE, CDISASM_X86_NAME_VPPERM, "vpperm"}
};

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
                "expected=%u actual=%u decoded=%u\n",
                (unsigned int)cpu, (unsigned int)mode,
                (unsigned int)size, (unsigned int)status,
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
        XOP_STRUCTURAL_FLAGS, status);
}

#if USE_EXTRA_OPCODES
static cdisasm_instruction decode_bulldozer(
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    uint32_t *decoded_size)
{
    return decode_mode(
        CDISASM_CPU_AMD_BULLDOZER, mode, bytes, size,
        CDISASM_X86_DECODE_FLAG_XOP, decoded_size);
}

static void expect_register(
    const cdisasm_opcode *operand,
    cdisasm_x86_reg_id reg,
    unsigned int size,
    cdisasm_operand_access access)
{
    EXPECT(operand->type == CDISASM_OPERAND_REGISTER);
    EXPECT(operand->reg == reg);
    EXPECT(operand->size == size);
    EXPECT(operand->access == access);
}

static void expect_memory(
    const cdisasm_opcode *operand,
    cdisasm_x86_reg_id base,
    unsigned int size)
{
    EXPECT(operand->type == CDISASM_OPERAND_MEMORY);
    EXPECT(operand->base_reg == base);
    EXPECT(operand->size == size);
    EXPECT(operand->access == CDISASM_OPERAND_ACCESS_READ);
}

static void expect_common_metadata(
    const cdisasm_instruction *instruction,
    cdisasm_x86_name_id name_id,
    uint32_t prefix)
{
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == name_id);
    EXPECT((instruction->opcode_flags & prefix) != 0);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_XOP));
    EXPECT(instruction->encoding.prefix_size == 3);
    EXPECT(instruction->encoding.opcode_offset == 3);
    EXPECT(instruction->encoding.opcode_size == 1);
    EXPECT(instruction->encoding.modrm_offset == 4);
    if (name_id == CDISASM_X86_NAME_VPPERM) {
        EXPECT(instruction->encoding.immediate_count == 0);
        EXPECT(instruction->encoding.selector_offset == 5);
    } else {
        EXPECT(instruction->encoding.immediate_count == 1);
        EXPECT(instruction->encoding.immediate_offset[0] == 5);
        EXPECT(instruction->encoding.immediate_size[0] == 1);
    }
}

#if USE_DISASM_FORMAT
static void expect_format(
    const cdisasm_instruction *instruction,
    const char *intel,
    const char *att)
{
    char text[192];
    size_t length = cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        text, sizeof(text));

    EXPECT(length == strlen(intel));
    EXPECT(strcmp(text, intel) == 0);
    length = cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        text, sizeof(text));
    EXPECT(length == strlen(att));
    EXPECT(strcmp(text, att) == 0);
}
#endif
#endif

static void test_map8_catalog_and_operands(void)
{
    size_t case_index;

    EXPECT(sizeof(map8_cases) / sizeof(map8_cases[0]) == 21u);
    for (case_index = 0;
         case_index < sizeof(map8_cases) / sizeof(map8_cases[0]);
         ++case_index) {
        const map8_case *test = &map8_cases[case_index];
        unsigned int w;

        for (w = 0; w != 2; ++w) {
            uint8_t code[] = {
                0x8f, 0xe8, (uint8_t)(0x68u | (w << 7)),
                test->opcode, 0xcb,
                test->shape == MAP8_COMPARE ? 0xe5 : 0x4f
            };
            uint8_t memory[] = {
                0x8f, 0xe8, (uint8_t)(0x68u | (w << 7)),
                test->opcode, 0x08,
                test->shape == MAP8_COMPARE ? 0xe5 : 0x4f
            };
            const int w_is_valid = w == 0 || test->shape == MAP8_PERMUTE;

            if (!w_is_valid) {
                expect_error(
                    code, sizeof(code), CDISASM_STATUS_INVALID_INSTRUCTION);
                expect_error(
                    memory, sizeof(memory),
                    CDISASM_STATUS_INVALID_INSTRUCTION);
                continue;
            }
#if USE_EXTRA_OPCODES
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode_bulldozer(
                    CDISASM_MODE_64, code, sizeof(code), &decoded_size);

                EXPECT(decoded_size == sizeof(code));
                expect_common_metadata(
                    &instruction, test->name_id, CDISASM_PREFIX_XOP);
                if (test->shape == MAP8_PERMUTE) {
                    EXPECT(instruction.form_id == UINT16_C(7688));
                }
                EXPECT(instruction.operand_count == 4);
                expect_register(
                    &instruction.opcode[0], CDISASM_X86_REG_XMM1, 16,
                    CDISASM_OPERAND_ACCESS_WRITE);
                expect_register(
                    &instruction.opcode[1], CDISASM_X86_REG_XMM2, 16,
                    CDISASM_OPERAND_ACCESS_READ);
                if (test->shape == MAP8_COMPARE) {
                    expect_register(
                        &instruction.opcode[2], CDISASM_X86_REG_XMM3, 16,
                        CDISASM_OPERAND_ACCESS_READ);
                    EXPECT(instruction.opcode[3].type
                           == CDISASM_OPERAND_IMMEDIATE);
                    EXPECT(instruction.opcode[3].size == 1);
                    EXPECT(instruction.opcode[3].imm == UINT64_C(0xe5));
                } else {
                    const cdisasm_x86_reg_id third = w != 0
                        ? CDISASM_X86_REG_XMM4 : CDISASM_X86_REG_XMM3;
                    const cdisasm_x86_reg_id fourth = w != 0
                        ? CDISASM_X86_REG_XMM3 : CDISASM_X86_REG_XMM4;

                    expect_register(
                        &instruction.opcode[2], third, 16,
                        CDISASM_OPERAND_ACCESS_READ);
                    expect_register(
                        &instruction.opcode[3], fourth, 16,
                        CDISASM_OPERAND_ACCESS_READ);
                }
#if USE_DISASM_FORMAT
                {
                    char intel[160];
                    char att[160];

                    if (test->shape == MAP8_COMPARE) {
                        (void)snprintf(
                            intel, sizeof(intel),
                            "%s xmm1, xmm2, xmm3, 0xe5",
                            test->mnemonic);
                        (void)snprintf(
                            att, sizeof(att),
                            "%s $0xe5, %%xmm3, %%xmm2, %%xmm1",
                            test->mnemonic);
                    } else if (w == 0) {
                        (void)snprintf(
                            intel, sizeof(intel),
                            "%s xmm1, xmm2, xmm3, xmm4",
                            test->mnemonic);
                        (void)snprintf(
                            att, sizeof(att),
                            "%s %%xmm4, %%xmm3, %%xmm2, %%xmm1",
                            test->mnemonic);
                    } else {
                        (void)snprintf(
                            intel, sizeof(intel),
                            "%s xmm1, xmm2, xmm4, xmm3",
                            test->mnemonic);
                        (void)snprintf(
                            att, sizeof(att),
                            "%s %%xmm3, %%xmm4, %%xmm2, %%xmm1",
                            test->mnemonic);
                    }
                    expect_format(&instruction, intel, att);
                }
#endif

                instruction = decode_bulldozer(
                    CDISASM_MODE_64, memory, sizeof(memory), &decoded_size);
                EXPECT(decoded_size == sizeof(memory));
                expect_common_metadata(
                    &instruction, test->name_id, CDISASM_PREFIX_XOP);
                if (test->shape == MAP8_PERMUTE) {
                    EXPECT(instruction.form_id
                        == (cdisasm_x86_form_id)(UINT16_C(7686) + w));
                }
                if (test->shape == MAP8_COMPARE || w == 0) {
                    expect_memory(
                        &instruction.opcode[2], CDISASM_X86_REG_RAX, 16);
                } else {
                    expect_memory(
                        &instruction.opcode[3], CDISASM_X86_REG_RAX, 16);
                }
            }
#else
            expect_error(
                code, sizeof(code),
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error(
                memory, sizeof(memory),
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

static void test_map8_structural_rules(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(map8_cases) / sizeof(map8_cases[0]);
         ++case_index) {
        const map8_case *test = &map8_cases[case_index];
        const uint8_t missing_modrm[] = {
            0x8f, 0xe8, 0x68, test->opcode
        };
        const uint8_t missing_imm[] = {
            0x8f, 0xe8, 0x68, test->opcode, 0xcb
        };
        const uint8_t wrong_l[] = {
            0x8f, 0xe8, 0x6c, test->opcode, 0xcb, 0x40
        };
        const uint8_t wrong_pp[] = {
            0x8f, 0xe8, 0x69, test->opcode, 0xcb, 0x40
        };

        expect_error(
            missing_modrm, sizeof(missing_modrm),
            CDISASM_STATUS_TRUNCATED);
        expect_error(
            missing_imm, sizeof(missing_imm),
            CDISASM_STATUS_TRUNCATED);
        expect_error(
            wrong_l, sizeof(wrong_l),
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error(
            wrong_pp, sizeof(wrong_pp),
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_vpermil2_matrix(void)
{
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_name_id names[] = {
        CDISASM_X86_NAME_VPERMIL2PS,
        CDISASM_X86_NAME_VPERMIL2PD
    };
#if USE_DISASM_FORMAT
    static const char *const mnemonics[] = {
        "vpermil2ps", "vpermil2pd"
    };
#endif
#endif
    unsigned int kind;

    for (kind = 0; kind != 2; ++kind) {
        unsigned int l;

        for (l = 0; l != 2; ++l) {
            unsigned int w;

            for (w = 0; w != 2; ++w) {
                unsigned int memory_form;

                for (memory_form = 0; memory_form != 2; ++memory_form) {
                    uint8_t code[] = {
                        0xc4, 0xe3,
                        (uint8_t)(0x69u | (l << 2) | (w << 7)),
                        (uint8_t)(0x48u + kind),
                        (uint8_t)(memory_form != 0 ? 0x08 : 0xcb),
                        0x42
                    };

#if USE_EXTRA_OPCODES
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode_bulldozer(
                        CDISASM_MODE_64, code, sizeof(code), &decoded_size);
                    const cdisasm_x86_reg_id base = l != 0
                        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
                    const unsigned int size = l != 0 ? 32u : 16u;

                    EXPECT(decoded_size == sizeof(code));
                    expect_common_metadata(
                        &instruction, names[kind], CDISASM_PREFIX_VEX);
                    EXPECT(instruction.operand_count == 5);
                    expect_register(
                        &instruction.opcode[0], base + 1u, size,
                        CDISASM_OPERAND_ACCESS_WRITE);
                    expect_register(
                        &instruction.opcode[1], base + 2u, size,
                        CDISASM_OPERAND_ACCESS_READ);
                    if (w == 0) {
                        if (memory_form != 0) {
                            expect_memory(
                                &instruction.opcode[2],
                                CDISASM_X86_REG_RAX, size);
                        } else {
                            expect_register(
                                &instruction.opcode[2], base + 3u, size,
                                CDISASM_OPERAND_ACCESS_READ);
                        }
                        expect_register(
                            &instruction.opcode[3], base + 4u, size,
                            CDISASM_OPERAND_ACCESS_READ);
                    } else {
                        expect_register(
                            &instruction.opcode[2], base + 4u, size,
                            CDISASM_OPERAND_ACCESS_READ);
                        if (memory_form != 0) {
                            expect_memory(
                                &instruction.opcode[3],
                                CDISASM_X86_REG_RAX, size);
                        } else {
                            expect_register(
                                &instruction.opcode[3], base + 3u, size,
                                CDISASM_OPERAND_ACCESS_READ);
                        }
                    }
                    EXPECT(instruction.opcode[4].type
                           == CDISASM_OPERAND_IMMEDIATE);
                    EXPECT(instruction.opcode[4].size == 1);
                    EXPECT(instruction.opcode[4].imm == UINT64_C(0x42));

#if USE_DISASM_FORMAT
                    if (memory_form == 0) {
                        char intel[192];
                        char att[192];
                        const char *reg = l != 0 ? "ymm" : "xmm";

                        (void)snprintf(
                            intel, sizeof(intel),
                            "%s %s1, %s2, %s%u, %s%u, 0x42",
                            mnemonics[kind], reg, reg, reg,
                            w != 0 ? 4u : 3u, reg,
                            w != 0 ? 3u : 4u);
                        (void)snprintf(
                            att, sizeof(att),
                            "%s $0x42, %%%s%u, %%%s%u, %%%s2, %%%s1",
                            mnemonics[kind], reg,
                            w != 0 ? 3u : 4u, reg,
                            w != 0 ? 4u : 3u, reg, reg);
                        expect_format(&instruction, intel, att);
                    }
#endif
#else
                    expect_error(
                        code, sizeof(code),
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
            }
        }
    }
}

static void test_vpermil2_structural_rules(void)
{
    unsigned int opcode;

    for (opcode = 0x48; opcode <= 0x49; ++opcode) {
        const uint8_t missing_modrm[] = {
            0xc4, 0xe3, 0x69, (uint8_t)opcode
        };
        const uint8_t missing_imm[] = {
            0xc4, 0xe3, 0x69, (uint8_t)opcode, 0xcb
        };
        unsigned int pp;

        expect_error(
            missing_modrm, sizeof(missing_modrm),
            CDISASM_STATUS_TRUNCATED);
        expect_error(
            missing_imm, sizeof(missing_imm),
            CDISASM_STATUS_TRUNCATED);
        for (pp = 0; pp != 4; ++pp) {
            uint8_t wrong_pp[] = {
                0xc4, 0xe3, (uint8_t)(0x68u | pp),
                (uint8_t)opcode, 0xcb, 0x42
            };

            if (pp != 1) {
                expect_error(
                    wrong_pp, sizeof(wrong_pp),
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }
    }
}

static void test_is4_non64_masking(void)
{
    static const uint8_t vpmac[] = {0x8f, 0xe8, 0x68, 0x85, 0xcb, 0xc0};
    static const uint8_t vpperm[] = {0x8f, 0xe8, 0x68, 0xa3, 0xcb, 0xc0};
    static const uint8_t vpcmov[] = {0x8f, 0xe8, 0x68, 0xa2, 0xcb, 0xc0};
    static const uint8_t fma4[] = {0xc4, 0xe3, 0x69, 0x68, 0xcb, 0xc0};
    static const uint8_t vpermil2[] = {0xc4, 0xe3, 0x69, 0x48, 0xcb, 0xc2};

#if USE_EXTRA_OPCODES
    static const struct {
        const uint8_t *bytes;
        size_t size;
        unsigned int selector_operand;
        cdisasm_x86_decode_option flags;
    } cases[] = {
        {vpmac, sizeof(vpmac), 3, CDISASM_X86_DECODE_FLAG_XOP},
        {vpperm, sizeof(vpperm), 3, CDISASM_X86_DECODE_FLAG_XOP},
        {vpcmov, sizeof(vpcmov), 3, CDISASM_X86_DECODE_FLAG_XOP},
        {fma4, sizeof(fma4), 3, CDISASM_X86_DECODE_FLAG_FMA4},
        {vpermil2, sizeof(vpermil2), 3, CDISASM_X86_DECODE_FLAG_XOP}
    };
    size_t case_index;

    for (case_index = 0; case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        unsigned int mode_index;

        for (mode_index = 0; mode_index != 2; ++mode_index) {
            const cdisasm_mode mode = mode_index == 0
                ? CDISASM_MODE_16 : CDISASM_MODE_32;
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode_mode(
                CDISASM_CPU_AMD_BULLDOZER, mode,
                cases[case_index].bytes, cases[case_index].size,
                cases[case_index].flags, &decoded_size);

            EXPECT(decoded_size == cases[case_index].size);
            expect_register(
                &instruction.opcode[cases[case_index].selector_operand],
                CDISASM_X86_REG_XMM4, 16,
                CDISASM_OPERAND_ACCESS_READ);
        }
        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode_mode(
                CDISASM_CPU_AMD_BULLDOZER, CDISASM_MODE_64,
                cases[case_index].bytes, cases[case_index].size,
                cases[case_index].flags, &decoded_size);

            EXPECT(decoded_size == cases[case_index].size);
            expect_register(
                &instruction.opcode[cases[case_index].selector_operand],
                CDISASM_X86_REG_XMM12, 16,
                CDISASM_OPERAND_ACCESS_READ);
        }
    }
#else
    expect_error(vpmac, sizeof(vpmac),
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(vpperm, sizeof(vpperm),
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(vpcmov, sizeof(vpcmov),
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(fma4, sizeof(fma4),
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(vpermil2, sizeof(vpermil2),
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_cpu_and_runtime_gates(void)
{
    static const uint8_t xop[] = {0x8f, 0xe8, 0x68, 0x85, 0xcb, 0x40};
    static const uint8_t vex[] = {0xc4, 0xe3, 0x69, 0x48, 0xcb, 0x42};

#if USE_EXTRA_OPCODES
    const uint8_t *codes[] = {xop, vex};
    const size_t sizes[] = {sizeof(xop), sizeof(vex)};
    size_t index;

    for (index = 0; index != 2; ++index) {
        expect_error_mode(
            CDISASM_CPU_AMD_BULLDOZER, CDISASM_MODE_64,
            codes[index], sizes[index], CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error_mode(
            CDISASM_CPU_AMD_BULLDOZER, CDISASM_MODE_64,
            codes[index], sizes[index], CDISASM_X86_DECODE_FLAG_AVX,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error_mode(
            CDISASM_CPU_HASWELL, CDISASM_MODE_64,
            codes[index], sizes[index], CDISASM_X86_DECODE_FLAG_XOP,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error_mode(
            CDISASM_CPU_AMD_ZEN, CDISASM_MODE_64,
            codes[index], sizes[index], CDISASM_X86_DECODE_FLAG_XOP,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#else
    expect_error(xop, sizeof(xop),
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(vex, sizeof(vex),
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

#undef XOP_STRUCTURAL_FLAGS

int main(void)
{
    test_map8_catalog_and_operands();
    test_map8_structural_rules();
    test_vpermil2_matrix();
    test_vpermil2_structural_rules();
    test_is4_non64_masking();
    test_cpu_and_runtime_gates();

    if (failures != 0) {
        fprintf(stderr,
                "remaining XOP tests failed: %d (extra=%d, format=%d)\n",
                failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("remaining XOP tests passed (extra=%d, format=%d)\n",
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
