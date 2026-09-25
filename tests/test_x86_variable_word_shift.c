#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct word_shift_case {
    uint8_t opcode;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} word_shift_case;

enum source_form {
    SOURCE_REGISTER = 0,
    SOURCE_MEMORY = 1
};

enum mask_form {
    MASK_NONE = 0,
    MASK_MERGE = 1,
    MASK_ZERO = 2
};

static const word_shift_case cases[] = {
    {0x12, CDISASM_X86_NAME_VPSLLVW, "vpsllvw"},
    {0x10, CDISASM_X86_NAME_VPSRLVW, "vpsrlvw"},
    {0x11, CDISASM_X86_NAME_VPSRAVW, "vpsravw"}
};

_Static_assert(CDISASM_X86_NAME_VPSLLVW == UINT16_C(1043),
    "variable-word-shift catalog start changed");
_Static_assert(CDISASM_X86_NAME_VPSRAVW == UINT16_C(1045),
    "variable-word-shift catalog end changed");
_Static_assert(CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1),
    "variable-word-shift public catalog is incomplete");
_Static_assert(CDISASM_NAME_VPSLLVW == CDISASM_X86_NAME_VPSLLVW
        && CDISASM_NAME_VPSRLVW == CDISASM_X86_NAME_VPSRLVW
        && CDISASM_NAME_VPSRAVW == CDISASM_X86_NAME_VPSRAVW,
    "legacy variable-word-shift aliases changed");

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

static void make_encoding(
    const word_shift_case *test,
    unsigned int length,
    enum source_form source,
    enum mask_form mask,
    uint8_t code[6])
{
    uint8_t p2 = (uint8_t)(UINT8_C(0x08) | (length << 5));

    if (mask != MASK_NONE) {
        p2 |= UINT8_C(0x02);
    }
    if (mask == MASK_ZERO) {
        p2 |= UINT8_C(0x80);
    }
    code[0] = UINT8_C(0x62);
    code[1] = UINT8_C(0xf2);
    code[2] = UINT8_C(0xed);
    code[3] = p2;
    code[4] = test->opcode;
    code[5] = source == SOURCE_REGISTER
        ? UINT8_C(0xcb) : UINT8_C(0x08);
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

static cdisasm_x86_reg_id expected_base(cdisasm_mode mode)
{
    return mode == CDISASM_MODE_16 ? CDISASM_X86_REG_BX
        : mode == CDISASM_MODE_32 ? CDISASM_X86_REG_EAX
        : CDISASM_X86_REG_RAX;
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

static void expect_case_format(
    const cdisasm_instruction *instruction,
    const word_shift_case *test,
    cdisasm_mode mode,
    unsigned int vector_bits,
    enum source_form source,
    enum mask_form mask)
{
    const char *reg = vector_bits == 128u ? "xmm"
        : vector_bits == 256u ? "ymm" : "zmm";
    const char *intel_mask = mask == MASK_NONE ? ""
        : mask == MASK_MERGE ? " {k2}" : " {k2}{z}";
    const char *att_mask = mask == MASK_NONE ? ""
        : mask == MASK_MERGE ? "{%k2}" : "{%k2}{z}";
    const char *intel_address = mode == CDISASM_MODE_16 ? "bx + si"
        : mode == CDISASM_MODE_32 ? "eax" : "rax";
    const char *att_address = mode == CDISASM_MODE_16 ? "(%bx,%si)"
        : mode == CDISASM_MODE_32 ? "(%eax)" : "(%rax)";
    const char *memory_type = vector_bits == 128u ? "xmmword"
        : vector_bits == 256u ? "ymmword" : "zmmword";
    char intel[192];
    char att[192];

    if (source == SOURCE_REGISTER) {
        snprintf(intel, sizeof(intel), "%s %s1%s, %s2, %s3",
            test->mnemonic, reg, intel_mask, reg, reg);
        snprintf(att, sizeof(att), "%s %%%s3, %%%s2, %%%s1%s",
            test->mnemonic, reg, reg, reg, att_mask);
    } else {
        snprintf(intel, sizeof(intel),
            "%s %s1%s, %s2, %s ptr [%s]",
            test->mnemonic, reg, intel_mask, reg,
            memory_type, intel_address);
        snprintf(att, sizeof(att), "%s %s, %%%s2, %%%s1%s",
            test->mnemonic, att_address, reg, reg, att_mask);
    }
    expect_format(instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL, intel);
    expect_format(instruction, CDISASM_FORMAT_SYNTAX_X86_ATT, att);
}
#endif
#endif

static void test_canonical_matrix(void)
{
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t decoded_cases = 0;
    size_t mode_index;
    size_t case_index;

    for (mode_index = 0;
         mode_index < sizeof(modes) / sizeof(modes[0]);
         ++mode_index) {
        for (case_index = 0;
             case_index < sizeof(cases) / sizeof(cases[0]);
             ++case_index) {
            unsigned int length;

            for (length = 0; length != 3; ++length) {
                enum source_form source;

                for (source = SOURCE_REGISTER;
                     source <= SOURCE_MEMORY;
                     source = (enum source_form)(source + 1)) {
                    enum mask_form mask;

                    for (mask = MASK_NONE;
                         mask <= MASK_ZERO;
                         mask = (enum mask_form)(mask + 1)) {
                        const unsigned int vector_bits = 128u << length;
                        uint8_t code[6];

                        make_encoding(&cases[case_index], length,
                            source, mask, code);
                        ++decoded_cases;
#if USE_EXTRA_OPCODES
                        {
                            uint32_t decoded_size;
                            cdisasm_instruction instruction = decode(
                                CDISASM_CPU_SKYLAKE_SP,
                                modes[mode_index], code, sizeof(code),
                                CDISASM_X86_DECODE_FLAG_AVX512,
                                &decoded_size);

                            EXPECT(decoded_size == sizeof(code));
                            EXPECT(instruction.last_error_id
                                == CDISASM_STATUS_OK);
                            EXPECT(instruction.name_id
                                == cases[case_index].name_id);
                            EXPECT(instruction.operand_count == 3u);
                            EXPECT(instruction.opcode[0].reg
                                == vector_register(1u, vector_bits));
                            EXPECT(instruction.opcode[1].reg
                                == vector_register(2u, vector_bits));
                            EXPECT(instruction.opcode[0].access
                                == (mask == MASK_MERGE
                                    ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                    : CDISASM_OPERAND_ACCESS_WRITE));
                            EXPECT(instruction.opcode[1].access
                                == CDISASM_OPERAND_ACCESS_READ);
                            EXPECT(instruction.opcode[0].size
                                == vector_bits / 8u);
                            EXPECT(instruction.opcode[1].size
                                == vector_bits / 8u);
                            EXPECT(instruction.mask_reg
                                == (mask == MASK_NONE
                                    ? CDISASM_X86_REG_NONE
                                    : CDISASM_X86_REG_K2));
                            EXPECT(instruction.mask_mode
                                == (mask == MASK_NONE
                                    ? CDISASM_X86_MASK_NONE
                                    : mask == MASK_MERGE
                                        ? CDISASM_X86_MASK_MERGE
                                        : CDISASM_X86_MASK_ZERO));
                            EXPECT(cdisasm_instruction_has_x86_group(
                                &instruction, CDISASM_X86_GROUP_AVX));
                            EXPECT(cdisasm_instruction_has_x86_group(
                                &instruction, CDISASM_X86_GROUP_AVX512F));
                            EXPECT(cdisasm_instruction_has_x86_group(
                                &instruction, CDISASM_X86_GROUP_AVX512BW));
                            EXPECT(cdisasm_instruction_has_x86_group(
                                       &instruction,
                                       CDISASM_X86_GROUP_AVX512VL)
                                == (vector_bits < 512u));
                            EXPECT(!cdisasm_instruction_has_x86_group(
                                &instruction,
                                CDISASM_X86_GROUP_AVX10_1));
                            if (source == SOURCE_REGISTER) {
                                EXPECT(instruction.opcode[2].type
                                    == CDISASM_OPERAND_REGISTER);
                                EXPECT(instruction.opcode[2].reg
                                    == vector_register(3u, vector_bits));
                            } else {
                                EXPECT(instruction.opcode[2].type
                                    == CDISASM_OPERAND_MEMORY);
                                EXPECT(instruction.opcode[2].base_reg
                                    == expected_base(modes[mode_index]));
                                EXPECT(instruction.opcode[2].index_reg
                                    == (modes[mode_index]
                                            == CDISASM_MODE_16
                                        ? CDISASM_X86_REG_SI
                                        : CDISASM_X86_REG_NONE));
                                EXPECT(instruction.opcode[2].broadcast
                                    == CDISASM_X86_BROADCAST_NONE);
                            }
                            EXPECT(instruction.opcode[2].size
                                == vector_bits / 8u);
                            EXPECT(instruction.opcode[2].access
                                == CDISASM_OPERAND_ACCESS_READ);
                            EXPECT(instruction.encoding.prefix_size == 4u);
                            EXPECT(instruction.encoding.opcode_offset == 4u);
                            EXPECT(instruction.encoding.modrm_offset == 5u);
#if USE_DISASM_FORMAT
                            expect_case_format(&instruction,
                                &cases[case_index], modes[mode_index],
                                vector_bits, source, mask);
#endif
                        }
#else
                        (void)vector_bits;
                        expect_error("extra-opcodes OFF word shift",
                            CDISASM_CPU_X86, modes[mode_index],
                            code, sizeof(code),
                            CDISASM_X86_DECODE_FLAG_BASE,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                    }
                }
            }
        }
    }
    EXPECT(decoded_cases == 162u);
}

static void test_compressed_displacement(void)
{
    size_t decoded_cases = 0;
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            const unsigned int vector_bits = 128u << length;
            uint8_t code[] = {
                0x62, 0xf2, 0xed,
                (uint8_t)(0x0a + (length << 5)),
                cases[case_index].opcode, 0x48, 0x02
            };

            ++decoded_cases;
#if USE_EXTRA_OPCODES
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                    &decoded_size);

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.name_id == cases[case_index].name_id);
                EXPECT(instruction.opcode[2].size == vector_bits / 8u);
                EXPECT(instruction.opcode[2].imm == vector_bits / 4u);
                EXPECT(instruction.encoding.displacement_offset == 6u);
                EXPECT(instruction.encoding.displacement_size == 1u);
            }
#else
            (void)vector_bits;
            expect_error("extra-opcodes OFF word-shift disp8",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
    EXPECT(decoded_cases == 9u);
}

static void test_feature_routes(void)
{
    static const uint8_t code[] = {
        0x62, 0xf2, 0xed, 0x4a, 0x12, 0xcb
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    expect_error("word-shift runtime AVX-512 gate",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("word-shift CPU AVX-512BW gate",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy profile rejects word-shift AVX10 route",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 profile rejects word-shift AVX-512 route",
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX10,
        &decoded_size);
    EXPECT(decoded_size == sizeof(code));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPSLLVW);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512BW));
#else
    expect_error("extra-opcodes OFF word-shift feature route",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_apx_b4_matrix(void)
{
    size_t decoded_cases = 0;
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            enum source_form source;

            for (source = SOURCE_REGISTER;
                 source <= SOURCE_MEMORY;
                 source = (enum source_form)(source + 1)) {
                enum mask_form mask;

                for (mask = MASK_NONE;
                     mask <= MASK_ZERO;
                     mask = (enum mask_form)(mask + 1)) {
                    const unsigned int vector_bits = 128u << length;
                    uint8_t code[6];

                    make_encoding(&cases[case_index], length,
                        source, mask, code);
                    code[1] |= UINT8_C(0x08);
                    ++decoded_cases;
#if USE_EXTRA_OPCODES
                    {
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_APX, CDISASM_MODE_64,
                            code, sizeof(code),
                            CDISASM_X86_DECODE_FLAG_AVX10
                                | CDISASM_X86_DECODE_FLAG_APX,
                            &decoded_size);

                        EXPECT(decoded_size == sizeof(code));
                        EXPECT(instruction.name_id
                            == cases[case_index].name_id);
                        EXPECT(cdisasm_instruction_has_x86_group(
                            &instruction, CDISASM_X86_GROUP_AVX10_1));
                        EXPECT(cdisasm_instruction_has_x86_group(
                            &instruction, CDISASM_X86_GROUP_APX_F));
                        if (source == SOURCE_REGISTER) {
                            EXPECT(instruction.opcode[2].reg
                                == vector_register(3u, vector_bits));
                        } else {
                            EXPECT(instruction.opcode[2].base_reg
                                == CDISASM_X86_REG_R16);
                            EXPECT(instruction.opcode[2].index_reg
                                == CDISASM_X86_REG_NONE);
                        }
                    }
#else
                    (void)vector_bits;
                    expect_error("extra-opcodes OFF APX B4 word shift",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
            }
        }
    }
    EXPECT(decoded_cases == 54u);

    {
        static const uint8_t apx_register[] = {
            0x62, 0xfa, 0xed, 0x4a, 0x12, 0xcb
        };
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        expect_error("APX B4 word-shift runtime gate",
            CDISASM_CPU_APX, CDISASM_MODE_64,
            apx_register, sizeof(apx_register),
            CDISASM_X86_DECODE_FLAG_AVX10,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("APX B4 word-shift CPU gate",
            CDISASM_CPU_AVX10, CDISASM_MODE_64,
            apx_register, sizeof(apx_register),
            CDISASM_X86_DECODE_FLAG_AVX10
                | CDISASM_X86_DECODE_FLAG_APX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("APX B4 word-shift mode gate",
            CDISASM_CPU_APX, CDISASM_MODE_32,
            apx_register, sizeof(apx_register),
            CDISASM_X86_DECODE_FLAG_AVX10
                | CDISASM_X86_DECODE_FLAG_APX,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        instruction = decode(
            CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
            apx_register, sizeof(apx_register),
            CDISASM_X86_DECODE_FLAG_AVX512
                | CDISASM_X86_DECODE_FLAG_APX,
            &decoded_size);
        EXPECT(decoded_size == sizeof(apx_register));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512F));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512BW));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
#else
        expect_error("extra-opcodes OFF APX B4 gate control",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            apx_register, sizeof(apx_register),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_apx_u0_matrix(void)
{
    size_t decoded_cases = 0;
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            unsigned int b4;

            for (b4 = 0; b4 != 2; ++b4) {
                enum mask_form mask;

                for (mask = MASK_NONE;
                     mask <= MASK_ZERO;
                     mask = (enum mask_form)(mask + 1)) {
                    const unsigned int vector_bits = 128u << length;
                    uint8_t code[6];

                    make_encoding(&cases[case_index], length,
                        SOURCE_MEMORY, mask, code);
                    code[2] &= UINT8_C(0xfb);
                    if (b4 != 0) {
                        code[1] |= UINT8_C(0x08);
                    }
                    ++decoded_cases;
#if USE_EXTRA_OPCODES
                    {
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_APX, CDISASM_MODE_64,
                            code, sizeof(code),
                            CDISASM_X86_DECODE_FLAG_AVX10
                                | CDISASM_X86_DECODE_FLAG_APX,
                            &decoded_size);

                        EXPECT(decoded_size == sizeof(code));
                        EXPECT(instruction.name_id
                            == cases[case_index].name_id);
                        EXPECT(instruction.opcode[2].type
                            == CDISASM_OPERAND_MEMORY);
                        EXPECT(instruction.opcode[2].base_reg
                            == (b4 != 0
                                ? CDISASM_X86_REG_R16
                                : CDISASM_X86_REG_RAX));
                        EXPECT(instruction.opcode[2].index_reg
                            == CDISASM_X86_REG_NONE);
                        EXPECT(instruction.opcode[2].size
                            == vector_bits / 8u);
                        EXPECT(cdisasm_instruction_has_x86_group(
                            &instruction, CDISASM_X86_GROUP_APX_F));
                    }
#else
                    (void)vector_bits;
                    expect_error("extra-opcodes OFF APX U0 word shift",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
            }
        }
    }
    EXPECT(decoded_cases == 54u);

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        static const struct address_case {
            uint8_t p0;
            uint8_t p1;
            cdisasm_x86_reg_id base;
            cdisasm_x86_reg_id index;
        } addresses[] = {
            {0xf2, 0xe9, CDISASM_X86_REG_RAX, CDISASM_X86_REG_R17},
            {0xfa, 0xe9, CDISASM_X86_REG_R16, CDISASM_X86_REG_R17},
            {0xfa, 0xed, CDISASM_X86_REG_R16, CDISASM_X86_REG_RCX},
            {0x9a, 0xe9, CDISASM_X86_REG_R24, CDISASM_X86_REG_R25}
        };
        size_t address_index;

        for (address_index = 0;
             address_index < sizeof(addresses) / sizeof(addresses[0]);
             ++address_index) {
            uint8_t code[] = {
                0x62, addresses[address_index].p0,
                addresses[address_index].p1, 0x0a,
                cases[case_index].opcode, 0x0c, 0x08
            };
#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_APX, CDISASM_MODE_64,
                code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_AVX10
                    | CDISASM_X86_DECODE_FLAG_APX,
                &decoded_size);

            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.name_id == cases[case_index].name_id);
            EXPECT(instruction.opcode[2].base_reg
                == addresses[address_index].base);
            EXPECT(instruction.opcode[2].index_reg
                == addresses[address_index].index);
#else
            expect_error("extra-opcodes OFF APX word-shift ownership",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }

    {
        static const uint8_t u0_memory[] = {
            0x62, 0xf2, 0xe9, 0x0a, 0x12, 0x08
        };
        static const uint8_t u0_register[] = {
            0x62, 0xf2, 0xe9, 0x0a, 0x12, 0xcb
        };

        expect_error("APX U0 word-shift register is reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            u0_register, sizeof(u0_register),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("APX U0 word shift is 64-bit only",
            CDISASM_CPU_X86, CDISASM_MODE_32,
            u0_memory, sizeof(u0_memory),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
#if USE_EXTRA_OPCODES
        expect_error("APX U0 word-shift runtime gate",
            CDISASM_CPU_APX, CDISASM_MODE_64,
            u0_memory, sizeof(u0_memory),
            CDISASM_X86_DECODE_FLAG_AVX10,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("APX U0 word-shift CPU gate",
            CDISASM_CPU_AVX10, CDISASM_MODE_64,
            u0_memory, sizeof(u0_memory),
            CDISASM_X86_DECODE_FLAG_AVX10
                | CDISASM_X86_DECODE_FLAG_APX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        expect_error("extra-opcodes OFF APX U0 gate control",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            u0_memory, sizeof(u0_memory),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_reserved_matrix(void)
{
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t rejected_cases = 0;
    size_t mode_index;
    size_t case_index;

    for (mode_index = 0;
         mode_index < sizeof(modes) / sizeof(modes[0]);
         ++mode_index) {
        for (case_index = 0;
             case_index < sizeof(cases) / sizeof(cases[0]);
             ++case_index) {
            unsigned int length;

            for (length = 0; length != 3; ++length) {
                enum source_form source;

                for (source = SOURCE_REGISTER;
                     source <= SOURCE_MEMORY;
                     source = (enum source_form)(source + 1)) {
                    enum mask_form mask;

                    for (mask = MASK_NONE;
                         mask <= MASK_ZERO;
                         mask = (enum mask_form)(mask + 1)) {
                        uint8_t w0[6];
                        uint8_t b_set[6];

                        make_encoding(&cases[case_index], length,
                            source, mask, w0);
                        memcpy(b_set, w0, sizeof(b_set));
                        w0[2] &= UINT8_C(0x7f);
                        b_set[3] |= UINT8_C(0x10);
                        expect_error("reserved word-shift W=0",
                            CDISASM_CPU_X86, modes[mode_index],
                            w0, sizeof(w0),
                            CDISASM_X86_DECODE_FLAG_BASE,
                            CDISASM_STATUS_INVALID_INSTRUCTION);
                        expect_error("reserved word-shift EVEX.b",
                            CDISASM_CPU_X86, modes[mode_index],
                            b_set, sizeof(b_set),
                            CDISASM_X86_DECODE_FLAG_BASE,
                            CDISASM_STATUS_INVALID_INSTRUCTION);
                        rejected_cases += 2u;
                    }
                }

                for (source = SOURCE_REGISTER;
                     source <= SOURCE_MEMORY;
                     source = (enum source_form)(source + 1)) {
                    uint8_t zero_k0[6];

                    make_encoding(&cases[case_index], length,
                        source, MASK_NONE, zero_k0);
                    zero_k0[3] |= UINT8_C(0x80);
                    expect_error("word-shift zeroing without mask",
                        CDISASM_CPU_X86, modes[mode_index],
                        zero_k0, sizeof(zero_k0),
                        CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_INVALID_INSTRUCTION);
                    ++rejected_cases;
                }

                {
                    enum mask_form mask;

                    for (mask = MASK_NONE;
                         mask <= MASK_ZERO;
                         mask = (enum mask_form)(mask + 1)) {
                        uint8_t u0_register[6];

                        make_encoding(&cases[case_index], length,
                            SOURCE_REGISTER, mask, u0_register);
                        u0_register[2] &= UINT8_C(0xfb);
                        expect_error("word-shift U0 register",
                            CDISASM_CPU_X86, modes[mode_index],
                            u0_register, sizeof(u0_register),
                            CDISASM_X86_DECODE_FLAG_BASE,
                            CDISASM_STATUS_INVALID_INSTRUCTION);
                        ++rejected_cases;
                    }
                }
            }

            {
                enum source_form source;

                for (source = SOURCE_REGISTER;
                     source <= SOURCE_MEMORY;
                     source = (enum source_form)(source + 1)) {
                    enum mask_form mask;

                    for (mask = MASK_NONE;
                         mask <= MASK_ZERO;
                         mask = (enum mask_form)(mask + 1)) {
                        uint8_t ll3[6];

                        make_encoding(&cases[case_index], 0u,
                            source, mask, ll3);
                        ll3[3] = (uint8_t)((ll3[3]
                            & UINT8_C(0x9f)) | UINT8_C(0x60));
                        expect_error("reserved word-shift LL=3",
                            CDISASM_CPU_X86, modes[mode_index],
                            ll3, sizeof(ll3),
                            CDISASM_X86_DECODE_FLAG_BASE,
                            CDISASM_STATUS_INVALID_INSTRUCTION);
                        ++rejected_cases;
                    }
                }
            }
        }
    }
    EXPECT(rejected_cases == 513u);
}

static void test_unowned_and_truncation(void)
{
    static const uint8_t vex_nonexistent[] = {
        0xc4, 0xe2, 0xed, 0x12, 0xcb
    };
    static const uint8_t unowned_pp[] = {
        0x62, 0xf2, 0xec, 0x4a, 0x12, 0xcb
    };
    static const uint8_t adjacent_opcode[] = {
        0x62, 0xf2, 0xed, 0x4a, 0x13, 0xcb
    };
    static const uint8_t truncated_modrm[] = {
        0x62, 0xf2, 0xed, 0x4a, 0x12
    };
    static const uint8_t truncated_disp8[] = {
        0x62, 0xf2, 0xed, 0x4a, 0x12, 0x48
    };
    static const uint8_t reserved_w_truncated[] = {
        0x62, 0xf2, 0x6d, 0x4a, 0x12
    };

    expect_error("word shifts have no VEX encoding",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        vex_nonexistent, sizeof(vex_nonexistent),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("word-shift unowned pp",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        unowned_pp, sizeof(unowned_pp),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("word-shift adjacent opcode stays unowned",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        adjacent_opcode, sizeof(adjacent_opcode),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("truncated word-shift ModRM",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_modrm, sizeof(truncated_modrm),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated word-shift disp8",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_disp8, sizeof(truncated_disp8),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved W precedes missing ModRM",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        reserved_w_truncated, sizeof(reserved_w_truncated),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

int main(void)
{
    test_canonical_matrix();
    test_compressed_displacement();
    test_feature_routes();
    test_apx_b4_matrix();
    test_apx_u0_matrix();
    test_reserved_matrix();
    test_unowned_and_truncation();

    if (failures != 0) {
        fprintf(stderr,
            "%d x86 variable-word-shift test(s) failed\n", failures);
        return 1;
    }
    printf("x86 variable-word-shift tests passed (extra=%d, format=%d)\n",
        USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
