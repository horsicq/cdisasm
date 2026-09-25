#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct shift_case {
    uint8_t extension;
    uint8_t w;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} shift_case;

enum source_form {
    SOURCE_REGISTER = 0,
    SOURCE_FULL_MEMORY = 1,
    SOURCE_BROADCAST_MEMORY = 2
};

enum mask_form {
    MASK_NONE = 0,
    MASK_MERGE = 1,
    MASK_ZERO = 2
};

enum matrix_count {
    CANONICAL_CONTROL_SHAPES = 324,
    CANONICAL_WIRE_ENCODINGS = CANONICAL_CONTROL_SHAPES * 256,
    COMPRESSED_DISPLACEMENT_CASES = 24,
    APX_B4_U1_CASES = 108,
    APX_U0_NOSIB_CASES = 144,
    APX_U0_X4_SIB_CASES = 144,
    APX_TOTAL_CASES = 396,
    OPCODE_CONTROL_CASES = 16
};

static const shift_case cases[] = {
    {2, 0, CDISASM_X86_NAME_VPSRLD, "vpsrld"},
    {4, 0, CDISASM_X86_NAME_VPSRAD, "vpsrad"},
    {4, 1, CDISASM_X86_NAME_VPSRAQ, "vpsraq"},
    {6, 0, CDISASM_X86_NAME_VPSLLD, "vpslld"}
};

_Static_assert(CANONICAL_WIRE_ENCODINGS == 82944,
    "immediate-shift canonical matrix changed");
_Static_assert(APX_B4_U1_CASES + APX_U0_NOSIB_CASES
        + APX_U0_X4_SIB_CASES == APX_TOTAL_CASES,
    "APX immediate-shift matrix changed");
_Static_assert(OPCODE_CONTROL_CASES == 2 * 8,
    "opcode-72 W-by-extension matrix changed");
_Static_assert(CDISASM_X86_NAME_VPSRLD == UINT16_C(1054),
    "immediate-shift catalog start changed");
_Static_assert(CDISASM_X86_NAME_VPSLLD == UINT16_C(1057),
    "immediate-shift catalog end changed");
_Static_assert(CDISASM_X86_NAME_VPSLLDQ == UINT16_C(1064),
    "version-11.12 terminal x86 name ID changed");
_Static_assert(CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1),
    "immediate-shift catalog count changed");
_Static_assert(CDISASM_NAME_VPSRLD == CDISASM_X86_NAME_VPSRLD
        && CDISASM_NAME_VPSRAD == CDISASM_X86_NAME_VPSRAD
        && CDISASM_NAME_VPSRAQ == CDISASM_X86_NAME_VPSRAQ
        && CDISASM_NAME_VPSLLD == CDISASM_X86_NAME_VPSLLD,
    "legacy immediate-shift aliases changed");

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",            \
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
    const shift_case *test,
    unsigned int length,
    enum source_form source,
    enum mask_form mask,
    uint8_t immediate,
    uint8_t code[7])
{
    uint8_t p2 = (uint8_t)(UINT8_C(0x08) | (length << 5));

    if (source == SOURCE_BROADCAST_MEMORY) {
        p2 |= UINT8_C(0x10);
    }
    if (mask != MASK_NONE) {
        p2 |= UINT8_C(0x02);
    }
    if (mask == MASK_ZERO) {
        p2 |= UINT8_C(0x80);
    }
    code[0] = UINT8_C(0x62);
    code[1] = UINT8_C(0xf1);
    code[2] = test->w != 0 ? UINT8_C(0xf5) : UINT8_C(0x75);
    code[3] = p2;
    code[4] = UINT8_C(0x72);
    code[5] = (uint8_t)((test->extension << 3)
        | (source == SOURCE_REGISTER ? UINT8_C(0xc2) : UINT8_C(0x00)));
    code[6] = immediate;
}

static cdisasm_x86_name_id expected_control_name(
    unsigned int w,
    unsigned int extension)
{
    switch (extension) {
        case 0:
            return w != 0 ? CDISASM_X86_NAME_VPRORQ
                : CDISASM_X86_NAME_VPRORD;
        case 1:
            return w != 0 ? CDISASM_X86_NAME_VPROLQ
                : CDISASM_X86_NAME_VPROLD;
        case 2:
            return w == 0 ? CDISASM_X86_NAME_VPSRLD
                : CDISASM_X86_NAME_NONE;
        case 4:
            return w != 0 ? CDISASM_X86_NAME_VPSRAQ
                : CDISASM_X86_NAME_VPSRAD;
        case 6:
            return w == 0 ? CDISASM_X86_NAME_VPSLLD
                : CDISASM_X86_NAME_NONE;
        default:
            return CDISASM_X86_NAME_NONE;
    }
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
    const shift_case *test,
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
    char intel[192];
    char att[192];

    if (source == SOURCE_REGISTER) {
        (void)snprintf(intel, sizeof(intel), "%s %s1%s, %s2, 0x13",
            test->mnemonic, reg, intel_mask, reg);
        (void)snprintf(att, sizeof(att), "%s $0x13, %%%s2, %%%s1%s",
            test->mnemonic, reg, reg, att_mask);
    } else {
        const unsigned int element_bits = test->w != 0 ? 64u : 32u;
        const char *memory_type = source == SOURCE_BROADCAST_MEMORY
            ? (test->w != 0 ? "qword" : "dword")
            : vector_bits == 128u ? "xmmword"
            : vector_bits == 256u ? "ymmword" : "zmmword";
        char broadcast[16] = "";

        if (source == SOURCE_BROADCAST_MEMORY) {
            (void)snprintf(broadcast, sizeof(broadcast), "{1to%u}",
                vector_bits / element_bits);
        }
        (void)snprintf(intel, sizeof(intel),
            "%s %s1%s, %s ptr [%s]%s, 0x13",
            test->mnemonic, reg, intel_mask,
            memory_type, intel_address, broadcast);
        (void)snprintf(att, sizeof(att), "%s $0x13, %s%s, %%%s1%s",
            test->mnemonic, att_address, broadcast, reg, att_mask);
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
                     source <= SOURCE_BROADCAST_MEMORY;
                     source = (enum source_form)(source + 1)) {
                    enum mask_form mask;

                    for (mask = MASK_NONE;
                         mask <= MASK_ZERO;
                         mask = (enum mask_form)(mask + 1)) {
                        unsigned int immediate;

                        for (immediate = 0; immediate != 256u; ++immediate) {
                            const unsigned int vector_bits = 128u << length;
                            const unsigned int element_bits =
                                cases[case_index].w != 0 ? 64u : 32u;
                            uint8_t code[7];

                            make_encoding(&cases[case_index], length,
                                source, mask, (uint8_t)immediate, code);
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
                                EXPECT((instruction.opcode_flags
                                    & CDISASM_PREFIX_EVEX) != 0);
                                EXPECT(instruction.operand_count == 3u);
                                EXPECT(instruction.opcode[0].type
                                    == CDISASM_OPERAND_REGISTER);
                                EXPECT(instruction.opcode[0].reg
                                    == vector_register(1u, vector_bits));
                                EXPECT(instruction.opcode[0].access
                                    == (mask == MASK_MERGE
                                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                        : CDISASM_OPERAND_ACCESS_WRITE));
                                EXPECT(instruction.opcode[1].access
                                    == CDISASM_OPERAND_ACCESS_READ);
                                EXPECT(instruction.opcode[2].type
                                    == CDISASM_OPERAND_IMMEDIATE);
                                EXPECT(instruction.opcode[2].size == 1u);
                                EXPECT(instruction.opcode[2].imm
                                    == immediate);
                                EXPECT(instruction.opcode[2].access
                                    == CDISASM_OPERAND_ACCESS_READ);
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
                                    &instruction,
                                    CDISASM_X86_GROUP_AVX512F));
                                EXPECT(cdisasm_instruction_has_x86_group(
                                           &instruction,
                                           CDISASM_X86_GROUP_AVX512VL)
                                    == (vector_bits < 512u));
                                EXPECT(!cdisasm_instruction_has_x86_group(
                                    &instruction,
                                    CDISASM_X86_GROUP_AVX10_1));
                                if (source == SOURCE_REGISTER) {
                                    EXPECT(instruction.opcode[1].type
                                        == CDISASM_OPERAND_REGISTER);
                                    EXPECT(instruction.opcode[1].reg
                                        == vector_register(2u, vector_bits));
                                    EXPECT(instruction.opcode[1].size
                                        == vector_bits / 8u);
                                    EXPECT(instruction.opcode[1].broadcast
                                        == CDISASM_X86_BROADCAST_NONE);
                                } else {
                                    const unsigned int memory_bits =
                                        source == SOURCE_BROADCAST_MEMORY
                                            ? element_bits : vector_bits;

                                    EXPECT(instruction.opcode[1].type
                                        == CDISASM_OPERAND_MEMORY);
                                    EXPECT(instruction.opcode[1].size
                                        == memory_bits / 8u);
                                    EXPECT(instruction.opcode[1].base_reg
                                        == expected_base(modes[mode_index]));
                                    EXPECT(instruction.opcode[1].index_reg
                                        == (modes[mode_index]
                                                == CDISASM_MODE_16
                                            ? CDISASM_X86_REG_SI
                                            : CDISASM_X86_REG_NONE));
                                    EXPECT(instruction.opcode[1].broadcast
                                        == (source
                                                == SOURCE_BROADCAST_MEMORY
                                            ? (cdisasm_x86_broadcast)(
                                                vector_bits / element_bits)
                                            : CDISASM_X86_BROADCAST_NONE));
                                }
                                EXPECT(instruction.encoding.prefix_size
                                    == 4u);
                                EXPECT(instruction.encoding.opcode_offset
                                    == 4u);
                                EXPECT(instruction.encoding.modrm_offset
                                    == 5u);
                                EXPECT(instruction.encoding.immediate_count
                                    == 1u);
                                EXPECT(instruction.encoding
                                    .immediate_offset[0] == 6u);
#if USE_DISASM_FORMAT
                                if (immediate == UINT8_C(0x13)) {
                                    expect_case_format(&instruction,
                                        &cases[case_index],
                                        modes[mode_index], vector_bits,
                                        source, mask);
                                }
#endif
                            }
#else
                            (void)vector_bits;
                            (void)element_bits;
                            expect_error(
                                "extra-opcodes OFF EVEX immediate shift",
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
    }
    EXPECT(decoded_cases == CANONICAL_WIRE_ENCODINGS);
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
            enum source_form source;

            for (source = SOURCE_FULL_MEMORY;
                 source <= SOURCE_BROADCAST_MEMORY;
                 source = (enum source_form)(source + 1)) {
                const unsigned int vector_bits = 128u << length;
                const unsigned int element_bits =
                    cases[case_index].w != 0 ? 64u : 32u;
                const unsigned int memory_bits =
                    source == SOURCE_BROADCAST_MEMORY
                        ? element_bits : vector_bits;
                uint8_t base[7];
                uint8_t code[8];

                make_encoding(&cases[case_index], length,
                    source, MASK_MERGE, UINT8_C(0x13), base);
                memcpy(code, base, 6u);
                code[5] = (uint8_t)(UINT8_C(0x40)
                    | (cases[case_index].extension << 3));
                code[6] = UINT8_C(0x02);
                code[7] = UINT8_C(0x13);
                ++decoded_cases;
#if USE_EXTRA_OPCODES
                {
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                        code, sizeof(code),
                        CDISASM_X86_DECODE_FLAG_AVX512,
                        &decoded_size);

                    EXPECT(decoded_size == sizeof(code));
                    EXPECT(instruction.name_id
                        == cases[case_index].name_id);
                    EXPECT(instruction.opcode[1].size == memory_bits / 8u);
                    EXPECT(instruction.opcode[1].imm == memory_bits / 4u);
                    EXPECT(instruction.encoding.displacement_offset == 6u);
                    EXPECT(instruction.encoding.displacement_size == 1u);
                    EXPECT(instruction.encoding.immediate_offset[0] == 7u);
                }
#else
                (void)memory_bits;
                expect_error("extra-opcodes OFF immediate shift disp8",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            }
        }
    }
    EXPECT(decoded_cases == COMPRESSED_DISPLACEMENT_CASES);
}

static void test_feature_routes(void)
{
    static const uint8_t evex[] = {
        0x62, 0xf1, 0x75, 0x4a, 0x72, 0xd2, 0x13
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    expect_error("immediate-shift runtime AVX-512 gate",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("immediate-shift CPU AVX-512 gate",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy profile rejects immediate-shift AVX10 route",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 profile rejects immediate-shift AVX-512 route",
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_AVX10,
        &decoded_size);
    EXPECT(decoded_size == sizeof(evex));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPSRLD);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512VL));
#else
    expect_error("extra-opcodes OFF immediate-shift feature route",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_apx_b4(void)
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
                 source <= SOURCE_BROADCAST_MEMORY;
                 source = (enum source_form)(source + 1)) {
                enum mask_form mask;

                for (mask = MASK_NONE;
                     mask <= MASK_ZERO;
                     mask = (enum mask_form)(mask + 1)) {
                    const unsigned int vector_bits = 128u << length;
                    const unsigned int element_bits =
                        cases[case_index].w != 0 ? 64u : 32u;
                    uint8_t code[7];

                    make_encoding(&cases[case_index], length,
                        source, mask, UINT8_C(0x13), code);
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
                            EXPECT(instruction.opcode[1].reg
                                == vector_register(2u, vector_bits));
                        } else {
                            EXPECT(instruction.opcode[1].base_reg
                                == CDISASM_X86_REG_R16);
                            EXPECT(instruction.opcode[1].size
                                == (source == SOURCE_BROADCAST_MEMORY
                                    ? element_bits / 8u
                                    : vector_bits / 8u));
                        }
                    }
#else
                    (void)vector_bits;
                    (void)element_bits;
                    expect_error("extra-opcodes OFF APX B4 immediate shift",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
            }
        }
    }
    EXPECT(decoded_cases == APX_B4_U1_CASES);
}

static void test_apx_u0_memory(void)
{
    size_t decoded_cases = 0;
    size_t x4_cases = 0;
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            unsigned int b4;

            for (b4 = 0; b4 != 2; ++b4) {
                enum source_form source;

                for (source = SOURCE_FULL_MEMORY;
                     source <= SOURCE_BROADCAST_MEMORY;
                     source = (enum source_form)(source + 1)) {
                    enum mask_form mask;

                    for (mask = MASK_NONE;
                         mask <= MASK_ZERO;
                         mask = (enum mask_form)(mask + 1)) {
                        const unsigned int vector_bits = 128u << length;
                        const unsigned int element_bits =
                            cases[case_index].w != 0 ? 64u : 32u;
                        uint8_t code[7];

                        make_encoding(&cases[case_index], length,
                            source, mask, UINT8_C(0x13), code);
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
                            EXPECT(instruction.opcode[1].type
                                == CDISASM_OPERAND_MEMORY);
                            EXPECT(instruction.opcode[1].base_reg
                                == (b4 != 0
                                    ? CDISASM_X86_REG_R16
                                    : CDISASM_X86_REG_RAX));
                            EXPECT(instruction.opcode[1].size
                                == (source == SOURCE_BROADCAST_MEMORY
                                    ? element_bits / 8u
                                    : vector_bits / 8u));
                            EXPECT(cdisasm_instruction_has_x86_group(
                                &instruction, CDISASM_X86_GROUP_APX_F));
                        }
#else
                        (void)vector_bits;
                        (void)element_bits;
                        expect_error(
                            "extra-opcodes OFF APX U0 immediate shift",
                            CDISASM_CPU_X86, CDISASM_MODE_64,
                            code, sizeof(code),
                            CDISASM_X86_DECODE_FLAG_BASE,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                        {
                            uint8_t x4_code[8];

                            memcpy(x4_code, code, 6u);
                            x4_code[5] = (uint8_t)(UINT8_C(0x04)
                                | (cases[case_index].extension << 3));
                            x4_code[6] = UINT8_C(0x08);
                            x4_code[7] = UINT8_C(0x13);
                            ++x4_cases;
#if USE_EXTRA_OPCODES
                            {
                                uint32_t decoded_size;
                                cdisasm_instruction instruction = decode(
                                    CDISASM_CPU_APX, CDISASM_MODE_64,
                                    x4_code, sizeof(x4_code),
                                    CDISASM_X86_DECODE_FLAG_AVX10
                                        | CDISASM_X86_DECODE_FLAG_APX,
                                    &decoded_size);

                                EXPECT(decoded_size == sizeof(x4_code));
                                EXPECT(instruction.name_id
                                    == cases[case_index].name_id);
                                EXPECT(instruction.opcode[1].base_reg
                                    == (b4 != 0
                                        ? CDISASM_X86_REG_R16
                                        : CDISASM_X86_REG_RAX));
                                EXPECT(instruction.opcode[1].index_reg
                                    == CDISASM_X86_REG_R17);
                                EXPECT(instruction.opcode[1].size
                                    == (source == SOURCE_BROADCAST_MEMORY
                                        ? element_bits / 8u
                                        : vector_bits / 8u));
                                EXPECT(cdisasm_instruction_has_x86_group(
                                    &instruction,
                                    CDISASM_X86_GROUP_APX_F));
                            }
#else
                            expect_error(
                                "extra-opcodes OFF APX U0/X4 immediate shift",
                                CDISASM_CPU_X86, CDISASM_MODE_64,
                                x4_code, sizeof(x4_code),
                                CDISASM_X86_DECODE_FLAG_BASE,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                        }
                    }
                }
            }
        }
    }
    EXPECT(decoded_cases == APX_U0_NOSIB_CASES);
    EXPECT(x4_cases == APX_U0_X4_SIB_CASES);
    EXPECT(APX_B4_U1_CASES + decoded_cases + x4_cases
        == APX_TOTAL_CASES);
}

static void test_opcode_extension_matrix(void)
{
    size_t allocated_cases = 0;
    size_t reserved_cases = 0;
    size_t truncated_cases = 0;
    unsigned int w;

    for (w = 0; w != 2; ++w) {
        unsigned int extension;

        for (extension = 0; extension != 8; ++extension) {
            const cdisasm_x86_name_id expected_name =
                expected_control_name(w, extension);
            uint8_t code[7] = {
                0x62, 0xf1, w != 0 ? 0xf5 : 0x75,
                0x4a, 0x72,
                (uint8_t)((extension << 3) | 0xc2), 0x13
            };
            char label[96];

            (void)snprintf(label, sizeof(label),
                "opcode-72 W=%u /%u complete", w, extension);
            if (expected_name != CDISASM_X86_NAME_NONE) {
                ++allocated_cases;
#if USE_EXTRA_OPCODES
                {
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                        code, sizeof(code),
                        CDISASM_X86_DECODE_FLAG_AVX512,
                        &decoded_size);

                    EXPECT(decoded_size == sizeof(code));
                    EXPECT(instruction.last_error_id
                        == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id == expected_name);
                }
#else
                expect_error(label, CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            } else {
                ++reserved_cases;
                expect_error(label, CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }

            (void)snprintf(label, sizeof(label),
                "opcode-72 W=%u /%u truncated", w, extension);
            expect_error(label, CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code) - 1u, CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_TRUNCATED);
            ++truncated_cases;
        }
    }
    EXPECT(allocated_cases == 8u);
    EXPECT(reserved_cases == 8u);
    EXPECT(allocated_cases + reserved_cases == OPCODE_CONTROL_CASES);
    EXPECT(truncated_cases == OPCODE_CONTROL_CASES);
}

static void test_reserved_and_truncation_precedence(void)
{
    static const uint8_t ll3[] = {
        0x62, 0xf1, 0x75, 0x6a, 0x72, 0xd2, 0x13
    };
    static const uint8_t register_b[] = {
        0x62, 0xf1, 0x75, 0x5a, 0x72, 0xd2, 0x13
    };
    static const uint8_t zero_without_mask[] = {
        0x62, 0xf1, 0x75, 0xc8, 0x72, 0xd2, 0x13
    };
    static const uint8_t u0_register[] = {
        0x62, 0xf1, 0x71, 0x4a, 0x72, 0xd2, 0x13
    };
    static const uint8_t b4_mode32[] = {
        0x62, 0xf9, 0x75, 0x4a, 0x72, 0xd2, 0x13
    };
    static const uint8_t legacy_prefix[] = {
        0xf0, 0x62, 0xf1, 0x75, 0x4a, 0x72, 0xd2, 0x13
    };
    static const uint8_t truncated_modrm[] = {
        0x62, 0xf1, 0x75, 0x4a, 0x72
    };
    static const uint8_t truncated_disp8[] = {
        0x62, 0xf1, 0x75, 0x4a, 0x72, 0x50
    };
    static const uint8_t truncated_after_disp8[] = {
        0x62, 0xf1, 0x75, 0x4a, 0x72, 0x50, 0x02
    };

    expect_error("reserved immediate shift LL=3",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        ll3, sizeof(ll3), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved immediate shift register EVEX.b",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        register_b, sizeof(register_b), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved immediate shift zero without mask",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        zero_without_mask, sizeof(zero_without_mask),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved immediate shift U0 register",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        u0_register, sizeof(u0_register), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved immediate shift B4 outside mode64",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        b4_mode32, sizeof(b4_mode32), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved immediate shift legacy prefix",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_prefix, sizeof(legacy_prefix),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    expect_error("truncated immediate shift ModRM",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_modrm, sizeof(truncated_modrm),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate shift disp8",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_disp8, sizeof(truncated_disp8),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate shift after disp8",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_after_disp8, sizeof(truncated_after_disp8),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate shift LL3 precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        ll3, sizeof(ll3) - 1u, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate shift register-b precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        register_b, sizeof(register_b) - 1u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate shift zero/mask precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        zero_without_mask, sizeof(zero_without_mask) - 1u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate shift U0 precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        u0_register, sizeof(u0_register) - 1u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate shift B4/mode precedence",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        b4_mode32, sizeof(b4_mode32) - 1u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate shift legacy-prefix precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_prefix, sizeof(legacy_prefix) - 1u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
}

int main(void)
{
    test_canonical_matrix();
    test_compressed_displacement();
    test_feature_routes();
    test_apx_b4();
    test_apx_u0_memory();
    test_opcode_extension_matrix();
    test_reserved_and_truncation_precedence();

    if (failures != 0) {
        fprintf(stderr, "%d x86 immediate-shift test(s) failed\n",
            failures);
        return 1;
    }
    printf("x86 immediate-shift tests passed "
           "(extra=%d, format=%d, canonical=%u, APX=%u, controls=%u)\n",
        USE_EXTRA_OPCODES, USE_DISASM_FORMAT,
        (unsigned int)CANONICAL_WIRE_ENCODINGS,
        (unsigned int)APX_TOTAL_CASES,
        (unsigned int)OPCODE_CONTROL_CASES);
    return 0;
}
