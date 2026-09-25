#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct rotate_case {
    uint8_t extension;
    uint8_t w;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} rotate_case;

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
    APX_B4_U1_CASES = 108,
    APX_U0_NOSIB_CASES = 144,
    APX_U0_X4_SIB_CASES = 144,
    APX_TOTAL_CASES = 396,
    RESERVED_CASES = 432,
    ADJACENT_CONTROL_CASES = 16
};

static const rotate_case cases[] = {
    {1, 0, CDISASM_X86_NAME_VPROLD, "vprold"},
    {1, 1, CDISASM_X86_NAME_VPROLQ, "vprolq"},
    {0, 0, CDISASM_X86_NAME_VPRORD, "vprord"},
    {0, 1, CDISASM_X86_NAME_VPRORQ, "vprorq"}
};

_Static_assert(CANONICAL_WIRE_ENCODINGS == 82944,
    "immediate-rotate canonical matrix changed");
_Static_assert(APX_B4_U1_CASES + APX_U0_NOSIB_CASES
        + APX_U0_X4_SIB_CASES == APX_TOTAL_CASES,
    "APX immediate-rotate matrix changed");
_Static_assert(ADJACENT_CONTROL_CASES == 2 * 8,
    "opcode-72 W-by-extension matrix changed");
_Static_assert(CDISASM_X86_NAME_VPROLD == UINT16_C(1050),
    "immediate-rotate catalog start changed");
_Static_assert(CDISASM_X86_NAME_VPRORQ == UINT16_C(1053),
    "immediate-rotate catalog end changed");
_Static_assert(CDISASM_X86_NAME_VPSLLDQ == UINT16_C(1064),
    "version-11.12 terminal x86 name ID changed");
_Static_assert(CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1),
    "immediate-rotate catalog count changed");
_Static_assert(CDISASM_NAME_VPROLD == CDISASM_X86_NAME_VPROLD
        && CDISASM_NAME_VPROLQ == CDISASM_X86_NAME_VPROLQ
        && CDISASM_NAME_VPRORD == CDISASM_X86_NAME_VPRORD
        && CDISASM_NAME_VPRORQ == CDISASM_X86_NAME_VPRORQ,
    "legacy immediate-rotate aliases changed");

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
    const rotate_case *test,
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
    const rotate_case *test,
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
        snprintf(intel, sizeof(intel), "%s %s1%s, %s2, 0x13",
            test->mnemonic, reg, intel_mask, reg);
        snprintf(att, sizeof(att), "%s $0x13, %%%s2, %%%s1%s",
            test->mnemonic, reg, reg, att_mask);
    } else {
        const unsigned int element_bits = test->w != 0 ? 64u : 32u;
        const char *memory_type = source == SOURCE_BROADCAST_MEMORY
            ? (test->w != 0 ? "qword" : "dword")
            : vector_bits == 128u ? "xmmword"
            : vector_bits == 256u ? "ymmword" : "zmmword";
        char broadcast[16] = "";

        if (source == SOURCE_BROADCAST_MEMORY) {
            snprintf(broadcast, sizeof(broadcast), "{1to%u}",
                vector_bits / element_bits);
        }
        snprintf(intel, sizeof(intel), "%s %s1%s, %s ptr [%s]%s, 0x13",
            test->mnemonic, reg, intel_mask,
            memory_type, intel_address, broadcast);
        snprintf(att, sizeof(att), "%s $0x13, %s%s, %%%s1%s",
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
                                "extra-opcodes OFF EVEX immediate rotate",
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
                expect_error("extra-opcodes OFF immediate rotate disp8",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            }
        }
    }
    EXPECT(decoded_cases == 24u);
}

static void test_feature_routes(void)
{
    static const uint8_t evex[] = {
        0x62, 0xf1, 0x75, 0x4a, 0x72, 0xca, 0x13
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    expect_error("immediate-rotate runtime AVX-512 gate",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("immediate-rotate CPU AVX-512 gate",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy profile rejects immediate rotate AVX10 route",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 profile rejects immediate rotate AVX-512 route",
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_AVX10,
        &decoded_size);
    EXPECT(decoded_size == sizeof(evex));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPROLD);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512VL));
#else
    expect_error("extra-opcodes OFF immediate rotate feature route",
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
                        EXPECT(instruction.opcode[2].imm
                            == UINT64_C(0x13));
                    }
#else
                    (void)vector_bits;
                    (void)element_bits;
                    expect_error("extra-opcodes OFF APX B4 immediate rotate",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
            }
        }
    }
    EXPECT(decoded_cases == APX_B4_U1_CASES);

    {
        static const uint8_t apx_register[] = {
            0x62, 0xf9, 0x75, 0x4a, 0x72, 0xca, 0x13
        };
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        expect_error("APX immediate-rotate runtime gate",
            CDISASM_CPU_APX, CDISASM_MODE_64,
            apx_register, sizeof(apx_register),
            CDISASM_X86_DECODE_FLAG_AVX10,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("APX immediate-rotate CPU gate",
            CDISASM_CPU_AVX10, CDISASM_MODE_64,
            apx_register, sizeof(apx_register),
            CDISASM_X86_DECODE_FLAG_AVX10
                | CDISASM_X86_DECODE_FLAG_APX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("APX immediate-rotate mode gate",
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
            &instruction, CDISASM_X86_GROUP_APX_F));
#else
        expect_error("extra-opcodes OFF APX immediate-rotate gate",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            apx_register, sizeof(apx_register),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
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
                        expect_error("extra-opcodes OFF APX U0 immediate rotate",
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
                                EXPECT(instruction.opcode[1].broadcast
                                    == (source == SOURCE_BROADCAST_MEMORY
                                        ? (cdisasm_x86_broadcast)(
                                            vector_bits / element_bits)
                                        : CDISASM_X86_BROADCAST_NONE));
                                EXPECT(cdisasm_instruction_has_x86_group(
                                    &instruction,
                                    CDISASM_X86_GROUP_APX_F));
                            }
#else
                            expect_error(
                                "extra-opcodes OFF APX U0/X4 immediate rotate",
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

    {
        static const uint8_t u0_memory[] = {
            0x62, 0xf1, 0x71, 0x0a, 0x72, 0x08, 0x13
        };
        static const uint8_t u0_register[] = {
            0x62, 0xf1, 0x71, 0x0a, 0x72, 0xca, 0x13
        };

        expect_error("APX immediate rotate U0 register reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            u0_register, sizeof(u0_register),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("APX immediate rotate U0 unavailable outside mode64",
            CDISASM_CPU_X86, CDISASM_MODE_32,
            u0_memory, sizeof(u0_memory),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
#if USE_EXTRA_OPCODES
        expect_error("APX immediate rotate U0 runtime gate",
            CDISASM_CPU_APX, CDISASM_MODE_64,
            u0_memory, sizeof(u0_memory),
            CDISASM_X86_DECODE_FLAG_AVX10,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("APX immediate rotate U0 CPU gate",
            CDISASM_CPU_AVX10, CDISASM_MODE_64,
            u0_memory, sizeof(u0_memory),
            CDISASM_X86_DECODE_FLAG_AVX10
                | CDISASM_X86_DECODE_FLAG_APX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
    }
}

static void test_reserved_matrix(void)
{
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t reserved_cases = 0;
    size_t mode_index;
    size_t case_index;

    for (mode_index = 0;
         mode_index < sizeof(modes) / sizeof(modes[0]);
         ++mode_index) {
        for (case_index = 0;
             case_index < sizeof(cases) / sizeof(cases[0]);
             ++case_index) {
            enum source_form source;

            for (source = SOURCE_REGISTER;
                 source <= SOURCE_BROADCAST_MEMORY;
                 source = (enum source_form)(source + 1)) {
                enum mask_form mask;

                for (mask = MASK_NONE;
                     mask <= MASK_ZERO;
                     mask = (enum mask_form)(mask + 1)) {
                    uint8_t code[7];

                    make_encoding(&cases[case_index], 0,
                        source, mask, UINT8_C(0x13), code);
                    code[3] = (uint8_t)((code[3] & UINT8_C(0x9f))
                        | UINT8_C(0x60));
                    expect_error("reserved immediate rotate LL=3",
                        CDISASM_CPU_X86, modes[mode_index],
                        code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_INVALID_INSTRUCTION);
                    ++reserved_cases;
                }
            }

            {
                unsigned int length;

                for (length = 0; length != 3; ++length) {
                    enum mask_form mask;

                    for (mask = MASK_NONE;
                         mask <= MASK_ZERO;
                         mask = (enum mask_form)(mask + 1)) {
                        uint8_t register_b[7];
                        uint8_t u0_register[7];

                        make_encoding(&cases[case_index], length,
                            SOURCE_REGISTER, mask,
                            UINT8_C(0x13), register_b);
                        memcpy(u0_register, register_b,
                            sizeof(u0_register));
                        register_b[3] |= UINT8_C(0x10);
                        u0_register[2] &= UINT8_C(0xfb);
                        expect_error(
                            "reserved immediate rotate register EVEX.b",
                            CDISASM_CPU_X86, modes[mode_index],
                            register_b, sizeof(register_b),
                            CDISASM_X86_DECODE_FLAG_BASE,
                            CDISASM_STATUS_INVALID_INSTRUCTION);
                        expect_error(
                            "reserved immediate rotate U0 register",
                            CDISASM_CPU_X86, modes[mode_index],
                            u0_register, sizeof(u0_register),
                            CDISASM_X86_DECODE_FLAG_BASE,
                            CDISASM_STATUS_INVALID_INSTRUCTION);
                        reserved_cases += 2u;
                    }

                    for (source = SOURCE_REGISTER;
                         source <= SOURCE_BROADCAST_MEMORY;
                         source = (enum source_form)(source + 1)) {
                        uint8_t zero_without_mask[7];

                        make_encoding(&cases[case_index], length,
                            source, MASK_NONE,
                            UINT8_C(0x13), zero_without_mask);
                        zero_without_mask[3] |= UINT8_C(0x80);
                        expect_error(
                            "reserved immediate rotate zero without mask",
                            CDISASM_CPU_X86, modes[mode_index],
                            zero_without_mask,
                            sizeof(zero_without_mask),
                            CDISASM_X86_DECODE_FLAG_BASE,
                            CDISASM_STATUS_INVALID_INSTRUCTION);
                        ++reserved_cases;
                    }
                }
            }
        }
    }
    EXPECT(reserved_cases == RESERVED_CASES);
}

static void test_opcode_extension_matrix(void)
{
    size_t complete_cases = 0;
    size_t truncated_cases = 0;
    unsigned int w;

    for (w = 0; w != 2; ++w) {
        unsigned int extension;

        for (extension = 0; extension != 8; ++extension) {
            uint8_t code[7] = {
                0x62, 0xf1, w != 0 ? 0xf5 : 0x75,
                0x4a, 0x72, (uint8_t)((extension << 3) | 0xc2), 0x13
            };
            char label[96];

            snprintf(label, sizeof(label),
                "opcode-72 W=%u /%u complete", w, extension);
            ++complete_cases;
            if (extension <= 1u) {
#if USE_EXTRA_OPCODES
                const cdisasm_x86_name_id expected_name = extension != 0
                    ? (w != 0 ? CDISASM_X86_NAME_VPROLQ
                              : CDISASM_X86_NAME_VPROLD)
                    : (w != 0 ? CDISASM_X86_NAME_VPRORQ
                              : CDISASM_X86_NAME_VPRORD);
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                    code, sizeof(code),
                    CDISASM_X86_DECODE_FLAG_AVX512,
                    &decoded_size);

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == expected_name);
#else
                expect_error(label, CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            } else {
                const int allocated_neighbor = extension == 4u
                    || (w == 0 && (extension == 2u || extension == 6u));

                expect_error(label, CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    allocated_neighbor
                        ? CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
                        : CDISASM_STATUS_INVALID_INSTRUCTION);
            }

            snprintf(label, sizeof(label),
                "opcode-72 W=%u /%u truncated", w, extension);
            expect_error(label, CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code) - 1u, CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_TRUNCATED);
            ++truncated_cases;
        }
    }
    EXPECT(complete_cases == ADJACENT_CONTROL_CASES);
    EXPECT(truncated_cases == ADJACENT_CONTROL_CASES);
}

static void test_collisions_and_truncation(void)
{
    static const uint8_t unowned_pp[] = {
        0x62, 0xf1, 0x74, 0x4a, 0x72, 0xca, 0x13
    };
    static const uint8_t adjacent_opcode[] = {
        0x62, 0xf1, 0x75, 0x4a, 0x73, 0xca, 0x13
    };
    static const uint8_t truncated_modrm[] = {
        0x62, 0xf1, 0x75, 0x4a, 0x72
    };
    static const uint8_t truncated_immediate[] = {
        0x62, 0xf1, 0x75, 0x4a, 0x72, 0xca
    };
    static const uint8_t truncated_ll3[] = {
        0x62, 0xf1, 0x75, 0x6a, 0x72, 0xca
    };
    static const uint8_t truncated_reserved_b[] = {
        0x62, 0xf1, 0x75, 0x5a, 0x72, 0xca
    };
    static const uint8_t truncated_zero_without_mask[] = {
        0x62, 0xf1, 0x75, 0xc8, 0x72, 0xca
    };
    static const uint8_t truncated_u0[] = {
        0x62, 0xf1, 0x71, 0x4a, 0x72, 0xca
    };
    static const uint8_t truncated_b4_mode32[] = {
        0x62, 0xf9, 0x75, 0x4a, 0x72, 0xca
    };
    static const uint8_t truncated_legacy_prefix[] = {
        0xf0, 0x62, 0xf1, 0x75, 0x4a, 0x72, 0xca
    };
    static const uint8_t truncated_disp8[] = {
        0x62, 0xf1, 0x75, 0x4a, 0x72, 0x48
    };
    static const uint8_t truncated_after_disp8[] = {
        0x62, 0xf1, 0x75, 0x4a, 0x72, 0x48, 0x02
    };

    expect_error("unowned immediate rotate mandatory prefix",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        unowned_pp, sizeof(unowned_pp), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("reserved adjacent immediate shift opcode control",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        adjacent_opcode, sizeof(adjacent_opcode),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("truncated immediate rotate ModRM",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_modrm, sizeof(truncated_modrm),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate rotate imm8",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_immediate, sizeof(truncated_immediate),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate rotate LL3 precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_ll3, sizeof(truncated_ll3),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate rotate register-b precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_reserved_b, sizeof(truncated_reserved_b),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate rotate z-without-mask precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_zero_without_mask,
        sizeof(truncated_zero_without_mask),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate rotate U0-register precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_u0, sizeof(truncated_u0),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate rotate B4 mode precedence",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        truncated_b4_mode32, sizeof(truncated_b4_mode32),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate rotate legacy-prefix precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_legacy_prefix, sizeof(truncated_legacy_prefix),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate rotate disp8",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_disp8, sizeof(truncated_disp8),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated immediate rotate after disp8",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_after_disp8, sizeof(truncated_after_disp8),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);
}

int main(void)
{
    test_canonical_matrix();
    test_compressed_displacement();
    test_feature_routes();
    test_apx_b4();
    test_apx_u0_memory();
    test_reserved_matrix();
    test_opcode_extension_matrix();
    test_collisions_and_truncation();

    if (failures != 0) {
        fprintf(stderr, "%d x86 immediate-rotate test(s) failed\n",
            failures);
        return 1;
    }
    printf("x86 immediate-rotate tests passed "
           "(extra=%d, format=%d, canonical=%u, APX=%u, reserved=%u, "
           "adjacent=%u)\n",
        USE_EXTRA_OPCODES, USE_DISASM_FORMAT,
        (unsigned int)CANONICAL_WIRE_ENCODINGS,
        (unsigned int)APX_TOTAL_CASES,
        (unsigned int)RESERVED_CASES,
        (unsigned int)ADJACENT_CONTROL_CASES);
    return 0;
}
