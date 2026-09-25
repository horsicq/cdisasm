#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct shift_case {
    uint8_t opcode;
    uint8_t w;
    uint8_t has_vex;
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

static const shift_case cases[] = {
    {0x47, 0, 1, CDISASM_X86_NAME_VPSLLVD, "vpsllvd"},
    {0x47, 1, 1, CDISASM_X86_NAME_VPSLLVQ, "vpsllvq"},
    {0x45, 0, 1, CDISASM_X86_NAME_VPSRLVD, "vpsrlvd"},
    {0x45, 1, 1, CDISASM_X86_NAME_VPSRLVQ, "vpsrlvq"},
    {0x46, 0, 1, CDISASM_X86_NAME_VPSRAVD, "vpsravd"},
    {0x46, 1, 0, CDISASM_X86_NAME_VPSRAVQ, "vpsravq"}
};

_Static_assert(CDISASM_X86_NAME_VPSLLVD == UINT16_C(1037),
    "variable-shift catalog start changed");
_Static_assert(CDISASM_X86_NAME_VPSRAVQ == UINT16_C(1042),
    "variable-shift catalog end changed");
_Static_assert(CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1),
    "variable-shift public catalog is incomplete");
_Static_assert(CDISASM_NAME_VPSLLVD == CDISASM_X86_NAME_VPSLLVD
        && CDISASM_NAME_VPSRAVQ == CDISASM_X86_NAME_VPSRAVQ,
    "legacy variable-shift aliases changed");

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

static void make_vex_encoding(
    const shift_case *test,
    unsigned int length,
    enum source_form source,
    uint8_t code[5])
{
    code[0] = UINT8_C(0xc4);
    code[1] = UINT8_C(0xe2);
    code[2] = (uint8_t)(UINT8_C(0x69)
        | (test->w != 0 ? UINT8_C(0x80) : 0u)
        | (length != 0 ? UINT8_C(0x04) : 0u));
    code[3] = test->opcode;
    code[4] = source == SOURCE_REGISTER
        ? UINT8_C(0xcb) : UINT8_C(0x08);
}

static void make_evex_encoding(
    const shift_case *test,
    unsigned int length,
    enum source_form source,
    enum mask_form mask,
    uint8_t code[6])
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
    code[1] = UINT8_C(0xf2);
    code[2] = test->w != 0 ? UINT8_C(0xed) : UINT8_C(0x6d);
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
        snprintf(intel, sizeof(intel), "%s %s1%s, %s2, %s3",
            test->mnemonic, reg, intel_mask, reg, reg);
        snprintf(att, sizeof(att), "%s %%%s3, %%%s2, %%%s1%s",
            test->mnemonic, reg, reg, reg, att_mask);
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
        snprintf(intel, sizeof(intel), "%s %s1%s, %s2, %s ptr [%s]%s",
            test->mnemonic, reg, intel_mask, reg,
            memory_type, intel_address, broadcast);
        snprintf(att, sizeof(att), "%s %s%s, %%%s2, %%%s1%s",
            test->mnemonic, att_address, broadcast,
            reg, reg, att_mask);
    }
    expect_format(instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL, intel);
    expect_format(instruction, CDISASM_FORMAT_SYNTAX_X86_ATT, att);
}
#endif
#endif

static void test_vex_matrix(void)
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

            if (!cases[case_index].has_vex) {
                continue;
            }
            for (length = 0; length != 2; ++length) {
                enum source_form source;

                for (source = SOURCE_REGISTER;
                     source <= SOURCE_FULL_MEMORY;
                     source = (enum source_form)(source + 1)) {
                    const unsigned int vector_bits = 128u << length;
                    uint8_t code[5];

                    make_vex_encoding(
                        &cases[case_index], length, source, code);
                    ++decoded_cases;
#if USE_EXTRA_OPCODES
                    {
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_HASWELL, modes[mode_index],
                            code, sizeof(code),
                            CDISASM_X86_DECODE_FLAG_AVX2,
                            &decoded_size);

                        EXPECT(decoded_size == sizeof(code));
                        EXPECT(instruction.last_error_id
                            == CDISASM_STATUS_OK);
                        EXPECT(instruction.name_id
                            == cases[case_index].name_id);
                        EXPECT((instruction.opcode_flags
                            & CDISASM_PREFIX_VEX) != 0);
                        EXPECT(instruction.operand_count == 3u);
                        EXPECT(instruction.opcode[0].reg
                            == vector_register(1u, vector_bits));
                        EXPECT(instruction.opcode[1].reg
                            == vector_register(2u, vector_bits));
                        EXPECT(instruction.opcode[0].access
                            == CDISASM_OPERAND_ACCESS_WRITE);
                        EXPECT(instruction.opcode[1].access
                            == CDISASM_OPERAND_ACCESS_READ);
                        EXPECT(instruction.opcode[0].size
                            == vector_bits / 8u);
                        EXPECT(instruction.opcode[1].size
                            == vector_bits / 8u);
                        EXPECT(cdisasm_instruction_has_x86_group(
                            &instruction, CDISASM_X86_GROUP_AVX));
                        EXPECT(cdisasm_instruction_has_x86_group(
                            &instruction, CDISASM_X86_GROUP_AVX2));
                        EXPECT(instruction.mask_reg
                            == CDISASM_X86_REG_NONE);
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
                                == (modes[mode_index] == CDISASM_MODE_16
                                    ? CDISASM_X86_REG_SI
                                    : CDISASM_X86_REG_NONE));
                        }
                        EXPECT(instruction.opcode[2].size
                            == vector_bits / 8u);
                        EXPECT(instruction.opcode[2].access
                            == CDISASM_OPERAND_ACCESS_READ);
                        EXPECT(instruction.encoding.prefix_size == 3u);
                        EXPECT(instruction.encoding.opcode_offset == 3u);
                        EXPECT(instruction.encoding.modrm_offset == 4u);
#if USE_DISASM_FORMAT
                        expect_case_format(&instruction,
                            &cases[case_index], modes[mode_index],
                            vector_bits, source, MASK_NONE);
#endif
                    }
#else
                    (void)vector_bits;
                    expect_error("extra-opcodes OFF VEX variable shift",
                        CDISASM_CPU_X86, modes[mode_index],
                        code, sizeof(code),
                        CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
            }
        }
    }
    EXPECT(decoded_cases == 60u);
}

static void test_evex_matrix(void)
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
                        const unsigned int vector_bits = 128u << length;
                        const unsigned int element_bits =
                            cases[case_index].w != 0 ? 64u : 32u;
                        uint8_t code[6];

                        make_evex_encoding(&cases[case_index], length,
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
                            EXPECT((instruction.opcode_flags
                                & CDISASM_PREFIX_EVEX) != 0);
                            EXPECT(instruction.operand_count == 3u);
                            EXPECT(instruction.opcode[0].reg
                                == vector_register(1u, vector_bits));
                            EXPECT(instruction.opcode[1].reg
                                == vector_register(2u, vector_bits));
                            EXPECT(instruction.opcode[0].size
                                == vector_bits / 8u);
                            EXPECT(instruction.opcode[1].size
                                == vector_bits / 8u);
                            EXPECT(instruction.opcode[0].access
                                == (mask == MASK_MERGE
                                    ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                    : CDISASM_OPERAND_ACCESS_WRITE));
                            EXPECT(instruction.opcode[1].access
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
                            EXPECT(instruction.rounding
                                == CDISASM_X86_ROUNDING_NONE);
                            EXPECT(instruction.sae
                                == CDISASM_X86_SAE_NONE);
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
                                EXPECT(instruction.opcode[2].type
                                    == CDISASM_OPERAND_REGISTER);
                                EXPECT(instruction.opcode[2].reg
                                    == vector_register(3u, vector_bits));
                                EXPECT(instruction.opcode[2].size
                                    == vector_bits / 8u);
                            } else {
                                const unsigned int memory_bits =
                                    source == SOURCE_BROADCAST_MEMORY
                                        ? element_bits : vector_bits;

                                EXPECT(instruction.opcode[2].type
                                    == CDISASM_OPERAND_MEMORY);
                                EXPECT(instruction.opcode[2].size
                                    == memory_bits / 8u);
                                EXPECT(instruction.opcode[2].base_reg
                                    == expected_base(modes[mode_index]));
                                EXPECT(instruction.opcode[2].index_reg
                                    == (modes[mode_index]
                                            == CDISASM_MODE_16
                                        ? CDISASM_X86_REG_SI
                                        : CDISASM_X86_REG_NONE));
                                EXPECT(instruction.opcode[2].broadcast
                                    == (source
                                            == SOURCE_BROADCAST_MEMORY
                                        ? (cdisasm_x86_broadcast)(
                                            vector_bits / element_bits)
                                        : CDISASM_X86_BROADCAST_NONE));
                            }
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
                        (void)element_bits;
                        expect_error("extra-opcodes OFF EVEX variable shift",
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
    EXPECT(decoded_cases == 486u);
}

static void test_compressed_displacement(void)
{
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
                uint8_t code[] = {
                    0x62, 0xf2,
                    cases[case_index].w != 0 ? 0xed : 0x6d,
                    (uint8_t)(0x0a + (length << 5)
                        + (source == SOURCE_BROADCAST_MEMORY ? 0x10 : 0)),
                    cases[case_index].opcode, 0x48, 0x02
                };
#if USE_EXTRA_OPCODES
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                    &decoded_size);

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.name_id == cases[case_index].name_id);
                EXPECT(instruction.opcode[2].size == memory_bits / 8u);
                EXPECT(instruction.opcode[2].imm == memory_bits / 4u);
                EXPECT(instruction.encoding.displacement_offset == 6u);
                EXPECT(instruction.encoding.displacement_size == 1u);
#else
                (void)memory_bits;
                expect_error("extra-opcodes OFF variable-shift disp8",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            }
        }
    }
}

static void test_feature_routes(void)
{
    static const uint8_t vex[] = {
        0xc4, 0xe2, 0x69, 0x47, 0xcb
    };
    static const uint8_t evex[] = {
        0x62, 0xf2, 0x6d, 0x4a, 0x47, 0xcb
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    expect_error("VEX variable-shift runtime AVX2 gate",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        vex, sizeof(vex), CDISASM_X86_DECODE_FLAG_AVX,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VEX variable-shift CPU AVX2 gate",
        CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
        vex, sizeof(vex), CDISASM_X86_DECODE_FLAG_AVX2,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("EVEX variable-shift runtime AVX-512 gate",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("EVEX variable-shift CPU AVX-512 gate",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy profile rejects AVX10 route",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 profile rejects AVX-512 route",
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        evex, sizeof(evex), CDISASM_X86_DECODE_FLAG_AVX10,
        &decoded_size);
    EXPECT(decoded_size == sizeof(evex));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPSLLVD);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512VL));
#else
    expect_error("extra-opcodes OFF VEX feature route",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        vex, sizeof(vex), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("extra-opcodes OFF EVEX feature route",
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
                    uint8_t code[6];

                    make_evex_encoding(&cases[case_index], length,
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
                        EXPECT(instruction.mask_mode
                            == (mask == MASK_NONE
                                ? CDISASM_X86_MASK_NONE
                                : mask == MASK_MERGE
                                    ? CDISASM_X86_MASK_MERGE
                                    : CDISASM_X86_MASK_ZERO));
                        if (source == SOURCE_REGISTER) {
                            EXPECT(instruction.opcode[2].reg
                                == vector_register(3u, vector_bits));
                        } else {
                            EXPECT(instruction.opcode[2].base_reg
                                == CDISASM_X86_REG_R16);
                            EXPECT(instruction.opcode[2].index_reg
                                == CDISASM_X86_REG_NONE);
                            EXPECT(instruction.opcode[2].size
                                == (source == SOURCE_BROADCAST_MEMORY
                                    ? element_bits / 8u
                                    : vector_bits / 8u));
                        }
                    }
#else
                    (void)vector_bits;
                    (void)element_bits;
                    expect_error("extra-opcodes OFF APX variable shift",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
            }
        }
    }
    EXPECT(decoded_cases == 162u);

    {
        static const uint8_t apx_register[] = {
            0x62, 0xfa, 0x6d, 0x4a, 0x47, 0xcb
        };
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        expect_error("APX variable-shift runtime gate",
            CDISASM_CPU_APX, CDISASM_MODE_64,
            apx_register, sizeof(apx_register),
            CDISASM_X86_DECODE_FLAG_AVX10,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("APX variable-shift CPU gate",
            CDISASM_CPU_AVX10, CDISASM_MODE_64,
            apx_register, sizeof(apx_register),
            CDISASM_X86_DECODE_FLAG_AVX10
                | CDISASM_X86_DECODE_FLAG_APX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("APX variable-shift mode gate",
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
        expect_error("extra-opcodes OFF APX gate control",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            apx_register, sizeof(apx_register),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_apx_u0_memory(void)
{
    static const struct apx_address_case {
        uint8_t p0;
        uint8_t keep_u;
        cdisasm_x86_reg_id base;
        cdisasm_x86_reg_id index;
        const char *intel_address;
        const char *att_address;
    } addresses[] = {
        {0xf2, 0, CDISASM_X86_REG_RAX, CDISASM_X86_REG_NONE,
            "rax", "(%rax)"},
        {0xf2, 0, CDISASM_X86_REG_RAX, CDISASM_X86_REG_R17,
            "rax + r17", "(%rax,%r17)"},
        {0xfa, 0, CDISASM_X86_REG_R16, CDISASM_X86_REG_R17,
            "r16 + r17", "(%r16,%r17)"},
        {0xfa, 1, CDISASM_X86_REG_R16, CDISASM_X86_REG_RCX,
            "r16 + rcx", "(%r16,%rcx)"}
    };
    size_t decoded_cases = 0;
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
                        uint8_t code[6];

                        make_evex_encoding(&cases[case_index], length,
                            source, mask, code);
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
                            EXPECT(instruction.last_error_id
                                == CDISASM_STATUS_OK);
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
                                == (source == SOURCE_BROADCAST_MEMORY
                                    ? element_bits / 8u
                                    : vector_bits / 8u));
                            EXPECT(instruction.opcode[2].broadcast
                                == (source == SOURCE_BROADCAST_MEMORY
                                    ? (cdisasm_x86_broadcast)(
                                        vector_bits / element_bits)
                                    : CDISASM_X86_BROADCAST_NONE));
                            EXPECT(cdisasm_instruction_has_x86_group(
                                &instruction, CDISASM_X86_GROUP_APX_F));
                        }
#else
                        (void)vector_bits;
                        (void)element_bits;
                        expect_error(
                            "extra-opcodes OFF APX U0 exhaustive shift",
                            CDISASM_CPU_X86, CDISASM_MODE_64,
                            code, sizeof(code),
                            CDISASM_X86_DECODE_FLAG_BASE,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                    }
                }
            }
        }
    }
    EXPECT(decoded_cases == 216u);

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        size_t address_index;

        for (address_index = 0;
             address_index < sizeof(addresses) / sizeof(addresses[0]);
             ++address_index) {
            uint8_t code[] = {
                0x62, addresses[address_index].p0,
                cases[case_index].w != 0 ? 0xed : 0x6d,
                0x0a, cases[case_index].opcode,
                address_index == 0 ? 0x08 : 0x0c, 0x08
            };
            size_t code_size = address_index == 0 ? 6u : 7u;

            if (!addresses[address_index].keep_u) {
                code[2] &= UINT8_C(0xfb);
            }
#if USE_EXTRA_OPCODES
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_APX, CDISASM_MODE_64,
                    code, code_size,
                    CDISASM_X86_DECODE_FLAG_AVX10
                        | CDISASM_X86_DECODE_FLAG_APX,
                    &decoded_size);

                EXPECT(decoded_size == code_size);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == cases[case_index].name_id);
                EXPECT(instruction.operand_count == 3u);
                EXPECT(instruction.opcode[2].type
                    == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[2].base_reg
                    == addresses[address_index].base);
                EXPECT(instruction.opcode[2].index_reg
                    == addresses[address_index].index);
                EXPECT(instruction.opcode[2].size == 16u);
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX10_1));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_APX_F));
#if USE_DISASM_FORMAT
                {
                    char intel[192];
                    char att[192];

                    snprintf(intel, sizeof(intel),
                        "%s xmm1 {k2}, xmm2, xmmword ptr [%s]",
                        cases[case_index].mnemonic,
                        addresses[address_index].intel_address);
                    snprintf(att, sizeof(att),
                        "%s %s, %%xmm2, %%xmm1{%%k2}",
                        cases[case_index].mnemonic,
                        addresses[address_index].att_address);
                    expect_format(&instruction,
                        CDISASM_FORMAT_SYNTAX_X86_INTEL, intel);
                    expect_format(&instruction,
                        CDISASM_FORMAT_SYNTAX_X86_ATT, att);
                }
#endif
            }
#else
            expect_error("extra-opcodes OFF APX U0 variable shift",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, code_size, CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }

    {
        static const uint8_t u0_memory[] = {
            0x62, 0xf2, 0x69, 0x0a, 0x47, 0x08
        };
        static const uint8_t u0_register[] = {
            0x62, 0xf2, 0x69, 0x0a, 0x47, 0xcb
        };

        expect_error("APX U0 register stays reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            u0_register, sizeof(u0_register),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("APX U0 is unavailable outside 64-bit mode",
            CDISASM_CPU_X86, CDISASM_MODE_32,
            u0_memory, sizeof(u0_memory),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
#if USE_EXTRA_OPCODES
        expect_error("APX U0 runtime gate",
            CDISASM_CPU_APX, CDISASM_MODE_64,
            u0_memory, sizeof(u0_memory),
            CDISASM_X86_DECODE_FLAG_AVX10,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("APX U0 CPU gate",
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

static void test_reserved_collisions_and_truncation(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            uint8_t ll3[6];
            uint8_t register_b[6];
            uint8_t reserved_u[6];
            uint8_t zero_without_mask[6];

            make_evex_encoding(&cases[case_index], length,
                SOURCE_REGISTER, MASK_MERGE, ll3);
            memcpy(register_b, ll3, sizeof(register_b));
            memcpy(reserved_u, ll3, sizeof(reserved_u));
            make_evex_encoding(&cases[case_index], length,
                SOURCE_REGISTER, MASK_NONE, zero_without_mask);
            ll3[3] = UINT8_C(0x6a);
            register_b[3] |= UINT8_C(0x10);
            reserved_u[2] &= UINT8_C(0xfb);
            zero_without_mask[3] |= UINT8_C(0x80);

            expect_error("reserved EVEX variable-shift LL=3",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                ll3, sizeof(ll3), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("reserved EVEX variable-shift register b",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                register_b, sizeof(register_b),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("reserved EVEX variable-shift U bit",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                reserved_u, sizeof(reserved_u),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("EVEX variable-shift zeroing without mask",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                zero_without_mask, sizeof(zero_without_mask),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    {
        static const uint8_t vex_ravq_register[] = {
            0xc4, 0xe2, 0xe9, 0x46, 0xcb
        };
        static const uint8_t vex_ravq_memory[] = {
            0xc4, 0xe2, 0xed, 0x46, 0x08
        };
        static const uint8_t vex_bad_pp[] = {
            0xc4, 0xe2, 0x68, 0x47, 0xcb
        };
        static const uint8_t vex2_kxor_collision[] = {
            0xc5, 0xed, 0x47, 0xcb
        };
        static const uint8_t evex_unowned_pp[] = {
            0x62, 0xf2, 0x6c, 0x4a, 0x47, 0xcb
        };
        static const uint8_t vex_truncated[] = {
            0xc4, 0xe2, 0x69, 0x47
        };
        static const uint8_t evex_truncated[] = {
            0x62, 0xf2, 0x6d, 0x4a, 0x47
        };
        static const uint8_t evex_truncated_disp8[] = {
            0x62, 0xf2, 0x6d, 0x4a, 0x47, 0x48
        };

        expect_error("VEX VPSRAVQ register is reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_ravq_register, sizeof(vex_ravq_register),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("VEX VPSRAVQ memory is reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_ravq_memory, sizeof(vex_ravq_memory),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("VEX variable-shift pp is reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_bad_pp, sizeof(vex_bad_pp),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("EVEX variable-shift unowned pp",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_unowned_pp, sizeof(evex_unowned_pp),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("truncated VEX variable shift",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_truncated, sizeof(vex_truncated),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_TRUNCATED);
        expect_error("truncated EVEX variable shift",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_truncated, sizeof(evex_truncated),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_TRUNCATED);
        expect_error("truncated EVEX variable-shift disp8",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_truncated_disp8, sizeof(evex_truncated_disp8),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_TRUNCATED);

#if USE_EXTRA_OPCODES
        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                vex2_kxor_collision, sizeof(vex2_kxor_collision),
                CDISASM_X86_DECODE_FLAG_AVX512,
                &decoded_size);

            EXPECT(decoded_size == sizeof(vex2_kxor_collision));
            EXPECT(instruction.name_id == CDISASM_X86_NAME_KXORB);
            EXPECT(instruction.name_id != CDISASM_X86_NAME_VPSLLVD);
        }
#else
        expect_error("extra-opcodes OFF VEX2 collision",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            vex2_kxor_collision, sizeof(vex2_kxor_collision),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

int main(void)
{
    test_vex_matrix();
    test_evex_matrix();
    test_compressed_displacement();
    test_feature_routes();
    test_apx_b4();
    test_apx_u0_memory();
    test_reserved_collisions_and_truncation();

    if (failures != 0) {
        fprintf(stderr, "%d x86 variable-shift test(s) failed\n", failures);
        return 1;
    }
    printf("x86 variable-shift tests passed (extra=%d, format=%d)\n",
        USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
