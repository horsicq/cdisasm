#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct logical_case {
    uint8_t opcode;
    uint8_t w;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} logical_case;

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

static const logical_case cases[] = {
    {0xdb, 0, CDISASM_X86_NAME_VPANDD,  "vpandd"},
    {0xdb, 1, CDISASM_X86_NAME_VPANDQ,  "vpandq"},
    {0xdf, 0, CDISASM_X86_NAME_VPANDND, "vpandnd"},
    {0xdf, 1, CDISASM_X86_NAME_VPANDNQ, "vpandnq"},
    {0xeb, 0, CDISASM_X86_NAME_VPORD,   "vpord"},
    {0xeb, 1, CDISASM_X86_NAME_VPORQ,   "vporq"},
    {0xef, 0, CDISASM_X86_NAME_VPXORD,  "vpxord"},
    {0xef, 1, CDISASM_X86_NAME_VPXORQ,  "vpxorq"}
};

_Static_assert(CDISASM_X86_NAME_VPANDD == UINT16_C(1029),
    "EVEX logical catalog start changed");
_Static_assert(CDISASM_X86_NAME_VPXORQ == UINT16_C(1036),
    "EVEX logical catalog end changed");
_Static_assert(CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1),
    "EVEX logical public catalog is incomplete");
_Static_assert(CDISASM_NAME_VPANDD == CDISASM_X86_NAME_VPANDD
        && CDISASM_NAME_VPXORQ == CDISASM_X86_NAME_VPXORQ,
    "legacy EVEX logical aliases changed");

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
    const logical_case *test,
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
    code[1] = UINT8_C(0xf1);
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
    const logical_case *test,
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
            : (vector_bits == 128u ? "xmmword"
                : vector_bits == 256u ? "ymmword" : "zmmword");
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

static void test_complete_classic_matrix(void)
{
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
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

                        make_encoding(&cases[case_index], length,
                            source, mask, code);
#if USE_EXTRA_OPCODES
                        {
                            uint32_t decoded_size;
                            cdisasm_instruction instruction = decode(
                                CDISASM_CPU_SKYLAKE_SP, modes[mode_index],
                                code, sizeof(code),
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
                            EXPECT(instruction.sae == CDISASM_X86_SAE_NONE);
                            EXPECT(cdisasm_instruction_has_x86_group(
                                &instruction,
                                CDISASM_X86_GROUP_AVX512F));
                            EXPECT(cdisasm_instruction_has_x86_group(
                                       &instruction,
                                       CDISASM_X86_GROUP_AVX512VL)
                                == (vector_bits < 512u));
                            EXPECT(!cdisasm_instruction_has_x86_group(
                                &instruction, CDISASM_X86_GROUP_AVX10_1));
                            EXPECT(!cdisasm_instruction_has_x86_group(
                                &instruction, CDISASM_X86_GROUP_APX_F));

                            if (source == SOURCE_REGISTER) {
                                EXPECT(instruction.opcode[2].type
                                    == CDISASM_OPERAND_REGISTER);
                                EXPECT(instruction.opcode[2].reg
                                    == vector_register(3u, vector_bits));
                                EXPECT(instruction.opcode[2].size
                                    == vector_bits / 8u);
                                EXPECT(instruction.opcode[2].broadcast
                                    == CDISASM_X86_BROADCAST_NONE);
                            } else {
                                const unsigned int memory_bits =
                                    source == SOURCE_BROADCAST_MEMORY
                                        ? element_bits : vector_bits;

                                EXPECT(instruction.opcode[2].type
                                    == CDISASM_OPERAND_MEMORY);
                                EXPECT(instruction.opcode[2].size
                                    == memory_bits / 8u);
                                EXPECT(instruction.opcode[2].access
                                    == CDISASM_OPERAND_ACCESS_READ);
                                EXPECT(instruction.opcode[2].base_reg
                                    == (modes[mode_index]
                                            == CDISASM_MODE_16
                                        ? CDISASM_X86_REG_BX
                                        : modes[mode_index]
                                                == CDISASM_MODE_32
                                            ? CDISASM_X86_REG_EAX
                                            : CDISASM_X86_REG_RAX));
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
                            EXPECT(instruction.encoding.prefix_size == 4u);
                            EXPECT(instruction.encoding.opcode_offset == 4u);
                            EXPECT(instruction.encoding.opcode_size == 1u);
                            EXPECT(instruction.encoding.modrm_offset == 5u);
                            EXPECT(instruction.encoding.immediate_count == 0u);
#if USE_DISASM_FORMAT
                            expect_case_format(&instruction,
                                &cases[case_index], modes[mode_index],
                                vector_bits, source, mask);
#endif
                        }
#else
                        (void)vector_bits;
                        (void)element_bits;
                        expect_error("extra-opcodes OFF logical form",
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

static void test_compressed_displacement(void)
{
    static const struct displacement_case {
        uint8_t p1;
        uint8_t p2;
        uint8_t opcode;
        unsigned int expected_bytes;
        uint64_t expected_displacement;
        cdisasm_x86_broadcast expected_broadcast;
    } displacement_cases[] = {
        {0x6d, 0x0a, 0xdb, 16, UINT64_C(0x20),
            CDISASM_X86_BROADCAST_NONE},
        {0xed, 0x2a, 0xdf, 32, UINT64_C(0x40),
            CDISASM_X86_BROADCAST_NONE},
        {0x6d, 0x4a, 0xeb, 64, UINT64_C(0x80),
            CDISASM_X86_BROADCAST_NONE},
        {0x6d, 0x1a, 0xef, 4, UINT64_C(0x08),
            CDISASM_X86_BROADCAST_1_TO_4},
        {0xed, 0x3a, 0xdb, 8, UINT64_C(0x10),
            CDISASM_X86_BROADCAST_1_TO_4},
        {0x6d, 0x5a, 0xdf, 4, UINT64_C(0x08),
            CDISASM_X86_BROADCAST_1_TO_16},
        {0xed, 0x5a, 0xeb, 8, UINT64_C(0x10),
            CDISASM_X86_BROADCAST_1_TO_8}
    };
    size_t index;

    for (index = 0;
         index < sizeof(displacement_cases) / sizeof(displacement_cases[0]);
         ++index) {
        uint8_t code[] = {
            0x62, 0xf1,
            displacement_cases[index].p1,
            displacement_cases[index].p2,
            displacement_cases[index].opcode,
            0x48, 0x02
        };

#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
            &decoded_size);

        EXPECT(decoded_size == sizeof(code));
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.opcode[2].size
            == displacement_cases[index].expected_bytes);
        EXPECT(instruction.opcode[2].imm
            == displacement_cases[index].expected_displacement);
        EXPECT(instruction.opcode[2].broadcast
            == displacement_cases[index].expected_broadcast);
        EXPECT(instruction.encoding.displacement_offset == 6u);
        EXPECT(instruction.encoding.displacement_size == 1u);
#else
        expect_error("extra-opcodes OFF compressed displacement",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_feature_routes(void)
{
    static const uint8_t vpandd[] = {
        0x62, 0xf1, 0x6d, 0x4a, 0xdb, 0xcb
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    expect_error("runtime AVX-512 flag gate",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vpandd, sizeof(vpandd), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("pre-AVX-512 CPU gate",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        vpandd, sizeof(vpandd), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("disabled client AVX-512 gate",
        CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
        vpandd, sizeof(vpandd), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy profile does not use AVX10 runtime route",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vpandd, sizeof(vpandd), CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 profile does not use legacy runtime route",
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        vpandd, sizeof(vpandd), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    instruction = decode(
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        vpandd, sizeof(vpandd), CDISASM_X86_DECODE_FLAG_AVX10,
        &decoded_size);
    EXPECT(decoded_size == sizeof(vpandd));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPANDD);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512VL));
#else
    expect_error("extra-opcodes build gate",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        vpandd, sizeof(vpandd), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_apx_b4_boundary(void)
{
    static const uint8_t register_form[] = {
        0x62, 0xf9, 0x6d, 0x4a, 0xdb, 0xcb
    };
    static const uint8_t memory_form[] = {
        0x62, 0xf9, 0xed, 0x5a, 0xef, 0x08
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_APX, CDISASM_MODE_64,
        register_form, sizeof(register_form),
        CDISASM_X86_DECODE_FLAG_AVX10
            | CDISASM_X86_DECODE_FLAG_APX,
        &decoded_size);

    EXPECT(decoded_size == sizeof(register_form));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPANDD);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_ZMM3);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));

    instruction = decode(
        CDISASM_CPU_APX, CDISASM_MODE_64,
        memory_form, sizeof(memory_form),
        CDISASM_X86_DECODE_FLAG_AVX10
            | CDISASM_X86_DECODE_FLAG_APX,
        &decoded_size);
    EXPECT(decoded_size == sizeof(memory_form));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPXORQ);
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R16);
    EXPECT(instruction.opcode[2].size == 8u);
    EXPECT(instruction.opcode[2].broadcast
        == CDISASM_X86_BROADCAST_1_TO_8);

    expect_error("B4 runtime APX gate",
        CDISASM_CPU_APX, CDISASM_MODE_64,
        register_form, sizeof(register_form),
        CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("B4 CPU APX gate",
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        register_form, sizeof(register_form),
        CDISASM_X86_DECODE_FLAG_AVX10
            | CDISASM_X86_DECODE_FLAG_APX,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("B4 requires long mode",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        register_form, sizeof(register_form),
        CDISASM_X86_DECODE_FLAG_ALL,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(
        CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        register_form, sizeof(register_form),
        CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_APX,
        &decoded_size);
    EXPECT(decoded_size == sizeof(register_form));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
#else
    expect_error("extra-opcodes OFF B4 register form",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        register_form, sizeof(register_form),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("extra-opcodes OFF B4 memory form",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        memory_form, sizeof(memory_form),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_and_truncated(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        unsigned int length;
        uint8_t ll3[6];

        make_encoding(&cases[case_index], 0u,
            SOURCE_REGISTER, MASK_MERGE, ll3);
        ll3[3] = UINT8_C(0x6a);
        expect_error("reserved LL=3",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            ll3, sizeof(ll3), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        for (length = 0; length != 3; ++length) {
            uint8_t register_b[6];
            uint8_t reserved_u[6];
            uint8_t zero_without_mask[6];

            make_encoding(&cases[case_index], length,
                SOURCE_REGISTER, MASK_NONE, register_b);
            memcpy(reserved_u, register_b, sizeof(reserved_u));
            memcpy(zero_without_mask,
                register_b, sizeof(zero_without_mask));
            register_b[3] |= UINT8_C(0x10);
            reserved_u[2] &= UINT8_C(0xfb);
            zero_without_mask[3] |= UINT8_C(0x80);

            expect_error("register source with EVEX.b",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                register_b, sizeof(register_b),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("reserved EVEX U bit",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                reserved_u, sizeof(reserved_u),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("zeroing without mask",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                zero_without_mask, sizeof(zero_without_mask),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    {
        static const uint8_t unowned_prefix[] = {
            0x62, 0xf1, 0x6c, 0x4a, 0xdb, 0xcb
        };
        static const uint8_t truncated_modrm[] = {
            0x62, 0xf1, 0x6d, 0x4a, 0xdb
        };
        static const uint8_t truncated_disp8[] = {
            0x62, 0xf1, 0x6d, 0x4a, 0xdb, 0x48
        };

        expect_error("unowned mandatory-prefix sibling",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            unowned_prefix, sizeof(unowned_prefix),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("truncated register form",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            truncated_modrm, sizeof(truncated_modrm),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_TRUNCATED);
        expect_error("truncated compressed displacement",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            truncated_disp8, sizeof(truncated_disp8),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_TRUNCATED);
    }
}

int main(void)
{
    test_complete_classic_matrix();
    test_compressed_displacement();
    test_feature_routes();
    test_apx_b4_boundary();
    test_reserved_and_truncated();

    if (failures != 0) {
        fprintf(stderr,
            "x86 EVEX packed-integer logical tests failed: %d "
            "(extra=%d, format=%d)\n",
            failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("x86 EVEX packed-integer logical tests passed "
           "(extra=%d, format=%d)\n",
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
