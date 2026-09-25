#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct compare_case {
    uint8_t opcode;
    uint8_t w;
    uint8_t element_bits;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_group_id feature_group;
    const char *mnemonic;
} compare_case;

static const compare_case cases[] = {
    {0x3f, 0,  8, CDISASM_X86_NAME_VPCMPB,
        CDISASM_X86_GROUP_AVX512BW, "vpcmpb"},
    {0x3f, 1, 16, CDISASM_X86_NAME_VPCMPW,
        CDISASM_X86_GROUP_AVX512BW, "vpcmpw"},
    {0x1f, 0, 32, CDISASM_X86_NAME_VPCMPD,
        CDISASM_X86_GROUP_AVX512F, "vpcmpd"},
    {0x1f, 1, 64, CDISASM_X86_NAME_VPCMPQ,
        CDISASM_X86_GROUP_AVX512F, "vpcmpq"},
    {0x3e, 0,  8, CDISASM_X86_NAME_VPCMPUB,
        CDISASM_X86_GROUP_AVX512BW, "vpcmpub"},
    {0x3e, 1, 16, CDISASM_X86_NAME_VPCMPUW,
        CDISASM_X86_GROUP_AVX512BW, "vpcmpuw"},
    {0x1e, 0, 32, CDISASM_X86_NAME_VPCMPUD,
        CDISASM_X86_GROUP_AVX512F, "vpcmpud"},
    {0x1e, 1, 64, CDISASM_X86_NAME_VPCMPUQ,
        CDISASM_X86_GROUP_AVX512F, "vpcmpuq"}
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

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id vector_register(unsigned int index, unsigned int bits)
{
    if (bits == 128) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + index);
    }
    if (bits == 256) {
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
    char buffer[160];
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

static void test_register_matrix(void)
{
    size_t index;

    EXPECT(sizeof(cases) / sizeof(cases[0]) == 8u);
    EXPECT(CDISASM_X86_NAME_VPCMPB == UINT16_C(994));
    EXPECT(CDISASM_X86_NAME_VPCMPUQ == UINT16_C(1001));
    EXPECT(CDISASM_X86_NAME_VPMAXUQ == UINT16_C(1013));
    EXPECT(CDISASM_X86_NAME_VPMADDUBSW == UINT16_C(1020));
    EXPECT(CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1));

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        unsigned int length;
        const compare_case *test = &cases[index];

        for (length = 0; length != 3; ++length) {
            const unsigned int vector_bits = 128u << length;
            const unsigned int mask_bits = vector_bits / test->element_bits;
            uint8_t code[] = {
                0x62, 0xf3, (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                (uint8_t)(0x0au | (length << 5)),
                test->opcode, 0xcb, 0x04
            };

#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                &decoded_size);

            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id == test->name_id);
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0);
            EXPECT(instruction.operand_count == 4u);
            EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_K1);
            EXPECT(instruction.opcode[0].size == (mask_bits + 7u) / 8u);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.opcode[1].reg
                == vector_register(2u, vector_bits));
            EXPECT(instruction.opcode[2].reg
                == vector_register(3u, vector_bits));
            EXPECT(instruction.opcode[1].size == vector_bits / 8u);
            EXPECT(instruction.opcode[2].size == vector_bits / 8u);
            EXPECT(instruction.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
            EXPECT(instruction.opcode[3].size == 1u);
            EXPECT(instruction.opcode[3].imm == UINT64_C(4));
            EXPECT(instruction.opcode[3].access
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
                == (test->feature_group == CDISASM_X86_GROUP_AVX512BW));
            EXPECT(instruction.encoding.prefix_size == 4u);
            EXPECT(instruction.encoding.opcode_offset == 4u);
            EXPECT(instruction.encoding.opcode_size == 1u);
            EXPECT(instruction.encoding.modrm_offset == 5u);
            EXPECT(instruction.encoding.immediate_count == 1u);
            EXPECT(instruction.encoding.immediate_offset[0] == 6u);

#if USE_DISASM_FORMAT
            {
                const char *reg = length == 0 ? "xmm"
                    : length == 1 ? "ymm" : "zmm";
                char intel[128];
                char att[128];

                snprintf(intel, sizeof(intel),
                    "%s k1 {k2}, %s2, %s3, 0x4",
                    test->mnemonic, reg, reg);
                snprintf(att, sizeof(att),
                    "%s $0x4, %%%s3, %%%s2, %%k1{%%k2}",
                    test->mnemonic, reg, reg);
                expect_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_X86_INTEL, intel);
                expect_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_X86_ATT, att);
            }
#endif
#else
            (void)mask_bits;
            expect_error("extra-opcodes OFF register form",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

            expect_error("truncated compare immediate",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code) - 1u, CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_TRUNCATED);
        }
    }
}

static void test_memory_forms(void)
{
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const compare_case *test = &cases[index];
        const int broadcast = test->element_bits >= 32u;
        uint8_t code[] = {
            0x62, 0xf3, (uint8_t)(test->w != 0 ? 0xed : 0x6d),
            (uint8_t)(broadcast ? 0x5a : 0x4a),
            test->opcode, 0x48, 0x02, 0x04
        };

#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
            &decoded_size);

        EXPECT(decoded_size == sizeof(code));
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(instruction.operand_count == 4u);
        EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_NONE);
        EXPECT(instruction.opcode[2].size
            == (broadcast ? test->element_bits / 8u : 64u));
        EXPECT(instruction.opcode[2].imm
            == (broadcast ? test->element_bits / 4u : 128u));
        EXPECT(instruction.opcode[2].broadcast
            == (broadcast
                ? (cdisasm_x86_broadcast)(512u / test->element_bits)
                : CDISASM_X86_BROADCAST_NONE));
        EXPECT(instruction.encoding.displacement_offset == 6u);
        EXPECT(instruction.encoding.displacement_size == 1u);
        EXPECT(instruction.encoding.immediate_offset[0] == 7u);
#else
        expect_error("extra-opcodes OFF memory form",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_feature_gates(void)
{
    static const uint8_t vpcmpd[] = {
        0x62, 0xf3, 0x6d, 0x4a, 0x1f, 0xcb, 0x04
    };

#if USE_EXTRA_OPCODES
    expect_error("runtime AVX-512 flag gate",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vpcmpd, sizeof(vpcmpd), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("pre-AVX-512 CPU gate",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        vpcmpd, sizeof(vpcmpd), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    expect_error("extra-opcodes build gate",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        vpcmpd, sizeof(vpcmpd), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_avx10_alternate_route(void)
{
    static const uint8_t vpcmpb[] = {
        0x62, 0xf3, 0x6d, 0x4a, 0x3f, 0xcb, 0x04
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        vpcmpb, sizeof(vpcmpb), CDISASM_X86_DECODE_FLAG_AVX10,
        &decoded_size);

    EXPECT(decoded_size == sizeof(vpcmpb));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPCMPB);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512BW));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512VL));

    expect_error("AVX10 route is not a legacy AVX-512 route",
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        vpcmpb, sizeof(vpcmpb), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("Skylake-SP requires the legacy AVX-512 flag",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vpcmpb, sizeof(vpcmpb), CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    expect_error("extra-opcodes OFF AVX10 compare route",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        vpcmpb, sizeof(vpcmpb), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_encodings(void)
{
    static const struct invalid_case {
        const char *label;
        uint8_t bytes[8];
        uint8_t size;
    } invalid[] = {
        {"extended K destination R-prime",
            {0x62, 0x73, 0x6d, 0x4a, 0x1f, 0xcb, 0x04}, 7},
        {"extended K destination R",
            {0x62, 0xe3, 0x6d, 0x4a, 0x1f, 0xcb, 0x04}, 7},
        {"compare-to-mask zeroing",
            {0x62, 0xf3, 0x6d, 0xca, 0x1f, 0xcb, 0x04}, 7},
        {"compare-to-mask zeroing with aaa zero",
            {0x62, 0xf3, 0x6d, 0xc8, 0x1f, 0xcb, 0x04}, 7},
        {"reserved LL=3",
            {0x62, 0xf3, 0x6d, 0x6a, 0x1f, 0xcb, 0x04}, 7},
        {"register source with EVEX.b",
            {0x62, 0xf3, 0x6d, 0x5a, 0x1f, 0xcb, 0x04}, 7},
        {"byte compare memory with EVEX.b",
            {0x62, 0xf3, 0x6d, 0x5a, 0x3f, 0x08, 0x04}, 7},
        {"reserved EVEX U bit",
            {0x62, 0xf3, 0x69, 0x4a, 0x1f, 0xcb, 0x04}, 7},
        {"legacy operand-size prefix before EVEX",
            {0x66, 0x62, 0xf3, 0x6d, 0x4a, 0x1f, 0xcb, 0x04}, 8}
    };
    size_t index;

    for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error(invalid[index].label,
            CDISASM_CPU_X86, CDISASM_MODE_64,
            invalid[index].bytes, invalid[index].size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_extended_sources(void)
{
    static const uint8_t source_v_prime[] = {
        0x62, 0xf3, 0x6d, 0x42, 0x1f, 0xcb, 0x04
    };
    static const uint8_t rm_b_prime[] = {
        0x62, 0xb3, 0x6d, 0x4a, 0x1f, 0xcb, 0x04
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        source_v_prime, sizeof(source_v_prime),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);

    EXPECT(decoded_size == sizeof(source_v_prime));
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ZMM18);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_ZMM3);

    instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        rm_b_prime, sizeof(rm_b_prime),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
    EXPECT(decoded_size == sizeof(rm_b_prime));
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ZMM2);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_ZMM19);
#else
    expect_error("extra-opcodes OFF V-prime source",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        source_v_prime, sizeof(source_v_prime),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("extra-opcodes OFF B-prime source",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        rm_b_prime, sizeof(rm_b_prime),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_legacy_32bit_mode(void)
{
    static const uint8_t low_registers[] = {
        0x62, 0xf3, 0x6d, 0x0a, 0x1f, 0xcb, 0x04
    };
    static const uint8_t extended_source[] = {
        0x62, 0xf3, 0x6d, 0x02, 0x1f, 0xcb, 0x04
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_32,
        low_registers, sizeof(low_registers),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);

    EXPECT(decoded_size == sizeof(low_registers));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPCMPD);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_K1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM2);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM3);
#else
    expect_error("extra-opcodes OFF 32-bit compare",
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
}

int main(void)
{
    test_register_matrix();
    test_memory_forms();
    test_feature_gates();
    test_avx10_alternate_route();
    test_reserved_encodings();
    test_extended_sources();
    test_legacy_32bit_mode();

    if (failures != 0) {
        fprintf(stderr,
            "x86 EVEX compare-to-mask tests failed: %d "
            "(extra=%d, format=%d)\n",
            failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("x86 EVEX compare-to-mask tests passed "
           "(extra=%d, format=%d)\n",
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
