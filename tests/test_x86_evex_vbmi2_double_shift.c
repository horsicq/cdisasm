#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct double_shift_case {
    uint8_t map;
    uint8_t opcode;
    uint8_t w;
    uint8_t element_bits;
    uint8_t immediate;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} double_shift_case;

static const double_shift_case cases[] = {
    {3, 0x70, 1, 16, 1, CDISASM_X86_NAME_VPSHLDW, "vpshldw"},
    {3, 0x71, 0, 32, 1, CDISASM_X86_NAME_VPSHLDD, "vpshldd"},
    {3, 0x71, 1, 64, 1, CDISASM_X86_NAME_VPSHLDQ, "vpshldq"},
    {2, 0x70, 1, 16, 0, CDISASM_X86_NAME_VPSHLDVW, "vpshldvw"},
    {2, 0x71, 0, 32, 0, CDISASM_X86_NAME_VPSHLDVD, "vpshldvd"},
    {2, 0x71, 1, 64, 0, CDISASM_X86_NAME_VPSHLDVQ, "vpshldvq"},
    {3, 0x72, 1, 16, 1, CDISASM_X86_NAME_VPSHRDW, "vpshrdw"},
    {3, 0x73, 0, 32, 1, CDISASM_X86_NAME_VPSHRDD, "vpshrdd"},
    {3, 0x73, 1, 64, 1, CDISASM_X86_NAME_VPSHRDQ, "vpshrdq"},
    {2, 0x72, 1, 16, 0, CDISASM_X86_NAME_VPSHRDVW, "vpshrdvw"},
    {2, 0x73, 0, 32, 0, CDISASM_X86_NAME_VPSHRDVD, "vpshrdvd"},
    {2, 0x73, 1, 64, 0, CDISASM_X86_NAME_VPSHRDVQ, "vpshrdvq"}
};

_Static_assert(CDISASM_X86_NAME_VPSHLDW == UINT16_C(1065),
    "VBMI2 double-shift catalog start changed");
_Static_assert(CDISASM_X86_NAME_VPSHRDVQ == UINT16_C(1076),
    "VBMI2 double-shift catalog end changed");
_Static_assert(CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1),
    "VBMI2 double-shift public catalog is incomplete");
_Static_assert(CDISASM_NAME_VPSHLDW == CDISASM_X86_NAME_VPSHLDW
        && CDISASM_NAME_VPSHRDVQ == CDISASM_X86_NAME_VPSHRDVQ,
    "legacy VBMI2 double-shift aliases changed");

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
    const uint8_t *code,
    size_t size,
    cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu, mode, code, size, UINT64_C(0x1000), flags, &instruction);
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

static void expect_status(
    const char *label,
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *code,
    size_t size,
    cdisasm_x86_decode_option flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu, mode, code, size, flags, &decoded_size);

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
#endif

static const double_shift_case *find_case(
    uint8_t map,
    uint8_t opcode,
    uint8_t w)
{
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        if (cases[index].map == map
            && cases[index].opcode == opcode
            && cases[index].w == w) {
            return &cases[index];
        }
    }
    return NULL;
}

static size_t make_encoding(
    const double_shift_case *test,
    unsigned int length,
    int memory,
    int broadcast,
    int mask_mode,
    uint8_t immediate,
    uint8_t code[8])
{
    uint8_t p2 = (uint8_t)(UINT8_C(0x08) | (length << 5));
    size_t size = 6u;

    if (broadcast) {
        p2 |= UINT8_C(0x10);
    }
    if (mask_mode != 0) {
        p2 |= UINT8_C(0x02);
    }
    if (mask_mode == 2) {
        p2 |= UINT8_C(0x80);
    }
    code[0] = UINT8_C(0x62);
    code[1] = (uint8_t)(UINT8_C(0xf0) | test->map);
    code[2] = test->w != 0 ? UINT8_C(0xed) : UINT8_C(0x6d);
    code[3] = p2;
    code[4] = test->opcode;
    code[5] = memory ? UINT8_C(0x4b) : UINT8_C(0xcb);
    if (memory) {
        code[size++] = UINT8_C(2);
    }
    if (test->immediate) {
        code[size++] = immediate;
    }
    return size;
}

#if USE_EXTRA_OPCODES
static void expect_success_shape(
    const double_shift_case *test,
    const cdisasm_instruction *instruction,
    unsigned int vector_bits)
{
    const cdisasm_operand_access destination_access = test->immediate
        ? CDISASM_OPERAND_ACCESS_WRITE
        : CDISASM_OPERAND_ACCESS_READ_WRITE;

    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == test->name_id);
    EXPECT(instruction->operand_count == (test->immediate ? 4u : 3u));
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg == vector_register(1u, vector_bits));
    EXPECT(instruction->opcode[0].size == vector_bits / 8u);
    EXPECT(instruction->opcode[0].access == destination_access);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg == vector_register(2u, vector_bits));
    EXPECT(instruction->opcode[1].size == vector_bits / 8u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0);
    if (test->immediate) {
        EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
        EXPECT(instruction->opcode[3].size == 1u);
        EXPECT(instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ);
    }
}
#endif

static void test_all_names_and_lengths(void)
{
    size_t case_index;
    unsigned int decoded_cases = 0;

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        const double_shift_case *test = &cases[case_index];
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            uint8_t code[8];
            size_t size = make_encoding(
                test, length, 0, 0, 0, UINT8_C(0x13), code);

            ++decoded_cases;
#if USE_EXTRA_OPCODES
            {
                const unsigned int vector_bits = 128u << length;
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
                    code, size, CDISASM_X86_DECODE_FLAG_AVX512,
                    &decoded_size);

                if (decoded_size != size) {
                    fprintf(stderr,
                        "%s LL=%u failed: status=%u size=%u\n",
                        test->mnemonic, length,
                        (unsigned int)instruction.last_error_id,
                        (unsigned int)decoded_size);
                }
                EXPECT(decoded_size == size);
                expect_success_shape(test, &instruction, vector_bits);
                EXPECT(instruction.opcode[2].type
                    == CDISASM_OPERAND_REGISTER);
                EXPECT(instruction.opcode[2].reg
                    == vector_register(3u, vector_bits));
                EXPECT(instruction.opcode[2].size == vector_bits / 8u);
                if (test->immediate) {
                    EXPECT(instruction.opcode[3].imm == UINT64_C(0x13));
                }
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512F));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512VBMI2));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512VL)
                    == (length != 2));
            }
#else
            if (length == 0u) {
                expect_status("extra-opcodes OFF legal VBMI2 double shift",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, size, CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            }
#endif
        }
    }
    EXPECT(decoded_cases == 36u);
}

static void test_control_and_immediate_matrix(void)
{
    unsigned int map;
    unsigned int legal_controls = 0;
    unsigned int reserved_controls = 0;

    for (map = 2; map != 4; ++map) {
        unsigned int opcode;

        for (opcode = 0x70; opcode != 0x74; ++opcode) {
            unsigned int w;

            for (w = 0; w != 2; ++w) {
                const double_shift_case *test = find_case(
                    (uint8_t)map, (uint8_t)opcode, (uint8_t)w);
                const double_shift_case reserved = {
                    (uint8_t)map, (uint8_t)opcode, (uint8_t)w,
                    16, (uint8_t)(map == 3), CDISASM_X86_NAME_NONE, NULL
                };
                uint8_t code[8];
                size_t size = make_encoding(test != NULL ? test : &reserved,
                    2, 0, 0, 0, 0, code);

                if (test == NULL) {
                    ++reserved_controls;
                    expect_status("reserved VBMI2 double-shift W control",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, size, CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_INVALID_INSTRUCTION);
                    expect_status("truncated reserved VBMI2 control",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, size - 1u, CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_TRUNCATED);
                    continue;
                }
                ++legal_controls;
                if (test->immediate) {
                    unsigned int immediate;

                    for (immediate = 0; immediate != 256u; ++immediate) {
                        code[size - 1u] = (uint8_t)immediate;
#if USE_EXTRA_OPCODES
                        {
                            uint32_t decoded_size;
                            cdisasm_instruction instruction = decode(
                                CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
                                code, size,
                                CDISASM_X86_DECODE_FLAG_AVX512,
                                &decoded_size);

                            EXPECT(decoded_size == size);
                            EXPECT(instruction.name_id == test->name_id);
                            EXPECT(instruction.opcode[3].imm == immediate);
                        }
#else
                        if (immediate == 0u) {
                            expect_status(
                                "extra-opcodes OFF VBMI2 imm8 ownership",
                                CDISASM_CPU_X86, CDISASM_MODE_64,
                                code, size, CDISASM_X86_DECODE_FLAG_BASE,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
                        }
#endif
                    }
                }
            }
        }
    }
    EXPECT(legal_controls == 12u);
    EXPECT(reserved_controls == 4u);
}

static void test_memory_broadcast_masks_and_disp8(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        const double_shift_case *test = &cases[case_index];
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            const unsigned int vector_bits = 128u << length;
            uint8_t code[8];
            size_t size = make_encoding(
                test, length, 1, 0, 2, UINT8_C(0xa5), code);

#if USE_EXTRA_OPCODES
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
                    code, size, CDISASM_X86_DECODE_FLAG_AVX512,
                    &decoded_size);

                EXPECT(decoded_size == size);
                expect_success_shape(test, &instruction, vector_bits);
                EXPECT(instruction.mask_reg == CDISASM_X86_REG_K2);
                EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
                EXPECT(instruction.opcode[0].access
                    == (test->immediate
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ_WRITE));
                EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[2].base_reg
                    == CDISASM_X86_REG_RBX);
                EXPECT(instruction.opcode[2].size == vector_bits / 8u);
                EXPECT(instruction.opcode[2].imm
                    == UINT64_C(2) * (vector_bits / 8u));
                EXPECT(instruction.opcode[2].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
            }
#else
            (void)vector_bits;
            if (length == 0u) {
                expect_status("extra-opcodes OFF VBMI2 full memory",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, size, CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            }
#endif

            size = make_encoding(
                test, length, 1, 1, 1, UINT8_C(0x5a), code);
            if (test->element_bits == 16u) {
                expect_status("word VBMI2 broadcast reserved",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, size, CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            } else {
#if USE_EXTRA_OPCODES
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
                    code, size, CDISASM_X86_DECODE_FLAG_AVX512,
                    &decoded_size);

                EXPECT(decoded_size == size);
                EXPECT(instruction.name_id == test->name_id);
                EXPECT(instruction.mask_mode == CDISASM_X86_MASK_MERGE);
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
                EXPECT(instruction.opcode[2].size
                    == test->element_bits / 8u);
                EXPECT(instruction.opcode[2].imm
                    == UINT64_C(2) * (test->element_bits / 8u));
                EXPECT(instruction.opcode[2].broadcast
                    == (cdisasm_x86_broadcast)(
                        vector_bits / test->element_bits));
#else
                if (length == 0u) {
                    expect_status("extra-opcodes OFF VBMI2 broadcast",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, size, CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
                }
#endif
            }
        }
    }
}

static void test_reserved_decorators_and_namespace(void)
{
    const double_shift_case *test = &cases[1];
    uint8_t code[8];
    size_t size = make_encoding(
        test, 2, 0, 1, 0, UINT8_C(0x13), code);

    expect_status("VBMI2 register EVEX.b reserved",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    size = make_encoding(test, 2, 0, 0, 0, UINT8_C(0x13), code);
    code[3] |= UINT8_C(0x80);
    expect_status("VBMI2 zeroing without mask reserved",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    size = make_encoding(test, 2, 0, 0, 0, UINT8_C(0x13), code);
    code[3] = (uint8_t)((code[3] & UINT8_C(0x9f)) | UINT8_C(0x60));
    expect_status("VBMI2 LL=3 reserved",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    size = make_encoding(test, 2, 0, 0, 0, UINT8_C(0x13), code);
    code[2] &= UINT8_C(0xfc);
    expect_status("non-66 VBMI2 namespace is unowned",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
}

static void test_deferred_legality_and_truncation(void)
{
    static const uint8_t prefixed_immediate_missing_imm[] = {
        0x66, 0x62, 0xf3, 0xed, 0x48, 0x70, 0xcb
    };
    static const uint8_t prefixed_immediate_complete[] = {
        0x66, 0x62, 0xf3, 0xed, 0x48, 0x70, 0xcb, 0x13
    };
    static const uint8_t prefixed_variable_missing_modrm[] = {
        0x66, 0x62, 0xf2, 0xed, 0x48, 0x70
    };
    static const uint8_t prefixed_variable_complete[] = {
        0x66, 0x62, 0xf2, 0xed, 0x48, 0x70, 0xcb
    };
    static const uint8_t mode32_b4_immediate_missing_imm[] = {
        0x62, 0xfb, 0xed, 0x48, 0x70, 0xcb
    };
    static const uint8_t mode32_b4_immediate_complete[] = {
        0x62, 0xfb, 0xed, 0x48, 0x70, 0xcb, 0x13
    };
    static const uint8_t mode32_b4_variable_missing_modrm[] = {
        0x62, 0xfa, 0xed, 0x48, 0x70
    };
    static const uint8_t mode32_b4_variable_complete[] = {
        0x62, 0xfa, 0xed, 0x48, 0x70, 0xcb
    };

    expect_status("prefixed immediate VBMI2 missing imm8",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        prefixed_immediate_missing_imm,
        sizeof(prefixed_immediate_missing_imm),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_status("prefixed immediate VBMI2 complete",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        prefixed_immediate_complete, sizeof(prefixed_immediate_complete),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("prefixed variable VBMI2 missing ModRM",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        prefixed_variable_missing_modrm,
        sizeof(prefixed_variable_missing_modrm),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_status("prefixed variable VBMI2 complete",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        prefixed_variable_complete, sizeof(prefixed_variable_complete),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_INVALID_INSTRUCTION);

    expect_status("32-bit B4 immediate VBMI2 missing imm8",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        mode32_b4_immediate_missing_imm,
        sizeof(mode32_b4_immediate_missing_imm),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_status("32-bit B4 immediate VBMI2 complete",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        mode32_b4_immediate_complete, sizeof(mode32_b4_immediate_complete),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("32-bit B4 variable VBMI2 missing ModRM",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        mode32_b4_variable_missing_modrm,
        sizeof(mode32_b4_variable_missing_modrm),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_status("32-bit B4 variable VBMI2 complete",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        mode32_b4_variable_complete, sizeof(mode32_b4_variable_complete),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_feature_and_runtime_routes(void)
{
    const double_shift_case *test = &cases[11];
    uint8_t code[8];
    size_t size = make_encoding(
        test, 2, 0, 0, 0, UINT8_C(0), code);

#if USE_EXTRA_OPCODES
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_AVX10, CDISASM_MODE_64,
            code, size, CDISASM_X86_DECODE_FLAG_AVX10,
            &decoded_size);

        EXPECT(decoded_size == size);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPSHRDVQ);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512F));
    }
    expect_status("VBMI2 runtime AVX512 gate",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("VBMI2 CPU feature gate",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    expect_status("extra-opcodes OFF VBMI2 feature route",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

typedef struct apx_case {
    uint8_t code[8];
    uint8_t size;
    uint8_t immediate;
    cdisasm_x86_reg_id base;
    cdisasm_x86_reg_id index;
} apx_case;

static void test_diamond_rapids_apx_oracle(void)
{
    static const apx_case accepted[] = {
        {{0x62, 0xfa, 0x2d, 0x48, 0x71, 0xcb, 0, 0}, 6, 0,
            CDISASM_X86_REG_NONE, CDISASM_X86_REG_NONE},
        {{0x62, 0xfa, 0x2d, 0x48, 0x71, 0x0b, 0, 0}, 6, 0,
            CDISASM_X86_REG_R19, CDISASM_X86_REG_NONE},
        {{0x62, 0xf2, 0x29, 0x48, 0x71, 0x0c, 0x03, 0}, 7, 0,
            CDISASM_X86_REG_RBX, CDISASM_X86_REG_R16},
        {{0x62, 0xfa, 0x29, 0x48, 0x71, 0x0c, 0x03, 0}, 7, 0,
            CDISASM_X86_REG_R19, CDISASM_X86_REG_R16},
        {{0x62, 0xfb, 0x2d, 0x48, 0x71, 0xcb, 0x13, 0}, 7, 1,
            CDISASM_X86_REG_NONE, CDISASM_X86_REG_NONE},
        {{0x62, 0xf3, 0x29, 0x48, 0x71, 0x0c, 0x03, 0x13}, 8, 1,
            CDISASM_X86_REG_RBX, CDISASM_X86_REG_R16}
    };
    static const uint8_t u0_register[] = {
        0x62, 0xf2, 0x29, 0x48, 0x71, 0xcb
    };
    size_t index;

    for (index = 0; index < sizeof(accepted) / sizeof(accepted[0]); ++index) {
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_APX, CDISASM_MODE_64,
            accepted[index].code, accepted[index].size,
            CDISASM_X86_DECODE_FLAG_AVX10 | CDISASM_X86_DECODE_FLAG_APX,
            &decoded_size);

        EXPECT(decoded_size == accepted[index].size);
        EXPECT(instruction.name_id == (accepted[index].immediate
            ? CDISASM_X86_NAME_VPSHLDD
            : CDISASM_X86_NAME_VPSHLDVD));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        if (accepted[index].base == CDISASM_X86_REG_NONE) {
            EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_REGISTER);
            EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_ZMM3);
        } else {
            EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
            EXPECT(instruction.opcode[2].base_reg == accepted[index].base);
            EXPECT(instruction.opcode[2].index_reg == accepted[index].index);
        }
#else
        if (index == 0u) {
            expect_status("extra-opcodes OFF APX VBMI2 route",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                accepted[index].code, accepted[index].size,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
#endif
    }

    expect_status("VBMI2 U0 register reserved",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        u0_register, sizeof(u0_register), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("VBMI2 B4 non-long-mode reserved",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        accepted[0].code, accepted[0].size,
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#if USE_EXTRA_OPCODES
    expect_status("VBMI2 B4 requires APX CPU feature",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        accepted[0].code, accepted[0].size,
        CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
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

static void test_formatting(void)
{
    static const uint8_t variable[] = {
        0x62, 0xf2, 0xed, 0x4a, 0x73, 0xcb
    };
    static const uint8_t immediate[] = {
        0x62, 0xf3, 0x6d, 0xca, 0x71, 0xcb, 0x13
    };
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        variable, sizeof(variable), CDISASM_X86_DECODE_FLAG_AVX512,
        &decoded_size);

    EXPECT(decoded_size == sizeof(variable));
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpshrdvq zmm1 {k2}, zmm2, zmm3");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpshrdvq %zmm3, %zmm2, %zmm1{%k2}");

    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        immediate, sizeof(immediate), CDISASM_X86_DECODE_FLAG_AVX512,
        &decoded_size);
    EXPECT(decoded_size == sizeof(immediate));
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpshldd zmm1 {k2}{z}, zmm2, zmm3, 0x13");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpshldd $0x13, %zmm3, %zmm2, %zmm1{%k2}{z}");
}
#endif

int main(void)
{
    test_all_names_and_lengths();
    test_control_and_immediate_matrix();
    test_memory_broadcast_masks_and_disp8();
    test_reserved_decorators_and_namespace();
    test_deferred_legality_and_truncation();
    test_feature_and_runtime_routes();
    test_diamond_rapids_apx_oracle();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d VBMI2 double-shift test(s) failed\n", failures);
        return 1;
    }
    puts("x86 EVEX VBMI2 double-shift tests passed");
    return 0;
}
