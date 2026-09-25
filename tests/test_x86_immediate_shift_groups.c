#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct immediate_group_case {
    uint8_t opcode;
    uint8_t extension;
    uint8_t w;
    uint8_t broadcast;
    uint8_t mask;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_group_id group;
} immediate_group_case;

static const immediate_group_case allocated[] = {
    {0x71, 2, 2, 0, 1, CDISASM_X86_NAME_VPSRLW, CDISASM_X86_GROUP_AVX512BW},
    {0x71, 4, 2, 0, 1, CDISASM_X86_NAME_VPSRAW, CDISASM_X86_GROUP_AVX512BW},
    {0x71, 6, 2, 0, 1, CDISASM_X86_NAME_VPSLLW, CDISASM_X86_GROUP_AVX512BW},
    {0x73, 2, 1, 1, 1, CDISASM_X86_NAME_VPSRLQ, CDISASM_X86_GROUP_AVX512F},
    {0x73, 3, 2, 0, 0, CDISASM_X86_NAME_VPSRLDQ, CDISASM_X86_GROUP_AVX512BW},
    {0x73, 6, 1, 1, 1, CDISASM_X86_NAME_VPSLLQ, CDISASM_X86_GROUP_AVX512F},
    {0x73, 7, 2, 0, 0, CDISASM_X86_NAME_VPSLLDQ, CDISASM_X86_GROUP_AVX512BW}
};

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",            \
                __FILE__, __LINE__, #expression);                           \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

static cdisasm_instruction decode(cdisasm_cpu_id cpu,
    const uint8_t *code, size_t size, cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(cpu, CDISASM_MODE_64, code, size,
        UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static void expect_status(const char *label, cdisasm_cpu_id cpu,
    const uint8_t *code, size_t size, cdisasm_x86_decode_option flags,
    cdisasm_status expected)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(cpu, code, size, flags,
        &decoded_size);

    if (decoded_size != 0 || instruction.last_error_id != expected) {
        fprintf(stderr, "%s: decoded=%u status=%u expected=%u\n", label,
            (unsigned int)decoded_size, (unsigned int)instruction.last_error_id,
            (unsigned int)expected);
    }
    EXPECT(decoded_size == 0);
    EXPECT(instruction.last_error_id == expected);
}

static const immediate_group_case *find_case(uint8_t opcode, uint8_t w,
    uint8_t extension)
{
    size_t index;

    for (index = 0; index < sizeof(allocated) / sizeof(allocated[0]);
         ++index) {
        if (allocated[index].opcode == opcode
            && (allocated[index].w == 2 || allocated[index].w == w)
            && allocated[index].extension == extension) {
            return &allocated[index];
        }
    }
    return NULL;
}

static void make_encoding(uint8_t opcode, uint8_t w, uint8_t extension,
    uint8_t p2_extra, uint8_t modrm_low, uint8_t immediate, uint8_t code[7])
{
    code[0] = 0x62;
    code[1] = 0xf1;
    code[2] = w != 0 ? 0xf5 : 0x75;
    code[3] = (uint8_t)(0x48 | p2_extra);
    code[4] = opcode;
    code[5] = (uint8_t)((extension << 3) | modrm_low);
    code[6] = immediate;
}

static void test_legality_matrix(void)
{
    static const uint8_t opcodes[] = {0x71, 0x73};
    size_t opcode_index;
    unsigned int controls = 0;
    unsigned int legal = 0;
    unsigned int rejected = 0;

    for (opcode_index = 0; opcode_index < sizeof(opcodes); ++opcode_index) {
        unsigned int w;

        for (w = 0; w != 2; ++w) {
            unsigned int extension;

            for (extension = 0; extension != 8; ++extension) {
                const immediate_group_case *test = find_case(
                    opcodes[opcode_index], (uint8_t)w, (uint8_t)extension);
                uint8_t code[7];
                unsigned int immediate;

                ++controls;
                for (immediate = 0; immediate != 256u; ++immediate) {
                    uint32_t decoded_size;
                    cdisasm_instruction instruction;

                    make_encoding(opcodes[opcode_index], (uint8_t)w,
                        (uint8_t)extension,
                        test != NULL && test->mask ? 0x02 : 0,
                        0xc2, (uint8_t)immediate,
                        code);
                    if (test == NULL) {
                        if (immediate == 0) {
                            ++rejected;
                            expect_status("reserved immediate-shift control",
                                CDISASM_CPU_X86, code, sizeof(code),
                                CDISASM_X86_DECODE_FLAG_BASE,
                                CDISASM_STATUS_INVALID_INSTRUCTION);
                        }
                        continue;
                    }
                    ++legal;
#if USE_EXTRA_OPCODES
                    instruction = decode(CDISASM_CPU_SKYLAKE_SP, code,
                        sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                        &decoded_size);
                    EXPECT(decoded_size == sizeof(code));
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id == test->name_id);
                    EXPECT(instruction.opcode[2].imm == immediate);
                    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                        test->group));
#else
                    (void)instruction;
                    (void)decoded_size;
                    expect_status("extra-opcodes OFF immediate-shift control",
                        CDISASM_CPU_X86, code, sizeof(code),
                        CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
                make_encoding(opcodes[opcode_index], (uint8_t)w,
                    (uint8_t)extension, 0, 0xc2, 0x13, code);
                expect_status("immediate-shift control truncated imm8",
                    CDISASM_CPU_X86, code, sizeof(code) - 1u,
                    CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
            }
        }
    }
    EXPECT(controls == 32u);
    EXPECT(legal == 12u * 256u);
    EXPECT(rejected == 20u);
}

static void test_source_and_prefix_legality(void)
{
    size_t index;

    for (index = 0; index < sizeof(allocated) / sizeof(allocated[0]);
         ++index) {
        const immediate_group_case *test = &allocated[index];
        uint8_t code[7];

        const uint8_t p2_mask = test->mask ? 0x02 : 0;

        make_encoding(test->opcode, test->w == 2 ? 0 : test->w,
            test->extension, (uint8_t)(p2_mask | 0x10), 0xc2, 0x13,
            code);
        expect_status("immediate-shift register EVEX.b", CDISASM_CPU_X86,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        make_encoding(test->opcode, test->w == 2 ? 0 : test->w,
            test->extension, (uint8_t)(p2_mask | 0x10), 0x00, 0x13,
            code);
        if (!test->broadcast) {
            expect_status("immediate-shift reserved memory EVEX.b",
                CDISASM_CPU_X86, code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        } else {
#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(CDISASM_CPU_SKYLAKE_SP,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                &decoded_size);
            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.name_id == test->name_id);
            EXPECT(instruction.opcode[1].size == 8u);
            EXPECT(instruction.opcode[1].broadcast
                == CDISASM_X86_BROADCAST_1_TO_8);
#else
            expect_status("extra-opcodes OFF immediate-shift broadcast",
                CDISASM_CPU_X86, code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
        if (!test->mask) {
            make_encoding(test->opcode, 0, test->extension, 0x02, 0xc2,
                0x13, code);
            expect_status("immediate DQ shift mask reserved", CDISASM_CPU_X86,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            make_encoding(test->opcode, 0, test->extension, 0x80, 0xc2,
                0x13, code);
            expect_status("immediate DQ shift zeroing k0 reserved",
                CDISASM_CPU_X86, code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
}

typedef struct apx_positive_case {
    uint8_t code[8];
    uint8_t code_size;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_reg_id base_reg;
    cdisasm_x86_reg_id index_reg;
    uint16_t memory_size;
    cdisasm_x86_broadcast broadcast;
} apx_positive_case;

static void test_apx_positive_routes(void)
{
    static const apx_positive_case routes[] = {
        {{0x62, 0xf9, 0x7d, 0x48, 0x71, 0xd1, 0x07, 0x00}, 7,
            CDISASM_X86_NAME_VPSRLW, CDISASM_X86_REG_NONE,
            CDISASM_X86_REG_NONE, 0, CDISASM_X86_BROADCAST_NONE},
        {{0x62, 0xf9, 0xfd, 0x48, 0x71, 0xe1, 0x07, 0x00}, 7,
            CDISASM_X86_NAME_VPSRAW, CDISASM_X86_REG_NONE,
            CDISASM_X86_REG_NONE, 0, CDISASM_X86_BROADCAST_NONE},
        {{0x62, 0xf9, 0x7d, 0x48, 0x71, 0xf1, 0x07, 0x00}, 7,
            CDISASM_X86_NAME_VPSLLW, CDISASM_X86_REG_NONE,
            CDISASM_X86_REG_NONE, 0, CDISASM_X86_BROADCAST_NONE},
        {{0x62, 0xf9, 0xfd, 0x48, 0x73, 0xd1, 0x07, 0x00}, 7,
            CDISASM_X86_NAME_VPSRLQ, CDISASM_X86_REG_NONE,
            CDISASM_X86_REG_NONE, 0, CDISASM_X86_BROADCAST_NONE},
        {{0x62, 0xf9, 0xfd, 0x48, 0x73, 0xf1, 0x07, 0x00}, 7,
            CDISASM_X86_NAME_VPSLLQ, CDISASM_X86_REG_NONE,
            CDISASM_X86_REG_NONE, 0, CDISASM_X86_BROADCAST_NONE},
        {{0x62, 0xf9, 0xfd, 0x48, 0x73, 0xd9, 0x07, 0x00}, 7,
            CDISASM_X86_NAME_VPSRLDQ, CDISASM_X86_REG_NONE,
            CDISASM_X86_REG_NONE, 0, CDISASM_X86_BROADCAST_NONE},
        {{0x62, 0xf9, 0x7d, 0x48, 0x73, 0xf9, 0x07, 0x00}, 7,
            CDISASM_X86_NAME_VPSLLDQ, CDISASM_X86_REG_NONE,
            CDISASM_X86_REG_NONE, 0, CDISASM_X86_BROADCAST_NONE},
        {{0x62, 0xf9, 0x7d, 0x48, 0x71, 0x10, 0x07, 0x00}, 7,
            CDISASM_X86_NAME_VPSRLW, CDISASM_X86_REG_R16,
            CDISASM_X86_REG_NONE, 64, CDISASM_X86_BROADCAST_NONE},
        {{0x62, 0xf1, 0x79, 0x48, 0x71, 0x10, 0x07, 0x00}, 7,
            CDISASM_X86_NAME_VPSRLW, CDISASM_X86_REG_RAX,
            CDISASM_X86_REG_NONE, 64, CDISASM_X86_BROADCAST_NONE},
        {{0x62, 0xf9, 0x79, 0x48, 0x71, 0x10, 0x07, 0x00}, 7,
            CDISASM_X86_NAME_VPSRLW, CDISASM_X86_REG_R16,
            CDISASM_X86_REG_NONE, 64, CDISASM_X86_BROADCAST_NONE},
        {{0x62, 0xf1, 0x79, 0x48, 0x71, 0x14, 0x08, 0x07}, 8,
            CDISASM_X86_NAME_VPSRLW, CDISASM_X86_REG_RAX,
            CDISASM_X86_REG_R17, 64, CDISASM_X86_BROADCAST_NONE},
        {{0x62, 0xf9, 0xf9, 0x58, 0x73, 0x14, 0x08, 0x07}, 8,
            CDISASM_X86_NAME_VPSRLQ, CDISASM_X86_REG_R16,
            CDISASM_X86_REG_R17, 8, CDISASM_X86_BROADCAST_1_TO_8},
        {{0x62, 0xf9, 0xf9, 0x48, 0x73, 0x1c, 0x08, 0x07}, 8,
            CDISASM_X86_NAME_VPSRLDQ, CDISASM_X86_REG_R16,
            CDISASM_X86_REG_R17, 64, CDISASM_X86_BROADCAST_NONE}
    };
    size_t index;

    for (index = 0; index < sizeof(routes) / sizeof(routes[0]); ++index) {
        const apx_positive_case *test = &routes[index];
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_APX,
            test->code, test->code_size,
            CDISASM_X86_DECODE_FLAG_AVX10 | CDISASM_X86_DECODE_FLAG_APX,
            &decoded_size);

        EXPECT(decoded_size == test->code_size);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(instruction.opcode[2].imm == UINT64_C(7));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        if (test->base_reg == CDISASM_X86_REG_NONE) {
            EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
        } else {
            EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
            EXPECT(instruction.opcode[1].base_reg == test->base_reg);
            EXPECT(instruction.opcode[1].index_reg == test->index_reg);
            EXPECT(instruction.opcode[1].size == test->memory_size);
            EXPECT(instruction.opcode[1].broadcast == test->broadcast);
        }
#else
        if (index == 0u) {
            expect_status("extra-opcodes OFF APX immediate-shift route",
                CDISASM_CPU_X86, test->code, test->code_size,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
#endif
    }

#if USE_EXTRA_OPCODES
    expect_status("immediate word shift B4 CPU gate",
        CDISASM_CPU_SKYLAKE_SP, routes[0].code, routes[0].code_size,
        CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
}

typedef struct vector_length_case {
    uint8_t code[8];
    cdisasm_x86_name_id name_id;
    cdisasm_x86_reg_id destination_reg;
    uint16_t memory_size;
    uint64_t displacement;
    cdisasm_x86_broadcast broadcast;
    cdisasm_x86_group_id feature_group;
    uint8_t has_avx512vl;
    uint8_t mask_mode;
} vector_length_case;

static void test_vector_lengths_and_compressed_disp8(void)
{
    static const vector_length_case routes[] = {
        /* XMM full-memory word shift, disp8*N=2*16, {k2}{z}. */
        {{0x62, 0xf1, 0x75, 0x8a, 0x71, 0x50, 0x02, 0x13},
            CDISASM_X86_NAME_VPSRLW, CDISASM_X86_REG_XMM1,
            16, UINT64_C(32), CDISASM_X86_BROADCAST_NONE,
            CDISASM_X86_GROUP_AVX512BW, 1, CDISASM_X86_MASK_ZERO},
        /* YMM full-memory byte-count lane shift, disp8*N=2*32. */
        {{0x62, 0xf1, 0x75, 0x28, 0x73, 0x58, 0x02, 0x13},
            CDISASM_X86_NAME_VPSRLDQ, CDISASM_X86_REG_YMM1,
            32, UINT64_C(64), CDISASM_X86_BROADCAST_NONE,
            CDISASM_X86_GROUP_AVX512BW, 1, CDISASM_X86_MASK_NONE},
        /* ZMM qword broadcast shift, disp8*N=2*8. */
        {{0x62, 0xf1, 0xf5, 0x5a, 0x73, 0x50, 0x02, 0x13},
            CDISASM_X86_NAME_VPSRLQ, CDISASM_X86_REG_ZMM1,
            8, UINT64_C(16), CDISASM_X86_BROADCAST_1_TO_8,
            CDISASM_X86_GROUP_AVX512F, 0, CDISASM_X86_MASK_MERGE}
    };
    size_t index;

    for (index = 0; index < sizeof(routes) / sizeof(routes[0]); ++index) {
        const vector_length_case *test = &routes[index];
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_SKYLAKE_SP,
            test->code, sizeof(test->code), CDISASM_X86_DECODE_FLAG_AVX512,
            &decoded_size);

        EXPECT(decoded_size == sizeof(test->code));
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(instruction.opcode[0].reg == test->destination_reg);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[1].size == test->memory_size);
        EXPECT(instruction.opcode[1].imm == test->displacement);
        EXPECT(instruction.opcode[1].broadcast == test->broadcast);
        EXPECT(instruction.opcode[2].imm == UINT64_C(0x13));
        EXPECT(instruction.encoding.displacement_offset == 6u);
        EXPECT(instruction.encoding.displacement_size == 1u);
        EXPECT(instruction.encoding.immediate_offset[0] == 7u);
        EXPECT(instruction.mask_mode == test->mask_mode);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, test->feature_group));
        EXPECT(cdisasm_instruction_has_x86_group(
                   &instruction, CDISASM_X86_GROUP_AVX512VL)
            == test->has_avx512vl);
#else
        if (index == 0u) {
            expect_status("extra-opcodes OFF compressed immediate shift",
                CDISASM_CPU_X86, test->code, sizeof(test->code),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
#endif
    }
}

static void test_feature_and_apx_gates(void)
{
    uint8_t code[7];

    make_encoding(0x71, 0, 2, 0, 0xc2, 0x13, code);
#if USE_EXTRA_OPCODES
    expect_status("immediate word shift runtime gate", CDISASM_CPU_SKYLAKE_SP,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("immediate word shift CPU gate", CDISASM_CPU_HASWELL,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    expect_status("extra-opcodes OFF immediate word shift", CDISASM_CPU_X86,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    make_encoding(0x73, 1, 6, 0, 0xc2, 0x13, code);
    code[2] &= 0xfbu;
#if USE_EXTRA_OPCODES
    expect_status("immediate qword shift APX U0 register gate", CDISASM_CPU_APX,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX10
            | CDISASM_X86_DECODE_FLAG_APX, CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    expect_status("extra-opcodes OFF immediate qword shift APX U0 invalid",
        CDISASM_CPU_X86, code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
}

int main(void)
{
    test_legality_matrix();
    test_source_and_prefix_legality();
    test_apx_positive_routes();
    test_vector_lengths_and_compressed_disp8();
    test_feature_and_apx_gates();

    if (failures != 0) {
        fprintf(stderr, "%d immediate shift group test(s) failed\n", failures);
        return 1;
    }
    printf("x86 immediate shift group legality tests passed\n");
    return 0;
}
