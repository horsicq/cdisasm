#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_GROUP_SHA512 == UINT16_C(95),
               "SHA512 group ID changed");
_Static_assert(CDISASM_X86_GROUP_SM3 == UINT16_C(96),
               "SM3 group ID changed");
_Static_assert(CDISASM_X86_GROUP_SM4 == UINT16_C(97),
               "SM4 group ID changed");
_Static_assert(CDISASM_X86_NAME_VSHA512MSG1 == UINT16_C(885),
               "modern crypto name range start changed");
_Static_assert(CDISASM_X86_NAME_VSM4RNDS4 == UINT16_C(892),
               "modern crypto name range end changed");
_Static_assert(CDISASM_X86_NAME_COUNT >= UINT16_C(917),
               "modern crypto name range is incomplete");
_Static_assert(CDISASM_X86_DECODE_FLAG_SM3 == UINT64_C(0x080000000),
               "SM3 runtime flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SM4 == UINT64_C(0x100000000),
               "SM4 runtime flag changed");
_Static_assert(CDISASM_CPU_ARROW_LAKE
                   == (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0032)),
               "Arrow Lake CPU ID changed");

static int failures;

#if USE_EXTRA_OPCODES
#define CRYPTO_STRUCTURAL_FLAGS CDISASM_X86_DECODE_FLAG_ALL
#else
#define CRYPTO_STRUCTURAL_FLAGS CDISASM_X86_DECODE_FLAG_BASE
#endif

#define EXPECT(expression)                                                     \
    do {                                                                       \
        if (!(expression)) {                                                   \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",              \
                    __FILE__, __LINE__, #expression);                          \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

typedef struct crypto_case {
    const uint8_t *bytes;
    size_t size;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_group_id group_id;
    cdisasm_x86_decode_option flag;
    uint8_t operand_count;
    const char *intel;
} crypto_case;

static const uint8_t vsha512msg1[] = {0xc4, 0xe2, 0x7f, 0xcc, 0xca};
static const uint8_t vsha512msg2[] = {0xc4, 0xe2, 0x7f, 0xcd, 0xca};
static const uint8_t vsha512rnds2[] = {0xc4, 0xe2, 0x6f, 0xcb, 0xcb};
static const uint8_t vsm3msg1[] = {0xc4, 0xe2, 0x68, 0xda, 0xcb};
static const uint8_t vsm3msg2[] = {0xc4, 0xe2, 0x69, 0xda, 0xcb};
static const uint8_t vsm3rnds2[] = {0xc4, 0xe3, 0x69, 0xde, 0xcb, 0x07};
static const uint8_t vsm4key4[] = {0xc4, 0xe2, 0x6a, 0xda, 0xcb};
static const uint8_t vsm4rnds4[] = {0xc4, 0xe2, 0x6f, 0xda, 0xcb};

static const crypto_case vex_cases[] = {
    {vsha512msg1, sizeof(vsha512msg1), CDISASM_X86_NAME_VSHA512MSG1,
     CDISASM_X86_GROUP_SHA512, CDISASM_X86_DECODE_FLAG_SHA, 2,
     "vsha512msg1 ymm1, xmm2"},
    {vsha512msg2, sizeof(vsha512msg2), CDISASM_X86_NAME_VSHA512MSG2,
     CDISASM_X86_GROUP_SHA512, CDISASM_X86_DECODE_FLAG_SHA, 2,
     "vsha512msg2 ymm1, ymm2"},
    {vsha512rnds2, sizeof(vsha512rnds2), CDISASM_X86_NAME_VSHA512RNDS2,
     CDISASM_X86_GROUP_SHA512, CDISASM_X86_DECODE_FLAG_SHA, 3,
     "vsha512rnds2 ymm1, ymm2, xmm3"},
    {vsm3msg1, sizeof(vsm3msg1), CDISASM_X86_NAME_VSM3MSG1,
     CDISASM_X86_GROUP_SM3, CDISASM_X86_DECODE_FLAG_SM3, 3,
     "vsm3msg1 xmm1, xmm2, xmm3"},
    {vsm3msg2, sizeof(vsm3msg2), CDISASM_X86_NAME_VSM3MSG2,
     CDISASM_X86_GROUP_SM3, CDISASM_X86_DECODE_FLAG_SM3, 3,
     "vsm3msg2 xmm1, xmm2, xmm3"},
    {vsm3rnds2, sizeof(vsm3rnds2), CDISASM_X86_NAME_VSM3RNDS2,
     CDISASM_X86_GROUP_SM3, CDISASM_X86_DECODE_FLAG_SM3, 4,
     "vsm3rnds2 xmm1, xmm2, xmm3, 0x7"},
    {vsm4key4, sizeof(vsm4key4), CDISASM_X86_NAME_VSM4KEY4,
     CDISASM_X86_GROUP_SM4, CDISASM_X86_DECODE_FLAG_SM4, 3,
     "vsm4key4 xmm1, xmm2, xmm3"},
    {vsm4rnds4, sizeof(vsm4rnds4), CDISASM_X86_NAME_VSM4RNDS4,
     CDISASM_X86_GROUP_SM4, CDISASM_X86_DECODE_FLAG_SM4, 3,
     "vsm4rnds4 ymm1, ymm2, ymm3"}
};

static cdisasm_instruction decode_mode(
    cdisasm_cpu_id cpu_id,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu_id, mode, bytes, size, UINT64_C(0x1000), flags, &instruction);
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
    cdisasm_cpu_id cpu_id,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        cpu_id, mode, bytes, size, flags, &decoded_size);

    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, status));
}

static void expect_structural_error(
    const uint8_t *bytes,
    size_t size,
    cdisasm_status status)
{
    expect_error_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64, bytes, size,
        CRYPTO_STRUCTURAL_FLAGS, status);
}

#if USE_EXTRA_OPCODES
static void expect_register_operand(
    const cdisasm_instruction *instruction,
    unsigned int index,
    cdisasm_x86_reg_id reg,
    unsigned int size,
    cdisasm_operand_access access)
{
    EXPECT(index < instruction->operand_count);
    EXPECT(instruction->opcode[index].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[index].reg == reg);
    EXPECT(instruction->opcode[index].size == size);
    EXPECT(instruction->opcode[index].access == access);
}

static void check_vex_operands(
    const crypto_case *test,
    const cdisasm_instruction *instruction)
{
    const int sha = test->group_id == CDISASM_X86_GROUP_SHA512;
    const int sm3 = test->group_id == CDISASM_X86_GROUP_SM3;
    const unsigned int packed_size =
        test->name_id == CDISASM_X86_NAME_VSM4RNDS4 ? 32u : 16u;

    EXPECT(instruction->operand_count == test->operand_count);
    if (test->name_id == CDISASM_X86_NAME_VSHA512MSG1) {
        expect_register_operand(instruction, 0, CDISASM_X86_REG_YMM1, 32u,
                                CDISASM_OPERAND_ACCESS_READ_WRITE);
        expect_register_operand(instruction, 1, CDISASM_X86_REG_XMM2, 16u,
                                CDISASM_OPERAND_ACCESS_READ);
        return;
    }
    if (test->name_id == CDISASM_X86_NAME_VSHA512MSG2) {
        expect_register_operand(instruction, 0, CDISASM_X86_REG_YMM1, 32u,
                                CDISASM_OPERAND_ACCESS_READ_WRITE);
        expect_register_operand(instruction, 1, CDISASM_X86_REG_YMM2, 32u,
                                CDISASM_OPERAND_ACCESS_READ);
        return;
    }
    if (test->name_id == CDISASM_X86_NAME_VSHA512RNDS2) {
        expect_register_operand(instruction, 0, CDISASM_X86_REG_YMM1, 32u,
                                CDISASM_OPERAND_ACCESS_READ_WRITE);
        expect_register_operand(instruction, 1, CDISASM_X86_REG_YMM2, 32u,
                                CDISASM_OPERAND_ACCESS_READ);
        expect_register_operand(instruction, 2, CDISASM_X86_REG_XMM3, 16u,
                                CDISASM_OPERAND_ACCESS_READ);
        return;
    }

    expect_register_operand(
        instruction, 0,
        (cdisasm_x86_reg_id)((packed_size == 32u
            ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0) + 1u),
        packed_size,
        sm3 ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_WRITE);
    expect_register_operand(
        instruction, 1,
        (cdisasm_x86_reg_id)((packed_size == 32u
            ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0) + 2u),
        packed_size, CDISASM_OPERAND_ACCESS_READ);
    expect_register_operand(
        instruction, 2,
        (cdisasm_x86_reg_id)((packed_size == 32u
            ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0) + 3u),
        packed_size, CDISASM_OPERAND_ACCESS_READ);
    if (sm3 && test->name_id == CDISASM_X86_NAME_VSM3RNDS2) {
        EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
        EXPECT(instruction->opcode[3].size == 1u);
        EXPECT(instruction->opcode[3].imm == UINT64_C(7));
        EXPECT(instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ);
    }
    (void)sha;
}
#endif

static void test_vex_catalog_and_operands(void)
{
    size_t index;

    EXPECT(sizeof(vex_cases) / sizeof(vex_cases[0]) == 8u);
    for (index = 0; index < sizeof(vex_cases) / sizeof(vex_cases[0]); ++index) {
        const crypto_case *test = &vex_cases[index];
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_ARROW_LAKE, CDISASM_MODE_64,
            test->bytes, test->size, test->flag, &decoded_size);

        EXPECT(decoded_size == test->size);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX) != 0);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, test->group_id));
        EXPECT(instruction.encoding.prefix_size == 3u);
        EXPECT(instruction.encoding.opcode_offset == 3u);
        EXPECT(instruction.encoding.opcode_size == 1u);
        EXPECT(instruction.encoding.modrm_offset == 4u);
        EXPECT(instruction.encoding.immediate_count
            == (test->name_id == CDISASM_X86_NAME_VSM3RNDS2 ? 1u : 0u));
        check_vex_operands(test, &instruction);

#if USE_DISASM_FORMAT
        {
            char text[96];
            size_t length = cdisasm_x86_format(
                &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
                text, sizeof(text));

            EXPECT(length == strlen(test->intel));
            EXPECT(strcmp(text, test->intel) == 0);
        }
#endif
#else
        expect_structural_error(
            test->bytes, test->size,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_vex_memory_and_modes(void)
{
    static const uint8_t sm3msg1_mem[] = {0xc4, 0xe2, 0x68, 0xda, 0x08};
    static const uint8_t sm3rnds2_mem[] = {
        0xc4, 0xe3, 0x69, 0xde, 0x08, 0x07
    };
    static const uint8_t sm4key4_mem[] = {0xc4, 0xe2, 0x6e, 0xda, 0x08};
    static const uint8_t sm4rnds4_mem[] = {0xc4, 0xe2, 0x6f, 0xda, 0x08};
    static const struct {
        const uint8_t *bytes;
        size_t size;
        cdisasm_x86_name_id name_id;
        cdisasm_x86_decode_option flag;
        unsigned int memory_size;
    } cases[] = {
        {sm3msg1_mem, sizeof(sm3msg1_mem), CDISASM_X86_NAME_VSM3MSG1,
         CDISASM_X86_DECODE_FLAG_SM3, 16u},
        {sm3rnds2_mem, sizeof(sm3rnds2_mem), CDISASM_X86_NAME_VSM3RNDS2,
         CDISASM_X86_DECODE_FLAG_SM3, 16u},
        {sm4key4_mem, sizeof(sm4key4_mem), CDISASM_X86_NAME_VSM4KEY4,
         CDISASM_X86_DECODE_FLAG_SM4, 32u},
        {sm4rnds4_mem, sizeof(sm4rnds4_mem), CDISASM_X86_NAME_VSM4RNDS4,
         CDISASM_X86_DECODE_FLAG_SM4, 32u}
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_ARROW_LAKE, CDISASM_MODE_64,
            cases[index].bytes, cases[index].size,
            cases[index].flag, &decoded_size);
        const unsigned int memory_index =
            cases[index].name_id == CDISASM_X86_NAME_VSM3RNDS2 ? 2u : 2u;

        EXPECT(decoded_size == cases[index].size);
        EXPECT(instruction.name_id == cases[index].name_id);
        EXPECT(instruction.opcode[memory_index].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[memory_index].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[memory_index].size == cases[index].memory_size);
        EXPECT(instruction.opcode[memory_index].access
            == CDISASM_OPERAND_ACCESS_READ);
#else
        expect_structural_error(
            cases[index].bytes, cases[index].size,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

    {
        static const cdisasm_mode modes[] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
        };
        size_t mode_index;

        for (mode_index = 0; mode_index < sizeof(modes) / sizeof(modes[0]);
             ++mode_index) {
#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode_mode(
                CDISASM_CPU_ARROW_LAKE, modes[mode_index],
                vsm3msg1, sizeof(vsm3msg1),
                CDISASM_X86_DECODE_FLAG_SM3, &decoded_size);

            EXPECT(decoded_size == sizeof(vsm3msg1));
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VSM3MSG1);
#else
            expect_error_mode(
                CDISASM_CPU_ARROW_LAKE, modes[mode_index],
                vsm3msg1, sizeof(vsm3msg1),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

static void test_evex_sm4(void)
{
    static const uint8_t key4_zmm[] = {0x62, 0xf2, 0x6e, 0x48, 0xda, 0xcb};
    static const uint8_t rnds4_zmm[] = {0x62, 0xf2, 0x6f, 0x48, 0xda, 0xcb};
    static const uint8_t key4_mem[] = {0x62, 0xf2, 0x6e, 0x48, 0xda, 0x08};
    static const uint8_t key4_high[] = {0x62, 0xa2, 0x6e, 0x00, 0xda, 0xcb};
    static const struct {
        const uint8_t *bytes;
        size_t size;
        cdisasm_x86_name_id name_id;
    } cases[] = {
        {key4_zmm, sizeof(key4_zmm), CDISASM_X86_NAME_VSM4KEY4},
        {rnds4_zmm, sizeof(rnds4_zmm), CDISASM_X86_NAME_VSM4RNDS4}
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].bytes, cases[index].size,
            CDISASM_X86_DECODE_FLAG_SM4 | CDISASM_X86_DECODE_FLAG_AVX10,
            &decoded_size);

        EXPECT(decoded_size == cases[index].size);
        EXPECT(instruction.name_id == cases[index].name_id);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_2));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_SM4));
        EXPECT(instruction.encoding.prefix_size == 4u);
        EXPECT(instruction.encoding.opcode_offset == 4u);
        EXPECT(instruction.encoding.modrm_offset == 5u);
        EXPECT(instruction.operand_count == 3u);
        expect_register_operand(
            &instruction, 0, CDISASM_X86_REG_ZMM1, 64u,
            CDISASM_OPERAND_ACCESS_WRITE);
        expect_register_operand(
            &instruction, 1, CDISASM_X86_REG_ZMM2, 64u,
            CDISASM_OPERAND_ACCESS_READ);
        expect_register_operand(
            &instruction, 2, CDISASM_X86_REG_ZMM3, 64u,
            CDISASM_OPERAND_ACCESS_READ);
#else
        expect_structural_error(
            cases[index].bytes, cases[index].size,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

#if USE_EXTRA_OPCODES
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            key4_mem, sizeof(key4_mem),
            CDISASM_X86_DECODE_FLAG_SM4 | CDISASM_X86_DECODE_FLAG_AVX10,
            &decoded_size);

        EXPECT(decoded_size == sizeof(key4_mem));
        EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[2].size == 64u);
        EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);

        instruction = decode_mode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            key4_high, sizeof(key4_high),
            CDISASM_X86_DECODE_FLAG_SM4 | CDISASM_X86_DECODE_FLAG_AVX10,
            &decoded_size);
        EXPECT(decoded_size == sizeof(key4_high));
        expect_register_operand(
            &instruction, 0, CDISASM_X86_REG_XMM17, 16u,
            CDISASM_OPERAND_ACCESS_WRITE);
        expect_register_operand(
            &instruction, 1, CDISASM_X86_REG_XMM18, 16u,
            CDISASM_OPERAND_ACCESS_READ);
        expect_register_operand(
            &instruction, 2, CDISASM_X86_REG_XMM19, 16u,
            CDISASM_OPERAND_ACCESS_READ);
    }
#else
    expect_structural_error(
        key4_mem, sizeof(key4_mem),
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_structural_error(
        key4_high, sizeof(key4_high),
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_and_truncated_forms(void)
{
    static const uint8_t sha_memory[] = {0xc4, 0xe2, 0x7f, 0xcc, 0x0a};
    static const uint8_t sha_l0[] = {0xc4, 0xe2, 0x7b, 0xcc, 0xca};
    static const uint8_t sha_vvvv[] = {0xc4, 0xe2, 0x6f, 0xcc, 0xca};
    static const uint8_t sha_w1[] = {0xc4, 0xe2, 0xff, 0xcc, 0xca};
    static const uint8_t sm3_l1[] = {0xc4, 0xe2, 0x6c, 0xda, 0xcb};
    static const uint8_t sm3_w1[] = {0xc4, 0xe2, 0xe8, 0xda, 0xcb};
    static const uint8_t sm4_w1[] = {0xc4, 0xe2, 0xea, 0xda, 0xcb};
    static const uint8_t evex_k1[] = {0x62, 0xf2, 0x6e, 0x49, 0xda, 0xcb};
    static const uint8_t evex_zero[] = {0x62, 0xf2, 0x6e, 0xc8, 0xda, 0xcb};
    static const uint8_t evex_b[] = {0x62, 0xf2, 0x6e, 0x58, 0xda, 0xcb};
    static const uint8_t evex_ll3[] = {0x62, 0xf2, 0x6e, 0x68, 0xda, 0xcb};
    static const uint8_t evex_w1[] = {0x62, 0xf2, 0xee, 0x48, 0xda, 0xcb};
    static const uint8_t evex_u0[] = {0x62, 0xf2, 0x6a, 0x48, 0xda, 0xcb};
    static const struct {
        const uint8_t *bytes;
        size_t size;
    } invalid[] = {
        {sha_memory, sizeof(sha_memory)},
        {sha_l0, sizeof(sha_l0)},
        {sha_vvvv, sizeof(sha_vvvv)},
        {sha_w1, sizeof(sha_w1)},
        {sm3_l1, sizeof(sm3_l1)},
        {sm3_w1, sizeof(sm3_w1)},
        {sm4_w1, sizeof(sm4_w1)},
        {evex_k1, sizeof(evex_k1)},
        {evex_zero, sizeof(evex_zero)},
        {evex_b, sizeof(evex_b)},
        {evex_ll3, sizeof(evex_ll3)},
        {evex_w1, sizeof(evex_w1)},
        {evex_u0, sizeof(evex_u0)}
    };
    static const uint8_t sha_missing_modrm[] = {0xc4, 0xe2, 0x7f, 0xcc};
    static const uint8_t sm3_missing_imm[] = {0xc4, 0xe3, 0x69, 0xde, 0xcb};
    static const uint8_t evex_missing_modrm[] = {0x62, 0xf2, 0x6e, 0x48, 0xda};
    static const uint8_t evex_missing_disp[] = {
        0x62, 0xf2, 0x6e, 0x48, 0xda, 0x48
    };
    size_t index;

    for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_structural_error(
            invalid[index].bytes, invalid[index].size,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_structural_error(
        sha_missing_modrm, sizeof(sha_missing_modrm),
        CDISASM_STATUS_TRUNCATED);
    expect_structural_error(
        sm3_missing_imm, sizeof(sm3_missing_imm),
        CDISASM_STATUS_TRUNCATED);
    expect_structural_error(
        evex_missing_modrm, sizeof(evex_missing_modrm),
        CDISASM_STATUS_TRUNCATED);
    expect_structural_error(
        evex_missing_disp, sizeof(evex_missing_disp),
        CDISASM_STATUS_TRUNCATED);
}

static void test_cpu_and_runtime_gates(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t evex_sm4[] = {0x62, 0xf2, 0x6e, 0x48, 0xda, 0xcb};
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    const cdisasm_x86_decode_option arrow_flags =
        cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_ARROW_LAKE, CDISASM_MODE_64);

    EXPECT((arrow_flags & (CDISASM_X86_DECODE_FLAG_SHA
                           | CDISASM_X86_DECODE_FLAG_SM3
                           | CDISASM_X86_DECODE_FLAG_SM4))
        == (CDISASM_X86_DECODE_FLAG_SHA
            | CDISASM_X86_DECODE_FLAG_SM3
            | CDISASM_X86_DECODE_FLAG_SM4));
    EXPECT((arrow_flags & CDISASM_X86_DECODE_FLAG_AVX10) == 0);
    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
               CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64)
            & (CDISASM_X86_DECODE_FLAG_SM3
               | CDISASM_X86_DECODE_FLAG_SM4)) == 0);

    expect_error_mode(
        CDISASM_CPU_ARROW_LAKE, CDISASM_MODE_64,
        vsm4key4, sizeof(vsm4key4), CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode_mode(
        CDISASM_CPU_ARROW_LAKE, CDISASM_MODE_64,
        vsm4key4, sizeof(vsm4key4), CDISASM_X86_DECODE_FLAG_SM4,
        &decoded_size);
    EXPECT(decoded_size == sizeof(vsm4key4));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VSM4KEY4);

    expect_error_mode(
        CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
        vsha512msg1, sizeof(vsha512msg1), CDISASM_X86_DECODE_FLAG_SHA,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64,
        vsm3msg1, sizeof(vsm3msg1), CDISASM_X86_DECODE_FLAG_SM3,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        vsm4key4, sizeof(vsm4key4), CDISASM_X86_DECODE_FLAG_SM4,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    expect_error_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        evex_sm4, sizeof(evex_sm4), CDISASM_X86_DECODE_FLAG_SM4,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        evex_sm4, sizeof(evex_sm4), CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        evex_sm4, sizeof(evex_sm4),
        CDISASM_X86_DECODE_FLAG_SM4 | CDISASM_X86_DECODE_FLAG_AVX10,
        &decoded_size);
    EXPECT(decoded_size == sizeof(evex_sm4));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VSM4KEY4);

    expect_error_mode(
        CDISASM_CPU_ARROW_LAKE, CDISASM_MODE_64,
        evex_sm4, sizeof(evex_sm4),
        CDISASM_X86_DECODE_FLAG_SM4 | CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        evex_sm4, sizeof(evex_sm4),
        CDISASM_X86_DECODE_FLAG_SM4 | CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
               CDISASM_CPU_ARROW_LAKE, CDISASM_MODE_64)
        == CDISASM_X86_DECODE_FLAG_BASE);
#endif
}

#if USE_DISASM_FORMAT
static void test_formatter_table_variant(void)
{
    static const cdisasm_x86_name_id names[] = {
        CDISASM_X86_NAME_VSHA512MSG1,
        CDISASM_X86_NAME_VSHA512MSG2,
        CDISASM_X86_NAME_VSHA512RNDS2,
        CDISASM_X86_NAME_VSM3MSG1,
        CDISASM_X86_NAME_VSM3MSG2,
        CDISASM_X86_NAME_VSM3RNDS2,
        CDISASM_X86_NAME_VSM4KEY4,
        CDISASM_X86_NAME_VSM4RNDS4
    };
    static const char *const spellings[] = {
        "vsha512msg1", "vsha512msg2", "vsha512rnds2", "vsm3msg1",
        "vsm3msg2", "vsm3rnds2", "vsm4key4", "vsm4rnds4"
    };
    size_t index;

    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        cdisasm_instruction instruction;
        char text[32];
        size_t length;

        memset(&instruction, 0, sizeof(instruction));
        instruction.opcode_size = 1;
        instruction.name_id = names[index];
        instruction.last_error_id = CDISASM_STATUS_OK;
        instruction.x86_group_count = 1;
        instruction.x86_group_ids[0] = index < 3
            ? CDISASM_X86_GROUP_SHA512
            : index < 6 ? CDISASM_X86_GROUP_SM3 : CDISASM_X86_GROUP_SM4;
        memset(text, 'X', sizeof(text));
        length = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text));
#if USE_EXTRA_OPCODES
        EXPECT(length == strlen(spellings[index]));
        EXPECT(strcmp(text, spellings[index]) == 0);
#else
        (void)spellings;
        EXPECT(length == 0);
        EXPECT(text[0] == '\0');
#endif
    }
}
#endif

#undef CRYPTO_STRUCTURAL_FLAGS

int main(void)
{
    test_vex_catalog_and_operands();
    test_vex_memory_and_modes();
    test_evex_sm4();
    test_reserved_and_truncated_forms();
    test_cpu_and_runtime_gates();
#if USE_DISASM_FORMAT
    test_formatter_table_variant();
#endif

    if (failures != 0) {
        fprintf(stderr,
                "modern x86 crypto tests failed: %d (extra=%d, format=%d)\n",
                failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("modern x86 crypto tests passed (extra=%d, format=%d)\n",
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
