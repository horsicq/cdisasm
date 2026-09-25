#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct cd_case {
    uint8_t opcode;
    uint8_t w;
    uint8_t element_bits;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} cd_case;

typedef struct cd_mask_broadcast_case {
    uint8_t opcode;
    uint8_t w;
    uint8_t source_bits;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} cd_mask_broadcast_case;

static const cd_case cd_cases[] = {
    {0xc4, 0, 32, CDISASM_X86_NAME_VPCONFLICTD, "vpconflictd"},
    {0xc4, 1, 64, CDISASM_X86_NAME_VPCONFLICTQ, "vpconflictq"},
    {0x44, 0, 32, CDISASM_X86_NAME_VPLZCNTD, "vplzcntd"},
    {0x44, 1, 64, CDISASM_X86_NAME_VPLZCNTQ, "vplzcntq"}
};

static const cd_mask_broadcast_case cd_mask_broadcast_cases[] = {
    {0x2a, 1, 64, CDISASM_X86_NAME_VPBROADCASTMB2Q,
        "vpbroadcastmb2q"},
    {0x3a, 0, 64, CDISASM_X86_NAME_VPBROADCASTMW2D,
        "vpbroadcastmw2d"}
};

_Static_assert(CDISASM_X86_NAME_VPCONFLICTD == UINT16_C(1089)
        && CDISASM_X86_NAME_VPCONFLICTQ == UINT16_C(1090)
        && CDISASM_X86_NAME_VPLZCNTD == UINT16_C(1091)
        && CDISASM_X86_NAME_VPLZCNTQ == UINT16_C(1092)
        && CDISASM_X86_NAME_VPBROADCASTMB2Q == UINT16_C(1093)
        && CDISASM_X86_NAME_VPBROADCASTMW2D == UINT16_C(1094),
    "AVX512CD appended IDs changed");
_Static_assert(CDISASM_X86_NAME_VGETEXPBF16 < CDISASM_X86_NAME_COUNT
        && CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1),
    "AVX512CD catalog is incomplete");
_Static_assert(CDISASM_NAME_VPCONFLICTD
            == CDISASM_X86_NAME_VPCONFLICTD
        && CDISASM_NAME_VPLZCNTQ == CDISASM_X86_NAME_VPLZCNTQ
        && CDISASM_NAME_VPBROADCASTMB2Q
            == CDISASM_X86_NAME_VPBROADCASTMB2Q
        && CDISASM_NAME_VPBROADCASTMW2D
            == CDISASM_X86_NAME_VPBROADCASTMW2D,
    "legacy AVX512CD aliases changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_CD
        == UINT64_C(0x1000000000000000),
    "AVX512CD runtime flag changed");
_Static_assert(CDISASM_X86_DECODE_USE_AVX512_CD
        == CDISASM_X86_DECODE_FLAG_AVX512_CD,
    "AVX512CD USE alias changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI
        == UINT64_C(0x2000000000000000),
    "AVX-VNNI runtime flag boundary changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8
        == UINT64_C(0x4000000000000000),
    "AVX-VNNI-INT8 runtime flag boundary changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16
        == UINT64_C(0x8000000000000000),
    "AVX-VNNI-INT16 runtime flag boundary changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_KNOWN_MASK
        == UINT64_C(0xffffffffffffffff),
    "AVX512CD known-mask boundary changed");

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

static size_t make_encoding(
    const cd_case *test,
    unsigned int length,
    int memory,
    int broadcast,
    int mask_mode,
    uint8_t code[8])
{
    uint8_t p2 = (uint8_t)(UINT8_C(0x08) | (length << 5));

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
    code[1] = UINT8_C(0xf2);
    code[2] = test->w != 0 ? UINT8_C(0xfd) : UINT8_C(0x7d);
    code[3] = p2;
    code[4] = test->opcode;
    code[5] = memory ? UINT8_C(0x4b) : UINT8_C(0xcb);
    if (memory) {
        code[6] = UINT8_C(2);
        return 7u;
    }
    return 6u;
}

static size_t make_mask_broadcast_encoding(
    const cd_mask_broadcast_case *test,
    unsigned int length,
    unsigned int destination,
    unsigned int source,
    uint8_t code[8])
{
    uint8_t p0 = UINT8_C(0xf2);

    if ((destination & 8u) != 0u) {
        p0 &= (uint8_t)~UINT8_C(0x80);
    }
    if ((destination & 16u) != 0u) {
        p0 &= (uint8_t)~UINT8_C(0x10);
    }
    code[0] = UINT8_C(0x62);
    code[1] = p0;
    code[2] = test->w != 0u ? UINT8_C(0xfe) : UINT8_C(0x7e);
    code[3] = (uint8_t)(UINT8_C(0x08) | (length << 5));
    code[4] = test->opcode;
    code[5] = (uint8_t)(UINT8_C(0xc0)
        | ((destination & 7u) << 3) | (source & 7u));
    return 6u;
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

static void expect_avx512_groups(
    const cdisasm_instruction *instruction,
    unsigned int length)
{
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512CD));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512VL) == (length != 2u));
}
#endif

static void test_names_lengths_memory_broadcast_masks(void)
{
    size_t case_index;
    unsigned int decoded_cases = 0;

    for (case_index = 0;
         case_index < sizeof(cd_cases) / sizeof(cd_cases[0]);
         ++case_index) {
        const cd_case *test = &cd_cases[case_index];
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            const unsigned int vector_bits = 128u << length;
            uint8_t code[8];
            size_t size = make_encoding(test, length, 0, 0, 0, code);

            ++decoded_cases;
#if USE_EXTRA_OPCODES
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                    code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
                    &decoded_size);

                EXPECT(decoded_size == size);
                EXPECT(instruction.name_id == test->name_id);
                EXPECT(instruction.operand_count == 2u);
                EXPECT(instruction.opcode[0].reg
                    == vector_register(1u, vector_bits));
                EXPECT(instruction.opcode[0].size == vector_bits / 8u);
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.opcode[1].reg
                    == vector_register(3u, vector_bits));
                EXPECT(instruction.opcode[1].size == vector_bits / 8u);
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(instruction.mask_mode == CDISASM_X86_MASK_NONE);
                expect_avx512_groups(&instruction, length);
            }
#else
            (void)vector_bits;
            expect_status("extra-opcodes OFF AVX512CD register",
                CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

            size = make_encoding(test, length, 1, 0, 1, code);
            ++decoded_cases;
#if USE_EXTRA_OPCODES
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                    code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
                    &decoded_size);

                EXPECT(decoded_size == size);
                EXPECT(instruction.name_id == test->name_id);
                EXPECT(instruction.mask_reg == CDISASM_X86_REG_K2);
                EXPECT(instruction.mask_mode == CDISASM_X86_MASK_MERGE);
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
                EXPECT(instruction.opcode[1].type
                    == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[1].base_reg
                    == CDISASM_X86_REG_RBX);
                EXPECT(instruction.opcode[1].size == vector_bits / 8u);
                EXPECT(instruction.opcode[1].imm
                    == UINT64_C(2) * (vector_bits / 8u));
                EXPECT(instruction.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                expect_avx512_groups(&instruction, length);
            }
#endif

            size = make_encoding(test, length, 1, 1, 2, code);
            ++decoded_cases;
#if USE_EXTRA_OPCODES
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                    code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
                    &decoded_size);

                EXPECT(decoded_size == size);
                EXPECT(instruction.name_id == test->name_id);
                EXPECT(instruction.mask_reg == CDISASM_X86_REG_K2);
                EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.opcode[1].size
                    == test->element_bits / 8u);
                EXPECT(instruction.opcode[1].imm
                    == UINT64_C(2) * (test->element_bits / 8u));
                EXPECT(instruction.opcode[1].broadcast
                    == (cdisasm_x86_broadcast)(
                        vector_bits / test->element_bits));
                expect_avx512_groups(&instruction, length);
            }
#else
            expect_status("extra-opcodes OFF AVX512CD broadcast",
                CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
    EXPECT(decoded_cases == 36u);
}

static void test_mask_broadcast_lengths_and_operands(void)
{
    size_t case_index;
    unsigned int decoded_cases = 0;

    for (case_index = 0;
         case_index < sizeof(cd_mask_broadcast_cases)
            / sizeof(cd_mask_broadcast_cases[0]);
         ++case_index) {
        const cd_mask_broadcast_case *test =
            &cd_mask_broadcast_cases[case_index];
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            const unsigned int vector_bits = 128u << length;
            uint8_t code[8];
            size_t size = make_mask_broadcast_encoding(
                test, length, 1u, 3u, code);

            ++decoded_cases;
#if USE_EXTRA_OPCODES
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                    code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
                    &decoded_size);

                EXPECT(decoded_size == size);
                EXPECT(instruction.name_id == test->name_id);
                EXPECT(instruction.operand_count == 2u);
                EXPECT(instruction.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                EXPECT(instruction.opcode[0].reg
                    == vector_register(1u, vector_bits));
                EXPECT(instruction.opcode[0].size == vector_bits / 8u);
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_K3);
                EXPECT(instruction.opcode[1].size
                    == test->source_bits / 8u);
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(instruction.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                EXPECT(instruction.mask_reg == CDISASM_X86_REG_NONE);
                EXPECT(instruction.mask_mode == CDISASM_X86_MASK_NONE);
                expect_avx512_groups(&instruction, length);
            }
#else
            (void)vector_bits;
            expect_status("extra-opcodes OFF AVX512CD mask broadcast",
                CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
    EXPECT(decoded_cases == 6u);
}

static void test_mask_broadcast_reserved_controls_and_truncation(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cd_mask_broadcast_cases)
            / sizeof(cd_mask_broadcast_cases[0]);
         ++case_index) {
        const cd_mask_broadcast_case *test =
            &cd_mask_broadcast_cases[case_index];
        uint8_t code[8];
        size_t size = make_mask_broadcast_encoding(
            test, 2u, 1u, 3u, code);

        code[2] ^= UINT8_C(0x80);
        expect_status("AVX512CD mask broadcast wrong W",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_mask_broadcast_encoding(test, 2u, 1u, 3u, code);
        code[2] &= (uint8_t)~UINT8_C(0x08);
        expect_status("AVX512CD mask broadcast noncanonical vvvv",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_mask_broadcast_encoding(test, 2u, 1u, 3u, code);
        code[3] &= (uint8_t)~UINT8_C(0x08);
        expect_status("AVX512CD mask broadcast noncanonical V-prime",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_mask_broadcast_encoding(test, 2u, 1u, 3u, code);
        code[3] = UINT8_C(0x68);
        expect_status("AVX512CD mask broadcast LL=3 reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_mask_broadcast_encoding(test, 2u, 1u, 3u, code);
        code[3] |= UINT8_C(0x10);
        expect_status("AVX512CD mask broadcast EVEX.b reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_mask_broadcast_encoding(test, 2u, 1u, 3u, code);
        code[3] |= UINT8_C(0x01);
        expect_status("AVX512CD mask broadcast aaa reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_mask_broadcast_encoding(test, 2u, 1u, 3u, code);
        code[3] |= UINT8_C(0x80);
        expect_status("AVX512CD mask broadcast zeroing reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_mask_broadcast_encoding(test, 2u, 1u, 3u, code);
        code[5] &= UINT8_C(0x3f);
        expect_status("AVX512CD mask broadcast memory form reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_mask_broadcast_encoding(test, 2u, 1u, 3u, code);
        code[2] &= (uint8_t)~UINT8_C(0x04);
        expect_status("AVX512CD mask broadcast U0 reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    {
        static const uint8_t missing_modrm[] = {
            0x62, 0xf2, 0xfe, 0x48, 0x2a
        };
        static const uint8_t missing_disp8[] = {
            0x62, 0xf2, 0x7e, 0x48, 0x3a, 0x4b
        };

        expect_status("VPBROADCASTMB2Q missing ModRM",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            missing_modrm, sizeof(missing_modrm),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        expect_status("VPBROADCASTMW2D reserved memory missing disp8",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            missing_disp8, sizeof(missing_disp8),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    }
}

static void test_reserved_controls_and_truncation(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cd_cases) / sizeof(cd_cases[0]);
         ++case_index) {
        const cd_case *test = &cd_cases[case_index];
        uint8_t code[8];
        size_t size = make_encoding(test, 2, 0, 0, 0, code);

        code[2] &= (uint8_t)~UINT8_C(0x08);
        expect_status("AVX512CD noncanonical EVEX.vvvv",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2, 0, 1, 0, code);
        expect_status("AVX512CD register EVEX.b reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2, 0, 0, 0, code);
        code[3] = (uint8_t)((code[3] & UINT8_C(0x9f)) | UINT8_C(0x60));
        expect_status("AVX512CD LL=3 reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2, 0, 0, 0, code);
        code[3] |= UINT8_C(0x80);
        expect_status("AVX512CD zero without mask reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2, 0, 0, 0, code);
        code[3] &= (uint8_t)~UINT8_C(0x08);
        expect_status("AVX512CD noncanonical EVEX.V-prime",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2, 0, 0, 0, code);
        code[2] &= UINT8_C(0xfc);
        expect_status("AVX512CD wrong mandatory prefix unowned",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    {
        static const uint8_t missing_modrm[] = {
            0x62, 0xf2, 0x7d, 0x48, 0xc4
        };
        static const uint8_t missing_disp8[] = {
            0x62, 0xf2, 0xfd, 0x48, 0x44, 0x4b
        };
        static const uint8_t missing_sib[] = {
            0x62, 0xf2, 0x79, 0x48, 0xc4, 0x0c
        };

        expect_status("VPCONFLICTD missing ModRM",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            missing_modrm, sizeof(missing_modrm),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        expect_status("VPLZCNTQ missing disp8",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            missing_disp8, sizeof(missing_disp8),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        expect_status("VPCONFLICTD APX U0 missing SIB",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            missing_sib, sizeof(missing_sib),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    }
}

#if USE_EXTRA_OPCODES
static void test_mask_broadcast_complete_register_space(void)
{
    size_t case_index;
    unsigned int accepted64 = 0;
    unsigned int accepted32 = 0;

    for (case_index = 0;
         case_index < sizeof(cd_mask_broadcast_cases)
            / sizeof(cd_mask_broadcast_cases[0]);
         ++case_index) {
        const cd_mask_broadcast_case *test =
            &cd_mask_broadcast_cases[case_index];
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            const unsigned int vector_bits = 128u << length;
            unsigned int destination;

            for (destination = 0; destination != 32; ++destination) {
                unsigned int source;

                for (source = 0; source != 8; ++source) {
                    uint8_t code[8];
                    size_t size = make_mask_broadcast_encoding(
                        test, length, destination, source, code);
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                        code, size,
                        CDISASM_X86_DECODE_FLAG_AVX512_CD,
                        &decoded_size);

                    ++accepted64;
                    EXPECT(decoded_size == size);
                    EXPECT(instruction.name_id == test->name_id);
                    EXPECT(instruction.opcode[0].reg
                        == vector_register(destination, vector_bits));
                    EXPECT(instruction.opcode[1].reg
                        == (cdisasm_x86_reg_id)(
                            CDISASM_X86_REG_K0 + source));
                    EXPECT(instruction.opcode[1].size
                        == test->source_bits / 8u);
                    expect_avx512_groups(&instruction, length);
                }
            }

            for (destination = 0; destination != 8; ++destination) {
                unsigned int source;

                for (source = 0; source != 8; ++source) {
                    uint8_t code[8];
                    size_t size = make_mask_broadcast_encoding(
                        test, length, destination, source, code);
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_32,
                        code, size,
                        CDISASM_X86_DECODE_FLAG_AVX512_CD,
                        &decoded_size);

                    ++accepted32;
                    EXPECT(decoded_size == size);
                    EXPECT(instruction.name_id == test->name_id);
                    EXPECT(instruction.opcode[0].reg
                        == vector_register(destination, vector_bits));
                    EXPECT(instruction.opcode[1].reg
                        == (cdisasm_x86_reg_id)(
                            CDISASM_X86_REG_K0 + source));
                }
            }
        }
    }
    EXPECT(accepted64 == 1536u);
    EXPECT(accepted32 == 384u);
}

static void test_mask_broadcast_runtime_avx10_and_apx(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cd_mask_broadcast_cases)
            / sizeof(cd_mask_broadcast_cases[0]);
         ++case_index) {
        const cd_mask_broadcast_case *test =
            &cd_mask_broadcast_cases[case_index];
        uint8_t code[8];
        size_t size = make_mask_broadcast_encoding(
            test, 2u, 1u, 3u, code);
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
            code, size, CDISASM_X86_DECODE_FLAG_AVX512,
            &decoded_size);
        EXPECT(decoded_size == size);
        EXPECT(instruction.name_id == test->name_id);

        expect_status("unrelated flag rejects AVX512CD mask broadcast",
            CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_status("pre-AVX512 CPU lacks AVX512CD mask broadcast",
            CDISASM_CPU_HASWELL, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_AVX512_CD,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
            code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
            &decoded_size);
        EXPECT(decoded_size == size);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512CD));

        /* EVEX.B and EVEX.X do not extend a K register selected by rm3. */
        code[1] &= (uint8_t)~UINT8_C(0x20);
        instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
            code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
            &decoded_size);
        EXPECT(decoded_size == size);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_K3);
        code[1] |= UINT8_C(0x20);
        code[1] &= (uint8_t)~UINT8_C(0x40);
        instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
            code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
            &decoded_size);
        EXPECT(decoded_size == size);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_K3);

        size = make_mask_broadcast_encoding(
            test, 2u, 1u, 3u, code);
        code[1] |= UINT8_C(0x08);
        instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
            code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
            &decoded_size);
        EXPECT(decoded_size == size);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_K3);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));

        expect_status("AVX512CD mask broadcast B4 needs APX CPU",
            CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_AVX512_CD,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_status("AVX512CD mask broadcast B4 mode32 reserved",
            CDISASM_CPU_APX, CDISASM_MODE_32, code, size,
            CDISASM_X86_DECODE_FLAG_AVX512_CD,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_runtime_features_and_avx10(void)
{
    static const uint8_t vpconflictd[] = {
        0x62, 0xf2, 0x7d, 0x48, 0xc4, 0xcb
    };
    cdisasm_x86_decode_option cpu_flags;
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    cpu_flags = cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512) != 0);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512_CD) != 0);
    EXPECT((cpu_flags & ~CDISASM_X86_DECODE_FLAG_KNOWN_MASK) == 0);

    instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vpconflictd, sizeof(vpconflictd),
        CDISASM_X86_DECODE_FLAG_AVX512_CD, &decoded_size);
    EXPECT(decoded_size == sizeof(vpconflictd));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPCONFLICTD);
    instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vpconflictd, sizeof(vpconflictd),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
    EXPECT(decoded_size == sizeof(vpconflictd));

    expect_status("unrelated granular flag rejects AVX512CD",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vpconflictd, sizeof(vpconflictd),
        CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("pre-AVX512 CPU lacks AVX512CD",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        vpconflictd, sizeof(vpconflictd),
        CDISASM_X86_DECODE_FLAG_AVX512_CD,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        vpconflictd, sizeof(vpconflictd),
        CDISASM_X86_DECODE_FLAG_AVX512_CD, &decoded_size);
    EXPECT(decoded_size == sizeof(vpconflictd));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512CD));
    cpu_flags = cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_AVX10, CDISASM_MODE_64);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX10) != 0);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512_CD) != 0);
}

static void test_complete_decorator_matrix(void)
{
    size_t case_index;
    unsigned int accepted = 0;

    for (case_index = 0;
         case_index < sizeof(cd_cases) / sizeof(cd_cases[0]);
         ++case_index) {
        const cd_case *test = &cd_cases[case_index];
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            const unsigned int vector_bits = 128u << length;
            unsigned int source_kind;

            for (source_kind = 0; source_kind != 3; ++source_kind) {
                int mask_mode;

                for (mask_mode = 0; mask_mode != 3; ++mask_mode) {
                    const int memory = source_kind != 0u;
                    const int broadcast = source_kind == 2u;
                    uint8_t code[8];
                    size_t size = make_encoding(test, length, memory,
                        broadcast, mask_mode, code);
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                        code, size,
                        CDISASM_X86_DECODE_FLAG_AVX512_CD,
                        &decoded_size);

                    ++accepted;
                    EXPECT(decoded_size == size);
                    EXPECT(instruction.name_id == test->name_id);
                    EXPECT(instruction.mask_mode
                        == (mask_mode == 0 ? CDISASM_X86_MASK_NONE
                            : (mask_mode == 1
                                ? CDISASM_X86_MASK_MERGE
                                : CDISASM_X86_MASK_ZERO)));
                    EXPECT(instruction.opcode[0].access
                        == (mask_mode == 1
                            ? CDISASM_OPERAND_ACCESS_READ_WRITE
                            : CDISASM_OPERAND_ACCESS_WRITE));
                    EXPECT(instruction.opcode[1].type
                        == (memory ? CDISASM_OPERAND_MEMORY
                                   : CDISASM_OPERAND_REGISTER));
                    EXPECT(instruction.opcode[1].size
                        == (broadcast ? test->element_bits / 8u
                                      : vector_bits / 8u));
                    EXPECT(instruction.opcode[1].broadcast
                        == (broadcast
                            ? (cdisasm_x86_broadcast)(
                                vector_bits / test->element_bits)
                            : CDISASM_X86_BROADCAST_NONE));
                }
            }
        }
    }
    EXPECT(accepted == 108u);
}

static void test_legacy_evex_in_mode32(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cd_cases) / sizeof(cd_cases[0]);
         ++case_index) {
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            uint8_t code[8];
            size_t size = make_encoding(
                &cd_cases[case_index], length, 0, 0, 0, code);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_32,
                code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
                &decoded_size);

            EXPECT(decoded_size == size);
            EXPECT(instruction.name_id == cd_cases[case_index].name_id);
            expect_avx512_groups(&instruction, length);
        }
    }
}

static void test_diamond_rapids_apx_oracle(void)
{
    size_t case_index;
    unsigned int accepted = 0;
    unsigned int rejected = 0;

    for (case_index = 0;
         case_index < sizeof(cd_cases) / sizeof(cd_cases[0]);
         ++case_index) {
        const cd_case *test = &cd_cases[case_index];
        uint8_t code[8];
        size_t size = make_encoding(test, 2, 0, 0, 0, code);
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        code[1] |= UINT8_C(0x08);
        instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
            code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
            &decoded_size);
        ++accepted;
        EXPECT(decoded_size == size);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ZMM3);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));

        size = make_encoding(test, 2, 1, 0, 0, code);
        code[1] |= UINT8_C(0x08);
        instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
            code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
            &decoded_size);
        ++accepted;
        EXPECT(decoded_size == size);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R19);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));

        size = make_encoding(test, 2, 1, 0, 0, code);
        code[2] &= (uint8_t)~UINT8_C(0x04);
        code[5] = UINT8_C(0x0b);
        instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
            code, 6u, CDISASM_X86_DECODE_FLAG_AVX512_CD,
            &decoded_size);
        ++accepted;
        EXPECT(decoded_size == 6u);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RBX);
        EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_NONE);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));

        size = make_encoding(test, 2, 1, 0, 0, code);
        code[2] &= (uint8_t)~UINT8_C(0x04);
        code[5] = UINT8_C(0x0c);
        code[6] = UINT8_C(0x03);
        instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
            code, 7u, CDISASM_X86_DECODE_FLAG_AVX512_CD,
            &decoded_size);
        ++accepted;
        EXPECT(decoded_size == 7u);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RBX);
        EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R16);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));

        code[1] |= UINT8_C(0x08);
        instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
            code, 7u, CDISASM_X86_DECODE_FLAG_AVX512_CD,
            &decoded_size);
        ++accepted;
        EXPECT(decoded_size == 7u);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R19);
        EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R16);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));

        size = make_encoding(test, 2, 0, 0, 0, code);
        code[2] &= (uint8_t)~UINT8_C(0x04);
        ++rejected;
        expect_status("AVX512CD U0 register reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2, 0, 0, 0, code);
        code[1] |= UINT8_C(0x08);
        ++rejected;
        expect_status("AVX512CD APX B4 non-64 reserved",
            CDISASM_CPU_APX, CDISASM_MODE_32, code, size,
            CDISASM_X86_DECODE_FLAG_AVX512_CD,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2, 1, 0, 0, code);
        code[2] &= (uint8_t)~UINT8_C(0x04);
        ++rejected;
        expect_status("AVX512CD APX U0 memory non-64 reserved",
            CDISASM_CPU_APX, CDISASM_MODE_32, code, size,
            CDISASM_X86_DECODE_FLAG_AVX512_CD,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    EXPECT(accepted == 20u);
    EXPECT(rejected == 12u);
}
#endif

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
    uint8_t code[8];
    size_t size = make_encoding(&cd_cases[0], 2, 1, 1, 2, code);
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
        &decoded_size);

    EXPECT(decoded_size == size);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpconflictd zmm1 {k2}{z}, dword ptr [rbx + 0x8]{1to16}");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpconflictd 0x8(%rbx){1to16}, %zmm1{%k2}{z}");

    size = make_encoding(&cd_cases[3], 2, 1, 0, 1, code);
    instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
        &decoded_size);
    EXPECT(decoded_size == size);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vplzcntq zmm1 {k2}, zmmword ptr [rbx + 0x80]");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vplzcntq 0x80(%rbx), %zmm1{%k2}");

    size = make_mask_broadcast_encoding(
        &cd_mask_broadcast_cases[0], 2u, 1u, 3u, code);
    instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
        &decoded_size);
    EXPECT(decoded_size == size);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpbroadcastmb2q zmm1, k3");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpbroadcastmb2q %k3, %zmm1");

    size = make_mask_broadcast_encoding(
        &cd_mask_broadcast_cases[1], 1u, 17u, 7u, code);
    instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512_CD,
        &decoded_size);
    EXPECT(decoded_size == size);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL
            | CDISASM_FORMAT_UPPERCASE_OPCODE,
        "VPBROADCASTMW2D ymm17, k7");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpbroadcastmw2d %k7, %ymm17");
}
#endif

int main(void)
{
    test_names_lengths_memory_broadcast_masks();
    test_mask_broadcast_lengths_and_operands();
    test_reserved_controls_and_truncation();
    test_mask_broadcast_reserved_controls_and_truncation();
#if USE_EXTRA_OPCODES
    test_mask_broadcast_complete_register_space();
    test_mask_broadcast_runtime_avx10_and_apx();
    test_runtime_features_and_avx10();
    test_complete_decorator_matrix();
    test_legacy_evex_in_mode32();
    test_diamond_rapids_apx_oracle();
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d AVX512CD test(s) failed\n", failures);
        return 1;
    }
    puts("x86 EVEX AVX512CD tests passed");
    return 0;
}
