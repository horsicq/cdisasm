#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct popcount_case {
    uint8_t opcode;
    uint8_t w;
    uint8_t element_bits;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_group_id feature_group;
    cdisasm_x86_decode_option runtime_flag;
    const char *mnemonic;
} popcount_case;

static const popcount_case popcount_cases[] = {
    {0x54, 0, 8, CDISASM_X86_NAME_VPOPCNTB,
        CDISASM_X86_GROUP_AVX512BITALG,
        CDISASM_X86_DECODE_FLAG_AVX512_BITALG, "vpopcntb"},
    {0x54, 1, 16, CDISASM_X86_NAME_VPOPCNTW,
        CDISASM_X86_GROUP_AVX512BITALG,
        CDISASM_X86_DECODE_FLAG_AVX512_BITALG, "vpopcntw"},
    {0x55, 0, 32, CDISASM_X86_NAME_VPOPCNTD,
        CDISASM_X86_GROUP_AVX512VPOPCNTDQ,
        CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ, "vpopcntd"},
    {0x55, 1, 64, CDISASM_X86_NAME_VPOPCNTQ,
        CDISASM_X86_GROUP_AVX512VPOPCNTDQ,
        CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ, "vpopcntq"}
};

_Static_assert(CDISASM_X86_NAME_VPOPCNTD == UINT16_C(716),
    "established VPOPCNTD ID changed");
_Static_assert(CDISASM_X86_NAME_VPOPCNTB == UINT16_C(1085)
        && CDISASM_X86_NAME_VPOPCNTW == UINT16_C(1086)
        && CDISASM_X86_NAME_VPOPCNTQ == UINT16_C(1087)
        && CDISASM_X86_NAME_VPSHUFBITQMB == UINT16_C(1088),
    "BITALG/popcount appended IDs changed");
_Static_assert(CDISASM_X86_NAME_VGETEXPBF16 < CDISASM_X86_NAME_COUNT
        && CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1),
    "BITALG/popcount catalog is incomplete");
_Static_assert(CDISASM_NAME_VPOPCNTB == CDISASM_X86_NAME_VPOPCNTB
        && CDISASM_NAME_VPSHUFBITQMB
            == CDISASM_X86_NAME_VPSHUFBITQMB,
    "legacy BITALG/popcount aliases changed");

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",          \
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

static size_t make_popcount(
    const popcount_case *test,
    unsigned int length,
    int memory,
    int broadcast,
    int mask_mode,
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
    code[1] = UINT8_C(0xf2);
    code[2] = test->w != 0 ? UINT8_C(0xfd) : UINT8_C(0x7d);
    code[3] = p2;
    code[4] = test->opcode;
    code[5] = memory ? UINT8_C(0x4b) : UINT8_C(0xcb);
    if (memory) {
        code[size++] = UINT8_C(2);
    }
    return size;
}

static size_t make_bitshuffle(
    unsigned int length,
    int memory,
    int mask,
    uint8_t code[8])
{
    code[0] = UINT8_C(0x62);
    code[1] = UINT8_C(0xf2);
    code[2] = UINT8_C(0x6d);
    code[3] = (uint8_t)(UINT8_C(0x08) | (length << 5)
        | (mask ? UINT8_C(0x02) : 0u));
    code[4] = UINT8_C(0x8f);
    code[5] = memory ? UINT8_C(0x4b) : UINT8_C(0xcb);
    if (memory) {
        code[6] = UINT8_C(2);
        return 7u;
    }
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

static void expect_groups(
    const cdisasm_instruction *instruction,
    cdisasm_x86_group_id feature,
    unsigned int length)
{
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, feature));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512VL) == (length != 2u));
}
#endif

static void test_popcount_names_lengths_memory_and_broadcast(void)
{
    size_t case_index;
    unsigned int decoded = 0;

    for (case_index = 0;
         case_index < sizeof(popcount_cases) / sizeof(popcount_cases[0]);
         ++case_index) {
        const popcount_case *test = &popcount_cases[case_index];
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            const unsigned int vector_bits = 128u << length;
            uint8_t code[8];
            size_t size = make_popcount(test, length, 0, 0, 0, code);

            ++decoded;
#if USE_EXTRA_OPCODES
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
                    code, size, test->runtime_flag, &decoded_size);

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
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                expect_groups(&instruction, test->feature_group, length);
            }
#else
            (void)vector_bits;
            expect_status("extra-opcodes OFF popcount register",
                CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

            size = make_popcount(test, length, 1, 0, 1, code);
            ++decoded;
#if USE_EXTRA_OPCODES
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
                    code, size, test->runtime_flag, &decoded_size);

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
                expect_groups(&instruction, test->feature_group, length);
            }
#endif

            size = make_popcount(test, length, 1, 1, 2, code);
            if (test->element_bits <= 16u) {
                expect_status("byte/word popcount broadcast reserved",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, size, CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            } else {
#if USE_EXTRA_OPCODES
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
                    code, size, test->runtime_flag, &decoded_size);

                EXPECT(decoded_size == size);
                EXPECT(instruction.name_id == test->name_id);
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
#else
                expect_status("extra-opcodes OFF popcount broadcast",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, size, CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            }
        }
    }
    EXPECT(decoded == 24u);
}

static void test_bitshuffle_lengths_memory_and_masks(void)
{
    unsigned int length;

    for (length = 0; length != 3; ++length) {
        const unsigned int vector_bits = 128u << length;
        uint8_t code[8];
        size_t size = make_bitshuffle(length, 0, 0, code);

#if USE_EXTRA_OPCODES
        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_AVX512_BITALG, &decoded_size);

            EXPECT(decoded_size == size);
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VPSHUFBITQMB);
            EXPECT(instruction.operand_count == 3u);
            EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
            EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_K1);
            EXPECT(instruction.opcode[0].size == vector_bits / 64u);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.opcode[1].reg
                == vector_register(2u, vector_bits));
            EXPECT(instruction.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.opcode[2].reg
                == vector_register(3u, vector_bits));
            EXPECT(instruction.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            expect_groups(&instruction,
                CDISASM_X86_GROUP_AVX512BITALG, length);
        }
#else
        (void)vector_bits;
        expect_status("extra-opcodes OFF VPSHUFBITQMB register",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

        size = make_bitshuffle(length, 1, 1, code);
#if USE_EXTRA_OPCODES
        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_AVX512_BITALG, &decoded_size);

            EXPECT(decoded_size == size);
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VPSHUFBITQMB);
            EXPECT(instruction.mask_reg == CDISASM_X86_REG_K2);
            EXPECT(instruction.mask_mode == CDISASM_X86_MASK_MERGE);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
            EXPECT(instruction.opcode[2].base_reg
                == CDISASM_X86_REG_RBX);
            EXPECT(instruction.opcode[2].size == vector_bits / 8u);
            EXPECT(instruction.opcode[2].imm
                == UINT64_C(2) * (vector_bits / 8u));
            EXPECT(instruction.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
#endif
    }
}

static void test_reserved_controls_and_truncation(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(popcount_cases) / sizeof(popcount_cases[0]);
         ++case_index) {
        const popcount_case *test = &popcount_cases[case_index];
        uint8_t code[8];
        size_t size = make_popcount(test, 2, 0, 0, 0, code);

        code[2] &= (uint8_t)~UINT8_C(0x08);
        expect_status("popcount noncanonical EVEX.vvvv",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        size = make_popcount(test, 2, 0, 1, 0, code);
        expect_status("popcount register EVEX.b reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        size = make_popcount(test, 2, 0, 0, 0, code);
        code[3] = (uint8_t)((code[3] & UINT8_C(0x9f)) | UINT8_C(0x60));
        expect_status("popcount LL=3 reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    {
        uint8_t code[8];
        size_t size = make_bitshuffle(2, 0, 1, code);

        code[3] |= UINT8_C(0x80);
        expect_status("VPSHUFBITQMB zeroing reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        size = make_bitshuffle(2, 0, 0, code);
        code[2] |= UINT8_C(0x80);
        expect_status("VPSHUFBITQMB W=1 reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        size = make_bitshuffle(2, 0, 0, code);
        code[1] &= (uint8_t)~UINT8_C(0x80);
        expect_status("VPSHUFBITQMB P0.R canonical",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        size = make_bitshuffle(2, 0, 0, code);
        code[1] &= (uint8_t)~UINT8_C(0x10);
        expect_status("VPSHUFBITQMB P0.R-prime canonical",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        size = make_bitshuffle(2, 1, 0, code);
        code[3] |= UINT8_C(0x10);
        expect_status("VPSHUFBITQMB EVEX.b reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        size = make_bitshuffle(2, 0, 0, code);
        code[3] = (uint8_t)((code[3] & UINT8_C(0x9f)) | UINT8_C(0x60));
        expect_status("VPSHUFBITQMB LL=3 reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    {
        static const uint8_t popcount_missing_modrm[] = {
            0x62, 0xf2, 0x7d, 0x48, 0x54
        };
        static const uint8_t bitshuffle_missing_disp8[] = {
            0x62, 0xf2, 0x6d, 0x48, 0x8f, 0x4b
        };

        expect_status("popcount missing ModRM",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            popcount_missing_modrm, sizeof(popcount_missing_modrm),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        expect_status("VPSHUFBITQMB missing disp8",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            bitshuffle_missing_disp8, sizeof(bitshuffle_missing_disp8),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    }
}

#if USE_EXTRA_OPCODES
static void test_runtime_features_and_avx10(void)
{
    static const uint8_t vpopcntb[] = {
        0x62, 0xf2, 0x7d, 0x48, 0x54, 0xcb
    };
    static const uint8_t vpopcntq[] = {
        0x62, 0xf2, 0xfd, 0x48, 0x55, 0xcb
    };
    static const uint8_t vpshufbitqmb[] = {
        0x62, 0xf2, 0x6d, 0x48, 0x8f, 0xcb
    };
    cdisasm_x86_decode_option cpu_flags =
        cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512) != 0);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512_BITALG) != 0);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ) != 0);

    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        vpopcntb, sizeof(vpopcntb),
        CDISASM_X86_DECODE_FLAG_AVX512_BITALG, &decoded_size);
    EXPECT(decoded_size == sizeof(vpopcntb));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPOPCNTB);
    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        vpopcntq, sizeof(vpopcntq),
        CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ, &decoded_size);
    EXPECT(decoded_size == sizeof(vpopcntq));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPOPCNTQ);
    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        vpshufbitqmb, sizeof(vpshufbitqmb),
        CDISASM_X86_DECODE_FLAG_AVX512_BITALG, &decoded_size);
    EXPECT(decoded_size == sizeof(vpshufbitqmb));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPSHUFBITQMB);

    expect_status("VPOPCNTDQ flag rejects BITALG popcount",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        vpopcntb, sizeof(vpopcntb),
        CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("BITALG flag rejects VPOPCNTDQ",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        vpopcntq, sizeof(vpopcntq),
        CDISASM_X86_DECODE_FLAG_AVX512_BITALG,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        vpopcntb, sizeof(vpopcntb),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
    EXPECT(decoded_size == sizeof(vpopcntb));
    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        vpopcntq, sizeof(vpopcntq),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
    EXPECT(decoded_size == sizeof(vpopcntq));
    expect_status("Skylake-SP lacks BITALG",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vpopcntb, sizeof(vpopcntb),
        CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("Skylake-SP lacks VPOPCNTDQ",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vpopcntq, sizeof(vpopcntq),
        CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        vpshufbitqmb, sizeof(vpshufbitqmb),
        CDISASM_X86_DECODE_FLAG_AVX512_BITALG, &decoded_size);
    EXPECT(decoded_size == sizeof(vpshufbitqmb));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512BITALG));
    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        vpopcntq, sizeof(vpopcntq),
        CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ, &decoded_size);
    EXPECT(decoded_size == sizeof(vpopcntq));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
}

static void test_diamond_rapids_apx_oracle(void)
{
    unsigned int row;
    unsigned int accepted = 0;
    unsigned int rejected = 0;

    for (row = 0; row != 5; ++row) {
        const int bitshuffle = row == 4u;
        uint8_t code[8];
        size_t size;
        uint32_t decoded_size;
        cdisasm_instruction instruction;
        cdisasm_x86_name_id expected_name;
        cdisasm_x86_decode_option flag;

        if (bitshuffle) {
            size = make_bitshuffle(2, 0, 0, code);
            expected_name = CDISASM_X86_NAME_VPSHUFBITQMB;
            flag = CDISASM_X86_DECODE_FLAG_AVX512_BITALG;
        } else {
            const popcount_case *test = &popcount_cases[row];

            size = make_popcount(test, 2, 0, 0, 0, code);
            expected_name = test->name_id;
            flag = test->runtime_flag;
        }
        code[1] |= UINT8_C(0x08);
        instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
            code, size, flag, &decoded_size);
        ++accepted;
        EXPECT(decoded_size == size);
        EXPECT(instruction.name_id == expected_name);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));

        if (bitshuffle) {
            size = make_bitshuffle(2, 1, 0, code);
        } else {
            size = make_popcount(&popcount_cases[row], 2, 1, 0, 0, code);
        }
        code[1] |= UINT8_C(0x08);
        instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
            code, size, flag, &decoded_size);
        ++accepted;
        EXPECT(decoded_size == size);
        EXPECT(instruction.opcode[bitshuffle ? 2 : 1].base_reg
            == CDISASM_X86_REG_R19);

        if (bitshuffle) {
            size = make_bitshuffle(2, 1, 0, code);
        } else {
            size = make_popcount(&popcount_cases[row], 2, 1, 0, 0, code);
        }
        code[2] &= (uint8_t)~UINT8_C(0x04);
        code[5] = bitshuffle ? UINT8_C(0x0c) : UINT8_C(0x0c);
        code[6] = UINT8_C(0x03);
        instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
            code, 7u, flag, &decoded_size);
        ++accepted;
        EXPECT(decoded_size == 7u);
        EXPECT(instruction.opcode[bitshuffle ? 2 : 1].base_reg
            == CDISASM_X86_REG_RBX);
        EXPECT(instruction.opcode[bitshuffle ? 2 : 1].index_reg
            == CDISASM_X86_REG_R16);

        code[1] |= UINT8_C(0x08);
        instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
            code, 7u, flag, &decoded_size);
        ++accepted;
        EXPECT(decoded_size == 7u);
        EXPECT(instruction.opcode[bitshuffle ? 2 : 1].base_reg
            == CDISASM_X86_REG_R19);
        EXPECT(instruction.opcode[bitshuffle ? 2 : 1].index_reg
            == CDISASM_X86_REG_R16);

        if (bitshuffle) {
            size = make_bitshuffle(2, 0, 0, code);
        } else {
            size = make_popcount(&popcount_cases[row], 2, 0, 0, 0, code);
        }
        code[2] &= (uint8_t)~UINT8_C(0x04);
        ++rejected;
        expect_status("BITALG/popcount U0 register reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    EXPECT(accepted == 20u);
    EXPECT(rejected == 5u);
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
    size_t size = make_popcount(&popcount_cases[3], 2, 1, 1, 2, code);
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64, code, size,
        CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ, &decoded_size);

    EXPECT(decoded_size == size);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpopcntq zmm1 {k2}{z}, qword ptr [rbx + 0x10]{1to8}");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpopcntq 0x10(%rbx){1to8}, %zmm1{%k2}{z}");

    size = make_bitshuffle(2, 1, 1, code);
    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512_BITALG,
        &decoded_size);
    EXPECT(decoded_size == size);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpshufbitqmb k1 {k2}, zmm2, zmmword ptr [rbx + 0x80]");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpshufbitqmb 0x80(%rbx), %zmm2, %k1{%k2}");
}
#endif

int main(void)
{
    test_popcount_names_lengths_memory_and_broadcast();
    test_bitshuffle_lengths_memory_and_masks();
    test_reserved_controls_and_truncation();
#if USE_EXTRA_OPCODES
    test_runtime_features_and_avx10();
    test_diamond_rapids_apx_oracle();
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d BITALG/popcount test(s) failed\n", failures);
        return 1;
    }
    puts("x86 EVEX BITALG/popcount tests passed");
    return 0;
}
