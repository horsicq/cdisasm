#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct compress_expand_case {
    uint8_t opcode;
    uint8_t w;
    uint8_t element_bits;
    uint8_t compress;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
    cdisasm_x86_form_id form_base;
} compress_expand_case;

static const compress_expand_case cases[] = {
    {0x63, 0, 8, 1, CDISASM_X86_NAME_VPCOMPRESSB,
        "vpcompressb", 0},
    {0x63, 1, 16, 1, CDISASM_X86_NAME_VPCOMPRESSW,
        "vpcompressw", 0},
    {0x8b, 0, 32, 1, CDISASM_X86_NAME_VPCOMPRESSD,
        "vpcompressd", 0},
    {0x8b, 1, 64, 1, CDISASM_X86_NAME_VPCOMPRESSQ,
        "vpcompressq", 0},
    {0x62, 0, 8, 0, CDISASM_X86_NAME_VPEXPANDB,
        "vpexpandb", 0},
    {0x62, 1, 16, 0, CDISASM_X86_NAME_VPEXPANDW,
        "vpexpandw", 0},
    {0x89, 0, 32, 0, CDISASM_X86_NAME_VPEXPANDD,
        "vpexpandd", 0},
    {0x89, 1, 64, 0, CDISASM_X86_NAME_VPEXPANDQ,
        "vpexpandq", 0},
    {0x8a, 1, 64, 1, CDISASM_X86_NAME_VCOMPRESSPD,
        "vcompresspd", UINT16_C(3637)},
    {0x8a, 0, 32, 1, CDISASM_X86_NAME_VCOMPRESSPS,
        "vcompressps", UINT16_C(3643)},
    {0x88, 1, 64, 0, CDISASM_X86_NAME_VEXPANDPD,
        "vexpandpd", UINT16_C(4527)},
    {0x88, 0, 32, 0, CDISASM_X86_NAME_VEXPANDPS,
        "vexpandps", UINT16_C(4533)}
};

_Static_assert(CDISASM_X86_NAME_VPCOMPRESSB == UINT16_C(1077),
    "compress/expand catalog start changed");
_Static_assert(CDISASM_X86_NAME_VPEXPANDQ == UINT16_C(1084),
    "compress/expand catalog end changed");
_Static_assert(CDISASM_X86_NAME_COUNT >= UINT16_C(1085),
    "compress/expand catalog is incomplete");
_Static_assert(CDISASM_X86_NAME_VCOMPRESSPD == UINT16_C(1505)
        && CDISASM_X86_NAME_VCOMPRESSPS == UINT16_C(1506)
        && CDISASM_X86_NAME_VEXPANDPD == UINT16_C(1644)
        && CDISASM_X86_NAME_VEXPANDPS == UINT16_C(1645),
    "floating compress/expand catalog IDs changed");
_Static_assert(CDISASM_X86_NAME_COUNT >= UINT16_C(1646),
    "floating compress/expand catalog is incomplete");
_Static_assert(CDISASM_NAME_VPCOMPRESSB == CDISASM_X86_NAME_VPCOMPRESSB
        && CDISASM_NAME_VPEXPANDQ == CDISASM_X86_NAME_VPEXPANDQ,
    "legacy compress/expand aliases changed");
_Static_assert(CDISASM_NAME_VCOMPRESSPD == CDISASM_X86_NAME_VCOMPRESSPD
        && CDISASM_NAME_VCOMPRESSPS == CDISASM_X86_NAME_VCOMPRESSPS
        && CDISASM_NAME_VEXPANDPD == CDISASM_X86_NAME_VEXPANDPD
        && CDISASM_NAME_VEXPANDPS == CDISASM_X86_NAME_VEXPANDPS,
    "legacy floating compress/expand aliases changed");
_Static_assert(
    CDISASM_X86_DECODE_FLAG_AVX512_VBMI2 == UINT64_C(0x200000000)
        && CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ
            == UINT64_C(0x400000000)
        && CDISASM_X86_DECODE_FLAG_AVX512_BITALG
            == UINT64_C(0x800000000)
        && CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND
            == UINT64_C(0x1000000000)
        && (CDISASM_X86_DECODE_FLAG_KNOWN_MASK
                & UINT64_C(0x1fffffffff))
            == UINT64_C(0x1fffffffff),
    "x86 specific AVX-512 runtime flags changed");
_Static_assert(
    CDISASM_X86_DECODE_USE_AVX512_VBMI2
            == CDISASM_X86_DECODE_FLAG_AVX512_VBMI2
        && CDISASM_X86_DECODE_USE_AVX512_VPOPCNTDQ
            == CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ
        && CDISASM_X86_DECODE_USE_AVX512_BITALG
            == CDISASM_X86_DECODE_FLAG_AVX512_BITALG
        && CDISASM_X86_DECODE_USE_COMPRESS_EXPAND
            == CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
    "x86 specific AVX-512 USE aliases changed");

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
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact_flags =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(flags);
    const cdisasm_x86_decode_flags *selected_flags = flags != 0u
        ? &exact_flags : NULL;
    size_t offset;

    /* Floating compress/expand now preserves its pinned width-specific
     * AVX512F ISA_SET.  The compatibility word-0 family remains necessary,
     * but exact decoding must also opt into that form's bitmap-2 width bit. */
    for (offset = 0u; offset + 4u < size; ++offset) {
        if (code[offset] == UINT8_C(0x62)
            && (code[offset + 1u] & UINT8_C(7)) == UINT8_C(2)
            && (code[offset + 4u] == UINT8_C(0x88)
                || code[offset + 4u] == UINT8_C(0x8a))) {
            const unsigned int length =
                ((unsigned int)code[offset + 3u] >> 5) & 3u;
            const cdisasm_x86_decode_bit_id bit = length == 0u
                ? CDISASM_X86_DECODE_BIT_AVX512F_128
                : length == 1u ? CDISASM_X86_DECODE_BIT_AVX512F_256
                               : CDISASM_X86_DECODE_BIT_AVX512F_512;

            if (length < 3u) {
                EXPECT(cdisasm_decode_flags_set_bit(&exact_flags, bit));
                selected_flags = &exact_flags;
            }
            break;
        }
    }
#else
    (void)flags;
#endif

    memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
    *decoded_size = cdisasm_test_x86_decode_exact_flags(
        cpu, mode, code, size, UINT64_C(0x1000),
#if USE_EXTRA_OPCODES
        selected_flags,
#else
        NULL,
#endif
        &instruction);
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
    const compress_expand_case *test,
    unsigned int length,
    int memory,
    int mask_mode,
    int evex_b,
    uint8_t code[8])
{
    uint8_t p2 = (uint8_t)(UINT8_C(0x08) | (length << 5));
    size_t size = 6u;

    if (mask_mode != 0) {
        p2 |= UINT8_C(0x02);
    }
    if (mask_mode == 2) {
        p2 |= UINT8_C(0x80);
    }
    if (evex_b) {
        p2 |= UINT8_C(0x10);
    }
    code[0] = UINT8_C(0x62);
    code[1] = UINT8_C(0xf2);
    code[2] = test->w != 0 ? UINT8_C(0xfd) : UINT8_C(0x7d);
    code[3] = p2;
    code[4] = test->opcode;
    code[5] = test->compress
        ? (memory ? UINT8_C(0x53) : UINT8_C(0xd1))
        : (memory ? UINT8_C(0x4b) : UINT8_C(0xcb));
    if (memory) {
        code[size++] = UINT8_C(2);
    }
    return size;
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_form_id expected_form(
    const compress_expand_case *test,
    unsigned int length,
    int memory)
{
    if (test->form_base == 0u) {
        return 0u;
    }
    if (test->compress) {
        return (cdisasm_x86_form_id)(
            test->form_base + (memory ? 0u : 3u) + length);
    }
    return (cdisasm_x86_form_id)(
        test->form_base + 2u * length + (memory ? 0u : 1u));
}
#endif

#if USE_EXTRA_OPCODES
static size_t make_apx_encoding(
    const compress_expand_case *test,
    int b4,
    int u0,
    int memory,
    uint8_t code[8])
{
    code[0] = UINT8_C(0x62);
    code[1] = (uint8_t)(UINT8_C(0xf2) | (b4 ? UINT8_C(0x08) : 0u));
    code[2] = test->w != 0 ? UINT8_C(0xfd) : UINT8_C(0x7d);
    if (u0) {
        code[2] &= (uint8_t)~UINT8_C(0x04);
    }
    code[3] = UINT8_C(0x48);
    code[4] = test->opcode;
    if (!memory) {
        code[5] = test->compress ? UINT8_C(0xd1) : UINT8_C(0xcb);
        return 6u;
    }
    if (u0) {
        code[5] = test->compress ? UINT8_C(0x14) : UINT8_C(0x0c);
        code[6] = UINT8_C(0x03);
        return 7u;
    }
    code[5] = test->compress ? UINT8_C(0x13) : UINT8_C(0x0b);
    return 6u;
}
#endif

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

static cdisasm_cpu_id legacy_cpu(const compress_expand_case *test)
{
    return test->element_bits <= 16u
        ? CDISASM_CPU_ICE_LAKE : CDISASM_CPU_SKYLAKE_SP;
}

static void expect_register_shape(
    const compress_expand_case *test,
    const cdisasm_instruction *instruction,
    unsigned int vector_bits,
    cdisasm_operand_access destination_access)
{
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == test->name_id);
    if (test->form_base != 0u) {
        const unsigned int length = vector_bits == 128u
            ? 0u : vector_bits == 256u ? 1u : 2u;

        EXPECT(instruction->form_id == expected_form(test, length, 0));
    }
    EXPECT(instruction->operand_count == 2u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg == vector_register(1u, vector_bits));
    EXPECT(instruction->opcode[0].size == vector_bits / 8u);
    EXPECT(instruction->opcode[0].access == destination_access);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg == vector_register(
        test->compress ? 2u : 3u, vector_bits));
    EXPECT(instruction->opcode[1].size == vector_bits / 8u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0);
}

static void expect_legacy_groups(
    const compress_expand_case *test,
    const cdisasm_instruction *instruction,
    unsigned int length)
{
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512VL) == (length != 2u));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512VBMI2)
        == (test->element_bits <= 16u));
    if (test->form_base != 0u) {
        const cdisasm_x86_group_id exact_width = length == 0u
            ? CDISASM_X86_GROUP_AVX512F_128
            : length == 1u ? CDISASM_X86_GROUP_AVX512F_256
                           : CDISASM_X86_GROUP_AVX512F_512;

        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, exact_width));
        EXPECT(instruction->x86_group_count != 0u);
        EXPECT(instruction->x86_group_ids[
            instruction->x86_group_count - 1u] == exact_width);
    }
}

static void expect_mask_shape(
    const cdisasm_instruction *instruction,
    uint8_t p2)
{
    const unsigned int aaa = p2 & UINT8_C(0x07);

    EXPECT(instruction->mask_reg == (aaa == 0u
        ? CDISASM_X86_REG_NONE
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
    EXPECT(instruction->mask_mode == (aaa == 0u
        ? CDISASM_X86_MASK_NONE
        : (p2 & UINT8_C(0x80)) != 0u
            ? CDISASM_X86_MASK_ZERO : CDISASM_X86_MASK_MERGE));
}

static void expect_memory_shape(
    const compress_expand_case *test,
    const cdisasm_instruction *instruction,
    unsigned int length,
    uint8_t p2)
{
    const unsigned int vector_bits = 128u << length;
    const unsigned int memory_index = test->compress ? 0u : 1u;

    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == test->name_id);
    EXPECT(instruction->form_id == expected_form(test, length, 1));
    EXPECT(instruction->operand_count == 2u);
    EXPECT(instruction->opcode[memory_index].type
        == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction->opcode[memory_index].base_reg
        == CDISASM_X86_REG_RBX);
    EXPECT(instruction->opcode[memory_index].index_reg
        == CDISASM_X86_REG_NONE);
    EXPECT(instruction->opcode[memory_index].size == vector_bits / 8u);
    EXPECT(instruction->opcode[memory_index].imm
        == UINT64_C(2) * (test->element_bits / 8u));
    EXPECT(instruction->opcode[memory_index].broadcast
        == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[memory_index].access
        == (test->compress ? CDISASM_OPERAND_ACCESS_WRITE
                           : CDISASM_OPERAND_ACCESS_READ));
    EXPECT(instruction->opcode[0].access
        == (test->compress || instruction->mask_mode
                != CDISASM_X86_MASK_MERGE
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ_WRITE));
    EXPECT(instruction->opcode[1].access
        == CDISASM_OPERAND_ACCESS_READ);
    expect_mask_shape(instruction, p2);
}
#endif

static void test_all_names_lengths_memory_and_masks(void)
{
    size_t case_index;
    unsigned int decoded_cases = 0;

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        const compress_expand_case *test = &cases[case_index];
        unsigned int length;

        for (length = 0; length != 3; ++length) {
            uint8_t code[8];
            size_t size = make_encoding(test, length, 0, 0, 0, code);

            ++decoded_cases;
#if USE_EXTRA_OPCODES
            {
                const unsigned int vector_bits = 128u << length;
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    legacy_cpu(test), CDISASM_MODE_64, code, size,
                    CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
                    &decoded_size);

                EXPECT(decoded_size == size);
                expect_register_shape(test, &instruction, vector_bits,
                    CDISASM_OPERAND_ACCESS_WRITE);
                expect_legacy_groups(test, &instruction, length);
            }
#else
            expect_status("extra-opcodes OFF compress/expand register",
                CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

            size = make_encoding(test, length, 1, 1, 0, code);
            ++decoded_cases;
#if USE_EXTRA_OPCODES
            {
                const unsigned int vector_bits = 128u << length;
                const unsigned int memory_index = test->compress ? 0u : 1u;
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    legacy_cpu(test), CDISASM_MODE_64, code, size,
                    CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
                    &decoded_size);

                EXPECT(decoded_size == size);
                EXPECT(instruction.name_id == test->name_id);
                if (test->form_base != 0u) {
                    EXPECT(instruction.form_id
                        == expected_form(test, length, 1));
                }
                EXPECT(instruction.operand_count == 2u);
                EXPECT(instruction.mask_reg == CDISASM_X86_REG_K2);
                EXPECT(instruction.mask_mode == CDISASM_X86_MASK_MERGE);
                EXPECT(instruction.opcode[memory_index].type
                    == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[memory_index].base_reg
                    == CDISASM_X86_REG_RBX);
                EXPECT(instruction.opcode[memory_index].index_reg
                    == CDISASM_X86_REG_NONE);
                EXPECT(instruction.opcode[memory_index].size
                    == vector_bits / 8u);
                EXPECT(instruction.opcode[memory_index].imm
                    == UINT64_C(2) * (test->element_bits / 8u));
                EXPECT(instruction.opcode[memory_index].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                EXPECT(instruction.opcode[memory_index].access
                    == (test->compress ? CDISASM_OPERAND_ACCESS_WRITE
                                       : CDISASM_OPERAND_ACCESS_READ));
                EXPECT(instruction.opcode[0].access
                    == (test->compress ? CDISASM_OPERAND_ACCESS_WRITE
                                       : CDISASM_OPERAND_ACCESS_READ_WRITE));
                if (test->compress) {
                    EXPECT(instruction.opcode[1].reg
                        == vector_register(2u, vector_bits));
                    EXPECT(instruction.opcode[1].access
                        == CDISASM_OPERAND_ACCESS_READ);
                } else {
                    EXPECT(instruction.opcode[0].reg
                        == vector_register(1u, vector_bits));
                }
                expect_legacy_groups(test, &instruction, length);
            }
#else
            expect_status("extra-opcodes OFF compress/expand memory",
                CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
    EXPECT(decoded_cases == 72u);
}

static void test_decorators_reserved_controls_and_truncation(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        const compress_expand_case *test = &cases[case_index];
        uint8_t code[8];
        size_t size = make_encoding(test, 2, 0, 1, 0, code);

#if USE_EXTRA_OPCODES
        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                legacy_cpu(test), CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND, &decoded_size);

            EXPECT(decoded_size == size);
            expect_register_shape(test, &instruction, 512u,
                CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.mask_reg == CDISASM_X86_REG_K2);
            EXPECT(instruction.mask_mode == CDISASM_X86_MASK_MERGE);
        }
#endif
        size = make_encoding(test, 2, 0, 2, 0, code);
#if USE_EXTRA_OPCODES
        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                legacy_cpu(test), CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND, &decoded_size);

            EXPECT(decoded_size == size);
            expect_register_shape(test, &instruction, 512u,
                CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
        }
#endif

        size = make_encoding(test, 2, 0, 0, 1, code);
        expect_status("compress/expand register EVEX.b reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        size = make_encoding(test, 2, 1, 1, 1, code);
        expect_status("compress/expand memory EVEX.b reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2, 0, 0, 0, code);
        code[3] = (uint8_t)((code[3] & UINT8_C(0x9f)) | UINT8_C(0x60));
        expect_status("compress/expand LL=3 reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        size = make_encoding(test, 2, 0, 0, 0, code);
        code[2] &= (uint8_t)~UINT8_C(0x08);
        expect_status("compress/expand noncanonical EVEX.vvvv",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2, 1, 2, 0, code);
        if (test->compress) {
            expect_status("compress memory zeroing reserved",
                CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        } else {
#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                legacy_cpu(test), CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND, &decoded_size);

            EXPECT(decoded_size == size);
            EXPECT(instruction.name_id == test->name_id);
            EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
#else
            expect_status("extra-opcodes OFF expand memory zeroing",
                CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }

    {
        uint8_t code[8];
        size_t size = make_encoding(&cases[2], 2, 0, 0, 0, code);

        code[3] |= UINT8_C(0x80);
        expect_status("compress/expand zeroing without mask",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        size = make_encoding(&cases[2], 2, 0, 0, 0, code);
        code[2] &= UINT8_C(0xfc);
        expect_status("compress/expand non-66 namespace unowned",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    {
        static const uint8_t missing_modrm[] = {
            0x62, 0xf2, 0x7d, 0x48, 0x8b
        };
        static const uint8_t missing_disp8[] = {
            0x62, 0xf2, 0x7d, 0x48, 0x8b, 0x53
        };
        static const uint8_t prefixed_missing_modrm[] = {
            0x66, 0x62, 0xf2, 0x7d, 0x48, 0x8b
        };
        static const uint8_t prefixed_complete[] = {
            0x66, 0x62, 0xf2, 0x7d, 0x48, 0x8b, 0xd1
        };

        expect_status("compress/expand missing ModRM",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            missing_modrm, sizeof(missing_modrm),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        expect_status("compress/expand missing disp8",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            missing_disp8, sizeof(missing_disp8),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        expect_status("prefixed compress/expand missing ModRM",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            prefixed_missing_modrm, sizeof(prefixed_missing_modrm),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_TRUNCATED);
        expect_status("prefixed compress/expand complete",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            prefixed_complete, sizeof(prefixed_complete),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

/* Pinned XED allocates precisely 45 register controls per floating opcode/W
 * selector: LL=0/1/2, b=0, V'=1, and either unmasked, merge-masked, or
 * zero-masked with a nonzero mask.  A floating compress memory destination
 * additionally reserves every zeroing control; floating expand does not. */
static void test_fp_p2_selector_oracle(void)
{
    unsigned int allocated = 0u;
    unsigned int reserved = 0u;
    size_t case_index;

    for (case_index = 8u;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        const compress_expand_case *test = &cases[case_index];
        unsigned int memory;

        for (memory = 0u; memory < 2u; ++memory) {
            unsigned int p2_value;

            for (p2_value = 0u; p2_value < 256u; ++p2_value) {
                const uint8_t p2 = (uint8_t)p2_value;
                const unsigned int length = (p2 >> 5) & 3u;
                const unsigned int aaa = p2 & 7u;
                const int zeroing = (p2 & UINT8_C(0x80)) != 0u;
                const int valid = length != 3u
                    && (p2 & UINT8_C(0x10)) == 0u
                    && (p2 & UINT8_C(0x08)) != 0u
                    && (!zeroing || aaa != 0u)
                    && !(test->compress && memory != 0u && zeroing);
                uint8_t code[7] = {
                    0x62, 0xf2,
                    test->w != 0u ? UINT8_C(0xfd) : UINT8_C(0x7d),
                    p2, test->opcode,
                    test->compress
                        ? (memory != 0u ? UINT8_C(0x53) : UINT8_C(0xd1))
                        : (memory != 0u ? UINT8_C(0x4b) : UINT8_C(0xcb)),
                    0x02
                };
                const size_t size = memory != 0u ? 7u : 6u;

                if (!valid) {
                    ++reserved;
                    expect_status("floating compress/expand reserved P2",
                        CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
                        CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_INVALID_INSTRUCTION);
                    continue;
                }
                ++allocated;
#if USE_EXTRA_OPCODES
                {
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
                        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
                        &decoded_size);

                    EXPECT(decoded_size == size);
                    if (memory != 0u) {
                        expect_memory_shape(
                            test, &instruction, length, p2);
                    } else {
                        expect_register_shape(test, &instruction,
                            128u << length,
                            aaa != 0u && !zeroing
                                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                : CDISASM_OPERAND_ACCESS_WRITE);
                        expect_mask_shape(&instruction, p2);
                    }
                }
#else
                expect_status("floating compress/expand allocated P2 OFF",
                    CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
                    CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            }
        }
    }
    EXPECT(allocated == 318u);
    EXPECT(reserved == 1730u);
}

/* Sweep every EVEX P1 value over each opcode.  Only pp=66, U=1, and
 * inverted-vvvv=1111 are allocated; W is the exact PS/PD selector. */
static void test_fp_p1_and_map_oracle(void)
{
    static const uint8_t opcodes[2] = {0x8a, 0x88};
    unsigned int allocated = 0u;
    unsigned int reserved = 0u;
    unsigned int unowned = 0u;
    size_t opcode_index;

    for (opcode_index = 0u;
         opcode_index < sizeof(opcodes) / sizeof(opcodes[0]);
         ++opcode_index) {
        unsigned int p1_value;

        for (p1_value = 0u; p1_value < 256u; ++p1_value) {
            const uint8_t p1 = (uint8_t)p1_value;
            const int exact = p1 == UINT8_C(0x7d)
                || p1 == UINT8_C(0xfd);
            const int structurally_reserved =
                (p1 & UINT8_C(0x04)) == 0u
                || (p1 & UINT8_C(0x03)) == UINT8_C(1);
            uint8_t code[6] = {
                0x62, 0xf2, p1, 0x48, opcodes[opcode_index],
                opcode_index == 0u ? UINT8_C(0xd1) : UINT8_C(0xcb)
            };

            if (exact) {
#if USE_EXTRA_OPCODES
                const compress_expand_case *test = opcode_index == 0u
                    ? (p1 & UINT8_C(0x80)) != 0u
                        ? &cases[8] : &cases[9]
                    : (p1 & UINT8_C(0x80)) != 0u
                        ? &cases[10] : &cases[11];
#endif

                ++allocated;
#if USE_EXTRA_OPCODES
                {
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, sizeof(code),
                        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
                        &decoded_size);

                    EXPECT(decoded_size == sizeof(code));
                    expect_register_shape(test, &instruction, 512u,
                        CDISASM_OPERAND_ACCESS_WRITE);
                }
#else
                expect_status("floating compress/expand allocated P1 OFF",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            } else if (structurally_reserved) {
                ++reserved;
                expect_status("floating compress/expand reserved P1",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            } else {
                ++unowned;
                expect_status("floating compress/expand unowned pp",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            }
        }
    }
    EXPECT(allocated == 4u);
    EXPECT(reserved == 316u);
    EXPECT(unowned == 192u);

    for (opcode_index = 0u;
         opcode_index < sizeof(opcodes) / sizeof(opcodes[0]);
         ++opcode_index) {
        unsigned int map;

        for (map = 0u; map < 8u; ++map) {
            uint8_t code[6] = {
                0x62, (uint8_t)(UINT8_C(0xf0) | map),
                0x7d, 0x48, opcodes[opcode_index],
                opcode_index == 0u ? UINT8_C(0xd1) : UINT8_C(0xcb)
            };

            if (map == 2u) {
#if USE_EXTRA_OPCODES
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code),
                    CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
                    &decoded_size);

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.name_id == (opcode_index == 0u
                    ? CDISASM_X86_NAME_VCOMPRESSPS
                    : CDISASM_X86_NAME_VEXPANDPS));
#else
                expect_status("floating compress/expand exact map OFF",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            } else {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    &decoded_size);

                EXPECT(decoded_size == 0u);
                EXPECT(instruction.last_error_id
                    == CDISASM_STATUS_INVALID_INSTRUCTION
                    || instruction.last_error_id
                        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
                EXPECT(is_error_only(
                    &instruction,
                    (cdisasm_status)instruction.last_error_id));
            }
        }
    }
}

static void test_fp_non_long_aliases_and_apx_boundaries(void)
{
    static const uint8_t p0_aliases[4] = {0xc2, 0xd2, 0xe2, 0xf2};
    size_t case_index;

    for (case_index = 8u;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        const compress_expand_case *test = &cases[case_index];
        size_t alias_index;

        for (alias_index = 0u;
             alias_index < sizeof(p0_aliases) / sizeof(p0_aliases[0]);
             ++alias_index) {
            uint8_t code[6] = {
                0x62, p0_aliases[alias_index],
                test->w != 0u ? UINT8_C(0xfd) : UINT8_C(0x7d),
                0x08, test->opcode,
                test->compress ? UINT8_C(0xd1) : UINT8_C(0xcb)
            };

#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_32,
                code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
                &decoded_size);

            EXPECT(decoded_size == sizeof(code));
            expect_register_shape(test, &instruction, 128u,
                CDISASM_OPERAND_ACCESS_WRITE);
#else
            expect_status("floating compress/expand 32-bit alias OFF",
                CDISASM_CPU_X86, CDISASM_MODE_32,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }

        {
            uint8_t code[6] = {
                0x62, 0xf2,
                test->w != 0u ? UINT8_C(0xfd) : UINT8_C(0x7d),
                0x08, test->opcode,
                test->compress ? UINT8_C(0xd1) : UINT8_C(0xcb)
            };
#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_16,
                code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
                &decoded_size);

            EXPECT(decoded_size == sizeof(code));
            expect_register_shape(test, &instruction, 128u,
                CDISASM_OPERAND_ACCESS_WRITE);
#else
            expect_status("floating compress/expand 16-bit form OFF",
                CDISASM_CPU_X86, CDISASM_MODE_16,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }

    {
        uint8_t b4_register[] = {
            0x62, 0xfa, 0x7d, 0x08, 0x8a, 0xd1
        };
        uint8_t u0_memory[] = {
            0x62, 0xf2, 0x79, 0x08, 0x88, 0x4b, 0x02
        };
        uint8_t extended_vprime[] = {
            0x62, 0xf2, 0x7d, 0x00, 0x8a, 0xd1
        };

        expect_status("floating compress B4 outside long mode",
            CDISASM_CPU_X86, CDISASM_MODE_32,
            b4_register, sizeof(b4_register),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_status("floating expand U0 outside long mode",
            CDISASM_CPU_X86, CDISASM_MODE_32,
            u0_memory, sizeof(u0_memory),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_status("floating compress V-prime outside long mode",
            CDISASM_CPU_X86, CDISASM_MODE_32,
            extended_vprime, sizeof(extended_vprime),
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

#if USE_EXTRA_OPCODES
static void expect_success_with_flag(
    const uint8_t *code,
    size_t size,
    cdisasm_cpu_id cpu,
    cdisasm_x86_decode_option flag,
    cdisasm_x86_name_id name_id)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu, CDISASM_MODE_64, code, size, flag, &decoded_size);

    EXPECT(decoded_size == size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == name_id);
}

static void test_feature_and_runtime_family_routes(void)
{
    static const uint8_t vpcompressb[] = {
        0x62, 0xf2, 0x7d, 0x48, 0x63, 0xd1
    };
    static const uint8_t vpcompressd[] = {
        0x62, 0xf2, 0x7d, 0x48, 0x8b, 0xd1
    };
    static const uint8_t vcompressps[] = {
        0x62, 0xf2, 0x7d, 0x48, 0x8a, 0xd1
    };
    static const uint8_t vpopcntd[] = {
        0x62, 0xf2, 0x7d, 0x48, 0x55, 0xc1
    };
    static const uint8_t vpshldvd[] = {
        0x62, 0xf2, 0x6d, 0x48, 0x71, 0xcb
    };
    static const cdisasm_x86_decode_option unrelated[] = {
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI2,
        CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ,
        CDISASM_X86_DECODE_FLAG_AVX512_BITALG
    };
    cdisasm_x86_decode_option ice_lake =
        cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64);
    cdisasm_x86_decode_option skylake_sp =
        cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64);
    size_t index;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, CDISASM_MODE_64)
        == CDISASM_X86_DECODE_FLAG_KNOWN_MASK);
    EXPECT((ice_lake & CDISASM_X86_DECODE_FLAG_AVX512)
        != 0);
    EXPECT((ice_lake & CDISASM_X86_DECODE_FLAG_AVX512_VBMI2)
        != 0);
    EXPECT((ice_lake & CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ)
        != 0);
    EXPECT((ice_lake & CDISASM_X86_DECODE_FLAG_AVX512_BITALG)
        != 0);
    EXPECT((ice_lake & CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND)
        != 0);
    EXPECT((skylake_sp & CDISASM_X86_DECODE_FLAG_AVX512)
        != 0);
    EXPECT((skylake_sp & CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND)
        != 0);
    EXPECT((skylake_sp & CDISASM_X86_DECODE_FLAG_AVX512_VBMI2)
        == 0);

    expect_success_with_flag(vpcompressb, sizeof(vpcompressb),
        CDISASM_CPU_ICE_LAKE,
        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
        CDISASM_X86_NAME_VPCOMPRESSB);
    expect_success_with_flag(vpcompressd, sizeof(vpcompressd),
        CDISASM_CPU_SKYLAKE_SP,
        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
        CDISASM_X86_NAME_VPCOMPRESSD);
    expect_success_with_flag(vcompressps, sizeof(vcompressps),
        CDISASM_CPU_SKYLAKE_SP,
        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
        CDISASM_X86_NAME_VCOMPRESSPS);
    expect_success_with_flag(vcompressps, sizeof(vcompressps),
        CDISASM_CPU_SKYLAKE_SP,
        CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_X86_NAME_VCOMPRESSPS);
    expect_success_with_flag(vpcompressb, sizeof(vpcompressb),
        CDISASM_CPU_ICE_LAKE, CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_X86_NAME_VPCOMPRESSB);
    for (index = 0; index < sizeof(unrelated) / sizeof(unrelated[0]);
         ++index) {
        expect_status("unrelated specific flag rejects compress/expand",
            CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
            vpcompressb, sizeof(vpcompressb), unrelated[index],
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    expect_status("base runtime flag rejects compress/expand",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        vpcompressb, sizeof(vpcompressb),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("VBMI2 feature required for byte compress",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vpcompressb, sizeof(vpcompressb),
        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("AVX512F feature required for dword compress",
        CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
        vpcompressd, sizeof(vpcompressd),
        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("AVX512F feature required for floating compress",
        CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
        vcompressps, sizeof(vcompressps),
        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    {
        cdisasm_x86_decode_flags good =
            CDISASM_X86_DECODE_FLAGS_INITIALIZER(
                CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND);
        cdisasm_x86_decode_flags wrong = good;
        cdisasm_x86_decode_flags family_only = good;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        EXPECT(cdisasm_decode_flags_set_bit(
            &good, CDISASM_X86_DECODE_BIT_AVX512F_512));
        EXPECT(cdisasm_decode_flags_set_bit(
            &wrong, CDISASM_X86_DECODE_BIT_AVX512F_256));
        instruction = (cdisasm_instruction){0};
        decoded_size = cdisasm_test_x86_decode_exact_flags(
            CDISASM_CPU_SKYLAKE_SP,CDISASM_MODE_64,
            vcompressps,sizeof(vcompressps),UINT64_C(0x1000),
            &good,&instruction);
        EXPECT(decoded_size == sizeof(vcompressps));
        EXPECT(instruction.form_id == UINT16_C(3648));
        instruction = (cdisasm_instruction){0};
        decoded_size = cdisasm_test_x86_decode_exact_flags(
            CDISASM_CPU_SKYLAKE_SP,CDISASM_MODE_64,
            vcompressps,sizeof(vcompressps),UINT64_C(0x1000),
            &wrong,&instruction);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
        instruction = (cdisasm_instruction){0};
        decoded_size = cdisasm_test_x86_decode_exact_flags(
            CDISASM_CPU_SKYLAKE_SP,CDISASM_MODE_64,
            vcompressps,sizeof(vcompressps),UINT64_C(0x1000),
            &family_only,&instruction);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    }

    expect_success_with_flag(vpopcntd, sizeof(vpopcntd),
        CDISASM_CPU_ICE_LAKE,
        CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ,
        CDISASM_X86_NAME_VPOPCNTD);
    expect_success_with_flag(vpopcntd, sizeof(vpopcntd),
        CDISASM_CPU_ICE_LAKE, CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_X86_NAME_VPOPCNTD);
    expect_status("compress/expand flag rejects VPOPCNTDQ",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        vpopcntd, sizeof(vpopcntd),
        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_success_with_flag(vpshldvd, sizeof(vpshldvd),
        CDISASM_CPU_ICE_LAKE,
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI2,
        CDISASM_X86_NAME_VPSHLDVD);
    expect_success_with_flag(vpshldvd, sizeof(vpshldvd),
        CDISASM_CPU_ICE_LAKE, CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_X86_NAME_VPSHLDVD);
    expect_status("compress/expand flag rejects VBMI2 double shift",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        vpshldvd, sizeof(vpshldvd),
        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_AVX10, CDISASM_MODE_64,
            vpcompressb, sizeof(vpcompressb),
            CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND, &decoded_size);

        EXPECT(decoded_size == sizeof(vpcompressb));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPCOMPRESSB);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512F));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512VBMI2));
    }

    {
        unsigned int length;

        for (length = 0u; length < 3u; ++length) {
            uint8_t code[8];
            size_t size = make_encoding(
                &cases[9], length, 0, 0, 0, code);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                code, size, CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
                &decoded_size);

            EXPECT(decoded_size == size);
            expect_register_shape(&cases[9], &instruction,
                128u << length, CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512F));
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512VL)
                == (length != 2u));
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction,
                length == 0u ? CDISASM_X86_GROUP_AVX512F_128
                    : length == 1u ? CDISASM_X86_GROUP_AVX512F_256
                                   : CDISASM_X86_GROUP_AVX512F_512));

            instruction = decode(
                CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
                code, size, CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
                &decoded_size);
            if (length == 2u) {
                EXPECT(decoded_size == size);
                expect_register_shape(&cases[9], &instruction, 512u,
                    CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX512VL));
            } else {
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
            }

            instruction = decode(
                CDISASM_CPU_AVX10, CDISASM_MODE_64,
                code, size, CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
                &decoded_size);
            EXPECT(decoded_size == size);
            expect_register_shape(&cases[9], &instruction,
                128u << length, CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX10_1));
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512F));
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512VL));
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction,
                length == 0u ? CDISASM_X86_GROUP_AVX512F_128
                    : length == 1u ? CDISASM_X86_GROUP_AVX512F_256
                                   : CDISASM_X86_GROUP_AVX512F_512));
        }
    }
}

static void test_diamond_rapids_apx_oracle(void)
{
    size_t case_index;
    unsigned int accepted = 0;
    unsigned int rejected = 0;

    for (case_index = 0;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        const compress_expand_case *test = &cases[case_index];
        uint8_t code[8];
        size_t size = make_apx_encoding(test, 1, 0, 0, code);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_APX, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND, &decoded_size);

        ++accepted;
        EXPECT(decoded_size == size);
        expect_register_shape(test, &instruction, 512u,
            CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));

        size = make_apx_encoding(test, 1, 0, 1, code);
        instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
            code, size, CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
            &decoded_size);
        ++accepted;
        EXPECT(decoded_size == size);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(instruction.opcode[test->compress ? 0 : 1].base_reg
            == CDISASM_X86_REG_R19);

        size = make_apx_encoding(test, 0, 1, 1, code);
        instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
            code, size, CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
            &decoded_size);
        ++accepted;
        EXPECT(decoded_size == size);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(instruction.opcode[test->compress ? 0 : 1].base_reg
            == CDISASM_X86_REG_RBX);
        EXPECT(instruction.opcode[test->compress ? 0 : 1].index_reg
            == CDISASM_X86_REG_R16);

        size = make_apx_encoding(test, 1, 1, 1, code);
        instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
            code, size, CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
            &decoded_size);
        ++accepted;
        EXPECT(decoded_size == size);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(instruction.opcode[test->compress ? 0 : 1].base_reg
            == CDISASM_X86_REG_R19);
        EXPECT(instruction.opcode[test->compress ? 0 : 1].index_reg
            == CDISASM_X86_REG_R16);

        size = make_apx_encoding(test, 0, 1, 0, code);
        ++rejected;
        expect_status("compress/expand U0 register reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    EXPECT(accepted == 48u);
    EXPECT(rejected == 12u);

    {
        uint8_t code[8];
        size_t size = make_apx_encoding(&cases[10], 1, 1, 1, code);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_APX, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND, &decoded_size);

        EXPECT(decoded_size == size);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VEXPANDPD);
        EXPECT(instruction.form_id == UINT16_C(4531));
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R19);
        EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R16);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
    }

    {
        uint8_t code[8];
        size_t size = make_apx_encoding(&cases[2], 1, 0, 0, code);

        expect_status("compress/expand B4 non-long-mode reserved",
            CDISASM_CPU_X86, CDISASM_MODE_32, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_status("compress/expand B4 requires APX CPU feature",
            CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_AVX512,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
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

static void reject_format(const cdisasm_instruction *instruction)
{
    static const uint32_t syntaxes[2] = {
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        CDISASM_FORMAT_SYNTAX_X86_ATT
    };
    size_t syntax_index;

    for (syntax_index = 0u; syntax_index < 2u; ++syntax_index) {
        char output[96] = {'x'};

        EXPECT(cdisasm_x86_format(instruction, syntaxes[syntax_index],
            output, sizeof(output)) == 0u);
        EXPECT(output[0] == '\0');
    }
}

static void test_formatting(void)
{
    uint8_t code[8];
    size_t size = make_encoding(&cases[2], 2, 1, 1, 0, code);
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64, code, size,
        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND, &decoded_size);

    EXPECT(decoded_size == size);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpcompressd zmmword ptr [rbx + 0x8] {k2}, zmm2");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpcompressd %zmm2, 0x8(%rbx){%k2}");

    size = make_encoding(&cases[7], 2, 1, 2, 0, code);
    instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
        &decoded_size);
    EXPECT(decoded_size == size);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpexpandq zmm1 {k2}{z}, zmmword ptr [rbx + 0x10]");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpexpandq 0x10(%rbx), %zmm1{%k2}{z}");

    size = make_encoding(&cases[9], 1, 1, 1, 0, code);
    instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
        &decoded_size);
    EXPECT(decoded_size == size);
    EXPECT(instruction.form_id == UINT16_C(3644));
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vcompressps ymmword ptr [rbx + 0x8] {k2}, ymm2");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vcompressps %ymm2, 0x8(%rbx){%k2}");
    {
        cdisasm_instruction forged = instruction;

        forged.mask_mode = CDISASM_X86_MASK_ZERO;
        reject_format(&forged);
        forged = instruction;
        forged.form_id = UINT16_C(3645);
        reject_format(&forged);
        forged = instruction;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        reject_format(&forged);
        forged = instruction;
        forged.encoding.modrm ^= UINT8_C(0x40);
        reject_format(&forged);
    }

    size = make_encoding(&cases[10], 0, 1, 2, 0, code);
    instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
        &decoded_size);
    EXPECT(decoded_size == size);
    EXPECT(instruction.form_id == UINT16_C(4527));
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vexpandpd xmm1 {k2}{z}, xmmword ptr [rbx + 0x10]");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vexpandpd 0x10(%rbx), %xmm1{%k2}{z}");
    {
        cdisasm_instruction forged = instruction;

        forged.name_id = CDISASM_X86_NAME_VEXPANDPS;
        reject_format(&forged);
        forged = instruction;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        reject_format(&forged);
        forged = instruction;
        forged.opcode[1].size = 8u;
        reject_format(&forged);
        forged = instruction;
        forged.x86_group_count = 0u;
        reject_format(&forged);
        forged = instruction;
        forged.x86_group_ids[forged.x86_group_count - 1u]
            = CDISASM_X86_GROUP_AVX512F_256;
        reject_format(&forged);
    }
}
#endif

int main(void)
{
    test_all_names_lengths_memory_and_masks();
    test_decorators_reserved_controls_and_truncation();
    test_fp_p2_selector_oracle();
    test_fp_p1_and_map_oracle();
    test_fp_non_long_aliases_and_apx_boundaries();
#if USE_EXTRA_OPCODES
    test_feature_and_runtime_family_routes();
    test_diamond_rapids_apx_oracle();
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d EVEX compress/expand test(s) failed\n", failures);
        return 1;
    }
    puts("x86 EVEX compress/expand tests passed");
    return 0;
}
