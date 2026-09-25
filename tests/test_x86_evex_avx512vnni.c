#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct vnni_case {
    uint8_t opcode;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} vnni_case;

typedef struct vnni_int8_evex_case {
    uint8_t opcode;
    uint8_t prefix;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_base;
    const char *mnemonic;
} vnni_int8_evex_case;

static const vnni_case vnni_cases[] = {
    {0x50, CDISASM_X86_NAME_VPDPBUSD, "vpdpbusd"},
    {0x51, CDISASM_X86_NAME_VPDPBUSDS, "vpdpbusds"},
    {0x52, CDISASM_X86_NAME_VPDPWSSD, "vpdpwssd"},
    {0x53, CDISASM_X86_NAME_VPDPWSSDS, "vpdpwssds"}
};

/* EVEX.pp values: none=0, F3=2, F2=3.  Each form_base is the pinned XED
 * XMM-memory IFORM; register and wider-vector forms follow in pairs. */
static const vnni_int8_evex_case vnni_int8_evex_cases[] = {
    {0x50, 0, CDISASM_X86_NAME_VPDPBUUD, UINT16_C(6680), "vpdpbuud"},
    {0x51, 0, CDISASM_X86_NAME_VPDPBUUDS, UINT16_C(6670), "vpdpbuuds"},
    {0x50, 2, CDISASM_X86_NAME_VPDPBSUD, UINT16_C(6640), "vpdpbsud"},
    {0x51, 2, CDISASM_X86_NAME_VPDPBSUDS, UINT16_C(6630), "vpdpbsuds"},
    {0x50, 3, CDISASM_X86_NAME_VPDPBSSD, UINT16_C(6620), "vpdpbssd"},
    {0x51, 3, CDISASM_X86_NAME_VPDPBSSDS, UINT16_C(6610), "vpdpbssds"}
};

_Static_assert(CDISASM_X86_NAME_VPDPBUSD == UINT16_C(715),
    "existing VPDPBUSD ID changed");
_Static_assert(CDISASM_X86_NAME_VPDPBUSDS == UINT16_C(1095)
        && CDISASM_X86_NAME_VPDPWSSD == UINT16_C(1096)
        && CDISASM_X86_NAME_VPDPWSSDS == UINT16_C(1097),
    "VNNI dot-product appended IDs changed");
_Static_assert(CDISASM_X86_NAME_VPDPWSSDS < CDISASM_X86_NAME_COUNT
        && CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1),
    "VNNI dot-product catalog boundary changed");
_Static_assert(CDISASM_NAME_VPDPBUSDS == CDISASM_X86_NAME_VPDPBUSDS
        && CDISASM_NAME_VPDPWSSD == CDISASM_X86_NAME_VPDPWSSD
        && CDISASM_NAME_VPDPWSSDS == CDISASM_X86_NAME_VPDPWSSDS,
    "legacy VNNI aliases changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_VNNI
        == UINT64_C(0x8000000000),
    "AVX512 VNNI runtime flag changed");
_Static_assert(CDISASM_X86_NAME_VPDPBSSD == UINT16_C(1104)
        && CDISASM_X86_NAME_VPDPBUUDS == UINT16_C(1109),
    "AVX-VNNI-INT8 name range changed");

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

/* source_kind: 0 = register, 1 = full-tuple memory, 2 = m32bcst. */
static size_t make_encoding(
    const vnni_case *test,
    unsigned int length,
    unsigned int source_kind,
    unsigned int mask_mode,
    uint8_t code[8])
{
    uint8_t p2 = (uint8_t)(UINT8_C(0x08) | (length << 5));

    if (source_kind == 2u) {
        p2 |= UINT8_C(0x10);
    }
    if (mask_mode != 0u) {
        p2 |= UINT8_C(0x02);
    }
    if (mask_mode == 2u) {
        p2 |= UINT8_C(0x80);
    }
    code[0] = UINT8_C(0x62);
    code[1] = UINT8_C(0xf2);
    code[2] = UINT8_C(0x6d);
    code[3] = p2;
    code[4] = test->opcode;
    code[5] = source_kind == 0u ? UINT8_C(0xcb) : UINT8_C(0x4b);
    if (source_kind != 0u) {
        code[6] = UINT8_C(2);
        return 7u;
    }
    return 6u;
}

static size_t make_int8_evex_encoding(
    const vnni_int8_evex_case *test,
    unsigned int length,
    unsigned int source_kind,
    unsigned int mask_mode,
    uint8_t code[8])
{
    uint8_t p2 = (uint8_t)(UINT8_C(0x08) | (length << 5));

    if (source_kind == 2u) {
        p2 |= UINT8_C(0x10);
    }
    if (mask_mode != 0u) {
        p2 |= UINT8_C(0x02);
    }
    if (mask_mode == 2u) {
        p2 |= UINT8_C(0x80);
    }
    code[0] = UINT8_C(0x62);
    code[1] = UINT8_C(0xf2);
    code[2] = (uint8_t)(UINT8_C(0x6c) | test->prefix);
    code[3] = p2;
    code[4] = test->opcode;
    code[5] = source_kind == 0u ? UINT8_C(0xcb) : UINT8_C(0x4b);
    if (source_kind != 0u) {
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

static void expect_legacy_groups(
    const cdisasm_instruction *instruction,
    unsigned int length)
{
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512VNNI));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512VL) == (length != 2u));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX10_1));
}


static void expect_avx10_2_int8_groups(
    const cdisasm_instruction *instruction)
{
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX10_2));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512VNNI));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX_VNNI_INT8));
}
#endif

static void test_avx10_2_int8_complete_matrix(void)
{
    size_t case_index;
    unsigned int accepted = 0;

    for (case_index = 0;
         case_index < sizeof(vnni_int8_evex_cases)
             / sizeof(vnni_int8_evex_cases[0]);
         ++case_index) {
        const vnni_int8_evex_case *test = &vnni_int8_evex_cases[case_index];
        unsigned int length;

        for (length = 0; length != 3u; ++length) {
            const unsigned int vector_bits = 128u << length;
            unsigned int source_kind;

            for (source_kind = 0; source_kind != 3u; ++source_kind) {
                unsigned int mask_mode;

                for (mask_mode = 0; mask_mode != 3u; ++mask_mode) {
                    const int memory = source_kind != 0u;
                    const int broadcast = source_kind == 2u;
                    uint8_t code[8];
                    size_t size = make_int8_evex_encoding(
                        test, length, source_kind, mask_mode, code);

                    ++accepted;
#if USE_EXTRA_OPCODES
                    {
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_AVX10, CDISASM_MODE_64,
                            code, size, CDISASM_X86_DECODE_FLAG_AVX10,
                            &decoded_size);
                        cdisasm_x86_mask_mode expected_mask = mask_mode == 0u
                            ? CDISASM_X86_MASK_NONE
                            : (mask_mode == 1u
                                ? CDISASM_X86_MASK_MERGE
                                : CDISASM_X86_MASK_ZERO);
                        cdisasm_x86_form_id expected_form =
                            (cdisasm_x86_form_id)(test->form_base
                                + length * 4u + (memory ? 0u : 1u));

                        EXPECT(decoded_size == size);
                        EXPECT(instruction.name_id == test->name_id);
                        EXPECT(instruction.form_id == expected_form);
                        EXPECT(instruction.operand_count == 3u);
                        EXPECT((instruction.opcode_flags
                                & CDISASM_PREFIX_EVEX) != 0);
                        EXPECT((instruction.opcode_flags
                                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK)
                               == 0);
                        EXPECT(instruction.opcode[0].type
                            == CDISASM_OPERAND_REGISTER);
                        EXPECT(instruction.opcode[0].reg
                            == vector_register(1u, vector_bits));
                        EXPECT(instruction.opcode[0].size
                            == vector_bits / 8u);
                        EXPECT(instruction.opcode[0].access
                            == CDISASM_OPERAND_ACCESS_READ_WRITE);
                        EXPECT(instruction.opcode[1].reg
                            == vector_register(2u, vector_bits));
                        EXPECT(instruction.opcode[1].access
                            == CDISASM_OPERAND_ACCESS_READ);
                        EXPECT(instruction.opcode[2].type
                            == (memory ? CDISASM_OPERAND_MEMORY
                                       : CDISASM_OPERAND_REGISTER));
                        EXPECT(instruction.opcode[2].size
                            == (broadcast ? 4u : vector_bits / 8u));
                        EXPECT(instruction.opcode[2].access
                            == CDISASM_OPERAND_ACCESS_READ);
                        EXPECT(instruction.opcode[2].broadcast
                            == (broadcast
                                ? (cdisasm_x86_broadcast)(vector_bits / 32u)
                                : CDISASM_X86_BROADCAST_NONE));
                        EXPECT(instruction.mask_mode == expected_mask);
                        EXPECT(instruction.mask_reg
                            == (mask_mode == 0u
                                ? CDISASM_X86_REG_NONE
                                : CDISASM_X86_REG_K2));
                        if (memory) {
                            EXPECT(instruction.opcode[2].base_reg
                                == CDISASM_X86_REG_RBX);
                            EXPECT(instruction.opcode[2].imm
                                == UINT64_C(2) * (broadcast
                                    ? UINT64_C(4)
                                    : (uint64_t)(vector_bits / 8u)));
                        } else {
                            EXPECT(instruction.opcode[2].reg
                                == vector_register(3u, vector_bits));
                        }
                        expect_avx10_2_int8_groups(&instruction);
                    }
#else
                    (void)memory;
                    (void)broadcast;
                    (void)vector_bits;
                    expect_status("extra-opcodes OFF AVX10.2 VNNI-INT8",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, size, CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
            }
        }
    }
    EXPECT(accepted == 162u);
}

static void test_avx10_2_int8_reserved_and_truncated(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(vnni_int8_evex_cases)
             / sizeof(vnni_int8_evex_cases[0]);
         ++case_index) {
        const vnni_int8_evex_case *test = &vnni_int8_evex_cases[case_index];
        uint8_t code[9];
        size_t size = make_int8_evex_encoding(test, 2u, 0u, 0u, code);

        code[2] |= UINT8_C(0x80);
        expect_status("AVX10.2 VNNI-INT8 W1 reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_int8_evex_encoding(test, 2u, 0u, 0u, code);
        code[3] = (uint8_t)((code[3] & UINT8_C(0x9f)) | UINT8_C(0x60));
        expect_status("AVX10.2 VNNI-INT8 LL3 reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_int8_evex_encoding(test, 2u, 0u, 0u, code);
        code[3] |= UINT8_C(0x10);
        expect_status("AVX10.2 VNNI-INT8 register EVEX.b reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_int8_evex_encoding(test, 2u, 0u, 0u, code);
        code[3] |= UINT8_C(0x80);
        expect_status("AVX10.2 VNNI-INT8 zero without mask reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_int8_evex_encoding(test, 2u, 0u, 0u, code);
        code[2] &= (uint8_t)~UINT8_C(0x04);
        expect_status("AVX10.2 VNNI-INT8 U0 register reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_int8_evex_encoding(test, 2u, 0u, 0u, code);
        memmove(code + 1, code, size);
        code[0] = UINT8_C(0x66);
        expect_status("AVX10.2 VNNI-INT8 legacy prefix reserved",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size + 1u,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    {
        static const uint8_t missing_modrm[] = {
            0x62, 0xf2, 0x6c, 0x48, 0x51
        };
        static const uint8_t missing_disp8[] = {
            0x62, 0xf2, 0x6e, 0x48, 0x50, 0x4b
        };
        static const uint8_t missing_sib[] = {
            0x62, 0xf2, 0x6f, 0x48, 0x51, 0x0c
        };
        static const uint8_t short_disp32[] = {
            0x62, 0xf2, 0x6c, 0x48, 0x50, 0x05, 0x7f
        };

        expect_status("AVX10.2 VNNI-INT8 missing ModRM",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            missing_modrm, sizeof(missing_modrm),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        expect_status("AVX10.2 VNNI-INT8 missing disp8",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            missing_disp8, sizeof(missing_disp8),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        expect_status("AVX10.2 VNNI-INT8 missing SIB",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            missing_sib, sizeof(missing_sib),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        expect_status("AVX10.2 VNNI-INT8 short disp32",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            short_disp32, sizeof(short_disp32),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    }
}

static void test_complete_width_source_mask_matrix(void)
{
    size_t case_index;
    unsigned int accepted = 0;

    for (case_index = 0;
         case_index < sizeof(vnni_cases) / sizeof(vnni_cases[0]);
         ++case_index) {
        const vnni_case *test = &vnni_cases[case_index];
        unsigned int length;

        for (length = 0; length != 3u; ++length) {
            const unsigned int vector_bits = 128u << length;
            unsigned int source_kind;

            for (source_kind = 0; source_kind != 3u; ++source_kind) {
                unsigned int mask_mode;

                for (mask_mode = 0; mask_mode != 3u; ++mask_mode) {
                    const int memory = source_kind != 0u;
                    const int broadcast = source_kind == 2u;
                    uint8_t code[8];
                    size_t size = make_encoding(
                        test, length, source_kind, mask_mode, code);

                    ++accepted;
#if USE_EXTRA_OPCODES
                    {
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
                            code, size,
                            CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
                            &decoded_size);
                        cdisasm_x86_mask_mode expected_mask = mask_mode == 0u
                            ? CDISASM_X86_MASK_NONE
                            : (mask_mode == 1u
                                ? CDISASM_X86_MASK_MERGE
                                : CDISASM_X86_MASK_ZERO);

                        EXPECT(decoded_size == size);
                        EXPECT(instruction.name_id == test->name_id);
                        EXPECT(instruction.operand_count == 3u);
                        EXPECT(instruction.opcode[0].type
                            == CDISASM_OPERAND_REGISTER);
                        EXPECT(instruction.opcode[0].reg
                            == vector_register(1u, vector_bits));
                        EXPECT(instruction.opcode[0].size
                            == vector_bits / 8u);
                        /* These are destructive accumulates, including {z}. */
                        EXPECT(instruction.opcode[0].access
                            == CDISASM_OPERAND_ACCESS_READ_WRITE);
                        EXPECT(instruction.opcode[1].reg
                            == vector_register(2u, vector_bits));
                        EXPECT(instruction.opcode[1].access
                            == CDISASM_OPERAND_ACCESS_READ);
                        EXPECT(instruction.opcode[2].type
                            == (memory ? CDISASM_OPERAND_MEMORY
                                       : CDISASM_OPERAND_REGISTER));
                        EXPECT(instruction.opcode[2].size
                            == (broadcast ? 4u : vector_bits / 8u));
                        EXPECT(instruction.opcode[2].access
                            == CDISASM_OPERAND_ACCESS_READ);
                        EXPECT(instruction.opcode[2].broadcast
                            == (broadcast
                                ? (cdisasm_x86_broadcast)(vector_bits / 32u)
                                : CDISASM_X86_BROADCAST_NONE));
                        EXPECT(instruction.mask_mode == expected_mask);
                        EXPECT(instruction.mask_reg
                            == (mask_mode == 0u
                                ? CDISASM_X86_REG_NONE
                                : CDISASM_X86_REG_K2));
                        if (memory) {
                            EXPECT(instruction.opcode[2].base_reg
                                == CDISASM_X86_REG_RBX);
                            EXPECT(instruction.opcode[2].imm
                                == UINT64_C(2) * (broadcast
                                    ? UINT64_C(4)
                                    : (uint64_t)(vector_bits / 8u)));
                        } else {
                            EXPECT(instruction.opcode[2].reg
                                == vector_register(3u, vector_bits));
                        }
                        expect_legacy_groups(&instruction, length);
                    }
#else
                    (void)memory;
                    (void)broadcast;
                    (void)vector_bits;
                    expect_status("extra-opcodes OFF VNNI owned encoding",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, size, CDISASM_X86_DECODE_FLAG_BASE,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                }
            }
        }
    }
    EXPECT(accepted == 108u);
}

static void test_reserved_controls_and_truncation(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(vnni_cases) / sizeof(vnni_cases[0]);
         ++case_index) {
        const vnni_case *test = &vnni_cases[case_index];
        uint8_t code[9];
        size_t size = make_encoding(test, 2u, 0u, 0u, code);

        code[2] |= UINT8_C(0x80);
        expect_status("VNNI W1 reserved", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, size, CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2u, 0u, 0u, code);
        code[2] &= (uint8_t)~UINT8_C(0x03);
        expect_status("VNNI wrong mandatory prefix", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, size, CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        size = make_encoding(test, 2u, 0u, 0u, code);
        code[1] = (uint8_t)((code[1] & UINT8_C(0xf8)) | UINT8_C(0x03));
        expect_status("VNNI map-neighbor truncation", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, size, CDISASM_X86_DECODE_FLAG_BASE,
#if USE_EXTRA_OPCODES
            CDISASM_STATUS_TRUNCATED);
#else
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

        size = make_encoding(test, 2u, 0u, 0u, code);
        code[3] = (uint8_t)((code[3] & UINT8_C(0x9f)) | UINT8_C(0x60));
        expect_status("VNNI LL3 reserved", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, size, CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2u, 0u, 0u, code);
        code[3] |= UINT8_C(0x10);
        expect_status("VNNI register EVEX.b reserved", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, size, CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2u, 0u, 0u, code);
        code[3] |= UINT8_C(0x80);
        expect_status("VNNI zero without mask reserved", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, size, CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2u, 0u, 0u, code);
        code[2] &= (uint8_t)~UINT8_C(0x04);
        expect_status("VNNI U0 register reserved", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, size, CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        size = make_encoding(test, 2u, 0u, 0u, code);
        memmove(code + 1, code, size);
        code[0] = UINT8_C(0x66);
        expect_status("VNNI legacy prefix reserved", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, size + 1u,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    {
        static const uint8_t missing_modrm[] = {
            0x62, 0xf2, 0x6d, 0x48, 0x51
        };
        static const uint8_t missing_disp8[] = {
            0x62, 0xf2, 0x6d, 0x48, 0x52, 0x4b
        };
        static const uint8_t missing_sib[] = {
            0x62, 0xf2, 0x6d, 0x48, 0x53, 0x0c
        };
        static const uint8_t short_disp32[] = {
            0x62, 0xf2, 0x6d, 0x48, 0x50, 0x05, 0x7f
        };

        expect_status("VNNI missing ModRM", CDISASM_CPU_X86,
            CDISASM_MODE_64, missing_modrm, sizeof(missing_modrm),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        expect_status("VNNI missing disp8", CDISASM_CPU_X86,
            CDISASM_MODE_64, missing_disp8, sizeof(missing_disp8),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        expect_status("VNNI missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64, missing_sib, sizeof(missing_sib),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        expect_status("VNNI short disp32", CDISASM_CPU_X86,
            CDISASM_MODE_64, short_disp32, sizeof(short_disp32),
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    }
}

#if USE_EXTRA_OPCODES
static void test_runtime_cpu_mode_and_avx10_routes(void)
{
    uint8_t code[8];
    size_t size = make_encoding(&vnni_cases[1], 0u, 0u, 0u, code);
    uint32_t decoded_size;
    cdisasm_x86_decode_option cpu_flags;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        &decoded_size);
    EXPECT(decoded_size == size);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPDPBUSDS);
    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512,
        &decoded_size);
    EXPECT(decoded_size == size);

    expect_status("unrelated runtime selector rejects VNNI",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64, code, size,
        CDISASM_X86_DECODE_FLAG_AVX512_CD,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("Skylake-SP lacks AVX512VNNI",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64, code, size,
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("Haswell lacks EVEX VNNI",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64, code, size,
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        &decoded_size);
    EXPECT(decoded_size == size);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512VNNI));

    cpu_flags = cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512_VNNI) != 0);
    cpu_flags = cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_AVX10, CDISASM_MODE_64);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX10) != 0);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512_VNNI) != 0);
    cpu_flags = cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_APX, CDISASM_MODE_64);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_APX) != 0);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512_VNNI) != 0);

    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_32,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        &decoded_size);
    EXPECT(decoded_size == size);
    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_16,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        &decoded_size);
    EXPECT(decoded_size == size);

    /* R' keeps the 0x62 byte unambiguously EVEX outside long mode while
     * selecting a vector register that those modes cannot address. */
    code[1] &= (uint8_t)~UINT8_C(0x10);
    expect_status("VNNI vector extension outside 64-bit mode",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_32, code, size,
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_avx10_2_int8_runtime_cpu_mode_and_collisions(void)
{
    uint8_t code[8];
    size_t size = make_int8_evex_encoding(
        &vnni_int8_evex_cases[1], 2u, 0u, 0u, code);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == size);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPDPBUUDS);
    EXPECT(instruction.form_id == UINT16_C(6679));
    expect_avx10_2_int8_groups(&instruction);

    instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == size);
    instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == size);

    expect_status("Granite Rapids lacks AVX10.2 VNNI-INT8",
        CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64, code, size,
        CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("Arrow Lake lacks EVEX VNNI-INT8",
        CDISASM_CPU_ARROW_LAKE, CDISASM_MODE_64, code, size,
        CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("Ice Lake lacks EVEX VNNI-INT8",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64, code, size,
        CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("VEX VNNI-INT8 selector rejects EVEX allocation",
        CDISASM_CPU_AVX10, CDISASM_MODE_64, code, size,
        CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("AVX512VNNI selector rejects AVX10.2 VNNI-INT8",
        CDISASM_CPU_AVX10, CDISASM_MODE_64, code, size,
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("APX selector does not replace AVX10 family",
        CDISASM_CPU_APX, CDISASM_MODE_64, code, size,
        CDISASM_X86_DECODE_FLAG_APX,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_32,
        code, size, CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == size);
    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_16,
        code, size, CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == size);

    code[1] &= (uint8_t)~UINT8_C(0x10);
    expect_status("AVX10.2 VNNI-INT8 vector extension outside mode64",
        CDISASM_CPU_AVX10, CDISASM_MODE_32, code, size,
        CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    /* pp=66 is not an alias of the INT8 family: it remains the established
     * AVX512VNNI/AVX10.1 VPDPBUSD(S) row. */
    size = make_int8_evex_encoding(
        &vnni_int8_evex_cases[0], 2u, 0u, 0u, code);
    code[2] = (uint8_t)((code[2] & UINT8_C(0xfc)) | UINT8_C(0x01));
    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        &decoded_size);
    EXPECT(decoded_size == size);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPDPBUSD);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_2));
}

static void test_avx10_2_int8_apx_addressing(void)
{
    static const uint8_t b4_register[] = {
        0x62, 0xfa, 0x6c, 0x49, 0x50, 0xcb
    };
    static const uint8_t u0_memory[] = {
        0x62, 0xf2, 0x68, 0x49, 0x51, 0x0b
    };
    static const uint8_t b4_u0_sib[] = {
        0x62, 0xfa, 0x68, 0x49, 0x51, 0x0c, 0x03
    };
    static const uint8_t u0_register[] = {
        0x62, 0xf2, 0x68, 0x49, 0x51, 0xcb
    };
    const cdisasm_x86_decode_option apx_flags =
        CDISASM_X86_DECODE_FLAG_AVX10 | CDISASM_X86_DECODE_FLAG_APX;
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_APX, CDISASM_MODE_64,
        b4_register, sizeof(b4_register),
        apx_flags, &decoded_size);

    EXPECT(decoded_size == sizeof(b4_register));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPDPBUUD);
    EXPECT(instruction.form_id == UINT16_C(6689));
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_ZMM3);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_2));

    instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
        u0_memory, sizeof(u0_memory),
        apx_flags, &decoded_size);
    EXPECT(decoded_size == sizeof(u0_memory));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPDPBUUDS);
    EXPECT(instruction.form_id == UINT16_C(6678));
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RBX);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));

    instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
        b4_u0_sib, sizeof(b4_u0_sib),
        apx_flags, &decoded_size);
    EXPECT(decoded_size == sizeof(b4_u0_sib));
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R19);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R16);

    expect_status("AVX10.2 VNNI-INT8 U0 register remains reserved",
        CDISASM_CPU_APX, CDISASM_MODE_64,
        u0_register, sizeof(u0_register),
        apx_flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("AVX10.2 VNNI-INT8 B4 requires APX selector",
        CDISASM_CPU_APX, CDISASM_MODE_64,
        b4_register, sizeof(b4_register),
        CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("AVX10.2 VNNI-INT8 U0 requires APX selector",
        CDISASM_CPU_APX, CDISASM_MODE_64,
        u0_memory, sizeof(u0_memory),
        CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("AVX10.2 VNNI-INT8 B4 requires AVX10 selector",
        CDISASM_CPU_APX, CDISASM_MODE_64,
        b4_register, sizeof(b4_register),
        CDISASM_X86_DECODE_FLAG_APX,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("AVX10.2 VNNI-INT8 B4 requires APX profile",
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        b4_register, sizeof(b4_register),
        apx_flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("AVX10.2 VNNI-INT8 B4 reserved in mode32",
        CDISASM_CPU_APX, CDISASM_MODE_32,
        b4_register, sizeof(b4_register),
        apx_flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("AVX10.2 VNNI-INT8 U0 memory reserved in mode32",
        CDISASM_CPU_APX, CDISASM_MODE_32,
        u0_memory, sizeof(u0_memory),
        apx_flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_apx_b4_u0_addressing(void)
{
    static const uint8_t b4_register[] = {
        0x62, 0xfa, 0x6d, 0x49, 0x50, 0xcb
    };
    static const uint8_t b4_memory[] = {
        0x62, 0xfa, 0x6d, 0x49, 0x51, 0x0b
    };
    static const uint8_t u0_memory[] = {
        0x62, 0xf2, 0x69, 0x49, 0x52, 0x0b
    };
    static const uint8_t b4_u0_sib[] = {
        0x62, 0xfa, 0x69, 0x49, 0x53, 0x0c, 0x03
    };
    static const uint8_t u0_register[] = {
        0x62, 0xf2, 0x69, 0x49, 0x50, 0xcb
    };
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_APX, CDISASM_MODE_64,
        b4_register, sizeof(b4_register),
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI, &decoded_size);

    EXPECT(decoded_size == sizeof(b4_register));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPDPBUSD);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_ZMM3);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));

    instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
        b4_memory, sizeof(b4_memory),
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI, &decoded_size);
    EXPECT(decoded_size == sizeof(b4_memory));
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R19);

    instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
        u0_memory, sizeof(u0_memory),
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI, &decoded_size);
    EXPECT(decoded_size == sizeof(u0_memory));
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RBX);

    instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
        b4_u0_sib, sizeof(b4_u0_sib),
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI, &decoded_size);
    EXPECT(decoded_size == sizeof(b4_u0_sib));
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R19);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R16);

    expect_status("VNNI U0 register remains reserved",
        CDISASM_CPU_APX, CDISASM_MODE_64,
        u0_register, sizeof(u0_register),
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("VNNI B4 requires APX profile",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        b4_register, sizeof(b4_register),
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("VNNI B4 reserved in mode32",
        CDISASM_CPU_APX, CDISASM_MODE_32,
        b4_register, sizeof(b4_register),
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("VNNI U0 memory reserved in mode32",
        CDISASM_CPU_APX, CDISASM_MODE_32,
        u0_memory, sizeof(u0_memory),
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        CDISASM_STATUS_INVALID_INSTRUCTION);
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
    size_t size = make_encoding(&vnni_cases[3], 2u, 2u, 2u, code);
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        &decoded_size);

    EXPECT(decoded_size == size);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpdpwssds zmm1 {k2}{z}, zmm2, dword ptr [rbx + 0x8]{1to16}");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpdpwssds 0x8(%rbx){1to16}, %zmm2, %zmm1{%k2}{z}");

    size = make_encoding(&vnni_cases[1], 0u, 0u, 0u, code);
    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        &decoded_size);
    EXPECT(decoded_size == size);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpdpbusds xmm1, xmm2, xmm3");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpdpbusds %xmm3, %xmm2, %xmm1");

    size = make_int8_evex_encoding(
        &vnni_int8_evex_cases[3], 2u, 2u, 2u, code);
    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == size);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpdpbsuds zmm1 {k2}{z}, zmm2, dword ptr [rbx + 0x8]{1to16}");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpdpbsuds 0x8(%rbx){1to16}, %zmm2, %zmm1{%k2}{z}");

    size = make_int8_evex_encoding(
        &vnni_int8_evex_cases[4], 0u, 0u, 0u, code);
    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        code, size, CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == size);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpdpbssd xmm1, xmm2, xmm3");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpdpbssd %xmm3, %xmm2, %xmm1");
}
#endif

int main(void)
{
    test_complete_width_source_mask_matrix();
    test_avx10_2_int8_complete_matrix();
    test_reserved_controls_and_truncation();
    test_avx10_2_int8_reserved_and_truncated();
#if USE_EXTRA_OPCODES
    test_runtime_cpu_mode_and_avx10_routes();
    test_avx10_2_int8_runtime_cpu_mode_and_collisions();
    test_avx10_2_int8_apx_addressing();
    test_apx_b4_u0_addressing();
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d AVX512 VNNI test(s) failed\n", failures);
        return 1;
    }
    puts("x86 EVEX AVX512 VNNI tests passed");
    return 0;
}
