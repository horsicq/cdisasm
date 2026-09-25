#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct vbmi_case {
    uint8_t opcode;
    uint8_t w;
    uint8_t broadcast;
    uint8_t destructive;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_group_id feature_group;
    cdisasm_x86_decode_option runtime_flag;
} vbmi_case;

static const vbmi_case vbmi_cases[] = {
    {0x75, 0, 0, 1, CDISASM_X86_NAME_VPERMI2B,
        CDISASM_X86_GROUP_AVX512VBMI,
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI},
    {0x7d, 0, 0, 1, CDISASM_X86_NAME_VPERMT2B,
        CDISASM_X86_GROUP_AVX512VBMI,
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI},
    {0x83, 1, 1, 0, CDISASM_X86_NAME_VPMULTISHIFTQB,
        CDISASM_X86_GROUP_AVX512VBMI,
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI},
    {0x8d, 0, 0, 0, CDISASM_X86_NAME_VPERMB,
        CDISASM_X86_GROUP_AVX512VBMI,
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI}
};

_Static_assert(CDISASM_X86_NAME_VPERMB == UINT16_C(714),
    "existing VPERMB ID changed");
_Static_assert(CDISASM_X86_NAME_VPERMI2B == UINT16_C(1098)
        && CDISASM_X86_NAME_VPERMT2B == UINT16_C(1099)
        && CDISASM_X86_NAME_VPMULTISHIFTQB == UINT16_C(1100),
    "AVX512 VBMI appended IDs changed");
_Static_assert(CDISASM_X86_NAME_VPERMI2W == UINT16_C(1101)
        && CDISASM_X86_NAME_VPERMT2W == UINT16_C(1102)
        && CDISASM_X86_NAME_VPERMW == UINT16_C(1103),
    "AVX512BW word-permute IDs changed");
_Static_assert(CDISASM_X86_NAME_VGETEXPBF16 < CDISASM_X86_NAME_COUNT
        && CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1),
    "AVX512 VBMI catalog is incomplete");
_Static_assert(CDISASM_NAME_VPERMI2B == CDISASM_X86_NAME_VPERMI2B
        && CDISASM_NAME_VPERMT2B == CDISASM_X86_NAME_VPERMT2B
        && CDISASM_NAME_VPMULTISHIFTQB
            == CDISASM_X86_NAME_VPMULTISHIFTQB,
    "legacy AVX512 VBMI aliases changed");
_Static_assert(CDISASM_NAME_VPERMI2W == CDISASM_X86_NAME_VPERMI2W
        && CDISASM_NAME_VPERMT2W == CDISASM_X86_NAME_VPERMT2W
        && CDISASM_NAME_VPERMW == CDISASM_X86_NAME_VPERMW,
    "legacy AVX512BW word-permute aliases changed");

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",           \
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

static size_t make_encoding(
    const vbmi_case *test,
    unsigned int w,
    unsigned int length,
    unsigned int memory,
    unsigned int broadcast,
    unsigned int mask,
    unsigned int zero,
    uint8_t code[8])
{
    code[0] = UINT8_C(0x62);
    code[1] = UINT8_C(0xf2);
    code[2] = (uint8_t)(w != 0u ? UINT8_C(0xed) : UINT8_C(0x6d));
    code[3] = (uint8_t)(UINT8_C(0x08) | (length << 5) | mask);
    if (broadcast != 0u) {
        code[3] |= UINT8_C(0x10);
    }
    if (zero != 0u) {
        code[3] |= UINT8_C(0x80);
    }
    code[4] = test->opcode;
    code[5] = memory != 0u ? UINT8_C(0x0b) : UINT8_C(0xcb);
    return 6u;
}

static void check_legal_instruction(
    const vbmi_case *test,
    unsigned int length,
    unsigned int memory,
    unsigned int broadcast,
    unsigned int mask,
    unsigned int zero,
    const uint8_t *code,
    size_t size)
{
#if USE_EXTRA_OPCODES
    const unsigned int vector_bits = 128u << length;
    const cdisasm_operand_access destination_access =
        test->destructive != 0u
            || (mask != 0u && zero == 0u)
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_WRITE;
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        code, size, test->runtime_flag,
        &decoded_size);

    EXPECT(decoded_size == size);
    EXPECT(instruction.name_id == test->name_id);
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[0].reg == vector_register(1u, vector_bits));
    EXPECT(instruction.opcode[0].size == vector_bits / 8u);
    EXPECT(instruction.opcode[0].access == destination_access);
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[1].reg == vector_register(2u, vector_bits));
    EXPECT(instruction.opcode[1].size == vector_bits / 8u);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[2].type == (memory != 0u
        ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
    EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    if (memory != 0u) {
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RBX);
        EXPECT(instruction.opcode[2].size == (broadcast != 0u
            ? 8u : vector_bits / 8u));
        EXPECT(instruction.opcode[2].broadcast == (broadcast != 0u
            ? vector_bits / 64u : CDISASM_X86_BROADCAST_NONE));
    } else {
        EXPECT(instruction.opcode[2].reg == vector_register(3u, vector_bits));
        EXPECT(instruction.opcode[2].size == vector_bits / 8u);
        EXPECT(instruction.opcode[2].broadcast
            == CDISASM_X86_BROADCAST_NONE);
    }
    EXPECT(instruction.mask_mode == (mask == 0u
        ? CDISASM_X86_MASK_NONE
        : zero != 0u ? CDISASM_X86_MASK_ZERO : CDISASM_X86_MASK_MERGE));
    EXPECT(instruction.mask_reg == (mask == 0u
        ? CDISASM_REG_NONE
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + mask)));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, test->feature_group));
    if (test->feature_group == CDISASM_X86_GROUP_AVX512BW) {
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512VBMI));
    }
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512VL) == (length != 2u));
#else
    (void)test;
    (void)length;
    (void)memory;
    (void)broadcast;
    (void)mask;
    (void)zero;
    expect_status("extra-opcodes OFF legal VBMI encoding",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64, code, size,
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_complete_control_lattice(void)
{
    unsigned int allocated = 0;
    unsigned int reserved = 0;
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(vbmi_cases) / sizeof(vbmi_cases[0]);
         ++case_index) {
        const vbmi_case *test = &vbmi_cases[case_index];
        unsigned int w;

        for (w = 0; w != 2u; ++w) {
            unsigned int length;

            for (length = 0; length != 4u; ++length) {
                unsigned int memory;

                for (memory = 0; memory != 2u; ++memory) {
                    unsigned int broadcast;

                    for (broadcast = 0; broadcast != 2u; ++broadcast) {
                        unsigned int mask;

                        for (mask = 0; mask != 8u; ++mask) {
                            unsigned int zero;

                            for (zero = 0; zero != 2u; ++zero) {
                                const int is_target = w == test->w;
                                const int is_word_sibling = w != 0u
                                    && test->opcode != UINT8_C(0x83);
                                const int controls_are_legal = length != 3u
                                    && (broadcast == 0u
                                        || (memory != 0u
                                            && test->broadcast != 0u))
                                    && (zero == 0u || mask != 0u);
                                const int is_legal = is_target
                                    && controls_are_legal;
                                uint8_t code[8];
                                size_t size = make_encoding(test, w, length,
                                    memory, broadcast, mask, zero, code);

                                if (is_legal) {
                                    ++allocated;
                                    check_legal_instruction(test, length,
                                        memory, broadcast, mask, zero,
                                        code, size);
                                } else if (is_word_sibling
                                    && controls_are_legal) {
                                    vbmi_case sibling = *test;

                                    ++allocated;
                                    sibling.w = 1u;
                                    sibling.name_id = test->opcode
                                            == UINT8_C(0x75)
                                        ? CDISASM_X86_NAME_VPERMI2W
                                        : test->opcode == UINT8_C(0x7d)
                                            ? CDISASM_X86_NAME_VPERMT2W
                                            : CDISASM_X86_NAME_VPERMW;
                                    sibling.feature_group =
                                        CDISASM_X86_GROUP_AVX512BW;
                                    sibling.runtime_flag =
                                        CDISASM_X86_DECODE_FLAG_AVX512_BW;
                                    check_legal_instruction(&sibling, length,
                                        memory, broadcast, mask, zero,
                                        code, size);
                                } else {
                                    ++reserved;
                                    expect_status("reserved VBMI control",
                                        CDISASM_CPU_X86, CDISASM_MODE_64,
                                        code, size,
                                        CDISASM_X86_DECODE_FLAG_BASE,
                                        CDISASM_STATUS_INVALID_INSTRUCTION);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    EXPECT(allocated == 675u);
    EXPECT(reserved == 1373u);
}

static void test_tuple_scaling_and_truncation(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t vpermi2b_full[] = {
        0x62, 0xf2, 0x6d, 0x4a, 0x75, 0x4b, 0x02
    };
    static const uint8_t multishift_broadcast[] = {
        0x62, 0xf2, 0xed, 0xda, 0x83, 0x4b, 0x02
    };
    static const uint8_t vpermi2w_full[3][7] = {
        {0x62, 0xf2, 0xed, 0x0a, 0x75, 0x4b, 0x02},
        {0x62, 0xf2, 0xed, 0x2a, 0x75, 0x4b, 0x02},
        {0x62, 0xf2, 0xed, 0x4a, 0x75, 0x4b, 0x02}
    };
#endif
    static const uint8_t missing_modrm[] = {
        0x62, 0xf2, 0x6d, 0x48, 0x7d
    };
    static const uint8_t missing_disp8[] = {
        0x62, 0xf2, 0xed, 0x58, 0x83, 0x4b
    };
    static const uint8_t legacy_prefix[] = {
        0x66, 0x62, 0xf2, 0x6d, 0x48, 0x75, 0xcb
    };
    static const uint8_t legacy_prefix_missing_modrm[] = {
        0x66, 0x62, 0xf2, 0x6d, 0x48, 0x75
    };
    static const uint8_t b4_missing_modrm[] = {
        0x62, 0xfa, 0x6d, 0x49, 0x75
    };
    static const uint8_t b4_complete[] = {
        0x62, 0xfa, 0x6d, 0x49, 0x75, 0xcb
    };
    static const uint8_t w0_multishift_missing_modrm[] = {
        0x62, 0xf2, 0x6d, 0x48, 0x83
    };
    static const uint8_t w0_multishift_complete[] = {
        0x62, 0xf2, 0x6d, 0x48, 0x83, 0xcb
    };
    static const uint8_t zero_without_mask_missing_modrm[] = {
        0x62, 0xf2, 0x6d, 0xc8, 0x75
    };
    static const uint8_t zero_without_mask_complete[] = {
        0x62, 0xf2, 0x6d, 0xc8, 0x75, 0xcb
    };

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    unsigned int length;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        vpermi2b_full, sizeof(vpermi2b_full),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI, &decoded_size);

    EXPECT(decoded_size == sizeof(vpermi2b_full));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPERMI2B);
    EXPECT(instruction.opcode[2].size == 64u);
    EXPECT(instruction.opcode[2].imm == UINT64_C(128));
    EXPECT(instruction.opcode[2].broadcast == CDISASM_X86_BROADCAST_NONE);

    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        multishift_broadcast, sizeof(multishift_broadcast),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI, &decoded_size);
    EXPECT(decoded_size == sizeof(multishift_broadcast));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPMULTISHIFTQB);
    EXPECT(instruction.opcode[2].size == 8u);
    EXPECT(instruction.opcode[2].imm == UINT64_C(16));
    EXPECT(instruction.opcode[2].broadcast == CDISASM_X86_BROADCAST_1_TO_8);

    for (length = 0u; length != 3u; ++length) {
        instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
            vpermi2w_full[length], sizeof(vpermi2w_full[length]),
            CDISASM_X86_DECODE_FLAG_AVX512_BW, &decoded_size);
        EXPECT(decoded_size == sizeof(vpermi2w_full[length]));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPERMI2W);
        EXPECT(instruction.opcode[2].size
            == (UINT8_C(16) << length));
        EXPECT(instruction.opcode[2].imm
            == (UINT64_C(32) << length));
        EXPECT(instruction.opcode[2].broadcast
            == CDISASM_X86_BROADCAST_NONE);
    }
#endif

    expect_status("VBMI missing ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, missing_modrm, sizeof(missing_modrm),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_status("VBMI missing disp8", CDISASM_CPU_X86,
        CDISASM_MODE_64, missing_disp8, sizeof(missing_disp8),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_status("legacy prefix before VBMI EVEX", CDISASM_CPU_X86,
        CDISASM_MODE_64, legacy_prefix, sizeof(legacy_prefix),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("legacy-prefix VBMI missing ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, legacy_prefix_missing_modrm,
        sizeof(legacy_prefix_missing_modrm),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_status("non-long-mode B4 VBMI missing ModRM", CDISASM_CPU_APX,
        CDISASM_MODE_32, b4_missing_modrm, sizeof(b4_missing_modrm),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_status("non-long-mode B4 VBMI complete", CDISASM_CPU_APX,
        CDISASM_MODE_32, b4_complete, sizeof(b4_complete),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("W0 multishift missing ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, w0_multishift_missing_modrm,
        sizeof(w0_multishift_missing_modrm),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_status("W0 multishift complete", CDISASM_CPU_X86,
        CDISASM_MODE_64, w0_multishift_complete,
        sizeof(w0_multishift_complete),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("zero-with-k0 VBMI missing ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, zero_without_mask_missing_modrm,
        sizeof(zero_without_mask_missing_modrm),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    expect_status("zero-with-k0 VBMI complete", CDISASM_CPU_X86,
        CDISASM_MODE_64, zero_without_mask_complete,
        sizeof(zero_without_mask_complete),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

#if USE_EXTRA_OPCODES
static void test_cpu_mode_runtime_and_avx10(void)
{
    static const uint8_t code[] = {
        0x62, 0xf2, 0x6d, 0x48, 0x75, 0xcb
    };
    static const uint8_t word_code[] = {
        0x62, 0xf2, 0xed, 0x48, 0x75, 0xcb
    };
    uint32_t decoded_size;
    cdisasm_x86_decode_option cpu_flags;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512_VBMI,
        &decoded_size);

    EXPECT(decoded_size == sizeof(code));
    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
        &decoded_size);
    EXPECT(decoded_size == sizeof(code));
    expect_status("unrelated runtime selector rejects VBMI",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64, code, sizeof(code),
        CDISASM_X86_DECODE_FLAG_AVX512_CD,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("Skylake-SP lacks VBMI",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64, code, sizeof(code),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512_VBMI,
        &decoded_size);
    EXPECT(decoded_size == sizeof(code));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512VBMI));

    cpu_flags = cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512_VBMI) != 0);

    instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        word_code, sizeof(word_code),
        CDISASM_X86_DECODE_FLAG_AVX512_BW, &decoded_size);
    EXPECT(decoded_size == sizeof(word_code));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPERMI2W);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512BW));
    instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        word_code, sizeof(word_code),
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
    EXPECT(decoded_size == sizeof(word_code));
    expect_status("VBMI selector rejects AVX512BW word permute",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        word_code, sizeof(word_code),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("Haswell lacks AVX512BW",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        word_code, sizeof(word_code),
        CDISASM_X86_DECODE_FLAG_AVX512_BW,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        word_code, sizeof(word_code),
        CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == sizeof(word_code));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPERMI2W);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512BW));
    expect_status("legacy BW selector is not synthesized on AVX10",
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        word_code, sizeof(word_code),
        CDISASM_X86_DECODE_FLAG_AVX512_BW,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    cpu_flags = cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512_BW) != 0);
    cpu_flags = cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_AVX10, CDISASM_MODE_64);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX10) != 0);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512_BW) == 0);
    cpu_flags = cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_AVX10, CDISASM_MODE_64);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX10) != 0);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512_VBMI) != 0);
    cpu_flags = cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_APX, CDISASM_MODE_64);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_APX) != 0);
    EXPECT((cpu_flags & CDISASM_X86_DECODE_FLAG_AVX512_VBMI) != 0);

    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_32,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512_VBMI,
        &decoded_size);
    EXPECT(decoded_size == sizeof(code));
    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_16,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512_VBMI,
        &decoded_size);
    EXPECT(decoded_size == sizeof(code));
}

static void test_apx_b4_u0_routes(void)
{
    static const uint8_t b4_register[] = {
        0x62, 0xfa, 0x6d, 0x49, 0x8d, 0xcb
    };
    static const uint8_t b4_memory[] = {
        0x62, 0xfa, 0x6d, 0x49, 0x75, 0x0b
    };
    static const uint8_t u0_memory[] = {
        0x62, 0xf2, 0xe9, 0x59, 0x83, 0x0b
    };
    static const uint8_t b4_u0_sib[] = {
        0x62, 0xfa, 0x69, 0x49, 0x7d, 0x0c, 0x03
    };
    static const uint8_t u0_register[] = {
        0x62, 0xf2, 0x69, 0x49, 0x75, 0xcb
    };
    static const uint8_t u0_word_sibling[] = {
        0x62, 0xf2, 0xe9, 0x49, 0x75, 0x0b
    };
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_APX, CDISASM_MODE_64,
        b4_register, sizeof(b4_register),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI, &decoded_size);

    EXPECT(decoded_size == sizeof(b4_register));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPERMB);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_ZMM3);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));

    instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
        b4_memory, sizeof(b4_memory),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI, &decoded_size);
    EXPECT(decoded_size == sizeof(b4_memory));
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R19);

    instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
        u0_memory, sizeof(u0_memory),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI, &decoded_size);
    EXPECT(decoded_size == sizeof(u0_memory));
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RBX);
    EXPECT(instruction.opcode[2].broadcast == CDISASM_X86_BROADCAST_1_TO_8);

    instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
        b4_u0_sib, sizeof(b4_u0_sib),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI, &decoded_size);
    EXPECT(decoded_size == sizeof(b4_u0_sib));
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R19);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R16);

    expect_status("VBMI U0 register remains reserved",
        CDISASM_CPU_APX, CDISASM_MODE_64,
        u0_register, sizeof(u0_register),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    instruction = decode(CDISASM_CPU_APX, CDISASM_MODE_64,
        u0_word_sibling, sizeof(u0_word_sibling),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(u0_word_sibling));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPERMI2W);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RBX);
    EXPECT(instruction.opcode[2].broadcast
        == CDISASM_X86_BROADCAST_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    expect_status("VBMI B4 requires APX profile",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        b4_register, sizeof(b4_register),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("VBMI B4 reserved outside long mode",
        CDISASM_CPU_APX, CDISASM_MODE_32,
        b4_register, sizeof(b4_register),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI,
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
    static const uint8_t permute[] = {
        0x62, 0xf2, 0x6d, 0xca, 0x75, 0xcb
    };
    static const uint8_t multishift[] = {
        0x62, 0xf2, 0xed, 0xda, 0x83, 0x4b, 0x02
    };
    static const uint8_t word_permute[] = {
        0x62, 0xf2, 0xed, 0xca, 0x7d, 0xcb
    };
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        permute, sizeof(permute),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI, &decoded_size);

    EXPECT(decoded_size == sizeof(permute));
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpermi2b zmm1 {k2}{z}, zmm2, zmm3");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpermi2b %zmm3, %zmm2, %zmm1{%k2}{z}");

    instruction = decode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        multishift, sizeof(multishift),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI, &decoded_size);
    EXPECT(decoded_size == sizeof(multishift));
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpmultishiftqb zmm1 {k2}{z}, zmm2, qword ptr [rbx + 0x10]{1to8}");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpmultishiftqb 0x10(%rbx){1to8}, %zmm2, %zmm1{%k2}{z}");

    instruction = decode(CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        word_permute, sizeof(word_permute),
        CDISASM_X86_DECODE_FLAG_AVX512_BW, &decoded_size);
    EXPECT(decoded_size == sizeof(word_permute));
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vpermt2w zmm1 {k2}{z}, zmm2, zmm3");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vpermt2w %zmm3, %zmm2, %zmm1{%k2}{z}");
}
#endif

int main(void)
{
    test_complete_control_lattice();
    test_tuple_scaling_and_truncation();
#if USE_EXTRA_OPCODES
    test_cpu_mode_runtime_and_avx10();
    test_apx_b4_u0_routes();
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d AVX512 VBMI test(s) failed\n", failures);
        return 1;
    }
    puts("x86 EVEX AVX512 VBMI tests passed: "
        "675 decoded, "
        "1373 reserved control cells");
    return 0;
}
