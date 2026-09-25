#include "cdisasm/cdisasm_x86.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct rao_case {
    const char *label;
    uint8_t code[6];
    size_t size;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    uint8_t operand_size;
    const char *intel;
    const char *att;
} rao_case;

static const rao_case rao_cases[] = {
    {"AADD r32", {0x0f, 0x38, 0xfc, 0x08}, 4,
     CDISASM_X86_NAME_AADD, UINT16_C(2), 4,
     "aadd dword ptr [rax], ecx", "aadd %ecx, (%rax)"},
    {"AADD r64", {0x48, 0x0f, 0x38, 0xfc, 0x08}, 5,
     CDISASM_X86_NAME_AADD, UINT16_C(3), 8,
     "aadd qword ptr [rax], rcx", "aadd %rcx, (%rax)"},
    {"AAND r32", {0x66, 0x0f, 0x38, 0xfc, 0x08}, 5,
     CDISASM_X86_NAME_AAND, UINT16_C(8), 4,
     "aand dword ptr [rax], ecx", "aand %ecx, (%rax)"},
    {"AAND r64", {0x66, 0x48, 0x0f, 0x38, 0xfc, 0x08}, 6,
     CDISASM_X86_NAME_AAND, UINT16_C(9), 8,
     "aand qword ptr [rax], rcx", "aand %rcx, (%rax)"},
    {"AOR r32", {0xf2, 0x0f, 0x38, 0xfc, 0x08}, 5,
     CDISASM_X86_NAME_AOR, UINT16_C(257), 4,
     "aor dword ptr [rax], ecx", "aor %ecx, (%rax)"},
    {"AOR r64", {0xf2, 0x48, 0x0f, 0x38, 0xfc, 0x08}, 6,
     CDISASM_X86_NAME_AOR, UINT16_C(258), 8,
     "aor qword ptr [rax], rcx", "aor %rcx, (%rax)"},
    {"AXOR r32", {0xf3, 0x0f, 0x38, 0xfc, 0x08}, 5,
     CDISASM_X86_NAME_AXOR, UINT16_C(263), 4,
     "axor dword ptr [rax], ecx", "axor %ecx, (%rax)"},
    {"AXOR r64", {0xf3, 0x48, 0x0f, 0x38, 0xfc, 0x08}, 6,
     CDISASM_X86_NAME_AXOR, UINT16_C(264), 8,
     "axor qword ptr [rax], rcx", "axor %rcx, (%rax)"}
};

static const rao_case apx_rao_cases[] = {
    {"APX AADD r32", {0x62, 0xf4, 0x78, 0x08, 0xfc, 0x08}, 6,
     CDISASM_X86_NAME_AADD, UINT16_C(4), 4,
     "aadd dword ptr [rax], ecx", "aadd %ecx, (%rax)"},
    {"APX AADD r64", {0x62, 0xf4, 0xf8, 0x08, 0xfc, 0x08}, 6,
     CDISASM_X86_NAME_AADD, UINT16_C(5), 8,
     "aadd qword ptr [rax], rcx", "aadd %rcx, (%rax)"},
    {"APX AAND r32", {0x62, 0xf4, 0x79, 0x08, 0xfc, 0x08}, 6,
     CDISASM_X86_NAME_AAND, UINT16_C(10), 4,
     "aand dword ptr [rax], ecx", "aand %ecx, (%rax)"},
    {"APX AAND r64", {0x62, 0xf4, 0xf9, 0x08, 0xfc, 0x08}, 6,
     CDISASM_X86_NAME_AAND, UINT16_C(11), 8,
     "aand qword ptr [rax], rcx", "aand %rcx, (%rax)"},
    {"APX AOR r32", {0x62, 0xf4, 0x7b, 0x08, 0xfc, 0x08}, 6,
     CDISASM_X86_NAME_AOR, UINT16_C(259), 4,
     "aor dword ptr [rax], ecx", "aor %ecx, (%rax)"},
    {"APX AOR r64", {0x62, 0xf4, 0xfb, 0x08, 0xfc, 0x08}, 6,
     CDISASM_X86_NAME_AOR, UINT16_C(260), 8,
     "aor qword ptr [rax], rcx", "aor %rcx, (%rax)"},
    {"APX AXOR r32", {0x62, 0xf4, 0x7a, 0x08, 0xfc, 0x08}, 6,
     CDISASM_X86_NAME_AXOR, UINT16_C(265), 4,
     "axor dword ptr [rax], ecx", "axor %ecx, (%rax)"},
    {"APX AXOR r64", {0x62, 0xf4, 0xfa, 0x08, 0xfc, 0x08}, 6,
     CDISASM_X86_NAME_AXOR, UINT16_C(266), 8,
     "axor qword ptr [rax], rcx", "axor %rcx, (%rax)"}
};

_Static_assert(CDISASM_X86_NAME_AADD == UINT16_C(1198)
        && CDISASM_X86_NAME_AAND == UINT16_C(1199)
        && CDISASM_X86_NAME_AOR == UINT16_C(1211)
        && CDISASM_X86_NAME_AXOR == UINT16_C(1212),
    "RAO-INT mnemonic IDs changed");
_Static_assert(CDISASM_X86_GROUP_RAO_INT == UINT16_C(298),
    "RAO-INT group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_RAO_INT == UINT32_C(245),
    "RAO-INT decode bit changed");
_Static_assert(CDISASM_X86_GROUP_APX_F_RAO_INT == UINT16_C(148),
    "APX-F RAO-INT group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_APX_F_RAO_INT == UINT32_C(96),
    "APX-F RAO-INT decode bit changed");

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",             \
                __FILE__, __LINE__, #expression);                            \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags rao_flags(void)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_RAO_INT));
    return flags;
}

static cdisasm_x86_decode_flags apx_rao_flags(void)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_APX_F_RAO_INT));
    return flags;
}
#endif

static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static cdisasm_instruction decode(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu_id, mode, code, size, UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static void expect_error(
    const char *label,
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu_id, mode, code, size, flags, &decoded_size);

    if (decoded_size != 0 || !is_error_only(&instruction, status)) {
        fprintf(stderr,
            "%s: expected status %u, got size/status %u/%u\n",
            label, (unsigned int)status, (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id);
    }
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_DISASM_FORMAT && USE_EXTRA_OPCODES
static void expect_format(
    const cdisasm_instruction *instruction,
    uint32_t syntax,
    const char *expected)
{
    char output[160];
    size_t required = cdisasm_x86_format(
        instruction, syntax, output, sizeof(output));

    if (required != strlen(expected) || strcmp(output, expected) != 0) {
        fprintf(stderr, "formatted as \"%s\", expected \"%s\"\n",
            output, expected);
    }
    EXPECT(required == strlen(expected));
    EXPECT(strcmp(output, expected) == 0);
}
#endif

static void test_exact_forms(void)
{
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = rao_flags();
#endif

    for (index = 0; index < sizeof(rao_cases) / sizeof(rao_cases[0]); ++index) {
        const rao_case *test = &rao_cases[index];
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            test->code, test->size, &flags, &decoded_size);
        uint8_t prefix_size = (uint8_t)(test->size - 4u);

        EXPECT(decoded_size == test->size);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(instruction.form_id == test->form_id);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[0].size == test->operand_size);
        EXPECT(instruction.opcode[0].access
            == CDISASM_OPERAND_ACCESS_READ_WRITE);
        EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_NONE);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[1].size == test->operand_size);
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.opcode[1].reg
            == (test->operand_size == 8u
                ? CDISASM_X86_REG_RCX : CDISASM_X86_REG_ECX));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_RAO_INT));
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EFFECTIVE_MASK)
            == 0u);
        EXPECT(instruction.encoding.prefix_size == prefix_size);
        EXPECT(instruction.encoding.opcode_offset == prefix_size);
        EXPECT(instruction.encoding.opcode_size == 3u);
        EXPECT(instruction.encoding.modrm_offset == prefix_size + 3u);
        EXPECT(instruction.encoding.modrm == UINT8_C(0x08));
        EXPECT(instruction.encoding.displacement_size == 0u);
#if USE_DISASM_FORMAT
        expect_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL, test->intel);
        expect_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ATT, test->att);
#endif
#else
        expect_error(
            test->label, CDISASM_CPU_X86, CDISASM_MODE_64,
            test->code, test->size, NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_apx_exact_forms(void)
{
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = apx_rao_flags();
#endif

    for (index = 0;
         index < sizeof(apx_rao_cases) / sizeof(apx_rao_cases[0]);
         ++index) {
        const rao_case *test = &apx_rao_cases[index];
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            test->code, test->size, &flags, &decoded_size);

        EXPECT(decoded_size == test->size);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(instruction.form_id == test->form_id);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[0].size == test->operand_size);
        EXPECT(instruction.opcode[0].access
            == CDISASM_OPERAND_ACCESS_READ_WRITE);
        EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_NONE);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[1].size == test->operand_size);
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.opcode[1].reg
            == (test->operand_size == 8u
                ? CDISASM_X86_REG_RCX : CDISASM_X86_REG_ECX));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F_RAO_INT));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_RAO_INT));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
        EXPECT((instruction.opcode_flags
            & (CDISASM_PREFIX_APX_NDD | CDISASM_PREFIX_APX_NF
                | CDISASM_PREFIX_EFFECTIVE_MASK)) == 0u);
        EXPECT(instruction.encoding.prefix_size == 4u);
        EXPECT(instruction.encoding.opcode_offset == 4u);
        EXPECT(instruction.encoding.opcode_size == 1u);
        EXPECT(instruction.encoding.modrm_offset == 5u);
        EXPECT(instruction.encoding.modrm == UINT8_C(0x08));
#if USE_DISASM_FORMAT
        expect_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL, test->intel);
        expect_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ATT, test->att);
#endif
#else
        expect_error(
            test->label, CDISASM_CPU_X86, CDISASM_MODE_64,
            test->code, test->size, NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_apx_addressing_and_gates(void)
{
    static const uint8_t egpr_u0_disp8[] = {
        0x62, 0xac, 0x78, 0x08, 0xfc, 0x4c, 0x38, 0x7f
    };
    static const uint8_t egpr_u1_disp8[] = {
        0x62, 0xac, 0x7c, 0x08, 0xfc, 0x4c, 0x38, 0x80
    };
    static const uint8_t mode32_collision[] = {
        0x62, 0xf4, 0x78, 0x08, 0xfc, 0x08
    };
#if USE_EXTRA_OPCODES
    static const uint8_t valid[] = {
        0x62, 0xf4, 0x78, 0x08, 0xfc, 0x08
    };
    cdisasm_x86_decode_flags flags = apx_rao_flags();
    cdisasm_instruction instruction;
    uint32_t decoded_size;

    instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        egpr_u0_disp8, sizeof(egpr_u0_disp8), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(egpr_u0_disp8));
    EXPECT(instruction.form_id == UINT16_C(4));
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R16);
    EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_R31);
    EXPECT(instruction.opcode[0].scale == 1u);
    EXPECT(instruction.opcode[0].imm == UINT64_C(0x7f));
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R17D);

    instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        egpr_u1_disp8, sizeof(egpr_u1_disp8), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(egpr_u1_disp8));
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R16);
    EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_R15);
    EXPECT(instruction.opcode[0].imm == (uint64_t)INT64_C(-128));
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R17D);

    expect_error(
        "APX RAO runtime exact gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, valid, sizeof(valid), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        cdisasm_x86_decode_flags wrong = rao_flags();

        EXPECT(cdisasm_decode_flags_set_bit(
            &wrong, CDISASM_X86_DECODE_BIT_APX));
        expect_error(
            "APX RAO rejects legacy/generic gates", CDISASM_CPU_X86,
            CDISASM_MODE_64, valid, sizeof(valid), &wrong,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    expect_error(
        "APX RAO abstract APX profile gate", CDISASM_CPU_APX,
        CDISASM_MODE_64, valid, sizeof(valid), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        "APX RAO Diamond Rapids profile gate", CDISASM_CPU_DIAMOND_RAPIDS,
        CDISASM_MODE_64, valid, sizeof(valid), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    expect_error(
        "APX RAO EGPR U0 OFF", CDISASM_CPU_X86, CDISASM_MODE_64,
        egpr_u0_disp8, sizeof(egpr_u0_disp8), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(
        "APX RAO EGPR U1 OFF", CDISASM_CPU_X86, CDISASM_MODE_64,
        egpr_u1_disp8, sizeof(egpr_u1_disp8), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    expect_error(
        "APX RAO mode32", CDISASM_CPU_X86, CDISASM_MODE_32,
        mode32_collision, sizeof(mode32_collision),
#if USE_EXTRA_OPCODES
        &flags,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static size_t build_apx_rao_encoding(
    uint8_t code[12], uint8_t p0, uint8_t p1, uint8_t p2, uint8_t modrm)
{
    uint8_t mod = modrm >> 6;
    uint8_t rm = modrm & UINT8_C(7);
    size_t size = 6u;

    code[0] = UINT8_C(0x62);
    code[1] = p0;
    code[2] = p1;
    code[3] = p2;
    code[4] = UINT8_C(0xfc);
    code[5] = modrm;
    if (mod != 3u && rm == 4u) {
        code[size++] = UINT8_C(0x00);
    } else if (mod == 0u && rm == 5u) {
        code[size++] = UINT8_C(0x44);
        code[size++] = UINT8_C(0x33);
        code[size++] = UINT8_C(0x22);
        code[size++] = UINT8_C(0x11);
    }
    if (mod == 1u) {
        code[size++] = UINT8_C(0x5a);
    } else if (mod == 2u) {
        code[size++] = UINT8_C(0x44);
        code[size++] = UINT8_C(0x33);
        code[size++] = UINT8_C(0x22);
        code[size++] = UINT8_C(0x11);
    }
    return size;
}

static void test_apx_exhaustive_encoding_space(void)
{
    uint8_t code[12];
    unsigned int extension;
    unsigned int pp;
    unsigned int w;
    unsigned int u;
    unsigned int raw_modrm;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = apx_rao_flags();
#endif

    /* 32 extension tuples x 16 pp/W/U tuples x all 256 ModRM values:
     * 98,304 allocated memory encodings and 32,768 reserved register forms. */
    for (extension = 0u; extension < 32u; ++extension) {
        uint8_t p0 = (uint8_t)((extension << 3) | 4u);

        for (pp = 0u; pp < 4u; ++pp) {
            for (w = 0u; w < 2u; ++w) {
                for (u = 0u; u < 2u; ++u) {
                    uint8_t p1 = (uint8_t)(UINT8_C(0x78) | pp
                        | (w << 7) | (u << 2));
#if USE_EXTRA_OPCODES
                    cdisasm_x86_name_id expected_name = pp == 1u
                        ? CDISASM_X86_NAME_AAND
                        : pp == 3u ? CDISASM_X86_NAME_AOR
                        : pp == 2u ? CDISASM_X86_NAME_AXOR
                        : CDISASM_X86_NAME_AADD;
                    cdisasm_x86_form_id form32 = pp == 1u
                        ? UINT16_C(10)
                        : pp == 3u ? UINT16_C(259)
                        : pp == 2u ? UINT16_C(265) : UINT16_C(4);
#endif

                    for (raw_modrm = 0u; raw_modrm < 256u; ++raw_modrm) {
                        uint32_t decoded_size;
                        size_t size = build_apx_rao_encoding(
                            code, p0, p1, UINT8_C(0x08),
                            (uint8_t)raw_modrm);
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
#if USE_EXTRA_OPCODES
                            &flags,
#else
                            NULL,
#endif
                            &decoded_size);

                        if (raw_modrm < 192u) {
#if USE_EXTRA_OPCODES
                            EXPECT(decoded_size == size);
                            EXPECT(instruction.last_error_id
                                == CDISASM_STATUS_OK);
                            EXPECT(instruction.name_id == expected_name);
                            EXPECT(instruction.form_id
                                == (cdisasm_x86_form_id)(form32 + w));
                            EXPECT(instruction.opcode[0].type
                                == CDISASM_OPERAND_MEMORY);
                            EXPECT(instruction.opcode[0].size
                                == (w != 0u ? 8u : 4u));
                            EXPECT(instruction.opcode[1].type
                                == CDISASM_OPERAND_REGISTER);
                            EXPECT(instruction.opcode[1].size
                                == instruction.opcode[0].size);
#else
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(
                                &instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        } else {
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(
                                &instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                        }
                    }
                }
            }
        }
    }
}

static void test_apx_exhaustive_control_space(void)
{
    uint8_t code[12];
    unsigned int raw_p1;
    unsigned int raw_p2;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = apx_rao_flags();
#endif

    /* Every P1/P2 bit combination for a fixed MAP4 FC memory operand.
     * Exactly 16 spellings are allocated (pp/W/U); 65,520 are reserved. */
    for (raw_p1 = 0u; raw_p1 < 256u; ++raw_p1) {
        for (raw_p2 = 0u; raw_p2 < 256u; ++raw_p2) {
            uint32_t decoded_size;
            size_t size = build_apx_rao_encoding(
                code, UINT8_C(0xf4), (uint8_t)raw_p1,
                (uint8_t)raw_p2, UINT8_C(0x08));
            int allocated = (raw_p1 & 0x78u) == 0x78u
                && raw_p2 == 0x08u;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
#if USE_EXTRA_OPCODES
                &flags,
#else
                NULL,
#endif
                &decoded_size);

            if (allocated) {
#if USE_EXTRA_OPCODES
                EXPECT(decoded_size == size);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            } else {
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction,
                    CDISASM_STATUS_INVALID_INSTRUCTION));
            }
        }
    }
}

static void test_apx_structural_failures(void)
{
    static const struct malformed_case {
        const char *label;
        uint8_t code[9];
        size_t size;
        cdisasm_status status;
    } cases[] = {
        {"APX RAO register ModRM", {0x62, 0xf4, 0x78, 0x08, 0xfc, 0xc1},
         6, CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX RAO noncanonical vvvv", {0x62, 0xf4, 0x70, 0x08, 0xfc, 0x08},
         6, CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX RAO ND", {0x62, 0xf4, 0x78, 0x18, 0xfc, 0x08},
         6, CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX RAO NF", {0x62, 0xf4, 0x78, 0x0c, 0xfc, 0x08},
         6, CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX RAO LL", {0x62, 0xf4, 0x78, 0x28, 0xfc, 0x08},
         6, CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX RAO mask", {0x62, 0xf4, 0x78, 0x09, 0xfc, 0x08},
         6, CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX RAO zeroing", {0x62, 0xf4, 0x78, 0x88, 0xfc, 0x08},
         6, CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX RAO legacy prefix", {0x66, 0x62, 0xf4, 0x78, 0x08, 0xfc, 0x08},
         7, CDISASM_STATUS_INVALID_INSTRUCTION},
        {"APX RAO truncated ModRM", {0x62, 0xf4, 0x78, 0x08, 0xfc},
         5, CDISASM_STATUS_TRUNCATED},
        {"APX RAO truncated disp8", {0x62, 0xf4, 0x78, 0x08, 0xfc, 0x48},
         6, CDISASM_STATUS_TRUNCATED},
        {"APX RAO truncated SIB", {0x62, 0xf4, 0x78, 0x08, 0xfc, 0x04},
         6, CDISASM_STATUS_TRUNCATED}
    };
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = apx_rao_flags();
#endif

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error(
            cases[index].label, CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size,
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            cases[index].status);
    }
}

static void test_addressing_and_modes(void)
{
    static const uint8_t mode16[] = {0x0f, 0x38, 0xfc, 0x08};
    static const uint8_t mode32[] = {0x66, 0x0f, 0x38, 0xfc, 0x08};
    static const uint8_t extended_sib[] = {
        0x4d, 0x0f, 0x38, 0xfc, 0x4c, 0x88, 0x7f
    };
#if USE_EXTRA_OPCODES
    static const uint8_t address32[] = {0x67, 0x0f, 0x38, 0xfc, 0x08};
    static const uint8_t fs_override[] = {
        0x64, 0xf3, 0x0f, 0x38, 0xfc, 0x08
    };
    cdisasm_x86_decode_flags flags = rao_flags();
#endif

#if USE_EXTRA_OPCODES
    cdisasm_instruction instruction;
    uint32_t decoded_size;

    instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_16,
        mode16, sizeof(mode16), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(mode16));
    EXPECT(instruction.form_id == UINT16_C(2));
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_BX);
    EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_SI);
    EXPECT(instruction.opcode[0].scale == 1u);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ECX);

    instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_32,
        mode32, sizeof(mode32), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(mode32));
    EXPECT(instruction.form_id == UINT16_C(8));
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_EAX);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ECX);

    instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        address32, sizeof(address32), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(address32));
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_EAX);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u);

    instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        extended_sib, sizeof(extended_sib), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(extended_sib));
    EXPECT(instruction.form_id == UINT16_C(3));
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R8);
    EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_RCX);
    EXPECT(instruction.opcode[0].scale == 4u);
    EXPECT(instruction.opcode[0].imm == UINT64_C(0x7f));
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R9);

    instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        fs_override, sizeof(fs_override), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(fs_override));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_AXOR);
    EXPECT(instruction.opcode[0].segment_reg == CDISASM_X86_REG_FS);
#else
    expect_error(
        "RAO mode16 OFF", CDISASM_CPU_X86, CDISASM_MODE_16,
        mode16, sizeof(mode16), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(
        "RAO mode32 OFF", CDISASM_CPU_X86, CDISASM_MODE_32,
        mode32, sizeof(mode32), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(
        "RAO extended SIB OFF", CDISASM_CPU_X86, CDISASM_MODE_64,
        extended_sib, sizeof(extended_sib), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_prefix_selection_and_failures(void)
{
#if USE_EXTRA_OPCODES
    static const struct prefix_case {
        uint8_t code[7];
        size_t size;
        cdisasm_x86_name_id name_id;
    } prefix_cases[] = {
        {{0x66, 0xf2, 0x0f, 0x38, 0xfc, 0x08}, 6,
         CDISASM_X86_NAME_AOR},
        {{0xf2, 0x66, 0x0f, 0x38, 0xfc, 0x08}, 6,
         CDISASM_X86_NAME_AOR},
        {{0xf2, 0xf3, 0x0f, 0x38, 0xfc, 0x08}, 6,
         CDISASM_X86_NAME_AXOR},
        {{0xf3, 0xf2, 0x0f, 0x38, 0xfc, 0x08}, 6,
         CDISASM_X86_NAME_AOR},
        {{0x66, 0x66, 0x0f, 0x38, 0xfc, 0x08}, 6,
         CDISASM_X86_NAME_AAND}
    };
#endif
    static const uint8_t valid[] = {0x0f, 0x38, 0xfc, 0x08};
    static const uint8_t locked[] = {0xf0, 0x0f, 0x38, 0xfc, 0x08};
    static const uint8_t register_modrm[] = {0x0f, 0x38, 0xfc, 0xc1};
    static const uint8_t truncated[] = {0xf3, 0x0f, 0x38, 0xfc};
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = rao_flags();
    size_t index;
#endif

#if USE_EXTRA_OPCODES
    for (index = 0;
         index < sizeof(prefix_cases) / sizeof(prefix_cases[0]);
         ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            prefix_cases[index].code, prefix_cases[index].size,
            &flags, &decoded_size);

        EXPECT(decoded_size == prefix_cases[index].size);
        EXPECT(instruction.name_id == prefix_cases[index].name_id);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EFFECTIVE_MASK)
            == 0u);
    }

    expect_error(
        "RAO runtime family gate", CDISASM_CPU_X86, CDISASM_MODE_64,
        valid, sizeof(valid), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        cdisasm_x86_decode_flags wrong =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

        EXPECT(cdisasm_decode_flags_set_bit(
            &wrong, CDISASM_X86_DECODE_BIT_APX_F_RAO_INT));
        expect_error(
            "RAO exact bit gate", CDISASM_CPU_X86, CDISASM_MODE_64,
            valid, sizeof(valid), &wrong,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    expect_error(
        "RAO named CPU gate", CDISASM_CPU_DIAMOND_RAPIDS,
        CDISASM_MODE_64, valid, sizeof(valid), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    expect_error(
        "RAO optional implementation OFF", CDISASM_CPU_X86,
        CDISASM_MODE_64, valid, sizeof(valid), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    expect_error(
        "RAO rejects LOCK", CDISASM_CPU_X86, CDISASM_MODE_64,
        locked, sizeof(locked),
#if USE_EXTRA_OPCODES
        &flags,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        "RAO rejects register ModRM", CDISASM_CPU_X86, CDISASM_MODE_64,
        register_modrm, sizeof(register_modrm),
#if USE_EXTRA_OPCODES
        &flags,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        "RAO truncated ModRM", CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated, sizeof(truncated),
#if USE_EXTRA_OPCODES
        &flags,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
}

static void test_cpu_flag_masks(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t index;

    for (index = 0; index < sizeof(modes) / sizeof(modes[0]); ++index) {
        cdisasm_x86_decode_flags flags;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_X86, modes[index], &flags) == CDISASM_STATUS_OK);
        EXPECT(cdisasm_decode_flags_test_bit(
            &flags, CDISASM_X86_DECODE_BIT_RAO_INT)
            == USE_EXTRA_OPCODES);
        EXPECT(cdisasm_decode_flags_test_bit(
            &flags, CDISASM_X86_DECODE_BIT_APX_F_RAO_INT)
            == (USE_EXTRA_OPCODES && modes[index] == CDISASM_MODE_64));
    }
#if USE_EXTRA_OPCODES
    {
        cdisasm_x86_decode_flags flags;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64, &flags)
            == CDISASM_STATUS_OK);
        EXPECT(!cdisasm_decode_flags_test_bit(
            &flags, CDISASM_X86_DECODE_BIT_RAO_INT));
        EXPECT(!cdisasm_decode_flags_test_bit(
            &flags, CDISASM_X86_DECODE_BIT_APX_F_RAO_INT));
    }
#endif
}

int main(void)
{
    test_exact_forms();
    test_apx_exact_forms();
    test_addressing_and_modes();
    test_apx_addressing_and_gates();
    test_prefix_selection_and_failures();
    test_apx_exhaustive_encoding_space();
    test_apx_exhaustive_control_space();
    test_apx_structural_failures();
    test_cpu_flag_masks();

    if (failures != 0) {
        fprintf(stderr, "%d RAO-INT test(s) failed\n", failures);
        return 1;
    }
    puts("all x86 RAO-INT tests passed (196608 exhaustive APX cases)");
    return 0;
}
