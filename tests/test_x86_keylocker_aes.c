#include "cdisasm/cdisasm_x86.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",            \
                __FILE__, __LINE__, #expression);                            \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_GROUP_KEYLOCKER == UINT16_C(277),
    "KEYLOCKER group ID changed");
_Static_assert(CDISASM_X86_GROUP_KEYLOCKER_WIDE == UINT16_C(278),
    "KEYLOCKER_WIDE group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_KEYLOCKER == UINT32_C(224),
    "KEYLOCKER decode bit changed");
_Static_assert(CDISASM_X86_DECODE_BIT_KEYLOCKER_WIDE == UINT32_C(225),
    "KEYLOCKER_WIDE decode bit changed");

typedef struct keylocker_case {
    const char *label;
    uint8_t opcode;
    uint8_t modrm;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    uint8_t memory_size;
    uint8_t wide;
    const char *intel;
    const char *att;
} keylocker_case;

static const keylocker_case keylocker_cases[] = {
    {"AESDEC128KL", 0xdd, 0x00, CDISASM_X86_NAME_AESDEC128KL,
     UINT16_C(157), 48, 0,
     "aesdec128kl xmm0, m48byte ptr [rax]",
     "aesdec128kl (%rax), %xmm0"},
    {"AESDEC256KL", 0xdf, 0x00, CDISASM_X86_NAME_AESDEC256KL,
     UINT16_C(158), 64, 0,
     "aesdec256kl xmm0, zmmword ptr [rax]",
     "aesdec256kl (%rax), %xmm0"},
    {"AESDECWIDE128KL", 0xd8, 0x08,
     CDISASM_X86_NAME_AESDECWIDE128KL, UINT16_C(161), 48, 1,
     "aesdecwide128kl m48byte ptr [rax]",
     "aesdecwide128kl (%rax)"},
    {"AESDECWIDE256KL", 0xd8, 0x18,
     CDISASM_X86_NAME_AESDECWIDE256KL, UINT16_C(162), 64, 1,
     "aesdecwide256kl zmmword ptr [rax]",
     "aesdecwide256kl (%rax)"},
    {"AESENC128KL", 0xdc, 0x00, CDISASM_X86_NAME_AESENC128KL,
     UINT16_C(165), 48, 0,
     "aesenc128kl xmm0, m48byte ptr [rax]",
     "aesenc128kl (%rax), %xmm0"},
    {"AESENC256KL", 0xde, 0x00, CDISASM_X86_NAME_AESENC256KL,
     UINT16_C(166), 64, 0,
     "aesenc256kl xmm0, zmmword ptr [rax]",
     "aesenc256kl (%rax), %xmm0"},
    {"AESENCWIDE128KL", 0xd8, 0x00,
     CDISASM_X86_NAME_AESENCWIDE128KL, UINT16_C(169), 48, 1,
     "aesencwide128kl m48byte ptr [rax]",
     "aesencwide128kl (%rax)"},
    {"AESENCWIDE256KL", 0xd8, 0x10,
     CDISASM_X86_NAME_AESENCWIDE256KL, UINT16_C(170), 64, 1,
     "aesencwide256kl zmmword ptr [rax]",
     "aesencwide256kl (%rax)"}
};

typedef struct key_management_case {
    const char *label;
    uint8_t opcode;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    uint8_t vector_operands;
    uint8_t privileged;
    const char *intel;
    const char *att;
} key_management_case;

static const key_management_case key_management_cases[] = {
    {"ENCODEKEY128", 0xfa, CDISASM_X86_NAME_ENCODEKEY128,
     UINT16_C(1138), 0, 0,
     "encodekey128 eax, ecx", "encodekey128 %ecx, %eax"},
    {"ENCODEKEY256", 0xfb, CDISASM_X86_NAME_ENCODEKEY256,
     UINT16_C(1139), 0, 0,
     "encodekey256 eax, ecx", "encodekey256 %ecx, %eax"},
    {"LOADIWKEY", 0xdc, CDISASM_X86_NAME_LOADIWKEY,
     UINT16_C(1596), 1, 1,
     "loadiwkey xmm0, xmm1", "loadiwkey %xmm1, %xmm0"}
};

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
        fprintf(stderr, "%s: got size/status %u/%u, expected 0/%u\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id,
            (unsigned int)status);
    }
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags one_bit(cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit_id));
    return flags;
}

static int expected_group_present(
    const cdisasm_instruction *instruction,
    int wide)
{
    return cdisasm_instruction_has_x86_group(
        instruction,
        wide ? CDISASM_X86_GROUP_KEYLOCKER_WIDE
             : CDISASM_X86_GROUP_KEYLOCKER);
}

#  if USE_DISASM_FORMAT
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
#  endif
#endif

static void test_exact_examples(void)
{
    size_t index;

    for (index = 0;
         index < sizeof(keylocker_cases) / sizeof(keylocker_cases[0]);
         ++index) {
        const keylocker_case *test = &keylocker_cases[index];
        uint8_t code[] = {0xf3, 0x0f, 0x38, test->opcode, test->modrm};
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(
            test->wide ? CDISASM_X86_DECODE_BIT_KEYLOCKER_WIDE
                       : CDISASM_X86_DECODE_BIT_KEYLOCKER);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(code));
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(instruction.form_id == test->form_id);
        EXPECT(expected_group_present(&instruction, test->wide));
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS) == 0u);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REP) != 0u);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EFFECTIVE_MASK)
            == 0u);
        EXPECT(instruction.encoding.prefix_size == 1u);
        EXPECT(instruction.encoding.opcode_offset == 1u);
        EXPECT(instruction.encoding.opcode_size == 3u);
        EXPECT(instruction.encoding.modrm_offset == 4u);
        EXPECT(instruction.encoding.modrm == test->modrm);
        EXPECT(instruction.operand_count == (test->wide ? 1u : 2u));
        if (!test->wide) {
            EXPECT(instruction.opcode[0].type
                == CDISASM_OPERAND_REGISTER);
            EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM0);
            EXPECT(instruction.opcode[0].size == 16u);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
        }
        EXPECT(instruction.opcode[test->wide ? 0 : 1].type
            == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[test->wide ? 0 : 1].size
            == test->memory_size);
        EXPECT(instruction.opcode[test->wide ? 0 : 1].access
            == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.opcode[test->wide ? 0 : 1].base_reg
            == CDISASM_X86_REG_RAX);
#  if USE_DISASM_FORMAT
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL, test->intel);
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT, test->att);
#  endif
#else
        expect_error(test->label, CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_key_management_examples(void)
{
    size_t index;

    for (index = 0;
         index < sizeof(key_management_cases)
             / sizeof(key_management_cases[0]);
         ++index) {
        const key_management_case *test = &key_management_cases[index];
        uint8_t code[] = {0xf3, 0x0f, 0x38, test->opcode, 0xc1};
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(
            CDISASM_X86_DECODE_BIT_KEYLOCKER);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);
        cdisasm_x86_reg_id first_reg = test->vector_operands
            ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_EAX;
        cdisasm_x86_reg_id second_reg = test->vector_operands
            ? CDISASM_X86_REG_XMM1 : CDISASM_X86_REG_ECX;
        uint8_t operand_size = test->vector_operands ? 16u : 4u;

        EXPECT(decoded_size == sizeof(code));
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(instruction.form_id == test->form_id);
        EXPECT(expected_group_present(&instruction, 0));
        EXPECT(!expected_group_present(&instruction, 1));
        EXPECT(((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u)
            == test->privileged);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS) == 0u);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REP) != 0u);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EFFECTIVE_MASK)
            == 0u);
        EXPECT(instruction.encoding.prefix_size == 1u);
        EXPECT(instruction.encoding.opcode_offset == 1u);
        EXPECT(instruction.encoding.opcode_size == 3u);
        EXPECT(instruction.encoding.modrm_offset == 4u);
        EXPECT(instruction.encoding.modrm == 0xc1u);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[0].reg == first_reg);
        EXPECT(instruction.opcode[0].size == operand_size);
        EXPECT(instruction.opcode[0].access
            == (test->vector_operands
                ? CDISASM_OPERAND_ACCESS_READ
                : CDISASM_OPERAND_ACCESS_WRITE));
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[1].reg == second_reg);
        EXPECT(instruction.opcode[1].size == operand_size);
        EXPECT(instruction.opcode[1].access
            == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL, test->intel);
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT, test->att);
#  endif
#else
        expect_error(test->label, CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_exhaustive_narrow_space(void)
{
    static const uint8_t opcodes[] = {0xdc, 0xdd, 0xde, 0xdf};
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;
    size_t opcode_index;

    for (mode_index = 0; mode_index < 3u; ++mode_index) {
        for (opcode_index = 0; opcode_index < 4u; ++opcode_index) {
            unsigned int mod;
            unsigned int reg;
            unsigned int rm;
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags flags = one_bit(
                CDISASM_X86_DECODE_BIT_KEYLOCKER);
#endif

            for (mod = 0; mod < 3u; ++mod) {
                for (reg = 0; reg < 8u; ++reg) {
                    for (rm = 0; rm < 8u; ++rm) {
                        uint8_t code[15] = {
                            0xf3, 0x0f, 0x38, opcodes[opcode_index],
                            (uint8_t)((mod << 6) | (reg << 3) | rm)
                        };
#if USE_EXTRA_OPCODES
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_X86, modes[mode_index],
                            code, sizeof(code), &flags, &decoded_size);
                        uint8_t expected_memory_size = opcode_index >= 2u
                            ? 64u : 48u;

                        EXPECT(decoded_size >= 5u);
                        EXPECT(instruction.last_error_id
                            == CDISASM_STATUS_OK);
                        EXPECT(instruction.form_id
                            == keylocker_cases[
                                opcode_index == 0 ? 4u
                                : opcode_index == 1 ? 0u
                                : opcode_index == 2 ? 5u : 1u].form_id);
                        EXPECT(instruction.opcode[0].type
                            == CDISASM_OPERAND_REGISTER);
                        EXPECT(instruction.opcode[0].size == 16u);
                        EXPECT(instruction.opcode[0].access
                            == CDISASM_OPERAND_ACCESS_READ_WRITE);
                        EXPECT(instruction.opcode[1].type
                            == CDISASM_OPERAND_MEMORY);
                        EXPECT(instruction.opcode[1].size
                            == expected_memory_size);
                        EXPECT(instruction.opcode[1].access
                            == CDISASM_OPERAND_ACCESS_READ);
#else
                        expect_error("narrow exhaustive OFF",
                            CDISASM_CPU_X86, modes[mode_index],
                            code, sizeof(code), NULL,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                    }
                }
            }
        }
    }
}

static void test_exhaustive_wide_space(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;

    for (mode_index = 0; mode_index < 3u; ++mode_index) {
        unsigned int mod;
        unsigned int selector;
        unsigned int rm;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(
            CDISASM_X86_DECODE_BIT_KEYLOCKER_WIDE);
#endif

        for (mod = 0; mod < 4u; ++mod) {
            for (selector = 0; selector < 8u; ++selector) {
                for (rm = 0; rm < 8u; ++rm) {
                    uint8_t code[15] = {
                        0xf3, 0x0f, 0x38, 0xd8,
                        (uint8_t)((mod << 6) | (selector << 3) | rm)
                    };
                    const int allocated = mod < 3u && selector < 4u;
#if USE_EXTRA_OPCODES
                    if (allocated) {
                        static const cdisasm_x86_form_id forms[4] = {
                            UINT16_C(169), UINT16_C(161),
                            UINT16_C(170), UINT16_C(162)
                        };
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_X86, modes[mode_index],
                            code, sizeof(code), &flags, &decoded_size);

                        EXPECT(decoded_size >= 5u);
                        EXPECT(instruction.last_error_id
                            == CDISASM_STATUS_OK);
                        EXPECT(instruction.form_id == forms[selector]);
                        EXPECT(instruction.operand_count == 1u);
                        EXPECT(instruction.opcode[0].type
                            == CDISASM_OPERAND_MEMORY);
                        EXPECT(instruction.opcode[0].size
                            == ((selector & 2u) != 0u ? 64u : 48u));
                        EXPECT(instruction.opcode[0].access
                            == CDISASM_OPERAND_ACCESS_READ);
                    } else {
                        expect_error("reserved wide tuple",
                            CDISASM_CPU_X86, modes[mode_index],
                            code, sizeof(code), &flags,
                            CDISASM_STATUS_INVALID_INSTRUCTION);
                    }
#else
                    expect_error("wide exhaustive OFF",
                        CDISASM_CPU_X86, modes[mode_index],
                        code, sizeof(code), NULL,
                        allocated ? CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
                                  : CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
                }
            }
        }
    }
}

static void test_exhaustive_encodekey_space(void)
{
    static const uint8_t opcodes[] = {0xfa, 0xfb};
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;
    size_t opcode_index;

    for (mode_index = 0; mode_index < 3u; ++mode_index) {
        for (opcode_index = 0; opcode_index < 2u; ++opcode_index) {
            unsigned int mod;
            unsigned int reg;
            unsigned int rm;
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags flags = one_bit(
                CDISASM_X86_DECODE_BIT_KEYLOCKER);
#endif

            for (mod = 0; mod < 4u; ++mod) {
                for (reg = 0; reg < 8u; ++reg) {
                    for (rm = 0; rm < 8u; ++rm) {
                        uint8_t code[15] = {
                            0xf3, 0x0f, 0x38, opcodes[opcode_index],
                            (uint8_t)((mod << 6) | (reg << 3) | rm)
                        };
                        const int allocated = mod == 3u;
#if USE_EXTRA_OPCODES
                        if (allocated) {
                            uint32_t decoded_size;
                            cdisasm_instruction instruction = decode(
                                CDISASM_CPU_X86, modes[mode_index],
                                code, sizeof(code), &flags, &decoded_size);

                            EXPECT(decoded_size == 5u);
                            EXPECT(instruction.last_error_id
                                == CDISASM_STATUS_OK);
                            EXPECT(instruction.name_id
                                == key_management_cases[opcode_index].name_id);
                            EXPECT(instruction.form_id
                                == key_management_cases[opcode_index].form_id);
                            EXPECT(instruction.operand_count == 2u);
                            EXPECT(instruction.opcode[0].type
                                == CDISASM_OPERAND_REGISTER);
                            EXPECT(instruction.opcode[0].reg
                                == (cdisasm_x86_reg_id)(
                                    CDISASM_X86_REG_EAX + reg));
                            EXPECT(instruction.opcode[0].size == 4u);
                            EXPECT(instruction.opcode[0].access
                                == CDISASM_OPERAND_ACCESS_WRITE);
                            EXPECT(instruction.opcode[1].type
                                == CDISASM_OPERAND_REGISTER);
                            EXPECT(instruction.opcode[1].reg
                                == (cdisasm_x86_reg_id)(
                                    CDISASM_X86_REG_EAX + rm));
                            EXPECT(instruction.opcode[1].size == 4u);
                            EXPECT(instruction.opcode[1].access
                                == CDISASM_OPERAND_ACCESS_READ);
                        } else {
                            expect_error("ENCODEKEY memory tuple",
                                CDISASM_CPU_X86, modes[mode_index],
                                code, sizeof(code), &flags,
                                CDISASM_STATUS_INVALID_INSTRUCTION);
                        }
#else
                        expect_error("ENCODEKEY exhaustive OFF",
                            CDISASM_CPU_X86, modes[mode_index],
                            code, sizeof(code), NULL,
                            allocated ? CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
                                      : CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
                    }
                }
            }
        }
    }
}

static void test_exhaustive_loadiwkey_space(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;

    for (mode_index = 0; mode_index < 3u; ++mode_index) {
        unsigned int reg;
        unsigned int rm;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(
            CDISASM_X86_DECODE_BIT_KEYLOCKER);
#endif

        for (reg = 0; reg < 8u; ++reg) {
            for (rm = 0; rm < 8u; ++rm) {
                uint8_t code[] = {
                    0xf3, 0x0f, 0x38, 0xdc,
                    (uint8_t)(0xc0u | (reg << 3) | rm)
                };
#if USE_EXTRA_OPCODES
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, modes[mode_index],
                    code, sizeof(code), &flags, &decoded_size);

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == CDISASM_X86_NAME_LOADIWKEY);
                EXPECT(instruction.form_id == UINT16_C(1596));
                EXPECT((instruction.opcode_groups
                    & CDISASM_GROUP_PRIVILEGED) != 0u);
                EXPECT(instruction.operand_count == 2u);
                EXPECT(instruction.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                EXPECT(instruction.opcode[0].reg
                    == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + reg));
                EXPECT(instruction.opcode[0].size == 16u);
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(instruction.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                EXPECT(instruction.opcode[1].reg
                    == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + rm));
                EXPECT(instruction.opcode[1].size == 16u);
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
#else
                expect_error("LOADIWKEY exhaustive OFF",
                    CDISASM_CPU_X86, modes[mode_index],
                    code, sizeof(code), NULL,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            }
        }
    }
}

static void test_prefix_address_and_collisions(void)
{
    static const uint8_t rex_w[] = {
        0xf3, 0x48, 0x0f, 0x38, 0xdd, 0x00};
    static const uint8_t rex_r[] = {
        0xf3, 0x44, 0x0f, 0x38, 0xdd, 0x00};
    static const uint8_t wide_rex_r[] = {
        0xf3, 0x44, 0x0f, 0x38, 0xd8, 0x08};
    static const uint8_t redundant_66[] = {
        0x66, 0xf3, 0x0f, 0x38, 0xdd, 0x00};
    static const uint8_t f2_then_f3[] = {
        0xf2, 0xf3, 0x0f, 0x38, 0xdd, 0x00};
    static const uint8_t f3_then_f2[] = {
        0xf3, 0xf2, 0x0f, 0x38, 0xdd, 0x00};
    static const uint8_t loadiwkey[] = {
        0xf3, 0x0f, 0x38, 0xdc, 0xc1};
    static const uint8_t aesni_collision[] = {
        0x66, 0x0f, 0x38, 0xdc, 0xc1};
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_KEYLOCKER);
    cdisasm_x86_decode_flags wide = one_bit(
        CDISASM_X86_DECODE_BIT_KEYLOCKER_WIDE);
    const uint8_t *examples[] = {rex_w, redundant_66, f2_then_f3};
    const size_t sizes[] = {
        sizeof(rex_w), sizeof(redundant_66), sizeof(f2_then_f3)};
    size_t index;

    for (index = 0; index < 3u; ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            examples[index], sizes[index], &flags, &decoded_size);

        EXPECT(decoded_size == sizes[index]);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_AESDEC128KL);
    }
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            rex_r, sizeof(rex_r), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(rex_r));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM8);
    }
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            wide_rex_r, sizeof(wide_rex_r), &wide, &decoded_size);

        EXPECT(decoded_size == sizeof(wide_rex_r));
        EXPECT(instruction.name_id
            == CDISASM_X86_NAME_AESDECWIDE128KL);
    }
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            loadiwkey, sizeof(loadiwkey), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(loadiwkey));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LOADIWKEY);
        EXPECT(instruction.form_id == UINT16_C(1596));
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM0);
        EXPECT(instruction.opcode[0].access
            == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
        EXPECT(instruction.opcode[1].access
            == CDISASM_OPERAND_ACCESS_READ);
        EXPECT((instruction.opcode_groups
            & CDISASM_GROUP_PRIVILEGED) != 0u);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
    }
    {
        cdisasm_x86_decode_flags all_flags;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_X86, CDISASM_MODE_64, &all_flags)
            == CDISASM_STATUS_OK);
        instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            aesni_collision, sizeof(aesni_collision),
            &all_flags, &decoded_size);
        EXPECT(decoded_size == sizeof(aesni_collision));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_AESENC);
        EXPECT(!expected_group_present(&instruction, 0));
        EXPECT(!expected_group_present(&instruction, 1));
    }
#else
    expect_error("REX.W OFF", CDISASM_CPU_X86, CDISASM_MODE_64,
        rex_w, sizeof(rex_w), NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX.R OFF", CDISASM_CPU_X86, CDISASM_MODE_64,
        rex_r, sizeof(rex_r), NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("wide REX.R OFF", CDISASM_CPU_X86, CDISASM_MODE_64,
        wide_rex_r, sizeof(wide_rex_r), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("redundant 66 OFF", CDISASM_CPU_X86, CDISASM_MODE_64,
        redundant_66, sizeof(redundant_66), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("F2 F3 OFF", CDISASM_CPU_X86, CDISASM_MODE_64,
        f2_then_f3, sizeof(f2_then_f3), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("LOADIWKEY OFF", CDISASM_CPU_X86, CDISASM_MODE_64,
        loadiwkey, sizeof(loadiwkey), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AES-NI collision OFF", CDISASM_CPU_X86,
        CDISASM_MODE_64, aesni_collision, sizeof(aesni_collision), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    expect_error("rightmost F2", CDISASM_CPU_X86, CDISASM_MODE_64,
        f3_then_f2, sizeof(f3_then_f2), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_key_management_prefixes(void)
{
    static const uint8_t encode_rex_w[] = {
        0xf3, 0x48, 0x0f, 0x38, 0xfa, 0xc1};
    static const uint8_t encode_rex_r[] = {
        0xf3, 0x44, 0x0f, 0x38, 0xfa, 0xc1};
    static const uint8_t encode_rex_b[] = {
        0xf3, 0x41, 0x0f, 0x38, 0xfb, 0xc1};
    static const uint8_t loadiw_rex_w[] = {
        0xf3, 0x48, 0x0f, 0x38, 0xdc, 0xc1};
    static const uint8_t loadiw_rex_r[] = {
        0xf3, 0x44, 0x0f, 0x38, 0xdc, 0xc1};
    static const uint8_t loadiw_rex_b[] = {
        0xf3, 0x41, 0x0f, 0x38, 0xdc, 0xc1};
    static const uint8_t encode_redundant_66[] = {
        0x66, 0xf3, 0x0f, 0x38, 0xfa, 0xc1};
    static const uint8_t loadiw_rightmost_f3[] = {
        0xf2, 0xf3, 0x0f, 0x38, 0xdc, 0xc1};
    struct prefix_case {
        const char *label;
        const uint8_t *code;
        size_t size;
        cdisasm_x86_name_id name_id;
        cdisasm_x86_reg_id first_reg;
        cdisasm_x86_reg_id second_reg;
    };
    static const struct prefix_case cases[] = {
        {"ENCODEKEY REX.W", encode_rex_w, sizeof(encode_rex_w),
         CDISASM_X86_NAME_ENCODEKEY128,
         CDISASM_X86_REG_EAX, CDISASM_X86_REG_ECX},
        {"ENCODEKEY REX.R", encode_rex_r, sizeof(encode_rex_r),
         CDISASM_X86_NAME_ENCODEKEY128,
         CDISASM_X86_REG_R8D, CDISASM_X86_REG_ECX},
        {"ENCODEKEY REX.B", encode_rex_b, sizeof(encode_rex_b),
         CDISASM_X86_NAME_ENCODEKEY256,
         CDISASM_X86_REG_EAX, CDISASM_X86_REG_R9D},
        {"LOADIWKEY REX.W", loadiw_rex_w, sizeof(loadiw_rex_w),
         CDISASM_X86_NAME_LOADIWKEY,
         CDISASM_X86_REG_XMM0, CDISASM_X86_REG_XMM1},
        {"LOADIWKEY REX.R", loadiw_rex_r, sizeof(loadiw_rex_r),
         CDISASM_X86_NAME_LOADIWKEY,
         CDISASM_X86_REG_XMM8, CDISASM_X86_REG_XMM1},
        {"LOADIWKEY REX.B", loadiw_rex_b, sizeof(loadiw_rex_b),
         CDISASM_X86_NAME_LOADIWKEY,
         CDISASM_X86_REG_XMM0, CDISASM_X86_REG_XMM9},
        {"ENCODEKEY redundant 66", encode_redundant_66,
         sizeof(encode_redundant_66), CDISASM_X86_NAME_ENCODEKEY128,
         CDISASM_X86_REG_EAX, CDISASM_X86_REG_ECX},
        {"LOADIWKEY rightmost F3", loadiw_rightmost_f3,
         sizeof(loadiw_rightmost_f3), CDISASM_X86_NAME_LOADIWKEY,
         CDISASM_X86_REG_XMM0, CDISASM_X86_REG_XMM1}
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(
            CDISASM_X86_DECODE_BIT_KEYLOCKER);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);

        EXPECT(decoded_size == cases[index].size);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == cases[index].name_id);
        EXPECT(instruction.opcode[0].reg == cases[index].first_reg);
        EXPECT(instruction.opcode[1].reg == cases[index].second_reg);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EFFECTIVE_MASK)
            == 0u);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
#else
        expect_error(cases[index].label,
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_gates_and_boundaries(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t narrow[] = {0xf3, 0x0f, 0x38, 0xdd, 0x00};
    static const uint8_t wide_code[] = {0xf3, 0x0f, 0x38, 0xd8, 0x08};
#endif
    static const uint8_t lock[] = {0xf0, 0xf3, 0x0f, 0x38, 0xdd, 0x00};
    static const uint8_t register_form[] = {
        0xf3, 0x0f, 0x38, 0xdd, 0xc0};
    static const uint8_t wide_reserved[] = {
        0xf3, 0x0f, 0x38, 0xd8, 0x20};
    static const uint8_t truncated_modrm[] = {0xf3, 0x0f, 0x38, 0xdd};
    static const uint8_t truncated_disp8[] = {
        0xf3, 0x0f, 0x38, 0xdd, 0x40};
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_KEYLOCKER);
    cdisasm_x86_decode_flags wide = one_bit(
        CDISASM_X86_DECODE_BIT_KEYLOCKER_WIDE);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    expect_error("no exact bit", CDISASM_CPU_X86, CDISASM_MODE_64,
        narrow, sizeof(narrow), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("wrong exact bit", CDISASM_CPU_X86, CDISASM_MODE_64,
        narrow, sizeof(narrow), &wide,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("wide wrong exact bit", CDISASM_CPU_X86, CDISASM_MODE_64,
        wide_code, sizeof(wide_code), &flags,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("Ice Lake CPU gate", CDISASM_CPU_ICE_LAKE,
        CDISASM_MODE_64, narrow, sizeof(narrow), &flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    instruction = decode(CDISASM_CPU_TIGER_LAKE, CDISASM_MODE_64,
        narrow, sizeof(narrow), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(narrow));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_AESDEC128KL);
#else
    const cdisasm_x86_decode_flags *flags_ptr = NULL;
#endif
    expect_error("LOCK", CDISASM_CPU_X86, CDISASM_MODE_64,
        lock, sizeof(lock),
#if USE_EXTRA_OPCODES
        &flags,
#else
        flags_ptr,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("register target", CDISASM_CPU_X86, CDISASM_MODE_64,
        register_form, sizeof(register_form),
#if USE_EXTRA_OPCODES
        &flags,
#else
        flags_ptr,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("wide reserved selector", CDISASM_CPU_X86,
        CDISASM_MODE_64, wide_reserved, sizeof(wide_reserved),
#if USE_EXTRA_OPCODES
        &wide,
#else
        flags_ptr,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("truncated ModRM", CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_modrm, sizeof(truncated_modrm),
#if USE_EXTRA_OPCODES
        &flags,
#else
        flags_ptr,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated disp8", CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_disp8, sizeof(truncated_disp8),
#if USE_EXTRA_OPCODES
        &flags,
#else
        flags_ptr,
#endif
        CDISASM_STATUS_TRUNCATED);
}

static void test_key_management_gates_and_boundaries(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t encodekey[] = {
        0xf3, 0x0f, 0x38, 0xfa, 0xc1};
    static const uint8_t loadiwkey[] = {
        0xf3, 0x0f, 0x38, 0xdc, 0xc1};
#endif
    static const uint8_t missing_f3[] = {
        0x0f, 0x38, 0xfa, 0xc1};
    static const uint8_t wrong_f2[] = {
        0xf2, 0x0f, 0x38, 0xfa, 0xc1};
    static const uint8_t rightmost_f2[] = {
        0xf3, 0xf2, 0x0f, 0x38, 0xdc, 0xc1};
    static const uint8_t lock[] = {
        0xf0, 0xf3, 0x0f, 0x38, 0xfa, 0xc1};
    static const uint8_t rex2[] = {
        0xf3, 0xd5, 0x00, 0x0f, 0x38, 0xfa, 0xc1};
    static const uint8_t memory_complete[] = {
        0xf3, 0x0f, 0x38, 0xfa, 0x84, 0x88, 0x78, 0x56, 0x34, 0x12};
    static const uint8_t memory_truncated[] = {
        0xf3, 0x0f, 0x38, 0xfa, 0x84, 0x88, 0x78, 0x56, 0x34};
    static const uint8_t sib_truncated[] = {
        0xf3, 0x0f, 0x38, 0xfa, 0x04};
    static const uint8_t modrm_truncated[] = {
        0xf3, 0x0f, 0x38, 0xfb};
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_KEYLOCKER);
    cdisasm_x86_decode_flags wide = one_bit(
        CDISASM_X86_DECODE_BIT_KEYLOCKER_WIDE);

    expect_error("ENCODEKEY no exact bit",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        encodekey, sizeof(encodekey), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("ENCODEKEY wrong exact bit",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        encodekey, sizeof(encodekey), &wide,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("LOADIWKEY no exact bit",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        loadiwkey, sizeof(loadiwkey), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("LOADIWKEY wrong exact bit",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        loadiwkey, sizeof(loadiwkey), &wide,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    const cdisasm_x86_decode_flags *flags_ptr = NULL;
#endif

    expect_error("ENCODEKEY missing F3",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        missing_f3, sizeof(missing_f3), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("ENCODEKEY F2",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        wrong_f2, sizeof(wrong_f2), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("LOADIWKEY rightmost F2",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        rightmost_f2, sizeof(rightmost_f2), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("ENCODEKEY LOCK",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        lock, sizeof(lock),
#if USE_EXTRA_OPCODES
        &flags,
#else
        flags_ptr,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("ENCODEKEY REX2",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2),
#if USE_EXTRA_OPCODES
        &flags,
#else
        flags_ptr,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("ENCODEKEY complete memory payload",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        memory_complete, sizeof(memory_complete),
#if USE_EXTRA_OPCODES
        &flags,
#else
        flags_ptr,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("ENCODEKEY truncated memory payload",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        memory_truncated, sizeof(memory_truncated),
#if USE_EXTRA_OPCODES
        &flags,
#else
        flags_ptr,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("ENCODEKEY truncated SIB",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        sib_truncated, sizeof(sib_truncated),
#if USE_EXTRA_OPCODES
        &flags,
#else
        flags_ptr,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("ENCODEKEY truncated ModRM",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        modrm_truncated, sizeof(modrm_truncated),
#if USE_EXTRA_OPCODES
        &flags,
#else
        flags_ptr,
#endif
        CDISASM_STATUS_TRUNCATED);
}

static void test_key_management_cpu_runtime_matrix(void)
{
    static const cdisasm_x86_cpu_id supported[] = {
        CDISASM_CPU_X86, CDISASM_CPU_TIGER_LAKE,
        CDISASM_CPU_ALDER_LAKE, CDISASM_CPU_AVX10,
        CDISASM_CPU_APX, CDISASM_CPU_ARROW_LAKE
    };
    static const cdisasm_x86_cpu_id rejected[] = {
        CDISASM_CPU_ICE_LAKE, CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_CPU_GRANITE_RAPIDS, CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const uint8_t encodekey128[] = {
        0xf3, 0x0f, 0x38, 0xfa, 0xc1};
    static const uint8_t encodekey256[] = {
        0xf3, 0x0f, 0x38, 0xfb, 0xc1};
    static const uint8_t loadiwkey[] = {
        0xf3, 0x0f, 0x38, 0xdc, 0xc1};
    static const uint8_t *codes[] = {
        encodekey128, encodekey256, loadiwkey
    };
    size_t cpu_index;
    size_t code_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_KEYLOCKER);
#endif

    for (cpu_index = 0;
         cpu_index < sizeof(supported) / sizeof(supported[0]);
         ++cpu_index) {
        for (code_index = 0; code_index < 3u; ++code_index) {
#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                supported[cpu_index], CDISASM_MODE_64,
                codes[code_index], 5u, &flags, &decoded_size);

            EXPECT(decoded_size == 5u);
            EXPECT(instruction.name_id
                == key_management_cases[code_index].name_id);
#else
            expect_error("Key management supported CPU OFF",
                supported[cpu_index], CDISASM_MODE_64,
                codes[code_index], 5u, NULL,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
    for (cpu_index = 0;
         cpu_index < sizeof(rejected) / sizeof(rejected[0]);
         ++cpu_index) {
        for (code_index = 0; code_index < 3u; ++code_index) {
            expect_error("Key management rejected CPU",
                rejected[cpu_index], CDISASM_MODE_64,
                codes[code_index], 5u,
#if USE_EXTRA_OPCODES
                &flags,
#else
                NULL,
#endif
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
}

static void test_cpu_flag_masks(void)
{
    static const cdisasm_x86_cpu_id supported[] = {
        CDISASM_CPU_X86, CDISASM_CPU_TIGER_LAKE,
        CDISASM_CPU_ALDER_LAKE, CDISASM_CPU_AVX10,
        CDISASM_CPU_APX, CDISASM_CPU_ARROW_LAKE
    };
    static const cdisasm_x86_cpu_id rejected[] = {
        CDISASM_CPU_ICE_LAKE, CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_CPU_GRANITE_RAPIDS, CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t cpu_index;
    size_t mode_index;

    for (cpu_index = 0;
         cpu_index < sizeof(supported) / sizeof(supported[0]);
         ++cpu_index) {
        for (mode_index = 0; mode_index < 3u; ++mode_index) {
            cdisasm_x86_decode_flags flags;

            EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                supported[cpu_index], modes[mode_index], &flags)
                == CDISASM_STATUS_OK);
            EXPECT(cdisasm_decode_flags_test_bit(
                &flags, CDISASM_X86_DECODE_BIT_KEYLOCKER)
                == USE_EXTRA_OPCODES);
            EXPECT(cdisasm_decode_flags_test_bit(
                &flags, CDISASM_X86_DECODE_BIT_KEYLOCKER_WIDE)
                == USE_EXTRA_OPCODES);
        }
    }
    for (cpu_index = 0;
         cpu_index < sizeof(rejected) / sizeof(rejected[0]);
         ++cpu_index) {
        cdisasm_x86_decode_flags flags;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            rejected[cpu_index], CDISASM_MODE_64, &flags)
            == CDISASM_STATUS_OK);
        EXPECT(!cdisasm_decode_flags_test_bit(
            &flags, CDISASM_X86_DECODE_BIT_KEYLOCKER));
        EXPECT(!cdisasm_decode_flags_test_bit(
            &flags, CDISASM_X86_DECODE_BIT_KEYLOCKER_WIDE));
    }
}

int main(void)
{
    test_exact_examples();
    test_key_management_examples();
    test_exhaustive_narrow_space();
    test_exhaustive_wide_space();
    test_exhaustive_encodekey_space();
    test_exhaustive_loadiwkey_space();
    test_prefix_address_and_collisions();
    test_key_management_prefixes();
    test_gates_and_boundaries();
    test_key_management_gates_and_boundaries();
    test_key_management_cpu_runtime_matrix();
    test_cpu_flag_masks();

    if (failures != 0) {
        fprintf(stderr, "%d Key Locker test(s) failed\n", failures);
        return 1;
    }
    puts("x86 Key Locker tests passed "
         "(2304 AES narrow tuples; 288/768 AES wide tuples; "
         "384/1536 ENCODEKEY tuples; 192 LOADIWKEY tuples allocated)");
    return 0;
}
