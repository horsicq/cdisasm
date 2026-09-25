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

_Static_assert(CDISASM_X86_REG_BSR0 == UINT16_C(308),
    "BSR0 register ID changed");
_Static_assert(CDISASM_X86_GROUP_ACE_1 == UINT16_C(116),
    "ACE_1 group ID changed");
_Static_assert(CDISASM_X86_GROUP_APX_F_USER_MSR == UINT16_C(149),
    "APX_F_USER_MSR group ID changed");
_Static_assert(CDISASM_X86_GROUP_USER_MSR == UINT16_C(315),
    "USER_MSR group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_APX_F_USER_MSR == UINT32_C(97),
    "APX_F_USER_MSR decode bit changed");
_Static_assert(CDISASM_X86_DECODE_BIT_USER_MSR == UINT32_C(261),
    "USER_MSR decode bit changed");
_Static_assert(CDISASM_X86_GROUP_APX_F_ENQCMD == UINT16_C(132),
    "APX_F_ENQCMD group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_APX_F_ENQCMD == UINT32_C(80),
    "APX_F_ENQCMD decode bit changed");

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
    cdisasm_x86_cpu_id cpu,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu, mode, code, size, UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static void expect_error(
    const uint8_t *code,
    size_t size,
    cdisasm_x86_mode mode,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_X86, mode, code, size, flags, &decoded_size);

    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags one_bit(cdisasm_x86_decode_bit_id bit)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit));
    return flags;
}

static void expect_text(
    const cdisasm_instruction *instruction,
    const char *expected)
{
#if USE_DISASM_FORMAT
    char text[160];

    if (cdisasm_x86_format(instruction, 0, text, sizeof(text))
            != strlen(expected)
        || strcmp(text, expected) != 0) {
        fprintf(stderr, "formatted as \"%s\", expected \"%s\"\n",
            text, expected);
    }
    EXPECT(cdisasm_x86_format(
        instruction, 0, text, sizeof(text)) == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
#else
    (void)instruction;
    (void)expected;
#endif
}

static void expect_register(
    const cdisasm_instruction *instruction,
    size_t index,
    cdisasm_x86_reg_id reg,
    uint8_t size,
    cdisasm_operand_access access)
{
    EXPECT(index < instruction->operand_count);
    EXPECT(instruction->opcode[index].type == CDISASM_OPERAND_REGISTER);
    if (instruction->opcode[index].reg != reg) {
        fprintf(stderr, "register mismatch at %zu: got %u expected %u\n",
            index, (unsigned int)instruction->opcode[index].reg,
            (unsigned int)reg);
    }
    EXPECT(instruction->opcode[index].reg == reg);
    EXPECT(instruction->opcode[index].size == size);
    EXPECT(instruction->opcode[index].access == access);
}
#endif

static void test_bsr_examples(void)
{
    static const struct bsr_case {
        uint8_t code[8];
        size_t size;
        cdisasm_x86_name_id name;
        cdisasm_x86_form_id form;
        uint8_t operands;
        const char *text;
    } cases[] = {
        {{0xc4, 0xe2, 0xfb, 0x49, 0xc0}, 5,
         CDISASM_X86_NAME_BSRINIT, UINT16_C(378), 1,
         "bsrinit bsr0"},
        {{0x62, 0xf6, 0xf4, 0x48, 0x95, 0xc2}, 6,
         CDISASM_X86_NAME_BSRMOVF, UINT16_C(380), 3,
         "bsrmovf bsr0, zmm1, zmm2"},
        {{0x62, 0xf6, 0xf4, 0x48, 0x95, 0x00}, 6,
         CDISASM_X86_NAME_BSRMOVF, UINT16_C(379), 3,
         "bsrmovf bsr0, zmm1, zmmword ptr [rax]"},
        {{0x62, 0xf6, 0xff, 0x48, 0x95, 0xc1}, 6,
         CDISASM_X86_NAME_BSRMOVH, UINT16_C(382), 2,
         "bsrmovh bsr0, zmm1"},
        {{0x62, 0xf6, 0x7f, 0x48, 0x95, 0xc1}, 6,
         CDISASM_X86_NAME_BSRMOVH, UINT16_C(384), 2,
         "bsrmovh zmm1, bsr0"},
        {{0x62, 0xf6, 0x7f, 0x48, 0x95, 0x00}, 6,
         CDISASM_X86_NAME_BSRMOVH, UINT16_C(383), 2,
         "bsrmovh zmmword ptr [rax], bsr0"},
        {{0x62, 0xf6, 0xfe, 0x48, 0x95, 0xc2}, 6,
         CDISASM_X86_NAME_BSRMOVL, UINT16_C(386), 2,
         "bsrmovl bsr0, zmm2"},
        {{0x62, 0xf6, 0x7e, 0x48, 0x95, 0xc2}, 6,
         CDISASM_X86_NAME_BSRMOVL, UINT16_C(388), 2,
         "bsrmovl zmm2, bsr0"},
        {{0x62, 0xf6, 0xfe, 0x48, 0x95, 0x00}, 6,
         CDISASM_X86_NAME_BSRMOVL, UINT16_C(385), 2,
         "bsrmovl bsr0, zmmword ptr [rax]"},
        {{0x62, 0xf6, 0xff, 0x48, 0x95, 0x40, 0x01}, 7,
         CDISASM_X86_NAME_BSRMOVH, UINT16_C(381), 2,
         "bsrmovh bsr0, zmmword ptr [rax + 0x1]"},
        {{0x62, 0xf6, 0x7e, 0x48, 0x95, 0x40, 0xff}, 7,
         CDISASM_X86_NAME_BSRMOVL, UINT16_C(387), 2,
         "bsrmovl zmmword ptr [rax - 0x1], bsr0"}
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(
            CDISASM_X86_DECODE_BIT_ACE_1);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[i].code, cases[i].size, &flags, &decoded_size);

        EXPECT(decoded_size == cases[i].size);
        EXPECT(instruction.name_id == cases[i].name);
        EXPECT(instruction.form_id == cases[i].form);
        EXPECT(instruction.operand_count == cases[i].operands);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_ACE_1));
        expect_text(&instruction, cases[i].text);
#else
        expect_error(cases[i].code, cases[i].size, CDISASM_MODE_64,
            NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

#if USE_EXTRA_OPCODES
    {
        cdisasm_x86_decode_flags flags = one_bit(
            CDISASM_X86_DECODE_BIT_ACE_1);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[1].code, cases[1].size, &flags, &decoded_size);

        expect_register(&instruction, 0, CDISASM_X86_REG_BSR0, 128u,
            CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT((instruction.opcode[0].flags
            & CDISASM_OPERAND_FLAG_IMPLICIT) != 0u);
        expect_register(&instruction, 1, CDISASM_X86_REG_ZMM1, 64u,
            CDISASM_OPERAND_ACCESS_READ);
        expect_register(&instruction, 2, CDISASM_X86_REG_ZMM2, 64u,
            CDISASM_OPERAND_ACCESS_READ);
    }
#endif
}

static void test_bsr_exhaustive_register_space(void)
{
    size_t decoded = 0;
    unsigned int prefix;
    unsigned int w;
    unsigned int source;
    unsigned int rm;

    for (prefix = 0; prefix < 4; ++prefix) {
        for (w = 0; w < 2; ++w) {
            for (source = 0; source < 32; ++source) {
                for (rm = 0; rm < 32; ++rm) {
                    uint8_t code[] = {
                        0x62,
                        (uint8_t)(0x96u
                            | (rm < 16 ? 0x40u : 0u)
                            | ((rm & 8u) == 0 ? 0x20u : 0u)),
                        (uint8_t)((w != 0 ? 0x80u : 0u)
                            | ((~source & 15u) << 3) | 0x04u | prefix),
                        (uint8_t)(0x40u | (source < 16 ? 0x08u : 0u)),
                        0x95,
                        (uint8_t)(0xc0u | (rm & 7u))
                    };
                    const int valid = prefix != 1
                        && (prefix != 0 || w != 0)
                        && (prefix == 0 || source == 0);
#if USE_EXTRA_OPCODES
                    cdisasm_x86_decode_flags flags = one_bit(
                        CDISASM_X86_DECODE_BIT_ACE_1);
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, sizeof(code), &flags, &decoded_size);

                    if (valid) {
                        const uint16_t expected_form = prefix == 0
                            ? UINT16_C(380)
                            : prefix == 3
                                ? (w != 0 ? UINT16_C(382)
                                          : UINT16_C(384))
                                : (w != 0 ? UINT16_C(386)
                                          : UINT16_C(388));

                        EXPECT(decoded_size == sizeof(code));
                        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                        EXPECT(instruction.form_id == expected_form);
                        ++decoded;
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(instruction.last_error_id
                            == CDISASM_STATUS_INVALID_INSTRUCTION);
                    }
#else
                    expect_error(code, sizeof(code), CDISASM_MODE_64, NULL,
                        valid ? CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
                              : CDISASM_STATUS_INVALID_INSTRUCTION);
                    if (valid) {
                        ++decoded;
                    }
#endif
                }
            }
        }
    }
    EXPECT(decoded == 1152u);
}

static void test_user_msr_examples(void)
{
    static const struct msr_case {
        uint8_t code[10];
        size_t size;
        cdisasm_x86_name_id name;
        cdisasm_x86_form_id form;
        cdisasm_x86_decode_bit_id bit;
        cdisasm_x86_group_id group;
        const char *text;
    } cases[] = {
        {{0xf2, 0x0f, 0x38, 0xf8, 0xd8}, 5,
         CDISASM_X86_NAME_URDMSR, UINT16_C(3353),
         CDISASM_X86_DECODE_BIT_USER_MSR, CDISASM_X86_GROUP_USER_MSR,
         "urdmsr rax, rbx"},
        {{0x62, 0xf4, 0x7f, 0x08, 0xf8, 0xd8}, 6,
         CDISASM_X86_NAME_URDMSR, UINT16_C(3354),
         CDISASM_X86_DECODE_BIT_APX_F_USER_MSR,
         CDISASM_X86_GROUP_APX_F_USER_MSR, "urdmsr rax, rbx"},
        {{0xc4, 0xe7, 0x7b, 0xf8, 0xc0, 0x78, 0x56, 0x34, 0x12}, 9,
         CDISASM_X86_NAME_URDMSR, UINT16_C(3355),
         CDISASM_X86_DECODE_BIT_USER_MSR, CDISASM_X86_GROUP_USER_MSR,
         "urdmsr rax, 0x12345678"},
        {{0x62, 0xf7, 0x7f, 0x08, 0xf8, 0xc0,
          0x78, 0x56, 0x34, 0x12}, 10,
         CDISASM_X86_NAME_URDMSR, UINT16_C(3356),
         CDISASM_X86_DECODE_BIT_APX_F_USER_MSR,
         CDISASM_X86_GROUP_APX_F_USER_MSR,
         "urdmsr rax, 0x12345678"},
        {{0xf3, 0x0f, 0x38, 0xf8, 0xd8}, 5,
         CDISASM_X86_NAME_UWRMSR, UINT16_C(3357),
         CDISASM_X86_DECODE_BIT_USER_MSR, CDISASM_X86_GROUP_USER_MSR,
         "uwrmsr rbx, rax"},
        {{0x62, 0xf4, 0x7e, 0x08, 0xf8, 0xd8}, 6,
         CDISASM_X86_NAME_UWRMSR, UINT16_C(3358),
         CDISASM_X86_DECODE_BIT_APX_F_USER_MSR,
         CDISASM_X86_GROUP_APX_F_USER_MSR, "uwrmsr rbx, rax"},
        {{0xc4, 0xe7, 0x7a, 0xf8, 0xc0, 0x78, 0x56, 0x34, 0x12}, 9,
         CDISASM_X86_NAME_UWRMSR, UINT16_C(3359),
         CDISASM_X86_DECODE_BIT_USER_MSR, CDISASM_X86_GROUP_USER_MSR,
         "uwrmsr 0x12345678, rax"},
        {{0x62, 0xf7, 0x7e, 0x08, 0xf8, 0xc0,
          0x78, 0x56, 0x34, 0x12}, 10,
         CDISASM_X86_NAME_UWRMSR, UINT16_C(3360),
         CDISASM_X86_DECODE_BIT_APX_F_USER_MSR,
         CDISASM_X86_GROUP_APX_F_USER_MSR,
         "uwrmsr 0x12345678, rax"}
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(cases[i].bit);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[i].code, cases[i].size, &flags, &decoded_size);

        if (decoded_size != cases[i].size) {
            fprintf(stderr, "USER_MSR case %zu: size/status %u/%u\n",
                i, (unsigned int)decoded_size,
                (unsigned int)instruction.last_error_id);
        }
        EXPECT(decoded_size == cases[i].size);
        EXPECT(instruction.name_id == cases[i].name);
        EXPECT(instruction.form_id == cases[i].form);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, cases[i].group));
        expect_text(&instruction, cases[i].text);
#else
        expect_error(cases[i].code, cases[i].size, CDISASM_MODE_64,
            NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_colliding_apx_memory_forms(void)
{
    static const uint8_t enqcmd[] = {
        0x62, 0xf4, 0x7f, 0x08, 0xf8, 0x18
    };
    static const uint8_t enqcmd_u0_sib[] = {
        0x62, 0xa4, 0x7b, 0x08, 0xf8, 0x04, 0x38
    };
    static const uint8_t enqcmd_u0_truncated[] = {
        0x62, 0xf4, 0x7b, 0x08, 0xf8
    };
    static const uint8_t enqcmds[] = {
        0x62, 0xf4, 0x7e, 0x08, 0xf8, 0x18
    };
    static const uint8_t movdir64b_u0_sib[] = {
        0x62, 0xa4, 0x79, 0x08, 0xf8, 0x04, 0x38
    };
    static const uint8_t movdir64b_u0_truncated[] = {
        0x62, 0xa4, 0x79, 0x08, 0xf8
    };
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags enq = one_bit(
        CDISASM_X86_DECODE_BIT_APX_F_ENQCMD);
    cdisasm_x86_decode_flags apx_system =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    apx_system.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        CDISASM_X86_DECODE_FLAG_APX | CDISASM_X86_DECODE_FLAG_SYSTEM;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        enqcmd, sizeof(enqcmd), &enq, &decoded_size);
    EXPECT(decoded_size == sizeof(enqcmd));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_ENQCMD);
    EXPECT(instruction.form_id == UINT16_C(1145));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_ENQCMD));
    expect_text(&instruction, "enqcmd rbx, zmmword ptr [rax]");

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        enqcmds, sizeof(enqcmds), &enq, &decoded_size);
    EXPECT(decoded_size == sizeof(enqcmds));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_ENQCMDS);
    EXPECT(instruction.form_id == UINT16_C(1143));
    EXPECT((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
    expect_text(&instruction, "enqcmds rbx, zmmword ptr [rax]");

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        enqcmd_u0_sib, sizeof(enqcmd_u0_sib), &enq, &decoded_size);
    EXPECT(decoded_size == sizeof(enqcmd_u0_sib));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_ENQCMD);
    expect_register(&instruction, 0, CDISASM_X86_REG_R16, 8u,
        CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R31);
    EXPECT(instruction.opcode[1].size == 64u);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    expect_text(
        &instruction, "enqcmd r16, zmmword ptr [rax + r31]");

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        movdir64b_u0_sib, sizeof(movdir64b_u0_sib), &apx_system,
        &decoded_size);
    EXPECT(decoded_size == sizeof(movdir64b_u0_sib));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVDIR64B);
    expect_register(&instruction, 0, CDISASM_X86_REG_R16, 8u,
        CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R31);
    expect_text(&instruction,
        "movdir64b r16, zmmword ptr [rax + r31], zmmword ptr [r16]");

    expect_error(enqcmd, sizeof(enqcmd), CDISASM_MODE_64, &apx_system,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    expect_error(enqcmd, sizeof(enqcmd), CDISASM_MODE_64, NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(enqcmd_u0_sib, sizeof(enqcmd_u0_sib), CDISASM_MODE_64, NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(enqcmds, sizeof(enqcmds), CDISASM_MODE_64, NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(movdir64b_u0_sib, sizeof(movdir64b_u0_sib), CDISASM_MODE_64,
        NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    expect_error(movdir64b_u0_truncated, sizeof(movdir64b_u0_truncated),
        CDISASM_MODE_64, NULL, CDISASM_STATUS_TRUNCATED);
    expect_error(enqcmd_u0_truncated, sizeof(enqcmd_u0_truncated),
        CDISASM_MODE_64, NULL, CDISASM_STATUS_TRUNCATED);
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id gpr64_id(unsigned int index)
{
    return index < 16u
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_RAX + index)
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_R16 + index - 16u);
}

static void test_user_msr_exhaustive_register_space(void)
{
    cdisasm_x86_decode_flags user = one_bit(
        CDISASM_X86_DECODE_BIT_USER_MSR);
    cdisasm_x86_decode_flags apx = one_bit(
        CDISASM_X86_DECODE_BIT_APX_F_USER_MSR);
    size_t decoded = 0;
    unsigned int operation;
    unsigned int reg;
    unsigned int rm;

    for (operation = 0; operation < 2; ++operation) {
        for (reg = 0; reg < 8; ++reg) {
            for (rm = 0; rm < 8; ++rm) {
                uint8_t code[] = {
                    (uint8_t)(operation == 0 ? 0xf2 : 0xf3),
                    0x0f, 0x38, 0xf8,
                    (uint8_t)(0xc0u | (reg << 3) | rm)
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), &user, &decoded_size);

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.form_id
                    == (operation == 0 ? UINT16_C(3353)
                                       : UINT16_C(3357)));
                expect_register(&instruction, 0,
                    gpr64_id(operation == 0 ? rm : reg), 8u,
                    operation == 0 ? CDISASM_OPERAND_ACCESS_WRITE
                                   : CDISASM_OPERAND_ACCESS_READ);
                expect_register(&instruction, 1,
                    gpr64_id(operation == 0 ? reg : rm), 8u,
                    CDISASM_OPERAND_ACCESS_READ);
                ++decoded;
            }
        }
    }

    for (operation = 0; operation < 2; ++operation) {
        unsigned int ignored_x;

        for (ignored_x = 0; ignored_x < 2; ++ignored_x) {
            for (rm = 0; rm < 16; ++rm) {
                uint8_t code[] = {
                    0xc4,
                    (uint8_t)(0x87u
                        | (ignored_x != 0 ? 0x40u : 0u)
                        | (rm < 8 ? 0x20u : 0u)),
                    (uint8_t)(operation == 0 ? 0x7b : 0x7a),
                    0xf8, (uint8_t)(0xc0u | (rm & 7u)),
                    0x78, 0x56, 0x34, 0x12
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), &user, &decoded_size);

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.form_id
                    == (operation == 0 ? UINT16_C(3355)
                                       : UINT16_C(3359)));
                ++decoded;
            }
        }
    }

    for (operation = 0; operation < 2; ++operation) {
        for (reg = 0; reg < 32; ++reg) {
            for (rm = 0; rm < 32; ++rm) {
                uint8_t p0 = UINT8_C(0x44);
                uint8_t code[6];
                uint32_t decoded_size;
                cdisasm_instruction instruction;

                p0 |= (reg & 8u) == 0 ? UINT8_C(0x80) : 0u;
                p0 |= reg < 16u ? UINT8_C(0x10) : 0u;
                p0 |= (rm & 8u) == 0 ? UINT8_C(0x20) : 0u;
                p0 |= rm >= 16u ? UINT8_C(0x08) : 0u;
                code[0] = 0x62;
                code[1] = p0;
                code[2] = (uint8_t)(operation == 0 ? 0x7f : 0x7e);
                code[3] = 0x08;
                code[4] = 0xf8;
                code[5] = (uint8_t)(0xc0u
                    | ((reg & 7u) << 3) | (rm & 7u));
                instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), &apx, &decoded_size);

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.form_id
                    == (operation == 0 ? UINT16_C(3354)
                                       : UINT16_C(3358)));
                expect_register(&instruction, 0,
                    gpr64_id(operation == 0 ? rm : reg), 8u,
                    operation == 0 ? CDISASM_OPERAND_ACCESS_WRITE
                                   : CDISASM_OPERAND_ACCESS_READ);
                expect_register(&instruction, 1,
                    gpr64_id(operation == 0 ? reg : rm), 8u,
                    CDISASM_OPERAND_ACCESS_READ);
                ++decoded;
            }
        }
    }

    for (operation = 0; operation < 2; ++operation) {
        for (rm = 0; rm < 32; ++rm) {
            uint8_t p0 = UINT8_C(0xd7);
            uint8_t code[10];
            uint32_t decoded_size;
            cdisasm_instruction instruction;

            if ((rm & 8u) != 0) {
                p0 &= (uint8_t)~UINT8_C(0x20);
            } else {
                p0 |= UINT8_C(0x20);
            }
            p0 |= rm >= 16u ? UINT8_C(0x08) : 0u;
            code[0] = 0x62;
            code[1] = p0;
            code[2] = (uint8_t)(operation == 0 ? 0x7f : 0x7e);
            code[3] = 0x08;
            code[4] = 0xf8;
            code[5] = (uint8_t)(0xc0u | (rm & 7u));
            code[6] = 0x78;
            code[7] = 0x56;
            code[8] = 0x34;
            code[9] = 0x12;
            instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), &apx, &decoded_size);

            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.form_id
                == (operation == 0 ? UINT16_C(3356)
                                   : UINT16_C(3360)));
            ++decoded;
        }
    }
    EXPECT(decoded == 2304u);
}
#endif

static void test_gates_and_boundaries(void)
{
    static const uint8_t tilezero[] = {0xc4, 0xe2, 0x7b, 0x49, 0xd0};
    static const uint8_t bsr[] = {0x62, 0xf6, 0xf4, 0x48, 0x95, 0xc2};
    static const uint8_t bsr_bad_pp[] = {
        0x62, 0xf6, 0xf5, 0x48, 0x95, 0xc2
    };
    static const uint8_t bsr_truncated[] = {
        0x62, 0xf6, 0xf4, 0x48, 0x95
    };
    static const uint8_t msr[] = {0xf2, 0x0f, 0x38, 0xf8, 0xd8};
    static const uint8_t msr_memory[] = {0xf2, 0x0f, 0x38, 0xf8, 0x18};
    static const uint8_t vex_bad_reg[] = {
        0xc4, 0xe7, 0x7b, 0xf8, 0xc8, 0, 0, 0, 0
    };
    static const uint8_t vex_truncated[] = {
        0xc4, 0xe7, 0x7b, 0xf8, 0xc0, 0, 0, 0
    };
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags ace = one_bit(CDISASM_X86_DECODE_BIT_ACE_1);
    cdisasm_x86_decode_flags amx = one_bit(
        CDISASM_X86_DECODE_BIT_AMX_TILE);
    cdisasm_x86_decode_flags user = one_bit(
        CDISASM_X86_DECODE_BIT_USER_MSR);
    cdisasm_x86_decode_flags apx_user = one_bit(
        CDISASM_X86_DECODE_BIT_APX_F_USER_MSR);
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    const cdisasm_x86_decode_flags *ace_ptr = &ace;
    const cdisasm_x86_decode_flags *user_ptr = &user;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        tilezero, sizeof(tilezero), &amx, &decoded_size);
    EXPECT(decoded_size == sizeof(tilezero));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_TILEZERO);

    expect_error(bsr, sizeof(bsr), CDISASM_MODE_64, NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(msr, sizeof(msr), CDISASM_MODE_64, NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(msr, sizeof(msr), CDISASM_MODE_64, &apx_user,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        bsr, sizeof(bsr), &ace, &decoded_size);
    EXPECT(decoded_size == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        msr, sizeof(msr), &user, &decoded_size);
    EXPECT(decoded_size == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    const cdisasm_x86_decode_flags *ace_ptr = NULL;
    const cdisasm_x86_decode_flags *user_ptr = NULL;
    expect_error(tilezero, sizeof(tilezero), CDISASM_MODE_64, NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    expect_error(bsr, sizeof(bsr), CDISASM_MODE_32, ace_ptr,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(bsr_bad_pp, sizeof(bsr_bad_pp), CDISASM_MODE_64, ace_ptr,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(bsr_truncated, sizeof(bsr_truncated), CDISASM_MODE_64, ace_ptr,
        CDISASM_STATUS_TRUNCATED);
    expect_error(msr, sizeof(msr), CDISASM_MODE_32, user_ptr,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(msr_memory, sizeof(msr_memory), CDISASM_MODE_64, user_ptr,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(vex_bad_reg, sizeof(vex_bad_reg), CDISASM_MODE_64, user_ptr,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(vex_truncated, sizeof(vex_truncated), CDISASM_MODE_64, user_ptr,
        CDISASM_STATUS_TRUNCATED);
}

int main(void)
{
    test_bsr_examples();
    test_bsr_exhaustive_register_space();
    test_user_msr_examples();
    test_colliding_apx_memory_forms();
#if USE_EXTRA_OPCODES
    test_user_msr_exhaustive_register_space();
#endif
    test_gates_and_boundaries();

    if (failures != 0) {
        fprintf(stderr, "%d x86 BSR/USER_MSR test(s) failed\n", failures);
        return 1;
    }
    puts("x86 BSR/USER_MSR tests passed (1152 BSR and 2304 USER_MSR tuples)");
    return 0;
}
