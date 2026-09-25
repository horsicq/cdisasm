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
            fprintf(stderr, "%s:%d: expectation failed: %s\n",           \
                __FILE__, __LINE__, #expression);                            \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_RDMSRLIST == UINT16_C(1384),
    "RDMSRLIST name ID changed");
_Static_assert(CDISASM_X86_NAME_WRMSRLIST == UINT16_C(2022),
    "WRMSRLIST name ID changed");
_Static_assert(CDISASM_X86_NAME_WRMSRNS == UINT16_C(2023),
    "WRMSRNS name ID changed");
_Static_assert(CDISASM_X86_GROUP_APX_F_MSR_IMM == UINT16_C(144),
    "APX_F_MSR_IMM group ID changed");
_Static_assert(CDISASM_X86_GROUP_MSRLIST == UINT16_C(286),
    "MSRLIST group ID changed");
_Static_assert(CDISASM_X86_GROUP_MSR_IMM == UINT16_C(287),
    "MSR_IMM group ID changed");
_Static_assert(CDISASM_X86_GROUP_WRMSRNS == UINT16_C(322),
    "WRMSRNS group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_APX_F_MSR_IMM == UINT32_C(92),
    "APX_F_MSR_IMM decode bit changed");
_Static_assert(CDISASM_X86_DECODE_BIT_MSRLIST == UINT32_C(233),
    "MSRLIST decode bit changed");
_Static_assert(CDISASM_X86_DECODE_BIT_MSR_IMM == UINT32_C(234),
    "MSR_IMM decode bit changed");
_Static_assert(CDISASM_X86_DECODE_BIT_WRMSRNS == UINT32_C(268),
    "WRMSRNS decode bit changed");

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

static void expect_error_cpu(
    cdisasm_x86_cpu_id cpu,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu, mode, code, size, flags, &decoded_size);

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

static cdisasm_x86_decode_flags exact_rex2_flags(
    cdisasm_x86_decode_bit_id bit)
{
    cdisasm_x86_decode_flags flags = one_bit(bit);

    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_APX));
    return flags;
}

static cdisasm_x86_reg_id gpr64(unsigned int index)
{
    return index < 16u
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_RAX + index)
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_R16 + index - 16u);
}

static void expect_text(
    const cdisasm_instruction *instruction,
    const char *expected)
{
#if USE_DISASM_FORMAT
    char text[160];
    size_t length = cdisasm_x86_format(
        instruction, 0, text, sizeof(text));

    if (length != strlen(expected) || strcmp(text, expected) != 0) {
        fprintf(stderr, "formatted as \"%s\", expected \"%s\"\n",
            text, expected);
    }
    EXPECT(length == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
#else
    (void)instruction;
    (void)expected;
#endif
}

static void expect_register(
    const cdisasm_instruction *instruction,
    unsigned int index,
    cdisasm_x86_reg_id reg,
    cdisasm_operand_access access)
{
    EXPECT(index < instruction->operand_count);
    EXPECT(instruction->opcode[index].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[index].reg == reg);
    EXPECT(instruction->opcode[index].size == 8u);
    EXPECT(instruction->opcode[index].access == access);
    EXPECT(instruction->opcode[index].flags == CDISASM_OPERAND_FLAG_NONE);
}

static void expect_immediate(
    const cdisasm_instruction *instruction,
    unsigned int index,
    uint64_t value)
{
    EXPECT(index < instruction->operand_count);
    EXPECT(instruction->opcode[index].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[index].size == 4u);
    EXPECT(instruction->opcode[index].imm == value);
    EXPECT(instruction->opcode[index].access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_common(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t size,
    cdisasm_x86_name_id name,
    cdisasm_x86_form_id form,
    cdisasm_x86_group_id group)
{
    EXPECT(decoded_size == size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == name);
    EXPECT(instruction->form_id == form);
    EXPECT(cdisasm_instruction_has_x86_group(instruction, group));
    EXPECT((instruction->opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_EFFECTIVE_MASK | CDISASM_PREFIX_HLE_MASK)) == 0u);
}
#endif

static void test_examples(void)
{
    static const struct msr_case {
        uint8_t code[10];
        uint8_t size;
        cdisasm_x86_name_id name;
        cdisasm_x86_form_id form;
        cdisasm_x86_decode_bit_id bit;
        cdisasm_x86_group_id group;
        const char *text;
    } cases[] = {
        {{0xf2, 0x0f, 0x01, 0xc6}, 4,
         CDISASM_X86_NAME_RDMSRLIST, UINT16_C(2571),
         CDISASM_X86_DECODE_BIT_MSRLIST, CDISASM_X86_GROUP_MSRLIST,
         "rdmsrlist"},
        {{0xf3, 0x0f, 0x01, 0xc6}, 4,
         CDISASM_X86_NAME_WRMSRLIST, UINT16_C(8892),
         CDISASM_X86_DECODE_BIT_MSRLIST, CDISASM_X86_GROUP_MSRLIST,
         "wrmsrlist"},
        {{0x0f, 0x01, 0xc6}, 3,
         CDISASM_X86_NAME_WRMSRNS, UINT16_C(8893),
         CDISASM_X86_DECODE_BIT_WRMSRNS, CDISASM_X86_GROUP_WRMSRNS,
         "wrmsrns"},
        {{0xc4, 0xe7, 0x7b, 0xf6, 0xc0, 0x78, 0x56, 0x34, 0x12}, 9,
         CDISASM_X86_NAME_RDMSR, UINT16_C(2572),
         CDISASM_X86_DECODE_BIT_MSR_IMM, CDISASM_X86_GROUP_MSR_IMM,
         "rdmsr rax, 0x12345678"},
        {{0xc4, 0xe7, 0x7a, 0xf6, 0xc0, 0x78, 0x56, 0x34, 0x12}, 9,
         CDISASM_X86_NAME_WRMSRNS, UINT16_C(8894),
         CDISASM_X86_DECODE_BIT_MSR_IMM, CDISASM_X86_GROUP_MSR_IMM,
         "wrmsrns 0x12345678, rax"},
        {{0x62, 0xf7, 0x7f, 0x08, 0xf6, 0xc0,
          0x78, 0x56, 0x34, 0x12}, 10,
         CDISASM_X86_NAME_RDMSR, UINT16_C(2573),
         CDISASM_X86_DECODE_BIT_APX_F_MSR_IMM,
         CDISASM_X86_GROUP_APX_F_MSR_IMM,
         "rdmsr rax, 0x12345678"},
        {{0x62, 0xdf, 0x7e, 0x08, 0xf6, 0xc7,
          0x78, 0x56, 0x34, 0x12}, 10,
         CDISASM_X86_NAME_WRMSRNS, UINT16_C(8895),
         CDISASM_X86_DECODE_BIT_APX_F_MSR_IMM,
         CDISASM_X86_GROUP_APX_F_MSR_IMM,
         "wrmsrns 0x12345678, r31"}
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(cases[index].bit);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, cases[index].code,
            cases[index].size, &flags, &decoded_size);

        check_common(&instruction, decoded_size, cases[index].size,
            cases[index].name, cases[index].form, cases[index].group);
        EXPECT(instruction.operand_count
            == (cases[index].form == UINT16_C(2571)
                || cases[index].form == UINT16_C(8892)
                || cases[index].form == UINT16_C(8893) ? 0u : 2u));
        expect_text(&instruction, cases[index].text);
#else
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

#if USE_EXTRA_OPCODES
    {
        cdisasm_x86_decode_flags flags = one_bit(
            CDISASM_X86_DECODE_BIT_MSR_IMM);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[3].code, cases[3].size, &flags, &decoded_size);

        expect_register(&instruction, 0, CDISASM_X86_REG_RAX,
            CDISASM_OPERAND_ACCESS_WRITE);
        expect_immediate(&instruction, 1, UINT64_C(0x12345678));
        EXPECT(instruction.encoding.prefix_size == 3u);
        EXPECT(instruction.encoding.opcode_offset == 3u);
        EXPECT(instruction.encoding.opcode_size == 1u);
        EXPECT(instruction.encoding.modrm_offset == 4u);
        EXPECT(instruction.encoding.modrm == UINT8_C(0xc0));
        EXPECT(instruction.encoding.immediate_count == 1u);
        EXPECT(instruction.encoding.immediate_offset[0] == 5u);
        EXPECT(instruction.encoding.immediate_size[0] == 4u);
    }
    {
        cdisasm_x86_decode_flags flags = one_bit(
            CDISASM_X86_DECODE_BIT_APX_F_MSR_IMM);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[6].code, cases[6].size, &flags, &decoded_size);

        expect_immediate(&instruction, 0, UINT64_C(0x12345678));
        expect_register(&instruction, 1, CDISASM_X86_REG_R31,
            CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.encoding.prefix_size == 4u);
        EXPECT(instruction.encoding.opcode_offset == 4u);
        EXPECT(instruction.encoding.modrm_offset == 5u);
        EXPECT(instruction.encoding.immediate_offset[0] == 6u);
        EXPECT(instruction.encoding.immediate_size[0] == 4u);
    }
#endif
}

static void test_legacy_space(void)
{
    unsigned int selector;
    unsigned int mode_index;
    unsigned int raw_modrm;
    size_t valid = 0;
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };

    for (selector = 0; selector < 3; ++selector) {
        for (mode_index = 0; mode_index < 3; ++mode_index) {
            for (raw_modrm = 0; raw_modrm < 256; ++raw_modrm) {
                uint8_t code[4] = {0, 0x0f, 0x01, (uint8_t)raw_modrm};
                const uint8_t *bytes = code;
                size_t size = sizeof(code);
#if USE_EXTRA_OPCODES
                cdisasm_x86_decode_flags flags = one_bit(
                    selector == 0 ? CDISASM_X86_DECODE_BIT_WRMSRNS
                                  : CDISASM_X86_DECODE_BIT_MSRLIST);
                uint32_t decoded_size;
                cdisasm_instruction instruction;
#endif

                if (selector == 0) {
                    ++bytes;
                    --size;
                } else {
                    code[0] = (uint8_t)(selector == 1 ? 0xf2 : 0xf3);
                }
#if USE_EXTRA_OPCODES
                instruction = decode(CDISASM_CPU_X86, modes[mode_index],
                    bytes, size, &flags, &decoded_size);
                if (raw_modrm == UINT8_C(0xc6)
                    && (selector == 0 || modes[mode_index] == CDISASM_MODE_64)) {
                    EXPECT(decoded_size == size);
                    EXPECT(instruction.form_id == (selector == 0
                        ? UINT16_C(8893) : selector == 1
                            ? UINT16_C(2571) : UINT16_C(8892)));
                    ++valid;
                } else if (decoded_size != 0u) {
                    EXPECT(instruction.form_id != UINT16_C(2571));
                    EXPECT(instruction.form_id != UINT16_C(8892));
                    EXPECT(instruction.form_id != UINT16_C(8893));
                    EXPECT(instruction.name_id != CDISASM_X86_NAME_RDMSRLIST);
                    EXPECT(instruction.name_id != CDISASM_X86_NAME_WRMSRLIST);
                } else if (raw_modrm == UINT8_C(0xc6)) {
                    EXPECT(instruction.last_error_id
                        == CDISASM_STATUS_INVALID_INSTRUCTION);
                }
#else
                if (raw_modrm == UINT8_C(0xc6)) {
                    expect_error_cpu(CDISASM_CPU_X86, modes[mode_index],
                        bytes, size, NULL,
                        selector == 0 || modes[mode_index] == CDISASM_MODE_64
                            ? CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
                            : CDISASM_STATUS_INVALID_INSTRUCTION);
                    if (selector == 0
                        || modes[mode_index] == CDISASM_MODE_64) {
                        ++valid;
                    }
                }
#endif
            }
        }
    }
    EXPECT(valid == 5u);
}

static void test_rex2_payload_space(void)
{
    unsigned int selector;
    unsigned int payload;
    size_t valid = 0;

    for (selector = 0; selector < 3; ++selector) {
        for (payload = 0x80; payload <= 0xff; ++payload) {
            uint8_t code[6] = {
                0, 0xd5, (uint8_t)payload, 0x01, 0xc6, 0
            };
            const uint8_t *bytes = code;
            size_t size = 5;

            if (selector == 0) {
                ++bytes;
                --size;
            } else {
                code[0] = (uint8_t)(selector == 1 ? 0xf2 : 0xf3);
            }
#if USE_EXTRA_OPCODES
            {
                cdisasm_x86_decode_flags flags = exact_rex2_flags(
                    selector == 0 ? CDISASM_X86_DECODE_BIT_WRMSRNS
                                  : CDISASM_X86_DECODE_BIT_MSRLIST);
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    bytes, size, &flags, &decoded_size);

                EXPECT(decoded_size == size);
                EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0u);
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_APX_F));
                EXPECT(instruction.form_id == (selector == 0
                    ? UINT16_C(8893) : selector == 1
                        ? UINT16_C(2571) : UINT16_C(8892)));
            }
#else
            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                bytes, size, NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            ++valid;
        }
    }
    EXPECT(valid == 384u);
}

static void test_legacy_rex_and_rex2_collisions(void)
{
    unsigned int selector;
    unsigned int rex;
    unsigned int mode_index;
    static const cdisasm_x86_mode legacy_modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32
    };

    for (selector = 0; selector < 3; ++selector) {
        for (rex = 0x40; rex <= 0x4f; ++rex) {
            uint8_t code[] = {
                0, (uint8_t)rex, 0x0f, 0x01, 0xc6
            };
            const uint8_t *bytes = code;
            size_t size = sizeof(code);
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags flags = one_bit(
                selector == 0 ? CDISASM_X86_DECODE_BIT_WRMSRNS
                              : CDISASM_X86_DECODE_BIT_MSRLIST);
            uint32_t decoded_size;
            cdisasm_instruction instruction;
#endif

            if (selector == 0) {
                ++bytes;
                --size;
            } else {
                code[0] = (uint8_t)(selector == 1 ? 0xf2 : 0xf3);
            }
#if USE_EXTRA_OPCODES
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                bytes, size, &flags, &decoded_size);
            EXPECT(decoded_size == size);
            EXPECT(instruction.form_id == (selector == 0
                ? UINT16_C(8893) : selector == 1
                    ? UINT16_C(2571) : UINT16_C(8892)));
#else
            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                bytes, size, NULL,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            for (mode_index = 0; mode_index < 2; ++mode_index) {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, legacy_modes[mode_index],
                    bytes, size,
#if USE_EXTRA_OPCODES
                    &flags,
#else
                    NULL,
#endif
                    &decoded_size);

                EXPECT(decoded_size != 0u);
                EXPECT(instruction.name_id == CDISASM_X86_NAME_INC
                    || instruction.name_id == CDISASM_X86_NAME_DEC);
                EXPECT(instruction.form_id != UINT16_C(2571));
                EXPECT(instruction.form_id != UINT16_C(8892));
                EXPECT(instruction.form_id != UINT16_C(8893));
            }
        }
    }

#if USE_EXTRA_OPCODES
    for (selector = 0; selector < 3; ++selector) {
        unsigned int payload;

        for (payload = 0; payload < 0x80; ++payload) {
            uint8_t code[] = {
                0, 0xd5, (uint8_t)payload, 0x01, 0xc6
            };
            const uint8_t *bytes = code;
            size_t size = sizeof(code);
            cdisasm_x86_decode_flags flags = exact_rex2_flags(
                selector == 0 ? CDISASM_X86_DECODE_BIT_WRMSRNS
                              : CDISASM_X86_DECODE_BIT_MSRLIST);
            uint32_t decoded_size;
            cdisasm_instruction instruction;

            if (selector == 0) {
                ++bytes;
                --size;
            } else {
                code[0] = (uint8_t)(selector == 1 ? 0xf2 : 0xf3);
            }
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                bytes, size, &flags, &decoded_size);
            if (decoded_size != 0u) {
                EXPECT(instruction.form_id != UINT16_C(2571));
                EXPECT(instruction.form_id != UINT16_C(8892));
                EXPECT(instruction.form_id != UINT16_C(8893));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_MSRLIST));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_WRMSRNS));
            }
        }
    }
#endif
}

static void test_vex_space(void)
{
    unsigned int operation;
    unsigned int raw_extensions;
    unsigned int rm;
    size_t valid = 0;

    for (operation = 0; operation < 2; ++operation) {
        for (raw_extensions = 0; raw_extensions < 8; ++raw_extensions) {
            for (rm = 0; rm < 8; ++rm) {
                uint8_t p0 = (uint8_t)(0x07u | (raw_extensions << 5));
                uint8_t code[] = {
                    0xc4, p0,
                    (uint8_t)(operation == 0 ? 0x7b : 0x7a),
                    0xf6, (uint8_t)(0xc0u | rm), 0x78, 0x56, 0x34, 0x12
                };
#if USE_EXTRA_OPCODES
                cdisasm_x86_decode_flags flags = one_bit(
                    CDISASM_X86_DECODE_BIT_MSR_IMM);
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), &flags, &decoded_size);
                unsigned int reg = rm
                    + ((p0 & UINT8_C(0x20)) == 0 ? 8u : 0u);

                check_common(&instruction, decoded_size, sizeof(code),
                    operation == 0 ? CDISASM_X86_NAME_RDMSR
                                   : CDISASM_X86_NAME_WRMSRNS,
                    operation == 0 ? UINT16_C(2572) : UINT16_C(8894),
                    CDISASM_X86_GROUP_MSR_IMM);
                expect_register(&instruction, operation == 0 ? 0u : 1u,
                    gpr64(reg), operation == 0
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ);
#else
                expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), NULL,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                ++valid;
            }
        }
    }
    EXPECT(valid == 128u);
}

static void test_apx_space(void)
{
    unsigned int operation;
    unsigned int raw_extensions;
    unsigned int rm;
    size_t valid = 0;

    for (operation = 0; operation < 2; ++operation) {
        for (raw_extensions = 0; raw_extensions < 32; ++raw_extensions) {
            for (rm = 0; rm < 8; ++rm) {
                uint8_t p0 = (uint8_t)(0x07u | (raw_extensions << 3));
                uint8_t code[] = {
                    0x62, p0,
                    (uint8_t)(operation == 0 ? 0x7f : 0x7e),
                    0x08, 0xf6, (uint8_t)(0xc0u | rm),
                    0x78, 0x56, 0x34, 0x12
                };
#if USE_EXTRA_OPCODES
                cdisasm_x86_decode_flags flags = one_bit(
                    CDISASM_X86_DECODE_BIT_APX_F_MSR_IMM);
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), &flags, &decoded_size);
                unsigned int reg = rm
                    + ((p0 & UINT8_C(0x20)) == 0 ? 8u : 0u)
                    + ((p0 & UINT8_C(0x08)) != 0 ? 16u : 0u);

                check_common(&instruction, decoded_size, sizeof(code),
                    operation == 0 ? CDISASM_X86_NAME_RDMSR
                                   : CDISASM_X86_NAME_WRMSRNS,
                    operation == 0 ? UINT16_C(2573) : UINT16_C(8895),
                    CDISASM_X86_GROUP_APX_F_MSR_IMM);
                expect_register(&instruction, operation == 0 ? 0u : 1u,
                    gpr64(reg), operation == 0
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ);
#else
                expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), NULL,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                ++valid;
            }
        }
    }
    EXPECT(valid == 512u);
}

static void test_control_byte_sweeps(void)
{
    unsigned int value;
    unsigned int operation;
    size_t vex_p1_valid = 0;
    size_t apx_p1_valid = 0;
    size_t apx_p2_valid = 0;
    size_t vex_p0_valid = 0;
    size_t apx_p0_valid = 0;
    size_t vex_modrm_valid = 0;
    size_t apx_modrm_valid = 0;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags vex_flags = one_bit(
        CDISASM_X86_DECODE_BIT_MSR_IMM);
    cdisasm_x86_decode_flags apx_flags = one_bit(
        CDISASM_X86_DECODE_BIT_APX_F_MSR_IMM);
    const cdisasm_x86_decode_flags *vex_ptr = &vex_flags;
    const cdisasm_x86_decode_flags *apx_ptr = &apx_flags;
#else
    const cdisasm_x86_decode_flags *vex_ptr = NULL;
    const cdisasm_x86_decode_flags *apx_ptr = NULL;
#endif

    for (value = 0; value < 256; ++value) {
        uint8_t code[] = {
            0xc4, 0xe7, (uint8_t)value, 0xf6, 0xc0, 0, 0, 0, 0
        };
        const int valid = value == UINT8_C(0x7a)
            || value == UINT8_C(0x7b);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), vex_ptr, &decoded_size);

        if (valid) {
#if USE_EXTRA_OPCODES
            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.form_id == (value == UINT8_C(0x7b)
                ? UINT16_C(2572) : UINT16_C(8894)));
#else
            EXPECT(decoded_size == 0u);
            EXPECT(instruction.last_error_id
                == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            ++vex_p1_valid;
        } else {
            EXPECT(decoded_size == 0u);
            EXPECT(instruction.last_error_id
                == CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    for (value = 0; value < 256; ++value) {
        uint8_t code[] = {
            0x62, 0xf7, (uint8_t)value, 0x08, 0xf6, 0xc0, 0, 0, 0, 0
        };
        const int valid = value == UINT8_C(0x7e)
            || value == UINT8_C(0x7f);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), apx_ptr, &decoded_size);

        if (valid) {
#if USE_EXTRA_OPCODES
            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.form_id == (value == UINT8_C(0x7f)
                ? UINT16_C(2573) : UINT16_C(8895)));
#else
            EXPECT(decoded_size == 0u);
            EXPECT(instruction.last_error_id
                == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            ++apx_p1_valid;
        } else {
            EXPECT(decoded_size == 0u);
            EXPECT(instruction.last_error_id
                == CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    for (operation = 0; operation < 2; ++operation) {
        for (value = 0; value < 256; ++value) {
            uint8_t code[] = {
                0x62, 0xf7,
                (uint8_t)(operation == 0 ? 0x7f : 0x7e),
                (uint8_t)value, 0xf6, 0xc0, 0, 0, 0, 0
            };
            const int valid = value == UINT8_C(0x08);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), apx_ptr, &decoded_size);

            if (valid) {
#if USE_EXTRA_OPCODES
                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.form_id == (operation == 0
                    ? UINT16_C(2573) : UINT16_C(8895)));
#else
                EXPECT(decoded_size == 0u);
                EXPECT(instruction.last_error_id
                    == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                ++apx_p2_valid;
            } else {
                EXPECT(decoded_size == 0u);
                EXPECT(instruction.last_error_id
                    == CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }
    }

#if USE_EXTRA_OPCODES
    for (operation = 0; operation < 2; ++operation) {
        for (value = 0; value < 256; ++value) {
            uint8_t vex[] = {
                0xc4, (uint8_t)value,
                (uint8_t)(operation == 0 ? 0x7b : 0x7a),
                0xf6, 0xc0, 0, 0, 0, 0
            };
            uint8_t apx[] = {
                0x62, (uint8_t)value,
                (uint8_t)(operation == 0 ? 0x7f : 0x7e),
                0x08, 0xf6, 0xc0, 0, 0, 0, 0
            };
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                vex, sizeof(vex), &vex_flags, &decoded_size);

            if ((value & UINT8_C(0x1f)) == UINT8_C(0x07)) {
                EXPECT(decoded_size == sizeof(vex));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_MSR_IMM));
                ++vex_p0_valid;
            } else if (decoded_size != 0u) {
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_MSR_IMM));
            }

            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                apx, sizeof(apx), &apx_flags, &decoded_size);
            if ((value & UINT8_C(0x07)) == UINT8_C(0x07)) {
                EXPECT(decoded_size == sizeof(apx));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_APX_F_MSR_IMM));
                ++apx_p0_valid;
            } else if (decoded_size != 0u) {
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_APX_F_MSR_IMM));
            }
        }
    }
#else
    vex_p0_valid = 16u;
    apx_p0_valid = 64u;
#endif

    for (operation = 0; operation < 2; ++operation) {
        for (value = 0; value < 256; ++value) {
            uint8_t vex[15] = {
                0xc4, 0xe7,
                (uint8_t)(operation == 0 ? 0x7b : 0x7a),
                0xf6, (uint8_t)value
            };
            uint8_t apx[15] = {
                0x62, 0xf7,
                (uint8_t)(operation == 0 ? 0x7f : 0x7e),
                0x08, 0xf6, (uint8_t)value
            };
            const int valid = value >= UINT8_C(0xc0)
                && value <= UINT8_C(0xc7);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                vex, sizeof(vex), vex_ptr, &decoded_size);

            if (valid) {
#if USE_EXTRA_OPCODES
                EXPECT(decoded_size == 9u);
#else
                EXPECT(decoded_size == 0u);
                EXPECT(instruction.last_error_id
                    == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                ++vex_modrm_valid;
            } else {
                EXPECT(decoded_size == 0u);
                EXPECT(instruction.last_error_id
                    == CDISASM_STATUS_INVALID_INSTRUCTION);
            }

            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                apx, sizeof(apx), apx_ptr, &decoded_size);
            if (valid) {
#if USE_EXTRA_OPCODES
                EXPECT(decoded_size == 10u);
#else
                EXPECT(decoded_size == 0u);
                EXPECT(instruction.last_error_id
                    == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                ++apx_modrm_valid;
            } else {
                EXPECT(decoded_size == 0u);
                EXPECT(instruction.last_error_id
                    == CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }
    }

    EXPECT(vex_p1_valid == 2u);
    EXPECT(apx_p1_valid == 2u);
    EXPECT(apx_p2_valid == 2u);
    EXPECT(vex_p0_valid == 16u);
    EXPECT(apx_p0_valid == 64u);
    EXPECT(vex_modrm_valid == 16u);
    EXPECT(apx_modrm_valid == 16u);
}

static void test_modern_prefixes_and_collisions(void)
{
    static const uint8_t ignored_prefixes[] = {
        0x67, 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65
    };
    static const uint8_t invalid_prefixes[] = {
        0x66, 0xf2, 0xf3, 0xf0
    };
    unsigned int operation;
    size_t prefix_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags vex_flags = one_bit(
        CDISASM_X86_DECODE_BIT_MSR_IMM);
    cdisasm_x86_decode_flags apx_flags = one_bit(
        CDISASM_X86_DECODE_BIT_APX_F_MSR_IMM);
    const cdisasm_x86_decode_flags *vex_ptr = &vex_flags;
    const cdisasm_x86_decode_flags *apx_ptr = &apx_flags;
#else
    const cdisasm_x86_decode_flags *vex_ptr = NULL;
    const cdisasm_x86_decode_flags *apx_ptr = NULL;
#endif

    for (operation = 0; operation < 2; ++operation) {
        for (prefix_index = 0;
             prefix_index < sizeof(ignored_prefixes);
             ++prefix_index) {
            uint8_t vex[] = {
                ignored_prefixes[prefix_index], 0xc4, 0xe7,
                (uint8_t)(operation == 0 ? 0x7b : 0x7a),
                0xf6, 0xc0, 0, 0, 0, 0
            };
            uint8_t apx[] = {
                ignored_prefixes[prefix_index], 0x62, 0xf7,
                (uint8_t)(operation == 0 ? 0x7f : 0x7e),
                0x08, 0xf6, 0xc0, 0, 0, 0, 0
            };
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                vex, sizeof(vex), vex_ptr, &decoded_size);

#if USE_EXTRA_OPCODES
            EXPECT(decoded_size == sizeof(vex));
            EXPECT(instruction.form_id == (operation == 0
                ? UINT16_C(2572) : UINT16_C(8894)));
#else
            EXPECT(decoded_size == 0u);
            EXPECT(instruction.last_error_id
                == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                apx, sizeof(apx), apx_ptr, &decoded_size);
#if USE_EXTRA_OPCODES
            EXPECT(decoded_size == sizeof(apx));
            EXPECT(instruction.form_id == (operation == 0
                ? UINT16_C(2573) : UINT16_C(8895)));
#else
            EXPECT(decoded_size == 0u);
            EXPECT(instruction.last_error_id
                == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }

        for (prefix_index = 0;
             prefix_index < sizeof(invalid_prefixes);
             ++prefix_index) {
            uint8_t vex[] = {
                invalid_prefixes[prefix_index], 0xc4, 0xe7,
                (uint8_t)(operation == 0 ? 0x7b : 0x7a),
                0xf6, 0xc0, 0, 0, 0, 0
            };
            uint8_t apx[] = {
                invalid_prefixes[prefix_index], 0x62, 0xf7,
                (uint8_t)(operation == 0 ? 0x7f : 0x7e),
                0x08, 0xf6, 0xc0, 0, 0, 0, 0
            };

            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                vex, sizeof(vex), vex_ptr,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                apx, sizeof(apx), apx_ptr,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }

        for (prefix_index = 0; prefix_index < 16; ++prefix_index) {
            uint8_t vex[] = {
                (uint8_t)(0x40u + prefix_index), 0xc4, 0xe7,
                (uint8_t)(operation == 0 ? 0x7b : 0x7a),
                0xf6, 0xc0, 0, 0, 0, 0
            };
            uint8_t apx[] = {
                (uint8_t)(0x40u + prefix_index), 0x62, 0xf7,
                (uint8_t)(operation == 0 ? 0x7f : 0x7e),
                0x08, 0xf6, 0xc0, 0, 0, 0, 0
            };

            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                vex, sizeof(vex), vex_ptr,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                apx, sizeof(apx), apx_ptr,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t vex_user[] = {
            0xc4, 0xe7, 0x7b, 0xf8, 0xc0, 0, 0, 0, 0
        };
        static const uint8_t apx_user[] = {
            0x62, 0x07, 0x7f, 0x08, 0xf8, 0xc0, 0, 0, 0, 0
        };
        static const uint8_t vex_neighbor[] = {
            0xc4, 0xe7, 0x7b, 0xf7, 0xc0, 0, 0, 0, 0
        };
        static const uint8_t apx_neighbor[] = {
            0x62, 0xf7, 0x7f, 0x08, 0xf7, 0xc0, 0, 0, 0, 0
        };
        cdisasm_x86_decode_flags user = one_bit(
            CDISASM_X86_DECODE_BIT_USER_MSR);
        cdisasm_x86_decode_flags apx_user_flags = one_bit(
            CDISASM_X86_DECODE_BIT_APX_F_USER_MSR);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_user, sizeof(vex_user), &user, &decoded_size);

        EXPECT(decoded_size == sizeof(vex_user));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_URDMSR);
        EXPECT(instruction.form_id == UINT16_C(3355));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_MSR_IMM));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            apx_user, sizeof(apx_user), &apx_user_flags, &decoded_size);
        EXPECT(decoded_size == sizeof(apx_user));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_URDMSR);
        EXPECT(instruction.form_id == UINT16_C(3356));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F_MSR_IMM));
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_neighbor, sizeof(vex_neighbor), &vex_flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            apx_neighbor, sizeof(apx_neighbor), &apx_flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#endif
}

static void test_reserved_controls_and_truncation(void)
{
    static const uint8_t legacy_np[] = {0x0f, 0x01, 0xc6};
    static const uint8_t legacy_rd[] = {0xf2, 0x0f, 0x01, 0xc6};
    static const uint8_t legacy_wr[] = {0xf3, 0x0f, 0x01, 0xc6};
    static const uint8_t rex2_np[] = {0xd5, 0x80, 0x01, 0xc6};
    static const uint8_t rex2_rd[] = {0xf2, 0xd5, 0xff, 0x01, 0xc6};
    static const uint8_t rex2_wr[] = {0xf3, 0xd5, 0x80, 0x01, 0xc6};
    static const uint8_t legacy_lock[] = {0xf0, 0x0f, 0x01, 0xc6};
    static const uint8_t legacy_np_66[] = {0x66, 0x0f, 0x01, 0xc6};
    static const uint8_t legacy_list_66[] = {0x66, 0xf2, 0x0f, 0x01, 0xc6};
    static const uint8_t legacy_rightmost[] = {
        0xf2, 0xf3, 0x0f, 0x01, 0xc6
    };
    static const uint8_t legacy_ignored[] = {
        0x64, 0x67, 0x48, 0xf2, 0x0f, 0x01, 0xc6
    };
    static const uint8_t vex[] = {
        0xc4, 0xe7, 0x7b, 0xf6, 0xc0, 0, 0, 0, 0
    };
    static const uint8_t apx[] = {
        0x62, 0xf7, 0x7f, 0x08, 0xf6, 0xc0, 0, 0, 0, 0
    };
    static const uint8_t apx_w1_short[] = {
        0x62, 0xf7, 0xff, 0x08, 0xf6, 0xc0, 0, 0
    };
    static const uint8_t apx_p2_short[] = {
        0x62, 0xf7, 0x7f, 0x18, 0xf6, 0xc0, 0, 0
    };
    uint8_t bad[sizeof(apx)];
    size_t length;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags list = one_bit(
        CDISASM_X86_DECODE_BIT_MSRLIST);
    cdisasm_x86_decode_flags vex_flags = one_bit(
        CDISASM_X86_DECODE_BIT_MSR_IMM);
    cdisasm_x86_decode_flags apx_flags = one_bit(
        CDISASM_X86_DECODE_BIT_APX_F_MSR_IMM);
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    const cdisasm_x86_decode_flags *list_ptr = &list;
    const cdisasm_x86_decode_flags *vex_ptr = &vex_flags;
    const cdisasm_x86_decode_flags *apx_ptr = &apx_flags;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_list_66, sizeof(legacy_list_66), &list, &decoded_size);
    EXPECT(decoded_size == sizeof(legacy_list_66));
    EXPECT(instruction.form_id == UINT16_C(2571));
    expect_text(&instruction, "rdmsrlist");
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_rightmost, sizeof(legacy_rightmost), &list, &decoded_size);
    EXPECT(decoded_size == sizeof(legacy_rightmost));
    EXPECT(instruction.form_id == UINT16_C(8892));
    expect_text(&instruction, "wrmsrlist");
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_ignored, sizeof(legacy_ignored), &list, &decoded_size);
    EXPECT(decoded_size == sizeof(legacy_ignored));
    EXPECT(instruction.form_id == UINT16_C(2571));
    expect_text(&instruction, "rdmsrlist");
#else
    const cdisasm_x86_decode_flags *list_ptr = NULL;
    const cdisasm_x86_decode_flags *vex_ptr = NULL;
    const cdisasm_x86_decode_flags *apx_ptr = NULL;
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_list_66, sizeof(legacy_list_66), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_rightmost, sizeof(legacy_rightmost), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_ignored, sizeof(legacy_ignored), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_lock, sizeof(legacy_lock), list_ptr,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_np_66, sizeof(legacy_np_66), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    memcpy(bad, vex, sizeof(vex));
    bad[2] |= UINT8_C(0x80);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        bad, sizeof(vex), vex_ptr, CDISASM_STATUS_INVALID_INSTRUCTION);
    memcpy(bad, vex, sizeof(vex));
    bad[2] ^= UINT8_C(0x04);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        bad, sizeof(vex), vex_ptr, CDISASM_STATUS_INVALID_INSTRUCTION);
    memcpy(bad, vex, sizeof(vex));
    bad[2] ^= UINT8_C(0x08);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        bad, sizeof(vex), vex_ptr, CDISASM_STATUS_INVALID_INSTRUCTION);
    memcpy(bad, vex, sizeof(vex));
    bad[4] = UINT8_C(0xc8);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        bad, sizeof(vex), vex_ptr, CDISASM_STATUS_INVALID_INSTRUCTION);
    memcpy(bad, vex, sizeof(vex));
    bad[4] = UINT8_C(0x00);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        bad, sizeof(vex), vex_ptr, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_32,
        vex, sizeof(vex), vex_ptr, CDISASM_STATUS_INVALID_INSTRUCTION);

    memcpy(bad, apx, sizeof(apx));
    bad[2] |= UINT8_C(0x80);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        bad, sizeof(apx), apx_ptr, CDISASM_STATUS_INVALID_INSTRUCTION);
    memcpy(bad, apx, sizeof(apx));
    bad[2] &= (uint8_t)~UINT8_C(0x04);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        bad, sizeof(apx), apx_ptr, CDISASM_STATUS_INVALID_INSTRUCTION);
    memcpy(bad, apx, sizeof(apx));
    bad[2] ^= UINT8_C(0x08);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        bad, sizeof(apx), apx_ptr, CDISASM_STATUS_INVALID_INSTRUCTION);
    {
        static const uint8_t p2_bad[] = {0x80, 0x10, 0x04, 0x20, 0x08};
        unsigned int index;

        for (index = 0; index < sizeof(p2_bad); ++index) {
            memcpy(bad, apx, sizeof(apx));
            bad[3] = index + 1u == sizeof(p2_bad)
                ? UINT8_C(0x00)
                : (uint8_t)(UINT8_C(0x08) | p2_bad[index]);
            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                bad, sizeof(apx), apx_ptr,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    memcpy(bad, apx, sizeof(apx));
    bad[5] = UINT8_C(0xc8);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        bad, sizeof(apx), apx_ptr, CDISASM_STATUS_INVALID_INSTRUCTION);
    memcpy(bad, apx, sizeof(apx));
    bad[5] = UINT8_C(0x00);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        bad, sizeof(apx), apx_ptr, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_32,
        apx, sizeof(apx), apx_ptr, CDISASM_STATUS_INVALID_INSTRUCTION);

    for (length = 1; length < sizeof(vex); ++length) {
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex, length, vex_ptr, CDISASM_STATUS_TRUNCATED);
    }
    for (length = 1; length < sizeof(apx); ++length) {
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            apx, length, apx_ptr, CDISASM_STATUS_TRUNCATED);
    }
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        apx_w1_short, sizeof(apx_w1_short), apx_ptr,
        CDISASM_STATUS_TRUNCATED);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        apx_p2_short, sizeof(apx_p2_short), apx_ptr,
        CDISASM_STATUS_TRUNCATED);
    {
        static const struct truncated_case {
            const uint8_t *code;
            size_t size;
        } cases[] = {
            {legacy_np, sizeof(legacy_np)},
            {legacy_rd, sizeof(legacy_rd)},
            {legacy_wr, sizeof(legacy_wr)},
            {rex2_np, sizeof(rex2_np)},
            {rex2_rd, sizeof(rex2_rd)},
            {rex2_wr, sizeof(rex2_wr)}
        };
        size_t case_index;

        for (case_index = 0;
             case_index < sizeof(cases) / sizeof(cases[0]);
             ++case_index) {
            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                cases[case_index].code, 0u, NULL,
                CDISASM_STATUS_END_OF_INPUT);
            for (length = 1; length < cases[case_index].size; ++length) {
                expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                    cases[case_index].code, length, NULL,
                    CDISASM_STATUS_TRUNCATED);
            }
        }
    }
}

static void test_cpu_and_runtime_gates(void)
{
    static const uint8_t rdlist[] = {0xf2, 0x0f, 0x01, 0xc6};
    static const uint8_t wrns[] = {0x0f, 0x01, 0xc6};
    static const uint8_t rex2_rdlist[] = {
        0xf2, 0xd5, 0x80, 0x01, 0xc6
    };
    static const uint8_t vex[] = {
        0xc4, 0xe7, 0x7b, 0xf6, 0xc0, 0, 0, 0, 0
    };
    static const uint8_t apx[] = {
        0x62, 0xf7, 0x7f, 0x08, 0xf6, 0xc0, 0, 0, 0, 0
    };
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags list = one_bit(
        CDISASM_X86_DECODE_BIT_MSRLIST);
    cdisasm_x86_decode_flags wr = one_bit(
        CDISASM_X86_DECODE_BIT_WRMSRNS);
    cdisasm_x86_decode_flags vex_flags = one_bit(
        CDISASM_X86_DECODE_BIT_MSR_IMM);
    cdisasm_x86_decode_flags apx_flags = one_bit(
        CDISASM_X86_DECODE_BIT_APX_F_MSR_IMM);
    cdisasm_x86_decode_flags rex2_flags = exact_rex2_flags(
        CDISASM_X86_DECODE_BIT_MSRLIST);
    cdisasm_x86_decode_flags system_only =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    system_only.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        CDISASM_X86_DECODE_FLAG_SYSTEM;

    instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        rdlist, sizeof(rdlist), &list, &decoded_size);
    EXPECT(decoded_size == sizeof(rdlist));
    EXPECT(instruction.form_id == UINT16_C(2571));
    instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_32,
        wrns, sizeof(wrns), &wr, &decoded_size);
    EXPECT(decoded_size == sizeof(wrns));
    EXPECT(instruction.form_id == UINT16_C(8893));
    instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_16,
        wrns, sizeof(wrns), &wr, &decoded_size);
    EXPECT(decoded_size == sizeof(wrns));
    EXPECT(instruction.form_id == UINT16_C(8893));
    instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        wrns, sizeof(wrns), &wr, &decoded_size);
    EXPECT(decoded_size == sizeof(wrns));
    EXPECT(instruction.form_id == UINT16_C(8893));
    instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        rex2_rdlist, sizeof(rex2_rdlist), &rex2_flags, &decoded_size);
    EXPECT(decoded_size == sizeof(rex2_rdlist));
    EXPECT(instruction.form_id == UINT16_C(2571));
    expect_error_cpu(CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64,
        rdlist, sizeof(rdlist), &list, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64,
        wrns, sizeof(wrns), &wr, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        vex, sizeof(vex), &vex_flags, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        apx, sizeof(apx), &apx_flags, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_APX, CDISASM_MODE_64,
        rdlist, sizeof(rdlist), &list, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_APX, CDISASM_MODE_64,
        wrns, sizeof(wrns), &wr, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_APX, CDISASM_MODE_64,
        vex, sizeof(vex), &vex_flags, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_APX, CDISASM_MODE_64,
        apx, sizeof(apx), &apx_flags, CDISASM_STATUS_INVALID_INSTRUCTION);

    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        rdlist, sizeof(rdlist), &system_only,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        wrns, sizeof(wrns), &list, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        vex, sizeof(vex), &list, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        apx, sizeof(apx), &vex_flags,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2_rdlist, sizeof(rex2_rdlist), &list,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2_rdlist, sizeof(rex2_rdlist), &rex2_flags, &decoded_size);
    EXPECT(decoded_size == sizeof(rex2_rdlist));
    EXPECT(instruction.form_id == UINT16_C(2571));
#else
    expect_error_cpu(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        rdlist, sizeof(rdlist), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_32,
        wrns, sizeof(wrns), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_16,
        wrns, sizeof(wrns), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        wrns, sizeof(wrns), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64,
        rdlist, sizeof(rdlist), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        vex, sizeof(vex), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2_rdlist, sizeof(rex2_rdlist), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
        apx, sizeof(apx), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_APX, CDISASM_MODE_64,
        rdlist, sizeof(rdlist), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_APX, CDISASM_MODE_64,
        wrns, sizeof(wrns), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_APX, CDISASM_MODE_64,
        vex, sizeof(vex), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_cpu(CDISASM_CPU_APX, CDISASM_MODE_64,
        apx, sizeof(apx), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
}

static void test_owned_body_error_precedence(void)
{
    unsigned int operation;
    size_t part;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags vex_flags = one_bit(
        CDISASM_X86_DECODE_BIT_MSR_IMM);
    cdisasm_x86_decode_flags apx_flags = one_bit(
        CDISASM_X86_DECODE_BIT_APX_F_MSR_IMM);
    const cdisasm_x86_decode_flags *vex_ptr = &vex_flags;
    const cdisasm_x86_decode_flags *apx_ptr = &apx_flags;
#else
    const cdisasm_x86_decode_flags *vex_ptr = NULL;
    const cdisasm_x86_decode_flags *apx_ptr = NULL;
#endif

    for (operation = 0; operation < 2; ++operation) {
        const uint8_t vex_p1 = (uint8_t)(operation == 0 ? 0x7b : 0x7a);
        const uint8_t apx_p1 = (uint8_t)(operation == 0 ? 0x7f : 0x7e);
        uint8_t vex_bad_reg[9] = {
            0xc4, 0xe7, vex_p1, 0xf6, 0xc8, 0, 0, 0, 0
        };
        uint8_t apx_bad_reg[10] = {
            0x62, 0xf7, apx_p1, 0x08, 0xf6, 0xc8, 0, 0, 0, 0
        };
        uint8_t vex_mem[14] = {
            0xc4, 0xe7, vex_p1, 0xf6, 0x04, 0x25,
            0, 0, 0, 0, 0, 0, 0, 0
        };
        uint8_t apx_mem[15] = {
            0x62, 0xf7, apx_p1, 0x08, 0xf6, 0x04, 0x25,
            0, 0, 0, 0, 0, 0, 0, 0
        };
        uint8_t vex_header[9] = {
            0xc4, 0xe7, vex_p1, 0xf6, 0xc0, 0, 0, 0, 0
        };
        uint8_t apx_header[10] = {
            0x62, 0xf7, apx_p1, 0x18, 0xf6, 0xc0, 0, 0, 0, 0
        };
        uint8_t vex_prefixed[10] = {
            0x66, 0xc4, 0xe7, vex_p1, 0xf6, 0xc0, 0, 0, 0, 0
        };

        /* Raw /1 owns the body shape but is reserved after its imm32. */
        for (part = 0; part < 4; ++part) {
            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                vex_bad_reg, 5u + part, vex_ptr,
                CDISASM_STATUS_TRUNCATED);
            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                apx_bad_reg, 6u + part, apx_ptr,
                CDISASM_STATUS_TRUNCATED);
        }
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_bad_reg, sizeof(vex_bad_reg), vex_ptr,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            apx_bad_reg, sizeof(apx_bad_reg), apx_ptr,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        /* Exercise a missing SIB, partial base-5 disp32, and then each
         * partial imm32 length following a complete memory address. */
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_mem, 5u, vex_ptr, CDISASM_STATUS_TRUNCATED);
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            apx_mem, 6u, apx_ptr, CDISASM_STATUS_TRUNCATED);
        for (part = 0; part < 4; ++part) {
            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                vex_mem, 6u + part, vex_ptr,
                CDISASM_STATUS_TRUNCATED);
            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                apx_mem, 7u + part, apx_ptr,
                CDISASM_STATUS_TRUNCATED);
            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                vex_mem, 10u + part, vex_ptr,
                CDISASM_STATUS_TRUNCATED);
            expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
                apx_mem, 11u + part, apx_ptr,
                CDISASM_STATUS_TRUNCATED);
        }
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_mem, sizeof(vex_mem), vex_ptr,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            apx_mem, sizeof(apx_mem), apx_ptr,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        vex_header[2] |= UINT8_C(0x80);
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_header, 7u, vex_ptr, CDISASM_STATUS_TRUNCATED);
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_header, sizeof(vex_header), vex_ptr,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        vex_header[2] = (uint8_t)(vex_p1 ^ UINT8_C(0x08));
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_header, 7u, vex_ptr, CDISASM_STATUS_TRUNCATED);
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_header, sizeof(vex_header), vex_ptr,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            apx_header, 8u, apx_ptr, CDISASM_STATUS_TRUNCATED);
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            apx_header, sizeof(apx_header), apx_ptr,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        apx_header[3] = UINT8_C(0x08);
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_32,
            apx_header, 8u, apx_ptr, CDISASM_STATUS_TRUNCATED);
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_32,
            apx_header, sizeof(apx_header), apx_ptr,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        /* Once map-7 F6 is owned, an illegal leading legacy prefix is
         * adjudicated only after the complete immediate-selector body. */
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_prefixed, 8u, vex_ptr, CDISASM_STATUS_TRUNCATED);
        expect_error_cpu(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex_prefixed, sizeof(vex_prefixed), vex_ptr,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

int main(void)
{
    test_examples();
    test_legacy_space();
    test_rex2_payload_space();
    test_legacy_rex_and_rex2_collisions();
    test_vex_space();
    test_apx_space();
    test_control_byte_sweeps();
    test_modern_prefixes_and_collisions();
    test_reserved_controls_and_truncation();
    test_cpu_and_runtime_gates();
    test_owned_body_error_precedence();

    if (failures != 0) {
        fprintf(stderr, "%d x86 MSR system test(s) failed\n", failures);
        return 1;
    }
    puts("x86 MSR system tests passed (5 legacy mode/selectors, "
         "384 REX2, 128 VEX, and 512 APX tuples)");
    return 0;
}
