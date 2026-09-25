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
            if (failures < 64) {                                             \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",        \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VPERMILPD == UINT16_C(1834)
        && CDISASM_X86_NAME_VPERMILPS == UINT16_C(1835),
    "VPERMILPD/VPERMILPS name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VPERMILPD/VPERMILPS AVX IDs changed");

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
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_X86, mode, code, size, flags, &decoded_size);

    if (decoded_size != 0u || !is_error_only(&instruction, status)) {
        fprintf(stderr, "%s: got size/status %u/%u, expected 0/%u\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id, (unsigned int)status);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags selected_flags(int avx, int avx2)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    if (avx) {
        EXPECT(cdisasm_decode_flags_set_bit(
            &flags, CDISASM_X86_DECODE_BIT_AVX));
    }
    if (avx2) {
        EXPECT(cdisasm_decode_flags_set_bit(
            &flags, CDISASM_X86_DECODE_BIT_AVX2));
    }
    return flags;
}

static cdisasm_x86_decode_flags all_flags(cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, mode, &flags) == CDISASM_STATUS_OK);
    return flags;
}

static cdisasm_x86_form_id expected_form(
    uint8_t opcode,
    int immediate_form,
    unsigned int vector_bits,
    int register_form)
{
    const int is_double = opcode == UINT8_C(0x05)
        || opcode == UINT8_C(0x0d);

    return (cdisasm_x86_form_id)(
        (is_double ? UINT16_C(6834) : UINT16_C(6854))
        + (immediate_form ? 0u : 2u)
        + (vector_bits == 256u ? 12u : 0u)
        + (register_form ? 1u : 0u));
}

static void check_permil(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t opcode,
    int immediate_form,
    unsigned int vector_bits,
    int register_form)
{
    const cdisasm_x86_name_id name =
        opcode == UINT8_C(0x05) || opcode == UINT8_C(0x0d)
        ? CDISASM_X86_NAME_VPERMILPD : CDISASM_X86_NAME_VPERMILPS;
    const cdisasm_x86_reg_id register_base = vector_bits == 128u
        ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
    const size_t memory_index = immediate_form ? 1u : 2u;
    size_t index;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == name);
    EXPECT(instruction->form_id == expected_form(
        opcode, immediate_form, vector_bits, register_form));
    EXPECT(instruction->operand_count == 3u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
        == CDISASM_PREFIX_VEX);
    EXPECT(instruction->encoding.prefix_size >= 3u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count
        == (immediate_form ? 1u : 0u));
    if (immediate_form) {
        EXPECT(instruction->encoding.immediate_size[0] == 1u);
        EXPECT(instruction->encoding.immediate_offset[0]
            == instruction->opcode_size - 1u);
    }
    EXPECT(instruction->encoding.selector_offset == 0u);

    for (index = 0u; index < (immediate_form ? 2u : 3u); ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = !register_form && index == memory_index;

        EXPECT(operand->type == (memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(operand->size == vector_bits / 8u);
        EXPECT(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
        EXPECT(operand->broadcast == CDISASM_X86_BROADCAST_NONE);
        if (memory) {
            EXPECT((operand->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
        } else {
            EXPECT(operand->reg >= register_base
                && operand->reg <= register_base + 15u);
            EXPECT(operand->flags == 0u);
            if (mode != CDISASM_MODE_64) {
                EXPECT(operand->reg <= register_base + 7u);
            }
        }
    }
    if (immediate_form) {
        EXPECT(instruction->opcode[2].type == CDISASM_OPERAND_IMMEDIATE);
        EXPECT(instruction->opcode[2].size == 1u);
        EXPECT(instruction->opcode[2].access
            == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction->opcode[2].flags == 0u);
        EXPECT(instruction->opcode[2].broadcast
            == CDISASM_X86_BROADCAST_NONE);
        EXPECT(instruction->opcode[2].imm <= UINT8_MAX);
    }
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2));
}
#endif

static void test_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const uint8_t maps[2] = {UINT8_C(3), UINT8_C(2)};
    static const uint8_t opcodes[2][2] = {
        {UINT8_C(0x05), UINT8_C(0x04)},
        {UINT8_C(0x0d), UINT8_C(0x0c)}};
    static const uint64_t expected_counts[2][2] = {
        {UINT64_C(2304), UINT64_C(768)},
        {UINT64_C(36864), UINT64_C(12288)}};
    uint64_t form_counts[2][2][2][2] = {{{{0u}}}};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;
    size_t kind;
    size_t family;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        const unsigned int p0_count = long_mode ? 8u : 2u;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

        for (kind = 0u; kind < 2u; ++kind) {
            for (family = 0u; family < 2u; ++family) {
                unsigned int p0_index;

                for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
                    const uint8_t p0 = long_mode
                        ? (uint8_t)((p0_index << 5) | maps[kind])
                        : (uint8_t)(0xc0u | (p0_index << 5) | maps[kind]);
                    unsigned int p1;

                    for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                        const int valid = (p1 & UINT8_C(0x83))
                                == UINT8_C(0x01)
                            && (kind != 0u
                                || (p1 & UINT8_C(0x78))
                                    == UINT8_C(0x78));
                        unsigned int modrm;

                        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                            const int register_form =
                                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                            const unsigned int vector_bits =
                                (p1 & UINT8_C(4)) != 0u ? 256u : 128u;
                            const uint8_t code[15] = {
                                0xc4, p0, (uint8_t)p1,
                                opcodes[kind][family], (uint8_t)modrm,
                                0x24, 0x10, 0x20, 0x30, 0x40,
                                0x50, 0x60, 0x70, 0x80, 0x90};
                            uint32_t decoded_size;
                            cdisasm_instruction instruction = decode(
                                CDISASM_CPU_X86, modes[mode_index],
                                code, sizeof(code),
#if USE_EXTRA_OPCODES
                                &flags,
#else
                                NULL,
#endif
                                &decoded_size);

                            if (valid) {
#if USE_EXTRA_OPCODES
                                check_permil(&instruction, decoded_size,
                                    modes[mode_index], opcodes[kind][family],
                                    kind == 0u, vector_bits, register_form);
#else
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                ++form_counts[kind][family]
                                    [vector_bits == 256u][register_form];
                                ++allocated;
                            } else {
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_INVALID_INSTRUCTION));
                                ++reserved;
                            }
                        }
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT64_C(208896));
    EXPECT(reserved == UINT64_C(2936832));
    for (kind = 0u; kind < 2u; ++kind) {
        for (family = 0u; family < 2u; ++family) {
            size_t width;

            for (width = 0u; width < 2u; ++width) {
                EXPECT(form_counts[kind][family][width][0]
                    == expected_counts[kind][0]);
                EXPECT(form_counts[kind][family][width][1]
                    == expected_counts[kind][1]);
            }
        }
    }
}

static void test_exact_forms_modes_and_gates(void)
{
    static const struct exact_case {
        uint8_t code[8];
        size_t size;
        uint16_t form;
    } cases[] = {
        {{0xc4,0xe3,0x79,0x05,0x00,0x1b},6u,6834},
        {{0xc4,0xe3,0x79,0x05,0xc1,0x1b},6u,6835},
        {{0xc4,0xe2,0x71,0x0d,0x00},5u,6836},
        {{0xc4,0xe2,0x71,0x0d,0xc2},5u,6837},
        {{0xc4,0xe3,0x7d,0x05,0x00,0x1b},6u,6846},
        {{0xc4,0xe3,0x7d,0x05,0xc1,0x1b},6u,6847},
        {{0xc4,0xe2,0x75,0x0d,0x00},5u,6848},
        {{0xc4,0xe2,0x75,0x0d,0xc2},5u,6849},
        {{0xc4,0xe3,0x79,0x04,0x00,0x1b},6u,6854},
        {{0xc4,0xe3,0x79,0x04,0xc1,0x1b},6u,6855},
        {{0xc4,0xe2,0x71,0x0c,0x00},5u,6856},
        {{0xc4,0xe2,0x71,0x0c,0xc2},5u,6857},
        {{0xc4,0xe3,0x7d,0x04,0x00,0x1b},6u,6866},
        {{0xc4,0xe3,0x7d,0x04,0xc1,0x1b},6u,6867},
        {{0xc4,0xe2,0x75,0x0c,0x00},5u,6868},
        {{0xc4,0xe2,0x75,0x0c,0xc2},5u,6869}};
    size_t index;

#if USE_EXTRA_OPCODES
    const cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
    const cdisasm_x86_decode_flags none = selected_flags(0, 0);
    const cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    const cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags64, &decoded_size);

        EXPECT(decoded_size == cases[index].size);
        EXPECT(instruction.form_id == cases[index].form);
#if USE_DISASM_FORMAT
        {
            char output[192];

            EXPECT(cdisasm_x86_format(&instruction,
                CDISASM_FORMAT_SYNTAX_INTEL,
                output, sizeof(output)) != 0u);
            EXPECT(cdisasm_x86_format(&instruction,
                CDISASM_FORMAT_SYNTAX_ATT,
                output, sizeof(output)) != 0u);
        }
#endif
    }
    expect_error("VPERMIL needs AVX", CDISASM_MODE_64,
        cases[0].code, cases[0].size, &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX2 alone does not admit VPERMIL", CDISASM_MODE_64,
        cases[3].code, cases[3].size, &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[15].code, cases[15].size, &avx, &decoded_size);

        EXPECT(decoded_size == cases[15].size);
        EXPECT(instruction.form_id == UINT16_C(6869));
    }

    for (index = 0u; index < 3u; ++index) {
        static const cdisasm_x86_mode modes[3] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
        cdisasm_x86_decode_flags flags = all_flags(modes[index]);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, modes[index],
            cases[0].code, cases[0].size, &flags, &decoded_size);

        EXPECT(decoded_size == cases[0].size);
        EXPECT(instruction.form_id == UINT16_C(6834));
    }
    for (index = 0u; index < 2u; ++index) {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        static const uint8_t immediate_alias[] = {
            0xc4,0xc3,0x79,0x05,0xc1,0x1b};
        static const uint8_t variable_alias[] = {
            0xc4,0xc2,0x31,0x0d,0xc2};
        cdisasm_x86_decode_flags flags = all_flags(modes[index]);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, modes[index], immediate_alias,
            sizeof(immediate_alias), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(immediate_alias));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM0);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
        instruction = decode(CDISASM_CPU_X86, modes[index], variable_alias,
            sizeof(variable_alias), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(variable_alias));
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
    }
#else
    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error("VPERMIL extras off", CDISASM_MODE_64,
            cases[index].code, cases[index].size, NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif
}

static void test_reserved_truncation_and_collisions(void)
{
    static const uint8_t immediate_opcodes[2] = {0x05, 0x04};
    static const uint8_t variable_opcodes[2] = {0x0d, 0x0c};
    size_t family;

    for (family = 0u; family < 2u; ++family) {
        const uint8_t immediate[] = {
            0xc4,0xe3,0x79,immediate_opcodes[family],0xc1,0x1b};
        const uint8_t variable[] = {
            0xc4,0xe2,0x71,variable_opcodes[family],0xc2};
        size_t size;

        for (size = 1u; size < sizeof(immediate); ++size) {
            expect_error("truncated VPERMIL immediate", CDISASM_MODE_64,
                immediate, size, NULL, CDISASM_STATUS_TRUNCATED);
        }
        for (size = 1u; size < sizeof(variable); ++size) {
            expect_error("truncated VPERMIL variable", CDISASM_MODE_64,
                variable, size, NULL, CDISASM_STATUS_TRUNCATED);
        }
        expect_error("reserved immediate missing SIB", CDISASM_MODE_64,
            (const uint8_t[]){0xc4,0xe3,0x71,
                immediate_opcodes[family],0x04},
            5u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved immediate missing imm8", CDISASM_MODE_64,
            (const uint8_t[]){0xc4,0xe3,0x71,
                immediate_opcodes[family],0x04,0x24},
            6u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved immediate complete", CDISASM_MODE_64,
            (const uint8_t[]){0xc4,0xe3,0x71,
                immediate_opcodes[family],0x04,0x24,0x1b},
            7u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("reserved variable missing disp8", CDISASM_MODE_64,
            (const uint8_t[]){0xc4,0xe2,0xf1,
                variable_opcodes[family],0x45},
            5u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved variable complete", CDISASM_MODE_64,
            (const uint8_t[]){0xc4,0xe2,0xf1,
                variable_opcodes[family],0x45,0x10},
            6u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("legacy prefix missing immediate", CDISASM_MODE_64,
            (const uint8_t[]){0x66,0xc4,0xe3,0x79,
                immediate_opcodes[family],0xc1},
            6u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("legacy prefix complete immediate", CDISASM_MODE_64,
            (const uint8_t[]){0x66,0xc4,0xe3,0x79,
                immediate_opcodes[family],0xc1,0x1b},
            7u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    expect_error("immediate W1", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0xf9,0x05,0xc1,0x1b}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("immediate non-NOVSR", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x71,0x04,0xc1,0x1b}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("variable W1", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0xf1,0x0d,0xc2}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("wrong pp", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x70,0x0c,0xc2}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        static const uint8_t les_collision[] = {
            0xc4,0x63,0x79,0x05,0xc1,0x1b};
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_16);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_16,
            les_collision, sizeof(les_collision), &flags, &decoded_size);

        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
    }
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format_rejected(const cdisasm_instruction *instruction)
{
    char output[192] = {'x'};

    EXPECT(cdisasm_x86_format(instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
    output[0] = 'x';
    EXPECT(cdisasm_x86_format(instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
}

static void mutate_memory_layout(const cdisasm_instruction *instruction)
{
    cdisasm_instruction forged;
    size_t index;

    EXPECT((instruction->encoding.modrm & UINT8_C(0xc7)) == 0u);
    forged = *instruction;
    forged.encoding.modrm |= UINT8_C(4);
    expect_format_rejected(&forged);
    forged = *instruction;
    forged.encoding.modrm |= UINT8_C(0x40);
    expect_format_rejected(&forged);
    forged = *instruction;
    forged.encoding.sib_offset = forged.encoding.modrm_offset + 1u;
    forged.encoding.sib = UINT8_C(0x24);
    for (index = 0u; index < forged.encoding.immediate_count; ++index) {
        ++forged.encoding.immediate_offset[index];
    }
    ++forged.opcode_size;
    expect_format_rejected(&forged);
    forged = *instruction;
    forged.encoding.displacement_offset = forged.encoding.modrm_offset + 1u;
    forged.encoding.displacement_size = 1u;
    for (index = 0u; index < forged.encoding.immediate_count; ++index) {
        ++forged.encoding.immediate_offset[index];
    }
    ++forged.opcode_size;
    expect_format_rejected(&forged);
}

static void test_formatting_and_evex_boundaries(void)
{
    static const struct format_case {
        uint8_t code[8];
        size_t size;
        const char *intel;
        const char *att;
    } classic[] = {
        {{0xc4,0xe3,0x79,0x05,0x00,0x1b},6u,
            "vpermilpd xmm0, xmmword ptr [rax], 0x1b",
            "vpermilpd $0x1b, (%rax), %xmm0"},
        {{0xc4,0xe2,0x75,0x0c,0xc2},5u,
            "vpermilps ymm0, ymm1, ymm2",
            "vpermilps %ymm2, %ymm1, %ymm0"}};
    static const struct evex_case {
        uint8_t code[7];
        size_t size;
        uint16_t form;
    } evex[] = {
        {{0x62,0xf3,0xfd,0x09,0x05,0x00,0x1b},7u,6838},
        {{0x62,0xf3,0xfd,0x09,0x05,0xc1,0x1b},7u,6839},
        {{0x62,0xf2,0xf5,0x09,0x0d,0x00},6u,6840},
        {{0x62,0xf2,0xf5,0x09,0x0d,0xc2},6u,6841},
        {{0x62,0xf3,0xfd,0x29,0x05,0x00,0x1b},7u,6842},
        {{0x62,0xf3,0xfd,0x29,0x05,0xc1,0x1b},7u,6843},
        {{0x62,0xf2,0xf5,0x29,0x0d,0x00},6u,6844},
        {{0x62,0xf2,0xf5,0x29,0x0d,0xc2},6u,6845},
        {{0x62,0xf3,0xfd,0x49,0x05,0x00,0x1b},7u,6850},
        {{0x62,0xf3,0xfd,0x49,0x05,0xc1,0x1b},7u,6851},
        {{0x62,0xf2,0xf5,0x49,0x0d,0x00},6u,6852},
        {{0x62,0xf2,0xf5,0x49,0x0d,0xc2},6u,6853},
        {{0x62,0xf3,0x7d,0x09,0x04,0x00,0x1b},7u,6858},
        {{0x62,0xf3,0x7d,0x09,0x04,0xc1,0x1b},7u,6859},
        {{0x62,0xf2,0x75,0x09,0x0c,0x00},6u,6860},
        {{0x62,0xf2,0x75,0x09,0x0c,0xc2},6u,6861},
        {{0x62,0xf3,0x7d,0x29,0x04,0x00,0x1b},7u,6862},
        {{0x62,0xf3,0x7d,0x29,0x04,0xc1,0x1b},7u,6863},
        {{0x62,0xf2,0x75,0x29,0x0c,0x00},6u,6864},
        {{0x62,0xf2,0x75,0x29,0x0c,0xc2},6u,6865},
        {{0x62,0xf3,0x7d,0x49,0x04,0x00,0x1b},7u,6870},
        {{0x62,0xf3,0x7d,0x49,0x04,0xc1,0x1b},7u,6871},
        {{0x62,0xf2,0x75,0x49,0x0c,0x00},6u,6872},
        {{0x62,0xf2,0x75,0x49,0x0c,0xc2},6u,6873}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(classic) / sizeof(classic[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            classic[index].code, classic[index].size, &flags, &decoded_size);

        EXPECT(decoded_size == classic[index].size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(classic[index].intel));
        EXPECT(strcmp(output, classic[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(classic[index].att));
        EXPECT(strcmp(output, classic[index].att) == 0);

        {
            const size_t rm_index = instruction.form_id == UINT16_C(6836)
                    || instruction.form_id == UINT16_C(6837)
                    || instruction.form_id == UINT16_C(6848)
                    || instruction.form_id == UINT16_C(6849)
                    || instruction.form_id == UINT16_C(6856)
                    || instruction.form_id == UINT16_C(6857)
                    || instruction.form_id == UINT16_C(6868)
                    || instruction.form_id == UINT16_C(6869)
                ? 2u : 1u;
            cdisasm_instruction forged = instruction;

            forged.name_id = instruction.name_id == CDISASM_X86_NAME_VPERMILPD
                ? CDISASM_X86_NAME_VPERMILPS
                : CDISASM_X86_NAME_VPERMILPD;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.encoding.prefix_size = 0u;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.branch_target = UINT64_C(0x1234);
            expect_format_rejected(&forged);
            forged = instruction;
            ++forged.opcode[0].reg;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.encoding.modrm ^= UINT8_C(8);
            expect_format_rejected(&forged);
            if (instruction.opcode[rm_index].type == CDISASM_OPERAND_MEMORY) {
                mutate_memory_layout(&instruction);
                forged = instruction;
                forged.opcode[rm_index].base_reg = CDISASM_X86_REG_R16;
                expect_format_rejected(&forged);
            } else {
                forged = instruction;
                ++forged.opcode[rm_index].reg;
                expect_format_rejected(&forged);
                forged = instruction;
                forged.encoding.modrm ^= UINT8_C(1);
                expect_format_rejected(&forged);
            }
        }
    }

    for (index = 0u; index < sizeof(evex) / sizeof(evex[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            evex[index].code, evex[index].size, &flags, &decoded_size);
        cdisasm_instruction forged;
        const int variable = instruction.form_id == UINT16_C(6840)
            || instruction.form_id == UINT16_C(6841)
            || instruction.form_id == UINT16_C(6844)
            || instruction.form_id == UINT16_C(6845)
            || instruction.form_id == UINT16_C(6852)
            || instruction.form_id == UINT16_C(6853)
            || instruction.form_id == UINT16_C(6860)
            || instruction.form_id == UINT16_C(6861)
            || instruction.form_id == UINT16_C(6864)
            || instruction.form_id == UINT16_C(6865)
            || instruction.form_id == UINT16_C(6872)
            || instruction.form_id == UINT16_C(6873);
        const size_t rm_index = variable ? 2u : 1u;

        EXPECT(decoded_size == evex[index].size);
        EXPECT(instruction.form_id == evex[index].form);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) != 0u);

        forged = instruction;
        forged.opcode_flags &=
            ~CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.operand_count = 1u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.prefix_size = 0u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.branch_target = UINT64_C(1);
        expect_format_rejected(&forged);
        forged = instruction;
        ++forged.opcode[0].reg;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.modrm ^= UINT8_C(8);
        expect_format_rejected(&forged);
        if (instruction.opcode[rm_index].type == CDISASM_OPERAND_MEMORY) {
            mutate_memory_layout(&instruction);
        } else {
            forged = instruction;
            ++forged.opcode[rm_index].reg;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.encoding.modrm ^= UINT8_C(1);
            expect_format_rejected(&forged);
        }
    }

    {
        static const uint8_t broadcast[] = {
            0x62,0xf3,0xfd,0x59,0x05,0x00,0x1b};
        static const uint8_t egpr[] = {
            0x62,0xfb,0xfd,0x09,0x05,0x00,0x1b};
        const uint8_t *codes[2] = {broadcast, egpr};
        const size_t sizes[2] = {sizeof(broadcast), sizeof(egpr)};

        for (index = 0u; index < 2u; ++index) {
            char output[192];
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                codes[index], sizes[index], &flags, &decoded_size);

            EXPECT(decoded_size == sizes[index]);
            EXPECT(cdisasm_x86_format(&instruction,
                CDISASM_FORMAT_SYNTAX_INTEL,
                output, sizeof(output)) != 0u);
        }
    }
}
#else
static void test_formatting_and_evex_boundaries(void)
{
}
#endif

int main(void)
{
    test_control_partition();
    test_exact_forms_modes_and_gates();
    test_reserved_truncation_and_collisions();
    test_formatting_and_evex_boundaries();

    if (failures != 0) {
        fprintf(stderr, "%d VPERMILPD/VPERMILPS test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
