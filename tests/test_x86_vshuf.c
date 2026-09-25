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

_Static_assert(CDISASM_X86_NAME_VSHUFPD == UINT16_C(2001)
        && CDISASM_X86_NAME_VSHUFPS == UINT16_C(2002),
    "VSHUF name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VSHUF AVX IDs changed");

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
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86, mode, code, size, UINT64_C(0x1000),
        flags, &instruction);
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
        mode, code, size, flags, &decoded_size);

    if (decoded_size != 0u || !is_error_only(&instruction, status)) {
        fprintf(stderr, "%s: got size/status %u/%u, expected 0/%u\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id, (unsigned int)status);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags all_flags(cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, mode, &flags) == CDISASM_STATUS_OK);
    return flags;
}

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

static cdisasm_x86_form_id expected_form(
    int is_double,
    unsigned int vector_bits,
    int register_form)
{
    return (cdisasm_x86_form_id)(
        (is_double ? UINT16_C(8664) : UINT16_C(8674))
        + (vector_bits == 256u ? 6u : 0u)
        + (register_form ? 1u : 0u));
}

static void check_shuf(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    int is_double,
    unsigned int vector_bits,
    int register_form)
{
    const unsigned int vector_bytes = vector_bits / 8u;
    const cdisasm_x86_reg_id register_base = vector_bits == 256u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    size_t index;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (is_double
        ? CDISASM_X86_NAME_VSHUFPD : CDISASM_X86_NAME_VSHUFPS));
    EXPECT(instruction->form_id == expected_form(
        is_double, vector_bits, register_form));
    EXPECT(instruction->operand_count == 4u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
        == CDISASM_PREFIX_VEX);
    EXPECT(instruction->encoding.prefix_size >= 2u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 1u);
    EXPECT(instruction->encoding.immediate_size[0] == 1u);
    EXPECT(instruction->encoding.immediate_offset[0]
        == instruction->opcode_size - 1u);
    EXPECT(instruction->encoding.selector_offset == 0u);

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = !register_form && index == 2u;

        EXPECT(operand->type == (memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(operand->size == vector_bytes);
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
    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[3].size == 1u);
    EXPECT(instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[3].flags == 0u);
    EXPECT(instruction->opcode[3].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[3].imm <= UINT8_MAX);
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->branch_target == 0u);
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
    static const uint64_t expected_counts[8] = {
        73728, 24576, 73728, 24576,
        73728, 24576, 73728, 24576};
    uint64_t form_counts[8] = {0u};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        const unsigned int p0_count = long_mode ? 8u : 2u;
        unsigned int p0_index;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

        for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
            const uint8_t p0 = long_mode
                ? (uint8_t)((p0_index << 5) | 1u)
                : (uint8_t)(0xc1u | (p0_index << 5));
            unsigned int p1;

            for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                const uint8_t pp = (uint8_t)p1 & UINT8_C(3);
                const int valid = pp == UINT8_C(0)
                    || pp == UINT8_C(1);
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const uint8_t code[15] = {
                        0xc4, p0, (uint8_t)p1, 0xc6, (uint8_t)modrm,
                        0x24, 0x10, 0x20, 0x30, 0x40,
                        0x50, 0x60, 0x70, 0x80, 0x90};
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                        &flags,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (valid) {
#if USE_EXTRA_OPCODES
                        const int is_double = pp == UINT8_C(1);
                        const unsigned int vector_bits =
                            (p1 & UINT8_C(4)) != 0u ? 256u : 128u;
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                        const cdisasm_x86_form_id form = expected_form(
                            is_double, vector_bits, register_form);
                        unsigned int form_slot;

                        check_shuf(&instruction, decoded_size,
                            modes[mode_index], is_double,
                            vector_bits, register_form);
                        form_slot = (is_double ? 0u : 4u)
                            + (vector_bits == 256u ? 2u : 0u)
                            + (register_form ? 1u : 0u);
                        EXPECT(form == (cdisasm_x86_form_id)(
                            (is_double ? UINT16_C(8664) : UINT16_C(8674))
                            + (vector_bits == 256u ? 6u : 0u)
                            + (register_form ? 1u : 0u)));
                        ++form_counts[form_slot];
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
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
    EXPECT(allocated == UINT64_C(393216));
    EXPECT(reserved == UINT64_C(393216));
#if USE_EXTRA_OPCODES
    for (mode_index = 0u; mode_index < 8u; ++mode_index) {
        EXPECT(form_counts[mode_index] == expected_counts[mode_index]);
    }
#else
    (void)form_counts;
    (void)expected_counts;
#endif
}

static void test_exact_forms_gates_and_immediates(void)
{
    static const struct exact_case {
        uint8_t code[6];
        uint16_t form;
    } cases[] = {
        {{0xc4,0xe1,0x71,0xc6,0x00,0x1b},8664},
        {{0xc4,0xe1,0x71,0xc6,0xc2,0x1b},8665},
        {{0xc4,0xe1,0x75,0xc6,0x00,0x1b},8670},
        {{0xc4,0xe1,0x75,0xc6,0xc2,0x1b},8671},
        {{0xc4,0xe1,0x70,0xc6,0x00,0x1b},8674},
        {{0xc4,0xe1,0x70,0xc6,0xc2,0x1b},8675},
        {{0xc4,0xe1,0x74,0xc6,0x00,0x1b},8680},
        {{0xc4,0xe1,0x74,0xc6,0xc2,0x1b},8681}};
    size_t index;

#if USE_EXTRA_OPCODES
    const cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    const cdisasm_x86_decode_flags none = selected_flags(0, 0);
    const cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    const cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, cases[index].code,
            sizeof(cases[index].code), &flags, &decoded_size);
        unsigned int immediate;

        EXPECT(decoded_size == sizeof(cases[index].code));
        EXPECT(instruction.form_id == cases[index].form);
        for (immediate = 0u; immediate <= UINT8_MAX; ++immediate) {
            uint8_t code[6];

            memcpy(code, cases[index].code, sizeof(code));
            code[5] = (uint8_t)immediate;
            instruction = decode(CDISASM_MODE_64, code, sizeof(code),
                &flags, &decoded_size);
            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.form_id == cases[index].form);
            EXPECT(instruction.opcode[3].imm == immediate);
        }
    }
    expect_error("VSHUF needs AVX", CDISASM_MODE_64,
        cases[0].code, sizeof(cases[0].code), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX2 alone does not admit VSHUF", CDISASM_MODE_64,
        cases[7].code, sizeof(cases[7].code), &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, cases[7].code, sizeof(cases[7].code),
            &avx, &decoded_size);

        EXPECT(decoded_size == sizeof(cases[7].code));
        EXPECT(instruction.form_id == UINT16_C(8681));
    }
#else
    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error("VSHUF extras off", CDISASM_MODE_64,
            cases[index].code, sizeof(cases[index].code), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif
}

static void test_aliases_truncation_and_collisions(void)
{
    static const uint8_t vex2[] = {0xc5,0xf1,0xc6,0xc1,0x7f};
    static const uint8_t vex3[] = {0xc4,0xe1,0xf0,0xc6,0xc1,0x7f};
    size_t size;

    for (size = 1u; size < sizeof(vex2); ++size) {
        expect_error("truncated C5 VSHUF", CDISASM_MODE_64,
            vex2, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    for (size = 1u; size < sizeof(vex3); ++size) {
        expect_error("truncated C4 VSHUF", CDISASM_MODE_64,
            vex3, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    expect_error("reserved pp missing SIB", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x72,0xc6,0x04}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp missing immediate", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x72,0xc6,0x04,0x24}, 6u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp complete", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x72,0xc6,0x04,0x24,0x7f}, 7u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy prefix missing immediate", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc5,0xf1,0xc6,0xc1}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("legacy prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc5,0xf1,0xc6,0xc1,0x7f}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("LOCK prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0xf0,0xc4,0xe1,0x70,0xc6,0xc1,0x7f}, 7u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        static const cdisasm_x86_mode modes[3] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
        size_t index;

        for (index = 0u; index < 3u; ++index) {
            static const uint8_t c5_pd[] = {0xc5,0xf1,0xc6,0xc1,0x7f};
            static const uint8_t c5_ps[] = {0xc5,0xf0,0xc6,0xc1,0x7f};
            cdisasm_x86_decode_flags flags = all_flags(modes[index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                modes[index], c5_pd, sizeof(c5_pd), &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(c5_pd));
            EXPECT(instruction.form_id == UINT16_C(8665));
            instruction = decode(modes[index], c5_ps, sizeof(c5_ps),
                &flags, &decoded_size);
            EXPECT(decoded_size == sizeof(c5_ps));
            EXPECT(instruction.form_id == UINT16_C(8675));
        }
    }
    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        static const uint8_t nonlong_alias[] = {
            0xc4,0xc1,0xb1,0xc6,0xc1,0xa5};
        size_t index;

        for (index = 0u; index < 2u; ++index) {
            cdisasm_x86_decode_flags flags = all_flags(modes[index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                modes[index], nonlong_alias, sizeof(nonlong_alias),
                &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(nonlong_alias));
            EXPECT(instruction.form_id == UINT16_C(8665));
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
            EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM1);
        }
    }
    {
        static const uint8_t wig[] = {
            0xc4,0xe1,0xf5,0xc6,0x44,0x88,0x10,0xff};
        static const uint8_t address_segment[] = {
            0x64,0x67,0xc4,0xe1,0xfc,0xc6,0x04,0x24,0xa5};
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, wig, sizeof(wig), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(wig));
        EXPECT(instruction.form_id == UINT16_C(8670));
        EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
        instruction = decode(CDISASM_MODE_64, address_segment,
            sizeof(address_segment), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(address_segment));
        EXPECT(instruction.form_id == UINT16_C(8680));
        EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_FS);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_ESP);
    }
    {
        static const uint8_t les_collision[] = {
            0xc4,0x61,0x71,0xc6,0xc1,0x1b};
        static const uint8_t legacy_pd[] = {0x66,0x0f,0xc6,0xc1,0x1b};
        static const uint8_t legacy_ps[] = {0x0f,0xc6,0xc1,0x1b};
        cdisasm_x86_decode_flags flags16 = all_flags(CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_16, les_collision, sizeof(les_collision),
            &flags16, &decoded_size);

        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_MODE_64, legacy_pd,
            sizeof(legacy_pd), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_pd));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_SHUFPD);
        instruction = decode(CDISASM_MODE_64, legacy_ps,
            sizeof(legacy_ps), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_ps));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_SHUFPS);
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

static void test_formatting_and_schema(void)
{
    static const struct format_case {
        uint8_t code[8];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc5,0xf1,0xc6,0x00,0x1b},5u,
            "vshufpd xmm0, xmm1, xmmword ptr [rax], 0x1b",
            "vshufpd $0x1b, (%rax), %xmm1, %xmm0"},
        {{0xc4,0xe1,0xfd,0xc6,0xc2,0xa5},6u,
            "vshufpd ymm0, ymm0, ymm2, 0xa5",
            "vshufpd $0xa5, %ymm2, %ymm0, %ymm0"},
        {{0xc5,0xf0,0xc6,0xc2,0x7f},5u,
            "vshufps xmm0, xmm1, xmm2, 0x7f",
            "vshufps $0x7f, %xmm2, %xmm1, %xmm0"},
        {{0xc4,0xe1,0xf4,0xc6,0x00,0xff},6u,
            "vshufps ymm0, ymm1, ymmword ptr [rax], 0xff",
            "vshufps $0xff, (%rax), %ymm1, %ymm0"}};
    static const struct evex_case {
        uint8_t code[7];
        uint16_t form;
        uint16_t name;
    } evex_cases[] = {
        {{0x62,0xf1,0xed,0x09,0xc6,0xc1,0x7f},8667,2001},
        {{0x62,0xf1,0x6c,0x19,0xc6,0x00,0x7f},8676,2002},
        {{0x62,0xf1,0xed,0x29,0xc6,0xc1,0x7f},8669,2001},
        {{0x62,0xf1,0x6c,0x49,0xc6,0xc1,0x7f},8683,2002}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, cases[index].code, cases[index].size,
            &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == cases[index].size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);

        forged = instruction;
        forged.name_id = instruction.name_id == CDISASM_X86_NAME_VSHUFPD
            ? CDISASM_X86_NAME_VSHUFPS : CDISASM_X86_NAME_VSHUFPD;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.form_id = (cdisasm_x86_form_id)(instruction.form_id + 1u);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.operand_count = 3u;
        expect_format_rejected(&forged);
        forged = instruction;
        ++forged.opcode[0].reg;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.modrm ^= UINT8_C(8);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[2].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[3].size = 2u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.immediate_count = 0u;
        expect_format_rejected(&forged);
    }

    for (index = 0u;
         index < sizeof(evex_cases) / sizeof(evex_cases[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, evex_cases[index].code,
            sizeof(evex_cases[index].code), &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(evex_cases[index].code));
        EXPECT(instruction.name_id == evex_cases[index].name);
        EXPECT(instruction.form_id == evex_cases[index].form);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) != 0u);
        forged = instruction;
        forged.opcode_flags &=
            ~CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.form_id = evex_cases[index].name == 2001u
            ? UINT16_C(8677) : UINT16_C(8667);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[3].size = 2u;
        expect_format_rejected(&forged);
    }
}
#else
static void test_formatting_and_schema(void)
{
}
#endif

int main(void)
{
    test_control_partition();
    test_exact_forms_gates_and_immediates();
    test_aliases_truncation_and_collisions();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VSHUF test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
