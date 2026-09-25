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

_Static_assert(CDISASM_X86_NAME_VTESTPD == UINT16_C(2009)
        && CDISASM_X86_NAME_VTESTPS == UINT16_C(2010),
    "VTEST name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VTEST AVX IDs changed");

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
        (is_double ? UINT16_C(8795) : UINT16_C(8799))
        + (vector_bits == 256u ? 2u : 0u)
        + (register_form ? 1u : 0u));
}

static void check_vtest(
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
        ? CDISASM_X86_NAME_VTESTPD : CDISASM_X86_NAME_VTESTPS));
    EXPECT(instruction->form_id == expected_form(
        is_double, vector_bits, register_form));
    EXPECT(instruction->operand_count == 2u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
        == CDISASM_PREFIX_VEX);
    EXPECT(instruction->encoding.prefix_size >= 3u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset == 0u);

    for (index = 0u; index < 2u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = !register_form && index == 1u;

        EXPECT(operand->type == (memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(operand->size == vector_bytes);
        EXPECT(operand->access == CDISASM_OPERAND_ACCESS_READ);
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
        2304, 768, 2304, 768, 2304, 768, 2304, 768};
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
                ? (uint8_t)((p0_index << 5) | 2u)
                : (uint8_t)(0xc2u | (p0_index << 5));
            unsigned int opcode;

            for (opcode = UINT8_C(0x0e); opcode <= UINT8_C(0x0f);
                 ++opcode) {
                unsigned int p1;

                for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                    const int valid = p1 == UINT8_C(0x79)
                        || p1 == UINT8_C(0x7d);
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const uint8_t code[15] = {
                            0xc4, p0, (uint8_t)p1, (uint8_t)opcode,
                            (uint8_t)modrm, 0x24, 0x10, 0x20, 0x30, 0x40,
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
                            const int is_double = opcode == UINT8_C(0x0f);
                            const unsigned int vector_bits =
                                (p1 & UINT8_C(4)) != 0u ? 256u : 128u;
                            const int register_form =
                                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                            const unsigned int form_slot =
                                (is_double ? 0u : 4u)
                                + (vector_bits == 256u ? 2u : 0u)
                                + (register_form ? 1u : 0u);

                            check_vtest(&instruction, decoded_size,
                                modes[mode_index], is_double,
                                vector_bits, register_form);
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
    }
    EXPECT(allocated == UINT64_C(12288));
    EXPECT(reserved == UINT64_C(1560576));
#if USE_EXTRA_OPCODES
    for (mode_index = 0u; mode_index < 8u; ++mode_index) {
        EXPECT(form_counts[mode_index] == expected_counts[mode_index]);
    }
#else
    (void)form_counts;
    (void)expected_counts;
#endif
}

static void test_exact_forms_and_gates(void)
{
    static const struct exact_case {
        uint8_t code[5];
        uint16_t form;
    } cases[] = {
        {{0xc4,0xe2,0x79,0x0f,0x00},8795},
        {{0xc4,0xe2,0x79,0x0f,0xc2},8796},
        {{0xc4,0xe2,0x7d,0x0f,0x00},8797},
        {{0xc4,0xe2,0x7d,0x0f,0xc2},8798},
        {{0xc4,0xe2,0x79,0x0e,0x00},8799},
        {{0xc4,0xe2,0x79,0x0e,0xc2},8800},
        {{0xc4,0xe2,0x7d,0x0e,0x00},8801},
        {{0xc4,0xe2,0x7d,0x0e,0xc2},8802}};
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

        EXPECT(decoded_size == sizeof(cases[index].code));
        EXPECT(instruction.form_id == cases[index].form);
    }
    expect_error("VTEST needs AVX", CDISASM_MODE_64,
        cases[0].code, sizeof(cases[0].code), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX2 alone does not admit VTEST", CDISASM_MODE_64,
        cases[7].code, sizeof(cases[7].code), &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, cases[7].code, sizeof(cases[7].code),
            &avx, &decoded_size);

        EXPECT(decoded_size == sizeof(cases[7].code));
        EXPECT(instruction.form_id == UINT16_C(8802));
    }
#else
    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error("VTEST extras off", CDISASM_MODE_64,
            cases[index].code, sizeof(cases[index].code), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif
}

static void test_controls_aliases_and_truncation(void)
{
    static const uint8_t valid[] = {0xc4,0xe2,0x79,0x0f,0xc1};
    size_t size;

    for (size = 1u; size < sizeof(valid); ++size) {
        expect_error("truncated C4 VTEST", CDISASM_MODE_64,
            valid, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    expect_error("reserved pp missing SIB", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x78,0x0e,0x04}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp complete", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x78,0x0e,0x04,0x24}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved W missing disp8", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0xf9,0x0f,0x45}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("reserved W complete", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0xf9,0x0f,0x45,0x10}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved vvvv complete", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x71,0x0f,0xc1}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy prefix missing SIB", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc4,0xe2,0x79,0x0f,0x04}, 6u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("legacy prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc4,0xe2,0x79,0x0f,0x04,0x24}, 7u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("LOCK prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0xf0,0xc4,0xe2,0x79,0x0e,0xc1}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        static const cdisasm_x86_mode modes[3] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
        size_t index;

        for (index = 0u; index < 3u; ++index) {
            cdisasm_x86_decode_flags flags = all_flags(modes[index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                modes[index], valid, sizeof(valid), &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(valid));
            EXPECT(instruction.form_id == UINT16_C(8796));
        }
    }
    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        static const uint8_t nonlong_b_alias[] = {
            0xc4,0xc2,0x79,0x0f,0xc1};
        size_t index;

        for (index = 0u; index < 2u; ++index) {
            cdisasm_x86_decode_flags flags = all_flags(modes[index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                modes[index], nonlong_b_alias,
                sizeof(nonlong_b_alias), &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(nonlong_b_alias));
            EXPECT(instruction.form_id == UINT16_C(8796));
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
        }
    }
    {
        static const uint8_t high_sib[] = {
            0xc4,0x22,0x7d,0x0e,0x4c,0x88,0x10};
        static const uint8_t address_segment[] = {
            0x64,0x67,0xc4,0xe2,0x79,0x0f,0x04,0x24};
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, high_sib, sizeof(high_sib),
            &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(high_sib));
        EXPECT(instruction.form_id == UINT16_C(8801));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM9);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        instruction = decode(CDISASM_MODE_64, address_segment,
            sizeof(address_segment), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(address_segment));
        EXPECT(instruction.form_id == UINT16_C(8795));
        EXPECT(instruction.opcode[1].segment_reg == CDISASM_X86_REG_FS);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_ESP);
    }
    {
        static const uint8_t les_collision[] = {
            0xc4,0x62,0x79,0x0f,0xc1};
        static const uint8_t vptest_sibling[] = {
            0xc4,0xe2,0x79,0x17,0xc1};
        cdisasm_x86_decode_flags flags16 = all_flags(CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_16, les_collision, sizeof(les_collision),
            &flags16, &decoded_size);

        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_MODE_64, vptest_sibling,
            sizeof(vptest_sibling), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(vptest_sibling));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPTEST);
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
        uint8_t code[7];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4,0xe2,0x79,0x0f,0xc1},5u,
            "vtestpd xmm0, xmm1", "vtestpd %xmm1, %xmm0"},
        {{0xc4,0xe2,0x7d,0x0f,0x00},5u,
            "vtestpd ymm0, ymmword ptr [rax]", "vtestpd (%rax), %ymm0"},
        {{0xc4,0xe2,0x79,0x0e,0x00},5u,
            "vtestps xmm0, xmmword ptr [rax]", "vtestps (%rax), %xmm0"},
        {{0xc4,0x42,0x7d,0x0e,0xcb},5u,
            "vtestps ymm9, ymm11", "vtestps %ymm11, %ymm9"}};
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
        forged.name_id = instruction.name_id == CDISASM_X86_NAME_VTESTPD
            ? CDISASM_X86_NAME_VTESTPS : CDISASM_X86_NAME_VTESTPD;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags &=
            ~CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.form_id = (cdisasm_x86_form_id)(instruction.form_id ^ 1u);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.operand_count = 1u;
        expect_format_rejected(&forged);
        forged = instruction;
        ++forged.opcode[0].reg;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.modrm ^= UINT8_C(8);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.immediate_count = 1u;
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
    test_exact_forms_and_gates();
    test_controls_aliases_and_truncation();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VTEST test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
