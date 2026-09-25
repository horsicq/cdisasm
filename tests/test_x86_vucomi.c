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

_Static_assert(CDISASM_X86_NAME_VUCOMISD == UINT16_C(2011)
        && CDISASM_X86_NAME_VUCOMISH == UINT16_C(2012)
        && CDISASM_X86_NAME_VUCOMISS == UINT16_C(2013)
        && CDISASM_X86_NAME_VCOMISD == UINT16_C(1502)
        && CDISASM_X86_NAME_VCOMISS == UINT16_C(1504),
    "VCOMI name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VUCOMI AVX IDs changed");

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
    int ordered, int is_double, int register_form)
{
    return (cdisasm_x86_form_id)(
        (ordered
            ? (is_double ? UINT16_C(3629) : UINT16_C(3633))
            : (is_double ? UINT16_C(8803) : UINT16_C(8809)))
        + (register_form ? 1u : 0u));
}

static void check_vcomi(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    int ordered,
    int is_double,
    int register_form)
{
    const unsigned int scalar_bytes = is_double ? 8u : 4u;
    size_t index;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (ordered
        ? (is_double ? CDISASM_X86_NAME_VCOMISD
            : CDISASM_X86_NAME_VCOMISS)
        : (is_double ? CDISASM_X86_NAME_VUCOMISD
            : CDISASM_X86_NAME_VUCOMISS)));
    EXPECT(instruction->form_id == expected_form(
        ordered, is_double, register_form));
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
    EXPECT(instruction->encoding.prefix_size >= 2u);
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
        EXPECT(operand->size == (index == 0u ? 16u : scalar_bytes));
        EXPECT(operand->access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(operand->broadcast == CDISASM_X86_BROADCAST_NONE);
        if (memory) {
            EXPECT((operand->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
        } else {
            EXPECT(operand->reg >= CDISASM_X86_REG_XMM0
                && operand->reg <= CDISASM_X86_REG_XMM15);
            EXPECT(operand->flags == 0u);
            if (mode != CDISASM_MODE_64) {
                EXPECT(operand->reg <= CDISASM_X86_REG_XMM7);
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
    static const uint64_t expected_counts[4] = {
        9216, 3072, 9216, 3072};
    uint64_t form_counts[4] = {0u};
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
                const int valid = ((uint8_t)p1 & UINT8_C(0x78))
                        == UINT8_C(0x78)
                    && (pp == UINT8_C(0) || pp == UINT8_C(1));
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const uint8_t code[15] = {
                        0xc4, p0, (uint8_t)p1, 0x2e, (uint8_t)modrm,
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
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                        const unsigned int form_slot =
                            (is_double ? 0u : 2u)
                            + (register_form ? 1u : 0u);

                        check_vcomi(&instruction, decoded_size,
                            modes[mode_index], 0, is_double, register_form);
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
    EXPECT(allocated == UINT64_C(24576));
    EXPECT(reserved == UINT64_C(761856));
#if USE_EXTRA_OPCODES
    for (mode_index = 0u; mode_index < 4u; ++mode_index) {
        EXPECT(form_counts[mode_index] == expected_counts[mode_index]);
    }
#else
    (void)form_counts;
    (void)expected_counts;
#endif
}

static void test_vcomis_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const uint64_t expected_counts[4] = {
        9216, 3072, 9216, 3072};
    uint64_t form_counts[4] = {0u};
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
                const int valid = ((uint8_t)p1 & UINT8_C(0x78))
                        == UINT8_C(0x78)
                    && (pp == UINT8_C(0) || pp == UINT8_C(1));
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const uint8_t code[15] = {
                        0xc4, p0, (uint8_t)p1, 0x2f, (uint8_t)modrm,
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
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                        const unsigned int form_slot =
                            (is_double ? 0u : 2u)
                            + (register_form ? 1u : 0u);

                        check_vcomi(&instruction, decoded_size,
                            modes[mode_index], 1, is_double, register_form);
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
    EXPECT(allocated == UINT64_C(24576));
    EXPECT(reserved == UINT64_C(761856));
#if USE_EXTRA_OPCODES
    for (mode_index = 0u; mode_index < 4u; ++mode_index) {
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
        uint8_t code[4];
        uint16_t form;
    } cases[] = {
        {{0xc5,0xf9,0x2e,0x00},8803},
        {{0xc5,0xf9,0x2e,0xc1},8804},
        {{0xc5,0xf8,0x2e,0x00},8809},
        {{0xc5,0xf8,0x2e,0xc1},8810},
        {{0xc5,0xf9,0x2f,0x00},3629},
        {{0xc5,0xf9,0x2f,0xc1},3630},
        {{0xc5,0xf8,0x2f,0x00},3633},
        {{0xc5,0xf8,0x2f,0xc1},3634}};
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
        const int ordered = cases[index].code[2] == UINT8_C(0x2f);
        const int is_double =
            (cases[index].code[1] & UINT8_C(3)) == UINT8_C(1);
        const int register_form =
            (cases[index].code[3] & UINT8_C(0xc0)) == UINT8_C(0xc0);

        EXPECT(decoded_size == sizeof(cases[index].code));
        EXPECT(instruction.form_id == cases[index].form);
        check_vcomi(&instruction, decoded_size, CDISASM_MODE_64,
            ordered, is_double, register_form);
    }
    expect_error("VUCOMI needs AVX", CDISASM_MODE_64,
        cases[0].code, sizeof(cases[0].code), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX2 alone does not admit VCOMI", CDISASM_MODE_64,
        cases[7].code, sizeof(cases[7].code), &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, cases[7].code, sizeof(cases[7].code),
            &avx, &decoded_size);

        EXPECT(decoded_size == sizeof(cases[7].code));
        EXPECT(instruction.form_id == UINT16_C(3634));
    }
#else
    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error("VUCOMI extras off", CDISASM_MODE_64,
            cases[index].code, sizeof(cases[index].code), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif
}

static void test_controls_aliases_truncation_and_collisions(void)
{
    static const uint8_t vex2[] = {0xc5,0xf9,0x2e,0xc1};
    static const uint8_t vex3[] = {0xc4,0xe1,0xf8,0x2e,0xc1};
    static const uint8_t vcomis_vex2[] = {0xc5,0xf9,0x2f,0xc1};
    static const uint8_t vcomis_vex3[] = {0xc4,0xe1,0xf8,0x2f,0xc1};
    size_t size;

    for (size = 1u; size < sizeof(vex2); ++size) {
        expect_error("truncated C5 VUCOMI", CDISASM_MODE_64,
            vex2, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    for (size = 1u; size < sizeof(vex3); ++size) {
        expect_error("truncated C4 VUCOMI", CDISASM_MODE_64,
            vex3, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    for (size = 1u; size < sizeof(vcomis_vex2); ++size) {
        expect_error("truncated C5 VCOMIS", CDISASM_MODE_64,
            vcomis_vex2, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    for (size = 1u; size < sizeof(vcomis_vex3); ++size) {
        expect_error("truncated C4 VCOMIS", CDISASM_MODE_64,
            vcomis_vex3, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    expect_error("VCOMIS reserved pp missing SIB", CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xfa,0x2f,0x04}, 4u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("VCOMIS reserved pp complete", CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xfa,0x2f,0x04,0x24}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VCOMIS reserved vvvv missing disp8", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x71,0x2f,0x45}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("VCOMIS reserved vvvv complete", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x71,0x2f,0x45,0x10}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VCOMIS legacy prefix missing SIB", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc5,0xf9,0x2f,0x04}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("VCOMIS legacy prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc5,0xf9,0x2f,0x04,0x24}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved pp missing SIB", CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xfa,0x2e,0x04}, 4u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp complete", CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xfa,0x2e,0x04,0x24}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved vvvv missing disp8", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x71,0x2e,0x45}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("reserved vvvv complete", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x71,0x2e,0x45,0x10}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("legacy prefix missing SIB", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc5,0xf9,0x2e,0x04}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("legacy prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc5,0xf9,0x2e,0x04,0x24}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("LOCK prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0xf0,0xc5,0xf8,0x2e,0xc1}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("REX prefix complete", CDISASM_MODE_64,
        (const uint8_t[]){0x48,0xc5,0xf9,0x2e,0xc1}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        static const cdisasm_x86_mode modes[3] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
        size_t index;

        for (index = 0u; index < 3u; ++index) {
            static const uint8_t c5_sd[] = {0xc5,0xfd,0x2e,0xc1};
            static const uint8_t c5_ss[] = {0xc5,0xfc,0x2e,0xc1};
            static const uint8_t c5_vcomisd[] = {0xc5,0xfd,0x2f,0xc1};
            static const uint8_t c5_vcomiss[] = {0xc5,0xfc,0x2f,0xc1};
            cdisasm_x86_decode_flags flags = all_flags(modes[index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                modes[index], c5_sd, sizeof(c5_sd), &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(c5_sd));
            EXPECT(instruction.form_id == UINT16_C(8804));
            instruction = decode(modes[index], c5_ss, sizeof(c5_ss),
                &flags, &decoded_size);
            EXPECT(decoded_size == sizeof(c5_ss));
            EXPECT(instruction.form_id == UINT16_C(8810));
            instruction = decode(modes[index], c5_vcomisd,
                sizeof(c5_vcomisd), &flags, &decoded_size);
            EXPECT(decoded_size == sizeof(c5_vcomisd));
            EXPECT(instruction.form_id == UINT16_C(3630));
            instruction = decode(modes[index], c5_vcomiss,
                sizeof(c5_vcomiss), &flags, &decoded_size);
            EXPECT(decoded_size == sizeof(c5_vcomiss));
            EXPECT(instruction.form_id == UINT16_C(3634));
        }
    }
    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        static const uint8_t nonlong_b_alias[] = {
            0xc4,0xc1,0xfd,0x2e,0xc1};
        static const uint8_t vcomis_nonlong_b_alias[] = {
            0xc4,0xc1,0xfd,0x2f,0xc1};
        size_t index;

        for (index = 0u; index < 2u; ++index) {
            cdisasm_x86_decode_flags flags = all_flags(modes[index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                modes[index], nonlong_b_alias,
                sizeof(nonlong_b_alias), &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(nonlong_b_alias));
            EXPECT(instruction.form_id == UINT16_C(8804));
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
            instruction = decode(modes[index], vcomis_nonlong_b_alias,
                sizeof(vcomis_nonlong_b_alias), &flags, &decoded_size);
            EXPECT(decoded_size == sizeof(vcomis_nonlong_b_alias));
            EXPECT(instruction.form_id == UINT16_C(3630));
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
        }
    }
    {
        static const uint8_t wig_lig_sd[] = {
            0xc4,0xe1,0xfd,0x2e,0xc1};
        static const uint8_t wig_lig_ss[] = {
            0xc4,0xe1,0xfc,0x2e,0xc1};
        static const uint8_t high_sib[] = {
            0xc4,0x01,0x79,0x2e,0x54,0x8b,0x20};
        static const uint8_t address_segment[] = {
            0x64,0x67,0xc5,0xf8,0x2e,0x04,0x24};
        static const uint8_t vcomisd_wig_lig[] = {
            0xc4,0xe1,0xfd,0x2f,0xc1};
        static const uint8_t vcomiss_high_sib[] = {
            0xc4,0x21,0x78,0x2f,0x4c,0x88,0x10};
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, wig_lig_sd, sizeof(wig_lig_sd),
            &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(wig_lig_sd));
        EXPECT(instruction.form_id == UINT16_C(8804));
        instruction = decode(CDISASM_MODE_64, wig_lig_ss,
            sizeof(wig_lig_ss), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(wig_lig_ss));
        EXPECT(instruction.form_id == UINT16_C(8810));
        instruction = decode(CDISASM_MODE_64, high_sib,
            sizeof(high_sib), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(high_sib));
        EXPECT(instruction.form_id == UINT16_C(8803));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM10);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        instruction = decode(CDISASM_MODE_64, address_segment,
            sizeof(address_segment), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(address_segment));
        EXPECT(instruction.form_id == UINT16_C(8809));
        EXPECT(instruction.opcode[1].segment_reg == CDISASM_X86_REG_FS);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_ESP);
        instruction = decode(CDISASM_MODE_64, vcomisd_wig_lig,
            sizeof(vcomisd_wig_lig), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(vcomisd_wig_lig));
        EXPECT(instruction.form_id == UINT16_C(3630));
        instruction = decode(CDISASM_MODE_64, vcomiss_high_sib,
            sizeof(vcomiss_high_sib), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(vcomiss_high_sib));
        EXPECT(instruction.form_id == UINT16_C(3633));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM9);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
    }
    {
        static const uint8_t les_collision[] = {
            0xc4,0x61,0x79,0x2e,0xc1};
        static const uint8_t lds_collision[] = {
            0xc5,0x79,0x2e,0xc1};
        static const uint8_t legacy_sd[] = {0x66,0x0f,0x2e,0xc1};
        static const uint8_t legacy_ss[] = {0x0f,0x2e,0xc1};
        static const uint8_t legacy_comisd[] = {0x66,0x0f,0x2f,0xc1};
        static const uint8_t legacy_comiss[] = {0x0f,0x2f,0xc1};
        static const struct sibling_case {
            uint8_t code[6];
            uint16_t name;
            uint16_t form;
        } siblings[] = {
            {{0x62,0xf1,0xfd,0x08,0x2e,0xc1},2011,8806},
            {{0x62,0xf1,0x7c,0x08,0x2e,0xc1},2013,8812},
            {{0x62,0xf5,0x7c,0x08,0x2e,0xc1},2012,8808},
            {{0x62,0xf1,0xfd,0x08,0x2f,0xc1},1502,3628},
            {{0x62,0xf1,0x7c,0x08,0x2f,0xc1},1504,3636},
            {{0x62,0xf5,0x7c,0x08,0x2f,0xc1},1503,3632}};
        cdisasm_x86_decode_flags flags16 = all_flags(CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_16, les_collision, sizeof(les_collision),
            &flags16, &decoded_size);
        size_t index;

        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_MODE_16, lds_collision,
            sizeof(lds_collision), &flags16, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LDS);
        instruction = decode(CDISASM_MODE_64, legacy_sd,
            sizeof(legacy_sd), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_sd));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_UCOMISD);
        instruction = decode(CDISASM_MODE_64, legacy_ss,
            sizeof(legacy_ss), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_ss));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_UCOMISS);
        instruction = decode(CDISASM_MODE_64, legacy_comisd,
            sizeof(legacy_comisd), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_comisd));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_COMISD);
        instruction = decode(CDISASM_MODE_64, legacy_comiss,
            sizeof(legacy_comiss), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_comiss));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_COMISS);
        for (index = 0u;
             index < sizeof(siblings) / sizeof(siblings[0]); ++index) {
            instruction = decode(CDISASM_MODE_64, siblings[index].code,
                sizeof(siblings[index].code), &flags64, &decoded_size);
            EXPECT(decoded_size == sizeof(siblings[index].code));
            EXPECT(instruction.name_id == siblings[index].name);
            EXPECT(instruction.form_id == siblings[index].form);
            EXPECT((instruction.opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
        }
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
        {{0xc5,0xf9,0x2e,0xc1},4u,
            "vucomisd xmm0, xmm1", "vucomisd %xmm1, %xmm0"},
        {{0xc5,0xf9,0x2e,0x00},4u,
            "vucomisd xmm0, qword ptr [rax]", "vucomisd (%rax), %xmm0"},
        {{0xc5,0xf8,0x2e,0xc1},4u,
            "vucomiss xmm0, xmm1", "vucomiss %xmm1, %xmm0"},
        {{0xc4,0x21,0x78,0x2e,0x4c,0x88,0x10},7u,
            "vucomiss xmm9, dword ptr [rax + r9*4 + 0x10]",
            "vucomiss 0x10(%rax,%r9,4), %xmm9"},
        {{0xc5,0xf9,0x2f,0xc1},4u,
            "vcomisd xmm0, xmm1", "vcomisd %xmm1, %xmm0"},
        {{0xc5,0xf9,0x2f,0x00},4u,
            "vcomisd xmm0, qword ptr [rax]", "vcomisd (%rax), %xmm0"},
        {{0xc5,0xf8,0x2f,0xc1},4u,
            "vcomiss xmm0, xmm1", "vcomiss %xmm1, %xmm0"},
        {{0xc4,0x21,0x78,0x2f,0x4c,0x88,0x10},7u,
            "vcomiss xmm9, dword ptr [rax + r9*4 + 0x10]",
            "vcomiss 0x10(%rax,%r9,4), %xmm9"}};
    static const struct sibling_case {
        uint8_t code[6];
        const char *intel;
        const char *att;
    } siblings[] = {
        {{0x62,0xf1,0xfd,0x08,0x2e,0xc1},
            "vucomisd xmm0, xmm1", "vucomisd %xmm1, %xmm0"},
        {{0x62,0xf1,0x7c,0x08,0x2e,0xc1},
            "vucomiss xmm0, xmm1", "vucomiss %xmm1, %xmm0"},
        {{0x62,0xf5,0x7c,0x08,0x2e,0xc1},
            "vucomish xmm0, xmm1", "vucomish %xmm1, %xmm0"},
        {{0x62,0xf1,0xfd,0x08,0x2f,0xc1},
            "vcomisd xmm0, xmm1", "vcomisd %xmm1, %xmm0"},
        {{0x62,0xf1,0x7c,0x08,0x2f,0xc1},
            "vcomiss xmm0, xmm1", "vcomiss %xmm1, %xmm0"},
        {{0x62,0xf5,0x7c,0x08,0x2f,0xc1},
            "vcomish xmm0, xmm1", "vcomish %xmm1, %xmm0"}};
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
        forged.name_id = instruction.name_id == CDISASM_X86_NAME_VCOMISD
            ? CDISASM_X86_NAME_VUCOMISD : CDISASM_X86_NAME_VCOMISD;
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
        forged.form_id = UINT16_C(0);
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

    for (index = 0u;
         index < sizeof(siblings) / sizeof(siblings[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_MODE_64, siblings[index].code,
            sizeof(siblings[index].code), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(siblings[index].code));
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(siblings[index].intel));
        EXPECT(strcmp(output, siblings[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(siblings[index].att));
        EXPECT(strcmp(output, siblings[index].att) == 0);
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
    test_vcomis_control_partition();
    test_exact_forms_and_gates();
    test_controls_aliases_truncation_and_collisions();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VCOMI test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
