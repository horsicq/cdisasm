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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",          \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VMASKMOVPD == UINT16_C(1753)
        && CDISASM_X86_NAME_VMASKMOVPS == UINT16_C(1754),
    "VMASKMOV name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VMASKMOV AVX IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VMASKMOV profile checks");

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

static cdisasm_x86_decode_flags one_bit(
    cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit_id));
    return flags;
}

static cdisasm_x86_form_id expected_form(
    uint8_t opcode,
    unsigned int vector_bits)
{
    cdisasm_x86_form_id form;

    if (opcode == UINT8_C(0x2c)) {
        form = UINT16_C(5593);
    } else if (opcode == UINT8_C(0x2d)) {
        form = UINT16_C(5589);
    } else if (opcode == UINT8_C(0x2e)) {
        form = UINT16_C(5591);
    } else {
        form = UINT16_C(5587);
    }
    return (cdisasm_x86_form_id)(form
        + (vector_bits == 256u ? UINT16_C(1) : UINT16_C(0)));
}

static void check_vmaskmov(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t p0,
    uint8_t p1,
    uint8_t opcode,
    uint8_t modrm)
{
    const int store = opcode >= UINT8_C(0x2e);
    const int pd = (opcode & UINT8_C(1)) != 0u;
    const unsigned int vector_bits =
        (p1 & UINT8_C(4)) != 0u ? 256u : 128u;
    const unsigned int vector_bytes = vector_bits / 8u;
    const cdisasm_x86_reg_id register_base = vector_bits == 256u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    const size_t memory_index = store ? 0u : 2u;
    const size_t data_index = store ? 2u : 0u;
    unsigned int mask_index = ((unsigned int)(~p1) >> 3) & 15u;
    unsigned int data_index_value = (modrm >> 3) & 7u;
    size_t index;

    if (mode == CDISASM_MODE_64) {
        data_index_value |= (p0 & UINT8_C(0x80)) == 0u ? 8u : 0u;
    } else {
        mask_index &= 7u;
    }

    EXPECT(decoded_size >= 5u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (pd
        ? CDISASM_X86_NAME_VMASKMOVPD
        : CDISASM_X86_NAME_VMASKMOVPS));
    EXPECT(instruction->form_id == expected_form(opcode, vector_bits));
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
    EXPECT(instruction->encoding.modrm == modrm);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset == 0u);

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = index == memory_index;
        const cdisasm_operand_access expected_access = memory
            ? (store ? CDISASM_OPERAND_ACCESS_WRITE
                     : CDISASM_OPERAND_ACCESS_READ)
            : (index == data_index && !store
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ);

        EXPECT(operand->type == (memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(operand->size == vector_bytes);
        EXPECT(operand->access == expected_access);
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
    EXPECT(instruction->opcode[1].reg == register_base + mask_index);
    EXPECT(instruction->opcode[data_index].reg
        == register_base + data_index_value);
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

static void test_complete_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
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

            for (opcode = UINT8_C(0x2c); opcode <= UINT8_C(0x2f);
                 ++opcode) {
                unsigned int p1;

                for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                    const int valid_control =
                        (p1 & UINT8_C(0x83)) == UINT8_C(1);
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const int valid = valid_control
                            && (modrm & UINT8_C(0xc0))
                                != UINT8_C(0xc0);
                        const uint8_t code[15] = {
                            0xc4, p0, (uint8_t)p1, (uint8_t)opcode,
                            (uint8_t)modrm, 0x24, 0x10, 0x20, 0x30, 0x40,
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
                            const cdisasm_x86_form_id form = expected_form(
                                (uint8_t)opcode,
                                (p1 & UINT8_C(4)) != 0u ? 256u : 128u);

                            check_vmaskmov(&instruction, decoded_size,
                                modes[mode_index], p0, (uint8_t)p1,
                                (uint8_t)opcode, (uint8_t)modrm);
                            ++form_counts[form - UINT16_C(5587)];
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

    EXPECT(allocated == UINT64_C(294912));
    EXPECT(reserved == UINT64_C(2850816));
#if USE_EXTRA_OPCODES
    for (mode_index = 0u; mode_index < 8u; ++mode_index) {
        EXPECT(form_counts[mode_index] == UINT64_C(36864));
    }
#else
    (void)form_counts;
#endif
}

static void test_exact_forms_and_gates(void)
{
    static const struct exact_case {
        uint8_t code[5];
        cdisasm_x86_form_id form;
    } cases[] = {
        {{0xc4,0xe2,0x69,0x2f,0x08},UINT16_C(5587)},
        {{0xc4,0xe2,0x6d,0x2f,0x08},UINT16_C(5588)},
        {{0xc4,0xe2,0x69,0x2d,0x08},UINT16_C(5589)},
        {{0xc4,0xe2,0x6d,0x2d,0x08},UINT16_C(5590)},
        {{0xc4,0xe2,0x69,0x2e,0x08},UINT16_C(5591)},
        {{0xc4,0xe2,0x6d,0x2e,0x08},UINT16_C(5592)},
        {{0xc4,0xe2,0x69,0x2c,0x08},UINT16_C(5593)},
        {{0xc4,0xe2,0x6d,0x2c,0x08},UINT16_C(5594)}};
    size_t index;

#if USE_EXTRA_OPCODES
    const cdisasm_x86_decode_flags all = all_flags(CDISASM_MODE_64);
    const cdisasm_x86_decode_flags none =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    const cdisasm_x86_decode_flags avx =
        one_bit(CDISASM_X86_DECODE_BIT_AVX);
    const cdisasm_x86_decode_flags avx2 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX2);

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, sizeof(cases[index].code),
            &all, &decoded_size);

        EXPECT(decoded_size == sizeof(cases[index].code));
        EXPECT(instruction.form_id == cases[index].form);
    }

    for (index = 0u; index < 3u; ++index) {
        static const cdisasm_x86_mode modes[3] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, modes[index], cases[6].code,
            sizeof(cases[6].code), &avx, &decoded_size);

        EXPECT(decoded_size == sizeof(cases[6].code));
        EXPECT(instruction.form_id == UINT16_C(5593));
    }
    expect_error("VMASKMOV needs AVX", CDISASM_CPU_X86,
        CDISASM_MODE_64, cases[0].code, sizeof(cases[0].code), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX2 alone does not admit VMASKMOV", CDISASM_CPU_X86,
        CDISASM_MODE_64, cases[7].code, sizeof(cases[7].code), &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("Westmere VMASKMOV gate", CDISASM_CPU_WESTMERE,
        CDISASM_MODE_64, cases[6].code, sizeof(cases[6].code), &all,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
            cases[7].code, sizeof(cases[7].code), &all, &decoded_size);

        EXPECT(decoded_size == sizeof(cases[7].code));
        EXPECT(instruction.form_id == UINT16_C(5594));
    }
#else
    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error("VMASKMOV extras off", CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code,
            sizeof(cases[index].code), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif
}

static void test_controls_aliases_and_truncation(void)
{
    static const uint8_t valid[] = {0xc4,0xe2,0x69,0x2c,0x08};
    size_t size;

    for (size = 1u; size < sizeof(valid); ++size) {
        expect_error("truncated C4 VMASKMOV", CDISASM_CPU_X86,
            CDISASM_MODE_64, valid, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    expect_error("reserved pp missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x68,0x2c,0x04}, 5u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x68,0x2c,0x04,0x24}, 6u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved W missing displacement", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0xe9,0x2d,0x45}, 5u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved W complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0xe9,0x2d,0x45,0x10}, 6u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("register ModRM reserved", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x69,0x2e,0xc1}, 5u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("wrong pp F3", CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x6a,0x2f,0x08}, 5u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("C5 cannot encode map 2", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf9,0x2c,0x08}, 4u, NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("wrong VEX map", CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x79,0x2c,0x08}, 5u, NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("legacy 66 missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc4,0xe2,0x69,0x2c,0x04}, 6u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("legacy 66 complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc4,0xe2,0x69,0x2c,0x04,0x24}, 7u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("LOCK prefix complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xf0,0xc4,0xe2,0x69,0x2d,0x08}, 6u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("F2 prefix complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xf2,0xc4,0xe2,0x69,0x2e,0x08}, 6u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("F3 prefix complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xf3,0xc4,0xe2,0x69,0x2f,0x08}, 6u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("REX prefix complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x48,0xc4,0xe2,0x69,0x2c,0x08}, 6u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        static const uint8_t alias[] = {
            0xc4,0xc2,0x39,0x2c,0x08};
        size_t index;

        for (index = 0u; index < 2u; ++index) {
            cdisasm_x86_decode_flags flags = all_flags(modes[index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[index], alias, sizeof(alias),
                &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(alias));
            EXPECT(instruction.form_id == UINT16_C(5593));
            EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM0);
            EXPECT(instruction.opcode[2].base_reg == (modes[index]
                    == CDISASM_MODE_16
                ? CDISASM_X86_REG_BX : CDISASM_X86_REG_EAX));
        }
    }
    {
        static const uint8_t high_load[] = {
            0xc4,0x02,0x3d,0x2c,0x4c,0xa5,0x80};
        static const uint8_t high_store[] = {
            0xc4,0x02,0x39,0x2f,0x4c,0xa5,0x80};
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            high_load, sizeof(high_load), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(high_load));
        EXPECT(instruction.form_id == UINT16_C(5594));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM9);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM8);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R13);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R12);
        EXPECT(instruction.opcode[2].scale == 4u);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            high_store, sizeof(high_store), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(high_store));
        EXPECT(instruction.form_id == UINT16_C(5587));
        EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R13);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM8);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM9);
    }
    {
        static const uint8_t duplicate_prefixes[] = {
            0x64,0x67,0x67,0xc4,0xe2,0x69,0x2e,0x08};
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            duplicate_prefixes, sizeof(duplicate_prefixes),
            &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(duplicate_prefixes));
        EXPECT(instruction.form_id == UINT16_C(5591));
        EXPECT(instruction.encoding.prefix_size == 6u);
        EXPECT(instruction.opcode[0].segment_reg == CDISASM_X86_REG_FS);
        EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_EAX);
    }
    {
        static const uint8_t les_collision[] = {
            0xc4,0x62,0x69,0x2c,0x08};
        cdisasm_x86_decode_flags flags16 = all_flags(CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags32 = all_flags(CDISASM_MODE_32);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_16,
            les_collision, sizeof(les_collision),
            &flags16, &decoded_size);

        EXPECT(decoded_size == 3u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
            les_collision, sizeof(les_collision), &flags32, &decoded_size);
        EXPECT(decoded_size == 3u);
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

static void test_formatting_and_schema(void)
{
    static const struct format_case {
        uint8_t code[8];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4,0xe2,0x69,0x2c,0x08},5u,
            "vmaskmovps xmm1, xmm2, xmmword ptr [rax]",
            "vmaskmovps (%rax), %xmm2, %xmm1"},
        {{0xc4,0xe2,0x6d,0x2d,0x08},5u,
            "vmaskmovpd ymm1, ymm2, ymmword ptr [rax]",
            "vmaskmovpd (%rax), %ymm2, %ymm1"},
        {{0xc4,0xe2,0x69,0x2e,0x08},5u,
            "vmaskmovps xmmword ptr [rax], xmm2, xmm1",
            "vmaskmovps %xmm1, %xmm2, (%rax)"},
        {{0xc4,0x02,0x39,0x2f,0x4c,0xa5,0x80},7u,
            "vmaskmovpd xmmword ptr [r13 + r12*4 - 0x80], xmm8, xmm9",
            "vmaskmovpd %xmm9, %xmm8, -0x80(%r13,%r12,4)"},
        {{0x64,0x67,0xc4,0xe2,0x69,0x2e,0x08},7u,
            "vmaskmovps xmmword ptr fs:[eax], xmm2, xmm1",
            "vmaskmovps %xmm1, %xmm2, %fs:(%eax)"}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size,
            &flags, &decoded_size);
        cdisasm_instruction forged;
        const int store = instruction.form_id <= UINT16_C(5588)
            || (instruction.form_id >= UINT16_C(5591)
                && instruction.form_id <= UINT16_C(5592));
        const size_t memory_index = store ? 0u : 2u;
        const size_t data_index = store ? 2u : 0u;

        EXPECT(decoded_size == cases[index].size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);

        forged = instruction;
        forged.name_id = instruction.name_id == CDISASM_X86_NAME_VMASKMOVPD
            ? CDISASM_X86_NAME_VMASKMOVPS
            : CDISASM_X86_NAME_VMASKMOVPD;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.form_id = (cdisasm_x86_form_id)(
            instruction.form_id == UINT16_C(5594)
                ? UINT16_C(5587) : instruction.form_id + UINT16_C(1));
        expect_format_rejected(&forged);
        forged = instruction;
        forged.name_id = CDISASM_X86_NAME_VMASKMOVDQU;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.operand_count = 2u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.mask_reg = CDISASM_X86_REG_K1;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.prefix_size = 2u;
        forged.encoding.opcode_offset = 2u;
        forged.encoding.modrm_offset = 3u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.modrm |= UINT8_C(0xc0);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.modrm ^= UINT8_C(8);
        expect_format_rejected(&forged);
        forged = instruction;
        ++forged.opcode[data_index].reg;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[memory_index].access =
            store ? CDISASM_OPERAND_ACCESS_READ
                  : CDISASM_OPERAND_ACCESS_WRITE;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[memory_index].size = 4u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.immediate_count = 1u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.selector_offset = 1u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_SSE;
        expect_format_rejected(&forged);
    }

    {
        static const uint8_t duplicates[] = {
            0x67,0x67,0xc4,0xe2,0x69,0x2c,0x08};
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            duplicates, sizeof(duplicates), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(duplicates));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output))
            == strlen("vmaskmovps xmm1, xmm2, xmmword ptr [eax]"));
        EXPECT(strcmp(output,
            "vmaskmovps xmm1, xmm2, xmmword ptr [eax]") == 0);
    }
    {
        static const uint8_t high[] = {
            0xc4,0x02,0x3d,0x2c,0x4c,0xa5,0x80};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            high, sizeof(high), &flags, &decoded_size);
        cdisasm_instruction forged = instruction;

        EXPECT(decoded_size == sizeof(high));
        EXPECT(forged.x86_group_count == 2u);
        forged.x86_group_count = 1u;
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_AVX;
        forged.x86_group_ids[1] = CDISASM_X86_GROUP_NONE;
        expect_format_rejected(&forged);
    }
    {
        static const uint8_t base[] = {
            0xc4,0xe2,0x69,0x2c,0x08};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            base, sizeof(base), &flags, &decoded_size);
        cdisasm_instruction forged = instruction;

        EXPECT(decoded_size == sizeof(base));
        forged.form_id = 0u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.name_id = CDISASM_X86_NAME_NOP;
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
    test_complete_control_partition();
    test_exact_forms_and_gates();
    test_controls_aliases_and_truncation();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VMASKMOV test(s) failed\n", failures);
        return 1;
    }
    printf("x86 VMASKMOV tests passed (294,912 allocated and "
        "2,850,816 reserved C4 controls)\n");
    return 0;
}
