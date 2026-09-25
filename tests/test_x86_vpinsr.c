#include "cdisasm/cdisasm_x86.h"
#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(expression) do { if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); \
    ++failures; } } while (0)

_Static_assert(CDISASM_X86_NAME_VPINSRB == UINT16_C(1859)
        && CDISASM_X86_NAME_VPINSRD == UINT16_C(1860)
        && CDISASM_X86_NAME_VPINSRQ == UINT16_C(1861)
        && CDISASM_X86_NAME_VPINSRW == UINT16_C(1862),
    "VPINSR name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VPINSR AVX IDs changed");

static int is_error_only(const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static cdisasm_instruction decode(cdisasm_cpu_id cpu, cdisasm_mode mode,
    const uint8_t *code, size_t size,
    const cdisasm_x86_decode_flags *flags, uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(cpu, mode, code, size,
        UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static void expect_error(const char *label, cdisasm_mode mode,
    const uint8_t *code, size_t size,
    const cdisasm_x86_decode_flags *flags, cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(CDISASM_CPU_X86, mode,
        code, size, flags, &decoded_size);

    if (decoded_size != 0u || !is_error_only(&instruction, status)) {
        fprintf(stderr, "%s: got size/status %u/%u, expected 0/%u\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id, (unsigned int)status);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags all_flags(cdisasm_mode mode)
{
    cdisasm_x86_decode_flags flags;

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
    cdisasm_x86_name_id name, int register_form)
{
    cdisasm_x86_form_id base;

    switch (name) {
        case CDISASM_X86_NAME_VPINSRB: base = UINT16_C(7060); break;
        case CDISASM_X86_NAME_VPINSRD: base = UINT16_C(7064); break;
        case CDISASM_X86_NAME_VPINSRQ: base = UINT16_C(7068); break;
        case CDISASM_X86_NAME_VPINSRW: base = UINT16_C(7072); break;
        default:
            EXPECT(0);
            return CDISASM_X86_FORM_NONE;
    }
    return (cdisasm_x86_form_id)(base + (register_form ? 0u : 1u));
}

static unsigned int expected_memory_size(cdisasm_x86_name_id name)
{
    switch (name) {
        case CDISASM_X86_NAME_VPINSRB: return 1u;
        case CDISASM_X86_NAME_VPINSRW: return 2u;
        case CDISASM_X86_NAME_VPINSRD: return 4u;
        case CDISASM_X86_NAME_VPINSRQ: return 8u;
        default:
            EXPECT(0);
            return 0u;
    }
}

static void check_instruction(const cdisasm_instruction *instruction,
    uint32_t decoded_size, cdisasm_mode mode,
    cdisasm_x86_name_id name, int register_form)
{
    const unsigned int scalar_size = expected_memory_size(name);
    size_t index;

    EXPECT(decoded_size >= 5u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == name);
    EXPECT(instruction->form_id == expected_form(name, register_form));
    EXPECT(instruction->operand_count == 4u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
            | CDISASM_PREFIX_SEGMENT)) == 0u);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_VEX) != 0u);
    EXPECT(instruction->encoding.prefix_size >= 2u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 1u);
    EXPECT(instruction->encoding.immediate_size[0] == 1u);
    EXPECT(instruction->encoding.immediate_offset[0]
        == instruction->opcode_size - 1u);
    EXPECT(instruction->encoding.selector_offset == 0u);
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];

        EXPECT(operand->type == CDISASM_OPERAND_REGISTER);
        EXPECT(operand->reg >= CDISASM_X86_REG_XMM0);
        EXPECT(operand->reg <= CDISASM_X86_REG_XMM15);
        EXPECT(operand->size == 16u);
        EXPECT(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
        EXPECT(operand->flags == 0u);
        EXPECT(operand->broadcast == CDISASM_X86_BROADCAST_NONE);
        if (mode != CDISASM_MODE_64) {
            EXPECT(operand->reg <= CDISASM_X86_REG_XMM7);
        }
    }
    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[2].size == (register_form
        ? (name == CDISASM_X86_NAME_VPINSRQ ? 8u : 4u)
        : scalar_size));
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT((instruction->opcode[2].flags
        & (CDISASM_OPERAND_FLAG_IMPLICIT
            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[3].size == 1u);
    EXPECT(instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[3].flags == 0u);
    EXPECT(instruction->opcode[3].broadcast
        == CDISASM_X86_BROADCAST_NONE);
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

static void test_complete_c4_partition(void)
{
    static const cdisasm_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const struct owned_row {
        uint8_t map;
        uint8_t opcode;
    } rows[] = {{3,0x20},{3,0x22},{1,0xc4}};
    static const uint64_t expected_forms[8] = {
        24576u,73728u,16384u,49152u,
        8192u,24576u,24576u,73728u};
    uint64_t form_counts[8] = {0};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t row_index;
    size_t mode_index;

    for (row_index = 0u;
         row_index < sizeof(rows) / sizeof(rows[0]); ++row_index) {
        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            const int long_mode = modes[mode_index] == CDISASM_MODE_64;
            const unsigned int p0_count = long_mode ? 8u : 2u;
            unsigned int p0_index;
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

            for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
                const uint8_t p0 = long_mode
                    ? (uint8_t)((p0_index << 5) | rows[row_index].map)
                    : (uint8_t)(UINT8_C(0xc0)
                        | (p0_index << 5) | rows[row_index].map);
                unsigned int p1;

                for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                    const int valid = (p1 & UINT8_C(7)) == UINT8_C(1);
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const uint8_t code[15] = {
                            0xc4,p0,(uint8_t)p1,rows[row_index].opcode,
                            (uint8_t)modrm,0x24,0x10,0x20,0x30,0x40,
                            0x50,0x60,0x70,0x80,0x90};
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_X86, modes[mode_index], code,
                            sizeof(code),
#if USE_EXTRA_OPCODES
                            &flags,
#else
                            NULL,
#endif
                            &decoded_size);

                        if (valid) {
                            const int register_form =
                                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
#if USE_EXTRA_OPCODES
                            cdisasm_x86_name_id name;
                            unsigned int family_index;

                            if (rows[row_index].map == UINT8_C(1)) {
                                name = CDISASM_X86_NAME_VPINSRW;
                                family_index = 3u;
                            } else if (rows[row_index].opcode
                                    == UINT8_C(0x20)) {
                                name = CDISASM_X86_NAME_VPINSRB;
                                family_index = 0u;
                            } else if ((p1 & UINT8_C(0x80)) != 0u
                                    && long_mode) {
                                name = CDISASM_X86_NAME_VPINSRQ;
                                family_index = 2u;
                            } else {
                                name = CDISASM_X86_NAME_VPINSRD;
                                family_index = 1u;
                            }
                            check_instruction(&instruction, decoded_size,
                                modes[mode_index], name, register_form);
                            ++form_counts[2u * family_index
                                + (register_form ? 0u : 1u)];
#else
                            (void)register_form;
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
    EXPECT(reserved == UINT64_C(2064384));
#if USE_EXTRA_OPCODES
    for (row_index = 0u;
         row_index < sizeof(expected_forms) / sizeof(expected_forms[0]);
         ++row_index) {
        EXPECT(form_counts[row_index] == expected_forms[row_index]);
    }
#else
    (void)expected_forms;
    (void)form_counts;
#endif
}

static void test_complete_c5_partition(void)
{
    static const cdisasm_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    uint64_t form_counts[2] = {0u,0u};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        const unsigned int p1_count = long_mode ? 256u : 64u;
        unsigned int p1_index;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

        for (p1_index = 0u; p1_index < p1_count; ++p1_index) {
            const uint8_t p1 = long_mode
                ? (uint8_t)p1_index
                : (uint8_t)(UINT8_C(0xc0) | p1_index);
            const int valid = (p1 & UINT8_C(7)) == UINT8_C(1);
            unsigned int modrm;

            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                const uint8_t code[15] = {
                    0xc5,p1,0xc4,(uint8_t)modrm,0x24,0x10,0x20,0x30,
                    0x40,0x50,0x60,0x70,0x80,0x90,0xa0};
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                    modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                    &flags,
#else
                    NULL,
#endif
                    &decoded_size);

                if (valid) {
                    const int register_form =
                        (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
#if USE_EXTRA_OPCODES
                    check_instruction(&instruction, decoded_size,
                        modes[mode_index], CDISASM_X86_NAME_VPINSRW,
                        register_form);
                    ++form_counts[register_form ? 0u : 1u];
#else
                    (void)register_form;
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
    EXPECT(allocated == UINT64_C(12288));
    EXPECT(reserved == UINT64_C(86016));
#if USE_EXTRA_OPCODES
    EXPECT(form_counts[0] == UINT64_C(3072));
    EXPECT(form_counts[1] == UINT64_C(9216));
#else
    (void)form_counts;
#endif
}

static void test_forms_gates_and_aliases(void)
{
    static const uint8_t b_mem[] = {0xc4,0xe3,0x71,0x20,0x00,0x05};
    static const uint8_t b_reg[] = {0xc4,0xe3,0xf1,0x20,0xc2,0x05};
    static const uint8_t d_reg[] = {0xc4,0xe3,0x71,0x22,0xc2,0x05};
    static const uint8_t q_reg[] = {0xc4,0xe3,0xf1,0x22,0xc2,0x05};
    static const uint8_t w_c5[] = {0xc5,0xf1,0xc4,0xc2,0x05};
    static const uint8_t w_c4[] = {0xc4,0xe1,0xf1,0xc4,0xc2,0x05};
    static const uint8_t high_b[] = {0xc4,0x43,0x29,0x20,0xcb,0xff};
    static const uint8_t nonlong_d_w1[] =
        {0xc4,0xc3,0xb1,0x22,0xc2,0x05};
    static const uint8_t address[] =
        {0x67,0xc4,0xe3,0x71,0x20,0x00,0x05};
    static const uint8_t segment[] =
        {0x64,0xc4,0xe3,0x71,0x20,0x00,0x05};
#if !USE_EXTRA_OPCODES
    static const struct legal_case {
        const uint8_t *code;
        size_t size;
        cdisasm_mode mode;
    } cases[] = {
        {b_mem,sizeof(b_mem),CDISASM_MODE_64},
        {b_reg,sizeof(b_reg),CDISASM_MODE_64},
        {d_reg,sizeof(d_reg),CDISASM_MODE_64},
        {q_reg,sizeof(q_reg),CDISASM_MODE_64},
        {w_c5,sizeof(w_c5),CDISASM_MODE_64},
        {w_c4,sizeof(w_c4),CDISASM_MODE_64},
        {high_b,sizeof(high_b),CDISASM_MODE_64},
        {nonlong_d_w1,sizeof(nonlong_d_w1),CDISASM_MODE_32},
        {address,sizeof(address),CDISASM_MODE_64},
        {segment,sizeof(segment),CDISASM_MODE_64}};
    size_t index;
#endif

#if USE_EXTRA_OPCODES
    {
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            b_mem, sizeof(b_mem), &flags, &decoded_size);
        check_instruction(&instruction, decoded_size, CDISASM_MODE_64,
            CDISASM_X86_NAME_VPINSRB, 0);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            b_reg, sizeof(b_reg), &flags, &decoded_size);
        check_instruction(&instruction, decoded_size, CDISASM_MODE_64,
            CDISASM_X86_NAME_VPINSRB, 1);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            d_reg, sizeof(d_reg), &flags, &decoded_size);
        check_instruction(&instruction, decoded_size, CDISASM_MODE_64,
            CDISASM_X86_NAME_VPINSRD, 1);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            q_reg, sizeof(q_reg), &flags, &decoded_size);
        check_instruction(&instruction, decoded_size, CDISASM_MODE_64,
            CDISASM_X86_NAME_VPINSRQ, 1);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            w_c5, sizeof(w_c5), &flags, &decoded_size);
        check_instruction(&instruction, decoded_size, CDISASM_MODE_64,
            CDISASM_X86_NAME_VPINSRW, 1);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            w_c4, sizeof(w_c4), &flags, &decoded_size);
        check_instruction(&instruction, decoded_size, CDISASM_MODE_64,
            CDISASM_X86_NAME_VPINSRW, 1);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            high_b, sizeof(high_b), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(high_b));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM9);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM10);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_R11D);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            address, sizeof(address), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(address));
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_EAX);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            segment, sizeof(segment), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(segment));
        EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_FS);
    }
    {
        static const cdisasm_mode nonlong_modes[2] = {
            CDISASM_MODE_16,CDISASM_MODE_32};
        size_t index;

        for (index = 0u; index < 2u; ++index) {
            cdisasm_x86_decode_flags flags = all_flags(nonlong_modes[index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                nonlong_modes[index], nonlong_d_w1,
                sizeof(nonlong_d_w1), &flags, &decoded_size);

            check_instruction(&instruction, decoded_size,
                nonlong_modes[index], CDISASM_X86_NAME_VPINSRD, 1);
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
            EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_EDX);
        }
    }
    {
        const cdisasm_x86_decode_flags none = selected_flags(0, 0);
        const cdisasm_x86_decode_flags avx = selected_flags(1, 0);
        const cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);
        cdisasm_x86_decode_flags profile;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        expect_error("VPINSR needs AVX", CDISASM_MODE_64,
            b_reg, sizeof(b_reg), &none,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX2 alone does not admit VPINSR", CDISASM_MODE_64,
            b_reg, sizeof(b_reg), &avx2,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            b_reg, sizeof(b_reg), &avx, &decoded_size);
        EXPECT(decoded_size == sizeof(b_reg));
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_SANDY_BRIDGE,
            CDISASM_MODE_64, &profile) == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
            b_reg, sizeof(b_reg), &profile, &decoded_size);
        EXPECT(decoded_size == sizeof(b_reg));
        EXPECT(instruction.form_id == UINT16_C(7060));
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_WESTMERE,
            CDISASM_MODE_64, &profile) == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_WESTMERE, CDISASM_MODE_64,
            b_reg, sizeof(b_reg), &profile, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    }
#else
    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error("VPINSR extras off", cases[index].mode,
            cases[index].code, cases[index].size, NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif
}

static void test_controls_and_precedence(void)
{
    static const uint8_t valid_c4[] = {0xc4,0xe3,0x71,0x20,0xc2,0x05};
    static const uint8_t valid_c5[] = {0xc5,0xf1,0xc4,0xc2,0x05};
    size_t size;

    for (size = 1u; size < sizeof(valid_c4); ++size) {
        expect_error("truncated C4 VPINSR", CDISASM_MODE_64,
            valid_c4, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    for (size = 1u; size < sizeof(valid_c5); ++size) {
        expect_error("truncated C5 VPINSRW", CDISASM_MODE_64,
            valid_c5, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    expect_error("wrong pp", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x70,0x20,0xc2,0x05}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("L=1", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x75,0x20,0xc2,0x05}, 6u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("C5 wrong pp", CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf0,0xc4,0xc2,0x05}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("C5 L=1", CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf5,0xc4,0xc2,0x05}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("wrong pp missing immediate", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x70,0x20,0xc2}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("L=1 missing SIB", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x75,0x20,0x04}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("C5 bad pp missing disp32", CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf0,0xc4,0x05,0x11,0x22,0x33}, 7u,
        NULL, CDISASM_STATUS_TRUNCATED);
    {
        static const uint8_t encountered[5] = {0x66,0xf2,0xf3,0xf0,0x48};
        size_t index;

        for (index = 0u; index < sizeof(encountered); ++index) {
            const uint8_t missing_immediate[7] = {
                encountered[index],0xc4,0xe3,0x71,0x20,0xc2,0x00};
            const uint8_t complete[7] = {
                encountered[index],0xc4,0xe3,0x71,0x20,0xc2,0x05};
            const uint8_t map1_missing_immediate[7] = {
                encountered[index],0xc4,0xe1,0x71,0xc4,0xc2,0x00};
            const uint8_t map1_complete[7] = {
                encountered[index],0xc4,0xe1,0x71,0xc4,0xc2,0x05};
            const uint8_t c5_missing_immediate[6] = {
                encountered[index],0xc5,0xf1,0xc4,0xc2,0x00};
            const uint8_t c5_complete[6] = {
                encountered[index],0xc5,0xf1,0xc4,0xc2,0x05};

            expect_error("encountered prefix missing immediate",
                CDISASM_MODE_64, missing_immediate,
                sizeof(missing_immediate) - 1u, NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("encountered prefix complete",
                CDISASM_MODE_64, complete, sizeof(complete), NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("map1 encountered prefix missing immediate",
                CDISASM_MODE_64, map1_missing_immediate,
                sizeof(map1_missing_immediate) - 1u, NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("map1 encountered prefix complete",
                CDISASM_MODE_64, map1_complete, sizeof(map1_complete), NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("C5 encountered prefix missing immediate",
                CDISASM_MODE_64, c5_missing_immediate,
                sizeof(c5_missing_immediate) - 1u, NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("C5 encountered prefix complete",
                CDISASM_MODE_64, c5_complete, sizeof(c5_complete), NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
}

static void test_legacy_and_evex_isolation(void)
{
#if USE_EXTRA_OPCODES
    static const struct sibling {
        uint8_t code[7];
        uint8_t size;
        cdisasm_x86_name_id name;
        cdisasm_x86_form_id forbidden_form;
    } siblings[] = {
        {{0x66,0x0f,0x3a,0x20,0xc2,0x05,0},6,
            CDISASM_X86_NAME_PINSRB,UINT16_C(7060)},
        {{0x66,0x0f,0x3a,0x22,0xc2,0x05,0},6,
            CDISASM_X86_NAME_PINSRD,UINT16_C(7064)},
        {{0x66,0x0f,0xc4,0xc2,0x05,0,0},5,
            CDISASM_X86_NAME_PINSRW,UINT16_C(7072)},
        {{0x0f,0xc4,0xc2,0x05,0,0,0},4,
            CDISASM_X86_NAME_PINSRW,UINT16_C(7072)},
        {{0x66,0x48,0x0f,0x3a,0x22,0xc2,0x01},7,
            CDISASM_X86_NAME_PINSRQ,UINT16_C(7068)},
        {{0x62,0xf3,0x75,0x08,0x20,0xc2,0x05},7,
            CDISASM_X86_NAME_VPINSRB,UINT16_C(7060)},
        {{0x62,0xf3,0x75,0x08,0x22,0xc2,0x05},7,
            CDISASM_X86_NAME_VPINSRD,UINT16_C(7064)},
        {{0x62,0xf3,0xf5,0x08,0x22,0xc2,0x01},7,
            CDISASM_X86_NAME_VPINSRQ,UINT16_C(7068)},
        {{0x62,0xf1,0x75,0x08,0xc4,0xc2,0x05},7,
            CDISASM_X86_NAME_VPINSRW,UINT16_C(7072)}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(siblings) / sizeof(siblings[0]);
         ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, siblings[index].code, siblings[index].size,
            &flags, &decoded_size);

        EXPECT(decoded_size == siblings[index].size);
        EXPECT(instruction.name_id == siblings[index].name);
        EXPECT(instruction.form_id != siblings[index].forbidden_form);
        if (siblings[index].code[0] == UINT8_C(0x62)) {
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX) == 0u);
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
        uint8_t code[9];
        uint8_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4,0xe3,0x71,0x20,0xc2,0x05,0},6,
            "vpinsrb xmm0, xmm1, edx, 0x5",
            "vpinsrb $0x5, %edx, %xmm1, %xmm0"},
        {{0xc4,0xe3,0x71,0x20,0x00,0x05,0},6,
            "vpinsrb xmm0, xmm1, byte ptr [rax], 0x5",
            "vpinsrb $0x5, (%rax), %xmm1, %xmm0"},
        {{0xc4,0xe3,0x71,0x22,0x00,0x05,0},6,
            "vpinsrd xmm0, xmm1, dword ptr [rax], 0x5",
            "vpinsrd $0x5, (%rax), %xmm1, %xmm0"},
        {{0xc4,0xe3,0xf1,0x22,0xc2,0x01,0},6,
            "vpinsrq xmm0, xmm1, rdx, 0x1",
            "vpinsrq $0x1, %rdx, %xmm1, %xmm0"},
        {{0xc5,0xf1,0xc4,0xc2,0x05,0,0},5,
            "vpinsrw xmm0, xmm1, edx, 0x5",
            "vpinsrw $0x5, %edx, %xmm1, %xmm0"},
        {{0xc4,0xe1,0xf1,0xc4,0x00,0x05,0},6,
            "vpinsrw xmm0, xmm1, word ptr [rax], 0x5",
            "vpinsrw $0x5, (%rax), %xmm1, %xmm0"},
        {{0x62,0xf3,0x75,0x08,0x20,0xc2,0x05},7,
            "vpinsrb xmm0, xmm1, edx, 0x5",
            "vpinsrb $0x5, %edx, %xmm1, %xmm0"},
        {{0x62,0xf3,0x75,0x08,0x20,0x00,0x05},7,
            "vpinsrb xmm0, xmm1, byte ptr [rax], 0x5",
            "vpinsrb $0x5, (%rax), %xmm1, %xmm0"},
        {{0x62,0xf3,0x75,0x08,0x22,0xc2,0x05},7,
            "vpinsrd xmm0, xmm1, edx, 0x5",
            "vpinsrd $0x5, %edx, %xmm1, %xmm0"},
        {{0x62,0xf3,0x75,0x08,0x22,0x00,0x05},7,
            "vpinsrd xmm0, xmm1, dword ptr [rax], 0x5",
            "vpinsrd $0x5, (%rax), %xmm1, %xmm0"},
        {{0x62,0xf3,0xf5,0x08,0x22,0xc2,0x01},7,
            "vpinsrq xmm0, xmm1, rdx, 0x1",
            "vpinsrq $0x1, %rdx, %xmm1, %xmm0"},
        {{0x62,0xf3,0xf5,0x08,0x22,0x00,0x01},7,
            "vpinsrq xmm0, xmm1, qword ptr [rax], 0x1",
            "vpinsrq $0x1, (%rax), %xmm1, %xmm0"},
        {{0x62,0xf1,0x75,0x08,0xc4,0xc2,0x05},7,
            "vpinsrw xmm0, xmm1, edx, 0x5",
            "vpinsrw $0x5, %edx, %xmm1, %xmm0"},
        {{0x62,0xf1,0x75,0x08,0xc4,0x00,0x05},7,
            "vpinsrw xmm0, xmm1, word ptr [rax], 0x5",
            "vpinsrw $0x5, (%rax), %xmm1, %xmm0"},
        {{0x64,0x67,0xc4,0xe3,0x71,0x20,0x00,0x05},8,
            "vpinsrb xmm0, xmm1, byte ptr fs:[eax], 0x5",
            "vpinsrb $0x5, %fs:(%eax), %xmm1, %xmm0"},
        {{0x64,0x67,0x62,0xf3,0x75,0x08,0x20,0x00,0x05},9,
            "vpinsrb xmm0, xmm1, byte ptr fs:[eax], 0x5",
            "vpinsrb $0x5, %fs:(%eax), %xmm1, %xmm0"}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, cases[index].size,
            &flags, &decoded_size);

        EXPECT(decoded_size == cases[index].size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);

        {
            cdisasm_instruction forged;
            const int evex = (instruction.opcode_flags
                & CDISASM_PREFIX_EVEX) != 0u;

            forged = instruction;
            forged.name_id = CDISASM_X86_NAME_VPHMINPOSUW;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.form_id = (cdisasm_x86_form_id)(instruction.form_id ^ 1u);
            expect_format_rejected(&forged);
            forged = instruction;
            forged.form_id = (cdisasm_x86_form_id)(instruction.form_id + 2u);
            expect_format_rejected(&forged);
            forged = instruction;
            if (evex) {
                forged.opcode_flags &=
                    ~CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
            } else {
                forged.opcode_flags |=
                    CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
            }
            expect_format_rejected(&forged);
            forged = instruction;
            forged.operand_count = 3u;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.x86_group_ids[forged.x86_group_count++] =
                CDISASM_X86_GROUP_AVX2;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.mask_mode = CDISASM_X86_MASK_MERGE;
            forged.mask_reg = CDISASM_X86_REG_K1;
            expect_format_rejected(&forged);
            forged = instruction;
            ++forged.opcode[0].reg;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
            expect_format_rejected(&forged);
            forged = instruction;
            ++forged.opcode[2].size;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[3].imm = UINT64_C(256);
            expect_format_rejected(&forged);
            forged = instruction;
            forged.encoding.modrm ^= UINT8_C(8);
            expect_format_rejected(&forged);
            forged = instruction;
            forged.encoding.immediate_count = 0u;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.encoding.prefix_size = evex ? 3u : 1u;
            expect_format_rejected(&forged);
            if ((instruction.opcode_flags
                    & (CDISASM_PREFIX_ADDRESS_SIZE
                        | CDISASM_PREFIX_SEGMENT)) == 0u) {
                forged = instruction;
                forged.opcode_flags |= CDISASM_PREFIX_ADDRESS_SIZE;
                expect_format_rejected(&forged);
                forged = instruction;
                forged.opcode_flags |=
                    CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
                ++forged.opcode_size;
                ++forged.encoding.prefix_size;
                ++forged.encoding.opcode_offset;
                ++forged.encoding.modrm_offset;
                ++forged.encoding.immediate_offset[0];
                expect_format_rejected(&forged);
                forged = instruction;
                ++forged.opcode_size;
                ++forged.encoding.prefix_size;
                ++forged.encoding.opcode_offset;
                ++forged.encoding.modrm_offset;
                ++forged.encoding.immediate_offset[0];
                if (!evex && instruction.encoding.prefix_size == 2u) {
                    /* A single increment could still describe native C4 W. */
                    ++forged.opcode_size;
                    ++forged.encoding.prefix_size;
                    ++forged.encoding.opcode_offset;
                    ++forged.encoding.modrm_offset;
                    ++forged.encoding.immediate_offset[0];
                }
                expect_format_rejected(&forged);
            }
            forged = instruction;
            forged.opcode[0].type = CDISASM_OPERAND_MEMORY;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[1].size = 32u;
            expect_format_rejected(&forged);
            forged = instruction;
            forged.opcode[3].access = CDISASM_OPERAND_ACCESS_WRITE;
            expect_format_rejected(&forged);
            if (evex) {
                forged = instruction;
                forged.opcode[1].reg =
                    (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM31 + 1u);
                expect_format_rejected(&forged);
            } else if (instruction.name_id != CDISASM_X86_NAME_VPINSRW) {
                /* B/D/Q require C4's three-byte VEX metadata. */
                forged = instruction;
                forged.encoding.prefix_size = 2u;
                expect_format_rejected(&forged);
            }
        }
    }
}
#else
static void test_formatting_and_schema(void)
{
}
#endif

int main(void)
{
    test_complete_c4_partition();
    test_complete_c5_partition();
    test_forms_gates_and_aliases();
    test_controls_and_precedence();
    test_legacy_and_evex_isolation();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VPINSR test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
