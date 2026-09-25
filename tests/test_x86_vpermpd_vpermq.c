#include "cdisasm/cdisasm_x86.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <limits.h>
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

_Static_assert(CDISASM_X86_NAME_VPERMPD == UINT16_C(1836)
        && CDISASM_X86_NAME_VPERMQ == UINT16_C(1838),
    "VPERMPD/VPERMQ name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46),
    "VPERMPD/VPERMQ group IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "VPERMPD/VPERMQ runtime bits changed");

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

static cdisasm_x86_form_id form_for(uint8_t opcode, int register_form)
{
    return (cdisasm_x86_form_id)(
        (opcode == UINT8_C(0x01) ? UINT16_C(6878) : UINT16_C(6890))
        + (register_form ? 1u : 0u));
}

static void check_permute(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t opcode,
    int register_form)
{
    size_t index;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (opcode == UINT8_C(0x01)
        ? CDISASM_X86_NAME_VPERMPD : CDISASM_X86_NAME_VPERMQ));
    EXPECT(instruction->form_id == form_for(opcode, register_form));
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
        const int memory = !register_form && index == 1u;

        EXPECT(operand->type == (memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(operand->size == 32u);
        EXPECT(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
        EXPECT(operand->broadcast == CDISASM_X86_BROADCAST_NONE);
        if (memory) {
            EXPECT((operand->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
        } else {
            EXPECT(operand->reg >= CDISASM_X86_REG_YMM0
                && operand->reg <= CDISASM_X86_REG_YMM15);
            EXPECT(operand->flags == 0u);
            if (mode != CDISASM_MODE_64) {
                EXPECT(operand->reg <= CDISASM_X86_REG_YMM7);
            }
        }
    }
    EXPECT(instruction->opcode[2].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[2].size == 1u);
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].flags == 0u);
    EXPECT(instruction->opcode[2].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[2].imm <= UINT8_MAX);
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2));
}
#endif

static void test_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const uint8_t opcodes[2] = {UINT8_C(0x00), UINT8_C(0x01)};
    static const uint64_t expected_form_counts[2][2] = {
        {UINT64_C(2304), UINT64_C(768)},
        {UINT64_C(2304), UINT64_C(768)}};
    uint64_t form_counts[2][2] = {{0u, 0u}, {0u, 0u}};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;
    size_t opcode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        const unsigned int p0_count = long_mode ? 8u : 2u;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

        for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
            unsigned int p0_index;

            for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
                const uint8_t p0 = long_mode
                    ? (uint8_t)((p0_index << 5) | 3u)
                    : (uint8_t)(0xc3u | (p0_index << 5));
                unsigned int p1;

                for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                        const uint8_t code[15] = {
                            0xc4, p0, (uint8_t)p1,
                            opcodes[opcode_index], (uint8_t)modrm,
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

                        if (p1 == UINT8_C(0xfd)) {
#if USE_EXTRA_OPCODES
                            check_permute(&instruction, decoded_size,
                                modes[mode_index], opcodes[opcode_index],
                                register_form);
#else
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            ++form_counts[opcode_index][register_form];
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

    EXPECT(allocated == UINT64_C(6144));
    EXPECT(reserved == UINT64_C(1566720));
    for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
        EXPECT(form_counts[opcode_index][0]
            == expected_form_counts[opcode_index][0]);
        EXPECT(form_counts[opcode_index][1]
            == expected_form_counts[opcode_index][1]);
    }
}

static void test_exact_forms_and_gates(void)
{
    static const uint8_t q_register[] = {
        0xc4, 0x43, 0xfd, 0x00, 0xcb, 0x5a};
    static const uint8_t pd_memory[] = {
        0xc4, 0x63, 0xfd, 0x01, 0x4c, 0x88, 0x10, 0xa5};

#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
    cdisasm_x86_decode_flags none = selected_flags(0, 0);
    cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);
    cdisasm_x86_decode_flags both = selected_flags(1, 1);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t mode_index;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        q_register, sizeof(q_register), &flags64, &decoded_size);
    check_permute(&instruction, decoded_size, CDISASM_MODE_64, 0x00, 1);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM9);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM11);
    EXPECT(instruction.opcode[2].imm == UINT64_C(0x5a));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        pd_memory, sizeof(pd_memory), &flags64, &decoded_size);
    check_permute(&instruction, decoded_size, CDISASM_MODE_64, 0x01, 0);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM9);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_RCX);
    EXPECT(instruction.opcode[1].scale == 4u);
    EXPECT(instruction.opcode[1].imm == UINT64_C(0x10));
    EXPECT(instruction.opcode[2].imm == UINT64_C(0xa5));

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        static const cdisasm_x86_mode modes[3] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
        const uint8_t code[] = {0xc4, 0xe3, 0xfd, 0x00, 0xc1, 0x1b};

        instruction = decode(CDISASM_CPU_X86, modes[mode_index],
            code, sizeof(code), &flags, &decoded_size);
        check_permute(&instruction, decoded_size, modes[mode_index], 0x00, 1);
    }

    for (mode_index = 0u; mode_index < 2u; ++mode_index) {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
        const uint8_t alias[] = {0xc4, 0xc3, 0xfd, 0x01, 0xc1, 0x1b};

        instruction = decode(CDISASM_CPU_X86, modes[mode_index],
            alias, sizeof(alias), &flags, &decoded_size);
        check_permute(&instruction, decoded_size, modes[mode_index], 0x01, 1);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM0);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM1);
    }

    expect_error("VPERMQ needs AVX2", CDISASM_MODE_64,
        q_register, sizeof(q_register), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX alone does not admit VPERMPD", CDISASM_MODE_64,
        pd_memory, sizeof(pd_memory), &avx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        q_register, sizeof(q_register), &avx2, &decoded_size);
    check_permute(&instruction, decoded_size, CDISASM_MODE_64, 0x00, 1);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        pd_memory, sizeof(pd_memory), &both, &decoded_size);
    check_permute(&instruction, decoded_size, CDISASM_MODE_64, 0x01, 0);
#else
    expect_error("VPERMQ extras off", CDISASM_MODE_64,
        q_register, sizeof(q_register), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VPERMPD extras off", CDISASM_MODE_64,
        pd_memory, sizeof(pd_memory), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_truncation_and_collisions(void)
{
    static const uint8_t opcodes[2] = {UINT8_C(0x00), UINT8_C(0x01)};
    static const uint8_t bad_p1[4] = {0x7d, 0xf9, 0xed, 0xfc};
    size_t opcode_index;

    for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
        const uint8_t complete[6] = {
            0xc4, 0xe3, 0xfd, opcodes[opcode_index], 0xc1, 0x1b};
        size_t index;

        for (index = 1u; index < sizeof(complete); ++index) {
            expect_error("truncated VPERMPD/VPERMQ", CDISASM_MODE_64,
                complete, index, NULL, CDISASM_STATUS_TRUNCATED);
        }
        for (index = 0u; index < sizeof(bad_p1); ++index) {
            const uint8_t bad[] = {
                0xc4, 0xe3, bad_p1[index],
                opcodes[opcode_index], 0xc1, 0x1b};

            expect_error("reserved VPERMPD/VPERMQ control",
                CDISASM_MODE_64, bad, sizeof(bad), NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        expect_error("reserved control missing SIB", CDISASM_MODE_64,
            (const uint8_t[]){
                0xc4, 0xe3, 0x7d, opcodes[opcode_index], 0x04},
            5u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved control missing imm8", CDISASM_MODE_64,
            (const uint8_t[]){
                0xc4, 0xe3, 0x7d, opcodes[opcode_index], 0x04, 0x24},
            6u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("legacy prefix missing imm8", CDISASM_MODE_64,
            (const uint8_t[]){
                0x66, 0xc4, 0xe3, 0xfd, opcodes[opcode_index], 0xc1},
            6u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("legacy prefix complete", CDISASM_MODE_64,
            (const uint8_t[]){
                0x66, 0xc4, 0xe3, 0xfd,
                opcodes[opcode_index], 0xc1, 0x1b},
            7u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t les_collision[] = {
            0xc4, 0x63, 0xfd, 0x00, 0xc1, 0x1b};
        static const uint8_t wrong_map[] = {
            0xc4, 0xe2, 0xfd, 0x01, 0xc1, 0x1b};
        cdisasm_x86_decode_flags flags16 = all_flags(CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
        cdisasm_instruction instruction;
        uint32_t decoded_size;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_16,
            les_collision, sizeof(les_collision), &flags16, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            wrong_map, sizeof(wrong_map), &flags64, &decoded_size);
        EXPECT(instruction.name_id != CDISASM_X86_NAME_VPERMPD);
        EXPECT(instruction.name_id != CDISASM_X86_NAME_VPERMQ);
        EXPECT(instruction.form_id != UINT16_C(6878)
            && instruction.form_id != UINT16_C(6879)
            && instruction.form_id != UINT16_C(6890)
            && instruction.form_id != UINT16_C(6891));
    }
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_forged_format_rejected(
    const cdisasm_instruction *instruction)
{
    char output[160] = {'x'};

    EXPECT(cdisasm_x86_format(instruction, CDISASM_FORMAT_SYNTAX_INTEL,
               output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
    output[0] = 'x';
    EXPECT(cdisasm_x86_format(instruction, CDISASM_FORMAT_SYNTAX_ATT,
               output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
}

static void expect_modrm_memory_layout_mutations_rejected(
    const cdisasm_instruction *instruction)
{
    cdisasm_instruction forged;
    size_t index;

    EXPECT((instruction->encoding.modrm & UINT8_C(0xc7)) == 0u);
    EXPECT(instruction->encoding.sib_offset == 0u);
    EXPECT(instruction->encoding.displacement_size == 0u);

    /* r/m=100 requires a SIB in 32-/64-bit addressing. */
    forged = *instruction;
    forged.encoding.modrm = (uint8_t)(
        (forged.encoding.modrm & UINT8_C(0xf8)) | UINT8_C(4));
    expect_forged_format_rejected(&forged);

    /* mod=01 requires an encoded disp8. */
    forged = *instruction;
    forged.encoding.modrm |= UINT8_C(0x40);
    expect_forged_format_rejected(&forged);

    /* A SIB cannot be inserted while r/m still selects a direct base. */
    forged = *instruction;
    forged.encoding.sib_offset =
        (uint8_t)(forged.encoding.modrm_offset + 1u);
    forged.encoding.sib = UINT8_C(0x24);
    for (index = 0u; index < forged.encoding.immediate_count; ++index) {
        ++forged.encoding.immediate_offset[index];
    }
    ++forged.opcode_size;
    expect_forged_format_rejected(&forged);

    /* mod=00 with a non-sentinel direct base has no displacement. */
    forged = *instruction;
    forged.encoding.displacement_offset =
        (uint8_t)(forged.encoding.modrm_offset + 1u);
    forged.encoding.displacement_size = 1u;
    for (index = 0u; index < forged.encoding.immediate_count; ++index) {
        ++forged.encoding.immediate_offset[index];
    }
    ++forged.opcode_size;
    expect_forged_format_rejected(&forged);
}
#endif

static void test_formatting_and_evex_boundary(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const struct format_case {
        uint8_t code[8];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4, 0x43, 0xfd, 0x00, 0xcb, 0x5a, 0, 0}, 6u,
            "vpermq ymm9, ymm11, 0x5a",
            "vpermq $0x5a, %ymm11, %ymm9"},
        {{0xc4, 0x63, 0xfd, 0x01, 0x4c, 0x88, 0x10, 0xa5}, 8u,
            "vpermpd ymm9, ymmword ptr [rax + rcx*4 + 0x10], 0xa5",
            "vpermpd $0xa5, 0x10(%rax,%rcx,4), %ymm9"}};
    static const struct memory_layout_case {
        uint8_t code[11];
        size_t size;
        cdisasm_x86_mode mode;
    } memory_layout_cases[] = {
        {{0xc4, 0xe3, 0xfd, 0x01, 0x40, 0x7f, 0xa5},
            7u, CDISASM_MODE_64},
        {{0xc4, 0xe3, 0xfd, 0x01, 0x80,
             0x78, 0x56, 0x34, 0x12, 0xa5},
            10u, CDISASM_MODE_64},
        {{0xc4, 0xe3, 0xfd, 0x01, 0x05,
             0x78, 0x56, 0x34, 0x12, 0xa5},
            10u, CDISASM_MODE_64},
        {{0xc4, 0xe3, 0xfd, 0x01, 0x04, 0x24, 0xa5},
            7u, CDISASM_MODE_64},
        {{0xc4, 0xe3, 0xfd, 0x01, 0x04, 0x25,
             0x78, 0x56, 0x34, 0x12, 0xa5},
            11u, CDISASM_MODE_64},
        {{0xc4, 0xe3, 0xfd, 0x01, 0x04, 0x05,
             0x78, 0x56, 0x34, 0x12, 0xa5},
            11u, CDISASM_MODE_64},
        {{0xc4, 0xe3, 0xfd, 0x01, 0x05,
             0x78, 0x56, 0x34, 0x12, 0xa5},
            10u, CDISASM_MODE_32},
        {{0xc4, 0xe3, 0xfd, 0x01, 0x00, 0xa5},
            6u, CDISASM_MODE_16},
        {{0xc4, 0xe3, 0xfd, 0x01, 0x46, 0x7f, 0xa5},
            7u, CDISASM_MODE_16},
        {{0xc4, 0xe3, 0xfd, 0x01, 0x86, 0x34, 0x12, 0xa5},
            8u, CDISASM_MODE_16},
        {{0xc4, 0xe3, 0xfd, 0x01, 0x06, 0x34, 0x12, 0xa5},
            8u, CDISASM_MODE_16}};
    static const struct evex_case {
        uint8_t code[7];
        size_t size;
        cdisasm_x86_name_id name;
        cdisasm_x86_form_id form;
    } evex_cases[] = {
        {{0x62, 0xf3, 0xfd, 0x29, 0x01, 0x00, 0x1b}, 7u,
            CDISASM_X86_NAME_VPERMPD, UINT16_C(6874)},
        {{0x62, 0xf3, 0xfd, 0x29, 0x01, 0xc1, 0x1b}, 7u,
            CDISASM_X86_NAME_VPERMPD, UINT16_C(6875)},
        {{0x62, 0xf2, 0xf5, 0x29, 0x16, 0x00, 0}, 6u,
            CDISASM_X86_NAME_VPERMPD, UINT16_C(6876)},
        {{0x62, 0xf2, 0xf5, 0x29, 0x16, 0xc2, 0}, 6u,
            CDISASM_X86_NAME_VPERMPD, UINT16_C(6877)},
        {{0x62, 0xf3, 0xfd, 0x49, 0x01, 0x00, 0x1b}, 7u,
            CDISASM_X86_NAME_VPERMPD, UINT16_C(6880)},
        {{0x62, 0xf3, 0xfd, 0x49, 0x01, 0xc1, 0x1b}, 7u,
            CDISASM_X86_NAME_VPERMPD, UINT16_C(6881)},
        {{0x62, 0xf2, 0xf5, 0x49, 0x16, 0x00, 0}, 6u,
            CDISASM_X86_NAME_VPERMPD, UINT16_C(6882)},
        {{0x62, 0xf2, 0xf5, 0x49, 0x16, 0xc2, 0}, 6u,
            CDISASM_X86_NAME_VPERMPD, UINT16_C(6883)},
        {{0x62, 0xf3, 0xfd, 0x29, 0x00, 0x00, 0x1b}, 7u,
            CDISASM_X86_NAME_VPERMQ, UINT16_C(6892)},
        {{0x62, 0xf3, 0xfd, 0x29, 0x00, 0xc1, 0x1b}, 7u,
            CDISASM_X86_NAME_VPERMQ, UINT16_C(6893)},
        {{0x62, 0xf2, 0xf5, 0x29, 0x36, 0x00, 0}, 6u,
            CDISASM_X86_NAME_VPERMQ, UINT16_C(6894)},
        {{0x62, 0xf2, 0xf5, 0x29, 0x36, 0xc2, 0}, 6u,
            CDISASM_X86_NAME_VPERMQ, UINT16_C(6895)},
        {{0x62, 0xf3, 0xfd, 0x49, 0x00, 0x00, 0x1b}, 7u,
            CDISASM_X86_NAME_VPERMQ, UINT16_C(6896)},
        {{0x62, 0xf3, 0xfd, 0x49, 0x00, 0xc1, 0x1b}, 7u,
            CDISASM_X86_NAME_VPERMQ, UINT16_C(6897)},
        {{0x62, 0xf2, 0xf5, 0x49, 0x36, 0x00, 0}, 6u,
            CDISASM_X86_NAME_VPERMQ, UINT16_C(6898)},
        {{0x62, 0xf2, 0xf5, 0x49, 0x36, 0xc2, 0}, 6u,
            CDISASM_X86_NAME_VPERMQ, UINT16_C(6899)}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);

        EXPECT(decoded_size == cases[index].size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
                   output, sizeof(output)) == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
                   output, sizeof(output)) == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);
    }

    for (index = 0u;
         index < sizeof(memory_layout_cases) / sizeof(memory_layout_cases[0]);
         ++index) {
        char output[192];
        const cdisasm_x86_decode_flags mode_flags =
            all_flags(memory_layout_cases[index].mode);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, memory_layout_cases[index].mode,
            memory_layout_cases[index].code,
            memory_layout_cases[index].size, &mode_flags, &decoded_size);

        EXPECT(decoded_size == memory_layout_cases[index].size);
        EXPECT(instruction.form_id == UINT16_C(6878));
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) != 0u);
    }

    for (index = 0u;
         index < sizeof(evex_cases) / sizeof(evex_cases[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_cases[index].code, evex_cases[index].size,
            &flags, &decoded_size);

        EXPECT(decoded_size == evex_cases[index].size);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == evex_cases[index].name);
        EXPECT(instruction.form_id == evex_cases[index].form);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
        EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) != 0u);

        {
            cdisasm_instruction forged = instruction;

            forged.opcode[0].reg = CDISASM_X86_REG_EAX;
            expect_forged_format_rejected(&forged);
            forged = instruction;
            forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ;
            expect_forged_format_rejected(&forged);
            forged = instruction;
            forged.operand_count = 1u;
            expect_forged_format_rejected(&forged);
            forged = instruction;
            memset(&forged.encoding, 0, sizeof(forged.encoding));
            expect_forged_format_rejected(&forged);
            forged = instruction;
            forged.opcode_flags &=
                ~CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
            expect_forged_format_rejected(&forged);
            forged = instruction;
            forged.opcode_flags |=
                CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
            expect_forged_format_rejected(&forged);
            forged = instruction;
            forged.branch_target = UINT64_C(0x1000);
            expect_forged_format_rejected(&forged);
            forged = instruction;
            if ((instruction.form_id & UINT16_C(1)) == 0u) {
                forged.encoding.modrm |= UINT8_C(0xc0);
            } else {
                forged.encoding.modrm &= UINT8_C(0x3f);
            }
            expect_forged_format_rejected(&forged);
            forged = instruction;
            forged.encoding.prefix_size = 0u;
            forged.encoding.opcode_offset = 0u;
            forged.encoding.modrm_offset = 1u;
            forged.encoding.sib_offset = 0u;
            forged.encoding.sib = 0u;
            forged.encoding.displacement_offset = 0u;
            forged.encoding.displacement_size = 0u;
            forged.opcode_size = (uint32_t)(
                2u + forged.encoding.immediate_count);
            if (forged.encoding.immediate_count != 0u) {
                forged.encoding.immediate_offset[0] = 2u;
            }
            expect_forged_format_rejected(&forged);
            if ((instruction.form_id & UINT16_C(1)) != 0u) {
                const size_t rm_operand_index =
                    instruction.form_id == UINT16_C(6877)
                        || instruction.form_id == UINT16_C(6883)
                        || instruction.form_id == UINT16_C(6895)
                        || instruction.form_id == UINT16_C(6899)
                    ? 2u : 1u;

                forged = instruction;
                ++forged.opcode[0].reg;
                expect_forged_format_rejected(&forged);
                forged = instruction;
                ++forged.opcode[rm_operand_index].reg;
                expect_forged_format_rejected(&forged);
                forged = instruction;
                forged.encoding.modrm ^= UINT8_C(0x08);
                expect_forged_format_rejected(&forged);
                forged = instruction;
                forged.encoding.modrm ^= UINT8_C(0x01);
                expect_forged_format_rejected(&forged);
                forged = instruction;
                forged.encoding.sib_offset =
                    forged.encoding.modrm_offset + 1u;
                forged.encoding.sib = UINT8_C(0x24);
                ++forged.opcode_size;
                if (forged.encoding.immediate_count != 0u) {
                    ++forged.encoding.immediate_offset[0];
                }
                expect_forged_format_rejected(&forged);
            } else {
                expect_modrm_memory_layout_mutations_rejected(&instruction);
            }
        }
    }

    {
        static const uint8_t code[] = {
            0x62, 0xfb, 0xfd, 0x29, 0x01, 0x00, 0x1b};
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(code));
        EXPECT(instruction.form_id == UINT16_C(6874));
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R16);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) != 0u);
    }

    {
        static const uint8_t pd_immediate[] = {
            0x62, 0xf3, 0xfd, 0x29, 0x01, 0xc1, 0x1b};
        static const uint8_t q_immediate[] = {
            0x62, 0xf3, 0xfd, 0x29, 0x00, 0xc1, 0x1b};
        const uint8_t *codes[2] = {pd_immediate, q_immediate};
        const cdisasm_x86_form_id variable_forms[2] = {
            UINT16_C(6877), UINT16_C(6895)};

        for (index = 0u; index < 2u; ++index) {
            uint32_t decoded_size;
            cdisasm_instruction forged = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                codes[index], sizeof(pd_immediate), &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(pd_immediate));
            forged.form_id = variable_forms[index];
            expect_forged_format_rejected(&forged);
        }
    }

    {
        static const uint8_t code[] = {
            0xc4, 0x63, 0xfd, 0x01, 0x4c, 0x88, 0x10, 0xa5};
        uint32_t decoded_size;
        cdisasm_instruction original = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(code));
        forged = original;
        forged.name_id = CDISASM_X86_NAME_VPERMQ;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.form_id = UINT16_C(6879);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.form_id = UINT16_C(3585);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.operand_count = 2u;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.immediate_count = 0u;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = original;
        ++forged.opcode[0].reg;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.modrm ^= UINT8_C(0x08);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode[1].base_reg = CDISASM_X86_REG_R16;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode[1].index_reg = CDISASM_X86_REG_R17;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode[2].size = 2u;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.branch_target = UINT64_C(0x1000);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.modrm |= UINT8_C(0xc0);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.prefix_size = 0u;
        forged.encoding.opcode_offset = 0u;
        forged.encoding.modrm_offset = 1u;
        forged.encoding.sib_offset = 0u;
        forged.encoding.sib = 0u;
        forged.encoding.displacement_offset = 0u;
        forged.encoding.displacement_size = 0u;
        forged.encoding.immediate_offset[0] = 2u;
        forged.opcode_size = 3u;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.modrm = (uint8_t)(
            (forged.encoding.modrm & UINT8_C(0xf8)) | UINT8_C(0));
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.modrm &= UINT8_C(0x3f);
        expect_forged_format_rejected(&forged);
    }

    {
        static const uint8_t code[] = {
            0xc4, 0xe3, 0xfd, 0x01, 0x00, 0xa5};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(code));
        EXPECT(instruction.form_id == UINT16_C(6878));
        expect_modrm_memory_layout_mutations_rejected(&instruction);
    }

    {
        static const uint8_t code[] = {
            0xc4, 0xe3, 0xfd, 0x01, 0xc1, 0x1b};
        uint32_t decoded_size;
        cdisasm_instruction original = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(code));
        EXPECT(original.form_id == UINT16_C(6879));
        forged = original;
        ++forged.opcode[0].reg;
        expect_forged_format_rejected(&forged);
        forged = original;
        ++forged.opcode[1].reg;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.modrm ^= UINT8_C(0x08);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.modrm ^= UINT8_C(0x01);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.modrm &= UINT8_C(0x3f);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.sib_offset =
            forged.encoding.modrm_offset + 1u;
        forged.encoding.sib = UINT8_C(0x24);
        ++forged.encoding.immediate_offset[0];
        ++forged.opcode_size;
        expect_forged_format_rejected(&forged);
    }

    {
        static const uint8_t vaddps_code[] = {
            0xc4, 0x41, 0x2c, 0x58, 0xcb};
        uint32_t decoded_size;
        cdisasm_instruction forged = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            vaddps_code, sizeof(vaddps_code), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(vaddps_code));
        forged.form_id = UINT16_C(6899);
        expect_forged_format_rejected(&forged);
    }
#endif
}

int main(void)
{
    test_control_partition();
    test_exact_forms_and_gates();
    test_reserved_truncation_and_collisions();
    test_formatting_and_evex_boundary();

    if (failures != 0) {
        fprintf(stderr, "%d VPERMPD/VPERMQ test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
