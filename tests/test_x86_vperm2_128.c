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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VPERM2F128 == UINT16_C(1827)
        && CDISASM_X86_NAME_VPERM2I128 == UINT16_C(1828),
    "VPERM2F128/I128 name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46),
    "VPERM2F128/I128 group IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "VPERM2F128/I128 runtime bits changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VPERM2F128/I128 profile sweep");

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
static int is_integer_opcode(uint8_t opcode)
{
    return opcode == UINT8_C(0x46);
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

static cdisasm_x86_decode_flags all_flags(cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, mode, &flags) == CDISASM_STATUS_OK);
    return flags;
}

static cdisasm_x86_form_id form_for(
    uint8_t opcode,
    int register_form)
{
    return (cdisasm_x86_form_id)(
        (is_integer_opcode(opcode) ? UINT16_C(6772) : UINT16_C(6770))
        + (register_form ? 1u : 0u));
}

static void check_perm2(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t opcode,
    int register_form)
{
    const int integer = is_integer_opcode(opcode);
    size_t index;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (integer
        ? CDISASM_X86_NAME_VPERM2I128
        : CDISASM_X86_NAME_VPERM2F128));
    EXPECT(instruction->form_id == form_for(opcode, register_form));
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
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 1u);
    EXPECT(instruction->encoding.immediate_size[0] == 1u);
    EXPECT(instruction->encoding.immediate_offset[0]
        == decoded_size - UINT32_C(1));
    EXPECT(instruction->encoding.selector_offset == 0u);

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = !register_form && index == 2u;

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
    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[3].size == 1u);
    EXPECT(instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[3].flags == 0u);
    EXPECT(instruction->opcode[3].broadcast
        == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2) == integer);
}
#endif

#if !USE_EXTRA_OPCODES
static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size)
{
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
}
#endif

static void test_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const uint8_t opcodes[2] = {UINT8_C(0x06), UINT8_C(0x46)};
    static const uint64_t expected_form_counts[2][2] = {
        {UINT64_C(36864), UINT64_C(12288)},
        {UINT64_C(36864), UINT64_C(12288)}};
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
            const uint8_t opcode = opcodes[opcode_index];
            unsigned int p0_index;

            for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
                const uint8_t p0 = long_mode
                    ? (uint8_t)((p0_index << 5) | 3u)
                    : (uint8_t)(0xc3u | (p0_index << 5));
                unsigned int p1;

                for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                    const int valid_selector =
                        (p1 & UINT8_C(0x87)) == UINT8_C(0x05);
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                        const uint8_t code[15] = {
                            0xc4, p0, (uint8_t)p1, opcode, (uint8_t)modrm,
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

                        if (valid_selector) {
#if USE_EXTRA_OPCODES
                            check_perm2(&instruction, decoded_size,
                                modes[mode_index], opcode, register_form);
#else
                            check_allocated(&instruction, decoded_size);
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

    EXPECT(allocated == UINT64_C(98304));
    EXPECT(reserved == UINT64_C(1474560));
    for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
        EXPECT(form_counts[opcode_index][0]
            == expected_form_counts[opcode_index][0]);
        EXPECT(form_counts[opcode_index][1]
            == expected_form_counts[opcode_index][1]);
    }
}

static void test_exact_forms_immediates_and_aliases(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t opcodes[2] = {UINT8_C(0x06), UINT8_C(0x46)};
    cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    for (index = 0u; index < 2u; ++index) {
        const uint8_t opcode = opcodes[index];
        const uint8_t register_code[6] = {
            0xc4, 0x43, 0x2d, opcode, 0xcb, 0x5a};
        const uint8_t memory_code[8] = {
            0xc4, 0x63, 0x2d, opcode, 0x4c, 0x88, 0x10, 0x5a};
        unsigned int immediate;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            register_code, sizeof(register_code),
            &flags64, &decoded_size);
        check_perm2(&instruction, decoded_size, CDISASM_MODE_64, opcode, 1);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM9);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM10);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_YMM11);
        EXPECT(instruction.opcode[3].imm == UINT64_C(0x5a));

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            memory_code, sizeof(memory_code), &flags64, &decoded_size);
        check_perm2(&instruction, decoded_size, CDISASM_MODE_64, opcode, 0);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM9);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM10);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_RCX);
        EXPECT(instruction.opcode[2].scale == 4u);
        EXPECT(instruction.opcode[2].imm == UINT64_C(0x10));
        EXPECT(instruction.opcode[3].imm == UINT64_C(0x5a));

        /* Every bit of imm8 is payload rather than opcode metadata. */
        for (immediate = 0u; immediate <= UINT8_MAX; ++immediate) {
            const uint8_t code[6] = {
                0xc4, 0xe3, 0x6d, opcode, 0xc1, (uint8_t)immediate};

            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), &flags64, &decoded_size);
            check_perm2(&instruction, decoded_size,
                CDISASM_MODE_64, opcode, 1);
            EXPECT(instruction.opcode[3].imm == immediate);
        }
    }

    {
        static const uint8_t address_memory[] = {
            0x67, 0xc4, 0xe3, 0x6d, 0x06, 0x00, 0x5a};
        static const uint8_t segment_memory[] = {
            0x64, 0xc4, 0xe3, 0x6d, 0x46, 0x00, 0x5a};
        static const uint8_t segment_register[] = {
            0x64, 0xc4, 0xe3, 0x6d, 0x06, 0xc1, 0x5a};

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            address_memory, sizeof(address_memory),
            &flags64, &decoded_size);
        check_perm2(&instruction, decoded_size, CDISASM_MODE_64, 0x06, 0);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_EAX);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            segment_memory, sizeof(segment_memory),
            &flags64, &decoded_size);
        check_perm2(&instruction, decoded_size, CDISASM_MODE_64, 0x46, 0);
        EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_FS);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            segment_register, sizeof(segment_register),
            &flags64, &decoded_size);
        check_perm2(&instruction, decoded_size, CDISASM_MODE_64, 0x06, 1);
    }

    for (index = 0u; index < 2u; ++index) {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        cdisasm_x86_decode_flags flags = all_flags(modes[index]);
        unsigned int opcode_index;

        for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
            const uint8_t opcode = opcodes[opcode_index];
            unsigned int raw_b;

            for (raw_b = 0u; raw_b < 2u; ++raw_b) {
                const uint8_t p0 = raw_b
                    ? UINT8_C(0xe3) : UINT8_C(0xc3);
                const uint8_t code[6] = {
                    0xc4, p0, 0x3d, opcode, 0xc1, 0x01};

                instruction = decode(CDISASM_CPU_X86, modes[index],
                    code, sizeof(code), &flags, &decoded_size);
                check_perm2(&instruction, decoded_size,
                    modes[index], opcode, 1);
                EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM0);
                EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM0);
                EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_YMM1);
            }
        }
    }

    {
        static const uint8_t long_high[] = {
            0xc4, 0xc3, 0x3d, 0x06, 0xc1, 0x01};

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            long_high, sizeof(long_high), &flags64, &decoded_size);
        check_perm2(&instruction, decoded_size, CDISASM_MODE_64, 0x06, 1);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM0);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM8);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_YMM9);
    }
#endif
}

static void test_runtime_profiles_and_extras(void)
{
    static const uint8_t float_code[] = {
        0xc4, 0xe3, 0x6d, 0x06, 0xc1, 0x01};
    static const uint8_t integer_code[] = {
        0xc4, 0xe3, 0x6d, 0x46, 0xc1, 0x01};

#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags none = selected_flags(0, 0);
    cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);
    cdisasm_x86_decode_flags both = selected_flags(1, 1);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    cdisasm_x86_cpu_id cpu_id;

    expect_error("VPERM2F128 needs AVX", CDISASM_CPU_X86,
        CDISASM_MODE_64, float_code, sizeof(float_code), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX2 alone does not admit AVX-only VPERM2F128",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        float_code, sizeof(float_code), &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        float_code, sizeof(float_code), &avx, &decoded_size);
    check_perm2(&instruction, decoded_size, CDISASM_MODE_64, 0x06, 1);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        float_code, sizeof(float_code), &both, &decoded_size);
    check_perm2(&instruction, decoded_size, CDISASM_MODE_64, 0x06, 1);

    expect_error("VPERM2I128 needs AVX2", CDISASM_CPU_X86,
        CDISASM_MODE_64, integer_code, sizeof(integer_code), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX alone does not admit VPERM2I128",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        integer_code, sizeof(integer_code), &avx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        integer_code, sizeof(integer_code), &avx2, &decoded_size);
    check_perm2(&instruction, decoded_size, CDISASM_MODE_64, 0x46, 1);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        integer_code, sizeof(integer_code), &both, &decoded_size);
    check_perm2(&instruction, decoded_size, CDISASM_MODE_64, 0x46, 1);

    for (cpu_id = CDISASM_CPU_FIRST; cpu_id <= CDISASM_CPU_LAST; ++cpu_id) {
        cdisasm_x86_decode_flags flags =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        const int mask_ok = cdisasm_x86_cpu_decode_flag_mask(
            cpu_id, CDISASM_MODE_16, &flags) == CDISASM_STATUS_OK;
        const int has_avx = cdisasm_decode_flags_test_bit(
            &flags, CDISASM_X86_DECODE_BIT_AVX);
        const int has_avx2 = cdisasm_decode_flags_test_bit(
            &flags, CDISASM_X86_DECODE_BIT_AVX2);

        EXPECT(mask_ok);
        if (has_avx) {
            instruction = decode(cpu_id, CDISASM_MODE_16,
                float_code, sizeof(float_code), &flags, &decoded_size);
            check_perm2(&instruction, decoded_size,
                CDISASM_MODE_16, 0x06, 1);
        } else {
            expect_error("profile lacks VPERM2F128", cpu_id,
                CDISASM_MODE_16, float_code, sizeof(float_code), &flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (has_avx2) {
            instruction = decode(cpu_id, CDISASM_MODE_16,
                integer_code, sizeof(integer_code), &flags, &decoded_size);
            check_perm2(&instruction, decoded_size,
                CDISASM_MODE_16, 0x46, 1);
        } else {
            expect_error("profile lacks VPERM2I128", cpu_id,
                CDISASM_MODE_16, integer_code, sizeof(integer_code), &flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
#else
    expect_error("VPERM2F128 extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, float_code, sizeof(float_code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VPERM2I128 extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, integer_code, sizeof(integer_code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_truncation_and_collisions(void)
{
    static const uint8_t opcodes[2] = {UINT8_C(0x06), UINT8_C(0x46)};
    static const uint8_t legacy_prefixes[5] = {
        0x66, 0xf2, 0xf3, 0xf0, 0x48};
    size_t opcode_index;

    for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
        const uint8_t opcode = opcodes[opcode_index];
        const uint8_t complete[6] = {
            0xc4, 0xe3, 0x6d, opcode, 0xc1, 0x01};
        size_t index;

        for (index = 1u; index < sizeof(complete); ++index) {
            expect_error("truncated VPERM2 form", CDISASM_CPU_X86,
                CDISASM_MODE_64, complete, index, NULL,
                CDISASM_STATUS_TRUNCATED);
        }
        expect_error("reserved W missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe3, 0xed, opcode, 0x04},
            5u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved W missing immediate", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){
                0xc4, 0xe3, 0xed, opcode, 0x04, 0x24},
            6u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved W complete", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){
                0xc4, 0xe3, 0xed, opcode, 0x04, 0x24, 0x01},
            7u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("reserved L missing displacement", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){
                0xc4, 0xe3, 0x69, opcode, 0x44, 0x24},
            6u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved L missing immediate", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){
                0xc4, 0xe3, 0x69, opcode, 0x44, 0x24, 0x7f},
            7u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved L complete", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){
                0xc4, 0xe3, 0x69, opcode, 0x44, 0x24, 0x7f, 0x01},
            8u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        for (index = 0u; index < 3u; ++index) {
            static const uint8_t reserved_pp[3] = {0u, 2u, 3u};
            expect_error("reserved pp", CDISASM_CPU_X86,
                CDISASM_MODE_64,
                (const uint8_t[]){0xc4, 0xe3,
                    (uint8_t)(0x6cu | reserved_pp[index]),
                    opcode, 0xc1, 0x01},
                6u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        for (index = 0u; index < sizeof(legacy_prefixes); ++index) {
            const uint8_t prefixed[7] = {legacy_prefixes[index],
                0xc4, 0xe3, 0x6d, opcode, 0xc1, 0x01};

            expect_error("prefixed VPERM2 missing immediate",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                prefixed, 6u, NULL, CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed complete VPERM2",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                prefixed, sizeof(prefixed), NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t r_collision[] = {
            0xc4, 0x63, 0x6d, 0x06, 0xc1, 0x01, 0, 0, 0};
        static const uint8_t x_collision[] = {
            0xc4, 0xa3, 0x6d, 0x46, 0xc1, 0x01, 0, 0, 0};
        static const uint8_t evex_float[] = {
            0x62, 0xf3, 0x6d, 0x28, 0x06, 0xcb, 0x5a};
        static const uint8_t evex_integer[] = {
            0x62, 0xf3, 0x6d, 0x28, 0x46, 0xcb, 0x5a};
        static const uint8_t wrong_map[2][5] = {
            {0xc4, 0xe2, 0x6d, 0x06, 0xc1},
            {0xc4, 0xe2, 0x6d, 0x46, 0xc1}};
        cdisasm_x86_decode_flags flags16 = all_flags(CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags32 = all_flags(CDISASM_MODE_32);
        cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
        cdisasm_instruction instruction;
        uint32_t decoded_size;
        size_t index;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_16,
            r_collision, sizeof(r_collision), &flags16, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
            x_collision, sizeof(x_collision), &flags32, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);

        for (index = 0u; index < 2u; ++index) {
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                wrong_map[index], sizeof(wrong_map[index]),
                &flags64, &decoded_size);
            EXPECT(instruction.name_id != CDISASM_X86_NAME_VPERM2F128);
            EXPECT(instruction.name_id != CDISASM_X86_NAME_VPERM2I128);
            EXPECT(instruction.form_id < UINT16_C(6770)
                || instruction.form_id > UINT16_C(6773));
            if (decoded_size == 0u) {
                EXPECT(is_error_only(&instruction,
                    (cdisasm_status)instruction.last_error_id));
            }
        }

        for (index = 0u; index < 2u; ++index) {
            const uint8_t *code = index == 0u ? evex_float : evex_integer;

            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(evex_float), &flags64, &decoded_size);
            if (decoded_size != 0u) {
                EXPECT(instruction.name_id != CDISASM_X86_NAME_VPERM2F128);
                EXPECT(instruction.name_id != CDISASM_X86_NAME_VPERM2I128);
                EXPECT(instruction.form_id < UINT16_C(6770)
                    || instruction.form_id > UINT16_C(6773));
            } else {
                EXPECT(is_error_only(&instruction,
                    (cdisasm_status)instruction.last_error_id));
            }
        }
    }
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_forged_format_rejected(
    const cdisasm_instruction *instruction)
{
    char output[128] = {'x'};

    EXPECT(cdisasm_x86_format(instruction, CDISASM_FORMAT_SYNTAX_INTEL,
               output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
    output[0] = 'x';
    EXPECT(cdisasm_x86_format(instruction, CDISASM_FORMAT_SYNTAX_ATT,
               output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
}
#endif

static void test_formatting_and_schema(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const struct format_case {
        uint8_t code[8];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4, 0x43, 0x2d, 0x06, 0xcb, 0x5a, 0, 0}, 6u,
            "vperm2f128 ymm9, ymm10, ymm11, 0x5a",
            "vperm2f128 $0x5a, %ymm11, %ymm10, %ymm9"},
        {{0xc4, 0x63, 0x2d, 0x06, 0x4c, 0x88, 0x10, 0x5a}, 8u,
            "vperm2f128 ymm9, ymm10, ymmword ptr [rax + rcx*4 + 0x10], 0x5a",
            "vperm2f128 $0x5a, 0x10(%rax,%rcx,4), %ymm10, %ymm9"},
        {{0xc4, 0x43, 0x2d, 0x46, 0xcb, 0x5a, 0, 0}, 6u,
            "vperm2i128 ymm9, ymm10, ymm11, 0x5a",
            "vperm2i128 $0x5a, %ymm11, %ymm10, %ymm9"},
        {{0xc4, 0x63, 0x2d, 0x46, 0x4c, 0x88, 0x10, 0x5a}, 8u,
            "vperm2i128 ymm9, ymm10, ymmword ptr [rax + rcx*4 + 0x10], 0x5a",
            "vperm2i128 $0x5a, 0x10(%rax,%rcx,4), %ymm10, %ymm9"}};
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

    {
        static const uint8_t code[] = {
            0xc4, 0x63, 0x2d, 0x06, 0x4c, 0x88, 0x10, 0x5a};
        uint32_t decoded_size;
        cdisasm_instruction original = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(code));
        forged = original;
        forged.name_id = CDISASM_X86_NAME_VADDPS;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.form_id = UINT16_C(3585);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.name_id = CDISASM_X86_NAME_VPERM2I128;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.form_id = UINT16_C(6771);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.operand_count = 3u;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        forged.form_id = UINT16_C(3585);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.x86_group_count = 2u;
        forged.x86_group_ids[1] = CDISASM_X86_GROUP_AVX2;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode_groups = CDISASM_GROUP_JUMP;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.immediate_count = 0u;
        forged.encoding.immediate_offset[0] = 0u;
        forged.encoding.immediate_size[0] = 0u;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.immediate_size[0] = 2u;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode[2].size = 16u;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode[2].flags |= CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode[3].imm = UINT64_C(0x100);
        expect_forged_format_rejected(&forged);
    }
#endif
}

int main(void)
{
    test_control_partition();
    test_exact_forms_immediates_and_aliases();
    test_runtime_profiles_and_extras();
    test_reserved_truncation_and_collisions();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VPERM2F128/I128 test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
