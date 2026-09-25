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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",         \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VPERMD == UINT16_C(1829)
        && CDISASM_X86_NAME_VPERMPS == UINT16_C(1837),
    "VPERMD/VPERMPS name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46),
    "VPERMD/VPERMPS group IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "VPERMD/VPERMPS runtime bits changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VPERMD/VPERMPS profile sweep");

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
    return opcode == UINT8_C(0x36);
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
        (is_integer_opcode(opcode) ? UINT16_C(6780) : UINT16_C(6886))
        + (register_form ? 1u : 0u));
}

static void check_permute(
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
        ? CDISASM_X86_NAME_VPERMD : CDISASM_X86_NAME_VPERMPS));
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
    EXPECT(instruction->encoding.immediate_count == 0u);
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
    static const uint8_t opcodes[2] = {UINT8_C(0x36), UINT8_C(0x16)};
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
                    ? (uint8_t)((p0_index << 5) | 2u)
                    : (uint8_t)(0xc2u | (p0_index << 5));
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
                            check_permute(&instruction, decoded_size,
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

static void test_exact_forms_modes_and_aliases(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t opcodes[2] = {UINT8_C(0x36), UINT8_C(0x16)};
    cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    for (index = 0u; index < 2u; ++index) {
        const uint8_t opcode = opcodes[index];
        const uint8_t register_code[5] = {
            0xc4, 0x42, 0x2d, opcode, 0xcb};
        const uint8_t memory_code[7] = {
            0xc4, 0x62, 0x2d, opcode, 0x4c, 0x88, 0x10};

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            register_code, sizeof(register_code),
            &flags64, &decoded_size);
        check_permute(&instruction, decoded_size,
            CDISASM_MODE_64, opcode, 1);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM9);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM10);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_YMM11);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            memory_code, sizeof(memory_code), &flags64, &decoded_size);
        check_permute(&instruction, decoded_size,
            CDISASM_MODE_64, opcode, 0);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM9);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM10);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_RCX);
        EXPECT(instruction.opcode[2].scale == 4u);
        EXPECT(instruction.opcode[2].imm == UINT64_C(0x10));
    }

    for (index = 0u; index < 3u; ++index) {
        static const cdisasm_x86_mode modes[3] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
        cdisasm_x86_decode_flags flags = all_flags(modes[index]);
        size_t opcode_index;

        for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
            const uint8_t code[5] = {
                0xc4, 0xe2, 0x6d, opcodes[opcode_index], 0xc1};

            instruction = decode(CDISASM_CPU_X86, modes[index],
                code, sizeof(code), &flags, &decoded_size);
            check_permute(&instruction, decoded_size,
                modes[index], opcodes[opcode_index], 1);
        }
    }

    for (index = 0u; index < 2u; ++index) {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        cdisasm_x86_decode_flags flags = all_flags(modes[index]);
        size_t opcode_index;

        for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
            unsigned int raw_b;

            for (raw_b = 0u; raw_b < 2u; ++raw_b) {
                const uint8_t p0 = raw_b
                    ? UINT8_C(0xe2) : UINT8_C(0xc2);
                const uint8_t code[5] = {
                    0xc4, p0, 0x3d, opcodes[opcode_index], 0xc1};

                instruction = decode(CDISASM_CPU_X86, modes[index],
                    code, sizeof(code), &flags, &decoded_size);
                check_permute(&instruction, decoded_size,
                    modes[index], opcodes[opcode_index], 1);
                EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM0);
                EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM0);
                EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_YMM1);
            }
        }
    }

    {
        static const uint8_t long_high[] = {
            0xc4, 0xc2, 0x3d, 0x36, 0xc1};

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            long_high, sizeof(long_high), &flags64, &decoded_size);
        check_permute(&instruction, decoded_size,
            CDISASM_MODE_64, 0x36, 1);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM0);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM8);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_YMM9);
    }

    {
        static const uint8_t address_memory[] = {
            0x67, 0xc4, 0xe2, 0x6d, 0x36, 0x00};
        static const uint8_t segment_memory[] = {
            0x64, 0xc4, 0xe2, 0x6d, 0x16, 0x00};
        static const uint8_t segment_register[] = {
            0x64, 0xc4, 0xe2, 0x6d, 0x36, 0xc1};

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            address_memory, sizeof(address_memory),
            &flags64, &decoded_size);
        check_permute(&instruction, decoded_size,
            CDISASM_MODE_64, 0x36, 0);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_EAX);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            segment_memory, sizeof(segment_memory),
            &flags64, &decoded_size);
        check_permute(&instruction, decoded_size,
            CDISASM_MODE_64, 0x16, 0);
        EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_FS);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            segment_register, sizeof(segment_register),
            &flags64, &decoded_size);
        check_permute(&instruction, decoded_size,
            CDISASM_MODE_64, 0x36, 1);
    }
#endif
}

static void test_runtime_profiles_and_extras(void)
{
    static const uint8_t dword_code[] = {
        0xc4, 0xe2, 0x6d, 0x36, 0xc1};
    static const uint8_t float_code[] = {
        0xc4, 0xe2, 0x6d, 0x16, 0xc1};

#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags none = selected_flags(0, 0);
    cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);
    cdisasm_x86_decode_flags both = selected_flags(1, 1);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    cdisasm_x86_cpu_id cpu_id;
    size_t opcode_index;

    for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
        const uint8_t *code = opcode_index == 0u ? dword_code : float_code;
        const uint8_t opcode = code[3];

        expect_error("VPERMD/VPERMPS needs AVX2", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, sizeof(dword_code), &none,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX alone does not admit VPERMD/VPERMPS",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(dword_code), &avx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(dword_code), &avx2, &decoded_size);
        check_permute(&instruction, decoded_size,
            CDISASM_MODE_64, opcode, 1);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(dword_code), &both, &decoded_size);
        check_permute(&instruction, decoded_size,
            CDISASM_MODE_64, opcode, 1);
    }

    for (cpu_id = CDISASM_CPU_FIRST; cpu_id <= CDISASM_CPU_LAST; ++cpu_id) {
        cdisasm_x86_decode_flags flags =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        const int mask_ok = cdisasm_x86_cpu_decode_flag_mask(
            cpu_id, CDISASM_MODE_16, &flags) == CDISASM_STATUS_OK;
        const int has_avx2 = cdisasm_decode_flags_test_bit(
            &flags, CDISASM_X86_DECODE_BIT_AVX2);

        EXPECT(mask_ok);
        for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
            const uint8_t *code =
                opcode_index == 0u ? dword_code : float_code;
            const uint8_t opcode = code[3];

            if (has_avx2) {
                instruction = decode(cpu_id, CDISASM_MODE_16,
                    code, sizeof(dword_code), &flags, &decoded_size);
                check_permute(&instruction, decoded_size,
                    CDISASM_MODE_16, opcode, 1);
            } else {
                expect_error("profile lacks AVX2 permutation", cpu_id,
                    CDISASM_MODE_16, code, sizeof(dword_code), &flags,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }
    }
#else
    expect_error("VPERMD extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, dword_code, sizeof(dword_code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VPERMPS extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, float_code, sizeof(float_code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_truncation_and_collisions(void)
{
    static const uint8_t opcodes[2] = {UINT8_C(0x36), UINT8_C(0x16)};
    static const uint8_t legacy_prefixes[5] = {
        0x66, 0xf2, 0xf3, 0xf0, 0x48};
    size_t opcode_index;

    for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
        const uint8_t opcode = opcodes[opcode_index];
        const uint8_t complete[5] = {
            0xc4, 0xe2, 0x6d, opcode, 0xc1};
        size_t index;

        for (index = 1u; index < sizeof(complete); ++index) {
            expect_error("truncated VPERMD/VPERMPS form", CDISASM_CPU_X86,
                CDISASM_MODE_64, complete, index, NULL,
                CDISASM_STATUS_TRUNCATED);
        }
        expect_error("reserved W missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0xed, opcode, 0x04},
            5u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved W complete", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0xed, opcode, 0x04, 0x24},
            6u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("reserved L missing displacement", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0x69, opcode, 0x44, 0x24},
            6u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved L complete", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){
                0xc4, 0xe2, 0x69, opcode, 0x44, 0x24, 0x7f},
            7u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        for (index = 0u; index < 3u; ++index) {
            static const uint8_t reserved_pp[3] = {0u, 2u, 3u};
            expect_error("reserved pp", CDISASM_CPU_X86,
                CDISASM_MODE_64,
                (const uint8_t[]){0xc4, 0xe2,
                    (uint8_t)(0x6cu | reserved_pp[index]), opcode, 0xc1},
                5u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        for (index = 0u; index < sizeof(legacy_prefixes); ++index) {
            const uint8_t prefixed[6] = {legacy_prefixes[index],
                0xc4, 0xe2, 0x6d, opcode, 0xc1};

            expect_error("prefixed permutation missing ModRM",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                prefixed, 5u, NULL, CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed complete permutation",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                prefixed, sizeof(prefixed), NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t r_collision[] = {
            0xc4, 0x62, 0x6d, 0x36, 0xc1, 0, 0, 0, 0};
        static const uint8_t x_collision[] = {
            0xc4, 0xa2, 0x6d, 0x16, 0xc1, 0, 0, 0, 0};
        static const uint8_t wrong_map[2][5] = {
            {0xc4, 0xe3, 0x6d, 0x36, 0xc1},
            {0xc4, 0xe3, 0x6d, 0x16, 0xc1}};
        static const struct evex_case {
            uint8_t code[6];
            cdisasm_x86_form_id sibling_form;
        } evex_cases[] = {
            {{0x62, 0xf2, 0x6d, 0x29, 0x36, 0x08}, UINT16_C(6782)},
            {{0x62, 0xf2, 0x6d, 0x29, 0x36, 0xcb}, UINT16_C(6783)},
            {{0x62, 0x62, 0x0d, 0x40, 0x36, 0x28}, UINT16_C(6784)},
            {{0x62, 0x02, 0x0d, 0x40, 0x36, 0xef}, UINT16_C(6785)},
            {{0x62, 0xf2, 0x6d, 0x29, 0x16, 0x08}, UINT16_C(6884)},
            {{0x62, 0xf2, 0x6d, 0x29, 0x16, 0xcb}, UINT16_C(6885)},
            {{0x62, 0x62, 0x0d, 0x40, 0x16, 0x28}, UINT16_C(6888)},
            {{0x62, 0x02, 0x0d, 0x40, 0x16, 0xef}, UINT16_C(6889)}};
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
            EXPECT(instruction.name_id != CDISASM_X86_NAME_VPERMD);
            EXPECT(instruction.name_id != CDISASM_X86_NAME_VPERMPS);
            EXPECT(instruction.form_id != UINT16_C(6780)
                && instruction.form_id != UINT16_C(6781)
                && instruction.form_id != UINT16_C(6886)
                && instruction.form_id != UINT16_C(6887));
            if (decoded_size == 0u) {
                EXPECT(is_error_only(&instruction,
                    (cdisasm_status)instruction.last_error_id));
            }
        }

        for (index = 0u;
             index < sizeof(evex_cases) / sizeof(evex_cases[0]); ++index) {
            const cdisasm_x86_name_id expected_name = index < 4u
                ? CDISASM_X86_NAME_VPERMD : CDISASM_X86_NAME_VPERMPS;
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                evex_cases[index].code, sizeof(evex_cases[index].code),
                &flags64, &decoded_size);
            EXPECT(evex_cases[index].sibling_form != UINT16_C(6780)
                && evex_cases[index].sibling_form != UINT16_C(6781)
                && evex_cases[index].sibling_form != UINT16_C(6886)
                && evex_cases[index].sibling_form != UINT16_C(6887));
            EXPECT(decoded_size == sizeof(evex_cases[index].code));
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id == expected_name);
            EXPECT(instruction.form_id == evex_cases[index].sibling_form);
            EXPECT((instruction.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX))
                == CDISASM_PREFIX_EVEX);
            EXPECT((instruction.opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
            EXPECT((instruction.opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
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
        uint8_t code[7];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4, 0x42, 0x2d, 0x36, 0xcb, 0, 0}, 5u,
            "vpermd ymm9, ymm10, ymm11",
            "vpermd %ymm11, %ymm10, %ymm9"},
        {{0xc4, 0x62, 0x2d, 0x36, 0x4c, 0x88, 0x10}, 7u,
            "vpermd ymm9, ymm10, ymmword ptr [rax + rcx*4 + 0x10]",
            "vpermd 0x10(%rax,%rcx,4), %ymm10, %ymm9"},
        {{0xc4, 0x42, 0x2d, 0x16, 0xcb, 0, 0}, 5u,
            "vpermps ymm9, ymm10, ymm11",
            "vpermps %ymm11, %ymm10, %ymm9"},
        {{0xc4, 0x62, 0x2d, 0x16, 0x4c, 0x88, 0x10}, 7u,
            "vpermps ymm9, ymm10, ymmword ptr [rax + rcx*4 + 0x10]",
            "vpermps 0x10(%rax,%rcx,4), %ymm10, %ymm9"}};
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
            0xc4, 0x62, 0x2d, 0x36, 0x4c, 0x88, 0x10};
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
        forged.form_id = UINT16_C(3585);
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.form_id = UINT16_C(3585);
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_XOP;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.name_id = CDISASM_X86_NAME_VPERMPS;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.form_id = UINT16_C(6781);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.form_id = UINT16_C(6782);
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.name_id = CDISASM_X86_NAME_VPERMPS;
        forged.form_id = UINT16_C(6888);
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.operand_count = 2u;
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
        forged.form_id = UINT16_C(6888);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.x86_group_count = 1u;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode_groups = CDISASM_GROUP_JUMP;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.immediate_count = 1u;
        forged.encoding.immediate_size[0] = 1u;
        forged.encoding.immediate_offset[0] = forged.opcode_size;
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
    }

    {
        static const uint8_t evex_code[] = {
            0x62, 0xf2, 0x6d, 0x29, 0x36, 0xcb};
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction original = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_code, sizeof(evex_code), &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(evex_code));
        EXPECT(original.form_id == UINT16_C(6783));
        EXPECT(cdisasm_x86_format(&original, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);
        forged = original;
        forged.opcode_flags &= ~CDISASM_PREFIX_EVEX;
        forged.opcode_flags |= CDISASM_PREFIX_VEX;
        expect_forged_format_rejected(&forged);
    }

    {
        static const uint8_t vaddps_code[] = {
            0xc4, 0x41, 0x2c, 0x58, 0xcb};
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction original = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            vaddps_code, sizeof(vaddps_code), &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(vaddps_code));
        EXPECT(original.name_id == CDISASM_X86_NAME_VADDPS);
        EXPECT(cdisasm_x86_format(&original, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) != 0u);
        forged = original;
        forged.form_id = UINT16_C(6783);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.form_id = UINT16_C(6888);
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        expect_forged_format_rejected(&forged);
    }
#endif
}

int main(void)
{
    test_control_partition();
    test_exact_forms_modes_and_aliases();
    test_runtime_profiles_and_extras();
    test_reserved_truncation_and_collisions();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VPERMD/VPERMPS test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
