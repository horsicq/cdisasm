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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",         \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VBROADCASTF128 == UINT16_C(1480)
        && CDISASM_X86_NAME_VBROADCASTI128 == UINT16_C(1486),
    "VBROADCASTF128/I128 name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46),
    "VBROADCASTF128/I128 ISA-set group IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "VBROADCASTF128/I128 runtime-bit IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VBROADCASTF128/I128 profile sweep");

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
static cdisasm_x86_decode_flags cpu_flags(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(cpu_id, mode, &flags)
        == CDISASM_STATUS_OK);
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

static void check_vbroadcast128(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    int integer,
    unsigned int destination)
{
    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (integer
        ? CDISASM_X86_NAME_VBROADCASTI128
        : CDISASM_X86_NAME_VBROADCASTF128));
    EXPECT(instruction->form_id == (integer
        ? UINT16_C(3554) : UINT16_C(3543)));
    EXPECT(instruction->operand_count == 2u);
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
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg
        == (cdisasm_x86_reg_id)(CDISASM_X86_REG_YMM0 + destination));
    EXPECT(instruction->opcode[0].size == 32u);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[0].flags == 0u);
    EXPECT(instruction->opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction->opcode[1].size == 16u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT((instruction->opcode[1].flags
        & (CDISASM_OPERAND_FLAG_IMPLICIT
            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
    EXPECT(instruction->opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2) == integer);
    if (mode != CDISASM_MODE_64) {
        EXPECT(destination < 8u);
    }
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    int integer)
{
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (integer
        ? CDISASM_X86_NAME_VBROADCASTI128
        : CDISASM_X86_NAME_VBROADCASTF128));
    EXPECT(instruction->form_id == (integer
        ? UINT16_C(3554) : UINT16_C(3543)));
    EXPECT(instruction->operand_count == 2u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].size == 32u);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction->opcode[1].size == 16u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
#else
    (void)integer;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const uint8_t opcodes[2] = {UINT8_C(0x1a), UINT8_C(0x5a)};
    static const uint64_t expected_mode_counts[3] = {
        UINT64_C(768), UINT64_C(768), UINT64_C(3072)};
    uint64_t form_counts[2] = {0u, 0u};
    uint64_t mode_counts[3] = {0u, 0u, 0u};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;
    unsigned int opcode_index;

    for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            const int long_mode = modes[mode_index] == CDISASM_MODE_64;
            const unsigned int p0_count = long_mode ? 8u : 2u;
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags flags =
                cpu_flags(CDISASM_CPU_X86, modes[mode_index]);
#endif
            unsigned int p0_index;

            for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
                const uint8_t p0 = long_mode
                    ? (uint8_t)((p0_index << 5) | 2u)
                    : (uint8_t)(0xc2u | (p0_index << 5));
                unsigned int w;

                for (w = 0u; w < 2u; ++w) {
                    unsigned int l;

                    for (l = 0u; l < 2u; ++l) {
                        unsigned int pp;

                        for (pp = 0u; pp < 4u; ++pp) {
                            unsigned int vvvv;

                            for (vvvv = 0u; vvvv < 16u; ++vvvv) {
                                unsigned int modrm;

                                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                                    const int valid = w == 0u && l == 1u
                                        && pp == 1u && vvvv == 0u
                                        && (modrm & UINT8_C(0xc0))
                                            != UINT8_C(0xc0);
                                    const uint8_t code[15] = {0xc4, p0,
                                        (uint8_t)((w << 7)
                                            | (((~vvvv) & 15u) << 3)
                                            | (l << 2) | pp),
                                        opcodes[opcode_index], (uint8_t)modrm,
                                        0x24, 0x10, 0x20, 0x30, 0x40, 0x50,
                                        0x60, 0x70, 0x80, 0x90};
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
                                        check_allocated(&instruction,
                                            decoded_size,
                                            opcode_index != 0u);
                                        ++form_counts[opcode_index];
                                        ++mode_counts[mode_index];
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
        }
    }
    EXPECT(allocated == UINT64_C(4608));
    EXPECT(reserved == UINT64_C(1568256));
    EXPECT(form_counts[0] == UINT64_C(2304));
    EXPECT(form_counts[1] == UINT64_C(2304));
    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        EXPECT(mode_counts[mode_index] == expected_mode_counts[mode_index]);
    }
}

static void test_forms_modes_and_addresses(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t f_canonical[] = {0xc4, 0xe2, 0x7d, 0x1a, 0x08};
    static const uint8_t i_canonical[] = {0xc4, 0xe2, 0x7d, 0x5a, 0x08};
    static const uint8_t f_high[] = {
        0xc4, 0x22, 0x7d, 0x1a, 0x44, 0x58, 0x20};
    static const uint8_t i_high[] = {
        0xc4, 0x62, 0x7d, 0x5a, 0x7c, 0x8b, 0xf0};
    static const uint8_t rip_relative[] = {
        0xc4, 0xe2, 0x7d, 0x1a, 0x05, 0x78, 0x56, 0x34, 0x12};
    static const uint8_t address_override[] = {
        0x67, 0xc4, 0xe2, 0x7d, 0x5a, 0x00};
    static const uint8_t segment_override[] = {
        0x64, 0xc4, 0xe2, 0x7d, 0x1a, 0x00};
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t mode_index;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64, f_canonical,
        sizeof(f_canonical), &flags, &decoded_size);
    check_vbroadcast128(
        &instruction, decoded_size, CDISASM_MODE_64, 0, 1u);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RAX);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64, i_canonical,
        sizeof(i_canonical), &flags, &decoded_size);
    check_vbroadcast128(
        &instruction, decoded_size, CDISASM_MODE_64, 1, 1u);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RAX);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        f_high, sizeof(f_high), &flags, &decoded_size);
    check_vbroadcast128(
        &instruction, decoded_size, CDISASM_MODE_64, 0, 8u);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R11);
    EXPECT(instruction.opcode[1].scale == 2u);
    EXPECT(instruction.opcode[1].imm == UINT64_C(0x20));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        i_high, sizeof(i_high), &flags, &decoded_size);
    check_vbroadcast128(
        &instruction, decoded_size, CDISASM_MODE_64, 1, 15u);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RBX);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_RCX);
    EXPECT(instruction.opcode[1].scale == 4u);
    EXPECT(instruction.opcode[1].imm == (uint64_t)-INT64_C(16));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rip_relative, sizeof(rip_relative), &flags, &decoded_size);
    check_vbroadcast128(
        &instruction, decoded_size, CDISASM_MODE_64, 0, 0u);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RIP);
    EXPECT(instruction.opcode[1].imm == UINT64_C(0x12345678));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        address_override, sizeof(address_override), &flags, &decoded_size);
    check_vbroadcast128(
        &instruction, decoded_size, CDISASM_MODE_64, 1, 0u);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_EAX);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        segment_override, sizeof(segment_override), &flags, &decoded_size);
    check_vbroadcast128(
        &instruction, decoded_size, CDISASM_MODE_64, 0, 0u);
    EXPECT(instruction.opcode[1].segment_reg == CDISASM_X86_REG_FS);

    for (mode_index = 0u; mode_index < 2u; ++mode_index) {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        static const uint8_t aliases[2] = {0xc2, 0xe2};
        size_t alias_index;

        for (alias_index = 0u; alias_index < 2u; ++alias_index) {
            uint8_t f_code[6] = {
                0xc4, aliases[alias_index], 0x7d, 0x1a, 0x04, 0x24};
            uint8_t i_code[6] = {
                0xc4, aliases[alias_index], 0x7d, 0x5a, 0x04, 0x24};
            const size_t size = modes[mode_index] == CDISASM_MODE_16
                ? 5u : 6u;
            cdisasm_x86_decode_flags mode_flags =
                cpu_flags(CDISASM_CPU_X86, modes[mode_index]);

            instruction = decode(CDISASM_CPU_X86, modes[mode_index],
                f_code, size, &mode_flags, &decoded_size);
            check_vbroadcast128(
                &instruction, decoded_size, modes[mode_index], 0, 0u);
            EXPECT(instruction.opcode[1].base_reg
                == (modes[mode_index] == CDISASM_MODE_16
                    ? CDISASM_X86_REG_SI : CDISASM_X86_REG_ESP));
            instruction = decode(CDISASM_CPU_X86, modes[mode_index],
                i_code, size, &mode_flags, &decoded_size);
            check_vbroadcast128(
                &instruction, decoded_size, modes[mode_index], 1, 0u);
        }
    }
#endif
}

static void test_runtime_profiles_and_extras(void)
{
    static const uint8_t f_code[] = {0xc4, 0xe2, 0x7d, 0x1a, 0x08};
    static const uint8_t i_code[] = {0xc4, 0xe2, 0x7d, 0x5a, 0x08};

#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags none = selected_flags(0, 0);
    cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);
    cdisasm_x86_decode_flags both = selected_flags(1, 1);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    cdisasm_x86_cpu_id cpu_id;

    expect_error("VBROADCASTF128 needs AVX", CDISASM_CPU_X86,
        CDISASM_MODE_64, f_code, sizeof(f_code), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX2 selector does not admit AVX-only form",
        CDISASM_CPU_X86, CDISASM_MODE_64, f_code, sizeof(f_code), &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        f_code, sizeof(f_code), &avx, &decoded_size);
    check_vbroadcast128(
        &instruction, decoded_size, CDISASM_MODE_64, 0, 1u);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        f_code, sizeof(f_code), &both, &decoded_size);
    check_vbroadcast128(
        &instruction, decoded_size, CDISASM_MODE_64, 0, 1u);

    expect_error("VBROADCASTI128 needs AVX2", CDISASM_CPU_X86,
        CDISASM_MODE_64, i_code, sizeof(i_code), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX alone does not admit VBROADCASTI128",
        CDISASM_CPU_X86, CDISASM_MODE_64, i_code, sizeof(i_code), &avx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        i_code, sizeof(i_code), &avx2, &decoded_size);
    check_vbroadcast128(
        &instruction, decoded_size, CDISASM_MODE_64, 1, 1u);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        i_code, sizeof(i_code), &both, &decoded_size);
    check_vbroadcast128(
        &instruction, decoded_size, CDISASM_MODE_64, 1, 1u);

    for (cpu_id = CDISASM_CPU_FIRST; cpu_id <= CDISASM_CPU_LAST; ++cpu_id) {
        cdisasm_x86_decode_flags profile_flags =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        const int mask_ok = cdisasm_x86_cpu_decode_flag_mask(
            cpu_id, CDISASM_MODE_16, &profile_flags) == CDISASM_STATUS_OK;
        const int has_avx = cdisasm_decode_flags_test_bit(
            &profile_flags, CDISASM_X86_DECODE_BIT_AVX);
        const int has_avx2 = cdisasm_decode_flags_test_bit(
            &profile_flags, CDISASM_X86_DECODE_BIT_AVX2);

        EXPECT(mask_ok);
        if (has_avx) {
            instruction = decode(cpu_id, CDISASM_MODE_16,
                f_code, sizeof(f_code), &profile_flags, &decoded_size);
            check_vbroadcast128(
                &instruction, decoded_size, CDISASM_MODE_16, 0, 1u);
        } else {
            expect_error("profile lacks AVX for VBROADCASTF128", cpu_id,
                CDISASM_MODE_16, f_code, sizeof(f_code), &profile_flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (has_avx2) {
            instruction = decode(cpu_id, CDISASM_MODE_16,
                i_code, sizeof(i_code), &profile_flags, &decoded_size);
            check_vbroadcast128(
                &instruction, decoded_size, CDISASM_MODE_16, 1, 1u);
        } else {
            expect_error("profile lacks AVX2 for VBROADCASTI128", cpu_id,
                CDISASM_MODE_16, i_code, sizeof(i_code), &profile_flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
#else
    expect_error("VBROADCASTF128 extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, f_code, sizeof(f_code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VBROADCASTI128 extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, i_code, sizeof(i_code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_prefixes_truncation_and_collisions(void)
{
    static const uint8_t complete[2][5] = {
        {0xc4, 0xe2, 0x7d, 0x1a, 0x08},
        {0xc4, 0xe2, 0x7d, 0x5a, 0x08}};
    static const uint8_t legacy_prefixes[5] = {0x66, 0xf2, 0xf3, 0xf0, 0x48};
    unsigned int opcode_index;
    size_t index;

    for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
        const uint8_t opcode = opcode_index == 0u
            ? UINT8_C(0x1a) : UINT8_C(0x5a);

        for (index = 1u; index < sizeof(complete[opcode_index]); ++index) {
            expect_error("truncated VBROADCASTF128/I128", CDISASM_CPU_X86,
                CDISASM_MODE_64, complete[opcode_index], index, NULL,
                CDISASM_STATUS_TRUNCATED);
        }
        expect_error("reserved W missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0xfd, opcode, 0x04}, 5u, NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("reserved W complete", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0xfd, opcode, 0x04, 0x24}, 6u,
            NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("reserved L missing displacement", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0x79, opcode, 0x44, 0x24}, 6u,
            NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved L complete", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0x79, opcode, 0x44, 0x24, 0x7f},
            7u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        for (index = 0u; index < 3u; ++index) {
            static const uint8_t reserved_pp[3] = {0u, 2u, 3u};
            expect_error("reserved pp", CDISASM_CPU_X86, CDISASM_MODE_64,
                (const uint8_t[]){0xc4, 0xe2,
                    (uint8_t)(0x7cu | reserved_pp[index]), opcode, 0x08},
                5u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        expect_error("reserved pp missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0x7c, opcode, 0x04}, 5u, NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("reserved vvvv missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0x6d, opcode, 0x04}, 5u, NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("reserved vvvv complete", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0x6d, opcode, 0x04, 0x24}, 6u,
            NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("register source reserved", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0x7d, opcode, 0xc0}, 5u, NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        for (index = 0u; index < sizeof(legacy_prefixes); ++index) {
            const uint8_t prefixed[7] = {
                legacy_prefixes[index], 0xc4, 0xe2, 0x7d,
                opcode, 0x04, 0x24};

            expect_error("prefixed broadcast missing SIB", CDISASM_CPU_X86,
                CDISASM_MODE_64, prefixed, 6u, NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed complete broadcast", CDISASM_CPU_X86,
                CDISASM_MODE_64, prefixed, sizeof(prefixed), NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t r_collision[] = {
            0xc4, 0x62, 0x7d, 0x1a, 0x08, 0, 0, 0, 0};
        static const uint8_t x_collision[] = {
            0xc4, 0xa2, 0x7d, 0x5a, 0x08, 0, 0, 0, 0};
        cdisasm_x86_decode_flags flags16 =
            cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags32 =
            cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_32);
        cdisasm_instruction instruction;
        uint32_t decoded_size;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_16,
            r_collision, sizeof(r_collision), &flags16, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
            x_collision, sizeof(x_collision), &flags32, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
    }
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_forged_format_rejected(
    const cdisasm_instruction *instruction)
{
    char output[96] = {'x'};

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
        uint8_t code[9];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4, 0xe2, 0x7d, 0x1a, 0x08, 0, 0, 0, 0}, 5u,
            "vbroadcastf128 ymm1, xmmword ptr [rax]",
            "vbroadcastf128 (%rax), %ymm1"},
        {{0xc4, 0xe2, 0x7d, 0x5a, 0x08, 0, 0, 0, 0}, 5u,
            "vbroadcasti128 ymm1, xmmword ptr [rax]",
            "vbroadcasti128 (%rax), %ymm1"},
        {{0xc4, 0x22, 0x7d, 0x1a, 0x44, 0x58, 0x20, 0, 0}, 7u,
            "vbroadcastf128 ymm8, xmmword ptr [rax + r11*2 + 0x20]",
            "vbroadcastf128 0x20(%rax,%r11,2), %ymm8"},
        {{0xc4, 0x62, 0x7d, 0x5a, 0x7c, 0x8b, 0xf0, 0, 0}, 7u,
            "vbroadcasti128 ymm15, xmmword ptr [rbx + rcx*4 - 0x10]",
            "vbroadcasti128 -0x10(%rbx,%rcx,4), %ymm15"},
        {{0x64, 0xc4, 0xe2, 0x7d, 0x1a, 0x00, 0, 0, 0}, 6u,
            "vbroadcastf128 ymm0, xmmword ptr fs:[rax]",
            "vbroadcastf128 %fs:(%rax), %ymm0"},
        {{0xc4, 0xe2, 0x7d, 0x1a, 0x05, 0x78, 0x56, 0x34, 0x12}, 9u,
            "vbroadcastf128 ymm0, xmmword ptr [rip + 0x12345678]",
            "vbroadcastf128 0x12345678(%rip), %ymm0"}
    };
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_instruction instruction;
        uint32_t decoded_size;
        char output[192];
        char tiny[4] = {'x', 'x', 'x', 'x'};
        size_t required;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        EXPECT(decoded_size == cases[index].size);
        required = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL, NULL, 0u);
        EXPECT(required == strlen(cases[index].intel));
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
                   output, sizeof(output)) == required);
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
                   tiny, sizeof(tiny)) == required);
        EXPECT(tiny[sizeof(tiny) - 1u] == '\0');
        required = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ATT, NULL, 0u);
        EXPECT(required == strlen(cases[index].att));
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
                   output, sizeof(output)) == required);
        EXPECT(strcmp(output, cases[index].att) == 0);
    }

    {
        static const uint8_t f_code[] = {0xc4, 0xe2, 0x7d, 0x1a, 0x08};
        static const uint8_t i_code[] = {0xc4, 0xe2, 0x7d, 0x5a, 0x08};
        static const uint8_t high_code[] = {
            0xc4, 0x22, 0x7d, 0x1a, 0x44, 0x58, 0x20};
        cdisasm_instruction valid;
        cdisasm_instruction high;
        cdisasm_instruction forged;
        uint32_t decoded_size;

        valid = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            f_code, sizeof(f_code), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(f_code));
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VBROADCASTI128;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(3554);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.operand_count = 1u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |= CDISASM_PREFIX_OPERAND_SIZE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
        forged.mask_reg = CDISASM_X86_REG_K1;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].type = CDISASM_OPERAND_MEMORY;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].reg = CDISASM_X86_REG_XMM1;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].size = 16u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].flags = CDISASM_OPERAND_FLAG_IMPLICIT;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].broadcast = CDISASM_X86_BROADCAST_1_TO_8;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].type = CDISASM_OPERAND_REGISTER;
        forged.opcode[1].reg = CDISASM_X86_REG_XMM2;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].size = 8u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].flags |= CDISASM_OPERAND_FLAG_IMPLICIT;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].broadcast = CDISASM_X86_BROADCAST_1_TO_2;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.immediate_count = 1u;
        forged.encoding.immediate_offset[0] = 5u;
        forged.encoding.immediate_size[0] = 1u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.selector_offset = 5u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.x86_group_count = 0u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_AVX2;
        expect_forged_format_rejected(&forged);

        valid = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            i_code, sizeof(i_code), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(i_code));
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VBROADCASTF128;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(3543);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.x86_group_count -= 1u;
        expect_forged_format_rejected(&forged);

        high = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            high_code, sizeof(high_code), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(high_code));
        EXPECT(high.x86_group_count == 2u);
        EXPECT(high.x86_group_ids[0] == CDISASM_X86_GROUP_AMD64);
        EXPECT(high.x86_group_ids[1] == CDISASM_X86_GROUP_AVX);
        forged = high;
        forged.x86_group_ids[0] = forged.x86_group_ids[1];
        forged.x86_group_ids[1] = CDISASM_X86_GROUP_NONE;
        forged.x86_group_count = 1u;
        expect_forged_format_rejected(&forged);
    }
#endif
}

int main(void)
{
    test_control_partition();
    test_forms_modes_and_addresses();
    test_runtime_profiles_and_extras();
    test_prefixes_truncation_and_collisions();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr,
            "x86 VBROADCASTF128/I128 tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 VBROADCASTF128/I128 tests passed");
    return 0;
}
