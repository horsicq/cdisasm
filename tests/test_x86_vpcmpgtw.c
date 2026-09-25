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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",           \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VPCMPGTW == UINT16_C(658),
    "VPCMPGTW name ID changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46),
    "VPCMPGTW ISA-set group IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "VPCMPGTW runtime-bit IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VPCMPGTW profile sweep");

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
            (unsigned int)instruction.last_error_id,
            (unsigned int)status);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_form_id expected_form(
    unsigned int l,
    int register_form)
{
    return (cdisasm_x86_form_id)(UINT16_C(6512) + 2u * l
        + (register_form ? 1u : 0u));
}

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

static cdisasm_x86_reg_id vector_reg(
    unsigned int l,
    unsigned int index)
{
    return (cdisasm_x86_reg_id)(
        (l != 0u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0)
        + index);
}

static void check_vpcmpgtw(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    unsigned int l,
    int register_form,
    unsigned int destination,
    unsigned int source1,
    unsigned int source2)
{
    const unsigned int vector_bytes = l != 0u ? 32u : 16u;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_VPCMPGTW);
    EXPECT(instruction->form_id == expected_form(l, register_form));
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

    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg == vector_reg(l, destination));
    EXPECT(instruction->opcode[0].size == vector_bytes);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[0].flags == 0u);
    EXPECT(instruction->opcode[0].broadcast
        == CDISASM_X86_BROADCAST_NONE);

    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg == vector_reg(l, source1));
    EXPECT(instruction->opcode[1].size == vector_bytes);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].flags == 0u);
    EXPECT(instruction->opcode[1].broadcast
        == CDISASM_X86_BROADCAST_NONE);

    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[2].size == vector_bytes);
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].broadcast
        == CDISASM_X86_BROADCAST_NONE);
    if (register_form) {
        EXPECT(instruction->opcode[2].reg == vector_reg(l, source2));
        EXPECT(instruction->opcode[2].flags == 0u);
    } else {
        EXPECT((instruction->opcode[2].flags
            & (CDISASM_OPERAND_FLAG_IMPLICIT
                | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                | CDISASM_OPERAND_FLAG_SIGNED)) == 0u);
    }

    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2) == (l != 0u));
    if (mode != CDISASM_MODE_64) {
        EXPECT(destination < 8u);
        EXPECT(source1 < 8u);
        EXPECT(!register_form || source2 < 8u);
    }
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t p0,
    unsigned int l,
    unsigned int vvvv,
    uint8_t modrm)
{
#if USE_EXTRA_OPCODES
    const int long_mode = mode == CDISASM_MODE_64;
    const int register_form = (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
    const unsigned int destination = ((unsigned int)modrm >> 3) & 7u;
    const unsigned int source1 = long_mode ? vvvv : vvvv & 7u;
    const unsigned int source2 = modrm & 7u;
    const unsigned int vector_bytes = l != 0u ? 32u : 16u;
    const cdisasm_x86_reg_id register_base = l != 0u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    const unsigned int extended_destination = destination
        + (long_mode && (p0 & UINT8_C(0x80)) == 0u ? 8u : 0u);
    const unsigned int extended_source2 = source2
        + (long_mode && (p0 & UINT8_C(0x20)) == 0u ? 8u : 0u);

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_VPCMPGTW);
    EXPECT(instruction->form_id == expected_form(l, register_form));
    EXPECT(instruction->operand_count == 3u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX))
        == CDISASM_PREFIX_VEX);
    EXPECT(instruction->opcode[0].reg
        == (cdisasm_x86_reg_id)(register_base + extended_destination));
    EXPECT(instruction->opcode[1].reg
        == (cdisasm_x86_reg_id)(register_base + source1));
    EXPECT(instruction->opcode[0].size == vector_bytes);
    EXPECT(instruction->opcode[1].size == vector_bytes);
    EXPECT(instruction->opcode[2].size == vector_bytes);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    if (register_form) {
        EXPECT(instruction->opcode[2].reg
            == (cdisasm_x86_reg_id)(register_base + extended_source2));
    }
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2) == (l != 0u));
#else
    (void)mode;
    (void)p0;
    (void)l;
    (void)vvvv;
    (void)modrm;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint64_t expected_form_counts[4] = {
        UINT64_C(82944), UINT64_C(27648),
        UINT64_C(82944), UINT64_C(27648)
    };
    uint64_t form_counts[4] = {0u, 0u, 0u, 0u};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;

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
                ? (uint8_t)((p0_index << 5) | 1u)
                : (uint8_t)(0xc1u | (p0_index << 5));
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
                                const int register_form =
                                    (modrm & UINT8_C(0xc0))
                                        == UINT8_C(0xc0);
                                const uint8_t code[15] = {
                                    0xc4, p0,
                                    (uint8_t)((w << 7)
                                        | (((~vvvv) & 15u) << 3)
                                        | (l << 2) | pp),
                                    0x65, (uint8_t)modrm,
                                    0x24,0x10,0x20,0x30,0x40,
                                    0x50,0x60,0x70,0x80,0x90
                                };
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

                                if (pp == 1u) {
                                    const unsigned int form_index =
                                        2u * l + (register_form ? 1u : 0u);

                                    check_allocated(&instruction, decoded_size,
                                        modes[mode_index], p0, l, vvvv,
                                        (uint8_t)modrm);
                                    ++form_counts[form_index];
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

    /* C5 adds every native map-1 spelling.  Outside long mode, only bytes
     * with encoded R'=1 and encoded vvvv[3]=1 are VEX rather than LDS. */
    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const cdisasm_x86_mode mode = modes[mode_index];
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags =
            cpu_flags(CDISASM_CPU_X86, mode);
#endif
        unsigned int p1;

        for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
            const unsigned int pp = p1 & 3u;
            const unsigned int l = (p1 >> 2) & 1u;
            const unsigned int vvvv = ((~p1) >> 3) & 15u;
            const uint8_t synthetic_p0 = (uint8_t)(
                ((p1 & UINT8_C(0x80)) != 0u ? UINT8_C(0xe0)
                                            : UINT8_C(0x60))
                | UINT8_C(1));
            unsigned int modrm;

            if (mode != CDISASM_MODE_64 && p1 < UINT8_C(0xc0)) {
                continue;
            }
            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const uint8_t code[14] = {
                    0xc5, (uint8_t)p1, 0x65, (uint8_t)modrm,
                    0x24,0x10,0x20,0x30,0x40,
                    0x50,0x60,0x70,0x80,0x90
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, mode, code, sizeof(code),
#if USE_EXTRA_OPCODES
                    &flags,
#else
                    NULL,
#endif
                    &decoded_size);

                if (pp == 1u) {
                    const unsigned int form_index =
                        2u * l + (register_form ? 1u : 0u);

                    check_allocated(&instruction, decoded_size,
                        mode, synthetic_p0, l, vvvv,
                        (uint8_t)modrm);
                    ++form_counts[form_index];
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

    EXPECT(allocated == UINT64_C(221184));
    EXPECT(reserved == UINT64_C(663552));
    for (mode_index = 0u; mode_index < 4u; ++mode_index) {
        EXPECT(form_counts[mode_index] == expected_form_counts[mode_index]);
    }
}

static void test_forms_modes_and_addresses(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t xmm_reg[] = {0xc4,0xe1,0x69,0x65,0xcb};
    static const uint8_t xmm_reg_w1[] = {0xc4,0xe1,0xe9,0x65,0xcb};
    static const uint8_t ymm_reg[] = {0xc4,0xe1,0x6d,0x65,0xcb};
    static const uint8_t c5_xmm_reg[] = {0xc5,0xe9,0x65,0xcb};
    static const uint8_t c5_ymm_mem[] = {0xc5,0xed,0x65,0x00};
    static const uint8_t c5_high_reg[] = {0xc5,0x29,0x65,0xcb};
    static const uint8_t high_reg[] = {0xc4,0x01,0x09,0x65,0xfd};
    static const uint8_t high_memory[] =
        {0xc4,0x21,0x69,0x65,0x44,0x58,0x20};
    static const uint8_t ymm_memory[] =
        {0xc4,0x61,0x6d,0x65,0x7c,0x8b,0xf0};
    static const uint8_t rip_relative[] =
        {0xc4,0xe1,0x69,0x65,0x05,0x78,0x56,0x34,0x12};
    static const uint8_t address_override[] =
        {0x67,0xc4,0xe1,0x69,0x65,0x00};
    static const uint8_t segment_override[] =
        {0x64,0xc4,0xe1,0x69,0x65,0x00};
    static const uint8_t duplicate_address[] =
        {0x67,0x67,0xc4,0xe1,0x69,0x65,0x00};
    static const uint8_t duplicate_segment[] =
        {0x64,0x65,0xc4,0xe1,0x69,0x65,0x00};
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    size_t mode_index;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        xmm_reg, sizeof(xmm_reg), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 1, 1u, 2u, 3u);
    EXPECT(instruction.x86_group_count == 1u);
    EXPECT(instruction.x86_group_ids[0] == CDISASM_X86_GROUP_AVX);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        xmm_reg_w1, sizeof(xmm_reg_w1), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 1, 1u, 2u, 3u);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        ymm_reg, sizeof(ymm_reg), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        1u, 1, 1u, 2u, 3u);
    EXPECT(instruction.x86_group_count == 2u);
    EXPECT(instruction.x86_group_ids[0] == CDISASM_X86_GROUP_AVX);
    EXPECT(instruction.x86_group_ids[1] == CDISASM_X86_GROUP_AVX2);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        c5_xmm_reg, sizeof(c5_xmm_reg), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 1, 1u, 2u, 3u);
    EXPECT(instruction.encoding.prefix_size == 2u);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        c5_ymm_mem, sizeof(c5_ymm_mem), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        1u, 0, 0u, 2u, 0u);
    EXPECT(instruction.encoding.prefix_size == 2u);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        c5_high_reg, sizeof(c5_high_reg), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 1, 9u, 10u, 3u);
    EXPECT(instruction.encoding.prefix_size == 2u);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        high_reg, sizeof(high_reg), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 1, 15u, 14u, 13u);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        high_memory, sizeof(high_memory), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 0, 8u, 2u, 0u);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R11);
    EXPECT(instruction.opcode[2].scale == 2u);
    EXPECT(instruction.opcode[2].imm == UINT64_C(0x20));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        ymm_memory, sizeof(ymm_memory), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        1u, 0, 15u, 2u, 0u);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RBX);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_RCX);
    EXPECT(instruction.opcode[2].scale == 4u);
    EXPECT(instruction.opcode[2].imm == (uint64_t)-INT64_C(16));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rip_relative, sizeof(rip_relative), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 0, 0u, 2u, 0u);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RIP);
    EXPECT(instruction.opcode[2].imm == UINT64_C(0x12345678));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        address_override, sizeof(address_override), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 0, 0u, 2u, 0u);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_EAX);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        segment_override, sizeof(segment_override), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 0, 0u, 2u, 0u);
    EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_FS);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        duplicate_address, sizeof(duplicate_address), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 0, 0u, 2u, 0u);
    EXPECT(instruction.encoding.prefix_size == 5u);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_EAX);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        duplicate_segment, sizeof(duplicate_segment), &flags, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 0, 0u, 2u, 0u);
    EXPECT(instruction.encoding.prefix_size == 5u);
    EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_GS);

    for (mode_index = 0u; mode_index < 2u; ++mode_index) {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32
        };
        static const uint8_t b_vvvv_alias[] =
            {0xc4,0xc1,0x29,0x65,0xfa};
        static const uint8_t canonical[] =
            {0xc4,0xe1,0x69,0x65,0xfa};
        static const uint8_t c5_canonical[] =
            {0xc5,0xe9,0x65,0xfa};
        cdisasm_x86_decode_flags mode_flags =
            cpu_flags(CDISASM_CPU_X86, modes[mode_index]);

        instruction = decode(CDISASM_CPU_X86, modes[mode_index],
            b_vvvv_alias, sizeof(b_vvvv_alias),
            &mode_flags, &decoded_size);
        check_vpcmpgtw(&instruction, decoded_size, modes[mode_index],
            0u, 1, 7u, 2u, 2u);
        instruction = decode(CDISASM_CPU_X86, modes[mode_index],
            c5_canonical, sizeof(c5_canonical),
            &mode_flags, &decoded_size);
        check_vpcmpgtw(&instruction, decoded_size, modes[mode_index],
            0u, 1, 7u, 2u, 2u);
        EXPECT(instruction.encoding.prefix_size == 2u);
        instruction = decode(CDISASM_CPU_X86, modes[mode_index],
            canonical, sizeof(canonical), &mode_flags, &decoded_size);
        check_vpcmpgtw(&instruction, decoded_size, modes[mode_index],
            0u, 1, 7u, 2u, 2u);
    }
#endif
}

static void test_runtime_profiles_and_extras(void)
{
    static const uint8_t xmm[] = {0xc4,0xe1,0x69,0x65,0xcb};
    static const uint8_t ymm[] = {0xc4,0xe1,0x6d,0x65,0xcb};

#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags none = selected_flags(0, 0);
    cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);
    cdisasm_x86_decode_flags both = selected_flags(1, 1);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    cdisasm_x86_cpu_id cpu_id;
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;

    expect_error("VPCMPGTW XMM needs AVX", CDISASM_CPU_X86,
        CDISASM_MODE_64, xmm, sizeof(xmm), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        xmm, sizeof(xmm), &avx, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 1, 1u, 2u, 3u);
    expect_error("AVX2 bit is not the XMM AVX bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, xmm, sizeof(xmm), &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX bit is not the YMM AVX2 bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, ymm, sizeof(ymm), &avx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        ymm, sizeof(ymm), &avx2, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        1u, 1, 1u, 2u, 3u);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        ymm, sizeof(ymm), &both, &decoded_size);
    check_vpcmpgtw(&instruction, decoded_size, CDISASM_MODE_64,
        1u, 1, 1u, 2u, 3u);

    for (cpu_id = CDISASM_CPU_FIRST; cpu_id <= CDISASM_CPU_LAST; ++cpu_id) {
        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            const cdisasm_x86_mode mode = modes[mode_index];
            cdisasm_x86_decode_flags profile_flags =
                CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
            const int mask_ok = cdisasm_x86_cpu_decode_flag_mask(
                cpu_id, mode, &profile_flags) == CDISASM_STATUS_OK;
            const int has_avx = cdisasm_decode_flags_test_bit(
                &profile_flags, CDISASM_X86_DECODE_BIT_AVX);
            const int has_avx2 = cdisasm_decode_flags_test_bit(
                &profile_flags, CDISASM_X86_DECODE_BIT_AVX2);

            /* Early named profiles reject modes they predate.  Exercise
             * every supported profile/mode pair and skip only those API-
             * invalid combinations. */
            if (!mask_ok) {
                continue;
            }
            if (has_avx) {
                instruction = decode(cpu_id, mode, xmm, sizeof(xmm),
                    &profile_flags, &decoded_size);
                check_vpcmpgtw(&instruction, decoded_size, mode,
                    0u, 1, 1u, 2u, 3u);
            } else {
                expect_error("profile lacks AVX", cpu_id, mode,
                    xmm, sizeof(xmm), &profile_flags,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
            if (has_avx2) {
                instruction = decode(cpu_id, mode, ymm, sizeof(ymm),
                    &profile_flags, &decoded_size);
                check_vpcmpgtw(&instruction, decoded_size, mode,
                    1u, 1, 1u, 2u, 3u);
            } else {
                expect_error("profile lacks AVX2", cpu_id, mode,
                    ymm, sizeof(ymm), &profile_flags,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }
    }
#else
    expect_error("VPCMPGTW XMM extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, xmm, sizeof(xmm), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VPCMPGTW YMM extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, ymm, sizeof(ymm), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_prefixes_truncation_and_neighbors(void)
{
    static const uint8_t complete[] = {0xc4,0xe1,0x69,0x65,0xcb};
    static const uint8_t legacy_prefixes[5] = {0x66,0xf2,0xf3,0xf0,0x48};
    size_t index;

    for (index = 1u; index < sizeof(complete); ++index) {
        expect_error("truncated VPCMPGTW", CDISASM_CPU_X86,
            CDISASM_MODE_64, complete, index, NULL,
            CDISASM_STATUS_TRUNCATED);
    }
    expect_error("reserved pp missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x68,0x65,0x04}, 5u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp complete SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x68,0x65,0x04,0x24}, 6u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved pp missing disp8", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x6b,0x65,0x44,0x24}, 6u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp complete disp8", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x6b,0x65,0x44,0x24,0x7f}, 7u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    for (index = 0u; index < sizeof(legacy_prefixes); ++index) {
        const uint8_t prefixed[] = {
            legacy_prefixes[index],0xc4,0xe1,0x69,0x65,0x04,0x24
        };
        const uint8_t c5_prefixed[] = {
            legacy_prefixes[index],0xc5,0xe9,0x65,0x04,0x24
        };

        expect_error("prefixed VPCMPGTW missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64, prefixed, sizeof(prefixed) - 1u, NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("prefixed VPCMPGTW complete", CDISASM_CPU_X86,
            CDISASM_MODE_64, prefixed, sizeof(prefixed), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("prefixed C5 VPCMPGTW missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64, c5_prefixed,
            sizeof(c5_prefixed) - 1u, NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("prefixed C5 VPCMPGTW complete", CDISASM_CPU_X86,
            CDISASM_MODE_64, c5_prefixed, sizeof(c5_prefixed), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 1u; index < 5u; ++index) {
        static const uint8_t c5_payload[] = {0xc5,0xe9,0x65,0x04,0x24};

        expect_error("truncated C5 VPCMPGTW", CDISASM_CPU_X86,
            CDISASM_MODE_64, c5_payload, index, NULL,
            CDISASM_STATUS_TRUNCATED);
    }
    expect_error("reserved C5 pp missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xe8,0x65,0x04}, 4u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved C5 pp complete SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xe8,0x65,0x04,0x24}, 5u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("C4 map 2 is not VPCMPGTW", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x69,0x65,0xd3}, 5u, NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        static const uint8_t legacy[] = {0x66,0x0f,0x65,0xcb};
        static const uint8_t evex[] = {0x62,0xf1,0xed,0x08,0x65,0xcb};
        static const uint8_t evex_w0[] =
            {0x62,0xf1,0x6d,0x08,0x65,0xcb};
        static const uint8_t evex_b_reserved[] =
            {0x62,0xf1,0xed,0x18,0x65,0x00};
        static const uint8_t evex_b_truncated_sib[] =
            {0x62,0xf1,0xed,0x18,0x65,0x04};
        static const uint8_t evex_z_reserved[] =
            {0x62,0xf1,0xed,0x8a,0x65,0xcb};
        static const uint8_t low_neighbor[] = {0xc4,0xe1,0x69,0x64,0xcb};
        static const uint8_t high_neighbor[] = {0xc4,0xe1,0x69,0x66,0xcb};
        static const uint8_t r_collision[] =
            {0xc4,0x61,0x69,0x65,0xcb,0,0,0,0};
        static const uint8_t x_collision[] =
            {0xc4,0xa1,0x69,0x65,0xcb,0,0,0,0};
        static const uint8_t c5_r_collision[] =
            {0xc5,0x29,0x65,0xcb,0,0,0,0};
        static const uint8_t c5_vvvv_collision[] =
            {0xc5,0xa9,0x65,0xcb,0,0,0,0};
        cdisasm_x86_decode_flags flags64 =
            cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
        cdisasm_x86_decode_flags flags16 =
            cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags32 =
            cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_32);
        cdisasm_instruction instruction;
        uint32_t decoded_size;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy, sizeof(legacy), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PCMPGTW);
        EXPECT((instruction.opcode_flags
            & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX)) == 0u);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex, sizeof(evex), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(evex));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPCMPGTW);
        EXPECT(instruction.form_id >= UINT16_C(6506)
            && instruction.form_id <= UINT16_C(6511));
        EXPECT((instruction.opcode_flags
            & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX))
            == CDISASM_PREFIX_EVEX);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_w0, sizeof(evex_w0), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(evex_w0));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPCMPGTW);
        EXPECT(instruction.form_id == UINT16_C(6507));
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
        expect_error("EVEX VPCMPGTW b is reserved", CDISASM_CPU_X86,
            CDISASM_MODE_64, evex_b_reserved, sizeof(evex_b_reserved),
            &flags64, CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("EVEX VPCMPGTW b missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64, evex_b_truncated_sib,
            sizeof(evex_b_truncated_sib), &flags64,
            CDISASM_STATUS_TRUNCATED);
        expect_error("EVEX VPCMPGTW z is reserved", CDISASM_CPU_X86,
            CDISASM_MODE_64, evex_z_reserved, sizeof(evex_z_reserved),
            &flags64, CDISASM_STATUS_INVALID_INSTRUCTION);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            low_neighbor, sizeof(low_neighbor), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(low_neighbor));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPCMPGTB);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            high_neighbor, sizeof(high_neighbor), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(high_neighbor));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPCMPGTD);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_16,
            r_collision, sizeof(r_collision), &flags16, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_16,
            c5_r_collision, sizeof(c5_r_collision),
            &flags16, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LDS);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
            c5_vvvv_collision, sizeof(c5_vvvv_collision),
            &flags32, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LDS);
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
        uint8_t code[8];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4,0xe1,0x69,0x65,0xcb,0,0,0},5u,
            "vpcmpgtw xmm1, xmm2, xmm3",
            "vpcmpgtw %xmm3, %xmm2, %xmm1"},
        {{0xc4,0xe1,0xed,0x65,0xcb,0,0,0},5u,
            "vpcmpgtw ymm1, ymm2, ymm3",
            "vpcmpgtw %ymm3, %ymm2, %ymm1"},
        {{0xc4,0x21,0x69,0x65,0x44,0x58,0x20,0},7u,
            "vpcmpgtw xmm8, xmm2, xmmword ptr [rax + r11*2 + 0x20]",
            "vpcmpgtw 0x20(%rax,%r11,2), %xmm2, %xmm8"},
        {{0xc4,0x61,0x6d,0x65,0x7c,0x8b,0xf0,0},7u,
            "vpcmpgtw ymm15, ymm2, ymmword ptr [rbx + rcx*4 - 0x10]",
            "vpcmpgtw -0x10(%rbx,%rcx,4), %ymm2, %ymm15"},
        {{0x62,0xf1,0xed,0x08,0x65,0x00,0,0},6u,
            "vpcmpgtw k0, xmm2, xmmword ptr [rax]",
            "vpcmpgtw (%rax), %xmm2, %k0"},
        {{0x62,0xf1,0xed,0x08,0x65,0xcb,0,0},6u,
            "vpcmpgtw k1, xmm2, xmm3",
            "vpcmpgtw %xmm3, %xmm2, %k1"},
        {{0x62,0xf1,0xed,0x28,0x65,0x00,0,0},6u,
            "vpcmpgtw k0, ymm2, ymmword ptr [rax]",
            "vpcmpgtw (%rax), %ymm2, %k0"},
        {{0x62,0xf1,0xed,0x28,0x65,0xcb,0,0},6u,
            "vpcmpgtw k1, ymm2, ymm3",
            "vpcmpgtw %ymm3, %ymm2, %k1"},
        {{0x62,0xf1,0xed,0x48,0x65,0x00,0,0},6u,
            "vpcmpgtw k0, zmm2, zmmword ptr [rax]",
            "vpcmpgtw (%rax), %zmm2, %k0"},
        {{0x62,0xf1,0xed,0x48,0x65,0xcb,0,0},6u,
            "vpcmpgtw k1, zmm2, zmm3",
            "vpcmpgtw %zmm3, %zmm2, %k1"},
        {{0x62,0xf1,0xed,0x0a,0x65,0x00,0,0},6u,
            "vpcmpgtw k0 {k2}, xmm2, xmmword ptr [rax]",
            "vpcmpgtw (%rax), %xmm2, %k0{%k2}"},
        {{0xc5,0xe9,0x65,0xcb,0,0,0,0},4u,
            "vpcmpgtw xmm1, xmm2, xmm3",
            "vpcmpgtw %xmm3, %xmm2, %xmm1"},
        {{0xc5,0xed,0x65,0x00,0,0,0,0},4u,
            "vpcmpgtw ymm0, ymm2, ymmword ptr [rax]",
            "vpcmpgtw (%rax), %ymm2, %ymm0"}
    };
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_instruction instruction;
        uint32_t decoded_size;
        char output[192];
        char tiny[4] = {'x','x','x','x'};
        size_t required;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        EXPECT(decoded_size == cases[index].size);
        if (index >= 4u && index < 11u) {
            const unsigned int evex_case = (unsigned int)(index - 4u);
            const unsigned int width = evex_case < 6u
                ? evex_case / 2u : 0u;

            EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
                UINT16_C(6506) + (evex_case < 6u ? evex_case : 0u)));
            EXPECT(instruction.opcode_flags
                == (CDISASM_PREFIX_EVEX
                    | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK));
            EXPECT(instruction.operand_count == 3u);
            EXPECT(instruction.opcode[0].type
                == CDISASM_OPERAND_REGISTER);
            EXPECT(instruction.opcode[0].size == 8u);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.opcode[1].size == (16u << width));
            EXPECT(instruction.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.x86_group_count == 1u);
            EXPECT(instruction.x86_group_ids[0]
                == (width == 0u ? CDISASM_X86_GROUP_AVX512BW_128
                    : width == 1u ? CDISASM_X86_GROUP_AVX512BW_256
                                  : CDISASM_X86_GROUP_AVX512BW_512));
        }
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, NULL, 0u);
        EXPECT(required == strlen(cases[index].intel));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output)) == required);
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, tiny, sizeof(tiny)) == required);
        EXPECT(tiny[sizeof(tiny) - 1u] == '\0');
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT, NULL, 0u);
        EXPECT(required == strlen(cases[index].att));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT, output, sizeof(output)) == required);
        EXPECT(strcmp(output, cases[index].att) == 0);
    }

    {
        static const uint8_t code[] = {0xc4,0xe1,0x69,0x65,0xcb};
        cdisasm_instruction valid;
        cdisasm_instruction forged;
        uint32_t decoded_size;

        valid = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(code));
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_ADD;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(6516);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(6512);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.operand_count = 2u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |= CDISASM_PREFIX_OPERAND_SIZE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].size = 32u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].reg = CDISASM_X86_REG_YMM2;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].broadcast = CDISASM_X86_BROADCAST_1_TO_2;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].type = CDISASM_OPERAND_MEMORY;
        forged.opcode[2].reg = CDISASM_X86_REG_NONE;
        forged.opcode[2].base_reg = CDISASM_X86_REG_RAX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.mask_reg = CDISASM_X86_REG_K1;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.immediate_count = 1u;
        forged.encoding.immediate_offset[0] = 5u;
        forged.encoding.immediate_size[0] = 1u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_AVX2;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_groups = CDISASM_GROUP_PRIVILEGED;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.branch_target = UINT64_C(0x1234);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.rounding = CDISASM_X86_ROUNDING_RN;
        forged.sae = CDISASM_X86_SAE_ENABLED;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.prefix_size = 1u;
        forged.encoding.opcode_offset = 1u;
        forged.encoding.modrm_offset = 2u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        ++forged.encoding.opcode_offset;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.opcode_size = 2u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.modrm ^= UINT8_C(8);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.sib_offset = 1u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(6507);
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX
            | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VPCMPGTQ;
        expect_forged_format_rejected(&forged);
    }

    {
        static const uint8_t c5_register_code[] = {0xc5,0xe9,0x65,0xcb};
        static const uint8_t c5_memory_code[] = {0xc5,0xe9,0x65,0x00};
        cdisasm_instruction valid;
        cdisasm_instruction forged;
        uint32_t decoded_size;

        valid = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            c5_register_code, sizeof(c5_register_code),
            &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(c5_register_code));
        EXPECT(valid.form_id == UINT16_C(6513));
        EXPECT(valid.encoding.prefix_size == 2u);
        forged = valid;
        forged.opcode[2].reg = CDISASM_X86_REG_XMM11;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.prefix_size = 1u;
        forged.encoding.opcode_offset = 1u;
        forged.encoding.modrm_offset = 2u;
        expect_forged_format_rejected(&forged);

        valid = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            c5_memory_code, sizeof(c5_memory_code),
            &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(c5_memory_code));
        EXPECT(valid.form_id == UINT16_C(6512));
        EXPECT(valid.encoding.prefix_size == 2u);
        forged = valid;
        forged.opcode[2].base_reg = CDISASM_X86_REG_R8;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].index_reg = CDISASM_X86_REG_R9;
        forged.opcode[2].scale = 2u;
        expect_forged_format_rejected(&forged);
    }

    {
        static const uint8_t memory_code[] = {
            0x64,0x67,0xc4,0xe1,0x71,0x65,0x44,0x24,0x20};
        cdisasm_instruction valid;
        cdisasm_instruction forged;
        uint32_t decoded_size;

        valid = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            memory_code, sizeof(memory_code), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(memory_code));
        EXPECT(valid.form_id == UINT16_C(6512));
        forged = valid;
        forged.opcode[2].flags &= ~CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].segment_reg = CDISASM_X86_REG_NONE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags &= ~CDISASM_PREFIX_SEGMENT;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.prefix_size = 4u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.modrm |= UINT8_C(0xc0);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].base_reg = CDISASM_X86_REG_RAX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].flags |= CDISASM_OPERAND_FLAG_SIGNED;
        expect_forged_format_rejected(&forged);
    }

    {
        static const uint8_t evex_code[] = {
            0x62,0xf1,0xed,0x08,0x65,0xcb};
        cdisasm_instruction valid;
        cdisasm_instruction forged;
        uint32_t decoded_size;

        valid = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_code, sizeof(evex_code), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(evex_code));
        EXPECT(valid.form_id == UINT16_C(6507));
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_ADD;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(6506);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(6512);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags &=
            ~CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.operand_count = 2u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].size = 16u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].type = CDISASM_OPERAND_MEMORY;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].size = 32u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.mask_mode = CDISASM_X86_MASK_ZERO;
        forged.mask_reg = CDISASM_X86_REG_K2;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.rounding = CDISASM_X86_ROUNDING_RN;
        forged.sae = CDISASM_X86_SAE_ENABLED;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_groups = CDISASM_GROUP_PRIVILEGED;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.branch_target = UINT64_C(0x1234);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.prefix_size = 3u;
        forged.encoding.opcode_offset = 3u;
        forged.encoding.modrm_offset = 4u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.opcode_size = 2u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.modrm ^= UINT8_C(8);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.immediate_count = 1u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.selector_offset = 1u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_AVX512F_256;
        expect_forged_format_rejected(&forged);
    }

    {
        static const uint8_t evex_memory_code[] = {
            0x64,0x62,0xf1,0xed,0x0a,0x65,0x00};
        cdisasm_instruction valid;
        cdisasm_instruction forged;
        uint32_t decoded_size;

        valid = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_memory_code, sizeof(evex_memory_code),
            &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(evex_memory_code));
        EXPECT(valid.form_id == UINT16_C(6506));
        EXPECT(valid.opcode[2].size == 16u);
        EXPECT(valid.opcode[2].broadcast
            == CDISASM_X86_BROADCAST_NONE);
        forged = valid;
        forged.opcode[2].flags &= ~CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].segment_reg = CDISASM_X86_REG_NONE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags &= ~CDISASM_PREFIX_SEGMENT;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].broadcast = CDISASM_X86_BROADCAST_1_TO_4;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].size = 8u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].flags |= CDISASM_OPERAND_FLAG_SIGNED;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.modrm = UINT8_C(0x08);
        expect_forged_format_rejected(&forged);
    }
#endif
}

int main(void)
{
    test_control_partition();
    test_forms_modes_and_addresses();
    test_runtime_profiles_and_extras();
    test_prefixes_truncation_and_neighbors();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "x86 VPCMPGTW tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 VPCMPGTW tests passed");
    return 0;
}
