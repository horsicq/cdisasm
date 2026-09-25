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

_Static_assert(CDISASM_X86_NAME_VDPPD == UINT16_C(1639)
        && CDISASM_X86_NAME_VDPPS == UINT16_C(1641),
    "VDPP name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VDPP AVX IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VDPP profile sweeps");

static const uint8_t dot_opcodes[2] = {0x41, 0x40};

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

static cdisasm_x86_reg_id vector_reg(
    unsigned int vector_bits,
    unsigned int index)
{
    const cdisasm_x86_reg_id base = vector_bits == 256u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;

    return (cdisasm_x86_reg_id)(base + index);
}

static cdisasm_x86_form_id expected_form(
    unsigned int family,
    unsigned int vector_bits,
    int register_form)
{
    const cdisasm_x86_form_id base = family == 0u
        ? UINT16_C(4507) : UINT16_C(4515);

    return (cdisasm_x86_form_id)(base
        + (family != 0u && vector_bits == 256u ? 2u : 0u)
        + (register_form ? 1u : 0u));
}

static unsigned int form_count_index(cdisasm_x86_form_id form_id)
{
    return form_id <= UINT16_C(4508)
        ? (unsigned int)(form_id - UINT16_C(4507))
        : 2u + (unsigned int)(form_id - UINT16_C(4515));
}

static void check_dot(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    unsigned int family,
    unsigned int vector_bits,
    int register_form,
    unsigned int destination,
    unsigned int source1,
    unsigned int source2,
    uint64_t immediate)
{
    const cdisasm_x86_name_id name_id = family == 0u
        ? CDISASM_X86_NAME_VDPPD : CDISASM_X86_NAME_VDPPS;
    const cdisasm_x86_form_id form_id = expected_form(
        family, vector_bits, register_form);
    const unsigned int vector_size = vector_bits / 8u;
    const cdisasm_x86_reg_id register_base = vector_bits == 256u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    size_t index;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == name_id);
    EXPECT(instruction->form_id == form_id);
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
    EXPECT(instruction->encoding.prefix_size >= 3u);
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
        EXPECT(operand->size == vector_size);
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
    EXPECT(instruction->opcode[0].reg
        == vector_reg(vector_bits, destination));
    EXPECT(instruction->opcode[1].reg
        == vector_reg(vector_bits, source1));
    if (register_form) {
        EXPECT(instruction->opcode[2].reg
            == vector_reg(vector_bits, source2));
    }
    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[3].size == 1u);
    EXPECT(instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[3].flags == 0u);
    EXPECT(instruction->opcode[3].broadcast
        == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[3].imm == immediate);
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

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    unsigned int family,
    unsigned int vector_bits,
    int register_form)
{
#if USE_EXTRA_OPCODES
    const cdisasm_x86_form_id form_id = expected_form(
        family, vector_bits, register_form);

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (family == 0u
        ? CDISASM_X86_NAME_VDPPD : CDISASM_X86_NAME_VDPPS));
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->operand_count == 4u);
    EXPECT(instruction->opcode[0].size == vector_bits / 8u);
    EXPECT(instruction->opcode[1].size == vector_bits / 8u);
    EXPECT(instruction->opcode[2].size == vector_bits / 8u);
    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->encoding.immediate_count == 1u);
    EXPECT(instruction->encoding.immediate_offset[0]
        == decoded_size - UINT32_C(1));
    if (mode != CDISASM_MODE_64) {
        const cdisasm_x86_reg_id base = vector_bits == 256u
            ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;

        EXPECT(instruction->opcode[0].reg <= base + 7u);
        EXPECT(instruction->opcode[1].reg <= base + 7u);
        EXPECT(!register_form || instruction->opcode[2].reg <= base + 7u);
    }
#else
    (void)mode;
    (void)family;
    (void)vector_bits;
    (void)register_form;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_complete_c4_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const uint64_t expected_form_counts[6] = {
        UINT64_C(73728), UINT64_C(24576),
        UINT64_C(73728), UINT64_C(24576),
        UINT64_C(73728), UINT64_C(24576)};
    uint64_t form_counts[6] = {0u};
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
                ? (uint8_t)((p0_index << 5) | 3u)
                : (uint8_t)(0xc3u | (p0_index << 5));
            unsigned int family;

            for (family = 0u; family < 2u; ++family) {
                unsigned int w;

                for (w = 0u; w < 2u; ++w) {
                    unsigned int l;

                    for (l = 0u; l < 2u; ++l) {
                        unsigned int pp;

                        for (pp = 0u; pp < 4u; ++pp) {
                            unsigned int vvvv;

                            for (vvvv = 0u; vvvv < 16u; ++vvvv) {
                                unsigned int modrm;

                                for (modrm = 0u; modrm <= UINT8_MAX;
                                     ++modrm) {
                                    const int register_form =
                                        (modrm & UINT8_C(0xc0))
                                            == UINT8_C(0xc0);
                                    const int valid = pp == 1u
                                        && (family != 0u || l == 0u);
                                    const unsigned int vector_bits =
                                        l != 0u ? 256u : 128u;
                                    const uint8_t code[15] = {
                                        0xc4, p0,
                                        (uint8_t)((w << 7)
                                            | (((~vvvv) & 15u) << 3)
                                            | (l << 2) | pp),
                                        dot_opcodes[family],
                                        (uint8_t)modrm, 0x24, 0x10, 0x20,
                                        0x30, 0x40, 0x50, 0x60, 0x70,
                                        0x80, 0x90};
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
                                            modes[mode_index], family,
                                            vector_bits, register_form);
#if USE_EXTRA_OPCODES
                                        EXPECT(instruction.opcode[3].imm
                                            == code[decoded_size - 1u]);
                                        ++form_counts[form_count_index(
                                            instruction.form_id)];
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
            }
        }
    }

    EXPECT(allocated == UINT64_C(294912));
    EXPECT(reserved == UINT64_C(1277952));
#if USE_EXTRA_OPCODES
    for (mode_index = 0u; mode_index < 6u; ++mode_index) {
        EXPECT(form_counts[mode_index] == expected_form_counts[mode_index]);
    }
#else
    (void)expected_form_counts;
    (void)form_counts;
#endif
}

static void test_c5_exclusion_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    uint64_t probes = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const unsigned int p1_start = modes[mode_index] == CDISASM_MODE_64
            ? 0u : 0xc0u;
        unsigned int family;

        for (family = 0u; family < 2u; ++family) {
            unsigned int p1;

            for (p1 = p1_start; p1 <= UINT8_MAX; ++p1) {
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const uint8_t code[15] = {
                        0xc5, (uint8_t)p1, dot_opcodes[family],
                        (uint8_t)modrm, 0x24, 0x10, 0x20, 0x30,
                        0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0};
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, modes[mode_index],
                        code, sizeof(code), NULL, &decoded_size);

                    EXPECT(decoded_size == 0u
                        || (instruction.name_id != CDISASM_X86_NAME_VDPPD
                            && instruction.name_id
                                != CDISASM_X86_NAME_VDPPS));
                    ++probes;
                }
            }
        }
    }
    EXPECT(probes == UINT64_C(196608));
}

static void test_forms_addresses_aliases_and_immediates(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t pd_memory[] =
        {0xc4,0xe3,0x71,0x41,0x00,0x5a};
    static const uint8_t pd_register[] =
        {0xc4,0xe3,0xe9,0x41,0xcb,0xa5};
    static const uint8_t ps_xmm_register[] =
        {0xc4,0xe3,0x69,0x40,0xcb,0xc3};
    static const uint8_t ps_ymm_memory[] =
        {0xc4,0xe3,0xf5,0x40,0x40,0x7f,0x3c};
    static const uint8_t pd_high_registers[] =
        {0xc4,0x43,0xe9,0x41,0xfb,0xff};
    static const uint8_t ps_high_sib[] =
        {0xc4,0x03,0x35,0x40,0x44,0xa5,0x80,0x7e};
    static const uint8_t rip_relative[] =
        {0xc4,0xe3,0x71,0x41,0x05,0x78,0x56,0x34,0x12,0x11};
    static const uint8_t address_override[] =
        {0x67,0xc4,0xe3,0x71,0x40,0x00,0x22};
    static const uint8_t segment_override[] =
        {0x64,0xc4,0xe3,0x71,0x41,0x00,0x33};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    unsigned int immediate;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        pd_memory, sizeof(pd_memory), &flags, &decoded_size);
    check_dot(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 128u, 0, 0u, 1u, 0u, 0x5au);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        pd_register, sizeof(pd_register), &flags, &decoded_size);
    check_dot(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 128u, 1, 1u, 2u, 3u, 0xa5u);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        ps_xmm_register, sizeof(ps_xmm_register), &flags, &decoded_size);
    check_dot(&instruction, decoded_size, CDISASM_MODE_64,
        1u, 128u, 1, 1u, 2u, 3u, 0xc3u);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        ps_ymm_memory, sizeof(ps_ymm_memory), &flags, &decoded_size);
    check_dot(&instruction, decoded_size, CDISASM_MODE_64,
        1u, 256u, 0, 0u, 1u, 0u, 0x3cu);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[2].imm == UINT64_C(0x7f));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        pd_high_registers, sizeof(pd_high_registers), &flags, &decoded_size);
    check_dot(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 128u, 1, 15u, 2u, 11u, 0xffu);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        ps_high_sib, sizeof(ps_high_sib), &flags, &decoded_size);
    check_dot(&instruction, decoded_size, CDISASM_MODE_64,
        1u, 256u, 0, 8u, 9u, 0u, 0x7eu);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R13);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R12);
    EXPECT(instruction.opcode[2].scale == 4u);
    EXPECT(instruction.opcode[2].imm == (uint64_t)-INT64_C(128));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rip_relative, sizeof(rip_relative), &flags, &decoded_size);
    check_dot(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 128u, 0, 0u, 1u, 0u, 0x11u);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RIP);
    EXPECT(instruction.opcode[2].imm == UINT64_C(0x12345678));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        address_override, sizeof(address_override), &flags, &decoded_size);
    check_dot(&instruction, decoded_size, CDISASM_MODE_64,
        1u, 128u, 0, 0u, 1u, 0u, 0x22u);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_EAX);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        segment_override, sizeof(segment_override), &flags, &decoded_size);
    check_dot(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 128u, 0, 0u, 1u, 0u, 0x33u);
    EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_FS);

    for (immediate = 0u; immediate <= UINT8_MAX; ++immediate) {
        uint8_t pd[] = {0xc4,0xe3,0x69,0x41,0xc2,(uint8_t)immediate};
        uint8_t ps[] = {0xc4,0xe3,0x6d,0x40,0xc2,(uint8_t)immediate};

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            pd, sizeof(pd), &flags, &decoded_size);
        check_dot(&instruction, decoded_size, CDISASM_MODE_64,
            0u, 128u, 1, 0u, 2u, 2u, immediate);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            ps, sizeof(ps), &flags, &decoded_size);
        check_dot(&instruction, decoded_size, CDISASM_MODE_64,
            1u, 256u, 1, 0u, 2u, 2u, immediate);
    }

    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        static const uint8_t known_b_alias[] =
            {0xc4,0xc3,0x71,0x41,0xc2,0x01};
        static const uint8_t b_vvvv_alias[] =
            {0xc4,0xc3,0x31,0x40,0xc2,0x5a};
        size_t index;

        for (index = 0u; index < 2u; ++index) {
            cdisasm_x86_decode_flags mode_flags = all_flags(modes[index]);

            instruction = decode(CDISASM_CPU_X86, modes[index],
                known_b_alias, sizeof(known_b_alias),
                &mode_flags, &decoded_size);
            check_dot(&instruction, decoded_size, modes[index],
                0u, 128u, 1, 0u, 1u, 2u, 0x01u);
            instruction = decode(CDISASM_CPU_X86, modes[index],
                b_vvvv_alias, sizeof(b_vvvv_alias),
                &mode_flags, &decoded_size);
            check_dot(&instruction, decoded_size, modes[index],
                1u, 128u, 1, 0u, 1u, 2u, 0x5au);
        }
    }
#endif
}

static void test_runtime_and_profile_gates(void)
{
    static const uint8_t pd[] = {0xc4,0xe3,0x69,0x41,0xc2,0x5a};
    static const uint8_t ps_ymm[] = {0xc4,0xe3,0x6d,0x40,0xc2,0xa5};

#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags avx = one_bit(CDISASM_X86_DECODE_BIT_AVX);
    cdisasm_x86_decode_flags avx2 = one_bit(CDISASM_X86_DECODE_BIT_AVX2);
    cdisasm_x86_decode_flags sandy;
    cdisasm_x86_decode_flags westmere;
    cdisasm_x86_decode_flags bulldozer;
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        pd, sizeof(pd), &avx, &decoded_size);
    check_dot(&instruction, decoded_size, CDISASM_MODE_64,
        0u, 128u, 1, 0u, 2u, 2u, 0x5au);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        ps_ymm, sizeof(ps_ymm), &avx, &decoded_size);
    check_dot(&instruction, decoded_size, CDISASM_MODE_64,
        1u, 256u, 1, 0u, 2u, 2u, 0xa5u);
    expect_error("VDPP needs AVX", CDISASM_CPU_X86, CDISASM_MODE_64,
        pd, sizeof(pd), NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX2 alone does not admit VDPP", CDISASM_CPU_X86,
        CDISASM_MODE_64, pd, sizeof(pd), &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64, &sandy)
        == CDISASM_STATUS_OK);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_WESTMERE, CDISASM_MODE_64, &westmere)
        == CDISASM_STATUS_OK);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_BULLDOZER, CDISASM_MODE_64, &bulldozer)
        == CDISASM_STATUS_OK);
    instruction = decode(CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
        ps_ymm, sizeof(ps_ymm), &sandy, &decoded_size);
    EXPECT(decoded_size == sizeof(ps_ymm));
    instruction = decode(CDISASM_CPU_BULLDOZER, CDISASM_MODE_64,
        pd, sizeof(pd), &bulldozer, &decoded_size);
    EXPECT(decoded_size == sizeof(pd));
    expect_error("Westmere VDPP gate", CDISASM_CPU_WESTMERE,
        CDISASM_MODE_64, pd, sizeof(pd), &westmere,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    expect_error("VDPPD extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, pd, sizeof(pd), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VDPPS extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, ps_ymm, sizeof(ps_ymm), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_truncation_and_siblings(void)
{
    static const uint8_t legacy_prefixes[5] = {0x66,0xf2,0xf3,0xf0,0x48};
    size_t family;
    size_t index;

    for (family = 0u; family < 2u; ++family) {
        uint8_t complete[] = {
            0xc4,0xe3,0x69,dot_opcodes[family],0xc2,0x5a};

        for (index = 1u; index < sizeof(complete); ++index) {
            expect_error("truncated VDPP", CDISASM_CPU_X86,
                CDISASM_MODE_64, complete, index, NULL,
                CDISASM_STATUS_TRUNCATED);
        }
        for (index = 0u; index < sizeof(legacy_prefixes); ++index) {
            uint8_t prefixed[] = {
                legacy_prefixes[index],0xc4,0xe3,0x69,
                dot_opcodes[family],0x04,0x24,0x5a};

            expect_error("prefixed VDPP missing SIB", CDISASM_CPU_X86,
                CDISASM_MODE_64, prefixed, 6u, NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed VDPP missing imm8", CDISASM_CPU_X86,
                CDISASM_MODE_64, prefixed, 7u, NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed complete VDPP", CDISASM_CPU_X86,
                CDISASM_MODE_64, prefixed, sizeof(prefixed), NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }

        for (index = 0u; index < 4u; ++index) {
            if (index != 1u) {
                uint8_t wrong_pp[] = {
                    0xc4,0xe3,(uint8_t)(0x68u | index),
                    dot_opcodes[family],0xc2,0x5a};

                expect_error("VDPP reserved pp", CDISASM_CPU_X86,
                    CDISASM_MODE_64, wrong_pp, sizeof(wrong_pp), NULL,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }
    }

    expect_error("VDPPD L1", CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x6d,0x41,0xc2,0x5a}, 6u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VDPP wrong map", CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe4,0x69,0x40,0xc2,0x5a}, 6u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VDPP missing SIB", CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x69,0x40,0x04}, 5u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("VDPP missing disp32", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x69,0x41,0x05,0x10,0x20}, 7u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("VDPP reserved pp missing immediate", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x68,0x40,0xc2}, 5u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("VDPPD L1 missing immediate", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe3,0x6d,0x41,0xc2}, 5u, NULL,
        CDISASM_STATUS_TRUNCATED);

    {
        static const uint8_t legacy_pd[] =
            {0x66,0x0f,0x3a,0x41,0xc2,0x01};
        static const uint8_t legacy_ps[] =
            {0x66,0x0f,0x3a,0x40,0xc2,0x02};
        static const uint8_t evex_pd[] =
            {0x62,0xf3,0xed,0x08,0x41,0xc2,0x01};
        static const uint8_t evex_ps[] =
            {0x62,0xf3,0x6d,0x08,0x40,0xc2,0x02};
        static const uint8_t c5_pd[] = {0xc5,0xe9,0x41,0xc2,0x01};
        static const uint8_t c5_ps[] = {0xc5,0xe9,0x40,0xc2,0x02};
        static const uint8_t r_collision[10] =
            {0xc4,0x63,0x69,0x41,0xc2,0x01,0,0,0,0};
        static const uint8_t x_collision[10] =
            {0xc4,0xa3,0x69,0x40,0xc2,0x02,0,0,0,0};
        cdisasm_x86_decode_flags sibling_flags =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_X86, CDISASM_MODE_64, &sibling_flags)
            == CDISASM_STATUS_OK);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_pd, sizeof(legacy_pd), &sibling_flags, &decoded_size);
#if USE_EXTRA_OPCODES
        EXPECT(decoded_size == sizeof(legacy_pd));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_DPPD);
        EXPECT((instruction.opcode_flags
            & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX)) == 0u);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_ps, sizeof(legacy_ps), &sibling_flags, &decoded_size);
#if USE_EXTRA_OPCODES
        EXPECT(decoded_size == sizeof(legacy_ps));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_DPPS);
        EXPECT((instruction.opcode_flags
            & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX)) == 0u);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_pd, sizeof(evex_pd), NULL, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION
            || instruction.last_error_id
                == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_ps, sizeof(evex_ps), NULL, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION
            || instruction.last_error_id
                == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            c5_pd, sizeof(c5_pd), NULL, &decoded_size);
        EXPECT(decoded_size == 0u);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            c5_ps, sizeof(c5_ps), NULL, &decoded_size);
        EXPECT(decoded_size == 0u);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_16,
            r_collision, sizeof(r_collision), NULL, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
            x_collision, sizeof(x_collision), NULL, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
    }
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
        {{0xc4,0xe3,0x71,0x41,0x00,0x5a,0},6u,
            "vdppd xmm0, xmm1, xmmword ptr [rax], 0x5a",
            "vdppd $0x5a, (%rax), %xmm1, %xmm0"},
        {{0xc4,0xe3,0x69,0x41,0xcb,0xa5,0},6u,
            "vdppd xmm1, xmm2, xmm3, 0xa5",
            "vdppd $0xa5, %xmm3, %xmm2, %xmm1"},
        {{0xc4,0xe3,0x71,0x40,0x00,0xc3,0},6u,
            "vdpps xmm0, xmm1, xmmword ptr [rax], 0xc3",
            "vdpps $0xc3, (%rax), %xmm1, %xmm0"},
        {{0xc4,0xe3,0x69,0x40,0xcb,0x3c,0},6u,
            "vdpps xmm1, xmm2, xmm3, 0x3c",
            "vdpps $0x3c, %xmm3, %xmm2, %xmm1"},
        {{0xc4,0xe3,0x75,0x40,0x40,0x7f,0x7e},7u,
            "vdpps ymm0, ymm1, ymmword ptr [rax + 0x7f], 0x7e",
            "vdpps $0x7e, 0x7f(%rax), %ymm1, %ymm0"},
        {{0xc4,0xe3,0x6d,0x40,0xcb,0xff,0},6u,
            "vdpps ymm1, ymm2, ymm3, 0xff",
            "vdpps $0xff, %ymm3, %ymm2, %ymm1"}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        char output[192];
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == cases[index].size);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);

        forged = instruction;
        forged.name_id = instruction.name_id == CDISASM_X86_NAME_VDPPD
            ? CDISASM_X86_NAME_VDPPS : CDISASM_X86_NAME_VDPPD;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.form_id = instruction.form_id == UINT16_C(4518)
            ? UINT16_C(4517)
            : (cdisasm_x86_form_id)(instruction.form_id + 1u);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.operand_count = 3u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.x86_group_count = 0u;
        memset(forged.x86_group_ids, 0, sizeof(forged.x86_group_ids));
        expect_format_rejected(&forged);
        forged = instruction;
        ++forged.opcode[0].reg;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.modrm ^= UINT8_C(8);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[2].size = 8u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[3].size = 2u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.immediate_count = 0u;
        expect_format_rejected(&forged);
        forged = instruction;
        ++forged.encoding.prefix_size;
        ++forged.encoding.opcode_offset;
        ++forged.encoding.modrm_offset;
        ++forged.encoding.immediate_offset[0];
        ++forged.opcode_size;
        if (forged.encoding.sib_offset != 0u) {
            ++forged.encoding.sib_offset;
        }
        if (forged.encoding.displacement_offset != 0u) {
            ++forged.encoding.displacement_offset;
        }
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |= CDISASM_PREFIX_SEGMENT;
        expect_format_rejected(&forged);

        if (instruction.opcode[2].type == CDISASM_OPERAND_MEMORY) {
            forged = instruction;
            forged.opcode[2].base_reg = CDISASM_X86_REG_R16;
            expect_format_rejected(&forged);

            /* Segment provenance must agree in all three public views: the
             * prefix bitmap/layout, memory operand, and ISA-set groups. */
            forged = instruction;
            forged.opcode[2].segment_reg = CDISASM_X86_REG_FS;
            forged.opcode[2].flags |=
                CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT;
            memmove(&forged.x86_group_ids[1], &forged.x86_group_ids[0],
                forged.x86_group_count * sizeof(forged.x86_group_ids[0]));
            forged.x86_group_ids[0] = CDISASM_X86_GROUP_I386;
            ++forged.x86_group_count;
            expect_format_rejected(&forged);

            forged = instruction;
            forged.opcode_flags |= CDISASM_PREFIX_SEGMENT;
            ++forged.encoding.prefix_size;
            ++forged.encoding.opcode_offset;
            ++forged.encoding.modrm_offset;
            ++forged.encoding.immediate_offset[0];
            ++forged.opcode_size;
            if (forged.encoding.sib_offset != 0u) {
                ++forged.encoding.sib_offset;
            }
            if (forged.encoding.displacement_offset != 0u) {
                ++forged.encoding.displacement_offset;
            }
            memmove(&forged.x86_group_ids[1], &forged.x86_group_ids[0],
                forged.x86_group_count * sizeof(forged.x86_group_ids[0]));
            forged.x86_group_ids[0] = CDISASM_X86_GROUP_I386;
            ++forged.x86_group_count;
            expect_format_rejected(&forged);
        } else {
            forged = instruction;
            ++forged.opcode[2].reg;
            expect_format_rejected(&forged);
        }
    }

    {
        static const uint8_t legacy[] =
            {0x66,0x0f,0x3a,0x41,0xc2,0x01};
        cdisasm_x86_decode_flags sibling_flags =
            all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy, sizeof(legacy), &sibling_flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(legacy));
        forged = instruction;
        forged.name_id = CDISASM_X86_NAME_VDPPD;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.name_id = CDISASM_X86_NAME_VDPPD;
        forged.form_id = UINT16_C(4508);
        expect_format_rejected(&forged);
    }
#endif
}

int main(void)
{
    test_complete_c4_control_partition();
    test_c5_exclusion_partition();
    test_forms_addresses_aliases_and_immediates();
    test_runtime_and_profile_gates();
    test_reserved_truncation_and_siblings();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VDPP test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
