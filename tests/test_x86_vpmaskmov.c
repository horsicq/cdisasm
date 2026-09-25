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

_Static_assert(CDISASM_X86_NAME_VPMASKMOVD == UINT16_C(1863)
        && CDISASM_X86_NAME_VPMASKMOVQ == UINT16_C(1864),
    "VPMASKMOV name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "VPMASKMOV AVX2 IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VPMASKMOV profile sweep");

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

static cdisasm_x86_form_id expected_form(
    uint8_t opcode,
    unsigned int w,
    unsigned int l)
{
    if (opcode == UINT8_C(0x8c)) {
        return (cdisasm_x86_form_id)(
            (w != 0u ? UINT16_C(7158) : UINT16_C(7154)) + l);
    }
    return (cdisasm_x86_form_id)(
        (w != 0u ? UINT16_C(7156) : UINT16_C(7152)) + l);
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

static cdisasm_x86_reg_id vector_reg(unsigned int l, unsigned int index)
{
    return (cdisasm_x86_reg_id)(
        (l != 0u ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0)
        + index);
}

static void check_vpmaskmov(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t opcode,
    uint8_t p0,
    unsigned int w,
    unsigned int l,
    unsigned int vvvv,
    uint8_t modrm)
{
    const int load = opcode == UINT8_C(0x8c);
    const int long_mode = mode == CDISASM_MODE_64;
    const unsigned int destination = ((unsigned int)modrm >> 3) & 7u;
    const unsigned int data_index = destination
        + (long_mode && (p0 & UINT8_C(0x80)) == 0u ? 8u : 0u);
    const unsigned int mask_index = long_mode ? vvvv : vvvv & 7u;
    const unsigned int vector_bytes = l != 0u ? 32u : 16u;
    const size_t memory_operand = load ? 2u : 0u;
    const size_t data_operand = load ? 0u : 2u;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (w != 0u
        ? CDISASM_X86_NAME_VPMASKMOVQ
        : CDISASM_X86_NAME_VPMASKMOVD));
    EXPECT(instruction->form_id == expected_form(opcode, w, l));
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
    EXPECT(instruction->opcode[memory_operand].type
        == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction->opcode[memory_operand].size == vector_bytes);
    EXPECT(instruction->opcode[memory_operand].access == (load
        ? CDISASM_OPERAND_ACCESS_READ
        : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT((instruction->opcode[memory_operand].flags
        & (CDISASM_OPERAND_FLAG_IMPLICIT
            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
            | CDISASM_OPERAND_FLAG_SIGNED)) == 0u);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg == vector_reg(l, mask_index));
    EXPECT(instruction->opcode[1].size == vector_bytes);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[data_operand].type
        == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[data_operand].reg
        == vector_reg(l, data_index));
    EXPECT(instruction->opcode[data_operand].size == vector_bytes);
    EXPECT(instruction->opcode[data_operand].access == (load
        ? CDISASM_OPERAND_ACCESS_WRITE
        : CDISASM_OPERAND_ACCESS_READ));
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->branch_target == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    if (!long_mode) {
        EXPECT(data_index < 8u);
        EXPECT(mask_index < 8u);
    }
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t opcode,
    uint8_t p0,
    unsigned int w,
    unsigned int l,
    unsigned int vvvv,
    uint8_t modrm)
{
#if USE_EXTRA_OPCODES
    check_vpmaskmov(instruction, decoded_size, mode, opcode, p0,
        w, l, vvvv, modrm);
#else
    (void)mode;
    (void)opcode;
    (void)p0;
    (void)w;
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
    static const uint8_t opcodes[2] = {0x8c,0x8e};
    uint64_t form_counts[8] = {0u,0u,0u,0u,0u,0u,0u,0u};
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
        size_t opcode_index;

        for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
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

                                for (modrm = 0u; modrm <= UINT8_MAX;
                                     ++modrm) {
                                    const uint8_t code[15] = {
                                        0xc4,p0,
                                        (uint8_t)((w << 7)
                                            | (((~vvvv) & 15u) << 3)
                                            | (l << 2) | pp),
                                        opcodes[opcode_index],(uint8_t)modrm,
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
                                    const int memory =
                                        (modrm & UINT8_C(0xc0))
                                            != UINT8_C(0xc0);

                                    if (pp == 1u && memory) {
                                        const cdisasm_x86_form_id form =
                                            expected_form(
                                                opcodes[opcode_index],w,l);

                                        check_allocated(&instruction,
                                            decoded_size, modes[mode_index],
                                            opcodes[opcode_index], p0,
                                            w, l, vvvv, (uint8_t)modrm);
                                        ++form_counts[form - UINT16_C(7152)];
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
    for (mode_index = 0u; mode_index < 8u; ++mode_index) {
        EXPECT(form_counts[mode_index] == UINT64_C(36864));
    }
}

static void test_forms_modes_and_addresses(void)
{
#if USE_EXTRA_OPCODES
    static const struct form_case {
        uint8_t code[5];
        uint8_t opcode;
        uint8_t w;
        uint8_t l;
    } forms[] = {
        {{0xc4,0xe2,0x71,0x8e,0x10},0x8e,0,0},
        {{0xc4,0xe2,0x75,0x8e,0x10},0x8e,0,1},
        {{0xc4,0xe2,0x69,0x8c,0x08},0x8c,0,0},
        {{0xc4,0xe2,0x6d,0x8c,0x08},0x8c,0,1},
        {{0xc4,0xe2,0xf1,0x8e,0x10},0x8e,1,0},
        {{0xc4,0xe2,0xf5,0x8e,0x10},0x8e,1,1},
        {{0xc4,0xe2,0xe9,0x8c,0x08},0x8c,1,0},
        {{0xc4,0xe2,0xed,0x8c,0x08},0x8c,1,1}
    };
    static const uint8_t high_load[] =
        {0xc4,0x22,0x69,0x8c,0x44,0x58,0x20};
    static const uint8_t high_store[] =
        {0xc4,0x02,0xf1,0x8e,0x54,0xa5,0x80};
    static const uint8_t rip_relative[] =
        {0xc4,0xe2,0x69,0x8c,0x0d,0x78,0x56,0x34,0x12};
    static const uint8_t address_override[] =
        {0x67,0xc4,0xe2,0x69,0x8c,0x08};
    static const uint8_t segment_override[] =
        {0x64,0xc4,0xe2,0x69,0x8c,0x08};
    static const uint8_t duplicate_prefixes[] =
        {0x67,0x67,0x64,0x65,0xc4,0xe2,0x69,0x8c,0x08};
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    for (index = 0u; index < sizeof(forms) / sizeof(forms[0]); ++index) {
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            forms[index].code, sizeof(forms[index].code),
            &flags, &decoded_size);
        check_vpmaskmov(&instruction, decoded_size, CDISASM_MODE_64,
            forms[index].opcode, UINT8_C(0xe2),
            forms[index].w, forms[index].l,
            forms[index].opcode == UINT8_C(0x8c) ? 2u : 1u,
            forms[index].opcode == UINT8_C(0x8c)
                ? UINT8_C(0x08) : UINT8_C(0x10));
        EXPECT(instruction.form_id == UINT16_C(7152) + index);
        EXPECT(instruction.x86_group_count == 2u);
        EXPECT(instruction.x86_group_ids[0] == CDISASM_X86_GROUP_AMD64);
        EXPECT(instruction.x86_group_ids[1] == CDISASM_X86_GROUP_AVX2);
    }

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        high_load, sizeof(high_load), &flags, &decoded_size);
    check_vpmaskmov(&instruction, decoded_size, CDISASM_MODE_64,
        0x8c,0x22,0,0,2,0x44);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R11);
    EXPECT(instruction.opcode[2].scale == 2u);
    EXPECT(instruction.opcode[2].imm == UINT64_C(0x20));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        high_store, sizeof(high_store), &flags, &decoded_size);
    check_vpmaskmov(&instruction, decoded_size, CDISASM_MODE_64,
        0x8e,0x02,1,0,1,0x54);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R13);
    EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_R12);
    EXPECT(instruction.opcode[0].scale == 4u);
    EXPECT(instruction.opcode[0].imm == (uint64_t)-INT64_C(128));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rip_relative, sizeof(rip_relative), &flags, &decoded_size);
    check_vpmaskmov(&instruction, decoded_size, CDISASM_MODE_64,
        0x8c,0xe2,0,0,2,0x0d);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RIP);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        address_override, sizeof(address_override), &flags, &decoded_size);
    check_vpmaskmov(&instruction, decoded_size, CDISASM_MODE_64,
        0x8c,0xe2,0,0,2,0x08);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_EAX);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        segment_override, sizeof(segment_override), &flags, &decoded_size);
    check_vpmaskmov(&instruction, decoded_size, CDISASM_MODE_64,
        0x8c,0xe2,0,0,2,0x08);
    EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_FS);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        duplicate_prefixes, sizeof(duplicate_prefixes), &flags, &decoded_size);
    check_vpmaskmov(&instruction, decoded_size, CDISASM_MODE_64,
        0x8c,0xe2,0,0,2,0x08);
    EXPECT(instruction.encoding.prefix_size == 7u);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_EAX);
    EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_GS);

    for (index = 0u; index < 2u; ++index) {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32
        };
        static const uint8_t alias[] = {0xc4,0xc2,0x29,0x8c,0x10};
        static const uint8_t canonical[] = {0xc4,0xe2,0x69,0x8c,0x10};
        cdisasm_x86_decode_flags mode_flags =
            cpu_flags(CDISASM_CPU_X86, modes[index]);

        instruction = decode(CDISASM_CPU_X86,
            modes[index], alias, sizeof(alias), &mode_flags, &decoded_size);
        check_vpmaskmov(&instruction, decoded_size, modes[index],
            0x8c,0xc2,0,0,10,0x10);
        instruction = decode(CDISASM_CPU_X86,
            modes[index], canonical, sizeof(canonical),
            &mode_flags, &decoded_size);
        check_vpmaskmov(&instruction, decoded_size, modes[index],
            0x8c,0xe2,0,0,2,0x10);
    }
#endif
}

static void test_gates_prefixes_and_neighbors(void)
{
    static const uint8_t complete[] = {0xc4,0xe2,0x69,0x8c,0x08};
    static const uint8_t ymm[] = {0xc4,0xe2,0x6d,0x8c,0x08};
    static const uint8_t encountered[5] = {0x66,0xf2,0xf3,0xf0,0x48};
    size_t index;

    for (index = 1u; index < sizeof(complete); ++index) {
        expect_error("truncated VPMASKMOV", CDISASM_CPU_X86,
            CDISASM_MODE_64, complete, index, NULL,
            CDISASM_STATUS_TRUNCATED);
    }
    expect_error("reserved pp missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x68,0x8c,0x04},5u,NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp complete SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x68,0x8c,0x04,0x24},6u,NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("register load reserved", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x69,0x8c,0xc8},5u,NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("register store reserved", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x69,0x8e,0xc8},5u,NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    for (index = 0u; index < sizeof(encountered); ++index) {
        const uint8_t prefixed[] = {
            encountered[index],0xc4,0xe2,0x69,0x8c,0x04,0x24
        };

        expect_error("prefixed missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64, prefixed, sizeof(prefixed) - 1u, NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("prefixed complete", CDISASM_CPU_X86,
            CDISASM_MODE_64, prefixed, sizeof(prefixed), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("C5 wrong map", CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xe9,0x8c,0x08},4u,NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        cdisasm_x86_decode_flags none = selected_flags(0,0);
        cdisasm_x86_decode_flags avx = selected_flags(1,0);
        cdisasm_x86_decode_flags avx2 = selected_flags(0,1);
        cdisasm_instruction instruction;
        uint32_t decoded_size;
        cdisasm_x86_cpu_id cpu_id;
        static const cdisasm_x86_mode modes[3] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
        };
        size_t mode_index;

        expect_error("VPMASKMOV needs AVX2", CDISASM_CPU_X86,
            CDISASM_MODE_64, complete, sizeof(complete), &none,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX is not AVX2", CDISASM_CPU_X86,
            CDISASM_MODE_64, complete, sizeof(complete), &avx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            complete, sizeof(complete), &avx2, &decoded_size);
        check_vpmaskmov(&instruction, decoded_size, CDISASM_MODE_64,
            0x8c,0xe2,0,0,2,0x08);

        for (cpu_id = CDISASM_CPU_FIRST; cpu_id <= CDISASM_CPU_LAST;
             ++cpu_id) {
            for (mode_index = 0u; mode_index < 3u; ++mode_index) {
                cdisasm_x86_decode_flags profile =
                    CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
                const cdisasm_x86_mode mode = modes[mode_index];

                if (cdisasm_x86_cpu_decode_flag_mask(
                        cpu_id, mode, &profile) != CDISASM_STATUS_OK) {
                    continue;
                }
                if (cdisasm_decode_flags_test_bit(
                        &profile, CDISASM_X86_DECODE_BIT_AVX2)) {
                    instruction = decode(cpu_id, mode,
                        ymm, sizeof(ymm), &profile, &decoded_size);
                    check_vpmaskmov(&instruction, decoded_size, mode,
                        0x8c,0xe2,0,1,2,0x08);
                } else {
                    expect_error("profile lacks AVX2", cpu_id, mode,
                        ymm, sizeof(ymm), &profile,
                        CDISASM_STATUS_INVALID_INSTRUCTION);
                }
            }
        }

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            (const uint8_t[]){0xc4,0xe2,0x69,0x8b,0x08},5u,
            &avx2, &decoded_size);
        EXPECT(decoded_size == 0u
            || instruction.name_id != CDISASM_X86_NAME_VPMASKMOVD);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            (const uint8_t[]){0xc4,0xe2,0x69,0x8d,0x08},5u,
            &avx2, &decoded_size);
        EXPECT(decoded_size == 0u
            || instruction.name_id != CDISASM_X86_NAME_VPMASKMOVD);
    }
#else
    expect_error("VPMASKMOV extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, complete, sizeof(complete), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VPMASKMOV YMM extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, ymm, sizeof(ymm), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
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
        {{0xc4,0xe2,0x69,0x8c,0x08,0,0,0},5u,
            "vpmaskmovd xmm1, xmm2, xmmword ptr [rax]",
            "vpmaskmovd (%rax), %xmm2, %xmm1"},
        {{0xc4,0xe2,0xed,0x8c,0x08,0,0,0},5u,
            "vpmaskmovq ymm1, ymm2, ymmword ptr [rax]",
            "vpmaskmovq (%rax), %ymm2, %ymm1"},
        {{0xc4,0xe2,0x71,0x8e,0x10,0,0,0},5u,
            "vpmaskmovd xmmword ptr [rax], xmm1, xmm2",
            "vpmaskmovd %xmm2, %xmm1, (%rax)"},
        {{0xc4,0x02,0xf5,0x8e,0x54,0xa5,0x80,0},7u,
            "vpmaskmovq ymmword ptr [r13 + r12*4 - 0x80], ymm1, ymm10",
            "vpmaskmovq %ymm10, %ymm1, -0x80(%r13,%r12,4)"},
        {{0x64,0x67,0xc4,0xe2,0x69,0x8c,0x08,0},7u,
            "vpmaskmovd xmm1, xmm2, xmmword ptr fs:[eax]",
            "vpmaskmovd %fs:(%eax), %xmm2, %xmm1"}
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
            CDISASM_FORMAT_SYNTAX_ATT, output, sizeof(output));
        EXPECT(required == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);
    }

    {
        static const uint8_t code[] = {0xc4,0xe2,0x69,0x8c,0x08};
        cdisasm_instruction valid;
        cdisasm_instruction forged;
        uint32_t decoded_size;

        valid = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(code));
        EXPECT(valid.form_id == UINT16_C(7154));
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_ADD;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VPMASKMOVQ;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(7155);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(7152);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(7160);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.operand_count = 2u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
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
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |= CDISASM_PREFIX_OPERAND_SIZE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].size = 32u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].reg = CDISASM_X86_REG_YMM2;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].flags |= CDISASM_OPERAND_FLAG_SIGNED;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].broadcast = CDISASM_X86_BROADCAST_1_TO_4;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.mask_reg = CDISASM_X86_REG_K1;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
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
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_AVX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.prefix_size = 2u;
        forged.encoding.opcode_offset = 2u;
        forged.encoding.modrm_offset = 3u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        ++forged.opcode_size;
        ++forged.encoding.prefix_size;
        ++forged.encoding.opcode_offset;
        ++forged.encoding.modrm_offset;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |= CDISASM_PREFIX_ADDRESS_SIZE;
        forged.opcode[2].base_reg = CDISASM_X86_REG_EAX;
        forged.x86_group_count = 3u;
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_I386;
        forged.x86_group_ids[1] = CDISASM_X86_GROUP_AMD64;
        forged.x86_group_ids[2] = CDISASM_X86_GROUP_AVX2;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |= CDISASM_PREFIX_SEGMENT;
        forged.opcode[2].flags |=
            CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT;
        forged.opcode[2].segment_reg = CDISASM_X86_REG_FS;
        forged.x86_group_count = 3u;
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_I386;
        forged.x86_group_ids[1] = CDISASM_X86_GROUP_AMD64;
        forged.x86_group_ids[2] = CDISASM_X86_GROUP_AVX2;
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
        forged.encoding.immediate_count = 1u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.selector_offset = 1u;
        expect_forged_format_rejected(&forged);
    }

    {
        static const uint8_t code[] =
            {0x64,0x67,0xc4,0xe2,0x71,0x8e,0x10};
        cdisasm_instruction valid;
        cdisasm_instruction forged;
        uint32_t decoded_size;

        valid = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(code));
        EXPECT(valid.form_id == UINT16_C(7152));
        forged = valid;
        forged.opcode[0].flags &=
            ~CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].segment_reg = CDISASM_X86_REG_NONE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags &= ~CDISASM_PREFIX_SEGMENT;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].base_reg = CDISASM_X86_REG_RAX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.modrm |= UINT8_C(0xc0);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.sib_offset = 1u;
        expect_forged_format_rejected(&forged);
    }
#endif
}

int main(void)
{
    test_control_partition();
    test_forms_modes_and_addresses();
    test_gates_prefixes_and_neighbors();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "x86 VPMASKMOV tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 VPMASKMOV tests passed");
    return 0;
}
