#include "cdisasm/cdisasm_x86.h"
#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#ifndef CDISASM_TEST_VPMOVZX
#  define CDISASM_TEST_VPMOVZX 0
#endif

#define EXPECT(expression) do { if (!(expression)) { \
    if (failures < 64) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); \
    } \
    ++failures; } } while (0)

#if CDISASM_TEST_VPMOVZX
_Static_assert(CDISASM_X86_NAME_VPMOVZXBD == UINT16_C(1899)
        && CDISASM_X86_NAME_VPMOVZXBQ == UINT16_C(1900)
        && CDISASM_X86_NAME_VPMOVZXBW == UINT16_C(1901)
        && CDISASM_X86_NAME_VPMOVZXDQ == UINT16_C(1902)
        && CDISASM_X86_NAME_VPMOVZXWD == UINT16_C(1903)
        && CDISASM_X86_NAME_VPMOVZXWQ == UINT16_C(1904),
    "VPMOVZX name IDs changed");
#  define TEST_FAMILY_LABEL "VPMOVZX"
#  define TEST_LEGACY_BW_NAME CDISASM_X86_NAME_PMOVZXBW
#else
_Static_assert(CDISASM_X86_NAME_VPMOVSXBD == UINT16_C(1885)
        && CDISASM_X86_NAME_VPMOVSXBQ == UINT16_C(1886)
        && CDISASM_X86_NAME_VPMOVSXBW == UINT16_C(1887)
        && CDISASM_X86_NAME_VPMOVSXDQ == UINT16_C(1888)
        && CDISASM_X86_NAME_VPMOVSXWD == UINT16_C(1889)
        && CDISASM_X86_NAME_VPMOVSXWQ == UINT16_C(1890),
    "VPMOVSX name IDs changed");
#  define TEST_FAMILY_LABEL "VPMOVSX"
#  define TEST_LEGACY_BW_NAME CDISASM_X86_NAME_PMOVSXBW
#endif
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    TEST_FAMILY_LABEL " AVX IDs changed");

typedef struct family {
    cdisasm_x86_name_id name;
    uint8_t opcode;
    uint16_t xmm_memory_form;
    uint16_t ymm_memory_form;
    uint8_t xmm_source_size;
    const char *mnemonic;
} family;

#if CDISASM_TEST_VPMOVZX
static const family families[6] = {
    {CDISASM_X86_NAME_VPMOVZXBW, 0x30, 7524, 7530, 8, "vpmovzxbw"},
    {CDISASM_X86_NAME_VPMOVZXBD, 0x31, 7504, 7510, 4, "vpmovzxbd"},
    {CDISASM_X86_NAME_VPMOVZXBQ, 0x32, 7514, 7520, 2, "vpmovzxbq"},
    {CDISASM_X86_NAME_VPMOVZXWD, 0x33, 7544, 7550, 8, "vpmovzxwd"},
    {CDISASM_X86_NAME_VPMOVZXWQ, 0x34, 7554, 7560, 4, "vpmovzxwq"},
    {CDISASM_X86_NAME_VPMOVZXDQ, 0x35, 7534, 7540, 8, "vpmovzxdq"}
};
#else
static const family families[6] = {
    {CDISASM_X86_NAME_VPMOVSXBW, 0x20, 7419, 7425, 8, "vpmovsxbw"},
    {CDISASM_X86_NAME_VPMOVSXBD, 0x21, 7399, 7405, 4, "vpmovsxbd"},
    {CDISASM_X86_NAME_VPMOVSXBQ, 0x22, 7409, 7415, 2, "vpmovsxbq"},
    {CDISASM_X86_NAME_VPMOVSXWD, 0x23, 7439, 7445, 8, "vpmovsxwd"},
    {CDISASM_X86_NAME_VPMOVSXWQ, 0x24, 7449, 7455, 4, "vpmovsxwq"},
    {CDISASM_X86_NAME_VPMOVSXDQ, 0x25, 7429, 7435, 8, "vpmovsxdq"}
};
#endif

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

static void expect_error_cpu(const char *label, cdisasm_cpu_id cpu,
    cdisasm_mode mode, const uint8_t *code, size_t size,
    const cdisasm_x86_decode_flags *flags, cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(cpu, mode, code, size,
        flags, &decoded_size);

    if (decoded_size != 0u || !is_error_only(&instruction, status)) {
        fprintf(stderr, "%s: got size/status %u/%u, expected 0/%u\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id, (unsigned int)status);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

static void expect_error(const char *label, cdisasm_mode mode,
    const uint8_t *code, size_t size,
    const cdisasm_x86_decode_flags *flags, cdisasm_status status)
{
    expect_error_cpu(label, CDISASM_CPU_X86, mode, code, size,
        flags, status);
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

static cdisasm_x86_form_id expected_form(const family *item,
    unsigned int l, int register_form)
{
    return (cdisasm_x86_form_id)((l != 0u
        ? item->ymm_memory_form : item->xmm_memory_form)
        + (register_form ? 1u : 0u));
}

static void check_instruction(const cdisasm_instruction *instruction,
    uint32_t decoded_size, cdisasm_mode mode, const family *item,
    unsigned int l, int register_form)
{
    const unsigned int vector_size = 16u << l;
    const unsigned int source_size = item->xmm_source_size << l;
    const cdisasm_x86_reg_id destination_base = l != 0u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    const cdisasm_opcode *destination = &instruction->opcode[0];
    const cdisasm_opcode *source = &instruction->opcode[1];

    EXPECT(decoded_size >= 5u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == item->name);
    EXPECT(instruction->form_id == expected_form(
        item, l, register_form));
    EXPECT(instruction->operand_count == 2u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
            | CDISASM_PREFIX_SEGMENT)) == 0u);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_VEX) != 0u);
    EXPECT(instruction->encoding.prefix_size >= 3u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset == 0u);
    EXPECT(destination->type == CDISASM_OPERAND_REGISTER);
    EXPECT(destination->reg >= destination_base);
    EXPECT(destination->reg <= destination_base + 15u);
    EXPECT(destination->size == vector_size);
    EXPECT(destination->access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(destination->flags == 0u);
    EXPECT(destination->broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(source->type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(source->size == source_size);
    EXPECT(source->access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(source->broadcast == CDISASM_X86_BROADCAST_NONE);
    if (register_form) {
        EXPECT(source->reg >= CDISASM_X86_REG_XMM0);
        EXPECT(source->reg <= CDISASM_X86_REG_XMM15);
        EXPECT(source->flags == 0u);
    } else {
        EXPECT((source->flags
            & (CDISASM_OPERAND_FLAG_IMPLICIT
                | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
    }
    if (mode != CDISASM_MODE_64) {
        EXPECT(destination->reg <= destination_base + 7u);
        EXPECT(!register_form || source->reg <= CDISASM_X86_REG_XMM7);
    }
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->branch_target == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2) == (l != 0u));
}
#endif

static void test_complete_c4_partition(void)
{
    static const cdisasm_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    uint64_t form_counts[6][2][2] = {{{0}}};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t family_index;
    size_t mode_index;

    for (family_index = 0u; family_index < 6u; ++family_index) {
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
                    : (uint8_t)(UINT8_C(0xc2) | (p0_index << 5));
                unsigned int p1;

                for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                    const int valid = (p1 & UINT8_C(0x7b))
                        == UINT8_C(0x79);
                    const unsigned int l = (p1 >> 2) & 1u;
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const uint8_t code[15] = {
                            0xc4,p0,(uint8_t)p1,families[family_index].opcode,
                            (uint8_t)modrm,0x24,0x10,0x20,0x30,0x40,
                            0x50,0x60,0x70,0x80,0x90};
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
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
#if USE_EXTRA_OPCODES
                            check_instruction(&instruction, decoded_size,
                                modes[mode_index], &families[family_index],
                                l, register_form);
#else
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            ++form_counts[family_index][l]
                                [register_form ? 1u : 0u];
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
    EXPECT(allocated == UINT64_C(73728));
    EXPECT(reserved == UINT64_C(4644864));
    for (family_index = 0u; family_index < 6u; ++family_index) {
        unsigned int l;

        for (l = 0u; l < 2u; ++l) {
            EXPECT(form_counts[family_index][l][0] == UINT64_C(4608));
            EXPECT(form_counts[family_index][l][1] == UINT64_C(1536));
        }
    }
}

static void test_forms_gates_and_aliases(void)
{
    size_t family_index;

    for (family_index = 0u; family_index < 6u; ++family_index) {
        unsigned int l;

        for (l = 0u; l < 2u; ++l) {
            unsigned int register_form;

            for (register_form = 0u; register_form < 2u;
                 ++register_form) {
                const uint8_t code[5] = {
                    0xc4,0xe2,(uint8_t)(0x79u | (l << 2)),
                    families[family_index].opcode,
                    (uint8_t)(register_form ? 0xc2 : 0x00)};
#if USE_EXTRA_OPCODES
                cdisasm_x86_decode_flags flags =
                    all_flags(CDISASM_MODE_64);
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
                    &flags, &decoded_size);

                check_instruction(&instruction, decoded_size,
                    CDISASM_MODE_64, &families[family_index], l,
                    register_form != 0u);
#else
                expect_error(TEST_FAMILY_LABEL " extras off", CDISASM_MODE_64,
                    code, sizeof(code), NULL,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            }
        }
    }

#if USE_EXTRA_OPCODES
    {
        const cdisasm_x86_decode_flags none = selected_flags(0, 0);
        const cdisasm_x86_decode_flags avx = selected_flags(1, 0);
        const cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);
        const uint8_t xmm[] = {
            0xc4,0xe2,0x79,families[0].opcode,0xc2};
        const uint8_t ymm[] = {
            0xc4,0xe2,0x7d,families[0].opcode,0xc2};
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        expect_error("XMM " TEST_FAMILY_LABEL " needs AVX", CDISASM_MODE_64,
            xmm, sizeof(xmm), &none,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX2 does not imply AVX for XMM " TEST_FAMILY_LABEL,
            CDISASM_MODE_64, xmm, sizeof(xmm), &avx2,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("YMM " TEST_FAMILY_LABEL " needs AVX2", CDISASM_MODE_64,
            ymm, sizeof(ymm), &avx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            xmm, sizeof(xmm), &avx, &decoded_size);
        EXPECT(decoded_size == sizeof(xmm));
        EXPECT(instruction.form_id == families[0].xmm_memory_form + 1u);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            ymm, sizeof(ymm), &avx2, &decoded_size);
        EXPECT(decoded_size == sizeof(ymm));
        EXPECT(instruction.form_id == families[0].ymm_memory_form + 1u);
    }
    {
        const uint8_t xmm[] = {
            0xc4,0xe2,0x79,families[0].opcode,0xc2};
        const uint8_t ymm[] = {
            0xc4,0xe2,0x7d,families[0].opcode,0xc2};
        cdisasm_x86_decode_flags flags;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_SANDY_BRIDGE,
            CDISASM_MODE_64, &flags) == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
            xmm, sizeof(xmm), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(xmm));
        EXPECT(instruction.form_id == families[0].xmm_memory_form + 1u);
        expect_error_cpu("Sandy Bridge YMM " TEST_FAMILY_LABEL " gate",
            CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
            ymm, sizeof(ymm), &flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_HASWELL,
            CDISASM_MODE_64, &flags) == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_HASWELL, CDISASM_MODE_64,
            ymm, sizeof(ymm), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(ymm));
        EXPECT(instruction.form_id == families[0].ymm_memory_form + 1u);
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_WESTMERE,
            CDISASM_MODE_64, &flags) == CDISASM_STATUS_OK);
        expect_error_cpu("Westmere " TEST_FAMILY_LABEL " gate",
            CDISASM_CPU_WESTMERE,
            CDISASM_MODE_64, xmm, sizeof(xmm), &flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    {
        static const cdisasm_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        const uint8_t alias[] = {
            0xc4,0xc2,0xf9,families[0].opcode,0xcb};
        const uint8_t high[] = {
            0xc4,0x42,0xfd,families[2].opcode,0xcb};
        const uint8_t address[] = {
            0x67,0xc4,0xe2,0x79,families[1].opcode,0x00};
        const uint8_t segment[] = {
            0x64,0xc4,0xe2,0x7d,families[3].opcode,0x00};
        size_t mode_index;
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, high, sizeof(high), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(high));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM9);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM11);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            address, sizeof(address), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(address));
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_EAX);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            segment, sizeof(segment), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(segment));
        EXPECT(instruction.opcode[1].segment_reg == CDISASM_X86_REG_FS);
        for (mode_index = 0u; mode_index < 2u; ++mode_index) {
            cdisasm_x86_decode_flags mode_flags = all_flags(
                modes[mode_index]);

            instruction = decode(CDISASM_CPU_X86, modes[mode_index],
                alias, sizeof(alias), &mode_flags, &decoded_size);
            EXPECT(decoded_size == sizeof(alias));
            EXPECT(instruction.name_id == families[0].name);
            EXPECT(instruction.form_id
                == families[0].xmm_memory_form + 1u);
            EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM3);
        }
    }
#endif
}

static void test_controls_precedence_and_siblings(void)
{
    const uint8_t valid[] = {
        0xc4,0xe2,0x79,families[0].opcode,0xc2};
    size_t size;

    for (size = 1u; size < sizeof(valid); ++size) {
        expect_error("truncated C4 " TEST_FAMILY_LABEL, CDISASM_MODE_64,
            valid, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    expect_error(TEST_FAMILY_LABEL " wrong pp", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x78,families[0].opcode,0xc2}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(TEST_FAMILY_LABEL " reserved vvvv", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x71,families[0].opcode,0xc2}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(TEST_FAMILY_LABEL " wrong pp missing SIB", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x78,families[0].opcode,0x04}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error(TEST_FAMILY_LABEL " vvvv missing disp32", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x71,families[5].opcode,
            0x05,0x11,0x22,0x33}, 8u,
        NULL, CDISASM_STATUS_TRUNCATED);
    {
        static const uint8_t encountered[5] = {0x66,0xf2,0xf3,0xf0,0x48};
        size_t index;

        for (index = 0u; index < sizeof(encountered); ++index) {
            const uint8_t incomplete[6] = {
                encountered[index],0xc4,0xe2,0x79,
                families[0].opcode,0x04};
            const uint8_t complete[7] = {
                encountered[index],0xc4,0xe2,0x79,
                families[0].opcode,0x04,0x24};

            expect_error("prefixed " TEST_FAMILY_LABEL " missing SIB",
                CDISASM_MODE_64, incomplete, sizeof(incomplete), NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed " TEST_FAMILY_LABEL " complete",
                CDISASM_MODE_64, complete, sizeof(complete), NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    {
        const uint8_t legacy[] = {
            0x66,0x0f,0x38,families[0].opcode,0xc2};
        const uint8_t c5[] = {0xc5,0xf9,families[0].opcode,0xc2};
        const uint8_t evex[] = {
            0x62,0xf2,0x7d,0x08,families[0].opcode,0xc2};
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, legacy, sizeof(legacy),
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        EXPECT(decoded_size == sizeof(legacy));
        EXPECT(instruction.name_id == TEST_LEGACY_BW_NAME);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX) == 0u);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            c5, sizeof(c5),
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex, sizeof(evex),
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);
        if (decoded_size != 0u) {
            EXPECT(instruction.name_id == families[0].name);
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
        } else {
            EXPECT(is_error_only(&instruction,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
        }
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

static void test_formatting_and_schema(void)
{
    static const struct format_case {
        uint8_t code[5];
        const char *intel;
        const char *att;
    } cases[] = {
#if CDISASM_TEST_VPMOVZX
        {{0xc4,0xe2,0x79,0x30,0xc2},
            "vpmovzxbw xmm0, xmm2", "vpmovzxbw %xmm2, %xmm0"},
        {{0xc4,0xe2,0x7d,0x30,0x00},
            "vpmovzxbw ymm0, xmmword ptr [rax]",
            "vpmovzxbw (%rax), %ymm0"},
        {{0xc4,0xe2,0x79,0x31,0x00},
            "vpmovzxbd xmm0, dword ptr [rax]",
            "vpmovzxbd (%rax), %xmm0"},
        {{0xc4,0xe2,0x7d,0x31,0xc2},
            "vpmovzxbd ymm0, xmm2", "vpmovzxbd %xmm2, %ymm0"},
        {{0xc4,0xe2,0x79,0x32,0x00},
            "vpmovzxbq xmm0, word ptr [rax]",
            "vpmovzxbq (%rax), %xmm0"},
        {{0xc4,0xe2,0x7d,0x32,0xc2},
            "vpmovzxbq ymm0, xmm2", "vpmovzxbq %xmm2, %ymm0"},
        {{0xc4,0xe2,0x79,0x33,0xc2},
            "vpmovzxwd xmm0, xmm2", "vpmovzxwd %xmm2, %xmm0"},
        {{0xc4,0xe2,0x7d,0x33,0x00},
            "vpmovzxwd ymm0, xmmword ptr [rax]",
            "vpmovzxwd (%rax), %ymm0"},
        {{0xc4,0xe2,0x79,0x34,0x00},
            "vpmovzxwq xmm0, dword ptr [rax]",
            "vpmovzxwq (%rax), %xmm0"},
        {{0xc4,0xe2,0x7d,0x34,0xc2},
            "vpmovzxwq ymm0, xmm2", "vpmovzxwq %xmm2, %ymm0"},
        {{0xc4,0xe2,0x79,0x35,0xc2},
            "vpmovzxdq xmm0, xmm2", "vpmovzxdq %xmm2, %xmm0"},
        {{0xc4,0xe2,0x7d,0x35,0x00},
            "vpmovzxdq ymm0, xmmword ptr [rax]",
            "vpmovzxdq (%rax), %ymm0"}
#else
        {{0xc4,0xe2,0x79,0x20,0xc2},
            "vpmovsxbw xmm0, xmm2", "vpmovsxbw %xmm2, %xmm0"},
        {{0xc4,0xe2,0x7d,0x20,0x00},
            "vpmovsxbw ymm0, xmmword ptr [rax]",
            "vpmovsxbw (%rax), %ymm0"},
        {{0xc4,0xe2,0x79,0x21,0x00},
            "vpmovsxbd xmm0, dword ptr [rax]",
            "vpmovsxbd (%rax), %xmm0"},
        {{0xc4,0xe2,0x7d,0x21,0xc2},
            "vpmovsxbd ymm0, xmm2", "vpmovsxbd %xmm2, %ymm0"},
        {{0xc4,0xe2,0x79,0x22,0x00},
            "vpmovsxbq xmm0, word ptr [rax]",
            "vpmovsxbq (%rax), %xmm0"},
        {{0xc4,0xe2,0x7d,0x22,0xc2},
            "vpmovsxbq ymm0, xmm2", "vpmovsxbq %xmm2, %ymm0"},
        {{0xc4,0xe2,0x79,0x23,0xc2},
            "vpmovsxwd xmm0, xmm2", "vpmovsxwd %xmm2, %xmm0"},
        {{0xc4,0xe2,0x7d,0x23,0x00},
            "vpmovsxwd ymm0, xmmword ptr [rax]",
            "vpmovsxwd (%rax), %ymm0"},
        {{0xc4,0xe2,0x79,0x24,0x00},
            "vpmovsxwq xmm0, dword ptr [rax]",
            "vpmovsxwq (%rax), %xmm0"},
        {{0xc4,0xe2,0x7d,0x24,0xc2},
            "vpmovsxwq ymm0, xmm2", "vpmovsxwq %xmm2, %ymm0"},
        {{0xc4,0xe2,0x79,0x25,0xc2},
            "vpmovsxdq xmm0, xmm2", "vpmovsxdq %xmm2, %xmm0"},
        {{0xc4,0xe2,0x7d,0x25,0x00},
            "vpmovsxdq ymm0, xmmword ptr [rax]",
            "vpmovsxdq (%rax), %ymm0"}
#endif
    };
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, sizeof(cases[index].code),
            &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(cases[index].code));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output))
            == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT, output, sizeof(output))
            == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);
    }
    {
        const uint8_t code[] = {
            0xc4,0xe2,0x79,families[0].opcode,0xc2};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, code, sizeof(code), &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(code));
        forged = instruction;
        forged.name_id = families[1].name;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.form_id = families[0].xmm_memory_form;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.operand_count = 1u;
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
        forged.opcode[1].size = 16u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.modrm ^= UINT8_C(8);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.immediate_count = 1u;
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
    test_complete_c4_partition();
    test_forms_gates_and_aliases();
    test_controls_precedence_and_siblings();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d %s test(s) failed\n",
            failures, TEST_FAMILY_LABEL);
        return 1;
    }
    return 0;
}
