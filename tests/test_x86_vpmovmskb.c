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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",        \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VPMOVMSKB == UINT16_C(1873),
    "VPMOVMSKB name ID changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "VPMOVMSKB capability IDs changed");

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
    cdisasm_cpu_id cpu,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu, mode, code, size, UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static void expect_error(
    const char *label,
    cdisasm_cpu_id cpu,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu, mode, code, size, flags, &decoded_size);

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

static void check_vpmovmskb(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    uint32_t expected_size,
    cdisasm_x86_mode mode,
    unsigned int vector_bits,
    unsigned int destination,
    unsigned int source)
{
    const unsigned int vector_bytes = vector_bits / 8u;
    const cdisasm_x86_reg_id vector_base = vector_bits == 256u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;

    EXPECT(decoded_size == expected_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_VPMOVMSKB);
    EXPECT(instruction->form_id == (vector_bits == 256u
        ? UINT16_C(7335) : UINT16_C(7334)));
    EXPECT(instruction->operand_count == 2u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg
        == (cdisasm_x86_reg_id)(CDISASM_X86_REG_EAX + destination));
    EXPECT(instruction->opcode[0].size == 4u);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[0].flags == 0u);
    EXPECT(instruction->opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg
        == (cdisasm_x86_reg_id)(vector_base + source));
    EXPECT(instruction->opcode[1].size == vector_bytes);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].flags == 0u);
    EXPECT(instruction->opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
        == CDISASM_PREFIX_VEX);
    EXPECT(instruction->encoding.prefix_size >= 2u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT((instruction->encoding.modrm & UINT8_C(0xc0))
        == UINT8_C(0xc0));
    EXPECT(instruction->encoding.sib_offset == 0u);
    EXPECT(instruction->encoding.displacement_offset == 0u);
    EXPECT(instruction->encoding.displacement_size == 0u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset == 0u);
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->branch_target == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2) == (vector_bits == 256u));
    if (mode != CDISASM_MODE_64) {
        EXPECT(destination <= 7u);
        EXPECT(source <= 7u);
    }
}
#endif

static void test_complete_allocated_domain(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    uint32_t form_counts[2] = {0u, 0u};
    uint32_t total = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        unsigned int raw_r;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

        for (raw_r = long_mode ? 0u : 1u; raw_r <= 1u; ++raw_r) {
            unsigned int l;

            for (l = 0u; l <= 1u; ++l) {
                unsigned int modrm;

                for (modrm = 0xc0u; modrm <= 0xffu; ++modrm) {
                    const uint8_t code[4] = {
                        0xc5, (uint8_t)((raw_r << 7) | 0x79u | (l << 2)),
                        0xd7, (uint8_t)modrm};
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

#if USE_EXTRA_OPCODES
                    check_vpmovmskb(&instruction, decoded_size,
                        sizeof(code), modes[mode_index], l ? 256u : 128u,
                        ((modrm >> 3u) & 7u)
                            + ((!raw_r && long_mode) ? 8u : 0u),
                        modrm & 7u);
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    ++form_counts[l];
                    ++total;
                }
            }
        }

        {
            unsigned int extension;

            for (extension = long_mode ? 0u : 6u; extension <= 7u;
                 ++extension) {
                unsigned int w;

                for (w = 0u; w <= 1u; ++w) {
                    unsigned int l;

                    for (l = 0u; l <= 1u; ++l) {
                        unsigned int modrm;

                        for (modrm = 0xc0u; modrm <= 0xffu; ++modrm) {
                            const uint8_t code[5] = {
                                0xc4,
                                (uint8_t)((extension << 5) | 1u),
                                (uint8_t)((w << 7) | 0x79u | (l << 2)),
                                0xd7, (uint8_t)modrm};
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

#if USE_EXTRA_OPCODES
                            check_vpmovmskb(&instruction, decoded_size,
                                sizeof(code), modes[mode_index],
                                l ? 256u : 128u,
                                ((modrm >> 3u) & 7u)
                                    + (long_mode
                                        && (extension & 4u) == 0u
                                        ? 8u : 0u),
                                (modrm & 7u)
                                    + (long_mode
                                        && (extension & 1u) == 0u
                                        ? 8u : 0u));
#else
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            ++form_counts[l];
                            ++total;
                        }
                    }
                }
            }
        }
    }

    EXPECT(total == UINT32_C(3584));
    EXPECT(form_counts[0] == UINT32_C(1792));
    EXPECT(form_counts[1] == UINT32_C(1792));
}

static void test_long_parent_partitions(void)
{
    uint32_t c5_allocated = 0u;
    uint32_t c5_reserved = 0u;
    uint32_t c4_allocated = 0u;
    uint32_t c4_reserved = 0u;
    unsigned int control;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif

    for (control = 0u; control <= UINT8_MAX; ++control) {
        unsigned int modrm;

        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
            const uint8_t code[12] = {
                0xc5, (uint8_t)control, 0xd7, (uint8_t)modrm,
                0x24,0x10,0x20,0x30,0x40,0x50,0x60,0x70};
            const int valid =
                (control & UINT8_C(0x7b)) == UINT8_C(0x79)
                && (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
                &flags,
#else
                NULL,
#endif
                &decoded_size);

            if (valid) {
#if USE_EXTRA_OPCODES
                check_vpmovmskb(&instruction, decoded_size, 4u,
                    CDISASM_MODE_64,
                    (control & UINT8_C(4)) != 0u ? 256u : 128u,
                    ((modrm >> 3u) & 7u)
                        + ((control & UINT8_C(0x80)) == 0u ? 8u : 0u),
                    modrm & 7u);
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                ++c5_allocated;
            } else {
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                ++c5_reserved;
            }
        }
    }

    {
        unsigned int extension;

        for (extension = 0u; extension < 8u; ++extension) {
            for (control = 0u; control <= UINT8_MAX; ++control) {
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const uint8_t code[12] = {
                        0xc4, (uint8_t)((extension << 5) | 1u),
                        (uint8_t)control, 0xd7, (uint8_t)modrm,
                        0x24,0x10,0x20,0x30,0x40,0x50,0x60};
                    const int valid =
                        (control & UINT8_C(0x7b)) == UINT8_C(0x79)
                        && (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, sizeof(code),
#if USE_EXTRA_OPCODES
                        &flags,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (valid) {
#if USE_EXTRA_OPCODES
                        check_vpmovmskb(&instruction, decoded_size, 5u,
                            CDISASM_MODE_64,
                            (control & UINT8_C(4)) != 0u ? 256u : 128u,
                            ((modrm >> 3u) & 7u)
                                + ((extension & 4u) == 0u ? 8u : 0u),
                            (modrm & 7u)
                                + ((extension & 1u) == 0u ? 8u : 0u));
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++c4_allocated;
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++c4_reserved;
                    }
                }
            }
        }
    }

    EXPECT(c5_allocated == UINT32_C(256));
    EXPECT(c5_reserved == UINT32_C(65280));
    EXPECT(c4_allocated == UINT32_C(2048));
    EXPECT(c4_reserved == UINT32_C(522240));
}

static void test_gates_aliases_and_collisions(void)
{
    static const uint8_t xmm[] = {0xc5,0xf9,0xd7,0xc1};
    static const uint8_t ymm[] = {0xc5,0xfd,0xd7,0xc1};
    static const uint8_t nonlong_b[] = {0xc4,0xc1,0xf9,0xd7,0xc1};

#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags all = all_flags(CDISASM_MODE_64);
    cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);
    cdisasm_x86_decode_flags none = selected_flags(0, 0);
    cdisasm_x86_decode_flags available;
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        xmm, sizeof(xmm), &all, &decoded_size);
    EXPECT(decoded_size == sizeof(xmm));
    EXPECT(instruction.form_id == UINT16_C(7334));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        ymm, sizeof(ymm), &all, &decoded_size);
    EXPECT(decoded_size == sizeof(ymm));
    EXPECT(instruction.form_id == UINT16_C(7335));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        xmm, sizeof(xmm), &avx, &decoded_size);
    EXPECT(decoded_size == sizeof(xmm));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        ymm, sizeof(ymm), &avx2, &decoded_size);
    EXPECT(decoded_size == sizeof(ymm));
    expect_error("XMM needs AVX", CDISASM_CPU_X86, CDISASM_MODE_64,
        xmm, sizeof(xmm), &none, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("XMM rejects AVX2-only", CDISASM_CPU_X86,
        CDISASM_MODE_64, xmm, sizeof(xmm), &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("YMM needs AVX2", CDISASM_CPU_X86, CDISASM_MODE_64,
        ymm, sizeof(ymm), &avx, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("Sandy Bridge YMM gate", CDISASM_CPU_SANDY_BRIDGE,
        CDISASM_MODE_64, ymm, sizeof(ymm), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64, &available)
        == CDISASM_STATUS_OK);
    instruction = decode(CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
        xmm, sizeof(xmm), &available, &decoded_size);
    EXPECT(decoded_size == sizeof(xmm));
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_HASWELL, CDISASM_MODE_64, &available)
        == CDISASM_STATUS_OK);
    instruction = decode(CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        ymm, sizeof(ymm), &available, &decoded_size);
    EXPECT(decoded_size == sizeof(ymm));
    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        size_t index;

        for (index = 0u; index < 2u; ++index) {
            cdisasm_x86_decode_flags flags = all_flags(modes[index]);

            instruction = decode(CDISASM_CPU_X86, modes[index],
                nonlong_b, sizeof(nonlong_b), &flags, &decoded_size);
            check_vpmovmskb(&instruction, decoded_size,
                sizeof(nonlong_b), modes[index], 128u, 0u, 1u);
        }
    }
    {
        static const struct sibling_case {
            uint8_t code[6];
            size_t size;
            uint16_t name;
        } siblings[] = {
            {{0x66,0x0f,0xd7,0xc1,0,0},4u,CDISASM_X86_NAME_PMOVMSKB},
            {{0x62,0xf2,0x7e,0x08,0x29,0xc9},6u,CDISASM_X86_NAME_VPMOVB2M},
            {{0x62,0xf2,0xfe,0x08,0x29,0xc9},6u,CDISASM_X86_NAME_VPMOVW2M},
            {{0x62,0xf2,0x7e,0x08,0x39,0xc9},6u,CDISASM_X86_NAME_VPMOVD2M},
            {{0x62,0xf2,0xfe,0x08,0x39,0xc9},6u,CDISASM_X86_NAME_VPMOVQ2M},
            {{0x62,0xf2,0x7e,0x08,0x28,0xc9},6u,CDISASM_X86_NAME_VPMOVM2B},
            {{0x62,0xf2,0xfe,0x08,0x28,0xc9},6u,CDISASM_X86_NAME_VPMOVM2W},
            {{0x62,0xf2,0x7e,0x08,0x38,0xc9},6u,CDISASM_X86_NAME_VPMOVM2D},
            {{0x62,0xf2,0xfe,0x08,0x38,0xc9},6u,CDISASM_X86_NAME_VPMOVM2Q}};
        size_t index;

        for (index = 0u; index < sizeof(siblings) / sizeof(siblings[0]);
             ++index) {
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                siblings[index].code, siblings[index].size,
                &all, &decoded_size);
            EXPECT(decoded_size == siblings[index].size);
            EXPECT(instruction.name_id == siblings[index].name);
        }
    }
#else
    (void)xmm;
    (void)ymm;
    expect_error("nonlong alias extras OFF 16", CDISASM_CPU_X86,
        CDISASM_MODE_16, nonlong_b, sizeof(nonlong_b), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("nonlong alias extras OFF 32", CDISASM_CPU_X86,
        CDISASM_MODE_32, nonlong_b, sizeof(nonlong_b), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_and_payload_first(void)
{
    static const uint8_t valid[] = {0xc5,0xf9,0xd7,0xc1};
    size_t size;

    for (size = 1u; size < sizeof(valid); ++size) {
        expect_error("truncated C5 VPMOVMSKB", CDISASM_CPU_X86,
            CDISASM_MODE_64, valid, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    expect_error("reserved pp", CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf8,0xd7,0xc1}, 4u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved vvvv", CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xe9,0xd7,0xc1}, 4u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("memory complete", CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf9,0xd7,0x04,0x24}, 5u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("memory missing SIB", CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf9,0xd7,0x04}, 4u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf8,0xd7,0x04}, 4u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("prefixed C5 missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc5,0xf9,0xd7,0x04}, 5u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("prefixed C5 complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc5,0xf9,0xd7,0x04,0x24}, 6u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("prefixed C4 missing disp8", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc4,0xe1,0x79,0xd7,0x45}, 6u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("prefixed C4 complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x66,0xc4,0xe1,0x79,0xd7,0x45,0x10}, 7u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format_rejected(const cdisasm_instruction *instruction)
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

static void test_formatting_and_schema(void)
{
    static const struct format_case {
        uint8_t code[5];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc5,0xf9,0xd7,0xc1,0},4u,
            "vpmovmskb eax, xmm1", "vpmovmskb %xmm1, %eax"},
        {{0xc5,0x79,0xd7,0xc1,0},4u,
            "vpmovmskb r8d, xmm1", "vpmovmskb %xmm1, %r8d"},
        {{0xc4,0x01,0xfd,0xd7,0xc1},5u,
            "vpmovmskb r8d, ymm9", "vpmovmskb %ymm9, %r8d"}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char output[128];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == cases[index].size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);

        forged = instruction;
        forged.name_id = CDISASM_X86_NAME_PMOVMSKB;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.form_id = UINT16_C(5860);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.form_id = instruction.form_id == UINT16_C(7334)
            ? UINT16_C(7335) : UINT16_C(7334);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.operand_count = 1u;
        expect_format_rejected(&forged);
        forged = instruction;
        ++forged.opcode[0].reg;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.modrm ^= UINT8_C(8);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
        forged.mask_reg = CDISASM_X86_REG_K1;
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
    test_complete_allocated_domain();
    test_long_parent_partitions();
    test_gates_aliases_and_collisions();
    test_reserved_and_payload_first();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VPMOVMSKB test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
