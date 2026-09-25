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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VBLENDVPD == UINT16_C(1478)
        && CDISASM_X86_NAME_VBLENDVPS == UINT16_C(1479),
    "VBLENDVPD/VBLENDVPS name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46),
    "VBLENDVPD/VBLENDVPS ISA-set group IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "VBLENDVPD/VBLENDVPS runtime-bit IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VBLENDVPD/VBLENDVPS profile sweep");

typedef struct blend_family {
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id base_form;
    uint8_t opcode;
} blend_family;

static const blend_family families[2] = {
    {CDISASM_X86_NAME_VBLENDVPD, UINT16_C(3535), UINT8_C(0x4b)},
    {CDISASM_X86_NAME_VBLENDVPS, UINT16_C(3539), UINT8_C(0x4a)}
};

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

static cdisasm_x86_reg_id vector_reg(
    unsigned int vector_bits,
    unsigned int index)
{
    return (cdisasm_x86_reg_id)((vector_bits == 128u
        ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0) + index);
}

static cdisasm_x86_form_id expected_form(
    const blend_family *family,
    unsigned int vector_bits,
    int register_form)
{
    return (cdisasm_x86_form_id)(family->base_form
        + (vector_bits == 256u ? 2u : 0u)
        + (register_form ? 1u : 0u));
}

static void check_vblendv(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    const blend_family *family,
    cdisasm_x86_mode mode,
    unsigned int vector_bits,
    int register_form,
    unsigned int destination,
    unsigned int source1,
    unsigned int rm_source,
    unsigned int selector_source)
{
    unsigned int index;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == family->name_id);
    EXPECT(instruction->form_id
        == expected_form(family, vector_bits, register_form));
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
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset
        == decoded_size - UINT32_C(1));

    for (index = 0u; index < 4u; ++index) {
        const int is_memory = !register_form && index == 2u;

        EXPECT(instruction->opcode[index].type == (is_memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(instruction->opcode[index].size == vector_bits / 8u);
        EXPECT(instruction->opcode[index].access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
        EXPECT(instruction->opcode[index].broadcast
            == CDISASM_X86_BROADCAST_NONE);
        if (!is_memory) {
            EXPECT(instruction->opcode[index].flags == 0u);
        } else {
            EXPECT((instruction->opcode[index].flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
        }
    }
    EXPECT(instruction->opcode[0].reg
        == vector_reg(vector_bits, destination));
    EXPECT(instruction->opcode[1].reg
        == vector_reg(vector_bits, source1));
    if (register_form) {
        EXPECT(instruction->opcode[2].reg
            == vector_reg(vector_bits, rm_source));
    }
    EXPECT(instruction->opcode[3].reg
        == vector_reg(vector_bits, selector_source));
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2));
    if (mode != CDISASM_MODE_64) {
        EXPECT(destination < 8u);
        EXPECT(source1 < 8u);
        EXPECT(!register_form || rm_source < 8u);
        EXPECT(selector_source < 8u);
    }
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    const blend_family *family,
    unsigned int vector_bits,
    int register_form)
{
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == family->name_id);
    EXPECT(instruction->form_id
        == expected_form(family, vector_bits, register_form));
    EXPECT(instruction->operand_count == 4u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset
        == decoded_size - UINT32_C(1));
    EXPECT(instruction->opcode[2].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[3].type == CDISASM_OPERAND_REGISTER);
#else
    (void)family;
    (void)vector_bits;
    (void)register_form;
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
    static const uint64_t expected_form_counts[8] = {
        UINT64_C(36864), UINT64_C(12288),
        UINT64_C(36864), UINT64_C(12288),
        UINT64_C(36864), UINT64_C(12288),
        UINT64_C(36864), UINT64_C(12288)
    };
    uint64_t form_counts[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t family_index;

    for (family_index = 0u; family_index < 2u; ++family_index) {
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
                    ? (uint8_t)((p0_index << 5) | 3u)
                    : (uint8_t)(0xc3u | (p0_index << 5));
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
                                    const int valid = w == 0u && pp == 1u;
                                    const unsigned int vector_bits = l != 0u
                                        ? 256u : 128u;
                                    const uint8_t code[15] = {
                                        0xc4, p0,
                                        (uint8_t)((w << 7)
                                            | (((~vvvv) & 15u) << 3)
                                            | (l << 2) | pp),
                                        families[family_index].opcode,
                                        (uint8_t)modrm,
                                        0x24, 0x10, 0x20, 0x30, 0x40,
                                        0x50, 0x60, 0x70, 0x80, 0x90
                                    };
                                    uint32_t decoded_size;
                                    cdisasm_instruction instruction = decode(
                                        CDISASM_CPU_X86,
                                        modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                                        &flags,
#else
                                        NULL,
#endif
                                        &decoded_size);

                                    if (valid) {
                                        const unsigned int form_index =
                                            (unsigned int)family_index * 4u
                                            + l * 2u
                                            + (register_form ? 1u : 0u);

                                        check_allocated(&instruction,
                                            decoded_size,
                                            &families[family_index],
                                            vector_bits, register_form);
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
    }
    EXPECT(allocated == UINT64_C(196608));
    EXPECT(reserved == UINT64_C(1376256));
    for (family_index = 0u; family_index < 8u; ++family_index) {
        EXPECT(form_counts[family_index]
            == expected_form_counts[family_index]);
    }
}

static void test_forms_addresses_and_selectors(void)
{
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    size_t family_index;

    for (family_index = 0u; family_index < 2u; ++family_index) {
        unsigned int l;

        for (l = 0u; l < 2u; ++l) {
            unsigned int register_form;

            for (register_form = 0u; register_form < 2u;
                 ++register_form) {
                const uint8_t code[] = {
                    0xc4, 0xe3, (uint8_t)(0x69u | (l << 2)),
                    families[family_index].opcode,
                    (uint8_t)(register_form ? 0xcbu : 0x00u), 0x4f
                };

                instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), &flags, &decoded_size);
                check_vblendv(&instruction, decoded_size,
                    &families[family_index], CDISASM_MODE_64,
                    l != 0u ? 256u : 128u, register_form != 0u,
                    register_form ? 1u : 0u, 2u,
                    register_form ? 3u : 0u, 4u);
            }
        }
    }

    {
        static const uint8_t high_reg[] =
            {0xc4, 0x43, 0x31, 0x4b, 0xfa, 0xff};
        static const uint8_t high_mem[] =
            {0xc4, 0x03, 0x35, 0x4a, 0x44, 0xa5, 0x80, 0xf1};
        static const uint8_t rip_relative[] =
            {0xc4, 0xe3, 0x69, 0x4b, 0x05,
             0x78, 0x56, 0x34, 0x12, 0x7e};
        static const uint8_t address_override[] =
            {0x67, 0xc4, 0xe3, 0x69, 0x4a, 0x00, 0x4f};
        static const uint8_t segment_override[] =
            {0x64, 0xc4, 0xe3, 0x69, 0x4b, 0x00, 0x4f};

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            high_reg, sizeof(high_reg), &flags, &decoded_size);
        check_vblendv(&instruction, decoded_size, &families[0],
            CDISASM_MODE_64, 128u, 1, 15u, 9u, 10u, 15u);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            high_mem, sizeof(high_mem), &flags, &decoded_size);
        check_vblendv(&instruction, decoded_size, &families[1],
            CDISASM_MODE_64, 256u, 0, 8u, 9u, 0u, 15u);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R13);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R12);
        EXPECT(instruction.opcode[2].scale == 4u);
        EXPECT(instruction.opcode[2].imm == (uint64_t)-INT64_C(128));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            rip_relative, sizeof(rip_relative), &flags, &decoded_size);
        check_vblendv(&instruction, decoded_size, &families[0],
            CDISASM_MODE_64, 128u, 0, 0u, 2u, 0u, 7u);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RIP);
        EXPECT(instruction.opcode[2].imm == UINT64_C(0x12345678));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            address_override, sizeof(address_override), &flags,
            &decoded_size);
        check_vblendv(&instruction, decoded_size, &families[1],
            CDISASM_MODE_64, 128u, 0, 0u, 2u, 0u, 4u);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_EAX);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            segment_override, sizeof(segment_override), &flags,
            &decoded_size);
        check_vblendv(&instruction, decoded_size, &families[0],
            CDISASM_MODE_64, 128u, 0, 0u, 2u, 0u, 4u);
        EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_FS);
    }

    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32
        };
        size_t mode_index;

        for (mode_index = 0u; mode_index < 2u; ++mode_index) {
            static const uint8_t alias_reg[] =
                {0xc4, 0xc3, 0x29, 0x4b, 0xfa, 0xff};
            static const uint8_t alias_address[] =
                {0xc4, 0xc3, 0x69, 0x4a, 0x04, 0x24, 0x4f};
            cdisasm_x86_decode_flags mode_flags =
                cpu_flags(CDISASM_CPU_X86, modes[mode_index]);

            instruction = decode(CDISASM_CPU_X86, modes[mode_index],
                alias_reg, sizeof(alias_reg), &mode_flags, &decoded_size);
            check_vblendv(&instruction, decoded_size, &families[0],
                modes[mode_index], 128u, 1, 7u, 2u, 2u, 7u);
            instruction = decode(CDISASM_CPU_X86, modes[mode_index],
                alias_address,
                modes[mode_index] == CDISASM_MODE_16 ? 6u : 7u,
                &mode_flags, &decoded_size);
            check_vblendv(&instruction, decoded_size, &families[1],
                modes[mode_index], 128u, 0, 0u, 2u, 0u,
                modes[mode_index] == CDISASM_MODE_16 ? 2u : 4u);
            EXPECT(instruction.opcode[2].base_reg
                == (modes[mode_index] == CDISASM_MODE_16
                    ? CDISASM_X86_REG_SI : CDISASM_X86_REG_ESP));
            EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_NONE);
        }
    }

    {
        static const cdisasm_x86_mode modes[3] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
        };
        size_t mode_index;

        for (family_index = 0u; family_index < 2u; ++family_index) {
            for (mode_index = 0u; mode_index < 3u; ++mode_index) {
                cdisasm_x86_decode_flags mode_flags =
                    cpu_flags(CDISASM_CPU_X86, modes[mode_index]);
                unsigned int l;

                for (l = 0u; l < 2u; ++l) {
                    unsigned int selector;

                    for (selector = 0u; selector <= UINT8_MAX; ++selector) {
                        const uint8_t code[] = {
                            0xc4, 0xe3,
                            (uint8_t)(0x69u | (l << 2)),
                            families[family_index].opcode,
                            0xcb, (uint8_t)selector
                        };

                        instruction = decode(CDISASM_CPU_X86,
                            modes[mode_index], code, sizeof(code),
                            &mode_flags, &decoded_size);
                        check_vblendv(&instruction, decoded_size,
                            &families[family_index], modes[mode_index],
                            l ? 256u : 128u, 1, 1u, 2u, 3u,
                            (selector >> 4)
                                & (modes[mode_index] == CDISASM_MODE_64
                                    ? 15u : 7u));
                    }
                }
            }
        }
    }
#endif
}

static void test_runtime_and_profile_gates(void)
{
    static const uint8_t xmm[] =
        {0xc4, 0xe3, 0x69, 0x4b, 0xcb, 0x4f};
    static const uint8_t ymm[] =
        {0xc4, 0xe3, 0x6d, 0x4a, 0xcb, 0x4f};

#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags none = selected_flags(0, 0);
    cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    cdisasm_x86_decode_flags avx2_only = selected_flags(0, 1);
    cdisasm_x86_decode_flags both = selected_flags(1, 1);
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    cdisasm_x86_cpu_id cpu_id;

    expect_error("VBLENDVPD needs AVX", CDISASM_CPU_X86,
        CDISASM_MODE_64, xmm, sizeof(xmm), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX2 alone does not imply AVX", CDISASM_CPU_X86,
        CDISASM_MODE_64, ymm, sizeof(ymm), &avx2_only,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        xmm, sizeof(xmm), &avx, &decoded_size);
    check_vblendv(&instruction, decoded_size, &families[0],
        CDISASM_MODE_64, 128u, 1, 1u, 2u, 3u, 4u);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        ymm, sizeof(ymm), &avx, &decoded_size);
    check_vblendv(&instruction, decoded_size, &families[1],
        CDISASM_MODE_64, 256u, 1, 1u, 2u, 3u, 4u);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        ymm, sizeof(ymm), &both, &decoded_size);
    check_vblendv(&instruction, decoded_size, &families[1],
        CDISASM_MODE_64, 256u, 1, 1u, 2u, 3u, 4u);

    for (cpu_id = CDISASM_CPU_FIRST; cpu_id <= CDISASM_CPU_LAST; ++cpu_id) {
        cdisasm_x86_decode_flags profile_flags =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        const int mask_ok = cdisasm_x86_cpu_decode_flag_mask(
            cpu_id, CDISASM_MODE_16, &profile_flags) == CDISASM_STATUS_OK;
        const int has_avx = cdisasm_decode_flags_test_bit(
            &profile_flags, CDISASM_X86_DECODE_BIT_AVX);

        EXPECT(mask_ok);
        if (has_avx) {
            instruction = decode(cpu_id, CDISASM_MODE_16,
                xmm, sizeof(xmm), &profile_flags, &decoded_size);
            check_vblendv(&instruction, decoded_size, &families[0],
                CDISASM_MODE_16, 128u, 1, 1u, 2u, 3u, 4u);
            instruction = decode(cpu_id, CDISASM_MODE_16,
                ymm, sizeof(ymm), &profile_flags, &decoded_size);
            check_vblendv(&instruction, decoded_size, &families[1],
                CDISASM_MODE_16, 256u, 1, 1u, 2u, 3u, 4u);
        } else {
            expect_error("profile lacks AVX", cpu_id, CDISASM_MODE_16,
                xmm, sizeof(xmm), &profile_flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("profile lacks AVX for YMM", cpu_id,
                CDISASM_MODE_16, ymm, sizeof(ymm), &profile_flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
#else
    expect_error("VBLENDVPD extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, xmm, sizeof(xmm), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VBLENDVPS YMM extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, ymm, sizeof(ymm), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_prefixes_truncation_and_collisions(void)
{
    static const uint8_t legacy_prefixes[5] =
        {0x66, 0xf2, 0xf3, 0xf0, 0x48};
    size_t family_index;

    for (family_index = 0u; family_index < 2u; ++family_index) {
        const uint8_t complete[] = {
            0xc4, 0xe3, 0x69, families[family_index].opcode, 0xcb, 0x4f
        };
        size_t index;

        for (index = 1u; index < sizeof(complete); ++index) {
            expect_error("truncated VBLENDV", CDISASM_CPU_X86,
                CDISASM_MODE_64, complete, index, NULL,
                CDISASM_STATUS_TRUNCATED);
        }
        expect_error("reserved W missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe3, 0xe9,
                families[family_index].opcode, 0x04},
            5u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved W missing selector", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe3, 0xe9,
                families[family_index].opcode, 0x04, 0x24},
            6u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved W complete", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe3, 0xe9,
                families[family_index].opcode, 0x04, 0x24, 0x4f},
            7u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

        for (index = 0u; index < 4u; ++index) {
            if (index != 1u) {
                expect_error("reserved pp complete", CDISASM_CPU_X86,
                    CDISASM_MODE_64,
                    (const uint8_t[]){0xc4, 0xe3,
                        (uint8_t)(0x68u | index),
                        families[family_index].opcode,
                        0x04, 0x24, 0x4f},
                    7u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }
        expect_error("reserved pp missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe3, 0x68,
                families[family_index].opcode, 0x04},
            5u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved pp missing selector", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe3, 0x6a,
                families[family_index].opcode, 0x04, 0x24},
            6u, NULL, CDISASM_STATUS_TRUNCATED);

        for (index = 0u; index < sizeof(legacy_prefixes); ++index) {
            const uint8_t prefixed[] = {
                legacy_prefixes[index], 0xc4, 0xe3, 0x69,
                families[family_index].opcode, 0x04, 0x24, 0x4f
            };

            expect_error("prefixed VBLENDV missing SIB", CDISASM_CPU_X86,
                CDISASM_MODE_64, prefixed, 6u, NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed VBLENDV missing selector",
                CDISASM_CPU_X86, CDISASM_MODE_64, prefixed, 7u, NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed complete VBLENDV", CDISASM_CPU_X86,
                CDISASM_MODE_64, prefixed, sizeof(prefixed), NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    expect_error("VBLENDV opcode neighbor", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4, 0xe3, 0x69, 0x4d, 0xcb, 0x4f}, 6u,
        NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        static const uint8_t r_collision[] =
            {0xc4, 0x63, 0x69, 0x4b, 0xcb, 0x4f, 0, 0, 0, 0};
        static const uint8_t x_collision[] =
            {0xc4, 0xa3, 0x69, 0x4a, 0xcb, 0x4f, 0, 0, 0, 0};
        cdisasm_x86_decode_flags flags16 =
            cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags32 =
            cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_32);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_16,
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
        uint8_t code[10];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4, 0xe3, 0x69, 0x4b, 0xcb, 0x41, 0, 0, 0, 0}, 6u,
            "vblendvpd xmm1, xmm2, xmm3, xmm4",
            "vblendvpd %xmm4, %xmm3, %xmm2, %xmm1"},
        {{0xc4, 0xe3, 0x6d, 0x4a, 0x00, 0x4f, 0, 0, 0, 0}, 6u,
            "vblendvps ymm0, ymm2, ymmword ptr [rax], ymm4",
            "vblendvps %ymm4, (%rax), %ymm2, %ymm0"},
        {{0xc4, 0x43, 0x31, 0x4b, 0xfa, 0xff, 0, 0, 0, 0}, 6u,
            "vblendvpd xmm15, xmm9, xmm10, xmm15",
            "vblendvpd %xmm15, %xmm10, %xmm9, %xmm15"},
        {{0xc4, 0xe3, 0x69, 0x4a, 0x05,
          0x78, 0x56, 0x34, 0x12, 0x7e}, 10u,
            "vblendvps xmm0, xmm2, xmmword ptr [rip + 0x12345678], xmm7",
            "vblendvps %xmm7, 0x12345678(%rip), %xmm2, %xmm0"}
    };
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        char output[192];
        char tiny[4] = {'x', 'x', 'x', 'x'};
        size_t required;

        EXPECT(decoded_size == cases[index].size);
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, NULL, 0u);
        EXPECT(required == strlen(cases[index].intel));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output))
            == required);
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

    /* Register-only VBLENDV has the same ignored-FS provenance boundary as
     * the minimized VPBROADCASTB sanitizer input: FS requires 80386, but no
     * memory operand retains its segment register. */
    {
        static const cdisasm_x86_mode modes[3] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
        };
        static const uint8_t fs_register[] =
            {0x64, 0xc4, 0xe3, 0x69, 0x4b, 0xcb, 0x4f};
        size_t mode_index;

        for (mode_index = 0u;
             mode_index < sizeof(modes) / sizeof(modes[0]);
             ++mode_index) {
            cdisasm_x86_decode_flags mode_flags =
                cpu_flags(CDISASM_CPU_X86, modes[mode_index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[mode_index],
                fs_register, sizeof(fs_register), &mode_flags,
                &decoded_size);
            char output[96];

            check_vblendv(&instruction, decoded_size, &families[0],
                modes[mode_index], 128u, 1, 1u, 2u, 3u, 4u);
            EXPECT(decoded_size == sizeof(fs_register));
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_I386));
            EXPECT(cdisasm_x86_format(&instruction,
                CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output))
                == strlen("vblendvpd xmm1, xmm2, xmm3, xmm4"));
            EXPECT(strcmp(output, "vblendvpd xmm1, xmm2, xmm3, xmm4") == 0);
            EXPECT(cdisasm_x86_format(&instruction,
                CDISASM_FORMAT_SYNTAX_ATT, output, sizeof(output))
                == strlen("vblendvpd %xmm4, %xmm3, %xmm2, %xmm1"));
            EXPECT(strcmp(output,
                "vblendvpd %xmm4, %xmm3, %xmm2, %xmm1") == 0);
        }
    }

    {
        static const uint8_t code[] =
            {0xc4, 0xe3, 0x69, 0x4b, 0xcb, 0x4f};
        static const uint8_t high_code[] =
            {0xc4, 0x43, 0x31, 0x4b, 0xfa, 0xff};
        uint32_t decoded_size;
        cdisasm_instruction valid = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);
        cdisasm_instruction high;
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(code));
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VBLENDVPS;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VPBLENDVB;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(3539);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(6334);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.operand_count = 3u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_XOP;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |= CDISASM_PREFIX_OPERAND_SIZE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
        forged.mask_reg = CDISASM_X86_REG_K1;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].size = 32u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].type = CDISASM_OPERAND_MEMORY;
        forged.opcode[2].reg = CDISASM_X86_REG_NONE;
        forged.opcode[2].base_reg = CDISASM_X86_REG_RAX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[3].broadcast = CDISASM_X86_BROADCAST_1_TO_8;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.selector_offset = 0u;
        forged.encoding.immediate_count = 1u;
        forged.encoding.immediate_offset[0] = 5u;
        forged.encoding.immediate_size[0] = 1u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.x86_group_count = 0u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_AVX2;
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
    test_forms_addresses_and_selectors();
    test_runtime_and_profile_gates();
    test_prefixes_truncation_and_collisions();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "x86 VBLENDV tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 VBLENDV tests passed");
    return 0;
}
