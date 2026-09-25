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
            if (failures < 48) {                                             \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",          \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VMOVMSKPS == UINT16_C(1196),
    "VMOVMSKPS name ID changed");
_Static_assert(CDISASM_X86_NAME_VMOVMSKPD == UINT16_C(1197),
    "VMOVMSKPD name ID changed");
_Static_assert(CDISASM_X86_NAME_MOVMSKPS == UINT16_C(282)
        && CDISASM_X86_NAME_MOVMSKPD == UINT16_C(344),
    "legacy MOVMSK collision IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "AVX family identity changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VMOVMSK profile sweeps");

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
static cdisasm_x86_decode_flags one_bit(cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit_id));
    return flags;
}

static cdisasm_x86_reg_id gpr32_id(unsigned int index)
{
    return (cdisasm_x86_reg_id)(CDISASM_X86_REG_EAX + index);
}

static cdisasm_x86_reg_id vector_id(unsigned int index, unsigned int bits)
{
    return (cdisasm_x86_reg_id)((bits == 128u
        ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0) + index);
}

static void check_move_mask(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    unsigned int form_index,
    unsigned int destination_index,
    unsigned int source_index)
{
    static const cdisasm_x86_name_id names[] = {
        CDISASM_X86_NAME_VMOVMSKPD,
        CDISASM_X86_NAME_VMOVMSKPD,
        CDISASM_X86_NAME_VMOVMSKPS,
        CDISASM_X86_NAME_VMOVMSKPS
    };
    static const cdisasm_x86_form_id forms[] = {
        UINT16_C(5860), UINT16_C(5861),
        UINT16_C(5862), UINT16_C(5863)
    };
    const unsigned int vector_bits = (form_index & 1u) != 0u
        ? 256u : 128u;

    EXPECT(form_index < 4u);
    EXPECT(decoded_size == expected_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == names[form_index]);
    EXPECT(instruction->form_id == forms[form_index]);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_VEX) != 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_LOCK | CDISASM_PREFIX_REP
            | CDISASM_PREFIX_REPNE | CDISASM_PREFIX_EVEX
            | CDISASM_PREFIX_REX | CDISASM_PREFIX_REX2
            | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(instruction->operand_count == 2u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg == gpr32_id(destination_index));
    EXPECT(instruction->opcode[0].size == 4u);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg
        == vector_id(source_index, vector_bits));
    EXPECT(instruction->opcode[1].size == vector_bits / 8u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT((instruction->encoding.modrm & UINT8_C(0xc0))
        == UINT8_C(0xc0));
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
}
#endif

static unsigned int form_index_for_fields(unsigned int prefix, unsigned int l)
{
    return (prefix == 1u ? 0u : 2u) + l;
}

static void test_four_forms_in_all_modes(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint8_t codes[][4] = {
        {0xc5, 0xf9, 0x50, 0xc1},
        {0xc5, 0xfd, 0x50, 0xc1},
        {0xc5, 0xf8, 0x50, 0xc1},
        {0xc5, 0xfc, 0x50, 0xc1}
    };
    size_t mode_index;
    size_t form_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags avx =
            one_bit(CDISASM_X86_DECODE_BIT_AVX);
#endif

        for (form_index = 0u; form_index < 4u; ++form_index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[mode_index], codes[form_index],
                sizeof(codes[form_index]),
#if USE_EXTRA_OPCODES
                &avx,
#else
                NULL,
#endif
                &decoded_size);

#if USE_EXTRA_OPCODES
            check_move_mask(&instruction, decoded_size,
                sizeof(codes[form_index]), (unsigned int)form_index,
                0u, 1u);
            EXPECT(instruction.encoding.prefix_size == 2u);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static void test_complete_allocated_domain(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint32_t per_form[4] = {0u, 0u, 0u, 0u};
    uint32_t total = 0u;
    size_t mode_index;

    /* Enumerate every architectural register assignment and every ignored
     * VEX field for both two- and three-byte encodings in every mode. */
    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int is_64 = modes[mode_index] == CDISASM_MODE_64;
        unsigned int raw_r;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags avx =
            one_bit(CDISASM_X86_DECODE_BIT_AVX);
#endif

        for (raw_r = is_64 ? 0u : 1u; raw_r <= 1u; ++raw_r) {
            unsigned int prefix;

            for (prefix = 0u; prefix <= 1u; ++prefix) {
                unsigned int l;

                for (l = 0u; l <= 1u; ++l) {
                    unsigned int modrm;
                    const unsigned int form_index =
                        form_index_for_fields(prefix, l);

                    for (modrm = 0xc0u; modrm <= 0xffu; ++modrm) {
                        uint8_t code[] = {
                            0xc5,
                            (uint8_t)((raw_r << 7) | 0x78u
                                | (l << 2) | prefix),
                            0x50, (uint8_t)modrm
                        };
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_X86, modes[mode_index], code,
                            sizeof(code),
#if USE_EXTRA_OPCODES
                            &avx,
#else
                            NULL,
#endif
                            &decoded_size);

#if USE_EXTRA_OPCODES
                        check_move_mask(&instruction, decoded_size,
                            sizeof(code), form_index,
                            ((modrm >> 3u) & 7u)
                                + ((!raw_r && is_64) ? 8u : 0u),
                            modrm & 7u);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++per_form[form_index];
                        ++total;
                    }
                }
            }
        }

        {
            unsigned int extension;

            for (extension = is_64 ? 0u : 6u;
                 extension <= 7u;
                 ++extension) {
                unsigned int w;

                for (w = 0u; w <= 1u; ++w) {
                    unsigned int prefix;

                    for (prefix = 0u; prefix <= 1u; ++prefix) {
                        unsigned int l;

                        for (l = 0u; l <= 1u; ++l) {
                            unsigned int modrm;
                            const unsigned int form_index =
                                form_index_for_fields(prefix, l);

                            for (modrm = 0xc0u; modrm <= 0xffu; ++modrm) {
                                uint8_t code[] = {
                                    0xc4,
                                    (uint8_t)((extension << 5) | 1u),
                                    (uint8_t)((w << 7) | 0x78u
                                        | (l << 2) | prefix),
                                    0x50, (uint8_t)modrm
                                };
                                uint32_t decoded_size;
                                cdisasm_instruction instruction = decode(
                                    CDISASM_CPU_X86, modes[mode_index], code,
                                    sizeof(code),
#if USE_EXTRA_OPCODES
                                    &avx,
#else
                                    NULL,
#endif
                                    &decoded_size);

#if USE_EXTRA_OPCODES
                                check_move_mask(&instruction, decoded_size,
                                    sizeof(code), form_index,
                                    ((modrm >> 3u) & 7u)
                                        + (((extension & 4u) == 0u && is_64)
                                            ? 8u : 0u),
                                    (modrm & 7u)
                                        + (((extension & 1u) == 0u && is_64)
                                            ? 8u : 0u));
#else
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                ++per_form[form_index];
                                ++total;
                            }
                        }
                    }
                }
            }
        }
    }

    EXPECT(total == UINT32_C(7168));
    EXPECT(per_form[0] == UINT32_C(1792));
    EXPECT(per_form[1] == UINT32_C(1792));
    EXPECT(per_form[2] == UINT32_C(1792));
    EXPECT(per_form[3] == UINT32_C(1792));
}

static void test_complete_long_mode_selector_space(void)
{
    uint32_t vex2_allocated = 0u;
    uint32_t vex2_reserved = 0u;
    uint32_t vex3_allocated = 0u;
    uint32_t vex3_reserved = 0u;
    unsigned int control;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags avx =
        one_bit(CDISASM_X86_DECODE_BIT_AVX);
#endif

    for (control = 0u; control <= UINT8_MAX; ++control) {
        unsigned int modrm;

        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
            uint8_t code[12] = {
                0xc5, (uint8_t)control, 0x50, (uint8_t)modrm,
                0x24, 0x10, 0x20, 0x30, 0x40
            };
            const int valid =
                (control & UINT8_C(0x78)) == UINT8_C(0x78)
                && (control & UINT8_C(0x03)) <= UINT8_C(1)
                && (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
                &avx,
#else
                NULL,
#endif
                &decoded_size);

            if (valid) {
#if USE_EXTRA_OPCODES
                const unsigned int prefix = control & 3u;
                const unsigned int l = (control >> 2u) & 1u;
                check_move_mask(&instruction, decoded_size, 4u,
                    form_index_for_fields(prefix, l),
                    ((modrm >> 3u) & 7u)
                        + ((control & 0x80u) == 0u ? 8u : 0u),
                    modrm & 7u);
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                ++vex2_allocated;
            } else {
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                ++vex2_reserved;
            }
        }
    }

    {
        unsigned int extension;

        for (extension = 0u; extension < 8u; ++extension) {
            for (control = 0u; control <= UINT8_MAX; ++control) {
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    uint8_t code[12] = {
                        0xc4, (uint8_t)((extension << 5) | 1u),
                        (uint8_t)control, 0x50, (uint8_t)modrm,
                        0x24, 0x10, 0x20, 0x30, 0x40
                    };
                    const int valid =
                        (control & UINT8_C(0x78)) == UINT8_C(0x78)
                        && (control & UINT8_C(0x03)) <= UINT8_C(1)
                        && (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, sizeof(code),
#if USE_EXTRA_OPCODES
                        &avx,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (valid) {
#if USE_EXTRA_OPCODES
                        const unsigned int prefix = control & 3u;
                        const unsigned int l = (control >> 2u) & 1u;
                        check_move_mask(&instruction, decoded_size, 5u,
                            form_index_for_fields(prefix, l),
                            ((modrm >> 3u) & 7u)
                                + ((extension & 4u) == 0u ? 8u : 0u),
                            (modrm & 7u)
                                + ((extension & 1u) == 0u ? 8u : 0u));
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++vex3_allocated;
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++vex3_reserved;
                    }
                }
            }
        }
    }

    EXPECT(vex2_allocated == UINT32_C(512));
    EXPECT(vex2_reserved == UINT32_C(65024));
    EXPECT(vex3_allocated == UINT32_C(4096));
    EXPECT(vex3_reserved == UINT32_C(520192));
}

static void test_profiles_modes_and_collisions(void)
{
    static const uint8_t vmovmsk[] = {0xc5, 0xfc, 0x50, 0xc1};
    static const uint8_t legacy_ps[] = {0x0f, 0x50, 0xc1};
    static const uint8_t legacy_pd[] = {0x66, 0x0f, 0x50, 0xc1};
    static const uint8_t map2_vnni[] = {0xc4, 0xe2, 0x69, 0x50, 0xcb};
    static const uint8_t evex_map1[] = {
        0x62, 0xf1, 0x7c, 0x08, 0x50, 0xc1
    };
    static const uint8_t rex2_map1[] = {0xd5, 0x80, 0x50, 0xc1};
    static const uint8_t non64_b_ignored[] = {
        0xc4, 0xc1, 0x78, 0x50, 0xc1
    };
    static const uint8_t non64_les_boundary[] = {
        0xc4, 0xa1, 0x00, 0x00, 0x00, 0x00
    };

    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_16,
            non64_les_boundary, sizeof(non64_les_boundary), NULL,
            &decoded_size);

        EXPECT(decoded_size == 4u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX) == 0u);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
            non64_les_boundary, sizeof(non64_les_boundary), NULL,
            &decoded_size);
        EXPECT(decoded_size == sizeof(non64_les_boundary));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX) == 0u);
    }

    expect_error("Nehalem profile gate", CDISASM_CPU_NEHALEM,
        CDISASM_MODE_64, vmovmsk, sizeof(vmovmsk), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("unowned EVEX map-1/50", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex_map1, sizeof(evex_map1), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 map-1/50 without APX runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, rex2_map1, sizeof(rex2_map1), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        cdisasm_x86_decode_flags avx =
            one_bit(CDISASM_X86_DECODE_BIT_AVX);
        cdisasm_x86_decode_flags none =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        cdisasm_x86_decode_flags available;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            vmovmsk, sizeof(vmovmsk), &avx, &decoded_size);
        check_move_mask(&instruction, decoded_size, sizeof(vmovmsk),
            3u, 0u, 1u);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_16,
            non64_b_ignored, sizeof(non64_b_ignored), &avx,
            &decoded_size);
        check_move_mask(&instruction, decoded_size,
            sizeof(non64_b_ignored), 2u, 0u, 1u);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
            non64_b_ignored, sizeof(non64_b_ignored), &avx,
            &decoded_size);
        check_move_mask(&instruction, decoded_size,
            sizeof(non64_b_ignored), 2u, 0u, 1u);
        expect_error("runtime AVX bit", CDISASM_CPU_X86,
            CDISASM_MODE_64, vmovmsk, sizeof(vmovmsk), &none,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_SANDY_BRIDGE,
            CDISASM_MODE_64, vmovmsk, sizeof(vmovmsk), &available,
            &decoded_size);
        EXPECT(decoded_size == sizeof(vmovmsk));
        EXPECT(instruction.form_id == UINT16_C(5863));

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_X86, CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_ps, sizeof(legacy_ps), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_ps));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVMSKPS);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX) == 0u);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_pd, sizeof(legacy_pd), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_pd));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVMSKPD);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX) == 0u);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            rex2_map1, sizeof(rex2_map1), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(rex2_map1));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVMSKPS);
        EXPECT(instruction.name_id != CDISASM_X86_NAME_VMOVMSKPS);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0u);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            map2_vnni, sizeof(map2_vnni), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(map2_vnni));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPDPBUSD);
        EXPECT(instruction.name_id != CDISASM_X86_NAME_VMOVMSKPD);
        EXPECT(instruction.name_id != CDISASM_X86_NAME_VMOVMSKPS);
    }
#else
    (void)legacy_ps;
    (void)legacy_pd;
    (void)map2_vnni;
    expect_error("non-64 VEX.B ignored, extras OFF (16-bit)",
        CDISASM_CPU_X86, CDISASM_MODE_16, non64_b_ignored,
        sizeof(non64_b_ignored), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("non-64 VEX.B ignored, extras OFF (32-bit)",
        CDISASM_CPU_X86, CDISASM_MODE_32, non64_b_ignored,
        sizeof(non64_b_ignored), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_invalid_controls_and_truncation(void)
{
    static const uint8_t invalid_cases[][6] = {
        {0xc5, 0xe8, 0x50, 0xc1, 0x00, 0x00},
        {0xc5, 0xfa, 0x50, 0xc1, 0x00, 0x00},
        {0xc5, 0xfb, 0x50, 0xc1, 0x00, 0x00},
        {0xc5, 0xf8, 0x50, 0x01, 0x00, 0x00},
        {0xc4, 0xe1, 0x68, 0x50, 0xc1, 0x00},
        {0xc4, 0xe1, 0xfa, 0x50, 0xc1, 0x00},
        {0xc4, 0xe1, 0xfb, 0x50, 0xc1, 0x00},
        {0xc4, 0xe1, 0x78, 0x50, 0x01, 0x00}
    };
    static const uint8_t vex2_modrm[] = {0xc5, 0xf8, 0x50};
    static const uint8_t vex3_modrm[] = {0xc4, 0xe1, 0xf9, 0x50};
    static const uint8_t valid_memory_sib[] = {
        0xc4, 0xe1, 0x78, 0x50, 0x04
    };
    static const uint8_t bad_vvvv_memory_sib[] = {
        0xc4, 0xe1, 0x68, 0x50, 0x04
    };
    static const uint8_t bad_pp_memory_sib[] = {
        0xc4, 0xe1, 0x7a, 0x50, 0x04
    };
    size_t index;

    for (index = 0u;
         index < sizeof(invalid_cases) / sizeof(invalid_cases[0]);
         ++index) {
        expect_error("reserved VMOVMSK selector", CDISASM_CPU_X86,
            CDISASM_MODE_64, invalid_cases[index],
            sizeof(invalid_cases[index]), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("VEX2 missing ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex2_modrm, sizeof(vex2_modrm), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("VEX3 missing ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex3_modrm, sizeof(vex3_modrm), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("register-only memory missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64, valid_memory_sib, sizeof(valid_memory_sib), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("bad vvvv memory missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64, bad_vvvv_memory_sib,
        sizeof(bad_vvvv_memory_sib), NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("bad pp memory missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64, bad_pp_memory_sib, sizeof(bad_pp_memory_sib),
        NULL, CDISASM_STATUS_TRUNCATED);
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const uint8_t ps[] = {0xc4, 0x41, 0xfc, 0x50, 0xdc};
    static const uint8_t pd[] = {0xc4, 0x01, 0xf9, 0x50, 0xc7};
    cdisasm_x86_decode_flags avx =
        one_bit(CDISASM_X86_DECODE_BIT_AVX);
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    char output[128];

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        ps, sizeof(ps), &avx, &decoded_size);
    check_move_mask(&instruction, decoded_size, sizeof(ps),
        3u, 11u, 12u);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == strlen("vmovmskps r11d, ymm12"));
    EXPECT(strcmp(output, "vmovmskps r11d, ymm12") == 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        pd, sizeof(pd), &avx, &decoded_size);
    check_move_mask(&instruction, decoded_size, sizeof(pd),
        0u, 8u, 15u);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output)) == strlen("vmovmskpd %xmm15, %r8d"));
    EXPECT(strcmp(output, "vmovmskpd %xmm15, %r8d") == 0);
#endif
}

int main(void)
{
    test_four_forms_in_all_modes();
    test_complete_allocated_domain();
    test_complete_long_mode_selector_space();
    test_profiles_modes_and_collisions();
    test_invalid_controls_and_truncation();
    test_formatting();

    if (failures != 0) {
        fprintf(stderr, "%d VMOVMSK test(s) failed\n", failures);
        return 1;
    }
    puts("x86 VMOVMSK tests passed (4 forms; 7,168 allocated encodings; exhaustive VEX controls/ModRM)");
    return 0;
}
