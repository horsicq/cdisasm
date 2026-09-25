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

_Static_assert(CDISASM_X86_NAME_VMOVSD == UINT16_C(1788),
    "VMOVSD name ID changed");
_Static_assert(CDISASM_X86_GROUP_AVX512F_SCALAR == UINT16_C(185),
    "AVX512F_SCALAR group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512F_SCALAR == UINT32_C(133),
    "AVX512F_SCALAR decode bit changed");

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

static cdisasm_x86_decode_flags two_bits(
    cdisasm_x86_decode_bit_id first,
    cdisasm_x86_decode_bit_id second)
{
    cdisasm_x86_decode_flags flags = one_bit(first);

    EXPECT(cdisasm_decode_flags_set_bit(&flags, second));
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

static void check_modern(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_form_id form_id,
    int evex,
    int apx,
    unsigned int aaa,
    int zero)
{
    const cdisasm_operand_access destination_access =
        evex && aaa != 0u && !zero
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_WRITE;
    const int memory_destination =
        form_id == UINT16_C(5909) || form_id == UINT16_C(5910);
    const int memory_source =
        form_id == UINT16_C(5911) || form_id == UINT16_C(5914);
    const unsigned int expected_operands =
        memory_destination || memory_source ? 2u : 3u;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_VMOVSD);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->operand_count == expected_operands);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT(((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u)
        == evex);
    EXPECT(((instruction->opcode_flags & CDISASM_PREFIX_VEX) != 0u)
        == !evex);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512F_SCALAR) == evex);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == apx);
    EXPECT(instruction->mask_reg == (aaa == 0u
        ? CDISASM_X86_REG_NONE
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
    EXPECT(instruction->mask_mode == (aaa == 0u
        ? CDISASM_X86_MASK_NONE
        : zero ? CDISASM_X86_MASK_ZERO : CDISASM_X86_MASK_MERGE));
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);

    if (memory_destination) {
        EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction->opcode[0].size == 8u);
        EXPECT(instruction->opcode[0].access
            == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction->opcode[1].size == 16u);
        EXPECT(instruction->opcode[1].access
            == CDISASM_OPERAND_ACCESS_READ);
    } else if (memory_source) {
        EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction->opcode[0].size == 16u);
        EXPECT(instruction->opcode[0].access == destination_access);
        EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction->opcode[1].size == 8u);
        EXPECT(instruction->opcode[1].access
            == CDISASM_OPERAND_ACCESS_READ);
    } else {
        unsigned int index;

        for (index = 0u; index < 3u; ++index) {
            EXPECT(instruction->opcode[index].type
                == CDISASM_OPERAND_REGISTER);
            EXPECT(instruction->opcode[index].size == 16u);
            EXPECT(instruction->opcode[index].access == (index == 0u
                ? destination_access : CDISASM_OPERAND_ACCESS_READ));
        }
    }
}
#endif

static cdisasm_x86_form_id selected_form(uint8_t opcode, int is_register)
{
    if (is_register) {
        return opcode == UINT8_C(0x10)
            ? UINT16_C(5912) : UINT16_C(5913);
    }
    return opcode == UINT8_C(0x10)
        ? UINT16_C(5911) : UINT16_C(5910);
}

static cdisasm_x86_form_id selected_evex_form(
    uint8_t opcode,
    int is_register)
{
    if (is_register) {
        return UINT16_C(5915);
    }
    return opcode == UINT8_C(0x10)
        ? UINT16_C(5914) : UINT16_C(5909);
}

static void test_representative_forms_and_legacy(void)
{
    static const uint8_t modern[][7] = {
        {0xc5,0xfb,0x10,0x00,0,0,0},
        {0xc5,0xfb,0x11,0x00,0,0,0},
        {0xc5,0xeb,0x10,0xcb,0,0,0},
        {0xc5,0xeb,0x11,0xcb,0,0,0},
        {0x62,0xf1,0xff,0x08,0x10,0x00,0},
        {0x62,0xf1,0xff,0x08,0x11,0x00,0},
        {0x62,0xf1,0xef,0x08,0x10,0xcb,0}
    };
    static const uint8_t modern_sizes[] = {4,4,4,4,6,6,6};
    static const cdisasm_x86_form_id forms[] = {
        5911,5910,5912,5913,5914,5909,5915
    };
    size_t index;

    for (index = 0u; index < sizeof(forms) / sizeof(forms[0]); ++index) {
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, modern[index],
            modern_sizes[index], &flags, &decoded_size);

        check_modern(&instruction, decoded_size, forms[index], index >= 4u,
            0, 0u, 0);
        EXPECT(decoded_size == modern_sizes[index]);
#else
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, modern[index],
            modern_sizes[index], NULL, &decoded_size);

        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t legacy[][4] = {
            {0xf2,0x0f,0x10,0x01}, {0xf2,0x0f,0x10,0xc1},
            {0xf2,0x0f,0x11,0x01}, {0xf2,0x0f,0x11,0xc1}
        };
        cdisasm_x86_decode_flags flags =
            one_bit(CDISASM_X86_DECODE_BIT_SSE2);

        for (index = 0u; index < 4u; ++index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                legacy[index], sizeof(legacy[index]), &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(legacy[index]));
            EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVSD);
            EXPECT((instruction.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX)) == 0u);
            EXPECT(instruction.operand_count == 2u);
            EXPECT(instruction.opcode[0].access == (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : index == 1u || index == 3u
                    ? CDISASM_OPERAND_ACCESS_READ_WRITE
                    : CDISASM_OPERAND_ACCESS_WRITE));
        }
    }
#endif
}

static void test_complete_vex_allocated_domain(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint32_t per_form[7] = {0};
    uint32_t allocated = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const cdisasm_x86_mode mode = modes[mode_index];
        const int long_mode = mode == CDISASM_MODE_64;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(mode);
#endif
        unsigned int opcode_index;

        for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
            const uint8_t opcode = (uint8_t)(0x10u + opcode_index);
            unsigned int register_form;

            for (register_form = 0u; register_form < 2u; ++register_form) {
                unsigned int raw_r;

                /* Two-byte VEX: non-long disambiguation fixes raw R=1 and
                 * raw vvvv[3]=1; long mode exposes both/all values. */
                for (raw_r = long_mode ? 0u : 1u; raw_r < 2u; ++raw_r) {
                    unsigned int raw_v;

                    for (raw_v = register_form
                            ? (long_mode ? 0u : 8u) : 15u;
                         raw_v <= (register_form ? 15u : 15u); ++raw_v) {
                        unsigned int l;

                        for (l = 0u; l < 2u; ++l) {
                            unsigned int modrm;

                            for (modrm = register_form ? 192u : 0u;
                                 modrm < (register_form ? 256u : 192u);
                                 ++modrm) {
                                uint8_t code[12] = {
                                    0xc5,
                                    (uint8_t)((raw_r << 7)
                                        | (raw_v << 3) | (l << 2) | 3u),
                                    opcode,(uint8_t)modrm,
                                    0x24,0x10,0x20,0x30,0x40,0x50,0x60,0x70
                                };
                                uint32_t decoded_size;
                                const cdisasm_x86_form_id form_id =
                                    selected_form(opcode, register_form != 0u);
                                cdisasm_instruction instruction = decode(
                                    CDISASM_CPU_X86, mode, code, sizeof(code),
#if USE_EXTRA_OPCODES
                                    &flags,
#else
                                    NULL,
#endif
                                    &decoded_size);

#if USE_EXTRA_OPCODES
                                check_modern(&instruction, decoded_size,
                                    form_id, 0, 0, 0u, 0);
#else
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                ++per_form[form_id - UINT16_C(5909)];
                                ++allocated;
                            }
                        }
                    }
                }

                /* Three-byte VEX: C4 fixes raw R/X=1 outside long mode;
                 * B is ignored there, while all three extend in long mode. */
                for (raw_r = long_mode ? 0u : 1u; raw_r < 2u; ++raw_r) {
                    unsigned int raw_x;

                    for (raw_x = long_mode ? 0u : 1u; raw_x < 2u; ++raw_x) {
                        unsigned int raw_b;

                        for (raw_b = 0u; raw_b < 2u; ++raw_b) {
                            unsigned int raw_v;

                            for (raw_v = register_form ? 0u : 15u;
                                 raw_v <= (register_form ? 15u : 15u);
                                 ++raw_v) {
                                unsigned int w;

                                for (w = 0u; w < 2u; ++w) {
                                    unsigned int l;

                                    for (l = 0u; l < 2u; ++l) {
                                        unsigned int modrm;

                                        for (modrm = register_form
                                                ? 192u : 0u;
                                             modrm < (register_form
                                                ? 256u : 192u);
                                             ++modrm) {
                                            uint8_t code[12] = {
                                                0xc4,
                                                (uint8_t)((raw_r << 7)
                                                    | (raw_x << 6)
                                                    | (raw_b << 5) | 1u),
                                                (uint8_t)((w << 7)
                                                    | (raw_v << 3)
                                                    | (l << 2) | 3u),
                                                opcode,(uint8_t)modrm,
                                                0x24,0x10,0x20,0x30,0x40,
                                                0x50,0x60
                                            };
                                            uint32_t decoded_size;
                                            const cdisasm_x86_form_id form_id =
                                                selected_form(opcode,
                                                    register_form != 0u);
                                            cdisasm_instruction instruction =
                                                decode(CDISASM_CPU_X86, mode,
                                                    code, sizeof(code),
#if USE_EXTRA_OPCODES
                                                    &flags,
#else
                                                    NULL,
#endif
                                                    &decoded_size);

#if USE_EXTRA_OPCODES
                                            check_modern(&instruction,
                                                decoded_size, form_id,
                                                0, 0, 0u, 0);
#else
                                            EXPECT(decoded_size == 0u);
                                            EXPECT(is_error_only(&instruction,
                                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                            ++per_form[
                                                form_id - UINT16_C(5909)];
                                            ++allocated;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(132096));
    EXPECT(per_form[5910u - 5909u] == UINT32_C(10752));
    EXPECT(per_form[5911u - 5909u] == UINT32_C(10752));
    EXPECT(per_form[5912u - 5909u] == UINT32_C(55296));
    EXPECT(per_form[5913u - 5909u] == UINT32_C(55296));
}

static void test_complete_evex_allocated_domain(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint32_t per_form[7] = {0};
    uint32_t allocated = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const cdisasm_x86_mode mode = modes[mode_index];
        const int long_mode = mode == CDISASM_MODE_64;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(mode);
#endif
        unsigned int p0_selector;

        for (p0_selector = 0u; p0_selector < (long_mode ? 32u : 4u);
             ++p0_selector) {
            const uint8_t p0 = long_mode
                ? (uint8_t)((p0_selector << 3) | 1u)
                : (uint8_t)(0xc1u
                    | ((p0_selector & 2u) << 4)
                    | ((p0_selector & 1u) << 4));
            const int b4 = (p0 & UINT8_C(0x08)) != 0;
            unsigned int opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                const uint8_t opcode = (uint8_t)(0x10u + opcode_index);
                unsigned int register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    unsigned int u;

                    for (u = register_form || !long_mode ? 1u : 0u;
                         u < 2u; ++u) {
                        unsigned int raw_v;

                        for (raw_v = register_form ? 0u : 15u;
                             raw_v <= (register_form ? 15u : 15u);
                             ++raw_v) {
                            unsigned int v_prime;

                            for (v_prime = register_form && long_mode
                                    ? 0u : 1u;
                                 v_prime < 2u; ++v_prime) {
                                unsigned int ll;

                                for (ll = 0u; ll < 3u; ++ll) {
                                    unsigned int zero;

                                    for (zero = 0u; zero < 2u; ++zero) {
                                        unsigned int aaa;

                                        if (zero != 0u
                                            && !register_form
                                            && opcode == UINT8_C(0x11)) {
                                            continue;
                                        }
                                        for (aaa = zero != 0u ? 1u : 0u;
                                             aaa < 8u; ++aaa) {
                                            unsigned int modrm;

                                            for (modrm = register_form
                                                    ? 192u : 0u;
                                                 modrm < (register_form
                                                    ? 256u : 192u);
                                                 ++modrm) {
                                                const uint8_t p1 = (uint8_t)(
                                                    0x80u | (raw_v << 3)
                                                    | (u << 2) | 3u);
                                                const uint8_t p2 = (uint8_t)(
                                                    (zero << 7) | (ll << 5)
                                                    | (v_prime << 3) | aaa);
                                                uint8_t code[12] = {
                                                    0x62,p0,p1,p2,opcode,
                                                    (uint8_t)modrm,0x24,0x10,
                                                    0x20,0x30,0x40,0x50
                                                };
                                                uint32_t decoded_size;
                                                const int apx = b4 || u == 0u;
                                                const cdisasm_x86_form_id
                                                    form_id =
                                                    selected_evex_form(opcode,
                                                        register_form != 0u);
                                                cdisasm_instruction instruction =
                                                    decode(CDISASM_CPU_X86,
                                                        mode, code,
                                                        sizeof(code),
#if USE_EXTRA_OPCODES
                                                        &flags,
#else
                                                        NULL,
#endif
                                                        &decoded_size);

#if USE_EXTRA_OPCODES
                                                check_modern(&instruction,
                                                    decoded_size, form_id,
                                                    1, apx, aaa, zero != 0u);
#else
                                                (void)apx;
                                                EXPECT(decoded_size == 0u);
                                                EXPECT(is_error_only(
                                                    &instruction,
                                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                                ++per_form[
                                                    form_id - UINT16_C(5909)];
                                                ++allocated;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(7589376));
    EXPECT(per_form[5909u - 5909u] == UINT32_C(331776));
    EXPECT(per_form[5914u - 5909u] == UINT32_C(622080));
    EXPECT(per_form[5915u - 5909u] == UINT32_C(6635520));
}

static void test_factored_reserved_and_collisions(void)
{
    uint32_t reserved = 0u;
    uint32_t collisions = 4u; /* Four legacy MOVSD direction/mod forms. */
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
    unsigned int encoding;

    /* Exhaust both VEX payload bytes at representative memory/register
     * ModRM values.  Other pp values are adjacent move-family collisions. */
    for (encoding = 0u; encoding < 2u; ++encoding) {
        unsigned int value;

        for (value = 0u; value <= UINT8_MAX; ++value) {
            unsigned int opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                unsigned int register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    const uint8_t modrm = register_form ? 0xc0 : 0x00;
                    uint8_t code[12] = {
                        encoding == 0u ? 0xc5 : 0xc4,
                        encoding == 0u ? (uint8_t)value : 0xe1,
                        encoding == 0u
                            ? (uint8_t)(0x10u + opcode_index)
                            : (uint8_t)value,
                        encoding == 0u
                            ? modrm : (uint8_t)(0x10u + opcode_index),
                        encoding == 0u ? 0x24 : modrm,
                        0x24,0x10,0x20,0x30,0x40,0x50,0x60
                    };
                    const size_t size = encoding == 0u ? 11u : 12u;
                    const unsigned int encoded_source =
                        ((~value) >> 3) & 15u;
                    const int collision = (value & 3u) != 3u;
                    const int valid = !collision
                        && (register_form || encoded_source == 0u);
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
#if USE_EXTRA_OPCODES
                        &flags,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (collision) {
                        EXPECT(decoded_size == 0u
                            || instruction.name_id
                                != CDISASM_X86_NAME_VMOVSD);
                        ++collisions;
                    } else if (valid) {
#if USE_EXTRA_OPCODES
                        check_modern(&instruction, decoded_size,
                            selected_form(
                                (uint8_t)(0x10u + opcode_index),
                                register_form != 0u),
                            0, 0, 0u, 0);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(
                            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++reserved;
                    }
                }
            }
        }
    }

    /* EVEX P1 owns only F2/W1; U=0 is address-only and memory vvvv is
     * fixed.  Other pp values are the UPS/UPD/SS collision selectors. */
    {
        unsigned int value;

        for (value = 0u; value <= UINT8_MAX; ++value) {
            unsigned int opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                unsigned int register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    const uint8_t modrm = register_form ? 0xc0 : 0x00;
                    const unsigned int encoded_source =
                        ((~value) >> 3) & 15u;
                    const int collision = (value & 3u) != 3u;
                    const int valid = !collision
                        && (value & UINT8_C(0x80)) != 0
                        && (register_form
                            ? (value & UINT8_C(0x04)) != 0
                            : encoded_source == 0u);
                    uint8_t code[12] = {
                        0x62,0xf1,(uint8_t)value,0x08,
                        (uint8_t)(0x10u + opcode_index),modrm,
                        0x24,0x10,0x20,0x30,0x40,0x50
                    };
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

                    if (collision) {
                        EXPECT(decoded_size == 0u
                            || instruction.name_id
                                != CDISASM_X86_NAME_VMOVSD);
                        ++collisions;
                    } else if (valid) {
#if USE_EXTRA_OPCODES
                        check_modern(&instruction, decoded_size,
                            selected_evex_form(
                                (uint8_t)(0x10u + opcode_index),
                                register_form != 0u),
                            1, !register_form
                                && (value & UINT8_C(0x04)) == 0,
                            0u, 0);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(
                            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++reserved;
                    }
                }
            }
        }
    }

    /* Exhaust every EVEX P2 value for both directions and ModRM classes. */
    {
        unsigned int value;

        for (value = 0u; value <= UINT8_MAX; ++value) {
            const unsigned int ll = (value >> 5) & 3u;
            const unsigned int aaa = value & 7u;
            const int zero = (value & UINT8_C(0x80)) != 0;
            unsigned int opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                unsigned int register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    const uint8_t modrm = register_form ? 0xc0 : 0x00;
                    const int valid = ll < 3u
                        && (value & UINT8_C(0x10)) == 0
                        && (register_form
                            || (value & UINT8_C(0x08)) != 0)
                        && !(zero && aaa == 0u)
                        && !(zero && !register_form
                            && opcode_index == 1u);
                    uint8_t code[12] = {
                        0x62,0xf1,
                        register_form ? 0xef : 0xff,
                        (uint8_t)value,
                        (uint8_t)(0x10u + opcode_index),modrm,
                        0x24,0x10,0x20,0x30,0x40,0x50
                    };
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
                        check_modern(&instruction, decoded_size,
                            selected_evex_form(
                                (uint8_t)(0x10u + opcode_index),
                                register_form != 0u),
                            1, 0, aaa, zero);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(
                            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++reserved;
                    }
                }
            }
        }
    }

    EXPECT(reserved == UINT32_C(1235));
    EXPECT(collisions == UINT32_C(2308));
}

static void test_profiles_runtime_apx_and_disp8(void)
{
    static const uint8_t vex[] = {0xc5,0xeb,0x10,0xcb};
    static const uint8_t evex[] = {0x62,0xf1,0xef,0x08,0x10,0xcb};
    static const uint8_t b4_memory[] = {0x62,0xf9,0xff,0x08,0x10,0x00};
#if USE_EXTRA_OPCODES
    static const uint8_t b4_register[] = {0x62,0xf9,0xef,0x08,0x10,0xcb};
    static const uint8_t x4_memory[] = {
        0x62,0xf1,0xfb,0x08,0x10,0x04,0xa4
    };
    static const uint8_t addr32_b4[] = {
        0x67,0x62,0xf9,0xff,0x08,0x10,0x00
    };
    static const uint8_t disp8_load[] = {
        0x62,0xf1,0xff,0x89,0x10,0x40,0xff
    };
    static const uint8_t disp8_store[] = {
        0x62,0xf1,0xff,0x09,0x11,0x40,0xff
    };
    static const uint8_t non64_vex[] = {0xc4,0xc1,0xbb,0x10,0xcb};
    static const uint8_t non64_evex[] = {0x62,0xc1,0xaf,0x08,0x10,0xcb};
    static const cdisasm_x86_cpu_id positive_profiles[] = {
        CDISASM_CPU_SKYLAKE_SP, CDISASM_CPU_ICE_LAKE,
        CDISASM_CPU_TIGER_LAKE, CDISASM_CPU_AMD_ZEN_4,
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_CPU_AVX10,
        CDISASM_CPU_APX, CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_CPU_KNIGHTS_MILL
    };
    static const cdisasm_x86_cpu_id negative_profiles[] = {
        CDISASM_CPU_SKYLAKE, CDISASM_CPU_ALDER_LAKE,
        CDISASM_CPU_BROADWELL
    };
    cdisasm_x86_decode_flags avx = one_bit(CDISASM_X86_DECODE_BIT_AVX);
    cdisasm_x86_decode_flags scalar =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_SCALAR);
    cdisasm_x86_decode_flags avx512 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512);
    cdisasm_x86_decode_flags scalar_apx = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512F_SCALAR,
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags available;
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vex, sizeof(vex), &avx, &decoded_size);
    check_modern(&instruction, decoded_size, UINT16_C(5912), 0, 0, 0u, 0);
    expect_error("VEX exact-scalar bit is not AVX", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex, sizeof(vex), &scalar,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        evex, sizeof(evex), &scalar, &decoded_size);
    check_modern(&instruction, decoded_size, UINT16_C(5915), 1, 0, 0u, 0);
    expect_error("AVX512 umbrella does not replace exact scalar bit",
        CDISASM_CPU_X86, CDISASM_MODE_64, evex, sizeof(evex), &avx512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    for (index = 0u;
         index < sizeof(positive_profiles) / sizeof(positive_profiles[0]);
         ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            positive_profiles[index], CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        instruction = decode(positive_profiles[index], CDISASM_MODE_64,
            evex, sizeof(evex), &available, &decoded_size);
        check_modern(&instruction, decoded_size,
            UINT16_C(5915), 1, 0, 0u, 0);
    }
    for (index = 0u;
         index < sizeof(negative_profiles) / sizeof(negative_profiles[0]);
         ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            negative_profiles[index], CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        expect_error("negative scalar profile", negative_profiles[index],
            CDISASM_MODE_64, evex, sizeof(evex), &available,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_memory, sizeof(b4_memory), &scalar_apx, &decoded_size);
    check_modern(&instruction, decoded_size, UINT16_C(5914), 1, 1, 0u, 0);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R16);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_register, sizeof(b4_register), &scalar_apx, &decoded_size);
    check_modern(&instruction, decoded_size, UINT16_C(5915), 1, 1, 0u, 0);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM3);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        x4_memory, sizeof(x4_memory), &scalar_apx, &decoded_size);
    check_modern(&instruction, decoded_size, UINT16_C(5914), 1, 1, 0u, 0);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RSP);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R20);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        addr32_b4, sizeof(addr32_b4), &scalar_apx, &decoded_size);
    check_modern(&instruction, decoded_size, UINT16_C(5914), 1, 1, 0u, 0);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R16D);

    expect_error("APX runtime bit", CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_memory, sizeof(b4_memory), &scalar,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 profile rejects B4", CDISASM_CPU_AVX10,
        CDISASM_MODE_64, b4_memory, sizeof(b4_memory), &scalar_apx,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        disp8_load, sizeof(disp8_load), &scalar, &decoded_size);
    check_modern(&instruction, decoded_size, UINT16_C(5914), 1, 0, 1u, 1);
    EXPECT(instruction.opcode[1].imm == (uint64_t)INT64_C(-8));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        disp8_store, sizeof(disp8_store), &scalar, &decoded_size);
    check_modern(&instruction, decoded_size, UINT16_C(5909), 1, 0, 1u, 0);
    EXPECT(instruction.opcode[0].imm == (uint64_t)INT64_C(-8));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
        non64_vex, sizeof(non64_vex), &avx, &decoded_size);
    check_modern(&instruction, decoded_size, UINT16_C(5912), 0, 0, 0u, 0);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM0);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM3);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
        non64_evex, sizeof(non64_evex), &scalar, &decoded_size);
    check_modern(&instruction, decoded_size, UINT16_C(5915), 1, 0, 0u, 0);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM2);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM3);
#else
    expect_error("VEX extras off", CDISASM_CPU_X86, CDISASM_MODE_64,
        vex, sizeof(vex), NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("EVEX extras off", CDISASM_CPU_X86, CDISASM_MODE_64,
        evex, sizeof(evex), NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("EVEX APX extras off", CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_memory, sizeof(b4_memory), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_invalid_and_truncated(void)
{
    static const uint8_t invalid[][7] = {
        {0xc5,0xf3,0x10,0x00,0,0,0},       /* memory vvvv */
        {0x62,0xf1,0x7f,0x08,0x10,0x00,0}, /* W0 */
        {0x62,0xf1,0xff,0x18,0x10,0x00,0}, /* b */
        {0x62,0xf1,0xff,0x68,0x10,0x00,0}, /* LL3 */
        {0x62,0xf1,0xff,0x88,0x10,0x00,0}, /* z with k0 */
        {0x62,0xf1,0xff,0x89,0x11,0x00,0}, /* store zeroing */
        {0x62,0xf1,0xef,0x00,0x10,0xcb,0}, /* non-long V' below */
        {0x62,0xf1,0xeb,0x08,0x10,0xcb,0}  /* U0 register */
    };
    static const size_t sizes[] = {4,6,6,6,6,6,6,6};
    static const uint8_t missing_vex_modrm[] = {0xc5,0xf3,0x10};
    static const uint8_t missing_evex_modrm[] = {
        0x62,0xf1,0x7f,0x18,0x10
    };
    static const uint8_t bad_control_missing_sib[] = {
        0x62,0xf1,0x7f,0x18,0x10,0x04
    };
    size_t index;

    for (index = 0u; index < 6u; ++index) {
        expect_error("reserved VMOVSD selector", CDISASM_CPU_X86,
            CDISASM_MODE_64, invalid[index], sizes[index], NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("EVEX V' outside long", CDISASM_CPU_X86,
        CDISASM_MODE_32, invalid[6], sizes[6], NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("EVEX U0 register", CDISASM_CPU_X86,
        CDISASM_MODE_64, invalid[7], sizes[7], NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VEX missing ModRM after bad vvvv", CDISASM_CPU_X86,
        CDISASM_MODE_64, missing_vex_modrm, sizeof(missing_vex_modrm), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("EVEX missing ModRM after bad controls", CDISASM_CPU_X86,
        CDISASM_MODE_64, missing_evex_modrm, sizeof(missing_evex_modrm),
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("EVEX missing SIB after bad controls", CDISASM_CPU_X86,
        CDISASM_MODE_64, bad_control_missing_sib,
        sizeof(bad_control_missing_sib), NULL, CDISASM_STATUS_TRUNCATED);
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const uint8_t vex[] = {0xc5,0xeb,0x11,0xcb};
    static const uint8_t load[] = {
        0x62,0xf1,0xff,0x89,0x10,0x40,0xff
    };
    static const uint8_t store[] = {
        0x62,0xf1,0xff,0x09,0x11,0x40,0xff
    };
    cdisasm_x86_decode_flags avx = one_bit(CDISASM_X86_DECODE_BIT_AVX);
    cdisasm_x86_decode_flags scalar =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_SCALAR);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    char output[128];

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vex, sizeof(vex), &avx, &decoded_size);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == strlen("vmovsd xmm3, xmm2, xmm1"));
    EXPECT(strcmp(output, "vmovsd xmm3, xmm2, xmm1") == 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output)) == strlen("vmovsd %xmm1, %xmm2, %xmm3"));
    EXPECT(strcmp(output, "vmovsd %xmm1, %xmm2, %xmm3") == 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        load, sizeof(load), &scalar, &decoded_size);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output))
        == strlen("vmovsd xmm0 {k1}{z}, qword ptr [rax - 0x8]"));
    EXPECT(strcmp(output,
        "vmovsd xmm0 {k1}{z}, qword ptr [rax - 0x8]") == 0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        store, sizeof(store), &scalar, &decoded_size);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output))
        == strlen("vmovsd qword ptr [rax - 0x8] {k1}, xmm0"));
    EXPECT(strcmp(output,
        "vmovsd qword ptr [rax - 0x8] {k1}, xmm0") == 0);
#endif
}

int main(void)
{
#define RUN_TEST(function)                                                   \
    do {                                                                     \
        int before = failures;                                               \
        function();                                                          \
        if (failures != before) {                                            \
            fprintf(stderr, #function ": %d new failure(s)\n",             \
                failures - before);                                          \
        }                                                                    \
    } while (0)

    RUN_TEST(test_representative_forms_and_legacy);
    RUN_TEST(test_complete_vex_allocated_domain);
    RUN_TEST(test_complete_evex_allocated_domain);
    RUN_TEST(test_factored_reserved_and_collisions);
    RUN_TEST(test_profiles_runtime_apx_and_disp8);
    RUN_TEST(test_invalid_and_truncated);
    RUN_TEST(test_formatting);

#undef RUN_TEST

    if (failures != 0) {
        fprintf(stderr, "%d VMOVSD test(s) failed\n", failures);
        return 1;
    }
    puts("x86 VMOVSD tests passed (7 forms; allocated=7,721,472; "
         "factored reserved=1,235; collision selector cells=2,308)");
    return 0;
}
