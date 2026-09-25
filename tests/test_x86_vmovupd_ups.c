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

_Static_assert(CDISASM_X86_NAME_VMOVUPS == UINT16_C(1186)
        && CDISASM_X86_NAME_VMOVUPD == UINT16_C(1187),
    "VMOVUPD/VMOVUPS name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX512F_128 == UINT16_C(180)
        && CDISASM_X86_GROUP_AVX512F_256 == UINT16_C(182)
        && CDISASM_X86_GROUP_AVX512F_512 == UINT16_C(183),
    "VMOVUPD/VMOVUPS ISA-set IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512F_128 == UINT32_C(128)
        && CDISASM_X86_DECODE_BIT_AVX512F_256 == UINT32_C(130)
        && CDISASM_X86_DECODE_BIT_AVX512F_512 == UINT32_C(131),
    "VMOVUPD/VMOVUPS ISA-set bits changed");

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

static cdisasm_x86_group_id width_group(unsigned int vector_bits)
{
    return vector_bits == 128u ? CDISASM_X86_GROUP_AVX512F_128
        : vector_bits == 256u ? CDISASM_X86_GROUP_AVX512F_256
                              : CDISASM_X86_GROUP_AVX512F_512;
}

static void check_move(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    int is_pd,
    cdisasm_x86_form_id form_id,
    uint8_t opcode,
    unsigned int vector_bits,
    int memory,
    int evex,
    int apx,
    unsigned int aaa,
    int zero)
{
    const int memory_destination = memory && opcode == UINT8_C(0x11);
    const int memory_source = memory && opcode == UINT8_C(0x10);
    const int merge_destination = evex && aaa != 0u && !zero
        && !memory_destination;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (is_pd
        ? CDISASM_X86_NAME_VMOVUPD : CDISASM_X86_NAME_VMOVUPS));
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->operand_count == 2u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT(((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u)
        == evex);
    EXPECT(((instruction->opcode_flags & CDISASM_PREFIX_VEX) != 0u)
        == !evex);
    EXPECT(instruction->opcode[0].type == (memory_destination
        ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
    EXPECT(instruction->opcode[0].size == vector_bits / 8u);
    EXPECT(instruction->opcode[0].access == (merge_destination
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT(instruction->opcode[1].type == (memory_source
        ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
    EXPECT(instruction->opcode[1].size == vector_bits / 8u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, width_group(vector_bits)) == evex);
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
    EXPECT(instruction->encoding.immediate_count == 0u);
}
#endif

static cdisasm_x86_form_id vex_form(
    int is_pd,
    uint8_t opcode,
    unsigned int vector_bits,
    int is_register)
{
    const cdisasm_x86_form_id base =
        is_pd ? UINT16_C(5946) : UINT16_C(5963);

    if (!is_register) {
        return (cdisasm_x86_form_id)(base
            + (opcode == UINT8_C(0x11)
                ? (vector_bits == 128u ? 0u : 4u)
                : (vector_bits == 128u ? 5u : 12u)));
    }
    return (cdisasm_x86_form_id)(base
        + (opcode == UINT8_C(0x10)
            ? (vector_bits == 128u ? 6u : 13u)
            : (vector_bits == 128u ? 7u : 14u)));
}

static cdisasm_x86_form_id evex_form(
    int is_pd,
    uint8_t opcode,
    unsigned int ll,
    int is_register)
{
    static const cdisasm_x86_form_id pd_store_memory[3] = {
        UINT16_C(5947), UINT16_C(5948), UINT16_C(5949)
    };
    static const cdisasm_x86_form_id pd_load_memory[3] = {
        UINT16_C(5954), UINT16_C(5956), UINT16_C(5961)
    };
    static const cdisasm_x86_form_id pd_register[3] = {
        UINT16_C(5955), UINT16_C(5957), UINT16_C(5962)
    };
    static const cdisasm_x86_form_id ps_store_memory[3] = {
        UINT16_C(5964), UINT16_C(5965), UINT16_C(5966)
    };
    static const cdisasm_x86_form_id ps_load_memory[3] = {
        UINT16_C(5971), UINT16_C(5973), UINT16_C(5978)
    };
    static const cdisasm_x86_form_id ps_register[3] = {
        UINT16_C(5972), UINT16_C(5974), UINT16_C(5979)
    };

    if (is_register) {
        return is_pd ? pd_register[ll] : ps_register[ll];
    }
    if (opcode == UINT8_C(0x10)) {
        return is_pd ? pd_load_memory[ll] : ps_load_memory[ll];
    }
    return is_pd ? pd_store_memory[ll] : ps_store_memory[ll];
}

static void test_representative_form_order_and_legacy_collisions(void)
{
    static const struct {
        uint8_t code[6];
        uint8_t size;
        uint8_t opcode;
    } forms[34] = {
        {{0xc5,0xf9,0x11,0x00,0,0},4,0x11},
        {{0x62,0xf1,0xfd,0x08,0x11,0x00},6,0x11},
        {{0x62,0xf1,0xfd,0x28,0x11,0x00},6,0x11},
        {{0x62,0xf1,0xfd,0x48,0x11,0x00},6,0x11},
        {{0xc5,0xfd,0x11,0x00,0,0},4,0x11},
        {{0xc5,0xf9,0x10,0x00,0,0},4,0x10},
        {{0xc5,0xf9,0x10,0xc1,0,0},4,0x10},
        {{0xc5,0xf9,0x11,0xc1,0,0},4,0x11},
        {{0x62,0xf1,0xfd,0x08,0x10,0x00},6,0x10},
        {{0x62,0xf1,0xfd,0x08,0x10,0xc1},6,0x10},
        {{0x62,0xf1,0xfd,0x28,0x10,0x00},6,0x10},
        {{0x62,0xf1,0xfd,0x28,0x10,0xc1},6,0x10},
        {{0xc5,0xfd,0x10,0x00,0,0},4,0x10},
        {{0xc5,0xfd,0x10,0xc1,0,0},4,0x10},
        {{0xc5,0xfd,0x11,0xc1,0,0},4,0x11},
        {{0x62,0xf1,0xfd,0x48,0x10,0x00},6,0x10},
        {{0x62,0xf1,0xfd,0x48,0x10,0xc1},6,0x10},
        {{0xc5,0xf8,0x11,0x00,0,0},4,0x11},
        {{0x62,0xf1,0x7c,0x08,0x11,0x00},6,0x11},
        {{0x62,0xf1,0x7c,0x28,0x11,0x00},6,0x11},
        {{0x62,0xf1,0x7c,0x48,0x11,0x00},6,0x11},
        {{0xc5,0xfc,0x11,0x00,0,0},4,0x11},
        {{0xc5,0xf8,0x10,0x00,0,0},4,0x10},
        {{0xc5,0xf8,0x10,0xc1,0,0},4,0x10},
        {{0xc5,0xf8,0x11,0xc1,0,0},4,0x11},
        {{0x62,0xf1,0x7c,0x08,0x10,0x00},6,0x10},
        {{0x62,0xf1,0x7c,0x08,0x10,0xc1},6,0x10},
        {{0x62,0xf1,0x7c,0x28,0x10,0x00},6,0x10},
        {{0x62,0xf1,0x7c,0x28,0x10,0xc1},6,0x10},
        {{0xc5,0xfc,0x10,0x00,0,0},4,0x10},
        {{0xc5,0xfc,0x10,0xc1,0,0},4,0x10},
        {{0xc5,0xfc,0x11,0xc1,0,0},4,0x11},
        {{0x62,0xf1,0x7c,0x48,0x10,0x00},6,0x10},
        {{0x62,0xf1,0x7c,0x48,0x10,0xc1},6,0x10}
    };
    size_t index;

    for (index = 0u; index < 34u; ++index) {
        const cdisasm_x86_form_id form_id =
            (cdisasm_x86_form_id)(UINT16_C(5946) + index);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            forms[index].code, forms[index].size,
#if USE_EXTRA_OPCODES
            &(cdisasm_x86_decode_flags)CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        EXPECT(decoded_size == forms[index].size);
        EXPECT(instruction.form_id == form_id);
        EXPECT(instruction.name_id == (form_id <= UINT16_C(5962)
            ? CDISASM_X86_NAME_VMOVUPD : CDISASM_X86_NAME_VMOVUPS));
#else
        (void)form_id;
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t legacy[][4] = {
            {0x0f,0x10,0xc1,0}, {0x0f,0x11,0xc1,0},
            {0x66,0x0f,0x10,0xc1}, {0x66,0x0f,0x11,0xc1}
        };
        static const uint8_t sizes[] = {3,3,4,4};
        static const cdisasm_x86_name_id names[] = {
            CDISASM_X86_NAME_MOVUPS, CDISASM_X86_NAME_MOVUPS,
            CDISASM_X86_NAME_MOVUPD, CDISASM_X86_NAME_MOVUPD
        };
        cdisasm_x86_decode_flags flags =
            CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;

        for (index = 0u; index < 4u; ++index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                legacy[index], sizes[index], &flags, &decoded_size);

            EXPECT(decoded_size == sizes[index]);
            EXPECT(instruction.name_id == names[index]);
            EXPECT((instruction.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX)) == 0u);
        }
    }
#endif
}

static void test_complete_vex_domain(uint32_t per_form[34])
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint32_t allocated = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const cdisasm_x86_mode mode = modes[mode_index];
        const int long_mode = mode == CDISASM_MODE_64;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(mode);
#endif
        unsigned int is_pd;

        for (is_pd = 0u; is_pd < 2u; ++is_pd) {
            unsigned int opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                const uint8_t opcode =
                    (uint8_t)(UINT8_C(0x10) + opcode_index);
                unsigned int register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    unsigned int raw_r;

                    for (raw_r = long_mode ? 0u : 1u;
                         raw_r < 2u; ++raw_r) {
                        unsigned int l;

                        for (l = 0u; l < 2u; ++l) {
                            unsigned int modrm;

                            for (modrm = register_form ? 192u : 0u;
                                 modrm < (register_form ? 256u : 192u);
                                 ++modrm) {
                                uint8_t code[12] = {
                                    0xc5,(uint8_t)((raw_r << 7) | 0x78u
                                        | (l << 2) | is_pd),opcode,
                                    (uint8_t)modrm,0x24,0x10,0x20,0x30,
                                    0x40,0x50,0x60,0x70
                                };
                                const unsigned int bits = 128u << l;
                                const cdisasm_x86_form_id form_id = vex_form(
                                    is_pd != 0u, opcode, bits,
                                    register_form != 0u);
                                uint32_t decoded_size;
                                cdisasm_instruction instruction = decode(
                                    CDISASM_CPU_X86, mode, code, sizeof(code),
#if USE_EXTRA_OPCODES
                                    &flags,
#else
                                    NULL,
#endif
                                    &decoded_size);

#if USE_EXTRA_OPCODES
                                check_move(&instruction, decoded_size,
                                    is_pd != 0u, form_id, opcode, bits,
                                    !register_form, 0, 0, 0u, 0);
#else
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                ++per_form[form_id - UINT16_C(5946)];
                                ++allocated;
                            }
                        }
                    }

                    for (raw_r = long_mode ? 0u : 1u;
                         raw_r < 2u; ++raw_r) {
                        unsigned int raw_x;

                        for (raw_x = long_mode ? 0u : 1u;
                             raw_x < 2u; ++raw_x) {
                            unsigned int raw_b;

                            for (raw_b = 0u; raw_b < 2u; ++raw_b) {
                                unsigned int w;

                                for (w = 0u; w < 2u; ++w) {
                                    unsigned int l;

                                    for (l = 0u; l < 2u; ++l) {
                                        unsigned int modrm;

                                        for (modrm = register_form
                                                ? 192u : 0u;
                                             modrm < (register_form
                                                ? 256u : 192u); ++modrm) {
                                            uint8_t code[12] = {
                                                0xc4,
                                                (uint8_t)((raw_r << 7)
                                                    | (raw_x << 6)
                                                    | (raw_b << 5) | 1u),
                                                (uint8_t)((w << 7) | 0x78u
                                                    | (l << 2) | is_pd),
                                                opcode,(uint8_t)modrm,0x24,
                                                0x10,0x20,0x30,0x40,0x50,
                                                0x60
                                            };
                                            const unsigned int bits =
                                                128u << l;
                                            const cdisasm_x86_form_id form_id =
                                                vex_form(is_pd != 0u, opcode,
                                                    bits,
                                                    register_form != 0u);
                                            uint32_t decoded_size;
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
                                            check_move(&instruction,
                                                decoded_size, is_pd != 0u,
                                                form_id, opcode, bits,
                                                !register_form, 0, 0, 0u, 0);
#else
                                            EXPECT(decoded_size == 0u);
                                            EXPECT(is_error_only(&instruction,
                                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                            ++per_form[
                                                form_id - UINT16_C(5946)];
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
    EXPECT(allocated == UINT32_C(57344));
}

static void test_complete_evex_domain(uint32_t per_form[34])
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
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
                : (uint8_t)(0xc1u | ((p0_selector & 2u) << 4)
                    | ((p0_selector & 1u) << 4));
            const int b4 = (p0 & UINT8_C(0x08)) != 0;
#if !USE_EXTRA_OPCODES
            (void)b4;
#endif
            unsigned int is_pd;

            for (is_pd = 0u; is_pd < 2u; ++is_pd) {
                unsigned int opcode_index;

                for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                    const uint8_t opcode =
                        (uint8_t)(UINT8_C(0x10) + opcode_index);
                    unsigned int register_form;

                    for (register_form = 0u; register_form < 2u;
                         ++register_form) {
                        unsigned int u;

                        for (u = register_form || !long_mode ? 1u : 0u;
                             u < 2u; ++u) {
                            unsigned int ll;

                            for (ll = 0u; ll < 3u; ++ll) {
                                unsigned int zero;

                                for (zero = 0u; zero < 2u; ++zero) {
                                    unsigned int aaa;

                                    if (zero && !register_form
                                        && opcode == UINT8_C(0x11)) {
                                        continue;
                                    }
                                    for (aaa = zero ? 1u : 0u;
                                         aaa < 8u; ++aaa) {
                                        unsigned int modrm;

                                        for (modrm = register_form
                                                ? 192u : 0u;
                                             modrm < (register_form
                                                ? 256u : 192u); ++modrm) {
                                            const uint8_t p1 = (uint8_t)(
                                                (is_pd ? 0xf9u : 0x78u)
                                                | (u << 2));
                                            const uint8_t p2 = (uint8_t)(
                                                (zero << 7) | (ll << 5)
                                                | 0x08u | aaa);
                                            uint8_t code[12] = {
                                                0x62,p0,p1,p2,opcode,
                                                (uint8_t)modrm,0x24,0x10,
                                                0x20,0x30,0x40,0x50
                                            };
                                            const unsigned int bits =
                                                128u << ll;
                                            const cdisasm_x86_form_id form_id =
                                                evex_form(is_pd != 0u, opcode,
                                                    ll,
                                                    register_form != 0u);
                                            uint32_t decoded_size;
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
                                            check_move(&instruction,
                                                decoded_size, is_pd != 0u,
                                                form_id, opcode, bits,
                                                !register_form, 1,
                                                b4 || u == 0u, aaa, zero);
#else
                                            (void)bits;
                                            EXPECT(decoded_size == 0u);
                                            EXPECT(is_error_only(&instruction,
                                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                            ++per_form[
                                                form_id - UINT16_C(5946)];
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
    EXPECT(allocated == UINT32_C(2368512));
}

static void test_all_allocated_domains(void)
{
    static const uint32_t expected[34] = {
        5376,110592,110592,110592,5376,5376,1792,1792,207360,76800,
        207360,76800,5376,1792,1792,207360,76800,
        5376,110592,110592,110592,5376,5376,1792,1792,207360,76800,
        207360,76800,5376,1792,1792,207360,76800
    };
    uint32_t per_form[34] = {0};
    size_t index;

    test_complete_vex_domain(per_form);
    test_complete_evex_domain(per_form);
    for (index = 0u; index < 34u; ++index) {
        EXPECT(per_form[index] == expected[index]);
    }
}

static void test_factored_reserved_and_collisions(void)
{
    uint32_t reserved = 0u;
    uint32_t collisions = 8u; /* Eight legacy MOVUPD/MOVUPS selector cells. */
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
    unsigned int encoding;

    for (encoding = 0u; encoding < 2u; ++encoding) {
        unsigned int value;

        for (value = 0u; value <= UINT8_MAX; ++value) {
            unsigned int opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                unsigned int register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    const uint8_t prefix = (uint8_t)(value & 3u);
                    const int collision = prefix >= 2u;
                    const int valid = !collision
                        && (((~value) >> 3) & 15u) == 0u;
                    const uint8_t modrm = register_form ? 0xc0 : 0x00;
                    uint8_t code[12] = {
                        encoding ? 0xc4 : 0xc5,
                        encoding ? 0xe1 : (uint8_t)value,
                        encoding ? (uint8_t)value
                                 : (uint8_t)(0x10u + opcode_index),
                        encoding ? (uint8_t)(0x10u + opcode_index) : modrm,
                        encoding ? modrm : 0x24,
                        0x24,0x10,0x20,0x30,0x40,0x50,0x60
                    };
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
                        &flags,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (collision) {
                        EXPECT(decoded_size == 0u
                            || (instruction.name_id
                                    != CDISASM_X86_NAME_VMOVUPD
                                && instruction.name_id
                                    != CDISASM_X86_NAME_VMOVUPS));
                        ++collisions;
                    } else if (valid) {
#if USE_EXTRA_OPCODES
                        EXPECT(decoded_size != 0u);
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

    {
        unsigned int value;

        for (value = 0u; value <= UINT8_MAX; ++value) {
            const uint8_t prefix = (uint8_t)(value & 3u);
            unsigned int opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                unsigned int register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    const int collision = prefix >= 2u;
                    const int valid = !collision
                        && (((~value) >> 3) & 15u) == 0u
                        && (((value & UINT8_C(0x80)) != 0u)
                            == (prefix == UINT8_C(1)))
                        && (!register_form
                            || (value & UINT8_C(0x04)) != 0u);
                    const uint8_t modrm = register_form ? 0xc0 : 0x00;
                    uint8_t code[12] = {
                        0x62,0xf1,(uint8_t)value,0x08,
                        (uint8_t)(0x10u + opcode_index),modrm,
                        0x24,0x10,0x20,0x30,0x40,0x50
                    };
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
                        &flags,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (collision) {
                        EXPECT(decoded_size == 0u
                            || (instruction.name_id
                                    != CDISASM_X86_NAME_VMOVUPD
                                && instruction.name_id
                                    != CDISASM_X86_NAME_VMOVUPS));
                        ++collisions;
                    } else if (valid) {
#if USE_EXTRA_OPCODES
                        EXPECT(decoded_size != 0u);
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

    {
        unsigned int value;

        for (value = 0u; value <= UINT8_MAX; ++value) {
            const unsigned int ll = (value >> 5) & 3u;
            const unsigned int aaa = value & 7u;
            const int zero = (value & UINT8_C(0x80)) != 0;
            unsigned int is_pd;

            for (is_pd = 0u; is_pd < 2u; ++is_pd) {
                unsigned int opcode_index;

                for (opcode_index = 0u; opcode_index < 2u;
                     ++opcode_index) {
                    unsigned int register_form;

                    for (register_form = 0u; register_form < 2u;
                         ++register_form) {
                        const int valid = ll < 3u
                            && (value & UINT8_C(0x18)) == UINT8_C(0x08)
                            && (!zero || aaa != 0u)
                            && !(zero && !register_form
                                && opcode_index == 1u);
                        const uint8_t modrm =
                            register_form ? 0xc0 : 0x00;
                        uint8_t code[12] = {
                            0x62,0xf1,(uint8_t)(is_pd ? 0xfdu : 0x7cu),
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
                            EXPECT(decoded_size != 0u);
#else
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
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

    EXPECT(reserved == UINT32_C(3190));
    EXPECT(collisions == UINT32_C(1544));
}

static void test_profiles_runtime_apx_and_disp8(void)
{
    static const uint8_t vex[] = {0xc5,0xf9,0x10,0xc1};
    static const uint8_t xmm[] = {0x62,0xf1,0xfd,0x08,0x10,0xc1};
    static const uint8_t zmm[] = {0x62,0xf1,0x7c,0x48,0x10,0xc1};
    static const uint8_t b4[] = {0x62,0xf9,0xfd,0x08,0x10,0x00};
#if USE_EXTRA_OPCODES
    static const uint8_t b4_register[] = {
        0x62,0xf9,0xfd,0x08,0x10,0xcb
    };
    static const uint8_t x4[] = {
        0x62,0xf1,0xf9,0x08,0x10,0x04,0xa4
    };
    static const uint8_t disp128[] = {
        0x62,0xf1,0xfd,0x08,0x10,0x40,0xff
    };
    static const uint8_t disp256[] = {
        0x62,0xf1,0x7c,0x28,0x10,0x40,0xff
    };
    static const uint8_t disp512[] = {
        0x62,0xf1,0x7c,0x48,0x10,0x40,0xff
    };
    static const uint8_t non64_vex[] = {0xc4,0xc1,0xf9,0x10,0xcb};
    static const uint8_t non64_evex[] = {
        0x62,0xc1,0xfd,0x08,0x10,0xcb
    };
    static const cdisasm_x86_cpu_id width128_positive[] = {
        CDISASM_CPU_SKYLAKE_SP, CDISASM_CPU_ICE_LAKE,
        CDISASM_CPU_TIGER_LAKE, CDISASM_CPU_AMD_ZEN_4,
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_CPU_AVX10,
        CDISASM_CPU_APX, CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_DIAMOND_RAPIDS
    };
    cdisasm_x86_decode_flags avx = one_bit(CDISASM_X86_DECODE_BIT_AVX);
    cdisasm_x86_decode_flags width128 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_128);
    cdisasm_x86_decode_flags width256 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_256);
    cdisasm_x86_decode_flags width512 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_512);
    cdisasm_x86_decode_flags avx512 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512);
    cdisasm_x86_decode_flags width_apx = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512F_128,
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags available;
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vex, sizeof(vex), &avx, &decoded_size);
    check_move(&instruction, decoded_size, 1, UINT16_C(5952),
        0x10,128u,0,0,0,0u,0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        xmm, sizeof(xmm), &width128, &decoded_size);
    check_move(&instruction, decoded_size, 1, UINT16_C(5955),
        0x10,128u,0,1,0,0u,0);
    expect_error("AVX512 umbrella is not exact width",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        xmm, sizeof(xmm), &avx512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    for (index = 0u;
         index < sizeof(width128_positive) / sizeof(width128_positive[0]);
         ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            width128_positive[index], CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        instruction = decode(width128_positive[index], CDISASM_MODE_64,
            xmm, sizeof(xmm), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(xmm));
    }
    expect_error("Knights Mill lacks AVX512VL width",
        CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
        xmm, sizeof(xmm), NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64, &available)
        == CDISASM_STATUS_OK);
    instruction = decode(CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
        zmm, sizeof(zmm), &available, &decoded_size);
    EXPECT(decoded_size == sizeof(zmm));
    expect_error("Skylake client lacks AVX512F",
        CDISASM_CPU_SKYLAKE, CDISASM_MODE_64,
        zmm, sizeof(zmm), NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b4, sizeof(b4), &width_apx, &decoded_size);
    check_move(&instruction, decoded_size, 1, UINT16_C(5954),
        0x10,128u,1,1,1,0u,0);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R16);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_register, sizeof(b4_register), &width_apx, &decoded_size);
    EXPECT(decoded_size == sizeof(b4_register));
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM3);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        x4, sizeof(x4), &width_apx, &decoded_size);
    EXPECT(decoded_size == sizeof(x4));
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R20);
    expect_error("APX runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, b4, sizeof(b4), &width128,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 profile rejects B4", CDISASM_CPU_AVX10,
        CDISASM_MODE_64, b4, sizeof(b4), &width_apx,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        disp128, sizeof(disp128), &width128, &decoded_size);
    EXPECT(instruction.opcode[1].imm == (uint64_t)INT64_C(-16));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        disp256, sizeof(disp256), &width256, &decoded_size);
    EXPECT(instruction.opcode[1].imm == (uint64_t)INT64_C(-32));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        disp512, sizeof(disp512), &width512, &decoded_size);
    EXPECT(instruction.opcode[1].imm == (uint64_t)INT64_C(-64));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
        non64_vex, sizeof(non64_vex),
        &(cdisasm_x86_decode_flags)CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER,
        &decoded_size);
    EXPECT(decoded_size == sizeof(non64_vex));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM3);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
        non64_evex, sizeof(non64_evex),
        &(cdisasm_x86_decode_flags)CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER,
        &decoded_size);
    EXPECT(decoded_size == sizeof(non64_evex));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM3);
#else
    (void)zmm;
    expect_error("VEX extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex, sizeof(vex), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("EVEX extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, xmm, sizeof(xmm), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("APX extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, b4, sizeof(b4), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_invalid_and_truncated(void)
{
    static const uint8_t invalid[][6] = {
        {0xc5,0xe9,0x10,0xc1,0,0},       /* VEX vvvv */
        {0x62,0xf1,0x7d,0x08,0x10,0xc1}, /* UPS W1 */
        {0x62,0xf1,0x7c,0x18,0x10,0xc1}, /* b */
        {0x62,0xf1,0x7c,0x68,0x10,0xc1}, /* LL3 */
        {0x62,0xf1,0x7c,0x88,0x10,0xc1}, /* z/k0 */
        {0x62,0xf1,0x7c,0x00,0x10,0xc1}, /* V' */
        {0x62,0xf1,0x6c,0x08,0x10,0xc1}, /* vvvv */
        {0x62,0xf1,0x78,0x08,0x10,0xc1}, /* U0 register */
        {0x62,0xf1,0xfd,0x89,0x11,0x00}, /* store zeroing */
        {0x62,0xf9,0xfd,0x08,0x10,0x00}  /* APX profile/runtime */
    };
    static const uint8_t vex_missing_modrm[] = {0xc5,0xe9,0x10};
    static const uint8_t evex_missing_modrm[] = {
        0x62,0xf1,0x7d,0x18,0x10
    };
    static const uint8_t evex_missing_sib[] = {
        0x62,0xf1,0x7d,0x18,0x10,0x04
    };
    static const uint8_t non64_b4[] = {
        0x62,0xf9,0xfd,0x08,0x10,0x00
    };
    size_t index;

    for (index = 0u; index < 9u; ++index) {
        expect_error("reserved packed-move selector",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            invalid[index], sizeof(invalid[index]), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("VEX bad control missing ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex_missing_modrm, sizeof(vex_missing_modrm),
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("EVEX bad control missing ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex_missing_modrm, sizeof(evex_missing_modrm),
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("EVEX bad control missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex_missing_sib, sizeof(evex_missing_sib),
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("non-long APX B4", CDISASM_CPU_X86,
        CDISASM_MODE_32, non64_b4, sizeof(non64_b4),
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const struct {
        uint8_t code[7];
        size_t size;
        cdisasm_x86_decode_bit_id bit;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc5,0xf9,0x10,0xcb,0,0,0},4,
            CDISASM_X86_DECODE_BIT_AVX,
            "vmovupd xmm1, xmm3", "vmovupd %xmm3, %xmm1"},
        {{0x62,0xf1,0x7c,0x4a,0x10,0xcb,0},6,
            CDISASM_X86_DECODE_BIT_AVX512F_512,
            "vmovups zmm1 {k2}, zmm3", "vmovups %zmm3, %zmm1{%k2}"},
        {{0x62,0xf1,0xfd,0xa9,0x10,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512F_256,
            "vmovupd ymm0 {k1}{z}, ymmword ptr [rax - 0x20]",
            "vmovupd -0x20(%rax), %ymm0{%k1}{z}"},
        {{0x62,0xf1,0x7c,0x09,0x11,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512F_128,
            "vmovups xmmword ptr [rax - 0x10] {k1}, xmm0",
            "vmovups %xmm0, -0x10(%rax){%k1}"}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags = one_bit(cases[index].bit);
        cdisasm_instruction instruction;
        uint32_t decoded_size;
        char output[180];

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        EXPECT(decoded_size == cases[index].size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);
    }
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

    RUN_TEST(test_representative_form_order_and_legacy_collisions);
    RUN_TEST(test_all_allocated_domains);
    RUN_TEST(test_factored_reserved_and_collisions);
    RUN_TEST(test_profiles_runtime_apx_and_disp8);
    RUN_TEST(test_invalid_and_truncated);
    RUN_TEST(test_formatting);

#undef RUN_TEST

    if (failures != 0) {
        fprintf(stderr, "%d VMOVUPD/VMOVUPS test(s) failed\n", failures);
        return 1;
    }
    puts("x86 VMOVUPD/VMOVUPS tests passed "
         "(34 forms; allocated=2,425,856; factored reserved=3,190; "
         "collision selector cells=1,544)");
    return 0;
}
