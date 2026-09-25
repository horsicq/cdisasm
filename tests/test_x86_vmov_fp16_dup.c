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

_Static_assert(CDISASM_X86_NAME_VMOVSH == UINT16_C(1789)
        && CDISASM_X86_NAME_VMOVSHDUP == UINT16_C(1790)
        && CDISASM_X86_NAME_VMOVSLDUP == UINT16_C(1791),
    "VMOVSH/duplicate-move name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX512F_128 == UINT16_C(180)
        && CDISASM_X86_GROUP_AVX512F_256 == UINT16_C(182)
        && CDISASM_X86_GROUP_AVX512F_512 == UINT16_C(183)
        && CDISASM_X86_GROUP_AVX512_FP16_SCALAR == UINT16_C(204),
    "VMOVSH/duplicate-move ISA-set IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX512F_128 == UINT32_C(128)
        && CDISASM_X86_DECODE_BIT_AVX512F_256 == UINT32_C(130)
        && CDISASM_X86_DECODE_BIT_AVX512F_512 == UINT32_C(131)
        && CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR == UINT32_C(152),
    "VMOVSH/duplicate-move ISA-set bits changed");

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

static cdisasm_x86_group_id duplicate_width_group(unsigned int vector_bits)
{
    return vector_bits == 128u ? CDISASM_X86_GROUP_AVX512F_128
        : vector_bits == 256u ? CDISASM_X86_GROUP_AVX512F_256
                              : CDISASM_X86_GROUP_AVX512F_512;
}

static void check_duplicate(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_name_id name_id,
    cdisasm_x86_form_id form_id,
    unsigned int vector_bits,
    int memory_source,
    int evex,
    int apx,
    unsigned int aaa,
    int zero)
{
    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == name_id);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->operand_count == 2u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT(((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u)
        == evex);
    EXPECT(((instruction->opcode_flags & CDISASM_PREFIX_VEX) != 0u)
        == !evex);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].size == vector_bits / 8u);
    EXPECT(instruction->opcode[0].access
        == (evex && aaa != 0u && !zero
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
        instruction, duplicate_width_group(vector_bits)) == evex);
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

static void check_vmovsh(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_form_id form_id,
    int apx,
    unsigned int aaa,
    int zero)
{
    const int memory_destination = form_id == UINT16_C(5926);
    const int memory_source = form_id == UINT16_C(5927);
    const cdisasm_operand_access destination_access = aaa != 0u && !zero
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_WRITE;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_VMOVSH);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->operand_count
        == (memory_destination || memory_source ? 2u : 3u));
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
    EXPECT(instruction->opcode[0].type == (memory_destination
        ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
    EXPECT(instruction->opcode[0].size
        == (memory_destination ? 2u : 16u));
    EXPECT(instruction->opcode[0].access == (memory_destination
        ? CDISASM_OPERAND_ACCESS_WRITE : destination_access));
    EXPECT(instruction->opcode[1].type == (memory_source
        ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
    EXPECT(instruction->opcode[1].size == (memory_source ? 2u : 16u));
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    if (instruction->operand_count == 3u) {
        EXPECT(instruction->opcode[2].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction->opcode[2].size == 16u);
        EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    }
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512_FP16_SCALAR));
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

static cdisasm_x86_form_id duplicate_vex_form(
    uint8_t opcode,
    unsigned int vector_bits,
    int is_register)
{
    if (opcode == UINT8_C(0x16)) {
        return vector_bits == 128u
            ? (is_register ? UINT16_C(5917) : UINT16_C(5916))
            : (is_register ? UINT16_C(5923) : UINT16_C(5922));
    }
    return vector_bits == 128u
        ? (is_register ? UINT16_C(5930) : UINT16_C(5929))
        : (is_register ? UINT16_C(5936) : UINT16_C(5935));
}

static cdisasm_x86_form_id duplicate_evex_form(
    uint8_t opcode,
    unsigned int ll,
    int is_register)
{
    static const cdisasm_x86_form_id shdup_memory[3] = {
        UINT16_C(5918), UINT16_C(5920), UINT16_C(5924)
    };
    static const cdisasm_x86_form_id shdup_register[3] = {
        UINT16_C(5919), UINT16_C(5921), UINT16_C(5925)
    };
    static const cdisasm_x86_form_id sldup_memory[3] = {
        UINT16_C(5931), UINT16_C(5933), UINT16_C(5937)
    };
    static const cdisasm_x86_form_id sldup_register[3] = {
        UINT16_C(5932), UINT16_C(5934), UINT16_C(5938)
    };

    if (opcode == UINT8_C(0x16)) {
        return is_register ? shdup_register[ll] : shdup_memory[ll];
    }
    return is_register ? sldup_register[ll] : sldup_memory[ll];
}

static void test_representative_forms_and_legacy_collisions(void)
{
    static const uint8_t forms[][7] = {
        {0xc5,0xfa,0x16,0x00,0,0,0},
        {0xc5,0xfa,0x16,0xc1,0,0,0},
        {0x62,0xf1,0x7e,0x08,0x16,0x00,0},
        {0x62,0xf1,0x7e,0x08,0x16,0xc1,0},
        {0x62,0xf1,0x7e,0x28,0x16,0x00,0},
        {0x62,0xf1,0x7e,0x28,0x16,0xc1,0},
        {0xc5,0xfe,0x16,0x00,0,0,0},
        {0xc5,0xfe,0x16,0xc1,0,0,0},
        {0x62,0xf1,0x7e,0x48,0x16,0x00,0},
        {0x62,0xf1,0x7e,0x48,0x16,0xc1,0},
        {0x62,0xf5,0x7e,0x08,0x11,0x00,0},
        {0x62,0xf5,0x7e,0x08,0x10,0x00,0},
        {0x62,0xf5,0x6e,0x08,0x10,0xc1,0},
        {0xc5,0xfa,0x12,0x00,0,0,0},
        {0xc5,0xfa,0x12,0xc1,0,0,0},
        {0x62,0xf1,0x7e,0x08,0x12,0x00,0},
        {0x62,0xf1,0x7e,0x08,0x12,0xc1,0},
        {0x62,0xf1,0x7e,0x28,0x12,0x00,0},
        {0x62,0xf1,0x7e,0x28,0x12,0xc1,0},
        {0xc5,0xfe,0x12,0x00,0,0,0},
        {0xc5,0xfe,0x12,0xc1,0,0,0},
        {0x62,0xf1,0x7e,0x48,0x12,0x00,0},
        {0x62,0xf1,0x7e,0x48,0x12,0xc1,0}
    };
    size_t index;

    for (index = 0u; index < 23u; ++index) {
        const cdisasm_x86_form_id form_id =
            (cdisasm_x86_form_id)(UINT16_C(5916) + index);
        const size_t size = forms[index][0] == UINT8_C(0xc5) ? 4u : 6u;
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            forms[index], size,
#if USE_EXTRA_OPCODES
            &(cdisasm_x86_decode_flags)CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        EXPECT(decoded_size == size);
        EXPECT(instruction.form_id == form_id);
        EXPECT(instruction.name_id == (form_id <= UINT16_C(5925)
            ? CDISASM_X86_NAME_VMOVSHDUP
            : form_id <= UINT16_C(5928)
                ? CDISASM_X86_NAME_VMOVSH
                : CDISASM_X86_NAME_VMOVSLDUP));
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
            {0xf3,0x0f,0x16,0xc1}, {0xf3,0x0f,0x16,0x01},
            {0xf3,0x0f,0x12,0xc1}, {0xf3,0x0f,0x12,0x01}
        };
        static const cdisasm_x86_name_id names[] = {
            CDISASM_X86_NAME_MOVSHDUP, CDISASM_X86_NAME_MOVSHDUP,
            CDISASM_X86_NAME_MOVSLDUP, CDISASM_X86_NAME_MOVSLDUP
        };
        cdisasm_x86_decode_flags flags = one_bit(
            CDISASM_X86_DECODE_BIT_SSE3);

        for (index = 0u; index < 4u; ++index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                legacy[index], sizeof(legacy[index]), &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(legacy[index]));
            EXPECT(instruction.name_id == names[index]);
            EXPECT((instruction.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX)) == 0u);
        }
    }
#endif
}

static void test_complete_vex_allocated_domain(uint32_t per_form[23])
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint8_t opcodes[] = {0x16,0x12};
    uint32_t allocated = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const cdisasm_x86_mode mode = modes[mode_index];
        const int long_mode = mode == CDISASM_MODE_64;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(mode);
#endif
        size_t opcode_index;

        for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
            const uint8_t opcode = opcodes[opcode_index];
            unsigned int register_form;

            for (register_form = 0u; register_form < 2u; ++register_form) {
                unsigned int raw_r;

                for (raw_r = long_mode ? 0u : 1u; raw_r < 2u; ++raw_r) {
                    unsigned int l;

                    for (l = 0u; l < 2u; ++l) {
                        unsigned int modrm;

                        for (modrm = register_form ? 192u : 0u;
                             modrm < (register_form ? 256u : 192u);
                             ++modrm) {
                            uint8_t code[12] = {
                                0xc5,(uint8_t)((raw_r << 7) | 0x7au
                                    | (l << 2)),opcode,(uint8_t)modrm,
                                0x24,0x10,0x20,0x30,0x40,0x50,0x60,0x70
                            };
                            const unsigned int bits = 128u << l;
                            const cdisasm_x86_form_id form_id =
                                duplicate_vex_form(opcode, bits,
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
                            check_duplicate(&instruction, decoded_size,
                                opcode == UINT8_C(0x16)
                                    ? CDISASM_X86_NAME_VMOVSHDUP
                                    : CDISASM_X86_NAME_VMOVSLDUP,
                                form_id, bits, !register_form,
                                0, 0, 0u, 0);
#else
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            ++per_form[form_id - UINT16_C(5916)];
                            ++allocated;
                        }
                    }
                }

                for (raw_r = long_mode ? 0u : 1u; raw_r < 2u; ++raw_r) {
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

                                    for (modrm = register_form ? 192u : 0u;
                                         modrm < (register_form
                                            ? 256u : 192u); ++modrm) {
                                        uint8_t code[12] = {
                                            0xc4,
                                            (uint8_t)((raw_r << 7)
                                                | (raw_x << 6)
                                                | (raw_b << 5) | 1u),
                                            (uint8_t)((w << 7) | 0x7au
                                                | (l << 2)),
                                            opcode,(uint8_t)modrm,
                                            0x24,0x10,0x20,0x30,0x40,
                                            0x50,0x60
                                        };
                                        const unsigned int bits = 128u << l;
                                        const cdisasm_x86_form_id form_id =
                                            duplicate_vex_form(opcode, bits,
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
                                        check_duplicate(&instruction,
                                            decoded_size,
                                            opcode == UINT8_C(0x16)
                                                ? CDISASM_X86_NAME_VMOVSHDUP
                                                : CDISASM_X86_NAME_VMOVSLDUP,
                                            form_id, bits, !register_form,
                                            0, 0, 0u, 0);
#else
                                        EXPECT(decoded_size == 0u);
                                        EXPECT(is_error_only(&instruction,
                                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                        ++per_form[
                                            form_id - UINT16_C(5916)];
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
    EXPECT(allocated == UINT32_C(28672));
}

static void test_complete_duplicate_evex_domain(uint32_t per_form[23])
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint8_t opcodes[] = {0x16,0x12};
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
            size_t opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                const uint8_t opcode = opcodes[opcode_index];
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

                                for (aaa = zero ? 1u : 0u;
                                     aaa < 8u; ++aaa) {
                                    unsigned int modrm;

                                    for (modrm = register_form ? 192u : 0u;
                                         modrm < (register_form
                                            ? 256u : 192u); ++modrm) {
                                        const uint8_t p1 =
                                            (uint8_t)(0x7au | (u << 2));
                                        const uint8_t p2 = (uint8_t)(
                                            (zero << 7) | (ll << 5)
                                            | 0x08u | aaa);
                                        uint8_t code[12] = {
                                            0x62,p0,p1,p2,opcode,
                                            (uint8_t)modrm,0x24,0x10,0x20,
                                            0x30,0x40,0x50
                                        };
                                        const unsigned int bits = 128u << ll;
                                        const cdisasm_x86_form_id form_id =
                                            duplicate_evex_form(opcode, ll,
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
                                        check_duplicate(&instruction,
                                            decoded_size,
                                            opcode == UINT8_C(0x16)
                                                ? CDISASM_X86_NAME_VMOVSHDUP
                                                : CDISASM_X86_NAME_VMOVSLDUP,
                                            form_id, bits, !register_form,
                                            1, b4 || u == 0u, aaa, zero);
#else
                                        (void)bits;
                                        EXPECT(decoded_size == 0u);
                                        EXPECT(is_error_only(&instruction,
                                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                        ++per_form[
                                            form_id - UINT16_C(5916)];
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
    EXPECT(allocated == UINT32_C(1474560));
}

static void test_complete_vmovsh_domain(uint32_t per_form[23])
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
                ? (uint8_t)((p0_selector << 3) | 5u)
                : (uint8_t)(0xc5u | ((p0_selector & 2u) << 4)
                    | ((p0_selector & 1u) << 4));
            const int b4 = (p0 & UINT8_C(0x08)) != 0;
#if !USE_EXTRA_OPCODES
            (void)b4;
#endif
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
                                                    (raw_v << 3) | (u << 2)
                                                    | 2u);
                                                const uint8_t p2 = (uint8_t)(
                                                    (zero << 7) | (ll << 5)
                                                    | (v_prime << 3) | aaa);
                                                uint8_t code[12] = {
                                                    0x62,p0,p1,p2,opcode,
                                                    (uint8_t)modrm,0x24,0x10,
                                                    0x20,0x30,0x40,0x50
                                                };
                                                const cdisasm_x86_form_id
                                                    form_id = register_form
                                                        ? UINT16_C(5928)
                                                        : opcode
                                                                == UINT8_C(0x10)
                                                            ? UINT16_C(5927)
                                                            : UINT16_C(5926);
                                                uint32_t decoded_size;
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
                                                check_vmovsh(&instruction,
                                                    decoded_size, form_id,
                                                    b4 || u == 0u,
                                                    aaa, zero);
#else
                                                EXPECT(decoded_size == 0u);
                                                EXPECT(is_error_only(
                                                    &instruction,
                                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                                ++per_form[
                                                    form_id - UINT16_C(5916)];
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
}

static void test_all_allocated_domains(void)
{
    static const uint32_t expected[23] = {
        5376,1792,207360,38400,207360,38400,5376,1792,207360,38400,
        331776,622080,6635520,
        5376,1792,207360,38400,207360,38400,5376,1792,207360,38400
    };
    uint32_t per_form[23] = {0};
    size_t index;

    test_complete_vex_allocated_domain(per_form);
    test_complete_duplicate_evex_domain(per_form);
    test_complete_vmovsh_domain(per_form);
    for (index = 0u; index < 23u; ++index) {
        EXPECT(per_form[index] == expected[index]);
    }
}

static void test_factored_reserved_and_collisions(void)
{
    static const uint8_t opcodes[] = {0x16,0x12};
    uint32_t duplicate_reserved = 0u;
    uint32_t vmovsh_reserved = 0u;
    uint32_t collisions = 4u;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
    unsigned int encoding;

    for (encoding = 0u; encoding < 2u; ++encoding) {
        unsigned int value;

        for (value = 0u; value <= UINT8_MAX; ++value) {
            size_t opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                unsigned int register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    const uint8_t modrm = register_form ? 0xc0 : 0x00;
                    const int collision = (value & 3u) != 2u;
                    const int valid = !collision
                        && (((~value) >> 3) & 15u) == 0u;
                    uint8_t code[12] = {
                        encoding ? 0xc4 : 0xc5,
                        encoding ? 0xe1 : (uint8_t)value,
                        encoding ? (uint8_t)value : opcodes[opcode_index],
                        encoding ? opcodes[opcode_index] : modrm,
                        encoding ? modrm : 0x24,
                        0x24,0x10,0x20,0x30,0x40,0x50,0x60
                    };
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, CDISASM_MODE_64, code,
                        encoding ? 12u : 11u,
#if USE_EXTRA_OPCODES
                        &flags,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (collision) {
                        EXPECT(decoded_size == 0u
                            || (instruction.name_id
                                    != CDISASM_X86_NAME_VMOVSHDUP
                                && instruction.name_id
                                    != CDISASM_X86_NAME_VMOVSLDUP));
                        ++collisions;
                    } else if (valid) {
#if USE_EXTRA_OPCODES
                        EXPECT(decoded_size != 0u);
                        EXPECT(instruction.name_id == (opcode_index == 0u
                            ? CDISASM_X86_NAME_VMOVSHDUP
                            : CDISASM_X86_NAME_VMOVSLDUP));
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(
                            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++duplicate_reserved;
                    }
                }
            }
        }
    }

    {
        unsigned int value;

        for (value = 0u; value <= UINT8_MAX; ++value) {
            size_t opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                unsigned int register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    const uint8_t modrm = register_form ? 0xc0 : 0x00;
                    const int collision = (value & 3u) != 2u;
                    const int valid = !collision
                        && (value & UINT8_C(0x80)) == 0u
                        && (((~value) >> 3) & 15u) == 0u
                        && (!register_form
                            || (value & UINT8_C(0x04)) != 0u);
                    uint8_t code[12] = {
                        0x62,0xf1,(uint8_t)value,0x08,
                        opcodes[opcode_index],modrm,
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
                            || (instruction.name_id
                                    != CDISASM_X86_NAME_VMOVSHDUP
                                && instruction.name_id
                                    != CDISASM_X86_NAME_VMOVSLDUP));
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
                        ++duplicate_reserved;
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
            const int valid = ll < 3u
                && (value & UINT8_C(0x18)) == UINT8_C(0x08)
                && (!zero || aaa != 0u);
            size_t opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                unsigned int register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    const uint8_t modrm = register_form ? 0xc0 : 0x00;
                    uint8_t code[12] = {
                        0x62,0xf1,0x7e,(uint8_t)value,
                        opcodes[opcode_index],modrm,
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
                        EXPECT(is_error_only(
                            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++duplicate_reserved;
                    }
                }
            }
        }
    }

    {
        unsigned int value;

        for (value = 0u; value <= UINT8_MAX; ++value) {
            unsigned int opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                unsigned int register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    const uint8_t modrm = register_form ? 0xc0 : 0x00;
                    const int valid = (value & UINT8_C(0x83)) == 2u
                        && (register_form
                            ? (value & UINT8_C(0x04)) != 0u
                            : (((~value) >> 3) & 15u) == 0u);
                    uint8_t code[12] = {
                        0x62,0xf5,(uint8_t)value,0x08,
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
                        EXPECT(instruction.name_id
                            == CDISASM_X86_NAME_VMOVSH);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(
                            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++vmovsh_reserved;
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
            unsigned int opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                unsigned int register_form;

                for (register_form = 0u; register_form < 2u;
                     ++register_form) {
                    const int valid = ll < 3u
                        && (value & UINT8_C(0x10)) == 0u
                        && (register_form
                            || (value & UINT8_C(0x08)) != 0u)
                        && (!zero || aaa != 0u)
                        && !(zero && !register_form
                            && opcode_index == 1u);
                    const uint8_t modrm = register_form ? 0xc0 : 0x00;
                    uint8_t code[12] = {
                        0x62,0xf5,
                        register_form ? 0x6e : 0x7e,
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
                        EXPECT(is_error_only(
                            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++vmovsh_reserved;
                    }
                }
            }
        }
    }

    EXPECT(duplicate_reserved == UINT32_C(1574));
    EXPECT(vmovsh_reserved == UINT32_C(1763));
    EXPECT(collisions == UINT32_C(2308));
}

static void test_profiles_runtime_apx_and_disp8(void)
{
    static const uint8_t vex[] = {0xc5,0xfa,0x16,0xc1};
    static const uint8_t duplicate128[] = {0x62,0xf1,0x7e,0x08,0x16,0xc1};
    static const uint8_t duplicate512[] = {0x62,0xf1,0x7e,0x48,0x16,0xc1};
    static const uint8_t vmovsh[] = {0x62,0xf5,0x6e,0x08,0x10,0xcb};
    static const uint8_t duplicate_b4[] = {
        0x62,0xf9,0x7e,0x08,0x16,0x00
    };
#if USE_EXTRA_OPCODES
    static const uint8_t duplicate_x4[] = {
        0x62,0xf1,0x7a,0x08,0x12,0x04,0xa4
    };
    static const uint8_t duplicate_b4_reg[] = {
        0x62,0xf9,0x7e,0x08,0x16,0xcb
    };
    static const uint8_t vmovsh_b4[] = {
        0x62,0xfd,0x7e,0x08,0x10,0x00
    };
    static const uint8_t vmovsh_x4[] = {
        0x62,0xf5,0x7a,0x08,0x10,0x04,0xa4
    };
    static const uint8_t dup_disp128[] = {
        0x62,0xf1,0x7e,0x08,0x16,0x40,0xff
    };
    static const uint8_t dup_disp256[] = {
        0x62,0xf1,0x7e,0x28,0x16,0x40,0xff
    };
    static const uint8_t dup_disp512[] = {
        0x62,0xf1,0x7e,0x48,0x16,0x40,0xff
    };
    static const uint8_t sh_disp[] = {
        0x62,0xf5,0x7e,0x89,0x10,0x40,0xff
    };
    static const uint8_t non64_vex[] = {0xc4,0xc1,0x7a,0x16,0xcb};
    static const uint8_t non64_dup[] = {0x62,0xc1,0x7e,0x08,0x16,0xcb};
    static const uint8_t non64_sh[] = {0x62,0xc5,0x2e,0x08,0x10,0xcb};
    static const cdisasm_x86_cpu_id dup128_positive[] = {
        CDISASM_CPU_SKYLAKE_SP, CDISASM_CPU_ICE_LAKE,
        CDISASM_CPU_TIGER_LAKE, CDISASM_CPU_AMD_ZEN_4,
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_CPU_AVX10,
        CDISASM_CPU_APX, CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const cdisasm_x86_cpu_id sh_positive[] = {
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_CPU_AVX10,
        CDISASM_CPU_APX, CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_DIAMOND_RAPIDS
    };
    cdisasm_x86_decode_flags avx = one_bit(CDISASM_X86_DECODE_BIT_AVX);
    cdisasm_x86_decode_flags width128 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_128);
    cdisasm_x86_decode_flags width512 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_512);
    cdisasm_x86_decode_flags fp16 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR);
    cdisasm_x86_decode_flags avx512 = one_bit(
        CDISASM_X86_DECODE_BIT_AVX512);
    cdisasm_x86_decode_flags width_apx = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512F_128,
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags fp16_apx = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR,
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags available;
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vex, sizeof(vex), &avx, &decoded_size);
    check_duplicate(&instruction, decoded_size,
        CDISASM_X86_NAME_VMOVSHDUP, UINT16_C(5917),
        128u, 0, 0, 0, 0u, 0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        duplicate128, sizeof(duplicate128), &width128, &decoded_size);
    check_duplicate(&instruction, decoded_size,
        CDISASM_X86_NAME_VMOVSHDUP, UINT16_C(5919),
        128u, 0, 1, 0, 0u, 0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vmovsh, sizeof(vmovsh), &fp16, &decoded_size);
    check_vmovsh(&instruction, decoded_size, UINT16_C(5928), 0, 0u, 0);
    expect_error("AVX512 umbrella is not exact duplicate width",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        duplicate128, sizeof(duplicate128), &avx512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX512 umbrella is not exact FP16 scalar",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        vmovsh, sizeof(vmovsh), &avx512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    for (index = 0u;
         index < sizeof(dup128_positive) / sizeof(dup128_positive[0]);
         ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            dup128_positive[index], CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        instruction = decode(dup128_positive[index], CDISASM_MODE_64,
            duplicate128, sizeof(duplicate128), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(duplicate128));
    }
    expect_error("Knights Mill lacks AVX512VL duplicate width",
        CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
        duplicate128, sizeof(duplicate128), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64, &available)
        == CDISASM_STATUS_OK);
    instruction = decode(CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
        duplicate512, sizeof(duplicate512), &available, &decoded_size);
    EXPECT(decoded_size == sizeof(duplicate512));
    expect_error("Skylake client lacks AVX512 duplicate",
        CDISASM_CPU_SKYLAKE, CDISASM_MODE_64,
        duplicate512, sizeof(duplicate512), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    for (index = 0u; index < sizeof(sh_positive) / sizeof(sh_positive[0]);
         ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            sh_positive[index], CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        instruction = decode(sh_positive[index], CDISASM_MODE_64,
            vmovsh, sizeof(vmovsh), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(vmovsh));
    }
    expect_error("Skylake-SP lacks AVX512-FP16",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vmovsh, sizeof(vmovsh), NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("Zen4 lacks AVX512-FP16",
        CDISASM_CPU_AMD_ZEN_4, CDISASM_MODE_64,
        vmovsh, sizeof(vmovsh), NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        duplicate_b4, sizeof(duplicate_b4), &width_apx, &decoded_size);
    check_duplicate(&instruction, decoded_size,
        CDISASM_X86_NAME_VMOVSHDUP, UINT16_C(5918),
        128u, 1, 1, 1, 0u, 0);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R16);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        duplicate_b4_reg, sizeof(duplicate_b4_reg),
        &width_apx, &decoded_size);
    EXPECT(decoded_size == sizeof(duplicate_b4_reg));
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM3);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        duplicate_x4, sizeof(duplicate_x4), &width_apx, &decoded_size);
    EXPECT(decoded_size == sizeof(duplicate_x4));
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R20);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vmovsh_b4, sizeof(vmovsh_b4), &fp16_apx, &decoded_size);
    EXPECT(decoded_size == sizeof(vmovsh_b4));
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R16);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vmovsh_x4, sizeof(vmovsh_x4), &fp16_apx, &decoded_size);
    EXPECT(decoded_size == sizeof(vmovsh_x4));
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R20);
    expect_error("duplicate APX runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, duplicate_b4, sizeof(duplicate_b4), &width128,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("FP16 APX runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, vmovsh_b4, sizeof(vmovsh_b4), &fp16,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 profile rejects duplicate B4",
        CDISASM_CPU_AVX10, CDISASM_MODE_64,
        duplicate_b4, sizeof(duplicate_b4), &width_apx,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        dup_disp128, sizeof(dup_disp128), &width128, &decoded_size);
    EXPECT(instruction.opcode[1].imm == (uint64_t)INT64_C(-16));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        dup_disp256, sizeof(dup_disp256),
        &(cdisasm_x86_decode_flags)CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER,
        &decoded_size);
    EXPECT(instruction.opcode[1].imm == (uint64_t)INT64_C(-32));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        dup_disp512, sizeof(dup_disp512), &width512, &decoded_size);
    EXPECT(instruction.opcode[1].imm == (uint64_t)INT64_C(-64));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        sh_disp, sizeof(sh_disp), &fp16, &decoded_size);
    EXPECT(instruction.opcode[1].imm == (uint64_t)INT64_C(-2));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
        non64_vex, sizeof(non64_vex), &avx, &decoded_size);
    EXPECT(decoded_size == sizeof(non64_vex));
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM3);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
        non64_dup, sizeof(non64_dup),
        &(cdisasm_x86_decode_flags)CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER,
        &decoded_size);
    EXPECT(decoded_size == sizeof(non64_dup));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM3);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
        non64_sh, sizeof(non64_sh),
        &(cdisasm_x86_decode_flags)CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER,
        &decoded_size);
    EXPECT(decoded_size == sizeof(non64_sh));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM2);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM3);
#else
    (void)duplicate512;
    expect_error("VEX extras off", CDISASM_CPU_X86, CDISASM_MODE_64,
        vex, sizeof(vex), NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("duplicate EVEX extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, duplicate128, sizeof(duplicate128), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VMOVSH extras off", CDISASM_CPU_X86, CDISASM_MODE_64,
        vmovsh, sizeof(vmovsh), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("APX duplicate extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, duplicate_b4, sizeof(duplicate_b4), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_invalid_and_truncated(void)
{
    static const uint8_t invalid[][7] = {
        {0xc5,0xf2,0x16,0xc1,0,0,0},       /* VEX vvvv */
        {0x62,0xf1,0xfe,0x08,0x16,0xc1,0}, /* duplicate W1 */
        {0x62,0xf1,0x7e,0x18,0x16,0xc1,0}, /* duplicate b */
        {0x62,0xf1,0x7e,0x68,0x16,0xc1,0}, /* duplicate LL3 */
        {0x62,0xf1,0x7e,0x88,0x16,0xc1,0}, /* duplicate z/k0 */
        {0x62,0xf1,0x7e,0x00,0x16,0xc1,0}, /* duplicate V' */
        {0x62,0xf1,0x6e,0x08,0x16,0xc1,0}, /* duplicate vvvv */
        {0x62,0xf1,0x7a,0x08,0x16,0xc1,0}, /* duplicate U0 reg */
        {0x62,0xf5,0xfe,0x08,0x10,0xc1,0}, /* VMOVSH W1 */
        {0x62,0xf5,0x7e,0x18,0x10,0xc1,0}, /* VMOVSH b */
        {0x62,0xf5,0x7e,0x68,0x10,0xc1,0}, /* VMOVSH LL3 */
        {0x62,0xf5,0x7e,0x88,0x10,0xc1,0}, /* VMOVSH z/k0 */
        {0x62,0xf5,0x7e,0x89,0x11,0x00,0}, /* store zeroing */
        {0x62,0xf5,0x7e,0x00,0x10,0x00,0}, /* memory V' */
        {0x62,0xf5,0x7a,0x08,0x10,0xc1,0}, /* VMOVSH U0 reg */
        {0x62,0xf5,0x7d,0x08,0x10,0xc1,0}  /* VMOVSH p66 */
    };
    static const uint8_t vex_missing_modrm[] = {0xc5,0xf2,0x16};
    static const uint8_t dup_missing_modrm[] = {0x62,0xf1,0xfe,0x18,0x16};
    static const uint8_t sh_missing_modrm[] = {0x62,0xf5,0xfd,0x18,0x10};
    static const uint8_t dup_missing_sib[] = {
        0x62,0xf1,0xfe,0x18,0x16,0x04
    };
    static const uint8_t sh_missing_sib[] = {
        0x62,0xf5,0xfd,0x18,0x10,0x04
    };
    static const uint8_t sh_non64_vprime_register[] = {
        0x62,0xf5,0x6e,0x00,0x10,0xcb
    };
    size_t index;

    for (index = 0u; index < 16u; ++index) {
        expect_error("reserved move selector", CDISASM_CPU_X86,
            CDISASM_MODE_64, invalid[index], 6u, NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("VEX bad control missing ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, vex_missing_modrm, sizeof(vex_missing_modrm),
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("duplicate bad control missing ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, dup_missing_modrm, sizeof(dup_missing_modrm),
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("VMOVSH bad control missing ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, sh_missing_modrm, sizeof(sh_missing_modrm),
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("duplicate bad control missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64, dup_missing_sib, sizeof(dup_missing_sib),
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("VMOVSH bad control missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64, sh_missing_sib, sizeof(sh_missing_sib),
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("VMOVSH non-long register V-prime", CDISASM_CPU_X86,
        CDISASM_MODE_32, sh_non64_vprime_register,
        sizeof(sh_non64_vprime_register), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
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
        {{0xc5,0xfa,0x16,0xcb,0,0,0},4,
            CDISASM_X86_DECODE_BIT_AVX,
            "vmovshdup xmm1, xmm3", "vmovshdup %xmm3, %xmm1"},
        {{0x62,0xf1,0x7e,0x4a,0x16,0xcb,0},6,
            CDISASM_X86_DECODE_BIT_AVX512F_512,
            "vmovshdup zmm1 {k2}, zmm3", "vmovshdup %zmm3, %zmm1{%k2}"},
        {{0x62,0xf1,0x7e,0xa9,0x12,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512F_256,
            "vmovsldup ymm0 {k1}{z}, ymmword ptr [rax - 0x20]",
            "vmovsldup -0x20(%rax), %ymm0{%k1}{z}"},
        {{0x62,0xf5,0x6e,0x08,0x10,0xcb,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR,
            "vmovsh xmm1, xmm2, xmm3", "vmovsh %xmm3, %xmm2, %xmm1"},
        {{0x62,0xf5,0x7e,0x89,0x10,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR,
            "vmovsh xmm0 {k1}{z}, word ptr [rax - 0x2]",
            "vmovsh -0x2(%rax), %xmm0{%k1}{z}"},
        {{0x62,0xf5,0x7e,0x09,0x11,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR,
            "vmovsh word ptr [rax - 0x2] {k1}, xmm0",
            "vmovsh %xmm0, -0x2(%rax){%k1}"}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags = one_bit(cases[index].bit);
        cdisasm_instruction instruction;
        uint32_t decoded_size;
        char output[160];

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

    RUN_TEST(test_representative_forms_and_legacy_collisions);
    RUN_TEST(test_all_allocated_domains);
    RUN_TEST(test_factored_reserved_and_collisions);
    RUN_TEST(test_profiles_runtime_apx_and_disp8);
    RUN_TEST(test_invalid_and_truncated);
    RUN_TEST(test_formatting);

#undef RUN_TEST

    if (failures != 0) {
        fprintf(stderr, "%d VMOVSH/duplicate-move test(s) failed\n",
            failures);
        return 1;
    }
    puts("x86 VMOVSH/VMOVSHDUP/VMOVSLDUP tests passed "
         "(23 forms; allocated=9,092,608; factored reserved=3,337; "
         "collision selector cells=2,308)");
    return 0;
}
