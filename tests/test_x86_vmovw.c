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

_Static_assert(CDISASM_X86_NAME_VMOVW == UINT16_C(1793),
    "VMOVW name ID changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "AVX identity changed");
_Static_assert(CDISASM_X86_GROUP_AVX512_FP16_128N == UINT16_C(198)
        && CDISASM_X86_DECODE_BIT_AVX512_FP16_128N == UINT32_C(146),
    "AVX512_FP16_128N identity changed");
_Static_assert(CDISASM_X86_GROUP_AVX512_MOVZXC_128 == UINT16_C(221)
        && CDISASM_X86_DECODE_BIT_AVX512_MOVZXC_128 == UINT32_C(169),
    "AVX512_MOVZXC_128 identity changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VMOVW profile sweeps");

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

static void check_vmovw(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_form_id form_id,
    int apx)
{
    const int memory_destination = form_id == UINT16_C(5981)
        || form_id == UINT16_C(5982);
    const int memory_source = form_id == UINT16_C(5984)
        || form_id == UINT16_C(5985);
    const int gpr_destination = form_id == UINT16_C(5980);
    const int gpr_source = form_id == UINT16_C(5983);
    const int fp16 = form_id == UINT16_C(5980)
        || form_id == UINT16_C(5981)
        || form_id == UINT16_C(5983)
        || form_id == UINT16_C(5984);

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_VMOVW);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->operand_count == 2u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
    EXPECT(instruction->opcode[0].type == (memory_destination
        ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
    EXPECT(instruction->opcode[0].size == (memory_destination
        ? 2u : gpr_destination ? 4u : 16u));
    EXPECT(instruction->opcode[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[1].type == (memory_source
        ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
    EXPECT(instruction->opcode[1].size == (memory_source
        ? 2u : gpr_source ? 4u : 16u));
    EXPECT(instruction->opcode[1].access
        == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, fp16
            ? CDISASM_X86_GROUP_AVX512_FP16_128N
            : CDISASM_X86_GROUP_AVX512_MOVZXC_128));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, fp16
            ? CDISASM_X86_GROUP_AVX512_MOVZXC_128
            : CDISASM_X86_GROUP_AVX512_FP16_128N));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == apx);
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->encoding.immediate_count == 0u);
}
#endif

static cdisasm_x86_form_id expected_form(
    uint8_t prefix,
    uint8_t opcode,
    uint8_t modrm)
{
    const int is_register = (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);

    if (prefix == UINT8_C(1)) {
        if (opcode == UINT8_C(0x6e)) {
            return is_register ? UINT16_C(5983) : UINT16_C(5984);
        }
        return is_register ? UINT16_C(5980) : UINT16_C(5981);
    }
    if (is_register) {
        return UINT16_C(5986);
    }
    return opcode == UINT8_C(0x6e)
        ? UINT16_C(5985) : UINT16_C(5982);
}

static void test_allocation_and_form_counts(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const struct {
        uint8_t prefix;
        uint8_t w;
    } selectors[] = {
        {1,0}, {1,1}, {2,0}
    };
    uint32_t form_counts[7] = {0};
    uint32_t allocated = 0u;
    uint32_t reserved_u = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        unsigned int p0_index;
        const unsigned int p0_count = long_mode ? 32u : 4u;

        for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
            const uint8_t p0 = long_mode
                ? (uint8_t)((p0_index << 3) | 5u)
                : (uint8_t)(0xc5u | (p0_index << 4));
            size_t selector_index;

            for (selector_index = 0u;
                 selector_index < sizeof(selectors) / sizeof(selectors[0]);
                 ++selector_index) {
                unsigned int opcode_index;

                for (opcode_index = 0u; opcode_index < 2u;
                     ++opcode_index) {
                    const uint8_t opcode = opcode_index == 0u
                        ? UINT8_C(0x6e) : UINT8_C(0x7e);
                    unsigned int u;

                    for (u = 0u; u <= 1u; ++u) {
                        unsigned int modrm;

                        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                            const int reg = (modrm & UINT8_C(0xc0))
                                == UINT8_C(0xc0);
                            const int valid = u != 0u
                                || (long_mode && !reg);
                            const int apx = (p0 & UINT8_C(0x08)) != 0
                                || u == 0u;
                            uint8_t code[12] = {
                                0x62,p0,
                                (uint8_t)((selectors[selector_index].w << 7)
                                    | 0x78u | (u << 2)
                                    | selectors[selector_index].prefix),
                                0x08,opcode,(uint8_t)modrm,
                                0x24,0x10,0x20,0x30,0x40,0x50
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
#if !USE_EXTRA_OPCODES
                            (void)apx;
#endif

                            if (!valid) {
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_INVALID_INSTRUCTION));
                                ++reserved_u;
                            } else {
                                const cdisasm_x86_form_id form_id =
                                    expected_form(
                                        selectors[selector_index].prefix,
                                        opcode, (uint8_t)modrm);
#if USE_EXTRA_OPCODES
                                check_vmovw(&instruction, decoded_size,
                                    form_id, apx);
#else
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                ++allocated;
                                ++form_counts[form_id - UINT16_C(5980)];
                            }
                        }
                    }
                }
            }
        }
    }

    EXPECT(form_counts[0] == UINT32_C(5120));
    EXPECT(form_counts[1] == UINT32_C(27648));
    EXPECT(form_counts[2] == UINT32_C(13824));
    EXPECT(form_counts[3] == UINT32_C(5120));
    EXPECT(form_counts[4] == UINT32_C(27648));
    EXPECT(form_counts[5] == UINT32_C(13824));
    EXPECT(form_counts[6] == UINT32_C(5120));
    EXPECT(allocated == UINT32_C(98304));
    EXPECT(reserved_u == UINT32_C(24576));
}

static void test_owned_p1_p2_spaces(void)
{
    uint32_t p1_allocated = 0u;
    uint32_t p1_reserved = 0u;
    uint32_t p2_allocated = 0u;
    uint32_t p2_reserved = 0u;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
    unsigned int value;

    for (value = 0u; value <= UINT8_MAX; ++value) {
        unsigned int opcode_index;

        for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
            unsigned int representative;

            for (representative = 0u; representative < 2u;
                 ++representative) {
                const uint8_t opcode = opcode_index == 0u
                    ? UINT8_C(0x6e) : UINT8_C(0x7e);
                const uint8_t modrm = representative != 0u
                    ? UINT8_C(0xc1) : UINT8_C(0x01);
                const uint8_t prefix = (uint8_t)value & UINT8_C(3);
                const int u = (value & UINT8_C(4)) != 0;
                const int w = (value & UINT8_C(0x80)) != 0;
                const int fixed_vvvv =
                    (value & UINT8_C(0x78)) == UINT8_C(0x78);
                const int valid_prefix = prefix == UINT8_C(1)
                    || (prefix == UINT8_C(2) && !w);
                const int valid_u = u || representative == 0u;
                const int valid = fixed_vvvv && valid_prefix && valid_u;
                uint8_t code[12] = {
                    0x62,0xf5,(uint8_t)value,0x08,opcode,modrm,
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
                    check_vmovw(&instruction, decoded_size,
                        expected_form(prefix, opcode, modrm), !u);
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    ++p1_allocated;
                } else {
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_INVALID_INSTRUCTION));
                    ++p1_reserved;
                }
            }
        }
    }

    for (value = 0u; value <= UINT8_MAX; ++value) {
        unsigned int prefix_index;

        for (prefix_index = 0u; prefix_index < 2u; ++prefix_index) {
            unsigned int opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                unsigned int representative;

                for (representative = 0u; representative < 2u;
                     ++representative) {
                    const uint8_t prefix = prefix_index == 0u
                        ? UINT8_C(1) : UINT8_C(2);
                    const uint8_t opcode = opcode_index == 0u
                        ? UINT8_C(0x6e) : UINT8_C(0x7e);
                    const uint8_t modrm = representative != 0u
                        ? UINT8_C(0xc1) : UINT8_C(0x01);
                    uint8_t code[12] = {
                        0x62,0xf5,(uint8_t)(0x7cu | prefix),
                        (uint8_t)value,opcode,modrm,
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

                    if (value == UINT8_C(0x08)) {
#if USE_EXTRA_OPCODES
                        check_vmovw(&instruction, decoded_size,
                            expected_form(prefix, opcode, modrm), 0);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++p2_allocated;
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++p2_reserved;
                    }
                }
            }
        }
    }

    EXPECT(p1_allocated == UINT32_C(18));
    EXPECT(p1_reserved == UINT32_C(1006));
    EXPECT(p2_allocated == UINT32_C(8));
    EXPECT(p2_reserved == UINT32_C(2040));
}

static void test_profiles_runtime_extensions_and_disp8(void)
{
    static const uint8_t fp16[] = {0x62,0xf5,0x7d,0x08,0x6e,0xc1};
    static const uint8_t movzxc[] = {0x62,0xf5,0x7e,0x08,0x6e,0xc1};
    static const uint8_t b4_gpr[] = {0x62,0xfd,0x7d,0x08,0x6e,0xc1};
    static const uint8_t b4_xmm[] = {0x62,0xfd,0x7e,0x08,0x6e,0xc1};
    static const uint8_t b4_memory[] = {0x62,0xfd,0x7d,0x08,0x6e,0x00};
    static const uint8_t x4_memory[] = {
        0x62,0xf5,0x79,0x08,0x6e,0x04,0xa4
    };
    static const uint8_t high_xmm[] = {0x62,0x05,0x7e,0x08,0x6e,0xc1};
    static const uint8_t nonlong[] = {0x62,0xc5,0x7e,0x08,0x6e,0xc1};
    static const uint8_t disp8[] = {
        0x62,0xf5,0x7e,0x08,0x6e,0x40,0xff
    };
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_cpu_id fp16_positive[] = {
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_CPU_AVX10,
        CDISASM_CPU_APX, CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const cdisasm_x86_cpu_id movzxc_positive[] = {
        CDISASM_CPU_AVX10, CDISASM_CPU_APX,
        CDISASM_CPU_DIAMOND_RAPIDS
    };
    cdisasm_x86_decode_flags fp16_flag =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512_FP16_128N);
    cdisasm_x86_decode_flags movzxc_flag =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512_MOVZXC_128);
    cdisasm_x86_decode_flags avx512_flag =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512);
    cdisasm_x86_decode_flags fp16_apx = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512_FP16_128N,
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags movzxc_apx = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512_MOVZXC_128,
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags available;
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        fp16, sizeof(fp16), &fp16_flag, &decoded_size);
    check_vmovw(&instruction, decoded_size, UINT16_C(5983), 0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        movzxc, sizeof(movzxc), &movzxc_flag, &decoded_size);
    check_vmovw(&instruction, decoded_size, UINT16_C(5986), 0);
    expect_error("FP16 exact runtime", CDISASM_CPU_X86,
        CDISASM_MODE_64, fp16, sizeof(fp16), &movzxc_flag,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("MOVZXC exact runtime", CDISASM_CPU_X86,
        CDISASM_MODE_64, movzxc, sizeof(movzxc), &fp16_flag,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX512 umbrella is not exact", CDISASM_CPU_X86,
        CDISASM_MODE_64, fp16, sizeof(fp16), &avx512_flag,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    for (index = 0u;
         index < sizeof(fp16_positive) / sizeof(fp16_positive[0]);
         ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            fp16_positive[index], CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        instruction = decode(fp16_positive[index], CDISASM_MODE_64,
            fp16, sizeof(fp16), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(fp16));
    }
    for (index = 0u;
         index < sizeof(movzxc_positive) / sizeof(movzxc_positive[0]);
         ++index) {
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            movzxc_positive[index], CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        instruction = decode(movzxc_positive[index], CDISASM_MODE_64,
            movzxc, sizeof(movzxc), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(movzxc));
    }
    expect_error("Ice Lake lacks FP16_128N", CDISASM_CPU_ICE_LAKE,
        CDISASM_MODE_64, fp16, sizeof(fp16), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("Sapphire Rapids lacks MOVZXC_128",
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
        movzxc, sizeof(movzxc), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_gpr, sizeof(b4_gpr), &fp16_apx, &decoded_size);
    check_vmovw(&instruction, decoded_size, UINT16_C(5983), 1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R17D);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_xmm, sizeof(b4_xmm), &movzxc_apx, &decoded_size);
    check_vmovw(&instruction, decoded_size, UINT16_C(5986), 1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_memory, sizeof(b4_memory), &fp16_apx, &decoded_size);
    check_vmovw(&instruction, decoded_size, UINT16_C(5984), 1);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R16);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        x4_memory, sizeof(x4_memory), &fp16_apx, &decoded_size);
    check_vmovw(&instruction, decoded_size, UINT16_C(5984), 1);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R20);
    expect_error("APX runtime", CDISASM_CPU_X86, CDISASM_MODE_64,
        b4_gpr, sizeof(b4_gpr), &fp16_flag,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX10 rejects APX B4", CDISASM_CPU_AVX10,
        CDISASM_MODE_64, b4_gpr, sizeof(b4_gpr), &fp16_apx,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        high_xmm, sizeof(high_xmm), &movzxc_flag, &decoded_size);
    check_vmovw(&instruction, decoded_size, UINT16_C(5986), 0);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM24);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM25);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
        nonlong, sizeof(nonlong), &movzxc_flag, &decoded_size);
    check_vmovw(&instruction, decoded_size, UINT16_C(5986), 0);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM0);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        disp8, sizeof(disp8), &movzxc_flag, &decoded_size);
    check_vmovw(&instruction, decoded_size, UINT16_C(5985), 0);
    EXPECT(instruction.opcode[1].imm == (uint64_t)INT64_C(-2));
#else
    expect_error("FP16 profile remains owned extras off",
        CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
        fp16, sizeof(fp16), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("MOVZXC profile remains owned extras off",
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
        movzxc, sizeof(movzxc), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    (void)b4_gpr;
    (void)b4_xmm;
    (void)b4_memory;
    (void)x4_memory;
    (void)high_xmm;
    (void)nonlong;
    (void)disp8;
#endif
}

static void test_invalid_truncated_and_collisions(void)
{
    static const uint8_t invalid[][7] = {
        {0x62,0xf5,0x7c,0x08,0x6e,0xc1,0}, /* pp none */
        {0x62,0xf5,0x7f,0x08,0x6e,0xc1,0}, /* pp F2 */
        {0x62,0xf5,0xfe,0x08,0x6e,0xc1,0}, /* F3 W1 */
        {0x62,0xf5,0x6d,0x08,0x6e,0xc1,0}, /* vvvv */
        {0x62,0xf5,0x7d,0x28,0x6e,0xc1,0}, /* LL1 */
        {0x62,0xf5,0x7d,0x18,0x6e,0xc1,0}, /* b */
        {0x62,0xf5,0x7d,0x09,0x6e,0xc1,0}, /* aaa */
        {0x62,0xf5,0x7d,0x88,0x6e,0xc1,0}, /* z */
        {0x62,0xf5,0x79,0x08,0x6e,0xc1,0}, /* U0 register */
        {0x62,0xfd,0x7d,0x08,0x6e,0xc1,0}  /* non-long B4 */
    };
    static const uint8_t missing_modrm[] = {
        0x62,0xf5,0x7c,0x08,0x6e
    };
    static const uint8_t missing_sib[] = {
        0x62,0xf5,0x6c,0x28,0x6e,0x04
    };
    static const uint8_t legacy_prefix[] = {
        0x66,0x62,0xf5,0x7d,0x08,0x6e,0xc1
    };
#if USE_EXTRA_OPCODES
    static const uint8_t map2_neighbors[][6] = {
        {0x62,0xf2,0x7d,0x08,0x7e,0xc1},
        {0x62,0xf2,0xfd,0x08,0x7e,0xc1},
        {0x62,0xf2,0x7d,0x08,0x7e,0x01},
        {0x62,0xf2,0xfd,0x08,0x7e,0x01}
    };
#endif
    size_t index;

    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error("reserved VMOVW selector", CDISASM_CPU_X86,
            index + 1u == sizeof(invalid) / sizeof(invalid[0])
                ? CDISASM_MODE_32 : CDISASM_MODE_64,
            invalid[index], 6u, NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("missing ModRM beats reserved pp", CDISASM_CPU_X86,
        CDISASM_MODE_64, missing_modrm, sizeof(missing_modrm), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("missing SIB beats reserved controls", CDISASM_CPU_X86,
        CDISASM_MODE_64, missing_sib, sizeof(missing_sib), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("legacy prefix collision", CDISASM_CPU_X86,
        CDISASM_MODE_64, legacy_prefix, sizeof(legacy_prefix), NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);

        for (index = 0u;
             index < sizeof(map2_neighbors) / sizeof(map2_neighbors[0]);
             ++index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                map2_neighbors[index], sizeof(map2_neighbors[index]),
                &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(map2_neighbors[index]));
            EXPECT(instruction.name_id != CDISASM_X86_NAME_VMOVW);
        }
    }
#endif

    /* The corresponding 12 canonical map-1 selector cells are delegated to
     * VMOVD/VMOVQ (10 allocated there, while F3/W0 6E reg/mem are invalid).
     * None may ever be captured as map-5 VMOVW. */
    {
        static const uint8_t p1s[] = {0x7d,0xfd,0x7e};
        unsigned int delegated = 0u;
        unsigned int allocated_neighbor = 0u;
        unsigned int reserved_neighbor = 0u;
        size_t p1_index;

        for (p1_index = 0u; p1_index < 3u; ++p1_index) {
            unsigned int opcode_index;

            for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
                unsigned int representative;

                for (representative = 0u; representative < 2u;
                     ++representative) {
                    uint8_t code[7] = {
                        0x62,0xf1,p1s[p1_index],0x08,
                        opcode_index == 0u ? 0x6e : 0x7e,
                        representative == 0u ? 0x01 : 0xc1,0x24
                    };
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, sizeof(code),
#if USE_EXTRA_OPCODES
                        &(cdisasm_x86_decode_flags)
                            CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (p1_index == 2u && opcode_index == 0u) {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++reserved_neighbor;
                    } else {
#if USE_EXTRA_OPCODES
                        EXPECT(decoded_size != 0u);
                        EXPECT(instruction.name_id
                            == (p1_index == 1u
                                ? CDISASM_X86_NAME_VMOVQ
                                : CDISASM_X86_NAME_VMOVD));
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++allocated_neighbor;
                    }
                    ++delegated;
                }
            }
        }
        EXPECT(delegated == UINT32_C(12));
        EXPECT(allocated_neighbor == UINT32_C(10));
        EXPECT(reserved_neighbor == UINT32_C(2));
    }
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
        {{0x62,0xf5,0x7d,0x08,0x6e,0xc1,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_128N,
            "vmovw xmm0, ecx", "vmovw %ecx, %xmm0"},
        {{0x62,0xf5,0x7d,0x08,0x6e,0x00,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_128N,
            "vmovw xmm0, word ptr [rax]", "vmovw (%rax), %xmm0"},
        {{0x62,0xf5,0x7d,0x08,0x7e,0xc1,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_128N,
            "vmovw ecx, xmm0", "vmovw %xmm0, %ecx"},
        {{0x62,0xf5,0x7d,0x08,0x7e,0x00,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_128N,
            "vmovw word ptr [rax], xmm0", "vmovw %xmm0, (%rax)"},
        {{0x62,0xf5,0x7e,0x08,0x6e,0xc1,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_MOVZXC_128,
            "vmovw xmm0, xmm1", "vmovw %xmm1, %xmm0"},
        {{0x62,0xf5,0x7e,0x08,0x6e,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512_MOVZXC_128,
            "vmovw xmm0, word ptr [rax - 0x2]",
            "vmovw -0x2(%rax), %xmm0"},
        {{0x62,0xf5,0x7e,0x08,0x7e,0xc1,0},6,
            CDISASM_X86_DECODE_BIT_AVX512_MOVZXC_128,
            "vmovw xmm1, xmm0", "vmovw %xmm0, %xmm1"},
        {{0x62,0xf5,0x7e,0x08,0x7e,0x40,0xff},7,
            CDISASM_X86_DECODE_BIT_AVX512_MOVZXC_128,
            "vmovw word ptr [rax - 0x2], xmm0",
            "vmovw %xmm0, -0x2(%rax)"}
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

    RUN_TEST(test_allocation_and_form_counts);
    RUN_TEST(test_owned_p1_p2_spaces);
    RUN_TEST(test_profiles_runtime_extensions_and_disp8);
    RUN_TEST(test_invalid_truncated_and_collisions);
    RUN_TEST(test_formatting);
#undef RUN_TEST

    if (failures != 0) {
        fprintf(stderr, "x86 VMOVW tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 VMOVW tests passed");
    return 0;
}
