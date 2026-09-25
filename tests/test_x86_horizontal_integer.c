#include "cdisasm/cdisasm_x86.h"
#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(c) do { if (!(c)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); \
    ++failures; } } while (0)

typedef struct family {
    uint8_t opcode;
    cdisasm_x86_name_id name;
    cdisasm_x86_form_id base;
} family;

static const family families[6] = {
    {0x02, CDISASM_X86_NAME_VPHADDD, 7012},
    {0x03, CDISASM_X86_NAME_VPHADDSW, 7016},
    {0x01, CDISASM_X86_NAME_VPHADDW, 7036},
    {0x06, CDISASM_X86_NAME_VPHSUBD, 7046},
    {0x07, CDISASM_X86_NAME_VPHSUBSW, 7050},
    {0x05, CDISASM_X86_NAME_VPHSUBW, 7056}};

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

static cdisasm_x86_decode_flags all_flags(cdisasm_mode mode)
{
    cdisasm_x86_decode_flags flags;
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, mode, &flags) == CDISASM_STATUS_OK);
    return flags;
}

#if USE_EXTRA_OPCODES
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
#endif

static int is_error(const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    return instruction->last_error_id == status
        && instruction->opcode_size == 0u
        && instruction->name_id == CDISASM_X86_NAME_NONE;
}

static void test_partition(void)
{
    static const cdisasm_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const uint8_t nonlong_p0[2] = {0xc2, 0xe2};
    static const uint8_t long_p0[8] = {
        0x02,0x22,0x42,0x62,0x82,0xa2,0xc2,0xe2};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    uint64_t form_counts[24] = {0};
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const uint8_t *p0s = mode_index == 2u ? long_p0 : nonlong_p0;
        const size_t p0_count = mode_index == 2u ? 8u : 2u;
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
        size_t p0_index;

        for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
            unsigned int p1;
            for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                unsigned int modrm;
                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    size_t family_index;
                    for (family_index = 0u; family_index < 6u;
                         ++family_index) {
                        const uint8_t code[15] = {
                            0xc4, p0s[p0_index], (uint8_t)p1,
                            families[family_index].opcode, (uint8_t)modrm,
                            0,0,0,0,0,0,0,0,0,0};
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_X86, modes[mode_index], code,
                            sizeof(code), &flags, &decoded_size);

                        if ((p1 & 3u) == 1u) {
                            const unsigned int width_offset =
                                (p1 & 4u) != 0u ? 2u : 0u;
                            const unsigned int register_offset =
                                (modrm & 0xc0u) == 0xc0u ? 1u : 0u;
#if USE_EXTRA_OPCODES
                            EXPECT(decoded_size >= 5u);
                            EXPECT(instruction.name_id
                                == families[family_index].name);
                            EXPECT(instruction.form_id
                                == families[family_index].base
                                    + width_offset + register_offset);
                            EXPECT(instruction.operand_count == 3u);
#else
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            ++form_counts[family_index * 4u
                                + width_offset + register_offset];
                            ++allocated;
                        } else {
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error(&instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                            ++reserved;
                        }
                    }
                }
            }
        }
    }
    EXPECT(allocated == UINT64_C(1179648));
    EXPECT(reserved == UINT64_C(3538944));
    for (mode_index = 0u; mode_index < 24u; ++mode_index) {
        EXPECT(form_counts[mode_index]
            == ((mode_index & 1u) != 0u
                ? UINT64_C(24576) : UINT64_C(73728)));
    }
}

static void test_exact_forms_and_boundaries(void)
{
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t family_index;

    for (family_index = 0u; family_index < 6u; ++family_index) {
        unsigned int width;
        for (width = 0u; width < 2u; ++width) {
            unsigned int reg_form;
            for (reg_form = 0u; reg_form < 2u; ++reg_form) {
                const uint8_t code[5] = {
                    0xc4,0xe2,(uint8_t)(0x71u | (width << 2)),
                    families[family_index].opcode,
                    (uint8_t)(reg_form != 0u ? 0xc2u : 0x00u)};
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                    CDISASM_MODE_64, code, sizeof(code), &flags,
                    &decoded_size);
#if USE_EXTRA_OPCODES
                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.name_id == families[family_index].name);
                EXPECT(instruction.form_id == families[family_index].base
                    + width * 2u + reg_form);
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(instruction.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX2) == (width != 0u));
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            }
        }
    }

    {
        const uint8_t short_prefix[] = {0xc4,0xe2};
        const uint8_t short_opcode[] = {0xc4,0xe2,0x71};
        const uint8_t bad_pp[] = {0xc4,0xe2,0x70,0x02,0xc2};
        const uint8_t short_sib[] = {0xc4,0xe2,0x71,0x02,0x04};
        const uint8_t short_disp8[] = {0xc4,0xe2,0x71,0x02,0x45};
        const uint8_t short_disp32[] = {
            0xc4,0xe2,0x71,0x02,0x05,0x11,0x22,0x33};
        const uint8_t prefixed_short[] = {
            0x66,0xc4,0xe2,0x71,0x02,0x04};
        const uint8_t prefixed_complete[] = {
            0x66,0xc4,0xe2,0x71,0x02,0xc2};
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            short_prefix, sizeof(short_prefix), &flags, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error(&instruction, CDISASM_STATUS_TRUNCATED));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            short_opcode, sizeof(short_opcode), &flags, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error(&instruction, CDISASM_STATUS_TRUNCATED));

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            bad_pp, sizeof(bad_pp), &flags, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            short_sib, sizeof(short_sib), &flags, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error(&instruction, CDISASM_STATUS_TRUNCATED));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            short_disp8, sizeof(short_disp8), &flags, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error(&instruction, CDISASM_STATUS_TRUNCATED));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            short_disp32, sizeof(short_disp32), &flags, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error(&instruction, CDISASM_STATUS_TRUNCATED));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            prefixed_short, sizeof(prefixed_short), &flags, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error(&instruction, CDISASM_STATUS_TRUNCATED));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            prefixed_complete, sizeof(prefixed_complete), &flags,
            &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error(&instruction,
            CDISASM_STATUS_INVALID_INSTRUCTION));
    }
}

static void test_aliases_and_siblings(void)
{
#if USE_EXTRA_OPCODES
    const uint8_t xmm[] = {0xc4,0xe2,0x71,0x02,0xc2};
    const uint8_t ymm[] = {0xc4,0xe2,0x75,0x02,0xc2};
#endif
    const uint8_t w1[] = {0xc4,0xe2,0xf1,0x03,0xc2};
    const uint8_t nonlong[] = {0xc4,0xc2,0x31,0x05,0xc2};
    const uint8_t high[] = {0xc4,0x42,0x35,0x02,0xcb};
    const uint8_t address[] = {0x67,0xc4,0xe2,0x71,0x02,0x00};
    const uint8_t legacy_add[] = {0x66,0x0f,0x38,0x02,0xc2};
    const uint8_t legacy_sub[] = {0x66,0x0f,0x38,0x07,0xc2};
    const uint8_t xop_add[] = {0x8f,0xe9,0x78,0xc6,0xc1};
    const uint8_t xop_sub[] = {0x8f,0xe9,0x78,0xe2,0xc1};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        w1, sizeof(w1), &flags, &decoded_size);
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(w1));
    EXPECT(instruction.form_id == UINT16_C(7017));
    {
        const cdisasm_x86_decode_flags none = selected_flags(0, 0);
        const cdisasm_x86_decode_flags avx = selected_flags(1, 0);
        const cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);
        cdisasm_x86_decode_flags profile;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            xmm, sizeof(xmm), &none, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            xmm, sizeof(xmm), &avx, &decoded_size);
        EXPECT(decoded_size == sizeof(xmm));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            xmm, sizeof(xmm), &avx2, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            ymm, sizeof(ymm), &avx, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            ymm, sizeof(ymm), &avx2, &decoded_size);
        EXPECT(decoded_size == sizeof(ymm));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX2));
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_SANDY_BRIDGE,
            CDISASM_MODE_64, &profile) == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
            xmm, sizeof(xmm), &profile, &decoded_size);
        EXPECT(decoded_size == sizeof(xmm));
        instruction = decode(CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
            ymm, sizeof(ymm), &profile, &decoded_size);
        EXPECT(decoded_size == 0u);
        EXPECT(is_error(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_HASWELL,
            CDISASM_MODE_64, &profile) == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_HASWELL, CDISASM_MODE_64,
            ymm, sizeof(ymm), &profile, &decoded_size);
        EXPECT(decoded_size == sizeof(ymm));
    }
#else
    EXPECT(decoded_size == 0u);
    EXPECT(is_error(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    flags = all_flags(CDISASM_MODE_16);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_16,
        nonlong, sizeof(nonlong), &flags, &decoded_size);
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(nonlong));
    EXPECT(instruction.form_id == UINT16_C(7057));
#else
    EXPECT(decoded_size == 0u);
    EXPECT(is_error(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    flags = all_flags(CDISASM_MODE_64);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        high, sizeof(high), &flags, &decoded_size);
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(high));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM9);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_YMM9);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_YMM11);
#else
    EXPECT(decoded_size == 0u);
    EXPECT(is_error(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        address, sizeof(address), &flags, &decoded_size);
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(address));
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_EAX);
#else
    EXPECT(decoded_size == 0u);
    EXPECT(is_error(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    flags = all_flags(CDISASM_MODE_64);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_add, sizeof(legacy_add), &flags, &decoded_size);
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(legacy_add));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PHADDD);
#else
    EXPECT(decoded_size == 0u);
    EXPECT(is_error(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_sub, sizeof(legacy_sub), &flags, &decoded_size);
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(legacy_sub));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PHSUBSW);
#else
    EXPECT(decoded_size == 0u);
    EXPECT(is_error(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        xop_add, sizeof(xop_add), &flags, &decoded_size);
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(xop_add));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPHADDWD);
#else
    EXPECT(decoded_size == 0u);
    EXPECT(is_error(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        xop_sub, sizeof(xop_sub), &flags, &decoded_size);
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(xop_sub));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPHSUBWD);
#else
    EXPECT(decoded_size == 0u);
    EXPECT(is_error(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void test_format_schema(void)
{
    const uint8_t code[] = {0xc4,0xe2,0x75,0x06,0xc2};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &flags, &decoded_size);
    cdisasm_instruction forged;
    char output[128];

    EXPECT(decoded_size == sizeof(code));
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) != 0u);
    EXPECT(strcmp(output, "vphsubd ymm0, ymm1, ymm2") == 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output)) != 0u);
    EXPECT(strcmp(output, "vphsubd %ymm2, %ymm1, %ymm0") == 0);
    forged = instruction;
    forged.form_id = UINT16_C(7050);
    EXPECT(cdisasm_x86_format(&forged, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == 0u);
    forged = instruction;
    forged.name_id = CDISASM_X86_NAME_VPHADDW;
    EXPECT(cdisasm_x86_format(&forged, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == 0u);
    forged = instruction;
    forged.operand_count
        = 0u;
    EXPECT(cdisasm_x86_format(&forged, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == 0u);
}
#else
static void test_format_schema(void) {}
#endif

int main(void)
{
    test_partition();
    test_exact_forms_and_boundaries();
    test_aliases_and_siblings();
    test_format_schema();
    if (failures != 0) {
        fprintf(stderr, "%d horizontal integer test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
