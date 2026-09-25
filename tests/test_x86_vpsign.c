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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",          \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VPSIGNB == UINT16_C(1912)
        && CDISASM_X86_NAME_VPSIGND == UINT16_C(1913)
        && CDISASM_X86_NAME_VPSIGNW == UINT16_C(1914),
    "VPSIGN name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "VPSIGN capability IDs changed");

typedef struct sign_family {
    uint8_t opcode;
    cdisasm_x86_name_id name;
    cdisasm_x86_form_id base;
} sign_family;

static const sign_family families[3] = {
    {0x08, CDISASM_X86_NAME_VPSIGNB, 7921},
    {0x0a, CDISASM_X86_NAME_VPSIGND, 7925},
    {0x09, CDISASM_X86_NAME_VPSIGNW, 7929}};

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

static void check_sign(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    const sign_family *family,
    unsigned int vector_bits,
    int register_form)
{
    const unsigned int vector_bytes = vector_bits / 8u;
    const cdisasm_x86_reg_id register_base = vector_bits == 256u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    const cdisasm_x86_form_id form = (cdisasm_x86_form_id)(family->base
        + (vector_bits == 256u ? 2u : 0u)
        + (register_form ? 1u : 0u));
    size_t index;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == family->name);
    EXPECT(instruction->form_id == form);
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
    EXPECT(instruction->encoding.prefix_size == 3u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset == 0u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = !register_form && index == 2u;

        EXPECT(operand->type == (memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(operand->size == vector_bytes);
        EXPECT(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
        EXPECT(operand->broadcast == CDISASM_X86_BROADCAST_NONE);
        if (memory) {
            EXPECT((operand->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
        } else {
            EXPECT(operand->reg >= register_base
                && operand->reg <= register_base + 15u);
            EXPECT(operand->flags == 0u);
            if (mode != CDISASM_MODE_64) {
                EXPECT(operand->reg <= register_base + 7u);
            }
        }
    }
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->branch_target == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT((vector_bits == 256u)
        == cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX2));
}
#endif

static void test_c4_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    uint64_t form_counts[12] = {0u};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;

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
                : (uint8_t)(0xc2u | (p0_index << 5));
            unsigned int p1;

            for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                const int valid = ((uint8_t)p1 & UINT8_C(3))
                    == UINT8_C(1);
                size_t family_index;

                for (family_index = 0u; family_index < 3u;
                     ++family_index) {
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const uint8_t code[15] = {
                            0xc4,p0,(uint8_t)p1,
                            families[family_index].opcode,(uint8_t)modrm,
                            0x24,0x10,0x20,0x30,0x40,
                            0x50,0x60,0x70,0x80,0x90};
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

                        if (valid) {
#if USE_EXTRA_OPCODES
                            const unsigned int vector_bits =
                                (p1 & UINT8_C(4)) != 0u ? 256u : 128u;
                            const cdisasm_x86_reg_id register_base =
                                vector_bits == 256u
                                    ? CDISASM_X86_REG_YMM0
                                    : CDISASM_X86_REG_XMM0;
                            const int register_form =
                                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                            const unsigned int slot = family_index * 4u
                                + (vector_bits == 256u ? 2u : 0u)
                                + (register_form ? 1u : 0u);

                            check_sign(&instruction, decoded_size,
                                modes[mode_index], &families[family_index],
                                vector_bits, register_form);
                            EXPECT(instruction.encoding.opcode_offset == 3u);
                            EXPECT(instruction.opcode[0].reg
                                == register_base
                                    + ((modrm >> 3) & UINT8_C(7))
                                    + (long_mode
                                        && (p0 & UINT8_C(0x80)) == 0u
                                        ? 8u : 0u));
                            EXPECT(instruction.opcode[1].reg
                                == register_base
                                    + (((~p1) >> 3)
                                        & (long_mode ? 15u : 7u)));
                            if (register_form) {
                                EXPECT(instruction.opcode[2].reg
                                    == register_base
                                        + (modrm & UINT8_C(7))
                                        + (long_mode
                                            && (p0 & UINT8_C(0x20)) == 0u
                                            ? 8u : 0u));
                            }
                            ++form_counts[slot];
#else
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
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
    EXPECT(allocated == UINT64_C(589824));
    EXPECT(reserved == UINT64_C(1769472));
#if USE_EXTRA_OPCODES
    for (mode_index = 0u; mode_index < 12u; ++mode_index) {
        EXPECT(form_counts[mode_index]
            == (mode_index % 2u == 0u
                ? UINT64_C(73728) : UINT64_C(24576)));
    }
#else
    (void)form_counts;
#endif
}

static void test_exact_forms_gates_and_collisions(void)
{
    size_t family_index;

    for (family_index = 0u; family_index < 3u; ++family_index) {
        unsigned int width;

        for (width = 0u; width < 2u; ++width) {
            unsigned int register_form;

            for (register_form = 0u; register_form < 2u; ++register_form) {
                const uint8_t code[6] = {
                    0xc4,0xe2,(uint8_t)(0x71u | (width << 2)),
                    families[family_index].opcode,
                    register_form != 0u ? UINT8_C(0xc2) : UINT8_C(0x00),
                    0x00};
#if USE_EXTRA_OPCODES
                cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), &flags, &decoded_size);

                EXPECT(decoded_size == (register_form != 0u ? 5u : 5u));
                EXPECT(instruction.form_id == (cdisasm_x86_form_id)(
                    families[family_index].base + width * 2u
                    + register_form));
#else
                expect_error("VPSIGN extras off", CDISASM_CPU_X86,
                    CDISASM_MODE_64, code,
                    register_form != 0u ? 5u : 5u, NULL,
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
        const uint8_t xmm[] = {0xc4,0xe2,0x71,0x08,0xc2};
        const uint8_t ymm[] = {0xc4,0xe2,0x75,0x08,0xc2};
        cdisasm_x86_decode_flags available;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        expect_error("XMM VPSIGN needs AVX", CDISASM_CPU_X86,
            CDISASM_MODE_64, xmm, sizeof(xmm), &none,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX2 does not imply XMM AVX", CDISASM_CPU_X86,
            CDISASM_MODE_64, xmm, sizeof(xmm), &avx2,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("YMM VPSIGN needs AVX2", CDISASM_CPU_X86,
            CDISASM_MODE_64, ymm, sizeof(ymm), &avx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            xmm, sizeof(xmm), &avx, &decoded_size);
        EXPECT(decoded_size == sizeof(xmm));
        EXPECT(instruction.form_id == UINT16_C(7922));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            ymm, sizeof(ymm), &avx2, &decoded_size);
        EXPECT(decoded_size == sizeof(ymm));
        EXPECT(instruction.form_id == UINT16_C(7924));

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
            xmm, sizeof(xmm), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(xmm));
        expect_error("Sandy Bridge YMM VPSIGN", CDISASM_CPU_SANDY_BRIDGE,
            CDISASM_MODE_64, ymm, sizeof(ymm), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_HASWELL, CDISASM_MODE_64, &available)
            == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_HASWELL, CDISASM_MODE_64,
            ymm, sizeof(ymm), &available, &decoded_size);
        EXPECT(decoded_size == sizeof(ymm));
    }
    {
        const uint8_t nonlong_alias[] = {0xc4,0xc2,0x31,0x08,0xc2};
        const uint8_t high_registers[] = {0xc4,0x42,0x31,0x09,0xcb};
        const uint8_t legacy_b[] = {0x66,0x0f,0x38,0x08,0xc2};
        const uint8_t legacy_w[] = {0x66,0x0f,0x38,0x09,0xc2};
        const uint8_t legacy_d[] = {0x66,0x0f,0x38,0x0a,0xc2};
        const uint8_t evex_reserved[] = {0x62,0xf2,0x75,0x08,0x08,0xc2};
        cdisasm_x86_decode_flags flags16 = all_flags(CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_16, nonlong_alias, sizeof(nonlong_alias),
            &flags16, &decoded_size);

        EXPECT(decoded_size == sizeof(nonlong_alias));
        EXPECT(instruction.form_id == UINT16_C(7922));
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            high_registers, sizeof(high_registers), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(high_registers));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPSIGNW);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM9);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM9);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM11);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_b, sizeof(legacy_b), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_b));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PSIGNB);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_w, sizeof(legacy_w), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_w));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PSIGNW);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_d, sizeof(legacy_d), &flags64, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_d));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PSIGND);
        expect_error("EVEX VPSIGN row remains reserved", CDISASM_CPU_X86,
            CDISASM_MODE_64, evex_reserved, sizeof(evex_reserved),
            &flags64, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif

    {
        const uint8_t c4[] = {0xc4,0xe2,0xf1,0x08,0xc2};
        size_t size;

        for (size = 1u; size < sizeof(c4); ++size) {
            expect_error("truncated C4 VPSIGN", CDISASM_CPU_X86,
                CDISASM_MODE_64, c4, size, NULL,
                CDISASM_STATUS_TRUNCATED);
        }
        expect_error("reserved pp missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4,0xe2,0x70,0x08,0x04}, 5u,
            NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved pp complete", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4,0xe2,0x70,0x08,0x04,0x24}, 6u,
            NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("legacy prefix missing disp8", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0x66,0xc4,0xe2,0x71,0x08,0x45}, 6u,
            NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("legacy prefix complete", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0x66,0xc4,0xe2,0x71,0x08,0x45,0x10}, 7u,
            NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("VEX2 cannot select map 2", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc5,0xf1,0x08,0xc2}, 4u,
            NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format_rejected(const cdisasm_instruction *instruction)
{
    char output[128];

    memset(output, 0xa5, sizeof(output));
    EXPECT(cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
}

static void test_formatting_and_schema(void)
{
    const uint8_t reg[] = {0xc4,0xe2,0x75,0x08,0xc2};
    const uint8_t mem[] = {0xc4,0xe2,0x71,0x0a,0x00};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
        CDISASM_MODE_64, reg, sizeof(reg), &flags, &decoded_size);
    cdisasm_instruction forged;
    char output[128];

    EXPECT(decoded_size == sizeof(reg));
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) != 0u);
    EXPECT(strcmp(output, "vpsignb ymm0, ymm1, ymm2") == 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output)) != 0u);
    EXPECT(strcmp(output, "vpsignb %ymm2, %ymm1, %ymm0") == 0);

    forged = instruction;
    forged.name_id = CDISASM_X86_NAME_VPSIGND;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.form_id = UINT16_C(7922);
    expect_format_rejected(&forged);
    forged = instruction;
    forged.opcode_flags |= CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.opcode_flags |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.operand_count = 2u;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.opcode[1].reg = CDISASM_X86_REG_XMM1;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.opcode[2].size = 16u;
    expect_format_rejected(&forged);
    forged = instruction;
    forged.encoding.modrm ^= UINT8_C(0x08);
    expect_format_rejected(&forged);
    forged = instruction;
    forged.mask_reg = CDISASM_X86_REG_K1;
    expect_format_rejected(&forged);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        mem, sizeof(mem), &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(mem));
    EXPECT(instruction.form_id == UINT16_C(7925));
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) != 0u);
    EXPECT(strcmp(output, "vpsignd xmm0, xmm1, xmmword ptr [rax]") == 0);
}
#else
static void test_formatting_and_schema(void)
{
}
#endif

int main(void)
{
    test_c4_control_partition();
    test_exact_forms_gates_and_collisions();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VPSIGN test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
