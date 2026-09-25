#include "cdisasm/cdisasm_x86.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <limits.h>
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

_Static_assert(CDISASM_X86_NAME_VEXTRACTPS == UINT16_C(1656)
        && CDISASM_X86_NAME_VINSERTPS == UINT16_C(1750),
    "VEX PS lane name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VEX PS lane AVX IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VEX PS lane profile sweep");

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

static int is_extract_opcode(uint8_t opcode)
{
    return opcode == UINT8_C(0x17);
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags selected_flags(int avx)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    if (avx) {
        EXPECT(cdisasm_decode_flags_set_bit(
            &flags, CDISASM_X86_DECODE_BIT_AVX));
    }
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

static cdisasm_x86_form_id form_for(
    uint8_t opcode,
    int register_form)
{
    if (is_extract_opcode(opcode)) {
        return register_form ? UINT16_C(4567) : UINT16_C(4569);
    }
    return register_form ? UINT16_C(5580) : UINT16_C(5579);
}

static void check_ps_lane(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t opcode,
    int register_form)
{
    const int extract = is_extract_opcode(opcode);
    const size_t variable_index = extract ? 0u : 2u;
    const size_t immediate_index = extract ? 2u : 3u;
    size_t index;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (extract
        ? CDISASM_X86_NAME_VEXTRACTPS
        : CDISASM_X86_NAME_VINSERTPS));
    EXPECT(instruction->form_id == form_for(opcode, register_form));
    EXPECT(instruction->operand_count == (extract ? 3u : 4u));
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
    EXPECT(instruction->encoding.immediate_count == 1u);
    EXPECT(instruction->encoding.immediate_size[0] == 1u);
    EXPECT(instruction->encoding.immediate_offset[0]
        == decoded_size - UINT32_C(1));
    EXPECT(instruction->encoding.selector_offset == 0u);

    for (index = 0u; index < immediate_index; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = !register_form && index == variable_index;
        const int gpr = extract && register_form && index == 0u;

        EXPECT(operand->type == (memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(operand->size == (memory || gpr ? 4u : 16u));
        EXPECT(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
        EXPECT(operand->broadcast == CDISASM_X86_BROADCAST_NONE);
        if (memory) {
            EXPECT((operand->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
        } else if (gpr) {
            EXPECT(operand->reg >= CDISASM_X86_REG_EAX
                && operand->reg <= CDISASM_X86_REG_R15D);
            EXPECT(operand->flags == 0u);
            if (mode != CDISASM_MODE_64) {
                EXPECT(operand->reg <= CDISASM_X86_REG_EDI);
            }
        } else {
            EXPECT(operand->reg >= CDISASM_X86_REG_XMM0
                && operand->reg <= CDISASM_X86_REG_XMM15);
            EXPECT(operand->flags == 0u);
            if (mode != CDISASM_MODE_64) {
                EXPECT(operand->reg <= CDISASM_X86_REG_XMM7);
            }
        }
    }
    EXPECT(instruction->opcode[immediate_index].type
        == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction->opcode[immediate_index].size == 1u);
    EXPECT(instruction->opcode[immediate_index].access
        == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[immediate_index].flags == 0u);
    EXPECT(instruction->opcode[immediate_index].broadcast
        == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2));
}
#endif

#if !USE_EXTRA_OPCODES
static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size)
{
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
}
#endif

static void test_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const uint8_t opcodes[2] = {UINT8_C(0x17), UINT8_C(0x21)};
    static const uint64_t expected_form_counts[2][2] = {
        {UINT64_C(4608), UINT64_C(1536)},
        {UINT64_C(73728), UINT64_C(24576)}};
    uint64_t form_counts[2][2] = {{0u, 0u}, {0u, 0u}};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;
    size_t opcode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        const unsigned int p0_count = long_mode ? 8u : 2u;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

        for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
            const uint8_t opcode = opcodes[opcode_index];
            unsigned int p0_index;

            for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
                const uint8_t p0 = long_mode
                    ? (uint8_t)((p0_index << 5) | 3u)
                    : (uint8_t)(0xc3u | (p0_index << 5));
                unsigned int p1;

                for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                    const int valid_selector = is_extract_opcode(opcode)
                        ? ((p1 & UINT8_C(0x7f)) == UINT8_C(0x79))
                        : ((p1 & UINT8_C(0x07)) == UINT8_C(0x01));
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                        const uint8_t code[15] = {
                            0xc4, p0, (uint8_t)p1, opcode, (uint8_t)modrm,
                            0x24, 0x10, 0x20, 0x30, 0x40,
                            0x50, 0x60, 0x70, 0x80, 0x90};
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

                        if (valid_selector) {
#if USE_EXTRA_OPCODES
                            check_ps_lane(&instruction, decoded_size,
                                modes[mode_index], opcode, register_form);
#else
                            check_allocated(&instruction, decoded_size);
#endif
                            ++form_counts[opcode_index][register_form];
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

    EXPECT(allocated == UINT64_C(104448));
    EXPECT(reserved == UINT64_C(1468416));
    for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
        EXPECT(form_counts[opcode_index][0]
            == expected_form_counts[opcode_index][0]);
        EXPECT(form_counts[opcode_index][1]
            == expected_form_counts[opcode_index][1]);
    }
}

static void test_exact_forms_wig_immediates_and_aliases(void)
{
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags64 = all_flags(CDISASM_MODE_64);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    unsigned int immediate;
    size_t index;

    {
        static const uint8_t extract_register[] = {
            0xc4, 0x43, 0x79, 0x17, 0xd3, 0x5a};
        static const uint8_t extract_memory[] = {
            0xc4, 0x63, 0x79, 0x17, 0x54, 0x88, 0x10, 0x5a};
        static const uint8_t insert_register[] = {
            0xc4, 0x43, 0x29, 0x21, 0xcb, 0x5a};
        static const uint8_t insert_memory[] = {
            0xc4, 0x63, 0x29, 0x21, 0x4c, 0x88, 0x10, 0x5a};

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            extract_register, sizeof(extract_register),
            &flags64, &decoded_size);
        check_ps_lane(&instruction, decoded_size, CDISASM_MODE_64, 0x17, 1);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R11D);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM10);
        EXPECT(instruction.opcode[2].imm == UINT64_C(0x5a));

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            extract_memory, sizeof(extract_memory),
            &flags64, &decoded_size);
        check_ps_lane(&instruction, decoded_size, CDISASM_MODE_64, 0x17, 0);
        EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_RCX);
        EXPECT(instruction.opcode[0].scale == 4u);
        EXPECT(instruction.opcode[0].imm == UINT64_C(0x10));

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            insert_register, sizeof(insert_register),
            &flags64, &decoded_size);
        check_ps_lane(&instruction, decoded_size, CDISASM_MODE_64, 0x21, 1);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM9);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM10);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM11);
        EXPECT(instruction.opcode[3].imm == UINT64_C(0x5a));

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            insert_memory, sizeof(insert_memory),
            &flags64, &decoded_size);
        check_ps_lane(&instruction, decoded_size, CDISASM_MODE_64, 0x21, 0);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_RCX);
        EXPECT(instruction.opcode[2].scale == 4u);
        EXPECT(instruction.opcode[2].imm == UINT64_C(0x10));
    }

    /* VEX.W is ignored and every bit of imm8 remains ordinary payload. */
    for (index = 0u; index < 2u; ++index) {
        const uint8_t opcode = index == 0u ? UINT8_C(0x17) : UINT8_C(0x21);

        for (immediate = 0u; immediate <= UINT8_MAX; ++immediate) {
            const uint8_t code_w0[6] = {0xc4, 0xe3,
                opcode == UINT8_C(0x17) ? 0x79 : 0x69,
                opcode, 0xc1, (uint8_t)immediate};
            uint8_t code_w1[6];
            const size_t immediate_index = opcode == UINT8_C(0x17)
                ? 2u : 3u;

            memcpy(code_w1, code_w0, sizeof(code_w1));
            code_w1[2] |= UINT8_C(0x80);
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                code_w0, sizeof(code_w0), &flags64, &decoded_size);
            check_ps_lane(&instruction, decoded_size,
                CDISASM_MODE_64, opcode, 1);
            EXPECT(instruction.opcode[immediate_index].imm == immediate);
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                code_w1, sizeof(code_w1), &flags64, &decoded_size);
            check_ps_lane(&instruction, decoded_size,
                CDISASM_MODE_64, opcode, 1);
            EXPECT(instruction.opcode[immediate_index].imm == immediate);
        }
    }

    {
        static const uint8_t address_memory[] = {
            0x67, 0xc4, 0xe3, 0x79, 0x17, 0x00, 0x5a};
        static const uint8_t segment_memory[] = {
            0x64, 0xc4, 0xe3, 0x69, 0x21, 0x00, 0x5a};
        static const uint8_t segment_register[] = {
            0x64, 0xc4, 0xe3, 0x69, 0x21, 0xc1, 0x5a};

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            address_memory, sizeof(address_memory),
            &flags64, &decoded_size);
        check_ps_lane(&instruction, decoded_size, CDISASM_MODE_64, 0x17, 0);
        EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_EAX);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            segment_memory, sizeof(segment_memory),
            &flags64, &decoded_size);
        check_ps_lane(&instruction, decoded_size, CDISASM_MODE_64, 0x21, 0);
        EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_FS);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            segment_register, sizeof(segment_register),
            &flags64, &decoded_size);
        check_ps_lane(&instruction, decoded_size, CDISASM_MODE_64, 0x21, 1);
    }

    for (index = 0u; index < 2u; ++index) {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        cdisasm_x86_decode_flags flags = all_flags(modes[index]);
        unsigned int raw_b;

        for (raw_b = 0u; raw_b < 2u; ++raw_b) {
            const uint8_t p0 = raw_b ? UINT8_C(0xe3) : UINT8_C(0xc3);
            const uint8_t extract_code[6] = {
                0xc4, p0, 0x79, 0x17, 0xc1, 0x01};
            const uint8_t insert_code[6] = {
                0xc4, p0, 0x39, 0x21, 0xc1, 0x01};

            instruction = decode(CDISASM_CPU_X86, modes[index],
                extract_code, sizeof(extract_code), &flags, &decoded_size);
            check_ps_lane(&instruction, decoded_size, modes[index], 0x17, 1);
            EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ECX);
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM0);
            instruction = decode(CDISASM_CPU_X86, modes[index],
                insert_code, sizeof(insert_code), &flags, &decoded_size);
            check_ps_lane(&instruction, decoded_size, modes[index], 0x21, 1);
            EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM0);
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM0);
            EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM1);
        }
    }

    {
        static const uint8_t long_high_vvvv[] = {
            0xc4, 0xc3, 0x39, 0x21, 0xc1, 0x01};

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            long_high_vvvv, sizeof(long_high_vvvv),
            &flags64, &decoded_size);
        check_ps_lane(&instruction, decoded_size, CDISASM_MODE_64, 0x21, 1);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM0);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM8);
        EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM9);
    }
#endif
}

static void test_runtime_profiles_and_extras(void)
{
    static const uint8_t extract_code[] = {
        0xc4, 0xe3, 0x79, 0x17, 0xc1, 0x01};
    static const uint8_t insert_code[] = {
        0xc4, 0xe3, 0x69, 0x21, 0xc1, 0x01};

#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags none = selected_flags(0);
    cdisasm_x86_decode_flags avx = selected_flags(1);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    cdisasm_x86_cpu_id cpu_id;

    expect_error("VEXTRACTPS needs AVX", CDISASM_CPU_X86,
        CDISASM_MODE_64, extract_code, sizeof(extract_code), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VINSERTPS needs AVX", CDISASM_CPU_X86,
        CDISASM_MODE_64, insert_code, sizeof(insert_code), &none,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        extract_code, sizeof(extract_code), &avx, &decoded_size);
    check_ps_lane(&instruction, decoded_size, CDISASM_MODE_64, 0x17, 1);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        insert_code, sizeof(insert_code), &avx, &decoded_size);
    check_ps_lane(&instruction, decoded_size, CDISASM_MODE_64, 0x21, 1);

    for (cpu_id = CDISASM_CPU_FIRST; cpu_id <= CDISASM_CPU_LAST; ++cpu_id) {
        cdisasm_x86_decode_flags flags =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        const int mask_ok = cdisasm_x86_cpu_decode_flag_mask(
            cpu_id, CDISASM_MODE_16, &flags) == CDISASM_STATUS_OK;
        const int has_avx = cdisasm_decode_flags_test_bit(
            &flags, CDISASM_X86_DECODE_BIT_AVX);

        EXPECT(mask_ok);
        if (has_avx) {
            instruction = decode(cpu_id, CDISASM_MODE_16,
                extract_code, sizeof(extract_code), &flags, &decoded_size);
            check_ps_lane(&instruction, decoded_size,
                CDISASM_MODE_16, 0x17, 1);
            instruction = decode(cpu_id, CDISASM_MODE_16,
                insert_code, sizeof(insert_code), &flags, &decoded_size);
            check_ps_lane(&instruction, decoded_size,
                CDISASM_MODE_16, 0x21, 1);
        } else {
            expect_error("profile lacks VEXTRACTPS", cpu_id,
                CDISASM_MODE_16, extract_code, sizeof(extract_code), &flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("profile lacks VINSERTPS", cpu_id,
                CDISASM_MODE_16, insert_code, sizeof(insert_code), &flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
#else
    expect_error("VEXTRACTPS extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, extract_code, sizeof(extract_code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VINSERTPS extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, insert_code, sizeof(insert_code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_truncation_and_collisions(void)
{
    static const uint8_t opcodes[2] = {UINT8_C(0x17), UINT8_C(0x21)};
    static const uint8_t legacy_prefixes[5] = {
        0x66, 0xf2, 0xf3, 0xf0, 0x48};
    size_t opcode_index;

    for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
        const uint8_t opcode = opcodes[opcode_index];
        const int extract = is_extract_opcode(opcode);
        const uint8_t valid_p1 = extract ? UINT8_C(0x79) : UINT8_C(0x69);
        const uint8_t complete[6] = {
            0xc4, 0xe3, valid_p1, opcode, 0xc1, 0x01};
        size_t index;

        for (index = 1u; index < sizeof(complete); ++index) {
            expect_error("truncated VEX PS lane form", CDISASM_CPU_X86,
                CDISASM_MODE_64, complete, index, NULL,
                CDISASM_STATUS_TRUNCATED);
        }
        expect_error("reserved L missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){
                0xc4, 0xe3, (uint8_t)(valid_p1 | 0x04), opcode, 0x04},
            5u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved L missing immediate", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){
                0xc4, 0xe3, (uint8_t)(valid_p1 | 0x04),
                opcode, 0x04, 0x24},
            6u, NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved L complete", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){
                0xc4, 0xe3, (uint8_t)(valid_p1 | 0x04),
                opcode, 0x04, 0x24, 0x01},
            7u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        for (index = 0u; index < 3u; ++index) {
            static const uint8_t reserved_pp[3] = {0u, 2u, 3u};
            expect_error("reserved pp", CDISASM_CPU_X86,
                CDISASM_MODE_64,
                (const uint8_t[]){0xc4, 0xe3,
                    (uint8_t)((valid_p1 & 0xfcu) | reserved_pp[index]),
                    opcode, 0xc1, 0x01},
                6u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (extract) {
            expect_error("extract reserved vvvv", CDISASM_CPU_X86,
                CDISASM_MODE_64,
                (const uint8_t[]){
                    0xc4, 0xe3, 0x69, opcode, 0xc1, 0x01},
                6u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("extract reserved vvvv missing immediate",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                (const uint8_t[]){0xc4, 0xe3, 0x69, opcode, 0xc1},
                5u, NULL, CDISASM_STATUS_TRUNCATED);
            expect_error("non-long high vvvv remains reserved for extract",
                CDISASM_CPU_X86, CDISASM_MODE_32,
                (const uint8_t[]){
                    0xc4, 0xe3, 0x39, opcode, 0xc1, 0x01},
                6u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        for (index = 0u; index < sizeof(legacy_prefixes); ++index) {
            const uint8_t prefixed[7] = {legacy_prefixes[index],
                0xc4, 0xe3, valid_p1, opcode, 0xc1, 0x01};

            expect_error("prefixed PS lane missing immediate",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                prefixed, 6u, NULL, CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed complete PS lane",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                prefixed, sizeof(prefixed), NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t r_collision[] = {
            0xc4, 0x63, 0x79, 0x17, 0xc1, 0x01, 0, 0, 0};
        static const uint8_t x_collision[] = {
            0xc4, 0xa3, 0x69, 0x21, 0xc1, 0x01, 0, 0, 0};
        cdisasm_x86_decode_flags flags16 = all_flags(CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags32 = all_flags(CDISASM_MODE_32);
        cdisasm_instruction instruction;
        uint32_t decoded_size;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_16,
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

static void test_evex_separation(void)
{
#if USE_EXTRA_OPCODES
    static const struct evex_case {
        uint8_t code[9];
        size_t size;
        cdisasm_x86_name_id name;
        cdisasm_x86_form_id form;
    } cases[] = {
        {{0x62, 0xf3, 0x7d, 0x08, 0x17, 0xd1, 0x5a, 0, 0}, 7u,
            CDISASM_X86_NAME_VEXTRACTPS, UINT16_C(4568)},
        {{0x62, 0xf3, 0x7d, 0x08, 0x17, 0x54, 0x88, 0x10, 0x5a}, 9u,
            CDISASM_X86_NAME_VEXTRACTPS, UINT16_C(4570)},
        {{0x62, 0xf3, 0x6d, 0x08, 0x21, 0xd9, 0x5a, 0, 0}, 7u,
            CDISASM_X86_NAME_VINSERTPS, UINT16_C(5582)},
        {{0x62, 0xf3, 0x6d, 0x08, 0x21, 0x4c, 0x88, 0x10, 0x5a}, 9u,
            CDISASM_X86_NAME_VINSERTPS, UINT16_C(5581)},
        {{0x62, 0xe3, 0x7d, 0x08, 0x17, 0xc8, 0x05, 0, 0}, 7u,
            CDISASM_X86_NAME_VEXTRACTPS, UINT16_C(4568)},
        {{0x62, 0xa3, 0x6d, 0x00, 0x21, 0xcb, 0x93, 0, 0}, 7u,
            CDISASM_X86_NAME_VINSERTPS, UINT16_C(5582)}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    cdisasm_x86_decode_flags avx_only = selected_flags(1);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);

        EXPECT(decoded_size == cases[index].size);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == cases[index].name);
        EXPECT(instruction.form_id == cases[index].form);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX) == 0u);
        EXPECT(instruction.form_id != UINT16_C(4567));
        EXPECT(instruction.form_id != UINT16_C(4569));
        EXPECT(instruction.form_id != UINT16_C(5579));
        EXPECT(instruction.form_id != UINT16_C(5580));
    }

    /* The AVX-only selector used by the new VEX forms must not admit these
     * pinned high-EVEX neighbors.  With the full feature mask above, they
     * retain their exact AVX-512 form IDs and EVEX prefix. */
    expect_error("high EVEX VEXTRACTPS needs its EVEX feature route",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0x62, 0xe3, 0x7d, 0x08,
            0x17, 0xc8, 0x05},
        7u, &avx_only, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("high EVEX VINSERTPS needs its EVEX feature route",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0x62, 0xa3, 0x6d, 0x00,
            0x21, 0xcb, 0x93},
        7u, &avx_only, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_forged_format_rejected(
    const cdisasm_instruction *instruction)
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
#endif

static void test_formatting_and_schema(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const struct format_case {
        uint8_t code[8];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4, 0x43, 0x79, 0x17, 0xd3, 0x5a, 0, 0}, 6u,
            "vextractps r11d, xmm10, 0x5a",
            "vextractps $0x5a, %xmm10, %r11d"},
        {{0xc4, 0x63, 0x79, 0x17, 0x54, 0x88, 0x10, 0x5a}, 8u,
            "vextractps dword ptr [rax + rcx*4 + 0x10], xmm10, 0x5a",
            "vextractps $0x5a, %xmm10, 0x10(%rax,%rcx,4)"},
        {{0xc4, 0x43, 0x29, 0x21, 0xcb, 0x5a, 0, 0}, 6u,
            "vinsertps xmm9, xmm10, xmm11, 0x5a",
            "vinsertps $0x5a, %xmm11, %xmm10, %xmm9"},
        {{0xc4, 0x63, 0x29, 0x21, 0x4c, 0x88, 0x10, 0x5a}, 8u,
            "vinsertps xmm9, xmm10, dword ptr [rax + rcx*4 + 0x10], 0x5a",
            "vinsertps $0x5a, 0x10(%rax,%rcx,4), %xmm10, %xmm9"}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);

        EXPECT(decoded_size == cases[index].size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
                   output, sizeof(output)) == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
                   output, sizeof(output)) == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);
    }

    {
        static const uint8_t code[] = {
            0xc4, 0x63, 0x29, 0x21, 0x4c, 0x88, 0x10, 0x5a};
        uint32_t decoded_size;
        cdisasm_instruction original = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(code));
        forged = original;
        forged.name_id = CDISASM_X86_NAME_VADDPS;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.form_id = UINT16_C(3585);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.name_id = CDISASM_X86_NAME_VEXTRACTPS;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.form_id = UINT16_C(5581);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.operand_count = 3u;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        forged.form_id = UINT16_C(3585);
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.x86_group_count = 2u;
        forged.x86_group_ids[1] = CDISASM_X86_GROUP_AVX2;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.immediate_count = 0u;
        forged.encoding.immediate_offset[0] = 0u;
        forged.encoding.immediate_size[0] = 0u;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.encoding.immediate_size[0] = 2u;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode[2].size = 16u;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode[2].flags |= CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
        expect_forged_format_rejected(&forged);
        forged = original;
        forged.opcode[3].imm = UINT64_C(0x100);
        expect_forged_format_rejected(&forged);
    }
#endif
}

int main(void)
{
    test_control_partition();
    test_exact_forms_wig_immediates_and_aliases();
    test_runtime_profiles_and_extras();
    test_reserved_truncation_and_collisions();
    test_evex_separation();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VEXTRACTPS/VINSERTPS test(s) failed\n",
            failures);
        return 1;
    }
    return 0;
}
