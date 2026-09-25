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

_Static_assert(CDISASM_X86_NAME_VBROADCASTSD == UINT16_C(1492)
        && CDISASM_X86_NAME_VBROADCASTSS == UINT16_C(1493),
    "VBROADCASTSD/SS name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_AVX2 == UINT16_C(46),
    "VBROADCASTSD/SS ISA-set group IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
    "VBROADCASTSD/SS runtime-bit IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VBROADCASTSD/SS profile sweep");

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

static cdisasm_x86_form_id expected_form(
    uint8_t opcode,
    unsigned int l,
    int register_form)
{
    if (opcode == UINT8_C(0x19)) {
        return register_form ? UINT16_C(3570) : UINT16_C(3569);
    }
    if (l == 0u) {
        return register_form ? UINT16_C(3574) : UINT16_C(3573);
    }
    return register_form ? UINT16_C(3580) : UINT16_C(3579);
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

static void check_scalar_broadcast(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    uint8_t opcode,
    unsigned int l,
    int register_form,
    unsigned int destination,
    unsigned int source)
{
    const unsigned int vector_bytes = 16u << l;
    const unsigned int scalar_bytes = opcode == UINT8_C(0x19) ? 8u : 4u;
    const cdisasm_x86_reg_id destination_base = l != 0u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (opcode == UINT8_C(0x19)
        ? CDISASM_X86_NAME_VBROADCASTSD
        : CDISASM_X86_NAME_VBROADCASTSS));
    EXPECT(instruction->form_id
        == expected_form(opcode, l, register_form));
    EXPECT(instruction->operand_count == 2u);
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
    EXPECT(instruction->encoding.selector_offset == 0u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg
        == (cdisasm_x86_reg_id)(destination_base + destination));
    EXPECT(instruction->opcode[0].size == vector_bytes);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[0].flags == 0u);
    EXPECT(instruction->opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->opcode[1].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[1].size
        == (register_form ? 16u : scalar_bytes));
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
    if (register_form) {
        EXPECT(instruction->opcode[1].reg
            == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + source));
        EXPECT(instruction->opcode[1].flags == 0u);
    } else {
        EXPECT((instruction->opcode[1].flags
            & (CDISASM_OPERAND_FLAG_IMPLICIT
                | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
    }
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2) == register_form);
    if (mode != CDISASM_MODE_64) {
        EXPECT(destination < 8u);
        EXPECT(!register_form || source < 8u);
    }
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    uint8_t opcode,
    unsigned int l,
    int register_form)
{
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (opcode == UINT8_C(0x19)
        ? CDISASM_X86_NAME_VBROADCASTSD
        : CDISASM_X86_NAME_VBROADCASTSS));
    EXPECT(instruction->form_id
        == expected_form(opcode, l, register_form));
    EXPECT(instruction->operand_count == 2u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].size == (16u << l));
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[1].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[1].size == (register_form
        ? 16u : (opcode == UINT8_C(0x19) ? 8u : 4u)));
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
#else
    (void)opcode;
    (void)l;
    (void)register_form;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const uint8_t opcodes[2] = {UINT8_C(0x18), UINT8_C(0x19)};
    static const uint64_t expected_mode_counts[3] = {
        UINT64_C(1536), UINT64_C(1536), UINT64_C(6144)};
    uint64_t form_counts[6] = {0u, 0u, 0u, 0u, 0u, 0u};
    uint64_t mode_counts[3] = {0u, 0u, 0u};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;
    unsigned int opcode_index;

    for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
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
                    ? (uint8_t)((p0_index << 5) | 2u)
                    : (uint8_t)(0xc2u | (p0_index << 5));
                unsigned int w;

                for (w = 0u; w < 2u; ++w) {
                    unsigned int l;

                    for (l = 0u; l < 2u; ++l) {
                        unsigned int pp;

                        for (pp = 0u; pp < 4u; ++pp) {
                            unsigned int vvvv;

                            for (vvvv = 0u; vvvv < 16u; ++vvvv) {
                                unsigned int raw_modrm;

                                for (raw_modrm = 0u;
                                     raw_modrm <= UINT8_MAX;
                                     ++raw_modrm) {
                                    const int register_form =
                                        (raw_modrm & UINT8_C(0xc0))
                                            == UINT8_C(0xc0);
                                    const int valid = w == 0u && pp == 1u
                                        && vvvv == 0u
                                        && (opcodes[opcode_index]
                                                == UINT8_C(0x18)
                                            || l == 1u);
                                    const uint8_t code[15] = {0xc4, p0,
                                        (uint8_t)((w << 7)
                                            | (((~vvvv) & 15u) << 3)
                                            | (l << 2) | pp),
                                        opcodes[opcode_index],
                                        (uint8_t)raw_modrm, 0x24, 0x10,
                                        0x20, 0x30, 0x40, 0x50, 0x60,
                                        0x70, 0x80, 0x90};
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
                                        const cdisasm_x86_form_id form_id =
                                            expected_form(
                                                opcodes[opcode_index], l,
                                                register_form);

                                        check_allocated(&instruction,
                                            decoded_size,
                                            opcodes[opcode_index], l,
                                            register_form);
                                        if (form_id == UINT16_C(3569)) {
                                            ++form_counts[0];
                                        } else if (form_id
                                            == UINT16_C(3570)) {
                                            ++form_counts[1];
                                        } else if (form_id
                                            == UINT16_C(3573)) {
                                            ++form_counts[2];
                                        } else if (form_id
                                            == UINT16_C(3574)) {
                                            ++form_counts[3];
                                        } else if (form_id
                                            == UINT16_C(3579)) {
                                            ++form_counts[4];
                                        } else {
                                            ++form_counts[5];
                                        }
                                        ++mode_counts[mode_index];
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
    EXPECT(allocated == UINT64_C(9216));
    EXPECT(reserved == UINT64_C(1563648));
    EXPECT(form_counts[0] == UINT64_C(2304));
    EXPECT(form_counts[1] == UINT64_C(768));
    EXPECT(form_counts[2] == UINT64_C(2304));
    EXPECT(form_counts[3] == UINT64_C(768));
    EXPECT(form_counts[4] == UINT64_C(2304));
    EXPECT(form_counts[5] == UINT64_C(768));
    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        EXPECT(mode_counts[mode_index] == expected_mode_counts[mode_index]);
    }
}

static void test_forms_modes_and_addresses(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t forms[6][5] = {
        {0xc4, 0xe2, 0x7d, 0x19, 0x08},
        {0xc4, 0xe2, 0x7d, 0x19, 0xc9},
        {0xc4, 0xe2, 0x79, 0x18, 0x08},
        {0xc4, 0xe2, 0x79, 0x18, 0xc9},
        {0xc4, 0xe2, 0x7d, 0x18, 0x08},
        {0xc4, 0xe2, 0x7d, 0x18, 0xc9}};
    static const uint8_t high_memory[] = {
        0xc4, 0x02, 0x7d, 0x18, 0x44, 0x58, 0x20};
    static const uint8_t high_register[] = {
        0xc4, 0x42, 0x7d, 0x19, 0xfa};
    static const uint8_t rip_relative[] = {
        0xc4, 0xe2, 0x7d, 0x19, 0x1d, 0x78, 0x56, 0x34, 0x12};
    static const uint8_t address_override[] = {
        0x67, 0xc4, 0xe2, 0x79, 0x18, 0x00};
    static const uint8_t segment_override[] = {
        0x64, 0xc4, 0xe2, 0x7d, 0x18, 0x00};
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    for (index = 0u; index < 6u; ++index) {
        const uint8_t opcode = forms[index][3];
        const unsigned int l = (forms[index][2] >> 2) & 1u;
        const int register_form = index % 2u != 0u;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            forms[index], sizeof(forms[index]), &flags, &decoded_size);
        check_scalar_broadcast(&instruction, decoded_size,
            CDISASM_MODE_64, opcode, l, register_form, 1u, 1u);
    }

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        high_memory, sizeof(high_memory), &flags, &decoded_size);
    check_scalar_broadcast(&instruction, decoded_size,
        CDISASM_MODE_64, UINT8_C(0x18), 1u, 0, 8u, 0u);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R8);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R11);
    EXPECT(instruction.opcode[1].scale == 2u);
    EXPECT(instruction.opcode[1].imm == UINT64_C(0x20));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        high_register, sizeof(high_register), &flags, &decoded_size);
    check_scalar_broadcast(&instruction, decoded_size,
        CDISASM_MODE_64, UINT8_C(0x19), 1u, 1, 15u, 10u);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rip_relative, sizeof(rip_relative), &flags, &decoded_size);
    check_scalar_broadcast(&instruction, decoded_size,
        CDISASM_MODE_64, UINT8_C(0x19), 1u, 0, 3u, 0u);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RIP);
    EXPECT(instruction.opcode[1].imm == UINT64_C(0x12345678));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        address_override, sizeof(address_override), &flags, &decoded_size);
    check_scalar_broadcast(&instruction, decoded_size,
        CDISASM_MODE_64, UINT8_C(0x18), 0u, 0, 0u, 0u);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_EAX);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        segment_override, sizeof(segment_override), &flags, &decoded_size);
    check_scalar_broadcast(&instruction, decoded_size,
        CDISASM_MODE_64, UINT8_C(0x18), 1u, 0, 0u, 0u);
    EXPECT(instruction.opcode[1].segment_reg == CDISASM_X86_REG_FS);

    for (index = 0u; index < 2u; ++index) {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        size_t b_alias;

        for (b_alias = 0u; b_alias < 2u; ++b_alias) {
            uint8_t memory_code[6] = {
                0xc4, (uint8_t)(b_alias != 0u ? 0xe2 : 0xc2),
                0x7d, 0x19, 0x04, 0x24};
            uint8_t register_code[5] = {
                0xc4, (uint8_t)(b_alias != 0u ? 0xe2 : 0xc2),
                0x79, 0x18, 0xc1};
            const size_t memory_size = modes[index] == CDISASM_MODE_16
                ? 5u : 6u;
            cdisasm_x86_decode_flags mode_flags =
                cpu_flags(CDISASM_CPU_X86, modes[index]);

            instruction = decode(CDISASM_CPU_X86, modes[index],
                memory_code, memory_size, &mode_flags, &decoded_size);
            check_scalar_broadcast(&instruction, decoded_size,
                modes[index], UINT8_C(0x19), 1u, 0, 0u, 0u);
            EXPECT(instruction.opcode[1].base_reg
                == (modes[index] == CDISASM_MODE_16
                    ? CDISASM_X86_REG_SI : CDISASM_X86_REG_ESP));
            instruction = decode(CDISASM_CPU_X86, modes[index],
                register_code, sizeof(register_code),
                &mode_flags, &decoded_size);
            check_scalar_broadcast(&instruction, decoded_size,
                modes[index], UINT8_C(0x18), 0u, 1, 0u, 1u);
        }
    }
#endif
}

static void test_runtime_profiles_and_extras(void)
{
    static const uint8_t forms[6][5] = {
        {0xc4, 0xe2, 0x7d, 0x19, 0x00},
        {0xc4, 0xe2, 0x7d, 0x19, 0xc1},
        {0xc4, 0xe2, 0x79, 0x18, 0x00},
        {0xc4, 0xe2, 0x79, 0x18, 0xc1},
        {0xc4, 0xe2, 0x7d, 0x18, 0x00},
        {0xc4, 0xe2, 0x7d, 0x18, 0xc1}};

#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags none = selected_flags(0, 0);
    cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);
    cdisasm_x86_decode_flags both = selected_flags(1, 1);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    cdisasm_x86_cpu_id cpu_id;
    size_t index;

    for (index = 0u; index < 6u; ++index) {
        const uint8_t opcode = forms[index][3];
        const unsigned int l = (forms[index][2] >> 2) & 1u;
        const int register_form = index % 2u != 0u;

        expect_error("scalar broadcast needs feature", CDISASM_CPU_X86,
            CDISASM_MODE_64, forms[index], sizeof(forms[index]), &none,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        if (register_form) {
            expect_error("register scalar broadcast needs AVX2",
                CDISASM_CPU_X86, CDISASM_MODE_64, forms[index],
                sizeof(forms[index]), &avx,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                forms[index], sizeof(forms[index]), &avx2, &decoded_size);
        } else {
            expect_error("AVX2 selector does not admit AVX memory form",
                CDISASM_CPU_X86, CDISASM_MODE_64, forms[index],
                sizeof(forms[index]), &avx2,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                forms[index], sizeof(forms[index]), &avx, &decoded_size);
        }
        check_scalar_broadcast(&instruction, decoded_size,
            CDISASM_MODE_64, opcode, l, register_form, 0u,
            register_form ? 1u : 0u);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            forms[index], sizeof(forms[index]), &both, &decoded_size);
        check_scalar_broadcast(&instruction, decoded_size,
            CDISASM_MODE_64, opcode, l, register_form, 0u,
            register_form ? 1u : 0u);
    }

    for (cpu_id = CDISASM_CPU_FIRST; cpu_id <= CDISASM_CPU_LAST; ++cpu_id) {
        cdisasm_x86_decode_flags profile_flags =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        const int mask_ok = cdisasm_x86_cpu_decode_flag_mask(
            cpu_id, CDISASM_MODE_16, &profile_flags) == CDISASM_STATUS_OK;
        const int has_avx = cdisasm_decode_flags_test_bit(
            &profile_flags, CDISASM_X86_DECODE_BIT_AVX);
        const int has_avx2 = cdisasm_decode_flags_test_bit(
            &profile_flags, CDISASM_X86_DECODE_BIT_AVX2);

        EXPECT(mask_ok);
        if (has_avx) {
            instruction = decode(cpu_id, CDISASM_MODE_16,
                forms[2], sizeof(forms[2]), &profile_flags, &decoded_size);
            check_scalar_broadcast(&instruction, decoded_size,
                CDISASM_MODE_16, UINT8_C(0x18), 0u, 0, 0u, 0u);
        } else {
            expect_error("profile lacks AVX scalar broadcast", cpu_id,
                CDISASM_MODE_16, forms[2], sizeof(forms[2]), &profile_flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        if (has_avx2) {
            instruction = decode(cpu_id, CDISASM_MODE_16,
                forms[1], sizeof(forms[1]), &profile_flags, &decoded_size);
            check_scalar_broadcast(&instruction, decoded_size,
                CDISASM_MODE_16, UINT8_C(0x19), 1u, 1, 0u, 1u);
        } else {
            expect_error("profile lacks AVX2 scalar broadcast", cpu_id,
                CDISASM_MODE_16, forms[1], sizeof(forms[1]), &profile_flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
#else
    size_t index;

    for (index = 0u; index < 6u; ++index) {
        expect_error("scalar broadcast extras off", CDISASM_CPU_X86,
            CDISASM_MODE_64, forms[index], sizeof(forms[index]), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif
}

static void test_prefixes_truncation_and_collisions(void)
{
    static const uint8_t complete[6][5] = {
        {0xc4, 0xe2, 0x7d, 0x19, 0x00},
        {0xc4, 0xe2, 0x7d, 0x19, 0xc1},
        {0xc4, 0xe2, 0x79, 0x18, 0x00},
        {0xc4, 0xe2, 0x79, 0x18, 0xc1},
        {0xc4, 0xe2, 0x7d, 0x18, 0x00},
        {0xc4, 0xe2, 0x7d, 0x18, 0xc1}};
    static const uint8_t legacy_prefixes[5] = {0x66, 0xf2, 0xf3, 0xf0, 0x48};
    static const uint8_t opcodes[2] = {UINT8_C(0x18), UINT8_C(0x19)};
    size_t index;
    unsigned int opcode_index;

    for (index = 0u; index < 6u; ++index) {
        size_t length;

        for (length = 1u; length < sizeof(complete[index]); ++length) {
            expect_error("truncated scalar broadcast", CDISASM_CPU_X86,
                CDISASM_MODE_64, complete[index], length, NULL,
                CDISASM_STATUS_TRUNCATED);
        }
    }

    for (opcode_index = 0u; opcode_index < 2u; ++opcode_index) {
        const uint8_t opcode = opcodes[opcode_index];

        expect_error("reserved W missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0xfd, opcode, 0x04}, 5u, NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("reserved W complete", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0xfd, opcode, 0x04, 0x24}, 6u,
            NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        for (index = 0u; index < 3u; ++index) {
            static const uint8_t reserved_pp[3] = {0u, 2u, 3u};

            expect_error("reserved pp", CDISASM_CPU_X86,
                CDISASM_MODE_64,
                (const uint8_t[]){0xc4, 0xe2,
                    (uint8_t)(0x7cu | reserved_pp[index]), opcode, 0xc1},
                5u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        expect_error("reserved pp missing displacement", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0x7c, opcode, 0x44, 0x24}, 6u,
            NULL, CDISASM_STATUS_TRUNCATED);
        expect_error("reserved vvvv missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0x6d, opcode, 0x04}, 5u, NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("reserved vvvv complete", CDISASM_CPU_X86,
            CDISASM_MODE_64,
            (const uint8_t[]){0xc4, 0xe2, 0x6d, opcode, 0x04, 0x24}, 6u,
            NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

        for (index = 0u; index < sizeof(legacy_prefixes); ++index) {
            const uint8_t prefixed[7] = {
                legacy_prefixes[index], 0xc4, 0xe2, 0x7d,
                opcode, 0x04, 0x24};

            expect_error("prefixed scalar broadcast missing SIB",
                CDISASM_CPU_X86, CDISASM_MODE_64, prefixed, 6u, NULL,
                CDISASM_STATUS_TRUNCATED);
            expect_error("prefixed complete scalar broadcast",
                CDISASM_CPU_X86, CDISASM_MODE_64, prefixed,
                sizeof(prefixed), NULL,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    expect_error("VBROADCASTSD L0 missing displacement", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4, 0xe2, 0x79, 0x19, 0x44, 0x24}, 6u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("VBROADCASTSD L0 complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4, 0xe2, 0x79, 0x19, 0x44, 0x24, 0x7f}, 7u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        static const uint8_t r_collision[] = {
            0xc4, 0x62, 0x79, 0x18, 0xc1, 0, 0, 0};
        static const uint8_t x_collision[] = {
            0xc4, 0xa2, 0x7d, 0x19, 0x00, 0, 0, 0};
        static const uint8_t evex_sibling[] = {
            0x62, 0xf2, 0x7d, 0x08, 0x18, 0xc1};
        cdisasm_x86_decode_flags flags16 =
            cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_16);
        cdisasm_x86_decode_flags flags32 =
            cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_32);
        cdisasm_x86_decode_flags flags64 =
            cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
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

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_sibling, sizeof(evex_sibling), &flags64, &decoded_size);
        EXPECT(decoded_size == 0u
            || (instruction.form_id != UINT16_C(3569)
                && instruction.form_id != UINT16_C(3570)
                && instruction.form_id != UINT16_C(3573)
                && instruction.form_id != UINT16_C(3574)
                && instruction.form_id != UINT16_C(3579)
                && instruction.form_id != UINT16_C(3580)
                && (instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0u));
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
        uint8_t code[9];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4, 0xe2, 0x79, 0x18, 0x00, 0, 0, 0, 0}, 5u,
            "vbroadcastss xmm0, dword ptr [rax]",
            "vbroadcastss (%rax), %xmm0"},
        {{0xc4, 0xe2, 0x79, 0x18, 0xc1, 0, 0, 0, 0}, 5u,
            "vbroadcastss xmm0, xmm1", "vbroadcastss %xmm1, %xmm0"},
        {{0xc4, 0xe2, 0x7d, 0x18, 0x10, 0, 0, 0, 0}, 5u,
            "vbroadcastss ymm2, dword ptr [rax]",
            "vbroadcastss (%rax), %ymm2"},
        {{0xc4, 0xe2, 0x7d, 0x18, 0xd1, 0, 0, 0, 0}, 5u,
            "vbroadcastss ymm2, xmm1", "vbroadcastss %xmm1, %ymm2"},
        {{0xc4, 0xe2, 0x7d, 0x19, 0x18, 0, 0, 0, 0}, 5u,
            "vbroadcastsd ymm3, qword ptr [rax]",
            "vbroadcastsd (%rax), %ymm3"},
        {{0xc4, 0xe2, 0x7d, 0x19, 0xd9, 0, 0, 0, 0}, 5u,
            "vbroadcastsd ymm3, xmm1", "vbroadcastsd %xmm1, %ymm3"},
        {{0xc4, 0x02, 0x7d, 0x18, 0x44, 0x58, 0x20, 0, 0}, 7u,
            "vbroadcastss ymm8, dword ptr [r8 + r11*2 + 0x20]",
            "vbroadcastss 0x20(%r8,%r11,2), %ymm8"},
        {{0xc4, 0x42, 0x7d, 0x19, 0xfa, 0, 0, 0, 0}, 5u,
            "vbroadcastsd ymm15, xmm10", "vbroadcastsd %xmm10, %ymm15"},
        {{0x64, 0xc4, 0xe2, 0x79, 0x18, 0x00, 0, 0, 0}, 6u,
            "vbroadcastss xmm0, dword ptr fs:[rax]",
            "vbroadcastss %fs:(%rax), %xmm0"},
        {{0x64, 0xc4, 0xe2, 0x79, 0x18, 0xc1, 0, 0, 0}, 6u,
            "vbroadcastss xmm0, xmm1", "vbroadcastss %xmm1, %xmm0"},
        {{0xc4, 0xe2, 0x7d, 0x19, 0x1d, 0x78, 0x56, 0x34, 0x12}, 9u,
            "vbroadcastsd ymm3, qword ptr [rip + 0x12345678]",
            "vbroadcastsd 0x12345678(%rip), %ymm3"}
    };
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_instruction instruction;
        uint32_t decoded_size;
        char output[192];
        char tiny[4] = {'x', 'x', 'x', 'x'};
        size_t required;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        EXPECT(decoded_size == cases[index].size);
        required = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL, NULL, 0u);
        EXPECT(required == strlen(cases[index].intel));
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
                   output, sizeof(output)) == required);
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
                   tiny, sizeof(tiny)) == required);
        EXPECT(tiny[sizeof(tiny) - 1u] == '\0');
        required = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ATT, NULL, 0u);
        EXPECT(required == strlen(cases[index].att));
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
                   output, sizeof(output)) == required);
        EXPECT(strcmp(output, cases[index].att) == 0);
    }

    {
        static const uint8_t memory_code[] = {
            0xc4, 0xe2, 0x79, 0x18, 0x00};
        static const uint8_t register_code[] = {
            0xc4, 0xe2, 0x7d, 0x19, 0xc1};
        static const uint8_t high_code[] = {
            0xc4, 0x42, 0x7d, 0x19, 0xfa};
        cdisasm_instruction memory;
        cdisasm_instruction reg;
        cdisasm_instruction high;
        cdisasm_instruction forged;
        uint32_t decoded_size;

        memory = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            memory_code, sizeof(memory_code), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(memory_code));
        forged = memory;
        forged.name_id = CDISASM_X86_NAME_VBROADCASTSD;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.form_id = UINT16_C(3569);
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.form_id = 0u;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.form_id = 0u;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.form_id = 0u;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.form_id = UINT16_C(3567);
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.form_id = UINT16_C(3575);
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.form_id = UINT16_C(3575);
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.form_id = UINT16_C(3575);
        forged.name_id = CDISASM_X86_NAME_VBROADCASTSD;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.operand_count = 1u;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.opcode_flags |= CDISASM_PREFIX_OPERAND_SIZE;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
        forged.mask_reg = CDISASM_X86_REG_K1;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.rounding = CDISASM_X86_ROUNDING_RN;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.opcode[0].type = CDISASM_OPERAND_MEMORY;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.opcode[0].reg = CDISASM_X86_REG_YMM0;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.opcode[0].size = 32u;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.opcode[0].flags = CDISASM_OPERAND_FLAG_IMPLICIT;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.opcode[1].type = CDISASM_OPERAND_REGISTER;
        forged.opcode[1].reg = CDISASM_X86_REG_XMM1;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.opcode[1].size = 8u;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.opcode[1].flags |= CDISASM_OPERAND_FLAG_IMPLICIT;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.opcode[1].broadcast = CDISASM_X86_BROADCAST_1_TO_4;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.encoding.modrm_offset += 1u;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.encoding.immediate_count = 1u;
        forged.encoding.immediate_offset[0] = 5u;
        forged.encoding.immediate_size[0] = 1u;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.encoding.selector_offset = 5u;
        expect_forged_format_rejected(&forged);
        forged = memory;
        forged.x86_group_count = 0u;
        expect_forged_format_rejected(&forged);

        reg = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            register_code, sizeof(register_code), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(register_code));
        forged = reg;
        forged.name_id = CDISASM_X86_NAME_VBROADCASTSS;
        expect_forged_format_rejected(&forged);
        forged = reg;
        forged.form_id = UINT16_C(3580);
        expect_forged_format_rejected(&forged);
        forged = reg;
        forged.opcode[1].size = 8u;
        expect_forged_format_rejected(&forged);
        forged = reg;
        forged.opcode[1].reg = CDISASM_X86_REG_YMM1;
        expect_forged_format_rejected(&forged);
        forged = reg;
        forged.x86_group_count -= 1u;
        expect_forged_format_rejected(&forged);

        high = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            high_code, sizeof(high_code), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(high_code));
        EXPECT(high.x86_group_count == 3u);
        EXPECT(high.x86_group_ids[0] == CDISASM_X86_GROUP_AMD64);
        EXPECT(high.x86_group_ids[1] == CDISASM_X86_GROUP_AVX);
        EXPECT(high.x86_group_ids[2] == CDISASM_X86_GROUP_AVX2);
        forged = high;
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_AVX;
        forged.x86_group_ids[1] = CDISASM_X86_GROUP_AVX2;
        forged.x86_group_ids[2] = CDISASM_X86_GROUP_NONE;
        forged.x86_group_count = 2u;
        expect_forged_format_rejected(&forged);
    }
#endif
}

int main(void)
{
    test_control_partition();
    test_forms_modes_and_addresses();
    test_runtime_profiles_and_extras();
    test_prefixes_truncation_and_collisions();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr,
            "x86 VBROADCASTSD/SS tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 VBROADCASTSD/SS tests passed");
    return 0;
}
