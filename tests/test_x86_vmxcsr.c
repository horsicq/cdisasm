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

_Static_assert(CDISASM_X86_NAME_VLDMXCSR == UINT16_C(1751)
        && CDISASM_X86_NAME_VSTMXCSR == UINT16_C(2006),
    "VMXCSR name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VMXCSR AVX IDs changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VMXCSR profile sweeps");

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
static cdisasm_x86_decode_flags all_flags(cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, mode, &flags) == CDISASM_STATUS_OK);
    return flags;
}

static cdisasm_x86_decode_flags one_bit(
    cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit_id));
    return flags;
}

static void check_vmxcsr(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    int load)
{
    const cdisasm_opcode *memory = &instruction->opcode[0];

    EXPECT(decoded_size >= 4u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == (load
        ? CDISASM_X86_NAME_VLDMXCSR : CDISASM_X86_NAME_VSTMXCSR));
    EXPECT(instruction->form_id == (load
        ? UINT16_C(5585) : UINT16_C(8752)));
    EXPECT(instruction->operand_count == 1u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
        == CDISASM_PREFIX_VEX);
    EXPECT(instruction->encoding.prefix_size >= 2u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT((instruction->encoding.modrm & UINT8_C(0xc0))
        != UINT8_C(0xc0));
    EXPECT(((instruction->encoding.modrm >> 3) & UINT8_C(7))
        == (load ? UINT8_C(2) : UINT8_C(3)));
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset == 0u);
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
    EXPECT(memory->size == 4u);
    EXPECT(memory->access == (load
        ? CDISASM_OPERAND_ACCESS_READ
        : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT((memory->flags
        & (CDISASM_OPERAND_FLAG_IMPLICIT
            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
    EXPECT(memory->broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->branch_target == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_SSE));
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    int load)
{
#if USE_EXTRA_OPCODES
    check_vmxcsr(instruction, decoded_size, load);
#else
    (void)load;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_complete_c4_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    uint64_t form_counts[2] = {0u, 0u};
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
                ? (uint8_t)((p0_index << 5) | 1u)
                : (uint8_t)(0xc1u | (p0_index << 5));
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
                                const unsigned int reg =
                                    (modrm >> 3) & 7u;
                                const int load = reg == 2u;
                                const int valid = l == 0u && pp == 0u
                                    && vvvv == 0u
                                    && (modrm & UINT8_C(0xc0))
                                        != UINT8_C(0xc0)
                                    && (reg == 2u || reg == 3u);
                                const uint8_t code[15] = {
                                    0xc4, p0,
                                    (uint8_t)((w << 7)
                                        | (((~vvvv) & 15u) << 3)
                                        | (l << 2) | pp),
                                    0xae, (uint8_t)modrm, 0x24, 0x10,
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
                                    check_allocated(
                                        &instruction, decoded_size, load);
#if USE_EXTRA_OPCODES
                                    ++form_counts[load ? 0u : 1u];
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
        }
    }

    EXPECT(allocated == UINT64_C(1152));
    EXPECT(reserved == UINT64_C(785280));
#if USE_EXTRA_OPCODES
    EXPECT(form_counts[0] == UINT64_C(576));
    EXPECT(form_counts[1] == UINT64_C(576));
#else
    (void)form_counts;
#endif
}

static void test_complete_c5_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    uint64_t form_counts[2] = {0u, 0u};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const unsigned int p1_start = modes[mode_index] == CDISASM_MODE_64
            ? 0u : 0xc0u;
        unsigned int p1;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

        for (p1 = p1_start; p1 <= UINT8_MAX; ++p1) {
            unsigned int modrm;

            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                const unsigned int reg = (modrm >> 3) & 7u;
                const int load = reg == 2u;
                const int valid = (p1 & 0x7fu) == 0x78u
                    && (modrm & UINT8_C(0xc0)) != UINT8_C(0xc0)
                    && (reg == 2u || reg == 3u);
                const uint8_t code[15] = {
                    0xc5, (uint8_t)p1, 0xae, (uint8_t)modrm,
                    0x24, 0x10, 0x20, 0x30, 0x40, 0x50,
                    0x60, 0x70, 0x80, 0x90, 0xa0};
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
                    check_allocated(&instruction, decoded_size, load);
#if USE_EXTRA_OPCODES
                    ++form_counts[load ? 0u : 1u];
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

    EXPECT(allocated == UINT64_C(192));
    EXPECT(reserved == UINT64_C(98112));
#if USE_EXTRA_OPCODES
    EXPECT(form_counts[0] == UINT64_C(96));
    EXPECT(form_counts[1] == UINT64_C(96));
#else
    (void)form_counts;
#endif
}

static void test_forms_addresses_and_aliases(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t c5_load[] = {0xc5,0xf8,0xae,0x10};
    static const uint8_t c5_store[] = {0xc5,0xf8,0xae,0x18};
    static const uint8_t c4_w1_load[] = {0xc4,0xe1,0xf8,0xae,0x10};
    static const uint8_t high_sib_store[] =
        {0xc4,0x81,0xf8,0xae,0x5c,0xa5,0x80};
    static const uint8_t rip_load[] =
        {0xc5,0xf8,0xae,0x15,0x78,0x56,0x34,0x12};
    static const uint8_t address_load[] = {0x67,0xc5,0xf8,0xae,0x10};
    static const uint8_t segment_store[] = {0x64,0xc5,0xf8,0xae,0x18};
    static const uint8_t r_ignored_load[] = {0xc5,0x78,0xae,0x10};
    static const uint8_t c4_r_ignored_load[] = {0xc4,0x61,0x78,0xae,0x10};
    static const uint8_t nonlong_b_alias[] = {0xc4,0xc1,0x78,0xae,0x10};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        c5_load, sizeof(c5_load), &flags, &decoded_size);
    check_vmxcsr(&instruction, decoded_size, 1);
    EXPECT(instruction.encoding.prefix_size == 2u);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_RAX);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        c5_store, sizeof(c5_store), &flags, &decoded_size);
    check_vmxcsr(&instruction, decoded_size, 0);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_RAX);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        c4_w1_load, sizeof(c4_w1_load), &flags, &decoded_size);
    check_vmxcsr(&instruction, decoded_size, 1);
    EXPECT(instruction.encoding.prefix_size == 3u);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_RAX);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        high_sib_store, sizeof(high_sib_store), &flags, &decoded_size);
    check_vmxcsr(&instruction, decoded_size, 0);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R13);
    EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_R12);
    EXPECT(instruction.opcode[0].scale == 4u);
    EXPECT(instruction.opcode[0].imm == (uint64_t)-INT64_C(128));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rip_load, sizeof(rip_load), &flags, &decoded_size);
    check_vmxcsr(&instruction, decoded_size, 1);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_RIP);
    EXPECT(instruction.opcode[0].imm == UINT64_C(0x12345678));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        address_load, sizeof(address_load), &flags, &decoded_size);
    check_vmxcsr(&instruction, decoded_size, 1);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_EAX);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        segment_store, sizeof(segment_store), &flags, &decoded_size);
    check_vmxcsr(&instruction, decoded_size, 0);
    EXPECT(instruction.opcode[0].segment_reg == CDISASM_X86_REG_FS);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        r_ignored_load, sizeof(r_ignored_load), &flags, &decoded_size);
    check_vmxcsr(&instruction, decoded_size, 1);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_RAX);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        c4_r_ignored_load, sizeof(c4_r_ignored_load),
        &flags, &decoded_size);
    check_vmxcsr(&instruction, decoded_size, 1);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_RAX);

    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32};
        size_t index;

        for (index = 0u; index < 2u; ++index) {
            cdisasm_x86_decode_flags mode_flags = all_flags(modes[index]);

            instruction = decode(CDISASM_CPU_X86, modes[index],
                nonlong_b_alias, sizeof(nonlong_b_alias),
                &mode_flags, &decoded_size);
            check_vmxcsr(&instruction, decoded_size, 1);
            EXPECT(instruction.opcode[0].base_reg == (index == 0u
                ? CDISASM_X86_REG_BX : CDISASM_X86_REG_EAX));
            if (index == 0u) {
                EXPECT(instruction.opcode[0].index_reg
                    == CDISASM_X86_REG_SI);
            }
        }
    }
#endif
}

static void test_runtime_and_profile_gates(void)
{
    static const uint8_t load[] = {0xc5,0xf8,0xae,0x10};
    static const uint8_t store[] = {0xc5,0xf8,0xae,0x18};

#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags avx = one_bit(CDISASM_X86_DECODE_BIT_AVX);
    cdisasm_x86_decode_flags avx2 = one_bit(CDISASM_X86_DECODE_BIT_AVX2);
    cdisasm_x86_decode_flags sandy;
    cdisasm_x86_decode_flags westmere;
    cdisasm_x86_decode_flags bulldozer;
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        load, sizeof(load), &avx, &decoded_size);
    check_vmxcsr(&instruction, decoded_size, 1);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        store, sizeof(store), &avx, &decoded_size);
    check_vmxcsr(&instruction, decoded_size, 0);
    expect_error("VLDMXCSR needs AVX", CDISASM_CPU_X86,
        CDISASM_MODE_64, load, sizeof(load), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX2 alone does not admit VLDMXCSR", CDISASM_CPU_X86,
        CDISASM_MODE_64, load, sizeof(load), &avx2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64, &sandy)
        == CDISASM_STATUS_OK);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_WESTMERE, CDISASM_MODE_64, &westmere)
        == CDISASM_STATUS_OK);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_BULLDOZER, CDISASM_MODE_64, &bulldozer)
        == CDISASM_STATUS_OK);
    instruction = decode(CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
        load, sizeof(load), &sandy, &decoded_size);
    check_vmxcsr(&instruction, decoded_size, 1);
    instruction = decode(CDISASM_CPU_BULLDOZER, CDISASM_MODE_64,
        store, sizeof(store), &bulldozer, &decoded_size);
    check_vmxcsr(&instruction, decoded_size, 0);
    expect_error("Westmere VLDMXCSR gate", CDISASM_CPU_WESTMERE,
        CDISASM_MODE_64, load, sizeof(load), &westmere,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    expect_error("VLDMXCSR extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, load, sizeof(load), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VSTMXCSR extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, store, sizeof(store), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_reserved_truncation_and_siblings(void)
{
    static const uint8_t complete[] = {0xc5,0xf8,0xae,0x14,0x24};
    static const uint8_t forbidden_prefixes[5] = {0x66,0xf2,0xf3,0xf0,0x48};
    size_t index;

    for (index = 1u; index < sizeof(complete); ++index) {
        expect_error("truncated VMXCSR", CDISASM_CPU_X86,
            CDISASM_MODE_64, complete, index, NULL,
            CDISASM_STATUS_TRUNCATED);
    }
    for (index = 0u;
         index < sizeof(forbidden_prefixes) / sizeof(forbidden_prefixes[0]);
         ++index) {
        const uint8_t prefixed[] = {
            forbidden_prefixes[index],0xc5,0xf8,0xae,0x14,0x24};

        expect_error("prefixed VMXCSR missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64, prefixed, 5u, NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("prefixed complete VMXCSR", CDISASM_CPU_X86,
            CDISASM_MODE_64, prefixed, sizeof(prefixed), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    expect_error("VMXCSR reserved L1", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xfc,0xae,0x10}, 4u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VMXCSR reserved pp66", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf9,0xae,0x10}, 4u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VMXCSR reserved vvvv", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf0,0xae,0x10}, 4u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VMXCSR register ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf8,0xae,0xd0}, 4u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VMXCSR unallocated /1", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf8,0xae,0x08}, 4u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("VMXCSR reserved pp missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf9,0xae,0x14}, 4u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("VMXCSR wrong reserved map", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe4,0x78,0xae,0x10}, 5u, NULL,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    {
        static const uint8_t legacy_load[] = {0x0f,0xae,0x10};
        static const uint8_t legacy_store[] = {0x0f,0xae,0x18};
        static const uint8_t fences[3][3] = {
            {0x0f,0xae,0xe8}, {0x0f,0xae,0xf0}, {0x0f,0xae,0xf8}};
#if USE_EXTRA_OPCODES
        static const cdisasm_x86_name_id fence_names[3] = {
            CDISASM_X86_NAME_LFENCE,
            CDISASM_X86_NAME_MFENCE,
            CDISASM_X86_NAME_SFENCE};
#endif
        static const uint8_t clflush[] = {0x0f,0xae,0x38};
        static const uint8_t les_collision[] =
            {0xc4,0x61,0x78,0xae,0x10,0,0,0};
        static const uint8_t lds_collision[] =
            {0xc5,0x78,0xae,0x10,0,0,0};
        static const uint8_t evex_neighbor[] =
            {0x62,0xf2,0x7d,0x08,0xae,0x10};
        cdisasm_x86_decode_flags flags =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

#if USE_EXTRA_OPCODES
        flags = all_flags(CDISASM_MODE_64);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_load, sizeof(legacy_load), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_load));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LDMXCSR);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy_store, sizeof(legacy_store), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(legacy_store));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_STMXCSR);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        for (index = 0u; index < 3u; ++index) {
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                fences[index], sizeof(fences[index]), &flags, &decoded_size);
            EXPECT(decoded_size == sizeof(fences[index]));
            EXPECT(instruction.name_id == fence_names[index]);
        }
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            clflush, sizeof(clflush), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(clflush));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_CLFLUSH);
#else
        expect_error("legacy LDMXCSR extras off", CDISASM_CPU_X86,
            CDISASM_MODE_64, legacy_load, sizeof(legacy_load), &flags,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("legacy STMXCSR extras off", CDISASM_CPU_X86,
            CDISASM_MODE_64, legacy_store, sizeof(legacy_store), &flags,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        for (index = 0u; index < 3u; ++index) {
            expect_error("legacy fence extras off", CDISASM_CPU_X86,
                CDISASM_MODE_64, fences[index], sizeof(fences[index]),
                &flags, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
        expect_error("legacy CLFLUSH extras off", CDISASM_CPU_X86,
            CDISASM_MODE_64, clflush, sizeof(clflush), &flags,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
            les_collision, sizeof(les_collision), NULL, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LES);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
            lds_collision, sizeof(lds_collision), NULL, &decoded_size);
        EXPECT(decoded_size != 0u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_LDS);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            evex_neighbor, sizeof(evex_neighbor), &flags, &decoded_size);
        EXPECT(decoded_size == 0u
            || (instruction.name_id != CDISASM_X86_NAME_VLDMXCSR
                && instruction.name_id != CDISASM_X86_NAME_VSTMXCSR));
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format_rejected(const cdisasm_instruction *instruction)
{
    char output[192] = {'x'};

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
        {{0xc5,0xf8,0xae,0x10,0,0,0,0},4u,
            "vldmxcsr dword ptr [rax]", "vldmxcsr (%rax)"},
        {{0xc5,0xf8,0xae,0x18,0,0,0,0},4u,
            "vstmxcsr dword ptr [rax]", "vstmxcsr (%rax)"},
        {{0xc4,0x81,0xf8,0xae,0x5c,0xa5,0x80,0},7u,
            "vstmxcsr dword ptr [r13 + r12*4 - 0x80]",
            "vstmxcsr -0x80(%r13,%r12,4)"},
        {{0x64,0xc5,0xf8,0xae,0x18,0,0,0},5u,
            "vstmxcsr dword ptr fs:[rax]", "vstmxcsr %fs:(%rax)"},
        {{0x67,0x67,0xc4,0xe1,0x78,0xae,0x10,0},7u,
            "vldmxcsr dword ptr [eax]", "vldmxcsr (%eax)"},
        {{0x67,0x67,0x67,0xc5,0xf8,0xae,0x10,0},7u,
            "vldmxcsr dword ptr [eax]", "vldmxcsr (%eax)"}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        char output[192];
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == cases[index].size);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);

        forged = instruction;
        forged.name_id = instruction.name_id == CDISASM_X86_NAME_VLDMXCSR
            ? CDISASM_X86_NAME_VSTMXCSR : CDISASM_X86_NAME_VLDMXCSR;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.form_id = instruction.form_id == UINT16_C(5585)
            ? UINT16_C(8752) : UINT16_C(5585);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags &= ~CDISASM_PREFIX_VEX;
        forged.opcode_flags |= CDISASM_PREFIX_EVEX;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.operand_count = 0u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[0].access = instruction.opcode[0].access
            == CDISASM_OPERAND_ACCESS_READ
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[0].size = 8u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.modrm ^= UINT8_C(8);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.x86_group_count = 0u;
        memset(forged.x86_group_ids, 0, sizeof(forged.x86_group_ids));
        expect_format_rejected(&forged);
        forged = instruction;
        ++forged.encoding.opcode_offset;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[0].base_reg = CDISASM_X86_REG_R16;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[0].flags ^=
            CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT;
        expect_format_rejected(&forged);

        if (instruction.encoding.prefix_size == 2u) {
            forged = instruction;
            forged.opcode[0].base_reg = CDISASM_X86_REG_R8;
            forged.x86_group_count = 2u;
            forged.x86_group_ids[0] = CDISASM_X86_GROUP_AMD64;
            forged.x86_group_ids[1] = CDISASM_X86_GROUP_AVX;
            expect_format_rejected(&forged);
        }
    }
    {
        static const uint8_t legacy[] = {0x0f,0xae,0x10};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy, sizeof(legacy), &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(legacy));
        forged = instruction;
        forged.name_id = CDISASM_X86_NAME_VLDMXCSR;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.name_id = CDISASM_X86_NAME_VLDMXCSR;
        forged.form_id = UINT16_C(5585);
        expect_format_rejected(&forged);
    }
#endif
}

int main(void)
{
    test_complete_c4_control_partition();
    test_complete_c5_control_partition();
    test_forms_addresses_and_aliases();
    test_runtime_and_profile_gates();
    test_reserved_truncation_and_siblings();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VMXCSR test(s) failed\n", failures);
        return 1;
    }
    printf("x86 VMXCSR tests passed (1,344 allocated and "
        "883,392 reserved C4/C5 controls)\n");
    return 0;
}
