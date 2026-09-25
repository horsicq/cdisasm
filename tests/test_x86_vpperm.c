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
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VPPERM == UINT16_C(882),
    "VPPERM name ID changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_GROUP_XOP == UINT16_C(38),
    "VPPERM ISA-set group IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
        && CDISASM_X86_DECODE_BIT_XOP == UINT32_C(12),
    "VPPERM runtime-bit IDs changed");

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

static cdisasm_x86_decode_flags selected_flags(int avx, int xop)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    if (avx) {
        EXPECT(cdisasm_decode_flags_set_bit(
            &flags, CDISASM_X86_DECODE_BIT_AVX));
    }
    if (xop) {
        EXPECT(cdisasm_decode_flags_set_bit(
            &flags, CDISASM_X86_DECODE_BIT_XOP));
    }
    return flags;
}

static cdisasm_x86_form_id expected_form(int w, int register_form)
{
    return (cdisasm_x86_form_id)(UINT16_C(7686)
        + (register_form ? 2u : (w ? 1u : 0u)));
}

static void check_vpperm(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_mode mode,
    int w,
    int register_form,
    unsigned int destination,
    unsigned int source1,
    unsigned int rm_source,
    unsigned int selector_source)
{
    const unsigned int rm_index = w ? 3u : 2u;
    const unsigned int selector_index = w ? 2u : 3u;
    unsigned int index;

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_VPPERM);
    EXPECT(instruction->form_id == expected_form(w, register_form));
    EXPECT(instruction->operand_count == 4u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
        == CDISASM_PREFIX_XOP);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset
        == decoded_size - UINT32_C(1));

    for (index = 0u; index < 4u; ++index) {
        const int is_memory = !register_form && index == rm_index;

        EXPECT(instruction->opcode[index].type == (is_memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(instruction->opcode[index].size == 16u);
        EXPECT(instruction->opcode[index].access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
        EXPECT(instruction->opcode[index].broadcast
            == CDISASM_X86_BROADCAST_NONE);
        if (!is_memory) {
            EXPECT(instruction->opcode[index].flags == 0u);
        } else {
            EXPECT((instruction->opcode[index].flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
        }
    }
    EXPECT(instruction->opcode[0].reg
        == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + destination));
    EXPECT(instruction->opcode[1].reg
        == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + source1));
    if (register_form) {
        EXPECT(instruction->opcode[rm_index].reg
            == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + rm_source));
    }
    EXPECT(instruction->opcode[selector_index].reg
        == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + selector_source));
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_XOP));
    if (mode != CDISASM_MODE_64) {
        EXPECT(destination < 8u);
        EXPECT(source1 < 8u);
        EXPECT(!register_form || rm_source < 8u);
        EXPECT(selector_source < 8u);
    }
}
#endif

static void check_allocated(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    int w,
    int register_form)
{
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_VPPERM);
    EXPECT(instruction->form_id == expected_form(w, register_form));
    EXPECT(instruction->operand_count == 4u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset
        == decoded_size - UINT32_C(1));
    EXPECT(instruction->opcode[w ? 3u : 2u].type == (register_form
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
#else
    (void)w;
    (void)register_form;
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(
        instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_control_partition(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint64_t expected_form_counts[3] = {
        UINT64_C(73728), UINT64_C(73728), UINT64_C(49152)
    };
    uint64_t form_counts[3] = {0, 0, 0};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags =
            cpu_flags(CDISASM_CPU_X86, modes[mode_index]);
#endif
        unsigned int p0_index;

        for (p0_index = 0u; p0_index < 8u; ++p0_index) {
            const uint8_t p0 = (uint8_t)((p0_index << 5) | 8u);
            unsigned int w;

            for (w = 0u; w < 2u; ++w) {
                unsigned int l;

                for (l = 0u; l < 2u; ++l) {
                    unsigned int pp;

                    for (pp = 0u; pp < 4u; ++pp) {
                        unsigned int vvvv;

                        for (vvvv = 0u; vvvv < 16u; ++vvvv) {
                            unsigned int modrm;

                            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                                const int register_form =
                                    (modrm & UINT8_C(0xc0))
                                        == UINT8_C(0xc0);
                                const uint8_t code[15] = {
                                    0x8f, p0,
                                    (uint8_t)((w << 7)
                                        | (((~vvvv) & 15u) << 3)
                                        | (l << 2) | pp),
                                    0xa3, (uint8_t)modrm,
                                    0x24, 0x4f, 0x20, 0x30, 0x40,
                                    0x50, 0x60, 0x70, 0x80, 0x90
                                };
                                uint32_t decoded_size;
                                cdisasm_instruction instruction = decode(
                                    CDISASM_CPU_X86, modes[mode_index],
                                    code, sizeof(code),
#if USE_EXTRA_OPCODES
                                    &flags, &decoded_size);
#else
                                    NULL, &decoded_size);
#endif

                                if (pp == 0u && l == 0u) {
                                    const unsigned int form_index =
                                        register_form ? 2u : w;

                                    check_allocated(&instruction,
                                        decoded_size, (int)w, register_form);
                                    ++form_counts[form_index];
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
    EXPECT(allocated == UINT64_C(196608));
    EXPECT(reserved == UINT64_C(1376256));
    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        EXPECT(form_counts[mode_index] == expected_form_counts[mode_index]);
    }
}

static void test_forms_operands_addresses_and_aliases(void)
{
#if USE_EXTRA_OPCODES
    static const struct form_case {
        uint8_t code[6];
        int w;
        unsigned int form_id;
    } forms[] = {
        {{0x8f, 0xe8, 0x68, 0xa3, 0x00, 0x4f}, 0, 7686u},
        {{0x8f, 0xe8, 0xe8, 0xa3, 0x00, 0x4f}, 1, 7687u},
        {{0x8f, 0xe8, 0x68, 0xa3, 0xcb, 0x4f}, 0, 7688u},
        {{0x8f, 0xe8, 0xe8, 0xa3, 0xcb, 0x4f}, 1, 7688u}
    };
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(forms) / sizeof(forms[0]); ++index) {
        const int register_form =
            (forms[index].code[4] & UINT8_C(0xc0)) == UINT8_C(0xc0);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            forms[index].code, sizeof(forms[index].code),
            &flags, &decoded_size);

        check_vpperm(&instruction, decoded_size, CDISASM_MODE_64,
            forms[index].w, register_form,
            register_form ? 1u : 0u, 2u,
            register_form ? 3u : 0u, 4u);
        EXPECT(instruction.form_id == forms[index].form_id);
        if (!register_form) {
            EXPECT(instruction.opcode[forms[index].w ? 3u : 2u].base_reg
                == CDISASM_X86_REG_RAX);
        }
    }

    {
        static const uint8_t high_registers[] =
            {0x8f, 0x48, 0x30, 0xa3, 0xfa, 0xff};
        static const uint8_t high_address[] =
            {0x8f, 0x08, 0x30, 0xa3, 0x44, 0xa5, 0x80, 0xf1};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            high_registers, sizeof(high_registers), &flags, &decoded_size);

        check_vpperm(&instruction, decoded_size, CDISASM_MODE_64,
            0, 1, 15u, 9u, 10u, 15u);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            high_address, sizeof(high_address), &flags, &decoded_size);
        check_vpperm(&instruction, decoded_size, CDISASM_MODE_64,
            0, 0, 8u, 9u, 0u, 15u);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R13);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_R12);
        EXPECT(instruction.opcode[2].scale == 4u);
        EXPECT(instruction.opcode[2].imm == (uint64_t)-INT64_C(128));
    }

    {
        static const cdisasm_x86_mode modes[2] = {
            CDISASM_MODE_16, CDISASM_MODE_32
        };
        static const uint8_t aliases[] =
            {0x8f, 0x08, 0x38, 0xa3, 0xfa, 0xff};

        for (index = 0u; index < 2u; ++index) {
            cdisasm_x86_decode_flags mode_flags =
                cpu_flags(CDISASM_CPU_X86, modes[index]);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[index], aliases, sizeof(aliases),
                &mode_flags, &decoded_size);

            check_vpperm(&instruction, decoded_size, modes[index],
                0, 1, 7u, 0u, 2u, 7u);
        }
    }

    {
        static const uint8_t sib_x_b_alias[] =
            {0x8f, 0x88, 0x68, 0xa3, 0x04, 0x24, 0x4f};
        cdisasm_x86_decode_flags mode_flags =
            cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_32);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_32,
            sib_x_b_alias, sizeof(sib_x_b_alias),
            &mode_flags, &decoded_size);

        /* LLVM's i386 policy aliases XOP.X/B here.  Pinned XED anomalously
         * exposes r12d for this 32-bit SIB.X spelling; stay consistent with
         * VPCMOV and the architecture's eight-register non-long namespace. */
        check_vpperm(&instruction, decoded_size, CDISASM_MODE_32,
            0, 0, 0u, 2u, 0u, 4u);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_ESP);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_NONE);
        EXPECT(instruction.x86_group_count == 3u);
        EXPECT(instruction.x86_group_ids[0] == CDISASM_X86_GROUP_I386);
        EXPECT(instruction.x86_group_ids[1] == CDISASM_X86_GROUP_AVX);
        EXPECT(instruction.x86_group_ids[2] == CDISASM_X86_GROUP_XOP);
    }

    {
        static const uint8_t address16_alias[] =
            {0x8f, 0x88, 0x68, 0xa3, 0x04, 0x4f};
        cdisasm_x86_decode_flags mode_flags =
            cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_16);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_16,
            address16_alias, sizeof(address16_alias),
            &mode_flags, &decoded_size);

        check_vpperm(&instruction, decoded_size, CDISASM_MODE_16,
            0, 0, 0u, 2u, 0u, 4u);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_SI);
        EXPECT(instruction.opcode[2].index_reg == CDISASM_X86_REG_NONE);
        EXPECT(instruction.x86_group_count == 2u);
        EXPECT(instruction.x86_group_ids[0] == CDISASM_X86_GROUP_AVX);
        EXPECT(instruction.x86_group_ids[1] == CDISASM_X86_GROUP_XOP);
    }

    {
        static const cdisasm_x86_mode modes[3] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
        };
        size_t mode_index;

        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            cdisasm_x86_decode_flags mode_flags =
                cpu_flags(CDISASM_CPU_X86, modes[mode_index]);
            unsigned int selector;

            for (selector = 0u; selector <= UINT8_MAX; ++selector) {
                unsigned int w;

                for (w = 0u; w < 2u; ++w) {
                    uint8_t code[] = {
                        0x8f, 0xe8,
                        (uint8_t)((w << 7) | 0x68u),
                        0xa3, 0xcb, (uint8_t)selector
                    };
                    const unsigned int selector_reg =
                        (selector >> 4)
                        & (modes[mode_index] == CDISASM_MODE_64
                            ? 15u : 7u);
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, modes[mode_index],
                        code, sizeof(code), &mode_flags, &decoded_size);

                    check_vpperm(&instruction, decoded_size,
                        modes[mode_index], (int)w, 1,
                        1u, 2u, 3u, selector_reg);
                }
            }
        }
    }

    {
        static const uint8_t address_override[] =
            {0x67, 0x8f, 0xe8, 0x68, 0xa3, 0x00, 0x4f};
        static const uint8_t segment_override[] =
            {0x64, 0x8f, 0xe8, 0xe8, 0xa3, 0x00, 0x4f};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            address_override, sizeof(address_override),
            &flags, &decoded_size);

        check_vpperm(&instruction, decoded_size, CDISASM_MODE_64,
            0, 0, 0u, 2u, 0u, 4u);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_EAX);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            segment_override, sizeof(segment_override),
            &flags, &decoded_size);
        check_vpperm(&instruction, decoded_size, CDISASM_MODE_64,
            1, 0, 0u, 2u, 0u, 4u);
        EXPECT(instruction.opcode[3].segment_reg == CDISASM_X86_REG_FS);
    }
#endif
}

static void test_runtime_and_profile_gates(void)
{
    static const uint8_t code[] =
        {0x8f, 0xe8, 0x68, 0xa3, 0xcb, 0x4f};

#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags avx = selected_flags(1, 0);
    cdisasm_x86_decode_flags xop = selected_flags(0, 1);
    cdisasm_x86_decode_flags both = selected_flags(1, 1);
    cdisasm_x86_decode_flags bulldozer =
        cpu_flags(CDISASM_CPU_AMD_BULLDOZER, CDISASM_MODE_64);
    cdisasm_x86_decode_flags haswell =
        cpu_flags(CDISASM_CPU_HASWELL, CDISASM_MODE_64);
    cdisasm_x86_decode_flags zen =
        cpu_flags(CDISASM_CPU_AMD_ZEN, CDISASM_MODE_64);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    expect_error("VPPERM needs XOP runtime family", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &avx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        code, sizeof(code), &xop, &decoded_size);
    check_vpperm(&instruction, decoded_size, CDISASM_MODE_64,
        0, 1, 1u, 2u, 3u, 4u);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        code, sizeof(code), &both, &decoded_size);
    check_vpperm(&instruction, decoded_size, CDISASM_MODE_64,
        0, 1, 1u, 2u, 3u, 4u);
    instruction = decode(CDISASM_CPU_AMD_BULLDOZER, CDISASM_MODE_64,
        code, sizeof(code), &bulldozer, &decoded_size);
    check_vpperm(&instruction, decoded_size, CDISASM_MODE_64,
        0, 1, 1u, 2u, 3u, 4u);
    expect_error("Haswell lacks AMD XOP", CDISASM_CPU_HASWELL,
        CDISASM_MODE_64, code, sizeof(code), &haswell,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("Zen dropped AMD XOP", CDISASM_CPU_AMD_ZEN,
        CDISASM_MODE_64, code, sizeof(code), &zen,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    {
        cdisasm_x86_cpu_id cpu_id;

        for (cpu_id = CDISASM_CPU_FIRST; cpu_id <= CDISASM_CPU_LAST;
             ++cpu_id) {
            cdisasm_x86_decode_flags profile_flags =
                CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

            EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                cpu_id, CDISASM_MODE_16, &profile_flags)
                == CDISASM_STATUS_OK);
            if (cpu_id == CDISASM_CPU_AMD_BULLDOZER) {
                instruction = decode(cpu_id, CDISASM_MODE_16,
                    code, sizeof(code), &profile_flags, &decoded_size);
                check_vpperm(&instruction, decoded_size,
                    CDISASM_MODE_16, 0, 1, 1u, 2u, 3u, 4u);
            } else {
                expect_error("named profile lacks XOP", cpu_id,
                    CDISASM_MODE_16, code, sizeof(code), &profile_flags,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }
    }
#else
    expect_error("VPPERM extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_prefixes_truncation_and_unowned_neighbors(void)
{
    static const uint8_t complete[] =
        {0x8f, 0xe8, 0x68, 0xa3, 0xcb, 0x4f};
    static const uint8_t legacy_prefixes[5] =
        {0x66, 0xf2, 0xf3, 0xf0, 0x48};
    size_t index;

    for (index = 1u; index < sizeof(complete); ++index) {
        expect_error("truncated VPPERM", CDISASM_CPU_X86,
            CDISASM_MODE_64, complete, index, NULL,
            CDISASM_STATUS_TRUNCATED);
    }
    expect_error("reserved L missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x8f, 0xe8, 0x6c, 0xa3, 0x04}, 5u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved L missing selector", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x8f, 0xe8, 0x6c, 0xa3, 0x04, 0x24}, 6u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved L complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x8f, 0xe8, 0x6c, 0xa3, 0x04, 0x24, 0x4f},
        7u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved pp missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x8f, 0xe8, 0x69, 0xa3, 0x04}, 5u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp missing selector", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x8f, 0xe8, 0x69, 0xa3, 0x04, 0x24}, 6u, NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("reserved pp complete", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x8f, 0xe8, 0x69, 0xa3, 0x04, 0x24, 0x4f},
        7u, NULL, CDISASM_STATUS_INVALID_INSTRUCTION);

    for (index = 0u; index < sizeof(legacy_prefixes); ++index) {
        uint8_t prefixed[] = {
            legacy_prefixes[index],
            0x8f, 0xe8, 0x68, 0xa3, 0x04, 0x24, 0x4f
        };

        expect_error("prefixed VPPERM missing SIB", CDISASM_CPU_X86,
            CDISASM_MODE_64, prefixed, 6u, NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("prefixed VPPERM missing selector", CDISASM_CPU_X86,
            CDISASM_MODE_64, prefixed, 7u, NULL,
            CDISASM_STATUS_TRUNCATED);
        expect_error("prefixed complete VPPERM", CDISASM_CPU_X86,
            CDISASM_MODE_64, prefixed, sizeof(prefixed), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    expect_error("VPPERM wrong XOP map", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x8f, 0xe9, 0x68, 0xa3, 0xcb, 0x4f},
        6u, NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("VPPERM opcode neighbor", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        (const uint8_t[]){0x8f, 0xe8, 0x68, 0xa4, 0xcb, 0x4f},
        6u, NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
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
        uint8_t code[8];
        size_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0x8f, 0xe8, 0x68, 0xa3, 0xcb, 0x41, 0, 0}, 6u,
            "vpperm xmm1, xmm2, xmm3, xmm4",
            "vpperm %xmm4, %xmm3, %xmm2, %xmm1"},
        {{0x8f, 0xe8, 0xe8, 0xa3, 0xcb, 0x4f, 0, 0}, 6u,
            "vpperm xmm1, xmm2, xmm4, xmm3",
            "vpperm %xmm3, %xmm4, %xmm2, %xmm1"},
        {{0x8f, 0xe8, 0x68, 0xa3, 0x00, 0xff, 0, 0}, 6u,
            "vpperm xmm0, xmm2, xmmword ptr [rax], xmm15",
            "vpperm %xmm15, (%rax), %xmm2, %xmm0"},
        {{0x8f, 0xe8, 0xe8, 0xa3, 0x40, 0x80, 0xf0, 0}, 7u,
            "vpperm xmm0, xmm2, xmm15, xmmword ptr [rax - 0x80]",
            "vpperm -0x80(%rax), %xmm15, %xmm2, %xmm0"}
    };
    cdisasm_x86_decode_flags flags =
        cpu_flags(CDISASM_CPU_X86, CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        char output[192];
        char tiny[4] = {'x', 'x', 'x', 'x'};
        size_t required;

        EXPECT(decoded_size == cases[index].size);
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, NULL, 0u);
        EXPECT(required == strlen(cases[index].intel));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output))
            == required);
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, tiny, sizeof(tiny)) == required);
        EXPECT(tiny[sizeof(tiny) - 1u] == '\0');
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT, NULL, 0u);
        EXPECT(required == strlen(cases[index].att));
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT, output, sizeof(output)) == required);
        EXPECT(strcmp(output, cases[index].att) == 0);
    }

    {
        static const uint8_t code[] =
            {0x8f, 0xe8, 0x68, 0xa3, 0xcb, 0x4f};
        uint32_t decoded_size;
        cdisasm_instruction valid = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(code));
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VPADDD;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.name_id = CDISASM_X86_NAME_VPCMOV;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(7685);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.form_id = UINT16_C(7686);
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.operand_count = 3u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags &= ~CDISASM_PREFIX_XOP;
        forged.opcode_flags |= CDISASM_PREFIX_VEX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |= CDISASM_PREFIX_REX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |= CDISASM_PREFIX_OPERAND_SIZE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.x86_group_ids[2] = CDISASM_X86_GROUP_FMA4;
        forged.x86_group_count = 3u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.x86_group_ids[2] = forged.x86_group_ids[1];
        forged.x86_group_ids[1] = forged.x86_group_ids[0];
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_I386;
        forged.x86_group_count = 3u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.x86_group_ids[2] = forged.x86_group_ids[1];
        forged.x86_group_ids[1] = forged.x86_group_ids[0];
        forged.x86_group_ids[0] = CDISASM_X86_GROUP_AMD64;
        forged.x86_group_count = 3u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
        forged.mask_reg = CDISASM_X86_REG_K1;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[1].size = 32u;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[2].type = CDISASM_OPERAND_MEMORY;
        forged.opcode[2].reg = CDISASM_X86_REG_NONE;
        forged.opcode[2].base_reg = CDISASM_X86_REG_RAX;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.opcode[3].broadcast = CDISASM_X86_BROADCAST_1_TO_8;
        expect_forged_format_rejected(&forged);
        forged = valid;
        forged.encoding.selector_offset = 0u;
        forged.encoding.immediate_count = 1u;
        forged.encoding.immediate_offset[0] = 5u;
        forged.encoding.immediate_size[0] = 1u;
        expect_forged_format_rejected(&forged);

        {
            static const uint8_t high_code[] =
                {0x8f, 0x48, 0x30, 0xa3, 0xfa, 0xff};
            cdisasm_instruction high = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                high_code, sizeof(high_code), &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(high_code));
            EXPECT(high.x86_group_count == 3u);
            EXPECT(high.x86_group_ids[0] == CDISASM_X86_GROUP_AMD64);
            forged = high;
            forged.x86_group_ids[0] = forged.x86_group_ids[1];
            forged.x86_group_ids[1] = forged.x86_group_ids[2];
            forged.x86_group_ids[2] = CDISASM_X86_GROUP_NONE;
            forged.x86_group_count = 2u;
            expect_forged_format_rejected(&forged);
        }
    }
#endif
}

int main(void)
{
    test_control_partition();
    test_forms_operands_addresses_and_aliases();
    test_runtime_and_profile_gates();
    test_prefixes_truncation_and_unowned_neighbors();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "x86 VPPERM tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 VPPERM tests passed");
    return 0;
}
