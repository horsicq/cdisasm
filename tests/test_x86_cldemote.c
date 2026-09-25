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
            fprintf(stderr, "%s:%d: expectation failed: %s\n",          \
                __FILE__, __LINE__, #expression);                            \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_CLDEMOTE == UINT16_C(1263),
    "CLDEMOTE name ID changed");
_Static_assert(CDISASM_X86_GROUP_CLDEMOTE == UINT16_C(264),
    "CLDEMOTE group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_CLDEMOTE == UINT32_C(211),
    "CLDEMOTE decode bit changed");

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

static cdisasm_x86_decode_flags cldemote_apx_flags(void)
{
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_CLDEMOTE);

    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_APX));
    return flags;
}
#endif

static void check_common_success(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size)
{
    if (decoded_size != expected_size
        || instruction->last_error_id != CDISASM_STATUS_OK) {
        fprintf(stderr, "%s: got size/status %u/%u, expected %u/0\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction->last_error_id,
            (unsigned int)expected_size);
    }
    EXPECT(decoded_size == expected_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
}

#if USE_EXTRA_OPCODES
static void check_cldemote(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    uint8_t prefix_size,
    uint8_t opcode_size)
{
    check_common_success(label, instruction, decoded_size, expected_size);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_CLDEMOTE);
    EXPECT(instruction->form_id == UINT16_C(710));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_CLDEMOTE));
    EXPECT((instruction->opcode_groups & CDISASM_GROUP_PRIVILEGED) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_EFFECTIVE_MASK | CDISASM_PREFIX_HLE_MASK)) == 0u);
    EXPECT(instruction->operand_count == 1u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction->opcode[0].size == 1u);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT((instruction->opcode[0].flags
        & CDISASM_OPERAND_FLAG_ADDRESS_ONLY) != 0u);
    EXPECT(instruction->encoding.prefix_size == prefix_size);
    EXPECT(instruction->encoding.opcode_offset == prefix_size);
    EXPECT(instruction->encoding.opcode_size == opcode_size);
    EXPECT(instruction->encoding.modrm_offset == prefix_size + opcode_size);
    EXPECT(instruction->encoding.immediate_count == 0u);
}
#endif

static void check_nop(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    int is_register,
    uint8_t operand_size,
    uint8_t prefix_size,
    uint8_t opcode_size)
{
    check_common_success(label, instruction, decoded_size, expected_size);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_NOP);
    EXPECT(instruction->form_id
        == (is_register ? UINT16_C(1855) : UINT16_C(1866)));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_P6));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_CLDEMOTE));
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_EFFECTIVE_MASK | CDISASM_PREFIX_HLE_MASK)) == 0u);
    EXPECT(instruction->operand_count == 2u);
    EXPECT(instruction->opcode[0].type == (is_register
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].size == operand_size);
    EXPECT(instruction->opcode[1].size == operand_size);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    if (!is_register) {
        EXPECT((instruction->opcode[0].flags
            & CDISASM_OPERAND_FLAG_ADDRESS_ONLY) == 0u);
    }
    EXPECT(instruction->encoding.prefix_size == prefix_size);
    EXPECT(instruction->encoding.opcode_offset == prefix_size);
    EXPECT(instruction->encoding.opcode_size == opcode_size);
    EXPECT(instruction->encoding.modrm_offset == prefix_size + opcode_size);
    EXPECT(instruction->encoding.immediate_count == 0u);
}

static size_t make_complete_legacy_row(
    cdisasm_x86_mode mode,
    uint8_t modrm,
    uint8_t code[15])
{
    const unsigned int mod = modrm >> 6;
    const unsigned int rm = modrm & 7u;
    size_t size = 0u;

    memset(code, 0, 15u);
    code[size++] = UINT8_C(0x0f);
    code[size++] = UINT8_C(0x1c);
    code[size++] = modrm;
    if (mod == 3u) {
        return size;
    }
    if (mode == CDISASM_MODE_16) {
        if (mod == 0u && rm == 6u) {
            size += 2u;
        } else if (mod == 1u) {
            size += 1u;
        } else if (mod == 2u) {
            size += 2u;
        }
        return size;
    }
    if (rm == 4u) {
        code[size++] = UINT8_C(0x00);
    }
    if ((mod == 0u && rm == 5u) || mod == 2u) {
        size += 4u;
    } else if (mod == 1u) {
        size += 1u;
    }
    return size;
}

static size_t make_complete_rex2_row(uint8_t modrm, uint8_t code[15])
{
    const unsigned int mod = modrm >> 6;
    const unsigned int rm = modrm & 7u;
    size_t size = 0u;

    memset(code, 0, 15u);
    code[size++] = UINT8_C(0xd5);
    code[size++] = UINT8_C(0x80);
    code[size++] = UINT8_C(0x1c);
    code[size++] = modrm;
    if (mod == 3u) {
        return size;
    }
    if (rm == 4u) {
        code[size++] = UINT8_C(0x00);
    }
    if ((mod == 0u && rm == 5u) || mod == 2u) {
        size += 4u;
    } else if (mod == 1u) {
        size += 1u;
    }
    return size;
}

static void test_complete_legacy_collision_space(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_CLDEMOTE);
#endif

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        unsigned int modrm;
        uint8_t operand_size = modes[mode_index] == CDISASM_MODE_16
            ? 2u : 4u;

        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
            uint8_t code[15];
            size_t size = make_complete_legacy_row(
                modes[mode_index], (uint8_t)modrm, code);
            const int is_register = modrm >= UINT8_C(0xc0);
#if USE_EXTRA_OPCODES
            const int canonical = !is_register
                && ((modrm >> 3) & 7u) == 0u;
#endif
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[mode_index], code, size,
#if USE_EXTRA_OPCODES
                &exact,
#else
                NULL,
#endif
                &decoded_size);

#if USE_EXTRA_OPCODES
            if (canonical) {
                check_cldemote("legacy ModRM sweep", &instruction,
                    decoded_size, size, 0u, 2u);
            } else
#endif
            {
                check_nop("legacy ModRM sweep", &instruction,
                    decoded_size, size, is_register, operand_size, 0u, 2u);
            }
        }
    }
}

static void test_prefix_partition_and_rex(void)
{
    static const uint8_t no_prefix[] = {0x0f, 0x1c, 0x00};
    static const uint8_t operand_66[] = {0x66, 0x0f, 0x1c, 0x00};
    static const uint8_t repeat_f2[] = {0xf2, 0x0f, 0x1c, 0x00};
    static const uint8_t repeat_f3[] = {0xf3, 0x0f, 0x1c, 0x00};
    static const uint8_t f2_then_f3[] = {
        0xf2, 0xf3, 0x0f, 0x1c, 0x00};
    static const uint8_t f3_then_66[] = {
        0xf3, 0x66, 0x0f, 0x1c, 0x00};
    static const uint8_t address_67[] = {0x67, 0x0f, 0x1c, 0x00};
    static const uint8_t segment_fs[] = {0x64, 0x0f, 0x1c, 0x00};
    static const struct prefix_case {
        const char *label;
        const uint8_t *code;
        size_t size;
        int canonical;
        uint8_t operand_size;
    } cases[] = {
        {"NP canonical", no_prefix, sizeof(no_prefix), 1, 4u},
        {"66 selects NOP", operand_66, sizeof(operand_66), 0, 2u},
        {"F2 selects NOP", repeat_f2, sizeof(repeat_f2), 0, 4u},
        {"F3 selects NOP", repeat_f3, sizeof(repeat_f3), 0, 4u},
        {"rightmost F3 is NOP", f2_then_f3, sizeof(f2_then_f3), 0, 4u},
        {"F3 plus 66 is NOP", f3_then_66, sizeof(f3_then_66), 0, 2u},
        {"67 remains CLDEMOTE", address_67, sizeof(address_67), 1, 4u},
        {"segment remains CLDEMOTE", segment_fs, sizeof(segment_fs), 1, 4u}
    };
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_CLDEMOTE);
#endif

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size,
#if USE_EXTRA_OPCODES
            &exact,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        if (cases[index].canonical) {
            check_cldemote(cases[index].label, &instruction, decoded_size,
                cases[index].size,
                (uint8_t)(cases[index].size - sizeof(no_prefix)), 2u);
        } else
#endif
        {
            check_nop(cases[index].label, &instruction, decoded_size,
                cases[index].size, 0, cases[index].operand_size,
                (uint8_t)(cases[index].size - sizeof(no_prefix)), 2u);
        }
    }

    for (index = 0u; index < 16u; ++index) {
        uint8_t code[] = {
            (uint8_t)(UINT8_C(0x40) + index), 0x0f, 0x1c, 0x00};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            &exact,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        check_cldemote("REX W/R/X/B sweep", &instruction, decoded_size,
            sizeof(code), 1u, 2u);
#else
        check_nop("REX W/R/X/B sweep", &instruction, decoded_size,
            sizeof(code), 0, (index & 8u) != 0u ? 8u : 4u, 1u, 2u);
#endif
    }

    {
        static const uint8_t register_rex[] = {
            0x4d, 0x0f, 0x1c, 0xc1};
        static const uint8_t memory_rex[] = {
            0x4d, 0x0f, 0x1c, 0x08};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            register_rex, sizeof(register_rex),
#if USE_EXTRA_OPCODES
            &exact,
#else
            NULL,
#endif
            &decoded_size);

        check_nop("REX register collision", &instruction, decoded_size,
            sizeof(register_rex), 1, 8u, 1u, 2u);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R9);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R8);

        instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            memory_rex, sizeof(memory_rex),
#if USE_EXTRA_OPCODES
            &exact,
#else
            NULL,
#endif
            &decoded_size);
        check_nop("REX memory collision", &instruction, decoded_size,
            sizeof(memory_rex), 0, 8u, 1u, 2u);
        EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R8);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R9);
    }
}

static void test_cpu_and_runtime_gates(void)
{
    static const cdisasm_x86_cpu_id cldemote_cpus[] = {
        CDISASM_CPU_X86,
        CDISASM_CPU_PENTIUM_SILVER_N6000,
        CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const cdisasm_x86_cpu_id nop_cpus[] = {
        CDISASM_CPU_TIGER_LAKE,
        CDISASM_CPU_ALDER_LAKE,
        CDISASM_CPU_AVX10,
        CDISASM_CPU_APX,
        CDISASM_CPU_ARROW_LAKE,
        CDISASM_CPU_AMD_ZEN_4
    };
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint8_t code[] = {0x0f, 0x1c, 0x00};
    size_t cpu_index;
    size_t mode_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_CLDEMOTE);
    cdisasm_x86_decode_flags memory_hints = one_bit(
        CDISASM_X86_DECODE_BIT_MEMORY_HINTS);
    cdisasm_x86_decode_flags wrong = one_bit(
        CDISASM_X86_DECODE_BIT_HRESET);
    cdisasm_x86_decode_flags exact_and_hints = exact;

    EXPECT(cdisasm_decode_flags_set_bit(
        &exact_and_hints, CDISASM_X86_DECODE_BIT_MEMORY_HINTS));
    expect_error("NULL flags are not exact CLDEMOTE", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("MEMORY_HINTS is not CLDEMOTE", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &memory_hints,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("wrong exact bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &wrong,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &exact_and_hints, &decoded_size);

        check_cldemote("exact bit plus umbrella", &instruction,
            decoded_size, sizeof(code), 0u, 2u);
    }
#endif

    for (cpu_index = 0u;
         cpu_index < sizeof(cldemote_cpus) / sizeof(cldemote_cpus[0]);
         ++cpu_index) {
        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            cdisasm_x86_decode_flags mask;
            uint32_t decoded_size;
            cdisasm_instruction instruction;

            EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                cldemote_cpus[cpu_index], modes[mode_index], &mask)
                == CDISASM_STATUS_OK);
            EXPECT(cdisasm_decode_flags_test_bit(
                &mask, CDISASM_X86_DECODE_BIT_CLDEMOTE)
                == USE_EXTRA_OPCODES);
            instruction = decode(
                cldemote_cpus[cpu_index], modes[mode_index],
                code, sizeof(code),
#if USE_EXTRA_OPCODES
                &exact,
#else
                NULL,
#endif
                &decoded_size);
#if USE_EXTRA_OPCODES
            check_cldemote("CLDEMOTE CPU profile", &instruction,
                decoded_size, sizeof(code), 0u, 2u);
#else
            check_nop("CLDEMOTE CPU profile OFF", &instruction,
                decoded_size, sizeof(code), 0,
                modes[mode_index] == CDISASM_MODE_16 ? 2u : 4u, 0u, 2u);
#endif
        }
    }

    for (cpu_index = 0u;
         cpu_index < sizeof(nop_cpus) / sizeof(nop_cpus[0]);
         ++cpu_index) {
        cdisasm_x86_decode_flags mask;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            nop_cpus[cpu_index], CDISASM_MODE_64, &mask)
            == CDISASM_STATUS_OK);
        EXPECT(!cdisasm_decode_flags_test_bit(
            &mask, CDISASM_X86_DECODE_BIT_CLDEMOTE));
        instruction = decode(
            nop_cpus[cpu_index], CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            &exact,
#else
            NULL,
#endif
            &decoded_size);
        check_nop("non-CLDEMOTE CPU falls back", &instruction,
            decoded_size, sizeof(code), 0, 4u, 0u, 2u);
    }

    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_PENTIUM_PRO, CDISASM_MODE_32,
            code, sizeof(code),
#if USE_EXTRA_OPCODES
            &exact,
#else
            NULL,
#endif
            &decoded_size);

        check_nop("P6 owns fallback NOP", &instruction, decoded_size,
            sizeof(code), 0, 4u, 0u, 2u);
        expect_error("pre-P6 cannot execute fallback NOP",
            CDISASM_CPU_PENTIUM, CDISASM_MODE_32,
            code, sizeof(code),
#if USE_EXTRA_OPCODES
            &exact,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_rex2_promotion(void)
{
    static const uint8_t canonical[] = {0xd5, 0x80, 0x1c, 0x00};
    static const uint8_t nop_memory[] = {0xd5, 0xc0, 0x1c, 0x08};
    static const uint8_t nop_register[] = {0xd5, 0xf8, 0x1c, 0xc1};
    static const uint8_t operand_66[] = {
        0x66, 0xd5, 0x80, 0x1c, 0x00};
    static const uint8_t repeat_f2[] = {
        0xf2, 0xd5, 0x80, 0x1c, 0x00};
    static const uint8_t repeat_f3[] = {
        0xf3, 0xd5, 0x80, 0x1c, 0x00};
    static const uint8_t address_67[] = {
        0x67, 0xd5, 0x80, 0x1c, 0x00};
    static const uint8_t segment_fs[] = {
        0x64, 0xd5, 0x80, 0x1c, 0x00};
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_CLDEMOTE);
    cdisasm_x86_decode_flags apx = one_bit(
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags both = cldemote_apx_flags();
    unsigned int modrm;
    unsigned int payload;

    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
        uint8_t code[15];
        size_t size = make_complete_rex2_row((uint8_t)modrm, code);
        const int is_register = modrm >= UINT8_C(0xc0);
        const int is_cldemote = !is_register
            && ((modrm >> 3) & 7u) == 0u;
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, size, &both, &decoded_size);

        if (is_cldemote) {
            check_cldemote("REX2 ModRM sweep", &instruction,
                decoded_size, size, 2u, 1u);
        } else {
            check_nop("REX2 ModRM sweep", &instruction,
                decoded_size, size, is_register, 4u, 2u, 1u);
        }
    }

    for (payload = UINT8_C(0x80); payload <= UINT8_MAX; ++payload) {
        uint8_t code[] = {0xd5, (uint8_t)payload, 0x1c, 0x00};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &both, &decoded_size);

        check_cldemote("REX2 payload sweep", &instruction, decoded_size,
            sizeof(code), 2u, 1u);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
    }

    expect_error("REX2 CLDEMOTE needs APX runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, canonical, sizeof(canonical), &exact,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 CLDEMOTE needs exact runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, canonical, sizeof(canonical), &apx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    {
        static const struct rex2_prefix_case {
            const char *label;
            const uint8_t *code;
            size_t size;
            uint8_t operand_size;
        } nop_cases[] = {
            {"REX2 66 selects NOP", operand_66, sizeof(operand_66), 2u},
            {"REX2 F2 selects NOP", repeat_f2, sizeof(repeat_f2), 4u},
            {"REX2 F3 selects NOP", repeat_f3, sizeof(repeat_f3), 4u}
        };
        size_t index;

        for (index = 0u;
             index < sizeof(nop_cases) / sizeof(nop_cases[0]);
             ++index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                nop_cases[index].code, nop_cases[index].size,
                &apx, &decoded_size);

            check_nop(nop_cases[index].label, &instruction,
                decoded_size, nop_cases[index].size, 0,
                nop_cases[index].operand_size, 3u, 1u);
        }
    }

    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            address_67, sizeof(address_67), &both, &decoded_size);

        check_cldemote("REX2 67 remains CLDEMOTE", &instruction,
            decoded_size, sizeof(address_67), 3u, 1u);
        instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            segment_fs, sizeof(segment_fs), &both, &decoded_size);
        check_cldemote("REX2 segment remains CLDEMOTE", &instruction,
            decoded_size, sizeof(segment_fs), 3u, 1u);
    }

    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            nop_memory, sizeof(nop_memory), &apx, &decoded_size);

        check_nop("REX2 memory NOP needs APX only", &instruction,
            decoded_size, sizeof(nop_memory), 0, 4u, 2u, 1u);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R17D);
        instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            nop_register, sizeof(nop_register), &apx, &decoded_size);
        check_nop("REX2 register NOP", &instruction,
            decoded_size, sizeof(nop_register), 1, 8u, 2u, 1u);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R17);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R16);
    }

    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
            canonical, sizeof(canonical), &both, &decoded_size);

        check_cldemote("Diamond Rapids REX2", &instruction,
            decoded_size, sizeof(canonical), 2u, 1u);
        expect_error("Granite has CLDEMOTE but not APX",
            CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64,
            canonical, sizeof(canonical), &both,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("Sapphire has CLDEMOTE but not APX",
            CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
            canonical, sizeof(canonical), &both,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        instruction = decode(
            CDISASM_CPU_APX, CDISASM_MODE_64,
            canonical, sizeof(canonical), &apx, &decoded_size);
        check_nop("APX profile without CLDEMOTE falls back", &instruction,
            decoded_size, sizeof(canonical), 0, 4u, 2u, 1u);
    }
#else
    unsigned int modrm;

    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
        uint8_t code[15];
        size_t size = make_complete_rex2_row((uint8_t)modrm, code);

        expect_error("complete REX2 row OFF", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, size, NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    expect_error("REX2 canonical OFF", CDISASM_CPU_X86,
        CDISASM_MODE_64, canonical, sizeof(canonical), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 memory NOP OFF", CDISASM_CPU_X86,
        CDISASM_MODE_64, nop_memory, sizeof(nop_memory), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 register NOP OFF", CDISASM_CPU_X86,
        CDISASM_MODE_64, nop_register, sizeof(nop_register), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 66 NOP OFF", CDISASM_CPU_X86,
        CDISASM_MODE_64, operand_66, sizeof(operand_66), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 F2 NOP OFF", CDISASM_CPU_X86,
        CDISASM_MODE_64, repeat_f2, sizeof(repeat_f2), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 F3 NOP OFF", CDISASM_CPU_X86,
        CDISASM_MODE_64, repeat_f3, sizeof(repeat_f3), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 67 CLDEMOTE OFF", CDISASM_CPU_X86,
        CDISASM_MODE_64, address_67, sizeof(address_67), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 segment CLDEMOTE OFF", CDISASM_CPU_X86,
        CDISASM_MODE_64, segment_fs, sizeof(segment_fs), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_truncation_and_lock_precedence(void)
{
    static const uint8_t truncated_modrm[] = {0x0f, 0x1c};
    static const uint8_t truncated_sib[] = {0x0f, 0x1c, 0x04};
    static const uint8_t truncated_disp[] = {
        0x0f, 0x1c, 0x05, 0x78, 0x56, 0x34};
    static const uint8_t lock_truncated_sib[] = {
        0xf0, 0x0f, 0x1c, 0x04};
    static const uint8_t lock_complete[] = {
        0xf0, 0x0f, 0x1c, 0x00};
    static const uint8_t mode16_truncated_disp[] = {0x0f, 0x1c, 0x06};
    static const uint8_t rex2_truncated_modrm[] = {0xd5, 0x80, 0x1c};
    static const uint8_t rex2_truncated_sib[] = {
        0xd5, 0x80, 0x1c, 0x04};
    static const uint8_t rex2_lock_complete[] = {
        0xf0, 0xd5, 0x80, 0x1c, 0x00};
    static const struct error_case {
        const char *label;
        const uint8_t *code;
        size_t size;
        cdisasm_status status;
    } cases[] = {
        {"truncated legacy ModRM", truncated_modrm,
         sizeof(truncated_modrm), CDISASM_STATUS_TRUNCATED},
        {"truncated legacy SIB", truncated_sib,
         sizeof(truncated_sib), CDISASM_STATUS_TRUNCATED},
        {"truncated legacy displacement", truncated_disp,
         sizeof(truncated_disp), CDISASM_STATUS_TRUNCATED},
        {"LOCK cannot outrank truncation", lock_truncated_sib,
         sizeof(lock_truncated_sib), CDISASM_STATUS_TRUNCATED},
        {"complete legacy LOCK", lock_complete,
         sizeof(lock_complete), CDISASM_STATUS_INVALID_INSTRUCTION},
        {"truncated REX2 ModRM", rex2_truncated_modrm,
         sizeof(rex2_truncated_modrm), CDISASM_STATUS_TRUNCATED},
        {"truncated REX2 SIB", rex2_truncated_sib,
         sizeof(rex2_truncated_sib), CDISASM_STATUS_TRUNCATED},
        {"complete REX2 LOCK", rex2_lock_complete,
         sizeof(rex2_lock_complete), CDISASM_STATUS_INVALID_INSTRUCTION}
    };
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = cldemote_apx_flags();
#endif

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error(cases[index].label, CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, cases[index].size,
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            cases[index].status);
    }
    expect_error("CPU gate cannot outrank truncation", CDISASM_CPU_8086,
        CDISASM_MODE_16, mode16_truncated_disp,
        sizeof(mode16_truncated_disp),
#if USE_EXTRA_OPCODES
        &flags,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
}

static void test_formatting_and_exact_metadata(void)
{
    static const uint8_t cldemote[] = {0x0f, 0x1c, 0x00};
    static const uint8_t nop_memory[] = {0x0f, 0x1c, 0x08};
    uint32_t decoded_size;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_CLDEMOTE);
#endif
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        cldemote, sizeof(cldemote),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        &decoded_size);

#if USE_EXTRA_OPCODES
    check_cldemote("format CLDEMOTE", &instruction, decoded_size,
        sizeof(cldemote), 0u, 2u);
#else
    check_nop("format fallback NOP", &instruction, decoded_size,
        sizeof(cldemote), 0, 4u, 0u, 2u);
#endif
    EXPECT(instruction.encoding.modrm == UINT8_C(0x00));
    EXPECT(instruction.encoding.sib_offset == 0u);
    EXPECT(instruction.encoding.displacement_size == 0u);

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    {
        char output[80];
        size_t required = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output));

        EXPECT(required == strlen("cldemote [rax]"));
        EXPECT(strcmp(output, "cldemote [rax]") == 0);
        required = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output));
        EXPECT(required == strlen("cldemote (%rax)"));
        EXPECT(strcmp(output, "cldemote (%rax)") == 0);
    }
#endif

    instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        nop_memory, sizeof(nop_memory),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        &decoded_size);
    check_nop("format NOP collision", &instruction, decoded_size,
        sizeof(nop_memory), 0, 4u, 0u, 2u);
#if USE_DISASM_FORMAT
    {
        char output[80];

        cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output));
        EXPECT(strcmp(output, "nop dword ptr [rax], ecx") == 0);
        cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output));
        EXPECT(strcmp(output, "nopl %ecx, (%rax)") == 0);
    }
#endif
}

int main(void)
{
    test_complete_legacy_collision_space();
    test_prefix_partition_and_rex();
    test_cpu_and_runtime_gates();
    test_rex2_promotion();
    test_truncation_and_lock_precedence();
    test_formatting_and_exact_metadata();

    if (failures != 0) {
        fprintf(stderr, "%d CLDEMOTE/NOP collision test(s) failed\n",
            failures);
        return 1;
    }
    puts("x86 CLDEMOTE/NOP collision tests passed "
         "(768 legacy ModRM tuples; 256 REX2 ModRM tuples; "
         "128 REX2 payloads when enabled)");
    return 0;
}
