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
            if (failures < 32) {                                            \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_PREFETCHRST2 == UINT16_C(1370),
    "PREFETCHRST2 name ID changed");
_Static_assert(CDISASM_X86_NAME_PREFETCHWT1 == UINT16_C(1371),
    "PREFETCHWT1 name ID changed");
_Static_assert(CDISASM_X86_GROUP_MOVRS == UINT16_C(285),
    "MOVRS group ID changed");
_Static_assert(CDISASM_X86_GROUP_PREFETCHWT1 == UINT16_C(295),
    "PREFETCHWT1 group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_MOVRS == UINT32_C(232),
    "MOVRS decode bit changed");
_Static_assert(CDISASM_X86_DECODE_BIT_PREFETCHWT1 == UINT32_C(242),
    "PREFETCHWT1 decode bit changed");

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

static void check_hint(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    cdisasm_x86_name_id expected_name,
    cdisasm_x86_form_id expected_form,
    cdisasm_x86_group_id expected_group,
    int expect_apx)
{
    const cdisasm_opcode *memory;

    EXPECT(decoded_size == expected_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == expected_name);
    EXPECT(instruction->form_id == expected_form);
    EXPECT(instruction->operand_count == 1u);
    memory = &instruction->opcode[0];
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
    EXPECT(memory->size == 1u);
    EXPECT(memory->access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT((memory->flags & CDISASM_OPERAND_FLAG_ADDRESS_ONLY) != 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, expected_group));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == expect_apx);
}
#endif

static void check_memory_nop(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    cdisasm_x86_form_id expected_form)
{
    EXPECT(decoded_size == expected_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_NOP);
    EXPECT(instruction->form_id == expected_form);
    EXPECT(instruction->operand_count == 2u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_P6));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_MOVRS));
}

static void test_prefetchrst2(void)
{
    static const uint8_t canonical[] = {0x0f, 0x18, 0x20};
    static const uint8_t prefixed[] = {
        0xf2, 0x66, 0xf3, 0x64, 0x4f, 0x0f, 0x18, 0x60, 0x7f
    };
    static const uint8_t rex2[] = {0xd5, 0xf0, 0x18, 0x20};
    static const uint8_t register_tuple[] = {0x0f, 0x18, 0xe0};
    static const uint8_t lock[] = {0xf0, 0x0f, 0x18, 0x20};
    static const uint8_t truncated_modrm[] = {0x0f, 0x18};
    static const uint8_t truncated_displacement[] = {
        0x0f, 0x18, 0xa0, 0x01, 0x02, 0x03
    };
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_MOVRS);
    cdisasm_x86_decode_flags umbrella =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(
            CDISASM_X86_DECODE_FLAG_MEMORY_HINTS);
    cdisasm_x86_decode_flags apx = two_bits(
        CDISASM_X86_DECODE_BIT_MOVRS,
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    for (index = 0u; index < sizeof(modes) / sizeof(modes[0]); ++index) {
        instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS, modes[index],
            canonical, sizeof(canonical), &exact, &decoded_size);
        check_hint(&instruction, decoded_size, sizeof(canonical),
            CDISASM_X86_NAME_PREFETCHRST2, UINT16_C(2311),
            CDISASM_X86_GROUP_MOVRS, 0);
    }
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        prefixed, sizeof(prefixed), &exact, &decoded_size);
    check_hint(&instruction, decoded_size, sizeof(prefixed),
        CDISASM_X86_NAME_PREFETCHRST2, UINT16_C(2311),
        CDISASM_X86_GROUP_MOVRS, 0);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R8);
    EXPECT(instruction.opcode[0].segment_reg == CDISASM_X86_REG_FS);
    EXPECT(instruction.opcode[0].imm == UINT64_C(0x7f));
    EXPECT((instruction.opcode_flags
        & (CDISASM_PREFIX_REP | CDISASM_PREFIX_REPNE
            | CDISASM_PREFIX_OPERAND_SIZE | CDISASM_PREFIX_SEGMENT
            | CDISASM_PREFIX_REX))
        == (CDISASM_PREFIX_REP | CDISASM_PREFIX_REPNE
            | CDISASM_PREFIX_OPERAND_SIZE | CDISASM_PREFIX_SEGMENT
            | CDISASM_PREFIX_REX));
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EFFECTIVE_MASK) == 0u);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), &apx, &decoded_size);
    check_hint(&instruction, decoded_size, sizeof(rex2),
        CDISASM_X86_NAME_PREFETCHRST2, UINT16_C(2311),
        CDISASM_X86_GROUP_MOVRS, 1);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R16);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        canonical, sizeof(canonical), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        canonical, sizeof(canonical), &umbrella,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), &exact,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    cdisasm_instruction instruction;
    uint32_t decoded_size;

    (void)prefixed;
    (void)modes;
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        canonical, sizeof(canonical), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        canonical, sizeof(canonical), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    instruction = decode(CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64,
        canonical, sizeof(canonical), NULL, &decoded_size);
    check_memory_nop(&instruction, decoded_size, sizeof(canonical),
        UINT16_C(1860));
    instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        register_tuple, sizeof(register_tuple), NULL, &decoded_size);
    EXPECT(decoded_size == sizeof(register_tuple));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_NOP);
    EXPECT(instruction.form_id == UINT16_C(1846));

    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        lock, sizeof(lock),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_modrm, sizeof(truncated_modrm),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_displacement, sizeof(truncated_displacement),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
}

static void test_prefetchwt1(void)
{
    static const uint8_t canonical[] = {0x0f, 0x0d, 0x10};
    static const uint8_t prefixed[] = {
        0xf2, 0x66, 0xf3, 0x64, 0x4f, 0x0f, 0x0d, 0x50, 0x7f
    };
    static const uint8_t rex2[] = {0xd5, 0xf0, 0x0d, 0x10};
    static const uint8_t register_tuple[] = {0x0f, 0x0d, 0xd0};
    static const uint8_t rex2_register_tuple[] = {0xd5, 0xf0, 0x0d, 0xd0};
    static const uint8_t rex2_prefetch[] = {0xd5, 0x80, 0x0d, 0x00};
    static const uint8_t rex2_prefetchw[] = {0xd5, 0x80, 0x0d, 0x08};
    static const uint8_t lock[] = {0xf0, 0x0f, 0x0d, 0x10};
    static const uint8_t truncated_modrm[] = {0x0f, 0x0d};
    static const uint8_t truncated_displacement[] = {
        0x0f, 0x0d, 0x90, 0x01, 0x02, 0x03
    };
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_PREFETCHWT1);
    cdisasm_x86_decode_flags umbrella =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(
            CDISASM_X86_DECODE_FLAG_MEMORY_HINTS);
    cdisasm_x86_decode_flags apx = two_bits(
        CDISASM_X86_DECODE_BIT_PREFETCHWT1,
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags apx_memory_hints = two_bits(
        CDISASM_X86_DECODE_BIT_APX,
        CDISASM_X86_DECODE_BIT_MEMORY_HINTS);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;

    for (index = 0u; index < sizeof(modes) / sizeof(modes[0]); ++index) {
        instruction = decode(CDISASM_CPU_KNIGHTS_MILL, modes[index],
            canonical, sizeof(canonical), &exact, &decoded_size);
        check_hint(&instruction, decoded_size, sizeof(canonical),
            CDISASM_X86_NAME_PREFETCHWT1, UINT16_C(2315),
            CDISASM_X86_GROUP_PREFETCHWT1, 0);
    }
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        prefixed, sizeof(prefixed), &exact, &decoded_size);
    check_hint(&instruction, decoded_size, sizeof(prefixed),
        CDISASM_X86_NAME_PREFETCHWT1, UINT16_C(2315),
        CDISASM_X86_GROUP_PREFETCHWT1, 0);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R8);
    EXPECT(instruction.opcode[0].segment_reg == CDISASM_X86_REG_FS);
    EXPECT(instruction.opcode[0].imm == UINT64_C(0x7f));
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EFFECTIVE_MASK) == 0u);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), &apx, &decoded_size);
    check_hint(&instruction, decoded_size, sizeof(rex2),
        CDISASM_X86_NAME_PREFETCHWT1, UINT16_C(2315),
        CDISASM_X86_GROUP_PREFETCHWT1, 1);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R16);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2_register_tuple, sizeof(rex2_register_tuple),
        &apx, &decoded_size);
    EXPECT(decoded_size == sizeof(rex2_register_tuple));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_NOP);
    EXPECT(instruction.form_id == UINT16_C(1851));
    EXPECT(instruction.operand_count == 2u);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2_prefetch, sizeof(rex2_prefetch),
        &apx_memory_hints, &decoded_size);
    EXPECT(decoded_size == sizeof(rex2_prefetch));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PREFETCH);
    EXPECT(instruction.operand_count == 1u);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2_prefetchw, sizeof(rex2_prefetchw),
        &apx_memory_hints, &decoded_size);
    EXPECT(decoded_size == sizeof(rex2_prefetchw));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PREFETCHW);
    EXPECT(instruction.operand_count == 1u);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));

    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        canonical, sizeof(canonical), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        canonical, sizeof(canonical), &umbrella,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), &exact,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        canonical, sizeof(canonical), &exact,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    (void)prefixed;
    (void)modes;
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        canonical, sizeof(canonical), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
        canonical, sizeof(canonical), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2_register_tuple, sizeof(rex2_register_tuple), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2_prefetch, sizeof(rex2_prefetch), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2_prefetchw, sizeof(rex2_prefetchw), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    /* The /2 register tuple belongs to the PREFETCH_NOP collision row, not
     * to the memory-only PREFETCHWT1 instruction. */
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            register_tuple, sizeof(register_tuple), NULL, &decoded_size);

        EXPECT(decoded_size == sizeof(register_tuple));
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_NOP);
        EXPECT(instruction.form_id == UINT16_C(1851));
        EXPECT(instruction.operand_count == 2u);
    }

    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        lock, sizeof(lock),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_modrm, sizeof(truncated_modrm),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_displacement, sizeof(truncated_displacement),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
}

static void test_prefetchwt1_modrm_ownership(void)
{
    unsigned int mod;
    unsigned int rm;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags all =
        CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;
#endif

    for (mod = 0u; mod < 4u; ++mod) {
        for (rm = 0u; rm < 8u; ++rm) {
            uint8_t code[15] = {
                0x0f, 0x0d,
                (uint8_t)((mod << 6) | UINT8_C(0x10) | rm),
                0x24, 0x10, 0x20, 0x30, 0x40,
                0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0
            };
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code),
#if USE_EXTRA_OPCODES
                &all,
#else
                NULL,
#endif
                &decoded_size);

            if (mod == 3u) {
                EXPECT(decoded_size == 3u);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == CDISASM_X86_NAME_NOP);
                EXPECT(instruction.form_id == UINT16_C(1851));
                EXPECT(instruction.operand_count == 2u);
                EXPECT(instruction.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                EXPECT(instruction.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_P6));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_PREFETCHWT1));
            }
#if USE_EXTRA_OPCODES
            else {
                check_hint(&instruction, decoded_size, decoded_size,
                    CDISASM_X86_NAME_PREFETCHWT1, UINT16_C(2315),
                    CDISASM_X86_GROUP_PREFETCHWT1, 0);
                EXPECT((instruction.encoding.modrm & UINT8_C(0x38))
                    == UINT8_C(0x10));
            }
#else
            else {
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
            }
#endif
        }
    }
}

static void test_profile_masks_and_formatting(void)
{
    cdisasm_x86_decode_flags mask;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64, &mask)
        == CDISASM_STATUS_OK);
    EXPECT(cdisasm_decode_flags_test_bit(
        &mask, CDISASM_X86_DECODE_BIT_MOVRS) == USE_EXTRA_OPCODES);
    EXPECT(!cdisasm_decode_flags_test_bit(
        &mask, CDISASM_X86_DECODE_BIT_PREFETCHWT1));
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64, &mask)
        == CDISASM_STATUS_OK);
    EXPECT(!cdisasm_decode_flags_test_bit(
        &mask, CDISASM_X86_DECODE_BIT_MOVRS));
    EXPECT(cdisasm_decode_flags_test_bit(
        &mask, CDISASM_X86_DECODE_BIT_PREFETCHWT1) == USE_EXTRA_OPCODES);

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    {
        static const uint8_t rst2[] = {0x0f, 0x18, 0x20};
        static const uint8_t wt1[] = {0x0f, 0x0d, 0x10};
        cdisasm_x86_decode_flags rst2_flags = one_bit(
            CDISASM_X86_DECODE_BIT_MOVRS);
        cdisasm_x86_decode_flags wt1_flags = one_bit(
            CDISASM_X86_DECODE_BIT_PREFETCHWT1);
        cdisasm_instruction instruction;
        uint32_t decoded_size;
        char output[128];

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            rst2, sizeof(rst2), &rst2_flags, &decoded_size);
        check_hint(&instruction, decoded_size, sizeof(rst2),
            CDISASM_X86_NAME_PREFETCHRST2, UINT16_C(2311),
            CDISASM_X86_GROUP_MOVRS, 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output))
            == strlen("prefetchrst2 [rax]"));
        EXPECT(strcmp(output, "prefetchrst2 [rax]") == 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT, output, sizeof(output))
            == strlen("prefetchrst2 (%rax)"));
        EXPECT(strcmp(output, "prefetchrst2 (%rax)") == 0);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            wt1, sizeof(wt1), &wt1_flags, &decoded_size);
        check_hint(&instruction, decoded_size, sizeof(wt1),
            CDISASM_X86_NAME_PREFETCHWT1, UINT16_C(2315),
            CDISASM_X86_GROUP_PREFETCHWT1, 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output))
            == strlen("prefetchwt1 [rax]"));
        EXPECT(strcmp(output, "prefetchwt1 [rax]") == 0);
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT, output, sizeof(output))
            == strlen("prefetchwt1 (%rax)"));
        EXPECT(strcmp(output, "prefetchwt1 (%rax)") == 0);
    }
#endif
}

int main(void)
{
    test_prefetchrst2();
    test_prefetchwt1();
    test_prefetchwt1_modrm_ownership();
    test_profile_masks_and_formatting();

    if (failures != 0) {
        fprintf(stderr, "%d PREFETCHRST2/PREFETCHWT1 test(s) failed\n",
            failures);
        return 1;
    }
    printf("x86 PREFETCHRST2/PREFETCHWT1 tests passed "
           "(USE_EXTRA_OPCODES=%d)\n", USE_EXTRA_OPCODES);
    return 0;
}
