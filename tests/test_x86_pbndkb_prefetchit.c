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

_Static_assert(CDISASM_X86_NAME_PBNDKB == UINT16_C(1358),
    "PBNDKB name ID changed");
_Static_assert(CDISASM_X86_NAME_PREFETCHIT0 == UINT16_C(1368),
    "PREFETCHIT0 name ID changed");
_Static_assert(CDISASM_X86_NAME_PREFETCHIT1 == UINT16_C(1369),
    "PREFETCHIT1 name ID changed");
_Static_assert(CDISASM_X86_GROUP_ICACHE_PREFETCH == UINT16_C(276),
    "ICACHE_PREFETCH group ID changed");
_Static_assert(CDISASM_X86_GROUP_PBNDKB == UINT16_C(288),
    "PBNDKB group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_ICACHE_PREFETCH == UINT32_C(223),
    "ICACHE_PREFETCH decode bit changed");
_Static_assert(CDISASM_X86_DECODE_BIT_PBNDKB == UINT32_C(235),
    "PBNDKB decode bit changed");

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

static void check_pbndkb(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    int expect_apx)
{
    EXPECT(decoded_size == expected_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_PBNDKB);
    EXPECT(instruction->form_id == UINT16_C(2039));
    EXPECT(instruction->operand_count == 0u);
    EXPECT((instruction->opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS) == 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_PBNDKB));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == expect_apx);
}

static void check_prefetchit(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    cdisasm_x86_name_id expected_name,
    int expect_apx)
{
    EXPECT(decoded_size == expected_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == expected_name);
    EXPECT(instruction->form_id == (expected_name
        == CDISASM_X86_NAME_PREFETCHIT0 ? UINT16_C(2308)
                                        : UINT16_C(2309)));
    EXPECT(instruction->operand_count == 1u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction->opcode[0].size == 1u);
    EXPECT(instruction->opcode[0].base_reg == CDISASM_X86_REG_RIP);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT((instruction->opcode[0].flags
        & (CDISASM_OPERAND_FLAG_ADDRESS_ONLY
            | CDISASM_OPERAND_FLAG_PC_RELATIVE))
        == (CDISASM_OPERAND_FLAG_ADDRESS_ONLY
            | CDISASM_OPERAND_FLAG_PC_RELATIVE));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_ICACHE_PREFETCH));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == expect_apx);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
}

static void check_prefetchrst2(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size)
{
    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_PREFETCHRST2);
    EXPECT(instruction->form_id == UINT16_C(2311));
    EXPECT(instruction->operand_count == 1u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction->opcode[0].size == 1u);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT((instruction->opcode[0].flags
        & CDISASM_OPERAND_FLAG_ADDRESS_ONLY) != 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_MOVRS));
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
}
#endif

static void check_nop_row(
    const cdisasm_instruction *instruction,
    unsigned reg3,
    int is_register)
{
    cdisasm_x86_form_id expected_form = is_register
        ? (cdisasm_x86_form_id)(UINT16_C(1842) + reg3)
        : (cdisasm_x86_form_id)(UINT16_C(1860) + reg3 - 4u);

    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_NOP);
    EXPECT(instruction->form_id == expected_form);
    EXPECT(instruction->operand_count == 2u);
    EXPECT(instruction->opcode[0].type == (is_register
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_P6));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_ICACHE_PREFETCH));
}

static void test_pbndkb(void)
{
    static const uint8_t canonical[] = {0x0f, 0x01, 0xc7};
    static const uint8_t address_segment[] = {
        0x67, 0x64, 0x0f, 0x01, 0xc7
    };
    static const uint8_t rex[] = {0x4f, 0x0f, 0x01, 0xc7};
    static const uint8_t rex2[] = {0xd5, 0x80, 0x01, 0xc7};
    static const uint8_t lock[] = {0xf0, 0x0f, 0x01, 0xc7};
    static const uint8_t f2[] = {0xf2, 0x0f, 0x01, 0xc7};
    static const uint8_t f3[] = {0xf3, 0x0f, 0x01, 0xc7};
    static const uint8_t osz[] = {0x66, 0x0f, 0x01, 0xc7};
    static const uint8_t truncated[] = {0x0f, 0x01};
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_PBNDKB);
    cdisasm_x86_decode_flags system =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(
            CDISASM_X86_DECODE_FLAG_SYSTEM);
    cdisasm_x86_decode_flags both = two_bits(
        CDISASM_X86_DECODE_BIT_PBNDKB,
        CDISASM_X86_DECODE_BIT_APX);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        canonical, sizeof(canonical), &exact, &decoded_size);
    check_pbndkb(&instruction, decoded_size, sizeof(canonical), 0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        address_segment, sizeof(address_segment), &exact, &decoded_size);
    check_pbndkb(&instruction, decoded_size, sizeof(address_segment), 0);
    EXPECT((instruction.opcode_flags
        & (CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT))
        == (CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex, sizeof(rex), &exact, &decoded_size);
    check_pbndkb(&instruction, decoded_size, sizeof(rex), 0);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX) != 0u);

    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        canonical, sizeof(canonical), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        canonical, sizeof(canonical), &system,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), &both, &decoded_size);
    check_pbndkb(&instruction, decoded_size, sizeof(rex2), 1);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), &exact,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        canonical, sizeof(canonical), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        address_segment, sizeof(address_segment), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex, sizeof(rex), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    expect_error(CDISASM_CPU_X86, CDISASM_MODE_16,
        canonical, sizeof(canonical),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_32,
        canonical, sizeof(canonical),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        canonical, sizeof(canonical),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        lock, sizeof(lock),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        f2, sizeof(f2),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        f3, sizeof(f3),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        osz, sizeof(osz),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated, sizeof(truncated),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
}

static void test_prefetch_row_ownership(void)
{
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_name_id data_names[4] = {
        CDISASM_X86_NAME_PREFETCHNTA,
        CDISASM_X86_NAME_PREFETCHT0,
        CDISASM_X86_NAME_PREFETCHT1,
        CDISASM_X86_NAME_PREFETCHT2
    };
#endif
    unsigned modrm_value;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags all =
        CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;
#endif

    for (modrm_value = 0u; modrm_value <= UINT8_MAX; ++modrm_value) {
        uint8_t code[15] = {
            0x0f, 0x18, (uint8_t)modrm_value,
            0x24, 0x10, 0x20, 0x30, 0x40,
            0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0
        };
        unsigned mod = modrm_value >> 6;
        unsigned reg3 = (modrm_value >> 3) & 7u;
        unsigned rm3 = modrm_value & 7u;
        int is_register = mod == 3u;
        int is_prefetchit = mod == 0u && rm3 == 5u && reg3 >= 6u;
        int is_prefetchrst2 = !is_register && reg3 == 4u;
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            &all,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        EXPECT(decoded_size != 0u);
        if (is_prefetchit) {
            check_prefetchit(&instruction, decoded_size, 7u,
                reg3 == 6u ? CDISASM_X86_NAME_PREFETCHIT1
                           : CDISASM_X86_NAME_PREFETCHIT0,
                0);
        } else if (is_prefetchrst2) {
            check_prefetchrst2(&instruction, decoded_size);
        } else if (!is_register && reg3 < 4u) {
            EXPECT(instruction.name_id == data_names[reg3]);
            EXPECT(instruction.operand_count == 1u);
            EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_SSE));
        } else {
            check_nop_row(&instruction, reg3, is_register);
        }
#else
        if (is_prefetchit || is_prefetchrst2
            || (!is_register && reg3 < 4u)) {
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
        } else {
            EXPECT(decoded_size != 0u);
            check_nop_row(&instruction, reg3, is_register);
        }
#endif
    }
}

static void test_prefetchit_gates_and_prefixes(void)
{
    static const uint8_t it0[] = {
        0x0f, 0x18, 0x3d, 0x78, 0x56, 0x34, 0x12
    };
    static const uint8_t it1[] = {
        0x0f, 0x18, 0x35, 0x78, 0x56, 0x34, 0x12
    };
    static const uint8_t non_rip[] = {0x0f, 0x18, 0x38};
    static const uint8_t asz[] = {
        0x67, 0x0f, 0x18, 0x3d, 0x78, 0x56, 0x34, 0x12
    };
    static const uint8_t prefixed[] = {
        0x66, 0xf3, 0x64, 0x4f, 0x0f, 0x18, 0x3d,
        0x78, 0x56, 0x34, 0x12
    };
    static const uint8_t lock[] = {
        0xf0, 0x0f, 0x18, 0x3d, 0x78, 0x56, 0x34, 0x12
    };
    static const uint8_t rex2[] = {
        0xd5, 0x80, 0x18, 0x3d, 0x78, 0x56, 0x34, 0x12
    };
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_ICACHE_PREFETCH);
    cdisasm_x86_decode_flags hint =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(
            CDISASM_X86_DECODE_FLAG_MEMORY_HINTS);
    cdisasm_x86_decode_flags both = two_bits(
        CDISASM_X86_DECODE_BIT_ICACHE_PREFETCH,
        CDISASM_X86_DECODE_BIT_APX);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        it0, sizeof(it0), &exact, &decoded_size);
    check_prefetchit(&instruction, decoded_size, sizeof(it0),
        CDISASM_X86_NAME_PREFETCHIT0, 0);
    instruction = decode(CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64,
        it1, sizeof(it1), &exact, &decoded_size);
    check_prefetchit(&instruction, decoded_size, sizeof(it1),
        CDISASM_X86_NAME_PREFETCHIT1, 0);
    instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        prefixed, sizeof(prefixed), &exact, &decoded_size);
    check_prefetchit(&instruction, decoded_size, sizeof(prefixed),
        CDISASM_X86_NAME_PREFETCHIT0, 0);
    EXPECT((instruction.opcode_flags
        & (CDISASM_PREFIX_OPERAND_SIZE | CDISASM_PREFIX_REP
            | CDISASM_PREFIX_SEGMENT | CDISASM_PREFIX_REX))
        == (CDISASM_PREFIX_OPERAND_SIZE | CDISASM_PREFIX_REP
            | CDISASM_PREFIX_SEGMENT | CDISASM_PREFIX_REX));

    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        it0, sizeof(it0), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        it0, sizeof(it0), &hint,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    instruction = decode(CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
        it0, sizeof(it0), NULL, &decoded_size);
    EXPECT(decoded_size == sizeof(it0));
    check_nop_row(&instruction, 7u, 0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        non_rip, sizeof(non_rip), NULL, &decoded_size);
    EXPECT(decoded_size == sizeof(non_rip));
    check_nop_row(&instruction, 7u, 0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        asz, sizeof(asz), NULL, &decoded_size);
    EXPECT(decoded_size == sizeof(asz));
    check_nop_row(&instruction, 7u, 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), &both, &decoded_size);
    check_prefetchit(&instruction, decoded_size, sizeof(rex2),
        CDISASM_X86_NAME_PREFETCHIT0, 1);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), &exact,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    (void)prefixed;

    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        it0, sizeof(it0), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64,
        it1, sizeof(it1), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
        it0, sizeof(it0), NULL, &decoded_size);
    EXPECT(decoded_size == sizeof(it0));
    check_nop_row(&instruction, 7u, 0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        asz, sizeof(asz), NULL, &decoded_size);
    EXPECT(decoded_size == sizeof(asz));
    check_nop_row(&instruction, 7u, 0);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        non_rip, sizeof(non_rip), NULL, &decoded_size);
    EXPECT(decoded_size == sizeof(non_rip));
    check_nop_row(&instruction, 7u, 0);
#endif

    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        lock, sizeof(lock),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);

    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_32,
            it0, sizeof(it0), NULL, &decoded_size);

        EXPECT(decoded_size == sizeof(it0));
        check_nop_row(&instruction, 7u, 0);
    }
}

static void test_profile_masks_and_transport(void)
{
    static const uint8_t it0[] = {
        0x0f, 0x18, 0x3d, 0x78, 0x56, 0x34, 0x12
    };
    static const uint8_t truncated_it[] = {
        0x0f, 0x18, 0x3d, 0x78, 0x56, 0x34
    };
    static const uint8_t truncated_pbndkb[] = {0x0f, 0x01};
    cdisasm_x86_decode_flags mask;

#if !USE_EXTRA_OPCODES
    (void)it0;
#endif

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64, &mask)
        == CDISASM_STATUS_OK);
    EXPECT(cdisasm_decode_flags_test_bit(
        &mask, CDISASM_X86_DECODE_BIT_ICACHE_PREFETCH)
        == USE_EXTRA_OPCODES);
    EXPECT(!cdisasm_decode_flags_test_bit(
        &mask, CDISASM_X86_DECODE_BIT_PBNDKB));
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, CDISASM_MODE_64, &mask)
        == CDISASM_STATUS_OK);
    EXPECT(cdisasm_decode_flags_test_bit(
        &mask, CDISASM_X86_DECODE_BIT_ICACHE_PREFETCH)
        == USE_EXTRA_OPCODES);
    EXPECT(cdisasm_decode_flags_test_bit(
        &mask, CDISASM_X86_DECODE_BIT_PBNDKB)
        == USE_EXTRA_OPCODES);

    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_it, sizeof(truncated_it),
#if USE_EXTRA_OPCODES
        &mask,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_pbndkb, sizeof(truncated_pbndkb),
#if USE_EXTRA_OPCODES
        &mask,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);

#if USE_EXTRA_OPCODES
    {
        cdisasm_instruction direct;
        cdisasm_instruction generic;
        uint32_t direct_size;
        uint32_t generic_size;

        direct = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            it0, sizeof(it0), &mask, &direct_size);
        memset(&generic, 0xa5, sizeof(generic));
        generic_size = cdisasm_decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            it0, sizeof(it0), UINT64_C(0x1000), &mask, &generic);
        EXPECT(direct_size == generic_size);
        EXPECT(memcmp(&direct, &generic, sizeof(direct)) == 0);
    }
#endif
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const uint8_t pbndkb[] = {0x0f, 0x01, 0xc7};
    static const uint8_t it0[] = {
        0x0f, 0x18, 0x3d, 0x78, 0x56, 0x34, 0x12
    };
    cdisasm_x86_decode_flags pbndkb_flags = one_bit(
        CDISASM_X86_DECODE_BIT_PBNDKB);
    cdisasm_x86_decode_flags prefetch_flags = one_bit(
        CDISASM_X86_DECODE_BIT_ICACHE_PREFETCH);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    char output[128];

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        pbndkb, sizeof(pbndkb), &pbndkb_flags, &decoded_size);
    check_pbndkb(&instruction, decoded_size, sizeof(pbndkb), 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == strlen("pbndkb"));
    EXPECT(strcmp(output, "pbndkb") == 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        it0, sizeof(it0), &prefetch_flags, &decoded_size);
    check_prefetchit(&instruction, decoded_size, sizeof(it0),
        CDISASM_X86_NAME_PREFETCHIT0, 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output))
        == strlen("prefetchit0 [rip + 0x12345678]"));
    EXPECT(strcmp(output, "prefetchit0 [rip + 0x12345678]") == 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output))
        == strlen("prefetchit0 0x12345678(%rip)"));
    EXPECT(strcmp(output, "prefetchit0 0x12345678(%rip)") == 0);
#endif
}

int main(void)
{
    test_pbndkb();
    test_prefetch_row_ownership();
    test_prefetchit_gates_and_prefixes();
    test_profile_masks_and_transport();
    test_formatting();

    if (failures != 0) {
        fprintf(stderr, "%d PBNDKB/PREFETCHIT test(s) failed\n", failures);
        return 1;
    }
    printf("x86 PBNDKB/PREFETCHIT tests passed "
           "(USE_EXTRA_OPCODES=%d, ModRM tuples=256)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
