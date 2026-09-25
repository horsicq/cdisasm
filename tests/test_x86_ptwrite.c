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

_Static_assert(CDISASM_X86_NAME_PTWRITE == UINT16_C(1380),
    "PTWRITE name ID changed");
_Static_assert(CDISASM_X86_GROUP_PTWRITE == UINT16_C(297),
    "PTWRITE group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_PTWRITE == UINT32_C(244),
    "PTWRITE decode bit changed");

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

static int profile_has_ptwrite(cdisasm_x86_cpu_id cpu_id)
{
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_ALDER_LAKE:
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
        case CDISASM_CPU_AVX10:
        case CDISASM_CPU_APX:
        case CDISASM_CPU_CELERON_N4020:
        case CDISASM_CPU_PENTIUM_SILVER_N6000:
        case CDISASM_CPU_GRANITE_RAPIDS:
        case CDISASM_CPU_ARROW_LAKE:
        case CDISASM_CPU_DIAMOND_RAPIDS:
            return 1;
        default:
            return 0;
    }
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags one_bit(cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit_id));
    return flags;
}

static cdisasm_x86_decode_flags ptwrite_apx_flags(void)
{
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_PTWRITE);

    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_APX));
    return flags;
}

static void check_ptwrite(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    uint8_t expected_type,
    cdisasm_x86_reg_id expected_reg,
    cdisasm_x86_reg_id expected_base,
    uint8_t operand_size,
    uint8_t prefix_size,
    uint8_t opcode_size,
    int expect_apx)
{
    const cdisasm_opcode *operand;

    if (decoded_size != expected_size
        || instruction->last_error_id != CDISASM_STATUS_OK) {
        fprintf(stderr, "%s: got size/status %u/%u, expected %u/0\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction->last_error_id,
            (unsigned int)expected_size);
    }
    EXPECT(decoded_size == expected_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_PTWRITE);
    EXPECT(instruction->form_id == (expected_type == CDISASM_OPERAND_REGISTER
        ? UINT16_C(2438) : UINT16_C(2439)));
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_REP) != 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_LOCK | CDISASM_PREFIX_OPERAND_SIZE
            | CDISASM_PREFIX_EFFECTIVE_MASK | CDISASM_PREFIX_HLE_MASK))
        == 0u);
    EXPECT(instruction->operand_count == 1u);
    operand = &instruction->opcode[0];
    EXPECT(operand->type == expected_type);
    EXPECT(operand->reg == expected_reg);
    EXPECT(operand->base_reg == expected_base);
    EXPECT(operand->size == operand_size);
    EXPECT(operand->access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_PTWRITE));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == expect_apx);
    EXPECT(instruction->encoding.prefix_size == prefix_size);
    EXPECT(instruction->encoding.opcode_offset == prefix_size);
    EXPECT(instruction->encoding.opcode_size == opcode_size);
    EXPECT(instruction->encoding.modrm_offset
        == (uint8_t)(prefix_size + opcode_size));
    EXPECT((instruction->encoding.modrm & UINT8_C(0x38))
        == UINT8_C(0x20));
    EXPECT(instruction->encoding.immediate_count == 0u);
}
#endif

static void test_forms_and_modes(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_reg_id bases[] = {
        CDISASM_X86_REG_BX, CDISASM_X86_REG_EAX, CDISASM_X86_REG_RAX
    };
#endif
    static const uint8_t memory_modrm[] = {0x20, 0x20, 0x20};
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_PTWRITE);
#endif

    for (index = 0u; index < 3u; ++index) {
        static const uint8_t reg[] = {0xf3, 0x0f, 0xae, 0xe0};
        uint8_t memory[] = {0xf3, 0x0f, 0xae, 0x20};
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        memory[3] = memory_modrm[index];
        instruction = decode(CDISASM_CPU_X86, modes[index],
            reg, sizeof(reg),
#if USE_EXTRA_OPCODES
            &exact,
#else
            NULL,
#endif
            &decoded_size);
#if USE_EXTRA_OPCODES
        check_ptwrite("canonical register", &instruction, decoded_size,
            sizeof(reg), CDISASM_OPERAND_REGISTER,
            CDISASM_X86_REG_EAX, CDISASM_X86_REG_NONE, 4u, 1u, 2u, 0);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

        instruction = decode(CDISASM_CPU_X86, modes[index],
            memory, sizeof(memory),
#if USE_EXTRA_OPCODES
            &exact,
#else
            NULL,
#endif
            &decoded_size);
#if USE_EXTRA_OPCODES
        check_ptwrite("canonical memory", &instruction, decoded_size,
            sizeof(memory), CDISASM_OPERAND_MEMORY,
            CDISASM_X86_REG_NONE, bases[index], 4u, 1u, 2u, 0);
        if (modes[index] == CDISASM_MODE_16) {
            EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_SI);
        }
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_rex_and_addressing(void)
{
    static const uint8_t rax[] = {0xf3, 0x48, 0x0f, 0xae, 0xe0};
#if USE_EXTRA_OPCODES
    static const uint8_t r8d[] = {0xf3, 0x41, 0x0f, 0xae, 0xe0};
    static const uint8_t r8_memory[] = {0xf3, 0x41, 0x0f, 0xae, 0x20};
    static const uint8_t rex_r_ignored[] = {0xf3, 0x44, 0x0f, 0xae, 0xe0};
    static const uint8_t early_rex_ignored[] = {0x48, 0xf3, 0x0f, 0xae, 0xe0};
    static const uint8_t qword_memory[] = {0xf3, 0x48, 0x0f, 0xae, 0x20};
    static const uint8_t addressed[] = {
        0x67, 0x64, 0xf3, 0x0f, 0xae, 0x60, 0x7f
    };
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_PTWRITE);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rax, sizeof(rax), &exact, &decoded_size);
    check_ptwrite("REX.W register", &instruction, decoded_size,
        sizeof(rax), CDISASM_OPERAND_REGISTER, CDISASM_X86_REG_RAX,
        CDISASM_X86_REG_NONE, 8u, 2u, 2u, 0);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX_W) != 0u);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        r8d, sizeof(r8d), &exact, &decoded_size);
    check_ptwrite("REX.B register", &instruction, decoded_size,
        sizeof(r8d), CDISASM_OPERAND_REGISTER, CDISASM_X86_REG_R8D,
        CDISASM_X86_REG_NONE, 4u, 2u, 2u, 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        r8_memory, sizeof(r8_memory), &exact, &decoded_size);
    check_ptwrite("REX.B memory base", &instruction, decoded_size,
        sizeof(r8_memory), CDISASM_OPERAND_MEMORY,
        CDISASM_X86_REG_NONE, CDISASM_X86_REG_R8, 4u, 2u, 2u, 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex_r_ignored, sizeof(rex_r_ignored), &exact, &decoded_size);
    check_ptwrite("REX.R opcode extension", &instruction, decoded_size,
        sizeof(rex_r_ignored), CDISASM_OPERAND_REGISTER,
        CDISASM_X86_REG_EAX, CDISASM_X86_REG_NONE, 4u, 2u, 2u, 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        early_rex_ignored, sizeof(early_rex_ignored), &exact, &decoded_size);
    check_ptwrite("REX before F3 is ineffective", &instruction, decoded_size,
        sizeof(early_rex_ignored), CDISASM_OPERAND_REGISTER,
        CDISASM_X86_REG_EAX, CDISASM_X86_REG_NONE, 4u, 2u, 2u, 0);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX_W) == 0u);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        qword_memory, sizeof(qword_memory), &exact, &decoded_size);
    check_ptwrite("REX.W memory", &instruction, decoded_size,
        sizeof(qword_memory), CDISASM_OPERAND_MEMORY,
        CDISASM_X86_REG_NONE, CDISASM_X86_REG_RAX, 8u, 2u, 2u, 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        addressed, sizeof(addressed), &exact, &decoded_size);
    check_ptwrite("address and segment override", &instruction, decoded_size,
        sizeof(addressed), CDISASM_OPERAND_MEMORY,
        CDISASM_X86_REG_NONE, CDISASM_X86_REG_EAX, 4u, 3u, 2u, 0);
    EXPECT(instruction.opcode[0].segment_reg == CDISASM_X86_REG_FS);
    EXPECT(instruction.opcode[0].imm == UINT64_C(0x7f));
    EXPECT((instruction.opcode_flags
        & (CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT))
        == (CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT));
#else
    expect_error("REX.W register extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, rax, sizeof(rax), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_prefixes_and_collisions(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t rightmost_f3[] = {
        0xf2, 0xf3, 0x0f, 0xae, 0xe0
    };
#endif
    static const uint8_t rightmost_f2[] = {
        0xf3, 0xf2, 0x0f, 0xae, 0xe0
    };
#if USE_EXTRA_OPCODES
    static const uint8_t duplicate_f3[] = {
        0xf3, 0xf3, 0x0f, 0xae, 0xe0
    };
#endif
    static const uint8_t osz_before[] = {
        0x66, 0xf3, 0x0f, 0xae, 0xe0
    };
    static const uint8_t osz_after[] = {
        0xf3, 0x66, 0x0f, 0xae, 0xe0
    };
    static const uint8_t lock[] = {0xf0, 0xf3, 0x0f, 0xae, 0xe0};
    static const uint8_t unprefixed_register[] = {0x0f, 0xae, 0xe0};
#if USE_EXTRA_OPCODES
    static const uint8_t unprefixed_memory[] = {0x0f, 0xae, 0x20};
#endif
    static const uint8_t f2_collision[] = {0xf2, 0x0f, 0xae, 0xe0};
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_PTWRITE);
    cdisasm_x86_decode_flags all =
        CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        rightmost_f3, sizeof(rightmost_f3), &exact, &decoded_size);

    check_ptwrite("rightmost F3", &instruction, decoded_size,
        sizeof(rightmost_f3), CDISASM_OPERAND_REGISTER,
        CDISASM_X86_REG_EAX, CDISASM_X86_REG_NONE, 4u, 2u, 2u, 0);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REPNE) != 0u);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EFFECTIVE_MASK) == 0u);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        duplicate_f3, sizeof(duplicate_f3), &exact, &decoded_size);
    check_ptwrite("duplicate F3", &instruction, decoded_size,
        sizeof(duplicate_f3), CDISASM_OPERAND_REGISTER,
        CDISASM_X86_REG_EAX, CDISASM_X86_REG_NONE, 4u, 2u, 2u, 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        unprefixed_memory, sizeof(unprefixed_memory), &all, &decoded_size);
    EXPECT(decoded_size == sizeof(unprefixed_memory));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XSAVE);
    EXPECT(instruction.name_id != CDISASM_X86_NAME_PTWRITE);
#endif

    expect_error("rightmost F2", CDISASM_CPU_X86, CDISASM_MODE_64,
        rightmost_f2, sizeof(rightmost_f2),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("66 before F3", CDISASM_CPU_X86, CDISASM_MODE_64,
        osz_before, sizeof(osz_before),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("66 after F3", CDISASM_CPU_X86, CDISASM_MODE_64,
        osz_after, sizeof(osz_after),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("LOCK", CDISASM_CPU_X86, CDISASM_MODE_64,
        lock, sizeof(lock),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("unprefixed register collision", CDISASM_CPU_X86,
        CDISASM_MODE_64, unprefixed_register, sizeof(unprefixed_register),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("F2 /4 collision", CDISASM_CPU_X86, CDISASM_MODE_64,
        f2_collision, sizeof(f2_collision),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_modrm_ownership(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags all =
        CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;
#endif

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        unsigned int modrm;

        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
            uint8_t code[15] = {
                0xf3, 0x0f, 0xae, (uint8_t)modrm,
                0x24, 0x10, 0x20, 0x30, 0x40, 0x50,
                0x60, 0x70, 0x80, 0x90, 0xa0
            };
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                &all,
#else
                NULL,
#endif
                &decoded_size);
            const int is_ptwrite = (modrm & UINT8_C(0x38))
                == UINT8_C(0x20);

            if (is_ptwrite) {
#if USE_EXTRA_OPCODES
                EXPECT(decoded_size >= 4u);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == CDISASM_X86_NAME_PTWRITE);
                EXPECT(instruction.form_id == ((modrm & UINT8_C(0xc0))
                        == UINT8_C(0xc0)
                    ? UINT16_C(2438) : UINT16_C(2439)));
                EXPECT(instruction.operand_count == 1u);
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            } else if (decoded_size != 0u) {
                EXPECT(instruction.name_id != CDISASM_X86_NAME_PTWRITE);
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_PTWRITE));
            }
        }
    }
}

static void test_rex2(void)
{
    static const uint8_t r16d[] = {0xf3, 0xd5, 0x90, 0xae, 0xe0};
#if USE_EXTRA_OPCODES
    static const uint8_t r24d[] = {0xf3, 0xd5, 0x91, 0xae, 0xe0};
    static const uint8_t r24[] = {0xf3, 0xd5, 0x99, 0xae, 0xe0};
    static const uint8_t rex2_r_ignored[] = {
        0xf3, 0xd5, 0x84, 0xae, 0xe0
    };
    static const uint8_t rex2_r4_ignored[] = {
        0xf3, 0xd5, 0xc0, 0xae, 0xe0
    };
    static const uint8_t memory[] = {0xf3, 0xd5, 0x90, 0xae, 0x20};
    static const uint8_t extended_sib[] = {
        0xf3, 0xd5, 0xb0, 0xae, 0x24, 0x18
    };
    static const uint8_t extended_sib_x_x4[] = {
        0xf3, 0xd5, 0xb2, 0xae, 0x24, 0x18
    };
#endif
    static const uint8_t map0[] = {0xf3, 0xd5, 0x10, 0xae, 0xe0};
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_PTWRITE);
    cdisasm_x86_decode_flags apx = one_bit(
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags both = ptwrite_apx_flags();
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        r16d, sizeof(r16d), &both, &decoded_size);
    check_ptwrite("REX2 B4 register", &instruction, decoded_size,
        sizeof(r16d), CDISASM_OPERAND_REGISTER, CDISASM_X86_REG_R16D,
        CDISASM_X86_REG_NONE, 4u, 3u, 1u, 1);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        r24d, sizeof(r24d), &both, &decoded_size);
    check_ptwrite("REX2 B/B4 register", &instruction, decoded_size,
        sizeof(r24d), CDISASM_OPERAND_REGISTER, CDISASM_X86_REG_R24D,
        CDISASM_X86_REG_NONE, 4u, 3u, 1u, 1);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        r24, sizeof(r24), &both, &decoded_size);
    check_ptwrite("REX2 W/B/B4 register", &instruction, decoded_size,
        sizeof(r24), CDISASM_OPERAND_REGISTER, CDISASM_X86_REG_R24,
        CDISASM_X86_REG_NONE, 8u, 3u, 1u, 1);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2_r_ignored, sizeof(rex2_r_ignored), &both, &decoded_size);
    check_ptwrite("REX2 R opcode extension", &instruction, decoded_size,
        sizeof(rex2_r_ignored), CDISASM_OPERAND_REGISTER,
        CDISASM_X86_REG_EAX, CDISASM_X86_REG_NONE, 4u, 3u, 1u, 1);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2_r4_ignored, sizeof(rex2_r4_ignored), &both, &decoded_size);
    check_ptwrite("REX2 R4 opcode extension", &instruction, decoded_size,
        sizeof(rex2_r4_ignored), CDISASM_OPERAND_REGISTER,
        CDISASM_X86_REG_EAX, CDISASM_X86_REG_NONE, 4u, 3u, 1u, 1);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        memory, sizeof(memory), &both, &decoded_size);
    check_ptwrite("REX2 B4 memory", &instruction, decoded_size,
        sizeof(memory), CDISASM_OPERAND_MEMORY, CDISASM_X86_REG_NONE,
        CDISASM_X86_REG_R16, 4u, 3u, 1u, 1);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        extended_sib, sizeof(extended_sib), &both, &decoded_size);
    check_ptwrite("REX2 B4/X4 SIB memory", &instruction, decoded_size,
        sizeof(extended_sib), CDISASM_OPERAND_MEMORY,
        CDISASM_X86_REG_NONE, CDISASM_X86_REG_R16, 4u, 3u, 1u, 1);
    EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_R19);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        extended_sib_x_x4, sizeof(extended_sib_x_x4),
        &both, &decoded_size);
    check_ptwrite("REX2 B4/X/X4 SIB memory", &instruction, decoded_size,
        sizeof(extended_sib_x_x4), CDISASM_OPERAND_MEMORY,
        CDISASM_X86_REG_NONE, CDISASM_X86_REG_R16, 4u, 3u, 1u, 1);
    EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_R27);

    expect_error("REX2 APX runtime gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, r16d, sizeof(r16d), &exact,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 PTWRITE runtime gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, r16d, sizeof(r16d), &apx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 profile APX gate", CDISASM_CPU_ALDER_LAKE,
        CDISASM_MODE_64, r16d, sizeof(r16d), &both,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        r16d, sizeof(r16d), &both, &decoded_size);
    check_ptwrite("REX2 Diamond Rapids", &instruction, decoded_size,
        sizeof(r16d), CDISASM_OPERAND_REGISTER, CDISASM_X86_REG_R16D,
        CDISASM_X86_REG_NONE, 4u, 3u, 1u, 1);
#else
    expect_error("REX2 extras off", CDISASM_CPU_X86, CDISASM_MODE_64,
        r16d, sizeof(r16d), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    expect_error("REX2 map 0 is not PTWRITE", CDISASM_CPU_X86,
        CDISASM_MODE_64, map0, sizeof(map0),
#if USE_EXTRA_OPCODES
        &both,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_runtime_and_profiles(void)
{
    static const uint8_t code[] = {0xf3, 0x0f, 0xae, 0xe0};
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint32_t cpu_value;
    size_t mode_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_PTWRITE);
    cdisasm_x86_decode_flags system =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(
            CDISASM_X86_DECODE_FLAG_SYSTEM);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    expect_error("PTWRITE exact runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &system,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    for (cpu_value = (uint32_t)CDISASM_CPU_X86;
         cpu_value <= (uint32_t)CDISASM_CPU_LAST;
         ++cpu_value) {
        const cdisasm_x86_cpu_id cpu_id =
            (cdisasm_x86_cpu_id)cpu_value;
        const int admitted = profile_has_ptwrite(cpu_id);

        for (mode_index = 0u;
             mode_index < sizeof(modes) / sizeof(modes[0]);
             ++mode_index) {
            cdisasm_x86_decode_flags mask;
            cdisasm_status mask_status = cdisasm_x86_cpu_decode_flag_mask(
                cpu_id, modes[mode_index], &mask);

            /* Pre-386 profiles legitimately reject later architectural
             * modes.  Sweep every mode that the profile itself admits. */
            if (mask_status == CDISASM_STATUS_INVALID_ARGUMENT) {
                continue;
            }

            EXPECT(mask_status == CDISASM_STATUS_OK);
            EXPECT(cdisasm_decode_flags_test_bit(
                &mask, CDISASM_X86_DECODE_BIT_PTWRITE)
                == (USE_EXTRA_OPCODES && admitted));
            if (!admitted) {
                expect_error("rejected PTWRITE profile", cpu_id,
                    modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                    &exact,
#else
                    NULL,
#endif
                    CDISASM_STATUS_INVALID_INSTRUCTION);
                continue;
            }
#if USE_EXTRA_OPCODES
            instruction = decode(cpu_id, modes[mode_index],
                code, sizeof(code), &exact, &decoded_size);
            check_ptwrite("admitted PTWRITE profile", &instruction,
                decoded_size, sizeof(code), CDISASM_OPERAND_REGISTER,
                CDISASM_X86_REG_EAX, CDISASM_X86_REG_NONE,
                4u, 1u, 2u, 0);
#else
            expect_error("PTWRITE extras-off profile", cpu_id,
                modes[mode_index], code, sizeof(code), NULL,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

static void test_truncation(void)
{
    static const uint8_t missing_modrm[] = {0xf3, 0x0f, 0xae};
    static const uint8_t missing_disp[] = {
        0xf3, 0x0f, 0xae, 0xa0, 0x01, 0x02, 0x03
    };
    static const uint8_t missing_rex2_payload[] = {0xf3, 0xd5};
    static const uint8_t missing_rex2_modrm[] = {0xf3, 0xd5, 0x80, 0xae};
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_PTWRITE);
    cdisasm_x86_decode_flags both = ptwrite_apx_flags();
#endif

    expect_error("missing ModRM", CDISASM_CPU_X86, CDISASM_MODE_64,
        missing_modrm, sizeof(missing_modrm),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("missing displacement", CDISASM_CPU_X86, CDISASM_MODE_64,
        missing_disp, sizeof(missing_disp),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("missing REX2 payload", CDISASM_CPU_X86,
        CDISASM_MODE_64, missing_rex2_payload,
        sizeof(missing_rex2_payload),
#if USE_EXTRA_OPCODES
        &both,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("missing REX2 ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, missing_rex2_modrm, sizeof(missing_rex2_modrm),
#if USE_EXTRA_OPCODES
        &both,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const uint8_t reg[] = {0xf3, 0x48, 0x0f, 0xae, 0xe0};
    static const uint8_t memory[] = {0x64, 0xf3, 0x0f, 0xae, 0x60, 0x7f};
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_PTWRITE);
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    char output[96];

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        reg, sizeof(reg), &exact, &decoded_size);
    check_ptwrite("format register", &instruction, decoded_size,
        sizeof(reg), CDISASM_OPERAND_REGISTER, CDISASM_X86_REG_RAX,
        CDISASM_X86_REG_NONE, 8u, 2u, 2u, 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == strlen("ptwrite rax"));
    EXPECT(strcmp(output, "ptwrite rax") == 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output)) == strlen("ptwrite %rax"));
    EXPECT(strcmp(output, "ptwrite %rax") == 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        memory, sizeof(memory), &exact, &decoded_size);
    check_ptwrite("format memory", &instruction, decoded_size,
        sizeof(memory), CDISASM_OPERAND_MEMORY, CDISASM_X86_REG_NONE,
        CDISASM_X86_REG_RAX, 4u, 2u, 2u, 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == strlen("ptwrite dword ptr fs:[rax + 0x7f]"));
    EXPECT(strcmp(output, "ptwrite dword ptr fs:[rax + 0x7f]") == 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output)) == strlen("ptwritel %fs:0x7f(%rax)"));
    EXPECT(strcmp(output, "ptwritel %fs:0x7f(%rax)") == 0);
#endif
}

int main(void)
{
    test_forms_and_modes();
    test_rex_and_addressing();
    test_prefixes_and_collisions();
    test_modrm_ownership();
    test_rex2();
    test_runtime_and_profiles();
    test_truncation();
    test_formatting();

    if (failures != 0) {
        fprintf(stderr, "%d PTWRITE test(s) failed\n", failures);
        return 1;
    }
    puts("x86 PTWRITE tests passed (768 F3/0F/AE ModRM controls)");
    return 0;
}
