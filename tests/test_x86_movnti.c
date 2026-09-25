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

_Static_assert(CDISASM_X86_NAME_MOVNTI == UINT16_C(1347),
    "MOVNTI name ID changed");
_Static_assert(CDISASM_X86_GROUP_SSE2 == UINT16_C(20),
    "SSE2 group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_SSE2 == UINT32_C(4),
    "SSE2 decode bit changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update MOVNTI profile sweep for new CPU profiles");

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

static int profile_has_movnti(cdisasm_x86_cpu_id cpu_id)
{
    return cpu_id == CDISASM_CPU_X86
        || (cpu_id >= CDISASM_CPU_PENTIUM_4
            && cpu_id <= CDISASM_CPU_PENTIUM_SILVER_N6000)
        || (cpu_id >= CDISASM_CPU_GRANITE_RAPIDS
            && cpu_id <= CDISASM_CPU_KNIGHTS_MILL);
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags one_bit(cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit_id));
    return flags;
}

static cdisasm_x86_decode_flags movnti_apx_flags(void)
{
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_SSE2);

    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_APX));
    return flags;
}

static cdisasm_x86_reg_id gpr_id(unsigned int index, unsigned int bits)
{
    if (bits == 32u) {
        return index < 16u
            ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_EAX + index)
            : (cdisasm_x86_reg_id)(CDISASM_X86_REG_R16D + index - 16u);
    }
    return index < 16u
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_RAX + index)
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_R16 + index - 16u);
}

static void check_movnti(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    unsigned int bits,
    cdisasm_x86_reg_id expected_source,
    cdisasm_x86_reg_id expected_base,
    cdisasm_x86_reg_id expected_index,
    uint8_t expected_scale,
    uint8_t prefix_size,
    uint8_t opcode_size,
    int expect_apx)
{
    const cdisasm_opcode *memory;
    const cdisasm_opcode *source;

    if (decoded_size != expected_size
        || instruction->last_error_id != CDISASM_STATUS_OK) {
        fprintf(stderr, "%s: got size/status %u/%u, expected %u/0\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction->last_error_id,
            (unsigned int)expected_size);
    }
    EXPECT(decoded_size == expected_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_MOVNTI);
    EXPECT(instruction->form_id == (bits == 64u
        ? UINT16_C(1693) : UINT16_C(1692)));
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_LOCK | CDISASM_PREFIX_OPERAND_SIZE
            | CDISASM_PREFIX_EFFECTIVE_MASK | CDISASM_PREFIX_HLE_MASK))
        == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_SSE2));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == expect_apx);
    EXPECT(instruction->operand_count == 2u);

    memory = &instruction->opcode[0];
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
    EXPECT(memory->reg == CDISASM_X86_REG_NONE);
    EXPECT(memory->base_reg == expected_base);
    EXPECT(memory->index_reg == expected_index);
    EXPECT(memory->scale == expected_scale);
    EXPECT(memory->size == bits / 8u);
    EXPECT(memory->access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(memory->broadcast == CDISASM_X86_BROADCAST_NONE);

    source = &instruction->opcode[1];
    EXPECT(source->type == CDISASM_OPERAND_REGISTER);
    EXPECT(source->reg == expected_source);
    EXPECT(source->base_reg == CDISASM_X86_REG_NONE);
    EXPECT(source->index_reg == CDISASM_X86_REG_NONE);
    EXPECT(source->size == bits / 8u);
    EXPECT(source->access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(source->flags == CDISASM_OPERAND_FLAG_NONE);
    EXPECT(source->broadcast == CDISASM_X86_BROADCAST_NONE);

    EXPECT(instruction->encoding.prefix_size == prefix_size);
    EXPECT(instruction->encoding.opcode_offset == prefix_size);
    EXPECT(instruction->encoding.opcode_size == opcode_size);
    EXPECT(instruction->encoding.modrm_offset
        == (uint8_t)(prefix_size + opcode_size));
    EXPECT((instruction->encoding.modrm & UINT8_C(0xc0))
        != UINT8_C(0xc0));
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
    static const cdisasm_x86_reg_id indexes[] = {
        CDISASM_X86_REG_SI,
        CDISASM_X86_REG_NONE,
        CDISASM_X86_REG_NONE
    };
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_SSE2);
#endif
    static const uint8_t code[] = {0x0f, 0xc3, 0x00};
    size_t index;

    for (index = 0u; index < 3u; ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, modes[index], code, sizeof(code),
#if USE_EXTRA_OPCODES
            &exact,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        check_movnti("canonical MOVNTI", &instruction, decoded_size,
            sizeof(code), 32u, CDISASM_X86_REG_EAX,
            bases[index], indexes[index], index == 0u ? 1u : 0u,
            0u, 2u, 0);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    {
        static const uint8_t qword[] = {0x48, 0x0f, 0xc3, 0x00};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            qword, sizeof(qword),
#if USE_EXTRA_OPCODES
            &exact,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        check_movnti("MOVNTI qword form", &instruction, decoded_size,
            sizeof(qword), 64u, CDISASM_X86_REG_RAX,
            CDISASM_X86_REG_RAX, CDISASM_X86_REG_NONE, 0u, 1u, 2u, 0);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX_W) != 0u);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_prefix_rules_and_order(void)
{
    static const uint8_t osz[] = {0x66, 0x0f, 0xc3, 0x00};
    static const uint8_t repne[] = {0xf2, 0x0f, 0xc3, 0x00};
    static const uint8_t rep[] = {0xf3, 0x0f, 0xc3, 0x00};
    static const uint8_t f2_f3[] = {0xf2, 0xf3, 0x0f, 0xc3, 0x00};
    static const uint8_t f3_f2[] = {0xf3, 0xf2, 0x0f, 0xc3, 0x00};
    static const uint8_t lock[] = {0xf0, 0x0f, 0xc3, 0x00};
    static const uint8_t register_modrm[] = {0x0f, 0xc3, 0xc0};
    static const struct invalid_case {
        const char *label;
        const uint8_t *code;
        size_t size;
    } invalid[] = {
        {"66", osz, sizeof(osz)},
        {"F2", repne, sizeof(repne)},
        {"F3", rep, sizeof(rep)},
        {"F2 F3", f2_f3, sizeof(f2_f3)},
        {"F3 F2", f3_f2, sizeof(f3_f2)},
        {"LOCK", lock, sizeof(lock)},
        {"register ModRM", register_modrm, sizeof(register_modrm)}
    };
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_SSE2);
#endif

    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        static const cdisasm_x86_mode modes[] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
        };
        size_t mode_index;

        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            expect_error(invalid[index].label, CDISASM_CPU_X86,
                modes[mode_index], invalid[index].code, invalid[index].size,
#if USE_EXTRA_OPCODES
                &exact,
#else
                NULL,
#endif
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t addressed[] = {
            0x67, 0x67, 0x64, 0x0f, 0xc3, 0x60, 0x7f
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            addressed, sizeof(addressed), &exact, &decoded_size);

        check_movnti("address and segment prefixes", &instruction,
            decoded_size, sizeof(addressed), 32u, CDISASM_X86_REG_ESP,
            CDISASM_X86_REG_EAX, CDISASM_X86_REG_NONE, 0u, 3u, 2u, 0);
        EXPECT(instruction.opcode[0].segment_reg == CDISASM_X86_REG_FS);
        EXPECT(instruction.opcode[0].imm == UINT64_C(0x7f));
        EXPECT((instruction.opcode_flags
            & (CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT))
            == (CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT));
    }
    {
        static const uint8_t early_rex[] = {
            0x48, 0x67, 0x0f, 0xc3, 0x00
        };
        static const uint8_t late_rex[] = {
            0x67, 0x48, 0x0f, 0xc3, 0x00
        };
        static const uint8_t last_rex_clear[] = {
            0x48, 0x40, 0x0f, 0xc3, 0x00
        };
        static const uint8_t last_rex_set[] = {
            0x40, 0x48, 0x0f, 0xc3, 0x00
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            early_rex, sizeof(early_rex), &exact, &decoded_size);
        check_movnti("REX before address prefix is ineffective",
            &instruction, decoded_size, sizeof(early_rex), 32u,
            CDISASM_X86_REG_EAX, CDISASM_X86_REG_EAX,
            CDISASM_X86_REG_NONE, 0u, 2u, 2u, 0);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX_W) == 0u);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            late_rex, sizeof(late_rex), &exact, &decoded_size);
        check_movnti("REX after address prefix is effective",
            &instruction, decoded_size, sizeof(late_rex), 64u,
            CDISASM_X86_REG_RAX, CDISASM_X86_REG_EAX,
            CDISASM_X86_REG_NONE, 0u, 2u, 2u, 0);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            last_rex_clear, sizeof(last_rex_clear), &exact, &decoded_size);
        check_movnti("last REX clears W", &instruction, decoded_size,
            sizeof(last_rex_clear), 32u, CDISASM_X86_REG_EAX,
            CDISASM_X86_REG_RAX, CDISASM_X86_REG_NONE, 0u, 2u, 2u, 0);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            last_rex_set, sizeof(last_rex_set), &exact, &decoded_size);
        check_movnti("last REX sets W", &instruction, decoded_size,
            sizeof(last_rex_set), 64u, CDISASM_X86_REG_RAX,
            CDISASM_X86_REG_RAX, CDISASM_X86_REG_NONE, 0u, 2u, 2u, 0);
    }
#endif
}

static void test_complete_modrm_space(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_SSE2);
#endif

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        unsigned int modrm;

        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
            uint8_t code[15] = {
                0x0f, 0xc3, (uint8_t)modrm, 0x24, 0x10,
                0x20, 0x30, 0x40, 0x50, 0x60,
                0x70, 0x80, 0x90, 0xa0, 0xb0
            };
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                &exact,
#else
                NULL,
#endif
                &decoded_size);

            if ((modrm & UINT8_C(0xc0)) != UINT8_C(0xc0)) {
#if USE_EXTRA_OPCODES
                EXPECT(decoded_size >= 3u);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVNTI);
                EXPECT(instruction.form_id == UINT16_C(1692));
                EXPECT(instruction.operand_count == 2u);
                EXPECT(instruction.opcode[0].type
                    == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(instruction.opcode[1].reg
                    == gpr_id((modrm >> 3u) & 7u, 32u));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_SSE2));
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            } else {
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
            }
        }
    }
}

static void test_rex_transport(void)
{
    unsigned int payload;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_SSE2);
#endif

    for (payload = 0u; payload < 16u; ++payload) {
        uint8_t code[] = {
            (uint8_t)(UINT8_C(0x40) + payload),
            0x0f, 0xc3, 0x5c, 0x58, 0x7f
        };
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
        {
            const unsigned int bits = (payload & 8u) != 0u ? 64u : 32u;
            const unsigned int source = 3u + ((payload & 4u) != 0u ? 8u : 0u);
            const unsigned int base = (payload & 1u) != 0u ? 8u : 0u;
            const unsigned int index = 3u + ((payload & 2u) != 0u ? 8u : 0u);

            check_movnti("REX W/R/X/B sweep", &instruction, decoded_size,
                sizeof(code), bits, gpr_id(source, bits),
                gpr_id(base, 64u), gpr_id(index, 64u), 2u, 1u, 2u, 0);
            EXPECT(((instruction.opcode_flags & CDISASM_PREFIX_REX_W) != 0u)
                == ((payload & 8u) != 0u));
        }
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t complex32[] = {
            0x46, 0x0f, 0xc3, 0x54, 0x88, 0x20
        };
        static const uint8_t complex64[] = {
            0x4f, 0x0f, 0xc3, 0x64, 0x58, 0xc0
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            complex32, sizeof(complex32), &exact, &decoded_size);

        check_movnti("REX extended dword SIB", &instruction, decoded_size,
            sizeof(complex32), 32u, CDISASM_X86_REG_R10D,
            CDISASM_X86_REG_RAX, CDISASM_X86_REG_R9, 4u, 1u, 2u, 0);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            complex64, sizeof(complex64), &exact, &decoded_size);
        check_movnti("REX extended qword SIB", &instruction, decoded_size,
            sizeof(complex64), 64u, CDISASM_X86_REG_R12,
            CDISASM_X86_REG_R8, CDISASM_X86_REG_R11, 2u, 1u, 2u, 0);
    }
#endif
}

static void test_rex2_transport_and_gates(void)
{
    static const uint8_t canonical[] = {
        0xd5, 0x80, 0xc3, 0x5c, 0x58, 0x7f
    };
    static const uint8_t map0[] = {0xd5, 0x00, 0xc3, 0x00};
    static const uint8_t rex_then_rex2[] = {
        0x48, 0xd5, 0x80, 0xc3, 0x00
    };
    unsigned int payload;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags sse2 = one_bit(
        CDISASM_X86_DECODE_BIT_SSE2);
    cdisasm_x86_decode_flags apx = one_bit(
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags both = movnti_apx_flags();
#endif

    for (payload = UINT8_C(0x80); payload <= UINT8_MAX; ++payload) {
        uint8_t code[] = {
            0xd5, (uint8_t)payload,
            0xc3, 0x5c, 0x58, 0x7f
        };
        uint8_t register_code[] = {
            0xd5, (uint8_t)payload, 0xc3, 0xc0
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            &both,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        {
            const unsigned int bits = (payload & 8u) != 0u ? 64u : 32u;
            const unsigned int source = 3u
                + ((payload & 4u) != 0u ? 8u : 0u)
                + ((payload & 0x40u) != 0u ? 16u : 0u);
            const unsigned int base = ((payload & 1u) != 0u ? 8u : 0u)
                + ((payload & 0x10u) != 0u ? 16u : 0u);
            const unsigned int index = 3u
                + ((payload & 2u) != 0u ? 8u : 0u)
                + ((payload & 0x20u) != 0u ? 16u : 0u);

            check_movnti("REX2 map-1 payload sweep", &instruction,
                decoded_size, sizeof(code), bits, gpr_id(source, bits),
                gpr_id(base, 64u), gpr_id(index, 64u), 2u, 2u, 1u, 1);
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0u);
        }
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        expect_error("REX2 register ModRM sweep", CDISASM_CPU_X86,
            CDISASM_MODE_64, register_code, sizeof(register_code),
#if USE_EXTRA_OPCODES
            &both,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

#if USE_EXTRA_OPCODES
    expect_error("REX2 needs APX runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, canonical, sizeof(canonical), &sse2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 needs SSE2 runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, canonical, sizeof(canonical), &apx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    {
        uint32_t cpu_value;

        for (cpu_value = (uint32_t)CDISASM_CPU_X86;
             cpu_value <= (uint32_t)CDISASM_CPU_LAST;
             ++cpu_value) {
            const cdisasm_x86_cpu_id cpu_id =
                (cdisasm_x86_cpu_id)cpu_value;
            const int has_sse2 = profile_has_movnti(cpu_id);
            const int has_apx = cpu_id == CDISASM_CPU_X86
                || cpu_id == CDISASM_CPU_APX
                || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS;
            cdisasm_x86_decode_flags mask;

            if ((cdisasm_x86_cpu_mode_mask(cpu_id)
                    & CDISASM_X86_MODE_MASK_64) == 0u) {
                continue;
            }
            EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                cpu_id, CDISASM_MODE_64, &mask) == CDISASM_STATUS_OK);
            EXPECT(cdisasm_decode_flags_test_bit(
                &mask, CDISASM_X86_DECODE_BIT_SSE2)
                == (USE_EXTRA_OPCODES && has_sse2));
            EXPECT(cdisasm_decode_flags_test_bit(
                &mask, CDISASM_X86_DECODE_BIT_APX)
                == (USE_EXTRA_OPCODES && has_apx));

            if (!has_sse2) {
                expect_error("REX2 profile without SSE2", cpu_id,
                    CDISASM_MODE_64, canonical, sizeof(canonical),
#if USE_EXTRA_OPCODES
                    &both,
#else
                    NULL,
#endif
                    CDISASM_STATUS_INVALID_INSTRUCTION);
#if USE_EXTRA_OPCODES
            } else if (!has_apx) {
                expect_error("REX2 profile without APX", cpu_id,
                    CDISASM_MODE_64, canonical, sizeof(canonical), &both,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            } else {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    cpu_id, CDISASM_MODE_64, canonical, sizeof(canonical),
                    &both, &decoded_size);

                check_movnti("REX2 APX profile", &instruction,
                    decoded_size, sizeof(canonical), 32u,
                    CDISASM_X86_REG_EBX, CDISASM_X86_REG_RAX,
                    CDISASM_X86_REG_RBX, 2u, 2u, 1u, 1);
#else
            } else {
                expect_error("REX2 profile extras off", cpu_id,
                    CDISASM_MODE_64, canonical, sizeof(canonical), NULL,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            }
        }
    }

    expect_error("REX followed by REX2", CDISASM_CPU_X86,
        CDISASM_MODE_64, rex_then_rex2, sizeof(rex_then_rex2),
#if USE_EXTRA_OPCODES
        &both,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            map0, sizeof(map0),
#if USE_EXTRA_OPCODES
            &both,
#else
            NULL,
#endif
            &decoded_size);

        EXPECT(instruction.name_id != CDISASM_X86_NAME_MOVNTI);
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_SSE2));
    }
    {
        static const cdisasm_x86_mode legacy_modes[] = {
            CDISASM_MODE_16, CDISASM_MODE_32
        };
        size_t index;

        for (index = 0u; index < 2u; ++index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, legacy_modes[index],
                canonical, sizeof(canonical),
#if USE_EXTRA_OPCODES
                &both,
#else
                NULL,
#endif
                &decoded_size);

            EXPECT(instruction.name_id != CDISASM_X86_NAME_MOVNTI);
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_SSE2));
        }
    }
}

static void test_runtime_and_profiles(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const cdisasm_x86_mode_mask mode_bits[] = {
        CDISASM_X86_MODE_MASK_16,
        CDISASM_X86_MODE_MASK_32,
        CDISASM_X86_MODE_MASK_64
    };
    static const uint8_t code[] = {0x0f, 0xc3, 0x00};
    uint32_t cpu_value;
    size_t mode_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_SSE2);
    cdisasm_x86_decode_flags wrong = one_bit(
        CDISASM_X86_DECODE_BIT_APX);

    expect_error("NULL runtime flags", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("wrong runtime family", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &wrong,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    for (cpu_value = (uint32_t)CDISASM_CPU_X86;
         cpu_value <= (uint32_t)CDISASM_CPU_LAST;
         ++cpu_value) {
        const cdisasm_x86_cpu_id cpu_id =
            (cdisasm_x86_cpu_id)cpu_value;
        const int admitted = profile_has_movnti(cpu_id);
        const cdisasm_x86_mode_mask profile_modes =
            cdisasm_x86_cpu_mode_mask(cpu_id);

        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            cdisasm_x86_decode_flags mask;
            cdisasm_status mask_status = cdisasm_x86_cpu_decode_flag_mask(
                cpu_id, modes[mode_index], &mask);

            if ((profile_modes & mode_bits[mode_index]) == 0u) {
                EXPECT(mask_status == CDISASM_STATUS_INVALID_ARGUMENT);
                continue;
            }
            EXPECT(mask_status == CDISASM_STATUS_OK);
            EXPECT(cdisasm_decode_flags_test_bit(
                &mask, CDISASM_X86_DECODE_BIT_SSE2)
                == (USE_EXTRA_OPCODES && admitted));

            if (!admitted) {
                expect_error("profile without SSE2", cpu_id,
                    modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                    &exact,
#else
                    NULL,
#endif
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            } else {
#if USE_EXTRA_OPCODES
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    cpu_id, modes[mode_index], code, sizeof(code),
                    &exact, &decoded_size);
                cdisasm_x86_reg_id base = modes[mode_index]
                        == CDISASM_MODE_16
                    ? CDISASM_X86_REG_BX
                    : (modes[mode_index] == CDISASM_MODE_32
                        ? CDISASM_X86_REG_EAX : CDISASM_X86_REG_RAX);
                cdisasm_x86_reg_id index = modes[mode_index]
                        == CDISASM_MODE_16
                    ? CDISASM_X86_REG_SI : CDISASM_X86_REG_NONE;

                check_movnti("profile with SSE2", &instruction,
                    decoded_size, sizeof(code), 32u,
                    CDISASM_X86_REG_EAX, base, index,
                    modes[mode_index] == CDISASM_MODE_16 ? 1u : 0u,
                    0u, 2u, 0);
#else
                expect_error("SSE2 profile extras off", cpu_id,
                    modes[mode_index], code, sizeof(code), NULL,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            }
        }
    }
}

static void test_truncation(void)
{
    static const uint8_t missing_modrm[] = {0x0f, 0xc3};
    static const uint8_t missing_sib[] = {0x0f, 0xc3, 0x04};
    static const uint8_t missing_disp[] = {
        0x0f, 0xc3, 0x84, 0x24, 0x01, 0x02, 0x03
    };
    static const uint8_t invalid_prefix_missing_sib[] = {
        0x66, 0x0f, 0xc3, 0x04
    };
    static const uint8_t missing_rex2_payload[] = {0xd5};
    static const uint8_t missing_rex2_opcode[] = {0xd5, 0x80};
    static const uint8_t missing_rex2_modrm[] = {0xd5, 0x80, 0xc3};
    static const uint8_t missing_rex2_sib[] = {0xd5, 0x80, 0xc3, 0x04};
    static const uint8_t missing_rex2_disp[] = {
        0xd5, 0x80, 0xc3, 0x84, 0x24, 0x01, 0x02, 0x03
    };
    static const struct truncation_case {
        const char *label;
        const uint8_t *code;
        size_t size;
        int rex2;
    } cases[] = {
        {"missing ModRM", missing_modrm, sizeof(missing_modrm), 0},
        {"missing SIB", missing_sib, sizeof(missing_sib), 0},
        {"missing displacement", missing_disp, sizeof(missing_disp), 0},
        {"invalid prefix cannot outrank truncation",
         invalid_prefix_missing_sib, sizeof(invalid_prefix_missing_sib), 0},
        {"missing REX2 payload", missing_rex2_payload,
         sizeof(missing_rex2_payload), 1},
        {"missing REX2 opcode", missing_rex2_opcode,
         sizeof(missing_rex2_opcode), 1},
        {"missing REX2 ModRM", missing_rex2_modrm,
         sizeof(missing_rex2_modrm), 1},
        {"missing REX2 SIB", missing_rex2_sib,
         sizeof(missing_rex2_sib), 1},
        {"missing REX2 displacement", missing_rex2_disp,
         sizeof(missing_rex2_disp), 1}
    };
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_SSE2);
    cdisasm_x86_decode_flags both = movnti_apx_flags();
#endif

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error(cases[index].label, CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, cases[index].size,
#if USE_EXTRA_OPCODES
            cases[index].rex2 ? &both : &exact,
#else
            NULL,
#endif
            CDISASM_STATUS_TRUNCATED);
    }
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const uint8_t legacy[] = {0x0f, 0xc3, 0x00};
    static const uint8_t complex[] = {
        0x4f, 0x0f, 0xc3, 0x64, 0x58, 0xc0
    };
    static const uint8_t rex2[] = {
        0xd5, 0xff, 0xc3, 0x64, 0x58, 0xc0
    };
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_SSE2);
    cdisasm_x86_decode_flags both = movnti_apx_flags();
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    char output[128];

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_16,
        legacy, sizeof(legacy), &exact, &decoded_size);
    check_movnti("format 16-bit address", &instruction, decoded_size,
        sizeof(legacy), 32u, CDISASM_X86_REG_EAX,
        CDISASM_X86_REG_BX, CDISASM_X86_REG_SI, 1u, 0u, 2u, 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == strlen("movnti dword ptr [bx + si], eax"));
    EXPECT(strcmp(output, "movnti dword ptr [bx + si], eax") == 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output)) == strlen("movnti %eax, (%bx,%si)"));
    EXPECT(strcmp(output, "movnti %eax, (%bx,%si)") == 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        complex, sizeof(complex), &exact, &decoded_size);
    check_movnti("format extended SIB", &instruction, decoded_size,
        sizeof(complex), 64u, CDISASM_X86_REG_R12,
        CDISASM_X86_REG_R8, CDISASM_X86_REG_R11, 2u, 1u, 2u, 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output))
        == strlen("movnti qword ptr [r8 + r11*2 - 0x40], r12"));
    EXPECT(strcmp(output,
        "movnti qword ptr [r8 + r11*2 - 0x40], r12") == 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output))
        == strlen("movnti %r12, -0x40(%r8,%r11,2)"));
    EXPECT(strcmp(output, "movnti %r12, -0x40(%r8,%r11,2)") == 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), &both, &decoded_size);
    check_movnti("format REX2 EGPR", &instruction, decoded_size,
        sizeof(rex2), 64u, CDISASM_X86_REG_R28,
        CDISASM_X86_REG_R24, CDISASM_X86_REG_R27, 2u, 2u, 1u, 1);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output))
        == strlen("movnti qword ptr [r24 + r27*2 - 0x40], r28"));
    EXPECT(strcmp(output,
        "movnti qword ptr [r24 + r27*2 - 0x40], r28") == 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output))
        == strlen("movnti %r28, -0x40(%r24,%r27,2)"));
    EXPECT(strcmp(output, "movnti %r28, -0x40(%r24,%r27,2)") == 0);
#endif
}

int main(void)
{
    test_forms_and_modes();
    test_prefix_rules_and_order();
    test_complete_modrm_space();
    test_rex_transport();
    test_rex2_transport_and_gates();
    test_runtime_and_profiles();
    test_truncation();
    test_formatting();

    if (failures != 0) {
        fprintf(stderr, "%d MOVNTI test(s) failed\n", failures);
        return 1;
    }
    puts("x86 MOVNTI tests passed "
         "(768 ModRM controls; 16 REX and 256 REX2 controls)");
    return 0;
}
