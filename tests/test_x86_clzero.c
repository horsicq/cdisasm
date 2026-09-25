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
            fprintf(stderr, "%s:%d: expectation failed: %s\n",            \
                __FILE__, __LINE__, #expression);                            \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_CLZERO == UINT16_C(1264),
    "CLZERO name ID changed");
_Static_assert(CDISASM_X86_GROUP_CLZERO == UINT16_C(266),
    "CLZERO group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_CLZERO == UINT32_C(213),
    "CLZERO decode bit changed");

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

static cdisasm_x86_decode_flags clzero_apx_flags(void)
{
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_CLZERO);

    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_APX));
    return flags;
}

static void check_clzero(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    uint8_t prefix_size,
    uint8_t opcode_size,
    int expect_apx)
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
    EXPECT(instruction->name_id == CDISASM_X86_NAME_CLZERO);
    EXPECT(instruction->form_id == UINT16_C(719));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_CLZERO));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == expect_apx);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_EFFECTIVE_MASK | CDISASM_PREFIX_HLE_MASK)) == 0u);
    EXPECT(instruction->operand_count == 0u);
    EXPECT(instruction->encoding.prefix_size == prefix_size);
    EXPECT(instruction->encoding.opcode_offset == prefix_size);
    EXPECT(instruction->encoding.opcode_size == opcode_size);
    EXPECT(instruction->encoding.modrm_offset == prefix_size + opcode_size);
    EXPECT(instruction->encoding.modrm == UINT8_C(0xfc));
    EXPECT(instruction->encoding.sib_offset == 0u);
    EXPECT(instruction->encoding.displacement_size == 0u);
    EXPECT(instruction->encoding.immediate_count == 0u);
}
#endif

static void test_complete_modrm_ownership(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_CLZERO);
#endif

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        unsigned int modrm;

        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
            uint8_t code[] = {
                0x0f, 0x01, (uint8_t)modrm,
                0x24, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[mode_index],
                code, sizeof(code),
#if USE_EXTRA_OPCODES
                &exact,
#else
                NULL,
#endif
                &decoded_size);

            if (modrm == UINT8_C(0xfc)) {
#if USE_EXTRA_OPCODES
                check_clzero("fixed ModRM allocation", &instruction,
                    decoded_size, 3u, 0u, 2u, 0);
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            } else {
                EXPECT(instruction.name_id != CDISASM_X86_NAME_CLZERO);
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_CLZERO));
                if (decoded_size == 0u) {
                    EXPECT(instruction.last_error_id != CDISASM_STATUS_OK);
                    EXPECT(is_error_only(&instruction,
                        (cdisasm_status)instruction.last_error_id));
                }
            }
        }
    }
}

static void test_redundant_prefixes_and_rex(void)
{
    static const uint8_t no_prefix[] = {0x0f, 0x01, 0xfc};
    static const uint8_t repne[] = {0xf2, 0x0f, 0x01, 0xfc};
    static const uint8_t rep[] = {0xf3, 0x0f, 0x01, 0xfc};
    static const uint8_t operand[] = {0x66, 0x0f, 0x01, 0xfc};
    static const uint8_t address[] = {0x67, 0x0f, 0x01, 0xfc};
    static const uint8_t segment[] = {0x64, 0x0f, 0x01, 0xfc};
    static const uint8_t f2_f3[] = {0xf2, 0xf3, 0x0f, 0x01, 0xfc};
    static const uint8_t f3_f2[] = {0xf3, 0xf2, 0x0f, 0x01, 0xfc};
    static const uint8_t op_f2[] = {0x66, 0xf2, 0x0f, 0x01, 0xfc};
    static const uint8_t f2_op[] = {0xf2, 0x66, 0x0f, 0x01, 0xfc};
    static const struct prefix_case {
        const char *label;
        const uint8_t *code;
        size_t size;
        uint32_t raw_flags;
    } cases[] = {
        {"no prefix", no_prefix, sizeof(no_prefix), 0u},
        {"ignored F2", repne, sizeof(repne), CDISASM_PREFIX_REPNE},
        {"ignored F3", rep, sizeof(rep), CDISASM_PREFIX_REP},
        {"ignored 66", operand, sizeof(operand),
         CDISASM_PREFIX_OPERAND_SIZE},
        {"ignored 67", address, sizeof(address),
         CDISASM_PREFIX_ADDRESS_SIZE},
        {"ignored segment", segment, sizeof(segment),
         CDISASM_PREFIX_SEGMENT},
        {"F2 then F3", f2_f3, sizeof(f2_f3),
         CDISASM_PREFIX_REPNE | CDISASM_PREFIX_REP},
        {"F3 then F2", f3_f2, sizeof(f3_f2),
         CDISASM_PREFIX_REPNE | CDISASM_PREFIX_REP},
        {"66 then F2", op_f2, sizeof(op_f2),
         CDISASM_PREFIX_OPERAND_SIZE | CDISASM_PREFIX_REPNE},
        {"F2 then 66", f2_op, sizeof(f2_op),
         CDISASM_PREFIX_OPERAND_SIZE | CDISASM_PREFIX_REPNE}
    };
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_CLZERO);
#endif

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size,
            &exact, &decoded_size);

        check_clzero(cases[index].label, &instruction, decoded_size,
            cases[index].size,
            (uint8_t)(cases[index].size - sizeof(no_prefix)), 2u, 0);
        EXPECT((instruction.opcode_flags & cases[index].raw_flags)
            == cases[index].raw_flags);
#else
        expect_error(cases[index].label, CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, cases[index].size,
            NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

    for (index = 0u; index < 16u; ++index) {
        uint8_t code[] = {
            (uint8_t)(UINT8_C(0x40) + index), 0x0f, 0x01, 0xfc
        };
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &exact, &decoded_size);

        check_clzero("REX W/R/X/B sweep", &instruction, decoded_size,
            sizeof(code), 1u, 2u, 0);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX) != 0u);
        EXPECT(((instruction.opcode_flags & CDISASM_PREFIX_REX_W) != 0u)
            == ((index & 8u) != 0u));
#else
        expect_error("REX W/R/X/B sweep OFF", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, sizeof(code), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_cpu_and_runtime_gates(void)
{
    static const cdisasm_x86_cpu_id supported_cpus[] = {
        CDISASM_CPU_X86,
        CDISASM_CPU_AMD_ZEN,
        CDISASM_CPU_AMD_ZEN_4
    };
    static const cdisasm_x86_cpu_id rejected_cpus[] = {
        CDISASM_CPU_AMD_V,
        CDISASM_CPU_AMD_BULLDOZER,
        CDISASM_CPU_TIGER_LAKE,
        CDISASM_CPU_APX,
        CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint8_t code[] = {0x0f, 0x01, 0xfc};
    size_t cpu_index;
    size_t mode_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_CLZERO);
    cdisasm_x86_decode_flags wrong = one_bit(
        CDISASM_X86_DECODE_BIT_CLDEMOTE);
    cdisasm_x86_decode_flags system =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_x86_decode_flags exact_system = exact;

    system.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        CDISASM_X86_DECODE_FLAG_SYSTEM;
    exact_system.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        CDISASM_X86_DECODE_FLAG_SYSTEM;
    expect_error("NULL flags", CDISASM_CPU_X86, CDISASM_MODE_64,
        code, sizeof(code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("SYSTEM is not CLZERO", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &system,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("wrong exact bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &wrong,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &exact_system, &decoded_size);

        check_clzero("exact bit plus unrelated family", &instruction,
            decoded_size, sizeof(code), 0u, 2u, 0);
    }
#endif

    for (cpu_index = 0u;
         cpu_index < sizeof(supported_cpus) / sizeof(supported_cpus[0]);
         ++cpu_index) {
        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            cdisasm_x86_decode_flags mask;
            uint32_t decoded_size;
            cdisasm_instruction instruction;

            EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                supported_cpus[cpu_index], modes[mode_index], &mask)
                == CDISASM_STATUS_OK);
            EXPECT(cdisasm_decode_flags_test_bit(
                &mask, CDISASM_X86_DECODE_BIT_CLZERO)
                == USE_EXTRA_OPCODES);
            instruction = decode(
                supported_cpus[cpu_index], modes[mode_index],
                code, sizeof(code),
#if USE_EXTRA_OPCODES
                &exact,
#else
                NULL,
#endif
                &decoded_size);
#if USE_EXTRA_OPCODES
            check_clzero("CLZERO CPU profile", &instruction,
                decoded_size, sizeof(code), 0u, 2u, 0);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(&instruction,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }

    for (cpu_index = 0u;
         cpu_index < sizeof(rejected_cpus) / sizeof(rejected_cpus[0]);
         ++cpu_index) {
        cdisasm_x86_decode_flags mask;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            rejected_cpus[cpu_index], CDISASM_MODE_64, &mask)
            == CDISASM_STATUS_OK);
        EXPECT(!cdisasm_decode_flags_test_bit(
            &mask, CDISASM_X86_DECODE_BIT_CLZERO));
        expect_error("non-CLZERO CPU profile", rejected_cpus[cpu_index],
            CDISASM_MODE_64, code, sizeof(code),
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
    static const uint8_t canonical[] = {0xd5, 0x80, 0x01, 0xfc};
    static const uint8_t prefixed[] = {
        0xf2, 0x66, 0xd5, 0xff, 0x01, 0xfc
    };
    static const uint8_t map0[] = {0xd5, 0x00, 0x01, 0xfc};
    unsigned int payload;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_CLZERO);
    cdisasm_x86_decode_flags apx = one_bit(
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags both = clzero_apx_flags();

    for (payload = UINT8_C(0x80); payload <= UINT8_MAX; ++payload) {
        uint8_t code[] = {0xd5, (uint8_t)payload, 0x01, 0xfc};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &both, &decoded_size);

        check_clzero("REX2 map-1 payload sweep", &instruction,
            decoded_size, sizeof(code), 2u, 1u, 1);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0u);
    }

    expect_error("REX2 needs APX runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, canonical, sizeof(canonical), &exact,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 needs exact runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, canonical, sizeof(canonical), &apx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("Zen lacks APX", CDISASM_CPU_AMD_ZEN,
        CDISASM_MODE_64, canonical, sizeof(canonical), &both,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("Zen 4 lacks APX", CDISASM_CPU_AMD_ZEN_4,
        CDISASM_MODE_64, canonical, sizeof(canonical), &both,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("APX profile lacks CLZERO", CDISASM_CPU_APX,
        CDISASM_MODE_64, canonical, sizeof(canonical), &both,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            prefixed, sizeof(prefixed), &both, &decoded_size);

        check_clzero("redundant prefixes before REX2", &instruction,
            decoded_size, sizeof(prefixed), 4u, 1u, 1);
        EXPECT((instruction.opcode_flags & (CDISASM_PREFIX_REPNE
            | CDISASM_PREFIX_OPERAND_SIZE | CDISASM_PREFIX_REX2))
            == (CDISASM_PREFIX_REPNE | CDISASM_PREFIX_OPERAND_SIZE
                | CDISASM_PREFIX_REX2));
    }
#else
    for (payload = UINT8_C(0x80); payload <= UINT8_MAX; ++payload) {
        uint8_t code[] = {0xd5, (uint8_t)payload, 0x01, 0xfc};

        expect_error("REX2 map-1 payload sweep OFF", CDISASM_CPU_X86,
            CDISASM_MODE_64, code, sizeof(code), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    expect_error("redundant prefixes before REX2 OFF", CDISASM_CPU_X86,
        CDISASM_MODE_64, prefixed, sizeof(prefixed), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

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

            EXPECT(instruction.name_id != CDISASM_X86_NAME_CLZERO);
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_CLZERO));
        }
    }
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

        EXPECT(instruction.name_id != CDISASM_X86_NAME_CLZERO);
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_CLZERO));
    }
}

static void test_invlpg_collision_and_error_precedence(void)
{
    static const uint8_t lock_clzero[] = {0xf0, 0x0f, 0x01, 0xfc};
    static const uint8_t truncated_modrm[] = {0x0f, 0x01};
    static const uint8_t lock_truncated_modrm[] = {0xf0, 0x0f, 0x01};
    static const uint8_t truncated_sib[] = {0x0f, 0x01, 0x3c};
    static const uint8_t truncated_disp[] = {
        0x0f, 0x01, 0xbc, 0x24, 0x78, 0x56, 0x34
    };
    static const uint8_t truncated_rex2_prefix[] = {0xd5};
    static const uint8_t truncated_rex2_modrm[] = {0xd5, 0x80, 0x01};
#if USE_EXTRA_OPCODES
    static const uint8_t invlpg[] = {0x0f, 0x01, 0x38};
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_CLZERO);
    cdisasm_x86_decode_flags system =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_x86_decode_flags both = clzero_apx_flags();
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    system.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        CDISASM_X86_DECODE_FLAG_SYSTEM;
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        invlpg, sizeof(invlpg), &system, &decoded_size);
    EXPECT(decoded_size == sizeof(invlpg));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_INVLPG);
    EXPECT((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
    EXPECT(instruction.operand_count == 1u);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_CLZERO));
#endif

    expect_error("complete LOCK CLZERO", CDISASM_CPU_X86,
        CDISASM_MODE_64, lock_clzero, sizeof(lock_clzero),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("truncated legacy ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, truncated_modrm, sizeof(truncated_modrm),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("LOCK cannot outrank truncation", CDISASM_CPU_X86,
        CDISASM_MODE_64, lock_truncated_modrm,
        sizeof(lock_truncated_modrm),
#if USE_EXTRA_OPCODES
        &exact,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("INVLPG truncated SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64, truncated_sib, sizeof(truncated_sib),
#if USE_EXTRA_OPCODES
        &system,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("INVLPG truncated displacement", CDISASM_CPU_X86,
        CDISASM_MODE_64, truncated_disp, sizeof(truncated_disp),
#if USE_EXTRA_OPCODES
        &system,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated REX2 prefix", CDISASM_CPU_X86,
        CDISASM_MODE_64, truncated_rex2_prefix,
        sizeof(truncated_rex2_prefix),
#if USE_EXTRA_OPCODES
        &both,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated REX2 ModRM", CDISASM_CPU_X86,
        CDISASM_MODE_64, truncated_rex2_modrm,
        sizeof(truncated_rex2_modrm),
#if USE_EXTRA_OPCODES
        &both,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t code[] = {0x0f, 0x01, 0xfc};
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_CLZERO);
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        code, sizeof(code), &exact, &decoded_size);

    check_clzero("format CLZERO", &instruction, decoded_size,
        sizeof(code), 0u, 2u, 0);
#  if USE_DISASM_FORMAT
    {
        char output[80];
        size_t required = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output));

        EXPECT(required == strlen("clzero"));
        EXPECT(strcmp(output, "clzero") == 0);
        required = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output));
        EXPECT(required == strlen("clzero"));
        EXPECT(strcmp(output, "clzero") == 0);
    }
#  endif
#endif
}

int main(void)
{
    test_complete_modrm_ownership();
    test_redundant_prefixes_and_rex();
    test_cpu_and_runtime_gates();
    test_rex2_promotion();
    test_invlpg_collision_and_error_precedence();
    test_formatting();

    if (failures != 0) {
        fprintf(stderr, "%d CLZERO test(s) failed\n", failures);
        return 1;
    }
    puts("x86 CLZERO tests passed "
         "(3 fixed allocations; 765 non-CLZERO ModRM tuples; "
         "128 REX2 payloads)");
    return 0;
}
