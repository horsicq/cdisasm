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

_Static_assert(CDISASM_X86_NAME_CLAC == UINT16_C(1262),
    "CLAC name ID changed");
_Static_assert(CDISASM_X86_NAME_STAC == UINT16_C(1445),
    "STAC name ID changed");
_Static_assert(CDISASM_X86_GROUP_SMAP == UINT16_C(306),
    "SMAP group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_SMAP == UINT32_C(253),
    "SMAP decode bit changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update SMAP profile sweep for new CPU profiles");

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

static int profile_has_smap(cdisasm_x86_cpu_id cpu_id)
{
    switch (cpu_id) {
        case CDISASM_CPU_X86:
        case CDISASM_CPU_BROADWELL:
        case CDISASM_CPU_SKYLAKE:
        case CDISASM_CPU_GOLDMONT:
        case CDISASM_CPU_AMD_ZEN:
        case CDISASM_CPU_SKYLAKE_SP:
        case CDISASM_CPU_ICE_LAKE:
        case CDISASM_CPU_TIGER_LAKE:
        case CDISASM_CPU_ALDER_LAKE:
        case CDISASM_CPU_AMD_ZEN_4:
        case CDISASM_CPU_SAPPHIRE_RAPIDS:
        case CDISASM_CPU_AVX10:
        case CDISASM_CPU_APX:
        case CDISASM_CPU_CELERON_G3900:
        case CDISASM_CPU_CELERON_N3350:
        case CDISASM_CPU_CELERON_N4020:
        case CDISASM_CPU_CELERON_G5900:
        case CDISASM_CPU_PENTIUM_SILVER_N6000:
        case CDISASM_CPU_GRANITE_RAPIDS:
        case CDISASM_CPU_ARROW_LAKE:
        case CDISASM_CPU_DIAMOND_RAPIDS:
            return 1;
        default:
            return 0;
    }
}

static int profile_has_apx(cdisasm_x86_cpu_id cpu_id)
{
    return cpu_id == CDISASM_CPU_X86
        || cpu_id == CDISASM_CPU_APX
        || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS;
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags one_bit(cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit_id));
    return flags;
}

static cdisasm_x86_decode_flags smap_apx_flags(void)
{
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_SMAP);

    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_APX));
    return flags;
}

static void check_smap(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    uint8_t fixed,
    uint8_t prefix_size,
    uint8_t opcode_size,
    int expect_apx)
{
    const cdisasm_x86_name_id name_id = fixed == UINT8_C(0xca)
        ? CDISASM_X86_NAME_CLAC : CDISASM_X86_NAME_STAC;
    const cdisasm_x86_form_id form_id = fixed == UINT8_C(0xca)
        ? UINT16_C(707) : UINT16_C(3158);

    if (decoded_size != expected_size
        || instruction->last_error_id != CDISASM_STATUS_OK) {
        fprintf(stderr, "%s: got size/status %u/%u, expected %u/0\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction->last_error_id,
            (unsigned int)expected_size);
    }
    EXPECT(decoded_size == expected_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == name_id);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_PRIVILEGED);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_PREFIX_EFFECTIVE_MASK
            | CDISASM_PREFIX_HLE_MASK)) == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_SMAP));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == expect_apx);
    EXPECT(instruction->operand_count == 0u);
    EXPECT(instruction->encoding.prefix_size == prefix_size);
    EXPECT(instruction->encoding.opcode_offset == prefix_size);
    EXPECT(instruction->encoding.opcode_size == opcode_size);
    EXPECT(instruction->encoding.modrm_offset
        == (uint8_t)(prefix_size + opcode_size));
    EXPECT(instruction->encoding.modrm == fixed);
    EXPECT(instruction->encoding.sib_offset == 0u);
    EXPECT(instruction->encoding.displacement_size == 0u);
    EXPECT(instruction->encoding.immediate_count == 0u);
}

static void check_fred_collision(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    cdisasm_x86_name_id name_id)
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
    EXPECT(instruction->name_id == name_id);
    EXPECT(instruction->form_id == (name_id == CDISASM_X86_NAME_ERETS
        ? UINT16_C(1147) : UINT16_C(1148)));
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_FRED));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_SMAP));
    EXPECT(instruction->name_id != CDISASM_X86_NAME_CLAC);
    EXPECT(instruction->name_id != CDISASM_X86_NAME_STAC);
}
#endif

static void test_forms_modes_and_modrm_ownership(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_SMAP);
#endif

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        unsigned int modrm;

        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
            uint8_t code[15] = {
                0x0f, 0x01, (uint8_t)modrm,
                0x24, 0x10, 0x20, 0x30, 0x40,
                0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0
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

            if (modrm == UINT8_C(0xca) || modrm == UINT8_C(0xcb)) {
#if USE_EXTRA_OPCODES
                check_smap("fixed Group-7 allocation", &instruction,
                    decoded_size, 3u, (uint8_t)modrm, 0u, 2u, 0);
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            } else {
                EXPECT(instruction.name_id != CDISASM_X86_NAME_CLAC);
                EXPECT(instruction.name_id != CDISASM_X86_NAME_STAC);
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_SMAP));
            }
        }
    }
}

static void test_legal_prefixes_and_rex(void)
{
    static const uint8_t prefixes[] = {
        0x67, 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65
    };
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_SMAP);
#endif

    for (index = 0u; index < sizeof(prefixes); ++index) {
        uint8_t code[] = {prefixes[index], 0x0f, 0x01, 0xca};
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
        check_smap("ignored address/segment prefix", &instruction,
            decoded_size, sizeof(code), UINT8_C(0xca), 1u, 2u, 0);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    for (index = 0u; index < 16u; ++index) {
        uint8_t fixed;

        for (fixed = UINT8_C(0xca); fixed <= UINT8_C(0xcb); ++fixed) {
            uint8_t code[] = {
                (uint8_t)(UINT8_C(0x40) + index), 0x0f, 0x01, fixed
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
            check_smap("ignored REX payload", &instruction, decoded_size,
                sizeof(code), fixed, 1u, 2u, 0);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AMD64));
            EXPECT(((instruction.opcode_flags & CDISASM_PREFIX_REX_W) != 0u)
                == ((index & 8u) != 0u));
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static void test_illegal_prefixes_and_fred_collision(void)
{
    static const uint8_t osz[] = {0x66, 0x0f, 0x01, 0xca};
    static const uint8_t lock[] = {0xf0, 0x0f, 0x01, 0xca};
    static const uint8_t repne_cb[] = {0xf2, 0x0f, 0x01, 0xcb};
    static const uint8_t rep_cb[] = {0xf3, 0x0f, 0x01, 0xcb};
    static const uint8_t erets[] = {0xf2, 0x0f, 0x01, 0xca};
    static const uint8_t eretu[] = {0xf3, 0x0f, 0x01, 0xca};
    static const uint8_t f2_f3[] = {0xf2, 0xf3, 0x0f, 0x01, 0xca};
    static const uint8_t f3_f2[] = {0xf3, 0xf2, 0x0f, 0x01, 0xca};
    static const uint8_t osz_erets[] = {
        0x66, 0xf2, 0x0f, 0x01, 0xca
    };
    static const uint8_t rex_eretu[] = {
        0xf3, 0x4f, 0x0f, 0x01, 0xca
    };
    static const uint8_t ineffective_rex[] = {
        0x4f, 0xf2, 0x0f, 0x01, 0xca
    };
    static const uint8_t *const reserved[] = {
        osz, lock, repne_cb, rep_cb
    };
    static const size_t reserved_sizes[] = {
        sizeof(osz), sizeof(lock), sizeof(repne_cb), sizeof(rep_cb)
    };
    static const uint8_t *const fred[] = {
        erets, eretu, f2_f3, f3_f2, osz_erets, rex_eretu, ineffective_rex
    };
    static const size_t fred_sizes[] = {
        sizeof(erets), sizeof(eretu), sizeof(f2_f3), sizeof(f3_f2),
        sizeof(osz_erets), sizeof(rex_eretu), sizeof(ineffective_rex)
    };
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_name_id fred_names[] = {
        CDISASM_X86_NAME_ERETS, CDISASM_X86_NAME_ERETU,
        CDISASM_X86_NAME_ERETU, CDISASM_X86_NAME_ERETS,
        CDISASM_X86_NAME_ERETS, CDISASM_X86_NAME_ERETU,
        CDISASM_X86_NAME_ERETS
    };
#endif
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags all =
        CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;
#endif

    for (index = 0u; index < sizeof(reserved) / sizeof(reserved[0]); ++index) {
        expect_error("reserved SMAP prefix", CDISASM_CPU_X86,
            CDISASM_MODE_64, reserved[index], reserved_sizes[index],
#if USE_EXTRA_OPCODES
            &all,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 0u; index < sizeof(fred) / sizeof(fred[0]); ++index) {
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            fred[index], fred_sizes[index], &all, &decoded_size);

        check_fred_collision("owned FRED collision", &instruction,
            decoded_size, fred_sizes[index], fred_names[index]);
        instruction = decode(
            CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
            fred[index], fred_sizes[index], &all, &decoded_size);
        check_fred_collision("FRED collision on Diamond Rapids",
            &instruction, decoded_size, fred_sizes[index], fred_names[index]);
#else
        expect_error("owned FRED collision", CDISASM_CPU_X86,
            CDISASM_MODE_64, fred[index], fred_sizes[index],
            NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("FRED collision on Diamond Rapids",
            CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
            fred[index], fred_sizes[index],
            NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        expect_error("FRED collision outside FRED profile",
            CDISASM_CPU_APX, CDISASM_MODE_64,
            fred[index], fred_sizes[index],
#if USE_EXTRA_OPCODES
            &all,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
        if (index < 5u) {
            expect_error("FRED collision outside 64-bit mode",
                CDISASM_CPU_X86, CDISASM_MODE_32,
                fred[index], fred_sizes[index],
#if USE_EXTRA_OPCODES
                &all,
#else
                NULL,
#endif
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
}

static void test_cpu_and_runtime_gates(void)
{
    static const uint8_t code[] = {0x0f, 0x01, 0xca};
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint32_t cpu_value;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_SMAP);
    cdisasm_x86_decode_flags system = one_bit(
        CDISASM_X86_DECODE_BIT_SYSTEM);
    cdisasm_x86_decode_flags apx = one_bit(
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags all =
        CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;

    expect_error("NULL runtime mask", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("SYSTEM is not the exact SMAP gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &system,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("APX is not the exact SMAP gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &apx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, sizeof(code), &all, &decoded_size);

        check_smap("all runtime bits", &instruction, decoded_size,
            sizeof(code), UINT8_C(0xca), 0u, 2u, 0);
    }
#endif

    for (cpu_value = (uint32_t)CDISASM_CPU_X86;
         cpu_value <= (uint32_t)CDISASM_CPU_LAST;
         ++cpu_value) {
        const cdisasm_x86_cpu_id cpu_id =
            (cdisasm_x86_cpu_id)cpu_value;
        const int admitted = profile_has_smap(cpu_id);
        size_t mode_index;

        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            cdisasm_x86_decode_flags mask;
            cdisasm_status mask_status = cdisasm_x86_cpu_decode_flag_mask(
                cpu_id, modes[mode_index], &mask);

            if (mask_status == CDISASM_STATUS_INVALID_ARGUMENT) {
                continue;
            }
            EXPECT(mask_status == CDISASM_STATUS_OK);
            EXPECT(cdisasm_decode_flags_test_bit(
                &mask, CDISASM_X86_DECODE_BIT_SMAP)
                == (USE_EXTRA_OPCODES && admitted));
            if (!admitted) {
                expect_error("profile without SMAP", cpu_id,
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

                check_smap("profile with SMAP", &instruction,
                    decoded_size, sizeof(code), UINT8_C(0xca), 0u, 2u, 0);
#else
                expect_error("SMAP profile extras off", cpu_id,
                    modes[mode_index], code, sizeof(code), NULL,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            }
        }
    }
}

static void test_rex2_transport_and_gates(void)
{
    static const uint8_t canonical[] = {0xd5, 0x80, 0x01, 0xca};
    static const uint8_t rex_then_rex2[] = {
        0x48, 0xd5, 0x80, 0x01, 0xca
    };
    static const uint8_t erets[] = {
        0xf2, 0xd5, 0xff, 0x01, 0xca
    };
    static const uint8_t eretu[] = {
        0xf3, 0xd5, 0x80, 0x01, 0xca
    };
    unsigned int payload;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags smap = one_bit(
        CDISASM_X86_DECODE_BIT_SMAP);
    cdisasm_x86_decode_flags apx = one_bit(
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags both = smap_apx_flags();
#endif

    for (payload = UINT8_C(0x80); payload <= UINT8_MAX; ++payload) {
        uint8_t fixed;

        for (fixed = UINT8_C(0xca); fixed <= UINT8_C(0xcb); ++fixed) {
            uint8_t code[] = {
                0xd5, (uint8_t)payload, 0x01, fixed
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
            check_smap("REX2 map-1 payload sweep", &instruction,
                decoded_size, sizeof(code), fixed, 2u, 1u, 1);
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0u);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AMD64));
            EXPECT(((instruction.opcode_flags & CDISASM_PREFIX_REX_W) != 0u)
                == ((payload & 8u) != 0u));
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }

    for (payload = 0u; payload < UINT8_C(0x80); ++payload) {
        uint8_t code[] = {0xd5, (uint8_t)payload, 0x01, 0xca};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            &both,
#else
            NULL,
#endif
            &decoded_size);

        EXPECT(instruction.name_id != CDISASM_X86_NAME_CLAC);
        EXPECT(instruction.name_id != CDISASM_X86_NAME_STAC);
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_SMAP));
    }

#if USE_EXTRA_OPCODES
    expect_error("REX2 needs APX runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, canonical, sizeof(canonical), &smap,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 needs SMAP runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, canonical, sizeof(canonical), &apx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    expect_error("REX plus REX2 is invalid", CDISASM_CPU_X86,
        CDISASM_MODE_64, rex_then_rex2, sizeof(rex_then_rex2),
#if USE_EXTRA_OPCODES
        &both,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("REX2 SMAP on a non-APX profile", CDISASM_CPU_BROADWELL,
        CDISASM_MODE_64, canonical, sizeof(canonical),
#if USE_EXTRA_OPCODES
        &both,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
#if USE_EXTRA_OPCODES
    {
        cdisasm_x86_decode_flags all =
            CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            erets, sizeof(erets), &all, &decoded_size);

        check_fred_collision("REX2 ERETS remains owned", &instruction,
            decoded_size, sizeof(erets), CDISASM_X86_NAME_ERETS);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            eretu, sizeof(eretu), &all, &decoded_size);
        check_fred_collision("REX2 ERETU remains owned", &instruction,
            decoded_size, sizeof(eretu), CDISASM_X86_NAME_ERETU);
    }
#else
    expect_error("REX2 ERETS remains owned", CDISASM_CPU_X86,
        CDISASM_MODE_64, erets, sizeof(erets), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 ERETU remains owned", CDISASM_CPU_X86,
        CDISASM_MODE_64, eretu, sizeof(eretu), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    {
        static const cdisasm_x86_cpu_id profiles[] = {
            CDISASM_CPU_X86, CDISASM_CPU_APX,
            CDISASM_CPU_DIAMOND_RAPIDS
        };
        size_t index;

        for (index = 0u; index < sizeof(profiles) / sizeof(profiles[0]);
             ++index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                profiles[index], CDISASM_MODE_64,
                canonical, sizeof(canonical),
#if USE_EXTRA_OPCODES
                &both,
#else
                NULL,
#endif
                &decoded_size);

            EXPECT(profile_has_smap(profiles[index]));
            EXPECT(profile_has_apx(profiles[index]));
#if USE_EXTRA_OPCODES
            check_smap("REX2 admitted profile", &instruction,
                decoded_size, sizeof(canonical), UINT8_C(0xca), 2u, 1u, 1);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static void test_truncation_and_length(void)
{
    static const uint8_t escape[] = {0x0f};
    static const uint8_t missing_modrm[] = {0x0f, 0x01};
    static const uint8_t bad_prefix_missing_modrm[] = {0x66, 0x0f, 0x01};
    static const uint8_t rex2_payload[] = {0xd5};
    static const uint8_t rex2_opcode[] = {0xd5, 0x80};
    static const uint8_t rex2_modrm[] = {0xd5, 0x80, 0x01};
    static const uint8_t *const cases[] = {
        escape, missing_modrm, bad_prefix_missing_modrm,
        rex2_payload, rex2_opcode, rex2_modrm
    };
    static const size_t sizes[] = {
        sizeof(escape), sizeof(missing_modrm),
        sizeof(bad_prefix_missing_modrm), sizeof(rex2_payload),
        sizeof(rex2_opcode), sizeof(rex2_modrm)
    };
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags both = smap_apx_flags();
#endif

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error("truncated fixed allocation", CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index], sizes[index],
#if USE_EXTRA_OPCODES
            &both,
#else
            NULL,
#endif
            CDISASM_STATUS_TRUNCATED);
    }

    {
        static const uint8_t trailing[] = {0x0f, 0x01, 0xcb, 0x90};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            trailing, sizeof(trailing),
#if USE_EXTRA_OPCODES
            &both,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        check_smap("trailing byte excluded", &instruction, decoded_size,
            3u, UINT8_C(0xcb), 0u, 2u, 0);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const uint8_t clac[] = {0x0f, 0x01, 0xca};
    static const uint8_t stac[] = {0x0f, 0x01, 0xcb};
    static const char *const lowercase[] = {"clac", "stac"};
    static const char *const uppercase[] = {"CLAC", "STAC"};
    static const uint8_t *const codes[] = {clac, stac};
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_SMAP);
    size_t index;

    for (index = 0u; index < 2u; ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            codes[index], 3u, &exact, &decoded_size);
        char output[16];
        char tiny[3] = {'x', 'x', 'x'};
        size_t required;

        check_smap("format fixed SMAP instruction", &instruction,
            decoded_size, 3u, codes[index][2], 0u, 2u, 0);
        required = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output));
        EXPECT(required == strlen(lowercase[index]));
        EXPECT(strcmp(output, lowercase[index]) == 0);
        required = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output));
        EXPECT(required == strlen(lowercase[index]));
        EXPECT(strcmp(output, lowercase[index]) == 0);
        required = cdisasm_x86_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_INTEL
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            output, sizeof(output));
        EXPECT(required == strlen(uppercase[index]));
        EXPECT(strcmp(output, uppercase[index]) == 0);
        EXPECT(cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            NULL, 0u) == strlen(lowercase[index]));
        EXPECT(cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            tiny, sizeof(tiny)) == strlen(lowercase[index]));
        EXPECT(tiny[sizeof(tiny) - 1u] == '\0');
    }
#endif
}

int main(void)
{
    test_forms_modes_and_modrm_ownership();
    test_legal_prefixes_and_rex();
    test_illegal_prefixes_and_fred_collision();
    test_cpu_and_runtime_gates();
    test_rex2_transport_and_gates();
    test_truncation_and_length();
    test_formatting();

    if (failures != 0) {
        fprintf(stderr, "%d SMAP test(s) failed\n", failures);
        return 1;
    }
    puts("x86 SMAP tests passed "
         "(768 Group-7 ModRM controls; 32 REX and 384 REX2 controls)");
    return 0;
}
