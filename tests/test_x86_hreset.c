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

_Static_assert(CDISASM_X86_NAME_HRESET == UINT16_C(1325),
    "HRESET name ID changed");
_Static_assert(CDISASM_X86_GROUP_HRESET == UINT16_C(271),
    "HRESET group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_HRESET == UINT32_C(218),
    "HRESET decode bit changed");

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

static void check_success(
    const char *label,
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    uint8_t immediate,
    uint8_t prefix_size)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu_id, mode, code, size, flags, &decoded_size);

    if (decoded_size != size
        || instruction.last_error_id != CDISASM_STATUS_OK) {
        fprintf(stderr, "%s: got size/status %u/%u, expected %u/0\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id, (unsigned int)size);
    }
    EXPECT(decoded_size == size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_HRESET);
    EXPECT(instruction.form_id == UINT16_C(1319));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_HRESET));
    EXPECT((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
    EXPECT((instruction.opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
    EXPECT((instruction.opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
    EXPECT((instruction.opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REP) != 0u);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EFFECTIVE_MASK) == 0u);
    EXPECT(instruction.operand_count == 1u);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction.opcode[0].size == 1u);
    EXPECT(instruction.opcode[0].imm == immediate);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[0].flags == CDISASM_OPERAND_FLAG_NONE);
    EXPECT(instruction.encoding.prefix_size == prefix_size);
    EXPECT(instruction.encoding.opcode_offset == prefix_size);
    EXPECT(instruction.encoding.opcode_size == 3u);
    EXPECT(instruction.encoding.modrm_offset == prefix_size + 3u);
    EXPECT(instruction.encoding.modrm == UINT8_C(0xc0));
    EXPECT(instruction.encoding.displacement_size == 0u);
    EXPECT(instruction.encoding.immediate_count == 1u);
    EXPECT(instruction.encoding.immediate_offset[0] == prefix_size + 4u);
    EXPECT(instruction.encoding.immediate_size[0] == 1u);
}

#  if USE_DISASM_FORMAT
static void expect_format(
    const cdisasm_instruction *instruction,
    uint32_t syntax,
    const char *expected)
{
    char output[80];
    size_t required = cdisasm_x86_format(
        instruction, syntax, output, sizeof(output));

    if (required != strlen(expected) || strcmp(output, expected) != 0) {
        fprintf(stderr, "formatted as \"%s\", expected \"%s\"\n",
            output, expected);
    }
    EXPECT(required == strlen(expected));
    EXPECT(strcmp(output, expected) == 0);
}
#  endif
#endif

static void test_all_immediates_and_modes(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_HRESET);
#endif

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        unsigned int immediate;

        for (immediate = 0u; immediate <= UINT8_MAX; ++immediate) {
            uint8_t code[] = {
                0xf3, 0x0f, 0x3a, 0xf0, 0xc0, (uint8_t)immediate
            };
#if USE_EXTRA_OPCODES
            check_success("immediate sweep", CDISASM_CPU_X86,
                modes[mode_index], code, sizeof(code), &flags,
                (uint8_t)immediate, 1u);
#else
            expect_error("immediate sweep OFF", CDISASM_CPU_X86,
                modes[mode_index], code, sizeof(code), NULL,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

static void test_complete_modrm_space(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_HRESET);
#endif

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        unsigned int modrm;

        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
            uint8_t code[15] = {0};

            if (modrm == UINT8_C(0xc0)) {
                continue;
            }
            code[0] = UINT8_C(0xf3);
            code[1] = UINT8_C(0x0f);
            code[2] = UINT8_C(0x3a);
            code[3] = UINT8_C(0xf0);
            code[4] = (uint8_t)modrm;
            expect_error("reserved ModRM", CDISASM_CPU_X86,
                modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                &flags,
#else
                NULL,
#endif
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
}

static void test_prefixes_and_formatting(void)
{
    static const uint8_t base[] = {
        0xf3, 0x0f, 0x3a, 0xf0, 0xc0, 0x7f};
    static const uint8_t rex_w[] = {
        0xf3, 0x48, 0x0f, 0x3a, 0xf0, 0xc0, 0x7f};
    static const uint8_t rex_rb[] = {
        0xf3, 0x45, 0x0f, 0x3a, 0xf0, 0xc0, 0x7f};
    static const uint8_t redundant_66[] = {
        0x66, 0xf3, 0x0f, 0x3a, 0xf0, 0xc0, 0x7f};
    static const uint8_t rightmost_f3[] = {
        0xf2, 0xf3, 0x0f, 0x3a, 0xf0, 0xc0, 0x7f};
    static const uint8_t address_override[] = {
        0x67, 0xf3, 0x0f, 0x3a, 0xf0, 0xc0, 0x7f};
    struct prefix_case {
        const char *label;
        const uint8_t *code;
        size_t size;
        uint8_t prefix_size;
    };
    static const struct prefix_case cases[] = {
        {"base", base, sizeof(base), 1u},
        {"REX.W WIG", rex_w, sizeof(rex_w), 2u},
        {"REX.R/B ignored", rex_rb, sizeof(rex_rb), 2u},
        {"redundant 66", redundant_66, sizeof(redundant_66), 2u},
        {"rightmost F3", rightmost_f3, sizeof(rightmost_f3), 2u},
        {"address override", address_override, sizeof(address_override), 2u}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(
            CDISASM_X86_DECODE_BIT_HRESET);

        check_success(cases[index].label, CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, cases[index].size,
            &flags, UINT8_C(0x7f), cases[index].prefix_size);
#else
        expect_error(cases[index].label, CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, cases[index].size,
            NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    {
        static const uint8_t maximum[] = {
            0xf3, 0x0f, 0x3a, 0xf0, 0xc0, 0xff};
        cdisasm_x86_decode_flags flags = one_bit(
            CDISASM_X86_DECODE_BIT_HRESET);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            maximum, sizeof(maximum), &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(maximum));
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            "hreset 0xff");
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            "hreset $0xff");
    }
#endif
}

static void test_malformed_and_truncated(void)
{
    static const uint8_t missing_f3[] = {
        0x0f, 0x3a, 0xf0, 0xc0, 0x01};
    static const uint8_t f2_only[] = {
        0xf2, 0x0f, 0x3a, 0xf0, 0xc0, 0x01};
    static const uint8_t rightmost_f2[] = {
        0xf3, 0xf2, 0x0f, 0x3a, 0xf0, 0xc0, 0x01};
    static const uint8_t lock[] = {
        0xf0, 0xf3, 0x0f, 0x3a, 0xf0, 0xc0, 0x01};
    static const uint8_t rex2[] = {
        0xf3, 0xd5, 0x00, 0x0f, 0x3a, 0xf0, 0xc0, 0x01};
    static const uint8_t fixed_c1[] = {
        0xf3, 0x0f, 0x3a, 0xf0, 0xc1, 0x01};
    static const uint8_t memory_complete[] = {
        0xf3, 0x0f, 0x3a, 0xf0, 0x84, 0x88,
        0x78, 0x56, 0x34, 0x12, 0x01};
    struct invalid_case {
        const char *label;
        const uint8_t *code;
        size_t size;
    };
    static const struct invalid_case invalid_cases[] = {
        {"missing F3", missing_f3, sizeof(missing_f3)},
        {"F2 only", f2_only, sizeof(f2_only)},
        {"rightmost F2", rightmost_f2, sizeof(rightmost_f2)},
        {"LOCK", lock, sizeof(lock)},
        {"REX2", rex2, sizeof(rex2)},
        {"fixed ModRM C1", fixed_c1, sizeof(fixed_c1)},
        {"complete memory payload", memory_complete,
         sizeof(memory_complete)}
    };
    static const uint8_t truncated_opcode[] = {
        0xf3, 0x0f, 0x3a, 0xf0};
    static const uint8_t truncated_immediate[] = {
        0xf3, 0x0f, 0x3a, 0xf0, 0xc0};
    static const uint8_t malformed_prefix_truncated[] = {
        0xf2, 0x0f, 0x3a, 0xf0, 0xc0};
    static const uint8_t malformed_modrm_truncated[] = {
        0xf3, 0x0f, 0x3a, 0xf0, 0xc1};
    static const uint8_t truncated_sib[] = {
        0xf3, 0x0f, 0x3a, 0xf0, 0x04};
    static const uint8_t truncated_displacement[] = {
        0xf3, 0x0f, 0x3a, 0xf0, 0x84, 0x88, 0x78, 0x56, 0x34};
    static const uint8_t lock_truncated[] = {
        0xf0, 0xf3, 0x0f, 0x3a, 0xf0, 0xc0};
    struct truncated_case {
        const char *label;
        const uint8_t *code;
        size_t size;
    };
    static const struct truncated_case truncated_cases[] = {
        {"truncated ModRM", truncated_opcode, sizeof(truncated_opcode)},
        {"truncated immediate", truncated_immediate,
         sizeof(truncated_immediate)},
        {"wrong prefix before truncated immediate", malformed_prefix_truncated,
         sizeof(malformed_prefix_truncated)},
        {"wrong ModRM before truncated immediate", malformed_modrm_truncated,
         sizeof(malformed_modrm_truncated)},
        {"truncated SIB", truncated_sib, sizeof(truncated_sib)},
        {"truncated displacement", truncated_displacement,
         sizeof(truncated_displacement)},
        {"LOCK before truncated immediate", lock_truncated,
         sizeof(lock_truncated)}
    };
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_HRESET);
#endif

    for (index = 0u;
         index < sizeof(invalid_cases) / sizeof(invalid_cases[0]);
         ++index) {
        expect_error(invalid_cases[index].label,
            CDISASM_CPU_X86, CDISASM_MODE_64,
            invalid_cases[index].code, invalid_cases[index].size,
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 0u;
         index < sizeof(truncated_cases) / sizeof(truncated_cases[0]);
         ++index) {
        expect_error(truncated_cases[index].label,
            CDISASM_CPU_X86, CDISASM_MODE_64,
            truncated_cases[index].code, truncated_cases[index].size,
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            CDISASM_STATUS_TRUNCATED);
    }
}

static void test_cpu_and_runtime_gates(void)
{
    static const cdisasm_x86_cpu_id supported[] = {
        CDISASM_CPU_X86,
        CDISASM_CPU_ALDER_LAKE,
        CDISASM_CPU_AVX10,
        CDISASM_CPU_APX,
        CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_ARROW_LAKE,
        CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const cdisasm_x86_cpu_id rejected[] = {
        CDISASM_CPU_ICE_LAKE,
        CDISASM_CPU_TIGER_LAKE,
        CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_CPU_AMD_ZEN_4,
        CDISASM_CPU_KNIGHTS_MILL
    };
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint8_t code[] = {
        0xf3, 0x0f, 0x3a, 0xf0, 0xc0, 0x5a};
    size_t cpu_index;
    size_t mode_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags exact = one_bit(
        CDISASM_X86_DECODE_BIT_HRESET);
    cdisasm_x86_decode_flags system = one_bit(
        CDISASM_X86_DECODE_BIT_SYSTEM);
    cdisasm_x86_decode_flags wrong = one_bit(
        CDISASM_X86_DECODE_BIT_KEYLOCKER);

    expect_error("no exact runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("SYSTEM is not HRESET", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &system,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("wrong exact runtime bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, code, sizeof(code), &wrong,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    for (cpu_index = 0u;
         cpu_index < sizeof(supported) / sizeof(supported[0]);
         ++cpu_index) {
        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            cdisasm_x86_decode_flags mask;

            EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                supported[cpu_index], modes[mode_index], &mask)
                == CDISASM_STATUS_OK);
            EXPECT(cdisasm_decode_flags_test_bit(
                &mask, CDISASM_X86_DECODE_BIT_HRESET)
                == USE_EXTRA_OPCODES);
#if USE_EXTRA_OPCODES
            check_success("supported CPU", supported[cpu_index],
                modes[mode_index], code, sizeof(code), &exact,
                UINT8_C(0x5a), 1u);
#else
            expect_error("supported CPU OFF", supported[cpu_index],
                modes[mode_index], code, sizeof(code), NULL,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
    for (cpu_index = 0u;
         cpu_index < sizeof(rejected) / sizeof(rejected[0]);
         ++cpu_index) {
        cdisasm_x86_decode_flags mask;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            rejected[cpu_index], CDISASM_MODE_64, &mask)
            == CDISASM_STATUS_OK);
        EXPECT(!cdisasm_decode_flags_test_bit(
            &mask, CDISASM_X86_DECODE_BIT_HRESET));
        expect_error("rejected CPU", rejected[cpu_index],
            CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            &exact,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

int main(void)
{
    test_all_immediates_and_modes();
    test_complete_modrm_space();
    test_prefixes_and_formatting();
    test_malformed_and_truncated();
    test_cpu_and_runtime_gates();

    if (failures != 0) {
        fprintf(stderr, "%d HRESET test(s) failed\n", failures);
        return 1;
    }
    puts("x86 HRESET tests passed (768 immediate tuples allocated; "
         "765 fixed-ModRM neighbors reserved)");
    return 0;
}
