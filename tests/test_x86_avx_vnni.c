#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct avx_vnni_case {
    uint8_t opcode;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} avx_vnni_case;

static const avx_vnni_case avx_vnni_cases[] = {
    {0x50, CDISASM_X86_NAME_VPDPBUSD, "vpdpbusd"},
    {0x51, CDISASM_X86_NAME_VPDPBUSDS, "vpdpbusds"},
    {0x52, CDISASM_X86_NAME_VPDPWSSD, "vpdpwssd"},
    {0x53, CDISASM_X86_NAME_VPDPWSSDS, "vpdpwssds"}
};

_Static_assert(CDISASM_X86_NAME_VPDPBUSD == UINT16_C(715),
    "existing VPDPBUSD ID changed");
_Static_assert(CDISASM_X86_NAME_VPDPBUSDS == UINT16_C(1095)
        && CDISASM_X86_NAME_VPDPWSSD == UINT16_C(1096)
        && CDISASM_X86_NAME_VPDPWSSDS == UINT16_C(1097),
    "AVX-VNNI name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX_VNNI == UINT16_C(83),
    "AVX-VNNI group ID changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI
        == UINT64_C(0x2000000000000000),
    "AVX-VNNI runtime flag changed");
_Static_assert(CDISASM_X86_DECODE_USE_AVX_VNNI
        == CDISASM_X86_DECODE_FLAG_AVX_VNNI,
    "AVX-VNNI runtime alias changed");

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",             \
                __FILE__, __LINE__, #expression);                            \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

static cdisasm_instruction decode(
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *code,
    size_t size,
    cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu, mode, code, size, UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void expect_status(
    const char *label,
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *code,
    size_t size,
    cdisasm_x86_decode_option flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu, mode, code, size, flags, &decoded_size);

    if (decoded_size != 0 || !is_error_only(&instruction, status)) {
        fprintf(stderr,
            "%s: expected status=%u, actual=%u, decoded=%u\n",
            label, (unsigned int)status,
            (unsigned int)instruction.last_error_id,
            (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, status));
}

/* The returned buffer deliberately contains enough zero-filled SIB and
 * displacement bytes for every ModRM value.  The decoder still reports the
 * exact consumed instruction size. */
static void make_encoding(
    const avx_vnni_case *test,
    unsigned int length,
    unsigned int w,
    unsigned int prefix,
    uint8_t modrm,
    uint8_t code[15])
{
    memset(code, 0, 15u);
    code[0] = UINT8_C(0xc4);
    code[1] = UINT8_C(0xe2); /* no extensions, 0F38 map */
    code[2] = (uint8_t)(UINT8_C(0x70)
        | (w != 0u ? UINT8_C(0x80) : UINT8_C(0))
        | (length != 0u ? UINT8_C(0x04) : UINT8_C(0))
        | (uint8_t)prefix);
    code[3] = test->opcode;
    code[4] = modrm;
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id vector_register(
    unsigned int index,
    unsigned int bits)
{
    return (cdisasm_x86_reg_id)(
        (bits == 128u ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0)
        + index);
}
#endif

static void test_exhaustive_modrm_and_w_boundary(void)
{
    size_t case_index;
    unsigned int allocated = 0;
    unsigned int reserved = 0;

    for (case_index = 0;
         case_index < sizeof(avx_vnni_cases) / sizeof(avx_vnni_cases[0]);
         ++case_index) {
        const avx_vnni_case *test = &avx_vnni_cases[case_index];
        unsigned int length;

        for (length = 0; length != 2u; ++length) {
            const unsigned int vector_bits = length == 0u ? 128u : 256u;
            unsigned int modrm;

            (void)vector_bits;

            for (modrm = 0; modrm != 256u; ++modrm) {
                uint8_t code[15];

                make_encoding(test, length, 0u, 1u, (uint8_t)modrm, code);
                ++allocated;
#if USE_EXTRA_OPCODES
                {
                    const unsigned int mod = modrm >> 6;
                    const unsigned int destination = (modrm >> 3) & 7u;
                    const unsigned int rm = modrm & 7u;
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
                        code, sizeof(code),
                        CDISASM_X86_DECODE_FLAG_AVX_VNNI,
                        &decoded_size);

                    EXPECT(decoded_size >= 5u && decoded_size <= 10u);
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id == test->name_id);
                    EXPECT(instruction.operand_count == 3u);
                    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX)
                        != 0);
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX));
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX_VNNI));
                    EXPECT(!cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX512VNNI));
                    EXPECT(instruction.opcode[0].type
                        == CDISASM_OPERAND_REGISTER);
                    EXPECT(instruction.opcode[0].reg
                        == vector_register(destination, vector_bits));
                    EXPECT(instruction.opcode[0].size == vector_bits / 8u);
                    EXPECT(instruction.opcode[0].access
                        == CDISASM_OPERAND_ACCESS_READ_WRITE);
                    EXPECT(instruction.opcode[1].reg
                        == vector_register(1u, vector_bits));
                    EXPECT(instruction.opcode[1].size == vector_bits / 8u);
                    EXPECT(instruction.opcode[1].access
                        == CDISASM_OPERAND_ACCESS_READ);
                    EXPECT(instruction.opcode[2].type
                        == (mod == 3u
                            ? CDISASM_OPERAND_REGISTER
                            : CDISASM_OPERAND_MEMORY));
                    EXPECT(instruction.opcode[2].size == vector_bits / 8u);
                    EXPECT(instruction.opcode[2].access
                        == CDISASM_OPERAND_ACCESS_READ);
                    EXPECT(instruction.opcode[2].broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                    if (mod == 3u) {
                        EXPECT(instruction.opcode[2].reg
                            == vector_register(rm, vector_bits));
                    }
                    EXPECT(instruction.mask_mode == CDISASM_X86_MASK_NONE);
                    EXPECT(instruction.mask_reg == CDISASM_X86_REG_NONE);
                }
#else
                expect_status("extra-opcodes OFF AVX-VNNI encoding",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

                make_encoding(test, length, 1u, 1u, (uint8_t)modrm, code);
                ++reserved;
                expect_status("AVX-VNNI W1 reserved",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }
    }
    EXPECT(allocated == 2048u);
    EXPECT(reserved == 2048u);
}

static void test_adjacent_prefix_ownership(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(avx_vnni_cases) / sizeof(avx_vnni_cases[0]);
         ++case_index) {
        unsigned int length;

        /* Non-66 selectors at opcodes 50/51 are owned by the independent
         * AVX-VNNI-INT8 family.  Only the 52/53 siblings remain unallocated. */
        if (case_index < 2u) {
            continue;
        }

        for (length = 0; length != 2u; ++length) {
            unsigned int prefix;

            for (prefix = 0; prefix != 4u; ++prefix) {
                uint8_t code[15];

                if (prefix == 1u) {
                    continue;
                }
                make_encoding(&avx_vnni_cases[case_index], length, 0u,
                    prefix, UINT8_C(0xc2), code);
                expect_status("non-66 AVX-VNNI opcode52/53 remains unowned",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            }
        }
    }
}

static void test_truncation_and_prefix_rules(void)
{
    uint8_t code[16];
    size_t size;

    make_encoding(&avx_vnni_cases[0], 0u, 0u, 1u,
        UINT8_C(0xc2), code);
    expect_status("empty AVX-VNNI input",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        code, 0u, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_END_OF_INPUT);
    for (size = 1; size != 5u; ++size) {
        expect_status("truncated AVX-VNNI register form",
            CDISASM_CPU_X86, CDISASM_MODE_64,
            code, size, CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_TRUNCATED);
    }

    make_encoding(&avx_vnni_cases[1], 1u, 0u, 1u,
        UINT8_C(0x48), code);
    expect_status("truncated AVX-VNNI disp8",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        code, 5u, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);

    make_encoding(&avx_vnni_cases[2], 0u, 1u, 1u,
        UINT8_C(0xc2), code);
    expect_status("truncated W1 preserves truncation precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        code, 4u, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_TRUNCATED);

    make_encoding(&avx_vnni_cases[3], 0u, 0u, 1u,
        UINT8_C(0xc2), code + 1);
    code[0] = UINT8_C(0x66);
    expect_status("legacy prefix before AVX-VNNI VEX",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        code, 6u, CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

#if USE_EXTRA_OPCODES
static void test_runtime_cpu_and_modes(void)
{
    static const cdisasm_cpu_id supported_cpus[] = {
        CDISASM_CPU_ALDER_LAKE,
        CDISASM_CPU_ARROW_LAKE,
        CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_DIAMOND_RAPIDS,
        CDISASM_CPU_AVX10,
        CDISASM_CPU_APX
    };
    static const cdisasm_cpu_id unsupported_cpus[] = {
        CDISASM_CPU_HASWELL,
        CDISASM_CPU_ICE_LAKE,
        CDISASM_CPU_TIGER_LAKE,
        CDISASM_CPU_AMD_ZEN_4
    };
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint8_t code[15];
    size_t index;

    make_encoding(&avx_vnni_cases[0], 0u, 0u, 1u,
        UINT8_C(0xc2), code);

    for (index = 0;
         index < sizeof(supported_cpus) / sizeof(supported_cpus[0]);
         ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            supported_cpus[index], CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX_VNNI,
            &decoded_size);
        cdisasm_x86_decode_option available =
            cdisasm_x86_cpu_decode_flag_mask(
                supported_cpus[index], CDISASM_MODE_64);

        EXPECT(decoded_size == 5u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPDPBUSD);
        EXPECT((available & CDISASM_X86_DECODE_FLAG_AVX_VNNI) != 0);
    }

    for (index = 0;
         index < sizeof(unsupported_cpus) / sizeof(unsupported_cpus[0]);
         ++index) {
        cdisasm_x86_decode_option available =
            cdisasm_x86_cpu_decode_flag_mask(
                unsupported_cpus[index], CDISASM_MODE_64);

        EXPECT((available & CDISASM_X86_DECODE_FLAG_AVX_VNNI) == 0);
        expect_status("CPU lacks independent AVX-VNNI feature",
            unsupported_cpus[index], CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX_VNNI,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    expect_status("AVX2 selector does not imply AVX-VNNI",
        CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX2,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("AVX selector does not imply AVX-VNNI",
        CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("base selector excludes AVX-VNNI",
        CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    for (index = 0; index < sizeof(modes) / sizeof(modes[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, modes[index], code, sizeof(code),
            CDISASM_X86_DECODE_FLAG_AVX_VNNI, &decoded_size);
        cdisasm_x86_decode_option available =
            cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_X86, modes[index]);

        EXPECT(decoded_size == 5u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPDPBUSD);
        EXPECT((available & CDISASM_X86_DECODE_FLAG_AVX_VNNI) != 0);
    }
}
#endif

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(
    const cdisasm_instruction *instruction,
    uint32_t syntax,
    const char *expected)
{
    char buffer[192];
    size_t length = cdisasm_x86_format(
        instruction, syntax, buffer, sizeof(buffer));

    if (strcmp(buffer, expected) != 0) {
        fprintf(stderr, "format mismatch: expected='%s' actual='%s'\n",
            expected, buffer);
    }
    EXPECT(length == strlen(expected));
    EXPECT(strcmp(buffer, expected) == 0);
}

static void test_formatting(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(avx_vnni_cases) / sizeof(avx_vnni_cases[0]);
         ++case_index) {
        const avx_vnni_case *test = &avx_vnni_cases[case_index];
        uint8_t code[15];
        uint32_t decoded_size;
        char expected[96];
        cdisasm_instruction instruction;

        make_encoding(test, 0u, 0u, 1u, UINT8_C(0xc2), code);
        instruction = decode(
            CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX_VNNI,
            &decoded_size);
        EXPECT(decoded_size == 5u);
        (void)snprintf(expected, sizeof(expected),
            "%s xmm0, xmm1, xmm2", test->mnemonic);
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            expected);
        (void)snprintf(expected, sizeof(expected),
            "%s %%xmm2, %%xmm1, %%xmm0", test->mnemonic);
        expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            expected);
    }
}
#endif

int main(void)
{
    test_exhaustive_modrm_and_w_boundary();
    test_adjacent_prefix_ownership();
    test_truncation_and_prefix_rules();
#if USE_EXTRA_OPCODES
    test_runtime_cpu_and_modes();
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d AVX-VNNI test(s) failed\n", failures);
        return 1;
    }
    puts("x86 AVX-VNNI tests passed: 2048 allocated and 2048 W1 controls");
    return 0;
}
