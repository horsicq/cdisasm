#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct avx_vnni_int16_case {
    uint8_t prefix;
    uint8_t opcode;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} avx_vnni_int16_case;

static const avx_vnni_int16_case avx_vnni_int16_cases[] = {
    {2, 0xd2, CDISASM_X86_NAME_VPDPWSUD, "vpdpwsud"},
    {2, 0xd3, CDISASM_X86_NAME_VPDPWSUDS, "vpdpwsuds"},
    {1, 0xd2, CDISASM_X86_NAME_VPDPWUSD, "vpdpwusd"},
    {1, 0xd3, CDISASM_X86_NAME_VPDPWUSDS, "vpdpwusds"},
    {0, 0xd2, CDISASM_X86_NAME_VPDPWUUD, "vpdpwuud"},
    {0, 0xd3, CDISASM_X86_NAME_VPDPWUUDS, "vpdpwuuds"}
};

_Static_assert(CDISASM_X86_NAME_VPDPWSUD == UINT16_C(1110)
        && CDISASM_X86_NAME_VPDPWSUDS == UINT16_C(1111)
        && CDISASM_X86_NAME_VPDPWUSD == UINT16_C(1112)
        && CDISASM_X86_NAME_VPDPWUSDS == UINT16_C(1113)
        && CDISASM_X86_NAME_VPDPWUUD == UINT16_C(1114)
        && CDISASM_X86_NAME_VPDPWUUDS == UINT16_C(1115),
    "AVX-VNNI-INT16 name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX_VNNI_INT16 == UINT16_C(109),
    "AVX-VNNI-INT16 group ID changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16
        == UINT64_C(0x8000000000000000),
    "AVX-VNNI-INT16 runtime flag changed");
_Static_assert(CDISASM_X86_DECODE_USE_AVX_VNNI_INT16
        == CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16,
    "AVX-VNNI-INT16 runtime alias changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_ALL == UINT64_MAX
        && CDISASM_X86_DECODE_FLAG_KNOWN_MASK == UINT64_MAX,
    "the 64-family x86 runtime mask is incomplete");

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

/* The zero-filled tail supplies every possible SIB/displacement form while
 * the decoder still reports the exact number of consumed bytes. */
static void make_encoding(
    uint8_t map,
    uint8_t prefix,
    uint8_t opcode,
    unsigned int length,
    unsigned int w,
    uint8_t modrm,
    uint8_t code[15])
{
    memset(code, 0, 15u);
    code[0] = UINT8_C(0xc4);
    code[1] = (uint8_t)(UINT8_C(0xe0) | map);
    code[2] = (uint8_t)(UINT8_C(0x70)
        | (w != 0u ? UINT8_C(0x80) : UINT8_C(0))
        | (length != 0u ? UINT8_C(0x04) : UINT8_C(0))
        | prefix);
    code[3] = opcode;
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
         case_index < sizeof(avx_vnni_int16_cases)
             / sizeof(avx_vnni_int16_cases[0]);
         ++case_index) {
        const avx_vnni_int16_case *test =
            &avx_vnni_int16_cases[case_index];
        unsigned int length;

        for (length = 0; length != 2u; ++length) {
            const unsigned int vector_bits = length == 0u ? 128u : 256u;
            unsigned int modrm;

            (void)vector_bits;
            for (modrm = 0; modrm != 256u; ++modrm) {
                uint8_t code[15];

                make_encoding(2u, test->prefix, test->opcode, length, 0u,
                    (uint8_t)modrm, code);
                ++allocated;
#if USE_EXTRA_OPCODES
                {
                    const unsigned int mod = modrm >> 6;
                    const unsigned int destination = (modrm >> 3) & 7u;
                    const unsigned int rm = modrm & 7u;
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_ARROW_LAKE, CDISASM_MODE_64,
                        code, sizeof(code),
                        CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16,
                        &decoded_size);

                    EXPECT(decoded_size >= 5u && decoded_size <= 10u);
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id == test->name_id);
                    EXPECT(instruction.operand_count == 3u);
                    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX)
                        != 0);
                    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX)
                        == 0);
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX));
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX_VNNI_INT16));
                    EXPECT(!cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX_VNNI));
                    EXPECT(!cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX_VNNI_INT8));
                    EXPECT(instruction.opcode[0].type
                        == CDISASM_OPERAND_REGISTER);
                    EXPECT(instruction.opcode[0].reg
                        == vector_register(destination, vector_bits));
                    EXPECT(instruction.opcode[0].size == vector_bits / 8u);
                    EXPECT(instruction.opcode[0].access
                        == CDISASM_OPERAND_ACCESS_READ_WRITE);
                    EXPECT(instruction.opcode[1].type
                        == CDISASM_OPERAND_REGISTER);
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
                expect_status("extra-opcodes OFF AVX-VNNI-INT16 encoding",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

                make_encoding(2u, test->prefix, test->opcode, length, 1u,
                    (uint8_t)modrm, code);
                ++reserved;
                expect_status("AVX-VNNI-INT16 W1 reserved",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }
    }
    EXPECT(allocated == 3072u);
    EXPECT(reserved == 3072u);
}

static void test_encoding_boundaries(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(avx_vnni_int16_cases)
             / sizeof(avx_vnni_int16_cases[0]);
         ++case_index) {
        const avx_vnni_int16_case *test =
            &avx_vnni_int16_cases[case_index];
        uint8_t code[15];

        make_encoding(3u, test->prefix, test->opcode, 0u, 0u,
            UINT8_C(0xc2), code);
        expect_status("0F3A map does not alias AVX-VNNI-INT16",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            CDISASM_X86_DECODE_FLAG_ALL,
#else
            CDISASM_X86_DECODE_FLAG_BASE,
#endif
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    {
        uint8_t code[16];
        size_t size;

        make_encoding(2u, 3u, UINT8_C(0xd2), 0u, 0u,
            UINT8_C(0xc2), code);
        expect_status("F2 pp neighbor remains unowned",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            CDISASM_X86_DECODE_FLAG_ALL,
#else
            CDISASM_X86_DECODE_FLAG_BASE,
#endif
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        make_encoding(2u, avx_vnni_int16_cases[0].prefix,
            avx_vnni_int16_cases[0].opcode, 0u, 0u,
            UINT8_C(0xc2), code);
        expect_status("empty AVX-VNNI-INT16 input",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, 0u,
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_END_OF_INPUT);
        for (size = 1; size != 5u; ++size) {
            expect_status("truncated AVX-VNNI-INT16 register form",
                CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
                CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        }

        make_encoding(2u, avx_vnni_int16_cases[1].prefix,
            avx_vnni_int16_cases[1].opcode, 1u, 0u,
            UINT8_C(0x48), code);
        expect_status("truncated AVX-VNNI-INT16 disp8",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, 5u,
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);

        make_encoding(2u, avx_vnni_int16_cases[2].prefix,
            avx_vnni_int16_cases[2].opcode, 0u, 0u,
            UINT8_C(0xc2), code + 1);
        code[0] = UINT8_C(0x66);
        expect_status("legacy prefix before AVX-VNNI-INT16 VEX",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, 6u,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

#if USE_EXTRA_OPCODES
static void test_runtime_cpu_flags_and_modes(void)
{
    static const cdisasm_x86_decode_option wrong_selectors[] = {
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_X86_DECODE_FLAG_AVX,
        CDISASM_X86_DECODE_FLAG_AVX2,
        CDISASM_X86_DECODE_FLAG_AVX_VNNI,
        CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8,
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI
    };
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint8_t code[15];
    cdisasm_cpu_id cpu;
    size_t index;

    make_encoding(2u, avx_vnni_int16_cases[0].prefix,
        avx_vnni_int16_cases[0].opcode, 0u, 0u, UINT8_C(0xc2), code);

    for (cpu = CDISASM_CPU_FIRST; cpu <= CDISASM_CPU_LAST; ++cpu) {
        const cdisasm_x86_mode_mask mode_mask =
            cdisasm_x86_cpu_mode_mask(cpu);
        const cdisasm_mode selected_mode =
            (mode_mask & CDISASM_X86_MODE_MASK_64) != 0u
                ? CDISASM_MODE_64
                : ((mode_mask & CDISASM_X86_MODE_MASK_32) != 0u
                    ? CDISASM_MODE_32 : CDISASM_MODE_16);
        const int supported = cpu == CDISASM_CPU_ARROW_LAKE
            || cpu == CDISASM_CPU_DIAMOND_RAPIDS;
        const cdisasm_x86_decode_option available =
            cdisasm_x86_cpu_decode_flag_mask(cpu, selected_mode);

        EXPECT(mode_mask != CDISASM_X86_MODE_MASK_NONE);
        EXPECT(((available & CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16)
            != 0) == supported);
        if (supported) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                cpu, selected_mode, code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16,
                &decoded_size);

            EXPECT(decoded_size == 5u);
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VPDPWSUD);
        } else {
            expect_status("CPU lacks independent AVX-VNNI-INT16 feature",
                cpu, selected_mode, code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    for (index = 0;
         index < sizeof(wrong_selectors) / sizeof(wrong_selectors[0]);
         ++index) {
        expect_status("unrelated selector does not imply AVX-VNNI-INT16",
            CDISASM_CPU_ARROW_LAKE, CDISASM_MODE_64,
            code, sizeof(code), wrong_selectors[index],
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }

    for (index = 0; index != 3u; ++index) {
        static const cdisasm_x86_decode_option admitted_selectors[] = {
            CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16,
            CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16
                | CDISASM_X86_DECODE_FLAG_AVX,
            CDISASM_X86_DECODE_FLAG_ALL
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_ARROW_LAKE, CDISASM_MODE_64,
            code, sizeof(code), admitted_selectors[index], &decoded_size);

        EXPECT(decoded_size == 5u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPDPWSUD);
    }

    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64)
        & CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16) == 0u);
    for (index = 0; index < sizeof(modes) / sizeof(modes[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, modes[index], code, sizeof(code),
            CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16, &decoded_size);
        const cdisasm_x86_decode_option available =
            cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_X86, modes[index]);

        EXPECT(decoded_size == 5u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPDPWSUD);
        EXPECT((available & CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16) != 0);
    }
}
#else
static void test_extra_off_high_bit_contract(void)
{
    uint8_t code[15];

    make_encoding(2u, avx_vnni_int16_cases[0].prefix,
        avx_vnni_int16_cases[0].opcode, 0u, 0u, UINT8_C(0xc2), code);
    expect_status("extra-opcodes OFF rejects bit63 selector",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
        CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16,
        CDISASM_STATUS_INVALID_ARGUMENT);
}
#endif

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void test_formatting(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(avx_vnni_int16_cases)
             / sizeof(avx_vnni_int16_cases[0]);
         ++case_index) {
        const avx_vnni_int16_case *test =
            &avx_vnni_int16_cases[case_index];
        uint8_t code[15];
        uint32_t decoded_size;
        char actual[128];
        char expected[128];
        cdisasm_instruction instruction;
        size_t length;

        make_encoding(2u, test->prefix, test->opcode, 0u, 0u,
            UINT8_C(0xc2), code);
        instruction = decode(
            CDISASM_CPU_ARROW_LAKE, CDISASM_MODE_64,
            code, sizeof(code),
            CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16,
            &decoded_size);
        EXPECT(decoded_size == 5u);

        (void)snprintf(expected, sizeof(expected),
            "%s xmm0, xmm1, xmm2", test->mnemonic);
        length = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_X86_INTEL,
            actual, sizeof(actual));
        EXPECT(length == strlen(expected));
        EXPECT(strcmp(actual, expected) == 0);

        (void)snprintf(expected, sizeof(expected),
            "%s %%xmm2, %%xmm1, %%xmm0", test->mnemonic);
        length = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_X86_ATT,
            actual, sizeof(actual));
        EXPECT(length == strlen(expected));
        EXPECT(strcmp(actual, expected) == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_modrm_and_w_boundary();
    test_encoding_boundaries();
#if USE_EXTRA_OPCODES
    test_runtime_cpu_flags_and_modes();
#else
    test_extra_off_high_bit_contract();
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d AVX-VNNI-INT16 test(s) failed\n", failures);
        return 1;
    }
    puts("x86 AVX-VNNI-INT16 tests passed: 3072 allocated and 3072 W1 controls");
    return 0;
}
