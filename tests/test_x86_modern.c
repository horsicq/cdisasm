#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_NAME_AESENC == UINT16_C(670),
    "modern x86 mnemonic IDs must remain append-only");
_Static_assert(CDISASM_X86_NAME_POP2 == UINT16_C(732)
        && CDISASM_X86_NAME_VPCLMULQDQ == UINT16_C(736)
        && CDISASM_X86_NAME_RDRAND == UINT16_C(737)
        && CDISASM_X86_NAME_XTEST == UINT16_C(742)
        && CDISASM_X86_NAME_JMPABS == UINT16_C(803)
        && CDISASM_X86_NAME_VPSHAQ == UINT16_C(827),
    "modern x86 mnemonic tail changed");
_Static_assert(CDISASM_X86_NAME_COUNT >= UINT16_C(828),
    "modern x86 mnemonic expansion disappeared");
_Static_assert(CDISASM_X86_REG_R16 == UINT16_C(292)
        && CDISASM_X86_REG_R31 == UINT16_C(307),
    "APX register IDs changed");
_Static_assert(CDISASM_PREFIX_EVEX == (UINT32_C(1) << 11)
        && CDISASM_PREFIX_REX2 == (UINT32_C(1) << 12)
        && CDISASM_PREFIX_APX_NDD == (UINT32_C(1) << 13)
        && CDISASM_PREFIX_APX_NF == (UINT32_C(1) << 14)
        && CDISASM_PREFIX_APX_ZU == (UINT32_C(1) << 15),
    "modern x86 prefix metadata bits changed");

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",            \
                    __FILE__, __LINE__, #expression);                        \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

typedef struct modern_case {
    const char *label;
    const uint8_t *bytes;
    size_t size;
    cdisasm_cpu_id supporting_cpu;
    cdisasm_cpu_id rejecting_cpu;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_group_id feature_group;
    cdisasm_x86_decode_option decode_flags;
} modern_case;

static cdisasm_x86_decode_option enabled_extension_flags(void)
{
#if USE_EXTRA_OPCODES
    return CDISASM_X86_DECODE_FLAG_ALL;
#else
    return CDISASM_X86_DECODE_FLAG_BASE;
#endif
}

static cdisasm_instruction decode_one_with_flags(
    cdisasm_cpu_id cpu,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu, CDISASM_MODE_64, bytes, size, UINT64_C(0x1000),
        flags, &instruction);
    return instruction;
}

static cdisasm_instruction decode_mode_with_flags(
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    uint64_t address,
    cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu, mode, bytes, size, address, flags, &instruction);
    return instruction;
}

static cdisasm_instruction decode_one(
    cdisasm_cpu_id cpu,
    const uint8_t *bytes,
    size_t size,
    uint32_t *decoded_size)
{
    return decode_one_with_flags(
        cpu, bytes, size, enabled_extension_flags(), decoded_size);
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
    const uint8_t *bytes,
    size_t size,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_one_with_flags(
        CDISASM_CPU_X86, bytes, size,
        CDISASM_X86_DECODE_FLAG_BASE, &decoded_size);

    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, status));
}

static void test_semantic_families(void)
{
    static const uint8_t andn[] = {0xc4, 0xe2, 0x70, 0xf2, 0xc2};
    static const uint8_t f16c[] = {0xc4, 0xe3, 0x7d, 0x1d, 0xc8, 0x00};
    static const uint8_t fma3[] = {0xc4, 0xe2, 0x6d, 0x98, 0xcb};
    static const uint8_t fma3_sd[] = {0xc4, 0xe2, 0xe9, 0x99, 0xcb};
    static const uint8_t aesenc[] = {0x66, 0x0f, 0x38, 0xdc, 0xca};
    static const uint8_t pclmul[] = {0x66, 0x0f, 0x3a, 0x44, 0xca, 0x01};
    static const uint8_t sha[] = {0x0f, 0x38, 0xc9, 0xca};
    static const uint8_t xop[] = {0x8f, 0xe9, 0x60, 0x90, 0xca};
    static const uint8_t fma4[] = {0xc4, 0xe3, 0xe9, 0x68, 0xcc, 0x30};
    static const uint8_t evex_f[] = {0x62, 0xf1, 0x6c, 0xc9, 0x58, 0xcb};
    static const uint8_t evex_bw[] = {0x62, 0xf1, 0x6d, 0xc9, 0xfc, 0xcb};
    static const uint8_t evex_vbmi[] = {0x62, 0xf2, 0x6d, 0xc9, 0x8d, 0xcb};
    static const uint8_t evex_vnni[] = {0x62, 0xf2, 0x6d, 0x49, 0x50, 0xcb};
    static const uint8_t evex_ifma[] = {0x62, 0xf2, 0xed, 0x49, 0xb4, 0xcb};
    static const uint8_t amx[] = {0xc4, 0xe2, 0x7b, 0x49, 0xd0};
    static const uint8_t apx_ndd[] = {0x62, 0xec, 0xf4, 0x10, 0x01, 0xd3};
    static const uint8_t rex2[] = {0xd5, 0x58, 0x01, 0xd1};
    static const uint8_t vpshufb[] = {0xc4, 0xe2, 0x69, 0x00, 0xcb};
    static const uint8_t vpalignr[] = {
        0xc4, 0xe3, 0x69, 0x0f, 0xcb, 0x07
    };
    static const uint8_t vaesenc[] = {0xc4, 0xe2, 0x69, 0xdc, 0xcb};
    static const uint8_t vpclmul[] = {
        0xc4, 0xe3, 0x69, 0x44, 0xcb, 0x11
    };
    static const modern_case cases[] = {
        {"BMI1", andn, sizeof(andn), CDISASM_CPU_HASWELL,
            CDISASM_CPU_SANDY_BRIDGE, CDISASM_X86_NAME_ANDN,
            CDISASM_X86_GROUP_BMI1, CDISASM_X86_DECODE_FLAG_BITMANIP},
        {"F16C", f16c, sizeof(f16c), CDISASM_CPU_IVY_BRIDGE,
            CDISASM_CPU_SANDY_BRIDGE, CDISASM_X86_NAME_VCVTPS2PH,
            CDISASM_X86_GROUP_F16C, CDISASM_X86_DECODE_FLAG_F16C},
        {"FMA3", fma3, sizeof(fma3), CDISASM_CPU_HASWELL,
            CDISASM_CPU_IVY_BRIDGE, CDISASM_X86_NAME_VFMADD132PS,
            CDISASM_X86_GROUP_FMA3, CDISASM_X86_DECODE_FLAG_FMA3},
        {"FMA3 scalar double", fma3_sd, sizeof(fma3_sd),
            CDISASM_CPU_HASWELL, CDISASM_CPU_IVY_BRIDGE,
            CDISASM_X86_NAME_VFMADD132SD, CDISASM_X86_GROUP_FMA3,
            CDISASM_X86_DECODE_FLAG_FMA3},
        {"AES-NI", aesenc, sizeof(aesenc), CDISASM_CPU_WESTMERE,
            CDISASM_CPU_NEHALEM, CDISASM_X86_NAME_AESENC,
            CDISASM_X86_GROUP_AESNI, CDISASM_X86_DECODE_FLAG_AES},
        {"PCLMULQDQ", pclmul, sizeof(pclmul), CDISASM_CPU_WESTMERE,
            CDISASM_CPU_NEHALEM, CDISASM_X86_NAME_PCLMULQDQ,
            CDISASM_X86_GROUP_PCLMULQDQ,
            CDISASM_X86_DECODE_FLAG_PCLMUL},
        {"SHA", sha, sizeof(sha), CDISASM_CPU_GOLDMONT,
            CDISASM_CPU_SKYLAKE, CDISASM_X86_NAME_SHA1MSG1,
            CDISASM_X86_GROUP_SHA, CDISASM_X86_DECODE_FLAG_SHA},
        {"XOP", xop, sizeof(xop), CDISASM_CPU_AMD_BULLDOZER,
            CDISASM_CPU_HASWELL, CDISASM_X86_NAME_VPROTB,
            CDISASM_X86_GROUP_XOP, CDISASM_X86_DECODE_FLAG_XOP},
        {"FMA4", fma4, sizeof(fma4), CDISASM_CPU_AMD_BULLDOZER,
            CDISASM_CPU_HASWELL, CDISASM_X86_NAME_VFMADDPS,
            CDISASM_X86_GROUP_FMA4, CDISASM_X86_DECODE_FLAG_FMA4},
        {"AVX-512F", evex_f, sizeof(evex_f), CDISASM_CPU_SKYLAKE_SP,
            CDISASM_CPU_ALDER_LAKE, CDISASM_X86_NAME_VADDPS,
            CDISASM_X86_GROUP_AVX512F, CDISASM_X86_DECODE_FLAG_AVX512},
        {"AVX-512BW", evex_bw, sizeof(evex_bw), CDISASM_CPU_SKYLAKE_SP,
            CDISASM_CPU_ALDER_LAKE, CDISASM_X86_NAME_VPADDB,
            CDISASM_X86_GROUP_AVX512BW, CDISASM_X86_DECODE_FLAG_AVX512},
        {"AVX-512VBMI", evex_vbmi, sizeof(evex_vbmi), CDISASM_CPU_ICE_LAKE,
            CDISASM_CPU_SKYLAKE_SP, CDISASM_X86_NAME_VPERMB,
            CDISASM_X86_GROUP_AVX512VBMI,
            CDISASM_X86_DECODE_FLAG_AVX512},
        {"AVX-512VNNI", evex_vnni, sizeof(evex_vnni), CDISASM_CPU_ICE_LAKE,
            CDISASM_CPU_SKYLAKE_SP, CDISASM_X86_NAME_VPDPBUSD,
            CDISASM_X86_GROUP_AVX512VNNI,
            CDISASM_X86_DECODE_FLAG_AVX512},
        {"AVX-512IFMA", evex_ifma, sizeof(evex_ifma), CDISASM_CPU_ICE_LAKE,
            CDISASM_CPU_SKYLAKE_SP, CDISASM_X86_NAME_VPMADD52LUQ,
            CDISASM_X86_GROUP_AVX512IFMA,
            CDISASM_X86_DECODE_FLAG_AVX512},
        {"AMX-TILE", amx, sizeof(amx), CDISASM_CPU_SAPPHIRE_RAPIDS,
            CDISASM_CPU_ICE_LAKE, CDISASM_X86_NAME_TILEZERO,
            CDISASM_X86_GROUP_AMX_TILE, CDISASM_X86_DECODE_FLAG_AMX},
        {"APX NDD", apx_ndd, sizeof(apx_ndd), CDISASM_CPU_APX,
            CDISASM_CPU_AVX10, CDISASM_X86_NAME_ADD,
            CDISASM_X86_GROUP_APX_F, CDISASM_X86_DECODE_FLAG_APX},
        {"APX REX2", rex2, sizeof(rex2), CDISASM_CPU_APX,
            CDISASM_CPU_AVX10, CDISASM_X86_NAME_ADD,
            CDISASM_X86_GROUP_APX_F, CDISASM_X86_DECODE_FLAG_APX},
        {"VPSHUFB", vpshufb, sizeof(vpshufb), CDISASM_CPU_SANDY_BRIDGE,
            CDISASM_CPU_CELERON_G1840, CDISASM_X86_NAME_VPSHUFB,
            CDISASM_X86_GROUP_SSSE3, CDISASM_X86_DECODE_FLAG_AVX},
        {"VPALIGNR", vpalignr, sizeof(vpalignr),
            CDISASM_CPU_SANDY_BRIDGE, CDISASM_CPU_CELERON_G1840,
            CDISASM_X86_NAME_VPALIGNR, CDISASM_X86_GROUP_SSSE3,
            CDISASM_X86_DECODE_FLAG_AVX},
        {"VEX.128 VAESENC", vaesenc, sizeof(vaesenc),
            CDISASM_CPU_SANDY_BRIDGE, CDISASM_CPU_WESTMERE,
            CDISASM_X86_NAME_VAESENC, CDISASM_X86_GROUP_AESNI,
            CDISASM_X86_DECODE_FLAG_AES},
        {"VEX.128 VPCLMULQDQ", vpclmul, sizeof(vpclmul),
            CDISASM_CPU_SANDY_BRIDGE, CDISASM_CPU_WESTMERE,
            CDISASM_X86_NAME_VPCLMULQDQ,
            CDISASM_X86_GROUP_PCLMULQDQ,
            CDISASM_X86_DECODE_FLAG_PCLMUL}
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_x86_decode_option decode_flags =
            CDISASM_X86_DECODE_FLAG_BASE;
        cdisasm_instruction instruction;

#if USE_EXTRA_OPCODES
        decode_flags = cases[index].decode_flags;
#endif
        instruction = decode_one_with_flags(
#if USE_EXTRA_OPCODES
            cases[index].supporting_cpu,
#else
            CDISASM_CPU_X86,
#endif
            cases[index].bytes, cases[index].size, decode_flags,
            &decoded_size);

#if USE_EXTRA_OPCODES
        uint32_t rejected_size;
        cdisasm_instruction rejected;

        EXPECT(decoded_size == cases[index].size);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == cases[index].name_id);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, cases[index].feature_group));

        rejected = decode_one_with_flags(
            cases[index].rejecting_cpu,
            cases[index].bytes,
            cases[index].size,
            cases[index].decode_flags,
            &rejected_size);
        EXPECT(rejected_size == 0);
        EXPECT(is_error_only(
            &rejected, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
        (void)cases[index].supporting_cpu;
        (void)cases[index].rejecting_cpu;
        (void)cases[index].name_id;
        (void)cases[index].feature_group;
        EXPECT(decoded_size == 0);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

#if USE_EXTRA_OPCODES
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_one_with_flags(
            CDISASM_CPU_AVX10, evex_f, sizeof(evex_f),
            CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);

        EXPECT(decoded_size == sizeof(evex_f));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VADDPS);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
    }
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_one_with_flags(
            CDISASM_CPU_CELERON_G1840,
            andn, sizeof(andn), CDISASM_X86_DECODE_FLAG_BITMANIP,
            &decoded_size);

        EXPECT(decoded_size == 0);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    {
        static const uint8_t mulx[] = {0xc4, 0x42, 0xab, 0xf6, 0xcb};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_one_with_flags(
            CDISASM_CPU_HASWELL, mulx, sizeof(mulx),
            CDISASM_X86_DECODE_FLAG_BITMANIP, &decoded_size);

        EXPECT(decoded_size == sizeof(mulx));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_MULX);
        EXPECT(instruction.operand_count == 3);
    }
    {
        static const uint8_t apx_egpr_memory[] = {
            0x62, 0xe9, 0x64, 0xd2, 0x58, 0x0c, 0x24
        };
        uint32_t decoded_size;
        uint32_t rejected_size;
        cdisasm_instruction instruction = decode_one_with_flags(
            CDISASM_CPU_APX,
            apx_egpr_memory, sizeof(apx_egpr_memory),
            CDISASM_X86_DECODE_FLAG_APX, &decoded_size);

        EXPECT(decoded_size == sizeof(apx_egpr_memory));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VADDPS);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ZMM17);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ZMM19);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_R20);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        instruction = decode_one_with_flags(
            CDISASM_CPU_AVX10,
            apx_egpr_memory, sizeof(apx_egpr_memory),
            CDISASM_X86_DECODE_FLAG_APX, &rejected_size);
        EXPECT(rejected_size == 0);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    {
        static const uint8_t apx_nf[] = {
            0x62, 0xec, 0xf4, 0x14, 0x01, 0xd3
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_one_with_flags(
            CDISASM_CPU_APX, apx_nf, sizeof(apx_nf),
            CDISASM_X86_DECODE_FLAG_APX, &decoded_size);

        EXPECT(decoded_size == sizeof(apx_nf));
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NF) != 0);
    }
#  if USE_DISASM_FORMAT
    {
        uint32_t decoded_size;
        char text[96];
        cdisasm_instruction instruction = decode_one_with_flags(
            CDISASM_CPU_ICE_LAKE,
            vaesenc, sizeof(vaesenc), CDISASM_X86_DECODE_FLAG_AES,
            &decoded_size);

        EXPECT(decoded_size == sizeof(vaesenc));
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text));
        EXPECT(strcmp(text, "vaesenc xmm1, xmm2, xmm3") == 0);

        instruction = decode_one_with_flags(
            CDISASM_CPU_ICE_LAKE,
            vpclmul, sizeof(vpclmul), CDISASM_X86_DECODE_FLAG_PCLMUL,
            &decoded_size);
        EXPECT(decoded_size == sizeof(vpclmul));
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text));
        EXPECT(strcmp(text,
            "vpclmulqdq xmm1, xmm2, xmm3, 0x11") == 0);
    }
#  endif
#endif
}

static void test_apx_rex2_integer_core(void)
{
    static const struct apx_shape {
        uint8_t opcode;
        cdisasm_x86_name_id name_id;
    } shapes[] = {
        {0x00, CDISASM_X86_NAME_ADD}, {0x01, CDISASM_X86_NAME_ADD},
        {0x02, CDISASM_X86_NAME_ADD}, {0x03, CDISASM_X86_NAME_ADD},
        {0x08, CDISASM_X86_NAME_OR},  {0x09, CDISASM_X86_NAME_OR},
        {0x0a, CDISASM_X86_NAME_OR},  {0x0b, CDISASM_X86_NAME_OR},
        {0x10, CDISASM_X86_NAME_ADC}, {0x11, CDISASM_X86_NAME_ADC},
        {0x12, CDISASM_X86_NAME_ADC}, {0x13, CDISASM_X86_NAME_ADC},
        {0x18, CDISASM_X86_NAME_SBB}, {0x19, CDISASM_X86_NAME_SBB},
        {0x1a, CDISASM_X86_NAME_SBB}, {0x1b, CDISASM_X86_NAME_SBB},
        {0x20, CDISASM_X86_NAME_AND}, {0x21, CDISASM_X86_NAME_AND},
        {0x22, CDISASM_X86_NAME_AND}, {0x23, CDISASM_X86_NAME_AND},
        {0x28, CDISASM_X86_NAME_SUB}, {0x29, CDISASM_X86_NAME_SUB},
        {0x2a, CDISASM_X86_NAME_SUB}, {0x2b, CDISASM_X86_NAME_SUB},
        {0x30, CDISASM_X86_NAME_XOR}, {0x31, CDISASM_X86_NAME_XOR},
        {0x32, CDISASM_X86_NAME_XOR}, {0x33, CDISASM_X86_NAME_XOR},
        {0x38, CDISASM_X86_NAME_CMP}, {0x39, CDISASM_X86_NAME_CMP},
        {0x3a, CDISASM_X86_NAME_CMP}, {0x3b, CDISASM_X86_NAME_CMP},
        {0x84, CDISASM_X86_NAME_TEST}, {0x85, CDISASM_X86_NAME_TEST},
        {0x88, CDISASM_X86_NAME_MOV}, {0x89, CDISASM_X86_NAME_MOV},
        {0x8a, CDISASM_X86_NAME_MOV}, {0x8b, CDISASM_X86_NAME_MOV}
    };
    static const uint8_t byte_add[] = {0xd5, 0x50, 0x00, 0xec};
    static const uint8_t word_add[] = {0x66, 0xd5, 0x50, 0x01, 0xfe};
    static const uint8_t dword_add[] = {0xd5, 0x55, 0x01, 0xc8};
    static const uint8_t rex2_w_over_66[] = {
        0x66, 0xd5, 0x58, 0x01, 0xc8
    };
    static const uint8_t memory_destination[] = {
        0xd5, 0x78, 0x01, 0x74, 0xac, 0x20
    };
    static const uint8_t memory_source[] = {
        0xd5, 0x7b, 0x03, 0x7c, 0x48, 0xf0
    };
    static const uint8_t x4_index20[] = {
        0xd5, 0x68, 0x03, 0x04, 0x60
    };
    static const uint8_t direct_rip_b4_b3[] = {
        0xd5, 0x59, 0x03, 0x05, 0x20, 0x00, 0x00, 0x00
    };
    static const uint8_t direct_eip_b4[] = {
        0x67, 0xd5, 0x51, 0x03, 0x05, 0x20, 0x00, 0x00, 0x00
    };
    static const uint8_t sib_b4_no_base[] = {
        0xd5, 0x58, 0x03, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00
    };
    static const uint8_t sib_b4_no_base_truncated[] = {
        0xd5, 0x58, 0x03, 0x04, 0x25
    };
    static const uint8_t sib_b3_no_base[] = {
        0xd5, 0x49, 0x03, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00
    };
    static const uint8_t lock_memory[] = {
        0xf0, 0xd5, 0x58, 0x01, 0x2c, 0x24
    };
    static const uint8_t ignored_rep[] = {
        0xf3, 0xd5, 0x58, 0x01, 0xc8
    };
    static const uint8_t lock_register[] = {
        0xf0, 0xd5, 0x58, 0x01, 0xc8
    };
    static const uint8_t lock_cmp_memory[] = {
        0xf0, 0xd5, 0x58, 0x39, 0x08
    };
    static const uint8_t lock_reverse_add[] = {
        0xf0, 0xd5, 0x58, 0x03, 0x08
    };
    static const uint8_t lock_mov_memory[] = {
        0xf0, 0xd5, 0x58, 0x89, 0x08
    };
    static const uint8_t truncated_modrm[] = {0xd5, 0x58, 0x39};
    static const uint8_t truncated_sib[] = {0xd5, 0x78, 0x01, 0x74};
    static const uint8_t truncated_disp8[] = {
        0xd5, 0x78, 0x01, 0x74, 0xac
    };
    static const uint8_t truncated_direct_rip[] = {
        0xd5, 0x59, 0x03, 0x05
    };
    static const uint8_t truncated_sib_b3_no_base[] = {
        0xd5, 0x49, 0x03, 0x04, 0x25
    };
    static const uint8_t prefix_after_rex2[] = {
        0xd5, 0x58, 0x66, 0xc8
    };
    static const uint8_t rex_before_rex2[] = {
        0x48, 0xd5, 0x58, 0x01, 0xc8
    };
    static const uint8_t map0_reserved_row[] = {
        0xd5, 0x58, 0x70, 0x00
    };
    static const uint8_t map0_jmpabs_bad_w[] = {
        0xd5, 0x58, 0xa1, 0x00
    };
    static const uint8_t map1_reserved_row[] = {
        0xd5, 0xd8, 0x30, 0xc0
    };
    static const uint8_t map1_uncovered[] = {
        0xd5, 0xd8, 0x01, 0xc8
    };
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    size_t index;

    for (index = 0; index < sizeof(shapes) / sizeof(shapes[0]); ++index) {
        uint8_t bytes[] = {0xd5, 0x58, shapes[index].opcode, 0xc8};

        instruction = decode_one_with_flags(
#if USE_EXTRA_OPCODES
            CDISASM_CPU_APX,
#else
            CDISASM_CPU_X86,
#endif
            bytes, sizeof(bytes),
#if USE_EXTRA_OPCODES
            CDISASM_X86_DECODE_FLAG_APX,
#else
            CDISASM_X86_DECODE_FLAG_BASE,
#endif
            &decoded_size);
#if USE_EXTRA_OPCODES
        {
            const int reverse = (shapes[index].opcode & 2u) != 0;
            const int byte_form = (shapes[index].opcode & 1u) == 0;
            const cdisasm_x86_reg_id rm_register = byte_form
                ? CDISASM_X86_REG_R16B : CDISASM_X86_REG_R16;
            const cdisasm_x86_reg_id reg_register = byte_form
                ? CDISASM_X86_REG_R17B : CDISASM_X86_REG_R17;
            cdisasm_operand_access destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;

            if (shapes[index].name_id == CDISASM_X86_NAME_CMP
                || shapes[index].name_id == CDISASM_X86_NAME_TEST) {
                destination_access = CDISASM_OPERAND_ACCESS_READ;
            } else if (shapes[index].name_id == CDISASM_X86_NAME_MOV) {
                destination_access = CDISASM_OPERAND_ACCESS_WRITE;
            }
            EXPECT(decoded_size == sizeof(bytes));
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id == shapes[index].name_id);
            EXPECT(instruction.operand_count == 2);
            EXPECT(instruction.opcode[0].reg
                == (reverse ? reg_register : rm_register));
            EXPECT(instruction.opcode[1].reg
                == (reverse ? rm_register : reg_register));
            EXPECT(instruction.opcode[0].size == (byte_form ? 1 : 8));
            EXPECT(instruction.opcode[1].size == (byte_form ? 1 : 8));
            EXPECT(instruction.opcode[0].access == destination_access);
            EXPECT(instruction.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT((instruction.opcode_flags & (CDISASM_PREFIX_REX2
                    | CDISASM_PREFIX_REX_W))
                == (CDISASM_PREFIX_REX2 | CDISASM_PREFIX_REX_W));
            EXPECT(instruction.encoding.prefix_size == 2);
            EXPECT(instruction.encoding.opcode_offset == 2);
            EXPECT(instruction.encoding.modrm_offset == 3);
            EXPECT(instruction.encoding.modrm == 0xc8);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AMD64));
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_APX_F));
        }
#else
        EXPECT(decoded_size == 0);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

#if USE_EXTRA_OPCODES
    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, byte_add, sizeof(byte_add),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(byte_add));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R20B);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R21B);
    EXPECT(instruction.opcode[0].size == 1);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, word_add, sizeof(word_add),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(word_add));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R22W);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R23W);
    EXPECT(instruction.opcode[0].size == 2);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, dword_add, sizeof(dword_add),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(dword_add));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R24D);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R25D);
    EXPECT(instruction.opcode[0].size == 4);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, rex2_w_over_66, sizeof(rex2_w_over_66),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(rex2_w_over_66));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R16);
    EXPECT(instruction.opcode[0].size == 8);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_OPERAND_SIZE) != 0);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, memory_destination, sizeof(memory_destination),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(memory_destination));
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R20);
    EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_R21);
    EXPECT(instruction.opcode[0].scale == 4);
    EXPECT((int64_t)instruction.opcode[0].imm == INT64_C(0x20));
    EXPECT(instruction.opcode[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R22);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, memory_source, sizeof(memory_source),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(memory_source));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R23);
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R24);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R25);
    EXPECT(instruction.opcode[1].scale == 2);
    EXPECT((int64_t)instruction.opcode[1].imm == -INT64_C(0x10));
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, x4_index20, sizeof(x4_index20),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(x4_index20));
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R20);
    EXPECT(instruction.opcode[1].scale == 2);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, direct_rip_b4_b3, sizeof(direct_rip_b4_b3),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(direct_rip_b4_b3));
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RIP);
    EXPECT(instruction.opcode[1].address == UINT64_C(0x1028));
    EXPECT((instruction.opcode[1].flags
            & (CDISASM_OPERAND_FLAG_PC_RELATIVE
                | CDISASM_OPERAND_FLAG_HAS_ADDRESS))
        == (CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, direct_eip_b4, sizeof(direct_eip_b4),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(direct_eip_b4));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R16D);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_EIP);
    EXPECT(instruction.opcode[1].address == UINT64_C(0x1029));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, sib_b4_no_base, sizeof(sib_b4_no_base),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(sib_b4_no_base));
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_NONE);
    EXPECT((instruction.opcode[1].flags
            & (CDISASM_OPERAND_FLAG_ABSOLUTE
                | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT))
        == (CDISASM_OPERAND_FLAG_ABSOLUTE
            | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT));
    EXPECT(instruction.opcode[1].address == UINT64_C(0x20));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, sib_b3_no_base, sizeof(sib_b3_no_base),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(sib_b3_no_base));
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_NONE);
    EXPECT((instruction.opcode[1].flags & CDISASM_OPERAND_FLAG_ABSOLUTE) != 0);
    EXPECT(instruction.opcode[1].address == UINT64_C(0x20));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, lock_memory, sizeof(lock_memory),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(lock_memory));
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EFFECTIVE_LOCK) != 0);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R20);
    EXPECT(instruction.opcode[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, ignored_rep, sizeof(ignored_rep),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(ignored_rep));
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REP) != 0);
    EXPECT((instruction.opcode_flags & (CDISASM_PREFIX_EFFECTIVE_REP
            | CDISASM_PREFIX_EFFECTIVE_REPNE)) == 0);

    instruction = decode_one_with_flags(
        CDISASM_CPU_X86, byte_add, sizeof(byte_add),
        CDISASM_X86_DECODE_FLAG_BASE, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    instruction = decode_one_with_flags(
        CDISASM_CPU_AVX10, byte_add, sizeof(byte_add),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_APX, CDISASM_MODE_64)
            & CDISASM_X86_DECODE_FLAG_APX) != 0);
    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_AVX10, CDISASM_MODE_64)
            & CDISASM_X86_DECODE_FLAG_APX) == 0);

#  if USE_DISASM_FORMAT
    {
        char text[128];

        instruction = decode_one_with_flags(
            CDISASM_CPU_APX, byte_add, sizeof(byte_add),
            CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text));
        EXPECT(strcmp(text, "add r20b, r21b") == 0);
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            text, sizeof(text));
        EXPECT(strcmp(text, "addb %r21b, %r20b") == 0);

        instruction = decode_one_with_flags(
            CDISASM_CPU_APX, word_add, sizeof(word_add),
            CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text));
        EXPECT(strcmp(text, "add r22w, r23w") == 0);
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            text, sizeof(text));
        EXPECT(strcmp(text, "addw %r23w, %r22w") == 0);

        instruction = decode_one_with_flags(
            CDISASM_CPU_APX, memory_destination,
            sizeof(memory_destination), CDISASM_X86_DECODE_FLAG_APX,
            &decoded_size);
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text));
        EXPECT(strcmp(text,
            "add qword ptr [r20 + r21*4 + 0x20], r22") == 0);
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            text, sizeof(text));
        EXPECT(strcmp(text, "addq %r22, 0x20(%r20,%r21,4)") == 0);

        instruction = decode_one_with_flags(
            CDISASM_CPU_APX, lock_memory, sizeof(lock_memory),
            CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text));
        EXPECT(strcmp(text, "lock add qword ptr [r20], r21") == 0);
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            text, sizeof(text));
        EXPECT(strcmp(text, "lock addq %r21, (%r20)") == 0);

        instruction = decode_one_with_flags(
            CDISASM_CPU_APX, ignored_rep, sizeof(ignored_rep),
            CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text));
        EXPECT(strcmp(text, "add r16, r17") == 0);
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            text, sizeof(text));
        EXPECT(strcmp(text, "addq %r17, %r16") == 0);
    }
#  endif
#else
    (void)byte_add;
    (void)word_add;
    (void)dword_add;
    (void)rex2_w_over_66;
    (void)memory_destination;
    (void)memory_source;
    (void)x4_index20;
    (void)direct_rip_b4_b3;
    (void)direct_eip_b4;
    (void)sib_b4_no_base;
    (void)sib_b3_no_base;
    (void)lock_memory;
    (void)ignored_rep;
#endif

    expect_status(lock_register, sizeof(lock_register),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(sib_b4_no_base_truncated,
        sizeof(sib_b4_no_base_truncated), CDISASM_STATUS_TRUNCATED);
    expect_status(lock_cmp_memory, sizeof(lock_cmp_memory),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(lock_reverse_add, sizeof(lock_reverse_add),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(lock_mov_memory, sizeof(lock_mov_memory),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(truncated_modrm, sizeof(truncated_modrm),
        CDISASM_STATUS_TRUNCATED);
    expect_status(truncated_sib, sizeof(truncated_sib),
        CDISASM_STATUS_TRUNCATED);
    expect_status(truncated_disp8, sizeof(truncated_disp8),
        CDISASM_STATUS_TRUNCATED);
    expect_status(truncated_direct_rip, sizeof(truncated_direct_rip),
        CDISASM_STATUS_TRUNCATED);
    expect_status(
        truncated_sib_b3_no_base, sizeof(truncated_sib_b3_no_base),
        CDISASM_STATUS_TRUNCATED);
    expect_status(prefix_after_rex2, sizeof(prefix_after_rex2),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(rex_before_rex2, sizeof(rex_before_rex2),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(map0_reserved_row, sizeof(map0_reserved_row),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(map0_jmpabs_bad_w, sizeof(map0_jmpabs_bad_w),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(map1_reserved_row, sizeof(map1_reserved_row),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(map1_uncovered, sizeof(map1_uncovered),
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
}

static void test_entropy_and_rtm(void)
{
    static const uint8_t rdrand_ax[] = {0x66, 0x0f, 0xc7, 0xf0};
    static const uint8_t rdrand_eax[] = {0x0f, 0xc7, 0xf0};
    static const uint8_t rdrand_r11[] = {0x49, 0x0f, 0xc7, 0xf3};
    static const uint8_t rdseed_r11[] = {0x49, 0x0f, 0xc7, 0xfb};
    static const uint8_t xbegin32[] = {
        0xc7, 0xf8, 0x10, 0x00, 0x00, 0x00
    };
    static const uint8_t xbegin32_wrap[] = {
        0xc7, 0xf8, 0x01, 0x00, 0x00, 0x00
    };
    static const uint8_t xbegin16_cross_64k[] = {
        0xc7, 0xf8, 0x01, 0x00
    };
    static const uint8_t xbegin16[] = {0x66, 0xc7, 0xf8, 0xfe, 0xff};
    static const uint8_t xbegin_66_rex32[] = {
        0x66, 0x48, 0xc7, 0xf8, 0x10, 0x00, 0x00, 0x00
    };
    static const uint8_t xbegin_rex_66_16[] = {
        0x48, 0x66, 0xc7, 0xf8, 0xfe, 0xff
    };
    static const uint8_t xabort[] = {0xc6, 0xf8, 0x0d};
    static const uint8_t xabort_ignored_prefixes[] = {
        0x66, 0xf3, 0x48, 0xc6, 0xf8, 0x0d
    };
    static const uint8_t xend[] = {0x0f, 0x01, 0xd5};
    static const uint8_t xend_ignored_prefixes[] = {
        0x66, 0xf3, 0x48, 0x0f, 0x01, 0xd5
    };
    static const uint8_t xtest[] = {0x0f, 0x01, 0xd6};
    static const uint8_t xtest_ignored_prefixes[] = {
        0xf2, 0x66, 0x0f, 0x01, 0xd6
    };
    static const uint8_t vmxon[] = {0xf3, 0x0f, 0xc7, 0x30};
    static const uint8_t vmptrst[] = {0x0f, 0xc7, 0x38};
    uint32_t decoded_size;
    cdisasm_instruction instruction;

#if USE_EXTRA_OPCODES
    static const cdisasm_cpu_id no_tsx_cpus[] = {
        CDISASM_CPU_ICE_LAKE,
        CDISASM_CPU_TIGER_LAKE,
        CDISASM_CPU_ALDER_LAKE
    };
    size_t cpu_index;

    instruction = decode_mode_with_flags(
        CDISASM_CPU_IVY_BRIDGE, CDISASM_MODE_32,
        rdrand_eax, sizeof(rdrand_eax), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_SECURITY, &decoded_size);
    EXPECT(decoded_size == sizeof(rdrand_eax));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_RDRAND);
    EXPECT(instruction.operand_count == 1);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_EAX);
    EXPECT(instruction.opcode[0].size == 4);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_RDRAND));

    instruction = decode_mode_with_flags(
        CDISASM_CPU_IVY_BRIDGE, CDISASM_MODE_32,
        rdrand_ax, sizeof(rdrand_ax), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_SECURITY, &decoded_size);
    EXPECT(decoded_size == sizeof(rdrand_ax));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_RDRAND);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_AX);
    EXPECT(instruction.opcode[0].size == 2);

    instruction = decode_mode_with_flags(
        CDISASM_CPU_IVY_BRIDGE, CDISASM_MODE_64,
        rdrand_r11, sizeof(rdrand_r11), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_SECURITY, &decoded_size);
    EXPECT(decoded_size == sizeof(rdrand_r11));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_RDRAND);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R11);
    EXPECT(instruction.opcode[0].size == 8);

    instruction = decode_mode_with_flags(
        CDISASM_CPU_BROADWELL, CDISASM_MODE_64,
        rdseed_r11, sizeof(rdseed_r11), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_SECURITY, &decoded_size);
    EXPECT(decoded_size == sizeof(rdseed_r11));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_RDSEED);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R11);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_RDSEED));

    instruction = decode_mode_with_flags(
        CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_32,
        rdrand_eax, sizeof(rdrand_eax), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_SECURITY, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    instruction = decode_mode_with_flags(
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        rdseed_r11, sizeof(rdseed_r11), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_SECURITY, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));

    instruction = decode_mode_with_flags(
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        xbegin32, sizeof(xbegin32), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == sizeof(xbegin32));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XBEGIN);
    EXPECT(instruction.operand_count == 1);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction.opcode[0].size == 4);
    EXPECT(instruction.opcode[0].imm == UINT64_C(0x1016));
    EXPECT(instruction.branch_target == UINT64_C(0x1016));
    EXPECT((instruction.opcode_groups
            & (CDISASM_GROUP_JUMP
                | CDISASM_GROUP_RELATIVE_BRANCH
                | CDISASM_GROUP_CONDITIONAL))
        == (CDISASM_GROUP_JUMP
            | CDISASM_GROUP_RELATIVE_BRANCH
            | CDISASM_GROUP_CONDITIONAL));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_RTM));

    /* XBEGIN always computes a 32-bit fallback EIP outside long mode: rel32
     * wraps at 2^32, while rel16 deliberately does not wrap at 2^16. */
    instruction = decode_mode_with_flags(
        CDISASM_CPU_HASWELL, CDISASM_MODE_32,
        xbegin32_wrap, sizeof(xbegin32_wrap), UINT64_C(0xfffffffc),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == sizeof(xbegin32_wrap));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XBEGIN);
    EXPECT(instruction.opcode[0].size == 4);
    EXPECT(instruction.opcode[0].imm == UINT64_C(3));
    EXPECT(instruction.branch_target == UINT64_C(3));
#  if USE_DISASM_FORMAT
    {
        char text[32];

        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text));
        EXPECT(strcmp(text, "xbegin 0x3") == 0);
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            text, sizeof(text));
        EXPECT(strcmp(text, "xbegin 0x3") == 0);
    }
#  endif

    instruction = decode_mode_with_flags(
        CDISASM_CPU_HASWELL, CDISASM_MODE_16,
        xbegin16_cross_64k, sizeof(xbegin16_cross_64k), UINT64_C(0xfffc),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == sizeof(xbegin16_cross_64k));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XBEGIN);
    EXPECT(instruction.opcode[0].size == 2);
    EXPECT(instruction.opcode[0].imm == UINT64_C(0x10001));
    EXPECT(instruction.branch_target == UINT64_C(0x10001));

    instruction = decode_mode_with_flags(
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
        xbegin32, sizeof(xbegin32), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == sizeof(xbegin32));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XBEGIN);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_RTM));

    instruction = decode_mode_with_flags(
        CDISASM_CPU_HASWELL, CDISASM_MODE_32,
        xbegin16, sizeof(xbegin16), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == sizeof(xbegin16));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XBEGIN);
    EXPECT(instruction.opcode[0].size == 2);
    EXPECT(instruction.branch_target == UINT64_C(0x1003));

    instruction = decode_mode_with_flags(
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        xbegin16, sizeof(xbegin16), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == sizeof(xbegin16));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XBEGIN);
    EXPECT(instruction.opcode[0].size == 2);
    EXPECT(instruction.branch_target == UINT64_C(0x1003));

    /* An effective REX.W wins over an earlier 66 and maps XBEGIN's
     * operand64 form to rel32.  A legacy prefix after REX cancels that REX,
     * so the inverse byte ordering retains rel16. */
    instruction = decode_mode_with_flags(
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        xbegin_66_rex32, sizeof(xbegin_66_rex32), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == sizeof(xbegin_66_rex32));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XBEGIN);
    EXPECT(instruction.opcode[0].size == 4);
    EXPECT(instruction.branch_target == UINT64_C(0x1018));

    instruction = decode_mode_with_flags(
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        xbegin_rex_66_16, sizeof(xbegin_rex_66_16), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == sizeof(xbegin_rex_66_16));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XBEGIN);
    EXPECT(instruction.opcode[0].size == 2);
    EXPECT(instruction.branch_target == UINT64_C(0x1004));

    instruction = decode_mode_with_flags(
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        xabort, sizeof(xabort), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == sizeof(xabort));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XABORT);
    EXPECT(instruction.operand_count == 1);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction.opcode[0].size == 1);
    EXPECT(instruction.opcode[0].imm == UINT64_C(0x0d));

    instruction = decode_mode_with_flags(
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        xabort_ignored_prefixes, sizeof(xabort_ignored_prefixes),
        UINT64_C(0x1000), CDISASM_X86_DECODE_FLAG_TRANSACTIONAL,
        &decoded_size);
    EXPECT(decoded_size == sizeof(xabort_ignored_prefixes));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XABORT);
    EXPECT((instruction.opcode_flags & (CDISASM_PREFIX_OPERAND_SIZE
            | CDISASM_PREFIX_REP | CDISASM_PREFIX_REX
            | CDISASM_PREFIX_REX_W))
        == (CDISASM_PREFIX_OPERAND_SIZE | CDISASM_PREFIX_REP
            | CDISASM_PREFIX_REX | CDISASM_PREFIX_REX_W));
    EXPECT((instruction.opcode_flags & (CDISASM_PREFIX_EFFECTIVE_REP
            | CDISASM_PREFIX_EFFECTIVE_REPNE)) == 0);

    instruction = decode_mode_with_flags(
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        xend, sizeof(xend), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == sizeof(xend));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XEND);
    EXPECT(instruction.operand_count == 0);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_RTM));
    instruction = decode_mode_with_flags(
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
        xend, sizeof(xend), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == sizeof(xend));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XEND);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_RTM));
    instruction = decode_mode_with_flags(
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        xend_ignored_prefixes, sizeof(xend_ignored_prefixes),
        UINT64_C(0x1000), CDISASM_X86_DECODE_FLAG_TRANSACTIONAL,
        &decoded_size);
    EXPECT(decoded_size == sizeof(xend_ignored_prefixes));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XEND);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REP) != 0);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EFFECTIVE_REP) == 0);
    instruction = decode_mode_with_flags(
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        xtest, sizeof(xtest), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == sizeof(xtest));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XTEST);
    EXPECT(instruction.operand_count == 0);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_RTM));

    /* Sapphire Rapids exposes RTM, so XTEST takes and reports the RTM path.
     * Its redundant legacy prefixes remain recorded but non-effective. */
    instruction = decode_mode_with_flags(
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
        xtest_ignored_prefixes, sizeof(xtest_ignored_prefixes),
        UINT64_C(0x1000), CDISASM_X86_DECODE_FLAG_TRANSACTIONAL,
        &decoded_size);
    EXPECT(decoded_size == sizeof(xtest_ignored_prefixes));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_XTEST);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_RTM));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_HLE));
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REPNE) != 0);
    EXPECT((instruction.opcode_flags & (CDISASM_PREFIX_EFFECTIVE_REP
            | CDISASM_PREFIX_EFFECTIVE_REPNE)) == 0);
#  if USE_DISASM_FORMAT
    {
        char text[32];

        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text));
        EXPECT(strcmp(text, "xtest") == 0);
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            text, sizeof(text));
        EXPECT(strcmp(text, "xtest") == 0);
    }
#  endif

    instruction = decode_mode_with_flags(
        CDISASM_CPU_IVY_BRIDGE, CDISASM_MODE_64,
        xend, sizeof(xend), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    instruction = decode_mode_with_flags(
        CDISASM_CPU_IVY_BRIDGE, CDISASM_MODE_64,
        xtest, sizeof(xtest), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    for (cpu_index = 0;
         cpu_index < sizeof(no_tsx_cpus) / sizeof(no_tsx_cpus[0]);
         ++cpu_index) {
        instruction = decode_mode_with_flags(
            no_tsx_cpus[cpu_index], CDISASM_MODE_64,
            xbegin32, sizeof(xbegin32), UINT64_C(0x1000),
            CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
        EXPECT(decoded_size == 0);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        instruction = decode_mode_with_flags(
            no_tsx_cpus[cpu_index], CDISASM_MODE_64,
            xend, sizeof(xend), UINT64_C(0x1000),
            CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
        EXPECT(decoded_size == 0);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        instruction = decode_mode_with_flags(
            no_tsx_cpus[cpu_index], CDISASM_MODE_64,
            xtest, sizeof(xtest), UINT64_C(0x1000),
            CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, &decoded_size);
        EXPECT(decoded_size == 0);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    }

    /* Group-9 memory forms use the exact VTX runtime route. */
    {
        cdisasm_x86_decode_flags vtx =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

        EXPECT(cdisasm_decode_flags_set_bit(
            &vtx, CDISASM_X86_DECODE_BIT_VTX));
        memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
        decoded_size = cdisasm_test_x86_decode_exact_flags(
            CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_64,
            vmxon, sizeof(vmxon), UINT64_C(0x1000),
            &vtx, &instruction);
        EXPECT(decoded_size == sizeof(vmxon));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VMXON);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_VTX));
        memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
        decoded_size = cdisasm_test_x86_decode_exact_flags(
            CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_64,
            vmptrst, sizeof(vmptrst), UINT64_C(0x1000),
            &vtx, &instruction);
    }
    EXPECT(decoded_size == sizeof(vmptrst));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VMPTRST);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_VTX));
#else
    static const struct disabled_case {
        const uint8_t *bytes;
        size_t size;
    } disabled_cases[] = {
        {rdrand_eax, sizeof(rdrand_eax)},
        {rdseed_r11, sizeof(rdseed_r11)},
        {xbegin32, sizeof(xbegin32)},
        {xbegin32_wrap, sizeof(xbegin32_wrap)},
        {xbegin16, sizeof(xbegin16)},
        {xbegin_66_rex32, sizeof(xbegin_66_rex32)},
        {xbegin_rex_66_16, sizeof(xbegin_rex_66_16)},
        {xabort, sizeof(xabort)},
        {xabort_ignored_prefixes, sizeof(xabort_ignored_prefixes)},
        {xend, sizeof(xend)},
        {xend_ignored_prefixes, sizeof(xend_ignored_prefixes)},
        {xtest, sizeof(xtest)},
        {xtest_ignored_prefixes, sizeof(xtest_ignored_prefixes)},
        {vmptrst, sizeof(vmptrst)}
    };
    size_t index;

    for (index = 0;
         index < sizeof(disabled_cases) / sizeof(disabled_cases[0]);
         ++index) {
        instruction = decode_mode_with_flags(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            disabled_cases[index].bytes, disabled_cases[index].size,
            UINT64_C(0x1000), CDISASM_X86_DECODE_FLAG_BASE,
            &decoded_size);
        EXPECT(decoded_size == 0);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    }
    (void)rdrand_ax;
    (void)rdrand_r11;
    (void)xbegin16_cross_64k;
    (void)vmxon;
#endif
}

static void test_evex_metadata_and_formatting(void)
{
    static const uint8_t masked[] = {0x62, 0xf1, 0x6c, 0xc9, 0x58, 0xcb};
    static const uint8_t broadcast[] = {0x62, 0xf1, 0x6c, 0xd9, 0x58, 0x08};
    static const uint8_t compressed_broadcast[] = {
        0x62, 0xf1, 0x6c, 0xd9, 0x58, 0x48, 0x01
    };
    static const uint8_t rounding[] = {0x62, 0xf1, 0x6c, 0xb9, 0x58, 0xcb};

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_one(
        CDISASM_CPU_SKYLAKE_SP, masked, sizeof(masked), &decoded_size);

    EXPECT(decoded_size == sizeof(masked));
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0);
    EXPECT(instruction.mask_reg == CDISASM_X86_REG_K1);
    EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ZMM1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ZMM2);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_ZMM3);

    instruction = decode_one(
        CDISASM_CPU_SKYLAKE_SP,
        broadcast, sizeof(broadcast), &decoded_size);
    EXPECT(decoded_size == sizeof(broadcast));
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[2].size == 4);
    EXPECT(instruction.opcode[2].broadcast == CDISASM_X86_BROADCAST_1_TO_16);

    instruction = decode_one(
        CDISASM_CPU_SKYLAKE_SP,
        compressed_broadcast, sizeof(compressed_broadcast), &decoded_size);
    EXPECT(decoded_size == sizeof(compressed_broadcast));
    EXPECT((int64_t)instruction.opcode[2].imm == INT64_C(4));

    instruction = decode_one(
        CDISASM_CPU_SKYLAKE_SP,
        rounding, sizeof(rounding), &decoded_size);
    EXPECT(decoded_size == sizeof(rounding));
    EXPECT(instruction.rounding == CDISASM_X86_ROUNDING_RD);
    EXPECT(instruction.sae == CDISASM_X86_SAE_ENABLED);

#  if USE_DISASM_FORMAT
    {
        char text[128];

        instruction = decode_one(
            CDISASM_CPU_SKYLAKE_SP,
            masked, sizeof(masked), &decoded_size);
        EXPECT(cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text)) == strlen(
                "vaddps zmm1 {k1}{z}, zmm2, zmm3"));
        EXPECT(strcmp(text, "vaddps zmm1 {k1}{z}, zmm2, zmm3") == 0);

        instruction = decode_one(
            CDISASM_CPU_SKYLAKE_SP,
            broadcast, sizeof(broadcast), &decoded_size);
        (void)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text));
        EXPECT(strcmp(text,
            "vaddps zmm1 {k1}{z}, zmm2, dword ptr [rax]{1to16}") == 0);

        instruction = decode_one(
            CDISASM_CPU_SKYLAKE_SP,
            rounding, sizeof(rounding), &decoded_size);
        (void)cdisasm_x86_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_X86_INTEL
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text));
        EXPECT(strcmp(text,
            "VADDPS zmm1 {k1}{z}, zmm2, zmm3, {rd-sae}") == 0);
    }
#  endif
#else
    (void)masked;
    (void)broadcast;
    (void)compressed_broadcast;
    (void)rounding;
#  if USE_DISASM_FORMAT
    {
        cdisasm_instruction synthetic;
        char text[32] = "not empty";

        memset(&synthetic, 0, sizeof(synthetic));
        synthetic.opcode_size = 1;
        synthetic.name_id = CDISASM_X86_NAME_VPCLMULQDQ;
        EXPECT(cdisasm_x86_format(
            &synthetic, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            text, sizeof(text)) == 0);
        EXPECT(text[0] == '\0');
    }
#  endif
#endif
}

static void test_structural_statuses(void)
{
    static const uint8_t evex_truncated[] = {0x62, 0xf1, 0x6c, 0xc9, 0x58};
    static const uint8_t evex_bad_ll[] = {0x62, 0xf1, 0x6c, 0xe9, 0x58, 0xcb};
    static const uint8_t evex_bad_zero[] = {0x62, 0xf1, 0x6c, 0xc8, 0x58, 0xcb};
    static const uint8_t apx_truncated[] = {0x62, 0xec, 0xf4, 0x10, 0x01};
    static const uint8_t apx_reserved[] = {0x62, 0xec, 0xf4, 0x90, 0x01, 0xd3};
    static const uint8_t rex2_truncated_prefix[] = {0xd5};
    static const uint8_t rex2_truncated_modrm[] = {0xd5, 0x58, 0x01};
    static const uint8_t f16c_truncated[] = {0xc4, 0xe3, 0x7d, 0x1d, 0xc8};
    static const uint8_t xop_truncated[] = {0x8f, 0xe8, 0x78, 0xc0, 0xca};
    static const uint8_t vpshufb_truncated[] = {0xc4, 0xe2, 0x69, 0x00};
    static const uint8_t vpalignr_truncated[] = {
        0xc4, 0xe3, 0x69, 0x0f, 0xcb
    };
    static const uint8_t vaesenc_truncated[] = {0xc4, 0xe2, 0x69, 0xdc};
    static const uint8_t vpclmul_truncated[] = {
        0xc4, 0xe3, 0x69, 0x44, 0xcb
    };
    static const uint8_t rdrand_bad_repeat[] = {
        0xf2, 0x0f, 0xc7, 0xf0
    };
    static const uint8_t group9_register_reserved[] = {
        0x0f, 0xc7, 0xc0
    };
    static const uint8_t cmpxchg8b_register_invalid[] = {
        0x0f, 0xc7, 0xc8
    };
    static const uint8_t xsaves_register_invalid[] = {
        0x0f, 0xc7, 0xe8
    };
    static const uint8_t rdrand_lock_invalid[] = {
        0xf0, 0x0f, 0xc7, 0xf0
    };
    static const uint8_t rdseed_lock_invalid[] = {
        0xf0, 0x0f, 0xc7, 0xf8
    };
    static const uint8_t rdpid_uncovered[] = {
        0xf3, 0x0f, 0xc7, 0xf8
    };
    static const uint8_t rdpid_lock_invalid[] = {
        0xf0, 0xf3, 0x0f, 0xc7, 0xf8
    };
    static const uint8_t vmptrst_66_invalid[] = {
        0x66, 0x0f, 0xc7, 0x38
    };
    static const uint8_t vmptrst_f2_invalid[] = {
        0xf2, 0x0f, 0xc7, 0x38
    };
    static const uint8_t rdpid_memory_invalid[] = {
        0xf3, 0x0f, 0xc7, 0x38
    };
    static const uint8_t xabort_truncated[] = {0xc6, 0xf8};
    static const uint8_t xbegin_truncated[] = {0xc7, 0xf8, 0x00};
    static const uint8_t xabort_lock_invalid[] = {
        0xf0, 0xc6, 0xf8, 0x0d
    };
    static const uint8_t xbegin_lock_invalid[] = {
        0xf0, 0xc7, 0xf8, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t xbegin_66_rex32_truncated[] = {
        0x66, 0x48, 0xc7, 0xf8, 0x00, 0x00
    };
    static const uint8_t xbegin_rex_66_16_truncated[] = {
        0x48, 0x66, 0xc7, 0xf8, 0x00
    };
    static const uint8_t xabort_bad_modrm[] = {0xc6, 0xf9, 0x0d};
    static const uint8_t xend_lock_invalid[] = {
        0xf0, 0x0f, 0x01, 0xd5
    };
    static const uint8_t xtest_lock_invalid[] = {
        0xf0, 0x0f, 0x01, 0xd6
    };
    static const uint8_t senduipi_uncovered[] = {0xf3, 0x0f, 0xc7, 0xf0};
    static const uint8_t senduipi_66_uncovered[] = {
        0x66, 0xf3, 0x0f, 0xc7, 0xf0
    };
    static const uint8_t senduipi_lock_invalid[] = {
        0xf0, 0xf3, 0x0f, 0xc7, 0xf0
    };
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    expect_status(evex_truncated, sizeof(evex_truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_status(evex_bad_ll, sizeof(evex_bad_ll),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(evex_bad_zero, sizeof(evex_bad_zero),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(apx_truncated, sizeof(apx_truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_status(apx_reserved, sizeof(apx_reserved),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(rex2_truncated_prefix, sizeof(rex2_truncated_prefix),
        CDISASM_STATUS_TRUNCATED);
    expect_status(rex2_truncated_modrm, sizeof(rex2_truncated_modrm),
        CDISASM_STATUS_TRUNCATED);
    expect_status(f16c_truncated, sizeof(f16c_truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_status(xop_truncated, sizeof(xop_truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_status(vpshufb_truncated, sizeof(vpshufb_truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_status(vpalignr_truncated, sizeof(vpalignr_truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_status(vaesenc_truncated, sizeof(vaesenc_truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_status(vpclmul_truncated, sizeof(vpclmul_truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_status(rdrand_bad_repeat, sizeof(rdrand_bad_repeat),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(group9_register_reserved, sizeof(group9_register_reserved),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(
        cmpxchg8b_register_invalid, sizeof(cmpxchg8b_register_invalid),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(xsaves_register_invalid, sizeof(xsaves_register_invalid),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(rdrand_lock_invalid, sizeof(rdrand_lock_invalid),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(rdseed_lock_invalid, sizeof(rdseed_lock_invalid),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(rdpid_uncovered, sizeof(rdpid_uncovered),
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status(rdpid_lock_invalid, sizeof(rdpid_lock_invalid),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(vmptrst_66_invalid, sizeof(vmptrst_66_invalid),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(vmptrst_f2_invalid, sizeof(vmptrst_f2_invalid),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(rdpid_memory_invalid, sizeof(rdpid_memory_invalid),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(xabort_truncated, sizeof(xabort_truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_status(xbegin_truncated, sizeof(xbegin_truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_status(xabort_lock_invalid, sizeof(xabort_lock_invalid),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(xbegin_lock_invalid, sizeof(xbegin_lock_invalid),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(
        xbegin_66_rex32_truncated, sizeof(xbegin_66_rex32_truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_status(
        xbegin_rex_66_16_truncated, sizeof(xbegin_rex_66_16_truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_status(xabort_bad_modrm, sizeof(xabort_bad_modrm),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(xend_lock_invalid, sizeof(xend_lock_invalid),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(xtest_lock_invalid, sizeof(xtest_lock_invalid),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(senduipi_uncovered, sizeof(senduipi_uncovered),
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status(senduipi_66_uncovered, sizeof(senduipi_66_uncovered),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status(senduipi_lock_invalid, sizeof(senduipi_lock_invalid),
        CDISASM_STATUS_INVALID_INSTRUCTION);

    instruction = decode_mode_with_flags(
        CDISASM_CPU_X86, CDISASM_MODE_32,
        senduipi_uncovered, sizeof(senduipi_uncovered), UINT64_C(0x1000),
        CDISASM_X86_DECODE_FLAG_BASE, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
}

static void test_decode_flag_contract(void)
{
    static const uint8_t vaddps[] = {0xc5, 0xe8, 0x58, 0xcb};
    cdisasm_instruction instruction;
    uint32_t decoded_size;

    instruction = decode_one_with_flags(
        CDISASM_CPU_X86, vaddps, sizeof(vaddps),
        CDISASM_X86_DECODE_FLAG_BASE, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));

#if USE_EXTRA_OPCODES
    instruction = decode_one_with_flags(
        CDISASM_CPU_X86, vaddps, sizeof(vaddps),
        CDISASM_X86_DECODE_FLAG_AVX, &decoded_size);
    EXPECT(decoded_size == sizeof(vaddps));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VADDPS);

    instruction = decode_one_with_flags(
        CDISASM_CPU_X86, vaddps, sizeof(vaddps),
        CDISASM_X86_DECODE_FLAG_SSE2, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));

    instruction = decode_one_with_flags(
        CDISASM_CPU_X86, vaddps, sizeof(vaddps),
        CDISASM_X86_DECODE_FLAG_ALL, &decoded_size);
    EXPECT(decoded_size == sizeof(vaddps));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
#else
    instruction = decode_one_with_flags(
        CDISASM_CPU_X86, vaddps, sizeof(vaddps),
        CDISASM_X86_DECODE_FLAG_AVX, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    instruction = decode_one_with_flags(
        CDISASM_CPU_X86, vaddps, sizeof(vaddps),
        CDISASM_X86_DECODE_FLAG_ALL, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));
#endif

    instruction = decode_one_with_flags(
        CDISASM_CPU_X86, vaddps, sizeof(vaddps),
        CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16, &decoded_size);
    EXPECT(decoded_size == 0);
#if USE_EXTRA_OPCODES
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#else
    EXPECT(is_error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));
#endif
}

static void test_low_end_crypto_profiles(void)
{
    static const uint8_t aesenc[] = {0x66, 0x0f, 0x38, 0xdc, 0xca};
    static const uint8_t pclmul[] = {
        0x66, 0x0f, 0x3a, 0x44, 0xca, 0x01
    };
    static const uint8_t sha1msg1[] = {0x0f, 0x38, 0xc9, 0xca};
    static const cdisasm_cpu_id aes_pclmul_cpus[] = {
        CDISASM_CPU_CELERON_G3900,
        CDISASM_CPU_CELERON_G5900
    };
    static const cdisasm_cpu_id atom_crypto_cpus[] = {
        CDISASM_CPU_CELERON_N3350,
        CDISASM_CPU_CELERON_N4020,
        CDISASM_CPU_PENTIUM_SILVER_N6000
    };
    size_t index;

#if USE_EXTRA_OPCODES
    for (index = 0;
         index < sizeof(aes_pclmul_cpus) / sizeof(aes_pclmul_cpus[0]);
         ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_one(
            aes_pclmul_cpus[index], aesenc, sizeof(aesenc), &decoded_size);

        EXPECT(decoded_size == sizeof(aesenc));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_AESENC);
        instruction = decode_one(
            aes_pclmul_cpus[index], pclmul, sizeof(pclmul), &decoded_size);
        EXPECT(decoded_size == sizeof(pclmul));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PCLMULQDQ);
        instruction = decode_one(
            aes_pclmul_cpus[index], sha1msg1, sizeof(sha1msg1), &decoded_size);
        EXPECT(decoded_size == 0);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 0;
         index < sizeof(atom_crypto_cpus) / sizeof(atom_crypto_cpus[0]);
         ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_one(
            atom_crypto_cpus[index], aesenc, sizeof(aesenc), &decoded_size);

        EXPECT(decoded_size == sizeof(aesenc));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_AESENC);
        instruction = decode_one(
            atom_crypto_cpus[index], pclmul, sizeof(pclmul), &decoded_size);
        EXPECT(decoded_size == sizeof(pclmul));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PCLMULQDQ);
        instruction = decode_one(
            atom_crypto_cpus[index], sha1msg1, sizeof(sha1msg1), &decoded_size);
        EXPECT(decoded_size == sizeof(sha1msg1));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_SHA1MSG1);
    }
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_one(
            CDISASM_CPU_CELERON_G1840,
            aesenc, sizeof(aesenc), &decoded_size);

        EXPECT(decoded_size == 0);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
        instruction = decode_one(
            CDISASM_CPU_CELERON_G1840,
            pclmul, sizeof(pclmul), &decoded_size);
        EXPECT(decoded_size == 0);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
        instruction = decode_one(
            CDISASM_CPU_CELERON_G1840,
            sha1msg1, sizeof(sha1msg1), &decoded_size);
        EXPECT(decoded_size == 0);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#else
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_one(
            CDISASM_CPU_CELERON_G3900,
            aesenc, sizeof(aesenc), &decoded_size);

        EXPECT(decoded_size == 0);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode_one(
            CDISASM_CPU_CELERON_N3350,
            pclmul, sizeof(pclmul), &decoded_size);
        EXPECT(decoded_size == 0);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode_one(
            CDISASM_CPU_PENTIUM_SILVER_N6000,
            sha1msg1, sizeof(sha1msg1), &decoded_size);
        EXPECT(decoded_size == 0);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    (void)aes_pclmul_cpus;
    (void)atom_crypto_cpus;
    (void)index;
#endif
}

static void test_apx_adx_forms(void)
{
    static const uint8_t adcx_reg64[] = {
        0x62, 0xec, 0xfd, 0x08, 0x66, 0xc1
    };
    static const uint8_t adox_n3_mem32[] = {
        0x62, 0xec, 0x6e, 0x10, 0x66, 0x1c, 0x24
    };
    static const uint8_t andn_reg64[] = {
        0x62, 0xea, 0xf4, 0x00, 0xf2, 0xc2
    };
    static const uint8_t andn_nf_mem32[] = {
        0x62, 0xea, 0x74, 0x04, 0xf2, 0x02
    };
    static const uint8_t andn_u0_register[] = {
        0x62, 0xea, 0x70, 0x00, 0xf2, 0xc2
    };
    static const uint8_t bextr_reg64[] = {
        0x62, 0xea, 0xec, 0x00, 0xf7, 0xc1
    };
    static const uint8_t bextr_nf_mem32[] = {
        0x62, 0xea, 0x6c, 0x04, 0xf7, 0x01
    };
    static const uint8_t blsi_reg64[] = {
        0x62, 0xfa, 0xfc, 0x00, 0xf3, 0xd9
    };
    static const uint8_t blsr_nf_mem32[] = {
        0x62, 0xfa, 0x7c, 0x04, 0xf3, 0x09
    };
    static const uint8_t bzhi_reg64[] = {
        0x62, 0xea, 0xec, 0x00, 0xf5, 0xc1
    };
    static const uint8_t bzhi_nf_mem32[] = {
        0x62, 0xea, 0x6c, 0x04, 0xf5, 0x01
    };
    static const uint8_t pext_reg64[] = {
        0x62, 0xea, 0xf6, 0x00, 0xf5, 0xc2
    };
    static const uint8_t mulx_mem32[] = {
        0x62, 0xea, 0x77, 0x00, 0xf6, 0x02
    };
    static const uint8_t rorx_reg64[] = {
        0x62, 0xeb, 0xff, 0x08, 0xf0, 0xc1, 0x07
    };
    static const uint8_t rorx_reserved_p2[] = {
        0x62, 0xeb, 0x7f, 0x0c, 0xf0, 0xc1, 0x07
    };
    static const uint8_t setb_reg_zu[] = {
        0x62, 0xfc, 0x7f, 0x18, 0x42, 0xc0
    };
    static const uint8_t setb_mem[] = {
        0x62, 0xfc, 0x7b, 0x08, 0x42, 0x00
    };
    static const uint8_t setb_u0_register[] = {
        0x62, 0xfc, 0x7b, 0x08, 0x42, 0xc0
    };
    static const uint8_t cmovb_reg64[] = {
        0x62, 0xec, 0xfc, 0x10, 0x42, 0xca
    };
    static const uint8_t cmovb_mem64[] = {
        0x62, 0xec, 0xf8, 0x10, 0x42, 0x0a
    };
    static const uint8_t cmovb_nd0[] = {
        0x62, 0xec, 0xfc, 0x08, 0x42, 0xca
    };
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_one_with_flags(
        CDISASM_CPU_APX, adcx_reg64, sizeof(adcx_reg64),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);

#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(adcx_reg64));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_ADCX);
    EXPECT(instruction.form_id == UINT16_C(19));
    EXPECT(instruction.operand_count == 2);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_ADX));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_ADX));
    EXPECT((instruction.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
        == (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, adox_n3_mem32, sizeof(adox_n3_mem32),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(adox_n3_mem32));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_ADOX);
    EXPECT(instruction.form_id == UINT16_C(149));
    EXPECT(instruction.operand_count == 3);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_ADX_N3));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, andn_reg64, sizeof(andn_reg64),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(andn_reg64));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_ANDN);
    EXPECT(instruction.form_id == UINT16_C(187));
    EXPECT(instruction.operand_count == 3);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_BMI1));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_BMI1));
    EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, andn_nf_mem32, sizeof(andn_nf_mem32),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(andn_nf_mem32));
    EXPECT(instruction.form_id == UINT16_C(186));
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NF) != 0);
    EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) == 0);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_BMI1_N3));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, andn_u0_register, sizeof(andn_u0_register),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, cmovb_reg64, sizeof(cmovb_reg64),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(cmovb_reg64));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_CMOVB);
    EXPECT(instruction.form_id == UINT16_C(726));
    EXPECT(instruction.operand_count == 3);
    EXPECT(instruction.opcode[0].reg == CDISASM_REG_R16);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.opcode[1].reg == CDISASM_REG_R17);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[2].reg == CDISASM_REG_R18);
    EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0);
    EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS) != 0);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_CMOV));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_N3));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, cmovb_mem64, sizeof(cmovb_mem64),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(cmovb_mem64));
    EXPECT(instruction.form_id == UINT16_C(727));
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[2].base_reg == CDISASM_REG_R18);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, cmovb_nd0, sizeof(cmovb_nd0),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, bextr_reg64, sizeof(bextr_reg64),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(bextr_reg64));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_BEXTR);
    EXPECT(instruction.form_id == UINT16_C(273));
    EXPECT(instruction.operand_count == 3);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_BMI1));
    EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, bextr_nf_mem32, sizeof(bextr_nf_mem32),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(bextr_nf_mem32));
    EXPECT(instruction.form_id == UINT16_C(272));
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NF) != 0);
    EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) == 0);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_BMI1_N3));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, blsi_reg64, sizeof(blsi_reg64),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(blsi_reg64));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_BLSI);
    EXPECT(instruction.form_id == UINT16_C(325));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_BMI1));
    EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, blsr_nf_mem32, sizeof(blsr_nf_mem32),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(blsr_nf_mem32));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_BLSR);
    EXPECT(instruction.form_id == UINT16_C(348));
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NF) != 0);
    EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) == 0);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_BMI1_N3));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, bzhi_reg64, sizeof(bzhi_reg64),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(bzhi_reg64));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_BZHI);
    EXPECT(instruction.form_id == UINT16_C(420));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_BMI2));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_BMI2));
    EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, bzhi_nf_mem32, sizeof(bzhi_nf_mem32),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(bzhi_nf_mem32));
    EXPECT(instruction.form_id == UINT16_C(419));
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NF) != 0);
    EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) == 0);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_BMI2_N3));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, pext_reg64, sizeof(pext_reg64),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(pext_reg64));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PEXT);
    EXPECT(instruction.form_id == UINT16_C(2108));
    EXPECT(instruction.operand_count == 3);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_BMI2));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_BMI2));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, mulx_mem32, sizeof(mulx_mem32),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(mulx_mem32));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_MULX);
    EXPECT(instruction.form_id == UINT16_C(1804));
    EXPECT(instruction.operand_count == 3);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_BMI2));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, rorx_reg64, sizeof(rorx_reg64),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(rorx_reg64));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_RORX);
    EXPECT(instruction.form_id == UINT16_C(2686));
    EXPECT(instruction.operand_count == 3);
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction.opcode[2].imm == UINT64_C(7));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_BMI2));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, rorx_reserved_p2, sizeof(rorx_reserved_p2),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, setb_reg_zu, sizeof(setb_reg_zu),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(setb_reg_zu));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_SETB);
    EXPECT(instruction.form_id == UINT16_C(2876));
    EXPECT(instruction.operand_count == 1);
    EXPECT(instruction.opcode[0].reg == CDISASM_REG_R16B);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_ZU) != 0);
    EXPECT((instruction.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS) != 0);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_N3));

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, setb_mem, sizeof(setb_mem),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == sizeof(setb_mem));
    EXPECT(instruction.form_id == UINT16_C(2878));
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_REG_R16);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_ZU) == 0);

    instruction = decode_one_with_flags(
        CDISASM_CPU_APX, setb_u0_register, sizeof(setb_u0_register),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));

    instruction = decode_one_with_flags(
        CDISASM_CPU_AVX10, setb_reg_zu, sizeof(setb_reg_zu),
        CDISASM_X86_DECODE_FLAG_APX, &decoded_size);
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
    (void)adox_n3_mem32;
    (void)andn_reg64;
    (void)andn_nf_mem32;
    (void)andn_u0_register;
    (void)bextr_reg64;
    (void)bextr_nf_mem32;
    (void)blsi_reg64;
    (void)blsr_nf_mem32;
    (void)bzhi_reg64;
    (void)bzhi_nf_mem32;
    (void)pext_reg64;
    (void)mulx_mem32;
    (void)rorx_reg64;
    (void)rorx_reserved_p2;
    (void)setb_reg_zu;
    (void)setb_mem;
    (void)setb_u0_register;
    (void)cmovb_reg64;
    (void)cmovb_mem64;
    (void)cmovb_nd0;
    EXPECT(decoded_size == 0);
    (void)instruction;
#endif
}

int main(void)
{
    test_semantic_families();
    test_apx_rex2_integer_core();
    test_entropy_and_rtm();
    test_evex_metadata_and_formatting();
    test_structural_statuses();
    test_decode_flag_contract();
    test_low_end_crypto_profiles();
    test_apx_adx_forms();

    if (failures != 0) {
        fprintf(stderr, "modern x86 tests failed: %d (extra=%d)\n",
            failures, USE_EXTRA_OPCODES);
        return 1;
    }
    printf("modern x86 tests passed (extra=%d)\n", USE_EXTRA_OPCODES);
    return 0;
}
