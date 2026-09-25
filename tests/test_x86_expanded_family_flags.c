#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_IFMA
                   == UINT64_C(0x2000000000),
               "AVX512_IFMA flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_VBMI
                   == UINT64_C(0x4000000000),
               "AVX512_VBMI flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_VNNI
                   == UINT64_C(0x8000000000),
               "AVX512_VNNI flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_VAES
                   == UINT64_C(0x10000000000),
               "VAES flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_VPCLMULQDQ
                   == UINT64_C(0x20000000000),
               "VPCLMULQDQ flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SHA512
                   == UINT64_C(0x40000000000),
               "SHA512 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_TILE
                   == UINT64_C(0x80000000000),
               "AMX_TILE flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_INT8
                   == UINT64_C(0x100000000000),
               "AMX_INT8 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_BF16
                   == UINT64_C(0x200000000000),
               "AMX_BF16 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_FP16
                   == UINT64_C(0x400000000000),
               "AMX_FP16 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_COMPLEX
                   == UINT64_C(0x800000000000),
               "AMX_COMPLEX flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_FP8
                   == UINT64_C(0x1000000000000),
               "AMX_FP8 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_MOVRS
                   == UINT64_C(0x2000000000000),
               "AMX_MOVRS flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_AVX512
                   == UINT64_C(0x4000000000000),
               "AMX_AVX512 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_DQ
                   == UINT64_C(0x8000000000000),
               "AVX512_DQ flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_BW
                   == UINT64_C(0x10000000000000),
               "AVX512_BW flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SMX
                   == UINT64_C(0x00800000),
               "SMX flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_VMX
                   == UINT64_C(0x20000000000000),
               "VMX flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SVM
                   == UINT64_C(0x40000000000000),
               "SVM flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_VIRTUALIZATION
                   == CDISASM_X86_DECODE_FLAG_SMX,
               "legacy virtualization alias changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_INTEL_VIRTUALIZATION
                   == CDISASM_X86_DECODE_FLAG_VMX,
               "Intel virtualization alias changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMD_VIRTUALIZATION
                   == CDISASM_X86_DECODE_FLAG_SVM,
               "AMD virtualization alias changed");
_Static_assert(
    (CDISASM_X86_DECODE_FLAG_SMX
        & (CDISASM_X86_DECODE_FLAG_VMX
            | CDISASM_X86_DECODE_FLAG_SVM)) == 0,
    "SMX must be independent of VMX and SVM");
_Static_assert(
    (CDISASM_X86_DECODE_FLAG_VMX & CDISASM_X86_DECODE_FLAG_SVM) == 0,
    "Intel VMX and AMD SVM must use independent bits");
_Static_assert(CDISASM_X86_GROUP_VMX != CDISASM_X86_GROUP_SVM,
               "Intel VMX and AMD SVM must use independent groups");
_Static_assert(CDISASM_X86_GROUP_SMX != CDISASM_X86_GROUP_VMX
                   && CDISASM_X86_GROUP_SMX != CDISASM_X86_GROUP_SVM,
               "Intel SMX must use an independent group");
_Static_assert(CDISASM_X86_DECODE_FLAG_SSE41
                   == UINT64_C(0x80000000000000),
               "SSE41 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SSE42
                   == UINT64_C(0x100000000000000),
               "SSE42 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SSE4A
                   == UINT64_C(0x200000000000000),
               "SSE4A flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_BMI1
                   == UINT64_C(0x400000000000000),
               "BMI1 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_BMI2
                   == UINT64_C(0x800000000000000),
               "BMI2 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_CD
                   == UINT64_C(0x1000000000000000),
               "AVX512_CD flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI
                   == UINT64_C(0x2000000000000000),
               "AVX_VNNI flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8
                   == UINT64_C(0x4000000000000000),
               "AVX_VNNI_INT8 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16
                   == UINT64_C(0x8000000000000000),
               "AVX_VNNI_INT16 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_ALL
                   == UINT64_C(0xffffffffffffffff),
               "expanded x86 flag mask changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_KNOWN_MASK
                   == UINT64_C(0xffffffffffffffff),
               "expanded x86 known mask changed");

#if USE_EXTRA_OPCODES
typedef struct family_case {
    const char *label;
    uint8_t bytes[8];
    uint8_t size;
    cdisasm_x86_decode_option specific;
    cdisasm_x86_decode_option umbrella;
    cdisasm_x86_name_id name_id;
} family_case;

static const family_case cases[] = {
    {"AVX512_IFMA", {0x62, 0xf2, 0xed, 0x49, 0xb4, 0xcb}, 6,
     CDISASM_X86_DECODE_FLAG_AVX512_IFMA,
     CDISASM_X86_DECODE_FLAG_AVX512, CDISASM_X86_NAME_VPMADD52LUQ},
    {"AVX512_VBMI", {0x62, 0xf2, 0x6d, 0xc9, 0x8d, 0xcb}, 6,
     CDISASM_X86_DECODE_FLAG_AVX512_VBMI,
     CDISASM_X86_DECODE_FLAG_AVX512, CDISASM_X86_NAME_VPERMB},
    {"AVX512_VNNI", {0x62, 0xf2, 0x6d, 0x49, 0x50, 0xcb}, 6,
     CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
     CDISASM_X86_DECODE_FLAG_AVX512, CDISASM_X86_NAME_VPDPBUSD},
    {"VAES", {0xc4, 0xe2, 0x6d, 0xdc, 0xcb}, 5,
     CDISASM_X86_DECODE_FLAG_VAES,
     CDISASM_X86_DECODE_FLAG_AES, CDISASM_X86_NAME_VAESENC},
    {"VPCLMULQDQ", {0xc4, 0xe3, 0x6d, 0x44, 0xcb, 0x11}, 6,
     CDISASM_X86_DECODE_FLAG_VPCLMULQDQ,
     CDISASM_X86_DECODE_FLAG_PCLMUL, CDISASM_X86_NAME_VPCLMULQDQ},
    {"SHA512", {0xc4, 0xe2, 0x7f, 0xcc, 0xca}, 5,
     CDISASM_X86_DECODE_FLAG_SHA512,
     CDISASM_X86_DECODE_FLAG_SHA, CDISASM_X86_NAME_VSHA512MSG1},
    {"AMX_TILE", {0xc4, 0xe2, 0x7b, 0x49, 0xd0}, 5,
     CDISASM_X86_DECODE_FLAG_AMX_TILE,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TILEZERO},
    {"AMX_INT8", {0xc4, 0xe2, 0x60, 0x5e, 0xca}, 5,
     CDISASM_X86_DECODE_FLAG_AMX_INT8,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TDPBUUD},
    {"AMX_BF16", {0xc4, 0xe2, 0x62, 0x5c, 0xca}, 5,
     CDISASM_X86_DECODE_FLAG_AMX_BF16,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TDPBF16PS},
    {"AMX_FP16", {0xc4, 0xe2, 0x63, 0x5c, 0xca}, 5,
     CDISASM_X86_DECODE_FLAG_AMX_FP16,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TDPFP16PS},
    {"AMX_COMPLEX", {0xc4, 0xe2, 0x68, 0x6c, 0xc1}, 5,
     CDISASM_X86_DECODE_FLAG_AMX_COMPLEX,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TCMMRLFP16PS},
    {"AMX_FP8", {0xc4, 0xe5, 0x68, 0xfd, 0xc1}, 5,
     CDISASM_X86_DECODE_FLAG_AMX_FP8,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TDPBF8PS},
    {"AMX_MOVRS", {0xc4, 0xe2, 0x7b, 0x4a, 0x04, 0x10}, 6,
     CDISASM_X86_DECODE_FLAG_AMX_MOVRS,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TILELOADDRS},
    {"AMX_AVX512", {0x62, 0xf2, 0x7d, 0x48, 0x4a, 0xc1}, 6,
     CDISASM_X86_DECODE_FLAG_AMX_AVX512,
     CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TILEMOVROW},
    {"AVX512_DQ", {0x62, 0xf2, 0xed, 0x4a, 0x40, 0xcb}, 6,
     CDISASM_X86_DECODE_FLAG_AVX512_DQ,
     CDISASM_X86_DECODE_FLAG_AVX512, CDISASM_X86_NAME_VPMULLQ},
    {"AVX512_BW", {0x62, 0xf1, 0x6d, 0xc9, 0xfc, 0xcb}, 6,
     CDISASM_X86_DECODE_FLAG_AVX512_BW,
     CDISASM_X86_DECODE_FLAG_AVX512, CDISASM_X86_NAME_VPADDB},
    {"SMX", {0x0f, 0x37}, 2,
     CDISASM_X86_DECODE_FLAG_SMX,
     CDISASM_X86_DECODE_FLAG_SMX, CDISASM_X86_NAME_GETSEC},
    {"VMX", {0x0f, 0x01, 0xc1}, 3,
     CDISASM_X86_DECODE_FLAG_VMX,
     CDISASM_X86_DECODE_FLAG_VMX, CDISASM_X86_NAME_VMCALL},
    {"SVM", {0x0f, 0x01, 0xd8}, 3,
     CDISASM_X86_DECODE_FLAG_SVM,
     CDISASM_X86_DECODE_FLAG_SVM, CDISASM_X86_NAME_VMRUN},
    {"SSE41", {0x66, 0x0f, 0x38, 0x17, 0xc1}, 5,
     CDISASM_X86_DECODE_FLAG_SSE41,
     CDISASM_X86_DECODE_FLAG_SSE4, CDISASM_X86_NAME_PTEST},
    {"SSE42", {0xf2, 0x0f, 0x38, 0xf0, 0xc1}, 5,
     CDISASM_X86_DECODE_FLAG_SSE42,
     CDISASM_X86_DECODE_FLAG_SSE4, CDISASM_X86_NAME_CRC32},
    {"SSE4A", {0x66, 0x0f, 0x78, 0xc1, 0x08, 0x04}, 6,
     CDISASM_X86_DECODE_FLAG_SSE4A,
     CDISASM_X86_DECODE_FLAG_SSE4, CDISASM_X86_NAME_EXTRQ},
    {"BMI1", {0xc4, 0xe2, 0x70, 0xf2, 0xc2}, 5,
     CDISASM_X86_DECODE_FLAG_BMI1,
     CDISASM_X86_DECODE_FLAG_BITMANIP, CDISASM_X86_NAME_ANDN},
    {"BMI2", {0xc4, 0xe2, 0x70, 0xf5, 0xc2}, 5,
     CDISASM_X86_DECODE_FLAG_BMI2,
     CDISASM_X86_DECODE_FLAG_BITMANIP, CDISASM_X86_NAME_BZHI},
    {"AVX512_CD", {0x62, 0xf2, 0x7d, 0x48, 0xc4, 0xcb}, 6,
     CDISASM_X86_DECODE_FLAG_AVX512_CD,
     CDISASM_X86_DECODE_FLAG_AVX512, CDISASM_X86_NAME_VPCONFLICTD}
};
#endif

static int failures;

#define EXPECT(expression) \
    do { \
        if (!(expression)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #expression); \
            ++failures; \
        } \
    } while (0)

static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static uint32_t decode_case(
    const family_case *test,
    cdisasm_x86_decode_option flags,
    cdisasm_instruction *instruction)
{
    return cdisasm_x86_decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        test->bytes, test->size, UINT64_C(0x1000), flags, instruction);
}

static void test_family_filters(void)
{
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const family_case *test = &cases[index];
        const cdisasm_x86_decode_option wrong =
            test->specific == CDISASM_X86_DECODE_FLAG_BMI1
                ? CDISASM_X86_DECODE_FLAG_VAES
                : CDISASM_X86_DECODE_FLAG_BMI1;
        cdisasm_instruction instruction;

        if (decode_case(test, test->specific, &instruction) != test->size
            || instruction.name_id != test->name_id) {
            fprintf(stderr, "%s: specific flag did not admit name %u\n",
                    test->label, (unsigned int)test->name_id);
            ++failures;
        }
        EXPECT(decode_case(test, test->umbrella, &instruction) == test->size);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(decode_case(test, wrong, &instruction) == 0);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
        EXPECT(decode_case(test, CDISASM_X86_DECODE_FLAG_BASE,
                           &instruction) == 0);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    }
}

static void expect_family_result(
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    cdisasm_x86_name_id expected_name,
    int admitted)
{
    cdisasm_instruction instruction;
    const uint32_t decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        bytes, size, UINT64_C(0x1000), flags, &instruction);

    if (admitted) {
        EXPECT(decoded_size == size);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == expected_name);
    } else {
        EXPECT(decoded_size == 0);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    }
}

static void expect_vtx_apx_result(
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_name_id expected_name)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_instruction instruction;
    uint32_t decoded_size;

    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_VTX));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_APX));
    decoded_size = cdisasm_test_x86_decode_exact_flags(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        bytes, size, UINT64_C(0x1000), &flags, &instruction);
    EXPECT(decoded_size == size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == expected_name);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_VTX));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
}

static void test_virtualization_family_isolation(void)
{
    static const uint8_t getsec[] = {0x0f, 0x37};
    static const uint8_t vmcall[] = {0x0f, 0x01, 0xc1};
    static const uint8_t vmrun[] = {0x0f, 0x01, 0xd8};
    static const uint8_t vmgexit[] = {0xf2, 0x0f, 0x01, 0xd9};
    static const uint8_t rex2_vmptrld[] = {0xd5, 0x90, 0xc7, 0x30};

    expect_family_result(
        vmcall, sizeof(vmcall),
        CDISASM_X86_DECODE_FLAG_INTEL_VIRTUALIZATION,
        CDISASM_X86_NAME_VMCALL, 1);
    expect_family_result(
        vmcall, sizeof(vmcall),
        CDISASM_X86_DECODE_FLAG_AMD_VIRTUALIZATION,
        CDISASM_X86_NAME_VMCALL, 0);
    expect_family_result(
        vmcall, sizeof(vmcall), CDISASM_X86_DECODE_FLAG_SMX,
        CDISASM_X86_NAME_VMCALL, 0);

    expect_family_result(
        vmrun, sizeof(vmrun),
        CDISASM_X86_DECODE_FLAG_AMD_VIRTUALIZATION,
        CDISASM_X86_NAME_VMRUN, 1);
    expect_family_result(
        vmrun, sizeof(vmrun),
        CDISASM_X86_DECODE_FLAG_INTEL_VIRTUALIZATION,
        CDISASM_X86_NAME_VMRUN, 0);
    expect_family_result(
        vmrun, sizeof(vmrun), CDISASM_X86_DECODE_FLAG_SMX,
        CDISASM_X86_NAME_VMRUN, 0);

    expect_family_result(
        vmgexit, sizeof(vmgexit),
        CDISASM_X86_DECODE_FLAG_AMD_VIRTUALIZATION,
        CDISASM_X86_NAME_VMGEXIT, 1);
    expect_family_result(
        vmgexit, sizeof(vmgexit),
        CDISASM_X86_DECODE_FLAG_INTEL_VIRTUALIZATION,
        CDISASM_X86_NAME_VMGEXIT, 0);

    expect_family_result(
        getsec, sizeof(getsec), CDISASM_X86_DECODE_FLAG_SMX,
        CDISASM_X86_NAME_GETSEC, 1);
    expect_family_result(
        getsec, sizeof(getsec),
        CDISASM_X86_DECODE_FLAG_INTEL_VIRTUALIZATION,
        CDISASM_X86_NAME_GETSEC, 0);
    expect_family_result(
        getsec, sizeof(getsec),
        CDISASM_X86_DECODE_FLAG_AMD_VIRTUALIZATION,
        CDISASM_X86_NAME_GETSEC, 0);

    /* REX2 transports the exact VTX form and independently requires APX. */
    expect_vtx_apx_result(
        rex2_vmptrld, sizeof(rex2_vmptrld),
        CDISASM_X86_NAME_VMPTRLD);
    expect_family_result(
        rex2_vmptrld, sizeof(rex2_vmptrld),
        CDISASM_X86_DECODE_FLAG_INTEL_VIRTUALIZATION
            | CDISASM_X86_DECODE_FLAG_APX,
        CDISASM_X86_NAME_VMPTRLD, 0);
    expect_family_result(
        rex2_vmptrld, sizeof(rex2_vmptrld),
        CDISASM_X86_DECODE_FLAG_APX,
        CDISASM_X86_NAME_VMPTRLD, 0);
    expect_family_result(
        rex2_vmptrld, sizeof(rex2_vmptrld),
        CDISASM_X86_DECODE_FLAG_AMD_VIRTUALIZATION,
        CDISASM_X86_NAME_VMPTRLD, 0);

    /* The historical spelling is retained as an exact SMX alias, not as a
     * vendor-crossing umbrella. */
    expect_family_result(
        getsec, sizeof(getsec), CDISASM_X86_DECODE_FLAG_VIRTUALIZATION,
        CDISASM_X86_NAME_GETSEC, 1);
    expect_family_result(
        vmcall, sizeof(vmcall), CDISASM_X86_DECODE_FLAG_VIRTUALIZATION,
        CDISASM_X86_NAME_VMCALL, 0);
    expect_family_result(
        vmrun, sizeof(vmrun), CDISASM_X86_DECODE_FLAG_VIRTUALIZATION,
        CDISASM_X86_NAME_VMRUN, 0);

    expect_family_result(
        getsec, sizeof(getsec), CDISASM_X86_DECODE_FLAG_SYSTEM,
        CDISASM_X86_NAME_GETSEC, 0);
    expect_family_result(
        vmcall, sizeof(vmcall), CDISASM_X86_DECODE_FLAG_SYSTEM,
        CDISASM_X86_NAME_VMCALL, 0);
    expect_family_result(
        vmrun, sizeof(vmrun), CDISASM_X86_DECODE_FLAG_SYSTEM,
        CDISASM_X86_NAME_VMRUN, 0);
}

static void expect_query_has(
    cdisasm_cpu_id cpu_id,
    cdisasm_x86_decode_option expected,
    cdisasm_x86_decode_option forbidden)
{
    const cdisasm_x86_decode_option flags =
        cdisasm_x86_cpu_decode_flag_mask(cpu_id, CDISASM_MODE_64);

    EXPECT((flags & expected) == expected);
    EXPECT((flags & forbidden) == 0);
    EXPECT((flags & ~CDISASM_X86_DECODE_FLAG_KNOWN_MASK) == 0);
}

static void expect_virtualization_query(
    cdisasm_cpu_id cpu_id,
    cdisasm_x86_decode_option expected)
{
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint32_t mode_bits[] = {
        CDISASM_X86_MODE_MASK_16,
        CDISASM_X86_MODE_MASK_32,
        CDISASM_X86_MODE_MASK_64
    };
    const cdisasm_x86_decode_option virtualization =
        CDISASM_X86_DECODE_FLAG_SMX
        | CDISASM_X86_DECODE_FLAG_INTEL_VIRTUALIZATION
        | CDISASM_X86_DECODE_FLAG_AMD_VIRTUALIZATION;
    const uint32_t available_modes = cdisasm_x86_cpu_mode_mask(cpu_id);
    size_t index;

    for (index = 0; index < sizeof(modes) / sizeof(modes[0]); ++index) {
        const cdisasm_x86_decode_option flags =
            cdisasm_x86_cpu_decode_flag_mask(cpu_id, modes[index]);
        const cdisasm_x86_decode_option actual = flags & virtualization;

        if ((available_modes & mode_bits[index]) != 0) {
            if (actual != expected) {
                fprintf(stderr,
                    "CPU 0x%08x mode %u: virtualization mask 0x%016llx, "
                    "expected 0x%016llx\n",
                    (unsigned int)cpu_id, (unsigned int)modes[index],
                    (unsigned long long)actual,
                    (unsigned long long)expected);
                ++failures;
            }
        } else {
            EXPECT(flags == CDISASM_X86_DECODE_FLAG_BASE);
        }
    }
}

static void test_virtualization_cpu_query_matrix(void)
{
    static const cdisasm_cpu_id no_virtualization[] = {
        CDISASM_CPU_8086,
        CDISASM_CPU_80186,
        CDISASM_CPU_80286,
        CDISASM_CPU_80386,
        CDISASM_CPU_80486,
        CDISASM_CPU_80486_CPUID,
        CDISASM_CPU_PENTIUM,
        CDISASM_CPU_PENTIUM_PRO,
        CDISASM_CPU_PENTIUM_MMX,
        CDISASM_CPU_PENTIUM_II,
        CDISASM_CPU_AMD_K6_2,
        CDISASM_CPU_PENTIUM_III,
        CDISASM_CPU_PENTIUM_4,
        CDISASM_CPU_ATHLON_64,
        CDISASM_CPU_PRESCOTT,
        CDISASM_CPU_8086_8087,
        CDISASM_CPU_80186_80187,
        CDISASM_CPU_80286_80287,
        CDISASM_CPU_80386_80387
    };
    static const cdisasm_cpu_id intel_vmx_only[] = {
        CDISASM_CPU_INTEL_VT_X,
        CDISASM_CPU_CELERON_G1840,
        CDISASM_CPU_CELERON_G3900,
        CDISASM_CPU_CELERON_N3350,
        CDISASM_CPU_CELERON_N4020,
        CDISASM_CPU_CELERON_G5900,
        CDISASM_CPU_PENTIUM_SILVER_N6000
    };
    static const cdisasm_cpu_id intel_vmx_smx[] = {
        CDISASM_CPU_CORE_2,
        CDISASM_CPU_PENRYN,
        CDISASM_CPU_NEHALEM,
        CDISASM_CPU_WESTMERE,
        CDISASM_CPU_SANDY_BRIDGE,
        CDISASM_CPU_IVY_BRIDGE,
        CDISASM_CPU_HASWELL,
        CDISASM_CPU_BROADWELL,
        CDISASM_CPU_SKYLAKE,
        CDISASM_CPU_GOLDMONT,
        CDISASM_CPU_SKYLAKE_SP,
        CDISASM_CPU_ICE_LAKE,
        CDISASM_CPU_TIGER_LAKE,
        CDISASM_CPU_ALDER_LAKE,
        CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_CPU_AVX10,
        CDISASM_CPU_APX,
        CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_ARROW_LAKE,
        CDISASM_CPU_DIAMOND_RAPIDS,
        CDISASM_CPU_KNIGHTS_MILL
    };
    static const cdisasm_cpu_id amd_svm_only[] = {
        CDISASM_CPU_AMD_V,
        CDISASM_CPU_AMD_BARCELONA,
        CDISASM_CPU_AMD_BULLDOZER,
        CDISASM_CPU_AMD_ZEN,
        CDISASM_CPU_AMD_ZEN_4
    };
    _Static_assert(
        1u
                + sizeof(no_virtualization)
                    / sizeof(no_virtualization[0])
                + sizeof(intel_vmx_only) / sizeof(intel_vmx_only[0])
                + sizeof(intel_vmx_smx) / sizeof(intel_vmx_smx[0])
                + sizeof(amd_svm_only) / sizeof(amd_svm_only[0])
            == CDISASM_CPU_ORDINAL_OF(CDISASM_CPU_LAST) + 1u,
        "virtualization matrix must cover every x86 CPU profile");
    const cdisasm_x86_decode_option intel =
        CDISASM_X86_DECODE_FLAG_INTEL_VIRTUALIZATION;
    const cdisasm_x86_decode_option amd =
        CDISASM_X86_DECODE_FLAG_AMD_VIRTUALIZATION;
    const cdisasm_x86_decode_option smx = CDISASM_X86_DECODE_FLAG_SMX;
    size_t index;

    expect_virtualization_query(CDISASM_CPU_X86, intel | amd | smx);
    for (index = 0;
         index < sizeof(no_virtualization) / sizeof(no_virtualization[0]);
         ++index) {
        expect_virtualization_query(
            no_virtualization[index], CDISASM_X86_DECODE_FLAG_BASE);
    }
    for (index = 0;
         index < sizeof(intel_vmx_only) / sizeof(intel_vmx_only[0]);
         ++index) {
        expect_virtualization_query(intel_vmx_only[index], intel);
    }
    for (index = 0;
         index < sizeof(intel_vmx_smx) / sizeof(intel_vmx_smx[0]);
         ++index) {
        expect_virtualization_query(intel_vmx_smx[index], intel | smx);
    }
    for (index = 0;
         index < sizeof(amd_svm_only) / sizeof(amd_svm_only[0]);
         ++index) {
        expect_virtualization_query(amd_svm_only[index], amd);
    }
}

static void test_cpu_queries(void)
{
    const cdisasm_x86_decode_option all_amx_specific =
        CDISASM_X86_DECODE_FLAG_AMX_TILE
        | CDISASM_X86_DECODE_FLAG_AMX_INT8
        | CDISASM_X86_DECODE_FLAG_AMX_BF16
        | CDISASM_X86_DECODE_FLAG_AMX_FP16
        | CDISASM_X86_DECODE_FLAG_AMX_COMPLEX
        | CDISASM_X86_DECODE_FLAG_AMX_FP8
        | CDISASM_X86_DECODE_FLAG_AMX_MOVRS
        | CDISASM_X86_DECODE_FLAG_AMX_AVX512;
    const cdisasm_x86_decode_option implemented64 =
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
               CDISASM_CPU_X86, CDISASM_MODE_64) == implemented64);
    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_X86, CDISASM_MODE_32)
            & (all_amx_specific | CDISASM_X86_DECODE_FLAG_AMX
                | CDISASM_X86_DECODE_FLAG_APX)) == 0);

    expect_query_has(
        CDISASM_CPU_INTEL_VT_X, CDISASM_X86_DECODE_FLAG_VMX,
        CDISASM_X86_DECODE_FLAG_SVM | CDISASM_X86_DECODE_FLAG_SMX);
    expect_query_has(
        CDISASM_CPU_AMD_V, CDISASM_X86_DECODE_FLAG_SVM,
        CDISASM_X86_DECODE_FLAG_VMX | CDISASM_X86_DECODE_FLAG_SMX);
    expect_query_has(
        CDISASM_CPU_CORE_2,
        CDISASM_X86_DECODE_FLAG_VMX | CDISASM_X86_DECODE_FLAG_SMX,
        CDISASM_X86_DECODE_FLAG_SVM);
    expect_query_has(
        CDISASM_CPU_PENRYN, CDISASM_X86_DECODE_FLAG_SSE41,
        CDISASM_X86_DECODE_FLAG_SSE42 | CDISASM_X86_DECODE_FLAG_SSE4A);
    expect_query_has(
        CDISASM_CPU_AMD_BARCELONA, CDISASM_X86_DECODE_FLAG_SSE4A,
        CDISASM_X86_DECODE_FLAG_SSE41 | CDISASM_X86_DECODE_FLAG_SSE42);
    expect_query_has(
        CDISASM_CPU_NEHALEM,
        CDISASM_X86_DECODE_FLAG_SSE41 | CDISASM_X86_DECODE_FLAG_SSE42,
        CDISASM_X86_DECODE_FLAG_SSE4A);
    expect_query_has(
        CDISASM_CPU_HASWELL,
        CDISASM_X86_DECODE_FLAG_BMI1 | CDISASM_X86_DECODE_FLAG_BMI2,
        CDISASM_X86_DECODE_FLAG_AVX512_IFMA);
    expect_query_has(
        CDISASM_CPU_ICE_LAKE,
        CDISASM_X86_DECODE_FLAG_AVX512_IFMA
            | CDISASM_X86_DECODE_FLAG_AVX512_VBMI
            | CDISASM_X86_DECODE_FLAG_AVX512_VNNI
            | CDISASM_X86_DECODE_FLAG_AVX512_DQ
            | CDISASM_X86_DECODE_FLAG_AVX512_BW
            | CDISASM_X86_DECODE_FLAG_VAES
            | CDISASM_X86_DECODE_FLAG_VPCLMULQDQ,
        CDISASM_X86_DECODE_FLAG_AMX_TILE);
    expect_query_has(
        CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_X86_DECODE_FLAG_AMX_TILE
            | CDISASM_X86_DECODE_FLAG_AMX_INT8
            | CDISASM_X86_DECODE_FLAG_AMX_BF16,
        CDISASM_X86_DECODE_FLAG_AMX_FP16
            | CDISASM_X86_DECODE_FLAG_AMX_COMPLEX);
    expect_query_has(
        CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_X86_DECODE_FLAG_AMX_FP16
            | CDISASM_X86_DECODE_FLAG_AMX_COMPLEX,
        CDISASM_X86_DECODE_FLAG_AMX_FP8
            | CDISASM_X86_DECODE_FLAG_AMX_MOVRS);
    expect_query_has(
        CDISASM_CPU_DIAMOND_RAPIDS, all_amx_specific,
        CDISASM_X86_DECODE_FLAG_BASE);
    test_virtualization_cpu_query_matrix();
}

static void test_full_width_bits(void)
{
    static const uint8_t nop[] = {0x90};
    cdisasm_instruction instruction;

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_X86, CDISASM_MODE_64,
               nop, sizeof(nop), 0,
               CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8,
               &instruction) == sizeof(nop));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_X86, CDISASM_MODE_64,
               nop, sizeof(nop), 0,
               CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16,
               &instruction) == sizeof(nop));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
}

static void test_avx_ne_convert_family_flags(void)
{
    static const uint8_t bytes[] = {0xc4, 0xe2, 0x7a, 0x72, 0xc1};
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_instruction instruction;

    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_AVX));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_AVX_NE_CONVERT));
    EXPECT(cdisasm_test_x86_decode_exact_flags(
               CDISASM_CPU_X86, CDISASM_MODE_64,
               bytes, sizeof(bytes), UINT64_C(0x1000),
               &flags, &instruction) == sizeof(bytes));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VCVTNEPS2BF16);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX_NE_CONVERT));

    flags = (cdisasm_x86_decode_flags)
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_AVX));
    EXPECT(cdisasm_test_x86_decode_exact_flags(
               CDISASM_CPU_X86, CDISASM_MODE_64,
               bytes, sizeof(bytes), UINT64_C(0x1000),
               &flags, &instruction) == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
}
#else
static void test_disabled_contract(void)
{
    static const uint8_t nop[] = {0x90};
    static const cdisasm_x86_decode_option rejected[] = {
        CDISASM_X86_DECODE_FLAG_SMX,
        CDISASM_X86_DECODE_FLAG_INTEL_VIRTUALIZATION,
        CDISASM_X86_DECODE_FLAG_AMD_VIRTUALIZATION,
        CDISASM_X86_DECODE_FLAG_AVX512_IFMA,
        CDISASM_X86_DECODE_FLAG_BMI2,
        CDISASM_X86_DECODE_FLAG_AVX512_CD,
        CDISASM_X86_DECODE_FLAG_ALL,
        CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8,
        CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16
    };
    size_t index;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
               CDISASM_CPU_X86, CDISASM_MODE_64)
        == CDISASM_X86_DECODE_FLAG_BASE);
    for (index = 0; index < sizeof(rejected) / sizeof(rejected[0]); ++index) {
        cdisasm_instruction instruction;

        EXPECT(cdisasm_x86_decode(
                   CDISASM_CPU_X86, CDISASM_MODE_64,
                   nop, sizeof(nop), 0, rejected[index], &instruction) == 0);
        EXPECT(is_error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    }
}
#endif

int main(void)
{
#if !USE_EXTRA_OPCODES
    test_disabled_contract();
#else
    test_family_filters();
    test_virtualization_family_isolation();
    test_cpu_queries();
    test_full_width_bits();
    test_avx_ne_convert_family_flags();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d expanded family-flag test(s) failed\n", failures);
        return 1;
    }
#if USE_EXTRA_OPCODES
    puts("expanded x86 runtime family-flag tests passed");
#else
    puts("disabled x86 runtime family-flag contract tests passed");
#endif
    return 0;
}
