#include "cdisasm/cdisasm.h"
#include "cdisasm_cpu_detect_internal.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

static void expect_cpu(
    const char *case_name,
    cdisasm_cpu_id actual,
    cdisasm_cpu_id expected)
{
    if (actual != expected) {
        fprintf(stderr,
            "%s: expected 0x%08" PRIx32 ", got 0x%08" PRIx32 "\n",
            case_name,
            (uint32_t)expected,
            (uint32_t)actual);
        ++failures;
    }
}

#if USE_ARCH_ARM
static void expect_boolean(
    const char *case_name,
    int actual,
    int expected)
{
    if ((actual != 0) != (expected != 0)) {
        fprintf(stderr, "%s: expected %d, got %d\n",
            case_name, expected != 0, actual != 0);
        ++failures;
    }
}
#endif

#if USE_ARCH_X86

#define X86_VENDOR_INTEL_EBX UINT32_C(0x756e6547)
#define X86_VENDOR_INTEL_EDX UINT32_C(0x49656e69)
#define X86_VENDOR_INTEL_ECX UINT32_C(0x6c65746e)
#define X86_VENDOR_AMD_EBX UINT32_C(0x68747541)
#define X86_VENDOR_AMD_EDX UINT32_C(0x69746e65)
#define X86_VENDOR_AMD_ECX UINT32_C(0x444d4163)

#define X86_FEATURE_1_ECX_SSE3 (UINT32_C(1) << 0)
#define X86_FEATURE_1_ECX_VMX (UINT32_C(1) << 5)
#define X86_FEATURE_1_ECX_AVX (UINT32_C(1) << 28)
#define X86_FEATURE_1_ECX_HYPERVISOR (UINT32_C(1) << 31)
#define X86_FEATURE_1_EDX_FPU (UINT32_C(1) << 0)
#define X86_FEATURE_1_EDX_MMX (UINT32_C(1) << 23)
#define X86_FEATURE_1_EDX_SSE (UINT32_C(1) << 25)
#define X86_FEATURE_7_EBX_AVX512F (UINT32_C(1) << 16)
#define X86_FEATURE_7_1_EDX_AVX10 (UINT32_C(1) << 19)
#define X86_FEATURE_7_1_EDX_APX_F (UINT32_C(1) << 21)
#define X86_FEATURE_EXT1_ECX_SVM (UINT32_C(1) << 2)
#define X86_FEATURE_EXT1_EDX_LM (UINT32_C(1) << 29)
#define X86_FEATURE_EXT1_EDX_3DNOW (UINT32_C(1) << 31)

static uint32_t x86_signature(
    uint32_t display_family,
    uint32_t display_model,
    uint32_t stepping)
{
    uint32_t base_family;
    uint32_t extended_family = 0;
    uint32_t extended_model = 0;

    if (display_family >= UINT32_C(0x0f)) {
        base_family = UINT32_C(0x0f);
        extended_family = display_family - UINT32_C(0x0f);
    } else {
        base_family = display_family;
    }
    if (base_family == UINT32_C(0x06)
        || base_family == UINT32_C(0x0f)) {
        extended_model = (display_model >> 4) & UINT32_C(0x0f);
    }

    return (stepping & UINT32_C(0x0f))
        | ((display_model & UINT32_C(0x0f)) << 4)
        | ((base_family & UINT32_C(0x0f)) << 8)
        | (extended_model << 16)
        | ((extended_family & UINT32_C(0xff)) << 20);
}

static cdisasm_internal_x86_cpu_snapshot x86_intel(
    uint32_t family,
    uint32_t model)
{
    cdisasm_internal_x86_cpu_snapshot snapshot;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.max_basic_leaf = UINT32_C(0x24);
    snapshot.max_extended_leaf = UINT32_C(0x80000008);
    snapshot.vendor_ebx = X86_VENDOR_INTEL_EBX;
    snapshot.vendor_edx = X86_VENDOR_INTEL_EDX;
    snapshot.vendor_ecx = X86_VENDOR_INTEL_ECX;
    snapshot.leaf1_eax = x86_signature(family, model, 1);
    snapshot.leaf1_ecx = X86_FEATURE_1_ECX_AVX;
    snapshot.leaf1_edx = X86_FEATURE_1_EDX_MMX | X86_FEATURE_1_EDX_SSE;
    return snapshot;
}

static cdisasm_internal_x86_cpu_snapshot x86_amd(
    uint32_t family,
    uint32_t model)
{
    cdisasm_internal_x86_cpu_snapshot snapshot;

    snapshot = x86_intel(family, model);
    snapshot.vendor_ebx = X86_VENDOR_AMD_EBX;
    snapshot.vendor_edx = X86_VENDOR_AMD_EDX;
    snapshot.vendor_ecx = X86_VENDOR_AMD_ECX;
    return snapshot;
}

static void test_x86_invalid_evidence(void)
{
    cdisasm_internal_x86_cpu_snapshot snapshot;

    memset(&snapshot, 0, sizeof(snapshot));
    expect_cpu("x86 null snapshot",
        cdisasm_internal_classify_x86_cpu(NULL),
        CDISASM_CPU_UNKNOWN);
    expect_cpu("x86 no basic leaf 1",
        cdisasm_internal_classify_x86_cpu(&snapshot),
        CDISASM_CPU_UNKNOWN);

    snapshot = x86_intel(6, UINT32_C(0x3c));
    snapshot.vendor_ebx = UINT32_C(0x746e6543); /* CentaurHauls */
    snapshot.vendor_edx = UINT32_C(0x48727561);
    snapshot.vendor_ecx = UINT32_C(0x736c7561);
    expect_cpu("x86 unknown vendor",
        cdisasm_internal_classify_x86_cpu(&snapshot),
        CDISASM_CPU_UNKNOWN);

    snapshot = x86_intel(6, UINT32_C(0xfe));
    expect_cpu("x86 unknown Intel family-6 model",
        cdisasm_internal_classify_x86_cpu(&snapshot),
        CDISASM_CPU_UNKNOWN);

    snapshot = x86_amd(UINT32_C(0x1f), 0);
    expect_cpu("x86 unknown AMD family",
        cdisasm_internal_classify_x86_cpu(&snapshot),
        CDISASM_CPU_UNKNOWN);

    snapshot = x86_intel(UINT32_C(0x0f), 3);
    snapshot.leaf1_ecx = X86_FEATURE_1_ECX_SSE3;
    snapshot.extended1_edx = X86_FEATURE_EXT1_EDX_LM;
    snapshot.max_extended_leaf = UINT32_C(0x80000000);
    expect_cpu("x86 ignores unavailable extended leaf 1",
        cdisasm_internal_classify_x86_cpu(&snapshot),
        CDISASM_CPU_PENTIUM_4);

    snapshot = x86_amd(5, 8);
    snapshot.extended1_edx = X86_FEATURE_EXT1_EDX_3DNOW;
    snapshot.max_extended_leaf = UINT32_C(0x80000000);
    expect_cpu("AMD K6-2 ignores unavailable extended feature leaf",
        cdisasm_internal_classify_x86_cpu(&snapshot),
        CDISASM_CPU_UNKNOWN);

    snapshot = x86_amd(UINT32_C(0x19), 0);
    snapshot.leaf7_ebx = X86_FEATURE_7_EBX_AVX512F;
    snapshot.max_basic_leaf = UINT32_C(1);
    expect_cpu("AMD Zen ignores unavailable structured feature leaf",
        cdisasm_internal_classify_x86_cpu(&snapshot),
        CDISASM_CPU_AMD_ZEN);
}

static void test_x86_intel_legacy_buckets(void)
{
    static const struct {
        const char *name;
        uint32_t family;
        uint32_t model;
        uint32_t leaf1_edx;
        cdisasm_cpu_id expected;
    } cases[] = {
        { "Intel family 3 is not CPUID-identifiable", 3, 0, 0,
          CDISASM_CPU_UNKNOWN },
        { "Intel CPUID-capable 80486", 4, 3, X86_FEATURE_1_EDX_FPU,
          CDISASM_CPU_80486_CPUID },
        { "Intel CPUID-capable 80486 without an FPU profile", 4, 3, 0,
          CDISASM_CPU_UNKNOWN },
        { "Intel Pentium", 5, 2, 0, CDISASM_CPU_PENTIUM },
        { "Intel Pentium MMX", 5, 4, X86_FEATURE_1_EDX_MMX,
          CDISASM_CPU_PENTIUM_MMX },
        { "Intel Pentium Pro", 6, 1, 0, CDISASM_CPU_PENTIUM_PRO },
        { "Intel Pentium II model 3", 6, 3, 0,
          CDISASM_CPU_PENTIUM_II },
        { "Intel Pentium II model 5 without SSE", 6, 5, 0,
          CDISASM_CPU_PENTIUM_II },
        { "Intel Pentium III model 5 with SSE", 6, 5,
          X86_FEATURE_1_EDX_SSE, CDISASM_CPU_PENTIUM_III },
        { "Intel Pentium III", 6, 7, X86_FEATURE_1_EDX_SSE,
          CDISASM_CPU_PENTIUM_III },
        { "Intel Pentium 4", UINT32_C(0x0f), 2, 0,
          CDISASM_CPU_PENTIUM_4 },
        { "Intel family 0fh model 3 without long mode", UINT32_C(0x0f),
          3, 0, CDISASM_CPU_PENTIUM_4 }
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_internal_x86_cpu_snapshot snapshot =
            x86_intel(cases[index].family, cases[index].model);
        snapshot.leaf1_edx = cases[index].leaf1_edx;
        expect_cpu(cases[index].name,
            cdisasm_internal_classify_x86_cpu(&snapshot),
            cases[index].expected);
    }

    {
        cdisasm_internal_x86_cpu_snapshot snapshot =
            x86_intel(UINT32_C(0x0f), 3);
        snapshot.leaf1_ecx = X86_FEATURE_1_ECX_SSE3;
        expect_cpu("Intel family 0fh SSE3 without long mode",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_PENTIUM_4);
        snapshot.leaf1_ecx |= X86_FEATURE_1_ECX_VMX;
        expect_cpu("Intel VMX without long mode is not a VT-x profile",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_PENTIUM_4);
        snapshot.leaf1_ecx = X86_FEATURE_1_ECX_AVX;
        snapshot.extended1_edx = X86_FEATURE_EXT1_EDX_LM;
        expect_cpu("Intel family 0fh long mode without SSE3",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_PENTIUM_4);
        snapshot.leaf1_ecx |= X86_FEATURE_1_ECX_SSE3;
        expect_cpu("Intel Prescott SSE3 and long mode",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_PRESCOTT);
        snapshot.leaf1_ecx |= X86_FEATURE_1_ECX_VMX;
        expect_cpu("Intel Prescott with VMX",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_INTEL_VT_X);
    }
}

static void test_x86_intel_family6_buckets(void)
{
    static const struct {
        const char *name;
        uint32_t model;
        cdisasm_cpu_id expected;
    } cases[] = {
        { "Intel Core 2", UINT32_C(0x0f), CDISASM_CPU_CORE_2 },
        { "Intel Penryn", UINT32_C(0x17), CDISASM_CPU_PENRYN },
        { "Intel Nehalem", UINT32_C(0x1a), CDISASM_CPU_NEHALEM },
        { "Intel Westmere", UINT32_C(0x25), CDISASM_CPU_WESTMERE },
        { "Intel Sandy Bridge", UINT32_C(0x2a),
          CDISASM_CPU_SANDY_BRIDGE },
        { "Intel Ivy Bridge", UINT32_C(0x3a),
          CDISASM_CPU_IVY_BRIDGE },
        { "Intel Haswell", UINT32_C(0x3c), CDISASM_CPU_HASWELL },
        { "Intel Broadwell", UINT32_C(0x3d), CDISASM_CPU_BROADWELL },
        { "Intel Skylake", UINT32_C(0x5e), CDISASM_CPU_SKYLAKE },
        { "Intel Goldmont", UINT32_C(0x5f), CDISASM_CPU_GOLDMONT },
        { "Intel Skylake-SP", UINT32_C(0x55),
          CDISASM_CPU_SKYLAKE_SP },
        { "Intel Ice Lake", UINT32_C(0x7e), CDISASM_CPU_ICE_LAKE },
        { "Intel Tiger Lake", UINT32_C(0x8c),
          CDISASM_CPU_TIGER_LAKE },
        { "Intel Alder Lake", UINT32_C(0x97),
          CDISASM_CPU_ALDER_LAKE },
        { "Intel Sapphire Rapids", UINT32_C(0x8f),
          CDISASM_CPU_SAPPHIRE_RAPIDS },
        { "Intel Granite Rapids", UINT32_C(0xad),
          CDISASM_CPU_GRANITE_RAPIDS },
        { "Intel Arrow Lake", UINT32_C(0xc6),
          CDISASM_CPU_ARROW_LAKE },
        { "Intel Knights Mill", UINT32_C(0x85),
          CDISASM_CPU_KNIGHTS_MILL }
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_internal_x86_cpu_snapshot snapshot =
            x86_intel(6, cases[index].model);
        if (cases[index].expected == CDISASM_CPU_SKYLAKE_SP
            || cases[index].expected == CDISASM_CPU_KNIGHTS_MILL
            || cases[index].expected == CDISASM_CPU_ICE_LAKE
            || cases[index].expected == CDISASM_CPU_SAPPHIRE_RAPIDS
            || cases[index].expected == CDISASM_CPU_GRANITE_RAPIDS) {
            snapshot.leaf7_ebx |= X86_FEATURE_7_EBX_AVX512F;
        }
        expect_cpu(cases[index].name,
            cdisasm_internal_classify_x86_cpu(&snapshot),
            cases[index].expected);
    }
}

static void test_x86_low_end_avx_splits(void)
{
    static const struct {
        const char *name;
        uint32_t model;
        cdisasm_cpu_id no_avx_expected;
        cdisasm_cpu_id avx_expected;
    } cases[] = {
        { "Haswell model 3c", UINT32_C(0x3c),
          CDISASM_CPU_CELERON_G1840, CDISASM_CPU_HASWELL },
        { "Broadwell model 3d", UINT32_C(0x3d),
          CDISASM_CPU_CELERON_G1840, CDISASM_CPU_BROADWELL },
        { "Skylake model 5e", UINT32_C(0x5e),
          CDISASM_CPU_CELERON_G3900, CDISASM_CPU_SKYLAKE },
        { "Coffee Lake model 9e", UINT32_C(0x9e),
          CDISASM_CPU_CELERON_G3900, CDISASM_CPU_SKYLAKE },
        { "Comet Lake model a5", UINT32_C(0xa5),
          CDISASM_CPU_CELERON_G5900, CDISASM_CPU_SKYLAKE }
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_internal_x86_cpu_snapshot snapshot =
            x86_intel(6, cases[index].model);
        snapshot.leaf1_ecx &= ~X86_FEATURE_1_ECX_AVX;
        expect_cpu(cases[index].name,
            cdisasm_internal_classify_x86_cpu(&snapshot),
            cases[index].no_avx_expected);
        snapshot.leaf1_ecx |= X86_FEATURE_1_ECX_AVX;
        expect_cpu(cases[index].name,
            cdisasm_internal_classify_x86_cpu(&snapshot),
            cases[index].avx_expected);
    }

    {
        cdisasm_internal_x86_cpu_snapshot snapshot =
            x86_intel(6, UINT32_C(0x5c));
        expect_cpu("Apollo Lake Celeron N3350",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_CELERON_N3350);
    }
    {
        cdisasm_internal_x86_cpu_snapshot snapshot =
            x86_intel(6, UINT32_C(0x7a));
        expect_cpu("Gemini Lake Refresh Celeron N4020",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_CELERON_N4020);
    }
    {
        cdisasm_internal_x86_cpu_snapshot snapshot =
            x86_intel(6, UINT32_C(0x9c));
        expect_cpu("Jasper Lake Pentium Silver N6000",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_PENTIUM_SILVER_N6000);
    }
}

static void test_x86_extended_family_and_nextgen(void)
{
    cdisasm_internal_x86_cpu_snapshot snapshot;

    /* Display family 0x13 exercises CPUID's extended-family addition rule. */
    snapshot = x86_intel(UINT32_C(0x13), 1);
    expect_cpu("Intel Diamond Rapids extended family",
        cdisasm_internal_classify_x86_cpu(&snapshot),
        CDISASM_CPU_DIAMOND_RAPIDS);

    snapshot = x86_intel(6, UINT32_C(0xfe));
    snapshot.leaf7_1_edx = X86_FEATURE_7_1_EDX_AVX10;
    snapshot.leaf24_ebx = UINT32_C(1);
    expect_cpu("AVX10 bits do not invent an unknown model profile",
        cdisasm_internal_classify_x86_cpu(&snapshot),
        CDISASM_CPU_UNKNOWN);

    snapshot.leaf7_1_edx |= X86_FEATURE_7_1_EDX_APX_F;
    snapshot.leaf7_1_eax = UINT32_MAX;
    snapshot.leaf7_ecx = UINT32_MAX;
    snapshot.leaf7_edx = UINT32_MAX;
    expect_cpu("APX and unrelated future bits remain conservative",
        cdisasm_internal_classify_x86_cpu(&snapshot),
        CDISASM_CPU_UNKNOWN);

    snapshot = x86_intel(6, UINT32_C(0xad));
    snapshot.leaf1_ecx |= X86_FEATURE_1_ECX_HYPERVISOR;
    expect_cpu("hypervisor-present bit does not change model mapping",
        cdisasm_internal_classify_x86_cpu(&snapshot),
        CDISASM_CPU_GRANITE_RAPIDS);
}

static void test_x86_amd_buckets(void)
{
    static const struct {
        const char *name;
        uint32_t family;
        uint32_t model;
        cdisasm_cpu_id expected;
    } cases[] = {
        { "AMD K6-2", 5, 8, CDISASM_CPU_AMD_K6_2 },
        { "AMD Athlon 64", UINT32_C(0x0f), 4,
          CDISASM_CPU_ATHLON_64 },
        { "AMD Barcelona family 10h", UINT32_C(0x10), 2,
          CDISASM_CPU_AMD_BARCELONA },
        { "AMD Barcelona-compatible family 12h", UINT32_C(0x12), 1,
          CDISASM_CPU_AMD_BARCELONA },
        { "AMD Bulldozer", UINT32_C(0x15), 2,
          CDISASM_CPU_AMD_BULLDOZER },
        { "AMD Zen family 17h", UINT32_C(0x17), 1,
          CDISASM_CPU_AMD_ZEN },
        { "AMD Zen 3 family 19h model 21h", UINT32_C(0x19),
          UINT32_C(0x21), CDISASM_CPU_AMD_ZEN },
        { "AMD Zen 4 family 19h model 61h", UINT32_C(0x19),
          UINT32_C(0x61), CDISASM_CPU_AMD_ZEN_4 },
        { "AMD Zen 5 without AVX-512", UINT32_C(0x1a), 0,
          CDISASM_CPU_AMD_ZEN }
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_internal_x86_cpu_snapshot snapshot =
            x86_amd(cases[index].family, cases[index].model);
        if (cases[index].expected == CDISASM_CPU_AMD_K6_2) {
            snapshot.extended1_edx |= X86_FEATURE_EXT1_EDX_3DNOW;
        }
        if (cases[index].expected == CDISASM_CPU_ATHLON_64) {
            snapshot.extended1_edx |= X86_FEATURE_EXT1_EDX_LM;
        }
        expect_cpu(cases[index].name,
            cdisasm_internal_classify_x86_cpu(&snapshot),
            cases[index].expected);
    }

    {
        cdisasm_internal_x86_cpu_snapshot snapshot = x86_amd(5, 8);
        expect_cpu("AMD family 5 model 8 without 3DNow!",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_UNKNOWN);
    }
    {
        cdisasm_internal_x86_cpu_snapshot snapshot =
            x86_amd(UINT32_C(0x0f), 4);
        expect_cpu("AMD family 0fh without long mode evidence",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_UNKNOWN);
        snapshot.extended1_ecx = X86_FEATURE_EXT1_ECX_SVM;
        expect_cpu("AMD SVM without long mode remains unknown",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_UNKNOWN);
        snapshot.extended1_edx = X86_FEATURE_EXT1_EDX_LM;
        expect_cpu("AMD family 0fh with SVM",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_AMD_V);
    }
    {
        static const struct {
            uint32_t model;
            cdisasm_cpu_id expected;
        } family19_boundaries[] = {
            { UINT32_C(0x0f), CDISASM_CPU_AMD_ZEN },
            { UINT32_C(0x10), CDISASM_CPU_AMD_ZEN_4 },
            { UINT32_C(0x1f), CDISASM_CPU_AMD_ZEN_4 },
            { UINT32_C(0x20), CDISASM_CPU_AMD_ZEN },
            { UINT32_C(0x5f), CDISASM_CPU_AMD_ZEN },
            { UINT32_C(0x60), CDISASM_CPU_AMD_ZEN_4 },
            { UINT32_C(0xaf), CDISASM_CPU_AMD_ZEN_4 },
            { UINT32_C(0xb0), CDISASM_CPU_AMD_ZEN }
        };
        size_t boundary_index;

        for (boundary_index = 0;
             boundary_index < sizeof(family19_boundaries)
                 / sizeof(family19_boundaries[0]);
             ++boundary_index) {
            char case_name[56];
            cdisasm_internal_x86_cpu_snapshot snapshot = x86_amd(
                UINT32_C(0x19),
                family19_boundaries[boundary_index].model);
            (void)snprintf(case_name, sizeof(case_name),
                "AMD family 19h model boundary 0x%02" PRIx32,
                family19_boundaries[boundary_index].model);
            expect_cpu(case_name,
                cdisasm_internal_classify_x86_cpu(&snapshot),
                family19_boundaries[boundary_index].expected);
        }
    }
    {
        cdisasm_internal_x86_cpu_snapshot snapshot =
            x86_amd(UINT32_C(0x19), 0);
        snapshot.leaf7_ebx |= X86_FEATURE_7_EBX_AVX512F;
        expect_cpu("AMD family 19h AVX-512 evidence",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_AMD_ZEN_4);
        snapshot = x86_amd(UINT32_C(0x1a), 0);
        snapshot.leaf7_ebx |= X86_FEATURE_7_EBX_AVX512F;
        expect_cpu("AMD family 1ah AVX-512 closest profile",
            cdisasm_internal_classify_x86_cpu(&snapshot),
            CDISASM_CPU_AMD_ZEN_4);
    }
}

static void test_x86_classifier(void)
{
    test_x86_invalid_evidence();
    test_x86_intel_legacy_buckets();
    test_x86_intel_family6_buckets();
    test_x86_low_end_avx_splits();
    test_x86_extended_family_and_nextgen();
    test_x86_amd_buckets();
}

#endif

#if USE_ARCH_ARM

static uint32_t arm_midr(uint32_t implementer, uint32_t part)
{
    /* Nonzero variant and revision verify that classification masks them. */
    return (implementer << 24)
        | (UINT32_C(3) << 20)
        | (UINT32_C(0x0f) << 16)
        | ((part & UINT32_C(0x0fff)) << 4)
        | UINT32_C(7);
}

static void test_arm_standard_midr_buckets(void)
{
    static const struct {
        const char *name;
        uint32_t implementer;
        uint32_t part;
        int has_neon;
        cdisasm_cpu_id expected;
    } cases[] = {
        { "ARM7TDMI", UINT32_C(0x41), UINT32_C(0x770), 0,
          CDISASM_ARM_CPU_ARM7TDMI },
        { "Cortex-A7", UINT32_C(0x41), UINT32_C(0xc07), 0,
          CDISASM_ARM_CPU_CORTEX_A7 },
        { "Cortex-A7 NEON", UINT32_C(0x41), UINT32_C(0xc07), 1,
          CDISASM_ARM_CPU_CORTEX_A7_NEON },
        { "Cortex-A9", UINT32_C(0x41), UINT32_C(0xc09), 0,
          CDISASM_ARM_CPU_CORTEX_A9 },
        { "Cortex-A9 NEON", UINT32_C(0x41), UINT32_C(0xc09), 1,
          CDISASM_ARM_CPU_CORTEX_A9_NEON },
        { "Cortex-A32", UINT32_C(0x41), UINT32_C(0xd01), 1,
          CDISASM_ARM_CPU_CORTEX_A32 },
        { "Cortex-A34", UINT32_C(0x41), UINT32_C(0xd02), 1,
          CDISASM_ARM_CPU_CORTEX_A34 },
        { "Cortex-A35", UINT32_C(0x41), UINT32_C(0xd04), 1,
          CDISASM_ARM_CPU_CORTEX_A35 },
        { "Cortex-A53", UINT32_C(0x41), UINT32_C(0xd03), 1,
          CDISASM_ARM_CPU_CORTEX_A53 },
        { "Fujitsu A64FX", UINT32_C(0x46), UINT32_C(0x001), 1,
          CDISASM_ARM_CPU_FUJITSU_A64FX }
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_cpu(cases[index].name,
            cdisasm_internal_classify_arm_midr(
                arm_midr(cases[index].implementer, cases[index].part),
                cases[index].has_neon),
            cases[index].expected);
    }

    expect_cpu("ARM unknown implementer",
        cdisasm_internal_classify_arm_midr(
            arm_midr(UINT32_C(0x42), UINT32_C(0xd03)), 1),
        CDISASM_CPU_UNKNOWN);
    expect_cpu("ARM unknown part",
        cdisasm_internal_classify_arm_midr(
            arm_midr(UINT32_C(0x41), UINT32_C(0xfff)), 1),
        CDISASM_CPU_UNKNOWN);
    expect_cpu("ARM7 legacy part mismatch",
        cdisasm_internal_classify_arm_midr(
            arm_midr(UINT32_C(0x41), UINT32_C(0x700)), 0),
        CDISASM_CPU_UNKNOWN);
    expect_cpu("ARM zero MIDR",
        cdisasm_internal_classify_arm_midr(0, 0),
        CDISASM_CPU_UNKNOWN);
}

static void test_arm_apple_midr_buckets(void)
{
    static const struct {
        uint32_t part;
        cdisasm_cpu_id expected;
    } cases[] = {
        { UINT32_C(0x002), CDISASM_ARM_CPU_APPLE_A8 },
        { UINT32_C(0x003), CDISASM_ARM_CPU_APPLE_A8 },
        { UINT32_C(0x004), CDISASM_ARM_CPU_APPLE_A9 },
        { UINT32_C(0x005), CDISASM_ARM_CPU_APPLE_A9 },
        { UINT32_C(0x006), CDISASM_ARM_CPU_APPLE_A10 },
        { UINT32_C(0x007), CDISASM_ARM_CPU_APPLE_A10 },
        { UINT32_C(0x008), CDISASM_ARM_CPU_APPLE_A11 },
        { UINT32_C(0x009), CDISASM_ARM_CPU_APPLE_A11 },
        { UINT32_C(0x00b), CDISASM_ARM_CPU_APPLE_A12 },
        { UINT32_C(0x00c), CDISASM_ARM_CPU_APPLE_A12 },
        { UINT32_C(0x010), CDISASM_ARM_CPU_APPLE_A12 },
        { UINT32_C(0x011), CDISASM_ARM_CPU_APPLE_A12 },
        { UINT32_C(0x012), CDISASM_ARM_CPU_APPLE_A13 },
        { UINT32_C(0x013), CDISASM_ARM_CPU_APPLE_A13 },
        { UINT32_C(0x020), CDISASM_ARM_CPU_APPLE_A14 },
        { UINT32_C(0x021), CDISASM_ARM_CPU_APPLE_A14 },
        { UINT32_C(0x022), CDISASM_ARM_CPU_APPLE_M1 },
        { UINT32_C(0x023), CDISASM_ARM_CPU_APPLE_M1 },
        { UINT32_C(0x024), CDISASM_ARM_CPU_APPLE_M1 },
        { UINT32_C(0x025), CDISASM_ARM_CPU_APPLE_M1 },
        { UINT32_C(0x028), CDISASM_ARM_CPU_APPLE_M1 },
        { UINT32_C(0x029), CDISASM_ARM_CPU_APPLE_M1 },
        { UINT32_C(0x030), CDISASM_ARM_CPU_APPLE_A15 },
        { UINT32_C(0x031), CDISASM_ARM_CPU_APPLE_A15 },
        { UINT32_C(0x032), CDISASM_ARM_CPU_APPLE_M2 },
        { UINT32_C(0x033), CDISASM_ARM_CPU_APPLE_M2 },
        { UINT32_C(0x034), CDISASM_ARM_CPU_APPLE_M2 },
        { UINT32_C(0x035), CDISASM_ARM_CPU_APPLE_M2 },
        { UINT32_C(0x038), CDISASM_ARM_CPU_APPLE_M2 },
        { UINT32_C(0x039), CDISASM_ARM_CPU_APPLE_M2 },
        { UINT32_C(0x040), CDISASM_ARM_CPU_APPLE_A16 },
        { UINT32_C(0x041), CDISASM_ARM_CPU_APPLE_A16 },
        { UINT32_C(0x042), CDISASM_ARM_CPU_APPLE_M3 },
        { UINT32_C(0x043), CDISASM_ARM_CPU_APPLE_M3 },
        { UINT32_C(0x044), CDISASM_ARM_CPU_APPLE_M3 },
        { UINT32_C(0x045), CDISASM_ARM_CPU_APPLE_M3 },
        { UINT32_C(0x048), CDISASM_ARM_CPU_APPLE_M3 },
        { UINT32_C(0x049), CDISASM_ARM_CPU_APPLE_M3 },
        { UINT32_C(0x050), CDISASM_ARM_CPU_APPLE_A17 },
        { UINT32_C(0x051), CDISASM_ARM_CPU_APPLE_A17 },
        { UINT32_C(0x052), CDISASM_ARM_CPU_APPLE_M4 },
        { UINT32_C(0x053), CDISASM_ARM_CPU_APPLE_M4 },
        { UINT32_C(0x054), CDISASM_ARM_CPU_APPLE_M4 },
        { UINT32_C(0x055), CDISASM_ARM_CPU_APPLE_M4 },
        { UINT32_C(0x058), CDISASM_ARM_CPU_APPLE_M4 },
        { UINT32_C(0x059), CDISASM_ARM_CPU_APPLE_M4 }
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char case_name[48];
        (void)snprintf(case_name, sizeof(case_name),
            "Apple MIDR part 0x%03" PRIx32, cases[index].part);
        expect_cpu(case_name,
            cdisasm_internal_classify_arm_midr(
                arm_midr(UINT32_C(0x61), cases[index].part), 1),
            cases[index].expected);
    }

    expect_cpu("Apple unknown MIDR part",
        cdisasm_internal_classify_arm_midr(
            arm_midr(UINT32_C(0x61), UINT32_C(0x05a)), 1),
        CDISASM_CPU_UNKNOWN);
}

static void test_apple_cpufamily_buckets(void)
{
    static const struct {
        const char *name;
        uint32_t family;
        cdisasm_cpu_id expected;
    } cases[] = {
        { "Apple A4 Cortex-A8 family",
          CDISASM_INTERNAL_APPLE_CPUFAMILY_ARM_13,
          CDISASM_ARM_CPU_APPLE_A4 },
        { "Apple A5 Cortex-A9 family",
          CDISASM_INTERNAL_APPLE_CPUFAMILY_ARM_14,
          CDISASM_ARM_CPU_APPLE_A5 },
        { "Darwin Cortex-A7 family",
          CDISASM_INTERNAL_APPLE_CPUFAMILY_ARM_15,
          CDISASM_ARM_CPU_CORTEX_A7 },
        { "Apple Swift", CDISASM_INTERNAL_APPLE_CPUFAMILY_SWIFT,
          CDISASM_ARM_CPU_APPLE_A6 },
        { "Apple Cyclone", CDISASM_INTERNAL_APPLE_CPUFAMILY_CYCLONE,
          CDISASM_ARM_CPU_APPLE_A7 },
        { "Apple Typhoon", CDISASM_INTERNAL_APPLE_CPUFAMILY_TYPHOON,
          CDISASM_ARM_CPU_APPLE_A8 },
        { "Apple Twister", CDISASM_INTERNAL_APPLE_CPUFAMILY_TWISTER,
          CDISASM_ARM_CPU_APPLE_A9 },
        { "Apple Hurricane", CDISASM_INTERNAL_APPLE_CPUFAMILY_HURRICANE,
          CDISASM_ARM_CPU_APPLE_A10 },
        { "Apple Monsoon/Mistral",
          CDISASM_INTERNAL_APPLE_CPUFAMILY_MONSOON_MISTRAL,
          CDISASM_ARM_CPU_APPLE_A11 },
        { "Apple Vortex/Tempest",
          CDISASM_INTERNAL_APPLE_CPUFAMILY_VORTEX_TEMPEST,
          CDISASM_ARM_CPU_APPLE_A12 },
        { "Apple Lightning/Thunder",
          CDISASM_INTERNAL_APPLE_CPUFAMILY_LIGHTNING_THUNDER,
          CDISASM_ARM_CPU_APPLE_A13 },
        { "Apple Firestorm/Icestorm",
          CDISASM_INTERNAL_APPLE_CPUFAMILY_FIRESTORM_ICESTORM,
          CDISASM_ARM_CPU_APPLE_A14 },
        { "Apple Blizzard/Avalanche",
          CDISASM_INTERNAL_APPLE_CPUFAMILY_BLIZZARD_AVALANCHE,
          CDISASM_ARM_CPU_APPLE_A15 },
        { "Apple Everest/Sawtooth",
          CDISASM_INTERNAL_APPLE_CPUFAMILY_EVEREST_SAWTOOTH,
          CDISASM_ARM_CPU_APPLE_A16 },
        { "Apple Ibiza", CDISASM_INTERNAL_APPLE_CPUFAMILY_IBIZA,
          CDISASM_ARM_CPU_APPLE_M3 },
        { "Apple Palma", CDISASM_INTERNAL_APPLE_CPUFAMILY_PALMA,
          CDISASM_ARM_CPU_APPLE_M3 },
        { "Apple Lobos", CDISASM_INTERNAL_APPLE_CPUFAMILY_LOBOS,
          CDISASM_ARM_CPU_APPLE_M3 },
        { "Apple Coll", CDISASM_INTERNAL_APPLE_CPUFAMILY_COLL,
          CDISASM_ARM_CPU_APPLE_A17 },
        { "Apple Donan", CDISASM_INTERNAL_APPLE_CPUFAMILY_DONAN,
          CDISASM_ARM_CPU_APPLE_M4 },
        { "Apple Brava", CDISASM_INTERNAL_APPLE_CPUFAMILY_BRAVA,
          CDISASM_ARM_CPU_APPLE_M4 },
        { "Apple Tupai", CDISASM_INTERNAL_APPLE_CPUFAMILY_TUPAI,
          CDISASM_ARM_CPU_APPLE_A18 },
        { "Apple Tahiti", CDISASM_INTERNAL_APPLE_CPUFAMILY_TAHITI,
          CDISASM_ARM_CPU_APPLE_A18 },
        { "Apple Hidra", CDISASM_INTERNAL_APPLE_CPUFAMILY_HIDRA,
          CDISASM_ARM_CPU_APPLE_M5 },
        { "Apple Tilos", CDISASM_INTERNAL_APPLE_CPUFAMILY_TILOS,
          CDISASM_ARM_CPU_APPLE_A19 },
        { "Apple Thera", CDISASM_INTERNAL_APPLE_CPUFAMILY_THERA,
          CDISASM_ARM_CPU_APPLE_A19 }
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_cpu(cases[index].name,
            cdisasm_internal_classify_apple_family(
                cases[index].family, CDISASM_CPU_UNKNOWN),
            cases[index].expected);
    }

    expect_cpu("Apple valid M1 brand overrides shared family",
        cdisasm_internal_classify_apple_family(
            CDISASM_INTERNAL_APPLE_CPUFAMILY_FIRESTORM_ICESTORM,
            CDISASM_ARM_CPU_APPLE_M1),
        CDISASM_ARM_CPU_APPLE_M1);
    expect_cpu("Apple valid M2 brand overrides shared family",
        cdisasm_internal_classify_apple_family(
            CDISASM_INTERNAL_APPLE_CPUFAMILY_BLIZZARD_AVALANCHE,
            CDISASM_ARM_CPU_APPLE_M2),
        CDISASM_ARM_CPU_APPLE_M2);
    expect_cpu("Apple valid M3 brand overrides family",
        cdisasm_internal_classify_apple_family(
            CDISASM_INTERNAL_APPLE_CPUFAMILY_CYCLONE,
            CDISASM_ARM_CPU_APPLE_M3),
        CDISASM_ARM_CPU_APPLE_M3);
    expect_cpu("Apple valid M4 brand overrides family",
        cdisasm_internal_classify_apple_family(
            CDISASM_INTERNAL_APPLE_CPUFAMILY_CYCLONE,
            CDISASM_ARM_CPU_APPLE_M4),
        CDISASM_ARM_CPU_APPLE_M4);
    expect_cpu("Apple valid M5 brand overrides family",
        cdisasm_internal_classify_apple_family(
            CDISASM_INTERNAL_APPLE_CPUFAMILY_CYCLONE,
            CDISASM_ARM_CPU_APPLE_M5),
        CDISASM_ARM_CPU_APPLE_M5);
    expect_cpu("Apple A-series brand profile also overrides family",
        cdisasm_internal_classify_apple_family(
            CDISASM_INTERNAL_APPLE_CPUFAMILY_CYCLONE,
            CDISASM_ARM_CPU_APPLE_A14),
        CDISASM_ARM_CPU_APPLE_A14);
    expect_cpu("Apple malformed brand profile is ignored",
        cdisasm_internal_classify_apple_family(
            CDISASM_INTERNAL_APPLE_CPUFAMILY_CYCLONE,
            CDISASM_ARM_CPU_ANY),
        CDISASM_ARM_CPU_APPLE_A7);
    expect_cpu("Apple unknown family",
        cdisasm_internal_classify_apple_family(
            UINT32_C(0xdeadbeef), CDISASM_CPU_UNKNOWN),
        CDISASM_CPU_UNKNOWN);
    expect_cpu("Apple brand identifies otherwise unknown family",
        cdisasm_internal_classify_apple_family(
            UINT32_C(0xdeadbeef), CDISASM_ARM_CPU_APPLE_M3),
        CDISASM_ARM_CPU_APPLE_M3);
}

static void test_apple_brand_buckets(void)
{
    static const struct {
        const char *brand;
        cdisasm_cpu_id expected;
    } cases[] = {
        { "Apple A4", CDISASM_ARM_CPU_APPLE_A4 },
        { "Apple A19 Pro", CDISASM_ARM_CPU_APPLE_A19 },
        { "Apple M1", CDISASM_ARM_CPU_APPLE_M1 },
        { "Apple M5 Max", CDISASM_ARM_CPU_APPLE_M5 },
        { "Apple M4 Ultra", CDISASM_ARM_CPU_APPLE_M4 },
        { "Apple A17 Pro", CDISASM_ARM_CPU_APPLE_A17 },
        { "Apple S4", CDISASM_ARM_CPU_APPLE_S4 },
        { "Apple S10", CDISASM_ARM_CPU_APPLE_S10 },
        { "Apple A3", CDISASM_CPU_UNKNOWN },
        { "Apple A20", CDISASM_CPU_UNKNOWN },
        { "Apple M0", CDISASM_CPU_UNKNOWN },
        { "Apple M6", CDISASM_CPU_UNKNOWN },
        { "Apple S11", CDISASM_CPU_UNKNOWN },
        { "Apple X1", CDISASM_CPU_UNKNOWN },
        { "apple M3", CDISASM_CPU_UNKNOWN },
        { "Apple M300", CDISASM_CPU_UNKNOWN },
        { "Apple M1X", CDISASM_CPU_UNKNOWN },
        { "Apple A18Pro", CDISASM_CPU_UNKNOWN },
        { "Apple M01", CDISASM_CPU_UNKNOWN },
        { "Apple S10 Ultra", CDISASM_CPU_UNKNOWN }
    };
    size_t index;

    expect_cpu("Apple null brand",
        cdisasm_internal_classify_apple_brand(NULL),
        CDISASM_CPU_UNKNOWN);
    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_cpu(cases[index].brand,
            cdisasm_internal_classify_apple_brand(cases[index].brand),
            cases[index].expected);
    }
}

static cdisasm_cpu_id classify_arm_cpuinfo_lines(
    const char *const *lines,
    size_t line_count,
    int has_neon)
{
    cdisasm_internal_arm_cpuinfo_state state;
    size_t index;

    cdisasm_internal_arm_cpuinfo_init(&state, has_neon);
    for (index = 0; index < line_count; ++index) {
        if (!cdisasm_internal_arm_cpuinfo_feed(&state, lines[index])) {
            break;
        }
    }
    return cdisasm_internal_arm_cpuinfo_finish(&state);
}

static void test_arm_cpuinfo_parser(void)
{
    static const char *const homogeneous[] = {
        "processor\t: 0\n",
        "CPU implementer\t: 0x41\n",
        "CPU part\t: 0xd03\n",
        "\n",
        "processor\t: 1\n",
        "CPU implementer\t: 0x41\n",
        "CPU part\t: 0xd03\n"
    };
    static const char *const heterogeneous[] = {
        "processor : 0\n",
        "CPU implementer : 0x41\n",
        "CPU part : 0xd03\n",
        "processor : 1\n",
        "CPU implementer : 0x41\n",
        "CPU part : 0xd04\n"
    };
    static const char *const cross_record_pair[] = {
        "processor : 0\n",
        "CPU implementer : 0x41\n",
        "processor : 1\n",
        "CPU part : 0xd03\n"
    };
    static const char *const trailing_incomplete[] = {
        "processor : 0\n",
        "CPU implementer : 0x41\n"
    };
    static const char *const malformed[] = {
        "processor : 0\n",
        "CPU implementer : 0x141\n",
        "CPU part : 0xd03\n"
    };
    static const char *const no_processor_key[] = {
        "CPU implementer : 0x41\n",
        "CPU part : 0xc07\n"
    };

    expect_cpu("ARM cpuinfo homogeneous records",
        classify_arm_cpuinfo_lines(homogeneous,
            sizeof(homogeneous) / sizeof(homogeneous[0]), 1),
        CDISASM_ARM_CPU_CORTEX_A53);
    expect_cpu("ARM cpuinfo heterogeneous records",
        classify_arm_cpuinfo_lines(heterogeneous,
            sizeof(heterogeneous) / sizeof(heterogeneous[0]), 1),
        CDISASM_CPU_UNKNOWN);
    expect_cpu("ARM cpuinfo does not pair adjacent records",
        classify_arm_cpuinfo_lines(cross_record_pair,
            sizeof(cross_record_pair) / sizeof(cross_record_pair[0]), 1),
        CDISASM_CPU_UNKNOWN);
    expect_cpu("ARM cpuinfo rejects incomplete final record",
        classify_arm_cpuinfo_lines(trailing_incomplete,
            sizeof(trailing_incomplete) / sizeof(trailing_incomplete[0]), 1),
        CDISASM_CPU_UNKNOWN);
    expect_cpu("ARM cpuinfo rejects out-of-range identifiers",
        classify_arm_cpuinfo_lines(malformed,
            sizeof(malformed) / sizeof(malformed[0]), 1),
        CDISASM_CPU_UNKNOWN);
    expect_cpu("ARM cpuinfo accepts a complete implicit record",
        classify_arm_cpuinfo_lines(no_processor_key,
            sizeof(no_processor_key) / sizeof(no_processor_key[0]), 1),
        CDISASM_ARM_CPU_CORTEX_A7_NEON);

    {
        char long_relevant_line[256];

        memset(long_relevant_line, ' ', sizeof(long_relevant_line));
        memcpy(long_relevant_line, "CPU part : 0xd03", 16);
        long_relevant_line[sizeof(long_relevant_line) - 1u] = '\0';
        expect_boolean("ARM cpuinfo recognizes a truncated relevant line",
            cdisasm_internal_arm_cpuinfo_line_is_relevant(
                long_relevant_line),
            1);
        expect_boolean("ARM cpuinfo ignores a long unrelated field",
            cdisasm_internal_arm_cpuinfo_line_is_relevant(
                "Features : fp asimd aes sha1 sha2 crc32"),
            0);
    }
}

static void test_arm_classifier(void)
{
    test_arm_standard_midr_buckets();
    test_arm_apple_midr_buckets();
    test_apple_brand_buckets();
    test_apple_cpufamily_buckets();
    test_arm_cpuinfo_parser();
}

#endif

int main(void)
{
#if USE_ARCH_X86
    test_x86_classifier();
#endif
#if USE_ARCH_ARM
    test_arm_classifier();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d current-CPU classifier test(s) failed\n", failures);
        return 1;
    }
    puts("all current-CPU classifier tests passed");
    return 0;
}
