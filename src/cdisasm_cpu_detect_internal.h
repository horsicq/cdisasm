#ifndef CDISASM_CPU_DETECT_INTERNAL_H
#define CDISASM_CPU_DETECT_INTERNAL_H

#include "cdisasm/cdisasm.h"

#if USE_ARCH_X86
/* Injectable CPUID image used by the native reader and deterministic tests. */
typedef struct cdisasm_internal_x86_cpu_snapshot {
    uint32_t max_basic_leaf;
    uint32_t max_extended_leaf;
    uint32_t vendor_ebx;
    uint32_t vendor_edx;
    uint32_t vendor_ecx;
    uint32_t leaf1_eax;
    uint32_t leaf1_ecx;
    uint32_t leaf1_edx;
    uint32_t leaf7_ebx;
    uint32_t leaf7_ecx;
    uint32_t leaf7_edx;
    uint32_t leaf7_1_eax;
    uint32_t leaf7_1_edx;
    uint32_t leaf24_ebx;
    uint32_t extended1_ecx;
    uint32_t extended1_edx;
} cdisasm_internal_x86_cpu_snapshot;

cdisasm_cpu_id cdisasm_internal_classify_x86_cpu(
    const cdisasm_internal_x86_cpu_snapshot *snapshot);
#endif

#if USE_ARCH_ARM
/* Values exported by Darwin's hw.cpufamily sysctl. They are deliberately
 * unordered identifiers; keep them private to the detector. */
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_ARM_13 UINT32_C(0x0cc90e64)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_ARM_14 UINT32_C(0x96077ef1)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_ARM_15 UINT32_C(0xa8511bca)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_SWIFT UINT32_C(0x1e2d6381)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_CYCLONE UINT32_C(0x37a09642)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_TYPHOON UINT32_C(0x2c91a47e)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_TWISTER UINT32_C(0x92fb37c8)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_HURRICANE UINT32_C(0x67ceee93)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_MONSOON_MISTRAL \
    UINT32_C(0xe81e7ef6)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_VORTEX_TEMPEST \
    UINT32_C(0x07d34b9f)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_LIGHTNING_THUNDER \
    UINT32_C(0x462504d2)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_FIRESTORM_ICESTORM \
    UINT32_C(0x1b588bb3)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_BLIZZARD_AVALANCHE \
    UINT32_C(0xda33d83d)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_EVEREST_SAWTOOTH \
    UINT32_C(0x8765edea)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_IBIZA UINT32_C(0xfa33415e)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_PALMA UINT32_C(0x72015832)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_COLL UINT32_C(0x2876f5b5)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_LOBOS UINT32_C(0x5f4dea93)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_DONAN UINT32_C(0x6f5129ac)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_BRAVA UINT32_C(0x17d5b93a)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_TUPAI UINT32_C(0x204526d0)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_TAHITI UINT32_C(0x75d4acb9)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_HIDRA UINT32_C(0x1d5a87e8)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_TILOS UINT32_C(0x01d7a72b)
#define CDISASM_INTERNAL_APPLE_CPUFAMILY_THERA UINT32_C(0xab345f09)

/* Incremental parser state for Linux /proc/cpuinfo ARM records. */
typedef struct cdisasm_internal_arm_cpuinfo_state {
    cdisasm_cpu_id selected;
    uint32_t implementer;
    uint32_t part;
    int has_neon;
    int have_implementer;
    int have_part;
    int record_started;
    int found;
    int invalid;
} cdisasm_internal_arm_cpuinfo_state;

cdisasm_cpu_id cdisasm_internal_classify_arm_midr(
    uint32_t midr,
    int has_neon);

void cdisasm_internal_arm_cpuinfo_init(
    cdisasm_internal_arm_cpuinfo_state *state,
    int has_neon);

int cdisasm_internal_arm_cpuinfo_feed(
    cdisasm_internal_arm_cpuinfo_state *state,
    const char *line);

int cdisasm_internal_arm_cpuinfo_line_is_relevant(const char *line);

cdisasm_cpu_id cdisasm_internal_arm_cpuinfo_finish(
    cdisasm_internal_arm_cpuinfo_state *state);

cdisasm_cpu_id cdisasm_internal_classify_apple_brand(const char *brand);

cdisasm_cpu_id cdisasm_internal_classify_apple_family(
    uint32_t family,
    cdisasm_cpu_id brand_profile);
#endif

#endif
