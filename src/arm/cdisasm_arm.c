#include "cdisasm/cdisasm_arm.h"

#include "arm_decoder.h"
#include "arm_generated_alias.h"
#include "arm_generated_decoder.h"
#include "arm_t32_decoder.h"

#include <string.h>

_Static_assert(sizeof(cdisasm_arm_decode_flags)
                   == CDISASM_DECODE_FLAGS_SIZE,
               "ARM decode-flags ABI size changed");

typedef struct arm_cpu_profile {
    cdisasm_arm_mode_mask mode_mask;
    cdisasm_arm_capabilities capabilities;
} arm_cpu_profile;

#define ARM_CAPS_V7 \
    (CDISASM_ARM_CAP_V4 | CDISASM_ARM_CAP_V5 | CDISASM_ARM_CAP_V6 \
        | CDISASM_ARM_CAP_V7)
#if USE_EXTRA_OPCODES
#define ARM_CAPS_OPTIONAL_VFP CDISASM_ARM_CAP_VFP
#define ARM_CAPS_OPTIONAL_PAUTH CDISASM_ARM_CAP_PAUTH
#define ARM_CAPS_OPTIONAL_FP16 CDISASM_ARM_CAP_FP16
#define ARM_CAPS_OPTIONAL_SVE CDISASM_ARM_CAP_SVE
#define ARM_CAPS_OPTIONAL_BF16 CDISASM_ARM_CAP_BF16
#define ARM_CAPS_OPTIONAL_CRC32 \
    (UINT64_C(1) << CDISASM_ARM_FEATURE_CRC32)
#define ARM_CAPS_OPTIONAL_RAS_WORD1 \
    (UINT64_C(1) << (CDISASM_ARM_FEATURE_RAS - 64u))
#define ARM_CAPS_OPTIONAL_TRF_WORD2 \
    (UINT64_C(1) << (CDISASM_ARM_FEATURE_TRF - 128u))
#define ARM_CAPS_OPTIONAL_SME \
    (CDISASM_ARM_CAP_SME | CDISASM_ARM_CAP_SME2)
#else
#define ARM_CAPS_OPTIONAL_VFP UINT32_C(0)
#define ARM_CAPS_OPTIONAL_PAUTH UINT32_C(0)
#define ARM_CAPS_OPTIONAL_FP16 UINT32_C(0)
#define ARM_CAPS_OPTIONAL_SVE UINT32_C(0)
#define ARM_CAPS_OPTIONAL_BF16 UINT32_C(0)
#define ARM_CAPS_OPTIONAL_CRC32 UINT64_C(0)
#define ARM_CAPS_OPTIONAL_RAS_WORD1 UINT64_C(0)
#define ARM_CAPS_OPTIONAL_TRF_WORD2 UINT64_C(0)
#define ARM_CAPS_OPTIONAL_SME UINT32_C(0)
#endif
#define ARM_CAPABILITIES_HINTS_INITIALIZER(mask_, word1_, word2_) \
    {{ \
        (uint64_t)(mask_), (uint64_t)(word1_), (uint64_t)(word2_), \
        UINT64_C(0), UINT64_C(0), UINT64_C(0), UINT64_C(0), \
        UINT64_C(0) \
    }}
#define ARM_CAPS_V7_NEON \
    (ARM_CAPS_V7 | CDISASM_ARM_CAP_NEON | ARM_CAPS_OPTIONAL_VFP)
#define ARM_CAPS_V7_MP (ARM_CAPS_V7 | CDISASM_ARM_CAP_MP)
#define ARM_CAPS_V7_NEON_MP (ARM_CAPS_V7_NEON | CDISASM_ARM_CAP_MP)
#define ARM_CAPS_STANDARD_ALL \
    (CDISASM_ARM_CAP_STANDARD_ALL | ARM_CAPS_OPTIONAL_VFP \
        | CDISASM_ARM_CAP_MP)
#define ARM_CAPS_STANDARD_CRC32 \
    (ARM_CAPS_STANDARD_ALL | ARM_CAPS_OPTIONAL_CRC32)
#define ARM_CAPS_APPLE_A7 \
    (ARM_CAPS_STANDARD_ALL | CDISASM_ARM_CAP_APPLE_A7_SYSREG)
#define ARM_CAPS_APPLE_MUL53 \
    (ARM_CAPS_STANDARD_ALL | CDISASM_ARM_CAP_APPLE_MUL53)
#define ARM_CAPS_LOR CDISASM_ARM_CAP_LOR
#define ARM_CAPS_LSE_LOR \
    (CDISASM_ARM_CAP_LSE | CDISASM_ARM_CAP_LOR)
#define ARM_CAPS_LSE_LOR_RCPC \
    (ARM_CAPS_LSE_LOR | CDISASM_ARM_CAP_RCPC)
#define ARM_CAPS_APPLE_A10 \
    (ARM_CAPS_STANDARD_CRC32 | ARM_CAPS_LOR)
#define ARM_CAPS_APPLE_A11 \
    (ARM_CAPS_APPLE_MUL53 | ARM_CAPS_LSE_LOR | ARM_CAPS_OPTIONAL_FP16 \
        | ARM_CAPS_OPTIONAL_CRC32)
#define ARM_CAPS_APPLE_A12_PLUS \
    (ARM_CAPS_APPLE_MUL53 | ARM_CAPS_LSE_LOR_RCPC \
        | ARM_CAPS_OPTIONAL_PAUTH | ARM_CAPS_OPTIONAL_FP16 \
        | ARM_CAPS_OPTIONAL_CRC32)
#define ARM_CAPS_APPLE_A18 \
    (ARM_CAPS_APPLE_A12_PLUS | ARM_CAPS_OPTIONAL_SME \
        | ARM_CAPS_OPTIONAL_BF16)
#define ARM_CAPS_APPLE_M1_M3 \
    (ARM_CAPS_APPLE_MUL53 | CDISASM_ARM_CAP_APPLE_AMX \
        | CDISASM_ARM_CAP_APPLE_SYS | ARM_CAPS_LSE_LOR_RCPC \
        | ARM_CAPS_OPTIONAL_PAUTH | ARM_CAPS_OPTIONAL_FP16 \
        | ARM_CAPS_OPTIONAL_CRC32)
#define ARM_CAPS_APPLE_M4 \
    (ARM_CAPS_APPLE_M1_M3 | ARM_CAPS_OPTIONAL_SME \
        | ARM_CAPS_OPTIONAL_BF16)
#define ARM_CAPS_APPLE_M5 \
    (ARM_CAPS_APPLE_MUL53 | CDISASM_ARM_CAP_APPLE_SYS \
        | ARM_CAPS_LSE_LOR_RCPC | ARM_CAPS_OPTIONAL_PAUTH \
        | ARM_CAPS_OPTIONAL_FP16 | ARM_CAPS_OPTIONAL_CRC32)
#define ARM_CAPS_APPLE_S \
    (ARM_CAPS_STANDARD_ALL | ARM_CAPS_LSE_LOR_RCPC \
        | ARM_CAPS_OPTIONAL_PAUTH | ARM_CAPS_OPTIONAL_FP16 \
        | ARM_CAPS_OPTIONAL_CRC32)
#define ARM_CAPS_FUJITSU_A64FX \
    (ARM_CAPS_STANDARD_ALL | CDISASM_ARM_CAP_NEON | ARM_CAPS_OPTIONAL_SVE \
        | ARM_CAPS_OPTIONAL_CRC32)

static const arm_cpu_profile arm_cpu_profiles[] = {
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32
          | CDISASM_ARM_MODE_MASK_A64,
      CDISASM_ARM_CAPABILITIES_ALL_INITIALIZER }, /* unrestricted analysis */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(CDISASM_ARM_CAP_V4) }, /* ARM7TDMI */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_V7_MP) }, /* Cortex-A7 without optional NEON */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_V7_MP) }, /* Cortex-A9 without optional NEON */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_STANDARD_CRC32) }, /* Cortex-A32 */
    { CDISASM_ARM_MODE_MASK_A64, CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_STANDARD_CRC32) }, /* Cortex-A34 */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32
          | CDISASM_ARM_MODE_MASK_A64,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_STANDARD_CRC32) }, /* Cortex-A35 */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32
          | CDISASM_ARM_MODE_MASK_A64,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_STANDARD_CRC32) }, /* Cortex-A53 */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_V7_NEON_MP) }, /* Cortex-A9 with optional NEON */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_V7_NEON) }, /* Apple A4 */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_V7_NEON) }, /* Apple A5 */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_V7_NEON) }, /* Apple A6 */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32
          | CDISASM_ARM_MODE_MASK_A64,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_APPLE_A7) }, /* Apple A7 */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32
          | CDISASM_ARM_MODE_MASK_A64,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_STANDARD_ALL) }, /* Apple A8 */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32
          | CDISASM_ARM_MODE_MASK_A64,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_STANDARD_ALL) }, /* Apple A9 */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32
          | CDISASM_ARM_MODE_MASK_A64,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_APPLE_A10) }, /* Apple A10 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_A11, ARM_CAPS_OPTIONAL_RAS_WORD1, 0) }, /* Apple A11 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_A12_PLUS, ARM_CAPS_OPTIONAL_RAS_WORD1, 0) }, /* Apple A12 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_A12_PLUS, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple A13 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_A12_PLUS, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple A14 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_A12_PLUS, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple A15 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_A12_PLUS, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple A16 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_A12_PLUS, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple A17 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_A18, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple A18 */
    { CDISASM_ARM_MODE_MASK_A64, CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_APPLE_A12_PLUS) }, /* Apple A19 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_M1_M3, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple M1 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_M1_M3, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple M2 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_M1_M3, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple M3 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_M4, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple M4 */
    { CDISASM_ARM_MODE_MASK_A64, CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_APPLE_M5) }, /* Apple M5 */
    { CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32,
      CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(ARM_CAPS_V7_NEON_MP) }, /* Cortex-A7 with optional NEON */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_S, ARM_CAPS_OPTIONAL_RAS_WORD1, 0) }, /* Apple S4 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_S, ARM_CAPS_OPTIONAL_RAS_WORD1, 0) }, /* Apple S5 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_S, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple S6 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_S, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple S7 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_S, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple S8 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_S, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple S9 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_APPLE_S, ARM_CAPS_OPTIONAL_RAS_WORD1,
          ARM_CAPS_OPTIONAL_TRF_WORD2) }, /* Apple S10 */
    { CDISASM_ARM_MODE_MASK_A64,
      ARM_CAPABILITIES_HINTS_INITIALIZER(
          ARM_CAPS_FUJITSU_A64FX, ARM_CAPS_OPTIONAL_RAS_WORD1, 0) } /* A64FX */
};

_Static_assert(
    sizeof(arm_cpu_profiles) / sizeof(arm_cpu_profiles[0])
        == CDISASM_CPU_ORDINAL_OF(CDISASM_ARM_CPU_LAST) + 1u,
    "ARM CPU profile table must cover every public CPU ID");

#define CDISASM_ARM_IMPLEMENTED_MODE_MASK \
    (CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32 \
        | CDISASM_ARM_MODE_MASK_A64)

static const uint64_t arm_known_flag_masks[
    CDISASM_DECODE_FLAGS_BITMAP_COUNT] = {
    CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_0,
    CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_1,
    CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_2,
    CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_3,
    CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_4,
    CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_5,
    CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_6,
    CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_7
};

static int valid_cpu(cdisasm_arm_cpu_id cpu_id)
{
    return CDISASM_CPU_GROUP_OF(cpu_id) == CDISASM_CPU_GROUP_ARM
        && CDISASM_CPU_ORDINAL_OF(cpu_id)
            <= CDISASM_CPU_ORDINAL_OF(CDISASM_ARM_CPU_LAST);
}

static size_t cpu_profile_index(cdisasm_arm_cpu_id cpu_id)
{
    return (size_t)CDISASM_CPU_ORDINAL_OF(cpu_id);
}

static int capabilities_satisfy_requirements(
    const cdisasm_arm_capabilities *capabilities,
    const cdisasm_arm_requirements *requirements)
{
    cdisasm_arm_alternative_requirements alternatives =
        requirements->alternatives;

    if ((alternatives & CDISASM_ARM_ALTERNATIVE_SVE2_OR_SME2) != 0u) {
        if (!cdisasm_arm_capabilities_have_any_legacy(
                capabilities,
                CDISASM_ARM_CAP_SVE2 | CDISASM_ARM_CAP_SME2)) {
            return 0;
        }
    }
    if ((alternatives & CDISASM_ARM_ALTERNATIVE_SVE2P2_OR_SME2P2)
        != 0u) {
        if (!cdisasm_arm_capabilities_have_any_legacy(
                capabilities,
                CDISASM_ARM_CAP_SVE2P2 | CDISASM_ARM_CAP_SME2P2)) {
            return 0;
        }
    }
    if ((alternatives & CDISASM_ARM_ALTERNATIVE_SVE_OR_SME) != 0u) {
        if (!cdisasm_arm_capabilities_have_any_legacy(
                capabilities,
                CDISASM_ARM_CAP_SVE | CDISASM_ARM_CAP_SME)) {
            return 0;
        }
    }
    if ((alternatives & CDISASM_ARM_ALTERNATIVE_SVE2_OR_SME) != 0u) {
        if (!cdisasm_arm_capabilities_have_any_legacy(
                capabilities,
                CDISASM_ARM_CAP_SVE2 | CDISASM_ARM_CAP_SME)) {
            return 0;
        }
    }
    if ((alternatives & CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME2P1)
        != 0u) {
        if (!cdisasm_arm_capabilities_have_any_legacy(
                capabilities,
                CDISASM_ARM_CAP_SVE2P1 | CDISASM_ARM_CAP_SME2P1)) {
            return 0;
        }
    }
    if ((alternatives & CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME2) != 0u) {
        if (!cdisasm_arm_capabilities_have_any_legacy(
                capabilities,
                CDISASM_ARM_CAP_SVE2P1 | CDISASM_ARM_CAP_SME2)) {
            return 0;
        }
    }
    if ((alternatives & CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME) != 0u) {
        if (!cdisasm_arm_capabilities_have_any_legacy(
                capabilities,
                CDISASM_ARM_CAP_SVE2P1 | CDISASM_ARM_CAP_SME)) {
            return 0;
        }
    }
    if ((alternatives & CDISASM_ARM_ALTERNATIVE_SVE2P3_OR_SME2P3)
        != 0u) {
        if (!cdisasm_arm_capabilities_has_feature(
                capabilities, CDISASM_ARM_FEATURE_SVE2P3)
            && !cdisasm_arm_capabilities_has_feature(
                capabilities, CDISASM_ARM_FEATURE_SME2P3)) {
            return 0;
        }
    }
    if ((alternatives & CDISASM_ARM_ALTERNATIVE_SME_F16F16_OR_F8F16)
        != 0u) {
        if (!cdisasm_arm_capabilities_has_feature(
                capabilities, CDISASM_ARM_FEATURE_SME_F16F16)
            && !cdisasm_arm_capabilities_has_feature(
                capabilities, CDISASM_ARM_FEATURE_SME_F8F16)) {
            return 0;
        }
    }
    if ((alternatives
            & CDISASM_ARM_ALTERNATIVE_FP8DOT2_OR_SSVE_FP8DOT2) != 0u) {
        if (!cdisasm_arm_capabilities_has_feature(
                capabilities, CDISASM_ARM_FEATURE_FP8DOT2)
            && !cdisasm_arm_capabilities_has_feature(
                capabilities, CDISASM_ARM_FEATURE_SSVE_FP8DOT2)) {
            return 0;
        }
    }
    if ((alternatives
            & CDISASM_ARM_ALTERNATIVE_FP8DOT4_OR_SSVE_FP8DOT4) != 0u) {
        if (!cdisasm_arm_capabilities_has_feature(
                capabilities, CDISASM_ARM_FEATURE_FP8DOT4)
            && !cdisasm_arm_capabilities_has_feature(
                capabilities, CDISASM_ARM_FEATURE_SSVE_FP8DOT4)) {
            return 0;
        }
    }
    if ((alternatives
            & CDISASM_ARM_ALTERNATIVE_FP8FMA_OR_SSVE_FP8FMA) != 0u) {
        if (!cdisasm_arm_capabilities_has_feature(
                capabilities, CDISASM_ARM_FEATURE_FP8FMA)
            && !cdisasm_arm_capabilities_has_feature(
                capabilities, CDISASM_ARM_FEATURE_SSVE_FP8FMA)) {
            return 0;
        }
    }
    return cdisasm_arm_capabilities_have_all(
        capabilities, &requirements->features);
}

static cdisasm_arm_mode_mask mode_bit(cdisasm_arm_mode mode)
{
    switch (mode) {
        case CDISASM_ARM_MODE_A32:
            return CDISASM_ARM_MODE_MASK_A32;
        case CDISASM_ARM_MODE_T32:
            return CDISASM_ARM_MODE_MASK_T32;
        case CDISASM_ARM_MODE_A64:
            return CDISASM_ARM_MODE_MASK_A64;
        default:
            return CDISASM_ARM_MODE_MASK_NONE;
    }
}

#define ARM_FAMILY_MODES_A32_T32 \
    (CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32)
#define ARM_FAMILY_MODES_ALL \
    (CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32 \
        | CDISASM_ARM_MODE_MASK_A64)
#define ARM_FAMILY_MODES_A64 CDISASM_ARM_MODE_MASK_A64

#define ARM_FAMILY_CAP_DESCRIPTOR(id_, cap_, modes_, vendor_) \
    [id_] = { id_, (uint64_t)(cap_), CDISASM_ARM_FAMILY_FEATURE_NONE, \
        modes_, vendor_ }
#define ARM_FAMILY_FEATURE_DESCRIPTOR(id_, feature_, modes_, vendor_) \
    [id_] = { id_, UINT64_C(0), feature_, modes_, vendor_ }

static const cdisasm_arm_family_descriptor arm_family_descriptors[
    CDISASM_ARM_FAMILY_LAST + UINT16_C(1)] = {
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_V4,
        CDISASM_ARM_CAP_V4, ARM_FAMILY_MODES_A32_T32,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_V5,
        CDISASM_ARM_CAP_V5, ARM_FAMILY_MODES_A32_T32,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_V6,
        CDISASM_ARM_CAP_V6, ARM_FAMILY_MODES_A32_T32,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_V7,
        CDISASM_ARM_CAP_V7, ARM_FAMILY_MODES_A32_T32,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_V8,
        CDISASM_ARM_CAP_V8, ARM_FAMILY_MODES_ALL,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_NEON,
        CDISASM_ARM_CAP_NEON, ARM_FAMILY_MODES_ALL,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_VFP,
        CDISASM_ARM_CAP_VFP, ARM_FAMILY_MODES_ALL,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_FP16,
        CDISASM_ARM_CAP_FP16, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_SVE,
        CDISASM_ARM_CAP_SVE, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_SVE2,
        CDISASM_ARM_CAP_SVE2, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_SME,
        CDISASM_ARM_CAP_SME, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_SME2,
        CDISASM_ARM_CAP_SME2, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_LSE,
        CDISASM_ARM_CAP_LSE, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_LSE2,
        CDISASM_ARM_CAP_LSE2, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_LSE128,
        CDISASM_ARM_CAP_LSE128, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_RCPC,
        CDISASM_ARM_CAP_RCPC, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_RCPC3,
        CDISASM_ARM_CAP_RCPC3, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_BTI,
        CDISASM_ARM_CAP_BTI, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_PAUTH,
        CDISASM_ARM_CAP_PAUTH, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_MTE,
        CDISASM_ARM_CAP_MTE, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_MOPS,
        CDISASM_ARM_CAP_MOPS, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_LS64,
        CDISASM_ARM_CAP_LS64, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_CSSC,
        CDISASM_ARM_CAP_CSSC, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_BF16,
        CDISASM_ARM_CAP_BF16, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_FP8,
        CDISASM_ARM_CAP_FP8, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_F64MM,
        CDISASM_ARM_CAP_F64MM, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_APPLE_MUL53,
        CDISASM_ARM_CAP_APPLE_MUL53, ARM_FAMILY_MODES_ALL,
        CDISASM_ARM_FAMILY_VENDOR_APPLE),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_APPLE_AMX,
        CDISASM_ARM_CAP_APPLE_AMX, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_APPLE),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_APPLE_SYS,
        CDISASM_ARM_CAP_APPLE_SYS, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_APPLE),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_APPLE_A7_SYSREG,
        CDISASM_ARM_CAP_APPLE_A7_SYSREG, ARM_FAMILY_MODES_ALL,
        CDISASM_ARM_FAMILY_VENDOR_APPLE),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_CPA,
        CDISASM_ARM_CAP_CPA, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_MP,
        CDISASM_ARM_CAP_MP, ARM_FAMILY_MODES_A32_T32,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_CRC32,
        CDISASM_ARM_FEATURE_CRC32, ARM_FAMILY_MODES_ALL,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_AES,
        CDISASM_ARM_FEATURE_AES, ARM_FAMILY_MODES_ALL,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_PMULL,
        CDISASM_ARM_FEATURE_PMULL, ARM_FAMILY_MODES_ALL,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_SHA,
        CDISASM_ARM_FEATURE_SHA1, ARM_FAMILY_MODES_ALL,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_SM3,
        CDISASM_ARM_FEATURE_SM3, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_SM4,
        CDISASM_ARM_FEATURE_SM4, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_DOTPROD,
        CDISASM_ARM_FEATURE_DOTPROD, ARM_FAMILY_MODES_ALL,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_FCMA,
        CDISASM_ARM_FEATURE_FCMA, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_FHM,
        CDISASM_ARM_FEATURE_FHM, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_AA32I8MM,
        CDISASM_ARM_FEATURE_AA32I8MM, ARM_FAMILY_MODES_A32_T32,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_PAN,
        CDISASM_ARM_FEATURE_PAN, ARM_FAMILY_MODES_ALL,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_RAS,
        CDISASM_ARM_FEATURE_RAS, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_TRF,
        CDISASM_ARM_FEATURE_TRF, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_CLRBHB,
        CDISASM_ARM_FEATURE_CLRBHB, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_GCS,
        CDISASM_ARM_FEATURE_GCS, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_PAUTH_LR,
        CDISASM_ARM_FEATURE_PAUTH_LR, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_SVE2P1,
        CDISASM_ARM_CAP_SVE2P1, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_SME2P1,
        CDISASM_ARM_CAP_SME2P1, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_SVE2P2,
        CDISASM_ARM_CAP_SVE2P2, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_CAP_DESCRIPTOR(CDISASM_ARM_FAMILY_SME2P2,
        CDISASM_ARM_CAP_SME2P2, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_SVE2P3,
        CDISASM_ARM_FEATURE_SVE2P3, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_SME2P3,
        CDISASM_ARM_FEATURE_SME2P3, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_FAMINMAX,
        CDISASM_ARM_FEATURE_FAMINMAX, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_FPRCVT,
        CDISASM_ARM_FEATURE_FPRCVT, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_JSCVT,
        CDISASM_ARM_FEATURE_JSCVT, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_CHK,
        CDISASM_ARM_FEATURE_CHK, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_DGH,
        CDISASM_ARM_FEATURE_DGH, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM),
    ARM_FAMILY_FEATURE_DESCRIPTOR(CDISASM_ARM_FAMILY_SPE,
        CDISASM_ARM_FEATURE_SPE, ARM_FAMILY_MODES_A64,
        CDISASM_ARM_FAMILY_VENDOR_ARM)
};

static int arm_family_capability_present(
    cdisasm_arm_family_id family_id,
    const cdisasm_arm_capabilities *capabilities)
{
    const cdisasm_arm_family_descriptor *descriptor;

    if (capabilities == NULL
        || family_id < CDISASM_ARM_FAMILY_FIRST
        || family_id > CDISASM_ARM_FAMILY_LAST) {
        return 0;
    }
    descriptor = &arm_family_descriptors[family_id];
    if (family_id == CDISASM_ARM_FAMILY_SHA) {
        return cdisasm_arm_capabilities_has_feature(
                   capabilities, CDISASM_ARM_FEATURE_SHA1)
            || cdisasm_arm_capabilities_has_feature(
                   capabilities, CDISASM_ARM_FEATURE_SHA256)
            || cdisasm_arm_capabilities_has_feature(
                   capabilities, CDISASM_ARM_FEATURE_SHA3)
            || cdisasm_arm_capabilities_has_feature(
                   capabilities, CDISASM_ARM_FEATURE_SHA512);
    }
    if (descriptor->required_capability != UINT64_C(0)) {
        return (capabilities->bitmap[0] & descriptor->required_capability)
            != 0;
    }
    return descriptor->required_feature != CDISASM_ARM_FAMILY_FEATURE_NONE
        && cdisasm_arm_capabilities_has_feature(
            capabilities, descriptor->required_feature);
}

static cdisasm_arm_family_mask arm_family_mask_from_capabilities(
    const cdisasm_arm_capabilities *capabilities,
    cdisasm_arm_mode mode)
{
    const cdisasm_arm_mode_mask selected_mode = mode_bit(mode);
    cdisasm_arm_family_mask family_mask = CDISASM_ARM_FAMILY_MASK_NONE;
    cdisasm_arm_family_id family_id;

    if (selected_mode == CDISASM_ARM_MODE_MASK_NONE) {
        return family_mask;
    }
    for (family_id = CDISASM_ARM_FAMILY_FIRST;
         family_id <= CDISASM_ARM_FAMILY_LAST;
         ++family_id) {
        const cdisasm_arm_family_descriptor *descriptor =
            &arm_family_descriptors[family_id];

        if ((descriptor->allowed_modes & selected_mode) != 0
            && arm_family_capability_present(family_id, capabilities)) {
            family_mask |= CDISASM_ARM_FAMILY_MASK_FOR_ID(family_id);
        }
    }
    return family_mask;
}

#undef ARM_FAMILY_CAP_DESCRIPTOR
#undef ARM_FAMILY_FEATURE_DESCRIPTOR

static uint32_t read_u32_le(const uint8_t *code)
{
    return (uint32_t)code[0]
        | ((uint32_t)code[1] << 8)
        | ((uint32_t)code[2] << 16)
        | ((uint32_t)code[3] << 24);
}

static uint32_t read_u32_be(const uint8_t *code)
{
    return ((uint32_t)code[0] << 24)
        | ((uint32_t)code[1] << 16)
        | ((uint32_t)code[2] << 8)
        | (uint32_t)code[3];
}

static uint16_t read_u16_le(const uint8_t *code)
{
    return (uint16_t)((uint16_t)code[0] | ((uint16_t)code[1] << 8));
}

static uint16_t read_u16_be(const uint8_t *code)
{
    return (uint16_t)(((uint16_t)code[0] << 8) | (uint16_t)code[1]);
}

static uint32_t read_u32(const uint8_t *code, int big_endian)
{
    return big_endian ? read_u32_be(code) : read_u32_le(code);
}

static uint16_t read_u16(const uint8_t *code, int big_endian)
{
    return big_endian ? read_u16_be(code) : read_u16_le(code);
}

cdisasm_arm_mode_mask CDISASM_CALL cdisasm_arm_cpu_mode_mask(
    cdisasm_arm_cpu_id cpu_id)
{
    if (!valid_cpu(cpu_id)) {
        return CDISASM_ARM_MODE_MASK_NONE;
    }
    return arm_cpu_profiles[cpu_profile_index(cpu_id)].mode_mask;
}

cdisasm_arm_mode_mask CDISASM_CALL cdisasm_arm_decoder_mode_mask(
    cdisasm_arm_cpu_id cpu_id)
{
    if (!valid_cpu(cpu_id)) {
        return CDISASM_ARM_MODE_MASK_NONE;
    }
    return arm_cpu_profiles[cpu_profile_index(cpu_id)].mode_mask
        & CDISASM_ARM_IMPLEMENTED_MODE_MASK;
}

cdisasm_status CDISASM_CALL cdisasm_arm_cpu_decode_flag_mask(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    cdisasm_arm_decode_flags *flags)
{
    cdisasm_arm_mode_mask selected_mode;

    if (flags == NULL) {
        return CDISASM_STATUS_INVALID_ARGUMENT;
    }
    cdisasm_decode_flags_reset(flags);
    selected_mode = mode_bit(mode);
    if (!valid_cpu(cpu_id)
        || selected_mode == CDISASM_ARM_MODE_MASK_NONE
        || (arm_cpu_profiles[cpu_profile_index(cpu_id)].mode_mask
            & selected_mode) == 0) {
        return CDISASM_STATUS_INVALID_ARGUMENT;
    }
    flags->bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP] =
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN;
    if (mode == CDISASM_ARM_MODE_T32) {
        flags->bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP] |=
            CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK;
    }
    return CDISASM_STATUS_OK;
}

cdisasm_arm_family_mask CDISASM_CALL cdisasm_arm_cpu_family_mask(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode)
{
    const cdisasm_arm_mode_mask selected_mode = mode_bit(mode);

    if (!valid_cpu(cpu_id)
        || selected_mode == CDISASM_ARM_MODE_MASK_NONE
        || (arm_cpu_profiles[cpu_profile_index(cpu_id)].mode_mask
            & selected_mode) == 0) {
        return CDISASM_ARM_FAMILY_MASK_NONE;
    }
    return arm_family_mask_from_capabilities(
        &arm_cpu_profiles[cpu_profile_index(cpu_id)].capabilities,
        mode);
}

const cdisasm_arm_family_descriptor *CDISASM_CALL
cdisasm_arm_family_descriptor_get(cdisasm_arm_family_id family_id)
{
    if (family_id < CDISASM_ARM_FAMILY_FIRST
        || family_id > CDISASM_ARM_FAMILY_LAST) {
        return NULL;
    }
    return &arm_family_descriptors[family_id];
}

static cdisasm_arm_family_mask arm_family_mask_for_id(
    cdisasm_arm_family_id family_id)
{
    if (family_id < CDISASM_ARM_FAMILY_FIRST
        || family_id > CDISASM_ARM_FAMILY_LAST) {
        return CDISASM_ARM_FAMILY_MASK_NONE;
    }
    return CDISASM_ARM_FAMILY_MASK_FOR_ID(family_id);
}

cdisasm_status CDISASM_CALL cdisasm_arm_cpu_decode_context(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    cdisasm_arm_decode_context *context)
{
    cdisasm_status status;

    if (context == NULL) {
        return CDISASM_STATUS_INVALID_ARGUMENT;
    }
    memset(context, 0, sizeof(*context));
    status = cdisasm_arm_cpu_decode_flag_mask(
        cpu_id, mode, &context->flags);
    if (status != CDISASM_STATUS_OK) {
        return status;
    }
    context->cpu_id = cpu_id;
    context->mode = mode;
    context->family_mask = cdisasm_arm_cpu_family_mask(cpu_id, mode);
    context->family_value = context->family_mask
        & CDISASM_ARM_FAMILY_MASK_DEFAULT;
    return CDISASM_STATUS_OK;
}

int CDISASM_CALL cdisasm_arm_decode_context_add_family(
    cdisasm_arm_decode_context *context,
    cdisasm_arm_family_id family_id)
{
    const cdisasm_arm_family_mask family_mask =
        arm_family_mask_for_id(family_id);

    if (context == NULL || family_mask == CDISASM_ARM_FAMILY_MASK_NONE
        || (context->family_mask & family_mask) == 0) {
        return 0;
    }
    context->family_value |= family_mask;
    return 1;
}

int CDISASM_CALL cdisasm_arm_decode_context_remove_family(
    cdisasm_arm_decode_context *context,
    cdisasm_arm_family_id family_id)
{
    const cdisasm_arm_family_mask family_mask =
        arm_family_mask_for_id(family_id);

    if (context == NULL || family_mask == CDISASM_ARM_FAMILY_MASK_NONE
        || (context->family_mask & family_mask) == 0) {
        return 0;
    }
    context->family_value &= ~family_mask;
    return 1;
}

cdisasm_arm_family_mask CDISASM_CALL
cdisasm_arm_decode_context_get_available_families(
    const cdisasm_arm_decode_context *context)
{
    return context == NULL
        ? CDISASM_ARM_FAMILY_MASK_NONE
        : context->family_mask;
}

cdisasm_arm_family_mask CDISASM_CALL
cdisasm_arm_decode_context_get_set_families(
    const cdisasm_arm_decode_context *context)
{
    return context == NULL
        ? CDISASM_ARM_FAMILY_MASK_NONE
        : context->family_value & context->family_mask;
}

uint32_t CDISASM_CALL cdisasm_arm_decode(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    const cdisasm_arm_decode_flags *flags,
    cdisasm_arm_instruction *instruction)
{
    cdisasm_arm_decode_flags flags_snapshot;
    const cdisasm_arm_decode_flags *selected_flags = flags;
    cdisasm_arm_mode_mask selected_mode;
    cdisasm_status status;
    cdisasm_arm_requirements required_capabilities =
        CDISASM_ARM_REQUIREMENTS_NONE_INITIALIZER;
    uint32_t raw_instruction;
    uint32_t opcode_size;
    int big_endian;
    int in_it_block;
    uint32_t bitmap_index;

    if (instruction == NULL) {
        return 0;
    }
    if (flags != NULL) {
        flags_snapshot = *flags;
        selected_flags = &flags_snapshot;
    }
    memset(instruction, 0, sizeof(*instruction));

    selected_mode = mode_bit(mode);
    if (!valid_cpu(cpu_id)
        || selected_mode == CDISASM_ARM_MODE_MASK_NONE
        || (arm_cpu_profiles[cpu_profile_index(cpu_id)].mode_mask
            & selected_mode) == 0) {
        instruction->last_error_id = (uint8_t)CDISASM_STATUS_INVALID_ARGUMENT;
        return 0;
    }
    if (selected_flags != NULL) {
        for (bitmap_index = 0;
             bitmap_index < CDISASM_DECODE_FLAGS_BITMAP_COUNT;
             ++bitmap_index) {
            if ((selected_flags->bitmap[bitmap_index]
                 & ~arm_known_flag_masks[bitmap_index]) != 0) {
                instruction->last_error_id =
                    (uint8_t)CDISASM_STATUS_INVALID_ARGUMENT;
                return 0;
            }
        }
    }
    big_endian = selected_flags != NULL
        && (selected_flags->bitmap[0]
            & CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN) != 0;
    in_it_block = selected_flags != NULL
        && (selected_flags->bitmap[0]
            & CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK) != 0;
    if (in_it_block && mode != CDISASM_ARM_MODE_T32) {
        instruction->last_error_id = (uint8_t)CDISASM_STATUS_INVALID_ARGUMENT;
        return 0;
    }
    if (code_size == 0) {
        instruction->last_error_id = (uint8_t)CDISASM_STATUS_END_OF_INPUT;
        return 0;
    }
    if (code == NULL) {
        instruction->last_error_id = (uint8_t)CDISASM_STATUS_INVALID_ARGUMENT;
        return 0;
    }
    opcode_size = CDISASM_ARM_MAX_INSTRUCTION_SIZE;
    if (mode == CDISASM_ARM_MODE_T32) {
        uint16_t first_halfword;

        if (code_size < 2u) {
            instruction->last_error_id = (uint8_t)CDISASM_STATUS_TRUNCATED;
            return 0;
        }
        first_halfword = read_u16(code, big_endian);
        opcode_size = cdisasm_arm_t32_instruction_size(first_halfword);
        if (code_size < opcode_size) {
            instruction->last_error_id = (uint8_t)CDISASM_STATUS_TRUNCATED;
            return 0;
        }
        raw_instruction = first_halfword;
        if (opcode_size == 4u) {
            raw_instruction |= (uint32_t)read_u16(code + 2, big_endian) << 16;
        }
        status = cdisasm_arm_decode_t32_core(
            raw_instruction,
            opcode_size,
            address,
            instruction,
            &required_capabilities);
    } else if (code_size < CDISASM_ARM_MAX_INSTRUCTION_SIZE) {
        instruction->last_error_id = (uint8_t)CDISASM_STATUS_TRUNCATED;
        return 0;
    } else {
        raw_instruction = read_u32(code, big_endian);
#if USE_EXTRA_OPCODES
        status = cpu_id == CDISASM_ARM_CPU_ANY
            ? cdisasm_arm_decode_generated_priority(
                raw_instruction,
                opcode_size,
                address,
                mode,
                instruction)
            : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        if (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
#endif
        status = cdisasm_arm_decode_core(
            raw_instruction,
            address,
            mode,
            instruction,
            &required_capabilities);
#if USE_EXTRA_OPCODES
        }
#endif
    }
#if USE_EXTRA_OPCODES
    if (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
        && (cpu_id == CDISASM_ARM_CPU_ANY
            || mode == CDISASM_ARM_MODE_A64)) {
        status = cdisasm_arm_decode_generated(
            raw_instruction,
            opcode_size,
            address,
            mode,
            &arm_cpu_profiles[cpu_profile_index(cpu_id)].capabilities,
            cpu_id == CDISASM_ARM_CPU_ANY,
            in_it_block,
            instruction);
        required_capabilities = (cdisasm_arm_requirements)
            CDISASM_ARM_REQUIREMENTS_NONE_INITIALIZER;
    }
#endif
    if (status == CDISASM_STATUS_OK
        && !capabilities_satisfy_requirements(
            &arm_cpu_profiles[cpu_profile_index(cpu_id)].capabilities,
            &required_capabilities)) {
        status = CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    if (status != CDISASM_STATUS_OK) {
        memset(instruction, 0, sizeof(*instruction));
        instruction->last_error_id = (uint8_t)status;
        return 0;
    }
#if USE_EXTRA_OPCODES
    if (cdisasm_arm_attach_generated_identity(
            raw_instruction,
            opcode_size,
            mode,
            &arm_cpu_profiles[cpu_profile_index(cpu_id)].capabilities,
            instruction)
        && in_it_block
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        (void)cdisasm_arm_apply_generated_it_context(
            &arm_cpu_profiles[cpu_profile_index(cpu_id)].capabilities,
            instruction);
    }
#endif
    return instruction->opcode_size;
}

uint32_t CDISASM_CALL cdisasm_arm_decode_with_context(
    const cdisasm_arm_decode_context *context,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_arm_instruction *instruction)
{
    if (context == NULL) {
        if (instruction != NULL) {
            memset(instruction, 0, sizeof(*instruction));
            instruction->last_error_id =
                (uint8_t)CDISASM_STATUS_INVALID_ARGUMENT;
        }
        return 0;
    }
    return cdisasm_arm_decode(
        context->cpu_id,
        context->mode,
        code,
        code_size,
        address,
        &context->flags,
        instruction);
}
