#ifndef CDISASM_ARM_DECODER_H
#define CDISASM_ARM_DECODER_H

#include "cdisasm/cdisasm_arm.h"

/*
 * Internal feature storage is deliberately wider than the public decode ABI.
 * AARCHMRS-generated feature catalogs can assign any stable ID in 0..511
 * without changing decoder function signatures or CPU-profile layout again.
 */
typedef uint16_t cdisasm_arm_feature_id;
#define CDISASM_ARM_FEATURE_BIT_COUNT UINT16_C(512)
#define CDISASM_ARM_FEATURE_WORD_COUNT UINT16_C(8)

typedef struct cdisasm_arm_capabilities {
    uint64_t bitmap[CDISASM_ARM_FEATURE_WORD_COUNT];
} cdisasm_arm_capabilities;

/* Alternative feature predicates are requirements, not CPU capabilities. */
typedef uint32_t cdisasm_arm_alternative_requirements;
#define CDISASM_ARM_ALTERNATIVE_SVE2_OR_SME2 (UINT32_C(1) << 0)
#define CDISASM_ARM_ALTERNATIVE_SVE2P2_OR_SME2P2 (UINT32_C(1) << 1)
#define CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME2P1 (UINT32_C(1) << 2)
#define CDISASM_ARM_ALTERNATIVE_SVE2_OR_SME (UINT32_C(1) << 3)
#define CDISASM_ARM_ALTERNATIVE_SVE_OR_SME (UINT32_C(1) << 4)
#define CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME2 (UINT32_C(1) << 5)
#define CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME (UINT32_C(1) << 6)
#define CDISASM_ARM_ALTERNATIVE_SVE2P3_OR_SME2P3 (UINT32_C(1) << 7)
#define CDISASM_ARM_ALTERNATIVE_SME_F16F16_OR_F8F16 (UINT32_C(1) << 8)
#define CDISASM_ARM_ALTERNATIVE_FP8DOT2_OR_SSVE_FP8DOT2 (UINT32_C(1) << 9)
#define CDISASM_ARM_ALTERNATIVE_FP8DOT4_OR_SSVE_FP8DOT4 (UINT32_C(1) << 10)
#define CDISASM_ARM_ALTERNATIVE_FP8FMA_OR_SSVE_FP8FMA (UINT32_C(1) << 11)

_Static_assert(
    (CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME
        & (CDISASM_ARM_ALTERNATIVE_SVE2_OR_SME2
            | CDISASM_ARM_ALTERNATIVE_SVE2P2_OR_SME2P2
            | CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME2P1
            | CDISASM_ARM_ALTERNATIVE_SVE2_OR_SME
            | CDISASM_ARM_ALTERNATIVE_SVE_OR_SME
            | CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME2
            | CDISASM_ARM_ALTERNATIVE_SVE2P3_OR_SME2P3)) == 0u,
    "PSEL ARM alternative-requirement bit overlaps an existing bit");

_Static_assert(
    (CDISASM_ARM_ALTERNATIVE_SVE2P3_OR_SME2P3
        & (CDISASM_ARM_ALTERNATIVE_SVE2_OR_SME2
            | CDISASM_ARM_ALTERNATIVE_SVE2P2_OR_SME2P2
            | CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME2P1
            | CDISASM_ARM_ALTERNATIVE_SVE2_OR_SME
            | CDISASM_ARM_ALTERNATIVE_SVE_OR_SME
            | CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME2
            | CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME)) == 0u,
    "SVE2p3-or-SME2p3 alternative bit overlaps an existing bit");

/* Generated feature ordinals 81 (SME2p3) and 102 (SVE2p3) are stored after
 * the 36 legacy capability bits.  Keep their internal IDs centralized so
 * handwritten alternative requirements use the same mapping as the
 * generated decoder. */
#define CDISASM_ARM_FEATURE_SME2P3 UINT16_C(117)
#define CDISASM_ARM_FEATURE_SVE2P3 UINT16_C(138)
#define CDISASM_ARM_FEATURE_SME_F16F16 UINT16_C(119)
#define CDISASM_ARM_FEATURE_SME_F8F16 UINT16_C(121)
#define CDISASM_ARM_FEATURE_FP8DOT2 UINT16_C(67)
#define CDISASM_ARM_FEATURE_FP8DOT4 UINT16_C(68)
#define CDISASM_ARM_FEATURE_SSVE_FP8DOT2 UINT16_C(131)
#define CDISASM_ARM_FEATURE_SSVE_FP8DOT4 UINT16_C(132)
#define CDISASM_ARM_FEATURE_FP8FMA UINT16_C(69)
#define CDISASM_ARM_FEATURE_SSVE_FP8FMA UINT16_C(133)
/* Generated crypto feature ordinals map after the 36 legacy capability bits.
 * Handwritten exact lowering uses the same identities as the generated
 * AARCHMRS selectors. */
#define CDISASM_ARM_FEATURE_SHA1 UINT16_C(107)
#define CDISASM_ARM_FEATURE_SHA256 UINT16_C(108)
#define CDISASM_ARM_FEATURE_SHA3 UINT16_C(109)
#define CDISASM_ARM_FEATURE_SHA512 UINT16_C(110)
#define CDISASM_ARM_FEATURE_SM3 UINT16_C(111)
#define CDISASM_ARM_FEATURE_SM4 UINT16_C(112)
/* Generated feature ordinal 13 is FEAT_CRC32.  Unlike the mandatory Armv8
 * baseline, CRC32 is optional and therefore must not be represented by the
 * coarse V8 capability bit. */
#define CDISASM_ARM_FEATURE_CRC32 UINT16_C(49)
/* Generated feature ordinal 26 is FEAT_FCMA. */
#define CDISASM_ARM_FEATURE_FCMA UINT16_C(62)
/* Generated feature ordinal 27 is FEAT_FHM. */
#define CDISASM_ARM_FEATURE_FHM UINT16_C(63)
/* Generated feature ordinals 17 and 1 are FEAT_DotProd and FEAT_AA32I8MM. */
#define CDISASM_ARM_FEATURE_DOTPROD UINT16_C(53)
#define CDISASM_ARM_FEATURE_AA32I8MM UINT16_C(37)
/* Generated feature ordinal 43 is FEAT_JSCVT. */
#define CDISASM_ARM_FEATURE_JSCVT UINT16_C(79)
/* Generated FEAT_AA32BF16/FEAT_BF16 share the catalog feature identity 34. */
#define CDISASM_ARM_FEATURE_BF16 UINT16_C(34)
/* Generated feature ordinal 61 is FEAT_PAN. */
#define CDISASM_ARM_FEATURE_PAN UINT16_C(97)
/* Architectural hint features retain their generated catalog ordinals:
 * FEAT_CLRBHB=9, FEAT_RAS=65, and FEAT_TRF=117. */
#define CDISASM_ARM_FEATURE_CLRBHB UINT16_C(45)
#define CDISASM_ARM_FEATURE_RAS UINT16_C(101)
#define CDISASM_ARM_FEATURE_TRF UINT16_C(153)
/* Additional fixed A64 architectural-hint feature ordinals from the same
 * generated feature pool (ordinal + 36 legacy capability identities). */
#define CDISASM_ARM_FEATURE_CHK UINT16_C(44)
#define CDISASM_ARM_FEATURE_DGH UINT16_C(52)
#define CDISASM_ARM_FEATURE_GCS UINT16_C(75)
#define CDISASM_ARM_FEATURE_PAUTH_LR UINT16_C(99)
#define CDISASM_ARM_FEATURE_SPE UINT16_C(127)
/* Generated decode and alias feature maps currently occupy internal feature
 * IDs through 168.  FEAT_PMULL is an execution-time guard that is absent
 * from both generated condition pools, so keep it in the first private slot
 * after their union.  The generated users assert their live counts against
 * this boundary and will fail the build if either map grows into it. */
#define CDISASM_ARM_FEATURE_PMULL UINT16_C(169)
#define CDISASM_ARM_FEATURE_AES UINT16_C(38)
/* Generated feature ordinal 34 is FEAT_FPRCVT. */
#define CDISASM_ARM_FEATURE_FPRCVT UINT16_C(70)
/* Generated feature ordinal 10 is FEAT_FAMINMAX. */
#define CDISASM_ARM_FEATURE_FAMINMAX UINT16_C(46)

_Static_assert(
    CDISASM_ARM_FEATURE_SME2P3 < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_SVE2P3 < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_SHA1 < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_SHA256 < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_SHA3 < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_SHA512 < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_SM3 < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_SM4 < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_CRC32 < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_FCMA < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_PAN < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_CLRBHB < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_RAS < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_TRF < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_CHK < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_DGH < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_GCS < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_PAUTH_LR < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_SPE < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_FAMINMAX < CDISASM_ARM_FEATURE_BIT_COUNT
        && CDISASM_ARM_FEATURE_SME2P3 != CDISASM_ARM_FEATURE_SVE2P3,
    "handwritten ARM internal feature IDs are invalid");
_Static_assert(
    CDISASM_ARM_FEATURE_PMULL > UINT16_C(168)
        && CDISASM_ARM_FEATURE_PMULL < CDISASM_ARM_FEATURE_BIT_COUNT,
    "PMULL internal feature ID overlaps generated features");

typedef struct cdisasm_arm_requirements {
    cdisasm_arm_capabilities features;
    cdisasm_arm_alternative_requirements alternatives;
} cdisasm_arm_requirements;

#define CDISASM_ARM_CAPABILITIES_NONE_INITIALIZER \
    {{ \
        UINT64_C(0), UINT64_C(0), UINT64_C(0), UINT64_C(0), \
        UINT64_C(0), UINT64_C(0), UINT64_C(0), UINT64_C(0) \
    }}
#define CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(mask_) \
    {{ \
        (uint64_t)(mask_), UINT64_C(0), UINT64_C(0), UINT64_C(0), \
        UINT64_C(0), UINT64_C(0), UINT64_C(0), UINT64_C(0) \
    }}
#if USE_EXTRA_OPCODES
#define CDISASM_ARM_CAPABILITIES_ALL_INITIALIZER \
    {{ \
        UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, \
        UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX \
    }}
#else
#define CDISASM_ARM_CAPABILITIES_ALL_INITIALIZER \
    CDISASM_ARM_CAPABILITIES_LEGACY_INITIALIZER(CDISASM_ARM_CAP_ALL)
#endif
#define CDISASM_ARM_REQUIREMENTS_NONE_INITIALIZER \
    { CDISASM_ARM_CAPABILITIES_NONE_INITIALIZER, UINT32_C(0) }

#define CDISASM_ARM_CAP_V4 (UINT32_C(1) << 0)
#define CDISASM_ARM_CAP_V5 (UINT32_C(1) << 1)
#define CDISASM_ARM_CAP_V6 (UINT32_C(1) << 2)
#define CDISASM_ARM_CAP_V7 (UINT32_C(1) << 3)
#define CDISASM_ARM_CAP_V8 (UINT32_C(1) << 4)
#define CDISASM_ARM_CAP_NEON (UINT32_C(1) << 5)
#define CDISASM_ARM_CAP_APPLE_MUL53 (UINT32_C(1) << 6)
#define CDISASM_ARM_CAP_APPLE_AMX (UINT32_C(1) << 7)
#define CDISASM_ARM_CAP_APPLE_SYS (UINT32_C(1) << 8)
#define CDISASM_ARM_CAP_APPLE_A7_SYSREG (UINT32_C(1) << 9)
#define CDISASM_ARM_CAP_LSE (UINT32_C(1) << 10)
#define CDISASM_ARM_CAP_LOR (UINT32_C(1) << 11)
#define CDISASM_ARM_CAP_RCPC (UINT32_C(1) << 12)
#define CDISASM_ARM_CAP_FP16 (UINT32_C(1) << 13)
#define CDISASM_ARM_CAP_SVE (UINT32_C(1) << 14)
#define CDISASM_ARM_CAP_SVE2 (UINT32_C(1) << 15)
#define CDISASM_ARM_CAP_SME (UINT32_C(1) << 16)
#define CDISASM_ARM_CAP_SME2 (UINT32_C(1) << 17)
#define CDISASM_ARM_CAP_LSE2 (UINT32_C(1) << 18)
#define CDISASM_ARM_CAP_LSE128 (UINT32_C(1) << 19)
#define CDISASM_ARM_CAP_RCPC3 (UINT32_C(1) << 20)
#define CDISASM_ARM_CAP_BTI (UINT32_C(1) << 21)
#define CDISASM_ARM_CAP_PAUTH (UINT32_C(1) << 22)
#define CDISASM_ARM_CAP_MTE (UINT32_C(1) << 23)
#define CDISASM_ARM_CAP_MOPS (UINT32_C(1) << 24)
#define CDISASM_ARM_CAP_LS64 (UINT32_C(1) << 25)
#define CDISASM_ARM_CAP_CSSC (UINT32_C(1) << 26)
#define CDISASM_ARM_CAP_VFP (UINT32_C(1) << 27)
#define CDISASM_ARM_CAP_CPA (UINT64_C(1) << 28)
#define CDISASM_ARM_CAP_SVE2P1 (UINT64_C(1) << 29)
#define CDISASM_ARM_CAP_SME2P1 (UINT64_C(1) << 30)
#define CDISASM_ARM_CAP_SVE2P2 (UINT64_C(1) << 31)
#define CDISASM_ARM_CAP_SME2P2 (UINT64_C(1) << 32)
#define CDISASM_ARM_CAP_F64MM (UINT64_C(1) << 33)
#define CDISASM_ARM_CAP_BF16 (UINT64_C(1) << 34)
#define CDISASM_ARM_CAP_FP8 (UINT64_C(1) << 35)
#define CDISASM_ARM_CAP_MP (UINT64_C(1) << 36)
/* Internal alternative-requirement markers, never CPU capabilities. */
/* SVE widening byte dot products are allocated by SVE2p3 or SME2p3. */
#define CDISASM_ARM_REQUIRE_SVE2P3_OR_SME2P3 (UINT64_C(1) << 56)
/* PSEL is allocated by either baseline SME or SVE2.1. */
#define CDISASM_ARM_REQUIRE_SVE2P1_OR_SME (UINT64_C(1) << 57)
/* SVE2.1 multi-extract instructions are also allocated by baseline SME2. */
#define CDISASM_ARM_REQUIRE_SVE2P1_OR_SME2 (UINT64_C(1) << 58)
#define CDISASM_ARM_REQUIRE_SVE2_OR_SME2 (UINT64_C(1) << 59)
#define CDISASM_ARM_REQUIRE_SVE2P2_OR_SME2P2 (UINT64_C(1) << 60)
#define CDISASM_ARM_REQUIRE_SVE2P1_OR_SME2P1 (UINT64_C(1) << 61)
#define CDISASM_ARM_REQUIRE_SVE2_OR_SME (UINT64_C(1) << 62)
/* Internal all-of requirement marker with an SVE-or-SME alternative. */
#define CDISASM_ARM_REQUIRE_SVE_OR_SME (UINT64_C(1) << 63)
#define CDISASM_ARM_CAP_STANDARD_ALL \
    (CDISASM_ARM_CAP_V4 | CDISASM_ARM_CAP_V5 | CDISASM_ARM_CAP_V6 \
        | CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_V8 \
        | CDISASM_ARM_CAP_NEON)
#define CDISASM_ARM_CAP_BASE_ALL \
    (CDISASM_ARM_CAP_STANDARD_ALL | CDISASM_ARM_CAP_APPLE_MUL53 \
        | CDISASM_ARM_CAP_APPLE_AMX | CDISASM_ARM_CAP_APPLE_SYS \
        | CDISASM_ARM_CAP_APPLE_A7_SYSREG | CDISASM_ARM_CAP_LSE \
        | CDISASM_ARM_CAP_LOR | CDISASM_ARM_CAP_RCPC)
#if USE_EXTRA_OPCODES
#define CDISASM_ARM_CAP_ALL \
    (CDISASM_ARM_CAP_BASE_ALL | CDISASM_ARM_CAP_FP16 \
        | CDISASM_ARM_CAP_SVE | CDISASM_ARM_CAP_SVE2 \
        | CDISASM_ARM_CAP_SME | CDISASM_ARM_CAP_SME2 \
        | CDISASM_ARM_CAP_LSE2 | CDISASM_ARM_CAP_LSE128 \
        | CDISASM_ARM_CAP_RCPC3 | CDISASM_ARM_CAP_BTI \
        | CDISASM_ARM_CAP_PAUTH | CDISASM_ARM_CAP_MTE \
        | CDISASM_ARM_CAP_MOPS | CDISASM_ARM_CAP_LS64 \
        | CDISASM_ARM_CAP_CSSC | CDISASM_ARM_CAP_VFP \
        | CDISASM_ARM_CAP_CPA | CDISASM_ARM_CAP_SVE2P1 \
        | CDISASM_ARM_CAP_SME2P1 | CDISASM_ARM_CAP_SVE2P2 \
        | CDISASM_ARM_CAP_SME2P2 | CDISASM_ARM_CAP_F64MM \
        | CDISASM_ARM_CAP_BF16 | CDISASM_ARM_CAP_FP8 \
        | CDISASM_ARM_CAP_MP)
#else
#define CDISASM_ARM_CAP_ALL CDISASM_ARM_CAP_BASE_ALL
#endif

_Static_assert(
    (CDISASM_ARM_CAP_ALL
        & (CDISASM_ARM_REQUIRE_SVE_OR_SME
            | CDISASM_ARM_REQUIRE_SVE2_OR_SME
            | CDISASM_ARM_REQUIRE_SVE2P1_OR_SME
            | CDISASM_ARM_REQUIRE_SVE2_OR_SME2
            | CDISASM_ARM_REQUIRE_SVE2P1_OR_SME2
            | CDISASM_ARM_REQUIRE_SVE2P1_OR_SME2P1
            | CDISASM_ARM_REQUIRE_SVE2P2_OR_SME2P2
            | CDISASM_ARM_REQUIRE_SVE2P3_OR_SME2P3)) == 0u,
    "alternative ARM requirement markers overlap CPU capabilities");
_Static_assert(
    (CDISASM_ARM_REQUIRE_SVE2P1_OR_SME
        & (CDISASM_ARM_REQUIRE_SVE2P1_OR_SME2
            | CDISASM_ARM_REQUIRE_SVE2_OR_SME2
            | CDISASM_ARM_REQUIRE_SVE2P2_OR_SME2P2
            | CDISASM_ARM_REQUIRE_SVE2P1_OR_SME2P1
            | CDISASM_ARM_REQUIRE_SVE2_OR_SME
            | CDISASM_ARM_REQUIRE_SVE_OR_SME
            | CDISASM_ARM_REQUIRE_SVE2P3_OR_SME2P3)) == 0u,
    "PSEL ARM requirement marker overlaps an existing marker");

#define CDISASM_ARM_LEGACY_FEATURE_MASK \
    ((UINT64_C(1) << 37) - UINT64_C(1))

_Static_assert(
    sizeof(cdisasm_arm_capabilities) == 64u,
    "ARM internal feature bitmap must remain exactly 512 bits");

static inline void cdisasm_arm_capabilities_clear(
    cdisasm_arm_capabilities *capabilities)
{
    unsigned index;

    for (index = 0; index < CDISASM_ARM_FEATURE_WORD_COUNT; ++index) {
        capabilities->bitmap[index] = UINT64_C(0);
    }
}

static inline int cdisasm_arm_capabilities_add_feature(
    cdisasm_arm_capabilities *capabilities,
    cdisasm_arm_feature_id feature_id)
{
    if (capabilities == NULL
        || feature_id >= CDISASM_ARM_FEATURE_BIT_COUNT) {
        return 0;
    }
    capabilities->bitmap[feature_id / 64u]
        |= UINT64_C(1) << (feature_id % 64u);
    return 1;
}

static inline int cdisasm_arm_capabilities_has_feature(
    const cdisasm_arm_capabilities *capabilities,
    cdisasm_arm_feature_id feature_id)
{
    return capabilities != NULL
        && feature_id < CDISASM_ARM_FEATURE_BIT_COUNT
        && (capabilities->bitmap[feature_id / 64u]
            & (UINT64_C(1) << (feature_id % 64u))) != 0u;
}

static inline int cdisasm_arm_capabilities_have_all(
    const cdisasm_arm_capabilities *capabilities,
    const cdisasm_arm_capabilities *required)
{
    unsigned index;

    for (index = 0; index < CDISASM_ARM_FEATURE_WORD_COUNT; ++index) {
        if ((capabilities->bitmap[index] & required->bitmap[index])
            != required->bitmap[index]) {
            return 0;
        }
    }
    return 1;
}

static inline int cdisasm_arm_capabilities_have_any_legacy(
    const cdisasm_arm_capabilities *capabilities,
    uint64_t legacy_mask)
{
    return (capabilities->bitmap[0]
        & (legacy_mask & CDISASM_ARM_LEGACY_FEATURE_MASK)) != 0u;
}

static inline void cdisasm_arm_requirements_clear(
    cdisasm_arm_requirements *requirements)
{
    cdisasm_arm_capabilities_clear(&requirements->features);
    requirements->alternatives = UINT32_C(0);
}

static inline int cdisasm_arm_requirements_add_feature(
    cdisasm_arm_requirements *requirements,
    cdisasm_arm_feature_id feature_id)
{
    return requirements != NULL
        && cdisasm_arm_capabilities_add_feature(
            &requirements->features, feature_id);
}

static inline void cdisasm_arm_requirements_add_legacy(
    cdisasm_arm_requirements *requirements,
    uint64_t legacy_mask)
{
    requirements->features.bitmap[0] |=
        legacy_mask & CDISASM_ARM_LEGACY_FEATURE_MASK;
    if ((legacy_mask & CDISASM_ARM_REQUIRE_SVE2_OR_SME2) != 0u) {
        requirements->alternatives |=
            CDISASM_ARM_ALTERNATIVE_SVE2_OR_SME2;
    }
    if ((legacy_mask & CDISASM_ARM_REQUIRE_SVE2P2_OR_SME2P2) != 0u) {
        requirements->alternatives |=
            CDISASM_ARM_ALTERNATIVE_SVE2P2_OR_SME2P2;
    }
    if ((legacy_mask & CDISASM_ARM_REQUIRE_SVE2P1_OR_SME2P1) != 0u) {
        requirements->alternatives |=
            CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME2P1;
    }
    if ((legacy_mask & CDISASM_ARM_REQUIRE_SVE2P1_OR_SME2) != 0u) {
        requirements->alternatives |=
            CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME2;
    }
    if ((legacy_mask & CDISASM_ARM_REQUIRE_SVE2P1_OR_SME) != 0u) {
        requirements->alternatives |=
            CDISASM_ARM_ALTERNATIVE_SVE2P1_OR_SME;
    }
    if ((legacy_mask & CDISASM_ARM_REQUIRE_SVE2_OR_SME) != 0u) {
        requirements->alternatives |=
            CDISASM_ARM_ALTERNATIVE_SVE2_OR_SME;
    }
    if ((legacy_mask & CDISASM_ARM_REQUIRE_SVE_OR_SME) != 0u) {
        requirements->alternatives |=
            CDISASM_ARM_ALTERNATIVE_SVE_OR_SME;
    }
    if ((legacy_mask & CDISASM_ARM_REQUIRE_SVE2P3_OR_SME2P3) != 0u) {
        requirements->alternatives |=
            CDISASM_ARM_ALTERNATIVE_SVE2P3_OR_SME2P3;
    }
}

static inline void cdisasm_arm_requirements_set_legacy(
    cdisasm_arm_requirements *requirements,
    uint64_t legacy_mask)
{
    cdisasm_arm_requirements_clear(requirements);
    cdisasm_arm_requirements_add_legacy(requirements, legacy_mask);
}

cdisasm_status cdisasm_arm_decode_a32_neon(
    uint32_t canonical_word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities);

cdisasm_status cdisasm_arm_decode_a32_coprocessor_transfer(
    uint32_t canonical_word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities);

cdisasm_status cdisasm_arm_decode_core(
    uint32_t raw_instruction,
    uint64_t address,
    cdisasm_arm_mode mode,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities);

#endif
