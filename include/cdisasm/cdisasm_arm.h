#ifndef CDISASM_CDISASM_ARM_H
#define CDISASM_CDISASM_ARM_H

#include "cdisasm_common.h"

#if !USE_ARCH_ARM
#  error "cdisasm ARM support is disabled in this build"
#endif

#include "cdisasm_arm_ids.h"

#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(CDISASM_STATIC) || defined(CDISASM_ARM_STATIC)
#    define CDISASM_ARM_API
#  elif defined(CDISASM_BUILDING_LIBRARY) \
        || defined(CDISASM_ARM_BUILDING_LIBRARY)
#    define CDISASM_ARM_API __declspec(dllexport)
#  else
#    define CDISASM_ARM_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  if defined(CDISASM_STATIC) || defined(CDISASM_ARM_STATIC)
#    define CDISASM_ARM_API __attribute__((visibility("hidden")))
#  else
#    define CDISASM_ARM_API __attribute__((visibility("default")))
#  endif
#else
#  define CDISASM_ARM_API
#endif

#define CDISASM_ARM_MAX_INSTRUCTION_SIZE 4
#define CDISASM_ARM_MAX_OPERANDS 4
#define CDISASM_ARM_OPERAND_SIZE 32
#define CDISASM_ARM_INSTRUCTION_SIZE 168

/** ARM instruction-set state, not instruction width. */
typedef uint32_t cdisasm_arm_mode;
#define CDISASM_ARM_MODE_A32 UINT32_C(1)
#define CDISASM_ARM_MODE_T32 UINT32_C(2)
#define CDISASM_ARM_MODE_A64 UINT32_C(3)
#define CDISASM_ARM_MODE_32 CDISASM_ARM_MODE_A32
#define CDISASM_ARM_MODE_64 CDISASM_ARM_MODE_A64

typedef uint32_t cdisasm_arm_mode_mask;
#define CDISASM_ARM_MODE_MASK_NONE UINT32_C(0)
#define CDISASM_ARM_MODE_MASK_A32 (UINT32_C(1) << 0)
#define CDISASM_ARM_MODE_MASK_T32 (UINT32_C(1) << 1)
#define CDISASM_ARM_MODE_MASK_A64 (UINT32_C(1) << 2)

/**
 * Stable ARM ISA-family IDs.  These are capability families, not instruction
 * states: A32, T32, and A64 remain represented by cdisasm_arm_mode.  The
 * family mask is intentionally separate from the decode-option bitmap so
 * callers can select and display architectural families without losing the
 * exact byte-order/IT-block options.
 */
typedef uint16_t cdisasm_arm_family_id;
typedef uint64_t cdisasm_arm_family_mask;
#define CDISASM_ARM_FAMILY_NONE UINT16_C(0)
#define CDISASM_ARM_FAMILY_V4 UINT16_C(1)
#define CDISASM_ARM_FAMILY_V5 UINT16_C(2)
#define CDISASM_ARM_FAMILY_V6 UINT16_C(3)
#define CDISASM_ARM_FAMILY_V7 UINT16_C(4)
#define CDISASM_ARM_FAMILY_V8 UINT16_C(5)
#define CDISASM_ARM_FAMILY_NEON UINT16_C(6)
#define CDISASM_ARM_FAMILY_VFP UINT16_C(7)
#define CDISASM_ARM_FAMILY_FP16 UINT16_C(8)
#define CDISASM_ARM_FAMILY_SVE UINT16_C(9)
#define CDISASM_ARM_FAMILY_SVE2 UINT16_C(10)
#define CDISASM_ARM_FAMILY_SME UINT16_C(11)
#define CDISASM_ARM_FAMILY_SME2 UINT16_C(12)
#define CDISASM_ARM_FAMILY_LSE UINT16_C(13)
#define CDISASM_ARM_FAMILY_LSE2 UINT16_C(14)
#define CDISASM_ARM_FAMILY_LSE128 UINT16_C(15)
#define CDISASM_ARM_FAMILY_RCPC UINT16_C(16)
#define CDISASM_ARM_FAMILY_RCPC3 UINT16_C(17)
#define CDISASM_ARM_FAMILY_BTI UINT16_C(18)
#define CDISASM_ARM_FAMILY_PAUTH UINT16_C(19)
#define CDISASM_ARM_FAMILY_MTE UINT16_C(20)
#define CDISASM_ARM_FAMILY_MOPS UINT16_C(21)
#define CDISASM_ARM_FAMILY_LS64 UINT16_C(22)
#define CDISASM_ARM_FAMILY_CSSC UINT16_C(23)
#define CDISASM_ARM_FAMILY_BF16 UINT16_C(24)
#define CDISASM_ARM_FAMILY_FP8 UINT16_C(25)
#define CDISASM_ARM_FAMILY_F64MM UINT16_C(26)
#define CDISASM_ARM_FAMILY_APPLE_MUL53 UINT16_C(27)
#define CDISASM_ARM_FAMILY_APPLE_AMX UINT16_C(28)
#define CDISASM_ARM_FAMILY_APPLE_SYS UINT16_C(29)
#define CDISASM_ARM_FAMILY_APPLE_A7_SYSREG UINT16_C(30)
#define CDISASM_ARM_FAMILY_CPA UINT16_C(31)
#define CDISASM_ARM_FAMILY_MP UINT16_C(32)
#define CDISASM_ARM_FAMILY_CRC32 UINT16_C(33)
#define CDISASM_ARM_FAMILY_AES UINT16_C(34)
#define CDISASM_ARM_FAMILY_PMULL UINT16_C(35)
#define CDISASM_ARM_FAMILY_SHA UINT16_C(36)
#define CDISASM_ARM_FAMILY_SM3 UINT16_C(37)
#define CDISASM_ARM_FAMILY_SM4 UINT16_C(38)
#define CDISASM_ARM_FAMILY_DOTPROD UINT16_C(39)
#define CDISASM_ARM_FAMILY_FCMA UINT16_C(40)
#define CDISASM_ARM_FAMILY_FHM UINT16_C(41)
#define CDISASM_ARM_FAMILY_AA32I8MM UINT16_C(42)
#define CDISASM_ARM_FAMILY_PAN UINT16_C(43)
#define CDISASM_ARM_FAMILY_RAS UINT16_C(44)
#define CDISASM_ARM_FAMILY_TRF UINT16_C(45)
#define CDISASM_ARM_FAMILY_CLRBHB UINT16_C(46)
#define CDISASM_ARM_FAMILY_GCS UINT16_C(47)
#define CDISASM_ARM_FAMILY_PAUTH_LR UINT16_C(48)
#define CDISASM_ARM_FAMILY_SVE2P1 UINT16_C(49)
#define CDISASM_ARM_FAMILY_SME2P1 UINT16_C(50)
#define CDISASM_ARM_FAMILY_SVE2P2 UINT16_C(51)
#define CDISASM_ARM_FAMILY_SME2P2 UINT16_C(52)
#define CDISASM_ARM_FAMILY_SVE2P3 UINT16_C(53)
#define CDISASM_ARM_FAMILY_SME2P3 UINT16_C(54)
#define CDISASM_ARM_FAMILY_FAMINMAX UINT16_C(55)
#define CDISASM_ARM_FAMILY_FPRCVT UINT16_C(56)
#define CDISASM_ARM_FAMILY_JSCVT UINT16_C(57)
#define CDISASM_ARM_FAMILY_CHK UINT16_C(58)
#define CDISASM_ARM_FAMILY_DGH UINT16_C(59)
#define CDISASM_ARM_FAMILY_SPE UINT16_C(60)
#define CDISASM_ARM_FAMILY_FIRST CDISASM_ARM_FAMILY_V4
#define CDISASM_ARM_FAMILY_LAST CDISASM_ARM_FAMILY_SPE

#define CDISASM_ARM_FAMILY_MASK_FOR_ID(family_id_) \
    (UINT64_C(1) << ((family_id_) - UINT16_C(1)))
#define CDISASM_ARM_FAMILY_MASK_NONE UINT64_C(0)
#define CDISASM_ARM_FAMILY_MASK_V4 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_V4)
#define CDISASM_ARM_FAMILY_MASK_V5 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_V5)
#define CDISASM_ARM_FAMILY_MASK_V6 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_V6)
#define CDISASM_ARM_FAMILY_MASK_V7 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_V7)
#define CDISASM_ARM_FAMILY_MASK_V8 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_V8)
#define CDISASM_ARM_FAMILY_MASK_NEON \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_NEON)
#define CDISASM_ARM_FAMILY_MASK_VFP \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_VFP)
#define CDISASM_ARM_FAMILY_MASK_FP16 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_FP16)
#define CDISASM_ARM_FAMILY_MASK_SVE \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SVE)
#define CDISASM_ARM_FAMILY_MASK_SVE2 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SVE2)
#define CDISASM_ARM_FAMILY_MASK_SME \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SME)
#define CDISASM_ARM_FAMILY_MASK_SME2 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SME2)
#define CDISASM_ARM_FAMILY_MASK_LSE \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_LSE)
#define CDISASM_ARM_FAMILY_MASK_LSE2 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_LSE2)
#define CDISASM_ARM_FAMILY_MASK_LSE128 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_LSE128)
#define CDISASM_ARM_FAMILY_MASK_RCPC \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_RCPC)
#define CDISASM_ARM_FAMILY_MASK_RCPC3 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_RCPC3)
#define CDISASM_ARM_FAMILY_MASK_BTI \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_BTI)
#define CDISASM_ARM_FAMILY_MASK_PAUTH \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_PAUTH)
#define CDISASM_ARM_FAMILY_MASK_MTE \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_MTE)
#define CDISASM_ARM_FAMILY_MASK_MOPS \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_MOPS)
#define CDISASM_ARM_FAMILY_MASK_LS64 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_LS64)
#define CDISASM_ARM_FAMILY_MASK_CSSC \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_CSSC)
#define CDISASM_ARM_FAMILY_MASK_BF16 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_BF16)
#define CDISASM_ARM_FAMILY_MASK_FP8 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_FP8)
#define CDISASM_ARM_FAMILY_MASK_F64MM \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_F64MM)
#define CDISASM_ARM_FAMILY_MASK_APPLE_MUL53 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_APPLE_MUL53)
#define CDISASM_ARM_FAMILY_MASK_APPLE_AMX \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_APPLE_AMX)
#define CDISASM_ARM_FAMILY_MASK_APPLE_SYS \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_APPLE_SYS)
#define CDISASM_ARM_FAMILY_MASK_APPLE_A7_SYSREG \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_APPLE_A7_SYSREG)
#define CDISASM_ARM_FAMILY_MASK_CPA \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_CPA)
#define CDISASM_ARM_FAMILY_MASK_MP \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_MP)
#define CDISASM_ARM_FAMILY_MASK_CRC32 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_CRC32)
#define CDISASM_ARM_FAMILY_MASK_AES \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_AES)
#define CDISASM_ARM_FAMILY_MASK_PMULL \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_PMULL)
#define CDISASM_ARM_FAMILY_MASK_SHA \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SHA)
#define CDISASM_ARM_FAMILY_MASK_SM3 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SM3)
#define CDISASM_ARM_FAMILY_MASK_SM4 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SM4)
#define CDISASM_ARM_FAMILY_MASK_DOTPROD \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_DOTPROD)
#define CDISASM_ARM_FAMILY_MASK_FCMA \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_FCMA)
#define CDISASM_ARM_FAMILY_MASK_FHM \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_FHM)
#define CDISASM_ARM_FAMILY_MASK_AA32I8MM \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_AA32I8MM)
#define CDISASM_ARM_FAMILY_MASK_PAN \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_PAN)
#define CDISASM_ARM_FAMILY_MASK_RAS \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_RAS)
#define CDISASM_ARM_FAMILY_MASK_TRF \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_TRF)
#define CDISASM_ARM_FAMILY_MASK_CLRBHB \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_CLRBHB)
#define CDISASM_ARM_FAMILY_MASK_GCS \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_GCS)
#define CDISASM_ARM_FAMILY_MASK_PAUTH_LR \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_PAUTH_LR)
#define CDISASM_ARM_FAMILY_MASK_SVE2P1 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SVE2P1)
#define CDISASM_ARM_FAMILY_MASK_SME2P1 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SME2P1)
#define CDISASM_ARM_FAMILY_MASK_SVE2P2 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SVE2P2)
#define CDISASM_ARM_FAMILY_MASK_SME2P2 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SME2P2)
#define CDISASM_ARM_FAMILY_MASK_SVE2P3 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SVE2P3)
#define CDISASM_ARM_FAMILY_MASK_SME2P3 \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SME2P3)
#define CDISASM_ARM_FAMILY_MASK_FAMINMAX \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_FAMINMAX)
#define CDISASM_ARM_FAMILY_MASK_FPRCVT \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_FPRCVT)
#define CDISASM_ARM_FAMILY_MASK_JSCVT \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_JSCVT)
#define CDISASM_ARM_FAMILY_MASK_CHK \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_CHK)
#define CDISASM_ARM_FAMILY_MASK_DGH \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_DGH)
#define CDISASM_ARM_FAMILY_MASK_SPE \
    CDISASM_ARM_FAMILY_MASK_FOR_ID(CDISASM_ARM_FAMILY_SPE)
#define CDISASM_ARM_FAMILY_MASK_ALL \
    ((UINT64_C(1) << CDISASM_ARM_FAMILY_LAST) - UINT64_C(1))
#define CDISASM_ARM_FAMILY_MASK_APPLE \
    (CDISASM_ARM_FAMILY_MASK_APPLE_MUL53 \
        | CDISASM_ARM_FAMILY_MASK_APPLE_AMX \
        | CDISASM_ARM_FAMILY_MASK_APPLE_SYS \
        | CDISASM_ARM_FAMILY_MASK_APPLE_A7_SYSREG)
#define CDISASM_ARM_FAMILY_MASK_DEFAULT \
    (CDISASM_ARM_FAMILY_MASK_ALL & ~CDISASM_ARM_FAMILY_MASK_APPLE)

typedef uint8_t cdisasm_arm_family_vendor;
#define CDISASM_ARM_FAMILY_VENDOR_ANY UINT8_C(0)
#define CDISASM_ARM_FAMILY_VENDOR_ARM UINT8_C(1)
#define CDISASM_ARM_FAMILY_VENDOR_APPLE UINT8_C(2)
#define CDISASM_ARM_FAMILY_FEATURE_NONE UINT16_MAX

/** Metadata for one direct ARM architectural family. */
typedef struct cdisasm_arm_family_descriptor {
    cdisasm_arm_family_id family_id;
    uint64_t required_capability;
    uint16_t required_feature;
    cdisasm_arm_mode_mask allowed_modes;
    cdisasm_arm_family_vendor vendor;
} cdisasm_arm_family_descriptor;

/**
 * ARM CPU IDs use CDISASM_CPU_GROUP_ARM in the upper 16 bits and a stable,
 * architecture-local ordinal in the lower 16 bits. They are profiles, not an
 * ordered feature hierarchy.
 */
typedef cdisasm_cpu_id cdisasm_arm_cpu_id;
#define CDISASM_ARM_CPU_ANY \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0000))
#define CDISASM_ARM_CPU_GENERIC CDISASM_ARM_CPU_ANY
#define CDISASM_ARM_CPU_ARM7TDMI \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0001))
#define CDISASM_ARM_CPU_CORTEX_A7 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0002))
#define CDISASM_ARM_CPU_CORTEX_A9 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0003))
#define CDISASM_ARM_CPU_CORTEX_A32 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0004))
#define CDISASM_ARM_CPU_CORTEX_A34 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0005))
#define CDISASM_ARM_CPU_CORTEX_A35 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0006))
#define CDISASM_ARM_CPU_CORTEX_A53 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0007))
#define CDISASM_ARM_CPU_CORTEX_A9_NEON \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0008))
#define CDISASM_ARM_CPU_CORTEX_A9_WITH_NEON \
    CDISASM_ARM_CPU_CORTEX_A9_NEON
#define CDISASM_ARM_CPU_APPLE_A4 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0009))
#define CDISASM_ARM_CPU_APPLE_A5 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x000a))
#define CDISASM_ARM_CPU_APPLE_A6 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x000b))
#define CDISASM_ARM_CPU_APPLE_A7 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x000c))
#define CDISASM_ARM_CPU_APPLE_A8 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x000d))
#define CDISASM_ARM_CPU_APPLE_A9 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x000e))
#define CDISASM_ARM_CPU_APPLE_A10 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x000f))
#define CDISASM_ARM_CPU_APPLE_A11 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0010))
#define CDISASM_ARM_CPU_APPLE_A12 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0011))
#define CDISASM_ARM_CPU_APPLE_A13 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0012))
#define CDISASM_ARM_CPU_APPLE_A14 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0013))
#define CDISASM_ARM_CPU_APPLE_A15 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0014))
#define CDISASM_ARM_CPU_APPLE_A16 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0015))
#define CDISASM_ARM_CPU_APPLE_A17 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0016))
#define CDISASM_ARM_CPU_APPLE_A18 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0017))
#define CDISASM_ARM_CPU_APPLE_A19 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0018))
#define CDISASM_ARM_CPU_APPLE_M1 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0019))
#define CDISASM_ARM_CPU_APPLE_M2 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x001a))
#define CDISASM_ARM_CPU_APPLE_M3 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x001b))
#define CDISASM_ARM_CPU_APPLE_M4 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x001c))
#define CDISASM_ARM_CPU_APPLE_M5 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x001d))
#define CDISASM_ARM_CPU_CORTEX_A7_NEON \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x001e))
#define CDISASM_ARM_CPU_CORTEX_A7_WITH_NEON \
    CDISASM_ARM_CPU_CORTEX_A7_NEON
#define CDISASM_ARM_CPU_APPLE_S4 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x001f))
#define CDISASM_ARM_CPU_APPLE_S5 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0020))
#define CDISASM_ARM_CPU_APPLE_S6 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0021))
#define CDISASM_ARM_CPU_APPLE_S7 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0022))
#define CDISASM_ARM_CPU_APPLE_S8 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0023))
#define CDISASM_ARM_CPU_APPLE_S9 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0024))
#define CDISASM_ARM_CPU_APPLE_S10 \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0025))
#define CDISASM_ARM_CPU_FUJITSU_A64FX \
    (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0026))
#define CDISASM_ARM_CPU_A64FX CDISASM_ARM_CPU_FUJITSU_A64FX
/* Product suffixes do not change the instruction-state profile. */
#define CDISASM_ARM_CPU_APPLE_A17_PRO CDISASM_ARM_CPU_APPLE_A17
#define CDISASM_ARM_CPU_APPLE_A18_PRO CDISASM_ARM_CPU_APPLE_A18
#define CDISASM_ARM_CPU_APPLE_A19_PRO CDISASM_ARM_CPU_APPLE_A19
#define CDISASM_ARM_CPU_APPLE_A8X CDISASM_ARM_CPU_APPLE_A8
#define CDISASM_ARM_CPU_APPLE_A9X CDISASM_ARM_CPU_APPLE_A9
#define CDISASM_ARM_CPU_APPLE_A10X CDISASM_ARM_CPU_APPLE_A10
#define CDISASM_ARM_CPU_APPLE_A12X CDISASM_ARM_CPU_APPLE_A12
#define CDISASM_ARM_CPU_APPLE_A12Z CDISASM_ARM_CPU_APPLE_A12
#define CDISASM_ARM_CPU_APPLE_M1_PRO CDISASM_ARM_CPU_APPLE_M1
#define CDISASM_ARM_CPU_APPLE_M1_MAX CDISASM_ARM_CPU_APPLE_M1
#define CDISASM_ARM_CPU_APPLE_M1_ULTRA CDISASM_ARM_CPU_APPLE_M1
#define CDISASM_ARM_CPU_APPLE_M2_PRO CDISASM_ARM_CPU_APPLE_M2
#define CDISASM_ARM_CPU_APPLE_M2_MAX CDISASM_ARM_CPU_APPLE_M2
#define CDISASM_ARM_CPU_APPLE_M2_ULTRA CDISASM_ARM_CPU_APPLE_M2
#define CDISASM_ARM_CPU_APPLE_M3_PRO CDISASM_ARM_CPU_APPLE_M3
#define CDISASM_ARM_CPU_APPLE_M3_MAX CDISASM_ARM_CPU_APPLE_M3
#define CDISASM_ARM_CPU_APPLE_M3_ULTRA CDISASM_ARM_CPU_APPLE_M3
#define CDISASM_ARM_CPU_APPLE_M4_PRO CDISASM_ARM_CPU_APPLE_M4
#define CDISASM_ARM_CPU_APPLE_M4_MAX CDISASM_ARM_CPU_APPLE_M4
#define CDISASM_ARM_CPU_APPLE_M4_ULTRA CDISASM_ARM_CPU_APPLE_M4
#define CDISASM_ARM_CPU_APPLE_M5_PRO CDISASM_ARM_CPU_APPLE_M5
#define CDISASM_ARM_CPU_APPLE_M5_MAX CDISASM_ARM_CPU_APPLE_M5
#define CDISASM_ARM_CPU_APPLE_M5_ULTRA CDISASM_ARM_CPU_APPLE_M5
#define CDISASM_ARM_CPU_APPLE_A_FIRST CDISASM_ARM_CPU_APPLE_A4
#define CDISASM_ARM_CPU_APPLE_A_LAST CDISASM_ARM_CPU_APPLE_A19
#define CDISASM_ARM_CPU_APPLE_M_FIRST CDISASM_ARM_CPU_APPLE_M1
#define CDISASM_ARM_CPU_APPLE_M_LAST CDISASM_ARM_CPU_APPLE_M5
#define CDISASM_ARM_CPU_APPLE_S_FIRST CDISASM_ARM_CPU_APPLE_S4
#define CDISASM_ARM_CPU_APPLE_S_LAST CDISASM_ARM_CPU_APPLE_S10
#define CDISASM_ARM_CPU_APPLE_FIRST CDISASM_ARM_CPU_APPLE_A_FIRST
#define CDISASM_ARM_CPU_APPLE_LAST CDISASM_ARM_CPU_APPLE_S_LAST
/* Stable append-only IDs leave the A/M and S Apple ranges non-contiguous. */
static inline int cdisasm_arm_cpu_is_apple_value(
    cdisasm_arm_cpu_id cpu_id)
{
    return (cpu_id >= CDISASM_ARM_CPU_APPLE_A_FIRST
            && cpu_id <= CDISASM_ARM_CPU_APPLE_M_LAST)
        || (cpu_id >= CDISASM_ARM_CPU_APPLE_S_FIRST
            && cpu_id <= CDISASM_ARM_CPU_APPLE_S_LAST);
}
#define CDISASM_ARM_CPU_IS_APPLE(cpu_id) \
    cdisasm_arm_cpu_is_apple_value((cdisasm_arm_cpu_id)(cpu_id))
#define CDISASM_ARM_CPU_FIRST CDISASM_ARM_CPU_ARM7TDMI
#define CDISASM_ARM_CPU_LAST CDISASM_ARM_CPU_FUJITSU_A64FX

/** ARM decode flags use the common fixed-size bitmap layout. */
typedef cdisasm_decode_flags cdisasm_arm_decode_flags;
/* Legacy scalar spelling retained as the type of one bitmap word. */
typedef cdisasm_decode_flag_bitmap cdisasm_arm_decode_option;
#define CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP 0u
typedef uint32_t cdisasm_arm_decode_bit_id;
#define CDISASM_ARM_DECODE_BIT_BIG_ENDIAN UINT32_C(0)
#define CDISASM_ARM_DECODE_BIT_BE CDISASM_ARM_DECODE_BIT_BIG_ENDIAN
#define CDISASM_ARM_DECODE_BIT_IN_IT_BLOCK UINT32_C(1)
#define CDISASM_ARM_DECODE_BIT_COUNT UINT32_C(2)
#define CDISASM_ARM_DECODE_OPTION_NONE CDISASM_DECODE_OPTION_NONE
/**
 * Interpret A32/A64 input as a big-endian 32-bit word and T32 input as a
 * sequence of big-endian 16-bit halfwords. The first T32 halfword remains the
 * first one decoded, including for a 32-bit Thumb instruction.
 */
#define CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN (UINT64_C(1) << 0)
#define CDISASM_ARM_DECODE_OPTION_BE \
    CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN
/**
 * Decode one T32 instruction as a member of an active IT block.  This state
 * changes the architecturally preferred alias for encodings whose assembly
 * rule calls InITBlock().  It is rejected for A32 and A64.
 */
#define CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK (UINT64_C(1) << 1)
#define CDISASM_ARM_DECODE_OPTION_KNOWN_MASK \
    (CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN \
        | CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK)
#define CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_0 \
    CDISASM_ARM_DECODE_OPTION_KNOWN_MASK
#define CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_1 UINT64_C(0)
#define CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_2 UINT64_C(0)
#define CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_3 UINT64_C(0)
#define CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_4 UINT64_C(0)
#define CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_5 UINT64_C(0)
#define CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_6 UINT64_C(0)
#define CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_7 UINT64_C(0)
#define CDISASM_ARM_DECODE_FLAGS_INITIALIZER(bitmap0_) \
    CDISASM_DECODE_FLAGS_INITIALIZER(bitmap0_)
#define CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER \
    CDISASM_ARM_DECODE_FLAGS_INITIALIZER(UINT64_C(0))
#define CDISASM_ARM_DECODE_FLAGS_ALL_INITIALIZER \
    {{ \
        CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_0, \
        CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_1, \
        CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_2, \
        CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_3, \
        CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_4, \
        CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_5, \
        CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_6, \
        CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_7 \
    }}

typedef uint8_t cdisasm_arm_isa_id;
#define CDISASM_ARM_ISA_NONE UINT8_C(0)
#define CDISASM_ARM_ISA_A32 UINT8_C(1)
#define CDISASM_ARM_ISA_T32 UINT8_C(2)
#define CDISASM_ARM_ISA_A64 UINT8_C(3)

/**
 * Numeric canonical AARCHMRS instruction-leaf identifier.
 *
 * Zero means that no generated canonical-leaf identity is attached.  The
 * generated decoder uses values 1..CDISASM_ARM_FORM_COUNT; the mapping is
 * append-only for a pinned machine-readable architecture baseline.
 */
typedef uint16_t cdisasm_arm_form_id;
#define CDISASM_ARM_FORM_NONE UINT16_C(0)
/** Last canonical form in the open AARCHMRS 2026-03 generated catalog. */
#define CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST UINT16_C(6569)
/** FEAT_HINTE form added by the reviewed Arm 2026-06 architecture delta. */
#define CDISASM_ARM_FORM_HINTE UINT16_C(6570)
#define CDISASM_ARM_FORM_LAST CDISASM_ARM_FORM_HINTE
#define CDISASM_ARM_FORM_COUNT UINT16_C(6571)

/** Condition IDs intentionally equal the architectural 4-bit encoding. */
typedef uint8_t cdisasm_arm_condition;
#define CDISASM_ARM_CONDITION_EQ UINT8_C(0)
#define CDISASM_ARM_CONDITION_NE UINT8_C(1)
#define CDISASM_ARM_CONDITION_CS UINT8_C(2)
#define CDISASM_ARM_CONDITION_HS CDISASM_ARM_CONDITION_CS
#define CDISASM_ARM_CONDITION_CC UINT8_C(3)
#define CDISASM_ARM_CONDITION_LO CDISASM_ARM_CONDITION_CC
#define CDISASM_ARM_CONDITION_MI UINT8_C(4)
#define CDISASM_ARM_CONDITION_PL UINT8_C(5)
#define CDISASM_ARM_CONDITION_VS UINT8_C(6)
#define CDISASM_ARM_CONDITION_VC UINT8_C(7)
#define CDISASM_ARM_CONDITION_HI UINT8_C(8)
#define CDISASM_ARM_CONDITION_LS UINT8_C(9)
#define CDISASM_ARM_CONDITION_GE UINT8_C(10)
#define CDISASM_ARM_CONDITION_LT UINT8_C(11)
#define CDISASM_ARM_CONDITION_GT UINT8_C(12)
#define CDISASM_ARM_CONDITION_LE UINT8_C(13)
#define CDISASM_ARM_CONDITION_AL UINT8_C(14)
#define CDISASM_ARM_CONDITION_NV UINT8_C(15)

typedef uint8_t cdisasm_arm_shift_type;
#define CDISASM_ARM_SHIFT_NONE UINT8_C(0)
#define CDISASM_ARM_SHIFT_LSL UINT8_C(1)
#define CDISASM_ARM_SHIFT_LSR UINT8_C(2)
#define CDISASM_ARM_SHIFT_ASR UINT8_C(3)
#define CDISASM_ARM_SHIFT_ROR UINT8_C(4)
#define CDISASM_ARM_SHIFT_RRX UINT8_C(5)
/** AdvSIMD modified-immediate shift-left-and-fill-with-ones modifier. */
#define CDISASM_ARM_SHIFT_MSL UINT8_C(6)

typedef uint8_t cdisasm_arm_extend_type;
#define CDISASM_ARM_EXTEND_NONE UINT8_C(0)
#define CDISASM_ARM_EXTEND_UXTB UINT8_C(1)
#define CDISASM_ARM_EXTEND_UXTH UINT8_C(2)
#define CDISASM_ARM_EXTEND_UXTW UINT8_C(3)
#define CDISASM_ARM_EXTEND_UXTX UINT8_C(4)
#define CDISASM_ARM_EXTEND_SXTB UINT8_C(5)
#define CDISASM_ARM_EXTEND_SXTH UINT8_C(6)
#define CDISASM_ARM_EXTEND_SXTW UINT8_C(7)
#define CDISASM_ARM_EXTEND_SXTX UINT8_C(8)

#define CDISASM_ARM_OPERAND_REGISTER_LIST UINT8_C(4)
/**
 * Two consecutive A64 scalar registers represented in one fixed-size operand.
 * reg is the first register and index_reg is the second. This preserves the
 * four-operand ABI while representing CASP's four registers plus memory.
 */
#define CDISASM_ARM_OPERAND_REGISTER_PAIR UINT8_C(5)
/** One SVE Z register. size is zero because its width is runtime-scalable. */
#define CDISASM_ARM_OPERAND_SCALABLE_REGISTER UINT8_C(6)
/** One SVE/SME predicate register, optionally carrying /m or /z. */
#define CDISASM_ARM_OPERAND_PREDICATE UINT8_C(7)
/** A brace-enclosed list of scalable registers. */
#define CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST UINT8_C(8)
/** An SME ZA/ZA-view/ZT0 operand, optionally with a W12-W15 slice selector. */
#define CDISASM_ARM_OPERAND_TILE UINT8_C(9)
/** A 128-bit implicit consecutive X-register pair displayed by its base Xn. */
#define CDISASM_ARM_OPERAND_REGISTER_PAIR_BASE UINT8_C(10)
/** Two predicate operands packed into one ABI operand and displayed separately. */
#define CDISASM_ARM_OPERAND_PREDICATE_PAIR UINT8_C(11)
/** A consecutive architectural register block displayed by its base register. */
#define CDISASM_ARM_OPERAND_REGISTER_BLOCK UINT8_C(12)
/**
 * An A64 system-register encoding. imm packs op0:op1:CRn:CRm:op2 in the
 * architectural 16-bit order used by bits 20:5 of MRS/MSR.
 */
#define CDISASM_ARM_OPERAND_SYSTEM_REGISTER UINT8_C(13)
/**
 * An A64 generic system-operation encoding. imm packs op1:CRn:CRm:op2 in
 * bits 13:0 and is rendered as the four architectural SYS/SYSL fields.
 */
#define CDISASM_ARM_OPERAND_SYSTEM_OPERATION UINT8_C(14)
/** A brace-enclosed list of fixed-width A64 Advanced SIMD V registers. */
#define CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST UINT8_C(15)
/** A64 MSR (immediate) PSTATE selector; imm contains a numeric field ID. */
#define CDISASM_ARM_OPERAND_PSTATE_FIELD UINT8_C(16)

typedef uint8_t cdisasm_arm_pstate_field_id;
#define CDISASM_ARM_PSTATE_FIELD_NONE UINT8_C(0)
#define CDISASM_ARM_PSTATE_FIELD_UAO UINT8_C(1)
#define CDISASM_ARM_PSTATE_FIELD_PAN UINT8_C(2)
#define CDISASM_ARM_PSTATE_FIELD_SPSEL UINT8_C(3)
#define CDISASM_ARM_PSTATE_FIELD_ALLINT UINT8_C(4)
#define CDISASM_ARM_PSTATE_FIELD_PM UINT8_C(5)
#define CDISASM_ARM_PSTATE_FIELD_SSBS UINT8_C(6)
#define CDISASM_ARM_PSTATE_FIELD_DIT UINT8_C(7)
#define CDISASM_ARM_PSTATE_FIELD_SVCRSM UINT8_C(8)
#define CDISASM_ARM_PSTATE_FIELD_SVCRZA UINT8_C(9)
#define CDISASM_ARM_PSTATE_FIELD_SVCRSMZA UINT8_C(10)
#define CDISASM_ARM_PSTATE_FIELD_TCO UINT8_C(11)
#define CDISASM_ARM_PSTATE_FIELD_DAIFSET UINT8_C(12)
#define CDISASM_ARM_PSTATE_FIELD_DAIFCLR UINT8_C(13)

/* Type-specific operand flags. They deliberately reuse the common flag byte. */
#define CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE UINT8_C(1)
#define CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO UINT8_C(2)
#define CDISASM_ARM_OPERAND_FLAG_HAS_LANE UINT8_C(4)
#define CDISASM_ARM_OPERAND_FLAG_WRITEBACK UINT8_C(8)
/** Predicate register carries an architectural element suffix such as .b. */
#define CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED UINT8_C(16)
/** An SME ZA slice operand selects the vertical view; absence means horizontal. */
#define CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL UINT8_C(32)
/**
 * ARM memory operand displacement is an unsigned coefficient of VL bytes.
 *
 * This flag is valid only for a CDISASM_OPERAND_MEMORY operand and is paired
 * with CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT.  imm stores the coefficient,
 * not a byte count.  The represented address is base + imm * VL, where VL is
 * the architectural vector length in bytes.  The SME ZA array-vector LDR/STR
 * forms use this coefficient.  Their runtime transfer size, and that of the
 * predicated contiguous ZA-slice LD1/ST1 forms, is represented by size == 0.
 */
#define CDISASM_ARM_OPERAND_FLAG_VL_SCALED UINT8_C(64)
/**
 * A trailing architectural rotation immediate is packed into this operand's
 * imm field.  This preserves the fixed four-operand ARM ABI for instructions
 * such as predicated SVE FCMLA whose tied destination plus predicate, two
 * vector sources, and rotation otherwise require five records.
 */
#define CDISASM_ARM_OPERAND_FLAG_HAS_ROTATION UINT8_C(128)

#define CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand_pointer) \
    ((uint8_t)((operand_pointer)->extend_type))
#define CDISASM_ARM_SCALABLE_LIST_COUNT(operand_pointer) \
    ((uint8_t)((operand_pointer)->register_list & UINT16_C(0xff)))
#define CDISASM_ARM_SCALABLE_LIST_STRIDE(operand_pointer) \
    ((uint8_t)((operand_pointer)->register_list >> 8))

/** Numeric state selector carried by SMSTART/SMSTOP immediate operands. */
typedef uint8_t cdisasm_arm_sme_state;
#define CDISASM_ARM_SME_STATE_NONE UINT8_C(0)
#define CDISASM_ARM_SME_STATE_SM UINT8_C(1)
#define CDISASM_ARM_SME_STATE_ZA UINT8_C(2)

typedef uint32_t cdisasm_arm_instruction_flag;
#define CDISASM_ARM_INSTRUCTION_FLAG_NONE UINT32_C(0)
#define CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS (UINT32_C(1) << 0)
#define CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK (UINT32_C(1) << 1)
#define CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX (UINT32_C(1) << 2)
#define CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX (UINT32_C(1) << 3)
#define CDISASM_ARM_INSTRUCTION_FLAG_LINK (UINT32_C(1) << 4)
#define CDISASM_ARM_INSTRUCTION_FLAG_BYTE (UINT32_C(1) << 5)
#define CDISASM_ARM_INSTRUCTION_FLAG_USER_REGISTERS (UINT32_C(1) << 6)
#define CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED (UINT32_C(1) << 7)
/** The encoding was decoded, but is not architecturally reliable to execute. */
#define CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL (UINT32_C(1) << 8)
/** A constrained-unpredictable rule was violated; implies ILLEGAL. */
#define CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE (UINT32_C(1) << 9)
/** A32/T32 multiple-transfer addresses advance. */
#define CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT (UINT32_C(1) << 10)
/** A32/T32 multiple-transfer addresses descend. */
#define CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT (UINT32_C(1) << 11)
/** The operands are packed SIMD vectors with explicit lane metadata. */
#define CDISASM_ARM_INSTRUCTION_FLAG_SIMD (UINT32_C(1) << 12)
/** The instruction performs floating-point arithmetic. */
#define CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT (UINT32_C(1) << 13)
/** The instruction or named system register is an Apple extension. */
#define CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY (UINT32_C(1) << 14)
/** The instruction belongs to Apple's undocumented matrix extension. */
#define CDISASM_ARM_INSTRUCTION_FLAG_APPLE_AMX (UINT32_C(1) << 15)
/** The instruction belongs to Apple's two-lane 53-bit multiply extension. */
#define CDISASM_ARM_INSTRUCTION_FLAG_APPLE_MUL53 (UINT32_C(1) << 16)
/** The instruction accesses an Apple-specific system facility. */
#define CDISASM_ARM_INSTRUCTION_FLAG_APPLE_SYSTEM (UINT32_C(1) << 17)
/** The instruction belongs to an architectural atomic/synchronization family. */
#define CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC (UINT32_C(1) << 18)
/** The instruction has acquire ordering semantics. */
#define CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE (UINT32_C(1) << 19)
/** The instruction has release ordering semantics. */
#define CDISASM_ARM_INSTRUCTION_FLAG_RELEASE (UINT32_C(1) << 20)
/** The instruction reads or updates the local exclusive monitor. */
#define CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE (UINT32_C(1) << 21)
/** The instruction uses runtime-scalable SVE vector or predicate state. */
#define CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR (UINT32_C(1) << 22)
/** At least one source or destination is governed by a predicate. */
#define CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED (UINT32_C(1) << 23)
/** The instruction belongs to the Scalable Matrix Extension. */
#define CDISASM_ARM_INSTRUCTION_FLAG_SME (UINT32_C(1) << 24)
/** The instruction changes or requires streaming SVE mode. */
#define CDISASM_ARM_INSTRUCTION_FLAG_STREAMING (UINT32_C(1) << 25)
/** The instruction accesses ZA or ZT matrix/table storage. */
#define CDISASM_ARM_INSTRUCTION_FLAG_MATRIX (UINT32_C(1) << 26)
/** The instruction manipulates allocation tags (FEAT_MTE). */
#define CDISASM_ARM_INSTRUCTION_FLAG_MEMORY_TAGGING (UINT32_C(1) << 27)
/** The instruction creates, authenticates, or strips pointer authentication. */
#define CDISASM_ARM_INSTRUCTION_FLAG_POINTER_AUTH (UINT32_C(1) << 28)
/** Each displayed register denotes the base of a consecutive architectural pair. */
#define CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC_PAIR (UINT32_C(1) << 29)
/** The canonical opcode leaf was selected by the generated AARCHMRS tree. */
#define CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK (UINT32_C(1) << 30)
/**
 * The opcode and mnemonic are known, but the generated operand recipe has not
 * yet populated the fixed public operand records.  cdisasm_arm_decode does not
 * report such partial metadata as a successful structured decode, so its
 * successful results never carry this flag.  The flag remains part of the ABI
 * for externally retained generated metadata; cdisasm_arm_format accepts such
 * metadata only when an exact generated rendering recipe is available.
 */
#define CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE (UINT32_C(1) << 31)

/** Numeric SDSB option values; values 4..15 are reserved and decode ILLEGAL. */
typedef uint8_t cdisasm_arm_apple_sdsb_option;
#define CDISASM_ARM_APPLE_SDSB_OSH UINT8_C(0)
#define CDISASM_ARM_APPLE_SDSB_NSH UINT8_C(1)
#define CDISASM_ARM_APPLE_SDSB_ISH UINT8_C(2)
#define CDISASM_ARM_APPLE_SDSB_SY UINT8_C(3)

/**
 * One architecture-specific operand in assembly order.
 *
 * imm is the semantic immediate value. For a memory operand it is the signed
 * displacement bit pattern. For a relative target, imm is the resolved target
 * and address is the signed displacement bit pattern. Shift/extend fields
 * preserve encoding semantics without constructing text. For a register
 * operand of an instruction carrying CDISASM_ARM_INSTRUCTION_FLAG_SIMD,
 * size is the total vector size in bytes, vector_element_size is the lane
 * size in bytes, and vector_element_count is the lane count. The vector
 * values are stored in extend_type/scale without changing the public ABI and
 * are exposed by CDISASM_ARM_VECTOR_ELEMENT_SIZE/COUNT; inspect those values
 * only for SIMD instructions. Unused fields are always zero.
 */
typedef struct cdisasm_arm_operand {
    uint64_t address;
    uint64_t imm;
    cdisasm_arm_reg_id reg;
    cdisasm_arm_reg_id base_reg;
    cdisasm_arm_reg_id index_reg;
    uint16_t register_list;
    uint8_t type;
    uint8_t size;
    cdisasm_operand_access access;
    uint8_t flags;
    cdisasm_arm_shift_type shift_type;
    uint8_t shift_amount;
    cdisasm_arm_extend_type extend_type;
    uint8_t scale;
} cdisasm_arm_operand;

#define CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand_pointer) \
    ((uint8_t)((operand_pointer)->extend_type))
#define CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand_pointer) \
    ((uint8_t)((operand_pointer)->scale))

/** Fixed-layout numeric result produced by cdisasm_arm_decode. */
typedef struct cdisasm_arm_instruction {
    uint64_t address;
    uint64_t branch_target;
    uint32_t opcode_size;
    uint32_t opcode_groups;
    uint32_t raw_instruction;
    uint32_t instruction_flags;
    cdisasm_arm_name_id name_id;
    uint8_t last_error_id;
    uint8_t operand_count;
    cdisasm_arm_condition condition;
    cdisasm_arm_isa_id isa_id;
    cdisasm_arm_form_id form_id;
    cdisasm_arm_operand operand[CDISASM_ARM_MAX_OPERANDS];
} cdisasm_arm_instruction;

#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(cdisasm_arm_operand) == CDISASM_ARM_OPERAND_SIZE,
              "unexpected cdisasm ARM operand ABI size");
static_assert(offsetof(cdisasm_arm_instruction, operand) == 40,
              "unexpected cdisasm ARM instruction ABI layout");
static_assert(offsetof(cdisasm_arm_instruction, form_id) == 38,
              "unexpected cdisasm ARM form-id ABI layout");
static_assert(sizeof(cdisasm_arm_instruction) == CDISASM_ARM_INSTRUCTION_SIZE,
              "unexpected cdisasm ARM instruction ABI size");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(cdisasm_arm_operand) == CDISASM_ARM_OPERAND_SIZE,
               "unexpected cdisasm ARM operand ABI size");
_Static_assert(offsetof(cdisasm_arm_instruction, operand) == 40,
               "unexpected cdisasm ARM instruction ABI layout");
_Static_assert(offsetof(cdisasm_arm_instruction, form_id) == 38,
               "unexpected cdisasm ARM form-id ABI layout");
_Static_assert(sizeof(cdisasm_arm_instruction) == CDISASM_ARM_INSTRUCTION_SIZE,
               "unexpected cdisasm ARM instruction ABI size");
#endif

/**
 * Reusable ARM CPU/mode decoding policy.  family_mask is the capability
 * projection for the selected CPU and instruction state; family_value is the
 * default family selection.  The complete decode-option bitmap remains in
 * flags and is authoritative for byte order and IT-block state.
 */
typedef struct cdisasm_arm_decode_context {
    cdisasm_arm_cpu_id cpu_id;
    cdisasm_arm_mode mode;
    cdisasm_arm_decode_flags flags;
    cdisasm_arm_family_mask family_mask;
    cdisasm_arm_family_mask family_value;
} cdisasm_arm_decode_context;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns the instruction states implemented by the selected physical CPU.
 *
 * This is a hardware-capability query: its result can include an instruction
 * state which this cdisasm build does not decode yet. Use
 * cdisasm_arm_decoder_mode_mask when selecting a state for the decoder.
 * Returns zero for an invalid CPU ID.
 */
CDISASM_ARM_API cdisasm_arm_mode_mask CDISASM_CALL cdisasm_arm_cpu_mode_mask(
    cdisasm_arm_cpu_id cpu_id);

/**
 * Returns the selected CPU's states currently implemented by this decoder.
 *
 * The result is the intersection of cdisasm_arm_cpu_mode_mask(cpu_id) and the
 * decoder implementation. Returns zero for an invalid CPU ID.
 */
CDISASM_ARM_API cdisasm_arm_mode_mask CDISASM_CALL
cdisasm_arm_decoder_mode_mask(cdisasm_arm_cpu_id cpu_id);

/**
 * Writes every ARM decode option accepted for one valid CPU/mode pair.
 * The output is cleared first; invalid arguments return
 * CDISASM_STATUS_INVALID_ARGUMENT. BIG_ENDIAN is available for every
 * supported ARM CPU/mode pair; IN_IT_BLOCK is available only for T32.
 */
CDISASM_ARM_API cdisasm_status CDISASM_CALL
cdisasm_arm_cpu_decode_flag_mask(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    cdisasm_arm_decode_flags *flags);

/** Returns the direct ARM families available for a CPU and instruction state. */
CDISASM_ARM_API cdisasm_arm_family_mask CDISASM_CALL
cdisasm_arm_cpu_family_mask(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode);

/** Returns immutable metadata for a direct ARM family, or NULL if invalid. */
CDISASM_ARM_API const cdisasm_arm_family_descriptor *CDISASM_CALL
cdisasm_arm_family_descriptor_get(cdisasm_arm_family_id family_id);

/** Initializes a reusable ARM CPU/mode context. */
CDISASM_ARM_API cdisasm_status CDISASM_CALL
cdisasm_arm_cpu_decode_context(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    cdisasm_arm_decode_context *context);

/** Adds/removes one available family from context->family_value. */
CDISASM_ARM_API int CDISASM_CALL cdisasm_arm_decode_context_add_family(
    cdisasm_arm_decode_context *context,
    cdisasm_arm_family_id family_id);
CDISASM_ARM_API int CDISASM_CALL cdisasm_arm_decode_context_remove_family(
    cdisasm_arm_decode_context *context,
    cdisasm_arm_family_id family_id);

/** Reads available and selected family masks without exposing context fields. */
CDISASM_ARM_API cdisasm_arm_family_mask CDISASM_CALL
cdisasm_arm_decode_context_get_available_families(
    const cdisasm_arm_decode_context *context);
CDISASM_ARM_API cdisasm_arm_family_mask CDISASM_CALL
cdisasm_arm_decode_context_get_set_families(
    const cdisasm_arm_decode_context *context);

/**
 * Decodes one A32, T32, or A64 instruction into numeric metadata. Input is
 * little-endian by default; CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN selects the
 * byte-stream contract documented with that option.
 *
 * Returns two or four on successful T32 decode, four on successful A32/A64
 * decode, and zero on failure. A non-NULL result is always initialized; on
 * failure every byte is zero except last_error_id. Generated forms for which
 * exact structured operands are unavailable fail with
 * CDISASM_STATUS_UNSUPPORTED_INSTRUCTION.
 */
CDISASM_ARM_API uint32_t CDISASM_CALL cdisasm_arm_decode(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    const cdisasm_arm_decode_flags *flags,
    cdisasm_arm_instruction *instruction);

/** Decodes using a reusable ARM CPU/mode context. */
CDISASM_ARM_API uint32_t CDISASM_CALL cdisasm_arm_decode_with_context(
    const cdisasm_arm_decode_context *context,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_arm_instruction *instruction);

#ifdef __cplusplus
}
#endif

#endif
