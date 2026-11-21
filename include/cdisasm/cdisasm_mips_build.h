#ifndef CDISASM_CDISASM_MIPS_BUILD_H
#define CDISASM_CDISASM_MIPS_BUILD_H

#include <stdint.h>
#include <cdisasm/cdisasm_config.h>

/* Configured family selection. CPU capabilities, ISA legality and
 * USE_EXTRA_OPCODES can further restrict the available native slices. */
#define CDISASM_MIPS_BUILD_FAMILY_MASK CDISASM_CONFIG_MIPS_FAMILY_MASK

#if defined(USE_MIPS_FPU)
#if USE_MIPS_FPU != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 0u) & 1u)
#error "USE_MIPS_FPU conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_FPU ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 0u) & 1u)
#endif

#if defined(USE_MIPS_DSP)
#if USE_MIPS_DSP != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 1u) & 1u)
#error "USE_MIPS_DSP conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_DSP ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 1u) & 1u)
#endif

#if defined(USE_MIPS_DSPR2)
#if USE_MIPS_DSPR2 != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 2u) & 1u)
#error "USE_MIPS_DSPR2 conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_DSPR2 ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 2u) & 1u)
#endif

#if defined(USE_MIPS_MT)
#if USE_MIPS_MT != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 3u) & 1u)
#error "USE_MIPS_MT conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_MT ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 3u) & 1u)
#endif

#if defined(USE_MIPS_MSA)
#if USE_MIPS_MSA != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 4u) & 1u)
#error "USE_MIPS_MSA conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_MSA ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 4u) & 1u)
#endif

#if defined(USE_MIPS_VZ)
#if USE_MIPS_VZ != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 5u) & 1u)
#error "USE_MIPS_VZ conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_VZ ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 5u) & 1u)
#endif

#if defined(USE_MIPS_EVA)
#if USE_MIPS_EVA != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 6u) & 1u)
#error "USE_MIPS_EVA conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_EVA ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 6u) & 1u)
#endif

#if defined(USE_MIPS_XPA)
#if USE_MIPS_XPA != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 7u) & 1u)
#error "USE_MIPS_XPA conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_XPA ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 7u) & 1u)
#endif

#if defined(USE_MIPS_DSPR3)
#if USE_MIPS_DSPR3 != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 8u) & 1u)
#error "USE_MIPS_DSPR3 conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_DSPR3 ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 8u) & 1u)
#endif

#if defined(USE_MIPS_MIPS3D)
#if USE_MIPS_MIPS3D != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 9u) & 1u)
#error "USE_MIPS_MIPS3D conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_MIPS3D ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 9u) & 1u)
#endif

#if defined(USE_MIPS_MDMX)
#if USE_MIPS_MDMX != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 10u) & 1u)
#error "USE_MIPS_MDMX conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_MDMX ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 10u) & 1u)
#endif

#if defined(USE_MIPS_SMARTMIPS)
#if USE_MIPS_SMARTMIPS != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 11u) & 1u)
#error "USE_MIPS_SMARTMIPS conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_SMARTMIPS ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 11u) & 1u)
#endif

#if defined(USE_MIPS_MCU)
#if USE_MIPS_MCU != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 12u) & 1u)
#error "USE_MIPS_MCU conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_MCU ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 12u) & 1u)
#endif

#if defined(USE_MIPS_CRC)
#if USE_MIPS_CRC != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 13u) & 1u)
#error "USE_MIPS_CRC conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_CRC ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 13u) & 1u)
#endif

#if defined(USE_MIPS_GINV)
#if USE_MIPS_GINV != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 14u) & 1u)
#error "USE_MIPS_GINV conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_GINV ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 14u) & 1u)
#endif

#if defined(USE_MIPS_COP2)
#if USE_MIPS_COP2 != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 15u) & 1u)
#error "USE_MIPS_COP2 conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_COP2 ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 15u) & 1u)
#endif

#if defined(USE_MIPS_COP3)
#if USE_MIPS_COP3 != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 16u) & 1u)
#error "USE_MIPS_COP3 conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_COP3 ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 16u) & 1u)
#endif

#if defined(USE_MIPS_PAIRED_SINGLE)
#if USE_MIPS_PAIRED_SINGLE != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 17u) & 1u)
#error "USE_MIPS_PAIRED_SINGLE conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_PAIRED_SINGLE ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 17u) & 1u)
#endif

#if defined(USE_MIPS_CNMIPS)
#if USE_MIPS_CNMIPS != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 18u) & 1u)
#error "USE_MIPS_CNMIPS conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_CNMIPS ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 18u) & 1u)
#endif

#if defined(USE_MIPS_CNMIPSP)
#if USE_MIPS_CNMIPSP != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 19u) & 1u)
#error "USE_MIPS_CNMIPSP conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_CNMIPSP ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 19u) & 1u)
#endif

#if defined(USE_MIPS_LOONGSON)
#if USE_MIPS_LOONGSON != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 20u) & 1u)
#error "USE_MIPS_LOONGSON conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_LOONGSON ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 20u) & 1u)
#endif

#if defined(USE_MIPS_ALLEGREX)
#if USE_MIPS_ALLEGREX != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 21u) & 1u)
#error "USE_MIPS_ALLEGREX conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_ALLEGREX ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 21u) & 1u)
#endif

#if defined(USE_MIPS_R5900)
#if USE_MIPS_R5900 != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 22u) & 1u)
#error "USE_MIPS_R5900 conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_R5900 ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 22u) & 1u)
#endif

#if defined(USE_MIPS_MXU)
#if USE_MIPS_MXU != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 23u) & 1u)
#error "USE_MIPS_MXU conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_MXU ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 23u) & 1u)
#endif

#if defined(USE_MIPS_MIPS16E2)
#if USE_MIPS_MIPS16E2 != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 24u) & 1u)
#error "USE_MIPS_MIPS16E2 conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_MIPS16E2 ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 24u) & 1u)
#endif

#if defined(USE_MIPS_LOONGSON2E)
#if USE_MIPS_LOONGSON2E != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 25u) & 1u)
#error "USE_MIPS_LOONGSON2E conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_LOONGSON2E ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 25u) & 1u)
#endif

#if defined(USE_MIPS_LOONGSON2F)
#if USE_MIPS_LOONGSON2F != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 26u) & 1u)
#error "USE_MIPS_LOONGSON2F conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_LOONGSON2F ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 26u) & 1u)
#endif

#if defined(USE_MIPS_LOONGSON_EXT)
#if USE_MIPS_LOONGSON_EXT != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 27u) & 1u)
#error "USE_MIPS_LOONGSON_EXT conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_LOONGSON_EXT ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 27u) & 1u)
#endif

#if defined(USE_MIPS_LOONGSON_EXT2)
#if USE_MIPS_LOONGSON_EXT2 != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 28u) & 1u)
#error "USE_MIPS_LOONGSON_EXT2 conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_LOONGSON_EXT2 ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 28u) & 1u)
#endif

#if defined(USE_MIPS_LOONGSON_CAM)
#if USE_MIPS_LOONGSON_CAM != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 29u) & 1u)
#error "USE_MIPS_LOONGSON_CAM conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_LOONGSON_CAM ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 29u) & 1u)
#endif

#if defined(USE_MIPS_DSP64)
#if USE_MIPS_DSP64 != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 30u) & 1u)
#error "USE_MIPS_DSP64 conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_DSP64 ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 30u) & 1u)
#endif

#if defined(USE_MIPS_MXU2)
#if USE_MIPS_MXU2 != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 31u) & 1u)
#error "USE_MIPS_MXU2 conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_MXU2 ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 31u) & 1u)
#endif

#if defined(USE_MIPS_MXU3)
#if USE_MIPS_MXU3 != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 32u) & 1u)
#error "USE_MIPS_MXU3 conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_MXU3 ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 32u) & 1u)
#endif

#if defined(USE_MIPS_LOONGSIMD)
#if USE_MIPS_LOONGSIMD != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 33u) & 1u)
#error "USE_MIPS_LOONGSIMD conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_LOONGSIMD ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 33u) & 1u)
#endif

#if defined(USE_MIPS_R5900_VU0)
#if USE_MIPS_R5900_VU0 != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 34u) & 1u)
#error "USE_MIPS_R5900_VU0 conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_R5900_VU0 ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 34u) & 1u)
#endif

#if defined(USE_MIPS_R5900_VU1)
#if USE_MIPS_R5900_VU1 != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 35u) & 1u)
#error "USE_MIPS_R5900_VU1 conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_R5900_VU1 ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 35u) & 1u)
#endif

#if defined(USE_MIPS_MXU3_1)
#if USE_MIPS_MXU3_1 != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 36u) & 1u)
#error "USE_MIPS_MXU3_1 conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_MXU3_1 ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 36u) & 1u)
#endif

#if defined(USE_MIPS_LOONGASX)
#if USE_MIPS_LOONGASX != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 37u) & 1u)
#error "USE_MIPS_LOONGASX conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_LOONGASX ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 37u) & 1u)
#endif

#if defined(USE_MIPS_XLR)
#if USE_MIPS_XLR != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 38u) & 1u)
#error "USE_MIPS_XLR conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_XLR ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 38u) & 1u)
#endif

#if defined(USE_MIPS_XLP)
#if USE_MIPS_XLP != ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 39u) & 1u)
#error "USE_MIPS_XLP conflicts with the configured cdisasm library"
#endif
#else
#define USE_MIPS_XLP ((CDISASM_MIPS_BUILD_FAMILY_MASK >> 39u) & 1u)
#endif

#endif
