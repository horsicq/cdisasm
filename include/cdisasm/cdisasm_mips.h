#ifndef CDISASM_CDISASM_MIPS_H
#define CDISASM_CDISASM_MIPS_H

#include "cdisasm_common.h"
#if !USE_ARCH_MIPS
#error "cdisasm MIPS support is disabled in this build"
#endif
#include "cdisasm_mips_ids.h"

#define CDISASM_MIPS_API CDISASM_API
#define CDISASM_MIPS_MAX_INSTRUCTION_SIZE 4u
#define CDISASM_MIPS_MAX_OPERANDS 6u
#define CDISASM_MIPS_OPERAND_SIZE 32u
#define CDISASM_MIPS_INSTRUCTION_SIZE 232u
#define CDISASM_MIPS_DECODE_CONTEXT_SIZE 96u

typedef uint32_t cdisasm_mips_mode;
#define CDISASM_MIPS_MODE_32 UINT32_C(32)
#define CDISASM_MIPS_MODE_64 UINT32_C(64)
typedef uint32_t cdisasm_mips_mode_mask;
#define CDISASM_MIPS_MODE_MASK_NONE UINT32_C(0)
#define CDISASM_MIPS_MODE_MASK_32 UINT32_C(1)
#define CDISASM_MIPS_MODE_MASK_64 UINT32_C(2)

/* ISA revision and register width are separate. Release 6 is not an ordered
 * superset of earlier releases: overlapping encodings require exact selection. */
typedef uint32_t cdisasm_mips_revision;
#define CDISASM_MIPS_REVISION_NONE UINT32_C(0)
#define CDISASM_MIPS_REVISION_I UINT32_C(1)
#define CDISASM_MIPS_REVISION_II UINT32_C(2)
#define CDISASM_MIPS_REVISION_III UINT32_C(3)
#define CDISASM_MIPS_REVISION_IV UINT32_C(4)
#define CDISASM_MIPS_REVISION_V UINT32_C(5)
#define CDISASM_MIPS_REVISION_32R1 UINT32_C(32)
#define CDISASM_MIPS_REVISION_32R2 UINT32_C(33)
#define CDISASM_MIPS_REVISION_32R3 UINT32_C(34)
#define CDISASM_MIPS_REVISION_32R5 UINT32_C(36)
#define CDISASM_MIPS_REVISION_32R6 UINT32_C(37)
#define CDISASM_MIPS_REVISION_64R1 UINT32_C(64)
#define CDISASM_MIPS_REVISION_64R2 UINT32_C(65)
#define CDISASM_MIPS_REVISION_64R3 UINT32_C(66)
#define CDISASM_MIPS_REVISION_64R5 UINT32_C(68)
#define CDISASM_MIPS_REVISION_64R6 UINT32_C(69)

typedef cdisasm_cpu_id cdisasm_mips_cpu_id;
#define CDISASM_MIPS_CPU_ANY (CDISASM_CPU_GROUP_MIPS | UINT32_C(0))
#define CDISASM_MIPS_CPU_GENERIC CDISASM_MIPS_CPU_ANY
#define CDISASM_MIPS_CPU_R3000 (CDISASM_CPU_GROUP_MIPS | UINT32_C(1))
#define CDISASM_MIPS_CPU_R4000 (CDISASM_CPU_GROUP_MIPS | UINT32_C(2))
#define CDISASM_MIPS_CPU_4KC (CDISASM_CPU_GROUP_MIPS | UINT32_C(3))
#define CDISASM_MIPS_CPU_24KC (CDISASM_CPU_GROUP_MIPS | UINT32_C(4))
#define CDISASM_MIPS_CPU_24KF (CDISASM_CPU_GROUP_MIPS | UINT32_C(5))
#define CDISASM_MIPS_CPU_5KC (CDISASM_CPU_GROUP_MIPS | UINT32_C(6))
#define CDISASM_MIPS_CPU_5KF (CDISASM_CPU_GROUP_MIPS | UINT32_C(7))
#define CDISASM_MIPS_CPU_24KEC (CDISASM_CPU_GROUP_MIPS | UINT32_C(8))
#define CDISASM_MIPS_CPU_34KC (CDISASM_CPU_GROUP_MIPS | UINT32_C(9))
#define CDISASM_MIPS_CPU_34KN (CDISASM_CPU_GROUP_MIPS | UINT32_C(10))
#define CDISASM_MIPS_CPU_74KC (CDISASM_CPU_GROUP_MIPS | UINT32_C(11))
#define CDISASM_MIPS_CPU_1004KC (CDISASM_CPU_GROUP_MIPS | UINT32_C(12))
#define CDISASM_MIPS_CPU_P5600 (CDISASM_CPU_GROUP_MIPS | UINT32_C(13))
#define CDISASM_MIPS_CPU_I6400 (CDISASM_CPU_GROUP_MIPS | UINT32_C(14))
#define CDISASM_MIPS_CPU_I6500 (CDISASM_CPU_GROUP_MIPS | UINT32_C(15))
#define CDISASM_MIPS_CPU_P6600 (CDISASM_CPU_GROUP_MIPS | UINT32_C(16))
#define CDISASM_MIPS_CPU_P5600_FPU (CDISASM_CPU_GROUP_MIPS | UINT32_C(17))
#define CDISASM_MIPS_CPU_P5600_FPU_MSA (CDISASM_CPU_GROUP_MIPS | UINT32_C(18))
#define CDISASM_MIPS_CPU_I6400_FPU (CDISASM_CPU_GROUP_MIPS | UINT32_C(19))
#define CDISASM_MIPS_CPU_I6400_FPU_MSA (CDISASM_CPU_GROUP_MIPS | UINT32_C(20))
#define CDISASM_MIPS_CPU_I6500_FPU (CDISASM_CPU_GROUP_MIPS | UINT32_C(21))
#define CDISASM_MIPS_CPU_I6500_FPU_MSA (CDISASM_CPU_GROUP_MIPS | UINT32_C(22))
#define CDISASM_MIPS_CPU_P6600_FPU (CDISASM_CPU_GROUP_MIPS | UINT32_C(23))
#define CDISASM_MIPS_CPU_P6600_FPU_MSA (CDISASM_CPU_GROUP_MIPS | UINT32_C(24))
#define CDISASM_MIPS_CPU_ALLEGREX (CDISASM_CPU_GROUP_MIPS | UINT32_C(25))
#define CDISASM_MIPS_CPU_R5900 (CDISASM_CPU_GROUP_MIPS | UINT32_C(26))
#define CDISASM_MIPS_CPU_OCTEON (CDISASM_CPU_GROUP_MIPS | UINT32_C(27))
#define CDISASM_MIPS_CPU_OCTEONP (CDISASM_CPU_GROUP_MIPS | UINT32_C(28))
#define CDISASM_MIPS_CPU_LOONGSON2E (CDISASM_CPU_GROUP_MIPS | UINT32_C(29))
#define CDISASM_MIPS_CPU_LOONGSON2F (CDISASM_CPU_GROUP_MIPS | UINT32_C(30))
#define CDISASM_MIPS_CPU_LOONGSON3A3000 (CDISASM_CPU_GROUP_MIPS | UINT32_C(31))
#define CDISASM_MIPS_CPU_LOONGSON3A4000 (CDISASM_CPU_GROUP_MIPS | UINT32_C(32))
#define CDISASM_MIPS_CPU_FIRST CDISASM_MIPS_CPU_R3000
#define CDISASM_MIPS_CPU_LAST CDISASM_MIPS_CPU_LOONGSON3A4000

typedef cdisasm_decode_flags cdisasm_mips_decode_flags;
typedef uint32_t cdisasm_mips_decode_bit_id;
#define CDISASM_MIPS_DECODE_BIT_BIG_ENDIAN UINT32_C(0)
#define CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN (UINT64_C(1) << 0)
#define CDISASM_MIPS_DECODE_BIT_FPU UINT32_C(1)
#define CDISASM_MIPS_DECODE_FLAG_FPU (UINT64_C(1) << 1)
#define CDISASM_MIPS_DECODE_BIT_DSP UINT32_C(2)
#define CDISASM_MIPS_DECODE_FLAG_DSP (UINT64_C(1) << 2)
#define CDISASM_MIPS_DECODE_BIT_DSPR2 UINT32_C(3)
#define CDISASM_MIPS_DECODE_FLAG_DSPR2 (UINT64_C(1) << 3)
#define CDISASM_MIPS_DECODE_BIT_MT UINT32_C(4)
#define CDISASM_MIPS_DECODE_FLAG_MT (UINT64_C(1) << 4)
#define CDISASM_MIPS_DECODE_BIT_MSA UINT32_C(5)
#define CDISASM_MIPS_DECODE_FLAG_MSA (UINT64_C(1) << 5)
#define CDISASM_MIPS_DECODE_BIT_VZ UINT32_C(6)
#define CDISASM_MIPS_DECODE_FLAG_VZ (UINT64_C(1) << 6)
#define CDISASM_MIPS_DECODE_BIT_EVA UINT32_C(7)
#define CDISASM_MIPS_DECODE_FLAG_EVA (UINT64_C(1) << 7)
#define CDISASM_MIPS_DECODE_BIT_XPA UINT32_C(8)
#define CDISASM_MIPS_DECODE_FLAG_XPA (UINT64_C(1) << 8)
#define CDISASM_MIPS_DECODE_BIT_MIPS16 UINT32_C(9)
#define CDISASM_MIPS_DECODE_FLAG_MIPS16 (UINT64_C(1) << 9)
#define CDISASM_MIPS_DECODE_BIT_MICROMIPS UINT32_C(10)
#define CDISASM_MIPS_DECODE_FLAG_MICROMIPS (UINT64_C(1) << 10)
#define CDISASM_MIPS_DECODE_BIT_NANOMIPS UINT32_C(11)
#define CDISASM_MIPS_DECODE_FLAG_NANOMIPS (UINT64_C(1) << 11)
#define CDISASM_MIPS_DECODE_BIT_FPR32 UINT32_C(12)
#define CDISASM_MIPS_DECODE_FLAG_FPR32 (UINT64_C(1) << 12)
#define CDISASM_MIPS_DECODE_BIT_EXPLICIT_FAMILIES UINT32_C(13)
#define CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES (UINT64_C(1) << 13)
#define CDISASM_MIPS_DECODE_BIT_ISA_I UINT32_C(32)
#define CDISASM_MIPS_DECODE_FLAG_ISA_I (UINT64_C(1) << 32)
#define CDISASM_MIPS_DECODE_BIT_ISA_II UINT32_C(33)
#define CDISASM_MIPS_DECODE_FLAG_ISA_II (UINT64_C(1) << 33)
#define CDISASM_MIPS_DECODE_BIT_ISA_III UINT32_C(34)
#define CDISASM_MIPS_DECODE_FLAG_ISA_III (UINT64_C(1) << 34)
#define CDISASM_MIPS_DECODE_BIT_ISA_IV UINT32_C(35)
#define CDISASM_MIPS_DECODE_FLAG_ISA_IV (UINT64_C(1) << 35)
#define CDISASM_MIPS_DECODE_BIT_ISA_32R1 UINT32_C(36)
#define CDISASM_MIPS_DECODE_FLAG_ISA_32R1 (UINT64_C(1) << 36)
#define CDISASM_MIPS_DECODE_BIT_ISA_32R2 UINT32_C(37)
#define CDISASM_MIPS_DECODE_FLAG_ISA_32R2 (UINT64_C(1) << 37)
#define CDISASM_MIPS_DECODE_BIT_ISA_32R5 UINT32_C(38)
#define CDISASM_MIPS_DECODE_FLAG_ISA_32R5 (UINT64_C(1) << 38)
#define CDISASM_MIPS_DECODE_BIT_ISA_32R6 UINT32_C(39)
#define CDISASM_MIPS_DECODE_FLAG_ISA_32R6 (UINT64_C(1) << 39)
#define CDISASM_MIPS_DECODE_BIT_ISA_64R1 UINT32_C(40)
#define CDISASM_MIPS_DECODE_FLAG_ISA_64R1 (UINT64_C(1) << 40)
#define CDISASM_MIPS_DECODE_BIT_ISA_64R2 UINT32_C(41)
#define CDISASM_MIPS_DECODE_FLAG_ISA_64R2 (UINT64_C(1) << 41)
#define CDISASM_MIPS_DECODE_BIT_ISA_64R6 UINT32_C(42)
#define CDISASM_MIPS_DECODE_FLAG_ISA_64R6 (UINT64_C(1) << 42)

#define CDISASM_MIPS_DECODE_BIT_DSPR3 UINT32_C(14)
#define CDISASM_MIPS_DECODE_FLAG_DSPR3 (UINT64_C(1) << 14)
#define CDISASM_MIPS_DECODE_BIT_MIPS3D UINT32_C(15)
#define CDISASM_MIPS_DECODE_FLAG_MIPS3D (UINT64_C(1) << 15)
#define CDISASM_MIPS_DECODE_BIT_MDMX UINT32_C(16)
#define CDISASM_MIPS_DECODE_FLAG_MDMX (UINT64_C(1) << 16)
#define CDISASM_MIPS_DECODE_BIT_SMARTMIPS UINT32_C(17)
#define CDISASM_MIPS_DECODE_FLAG_SMARTMIPS (UINT64_C(1) << 17)
#define CDISASM_MIPS_DECODE_BIT_MCU UINT32_C(18)
#define CDISASM_MIPS_DECODE_FLAG_MCU (UINT64_C(1) << 18)
#define CDISASM_MIPS_DECODE_BIT_CRC UINT32_C(19)
#define CDISASM_MIPS_DECODE_FLAG_CRC (UINT64_C(1) << 19)
#define CDISASM_MIPS_DECODE_BIT_GINV UINT32_C(20)
#define CDISASM_MIPS_DECODE_FLAG_GINV (UINT64_C(1) << 20)
#define CDISASM_MIPS_DECODE_BIT_COP2 UINT32_C(21)
#define CDISASM_MIPS_DECODE_FLAG_COP2 (UINT64_C(1) << 21)
#define CDISASM_MIPS_DECODE_BIT_COP3 UINT32_C(22)
#define CDISASM_MIPS_DECODE_FLAG_COP3 (UINT64_C(1) << 22)
#define CDISASM_MIPS_DECODE_BIT_PAIRED_SINGLE UINT32_C(23)
#define CDISASM_MIPS_DECODE_FLAG_PAIRED_SINGLE (UINT64_C(1) << 23)
#define CDISASM_MIPS_DECODE_BIT_CNMIPS UINT32_C(24)
#define CDISASM_MIPS_DECODE_FLAG_CNMIPS (UINT64_C(1) << 24)
#define CDISASM_MIPS_DECODE_BIT_CNMIPSP UINT32_C(25)
#define CDISASM_MIPS_DECODE_FLAG_CNMIPSP (UINT64_C(1) << 25)
#define CDISASM_MIPS_DECODE_BIT_LOONGSON UINT32_C(26)
#define CDISASM_MIPS_DECODE_FLAG_LOONGSON (UINT64_C(1) << 26)
#define CDISASM_MIPS_DECODE_BIT_ALLEGREX UINT32_C(27)
#define CDISASM_MIPS_DECODE_FLAG_ALLEGREX (UINT64_C(1) << 27)
#define CDISASM_MIPS_DECODE_BIT_R5900 UINT32_C(28)
#define CDISASM_MIPS_DECODE_FLAG_R5900 (UINT64_C(1) << 28)
#define CDISASM_MIPS_DECODE_BIT_MXU UINT32_C(29)
#define CDISASM_MIPS_DECODE_FLAG_MXU (UINT64_C(1) << 29)
#define CDISASM_MIPS_DECODE_BIT_MIPS16E2 UINT32_C(30)
#define CDISASM_MIPS_DECODE_FLAG_MIPS16E2 (UINT64_C(1) << 30)
#define CDISASM_MIPS_DECODE_BIT_ISA_V UINT32_C(43)
#define CDISASM_MIPS_DECODE_FLAG_ISA_V (UINT64_C(1) << 43)
#define CDISASM_MIPS_DECODE_BIT_ISA_32R3 UINT32_C(44)
#define CDISASM_MIPS_DECODE_FLAG_ISA_32R3 (UINT64_C(1) << 44)
#define CDISASM_MIPS_DECODE_BIT_ISA_64R3 UINT32_C(45)
#define CDISASM_MIPS_DECODE_FLAG_ISA_64R3 (UINT64_C(1) << 45)
#define CDISASM_MIPS_DECODE_BIT_ISA_64R5 UINT32_C(46)
#define CDISASM_MIPS_DECODE_FLAG_ISA_64R5 (UINT64_C(1) << 46)

#define CDISASM_MIPS_DECODE_BIT_LOONGSON2E UINT32_C(47)
#define CDISASM_MIPS_DECODE_FLAG_LOONGSON2E (UINT64_C(1) << 47)
#define CDISASM_MIPS_DECODE_BIT_LOONGSON2F UINT32_C(48)
#define CDISASM_MIPS_DECODE_FLAG_LOONGSON2F (UINT64_C(1) << 48)
#define CDISASM_MIPS_DECODE_BIT_LOONGSON_EXT UINT32_C(49)
#define CDISASM_MIPS_DECODE_FLAG_LOONGSON_EXT (UINT64_C(1) << 49)
#define CDISASM_MIPS_DECODE_BIT_LOONGSON_EXT2 UINT32_C(50)
#define CDISASM_MIPS_DECODE_FLAG_LOONGSON_EXT2 (UINT64_C(1) << 50)
#define CDISASM_MIPS_DECODE_BIT_LOONGSON_CAM UINT32_C(51)
#define CDISASM_MIPS_DECODE_FLAG_LOONGSON_CAM (UINT64_C(1) << 51)
#define CDISASM_MIPS_DECODE_BIT_DSP64 UINT32_C(52)
#define CDISASM_MIPS_DECODE_FLAG_DSP64 (UINT64_C(1) << 52)
#define CDISASM_MIPS_DECODE_BIT_MXU2 UINT32_C(53)
#define CDISASM_MIPS_DECODE_FLAG_MXU2 (UINT64_C(1) << 53)
#define CDISASM_MIPS_DECODE_BIT_MXU3 UINT32_C(54)
#define CDISASM_MIPS_DECODE_FLAG_MXU3 (UINT64_C(1) << 54)
#define CDISASM_MIPS_DECODE_BIT_LOONGSIMD UINT32_C(55)
#define CDISASM_MIPS_DECODE_FLAG_LOONGSIMD (UINT64_C(1) << 55)
#define CDISASM_MIPS_DECODE_BIT_R5900_VU0 UINT32_C(56)
#define CDISASM_MIPS_DECODE_FLAG_R5900_VU0 (UINT64_C(1) << 56)
#define CDISASM_MIPS_DECODE_BIT_R5900_VU1 UINT32_C(57)
#define CDISASM_MIPS_DECODE_FLAG_R5900_VU1 (UINT64_C(1) << 57)
#define CDISASM_MIPS_DECODE_BIT_VU_UPPER UINT32_C(58)
#define CDISASM_MIPS_DECODE_FLAG_VU_UPPER (UINT64_C(1) << 58)
#define CDISASM_MIPS_DECODE_BIT_VU_LOWER UINT32_C(59)
#define CDISASM_MIPS_DECODE_FLAG_VU_LOWER (UINT64_C(1) << 59)
#define CDISASM_MIPS_DECODE_BIT_VU_LOWER_LOI UINT32_C(60)
#define CDISASM_MIPS_DECODE_FLAG_VU_LOWER_LOI (UINT64_C(1) << 60)
#define CDISASM_MIPS_DECODE_BIT_MXU3_1 UINT32_C(61)
#define CDISASM_MIPS_DECODE_FLAG_MXU3_1 (UINT64_C(1) << 61)
#define CDISASM_MIPS_DECODE_BIT_LOONGASX UINT32_C(31)
#define CDISASM_MIPS_DECODE_FLAG_LOONGASX (UINT64_C(1) << 31)
#define CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK (UINT64_C(0x1f80007fffc1fe) | CDISASM_MIPS_DECODE_FLAG_MXU2 | CDISASM_MIPS_DECODE_FLAG_MXU3 | CDISASM_MIPS_DECODE_FLAG_LOONGSIMD | CDISASM_MIPS_DECODE_FLAG_R5900_VU0 | CDISASM_MIPS_DECODE_FLAG_R5900_VU1 | CDISASM_MIPS_DECODE_FLAG_MXU3_1 | CDISASM_MIPS_DECODE_FLAG_LOONGASX)
#define CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK (UINT64_C(0xe00) | CDISASM_MIPS_DECODE_FLAG_VU_UPPER | CDISASM_MIPS_DECODE_FLAG_VU_LOWER | CDISASM_MIPS_DECODE_FLAG_VU_LOWER_LOI)
#define CDISASM_MIPS_DECODE_FLAG_ISA_MASK UINT64_C(0x7fff00000000)
#define CDISASM_MIPS_DECODE_FLAG_KNOWN_MASK_0 (CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN | CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK | CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK | CDISASM_MIPS_DECODE_FLAG_FPR32 | CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES | CDISASM_MIPS_DECODE_FLAG_ISA_MASK)
#define CDISASM_MIPS_DECODE_FLAGS_INITIALIZER(bitmap0_) CDISASM_DECODE_FLAGS_INITIALIZER(bitmap0_)
#define CDISASM_MIPS_DECODE_FLAGS_NONE_INITIALIZER CDISASM_MIPS_DECODE_FLAGS_INITIALIZER(UINT64_C(0))

/* Decode flags bitmap 0: BE changes byte order; ISA_* bits select exactly one
 * revision for ANY and may only repeat the fixed revision of a named CPU.
 * NULL/all-zero uses a named CPU's supported families and little-endian input.
 * Any feature bit, or EXPLICIT_FAMILIES alone, selects an exact family subset.
 * DSPR2 requires DSP; MSA requires FPU. Nonzero words 1..7 are invalid.
 * MIPS16/microMIPS/nanoMIPS requests return UNSUPPORTED_INSTRUCTION; this
 * backend currently decodes only standard fixed-width four-byte instructions.
 * Optional hardware is represented by separate named profiles: 24KF/5KF
 * include an FPU; unsuffixed P/I profiles exclude optional FPU/MSA units.
 * FPR32 selects paired 32-bit floating-point registers independently of GPR
 * mode. MIPS I/II and MIPS32 Release 1 inherently use FPR32; other ISAs
 * default to 64-bit FPRs. Release 6 rejects FPR32: paired FR=0 and FRE
 * emulation are not supported. An active MSA family also requires FR=1. */

typedef uint16_t cdisasm_mips_family_id;
typedef uint64_t cdisasm_mips_family_mask;
#define CDISASM_MIPS_FAMILY_NONE UINT16_C(0)
#define CDISASM_MIPS_FAMILY_MASK_NONE UINT64_C(0)
#define CDISASM_MIPS_FAMILY_FPU UINT16_C(1)
#define CDISASM_MIPS_FAMILY_MASK_FPU (UINT64_C(1) << 0)
#define CDISASM_MIPS_FAMILY_DSP UINT16_C(2)
#define CDISASM_MIPS_FAMILY_MASK_DSP (UINT64_C(1) << 1)
#define CDISASM_MIPS_FAMILY_DSPR2 UINT16_C(3)
#define CDISASM_MIPS_FAMILY_MASK_DSPR2 (UINT64_C(1) << 2)
#define CDISASM_MIPS_FAMILY_MT UINT16_C(4)
#define CDISASM_MIPS_FAMILY_MASK_MT (UINT64_C(1) << 3)
#define CDISASM_MIPS_FAMILY_MSA UINT16_C(5)
#define CDISASM_MIPS_FAMILY_MASK_MSA (UINT64_C(1) << 4)
#define CDISASM_MIPS_FAMILY_VZ UINT16_C(6)
#define CDISASM_MIPS_FAMILY_MASK_VZ (UINT64_C(1) << 5)
#define CDISASM_MIPS_FAMILY_EVA UINT16_C(7)
#define CDISASM_MIPS_FAMILY_MASK_EVA (UINT64_C(1) << 6)
#define CDISASM_MIPS_FAMILY_XPA UINT16_C(8)
#define CDISASM_MIPS_FAMILY_MASK_XPA (UINT64_C(1) << 7)
#define CDISASM_MIPS_FAMILY_DSPR3 UINT16_C(9)
#define CDISASM_MIPS_FAMILY_MASK_DSPR3 (UINT64_C(1) << 8)
#define CDISASM_MIPS_FAMILY_MIPS3D UINT16_C(10)
#define CDISASM_MIPS_FAMILY_MASK_MIPS3D (UINT64_C(1) << 9)
#define CDISASM_MIPS_FAMILY_MDMX UINT16_C(11)
#define CDISASM_MIPS_FAMILY_MASK_MDMX (UINT64_C(1) << 10)
#define CDISASM_MIPS_FAMILY_SMARTMIPS UINT16_C(12)
#define CDISASM_MIPS_FAMILY_MASK_SMARTMIPS (UINT64_C(1) << 11)
#define CDISASM_MIPS_FAMILY_MCU UINT16_C(13)
#define CDISASM_MIPS_FAMILY_MASK_MCU (UINT64_C(1) << 12)
#define CDISASM_MIPS_FAMILY_CRC UINT16_C(14)
#define CDISASM_MIPS_FAMILY_MASK_CRC (UINT64_C(1) << 13)
#define CDISASM_MIPS_FAMILY_GINV UINT16_C(15)
#define CDISASM_MIPS_FAMILY_MASK_GINV (UINT64_C(1) << 14)
#define CDISASM_MIPS_FAMILY_COP2 UINT16_C(16)
#define CDISASM_MIPS_FAMILY_MASK_COP2 (UINT64_C(1) << 15)
#define CDISASM_MIPS_FAMILY_COP3 UINT16_C(17)
#define CDISASM_MIPS_FAMILY_MASK_COP3 (UINT64_C(1) << 16)
#define CDISASM_MIPS_FAMILY_PAIRED_SINGLE UINT16_C(18)
#define CDISASM_MIPS_FAMILY_MASK_PAIRED_SINGLE (UINT64_C(1) << 17)
#define CDISASM_MIPS_FAMILY_CNMIPS UINT16_C(19)
#define CDISASM_MIPS_FAMILY_MASK_CNMIPS (UINT64_C(1) << 18)
#define CDISASM_MIPS_FAMILY_CNMIPSP UINT16_C(20)
#define CDISASM_MIPS_FAMILY_MASK_CNMIPSP (UINT64_C(1) << 19)
#define CDISASM_MIPS_FAMILY_LOONGSON UINT16_C(21)
#define CDISASM_MIPS_FAMILY_MASK_LOONGSON (UINT64_C(1) << 20)
#define CDISASM_MIPS_FAMILY_ALLEGREX UINT16_C(22)
#define CDISASM_MIPS_FAMILY_MASK_ALLEGREX (UINT64_C(1) << 21)
#define CDISASM_MIPS_FAMILY_R5900 UINT16_C(23)
#define CDISASM_MIPS_FAMILY_MASK_R5900 (UINT64_C(1) << 22)
#define CDISASM_MIPS_FAMILY_MXU UINT16_C(24)
#define CDISASM_MIPS_FAMILY_MASK_MXU (UINT64_C(1) << 23)
#define CDISASM_MIPS_FAMILY_MIPS16E2 UINT16_C(25)
#define CDISASM_MIPS_FAMILY_MASK_MIPS16E2 (UINT64_C(1) << 24)
#define CDISASM_MIPS_FAMILY_FIRST CDISASM_MIPS_FAMILY_FPU
#define CDISASM_MIPS_FAMILY_LOONGSON2E UINT16_C(26)
#define CDISASM_MIPS_FAMILY_MASK_LOONGSON2E (UINT64_C(1) << 25)
#define CDISASM_MIPS_FAMILY_LOONGSON2F UINT16_C(27)
#define CDISASM_MIPS_FAMILY_MASK_LOONGSON2F (UINT64_C(1) << 26)
#define CDISASM_MIPS_FAMILY_LOONGSON_EXT UINT16_C(28)
#define CDISASM_MIPS_FAMILY_MASK_LOONGSON_EXT (UINT64_C(1) << 27)
#define CDISASM_MIPS_FAMILY_LOONGSON_EXT2 UINT16_C(29)
#define CDISASM_MIPS_FAMILY_MASK_LOONGSON_EXT2 (UINT64_C(1) << 28)
#define CDISASM_MIPS_FAMILY_LOONGSON_CAM UINT16_C(30)
#define CDISASM_MIPS_FAMILY_MASK_LOONGSON_CAM (UINT64_C(1) << 29)
#define CDISASM_MIPS_FAMILY_DSP64 UINT16_C(31)
#define CDISASM_MIPS_FAMILY_MASK_DSP64 (UINT64_C(1) << 30)
#define CDISASM_MIPS_FAMILY_MXU2 UINT16_C(32)
#define CDISASM_MIPS_FAMILY_MASK_MXU2 (UINT64_C(1) << 31)
#define CDISASM_MIPS_FAMILY_MXU3 UINT16_C(33)
#define CDISASM_MIPS_FAMILY_MASK_MXU3 (UINT64_C(1) << 32)
#define CDISASM_MIPS_FAMILY_LOONGSIMD UINT16_C(34)
#define CDISASM_MIPS_FAMILY_MASK_LOONGSIMD (UINT64_C(1) << 33)
#define CDISASM_MIPS_FAMILY_R5900_VU0 UINT16_C(35)
#define CDISASM_MIPS_FAMILY_MASK_R5900_VU0 (UINT64_C(1) << 34)
#define CDISASM_MIPS_FAMILY_R5900_VU1 UINT16_C(36)
#define CDISASM_MIPS_FAMILY_MASK_R5900_VU1 (UINT64_C(1) << 35)
#define CDISASM_MIPS_FAMILY_MXU3_1 UINT16_C(37)
#define CDISASM_MIPS_FAMILY_MASK_MXU3_1 (UINT64_C(1) << 36)
/* Bounded MIPS LASX context-operation subset; not LoongArch LASX. Requires
 * FPU/LOONGSON and FR=1. Explicit selection is required even on 3A4000. */
#define CDISASM_MIPS_FAMILY_LOONGASX UINT16_C(38)
#define CDISASM_MIPS_FAMILY_MASK_LOONGASX (UINT64_C(1) << 37)
#define CDISASM_MIPS_FAMILY_LAST CDISASM_MIPS_FAMILY_LOONGASX
#define CDISASM_MIPS_FAMILY_MASK_ALL UINT64_C(0x3fffffffff)

typedef struct cdisasm_mips_family_descriptor {
    cdisasm_mips_family_id family_id;
    uint16_t reserved;
    cdisasm_mips_mode_mask allowed_modes;
    uint64_t required_flags;
} cdisasm_mips_family_descriptor;

typedef uint16_t cdisasm_mips_form_id;
#define CDISASM_MIPS_FORM_NONE UINT16_C(0)
/* Native canonical forms use their stable mnemonic ID. Assembly aliases can
 * retain the underlying canonical ID (for example NOP retains SLL).
 * Release 6 reassignments use R6_BASE + the canonical mnemonic ID; the range
 * reserves room for future append-only names without changing existing forms.
 * Exact generated DSP rows occupy an independently append-only range. */
#define CDISASM_MIPS_FORM_NATIVE_FIRST UINT16_C(1)
#define CDISASM_MIPS_FORM_NATIVE_LAST CDISASM_MIPS_NAME_LAST
#define CDISASM_MIPS_FORM_R6_BASE UINT16_C(4096)
#define CDISASM_MIPS_FORM_R6_FIRST UINT16_C(4097)
#define CDISASM_MIPS_FORM_R6_LAST (CDISASM_MIPS_FORM_R6_BASE + CDISASM_MIPS_NAME_LAST)
#define CDISASM_MIPS_FORM_DSP_FIRST UINT16_C(16385)
#define CDISASM_MIPS_FORM_DSP_LAST UINT16_C(18173)

#define CDISASM_MIPS_OPERAND_FLAG_SIGNED CDISASM_OPERAND_FLAG_SIGNED
#define CDISASM_MIPS_OPERAND_FLAG_RELATIVE CDISASM_OPERAND_FLAG_PC_RELATIVE
#define CDISASM_MIPS_OPERAND_FLAG_PC_RELATIVE CDISASM_OPERAND_FLAG_PC_RELATIVE
#define CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS CDISASM_OPERAND_FLAG_HAS_ADDRESS
#define CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE CDISASM_OPERAND_FLAG_ABSOLUTE
#define CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
/* A remote thread register. MT instruction u/sel/h fields in the subsequent
 * immediate operands determine the remote register bank and half selector. */
#define CDISASM_MIPS_OPERAND_FLAG_THREAD_REGISTER (UINT8_C(1) << 7)

/* The instruction has a following architectural delay slot; this does not
 * assert that the current instruction resides in another branch's delay slot. */
#define CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT (UINT32_C(1) << 0)
/* The delay slot is annulled when this branch is not taken. */
#define CDISASM_MIPS_INSTRUCTION_FLAG_BRANCH_LIKELY (UINT32_C(1) << 1)
#define CDISASM_MIPS_INSTRUCTION_FLAG_COMPACT_BRANCH (UINT32_C(1) << 2)
#define CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT (UINT32_C(1) << 3)
#define CDISASM_MIPS_INSTRUCTION_FLAG_DSP (UINT32_C(1) << 4)
#define CDISASM_MIPS_INSTRUCTION_FLAG_MT (UINT32_C(1) << 5)
#define CDISASM_MIPS_INSTRUCTION_FLAG_MSA (UINT32_C(1) << 6)
#define CDISASM_MIPS_INSTRUCTION_FLAG_FPR32 (UINT32_C(1) << 7)
#define CDISASM_MIPS_INSTRUCTION_FLAG_READS_HI (UINT32_C(1) << 8)
#define CDISASM_MIPS_INSTRUCTION_FLAG_READS_LO (UINT32_C(1) << 9)
#define CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_HI (UINT32_C(1) << 10)
#define CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_LO (UINT32_C(1) << 11)
/* Writes the implicit return-address GPR31; explicit JALR destinations remain
 * ordinary operand records instead. */
#define CDISASM_MIPS_INSTRUCTION_FLAG_LINK (UINT32_C(1) << 12)
#define CDISASM_MIPS_INSTRUCTION_FLAG_READS_DSPCONTROL (UINT32_C(1) << 13)
#define CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_DSPCONTROL (UINT32_C(1) << 14)

#define CDISASM_MIPS_INSTRUCTION_FLAG_DSPR2 (UINT32_C(1) << 15)
#define CDISASM_MIPS_INSTRUCTION_FLAG_DSPR3 (UINT32_C(1) << 16)
#define CDISASM_MIPS_INSTRUCTION_FLAG_MIPS3D (UINT32_C(1) << 17)
#define CDISASM_MIPS_INSTRUCTION_FLAG_VZ (UINT32_C(1) << 18)
#define CDISASM_MIPS_INSTRUCTION_FLAG_EVA (UINT32_C(1) << 19)
#define CDISASM_MIPS_INSTRUCTION_FLAG_XPA (UINT32_C(1) << 20)
#define CDISASM_MIPS_INSTRUCTION_FLAG_COP2 (UINT32_C(1) << 21)
#define CDISASM_MIPS_INSTRUCTION_FLAG_COP3 (UINT32_C(1) << 22)
#define CDISASM_MIPS_INSTRUCTION_FLAG_MDMX (UINT32_C(1) << 23)
#define CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR (UINT32_C(1) << 24)
#define CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_FCSR (UINT32_C(1) << 25)
#define CDISASM_MIPS_INSTRUCTION_FLAG_READS_MSACSR (UINT32_C(1) << 26)
#define CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_MSACSR (UINT32_C(1) << 27)
#define CDISASM_MIPS_INSTRUCTION_FLAG_ATOMIC (UINT32_C(1) << 28)
#define CDISASM_MIPS_INSTRUCTION_FLAG_MEMORY_BARRIER (UINT32_C(1) << 29)
#define CDISASM_MIPS_INSTRUCTION_FLAG_BARRIER CDISASM_MIPS_INSTRUCTION_FLAG_MEMORY_BARRIER
#define CDISASM_MIPS_INSTRUCTION_FLAG_PAIRED_SINGLE (UINT32_C(1) << 30)
#define CDISASM_MIPS_INSTRUCTION_FLAG_ISA_EXCHANGE (UINT32_C(1) << 31)
#define CDISASM_MIPS_INSTRUCTION_FLAG_READS_DSP_CONTROL CDISASM_MIPS_INSTRUCTION_FLAG_READS_DSPCONTROL
#define CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_DSP_CONTROL CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_DSPCONTROL

#define CDISASM_MIPS_OPERAND_DETAIL_HAS_LANE UINT8_C(1)
#define CDISASM_MIPS_OPERAND_DETAIL_REGISTER_LIST UINT8_C(2)
#define CDISASM_MIPS_OPERAND_DETAIL_INDEX_SCALED UINT8_C(4)
#define CDISASM_MIPS_OPERAND_DETAIL_HIGH_HALF UINT8_C(8)
#define CDISASM_MIPS_OPERAND_DETAIL_ACC_EXTENSION UINT8_C(16)
#define CDISASM_MIPS_OPERAND_DETAIL_REGISTER_SELECTOR UINT8_C(32)
#define CDISASM_MIPS_OPERAND_DETAIL_LANE_REGISTER UINT8_C(64)
#define CDISASM_MIPS_OPERAND_DETAIL_BARE_BASE UINT8_C(128)
/* Register-only interpretation: XYZW mask in lane_index, element_size=4.
 * The same bit means BARE_BASE only on memory operands. */
#define CDISASM_MIPS_OPERAND_DETAIL_COMPONENT_MASK UINT8_C(128)

/* Assembly-order numeric operands. size is bytes. A memory imm is the signed
 * displacement bit pattern; a PC-relative immediate stores its resolved target
 * in imm and displacement in address. Unused fields and records are zero.
 * In FPR32 mode, an eight-byte FPR operand denotes an even-odd register pair.
 * CP0 reg IDs include select, avoiding dependence on register text aliases. */
typedef struct cdisasm_mips_operand {
    uint64_t address;
    uint64_t imm;
    cdisasm_mips_reg_id reg;
    cdisasm_mips_reg_id base_reg;
    cdisasm_mips_reg_id index_reg;
    uint8_t type;
    uint8_t size;
    cdisasm_operand_access access;
    uint8_t flags;
    /* Version 12.2 operand details occupy the existing six-byte extension
     * storage. Layout and previously published instruction values are stable.
     * reserved[] remains a source-compatible storage alias. Unused detail
     * fields are zero. On VU scaled local-memory operands the low four bits
     * of component_mask (source-compatible alias reserved) hold XYZW lanes. */
    union {
        uint8_t reserved[6];
        struct {
            uint8_t lane_index;
            uint8_t element_size;
            uint8_t flags;
            uint8_t index_shift;
            union {
                uint16_t reserved;
                uint16_t component_mask;
            };
        } detail;
    };
} cdisasm_mips_operand;

typedef struct cdisasm_mips_instruction {
    uint64_t address;
    uint64_t branch_target;
    uint32_t opcode_size;
    uint32_t opcode_groups;
    uint32_t raw_instruction;
    uint32_t instruction_flags;
    cdisasm_mips_name_id name_id;
    cdisasm_mips_form_id form_id;
    uint8_t revision;
    uint8_t last_error_id;
    uint8_t operand_count;
    uint8_t mode;
    cdisasm_mips_operand operand[CDISASM_MIPS_MAX_OPERANDS];
} cdisasm_mips_instruction;

/* One register resource effect. selector is meaningful only with the
 * REGISTER_SELECTOR detail flag; lane/mask information remains in operands.
 * Queries merge duplicate resources and never allocate caller storage. */
typedef struct cdisasm_mips_register_effect {
    cdisasm_mips_reg_id reg;
    cdisasm_operand_access access;
    uint8_t flags;
    uint16_t size;
    uint16_t reserved;
    uint64_t selector;
} cdisasm_mips_register_effect;

/* Caller-owned reusable policy, with no mutable stream/host state. flags holds
 * a supported explicit family selection; family_value further restricts it.
 * Neither accepted option masks nor BE are enabled implicitly by initialization. */
typedef struct cdisasm_mips_decode_context {
    cdisasm_mips_cpu_id cpu_id;
    cdisasm_mips_mode mode;
    cdisasm_mips_revision revision;
    uint32_t reserved;
    cdisasm_mips_decode_flags flags;
    cdisasm_mips_family_mask family_mask;
    cdisasm_mips_family_mask family_value;
} cdisasm_mips_decode_context;

/* Source encoding descriptions are separate from decoded instructions. These
 * describe the original 61 unusual Allegrex patterns, including source-defined
 * syntax and patterns whose architectural operands or legality remain unknown.
 * A candidate name/form is an inventory identity, never a successful decode.
 * Field slices preserve encoded bits; they are not register/effect records. */
#define CDISASM_MIPS_PATTERN_MAX_FIELDS 6u
#define CDISASM_MIPS_PATTERN_OBSERVED_SYNTAX 1u
#define CDISASM_MIPS_PATTERN_UNVERIFIED_WIDTH 2u
#define CDISASM_MIPS_PATTERN_UNVERIFIED_LOAD_OPTION 3u
#define CDISASM_MIPS_PATTERN_SOURCE_SYNTAX 4u
#define CDISASM_MIPS_PATTERN_SCHEMA_DISAGREEMENT 1u
#define CDISASM_MIPS_PATTERN_PARTIAL_ALIAS 2u
#define CDISASM_MIPS_PATTERN_SOURCE_SUPPORTED 4u
#define CDISASM_MIPS_PATTERN_FIELD_VD 1u
#define CDISASM_MIPS_PATTERN_FIELD_VS 2u
#define CDISASM_MIPS_PATTERN_FIELD_VT 3u
#define CDISASM_MIPS_PATTERN_FIELD_BASE 4u
#define CDISASM_MIPS_PATTERN_FIELD_DISPLACEMENT 5u
#define CDISASM_MIPS_PATTERN_FIELD_IMMEDIATE 6u
#define CDISASM_MIPS_PATTERN_FIELD_CACHE 7u
#define CDISASM_MIPS_PATTERN_FIELD_VT_HIGH 8u
#define CDISASM_MIPS_PATTERN_FIELD_RAW 9u

typedef struct cdisasm_mips_encoding_field {
    uint8_t kind, lsb, bits, scale;
} cdisasm_mips_encoding_field;

typedef struct cdisasm_mips_encoding_pattern {
    uint32_t mask, value;
    uint16_t inventory_index;
    cdisasm_mips_form_id candidate_form_id;
    cdisasm_mips_name_id candidate_name_id;
    uint8_t status, vector_width, field_count, flags;
    cdisasm_mips_encoding_field field[CDISASM_MIPS_PATTERN_MAX_FIELDS];
    uint32_t partial_alias_word;
    cdisasm_mips_form_id partial_alias_form_id;
    cdisasm_mips_name_id partial_alias_name_id;
} cdisasm_mips_encoding_pattern;

#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(cdisasm_mips_operand) == CDISASM_MIPS_OPERAND_SIZE, "unexpected MIPS operand ABI size");
static_assert(offsetof(cdisasm_mips_instruction, operand) == 40, "unexpected MIPS operand ABI offset");
static_assert(sizeof(cdisasm_mips_instruction) == CDISASM_MIPS_INSTRUCTION_SIZE, "unexpected MIPS instruction ABI size");
static_assert(sizeof(cdisasm_mips_decode_context) == CDISASM_MIPS_DECODE_CONTEXT_SIZE, "unexpected MIPS context ABI size");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(cdisasm_mips_operand) == CDISASM_MIPS_OPERAND_SIZE, "unexpected MIPS operand ABI size");
_Static_assert(offsetof(cdisasm_mips_instruction, operand) == 40, "unexpected MIPS operand ABI offset");
_Static_assert(sizeof(cdisasm_mips_instruction) == CDISASM_MIPS_INSTRUCTION_SIZE, "unexpected MIPS instruction ABI size");
_Static_assert(sizeof(cdisasm_mips_decode_context) == CDISASM_MIPS_DECODE_CONTEXT_SIZE, "unexpected MIPS context ABI size");
#endif

#ifdef __cplusplus
extern "C" {
#endif

CDISASM_MIPS_API cdisasm_mips_mode_mask CDISASM_CALL cdisasm_mips_cpu_mode_mask(cdisasm_mips_cpu_id cpu_id);
CDISASM_MIPS_API cdisasm_mips_mode_mask CDISASM_CALL cdisasm_mips_decoder_mode_mask(cdisasm_mips_cpu_id cpu_id);
CDISASM_MIPS_API cdisasm_mips_revision CDISASM_CALL cdisasm_mips_cpu_revision(cdisasm_mips_cpu_id cpu_id);
/* Accepted options, not default selections. Includes BE and ISA selectors, but
 * never implies that alternate instruction encodings are implemented. */
CDISASM_MIPS_API cdisasm_status CDISASM_CALL cdisasm_mips_cpu_decode_flag_mask(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode, cdisasm_mips_decode_flags *flags);
/* Intersection of CPU capabilities and implemented family slices in this build.
 * A set family bit does not claim exhaustive coverage of every encoding. ANY
 * reports the union across revisions; a context narrows it to its exact ISA.
 * The handwritten FPU slice is always present. Generated ASE/vendor slices,
 * including DSP, MT, MSA, VZ, EVA and XPA, require USE_EXTRA_OPCODES. */
CDISASM_MIPS_API cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_cpu_family_mask(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode);
CDISASM_MIPS_API const cdisasm_mips_family_descriptor *CDISASM_CALL cdisasm_mips_family_descriptor_get(cdisasm_mips_family_id family_id);
/* Project explicitly set family flags into FAMILY_MASK_* bits. ISA, encoding,
 * byte-order and FPR-layout selectors do not become families. Capability masks
 * may include mutually exclusive alternatives; this query does not select a
 * CPU/revision or add dependencies. NULL, unknown bits or nonzero upper bitmap
 * words return FAMILY_MASK_NONE. */
CDISASM_MIPS_API cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_family_mask_from_flags(const cdisasm_mips_decode_flags *flags);
/* Validated instruction requirements, including selectable dependencies.
 * Processor replay policy is excluded: MSA on 3A4000 reports FPU|MSA.
 * The singular query returns the most specific direct family; independent
 * ties use the highest stable family ID, with MIPS3D before paired-single.
 * Base instructions, NULL, failed or forged results return FAMILY_NONE or
 * FAMILY_MASK_NONE. */
CDISASM_MIPS_API cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_instruction_family_mask(const cdisasm_mips_instruction *instruction);
CDISASM_MIPS_API cdisasm_mips_family_id CDISASM_CALL cdisasm_mips_instruction_family(const cdisasm_mips_instruction *instruction);
/* ANY requires a nonzero revision argument; a named CPU permits NONE or its
 * own exact revision. Context flags include the resolved ISA selector. */
CDISASM_MIPS_API cdisasm_status CDISASM_CALL cdisasm_mips_cpu_decode_context(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode, cdisasm_mips_revision revision, cdisasm_mips_decode_context *context);
CDISASM_MIPS_API int CDISASM_CALL cdisasm_mips_decode_context_add_family(cdisasm_mips_decode_context *context, cdisasm_mips_family_id family_id);
CDISASM_MIPS_API int CDISASM_CALL cdisasm_mips_decode_context_remove_family(cdisasm_mips_decode_context *context, cdisasm_mips_family_id family_id);
CDISASM_MIPS_API cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_decode_context_get_available_families(const cdisasm_mips_decode_context *context);
CDISASM_MIPS_API cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_decode_context_get_set_families(const cdisasm_mips_decode_context *context);
/* Returns four bytes on success, zero on failure. Non-NULL results are always
 * initialized; failures contain only last_error_id and zero in every other byte.
 * CPU-unavailable encodings are INVALID; caller-disabled families or currently
 * unimplemented instruction families are UNSUPPORTED. No ISA-completeness claim. */
CDISASM_MIPS_API uint32_t CDISASM_CALL cdisasm_mips_decode(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode, const uint8_t *code, size_t code_size, uint64_t address, const cdisasm_mips_decode_flags *flags, cdisasm_mips_instruction *instruction);
CDISASM_MIPS_API uint32_t CDISASM_CALL cdisasm_mips_decode_with_context(const cdisasm_mips_decode_context *context, const uint8_t *code, size_t code_size, uint64_t address, cdisasm_mips_instruction *instruction);
/* Returns total required effect records; capacity zero is a size query.
 * A valid instruction with no register effects returns zero as well. */
CDISASM_MIPS_API size_t CDISASM_CALL cdisasm_mips_register_effects(const cdisasm_mips_instruction *instruction, cdisasm_mips_register_effect *effects, size_t capacity);
/* Immutable catalog pointers live for the lifetime of the library. get uses a
 * zero-based catalog position; inventory_index is the stable source identity.
 * find accepts a normalized word, independent of host/input byte order or CPU.
 * It makes no CPU-support or execution-legality claim. Optional catalog data
 * requires USE_EXTRA_OPCODES; base builds return count zero and NULL pointers.
 * field_value accepts only a pointer returned by this library, sign extends
 * displacement fields and applies scale, clearing *value on every failure. */
CDISASM_MIPS_API size_t CDISASM_CALL cdisasm_mips_allegrex_pattern_count(void);
CDISASM_MIPS_API const cdisasm_mips_encoding_pattern *CDISASM_CALL cdisasm_mips_allegrex_pattern_get(size_t index);
CDISASM_MIPS_API const cdisasm_mips_encoding_pattern *CDISASM_CALL cdisasm_mips_allegrex_pattern_find(uint32_t word);
CDISASM_MIPS_API cdisasm_status CDISASM_CALL cdisasm_mips_allegrex_pattern_field_value(const cdisasm_mips_encoding_pattern *pattern, uint32_t word, size_t field_index, int64_t *value);
/* Numeric register syntax initially; no multi-instruction pseudo-operations.
 * flags uses the shared FORMAT_* contract. Returns required size excluding NUL;
 * size zero queries length, nonempty buffers are always NUL-terminated. */
#if USE_DISASM_FORMAT
CDISASM_MIPS_API size_t CDISASM_CALL cdisasm_mips_format(const cdisasm_mips_instruction *instruction, uint32_t flags, char *buffer, size_t buffer_size);
/* Formats a .word directive with candidate name, encoded fields and confidence;
 * never formats an unverified pattern as a valid typed instruction. The same
 * size-query, truncation and format-flag contract as format applies. */
CDISASM_MIPS_API size_t CDISASM_CALL cdisasm_mips_allegrex_pattern_format(uint32_t word, uint32_t flags, char *buffer, size_t buffer_size);
#endif

#ifdef __cplusplus
}
#endif
#endif
