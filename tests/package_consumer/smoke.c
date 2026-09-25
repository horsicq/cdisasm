#include <cdisasm/cdisasm.h>

#if USE_ARCH_X86
#  include <cdisasm/cdisasm_ids.h>
#endif

#if USE_DISASM_FORMAT && (USE_ARCH_X86 || USE_ARCH_ARM)
#  include <cdisasm/cdisasm_format.h>
#  include <string.h>
#endif

#if !defined(USE_ARCH_X86) || !defined(USE_ARCH_ARM) \
    || !defined(USE_DISASM_FORMAT) || !defined(USE_EXTRA_OPCODES)
#  error "installed cdisasm package does not expose feature defines"
#endif
#if USE_ARCH_X86 != CDISASM_PACKAGE_EXPECT_X86
#  error "installed x86 architecture define and exported targets disagree"
#endif
#if USE_ARCH_ARM != CDISASM_PACKAGE_EXPECT_ARM
#  error "installed ARM architecture define and exported targets disagree"
#endif
#if USE_DISASM_FORMAT != CDISASM_PACKAGE_EXPECT_FORMAT
#  error "installed formatter define and exported targets disagree"
#endif
#if USE_EXTRA_OPCODES != CDISASM_PACKAGE_EXPECT_EXTRA
#  error "installed extra-opcode define and package metadata disagree"
#endif
#if CDISASM_PACKAGE_EXPECT_SHARED
#  if defined(CDISASM_STATIC)
#    error "shared cdisasm package unexpectedly defines CDISASM_STATIC"
#  endif
#elif !defined(CDISASM_STATIC)
#  error "static cdisasm package does not define CDISASM_STATIC"
#endif

#if CDISASM_CPU_UNKNOWN != UINT32_C(0) \
    || CDISASM_CPU_GROUP_X86 != UINT32_C(0x00010000) \
    || CDISASM_CPU_GROUP_ARM != UINT32_C(0x00020000)
#  error "installed cdisasm package has unexpected CPU group IDs"
#endif

#if USE_DISASM_FORMAT && (USE_ARCH_X86 || USE_ARCH_ARM)
#  if CDISASM_FORMAT_SYNTAX_MASK != UINT32_C(0x07) \
      || CDISASM_FORMAT_SYNTAX_0 != UINT32_C(0x00) \
      || CDISASM_FORMAT_SYNTAX_1 != UINT32_C(0x01) \
      || CDISASM_FORMAT_SYNTAX_2 != UINT32_C(0x02) \
      || CDISASM_FORMAT_SYNTAX_3 != UINT32_C(0x03) \
      || CDISASM_FORMAT_SYNTAX_4 != UINT32_C(0x04) \
      || CDISASM_FORMAT_SYNTAX_5 != UINT32_C(0x05) \
      || CDISASM_FORMAT_SYNTAX_6 != UINT32_C(0x06) \
      || CDISASM_FORMAT_SYNTAX_7 != UINT32_C(0x07) \
      || CDISASM_FORMAT_SYNTAX_INTEL != CDISASM_FORMAT_SYNTAX_0 \
      || CDISASM_FORMAT_SYNTAX_ATT != CDISASM_FORMAT_SYNTAX_1 \
      || CDISASM_FORMAT_UPPERCASE_OPCODE != UINT32_C(0x08) \
      || CDISASM_FORMAT_KNOWN_FLAGS_MASK != UINT32_C(0x0f)
#    error "installed cdisasm package has unexpected formatter flags"
#  endif
#endif

#if USE_ARCH_X86
#if CDISASM_X86_MODE_MASK_NONE != UINT32_C(0x00) \
    || CDISASM_X86_MODE_MASK_16 != UINT32_C(0x01) \
    || CDISASM_X86_MODE_MASK_32 != UINT32_C(0x02) \
    || CDISASM_X86_MODE_MASK_64 != UINT32_C(0x04)
#  error "installed cdisasm package has unexpected x86 mode-mask values"
#endif
#if CDISASM_X86_DECODE_FLAG_BASE != UINT64_C(0x00000000) \
    || CDISASM_X86_DECODE_FLAG_FPU != UINT64_C(0x00000001) \
    || CDISASM_X86_DECODE_FLAG_MMX != UINT64_C(0x00000002) \
    || CDISASM_X86_DECODE_FLAG_3DNOW != UINT64_C(0x00000004) \
    || CDISASM_X86_DECODE_FLAG_SSE != UINT64_C(0x00000008) \
    || CDISASM_X86_DECODE_FLAG_SSE2 != UINT64_C(0x00000010) \
    || CDISASM_X86_DECODE_FLAG_SSE3 != UINT64_C(0x00000020) \
    || CDISASM_X86_DECODE_FLAG_SSSE3 != UINT64_C(0x00000040) \
    || CDISASM_X86_DECODE_FLAG_SSE4 != UINT64_C(0x00000080) \
    || CDISASM_X86_DECODE_FLAG_AVX != UINT64_C(0x00000100) \
    || CDISASM_X86_DECODE_FLAG_AVX2 != UINT64_C(0x00000200) \
    || CDISASM_X86_DECODE_FLAG_F16C != UINT64_C(0x00000400) \
    || CDISASM_X86_DECODE_FLAG_FMA3 != UINT64_C(0x00000800) \
    || CDISASM_X86_DECODE_FLAG_XOP != UINT64_C(0x00001000) \
    || CDISASM_X86_DECODE_FLAG_FMA4 != UINT64_C(0x00002000) \
    || CDISASM_X86_DECODE_FLAG_AES != UINT64_C(0x00004000) \
    || CDISASM_X86_DECODE_FLAG_PCLMUL != UINT64_C(0x00008000) \
    || CDISASM_X86_DECODE_FLAG_SHA != UINT64_C(0x00010000) \
    || CDISASM_X86_DECODE_FLAG_GFNI != UINT64_C(0x00020000) \
    || CDISASM_X86_DECODE_FLAG_BITMANIP != UINT64_C(0x00040000) \
    || CDISASM_X86_DECODE_FLAG_AVX512 != UINT64_C(0x00080000) \
    || CDISASM_X86_DECODE_FLAG_AVX10 != UINT64_C(0x00100000) \
    || CDISASM_X86_DECODE_FLAG_AMX != UINT64_C(0x00200000) \
    || CDISASM_X86_DECODE_FLAG_APX != UINT64_C(0x00400000) \
    || CDISASM_X86_DECODE_FLAG_SMX != UINT64_C(0x00800000) \
    || CDISASM_X86_DECODE_FLAG_VIRTUALIZATION \
        != CDISASM_X86_DECODE_FLAG_SMX \
    || CDISASM_X86_DECODE_FLAG_SYSTEM != UINT64_C(0x01000000) \
    || CDISASM_X86_DECODE_FLAG_CET != UINT64_C(0x02000000) \
    || CDISASM_X86_DECODE_FLAG_STATE != UINT64_C(0x04000000) \
    || CDISASM_X86_DECODE_FLAG_TRANSACTIONAL != UINT64_C(0x08000000) \
    || CDISASM_X86_DECODE_FLAG_SECURITY != UINT64_C(0x10000000) \
    || CDISASM_X86_DECODE_FLAG_MEMORY_HINTS != UINT64_C(0x20000000) \
    || CDISASM_X86_DECODE_FLAG_UNDOCUMENTED != UINT64_C(0x40000000) \
    || CDISASM_X86_DECODE_FLAG_SM3 != UINT64_C(0x080000000) \
    || CDISASM_X86_DECODE_FLAG_SM4 != UINT64_C(0x100000000) \
    || CDISASM_X86_DECODE_FLAG_AVX512_VBMI2 != UINT64_C(0x200000000) \
    || CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ != UINT64_C(0x400000000) \
    || CDISASM_X86_DECODE_FLAG_AVX512_BITALG != UINT64_C(0x800000000) \
    || CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND != UINT64_C(0x1000000000) \
    || CDISASM_X86_DECODE_FLAG_AVX512_IFMA != UINT64_C(0x2000000000) \
    || CDISASM_X86_DECODE_FLAG_AVX512_VBMI != UINT64_C(0x4000000000) \
    || CDISASM_X86_DECODE_FLAG_AVX512_VNNI != UINT64_C(0x8000000000) \
    || CDISASM_X86_DECODE_FLAG_VAES != UINT64_C(0x10000000000) \
    || CDISASM_X86_DECODE_FLAG_VPCLMULQDQ != UINT64_C(0x20000000000) \
    || CDISASM_X86_DECODE_FLAG_SHA512 != UINT64_C(0x40000000000) \
    || CDISASM_X86_DECODE_FLAG_AMX_TILE != UINT64_C(0x80000000000) \
    || CDISASM_X86_DECODE_FLAG_AMX_INT8 != UINT64_C(0x100000000000) \
    || CDISASM_X86_DECODE_FLAG_AMX_BF16 != UINT64_C(0x200000000000) \
    || CDISASM_X86_DECODE_FLAG_AMX_FP16 != UINT64_C(0x400000000000) \
    || CDISASM_X86_DECODE_FLAG_AMX_COMPLEX != UINT64_C(0x800000000000) \
    || CDISASM_X86_DECODE_FLAG_AMX_FP8 != UINT64_C(0x1000000000000) \
    || CDISASM_X86_DECODE_FLAG_AMX_MOVRS != UINT64_C(0x2000000000000) \
    || CDISASM_X86_DECODE_FLAG_AMX_AVX512 != UINT64_C(0x4000000000000) \
    || CDISASM_X86_DECODE_FLAG_AVX512_DQ != UINT64_C(0x8000000000000) \
    || CDISASM_X86_DECODE_FLAG_AVX512_BW != UINT64_C(0x10000000000000) \
    || CDISASM_X86_DECODE_FLAG_VMX != UINT64_C(0x20000000000000) \
    || CDISASM_X86_DECODE_FLAG_SVM != UINT64_C(0x40000000000000) \
    || CDISASM_X86_DECODE_FLAG_INTEL_VIRTUALIZATION \
        != CDISASM_X86_DECODE_FLAG_VMX \
    || CDISASM_X86_DECODE_FLAG_AMD_VIRTUALIZATION \
        != CDISASM_X86_DECODE_FLAG_SVM \
    || CDISASM_X86_DECODE_FLAG_SSE41 != UINT64_C(0x80000000000000) \
    || CDISASM_X86_DECODE_FLAG_SSE42 != UINT64_C(0x100000000000000) \
    || CDISASM_X86_DECODE_FLAG_SSE4A != UINT64_C(0x200000000000000) \
    || CDISASM_X86_DECODE_FLAG_BMI1 != UINT64_C(0x400000000000000) \
    || CDISASM_X86_DECODE_FLAG_BMI2 != UINT64_C(0x800000000000000) \
    || CDISASM_X86_DECODE_FLAG_AVX512_CD \
        != UINT64_C(0x1000000000000000) \
    || CDISASM_X86_DECODE_FLAG_AVX_VNNI \
        != UINT64_C(0x2000000000000000) \
    || CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8 \
        != UINT64_C(0x4000000000000000) \
    || CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16 \
        != UINT64_C(0x8000000000000000) \
    || CDISASM_X86_DECODE_FLAG_ALL != UINT64_C(0xffffffffffffffff) \
    || CDISASM_X86_DECODE_FLAG_KNOWN_MASK \
        != UINT64_C(0xffffffffffffffff) \
    || CDISASM_X86_DECODE_OPTION_NONE != CDISASM_X86_DECODE_FLAG_BASE \
    || CDISASM_X86_DECODE_OPTION_ALL != CDISASM_X86_DECODE_FLAG_ALL \
    || CDISASM_X86_DECODE_USE_SMX != CDISASM_X86_DECODE_FLAG_SMX \
    || CDISASM_X86_DECODE_USE_VIRTUALIZATION \
        != CDISASM_X86_DECODE_FLAG_SMX \
    || CDISASM_X86_DECODE_USE_VMX != CDISASM_X86_DECODE_FLAG_VMX \
    || CDISASM_X86_DECODE_USE_SVM != CDISASM_X86_DECODE_FLAG_SVM \
    || CDISASM_X86_DECODE_USE_INTEL_VIRTUALIZATION \
        != CDISASM_X86_DECODE_FLAG_VMX \
    || CDISASM_X86_DECODE_USE_AMD_VIRTUALIZATION \
        != CDISASM_X86_DECODE_FLAG_SVM
#  error "installed cdisasm package has unexpected x86 decode-family flags"
#endif
#ifndef CDISASM_X86_NAME_MOV
#  error "installed cdisasm package does not expose x86 name-id definitions"
#endif
#if CDISASM_X86_NAME_MOV != 118
#  error "installed cdisasm package has an unexpected MOV name-id"
#endif
#ifndef CDISASM_X86_REG_RBP
#  error "installed cdisasm package does not expose x86 register-ID definitions"
#endif
#if CDISASM_X86_REG_RSP != 57 || CDISASM_X86_REG_RBP != 58 \
    || CDISASM_X86_REG_MM0 != 120 || CDISASM_X86_REG_ZMM31 != 223 \
    || CDISASM_X86_REG_R31 != 307 || CDISASM_X86_REG_BSR0 != 308 \
    || CDISASM_X86_REG_COUNT != 309
#  error "installed cdisasm package has unexpected register IDs"
#endif
#if CDISASM_X86_NAME_FEMMS != 241 || CDISASM_X86_NAME_PSWAPD != 267 \
    || CDISASM_X86_NAME_UD0 != 268 || CDISASM_X86_NAME_UD1 != 269 \
    || CDISASM_X86_NAME_VZEROALL != 270 \
    || CDISASM_X86_NAME_VZEROUPPER != 271 \
    || CDISASM_X86_NAME_CRC32 != 507 \
    || CDISASM_X86_NAME_EXTRQ != 508 \
    || CDISASM_X86_NAME_INSERTQ != 509 \
    || CDISASM_X86_NAME_F2XM1 != 510 \
    || CDISASM_X86_NAME_FYL2XP1 != 608 \
    || CDISASM_X86_NAME_FSTPNCE != 609 \
    || CDISASM_X86_NAME_VADDPS != 610 \
    || CDISASM_X86_NAME_VPSADBW != 669 \
    || CDISASM_X86_NAME_AESENC != 670 \
    || CDISASM_X86_NAME_POP2 != 732 \
    || CDISASM_X86_NAME_VPCLMULQDQ != 736 \
    || CDISASM_X86_NAME_RDRAND != 737 \
    || CDISASM_X86_NAME_XTEST != 742 \
    || CDISASM_X86_NAME_JMPABS != 803 \
    || CDISASM_X86_NAME_VFMADDSUBPS != 804 \
    || CDISASM_X86_NAME_VPSHAQ != 827 \
    || CDISASM_X86_NAME_CLRSSBSY != 828 \
    || CDISASM_X86_NAME_WRUSSQ != 839 \
    || CDISASM_X86_NAME_UMONITOR != 840 \
    || CDISASM_X86_NAME_UMWAIT != 841 \
    || CDISASM_X86_NAME_TPAUSE != 842 \
    || CDISASM_X86_NAME_VFRCZPS != 843 \
    || CDISASM_X86_NAME_VPHSUBDQ != 861 \
    || CDISASM_X86_NAME_VPMACSSWW != 862 \
    || CDISASM_X86_NAME_VPERMIL2PD != 884 \
    || CDISASM_X86_NAME_VSHA512MSG1 != 885 \
    || CDISASM_X86_NAME_VSM4RNDS4 != 892 \
    || CDISASM_X86_NAME_VADDSUBPD != 893 \
    || CDISASM_X86_NAME_VCVTSS2SD != 916 \
    || CDISASM_X86_NAME_CLFLUSH != 917 \
    || CDISASM_X86_NAME_WBNOINVD != 924 \
    || CDISASM_X86_NAME_TCMMIMFP16PS != 925 \
    || CDISASM_X86_NAME_VDIVBF16 != 942 \
    || CDISASM_X86_NAME_KXORW != 953 \
    || CDISASM_X86_NAME_KXORQ != 993 \
    || CDISASM_X86_NAME_VPCMPB != 994 \
    || CDISASM_X86_NAME_VPCMPUQ != 1001 \
    || CDISASM_X86_NAME_VPMAXUQ != 1013 \
    || CDISASM_X86_NAME_VPMADDUBSW != 1020 \
    || CDISASM_X86_NAME_VPADDSB != 1021 \
    || CDISASM_X86_NAME_VPSUBUSW != 1028 \
    || CDISASM_X86_NAME_VPANDD != 1029 \
    || CDISASM_X86_NAME_VPXORQ != 1036 \
    || CDISASM_X86_NAME_VPSLLVD != 1037 \
    || CDISASM_X86_NAME_VPSRAVQ != 1042 \
    || CDISASM_X86_NAME_VPSLLVW != 1043 \
    || CDISASM_X86_NAME_VPSRAVW != 1045 \
    || CDISASM_X86_NAME_VPROLVD != 1046 \
    || CDISASM_X86_NAME_VPRORVQ != 1049 \
    || CDISASM_X86_NAME_VPROLD != 1050 \
    || CDISASM_X86_NAME_VPRORQ != 1053 \
    || CDISASM_X86_NAME_VPSRLD != 1054 \
    || CDISASM_X86_NAME_VPSLLD != 1057 \
    || CDISASM_X86_NAME_VPSRLW != 1058 \
    || CDISASM_X86_NAME_VPSRAW != 1059 \
    || CDISASM_X86_NAME_VPSLLW != 1060 \
    || CDISASM_X86_NAME_VPSRLQ != 1061 \
    || CDISASM_X86_NAME_VPSRLDQ != 1062 \
    || CDISASM_X86_NAME_VPSLLQ != 1063 \
    || CDISASM_X86_NAME_VPSLLDQ != 1064 \
    || CDISASM_X86_NAME_VPSHLDW != 1065 \
    || CDISASM_X86_NAME_VPSHLDD != 1066 \
    || CDISASM_X86_NAME_VPSHLDQ != 1067 \
    || CDISASM_X86_NAME_VPSHLDVW != 1068 \
    || CDISASM_X86_NAME_VPSHLDVD != 1069 \
    || CDISASM_X86_NAME_VPSHLDVQ != 1070 \
    || CDISASM_X86_NAME_VPSHRDW != 1071 \
    || CDISASM_X86_NAME_VPSHRDD != 1072 \
    || CDISASM_X86_NAME_VPSHRDQ != 1073 \
    || CDISASM_X86_NAME_VPSHRDVW != 1074 \
    || CDISASM_X86_NAME_VPSHRDVD != 1075 \
    || CDISASM_X86_NAME_VPSHRDVQ != 1076 \
    || CDISASM_X86_NAME_VPCOMPRESSB != 1077 \
    || CDISASM_X86_NAME_VPCOMPRESSW != 1078 \
    || CDISASM_X86_NAME_VPCOMPRESSD != 1079 \
    || CDISASM_X86_NAME_VPCOMPRESSQ != 1080 \
    || CDISASM_X86_NAME_VPEXPANDB != 1081 \
    || CDISASM_X86_NAME_VPEXPANDW != 1082 \
    || CDISASM_X86_NAME_VPEXPANDD != 1083 \
    || CDISASM_X86_NAME_VPEXPANDQ != 1084 \
    || CDISASM_X86_NAME_VPOPCNTB != 1085 \
    || CDISASM_X86_NAME_VPOPCNTW != 1086 \
    || CDISASM_X86_NAME_VPOPCNTQ != 1087 \
    || CDISASM_X86_NAME_VPSHUFBITQMB != 1088 \
    || CDISASM_X86_NAME_VPCONFLICTD != 1089 \
    || CDISASM_X86_NAME_VPCONFLICTQ != 1090 \
    || CDISASM_X86_NAME_VPLZCNTD != 1091 \
    || CDISASM_X86_NAME_VPLZCNTQ != 1092 \
    || CDISASM_X86_NAME_VPBROADCASTMB2Q != 1093 \
    || CDISASM_X86_NAME_VPBROADCASTMW2D != 1094 \
    || CDISASM_X86_NAME_VPDPBUSDS != 1095 \
    || CDISASM_X86_NAME_VPDPWSSD != 1096 \
    || CDISASM_X86_NAME_VPDPWSSDS != 1097 \
    || CDISASM_X86_NAME_VPERMI2B != 1098 \
    || CDISASM_X86_NAME_VPERMT2B != 1099 \
    || CDISASM_X86_NAME_VPMULTISHIFTQB != 1100 \
    || CDISASM_X86_NAME_VPERMI2W != 1101 \
    || CDISASM_X86_NAME_VPERMT2W != 1102 \
    || CDISASM_X86_NAME_VPERMW != 1103 \
    || CDISASM_X86_NAME_VPDPBSSD != 1104 \
    || CDISASM_X86_NAME_VPDPBUUDS != 1109 \
    || CDISASM_X86_NAME_VPDPWSUD != 1110 \
    || CDISASM_X86_NAME_VPDPWUUDS != 1115 \
    || CDISASM_X86_NAME_VP4DPWSSD != 1116 \
    || CDISASM_X86_NAME_VP4DPWSSDS != 1117 \
    || CDISASM_X86_NAME_V4FMADDPS != 1118 \
    || CDISASM_X86_NAME_V4FMADDSS != 1119 \
    || CDISASM_X86_NAME_V4FNMADDPS != 1120 \
    || CDISASM_X86_NAME_V4FNMADDSS != 1121 \
    || CDISASM_X86_NAME_VGETEXPPS != 1122 \
    || CDISASM_X86_NAME_VGETEXPPD != 1123 \
    || CDISASM_X86_NAME_VGETEXPSS != 1124 \
    || CDISASM_X86_NAME_VGETEXPSD != 1125 \
    || CDISASM_X86_NAME_VGETEXPPH != 1126 \
    || CDISASM_X86_NAME_VGETEXPSH != 1127 \
    || CDISASM_X86_NAME_VGETEXPBF16 != 1128 \
    || CDISASM_NAME_VPERMI2W != CDISASM_X86_NAME_VPERMI2W \
    || CDISASM_NAME_VPERMT2W != CDISASM_X86_NAME_VPERMT2W \
    || CDISASM_NAME_VPERMW != CDISASM_X86_NAME_VPERMW \
    || CDISASM_NAME_VPDPBSSD != CDISASM_X86_NAME_VPDPBSSD \
    || CDISASM_NAME_VPDPBUUDS != CDISASM_X86_NAME_VPDPBUUDS \
    || CDISASM_NAME_VPDPWSUD != CDISASM_X86_NAME_VPDPWSUD \
    || CDISASM_NAME_VPDPWUUDS != CDISASM_X86_NAME_VPDPWUUDS \
    || CDISASM_NAME_VP4DPWSSD != CDISASM_X86_NAME_VP4DPWSSD \
    || CDISASM_NAME_VP4DPWSSDS != CDISASM_X86_NAME_VP4DPWSSDS \
    || CDISASM_NAME_V4FMADDPS != CDISASM_X86_NAME_V4FMADDPS \
    || CDISASM_NAME_V4FMADDSS != CDISASM_X86_NAME_V4FMADDSS \
    || CDISASM_NAME_V4FNMADDPS != CDISASM_X86_NAME_V4FNMADDPS \
    || CDISASM_NAME_V4FNMADDSS != CDISASM_X86_NAME_V4FNMADDSS \
    || CDISASM_NAME_VGETEXPPS != CDISASM_X86_NAME_VGETEXPPS \
    || CDISASM_NAME_VGETEXPPD != CDISASM_X86_NAME_VGETEXPPD \
    || CDISASM_NAME_VGETEXPSS != CDISASM_X86_NAME_VGETEXPSS \
    || CDISASM_NAME_VGETEXPSD != CDISASM_X86_NAME_VGETEXPSD \
    || CDISASM_NAME_VGETEXPPH != CDISASM_X86_NAME_VGETEXPPH \
    || CDISASM_NAME_VGETEXPSH != CDISASM_X86_NAME_VGETEXPSH \
    || CDISASM_NAME_VGETEXPBF16 != CDISASM_X86_NAME_VGETEXPBF16 \
    || CDISASM_X86_NAME_VGETEXPBF16 >= CDISASM_X86_NAME_COUNT \
    || CDISASM_X86_NAME_COUNT != CDISASM_X86_NAME_LAST + 1
#  error "installed cdisasm package has unexpected name IDs"
#endif
#if CDISASM_PREFIX_VEX != (UINT32_C(1) << 7) \
    || CDISASM_PREFIX_XOP != (UINT32_C(1) << 10) \
    || CDISASM_PREFIX_EVEX != (UINT32_C(1) << 11) \
    || CDISASM_PREFIX_REX2 != (UINT32_C(1) << 12) \
    || CDISASM_PREFIX_APX_NDD != (UINT32_C(1) << 13) \
    || CDISASM_PREFIX_APX_NF != (UINT32_C(1) << 14) \
    || CDISASM_PREFIX_XACQUIRE != (UINT32_C(1) << 19) \
    || CDISASM_PREFIX_XRELEASE != (UINT32_C(1) << 20)
#  error "installed cdisasm package has unexpected prefix flags"
#endif
#if CDISASM_X86_GROUP_3DNOW != 16 || CDISASM_X86_GROUP_XOP != 38 \
    || CDISASM_X86_GROUP_FMA4 != 39 || CDISASM_X86_GROUP_MPX != 57 \
    || CDISASM_X86_GROUP_AVX512_4FMAPS != 72 \
    || CDISASM_X86_GROUP_APX_F != 91 \
    || CDISASM_X86_GROUP_AMX_FP16 != 93 \
    || CDISASM_X86_GROUP_WAITPKG != 94 \
    || CDISASM_X86_GROUP_SHA512 != 95 \
    || CDISASM_X86_GROUP_SM3 != 96 \
    || CDISASM_X86_GROUP_SM4 != 97 \
    || CDISASM_X86_GROUP_AMX_COMPLEX != 98 \
    || CDISASM_X86_GROUP_AMX_AVX512 != 101 \
    || CDISASM_X86_GROUP_CLWB != 102 \
    || CDISASM_X86_GROUP_WBNOINVD != 107 \
    || CDISASM_X86_GROUP_AVX_VNNI_INT8 != 108 \
    || CDISASM_X86_GROUP_AVX_VNNI_INT16 != 109 \
    || CDISASM_X86_GROUP_AVX_VNNI_INT16 >= CDISASM_X86_GROUP_COUNT \
    || CDISASM_X86_GROUP_COUNT != CDISASM_X86_GROUP_LAST + 1
#  error "installed cdisasm package has unexpected x86 group IDs"
#endif
#if CDISASM_CPU_APX \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0026)) \
    || CDISASM_CPU_LATEST != CDISASM_CPU_DIAMOND_RAPIDS \
    || CDISASM_CPU_CELERON_N4020 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x002a)) \
    || CDISASM_CPU_PENTIUM_SILVER_N6000 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x002c)) \
    || CDISASM_CPU_8086_8087 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x002d)) \
    || CDISASM_CPU_80186_80187 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x002e)) \
    || CDISASM_CPU_80286_80287 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x002f)) \
    || CDISASM_CPU_80386_80387 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0030)) \
    || CDISASM_CPU_GRANITE_RAPIDS \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0031)) \
    || CDISASM_CPU_ARROW_LAKE \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0032)) \
    || CDISASM_CPU_DIAMOND_RAPIDS \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0033)) \
    || CDISASM_CPU_INTEL_DIAMOND_RAPIDS \
        != CDISASM_CPU_DIAMOND_RAPIDS \
    || CDISASM_CPU_DMR != CDISASM_CPU_DIAMOND_RAPIDS \
    || CDISASM_CPU_KNIGHTS_MILL \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0034)) \
    || CDISASM_CPU_INTEL_KNIGHTS_MILL != CDISASM_CPU_KNIGHTS_MILL \
    || CDISASM_CPU_KNM != CDISASM_CPU_KNIGHTS_MILL \
    || CDISASM_CPU_LAST != CDISASM_CPU_KNIGHTS_MILL \
    || CDISASM_CPU_8088_8087 != CDISASM_CPU_8086_8087 \
    || CDISASM_CPU_286_287 != CDISASM_CPU_80286_80287 \
    || CDISASM_CPU_386_387 != CDISASM_CPU_80386_80387
#  error "installed cdisasm package has unexpected x86 CPU profile IDs"
#endif
#endif

_Static_assert(sizeof(cdisasm_decode_option) == 8,
               "installed generic decode-option width changed");
_Static_assert(sizeof(cdisasm_decode_flags) == CDISASM_DECODE_FLAGS_SIZE,
               "installed generic decode-flags ABI size changed");
_Static_assert(CDISASM_DECODE_FLAGS_BITMAP_COUNT == 8u,
               "installed decode-flags bitmap count changed");
#if USE_ARCH_X86
_Static_assert(sizeof(cdisasm_x86_decode_option) == 8,
               "installed x86 decode-option width changed");
_Static_assert(sizeof(cdisasm_x86_decode_flags)
                   == sizeof(cdisasm_decode_flags),
               "installed x86 decode-flags ABI size changed");
#endif
#if USE_ARCH_ARM
_Static_assert(sizeof(cdisasm_arm_decode_option) == 8,
               "installed ARM decode-option width changed");
_Static_assert(sizeof(cdisasm_arm_decode_flags)
                   == sizeof(cdisasm_decode_flags),
               "installed ARM decode-flags ABI size changed");
#endif

int main(void)
{
#if USE_ARCH_X86
    static const uint8_t code[] = {0x48, 0x89, 0xe5};
    static const uint8_t optional_vpermi2w[] = {
        UINT8_C(0x62), UINT8_C(0xf2), UINT8_C(0xed), UINT8_C(0x08),
        UINT8_C(0x75), UINT8_C(0xcb)
    };
    static const uint8_t optional_vpdpbusd[] = {
        UINT8_C(0xc4), UINT8_C(0xe2), UINT8_C(0x69),
        UINT8_C(0x50), UINT8_C(0xcb)
    };
    static const uint8_t optional_vpdpbuud[] = {
        UINT8_C(0xc4), UINT8_C(0xe2), UINT8_C(0x68),
        UINT8_C(0x50), UINT8_C(0xcb)
    };
    cdisasm_instruction structured;
    cdisasm_x86_decode_flags x86_flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_x86_decode_flags available_flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    uint32_t size = cdisasm_x86_decode(
        CDISASM_CPU_ATHLON_64,
        CDISASM_MODE_64,
        code,
        sizeof(code),
        0,
        NULL,
        &structured);
#if USE_DISASM_FORMAT
    static const char expected[] = "mov rbp, rsp";
#  if USE_EXTRA_OPCODES
    static const char optional_expected[] = "vpermi2w xmm1, xmm2, xmm3";
    static const char avx_vnni_expected[] =
        "vpdpbusd xmm1, xmm2, xmm3";
    static const char avx_vnni_int8_expected[] =
        "vpdpbuud xmm1, xmm2, xmm3";
    char optional_formatted[sizeof(optional_expected)];
    char avx_vnni_formatted[sizeof(avx_vnni_expected)];
    char avx_vnni_int8_formatted[sizeof(avx_vnni_int8_expected)];
#  endif
    char formatted[sizeof(expected)];
    size_t required_size = cdisasm_x86_format(
        &structured, CDISASM_FORMAT_SYNTAX_INTEL, NULL, 0);
    size_t formatted_size = cdisasm_format(
        &structured,
        CDISASM_FORMAT_SYNTAX_INTEL,
        formatted,
        sizeof(formatted));
#endif

    if (cdisasm_x86_cpu_mode_mask(CDISASM_CPU_ATHLON_64)
            != (CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32
                | CDISASM_X86_MODE_MASK_64)) {
        return 1;
    }
#if USE_EXTRA_OPCODES
    if (cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_PENTIUM_III,
            CDISASM_X86_MODE_32,
            &available_flags) != CDISASM_STATUS_OK
        || (available_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
                & CDISASM_X86_DECODE_FLAG_SSE) == 0u) {
        return 1;
    }
    if (cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_ARROW_LAKE,
            CDISASM_X86_MODE_64,
            &available_flags) != CDISASM_STATUS_OK
        || (available_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
                & CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8) == 0u
        || (available_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
                & CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16) == 0u) {
        return 1;
    }
#else
    if (cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_PENTIUM_III,
            CDISASM_X86_MODE_32,
            &available_flags) != CDISASM_STATUS_OK
        || available_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
            != 0u) {
        return 1;
    }
#endif

    if (!(size == sizeof(code)
            && sizeof(cdisasm_x86_mode_mask) == sizeof(uint32_t)
            && sizeof(cdisasm_x86_reg_id) == 2
            && sizeof(cdisasm_opcode) == CDISASM_OPCODE_SIZE
            && sizeof(cdisasm_instruction) == CDISASM_INSTRUCTION_SIZE
            && structured.last_error_id == CDISASM_STATUS_OK
            && structured.opcode_size == sizeof(code)
            && structured.name_id == CDISASM_X86_NAME_MOV
            && CDISASM_NAME_MOV == CDISASM_X86_NAME_MOV
            && structured.operand_count == 2
            && structured.opcode[0].reg == CDISASM_X86_REG_RBP
            && structured.opcode[1].reg == CDISASM_X86_REG_RSP
            && structured.mask_reg == CDISASM_X86_REG_NONE
            && structured.mask_mode == CDISASM_X86_MASK_NONE
            && structured.rounding == CDISASM_X86_ROUNDING_NONE
            && structured.sae == CDISASM_X86_SAE_NONE
            && CDISASM_REG_RBP == CDISASM_X86_REG_RBP
            && CDISASM_REG_RSP == CDISASM_X86_REG_RSP
            && structured.x86_group_reserved == 0
            && structured.x86_group_count == 1
            && structured.x86_group_ids[0] == CDISASM_X86_GROUP_AMD64
            && cdisasm_instruction_has_x86_group(
                &structured, CDISASM_X86_GROUP_AMD64)
            && !cdisasm_instruction_has_x86_group(
                &structured, CDISASM_X86_GROUP_3DNOW)
#if USE_DISASM_FORMAT
            && required_size == sizeof(expected) - 1
            && formatted_size == required_size
            && strcmp(formatted, expected) == 0
#endif
        )) {
        return 1;
    }

    x86_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        CDISASM_X86_DECODE_FLAG_AVX512_BW;
    size = cdisasm_x86_decode(
        CDISASM_CPU_SKYLAKE_SP,
        CDISASM_X86_MODE_64,
        optional_vpermi2w,
        sizeof(optional_vpermi2w),
        UINT64_C(0x111900),
        &x86_flags,
        &structured);
#if USE_EXTRA_OPCODES
    if (size != sizeof(optional_vpermi2w)
        || structured.last_error_id != CDISASM_STATUS_OK
        || structured.name_id != CDISASM_X86_NAME_VPERMI2W
        || structured.operand_count != 3u
        || structured.opcode[0].reg != CDISASM_X86_REG_XMM1
        || structured.opcode[0].access
            != CDISASM_OPERAND_ACCESS_READ_WRITE
        || structured.opcode[1].reg != CDISASM_X86_REG_XMM2
        || structured.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
        || structured.opcode[2].reg != CDISASM_X86_REG_XMM3
        || structured.opcode[2].access != CDISASM_OPERAND_ACCESS_READ
        || !cdisasm_instruction_has_x86_group(
            &structured, CDISASM_X86_GROUP_AVX512BW)
#  if USE_DISASM_FORMAT
        || cdisasm_x86_format(
               &structured,
               CDISASM_FORMAT_SYNTAX_INTEL,
               optional_formatted,
               sizeof(optional_formatted))
            != sizeof(optional_expected) - 1u
        || strcmp(optional_formatted, optional_expected) != 0
#  endif
    ) {
        return 1;
    }
#else
    if (size != 0u
        || structured.last_error_id != CDISASM_STATUS_INVALID_ARGUMENT) {
        return 1;
    }
#endif

    size = cdisasm_x86_decode(
        CDISASM_CPU_ALDER_LAKE,
        CDISASM_X86_MODE_64,
        optional_vpdpbusd,
        sizeof(optional_vpdpbusd),
        UINT64_C(0x111908),
        NULL,
        &structured);
    if (size != 0u
        || structured.last_error_id
            != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return 1;
    }

    x86_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        CDISASM_X86_DECODE_FLAG_AVX_VNNI;
    size = cdisasm_x86_decode(
        CDISASM_CPU_ALDER_LAKE,
        CDISASM_X86_MODE_64,
        optional_vpdpbusd,
        sizeof(optional_vpdpbusd),
        UINT64_C(0x111908),
        &x86_flags,
        &structured);
#if USE_EXTRA_OPCODES
    if (size != sizeof(optional_vpdpbusd)
        || structured.last_error_id != CDISASM_STATUS_OK
        || structured.name_id != CDISASM_X86_NAME_VPDPBUSD
        || structured.operand_count != 3u
        || structured.opcode[0].reg != CDISASM_X86_REG_XMM1
        || structured.opcode[0].access
            != CDISASM_OPERAND_ACCESS_READ_WRITE
        || structured.opcode[1].reg != CDISASM_X86_REG_XMM2
        || structured.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
        || structured.opcode[2].reg != CDISASM_X86_REG_XMM3
        || structured.opcode[2].access != CDISASM_OPERAND_ACCESS_READ
        || !cdisasm_instruction_has_x86_group(
            &structured, CDISASM_X86_GROUP_AVX)
        || !cdisasm_instruction_has_x86_group(
            &structured, CDISASM_X86_GROUP_AVX_VNNI)
#  if USE_DISASM_FORMAT
        || cdisasm_x86_format(
               &structured,
               CDISASM_FORMAT_SYNTAX_INTEL,
               avx_vnni_formatted,
               sizeof(avx_vnni_formatted))
            != sizeof(avx_vnni_expected) - 1u
        || strcmp(avx_vnni_formatted, avx_vnni_expected) != 0
#  endif
    ) {
        return 1;
    }
#else
    if (size != 0u
        || structured.last_error_id != CDISASM_STATUS_INVALID_ARGUMENT) {
        return 1;
    }
#endif

    size = cdisasm_x86_decode(
        CDISASM_CPU_ARROW_LAKE,
        CDISASM_X86_MODE_64,
        optional_vpdpbuud,
        sizeof(optional_vpdpbuud),
        UINT64_C(0x11190d),
        NULL,
        &structured);
    if (size != 0u
        || structured.last_error_id
            != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return 1;
    }

    x86_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8;
    size = cdisasm_x86_decode(
        CDISASM_CPU_ARROW_LAKE,
        CDISASM_X86_MODE_64,
        optional_vpdpbuud,
        sizeof(optional_vpdpbuud),
        UINT64_C(0x11190d),
        &x86_flags,
        &structured);
#if USE_EXTRA_OPCODES
    if (size != sizeof(optional_vpdpbuud)
        || structured.last_error_id != CDISASM_STATUS_OK
        || structured.name_id != CDISASM_X86_NAME_VPDPBUUD
        || structured.operand_count != 3u
        || structured.opcode[0].reg != CDISASM_X86_REG_XMM1
        || structured.opcode[0].access
            != CDISASM_OPERAND_ACCESS_READ_WRITE
        || structured.opcode[1].reg != CDISASM_X86_REG_XMM2
        || structured.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
        || structured.opcode[2].reg != CDISASM_X86_REG_XMM3
        || structured.opcode[2].access != CDISASM_OPERAND_ACCESS_READ
        || !cdisasm_instruction_has_x86_group(
            &structured, CDISASM_X86_GROUP_AVX)
        || !cdisasm_instruction_has_x86_group(
            &structured, CDISASM_X86_GROUP_AVX_VNNI_INT8)
#  if USE_DISASM_FORMAT
        || cdisasm_x86_format(
               &structured,
               CDISASM_FORMAT_SYNTAX_INTEL,
               avx_vnni_int8_formatted,
               sizeof(avx_vnni_int8_formatted))
            != sizeof(avx_vnni_int8_expected) - 1u
        || strcmp(avx_vnni_int8_formatted, avx_vnni_int8_expected) != 0
#  endif
    ) {
        return 1;
    }
#else
    if (size != 0u
        || structured.last_error_id != CDISASM_STATUS_INVALID_ARGUMENT) {
        return 1;
    }
#endif
#endif

#if USE_ARCH_ARM
    {
        static const uint8_t optional_frecpe[] = {
            UINT8_C(0xa7), UINT8_C(0xd9), UINT8_C(0xa1), UINT8_C(0x5e)
        };
        static const uint8_t optional_frsqrte[] = {
            UINT8_C(0xa7), UINT8_C(0xd9), UINT8_C(0xa1), UINT8_C(0x6e)
        };
        static const uint8_t optional_f64mm_zip1[] = {
            UINT8_C(0x20), UINT8_C(0x00), UINT8_C(0xa2), UINT8_C(0x05)
        };
        static const uint8_t optional_scvtf[] = {
            UINT8_C(0xa7), UINT8_C(0xad), UINT8_C(0x52), UINT8_C(0x65)
        };
        static const uint8_t optional_bfcvtn_multi[] = {
            UINT8_C(0xdf), UINT8_C(0x3b), UINT8_C(0x0a), UINT8_C(0x65)
        };
        cdisasm_arm_instruction arm_instruction;
        uint32_t arm_size;
#  if USE_DISASM_FORMAT
#    if USE_EXTRA_OPCODES
        static const char frecpe_expected[] = "frecpe s7, s13";
        static const char frsqrte_expected[] = "frsqrte v7.4s, v13.4s";
        static const char f64mm_zip1_expected[] =
            "zip1 z0.q, z1.q, z2.q";
        static const char scvtf_expected[] =
            "scvtf z7.h, p3/m, z13.h";
        static const char bfcvtn_expected[] =
            "bfcvtn z31.b, {z30.h, z31.h}";
        char arm_formatted[sizeof(frsqrte_expected)];
        char f64mm_formatted[sizeof(f64mm_zip1_expected)];
        char scvtf_formatted[sizeof(scvtf_expected)];
        char bfcvtn_formatted[sizeof(bfcvtn_expected)];
#    endif
#  endif

        arm_size = cdisasm_arm_decode(
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            optional_bfcvtn_multi,
            sizeof(optional_bfcvtn_multi),
            UINT64_C(0x111944),
            NULL,
            &arm_instruction);
#  if USE_EXTRA_OPCODES
        if (arm_size != sizeof(optional_bfcvtn_multi)
            || arm_instruction.last_error_id != CDISASM_STATUS_OK
            || arm_instruction.name_id != CDISASM_ARM_NAME_BFCVTN
            || arm_instruction.operand_count != 2u
            || arm_instruction.instruction_flags
                != (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
            || arm_instruction.operand[0].reg != CDISASM_ARM_REG_Z31
            || arm_instruction.operand[0].access
                != CDISASM_OPERAND_ACCESS_WRITE
            || CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
                &arm_instruction.operand[0]) != 1u
            || arm_instruction.operand[1].type
                != CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
            || arm_instruction.operand[1].reg != CDISASM_ARM_REG_Z30
            || arm_instruction.operand[1].register_list != UINT16_C(0x0102)
            || arm_instruction.operand[1].access
                != CDISASM_OPERAND_ACCESS_READ
            || CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
                &arm_instruction.operand[1]) != 2u
#    if USE_DISASM_FORMAT
            || cdisasm_arm_format(
                   &arm_instruction,
                   CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
                   bfcvtn_formatted,
                   sizeof(bfcvtn_formatted))
                != sizeof(bfcvtn_expected) - 1u
            || strcmp(bfcvtn_formatted, bfcvtn_expected) != 0
#    endif
        ) {
            return 1;
        }
#  else
        if (arm_size != 0u || arm_instruction.last_error_id
                != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return 1;
        }
#  endif

        arm_size = cdisasm_arm_decode(
            CDISASM_ARM_CPU_A64FX,
            CDISASM_ARM_MODE_A64,
            optional_scvtf,
            sizeof(optional_scvtf),
            UINT64_C(0x111940),
            NULL,
            &arm_instruction);
#  if USE_EXTRA_OPCODES
        if (arm_size != sizeof(optional_scvtf)
            || arm_instruction.last_error_id != CDISASM_STATUS_OK
            || arm_instruction.name_id != CDISASM_ARM_NAME_SCVTF
            || arm_instruction.operand_count != 3u
            || arm_instruction.instruction_flags
                != (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                    | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
            || arm_instruction.operand[0].reg != CDISASM_ARM_REG_Z7
            || arm_instruction.operand[0].access
                != CDISASM_OPERAND_ACCESS_READ_WRITE
            || CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
                &arm_instruction.operand[0]) != 2u
            || arm_instruction.operand[1].reg != CDISASM_ARM_REG_P3
            || arm_instruction.operand[1].access
                != CDISASM_OPERAND_ACCESS_READ
            || arm_instruction.operand[1].flags
                != CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE
            || CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
                &arm_instruction.operand[1]) != 2u
            || arm_instruction.operand[2].reg != CDISASM_ARM_REG_Z13
            || arm_instruction.operand[2].access
                != CDISASM_OPERAND_ACCESS_READ
            || CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
                &arm_instruction.operand[2]) != 2u
#    if USE_DISASM_FORMAT
            || cdisasm_arm_format(
                   &arm_instruction,
                   CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
                   scvtf_formatted,
                   sizeof(scvtf_formatted))
                != sizeof(scvtf_expected) - 1u
            || strcmp(scvtf_formatted, scvtf_expected) != 0
#    endif
        ) {
            return 1;
        }
#  else
        if (arm_size != 0u || arm_instruction.last_error_id
                != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return 1;
        }
#  endif

        arm_size = cdisasm_arm_decode(
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            optional_f64mm_zip1,
            sizeof(optional_f64mm_zip1),
            UINT64_C(0x111930),
            NULL,
            &arm_instruction);
#  if USE_EXTRA_OPCODES
        if (arm_size != sizeof(optional_f64mm_zip1)
            || arm_instruction.last_error_id != CDISASM_STATUS_OK
            || arm_instruction.name_id != CDISASM_ARM_NAME_ZIP1
            || arm_instruction.operand_count != 3u
            || arm_instruction.instruction_flags
                != CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            || arm_instruction.operand[0].reg != CDISASM_ARM_REG_Z0
            || arm_instruction.operand[0].access
                != CDISASM_OPERAND_ACCESS_WRITE
            || CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
                &arm_instruction.operand[0]) != 16u
            || arm_instruction.operand[1].reg != CDISASM_ARM_REG_Z1
            || arm_instruction.operand[1].access
                != CDISASM_OPERAND_ACCESS_READ
            || CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
                &arm_instruction.operand[1]) != 16u
            || arm_instruction.operand[2].reg != CDISASM_ARM_REG_Z2
            || arm_instruction.operand[2].access
                != CDISASM_OPERAND_ACCESS_READ
            || CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
                &arm_instruction.operand[2]) != 16u
#    if USE_DISASM_FORMAT
            || cdisasm_arm_format(
                   &arm_instruction,
                   CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
                   f64mm_formatted,
                   sizeof(f64mm_formatted))
                != sizeof(f64mm_zip1_expected) - 1u
            || strcmp(f64mm_formatted, f64mm_zip1_expected) != 0
#    endif
        ) {
            return 1;
        }
#  else
        if (arm_size != 0u || arm_instruction.last_error_id
                != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return 1;
        }
#  endif

        arm_size = cdisasm_arm_decode(
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            optional_frecpe,
            sizeof(optional_frecpe),
            UINT64_C(0x111910),
            NULL,
            &arm_instruction);
#  if USE_EXTRA_OPCODES
        if (arm_size != sizeof(optional_frecpe)
            || arm_instruction.last_error_id != CDISASM_STATUS_OK
            || arm_instruction.name_id != CDISASM_ARM_NAME_FRECPE
            || arm_instruction.operand_count != 2u
            || arm_instruction.instruction_flags
                != CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            || arm_instruction.operand[0].reg != CDISASM_ARM_REG_S7
            || arm_instruction.operand[0].access
                != CDISASM_OPERAND_ACCESS_WRITE
            || arm_instruction.operand[1].reg != CDISASM_ARM_REG_S13
            || arm_instruction.operand[1].access
                != CDISASM_OPERAND_ACCESS_READ
#    if USE_DISASM_FORMAT
            || cdisasm_arm_format(
                   &arm_instruction,
                   CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
                   arm_formatted,
                   sizeof(arm_formatted))
                != sizeof(frecpe_expected) - 1u
            || strcmp(arm_formatted, frecpe_expected) != 0
#    endif
        ) {
            return 1;
        }
#  else
        if (arm_size != 0u || arm_instruction.last_error_id
                != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return 1;
        }
#  endif

        arm_size = cdisasm_arm_decode(
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            optional_frsqrte,
            sizeof(optional_frsqrte),
            UINT64_C(0x111920),
            NULL,
            &arm_instruction);
#  if USE_EXTRA_OPCODES
        if (arm_size != sizeof(optional_frsqrte)
            || arm_instruction.last_error_id != CDISASM_STATUS_OK
            || arm_instruction.name_id != CDISASM_ARM_NAME_FRSQRTE
            || arm_instruction.operand_count != 2u
            || arm_instruction.instruction_flags
                != (CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
                    | CDISASM_ARM_INSTRUCTION_FLAG_SIMD)
            || arm_instruction.operand[0].reg != CDISASM_ARM_REG_V7
            || arm_instruction.operand[0].access
                != CDISASM_OPERAND_ACCESS_WRITE
            || arm_instruction.operand[1].reg != CDISASM_ARM_REG_V13
            || arm_instruction.operand[1].access
                != CDISASM_OPERAND_ACCESS_READ
#    if USE_DISASM_FORMAT
            || cdisasm_arm_format(
                   &arm_instruction,
                   CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
                   arm_formatted,
                   sizeof(arm_formatted))
                != sizeof(frsqrte_expected) - 1u
            || strcmp(arm_formatted, frsqrte_expected) != 0
#    endif
        ) {
            return 1;
        }
#  else
        if (arm_size != 0u || arm_instruction.last_error_id
                != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return 1;
        }
#  endif
    }
#endif

    return 0;
}
