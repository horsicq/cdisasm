#include "cdisasm/cdisasm_config.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#else
#  include "cdisasm/cdisasm_arm.h"
#endif

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if USE_DISASM_FORMAT
#  define FUZZ_FORMAT_CAPACITY 512
#endif
#define FUZZ_HEX_CAPACITY 64

_Static_assert(sizeof(cdisasm_arm_decode_option) == 8,
               "ARM decode-option ABI width changed");
_Static_assert(sizeof(cdisasm_arm_decode_flags) == 64,
               "ARM fuzzer requires the public 64-byte decode-flags ABI");
_Static_assert(CDISASM_DECODE_FLAGS_BITMAP_COUNT == 8u,
               "ARM fuzzer must exercise every public bitmap word");
_Static_assert(CDISASM_ARM_NAME_UDF == UINT16_C(1752),
               "update A64 UDF exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_OPERAND_FLAG_VL_SCALED == UINT8_C(64),
               "update ARM VL-scaled memory fuzz invariants");
_Static_assert(CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL == UINT8_C(32),
               "update ARM ZA-slice orientation fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_MOV == UINT16_C(31),
               "update SME2 MOVA exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_AND == UINT16_C(6)
                   && CDISASM_ARM_NAME_BIC == UINT16_C(9)
                   && CDISASM_ARM_NAME_EOR == UINT16_C(21)
                   && CDISASM_ARM_NAME_ORR == UINT16_C(37)
                   && CDISASM_ARM_NAME_XAR == UINT16_C(2045),
               "update SVE logical exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2325),
               "update SVE logical form fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_MOVAZ == UINT16_C(1117),
               "update SME2.1 MOVAZ exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_CFINV == UINT16_C(668),
               "update FlagM exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_XAFLAG == UINT16_C(2044),
               "update FlagM2 exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_AXFLAG == UINT16_C(561),
               "update FlagM2 exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_CRC32B == UINT16_C(445)
                   && CDISASM_ARM_NAME_CRC32CX == UINT16_C(452),
               "update fixed-width CRC32 exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_CLRBHB == UINT16_C(673)
                   && CDISASM_ARM_NAME_CSDB == UINT16_C(785)
                   && CDISASM_ARM_NAME_DBG == UINT16_C(788)
                   && CDISASM_ARM_NAME_ESB == UINT16_C(810)
                   && CDISASM_ARM_NAME_TSB == UINT16_C(1727),
               "update architectural-hint exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(4476),
               "update architectural-hint form fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(5603),
               "update fixed-width CRC32 form fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_RMIF == UINT16_C(1283),
               "update FlagM exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SETF8 == UINT16_C(1331),
               "update FlagM exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SETF16 == UINT16_C(1330),
               "update FlagM exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_RDFFR == UINT16_C(1261),
               "update SVE FFR exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_RDFFRS == UINT16_C(1262),
               "update SVE FFR exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_WRFFR == UINT16_C(2043),
               "update SVE FFR exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SETFFR == UINT16_C(1332),
               "update SVE FFR exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_CNTB == UINT16_C(245),
               "update SVE element-count exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_INCB == UINT16_C(926),
               "update SVE element-count exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_DECB == UINT16_C(793),
               "update SVE element-count exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQINCB == UINT16_C(1487),
               "update SVE saturating-count exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UQINCB == UINT16_C(1801),
               "update SVE saturating-count exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_CNTP == UINT16_C(684),
               "update SVE predicate-count exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_FIRSTP == UINT16_C(852),
               "update SVE FIRSTP exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_LASTP == UINT16_C(935),
               "update SVE LASTP exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_CTERMEQ == UINT16_C(786),
               "update SVE CTERMEQ exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_CTERMNE == UINT16_C(787),
               "update SVE CTERMNE exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_WHILEGE == UINT16_C(2034),
               "update SVE WHILEGE exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_WHILEGT == UINT16_C(2035),
               "update SVE WHILEGT exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_WHILEHI == UINT16_C(2036),
               "update SVE WHILEHI exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_WHILEHS == UINT16_C(2037),
               "update SVE WHILEHS exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_WHILELE == UINT16_C(2038),
               "update SVE WHILELE exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_WHILELS == UINT16_C(2039),
               "update SVE WHILELS exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_WHILELT == UINT16_C(2040),
               "update SVE WHILELT exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_WHILELO == UINT16_C(244),
               "update SVE WHILELO exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_WHILERW == UINT16_C(2041),
               "update SVE WHILERW exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_WHILEWR == UINT16_C(2042),
               "update SVE WHILEWR exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_PEXT == UINT16_C(1155),
               "update SVE2.1 PEXT exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_OPERAND_PREDICATE_PAIR == UINT8_C(11),
               "update paired-predicate WHILE fuzz invariants");
_Static_assert(CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED == UINT8_C(16),
               "update typed predicate-pair fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQINCP == UINT16_C(1490),
               "update SVE predicate-count exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_BRKA == UINT16_C(614),
               "update SVE predicate-break exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_BRKPBS == UINT16_C(623),
               "update SVE predicate-break exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_PFALSE == UINT16_C(1156),
               "update SVE predicate-control exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_PFIRST == UINT16_C(1157),
               "update SVE predicate-control exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_PNEXT == UINT16_C(1170),
               "update SVE predicate-control exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_PTEST == UINT16_C(1180),
               "update SVE predicate-control exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_PTRUES == UINT16_C(1181),
               "update SVE predicate-control exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_PSEL == UINT16_C(1178),
               "update SVE2.1 PSEL exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_PUNPKHI == UINT16_C(1182)
                   && CDISASM_ARM_NAME_PUNPKLO == UINT16_C(1183),
               "update SVE PUNPK exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SUNPKHI == UINT16_C(1702)
                   && CDISASM_ARM_NAME_SUNPKLO == UINT16_C(1703)
                   && CDISASM_ARM_NAME_UUNPKHI == UINT16_C(1860)
                   && CDISASM_ARM_NAME_UUNPKLO == UINT16_C(1861),
               "update SVE unpack exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2459),
               "update SVE unpack form fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SRI == UINT16_C(1521)
                   && CDISASM_ARM_NAME_SLI == UINT16_C(1393),
               "update SVE shift-insert exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2847),
               "update SVE shift-insert form fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_BEXT == UINT16_C(565)
                   && CDISASM_ARM_NAME_BDEP == UINT16_C(564)
                   && CDISASM_ARM_NAME_BGRP == UINT16_C(600),
               "update SVE BitPerm exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2831),
               "update SVE BitPerm form fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_BSL == UINT16_C(624)
                   && CDISASM_ARM_NAME_BIT == UINT16_C(602)
                   && CDISASM_ARM_NAME_BIF == UINT16_C(601),
               "update Advanced SIMD bitwise-select fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6198),
               "update Advanced SIMD bitwise-select form invariants");
_Static_assert(CDISASM_ARM_NAME_CMTST == UINT16_C(683),
               "update Advanced SIMD CMTST fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6131),
               "update Advanced SIMD CMTST form invariants");
_Static_assert(CDISASM_ARM_NAME_SSHL == UINT16_C(1533)
                   && CDISASM_ARM_NAME_USHL == UINT16_C(1835),
               "update Advanced SIMD variable-shift fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6164),
               "update Advanced SIMD variable-shift form invariants");
_Static_assert(CDISASM_ARM_NAME_CMLT == UINT16_C(681)
                   && CDISASM_ARM_NAME_CMLE == UINT16_C(680),
               "update Advanced SIMD compare-zero fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6045),
               "update Advanced SIMD compare-zero form invariants");
_Static_assert(CDISASM_ARM_NAME_SADDL == UINT16_C(1307)
                   && CDISASM_ARM_NAME_SADDW == UINT16_C(1314)
                   && CDISASM_ARM_NAME_SSUBL == UINT16_C(1541)
                   && CDISASM_ARM_NAME_SSUBW == UINT16_C(1546)
                   && CDISASM_ARM_NAME_UADDL == UINT16_C(1738)
                   && CDISASM_ARM_NAME_UADDW == UINT16_C(1744)
                   && CDISASM_ARM_NAME_USUBL == UINT16_C(1851)
                   && CDISASM_ARM_NAME_USUBW == UINT16_C(1854),
               "update Advanced SIMD widening add/sub fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6107),
               "update Advanced SIMD widening add/sub form invariants");
_Static_assert(CDISASM_ARM_NAME_SABAL == UINT16_C(1298)
                   && CDISASM_ARM_NAME_SABDL == UINT16_C(1301)
                   && CDISASM_ARM_NAME_UABAL == UINT16_C(1729)
                   && CDISASM_ARM_NAME_UABDL == UINT16_C(1732),
               "update Advanced SIMD absolute-difference-long invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6111),
               "update Advanced SIMD absolute-difference-long forms");
_Static_assert(CDISASM_ARM_NAME_SABD == UINT16_C(359)
                   && CDISASM_ARM_NAME_UABD == UINT16_C(360),
               "update Advanced SIMD absolute-difference invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6170),
               "update Advanced SIMD absolute-difference forms");
_Static_assert(CDISASM_ARM_NAME_SABA == UINT16_C(1297)
                   && CDISASM_ARM_NAME_UABA == UINT16_C(1728),
               "update Advanced SIMD absolute-difference-accumulate invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6171),
               "update Advanced SIMD absolute-difference-accumulate forms");
_Static_assert(CDISASM_ARM_NAME_MLA == UINT16_C(217)
                   && CDISASM_ARM_NAME_MLS == UINT16_C(310),
               "update Advanced SIMD multiply-accumulate invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6174),
               "update Advanced SIMD multiply-accumulate forms");
_Static_assert(CDISASM_ARM_NAME_SMLAL == UINT16_C(1414)
                   && CDISASM_ARM_NAME_SMLSL == UINT16_C(1431)
                   && CDISASM_ARM_NAME_SMULL == UINT16_C(1453)
                   && CDISASM_ARM_NAME_UMLAL == UINT16_C(1771)
                   && CDISASM_ARM_NAME_UMLSL == UINT16_C(1776)
                   && CDISASM_ARM_NAME_UMULL == UINT16_C(1787),
               "update Advanced SIMD widening-multiply invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6272),
               "update Advanced SIMD widening-multiply forms");
_Static_assert(CDISASM_ARM_NAME_SQDMLAL == UINT16_C(1475)
                   && CDISASM_ARM_NAME_SQDMLSL == UINT16_C(1479)
                   && CDISASM_ARM_NAME_SQDMULL == UINT16_C(1484),
               "update saturating widening-multiply invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6102),
               "update saturating widening-multiply forms");
_Static_assert(CDISASM_ARM_NAME_SQDMULH == UINT16_C(1483)
                   && CDISASM_ARM_NAME_SQRDMULH == UINT16_C(1495),
               "update saturating multiply-high invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6178),
               "update saturating multiply-high forms");
_Static_assert(CDISASM_ARM_NAME_PMULL == UINT16_C(1167),
               "update PMULL fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6103),
               "update PMULL form");
_Static_assert(CDISASM_ARM_NAME_PMUL == UINT16_C(1166),
               "update PMUL fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6175),
               "update PMUL form");
_Static_assert(CDISASM_ARM_NAME_ADDHN == UINT16_C(516)
                   && CDISASM_ARM_NAME_SUBHN == UINT16_C(1689)
                   && CDISASM_ARM_NAME_RADDHN == UINT16_C(1194)
                   && CDISASM_ARM_NAME_RSUBHN == UINT16_C(1294),
               "update Advanced SIMD high-narrow fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6110),
               "update Advanced SIMD high-narrow form invariants");
_Static_assert(CDISASM_ARM_NAME_BLRAA == UINT16_C(603)
                   && CDISASM_ARM_NAME_BLRAAZ == UINT16_C(604)
                   && CDISASM_ARM_NAME_BLRAB == UINT16_C(605)
                   && CDISASM_ARM_NAME_BLRABZ == UINT16_C(606)
                   && CDISASM_ARM_NAME_BRAA == UINT16_C(609)
                   && CDISASM_ARM_NAME_BRAAZ == UINT16_C(610)
                   && CDISASM_ARM_NAME_BRAB == UINT16_C(611)
                   && CDISASM_ARM_NAME_BRABZ == UINT16_C(612),
               "update A64 authenticated-branch fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(4528),
               "update A64 authenticated-branch form invariants");
_Static_assert(CDISASM_ARM_NAME_SUBR == UINT16_C(358),
               "update SVE integer-immediate exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQADD == UINT16_C(342),
               "update SVE integer-immediate exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_FMOV == UINT16_C(884),
               "update SVE DUP/FDUP immediate exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SDOT == UINT16_C(1325),
               "update SVE SDOT exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UDOT == UINT16_C(1753),
               "update SVE UDOT exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_USDOT == UINT16_C(1834),
               "update SVE USDOT exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SUDOT == UINT16_C(1695),
               "update indexed SVE SUDOT exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_AESIMC == UINT16_C(534)
                   && CDISASM_ARM_NAME_AESMC == UINT16_C(535),
               "update SVE AES unary exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_AESD == UINT16_C(530)
                   && CDISASM_ARM_NAME_AESE == UINT16_C(532)
                   && CDISASM_ARM_NAME_SM4E == UINT16_C(1401),
               "update SVE crypto-binary exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SRSHL == UINT16_C(1525),
               "update SVE predicated shift/saturating-round fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UQRSHLR == UINT16_C(1807),
               "update SVE predicated shift/saturating-round fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_URSHLR == UINT16_C(1826),
               "update SVE predicated shift/saturating-round fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQABS == UINT16_C(1464),
               "update SVE predicated saturating-unary fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQNEG == UINT16_C(1492),
               "update SVE predicated saturating-unary fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_URECPE == UINT16_C(1823),
               "update SVE predicated estimate-unary fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_URSQRTE == UINT16_C(1827),
               "update SVE predicated estimate-unary fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SADALP == UINT16_C(1304),
               "update SVE predicated accumulate-long fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UADALP == UINT16_C(1735),
               "update SVE predicated accumulate-long fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SADDLP == UINT16_C(1310),
               "update Advanced SIMD SADDLP fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UADDLP == UINT16_C(1740),
               "update Advanced SIMD UADDLP fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SHLL == UINT16_C(1383),
               "update Advanced SIMD SHLL fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_XTN == UINT16_C(2048),
               "update Advanced SIMD XTN fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SSHR == UINT16_C(1537),
               "update Advanced SIMD SSHR immediate fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_USHR == UINT16_C(1839),
               "update Advanced SIMD USHR immediate fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SSRA == UINT16_C(1538),
               "update Advanced SIMD SSRA immediate fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_USRA == UINT16_C(1847),
               "update Advanced SIMD USRA immediate fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SRSHR == UINT16_C(384),
               "update Advanced SIMD SRSHR immediate fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_URSHR == UINT16_C(385),
               "update Advanced SIMD URSHR immediate fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SRSRA == UINT16_C(1528),
               "update Advanced SIMD SRSRA immediate fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_URSRA == UINT16_C(1828),
               "update Advanced SIMD URSRA immediate fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SHL == UINT16_C(1382),
               "update Advanced SIMD SHL immediate fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_MOVI == UINT16_C(1118)
                   && CDISASM_ARM_NAME_MVNI == UINT16_C(1128),
               "update Advanced SIMD modified-immediate fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_ORR == UINT16_C(37)
                   && CDISASM_ARM_NAME_BIC == UINT16_C(9),
               "update Advanced SIMD logical-immediate fuzz invariants");
_Static_assert(CDISASM_ARM_SHIFT_MSL == UINT8_C(6),
               "update Advanced SIMD MSL modifier fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SHADD == UINT16_C(1378),
               "update SVE predicated halving fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SHSUB == UINT16_C(1388),
               "update SVE predicated halving fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SRHADD == UINT16_C(1520),
               "update SVE predicated halving fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SHSUBR == UINT16_C(1391),
               "update SVE predicated halving fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UHADD == UINT16_C(1754),
               "update SVE predicated halving fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UHSUB == UINT16_C(1759),
               "update SVE predicated halving fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_URHADD == UINT16_C(1824),
               "update SVE predicated halving fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UHSUBR == UINT16_C(1762),
               "update SVE predicated halving fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_ADDP == UINT16_C(519),
               "update SVE predicated pairwise fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_ADDV == UINT16_C(526),
               "update Advanced SIMD ADDV fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SADDLV == UINT16_C(1312),
               "update Advanced SIMD SADDLV fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UADDLV == UINT16_C(1742),
               "update Advanced SIMD UADDLV fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SMAXP == UINT16_C(1404),
               "update SVE predicated pairwise fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SMINP == UINT16_C(1407),
               "update SVE predicated pairwise fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SUBP == UINT16_C(1692),
               "update SVE predicated pairwise fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UMAXP == UINT16_C(1765),
               "update SVE predicated pairwise fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UMINP == UINT16_C(1768),
               "update SVE predicated pairwise fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UQADD == UINT16_C(343),
               "update SVE predicated saturating fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQSUB == UINT16_C(344),
               "update SVE predicated saturating fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UQSUB == UINT16_C(345),
               "update SVE predicated saturating fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQSUBR == UINT16_C(1513),
               "update SVE predicated saturating fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SUQADD == UINT16_C(1704),
               "update SVE predicated saturating fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UQSUBR == UINT16_C(1819),
               "update SVE predicated saturating fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_USQADD == UINT16_C(1846),
               "update SVE predicated saturating fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SCLAMP == UINT16_C(1323),
               "update SVE clamp exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UCLAMP == UINT16_C(1750),
               "update SVE clamp exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2702),
               "update SVE clamp form fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_MLAPT == UINT16_C(1114),
               "update SVE MLAPT exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_MADPT == UINT16_C(1110),
               "update SVE MADPT exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2708),
               "update SVE pointer multiply-add form fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_ZIPQ1 == UINT16_C(2051),
               "update SVE ZIPQ1 exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UZPQ1 == UINT16_C(1869),
               "update SVE UZPQ1 exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_ZIPQ2 == UINT16_C(2052),
               "update SVE ZIPQ2 exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UZPQ2 == UINT16_C(1870),
               "update SVE UZPQ2 exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2715),
               "update SVE quad-permute form fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_CDOT == UINT16_C(667),
               "update SVE CDOT exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_CMLA == UINT16_C(679),
               "update SVE CMLA exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQDMLALBT == UINT16_C(1477),
               "update SVE SQDMLALBT exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQDMLSLBT == UINT16_C(1481),
               "update SVE SQDMLSLBT exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQRDCMLAH == UINT16_C(1493),
               "update SVE SQRDCMLAH exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SMLALB == UINT16_C(1415),
               "update SVE widening multiply-add exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SMLSLB == UINT16_C(1432),
               "update SVE widening multiply-add exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SMLALT == UINT16_C(1422),
               "update SVE widening multiply-add exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SMLSLT == UINT16_C(1436),
               "update SVE widening multiply-add exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UMLALB == UINT16_C(1772),
               "update SVE widening multiply-add exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UMLSLB == UINT16_C(1777),
               "update SVE widening multiply-add exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UMLALT == UINT16_C(1775),
               "update SVE widening multiply-add exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_UMLSLT == UINT16_C(1779),
               "update SVE widening multiply-add exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQDMLALB == UINT16_C(1476),
               "update SVE widening multiply-add exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQDMLSLB == UINT16_C(1480),
               "update SVE widening multiply-add exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQDMLALT == UINT16_C(1478),
               "update SVE widening multiply-add exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQDMLSLT == UINT16_C(1482),
               "update SVE widening multiply-add exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQRDMLAH == UINT16_C(312),
               "update SVE rounding multiply-add exact-family fuzz invariants");
_Static_assert(CDISASM_ARM_NAME_SQRDMLSH == UINT16_C(1494),
               "update SVE rounding multiply-add exact-family fuzz invariants");

static void invariant_failed(
    const char *expression, const char *file, int line)
{
    fprintf(stderr, "%s:%d: fuzzer invariant failed: %s\n",
        file, line, expression);
    abort();
}

#define invariant(condition)                                                \
    do {                                                                    \
        if (!(condition)) {                                                 \
            invariant_failed(#condition, __FILE__, __LINE__);               \
        }                                                                   \
    } while (0)

static int hex_value(uint8_t character)
{
    if (character >= (uint8_t)'0' && character <= (uint8_t)'9') {
        return (int)(character - (uint8_t)'0');
    }
    character = (uint8_t)tolower((unsigned char)character);
    if (character >= (uint8_t)'a' && character <= (uint8_t)'f') {
        return (int)(character - (uint8_t)'a') + 10;
    }
    return -1;
}

/* Checked-in seeds are readable hexadecimal. Mutated input remains raw. */
static void normalize_input(const uint8_t *data, size_t size,
                            uint8_t *hex_bytes, const uint8_t **code,
                            size_t *code_size)
{
    size_t input_index;
    size_t output_size = 0;
    int high_nibble = -1;

    if (size == 0 || size > FUZZ_HEX_CAPACITY * 3u) {
        *code = data;
        *code_size = size;
        return;
    }
    for (input_index = 0; input_index < size; ++input_index) {
        int nibble;

        if (isspace((unsigned char)data[input_index])) {
            continue;
        }
        nibble = hex_value(data[input_index]);
        if (nibble < 0) {
            *code = data;
            *code_size = size;
            return;
        }
        if (high_nibble < 0) {
            high_nibble = nibble;
        } else {
            if (output_size == FUZZ_HEX_CAPACITY) {
                *code = data;
                *code_size = size;
                return;
            }
            hex_bytes[output_size++] =
                (uint8_t)((high_nibble << 4) | nibble);
            high_nibble = -1;
        }
    }
    if (high_nibble >= 0 || output_size == 0) {
        *code = data;
        *code_size = size;
        return;
    }
    *code = hex_bytes;
    *code_size = output_size;
}

static uint64_t input_hash(const uint8_t *data, size_t size)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t index;

    for (index = 0; index < size; ++index) {
        hash ^= data[index];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static void derive_decode_flags(
    const uint8_t *data, size_t size, cdisasm_arm_decode_flags *flags)
{
    size_t index;

    cdisasm_decode_flags_reset(flags);
    for (index = 0u; index < size; ++index) {
        size_t bitmap_index = (index / 8u)
            % CDISASM_DECODE_FLAGS_BITMAP_COUNT;
        unsigned shift = (unsigned)(index % 8u) * 8u;

        flags->bitmap[bitmap_index] ^=
            (uint64_t)data[index] << shift;
    }
}

static cdisasm_arm_decode_option decode_flag_word0(
    const cdisasm_arm_decode_flags *flags)
{
    return flags != NULL
        ? flags->bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP]
        : UINT64_C(0);
}

#if USE_DISASM_FORMAT
static uint64_t decode_flags_hash(
    const cdisasm_arm_decode_flags *flags)
{
    uint64_t hash = UINT64_C(0);
    size_t bitmap_index;

    if (flags == NULL) {
        return hash;
    }
    for (bitmap_index = 0u;
         bitmap_index < CDISASM_DECODE_FLAGS_BITMAP_COUNT;
         ++bitmap_index) {
        hash ^= flags->bitmap[bitmap_index]
            + UINT64_C(0x9e3779b97f4a7c15) * bitmap_index;
    }
    return hash;
}
#endif

static int result_is_error_only(const cdisasm_arm_instruction *instruction)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = instruction->last_error_id;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static int operand_is_zeroed(const cdisasm_arm_operand *operand)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int register_pair_is_architecturally_consecutive(
    cdisasm_arm_reg_id first,
    cdisasm_arm_reg_id second)
{
    if (first >= CDISASM_ARM_REG_W0 && first <= CDISASM_ARM_REG_W30) {
        unsigned encoding = (unsigned)(first - CDISASM_ARM_REG_W0);
        cdisasm_arm_reg_id expected = encoding == 30u
            ? CDISASM_ARM_REG_WZR
            : (cdisasm_arm_reg_id)(first + 1u);

        return (encoding & 1u) == 0u && second == expected;
    }
    if (first >= CDISASM_ARM_REG_X0 && first <= CDISASM_ARM_REG_X30) {
        unsigned encoding = (unsigned)(first - CDISASM_ARM_REG_X0);
        cdisasm_arm_reg_id expected = encoding == 30u
            ? CDISASM_ARM_REG_XZR
            : (cdisasm_arm_reg_id)(first + 1u);

        return (encoding & 1u) == 0u && second == expected;
    }
    return 0;
}

static uint32_t read_u32_le(const uint8_t *code)
{
    return (uint32_t)code[0]
        | ((uint32_t)code[1] << 8)
        | ((uint32_t)code[2] << 16)
        | ((uint32_t)code[3] << 24);
}

static uint16_t read_u16_le(const uint8_t *code)
{
    return (uint16_t)((uint16_t)code[0] | ((uint16_t)code[1] << 8));
}

static uint32_t read_u32_be(const uint8_t *code)
{
    return ((uint32_t)code[0] << 24)
        | ((uint32_t)code[1] << 16)
        | ((uint32_t)code[2] << 8)
        | (uint32_t)code[3];
}

static uint16_t read_u16_be(const uint8_t *code)
{
    return (uint16_t)(((uint16_t)code[0] << 8) | (uint16_t)code[1]);
}

static cdisasm_arm_reg_id fuzz_xreg(unsigned encoded, int use_sp)
{
    if (encoded == 31u) {
        return use_sp ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_XZR;
    }
    return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded);
}

static cdisasm_arm_reg_id fuzz_wreg(unsigned encoded)
{
    return encoded == 31u ? CDISASM_ARM_REG_WZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + encoded);
}

static void check_a64_udf_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xffff0000)) != UINT32_C(0)) {
        return;
    }
    invariant(instruction->name_id == CDISASM_ARM_NAME_UDF);
    invariant(instruction->form_id == UINT16_C(4387));
    invariant(instruction->opcode_groups == CDISASM_GROUP_INTERRUPT);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_NONE);
    invariant(instruction->operand_count == 1u);
    invariant(instruction->operand[0].type
        == CDISASM_OPERAND_IMMEDIATE);
    invariant(instruction->operand[0].imm == (word & UINT32_C(0xffff)));
    invariant(instruction->operand[0].size == 2u);
    invariant(instruction->operand[0].flags
        == CDISASM_OPERAND_FLAG_NONE);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ);
    invariant(instruction->operand[0].shift_type
        == CDISASM_ARM_SHIFT_NONE);
    invariant(instruction->operand[0].shift_amount == 0u);
}

static void check_a64_wfxt_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed;
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    const cdisasm_arm_operand *timeout;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    fixed = word & UINT32_C(0xffffffe0);
    if (fixed == UINT32_C(0xd5031000)) {
        expected_name = CDISASM_ARM_NAME_WFET;
        expected_form = UINT16_C(4457);
    } else if (fixed == UINT32_C(0xd5031020)) {
        expected_name = CDISASM_ARM_NAME_WFIT;
        expected_form = UINT16_C(4458);
    } else {
        return;
    }
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_NONE);
    invariant(instruction->operand_count == 1u);
    timeout = &instruction->operand[0];
    invariant(timeout->type == CDISASM_OPERAND_REGISTER);
    invariant(timeout->reg == fuzz_xreg(word & UINT32_C(31), 0));
    invariant(timeout->size == 8u);
    invariant(timeout->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(timeout->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(timeout->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(timeout->shift_amount == 0u);
    invariant(timeout->extend_type == CDISASM_ARM_EXTEND_NONE);
    invariant(timeout->scale == 0u);
}

static void check_a64_flagm_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    const cdisasm_arm_operand *operand;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if (word == UINT32_C(0xd500401f)) {
        expected_name = CDISASM_ARM_NAME_CFINV;
        expected_form = UINT16_C(4499);
    } else if (word == UINT32_C(0xd500403f)) {
        expected_name = CDISASM_ARM_NAME_XAFLAG;
        expected_form = UINT16_C(4500);
    } else if (word == UINT32_C(0xd500405f)) {
        expected_name = CDISASM_ARM_NAME_AXFLAG;
        expected_form = UINT16_C(4501);
    } else if ((word & UINT32_C(0xffe07c10))
            == UINT32_C(0xba000400)) {
        expected_name = CDISASM_ARM_NAME_RMIF;
        expected_form = UINT16_C(5696);
    } else if ((word & UINT32_C(0xfffffc1f))
            == UINT32_C(0x3a00080d)) {
        expected_name = CDISASM_ARM_NAME_SETF8;
        expected_form = UINT16_C(5697);
    } else if ((word & UINT32_C(0xfffffc1f))
            == UINT32_C(0x3a00480d)) {
        expected_name = CDISASM_ARM_NAME_SETF16;
        expected_form = UINT16_C(5698);
    } else {
        return;
    }

    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS
            | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK));
    if (expected_form >= UINT16_C(4499)
        && expected_form <= UINT16_C(4501)) {
        invariant(instruction->operand_count == 0u);
        return;
    }
    operand = &instruction->operand[0];
    invariant(operand->type == CDISASM_OPERAND_REGISTER);
    invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(operand->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(operand->shift_amount == 0u);
    invariant(operand->extend_type == CDISASM_ARM_EXTEND_NONE);
    invariant(operand->scale == 0u);
    if (expected_form == UINT16_C(5696)) {
        invariant(instruction->operand_count == 3u);
        invariant(operand->reg == fuzz_xreg((word >> 5) & 31u, 0));
        invariant(operand->size == 8u);
        operand = &instruction->operand[1];
        invariant(operand->type == CDISASM_OPERAND_IMMEDIATE);
        invariant(operand->imm == ((word >> 15) & 63u));
        invariant(operand->size == 1u);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->access == CDISASM_OPERAND_ACCESS_READ);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        operand = &instruction->operand[2];
        invariant(operand->type == CDISASM_OPERAND_IMMEDIATE);
        invariant(operand->imm == (word & 15u));
        invariant(operand->size == 1u);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->access == CDISASM_OPERAND_ACCESS_READ);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
    } else {
        unsigned encoded = (word >> 5) & 31u;

        invariant(instruction->operand_count == 1u);
        invariant(operand->reg == (encoded == 31u
            ? CDISASM_ARM_REG_WZR
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + encoded)));
        invariant(operand->size == 4u);
    }
}

static void check_a64_sve_ffr_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    uint32_t expected_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;
    unsigned destination = 0u;
    unsigned source = 0u;
    unsigned operand_count;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if ((word & UINT32_C(0xfffffe10)) == UINT32_C(0x2518f000)) {
        expected_name = CDISASM_ARM_NAME_RDFFR;
        expected_form = UINT16_C(2562);
        expected_flags |= CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;
        destination = word & 15u;
        source = (word >> 5) & 15u;
        operand_count = 2u;
    } else if ((word & UINT32_C(0xfffffe10))
                   == UINT32_C(0x2558f000)) {
        expected_name = CDISASM_ARM_NAME_RDFFRS;
        expected_form = UINT16_C(2563);
        expected_flags |= CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        destination = word & 15u;
        source = (word >> 5) & 15u;
        operand_count = 2u;
    } else if ((word & UINT32_C(0xfffffff0))
                   == UINT32_C(0x2519f000)) {
        expected_name = CDISASM_ARM_NAME_RDFFR;
        expected_form = UINT16_C(2564);
        destination = word & 15u;
        operand_count = 1u;
    } else if ((word & UINT32_C(0xfffffe1f))
                   == UINT32_C(0x25289000)) {
        expected_name = CDISASM_ARM_NAME_WRFFR;
        expected_form = UINT16_C(2617);
        source = (word >> 5) & 15u;
        operand_count = 1u;
    } else if (word == UINT32_C(0x252c9000)) {
        expected_name = CDISASM_ARM_NAME_SETFFR;
        expected_form = UINT16_C(2618);
        operand_count = 0u;
    } else {
        return;
    }

    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags == expected_flags);
    invariant(instruction->operand_count == operand_count);
    if (expected_form == UINT16_C(2618)) {
        return;
    }
    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == 1u);
    if (expected_form == UINT16_C(2617)) {
        invariant(instruction->operand[0].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + source));
        invariant(instruction->operand[0].flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
        invariant(instruction->operand[0].access
            == CDISASM_OPERAND_ACCESS_READ);
        return;
    }
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + destination));
    invariant(instruction->operand[0].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);
    if (operand_count == 1u) {
        return;
    }
    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + source));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == 1u);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_element_count_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t values[18] = {
        UINT32_C(0x0470c000), UINT32_C(0x0470c400),
        UINT32_C(0x04b0c000), UINT32_C(0x04b0c400),
        UINT32_C(0x04f0c000), UINT32_C(0x04f0c400),
        UINT32_C(0x0420e000), UINT32_C(0x0460e000),
        UINT32_C(0x04a0e000), UINT32_C(0x04e0e000),
        UINT32_C(0x0430e000), UINT32_C(0x0430e400),
        UINT32_C(0x0470e000), UINT32_C(0x0470e400),
        UINT32_C(0x04b0e000), UINT32_C(0x04b0e400),
        UINT32_C(0x04f0e000), UINT32_C(0x04f0e400)
    };
    static const cdisasm_arm_name_id names[18] = {
        CDISASM_ARM_NAME_INCH, CDISASM_ARM_NAME_DECH,
        CDISASM_ARM_NAME_INCW, CDISASM_ARM_NAME_DECW,
        CDISASM_ARM_NAME_INCD, CDISASM_ARM_NAME_DECD,
        CDISASM_ARM_NAME_CNTB, CDISASM_ARM_NAME_CNTH,
        CDISASM_ARM_NAME_CNTW, CDISASM_ARM_NAME_CNTD,
        CDISASM_ARM_NAME_INCB, CDISASM_ARM_NAME_DECB,
        CDISASM_ARM_NAME_INCH, CDISASM_ARM_NAME_DECH,
        CDISASM_ARM_NAME_INCW, CDISASM_ARM_NAME_DECW,
        CDISASM_ARM_NAME_INCD, CDISASM_ARM_NAME_DECD
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed;
    unsigned index;
    unsigned encoded_register;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *pattern;
    const cdisasm_arm_operand *multiplier;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    fixed = word & UINT32_C(0xfff0fc00);
    for (index = 0u; index < 18u && fixed != values[index]; ++index) {
    }
    if (index == 18u) {
        return;
    }

    encoded_register = word & 31u;
    invariant(instruction->name_id == names[index]);
    invariant(instruction->form_id == UINT16_C(2374) + index);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);
    destination = &instruction->operand[0];
    pattern = &instruction->operand[1];
    multiplier = &instruction->operand[2];
    invariant(destination->type == (index < 6u
        ? CDISASM_ARM_OPERAND_SCALABLE_REGISTER
        : CDISASM_OPERAND_REGISTER));
    invariant(destination->reg == (index < 6u
        ? (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded_register)
        : fuzz_xreg(encoded_register, 0)));
    invariant(destination->size == (index < 6u ? 0u : 8u));
    invariant(destination->extend_type == (index < 6u
        ? (uint8_t)(UINT8_C(1) << (((word >> 22) & 3u)))
        : CDISASM_ARM_EXTEND_NONE));
    invariant(destination->access == (index >= 6u && index < 10u
        ? CDISASM_OPERAND_ACCESS_WRITE
        : CDISASM_OPERAND_ACCESS_READ_WRITE));
    invariant(destination->base_reg == CDISASM_ARM_REG_NONE);
    invariant(destination->index_reg == CDISASM_ARM_REG_NONE);
    invariant(destination->register_list == 0u);
    invariant(destination->address == 0u && destination->imm == 0u);
    invariant(destination->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(destination->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(destination->shift_amount == 0u && destination->scale == 0u);
    invariant(pattern->type == CDISASM_OPERAND_IMMEDIATE);
    invariant(pattern->imm == ((word >> 5) & 31u));
    invariant(pattern->size == 1u);
    invariant(pattern->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(multiplier->type == CDISASM_OPERAND_IMMEDIATE);
    invariant(multiplier->imm == (((word >> 16) & 15u) + 1u));
    invariant(multiplier->size == 1u);
    invariant(multiplier->access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_saturating_count_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_form_id scalar_forms[4][2][4] = {
        {
            { UINT16_C(2392), UINT16_C(2393), UINT16_C(2394), UINT16_C(2395) },
            { UINT16_C(2396), UINT16_C(2416), UINT16_C(2397), UINT16_C(2417) }
        },
        {
            { UINT16_C(2398), UINT16_C(2399), UINT16_C(2400), UINT16_C(2401) },
            { UINT16_C(2402), UINT16_C(2418), UINT16_C(2403), UINT16_C(2419) }
        },
        {
            { UINT16_C(2404), UINT16_C(2405), UINT16_C(2406), UINT16_C(2407) },
            { UINT16_C(2408), UINT16_C(2420), UINT16_C(2409), UINT16_C(2421) }
        },
        {
            { UINT16_C(2410), UINT16_C(2411), UINT16_C(2412), UINT16_C(2413) },
            { UINT16_C(2414), UINT16_C(2422), UINT16_C(2415), UINT16_C(2423) }
        }
    };
    static const cdisasm_arm_name_id names[4][4] = {
        {
            CDISASM_ARM_NAME_SQINCB, CDISASM_ARM_NAME_UQINCB,
            CDISASM_ARM_NAME_SQDECB, CDISASM_ARM_NAME_UQDECB
        },
        {
            CDISASM_ARM_NAME_SQINCH, CDISASM_ARM_NAME_UQINCH,
            CDISASM_ARM_NAME_SQDECH, CDISASM_ARM_NAME_UQDECH
        },
        {
            CDISASM_ARM_NAME_SQINCW, CDISASM_ARM_NAME_UQINCW,
            CDISASM_ARM_NAME_SQDECW, CDISASM_ARM_NAME_UQDECW
        },
        {
            CDISASM_ARM_NAME_SQINCD, CDISASM_ARM_NAME_UQINCD,
            CDISASM_ARM_NAME_SQDECD, CDISASM_ARM_NAME_UQDECD
        }
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size = (word >> 22) & 3u;
    unsigned operation = (word >> 10) & 3u;
    unsigned encoded = word & 31u;
    unsigned pattern_index;
    int vector = (word & UINT32_C(0xff30f000))
        == UINT32_C(0x0420c000) && size != 0u;
    int scalar = (word & UINT32_C(0xff20f000))
        == UINT32_C(0x0420f000);
    int scalar_x = (word & UINT32_C(0x00100000)) != 0u;
    int dual = scalar && !scalar_x && (operation & 1u) == 0u;
    cdisasm_arm_form_id expected_form;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (!vector && !scalar)) {
        return;
    }
    if (vector) {
        unsigned local = ((operation & 1u) << 1) | (operation >> 1);

        expected_form = (cdisasm_arm_form_id)(UINT16_C(2362)
            + (size - 1u) * 4u + local);
    } else {
        expected_form = scalar_forms[size][scalar_x][operation];
    }
    invariant(instruction->form_id == expected_form);
    invariant(instruction->name_id == names[size][operation]);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == (dual ? 4u : 3u));
    if (vector) {
        invariant(instruction->operand[0].type
            == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
        invariant(instruction->operand[0].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[0]) == (UINT8_C(1) << size));
        invariant(instruction->operand[0].access
            == CDISASM_OPERAND_ACCESS_READ_WRITE);
    } else {
        int w_only = !scalar_x && (operation & 1u) != 0u;

        invariant(instruction->operand[0].type
            == CDISASM_OPERAND_REGISTER);
        invariant(instruction->operand[0].reg == (w_only
            ? fuzz_wreg(encoded) : fuzz_xreg(encoded, 0)));
        invariant(instruction->operand[0].size == (w_only ? 4u : 8u));
        invariant(instruction->operand[0].access == (dual
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ_WRITE));
        if (dual) {
            invariant(instruction->operand[1].type
                == CDISASM_OPERAND_REGISTER);
            invariant(instruction->operand[1].reg == fuzz_wreg(encoded));
            invariant(instruction->operand[1].size == 4u);
            invariant(instruction->operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
    }
    pattern_index = dual ? 2u : 1u;
    invariant(instruction->operand[pattern_index].type
        == CDISASM_OPERAND_IMMEDIATE);
    invariant(instruction->operand[pattern_index].imm
        == ((word >> 5) & 31u));
    invariant(instruction->operand[pattern_index].access
        == CDISASM_OPERAND_ACCESS_READ);
    invariant(instruction->operand[pattern_index + 1u].type
        == CDISASM_OPERAND_IMMEDIATE);
    invariant(instruction->operand[pattern_index + 1u].imm
        == (((word >> 16) & 15u) + 1u));
    invariant(instruction->operand[pattern_index + 1u].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_predicate_count_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t values[16] = {
        UINT32_C(0x25288000), UINT32_C(0x252a8000),
        UINT32_C(0x25298000), UINT32_C(0x252b8000),
        UINT32_C(0x252c8000), UINT32_C(0x252d8000),
        UINT32_C(0x25288800), UINT32_C(0x25298800),
        UINT32_C(0x252a8800), UINT32_C(0x252b8800),
        UINT32_C(0x25288c00), UINT32_C(0x252a8c00),
        UINT32_C(0x25298c00), UINT32_C(0x252b8c00),
        UINT32_C(0x252c8800), UINT32_C(0x252d8800)
    };
    static const cdisasm_arm_name_id names[16] = {
        CDISASM_ARM_NAME_SQINCP, CDISASM_ARM_NAME_SQDECP,
        CDISASM_ARM_NAME_UQINCP, CDISASM_ARM_NAME_UQDECP,
        CDISASM_ARM_NAME_INCP, CDISASM_ARM_NAME_DECP,
        CDISASM_ARM_NAME_SQINCP, CDISASM_ARM_NAME_UQINCP,
        CDISASM_ARM_NAME_SQDECP, CDISASM_ARM_NAME_UQDECP,
        CDISASM_ARM_NAME_SQINCP, CDISASM_ARM_NAME_SQDECP,
        CDISASM_ARM_NAME_UQINCP, CDISASM_ARM_NAME_UQDECP,
        CDISASM_ARM_NAME_INCP, CDISASM_ARM_NAME_DECP
    };
    static const uint8_t kinds[16] = {
        0u, 0u, 0u, 0u, 0u, 0u, 3u, 2u,
        3u, 2u, 1u, 1u, 1u, 1u, 1u, 1u
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed;
    unsigned size = (word >> 22) & 3u;
    unsigned encoded = word & 31u;
    unsigned predicate = (word >> 5) & 15u;
    unsigned index;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size);

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if ((word & UINT32_C(0xff3fc200)) == UINT32_C(0x25208000)) {
        invariant(instruction->form_id == UINT16_C(2597));
        invariant(instruction->name_id == CDISASM_ARM_NAME_CNTP);
        invariant(instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
        invariant(instruction->operand_count == 3u);
        invariant(instruction->operand[0].reg == fuzz_xreg(encoded, 0));
        invariant(instruction->operand[0].access
            == CDISASM_OPERAND_ACCESS_WRITE);
        invariant(instruction->operand[1].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0
                + ((word >> 10) & 15u)));
        invariant(instruction->operand[1].flags
            == CDISASM_OPERAND_FLAG_NONE);
        invariant(instruction->operand[2].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + predicate));
        invariant(instruction->operand[2].flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
        return;
    }
    if ((word & UINT32_C(0xff3fc200)) == UINT32_C(0x25218000)
        || (word & UINT32_C(0xff3fc200)) == UINT32_C(0x25228000)) {
        int last = (word & UINT32_C(0x00010000)) == 0u;

        invariant(instruction->form_id
            == (last ? UINT16_C(2599) : UINT16_C(2598)));
        invariant(instruction->name_id == (last
            ? CDISASM_ARM_NAME_LASTP : CDISASM_ARM_NAME_FIRSTP));
        invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
        invariant(instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
        invariant(instruction->operand_count == 3u);
        invariant(instruction->operand[0].type
            == CDISASM_OPERAND_REGISTER);
        invariant(instruction->operand[0].reg == fuzz_xreg(encoded, 0));
        invariant(instruction->operand[0].size == 8u);
        invariant(instruction->operand[0].access
            == CDISASM_OPERAND_ACCESS_WRITE);
        invariant(instruction->operand[1].type
            == CDISASM_ARM_OPERAND_PREDICATE);
        invariant(instruction->operand[1].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0
                + ((word >> 10) & 15u)));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[1]) == element_size);
        invariant(instruction->operand[1].flags
            == CDISASM_OPERAND_FLAG_NONE);
        invariant(instruction->operand[1].access
            == CDISASM_OPERAND_ACCESS_READ);
        invariant(instruction->operand[2].type
            == CDISASM_ARM_OPERAND_PREDICATE);
        invariant(instruction->operand[2].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + predicate));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[2]) == element_size);
        invariant(instruction->operand[2].flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
        invariant(instruction->operand[2].access
            == CDISASM_OPERAND_ACCESS_READ);
        return;
    }
    if ((word & UINT32_C(0xff3ffa00)) == UINT32_C(0x25208200)) {
        invariant(instruction->form_id == UINT16_C(2600));
        invariant(instruction->name_id == CDISASM_ARM_NAME_CNTP);
        invariant(instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
        invariant(instruction->operand_count == 3u);
        invariant(instruction->operand[0].reg == fuzz_xreg(encoded, 0));
        invariant(instruction->operand[0].access
            == CDISASM_OPERAND_ACCESS_WRITE);
        invariant(instruction->operand[1].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_PN0 + predicate));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[1]) == element_size);
        invariant(instruction->operand[1].flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
        invariant(instruction->operand[2].type
            == CDISASM_OPERAND_IMMEDIATE);
        invariant(instruction->operand[2].imm
            == ((word & UINT32_C(0x00000400)) != 0u ? 4u : 2u));
        return;
    }
    fixed = word & UINT32_C(0xff3ffe00);
    for (index = 0u; index < 16u && fixed != values[index]; ++index) {
    }
    if (index == 16u || (kinds[index] == 0u && size == 0u)) {
        return;
    }
    invariant(instruction->form_id == UINT16_C(2601) + index);
    invariant(instruction->name_id == names[index]);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == (kinds[index] == 3u ? 3u : 2u));
    if (kinds[index] == 0u) {
        invariant(instruction->operand[0].type
            == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
        invariant(instruction->operand[0].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[0]) == element_size);
        invariant(instruction->operand[0].access
            == CDISASM_OPERAND_ACCESS_READ_WRITE);
    } else {
        invariant(instruction->operand[0].type
            == CDISASM_OPERAND_REGISTER);
        invariant(instruction->operand[0].reg == (kinds[index] == 2u
            ? fuzz_wreg(encoded) : fuzz_xreg(encoded, 0)));
        invariant(instruction->operand[0].access == (kinds[index] == 3u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ_WRITE));
    }
    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + predicate));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
    if (kinds[index] == 3u) {
        invariant(instruction->operand[2].reg == fuzz_wreg(encoded));
        invariant(instruction->operand[2].size == 4u);
        invariant(instruction->operand[2].access
            == CDISASM_OPERAND_ACCESS_READ);
    }
}

static void check_sve_predicate_control_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t masks[6] = {
        UINT32_C(0xffffc21f), UINT32_C(0xfffffe10),
        UINT32_C(0xff3ffe10), UINT32_C(0xff3ffc10),
        UINT32_C(0xff3ffc10), UINT32_C(0xfffffff0)
    };
    static const uint32_t values[6] = {
        UINT32_C(0x2550c000), UINT32_C(0x2558c000),
        UINT32_C(0x2519c400), UINT32_C(0x2518e000),
        UINT32_C(0x2519e000), UINT32_C(0x2518e400)
    };
    static const cdisasm_arm_name_id names[6] = {
        CDISASM_ARM_NAME_PTEST, CDISASM_ARM_NAME_PFIRST,
        CDISASM_ARM_NAME_PNEXT, CDISASM_ARM_NAME_PTRUE,
        CDISASM_ARM_NAME_PTRUES, CDISASM_ARM_NAME_PFALSE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned index;
    unsigned pd;
    unsigned source;
    uint8_t element_size;
    uint32_t expected_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    for (index = 0u; index < 6u; ++index) {
        if ((word & masks[index]) == values[index]) {
            break;
        }
    }
    if (index == 6u) {
        return;
    }

    pd = word & 15u;
    source = (word >> 5) & 15u;
    element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    if (index == 0u) {
        expected_flags |= CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    } else if (index == 1u) {
        expected_flags |= CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;
    } else if (index == 4u) {
        expected_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    }

    invariant(instruction->form_id == UINT16_C(2556) + index);
    invariant(instruction->name_id == names[index]);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags == expected_flags);
    if (index == 0u) {
        invariant(instruction->operand_count == 2u);
        invariant(instruction->operand[0].type
            == CDISASM_ARM_OPERAND_PREDICATE);
        invariant(instruction->operand[0].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0
                + ((word >> 10) & 15u)));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[0]) == 1u);
        invariant(instruction->operand[0].flags
            == CDISASM_OPERAND_FLAG_NONE);
        invariant(instruction->operand[0].access
            == CDISASM_OPERAND_ACCESS_READ);
        invariant(instruction->operand[1].type
            == CDISASM_ARM_OPERAND_PREDICATE);
        invariant(instruction->operand[1].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + source));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[1]) == 1u);
        invariant(instruction->operand[1].flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
        invariant(instruction->operand[1].access
            == CDISASM_OPERAND_ACCESS_READ);
        return;
    }
    if (index == 1u || index == 2u) {
        uint8_t size = index == 1u ? 1u : element_size;

        invariant(instruction->operand_count == 3u);
        invariant(instruction->operand[0].type
            == CDISASM_ARM_OPERAND_PREDICATE);
        invariant(instruction->operand[0].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pd));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[0]) == size);
        invariant(instruction->operand[0].flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
        invariant(instruction->operand[0].access
            == CDISASM_OPERAND_ACCESS_WRITE);
        invariant(instruction->operand[1].type
            == CDISASM_ARM_OPERAND_PREDICATE);
        invariant(instruction->operand[1].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + source));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[1]) == size);
        invariant(instruction->operand[1].flags
            == CDISASM_OPERAND_FLAG_NONE);
        invariant(instruction->operand[1].access
            == CDISASM_OPERAND_ACCESS_READ);
        invariant(instruction->operand[2].type
            == CDISASM_ARM_OPERAND_PREDICATE);
        invariant(instruction->operand[2].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pd));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[2]) == size);
        invariant(instruction->operand[2].flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
        invariant(instruction->operand[2].access
            == CDISASM_OPERAND_ACCESS_READ);
        return;
    }
    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == (index == 5u ? 1u : element_size));
    invariant(instruction->operand[0].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);
    if (index == 3u || index == 4u) {
        invariant(instruction->operand_count == 2u);
        invariant(instruction->operand[1].type
            == CDISASM_OPERAND_IMMEDIATE);
        invariant(instruction->operand[1].imm
            == ((word >> 5) & UINT32_C(31)));
        invariant(instruction->operand[1].size == 1u);
        invariant(instruction->operand[1].flags
            == CDISASM_OPERAND_FLAG_NONE);
        invariant(instruction->operand[1].access
            == CDISASM_OPERAND_ACCESS_READ);
    } else {
        invariant(instruction->operand_count == 1u);
    }
}

static void check_sve_psel_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned tszl;
    unsigned size_log2;
    uint8_t element_size;
    uint64_t lane;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *source;
    const cdisasm_arm_operand *indexed;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff20c210)) != UINT32_C(0x25204000)) {
        return;
    }

    /* The open architectural leaf has no assembly type for tsz=0000. */
    invariant((word & UINT32_C(0x005c0000)) != 0u);
    tszl = (word >> 18) & 7u;
    size_log2 = (tszl & 1u) != 0u ? 0u
        : (tszl & 2u) != 0u ? 1u
        : (tszl & 4u) != 0u ? 2u : 3u;
    element_size = (uint8_t)(1u << size_log2);
    lane = (word >> 23) & 1u;
    if (size_log2 != 3u) {
        lane = (lane << (3u - size_log2))
            | (((word >> 22) & 1u) << (2u - size_log2))
            | (tszl >> (size_log2 + 1u));
    }

    invariant(instruction->form_id == UINT16_C(2565));
    invariant(instruction->name_id == CDISASM_ARM_NAME_PSEL);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);

    destination = &instruction->operand[0];
    source = &instruction->operand[1];
    indexed = &instruction->operand[2];
    invariant(destination->type == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(destination->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_P0 + (word & 15u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(destination)
        == element_size);
    invariant(destination->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(destination->access == CDISASM_OPERAND_ACCESS_WRITE);
    invariant(destination->base_reg == CDISASM_ARM_REG_NONE);
    invariant(destination->index_reg == CDISASM_ARM_REG_NONE);
    invariant(destination->imm == 0u);

    invariant(source->type == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(source->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_P0 + ((word >> 10) & 15u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(source) == element_size);
    invariant(source->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(source->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(source->base_reg == CDISASM_ARM_REG_NONE);
    invariant(source->index_reg == CDISASM_ARM_REG_NONE);
    invariant(source->imm == 0u);

    invariant(indexed->type == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(indexed->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_P0 + ((word >> 5) & 15u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(indexed) == element_size);
    invariant(indexed->flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(indexed->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(indexed->base_reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_W12 + ((word >> 16) & 3u)));
    invariant(indexed->index_reg == CDISASM_ARM_REG_NONE);
    invariant(indexed->imm == lane);
    invariant(indexed->register_list == 0u);
    invariant(indexed->address == 0u);
    invariant(indexed->scale == 0u);
    invariant(indexed->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(indexed->shift_amount == 0u);
}

static void check_sve_punpk_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int high = (word & UINT32_C(0x00010000)) != 0u;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *source;
    unsigned operand_index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xfffefe10)) != UINT32_C(0x05304000)) {
        return;
    }
    invariant(instruction->form_id
        == (high ? UINT16_C(2469) : UINT16_C(2468)));
    invariant(instruction->name_id == (high
        ? CDISASM_ARM_NAME_PUNPKHI : CDISASM_ARM_NAME_PUNPKLO));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 2u);

    destination = &instruction->operand[0];
    source = &instruction->operand[1];
    invariant(destination->type == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(destination->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_P0 + (word & 15u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(destination) == 2u);
    invariant(destination->flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(destination->access == CDISASM_OPERAND_ACCESS_WRITE);
    invariant(source->type == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(source->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_P0 + ((word >> 5) & 15u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(source) == 1u);
    invariant(source->flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(source->access == CDISASM_OPERAND_ACCESS_READ);

    for (operand_index = 0u; operand_index < 2u; ++operand_index) {
        const cdisasm_arm_operand *operand =
            &instruction->operand[operand_index];

        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->imm == 0u);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->size == 0u);
        invariant(operand->scale == 0u);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
    }
}

static void check_sve_unpack_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_SUNPKLO,
        CDISASM_ARM_NAME_SUNPKHI,
        CDISASM_ARM_NAME_UUNPKLO,
        CDISASM_ARM_NAME_UUNPKHI
    };
    uint32_t word = instruction->raw_instruction;
    unsigned control;
    unsigned size_code;
    uint8_t destination_size;
    unsigned operand_index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff3cfc00)) != UINT32_C(0x05303800)) {
        return;
    }
    control = (word >> 16) & 3u;
    size_code = (word >> 22) & 3u;
    invariant(size_code != 0u);
    destination_size = (uint8_t)(UINT8_C(1) << size_code);

    invariant(instruction->form_id == (cdisasm_arm_form_id)(
        UINT16_C(2456) + control));
    invariant(instruction->name_id == names[control]);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 2u);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == destination_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[1].reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == destination_size / 2u);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    for (operand_index = 0u; operand_index < 2u; ++operand_index) {
        const cdisasm_arm_operand *operand =
            &instruction->operand[operand_index];

        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->imm == 0u);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->size == 0u);
        invariant(operand->scale == 0u);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
    }
}

static void check_sve_shift_insert_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned encoded_immediate;
    unsigned element_bits;
    unsigned immediate;
    unsigned operand_index;
    int left;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff20f800)) != UINT32_C(0x4500f000)) {
        return;
    }
    encoded_immediate = (((word >> 22) & 3u) << 5)
        | ((word >> 16) & 31u);
    invariant(encoded_immediate >= 8u);
    element_bits = encoded_immediate >= 64u ? 64u
        : encoded_immediate >= 32u ? 32u
        : encoded_immediate >= 16u ? 16u : 8u;
    left = (word & UINT32_C(0x00000400)) != 0u;
    immediate = left
        ? encoded_immediate - element_bits
        : 2u * element_bits - encoded_immediate;

    invariant(instruction->form_id == (cdisasm_arm_form_id)(
        UINT16_C(2846) + (left ? 1u : 0u)));
    invariant(instruction->name_id == (left
        ? CDISASM_ARM_NAME_SLI : CDISASM_ARM_NAME_SRI));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_bits / 8u);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[1].reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_bits / 8u);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type == CDISASM_OPERAND_IMMEDIATE);
    invariant(instruction->operand[2].reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[2].imm == immediate);
    invariant(instruction->operand[2].size == 1u);
    invariant(instruction->operand[2].extend_type == CDISASM_ARM_EXTEND_NONE);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);

    for (operand_index = 0u; operand_index < 3u; ++operand_index) {
        const cdisasm_arm_operand *operand =
            &instruction->operand[operand_index];

        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand_index == 2u || operand->imm == 0u);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->scale == 0u);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        if (operand_index != 2u) {
            invariant(operand->size == 0u);
        }
    }
}

static void check_sve_bitperm_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[3] = {
        CDISASM_ARM_NAME_BEXT,
        CDISASM_ARM_NAME_BDEP,
        CDISASM_ARM_NAME_BGRP
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned operand_index;
    uint8_t element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff20f000)) != UINT32_C(0x4500b000)) {
        return;
    }
    operation = (word >> 10) & 3u;
    invariant(operation < 3u);
    element_size = (uint8_t)(UINT8_C(1) << ((word >> 22) & 3u));

    invariant(instruction->form_id == (cdisasm_arm_form_id)(
        UINT16_C(2829) + operation));
    invariant(instruction->name_id == names[operation]);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[1].reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);

    for (operand_index = 0u; operand_index < 3u; ++operand_index) {
        const cdisasm_arm_operand *operand =
            &instruction->operand[operand_index];

        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->imm == 0u);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->size == 0u);
        invariant(operand->scale == 0u);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
    }
}

static void check_sve_unpredicated_logical_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t values[4] = {
        UINT32_C(0x04203000), UINT32_C(0x04603000),
        UINT32_C(0x04a03000), UINT32_C(0x04e03000)
    };
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_AND, CDISASM_ARM_NAME_ORR,
        CDISASM_ARM_NAME_EOR, CDISASM_ARM_NAME_BIC
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xffe0fc00);
    unsigned operation;
    unsigned zd;
    unsigned zn;
    unsigned zm;
    unsigned operand_count;
    unsigned operand_index;
    int alias;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    for (operation = 0u; operation < 4u; ++operation) {
        if (fixed == values[operation]) {
            break;
        }
    }
    if (operation == 4u) {
        return;
    }
    zd = word & 31u;
    zn = (word >> 5) & 31u;
    zm = (word >> 16) & 31u;
    alias = operation == 1u && zn == zm;
    operand_count = alias ? 2u : 3u;

    invariant(instruction->form_id
        == (cdisasm_arm_form_id)(UINT16_C(2321) + operation));
    invariant(instruction->name_id
        == (alias ? CDISASM_ARM_NAME_MOV : names[operation]));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == operand_count);

    for (operand_index = 0u; operand_index < operand_count;
         ++operand_index) {
        const cdisasm_arm_operand *operand =
            &instruction->operand[operand_index];
        unsigned encoded = operand_index == 0u ? zd
            : operand_index == 1u ? zn : zm;

        invariant(operand->type
            == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_Z0 + encoded));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == 0u);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(operand->extend_type
            == (cdisasm_arm_extend_type)8u);
        invariant(operand->scale == 0u);
        invariant(operand->access == (operand_index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_sve_xar_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned encoded_immediate;
    unsigned element_bits;
    unsigned operand_index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff20fc00)) != UINT32_C(0x04203400)) {
        return;
    }
    encoded_immediate = (((word >> 22) & 3u) << 5)
        | ((word >> 16) & 31u);
    invariant(encoded_immediate >= 8u);
    element_bits = encoded_immediate >= 64u ? 64u
        : encoded_immediate >= 32u ? 32u
        : encoded_immediate >= 16u ? 16u : 8u;

    invariant(instruction->form_id == UINT16_C(2325));
    invariant(instruction->name_id == CDISASM_ARM_NAME_XAR);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u)));
    invariant(instruction->operand[0].extend_type
        == (cdisasm_arm_extend_type)(element_bits / 8u));
    invariant(instruction->operand[0].flags
        == CDISASM_OPERAND_FLAG_NONE);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[1].reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)));
    invariant(instruction->operand[1].extend_type
        == (cdisasm_arm_extend_type)(element_bits / 8u));
    invariant(instruction->operand[1].flags
        == CDISASM_OPERAND_FLAG_NONE);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_OPERAND_IMMEDIATE);
    invariant(instruction->operand[2].reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[2].imm
        == (uint64_t)(2u * element_bits - encoded_immediate));
    invariant(instruction->operand[2].size == 1u);
    invariant(instruction->operand[2].flags
        == CDISASM_OPERAND_FLAG_NONE);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);

    for (operand_index = 0u; operand_index < 3u; ++operand_index) {
        const cdisasm_arm_operand *operand =
            &instruction->operand[operand_index];

        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->scale == 0u);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        if (operand_index < 2u) {
            invariant(operand->imm == 0u);
            invariant(operand->size == 0u);
        } else {
            invariant(operand->extend_type == CDISASM_ARM_EXTEND_NONE);
        }
    }
}

static void check_sve_integer_immediate_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t masks[12] = {
        UINT32_C(0xff3fc000), UINT32_C(0xff3fc000),
        UINT32_C(0xff3fc000), UINT32_C(0xff3fc000),
        UINT32_C(0xff3fc000), UINT32_C(0xff3fc000),
        UINT32_C(0xff3fc000), UINT32_C(0xff3fe000),
        UINT32_C(0xff3fe000), UINT32_C(0xff3fe000),
        UINT32_C(0xff3fe000), UINT32_C(0xff3fe000)
    };
    static const uint32_t values[12] = {
        UINT32_C(0x2520c000), UINT32_C(0x2521c000),
        UINT32_C(0x2523c000), UINT32_C(0x2524c000),
        UINT32_C(0x2526c000), UINT32_C(0x2525c000),
        UINT32_C(0x2527c000), UINT32_C(0x2528c000),
        UINT32_C(0x252ac000), UINT32_C(0x2529c000),
        UINT32_C(0x252bc000), UINT32_C(0x2530c000)
    };
    static const cdisasm_arm_name_id names[12] = {
        CDISASM_ARM_NAME_ADD, CDISASM_ARM_NAME_SUB,
        CDISASM_ARM_NAME_SUBR, CDISASM_ARM_NAME_SQADD,
        CDISASM_ARM_NAME_SQSUB, CDISASM_ARM_NAME_UQADD,
        CDISASM_ARM_NAME_UQSUB, CDISASM_ARM_NAME_SMAX,
        CDISASM_ARM_NAME_SMIN, CDISASM_ARM_NAME_UMAX,
        CDISASM_ARM_NAME_UMIN, CDISASM_ARM_NAME_MUL
    };
    static const uint16_t form_ids[12] = {
        UINT16_C(2619), UINT16_C(2620), UINT16_C(2621), UINT16_C(2622),
        UINT16_C(2623), UINT16_C(2624), UINT16_C(2625), UINT16_C(2626),
        UINT16_C(2627), UINT16_C(2628), UINT16_C(2629), UINT16_C(2630)
    };
    uint32_t word = instruction->raw_instruction;
    unsigned index;
    unsigned encoded_immediate;
    unsigned encoded_register;
    unsigned size_code;
    int signed_immediate;
    int shifted;
    int64_t immediate_value;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *source;
    const cdisasm_arm_operand *immediate;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    for (index = 0u; index < 12u; ++index) {
        if ((word & masks[index]) == values[index]) {
            break;
        }
    }
    if (index == 12u) {
        return;
    }
    size_code = (word >> 22) & 3u;
    shifted = index < 7u
        && (word & UINT32_C(0x00002000)) != 0u;
    invariant(size_code != 0u || !shifted);
    encoded_immediate = (word >> 5) & 255u;
    encoded_register = word & 31u;
    signed_immediate = index == 7u || index == 8u || index == 11u;
    immediate_value = signed_immediate
        ? (encoded_immediate >= 128u
            ? (int64_t)encoded_immediate - INT64_C(256)
            : (int64_t)encoded_immediate)
        : (int64_t)((uint64_t)encoded_immediate
            << (shifted ? 8u : 0u));

    invariant(instruction->form_id == form_ids[index]);
    invariant(instruction->name_id == names[index]);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);
    destination = &instruction->operand[0];
    source = &instruction->operand[1];
    immediate = &instruction->operand[2];
    invariant(destination->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(destination->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + encoded_register));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(destination)
        == (uint8_t)(UINT8_C(1) << size_code));
    invariant(destination->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(destination->access == CDISASM_OPERAND_ACCESS_WRITE);
    invariant(source->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(source->reg == destination->reg);
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(source)
        == CDISASM_ARM_SCALABLE_ELEMENT_SIZE(destination));
    invariant(source->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(source->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(immediate->type == CDISASM_OPERAND_IMMEDIATE);
    invariant(immediate->imm == (uint64_t)immediate_value);
    invariant(immediate->size == 1u);
    invariant(immediate->flags == (signed_immediate
                && immediate_value < 0
            ? CDISASM_OPERAND_FLAG_SIGNED
            : CDISASM_OPERAND_FLAG_NONE));
    invariant(immediate->shift_type == (shifted
                && encoded_immediate == 0u
            ? CDISASM_ARM_SHIFT_LSL : CDISASM_ARM_SHIFT_NONE));
    invariant(immediate->shift_amount == (shifted
                && encoded_immediate == 0u ? 8u : 0u));
    invariant(immediate->access == CDISASM_OPERAND_ACCESS_READ);
}

static int64_t sve_dup_immediate_value(unsigned encoded, unsigned shifted)
{
    int64_t value = encoded >= 128u
        ? (int64_t)encoded - INT64_C(256) : (int64_t)encoded;

    return value * (shifted != 0u ? INT64_C(256) : INT64_C(1));
}

static uint64_t sve_fdup_immediate_value(
    unsigned encoded, uint8_t element_size)
{
    unsigned total_bits = 8u * element_size;
    unsigned exponent_bits = element_size == 2u ? 5u
        : element_size == 4u ? 8u : 11u;
    unsigned fraction_bits = total_bits - exponent_bits - 1u;
    unsigned selector = (encoded >> 6) & 1u;
    uint64_t exponent = (uint64_t)(selector ^ 1u)
        << (exponent_bits - 1u);

    if (selector != 0u) {
        exponent |= ((UINT64_C(1) << (exponent_bits - 3u))
                - UINT64_C(1))
            << 2u;
    }
    exponent |= (encoded >> 4) & 3u;
    return ((uint64_t)((encoded >> 7) & 1u) << (total_bits - 1u))
        | (exponent << fraction_bits)
        | ((uint64_t)(encoded & 15u) << (fraction_bits - 4u));
}

static void check_sve_dup_immediate_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned size_code;
    unsigned encoded;
    unsigned shifted;
    uint8_t element_size;
    int floating;
    int64_t integer_value;
    uint64_t expected_immediate;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *immediate;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if ((word & UINT32_C(0xff3fc000)) == UINT32_C(0x2538c000)) {
        floating = 0;
    } else if ((word & UINT32_C(0xff3fe000))
        == UINT32_C(0x2539c000)) {
        floating = 1;
    } else {
        return;
    }

    size_code = (word >> 22) & 3u;
    encoded = (word >> 5) & 255u;
    shifted = (word >> 13) & 1u;
    element_size = (uint8_t)(UINT8_C(1) << size_code);
    invariant(size_code != 0u || (!floating && shifted == 0u));
    invariant(!floating || shifted == 0u);
    integer_value = sve_dup_immediate_value(encoded, shifted);
    expected_immediate = floating
        ? sve_fdup_immediate_value(encoded, element_size)
        : (uint64_t)integer_value;

    invariant(instruction->form_id
        == (floating ? UINT16_C(2632) : UINT16_C(2631)));
    invariant(instruction->name_id == (floating
        ? CDISASM_ARM_NAME_FMOV : CDISASM_ARM_NAME_MOV));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | (floating
                ? CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT : 0u)));
    invariant(instruction->operand_count == 2u);

    destination = &instruction->operand[0];
    immediate = &instruction->operand[1];
    invariant(destination->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(destination->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(destination) == element_size);
    invariant(destination->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(destination->access == CDISASM_OPERAND_ACCESS_WRITE);
    invariant(destination->base_reg == CDISASM_ARM_REG_NONE);
    invariant(destination->index_reg == CDISASM_ARM_REG_NONE);
    invariant(destination->imm == 0u);

    invariant(immediate->type == CDISASM_OPERAND_IMMEDIATE);
    invariant(immediate->imm == expected_immediate);
    invariant(immediate->size == 1u);
    invariant(immediate->flags == (!floating && integer_value < 0
        ? CDISASM_OPERAND_FLAG_SIGNED : CDISASM_OPERAND_FLAG_NONE));
    invariant(immediate->shift_type == (!floating && shifted != 0u
                && encoded == 0u
            ? CDISASM_ARM_SHIFT_LSL : CDISASM_ARM_SHIFT_NONE));
    invariant(immediate->shift_amount == (!floating && shifted != 0u
                && encoded == 0u
            ? 8u : 0u));
    invariant(immediate->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(immediate->reg == CDISASM_ARM_REG_NONE);
    invariant(immediate->base_reg == CDISASM_ARM_REG_NONE);
    invariant(immediate->index_reg == CDISASM_ARM_REG_NONE);
    invariant(immediate->register_list == 0u);
    invariant(immediate->address == 0u);
    invariant(immediate->extend_type == CDISASM_ARM_EXTEND_NONE);
    invariant(immediate->scale == 0u);
}

static void check_sve_dot_product_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned size_code;
    unsigned zda;
    unsigned zn;
    unsigned zm;
    int is_unsigned;
    int p3;
    uint8_t destination_size;
    uint8_t source_size;
    cdisasm_arm_form_id expected_form;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *first_source;
    const cdisasm_arm_operand *second_source;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff20f800)) != UINT32_C(0x44000000)) {
        return;
    }
    size_code = (word >> 22) & 3u;
    invariant(size_code != 0u);
    is_unsigned = (word & UINT32_C(0x00000400)) != 0u;
    p3 = size_code == 1u;
    destination_size = (uint8_t)(UINT8_C(1) << size_code);
    source_size = p3 ? 1u : (uint8_t)(destination_size / 4u);
    expected_form = is_unsigned
        ? (p3 ? UINT16_C(2636) : UINT16_C(2635))
        : (p3 ? UINT16_C(2634) : UINT16_C(2633));
    zda = word & 31u;
    zn = (word >> 5) & 31u;
    zm = (word >> 16) & 31u;

    invariant(instruction->form_id == expected_form);
    invariant(instruction->name_id == (is_unsigned
        ? CDISASM_ARM_NAME_UDOT : CDISASM_ARM_NAME_SDOT));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);
    destination = &instruction->operand[0];
    first_source = &instruction->operand[1];
    second_source = &instruction->operand[2];

    invariant(destination->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(destination->reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zda));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(destination)
        == destination_size);
    invariant(destination->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(destination->access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    invariant(first_source->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(first_source->reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(first_source)
        == source_size);
    invariant(first_source->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(first_source->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(second_source->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(second_source->reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(second_source)
        == source_size);
    invariant(second_source->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(second_source->access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_usdot_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *first_source;
    const cdisasm_arm_operand *second_source;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xffe0fc00)) != UINT32_C(0x44807800)) {
        return;
    }
    invariant(instruction->form_id == UINT16_C(2656));
    invariant(instruction->name_id == CDISASM_ARM_NAME_USDOT);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);
    destination = &instruction->operand[0];
    first_source = &instruction->operand[1];
    second_source = &instruction->operand[2];

    invariant(destination->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(destination->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(destination) == 4u);
    invariant(destination->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(destination->access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    invariant(first_source->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(first_source->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(first_source) == 1u);
    invariant(first_source->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(first_source->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(second_source->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(second_source->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(second_source) == 1u);
    invariant(second_source->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(second_source->access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_dot_indexed_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *first_source;
    const cdisasm_arm_operand *indexed_source;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xffe0f800)) != UINT32_C(0x44a01800)) {
        return;
    }
    invariant(instruction->form_id == ((word & UINT32_C(0x00000400)) != 0u
        ? UINT16_C(2735) : UINT16_C(2734)));
    invariant(instruction->name_id == ((word & UINT32_C(0x00000400)) != 0u
        ? CDISASM_ARM_NAME_SUDOT : CDISASM_ARM_NAME_USDOT));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);
    destination = &instruction->operand[0];
    first_source = &instruction->operand[1];
    indexed_source = &instruction->operand[2];

    invariant(destination->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(destination->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(destination) == 4u);
    invariant(destination->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(destination->access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    invariant(destination->base_reg == CDISASM_ARM_REG_NONE);
    invariant(destination->index_reg == CDISASM_ARM_REG_NONE);
    invariant(destination->imm == 0u);

    invariant(first_source->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(first_source->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(first_source) == 1u);
    invariant(first_source->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(first_source->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(first_source->base_reg == CDISASM_ARM_REG_NONE);
    invariant(first_source->index_reg == CDISASM_ARM_REG_NONE);
    invariant(first_source->imm == 0u);

    invariant(indexed_source->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(indexed_source->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 16) & 7u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(indexed_source) == 1u);
    invariant(indexed_source->flags
        == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    invariant(indexed_source->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(indexed_source->base_reg == CDISASM_ARM_REG_NONE);
    invariant(indexed_source->index_reg == CDISASM_ARM_REG_NONE);
    invariant(indexed_source->imm == ((word >> 19) & 3u));
    invariant(indexed_source->register_list == 0u);
    invariant(indexed_source->address == 0u);
    invariant(indexed_source->size == 0u);
    invariant(indexed_source->scale == 0u);
    invariant(indexed_source->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(indexed_source->shift_amount == 0u);
}

static void check_sve_indexed_muladd_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned wide_size;
    unsigned high_size_or_lane;
    unsigned width_index;
    unsigned indexed_register;
    uint64_t lane;
    uint8_t element_size;
    int subtract;
    int mla_family;
    int sqrdml_family;
    cdisasm_arm_form_id form_base;
    cdisasm_arm_name_id expected_name;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *first_source;
    const cdisasm_arm_operand *indexed_source;

    mla_family = (word & UINT32_C(0xff20f800))
        == UINT32_C(0x44200800);
    sqrdml_family = (word & UINT32_C(0xff20f800))
        == UINT32_C(0x44201000);
    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (!mla_family && !sqrdml_family)) {
        return;
    }
    wide_size = (word >> 23) & 1u;
    high_size_or_lane = (word >> 22) & 1u;
    subtract = (word & UINT32_C(0x00000400)) != 0u;
    if (wide_size == 0u) {
        width_index = 0u;
        element_size = 2u;
        indexed_register = (word >> 16) & 7u;
        lane = (uint64_t)((high_size_or_lane << 2)
            | ((word >> 19) & 3u));
    } else if (high_size_or_lane == 0u) {
        width_index = 1u;
        element_size = 4u;
        indexed_register = (word >> 16) & 7u;
        lane = (word >> 19) & 3u;
    } else {
        width_index = 2u;
        element_size = 8u;
        indexed_register = (word >> 16) & 15u;
        lane = (word >> 20) & 1u;
    }

    form_base = sqrdml_family ? UINT16_C(2728) : UINT16_C(2722);
    expected_name = sqrdml_family
        ? (subtract
            ? CDISASM_ARM_NAME_SQRDMLSH : CDISASM_ARM_NAME_SQRDMLAH)
        : (subtract ? CDISASM_ARM_NAME_MLS : CDISASM_ARM_NAME_MLA);
    invariant(instruction->form_id == (cdisasm_arm_form_id)(
        form_base + (subtract ? UINT16_C(3) : UINT16_C(0))
        + (cdisasm_arm_form_id)width_index));
    invariant(instruction->name_id == expected_name);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);
    destination = &instruction->operand[0];
    first_source = &instruction->operand[1];
    indexed_source = &instruction->operand[2];

    invariant(destination->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(destination->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(destination)
        == element_size);
    invariant(destination->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(destination->access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    invariant(destination->base_reg == CDISASM_ARM_REG_NONE);
    invariant(destination->index_reg == CDISASM_ARM_REG_NONE);
    invariant(destination->imm == 0u);

    invariant(first_source->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(first_source->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(first_source)
        == element_size);
    invariant(first_source->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(first_source->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(first_source->base_reg == CDISASM_ARM_REG_NONE);
    invariant(first_source->index_reg == CDISASM_ARM_REG_NONE);
    invariant(first_source->imm == 0u);

    invariant(indexed_source->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(indexed_source->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + indexed_register));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(indexed_source)
        == element_size);
    invariant(indexed_source->flags
        == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    invariant(indexed_source->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(indexed_source->base_reg == CDISASM_ARM_REG_NONE);
    invariant(indexed_source->index_reg == CDISASM_ARM_REG_NONE);
    invariant(indexed_source->imm == lane);
    invariant(indexed_source->register_list == 0u);
    invariant(indexed_source->address == 0u);
    invariant(indexed_source->size == 0u);
    invariant(indexed_source->scale == 0u);
    invariant(indexed_source->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(indexed_source->shift_amount == 0u);
}

static void check_sve_aes_unary_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *source;
    cdisasm_arm_reg_id zd;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xfffffbe0)) != UINT32_C(0x4520e000)) {
        return;
    }
    invariant(instruction->form_id == ((word & UINT32_C(0x00000400)) != 0u
        ? UINT16_C(2904) : UINT16_C(2903)));
    invariant(instruction->name_id == ((word & UINT32_C(0x00000400)) != 0u
        ? CDISASM_ARM_NAME_AESIMC : CDISASM_ARM_NAME_AESMC));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 2u);
    destination = &instruction->operand[0];
    source = &instruction->operand[1];
    zd = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + (word & 31u));

    invariant(destination->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(destination->reg == zd);
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(destination) == 1u);
    invariant(destination->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(destination->access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    invariant(source->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(source->reg == zd);
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(source) == 1u);
    invariant(source->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(source->access == CDISASM_OPERAND_ACCESS_READ_WRITE);
}

static void check_sve_crypto_binary_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t values[3] = {
        UINT32_C(0x4522e000), UINT32_C(0x4522e400),
        UINT32_C(0x4523e000)
    };
    static const cdisasm_arm_form_id forms[3] = {
        UINT16_C(2905), UINT16_C(2906), UINT16_C(2907)
    };
    static const cdisasm_arm_name_id names[3] = {
        CDISASM_ARM_NAME_AESE, CDISASM_ARM_NAME_AESD,
        CDISASM_ARM_NAME_SM4E
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xfffffc00);
    cdisasm_arm_reg_id zd;
    cdisasm_arm_reg_id zm;
    uint8_t element_size;
    unsigned family;
    unsigned operand_index;

    for (family = 0u; family < 3u; ++family) {
        if (fixed == values[family]) {
            break;
        }
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64 || family == 3u) {
        return;
    }

    zd = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + (word & 31u));
    zm = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u));
    element_size = family == 2u ? 4u : 1u;
    invariant(instruction->form_id == forms[family]);
    invariant(instruction->name_id == names[family]);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);

    for (operand_index = 0u; operand_index < 3u; ++operand_index) {
        const cdisasm_arm_operand *operand =
            &instruction->operand[operand_index];

        invariant(operand->type
            == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
        invariant(operand->reg == (operand_index == 2u ? zm : zd));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand)
            == element_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->access == (operand_index == 2u
            ? CDISASM_OPERAND_ACCESS_READ
            : CDISASM_OPERAND_ACCESS_READ_WRITE));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->imm == 0u);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->size == 0u);
        invariant(operand->scale == 0u);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
    }
}

static void check_sve_predicated_shift_sat_round_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[16] = {
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_SRSHL, CDISASM_ARM_NAME_URSHL,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_SRSHLR, CDISASM_ARM_NAME_URSHLR,
        CDISASM_ARM_NAME_SQSHL, CDISASM_ARM_NAME_UQSHL,
        CDISASM_ARM_NAME_SQRSHL, CDISASM_ARM_NAME_UQRSHL,
        CDISASM_ARM_NAME_SQSHLR, CDISASM_ARM_NAME_UQSHLR,
        CDISASM_ARM_NAME_SQRSHLR, CDISASM_ARM_NAME_UQRSHLR
    };
    static const cdisasm_arm_form_id forms[16] = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_FORM_NONE,
        UINT16_C(2657), UINT16_C(2663),
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_FORM_NONE,
        UINT16_C(2658), UINT16_C(2664),
        UINT16_C(2659), UINT16_C(2665),
        UINT16_C(2660), UINT16_C(2666),
        UINT16_C(2661), UINT16_C(2667),
        UINT16_C(2662), UINT16_C(2668)
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned size_code;
    unsigned pg;
    unsigned zm;
    unsigned zdn;
    uint8_t element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff30e000)) != UINT32_C(0x44008000)) {
        return;
    }

    operation = (word >> 16) & 15u;
    size_code = (word >> 22) & 3u;
    pg = (word >> 10) & 7u;
    zm = (word >> 5) & 31u;
    zdn = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);

    invariant(names[operation] != CDISASM_ARM_NAME_NONE);
    invariant(forms[operation] != CDISASM_ARM_FORM_NONE);
    invariant(instruction->name_id == names[operation]);
    invariant(instruction->form_id == forms[operation]);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->operand_count == 4u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zdn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zdn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[3].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[3].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[3])
        == element_size);
    invariant(instruction->operand[3].flags == 0u);
    invariant(instruction->operand[3].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_predicated_sat_unary_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[2][2] = {
        { CDISASM_ARM_NAME_URECPE, CDISASM_ARM_NAME_URSQRTE },
        { CDISASM_ARM_NAME_SQABS, CDISASM_ARM_NAME_SQNEG }
    };
    uint32_t word = instruction->raw_instruction;
    unsigned saturating;
    unsigned operation;
    unsigned zeroing;
    unsigned size_code;
    unsigned pg;
    unsigned zn;
    unsigned zd;
    uint8_t element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff34e000)) != UINT32_C(0x4400a000)) {
        return;
    }

    saturating = (word >> 19) & 1u;
    operation = (word >> 16) & 1u;
    zeroing = (word >> 17) & 1u;
    size_code = (word >> 22) & 3u;
    pg = (word >> 10) & 7u;
    zn = (word >> 5) & 31u;
    zd = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);

    invariant(saturating != 0u || size_code == 2u);
    invariant(instruction->name_id == names[saturating][operation]);
    invariant(instruction->form_id == (cdisasm_arm_form_id)(
        UINT16_C(2669) + saturating * 4u + operation * 2u + zeroing));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    invariant(instruction->operand_count == 3u);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access == (zeroing != 0u
        ? CDISASM_OPERAND_ACCESS_WRITE
        : CDISASM_OPERAND_ACCESS_READ_WRITE));

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags == (zeroing != 0u
        ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
        : CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE));
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_predicated_accumulate_long_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned size_code;
    unsigned pg;
    unsigned zn;
    unsigned zda;
    uint8_t destination_size;
    uint8_t source_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff3ee000)) != UINT32_C(0x4404a000)) {
        return;
    }

    operation = (word >> 16) & 1u;
    size_code = (word >> 22) & 3u;
    pg = (word >> 10) & 7u;
    zn = (word >> 5) & 31u;
    zda = word & 31u;
    destination_size = (uint8_t)(UINT32_C(1) << size_code);
    source_size = (uint8_t)(destination_size / 2u);

    invariant(size_code != 0u);
    invariant(instruction->name_id == (operation != 0u
        ? CDISASM_ARM_NAME_UADALP : CDISASM_ARM_NAME_SADALP));
    invariant(instruction->form_id
        == (cdisasm_arm_form_id)(UINT16_C(2677) + operation));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    invariant(instruction->operand_count == 3u);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zda));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == destination_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == destination_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == source_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_predicated_halving_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_SHADD,
        CDISASM_ARM_NAME_UHADD,
        CDISASM_ARM_NAME_SHSUB,
        CDISASM_ARM_NAME_UHSUB,
        CDISASM_ARM_NAME_SRHADD,
        CDISASM_ARM_NAME_URHADD,
        CDISASM_ARM_NAME_SHSUBR,
        CDISASM_ARM_NAME_UHSUBR
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned size_code;
    unsigned pg;
    unsigned zm;
    unsigned zdn;
    uint8_t element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff38e000)) != UINT32_C(0x44108000)) {
        return;
    }

    operation = (word >> 16) & 7u;
    size_code = (word >> 22) & 3u;
    pg = (word >> 10) & 7u;
    zm = (word >> 5) & 31u;
    zdn = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);

    invariant(instruction->name_id == names[operation]);
    invariant(instruction->form_id == (cdisasm_arm_form_id)(
        UINT16_C(2679) + (operation >> 1) + (operation & 1u) * 4u));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    invariant(instruction->operand_count == 4u);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zdn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zdn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[3].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[3].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[3])
        == element_size);
    invariant(instruction->operand[3].flags == 0u);
    invariant(instruction->operand[3].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_predicated_pairwise_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_SUBP,
        CDISASM_ARM_NAME_ADDP,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_SMAXP,
        CDISASM_ARM_NAME_UMAXP,
        CDISASM_ARM_NAME_SMINP,
        CDISASM_ARM_NAME_UMINP
    };
    static const cdisasm_arm_form_id forms[8] = {
        UINT16_C(2687), UINT16_C(2688), CDISASM_ARM_FORM_NONE,
        CDISASM_ARM_FORM_NONE, UINT16_C(2689), UINT16_C(2691),
        UINT16_C(2690), UINT16_C(2692)
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned size_code;
    unsigned pg;
    unsigned zm;
    unsigned zdn;
    uint8_t element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff38e000)) != UINT32_C(0x4410a000)) {
        return;
    }

    operation = (word >> 16) & 7u;
    size_code = (word >> 22) & 3u;
    pg = (word >> 10) & 7u;
    zm = (word >> 5) & 31u;
    zdn = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);

    invariant(operation != 2u && operation != 3u);
    invariant(instruction->name_id == names[operation]);
    invariant(instruction->form_id == forms[operation]);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    invariant(instruction->operand_count == 4u);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zdn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zdn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[3].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[3].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[3])
        == element_size);
    invariant(instruction->operand[3].flags == 0u);
    invariant(instruction->operand[3].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_predicated_saturating_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_SQADD,
        CDISASM_ARM_NAME_UQADD,
        CDISASM_ARM_NAME_SQSUB,
        CDISASM_ARM_NAME_UQSUB,
        CDISASM_ARM_NAME_SUQADD,
        CDISASM_ARM_NAME_USQADD,
        CDISASM_ARM_NAME_SQSUBR,
        CDISASM_ARM_NAME_UQSUBR
    };
    static const cdisasm_arm_form_id forms[8] = {
        UINT16_C(2693), UINT16_C(2698), UINT16_C(2694), UINT16_C(2699),
        UINT16_C(2695), UINT16_C(2696), UINT16_C(2697), UINT16_C(2700)
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned size_code;
    unsigned pg;
    unsigned zm;
    unsigned zdn;
    uint8_t element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff38e000)) != UINT32_C(0x44188000)) {
        return;
    }

    operation = (word >> 16) & 7u;
    size_code = (word >> 22) & 3u;
    pg = (word >> 10) & 7u;
    zm = (word >> 5) & 31u;
    zdn = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);

    invariant(instruction->name_id == names[operation]);
    invariant(instruction->form_id == forms[operation]);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    invariant(instruction->operand_count == 4u);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zdn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zdn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[3].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[3].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[3])
        == element_size);
    invariant(instruction->operand[3].flags == 0u);
    invariant(instruction->operand[3].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_clamp_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned unsigned_operation;
    unsigned size_code;
    unsigned zd;
    unsigned zn;
    unsigned zm;
    uint8_t element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff20f800)) != UINT32_C(0x4400c000)) {
        return;
    }

    unsigned_operation = (word >> 10) & 1u;
    size_code = (word >> 22) & 3u;
    zd = word & 31u;
    zn = (word >> 5) & 31u;
    zm = (word >> 16) & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);

    invariant(instruction->name_id == (unsigned_operation != 0u
        ? CDISASM_ARM_NAME_UCLAMP : CDISASM_ARM_NAME_SCLAMP));
    invariant(instruction->form_id == (cdisasm_arm_form_id)(
        UINT16_C(2701) + unsigned_operation));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_pointer_muladd_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned zdn;
    unsigned middle;
    unsigned zm;
    unsigned first_source;
    unsigned second_source;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff20f400)) != UINT32_C(0x4400d000)
        || ((word >> 22) & 3u) != 3u) {
        return;
    }

    operation = (word >> 11) & 1u;
    zdn = word & 31u;
    middle = (word >> 5) & 31u;
    zm = (word >> 16) & 31u;
    first_source = operation != 0u ? zm : middle;
    second_source = operation != 0u ? middle : zm;

    invariant(instruction->name_id == (operation != 0u
        ? CDISASM_ARM_NAME_MADPT : CDISASM_ARM_NAME_MLAPT));
    invariant(instruction->form_id == (cdisasm_arm_form_id)(
        UINT16_C(2707) + operation));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zdn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == 8u);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + first_source));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == 8u);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + second_source));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == 8u);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_quad_permute_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_ZIPQ1,
        CDISASM_ARM_NAME_ZIPQ2,
        CDISASM_ARM_NAME_UZPQ1,
        CDISASM_ARM_NAME_UZPQ2
    };
    static const cdisasm_arm_form_id forms[4] = {
        UINT16_C(2711), UINT16_C(2714),
        UINT16_C(2712), UINT16_C(2715)
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xff20fc00);
    unsigned control;
    unsigned size_code;
    unsigned zd;
    unsigned zn;
    unsigned zm;
    uint8_t element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (fixed != UINT32_C(0x4400e000)
            && fixed != UINT32_C(0x4400e400)
            && fixed != UINT32_C(0x4400e800)
            && fixed != UINT32_C(0x4400ec00))) {
        return;
    }

    control = (word >> 10) & 3u;
    size_code = (word >> 22) & 3u;
    zd = word & 31u;
    zn = (word >> 5) & 31u;
    zm = (word >> 16) & 31u;
    element_size = (uint8_t)(UINT8_C(1) << size_code);

    invariant(instruction->name_id == names[control]);
    invariant(instruction->form_id == forms[control]);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_complex_muladd_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    unsigned family;
    uint8_t destination_size;
    uint8_t source_size;
    cdisasm_arm_form_id expected_form;
    cdisasm_arm_name_id expected_name;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *first_source;
    const cdisasm_arm_operand *second_source;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if ((word & UINT32_C(0xff20fc00)) == UINT32_C(0x44000800)) {
        family = 0u;
        invariant(size_code != 0u);
    } else if ((word & UINT32_C(0xff20fc00))
        == UINT32_C(0x44000c00)) {
        family = 1u;
        invariant(size_code != 0u);
    } else if ((word & UINT32_C(0xff20f000))
        == UINT32_C(0x44001000)) {
        family = 2u;
        invariant(size_code >= 2u);
    } else if ((word & UINT32_C(0xff20f000))
        == UINT32_C(0x44002000)) {
        family = 3u;
    } else if ((word & UINT32_C(0xff20f000))
        == UINT32_C(0x44003000)) {
        family = 4u;
    } else {
        return;
    }

    destination_size = (uint8_t)(UINT8_C(1) << size_code);
    source_size = family <= 1u
        ? (uint8_t)(destination_size / 2u)
        : family == 2u ? (uint8_t)(destination_size / 4u)
                       : destination_size;
    expected_form = (cdisasm_arm_form_id)(UINT16_C(2637) + family);
    expected_name = family == 0u ? CDISASM_ARM_NAME_SQDMLALBT
        : family == 1u ? CDISASM_ARM_NAME_SQDMLSLBT
        : family == 2u ? CDISASM_ARM_NAME_CDOT
        : family == 3u ? CDISASM_ARM_NAME_CMLA
                       : CDISASM_ARM_NAME_SQRDCMLAH;

    invariant(instruction->form_id == expected_form);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == (family >= 2u ? 4u : 3u));
    destination = &instruction->operand[0];
    first_source = &instruction->operand[1];
    second_source = &instruction->operand[2];

    invariant(destination->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(destination->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(destination)
        == destination_size);
    invariant(destination->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(destination->access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    invariant(first_source->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(first_source->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(first_source) == source_size);
    invariant(first_source->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(first_source->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(second_source->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(second_source->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(second_source) == source_size);
    invariant(second_source->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(second_source->access == CDISASM_OPERAND_ACCESS_READ);
    if (family >= 2u) {
        const cdisasm_arm_operand *rotation = &instruction->operand[3];

        invariant(rotation->type == CDISASM_OPERAND_IMMEDIATE);
        invariant(rotation->imm == ((word >> 10) & 3u) * 90u);
        invariant(rotation->size == 2u);
        invariant(rotation->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(rotation->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(rotation->shift_amount == 0u);
        invariant(rotation->extend_type == CDISASM_ARM_EXTEND_NONE);
        invariant(rotation->scale == 0u);
        invariant(rotation->access == CDISASM_OPERAND_ACCESS_READ);
        invariant(rotation->reg == CDISASM_ARM_REG_NONE);
        invariant(rotation->base_reg == CDISASM_ARM_REG_NONE);
        invariant(rotation->index_reg == CDISASM_ARM_REG_NONE);
        invariant(rotation->register_list == 0u);
        invariant(rotation->address == 0u);
    }
}

static void check_sve_widening_muladd_class(
    const cdisasm_arm_instruction *instruction)
{
    static const struct sve_widening_identity {
        uint32_t fixed_value;
        cdisasm_arm_form_id form_id;
        cdisasm_arm_name_id name_id;
    } identities[14] = {
        { UINT32_C(0x44004000), UINT16_C(2642),
          CDISASM_ARM_NAME_SMLALB },
        { UINT32_C(0x44005000), UINT16_C(2643),
          CDISASM_ARM_NAME_SMLSLB },
        { UINT32_C(0x44004400), UINT16_C(2644),
          CDISASM_ARM_NAME_SMLALT },
        { UINT32_C(0x44005400), UINT16_C(2645),
          CDISASM_ARM_NAME_SMLSLT },
        { UINT32_C(0x44004800), UINT16_C(2646),
          CDISASM_ARM_NAME_UMLALB },
        { UINT32_C(0x44005800), UINT16_C(2647),
          CDISASM_ARM_NAME_UMLSLB },
        { UINT32_C(0x44004c00), UINT16_C(2648),
          CDISASM_ARM_NAME_UMLALT },
        { UINT32_C(0x44005c00), UINT16_C(2649),
          CDISASM_ARM_NAME_UMLSLT },
        { UINT32_C(0x44006000), UINT16_C(2650),
          CDISASM_ARM_NAME_SQDMLALB },
        { UINT32_C(0x44006800), UINT16_C(2651),
          CDISASM_ARM_NAME_SQDMLSLB },
        { UINT32_C(0x44006400), UINT16_C(2652),
          CDISASM_ARM_NAME_SQDMLALT },
        { UINT32_C(0x44006c00), UINT16_C(2653),
          CDISASM_ARM_NAME_SQDMLSLT },
        { UINT32_C(0x44007000), UINT16_C(2654),
          CDISASM_ARM_NAME_SQRDMLAH },
        { UINT32_C(0x44007400), UINT16_C(2655),
          CDISASM_ARM_NAME_SQRDMLSH }
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    unsigned family;
    uint8_t destination_size;
    uint8_t source_size;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *first_source;
    const cdisasm_arm_operand *second_source;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    for (family = 0u; family < 14u; ++family) {
        if ((word & UINT32_C(0xff20fc00))
            == identities[family].fixed_value) {
            break;
        }
    }
    if (family == 14u) {
        return;
    }
    if (family < 12u) {
        invariant(size_code != 0u);
    }
    destination_size = (uint8_t)(UINT8_C(1) << size_code);
    source_size = family < 12u
        ? (uint8_t)(destination_size / 2u) : destination_size;

    invariant(instruction->form_id == identities[family].form_id);
    invariant(instruction->name_id == identities[family].name_id);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand_count == 3u);
    destination = &instruction->operand[0];
    first_source = &instruction->operand[1];
    second_source = &instruction->operand[2];

    invariant(destination->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(destination->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(destination)
        == destination_size);
    invariant(destination->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(destination->access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    invariant(first_source->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(first_source->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(first_source) == source_size);
    invariant(first_source->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(first_source->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(second_source->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(second_source->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(second_source) == source_size);
    invariant(second_source->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(second_source->access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_predicate_break_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t masks[10] = {
        UINT32_C(0xfff0c210), UINT32_C(0xfff0c210),
        UINT32_C(0xfff0c210), UINT32_C(0xfff0c210),
        UINT32_C(0xffffc200), UINT32_C(0xffffc210),
        UINT32_C(0xffffc200), UINT32_C(0xffffc210),
        UINT32_C(0xffffc210), UINT32_C(0xffffc210)
    };
    static const uint32_t values[10] = {
        UINT32_C(0x2500c000), UINT32_C(0x2540c000),
        UINT32_C(0x2500c010), UINT32_C(0x2540c010),
        UINT32_C(0x25104000), UINT32_C(0x25504000),
        UINT32_C(0x25904000), UINT32_C(0x25d04000),
        UINT32_C(0x25184000), UINT32_C(0x25584000)
    };
    static const cdisasm_arm_name_id names[10] = {
        CDISASM_ARM_NAME_BRKPA, CDISASM_ARM_NAME_BRKPAS,
        CDISASM_ARM_NAME_BRKPB, CDISASM_ARM_NAME_BRKPBS,
        CDISASM_ARM_NAME_BRKA, CDISASM_ARM_NAME_BRKAS,
        CDISASM_ARM_NAME_BRKB, CDISASM_ARM_NAME_BRKBS,
        CDISASM_ARM_NAME_BRKN, CDISASM_ARM_NAME_BRKNS
    };
    uint32_t word = instruction->raw_instruction;
    unsigned index;
    unsigned pd;
    unsigned pg;
    unsigned pn;
    int is_brkp;
    int is_brkn;
    int merging;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    for (index = 0u; index < 10u; ++index) {
        if ((word & masks[index]) == values[index]) {
            break;
        }
    }
    if (index == 10u) {
        return;
    }

    pd = word & 15u;
    pg = (word >> 10) & 15u;
    pn = (word >> 5) & 15u;
    is_brkp = index < 4u;
    is_brkn = index >= 8u;
    merging = !is_brkp && !is_brkn
        && (word & UINT32_C(0x10)) != 0u;

    invariant(instruction->form_id == UINT16_C(2546) + index);
    invariant(instruction->name_id == names[index]);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | ((word & UINT32_C(0x00400000)) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS : 0u)));
    invariant(instruction->operand_count
        == (is_brkp || is_brkn ? 4u : 3u));
    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == 1u);
    invariant(instruction->operand[0].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(instruction->operand[0].access == (merging
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_WRITE));
    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == 1u);
    invariant(instruction->operand[1].flags == (merging
        ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE
        : CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO));
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == 1u);
    invariant(instruction->operand[2].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
    if (is_brkp || is_brkn) {
        unsigned source = is_brkn ? pd : ((word >> 16) & 15u);

        invariant(instruction->operand[3].type
            == CDISASM_ARM_OPERAND_PREDICATE);
        invariant(instruction->operand[3].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + source));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[3]) == 1u);
        invariant(instruction->operand[3].flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
        invariant(instruction->operand[3].access
            == CDISASM_OPERAND_ACCESS_READ);
    }
}

static void check_sve_cterm_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xffa0fc1f);
    unsigned rn;
    unsigned rm;
    int wide;
    int not_equal;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (fixed != UINT32_C(0x25a02000)
            && fixed != UINT32_C(0x25a02010))) {
        return;
    }
    rn = (word >> 5) & 31u;
    rm = (word >> 16) & 31u;
    wide = (word & UINT32_C(0x00400000)) != 0u;
    not_equal = (word & UINT32_C(0x00000010)) != 0u;

    invariant(instruction->form_id
        == (not_equal ? UINT16_C(2594) : UINT16_C(2593)));
    invariant(instruction->name_id == (not_equal
        ? CDISASM_ARM_NAME_CTERMNE : CDISASM_ARM_NAME_CTERMEQ));
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS));
    invariant(instruction->operand_count == 2u);
    invariant(instruction->operand[0].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[0].reg
        == (wide ? fuzz_xreg(rn, 0) : fuzz_wreg(rn)));
    invariant(instruction->operand[0].size == (wide ? 8u : 4u));
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ);
    invariant(instruction->operand[1].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[1].reg
        == (wide ? fuzz_xreg(rm, 0) : fuzz_wreg(rm)));
    invariant(instruction->operand[1].size == (wide ? 8u : 4u));
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_while_single_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t values[8] = {
        UINT32_C(0x25200000), UINT32_C(0x25200800),
        UINT32_C(0x25200010), UINT32_C(0x25200810),
        UINT32_C(0x25200400), UINT32_C(0x25200c00),
        UINT32_C(0x25200410), UINT32_C(0x25200c10)
    };
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_WHILEGE, CDISASM_ARM_NAME_WHILEHS,
        CDISASM_ARM_NAME_WHILEGT, CDISASM_ARM_NAME_WHILEHI,
        CDISASM_ARM_NAME_WHILELT, CDISASM_ARM_NAME_WHILELO,
        CDISASM_ARM_NAME_WHILELE, CDISASM_ARM_NAME_WHILELS
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xff20ec10);
    unsigned index;
    unsigned size;
    unsigned pd;
    unsigned rn;
    unsigned rm;
    int wide;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    for (index = 0u; index < 8u && fixed != values[index]; ++index) {
    }
    if (index == 8u) {
        return;
    }
    size = (word >> 22) & 3u;
    pd = word & 15u;
    rn = (word >> 5) & 31u;
    rm = (word >> 16) & 31u;
    wide = (word & UINT32_C(0x00001000)) != 0u;

    invariant(instruction->form_id == UINT16_C(2585) + index);
    invariant(instruction->name_id == names[index]);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS));
    invariant(instruction->operand_count == 3u);
    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == (UINT8_C(1) << size));
    invariant(instruction->operand[0].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);
    invariant(instruction->operand[1].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[1].reg
        == (wide ? fuzz_xreg(rn, 0) : fuzz_wreg(rn)));
    invariant(instruction->operand[1].size == (wide ? 8u : 4u));
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
    invariant(instruction->operand[2].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[2].reg
        == (wide ? fuzz_xreg(rm, 0) : fuzz_wreg(rm)));
    invariant(instruction->operand[2].size == (wide ? 8u : 4u));
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_while_pair_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t values[8] = {
        UINT32_C(0x25205010), UINT32_C(0x25205810),
        UINT32_C(0x25205011), UINT32_C(0x25205811),
        UINT32_C(0x25205410), UINT32_C(0x25205c10),
        UINT32_C(0x25205411), UINT32_C(0x25205c11)
    };
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_WHILEGE, CDISASM_ARM_NAME_WHILEHS,
        CDISASM_ARM_NAME_WHILEGT, CDISASM_ARM_NAME_WHILEHI,
        CDISASM_ARM_NAME_WHILELT, CDISASM_ARM_NAME_WHILELO,
        CDISASM_ARM_NAME_WHILELE, CDISASM_ARM_NAME_WHILELS
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xff20fc11);
    unsigned index;
    unsigned size;
    unsigned pd;
    unsigned rn;
    unsigned rm;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    for (index = 0u; index < 8u && fixed != values[index]; ++index) {
    }
    if (index == 8u) {
        return;
    }
    size = (word >> 22) & 3u;
    pd = (word >> 1) & 7u;
    rn = (word >> 5) & 31u;
    rm = (word >> 16) & 31u;

    invariant(instruction->form_id == UINT16_C(2574) + index);
    invariant(instruction->name_id == names[index]);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS));
    invariant(instruction->operand_count == 3u);
    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_PREDICATE_PAIR);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pd * 2u));
    invariant(instruction->operand[0].index_reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pd * 2u + 1u));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == (UINT8_C(1) << size));
    invariant(instruction->operand[0].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);
    invariant(instruction->operand[1].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[1].reg == fuzz_xreg(rn, 0));
    invariant(instruction->operand[1].size == 8u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
    invariant(instruction->operand[2].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[2].reg == fuzz_xreg(rm, 0));
    invariant(instruction->operand[2].size == 8u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_while_counter_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t values[8] = {
        UINT32_C(0x25204010), UINT32_C(0x25204810),
        UINT32_C(0x25204018), UINT32_C(0x25204818),
        UINT32_C(0x25204410), UINT32_C(0x25204c10),
        UINT32_C(0x25204418), UINT32_C(0x25204c18)
    };
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_WHILEGE, CDISASM_ARM_NAME_WHILEHS,
        CDISASM_ARM_NAME_WHILEGT, CDISASM_ARM_NAME_WHILEHI,
        CDISASM_ARM_NAME_WHILELT, CDISASM_ARM_NAME_WHILELO,
        CDISASM_ARM_NAME_WHILELE, CDISASM_ARM_NAME_WHILELS
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xff20dc18);
    unsigned index;
    unsigned size;
    unsigned rn;
    unsigned rm;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    for (index = 0u; index < 8u && fixed != values[index]; ++index) {
    }
    if (index == 8u) {
        return;
    }
    size = (word >> 22) & 3u;
    rn = (word >> 5) & 31u;
    rm = (word >> 16) & 31u;

    invariant(instruction->form_id == UINT16_C(2566) + index);
    invariant(instruction->name_id == names[index]);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS));
    invariant(instruction->operand_count == 4u);
    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_PN8 + (word & 7u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == (UINT8_C(1) << size));
    invariant(instruction->operand[0].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);
    invariant(instruction->operand[1].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[1].reg == fuzz_xreg(rn, 0));
    invariant(instruction->operand[1].size == 8u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
    invariant(instruction->operand[2].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[2].reg == fuzz_xreg(rm, 0));
    invariant(instruction->operand[2].size == 8u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
    invariant(instruction->operand[3].type == CDISASM_OPERAND_IMMEDIATE);
    invariant(instruction->operand[3].imm
        == ((word & UINT32_C(0x00002000)) != 0u ? 4u : 2u));
    invariant(instruction->operand[3].size == 1u);
    invariant(instruction->operand[3].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_counter_mask_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned size = (word >> 22) & 3u;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size);
    unsigned first;
    unsigned source;
    unsigned lane;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if ((word & UINT32_C(0xff3ffc10)) == UINT32_C(0x25207010)) {
        invariant(instruction->form_id == UINT16_C(2582));
        invariant(instruction->name_id == CDISASM_ARM_NAME_PEXT);
        invariant(instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
        invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
        invariant(instruction->operand_count == 2u);
        invariant(instruction->operand[0].type
            == CDISASM_ARM_OPERAND_PREDICATE);
        invariant(instruction->operand[0].reg
            == (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + (word & 15u)));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[0]) == element_size);
        invariant(instruction->operand[0].flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
        invariant(instruction->operand[0].access
            == CDISASM_OPERAND_ACCESS_WRITE);
        source = (word >> 5) & 7u;
        lane = (word >> 8) & 3u;
    } else if ((word & UINT32_C(0xff3ffe10))
                   == UINT32_C(0x25207410)) {
        invariant(instruction->form_id == UINT16_C(2583));
        invariant(instruction->name_id == CDISASM_ARM_NAME_PEXT);
        invariant(instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
        invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
        invariant(instruction->operand_count == 2u);
        first = word & 15u;
        invariant(instruction->operand[0].type
            == CDISASM_ARM_OPERAND_PREDICATE_PAIR);
        invariant(instruction->operand[0].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + first));
        invariant(instruction->operand[0].index_reg
            == (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + ((first + 1u) & 15u)));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[0]) == element_size);
        invariant(instruction->operand[0].flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
        invariant(instruction->operand[0].access
            == CDISASM_OPERAND_ACCESS_WRITE);
        source = (word >> 5) & 7u;
        lane = (word >> 8) & 1u;
    } else if ((word & UINT32_C(0xff3ffff8))
                   == UINT32_C(0x25207810)) {
        invariant(instruction->form_id == UINT16_C(2584));
        invariant(instruction->name_id == CDISASM_ARM_NAME_PTRUE);
        invariant(instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
        invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
        invariant(instruction->operand_count == 1u);
        invariant(instruction->operand[0].type
            == CDISASM_ARM_OPERAND_PREDICATE);
        invariant(instruction->operand[0].reg
            == (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_PN8 + (word & 7u)));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(
            &instruction->operand[0]) == element_size);
        invariant(instruction->operand[0].flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
        invariant(instruction->operand[0].access
            == CDISASM_OPERAND_ACCESS_WRITE);
        return;
    } else {
        return;
    }
    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_PN8 + source));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == 0u);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    invariant(instruction->operand[1].imm == lane);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_whilewr_rw_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xff20fc10);
    unsigned reverse;
    unsigned size;
    unsigned pd;
    unsigned rn;
    unsigned rm;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (fixed != UINT32_C(0x25203000)
            && fixed != UINT32_C(0x25203010))) {
        return;
    }
    reverse = (word >> 4) & 1u;
    size = (word >> 22) & 3u;
    pd = word & 15u;
    rn = (word >> 5) & 31u;
    rm = (word >> 16) & 31u;

    invariant(instruction->form_id
        == (reverse != 0u ? UINT16_C(2596) : UINT16_C(2595)));
    invariant(instruction->name_id == (reverse != 0u
        ? CDISASM_ARM_NAME_WHILERW : CDISASM_ARM_NAME_WHILEWR));
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS));
    invariant(instruction->operand_count == 3u);
    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == (UINT8_C(1) << size));
    invariant(instruction->operand[0].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);
    invariant(instruction->operand[1].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[1].reg == fuzz_xreg(rn, 0));
    invariant(instruction->operand[1].size == 8u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
    invariant(instruction->operand[2].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[2].reg == fuzz_xreg(rm, 0));
    invariant(instruction->operand[2].size == 8u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_length_arithmetic_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed;
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned rd;
    unsigned rn;
    uint64_t immediate;
    unsigned immediate_index;
    int has_source;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    fixed = word & UINT32_C(0xffe0f800);
    if (fixed == UINT32_C(0x04205000)) {
        expected_name = CDISASM_ARM_NAME_ADDVL;
        expected_form = UINT16_C(2348);
        has_source = 1;
    } else if (fixed == UINT32_C(0x04605000)) {
        expected_name = CDISASM_ARM_NAME_ADDPL;
        expected_form = UINT16_C(2349);
        has_source = 1;
    } else if ((word & UINT32_C(0xfffff800))
                   == UINT32_C(0x04bf5000)) {
        expected_name = CDISASM_ARM_NAME_RDVL;
        expected_form = UINT16_C(2352);
        has_source = 0;
    } else {
        return;
    }

    rd = word & 31u;
    rn = (word >> 16) & 31u;
    immediate = (word >> 5) & 63u;
    if ((immediate & UINT64_C(32)) != 0u) {
        immediate |= ~UINT64_C(63);
    }
    immediate_index = has_source ? 2u : 1u;
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->operand_count == (has_source ? 3u : 2u));
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    invariant(instruction->operand[0].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[0].reg == fuzz_xreg(rd, has_source));
    invariant(instruction->operand[0].size == 8u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);
    if (has_source) {
        invariant(instruction->operand[1].type
            == CDISASM_OPERAND_REGISTER);
        invariant(instruction->operand[1].reg == fuzz_xreg(rn, 1));
        invariant(instruction->operand[1].size == 8u);
        invariant(instruction->operand[1].access
            == CDISASM_OPERAND_ACCESS_READ);
    }
    invariant(instruction->operand[immediate_index].type
        == CDISASM_OPERAND_IMMEDIATE);
    invariant(instruction->operand[immediate_index].imm == immediate);
    invariant(instruction->operand[immediate_index].size == 1u);
    invariant(instruction->operand[immediate_index].flags
        == ((immediate >> 63) != 0u
            ? CDISASM_OPERAND_FLAG_SIGNED : 0u));
    invariant(instruction->operand[immediate_index].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_advsimd_reverse_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xbf3ffc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned maximum_size;
    unsigned size_code;
    unsigned rn;
    unsigned rd;
    uint8_t element_size;
    uint8_t total_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if (fixed == UINT32_C(0x0e201800)) {
        expected_name = CDISASM_ARM_NAME_REV16;
        expected_form = UINT16_C(6004);
        maximum_size = 0u;
    } else if (fixed == UINT32_C(0x2e200800)) {
        expected_name = CDISASM_ARM_NAME_REV32;
        expected_form = UINT16_C(6038);
        maximum_size = 1u;
    } else if (fixed == UINT32_C(0x0e200800)) {
        expected_name = CDISASM_ARM_NAME_REV64;
        expected_form = UINT16_C(6003);
        maximum_size = 2u;
    } else {
        return;
    }

    size_code = (word >> 22) & 3u;
    rn = (word >> 5) & 31u;
    rd = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);
    total_size = (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    invariant(size_code <= maximum_size);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->operand_count == 2u);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        unsigned encoded = index == 0u ? rd : rn;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded));
        invariant(operand->size == total_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_bitcount_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xbf3ffc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned maximum_size;
    unsigned size_code;
    unsigned rn;
    unsigned rd;
    uint8_t element_size;
    uint8_t total_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if (fixed == UINT32_C(0x0e204800)) {
        expected_name = CDISASM_ARM_NAME_CLS;
        expected_form = UINT16_C(6007);
        maximum_size = 2u;
    } else if (fixed == UINT32_C(0x0e205800)) {
        expected_name = CDISASM_ARM_NAME_CNT;
        expected_form = UINT16_C(6008);
        maximum_size = 0u;
    } else if (fixed == UINT32_C(0x2e204800)) {
        expected_name = CDISASM_ARM_NAME_CLZ;
        expected_form = UINT16_C(6041);
        maximum_size = 2u;
    } else {
        return;
    }

    size_code = (word >> 22) & 3u;
    rn = (word >> 5) & 31u;
    rd = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);
    total_size = (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    invariant(size_code <= maximum_size);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->operand_count == 2u);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        unsigned encoded = index == 0u ? rd : rn;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded));
        invariant(operand->size == total_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_ext_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned q;
    unsigned imm4;
    unsigned registers[3];
    uint8_t total_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xbfe08400)) != UINT32_C(0x2e000000)) {
        return;
    }
    q = (word >> 30) & 1u;
    imm4 = (word >> 11) & 15u;
    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    total_size = q != 0u ? 16u : 8u;

    invariant(q != 0u || imm4 < 8u);
    invariant(instruction->name_id == CDISASM_ARM_NAME_EXT);
    invariant(instruction->form_id == UINT16_C(5910));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 4u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == 1u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand) == total_size);
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
    {
        const cdisasm_arm_operand *operand = &instruction->operand[3];

        invariant(operand->type == CDISASM_OPERAND_IMMEDIATE);
        invariant(operand->imm == imm4);
        invariant(operand->reg == CDISASM_ARM_REG_NONE);
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->size == 1u);
        invariant(operand->access == CDISASM_OPERAND_ACCESS_READ);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(operand->extend_type == CDISASM_ARM_EXTEND_NONE);
        invariant(operand->scale == 0u);
    }
}

static void check_crc32_register(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint8_t size, cdisasm_operand_access access)
{
    invariant(operand->type == CDISASM_OPERAND_REGISTER);
    invariant(operand->reg == reg);
    invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
    invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
    invariant(operand->register_list == 0u);
    invariant(operand->address == 0u);
    invariant(operand->imm == 0u);
    invariant(operand->size == size);
    invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(operand->shift_amount == 0u);
    invariant(operand->extend_type == CDISASM_ARM_EXTEND_NONE);
    invariant(operand->scale == 0u);
    invariant(operand->access == access);
}

static cdisasm_arm_reg_id crc32_a64_reg(unsigned encoded, int is_64)
{
    if (encoded == 31u) {
        return is_64 ? CDISASM_ARM_REG_XZR : CDISASM_ARM_REG_WZR;
    }
    return (cdisasm_arm_reg_id)(
        (is_64 ? CDISASM_ARM_REG_X0 : CDISASM_ARM_REG_W0) + encoded);
}

static void check_crc32_class(const cdisasm_arm_instruction *instruction)
{
    static const uint32_t a32_values[6] = {
        UINT32_C(0x01000040), UINT32_C(0x01200040),
        UINT32_C(0x01400040), UINT32_C(0x01000240),
        UINT32_C(0x01200240), UINT32_C(0x01400240)
    };
    static const uint32_t t32_values[6] = {
        UINT32_C(0xfac0f080), UINT32_C(0xfac0f090),
        UINT32_C(0xfac0f0a0), UINT32_C(0xfad0f080),
        UINT32_C(0xfad0f090), UINT32_C(0xfad0f0a0)
    };
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_CRC32B, CDISASM_ARM_NAME_CRC32H,
        CDISASM_ARM_NAME_CRC32W, CDISASM_ARM_NAME_CRC32X,
        CDISASM_ARM_NAME_CRC32CB, CDISASM_ARM_NAME_CRC32CH,
        CDISASM_ARM_NAME_CRC32CW, CDISASM_ARM_NAME_CRC32CX
    };
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_form_id expected_form;
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_condition expected_condition = CDISASM_ARM_CONDITION_AL;
    cdisasm_arm_reg_id expected_rd;
    cdisasm_arm_reg_id expected_rn;
    cdisasm_arm_reg_id expected_rm;
    uint32_t expected_groups = CDISASM_GROUP_NONE;
    unsigned rd;
    unsigned rn;
    unsigned rm;
    unsigned operation;
    uint8_t source_size;

    if (instruction->isa_id == CDISASM_ARM_ISA_T32) {
        word = (word << 16) | (word >> 16);
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A32) {
        for (operation = 0u; operation < 6u; ++operation) {
            if ((word & UINT32_C(0x0ff00ff0)) == a32_values[operation]) {
                break;
            }
        }
        if (operation == 6u
            || (word >> 28) == CDISASM_ARM_CONDITION_NV) {
            return;
        }
        rd = (word >> 12) & 15u;
        rn = (word >> 16) & 15u;
        rm = word & 15u;
        invariant(rd != 15u && rn != 15u && rm != 15u);
        expected_form = (cdisasm_arm_form_id)(UINT16_C(98) + operation);
        expected_name = names[operation < 3u ? operation : operation + 1u];
        expected_condition = (cdisasm_arm_condition)(word >> 28);
        expected_groups = expected_condition <= CDISASM_ARM_CONDITION_LE
            ? CDISASM_GROUP_CONDITIONAL : CDISASM_GROUP_NONE;
        expected_rd = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rd);
        expected_rn = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rn);
        expected_rm = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rm);
        source_size = (uint8_t)(UINT32_C(1) << (operation % 3u));
    } else if (instruction->isa_id == CDISASM_ARM_ISA_T32) {
        for (operation = 0u; operation < 6u; ++operation) {
            if ((word & UINT32_C(0xfff0f0f0)) == t32_values[operation]) {
                break;
            }
        }
        if (operation == 6u) {
            return;
        }
        rd = (word >> 8) & 15u;
        rn = (word >> 16) & 15u;
        rm = word & 15u;
        invariant(rd != 15u && rn != 15u && rm != 15u);
        expected_form = (cdisasm_arm_form_id)(
            UINT16_C(2169) + operation);
        expected_name = names[operation < 3u ? operation : operation + 1u];
        expected_rd = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rd);
        expected_rn = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rn);
        expected_rm = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rm);
        source_size = (uint8_t)(UINT32_C(1) << (operation % 3u));
    } else if (instruction->isa_id == CDISASM_ARM_ISA_A64
               && (word & UINT32_C(0x7fe0e000))
                    == UINT32_C(0x1ac04000)) {
        unsigned size_code = (word >> 10) & 3u;
        unsigned castagnoli = (word >> 12) & 1u;
        unsigned sf = word >> 31;

        invariant(sf == (size_code == 3u ? 1u : 0u));
        operation = castagnoli * 4u + size_code;
        rd = word & 31u;
        rn = (word >> 5) & 31u;
        rm = (word >> 16) & 31u;
        expected_form = size_code < 3u
            ? (cdisasm_arm_form_id)(UINT16_C(5582)
                + castagnoli * 3u + size_code)
            : (cdisasm_arm_form_id)(UINT16_C(5602) + castagnoli);
        expected_name = names[operation];
        expected_rd = crc32_a64_reg(rd, 0);
        expected_rn = crc32_a64_reg(rn, 0);
        expected_rm = crc32_a64_reg(rm, size_code == 3u);
        source_size = (uint8_t)(UINT32_C(1) << size_code);
    } else {
        return;
    }

    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == expected_condition);
    invariant(instruction->opcode_groups == expected_groups);
    invariant(instruction->instruction_flags == 0u);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    check_crc32_register(&instruction->operand[0], expected_rd, 4u,
        CDISASM_OPERAND_ACCESS_WRITE);
    check_crc32_register(&instruction->operand[1], expected_rn, 4u,
        CDISASM_OPERAND_ACCESS_READ);
    check_crc32_register(&instruction->operand[2], expected_rm, source_size,
        CDISASM_OPERAND_ACCESS_READ);
}

static void check_architectural_hint_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t a32_values[4] = {
        UINT32_C(0x0320f010), UINT32_C(0x0320f012),
        UINT32_C(0x0320f014), UINT32_C(0x0320f016)
    };
    static const uint32_t t32_values[4] = {
        UINT32_C(0xf3af8010), UINT32_C(0xf3af8012),
        UINT32_C(0xf3af8014), UINT32_C(0xf3af8016)
    };
    static const uint32_t a64_values[4] = {
        UINT32_C(0xd503221f), UINT32_C(0xd503225f),
        UINT32_C(0xd503229f), UINT32_C(0xd50322df)
    };
    static const cdisasm_arm_form_id a64_forms[4] = {
        UINT16_C(4471), UINT16_C(4473),
        UINT16_C(4475), UINT16_C(4476)
    };
    static const cdisasm_arm_name_id names[5] = {
        CDISASM_ARM_NAME_ESB, CDISASM_ARM_NAME_TSB,
        CDISASM_ARM_NAME_CSDB, CDISASM_ARM_NAME_CLRBHB,
        CDISASM_ARM_NAME_DBG
    };
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_form_id expected_form;
    cdisasm_arm_condition expected_condition =
        CDISASM_ARM_CONDITION_AL;
    uint32_t expected_groups = CDISASM_GROUP_NONE;
    unsigned operation;
    unsigned immediate = 0u;

    if (instruction->isa_id == CDISASM_ARM_ISA_T32) {
        word = (word << 16) | (word >> 16);
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A32) {
        if ((word >> 28) == CDISASM_ARM_CONDITION_NV) {
            return;
        }
        for (operation = 0u; operation < 4u; ++operation) {
            if ((word & UINT32_C(0x0fffffff)) == a32_values[operation]) {
                break;
            }
        }
        if (operation == 4u) {
            if ((word & UINT32_C(0x0ffffff0))
                    != UINT32_C(0x0320f0f0)) {
                return;
            }
            immediate = word & 15u;
        }
        expected_form = (cdisasm_arm_form_id)(
            UINT16_C(247) + operation);
        expected_condition = (cdisasm_arm_condition)(word >> 28);
        expected_groups = expected_condition <= CDISASM_ARM_CONDITION_LE
            ? CDISASM_GROUP_CONDITIONAL : CDISASM_GROUP_NONE;
    } else if (instruction->isa_id == CDISASM_ARM_ISA_T32) {
        for (operation = 0u; operation < 4u; ++operation) {
            if (word == t32_values[operation]) {
                break;
            }
        }
        if (operation == 4u) {
            if ((word & UINT32_C(0xfffffff0))
                    != UINT32_C(0xf3af80f0)) {
                return;
            }
            immediate = word & 15u;
        }
        expected_form = (cdisasm_arm_form_id)(
            UINT16_C(1831) + operation);
    } else if (instruction->isa_id == CDISASM_ARM_ISA_A64) {
        for (operation = 0u; operation < 4u; ++operation) {
            if (word == a64_values[operation]) {
                break;
            }
        }
        if (operation == 4u) {
            return;
        }
        expected_form = a64_forms[operation];
    } else {
        return;
    }

    invariant(instruction->form_id == expected_form);
    invariant(instruction->name_id == names[operation]);
    invariant(instruction->condition == expected_condition);
    invariant(instruction->opcode_groups == expected_groups);
    invariant(instruction->instruction_flags == 0u);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == (operation == 4u ? 1u : 0u));
    if (operation == 4u) {
        const cdisasm_arm_operand *operand = &instruction->operand[0];

        invariant(operand->type == CDISASM_OPERAND_IMMEDIATE);
        invariant(operand->reg == CDISASM_ARM_REG_NONE);
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == immediate);
        invariant(operand->size == 1u);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(operand->extend_type == CDISASM_ARM_EXTEND_NONE);
        invariant(operand->scale == 0u);
        invariant(operand->access == CDISASM_OPERAND_ACCESS_READ);
    }
}

static void check_advsimd_sha_operand(
    const cdisasm_arm_operand *operand,
    cdisasm_arm_reg_id reg,
    uint8_t size,
    uint8_t element_size,
    uint8_t element_count,
    cdisasm_operand_access access)
{
    invariant(operand->type == CDISASM_OPERAND_REGISTER);
    invariant(operand->reg == reg);
    invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
    invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
    invariant(operand->register_list == 0u);
    invariant(operand->address == 0u);
    invariant(operand->imm == 0u);
    invariant(operand->size == size);
    invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(operand->shift_amount == 0u);
    invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == element_size);
    invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand) == element_count);
    invariant(operand->access == access);
}

static int advsimd_sha_special_register(
    const cdisasm_arm_instruction *instruction, uint8_t operand_index)
{
    uint32_t fixed;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || operand_index >= 2u) {
        return 0;
    }
    if (((instruction->raw_instruction & UINT32_C(0xffe0fc00))
                == UINT32_C(0xce608000)
            && instruction->form_id == UINT16_C(6291)
            && instruction->name_id == CDISASM_ARM_NAME_SHA512H)
        || ((instruction->raw_instruction & UINT32_C(0xffe0fc00))
                == UINT32_C(0xce608400)
            && instruction->form_id == UINT16_C(6292)
            && instruction->name_id == CDISASM_ARM_NAME_SHA512H2)) {
        return 1;
    }
    fixed = instruction->raw_instruction & UINT32_C(0xffe0fc00);
    return (fixed == UINT32_C(0x5e000000)
            && instruction->form_id == UINT16_C(5731)
            && instruction->name_id == CDISASM_ARM_NAME_SHA1C)
        || (fixed == UINT32_C(0x5e001000)
            && instruction->form_id == UINT16_C(5732)
            && instruction->name_id == CDISASM_ARM_NAME_SHA1P)
        || (fixed == UINT32_C(0x5e002000)
            && instruction->form_id == UINT16_C(5733)
            && instruction->name_id == CDISASM_ARM_NAME_SHA1M)
        || (fixed == UINT32_C(0x5e004000)
            && instruction->form_id == UINT16_C(5735)
            && instruction->name_id == CDISASM_ARM_NAME_SHA256H)
        || (fixed == UINT32_C(0x5e005000)
            && instruction->form_id == UINT16_C(5736)
            && instruction->name_id == CDISASM_ARM_NAME_SHA256H2)
        || ((instruction->raw_instruction & UINT32_C(0xfffffc00))
                == UINT32_C(0x5e280800)
            && instruction->form_id == UINT16_C(5738)
            && instruction->name_id == CDISASM_ARM_NAME_SHA1H);
}

static void check_advsimd_sha_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[10] = {
        CDISASM_ARM_NAME_SHA1C, CDISASM_ARM_NAME_SHA1P,
        CDISASM_ARM_NAME_SHA1M, CDISASM_ARM_NAME_SHA1SU0,
        CDISASM_ARM_NAME_SHA256H, CDISASM_ARM_NAME_SHA256H2,
        CDISASM_ARM_NAME_SHA256SU1, CDISASM_ARM_NAME_SHA1H,
        CDISASM_ARM_NAME_SHA1SU1, CDISASM_ARM_NAME_SHA256SU0
    };
    static const cdisasm_arm_form_id a32_forms[10] = {
        UINT16_C(676), UINT16_C(687), UINT16_C(716), UINT16_C(728),
        UINT16_C(743), UINT16_C(748), UINT16_C(768), UINT16_C(819),
        UINT16_C(831), UINT16_C(832)
    };
    static const cdisasm_arm_form_id t32_forms[10] = {
        UINT16_C(1203), UINT16_C(1214), UINT16_C(1243), UINT16_C(1255),
        UINT16_C(1270), UINT16_C(1275), UINT16_C(1295), UINT16_C(1346),
        UINT16_C(1358), UINT16_C(1359)
    };
    static const cdisasm_arm_form_id a64_forms[10] = {
        UINT16_C(5731), UINT16_C(5732), UINT16_C(5733), UINT16_C(5734),
        UINT16_C(5735), UINT16_C(5736), UINT16_C(5737), UINT16_C(5738),
        UINT16_C(5739), UINT16_C(5740)
    };
    static const uint32_t sha2_values[3] = {
        UINT32_C(0x5e280800), UINT32_C(0x5e281800),
        UINT32_C(0x5e282800)
    };
    uint32_t word = instruction->raw_instruction;
    size_t operation;
    cdisasm_arm_form_id expected_form;
    unsigned rd;
    unsigned rn;
    unsigned rm;
    unsigned layout;

    if (instruction->isa_id == CDISASM_ARM_ISA_T32) {
        word = (word << 16) | (word >> 16);
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64) {
        for (operation = 0u; operation < 7u; ++operation) {
            if ((word & UINT32_C(0xffe0fc00))
                    == UINT32_C(0x5e000000)
                        + ((uint32_t)operation << 12)) {
                break;
            }
        }
        if (operation == 7u) {
            for (operation = 0u; operation < 3u; ++operation) {
                if ((word & UINT32_C(0xfffffc00))
                        == sha2_values[operation]) {
                    operation += 7u;
                    break;
                }
            }
            if (operation < 7u) {
                return;
            }
        }
        if (operation >= 10u) {
            return;
        }
        expected_form = a64_forms[operation];
        rd = word & 31u;
        rn = (word >> 5) & 31u;
        rm = (word >> 16) & 31u;
        layout = operation <= 2u ? 0u
            : operation == 3u || operation == 6u ? 1u
            : operation == 4u || operation == 5u ? 2u
            : operation == 7u ? 3u : 4u;
    } else if (instruction->isa_id == CDISASM_ARM_ISA_A32
               || instruction->isa_id == CDISASM_ARM_ISA_T32) {
        static const uint32_t a32_sha3[7] = {
            UINT32_C(0xf2000c00), UINT32_C(0xf2100c00),
            UINT32_C(0xf2200c00), UINT32_C(0xf2300c00),
            UINT32_C(0xf3000c00), UINT32_C(0xf3100c00),
            UINT32_C(0xf3200c00)
        };
        static const uint32_t t32_sha3[7] = {
            UINT32_C(0xef000c00), UINT32_C(0xef100c00),
            UINT32_C(0xef200c00), UINT32_C(0xef300c00),
            UINT32_C(0xff000c00), UINT32_C(0xff100c00),
            UINT32_C(0xff200c00)
        };
        static const uint32_t a32_sha2[3] = {
            UINT32_C(0xf3b102c0), UINT32_C(0xf3b20380),
            UINT32_C(0xf3b203c0)
        };
        static const uint32_t t32_sha2[3] = {
            UINT32_C(0xffb102c0), UINT32_C(0xffb20380),
            UINT32_C(0xffb203c0)
        };
        const uint32_t *three_values =
            instruction->isa_id == CDISASM_ARM_ISA_A32
                ? a32_sha3 : t32_sha3;
        const uint32_t *two_values =
            instruction->isa_id == CDISASM_ARM_ISA_A32
                ? a32_sha2 : t32_sha2;
        const cdisasm_arm_form_id *forms =
            instruction->isa_id == CDISASM_ARM_ISA_A32
                ? a32_forms : t32_forms;

        for (operation = 0u; operation < 7u; ++operation) {
            if ((word & UINT32_C(0xffb00f10))
                    == three_values[operation]) {
                break;
            }
        }
        if (operation == 7u) {
            for (operation = 0u; operation < 3u; ++operation) {
                if ((word & UINT32_C(0xffb30fd0))
                        == two_values[operation]) {
                    operation += 7u;
                    break;
                }
            }
            if (operation < 7u) {
                return;
            }
        }
        if (operation >= 10u) {
            return;
        }
        rd = ((word >> 18) & 16u) | ((word >> 12) & 15u);
        rn = ((word >> 3) & 16u) | ((word >> 16) & 15u);
        rm = ((word >> 1) & 16u) | (word & 15u);
        if (operation < 7u) {
            invariant((word & UINT32_C(0x40)) != 0u);
            invariant(((rd | rn | rm) & 1u) == 0u);
            layout = 5u;
        } else {
            invariant(((word >> 18) & 3u) == 2u);
            invariant(((rd | rm) & 1u) == 0u);
            layout = 6u;
        }
        expected_form = forms[operation];
        rd /= 2u;
        rn /= 2u;
        rm /= 2u;
    } else {
        return;
    }

    invariant(instruction->name_id == names[operation]);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count
        == (layout == 3u || layout == 4u || layout == 6u ? 2u : 3u));

    if (layout == 5u || layout == 6u) {
        check_advsimd_sha_operand(&instruction->operand[0],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Q0 + rd),
            16u, 4u, 4u, operation == 7u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ_WRITE);
        check_advsimd_sha_operand(&instruction->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Q0
                + (layout == 5u ? rn : rm)),
            16u, 4u, 4u, CDISASM_OPERAND_ACCESS_READ);
        if (layout == 5u) {
            check_advsimd_sha_operand(&instruction->operand[2],
                (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Q0 + rm),
                16u, 4u, 4u, CDISASM_OPERAND_ACCESS_READ);
        }
        return;
    }

    check_advsimd_sha_operand(&instruction->operand[0],
        (cdisasm_arm_reg_id)((layout == 3u ? CDISASM_ARM_REG_S0
                                          : CDISASM_ARM_REG_V0) + rd),
        layout == 3u ? 4u : 16u,
        layout == 1u || layout == 4u ? 4u
            : layout == 3u ? 0u : 16u,
        layout == 1u || layout == 4u ? 4u
            : layout == 3u ? 0u : 1u,
        operation == 7u ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ_WRITE);
    check_advsimd_sha_operand(&instruction->operand[1],
        (cdisasm_arm_reg_id)((layout == 0u || layout == 3u
                ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_V0) + rn),
        layout == 0u || layout == 3u ? 4u : 16u,
        layout == 1u || layout == 4u ? 4u
            : layout == 0u || layout == 3u ? 0u : 16u,
        layout == 1u || layout == 4u ? 4u
            : layout == 0u || layout == 3u ? 0u : 1u,
        CDISASM_OPERAND_ACCESS_READ);
    if (layout <= 2u) {
        check_advsimd_sha_operand(&instruction->operand[2],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rm),
            16u, 4u, 4u, CDISASM_OPERAND_ACCESS_READ);
    }
}

static void check_fixed_crypto_vector(
    const cdisasm_arm_operand *operand, unsigned encoded,
    uint8_t element_size, uint8_t flags, uint64_t lane,
    cdisasm_operand_access access)
{
    invariant(operand->type == CDISASM_OPERAND_REGISTER);
    invariant(operand->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_V0 + encoded));
    invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
    invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
    invariant(operand->register_list == 0u);
    invariant(operand->address == 0u);
    invariant(operand->imm == lane);
    invariant(operand->size == 16u);
    invariant(operand->flags == flags);
    invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(operand->shift_amount == 0u);
    invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == element_size);
    invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
        == 16u / element_size);
    invariant(operand->access == access);
}

static void check_fixed_crypto_immediate(
    const cdisasm_arm_operand *operand, uint64_t value)
{
    invariant(operand->type == CDISASM_OPERAND_IMMEDIATE);
    invariant(operand->reg == CDISASM_ARM_REG_NONE);
    invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
    invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
    invariant(operand->register_list == 0u);
    invariant(operand->address == 0u);
    invariant(operand->imm == value);
    invariant(operand->size == 1u);
    invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
    invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(operand->shift_amount == 0u);
    invariant(operand->extend_type == CDISASM_ARM_EXTEND_NONE);
    invariant(operand->scale == 0u);
    invariant(operand->access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_advsimd_fixed_crypto_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id tt_names[4] = {
        CDISASM_ARM_NAME_SM3TT1A, CDISASM_ARM_NAME_SM3TT1B,
        CDISASM_ARM_NAME_SM3TT2A, CDISASM_ARM_NAME_SM3TT2B
    };
    static const uint32_t three_values[7] = {
        UINT32_C(0xce608000), UINT32_C(0xce608400),
        UINT32_C(0xce608800), UINT32_C(0xce608c00),
        UINT32_C(0xce60c000), UINT32_C(0xce60c400),
        UINT32_C(0xce60c800)
    };
    static const cdisasm_arm_name_id three_names[7] = {
        CDISASM_ARM_NAME_SHA512H, CDISASM_ARM_NAME_SHA512H2,
        CDISASM_ARM_NAME_SHA512SU1, CDISASM_ARM_NAME_RAX1,
        CDISASM_ARM_NAME_SM3PARTW1, CDISASM_ARM_NAME_SM3PARTW2,
        CDISASM_ARM_NAME_SM4EKEY
    };
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_name_id expected_name = CDISASM_ARM_NAME_NONE;
    cdisasm_arm_form_id expected_form = CDISASM_ARM_FORM_NONE;
    unsigned rd = word & 31u;
    unsigned rn = (word >> 5) & 31u;
    unsigned rm = (word >> 16) & 31u;
    unsigned ra = (word >> 10) & 31u;
    unsigned layout = 0u;
    size_t operation;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if ((word & UINT32_C(0xffe0c000)) == UINT32_C(0xce408000)) {
        operation = (word >> 10) & 3u;
        expected_name = tt_names[operation];
        expected_form = (cdisasm_arm_form_id)(UINT16_C(6287) + operation);
        layout = 1u;
    } else {
        for (operation = 0u; operation < 7u; ++operation) {
            if ((word & UINT32_C(0xffe0fc00))
                    == three_values[operation]) {
                expected_name = three_names[operation];
                expected_form = (cdisasm_arm_form_id)(
                    UINT16_C(6291) + operation);
                layout = operation <= 1u ? 2u
                    : operation == 2u ? 3u
                    : operation == 3u ? 4u
                    : operation == 6u ? 11u : 5u;
                break;
            }
        }
    }
    if (expected_name == CDISASM_ARM_NAME_NONE
        && ((word & UINT32_C(0xffe08000)) == UINT32_C(0xce000000)
            || (word & UINT32_C(0xffe08000)) == UINT32_C(0xce200000)
            || (word & UINT32_C(0xffe08000)) == UINT32_C(0xce400000))) {
        uint32_t fixed = word & UINT32_C(0xffe08000);

        expected_name = fixed == UINT32_C(0xce000000)
            ? CDISASM_ARM_NAME_EOR3
            : fixed == UINT32_C(0xce200000)
                ? CDISASM_ARM_NAME_BCAX : CDISASM_ARM_NAME_SM3SS1;
        expected_form = fixed == UINT32_C(0xce000000)
            ? UINT16_C(6298)
            : fixed == UINT32_C(0xce200000)
                ? UINT16_C(6299) : UINT16_C(6300);
        layout = fixed == UINT32_C(0xce400000) ? 6u : 7u;
    }
    if (expected_name == CDISASM_ARM_NAME_NONE
        && (word & UINT32_C(0xffe00000)) == UINT32_C(0xce800000)) {
        expected_name = CDISASM_ARM_NAME_XAR;
        expected_form = UINT16_C(6301);
        layout = 8u;
    }
    if (expected_name == CDISASM_ARM_NAME_NONE
        && (word & UINT32_C(0xfffffc00)) == UINT32_C(0xcec08000)) {
        expected_name = CDISASM_ARM_NAME_SHA512SU0;
        expected_form = UINT16_C(6302);
        layout = 9u;
    }
    if (expected_name == CDISASM_ARM_NAME_NONE
        && (word & UINT32_C(0xfffffc00)) == UINT32_C(0xcec08400)) {
        expected_name = CDISASM_ARM_NAME_SM4E;
        expected_form = UINT16_C(6303);
        layout = 10u;
    }
    if (expected_name == CDISASM_ARM_NAME_NONE) {
        return;
    }

    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);

    if (layout == 1u) {
        invariant(instruction->operand_count == 3u);
        check_fixed_crypto_vector(&instruction->operand[0], rd, 4u,
            CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        check_fixed_crypto_vector(&instruction->operand[1], rn, 4u,
            CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_READ);
        check_fixed_crypto_vector(&instruction->operand[2], rm, 4u,
            CDISASM_ARM_OPERAND_FLAG_HAS_LANE, (word >> 12) & 3u,
            CDISASM_OPERAND_ACCESS_READ);
        return;
    }
    if (layout == 6u || layout == 7u) {
        uint8_t element_size = layout == 6u ? 4u : 1u;

        invariant(instruction->operand_count == 4u);
        check_fixed_crypto_vector(&instruction->operand[0], rd,
            element_size, CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_WRITE);
        check_fixed_crypto_vector(&instruction->operand[1], rn,
            element_size, CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_READ);
        check_fixed_crypto_vector(&instruction->operand[2], rm,
            element_size, CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_READ);
        check_fixed_crypto_vector(&instruction->operand[3], ra,
            element_size, CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_READ);
        return;
    }
    if (layout == 8u) {
        invariant(instruction->operand_count == 4u);
        check_fixed_crypto_vector(&instruction->operand[0], rd, 8u,
            CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_WRITE);
        check_fixed_crypto_vector(&instruction->operand[1], rn, 8u,
            CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_READ);
        check_fixed_crypto_vector(&instruction->operand[2], rm, 8u,
            CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_READ);
        check_fixed_crypto_immediate(
            &instruction->operand[3], (word >> 10) & 63u);
        return;
    }
    if (layout == 9u || layout == 10u) {
        uint8_t element_size = layout == 9u ? 8u : 4u;

        invariant(instruction->operand_count == 2u);
        check_fixed_crypto_vector(&instruction->operand[0], rd,
            element_size, CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        check_fixed_crypto_vector(&instruction->operand[1], rn,
            element_size, CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_READ);
        return;
    }
    {
        uint8_t destination_element_size = layout == 2u ? 16u
            : layout == 3u || layout == 4u ? 8u : 4u;
        uint8_t source_element_size = layout == 2u
            || layout == 3u || layout == 4u ? 8u : 4u;
        cdisasm_operand_access destination_access = layout == 4u
                || layout == 11u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ_WRITE;

        invariant(instruction->operand_count == 3u);
        check_fixed_crypto_vector(&instruction->operand[0], rd,
            destination_element_size, CDISASM_OPERAND_FLAG_NONE, 0u,
            destination_access);
        check_fixed_crypto_vector(&instruction->operand[1], rn,
            destination_element_size, CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_READ);
        check_fixed_crypto_vector(&instruction->operand[2], rm,
            source_element_size, CDISASM_OPERAND_FLAG_NONE, 0u,
            CDISASM_OPERAND_ACCESS_READ);
    }
}

static void check_advsimd_bitwise_select_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xbfe0fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned registers[3];
    uint8_t total_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if (fixed == UINT32_C(0x2e601c00)) {
        expected_name = CDISASM_ARM_NAME_BSL;
        expected_form = UINT16_C(6188);
    } else if (fixed == UINT32_C(0x2ea01c00)) {
        expected_name = CDISASM_ARM_NAME_BIT;
        expected_form = UINT16_C(6196);
    } else if (fixed == UINT32_C(0x2ee01c00)) {
        expected_name = CDISASM_ARM_NAME_BIF;
        expected_form = UINT16_C(6198);
    } else {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    total_size = (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == 1u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == total_size);
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_high_narrow_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xbf20fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned registers[3];
    unsigned size_code;
    int high;
    uint8_t result_element_size;
    uint8_t source_element_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if (fixed == UINT32_C(0x0e204000)) {
        expected_name = CDISASM_ARM_NAME_ADDHN;
        expected_form = UINT16_C(6093);
    } else if (fixed == UINT32_C(0x0e206000)) {
        expected_name = CDISASM_ARM_NAME_SUBHN;
        expected_form = UINT16_C(6095);
    } else if (fixed == UINT32_C(0x2e204000)) {
        expected_name = CDISASM_ARM_NAME_RADDHN;
        expected_form = UINT16_C(6108);
    } else if (fixed == UINT32_C(0x2e206000)) {
        expected_name = CDISASM_ARM_NAME_RSUBHN;
        expected_form = UINT16_C(6110);
    } else {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    size_code = (word >> 22) & 3u;
    high = (word & UINT32_C(0x40000000)) != 0u;
    result_element_size = (uint8_t)(UINT32_C(1) << size_code);
    source_element_size = (uint8_t)(result_element_size * 2u);
    invariant(size_code <= 2u);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        uint8_t element_size = index == 0u
            ? result_element_size : source_element_size;
        uint8_t total_size = index == 0u && !high ? 8u : 16u;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index != 0u
            ? CDISASM_OPERAND_ACCESS_READ
            : high ? CDISASM_OPERAND_ACCESS_READ_WRITE
                   : CDISASM_OPERAND_ACCESS_WRITE));
    }
}

static void check_advsimd_widening_add_sub_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xbf20fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned registers[3];
    unsigned size_code;
    int high;
    int wide_first;
    uint8_t source_element_size;
    uint8_t result_element_size;
    uint8_t narrow_total_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if (fixed == UINT32_C(0x0e200000)) {
        expected_name = CDISASM_ARM_NAME_SADDL;
        expected_form = UINT16_C(6089);
        wide_first = 0;
    } else if (fixed == UINT32_C(0x0e201000)) {
        expected_name = CDISASM_ARM_NAME_SADDW;
        expected_form = UINT16_C(6090);
        wide_first = 1;
    } else if (fixed == UINT32_C(0x0e202000)) {
        expected_name = CDISASM_ARM_NAME_SSUBL;
        expected_form = UINT16_C(6091);
        wide_first = 0;
    } else if (fixed == UINT32_C(0x0e203000)) {
        expected_name = CDISASM_ARM_NAME_SSUBW;
        expected_form = UINT16_C(6092);
        wide_first = 1;
    } else if (fixed == UINT32_C(0x2e200000)) {
        expected_name = CDISASM_ARM_NAME_UADDL;
        expected_form = UINT16_C(6104);
        wide_first = 0;
    } else if (fixed == UINT32_C(0x2e201000)) {
        expected_name = CDISASM_ARM_NAME_UADDW;
        expected_form = UINT16_C(6105);
        wide_first = 1;
    } else if (fixed == UINT32_C(0x2e202000)) {
        expected_name = CDISASM_ARM_NAME_USUBL;
        expected_form = UINT16_C(6106);
        wide_first = 0;
    } else if (fixed == UINT32_C(0x2e203000)) {
        expected_name = CDISASM_ARM_NAME_USUBW;
        expected_form = UINT16_C(6107);
        wide_first = 1;
    } else {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    size_code = (word >> 22) & 3u;
    high = (word & UINT32_C(0x40000000)) != 0u;
    source_element_size = (uint8_t)(UINT32_C(1) << size_code);
    result_element_size = (uint8_t)(source_element_size * 2u);
    narrow_total_size = high ? 16u : 8u;
    invariant(size_code <= 2u);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        uint8_t element_size = index == 0u
            || (index == 1u && wide_first)
            ? result_element_size : source_element_size;
        uint8_t total_size = index == 0u
            || (index == 1u && wide_first)
            ? 16u : narrow_total_size;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_absolute_difference_long_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xbf20fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned registers[3];
    unsigned size_code;
    int high;
    int accumulate;
    uint8_t source_element_size;
    uint8_t result_element_size;
    uint8_t narrow_total_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if (fixed == UINT32_C(0x0e205000)) {
        expected_name = CDISASM_ARM_NAME_SABAL;
        expected_form = UINT16_C(6094);
        accumulate = 1;
    } else if (fixed == UINT32_C(0x0e207000)) {
        expected_name = CDISASM_ARM_NAME_SABDL;
        expected_form = UINT16_C(6096);
        accumulate = 0;
    } else if (fixed == UINT32_C(0x2e205000)) {
        expected_name = CDISASM_ARM_NAME_UABAL;
        expected_form = UINT16_C(6109);
        accumulate = 1;
    } else if (fixed == UINT32_C(0x2e207000)) {
        expected_name = CDISASM_ARM_NAME_UABDL;
        expected_form = UINT16_C(6111);
        accumulate = 0;
    } else {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    size_code = (word >> 22) & 3u;
    high = (word & UINT32_C(0x40000000)) != 0u;
    source_element_size = (uint8_t)(UINT32_C(1) << size_code);
    result_element_size = (uint8_t)(source_element_size * 2u);
    narrow_total_size = high ? 16u : 8u;
    invariant(size_code <= 2u);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        uint8_t element_size = index == 0u
            ? result_element_size : source_element_size;
        uint8_t total_size = index == 0u ? 16u : narrow_total_size;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index != 0u
            ? CDISASM_OPERAND_ACCESS_READ
            : accumulate ? CDISASM_OPERAND_ACCESS_READ_WRITE
                         : CDISASM_OPERAND_ACCESS_WRITE));
    }
}

static void check_advsimd_absolute_difference_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf20fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned registers[3];
    unsigned size_code;
    uint8_t vector_size;
    uint8_t element_size;
    size_t index;

    if (operation == UINT32_C(0x0e207400)) {
        expected_name = CDISASM_ARM_NAME_SABD;
        expected_form = UINT16_C(6128);
    } else if (operation == UINT32_C(0x2e207400)) {
        expected_name = CDISASM_ARM_NAME_UABD;
        expected_form = UINT16_C(6170);
    } else {
        return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    size_code = (word >> 22) & 3u;
    vector_size = (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    element_size = (uint8_t)(UINT8_C(1) << size_code);
    invariant(size_code <= 2u);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == vector_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(vector_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_absolute_difference_accumulate_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf20fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned registers[3];
    unsigned size_code;
    uint8_t vector_size;
    uint8_t element_size;
    size_t index;

    if (operation == UINT32_C(0x0e207c00)) {
        expected_name = CDISASM_ARM_NAME_SABA;
        expected_form = UINT16_C(6129);
    } else if (operation == UINT32_C(0x2e207c00)) {
        expected_name = CDISASM_ARM_NAME_UABA;
        expected_form = UINT16_C(6171);
    } else {
        return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    size_code = (word >> 22) & 3u;
    vector_size = (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    element_size = (uint8_t)(UINT8_C(1) << size_code);
    invariant(size_code <= 2u);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == vector_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(vector_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_multiply_accumulate_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf20fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned registers[3];
    unsigned size_code;
    uint8_t vector_size;
    uint8_t element_size;
    size_t index;

    if (operation == UINT32_C(0x0e209400)) {
        expected_name = CDISASM_ARM_NAME_MLA;
        expected_form = UINT16_C(6132);
    } else if (operation == UINT32_C(0x2e209400)) {
        expected_name = CDISASM_ARM_NAME_MLS;
        expected_form = UINT16_C(6174);
    } else {
        return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    size_code = (word >> 22) & 3u;
    vector_size = (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    element_size = (uint8_t)(UINT8_C(1) << size_code);
    invariant(size_code <= 2u);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == vector_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(vector_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_multiply_accumulate_element_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf00f400);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned size_code;
    unsigned indexed_register;
    uint64_t lane;
    uint8_t vector_size;
    uint8_t element_size;
    size_t index;

    if (operation == UINT32_C(0x2f000000)) {
        expected_name = CDISASM_ARM_NAME_MLA;
        expected_form = UINT16_C(6268);
    } else if (operation == UINT32_C(0x2f004000)) {
        expected_name = CDISASM_ARM_NAME_MLS;
        expected_form = UINT16_C(6270);
    } else {
        return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }

    size_code = (word >> 22) & 3u;
    invariant(size_code == 1u || size_code == 2u);
    element_size = size_code == 1u ? 2u : 4u;
    vector_size = (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    if (size_code == 1u) {
        indexed_register = (word >> 16) & 15u;
        lane = (uint64_t)((((word >> 11) & 1u) << 2)
            | (((word >> 21) & 1u) << 1)
            | ((word >> 20) & 1u));
    } else {
        indexed_register = (word >> 16) & 31u;
        lane = (uint64_t)((((word >> 11) & 1u) << 1)
            | ((word >> 21) & 1u));
    }

    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        unsigned encoded = index == 0u
            ? word & 31u : (word >> 5) & 31u;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + encoded));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == vector_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(vector_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
    invariant(instruction->operand[2].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[2].reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_V0 + indexed_register));
    invariant(instruction->operand[2].base_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[2].index_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[2].register_list == 0u);
    invariant(instruction->operand[2].address == 0u);
    invariant(instruction->operand[2].imm == lane);
    invariant(instruction->operand[2].size == 16u);
    invariant(instruction->operand[2].flags
        == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    invariant(instruction->operand[2].shift_type
        == CDISASM_ARM_SHIFT_NONE);
    invariant(instruction->operand[2].shift_amount == 0u);
    invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(&instruction->operand[2])
        == (uint8_t)(16u / element_size));
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_advsimd_widening_multiply_element_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf00f400);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    int accumulate;
    unsigned size_code;
    unsigned indexed_register;
    uint64_t lane;
    uint8_t source_vector_size;
    uint8_t source_element_size;
    uint8_t result_element_size;

    if (operation == UINT32_C(0x0f002000)) {
        expected_name = CDISASM_ARM_NAME_SMLAL;
        expected_form = UINT16_C(6243);
        accumulate = 1;
    } else if (operation == UINT32_C(0x0f003000)) {
        expected_name = CDISASM_ARM_NAME_SQDMLAL;
        expected_form = UINT16_C(6244);
        accumulate = 1;
    } else if (operation == UINT32_C(0x0f006000)) {
        expected_name = CDISASM_ARM_NAME_SMLSL;
        expected_form = UINT16_C(6245);
        accumulate = 1;
    } else if (operation == UINT32_C(0x0f007000)) {
        expected_name = CDISASM_ARM_NAME_SQDMLSL;
        expected_form = UINT16_C(6246);
        accumulate = 1;
    } else if (operation == UINT32_C(0x0f00a000)) {
        expected_name = CDISASM_ARM_NAME_SMULL;
        expected_form = UINT16_C(6248);
        accumulate = 0;
    } else if (operation == UINT32_C(0x0f00b000)) {
        expected_name = CDISASM_ARM_NAME_SQDMULL;
        expected_form = UINT16_C(6249);
        accumulate = 0;
    } else if (operation == UINT32_C(0x2f002000)) {
        expected_name = CDISASM_ARM_NAME_UMLAL;
        expected_form = UINT16_C(6269);
        accumulate = 1;
    } else if (operation == UINT32_C(0x2f006000)) {
        expected_name = CDISASM_ARM_NAME_UMLSL;
        expected_form = UINT16_C(6271);
        accumulate = 1;
    } else if (operation == UINT32_C(0x2f00a000)) {
        expected_name = CDISASM_ARM_NAME_UMULL;
        expected_form = UINT16_C(6272);
        accumulate = 0;
    } else {
        return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }

    size_code = (word >> 22) & 3u;
    invariant(size_code == 1u || size_code == 2u);
    source_element_size = size_code == 1u ? 2u : 4u;
    result_element_size = (uint8_t)(source_element_size * 2u);
    source_vector_size =
        (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    if (size_code == 1u) {
        indexed_register = (word >> 16) & 15u;
        lane = (uint64_t)((((word >> 11) & 1u) << 2)
            | (((word >> 21) & 1u) << 1)
            | ((word >> 20) & 1u));
    } else {
        indexed_register = (word >> 16) & 31u;
        lane = (uint64_t)((((word >> 11) & 1u) << 1)
            | ((word >> 21) & 1u));
    }

    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);

    invariant(instruction->operand[0].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[0].reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_V0 + (word & 31u)));
    invariant(instruction->operand[0].base_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[0].index_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[0].register_list == 0u);
    invariant(instruction->operand[0].address == 0u);
    invariant(instruction->operand[0].imm == 0u);
    invariant(instruction->operand[0].size == 16u);
    invariant(instruction->operand[0].flags
        == CDISASM_OPERAND_FLAG_NONE);
    invariant(instruction->operand[0].shift_type
        == CDISASM_ARM_SHIFT_NONE);
    invariant(instruction->operand[0].shift_amount == 0u);
    invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction->operand[0])
        == result_element_size);
    invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(&instruction->operand[0])
        == (uint8_t)(16u / result_element_size));
    invariant(instruction->operand[0].access
        == (accumulate ? CDISASM_OPERAND_ACCESS_READ_WRITE
                       : CDISASM_OPERAND_ACCESS_WRITE));

    invariant(instruction->operand[1].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[1].reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)));
    invariant(instruction->operand[1].base_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[1].index_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[1].register_list == 0u);
    invariant(instruction->operand[1].address == 0u);
    invariant(instruction->operand[1].imm == 0u);
    invariant(instruction->operand[1].size == source_vector_size);
    invariant(instruction->operand[1].flags
        == CDISASM_OPERAND_FLAG_NONE);
    invariant(instruction->operand[1].shift_type
        == CDISASM_ARM_SHIFT_NONE);
    invariant(instruction->operand[1].shift_amount == 0u);
    invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction->operand[1])
        == source_element_size);
    invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(&instruction->operand[1])
        == (uint8_t)(source_vector_size / source_element_size));
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[2].reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_V0 + indexed_register));
    invariant(instruction->operand[2].base_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[2].index_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[2].register_list == 0u);
    invariant(instruction->operand[2].address == 0u);
    invariant(instruction->operand[2].imm == lane);
    invariant(instruction->operand[2].size == 16u);
    invariant(instruction->operand[2].flags
        == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    invariant(instruction->operand[2].shift_type
        == CDISASM_ARM_SHIFT_NONE);
    invariant(instruction->operand[2].shift_amount == 0u);
    invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction->operand[2])
        == source_element_size);
    invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(&instruction->operand[2])
        == (uint8_t)(16u / source_element_size));
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_advsimd_widening_multiply_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xbf20fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned registers[3];
    unsigned size_code;
    int high;
    int accumulate;
    uint8_t source_element_size;
    uint8_t result_element_size;
    uint8_t narrow_total_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if (fixed == UINT32_C(0x0e208000)) {
        expected_name = CDISASM_ARM_NAME_SMLAL;
        expected_form = UINT16_C(6097);
        accumulate = 1;
    } else if (fixed == UINT32_C(0x0e20a000)) {
        expected_name = CDISASM_ARM_NAME_SMLSL;
        expected_form = UINT16_C(6099);
        accumulate = 1;
    } else if (fixed == UINT32_C(0x0e20c000)) {
        expected_name = CDISASM_ARM_NAME_SMULL;
        expected_form = UINT16_C(6101);
        accumulate = 0;
    } else if (fixed == UINT32_C(0x2e208000)) {
        expected_name = CDISASM_ARM_NAME_UMLAL;
        expected_form = UINT16_C(6112);
        accumulate = 1;
    } else if (fixed == UINT32_C(0x2e20a000)) {
        expected_name = CDISASM_ARM_NAME_UMLSL;
        expected_form = UINT16_C(6113);
        accumulate = 1;
    } else if (fixed == UINT32_C(0x2e20c000)) {
        expected_name = CDISASM_ARM_NAME_UMULL;
        expected_form = UINT16_C(6114);
        accumulate = 0;
    } else {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    size_code = (word >> 22) & 3u;
    high = (word & UINT32_C(0x40000000)) != 0u;
    source_element_size = (uint8_t)(UINT32_C(1) << size_code);
    result_element_size = (uint8_t)(source_element_size * 2u);
    narrow_total_size = high ? 16u : 8u;
    invariant(size_code <= 2u);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        uint8_t element_size = index == 0u
            ? result_element_size : source_element_size;
        uint8_t total_size = index == 0u ? 16u : narrow_total_size;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index != 0u
            ? CDISASM_OPERAND_ACCESS_READ
            : accumulate ? CDISASM_OPERAND_ACCESS_READ_WRITE
                         : CDISASM_OPERAND_ACCESS_WRITE));
    }
}

static void check_advsimd_saturating_widening_multiply_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xbf20fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned registers[3];
    unsigned size_code;
    int high;
    int accumulate;
    uint8_t source_element_size;
    uint8_t result_element_size;
    uint8_t source_total_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if (fixed == UINT32_C(0x0e209000)) {
        expected_name = CDISASM_ARM_NAME_SQDMLAL;
        expected_form = UINT16_C(6098);
        accumulate = 1;
    } else if (fixed == UINT32_C(0x0e20b000)) {
        expected_name = CDISASM_ARM_NAME_SQDMLSL;
        expected_form = UINT16_C(6100);
        accumulate = 1;
    } else if (fixed == UINT32_C(0x0e20d000)) {
        expected_name = CDISASM_ARM_NAME_SQDMULL;
        expected_form = UINT16_C(6102);
        accumulate = 0;
    } else {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    size_code = (word >> 22) & 3u;
    high = (word & UINT32_C(0x40000000)) != 0u;
    source_element_size = (uint8_t)(UINT32_C(1) << size_code);
    result_element_size = (uint8_t)(source_element_size * 2u);
    source_total_size = high ? 16u : 8u;
    invariant(size_code == 1u || size_code == 2u);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        uint8_t element_size = index == 0u
            ? result_element_size : source_element_size;
        uint8_t total_size = index == 0u ? 16u : source_total_size;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index != 0u
            ? CDISASM_OPERAND_ACCESS_READ
            : accumulate ? CDISASM_OPERAND_ACCESS_READ_WRITE
                         : CDISASM_OPERAND_ACCESS_WRITE));
    }
}

static void check_advsimd_saturating_mulh_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xbf20fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned registers[3];
    unsigned size_code;
    uint8_t element_size;
    uint8_t vector_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if (fixed == UINT32_C(0x0e20b400)) {
        expected_name = CDISASM_ARM_NAME_SQDMULH;
        expected_form = UINT16_C(6136);
    } else if (fixed == UINT32_C(0x2e20b400)) {
        expected_name = CDISASM_ARM_NAME_SQRDMULH;
        expected_form = UINT16_C(6178);
    } else {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    size_code = (word >> 22) & 3u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);
    vector_size = (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    invariant(size_code == 1u || size_code == 2u);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == vector_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(vector_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_pmull_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned registers[3];
    unsigned size_code;
    uint8_t source_element_size;
    uint8_t result_element_size;
    uint8_t source_total_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xbf20fc00)) != UINT32_C(0x0e20e000)) {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    size_code = (word >> 22) & 3u;
    source_element_size = size_code == 0u ? 1u : 8u;
    result_element_size = (uint8_t)(source_element_size * 2u);
    source_total_size = (word & UINT32_C(0x40000000)) != 0u
        ? 16u : 8u;
    invariant(size_code == 0u || size_code == 3u);
    invariant(instruction->name_id == CDISASM_ARM_NAME_PMULL);
    invariant(instruction->form_id == UINT16_C(6103));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        uint8_t element_size = index == 0u
            ? result_element_size : source_element_size;
        uint8_t total_size = index == 0u ? 16u : source_total_size;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_pmul_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned registers[3];
    uint8_t vector_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xbf20fc00)) != UINT32_C(0x2e209c00)) {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    vector_size = (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    invariant(((word >> 22) & 3u) == 0u);
    invariant(instruction->name_id == CDISASM_ARM_NAME_PMUL);
    invariant(instruction->form_id == UINT16_C(6175));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == vector_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == 1u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand) == vector_size);
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_compare_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf20fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned registers[3];
    unsigned q;
    unsigned size_code;
    uint8_t vector_size;
    uint8_t element_size;
    size_t index;

    switch (operation) {
        case UINT32_C(0x0e203400):
            expected_name = CDISASM_ARM_NAME_CMGT;
            expected_form = UINT16_C(6120);
            break;
        case UINT32_C(0x0e203c00):
            expected_name = CDISASM_ARM_NAME_CMGE;
            expected_form = UINT16_C(6121);
            break;
        case UINT32_C(0x2e203400):
            expected_name = CDISASM_ARM_NAME_CMHI;
            expected_form = UINT16_C(6162);
            break;
        case UINT32_C(0x2e203c00):
            expected_name = CDISASM_ARM_NAME_CMHS;
            expected_form = UINT16_C(6163);
            break;
        case UINT32_C(0x2e208c00):
            expected_name = CDISASM_ARM_NAME_CMEQ;
            expected_form = UINT16_C(6173);
            break;
        default:
            return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    q = (word >> 30) & 1u;
    size_code = (word >> 22) & 3u;
    vector_size = q != 0u ? 16u : 8u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);
    invariant(size_code <= 2u || q != 0u);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == vector_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(vector_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_cmtst_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int scalar = (word & UINT32_C(0xffe0fc00))
        == UINT32_C(0x5ee08c00);
    int vector = (word & UINT32_C(0xbf20fc00))
        == UINT32_C(0x0e208c00);
    unsigned registers[3];
    unsigned q;
    unsigned size_code;
    uint8_t total_size;
    uint8_t element_size;
    cdisasm_arm_reg_id register_base;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (!scalar && !vector)) {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    q = (word >> 30) & 1u;
    size_code = (word >> 22) & 3u;
    if (vector) {
        invariant(size_code <= 2u || q != 0u);
    }
    total_size = scalar ? 8u : q != 0u ? 16u : 8u;
    element_size = scalar
        ? 8u : (uint8_t)(UINT8_C(1) << size_code);
    register_base = scalar ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;

    invariant(instruction->name_id == CDISASM_ARM_NAME_CMTST);
    invariant(instruction->form_id
        == (scalar ? UINT16_C(5831) : UINT16_C(6131)));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            register_base + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_variable_shift_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t scalar_operation = word & UINT32_C(0xffe0fc00);
    uint32_t vector_operation = word & UINT32_C(0xbf20fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    int scalar;
    unsigned registers[3];
    unsigned q;
    unsigned size_code;
    uint8_t total_size;
    uint8_t element_size;
    cdisasm_arm_reg_id register_base;
    size_t index;

    if (scalar_operation == UINT32_C(0x5ee04400)) {
        expected_name = CDISASM_ARM_NAME_SSHL;
        expected_form = UINT16_C(5826);
        scalar = 1;
    } else if (scalar_operation == UINT32_C(0x7ee04400)) {
        expected_name = CDISASM_ARM_NAME_USHL;
        expected_form = UINT16_C(5841);
        scalar = 1;
    } else if (vector_operation == UINT32_C(0x0e204400)) {
        expected_name = CDISASM_ARM_NAME_SSHL;
        expected_form = UINT16_C(6122);
        scalar = 0;
    } else if (vector_operation == UINT32_C(0x2e204400)) {
        expected_name = CDISASM_ARM_NAME_USHL;
        expected_form = UINT16_C(6164);
        scalar = 0;
    } else {
        return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    q = (word >> 30) & 1u;
    size_code = (word >> 22) & 3u;
    if (!scalar) {
        invariant(size_code <= 2u || q != 0u);
    }
    total_size = scalar ? 8u : q != 0u ? 16u : 8u;
    element_size = scalar
        ? 8u : (uint8_t)(UINT8_C(1) << size_code);
    register_base = scalar ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;

    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            register_base + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_compare_zero_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t scalar_operation = word & UINT32_C(0xfffffc00);
    uint32_t vector_operation = word & UINT32_C(0xbf3ffc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    int scalar;
    unsigned q;
    unsigned size_code;
    unsigned registers[2];
    uint8_t total_size;
    uint8_t element_size;
    cdisasm_arm_reg_id register_base;
    size_t index;

    if (scalar_operation == UINT32_C(0x5ee0a800)) {
        expected_name = CDISASM_ARM_NAME_CMLT;
        expected_form = UINT16_C(5777);
        scalar = 1;
    } else if (scalar_operation == UINT32_C(0x7ee09800)) {
        expected_name = CDISASM_ARM_NAME_CMLE;
        expected_form = UINT16_C(5794);
        scalar = 1;
    } else if (vector_operation == UINT32_C(0x0e20a800)) {
        expected_name = CDISASM_ARM_NAME_CMLT;
        expected_form = UINT16_C(6013);
        scalar = 0;
    } else if (vector_operation == UINT32_C(0x2e209800)) {
        expected_name = CDISASM_ARM_NAME_CMLE;
        expected_form = UINT16_C(6045);
        scalar = 0;
    } else {
        return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    q = (word >> 30) & 1u;
    size_code = (word >> 22) & 3u;
    if (!scalar) {
        invariant(size_code <= 2u || q != 0u);
    }
    total_size = scalar ? 8u : q != 0u ? 16u : 8u;
    element_size = scalar
        ? 8u : (uint8_t)(UINT8_C(1) << size_code);
    register_base = scalar ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;

    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            register_base + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
    invariant(instruction->operand[2].type
        == CDISASM_OPERAND_IMMEDIATE);
    invariant(instruction->operand[2].reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[2].base_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[2].index_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[2].register_list == 0u);
    invariant(instruction->operand[2].address == 0u);
    invariant(instruction->operand[2].imm == 0u);
    invariant(instruction->operand[2].size == 1u);
    invariant(instruction->operand[2].flags
        == CDISASM_OPERAND_FLAG_NONE);
    invariant(instruction->operand[2].shift_type
        == CDISASM_ARM_SHIFT_NONE);
    invariant(instruction->operand[2].shift_amount == 0u);
    invariant(instruction->operand[2].extend_type
        == CDISASM_ARM_EXTEND_NONE);
    invariant(instruction->operand[2].scale == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_advsimd_minmax_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf20fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned registers[3];
    unsigned size_code;
    uint8_t vector_size;
    uint8_t element_size;
    size_t index;

    switch (operation) {
        case UINT32_C(0x0e206400):
            expected_name = CDISASM_ARM_NAME_SMAX;
            expected_form = UINT16_C(6126);
            break;
        case UINT32_C(0x0e206c00):
            expected_name = CDISASM_ARM_NAME_SMIN;
            expected_form = UINT16_C(6127);
            break;
        case UINT32_C(0x2e206400):
            expected_name = CDISASM_ARM_NAME_UMAX;
            expected_form = UINT16_C(6168);
            break;
        case UINT32_C(0x2e206c00):
            expected_name = CDISASM_ARM_NAME_UMIN;
            expected_form = UINT16_C(6169);
            break;
        default:
            return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    size_code = (word >> 22) & 3u;
    vector_size = (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);
    invariant(size_code <= 2u);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == vector_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(operand->extend_type
            == (cdisasm_arm_extend_type)element_size);
        invariant(operand->scale
            == (uint8_t)(vector_size / element_size));
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(vector_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_pairwise_minmax_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf20fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    unsigned registers[3];
    unsigned size_code;
    uint8_t vector_size;
    uint8_t element_size;
    size_t index;

    switch (operation) {
        case UINT32_C(0x0e20a400):
            expected_name = CDISASM_ARM_NAME_SMAXP;
            expected_form = UINT16_C(6134);
            break;
        case UINT32_C(0x0e20ac00):
            expected_name = CDISASM_ARM_NAME_SMINP;
            expected_form = UINT16_C(6135);
            break;
        case UINT32_C(0x2e20a400):
            expected_name = CDISASM_ARM_NAME_UMAXP;
            expected_form = UINT16_C(6176);
            break;
        case UINT32_C(0x2e20ac00):
            expected_name = CDISASM_ARM_NAME_UMINP;
            expected_form = UINT16_C(6177);
            break;
        default:
            return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    size_code = (word >> 22) & 3u;
    vector_size = (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);
    invariant(size_code <= 2u);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == vector_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(operand->extend_type
            == (cdisasm_arm_extend_type)element_size);
        invariant(operand->scale
            == (uint8_t)(vector_size / element_size));
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(vector_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_addp_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int scalar = (word & UINT32_C(0xfffffc00))
        == UINT32_C(0x5ef1b800);
    int vector = (word & UINT32_C(0xbf20fc00))
        == UINT32_C(0x0e20bc00);
    unsigned registers[3];
    unsigned operand_count;
    unsigned size_code;
    uint8_t vector_size;
    uint8_t element_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (!scalar && !vector)) {
        return;
    }
    size_code = (word >> 22) & 3u;
    invariant(scalar || size_code <= 2u
        || (word & UINT32_C(0x40000000)) != 0u);
    invariant(instruction->name_id == CDISASM_ARM_NAME_ADDP);
    invariant(instruction->form_id
        == (scalar ? UINT16_C(5808) : UINT16_C(6137)));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);

    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    registers[2] = (word >> 16) & 31u;
    operand_count = scalar ? 2u : 3u;
    vector_size = scalar ? 8u
        : (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    element_size = scalar ? 8u
        : (uint8_t)(UINT32_C(1) << size_code);
    invariant(instruction->operand_count == operand_count);
    for (index = 0u; index < operand_count; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        cdisasm_arm_reg_id base = scalar && index == 0u
            ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;
        uint8_t total_size = scalar && index != 0u ? 16u : vector_size;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            base + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(operand->extend_type
            == (cdisasm_arm_extend_type)element_size);
        invariant(operand->scale
            == (uint8_t)(total_size / element_size));
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_addv_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned q;
    unsigned size_code;
    unsigned registers[2];
    uint8_t element_size;
    uint8_t vector_size;
    cdisasm_arm_reg_id scalar_base;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xbf3ffc00))
            != UINT32_C(0x0e31b800)) {
        return;
    }
    q = (word >> 30) & 1u;
    size_code = (word >> 22) & 3u;
    invariant(size_code <= 1u || (q != 0u && size_code == 2u));
    invariant(instruction->name_id == CDISASM_ARM_NAME_ADDV);
    invariant(instruction->form_id == UINT16_C(6077));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 2u);

    element_size = (uint8_t)(UINT32_C(1) << size_code);
    vector_size = q != 0u ? 16u : 8u;
    scalar_base = size_code == 0u ? CDISASM_ARM_REG_B0
        : size_code == 1u ? CDISASM_ARM_REG_H0 : CDISASM_ARM_REG_S0;
    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        cdisasm_arm_reg_id base = index == 0u
            ? scalar_base : CDISASM_ARM_REG_V0;
        uint8_t total_size = index == 0u ? element_size : vector_size;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            base + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(operand->extend_type
            == (cdisasm_arm_extend_type)element_size);
        invariant(operand->scale
            == (uint8_t)(total_size / element_size));
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_addlv_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf3ffc00);
    unsigned q;
    unsigned size_code;
    unsigned registers[2];
    uint8_t source_element_size;
    uint8_t result_element_size;
    uint8_t vector_size;
    cdisasm_arm_reg_id result_base;
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (operation != UINT32_C(0x0e303800)
            && operation != UINT32_C(0x2e303800))) {
        return;
    }
    q = (word >> 30) & 1u;
    size_code = (word >> 22) & 3u;
    invariant(size_code <= 1u || (q != 0u && size_code == 2u));
    expected_name = operation == UINT32_C(0x0e303800)
        ? CDISASM_ARM_NAME_SADDLV : CDISASM_ARM_NAME_UADDLV;
    expected_form = operation == UINT32_C(0x0e303800)
        ? UINT16_C(6074) : UINT16_C(6082);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 2u);

    source_element_size = (uint8_t)(UINT32_C(1) << size_code);
    result_element_size = (uint8_t)(source_element_size * 2u);
    vector_size = q != 0u ? 16u : 8u;
    result_base = result_element_size == 2u ? CDISASM_ARM_REG_H0
        : result_element_size == 4u ? CDISASM_ARM_REG_S0
        : CDISASM_ARM_REG_D0;
    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        uint8_t element_size = index == 0u
            ? result_element_size : source_element_size;
        uint8_t total_size = index == 0u
            ? result_element_size : vector_size;
        cdisasm_arm_reg_id base = index == 0u
            ? result_base : CDISASM_ARM_REG_V0;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            base + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(operand->extend_type
            == (cdisasm_arm_extend_type)element_size);
        invariant(operand->scale
            == (uint8_t)(total_size / element_size));
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_advsimd_pairwise_add_long_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t values[4] = {
        UINT32_C(0x0e202800), UINT32_C(0x0e206800),
        UINT32_C(0x2e202800), UINT32_C(0x2e206800)
    };
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_SADDLP, CDISASM_ARM_NAME_SADALP,
        CDISASM_ARM_NAME_UADDLP, CDISASM_ARM_NAME_UADALP
    };
    static const cdisasm_arm_form_id forms[4] = {
        UINT16_C(6005), UINT16_C(6009),
        UINT16_C(6039), UINT16_C(6042)
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf3ffc00);
    unsigned operation_index;
    unsigned q;
    unsigned size_code;
    unsigned registers[2];
    uint8_t source_element_size;
    uint8_t result_element_size;
    uint8_t vector_size;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    for (operation_index = 0u; operation_index < 4u; ++operation_index) {
        if (operation == values[operation_index]) {
            break;
        }
    }
    if (operation_index == 4u) {
        return;
    }
    q = (word >> 30) & 1u;
    size_code = (word >> 22) & 3u;
    invariant(size_code <= 2u);
    invariant(instruction->name_id == names[operation_index]);
    invariant(instruction->form_id == forms[operation_index]);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 2u);

    source_element_size = (uint8_t)(UINT32_C(1) << size_code);
    result_element_size = (uint8_t)(source_element_size * 2u);
    vector_size = q != 0u ? 16u : 8u;
    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        uint8_t element_size = index == 0u
            ? result_element_size : source_element_size;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == vector_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(operand->extend_type
            == (cdisasm_arm_extend_type)element_size);
        invariant(operand->scale
            == (uint8_t)(vector_size / element_size));
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(vector_size / element_size));
        invariant(operand->access == (index != 0u
            ? CDISASM_OPERAND_ACCESS_READ
            : (operation_index == 1u || operation_index == 3u)
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE));
    }
}

static void check_advsimd_narrow_widen_move_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf3ffc00);
    unsigned size_code;
    unsigned q;
    unsigned registers[2];
    uint8_t narrow_element_size;
    uint8_t wide_element_size;
    int widening;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (operation != UINT32_C(0x0e212800)
            && operation != UINT32_C(0x2e213800))) {
        return;
    }
    widening = operation == UINT32_C(0x2e213800);
    size_code = (word >> 22) & 3u;
    q = (word >> 30) & 1u;
    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    narrow_element_size = (uint8_t)(UINT32_C(1) << size_code);
    wide_element_size = (uint8_t)(narrow_element_size * 2u);

    invariant(size_code <= 2u);
    invariant(instruction->name_id == (widening
        ? CDISASM_ARM_NAME_SHLL : CDISASM_ARM_NAME_XTN));
    invariant(instruction->form_id == (widening
        ? UINT16_C(6048) : UINT16_C(6015)));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == (widening ? 3u : 2u));
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        uint8_t element_size = widening
            ? (index == 0u ? wide_element_size : narrow_element_size)
            : (index == 0u ? narrow_element_size : wide_element_size);
        uint8_t total_size = widening
            ? (index == 0u || q != 0u ? 16u : 8u)
            : (index == 0u ? (q != 0u ? 16u : 8u) : 16u);
        cdisasm_operand_access access = index != 0u
            ? CDISASM_OPERAND_ACCESS_READ
            : (!widening && q != 0u)
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(operand->extend_type
            == (cdisasm_arm_extend_type)element_size);
        invariant(operand->scale
            == (uint8_t)(total_size / element_size));
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == access);
    }
    if (widening) {
        const cdisasm_arm_operand *immediate = &instruction->operand[2];

        invariant(immediate->type == CDISASM_OPERAND_IMMEDIATE);
        invariant(immediate->reg == CDISASM_ARM_REG_NONE);
        invariant(immediate->base_reg == CDISASM_ARM_REG_NONE);
        invariant(immediate->index_reg == CDISASM_ARM_REG_NONE);
        invariant(immediate->register_list == 0u);
        invariant(immediate->address == 0u);
        invariant(immediate->imm
            == (uint64_t)narrow_element_size * UINT64_C(8));
        invariant(immediate->size == 1u);
        invariant(immediate->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(immediate->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(immediate->shift_amount == 0u);
        invariant(immediate->extend_type == CDISASM_ARM_EXTEND_NONE);
        invariant(immediate->scale == 0u);
        invariant(immediate->access == CDISASM_OPERAND_ACCESS_READ);
    }
}

static void check_advsimd_modified_immediate_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    unsigned cmode = (word >> 12) & 15u;
    unsigned encoded = (((word >> 16) & 7u) << 5)
        | ((word >> 5) & 31u);
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_shift_type shift_type = CDISASM_ARM_SHIFT_NONE;
    uint8_t shift_amount = 0u;
    uint8_t element_size;
    uint8_t total_size = q != 0u ? 16u : 8u;
    cdisasm_arm_reg_id register_base = CDISASM_ARM_REG_V0;
    cdisasm_operand_access destination_access =
        CDISASM_OPERAND_ACCESS_WRITE;
    uint64_t immediate = encoded;

    if ((word & UINT32_C(0xbff89c00)) == UINT32_C(0x0f001400)
        || (word & UINT32_C(0xbff89c00)) == UINT32_C(0x2f001400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6200) : UINT16_C(6208);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_ORR : CDISASM_ARM_NAME_BIC;
        element_size = 4u;
        shift_amount = (uint8_t)(4u * (cmode & ~1u));
        shift_type = shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        immediate <<= shift_amount;
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    } else if ((word & UINT32_C(0xbff8dc00))
            == UINT32_C(0x0f009400)
        || (word & UINT32_C(0xbff8dc00)) == UINT32_C(0x2f009400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6202) : UINT16_C(6210);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_ORR : CDISASM_ARM_NAME_BIC;
        element_size = 2u;
        shift_amount = (cmode & 2u) != 0u ? 8u : 0u;
        shift_type = shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        immediate <<= shift_amount;
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    } else if ((word & UINT32_C(0xbff89c00)) == UINT32_C(0x0f000400)
        || (word & UINT32_C(0xbff89c00)) == UINT32_C(0x2f000400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6199) : UINT16_C(6207);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_MOVI : CDISASM_ARM_NAME_MVNI;
        element_size = 4u;
        shift_amount = (uint8_t)(4u * cmode);
        shift_type = shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        immediate <<= shift_amount;
    } else if ((word & UINT32_C(0xbff8dc00))
            == UINT32_C(0x0f008400)
        || (word & UINT32_C(0xbff8dc00)) == UINT32_C(0x2f008400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6201) : UINT16_C(6209);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_MOVI : CDISASM_ARM_NAME_MVNI;
        element_size = 2u;
        shift_amount = (cmode & 2u) != 0u ? 8u : 0u;
        shift_type = shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        immediate <<= shift_amount;
    } else if ((word & UINT32_C(0xbff8ec00))
            == UINT32_C(0x0f00c400)
        || (word & UINT32_C(0xbff8ec00)) == UINT32_C(0x2f00c400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6203) : UINT16_C(6211);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_MOVI : CDISASM_ARM_NAME_MVNI;
        element_size = 4u;
        shift_type = CDISASM_ARM_SHIFT_MSL;
        shift_amount = (cmode & 1u) != 0u ? 16u : 8u;
        immediate = (immediate << shift_amount)
            | ((UINT64_C(1) << shift_amount) - UINT64_C(1));
    } else if ((word & UINT32_C(0xbff8fc00))
            == UINT32_C(0x0f00e400)) {
        form_id = UINT16_C(6204);
        name_id = CDISASM_ARM_NAME_MOVI;
        element_size = 1u;
    } else if ((word & UINT32_C(0xfff8fc00))
            == UINT32_C(0x2f00e400)
        || (word & UINT32_C(0xfff8fc00)) == UINT32_C(0x6f00e400)) {
        form_id = q == 0u ? UINT16_C(6212) : UINT16_C(6213);
        name_id = CDISASM_ARM_NAME_MOVI;
        element_size = 8u;
        immediate = UINT64_C(0);
        for (unsigned bit = 0u; bit < 8u; ++bit) {
            if ((encoded & (1u << bit)) != 0u) {
                immediate |= UINT64_C(0xff) << (8u * bit);
            }
        }
        if (q == 0u) {
            register_base = CDISASM_ARM_REG_D0;
        }
    } else {
        return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }

    invariant(instruction->name_id == name_id);
    invariant(instruction->form_id == form_id);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 2u);
    {
        const cdisasm_arm_operand *destination = &instruction->operand[0];

        invariant(destination->type == CDISASM_OPERAND_REGISTER);
        invariant(destination->reg == (cdisasm_arm_reg_id)(
            register_base + (word & 31u)));
        invariant(destination->base_reg == CDISASM_ARM_REG_NONE);
        invariant(destination->index_reg == CDISASM_ARM_REG_NONE);
        invariant(destination->register_list == 0u);
        invariant(destination->address == 0u);
        invariant(destination->imm == 0u);
        invariant(destination->size == total_size);
        invariant(destination->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(destination->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(destination->shift_amount == 0u);
        invariant(destination->extend_type
            == (cdisasm_arm_extend_type)element_size);
        invariant(destination->scale
            == (uint8_t)(total_size / element_size));
        invariant(destination->access == destination_access);
    }
    {
        const cdisasm_arm_operand *source = &instruction->operand[1];

        invariant(source->type == CDISASM_OPERAND_IMMEDIATE);
        invariant(source->reg == CDISASM_ARM_REG_NONE);
        invariant(source->base_reg == CDISASM_ARM_REG_NONE);
        invariant(source->index_reg == CDISASM_ARM_REG_NONE);
        invariant(source->register_list == 0u);
        invariant(source->address == 0u);
        invariant(source->imm == immediate);
        invariant(source->size == 1u);
        invariant(source->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(source->shift_type == shift_type);
        invariant(source->shift_amount == shift_amount);
        invariant(source->extend_type == CDISASM_ARM_EXTEND_NONE);
        invariant(source->scale == 0u);
        invariant(source->access == CDISASM_OPERAND_ACCESS_READ);
    }
}

static void check_advsimd_shift_right_immediate_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t scalar_operation = word & UINT32_C(0xffc0fc00);
    uint32_t vector_operation = word & UINT32_C(0xbf80fc00);
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    cdisasm_operand_access destination_access;
    int scalar;
    int left_shift;
    unsigned q;
    unsigned immh;
    unsigned encoded_immediate;
    unsigned element_bits;
    unsigned shift;
    unsigned registers[2];
    uint8_t element_size;
    uint8_t total_size;
    cdisasm_arm_reg_id register_base;
    size_t index;

    if (((word >> 19) & 15u) == 0u
        && (vector_operation == UINT32_C(0x0f000400)
            || vector_operation == UINT32_C(0x2f000400)
            || vector_operation == UINT32_C(0x0f001400)
            || vector_operation == UINT32_C(0x2f001400)
            || vector_operation == UINT32_C(0x0f002400)
            || vector_operation == UINT32_C(0x2f002400)
            || vector_operation == UINT32_C(0x0f003400)
            || vector_operation == UINT32_C(0x2f003400)
            || vector_operation == UINT32_C(0x0f005400)
            || vector_operation == UINT32_C(0x2f004400)
            || vector_operation == UINT32_C(0x2f005400))) {
        /* These overlaps belong to MOVI/MVNI/ORR/BIC, not shifts. */
        return;
    }
    if (scalar_operation == UINT32_C(0x5f400400)) {
        expected_name = CDISASM_ARM_NAME_SSHR;
        expected_form = UINT16_C(5853);
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        scalar = 1;
        left_shift = 0;
    } else if (scalar_operation == UINT32_C(0x7f400400)) {
        expected_name = CDISASM_ARM_NAME_USHR;
        expected_form = UINT16_C(5863);
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        scalar = 1;
        left_shift = 0;
    } else if (scalar_operation == UINT32_C(0x5f401400)) {
        expected_name = CDISASM_ARM_NAME_SSRA;
        expected_form = UINT16_C(5854);
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        scalar = 1;
        left_shift = 0;
    } else if (scalar_operation == UINT32_C(0x7f401400)) {
        expected_name = CDISASM_ARM_NAME_USRA;
        expected_form = UINT16_C(5864);
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        scalar = 1;
        left_shift = 0;
    } else if (scalar_operation == UINT32_C(0x5f402400)) {
        expected_name = CDISASM_ARM_NAME_SRSHR;
        expected_form = UINT16_C(5855);
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        scalar = 1;
        left_shift = 0;
    } else if (scalar_operation == UINT32_C(0x7f402400)) {
        expected_name = CDISASM_ARM_NAME_URSHR;
        expected_form = UINT16_C(5865);
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        scalar = 1;
        left_shift = 0;
    } else if (scalar_operation == UINT32_C(0x5f403400)) {
        expected_name = CDISASM_ARM_NAME_SRSRA;
        expected_form = UINT16_C(5856);
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        scalar = 1;
        left_shift = 0;
    } else if (scalar_operation == UINT32_C(0x7f403400)) {
        expected_name = CDISASM_ARM_NAME_URSRA;
        expected_form = UINT16_C(5866);
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        scalar = 1;
        left_shift = 0;
    } else if (scalar_operation == UINT32_C(0x5f405400)) {
        expected_name = CDISASM_ARM_NAME_SHL;
        expected_form = UINT16_C(5857);
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        scalar = 1;
        left_shift = 1;
    } else if (scalar_operation == UINT32_C(0x7f404400)) {
        expected_name = CDISASM_ARM_NAME_SRI;
        expected_form = UINT16_C(5867);
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        scalar = 1;
        left_shift = 0;
    } else if (scalar_operation == UINT32_C(0x7f405400)) {
        expected_name = CDISASM_ARM_NAME_SLI;
        expected_form = UINT16_C(5868);
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        scalar = 1;
        left_shift = 1;
    } else if (vector_operation == UINT32_C(0x0f000400)) {
        expected_name = CDISASM_ARM_NAME_SSHR;
        expected_form = UINT16_C(6215);
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        scalar = 0;
        left_shift = 0;
    } else if (vector_operation == UINT32_C(0x2f000400)) {
        expected_name = CDISASM_ARM_NAME_USHR;
        expected_form = UINT16_C(6228);
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        scalar = 0;
        left_shift = 0;
    } else if (vector_operation == UINT32_C(0x0f001400)) {
        expected_name = CDISASM_ARM_NAME_SSRA;
        expected_form = UINT16_C(6216);
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        scalar = 0;
        left_shift = 0;
    } else if (vector_operation == UINT32_C(0x2f001400)) {
        expected_name = CDISASM_ARM_NAME_USRA;
        expected_form = UINT16_C(6229);
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        scalar = 0;
        left_shift = 0;
    } else if (vector_operation == UINT32_C(0x0f002400)) {
        expected_name = CDISASM_ARM_NAME_SRSHR;
        expected_form = UINT16_C(6217);
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        scalar = 0;
        left_shift = 0;
    } else if (vector_operation == UINT32_C(0x2f002400)) {
        expected_name = CDISASM_ARM_NAME_URSHR;
        expected_form = UINT16_C(6230);
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        scalar = 0;
        left_shift = 0;
    } else if (vector_operation == UINT32_C(0x0f003400)) {
        expected_name = CDISASM_ARM_NAME_SRSRA;
        expected_form = UINT16_C(6218);
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        scalar = 0;
        left_shift = 0;
    } else if (vector_operation == UINT32_C(0x2f003400)) {
        expected_name = CDISASM_ARM_NAME_URSRA;
        expected_form = UINT16_C(6231);
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        scalar = 0;
        left_shift = 0;
    } else if (vector_operation == UINT32_C(0x0f005400)) {
        expected_name = CDISASM_ARM_NAME_SHL;
        expected_form = UINT16_C(6219);
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        scalar = 0;
        left_shift = 1;
    } else if (vector_operation == UINT32_C(0x2f004400)) {
        expected_name = CDISASM_ARM_NAME_SRI;
        expected_form = UINT16_C(6232);
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        scalar = 0;
        left_shift = 0;
    } else if (vector_operation == UINT32_C(0x2f005400)) {
        expected_name = CDISASM_ARM_NAME_SLI;
        expected_form = UINT16_C(6233);
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        scalar = 0;
        left_shift = 1;
    } else {
        return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }

    q = (word >> 30) & 1u;
    immh = (word >> 19) & 15u;
    if (!scalar) {
        invariant(immh != 0u);
        invariant(q != 0u || (immh & 8u) == 0u);
    }
    encoded_immediate = (immh << 3) | ((word >> 16) & 7u);
    element_bits = scalar || (immh & 8u) != 0u ? 64u
        : (immh & 4u) != 0u ? 32u
        : (immh & 2u) != 0u ? 16u : 8u;
    shift = left_shift
        ? encoded_immediate - element_bits
        : 2u * element_bits - encoded_immediate;
    registers[0] = word & 31u;
    registers[1] = (word >> 5) & 31u;
    element_size = (uint8_t)(element_bits / 8u);
    total_size = scalar ? 8u : q != 0u ? 16u : 8u;
    register_base = scalar ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;

    invariant(left_shift ? shift < element_bits
                         : shift >= 1u && shift <= element_bits);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == 3u);
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            register_base + registers[index]));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(operand->extend_type
            == (cdisasm_arm_extend_type)element_size);
        invariant(operand->scale
            == (uint8_t)(total_size / element_size));
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)
            == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index == 0u
            ? destination_access
            : CDISASM_OPERAND_ACCESS_READ));
    }
    {
        const cdisasm_arm_operand *immediate = &instruction->operand[2];

        invariant(immediate->type == CDISASM_OPERAND_IMMEDIATE);
        invariant(immediate->reg == CDISASM_ARM_REG_NONE);
        invariant(immediate->base_reg == CDISASM_ARM_REG_NONE);
        invariant(immediate->index_reg == CDISASM_ARM_REG_NONE);
        invariant(immediate->register_list == 0u);
        invariant(immediate->address == 0u);
        invariant(immediate->imm == (uint64_t)shift);
        invariant(immediate->size == 1u);
        invariant(immediate->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(immediate->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(immediate->shift_amount == 0u);
        invariant(immediate->extend_type == CDISASM_ARM_EXTEND_NONE);
        invariant(immediate->scale == 0u);
        invariant(immediate->access == CDISASM_OPERAND_ACCESS_READ);
    }
}

static void check_advsimd_shift_narrow_widen_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf80fc00);
    cdisasm_arm_name_id base_name;
    cdisasm_arm_name_id alias_name = CDISASM_ARM_NAME_NONE;
    cdisasm_arm_form_id form_id;
    unsigned q = (word >> 30) & 1u;
    unsigned immh = (word >> 19) & 15u;
    unsigned narrow_bits;
    unsigned encoded;
    unsigned shift;
    uint8_t narrow_size;
    uint8_t wide_size;
    int widening;
    int alias;

    if (immh == 0u) {
        /* These cells are either modified-immediate siblings or RSHRN's
         * unallocated cell, never members of this class. */
        return;
    }
    switch (operation) {
        case UINT32_C(0x0f008400):
            base_name = CDISASM_ARM_NAME_SHRN;
            form_id = UINT16_C(6221);
            widening = 0;
            break;
        case UINT32_C(0x0f008c00):
            base_name = CDISASM_ARM_NAME_RSHRN;
            form_id = UINT16_C(6222);
            widening = 0;
            break;
        case UINT32_C(0x0f00a400):
            base_name = CDISASM_ARM_NAME_SSHLL;
            alias_name = CDISASM_ARM_NAME_SXTL;
            form_id = UINT16_C(6225);
            widening = 1;
            break;
        case UINT32_C(0x2f00a400):
            base_name = CDISASM_ARM_NAME_USHLL;
            alias_name = CDISASM_ARM_NAME_UXTL;
            form_id = UINT16_C(6240);
            widening = 1;
            break;
        default:
            return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    invariant(immh <= 7u);
    narrow_bits = (immh & 4u) != 0u ? 32u
        : (immh & 2u) != 0u ? 16u : 8u;
    encoded = (immh << 3) | ((word >> 16) & 7u);
    shift = widening ? encoded - narrow_bits
                     : 2u * narrow_bits - encoded;
    narrow_size = (uint8_t)(narrow_bits / 8u);
    wide_size = (uint8_t)(narrow_size * 2u);
    alias = widening && shift == 0u;

    invariant(instruction->name_id == (alias ? alias_name : base_name));
    invariant(instruction->form_id == form_id);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == (alias ? 2u : 3u));
    for (size_t index = 0u; index < 2u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        uint8_t total_size = widening
            ? (index == 0u ? 16u : q != 0u ? 16u : 8u)
            : (index == 0u ? (q != 0u ? 16u : 8u) : 16u);
        uint8_t element_size = widening
            ? (index == 0u ? wide_size : narrow_size)
            : (index == 0u ? narrow_size : wide_size);
        cdisasm_operand_access access = index == 0u
            ? (widening || q == 0u ? CDISASM_OPERAND_ACCESS_WRITE
                                   : CDISASM_OPERAND_ACCESS_READ_WRITE)
            : CDISASM_OPERAND_ACCESS_READ;
        unsigned encoded_reg = index == 0u
            ? word & 31u : (word >> 5) & 31u;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_V0 + encoded_reg));
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(operand->extend_type
            == (cdisasm_arm_extend_type)element_size);
        invariant(operand->scale
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == access);
    }
    if (!alias) {
        const cdisasm_arm_operand *immediate = &instruction->operand[2];

        invariant(immediate->type == CDISASM_OPERAND_IMMEDIATE);
        invariant(immediate->reg == CDISASM_ARM_REG_NONE);
        invariant(immediate->base_reg == CDISASM_ARM_REG_NONE);
        invariant(immediate->index_reg == CDISASM_ARM_REG_NONE);
        invariant(immediate->register_list == 0u);
        invariant(immediate->address == 0u);
        invariant(immediate->imm == (uint64_t)shift);
        invariant(immediate->size == 1u);
        invariant(immediate->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(immediate->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(immediate->shift_amount == 0u);
        invariant(immediate->extend_type == CDISASM_ARM_EXTEND_NONE);
        invariant(immediate->scale == 0u);
        invariant(immediate->access == CDISASM_OPERAND_ACCESS_READ);
    }
}

static void check_a64_pauth_branch_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[2][2][2] = {
        {
            { CDISASM_ARM_NAME_BRAAZ, CDISASM_ARM_NAME_BRAA },
            { CDISASM_ARM_NAME_BRABZ, CDISASM_ARM_NAME_BRAB }
        },
        {
            { CDISASM_ARM_NAME_BLRAAZ, CDISASM_ARM_NAME_BLRAA },
            { CDISASM_ARM_NAME_BLRABZ, CDISASM_ARM_NAME_BLRAB }
        }
    };
    static const cdisasm_arm_form_id forms[2][2][2] = {
        {
            { UINT16_C(4510), UINT16_C(4525) },
            { UINT16_C(4511), UINT16_C(4526) }
        },
        {
            { UINT16_C(4513), UINT16_C(4527) },
            { UINT16_C(4514), UINT16_C(4528) }
        }
    };
    uint32_t word = instruction->raw_instruction;
    unsigned link;
    unsigned key_b;
    unsigned explicit_modifier;
    unsigned rn;
    unsigned rm;
    unsigned operand_count;
    unsigned index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xfedff800)) != UINT32_C(0xd61f0800)) {
        return;
    }
    link = (word >> 21) & 1u;
    key_b = (word >> 10) & 1u;
    explicit_modifier = (word >> 24) & 1u;
    rn = (word >> 5) & 31u;
    rm = word & 31u;
    operand_count = explicit_modifier != 0u ? 2u : 1u;

    invariant(explicit_modifier != 0u || rm == 31u);
    invariant(instruction->name_id
        == names[link][key_b][explicit_modifier]);
    invariant(instruction->form_id
        == forms[link][key_b][explicit_modifier]);
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups
        == (link != 0u ? CDISASM_GROUP_CALL : CDISASM_GROUP_JUMP));
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_POINTER_AUTH
            | (link != 0u ? CDISASM_ARM_INSTRUCTION_FLAG_LINK : 0u)));
    invariant(instruction->branch_target == 0u);
    invariant(instruction->operand_count == operand_count);
    for (index = 0u; index < operand_count; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        unsigned encoded = index == 0u ? rn : rm;
        cdisasm_arm_reg_id expected_reg = encoded == 31u
            ? (index == 0u ? CDISASM_ARM_REG_XZR : CDISASM_ARM_REG_SP)
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded);

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg == expected_reg);
        invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        invariant(operand->register_list == 0u);
        invariant(operand->address == 0u);
        invariant(operand->imm == 0u);
        invariant(operand->size == 8u);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        invariant(operand->shift_amount == 0u);
        invariant(operand->extend_type == CDISASM_ARM_EXTEND_NONE);
        invariant(operand->scale == 0u);
        invariant(operand->access == CDISASM_OPERAND_ACCESS_READ);
    }
}

static void check_sve_integer_reduction_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[32] = {
        [0] = CDISASM_ARM_NAME_SADDV,
        [1] = CDISASM_ARM_NAME_UADDV,
        [8] = CDISASM_ARM_NAME_SMAXV,
        [9] = CDISASM_ARM_NAME_UMAXV,
        [10] = CDISASM_ARM_NAME_SMINV,
        [11] = CDISASM_ARM_NAME_UMINV,
        [24] = CDISASM_ARM_NAME_ORV,
        [25] = CDISASM_ARM_NAME_EORV,
        [26] = CDISASM_ARM_NAME_ANDV
    };
    static const cdisasm_arm_form_id forms[32] = {
        [0] = UINT16_C(2243), [1] = UINT16_C(2244),
        [8] = UINT16_C(2246), [9] = UINT16_C(2248),
        [10] = UINT16_C(2247), [11] = UINT16_C(2249),
        [24] = UINT16_C(2255), [25] = UINT16_C(2256),
        [26] = UINT16_C(2257)
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xff3fe000);
    unsigned operation = (word >> 16) & 31u;
    unsigned size_code;
    unsigned pg;
    unsigned zn;
    unsigned vd;
    uint8_t element_size;
    uint8_t result_size;
    cdisasm_arm_reg_id result_base;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || names[operation] == CDISASM_ARM_NAME_NONE
        || fixed != (UINT32_C(0x04002000)
            | ((uint32_t)operation << 16))) {
        return;
    }
    size_code = (word >> 22) & 3u;
    pg = (word >> 10) & 7u;
    zn = (word >> 5) & 31u;
    vd = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);
    result_size = operation <= 1u ? 8u : element_size;
    result_base = result_size == 1u ? CDISASM_ARM_REG_B0
        : result_size == 2u ? CDISASM_ARM_REG_H0
        : result_size == 4u ? CDISASM_ARM_REG_S0
        : CDISASM_ARM_REG_D0;

    invariant(operation != 0u || size_code != 3u);
    invariant(instruction->name_id == names[operation]);
    invariant(instruction->form_id == forms[operation]);
    invariant(instruction->operand_count == 3u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    invariant(instruction->operand[0].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(result_base + vd));
    invariant(instruction->operand[0].size == result_size);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);
    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_f64mm_permute_q_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_ZIP1, CDISASM_ARM_NAME_ZIP2,
        CDISASM_ARM_NAME_UZP1, CDISASM_ARM_NAME_UZP2,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_TRN1, CDISASM_ARM_NAME_TRN2
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned zd;
    unsigned zn;
    unsigned zm;
    unsigned index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xffe0e000)) != UINT32_C(0x05a00000)) {
        return;
    }

    operation = (word >> 10) & 7u;
    zd = word & 31u;
    zn = (word >> 5) & 31u;
    zm = (word >> 16) & 31u;
    invariant(operation < 4u || operation >= 6u);
    invariant(instruction->name_id == names[operation]);
    invariant(instruction->operand_count == 3u);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        unsigned encoded_register = index == 0u ? zd
            : index == 1u ? zn : zm;

        invariant(operand->type
            == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
        invariant(operand->reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
                + encoded_register));
        invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand) == 16u);
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_sve_predicated_unary_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id integer_names[8] = {
        CDISASM_ARM_NAME_SXTB, CDISASM_ARM_NAME_UXTB,
        CDISASM_ARM_NAME_SXTH, CDISASM_ARM_NAME_UXTH,
        CDISASM_ARM_NAME_SXTW, CDISASM_ARM_NAME_UXTW,
        CDISASM_ARM_NAME_ABS, CDISASM_ARM_NAME_NEG
    };
    static const cdisasm_arm_name_id bitwise_names[8] = {
        CDISASM_ARM_NAME_CLS, CDISASM_ARM_NAME_CLZ,
        CDISASM_ARM_NAME_CNT, CDISASM_ARM_NAME_CNOT,
        CDISASM_ARM_NAME_FABS, CDISASM_ARM_NAME_FNEG,
        CDISASM_ARM_NAME_NOT, CDISASM_ARM_NAME_NONE
    };
    static const cdisasm_arm_name_id reverse_names[4] = {
        CDISASM_ARM_NAME_REVB, CDISASM_ARM_NAME_REVH,
        CDISASM_ARM_NAME_REVW, CDISASM_ARM_NAME_RBIT
    };
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_name_id expected_name;
    unsigned operation;
    unsigned size_code;
    unsigned pg;
    unsigned zn;
    unsigned zd;
    uint8_t element_size;
    int zeroing;
    int floating;

    /* The fuzzer feeds every byte stream to A32, T32, and A64.  An A32 or
     * T32 instruction can share the same raw 32-bit value as an A64 SVE
     * encoding, so only apply this encoding-class oracle to A64 results. */
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }

    if ((word & UINT32_C(0xff28e000)) == UINT32_C(0x0400a000)) {
        operation = (word >> 16) & 7u;
        expected_name = integer_names[operation];
        zeroing = (word & UINT32_C(0x00100000)) == 0u;
        floating = 0;
    } else if ((word & UINT32_C(0xff28e000))
                   == UINT32_C(0x0408a000)) {
        operation = (word >> 16) & 7u;
        expected_name = bitwise_names[operation];
        zeroing = (word & UINT32_C(0x00100000)) == 0u;
        floating = operation == 4u || operation == 5u;
    } else if ((word & UINT32_C(0xff3cc000))
                   == UINT32_C(0x05248000)) {
        operation = (word >> 16) & 3u;
        expected_name = reverse_names[operation];
        zeroing = (word & UINT32_C(0x00002000)) != 0u;
        floating = 0;
    } else {
        return;
    }

    size_code = (word >> 22) & 3u;
    pg = (word >> 10) & 7u;
    zn = (word >> 5) & 31u;
    zd = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);

    invariant(instruction->isa_id == CDISASM_ARM_ISA_A64);
    invariant(expected_name != CDISASM_ARM_NAME_NONE);
    invariant(instruction->name_id == expected_name);
    invariant(instruction->operand_count == 3u);
    invariant((instruction->instruction_flags
                  & (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                      | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED))
              == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                  | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    invariant(((instruction->instruction_flags
                    & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) != 0u)
              == floating);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].access
        == (zeroing ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ_WRITE));

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == (zeroing ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
                    : CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE));
    invariant(instruction->operand[1].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_integer_compare_vectors_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[2][8] = {
        {
            CDISASM_ARM_NAME_CMPHS, CDISASM_ARM_NAME_CMPHI,
            CDISASM_ARM_NAME_CMPEQ, CDISASM_ARM_NAME_CMPNE,
            CDISASM_ARM_NAME_CMPGE, CDISASM_ARM_NAME_CMPGT,
            CDISASM_ARM_NAME_CMPEQ, CDISASM_ARM_NAME_CMPNE
        },
        {
            CDISASM_ARM_NAME_CMPGE, CDISASM_ARM_NAME_CMPGT,
            CDISASM_ARM_NAME_CMPLT, CDISASM_ARM_NAME_CMPLE,
            CDISASM_ARM_NAME_CMPHS, CDISASM_ARM_NAME_CMPHI,
            CDISASM_ARM_NAME_CMPLO, CDISASM_ARM_NAME_CMPLS
        }
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned wide_group;
    unsigned size_code;
    unsigned zm;
    unsigned pg;
    unsigned zn;
    unsigned pd;
    uint8_t element_size;
    uint8_t source_element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff200000)) != UINT32_C(0x24000000)) {
        return;
    }

    operation = ((word >> 13) & 4u)
        | ((word >> 12) & 2u) | ((word >> 4) & 1u);
    wide_group = (word >> 14) & 1u;
    size_code = (word >> 22) & 3u;
    zm = (word >> 16) & 31u;
    pg = (word >> 10) & 7u;
    zn = (word >> 5) & 31u;
    pd = word & 15u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);
    source_element_size = wide_group != 0u
            || operation == 2u || operation == 3u
        ? UINT8_C(8) : element_size;

    invariant(size_code != 3u
        || (wide_group == 0u
            && operation != 2u && operation != 3u));
    invariant(instruction->name_id == names[wide_group][operation]);
    invariant(instruction->operand_count == 4u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(instruction->operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);
    invariant(instruction->operand[1].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[3].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[3].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[3])
        == source_element_size);
    invariant(instruction->operand[3].access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_integer_compare_immediate_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id signed_names[3][2] = {
        { CDISASM_ARM_NAME_CMPGE, CDISASM_ARM_NAME_CMPGT },
        { CDISASM_ARM_NAME_CMPLT, CDISASM_ARM_NAME_CMPLE },
        { CDISASM_ARM_NAME_CMPEQ, CDISASM_ARM_NAME_CMPNE }
    };
    static const cdisasm_arm_name_id unsigned_names[2][2] = {
        { CDISASM_ARM_NAME_CMPHS, CDISASM_ARM_NAME_CMPHI },
        { CDISASM_ARM_NAME_CMPLO, CDISASM_ARM_NAME_CMPLS }
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code;
    unsigned pg;
    unsigned zn;
    unsigned relation;
    unsigned pd;
    uint8_t element_size;
    uint64_t immediate;
    cdisasm_arm_name_id expected_name;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    relation = (word >> 4) & 1u;
    if ((word & UINT32_C(0xff200000)) == UINT32_C(0x24200000)) {
        unsigned inverse = (word >> 13) & 1u;

        expected_name = unsigned_names[inverse][relation];
        immediate = (word >> 14) & 127u;
    } else if ((word & UINT32_C(0xff204000))
                   == UINT32_C(0x25000000)) {
        unsigned operation = (word >> 13) & 7u;
        unsigned operation_index;
        uint64_t encoded_immediate;

        invariant(operation != 5u);
        operation_index = operation == 0u ? 0u
            : operation == 1u ? 1u : 2u;
        expected_name = signed_names[operation_index][relation];
        encoded_immediate = (word >> 16) & 31u;
        immediate = (encoded_immediate & 16u) != 0u
            ? encoded_immediate | ~UINT64_C(31)
            : encoded_immediate;
    } else {
        return;
    }

    size_code = (word >> 22) & 3u;
    pg = (word >> 10) & 7u;
    zn = (word >> 5) & 31u;
    pd = word & 15u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);

    invariant(instruction->name_id == expected_name);
    invariant(instruction->operand_count == 4u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(instruction->operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);
    invariant(instruction->operand[1].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[3].type == CDISASM_OPERAND_IMMEDIATE);
    invariant(instruction->operand[3].imm == immediate);
    invariant(instruction->operand[3].size == 1u);
    invariant(instruction->operand[3].flags
        == (((immediate >> 63) != 0u)
                ? CDISASM_OPERAND_FLAG_SIGNED : 0u));
    invariant(instruction->operand[3].access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_floating_compare_zero_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_FCMGE, CDISASM_ARM_NAME_FCMGT,
        CDISASM_ARM_NAME_FCMLT, CDISASM_ARM_NAME_FCMLE,
        CDISASM_ARM_NAME_FCMEQ, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_FCMNE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned size_code;
    unsigned pg;
    unsigned zn;
    unsigned pd;
    uint8_t element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff3ce000)) != UINT32_C(0x65102000)) {
        return;
    }
    operation = ((word >> 15) & 6u) | ((word >> 4) & 1u);
    size_code = (word >> 22) & 3u;
    pg = (word >> 10) & 7u;
    zn = (word >> 5) & 31u;
    pd = word & 15u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);

    invariant(size_code != 0u && operation != 5u && operation != 7u);
    invariant(instruction->name_id == names[operation]);
    invariant(instruction->operand_count == 4u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(instruction->operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);
    invariant(instruction->operand[1].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[3].type == CDISASM_OPERAND_IMMEDIATE);
    invariant(instruction->operand[3].imm == 0u);
    invariant(instruction->operand[3].size == 1u);
    invariant(instruction->operand[3].flags == 0u);
    invariant(instruction->operand[3].access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_floating_compare_vectors_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_FCMGE, CDISASM_ARM_NAME_FCMGT,
        CDISASM_ARM_NAME_FCMEQ, CDISASM_ARM_NAME_FCMNE,
        CDISASM_ARM_NAME_FCMUO, CDISASM_ARM_NAME_FACGE,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_FACGT
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned size_code;
    unsigned zm;
    unsigned pg;
    unsigned zn;
    unsigned pd;
    uint8_t element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff204000)) != UINT32_C(0x65004000)) {
        return;
    }
    operation = ((word >> 13) & 4u)
        | ((word >> 12) & 2u) | ((word >> 4) & 1u);
    size_code = (word >> 22) & 3u;
    zm = (word >> 16) & 31u;
    pg = (word >> 10) & 7u;
    zn = (word >> 5) & 31u;
    pd = word & 15u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);

    invariant(size_code != 0u && operation != 6u);
    invariant(instruction->name_id == names[operation]);
    invariant(instruction->operand_count == 4u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    invariant(instruction->operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);
    invariant(instruction->operand[1].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[3].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[3].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[3])
        == element_size);
    invariant(instruction->operand[3].access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_predicated_fp_binary_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[14] = {
        CDISASM_ARM_NAME_FADD, CDISASM_ARM_NAME_FSUB,
        CDISASM_ARM_NAME_FMUL, CDISASM_ARM_NAME_FSUBR,
        CDISASM_ARM_NAME_FMAXNM, CDISASM_ARM_NAME_FMINNM,
        CDISASM_ARM_NAME_FMAX, CDISASM_ARM_NAME_FMIN,
        CDISASM_ARM_NAME_FABD, CDISASM_ARM_NAME_FSCALE,
        CDISASM_ARM_NAME_FMULX, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_FDIVR, CDISASM_ARM_NAME_FDIV
    };
    static const cdisasm_arm_name_id bfloat_names[8] = {
        CDISASM_ARM_NAME_BFADD, CDISASM_ARM_NAME_BFSUB,
        CDISASM_ARM_NAME_BFMUL, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_BFMAXNM, CDISASM_ARM_NAME_BFMINNM,
        CDISASM_ARM_NAME_BFMAX, CDISASM_ARM_NAME_BFMIN
    };
    uint32_t word = instruction->raw_instruction;
    int bfloat;
    unsigned operation;
    unsigned size_code;
    unsigned zm;
    unsigned pg;
    unsigned zd;
    uint8_t element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff30e000)) != UINT32_C(0x65008000)) {
        return;
    }
    operation = (word >> 16) & 15u;
    size_code = (word >> 22) & 3u;
    bfloat = size_code == 0u && operation <= 7u;
    if ((size_code == 0u && !bfloat) || operation > 13u) {
        /* Other separately-featured B16 and FEAT_FAMINMAX neighbors. */
        return;
    }
    zm = (word >> 5) & 31u;
    pg = (word >> 10) & 7u;
    zd = word & 31u;
    element_size = bfloat
        ? 2u : (uint8_t)(UINT32_C(1) << size_code);

    invariant(operation != (bfloat ? 3u : 11u));
    invariant(instruction->name_id
        == (bfloat ? bfloat_names[operation] : names[operation]));
    invariant(instruction->operand_count == 4u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    invariant(instruction->operand[1].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[3].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[3].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[3])
        == element_size);
    invariant(instruction->operand[3].access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_fp_fast_reduction_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_FADDV, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_FMAXNMV, CDISASM_ARM_NAME_FMINNMV,
        CDISASM_ARM_NAME_FMAXV, CDISASM_ARM_NAME_FMINV
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned size_code;
    unsigned zn;
    unsigned pg;
    unsigned vd;
    uint8_t element_size;
    cdisasm_arm_reg_id scalar_base;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff38e000)) != UINT32_C(0x65002000)) {
        return;
    }
    operation = (word >> 16) & 7u;
    size_code = (word >> 22) & 3u;
    zn = (word >> 5) & 31u;
    pg = (word >> 10) & 7u;
    vd = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);
    scalar_base = size_code == 1u ? CDISASM_ARM_REG_H0
        : size_code == 2u ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;

    invariant(size_code != 0u);
    invariant(operation == 0u || operation >= 4u);
    invariant(instruction->name_id == names[operation]);
    invariant(instruction->operand_count == 3u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));

    invariant(instruction->operand[0].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(scalar_base + vd));
    invariant(instruction->operand[0].size == element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_fp_serial_reduction_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned size_code;
    unsigned zm;
    unsigned pg;
    unsigned vd;
    uint8_t element_size;
    cdisasm_arm_reg_id scalar_base;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff3fe000)) != UINT32_C(0x65182000)) {
        return;
    }
    size_code = (word >> 22) & 3u;
    zm = (word >> 5) & 31u;
    pg = (word >> 10) & 7u;
    vd = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);
    scalar_base = size_code == 1u ? CDISASM_ARM_REG_H0
        : size_code == 2u ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;

    invariant(size_code != 0u);
    invariant(instruction->name_id == CDISASM_ARM_NAME_FADDA);
    invariant(instruction->operand_count == 4u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));

    invariant(instruction->operand[0].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(scalar_base + vd));
    invariant(instruction->operand[0].size == element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type == CDISASM_OPERAND_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(scalar_base + vd));
    invariant(instruction->operand[2].size == element_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[3].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[3].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[3])
        == element_size);
    invariant(instruction->operand[3].flags == 0u);
    invariant(instruction->operand[3].access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_predicated_fp_unary_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[14] = {
        CDISASM_ARM_NAME_FRINTN, CDISASM_ARM_NAME_FRINTP,
        CDISASM_ARM_NAME_FRINTM, CDISASM_ARM_NAME_FRINTZ,
        CDISASM_ARM_NAME_FRINTA, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_FRINTX, CDISASM_ARM_NAME_FRINTI,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_FRECPX, CDISASM_ARM_NAME_FSQRT
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned size_code;
    unsigned pg;
    unsigned zn;
    unsigned zd;
    uint8_t element_size;
    int zeroing;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if ((word & UINT32_C(0xff38e000)) == UINT32_C(0x6500a000)
        || (word & UINT32_C(0xff3ee000)) == UINT32_C(0x650ca000)) {
        operation = (word >> 16) & 31u;
        zeroing = 0;
    } else if ((word & UINT32_C(0xff3e8000))
                   == UINT32_C(0x64188000)
        || (word & UINT32_C(0xff3fc000))
                   == UINT32_C(0x641b8000)) {
        operation = ((word >> 14) & 28u) | ((word >> 13) & 3u);
        zeroing = 1;
    } else {
        return;
    }

    size_code = (word >> 22) & 3u;
    pg = (word >> 10) & 7u;
    zn = (word >> 5) & 31u;
    zd = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);

    invariant(size_code != 0u);
    invariant(operation < sizeof(names) / sizeof(names[0]));
    invariant(operation != 5u);
    invariant(names[operation] != CDISASM_ARM_NAME_NONE);
    invariant(instruction->name_id == names[operation]);
    invariant(instruction->operand_count == 3u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == (zeroing ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ_WRITE));

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == (zeroing ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
                    : CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE));
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_fp_estimate_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int has_estimate_name = instruction->name_id == CDISASM_ARM_NAME_FRECPE
        || instruction->name_id == CDISASM_ARM_NAME_FRSQRTE;
    int is_scalable_estimate = has_estimate_name
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u;
    unsigned operation;
    unsigned size_code;
    unsigned zn;
    unsigned zd;
    uint8_t element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff3efc00)) != UINT32_C(0x650e3000)) {
        /* Keep the oracle bidirectional: these public IDs may never escape
         * the exact A64 encoding envelope if a descriptor mask is widened. */
        invariant(!is_scalable_estimate);
        return;
    }

    operation = (word >> 16) & 1u;
    size_code = (word >> 22) & 3u;
    zn = (word >> 5) & 31u;
    zd = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);

    invariant(size_code != 0u);
    invariant(has_estimate_name);
    invariant(instruction->name_id == (operation != 0u
        ? CDISASM_ARM_NAME_FRSQRTE : CDISASM_ARM_NAME_FRECPE));
    invariant(instruction->operand_count == 2u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static int is_multi_conversion_word(uint32_t word)
{
    unsigned selector = (((word >> 22) & 1u) << 4)
        | (((word >> 16) & 7u) << 1)
        | ((word >> 5) & 1u);
    int sme_envelope =
        (word & UINT32_C(0xffb8fc00)) == UINT32_C(0xc120e000);

    return (word & UINT32_C(0xfffff020)) == UINT32_C(0x650a3000)
        || (sme_envelope
            && (selector <= 8u || selector == 16u
                || selector == 17u || selector == 22u
                || selector == 24u));
}

static int is_sme2_multi4_conversion_word(uint32_t word)
{
    uint32_t fixed_list = word & UINT32_C(0xfffffc43);

    return fixed_list == UINT32_C(0xc131e000)
        || fixed_list == UINT32_C(0xc132e000)
        || (word & UINT32_C(0xff3ffc00)) == UINT32_C(0xc133e000)
        || (word & UINT32_C(0xfffffc40)) == UINT32_C(0xc134e000);
}

static void check_sme2_multi4_conversion_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id narrow_names[8] = {
        CDISASM_ARM_NAME_SQCVT,
        CDISASM_ARM_NAME_UQCVT,
        CDISASM_ARM_NAME_SQCVTN,
        CDISASM_ARM_NAME_UQCVTN,
        CDISASM_ARM_NAME_SQCVTU,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_SQCVTUN,
        CDISASM_ARM_NAME_NONE
    };
    static const cdisasm_arm_form_id narrow_forms[8] = {
        UINT16_C(4345), UINT16_C(4349), UINT16_C(4347), UINT16_C(4350),
        UINT16_C(4346), UINT16_C(0), UINT16_C(4348), UINT16_C(0)
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed_list = word & UINT32_C(0xfffffc43);
    unsigned source_base = ((word >> 7) & 7u) * 4u;
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    uint8_t destination_size;
    uint8_t source_size;
    int destination_is_list;
    int floating_point;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || !is_sme2_multi4_conversion_word(word)) {
        return;
    }

    if (fixed_list == UINT32_C(0xc131e000)
        || fixed_list == UINT32_C(0xc132e000)) {
        unsigned unsigned_conversion = (word >> 5) & 1u;
        int integer_to_float = fixed_list == UINT32_C(0xc132e000);

        expected_name = integer_to_float
            ? (unsigned_conversion != 0u
                ? CDISASM_ARM_NAME_UCVTF : CDISASM_ARM_NAME_SCVTF)
            : (unsigned_conversion != 0u
                ? CDISASM_ARM_NAME_FCVTZU : CDISASM_ARM_NAME_FCVTZS);
        expected_form = (cdisasm_arm_form_id)(
            (integer_to_float ? UINT16_C(4343) : UINT16_C(4341))
                + unsigned_conversion);
        destination_size = 4u;
        source_size = 4u;
        destination_is_list = 1;
        floating_point = 1;
    } else if ((word & UINT32_C(0xff3ffc00))
        == UINT32_C(0xc133e000)) {
        unsigned operation = (((word >> 22) & 1u) << 2)
            | ((word >> 5) & 3u);
        unsigned size = (word >> 23) & 1u;

        invariant(narrow_names[operation] != CDISASM_ARM_NAME_NONE);
        expected_name = narrow_names[operation];
        expected_form = narrow_forms[operation];
        destination_size = (uint8_t)(1u << size);
        source_size = (uint8_t)(4u << size);
        destination_is_list = 0;
        floating_point = 0;
    } else {
        unsigned narrow = (word >> 5) & 1u;

        expected_name = narrow != 0u
            ? CDISASM_ARM_NAME_FCVTN : CDISASM_ARM_NAME_FCVT;
        expected_form = (cdisasm_arm_form_id)(UINT16_C(4351) + narrow);
        destination_size = 1u;
        source_size = 4u;
        destination_is_list = 0;
        floating_point = 1;
    }

    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->operand_count == 2u);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_SME
            | (floating_point
                ? CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT : 0u)));

    invariant(instruction->operand[0].type
        == (destination_is_list
            ? CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
            : CDISASM_ARM_OPERAND_SCALABLE_REGISTER));
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
            + (destination_is_list
                ? ((word >> 2) & 7u) * 4u : word & 31u)));
    invariant(instruction->operand[0].register_list
        == (destination_is_list ? UINT16_C(0x0104) : UINT16_C(0)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == destination_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + source_base));
    invariant(instruction->operand[1].register_list == UINT16_C(0x0104));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == source_size);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
    invariant(source_base % 4u == 0u && source_base + 3u <= 31u);
}

static int is_sme2_multi4_followon_word(uint32_t word)
{
    return (word & UINT32_C(0xff3ffc22)) == UINT32_C(0xc135e000)
        || (word & UINT32_C(0xff3ffc61)) == UINT32_C(0xc136e000)
        || (word & UINT32_C(0xfffffc61)) == UINT32_C(0xc137e000)
        || (word & UINT32_C(0xff38fc63)) == UINT32_C(0xc138e000);
}

static void check_sme2_multi4_followon_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id frint_names[8] = {
        CDISASM_ARM_NAME_FRINTN,
        CDISASM_ARM_NAME_FRINTP,
        CDISASM_ARM_NAME_FRINTM,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_FRINTA,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_NONE
    };
    static const cdisasm_arm_form_id frint_forms[8] = {
        UINT16_C(4359), UINT16_C(4360), UINT16_C(4361), UINT16_C(0),
        UINT16_C(4362), UINT16_C(0), UINT16_C(0), UINT16_C(0)
    };
    uint32_t word = instruction->raw_instruction;
    unsigned destination_base = ((word >> 2) & 7u) * 4u;
    unsigned source_base = ((word >> 7) & 7u) * 4u;
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    uint16_t source_list = UINT16_C(0x0104);
    uint8_t destination_size;
    uint8_t source_size;
    int floating_point = 0;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || !is_sme2_multi4_followon_word(word)) {
        return;
    }

    if ((word & UINT32_C(0xff3ffc22))
        == UINT32_C(0xc135e000)) {
        unsigned unsigned_conversion = word & 1u;
        unsigned size = (word >> 22) & 3u;

        invariant(size != 0u);
        expected_name = unsigned_conversion != 0u
            ? CDISASM_ARM_NAME_UUNPK : CDISASM_ARM_NAME_SUNPK;
        expected_form = (cdisasm_arm_form_id)(
            UINT16_C(4353) + unsigned_conversion);
        destination_size = (uint8_t)(1u << size);
        source_size = (uint8_t)(1u << (size - 1u));
        source_base = ((word >> 6) & 15u) * 2u;
        source_list = UINT16_C(0x0102);
    } else if ((word & UINT32_C(0xff3ffc61))
        == UINT32_C(0xc136e000)) {
        unsigned unzip = (word >> 1) & 1u;

        expected_name = unzip != 0u
            ? CDISASM_ARM_NAME_UZP : CDISASM_ARM_NAME_ZIP;
        expected_form = (cdisasm_arm_form_id)(UINT16_C(4355) + unzip);
        destination_size = (uint8_t)(1u << ((word >> 22) & 3u));
        source_size = destination_size;
    } else if ((word & UINT32_C(0xfffffc61))
        == UINT32_C(0xc137e000)) {
        unsigned unzip = (word >> 1) & 1u;

        expected_name = unzip != 0u
            ? CDISASM_ARM_NAME_UZP : CDISASM_ARM_NAME_ZIP;
        expected_form = (cdisasm_arm_form_id)(UINT16_C(4357) + unzip);
        destination_size = 16u;
        source_size = 16u;
    } else {
        unsigned size = (word >> 22) & 3u;
        unsigned operation = (word >> 16) & 7u;

        invariant(size == 2u);
        invariant(frint_names[operation] != CDISASM_ARM_NAME_NONE);
        expected_name = frint_names[operation];
        expected_form = frint_forms[operation];
        destination_size = 4u;
        source_size = 4u;
        floating_point = 1;
    }

    invariant(instruction->name_id == expected_name);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->operand_count == 2u);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_SME
            | (floating_point
                ? CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT : 0u)));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + destination_base));
    invariant(instruction->operand[0].register_list == UINT16_C(0x0104));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == destination_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + source_base));
    invariant(instruction->operand[1].register_list == source_list);
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == source_size);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
    invariant(destination_base % 4u == 0u
        && destination_base + 3u <= 31u);
    invariant(source_base % (source_list == UINT16_C(0x0102) ? 2u : 4u)
        == 0u);
    invariant(source_base
        + (source_list == UINT16_C(0x0102) ? 1u : 3u) <= 31u);
}

static void check_sme_fmul_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t masks[4] = {
        UINT32_C(0xff21fc21), UINT32_C(0xff23fc63),
        UINT32_C(0xff21fc21), UINT32_C(0xff21fc63)
    };
    static const uint32_t values[4] = {
        UINT32_C(0xc120e400), UINT32_C(0xc121e400),
        UINT32_C(0xc120e800), UINT32_C(0xc121e800)
    };
    static const cdisasm_arm_form_id fmul_forms[4] = {
        UINT16_C(4363), UINT16_C(4365),
        UINT16_C(4367), UINT16_C(4369)
    };
    static const cdisasm_arm_form_id bfmul_forms[4] = {
        UINT16_C(4364), UINT16_C(4366),
        UINT16_C(4368), UINT16_C(4370)
    };
    uint32_t word = instruction->raw_instruction;
    unsigned descriptor;
    unsigned size;
    unsigned count;
    unsigned destination_base;
    unsigned first_source_base;
    unsigned second_source;
    uint8_t element_size;
    int scalar;
    const cdisasm_arm_operand *third;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    for (descriptor = 0u; descriptor < 4u; ++descriptor) {
        if ((word & masks[descriptor]) == values[descriptor]) {
            break;
        }
    }
    if (descriptor == 4u) {
        return;
    }

    size = (word >> 22) & 3u;
    count = (descriptor & 1u) != 0u ? 4u : 2u;
    scalar = descriptor >= 2u;
    destination_base = count == 4u ? word & 28u : word & 30u;
    first_source_base = count == 4u
        ? (word >> 5) & 28u : (word >> 5) & 30u;
    second_source = scalar
        ? (word >> 17) & 15u
        : count == 4u
            ? (word >> 16) & 28u : (word >> 16) & 30u;
    element_size = size == 0u
        ? UINT8_C(2) : (uint8_t)(UINT32_C(1) << size);

    invariant(instruction->name_id == (size == 0u
        ? CDISASM_ARM_NAME_BFMUL : CDISASM_ARM_NAME_FMUL));
    invariant(instruction->form_id == (size == 0u
        ? bfmul_forms[descriptor] : fmul_forms[descriptor]));
    invariant(instruction->operand_count == 3u);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SME
            | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + destination_base));
    invariant(instruction->operand[0].register_list
        == (uint16_t)(UINT16_C(0x0100) | count));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + first_source_base));
    invariant(instruction->operand[1].register_list
        == (uint16_t)(UINT16_C(0x0100) | count));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    third = &instruction->operand[2];
    invariant(third->type == (scalar
        ? CDISASM_ARM_OPERAND_SCALABLE_REGISTER
        : CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST));
    invariant(third->reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + second_source));
    invariant(third->register_list == (scalar
        ? UINT16_C(0) : (uint16_t)(UINT16_C(0x0100) | count)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(third) == element_size);
    invariant(third->flags == 0u);
    invariant(third->access == CDISASM_OPERAND_ACCESS_READ);
    invariant(destination_base % count == 0u
        && destination_base + count - 1u <= 31u);
    invariant(first_source_base % count == 0u
        && first_source_base + count - 1u <= 31u);
    invariant(scalar || (second_source % count == 0u
        && second_source + count - 1u <= 31u));
    invariant(!scalar || second_source <= 15u);
}

static void check_sme_za_load_store_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xffff9c10);
    unsigned rv;
    unsigned rn;
    unsigned off4;
    int load;
    uint8_t expected_memory_flags;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (fixed != UINT32_C(0xe1000000)
            && fixed != UINT32_C(0xe1200000))) {
        return;
    }
    load = fixed == UINT32_C(0xe1000000);
    rv = (word >> 13) & 3u;
    rn = (word >> 5) & 31u;
    off4 = word & 15u;
    expected_memory_flags = off4 == 0u
        ? CDISASM_OPERAND_FLAG_NONE
        : (uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_ARM_OPERAND_FLAG_VL_SCALED);

    invariant(instruction->name_id == (load
        ? CDISASM_ARM_NAME_LDR : CDISASM_ARM_NAME_STR));
    invariant(instruction->form_id == (load
        ? UINT16_C(4381) : UINT16_C(4382)));
    invariant(instruction->operand_count == 2u);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SME
            | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
            | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR));

    invariant(instruction->operand[0].type == CDISASM_ARM_OPERAND_TILE);
    invariant(instruction->operand[0].address == 0u);
    invariant(instruction->operand[0].reg == CDISASM_ARM_REG_ZA);
    invariant(instruction->operand[0].base_reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W12 + rv));
    invariant(instruction->operand[0].index_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[0].register_list == 0u);
    invariant(instruction->operand[0].imm == off4);
    invariant(instruction->operand[0].size == 0u);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].shift_type
        == CDISASM_ARM_SHIFT_NONE);
    invariant(instruction->operand[0].shift_amount == 0u);
    invariant(instruction->operand[0].extend_type
        == CDISASM_ARM_EXTEND_NONE);
    invariant(instruction->operand[0].scale == 0u);
    invariant(instruction->operand[0].access == (load
        ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ));

    invariant(instruction->operand[1].type == CDISASM_OPERAND_MEMORY);
    invariant(instruction->operand[1].address == 0u);
    invariant(instruction->operand[1].reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[1].base_reg == (rn == 31u
        ? CDISASM_ARM_REG_SP
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn)));
    invariant(instruction->operand[1].index_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[1].register_list == 0u);
    invariant(instruction->operand[1].size == 0u);
    invariant(instruction->operand[1].imm == off4);
    invariant(instruction->operand[1].flags == expected_memory_flags);
    invariant(instruction->operand[1].shift_type
        == CDISASM_ARM_SHIFT_NONE);
    invariant(instruction->operand[1].shift_amount == 0u);
    invariant(instruction->operand[1].extend_type
        == CDISASM_ARM_EXTEND_NONE);
    invariant(instruction->operand[1].scale == 0u);
    invariant(instruction->operand[1].access == (load
        ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE));
}

static void check_sme2_multi_mova_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_reg_id tile_bases[4] = {
        CDISASM_ARM_REG_ZAB0, CDISASM_ARM_REG_ZAH0,
        CDISASM_ARM_REG_ZAS0, CDISASM_ARM_REG_ZAD0
    };
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_form_id expected_form;
    const cdisasm_arm_operand *tile;
    const cdisasm_arm_operand *list;
    unsigned size = (word >> 22) & 3u;
    unsigned count;
    unsigned count_log2;
    unsigned group_offset_bits;
    unsigned encoded_list;
    unsigned encoded_slice;
    unsigned tile_number;
    unsigned tile_offset;
    uint8_t element_size;
    int extract = 0;
    int whole_array = 0;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if ((word & UINT32_C(0xff3f1c38)) == UINT32_C(0xc0040000)) {
        expected_form = (cdisasm_arm_form_id)(UINT16_C(3867) + size);
        count = 2u;
    } else if ((word & UINT32_C(0xff3f1c78))
            == UINT32_C(0xc0040400)
        && (size == 3u || (word & UINT32_C(4)) == 0u)) {
        expected_form = (cdisasm_arm_form_id)(UINT16_C(3871) + size);
        count = 4u;
    } else if ((word & UINT32_C(0xffff9c38))
            == UINT32_C(0xc0040800)) {
        expected_form = UINT16_C(3875);
        count = 2u;
        whole_array = 1;
    } else if ((word & UINT32_C(0xffff9c78))
            == UINT32_C(0xc0040c00)) {
        expected_form = UINT16_C(3876);
        count = 4u;
        whole_array = 1;
    } else if ((word & UINT32_C(0xff3f1f01))
            == UINT32_C(0xc0060000)) {
        expected_form = (cdisasm_arm_form_id)(UINT16_C(3882) + size);
        count = 2u;
        extract = 1;
    } else if ((word & UINT32_C(0xff3f1f03))
            == UINT32_C(0xc0060400)
        && (size == 3u || (word & UINT32_C(0x80)) == 0u)) {
        expected_form = (cdisasm_arm_form_id)(UINT16_C(3886) + size);
        count = 4u;
        extract = 1;
    } else if ((word & UINT32_C(0xffff9f01))
            == UINT32_C(0xc0060800)) {
        expected_form = UINT16_C(3890);
        count = 2u;
        whole_array = 1;
        extract = 1;
    } else if ((word & UINT32_C(0xffff9f03))
            == UINT32_C(0xc0060c00)) {
        expected_form = UINT16_C(3891);
        count = 4u;
        whole_array = 1;
        extract = 1;
    } else {
        return;
    }

    encoded_list = extract
        ? (count == 4u ? (word >> 2) & 7u : (word >> 1) & 15u)
        : (count == 4u ? (word >> 7) & 7u : (word >> 6) & 15u);
    encoded_slice = extract ? (word >> 5) & 7u : word & 7u;
    count_log2 = count == 4u ? 2u : 1u;
    group_offset_bits = 4u > size + count_log2
        ? 4u - size - count_log2 : 0u;
    tile_number = whole_array || group_offset_bits == 0u
        ? encoded_slice : encoded_slice >> group_offset_bits;
    tile_offset = whole_array ? encoded_slice
        : group_offset_bits == 0u ? 0u
        : (encoded_slice & ((1u << group_offset_bits) - 1u)) * count;
    element_size = whole_array ? 8u : (uint8_t)(1u << size);
    tile = &instruction->operand[extract ? 1u : 0u];
    list = &instruction->operand[extract ? 0u : 1u];

    invariant(instruction->name_id == CDISASM_ARM_NAME_MOV);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->operand_count == 2u);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SME
            | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
            | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR));
    invariant(tile->type == CDISASM_ARM_OPERAND_TILE);
    invariant(tile->reg == (whole_array ? CDISASM_ARM_REG_ZA
        : (cdisasm_arm_reg_id)(tile_bases[size] + tile_number)));
    invariant(tile->base_reg == (cdisasm_arm_reg_id)(
        (whole_array ? CDISASM_ARM_REG_W8 : CDISASM_ARM_REG_W12)
            + ((word >> 13) & 3u)));
    invariant(tile->index_reg == CDISASM_ARM_REG_NONE);
    invariant(tile->register_list == count);
    invariant(tile->address == 0u && tile->imm == tile_offset);
    invariant(tile->size == 0u);
    invariant(tile->flags == (!whole_array
            && (word & UINT32_C(0x00008000)) != 0u
        ? CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL
        : CDISASM_OPERAND_FLAG_NONE));
    invariant(tile->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(tile->shift_amount == 0u);
    invariant(tile->extend_type == element_size && tile->scale == 0u);
    invariant(tile->access == (extract
        ? CDISASM_OPERAND_ACCESS_READ
        : CDISASM_OPERAND_ACCESS_WRITE));
    invariant(list->type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    invariant(list->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + encoded_list * count));
    invariant(list->base_reg == CDISASM_ARM_REG_NONE);
    invariant(list->index_reg == CDISASM_ARM_REG_NONE);
    invariant(list->register_list
        == (uint16_t)(UINT16_C(0x0100) | count));
    invariant(list->address == 0u && list->imm == 0u);
    invariant(list->size == 0u && list->flags == 0u);
    invariant(list->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(list->shift_amount == 0u);
    invariant(list->extend_type == element_size && list->scale == 0u);
    invariant(list->access == (extract
        ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ));
}

static void check_sme2p1_movaz_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_reg_id tile_bases[5] = {
        CDISASM_ARM_REG_ZAB0, CDISASM_ARM_REG_ZAH0,
        CDISASM_ARM_REG_ZAS0, CDISASM_ARM_REG_ZAD0,
        CDISASM_ARM_REG_ZAQ0
    };
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_form_id expected_form;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *tile;
    unsigned size = (word >> 22) & 3u;
    unsigned element_log2 = size;
    unsigned count;
    unsigned encoded_destination;
    unsigned encoded_slice;
    unsigned count_log2;
    unsigned group_offset_bits;
    unsigned tile_number;
    unsigned tile_offset;
    uint8_t element_size;
    int whole_array = 0;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    if ((word & UINT32_C(0xff3e1e00)) == UINT32_C(0xc0020200)
        && ((word & UINT32_C(0x00010000)) == 0u || size == 3u)) {
        if ((word & UINT32_C(0x00010000)) != 0u) {
            element_log2 = 4u;
        }
        expected_form = (cdisasm_arm_form_id)(
            UINT16_C(3892) + element_log2);
        count = 1u;
        encoded_destination = word & 31u;
        encoded_slice = (word >> 5) & 15u;
    } else if ((word & UINT32_C(0xff3f1f01))
            == UINT32_C(0xc0060200)) {
        expected_form = (cdisasm_arm_form_id)(UINT16_C(3897) + size);
        count = 2u;
        encoded_destination = (word >> 1) & 15u;
        encoded_slice = (word >> 5) & 7u;
    } else if ((word & UINT32_C(0xff3f1f03))
            == UINT32_C(0xc0060600)
        && (size == 3u || (word & UINT32_C(0x80)) == 0u)) {
        expected_form = (cdisasm_arm_form_id)(UINT16_C(3901) + size);
        count = 4u;
        encoded_destination = (word >> 2) & 7u;
        encoded_slice = (word >> 5) & 7u;
    } else if ((word & UINT32_C(0xffff9f01))
            == UINT32_C(0xc0060a00)) {
        expected_form = UINT16_C(3905);
        count = 2u;
        encoded_destination = (word >> 1) & 15u;
        encoded_slice = (word >> 5) & 7u;
        element_log2 = 3u;
        whole_array = 1;
    } else if ((word & UINT32_C(0xffff9f03))
            == UINT32_C(0xc0060e00)) {
        expected_form = UINT16_C(3906);
        count = 4u;
        encoded_destination = (word >> 2) & 7u;
        encoded_slice = (word >> 5) & 7u;
        element_log2 = 3u;
        whole_array = 1;
    } else {
        return;
    }

    count_log2 = count == 4u ? 2u : count == 2u ? 1u : 0u;
    group_offset_bits = 4u > element_log2 + count_log2
        ? 4u - element_log2 - count_log2 : 0u;
    tile_number = whole_array || group_offset_bits == 0u
        ? encoded_slice : encoded_slice >> group_offset_bits;
    tile_offset = whole_array ? encoded_slice
        : group_offset_bits == 0u ? 0u
        : (encoded_slice & ((1u << group_offset_bits) - 1u)) * count;
    element_size = (uint8_t)(1u << element_log2);
    destination = &instruction->operand[0];
    tile = &instruction->operand[1];

    invariant(instruction->name_id == CDISASM_ARM_NAME_MOVAZ);
    invariant(instruction->form_id == expected_form);
    invariant(instruction->operand_count == 2u);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SME
            | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
            | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR));
    invariant(destination->type == (count == 1u
        ? CDISASM_ARM_OPERAND_SCALABLE_REGISTER
        : CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST));
    invariant(destination->reg == (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + encoded_destination * count));
    invariant(destination->base_reg == CDISASM_ARM_REG_NONE);
    invariant(destination->index_reg == CDISASM_ARM_REG_NONE);
    invariant(destination->register_list == (count == 1u ? 0u
        : (uint16_t)(UINT16_C(0x0100) | count)));
    invariant(destination->address == 0u && destination->imm == 0u);
    invariant(destination->size == 0u && destination->flags == 0u);
    invariant(destination->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(destination->shift_amount == 0u);
    invariant(destination->extend_type == element_size
        && destination->scale == 0u);
    invariant(destination->access == CDISASM_OPERAND_ACCESS_WRITE);
    invariant(tile->type == CDISASM_ARM_OPERAND_TILE);
    invariant(tile->reg == (whole_array ? CDISASM_ARM_REG_ZA
        : (cdisasm_arm_reg_id)(tile_bases[element_log2] + tile_number)));
    invariant(tile->base_reg == (cdisasm_arm_reg_id)(
        (whole_array ? CDISASM_ARM_REG_W8 : CDISASM_ARM_REG_W12)
            + ((word >> 13) & 3u)));
    invariant(tile->index_reg == CDISASM_ARM_REG_NONE);
    invariant(tile->register_list == (count == 1u ? 0u : count));
    invariant(tile->address == 0u && tile->imm == tile_offset);
    invariant(tile->size == 0u);
    invariant(tile->flags == (!whole_array
            && (word & UINT32_C(0x00008000)) != 0u
        ? CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL
        : CDISASM_OPERAND_FLAG_NONE));
    invariant(tile->shift_type == CDISASM_ARM_SHIFT_NONE);
    invariant(tile->shift_amount == 0u);
    invariant(tile->extend_type == element_size && tile->scale == 0u);
    invariant(tile->access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sme_za_contiguous_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t values[10] = {
        UINT32_C(0xe0000000), UINT32_C(0xe0200000),
        UINT32_C(0xe0400000), UINT32_C(0xe0600000),
        UINT32_C(0xe0800000), UINT32_C(0xe0a00000),
        UINT32_C(0xe0c00000), UINT32_C(0xe0e00000),
        UINT32_C(0xe1c00000), UINT32_C(0xe1e00000)
    };
    static const cdisasm_arm_name_id names[10] = {
        CDISASM_ARM_NAME_LD1B, CDISASM_ARM_NAME_ST1B,
        CDISASM_ARM_NAME_LD1H, CDISASM_ARM_NAME_ST1H,
        CDISASM_ARM_NAME_LD1W, CDISASM_ARM_NAME_ST1W,
        CDISASM_ARM_NAME_LD1D, CDISASM_ARM_NAME_ST1D,
        CDISASM_ARM_NAME_LD1Q, CDISASM_ARM_NAME_ST1Q
    };
    static const cdisasm_arm_form_id forms[10] = {
        UINT16_C(4373), UINT16_C(4377),
        UINT16_C(4374), UINT16_C(4378),
        UINT16_C(4375), UINT16_C(4379),
        UINT16_C(4376), UINT16_C(4380),
        UINT16_C(4385), UINT16_C(4386)
    };
    static const cdisasm_arm_reg_id tile_bases[5] = {
        CDISASM_ARM_REG_ZAB0, CDISASM_ARM_REG_ZAH0,
        CDISASM_ARM_REG_ZAS0, CDISASM_ARM_REG_ZAD0,
        CDISASM_ARM_REG_ZAQ0
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xffe00010);
    unsigned index;
    unsigned element_log2;
    unsigned element_size;
    unsigned offset_bits;
    unsigned low;
    unsigned rm;
    unsigned rn;
    int load;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    for (index = 0u; index < 10u && fixed != values[index]; ++index) {
    }
    if (index == 10u) {
        return;
    }
    element_log2 = index / 2u;
    element_size = 1u << element_log2;
    offset_bits = 4u - element_log2;
    low = word & 15u;
    rm = (word >> 16) & 31u;
    rn = (word >> 5) & 31u;
    load = (index & 1u) == 0u;

    invariant(instruction->name_id == names[index]);
    invariant(instruction->form_id == forms[index]);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SME
            | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
            | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    invariant(instruction->operand_count == 3u);

    invariant(instruction->operand[0].type == CDISASM_ARM_OPERAND_TILE);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(tile_bases[element_log2]
            + (low >> offset_bits)));
    invariant(instruction->operand[0].base_reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W12
            + ((word >> 13) & 3u)));
    invariant(instruction->operand[0].index_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[0].register_list == 0u);
    invariant(instruction->operand[0].address == 0u);
    invariant(instruction->operand[0].imm == (offset_bits == 0u
        ? 0u : low & ((1u << offset_bits) - 1u)));
    invariant(instruction->operand[0].size == 0u);
    invariant(instruction->operand[0].flags
        == ((word & UINT32_C(0x00008000)) != 0u
            ? CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL
            : CDISASM_OPERAND_FLAG_NONE));
    invariant(instruction->operand[0].shift_type
        == CDISASM_ARM_SHIFT_NONE);
    invariant(instruction->operand[0].shift_amount == 0u);
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].scale == 0u);
    invariant(instruction->operand[0].access == (load
        ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ));

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0
            + ((word >> 10) & 7u)));
    invariant(instruction->operand[1].base_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[1].index_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[1].register_list == 0u);
    invariant(instruction->operand[1].address == 0u);
    invariant(instruction->operand[1].imm == 0u);
    invariant(instruction->operand[1].size == 0u);
    invariant(instruction->operand[1].flags == (load
        ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
        : CDISASM_OPERAND_FLAG_NONE));
    invariant(instruction->operand[1].shift_type
        == CDISASM_ARM_SHIFT_NONE);
    invariant(instruction->operand[1].shift_amount == 0u);
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].scale == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type == CDISASM_OPERAND_MEMORY);
    invariant(instruction->operand[2].reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[2].base_reg == (rn == 31u
        ? CDISASM_ARM_REG_SP
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn)));
    invariant(instruction->operand[2].index_reg == (rm == 31u
        ? CDISASM_ARM_REG_NONE
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rm)));
    invariant(instruction->operand[2].register_list == 0u);
    invariant(instruction->operand[2].address == 0u);
    invariant(instruction->operand[2].imm == 0u);
    invariant(instruction->operand[2].size == 0u);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].shift_type
        == (rm == 31u || element_log2 == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL));
    invariant(instruction->operand[2].shift_amount
        == (rm == 31u ? 0u : element_log2));
    invariant(instruction->operand[2].extend_type
        == CDISASM_ARM_EXTEND_NONE);
    invariant(instruction->operand[2].scale == 0u);
    invariant(instruction->operand[2].access == (load
        ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE));
}

static void check_sme2_zt0_load_store_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xfffffc1f);
    unsigned rn;
    int load;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (fixed != UINT32_C(0xe11f8000)
            && fixed != UINT32_C(0xe13f8000))) {
        return;
    }
    load = fixed == UINT32_C(0xe11f8000);
    rn = (word >> 5) & 31u;

    invariant(instruction->name_id == (load
        ? CDISASM_ARM_NAME_LDR : CDISASM_ARM_NAME_STR));
    invariant(instruction->form_id == (load
        ? UINT16_C(4383) : UINT16_C(4384)));
    invariant(instruction->operand_count == 2u);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SME
            | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX));

    invariant(instruction->operand[0].type == CDISASM_ARM_OPERAND_TILE);
    invariant(instruction->operand[0].reg == CDISASM_ARM_REG_ZT0);
    invariant(instruction->operand[0].base_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[0].index_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[0].size == 0u);
    invariant(instruction->operand[0].extend_type
        == CDISASM_ARM_EXTEND_NONE);
    invariant(instruction->operand[0].access == (load
        ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ));

    invariant(instruction->operand[1].type == CDISASM_OPERAND_MEMORY);
    invariant(instruction->operand[1].base_reg == (rn == 31u
        ? CDISASM_ARM_REG_SP
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn)));
    invariant(instruction->operand[1].index_reg == CDISASM_ARM_REG_NONE);
    invariant(instruction->operand[1].size == 64u);
    invariant(instruction->operand[1].imm == 0u);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access == (load
        ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE));
}

static int is_sme2_multi_wide_integer_word(uint32_t word)
{
    return (word & UINT32_C(0xff3ffc00)) == UINT32_C(0xc125e000);
}

static void check_sme2_multi_wide_integer_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned size;
    unsigned source_element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || !is_sme2_multi_wide_integer_word(word)) {
        return;
    }

    size = (word >> 22) & 3u;
    invariant(size != 0u);
    source_element_size = size != 0u ? 1u << (size - 1u) : 0u;
    invariant(instruction->name_id == ((word & 1u) != 0u
        ? CDISASM_ARM_NAME_UUNPK : CDISASM_ARM_NAME_SUNPK));
    invariant(instruction->form_id == ((word & 1u) != 0u
        ? UINT16_C(4326) : UINT16_C(4325)));
    invariant(instruction->operand_count == 2u);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_SME));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + (word & 30u)));
    invariant(instruction->operand[0].register_list == UINT16_C(0x0102));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == source_element_size * 2u);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
            + ((word >> 5) & 31u)));
    invariant(instruction->operand[1].register_list == UINT16_C(0));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == source_element_size);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static int is_sme2_multi_wide_fp8_word(uint32_t word)
{
    return (word & UINT32_C(0xff3ffc00)) == UINT32_C(0xc126e000);
}

static void check_sme2_multi_wide_fp8_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[4][2] = {
        { CDISASM_ARM_NAME_F1CVT, CDISASM_ARM_NAME_F1CVTL },
        { CDISASM_ARM_NAME_BF1CVT, CDISASM_ARM_NAME_BF1CVTL },
        { CDISASM_ARM_NAME_F2CVT, CDISASM_ARM_NAME_F2CVTL },
        { CDISASM_ARM_NAME_BF2CVT, CDISASM_ARM_NAME_BF2CVTL }
    };
    static const cdisasm_arm_form_id forms[4][2] = {
        { UINT16_C(4327), UINT16_C(4331) },
        { UINT16_C(4328), UINT16_C(4332) },
        { UINT16_C(4329), UINT16_C(4333) },
        { UINT16_C(4330), UINT16_C(4334) }
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned late;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || !is_sme2_multi_wide_fp8_word(word)) {
        return;
    }

    operation = (word >> 22) & 3u;
    late = word & 1u;
    invariant(instruction->name_id == names[operation][late]);
    invariant(instruction->form_id == forms[operation][late]);
    invariant(instruction->operand_count == 2u);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SME));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + (word & 30u)));
    invariant(instruction->operand[0].register_list == UINT16_C(0x0102));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == 2u);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
            + ((word >> 5) & 31u)));
    invariant(instruction->operand[1].register_list == UINT16_C(0));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == 1u);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve2p1_multi_extract_narrow_class(
    const cdisasm_arm_instruction *instruction)
{
    static const struct operation {
        uint32_t value;
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
    } operations[] = {
        { UINT32_C(0x45314000), CDISASM_ARM_NAME_SQCVTN, UINT16_C(2881) },
        { UINT32_C(0x45315000), CDISASM_ARM_NAME_SQCVTUN, UINT16_C(2882) },
        { UINT32_C(0x45314800), CDISASM_ARM_NAME_UQCVTN, UINT16_C(2883) }
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xfffffc20);
    size_t operation_index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    for (operation_index = 0u;
         operation_index < sizeof(operations) / sizeof(operations[0]);
         ++operation_index) {
        if (fixed == operations[operation_index].value) {
            break;
        }
    }
    if (operation_index
        == sizeof(operations) / sizeof(operations[0])) {
        return;
    }

    invariant(instruction->name_id == operations[operation_index].name_id);
    invariant(instruction->form_id == operations[operation_index].form_id);
    invariant(instruction->operand_count == 2u);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + (word & 31u)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == 2u);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
            + (((word >> 6) & 15u) * 2u)));
    invariant(instruction->operand[1].register_list == UINT16_C(0x0102));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == 4u);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sme2_multi_frint_class(
    const cdisasm_arm_instruction *instruction)
{
    static const struct operation {
        uint32_t value;
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
    } operations[] = {
        { UINT32_C(0xc1a8e000), CDISASM_ARM_NAME_FRINTN, UINT16_C(4335) },
        { UINT32_C(0xc1a9e000), CDISASM_ARM_NAME_FRINTP, UINT16_C(4336) },
        { UINT32_C(0xc1aae000), CDISASM_ARM_NAME_FRINTM, UINT16_C(4337) },
        { UINT32_C(0xc1ace000), CDISASM_ARM_NAME_FRINTA, UINT16_C(4338) }
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xfffffc21);
    size_t operation_index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return;
    }
    for (operation_index = 0u;
         operation_index < sizeof(operations) / sizeof(operations[0]);
         ++operation_index) {
        if (fixed == operations[operation_index].value) {
            break;
        }
    }
    if (operation_index
        == sizeof(operations) / sizeof(operations[0])) {
        return;
    }

    invariant(instruction->name_id == operations[operation_index].name_id);
    invariant(instruction->form_id == operations[operation_index].form_id);
    invariant(instruction->operand_count == 2u);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SME));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + (word & 30u)));
    invariant(instruction->operand[0].register_list == UINT16_C(0x0102));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == 4u);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
            + (((word >> 6) & 15u) * 2u)));
    invariant(instruction->operand[1].register_list == UINT16_C(0x0102));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == 4u);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sme_f16f16_multi_wide_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xfffffc00)) != UINT32_C(0xc1a0e000)) {
        return;
    }

    invariant(instruction->name_id == ((word & 1u) != 0u
        ? CDISASM_ARM_NAME_FCVTL : CDISASM_ARM_NAME_FCVT));
    invariant(instruction->form_id == ((word & 1u) != 0u
        ? UINT16_C(4340) : UINT16_C(4339)));
    invariant(instruction->operand_count == 2u);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SME));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + (word & 30u)));
    invariant(instruction->operand[0].register_list == UINT16_C(0x0102));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == 4u);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
            + ((word >> 5) & 31u)));
    invariant(instruction->operand[1].register_list == UINT16_C(0));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == 2u);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_int_to_fp_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int has_conversion_name =
        instruction->name_id == CDISASM_ARM_NAME_SCVTF
        || instruction->name_id == CDISASM_ARM_NAME_UCVTF;
    unsigned operation;
    unsigned pg;
    unsigned zn;
    unsigned zd;
    uint8_t destination_element_size;
    uint8_t source_element_size;

    /* SCVTF/UCVTF also name scalar, AdvSIMD, and newer generated forms.
     * Their generated-tree validity and operand lowering have independent
     * oracles; this checker owns only the handwritten predicated-SVE class. */
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u) {
        return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        invariant(!has_conversion_name);
        return;
    }
    if (is_multi_conversion_word(word)
        || is_sme2_multi4_conversion_word(word)) {
        return;
    }

    if ((word & UINT32_C(0xfff8e000)) == UINT32_C(0x6550a000)) {
        operation = (word >> 16) & 7u;
        invariant(operation >= 2u);
        destination_element_size = 2u;
        source_element_size = (uint8_t)(operation < 4u ? 2u
            : operation < 6u ? 4u : 8u);
    } else {
        operation = (word >> 16) & 0xfeu;
        if ((word & UINT32_C(0xfffee000)) == UINT32_C(0x6594a000)) {
            destination_element_size = 4u;
            source_element_size = 4u;
        } else if ((word & UINT32_C(0xfffee000))
            == UINT32_C(0x65d4a000)) {
            destination_element_size = 4u;
            source_element_size = 8u;
        } else if ((word & UINT32_C(0xfffee000))
            == UINT32_C(0x65d0a000)) {
            destination_element_size = 8u;
            source_element_size = 4u;
        } else if ((word & UINT32_C(0xfffee000))
            == UINT32_C(0x65d6a000)) {
            destination_element_size = 8u;
            source_element_size = 8u;
        } else {
            invariant(!has_conversion_name);
            return;
        }
    }

    pg = (word >> 10) & 7u;
    zn = (word >> 5) & 31u;
    zd = word & 31u;

    invariant(has_conversion_name);
    invariant(instruction->name_id == ((word & UINT32_C(0x00010000)) != 0u
        ? CDISASM_ARM_NAME_UCVTF : CDISASM_ARM_NAME_SCVTF));
    invariant(instruction->operand_count == 3u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == destination_element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == source_element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == source_element_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_fcvt_class(
    const cdisasm_arm_instruction *instruction)
{
    static const uint8_t destination_sizes[8] = {
        2u, 4u, 0u, 0u, 2u, 8u, 4u, 8u
    };
    static const uint8_t source_sizes[8] = {
        4u, 2u, 0u, 0u, 8u, 2u, 8u, 4u
    };
    uint32_t word = instruction->raw_instruction;
    int has_fcvt_name = instruction->name_id == CDISASM_ARM_NAME_FCVT;
    int zeroing = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xffffe000)) == UINT32_C(0x649a8000);
    int merging = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xffbce000)) == UINT32_C(0x6588a000);
    uint8_t destination_size;
    uint8_t source_size;
    cdisasm_operand_access destination_access;
    uint8_t predicate_flag;
    unsigned selector;
    unsigned pg;
    unsigned zn;
    unsigned zd;

    if (is_multi_conversion_word(word)
        || is_sme2_multi4_conversion_word(word)
        || (instruction->isa_id == CDISASM_ARM_ISA_A64
            && (word & UINT32_C(0xfffffc00))
                == UINT32_C(0xc1a0e000))) {
        return;
    }
    if (!zeroing && !merging) {
        /* The public FCVT ID may only escape from these exact A64 classes. */
        invariant(!has_fcvt_name);
        return;
    }

    if (zeroing) {
        selector = 0u;
        destination_size = 2u;
        source_size = 4u;
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        predicate_flag = CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO;
    } else {
        selector = (((word >> 22) & 1u) << 2) | ((word >> 16) & 3u);
        if (selector == 2u || selector == 3u) {
            invariant(!has_fcvt_name);
            return;
        }
        destination_size = destination_sizes[selector];
        source_size = source_sizes[selector];
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        predicate_flag = CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE;
    }
    pg = (word >> 10) & 7u;
    zn = (word >> 5) & 31u;
    zd = word & 31u;

    invariant(has_fcvt_name);
    invariant(instruction->operand_count == 3u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == destination_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access == destination_access);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == source_size);
    invariant(instruction->operand[1].flags == predicate_flag);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == source_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static int is_multi_bf16_word(uint32_t word)
{
    uint32_t sme_fixed = word & UINT32_C(0xfffffc20);

    return sme_fixed == UINT32_C(0xc160e000)
        || sme_fixed == UINT32_C(0xc160e020)
        || sme_fixed == UINT32_C(0xc164e000)
        || (word & UINT32_C(0xfffffc20)) == UINT32_C(0x650a3800);
}

static void check_multi_bf16_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id sve_names[4] = {
        CDISASM_ARM_NAME_FCVTN,
        CDISASM_ARM_NAME_FCVTNB,
        CDISASM_ARM_NAME_BFCVTN,
        CDISASM_ARM_NAME_FCVTNT
    };
    static const cdisasm_arm_name_id sme_names[32] = {
        [0] = CDISASM_ARM_NAME_FCVT,
        [1] = CDISASM_ARM_NAME_FCVTN,
        [2] = CDISASM_ARM_NAME_FCVTZS,
        [3] = CDISASM_ARM_NAME_FCVTZU,
        [4] = CDISASM_ARM_NAME_SCVTF,
        [5] = CDISASM_ARM_NAME_UCVTF,
        [6] = CDISASM_ARM_NAME_SQCVT,
        [7] = CDISASM_ARM_NAME_UQCVT,
        [8] = CDISASM_ARM_NAME_FCVT,
        [16] = CDISASM_ARM_NAME_BFCVT,
        [17] = CDISASM_ARM_NAME_BFCVTN,
        [22] = CDISASM_ARM_NAME_SQCVTU,
        [24] = CDISASM_ARM_NAME_BFCVT
    };
    uint32_t word = instruction->raw_instruction;
    int multi = instruction->isa_id == CDISASM_ARM_ISA_A64
        && is_multi_conversion_word(word);
    int sve_fp8 =
        (word & UINT32_C(0xfffff020)) == UINT32_C(0x650a3000);
    int sme = !sve_fp8;
    unsigned selector = (((word >> 22) & 1u) << 4)
        | (((word >> 16) & 7u) << 1)
        | ((word >> 5) & 1u);
    unsigned operation = (word >> 10) & 3u;
    unsigned source_base = ((word >> 6) & 15u) * 2u;
    unsigned destination = word & 31u;
    int destination_is_list = sme && selector >= 2u && selector <= 5u;
    int floating_point = sve_fp8
        || (selector != 6u && selector != 7u && selector != 22u);
    uint8_t destination_size = destination_is_list ? 4u
        : (sve_fp8 || selector == 8u || selector == 24u) ? 1u : 2u;
    uint8_t source_size = sve_fp8
        ? (operation == 0u || operation == 2u ? 2u : 4u)
        : (selector == 8u || selector == 24u) ? 2u : 4u;

    if (!multi) {
        return;
    }

    if (sve_fp8) {
        invariant(instruction->name_id == sve_names[operation]);
    } else {
        invariant(sme_names[selector] != CDISASM_ARM_NAME_NONE);
        invariant(instruction->name_id == sme_names[selector]);
    }
    invariant(instruction->operand_count == 2u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | (floating_point
                ? CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT : 0u)
            | (sme ? CDISASM_ARM_INSTRUCTION_FLAG_SME : 0u)));

    invariant(instruction->operand[0].type
        == (destination_is_list
            ? CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
            : CDISASM_ARM_OPERAND_SCALABLE_REGISTER));
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
            + (destination_is_list ? destination & ~1u : destination)));
    invariant(instruction->operand[0].register_list
        == (destination_is_list ? UINT16_C(0x0102) : UINT16_C(0)));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == destination_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + source_base));
    invariant(instruction->operand[1].register_list == UINT16_C(0x0102));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == source_size);
    invariant(instruction->operand[1].flags == 0u);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_predicated_bf16_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int has_bfcvt_name = instruction->name_id == CDISASM_ARM_NAME_BFCVT;
    int has_bfcvtnt_name =
        instruction->name_id == CDISASM_ARM_NAME_BFCVTNT;
    uint32_t fixed = word & UINT32_C(0xffffe000);
    int top;
    int zeroing;
    unsigned pg;
    unsigned zn;
    unsigned zd;

    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && is_multi_bf16_word(word)) {
        return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (fixed != UINT32_C(0x658aa000)
            && fixed != UINT32_C(0x648aa000)
            && fixed != UINT32_C(0x649ac000)
            && fixed != UINT32_C(0x6482a000))) {
        invariant(!has_bfcvt_name);
        invariant(!has_bfcvtnt_name);
        return;
    }

    top = fixed == UINT32_C(0x648aa000)
        || fixed == UINT32_C(0x6482a000);
    zeroing = fixed == UINT32_C(0x649ac000)
        || fixed == UINT32_C(0x6482a000);
    pg = (word >> 10) & 7u;
    zn = (word >> 5) & 31u;
    zd = word & 31u;
    invariant(top ? has_bfcvtnt_name : has_bfcvt_name);
    invariant(top ? !has_bfcvt_name : !has_bfcvtnt_name);
    invariant(instruction->operand_count == 3u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == 2u);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == (!zeroing || top
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE));

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == 4u);
    invariant(instruction->operand[1].flags
        == (zeroing
                ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
                : CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE));
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == 4u);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_fp_to_int_class(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int has_conversion_name =
        instruction->name_id == CDISASM_ARM_NAME_FCVTZS
        || instruction->name_id == CDISASM_ARM_NAME_FCVTZU;
    unsigned selector;
    unsigned pg;
    unsigned zn;
    unsigned zd;
    uint8_t destination_element_size;
    uint8_t source_element_size;

    /* FCVTZS/FCVTZU also name scalar, AdvSIMD, and newer generated forms.
     * Their generated-tree validity and operand lowering have independent
     * oracles; this checker owns only the handwritten predicated-SVE class. */
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u) {
        return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        invariant(!has_conversion_name);
        return;
    }
    if (is_multi_conversion_word(word)
        || is_sme2_multi4_conversion_word(word)) {
        return;
    }

    selector = (word >> 16) & 7u;
    if ((word & UINT32_C(0xfff8e000)) == UINT32_C(0x6558a000)) {
        if (selector < 2u) {
            invariant(!has_conversion_name);
            return;
        }
        source_element_size = 2u;
        destination_element_size = (uint8_t)(selector < 4u ? 2u
            : selector < 6u ? 4u : 8u);
    } else if ((word & UINT32_C(0xfffee000))
        == UINT32_C(0x659ca000)) {
        destination_element_size = 4u;
        source_element_size = 4u;
    } else if ((word & UINT32_C(0xfff8e000))
        == UINT32_C(0x65d8a000)) {
        if (selector == 2u || selector == 3u) {
            invariant(!has_conversion_name);
            return;
        }
        if (selector < 2u) {
            destination_element_size = 4u;
            source_element_size = 8u;
        } else if (selector < 6u) {
            destination_element_size = 8u;
            source_element_size = 4u;
        } else {
            destination_element_size = 8u;
            source_element_size = 8u;
        }
    } else {
        invariant(!has_conversion_name);
        return;
    }

    pg = (word >> 10) & 7u;
    zn = (word >> 5) & 31u;
    zd = word & 31u;

    invariant(has_conversion_name);
    invariant(instruction->name_id
        == ((word & UINT32_C(0x00010000)) != 0u
            ? CDISASM_ARM_NAME_FCVTZU : CDISASM_ARM_NAME_FCVTZS));
    invariant(instruction->operand_count == 3u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == destination_element_size);
    invariant(instruction->operand[0].flags == 0u);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == source_element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    invariant(instruction->operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == source_element_size);
    invariant(instruction->operand[2].flags == 0u);
    invariant(instruction->operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
}

static void check_advsimd_fp_estimate_class(
    const cdisasm_arm_instruction *instruction)
{
    const uint32_t word = instruction->raw_instruction;
    const int has_estimate_name =
        instruction->name_id == CDISASM_ARM_NAME_FRECPE
        || instruction->name_id == CDISASM_ARM_NAME_FRSQRTE;
    const int is_scalable = (instruction->instruction_flags
        & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u;
    const int scalar_half =
        (word & UINT32_C(0xdffffc00)) == UINT32_C(0x5ef9d800);
    const int scalar_single_double =
        (word & UINT32_C(0xdfbffc00)) == UINT32_C(0x5ea1d800);
    const int vector_half =
        (word & UINT32_C(0x9ffffc00)) == UINT32_C(0x0ef9d800);
    const int vector_single_double =
        (word & UINT32_C(0x9fbffc00)) == UINT32_C(0x0ea1d800);
    const int in_fixed_estimate_class = scalar_half
        || scalar_single_double || vector_half || vector_single_double;
    const unsigned operation = (word >> 29) & 1u;
    const unsigned rn = (word >> 5) & 31u;
    const unsigned rd = word & 31u;
    uint8_t element_size;
    cdisasm_arm_reg_id register_base;
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || !in_fixed_estimate_class) {
        /* Keep this oracle bidirectional without excluding the separate SVE
         * encodings or possible future A32/T32 forms sharing the public IDs. */
        invariant(instruction->isa_id != CDISASM_ARM_ISA_A64
            || !has_estimate_name || is_scalable);
        return;
    }

    invariant(has_estimate_name);
    invariant(!is_scalable);
    invariant(instruction->name_id == (operation != 0u
        ? CDISASM_ARM_NAME_FRSQRTE : CDISASM_ARM_NAME_FRECPE));
    invariant(instruction->condition == CDISASM_ARM_CONDITION_AL);
    invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
    invariant(instruction->operand_count == 2u);

    if (scalar_half || scalar_single_double) {
        if (scalar_half) {
            element_size = 2u;
            register_base = CDISASM_ARM_REG_H0;
        } else if ((word & UINT32_C(0x00400000)) == 0u) {
            element_size = 4u;
            register_base = CDISASM_ARM_REG_S0;
        } else {
            element_size = 8u;
            register_base = CDISASM_ARM_REG_D0;
        }

        invariant(instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
        for (index = 0u; index < 2u; ++index) {
            const cdisasm_arm_operand *operand =
                &instruction->operand[index];
            const unsigned encoded = index == 0u ? rd : rn;

            invariant(operand->type == CDISASM_OPERAND_REGISTER);
            invariant(operand->reg
                == (cdisasm_arm_reg_id)(register_base + encoded));
            invariant(operand->size == element_size);
            invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
            invariant(operand->extend_type == CDISASM_ARM_EXTEND_NONE);
            invariant(operand->scale == 0u);
            invariant(operand->access == (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ));
        }
        return;
    }

    invariant(!vector_single_double
        || (word & UINT32_C(0x40400000)) != UINT32_C(0x00400000));
    element_size = vector_half ? 2u
        : (word & UINT32_C(0x00400000)) != 0u ? 8u : 4u;
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        const unsigned encoded = index == 0u ? rd : rn;
        const uint8_t total_size =
            (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;

        invariant(operand->type == CDISASM_OPERAND_REGISTER);
        invariant(operand->reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded));
        invariant(operand->size == total_size);
        invariant(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == element_size);
        invariant(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand)
            == (uint8_t)(total_size / element_size));
        invariant(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
    }
}

static void check_sve_predicated_vector_shift_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[16] = {
        CDISASM_ARM_NAME_ASR, CDISASM_ARM_NAME_LSR,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_LSL,
        CDISASM_ARM_NAME_ASRR, CDISASM_ARM_NAME_LSRR,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_LSLR,
        CDISASM_ARM_NAME_ASR, CDISASM_ARM_NAME_LSR,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_LSL,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned size_code;
    unsigned pg;
    unsigned zm;
    unsigned zd;
    uint8_t element_size;
    uint8_t source_element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff30e000)) != UINT32_C(0x04108000)) {
        return;
    }

    operation = (word >> 16) & 15u;
    size_code = (word >> 22) & 3u;
    pg = (word >> 10) & 7u;
    zm = (word >> 5) & 31u;
    zd = word & 31u;
    element_size = (uint8_t)(UINT32_C(1) << size_code);
    source_element_size = operation >= 8u ? UINT8_C(8) : element_size;

    invariant(names[operation] != CDISASM_ARM_NAME_NONE);
    invariant(operation < 8u || size_code != 3u);
    invariant(instruction->name_id == names[operation]);
    invariant(instruction->operand_count == 4u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    invariant(instruction->operand[1].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[3].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[3].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[3])
        == source_element_size);
    invariant(instruction->operand[3].access == CDISASM_OPERAND_ACCESS_READ);
}

static void check_sve_predicated_immediate_shift_class(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[16] = {
        CDISASM_ARM_NAME_ASR, CDISASM_ARM_NAME_LSR,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_LSL,
        CDISASM_ARM_NAME_ASRD, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_SQSHL, CDISASM_ARM_NAME_UQSHL,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_SRSHR, CDISASM_ARM_NAME_URSHR,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_SQSHLU
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;
    unsigned encoded_immediate;
    unsigned element_bits;
    unsigned immediate;
    unsigned pg;
    unsigned zd;
    uint8_t element_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (word & UINT32_C(0xff30e000)) != UINT32_C(0x04008000)) {
        return;
    }

    operation = (word >> 16) & 15u;
    encoded_immediate = ((word >> 17) & 0x60u)
        | ((word >> 5) & 0x1fu);
    pg = (word >> 10) & 7u;
    zd = word & 31u;
    invariant(encoded_immediate >= 8u);
    invariant(names[operation] != CDISASM_ARM_NAME_NONE);
    element_bits = encoded_immediate >= 64u ? 64u
        : encoded_immediate >= 32u ? 32u
        : encoded_immediate >= 16u ? 16u : 8u;
    element_size = (uint8_t)(element_bits / 8u);
    immediate = operation == 3u || operation == 6u
            || operation == 7u || operation == 15u
        ? encoded_immediate - element_bits
        : 2u * element_bits - encoded_immediate;

    invariant(instruction->name_id == names[operation]);
    invariant(instruction->operand_count == 4u);
    invariant(instruction->instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));

    invariant(instruction->operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[0].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[0])
        == element_size);
    invariant(instruction->operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    invariant(instruction->operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    invariant(instruction->operand[1].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[1])
        == element_size);
    invariant(instruction->operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    invariant(instruction->operand[1].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    invariant(instruction->operand[2].reg
        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd));
    invariant(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction->operand[2])
        == element_size);
    invariant(instruction->operand[2].access == CDISASM_OPERAND_ACCESS_READ);

    invariant(instruction->operand[3].type == CDISASM_OPERAND_IMMEDIATE);
    invariant(instruction->operand[3].imm == immediate);
    invariant(instruction->operand[3].size == 1u);
    invariant(instruction->operand[3].access == CDISASM_OPERAND_ACCESS_READ);
}

#if USE_DISASM_FORMAT
static void check_format(const cdisasm_arm_instruction *instruction,
                         uint64_t selector)
{
    char full[FUZZ_FORMAT_CAPACITY];
    char short_buffer[32];
    size_t required;
    size_t written;
    size_t short_capacity = (size_t)(selector % sizeof(short_buffer));
    uint32_t format_flags = (uint32_t)selector
        & CDISASM_FORMAT_UPPERCASE_OPCODE;

    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE) != 0u) {
        format_flags = CDISASM_FORMAT_SYNTAX_ARM_CANONICAL;
    }

    required = cdisasm_arm_format(
        instruction, format_flags, NULL, 0);
    invariant(required != 0u);
    invariant(required < sizeof(full) - 1u);

    memset(full, 0xa5, sizeof(full));
    written = cdisasm_arm_format(
        instruction, format_flags, full, required + 1u);
    invariant(written == required);
    invariant(full[required] == '\0');
    invariant(strlen(full) == required);
    invariant(full[required + 1u] == (char)0xa5);

    memset(short_buffer, 0x5a, sizeof(short_buffer));
    written = cdisasm_arm_format(
        instruction, format_flags, short_buffer, short_capacity);
    invariant(written == required);
    if (short_capacity == 0u) {
        invariant(short_buffer[0] == (char)0x5a);
    } else {
        size_t copied = required < short_capacity - 1u
            ? required
            : short_capacity - 1u;

        invariant(short_buffer[copied] == '\0');
        if (short_capacity < sizeof(short_buffer)) {
            invariant(short_buffer[short_capacity] == (char)0x5a);
        }
    }

    memset(short_buffer, 0x5a, sizeof(short_buffer));
    invariant(cdisasm_arm_format(
                  instruction,
                  CDISASM_FORMAT_KNOWN_FLAGS_MASK + UINT32_C(1),
                  short_buffer,
                  sizeof(short_buffer))
        == 0u);
    invariant(short_buffer[0] == '\0');
}
#endif

static int fixed_advsimd_shift_right_immediate(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand, uint8_t operand_index)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t scalar_operation = word & UINT32_C(0xffc0fc00);
    uint32_t vector_operation = word & UINT32_C(0xbf80fc00);
    int scalar = (scalar_operation == UINT32_C(0x5f400400)
            && instruction->form_id == UINT16_C(5853)
            && instruction->name_id == CDISASM_ARM_NAME_SSHR)
        || (scalar_operation == UINT32_C(0x7f400400)
            && instruction->form_id == UINT16_C(5863)
            && instruction->name_id == CDISASM_ARM_NAME_USHR)
        || (scalar_operation == UINT32_C(0x5f401400)
            && instruction->form_id == UINT16_C(5854)
            && instruction->name_id == CDISASM_ARM_NAME_SSRA)
        || (scalar_operation == UINT32_C(0x7f401400)
            && instruction->form_id == UINT16_C(5864)
            && instruction->name_id == CDISASM_ARM_NAME_USRA)
        || (scalar_operation == UINT32_C(0x5f402400)
            && instruction->form_id == UINT16_C(5855)
            && instruction->name_id == CDISASM_ARM_NAME_SRSHR)
        || (scalar_operation == UINT32_C(0x7f402400)
            && instruction->form_id == UINT16_C(5865)
            && instruction->name_id == CDISASM_ARM_NAME_URSHR)
        || (scalar_operation == UINT32_C(0x5f403400)
            && instruction->form_id == UINT16_C(5856)
            && instruction->name_id == CDISASM_ARM_NAME_SRSRA)
        || (scalar_operation == UINT32_C(0x7f403400)
            && instruction->form_id == UINT16_C(5866)
            && instruction->name_id == CDISASM_ARM_NAME_URSRA)
        || (scalar_operation == UINT32_C(0x5f405400)
            && instruction->form_id == UINT16_C(5857)
            && instruction->name_id == CDISASM_ARM_NAME_SHL)
        || (scalar_operation == UINT32_C(0x7f404400)
            && instruction->form_id == UINT16_C(5867)
            && instruction->name_id == CDISASM_ARM_NAME_SRI)
        || (scalar_operation == UINT32_C(0x7f405400)
            && instruction->form_id == UINT16_C(5868)
            && instruction->name_id == CDISASM_ARM_NAME_SLI);
    int vector = (vector_operation == UINT32_C(0x0f000400)
            && instruction->form_id == UINT16_C(6215)
            && instruction->name_id == CDISASM_ARM_NAME_SSHR)
        || (vector_operation == UINT32_C(0x2f000400)
            && instruction->form_id == UINT16_C(6228)
            && instruction->name_id == CDISASM_ARM_NAME_USHR)
        || (vector_operation == UINT32_C(0x0f001400)
            && instruction->form_id == UINT16_C(6216)
            && instruction->name_id == CDISASM_ARM_NAME_SSRA)
        || (vector_operation == UINT32_C(0x2f001400)
            && instruction->form_id == UINT16_C(6229)
            && instruction->name_id == CDISASM_ARM_NAME_USRA)
        || (vector_operation == UINT32_C(0x0f002400)
            && instruction->form_id == UINT16_C(6217)
            && instruction->name_id == CDISASM_ARM_NAME_SRSHR)
        || (vector_operation == UINT32_C(0x2f002400)
            && instruction->form_id == UINT16_C(6230)
            && instruction->name_id == CDISASM_ARM_NAME_URSHR)
        || (vector_operation == UINT32_C(0x0f003400)
            && instruction->form_id == UINT16_C(6218)
            && instruction->name_id == CDISASM_ARM_NAME_SRSRA)
        || (vector_operation == UINT32_C(0x2f003400)
            && instruction->form_id == UINT16_C(6231)
            && instruction->name_id == CDISASM_ARM_NAME_URSRA)
        || (vector_operation == UINT32_C(0x0f005400)
            && instruction->form_id == UINT16_C(6219)
            && instruction->name_id == CDISASM_ARM_NAME_SHL)
        || (vector_operation == UINT32_C(0x2f004400)
            && instruction->form_id == UINT16_C(6232)
            && instruction->name_id == CDISASM_ARM_NAME_SRI)
        || (vector_operation == UINT32_C(0x2f005400)
            && instruction->form_id == UINT16_C(6233)
            && instruction->name_id == CDISASM_ARM_NAME_SLI);
    unsigned immh = (word >> 19) & 15u;
    unsigned q = (word >> 30) & 1u;
    unsigned element_bits;
    unsigned immediate;
    int left_shift = scalar_operation == UINT32_C(0x5f405400)
        || scalar_operation == UINT32_C(0x7f405400)
        || vector_operation == UINT32_C(0x0f005400)
        || vector_operation == UINT32_C(0x2f005400);

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || operand_index != 2u || (!scalar && !vector)
        || (vector && (immh == 0u
            || (q == 0u && (immh & 8u) != 0u)))) {
        return 0;
    }
    element_bits = scalar || (immh & 8u) != 0u ? 64u
        : (immh & 4u) != 0u ? 32u
        : (immh & 2u) != 0u ? 16u : 8u;
    immediate = left_shift
        ? ((immh << 3) | ((word >> 16) & 7u)) - element_bits
        : 2u * element_bits - ((immh << 3) | ((word >> 16) & 7u));
    return (left_shift ? immediate < element_bits
                       : immediate >= 1u && immediate <= element_bits)
        && operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->imm == (uint64_t)immediate
        && operand->size == 1u
        && operand->access == CDISASM_OPERAND_ACCESS_READ
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u;
}

static int fixed_advsimd_ext_immediate(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand, uint8_t operand_index)
{
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    unsigned imm4 = (word >> 11) & 15u;

    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xbfe08400)) == UINT32_C(0x2e000000)
        && (q != 0u || imm4 < 8u)
        && instruction->form_id == UINT16_C(5910)
        && instruction->name_id == CDISASM_ARM_NAME_EXT
        && operand_index == 3u
        && operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->imm == imm4
        && operand->size == 1u
        && operand->access == CDISASM_OPERAND_ACCESS_READ
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u;
}

static int fixed_advsimd_shift_narrow_widen_immediate(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand, uint8_t operand_index)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf80fc00);
    unsigned immh = (word >> 19) & 15u;
    unsigned narrow_bits;
    unsigned encoded;
    unsigned immediate;
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    int widening;

    switch (operation) {
        case UINT32_C(0x0f008400):
            form_id = UINT16_C(6221);
            name_id = CDISASM_ARM_NAME_SHRN;
            widening = 0;
            break;
        case UINT32_C(0x0f008c00):
            form_id = UINT16_C(6222);
            name_id = CDISASM_ARM_NAME_RSHRN;
            widening = 0;
            break;
        case UINT32_C(0x0f00a400):
            form_id = UINT16_C(6225);
            name_id = CDISASM_ARM_NAME_SSHLL;
            widening = 1;
            break;
        case UINT32_C(0x2f00a400):
            form_id = UINT16_C(6240);
            name_id = CDISASM_ARM_NAME_USHLL;
            widening = 1;
            break;
        default:
            return 0;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || instruction->form_id != form_id
        || instruction->name_id != name_id
        || operand_index != 2u || immh < 1u || immh > 7u) {
        return 0;
    }
    narrow_bits = (immh & 4u) != 0u ? 32u
        : (immh & 2u) != 0u ? 16u : 8u;
    encoded = (immh << 3) | ((word >> 16) & 7u);
    immediate = widening ? encoded - narrow_bits
                         : 2u * narrow_bits - encoded;
    return (!widening || immediate != 0u)
        && operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->imm == (uint64_t)immediate
        && operand->size == 1u
        && operand->access == CDISASM_OPERAND_ACCESS_READ
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u;
}

static int fixed_advsimd_modified_immediate(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand, uint8_t operand_index)
{
    uint32_t word = instruction->raw_instruction;
    unsigned cmode = (word >> 12) & 15u;
    unsigned encoded = (((word >> 16) & 7u) << 5)
        | ((word >> 5) & 31u);
    cdisasm_arm_form_id form_id = CDISASM_ARM_FORM_NONE;
    cdisasm_arm_name_id name_id = CDISASM_ARM_NAME_NONE;
    cdisasm_arm_shift_type shift_type = CDISASM_ARM_SHIFT_NONE;
    uint8_t shift_amount = 0u;
    uint64_t immediate = encoded;

    if ((word & UINT32_C(0xbff89c00)) == UINT32_C(0x0f001400)
        || (word & UINT32_C(0xbff89c00)) == UINT32_C(0x2f001400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6200) : UINT16_C(6208);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_ORR : CDISASM_ARM_NAME_BIC;
        shift_amount = (uint8_t)(4u * (cmode & ~1u));
        shift_type = shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        immediate <<= shift_amount;
    } else if ((word & UINT32_C(0xbff8dc00))
            == UINT32_C(0x0f009400)
        || (word & UINT32_C(0xbff8dc00)) == UINT32_C(0x2f009400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6202) : UINT16_C(6210);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_ORR : CDISASM_ARM_NAME_BIC;
        shift_amount = (cmode & 2u) != 0u ? 8u : 0u;
        shift_type = shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        immediate <<= shift_amount;
    } else if ((word & UINT32_C(0xbff89c00)) == UINT32_C(0x0f000400)
        || (word & UINT32_C(0xbff89c00)) == UINT32_C(0x2f000400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6199) : UINT16_C(6207);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_MOVI : CDISASM_ARM_NAME_MVNI;
        shift_amount = (uint8_t)(4u * cmode);
        shift_type = shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        immediate <<= shift_amount;
    } else if ((word & UINT32_C(0xbff8dc00))
            == UINT32_C(0x0f008400)
        || (word & UINT32_C(0xbff8dc00)) == UINT32_C(0x2f008400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6201) : UINT16_C(6209);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_MOVI : CDISASM_ARM_NAME_MVNI;
        shift_amount = (cmode & 2u) != 0u ? 8u : 0u;
        shift_type = shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        immediate <<= shift_amount;
    } else if ((word & UINT32_C(0xbff8ec00))
            == UINT32_C(0x0f00c400)
        || (word & UINT32_C(0xbff8ec00)) == UINT32_C(0x2f00c400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6203) : UINT16_C(6211);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_MOVI : CDISASM_ARM_NAME_MVNI;
        shift_type = CDISASM_ARM_SHIFT_MSL;
        shift_amount = (cmode & 1u) != 0u ? 16u : 8u;
        immediate = (immediate << shift_amount)
            | ((UINT64_C(1) << shift_amount) - UINT64_C(1));
    } else if ((word & UINT32_C(0xbff8fc00))
            == UINT32_C(0x0f00e400)) {
        form_id = UINT16_C(6204);
        name_id = CDISASM_ARM_NAME_MOVI;
    } else if ((word & UINT32_C(0xfff8fc00))
            == UINT32_C(0x2f00e400)
        || (word & UINT32_C(0xfff8fc00)) == UINT32_C(0x6f00e400)) {
        form_id = (word & UINT32_C(0x40000000)) == 0u
            ? UINT16_C(6212) : UINT16_C(6213);
        name_id = CDISASM_ARM_NAME_MOVI;
        immediate = UINT64_C(0);
        for (unsigned bit = 0u; bit < 8u; ++bit) {
            if ((encoded & (1u << bit)) != 0u) {
                immediate |= UINT64_C(0xff) << (8u * bit);
            }
        }
    }
    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && operand_index == 1u && form_id != CDISASM_ARM_FORM_NONE
        && instruction->form_id == form_id
        && instruction->name_id == name_id
        && operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->imm == immediate
        && operand->size == 1u
        && operand->access == CDISASM_OPERAND_ACCESS_READ
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == shift_type
        && operand->shift_amount == shift_amount
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u;
}

static void check_success(const cdisasm_arm_instruction *instruction,
                          cdisasm_arm_mode mode, const uint8_t *code,
                          size_t code_size, uint64_t address,
                          const cdisasm_arm_decode_flags *decode_flags)
{
    uint8_t index;
    int relative_target_found = 0;
    unsigned atomic_memory_count = 0;
    cdisasm_operand_access atomic_memory_access =
        CDISASM_OPERAND_ACCESS_NONE;
    const int generated_unscaled_atomic =
        (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u
        && ((instruction->name_id >= CDISASM_ARM_NAME_LDAPUR
                && instruction->name_id <= CDISASM_ARM_NAME_LDAPURSW)
            || (instruction->name_id >= CDISASM_ARM_NAME_STLUR
                && instruction->name_id <= CDISASM_ARM_NAME_STLURH));
    const int t32_exclusive_offset = instruction->isa_id
            == CDISASM_ARM_ISA_T32
        && (instruction->form_id == UINT16_C(1726)
            || instruction->form_id == UINT16_C(1727));
    const uint32_t known_groups =
        CDISASM_GROUP_JUMP | CDISASM_GROUP_CALL | CDISASM_GROUP_RETURN
        | CDISASM_GROUP_INTERRUPT | CDISASM_GROUP_INTERRUPT_RETURN
        | CDISASM_GROUP_PRIVILEGED | CDISASM_GROUP_RELATIVE_BRANCH
        | CDISASM_GROUP_CONDITIONAL;
    const uint32_t known_instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS
        | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
        | CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
        | CDISASM_ARM_INSTRUCTION_FLAG_LINK
        | CDISASM_ARM_INSTRUCTION_FLAG_BYTE
        | CDISASM_ARM_INSTRUCTION_FLAG_USER_REGISTERS
        | CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED
        | CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
        | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE
        | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
        | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT
        | CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_AMX
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_MUL53
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_SYSTEM
        | CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
        | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
        | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE
        | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE
        | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
        | CDISASM_ARM_INSTRUCTION_FLAG_SME
        | CDISASM_ARM_INSTRUCTION_FLAG_STREAMING
        | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
        | CDISASM_ARM_INSTRUCTION_FLAG_MEMORY_TAGGING
        | CDISASM_ARM_INSTRUCTION_FLAG_POINTER_AUTH
        | CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC_PAIR
        | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK;

    invariant(instruction->opcode_size != 0u);
    invariant(instruction->opcode_size <= CDISASM_ARM_MAX_INSTRUCTION_SIZE);
    invariant(code_size >= instruction->opcode_size);
    invariant(instruction->address == address);
    if ((decode_flag_word0(decode_flags)
            & CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN) != 0u) {
        uint32_t expected_raw;

        if (instruction->opcode_size == 2u) {
            expected_raw = (uint32_t)read_u16_be(code);
        } else if (mode == CDISASM_ARM_MODE_T32) {
            expected_raw = (uint32_t)read_u16_be(code)
                | ((uint32_t)read_u16_be(code + 2) << 16);
        } else {
            expected_raw = read_u32_be(code);
        }
        invariant(instruction->raw_instruction == expected_raw);
    } else {
        invariant(instruction->raw_instruction
            == (instruction->opcode_size == 2u
                    ? (uint32_t)read_u16_le(code)
                    : read_u32_le(code)));
    }
    invariant(instruction->last_error_id == CDISASM_STATUS_OK);
    invariant(instruction->name_id >= CDISASM_ARM_NAME_FIRST);
    invariant(instruction->name_id <= CDISASM_ARM_NAME_LAST);
    invariant(instruction->operand_count <= CDISASM_ARM_MAX_OPERANDS);
    invariant(instruction->condition <= CDISASM_ARM_CONDITION_NV);
    invariant((instruction->opcode_groups & ~known_groups) == 0u);
    invariant((instruction->instruction_flags & ~known_instruction_flags)
              == 0u);
    invariant((instruction->instruction_flags
                  & CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE) == 0u
              || (instruction->instruction_flags
                  & CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL) != 0u);
    invariant((instruction->instruction_flags
                  & (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                      | CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX))
              != (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                  | CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX));
    invariant((instruction->instruction_flags
                  & (CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
                      | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT))
              != (CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
                  | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT));
    invariant((instruction->instruction_flags
                  & CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED) == 0u
              || (instruction->instruction_flags
                  & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u);
    invariant((instruction->instruction_flags
                  & (CDISASM_ARM_INSTRUCTION_FLAG_STREAMING
                      | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX)) == 0u
              || (instruction->instruction_flags
                  & CDISASM_ARM_INSTRUCTION_FLAG_SME) != 0u);
    invariant((instruction->instruction_flags
                  & CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC_PAIR) == 0u
              || (instruction->instruction_flags
                  & CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC) != 0u);
    invariant((mode == CDISASM_ARM_MODE_A32
                  && instruction->isa_id == CDISASM_ARM_ISA_A32)
              || (mode == CDISASM_ARM_MODE_T32
                  && instruction->isa_id == CDISASM_ARM_ISA_T32)
              || (mode == CDISASM_ARM_MODE_A64
                  && instruction->isa_id == CDISASM_ARM_ISA_A64));
    if (instruction->condition != CDISASM_ARM_CONDITION_AL) {
        invariant((instruction->opcode_groups & CDISASM_GROUP_CONDITIONAL)
                  != 0u);
    }

    for (index = 0; index < instruction->operand_count; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        const int fixed_pmull_q_destination =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->name_id == CDISASM_ARM_NAME_PMULL
            && instruction->form_id == UINT16_C(6103)
            && index == 0u && operand->extend_type == 16u;
        const int fixed_sha_special_register =
            advsimd_sha_special_register(instruction, index);
        const int fixed_compare_zero_immediate =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && (instruction->form_id == UINT16_C(5777)
                || instruction->form_id == UINT16_C(5794)
                || instruction->form_id == UINT16_C(6013)
                || instruction->form_id == UINT16_C(6045))
            && (instruction->name_id == CDISASM_ARM_NAME_CMLT
                || instruction->name_id == CDISASM_ARM_NAME_CMLE)
            && index == 2u
            && operand->type == CDISASM_OPERAND_IMMEDIATE;
        const int fixed_shll_immediate =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->form_id == UINT16_C(6048)
            && instruction->name_id == CDISASM_ARM_NAME_SHLL
            && index == 2u
            && operand->type == CDISASM_OPERAND_IMMEDIATE
            && (operand->imm == UINT64_C(8)
                || operand->imm == UINT64_C(16)
                || operand->imm == UINT64_C(32))
            && operand->size == 1u
            && operand->access == CDISASM_OPERAND_ACCESS_READ
            && operand->reg == CDISASM_ARM_REG_NONE
            && operand->base_reg == CDISASM_ARM_REG_NONE
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && operand->register_list == 0u
            && operand->address == 0u
            && operand->flags == CDISASM_OPERAND_FLAG_NONE
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->extend_type == CDISASM_ARM_EXTEND_NONE
            && operand->scale == 0u;
        const int fixed_shift_right_immediate =
            fixed_advsimd_shift_right_immediate(
                instruction, operand, index);
        const int fixed_ext_immediate =
            fixed_advsimd_ext_immediate(instruction, operand, index);
        const int fixed_shift_narrow_widen_immediate =
            fixed_advsimd_shift_narrow_widen_immediate(
                instruction, operand, index);
        const int fixed_modified_immediate =
            fixed_advsimd_modified_immediate(
                instruction, operand, index);
        const int fixed_xar_immediate =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->form_id == UINT16_C(6301)
            && instruction->name_id == CDISASM_ARM_NAME_XAR
            && index == 3u
            && operand->type == CDISASM_OPERAND_IMMEDIATE
            && operand->imm <= UINT64_C(63)
            && operand->size == 1u
            && operand->access == CDISASM_OPERAND_ACCESS_READ
            && operand->reg == CDISASM_ARM_REG_NONE
            && operand->base_reg == CDISASM_ARM_REG_NONE
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && operand->register_list == 0u
            && operand->address == 0u
            && operand->flags == CDISASM_OPERAND_FLAG_NONE
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->extend_type == CDISASM_ARM_EXTEND_NONE
            && operand->scale == 0u;

        invariant(operand->type >= CDISASM_OPERAND_REGISTER);
        invariant(operand->type <= CDISASM_ARM_OPERAND_SYSTEM_OPERATION);
        invariant(operand->access >= CDISASM_OPERAND_ACCESS_READ);
        invariant(operand->access <= CDISASM_OPERAND_ACCESS_READ_WRITE);
        invariant(operand->reg < CDISASM_ARM_REG_COUNT);
        invariant(operand->base_reg < CDISASM_ARM_REG_COUNT);
        invariant(operand->index_reg < CDISASM_ARM_REG_COUNT);
        invariant(operand->shift_type <= CDISASM_ARM_SHIFT_MSL);
        invariant(operand->extend_type <= CDISASM_ARM_EXTEND_SXTX
            || ((operand->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER
                    || operand->type == CDISASM_ARM_OPERAND_PREDICATE
                    || operand->type
                        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
                    || operand->type == CDISASM_ARM_OPERAND_TILE)
                && operand->extend_type == 16u)
            || fixed_pmull_q_destination
            || fixed_sha_special_register);
        if ((instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) != 0u) {
            if (fixed_compare_zero_immediate) {
                invariant(operand->imm == 0u && operand->size == 1u);
            } else if (!fixed_sha_special_register
                && !fixed_shll_immediate
                && !fixed_ext_immediate
                && !fixed_shift_right_immediate
                && !fixed_shift_narrow_widen_immediate
                && !fixed_modified_immediate
                && !fixed_xar_immediate) {
                uint8_t element_size =
                    CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand);
                uint8_t element_count =
                    CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand);

                invariant(operand->type == CDISASM_OPERAND_REGISTER);
                invariant(element_size == 1u || element_size == 2u
                    || element_size == 4u || element_size == 8u
                    || fixed_pmull_q_destination);
                invariant(element_count != 0u);
                invariant((uint32_t)element_size * element_count
                    == operand->size);
            }
        }
        if (operand->type == CDISASM_OPERAND_REGISTER) {
            invariant(operand->reg != CDISASM_ARM_REG_NONE);
            invariant(operand->size != 0u && operand->size <= 64u);
        } else if (operand->type == CDISASM_OPERAND_MEMORY) {
            invariant(operand->base_reg != CDISASM_ARM_REG_NONE);
            invariant(operand->size == 0u
                || operand->size == 1u || operand->size == 2u
                || operand->size == 4u || operand->size == 8u
                || operand->size == 16u || operand->size == 64u);
            if ((operand->flags
                    & CDISASM_ARM_OPERAND_FLAG_VL_SCALED) != 0u) {
                invariant(instruction->isa_id == CDISASM_ARM_ISA_A64);
                invariant(instruction->form_id == UINT16_C(4381)
                    || instruction->form_id == UINT16_C(4382));
                invariant(operand->size == 0u);
                invariant(operand->imm >= UINT64_C(1)
                    && operand->imm <= UINT64_C(15));
                invariant(operand->flags
                    == (CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                        | CDISASM_ARM_OPERAND_FLAG_VL_SCALED));
                invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
            }
            if ((instruction->instruction_flags
                    & CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC) != 0u) {
                ++atomic_memory_count;
                atomic_memory_access = operand->access;
                invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
                if (generated_unscaled_atomic) {
                    const uint8_t displacement_flags =
                        CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                        | CDISASM_OPERAND_FLAG_SIGNED;

                    invariant((operand->flags
                        & (uint8_t)~displacement_flags) == 0u);
                    invariant(((operand->flags
                        & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) != 0u)
                        == (operand->imm != 0u));
                    invariant((operand->flags
                            & CDISASM_OPERAND_FLAG_SIGNED) == 0u
                        || (operand->flags
                            & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) != 0u);
                } else if (t32_exclusive_offset) {
                    invariant(operand->imm <= UINT64_C(1020));
                    invariant((operand->imm & UINT64_C(3)) == 0u);
                    invariant(operand->flags == (operand->imm != 0u
                        ? CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                        : CDISASM_OPERAND_FLAG_NONE));
                } else {
                    invariant(operand->imm == 0u);
                    invariant(operand->flags
                        == CDISASM_OPERAND_FLAG_NONE);
                }
            }
        } else if (operand->type == CDISASM_ARM_OPERAND_REGISTER_LIST) {
            invariant(operand->size == 4u);
            invariant(operand->register_list != 0u
                || (instruction->instruction_flags
                    & (CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
                        | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE))
                    == (CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
                        | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE));
        } else if (operand->type == CDISASM_ARM_OPERAND_REGISTER_PAIR) {
            invariant(instruction->isa_id == CDISASM_ARM_ISA_A64);
            invariant(register_pair_is_architecturally_consecutive(
                operand->reg, operand->index_reg));
            invariant(operand->size
                == (operand->reg <= CDISASM_ARM_REG_W30 ? 4u : 8u));
            invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
            invariant(operand->register_list == 0u);
        } else if (operand->type
                       == CDISASM_ARM_OPERAND_SCALABLE_REGISTER) {
            uint8_t element_size =
                CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand);

            invariant(operand->reg >= CDISASM_ARM_REG_Z0
                && operand->reg <= CDISASM_ARM_REG_Z31);
            invariant(operand->size == 0u);
            invariant(element_size == 1u || element_size == 2u
                || element_size == 4u || element_size == 8u
                || element_size == 16u);
        } else if (operand->type == CDISASM_ARM_OPERAND_PREDICATE) {
            const int is_counter_typed =
                instruction->isa_id == CDISASM_ARM_ISA_A64
                && index == 0u
                && ((instruction->form_id >= UINT16_C(2566)
                        && instruction->form_id <= UINT16_C(2573))
                    || instruction->form_id == UINT16_C(2584))
                && operand->reg >= CDISASM_ARM_REG_PN8
                && operand->reg <= CDISASM_ARM_REG_PN15
                && operand->flags
                    == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED
                && (operand->extend_type == 1u
                    || operand->extend_type == 2u
                    || operand->extend_type == 4u
                    || operand->extend_type == 8u)
                && operand->imm == 0u
                && operand->access == CDISASM_OPERAND_ACCESS_WRITE;
            const int is_pext_source =
                instruction->isa_id == CDISASM_ARM_ISA_A64
                && index == 1u
                && (instruction->form_id == UINT16_C(2582)
                    || instruction->form_id == UINT16_C(2583))
                && instruction->name_id == CDISASM_ARM_NAME_PEXT
                && operand->reg >= CDISASM_ARM_REG_PN8
                && operand->reg <= CDISASM_ARM_REG_PN15
                && operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE
                && operand->extend_type == 0u
                && operand->imm <=
                    (instruction->form_id == UINT16_C(2582) ? 3u : 1u)
                && operand->access == CDISASM_OPERAND_ACCESS_READ;

            invariant((operand->reg >= CDISASM_ARM_REG_P0
                    && operand->reg <= CDISASM_ARM_REG_P15)
                || is_counter_typed
                || is_pext_source
                || (instruction->isa_id == CDISASM_ARM_ISA_A64
                    && instruction->form_id == UINT16_C(2600)
                    && instruction->name_id == CDISASM_ARM_NAME_CNTP
                    && operand->reg >= CDISASM_ARM_REG_PN0
                    && operand->reg <= CDISASM_ARM_REG_PN15
                    && operand->flags
                        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED));
            invariant(operand->size == 0u);
        } else if (operand->type
                       == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST) {
            invariant(operand->reg >= CDISASM_ARM_REG_Z0
                && operand->reg <= CDISASM_ARM_REG_Z31);
            invariant(CDISASM_ARM_SCALABLE_LIST_COUNT(operand) >= 1u);
            invariant(CDISASM_ARM_SCALABLE_LIST_COUNT(operand) <= 4u);
            invariant(CDISASM_ARM_SCALABLE_LIST_STRIDE(operand) >= 1u);
            invariant(operand->size == 0u);
        } else if (operand->type == CDISASM_ARM_OPERAND_TILE) {
            invariant(operand->reg >= CDISASM_ARM_REG_ZA
                && operand->reg <= CDISASM_ARM_REG_ZT0);
            invariant(operand->size == 0u);
        } else if (operand->type
                       == CDISASM_ARM_OPERAND_REGISTER_PAIR_BASE) {
            cdisasm_arm_reg_id expected =
                operand->reg == CDISASM_ARM_REG_X30
                    ? CDISASM_ARM_REG_XZR
                    : (cdisasm_arm_reg_id)(operand->reg + 1u);

            invariant(operand->reg >= CDISASM_ARM_REG_X0
                && operand->reg <= CDISASM_ARM_REG_X30);
            invariant(operand->index_reg == expected);
            invariant(operand->size == 16u);
        } else if (operand->type
                       == CDISASM_ARM_OPERAND_PREDICATE_PAIR) {
            if (operand->flags
                == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED) {
                const int is_while_pair =
                    instruction->form_id >= UINT16_C(2574)
                    && instruction->form_id <= UINT16_C(2581);
                const int is_pext_pair =
                    instruction->form_id == UINT16_C(2583)
                    && instruction->name_id == CDISASM_ARM_NAME_PEXT;

                invariant(is_while_pair || is_pext_pair);
                invariant(operand->reg >= CDISASM_ARM_REG_P0
                    && operand->reg <= CDISASM_ARM_REG_P15);
                if (is_while_pair) {
                    invariant(operand->reg <= CDISASM_ARM_REG_P14);
                    invariant(((unsigned)(operand->reg
                        - CDISASM_ARM_REG_P0) & 1u) == 0u);
                    invariant(operand->index_reg
                        == (cdisasm_arm_reg_id)(operand->reg + 1u));
                } else {
                    invariant(operand->index_reg
                        == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0
                            + (((unsigned)(operand->reg
                                - CDISASM_ARM_REG_P0) + 1u) & 15u)));
                }
                invariant(operand->access
                    == CDISASM_OPERAND_ACCESS_WRITE);
            } else {
                invariant(operand->flags
                    == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
                invariant(operand->reg >= CDISASM_ARM_REG_P0
                    && operand->reg <= CDISASM_ARM_REG_P7);
                invariant(operand->index_reg >= CDISASM_ARM_REG_P0
                    && operand->index_reg <= CDISASM_ARM_REG_P7);
                invariant(operand->access
                    == CDISASM_OPERAND_ACCESS_READ);
            }
            invariant(operand->size == 0u);
        } else if (operand->type
                       == CDISASM_ARM_OPERAND_REGISTER_BLOCK) {
            invariant(operand->reg >= CDISASM_ARM_REG_X0
                && operand->reg <= CDISASM_ARM_REG_X22);
            invariant(((unsigned)(operand->reg - CDISASM_ARM_REG_X0)
                & 1u) == 0u);
            invariant(operand->register_list == 8u);
            invariant(operand->size == 64u);
        } else if (operand->type == CDISASM_ARM_OPERAND_SYSTEM_REGISTER
                   || operand->type
                       == CDISASM_ARM_OPERAND_SYSTEM_OPERATION) {
            invariant(operand->size == 0u);
            invariant(operand->reg == CDISASM_ARM_REG_NONE);
            invariant(operand->base_reg == CDISASM_ARM_REG_NONE);
            invariant(operand->index_reg == CDISASM_ARM_REG_NONE);
        } else {
            invariant(operand->type == CDISASM_OPERAND_IMMEDIATE);
            invariant(operand->size != 0u && operand->size <= 8u);
        }
        if (operand->type == CDISASM_OPERAND_IMMEDIATE
            && (operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0u
            && operand->imm == instruction->branch_target) {
            relative_target_found = 1;
        }
    }
    for (; index < CDISASM_ARM_MAX_OPERANDS; ++index) {
        invariant(operand_is_zeroed(&instruction->operand[index]));
    }
    if ((instruction->opcode_groups & CDISASM_GROUP_RELATIVE_BRANCH) != 0u) {
        invariant(relative_target_found);
    }
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC) != 0u) {
        invariant(instruction->isa_id == CDISASM_ARM_ISA_A64
            || instruction->isa_id == CDISASM_ARM_ISA_T32);
        invariant(instruction->opcode_groups == CDISASM_GROUP_NONE);
        invariant(atomic_memory_count == 1u);
        if ((instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE) != 0u) {
            invariant(atomic_memory_access == CDISASM_OPERAND_ACCESS_READ
                || atomic_memory_access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
        }
        if ((instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_RELEASE) != 0u) {
            invariant(atomic_memory_access == CDISASM_OPERAND_ACCESS_WRITE
                || atomic_memory_access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
        }
    } else {
        invariant((instruction->instruction_flags
                & (CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                    | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE
                    | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE)) == 0u);
    }
    if (instruction->name_id >= CDISASM_ARM_NAME_LDADDB
        && instruction->name_id <= CDISASM_ARM_NAME_SWPAL) {
        unsigned ordering =
            ((unsigned)(instruction->name_id - CDISASM_ARM_NAME_LDADDB)
                % 12u) / 3u;
        int result_is_zero_register = instruction->operand_count == 3u
            && (instruction->operand[1].reg == CDISASM_ARM_REG_WZR
                || instruction->operand[1].reg == CDISASM_ARM_REG_XZR);
        uint32_t expected_ordering_flags =
            ((ordering & 1u) != 0u && !result_is_zero_register
                ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE : 0u)
            | ((ordering & 2u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_RELEASE : 0u);

        invariant((instruction->instruction_flags
                      & (CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                          | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE))
            == expected_ordering_flags);
    }
    check_a64_udf_class(instruction);
    check_a64_wfxt_class(instruction);
    check_a64_pauth_branch_class(instruction);
    check_a64_flagm_class(instruction);
    check_a64_sve_ffr_class(instruction);
    check_sve_element_count_class(instruction);
    check_sve_saturating_count_class(instruction);
    check_sve_predicate_count_class(instruction);
    check_sve_while_counter_class(instruction);
    check_sve_while_single_class(instruction);
    check_sve_while_pair_class(instruction);
    check_sve_counter_mask_class(instruction);
    check_sve_psel_class(instruction);
    check_sve_punpk_class(instruction);
    check_sve_unpack_class(instruction);
    check_sve_shift_insert_class(instruction);
    check_sve_bitperm_class(instruction);
    check_sve_unpredicated_logical_class(instruction);
    check_sve_xar_class(instruction);
    check_sve_integer_immediate_class(instruction);
    check_sve_dup_immediate_class(instruction);
    check_sve_dot_product_class(instruction);
    check_sve_usdot_class(instruction);
    check_sve_dot_indexed_class(instruction);
    check_sve_indexed_muladd_class(instruction);
    check_sve_aes_unary_class(instruction);
    check_sve_crypto_binary_class(instruction);
    check_sve_predicated_shift_sat_round_class(instruction);
    check_sve_predicated_sat_unary_class(instruction);
    check_sve_predicated_accumulate_long_class(instruction);
    check_sve_predicated_halving_class(instruction);
    check_sve_predicated_pairwise_class(instruction);
    check_sve_predicated_saturating_class(instruction);
    check_sve_clamp_class(instruction);
    check_sve_pointer_muladd_class(instruction);
    check_sve_quad_permute_class(instruction);
    check_sve_complex_muladd_class(instruction);
    check_sve_widening_muladd_class(instruction);
    check_sve_predicate_control_class(instruction);
    check_sve_predicate_break_class(instruction);
    check_sve_cterm_class(instruction);
    check_sve_whilewr_rw_class(instruction);
    check_sve_predicated_unary_class(instruction);
    check_sve_integer_compare_vectors_class(instruction);
    check_sve_integer_compare_immediate_class(instruction);
    check_sve_floating_compare_vectors_class(instruction);
    check_sve_floating_compare_zero_class(instruction);
    check_sve_predicated_fp_binary_class(instruction);
    check_sve_fp_fast_reduction_class(instruction);
    check_sve_fp_serial_reduction_class(instruction);
    check_sve_predicated_fp_unary_class(instruction);
    check_sve_fp_estimate_class(instruction);
    check_sve_int_to_fp_class(instruction);
    check_sve_fcvt_class(instruction);
    check_multi_bf16_class(instruction);
    check_sme2_multi_wide_integer_class(instruction);
    check_sme2_multi_wide_fp8_class(instruction);
    check_sve2p1_multi_extract_narrow_class(instruction);
    check_sme2_multi_frint_class(instruction);
    check_sme_f16f16_multi_wide_class(instruction);
    check_sme2_multi4_conversion_class(instruction);
    check_sme2_multi4_followon_class(instruction);
    check_sme_fmul_class(instruction);
    check_sme2_multi_mova_class(instruction);
    check_sme2p1_movaz_class(instruction);
    check_sme_za_contiguous_class(instruction);
    check_sme_za_load_store_class(instruction);
    check_sme2_zt0_load_store_class(instruction);
    check_sve_predicated_bf16_class(instruction);
    check_sve_fp_to_int_class(instruction);
    check_advsimd_fp_estimate_class(instruction);
    check_sve_predicated_immediate_shift_class(instruction);
    check_sve_predicated_vector_shift_class(instruction);
    check_sve_f64mm_permute_q_class(instruction);
    check_sve_length_arithmetic_class(instruction);
    check_advsimd_reverse_class(instruction);
    check_advsimd_bitcount_class(instruction);
    check_advsimd_ext_class(instruction);
    check_crc32_class(instruction);
    check_architectural_hint_class(instruction);
    check_advsimd_sha_class(instruction);
    check_advsimd_fixed_crypto_class(instruction);
    check_advsimd_bitwise_select_class(instruction);
    check_advsimd_widening_add_sub_class(instruction);
    check_advsimd_absolute_difference_long_class(instruction);
    check_advsimd_absolute_difference_class(instruction);
    check_advsimd_absolute_difference_accumulate_class(instruction);
    check_advsimd_multiply_accumulate_class(instruction);
    check_advsimd_multiply_accumulate_element_class(instruction);
    check_advsimd_widening_multiply_element_class(instruction);
    check_advsimd_widening_multiply_class(instruction);
    check_advsimd_saturating_widening_multiply_class(instruction);
    check_advsimd_saturating_mulh_class(instruction);
    check_advsimd_pmull_class(instruction);
    check_advsimd_pmul_class(instruction);
    check_advsimd_compare_class(instruction);
    check_advsimd_compare_zero_class(instruction);
    check_advsimd_cmtst_class(instruction);
    check_advsimd_variable_shift_class(instruction);
    check_advsimd_modified_immediate_class(instruction);
    check_advsimd_shift_right_immediate_class(instruction);
    check_advsimd_shift_narrow_widen_class(instruction);
    check_advsimd_minmax_class(instruction);
    check_advsimd_pairwise_minmax_class(instruction);
    check_advsimd_addp_class(instruction);
    check_advsimd_addv_class(instruction);
    check_advsimd_addlv_class(instruction);
    check_advsimd_pairwise_add_long_class(instruction);
    check_advsimd_narrow_widen_move_class(instruction);
    check_advsimd_high_narrow_class(instruction);
    check_sve_integer_reduction_class(instruction);
}

static void check_one(const uint8_t *code, size_t code_size,
                      cdisasm_arm_cpu_id cpu_id, cdisasm_arm_mode mode,
                      uint64_t address,
                      const cdisasm_arm_decode_flags *flags)
{
    cdisasm_arm_instruction first;
    cdisasm_arm_instruction second;
    uint32_t first_size;
    uint32_t second_size;

    memset(&first, 0xa5, sizeof(first));
    first_size = cdisasm_arm_decode(cpu_id, mode, code, code_size, address,
                                     flags, &first);
    memset(&second, 0x5a, sizeof(second));
    second_size = cdisasm_arm_decode(cpu_id, mode, code, code_size, address,
                                      flags, &second);
    invariant(first_size == second_size);
    invariant(memcmp(&first, &second, sizeof(first)) == 0);

    if (first_size == 0u) {
        invariant(first.last_error_id >= CDISASM_STATUS_INVALID_ARGUMENT);
        invariant(first.last_error_id <= CDISASM_STATUS_INTERNAL_ERROR);
        invariant(result_is_error_only(&first));
#if USE_DISASM_FORMAT
        {
            char invalid_buffer[8] = "invalid";

            invariant(cdisasm_arm_format(
                          &first,
                          CDISASM_FORMAT_SYNTAX_0,
                          invalid_buffer,
                          sizeof(invalid_buffer))
                == 0u);
            invariant(invalid_buffer[0] == '\0');
        }
#endif
        return;
    }
    invariant((mode == CDISASM_ARM_MODE_T32
                  && (first_size == 2u
                      || first_size == CDISASM_ARM_MAX_INSTRUCTION_SIZE))
              || ((mode == CDISASM_ARM_MODE_A32
                      || mode == CDISASM_ARM_MODE_A64)
                  && first_size == CDISASM_ARM_MAX_INSTRUCTION_SIZE));
    check_success(&first, mode, code, code_size, address, flags);
#if USE_DISASM_FORMAT
    check_format(&first, address ^ (uint64_t)cpu_id
        ^ (uint64_t)mode ^ decode_flags_hash(flags));
#endif
}

static void check_reserved_decode_flag_bitmaps(
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    const cdisasm_arm_decode_flags *fuzz_flags)
{
    cdisasm_arm_decode_flags flags =
        CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER;
    size_t bitmap_index;

    flags.bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP] =
        fuzz_flags->bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP]
            & CDISASM_ARM_DECODE_OPTION_KNOWN_MASK_0;
    for (bitmap_index = 1u;
         bitmap_index < CDISASM_DECODE_FLAGS_BITMAP_COUNT;
         ++bitmap_index) {
        uint64_t value = fuzz_flags->bitmap[bitmap_index];

        if (value == 0u) {
            value = UINT64_C(1) << (bitmap_index * 7u);
        }
        flags.bitmap[bitmap_index] = value;
        check_one(code, code_size, CDISASM_ARM_CPU_ANY,
                  CDISASM_ARM_MODE_A32, address, &flags);
        flags.bitmap[bitmap_index] = UINT64_C(0);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const cdisasm_arm_mode modes[] = {
        CDISASM_ARM_MODE_A32,
        CDISASM_ARM_MODE_T32,
        CDISASM_ARM_MODE_A64
    };
    uint8_t hex_bytes[FUZZ_HEX_CAPACITY];
    const uint8_t *code;
    size_t code_size;
    size_t mode_index;
    size_t boundary;
    uint64_t hash;
    uint64_t address;
    cdisasm_arm_cpu_id cpu_id;
    cdisasm_arm_decode_flags fuzz_flags =
        CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_arm_decode_flags big_endian_flags =
        CDISASM_ARM_DECODE_FLAGS_INITIALIZER(
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN);
    cdisasm_arm_decode_flags invalid_flags =
        CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER;

    derive_decode_flags(data, size, &fuzz_flags);
    normalize_input(data, size, hex_bytes, &code, &code_size);
    hash = input_hash(code, code_size);
    address = hash ^ (hash << 32);

    /* Every public CPU/state pair exercises both supported and rejected pairs. */
    for (cpu_id = CDISASM_ARM_CPU_ANY;
         cpu_id <= CDISASM_ARM_CPU_LAST;
         ++cpu_id) {
        for (mode_index = 0;
             mode_index < sizeof(modes) / sizeof(modes[0]);
             ++mode_index) {
            check_one(code, code_size, cpu_id, modes[mode_index], address,
                      NULL);
            check_one(code, code_size, cpu_id, modes[mode_index], address,
                      &big_endian_flags);
        }
    }

    /* Invalid CPU, mode, and option inputs must retain the failure contract. */
    check_one(code, code_size, CDISASM_ARM_CPU_LAST + 1u,
              CDISASM_ARM_MODE_A32, address,
              NULL);
    check_one(code, code_size, UINT32_C(0), CDISASM_ARM_MODE_A32,
              address, NULL);
    check_one(code, code_size, UINT32_C(1), CDISASM_ARM_MODE_A32,
              address, NULL);
    check_one(code, code_size,
              CDISASM_CPU_GROUP_X86 | UINT32_C(0x0001),
              CDISASM_ARM_MODE_A32, address,
              NULL);
    check_one(code, code_size, CDISASM_ARM_CPU_ANY, 0u, address,
              NULL);
    invalid_flags.bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP] =
        UINT64_C(2);
    check_one(code, code_size, CDISASM_ARM_CPU_ANY,
              CDISASM_ARM_MODE_A32, address, &invalid_flags);
    invalid_flags.bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP] =
        UINT64_C(0x80000000);
    check_one(code, code_size, CDISASM_ARM_CPU_ANY,
              CDISASM_ARM_MODE_A32, address, &invalid_flags);
    invalid_flags.bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP] =
        UINT64_C(0x100000000);
    check_one(code, code_size, CDISASM_ARM_CPU_ANY,
              CDISASM_ARM_MODE_A32, address, &invalid_flags);
    invalid_flags.bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP] =
        UINT64_C(0x8000000000000000);
    check_one(code, code_size, CDISASM_ARM_CPU_ANY,
              CDISASM_ARM_MODE_A32, address, &invalid_flags);

    /* Every byte through the fixed four-byte word is a truncation boundary. */
    for (boundary = 0;
         boundary <= code_size
             && boundary <= CDISASM_ARM_MAX_INSTRUCTION_SIZE;
         ++boundary) {
        check_one(code, boundary, CDISASM_ARM_CPU_ANY,
                  CDISASM_ARM_MODE_A32, address + boundary,
                  NULL);
        check_one(code, boundary, CDISASM_ARM_CPU_ANY,
                  CDISASM_ARM_MODE_T32, address + boundary,
                  NULL);
        check_one(code, boundary, CDISASM_ARM_CPU_ANY,
                  CDISASM_ARM_MODE_A64, address + boundary,
                  NULL);
        check_one(code, boundary, CDISASM_ARM_CPU_ANY,
                  CDISASM_ARM_MODE_A32, address + boundary,
                  &big_endian_flags);
        check_one(code, boundary, CDISASM_ARM_CPU_ANY,
                  CDISASM_ARM_MODE_T32, address + boundary,
                  &big_endian_flags);
        check_one(code, boundary, CDISASM_ARM_CPU_ANY,
                  CDISASM_ARM_MODE_A64, address + boundary,
                  &big_endian_flags);
    }
    check_reserved_decode_flag_bitmaps(
        code, code_size, address, &fuzz_flags);
    return 0;
}
