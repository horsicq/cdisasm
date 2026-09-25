#include "cdisasm/cdisasm_config.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#else
#  include "cdisasm/cdisasm_x86.h"
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

_Static_assert(sizeof(cdisasm_x86_decode_option) == 8,
               "x86 fuzzer requires the public 64-bit decode-option ABI");
_Static_assert(sizeof(cdisasm_x86_decode_flags) == 64,
               "x86 fuzzer requires the public 64-byte decode-flags ABI");
_Static_assert(CDISASM_DECODE_FLAGS_BITMAP_COUNT == 8u,
               "x86 fuzzer must exercise every public bitmap word");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
               "update x86 fuzzer CPU-capability invariants for new profiles");
_Static_assert(CDISASM_X86_NAME_GF2P8AFFINEINVQB == UINT16_C(1322)
                   && CDISASM_X86_NAME_GF2P8AFFINEQB == UINT16_C(1323)
                   && CDISASM_X86_NAME_GF2P8MULB == UINT16_C(1324)
                   && CDISASM_X86_NAME_VGF2P8AFFINEINVQB == UINT16_C(1737)
                   && CDISASM_X86_NAME_VGF2P8AFFINEQB == UINT16_C(1738)
                   && CDISASM_X86_NAME_VGF2P8MULB == UINT16_C(1739)
                   && CDISASM_X86_GROUP_GFNI == UINT16_C(76)
                   && CDISASM_X86_GROUP_AVX512_GFNI_128 == UINT16_C(208)
                   && CDISASM_X86_GROUP_AVX512_GFNI_256 == UINT16_C(209)
                   && CDISASM_X86_GROUP_AVX512_GFNI_512 == UINT16_C(210)
                   && CDISASM_X86_GROUP_AVX_GFNI == UINT16_C(260)
                   && CDISASM_X86_DECODE_BIT_GFNI == UINT32_C(17)
                   && CDISASM_X86_DECODE_BIT_AVX512_GFNI_128
                       == UINT32_C(156)
                   && CDISASM_X86_DECODE_BIT_AVX512_GFNI_256
                       == UINT32_C(157)
                   && CDISASM_X86_DECODE_BIT_AVX512_GFNI_512
                       == UINT32_C(158)
                   && CDISASM_X86_DECODE_BIT_AVX_GFNI == UINT32_C(208),
               "update GFNI fuzz invariants");
_Static_assert(CDISASM_X86_GROUP_VTX == UINT16_C(321)
                   && CDISASM_X86_DECODE_BIT_VTX == UINT32_C(267),
               "update VTX exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_CLDEMOTE == UINT16_C(1263)
                   && CDISASM_X86_GROUP_CLDEMOTE == UINT16_C(264)
                   && CDISASM_X86_DECODE_BIT_CLDEMOTE == UINT32_C(211),
               "update CLDEMOTE exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_CLZERO == UINT16_C(1264)
                   && CDISASM_X86_GROUP_CLZERO == UINT16_C(266)
                   && CDISASM_X86_DECODE_BIT_CLZERO == UINT32_C(213),
               "update CLZERO exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_PCONFIG == UINT16_C(1362)
                   && CDISASM_X86_GROUP_PCONFIG == UINT16_C(289)
                   && CDISASM_X86_DECODE_BIT_PCONFIG == UINT32_C(236),
               "update PCONFIG exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_PBNDKB == UINT16_C(1358)
                   && CDISASM_X86_GROUP_PBNDKB == UINT16_C(288)
                   && CDISASM_X86_DECODE_BIT_PBNDKB == UINT32_C(235),
               "update PBNDKB exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_RDPRU == UINT16_C(1385)
                   && CDISASM_X86_GROUP_RDPRU == UINT16_C(300)
                   && CDISASM_X86_DECODE_BIT_RDPRU == UINT32_C(247),
               "update RDPRU exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_PREFETCHIT0 == UINT16_C(1368)
                   && CDISASM_X86_NAME_PREFETCHIT1 == UINT16_C(1369)
                   && CDISASM_X86_GROUP_ICACHE_PREFETCH == UINT16_C(276)
                   && CDISASM_X86_DECODE_BIT_ICACHE_PREFETCH
                       == UINT32_C(223),
               "update PREFETCHIT exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_PREFETCHRST2 == UINT16_C(1370)
                   && CDISASM_X86_GROUP_MOVRS == UINT16_C(285)
                   && CDISASM_X86_DECODE_BIT_MOVRS == UINT32_C(232),
               "update PREFETCHRST2 exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_PREFETCHWT1 == UINT16_C(1371)
                   && CDISASM_X86_GROUP_PREFETCHWT1 == UINT16_C(295)
                   && CDISASM_X86_DECODE_BIT_PREFETCHWT1
                       == UINT32_C(242),
               "update PREFETCHWT1 exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_PTWRITE == UINT16_C(1380)
                   && CDISASM_X86_GROUP_PTWRITE == UINT16_C(297)
                   && CDISASM_X86_DECODE_BIT_PTWRITE == UINT32_C(244),
               "update PTWRITE exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_MOVNTI == UINT16_C(1347)
                   && CDISASM_X86_GROUP_SSE2 == UINT16_C(20)
                   && CDISASM_X86_DECODE_BIT_SSE2 == UINT32_C(4),
               "update MOVNTI exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_MOVNTDQ == UINT16_C(1346)
                   && CDISASM_X86_NAME_MOVNTPD == UINT16_C(341)
                   && CDISASM_X86_NAME_MOVNTPS == UINT16_C(279)
                   && CDISASM_X86_NAME_MOVNTQ == UINT16_C(336)
                   && CDISASM_X86_NAME_MOVNTSD == UINT16_C(501)
                   && CDISASM_X86_NAME_MOVNTSS == UINT16_C(500)
                   && CDISASM_X86_NAME_VMOVNTPS == UINT16_C(1192)
                   && CDISASM_X86_NAME_VMOVNTPD == UINT16_C(1193)
                   && CDISASM_X86_NAME_VMOVNTDQ == UINT16_C(1194),
               "update non-temporal SIMD-store fuzz invariants");
_Static_assert(CDISASM_X86_NAME_MOVNTDQA == UINT16_C(466)
                   && CDISASM_X86_NAME_VMOVNTDQA == UINT16_C(1782)
                   && CDISASM_X86_GROUP_SSE4 == UINT16_C(310)
                   && CDISASM_X86_DECODE_BIT_SSE4_ISA_SET == UINT32_C(270),
               "update MOVNTDQA/VMOVNTDQA fuzz invariants");
_Static_assert(CDISASM_X86_NAME_LDDQU == UINT16_C(437)
                   && CDISASM_X86_NAME_VLDDQU == UINT16_C(1195)
                   && CDISASM_X86_GROUP_SSE3 == UINT16_C(24)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_SSE3 == UINT32_C(5)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update LDDQU/VLDDQU fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VMOVMSKPS == UINT16_C(1196)
                   && CDISASM_X86_NAME_VMOVMSKPD == UINT16_C(1197)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update VMOVMSKPD/VMOVMSKPS fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPMOVMSKB == UINT16_C(1873)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update classic-VEX VPMOVMSKB fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPMOVSXBD == UINT16_C(1885)
                   && CDISASM_X86_NAME_VPMOVSXBQ == UINT16_C(1886)
                   && CDISASM_X86_NAME_VPMOVSXBW == UINT16_C(1887)
                   && CDISASM_X86_NAME_VPMOVSXDQ == UINT16_C(1888)
                   && CDISASM_X86_NAME_VPMOVSXWD == UINT16_C(1889)
                   && CDISASM_X86_NAME_VPMOVSXWQ == UINT16_C(1890)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update classic-VEX VPMOVSX fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPMOVZXBD == UINT16_C(1899)
                   && CDISASM_X86_NAME_VPMOVZXBQ == UINT16_C(1900)
                   && CDISASM_X86_NAME_VPMOVZXBW == UINT16_C(1901)
                   && CDISASM_X86_NAME_VPMOVZXDQ == UINT16_C(1902)
                   && CDISASM_X86_NAME_VPMOVZXWD == UINT16_C(1903)
                   && CDISASM_X86_NAME_VPMOVZXWQ == UINT16_C(1904)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update classic-VEX VPMOVZX fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPSIGNB == UINT16_C(1912)
                   && CDISASM_X86_NAME_VPSIGND == UINT16_C(1913)
                   && CDISASM_X86_NAME_VPSIGNW == UINT16_C(1914)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update classic-VEX VPSIGN fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPSHUFD == UINT16_C(1909)
                   && CDISASM_X86_NAME_VPSHUFHW == UINT16_C(1910)
                   && CDISASM_X86_NAME_VPSHUFLW == UINT16_C(1911)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update classic-VEX VPSHUF integer fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPHADDD == UINT16_C(1852)
                   && CDISASM_X86_NAME_VPHADDSW == UINT16_C(1853)
                   && CDISASM_X86_NAME_VPHADDW == UINT16_C(1854)
                   && CDISASM_X86_NAME_VPHSUBD == UINT16_C(1856)
                   && CDISASM_X86_NAME_VPHSUBSW == UINT16_C(1857)
                   && CDISASM_X86_NAME_VPHSUBW == UINT16_C(1858)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update classic-VEX horizontal integer fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPHMINPOSUW == UINT16_C(1855)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update classic-VEX VPHMINPOSUW fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPINSRB == UINT16_C(1859)
                   && CDISASM_X86_NAME_VPINSRD == UINT16_C(1860)
                   && CDISASM_X86_NAME_VPINSRQ == UINT16_C(1861)
                   && CDISASM_X86_NAME_VPINSRW == UINT16_C(1862)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update classic-VEX VPINSR fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPEXTRB == UINT16_C(1843)
                   && CDISASM_X86_NAME_VPEXTRD == UINT16_C(1844)
                   && CDISASM_X86_NAME_VPEXTRQ == UINT16_C(1845)
                   && CDISASM_X86_NAME_VPEXTRW == UINT16_C(1846)
                   && CDISASM_X86_NAME_VPEXTRW_C5 == UINT16_C(1847)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update classic-VEX VPEXTR fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VMOVQ == UINT16_C(1783)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_GROUP_AVX512F_128N == UINT16_C(181)
                   && CDISASM_X86_DECODE_BIT_AVX512F_128N
                       == UINT32_C(129),
               "update VMOVQ fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VMOVRSB == UINT16_C(1784)
                   && CDISASM_X86_NAME_VMOVRSD == UINT16_C(1785)
                   && CDISASM_X86_NAME_VMOVRSQ == UINT16_C(1786)
                   && CDISASM_X86_NAME_VMOVRSW == UINT16_C(1787)
                   && CDISASM_X86_GROUP_AVX10_MOVRS_128 == UINT16_C(155)
                   && CDISASM_X86_GROUP_AVX10_MOVRS_256 == UINT16_C(156)
                   && CDISASM_X86_GROUP_AVX10_MOVRS_512 == UINT16_C(157)
                   && CDISASM_X86_DECODE_BIT_AVX10_MOVRS_128
                       == UINT32_C(103)
                   && CDISASM_X86_DECODE_BIT_AVX10_MOVRS_256
                       == UINT32_C(104)
                   && CDISASM_X86_DECODE_BIT_AVX10_MOVRS_512
                       == UINT32_C(105),
               "update VMOVRS fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VMOVSD == UINT16_C(1788)
                   && CDISASM_X86_NAME_VMOVSS == UINT16_C(1792)
                   && CDISASM_X86_GROUP_AVX512F_SCALAR == UINT16_C(185)
                   && CDISASM_X86_DECODE_BIT_AVX512F_SCALAR
                       == UINT32_C(133),
               "update VMOVSD/VMOVSS fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VMOVUPS == UINT16_C(1186)
                   && CDISASM_X86_NAME_VMOVUPD == UINT16_C(1187)
                   && CDISASM_X86_GROUP_AVX512F_128 == UINT16_C(180)
                   && CDISASM_X86_GROUP_AVX512F_256 == UINT16_C(182)
                   && CDISASM_X86_GROUP_AVX512F_512 == UINT16_C(183)
                   && CDISASM_X86_DECODE_BIT_AVX512F_128
                       == UINT32_C(128)
                   && CDISASM_X86_DECODE_BIT_AVX512F_256
                       == UINT32_C(130)
                   && CDISASM_X86_DECODE_BIT_AVX512F_512
                       == UINT32_C(131),
               "update VMOVUPD/VMOVUPS fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VMOVSH == UINT16_C(1789)
                   && CDISASM_X86_NAME_VMOVSHDUP == UINT16_C(1790)
                   && CDISASM_X86_NAME_VMOVSLDUP == UINT16_C(1791)
                   && CDISASM_X86_GROUP_AVX512F_128 == UINT16_C(180)
                   && CDISASM_X86_GROUP_AVX512F_256 == UINT16_C(182)
                   && CDISASM_X86_GROUP_AVX512F_512 == UINT16_C(183)
                   && CDISASM_X86_GROUP_AVX512_FP16_SCALAR
                       == UINT16_C(204)
                   && CDISASM_X86_DECODE_BIT_AVX512F_128
                       == UINT32_C(128)
                   && CDISASM_X86_DECODE_BIT_AVX512F_256
                       == UINT32_C(130)
                   && CDISASM_X86_DECODE_BIT_AVX512F_512
                       == UINT32_C(131)
                   && CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR
                       == UINT32_C(152),
               "update VMOVSH/VMOVSHDUP/VMOVSLDUP fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VMOVW == UINT16_C(1793)
                   && CDISASM_X86_GROUP_AVX512_FP16_128N
                       == UINT16_C(198)
                   && CDISASM_X86_DECODE_BIT_AVX512_FP16_128N
                       == UINT32_C(146)
                   && CDISASM_X86_GROUP_AVX512_MOVZXC_128
                       == UINT16_C(221)
                   && CDISASM_X86_DECODE_BIT_AVX512_MOVZXC_128
                       == UINT32_C(169),
               "update VMOVW fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VMPSADBW == UINT16_C(1794)
                   && CDISASM_X86_GROUP_AVX512_MEDIAX_128
                       == UINT16_C(214)
                   && CDISASM_X86_GROUP_AVX512_MEDIAX_256
                       == UINT16_C(215)
                   && CDISASM_X86_GROUP_AVX512_MEDIAX_512
                       == UINT16_C(216)
                   && CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_128
                       == UINT32_C(162)
                   && CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_256
                       == UINT32_C(163)
                   && CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_512
                       == UINT32_C(164),
               "update VMPSADBW fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VDBPSADBW == UINT16_C(1635)
                   && CDISASM_X86_GROUP_AVX512BW_128 == UINT16_C(162)
                   && CDISASM_X86_GROUP_AVX512BW_256 == UINT16_C(164)
                   && CDISASM_X86_GROUP_AVX512BW_512 == UINT16_C(165)
                   && CDISASM_X86_DECODE_BIT_AVX512BW_128
                       == UINT32_C(110)
                   && CDISASM_X86_DECODE_BIT_AVX512BW_256
                       == UINT32_C(112)
                   && CDISASM_X86_DECODE_BIT_AVX512BW_512
                       == UINT32_C(113),
               "update VDBPSADBW fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VMULBF16 == UINT16_C(940)
                   && CDISASM_X86_GROUP_AVX10_2_BF16_128
                       == UINT16_C(151)
                   && CDISASM_X86_GROUP_AVX10_2_BF16_256
                       == UINT16_C(152)
                   && CDISASM_X86_GROUP_AVX10_2_BF16_512
                       == UINT16_C(153)
                   && CDISASM_X86_DECODE_BIT_AVX10_2_BF16_128
                       == UINT32_C(99)
                   && CDISASM_X86_DECODE_BIT_AVX10_2_BF16_256
                       == UINT32_C(100)
                   && CDISASM_X86_DECODE_BIT_AVX10_2_BF16_512
                       == UINT32_C(101),
               "update VMULBF16 fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VMULPH == UINT16_C(1795)
                   && CDISASM_X86_NAME_VMULSH == UINT16_C(1796)
                   && CDISASM_X86_GROUP_AVX512_FP16_128
                       == UINT16_C(197)
                   && CDISASM_X86_GROUP_AVX512_FP16_256
                       == UINT16_C(199)
                   && CDISASM_X86_GROUP_AVX512_FP16_512
                       == UINT16_C(200)
                   && CDISASM_X86_GROUP_AVX512_FP16_SCALAR
                       == UINT16_C(204)
                   && CDISASM_X86_DECODE_BIT_AVX512_FP16_128
                       == UINT32_C(145)
                   && CDISASM_X86_DECODE_BIT_AVX512_FP16_256
                       == UINT32_C(147)
                   && CDISASM_X86_DECODE_BIT_AVX512_FP16_512
                       == UINT32_C(148)
                   && CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR
                       == UINT32_C(152),
               "update VMULPH/VMULSH fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VMULPS == UINT16_C(618)
                   && CDISASM_X86_NAME_VMULPD == UINT16_C(619)
                   && CDISASM_X86_NAME_VMULSS == UINT16_C(620)
                   && CDISASM_X86_NAME_VMULSD == UINT16_C(621)
                   && CDISASM_X86_GROUP_AVX512F_128 == UINT16_C(180)
                   && CDISASM_X86_GROUP_AVX512F_256 == UINT16_C(182)
                   && CDISASM_X86_GROUP_AVX512F_512 == UINT16_C(183)
                   && CDISASM_X86_GROUP_AVX512F_SCALAR == UINT16_C(185)
                   && CDISASM_X86_DECODE_BIT_AVX512F_128
                       == UINT32_C(128)
                   && CDISASM_X86_DECODE_BIT_AVX512F_256
                       == UINT32_C(130)
                   && CDISASM_X86_DECODE_BIT_AVX512F_512
                       == UINT32_C(131)
                   && CDISASM_X86_DECODE_BIT_AVX512F_SCALAR
                       == UINT32_C(133),
               "update classic VMUL fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VORPS == UINT16_C(638)
                   && CDISASM_X86_NAME_VORPD == UINT16_C(639)
                   && CDISASM_X86_GROUP_AVX512DQ_128 == UINT16_C(171)
                   && CDISASM_X86_GROUP_AVX512DQ_256 == UINT16_C(173)
                   && CDISASM_X86_GROUP_AVX512DQ_512 == UINT16_C(174)
                   && CDISASM_X86_DECODE_BIT_AVX512DQ_128
                       == UINT32_C(119)
                   && CDISASM_X86_DECODE_BIT_AVX512DQ_256
                       == UINT32_C(121)
                   && CDISASM_X86_DECODE_BIT_AVX512DQ_512
                       == UINT32_C(122),
               "update classic VOR fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VP2INTERSECTD == UINT16_C(1797)
                   && CDISASM_X86_NAME_VP2INTERSECTQ == UINT16_C(1798)
                   && CDISASM_X86_GROUP_AVX512_VP2INTERSECT_128
                       == UINT16_C(250)
                   && CDISASM_X86_GROUP_AVX512_VP2INTERSECT_256
                       == UINT16_C(251)
                   && CDISASM_X86_GROUP_AVX512_VP2INTERSECT_512
                       == UINT16_C(252)
                   && CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_128
                       == UINT32_C(198)
                   && CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_256
                       == UINT32_C(199)
                   && CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_512
                       == UINT32_C(200),
               "update VP2INTERSECT fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPABSB == UINT16_C(1799)
                   && CDISASM_X86_NAME_VPABSD == UINT16_C(1800)
                   && CDISASM_X86_NAME_VPABSQ == UINT16_C(1801)
                   && CDISASM_X86_NAME_VPABSW == UINT16_C(1802)
                   && CDISASM_X86_GROUP_AVX512BW_128 == UINT16_C(162)
                   && CDISASM_X86_GROUP_AVX512BW_256 == UINT16_C(164)
                   && CDISASM_X86_GROUP_AVX512BW_512 == UINT16_C(165)
                   && CDISASM_X86_GROUP_AVX512F_128 == UINT16_C(180)
                   && CDISASM_X86_GROUP_AVX512F_256 == UINT16_C(182)
                   && CDISASM_X86_GROUP_AVX512F_512 == UINT16_C(183)
                   && CDISASM_X86_DECODE_BIT_AVX512BW_128
                       == UINT32_C(110)
                   && CDISASM_X86_DECODE_BIT_AVX512BW_256
                       == UINT32_C(112)
                   && CDISASM_X86_DECODE_BIT_AVX512BW_512
                       == UINT32_C(113)
                   && CDISASM_X86_DECODE_BIT_AVX512F_128
                       == UINT32_C(128)
                   && CDISASM_X86_DECODE_BIT_AVX512F_256
                       == UINT32_C(130)
                   && CDISASM_X86_DECODE_BIT_AVX512F_512
                       == UINT32_C(131),
               "update VPABS fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPACKSSDW == UINT16_C(1803)
                   && CDISASM_X86_NAME_VPACKSSWB == UINT16_C(1804)
                   && CDISASM_X86_NAME_VPACKUSDW == UINT16_C(1805)
                   && CDISASM_X86_NAME_VPACKUSWB == UINT16_C(1806)
                   && CDISASM_X86_GROUP_AVX512BW_128 == UINT16_C(162)
                   && CDISASM_X86_GROUP_AVX512BW_256 == UINT16_C(164)
                   && CDISASM_X86_GROUP_AVX512BW_512 == UINT16_C(165)
                   && CDISASM_X86_DECODE_BIT_AVX512BW_128
                       == UINT32_C(110)
                   && CDISASM_X86_DECODE_BIT_AVX512BW_256
                       == UINT32_C(112)
                   && CDISASM_X86_DECODE_BIT_AVX512BW_512
                       == UINT32_C(113),
               "update VPACK fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VBLENDPD == UINT16_C(1476)
                   && CDISASM_X86_NAME_VBLENDPS == UINT16_C(1477)
                   && CDISASM_X86_NAME_VBLENDVPD == UINT16_C(1478)
                   && CDISASM_X86_NAME_VBLENDVPS == UINT16_C(1479)
                   && CDISASM_X86_NAME_VPBLENDD == UINT16_C(1807)
                   && CDISASM_X86_NAME_VPBLENDVB == UINT16_C(1812)
                   && CDISASM_X86_NAME_VPBLENDW == UINT16_C(1813)
                   && CDISASM_X86_NAME_VPBROADCASTB == UINT16_C(1814)
                   && CDISASM_X86_NAME_VPBROADCASTD == UINT16_C(1815)
                   && CDISASM_X86_NAME_VPBROADCASTQ == UINT16_C(1816)
                   && CDISASM_X86_NAME_VPBROADCASTW == UINT16_C(1817)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update VEX blend fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPCMPEQQ == UINT16_C(1818)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update VEX VPCMPEQQ fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPCMPGTQ == UINT16_C(1823)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update VEX VPCMPGTQ fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPCMPGTW == UINT16_C(658)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update VEX VPCMPGTW fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPCMPEQB == UINT16_C(654)
                   && CDISASM_X86_NAME_VPCMPEQW == UINT16_C(655)
                   && CDISASM_X86_NAME_VPCMPEQD == UINT16_C(656)
                   && CDISASM_X86_NAME_VPCMPGTB == UINT16_C(657)
                   && CDISASM_X86_NAME_VPCMPGTD == UINT16_C(659),
               "update packed-compare fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPMASKMOVD == UINT16_C(1863)
                   && CDISASM_X86_NAME_VPMASKMOVQ == UINT16_C(1864)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update VEX VPMASKMOVD/Q fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VBROADCASTF128 == UINT16_C(1480)
                   && CDISASM_X86_NAME_VBROADCASTI128 == UINT16_C(1486)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update VEX VBROADCASTF128/I128 fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VEXTRACTF128 == UINT16_C(1646)
                   && CDISASM_X86_NAME_VEXTRACTI128 == UINT16_C(1651)
                   && CDISASM_X86_NAME_VINSERTF128 == UINT16_C(1740)
                   && CDISASM_X86_NAME_VINSERTI128 == UINT16_C(1745)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update VEX lane insert/extract fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VEXTRACTPS == UINT16_C(1656)
                   && CDISASM_X86_NAME_VINSERTPS == UINT16_C(1750)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update VEX PS lane fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPERM2F128 == UINT16_C(1827)
                   && CDISASM_X86_NAME_VPERM2I128 == UINT16_C(1828)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update VEX VPERM2F128/I128 fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPERMD == UINT16_C(1829)
                   && CDISASM_X86_NAME_VPERMPS == UINT16_C(1837)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update VEX VPERMD/VPERMPS fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPERMPD == UINT16_C(1836)
                   && CDISASM_X86_NAME_VPERMQ == UINT16_C(1838)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update VEX VPERMPD/VPERMQ fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPERMILPD == UINT16_C(1834)
                   && CDISASM_X86_NAME_VPERMILPS == UINT16_C(1835)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update VEX VPERMILPD/VPERMILPS fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VROUNDPD == UINT16_C(1963)
                   && CDISASM_X86_NAME_VROUNDPS == UINT16_C(1964)
                   && CDISASM_X86_NAME_VROUNDSD == UINT16_C(1965)
                   && CDISASM_X86_NAME_VROUNDSS == UINT16_C(1966)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update classic-VEX VROUND fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VCMPPD == UINT16_C(1495)
                   && CDISASM_X86_NAME_VCMPPS == UINT16_C(1497)
                   && CDISASM_X86_NAME_VCMPSD == UINT16_C(1498)
                   && CDISASM_X86_NAME_VCMPSS == UINT16_C(1500)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update classic-VEX VCMP fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VDPPD == UINT16_C(1639)
                   && CDISASM_X86_NAME_VDPPS == UINT16_C(1641)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update classic-VEX VDPP fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VLDMXCSR == UINT16_C(1751)
                   && CDISASM_X86_NAME_VSTMXCSR == UINT16_C(2006)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update classic-VEX VMXCSR fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VMASKMOVPD == UINT16_C(1753)
                   && CDISASM_X86_NAME_VMASKMOVPS == UINT16_C(1754)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update classic-VEX VMASKMOV fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VSHUFPD == UINT16_C(2001)
                   && CDISASM_X86_NAME_VSHUFPS == UINT16_C(2002)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update classic-VEX VSHUF fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VTESTPD == UINT16_C(2009)
                   && CDISASM_X86_NAME_VTESTPS == UINT16_C(2010)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update classic-VEX VTEST fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPTEST == UINT16_C(1917)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update classic-VEX VPTEST fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VUCOMISD == UINT16_C(2011)
                   && CDISASM_X86_NAME_VUCOMISH == UINT16_C(2012)
                   && CDISASM_X86_NAME_VUCOMISS == UINT16_C(2013)
                   && CDISASM_X86_NAME_VCOMISD == UINT16_C(1502)
                   && CDISASM_X86_NAME_VCOMISS == UINT16_C(1504)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update classic-VEX VCOMI fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VUNPCKHPD == UINT16_C(2018)
                   && CDISASM_X86_NAME_VUNPCKHPS == UINT16_C(2019)
                   && CDISASM_X86_NAME_VUNPCKLPD == UINT16_C(2020)
                   && CDISASM_X86_NAME_VUNPCKLPS == UINT16_C(2021)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
               "update classic-VEX VUNPCK fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VPUNPCKHBW == UINT16_C(1926)
                   && CDISASM_X86_NAME_VPUNPCKHDQ == UINT16_C(1927)
                   && CDISASM_X86_NAME_VPUNPCKHQDQ == UINT16_C(1928)
                   && CDISASM_X86_NAME_VPUNPCKHWD == UINT16_C(1929)
                   && CDISASM_X86_NAME_VPUNPCKLBW == UINT16_C(1930)
                   && CDISASM_X86_NAME_VPUNPCKLDQ == UINT16_C(1931)
                   && CDISASM_X86_NAME_VPUNPCKLQDQ == UINT16_C(1932)
                   && CDISASM_X86_NAME_VPUNPCKLWD == UINT16_C(1933)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update classic-VEX VPUNPCK fuzz invariants");
_Static_assert(CDISASM_X86_NAME_VBROADCASTSD == UINT16_C(1492)
                   && CDISASM_X86_NAME_VBROADCASTSS == UINT16_C(1493)
                   && CDISASM_X86_GROUP_AVX == UINT16_C(37)
                   && CDISASM_X86_GROUP_AVX2 == UINT16_C(46)
                   && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8)
                   && CDISASM_X86_DECODE_BIT_AVX2 == UINT32_C(9),
               "update VEX VBROADCASTSD/SS fuzz invariants");
_Static_assert(CDISASM_X86_NAME_CLAC == UINT16_C(1262)
                   && CDISASM_X86_NAME_STAC == UINT16_C(1445)
                   && CDISASM_X86_GROUP_SMAP == UINT16_C(306)
                   && CDISASM_X86_DECODE_BIT_SMAP == UINT32_C(253),
               "update SMAP exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_MCOMMIT == UINT16_C(1342)
                   && CDISASM_X86_GROUP_MCOMMIT == UINT16_C(282)
                   && CDISASM_X86_DECODE_BIT_MCOMMIT == UINT32_C(229),
               "update MCOMMIT exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_MONITORX == UINT16_C(1343)
                   && CDISASM_X86_NAME_MWAITX == UINT16_C(1354)
                   && CDISASM_X86_GROUP_MONITORX == UINT16_C(284)
                   && CDISASM_X86_DECODE_BIT_MONITORX == UINT32_C(231),
               "update MONITORX/MWAITX exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_ENQCMD == UINT16_C(1184)
                   && CDISASM_X86_NAME_ENQCMDS == UINT16_C(1185)
                   && CDISASM_X86_GROUP_ENQCMD == UINT16_C(115)
                   && CDISASM_X86_GROUP_APX_F_ENQCMD == UINT16_C(132)
                   && CDISASM_X86_DECODE_BIT_APX_F_ENQCMD == UINT32_C(80),
               "update ENQCMD exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_INVLPGB == UINT16_C(1328)
                   && CDISASM_X86_NAME_TLBSYNC == UINT16_C(1454)
                   && CDISASM_X86_GROUP_AMD_INVLPGB == UINT16_C(119)
                   && CDISASM_X86_DECODE_BIT_AMD_INVLPGB == UINT32_C(67),
               "update AMD_INVLPGB exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_PSMASH == UINT16_C(1378)
                   && CDISASM_X86_NAME_PVALIDATE == UINT16_C(1383)
                   && CDISASM_X86_NAME_RMPADJUST == UINT16_C(1431)
                   && CDISASM_X86_NAME_RMPUPDATE == UINT16_C(1432)
                   && CDISASM_X86_GROUP_SNP == UINT16_C(307)
                   && CDISASM_X86_DECODE_BIT_SNP == UINT32_C(254),
               "update SNP exact-family fuzz invariants");
_Static_assert(CDISASM_X86_NAME_RDMSRLIST == UINT16_C(1384)
                   && CDISASM_X86_NAME_WRMSRLIST == UINT16_C(2022)
                   && CDISASM_X86_NAME_WRMSRNS == UINT16_C(2023)
                   && CDISASM_X86_GROUP_APX_F_MSR_IMM == UINT16_C(144)
                   && CDISASM_X86_GROUP_MSRLIST == UINT16_C(286)
                   && CDISASM_X86_GROUP_MSR_IMM == UINT16_C(287)
                   && CDISASM_X86_GROUP_WRMSRNS == UINT16_C(322)
                   && CDISASM_X86_DECODE_BIT_APX_F_MSR_IMM == UINT32_C(92)
                   && CDISASM_X86_DECODE_BIT_MSRLIST == UINT32_C(233)
                   && CDISASM_X86_DECODE_BIT_MSR_IMM == UINT32_C(234)
                   && CDISASM_X86_DECODE_BIT_WRMSRNS == UINT32_C(268),
               "update privileged MSR exact-family fuzz invariants");

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

/* Checked-in seeds are readable hexadecimal. Mutated/non-text input remains raw. */
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
            hex_bytes[output_size++] = (uint8_t)((high_nibble << 4) | nibble);
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
    const uint8_t *data, size_t size, cdisasm_x86_decode_flags *flags)
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

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_option decode_flag_word0(
    const cdisasm_x86_decode_flags *flags)
{
    return flags != NULL
        ? flags->bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
        : UINT64_C(0);
}

static cdisasm_x86_decode_option cpu_flag_word0(
    cdisasm_x86_cpu_id cpu_id, cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    invariant(cdisasm_x86_cpu_decode_flag_mask(cpu_id, mode, &flags)
        == CDISASM_STATUS_OK);
    return flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP];
}

static int cpu_has_decode_bit(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    invariant(cdisasm_x86_cpu_decode_flag_mask(cpu_id, mode, &flags)
        == CDISASM_STATUS_OK);
    return cdisasm_decode_flags_test_bit(&flags, bit_id);
}
#endif

static int failure_result_is_zeroed(const cdisasm_instruction *instruction)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = instruction->last_error_id;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void check_groups(const cdisasm_instruction *instruction)
{
    uint8_t index;

    invariant(instruction->x86_group_count >= 1u);
    invariant(instruction->x86_group_count <= CDISASM_MAX_X86_GROUPS);
    invariant(instruction->x86_group_reserved == 0u);
    for (index = 0; index < instruction->x86_group_count; ++index) {
        invariant(instruction->x86_group_ids[index] >= CDISASM_X86_GROUP_FIRST);
        invariant(instruction->x86_group_ids[index] <= CDISASM_X86_GROUP_LAST);
        if (index != 0) {
            invariant(instruction->x86_group_ids[index - 1u]
                      < instruction->x86_group_ids[index]);
        }
        invariant(cdisasm_instruction_has_x86_group(
            instruction, instruction->x86_group_ids[index]));
    }
    for (; index < CDISASM_MAX_X86_GROUPS; ++index) {
        invariant(instruction->x86_group_ids[index] == CDISASM_X86_GROUP_NONE);
    }
}

#if USE_DISASM_FORMAT
static void check_format(const cdisasm_instruction *instruction, uint64_t hash)
{
    char full[FUZZ_FORMAT_CAPACITY];
    char short_buffer[32];
    size_t required;
    size_t written;
    size_t short_capacity = (size_t)(hash % sizeof(short_buffer));
    uint32_t format_flags = (uint32_t)hash
        & CDISASM_FORMAT_KNOWN_FLAGS_MASK;

    required = cdisasm_x86_format(
        instruction, format_flags, NULL, 0);
    invariant(required != 0);
    invariant(required < sizeof(full) - 1u);

    memset(full, 0xa5, sizeof(full));
    written = cdisasm_x86_format(
        instruction, format_flags, full, required + 1u);
    invariant(written == required);
    invariant(full[required] == '\0');
    invariant(strlen(full) == required);
    invariant(full[required + 1u] == (char)0xa5);

    memset(short_buffer, 0x5a, sizeof(short_buffer));
    written = cdisasm_x86_format(
        instruction, format_flags, short_buffer, short_capacity);
    invariant(written == required);
    if (short_capacity == 0) {
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
    invariant(cdisasm_x86_format(
                  instruction,
                  CDISASM_FORMAT_KNOWN_FLAGS_MASK + UINT32_C(1),
                  short_buffer,
                  sizeof(short_buffer))
        == 0u);
    invariant(short_buffer[0] == '\0');
}
#endif

static void check_one(const uint8_t *code, size_t code_size,
                      cdisasm_cpu_id cpu_id, cdisasm_mode mode,
                      uint64_t address, uint64_t hash,
                      const cdisasm_x86_decode_flags *decode_flags)
{
    const uint32_t known_opcode_flags = CDISASM_PREFIX_LOCK
        | CDISASM_PREFIX_REP
        | CDISASM_PREFIX_REPNE
        | CDISASM_PREFIX_OPERAND_SIZE
        | CDISASM_PREFIX_ADDRESS_SIZE
        | CDISASM_PREFIX_SEGMENT
        | CDISASM_PREFIX_REX
        | CDISASM_PREFIX_REX_W
        | CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_WAIT
        | CDISASM_PREFIX_XOP
        | CDISASM_PREFIX_EVEX
        | CDISASM_PREFIX_REX2
        | CDISASM_PREFIX_APX_NDD
        | CDISASM_PREFIX_APX_NF
        | CDISASM_PREFIX_APX_ZU
        | CDISASM_PREFIX_EFFECTIVE_MASK
        | CDISASM_PREFIX_HLE_MASK
        | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
        | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS
        | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    cdisasm_instruction first;
    cdisasm_instruction second;
    uint32_t first_size;
    uint32_t second_size;

#if !USE_DISASM_FORMAT
    (void)hash;
#endif

    memset(&first, 0xa5, sizeof(first));
    first_size = cdisasm_x86_decode(cpu_id, mode, code, code_size, address,
                                     decode_flags, &first);
    memset(&second, 0x5a, sizeof(second));
    second_size = cdisasm_x86_decode(cpu_id, mode, code, code_size, address,
                                      decode_flags, &second);
    invariant(first_size == second_size);
    invariant(memcmp(&first, &second, sizeof(first)) == 0);

    if (first_size == 0) {
        invariant(first.last_error_id >= CDISASM_STATUS_INVALID_ARGUMENT);
        invariant(first.last_error_id <= CDISASM_STATUS_INTERNAL_ERROR);
        invariant(failure_result_is_zeroed(&first));
#if !USE_EXTRA_OPCODES
        if (cpu_id == CDISASM_CPU_X86
            && ((code_size >= 3u
                    && code[0] == UINT8_C(0x0f)
                    && code[1] == UINT8_C(0x01)
                    && code[2] == UINT8_C(0xc6))
                || (mode == CDISASM_MODE_64
                    && code_size >= 4u
                    && (code[0] == UINT8_C(0xf2)
                        || code[0] == UINT8_C(0xf3))
                    && code[1] == UINT8_C(0x0f)
                    && code[2] == UINT8_C(0x01)
                    && code[3] == UINT8_C(0xc6))
                || (mode == CDISASM_MODE_64
                    && code_size >= 9u
                    && code[0] == UINT8_C(0xc4)
                    && code[1] == UINT8_C(0xe7)
                    && (code[2] == UINT8_C(0x7b)
                        || code[2] == UINT8_C(0x7a))
                    && code[3] == UINT8_C(0xf6)
                    && code[4] == UINT8_C(0xc0))
                || (mode == CDISASM_MODE_64
                    && code_size >= 10u
                    && code[0] == UINT8_C(0x62)
                    && code[1] == UINT8_C(0xf7)
                    && (code[2] == UINT8_C(0x7f)
                        || code[2] == UINT8_C(0x7e))
                    && code[3] == UINT8_C(0x08)
                    && code[4] == UINT8_C(0xf6)
                    && code[5] == UINT8_C(0xc0)))) {
            invariant(first.last_error_id
                == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
#endif
#if USE_DISASM_FORMAT
        {
            char invalid_buffer[8] = "invalid";

            invariant(cdisasm_x86_format(
                          &first,
                          CDISASM_FORMAT_SYNTAX_0,
                          invalid_buffer,
                          sizeof(invalid_buffer))
                == 0);
            invariant(invalid_buffer[0] == '\0');
        }
#endif
        return;
    }

    invariant(first_size <= CDISASM_MAX_INSTRUCTION_SIZE);
    invariant((size_t)first_size <= code_size);
    invariant(first.last_error_id == CDISASM_STATUS_OK);
    invariant(first.opcode_size == first_size);
    invariant(first.name_id >= CDISASM_X86_NAME_FIRST);
    invariant(first.name_id <= CDISASM_X86_NAME_LAST);
    invariant((first.opcode_flags & ~known_opcode_flags) == 0u);
    invariant((first.opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
    invariant(first.operand_count <= CDISASM_MAX_OPERANDS);
    invariant(first.mask_reg == CDISASM_X86_REG_NONE
        || (first.mask_reg >= CDISASM_X86_REG_K1
            && first.mask_reg <= CDISASM_X86_REG_K7));
    invariant(first.mask_mode <= CDISASM_X86_MASK_ZERO);
    invariant((first.mask_reg == CDISASM_X86_REG_NONE)
        == (first.mask_mode == CDISASM_X86_MASK_NONE));
    invariant(first.rounding <= CDISASM_X86_ROUNDING_RZ);
    invariant(first.sae <= CDISASM_X86_SAE_ENABLED);
    invariant(first.rounding == CDISASM_X86_ROUNDING_NONE
        || first.sae == CDISASM_X86_SAE_ENABLED);
    invariant((first.opcode_flags & (CDISASM_PREFIX_VEX
            | CDISASM_PREFIX_XOP | CDISASM_PREFIX_EVEX
            | CDISASM_PREFIX_REX2)) == 0u
        || ((first.opcode_flags & CDISASM_PREFIX_VEX) != 0u)
            + ((first.opcode_flags & CDISASM_PREFIX_XOP) != 0u)
            + ((first.opcode_flags & CDISASM_PREFIX_EVEX) != 0u)
            + ((first.opcode_flags & CDISASM_PREFIX_REX2) != 0u) == 1);
    invariant((first.opcode_flags & (CDISASM_PREFIX_APX_NDD
            | CDISASM_PREFIX_APX_NF | CDISASM_PREFIX_APX_ZU)) == 0u
        || (first.opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
    invariant(first.reserved == 0u);
    invariant(first.encoding.reserved == 0u);
    invariant(first.encoding.prefix_size <= first_size);
    invariant(first.encoding.opcode_offset <= first_size);
    invariant(first.encoding.opcode_size <= first_size
        - first.encoding.opcode_offset);
    if ((first.opcode_flags & CDISASM_PREFIX_VEX) != 0u) {
        invariant((first.opcode_flags
            & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_REP
                | CDISASM_PREFIX_REPNE
                | CDISASM_PREFIX_OPERAND_SIZE
                | CDISASM_PREFIX_REX)) == 0u);
        invariant(first.encoding.prefix_size >= 2u);
        invariant(first.encoding.opcode_offset
            == first.encoding.prefix_size);
        invariant(first.encoding.opcode_size == 1u);
    }
    if ((first.opcode_flags & CDISASM_PREFIX_VEX) != 0u
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        int is_zero = first.name_id == CDISASM_X86_NAME_VZEROALL
            || first.name_id == CDISASM_X86_NAME_VZEROUPPER;
#if USE_EXTRA_OPCODES
        int is_old_vector =
            (first.name_id >= CDISASM_X86_NAME_VADDPS
                && first.name_id <= CDISASM_X86_NAME_VPSADBW)
            || (first.name_id >= CDISASM_X86_NAME_VPADDSB
                && first.name_id <= CDISASM_X86_NAME_VPSUBUSW);
        int is_bmi = first.name_id >= CDISASM_X86_NAME_ANDN
            && first.name_id <= CDISASM_X86_NAME_SHRX;
        int is_f16c = first.name_id >= CDISASM_X86_NAME_VCVTPH2PS
            && first.name_id <= CDISASM_X86_NAME_VCVTPS2PH;
        int is_fma3 = (first.name_id >= CDISASM_X86_NAME_VFMADD132PS
                && first.name_id <= CDISASM_X86_NAME_VFMADD132SD)
            || (first.name_id >= CDISASM_X86_NAME_VFMADD213PD
                && first.name_id <= CDISASM_X86_NAME_VFNMSUB231SD);
        int is_fma4 = (first.name_id >= CDISASM_X86_NAME_VFMADDPS
                && first.name_id <= CDISASM_X86_NAME_VFMADDSD)
            || (first.name_id >= CDISASM_X86_NAME_VFMADDSUBPS
                && first.name_id <= CDISASM_X86_NAME_VFNMSUBSD);
        int is_amx = (first.name_id >= CDISASM_X86_NAME_LDTILECFG
                && first.name_id <= CDISASM_X86_NAME_TDPBF16PS)
            || first.name_id == CDISASM_X86_NAME_TDPFP16PS
            || (first.name_id >= CDISASM_X86_NAME_TCMMIMFP16PS
                && first.name_id <= CDISASM_X86_NAME_TILELOADDRST1);
        int is_map23_vector = (first.name_id >= CDISASM_X86_NAME_VPSHUFB
                && first.name_id <= CDISASM_X86_NAME_VPCLMULQDQ)
            || (first.name_id >= CDISASM_X86_NAME_VAESENCLAST
                && first.name_id <= CDISASM_X86_NAME_VAESKEYGENASSIST);
        int is_vpermil2 =
            first.name_id >= CDISASM_X86_NAME_VPERMIL2PS
            && first.name_id <= CDISASM_X86_NAME_VPERMIL2PD;
        int is_kmask = first.name_id >= CDISASM_X86_NAME_KANDNW
            && first.name_id <= CDISASM_X86_NAME_KXORQ;
        int is_avx_core = first.name_id >= CDISASM_X86_NAME_VADDSUBPD
            && first.name_id <= CDISASM_X86_NAME_VCVTSS2SD;
        int is_modern_crypto =
            first.name_id >= CDISASM_X86_NAME_VSHA512MSG1
            && first.name_id <= CDISASM_X86_NAME_VSM4RNDS4;
        int is_variable_shift =
            first.name_id >= CDISASM_X86_NAME_VPSLLVD
            && first.name_id <= CDISASM_X86_NAME_VPSRAVQ;
        int is_avx_vnni =
            first.name_id == CDISASM_X86_NAME_VPDPBUSD
            || (first.name_id >= CDISASM_X86_NAME_VPDPBUSDS
                && first.name_id <= CDISASM_X86_NAME_VPDPWSSDS);
        int is_avx_vnni_int8 =
            first.name_id >= CDISASM_X86_NAME_VPDPBSSD
            && first.name_id <= CDISASM_X86_NAME_VPDPBUUDS;
        int is_avx_vnni_int16 =
            first.name_id >= CDISASM_X86_NAME_VPDPWSUD
            && first.name_id <= CDISASM_X86_NAME_VPDPWUUDS;
        int is_bsr = first.name_id == CDISASM_X86_NAME_BSRINIT;
        int is_user_msr = first.name_id == CDISASM_X86_NAME_URDMSR
            || first.name_id == CDISASM_X86_NAME_UWRMSR;
        int is_msr_imm = cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_MSR_IMM);
        int is_non_temporal_store =
            first.name_id == CDISASM_X86_NAME_VMOVNTDQ
            || first.name_id == CDISASM_X86_NAME_VMOVNTPD
            || first.name_id == CDISASM_X86_NAME_VMOVNTPS;
        int is_non_temporal_load =
            first.name_id == CDISASM_X86_NAME_VMOVNTDQA;
        int is_unaligned_load =
            first.name_id == CDISASM_X86_NAME_VLDDQU;
        int is_move_mask =
            first.name_id == CDISASM_X86_NAME_VMOVMSKPD
            || first.name_id == CDISASM_X86_NAME_VMOVMSKPS;
        int is_vpmovmskb =
            first.name_id == CDISASM_X86_NAME_VPMOVMSKB
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_move_quadword =
            first.name_id == CDISASM_X86_NAME_VMOVQ;
        int is_move_scalar = first.name_id == CDISASM_X86_NAME_VMOVSD
            || first.name_id == CDISASM_X86_NAME_VMOVSS;
        int is_move_duplicate =
            first.name_id == CDISASM_X86_NAME_VMOVSHDUP
            || first.name_id == CDISASM_X86_NAME_VMOVSLDUP;
        int is_unaligned_packed_move =
            first.name_id == CDISASM_X86_NAME_VMOVUPD
            || first.name_id == CDISASM_X86_NAME_VMOVUPS;
        int is_packed_move =
            first.name_id >= CDISASM_X86_NAME_VMOVUPS
            && first.name_id <= CDISASM_X86_NAME_VMOVDQU;
        int is_vmpsadbw =
            first.name_id == CDISASM_X86_NAME_VMPSADBW;
        int is_vmul_fp = first.name_id == CDISASM_X86_NAME_VMULPS
            || first.name_id == CDISASM_X86_NAME_VMULPD
            || first.name_id == CDISASM_X86_NAME_VMULSS
            || first.name_id == CDISASM_X86_NAME_VMULSD;
        int is_vor_fp = first.name_id == CDISASM_X86_NAME_VORPS
            || first.name_id == CDISASM_X86_NAME_VORPD;
        int is_vpabs = first.name_id == CDISASM_X86_NAME_VPABSB
            || first.name_id == CDISASM_X86_NAME_VPABSW
            || first.name_id == CDISASM_X86_NAME_VPABSD
            || first.name_id == CDISASM_X86_NAME_VPABSQ;
        int is_vpack = first.name_id == CDISASM_X86_NAME_VPACKSSDW
            || first.name_id == CDISASM_X86_NAME_VPACKSSWB
            || first.name_id == CDISASM_X86_NAME_VPACKUSDW
            || first.name_id == CDISASM_X86_NAME_VPACKUSWB;
        int is_vpblend = first.name_id == CDISASM_X86_NAME_VBLENDPD
            || first.name_id == CDISASM_X86_NAME_VBLENDPS
            || first.name_id == CDISASM_X86_NAME_VPBLENDD
            || first.name_id == CDISASM_X86_NAME_VPBLENDW;
        int is_vpblendvb =
            first.name_id == CDISASM_X86_NAME_VPBLENDVB;
        int is_vblendv = first.name_id == CDISASM_X86_NAME_VBLENDVPD
            || first.name_id == CDISASM_X86_NAME_VBLENDVPS;
        int is_vpbroadcast =
            (first.name_id == CDISASM_X86_NAME_VPBROADCASTB
                || first.name_id == CDISASM_X86_NAME_VPBROADCASTW
                || first.name_id == CDISASM_X86_NAME_VPBROADCASTD
                || first.name_id == CDISASM_X86_NAME_VPBROADCASTQ)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vbroadcast128 =
            first.name_id == CDISASM_X86_NAME_VBROADCASTF128
            || first.name_id == CDISASM_X86_NAME_VBROADCASTI128;
        int is_vex_lane128 =
            first.name_id == CDISASM_X86_NAME_VEXTRACTF128
            || first.name_id == CDISASM_X86_NAME_VEXTRACTI128
            || first.name_id == CDISASM_X86_NAME_VINSERTF128
            || first.name_id == CDISASM_X86_NAME_VINSERTI128;
        int is_vex_ps_lane =
            (first.name_id == CDISASM_X86_NAME_VEXTRACTPS
                || first.name_id == CDISASM_X86_NAME_VINSERTPS)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_perm2_128 =
            first.name_id == CDISASM_X86_NAME_VPERM2F128
            || first.name_id == CDISASM_X86_NAME_VPERM2I128;
        int is_vex_permd_vpermps =
            (first.name_id == CDISASM_X86_NAME_VPERMD
                || first.name_id == CDISASM_X86_NAME_VPERMPS)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vpermpd_vpermq =
            (first.name_id == CDISASM_X86_NAME_VPERMPD
                || first.name_id == CDISASM_X86_NAME_VPERMQ)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vpermilpd_vpermilps =
            (first.name_id == CDISASM_X86_NAME_VPERMILPD
                || first.name_id == CDISASM_X86_NAME_VPERMILPS)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vround =
            (first.name_id == CDISASM_X86_NAME_VROUNDPD
                || first.name_id == CDISASM_X86_NAME_VROUNDPS
                || first.name_id == CDISASM_X86_NAME_VROUNDSD
                || first.name_id == CDISASM_X86_NAME_VROUNDSS)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vcmp =
            (first.name_id == CDISASM_X86_NAME_VCMPPD
                || first.name_id == CDISASM_X86_NAME_VCMPPS
                || first.name_id == CDISASM_X86_NAME_VCMPSD
                || first.name_id == CDISASM_X86_NAME_VCMPSS)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vdpp =
            (first.name_id == CDISASM_X86_NAME_VDPPD
                || first.name_id == CDISASM_X86_NAME_VDPPS)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vmxcsr =
            (first.name_id == CDISASM_X86_NAME_VLDMXCSR
                || first.name_id == CDISASM_X86_NAME_VSTMXCSR)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vmaskmov =
            (first.name_id == CDISASM_X86_NAME_VMASKMOVPD
                || first.name_id == CDISASM_X86_NAME_VMASKMOVPS)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vpmaskmov =
            (first.name_id == CDISASM_X86_NAME_VPMASKMOVD
                || first.name_id == CDISASM_X86_NAME_VPMASKMOVQ)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vshuf =
            (first.name_id == CDISASM_X86_NAME_VSHUFPD
                || first.name_id == CDISASM_X86_NAME_VSHUFPS)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vtest =
            (first.name_id == CDISASM_X86_NAME_VTESTPD
                || first.name_id == CDISASM_X86_NAME_VTESTPS)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vptest = first.name_id == CDISASM_X86_NAME_VPTEST
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vcomi =
            (first.name_id == CDISASM_X86_NAME_VUCOMISD
                || first.name_id == CDISASM_X86_NAME_VUCOMISS
                || first.name_id == CDISASM_X86_NAME_VCOMISD
                || first.name_id == CDISASM_X86_NAME_VCOMISS)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vunpck =
            (first.name_id == CDISASM_X86_NAME_VUNPCKHPD
                || first.name_id == CDISASM_X86_NAME_VUNPCKHPS
                || first.name_id == CDISASM_X86_NAME_VUNPCKLPD
                || first.name_id == CDISASM_X86_NAME_VUNPCKLPS)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vpunpck_integer =
            (first.name_id == CDISASM_X86_NAME_VPUNPCKHBW
                || first.name_id == CDISASM_X86_NAME_VPUNPCKHWD
                || first.name_id == CDISASM_X86_NAME_VPUNPCKHDQ
                || first.name_id == CDISASM_X86_NAME_VPUNPCKHQDQ
                || first.name_id == CDISASM_X86_NAME_VPUNPCKLBW
                || first.name_id == CDISASM_X86_NAME_VPUNPCKLWD
                || first.name_id == CDISASM_X86_NAME_VPUNPCKLDQ
                || first.name_id == CDISASM_X86_NAME_VPUNPCKLQDQ)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vpsign_integer =
            (first.name_id == CDISASM_X86_NAME_VPSIGNB
                || first.name_id == CDISASM_X86_NAME_VPSIGND
                || first.name_id == CDISASM_X86_NAME_VPSIGNW)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vpshuf_integer =
            (first.name_id == CDISASM_X86_NAME_VPSHUFD
                || first.name_id == CDISASM_X86_NAME_VPSHUFHW
                || first.name_id == CDISASM_X86_NAME_VPSHUFLW)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_horizontal_integer =
            (first.name_id == CDISASM_X86_NAME_VPHADDD
                || first.name_id == CDISASM_X86_NAME_VPHADDSW
                || first.name_id == CDISASM_X86_NAME_VPHADDW
                || first.name_id == CDISASM_X86_NAME_VPHSUBD
                || first.name_id == CDISASM_X86_NAME_VPHSUBSW
                || first.name_id == CDISASM_X86_NAME_VPHSUBW)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vphminposuw =
            first.name_id == CDISASM_X86_NAME_VPHMINPOSUW
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vpmovsx =
            (first.name_id == CDISASM_X86_NAME_VPMOVSXBW
                || first.name_id == CDISASM_X86_NAME_VPMOVSXBD
                || first.name_id == CDISASM_X86_NAME_VPMOVSXBQ
                || first.name_id == CDISASM_X86_NAME_VPMOVSXWD
                || first.name_id == CDISASM_X86_NAME_VPMOVSXWQ
                || first.name_id == CDISASM_X86_NAME_VPMOVSXDQ)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vpmovzx =
            (first.name_id == CDISASM_X86_NAME_VPMOVZXBW
                || first.name_id == CDISASM_X86_NAME_VPMOVZXBD
                || first.name_id == CDISASM_X86_NAME_VPMOVZXBQ
                || first.name_id == CDISASM_X86_NAME_VPMOVZXWD
                || first.name_id == CDISASM_X86_NAME_VPMOVZXWQ
                || first.name_id == CDISASM_X86_NAME_VPMOVZXDQ)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vpinsr =
            (first.name_id == CDISASM_X86_NAME_VPINSRB
                || first.name_id == CDISASM_X86_NAME_VPINSRD
                || first.name_id == CDISASM_X86_NAME_VPINSRQ
                || first.name_id == CDISASM_X86_NAME_VPINSRW)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_vpextr =
            (first.name_id == CDISASM_X86_NAME_VPEXTRB
                || first.name_id == CDISASM_X86_NAME_VPEXTRD
                || first.name_id == CDISASM_X86_NAME_VPEXTRQ
                || first.name_id == CDISASM_X86_NAME_VPEXTRW)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vbroadcast_scalar =
            (first.name_id == CDISASM_X86_NAME_VBROADCASTSD
                || first.name_id == CDISASM_X86_NAME_VBROADCASTSS)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vpcmpeqq =
            first.name_id == CDISASM_X86_NAME_VPCMPEQQ
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vpcmpgtq =
            first.name_id == CDISASM_X86_NAME_VPCMPGTQ
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vpcmpgtw =
            first.name_id == CDISASM_X86_NAME_VPCMPGTW
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vpcmpeqb =
            first.name_id == CDISASM_X86_NAME_VPCMPEQB
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vpcmpeqd =
            first.name_id == CDISASM_X86_NAME_VPCMPEQD
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vpcmpeqw =
            first.name_id == CDISASM_X86_NAME_VPCMPEQW
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vpcmpgtb =
            first.name_id == CDISASM_X86_NAME_VPCMPGTB
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vpcmpgtd =
            first.name_id == CDISASM_X86_NAME_VPCMPGTD
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_modular_add_sub =
            (first.name_id == CDISASM_X86_NAME_VPADDB
                || first.name_id == CDISASM_X86_NAME_VPADDW
                || first.name_id == CDISASM_X86_NAME_VPADDD
                || first.name_id == CDISASM_X86_NAME_VPADDQ
                || first.name_id == CDISASM_X86_NAME_VPSUBB
                || first.name_id == CDISASM_X86_NAME_VPSUBW
                || first.name_id == CDISASM_X86_NAME_VPSUBD
                || first.name_id == CDISASM_X86_NAME_VPSUBQ)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_vex_integer_minmax =
            (first.name_id == CDISASM_X86_NAME_VPMAXSB
                || first.name_id == CDISASM_X86_NAME_VPMAXSD
                || first.name_id == CDISASM_X86_NAME_VPMAXSW
                || first.name_id == CDISASM_X86_NAME_VPMAXUB
                || first.name_id == CDISASM_X86_NAME_VPMAXUD
                || first.name_id == CDISASM_X86_NAME_VPMAXUW
                || first.name_id == CDISASM_X86_NAME_VPMINSB
                || first.name_id == CDISASM_X86_NAME_VPMINSD
                || first.name_id == CDISASM_X86_NAME_VPMINSW
                || first.name_id == CDISASM_X86_NAME_VPMINUB
                || first.name_id == CDISASM_X86_NAME_VPMINUD
                || first.name_id == CDISASM_X86_NAME_VPMINUW)
            && (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        int is_gfni =
            first.name_id == CDISASM_X86_NAME_VGF2P8AFFINEINVQB
            || first.name_id == CDISASM_X86_NAME_VGF2P8AFFINEQB
            || first.name_id == CDISASM_X86_NAME_VGF2P8MULB;

        invariant(is_zero || is_old_vector || is_bmi || is_f16c
            || is_fma3 || is_fma4 || is_amx || is_map23_vector
            || is_vpermil2 || is_kmask || is_avx_core || is_modern_crypto
            || is_variable_shift || is_avx_vnni || is_avx_vnni_int8
            || is_avx_vnni_int16 || is_bsr || is_user_msr || is_msr_imm
            || is_non_temporal_store || is_non_temporal_load
            || is_unaligned_load || is_move_mask || is_move_quadword
            || is_vpmovmskb
            || is_move_scalar || is_move_duplicate
            || is_packed_move || is_vmpsadbw || is_vmul_fp || is_vor_fp
            || is_vpabs || is_vpack || is_vpblend || is_vblendv
            || is_vpblendvb
            || is_vpbroadcast || is_vbroadcast128 || is_vex_lane128
            || is_vex_ps_lane || is_vex_perm2_128
            || is_vex_permd_vpermps
            || is_vex_vpermpd_vpermq
            || is_vex_vpermilpd_vpermilps
            || is_vex_vround
            || is_vex_vcmp
            || is_vex_vdpp
            || is_vex_vmxcsr
            || is_vex_vmaskmov
            || is_vex_vpmaskmov
            || is_vex_vshuf
            || is_vex_vtest
            || is_vex_vptest
            || is_vex_vcomi
            || is_vex_vunpck
            || is_vex_vpunpck_integer
            || is_vex_vpsign_integer
            || is_vex_vpshuf_integer
            || is_vex_horizontal_integer
            || is_vex_vphminposuw
            || is_vex_vpmovsx
            || is_vex_vpmovzx
            || is_vex_vpextr
            || is_vex_vpinsr
            || is_vbroadcast_scalar || is_vpcmpeqq || is_vpcmpgtq
            || is_vpcmpgtw || is_vpcmpeqb || is_vpcmpeqd
            || is_vpcmpeqw || is_vpcmpgtb || is_vpcmpgtd
            || is_vex_modular_add_sub || is_vex_integer_minmax
            || is_gfni);
        if (is_vpblend) {
            const size_t vex_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[first.encoding.opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const unsigned int l = ((unsigned int)p1 >> 2) & 1u;
            const unsigned int vector_bytes = 16u << l;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const int is_d =
                first.name_id == CDISASM_X86_NAME_VPBLENDD;
            const int is_pd =
                first.name_id == CDISASM_X86_NAME_VBLENDPD;
            const int is_ps =
                first.name_id == CDISASM_X86_NAME_VBLENDPS;
            const int needs_avx2 = is_d
                || (!(is_pd || is_ps) && l != 0u);
            const cdisasm_x86_form_id base_form = is_d
                ? UINT16_C(6306)
                : is_pd ? UINT16_C(3527)
                : is_ps ? UINT16_C(3531) : UINT16_C(6338);
            const uint8_t expected_opcode = is_d
                ? UINT8_C(0x02)
                : is_pd ? UINT8_C(0x0d)
                : is_ps ? UINT8_C(0x0c) : UINT8_C(0x0e);

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(3));
            invariant((p1 & UINT8_C(3)) == UINT8_C(1));
            invariant(!is_d || (p1 & UINT8_C(0x80)) == 0u);
            invariant(opcode == expected_opcode);
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                base_form + 2u * l + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 4u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].size == vector_bytes);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[0].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].size == vector_bytes);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[1].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[2].type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(first.opcode[2].size == vector_bytes);
            invariant(first.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[2].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
            invariant(first.opcode[3].size == 1u);
            invariant(first.opcode[3].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[3].flags == 0u);
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_offset[0]
                == first_size - 1u);
            invariant(first.opcode[3].imm
                == code[first.encoding.immediate_offset[0]]);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(cdisasm_instruction_has_x86_group(
                &first,CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags,CDISASM_X86_DECODE_BIT_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first,CDISASM_X86_GROUP_AVX2) == needs_avx2);
            invariant(!needs_avx2
                || cdisasm_decode_flags_test_bit(
                    decode_flags,CDISASM_X86_DECODE_BIT_AVX2));
        }
        if (is_vex_vdpp) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const size_t vex_offset = opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int packed_single =
                first.name_id == CDISASM_X86_NAME_VDPPS;
            const unsigned int l = ((unsigned int)p1 >> 2) & 1u;
            const unsigned int vector_bytes = 16u << l;
            const cdisasm_x86_reg_id register_base = l != 0u
                ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            unsigned int source1 = ((unsigned int)(~p1) >> 3) & 15u;
            const unsigned int destination =
                (((unsigned int)modrm >> 3) & 7u)
                | ((mode == CDISASM_MODE_64
                        && (p0 & UINT8_C(0x80)) == 0u)
                    ? 8u : 0u);
            const unsigned int source2 = ((unsigned int)modrm & 7u)
                | ((mode == CDISASM_MODE_64
                        && (p0 & UINT8_C(0x20)) == 0u)
                    ? 8u : 0u);
            const cdisasm_x86_form_id base_form = packed_single
                ? (cdisasm_x86_form_id)(UINT16_C(4515) + 2u * l)
                : UINT16_C(4507);
            size_t operand_index;

            if (mode != CDISASM_MODE_64) {
                source1 &= 7u;
            }
            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(3));
            invariant((p1 & UINT8_C(3)) == UINT8_C(1));
            invariant(packed_single || l == 0u);
            invariant(opcode == (packed_single
                ? UINT8_C(0x40) : UINT8_C(0x41)));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                base_form + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 4u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant(first.encoding.prefix_size >= 3u);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_size[0] == 1u);
            invariant(first.encoding.immediate_offset[0]
                == first.opcode_size - 1u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 3u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 2u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == vector_bytes);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= register_base);
                    invariant(operand->reg <= register_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= register_base + 7u);
                    }
                }
            }
            invariant(first.opcode[0].reg
                == (cdisasm_x86_reg_id)(register_base + destination));
            invariant(first.opcode[1].reg
                == (cdisasm_x86_reg_id)(register_base + source1));
            invariant(!register_form || first.opcode[2].reg
                == (cdisasm_x86_reg_id)(register_base + source2));
            invariant(first.opcode[3].type
                == CDISASM_OPERAND_IMMEDIATE);
            invariant(first.opcode[3].size == 1u);
            invariant(first.opcode[3].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[3].flags == 0u);
            invariant(first.opcode[3].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[3].imm
                == code[first.encoding.immediate_offset[0]]);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vmxcsr) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const uint8_t control = code[opcode_offset - 1u];
            const uint8_t modrm = first.encoding.modrm;
            const int vex2 = code[opcode_offset - 2u] == UINT8_C(0xc5);
            const int load = first.name_id == CDISASM_X86_NAME_VLDMXCSR;

            invariant(first.form_id == (load
                ? UINT16_C(5585) : UINT16_C(8752)));
            invariant(first.operand_count == 1u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant(first.encoding.prefix_size >= (vex2 ? 2u : 3u));
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            invariant(code[opcode_offset] == UINT8_C(0xae));
            invariant((control & UINT8_C(0x7f)) == UINT8_C(0x78));
            invariant(vex2
                || (code[opcode_offset - 3u] == UINT8_C(0xc4)
                    && (code[opcode_offset - 2u] & UINT8_C(0x1f))
                        == UINT8_C(1)));
            invariant((modrm & UINT8_C(0xc0)) != UINT8_C(0xc0));
            invariant(((modrm >> 3) & UINT8_C(7))
                == (load ? UINT8_C(2) : UINT8_C(3)));
            invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
            invariant(first.opcode[0].size == 4u);
            invariant(first.opcode[0].access == (load
                ? CDISASM_OPERAND_ACCESS_READ
                : CDISASM_OPERAND_ACCESS_WRITE));
            invariant((first.opcode[0].flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
            invariant(first.opcode[0].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vmaskmov) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const size_t vex_offset = opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int pd = (opcode & UINT8_C(1)) != 0u;
            const int store = opcode >= UINT8_C(0x2e);
            const unsigned int vector_bytes =
                (p1 & UINT8_C(4)) != 0u ? 32u : 16u;
            const cdisasm_x86_reg_id register_base = vector_bytes == 16u
                ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
            const size_t memory_index = store ? 0u : 2u;
            const size_t data_index = store ? 2u : 0u;
            unsigned int mask_index = ((unsigned int)(~p1) >> 3) & 15u;
            unsigned int data_register = (modrm >> 3) & 7u;
            cdisasm_x86_form_id expected_form;
            size_t operand_index;

            if (mode == CDISASM_MODE_64) {
                data_register |= (p0 & UINT8_C(0x80)) == 0u ? 8u : 0u;
            } else {
                mask_index &= 7u;
            }
            if (opcode == UINT8_C(0x2c)) {
                expected_form = vector_bytes == 16u
                    ? UINT16_C(5593) : UINT16_C(5594);
            } else if (opcode == UINT8_C(0x2d)) {
                expected_form = vector_bytes == 16u
                    ? UINT16_C(5589) : UINT16_C(5590);
            } else if (opcode == UINT8_C(0x2e)) {
                expected_form = vector_bytes == 16u
                    ? UINT16_C(5591) : UINT16_C(5592);
            } else {
                expected_form = vector_bytes == 16u
                    ? UINT16_C(5587) : UINT16_C(5588);
            }

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(2));
            invariant((p1 & UINT8_C(0x83)) == UINT8_C(1));
            invariant(opcode >= UINT8_C(0x2c)
                && opcode <= UINT8_C(0x2f));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant((modrm & UINT8_C(0xc0)) != UINT8_C(0xc0));
            invariant(first.name_id == (pd
                ? CDISASM_X86_NAME_VMASKMOVPD
                : CDISASM_X86_NAME_VMASKMOVPS));
            invariant(first.form_id == expected_form);
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant(first.encoding.prefix_size >= 3u);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 3u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = operand_index == memory_index;
                const cdisasm_operand_access expected_access = memory
                    ? (store ? CDISASM_OPERAND_ACCESS_WRITE
                             : CDISASM_OPERAND_ACCESS_READ)
                    : (operand_index == data_index && !store
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ);

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == vector_bytes);
                invariant(operand->access == expected_access);
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= register_base);
                    invariant(operand->reg <= register_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= register_base + 7u);
                    }
                }
            }
            invariant(first.opcode[1].reg
                == register_base + mask_index);
            invariant(first.opcode[data_index].reg
                == register_base + data_register);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vpmaskmov) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const size_t vex_offset = opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int load = opcode == UINT8_C(0x8c);
            const unsigned int w = ((unsigned int)p1 >> 7) & 1u;
            const unsigned int l = ((unsigned int)p1 >> 2) & 1u;
            const unsigned int vector_bytes = 16u << l;
            const cdisasm_x86_reg_id register_base = l != 0u
                ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
            const size_t memory_index = load ? 2u : 0u;
            const size_t data_index = load ? 0u : 2u;
            unsigned int mask_index = ((unsigned int)(~p1) >> 3) & 15u;
            unsigned int data_register = (modrm >> 3) & 7u;
            const cdisasm_x86_form_id expected_form =
                (cdisasm_x86_form_id)((load
                    ? (w != 0u ? UINT16_C(7158) : UINT16_C(7154))
                    : (w != 0u ? UINT16_C(7156) : UINT16_C(7152))) + l);
            size_t operand_index;

            if (mode == CDISASM_MODE_64) {
                data_register |= (p0 & UINT8_C(0x80)) == 0u ? 8u : 0u;
            } else {
                mask_index &= 7u;
            }
            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(2));
            invariant((p1 & UINT8_C(0x03)) == UINT8_C(1));
            invariant(opcode == UINT8_C(0x8c)
                || opcode == UINT8_C(0x8e));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant((modrm & UINT8_C(0xc0)) != UINT8_C(0xc0));
            invariant(first.name_id == (w != 0u
                ? CDISASM_X86_NAME_VPMASKMOVQ
                : CDISASM_X86_NAME_VPMASKMOVD));
            invariant(first.form_id == expected_form);
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant(first.encoding.prefix_size >= 3u);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 3u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = operand_index == memory_index;
                const cdisasm_operand_access expected_access = memory
                    ? (load ? CDISASM_OPERAND_ACCESS_READ
                            : CDISASM_OPERAND_ACCESS_WRITE)
                    : (operand_index == data_index && load
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ);

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == vector_bytes);
                invariant(operand->access == expected_access);
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                            | CDISASM_OPERAND_FLAG_SIGNED)) == 0u);
                } else {
                    invariant(operand->reg >= register_base);
                    invariant(operand->reg <= register_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= register_base + 7u);
                    }
                }
            }
            invariant(first.opcode[1].reg
                == register_base + mask_index);
            invariant(first.opcode[data_index].reg
                == register_base + data_register);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX2));
        }
        if (is_vblendv || is_vpblendvb) {
            const size_t vex_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t modrm = first.encoding.modrm;
            const unsigned int l = ((unsigned int)p1 >> 2) & 1u;
            const unsigned int vector_bytes = 16u << l;
            const unsigned int selector =
                ((unsigned int)code[first.encoding.selector_offset] >> 4)
                & (mode == CDISASM_MODE_64 ? 15u : 7u);
            const cdisasm_x86_reg_id register_base = l != 0u
                ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const int is_pd =
                first.name_id == CDISASM_X86_NAME_VBLENDVPD;
            const int is_ps =
                first.name_id == CDISASM_X86_NAME_VBLENDVPS;
            const cdisasm_x86_form_id base_form = is_pd
                ? UINT16_C(3535) : is_ps
                    ? UINT16_C(3539) : UINT16_C(6334);
            const uint8_t expected_opcode = is_pd
                ? UINT8_C(0x4b) : is_ps
                    ? UINT8_C(0x4a) : UINT8_C(0x4c);
            const int needs_avx2 = is_vpblendvb && l != 0u;
            unsigned int operand_index;

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(3));
            invariant((p1 & UINT8_C(0x83)) == UINT8_C(1));
            invariant(code[first.encoding.opcode_offset]
                == expected_opcode);
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                base_form + 2u * l
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 4u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset
                == first.encoding.opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset + 1u == first_size);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[2].type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(first.opcode[3].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[3].reg
                == (cdisasm_x86_reg_id)(register_base + selector));
            for (operand_index = 0u; operand_index < 4u;
                 ++operand_index) {
                invariant(first.opcode[operand_index].size == vector_bytes);
                invariant(first.opcode[operand_index].access
                    == (operand_index == 0u
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ));
                invariant(first.opcode[operand_index].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(operand_index == 2u && !register_form
                    || first.opcode[operand_index].flags == 0u);
            }
            invariant(register_form
                || (first.opcode[2].flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                        | CDISASM_OPERAND_FLAG_SIGNED)) == 0u);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2) == needs_avx2);
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
            invariant(!needs_avx2
                || cdisasm_decode_flags_test_bit(
                    decode_flags, CDISASM_X86_DECODE_BIT_AVX2));
        }
        if (is_vpbroadcast) {
            const size_t vex_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[first.encoding.opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const unsigned int l = ((unsigned int)p1 >> 2) & 1u;
            const unsigned int vector_bytes = 16u << l;
            const cdisasm_x86_reg_id destination_base = l != 0u
                ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            cdisasm_x86_name_id expected_name;
            cdisasm_x86_form_id expected_form_id;
            unsigned int scalar_bytes;

            if (opcode == UINT8_C(0x58)) {
                expected_name = CDISASM_X86_NAME_VPBROADCASTD;
                scalar_bytes = 4u;
                expected_form_id = (cdisasm_x86_form_id)(l != 0u
                    ? (register_form ? UINT16_C(6361) : UINT16_C(6360))
                    : (register_form ? UINT16_C(6356) : UINT16_C(6355)));
            } else if (opcode == UINT8_C(0x59)) {
                expected_name = CDISASM_X86_NAME_VPBROADCASTQ;
                scalar_bytes = 8u;
                expected_form_id = (cdisasm_x86_form_id)(l != 0u
                    ? (register_form ? UINT16_C(6380) : UINT16_C(6379))
                    : (register_form ? UINT16_C(6375) : UINT16_C(6374)));
            } else if (opcode == UINT8_C(0x78)) {
                expected_name = CDISASM_X86_NAME_VPBROADCASTB;
                scalar_bytes = 1u;
                expected_form_id = (cdisasm_x86_form_id)(l != 0u
                    ? (register_form ? UINT16_C(6348) : UINT16_C(6347))
                    : (register_form ? UINT16_C(6343) : UINT16_C(6342)));
            } else {
                expected_name = CDISASM_X86_NAME_VPBROADCASTW;
                scalar_bytes = 2u;
                expected_form_id = (cdisasm_x86_form_id)(l != 0u
                    ? (register_form ? UINT16_C(6393) : UINT16_C(6392))
                    : (register_form ? UINT16_C(6388) : UINT16_C(6387)));
            }

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(2));
            invariant((p1 & UINT8_C(0xfb)) == UINT8_C(0x79));
            invariant(opcode == UINT8_C(0x58)
                || opcode == UINT8_C(0x59)
                || opcode == UINT8_C(0x78)
                || opcode == UINT8_C(0x79));
            invariant(first.name_id == expected_name);
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == expected_form_id);
            invariant(first.operand_count == 2u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset
                == first.encoding.opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].reg >= destination_base);
            invariant(first.opcode[0].reg <= destination_base + 15u);
            invariant(first.opcode[0].size == vector_bytes);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[0].flags == 0u);
            invariant(first.opcode[0].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[1].type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(first.opcode[1].size == scalar_bytes);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[1].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(!register_form
                || (first.opcode[1].reg >= CDISASM_X86_REG_XMM0
                    && first.opcode[1].reg <= CDISASM_X86_REG_XMM15
                    && first.opcode[1].flags == 0u));
            invariant(register_form
                || (first.opcode[1].flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX2));
            if (mode != CDISASM_MODE_64) {
                invariant(first.opcode[0].reg <= destination_base + 7u);
                invariant(!register_form
                    || first.opcode[1].reg <= CDISASM_X86_REG_XMM7);
            }
        }
        if (is_vbroadcast128) {
            const size_t vex_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[first.encoding.opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int integer =
                first.name_id == CDISASM_X86_NAME_VBROADCASTI128;

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(2));
            invariant(p1 == UINT8_C(0x7d));
            invariant(opcode == (integer ? UINT8_C(0x5a) : UINT8_C(0x1a)));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant((modrm & UINT8_C(0xc0)) != UINT8_C(0xc0));
            invariant(first.form_id == (integer
                ? UINT16_C(3554) : UINT16_C(3543)));
            invariant(first.operand_count == 2u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset
                == first.encoding.opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].reg >= CDISASM_X86_REG_YMM0);
            invariant(first.opcode[0].reg <= CDISASM_X86_REG_YMM15);
            invariant(first.opcode[0].size == 32u);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[0].flags == 0u);
            invariant(first.opcode[0].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[1].type == CDISASM_OPERAND_MEMORY);
            invariant(first.opcode[1].size == 16u);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant((first.opcode[1].flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
            invariant(first.opcode[1].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2) == integer);
            invariant(cdisasm_decode_flags_test_bit(decode_flags,
                integer ? CDISASM_X86_DECODE_BIT_AVX2
                        : CDISASM_X86_DECODE_BIT_AVX));
            if (mode != CDISASM_MODE_64) {
                invariant(first.opcode[0].reg <= CDISASM_X86_REG_YMM7);
            }
        }
        if (is_vex_lane128) {
            const size_t vex_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[first.encoding.opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const int extract =
                first.name_id == CDISASM_X86_NAME_VEXTRACTF128
                || first.name_id == CDISASM_X86_NAME_VEXTRACTI128;
            const int integer =
                first.name_id == CDISASM_X86_NAME_VEXTRACTI128
                || first.name_id == CDISASM_X86_NAME_VINSERTI128;
            const size_t lane_index = extract ? 0u : 2u;
            const size_t immediate_index = extract ? 2u : 3u;
            const cdisasm_x86_form_id base_form =
                first.name_id == CDISASM_X86_NAME_VEXTRACTF128
                ? UINT16_C(4539)
                : first.name_id == CDISASM_X86_NAME_VEXTRACTI128
                    ? UINT16_C(4553)
                    : first.name_id == CDISASM_X86_NAME_VINSERTF128
                        ? UINT16_C(5551) : UINT16_C(5565);
            const uint8_t expected_opcode = extract
                ? (integer ? UINT8_C(0x39) : UINT8_C(0x19))
                : (integer ? UINT8_C(0x38) : UINT8_C(0x18));
            size_t operand_index;

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(3));
            invariant((p1 & UINT8_C(0x87)) == UINT8_C(0x05));
            invariant(!extract || p1 == UINT8_C(0x7d));
            invariant(opcode == expected_opcode);
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                base_form + (register_form ? 1u : 0u)));
            invariant(first.operand_count == (extract ? 3u : 4u));
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset
                == first.encoding.opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_size[0] == 1u);
            invariant(first.encoding.immediate_offset[0]
                == first.opcode_size - 1u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < immediate_index;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const unsigned int expected_size =
                    operand_index == lane_index ? 16u : 32u;
                const cdisasm_x86_reg_id register_base =
                    expected_size == 16u
                    ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;

                invariant(operand->type
                    == (!register_form && operand_index == lane_index
                        ? CDISASM_OPERAND_MEMORY
                        : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == expected_size);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (operand->type == CDISASM_OPERAND_REGISTER) {
                    invariant(operand->reg >= register_base);
                    invariant(operand->reg <= register_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= register_base + 7u);
                    }
                } else {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                }
            }
            invariant(first.opcode[immediate_index].type
                == CDISASM_OPERAND_IMMEDIATE);
            invariant(first.opcode[immediate_index].size == 1u);
            invariant(first.opcode[immediate_index].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[immediate_index].flags == 0u);
            invariant(first.opcode[immediate_index].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2) == integer);
            invariant(cdisasm_decode_flags_test_bit(decode_flags,
                integer ? CDISASM_X86_DECODE_BIT_AVX2
                        : CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_ps_lane) {
            const size_t vex_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[first.encoding.opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const int extract =
                first.name_id == CDISASM_X86_NAME_VEXTRACTPS;
            const size_t variable_index = extract ? 0u : 2u;
            const size_t immediate_index = extract ? 2u : 3u;
            const cdisasm_x86_form_id expected_form = extract
                ? (register_form ? UINT16_C(4567) : UINT16_C(4569))
                : (register_form ? UINT16_C(5580) : UINT16_C(5579));
            size_t operand_index;

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(3));
            invariant((p1 & UINT8_C(0x07)) == UINT8_C(0x01));
            invariant(!extract
                || (p1 & UINT8_C(0x78)) == UINT8_C(0x78));
            invariant(opcode == (extract
                ? UINT8_C(0x17) : UINT8_C(0x21)));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == expected_form);
            invariant(first.operand_count == (extract ? 3u : 4u));
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset
                == first.encoding.opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_size[0] == 1u);
            invariant(first.encoding.immediate_offset[0]
                == first.opcode_size - 1u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < immediate_index;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == variable_index;
                const int gpr = extract && register_form
                    && operand_index == 0u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == (memory || gpr ? 4u : 16u));
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else if (gpr) {
                    invariant(operand->reg >= CDISASM_X86_REG_EAX);
                    invariant(operand->reg <= CDISASM_X86_REG_R15D);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= CDISASM_X86_REG_EDI);
                    }
                } else {
                    invariant(operand->reg >= CDISASM_X86_REG_XMM0);
                    invariant(operand->reg <= CDISASM_X86_REG_XMM15);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= CDISASM_X86_REG_XMM7);
                    }
                }
            }
            invariant(first.opcode[immediate_index].type
                == CDISASM_OPERAND_IMMEDIATE);
            invariant(first.opcode[immediate_index].size == 1u);
            invariant(first.opcode[immediate_index].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[immediate_index].flags == 0u);
            invariant(first.opcode[immediate_index].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_perm2_128) {
            const size_t vex_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[first.encoding.opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const int integer =
                first.name_id == CDISASM_X86_NAME_VPERM2I128;
            const cdisasm_x86_form_id base_form = integer
                ? UINT16_C(6772) : UINT16_C(6770);
            size_t operand_index;

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(3));
            invariant((p1 & UINT8_C(0x87)) == UINT8_C(0x05));
            invariant(opcode == (integer
                ? UINT8_C(0x46) : UINT8_C(0x06)));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                base_form + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 4u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset
                == first.encoding.opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_size[0] == 1u);
            invariant(first.encoding.immediate_offset[0]
                == first.opcode_size - 1u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 3u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 2u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == 32u);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= CDISASM_X86_REG_YMM0);
                    invariant(operand->reg <= CDISASM_X86_REG_YMM15);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= CDISASM_X86_REG_YMM7);
                    }
                }
            }
            invariant(first.opcode[3].type
                == CDISASM_OPERAND_IMMEDIATE);
            invariant(first.opcode[3].size == 1u);
            invariant(first.opcode[3].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[3].flags == 0u);
            invariant(first.opcode[3].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2) == integer);
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, integer
                    ? CDISASM_X86_DECODE_BIT_AVX2
                    : CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_permd_vpermps) {
            const size_t vex_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[first.encoding.opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const int integer =
                first.name_id == CDISASM_X86_NAME_VPERMD;
            const cdisasm_x86_form_id base_form = integer
                ? UINT16_C(6780) : UINT16_C(6886);
            size_t operand_index;

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(2));
            invariant((p1 & UINT8_C(0x87)) == UINT8_C(0x05));
            invariant(opcode == (integer
                ? UINT8_C(0x36) : UINT8_C(0x16)));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                base_form + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset
                == first.encoding.opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 3u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 2u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == 32u);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= CDISASM_X86_REG_YMM0);
                    invariant(operand->reg <= CDISASM_X86_REG_YMM15);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= CDISASM_X86_REG_YMM7);
                    }
                }
            }
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX2));
        }
        if (is_vex_vpermpd_vpermq) {
            const size_t vex_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[first.encoding.opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const int floating =
                first.name_id == CDISASM_X86_NAME_VPERMPD;
            const cdisasm_x86_form_id base_form = floating
                ? UINT16_C(6878) : UINT16_C(6890);
            size_t operand_index;

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(3));
            invariant(p1 == UINT8_C(0xfd));
            invariant(opcode == (floating
                ? UINT8_C(0x01) : UINT8_C(0x00)));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                base_form + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset
                == first.encoding.opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_size[0] == 1u);
            invariant(first.encoding.immediate_offset[0]
                == first.opcode_size - 1u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 2u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 1u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == 32u);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= CDISASM_X86_REG_YMM0);
                    invariant(operand->reg <= CDISASM_X86_REG_YMM15);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= CDISASM_X86_REG_YMM7);
                    }
                }
            }
            invariant(first.opcode[2].type
                == CDISASM_OPERAND_IMMEDIATE);
            invariant(first.opcode[2].size == 1u);
            invariant(first.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[2].flags == 0u);
            invariant(first.opcode[2].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX2));
        }
        if (is_vex_vpermilpd_vpermilps) {
            const size_t vex_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[first.encoding.opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const uint8_t map = p0 & UINT8_C(0x1f);
            const int immediate_form = map == UINT8_C(3);
            const int double_form =
                first.name_id == CDISASM_X86_NAME_VPERMILPD;
            const unsigned int vector_bytes =
                (p1 & UINT8_C(4)) != 0u ? 32u : 16u;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const cdisasm_x86_form_id base_form = double_form
                ? UINT16_C(6834) : UINT16_C(6854);
            const size_t memory_index = immediate_form ? 1u : 2u;
            size_t operand_index;

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant(map == UINT8_C(2) || map == UINT8_C(3));
            invariant((p1 & UINT8_C(0x83)) == UINT8_C(1));
            invariant(!immediate_form
                || (p1 & UINT8_C(0x78)) == UINT8_C(0x78));
            invariant(opcode == (double_form
                ? (immediate_form ? UINT8_C(0x05) : UINT8_C(0x0d))
                : (immediate_form ? UINT8_C(0x04) : UINT8_C(0x0c))));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                base_form + (immediate_form ? 0u : 2u)
                + (vector_bytes == 32u ? 12u : 0u)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset
                == first.encoding.opcode_offset + 1u);
            invariant(first.encoding.immediate_count
                == (immediate_form ? 1u : 0u));
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u;
                 operand_index < (immediate_form ? 2u : 3u);
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == memory_index;
                const cdisasm_x86_reg_id register_base =
                    vector_bytes == 16u
                    ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == vector_bytes);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= register_base);
                    invariant(operand->reg <= register_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= register_base + 7u);
                    }
                }
            }
            if (immediate_form) {
                invariant(first.encoding.immediate_size[0] == 1u);
                invariant(first.encoding.immediate_offset[0]
                    == first.opcode_size - 1u);
                invariant(first.opcode[2].type
                    == CDISASM_OPERAND_IMMEDIATE);
                invariant(first.opcode[2].size == 1u);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].flags == 0u);
                invariant(first.opcode[2].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
            }
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vcmp) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const int vex3 = opcode_offset >= 3u
                && code[opcode_offset - 3u] == UINT8_C(0xc4);
            const size_t vex_offset = opcode_offset - (vex3 ? 3u : 2u);
            const uint8_t p0 = vex3
                ? code[vex_offset + 1u] : UINT8_C(0);
            const uint8_t p1 = code[opcode_offset - 1u];
            const uint8_t prefix = p1 & UINT8_C(3);
            const uint8_t modrm = first.encoding.modrm;
            const int scalar = prefix >= UINT8_C(2);
            const int double_form = prefix == UINT8_C(1)
                || prefix == UINT8_C(3);
            const unsigned int vector_bytes = scalar ? 16u
                : ((p1 & UINT8_C(4)) != 0u ? 32u : 16u);
            const unsigned int scalar_bytes = double_form ? 8u : 4u;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const cdisasm_x86_form_id base_form = prefix == UINT8_C(0)
                ? UINT16_C(3611)
                : prefix == UINT8_C(1) ? UINT16_C(3595)
                : prefix == UINT8_C(2) ? UINT16_C(3623)
                                        : UINT16_C(3617);
            const cdisasm_x86_name_id expected_name = prefix == UINT8_C(0)
                ? CDISASM_X86_NAME_VCMPPS
                : prefix == UINT8_C(1) ? CDISASM_X86_NAME_VCMPPD
                : prefix == UINT8_C(2) ? CDISASM_X86_NAME_VCMPSS
                                        : CDISASM_X86_NAME_VCMPSD;
            const cdisasm_x86_reg_id register_base = vector_bytes == 32u
                ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
            const unsigned int encoded_source =
                (((unsigned int)(~p1) >> 3) & 15u)
                & (mode == CDISASM_MODE_64 ? 15u : 7u);
            size_t operand_index;

            invariant(code[vex_offset] == (vex3
                ? UINT8_C(0xc4) : UINT8_C(0xc5)));
            invariant(!vex3
                || (p0 & UINT8_C(0x1f)) == UINT8_C(1));
            invariant(code[opcode_offset] == UINT8_C(0xc2));
            invariant(mode == CDISASM_MODE_64
                || (vex3
                    ? (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0)
                    : (p1 & UINT8_C(0xc0)) == UINT8_C(0xc0)));
            invariant(first.name_id == expected_name);
            invariant(first.form_id == (cdisasm_x86_form_id)(base_form
                + (!scalar && vector_bytes == 32u ? 2u : 0u)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 4u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant(first.encoding.prefix_size >= 2u);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_size[0] == 1u);
            invariant(first.encoding.immediate_offset[0]
                == first.opcode_size - 1u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 3u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 2u;
                const unsigned int expected_size = scalar
                        && operand_index == 2u
                    ? scalar_bytes : vector_bytes;
                const cdisasm_x86_reg_id operand_base = scalar
                    ? CDISASM_X86_REG_XMM0 : register_base;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == expected_size);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= operand_base);
                    invariant(operand->reg <= operand_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= operand_base + 7u);
                    }
                }
            }
            invariant((unsigned int)first.opcode[1].reg
                    - (unsigned int)(scalar
                        ? CDISASM_X86_REG_XMM0 : register_base)
                == encoded_source);
            invariant(((unsigned int)first.opcode[0].reg
                    - (unsigned int)register_base) % 8u
                == ((unsigned int)modrm >> 3) % 8u);
            invariant(!register_form
                || ((unsigned int)first.opcode[2].reg
                        - (unsigned int)(scalar
                            ? CDISASM_X86_REG_XMM0 : register_base)) % 8u
                    == (unsigned int)modrm % 8u);
            invariant(first.opcode[3].type
                == CDISASM_OPERAND_IMMEDIATE);
            invariant(first.opcode[3].size == 1u);
            invariant(first.opcode[3].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[3].flags == 0u);
            invariant(first.opcode[3].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[3].imm <= UINT8_MAX);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vround) {
            const size_t vex_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[first.encoding.opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int scalar = opcode >= UINT8_C(0x0a);
            const int double_form = (opcode & UINT8_C(1)) != 0u;
            const unsigned int vector_bytes = scalar ? 16u
                : ((p1 & UINT8_C(4)) != 0u ? 32u : 16u);
            const unsigned int scalar_bytes = double_form ? 8u : 4u;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const cdisasm_x86_form_id base_form = scalar
                ? (double_form ? UINT16_C(8547) : UINT16_C(8549))
                : (double_form ? UINT16_C(8539) : UINT16_C(8543));
            const size_t source_index = scalar ? 2u : 1u;
            const size_t immediate_index = scalar ? 3u : 2u;
            cdisasm_x86_name_id expected_name;
            size_t operand_index;

            if (opcode == UINT8_C(0x08)) {
                expected_name = CDISASM_X86_NAME_VROUNDPS;
            } else if (opcode == UINT8_C(0x09)) {
                expected_name = CDISASM_X86_NAME_VROUNDPD;
            } else if (opcode == UINT8_C(0x0a)) {
                expected_name = CDISASM_X86_NAME_VROUNDSS;
            } else {
                expected_name = CDISASM_X86_NAME_VROUNDSD;
            }

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(3));
            invariant((p1 & UINT8_C(3)) == UINT8_C(1));
            invariant(opcode >= UINT8_C(0x08)
                && opcode <= UINT8_C(0x0b));
            invariant(scalar
                || (p1 & UINT8_C(0x78)) == UINT8_C(0x78));
            invariant(first.name_id == expected_name);
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == (cdisasm_x86_form_id)(base_form
                + (!scalar && vector_bytes == 32u ? 2u : 0u)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == (scalar ? 4u : 3u));
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.prefix_size >= 3u);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset
                == first.encoding.opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_size[0] == 1u);
            invariant(first.encoding.immediate_offset[0]
                == first.opcode_size - 1u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u;
                 operand_index < immediate_index;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == source_index;
                const unsigned int expected_size = scalar
                        && operand_index == source_index
                    ? scalar_bytes : vector_bytes;
                const cdisasm_x86_reg_id register_base = scalar
                    ? CDISASM_X86_REG_XMM0
                    : (vector_bytes == 16u
                        ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0);

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == expected_size);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= register_base);
                    invariant(operand->reg <= register_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= register_base + 7u);
                    }
                }
            }
            invariant(first.opcode[immediate_index].type
                == CDISASM_OPERAND_IMMEDIATE);
            invariant(first.opcode[immediate_index].size == 1u);
            invariant(first.opcode[immediate_index].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[immediate_index].flags == 0u);
            invariant(first.opcode[immediate_index].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[immediate_index].imm <= UINT8_MAX);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vshuf) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const int two_byte = opcode_offset >= 2u
                && code[opcode_offset - 2u] == UINT8_C(0xc5);
            const size_t vex_offset = opcode_offset - (two_byte ? 2u : 3u);
            const uint8_t p1 = code[opcode_offset - 1u];
            const uint8_t modrm = first.encoding.modrm;
            const int double_form = (p1 & UINT8_C(3)) == UINT8_C(1);
            const unsigned int vector_bytes =
                (p1 & UINT8_C(4)) != 0u ? 32u : 16u;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const cdisasm_x86_form_id base_form = double_form
                ? UINT16_C(8664) : UINT16_C(8674);
            const cdisasm_x86_reg_id register_base = vector_bytes == 16u
                ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
            size_t operand_index;

            invariant(code[vex_offset] == (two_byte
                ? UINT8_C(0xc5) : UINT8_C(0xc4)));
            if (!two_byte) {
                const uint8_t p0 = code[vex_offset + 1u];

                invariant((p0 & UINT8_C(0x1f)) == UINT8_C(1));
                invariant(mode == CDISASM_MODE_64
                    || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            } else if (mode != CDISASM_MODE_64) {
                invariant((p1 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            }
            invariant((p1 & UINT8_C(3)) <= UINT8_C(1));
            invariant(code[opcode_offset] == UINT8_C(0xc6));
            invariant(first.name_id == (double_form
                ? CDISASM_X86_NAME_VSHUFPD
                : CDISASM_X86_NAME_VSHUFPS));
            invariant(first.form_id == (cdisasm_x86_form_id)(base_form
                + (vector_bytes == 32u ? 6u : 0u)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 4u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.prefix_size >= (two_byte ? 2u : 3u));
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_size[0] == 1u);
            invariant(first.encoding.immediate_offset[0]
                == first.opcode_size - 1u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 3u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 2u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == vector_bytes);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= register_base);
                    invariant(operand->reg <= register_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= register_base + 7u);
                    }
                }
            }
            invariant(first.opcode[3].type
                == CDISASM_OPERAND_IMMEDIATE);
            invariant(first.opcode[3].size == 1u);
            invariant(first.opcode[3].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[3].flags == 0u);
            invariant(first.opcode[3].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[3].imm <= UINT8_MAX);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vtest) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const size_t vex_offset = opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int double_form = opcode == UINT8_C(0x0f);
            const unsigned int vector_bytes =
                (p1 & UINT8_C(4)) != 0u ? 32u : 16u;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const cdisasm_x86_form_id base_form = double_form
                ? UINT16_C(8795) : UINT16_C(8799);
            const cdisasm_x86_reg_id register_base = vector_bytes == 16u
                ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
            size_t operand_index;

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(2));
            invariant(p1 == UINT8_C(0x79) || p1 == UINT8_C(0x7d));
            invariant(opcode == UINT8_C(0x0e)
                || opcode == UINT8_C(0x0f));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.name_id == (double_form
                ? CDISASM_X86_NAME_VTESTPD
                : CDISASM_X86_NAME_VTESTPS));
            invariant(first.form_id == (cdisasm_x86_form_id)(base_form
                + (vector_bytes == 32u ? 2u : 0u)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 2u);
            invariant((first.opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.prefix_size >= 3u);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 2u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 1u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == vector_bytes);
                invariant(operand->access == CDISASM_OPERAND_ACCESS_READ);
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= register_base);
                    invariant(operand->reg <= register_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= register_base + 7u);
                    }
                }
            }
            invariant(((unsigned int)first.opcode[0].reg
                    - (unsigned int)register_base) % 8u
                == ((unsigned int)modrm >> 3) % 8u);
            invariant(!register_form
                || ((unsigned int)first.opcode[1].reg
                        - (unsigned int)register_base) % 8u
                    == (unsigned int)modrm % 8u);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vptest) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const size_t vex_offset = opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t modrm = first.encoding.modrm;
            const unsigned int vector_bytes =
                (p1 & UINT8_C(4)) != 0u ? 32u : 16u;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const cdisasm_x86_reg_id register_base = vector_bytes == 16u
                ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
            size_t operand_index;

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(2));
            invariant((p1 & UINT8_C(0x7b)) == UINT8_C(0x79));
            invariant(code[opcode_offset] == UINT8_C(0x17));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                UINT16_C(8319) + (vector_bytes == 32u ? 2u : 0u)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 2u);
            invariant((first.opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.prefix_size >= 3u);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 2u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 1u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == vector_bytes);
                invariant(operand->access == CDISASM_OPERAND_ACCESS_READ);
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= register_base);
                    invariant(operand->reg <= register_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= register_base + 7u);
                    }
                }
            }
            invariant(((unsigned int)first.opcode[0].reg
                    - (unsigned int)register_base) % 8u
                == ((unsigned int)modrm >> 3) % 8u);
            invariant(!register_form
                || ((unsigned int)first.opcode[1].reg
                        - (unsigned int)register_base) % 8u
                    == (unsigned int)modrm % 8u);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vcomi) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const int vex3 = opcode_offset >= 3u
                && code[opcode_offset - 3u] == UINT8_C(0xc4);
            const size_t vex_offset = opcode_offset - (vex3 ? 3u : 2u);
            const uint8_t p0 = vex3
                ? code[vex_offset + 1u] : UINT8_C(0);
            const uint8_t p1 = code[opcode_offset - 1u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int ordered = opcode == UINT8_C(0x2f);
            const int double_form = (p1 & UINT8_C(3)) == UINT8_C(1);
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const unsigned int scalar_bytes = double_form ? 8u : 4u;
            const uint8_t encoded_r = vex3 ? p0 : p1;
            const cdisasm_x86_form_id base_form = ordered
                ? (double_form ? UINT16_C(3629) : UINT16_C(3633))
                : (double_form ? UINT16_C(8803) : UINT16_C(8809));
            size_t operand_index;

            invariant(code[vex_offset] == (vex3
                ? UINT8_C(0xc4) : UINT8_C(0xc5)));
            invariant(!vex3
                || (p0 & UINT8_C(0x1f)) == UINT8_C(1));
            invariant((p1 & UINT8_C(0x78)) == UINT8_C(0x78));
            invariant((p1 & UINT8_C(3)) <= UINT8_C(1));
            invariant(opcode == UINT8_C(0x2e)
                || opcode == UINT8_C(0x2f));
            invariant(mode == CDISASM_MODE_64
                || (vex3
                    ? (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0)
                    : (p1 & UINT8_C(0xc0)) == UINT8_C(0xc0)));
            invariant(first.name_id == (ordered
                ? (double_form
                    ? CDISASM_X86_NAME_VCOMISD
                    : CDISASM_X86_NAME_VCOMISS)
                : (double_form
                    ? CDISASM_X86_NAME_VUCOMISD
                    : CDISASM_X86_NAME_VUCOMISS)));
            invariant(first.form_id == (cdisasm_x86_form_id)(base_form
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 2u);
            invariant((first.opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.prefix_size >= 2u);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 2u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 1u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == (operand_index == 0u
                    ? 16u : scalar_bytes));
                invariant(operand->access == CDISASM_OPERAND_ACCESS_READ);
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= CDISASM_X86_REG_XMM0);
                    invariant(operand->reg <= CDISASM_X86_REG_XMM15);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= CDISASM_X86_REG_XMM7);
                    }
                }
            }
            invariant(((unsigned int)first.opcode[0].reg
                    - (unsigned int)CDISASM_X86_REG_XMM0) % 8u
                == ((unsigned int)modrm >> 3) % 8u);
            invariant(first.opcode[0].reg
                == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0
                    + ((modrm >> 3) & UINT8_C(7))
                    + ((mode == CDISASM_MODE_64
                            && (encoded_r & UINT8_C(0x80)) == 0u)
                        ? 8u : 0u)));
            invariant(!register_form
                || ((unsigned int)first.opcode[1].reg
                        - (unsigned int)CDISASM_X86_REG_XMM0) % 8u
                    == (unsigned int)modrm % 8u);
            invariant(!register_form
                || first.opcode[1].reg
                    == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0
                        + (modrm & UINT8_C(7))
                        + ((mode == CDISASM_MODE_64 && vex3
                                && (p0 & UINT8_C(0x20)) == 0u)
                            ? 8u : 0u)));
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vunpck) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const int vex3 = opcode_offset >= 3u
                && code[opcode_offset - 3u] == UINT8_C(0xc4);
            const size_t vex_offset = opcode_offset - (vex3 ? 3u : 2u);
            const uint8_t p0 = vex3
                ? code[vex_offset + 1u] : UINT8_C(0);
            const uint8_t p1 = code[opcode_offset - 1u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int double_form = (p1 & UINT8_C(3)) == UINT8_C(1);
            const int high_half = opcode == UINT8_C(0x15);
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const unsigned int vector_bytes =
                (p1 & UINT8_C(4)) != 0u ? 32u : 16u;
            const cdisasm_x86_reg_id register_base = vector_bytes == 16u
                ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
            const uint8_t encoded_r = vex3 ? p0 : p1;
            unsigned int source_index =
                ((unsigned int)(~p1) >> 3) & 15u;
            cdisasm_x86_form_id base_form;
            cdisasm_x86_name_id expected_name;
            size_t operand_index;

            if (mode != CDISASM_MODE_64) {
                source_index &= 7u;
            }
            if (high_half) {
                base_form = double_form
                    ? UINT16_C(8825) : UINT16_C(8835);
                expected_name = double_form
                    ? CDISASM_X86_NAME_VUNPCKHPD
                    : CDISASM_X86_NAME_VUNPCKHPS;
            } else {
                base_form = double_form
                    ? UINT16_C(8845) : UINT16_C(8855);
                expected_name = double_form
                    ? CDISASM_X86_NAME_VUNPCKLPD
                    : CDISASM_X86_NAME_VUNPCKLPS;
            }

            invariant(code[vex_offset] == (vex3
                ? UINT8_C(0xc4) : UINT8_C(0xc5)));
            invariant(!vex3
                || (p0 & UINT8_C(0x1f)) == UINT8_C(1));
            invariant((p1 & UINT8_C(3)) <= UINT8_C(1));
            invariant(opcode == UINT8_C(0x14)
                || opcode == UINT8_C(0x15));
            invariant(mode == CDISASM_MODE_64
                || (vex3
                    ? (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0)
                    : (p1 & UINT8_C(0xc0)) == UINT8_C(0xc0)));
            invariant(first.name_id == expected_name);
            invariant(first.form_id == (cdisasm_x86_form_id)(base_form
                + (vector_bytes == 32u ? 6u : 0u)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.prefix_size >= (vex3 ? 3u : 2u));
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 3u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 2u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == vector_bytes);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= register_base);
                    invariant(operand->reg <= register_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= register_base + 7u);
                    }
                }
            }
            invariant(first.opcode[0].reg
                == (cdisasm_x86_reg_id)(register_base
                    + ((modrm >> 3) & UINT8_C(7))
                    + ((mode == CDISASM_MODE_64
                            && (encoded_r & UINT8_C(0x80)) == 0u)
                        ? 8u : 0u)));
            invariant(first.opcode[1].reg
                == (cdisasm_x86_reg_id)(register_base + source_index));
            invariant(!register_form
                || first.opcode[2].reg
                    == (cdisasm_x86_reg_id)(register_base
                        + (modrm & UINT8_C(7))
                        + ((mode == CDISASM_MODE_64 && vex3
                                && (p0 & UINT8_C(0x20)) == 0u)
                            ? 8u : 0u)));
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(first.x86_group_count == 1u
                || first.x86_group_count == 2u);
            invariant(first.x86_group_ids[first.x86_group_count - 1u]
                == CDISASM_X86_GROUP_AVX);
            invariant(first.x86_group_count == 1u
                || first.x86_group_ids[0] == CDISASM_X86_GROUP_I386
                || first.x86_group_ids[0] == CDISASM_X86_GROUP_AMD64);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_horizontal_integer) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const size_t vex_offset = opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const unsigned int vector_bytes =
                (p1 & UINT8_C(4)) != 0u ? 32u : 16u;
            const cdisasm_x86_reg_id register_base = vector_bytes == 16u
                ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
            const uint8_t encoded_r = p0;
            unsigned int source_index =
                ((unsigned int)(~p1) >> 3) & 15u;
            cdisasm_x86_form_id base_form = 0u;
            cdisasm_x86_name_id expected_name = CDISASM_X86_NAME_NONE;
            size_t operand_index;

            if (mode != CDISASM_MODE_64) {
                source_index &= 7u;
            }

            switch (opcode) {
                case 0x02:
                    base_form = UINT16_C(7012);
                    expected_name = CDISASM_X86_NAME_VPHADDD;
                    break;
                case 0x03:
                    base_form = UINT16_C(7016);
                    expected_name = CDISASM_X86_NAME_VPHADDSW;
                    break;
                case 0x01:
                    base_form = UINT16_C(7036);
                    expected_name = CDISASM_X86_NAME_VPHADDW;
                    break;
                case 0x06:
                    base_form = UINT16_C(7046);
                    expected_name = CDISASM_X86_NAME_VPHSUBD;
                    break;
                case 0x07:
                    base_form = UINT16_C(7050);
                    expected_name = CDISASM_X86_NAME_VPHSUBSW;
                    break;
                case 0x05:
                    base_form = UINT16_C(7056);
                    expected_name = CDISASM_X86_NAME_VPHSUBW;
                    break;
                default:
                    invariant(0);
            }
            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(2));
            invariant((p1 & UINT8_C(3)) == UINT8_C(1));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.name_id == expected_name);
            invariant(first.form_id == (cdisasm_x86_form_id)(base_form
                + (vector_bytes == 32u ? 2u : 0u)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant(first.encoding.prefix_size >= 3u);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 3u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 2u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == vector_bytes);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (!memory) {
                    invariant(operand->reg >= register_base);
                    invariant(operand->reg <= register_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= register_base + 7u);
                    }
                } else {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                }
            }
            invariant(first.opcode[0].reg
                == (cdisasm_x86_reg_id)(register_base
                    + ((modrm >> 3) & UINT8_C(7))
                    + ((mode == CDISASM_MODE_64
                            && (encoded_r & UINT8_C(0x80)) == 0u)
                        ? 8u : 0u)));
            invariant(first.opcode[1].reg
                == (cdisasm_x86_reg_id)(register_base + source_index));
            invariant(!register_form || first.opcode[2].reg
                == (cdisasm_x86_reg_id)(register_base
                    + (modrm & UINT8_C(7))
                    + ((mode == CDISASM_MODE_64
                            && (p0 & UINT8_C(0x20)) == 0u)
                        ? 8u : 0u)));
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant((vector_bytes == 32u)
                == cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, vector_bytes == 32u
                    ? CDISASM_X86_DECODE_BIT_AVX2
                    : CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vpmovsx || is_vex_vpmovzx) {
            static const cdisasm_x86_name_id expected_names[2][6] = {
                {
                    CDISASM_X86_NAME_VPMOVSXBW,
                    CDISASM_X86_NAME_VPMOVSXBD,
                    CDISASM_X86_NAME_VPMOVSXBQ,
                    CDISASM_X86_NAME_VPMOVSXWD,
                    CDISASM_X86_NAME_VPMOVSXWQ,
                    CDISASM_X86_NAME_VPMOVSXDQ
                },
                {
                    CDISASM_X86_NAME_VPMOVZXBW,
                    CDISASM_X86_NAME_VPMOVZXBD,
                    CDISASM_X86_NAME_VPMOVZXBQ,
                    CDISASM_X86_NAME_VPMOVZXWD,
                    CDISASM_X86_NAME_VPMOVZXWQ,
                    CDISASM_X86_NAME_VPMOVZXDQ
                }
            };
            static const uint16_t xmm_memory_forms[2][6] = {
                {7419, 7399, 7409, 7439, 7449, 7429},
                {7524, 7504, 7514, 7544, 7554, 7534}
            };
            static const uint16_t ymm_memory_forms[2][6] = {
                {7425, 7405, 7415, 7445, 7455, 7435},
                {7530, 7510, 7520, 7550, 7560, 7540}
            };
            static const uint8_t xmm_source_sizes[6] = {
                8, 4, 2, 8, 4, 8
            };
            const size_t opcode_offset = first.encoding.opcode_offset;
            const size_t vex_offset = opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const unsigned int l = ((unsigned int)p1 >> 2) & 1u;
            const unsigned int vector_size = 16u << l;
            const unsigned int unsigned_family =
                is_vex_vpmovzx != 0;
            const uint8_t first_opcode = unsigned_family != 0u
                ? UINT8_C(0x30) : UINT8_C(0x20);
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const cdisasm_x86_reg_id destination_base = l != 0u
                ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
            const cdisasm_opcode *destination = &first.opcode[0];
            const cdisasm_opcode *source = &first.opcode[1];
            unsigned int family;
            unsigned int source_size;
            cdisasm_x86_form_id expected_form;

            invariant(opcode_offset >= 3u);
            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(2));
            invariant((p1 & UINT8_C(0x7b)) == UINT8_C(0x79));
            invariant(opcode >= first_opcode
                && opcode <= first_opcode + UINT8_C(5));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));

            family = (unsigned int)opcode - first_opcode;
            source_size = (unsigned int)xmm_source_sizes[family] << l;
            expected_form = (cdisasm_x86_form_id)((l != 0u
                    ? ymm_memory_forms[unsigned_family][family]
                    : xmm_memory_forms[unsigned_family][family])
                + (register_form ? 1u : 0u));
            invariant(first.name_id
                == expected_names[unsigned_family][family]);
            invariant(first.form_id == expected_form);
            invariant(first.operand_count == 2u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant(first.encoding.prefix_size >= 3u);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.modrm_offset < first_size);
            invariant(code[first.encoding.modrm_offset] == modrm);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            invariant(destination->type == CDISASM_OPERAND_REGISTER);
            invariant(destination->reg >= destination_base);
            invariant(destination->reg <= destination_base + 15u);
            invariant(destination->size == vector_size);
            invariant(destination->access == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(destination->flags == 0u);
            invariant(destination->broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(source->type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(source->size == source_size);
            invariant(source->access == CDISASM_OPERAND_ACCESS_READ);
            invariant(source->broadcast == CDISASM_X86_BROADCAST_NONE);
            if (register_form) {
                invariant(source->reg >= CDISASM_X86_REG_XMM0);
                invariant(source->reg <= CDISASM_X86_REG_XMM15);
                invariant(source->flags == 0u);
                invariant(first.encoding.sib_offset == 0u);
                invariant(first.encoding.displacement_offset == 0u);
                invariant(first.encoding.displacement_size == 0u);
            } else {
                invariant((source->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
            }
            if (mode != CDISASM_MODE_64) {
                invariant(destination->reg <= destination_base + 7u);
                invariant(!register_form
                    || source->reg <= CDISASM_X86_REG_XMM7);
            }
            invariant(destination->reg == (cdisasm_x86_reg_id)(
                destination_base
                + ((modrm >> 3) & UINT8_C(7))
                + ((mode == CDISASM_MODE_64
                        && (p0 & UINT8_C(0x80)) == 0u)
                    ? 8u : 0u)));
            invariant(!register_form || source->reg
                == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0
                    + (modrm & UINT8_C(7))
                    + ((mode == CDISASM_MODE_64
                            && (p0 & UINT8_C(0x20)) == 0u)
                        ? 8u : 0u)));
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant((l != 0u)
                == cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, l != 0u
                    ? CDISASM_X86_DECODE_BIT_AVX2
                    : CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vphminposuw) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const size_t vex_offset = opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t modrm = first.encoding.modrm;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            size_t operand_index;

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(2));
            invariant((p1 & UINT8_C(0x7f)) == UINT8_C(0x79));
            invariant(code[opcode_offset] == UINT8_C(0x41));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == (register_form
                ? UINT16_C(7041) : UINT16_C(7040)));
            invariant(first.operand_count == 2u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant(first.encoding.prefix_size >= 3u);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 2u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 1u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == 16u);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (!memory) {
                    invariant(operand->reg >= CDISASM_X86_REG_XMM0);
                    invariant(operand->reg <= CDISASM_X86_REG_XMM15);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= CDISASM_X86_REG_XMM7);
                    }
                } else {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                }
            }
            invariant(first.opcode[0].reg
                == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0
                    + ((modrm >> 3) & UINT8_C(7))
                    + ((mode == CDISASM_MODE_64
                            && (p0 & UINT8_C(0x80)) == 0u)
                        ? 8u : 0u)));
            invariant(!register_form || first.opcode[1].reg
                == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0
                    + (modrm & UINT8_C(7))
                    + ((mode == CDISASM_MODE_64
                            && (p0 & UINT8_C(0x20)) == 0u)
                        ? 8u : 0u)));
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vpextr) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const int vex3 = opcode_offset >= 3u
                && code[opcode_offset - 3u] == UINT8_C(0xc4);
            const size_t vex_offset = opcode_offset - (vex3 ? 3u : 2u);
            const uint8_t p0 = vex3
                ? code[vex_offset + 1u] : UINT8_C(0);
            const uint8_t p1 = code[opcode_offset - 1u];
            const uint8_t map = vex3
                ? p0 & UINT8_C(0x1f) : UINT8_C(1);
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const int map1_c5 = map == UINT8_C(1)
                && opcode == UINT8_C(0xc5);
            const int w = vex3 && (p1 & UINT8_C(0x80)) != 0u;
            const uint8_t encoded_r = vex3 ? p0 : p1;
            cdisasm_x86_name_id expected_name;
            cdisasm_x86_form_id expected_form;
            unsigned int scalar_register_size;
            unsigned int scalar_memory_size;
            cdisasm_x86_reg_id scalar_base;
            const cdisasm_opcode *destination = &first.opcode[0];
            const cdisasm_opcode *source = &first.opcode[1];
            const cdisasm_opcode *immediate = &first.opcode[2];

            if (map1_c5) {
                expected_name = CDISASM_X86_NAME_VPEXTRW;
                expected_form = UINT16_C(6979);
                scalar_register_size = 4u;
                scalar_memory_size = 2u;
            } else if (map == UINT8_C(3)
                && opcode == UINT8_C(0x14)) {
                expected_name = CDISASM_X86_NAME_VPEXTRB;
                expected_form = register_form
                    ? UINT16_C(6966) : UINT16_C(6968);
                scalar_register_size = 4u;
                scalar_memory_size = 1u;
            } else if (map == UINT8_C(3)
                && opcode == UINT8_C(0x15)) {
                expected_name = CDISASM_X86_NAME_VPEXTRW;
                expected_form = register_form
                    ? UINT16_C(6978) : UINT16_C(6983);
                scalar_register_size = 4u;
                scalar_memory_size = 2u;
            } else if (map == UINT8_C(3)
                && opcode == UINT8_C(0x16)
                && w && mode == CDISASM_MODE_64) {
                expected_name = CDISASM_X86_NAME_VPEXTRQ;
                expected_form = register_form
                    ? UINT16_C(6974) : UINT16_C(6976);
                scalar_register_size = 8u;
                scalar_memory_size = 8u;
            } else {
                invariant(map == UINT8_C(3)
                    && opcode == UINT8_C(0x16));
                expected_name = CDISASM_X86_NAME_VPEXTRD;
                expected_form = register_form
                    ? UINT16_C(6970) : UINT16_C(6972);
                scalar_register_size = 4u;
                scalar_memory_size = 4u;
            }
            scalar_base = scalar_register_size == 8u
                ? CDISASM_X86_REG_RAX : CDISASM_X86_REG_EAX;

            invariant(code[vex_offset]
                == (uint8_t)(vex3 ? UINT8_C(0xc4) : UINT8_C(0xc5)));
            invariant((p1 & UINT8_C(0x7f)) == UINT8_C(0x79));
            invariant(!map1_c5 || register_form);
            invariant(mode == CDISASM_MODE_64 || !vex3
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.name_id == expected_name);
            invariant(first.form_id == expected_form);
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant(first.encoding.prefix_size >= (vex3 ? 3u : 2u));
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_size[0] == 1u);
            invariant(first.encoding.immediate_offset[0]
                == first.opcode_size - 1u);
            invariant(first.encoding.selector_offset == 0u);
            invariant(destination->type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(destination->size == (register_form
                ? scalar_register_size : scalar_memory_size));
            invariant(destination->access == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(destination->broadcast
                == CDISASM_X86_BROADCAST_NONE);
            if (register_form) {
                const unsigned int destination_selector = map1_c5
                    ? (modrm >> 3) & UINT8_C(7)
                    : modrm & UINT8_C(7);
                const unsigned int destination_extension =
                    mode == CDISASM_MODE_64
                    && ((map1_c5
                            ? encoded_r & UINT8_C(0x80)
                            : p0 & UINT8_C(0x20)) == 0u)
                        ? 8u : 0u;

                invariant(destination->reg
                    == (cdisasm_x86_reg_id)(scalar_base
                        + destination_selector + destination_extension));
                invariant(destination->flags == 0u);
            } else {
                invariant(!map1_c5);
                invariant((destination->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
            }
            invariant(source->type == CDISASM_OPERAND_REGISTER);
            invariant(source->size == 16u);
            invariant(source->access == CDISASM_OPERAND_ACCESS_READ);
            invariant(source->flags == 0u);
            invariant(source->broadcast == CDISASM_X86_BROADCAST_NONE);
            invariant(source->reg
                == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0
                    + (map1_c5
                        ? modrm & UINT8_C(7)
                        : (modrm >> 3) & UINT8_C(7))
                    + ((mode == CDISASM_MODE_64
                            && ((map1_c5
                                ? vex3 && (p0 & UINT8_C(0x20)) == 0u
                                : (p0 & UINT8_C(0x80)) == 0u)))
                        ? 8u : 0u)));
            if (mode != CDISASM_MODE_64) {
                invariant(source->reg <= CDISASM_X86_REG_XMM7);
            }
            invariant(immediate->type == CDISASM_OPERAND_IMMEDIATE);
            invariant(immediate->size == 1u);
            invariant(immediate->access == CDISASM_OPERAND_ACCESS_READ);
            invariant(immediate->flags == 0u);
            invariant(immediate->broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(immediate->imm
                == code[first.encoding.immediate_offset[0]]);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vpinsr) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const int vex3 = opcode_offset >= 3u
                && code[opcode_offset - 3u] == UINT8_C(0xc4);
            const size_t vex_offset = opcode_offset - (vex3 ? 3u : 2u);
            const uint8_t p0 = vex3
                ? code[vex_offset + 1u] : UINT8_C(0);
            const uint8_t p1 = code[opcode_offset - 1u];
            const uint8_t map = vex3
                ? p0 & UINT8_C(0x1f) : UINT8_C(1);
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const int w = vex3 && (p1 & UINT8_C(0x80)) != 0u;
            const uint8_t encoded_r = vex3 ? p0 : p1;
            unsigned int source_index =
                ((unsigned int)(~p1) >> 3) & 15u;
            cdisasm_x86_name_id expected_name;
            cdisasm_x86_form_id base_form;
            unsigned int scalar_register_size;
            unsigned int scalar_memory_size;
            cdisasm_x86_reg_id scalar_base;
            const cdisasm_opcode *destination = &first.opcode[0];
            const cdisasm_opcode *source = &first.opcode[1];
            const cdisasm_opcode *scalar = &first.opcode[2];
            const cdisasm_opcode *immediate = &first.opcode[3];

            if (mode != CDISASM_MODE_64) {
                source_index &= 7u;
            }
            if (map == UINT8_C(1) && opcode == UINT8_C(0xc4)) {
                expected_name = CDISASM_X86_NAME_VPINSRW;
                base_form = UINT16_C(7072);
                scalar_register_size = 4u;
                scalar_memory_size = 2u;
            } else if (map == UINT8_C(3)
                && opcode == UINT8_C(0x20)) {
                expected_name = CDISASM_X86_NAME_VPINSRB;
                base_form = UINT16_C(7060);
                scalar_register_size = 4u;
                scalar_memory_size = 1u;
            } else if (map == UINT8_C(3)
                && opcode == UINT8_C(0x22)
                && w && mode == CDISASM_MODE_64) {
                expected_name = CDISASM_X86_NAME_VPINSRQ;
                base_form = UINT16_C(7068);
                scalar_register_size = 8u;
                scalar_memory_size = 8u;
            } else {
                invariant(map == UINT8_C(3)
                    && opcode == UINT8_C(0x22));
                expected_name = CDISASM_X86_NAME_VPINSRD;
                base_form = UINT16_C(7064);
                scalar_register_size = 4u;
                scalar_memory_size = 4u;
            }
            scalar_base = scalar_register_size == 8u
                ? CDISASM_X86_REG_RAX : CDISASM_X86_REG_EAX;

            invariant(code[vex_offset]
                == (uint8_t)(vex3 ? UINT8_C(0xc4) : UINT8_C(0xc5)));
            invariant(!vex3 || map == UINT8_C(1) || map == UINT8_C(3));
            invariant((p1 & UINT8_C(7)) == UINT8_C(1));
            invariant(mode == CDISASM_MODE_64 || !vex3
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.name_id == expected_name);
            invariant(first.form_id == (cdisasm_x86_form_id)(base_form
                + (register_form ? 0u : 1u)));
            invariant(first.operand_count == 4u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant(first.encoding.prefix_size >= (vex3 ? 3u : 2u));
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_size[0] == 1u);
            invariant(first.encoding.immediate_offset[0]
                == first.opcode_size - 1u);
            invariant(first.encoding.selector_offset == 0u);
            invariant(destination->type == CDISASM_OPERAND_REGISTER);
            invariant(destination->size == 16u);
            invariant(destination->access == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(destination->reg >= CDISASM_X86_REG_XMM0);
            invariant(destination->reg <= CDISASM_X86_REG_XMM15);
            invariant(destination->flags == 0u);
            invariant(destination->broadcast == CDISASM_X86_BROADCAST_NONE);
            invariant(source->type == CDISASM_OPERAND_REGISTER);
            invariant(source->size == 16u);
            invariant(source->access == CDISASM_OPERAND_ACCESS_READ);
            invariant(source->reg >= CDISASM_X86_REG_XMM0);
            invariant(source->reg <= CDISASM_X86_REG_XMM15);
            invariant(source->flags == 0u);
            invariant(source->broadcast == CDISASM_X86_BROADCAST_NONE);
            if (mode != CDISASM_MODE_64) {
                invariant(destination->reg <= CDISASM_X86_REG_XMM7);
                invariant(source->reg <= CDISASM_X86_REG_XMM7);
            }
            invariant(destination->reg
                == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0
                    + ((modrm >> 3) & UINT8_C(7))
                    + ((mode == CDISASM_MODE_64
                            && (encoded_r & UINT8_C(0x80)) == 0u)
                        ? 8u : 0u)));
            invariant(source->reg
                == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0
                    + source_index));
            invariant(scalar->type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(scalar->size == (register_form
                ? scalar_register_size : scalar_memory_size));
            invariant(scalar->access == CDISASM_OPERAND_ACCESS_READ);
            invariant(scalar->broadcast == CDISASM_X86_BROADCAST_NONE);
            if (register_form) {
                invariant(scalar->reg >= scalar_base);
                invariant(scalar->reg <= scalar_base + 15u);
                invariant(scalar->flags == 0u);
                invariant(scalar->reg
                    == (cdisasm_x86_reg_id)(scalar_base
                        + (modrm & UINT8_C(7))
                        + ((mode == CDISASM_MODE_64 && vex3
                                && (p0 & UINT8_C(0x20)) == 0u)
                            ? 8u : 0u)));
            } else {
                invariant((scalar->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
            }
            invariant(immediate->type == CDISASM_OPERAND_IMMEDIATE);
            invariant(immediate->size == 1u);
            invariant(immediate->access == CDISASM_OPERAND_ACCESS_READ);
            invariant(immediate->flags == 0u);
            invariant(immediate->broadcast == CDISASM_X86_BROADCAST_NONE);
            invariant(immediate->imm
                == code[first.encoding.immediate_offset[0]]);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vpsign_integer) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const size_t vex_offset = opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const unsigned int vector_bytes =
                (p1 & UINT8_C(4)) != 0u ? 32u : 16u;
            const cdisasm_x86_reg_id register_base = vector_bytes == 16u
                ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
            unsigned int source_index =
                ((unsigned int)(~p1) >> 3) & 15u;
            cdisasm_x86_form_id base_form = 0u;
            cdisasm_x86_name_id expected_name = CDISASM_X86_NAME_NONE;
            size_t operand_index;

            if (mode != CDISASM_MODE_64) {
                source_index &= 7u;
            }
            switch (opcode) {
                case 0x08:
                    base_form = UINT16_C(7921);
                    expected_name = CDISASM_X86_NAME_VPSIGNB;
                    break;
                case 0x0a:
                    base_form = UINT16_C(7925);
                    expected_name = CDISASM_X86_NAME_VPSIGND;
                    break;
                case 0x09:
                    base_form = UINT16_C(7929);
                    expected_name = CDISASM_X86_NAME_VPSIGNW;
                    break;
                default:
                    invariant(0);
            }

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(2));
            invariant((p1 & UINT8_C(3)) == UINT8_C(1));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.name_id == expected_name);
            invariant(first.form_id == (cdisasm_x86_form_id)(base_form
                + (vector_bytes == 32u ? 2u : 0u)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant(first.encoding.prefix_size >= 3u);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 3u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 2u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == vector_bytes);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= register_base);
                    invariant(operand->reg <= register_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= register_base + 7u);
                    }
                }
            }
            invariant(first.opcode[0].reg
                == (cdisasm_x86_reg_id)(register_base
                    + ((modrm >> 3) & UINT8_C(7))
                    + ((mode == CDISASM_MODE_64
                            && (p0 & UINT8_C(0x80)) == 0u)
                        ? 8u : 0u)));
            invariant(first.opcode[1].reg
                == (cdisasm_x86_reg_id)(register_base + source_index));
            invariant(!register_form
                || first.opcode[2].reg
                    == (cdisasm_x86_reg_id)(register_base
                        + (modrm & UINT8_C(7))
                        + ((mode == CDISASM_MODE_64
                                && (p0 & UINT8_C(0x20)) == 0u)
                            ? 8u : 0u)));
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant((vector_bytes == 32u)
                == cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, vector_bytes == 32u
                    ? CDISASM_X86_DECODE_BIT_AVX2
                    : CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vpshuf_integer) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const int vex3 = opcode_offset >= 3u
                && code[opcode_offset - 3u] == UINT8_C(0xc4);
            const size_t vex_offset = opcode_offset - (vex3 ? 3u : 2u);
            const uint8_t p0 = vex3
                ? code[vex_offset + 1u] : UINT8_C(0);
            const uint8_t p1 = code[opcode_offset - 1u];
            const uint8_t modrm = first.encoding.modrm;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const unsigned int vector_bytes =
                (p1 & UINT8_C(4)) != 0u ? 32u : 16u;
            const cdisasm_x86_reg_id register_base = vector_bytes == 16u
                ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
            const uint8_t encoded_r = vex3 ? p0 : p1;
            const unsigned int prefix = p1 & UINT8_C(3);
            cdisasm_x86_form_id base_form = 0u;
            cdisasm_x86_name_id expected_name = CDISASM_X86_NAME_NONE;
            const cdisasm_opcode *destination = &first.opcode[0];
            const cdisasm_opcode *source = &first.opcode[1];
            const cdisasm_opcode *immediate = &first.opcode[2];

            switch (prefix) {
                case 1u:
                    base_form = UINT16_C(7891);
                    expected_name = CDISASM_X86_NAME_VPSHUFD;
                    break;
                case 2u:
                    base_form = UINT16_C(7901);
                    expected_name = CDISASM_X86_NAME_VPSHUFHW;
                    break;
                case 3u:
                    base_form = UINT16_C(7911);
                    expected_name = CDISASM_X86_NAME_VPSHUFLW;
                    break;
                default:
                    invariant(0);
            }

            invariant(code[vex_offset]
                == (uint8_t)(vex3 ? UINT8_C(0xc4) : UINT8_C(0xc5)));
            invariant(!vex3
                || (p0 & UINT8_C(0x1f)) == UINT8_C(1));
            invariant(first.encoding.opcode_size == 1u);
            invariant(code[opcode_offset] == UINT8_C(0x70));
            invariant((((unsigned int)(~p1) >> 3) & 15u) == 0u);
            invariant(mode == CDISASM_MODE_64 || !vex3
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.name_id == expected_name);
            invariant(first.form_id == (cdisasm_x86_form_id)(base_form
                + (vector_bytes == 32u ? 4u : 0u)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant(first.encoding.prefix_size >= (vex3 ? 3u : 2u));
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_size[0] == 1u);
            invariant(first.encoding.immediate_offset[0]
                == first.opcode_size - 1u);
            invariant(first.encoding.selector_offset == 0u);
            invariant(destination->type == CDISASM_OPERAND_REGISTER);
            invariant(destination->size == vector_bytes);
            invariant(destination->access == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(destination->reg >= register_base);
            invariant(destination->reg <= register_base + 15u);
            invariant(destination->flags == 0u);
            invariant(destination->broadcast == CDISASM_X86_BROADCAST_NONE);
            invariant(source->type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(source->size == vector_bytes);
            invariant(source->access == CDISASM_OPERAND_ACCESS_READ);
            invariant(source->broadcast == CDISASM_X86_BROADCAST_NONE);
            if (register_form) {
                invariant(source->reg >= register_base);
                invariant(source->reg <= register_base + 15u);
                invariant(source->flags == 0u);
            } else {
                invariant((source->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
            }
            if (mode != CDISASM_MODE_64) {
                invariant(destination->reg <= register_base + 7u);
                invariant(!register_form
                    || source->reg <= register_base + 7u);
            }
            invariant(destination->reg
                == (cdisasm_x86_reg_id)(register_base
                    + ((modrm >> 3) & UINT8_C(7))
                    + ((mode == CDISASM_MODE_64
                            && (encoded_r & UINT8_C(0x80)) == 0u)
                        ? 8u : 0u)));
            invariant(!register_form || source->reg
                == (cdisasm_x86_reg_id)(register_base
                    + (modrm & UINT8_C(7))
                    + ((mode == CDISASM_MODE_64 && vex3
                            && (p0 & UINT8_C(0x20)) == 0u)
                        ? 8u : 0u)));
            invariant(immediate->type == CDISASM_OPERAND_IMMEDIATE);
            invariant(immediate->size == 1u);
            invariant(immediate->access == CDISASM_OPERAND_ACCESS_READ);
            invariant(immediate->flags == 0u);
            invariant(immediate->broadcast == CDISASM_X86_BROADCAST_NONE);
            invariant(immediate->imm <= UINT8_MAX);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant((vector_bytes == 32u)
                == cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, vector_bytes == 32u
                    ? CDISASM_X86_DECODE_BIT_AVX2
                    : CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vex_vpunpck_integer) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const int vex3 = opcode_offset >= 3u
                && code[opcode_offset - 3u] == UINT8_C(0xc4);
            const size_t vex_offset = opcode_offset - (vex3 ? 3u : 2u);
            const uint8_t p0 = vex3
                ? code[vex_offset + 1u] : UINT8_C(0);
            const uint8_t p1 = code[opcode_offset - 1u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const unsigned int vector_bytes =
                (p1 & UINT8_C(4)) != 0u ? 32u : 16u;
            const cdisasm_x86_reg_id register_base = vector_bytes == 16u
                ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
            const uint8_t encoded_r = vex3 ? p0 : p1;
            unsigned int source_index =
                ((unsigned int)(~p1) >> 3) & 15u;
            cdisasm_x86_form_id base_form = 0u;
            cdisasm_x86_name_id expected_name = CDISASM_X86_NAME_NONE;
            size_t operand_index;

            if (mode != CDISASM_MODE_64) {
                source_index &= 7u;
            }
            switch (opcode) {
                case 0x68:
                    base_form = UINT16_C(8323);
                    expected_name = CDISASM_X86_NAME_VPUNPCKHBW;
                    break;
                case 0x6a:
                    base_form = UINT16_C(8333);
                    expected_name = CDISASM_X86_NAME_VPUNPCKHDQ;
                    break;
                case 0x6d:
                    base_form = UINT16_C(8343);
                    expected_name = CDISASM_X86_NAME_VPUNPCKHQDQ;
                    break;
                case 0x69:
                    base_form = UINT16_C(8353);
                    expected_name = CDISASM_X86_NAME_VPUNPCKHWD;
                    break;
                case 0x60:
                    base_form = UINT16_C(8363);
                    expected_name = CDISASM_X86_NAME_VPUNPCKLBW;
                    break;
                case 0x62:
                    base_form = UINT16_C(8373);
                    expected_name = CDISASM_X86_NAME_VPUNPCKLDQ;
                    break;
                case 0x6c:
                    base_form = UINT16_C(8383);
                    expected_name = CDISASM_X86_NAME_VPUNPCKLQDQ;
                    break;
                case 0x61:
                    base_form = UINT16_C(8393);
                    expected_name = CDISASM_X86_NAME_VPUNPCKLWD;
                    break;
                default:
                    invariant(0);
            }

            invariant(code[vex_offset] == (vex3
                ? UINT8_C(0xc4) : UINT8_C(0xc5)));
            invariant(!vex3
                || (p0 & UINT8_C(0x1f)) == UINT8_C(1));
            invariant((p1 & UINT8_C(3)) == UINT8_C(1));
            invariant(mode == CDISASM_MODE_64
                || (vex3
                    ? (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0)
                    : (p1 & UINT8_C(0xc0)) == UINT8_C(0xc0)));
            invariant(first.name_id == expected_name);
            invariant(first.form_id == (cdisasm_x86_form_id)(base_form
                + (vector_bytes == 32u ? 4u : 0u)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & ~(CDISASM_PREFIX_VEX | CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u);
            invariant(first.encoding.prefix_size >= (vex3 ? 3u : 2u));
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            for (operand_index = 0u; operand_index < 3u;
                 ++operand_index) {
                const cdisasm_opcode *operand =
                    &first.opcode[operand_index];
                const int memory = !register_form
                    && operand_index == 2u;

                invariant(operand->type == (memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(operand->size == vector_bytes);
                invariant(operand->access == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                invariant(operand->broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                if (memory) {
                    invariant((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
                } else {
                    invariant(operand->reg >= register_base);
                    invariant(operand->reg <= register_base + 15u);
                    invariant(operand->flags == 0u);
                    if (mode != CDISASM_MODE_64) {
                        invariant(operand->reg <= register_base + 7u);
                    }
                }
            }
            invariant(first.opcode[0].reg
                == (cdisasm_x86_reg_id)(register_base
                    + ((modrm >> 3) & UINT8_C(7))
                    + ((mode == CDISASM_MODE_64
                            && (encoded_r & UINT8_C(0x80)) == 0u)
                        ? 8u : 0u)));
            invariant(first.opcode[1].reg
                == (cdisasm_x86_reg_id)(register_base + source_index));
            invariant(!register_form
                || first.opcode[2].reg
                    == (cdisasm_x86_reg_id)(register_base
                        + (modrm & UINT8_C(7))
                        + ((mode == CDISASM_MODE_64 && vex3
                                && (p0 & UINT8_C(0x20)) == 0u)
                            ? 8u : 0u)));
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant((vector_bytes == 32u)
                == cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX2));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, vector_bytes == 32u
                    ? CDISASM_X86_DECODE_BIT_AVX2
                    : CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_vbroadcast_scalar) {
            const size_t vex_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            const uint8_t p0 = code[vex_offset + 1u];
            const uint8_t p1 = code[vex_offset + 2u];
            const uint8_t opcode = code[first.encoding.opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const unsigned int l = ((unsigned int)p1 >> 2) & 1u;
            const unsigned int vector_bytes = 16u << l;
            const unsigned int scalar_bytes = opcode == UINT8_C(0x19)
                ? 8u : 4u;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const cdisasm_x86_reg_id destination_base = l != 0u
                ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
            cdisasm_x86_form_id expected_form;

            if (opcode == UINT8_C(0x19)) {
                expected_form = register_form
                    ? UINT16_C(3570) : UINT16_C(3569);
            } else if (l == 0u) {
                expected_form = register_form
                    ? UINT16_C(3574) : UINT16_C(3573);
            } else {
                expected_form = register_form
                    ? UINT16_C(3580) : UINT16_C(3579);
            }

            invariant(code[vex_offset] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(2));
            invariant((p1 & UINT8_C(0xfb)) == UINT8_C(0x79));
            invariant(opcode == UINT8_C(0x18)
                || opcode == UINT8_C(0x19));
            invariant(opcode != UINT8_C(0x19) || l != 0u);
            invariant(first.name_id == (opcode == UINT8_C(0x19)
                ? CDISASM_X86_NAME_VBROADCASTSD
                : CDISASM_X86_NAME_VBROADCASTSS));
            invariant(mode == CDISASM_MODE_64
                || (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.form_id == expected_form);
            invariant(first.operand_count == 2u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset
                == first.encoding.opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].reg >= destination_base);
            invariant(first.opcode[0].reg <= destination_base + 15u);
            invariant(first.opcode[0].size == vector_bytes);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[0].flags == 0u);
            invariant(first.opcode[0].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[1].type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(first.opcode[1].size
                == (register_form ? 16u : scalar_bytes));
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[1].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(!register_form
                || (first.opcode[1].reg >= CDISASM_X86_REG_XMM0
                    && first.opcode[1].reg <= CDISASM_X86_REG_XMM15
                    && first.opcode[1].flags == 0u));
            invariant(register_form
                || (first.opcode[1].flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2) == register_form);
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, register_form
                    ? CDISASM_X86_DECODE_BIT_AVX2
                    : CDISASM_X86_DECODE_BIT_AVX));
            if (mode != CDISASM_MODE_64) {
                invariant(first.opcode[0].reg
                    <= destination_base + 7u);
                invariant(!register_form
                    || first.opcode[1].reg <= CDISASM_X86_REG_XMM7);
            }
        }
        if (is_vpack) {
            const uint8_t p1 = code[first.encoding.opcode_offset - 1u];
            const uint8_t opcode = code[first.encoding.opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const unsigned int ll = ((unsigned int)p1 >> 2) & 1u;
            const unsigned int vector_bytes = 16u << ll;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            cdisasm_x86_form_id xmm_form;
            cdisasm_x86_form_id ymm_form;

            if (first.name_id == CDISASM_X86_NAME_VPACKSSDW) {
                xmm_form = UINT16_C(6124);
                ymm_form = UINT16_C(6130);
            } else if (first.name_id == CDISASM_X86_NAME_VPACKSSWB) {
                xmm_form = UINT16_C(6134);
                ymm_form = UINT16_C(6140);
            } else if (first.name_id == CDISASM_X86_NAME_VPACKUSDW) {
                xmm_form = UINT16_C(6144);
                ymm_form = UINT16_C(6148);
            } else {
                xmm_form = UINT16_C(6154);
                ymm_form = UINT16_C(6158);
            }
            invariant((p1 & UINT8_C(0x03)) == UINT8_C(1));
            invariant((first.name_id == CDISASM_X86_NAME_VPACKSSDW
                    && opcode == UINT8_C(0x6b))
                || (first.name_id == CDISASM_X86_NAME_VPACKSSWB
                    && opcode == UINT8_C(0x63))
                || (first.name_id == CDISASM_X86_NAME_VPACKUSDW
                    && opcode == UINT8_C(0x2b))
                || (first.name_id == CDISASM_X86_NAME_VPACKUSWB
                    && opcode == UINT8_C(0x67)));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                (ll != 0u ? ymm_form : xmm_form)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].size == vector_bytes);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].size == vector_bytes);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[2].type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(first.opcode[2].size == vector_bytes);
            invariant(first.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2) == (ll != 0u));
        }
        if (is_vex_modular_add_sub) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const int two_byte = code[opcode_offset - 2u] == UINT8_C(0xc5);
            const size_t vex_offset = opcode_offset - (two_byte ? 2u : 3u);
            const uint8_t p0 = two_byte
                ? UINT8_C(0xe1) : code[vex_offset + 1u];
            const uint8_t p1 = code[opcode_offset - 1u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const unsigned int l = ((unsigned int)p1 >> 2) & 1u;
            const unsigned int vector_bytes = 16u << l;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const cdisasm_x86_reg_id register_base = l != 0u
                ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
            cdisasm_x86_form_id xmm_base;
            cdisasm_x86_form_id ymm_base;

            if (first.name_id == CDISASM_X86_NAME_VPADDB) {
                xmm_base = UINT16_C(6164);
                ymm_base = UINT16_C(6168);
            } else if (first.name_id == CDISASM_X86_NAME_VPADDW) {
                xmm_base = UINT16_C(6234);
                ymm_base = UINT16_C(6238);
            } else if (first.name_id == CDISASM_X86_NAME_VPADDD) {
                xmm_base = UINT16_C(6174);
                ymm_base = UINT16_C(6178);
            } else if (first.name_id == CDISASM_X86_NAME_VPADDQ) {
                xmm_base = UINT16_C(6184);
                ymm_base = UINT16_C(6188);
            } else if (first.name_id == CDISASM_X86_NAME_VPSUBB) {
                xmm_base = UINT16_C(8179);
                ymm_base = UINT16_C(8183);
            } else if (first.name_id == CDISASM_X86_NAME_VPSUBW) {
                xmm_base = UINT16_C(8249);
                ymm_base = UINT16_C(8253);
            } else if (first.name_id == CDISASM_X86_NAME_VPSUBD) {
                xmm_base = UINT16_C(8189);
                ymm_base = UINT16_C(8193);
            } else {
                xmm_base = UINT16_C(8199);
                ymm_base = UINT16_C(8203);
            }

            invariant(code[vex_offset]
                == (two_byte ? UINT8_C(0xc5) : UINT8_C(0xc4)));
            invariant(two_byte
                || (p0 & UINT8_C(0x1f)) == UINT8_C(1));
            invariant((p1 & UINT8_C(3)) == UINT8_C(1));
            invariant((first.name_id == CDISASM_X86_NAME_VPADDB
                    && opcode == UINT8_C(0xfc))
                || (first.name_id == CDISASM_X86_NAME_VPADDW
                    && opcode == UINT8_C(0xfd))
                || (first.name_id == CDISASM_X86_NAME_VPADDD
                    && opcode == UINT8_C(0xfe))
                || (first.name_id == CDISASM_X86_NAME_VPADDQ
                    && opcode == UINT8_C(0xd4))
                || (first.name_id == CDISASM_X86_NAME_VPSUBB
                    && opcode == UINT8_C(0xf8))
                || (first.name_id == CDISASM_X86_NAME_VPSUBW
                    && opcode == UINT8_C(0xf9))
                || (first.name_id == CDISASM_X86_NAME_VPSUBD
                    && opcode == UINT8_C(0xfa))
                || (first.name_id == CDISASM_X86_NAME_VPSUBQ
                    && opcode == UINT8_C(0xfb)));
            invariant(mode == CDISASM_MODE_64
                || (two_byte
                    ? (p1 & UINT8_C(0xc0)) == UINT8_C(0xc0)
                    : (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0)));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                (l != 0u ? ymm_base : xmm_base)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].reg >= register_base
                && first.opcode[0].reg <= register_base + 15u);
            invariant(first.opcode[0].size == vector_bytes);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[0].flags == 0u);
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].reg >= register_base
                && first.opcode[1].reg <= register_base + 15u);
            invariant(first.opcode[1].size == vector_bytes);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[1].flags == 0u);
            invariant(first.opcode[2].type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(first.opcode[2].size == vector_bytes);
            invariant(first.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE
                && first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE
                && first.opcode[2].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
            invariant(!register_form
                || (first.opcode[2].reg >= register_base
                    && first.opcode[2].reg <= register_base + 15u
                    && first.opcode[2].flags == 0u));
            invariant(register_form
                || (first.opcode[2].flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                        | CDISASM_OPERAND_FLAG_SIGNED)) == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first,CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first,CDISASM_X86_GROUP_AVX2) == (l != 0u));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags,l != 0u
                    ? CDISASM_X86_DECODE_BIT_AVX2
                    : CDISASM_X86_DECODE_BIT_AVX));
            if (mode != CDISASM_MODE_64) {
                invariant(first.opcode[0].reg <= register_base + 7u);
                invariant(first.opcode[1].reg <= register_base + 7u);
                invariant(!register_form
                    || first.opcode[2].reg <= register_base + 7u);
            }
            if (two_byte) {
                invariant(!register_form
                    || first.opcode[2].reg <= register_base + 7u);
            }
        }
        if (is_vex_integer_minmax) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const int two_byte = code[opcode_offset - 2u] == UINT8_C(0xc5);
            const size_t vex_offset = opcode_offset - (two_byte ? 2u : 3u);
            const uint8_t p0 = two_byte
                ? UINT8_C(0xe1) : code[vex_offset + 1u];
            const uint8_t p1 = code[opcode_offset - 1u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const unsigned int l = ((unsigned int)p1 >> 2) & 1u;
            const unsigned int vector_bytes = 16u << l;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const cdisasm_x86_reg_id register_base = l != 0u
                ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
            uint8_t expected_map;
            uint8_t expected_opcode;
            cdisasm_x86_form_id xmm_base;
            cdisasm_x86_form_id ymm_base;

            switch (first.name_id) {
                case CDISASM_X86_NAME_VPMAXSB:
                    expected_map = 2u; expected_opcode = UINT8_C(0x3c);
                    xmm_base = UINT16_C(7160); ymm_base = UINT16_C(7166);
                    break;
                case CDISASM_X86_NAME_VPMAXSD:
                    expected_map = 2u; expected_opcode = UINT8_C(0x3d);
                    xmm_base = UINT16_C(7170); ymm_base = UINT16_C(7176);
                    break;
                case CDISASM_X86_NAME_VPMAXSW:
                    expected_map = 1u; expected_opcode = UINT8_C(0xee);
                    xmm_base = UINT16_C(7186); ymm_base = UINT16_C(7192);
                    break;
                case CDISASM_X86_NAME_VPMAXUB:
                    expected_map = 1u; expected_opcode = UINT8_C(0xde);
                    xmm_base = UINT16_C(7196); ymm_base = UINT16_C(7200);
                    break;
                case CDISASM_X86_NAME_VPMAXUD:
                    expected_map = 2u; expected_opcode = UINT8_C(0x3f);
                    xmm_base = UINT16_C(7206); ymm_base = UINT16_C(7210);
                    break;
                case CDISASM_X86_NAME_VPMAXUW:
                    expected_map = 2u; expected_opcode = UINT8_C(0x3e);
                    xmm_base = UINT16_C(7222); ymm_base = UINT16_C(7226);
                    break;
                case CDISASM_X86_NAME_VPMINSB:
                    expected_map = 2u; expected_opcode = UINT8_C(0x38);
                    xmm_base = UINT16_C(7232); ymm_base = UINT16_C(7238);
                    break;
                case CDISASM_X86_NAME_VPMINSD:
                    expected_map = 2u; expected_opcode = UINT8_C(0x39);
                    xmm_base = UINT16_C(7242); ymm_base = UINT16_C(7248);
                    break;
                case CDISASM_X86_NAME_VPMINSW:
                    expected_map = 1u; expected_opcode = UINT8_C(0xea);
                    xmm_base = UINT16_C(7258); ymm_base = UINT16_C(7264);
                    break;
                case CDISASM_X86_NAME_VPMINUB:
                    expected_map = 1u; expected_opcode = UINT8_C(0xda);
                    xmm_base = UINT16_C(7268); ymm_base = UINT16_C(7272);
                    break;
                case CDISASM_X86_NAME_VPMINUD:
                    expected_map = 2u; expected_opcode = UINT8_C(0x3b);
                    xmm_base = UINT16_C(7278); ymm_base = UINT16_C(7282);
                    break;
                default:
                    expected_map = 2u; expected_opcode = UINT8_C(0x3a);
                    xmm_base = UINT16_C(7294); ymm_base = UINT16_C(7298);
                    break;
            }

            invariant(code[vex_offset]
                == (two_byte ? UINT8_C(0xc5) : UINT8_C(0xc4)));
            invariant(!two_byte || expected_map == 1u);
            invariant(two_byte
                || (p0 & UINT8_C(0x1f)) == expected_map);
            invariant((p1 & UINT8_C(3)) == UINT8_C(1));
            invariant(opcode == expected_opcode);
            invariant(mode == CDISASM_MODE_64
                || (two_byte
                    ? (p1 & UINT8_C(0xc0)) == UINT8_C(0xc0)
                    : (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0)));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                (l != 0u ? ymm_base : xmm_base)
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].reg >= register_base
                && first.opcode[0].reg <= register_base + 15u);
            invariant(first.opcode[0].size == vector_bytes);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[0].flags == 0u);
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].reg >= register_base
                && first.opcode[1].reg <= register_base + 15u);
            invariant(first.opcode[1].size == vector_bytes);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[1].flags == 0u);
            invariant(first.opcode[2].type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(first.opcode[2].size == vector_bytes);
            invariant(first.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE
                && first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE
                && first.opcode[2].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
            invariant(!register_form
                || (first.opcode[2].reg >= register_base
                    && first.opcode[2].reg <= register_base + 15u
                    && first.opcode[2].flags == 0u));
            invariant(register_form
                || (first.opcode[2].flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                        | CDISASM_OPERAND_FLAG_SIGNED)) == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first,CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first,CDISASM_X86_GROUP_AVX2) == (l != 0u));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags,l != 0u
                    ? CDISASM_X86_DECODE_BIT_AVX2
                    : CDISASM_X86_DECODE_BIT_AVX));
            if (mode != CDISASM_MODE_64) {
                invariant(first.opcode[0].reg <= register_base + 7u);
                invariant(first.opcode[1].reg <= register_base + 7u);
                invariant(!register_form
                    || first.opcode[2].reg <= register_base + 7u);
            }
            if (two_byte) {
                invariant(!register_form
                    || first.opcode[2].reg <= register_base + 7u);
            }
        }
        if (is_vpcmpeqq || is_vpcmpgtq || is_vpcmpgtw
            || is_vpcmpeqb || is_vpcmpeqd || is_vpcmpeqw
            || is_vpcmpgtb || is_vpcmpgtd) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const int two_byte = code[opcode_offset - 2u] == UINT8_C(0xc5);
            const int map1_compare = is_vpcmpgtw || is_vpcmpeqb
                || is_vpcmpeqd || is_vpcmpeqw
                || is_vpcmpgtb || is_vpcmpgtd;
            const size_t vex_offset = opcode_offset - (two_byte ? 2u : 3u);
            const uint8_t p0 = two_byte
                ? UINT8_C(0xe1) : code[vex_offset + 1u];
            const uint8_t p1 = code[opcode_offset - 1u];
            const uint8_t opcode = code[first.encoding.opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const unsigned int l = ((unsigned int)p1 >> 2) & 1u;
            const unsigned int vector_bytes = 16u << l;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const cdisasm_x86_reg_id register_base = l != 0u
                ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;

            invariant(code[vex_offset]
                == (two_byte ? UINT8_C(0xc5) : UINT8_C(0xc4)));
            invariant(!two_byte || map1_compare);
            invariant(two_byte
                || (p0 & UINT8_C(0x1f))
                    == (map1_compare ? UINT8_C(1) : UINT8_C(2)));
            invariant((p1 & UINT8_C(0x03)) == UINT8_C(1));
            invariant(opcode == (is_vpcmpeqb ? UINT8_C(0x74)
                : is_vpcmpeqd ? UINT8_C(0x76)
                : is_vpcmpeqw ? UINT8_C(0x75)
                : is_vpcmpgtb ? UINT8_C(0x64)
                : is_vpcmpgtd ? UINT8_C(0x66)
                : is_vpcmpgtw ? UINT8_C(0x65)
                : is_vpcmpgtq ? UINT8_C(0x37) : UINT8_C(0x29)));
            invariant(mode == CDISASM_MODE_64
                || (two_byte
                    ? (p1 & UINT8_C(0xc0)) == UINT8_C(0xc0)
                    : (p0 & UINT8_C(0xc0)) == UINT8_C(0xc0)));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                (is_vpcmpeqb ? UINT16_C(6434)
                    : is_vpcmpeqd ? UINT16_C(6444)
                    : is_vpcmpeqw ? UINT16_C(6464)
                    : is_vpcmpgtb ? UINT16_C(6482)
                    : is_vpcmpgtd ? UINT16_C(6492)
                    : is_vpcmpgtw ? UINT16_C(6512)
                    : is_vpcmpgtq ? UINT16_C(6502) : UINT16_C(6454))
                    + 2u * l
                    + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset
                == first.encoding.opcode_offset + 1u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].reg >= register_base
                && first.opcode[0].reg <= register_base + 15u);
            invariant(first.opcode[0].size == vector_bytes);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[0].flags == 0u);
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].reg >= register_base
                && first.opcode[1].reg <= register_base + 15u);
            invariant(first.opcode[1].size == vector_bytes);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[1].flags == 0u);
            invariant(first.opcode[2].type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(first.opcode[2].size == vector_bytes);
            invariant(first.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE
                && first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE
                && first.opcode[2].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
            invariant(!register_form
                || (first.opcode[2].reg >= register_base
                    && first.opcode[2].reg <= register_base + 15u
                    && first.opcode[2].flags == 0u));
            invariant(register_form
                || (first.opcode[2].flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                        | CDISASM_OPERAND_FLAG_SIGNED)) == 0u);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2) == (l != 0u));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, l != 0u
                    ? CDISASM_X86_DECODE_BIT_AVX2
                    : CDISASM_X86_DECODE_BIT_AVX));
            if (mode != CDISASM_MODE_64) {
                invariant(first.opcode[0].reg <= register_base + 7u);
                invariant(first.opcode[1].reg <= register_base + 7u);
                invariant(!register_form
                    || first.opcode[2].reg <= register_base + 7u);
            }
            if (two_byte) {
                invariant(!register_form
                    || first.opcode[2].reg <= register_base + 7u);
                invariant(register_form
                    || !((first.opcode[2].base_reg
                                >= CDISASM_X86_REG_R8W
                            && first.opcode[2].base_reg
                                <= CDISASM_X86_REG_R15W)
                        || (first.opcode[2].base_reg
                                >= CDISASM_X86_REG_R8D
                            && first.opcode[2].base_reg
                                <= CDISASM_X86_REG_R15D)
                        || (first.opcode[2].base_reg
                                >= CDISASM_X86_REG_R8
                            && first.opcode[2].base_reg
                                <= CDISASM_X86_REG_R15)
                        || (first.opcode[2].index_reg
                                >= CDISASM_X86_REG_R8W
                            && first.opcode[2].index_reg
                                <= CDISASM_X86_REG_R15W)
                        || (first.opcode[2].index_reg
                                >= CDISASM_X86_REG_R8D
                            && first.opcode[2].index_reg
                                <= CDISASM_X86_REG_R15D)
                        || (first.opcode[2].index_reg
                                >= CDISASM_X86_REG_R8
                            && first.opcode[2].index_reg
                                <= CDISASM_X86_REG_R15)));
            }
        }
        if (is_non_temporal_store) {
            invariant(first.operand_count == 2u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[0].size == first.opcode[1].size);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
        }
        if (is_non_temporal_load) {
            invariant(first.operand_count == 2u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[1].type == CDISASM_OPERAND_MEMORY);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[0].size == first.opcode[1].size);
            invariant(first.form_id == UINT16_C(5864)
                || first.form_id == UINT16_C(5866));
            invariant(cdisasm_instruction_has_x86_group(
                &first, first.form_id == UINT16_C(5864)
                    ? CDISASM_X86_GROUP_AVX : CDISASM_X86_GROUP_AVX2));
        }
        if (is_unaligned_load) {
            invariant(first.operand_count == 2u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[1].type == CDISASM_OPERAND_MEMORY);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[0].size == first.opcode[1].size);
            invariant(first.form_id == (first.opcode[0].size == 16u
                ? UINT16_C(5583) : UINT16_C(5584)));
            invariant(first.opcode[0].size == 16u
                || first.opcode[0].size == 32u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
        }
        if (is_move_mask) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const uint8_t control = code[opcode_offset - 1u];
            const unsigned int vector_bytes =
                (control & UINT8_C(0x04)) != 0u ? 32u : 16u;
            const int is_pd =
                first.name_id == CDISASM_X86_NAME_VMOVMSKPD;
            const cdisasm_x86_form_id expected_form =
                (cdisasm_x86_form_id)(
                    (is_pd ? UINT16_C(5860) : UINT16_C(5862))
                    + (vector_bytes == 32u ? 1u : 0u));

            invariant(first.operand_count == 2u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[0].size == 4u);
            invariant(first.opcode[0].reg >= CDISASM_X86_REG_EAX);
            invariant(first.opcode[0].reg
                <= (mode == CDISASM_MODE_64
                    ? CDISASM_X86_REG_R15D : CDISASM_X86_REG_EDI));
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[1].size == vector_bytes);
            invariant(first.opcode[1].reg >= (vector_bytes == 16u
                ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0));
            invariant(first.opcode[1].reg <= (vector_bytes == 16u
                ? (mode == CDISASM_MODE_64
                    ? CDISASM_X86_REG_XMM15 : CDISASM_X86_REG_XMM7)
                : (mode == CDISASM_MODE_64
                    ? CDISASM_X86_REG_YMM15 : CDISASM_X86_REG_YMM7)));
            if (mode != CDISASM_MODE_64) {
                const cdisasm_x86_reg_id vector_base = vector_bytes == 16u
                    ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;

                invariant(first.opcode[1].reg
                    == (cdisasm_x86_reg_id)(vector_base
                        + (first.encoding.modrm & UINT8_C(7))));
            }
            invariant(first.form_id == expected_form);
            invariant(first.encoding.opcode_size == 1u);
            invariant(code[opcode_offset] == UINT8_C(0x50));
            invariant((control & UINT8_C(0x78)) == UINT8_C(0x78));
            invariant((control & UINT8_C(0x03))
                == (is_pd ? UINT8_C(1) : UINT8_C(0)));
            invariant((first.encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0));
            invariant(code[opcode_offset - 2u] == UINT8_C(0xc5)
                || (code[opcode_offset - 3u] == UINT8_C(0xc4)
                    && (code[opcode_offset - 2u] & UINT8_C(0x1f))
                        == UINT8_C(1)));
            invariant(first.encoding.immediate_count == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_AVX) != 0u);
        }
        if (is_vpmovmskb) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const uint8_t control = code[opcode_offset - 1u];
            const uint8_t modrm = first.encoding.modrm;
            const unsigned int vector_bytes =
                (control & UINT8_C(4)) != 0u ? 32u : 16u;
            const cdisasm_x86_reg_id vector_base = vector_bytes == 32u
                ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
            const int vex2 = code[opcode_offset - 2u] == UINT8_C(0xc5);

            invariant(first.form_id == (vector_bytes == 32u
                ? UINT16_C(7335) : UINT16_C(7334)));
            invariant(first.operand_count == 2u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].reg >= CDISASM_X86_REG_EAX);
            invariant(first.opcode[0].reg <= (mode == CDISASM_MODE_64
                ? CDISASM_X86_REG_R15D : CDISASM_X86_REG_EDI));
            invariant(first.opcode[0].size == 4u);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[0].flags == 0u);
            invariant(first.opcode[0].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].reg >= vector_base);
            invariant(first.opcode[1].reg <= vector_base
                + (mode == CDISASM_MODE_64 ? 15u : 7u));
            invariant(first.opcode[1].size == vector_bytes);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[1].flags == 0u);
            invariant(first.opcode[1].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(((unsigned int)first.opcode[0].reg
                    - (unsigned int)CDISASM_X86_REG_EAX) % 8u
                == ((unsigned int)modrm >> 3) % 8u);
            invariant(((unsigned int)first.opcode[1].reg
                    - (unsigned int)vector_base) % 8u
                == (unsigned int)modrm % 8u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                    | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
                == CDISASM_PREFIX_VEX);
            invariant(first.encoding.prefix_size >= (vex2 ? 2u : 3u));
            invariant(first.encoding.opcode_size == 1u);
            invariant(first.encoding.modrm_offset == opcode_offset + 1u);
            invariant((modrm & UINT8_C(0xc0)) == UINT8_C(0xc0));
            invariant(first.encoding.sib_offset == 0u);
            invariant(first.encoding.displacement_offset == 0u);
            invariant(first.encoding.displacement_size == 0u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset == 0u);
            invariant(code[opcode_offset] == UINT8_C(0xd7));
            invariant((control & UINT8_C(0x7b)) == UINT8_C(0x79));
            invariant(vex2
                || (code[opcode_offset - 3u] == UINT8_C(0xc4)
                    && (code[opcode_offset - 2u] & UINT8_C(0x1f))
                        == UINT8_C(1)));
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.opcode_groups == CDISASM_GROUP_NONE);
            invariant(first.branch_target == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2) == (vector_bytes == 32u));
            invariant(cdisasm_decode_flags_test_bit(decode_flags,
                vector_bytes == 32u
                    ? CDISASM_X86_DECODE_BIT_AVX2
                    : CDISASM_X86_DECODE_BIT_AVX));
        }
        if (is_move_quadword) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const uint8_t control = code[opcode_offset - 1u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int is_vex2 =
                code[opcode_offset - 2u] == UINT8_C(0xc5);
            const int destination_is_memory =
                first.form_id == UINT16_C(5886)
                || first.form_id == UINT16_C(5887);
            const int source_is_memory =
                first.form_id == UINT16_C(5890)
                || first.form_id == UINT16_C(5891);
            const unsigned int destination_bytes =
                destination_is_memory
                    || first.form_id == UINT16_C(5884) ? 8u : 16u;
            const unsigned int source_bytes =
                source_is_memory
                    || first.form_id == UINT16_C(5889) ? 8u : 16u;

            invariant(first.form_id >= UINT16_C(5884)
                && first.form_id <= UINT16_C(5893)
                && first.form_id != UINT16_C(5885)
                && first.form_id != UINT16_C(5888));
            invariant(first.operand_count == 2u);
            invariant(first.opcode[0].type == (destination_is_memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
            invariant(first.opcode[0].size == destination_bytes);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[0].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[1].type == (source_is_memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
            invariant(first.opcode[1].size == source_bytes);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[1].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(((modrm & UINT8_C(0xc0)) != UINT8_C(0xc0))
                == (destination_is_memory || source_is_memory));
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.encoding.immediate_count == 0u);
            invariant((control & UINT8_C(0x7c)) == UINT8_C(0x78));
            invariant(is_vex2
                || (code[opcode_offset - 3u] == UINT8_C(0xc4)
                    && (code[opcode_offset - 2u] & UINT8_C(0x1f))
                        == UINT8_C(1)));
            invariant((opcode == UINT8_C(0x6e)
                    && (control & UINT8_C(3)) == UINT8_C(1)
                    && (first.form_id == UINT16_C(5889)
                        || first.form_id == UINT16_C(5890)))
                || (opcode == UINT8_C(0x7e)
                    && (control & UINT8_C(3)) == UINT8_C(1)
                    && (first.form_id == UINT16_C(5884)
                        || first.form_id == UINT16_C(5886)))
                || (opcode == UINT8_C(0x7e)
                    && (control & UINT8_C(3)) == UINT8_C(2)
                    && (first.form_id == UINT16_C(5891)
                        || first.form_id == UINT16_C(5892)))
                || (opcode == UINT8_C(0xd6)
                    && (control & UINT8_C(3)) == UINT8_C(1)
                    && (first.form_id == UINT16_C(5887)
                        || first.form_id == UINT16_C(5893))));
            if (first.form_id == UINT16_C(5884)
                || first.form_id == UINT16_C(5886)
                || first.form_id == UINT16_C(5889)
                || first.form_id == UINT16_C(5890)) {
                invariant(mode == CDISASM_MODE_64);
                invariant(!is_vex2);
                invariant((control & UINT8_C(0x80)) != 0u);
            }
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512F_128N));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_AVX) != 0u);
        }
        if (is_move_duplicate) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const uint8_t control = code[opcode_offset - 1u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int source_is_memory =
                (modrm & UINT8_C(0xc0)) != UINT8_C(0xc0);
            const unsigned int vector_bytes =
                (control & UINT8_C(0x04)) != 0u ? 32u : 16u;
            const cdisasm_x86_form_id base_form =
                first.name_id == CDISASM_X86_NAME_VMOVSHDUP
                    ? (vector_bytes == 16u
                        ? UINT16_C(5916) : UINT16_C(5922))
                    : (vector_bytes == 16u
                        ? UINT16_C(5929) : UINT16_C(5935));

            invariant(first.form_id
                == (cdisasm_x86_form_id)(base_form
                    + (source_is_memory ? 0u : 1u)));
            invariant(first.operand_count == 2u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].size == vector_bytes);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[0].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[1].type == (source_is_memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
            invariant(first.opcode[1].size == vector_bytes);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[1].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.encoding.immediate_count == 0u);
            invariant((control & UINT8_C(0x7b)) == UINT8_C(0x7a));
            invariant(code[opcode_offset - 2u] == UINT8_C(0xc5)
                || (code[opcode_offset - 3u] == UINT8_C(0xc4)
                    && (code[opcode_offset - 2u] & UINT8_C(0x1f))
                        == UINT8_C(1)));
            invariant((opcode == UINT8_C(0x16)
                    && first.name_id == CDISASM_X86_NAME_VMOVSHDUP)
                || (opcode == UINT8_C(0x12)
                    && first.name_id == CDISASM_X86_NAME_VMOVSLDUP));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512F_128));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512F_256));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512F_512));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_AVX) != 0u);
        }
        if (is_unaligned_packed_move) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const uint8_t control = code[opcode_offset - 1u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int is_pd =
                first.name_id == CDISASM_X86_NAME_VMOVUPD;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const int memory_destination =
                !register_form && opcode == UINT8_C(0x11);
            const int memory_source =
                !register_form && opcode == UINT8_C(0x10);
            const unsigned int vector_bytes =
                (control & UINT8_C(0x04)) != 0u ? 32u : 16u;
            const cdisasm_x86_form_id base_form = is_pd
                ? UINT16_C(5946) : UINT16_C(5963);
            const unsigned int relative_form = !register_form
                ? (opcode == UINT8_C(0x11)
                    ? (vector_bytes == 16u ? 0u : 4u)
                    : (vector_bytes == 16u ? 5u : 12u))
                : (opcode == UINT8_C(0x10)
                    ? (vector_bytes == 16u ? 6u : 13u)
                    : (vector_bytes == 16u ? 7u : 14u));

            invariant(first.form_id
                == (cdisasm_x86_form_id)(base_form + relative_form));
            invariant(first.operand_count == 2u);
            invariant(first.opcode[0].type == (memory_destination
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
            invariant(first.opcode[0].size == vector_bytes);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[0].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[1].type == (memory_source
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
            invariant(first.opcode[1].size == vector_bytes);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[1].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.encoding.immediate_count == 0u);
            invariant((control & UINT8_C(0x7b))
                == (is_pd ? UINT8_C(0x79) : UINT8_C(0x78)));
            invariant(code[opcode_offset - 2u] == UINT8_C(0xc5)
                || (code[opcode_offset - 3u] == UINT8_C(0xc4)
                    && (code[opcode_offset - 2u] & UINT8_C(0x1f))
                        == UINT8_C(1)));
            invariant(opcode == UINT8_C(0x10)
                || opcode == UINT8_C(0x11));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512F_128));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512F_256));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512F_512));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_AVX) != 0u);
        }
        if (is_vmpsadbw) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const uint8_t p0 = code[opcode_offset - 2u];
            const uint8_t p1 = code[opcode_offset - 1u];
            const uint8_t modrm = first.encoding.modrm;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const unsigned int vector_bytes =
                (p1 & UINT8_C(0x04)) != 0u ? 32u : 16u;
            const cdisasm_x86_form_id expected_form = vector_bytes == 16u
                ? (register_form ? UINT16_C(5988) : UINT16_C(5987))
                : (register_form ? UINT16_C(5992) : UINT16_C(5991));

            invariant(code[opcode_offset - 3u] == UINT8_C(0xc4));
            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(3));
            invariant((p1 & UINT8_C(3)) == UINT8_C(1));
            invariant(code[opcode_offset] == UINT8_C(0x42));
            invariant(first.form_id == expected_form);
            invariant(first.operand_count == 4u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].size == vector_bytes);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].size == vector_bytes);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[2].type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(first.opcode[2].size == vector_bytes);
            invariant(first.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
            invariant(first.opcode[3].size == 1u);
            invariant(first.opcode[3].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_size[0] == 1u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2)
                == (vector_bytes == 32u));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512_MEDIAX_128));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512_MEDIAX_256));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512_MEDIAX_512));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
        }
        if (is_move_scalar) {
            const size_t opcode_offset = first.encoding.opcode_offset;
            const uint8_t control = code[opcode_offset - 1u];
            const uint8_t opcode = code[opcode_offset];
            const uint8_t modrm = first.encoding.modrm;
            const int is_single =
                first.name_id == CDISASM_X86_NAME_VMOVSS;
            const int memory_destination =
                first.form_id == UINT16_C(5910)
                || first.form_id == UINT16_C(5939);
            const int memory_source = first.form_id == UINT16_C(5911)
                || first.form_id == UINT16_C(5941);

            invariant((!is_single
                    && first.form_id >= UINT16_C(5910)
                    && first.form_id <= UINT16_C(5913))
                || (is_single
                    && (first.form_id == UINT16_C(5939)
                        || (first.form_id >= UINT16_C(5941)
                            && first.form_id <= UINT16_C(5943)))));
            invariant(first.operand_count
                == (memory_destination || memory_source ? 2u : 3u));
            invariant(first.opcode[0].type == (memory_destination
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
            invariant(first.opcode[0].size
                == (memory_destination ? (is_single ? 4u : 8u) : 16u));
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[1].type == (memory_source
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
            invariant(first.opcode[1].size
                == (memory_source ? (is_single ? 4u : 8u) : 16u));
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            if (first.operand_count == 3u) {
                invariant(first.opcode[2].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[2].size == 16u);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
            }
            invariant(((modrm & UINT8_C(0xc0)) != UINT8_C(0xc0))
                == (memory_destination || memory_source));
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.encoding.immediate_count == 0u);
            invariant((control & UINT8_C(3))
                == (is_single ? UINT8_C(2) : UINT8_C(3)));
            invariant(!(memory_destination || memory_source)
                || (control & UINT8_C(0x78)) == UINT8_C(0x78));
            invariant(code[opcode_offset - 2u] == UINT8_C(0xc5)
                || (code[opcode_offset - 3u] == UINT8_C(0xc4)
                    && (code[opcode_offset - 2u] & UINT8_C(0x1f))
                        == UINT8_C(1)));
            invariant((opcode == UINT8_C(0x10)
                    && (first.form_id == UINT16_C(5911)
                        || first.form_id == UINT16_C(5912)
                        || first.form_id == UINT16_C(5941)
                        || first.form_id == UINT16_C(5942)))
                || (opcode == UINT8_C(0x11)
                    && (first.form_id == UINT16_C(5910)
                        || first.form_id == UINT16_C(5913)
                        || first.form_id == UINT16_C(5939)
                        || first.form_id == UINT16_C(5943))));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512F_SCALAR));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_AVX) != 0u);
        }
        if (is_old_vector) {
            invariant(first.operand_count == 3u);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            if (first.name_id >= CDISASM_X86_NAME_VPADDB
                && first.opcode[0].size == 32u) {
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX2));
            }
        }
        if (is_bmi) {
            invariant(first.operand_count >= 2u
                && first.operand_count <= 3u);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_BMI1)
                || cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_BMI2));
        }
        if (is_f16c) {
            invariant(first.operand_count >= 2u
                && first.operand_count <= 3u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_F16C));
        }
        if (is_fma3) {
            invariant(first.operand_count == 3u);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_FMA3));
        }
        if (is_avx_vnni || is_avx_vnni_int8 || is_avx_vnni_int16) {
            const cdisasm_x86_group_id vnni_group = is_avx_vnni
                ? CDISASM_X86_GROUP_AVX_VNNI
                : (is_avx_vnni_int8
                    ? CDISASM_X86_GROUP_AVX_VNNI_INT8
                    : CDISASM_X86_GROUP_AVX_VNNI_INT16);

            invariant(first.operand_count == 3u);
            invariant(first.opcode[0].type
                == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
            invariant(first.opcode[1].type
                == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[2].type
                    == CDISASM_OPERAND_REGISTER
                || first.opcode[2].type == CDISASM_OPERAND_MEMORY);
            invariant(first.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[0].size == first.opcode[1].size);
            invariant(first.opcode[0].size == first.opcode[2].size);
            invariant(first.encoding.immediate_count == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_instruction_has_x86_group(
                    &first, vnni_group));
            invariant(!cdisasm_instruction_has_x86_group(
                    &first, vnni_group == CDISASM_X86_GROUP_AVX_VNNI
                        ? CDISASM_X86_GROUP_AVX_VNNI_INT8
                        : CDISASM_X86_GROUP_AVX_VNNI));
            invariant(!cdisasm_instruction_has_x86_group(
                    &first, vnni_group == CDISASM_X86_GROUP_AVX_VNNI_INT16
                        ? CDISASM_X86_GROUP_AVX_VNNI_INT8
                        : CDISASM_X86_GROUP_AVX_VNNI_INT16));
        }
        if (is_fma4) {
            invariant(first.operand_count == 4u);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_FMA4));
        }
        if (is_amx) {
            invariant(first.operand_count == 0u
                || first.operand_count == 1u
                || first.operand_count == 2u
                || first.operand_count == 3u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AMX_TILE));
            invariant(mode == CDISASM_MODE_64);
        }
        if (is_map23_vector) {
            int has_immediate = first.name_id == CDISASM_X86_NAME_VPALIGNR
                || first.name_id == CDISASM_X86_NAME_VPCLMULQDQ
                || first.name_id == CDISASM_X86_NAME_VAESKEYGENASSIST;
            int is_unary = first.name_id == CDISASM_X86_NAME_VAESIMC
                || first.name_id == CDISASM_X86_NAME_VAESKEYGENASSIST;

            invariant(first.operand_count
                == (unsigned int)(is_unary ? 2 + has_immediate
                                           : 3 + has_immediate));
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(!has_immediate
                || first.opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
        }
        if (is_vpermil2) {
            unsigned int selector_operand =
                (code[2] & UINT8_C(0x80)) != 0u ? 2u : 3u;
            cdisasm_x86_reg_id selector_reg =
                first.opcode[selector_operand].reg;

            invariant(first.operand_count == 5u);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[selector_operand].type
                == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[selector_operand].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[4].type == CDISASM_OPERAND_IMMEDIATE);
            invariant(first.encoding.immediate_count == 1u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_XOP));
            if (first.opcode[selector_operand].size == 16u) {
                invariant(selector_reg >= CDISASM_X86_REG_XMM0);
                invariant(selector_reg <= (mode == CDISASM_MODE_64
                    ? CDISASM_X86_REG_XMM15 : CDISASM_X86_REG_XMM7));
            } else {
                invariant(first.opcode[selector_operand].size == 32u);
                invariant(selector_reg >= CDISASM_X86_REG_YMM0);
                invariant(selector_reg <= (mode == CDISASM_MODE_64
                    ? CDISASM_X86_REG_YMM15 : CDISASM_X86_REG_YMM7));
            }
        }
        if (is_kmask) {
            int has_avx512f = cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512F);
            int has_avx10_1 = cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX10_1);

            invariant(first.operand_count == 2u
                || first.operand_count == 3u);
            /* Legacy profiles expose the AVX-512 route, while the abstract
               AVX10/APX profiles expose the independently gated AVX10.1
               route for these shared encodings. */
            invariant(has_avx512f != has_avx10_1);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
        }
        if (is_avx_core) {
            uint8_t operand_index;

            invariant(first.operand_count == 2u
                || first.operand_count == 3u);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            for (operand_index = 1u;
                 operand_index < first.operand_count;
                 ++operand_index) {
                invariant(first.opcode[operand_index].access
                    == CDISASM_OPERAND_ACCESS_READ);
            }
        }
        if (is_vmul_fp) {
            const unsigned int vex_size =
                code[first.encoding.opcode_offset - 2u] == UINT8_C(0xc5)
                    ? 2u : 3u;
            const uint8_t lead = code[first.encoding.opcode_offset
                - vex_size];
            const uint8_t p1 = code[first.encoding.opcode_offset - 1u];
            const uint8_t modrm = first.encoding.modrm;
            const unsigned int l = ((unsigned int)p1 >> 2) & 1u;
            const unsigned int pp = p1 & UINT8_C(3);
            const int scalar = first.name_id == CDISASM_X86_NAME_VMULSS
                || first.name_id == CDISASM_X86_NAME_VMULSD;
            const int is_double = first.name_id == CDISASM_X86_NAME_VMULPD
                || first.name_id == CDISASM_X86_NAME_VMULSD;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const unsigned int vector_bytes = scalar ? 16u : 16u << l;
            const unsigned int memory_bytes = scalar
                ? (is_double ? 8u : 4u) : vector_bytes;
            const cdisasm_x86_form_id base_form =
                first.name_id == CDISASM_X86_NAME_VMULPD
                    ? (l == 0u ? UINT16_C(6012) : UINT16_C(6018))
                : first.name_id == CDISASM_X86_NAME_VMULPS
                    ? (l == 0u ? UINT16_C(6028) : UINT16_C(6034))
                : first.name_id == CDISASM_X86_NAME_VMULSD
                    ? UINT16_C(6038) : UINT16_C(6044);

            invariant(lead == UINT8_C(0xc5) || lead == UINT8_C(0xc4));
            invariant(vex_size == (lead == UINT8_C(0xc5) ? 2u : 3u));
            invariant(first.encoding.prefix_size >= vex_size);
            invariant(lead != UINT8_C(0xc4)
                || (code[first.encoding.opcode_offset - 2u]
                    & UINT8_C(0x1f)) == UINT8_C(1));
            invariant(code[first.encoding.opcode_offset] == UINT8_C(0x59));
            invariant(pp == (first.name_id == CDISASM_X86_NAME_VMULPS
                    ? 0u : first.name_id == CDISASM_X86_NAME_VMULPD
                    ? 1u : first.name_id == CDISASM_X86_NAME_VMULSS
                    ? 2u : 3u));
            invariant(first.form_id == (cdisasm_x86_form_id)(base_form
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].size == vector_bytes);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].size == vector_bytes);
            invariant(first.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[2].type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(first.opcode[2].size == (register_form
                ? vector_bytes : memory_bytes));
            invariant(first.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[2].broadcast == CDISASM_X86_BROADCAST_NONE);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.encoding.immediate_count == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512F_128));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512F_256));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512F_512));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512F_SCALAR));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
        }
        if (is_vor_fp) {
            const unsigned int vex_size =
                code[first.encoding.opcode_offset - 2u] == UINT8_C(0xc5)
                    ? 2u : 3u;
            const uint8_t lead = code[first.encoding.opcode_offset
                - vex_size];
            const uint8_t p1 = code[first.encoding.opcode_offset - 1u];
            const uint8_t modrm = first.encoding.modrm;
            const unsigned int l = ((unsigned int)p1 >> 2) & 1u;
            const unsigned int pp = p1 & UINT8_C(3);
            const int is_double =
                first.name_id == CDISASM_X86_NAME_VORPD;
            const int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            const unsigned int vector_bytes = 16u << l;
            const cdisasm_x86_form_id base_form = is_double
                ? (l == 0u ? UINT16_C(6054) : UINT16_C(6058))
                : (l == 0u ? UINT16_C(6064) : UINT16_C(6068));

            invariant(lead == UINT8_C(0xc5) || lead == UINT8_C(0xc4));
            invariant(vex_size == (lead == UINT8_C(0xc5) ? 2u : 3u));
            invariant(first.encoding.prefix_size >= vex_size);
            invariant(lead != UINT8_C(0xc4)
                || (code[first.encoding.opcode_offset - 2u]
                    & UINT8_C(0x1f)) == UINT8_C(1));
            invariant(code[first.encoding.opcode_offset] == UINT8_C(0x56));
            invariant(pp == (is_double ? 1u : 0u));
            invariant(first.form_id == (cdisasm_x86_form_id)(base_form
                + (register_form ? 1u : 0u)));
            invariant(first.operand_count == 3u);
            invariant((first.opcode_flags
                & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                    | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                    | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                == 0u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].size == vector_bytes);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].size == vector_bytes);
            invariant(first.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[2].type == (register_form
                ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(first.opcode[2].size == vector_bytes);
            invariant(first.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
            invariant(first.opcode[2].broadcast == CDISASM_X86_BROADCAST_NONE);
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
            invariant(first.sae == CDISASM_X86_SAE_NONE);
            invariant(first.encoding.immediate_count == 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512DQ));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512DQ_128));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512DQ_256));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX512DQ_512));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
        }
        if (is_modern_crypto) {
            invariant(first.operand_count >= 2u
                && first.operand_count <= 4u);
            if (first.name_id <= CDISASM_X86_NAME_VSHA512RNDS2) {
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_SHA512));
            } else if (first.name_id <= CDISASM_X86_NAME_VSM3RNDS2) {
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_SM3));
            } else {
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_SM4));
            }
        }
        if (is_variable_shift) {
            uint8_t vex_p1 = code[first.encoding.opcode_offset - 1u];
            uint8_t opcode = code[first.encoding.opcode_offset];
            int w = (vex_p1 & UINT8_C(0x80)) != 0u;

            invariant(first.name_id != CDISASM_X86_NAME_VPSRAVQ);
            invariant(first.operand_count == 3u);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant((code[first.encoding.opcode_offset - 2u]
                    & UINT8_C(0x1f)) == UINT8_C(0x02));
            invariant((vex_p1 & UINT8_C(0x03)) == UINT8_C(0x01));
            invariant((opcode == UINT8_C(0x47)
                    && first.name_id == (w
                        ? CDISASM_X86_NAME_VPSLLVQ
                        : CDISASM_X86_NAME_VPSLLVD))
                || (opcode == UINT8_C(0x45)
                    && first.name_id == (w
                        ? CDISASM_X86_NAME_VPSRLVQ
                        : CDISASM_X86_NAME_VPSRLVD))
                || (opcode == UINT8_C(0x46) && !w
                    && first.name_id == CDISASM_X86_NAME_VPSRAVD));
        }
#else
        invariant(is_zero);
#endif
#if USE_EXTRA_OPCODES
        /* AMX uses the VEX encoding envelope without depending on CPUID.AVX.
         * VPMASKMOVD/Q is catalogued directly in AVX2 rather than carrying a
         * redundant AVX group.  Their exact groups are checked above. */
        invariant(is_amx || is_bsr || is_user_msr || is_msr_imm
            || is_vex_vpmaskmov
            || cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
#else
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_AVX));
#endif
    }
    if ((first.opcode_flags & CDISASM_PREFIX_XOP) != 0u) {
        invariant(first.encoding.prefix_size >= 3u);
        invariant(first.encoding.opcode_offset == first.encoding.prefix_size);
        invariant(first.encoding.opcode_size == 1u);
    }
    if ((first.opcode_flags & CDISASM_PREFIX_XOP) != 0u
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
#if USE_EXTRA_OPCODES
        int is_map9_unary =
            first.name_id >= CDISASM_X86_NAME_VFRCZPS
            && first.name_id <= CDISASM_X86_NAME_VPHSUBDQ;
        int is_map8_extended =
            first.name_id >= CDISASM_X86_NAME_VPMACSSWW
            && first.name_id <= CDISASM_X86_NAME_VPPERM;
        int is_map8_compare =
            first.name_id >= CDISASM_X86_NAME_VPCOMB
            && first.name_id <= CDISASM_X86_NAME_VPCOMUQ;
        int is_map8_is4 = is_map8_extended && !is_map8_compare;

        invariant((first.name_id >= CDISASM_X86_NAME_VPROTB
                && first.name_id <= CDISASM_X86_NAME_VPCMOV)
            || (first.name_id >= CDISASM_X86_NAME_VPSHLB
                && first.name_id <= CDISASM_X86_NAME_VPSHAQ)
            || is_map9_unary || is_map8_extended);
        invariant(first.operand_count
                == (is_map9_unary ? 2u : (is_map8_extended ? 4u : 3u))
            || (!is_map9_unary && !is_map8_extended
                && first.operand_count == 4u));
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_XOP));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_AVX));
        if (is_map8_extended) {
            if (first.name_id == CDISASM_X86_NAME_VPPERM) {
                invariant(first.encoding.immediate_count == 0u);
                invariant(first.encoding.selector_offset + 1u
                    == first_size);
            } else {
                invariant(first.encoding.immediate_count == 1u);
                invariant(first.encoding.immediate_size[0] == 1u);
                invariant(first.encoding.immediate_offset[0]
                        + first.encoding.immediate_size[0]
                    == first_size);
            }
            if (is_map8_compare) {
                invariant(first.opcode[3].type
                    == CDISASM_OPERAND_IMMEDIATE);
            }
        }
        if (is_map8_is4) {
            size_t xop_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            unsigned int selector_operand =
                (code[xop_offset + 2u] & UINT8_C(0x80)) != 0u
                ? 2u : 3u;
            cdisasm_x86_reg_id selector_reg =
                first.opcode[selector_operand].reg;

            invariant(first.opcode[selector_operand].type
                == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[selector_operand].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(selector_reg >= CDISASM_X86_REG_XMM0);
            invariant(selector_reg <= (mode == CDISASM_MODE_64
                ? CDISASM_X86_REG_XMM15 : CDISASM_X86_REG_XMM7));
        }
        if (first.name_id == CDISASM_X86_NAME_VPCMOV) {
            size_t xop_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            uint8_t p0 = code[xop_offset + 1u];
            uint8_t p1 = code[xop_offset + 2u];
            uint8_t modrm = code[first.encoding.modrm_offset];
            int w = (p1 & UINT8_C(0x80)) != 0u;
            int l = (p1 & UINT8_C(0x04)) != 0u;
            int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            unsigned int memory_or_rm_operand = w ? 3u : 2u;
            unsigned int selector_operand = w ? 2u : 3u;
            unsigned int selector_reg =
                (unsigned int)(code[first.encoding.selector_offset] >> 4)
                & (mode == CDISASM_MODE_64 ? 15u : 7u);
            unsigned int operand_index;

            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(0x08));
            invariant((p1 & UINT8_C(0x03)) == 0u);
            invariant(code[first.encoding.opcode_offset]
                == UINT8_C(0xa2));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                UINT16_C(6410) + (l ? 3u : 0u)
                + (register_form ? 2u : (w ? 1u : 0u))));
            invariant(first.operand_count == 4u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset + 1u == first_size);
            invariant(first.opcode[memory_or_rm_operand].type
                == (register_form
                    ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(first.opcode[selector_operand].type
                == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[selector_operand].reg
                == (cdisasm_x86_reg_id)((l
                    ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0)
                    + selector_reg));
            for (operand_index = 0u; operand_index < 4u;
                 ++operand_index) {
                invariant(first.opcode[operand_index].size
                    == (l ? 32u : 16u));
                invariant(first.opcode[operand_index].access
                    == (operand_index == 0u
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ));
                invariant(first.opcode[operand_index].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
            }
        } else if (first.name_id == CDISASM_X86_NAME_VPPERM) {
            size_t xop_offset =
                (size_t)first.encoding.opcode_offset - 3u;
            uint8_t p0 = code[xop_offset + 1u];
            uint8_t p1 = code[xop_offset + 2u];
            uint8_t modrm = code[first.encoding.modrm_offset];
            int w = (p1 & UINT8_C(0x80)) != 0u;
            int register_form =
                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
            unsigned int memory_or_rm_operand = w ? 3u : 2u;
            unsigned int selector_operand = w ? 2u : 3u;
            unsigned int selector_reg =
                (unsigned int)(code[first.encoding.selector_offset] >> 4)
                & (mode == CDISASM_MODE_64 ? 15u : 7u);
            unsigned int operand_index;

            invariant((p0 & UINT8_C(0x1f)) == UINT8_C(0x08));
            invariant((p1 & UINT8_C(0x07)) == 0u);
            invariant(code[first.encoding.opcode_offset]
                == UINT8_C(0xa3));
            invariant(first.form_id == (cdisasm_x86_form_id)(
                UINT16_C(7686) + (register_form ? 2u : (w ? 1u : 0u))));
            invariant(first.operand_count == 4u);
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.selector_offset + 1u == first_size);
            invariant(first.opcode[memory_or_rm_operand].type
                == (register_form
                    ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
            invariant(first.opcode[selector_operand].type
                == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[selector_operand].reg
                == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0
                    + selector_reg));
            for (operand_index = 0u; operand_index < 4u;
                 ++operand_index) {
                invariant(first.opcode[operand_index].size == 16u);
                invariant(first.opcode[operand_index].access
                    == (operand_index == 0u
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ));
                invariant(first.opcode[operand_index].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
            }
        }
#else
        invariant(0);
#endif
    }
    if ((first.opcode_flags & CDISASM_PREFIX_EVEX) != 0u) {
#if USE_EXTRA_OPCODES
        invariant(first.encoding.prefix_size >= 4u);
        invariant(first.encoding.opcode_offset == first.encoding.prefix_size);
        invariant(first.encoding.opcode_size == 1u);
        if ((first.opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u) {
            const int exact_packed_compare =
                first.name_id == CDISASM_X86_NAME_VPCMPEQB
                || first.name_id == CDISASM_X86_NAME_VPCMPEQD
                || first.name_id == CDISASM_X86_NAME_VPCMPEQW
                || first.name_id == CDISASM_X86_NAME_VPCMPGTB
                || first.name_id == CDISASM_X86_NAME_VPCMPGTD;

            if (exact_packed_compare) {
                const int bw_family =
                    first.name_id == CDISASM_X86_NAME_VPCMPEQB
                    || first.name_id == CDISASM_X86_NAME_VPCMPEQW
                    || first.name_id == CDISASM_X86_NAME_VPCMPGTB;
                const cdisasm_x86_form_id form_base =
                    first.name_id == CDISASM_X86_NAME_VPCMPEQB
                        ? UINT16_C(6428)
                    : first.name_id == CDISASM_X86_NAME_VPCMPEQD
                        ? UINT16_C(6438)
                    : first.name_id == CDISASM_X86_NAME_VPCMPEQW
                        ? UINT16_C(6458)
                    : first.name_id == CDISASM_X86_NAME_VPCMPGTB
                        ? UINT16_C(6476) : UINT16_C(6486);
                const unsigned int relative =
                    (unsigned int)(first.form_id - form_base);
                const unsigned int vector_size = relative < 6u
                    ? 16u << (relative / 2u) : 0u;
                const unsigned int element_size =
                    first.name_id == CDISASM_X86_NAME_VPCMPEQB
                        || first.name_id == CDISASM_X86_NAME_VPCMPGTB
                    ? 1u
                    : first.name_id == CDISASM_X86_NAME_VPCMPEQW
                        ? 2u : 4u;
                const int memory_form = (relative & 1u) == 0u;
                const cdisasm_x86_reg_id register_base =
                    vector_size == 16u ? CDISASM_X86_REG_XMM0
                    : vector_size == 32u ? CDISASM_X86_REG_YMM0
                                         : CDISASM_X86_REG_ZMM0;
                const cdisasm_x86_group_id width_group = bw_family
                    ? (vector_size == 16u
                        ? CDISASM_X86_GROUP_AVX512BW_128
                        : vector_size == 32u
                            ? CDISASM_X86_GROUP_AVX512BW_256
                            : CDISASM_X86_GROUP_AVX512BW_512)
                    : (vector_size == 16u
                        ? CDISASM_X86_GROUP_AVX512F_128
                        : vector_size == 32u
                            ? CDISASM_X86_GROUP_AVX512F_256
                            : CDISASM_X86_GROUP_AVX512F_512);
                const uint32_t width_bit = bw_family
                    ? (vector_size == 16u
                        ? CDISASM_X86_DECODE_BIT_AVX512BW_128
                        : vector_size == 32u
                            ? CDISASM_X86_DECODE_BIT_AVX512BW_256
                            : CDISASM_X86_DECODE_BIT_AVX512BW_512)
                    : (vector_size == 16u
                        ? CDISASM_X86_DECODE_BIT_AVX512F_128
                        : vector_size == 32u
                            ? CDISASM_X86_DECODE_BIT_AVX512F_256
                            : CDISASM_X86_DECODE_BIT_AVX512F_512);

                invariant(relative < 6u);
                invariant(first.operand_count == 3u);
                invariant((first.opcode_flags
                    & ~(CDISASM_PREFIX_EVEX
                        | CDISASM_PREFIX_ADDRESS_SIZE
                        | CDISASM_PREFIX_SEGMENT
                        | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK))
                    == 0u);
                invariant((first.opcode_flags
                    & (CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                        | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                        | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                    == 0u);
                invariant(first.opcode_groups == CDISASM_GROUP_NONE);
                invariant(first.branch_target == 0u);
                invariant(first.mask_mode == CDISASM_X86_MASK_NONE
                    || first.mask_mode == CDISASM_X86_MASK_MERGE);
                invariant((first.mask_mode == CDISASM_X86_MASK_NONE)
                    == (first.mask_reg == CDISASM_X86_REG_NONE));
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.modrm_offset
                    == first.encoding.opcode_offset + 1u);
                invariant(first.encoding.immediate_count == 0u);
                invariant(first.encoding.selector_offset == 0u);
                invariant(((first.encoding.modrm & UINT8_C(0xc0))
                        != UINT8_C(0xc0)) == memory_form);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].reg >= CDISASM_X86_REG_K0
                    && first.opcode[0].reg <= CDISASM_X86_REG_K7);
                invariant(first.opcode[0].size == 8u);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                invariant(first.opcode[0].flags == 0u);
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].reg >= register_base
                    && first.opcode[1].reg <= register_base + 31u);
                invariant(first.opcode[1].size == vector_size);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[1].flags == 0u);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[2].type == (memory_form
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER));
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                if (memory_form) {
                    invariant((first.opcode[2].size == vector_size
                            && first.opcode[2].broadcast
                                == CDISASM_X86_BROADCAST_NONE)
                        || (!bw_family
                            && first.opcode[2].size == element_size
                            && first.opcode[2].broadcast
                                == (cdisasm_x86_broadcast)(
                                    vector_size / element_size)));
                    invariant((first.opcode[2].flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                            | CDISASM_OPERAND_FLAG_SIGNED)) == 0u);
                } else {
                    invariant(first.opcode[2].reg >= register_base
                        && first.opcode[2].reg <= register_base + 31u);
                    invariant(first.opcode[2].size == vector_size);
                    invariant(first.opcode[2].flags == 0u);
                    invariant(first.opcode[2].broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                }
                invariant(cdisasm_instruction_has_x86_group(
                    &first, width_group));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, width_bit));
            }
        } else if ((first.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0u) {
            invariant(first.name_id == CDISASM_X86_NAME_ADD
                || first.name_id == CDISASM_X86_NAME_OR
                || first.name_id == CDISASM_X86_NAME_ADC
                || first.name_id == CDISASM_X86_NAME_SBB
                || first.name_id == CDISASM_X86_NAME_AND
                || first.name_id == CDISASM_X86_NAME_SUB
                || first.name_id == CDISASM_X86_NAME_XOR
                || first.name_id == CDISASM_X86_NAME_PUSH2
                || first.name_id == CDISASM_X86_NAME_POP2);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
        } else {
            int is_apx_evex = cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F);
            int is_apx_rao_int = cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F_RAO_INT);
            int has_ace_1 = cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_ACE_1);
            int is_ace_tilemov = has_ace_1
                && (first.name_id == CDISASM_X86_NAME_TILEMOVROW
                    || first.name_id == CDISASM_X86_NAME_TILEMOVCOL);
            int is_ace_top = has_ace_1
                && first.name_id >= CDISASM_X86_NAME_TOP2BF16PS
                && first.name_id <= CDISASM_X86_NAME_TOP4MXHF8PS;
            int is_ace_bsr = has_ace_1
                && first.name_id >= CDISASM_X86_NAME_BSRMOVF
                && first.name_id <= CDISASM_X86_NAME_BSRMOVL;
            int is_user_msr =
                cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F_USER_MSR)
                && (first.name_id == CDISASM_X86_NAME_URDMSR
                    || first.name_id == CDISASM_X86_NAME_UWRMSR);
            int is_msr_imm = cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F_MSR_IMM);
            int is_amx_row = !has_ace_1
                && first.name_id >= CDISASM_X86_NAME_TCVTROWD2PS
                && first.name_id <= CDISASM_X86_NAME_TILEMOVROW;
            int is_avx10_bf16 =
                first.name_id >= CDISASM_X86_NAME_VADDBF16
                && first.name_id <= CDISASM_X86_NAME_VDIVBF16;
            int is_compare_mask =
                first.name_id >= CDISASM_X86_NAME_VPCMPB
                && first.name_id <= CDISASM_X86_NAME_VPCMPUQ;
            int is_integer_minmax =
                (first.name_id >= CDISASM_X86_NAME_VPMAXSW
                    && first.name_id <= CDISASM_X86_NAME_VPMINUB)
                || (first.name_id >= CDISASM_X86_NAME_VPMINSB
                    && first.name_id <= CDISASM_X86_NAME_VPMAXUQ);
            int is_integer_multiply =
                (first.name_id >= CDISASM_X86_NAME_VPMULLW
                    && first.name_id <= CDISASM_X86_NAME_VPMADDWD)
                || (first.name_id >= CDISASM_X86_NAME_VPMULLD
                    && first.name_id <= CDISASM_X86_NAME_VPMADDUBSW);
            int is_integer_add_sub =
                (first.name_id >= CDISASM_X86_NAME_VPADDB
                    && first.name_id <= CDISASM_X86_NAME_VPSUBQ)
                || (first.name_id >= CDISASM_X86_NAME_VPADDSB
                    && first.name_id <= CDISASM_X86_NAME_VPSUBUSW);
            int is_modular_add_sub =
                first.name_id == CDISASM_X86_NAME_VPADDB
                || first.name_id == CDISASM_X86_NAME_VPADDW
                || first.name_id == CDISASM_X86_NAME_VPADDD
                || first.name_id == CDISASM_X86_NAME_VPADDQ
                || first.name_id == CDISASM_X86_NAME_VPSUBB
                || first.name_id == CDISASM_X86_NAME_VPSUBW
                || first.name_id == CDISASM_X86_NAME_VPSUBD
                || first.name_id == CDISASM_X86_NAME_VPSUBQ;
            int is_integer_average =
                first.name_id >= CDISASM_X86_NAME_VPAVGB
                && first.name_id <= CDISASM_X86_NAME_VPAVGW;
            int is_integer_logical =
                first.name_id >= CDISASM_X86_NAME_VPANDD
                && first.name_id <= CDISASM_X86_NAME_VPXORQ;
            int is_variable_shift =
                first.name_id >= CDISASM_X86_NAME_VPSLLVD
                && first.name_id <= CDISASM_X86_NAME_VPRORVQ;
            int is_immediate_shift_rotate =
                first.name_id >= CDISASM_X86_NAME_VPROLD
                && first.name_id <= CDISASM_X86_NAME_VPSLLDQ;
            int is_vbmi2_double_shift =
                first.name_id >= CDISASM_X86_NAME_VPSHLDW
                && first.name_id <= CDISASM_X86_NAME_VPSHRDVQ;
            int is_compress_expand =
                (first.name_id >= CDISASM_X86_NAME_VPCOMPRESSB
                    && first.name_id <= CDISASM_X86_NAME_VPEXPANDQ)
                || first.name_id == CDISASM_X86_NAME_VCOMPRESSPD
                || first.name_id == CDISASM_X86_NAME_VCOMPRESSPS
                || first.name_id == CDISASM_X86_NAME_VEXPANDPD
                || first.name_id == CDISASM_X86_NAME_VEXPANDPS;
            int is_popcount =
                first.name_id == CDISASM_X86_NAME_VPOPCNTB
                || first.name_id == CDISASM_X86_NAME_VPOPCNTW
                || first.name_id == CDISASM_X86_NAME_VPOPCNTD
                || first.name_id == CDISASM_X86_NAME_VPOPCNTQ;
            int is_bitalg_mask_destination =
                first.name_id == CDISASM_X86_NAME_VPSHUFBITQMB;
            int is_avx512cd_unary =
                first.name_id >= CDISASM_X86_NAME_VPCONFLICTD
                && first.name_id <= CDISASM_X86_NAME_VPLZCNTQ;
            int is_avx512cd_mask_broadcast =
                first.name_id >= CDISASM_X86_NAME_VPBROADCASTMB2Q
                && first.name_id <= CDISASM_X86_NAME_VPBROADCASTMW2D;
            int is_avx512cd = is_avx512cd_unary
                || is_avx512cd_mask_broadcast;
            int is_vnni_dot_product =
                first.name_id == CDISASM_X86_NAME_VPDPBUSD
                || (first.name_id >= CDISASM_X86_NAME_VPDPBUSDS
                    && first.name_id <= CDISASM_X86_NAME_VPDPWSSDS);
            int is_avx10_vnni_int8 =
                first.name_id >= CDISASM_X86_NAME_VPDPBSSD
                && first.name_id <= CDISASM_X86_NAME_VPDPBUUDS;
            int is_4vnniw =
                first.name_id == CDISASM_X86_NAME_VP4DPWSSD
                || first.name_id == CDISASM_X86_NAME_VP4DPWSSDS;
            int is_4fmaps =
                first.name_id >= CDISASM_X86_NAME_V4FMADDPS
                && first.name_id <= CDISASM_X86_NAME_V4FNMADDSS;
            int is_vgetexp =
                first.name_id >= CDISASM_X86_NAME_VGETEXPPS
                && first.name_id <= CDISASM_X86_NAME_VGETEXPSD;
            int is_vgetexp16 =
                first.name_id >= CDISASM_X86_NAME_VGETEXPPH
                && first.name_id <= CDISASM_X86_NAME_VGETEXPBF16;
            int is_permute_ternary =
                first.name_id == CDISASM_X86_NAME_VPERMB
                || (first.name_id >= CDISASM_X86_NAME_VPERMI2B
                    && first.name_id
                        <= CDISASM_X86_NAME_VPMULTISHIFTQB)
                || (first.name_id >= CDISASM_X86_NAME_VPERMI2W
                    && first.name_id <= CDISASM_X86_NAME_VPERMW);
            int is_fma3 =
                (first.name_id >= CDISASM_X86_NAME_VFMADD132PS
                    && first.name_id <= CDISASM_X86_NAME_VFMADD132SD)
                || (first.name_id >= CDISASM_X86_NAME_VFMADD213PD
                    && first.name_id <= CDISASM_X86_NAME_VFNMSUB231SD);
            int is_non_temporal_store =
                first.name_id == CDISASM_X86_NAME_VMOVNTDQ
                || first.name_id == CDISASM_X86_NAME_VMOVNTPD
                || first.name_id == CDISASM_X86_NAME_VMOVNTPS;
            int is_non_temporal_load =
                first.name_id == CDISASM_X86_NAME_VMOVNTDQA;
            int is_move_quadword =
                first.name_id == CDISASM_X86_NAME_VMOVQ;
            int is_move_read_shared =
                first.name_id >= CDISASM_X86_NAME_VMOVRSB
                && first.name_id <= CDISASM_X86_NAME_VMOVRSW;
            int is_move_scalar =
                first.name_id == CDISASM_X86_NAME_VMOVSD
                || first.name_id == CDISASM_X86_NAME_VMOVSS;
            int is_move_half_scalar =
                first.name_id == CDISASM_X86_NAME_VMOVSH;
            int is_move_duplicate =
                first.name_id == CDISASM_X86_NAME_VMOVSHDUP
                || first.name_id == CDISASM_X86_NAME_VMOVSLDUP;
            int is_unaligned_packed_move =
                first.name_id == CDISASM_X86_NAME_VMOVUPD
                || first.name_id == CDISASM_X86_NAME_VMOVUPS;
            int is_move_word =
                first.name_id == CDISASM_X86_NAME_VMOVW;
            int is_vmpsadbw =
                first.name_id == CDISASM_X86_NAME_VMPSADBW;
            int is_vdbpsadbw =
                first.name_id == CDISASM_X86_NAME_VDBPSADBW;
            int is_vpternlog =
                first.name_id == CDISASM_X86_NAME_VPTERNLOGD
                || first.name_id == CDISASM_X86_NAME_VPTERNLOGQ;
            int is_vptest_mask =
                first.name_id == CDISASM_X86_NAME_VPTESTMB
                || first.name_id == CDISASM_X86_NAME_VPTESTMD
                || first.name_id == CDISASM_X86_NAME_VPTESTMQ
                || first.name_id == CDISASM_X86_NAME_VPTESTMW
                || first.name_id == CDISASM_X86_NAME_VPTESTNMB
                || first.name_id == CDISASM_X86_NAME_VPTESTNMD
                || first.name_id == CDISASM_X86_NAME_VPTESTNMQ
                || first.name_id == CDISASM_X86_NAME_VPTESTNMW;
            int is_vmulbf16 =
                first.name_id == CDISASM_X86_NAME_VMULBF16;
            int is_vmulph =
                first.name_id == CDISASM_X86_NAME_VMULPH;
            int is_vmulsh =
                first.name_id == CDISASM_X86_NAME_VMULSH;
            int is_vmul_fp =
                first.name_id == CDISASM_X86_NAME_VMULPS
                || first.name_id == CDISASM_X86_NAME_VMULPD
                || first.name_id == CDISASM_X86_NAME_VMULSS
                || first.name_id == CDISASM_X86_NAME_VMULSD;
            int is_vor_fp = first.name_id == CDISASM_X86_NAME_VORPS
                || first.name_id == CDISASM_X86_NAME_VORPD;
            int is_vp2intersect =
                first.name_id == CDISASM_X86_NAME_VP2INTERSECTD
                || first.name_id == CDISASM_X86_NAME_VP2INTERSECTQ;
            int is_vpabs = first.name_id == CDISASM_X86_NAME_VPABSB
                || first.name_id == CDISASM_X86_NAME_VPABSW
                || first.name_id == CDISASM_X86_NAME_VPABSD
                || first.name_id == CDISASM_X86_NAME_VPABSQ;
            int is_vpack = first.name_id == CDISASM_X86_NAME_VPACKSSDW
                || first.name_id == CDISASM_X86_NAME_VPACKSSWB
                || first.name_id == CDISASM_X86_NAME_VPACKUSDW
                || first.name_id == CDISASM_X86_NAME_VPACKUSWB;
            int is_gfni =
                first.name_id == CDISASM_X86_NAME_VGF2P8AFFINEINVQB
                || first.name_id == CDISASM_X86_NAME_VGF2P8AFFINEQB
                || first.name_id == CDISASM_X86_NAME_VGF2P8MULB;
            int is_avx_core =
                first.name_id >= CDISASM_X86_NAME_VADDSUBPD
                && first.name_id <= CDISASM_X86_NAME_VCVTSS2SD;
            int is_known_vector = first.name_id == CDISASM_X86_NAME_VADDPS
                || first.name_id == CDISASM_X86_NAME_VADDPD
                || first.name_id == CDISASM_X86_NAME_VSUBPS
                || first.name_id == CDISASM_X86_NAME_VSUBPD
                || first.name_id == CDISASM_X86_NAME_VDIVPS
                || first.name_id == CDISASM_X86_NAME_VDIVPD
                || (first.name_id >= CDISASM_X86_NAME_VPERMB
                    && first.name_id <= CDISASM_X86_NAME_VPMADD52HUQ)
                || first.name_id == CDISASM_X86_NAME_VAESENC
                || (first.name_id >= CDISASM_X86_NAME_VAESENCLAST
                    && first.name_id <= CDISASM_X86_NAME_VAESDECLAST)
                || first.name_id == CDISASM_X86_NAME_VPCLMULQDQ
                || is_vor_fp || is_vp2intersect || is_vpabs || is_vpack
                || is_avx10_bf16 || is_avx_core
                || is_integer_minmax
                || is_integer_multiply || is_integer_add_sub
                || is_integer_average || is_integer_logical
                || is_variable_shift || is_immediate_shift_rotate
                || is_vbmi2_double_shift || is_compress_expand
                || is_popcount || is_bitalg_mask_destination
                || is_avx512cd || is_vnni_dot_product
                || is_avx10_vnni_int8
                || is_4vnniw || is_4fmaps || is_vgetexp
                || is_vgetexp16
                || is_permute_ternary || is_fma3
                || is_non_temporal_store || is_non_temporal_load
                || is_move_quadword || is_move_read_shared
                || is_move_scalar || is_move_half_scalar
                || is_move_duplicate || is_unaligned_packed_move
                || is_move_word || is_vmpsadbw || is_vdbpsadbw
                || is_vpternlog || is_vptest_mask
                || is_vmulbf16
                || is_vmulph || is_vmulsh || is_vmul_fp || is_gfni;

            invariant(is_known_vector || is_apx_evex || is_apx_rao_int
                || is_amx_row
                || is_ace_tilemov || is_ace_top || is_ace_bsr
                || is_user_msr || is_msr_imm || is_compare_mask);
            invariant(first.operand_count == 2u
                || first.operand_count == 3u
                || first.operand_count == 4u);
            if (is_known_vector) {
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
            }
            if (is_non_temporal_store) {
                invariant(first.operand_count == 2u);
                invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[0].size == first.opcode[1].size);
                invariant(first.mask_reg == CDISASM_X86_REG_NONE);
                invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
            }
            if (is_non_temporal_load) {
                invariant(first.operand_count == 2u);
                invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                invariant(first.opcode[1].type == CDISASM_OPERAND_MEMORY);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[0].size == first.opcode[1].size);
                invariant(first.mask_reg == CDISASM_X86_REG_NONE);
                invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
            }
            if (is_move_read_shared) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int ll =
                    ((unsigned int)p2 >> 5) & 3u;
                const unsigned int vector_bytes = 16u << ll;
                const cdisasm_x86_group_id width_group =
                    (cdisasm_x86_group_id)(
                        CDISASM_X86_GROUP_AVX10_MOVRS_128 + ll);
                const cdisasm_x86_decode_bit_id width_bit =
                    (cdisasm_x86_decode_bit_id)(
                        CDISASM_X86_DECODE_BIT_AVX10_MOVRS_128 + ll);
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;

                invariant(mode == CDISASM_MODE_64);
                invariant(first.form_id >= UINT16_C(5897)
                    && first.form_id <= UINT16_C(5908));
                invariant(first.operand_count == 2u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].size == vector_bytes);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].type == CDISASM_OPERAND_MEMORY);
                invariant(first.opcode[1].size == vector_bytes);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.mask_mode != CDISASM_X86_MASK_NONE
                    || first.mask_reg == CDISASM_X86_REG_NONE);
                invariant(first.mask_mode == CDISASM_X86_MASK_NONE
                    || (first.mask_reg >= CDISASM_X86_REG_K1
                        && first.mask_reg <= CDISASM_X86_REG_K7));
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant((p0 & UINT8_C(7)) == UINT8_C(5));
                invariant((p1 & UINT8_C(0x78)) == UINT8_C(0x78));
                invariant((p1 & UINT8_C(3)) == UINT8_C(2)
                    || (p1 & UINT8_C(3)) == UINT8_C(3));
                invariant((p2 & UINT8_C(0x18)) == UINT8_C(0x08));
                invariant(ll < 3u);
                invariant((p2 & UINT8_C(0x80)) == 0u
                    || (p2 & UINT8_C(7)) != 0u);
                invariant(code[first.encoding.opcode_offset]
                    == UINT8_C(0x6f));
                invariant((modrm & UINT8_C(0xc0)) != UINT8_C(0xc0));
                invariant(((p1 & UINT8_C(3)) == UINT8_C(3)
                        && (p1 & UINT8_C(0x80)) == 0u
                        && first.name_id == CDISASM_X86_NAME_VMOVRSB
                        && first.form_id == UINT16_C(5897) + ll)
                    || ((p1 & UINT8_C(3)) == UINT8_C(2)
                        && (p1 & UINT8_C(0x80)) == 0u
                        && first.name_id == CDISASM_X86_NAME_VMOVRSD
                        && first.form_id == UINT16_C(5900) + ll)
                    || ((p1 & UINT8_C(3)) == UINT8_C(2)
                        && (p1 & UINT8_C(0x80)) != 0u
                        && first.name_id == CDISASM_X86_NAME_VMOVRSQ
                        && first.form_id == UINT16_C(5903) + ll)
                    || ((p1 & UINT8_C(3)) == UINT8_C(3)
                        && (p1 & UINT8_C(0x80)) != 0u
                        && first.name_id == CDISASM_X86_NAME_VMOVRSW
                        && first.form_id == UINT16_C(5906) + ll));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, width_group));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, width_bit));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
            }
            if (is_unaligned_packed_move) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t opcode =
                    code[first.encoding.opcode_offset];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int ll = ((unsigned int)p2 >> 5) & 3u;
                const unsigned int aaa = p2 & UINT8_C(7);
                const unsigned int vector_bytes = 16u << ll;
                const int is_pd =
                    first.name_id == CDISASM_X86_NAME_VMOVUPD;
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int memory_destination =
                    !register_form && opcode == UINT8_C(0x11);
                const int memory_source =
                    !register_form && opcode == UINT8_C(0x10);
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const cdisasm_x86_form_id base_form = is_pd
                    ? UINT16_C(5946) : UINT16_C(5963);
                const unsigned int relative_form = register_form
                    ? (ll == 0u ? 9u : ll == 1u ? 11u : 16u)
                    : opcode == UINT8_C(0x10)
                        ? (ll == 0u ? 8u : ll == 1u ? 10u : 15u)
                        : (ll == 0u ? 1u : ll == 1u ? 2u : 3u);
                const cdisasm_x86_group_id width_group = ll == 0u
                    ? CDISASM_X86_GROUP_AVX512F_128
                    : ll == 1u ? CDISASM_X86_GROUP_AVX512F_256
                               : CDISASM_X86_GROUP_AVX512F_512;
                const cdisasm_x86_decode_bit_id width_bit = ll == 0u
                    ? CDISASM_X86_DECODE_BIT_AVX512F_128
                    : ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512F_256
                               : CDISASM_X86_DECODE_BIT_AVX512F_512;

                invariant(ll < 3u);
                invariant(first.form_id
                    == (cdisasm_x86_form_id)(base_form + relative_form));
                invariant(first.operand_count == 2u);
                invariant(first.opcode[0].type == (memory_destination
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                invariant(first.opcode[0].size == vector_bytes);
                invariant(first.opcode[0].access
                    == (!memory_destination
                            && first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].type == (memory_source
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                invariant(first.opcode[1].size == vector_bytes);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.mask_reg == (aaa == 0u
                    ? CDISASM_X86_REG_NONE
                    : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
                invariant(first.mask_mode == (aaa == 0u
                    ? CDISASM_X86_MASK_NONE
                    : (p2 & UINT8_C(0x80)) != 0u
                        ? CDISASM_X86_MASK_ZERO
                        : CDISASM_X86_MASK_MERGE));
                invariant(first.mask_mode != CDISASM_X86_MASK_ZERO
                    || !memory_destination);
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant((p0 & UINT8_C(7)) == UINT8_C(1));
                invariant((p1 & UINT8_C(0xfb))
                    == (is_pd ? UINT8_C(0xf9) : UINT8_C(0x78)));
                invariant((p2 & UINT8_C(0x18)) == UINT8_C(0x08));
                invariant((p2 & UINT8_C(0x80)) == 0u || aaa != 0u);
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64 && !register_form));
                invariant((p0 & UINT8_C(0x08)) == 0u
                    || mode == CDISASM_MODE_64);
                invariant(opcode == UINT8_C(0x10)
                    || opcode == UINT8_C(0x11));
                if (!register_form
                    && (modrm & UINT8_C(0xc0)) == UINT8_C(0x40)) {
                    const unsigned int memory_operand =
                        memory_destination ? 0u : 1u;

                    invariant((first.opcode[memory_operand].imm
                        & (uint64_t)(vector_bytes - 1u)) == 0u);
                }
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, width_group));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, width_bit));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
            }
            if (is_move_word) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t opcode =
                    code[first.encoding.opcode_offset];
                const uint8_t modrm = first.encoding.modrm;
                const uint8_t prefix = p1 & UINT8_C(3);
                const int fp16 = prefix == UINT8_C(1);
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int memory_destination =
                    !register_form && opcode == UINT8_C(0x7e);
                const int memory_source =
                    !register_form && opcode == UINT8_C(0x6e);
                const int gpr_destination =
                    first.form_id == UINT16_C(5980);
                const int gpr_source =
                    first.form_id == UINT16_C(5983);
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const cdisasm_x86_form_id expected_form = fp16
                    ? (opcode == UINT8_C(0x6e)
                        ? (register_form
                            ? UINT16_C(5983) : UINT16_C(5984))
                        : (register_form
                            ? UINT16_C(5980) : UINT16_C(5981)))
                    : (register_form ? UINT16_C(5986)
                        : opcode == UINT8_C(0x6e)
                            ? UINT16_C(5985) : UINT16_C(5982));
                const cdisasm_x86_group_id exact_group = fp16
                    ? CDISASM_X86_GROUP_AVX512_FP16_128N
                    : CDISASM_X86_GROUP_AVX512_MOVZXC_128;
                const cdisasm_x86_decode_bit_id exact_bit = fp16
                    ? CDISASM_X86_DECODE_BIT_AVX512_FP16_128N
                    : CDISASM_X86_DECODE_BIT_AVX512_MOVZXC_128;

                invariant(first.form_id == expected_form);
                invariant(first.operand_count == 2u);
                invariant(first.opcode[0].type == (memory_destination
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                invariant(first.opcode[0].size == (memory_destination
                    ? 2u : gpr_destination ? 4u : 16u));
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].type == (memory_source
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                invariant(first.opcode[1].size == (memory_source
                    ? 2u : gpr_source ? 4u : 16u));
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.mask_reg == CDISASM_X86_REG_NONE);
                invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant((p0 & UINT8_C(7)) == UINT8_C(5));
                invariant((p1 & UINT8_C(0x78)) == UINT8_C(0x78));
                invariant(prefix == UINT8_C(1)
                    || prefix == UINT8_C(2));
                invariant(fp16 || (p1 & UINT8_C(0x80)) == 0u);
                invariant(p2 == UINT8_C(0x08));
                invariant(opcode == UINT8_C(0x6e)
                    || opcode == UINT8_C(0x7e));
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64 && !register_form));
                invariant((p0 & UINT8_C(0x08)) == 0u
                    || mode == CDISASM_MODE_64);
                if (!register_form
                    && (modrm & UINT8_C(0xc0)) == UINT8_C(0x40)) {
                    const unsigned int memory_operand =
                        memory_destination ? 0u : 1u;

                    invariant((first.opcode[memory_operand].imm
                        & UINT64_C(1)) == 0u);
                }
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, exact_group));
                invariant(!cdisasm_instruction_has_x86_group(
                    &first, fp16
                        ? CDISASM_X86_GROUP_AVX512_MOVZXC_128
                        : CDISASM_X86_GROUP_AVX512_FP16_128N));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, exact_bit));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
            }
            if (is_vmpsadbw) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int ll =
                    ((unsigned int)p2 >> 5) & 3u;
                const unsigned int aaa = p2 & UINT8_C(7);
                const unsigned int vector_bytes = 16u << ll;
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const cdisasm_x86_form_id expected_form = ll == 0u
                    ? (register_form ? UINT16_C(5990) : UINT16_C(5989))
                    : ll == 1u
                        ? (register_form
                            ? UINT16_C(5994) : UINT16_C(5993))
                        : (register_form
                            ? UINT16_C(5996) : UINT16_C(5995));
                const cdisasm_x86_group_id width_group = ll == 0u
                    ? CDISASM_X86_GROUP_AVX512_MEDIAX_128
                    : ll == 1u
                        ? CDISASM_X86_GROUP_AVX512_MEDIAX_256
                        : CDISASM_X86_GROUP_AVX512_MEDIAX_512;
                const cdisasm_x86_decode_bit_id width_bit = ll == 0u
                    ? CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_128
                    : ll == 1u
                        ? CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_256
                        : CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_512;

                invariant(ll < 3u);
                invariant((p0 & UINT8_C(7)) == UINT8_C(3));
                invariant((p1 & UINT8_C(0x83)) == UINT8_C(2));
                invariant((p2 & UINT8_C(0x10)) == 0u);
                invariant((p2 & UINT8_C(0x80)) == 0u || aaa != 0u);
                invariant(code[first.encoding.opcode_offset]
                    == UINT8_C(0x42));
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64 && !register_form));
                invariant((p0 & UINT8_C(0x08)) == 0u
                    || mode == CDISASM_MODE_64);
                invariant(mode == CDISASM_MODE_64
                    || (p2 & UINT8_C(0x08)) != 0u);
                invariant(first.form_id == expected_form);
                invariant(first.operand_count == 4u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].size == vector_bytes);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].size == vector_bytes);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type == (register_form
                    ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
                invariant(first.opcode[2].size == vector_bytes);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[2].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[3].type
                    == CDISASM_OPERAND_IMMEDIATE);
                invariant(first.opcode[3].size == 1u);
                invariant(first.opcode[3].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.mask_reg == (aaa == 0u
                    ? CDISASM_X86_REG_NONE
                    : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
                invariant(first.mask_mode == (aaa == 0u
                    ? CDISASM_X86_MASK_NONE
                    : (p2 & UINT8_C(0x80)) != 0u
                        ? CDISASM_X86_MASK_ZERO
                        : CDISASM_X86_MASK_MERGE));
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 1u);
                invariant(first.encoding.immediate_size[0] == 1u);
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(!cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX2));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, width_group));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, width_bit));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
                if (!register_form
                    && (modrm & UINT8_C(0xc0)) == UINT8_C(0x40)) {
                    invariant((first.opcode[2].imm
                        & (uint64_t)(vector_bytes - 1u)) == 0u);
                }
            }
            if (is_vdbpsadbw) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int ll =
                    ((unsigned int)p2 >> 5) & 3u;
                const unsigned int aaa = p2 & UINT8_C(7);
                const unsigned int vector_bytes = 16u << ll;
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const int has_avx512f =
                    cdisasm_instruction_has_x86_group(
                        &first,CDISASM_X86_GROUP_AVX512F);
                const int has_avx10_1 =
                    cdisasm_instruction_has_x86_group(
                        &first,CDISASM_X86_GROUP_AVX10_1);
                const cdisasm_x86_form_id expected_form =
                    (cdisasm_x86_form_id)(
                        UINT16_C(4453) + 2u * ll
                        + (register_form ? 1u : 0u));
                const cdisasm_x86_group_id width_group = ll == 0u
                    ? CDISASM_X86_GROUP_AVX512BW_128
                    : ll == 1u ? CDISASM_X86_GROUP_AVX512BW_256
                               : CDISASM_X86_GROUP_AVX512BW_512;
                const cdisasm_x86_decode_bit_id width_bit = ll == 0u
                    ? CDISASM_X86_DECODE_BIT_AVX512BW_128
                    : ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512BW_256
                               : CDISASM_X86_DECODE_BIT_AVX512BW_512;

                invariant(ll < 3u);
                invariant((p0 & UINT8_C(7)) == UINT8_C(3));
                invariant((p1 & UINT8_C(0x83)) == UINT8_C(1));
                invariant((p2 & UINT8_C(0x10)) == 0u);
                invariant((p2 & UINT8_C(0x80)) == 0u || aaa != 0u);
                invariant(code[first.encoding.opcode_offset]
                    == UINT8_C(0x42));
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64 && !register_form));
                invariant((p0 & UINT8_C(0x08)) == 0u
                    || mode == CDISASM_MODE_64);
                invariant(mode == CDISASM_MODE_64
                    || (p2 & UINT8_C(0x08)) != 0u);
                invariant(first.form_id == expected_form);
                invariant(first.operand_count == 4u);
                invariant((first.opcode_flags
                    & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                        | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE))
                    == 0u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].size == vector_bytes);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].size == vector_bytes);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type == (register_form
                    ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
                invariant(first.opcode[2].size == vector_bytes);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[2].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[3].type
                    == CDISASM_OPERAND_IMMEDIATE);
                invariant(first.opcode[3].size == 1u);
                invariant(first.opcode[3].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[3].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.mask_reg == (aaa == 0u
                    ? CDISASM_X86_REG_NONE
                    : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
                invariant(first.mask_mode == (aaa == 0u
                    ? CDISASM_X86_MASK_NONE
                    : (p2 & UINT8_C(0x80)) != 0u
                        ? CDISASM_X86_MASK_ZERO
                        : CDISASM_X86_MASK_MERGE));
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 1u);
                invariant(first.encoding.immediate_size[0] == 1u);
                invariant(first.encoding.immediate_offset[0]
                    < first_size);
                invariant(cdisasm_instruction_has_x86_group(
                    &first,CDISASM_X86_GROUP_AVX));
                invariant(has_avx512f != has_avx10_1);
                invariant(!has_avx512f
                    || cdisasm_instruction_has_x86_group(
                        &first,CDISASM_X86_GROUP_AVX512BW));
                invariant(!has_avx512f || ll == 2u
                    || cdisasm_instruction_has_x86_group(
                        &first,CDISASM_X86_GROUP_AVX512VL));
                invariant(!has_avx10_1
                    || !cdisasm_instruction_has_x86_group(
                        &first,CDISASM_X86_GROUP_AVX512VL));
                invariant(cdisasm_instruction_has_x86_group(
                    &first,width_group));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags,width_bit));
                invariant(is_apx_evex == uses_apx);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
                if (!register_form
                    && (modrm & UINT8_C(0xc0)) == UINT8_C(0x40)) {
                    invariant((first.opcode[2].imm
                        & (uint64_t)(vector_bytes - 1u)) == 0u);
                }
            }
            if (is_vpternlog) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int w =
                    (p1 & UINT8_C(0x80)) != 0u;
                const unsigned int ll =
                    ((unsigned int)p2 >> 5) & 3u;
                const unsigned int aaa = p2 & UINT8_C(7);
                const unsigned int vector_bytes = 16u << ll;
                const unsigned int element_bytes = w != 0u ? 8u : 4u;
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int broadcast = !register_form
                    && (p2 & UINT8_C(0x10)) != 0u;
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const int has_avx512f =
                    cdisasm_instruction_has_x86_group(
                        &first,CDISASM_X86_GROUP_AVX512F);
                const int has_avx10_1 =
                    cdisasm_instruction_has_x86_group(
                        &first,CDISASM_X86_GROUP_AVX10_1);
                const cdisasm_x86_form_id expected_form =
                    (cdisasm_x86_form_id)(
                        (w != 0u ? UINT16_C(8265) : UINT16_C(8259))
                        + 2u * ll + (register_form ? 1u : 0u));
                const cdisasm_x86_group_id width_group = ll == 0u
                    ? CDISASM_X86_GROUP_AVX512F_128
                    : ll == 1u ? CDISASM_X86_GROUP_AVX512F_256
                               : CDISASM_X86_GROUP_AVX512F_512;
                const cdisasm_x86_decode_bit_id width_bit = ll == 0u
                    ? CDISASM_X86_DECODE_BIT_AVX512F_128
                    : ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512F_256
                               : CDISASM_X86_DECODE_BIT_AVX512F_512;

                invariant(ll < 3u);
                invariant((p0 & UINT8_C(7)) == UINT8_C(3));
                invariant((p1 & UINT8_C(3)) == UINT8_C(1));
                invariant(code[first.encoding.opcode_offset]
                    == UINT8_C(0x25));
                invariant(!register_form
                    || (p2 & UINT8_C(0x10)) == 0u);
                invariant((p2 & UINT8_C(0x80)) == 0u || aaa != 0u);
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64 && !register_form));
                invariant((p0 & UINT8_C(0x08)) == 0u
                    || mode == CDISASM_MODE_64);
                invariant(mode == CDISASM_MODE_64
                    || (p2 & UINT8_C(0x08)) != 0u);
                invariant(first.name_id == (w != 0u
                    ? CDISASM_X86_NAME_VPTERNLOGQ
                    : CDISASM_X86_NAME_VPTERNLOGD));
                invariant(first.form_id == expected_form);
                invariant(first.operand_count == 4u);
                invariant((first.opcode_flags
                    & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                        | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE))
                    == 0u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].size == vector_bytes);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].size == vector_bytes);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[2].type == (register_form
                    ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
                invariant(first.opcode[2].size == (broadcast
                    ? element_bytes : vector_bytes));
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].broadcast == (broadcast
                    ? (cdisasm_x86_broadcast)(
                        vector_bytes / element_bytes)
                    : CDISASM_X86_BROADCAST_NONE));
                invariant(first.opcode[3].type
                    == CDISASM_OPERAND_IMMEDIATE);
                invariant(first.opcode[3].size == 1u);
                invariant(first.opcode[3].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[3].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.mask_reg == (aaa == 0u
                    ? CDISASM_X86_REG_NONE
                    : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
                invariant(first.mask_mode == (aaa == 0u
                    ? CDISASM_X86_MASK_NONE
                    : (p2 & UINT8_C(0x80)) != 0u
                        ? CDISASM_X86_MASK_ZERO
                        : CDISASM_X86_MASK_MERGE));
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 1u);
                invariant(first.encoding.immediate_size[0] == 1u);
                invariant(first.encoding.immediate_offset[0] < first_size);
                invariant(cdisasm_instruction_has_x86_group(
                    &first,CDISASM_X86_GROUP_AVX));
                invariant(has_avx512f != has_avx10_1);
                invariant(!has_avx512f || ll == 2u
                    || cdisasm_instruction_has_x86_group(
                        &first,CDISASM_X86_GROUP_AVX512VL));
                invariant(!has_avx10_1
                    || !cdisasm_instruction_has_x86_group(
                        &first,CDISASM_X86_GROUP_AVX512VL));
                invariant(cdisasm_instruction_has_x86_group(
                    &first,width_group));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags,width_bit));
                invariant(is_apx_evex == uses_apx);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
                if (!register_form
                    && (modrm & UINT8_C(0xc0)) == UINT8_C(0x40)) {
                    const unsigned int tuple_bytes = broadcast
                        ? element_bytes : vector_bytes;

                    invariant((first.opcode[2].imm
                        & (uint64_t)(tuple_bytes - 1u)) == 0u);
                }
            }
            if (is_vmulbf16) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int ll =
                    ((unsigned int)p2 >> 5) & 3u;
                const unsigned int aaa = p2 & UINT8_C(7);
                const unsigned int vector_bytes = 16u << ll;
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int broadcast = !register_form
                    && (p2 & UINT8_C(0x10)) != 0u;
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const cdisasm_x86_form_id expected_form =
                    (cdisasm_x86_form_id)(
                        UINT16_C(6006) + 2u * ll
                        + (register_form ? 1u : 0u));
                const cdisasm_x86_group_id width_group =
                    (cdisasm_x86_group_id)(
                        CDISASM_X86_GROUP_AVX10_2_BF16_128 + ll);
                const cdisasm_x86_decode_bit_id width_bit =
                    (cdisasm_x86_decode_bit_id)(
                        CDISASM_X86_DECODE_BIT_AVX10_2_BF16_128 + ll);

                invariant(ll < 3u);
                invariant((p0 & UINT8_C(7)) == UINT8_C(5));
                invariant((p1 & UINT8_C(0x83)) == UINT8_C(1));
                invariant(code[first.encoding.opcode_offset]
                    == UINT8_C(0x59));
                invariant(!register_form
                    || (p2 & UINT8_C(0x10)) == 0u);
                invariant((p2 & UINT8_C(0x80)) == 0u || aaa != 0u);
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64 && !register_form));
                invariant((p0 & UINT8_C(0x08)) == 0u
                    || mode == CDISASM_MODE_64);
                invariant(mode == CDISASM_MODE_64
                    || (p2 & UINT8_C(0x08)) != 0u);
                invariant(first.form_id == expected_form);
                invariant(first.operand_count == 3u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].size == vector_bytes);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].size == vector_bytes);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[2].type == (register_form
                    ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
                invariant(first.opcode[2].size
                    == (broadcast ? 2u : vector_bytes));
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].broadcast
                    == (cdisasm_x86_broadcast)(
                        broadcast ? vector_bytes / 2u : 0u));
                invariant(first.mask_reg == (aaa == 0u
                    ? CDISASM_X86_REG_NONE
                    : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
                invariant(first.mask_mode == (aaa == 0u
                    ? CDISASM_X86_MASK_NONE
                    : (p2 & UINT8_C(0x80)) != 0u
                        ? CDISASM_X86_MASK_ZERO
                        : CDISASM_X86_MASK_MERGE));
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_2));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, width_group));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, width_bit));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
                if (!register_form
                    && (modrm & UINT8_C(0xc0)) == UINT8_C(0x40)) {
                    const unsigned int disp8_scale = broadcast
                        ? 2u : vector_bytes;

                    invariant((first.opcode[2].imm
                        & (uint64_t)(disp8_scale - 1u)) == 0u);
                }
            }
            if (is_vmulph || is_vmulsh) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int encoded_ll =
                    ((unsigned int)p2 >> 5) & 3u;
                const unsigned int aaa = p2 & UINT8_C(7);
                const int scalar = is_vmulsh;
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int evex_b = (p2 & UINT8_C(0x10)) != 0u;
                const int embedded_rounding = register_form && evex_b;
                const int broadcast = !scalar && !register_form && evex_b;
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const int has_avx512f =
                    cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512F);
                const int has_fp16 =
                    cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512FP16);
                const int has_avx10_1 =
                    cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX10_1);
                const unsigned int effective_ll = scalar ? 0u
                    : embedded_rounding ? 2u : encoded_ll;
                const unsigned int vector_bytes = 16u << effective_ll;
                const cdisasm_x86_form_id expected_form = scalar
                    ? (cdisasm_x86_form_id)(UINT16_C(6042)
                        + (register_form ? 1u : 0u))
                    : embedded_rounding ? UINT16_C(6027)
                    : (cdisasm_x86_form_id)(UINT16_C(6022)
                        + 2u * encoded_ll + (register_form ? 1u : 0u));
                const cdisasm_x86_group_id width_group = scalar
                    ? CDISASM_X86_GROUP_AVX512_FP16_SCALAR
                    : effective_ll == 0u
                        ? CDISASM_X86_GROUP_AVX512_FP16_128
                        : effective_ll == 1u
                            ? CDISASM_X86_GROUP_AVX512_FP16_256
                            : CDISASM_X86_GROUP_AVX512_FP16_512;
                const cdisasm_x86_decode_bit_id width_bit = scalar
                    ? CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR
                    : effective_ll == 0u
                        ? CDISASM_X86_DECODE_BIT_AVX512_FP16_128
                        : effective_ll == 1u
                            ? CDISASM_X86_DECODE_BIT_AVX512_FP16_256
                            : CDISASM_X86_DECODE_BIT_AVX512_FP16_512;

                invariant((p0 & UINT8_C(7)) == UINT8_C(5));
                invariant((p1 & UINT8_C(0x83))
                    == (scalar ? UINT8_C(2) : UINT8_C(0)));
                invariant(code[first.encoding.opcode_offset]
                    == UINT8_C(0x59));
                invariant(embedded_rounding || encoded_ll < 3u);
                invariant(!scalar || !evex_b || register_form);
                invariant((p2 & UINT8_C(0x80)) == 0u || aaa != 0u);
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64 && !register_form));
                invariant((p0 & UINT8_C(0x08)) == 0u
                    || mode == CDISASM_MODE_64);
                invariant(mode == CDISASM_MODE_64
                    || (p2 & UINT8_C(0x08)) != 0u);
                invariant(first.form_id == expected_form);
                invariant(first.operand_count == 3u);
                invariant((first.opcode_flags
                    & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                        | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE))
                    == 0u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].size == vector_bytes);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].size == vector_bytes);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[2].type == (register_form
                    ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
                invariant(first.opcode[2].size == (!register_form
                        && (scalar || broadcast)
                    ? 2u : vector_bytes));
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].broadcast
                    == (cdisasm_x86_broadcast)(broadcast
                        ? vector_bytes / 2u : 0u));
                invariant(first.mask_reg == (aaa == 0u
                    ? CDISASM_X86_REG_NONE
                    : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
                invariant(first.mask_mode == (aaa == 0u
                    ? CDISASM_X86_MASK_NONE
                    : (p2 & UINT8_C(0x80)) != 0u
                        ? CDISASM_X86_MASK_ZERO
                        : CDISASM_X86_MASK_MERGE));
                invariant(first.rounding == (embedded_rounding
                    ? (cdisasm_x86_rounding_mode)(encoded_ll + 1u)
                    : CDISASM_X86_ROUNDING_NONE));
                invariant(first.sae == (embedded_rounding
                    ? CDISASM_X86_SAE_ENABLED : CDISASM_X86_SAE_NONE));
                invariant(first.encoding.immediate_count == 0u);
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(has_avx10_1 != (has_avx512f && has_fp16));
                if (has_avx512f && !scalar && vector_bytes < 64u) {
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512VL));
                }
                if (has_avx10_1) {
                    invariant(!cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512VL));
                }
                invariant(cdisasm_instruction_has_x86_group(
                    &first, width_group));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, width_bit));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
                if (!register_form
                    && (modrm & UINT8_C(0xc0)) == UINT8_C(0x40)) {
                    const unsigned int disp8_scale = scalar || broadcast
                        ? 2u : vector_bytes;

                    invariant((first.opcode[2].imm
                        & (uint64_t)(disp8_scale - 1u)) == 0u);
                }
            }
            if (is_vmul_fp) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int encoded_ll =
                    ((unsigned int)p2 >> 5) & 3u;
                const unsigned int aaa = p2 & UINT8_C(7);
                const int scalar = first.name_id == CDISASM_X86_NAME_VMULSS
                    || first.name_id == CDISASM_X86_NAME_VMULSD;
                const int is_double =
                    first.name_id == CDISASM_X86_NAME_VMULPD
                    || first.name_id == CDISASM_X86_NAME_VMULSD;
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int evex_b = (p2 & UINT8_C(0x10)) != 0u;
                const int embedded_rounding = register_form && evex_b;
                const int broadcast = !scalar && !register_form && evex_b;
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const int has_avx512f =
                    cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512F);
                const int has_avx10_1 =
                    cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX10_1);
                const unsigned int effective_ll = scalar ? 0u
                    : embedded_rounding ? 2u : encoded_ll;
                const unsigned int vector_bytes = 16u << effective_ll;
                const unsigned int element_bytes = is_double ? 8u : 4u;
                const cdisasm_x86_form_id base_form =
                    first.name_id == CDISASM_X86_NAME_VMULPD
                        ? UINT16_C(6014)
                    : first.name_id == CDISASM_X86_NAME_VMULPS
                        ? UINT16_C(6030)
                    : first.name_id == CDISASM_X86_NAME_VMULSD
                        ? UINT16_C(6040) : UINT16_C(6046);
                const cdisasm_x86_form_id expected_form = scalar
                    ? (cdisasm_x86_form_id)(base_form
                        + (register_form ? 1u : 0u))
                    : embedded_rounding
                        ? (cdisasm_x86_form_id)(base_form + 7u)
                        : (cdisasm_x86_form_id)(base_form
                            + (encoded_ll == 2u ? 6u : 2u * encoded_ll)
                            + (register_form ? 1u : 0u));
                const cdisasm_x86_group_id width_group = scalar
                    ? CDISASM_X86_GROUP_AVX512F_SCALAR
                    : effective_ll == 0u
                        ? CDISASM_X86_GROUP_AVX512F_128
                        : effective_ll == 1u
                            ? CDISASM_X86_GROUP_AVX512F_256
                            : CDISASM_X86_GROUP_AVX512F_512;
                const cdisasm_x86_decode_bit_id width_bit = scalar
                    ? CDISASM_X86_DECODE_BIT_AVX512F_SCALAR
                    : effective_ll == 0u
                        ? CDISASM_X86_DECODE_BIT_AVX512F_128
                        : effective_ll == 1u
                            ? CDISASM_X86_DECODE_BIT_AVX512F_256
                            : CDISASM_X86_DECODE_BIT_AVX512F_512;

                invariant((p0 & UINT8_C(7)) == UINT8_C(1));
                invariant((p1 & UINT8_C(0x83))
                    == (first.name_id == CDISASM_X86_NAME_VMULPS
                        ? UINT8_C(0)
                        : first.name_id == CDISASM_X86_NAME_VMULPD
                            ? UINT8_C(0x81)
                            : first.name_id == CDISASM_X86_NAME_VMULSS
                                ? UINT8_C(2) : UINT8_C(0x83)));
                invariant(code[first.encoding.opcode_offset]
                    == UINT8_C(0x59));
                invariant(embedded_rounding || encoded_ll < 3u);
                invariant(!scalar || !evex_b || register_form);
                invariant((p2 & UINT8_C(0x80)) == 0u || aaa != 0u);
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64 && !register_form));
                invariant((p0 & UINT8_C(0x08)) == 0u
                    || mode == CDISASM_MODE_64);
                invariant(mode == CDISASM_MODE_64
                    || (p2 & UINT8_C(0x08)) != 0u);
                invariant(first.form_id == expected_form);
                invariant(first.operand_count == 3u);
                invariant((first.opcode_flags
                    & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                        | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                        | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                        | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                    == 0u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].size == vector_bytes);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].size == vector_bytes);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type == (register_form
                    ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
                invariant(first.opcode[2].size == (register_form
                    ? vector_bytes
                    : scalar || broadcast ? element_bytes : vector_bytes));
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[2].broadcast
                    == (cdisasm_x86_broadcast)(broadcast
                        ? vector_bytes / element_bytes : 0u));
                invariant(first.mask_reg == (aaa == 0u
                    ? CDISASM_X86_REG_NONE
                    : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
                invariant(first.mask_mode == (aaa == 0u
                    ? CDISASM_X86_MASK_NONE
                    : (p2 & UINT8_C(0x80)) != 0u
                        ? CDISASM_X86_MASK_ZERO
                        : CDISASM_X86_MASK_MERGE));
                invariant(first.rounding == (embedded_rounding
                    ? (cdisasm_x86_rounding_mode)(encoded_ll + 1u)
                    : CDISASM_X86_ROUNDING_NONE));
                invariant(first.sae == (embedded_rounding
                    ? CDISASM_X86_SAE_ENABLED : CDISASM_X86_SAE_NONE));
                invariant(first.encoding.immediate_count == 0u);
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(has_avx512f != has_avx10_1);
                if (has_avx512f && !scalar && vector_bytes < 64u) {
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512VL));
                }
                if (has_avx10_1) {
                    invariant(!cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512VL));
                }
                invariant(cdisasm_instruction_has_x86_group(
                    &first, width_group));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, width_bit));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
                if (!register_form
                    && (modrm & UINT8_C(0xc0)) == UINT8_C(0x40)) {
                    const unsigned int disp8_scale = scalar || broadcast
                        ? element_bytes : vector_bytes;

                    invariant((first.opcode[2].imm
                        & (uint64_t)(disp8_scale - 1u)) == 0u);
                }
            }
            if (is_vor_fp) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int ll = ((unsigned int)p2 >> 5) & 3u;
                const unsigned int aaa = p2 & UINT8_C(7);
                const int is_double =
                    first.name_id == CDISASM_X86_NAME_VORPD;
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int broadcast = !register_form
                    && (p2 & UINT8_C(0x10)) != 0u;
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const int has_avx512dq =
                    cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512DQ);
                const int has_avx10_1 =
                    cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX10_1);
                const unsigned int vector_bytes = 16u << ll;
                const unsigned int element_bytes = is_double ? 8u : 4u;
                const cdisasm_x86_form_id base_form = is_double
                    ? UINT16_C(6056) : UINT16_C(6066);
                const cdisasm_x86_form_id expected_form =
                    (cdisasm_x86_form_id)(base_form
                        + (ll == 0u ? 0u : ll == 1u ? 4u : 6u)
                        + (register_form ? 1u : 0u));
                const cdisasm_x86_group_id width_group = ll == 0u
                    ? CDISASM_X86_GROUP_AVX512DQ_128
                    : ll == 1u ? CDISASM_X86_GROUP_AVX512DQ_256
                               : CDISASM_X86_GROUP_AVX512DQ_512;
                const cdisasm_x86_decode_bit_id width_bit = ll == 0u
                    ? CDISASM_X86_DECODE_BIT_AVX512DQ_128
                    : ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512DQ_256
                               : CDISASM_X86_DECODE_BIT_AVX512DQ_512;

                invariant((p0 & UINT8_C(7)) == UINT8_C(1));
                invariant((p1 & UINT8_C(0x83))
                    == (is_double ? UINT8_C(0x81) : UINT8_C(0)));
                invariant(code[first.encoding.opcode_offset]
                    == UINT8_C(0x56));
                invariant(ll < 3u);
                invariant(!register_form
                    || (p2 & UINT8_C(0x10)) == 0u);
                invariant((p2 & UINT8_C(0x80)) == 0u || aaa != 0u);
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64 && !register_form));
                invariant((p0 & UINT8_C(0x08)) == 0u
                    || mode == CDISASM_MODE_64);
                invariant(mode == CDISASM_MODE_64
                    || (p2 & UINT8_C(0x08)) != 0u);
                invariant(first.form_id == expected_form);
                invariant(first.operand_count == 3u);
                invariant((first.opcode_flags
                    & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                        | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                        | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                        | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                    == 0u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].size == vector_bytes);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].size == vector_bytes);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type == (register_form
                    ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
                invariant(first.opcode[2].size == (!register_form && broadcast
                    ? element_bytes : vector_bytes));
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[2].broadcast
                    == (cdisasm_x86_broadcast)(broadcast
                        ? vector_bytes / element_bytes : 0u));
                invariant(first.mask_reg == (aaa == 0u
                    ? CDISASM_X86_REG_NONE
                    : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
                invariant(first.mask_mode == (aaa == 0u
                    ? CDISASM_X86_MASK_NONE
                    : (p2 & UINT8_C(0x80)) != 0u
                        ? CDISASM_X86_MASK_ZERO
                        : CDISASM_X86_MASK_MERGE));
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(has_avx512dq != has_avx10_1);
                if (has_avx512dq && vector_bytes < 64u) {
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512VL));
                }
                if (has_avx10_1) {
                    invariant(!cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512VL));
                }
                invariant(cdisasm_instruction_has_x86_group(
                    &first, width_group));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, width_bit));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
                if (!register_form
                    && (modrm & UINT8_C(0xc0)) == UINT8_C(0x40)) {
                    const unsigned int disp8_scale = broadcast
                        ? element_bytes : vector_bytes;

                    invariant((first.opcode[2].imm
                        & (uint64_t)(disp8_scale - 1u)) == 0u);
                }
            }
            if (is_vp2intersect) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int ll = ((unsigned int)p2 >> 5) & 3u;
                const int is_q =
                    first.name_id == CDISASM_X86_NAME_VP2INTERSECTQ;
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int broadcast = !register_form
                    && (p2 & UINT8_C(0x10)) != 0u;
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const unsigned int vector_bytes = 16u << ll;
                const unsigned int element_bytes = is_q ? 8u : 4u;
                const unsigned int lanes = vector_bytes / element_bytes;
                const unsigned int mask_bytes = (lanes + 7u) / 8u;
                const cdisasm_x86_form_id base_form = is_q
                    ? UINT16_C(6080) : UINT16_C(6074);
                const cdisasm_x86_group_id width_group = ll == 0u
                    ? CDISASM_X86_GROUP_AVX512_VP2INTERSECT_128
                    : ll == 1u
                        ? CDISASM_X86_GROUP_AVX512_VP2INTERSECT_256
                        : CDISASM_X86_GROUP_AVX512_VP2INTERSECT_512;
                const cdisasm_x86_decode_bit_id width_bit = ll == 0u
                    ? CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_128
                    : ll == 1u
                        ? CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_256
                        : CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_512;

                invariant((p0 & UINT8_C(7)) == UINT8_C(2));
                invariant((p0 & UINT8_C(0x90)) == UINT8_C(0x90));
                invariant((p1 & UINT8_C(0x83))
                    == (is_q ? UINT8_C(0x83) : UINT8_C(0x03)));
                invariant((p2 & UINT8_C(0x87)) == 0u);
                invariant(code[first.encoding.opcode_offset]
                    == UINT8_C(0x68));
                invariant(ll < 3u);
                invariant(!register_form
                    || (p2 & UINT8_C(0x10)) == 0u);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant((p1 & UINT8_C(0x04)) != 0u || !register_form);
                invariant(mode == CDISASM_MODE_64
                    || (p2 & UINT8_C(0x08)) != 0u);
                invariant(first.form_id == (cdisasm_x86_form_id)(
                    base_form + 2u * ll + (register_form ? 1u : 0u)));
                invariant(first.operand_count == 4u);
                invariant((first.opcode_flags
                    & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                        | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                        | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                        | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                    == 0u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].reg >= CDISASM_X86_REG_K0
                    && first.opcode[0].reg <= CDISASM_X86_REG_K6);
                invariant(((first.opcode[0].reg - CDISASM_X86_REG_K0)
                    & 1u) == 0u);
                invariant(first.opcode[0].size == mask_bytes);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                invariant(first.opcode[0].flags == 0u);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].reg == first.opcode[0].reg + 1u);
                invariant(first.opcode[1].size == mask_bytes);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                invariant(first.opcode[1].flags
                    == CDISASM_OPERAND_FLAG_IMPLICIT);
                invariant(first.opcode[2].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[2].size == vector_bytes);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[3].type == (register_form
                    ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
                invariant(first.opcode[3].size == (broadcast
                    ? element_bytes : vector_bytes));
                invariant(first.opcode[3].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[3].broadcast
                    == (cdisasm_x86_broadcast)(broadcast ? lanes : 0u));
                invariant(first.mask_reg == CDISASM_X86_REG_NONE);
                invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512VP2INTERSECT));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, width_group));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, width_bit));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
                if (!register_form
                    && (modrm & UINT8_C(0xc0)) == UINT8_C(0x40)) {
                    const unsigned int disp8_scale = broadcast
                        ? element_bytes : vector_bytes;

                    invariant((first.opcode[3].imm
                        & (uint64_t)(disp8_scale - 1u)) == 0u);
                }
            }
            if (is_vpabs) {
                const int evex = (first.opcode_flags
                    & CDISASM_PREFIX_EVEX) != 0u;
                const size_t prefix_offset =
                    (size_t)first.encoding.opcode_offset
                        - (evex ? 4u : 3u);
                const uint8_t p0 = code[prefix_offset + 1u];
                const uint8_t p1 = code[prefix_offset + 2u];
                const uint8_t p2 = evex
                    ? code[prefix_offset + 3u] : UINT8_C(0);
                const uint8_t opcode =
                    code[first.encoding.opcode_offset];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int family =
                    (unsigned int)(opcode - UINT8_C(0x1c));
                const unsigned int ll = evex
                    ? ((unsigned int)p2 >> 5) & 3u
                    : ((unsigned int)p1 >> 2) & 1u;
                const unsigned int aaa = evex ? p2 & UINT8_C(7) : 0u;
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int broadcast = evex && !register_form
                    && family >= 2u && (p2 & UINT8_C(0x10)) != 0u;
                const int uses_apx = evex
                    && ((p0 & UINT8_C(0x08)) != 0u
                        || (p1 & UINT8_C(0x04)) == 0u);
                const unsigned int vector_bytes = 16u << ll;
                const unsigned int element_bytes = 1u << family;
                const cdisasm_x86_form_id base_form = family == 0u
                    ? (evex ? UINT16_C(6090) : UINT16_C(6088))
                    : family == 1u
                        ? (evex ? UINT16_C(6116) : UINT16_C(6114))
                        : family == 2u
                            ? (evex ? UINT16_C(6100) : UINT16_C(6098))
                            : UINT16_C(6108);
                const unsigned int width_offset = evex
                    ? (family == 3u ? 2u * ll
                        : ll == 2u ? 6u : 2u * ll)
                    : (ll != 0u ? 6u : 0u);
                const cdisasm_x86_group_id width_group = family <= 1u
                    ? (ll == 0u ? CDISASM_X86_GROUP_AVX512BW_128
                        : ll == 1u ? CDISASM_X86_GROUP_AVX512BW_256
                                   : CDISASM_X86_GROUP_AVX512BW_512)
                    : (ll == 0u ? CDISASM_X86_GROUP_AVX512F_128
                        : ll == 1u ? CDISASM_X86_GROUP_AVX512F_256
                                   : CDISASM_X86_GROUP_AVX512F_512);
                const cdisasm_x86_decode_bit_id width_bit = family <= 1u
                    ? (ll == 0u ? CDISASM_X86_DECODE_BIT_AVX512BW_128
                        : ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512BW_256
                                   : CDISASM_X86_DECODE_BIT_AVX512BW_512)
                    : (ll == 0u ? CDISASM_X86_DECODE_BIT_AVX512F_128
                        : ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512F_256
                                   : CDISASM_X86_DECODE_BIT_AVX512F_512);

                invariant(opcode >= UINT8_C(0x1c)
                    && opcode <= UINT8_C(0x1f));
                invariant((family == 0u
                        && first.name_id == CDISASM_X86_NAME_VPABSB)
                    || (family == 1u
                        && first.name_id == CDISASM_X86_NAME_VPABSW)
                    || (family == 2u
                        && first.name_id == CDISASM_X86_NAME_VPABSD)
                    || (family == 3u
                        && first.name_id == CDISASM_X86_NAME_VPABSQ));
                invariant((p0 & (evex ? UINT8_C(7) : UINT8_C(0x1f)))
                    == UINT8_C(2));
                invariant((p1 & UINT8_C(0x7b)) == UINT8_C(0x79));
                invariant(family <= 1u
                    || ((p1 & UINT8_C(0x80)) != 0u) == (family == 3u));
                invariant(ll < 3u);
                invariant(evex || family < 3u);
                if (evex) {
                    invariant((p2 & UINT8_C(0x08)) != 0u);
                    invariant(!register_form
                        || (p2 & UINT8_C(0x10)) == 0u);
                    invariant(family >= 2u
                        || (p2 & UINT8_C(0x10)) == 0u);
                    invariant((p2 & UINT8_C(0x80)) == 0u || aaa != 0u);
                    invariant((p1 & UINT8_C(0x04)) != 0u
                        || (mode == CDISASM_MODE_64 && !register_form));
                    invariant((p0 & UINT8_C(0x08)) == 0u
                        || mode == CDISASM_MODE_64);
                }
                invariant(first.form_id == (cdisasm_x86_form_id)(
                    base_form + width_offset
                        + (register_form ? 1u : 0u)));
                invariant(first.operand_count == 2u);
                invariant((first.opcode_flags
                    & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                        | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                        | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                        | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                    == 0u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].size == vector_bytes);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].type == (register_form
                    ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
                invariant(first.opcode[1].size == (broadcast
                    ? element_bytes : vector_bytes));
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[1].broadcast
                    == (cdisasm_x86_broadcast)(broadcast
                        ? vector_bytes / element_bytes : 0u));
                invariant(first.mask_reg == (aaa == 0u
                    ? CDISASM_X86_REG_NONE
                    : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
                invariant(first.mask_mode == (aaa == 0u
                    ? CDISASM_X86_MASK_NONE
                    : (p2 & UINT8_C(0x80)) != 0u
                        ? CDISASM_X86_MASK_ZERO
                        : CDISASM_X86_MASK_MERGE));
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                if (!evex) {
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX2) == (ll != 0u));
                    invariant(cdisasm_decode_flags_test_bit(
                        decode_flags, CDISASM_X86_DECODE_BIT_AVX));
                    invariant(ll == 0u || cdisasm_decode_flags_test_bit(
                        decode_flags, CDISASM_X86_DECODE_BIT_AVX2));
                    invariant(!uses_apx);
                } else {
                    const int has_avx10_1 =
                        cdisasm_instruction_has_x86_group(
                            &first, CDISASM_X86_GROUP_AVX10_1);
                    const int has_avx512_family =
                        cdisasm_instruction_has_x86_group(&first,
                            family <= 1u
                                ? CDISASM_X86_GROUP_AVX512BW
                                : CDISASM_X86_GROUP_AVX512F);

                    invariant(has_avx10_1 != has_avx512_family);
                    invariant(!has_avx512_family || ll == 2u
                        || cdisasm_instruction_has_x86_group(
                            &first, CDISASM_X86_GROUP_AVX512VL));
                    invariant(!has_avx10_1
                        || !cdisasm_instruction_has_x86_group(
                            &first, CDISASM_X86_GROUP_AVX512VL));
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, width_group));
                    invariant(cdisasm_decode_flags_test_bit(
                        decode_flags, width_bit));
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                    invariant(!uses_apx
                        || (decode_flag_word0(decode_flags)
                            & CDISASM_X86_DECODE_FLAG_APX) != 0u);
                }
                if (!register_form
                    && (modrm & UINT8_C(0xc0)) == UINT8_C(0x40)) {
                    const unsigned int disp8_scale = broadcast
                        ? element_bytes : vector_bytes;

                    invariant((first.opcode[1].imm
                        & (uint64_t)(disp8_scale - 1u)) == 0u);
                }
            }
            if (is_vpack) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t opcode =
                    code[first.encoding.opcode_offset];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int ll =
                    ((unsigned int)p2 >> 5) & 3u;
                const unsigned int aaa = p2 & UINT8_C(7);
                const unsigned int vector_bytes = 16u << ll;
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int dword_source =
                    first.name_id == CDISASM_X86_NAME_VPACKSSDW
                    || first.name_id == CDISASM_X86_NAME_VPACKUSDW;
                const int signed_family =
                    first.name_id == CDISASM_X86_NAME_VPACKSSDW
                    || first.name_id == CDISASM_X86_NAME_VPACKSSWB;
                const int broadcast = !register_form && dword_source
                    && (p2 & UINT8_C(0x10)) != 0u;
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const unsigned int element_bytes =
                    dword_source ? 4u : 2u;
                cdisasm_x86_form_id base_form;
                unsigned int width_offset;
                cdisasm_x86_group_id width_group;
                cdisasm_x86_decode_bit_id width_bit;

                if (first.name_id == CDISASM_X86_NAME_VPACKSSDW) {
                    base_form = UINT16_C(6126);
                } else if (first.name_id
                        == CDISASM_X86_NAME_VPACKSSWB) {
                    base_form = UINT16_C(6136);
                } else if (first.name_id
                        == CDISASM_X86_NAME_VPACKUSDW) {
                    base_form = UINT16_C(6146);
                } else {
                    base_form = UINT16_C(6156);
                }
                width_offset = signed_family
                    ? (ll == 2u ? 6u : 2u * ll)
                    : (ll == 0u ? 0u : ll == 1u ? 4u : 6u);
                width_group = ll == 0u
                    ? CDISASM_X86_GROUP_AVX512BW_128
                    : ll == 1u ? CDISASM_X86_GROUP_AVX512BW_256
                               : CDISASM_X86_GROUP_AVX512BW_512;
                width_bit = ll == 0u
                    ? CDISASM_X86_DECODE_BIT_AVX512BW_128
                    : ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512BW_256
                               : CDISASM_X86_DECODE_BIT_AVX512BW_512;

                invariant((p0 & UINT8_C(7))
                    == (first.name_id == CDISASM_X86_NAME_VPACKUSDW
                        ? UINT8_C(2) : UINT8_C(1)));
                invariant((p1 & UINT8_C(0x03)) == UINT8_C(1));
                invariant(!dword_source
                    || (p1 & UINT8_C(0x80)) == 0u);
                invariant((first.name_id == CDISASM_X86_NAME_VPACKSSDW
                        && opcode == UINT8_C(0x6b))
                    || (first.name_id == CDISASM_X86_NAME_VPACKSSWB
                        && opcode == UINT8_C(0x63))
                    || (first.name_id == CDISASM_X86_NAME_VPACKUSDW
                        && opcode == UINT8_C(0x2b))
                    || (first.name_id == CDISASM_X86_NAME_VPACKUSWB
                        && opcode == UINT8_C(0x67)));
                invariant(ll < 3u);
                invariant(!register_form
                    || (p2 & UINT8_C(0x10)) == 0u);
                invariant(dword_source
                    || (p2 & UINT8_C(0x10)) == 0u);
                invariant((p2 & UINT8_C(0x80)) == 0u || aaa != 0u);
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64 && !register_form));
                invariant((p0 & UINT8_C(0x08)) == 0u
                    || mode == CDISASM_MODE_64);
                invariant(mode == CDISASM_MODE_64
                    || (p2 & UINT8_C(0x08)) != 0u);
                invariant(first.form_id == (cdisasm_x86_form_id)(
                    base_form + width_offset
                        + (register_form ? 1u : 0u)));
                invariant(first.operand_count == 3u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].size == vector_bytes);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].size == vector_bytes);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[2].type == (register_form
                    ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
                invariant(first.opcode[2].size == (broadcast
                    ? element_bytes : vector_bytes));
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].broadcast
                    == (cdisasm_x86_broadcast)(broadcast
                        ? vector_bytes / element_bytes : 0u));
                invariant(first.mask_reg == (aaa == 0u
                    ? CDISASM_X86_REG_NONE
                    : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
                invariant(first.mask_mode == (aaa == 0u
                    ? CDISASM_X86_MASK_NONE
                    : (p2 & UINT8_C(0x80)) != 0u
                        ? CDISASM_X86_MASK_ZERO
                        : CDISASM_X86_MASK_MERGE));
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                {
                    const int has_avx10_1 =
                        cdisasm_instruction_has_x86_group(
                            &first, CDISASM_X86_GROUP_AVX10_1);
                    const int has_avx512bw =
                        cdisasm_instruction_has_x86_group(
                            &first, CDISASM_X86_GROUP_AVX512BW);

                    invariant(has_avx10_1 != has_avx512bw);
                    invariant(!has_avx512bw || ll == 2u
                        || cdisasm_instruction_has_x86_group(
                            &first, CDISASM_X86_GROUP_AVX512VL));
                    invariant(!has_avx10_1
                        || !cdisasm_instruction_has_x86_group(
                            &first, CDISASM_X86_GROUP_AVX512VL));
                }
                invariant(cdisasm_instruction_has_x86_group(
                    &first, width_group));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, width_bit));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx
                    || (decode_flag_word0(decode_flags)
                        & CDISASM_X86_DECODE_FLAG_APX) != 0u);
                if (!register_form
                    && (modrm & UINT8_C(0xc0)) == UINT8_C(0x40)) {
                    const unsigned int disp8_scale = broadcast
                        ? element_bytes : vector_bytes;

                    invariant((first.opcode[2].imm
                        & (uint64_t)(disp8_scale - 1u)) == 0u);
                }
            }
            if (is_move_duplicate) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t opcode =
                    code[first.encoding.opcode_offset];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int ll = ((unsigned int)p2 >> 5) & 3u;
                const unsigned int vector_bytes = 16u << ll;
                const int source_is_memory =
                    (modrm & UINT8_C(0xc0)) != UINT8_C(0xc0);
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const cdisasm_x86_form_id base_form =
                    first.name_id == CDISASM_X86_NAME_VMOVSHDUP
                        ? (ll == 0u ? UINT16_C(5918)
                            : ll == 1u ? UINT16_C(5920)
                                       : UINT16_C(5924))
                        : (ll == 0u ? UINT16_C(5931)
                            : ll == 1u ? UINT16_C(5933)
                                       : UINT16_C(5937));
                const cdisasm_x86_group_id width_group = ll == 0u
                    ? CDISASM_X86_GROUP_AVX512F_128
                    : ll == 1u ? CDISASM_X86_GROUP_AVX512F_256
                               : CDISASM_X86_GROUP_AVX512F_512;
                const cdisasm_x86_decode_bit_id width_bit = ll == 0u
                    ? CDISASM_X86_DECODE_BIT_AVX512F_128
                    : ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512F_256
                               : CDISASM_X86_DECODE_BIT_AVX512F_512;

                invariant(ll < 3u);
                invariant(first.form_id
                    == (cdisasm_x86_form_id)(base_form
                        + (source_is_memory ? 0u : 1u)));
                invariant(first.operand_count == 2u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].size == vector_bytes);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].type == (source_is_memory
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                invariant(first.opcode[1].size == vector_bytes);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.mask_mode != CDISASM_X86_MASK_NONE
                    || first.mask_reg == CDISASM_X86_REG_NONE);
                invariant(first.mask_mode == CDISASM_X86_MASK_NONE
                    || (first.mask_reg >= CDISASM_X86_REG_K1
                        && first.mask_reg <= CDISASM_X86_REG_K7));
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant((p0 & UINT8_C(7)) == UINT8_C(1));
                invariant((p1 & UINT8_C(0xfb)) == UINT8_C(0x7a));
                invariant((p2 & UINT8_C(0x18)) == UINT8_C(0x08));
                invariant((p2 & UINT8_C(0x80)) == 0u
                    || (p2 & UINT8_C(7)) != 0u);
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64 && source_is_memory));
                invariant((opcode == UINT8_C(0x16)
                        && first.name_id == CDISASM_X86_NAME_VMOVSHDUP)
                    || (opcode == UINT8_C(0x12)
                        && first.name_id == CDISASM_X86_NAME_VMOVSLDUP));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, width_group));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, width_bit));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
            }
            if (is_move_half_scalar) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t opcode =
                    code[first.encoding.opcode_offset];
                const uint8_t modrm = first.encoding.modrm;
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int memory_destination =
                    first.form_id == UINT16_C(5926);
                const int memory_source =
                    first.form_id == UINT16_C(5927);
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;

                invariant(first.form_id >= UINT16_C(5926)
                    && first.form_id <= UINT16_C(5928));
                invariant(first.operand_count
                    == (register_form ? 3u : 2u));
                invariant(first.opcode[0].type == (memory_destination
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                invariant(first.opcode[0].size
                    == (memory_destination ? 2u : 16u));
                invariant(first.opcode[0].access
                    == (!memory_destination
                            && first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[1].type == (memory_source
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                invariant(first.opcode[1].size
                    == (memory_source ? 2u : 16u));
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                if (register_form) {
                    invariant(first.opcode[2].type
                        == CDISASM_OPERAND_REGISTER);
                    invariant(first.opcode[2].size == 16u);
                    invariant(first.opcode[2].access
                        == CDISASM_OPERAND_ACCESS_READ);
                }
                invariant(first.mask_mode != CDISASM_X86_MASK_NONE
                    || first.mask_reg == CDISASM_X86_REG_NONE);
                invariant(first.mask_mode == CDISASM_X86_MASK_NONE
                    || (first.mask_reg >= CDISASM_X86_REG_K1
                        && first.mask_reg <= CDISASM_X86_REG_K7));
                invariant(first.mask_mode != CDISASM_X86_MASK_ZERO
                    || !memory_destination);
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant((p0 & UINT8_C(7)) == UINT8_C(5));
                invariant((p1 & UINT8_C(0x83)) == UINT8_C(0x02));
                invariant((p2 & UINT8_C(0x10)) == 0u);
                invariant(((p2 >> 5) & UINT8_C(3)) < UINT8_C(3));
                invariant((p2 & UINT8_C(0x80)) == 0u
                    || (p2 & UINT8_C(7)) != 0u);
                invariant(register_form
                    || (p1 & UINT8_C(0x78)) == UINT8_C(0x78));
                invariant(register_form
                    || (p2 & UINT8_C(0x08)) != 0u);
                invariant(mode == CDISASM_MODE_64
                    || (p2 & UINT8_C(0x08)) != 0u);
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64 && !register_form));
                invariant((opcode == UINT8_C(0x10)
                        && (memory_source || register_form))
                    || (opcode == UINT8_C(0x11)
                        && (memory_destination || register_form)));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512_FP16_SCALAR));
                invariant(cdisasm_decode_flags_test_bit(decode_flags,
                    CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
            }
            if (is_move_scalar) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t opcode =
                    code[first.encoding.opcode_offset];
                const uint8_t modrm = first.encoding.modrm;
                const int is_single =
                    first.name_id == CDISASM_X86_NAME_VMOVSS;
                const int memory_destination =
                    first.form_id == UINT16_C(5909)
                    || first.form_id == UINT16_C(5940);
                const int memory_source =
                    first.form_id == UINT16_C(5914)
                    || first.form_id == UINT16_C(5944);
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;

                invariant((!is_single
                        && (first.form_id == UINT16_C(5909)
                            || first.form_id == UINT16_C(5914)
                            || first.form_id == UINT16_C(5915)))
                    || (is_single
                        && (first.form_id == UINT16_C(5940)
                            || first.form_id == UINT16_C(5944)
                            || first.form_id == UINT16_C(5945))));
                invariant(first.operand_count
                    == (memory_destination || memory_source ? 2u : 3u));
                invariant(first.opcode[0].type == (memory_destination
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                invariant(first.opcode[0].size
                    == (memory_destination
                        ? (is_single ? 4u : 8u) : 16u));
                invariant(first.opcode[0].access
                    == (!memory_destination
                            && first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[1].type == (memory_source
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                invariant(first.opcode[1].size
                    == (memory_source ? (is_single ? 4u : 8u) : 16u));
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                if (first.operand_count == 3u) {
                    invariant(first.opcode[2].type
                        == CDISASM_OPERAND_REGISTER);
                    invariant(first.opcode[2].size == 16u);
                    invariant(first.opcode[2].access
                        == CDISASM_OPERAND_ACCESS_READ);
                }
                invariant(((modrm & UINT8_C(0xc0)) != UINT8_C(0xc0))
                    == (memory_destination || memory_source));
                invariant(first.mask_mode != CDISASM_X86_MASK_NONE
                    || first.mask_reg == CDISASM_X86_REG_NONE);
                invariant(first.mask_mode == CDISASM_X86_MASK_NONE
                    || (first.mask_reg >= CDISASM_X86_REG_K1
                        && first.mask_reg <= CDISASM_X86_REG_K7));
                invariant(first.mask_mode != CDISASM_X86_MASK_ZERO
                    || !memory_destination);
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant((p0 & UINT8_C(7)) == UINT8_C(1));
                invariant((p1 & UINT8_C(0x83))
                    == (is_single ? UINT8_C(0x02) : UINT8_C(0x83)));
                invariant((p2 & UINT8_C(0x10)) == 0u);
                invariant(((p2 >> 5) & UINT8_C(3)) < UINT8_C(3));
                invariant((p2 & UINT8_C(0x80)) == 0u
                    || (p2 & UINT8_C(7)) != 0u);
                invariant(!(memory_destination || memory_source)
                    || (p1 & UINT8_C(0x78)) == UINT8_C(0x78));
                invariant(!(memory_destination || memory_source)
                    || (p2 & UINT8_C(0x08)) != 0u);
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64
                        && (modrm & UINT8_C(0xc0)) != UINT8_C(0xc0)));
                invariant((opcode == UINT8_C(0x10)
                        && (first.form_id == UINT16_C(5914)
                            || first.form_id == UINT16_C(5915)
                            || first.form_id == UINT16_C(5944)
                            || first.form_id == UINT16_C(5945)))
                    || (opcode == UINT8_C(0x11)
                        && (first.form_id == UINT16_C(5909)
                            || first.form_id == UINT16_C(5915)
                            || first.form_id == UINT16_C(5940)
                            || first.form_id == UINT16_C(5945))));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F_SCALAR));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, CDISASM_X86_DECODE_BIT_AVX512F_SCALAR));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
            }
            if (is_move_quadword) {
                const size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t opcode =
                    code[first.encoding.opcode_offset];
                const uint8_t modrm = first.encoding.modrm;
                const int destination_is_memory =
                    first.form_id == UINT16_C(5888);
                const int source_is_memory =
                    first.form_id == UINT16_C(5895);
                const int uses_apx =
                    (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const unsigned int destination_bytes =
                    destination_is_memory
                        || first.form_id == UINT16_C(5885) ? 8u : 16u;
                const unsigned int source_bytes =
                    source_is_memory
                        || first.form_id == UINT16_C(5894) ? 8u : 16u;

                invariant(first.form_id == UINT16_C(5885)
                    || first.form_id == UINT16_C(5888)
                    || first.form_id == UINT16_C(5894)
                    || first.form_id == UINT16_C(5895)
                    || first.form_id == UINT16_C(5896));
                invariant(first.operand_count == 2u);
                invariant(first.opcode[0].type == (destination_is_memory
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                invariant(first.opcode[0].size == destination_bytes);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].type == (source_is_memory
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                invariant(first.opcode[1].size == source_bytes);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(((modrm & UINT8_C(0xc0)) != UINT8_C(0xc0))
                    == (destination_is_memory || source_is_memory));
                invariant(first.mask_reg == CDISASM_X86_REG_NONE);
                invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant((p0 & UINT8_C(0x07)) == UINT8_C(1));
                invariant((p1 & UINT8_C(0xf8)) == UINT8_C(0xf8));
                invariant(p2 == UINT8_C(0x08));
                invariant((opcode == UINT8_C(0x6e)
                        && (p1 & UINT8_C(3)) == UINT8_C(1)
                        && (first.form_id == UINT16_C(5894)
                            || first.form_id == UINT16_C(5895)))
                    || (opcode == UINT8_C(0x7e)
                        && (p1 & UINT8_C(3)) == UINT8_C(1)
                        && (first.form_id == UINT16_C(5885)
                            || first.form_id == UINT16_C(5888)))
                    || (opcode == UINT8_C(0x7e)
                        && (p1 & UINT8_C(3)) == UINT8_C(2)
                        && (first.form_id == UINT16_C(5895)
                            || first.form_id == UINT16_C(5896)))
                    || (opcode == UINT8_C(0xd6)
                        && (p1 & UINT8_C(3)) == UINT8_C(1)
                        && (first.form_id == UINT16_C(5888)
                            || first.form_id == UINT16_C(5896))));
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64
                        && (modrm & UINT8_C(0xc0)) != UINT8_C(0xc0)));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F_128N));
                invariant(cdisasm_decode_flags_test_bit(
                    decode_flags, CDISASM_X86_DECODE_BIT_AVX512F_128N));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_apx);
                invariant(!uses_apx || mode == CDISASM_MODE_64);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
            }
            if (is_amx_row) {
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AMX_TILE));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AMX_AVX512));
            }
            if (is_ace_tilemov) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                int uses_b4 =
                    (code[evex_offset + 1u] & UINT8_C(0x08)) != 0u;

                invariant(first.name_id == CDISASM_X86_NAME_TILEMOVROW
                    || first.name_id == CDISASM_X86_NAME_TILEMOVCOL);
                invariant(first.operand_count == 3u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].reg >= CDISASM_X86_REG_TMM0
                    && first.opcode[0].reg <= CDISASM_X86_REG_TMM7);
                invariant(first.opcode[0].size == UINT8_MAX);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].reg >= CDISASM_X86_REG_ZMM0
                    && first.opcode[1].reg <= CDISASM_X86_REG_ZMM31);
                invariant(first.opcode[1].size == 64u);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(!cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AMX_AVX512));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_b4);
                if (first.opcode[2].type == CDISASM_OPERAND_IMMEDIATE) {
                    invariant(first.opcode[2].size == 1u);
                    invariant(first.encoding.immediate_count == 1u);
                    invariant(first.encoding.immediate_size[0] == 1u);
                    invariant(first.form_id == UINT16_C(3300)
                        || first.form_id == UINT16_C(3302));
                } else {
                    invariant(first.opcode[2].type
                        == CDISASM_OPERAND_REGISTER);
                    invariant((first.opcode[2].reg
                            >= CDISASM_X86_REG_EAX
                            && first.opcode[2].reg
                                <= CDISASM_X86_REG_R15D)
                        || (first.opcode[2].reg
                            >= CDISASM_X86_REG_R16D
                            && first.opcode[2].reg
                                <= CDISASM_X86_REG_R31D));
                    invariant(first.opcode[2].size == 4u);
                    invariant(first.encoding.immediate_count == 0u);
                    invariant(first.form_id == UINT16_C(3299)
                        || first.form_id == UINT16_C(3301));
                }
            }
            if (is_ace_top) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                int uses_b4 =
                    (code[evex_offset + 1u] & UINT8_C(0x08)) != 0u;
                int has_immediate =
                    first.name_id >= CDISASM_X86_NAME_TOP4MXBF8PS;

                invariant(first.form_id
                    == (cdisasm_x86_form_id)(first.name_id + UINT16_C(1855)));
                invariant(first.operand_count == (has_immediate ? 4u : 3u));
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].reg >= CDISASM_X86_REG_TMM0
                    && first.opcode[0].reg <= CDISASM_X86_REG_TMM7);
                invariant(first.opcode[0].size == UINT8_MAX);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].reg >= CDISASM_X86_REG_ZMM0
                    && first.opcode[1].reg <= CDISASM_X86_REG_ZMM31);
                invariant(first.opcode[1].size == 64u);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[2].reg >= CDISASM_X86_REG_ZMM0
                    && first.opcode[2].reg <= CDISASM_X86_REG_ZMM31);
                invariant(first.opcode[2].size == 64u);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(!cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AMX_AVX512));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F) == uses_b4);
                invariant(first.encoding.immediate_count
                    == (has_immediate ? 1u : 0u));
                if (has_immediate) {
                    /* XED's additional BSR0 read is suppressed state, not a
                     * public syntax operand. */
                    invariant(first.opcode[3].type
                        == CDISASM_OPERAND_IMMEDIATE);
                    invariant(first.opcode[3].size == 1u);
                    invariant(first.opcode[3].access
                        == CDISASM_OPERAND_ACCESS_READ);
                    invariant(first.encoding.immediate_size[0] == 1u);
                }
            }
            if (is_compare_mask) {
                int has_avx512f = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F);
                int has_avx10_1 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1);

                invariant(first.operand_count == 4u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].reg >= CDISASM_X86_REG_K0
                    && first.opcode[0].reg <= CDISASM_X86_REG_K7);
                invariant(first.opcode[0].access
                    == (first.mask_reg == CDISASM_X86_REG_NONE
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ_WRITE));
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[3].type
                    == CDISASM_OPERAND_IMMEDIATE);
                invariant(first.opcode[3].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.encoding.immediate_count == 1u);
                invariant(has_avx512f != has_avx10_1);
            }
            if (is_modular_add_sub || is_integer_minmax) {
                const size_t opcode_offset = first.encoding.opcode_offset;
                const size_t evex_offset = opcode_offset - 4u;
                const uint8_t p0 = code[evex_offset + 1u];
                const uint8_t p1 = code[evex_offset + 2u];
                const uint8_t p2 = code[evex_offset + 3u];
                const uint8_t opcode = code[opcode_offset];
                const uint8_t modrm = first.encoding.modrm;
                const unsigned int ll = ((unsigned int)p2 >> 5) & 3u;
                const unsigned int vector_size = 16u << ll;
                const unsigned int aaa = p2 & UINT8_C(7);
                const int register_form =
                    (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                const int byte_family =
                    first.name_id == CDISASM_X86_NAME_VPADDB
                    || first.name_id == CDISASM_X86_NAME_VPSUBB
                    || first.name_id == CDISASM_X86_NAME_VPMAXSB
                    || first.name_id == CDISASM_X86_NAME_VPMAXUB
                    || first.name_id == CDISASM_X86_NAME_VPMINSB
                    || first.name_id == CDISASM_X86_NAME_VPMINUB;
                const int word_family =
                    first.name_id == CDISASM_X86_NAME_VPADDW
                    || first.name_id == CDISASM_X86_NAME_VPSUBW
                    || first.name_id == CDISASM_X86_NAME_VPMAXSW
                    || first.name_id == CDISASM_X86_NAME_VPMAXUW
                    || first.name_id == CDISASM_X86_NAME_VPMINSW
                    || first.name_id == CDISASM_X86_NAME_VPMINUW;
                const int bw_family = byte_family || word_family;
                const int qword_family =
                    first.name_id == CDISASM_X86_NAME_VPADDQ
                    || first.name_id == CDISASM_X86_NAME_VPSUBQ
                    || first.name_id == CDISASM_X86_NAME_VPMAXSQ
                    || first.name_id == CDISASM_X86_NAME_VPMAXUQ
                    || first.name_id == CDISASM_X86_NAME_VPMINSQ
                    || first.name_id == CDISASM_X86_NAME_VPMINUQ;
                const int dword_family =
                    first.name_id == CDISASM_X86_NAME_VPADDD
                    || first.name_id == CDISASM_X86_NAME_VPSUBD
                    || first.name_id == CDISASM_X86_NAME_VPMAXSD
                    || first.name_id == CDISASM_X86_NAME_VPMAXUD
                    || first.name_id == CDISASM_X86_NAME_VPMINSD
                    || first.name_id == CDISASM_X86_NAME_VPMINUD;
                const unsigned int element_size = byte_family ? 1u
                    : word_family ? 2u : dword_family ? 4u : 8u;
                const int map2_minmax = is_integer_minmax
                    && first.name_id != CDISASM_X86_NAME_VPMAXSW
                    && first.name_id != CDISASM_X86_NAME_VPMAXUB
                    && first.name_id != CDISASM_X86_NAME_VPMINSW
                    && first.name_id != CDISASM_X86_NAME_VPMINUB;
                const uint8_t expected_map = map2_minmax ? 2u : 1u;
                const int broadcast = !register_form
                    && (p2 & UINT8_C(0x10)) != 0u;
                const int uses_apx = (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                const int has_avx512f =
                    cdisasm_instruction_has_x86_group(
                        &first,CDISASM_X86_GROUP_AVX512F);
                const int has_avx512bw =
                    cdisasm_instruction_has_x86_group(
                        &first,CDISASM_X86_GROUP_AVX512BW);
                const int has_avx512vl =
                    cdisasm_instruction_has_x86_group(
                        &first,CDISASM_X86_GROUP_AVX512VL);
                const int has_avx10_1 =
                    cdisasm_instruction_has_x86_group(
                        &first,CDISASM_X86_GROUP_AVX10_1);
                const int has_apx = cdisasm_instruction_has_x86_group(
                    &first,CDISASM_X86_GROUP_APX_F);
                const int has_i386 = cdisasm_instruction_has_x86_group(
                    &first,CDISASM_X86_GROUP_I386);
                const int has_amd64 = cdisasm_instruction_has_x86_group(
                    &first,CDISASM_X86_GROUP_AMD64);
                const cdisasm_x86_reg_id register_base = ll == 0u
                    ? CDISASM_X86_REG_XMM0
                    : ll == 1u ? CDISASM_X86_REG_YMM0
                               : CDISASM_X86_REG_ZMM0;
                cdisasm_x86_form_id xmm_memory;
                cdisasm_x86_form_id ymm_memory;
                cdisasm_x86_form_id zmm_memory;
                cdisasm_x86_form_id width_memory;
                uint8_t expected_opcode;
                unsigned int expected_group_count;

                if (first.name_id == CDISASM_X86_NAME_VPADDB) {
                    expected_opcode = UINT8_C(0xfc);
                    xmm_memory = UINT16_C(6166);
                    ymm_memory = UINT16_C(6170);
                    zmm_memory = UINT16_C(6172);
                } else if (first.name_id == CDISASM_X86_NAME_VPADDW) {
                    expected_opcode = UINT8_C(0xfd);
                    xmm_memory = UINT16_C(6236);
                    ymm_memory = UINT16_C(6240);
                    zmm_memory = UINT16_C(6242);
                } else if (first.name_id == CDISASM_X86_NAME_VPADDD) {
                    expected_opcode = UINT8_C(0xfe);
                    xmm_memory = UINT16_C(6176);
                    ymm_memory = UINT16_C(6180);
                    zmm_memory = UINT16_C(6182);
                } else if (first.name_id == CDISASM_X86_NAME_VPADDQ) {
                    expected_opcode = UINT8_C(0xd4);
                    xmm_memory = UINT16_C(6186);
                    ymm_memory = UINT16_C(6190);
                    zmm_memory = UINT16_C(6192);
                } else if (first.name_id == CDISASM_X86_NAME_VPSUBB) {
                    expected_opcode = UINT8_C(0xf8);
                    xmm_memory = UINT16_C(8181);
                    ymm_memory = UINT16_C(8185);
                    zmm_memory = UINT16_C(8187);
                } else if (first.name_id == CDISASM_X86_NAME_VPSUBW) {
                    expected_opcode = UINT8_C(0xf9);
                    xmm_memory = UINT16_C(8251);
                    ymm_memory = UINT16_C(8255);
                    zmm_memory = UINT16_C(8257);
                } else if (first.name_id == CDISASM_X86_NAME_VPSUBD) {
                    expected_opcode = UINT8_C(0xfa);
                    xmm_memory = UINT16_C(8191);
                    ymm_memory = UINT16_C(8195);
                    zmm_memory = UINT16_C(8197);
                } else if (first.name_id == CDISASM_X86_NAME_VPSUBQ) {
                    expected_opcode = UINT8_C(0xfb);
                    xmm_memory = UINT16_C(8201);
                    ymm_memory = UINT16_C(8205);
                    zmm_memory = UINT16_C(8207);
                } else if (first.name_id == CDISASM_X86_NAME_VPMAXSB) {
                    expected_opcode = UINT8_C(0x3c);
                    xmm_memory = UINT16_C(7162);
                    ymm_memory = UINT16_C(7164);
                    zmm_memory = UINT16_C(7168);
                } else if (first.name_id == CDISASM_X86_NAME_VPMAXSD) {
                    expected_opcode = UINT8_C(0x3d);
                    xmm_memory = UINT16_C(7172);
                    ymm_memory = UINT16_C(7174);
                    zmm_memory = UINT16_C(7178);
                } else if (first.name_id == CDISASM_X86_NAME_VPMAXSQ) {
                    expected_opcode = UINT8_C(0x3d);
                    xmm_memory = UINT16_C(7180);
                    ymm_memory = UINT16_C(7182);
                    zmm_memory = UINT16_C(7184);
                } else if (first.name_id == CDISASM_X86_NAME_VPMAXSW) {
                    expected_opcode = UINT8_C(0xee);
                    xmm_memory = UINT16_C(7188);
                    ymm_memory = UINT16_C(7190);
                    zmm_memory = UINT16_C(7194);
                } else if (first.name_id == CDISASM_X86_NAME_VPMAXUB) {
                    expected_opcode = UINT8_C(0xde);
                    xmm_memory = UINT16_C(7198);
                    ymm_memory = UINT16_C(7202);
                    zmm_memory = UINT16_C(7204);
                } else if (first.name_id == CDISASM_X86_NAME_VPMAXUD) {
                    expected_opcode = UINT8_C(0x3f);
                    xmm_memory = UINT16_C(7208);
                    ymm_memory = UINT16_C(7212);
                    zmm_memory = UINT16_C(7214);
                } else if (first.name_id == CDISASM_X86_NAME_VPMAXUQ) {
                    expected_opcode = UINT8_C(0x3f);
                    xmm_memory = UINT16_C(7216);
                    ymm_memory = UINT16_C(7218);
                    zmm_memory = UINT16_C(7220);
                } else if (first.name_id == CDISASM_X86_NAME_VPMAXUW) {
                    expected_opcode = UINT8_C(0x3e);
                    xmm_memory = UINT16_C(7224);
                    ymm_memory = UINT16_C(7228);
                    zmm_memory = UINT16_C(7230);
                } else if (first.name_id == CDISASM_X86_NAME_VPMINSB) {
                    expected_opcode = UINT8_C(0x38);
                    xmm_memory = UINT16_C(7234);
                    ymm_memory = UINT16_C(7236);
                    zmm_memory = UINT16_C(7240);
                } else if (first.name_id == CDISASM_X86_NAME_VPMINSD) {
                    expected_opcode = UINT8_C(0x39);
                    xmm_memory = UINT16_C(7244);
                    ymm_memory = UINT16_C(7246);
                    zmm_memory = UINT16_C(7250);
                } else if (first.name_id == CDISASM_X86_NAME_VPMINSQ) {
                    expected_opcode = UINT8_C(0x39);
                    xmm_memory = UINT16_C(7252);
                    ymm_memory = UINT16_C(7254);
                    zmm_memory = UINT16_C(7256);
                } else if (first.name_id == CDISASM_X86_NAME_VPMINSW) {
                    expected_opcode = UINT8_C(0xea);
                    xmm_memory = UINT16_C(7260);
                    ymm_memory = UINT16_C(7262);
                    zmm_memory = UINT16_C(7266);
                } else if (first.name_id == CDISASM_X86_NAME_VPMINUB) {
                    expected_opcode = UINT8_C(0xda);
                    xmm_memory = UINT16_C(7270);
                    ymm_memory = UINT16_C(7274);
                    zmm_memory = UINT16_C(7276);
                } else if (first.name_id == CDISASM_X86_NAME_VPMINUD) {
                    expected_opcode = UINT8_C(0x3b);
                    xmm_memory = UINT16_C(7280);
                    ymm_memory = UINT16_C(7284);
                    zmm_memory = UINT16_C(7286);
                } else if (first.name_id == CDISASM_X86_NAME_VPMINUQ) {
                    expected_opcode = UINT8_C(0x3b);
                    xmm_memory = UINT16_C(7288);
                    ymm_memory = UINT16_C(7290);
                    zmm_memory = UINT16_C(7292);
                } else {
                    expected_opcode = UINT8_C(0x3a);
                    xmm_memory = UINT16_C(7296);
                    ymm_memory = UINT16_C(7300);
                    zmm_memory = UINT16_C(7302);
                }
                width_memory = ll == 0u ? xmm_memory
                    : ll == 1u ? ymm_memory : zmm_memory;

                invariant((p0 & UINT8_C(7)) == expected_map);
                invariant((p1 & UINT8_C(3)) == UINT8_C(1));
                invariant(ll < 3u);
                invariant(!dword_family || (p1 & UINT8_C(0x80)) == 0u);
                invariant(!qword_family || (p1 & UINT8_C(0x80)) != 0u);
                invariant(opcode == expected_opcode);
                invariant(!broadcast || !bw_family);
                invariant((p2 & UINT8_C(0x80)) == 0u || aaa != 0u);
                invariant((p1 & UINT8_C(0x04)) != 0u
                    || (mode == CDISASM_MODE_64 && !register_form));
                invariant((p0 & UINT8_C(0x08)) == 0u
                    || mode == CDISASM_MODE_64);
                invariant(mode == CDISASM_MODE_64
                    || (p2 & UINT8_C(0x08)) != 0u);
                invariant(first.form_id == (cdisasm_x86_form_id)(
                    width_memory + (register_form ? 1u : 0u)));
                invariant(first.operand_count == 3u);
                invariant((first.opcode_flags
                    & ~(CDISASM_PREFIX_EVEX
                        | CDISASM_PREFIX_ADDRESS_SIZE
                        | CDISASM_PREFIX_SEGMENT)) == 0u);
                invariant(first.opcode_groups == CDISASM_GROUP_NONE);
                invariant(first.branch_target == 0u);
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.sae == CDISASM_X86_SAE_NONE);
                invariant(first.encoding.modrm_offset == opcode_offset + 1u);
                invariant(first.encoding.immediate_count == 0u);
                invariant(first.encoding.selector_offset == 0u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].reg >= register_base
                    && first.opcode[0].reg <= register_base + 31u);
                invariant(first.opcode[0].size == vector_size);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[0].flags == 0u);
                invariant(first.opcode[0].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].reg >= register_base
                    && first.opcode[1].reg <= register_base + 31u);
                invariant(first.opcode[1].size == vector_size);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[1].flags == 0u);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.opcode[2].type == (register_form
                    ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                if (register_form) {
                    invariant(first.opcode[2].reg >= register_base
                        && first.opcode[2].reg <= register_base + 31u);
                    invariant(first.opcode[2].size == vector_size);
                    invariant(first.opcode[2].flags == 0u);
                    invariant(first.opcode[2].broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                } else {
                    invariant(first.opcode[2].size
                        == (broadcast ? element_size : vector_size));
                    invariant(first.opcode[2].broadcast
                        == (cdisasm_x86_broadcast)(broadcast
                            ? vector_size / element_size : 0u));
                    invariant((first.opcode[2].flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                            | CDISASM_OPERAND_FLAG_SIGNED)) == 0u);
                }
                invariant(first.mask_reg == (aaa == 0u
                    ? CDISASM_X86_REG_NONE
                    : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + aaa)));
                invariant(first.mask_mode == (aaa == 0u
                    ? CDISASM_X86_MASK_NONE
                    : (p2 & UINT8_C(0x80)) != 0u
                        ? CDISASM_X86_MASK_ZERO
                        : CDISASM_X86_MASK_MERGE));
                invariant(cdisasm_instruction_has_x86_group(
                    &first,CDISASM_X86_GROUP_AVX));
                invariant(has_avx512f != has_avx10_1);
                invariant(has_avx512bw == (has_avx512f && bw_family));
                invariant(has_avx512vl
                    == (has_avx512f && vector_size < 64u));
                invariant(has_apx == uses_apx);
                expected_group_count = (unsigned int)(2 + has_i386
                    + has_amd64 + has_apx
                    + (has_avx512f && bw_family)
                    + (has_avx512f && vector_size < 64u));
                invariant(first.x86_group_count == expected_group_count);
                invariant(!uses_apx || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
            }
            if (is_integer_minmax || is_integer_multiply
                || is_integer_add_sub || is_integer_average
                || is_integer_logical || is_variable_shift) {
                int has_avx512f = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F);
                int has_avx10_1 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1);

                invariant(first.operand_count == 3u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type
                        == CDISASM_OPERAND_REGISTER
                    || first.opcode[2].type == CDISASM_OPERAND_MEMORY);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.encoding.immediate_count == 0u);
                invariant(has_avx512f != has_avx10_1);
                if (is_variable_shift) {
                    size_t evex_offset =
                        (size_t)first.encoding.opcode_offset - 4u;
                    uint8_t p0 = code[evex_offset + 1u];
                    uint8_t p1 = code[evex_offset + 2u];
                    uint8_t opcode = code[first.encoding.opcode_offset];
                    int w = (p1 & UINT8_C(0x80)) != 0u;
                    int has_apx_encoding =
                        (p0 & UINT8_C(0x08)) != 0u
                        || (p1 & UINT8_C(0x04)) == 0u;
                    int is_word_shift =
                        first.name_id >= CDISASM_X86_NAME_VPSLLVW
                        && first.name_id <= CDISASM_X86_NAME_VPSRAVW;

                    invariant((p0 & UINT8_C(0x07)) == UINT8_C(0x02));
                    invariant((p1 & UINT8_C(0x03)) == UINT8_C(0x01));
                    invariant((opcode == UINT8_C(0x47)
                            && first.name_id == (w
                                ? CDISASM_X86_NAME_VPSLLVQ
                                : CDISASM_X86_NAME_VPSLLVD))
                        || (opcode == UINT8_C(0x45)
                            && first.name_id == (w
                                ? CDISASM_X86_NAME_VPSRLVQ
                                : CDISASM_X86_NAME_VPSRLVD))
                        || (opcode == UINT8_C(0x46)
                            && first.name_id == (w
                                ? CDISASM_X86_NAME_VPSRAVQ
                                : CDISASM_X86_NAME_VPSRAVD))
                        || (opcode == UINT8_C(0x12) && w
                            && first.name_id
                                == CDISASM_X86_NAME_VPSLLVW)
                        || (opcode == UINT8_C(0x10) && w
                            && first.name_id
                                == CDISASM_X86_NAME_VPSRLVW)
                        || (opcode == UINT8_C(0x11) && w
                            && first.name_id
                                == CDISASM_X86_NAME_VPSRAVW)
                        || (opcode == UINT8_C(0x15)
                            && first.name_id == (w
                                ? CDISASM_X86_NAME_VPROLVQ
                                : CDISASM_X86_NAME_VPROLVD))
                        || (opcode == UINT8_C(0x14)
                            && first.name_id == (w
                                ? CDISASM_X86_NAME_VPRORVQ
                                : CDISASM_X86_NAME_VPRORVD)));
                    invariant(is_apx_evex == has_apx_encoding);
                    if (is_word_shift) {
                        invariant(first.opcode[2].broadcast
                            == CDISASM_X86_BROADCAST_NONE);
                        invariant(!has_avx512f
                            || cdisasm_instruction_has_x86_group(
                                &first, CDISASM_X86_GROUP_AVX512BW));
                    }
                    if ((p1 & UINT8_C(0x04)) == 0u) {
                        invariant(mode == CDISASM_MODE_64);
                        invariant(first.opcode[2].type
                            == CDISASM_OPERAND_MEMORY);
                    }
                }
            }
            if (is_immediate_shift_rotate) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                uint8_t p0 = code[evex_offset + 1u];
                uint8_t p1 = code[evex_offset + 2u];
                uint8_t modrm = code[first.encoding.modrm_offset];
                unsigned int extension = (modrm >> 3) & 7u;
                int w = (p1 & UINT8_C(0x80)) != 0u;
                cdisasm_x86_name_id expected_name =
                    CDISASM_X86_NAME_NONE;
                int has_apx_encoding =
                    (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                int has_avx512f = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F);
                int has_avx10_1 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1);

                invariant(first.operand_count == 3u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[1].type
                        == CDISASM_OPERAND_REGISTER
                    || first.opcode[1].type == CDISASM_OPERAND_MEMORY);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type
                    == CDISASM_OPERAND_IMMEDIATE);
                invariant(first.opcode[2].size == 1u);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.encoding.immediate_count == 1u);
                invariant(first.encoding.immediate_size[0] == 1u);
                invariant(first.encoding.immediate_offset[0]
                    < first_size);
                invariant((p0 & UINT8_C(0x07)) == UINT8_C(0x01));
                invariant((p1 & UINT8_C(0x03)) == UINT8_C(0x01));
                switch (code[first.encoding.opcode_offset]) {
                    case UINT8_C(0x71):
                        switch (extension) {
                            case 2: expected_name = CDISASM_X86_NAME_VPSRLW;
                                break;
                            case 4: expected_name = CDISASM_X86_NAME_VPSRAW;
                                break;
                            case 6: expected_name = CDISASM_X86_NAME_VPSLLW;
                                break;
                            default: break;
                        }
                        break;
                    case UINT8_C(0x73):
                        switch (extension) {
                            case 2: expected_name = CDISASM_X86_NAME_VPSRLQ;
                                break;
                            case 3: expected_name = CDISASM_X86_NAME_VPSRLDQ;
                                break;
                            case 6: expected_name = CDISASM_X86_NAME_VPSLLQ;
                                break;
                            case 7: expected_name = CDISASM_X86_NAME_VPSLLDQ;
                                break;
                            default: break;
                        }
                        break;
                    case UINT8_C(0x72):
                        switch (extension) {
                    case 0:
                        expected_name = w ? CDISASM_X86_NAME_VPRORQ
                            : CDISASM_X86_NAME_VPRORD;
                        break;
                    case 1:
                        expected_name = w ? CDISASM_X86_NAME_VPROLQ
                            : CDISASM_X86_NAME_VPROLD;
                        break;
                    case 2:
                        if (!w) {
                            expected_name = CDISASM_X86_NAME_VPSRLD;
                        }
                        break;
                    case 4:
                        expected_name = w ? CDISASM_X86_NAME_VPSRAQ
                            : CDISASM_X86_NAME_VPSRAD;
                        break;
                    case 6:
                        if (!w) {
                            expected_name = CDISASM_X86_NAME_VPSLLD;
                        }
                        break;
                    default:
                        break;
                        }
                        break;
                    default:
                        invariant(0);
                        break;
                }
                invariant(expected_name != CDISASM_X86_NAME_NONE);
                invariant(first.name_id == expected_name);
                invariant(has_avx512f != has_avx10_1);
                invariant(is_apx_evex == has_apx_encoding);
                if ((p1 & UINT8_C(0x04)) == 0u) {
                    invariant(mode == CDISASM_MODE_64);
                    invariant(first.opcode[1].type
                        == CDISASM_OPERAND_MEMORY);
                }
            }
            if (is_vbmi2_double_shift) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                uint8_t p0 = code[evex_offset + 1u];
                uint8_t p1 = code[evex_offset + 2u];
                uint8_t map = p0 & UINT8_C(0x07);
                uint8_t opcode = code[first.encoding.opcode_offset];
                int w = (p1 & UINT8_C(0x80)) != 0u;
                int is_immediate = map == UINT8_C(0x03);
                int has_apx_encoding =
                    (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                int has_avx512f = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F);
                int has_avx10_1 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1);
                cdisasm_x86_name_id expected_name =
                    CDISASM_X86_NAME_NONE;

                invariant(map == UINT8_C(0x02)
                    || map == UINT8_C(0x03));
                invariant((p1 & UINT8_C(0x03)) == UINT8_C(0x01));
                invariant(opcode >= UINT8_C(0x70)
                    && opcode <= UINT8_C(0x73));
                invariant(first.operand_count == (is_immediate ? 4u : 3u));
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].access == (!is_immediate
                        || first.mask_mode == CDISASM_X86_MASK_MERGE
                    ? CDISASM_OPERAND_ACCESS_READ_WRITE
                    : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type
                        == CDISASM_OPERAND_REGISTER
                    || first.opcode[2].type == CDISASM_OPERAND_MEMORY);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.encoding.immediate_count
                    == (is_immediate ? 1u : 0u));
                if (is_immediate) {
                    invariant(first.opcode[3].type
                        == CDISASM_OPERAND_IMMEDIATE);
                    invariant(first.opcode[3].size == 1u);
                    invariant(first.opcode[3].access
                        == CDISASM_OPERAND_ACCESS_READ);
                    invariant(first.encoding.immediate_size[0] == 1u);
                    invariant(first.encoding.immediate_offset[0]
                        < first_size);
                }
                if (opcode == UINT8_C(0x70)) {
                    invariant(w);
                    expected_name = is_immediate
                        ? CDISASM_X86_NAME_VPSHLDW
                        : CDISASM_X86_NAME_VPSHLDVW;
                } else if (opcode == UINT8_C(0x71)) {
                    expected_name = is_immediate
                        ? (w ? CDISASM_X86_NAME_VPSHLDQ
                             : CDISASM_X86_NAME_VPSHLDD)
                        : (w ? CDISASM_X86_NAME_VPSHLDVQ
                             : CDISASM_X86_NAME_VPSHLDVD);
                } else if (opcode == UINT8_C(0x72)) {
                    invariant(w);
                    expected_name = is_immediate
                        ? CDISASM_X86_NAME_VPSHRDW
                        : CDISASM_X86_NAME_VPSHRDVW;
                } else {
                    expected_name = is_immediate
                        ? (w ? CDISASM_X86_NAME_VPSHRDQ
                             : CDISASM_X86_NAME_VPSHRDD)
                        : (w ? CDISASM_X86_NAME_VPSHRDVQ
                             : CDISASM_X86_NAME_VPSHRDVD);
                }
                invariant(first.name_id == expected_name);
                invariant(has_avx512f != has_avx10_1);
                invariant(is_apx_evex == has_apx_encoding);
                if (has_avx512f) {
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512VBMI2));
                }
                if (opcode == UINT8_C(0x70)
                    || opcode == UINT8_C(0x72)) {
                    invariant(first.opcode[2].broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                }
                if ((p1 & UINT8_C(0x04)) == 0u) {
                    invariant(mode == CDISASM_MODE_64);
                    invariant(first.opcode[2].type
                        == CDISASM_OPERAND_MEMORY);
                }
            }
            if (is_compress_expand) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                uint8_t p0 = code[evex_offset + 1u];
                uint8_t p1 = code[evex_offset + 2u];
                uint8_t p2 = code[evex_offset + 3u];
                uint8_t opcode = code[first.encoding.opcode_offset];
                int w = (p1 & UINT8_C(0x80)) != 0u;
                int is_compress =
                    (first.name_id >= CDISASM_X86_NAME_VPCOMPRESSB
                        && first.name_id <= CDISASM_X86_NAME_VPCOMPRESSQ)
                    || first.name_id == CDISASM_X86_NAME_VCOMPRESSPD
                    || first.name_id == CDISASM_X86_NAME_VCOMPRESSPS;
                int is_byte_word = opcode == UINT8_C(0x62)
                    || opcode == UINT8_C(0x63);
                int is_fp = opcode == UINT8_C(0x88)
                    || opcode == UINT8_C(0x8a);
                int has_apx_encoding =
                    (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                int has_avx512f = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F);
                int has_avx10_1 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1);
                unsigned int memory_operand = is_compress ? 0u : 1u;
                cdisasm_x86_name_id expected_name;

                invariant((p0 & UINT8_C(0x07)) == UINT8_C(0x02));
                invariant((p1 & UINT8_C(0x03)) == UINT8_C(0x01));
                invariant((p1 & UINT8_C(0x78)) == UINT8_C(0x78));
                invariant((p2 & UINT8_C(0x08)) != 0u);
                invariant((p2 & UINT8_C(0x10)) == 0u);
                invariant((p2 & UINT8_C(0x60)) != UINT8_C(0x60));
                invariant((p2 & UINT8_C(0x80)) == 0u
                    || (p2 & UINT8_C(0x07)) != 0u);
                invariant(first.operand_count == 2u);
                invariant(opcode == UINT8_C(0x62)
                    || opcode == UINT8_C(0x63)
                    || opcode == UINT8_C(0x88)
                    || opcode == UINT8_C(0x89)
                    || opcode == UINT8_C(0x8a)
                    || opcode == UINT8_C(0x8b));
                invariant((opcode == UINT8_C(0x63)
                        || opcode == UINT8_C(0x8a)
                        || opcode == UINT8_C(0x8b)) == is_compress);
                if (opcode == UINT8_C(0x63)) {
                    expected_name = w ? CDISASM_X86_NAME_VPCOMPRESSW
                        : CDISASM_X86_NAME_VPCOMPRESSB;
                } else if (opcode == UINT8_C(0x8b)) {
                    expected_name = w ? CDISASM_X86_NAME_VPCOMPRESSQ
                        : CDISASM_X86_NAME_VPCOMPRESSD;
                } else if (opcode == UINT8_C(0x62)) {
                    expected_name = w ? CDISASM_X86_NAME_VPEXPANDW
                        : CDISASM_X86_NAME_VPEXPANDB;
                } else if (opcode == UINT8_C(0x8a)) {
                    expected_name = w ? CDISASM_X86_NAME_VCOMPRESSPD
                        : CDISASM_X86_NAME_VCOMPRESSPS;
                } else if (opcode == UINT8_C(0x88)) {
                    expected_name = w ? CDISASM_X86_NAME_VEXPANDPD
                        : CDISASM_X86_NAME_VEXPANDPS;
                } else {
                    expected_name = w ? CDISASM_X86_NAME_VPEXPANDQ
                        : CDISASM_X86_NAME_VPEXPANDD;
                }
                invariant(first.name_id == expected_name);
                invariant(first.opcode[0].type
                        == CDISASM_OPERAND_REGISTER
                    || (is_compress && first.opcode[0].type
                        == CDISASM_OPERAND_MEMORY));
                invariant(first.opcode[1].type
                        == CDISASM_OPERAND_REGISTER
                    || (!is_compress && first.opcode[1].type
                        == CDISASM_OPERAND_MEMORY));
                invariant(first.opcode[0].access
                    == (first.opcode[0].type == CDISASM_OPERAND_MEMORY
                        || first.mask_mode != CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ_WRITE));
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.encoding.immediate_count == 0u);
                invariant(has_avx512f != has_avx10_1);
                invariant(is_apx_evex == has_apx_encoding);
                if (has_avx512f && is_byte_word) {
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512VBMI2));
                }
                if (first.opcode[memory_operand].type
                    == CDISASM_OPERAND_MEMORY) {
                    invariant(first.opcode[memory_operand].broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                    if (is_compress) {
                        invariant(first.mask_mode
                            != CDISASM_X86_MASK_ZERO);
                    }
                }
                if (is_fp) {
                    unsigned int ll = (p2 >> 5) & 3u;
                    int memory = first.opcode[memory_operand].type
                        == CDISASM_OPERAND_MEMORY;
                    cdisasm_x86_form_id base;
                    cdisasm_x86_form_id expected_form;
                    cdisasm_x86_group_id width_group;
                    cdisasm_x86_decode_bit_id width_bit;

                    if (opcode == UINT8_C(0x8a)) {
                        base = w ? UINT16_C(3637) : UINT16_C(3643);
                        expected_form = (cdisasm_x86_form_id)(
                            base + (memory ? 0u : 3u) + ll);
                    } else {
                        base = w ? UINT16_C(4527) : UINT16_C(4533);
                        expected_form = (cdisasm_x86_form_id)(
                            base + 2u * ll + (memory ? 0u : 1u));
                    }
                    invariant(first.form_id == expected_form);
                    width_group = ll == 0u
                        ? CDISASM_X86_GROUP_AVX512F_128
                        : ll == 1u ? CDISASM_X86_GROUP_AVX512F_256
                                   : CDISASM_X86_GROUP_AVX512F_512;
                    width_bit = ll == 0u
                        ? CDISASM_X86_DECODE_BIT_AVX512F_128
                        : ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512F_256
                                   : CDISASM_X86_DECODE_BIT_AVX512F_512;
                    invariant(cdisasm_instruction_has_x86_group(
                        &first,width_group));
                    invariant(cdisasm_decode_flags_test_bit(
                        decode_flags,width_bit));
                }
                if ((p1 & UINT8_C(0x04)) == 0u) {
                    invariant(mode == CDISASM_MODE_64);
                    invariant(first.opcode[memory_operand].type
                        == CDISASM_OPERAND_MEMORY);
                }
            }
            if (is_vnni_dot_product) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                uint8_t p0 = code[evex_offset + 1u];
                uint8_t p1 = code[evex_offset + 2u];
                uint8_t p2 = code[evex_offset + 3u];
                uint8_t opcode = code[first.encoding.opcode_offset];
                int has_apx_encoding =
                    (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                int has_avx512f = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F);
                int has_avx10_1 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1);
                cdisasm_x86_name_id expected_name = opcode == UINT8_C(0x50)
                    ? CDISASM_X86_NAME_VPDPBUSD
                    : opcode == UINT8_C(0x51)
                        ? CDISASM_X86_NAME_VPDPBUSDS
                        : opcode == UINT8_C(0x52)
                            ? CDISASM_X86_NAME_VPDPWSSD
                            : CDISASM_X86_NAME_VPDPWSSDS;

                invariant((p0 & UINT8_C(0x07)) == UINT8_C(0x02));
                invariant((p1 & UINT8_C(0x83)) == UINT8_C(0x01));
                invariant(opcode >= UINT8_C(0x50)
                    && opcode <= UINT8_C(0x53));
                invariant(first.name_id == expected_name);
                invariant(first.operand_count == 3u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type
                        == CDISASM_OPERAND_REGISTER
                    || first.opcode[2].type == CDISASM_OPERAND_MEMORY);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.encoding.immediate_count == 0u);
                invariant(has_avx512f != has_avx10_1);
                invariant(is_apx_evex == has_apx_encoding);
                if (has_avx512f) {
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512VNNI));
                }
                if (first.opcode[2].type == CDISASM_OPERAND_MEMORY
                    && (p2 & UINT8_C(0x10)) != 0u) {
                    invariant(first.opcode[2].size == 4u);
                    invariant(first.opcode[2].broadcast
                        == first.opcode[0].size / 4u);
                } else {
                    invariant(first.opcode[2].size
                        == first.opcode[0].size);
                    invariant(first.opcode[2].broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                }
                if ((p1 & UINT8_C(0x04)) == 0u) {
                    invariant(mode == CDISASM_MODE_64);
                    invariant(first.opcode[2].type
                        == CDISASM_OPERAND_MEMORY);
                }
            }
            if (is_avx10_vnni_int8) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                uint8_t p0 = code[evex_offset + 1u];
                uint8_t p1 = code[evex_offset + 2u];
                uint8_t p2 = code[evex_offset + 3u];
                uint8_t opcode = code[first.encoding.opcode_offset];
                int has_apx_encoding =
                    (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;

                invariant((p0 & UINT8_C(0x07)) == UINT8_C(0x02));
                invariant((p1 & UINT8_C(0x80)) == 0u);
                invariant((p1 & UINT8_C(0x03)) != UINT8_C(0x01));
                invariant(opcode == UINT8_C(0x50)
                    || opcode == UINT8_C(0x51));
                invariant(first.operand_count == 3u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type
                        == CDISASM_OPERAND_REGISTER
                    || first.opcode[2].type == CDISASM_OPERAND_MEMORY);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.encoding.immediate_count == 0u);
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_2));
                invariant(!cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F));
                invariant(is_apx_evex == has_apx_encoding);
                if (first.opcode[2].type == CDISASM_OPERAND_MEMORY
                    && (p2 & UINT8_C(0x10)) != 0u) {
                    invariant(first.opcode[2].size == 4u);
                    invariant(first.opcode[2].broadcast
                        == first.opcode[0].size / 4u);
                } else {
                    invariant(first.opcode[2].size
                        == first.opcode[0].size);
                    invariant(first.opcode[2].broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                }
                if ((p1 & UINT8_C(0x04)) == 0u) {
                    invariant(mode == CDISASM_MODE_64);
                    invariant(first.opcode[2].type
                        == CDISASM_OPERAND_MEMORY);
                }
            }
            if (is_4vnniw) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                uint8_t p0 = code[evex_offset + 1u];
                uint8_t p1 = code[evex_offset + 2u];
                uint8_t p2 = code[evex_offset + 3u];
                uint8_t opcode = code[first.encoding.opcode_offset];
                uint8_t modrm = code[first.encoding.modrm_offset];
                unsigned int encoded_source =
                    ((unsigned int)(~p1) >> 3) & 15u;

                encoded_source += (p2 & UINT8_C(0x08)) == 0u ? 16u : 0u;
                invariant((p0 & UINT8_C(0x0f)) == UINT8_C(0x02));
                invariant((p1 & UINT8_C(0x87)) == UINT8_C(0x07));
                invariant((p2 & UINT8_C(0x70)) == UINT8_C(0x40));
                invariant(opcode == UINT8_C(0x52)
                    || opcode == UINT8_C(0x53));
                invariant((modrm & UINT8_C(0xc0)) != UINT8_C(0xc0));
                invariant(first.name_id == (opcode == UINT8_C(0x52)
                    ? CDISASM_X86_NAME_VP4DPWSSD
                    : CDISASM_X86_NAME_VP4DPWSSDS));
                invariant(first.operand_count == 3u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].size == 64u);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].reg
                    == (cdisasm_x86_reg_id)(CDISASM_X86_REG_ZMM0
                        + encoded_source));
                invariant(first.opcode[1].size == 64u);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type == CDISASM_OPERAND_MEMORY);
                invariant(first.opcode[2].size == 16u);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512_4VNNIW));
                invariant(!cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1));
                invariant(!is_apx_evex);
                invariant(cpu_id == CDISASM_CPU_X86
                    || cpu_id == CDISASM_CPU_KNIGHTS_MILL);
            }
            if (is_4fmaps) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                uint8_t p0 = code[evex_offset + 1u];
                uint8_t p1 = code[evex_offset + 2u];
                uint8_t p2 = code[evex_offset + 3u];
                uint8_t opcode = code[first.encoding.opcode_offset];
                uint8_t modrm = code[first.encoding.modrm_offset];
                unsigned int encoded_source =
                    ((unsigned int)(~p1) >> 3) & 15u;
                int scalar = (opcode & UINT8_C(0x01)) != 0;
                cdisasm_x86_reg_id vector_base = scalar
                    ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_ZMM0;
                unsigned int vector_size = scalar ? 16u : 64u;
                cdisasm_x86_name_id expected_name =
                    opcode == UINT8_C(0x9a)
                        ? CDISASM_X86_NAME_V4FMADDPS
                    : opcode == UINT8_C(0x9b)
                        ? CDISASM_X86_NAME_V4FMADDSS
                    : opcode == UINT8_C(0xaa)
                        ? CDISASM_X86_NAME_V4FNMADDPS
                        : CDISASM_X86_NAME_V4FNMADDSS;

                encoded_source += (p2 & UINT8_C(0x08)) == 0u ? 16u : 0u;
                invariant((p0 & UINT8_C(0x0f)) == UINT8_C(0x02));
                invariant((p1 & UINT8_C(0x87)) == UINT8_C(0x07));
                invariant((p2 & UINT8_C(0x60))
                    != UINT8_C(0x60));
                invariant(scalar
                    || (p2 & UINT8_C(0x60)) == UINT8_C(0x40));
                invariant(opcode == UINT8_C(0x9a)
                    || opcode == UINT8_C(0x9b)
                    || opcode == UINT8_C(0xaa)
                    || opcode == UINT8_C(0xab));
                invariant((modrm & UINT8_C(0xc0)) != UINT8_C(0xc0));
                invariant(first.name_id == expected_name);
                invariant(first.operand_count == 3u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].size == vector_size);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].reg
                    == (cdisasm_x86_reg_id)(vector_base + encoded_source));
                invariant(first.opcode[1].size == vector_size);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type == CDISASM_OPERAND_MEMORY);
                invariant(first.opcode[2].size == 16u);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F));
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512_4FMAPS));
                invariant(!cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1));
                invariant(!is_apx_evex);
                invariant(cpu_id == CDISASM_CPU_X86
                    || cpu_id == CDISASM_CPU_KNIGHTS_MILL);
            }
            if (is_vgetexp) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                uint8_t p0 = code[evex_offset + 1u];
                uint8_t p1 = code[evex_offset + 2u];
                uint8_t p2 = code[evex_offset + 3u];
                uint8_t opcode = code[first.encoding.opcode_offset];
                unsigned int encoded_source =
                    ((unsigned int)(~p1) >> 3) & 15u;
                int scalar = opcode == UINT8_C(0x43);
                int w = (p1 & UINT8_C(0x80)) != 0u;
                int evex_b = (p2 & UINT8_C(0x10)) != 0u;
                unsigned int source_operand = scalar ? 2u : 1u;
                const cdisasm_opcode *source =
                    &first.opcode[source_operand];
                int source_is_register =
                    source->type == CDISASM_OPERAND_REGISTER;
                unsigned int element_size = w ? 8u : 4u;
                int has_avx512f = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F);
                int has_avx10_1 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1);
                cdisasm_x86_name_id expected_name = scalar
                    ? (w ? CDISASM_X86_NAME_VGETEXPSD
                         : CDISASM_X86_NAME_VGETEXPSS)
                    : (w ? CDISASM_X86_NAME_VGETEXPPD
                         : CDISASM_X86_NAME_VGETEXPPS);

                encoded_source +=
                    (p2 & UINT8_C(0x08)) == 0u ? 16u : 0u;
                invariant((p0 & UINT8_C(0x0f)) == UINT8_C(0x02));
                invariant((p1 & UINT8_C(0x07)) == UINT8_C(0x05));
                invariant(opcode == UINT8_C(0x42)
                    || opcode == UINT8_C(0x43));
                invariant(first.name_id == expected_name);
                invariant(first.operand_count == (scalar ? 3u : 2u));
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(scalar
                    ? first.opcode[0].size == 16u
                    : (first.opcode[0].size == 16u
                        || first.opcode[0].size == 32u
                        || first.opcode[0].size == 64u));
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                if (scalar) {
                    invariant(first.opcode[1].type
                        == CDISASM_OPERAND_REGISTER);
                    invariant(first.opcode[1].reg
                        == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0
                            + encoded_source));
                    invariant(first.opcode[1].size == 16u);
                    invariant(first.opcode[1].access
                        == CDISASM_OPERAND_ACCESS_READ);
                } else {
                    invariant(encoded_source == 0u);
                }
                invariant(source_is_register
                    || source->type == CDISASM_OPERAND_MEMORY);
                invariant(source->access == CDISASM_OPERAND_ACCESS_READ);
                if (source_is_register) {
                    invariant(source->size == first.opcode[0].size);
                    invariant(source->broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                } else if (scalar || evex_b) {
                    invariant(source->size == element_size);
                    invariant(source->broadcast == (scalar
                        ? CDISASM_X86_BROADCAST_NONE
                        : first.opcode[0].size / element_size));
                } else {
                    invariant(source->size == first.opcode[0].size);
                    invariant(source->broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                }
                invariant(first.sae == (source_is_register && evex_b
                    ? CDISASM_X86_SAE_ENABLED : CDISASM_X86_SAE_NONE));
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant(has_avx512f != has_avx10_1);
                invariant(!is_apx_evex);
                if (has_avx512f && !scalar
                    && first.opcode[0].size < 64u) {
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512VL));
                }
                if (has_avx10_1) {
                    invariant(!cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512VL));
                }
            }
            if (is_vgetexp16) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                uint8_t p0 = code[evex_offset + 1u];
                uint8_t p1 = code[evex_offset + 2u];
                uint8_t p2 = code[evex_offset + 3u];
                uint8_t opcode = code[first.encoding.opcode_offset];
                unsigned int encoded_source =
                    ((unsigned int)(~p1) >> 3) & 15u;
                int scalar =
                    first.name_id == CDISASM_X86_NAME_VGETEXPSH;
                int bf16 =
                    first.name_id == CDISASM_X86_NAME_VGETEXPBF16;
                int evex_b = (p2 & UINT8_C(0x10)) != 0u;
                unsigned int source_operand = scalar ? 2u : 1u;
                const cdisasm_opcode *source =
                    &first.opcode[source_operand];
                int source_is_register =
                    source->type == CDISASM_OPERAND_REGISTER;
                int has_avx512f = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F);
                int has_fp16 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512FP16);
                int has_avx10_1 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1);
                int has_avx10_2 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_2);

                encoded_source +=
                    (p2 & UINT8_C(0x08)) == 0u ? 16u : 0u;
                invariant((p0 & UINT8_C(0x0f)) == UINT8_C(0x06));
                invariant((p1 & UINT8_C(0x84)) == UINT8_C(0x04));
                invariant((p1 & UINT8_C(0x03))
                    == (bf16 ? UINT8_C(0) : UINT8_C(1)));
                invariant(opcode == (scalar
                    ? UINT8_C(0x43) : UINT8_C(0x42)));
                invariant(first.operand_count == (scalar ? 3u : 2u));
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(scalar
                    ? first.opcode[0].size == 16u
                    : (first.opcode[0].size == 16u
                        || first.opcode[0].size == 32u
                        || first.opcode[0].size == 64u));
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                if (scalar) {
                    invariant(first.opcode[1].type
                        == CDISASM_OPERAND_REGISTER);
                    invariant(first.opcode[1].reg
                        == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0
                            + encoded_source));
                    invariant(first.opcode[1].size == 16u);
                    invariant(first.opcode[1].access
                        == CDISASM_OPERAND_ACCESS_READ);
                } else {
                    invariant(encoded_source == 0u);
                }
                invariant(source_is_register
                    || source->type == CDISASM_OPERAND_MEMORY);
                invariant(source->access == CDISASM_OPERAND_ACCESS_READ);
                if (source_is_register) {
                    invariant(source->size == first.opcode[0].size);
                    invariant(source->broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                } else if (scalar || evex_b) {
                    invariant(source->size == 2u);
                    invariant(source->broadcast == (scalar
                        ? CDISASM_X86_BROADCAST_NONE
                        : first.opcode[0].size / 2u));
                } else {
                    invariant(source->size == first.opcode[0].size);
                    invariant(source->broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                }
                invariant(first.sae == (source_is_register && evex_b
                    ? CDISASM_X86_SAE_ENABLED : CDISASM_X86_SAE_NONE));
                invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant(!is_apx_evex);
                if (bf16) {
                    invariant(!evex_b || !source_is_register);
                    invariant(has_avx10_2);
                    invariant(!has_avx512f && !has_fp16 && !has_avx10_1);
                } else {
                    invariant(has_avx10_1
                        != (has_avx512f && has_fp16));
                    invariant(!has_avx10_2);
                    if (has_avx512f && !scalar
                        && first.opcode[0].size < 64u) {
                        invariant(cdisasm_instruction_has_x86_group(
                            &first, CDISASM_X86_GROUP_AVX512VL));
                    }
                    if (has_avx10_1) {
                        invariant(!cdisasm_instruction_has_x86_group(
                            &first, CDISASM_X86_GROUP_AVX512VL));
                    }
                }
                if (scalar) {
                    invariant(!evex_b || source_is_register);
                }
                if (evex_b && source_is_register) {
                    invariant(first.opcode[0].size
                        == (scalar ? 16u : 64u));
                }
            }
            if (is_permute_ternary) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                uint8_t p0 = code[evex_offset + 1u];
                uint8_t p1 = code[evex_offset + 2u];
                uint8_t p2 = code[evex_offset + 3u];
                uint8_t opcode = code[first.encoding.opcode_offset];
                int is_multishift =
                    first.name_id == CDISASM_X86_NAME_VPMULTISHIFTQB;
                int is_word_permute =
                    first.name_id >= CDISASM_X86_NAME_VPERMI2W
                    && first.name_id <= CDISASM_X86_NAME_VPERMW;
                int destructive =
                    first.name_id == CDISASM_X86_NAME_VPERMI2B
                    || first.name_id == CDISASM_X86_NAME_VPERMT2B
                    || first.name_id == CDISASM_X86_NAME_VPERMI2W
                    || first.name_id == CDISASM_X86_NAME_VPERMT2W;
                int has_apx_encoding =
                    (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                int has_avx512f = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F);
                int has_avx10_1 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1);

                invariant((p0 & UINT8_C(0x07)) == UINT8_C(0x02));
                invariant((p1 & UINT8_C(0x03)) == UINT8_C(0x01));
                invariant(opcode == UINT8_C(0x75)
                    || opcode == UINT8_C(0x7d)
                    || opcode == UINT8_C(0x83)
                    || opcode == UINT8_C(0x8d));
                invariant(((p1 & UINT8_C(0x80)) != 0u)
                    == (is_multishift || is_word_permute));
                invariant(first.operand_count == 3u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].access
                    == (destructive
                            || first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type
                        == CDISASM_OPERAND_REGISTER
                    || first.opcode[2].type == CDISASM_OPERAND_MEMORY);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.encoding.immediate_count == 0u);
                invariant(has_avx512f != has_avx10_1);
                invariant(is_apx_evex == has_apx_encoding);
                if (has_avx512f) {
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, is_word_permute
                            ? CDISASM_X86_GROUP_AVX512BW
                            : CDISASM_X86_GROUP_AVX512VBMI));
                }
                if (first.opcode[2].type == CDISASM_OPERAND_MEMORY
                    && (p2 & UINT8_C(0x10)) != 0u) {
                    invariant(is_multishift);
                    invariant(first.opcode[2].size == 8u);
                    invariant(first.opcode[2].broadcast
                        == first.opcode[0].size / 8u);
                } else {
                    invariant(first.opcode[2].size
                        == first.opcode[0].size);
                    invariant(first.opcode[2].broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                }
                if ((p1 & UINT8_C(0x04)) == 0u) {
                    invariant(mode == CDISASM_MODE_64);
                    invariant(first.opcode[2].type
                        == CDISASM_OPERAND_MEMORY);
                }
            }
            if (is_popcount || is_avx512cd_unary) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                uint8_t p0 = code[evex_offset + 1u];
                uint8_t p1 = code[evex_offset + 2u];
                uint8_t opcode = code[first.encoding.opcode_offset];
                int w = (p1 & UINT8_C(0x80)) != 0u;
                int has_apx_encoding =
                    (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                int has_avx512f = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F);
                int has_avx10_1 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1);
                cdisasm_x86_name_id expected_name;

                invariant((p0 & UINT8_C(0x07)) == UINT8_C(0x02));
                invariant((p1 & UINT8_C(0x03)) == UINT8_C(0x01));
                invariant(opcode == UINT8_C(0x44)
                    || opcode == UINT8_C(0x54)
                    || opcode == UINT8_C(0x55)
                    || opcode == UINT8_C(0xc4));
                if (opcode == UINT8_C(0x54)) {
                    expected_name = w ? CDISASM_X86_NAME_VPOPCNTW
                        : CDISASM_X86_NAME_VPOPCNTB;
                } else if (opcode == UINT8_C(0x55)) {
                    expected_name = w ? CDISASM_X86_NAME_VPOPCNTQ
                        : CDISASM_X86_NAME_VPOPCNTD;
                } else if (opcode == UINT8_C(0xc4)) {
                    expected_name = w ? CDISASM_X86_NAME_VPCONFLICTQ
                        : CDISASM_X86_NAME_VPCONFLICTD;
                } else {
                    expected_name = w ? CDISASM_X86_NAME_VPLZCNTQ
                        : CDISASM_X86_NAME_VPLZCNTD;
                }
                invariant(first.name_id == expected_name);
                invariant(first.operand_count == 2u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].access
                    == (first.mask_mode == CDISASM_X86_MASK_MERGE
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
                invariant(first.opcode[1].type
                        == CDISASM_OPERAND_REGISTER
                    || first.opcode[1].type == CDISASM_OPERAND_MEMORY);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.encoding.immediate_count == 0u);
                invariant(has_avx512f != has_avx10_1);
                invariant(is_apx_evex == has_apx_encoding);
                if (has_avx512f) {
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, is_avx512cd
                            ? CDISASM_X86_GROUP_AVX512CD
                            : (opcode == UINT8_C(0x54)
                                ? CDISASM_X86_GROUP_AVX512BITALG
                                : CDISASM_X86_GROUP_AVX512VPOPCNTDQ)));
                }
                if (opcode == UINT8_C(0x54)) {
                    invariant(first.opcode[1].broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                }
                if ((p1 & UINT8_C(0x04)) == 0u) {
                    invariant(mode == CDISASM_MODE_64);
                    invariant(first.opcode[1].type
                        == CDISASM_OPERAND_MEMORY);
                }
            }
            if (is_avx512cd_mask_broadcast) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                uint8_t p0 = code[evex_offset + 1u];
                uint8_t p1 = code[evex_offset + 2u];
                uint8_t p2 = code[evex_offset + 3u];
                uint8_t opcode = code[first.encoding.opcode_offset];
                uint8_t modrm = code[first.encoding.modrm_offset];
                int has_apx_encoding =
                    (p0 & UINT8_C(0x08)) != 0u;
                int has_avx512f = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F);
                int has_avx10_1 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1);

                invariant((p0 & UINT8_C(0x07)) == UINT8_C(0x02));
                invariant((p1 & UINT8_C(0x03)) == UINT8_C(0x02));
                invariant((p1 & UINT8_C(0x04)) != 0u);
                invariant((p2 & UINT8_C(0x9f)) == UINT8_C(0x08));
                invariant((modrm & UINT8_C(0xc0)) == UINT8_C(0xc0));
                invariant(opcode == UINT8_C(0x2a)
                    || opcode == UINT8_C(0x3a));
                invariant(((p1 & UINT8_C(0x80)) != 0u)
                    == (opcode == UINT8_C(0x2a)));
                invariant(first.name_id
                    == (opcode == UINT8_C(0x2a)
                        ? CDISASM_X86_NAME_VPBROADCASTMB2Q
                        : CDISASM_X86_NAME_VPBROADCASTMW2D));
                invariant(first.operand_count == 2u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].reg >= CDISASM_X86_REG_K0
                    && first.opcode[1].reg <= CDISASM_X86_REG_K7);
                invariant(first.opcode[1].reg
                    == (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0
                        + (modrm & UINT8_C(0x07))));
                invariant(first.opcode[1].size == 8u);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[1].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.mask_reg == CDISASM_X86_REG_NONE);
                invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant(has_avx512f != has_avx10_1);
                invariant(is_apx_evex == has_apx_encoding);
                if (has_avx512f) {
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512CD));
                }
            }
            if (is_bitalg_mask_destination) {
                size_t evex_offset =
                    (size_t)first.encoding.opcode_offset - 4u;
                uint8_t p0 = code[evex_offset + 1u];
                uint8_t p1 = code[evex_offset + 2u];
                int has_apx_encoding =
                    (p0 & UINT8_C(0x08)) != 0u
                    || (p1 & UINT8_C(0x04)) == 0u;
                int has_avx512f = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512F);
                int has_avx10_1 = cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX10_1);

                invariant((p0 & UINT8_C(0x07)) == UINT8_C(0x02));
                invariant((p1 & UINT8_C(0x83)) == UINT8_C(0x01));
                invariant(code[first.encoding.opcode_offset]
                    == UINT8_C(0x8f));
                invariant(first.operand_count == 3u);
                invariant(first.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[0].reg >= CDISASM_X86_REG_K0
                    && first.opcode[0].reg <= CDISASM_X86_REG_K7);
                invariant(first.opcode[0].access
                    == (first.mask_reg == CDISASM_X86_REG_NONE
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ_WRITE));
                invariant(first.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                invariant(first.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].type
                        == CDISASM_OPERAND_REGISTER
                    || first.opcode[2].type == CDISASM_OPERAND_MEMORY);
                invariant(first.opcode[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
                invariant(first.opcode[2].broadcast
                    == CDISASM_X86_BROADCAST_NONE);
                invariant(first.encoding.immediate_count == 0u);
                invariant(first.mask_mode != CDISASM_X86_MASK_ZERO);
                invariant(has_avx512f != has_avx10_1);
                invariant(is_apx_evex == has_apx_encoding);
                if (has_avx512f) {
                    invariant(cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AVX512BITALG));
                }
                if ((p1 & UINT8_C(0x04)) == 0u) {
                    invariant(mode == CDISASM_MODE_64);
                    invariant(first.opcode[2].type
                        == CDISASM_OPERAND_MEMORY);
                }
            }
            if (is_fma3) {
                invariant(first.operand_count == 3u);
                invariant(first.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
                invariant(cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_FMA3));
            }
        }
#else
        invariant(0);
#endif
    }
    if (first.name_id == CDISASM_X86_NAME_VMPTRLD
        || first.name_id == CDISASM_X86_NAME_VMPTRST) {
        invariant(first.form_id == (first.name_id
                == CDISASM_X86_NAME_VMPTRLD
            ? UINT16_C(5997) : UINT16_C(5998)));
        invariant((first.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
        invariant(first.operand_count == 1u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
        invariant(first.opcode[0].size == 8u);
        invariant(first.opcode[0].access == (first.name_id
                == CDISASM_X86_NAME_VMPTRST
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_VTX));
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
    }
    if (first.name_id == CDISASM_X86_NAME_VMREAD) {
        const int wide = mode == CDISASM_MODE_64;
        const int memory = first.opcode[0].type
            == CDISASM_OPERAND_MEMORY;
        const cdisasm_x86_form_id form_id = memory
            ? (wide ? UINT16_C(6002) : UINT16_C(6001))
            : (wide ? UINT16_C(6000) : UINT16_C(5999));

        invariant(first.form_id == form_id);
        invariant((first.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
        invariant(first.operand_count == 2u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY
            || first.opcode[0].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(first.opcode[0].size == (wide ? 8u : 4u));
        invariant(first.opcode[1].size == (wide ? 8u : 4u));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_VTX));
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
    }
    if (first.name_id == CDISASM_X86_NAME_VMWRITE) {
        const int wide = mode == CDISASM_MODE_64;
        const int memory = first.opcode[1].type
            == CDISASM_OPERAND_MEMORY;
        const cdisasm_x86_form_id form_id = memory
            ? (wide ? UINT16_C(6051) : UINT16_C(6049))
            : (wide ? UINT16_C(6050) : UINT16_C(6048));

        invariant(first.form_id == form_id);
        invariant((first.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
        invariant(first.operand_count == 2u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(first.opcode[1].type == CDISASM_OPERAND_MEMORY
            || first.opcode[1].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(first.opcode[0].size == (wide ? 8u : 4u));
        invariant(first.opcode[1].size == (wide ? 8u : 4u));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_VTX));
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
    }
    if (first.name_id == CDISASM_X86_NAME_VMRESUME) {
        invariant(first.form_id == UINT16_C(6003));
        invariant((first.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
        invariant(first.operand_count == 0u);
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_VTX));
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
    }
    if (first.name_id == CDISASM_X86_NAME_VMXOFF) {
        invariant(first.form_id == UINT16_C(6052));
        invariant((first.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
        invariant(first.operand_count == 0u);
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_VTX));
        invariant((first.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
    }
    if (first.name_id == CDISASM_X86_NAME_VMXON) {
        invariant(first.form_id == UINT16_C(6053));
        invariant((first.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
        invariant(first.operand_count == 1u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
        invariant(first.opcode[0].size == 8u);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_VTX));
        invariant((first.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
    }
#if USE_EXTRA_OPCODES
    if ((first.form_id >= UINT16_C(5997)
            && first.form_id <= UINT16_C(6003))
        || (first.form_id >= UINT16_C(6048)
            && first.form_id <= UINT16_C(6053))) {
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_VTX));
        invariant((first.opcode_flags & CDISASM_PREFIX_REX2) == 0u
            || (decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
    }
#endif
    if (first.name_id == CDISASM_X86_NAME_VMRUN) {
        invariant(first.form_id == UINT16_C(6004));
        invariant((first.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
        invariant(first.operand_count == 1u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        invariant((first.opcode[0].flags
            & CDISASM_OPERAND_FLAG_IMPLICIT) != 0u);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) == 0u);
        invariant(!cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_VTX));
    }
    if (first.name_id == CDISASM_X86_NAME_VMSAVE) {
        invariant(first.form_id == UINT16_C(6005));
        invariant((first.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
        invariant(first.operand_count == 0u);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) == 0u);
        invariant(!cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_VTX));
    }
    if ((first.opcode_flags & CDISASM_PREFIX_REX2) != 0u) {
        invariant(first.encoding.prefix_size >= 2u);
    }
    if ((first.opcode_flags & CDISASM_PREFIX_REX2) != 0u
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
#if USE_EXTRA_OPCODES
        int is_rex2_alu = first.name_id == CDISASM_X86_NAME_ADD
            || first.name_id == CDISASM_X86_NAME_OR
            || first.name_id == CDISASM_X86_NAME_ADC
            || first.name_id == CDISASM_X86_NAME_SBB
            || first.name_id == CDISASM_X86_NAME_AND
            || first.name_id == CDISASM_X86_NAME_SUB
            || first.name_id == CDISASM_X86_NAME_XOR
            || first.name_id == CDISASM_X86_NAME_CMP
            || first.name_id == CDISASM_X86_NAME_TEST
            || first.name_id == CDISASM_X86_NAME_MOV;
        int is_rex2_waitpkg = first.name_id >= CDISASM_X86_NAME_UMONITOR
            && first.name_id <= CDISASM_X86_NAME_TPAUSE;
        int is_rex2_cet = first.name_id == CDISASM_X86_NAME_CLRSSBSY
            || first.name_id == CDISASM_X86_NAME_INCSSPD
            || first.name_id == CDISASM_X86_NAME_INCSSPQ
            || first.name_id == CDISASM_X86_NAME_RSTORSSP
            || first.name_id == CDISASM_X86_NAME_SAVEPREVSSP
            || first.name_id == CDISASM_X86_NAME_SETSSBSY;
        int is_rex2_system = first.name_id == CDISASM_X86_NAME_RDPID
            || first.name_id == CDISASM_X86_NAME_SERIALIZE
            || first.name_id == CDISASM_X86_NAME_WBINVD
            || first.name_id == CDISASM_X86_NAME_PTWRITE;
        int is_rex2_movnti = first.name_id == CDISASM_X86_NAME_MOVNTI;
        int is_rex2_lddqu = first.name_id == CDISASM_X86_NAME_LDDQU;
        int is_rex2_non_temporal_store =
            first.name_id == CDISASM_X86_NAME_MOVNTDQ
            || first.name_id == CDISASM_X86_NAME_MOVNTPD
            || first.name_id == CDISASM_X86_NAME_MOVNTPS
            || first.name_id == CDISASM_X86_NAME_MOVNTQ
            || first.name_id == CDISASM_X86_NAME_MOVNTSD
            || first.name_id == CDISASM_X86_NAME_MOVNTSS;
        int is_rex2_monitor_mwait =
            first.name_id == CDISASM_X86_NAME_MONITOR
            || first.name_id == CDISASM_X86_NAME_MWAIT;
        int is_rex2_random = first.name_id == CDISASM_X86_NAME_RDRAND
            || first.name_id == CDISASM_X86_NAME_RDSEED;
        int is_rex2_vmx_pointer = first.name_id == CDISASM_X86_NAME_VMXON
            || first.name_id == CDISASM_X86_NAME_VMCLEAR
            || first.name_id == CDISASM_X86_NAME_VMPTRLD
            || first.name_id == CDISASM_X86_NAME_VMPTRST;
        int is_rex2_virtualization =
            first.name_id == CDISASM_X86_NAME_VMREAD
            || first.name_id == CDISASM_X86_NAME_VMWRITE
            || first.name_id == CDISASM_X86_NAME_VMRESUME
            || first.name_id == CDISASM_X86_NAME_VMXOFF
            || first.name_id == CDISASM_X86_NAME_VMRUN
            || first.name_id == CDISASM_X86_NAME_VMSAVE;
        int is_rex2_sse4a = first.name_id == CDISASM_X86_NAME_EXTRQ
            || first.name_id == CDISASM_X86_NAME_INSERTQ;
        int is_rex2_0fae_legacy = first.name_id == CDISASM_X86_NAME_CLFLUSH
            || first.name_id == CDISASM_X86_NAME_CLFLUSHOPT
            || first.name_id == CDISASM_X86_NAME_CLWB
            || first.name_id == CDISASM_X86_NAME_LDMXCSR
            || first.name_id == CDISASM_X86_NAME_STMXCSR
            || first.name_id == CDISASM_X86_NAME_LFENCE
            || first.name_id == CDISASM_X86_NAME_MFENCE
            || first.name_id == CDISASM_X86_NAME_SFENCE;
        int is_rex2_cldemote_row =
            first.name_id == CDISASM_X86_NAME_CLDEMOTE
            || first.name_id == CDISASM_X86_NAME_NOP;
        int is_rex2_clzero = first.name_id == CDISASM_X86_NAME_CLZERO;
        int is_rex2_pconfig = first.name_id == CDISASM_X86_NAME_PCONFIG;
        int is_rex2_smap = first.name_id == CDISASM_X86_NAME_CLAC
            || first.name_id == CDISASM_X86_NAME_STAC;
        int is_rex2_pbndkb = first.name_id == CDISASM_X86_NAME_PBNDKB;
        int is_rex2_rdpru = first.name_id == CDISASM_X86_NAME_RDPRU;
        int is_rex2_prefetch_row =
            first.name_id == CDISASM_X86_NAME_PREFETCH
            || first.name_id == CDISASM_X86_NAME_PREFETCHW
            || first.name_id == CDISASM_X86_NAME_PREFETCHNTA
            || first.name_id == CDISASM_X86_NAME_PREFETCHT0
            || first.name_id == CDISASM_X86_NAME_PREFETCHT1
            || first.name_id == CDISASM_X86_NAME_PREFETCHT2
            || first.name_id == CDISASM_X86_NAME_PREFETCHRST2
            || first.name_id == CDISASM_X86_NAME_PREFETCHWT1
            || first.name_id == CDISASM_X86_NAME_PREFETCHIT0
            || first.name_id == CDISASM_X86_NAME_PREFETCHIT1;
        int is_rex2_monitorx_cluster =
            first.name_id == CDISASM_X86_NAME_MCOMMIT
            || first.name_id == CDISASM_X86_NAME_MONITORX
            || first.name_id == CDISASM_X86_NAME_MWAITX;
        int is_rex2_amd_invlpgb =
            first.name_id == CDISASM_X86_NAME_INVLPGB
            || first.name_id == CDISASM_X86_NAME_TLBSYNC;
        int is_rex2_snp = first.name_id == CDISASM_X86_NAME_PSMASH
            || first.name_id == CDISASM_X86_NAME_PVALIDATE
            || first.name_id == CDISASM_X86_NAME_RMPADJUST
            || first.name_id == CDISASM_X86_NAME_RMPUPDATE;
        int is_rex2_msr_cluster =
            first.encoding.modrm == UINT8_C(0xc6)
            && (first.name_id == CDISASM_X86_NAME_RDMSRLIST
                || first.name_id == CDISASM_X86_NAME_WRMSRLIST
                || first.name_id == CDISASM_X86_NAME_WRMSRNS);
        int is_rex2_no_operand = first.name_id == CDISASM_X86_NAME_SERIALIZE
            || first.name_id == CDISASM_X86_NAME_WBINVD
            || is_rex2_monitor_mwait
            || is_rex2_clzero
            || is_rex2_pconfig
            || is_rex2_smap
            || is_rex2_pbndkb
            || is_rex2_rdpru
            || is_rex2_monitorx_cluster
            || is_rex2_amd_invlpgb
            || is_rex2_msr_cluster
            || first.name_id == CDISASM_X86_NAME_VMRESUME
            || first.name_id == CDISASM_X86_NAME_VMXOFF
            || first.name_id == CDISASM_X86_NAME_VMSAVE
            || first.name_id == CDISASM_X86_NAME_SAVEPREVSSP
            || first.name_id == CDISASM_X86_NAME_SETSSBSY
            || first.name_id == CDISASM_X86_NAME_LFENCE
            || first.name_id == CDISASM_X86_NAME_MFENCE
            || first.name_id == CDISASM_X86_NAME_SFENCE;
        unsigned int expected_rex2_operands =
            first.name_id == CDISASM_X86_NAME_INSERTQ
                ? 4u
                : (first.name_id == CDISASM_X86_NAME_EXTRQ
                    ? 3u
                    : (first.name_id == CDISASM_X86_NAME_PVALIDATE
                    || first.name_id == CDISASM_X86_NAME_RMPADJUST
                ? 3u
                : (first.name_id == CDISASM_X86_NAME_RMPUPDATE
                          || is_rex2_alu
                          || is_rex2_movnti
                          || is_rex2_lddqu
                          || is_rex2_non_temporal_store
                          || first.name_id == CDISASM_X86_NAME_VMREAD
                          || first.name_id == CDISASM_X86_NAME_VMWRITE
                          || first.name_id == CDISASM_X86_NAME_NOP
                      ? 2u
                      : (is_rex2_no_operand ? 0u : 1u))));

        /* decode_rex2_primary owns map-0 ALU/JMPABS plus the controlled map-1
         * C7, 01, 09, 0D, 18, 78, 79, AE, C3 and F0 rows.  Map-1 01 is deliberately
         * narrower than the legacy Group-7 dispatcher: only its CET spellings,
         * MONITOR/MWAIT, MONITORX/MWAITX/MCOMMIT, MSRLIST/WRMSRNS,
         * AMD_INVLPGB/SNP, SERIALIZE, CLZERO, RDPRU, PCONFIG, and SMAP can
         * succeed, plus the exact VMRESUME/VMXOFF/VMRUN/VMSAVE allocations. */
        invariant(is_rex2_alu
            || first.name_id == CDISASM_X86_NAME_JMPABS
            || is_rex2_waitpkg || is_rex2_cet || is_rex2_system
            || is_rex2_movnti || is_rex2_lddqu
            || is_rex2_non_temporal_store
            || is_rex2_monitor_mwait
            || is_rex2_random || is_rex2_vmx_pointer
            || is_rex2_virtualization || is_rex2_sse4a
            || is_rex2_0fae_legacy || is_rex2_cldemote_row
            || is_rex2_clzero || is_rex2_pconfig
            || is_rex2_smap
            || is_rex2_pbndkb || is_rex2_rdpru
            || is_rex2_prefetch_row
            || is_rex2_monitorx_cluster || is_rex2_amd_invlpgb
            || is_rex2_snp || is_rex2_msr_cluster);
        invariant(first.operand_count == expected_rex2_operands);
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F));
        invariant(mode == CDISASM_MODE_64);
        if (is_rex2_random) {
            invariant(first.operand_count == 1u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(cdisasm_instruction_has_x86_group(
                &first, first.name_id == CDISASM_X86_NAME_RDRAND
                    ? CDISASM_X86_GROUP_RDRAND
                    : CDISASM_X86_GROUP_RDSEED));
        }
#else
        invariant(0);
#endif
    }
#if USE_EXTRA_OPCODES
    if (first.name_id >= CDISASM_X86_NAME_CLRSSBSY
        && first.name_id <= CDISASM_X86_NAME_WRUSSQ
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        int is_qword = first.name_id == CDISASM_X86_NAME_INCSSPQ
            || first.name_id == CDISASM_X86_NAME_RDSSPQ
            || first.name_id == CDISASM_X86_NAME_WRSSQ
            || first.name_id == CDISASM_X86_NAME_WRUSSQ;
        int is_privileged = first.name_id == CDISASM_X86_NAME_CLRSSBSY
            || first.name_id == CDISASM_X86_NAME_SETSSBSY
            || first.name_id == CDISASM_X86_NAME_WRUSSD
            || first.name_id == CDISASM_X86_NAME_WRUSSQ;

        invariant((decode_flag_word0(decode_flags)
            & CDISASM_X86_DECODE_FLAG_CET) != 0u);
        invariant((cpu_flag_word0(cpu_id, mode)
            & CDISASM_X86_DECODE_FLAG_CET) != 0u);
        invariant(mode != CDISASM_MODE_16
            || first.name_id == CDISASM_X86_NAME_CLRSSBSY
            || first.name_id == CDISASM_X86_NAME_INCSSPD
            || first.name_id == CDISASM_X86_NAME_RDSSPD
            || first.name_id == CDISASM_X86_NAME_RSTORSSP
            || first.name_id == CDISASM_X86_NAME_SAVEPREVSSP
            || first.name_id == CDISASM_X86_NAME_SETSSBSY
            || first.name_id == CDISASM_X86_NAME_WRSSD
            || first.name_id == CDISASM_X86_NAME_WRUSSD);
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_CET_SS));
        invariant(((first.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u)
            == is_privileged);

        if (first.name_id == CDISASM_X86_NAME_CLRSSBSY
            && (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u
            && first.encoding.modrm_offset != 0u
            && (first.encoding.modrm & UINT8_C(0xc7)) == UINT8_C(0x04)
            && first.encoding.sib_offset != 0u
            && (first.encoding.sib & UINT8_C(0x07)) == UINT8_C(0x05)) {
            invariant(first.opcode[0].base_reg == CDISASM_X86_REG_NONE);
            invariant(first.encoding.displacement_size == 4u);
        }

        if (first.name_id == CDISASM_X86_NAME_CLRSSBSY
            || first.name_id == CDISASM_X86_NAME_RSTORSSP) {
            invariant(first.operand_count == 1u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
            invariant(first.opcode[0].size == 8u);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
        } else if (first.name_id == CDISASM_X86_NAME_INCSSPD
            || first.name_id == CDISASM_X86_NAME_INCSSPQ
            || first.name_id == CDISASM_X86_NAME_RDSSPD
            || first.name_id == CDISASM_X86_NAME_RDSSPQ) {
            int is_read = first.name_id == CDISASM_X86_NAME_INCSSPD
                || first.name_id == CDISASM_X86_NAME_INCSSPQ;

            invariant(first.operand_count == 1u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].size == (is_qword ? 8u : 4u));
            invariant(first.opcode[0].access == (is_read
                ? CDISASM_OPERAND_ACCESS_READ
                : CDISASM_OPERAND_ACCESS_WRITE));
        } else if (first.name_id == CDISASM_X86_NAME_SAVEPREVSSP
            || first.name_id == CDISASM_X86_NAME_SETSSBSY) {
            invariant(first.operand_count == 0u);
        } else {
            invariant(first.name_id >= CDISASM_X86_NAME_WRSSD
                && first.name_id <= CDISASM_X86_NAME_WRUSSQ);
            invariant(first.operand_count == 2u);
            invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
            invariant(first.opcode[0].size == (is_qword ? 8u : 4u));
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].size == first.opcode[0].size);
            invariant(first.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
    }
    if (first.name_id >= CDISASM_X86_NAME_UMONITOR
        && first.name_id <= CDISASM_X86_NAME_TPAUSE
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        uint8_t expected_size = 4u;
        int register_is_valid;
        int cpu_has_waitpkg = cpu_id == CDISASM_CPU_X86
            || cpu_id == CDISASM_CPU_PENTIUM_SILVER_N6000
            || cpu_id == CDISASM_CPU_ALDER_LAKE
            || cpu_id == CDISASM_CPU_SAPPHIRE_RAPIDS
            || cpu_id == CDISASM_CPU_GRANITE_RAPIDS
            || cpu_id == CDISASM_CPU_ARROW_LAKE
            || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS;

        invariant((decode_flag_word0(decode_flags)
            & CDISASM_X86_DECODE_FLAG_SYSTEM) != 0u);
        invariant(cpu_has_waitpkg);
        invariant(mode == CDISASM_MODE_16
            || mode == CDISASM_MODE_32
            || mode == CDISASM_MODE_64);
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_WAITPKG));
        if ((first.opcode_flags & CDISASM_PREFIX_REX2) != 0u) {
            /* REX2 additionally requires APX-F.  Of the current profiles,
             * unrestricted analysis and Diamond Rapids are the two profiles
             * that also provide WAITPKG; the abstract APX profile deliberately
             * does not imply WAITPKG. */
            invariant(cpu_id == CDISASM_CPU_X86
                || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
        }
        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant(first.operand_count == 1u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(first.opcode[0].flags == CDISASM_OPERAND_FLAG_NONE);

        if (first.name_id == CDISASM_X86_NAME_UMONITOR) {
            int address_override = (first.opcode_flags
                & CDISASM_PREFIX_ADDRESS_SIZE) != 0u;

            if (mode == CDISASM_MODE_16) {
                expected_size = (uint8_t)(address_override ? 4u : 2u);
            } else if (mode == CDISASM_MODE_32) {
                expected_size = (uint8_t)(address_override ? 2u : 4u);
            } else {
                expected_size = (uint8_t)(address_override ? 4u : 8u);
            }
        }
        invariant(first.opcode[0].size == expected_size);

        if (expected_size == 2u) {
            register_is_valid = (first.opcode[0].reg >= CDISASM_X86_REG_AX
                    && first.opcode[0].reg <= CDISASM_X86_REG_R15W)
                || ((first.opcode_flags & CDISASM_PREFIX_REX2) != 0u
                    && first.opcode[0].reg >= CDISASM_X86_REG_R16W
                    && first.opcode[0].reg <= CDISASM_X86_REG_R31W);
        } else if (expected_size == 4u) {
            register_is_valid = (first.opcode[0].reg >= CDISASM_X86_REG_EAX
                    && first.opcode[0].reg <= CDISASM_X86_REG_R15D)
                || ((first.opcode_flags & CDISASM_PREFIX_REX2) != 0u
                    && first.opcode[0].reg >= CDISASM_X86_REG_R16D
                    && first.opcode[0].reg <= CDISASM_X86_REG_R31D);
        } else {
            register_is_valid = (first.opcode[0].reg >= CDISASM_X86_REG_RAX
                    && first.opcode[0].reg <= CDISASM_X86_REG_R15)
                || ((first.opcode_flags & CDISASM_PREFIX_REX2) != 0u
                    && first.opcode[0].reg >= CDISASM_X86_REG_R16
                    && first.opcode[0].reg <= CDISASM_X86_REG_R31);
        }
        invariant(register_is_valid);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
            | CDISASM_PREFIX_EFFECTIVE_MASK
            | CDISASM_PREFIX_HLE_MASK)) == 0u);
        if (first.name_id == CDISASM_X86_NAME_UMONITOR) {
            invariant((first.opcode_flags & CDISASM_PREFIX_REP) != 0u);
        } else if (first.name_id == CDISASM_X86_NAME_UMWAIT) {
            invariant((first.opcode_flags & CDISASM_PREFIX_REPNE) != 0u);
        } else {
            invariant((first.opcode_flags & CDISASM_PREFIX_OPERAND_SIZE)
                != 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_REP | CDISASM_PREFIX_REPNE)) == 0u);
        }
    }
    if ((first.name_id == CDISASM_X86_NAME_AADD
            || first.name_id == CDISASM_X86_NAME_AAND
            || first.name_id == CDISASM_X86_NAME_AOR
            || first.name_id == CDISASM_X86_NAME_AXOR)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        uint8_t operand_size = first.opcode[0].size;
        int is_apx = (first.opcode_flags & CDISASM_PREFIX_EVEX) != 0u;
        cdisasm_x86_form_id form32 = first.name_id == CDISASM_X86_NAME_AADD
            ? (is_apx ? UINT16_C(4) : UINT16_C(2))
            : first.name_id == CDISASM_X86_NAME_AAND
                ? (is_apx ? UINT16_C(10) : UINT16_C(8))
                : first.name_id == CDISASM_X86_NAME_AOR
                    ? (is_apx ? UINT16_C(259) : UINT16_C(257))
                    : (is_apx ? UINT16_C(265) : UINT16_C(263));

        invariant(cpu_id == CDISASM_CPU_X86);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, is_apx
                ? CDISASM_X86_DECODE_BIT_APX_F_RAO_INT
                : CDISASM_X86_DECODE_BIT_RAO_INT));
        invariant(cdisasm_instruction_has_x86_group(
            &first, is_apx
                ? CDISASM_X86_GROUP_APX_F_RAO_INT
                : CDISASM_X86_GROUP_RAO_INT));
        invariant(first.operand_count == 2u);
        invariant(operand_size == 4u || operand_size == 8u);
        invariant(first.form_id
            == (cdisasm_x86_form_id)(form32 + (operand_size == 8u)));
        invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
        invariant(first.opcode[0].access
            == CDISASM_OPERAND_ACCESS_READ_WRITE);
        invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[1].size == operand_size);
        invariant(first.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        invariant((first.opcode_flags
            & (CDISASM_PREFIX_LOCK | CDISASM_PREFIX_REX2
                | CDISASM_PREFIX_EFFECTIVE_MASK)) == 0u);
        if (!is_apx) {
            invariant((operand_size == 8u)
                == ((first.opcode_flags & CDISASM_PREFIX_REX_W) != 0u));
        }
    }
    if ((first.name_id == CDISASM_X86_NAME_BSRINIT
            || first.name_id == CDISASM_X86_NAME_BSRMOVF
            || first.name_id == CDISASM_X86_NAME_BSRMOVH
            || first.name_id == CDISASM_X86_NAME_BSRMOVL)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        size_t bsr_index = first.name_id == CDISASM_X86_NAME_BSRINIT
                || first.opcode[0].reg == CDISASM_X86_REG_BSR0
            ? 0u : 1u;

        invariant(cpu_id == CDISASM_CPU_X86);
        /* ACE_1's exact bitmap bit and the legacy AMX umbrella are
         * equivalent runtime admission routes for these state forms. */
        invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_ACE_1)
            || (decode_flags != NULL
                && (decode_flags->bitmap[
                        CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
                    & CDISASM_X86_DECODE_FLAG_AMX) != 0u));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_ACE_1));
        invariant(first.opcode[bsr_index].type
            == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[bsr_index].reg == CDISASM_X86_REG_BSR0);
        invariant(first.opcode[bsr_index].size == 128u);
        invariant((first.opcode[bsr_index].flags
            & CDISASM_OPERAND_FLAG_IMPLICIT) != 0u);
        if (first.name_id == CDISASM_X86_NAME_BSRINIT) {
            invariant(first.form_id == UINT16_C(378));
            invariant(first.operand_count == 1u);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            invariant((first.opcode_flags & CDISASM_PREFIX_VEX) != 0u);
        } else {
            invariant(first.form_id >= UINT16_C(379)
                && first.form_id <= UINT16_C(388));
            invariant((first.opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
            invariant(first.opcode[bsr_index].access
                == (bsr_index == 0u ? CDISASM_OPERAND_ACCESS_WRITE
                                    : CDISASM_OPERAND_ACCESS_READ));
            invariant(first.operand_count
                == (first.name_id == CDISASM_X86_NAME_BSRMOVF ? 3u : 2u));
        }
    }
    if ((first.name_id == CDISASM_X86_NAME_URDMSR
            || first.name_id == CDISASM_X86_NAME_UWRMSR)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        int is_apx = (first.opcode_flags & CDISASM_PREFIX_EVEX) != 0u;

        invariant(cpu_id == CDISASM_CPU_X86);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, is_apx
                ? CDISASM_X86_DECODE_BIT_APX_F_USER_MSR
                : CDISASM_X86_DECODE_BIT_USER_MSR));
        invariant(cdisasm_instruction_has_x86_group(
            &first, is_apx
                ? CDISASM_X86_GROUP_APX_F_USER_MSR
                : CDISASM_X86_GROUP_USER_MSR));
        invariant(first.form_id >= UINT16_C(3353)
            && first.form_id <= UINT16_C(3360));
        invariant(first.operand_count == 2u);
        invariant(first.opcode[0].access
            == (first.name_id == CDISASM_X86_NAME_URDMSR
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ));
        invariant(first.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        if (first.name_id == CDISASM_X86_NAME_URDMSR) {
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].size == 8u);
        } else {
            invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[1].size == 8u);
        }
    }
    if ((cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_MSRLIST)
            || cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_MSR_IMM)
            || cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F_MSR_IMM)
            || cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_WRMSRNS))
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_list = cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_MSRLIST);
        const int is_vex_imm = cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_MSR_IMM);
        const int is_apx_imm = cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F_MSR_IMM);
        const int is_immediate = is_vex_imm || is_apx_imm;
        const int is_read = first.name_id == CDISASM_X86_NAME_RDMSR
            || first.name_id == CDISASM_X86_NAME_RDMSRLIST;
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;
        const cdisasm_x86_decode_bit_id family_bit = is_list
            ? CDISASM_X86_DECODE_BIT_MSRLIST
            : is_vex_imm ? CDISASM_X86_DECODE_BIT_MSR_IMM
            : is_apx_imm ? CDISASM_X86_DECODE_BIT_APX_F_MSR_IMM
            : CDISASM_X86_DECODE_BIT_WRMSRNS;

        invariant(cdisasm_decode_flags_test_bit(decode_flags, family_bit));
        invariant((first.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK
                | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
        invariant(first.encoding.displacement_size == 0u);
        if (is_immediate) {
            const size_t prefix_start = first.encoding.opcode_offset
                - (is_apx_imm ? 4u : 3u);
            const uint8_t w_byte = code[first.encoding.opcode_offset
                - (is_apx_imm ? 2u : 1u)];

            invariant(cpu_id == CDISASM_CPU_X86);
            invariant(mode == CDISASM_MODE_64);
            invariant(first.form_id == (is_read
                ? (is_apx_imm ? UINT16_C(2573) : UINT16_C(2572))
                : (is_apx_imm ? UINT16_C(8895) : UINT16_C(8894))));
            invariant(first.name_id == (is_read
                ? CDISASM_X86_NAME_RDMSR : CDISASM_X86_NAME_WRMSRNS));
            invariant(first.operand_count == 2u);
            invariant(first.opcode[is_read ? 0u : 1u].type
                == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[is_read ? 0u : 1u].size == 8u);
            invariant(first.opcode[is_read ? 0u : 1u].access
                == (is_read ? CDISASM_OPERAND_ACCESS_WRITE
                            : CDISASM_OPERAND_ACCESS_READ));
            invariant(first.opcode[is_read ? 1u : 0u].type
                == CDISASM_OPERAND_IMMEDIATE);
            invariant(first.opcode[is_read ? 1u : 0u].size == 4u);
            invariant(first.opcode[is_read ? 1u : 0u].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.encoding.modrm != 0u);
            invariant((first.encoding.modrm & UINT8_C(0xf8))
                == UINT8_C(0xc0));
            invariant(first.encoding.immediate_count == 1u);
            invariant(first.encoding.immediate_size[0] == 4u);
            invariant(first.encoding.immediate_offset[0] + 4u == first_size);
            invariant(code[first.encoding.opcode_offset] == UINT8_C(0xf6));
            invariant((w_byte & UINT8_C(0x80)) == 0u);
            invariant(code[prefix_start] == (is_apx_imm
                ? UINT8_C(0x62) : UINT8_C(0xc4)));
        } else {
            invariant(cpu_id == CDISASM_CPU_X86
                || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
            invariant(first.name_id == (is_list
                ? (is_read ? CDISASM_X86_NAME_RDMSRLIST
                           : CDISASM_X86_NAME_WRMSRLIST)
                : CDISASM_X86_NAME_WRMSRNS));
            invariant(first.form_id == (is_list
                ? (is_read ? UINT16_C(2571) : UINT16_C(8892))
                : UINT16_C(8893)));
            invariant(!is_list || mode == CDISASM_MODE_64);
            invariant(first.operand_count == 0u);
            invariant(first.encoding.modrm == UINT8_C(0xc6));
            invariant(first.encoding.immediate_count == 0u);
            invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
            if (is_rex2) {
                invariant(mode == CDISASM_MODE_64);
                invariant((decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
            }
        }
    }
    if ((first.name_id == CDISASM_X86_NAME_ENQCMD
            || first.name_id == CDISASM_X86_NAME_ENQCMDS)) {
        const int is_apx = (first.opcode_flags & CDISASM_PREFIX_EVEX) != 0u;
        const int is_privileged =
            first.name_id == CDISASM_X86_NAME_ENQCMDS;
        const cdisasm_x86_form_id expected_form =
            first.name_id == CDISASM_X86_NAME_ENQCMD
                ? (is_apx ? UINT16_C(1145) : UINT16_C(1144))
                : (is_apx ? UINT16_C(1143) : UINT16_C(1142));

        invariant(first.form_id == expected_form);
        invariant(first.operand_count == 2u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[0].size == 2u
            || first.opcode[0].size == 4u
            || first.opcode[0].size == 8u);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(first.opcode[0].flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(first.opcode[1].type == CDISASM_OPERAND_MEMORY);
        invariant(first.opcode[1].size == 64u);
        invariant(first.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(first.opcode[1].broadcast
            == CDISASM_X86_BROADCAST_NONE);
        invariant(((first.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u)
            == is_privileged);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS) == 0u);
        invariant((first.opcode_flags
            & (CDISASM_PREFIX_EFFECTIVE_MASK | CDISASM_PREFIX_REX2)) == 0u);
        if (is_apx) {
            invariant(mode == CDISASM_MODE_64);
            invariant(cpu_id == CDISASM_CPU_X86
                || cpu_id == CDISASM_CPU_APX
                || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_APX_F_ENQCMD));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F_ENQCMD));
            invariant((first.opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
        } else {
            invariant(cpu_id == CDISASM_CPU_X86
                || cpu_id == CDISASM_CPU_SAPPHIRE_RAPIDS
                || cpu_id == CDISASM_CPU_GRANITE_RAPIDS
                || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_SYSTEM) != 0u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_ENQCMD));
            invariant((first.opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
            invariant((first.opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX)) == 0u);
        }
    }
    if (first.name_id >= CDISASM_X86_NAME_AESDEC128KL
        && first.name_id <= CDISASM_X86_NAME_AESENCWIDE256KL
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_wide = first.name_id == CDISASM_X86_NAME_AESDECWIDE128KL
            || first.name_id == CDISASM_X86_NAME_AESDECWIDE256KL
            || first.name_id == CDISASM_X86_NAME_AESENCWIDE128KL
            || first.name_id == CDISASM_X86_NAME_AESENCWIDE256KL;
        const int is_256 = first.name_id == CDISASM_X86_NAME_AESDEC256KL
            || first.name_id == CDISASM_X86_NAME_AESDECWIDE256KL
            || first.name_id == CDISASM_X86_NAME_AESENC256KL
            || first.name_id == CDISASM_X86_NAME_AESENCWIDE256KL;
        const cdisasm_x86_form_id expected_form =
            first.name_id == CDISASM_X86_NAME_AESDEC128KL ? UINT16_C(157)
            : first.name_id == CDISASM_X86_NAME_AESDEC256KL ? UINT16_C(158)
            : first.name_id == CDISASM_X86_NAME_AESDECWIDE128KL
                ? UINT16_C(161)
            : first.name_id == CDISASM_X86_NAME_AESDECWIDE256KL
                ? UINT16_C(162)
            : first.name_id == CDISASM_X86_NAME_AESENC128KL ? UINT16_C(165)
            : first.name_id == CDISASM_X86_NAME_AESENC256KL ? UINT16_C(166)
            : first.name_id == CDISASM_X86_NAME_AESENCWIDE128KL
                ? UINT16_C(169)
                : UINT16_C(170);
        size_t memory_index = is_wide ? 0u : 1u;

        invariant(cpu_id == CDISASM_CPU_X86
            || cpu_id == CDISASM_CPU_TIGER_LAKE
            || cpu_id == CDISASM_CPU_ALDER_LAKE
            || cpu_id == CDISASM_CPU_AVX10
            || cpu_id == CDISASM_CPU_APX
            || cpu_id == CDISASM_CPU_ARROW_LAKE);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, is_wide
                ? CDISASM_X86_DECODE_BIT_KEYLOCKER_WIDE
                : CDISASM_X86_DECODE_BIT_KEYLOCKER));
        invariant(cdisasm_instruction_has_x86_group(
            &first, is_wide
                ? CDISASM_X86_GROUP_KEYLOCKER_WIDE
                : CDISASM_X86_GROUP_KEYLOCKER));
        invariant(first.form_id == expected_form);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
        invariant((first.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_PREFIX_EFFECTIVE_MASK)) == 0u);
        invariant(first.operand_count == (is_wide ? 1u : 2u));
        if (!is_wide) {
            invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[0].reg >= CDISASM_X86_REG_XMM0
                && first.opcode[0].reg <= CDISASM_X86_REG_XMM15);
            invariant(first.opcode[0].size == 16u);
            invariant(first.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
        }
        invariant(first.opcode[memory_index].type
            == CDISASM_OPERAND_MEMORY);
        invariant(first.opcode[memory_index].size
            == (is_256 ? 64u : 48u));
        invariant(first.opcode[memory_index].access
            == CDISASM_OPERAND_ACCESS_READ);
    }
    if ((first.name_id == CDISASM_X86_NAME_ENCODEKEY128
            || first.name_id == CDISASM_X86_NAME_ENCODEKEY256
            || first.name_id == CDISASM_X86_NAME_LOADIWKEY)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_loadiwkey =
            first.name_id == CDISASM_X86_NAME_LOADIWKEY;
        const cdisasm_x86_form_id expected_form =
            first.name_id == CDISASM_X86_NAME_ENCODEKEY128
                ? UINT16_C(1138)
            : first.name_id == CDISASM_X86_NAME_ENCODEKEY256
                ? UINT16_C(1139)
                : UINT16_C(1596);
        size_t operand_index;

        invariant(cpu_id == CDISASM_CPU_X86
            || cpu_id == CDISASM_CPU_TIGER_LAKE
            || cpu_id == CDISASM_CPU_ALDER_LAKE
            || cpu_id == CDISASM_CPU_AVX10
            || cpu_id == CDISASM_CPU_APX
            || cpu_id == CDISASM_CPU_ARROW_LAKE);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_KEYLOCKER));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_KEYLOCKER));
        invariant(!cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_KEYLOCKER_WIDE));
        invariant(first.form_id == expected_form);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
        invariant((first.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_PREFIX_EFFECTIVE_MASK)) == 0u);
        invariant((first.opcode_flags & CDISASM_PREFIX_REP) != 0u);
        invariant(first.operand_count == 2u);
        invariant(((first.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u)
            == is_loadiwkey);
        for (operand_index = 0u; operand_index < 2u; ++operand_index) {
            invariant(first.opcode[operand_index].type
                == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[operand_index].size
                == (is_loadiwkey ? 16u : 4u));
            if (is_loadiwkey) {
                invariant(first.opcode[operand_index].reg
                        >= CDISASM_X86_REG_XMM0
                    && first.opcode[operand_index].reg
                        <= CDISASM_X86_REG_XMM15);
                invariant(first.opcode[operand_index].access
                    == CDISASM_OPERAND_ACCESS_READ);
                if (mode != CDISASM_MODE_64) {
                    invariant(first.opcode[operand_index].reg
                        <= CDISASM_X86_REG_XMM7);
                }
            } else {
                invariant(first.opcode[operand_index].reg
                        >= CDISASM_X86_REG_EAX
                    && first.opcode[operand_index].reg
                        <= CDISASM_X86_REG_R15D);
                invariant(first.opcode[operand_index].access
                    == (operand_index == 0u
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ));
                if (mode != CDISASM_MODE_64) {
                    invariant(first.opcode[operand_index].reg
                        <= CDISASM_X86_REG_EDI);
                }
            }
        }
    }
    if (first.name_id == CDISASM_X86_NAME_HRESET
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        invariant(cpu_id == CDISASM_CPU_X86
            || cpu_id == CDISASM_CPU_ALDER_LAKE
            || cpu_id == CDISASM_CPU_AVX10
            || cpu_id == CDISASM_CPU_APX
            || cpu_id == CDISASM_CPU_GRANITE_RAPIDS
            || cpu_id == CDISASM_CPU_ARROW_LAKE
            || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_HRESET));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_HRESET));
        invariant(first.form_id == UINT16_C(1319));
        invariant((first.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
        invariant((first.opcode_flags & CDISASM_PREFIX_REP) != 0u);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_REX2
                | CDISASM_PREFIX_EFFECTIVE_MASK)) == 0u);
        invariant(first.operand_count == 1u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_IMMEDIATE);
        invariant(first.opcode[0].size == 1u);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(first.opcode[0].flags == CDISASM_OPERAND_FLAG_NONE);
        invariant(first.encoding.opcode_size == 3u);
        invariant(first.encoding.modrm == UINT8_C(0xc0));
        invariant(first.encoding.immediate_count == 1u);
        invariant(first.encoding.immediate_size[0] == 1u);
        invariant(first.encoding.immediate_offset[0] + 1u == first_size);
    }
    if (first.name_id == CDISASM_X86_NAME_CLDEMOTE
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        int is_rex2 = (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;

        invariant(cpu_id == CDISASM_CPU_X86
            || cpu_id == CDISASM_CPU_PENTIUM_SILVER_N6000
            || cpu_id == CDISASM_CPU_SAPPHIRE_RAPIDS
            || cpu_id == CDISASM_CPU_GRANITE_RAPIDS
            || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_CLDEMOTE));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_CLDEMOTE));
        invariant(!cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_P6));
        invariant(first.form_id == UINT16_C(710));
        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_REP | CDISASM_PREFIX_REPNE
                | CDISASM_PREFIX_OPERAND_SIZE
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK)) == 0u);
        invariant(first.operand_count == 1u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
        invariant(first.opcode[0].size == 1u);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        invariant((first.opcode[0].flags
            & CDISASM_OPERAND_FLAG_ADDRESS_ONLY) != 0u);
        invariant((first.encoding.modrm & UINT8_C(0xc0))
            != UINT8_C(0xc0));
        invariant((first.encoding.modrm & UINT8_C(0x38)) == 0u);
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x1c) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x1c));
        if (is_rex2) {
            invariant(cpu_id == CDISASM_CPU_X86
                || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        }
    }
    if (first.name_id == CDISASM_X86_NAME_CLZERO
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;

        invariant(cpu_id == CDISASM_CPU_X86
            || cpu_id == CDISASM_CPU_AMD_ZEN
            || cpu_id == CDISASM_CPU_AMD_ZEN_4);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_CLZERO));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_CLZERO));
        invariant(first.form_id == UINT16_C(719));
        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK)) == 0u);
        invariant(first.operand_count == 0u);
        invariant(first.encoding.modrm == UINT8_C(0xfc));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.displacement_size == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x01) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x01));
        if (is_rex2) {
            invariant(cpu_id == CDISASM_CPU_X86);
            invariant(mode == CDISASM_MODE_64);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        } else {
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
        }
    }
    if (first.name_id == CDISASM_X86_NAME_PCONFIG
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;

        invariant(cpu_id == CDISASM_CPU_X86
            || cpu_id == CDISASM_CPU_TIGER_LAKE
            || cpu_id == CDISASM_CPU_ALDER_LAKE
            || cpu_id == CDISASM_CPU_SAPPHIRE_RAPIDS
            || cpu_id == CDISASM_CPU_AVX10
            || cpu_id == CDISASM_CPU_APX
            || cpu_id == CDISASM_CPU_GRANITE_RAPIDS
            || cpu_id == CDISASM_CPU_ARROW_LAKE
            || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_PCONFIG));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_PCONFIG));
        invariant(first.form_id == (mode == CDISASM_MODE_64
            ? UINT16_C(2085) : UINT16_C(2084)));
        invariant((first.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS) == 0u);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_REP | CDISASM_PREFIX_REPNE
                | CDISASM_PREFIX_OPERAND_SIZE
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK)) == 0u);
        invariant(first.operand_count == 0u);
        invariant(first.encoding.modrm == UINT8_C(0xc5));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.displacement_size == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x01) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x01));
        if (is_rex2) {
            invariant(cpu_id == CDISASM_CPU_X86
                || cpu_id == CDISASM_CPU_APX
                || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
            invariant(mode == CDISASM_MODE_64);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        } else {
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F));
        }
    }
    if ((first.name_id == CDISASM_X86_NAME_CLAC
            || first.name_id == CDISASM_X86_NAME_STAC)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;

        invariant(cpu_id == CDISASM_CPU_X86
            || cpu_id == CDISASM_CPU_BROADWELL
            || cpu_id == CDISASM_CPU_SKYLAKE
            || cpu_id == CDISASM_CPU_GOLDMONT
            || cpu_id == CDISASM_CPU_AMD_ZEN
            || cpu_id == CDISASM_CPU_SKYLAKE_SP
            || cpu_id == CDISASM_CPU_ICE_LAKE
            || cpu_id == CDISASM_CPU_TIGER_LAKE
            || cpu_id == CDISASM_CPU_ALDER_LAKE
            || cpu_id == CDISASM_CPU_AMD_ZEN_4
            || cpu_id == CDISASM_CPU_SAPPHIRE_RAPIDS
            || cpu_id == CDISASM_CPU_AVX10
            || cpu_id == CDISASM_CPU_APX
            || cpu_id == CDISASM_CPU_CELERON_G3900
            || cpu_id == CDISASM_CPU_CELERON_N3350
            || cpu_id == CDISASM_CPU_CELERON_N4020
            || cpu_id == CDISASM_CPU_CELERON_G5900
            || cpu_id == CDISASM_CPU_PENTIUM_SILVER_N6000
            || cpu_id == CDISASM_CPU_GRANITE_RAPIDS
            || cpu_id == CDISASM_CPU_ARROW_LAKE
            || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_SMAP));
        invariant(cpu_has_decode_bit(
            cpu_id, mode, CDISASM_X86_DECODE_BIT_SMAP));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_SMAP));
        invariant(first.form_id == (first.name_id == CDISASM_X86_NAME_CLAC
            ? UINT16_C(707) : UINT16_C(3158)));
        invariant(first.encoding.modrm == (first.name_id
                == CDISASM_X86_NAME_CLAC
            ? UINT8_C(0xca) : UINT8_C(0xcb)));
        invariant(first.opcode_groups == CDISASM_GROUP_PRIVILEGED);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
        invariant((first.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                | CDISASM_PREFIX_LOCK | CDISASM_PREFIX_REP
                | CDISASM_PREFIX_REPNE | CDISASM_PREFIX_OPERAND_SIZE
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK)) == 0u);
        invariant(first.operand_count == 0u);
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.displacement_size == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x01) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x01));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
        if (is_rex2) {
            invariant(cpu_id == CDISASM_CPU_X86
                || cpu_id == CDISASM_CPU_APX
                || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
            invariant(mode == CDISASM_MODE_64);
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        }
    }
    if (first.name_id == CDISASM_X86_NAME_RDPRU
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;

        invariant(cpu_id == CDISASM_CPU_X86);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_RDPRU));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_RDPRU));
        invariant(first.form_id == UINT16_C(2578));
        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant((first.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK)) == 0u);
        invariant(first.operand_count == 0u);
        invariant(first.encoding.modrm == UINT8_C(0xfd));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.displacement_size == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x01) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x01));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
        if (is_rex2) {
#if USE_EXTRA_OPCODES
            invariant(mode == CDISASM_MODE_64);
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
#else
            invariant(0);
#endif
        }
    }
    if (first.name_id == CDISASM_X86_NAME_PTWRITE
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;
        const int is_register = first.form_id == UINT16_C(2438);

        invariant(cpu_id == CDISASM_CPU_X86
            || cpu_id == CDISASM_CPU_ALDER_LAKE
            || cpu_id == CDISASM_CPU_SAPPHIRE_RAPIDS
            || cpu_id == CDISASM_CPU_AVX10
            || cpu_id == CDISASM_CPU_APX
            || cpu_id == CDISASM_CPU_CELERON_N4020
            || cpu_id == CDISASM_CPU_PENTIUM_SILVER_N6000
            || cpu_id == CDISASM_CPU_GRANITE_RAPIDS
            || cpu_id == CDISASM_CPU_ARROW_LAKE
            || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_PTWRITE));
        invariant(cpu_has_decode_bit(
            cpu_id, mode, CDISASM_X86_DECODE_BIT_PTWRITE));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_PTWRITE));
        invariant(first.form_id == (is_register
            ? UINT16_C(2438) : UINT16_C(2439)));
        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant((first.opcode_flags & CDISASM_PREFIX_REP) != 0u);
        invariant((first.opcode_flags
            & (CDISASM_PREFIX_LOCK | CDISASM_PREFIX_OPERAND_SIZE
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK
                | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
        invariant(first.operand_count == 1u);
        invariant(first.opcode[0].type == (is_register
            ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
        invariant(first.opcode[0].size
            == (((first.opcode_flags & CDISASM_PREFIX_REX_W) != 0u)
                ? 8u : 4u));
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        invariant((first.encoding.modrm & UINT8_C(0x38))
            == UINT8_C(0x20));
        invariant(is_register
            == ((first.encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0xae) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0xae));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
        if (is_rex2) {
            invariant(mode == CDISASM_MODE_64);
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        }
    }
    if (first.name_id == CDISASM_X86_NAME_MOVNTI
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;
        const unsigned int bytes = first.opcode[0].size;

        invariant(cpu_id == CDISASM_CPU_X86
            || (cpu_id >= CDISASM_CPU_PENTIUM_4
                && cpu_id <= CDISASM_CPU_PENTIUM_SILVER_N6000)
            || (cpu_id >= CDISASM_CPU_GRANITE_RAPIDS
                && cpu_id <= CDISASM_CPU_KNIGHTS_MILL));
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_SSE2));
        invariant(cpu_has_decode_bit(
            cpu_id, mode, CDISASM_X86_DECODE_BIT_SSE2));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_SSE2));
        invariant(bytes == 4u || bytes == 8u);
        invariant(first.form_id == (bytes == 8u
            ? UINT16_C(1693) : UINT16_C(1692)));
        invariant((bytes == 8u)
            == ((first.opcode_flags & CDISASM_PREFIX_REX_W) != 0u));
        invariant(bytes != 8u || mode == CDISASM_MODE_64);
        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant((first.opcode_flags
            & (CDISASM_PREFIX_LOCK | CDISASM_PREFIX_REP
                | CDISASM_PREFIX_REPNE | CDISASM_PREFIX_OPERAND_SIZE
                | CDISASM_PREFIX_EFFECTIVE_MASK | CDISASM_PREFIX_HLE_MASK
                | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
        invariant(first.operand_count == 2u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
        invariant(first.opcode[0].size == bytes);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        invariant(first.opcode[0].broadcast
            == CDISASM_X86_BROADCAST_NONE);
        invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[1].size == bytes);
        invariant(first.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(first.opcode[1].broadcast
            == CDISASM_X86_BROADCAST_NONE);
        invariant((first.encoding.modrm & UINT8_C(0xc0))
            != UINT8_C(0xc0));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0xc3) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0xc3));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
        if (is_rex2) {
            invariant(mode == CDISASM_MODE_64);
            invariant((decode_flag_word0(decode_flags)
                & (CDISASM_X86_DECODE_FLAG_SSE2
                    | CDISASM_X86_DECODE_FLAG_APX))
                == (CDISASM_X86_DECODE_FLAG_SSE2
                    | CDISASM_X86_DECODE_FLAG_APX));
        }
    }
    if ((first.name_id == CDISASM_X86_NAME_MOVNTDQ
            || first.name_id == CDISASM_X86_NAME_MOVNTPD
            || first.name_id == CDISASM_X86_NAME_MOVNTPS
            || first.name_id == CDISASM_X86_NAME_MOVNTQ
            || first.name_id == CDISASM_X86_NAME_MOVNTSD
            || first.name_id == CDISASM_X86_NAME_MOVNTSS
            || first.name_id == CDISASM_X86_NAME_VMOVNTDQ
            || first.name_id == CDISASM_X86_NAME_VMOVNTPD
            || first.name_id == CDISASM_X86_NAME_VMOVNTPS)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_scalar = first.name_id == CDISASM_X86_NAME_MOVNTSD
            || first.name_id == CDISASM_X86_NAME_MOVNTSS;
        const int is_mmx = first.name_id == CDISASM_X86_NAME_MOVNTQ;
        const int is_evex =
            (first.opcode_flags & CDISASM_PREFIX_EVEX) != 0u;
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;
        const unsigned int memory_bytes = first.opcode[0].size;

        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant((first.opcode_flags
            & (CDISASM_PREFIX_LOCK | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK
                | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
        invariant(first.operand_count == 2u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        invariant(first.opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
        invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(first.opcode[1].size
            == (is_scalar ? 16u : memory_bytes));
        invariant(first.opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
        invariant((first.encoding.modrm & UINT8_C(0xc0))
            != UINT8_C(0xc0));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.mask_reg == CDISASM_X86_REG_NONE);
        invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
        invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
        invariant(first.sae == CDISASM_X86_SAE_NONE);
        invariant(!is_mmx
            || (first.form_id == UINT16_C(1696) && memory_bytes == 8u));
        invariant(first.name_id != CDISASM_X86_NAME_MOVNTSD
            || (first.form_id == UINT16_C(1697) && memory_bytes == 8u));
        invariant(first.name_id != CDISASM_X86_NAME_MOVNTSS
            || (first.form_id == UINT16_C(1698) && memory_bytes == 4u));
        invariant(!is_evex
            || (memory_bytes == 16u || memory_bytes == 32u
                || memory_bytes == 64u));
        invariant(!is_rex2 || mode == CDISASM_MODE_64);
        invariant(!is_rex2 || cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F));
    }
    if ((first.name_id == CDISASM_X86_NAME_MOVNTDQA
            || first.name_id == CDISASM_X86_NAME_VMOVNTDQA)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_vex =
            (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        const int is_evex =
            (first.opcode_flags & CDISASM_PREFIX_EVEX) != 0u;
        const unsigned int vector_bytes = first.opcode[0].size;

        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant((first.opcode_flags
            & (CDISASM_PREFIX_LOCK | CDISASM_PREFIX_REP
                | CDISASM_PREFIX_REPNE | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK
                | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
        invariant(first.operand_count == 2u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        invariant(first.opcode[1].type == CDISASM_OPERAND_MEMORY);
        invariant(first.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(first.opcode[1].size == vector_bytes);
        invariant(first.opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
        invariant((first.encoding.modrm & UINT8_C(0xc0))
            != UINT8_C(0xc0));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.mask_reg == CDISASM_X86_REG_NONE);
        invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
        invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
        invariant(first.sae == CDISASM_X86_SAE_NONE);
        if (first.name_id == CDISASM_X86_NAME_MOVNTDQA) {
            invariant(!is_vex && !is_evex);
            invariant(first.form_id == UINT16_C(1690));
            invariant(vector_bytes == 16u);
            invariant(first.encoding.opcode_size == 3u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_SSE4));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_SSE4_ISA_SET));
        } else if (is_vex) {
            invariant(first.form_id == (vector_bytes == 16u
                ? UINT16_C(5864) : UINT16_C(5866)));
            invariant(vector_bytes == 16u || vector_bytes == 32u);
            invariant(first.encoding.opcode_size == 1u);
            invariant((decode_flag_word0(decode_flags)
                & (vector_bytes == 16u ? CDISASM_X86_DECODE_FLAG_AVX
                                       : CDISASM_X86_DECODE_FLAG_AVX2))
                != 0u);
        } else {
            size_t evex_offset =
                (size_t)first.encoding.opcode_offset - 4u;
            const int uses_apx_address =
                (code[evex_offset + 1u] & UINT8_C(0x08)) != 0u
                || (code[evex_offset + 2u] & UINT8_C(0x04)) == 0u;
            cdisasm_x86_decode_bit_id width_bit = vector_bytes == 16u
                ? CDISASM_X86_DECODE_BIT_AVX512F_128
                : vector_bytes == 32u
                    ? CDISASM_X86_DECODE_BIT_AVX512F_256
                    : CDISASM_X86_DECODE_BIT_AVX512F_512;
            cdisasm_x86_group_id width_group = vector_bytes == 16u
                ? CDISASM_X86_GROUP_AVX512F_128
                : vector_bytes == 32u
                    ? CDISASM_X86_GROUP_AVX512F_256
                    : CDISASM_X86_GROUP_AVX512F_512;

            invariant(is_evex);
            invariant(vector_bytes == 16u || vector_bytes == 32u
                || vector_bytes == 64u);
            invariant(first.form_id == (vector_bytes == 16u
                ? UINT16_C(5865)
                : vector_bytes == 32u ? UINT16_C(5867)
                                      : UINT16_C(5868)));
            invariant(first.encoding.opcode_size == 1u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, width_group));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, width_bit));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F) == uses_apx_address);
            invariant(!uses_apx_address
                || (decode_flag_word0(decode_flags)
                    & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        }
    }
    if ((first.name_id == CDISASM_X86_NAME_LDDQU
            || first.name_id == CDISASM_X86_NAME_VLDDQU)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_vex =
            (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;
        const unsigned int vector_bytes = first.opcode[0].size;

        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant((first.opcode_flags
            & (CDISASM_PREFIX_LOCK | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK
                | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
        invariant(first.operand_count == 2u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        invariant(first.opcode[1].type == CDISASM_OPERAND_MEMORY);
        invariant(first.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(first.opcode[1].size == vector_bytes);
        invariant(first.opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
        invariant((first.encoding.modrm & UINT8_C(0xc0))
            != UINT8_C(0xc0));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.mask_reg == CDISASM_X86_REG_NONE);
        invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
        invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
        invariant(first.sae == CDISASM_X86_SAE_NONE);
        if (first.name_id == CDISASM_X86_NAME_LDDQU) {
            invariant(!is_vex);
            invariant(first.form_id == UINT16_C(1574));
            invariant(vector_bytes == 16u);
            invariant((first.opcode_flags & CDISASM_PREFIX_REPNE) != 0u);
            invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_SSE3));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_SSE3));
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
            invariant(!is_rex2 || mode == CDISASM_MODE_64);
            invariant(!is_rex2 || (decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        } else {
            invariant(is_vex && !is_rex2);
            invariant(vector_bytes == 16u || vector_bytes == 32u);
            invariant(first.form_id == (vector_bytes == 16u
                ? UINT16_C(5583) : UINT16_C(5584)));
            invariant(first.encoding.opcode_size == 1u);
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX2));
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_AVX) != 0u);
        }
    }
    if (first.name_id == CDISASM_X86_NAME_PBNDKB
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;

        invariant(cpu_id == CDISASM_CPU_X86);
        invariant(mode == CDISASM_MODE_64);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_PBNDKB));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_PBNDKB));
        invariant(first.form_id == UINT16_C(2039));
        invariant((first.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS) == 0u);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_REP | CDISASM_PREFIX_REPNE
                | CDISASM_PREFIX_OPERAND_SIZE
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK)) == 0u);
        invariant(first.operand_count == 0u);
        invariant(first.encoding.modrm == UINT8_C(0xc7));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.displacement_size == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x01) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x01));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
        if (is_rex2) {
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        }
    }
    if ((first.name_id == CDISASM_X86_NAME_PREFETCHIT0
            || first.name_id == CDISASM_X86_NAME_PREFETCHIT1)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;

        invariant(cpu_id == CDISASM_CPU_X86
            || cpu_id == CDISASM_CPU_GRANITE_RAPIDS
            || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
        invariant(mode == CDISASM_MODE_64);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_ICACHE_PREFETCH));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_ICACHE_PREFETCH));
        invariant(first.form_id == (first.name_id
                == CDISASM_X86_NAME_PREFETCHIT0
            ? UINT16_C(2308) : UINT16_C(2309)));
        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_ADDRESS_SIZE
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK
                | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
        invariant(first.operand_count == 1u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
        invariant(first.opcode[0].size == 1u);
        invariant(first.opcode[0].base_reg == CDISASM_X86_REG_RIP);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        invariant((first.opcode[0].flags
            & (CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                | CDISASM_OPERAND_FLAG_PC_RELATIVE))
            == (CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                | CDISASM_OPERAND_FLAG_PC_RELATIVE));
        invariant(first.encoding.modrm == (first.name_id
                == CDISASM_X86_NAME_PREFETCHIT0
            ? UINT8_C(0x3d) : UINT8_C(0x35)));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.displacement_size == 4u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x18) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x18));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
        if (is_rex2) {
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        }
    }
    if (first.name_id == CDISASM_X86_NAME_PREFETCHRST2
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;

        invariant(cpu_id == CDISASM_CPU_X86
            || cpu_id == CDISASM_CPU_DIAMOND_RAPIDS);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_MOVRS));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_MOVRS));
        invariant(first.form_id == UINT16_C(2311));
        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK
                | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
        invariant(first.operand_count == 1u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
        invariant(first.opcode[0].size == 1u);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        invariant((first.opcode[0].flags
            & CDISASM_OPERAND_FLAG_ADDRESS_ONLY) != 0u);
        invariant((first.encoding.modrm & UINT8_C(0xc0))
            != UINT8_C(0xc0));
        invariant((first.encoding.modrm & UINT8_C(0x38))
            == UINT8_C(0x20));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x18) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x18));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
        if (is_rex2) {
            invariant(mode == CDISASM_MODE_64);
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        }
    }
    if (first.name_id == CDISASM_X86_NAME_PREFETCHWT1
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;

        invariant(cpu_id == CDISASM_CPU_X86
            || cpu_id == CDISASM_CPU_KNIGHTS_MILL);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_PREFETCHWT1));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_PREFETCHWT1));
        invariant(first.form_id == UINT16_C(2315));
        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK
                | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
        invariant(first.operand_count == 1u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_MEMORY);
        invariant(first.opcode[0].size == 1u);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        invariant((first.opcode[0].flags
            & CDISASM_OPERAND_FLAG_ADDRESS_ONLY) != 0u);
        invariant((first.encoding.modrm & UINT8_C(0xc0))
            != UINT8_C(0xc0));
        invariant((first.encoding.modrm & UINT8_C(0x38))
            == UINT8_C(0x10));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x0d) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x0d));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
        if (is_rex2) {
            invariant(cpu_id == CDISASM_CPU_X86);
            invariant(mode == CDISASM_MODE_64);
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        }
    }
    if ((first.name_id == CDISASM_X86_NAME_MCOMMIT
            || first.name_id == CDISASM_X86_NAME_MONITORX
            || first.name_id == CDISASM_X86_NAME_MWAITX)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_mcommit =
            first.name_id == CDISASM_X86_NAME_MCOMMIT;
        const int is_mwaitx = first.name_id == CDISASM_X86_NAME_MWAITX;
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;
        const cdisasm_x86_decode_bit_id family_bit = is_mcommit
            ? CDISASM_X86_DECODE_BIT_MCOMMIT
            : CDISASM_X86_DECODE_BIT_MONITORX;
        const cdisasm_x86_group_id family_group = is_mcommit
            ? CDISASM_X86_GROUP_MCOMMIT
            : CDISASM_X86_GROUP_MONITORX;
        const cdisasm_x86_form_id family_form = is_mcommit
            ? UINT16_C(1629)
            : (is_mwaitx ? UINT16_C(1822) : UINT16_C(1640));

        invariant(cpu_id == CDISASM_CPU_X86);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, family_bit));
        invariant(cdisasm_instruction_has_x86_group(
            &first, family_group));
        invariant(!cdisasm_instruction_has_x86_group(
            &first, is_mcommit
                ? CDISASM_X86_GROUP_MONITORX
                : CDISASM_X86_GROUP_MCOMMIT));
        invariant(first.form_id == family_form);
        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant(((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u)
            == is_mcommit);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS) == 0u);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK)) == 0u);
        invariant(((first.opcode_flags & CDISASM_PREFIX_REP) != 0u)
            == is_mcommit);
        if (!is_mcommit) {
            invariant((first.opcode_flags & (CDISASM_PREFIX_REPNE
                    | CDISASM_PREFIX_OPERAND_SIZE)) == 0u);
        }
        invariant(first.operand_count == 0u);
        invariant(first.encoding.modrm
            == (is_mwaitx ? UINT8_C(0xfb) : UINT8_C(0xfa)));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.displacement_size == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x01) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x01));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
        if (is_rex2) {
            invariant(mode == CDISASM_MODE_64);
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        }
    }
    if ((first.name_id == CDISASM_X86_NAME_INVLPGB
            || first.name_id == CDISASM_X86_NAME_TLBSYNC)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_invlpgb =
            first.name_id == CDISASM_X86_NAME_INVLPGB;
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;

        invariant(cpu_id == CDISASM_CPU_X86);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_AMD_INVLPGB));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_AMD_INVLPGB));
        invariant(!cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_SNP));
        invariant(first.form_id == (is_invlpgb
            ? UINT16_C(1410) : UINT16_C(3309)));
        invariant(first.opcode_groups == CDISASM_GROUP_PRIVILEGED);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_REP | CDISASM_PREFIX_REPNE
                | CDISASM_PREFIX_OPERAND_SIZE
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK
                | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
        invariant(first.operand_count == 0u);
        invariant(first.encoding.modrm
            == (is_invlpgb ? UINT8_C(0xfe) : UINT8_C(0xff)));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.displacement_size == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x01) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x01));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
        if (is_invlpgb && mode == CDISASM_MODE_16) {
            invariant((first.opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE)
                != 0u);
        }
        if (is_invlpgb && mode == CDISASM_MODE_32) {
            invariant((first.opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE)
                == 0u);
        }
        if (is_rex2) {
            invariant(mode == CDISASM_MODE_64);
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        }
    }
    if ((first.name_id == CDISASM_X86_NAME_PSMASH
            || first.name_id == CDISASM_X86_NAME_PVALIDATE
            || first.name_id == CDISASM_X86_NAME_RMPADJUST
            || first.name_id == CDISASM_X86_NAME_RMPUPDATE)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_pvalidate =
            first.name_id == CDISASM_X86_NAME_PVALIDATE;
        const int is_rmpadjust =
            first.name_id == CDISASM_X86_NAME_RMPADJUST;
        const int is_rmpupdate =
            first.name_id == CDISASM_X86_NAME_RMPUPDATE;
        const int uses_f2 = is_pvalidate || is_rmpupdate;
        const int uses_fe = is_rmpadjust || is_rmpupdate;
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;
        const unsigned int operand_count =
            is_pvalidate || is_rmpadjust ? 3u : (is_rmpupdate ? 2u : 1u);
        const cdisasm_x86_form_id form_id = is_pvalidate
            ? UINT16_C(2487)
            : (is_rmpadjust ? UINT16_C(2632)
                : (is_rmpupdate ? UINT16_C(2633) : UINT16_C(2370)));
        unsigned int operand_index;

        invariant(cpu_id == CDISASM_CPU_X86);
        invariant(is_pvalidate || mode == CDISASM_MODE_64);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_SNP));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_SNP));
        invariant(!cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_AMD_INVLPGB));
        invariant(first.form_id == form_id);
        invariant(first.opcode_groups == CDISASM_GROUP_PRIVILEGED);
        invariant((first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
        invariant((first.opcode_flags & (CDISASM_PREFIX_LOCK
                | CDISASM_PREFIX_EFFECTIVE_MASK
                | CDISASM_PREFIX_HLE_MASK
                | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS)) == 0u);
        invariant((first.opcode_flags & (uses_f2
                ? CDISASM_PREFIX_REPNE : CDISASM_PREFIX_REP)) != 0u);
        invariant(first.operand_count == operand_count);
        for (operand_index = 0u; operand_index < operand_count;
             ++operand_index) {
            const cdisasm_x86_reg_id expected_register = operand_index == 0u
                ? CDISASM_X86_REG_RAX
                : (operand_index == 1u
                    ? (is_pvalidate
                        ? CDISASM_X86_REG_ECX : CDISASM_X86_REG_RCX)
                    : (is_pvalidate
                        ? CDISASM_X86_REG_EDX : CDISASM_X86_REG_RDX));

            invariant(first.opcode[operand_index].type
                == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[operand_index].reg == expected_register);
            invariant(first.opcode[operand_index].size
                == (is_pvalidate && operand_index != 0u ? 4u : 8u));
            invariant(first.opcode[operand_index].access
                == (operand_index == 0u
                    ? CDISASM_OPERAND_ACCESS_READ_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
            invariant(first.opcode[operand_index].flags
                == CDISASM_OPERAND_FLAG_IMPLICIT);
        }
        invariant(first.encoding.modrm
            == (uses_fe ? UINT8_C(0xfe) : UINT8_C(0xff)));
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.displacement_size == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x01) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x01));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
        if (is_rex2) {
            invariant(mode == CDISASM_MODE_64);
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        }
    }
    if ((first.name_id == CDISASM_X86_NAME_GF2P8AFFINEINVQB
            || first.name_id == CDISASM_X86_NAME_GF2P8AFFINEQB
            || first.name_id == CDISASM_X86_NAME_GF2P8MULB
            || first.name_id == CDISASM_X86_NAME_VGF2P8AFFINEINVQB
            || first.name_id == CDISASM_X86_NAME_VGF2P8AFFINEQB
            || first.name_id == CDISASM_X86_NAME_VGF2P8MULB)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int legacy =
            first.name_id == CDISASM_X86_NAME_GF2P8AFFINEINVQB
            || first.name_id == CDISASM_X86_NAME_GF2P8AFFINEQB
            || first.name_id == CDISASM_X86_NAME_GF2P8MULB;
        const int vex = (first.opcode_flags & CDISASM_PREFIX_VEX) != 0u;
        const int evex = (first.opcode_flags & CDISASM_PREFIX_EVEX) != 0u;
        const int affine =
            first.name_id == CDISASM_X86_NAME_GF2P8AFFINEINVQB
            || first.name_id == CDISASM_X86_NAME_GF2P8AFFINEQB
            || first.name_id == CDISASM_X86_NAME_VGF2P8AFFINEINVQB
            || first.name_id == CDISASM_X86_NAME_VGF2P8AFFINEQB;
        const unsigned int family_base = legacy
            ? (first.name_id == CDISASM_X86_NAME_GF2P8AFFINEINVQB
                ? 1308u
                : first.name_id == CDISASM_X86_NAME_GF2P8AFFINEQB
                    ? 1310u : 1312u)
            : (first.name_id == CDISASM_X86_NAME_VGF2P8AFFINEINVQB
                ? 5505u
                : first.name_id == CDISASM_X86_NAME_VGF2P8AFFINEQB
                    ? 5515u : 5525u);
        const unsigned int relative =
            (unsigned int)first.form_id - family_base;
        const unsigned int vector_size = legacy ? 16u
            : relative <= 3u ? 16u : relative <= 7u ? 32u : 64u;
        const int memory_form = (relative & 1u) == 0u;
        const unsigned int source_count = legacy ? 1u : 2u;
        const unsigned int rm_index = source_count;
        const cdisasm_x86_reg_id register_base = vector_size == 16u
            ? CDISASM_X86_REG_XMM0
            : vector_size == 32u ? CDISASM_X86_REG_YMM0
                                 : CDISASM_X86_REG_ZMM0;
        const int avx512 = cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_AVX512F);
        const int avx10 = cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_AVX10_1);
        const int uses_apx = cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F);
        unsigned int operand_index;

        invariant(relative < (legacy ? 2u : 10u));
        invariant((legacy != 0) + (vex != 0) + (evex != 0) == 1);
        invariant(legacy || (vex
            == (relative == 2u || relative == 3u
                || relative == 6u || relative == 7u)));
        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant(first.branch_target == 0u);
        invariant(first.rounding == CDISASM_X86_ROUNDING_NONE);
        invariant(first.sae == CDISASM_X86_SAE_NONE);
        invariant(first.encoding.opcode_size == (legacy ? 3u : 1u));
        invariant(first.encoding.modrm_offset
            == first.encoding.opcode_offset + first.encoding.opcode_size);
        invariant(first.encoding.selector_offset == 0u);
        invariant(first.encoding.immediate_count == (affine ? 1u : 0u));
        invariant(first.operand_count
            == 1u + source_count + (affine ? 1u : 0u));
        invariant(((first.encoding.modrm & UINT8_C(0xc0))
                != UINT8_C(0xc0)) == memory_form);
        invariant((decode_flag_word0(decode_flags)
            & CDISASM_X86_DECODE_FLAG_GFNI) != 0u);
        invariant(cdisasm_decode_flags_test_bit(
            decode_flags, CDISASM_X86_DECODE_BIT_GFNI));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_GFNI));
        invariant(!cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_AVX2));

        if (legacy) {
            const size_t opcode_offset = first.encoding.opcode_offset;

            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_I386));
            invariant(code[opcode_offset] == UINT8_C(0x0f));
            invariant(code[opcode_offset + 1u]
                == (affine ? UINT8_C(0x3a) : UINT8_C(0x38)));
            invariant(code[opcode_offset + 2u]
                == (first.name_id == CDISASM_X86_NAME_GF2P8AFFINEQB
                    ? UINT8_C(0xce) : UINT8_C(0xcf)));
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(!cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
        } else {
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX));
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_AVX) != 0u);
            invariant(code[first.encoding.opcode_offset]
                == (first.name_id == CDISASM_X86_NAME_VGF2P8AFFINEQB
                    ? UINT8_C(0xce) : UINT8_C(0xcf)));
        }
        if (vex) {
            invariant(cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_AVX_GFNI));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, CDISASM_X86_DECODE_BIT_AVX_GFNI));
            invariant(first.mask_reg == CDISASM_X86_REG_NONE);
            invariant(first.mask_mode == CDISASM_X86_MASK_NONE);
            invariant(!avx512 && !avx10 && !uses_apx);
        }
        if (evex) {
            const cdisasm_x86_group_id width_group = vector_size == 16u
                ? CDISASM_X86_GROUP_AVX512_GFNI_128
                : vector_size == 32u ? CDISASM_X86_GROUP_AVX512_GFNI_256
                                     : CDISASM_X86_GROUP_AVX512_GFNI_512;
            const cdisasm_x86_decode_bit_id width_bit = vector_size == 16u
                ? CDISASM_X86_DECODE_BIT_AVX512_GFNI_128
                : vector_size == 32u
                    ? CDISASM_X86_DECODE_BIT_AVX512_GFNI_256
                    : CDISASM_X86_DECODE_BIT_AVX512_GFNI_512;

            invariant(avx512 != avx10);
            invariant(cdisasm_instruction_has_x86_group(
                &first, width_group));
            invariant(cdisasm_decode_flags_test_bit(
                decode_flags, width_bit));
            invariant((decode_flag_word0(decode_flags)
                & (avx10 ? CDISASM_X86_DECODE_FLAG_AVX10
                         : CDISASM_X86_DECODE_FLAG_AVX512)) != 0u);
            invariant(!avx512 || vector_size == 64u
                || cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AVX512VL));
            invariant(!uses_apx || mode == CDISASM_MODE_64);
            invariant(!uses_apx || memory_form);
            invariant(!uses_apx || (decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
        }

        invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[0].reg >= register_base);
        invariant(first.opcode[0].reg <= register_base
            + (evex ? 31u : 15u));
        invariant(first.opcode[0].size == vector_size);
        invariant(first.opcode[0].access == (legacy
                || (evex && first.mask_mode == CDISASM_X86_MASK_MERGE)
            ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_WRITE));
        invariant(first.opcode[0].flags == 0u);
        invariant(first.opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);
        for (operand_index = 1u; operand_index < source_count;
             ++operand_index) {
            invariant(first.opcode[operand_index].type
                == CDISASM_OPERAND_REGISTER);
            invariant(first.opcode[operand_index].reg >= register_base);
            invariant(first.opcode[operand_index].reg
                <= register_base + (evex ? 31u : 15u));
            invariant(first.opcode[operand_index].size == vector_size);
            invariant(first.opcode[operand_index].access
                == CDISASM_OPERAND_ACCESS_READ);
            invariant(first.opcode[operand_index].flags == 0u);
            invariant(first.opcode[operand_index].broadcast
                == CDISASM_X86_BROADCAST_NONE);
        }
        invariant(first.opcode[rm_index].type == (memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        invariant(first.opcode[rm_index].access
            == CDISASM_OPERAND_ACCESS_READ);
        if (memory_form) {
            invariant((first.opcode[rm_index].size == vector_size
                    && first.opcode[rm_index].broadcast
                        == CDISASM_X86_BROADCAST_NONE)
                || (evex && affine
                    && first.opcode[rm_index].size == 8u
                    && first.opcode[rm_index].broadcast
                        == (cdisasm_x86_broadcast)(vector_size / 8u)));
            invariant((first.opcode[rm_index].flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                    | CDISASM_OPERAND_FLAG_SIGNED)) == 0u);
        } else {
            invariant(first.opcode[rm_index].reg >= register_base);
            invariant(first.opcode[rm_index].reg
                <= register_base + (evex ? 31u : 15u));
            invariant(first.opcode[rm_index].size == vector_size);
            invariant(first.opcode[rm_index].flags == 0u);
            invariant(first.opcode[rm_index].broadcast
                == CDISASM_X86_BROADCAST_NONE);
        }
        if (affine) {
            const cdisasm_opcode *immediate =
                &first.opcode[1u + source_count];

            invariant(first.encoding.immediate_size[0] == 1u);
            invariant(first.encoding.immediate_offset[0]
                == first_size - 1u);
            invariant(immediate->type == CDISASM_OPERAND_IMMEDIATE);
            invariant(immediate->size == 1u);
            invariant(immediate->access == CDISASM_OPERAND_ACCESS_READ);
            invariant(immediate->flags == 0u);
            invariant(immediate->broadcast == CDISASM_X86_BROADCAST_NONE);
        }
    }
#endif
    if (first.name_id == CDISASM_X86_NAME_NOP
        && first.form_id == UINT16_C(1851)
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;

        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_P6));
        invariant(!cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_PREFETCHWT1));
        invariant(first.operand_count == 2u);
        invariant(first.opcode[0].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(first.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        invariant((first.encoding.modrm & UINT8_C(0xf8))
            == UINT8_C(0xd0));
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x0d) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x0d));
        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_APX_F) == is_rex2);
        if (is_rex2) {
#if USE_EXTRA_OPCODES
            invariant(mode == CDISASM_MODE_64);
            invariant((decode_flag_word0(decode_flags)
                & CDISASM_X86_DECODE_FLAG_APX) != 0u);
#else
            invariant(0);
#endif
        }
    }
    if (first.name_id == CDISASM_X86_NAME_NOP
        && (first.form_id == UINT16_C(1855)
            || first.form_id == UINT16_C(1866))
        && (first.opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        const int is_register = first.form_id == UINT16_C(1855);
        const int is_rex2 =
            (first.opcode_flags & CDISASM_PREFIX_REX2) != 0u;

        invariant(cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_P6));
        invariant(!cdisasm_instruction_has_x86_group(
            &first, CDISASM_X86_GROUP_CLDEMOTE));
        invariant(first.opcode_groups == CDISASM_GROUP_NONE);
        invariant(first.operand_count == 2u);
        invariant(first.opcode[0].type == (is_register
            ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
        invariant(first.opcode[1].type == CDISASM_OPERAND_REGISTER);
        invariant(first.opcode[0].size == first.opcode[1].size);
        invariant(first.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(first.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        invariant(is_register
            == ((first.encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)));
        invariant(is_register
            || (first.opcode[0].flags
                & CDISASM_OPERAND_FLAG_ADDRESS_ONLY) == 0u);
        invariant(first.encoding.immediate_count == 0u);
        invariant(first.encoding.opcode_size == (is_rex2 ? 1u : 2u));
        invariant(code[first.encoding.opcode_offset] == (is_rex2
            ? UINT8_C(0x1c) : UINT8_C(0x0f)));
        invariant(is_rex2
            || code[first.encoding.opcode_offset + 1u] == UINT8_C(0x1c));
    }
    check_groups(&first);
#if USE_DISASM_FORMAT
    check_format(&first, hash);
#endif
}

static void check_invalid_decode_flags(
    const uint8_t *code,
    size_t code_size,
    const cdisasm_x86_decode_flags *decode_flags)
{
    cdisasm_instruction instruction;
    uint32_t decoded_size;

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        code,
        code_size,
        UINT64_C(0),
        decode_flags,
        &instruction);
    invariant(decoded_size == 0);
    invariant(instruction.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
    invariant(failure_result_is_zeroed(&instruction));
}

static void check_reserved_decode_flag_bitmaps(
    const uint8_t *code,
    size_t code_size,
    const cdisasm_x86_decode_flags *fuzz_flags)
{
    static const uint64_t known_masks[CDISASM_DECODE_FLAGS_BITMAP_COUNT] = {
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_0,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_1,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_2,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_3,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_4,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_5,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_6,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_7
    };
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    size_t bitmap_index;

    flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        fuzz_flags->bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
            & CDISASM_X86_DECODE_FLAG_KNOWN_MASK_0;
    for (bitmap_index = 1u;
         bitmap_index < CDISASM_DECODE_FLAGS_BITMAP_COUNT;
         ++bitmap_index) {
        uint64_t unknown_mask = ~known_masks[bitmap_index];
        uint64_t value;

        if (unknown_mask == 0u) {
            continue;
        }
        value = fuzz_flags->bitmap[bitmap_index] & unknown_mask;
        if (value == 0u) {
            value = unknown_mask & (UINT64_C(0) - unknown_mask);
        }
        flags.bitmap[bitmap_index] = value;
        check_invalid_decode_flags(code, code_size, &flags);
        flags.bitmap[bitmap_index] = UINT64_C(0);
    }
}

static cdisasm_mode eligible_mode(cdisasm_cpu_id cpu_id, uint64_t selector)
{
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const cdisasm_x86_mode_mask mode_bits[] = {
        CDISASM_X86_MODE_MASK_16,
        CDISASM_X86_MODE_MASK_32,
        CDISASM_X86_MODE_MASK_64
    };
    cdisasm_x86_mode_mask available_mask;
    size_t available_count = 0;
    size_t index;

    available_mask = cdisasm_x86_cpu_mode_mask(cpu_id);
    for (index = 0; index < sizeof(mode_bits) / sizeof(mode_bits[0]); ++index) {
        if ((available_mask & mode_bits[index]) != 0) {
            ++available_count;
        }
    }
    invariant(available_count != 0);
    selector %= available_count;
    for (index = 0; index < sizeof(mode_bits) / sizeof(mode_bits[0]); ++index) {
        if ((available_mask & mode_bits[index]) != 0) {
            if (selector == 0) {
                return modes[index];
            }
            --selector;
        }
    }

    invariant(0);
    return CDISASM_MODE_16;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint8_t hex_bytes[FUZZ_HEX_CAPACITY];
    const uint8_t *code;
    size_t code_size;
    size_t index;
    uint64_t hash;
    uint64_t address;
    cdisasm_cpu_id cpu_id;
    cdisasm_x86_decode_flags fuzz_flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags all_flags =
        CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;
    cdisasm_x86_decode_flags selected_family_flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    static const cdisasm_x86_decode_option family_flags[] = {
        CDISASM_X86_DECODE_FLAG_FPU,
        CDISASM_X86_DECODE_FLAG_MMX,
        CDISASM_X86_DECODE_FLAG_3DNOW,
        CDISASM_X86_DECODE_FLAG_SSE,
        CDISASM_X86_DECODE_FLAG_SSE2,
        CDISASM_X86_DECODE_FLAG_SSE3,
        CDISASM_X86_DECODE_FLAG_SSSE3,
        CDISASM_X86_DECODE_FLAG_SSE4,
        CDISASM_X86_DECODE_FLAG_AVX,
        CDISASM_X86_DECODE_FLAG_AVX2,
        CDISASM_X86_DECODE_FLAG_F16C,
        CDISASM_X86_DECODE_FLAG_FMA3,
        CDISASM_X86_DECODE_FLAG_XOP,
        CDISASM_X86_DECODE_FLAG_FMA4,
        CDISASM_X86_DECODE_FLAG_AES,
        CDISASM_X86_DECODE_FLAG_PCLMUL,
        CDISASM_X86_DECODE_FLAG_SHA,
        CDISASM_X86_DECODE_FLAG_GFNI,
        CDISASM_X86_DECODE_FLAG_BITMANIP,
        CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_X86_DECODE_FLAG_AMX,
        CDISASM_X86_DECODE_FLAG_APX,
        CDISASM_X86_DECODE_FLAG_SMX,
        CDISASM_X86_DECODE_FLAG_SYSTEM,
        CDISASM_X86_DECODE_FLAG_CET,
        CDISASM_X86_DECODE_FLAG_STATE,
        CDISASM_X86_DECODE_FLAG_TRANSACTIONAL,
        CDISASM_X86_DECODE_FLAG_SECURITY,
        CDISASM_X86_DECODE_FLAG_MEMORY_HINTS,
        CDISASM_X86_DECODE_FLAG_UNDOCUMENTED,
        CDISASM_X86_DECODE_FLAG_SM3,
        CDISASM_X86_DECODE_FLAG_SM4,
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI2,
        CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ,
        CDISASM_X86_DECODE_FLAG_AVX512_BITALG,
        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
        CDISASM_X86_DECODE_FLAG_AVX512_IFMA,
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI,
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        CDISASM_X86_DECODE_FLAG_VAES,
        CDISASM_X86_DECODE_FLAG_VPCLMULQDQ,
        CDISASM_X86_DECODE_FLAG_SHA512,
        CDISASM_X86_DECODE_FLAG_AMX_TILE,
        CDISASM_X86_DECODE_FLAG_AMX_INT8,
        CDISASM_X86_DECODE_FLAG_AMX_BF16,
        CDISASM_X86_DECODE_FLAG_AMX_FP16,
        CDISASM_X86_DECODE_FLAG_AMX_COMPLEX,
        CDISASM_X86_DECODE_FLAG_AMX_FP8,
        CDISASM_X86_DECODE_FLAG_AMX_MOVRS,
        CDISASM_X86_DECODE_FLAG_AMX_AVX512,
        CDISASM_X86_DECODE_FLAG_AVX512_DQ,
        CDISASM_X86_DECODE_FLAG_AVX512_BW,
        CDISASM_X86_DECODE_FLAG_VMX,
        CDISASM_X86_DECODE_FLAG_SVM,
        CDISASM_X86_DECODE_FLAG_SSE41,
        CDISASM_X86_DECODE_FLAG_SSE42,
        CDISASM_X86_DECODE_FLAG_SSE4A,
        CDISASM_X86_DECODE_FLAG_BMI1,
        CDISASM_X86_DECODE_FLAG_BMI2,
        CDISASM_X86_DECODE_FLAG_AVX512_CD,
        CDISASM_X86_DECODE_FLAG_AVX_VNNI,
        CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8,
        CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16
    };
    _Static_assert(
        sizeof(family_flags) / sizeof(family_flags[0]) == 64u,
        "single-family fuzz sweep must list every public x86 flag");
    _Static_assert(
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK == UINT64_MAX,
        "update the single-family fuzz sweep when x86 flags are appended");
#endif

    derive_decode_flags(data, size, &fuzz_flags);
    normalize_input(data, size, hex_bytes, &code, &code_size);
    hash = input_hash(code, code_size);
    address = hash ^ (hash << 32);

    for (index = 0; index < sizeof(modes) / sizeof(modes[0]); ++index) {
        check_one(code, code_size, CDISASM_CPU_X86, modes[index], address,
                  hash + index, NULL);
#if USE_EXTRA_OPCODES
        check_one(code, code_size, CDISASM_CPU_X86, modes[index], address,
                  hash + index, &all_flags);
        selected_family_flags.bitmap[
            CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
                family_flags[(hash + index)
                    % (sizeof(family_flags) / sizeof(family_flags[0]))];
        check_one(
            code,
            code_size,
            CDISASM_CPU_X86,
            modes[index],
            address,
            hash + index,
            &selected_family_flags);
#endif
    }

    /* One eligible mode for every named profile exercises non-monotonic gates. */
    for (cpu_id = CDISASM_CPU_FIRST; cpu_id <= CDISASM_CPU_LAST; ++cpu_id) {
        cdisasm_mode mode = eligible_mode(cpu_id, hash + cpu_id);
        check_one(code, code_size, cpu_id, mode, address,
                  hash ^ (uint64_t)cpu_id,
#if USE_EXTRA_OPCODES
                  &all_flags
#else
                  NULL
#endif
        );
    }

    /* Every byte boundary is also a potential truncation boundary. */
    for (index = 0;
         index < code_size && index <= CDISASM_MAX_INSTRUCTION_SIZE;
         ++index) {
        check_one(code, index, CDISASM_CPU_X86,
                  modes[hash % 3u], address, hash + index,
#if USE_EXTRA_OPCODES
                  &all_flags
#else
                  NULL
#endif
        );
    }
#if !USE_EXTRA_OPCODES
    {
        cdisasm_x86_decode_flags invalid_flags =
            CDISASM_X86_DECODE_FLAGS_INITIALIZER(
                CDISASM_X86_DECODE_FLAG_AVX);

        check_invalid_decode_flags(code, code_size, &invalid_flags);
    }
#endif
    check_reserved_decode_flag_bitmaps(code, code_size, &fuzz_flags);
    return 0;
}
