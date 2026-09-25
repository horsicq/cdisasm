#include "cdisasm/cdisasm_format.h"

#if USE_DISASM_FORMAT && USE_ARCH_X86

#include <stdint.h>

typedef struct text_writer {
    char *buffer;
    size_t buffer_size;
    size_t length;
} text_writer;

static const char *const mnemonic_names[] = {
    NULL, "aaa", "aad", "aam",
    "aas", "adc", "add", "and",
    "arpl", "bsf", "bsr", "bswap",
    "bt", "btc", "btr", "bts",
    "call", "cbw", "cdq", "cdqe",
    "clc", "cld", "cli", "clts",
    "cmc", "cmova", "cmovae", "cmovb",
    "cmovbe", "cmove", "cmovg", "cmovge",
    "cmovl", "cmovle", "cmovne", "cmovno",
    "cmovnp", "cmovns", "cmovo", "cmovp",
    "cmovs", "cmp", "cmpsb", "cmpsd",
    "cmpsq", "cmpsw", "cmpxchg", "cpuid",
    "cqo", "cwd", "cwde", "daa",
    "das", "dec", "div", "emms",
    "endbr32", "endbr64", "enter", "getsec",
    "hlt", "idiv", "imul", "in",
    "inc", "insb", "insd", "insw",
    "int", "int1", "int3", "into",
    "invd", "invlpg", "iret", "iretd",
    "iretq", "ja", "jae", "jb",
    "jbe", "jcxz", "je", "jecxz",
    "jg", "jge", "jl", "jle",
    "jmp", "jne", "jno", "jnp",
    "jns", "jo", "jp", "jrcxz",
    "js", "lahf", "lar", "lea",
    "leave", "lfs", "lgdt", "lgs",
    "lidt", "lldt", "lmsw", "lodsb",
    "lodsd", "lodsq", "lodsw", "loop",
    "loope", "loopne", "lsl", "lss",
    "ltr", "lzcnt", "mov", "movabs",
    "movsb", "movsd", "movsq", "movsw",
    "movsx", "movsxd", "movzx", "mul",
    "neg", "nop", "not", "or",
    "out", "outsb", "outsd", "outsw",
    "pause", "pop", "popcnt", "popf",
    "popfd", "popfq", "push", "pushf",
    "pushfd", "pushfq", "rcl", "rcr",
    "rdmsr", "rdpmc", "rdtsc", "ret",
    "retf", "rol", "ror", "sahf",
    "sar", "sbb", "scasb", "scasd",
    "scasq", "scasw", "seta", "setae",
    "setb", "setbe", "sete", "setg",
    "setge", "setl", "setle", "setne",
    "setno", "setnp", "setns", "seto",
    "setp", "sets", "sgdt", "shl",
    "shld", "shr", "shrd", "sidt",
    "sldt", "smsw", "stc", "std",
    "sti", "stosb", "stosd", "stosq",
    "stosw", "str", "sub", "syscall",
    "sysenter", "sysexit", "sysret", "test",
    "tzcnt", "ud2", "verr", "verw",
    "wait", "wbinvd", "wrmsr", "xadd",
    "xchg", "xlatb", "xor", "popa",
    "popad", "pusha", "pushad", "clgi",
    "invept", "invlpga", "invvpid", "loadall",
    "loadall286", "salc", "skinit", "stgi",
    "udb", "vmcall", "vmclear", "vmfunc",
    "vmgexit", "vmlaunch", "vmload", "vmmcall",
    "vmptrld", "vmptrst", "vmread", "vmresume",
    "vmrun", "vmsave", "vmwrite", "vmxoff",
    "vmxon",
    "femms", "pavgusb", "pf2id", "pf2iw",
    "pfacc", "pfadd", "pfcmpeq", "pfcmpge",
    "pfcmpgt", "pfmax", "pfmin", "pfmul",
    "pfnacc", "pfpnacc", "pfrcp", "pfrcpit1",
    "pfrcpit2", "pfrsqit1", "pfrsqrt", "pfsub",
    "pfsubr", "pi2fd", "pi2fw", "pmulhrw",
    "prefetch", "prefetchw", "pswapd", "ud0",
    "ud1", "vzeroall", "vzeroupper",
    "movups", "movss", "movaps", "movlps",
    "movhlps", "movhps", "movlhps", "movntps",
    "ucomiss", "comiss", "movmskps", "sqrtps",
    "sqrtss", "rsqrtps", "rsqrtss", "rcpps",
    "rcpss", "andps", "andnps", "orps",
    "xorps", "addps", "addss", "mulps",
    "mulss", "subps", "subss", "minps",
    "minss", "divps", "divss", "maxps",
    "maxss", "cmpps", "cmpss", "shufps",
    "unpcklps", "unpckhps", "cvtpi2ps", "cvtps2pi",
    "cvttps2pi", "cvtsi2ss", "cvtss2si", "cvttss2si",
    "ldmxcsr", "stmxcsr", "sfence", "prefetchnta",
    "prefetcht0", "prefetcht1", "prefetcht2", "pavgb",
    "pavgw", "pextrw", "pinsrw", "pmaxsw",
    "pmaxub", "pminsw", "pminub", "pmovmskb",
    "pmulhuw", "psadbw", "pshufw", "maskmovq",
    "movntq", "movupd", "movapd", "movlpd",
    "movhpd", "movntpd", "ucomisd", "comisd",
    "movmskpd", "sqrtpd", "sqrtsd", "andpd",
    "andnpd", "orpd", "xorpd", "addpd",
    "addsd", "mulpd", "mulsd", "subpd",
    "subsd", "minpd", "minsd", "divpd",
    "divsd", "maxpd", "maxsd", "cmppd",
    "shufpd", "unpcklpd", "unpckhpd", "movdqa",
    "movdqu", "cvtps2pd", "cvtss2sd", "cvtsd2ss",
    "cvtpd2ps", "cvtdq2ps", "cvtps2dq", "cvttps2dq",
    "cvtsi2sd", "cvtsd2si", "cvttsd2si", "punpcklbw",
    "punpcklwd", "punpckldq", "packsswb", "pcmpgtb",
    "pcmpgtw", "pcmpgtd", "packuswb", "punpckhbw",
    "punpckhwd", "punpckhdq", "packssdw", "punpcklqdq",
    "punpckhqdq", "pcmpeqb", "pcmpeqw", "pcmpeqd",
    "psrlw", "psrld", "psrlq", "paddq",
    "pmullw", "psubusb", "psubusw", "pand",
    "paddusb", "paddusw", "pandn", "psraw",
    "psrad", "pmulhw", "psubsb", "psubsw",
    "por", "paddsb", "paddsw", "pxor",
    "psllw", "pslld", "psllq", "pmuludq",
    "pmaddwd", "psubb", "psubw", "psubd",
    "psubq", "paddb", "paddw", "paddd",
    "movddup", "movsldup", "movshdup", "haddpd",
    "haddps", "hsubpd", "hsubps", "addsubpd",
    "addsubps", "lddqu", "pshufb", "phaddw",
    "phaddd", "phaddsw", "pmaddubsw", "phsubw",
    "phsubd", "phsubsw", "psignb", "psignw",
    "psignd", "pmulhrsw", "pabsb", "pabsw",
    "pabsd", "palignr", "pblendvb", "blendvps",
    "blendvpd", "ptest", "pmovsxbw", "pmovsxbd",
    "pmovsxbq", "pmovsxwd", "pmovsxwq", "pmovsxdq",
    "pmuldq", "pcmpeqq", "movntdqa", "packusdw",
    "pmovzxbw", "pmovzxbd", "pmovzxbq", "pmovzxwd",
    "pmovzxwq", "pmovzxdq", "pminsb", "pminsd",
    "pminuw", "pminud", "pmaxsb", "pmaxsd",
    "pmaxuw", "pmaxud", "pmulld", "phminposuw",
    "roundps", "roundpd", "roundss", "roundsd",
    "blendps", "blendpd", "pblendw", "pextrb",
    "pextrd", "extractps", "pinsrb", "insertps",
    "pinsrd", "dpps", "dppd", "mpsadbw",
    "movntss", "movntsd", "pcmpgtq", "pcmpestrm",
    "pcmpestri", "pcmpistrm", "pcmpistri", "crc32",
    "extrq", "insertq",
    "f2xm1", "fabs", "fadd", "faddp",
    "fbld", "fbstp", "fchs", "fclex",
    "fcmovb", "fcmovbe", "fcmove", "fcmovnb",
    "fcmovnbe", "fcmovne", "fcmovnu", "fcmovu",
    "fcom", "fcomi", "fcomip", "fcomp",
    "fcompp", "fcos", "fdecstp", "fdisi",
    "fdiv", "fdivp", "fdivr", "fdivrp",
    "feni", "ffree", "ffreep", "fiadd",
    "ficom", "ficomp", "fidiv", "fidivr",
    "fild", "fimul", "fincstp", "finit",
    "fist", "fistp", "fisttp", "fisub",
    "fisubr", "fld", "fld1", "fldcw",
    "fldenv", "fldl2e", "fldl2t", "fldlg2",
    "fldln2", "fldpi", "fldz", "fmul",
    "fmulp", "fnclex", "fndisi", "fneni",
    "fninit", "fnop", "fnsave", "fnsetpm",
    "fnstcw", "fnstenv", "fnstsw", "fpatan",
    "fprem", "fprem1", "fptan", "frndint",
    "frstor", "fsave", "fscale", "fsetpm",
    "fsin", "fsincos", "fsqrt", "fst",
    "fstcw", "fstenv", "fstp", "fstsw",
    "fsub", "fsubp", "fsubr", "fsubrp",
    "ftst", "fucom", "fucomi", "fucomip",
    "fucomp", "fucompp", "fxam", "fxch",
    "fxtract", "fyl2x", "fyl2xp1", "fstpnce",
#if USE_EXTRA_OPCODES
    "vaddps", "vaddpd", "vaddss", "vaddsd",
    "vsubps", "vsubpd", "vsubss", "vsubsd",
    "vmulps", "vmulpd", "vmulss", "vmulsd",
    "vdivps", "vdivpd", "vdivss", "vdivsd",
    "vminps", "vminpd", "vminss", "vminsd",
    "vmaxps", "vmaxpd", "vmaxss", "vmaxsd",
    "vandps", "vandpd", "vandnps", "vandnpd",
    "vorps", "vorpd", "vxorps", "vxorpd",
    "vpaddb", "vpaddw", "vpaddd", "vpaddq",
    "vpsubb", "vpsubw", "vpsubd", "vpsubq",
    "vpand", "vpandn", "vpor", "vpxor",
    "vpcmpeqb", "vpcmpeqw", "vpcmpeqd",
    "vpcmpgtb", "vpcmpgtw", "vpcmpgtd",
    "vpmullw", "vpmuludq", "vpmaddwd",
    "vpavgb", "vpavgw", "vpmaxsw", "vpmaxub",
    "vpminsw", "vpminub", "vpsadbw",
    "aesenc", "aesenclast", "aesdec", "aesdeclast",
    "aesimc", "aeskeygenassist", "pclmulqdq", "sha1msg1",
    "sha1msg2", "sha1nexte", "sha1rnds4", "sha256msg1",
    "sha256msg2", "sha256rnds2", "andn", "bextr",
    "blsi", "blsmsk", "blsr", "bzhi",
    "mulx", "pdep", "pext", "rorx",
    "sarx", "shlx", "shrx", "vcvtph2ps",
    "vcvtps2ph", "vfmadd132ps", "vfmadd213ps", "vfmadd231ps",
    "vfmadd132pd", "vfmadd132ss", "vfmadd132sd", "vprotb",
    "vprotw", "vprotd", "vprotq", "vpcmov",
    "vfmaddps", "vfmaddpd", "vfmaddss", "vfmaddsd",
    "vpermb", "vpdpbusd", "vpopcntd", "vpmadd52luq",
    "vpmadd52huq", "ldtilecfg", "sttilecfg", "tileloadd",
    "tileloaddt1", "tilestored", "tilezero", "tilerelease",
    "tdpbssd", "tdpbsud", "tdpbusd", "tdpbuud",
    "tdpbf16ps", "push2", "pop2",
    "vpshufb", "vpalignr", "vaesenc", "vpclmulqdq",
    "rdrand", "rdseed", "xbegin", "xabort", "xend", "xtest",
    "vfmadd213pd", "vfmadd231pd", "vfmadd213ss", "vfmadd213sd",
    "vfmadd231ss", "vfmadd231sd",
    "vfmaddsub132ps", "vfmaddsub132pd", "vfmaddsub213ps",
    "vfmaddsub213pd", "vfmaddsub231ps", "vfmaddsub231pd",
    "vfmsubadd132ps", "vfmsubadd132pd", "vfmsubadd213ps",
    "vfmsubadd213pd", "vfmsubadd231ps", "vfmsubadd231pd",
    "vfmsub132ps", "vfmsub132pd", "vfmsub132ss", "vfmsub132sd",
    "vfmsub213ps", "vfmsub213pd", "vfmsub213ss", "vfmsub213sd",
    "vfmsub231ps", "vfmsub231pd", "vfmsub231ss", "vfmsub231sd",
    "vfnmadd132ps", "vfnmadd132pd", "vfnmadd132ss", "vfnmadd132sd",
    "vfnmadd213ps", "vfnmadd213pd", "vfnmadd213ss", "vfnmadd213sd",
    "vfnmadd231ps", "vfnmadd231pd", "vfnmadd231ss", "vfnmadd231sd",
    "vfnmsub132ps", "vfnmsub132pd", "vfnmsub132ss", "vfnmsub132sd",
    "vfnmsub213ps", "vfnmsub213pd", "vfnmsub213ss", "vfnmsub213sd",
    "vfnmsub231ps", "vfnmsub231pd", "vfnmsub231ss", "vfnmsub231sd",
    "vaesenclast", "vaesdec", "vaesdeclast", "vaesimc",
    "vaeskeygenassist", "tdpfp16ps", "jmpabs",
    "vfmaddsubps", "vfmaddsubpd", "vfmsubaddps", "vfmsubaddpd",
    "vfmsubps", "vfmsubpd", "vfmsubss", "vfmsubsd",
    "vfnmaddps", "vfnmaddpd", "vfnmaddss", "vfnmaddsd",
    "vfnmsubps", "vfnmsubpd", "vfnmsubss", "vfnmsubsd",
    "vpshlb", "vpshlw", "vpshld", "vpshlq",
    "vpshab", "vpshaw", "vpshad", "vpshaq",
    "clrssbsy", "incsspd", "incsspq", "rdsspd",
    "rdsspq", "rstorssp", "saveprevssp", "setssbsy",
    "wrssd", "wrssq", "wrussd", "wrussq",
    "umonitor", "umwait", "tpause",
    "vfrczps", "vfrczpd", "vfrczss", "vfrczsd",
    "vphaddbw", "vphaddbd", "vphaddbq", "vphaddwd",
    "vphaddwq", "vphadddq", "vphaddubw", "vphaddubd",
    "vphaddubq", "vphadduwd", "vphadduwq", "vphaddudq",
    "vphsubbw", "vphsubwd", "vphsubdq",
    "vpmacssww", "vpmacsswd", "vpmacssdql", "vpmacssdd",
    "vpmacssdqh", "vpmacsww", "vpmacswd", "vpmacsdql",
    "vpmacsdd", "vpmacsdqh", "vpmadcsswd", "vpmadcswd",
    "vpcomb", "vpcomw", "vpcomd", "vpcomq",
    "vpcomub", "vpcomuw", "vpcomud", "vpcomuq",
    "vpperm", "vpermil2ps", "vpermil2pd",
    "vsha512msg1", "vsha512msg2", "vsha512rnds2", "vsm3msg1",
    "vsm3msg2", "vsm3rnds2", "vsm4key4", "vsm4rnds4",
    "vaddsubpd", "vaddsubps", "vhaddpd", "vhaddps",
    "vhsubpd", "vhsubps", "vrcpps", "vrcpss",
    "vrsqrtps", "vrsqrtss", "vsqrtpd", "vsqrtps",
    "vsqrtsd", "vsqrtss", "vcvtdq2pd", "vcvtdq2ps",
    "vcvtpd2dq", "vcvttpd2dq", "vcvtpd2ps", "vcvtps2dq",
    "vcvttps2dq", "vcvtps2pd", "vcvtsd2ss", "vcvtss2sd",
    "clflush", "clflushopt", "clwb", "rdpid",
    "serialize", "movdiri", "movdir64b", "wbnoinvd",
    "tcmmimfp16ps", "tcmmrlfp16ps", "tdpbf8ps", "tdpbhf8ps",
    "tdphbf8ps", "tdphf8ps", "tileloaddrs", "tileloaddrst1",
    "tcvtrowd2ps", "tcvtrowps2bf16h", "tcvtrowps2bf16l",
    "tcvtrowps2phh", "tcvtrowps2phl", "tilemovrow",
    "vaddbf16", "vmulbf16", "vsubbf16", "vdivbf16",
    "kandnw", "kandw", "kmovw", "knotw",
    "kortestw", "korw", "kshiftlw", "kshiftrw",
    "kunpckbw", "kxnorw", "kxorw",
    "kaddb", "kaddd", "kaddq", "kaddw",
    "kandb", "kandd", "kandnb", "kandnd",
    "kandnq", "kandq", "kmovb", "kmovd",
    "kmovq", "knotb", "knotd", "knotq",
    "korb", "kord", "korq", "kortestb",
    "kortestd", "kortestq", "kshiftlb", "kshiftld",
    "kshiftlq", "kshiftrb", "kshiftrd", "kshiftrq",
    "ktestb", "ktestd", "ktestq", "ktestw",
    "kunpckdq", "kunpckwd", "kxnorb", "kxnord",
    "kxnorq", "kxorb", "kxord", "kxorq",
    "vpcmpb", "vpcmpw", "vpcmpd", "vpcmpq",
    "vpcmpub", "vpcmpuw", "vpcmpud", "vpcmpuq",
    "vpminsb", "vpminsd", "vpminsq", "vpminuw",
    "vpminud", "vpminuq", "vpmaxsb", "vpmaxsd",
    "vpmaxsq", "vpmaxuw", "vpmaxud", "vpmaxuq",
    "vpmulld", "vpmullq", "vpmulhw", "vpmulhuw",
    "vpmulhrsw", "vpmuldq", "vpmaddubsw",
    "vpaddsb", "vpaddsw", "vpaddusb", "vpaddusw",
    "vpsubsb", "vpsubsw", "vpsubusb", "vpsubusw",
    "vpandd", "vpandq", "vpandnd", "vpandnq",
    "vpord", "vporq", "vpxord", "vpxorq",
    "vpsllvd", "vpsllvq", "vpsrlvd", "vpsrlvq",
    "vpsravd", "vpsravq",
    "vpsllvw", "vpsrlvw", "vpsravw",
    "vprolvd", "vprolvq", "vprorvd", "vprorvq",
    "vprold", "vprolq", "vprord", "vprorq",
    "vpsrld", "vpsrad", "vpsraq", "vpslld",
    "vpsrlw", "vpsraw", "vpsllw", "vpsrlq", "vpsrldq", "vpsllq",
    "vpslldq",
    "vpshldw", "vpshldd", "vpshldq",
    "vpshldvw", "vpshldvd", "vpshldvq",
    "vpshrdw", "vpshrdd", "vpshrdq",
    "vpshrdvw", "vpshrdvd", "vpshrdvq",
    "vpcompressb", "vpcompressw", "vpcompressd", "vpcompressq",
    "vpexpandb", "vpexpandw", "vpexpandd", "vpexpandq",
    "vpopcntb", "vpopcntw", "vpopcntq", "vpshufbitqmb",
    "vpconflictd", "vpconflictq", "vplzcntd", "vplzcntq",
    "vpbroadcastmb2q", "vpbroadcastmw2d",
    "vpdpbusds", "vpdpwssd", "vpdpwssds",
    "vpermi2b", "vpermt2b", "vpmultishiftqb",
    "vpermi2w", "vpermt2w", "vpermw",
    "vpdpbssd", "vpdpbssds", "vpdpbsud", "vpdpbsuds",
    "vpdpbuud", "vpdpbuuds",
    "vpdpwsud", "vpdpwsuds", "vpdpwusd", "vpdpwusds",
    "vpdpwuud", "vpdpwuuds",
    "vp4dpwssd", "vp4dpwssds",
    "v4fmaddps", "v4fmaddss", "v4fnmaddps", "v4fnmaddss",
    "vgetexpps", "vgetexppd", "vgetexpss", "vgetexpsd",
    "vgetexpph", "vgetexpsh", "vgetexpbf16",
    "bound", "lds", "les", "cmpxchg8b", "cmpxchg16b", "movbe",
    "adcx", "adox", "lfence", "mfence",
    "fxsave", "fxsave64", "fxrstor", "fxrstor64",
    "xsave", "xsave64", "xrstor", "xrstor64",
    "xsaveopt", "xsaveopt64", "xsavec", "xsavec64",
    "xsaves", "xsaves64", "xrstors", "xrstors64",
    "xgetbv", "xsetbv", "monitor", "mwait", "rdtscp", "invpcid",
    "rdfsbase", "rdgsbase", "wrfsbase", "wrgsbase", "rdpkru", "wrpkru",
    "bndmk", "bndcl", "bndcu", "bndcn", "bndmov", "bndldx", "bndstx",
    "encls", "enclu", "enclv", "xsusldtrk", "xresldtrk",
    "clui", "senduipi", "stui", "testui", "uiret", "enqcmd", "enqcmds",
    "vmovups", "vmovupd", "vmovaps", "vmovapd", "vmovdqa", "vmovdqu",
    "vmovntps", "vmovntpd", "vmovntdq", "vlddqu", "vmovmskps", "vmovmskpd",
#  define CDISASM_X86_ICLASS_MNEMONIC(value) value,
#  include "x86_iclass_mnemonics.inc"
#  undef CDISASM_X86_ICLASS_MNEMONIC
#else
#  define CDISASM_X86_FORMAT_NULL4 NULL, NULL, NULL, NULL
#  define CDISASM_X86_FORMAT_NULL8 \
    CDISASM_X86_FORMAT_NULL4, CDISASM_X86_FORMAT_NULL4
    CDISASM_X86_FORMAT_NULL4, CDISASM_X86_FORMAT_NULL4,
    CDISASM_X86_FORMAT_NULL4, CDISASM_X86_FORMAT_NULL4,
    CDISASM_X86_FORMAT_NULL4, CDISASM_X86_FORMAT_NULL4,
    CDISASM_X86_FORMAT_NULL4, CDISASM_X86_FORMAT_NULL4,
    CDISASM_X86_FORMAT_NULL4, CDISASM_X86_FORMAT_NULL4,
    CDISASM_X86_FORMAT_NULL4, CDISASM_X86_FORMAT_NULL4,
    CDISASM_X86_FORMAT_NULL4, CDISASM_X86_FORMAT_NULL4,
    CDISASM_X86_FORMAT_NULL4,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8,
    NULL, NULL, NULL, NULL, NULL,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL4,
    NULL, NULL, NULL,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    NULL, NULL, NULL,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    NULL, NULL,
    NULL, NULL, NULL, NULL,
    CDISASM_X86_FORMAT_NULL8, NULL, NULL, NULL,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL4,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    CDISASM_X86_FORMAT_NULL4,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL4,
    CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL4,
    CDISASM_X86_FORMAT_NULL4,
    NULL, NULL,
    NULL, NULL, NULL,
    NULL, NULL, NULL,
    NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL,
    CDISASM_X86_FORMAT_NULL4,
    NULL, NULL, NULL,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    NULL, NULL, NULL,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL8,
    NULL, NULL, NULL, NULL, NULL, NULL,
    CDISASM_X86_FORMAT_NULL8, CDISASM_X86_FORMAT_NULL4,
#  undef CDISASM_X86_FORMAT_NULL8
#  undef CDISASM_X86_FORMAT_NULL4
#  define CDISASM_X86_ICLASS_MNEMONIC(value) NULL,
#  include "x86_iclass_mnemonics.inc"
#  undef CDISASM_X86_ICLASS_MNEMONIC
#endif
};

static const char *const register_names[] = {
    NULL, "al", "cl", "dl",
    "bl", "ah", "ch", "dh",
    "bh", "spl", "bpl", "sil",
    "dil", "r8b", "r9b", "r10b",
    "r11b", "r12b", "r13b", "r14b",
    "r15b", "ax", "cx", "dx",
    "bx", "sp", "bp", "si",
    "di", "r8w", "r9w", "r10w",
    "r11w", "r12w", "r13w", "r14w",
    "r15w", "eax", "ecx", "edx",
    "ebx", "esp", "ebp", "esi",
    "edi", "r8d", "r9d", "r10d",
    "r11d", "r12d", "r13d", "r14d",
    "r15d", "rax", "rcx", "rdx",
    "rbx", "rsp", "rbp", "rsi",
    "rdi", "r8", "r9", "r10",
    "r11", "r12", "r13", "r14",
    "r15", "ip", "eip", "rip",
    "es", "cs", "ss", "ds",
    "fs", "gs", NULL, NULL,
    "cr0", "cr1", "cr2", "cr3",
    "cr4", "cr5", "cr6", "cr7",
    "cr8", "cr9", "cr10", "cr11",
    "cr12", "cr13", "cr14", "cr15",
    "dr0", "dr1", "dr2", "dr3",
    "dr4", "dr5", "dr6", "dr7",
    "dr8", "dr9", "dr10", "dr11",
    "dr12", "dr13", "dr14", "dr15",
    "st0", "st1", "st2", "st3",
    "st4", "st5", "st6", "st7",
    "mm0", "mm1", "mm2", "mm3",
    "mm4", "mm5", "mm6", "mm7",
    "xmm0", "xmm1", "xmm2", "xmm3",
    "xmm4", "xmm5", "xmm6", "xmm7",
    "xmm8", "xmm9", "xmm10", "xmm11",
    "xmm12", "xmm13", "xmm14", "xmm15",
    "xmm16", "xmm17", "xmm18", "xmm19",
    "xmm20", "xmm21", "xmm22", "xmm23",
    "xmm24", "xmm25", "xmm26", "xmm27",
    "xmm28", "xmm29", "xmm30", "xmm31",
    "ymm0", "ymm1", "ymm2", "ymm3",
    "ymm4", "ymm5", "ymm6", "ymm7",
    "ymm8", "ymm9", "ymm10", "ymm11",
    "ymm12", "ymm13", "ymm14", "ymm15",
    "ymm16", "ymm17", "ymm18", "ymm19",
    "ymm20", "ymm21", "ymm22", "ymm23",
    "ymm24", "ymm25", "ymm26", "ymm27",
    "ymm28", "ymm29", "ymm30", "ymm31",
    "zmm0", "zmm1", "zmm2", "zmm3",
    "zmm4", "zmm5", "zmm6", "zmm7",
    "zmm8", "zmm9", "zmm10", "zmm11",
    "zmm12", "zmm13", "zmm14", "zmm15",
    "zmm16", "zmm17", "zmm18", "zmm19",
    "zmm20", "zmm21", "zmm22", "zmm23",
    "zmm24", "zmm25", "zmm26", "zmm27",
    "zmm28", "zmm29", "zmm30", "zmm31",
    "k0", "k1", "k2", "k3",
    "k4", "k5", "k6", "k7",
    "bnd0", "bnd1", "bnd2", "bnd3",
    "tmm0", "tmm1", "tmm2", "tmm3",
    "tmm4", "tmm5", "tmm6", "tmm7",
    "r16b", "r17b", "r18b", "r19b",
    "r20b", "r21b", "r22b", "r23b",
    "r24b", "r25b", "r26b", "r27b",
    "r28b", "r29b", "r30b", "r31b",
    "r16w", "r17w", "r18w", "r19w",
    "r20w", "r21w", "r22w", "r23w",
    "r24w", "r25w", "r26w", "r27w",
    "r28w", "r29w", "r30w", "r31w",
    "r16d", "r17d", "r18d", "r19d",
    "r20d", "r21d", "r22d", "r23d",
    "r24d", "r25d", "r26d", "r27d",
    "r28d", "r29d", "r30d", "r31d",
    "r16", "r17", "r18", "r19",
    "r20", "r21", "r22", "r23",
    "r24", "r25", "r26", "r27",
    "r28", "r29", "r30", "r31",
    "bsr0"
};

_Static_assert(
    sizeof(mnemonic_names) / sizeof(mnemonic_names[0])
        == CDISASM_X86_NAME_COUNT,
    "x86 mnemonic table is incomplete");
_Static_assert(
    sizeof(register_names) / sizeof(register_names[0])
        == CDISASM_X86_REG_COUNT,
    "x86 register table is incomplete");

static const char *mnemonic_name(cdisasm_x86_name_id name_id)
{
    /* The generated catalog splits EVEX map-1 opcode C5 for descriptor
     * identity, but Intel and AT&T syntax retain the architectural spelling. */
    if (name_id == CDISASM_X86_NAME_VPEXTRW_C5) {
        return "vpextrw";
    }
#if !USE_EXTRA_OPCODES
    /* These legacy base instructions gained append-only IDs alongside the
     * generated catalog, but their hand-written decoders remain available in
     * the compact build.  Keep their spellings available there as well. */
    switch (name_id) {
        case CDISASM_X86_NAME_BOUND: return "bound";
        case CDISASM_X86_NAME_LDS: return "lds";
        case CDISASM_X86_NAME_LES: return "les";
        case CDISASM_X86_NAME_CMPXCHG8B: return "cmpxchg8b";
        case CDISASM_X86_NAME_CMPXCHG16B: return "cmpxchg16b";
        default: break;
    }
#endif
    return mnemonic_names[name_id];
}

static void writer_putc(text_writer *writer, char value)
{
    if (writer->buffer != NULL
        && writer->buffer_size != 0
        && writer->length < writer->buffer_size - 1) {
        writer->buffer[writer->length] = value;
    }
    ++writer->length;
}

static void writer_puts(text_writer *writer, const char *text)
{
    while (*text != '\0') {
        writer_putc(writer, *text++);
    }
}

static void writer_putc_opcode(
    text_writer *writer,
    char value,
    uint32_t flags)
{
    if ((flags & CDISASM_FORMAT_UPPERCASE_OPCODE) != 0
        && value >= 'a' && value <= 'z') {
        value = (char)(value - 'a' + 'A');
    }
    writer_putc(writer, value);
}

static void writer_puts_opcode(
    text_writer *writer,
    const char *text,
    uint32_t flags)
{
    while (*text != '\0') {
        writer_putc_opcode(writer, *text++, flags);
    }
}

static void writer_finish(text_writer *writer)
{
    if (writer->buffer != NULL && writer->buffer_size != 0) {
        size_t ending = writer->length < writer->buffer_size
            ? writer->length
            : writer->buffer_size - 1;
        writer->buffer[ending] = '\0';
    }
}

static void writer_hex(text_writer *writer, uint64_t value)
{
    static const char digits[] = "0123456789abcdef";
    char reversed[16];
    size_t count = 0;

    writer_puts(writer, "0x");
    do {
        reversed[count++] = digits[value & UINT64_C(0xf)];
        value >>= 4;
    } while (value != 0);

    while (count != 0) {
        writer_putc(writer, reversed[--count]);
    }
}

static void writer_decimal(text_writer *writer, unsigned int value)
{
    char reversed[3];
    size_t count = 0;

    do {
        reversed[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value != 0);
    while (count != 0) {
        writer_putc(writer, reversed[--count]);
    }
}

static int value_is_negative(uint64_t value)
{
    return (value & (UINT64_C(1) << 63)) != 0;
}

static void writer_signed_hex(text_writer *writer, uint64_t value)
{
    if (value_is_negative(value)) {
        writer_putc(writer, '-');
        value = UINT64_C(0) - value;
    }
    writer_hex(writer, value);
}

static int valid_register(cdisasm_x86_reg_id reg)
{
    return reg < CDISASM_X86_REG_COUNT && register_names[reg] != NULL;
}

static int bytes_are_zero(const void *data, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)data;
    size_t index;

    for (index = 0; index < size; ++index) {
        if (bytes[index] != 0) {
            return 0;
        }
    }
    return 1;
}

static int valid_address_register(cdisasm_x86_reg_id reg)
{
    return (reg >= CDISASM_X86_REG_AX && reg <= CDISASM_X86_REG_R15W)
        || (reg >= CDISASM_X86_REG_EAX && reg <= CDISASM_X86_REG_R15D)
        || (reg >= CDISASM_X86_REG_RAX && reg <= CDISASM_X86_REG_R15)
        || (reg >= CDISASM_X86_REG_R16W && reg <= CDISASM_X86_REG_R31W)
        || (reg >= CDISASM_X86_REG_R16D && reg <= CDISASM_X86_REG_R31D)
        || (reg >= CDISASM_X86_REG_R16 && reg <= CDISASM_X86_REG_R31)
        || (reg >= CDISASM_X86_REG_IP && reg <= CDISASM_X86_REG_RIP);
}

static int valid_access(cdisasm_operand_access access)
{
    return access <= CDISASM_OPERAND_ACCESS_READ_WRITE;
}

static int valid_broadcast(cdisasm_x86_broadcast broadcast)
{
    return broadcast == CDISASM_X86_BROADCAST_NONE
        || broadcast == CDISASM_X86_BROADCAST_1_TO_2
        || broadcast == CDISASM_X86_BROADCAST_1_TO_4
        || broadcast == CDISASM_X86_BROADCAST_1_TO_8
        || broadcast == CDISASM_X86_BROADCAST_1_TO_16
        || broadcast == CDISASM_X86_BROADCAST_1_TO_32
        || broadcast == CDISASM_X86_BROADCAST_1_TO_64;
}

static int valid_segment_register(cdisasm_x86_reg_id reg)
{
    return reg >= CDISASM_X86_REG_ES && reg <= CDISASM_X86_REG_GS;
}

static const char *pointer_size_name(uint8_t size)
{
    switch (size) {
        case CDISASM_X86_OPERAND_SIZE_VARIABLE:
            return "";
        case 1:
            return "byte ptr ";
        case 2:
            return "word ptr ";
        case 4:
            return "dword ptr ";
        case 6:
            return "fword ptr ";
        case 8:
            return "qword ptr ";
        case 10:
            return "tbyte ptr ";
        case 12:
            return "m12byte ptr ";
        case 14:
            return "m14byte ptr ";
        case 16:
            return "xmmword ptr ";
        case 24:
            return "m24byte ptr ";
        case 28:
            return "m28byte ptr ";
        case 32:
            return "ymmword ptr ";
        case 48:
            return "m48byte ptr ";
        case 64:
            return "zmmword ptr ";
        case 94:
            return "m94byte ptr ";
        case 108:
            return "m108byte ptr ";
        default:
            return NULL;
    }
}

static int is_compare_string_name(cdisasm_x86_name_id name_id)
{
    switch (name_id) {
        case CDISASM_X86_NAME_CMPSB:
        case CDISASM_X86_NAME_CMPSW:
        case CDISASM_X86_NAME_CMPSD:
        case CDISASM_X86_NAME_CMPSQ:
        case CDISASM_X86_NAME_SCASB:
        case CDISASM_X86_NAME_SCASW:
        case CDISASM_X86_NAME_SCASD:
        case CDISASM_X86_NAME_SCASQ:
            return 1;
        default:
            return 0;
    }
}

static int suppress_rep_prefix(const cdisasm_instruction *instruction)
{
    switch (instruction->name_id) {
        case CDISASM_X86_NAME_PAUSE:
        case CDISASM_X86_NAME_POPCNT:
        case CDISASM_X86_NAME_LZCNT:
        case CDISASM_X86_NAME_TZCNT:
        case CDISASM_X86_NAME_ENDBR32:
        case CDISASM_X86_NAME_ENDBR64:
        case CDISASM_X86_NAME_BSF:
        case CDISASM_X86_NAME_BSR:
        case CDISASM_X86_NAME_VMGEXIT:
        case CDISASM_X86_NAME_VMMCALL:
        case CDISASM_X86_NAME_VMXON:
        case CDISASM_X86_NAME_IBHF:
        case CDISASM_X86_NAME_REP_MONTMUL:
        case CDISASM_X86_NAME_REP_XCRYPTCBC:
        case CDISASM_X86_NAME_REP_XCRYPTCFB:
        case CDISASM_X86_NAME_REP_XCRYPTCTR:
        case CDISASM_X86_NAME_REP_XCRYPTECB:
        case CDISASM_X86_NAME_REP_XCRYPTOFB:
        case CDISASM_X86_NAME_REP_XSHA1:
        case CDISASM_X86_NAME_REP_XSHA256:
        case CDISASM_X86_NAME_REP_XSTORE:
            return 1;
        case CDISASM_X86_NAME_NOP:
            return 1;
        default:
            return 0;
    }
}

static int is_implicit_string_form(
    const cdisasm_instruction *instruction)
{
    size_t index;

    if (instruction->operand_count == 0) {
        return 0;
    }
    for (index = 0; index < instruction->operand_count; ++index) {
        if ((instruction->opcode[index].flags
                & CDISASM_OPERAND_FLAG_IMPLICIT) == 0) {
            return 0;
        }
    }
    return 1;
}

static int is_unsized_mov_register(cdisasm_x86_reg_id reg)
{
    return (reg >= CDISASM_X86_REG_ES && reg <= CDISASM_X86_REG_GS)
        || (reg >= CDISASM_X86_REG_CR0 && reg <= CDISASM_X86_REG_CR15)
        || (reg >= CDISASM_X86_REG_DR0 && reg <= CDISASM_X86_REG_DR15);
}

static int mov_has_unsized_register(
    const cdisasm_instruction *instruction)
{
    size_t index;

    for (index = 0; index < instruction->operand_count; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];

        if (operand->type == CDISASM_OPERAND_REGISTER
            && is_unsized_mov_register(operand->reg)) {
            return 1;
        }
    }
    return 0;
}

static char att_width_suffix(uint8_t size)
{
    switch (size) {
        case 1:
            return 'b';
        case 2:
            return 'w';
        case 4:
            return 'l';
        case 8:
            return 'q';
        default:
            return '\0';
    }
}

static char att_vector_width_suffix(uint8_t size)
{
    switch (size) {
        case 16:
            return 'x';
        case 32:
            return 'y';
        case 64:
            return 'z';
        default:
            return '\0';
    }
}

static int valid_format_mode(cdisasm_mode mode)
{
    return mode == CDISASM_MODE_16
        || mode == CDISASM_MODE_32
        || mode == CDISASM_MODE_64;
}

static char att_mode_width_suffix(
    const cdisasm_instruction *instruction,
    cdisasm_mode mode,
    int long_mode_override_is_word)
{
    int operand_override =
        (instruction->opcode_flags & CDISASM_PREFIX_OPERAND_SIZE) != 0;

    if (mode == CDISASM_MODE_16) {
        return operand_override ? 'l' : 'w';
    }
    if (mode == CDISASM_MODE_32) {
        return operand_override ? 'w' : 'l';
    }
    if (mode == CDISASM_MODE_64) {
        return operand_override && long_mode_override_is_word ? 'w' : 'q';
    }
    return '\0';
}

static char att_default_mode_width_suffix(cdisasm_mode mode)
{
    if (mode == CDISASM_MODE_16) {
        return 'w';
    }
    if (mode == CDISASM_MODE_32) {
        return 'l';
    }
    if (mode == CDISASM_MODE_64) {
        return 'q';
    }
    return '\0';
}

static char att_far_return_width_suffix(
    const cdisasm_instruction *instruction,
    cdisasm_mode mode)
{
    if (mode != CDISASM_MODE_64) {
        return att_mode_width_suffix(instruction, mode, 0);
    }

    /* Far RET defaults to 32 bits in long mode; REX.W selects 64 bits. */
    if ((instruction->opcode_flags & CDISASM_PREFIX_REX_W) != 0) {
        return 'q';
    }
    if ((instruction->opcode_flags & CDISASM_PREFIX_OPERAND_SIZE) != 0) {
        return 'w';
    }
    return 'l';
}

static const char *att_mnemonic_alias(
    const cdisasm_instruction *instruction)
{
    if (instruction->operand_count == 1
        && instruction->opcode[0].type == CDISASM_OPERAND_MEMORY
        && instruction->opcode[0].size == 8) {
        switch (instruction->name_id) {
            case CDISASM_X86_NAME_FILD:
                return "fildll";
            case CDISASM_X86_NAME_FISTP:
                return "fistpll";
            case CDISASM_X86_NAME_FISTTP:
                return "fisttpll";
            default:
                break;
        }
    }
    switch (instruction->name_id) {
        case CDISASM_X86_NAME_CBW:
            return "cbtw";
        case CDISASM_X86_NAME_CWDE:
            return "cwtl";
        case CDISASM_X86_NAME_CDQE:
            return "cltq";
        case CDISASM_X86_NAME_CWD:
            return "cwtd";
        case CDISASM_X86_NAME_CDQ:
            return "cltd";
        case CDISASM_X86_NAME_CQO:
            return "cqto";
        case CDISASM_X86_NAME_IRET:
            return "iretw";
        case CDISASM_X86_NAME_IRETD:
            return "iretl";
        case CDISASM_X86_NAME_IRETQ:
            return "iretq";
        case CDISASM_X86_NAME_RETF:
            return "lret";
        case CDISASM_X86_NAME_PUSHF:
            return "pushfw";
        case CDISASM_X86_NAME_PUSHFD:
            return "pushfl";
        case CDISASM_X86_NAME_PUSHFQ:
            return "pushfq";
        case CDISASM_X86_NAME_POPF:
            return "popfw";
        case CDISASM_X86_NAME_POPFD:
            return "popfl";
        case CDISASM_X86_NAME_POPFQ:
            return "popfq";
        case CDISASM_X86_NAME_PUSHA:
            return "pushaw";
        case CDISASM_X86_NAME_PUSHAD:
            return "pushal";
        case CDISASM_X86_NAME_POPA:
            return "popaw";
        case CDISASM_X86_NAME_POPAD:
            return "popal";
        case CDISASM_X86_NAME_INSD:
            return "insl";
        case CDISASM_X86_NAME_OUTSD:
            return "outsl";
        case CDISASM_X86_NAME_LODSD:
            return "lodsl";
        case CDISASM_X86_NAME_STOSD:
            return "stosl";
        case CDISASM_X86_NAME_SCASD:
            return "scasl";
        case CDISASM_X86_NAME_MOVSD:
            return is_implicit_string_form(instruction) ? "movsl" : NULL;
        case CDISASM_X86_NAME_CMPSD:
            return is_implicit_string_form(instruction) ? "cmpsl" : NULL;
        default:
            return NULL;
    }
}

static char att_instruction_suffix(
    const cdisasm_instruction *instruction,
    cdisasm_mode mode)
{
    cdisasm_x86_name_id name_id = instruction->name_id;

    if ((name_id >= CDISASM_X86_NAME_CMOVA
            && name_id <= CDISASM_X86_NAME_CMOVS)
        || name_id == CDISASM_X86_NAME_CMOVNB
        || name_id == CDISASM_X86_NAME_CMOVNBE
        || name_id == CDISASM_X86_NAME_CMOVNL
        || name_id == CDISASM_X86_NAME_CMOVNLE
        || name_id == CDISASM_X86_NAME_CMOVNZ
        || name_id == CDISASM_X86_NAME_CMOVZ) {
        return instruction->operand_count != 0
            ? att_width_suffix(instruction->opcode[0].size)
            : '\0';
    }

    switch (name_id) {
        /* The element type is part of these canonical mnemonics.  GNU/LLVM
         * AT&T syntax does not append an operand-width suffix for register,
         * full-memory, or broadcast-memory forms. */
        case CDISASM_X86_NAME_VGETEXPPH:
        case CDISASM_X86_NAME_VGETEXPSH:
        case CDISASM_X86_NAME_VGETEXPBF16:
            return '\0';
        case CDISASM_X86_NAME_VGETEXPPS:
        case CDISASM_X86_NAME_VGETEXPPD:
        case CDISASM_X86_NAME_VGETEXPSS:
        case CDISASM_X86_NAME_VGETEXPSD:
            if (instruction->operand_count != 0) {
                const cdisasm_opcode *source =
                    &instruction->opcode[instruction->operand_count - 1u];

                if (source->type == CDISASM_OPERAND_MEMORY) {
                    if ((name_id == CDISASM_X86_NAME_VGETEXPPS
                            || name_id == CDISASM_X86_NAME_VGETEXPPD)
                        && source->broadcast
                            == CDISASM_X86_BROADCAST_NONE) {
                        return att_vector_width_suffix(
                            instruction->opcode[0].size);
                    }
                    return name_id == CDISASM_X86_NAME_VGETEXPPS
                            || name_id == CDISASM_X86_NAME_VGETEXPSS
                        ? 'l' : 'q';
                }
            }
            return '\0';
        case CDISASM_X86_NAME_PTWRITE:
            return instruction->operand_count == 1
                    && instruction->opcode[0].type
                        == CDISASM_OPERAND_MEMORY
                ? att_width_suffix(instruction->opcode[0].size)
                : '\0';
        case CDISASM_X86_NAME_VP4DPWSSD:
        case CDISASM_X86_NAME_VP4DPWSSDS:
        case CDISASM_X86_NAME_V4FMADDPS:
        case CDISASM_X86_NAME_V4FMADDSS:
        case CDISASM_X86_NAME_V4FNMADDPS:
        case CDISASM_X86_NAME_V4FNMADDSS:
            return 'x';
        case CDISASM_X86_NAME_FADD:
        case CDISASM_X86_NAME_FCOM:
        case CDISASM_X86_NAME_FCOMP:
        case CDISASM_X86_NAME_FDIV:
        case CDISASM_X86_NAME_FDIVR:
        case CDISASM_X86_NAME_FLD:
        case CDISASM_X86_NAME_FMUL:
        case CDISASM_X86_NAME_FST:
        case CDISASM_X86_NAME_FSTP:
        case CDISASM_X86_NAME_FSUB:
        case CDISASM_X86_NAME_FSUBR:
            if (instruction->operand_count == 1
                && instruction->opcode[0].type == CDISASM_OPERAND_MEMORY) {
                switch (instruction->opcode[0].size) {
                    case 4:
                        return 's';
                    case 8:
                        return 'l';
                    case 10:
                        return 't';
                    default:
                        return '\0';
                }
            }
            return '\0';

        case CDISASM_X86_NAME_FIADD:
        case CDISASM_X86_NAME_FICOM:
        case CDISASM_X86_NAME_FICOMP:
        case CDISASM_X86_NAME_FIDIV:
        case CDISASM_X86_NAME_FIDIVR:
        case CDISASM_X86_NAME_FILD:
        case CDISASM_X86_NAME_FIMUL:
        case CDISASM_X86_NAME_FIST:
        case CDISASM_X86_NAME_FISTP:
        case CDISASM_X86_NAME_FISTTP:
        case CDISASM_X86_NAME_FISUB:
        case CDISASM_X86_NAME_FISUBR:
            if (instruction->operand_count == 1
                && instruction->opcode[0].type == CDISASM_OPERAND_MEMORY) {
                if (instruction->opcode[0].size == 2) {
                    return 's';
                }
                if (instruction->opcode[0].size == 4) {
                    return 'l';
                }
            }
            return '\0';

        case CDISASM_X86_NAME_CALL:
        case CDISASM_X86_NAME_JMP:
            if (instruction->operand_count == 1
                && instruction->opcode[0].type
                    != CDISASM_OPERAND_IMMEDIATE) {
                return att_width_suffix(instruction->opcode[0].size);
            }
            if (mode == 0) {
                return '\0';
            }
            if (name_id == CDISASM_X86_NAME_JMP
                && instruction->encoding.immediate_count != 0
                && instruction->encoding.immediate_size[0] == 1) {
                return att_default_mode_width_suffix(mode);
            }
            return att_mode_width_suffix(instruction, mode, 0);
        case CDISASM_X86_NAME_PUSH:
            if (instruction->operand_count != 1
                || (instruction->opcode[0].type
                        == CDISASM_OPERAND_REGISTER
                    && is_unsized_mov_register(
                        instruction->opcode[0].reg))) {
                return '\0';
            }
            if (instruction->opcode[0].type == CDISASM_OPERAND_IMMEDIATE) {
                return mode != 0
                    ? att_mode_width_suffix(instruction, mode, 1)
                    : '\0';
            }
            return att_width_suffix(instruction->opcode[0].size);
        case CDISASM_X86_NAME_POP:
            if (instruction->operand_count != 1
                || (instruction->opcode[0].type
                        == CDISASM_OPERAND_REGISTER
                    && is_unsized_mov_register(
                        instruction->opcode[0].reg))) {
                return '\0';
            }
            return att_width_suffix(instruction->opcode[0].size);
        case CDISASM_X86_NAME_IN:
            return instruction->operand_count != 0
                ? att_width_suffix(instruction->opcode[0].size)
                : '\0';
        case CDISASM_X86_NAME_OUT:
            return instruction->operand_count != 0
                ? att_width_suffix(
                    instruction->opcode[instruction->operand_count - 1].size)
                : '\0';
        case CDISASM_X86_NAME_RET:
            return mode != 0
                ? att_mode_width_suffix(instruction, mode, 0)
                : '\0';
        case CDISASM_X86_NAME_RETF:
            return mode != 0
                ? att_far_return_width_suffix(instruction, mode)
                : '\0';
        case CDISASM_X86_NAME_CRC32:
        case CDISASM_X86_NAME_CVTSI2SS:
        case CDISASM_X86_NAME_CVTSI2SD:
            return instruction->operand_count > 1
                ? att_width_suffix(instruction->opcode[1].size)
                : '\0';
        case CDISASM_X86_NAME_MOV:
            if (mov_has_unsized_register(instruction)) {
                return '\0';
            }
            break;
        case CDISASM_X86_NAME_ADC:
        case CDISASM_X86_NAME_ADD:
        case CDISASM_X86_NAME_AND:
        case CDISASM_X86_NAME_BSF:
        case CDISASM_X86_NAME_BSR:
        case CDISASM_X86_NAME_BSWAP:
        case CDISASM_X86_NAME_BT:
        case CDISASM_X86_NAME_BTC:
        case CDISASM_X86_NAME_BTR:
        case CDISASM_X86_NAME_BTS:
        case CDISASM_X86_NAME_CMP:
        case CDISASM_X86_NAME_CMPXCHG:
        case CDISASM_X86_NAME_DEC:
        case CDISASM_X86_NAME_DIV:
        case CDISASM_X86_NAME_IDIV:
        case CDISASM_X86_NAME_IMUL:
        case CDISASM_X86_NAME_INC:
        case CDISASM_X86_NAME_LAR:
        case CDISASM_X86_NAME_LEA:
        case CDISASM_X86_NAME_LFS:
        case CDISASM_X86_NAME_LGS:
        case CDISASM_X86_NAME_LSL:
        case CDISASM_X86_NAME_LSS:
        case CDISASM_X86_NAME_LZCNT:
        case CDISASM_X86_NAME_MOVABS:
        case CDISASM_X86_NAME_MUL:
        case CDISASM_X86_NAME_NEG:
        case CDISASM_X86_NAME_NOP:
        case CDISASM_X86_NAME_NOT:
        case CDISASM_X86_NAME_OR:
        case CDISASM_X86_NAME_POPCNT:
        case CDISASM_X86_NAME_RCL:
        case CDISASM_X86_NAME_RCR:
        case CDISASM_X86_NAME_RDRAND:
        case CDISASM_X86_NAME_RDSEED:
        case CDISASM_X86_NAME_ROL:
        case CDISASM_X86_NAME_ROR:
        case CDISASM_X86_NAME_SAR:
        case CDISASM_X86_NAME_SBB:
        case CDISASM_X86_NAME_SHL:
        case CDISASM_X86_NAME_SHLD:
        case CDISASM_X86_NAME_SHR:
        case CDISASM_X86_NAME_SHRD:
        case CDISASM_X86_NAME_SUB:
        case CDISASM_X86_NAME_TEST:
        case CDISASM_X86_NAME_TZCNT:
        case CDISASM_X86_NAME_XADD:
        case CDISASM_X86_NAME_XCHG:
        case CDISASM_X86_NAME_XOR:
            break;
        default:
            return '\0';
    }

    return instruction->operand_count != 0
        ? att_width_suffix(instruction->opcode[0].size)
        : '\0';
}

static void format_att_mnemonic(
    text_writer *writer,
    const cdisasm_instruction *instruction,
    uint32_t flags,
    cdisasm_mode mode)
{
    const char *alias;
    char source_suffix;
    char destination_suffix;
    char suffix;

    if ((instruction->name_id == CDISASM_X86_NAME_MOVSX
            || instruction->name_id == CDISASM_X86_NAME_MOVZX)
        && instruction->operand_count > 1) {
        source_suffix = att_width_suffix(instruction->opcode[1].size);
        destination_suffix = att_width_suffix(instruction->opcode[0].size);
        if (source_suffix != '\0' && destination_suffix != '\0') {
            writer_puts_opcode(
                writer,
                instruction->name_id == CDISASM_X86_NAME_MOVSX
                    ? "movs"
                    : "movz",
                flags);
            writer_putc_opcode(writer, source_suffix, flags);
            writer_putc_opcode(writer, destination_suffix, flags);
            return;
        }
    }
    if (instruction->name_id == CDISASM_X86_NAME_MOVSXD
        && instruction->operand_count > 1
        && instruction->opcode[1].size == 4
        && instruction->opcode[0].size == 8) {
        writer_puts_opcode(writer, "movslq", flags);
        return;
    }

    alias = att_mnemonic_alias(instruction);
    writer_puts_opcode(
        writer,
        alias != NULL ? alias : mnemonic_name(instruction->name_id),
        flags);
    if (alias == NULL || instruction->name_id == CDISASM_X86_NAME_RETF) {
        suffix = att_instruction_suffix(instruction, mode);
        if (suffix != '\0') {
            writer_putc_opcode(writer, suffix, flags);
        }
    }
}

static int valid_immediate(const cdisasm_opcode *operand)
{
    const uint8_t allowed_flags = CDISASM_OPERAND_FLAG_SIGNED
        | CDISASM_OPERAND_FLAG_IMPLICIT
        | CDISASM_OPERAND_FLAG_PC_RELATIVE
        | CDISASM_OPERAND_FLAG_HAS_ADDRESS;

    if (operand->reg != CDISASM_X86_REG_NONE
        || operand->base_reg != CDISASM_X86_REG_NONE
        || operand->index_reg != CDISASM_X86_REG_NONE
        || operand->scale != 0
        || operand->segment_reg != CDISASM_X86_REG_NONE
        || operand->broadcast != CDISASM_X86_BROADCAST_NONE
        || (operand->flags & (uint8_t)~allowed_flags) != 0) {
        return 0;
    }

    if (operand->size == 0) {
        if (operand->flags != CDISASM_OPERAND_FLAG_IMPLICIT
            || operand->address != 0
            || operand->imm != 1) {
            return 0;
        }
    } else if (operand->size != 1 && operand->size != 2
        && operand->size != 4 && operand->size != 8) {
        return 0;
    }
    if (operand->size != 0
        && (operand->flags & CDISASM_OPERAND_FLAG_IMPLICIT) != 0) {
        return 0;
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0
        && (operand->flags
            & (CDISASM_OPERAND_FLAG_SIGNED
                | CDISASM_OPERAND_FLAG_HAS_ADDRESS))
            != (CDISASM_OPERAND_FLAG_SIGNED
                | CDISASM_OPERAND_FLAG_HAS_ADDRESS)) {
        return 0;
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) == 0
        && ((operand->flags & CDISASM_OPERAND_FLAG_HAS_ADDRESS) != 0
            || operand->address != 0)) {
        return 0;
    }
    return 1;
}

static int is_vsib_instruction(cdisasm_x86_name_id name_id)
{
    switch (name_id) {
        case CDISASM_X86_NAME_VGATHERDPD:
        case CDISASM_X86_NAME_VGATHERDPS:
        case CDISASM_X86_NAME_VGATHERPF0DPD:
        case CDISASM_X86_NAME_VGATHERPF0DPS:
        case CDISASM_X86_NAME_VGATHERPF0QPD:
        case CDISASM_X86_NAME_VGATHERPF0QPS:
        case CDISASM_X86_NAME_VGATHERPF1DPD:
        case CDISASM_X86_NAME_VGATHERPF1DPS:
        case CDISASM_X86_NAME_VGATHERPF1QPD:
        case CDISASM_X86_NAME_VGATHERPF1QPS:
        case CDISASM_X86_NAME_VGATHERQPD:
        case CDISASM_X86_NAME_VGATHERQPS:
        case CDISASM_X86_NAME_VPGATHERDD:
        case CDISASM_X86_NAME_VPGATHERDQ:
        case CDISASM_X86_NAME_VPGATHERQD:
        case CDISASM_X86_NAME_VPGATHERQQ:
        case CDISASM_X86_NAME_VPSCATTERDD:
        case CDISASM_X86_NAME_VPSCATTERDQ:
        case CDISASM_X86_NAME_VPSCATTERQD:
        case CDISASM_X86_NAME_VPSCATTERQQ:
        case CDISASM_X86_NAME_VSCATTERDPD:
        case CDISASM_X86_NAME_VSCATTERDPS:
        case CDISASM_X86_NAME_VSCATTERPF0DPD:
        case CDISASM_X86_NAME_VSCATTERPF0DPS:
        case CDISASM_X86_NAME_VSCATTERPF0QPD:
        case CDISASM_X86_NAME_VSCATTERPF0QPS:
        case CDISASM_X86_NAME_VSCATTERPF1DPD:
        case CDISASM_X86_NAME_VSCATTERPF1DPS:
        case CDISASM_X86_NAME_VSCATTERPF1QPD:
        case CDISASM_X86_NAME_VSCATTERPF1QPS:
        case CDISASM_X86_NAME_VSCATTERQPD:
        case CDISASM_X86_NAME_VSCATTERQPS:
            return 1;
        default:
            return 0;
    }
}

static int valid_memory(
    const cdisasm_instruction *instruction,
    const cdisasm_opcode *operand)
{
    const uint8_t allowed_flags = CDISASM_OPERAND_FLAG_IMPLICIT
        | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
        | CDISASM_OPERAND_FLAG_ABSOLUTE
        | CDISASM_OPERAND_FLAG_PC_RELATIVE
        | CDISASM_OPERAND_FLAG_HAS_ADDRESS
        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
        | CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT;
    int has_base = operand->base_reg != CDISASM_X86_REG_NONE;
    int has_index = operand->index_reg != CDISASM_X86_REG_NONE;
    int is_absolute = (operand->flags & CDISASM_OPERAND_FLAG_ABSOLUTE) != 0;
    int is_pc_relative =
        (operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0;

    if (operand->reg != CDISASM_X86_REG_NONE
        || (operand->flags & (uint8_t)~allowed_flags) != 0
        || operand->size == 0
        || !valid_broadcast(operand->broadcast)) {
        return 0;
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_ADDRESS_ONLY) == 0
        && pointer_size_name(operand->size) == NULL) {
        return 0;
    }
    if (has_base && !valid_address_register(operand->base_reg)) {
        return 0;
    }
    if (has_index
        && !valid_address_register(operand->index_reg)
        && !(is_vsib_instruction(instruction->name_id)
            && ((operand->index_reg >= CDISASM_X86_REG_XMM0
                    && operand->index_reg <= CDISASM_X86_REG_XMM31)
                || (operand->index_reg >= CDISASM_X86_REG_YMM0
                    && operand->index_reg <= CDISASM_X86_REG_YMM31)
                || (operand->index_reg >= CDISASM_X86_REG_ZMM0
                    && operand->index_reg <= CDISASM_X86_REG_ZMM31)))) {
        return 0;
    }
    if ((!has_index && operand->scale != 0)
        || (has_index && operand->scale != 1 && operand->scale != 2
            && operand->scale != 4 && operand->scale != 8)) {
        return 0;
    }
    if (operand->segment_reg != CDISASM_X86_REG_NONE
        && !valid_segment_register(operand->segment_reg)) {
        return 0;
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0
        && operand->segment_reg == CDISASM_X86_REG_NONE) {
        return 0;
    }
    if (is_absolute
        && ((operand->flags & CDISASM_OPERAND_FLAG_HAS_ADDRESS) == 0
            || has_base || has_index || is_pc_relative)) {
        return 0;
    }
    if (is_pc_relative
        && ((operand->flags
                & (CDISASM_OPERAND_FLAG_HAS_ADDRESS
                    | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT))
                != (CDISASM_OPERAND_FLAG_HAS_ADDRESS
                    | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT)
            || (operand->base_reg != CDISASM_X86_REG_EIP
                && operand->base_reg != CDISASM_X86_REG_RIP)
            || has_index)) {
        return 0;
    }
    if (!is_pc_relative
        && (operand->base_reg == CDISASM_X86_REG_EIP
            || operand->base_reg == CDISASM_X86_REG_RIP)) {
        return 0;
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_HAS_ADDRESS) != 0
        && !is_absolute && !is_pc_relative) {
        return 0;
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_HAS_ADDRESS) == 0
        && operand->address != 0) {
        return 0;
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) == 0
        && operand->imm != 0) {
        return 0;
    }
    if (!has_base && !has_index && !is_absolute
        && (operand->flags & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) == 0) {
        return 0;
    }
    return 1;
}

static int valid_operand(
    const cdisasm_instruction *instruction,
    const cdisasm_opcode *operand)
{
    if (!valid_access(operand->access)
        || operand->reserved[0] != 0
        || operand->reserved[1] != 0) {
        return 0;
    }

    switch (operand->type) {
        case CDISASM_OPERAND_REGISTER:
            return (operand->size != 0
                    && (operand->size != UINT8_MAX
                        || (operand->reg >= CDISASM_X86_REG_TMM0
                            && operand->reg <= CDISASM_X86_REG_TMM7)))
                && valid_register(operand->reg)
                && operand->base_reg == CDISASM_X86_REG_NONE
                && operand->index_reg == CDISASM_X86_REG_NONE
                && operand->scale == 0
                && operand->segment_reg == CDISASM_X86_REG_NONE
                && operand->broadcast == CDISASM_X86_BROADCAST_NONE
                && (operand->flags
                    & (uint8_t)~CDISASM_OPERAND_FLAG_IMPLICIT) == 0
                && operand->address == 0
                && operand->imm == 0;
        case CDISASM_OPERAND_IMMEDIATE:
            return valid_immediate(operand);
        case CDISASM_OPERAND_MEMORY:
            return valid_memory(instruction, operand);
        default:
            return 0;
    }
}

static int valid_encoding(
    const cdisasm_instruction *instruction,
    const cdisasm_x86_encoding *encoding)
{
    size_t index;
    size_t cursor;

    if (encoding->reserved != 0) {
        return 0;
    }
    if (encoding->opcode_size == 0) {
        const uint8_t *bytes = (const uint8_t *)encoding;

        for (index = 0; index < sizeof(*encoding); ++index) {
            if (bytes[index] != 0) {
                return 0;
            }
        }
        return 1;
    }
    if (encoding->opcode_size > 4
        || encoding->opcode_offset != encoding->prefix_size
        || (size_t)encoding->opcode_offset + encoding->opcode_size
            > instruction->opcode_size
        || encoding->prefix_size > instruction->opcode_size
        || encoding->immediate_count > 2) {
        return 0;
    }
    cursor = (size_t)encoding->opcode_offset + encoding->opcode_size;
    if (encoding->modrm_offset != 0) {
        if (encoding->modrm_offset != cursor) {
            return 0;
        }
        ++cursor;
    } else if (encoding->modrm != 0) {
        return 0;
    }
    if (encoding->sib_offset != 0) {
        if (encoding->modrm_offset == 0
            || encoding->sib_offset != cursor) {
            return 0;
        }
        ++cursor;
    } else if (encoding->sib != 0) {
        return 0;
    }
    if (encoding->displacement_size != 0
        && (encoding->displacement_size != 1
            && encoding->displacement_size != 2
            && encoding->displacement_size != 4
            && encoding->displacement_size != 8)) {
        return 0;
    }
    if (encoding->displacement_size != 0) {
        if (encoding->displacement_offset != cursor) {
            return 0;
        }
        cursor += encoding->displacement_size;
    } else if (encoding->displacement_offset != 0) {
        return 0;
    }
    for (index = 0; index < 2; ++index) {
        if (index >= encoding->immediate_count) {
            if (encoding->immediate_offset[index] != 0
                || encoding->immediate_size[index] != 0) {
                return 0;
            }
        } else if (encoding->immediate_offset[index] != cursor
            || (encoding->immediate_size[index] != 1
                && encoding->immediate_size[index] != 2
                && encoding->immediate_size[index] != 4
                && encoding->immediate_size[index] != 8)) {
            return 0;
        } else {
            cursor += encoding->immediate_size[index];
        }
    }
    if (encoding->selector_offset != 0) {
        if (encoding->selector_offset != cursor) {
            return 0;
        }
        ++cursor;
    }
    return cursor == instruction->opcode_size;
}

/* Validate the part of a ModRM memory encoding that the byte-layout metadata
 * can describe without retaining the complete instruction bytes.  The
 * decoded address registers identify the effective 16-/32-/64-bit addressing
 * form, while their low three bits must agree with the ModRM/SIB selectors.
 * A register-less absolute address is accepted only through one of the
 * architectural displacement sentinels. */
static unsigned int address_register_bits(cdisasm_x86_reg_id reg)
{
    if (reg == CDISASM_X86_REG_NONE) {
        return 0u;
    }
    if ((reg >= CDISASM_X86_REG_AX && reg <= CDISASM_X86_REG_R15W)
        || (reg >= CDISASM_X86_REG_R16W
            && reg <= CDISASM_X86_REG_R31W)
        || reg == CDISASM_X86_REG_IP) {
        return 16u;
    }
    if ((reg >= CDISASM_X86_REG_EAX && reg <= CDISASM_X86_REG_R15D)
        || (reg >= CDISASM_X86_REG_R16D
            && reg <= CDISASM_X86_REG_R31D)
        || reg == CDISASM_X86_REG_EIP) {
        return 32u;
    }
    if ((reg >= CDISASM_X86_REG_RAX && reg <= CDISASM_X86_REG_R15)
        || (reg >= CDISASM_X86_REG_R16
            && reg <= CDISASM_X86_REG_R31)
        || reg == CDISASM_X86_REG_RIP) {
        return 64u;
    }
    return 1u;
}

static int address_register_low3(
    cdisasm_x86_reg_id reg,
    unsigned int bits,
    uint8_t *low3)
{
    unsigned int number;

    if (bits == 16u
        && reg >= CDISASM_X86_REG_AX && reg <= CDISASM_X86_REG_R15W) {
        number = (unsigned int)(reg - CDISASM_X86_REG_AX);
    } else if (bits == 16u
        && reg >= CDISASM_X86_REG_R16W
        && reg <= CDISASM_X86_REG_R31W) {
        number = 16u + (unsigned int)(reg - CDISASM_X86_REG_R16W);
    } else if (bits == 32u
        && reg >= CDISASM_X86_REG_EAX && reg <= CDISASM_X86_REG_R15D) {
        number = (unsigned int)(reg - CDISASM_X86_REG_EAX);
    } else if (bits == 32u
        && reg >= CDISASM_X86_REG_R16D
        && reg <= CDISASM_X86_REG_R31D) {
        number = 16u + (unsigned int)(reg - CDISASM_X86_REG_R16D);
    } else if (bits == 64u
        && reg >= CDISASM_X86_REG_RAX && reg <= CDISASM_X86_REG_R15) {
        number = (unsigned int)(reg - CDISASM_X86_REG_RAX);
    } else if (bits == 64u
        && reg >= CDISASM_X86_REG_R16
        && reg <= CDISASM_X86_REG_R31) {
        number = 16u + (unsigned int)(reg - CDISASM_X86_REG_R16);
    } else {
        return 0;
    }
    *low3 = (uint8_t)(number & 7u);
    return 1;
}

static int valid_modrm16_memory_encoding(
    const cdisasm_x86_encoding *encoding,
    const cdisasm_opcode *operand)
{
    static const cdisasm_x86_reg_id bases[8] = {
        CDISASM_X86_REG_BX, CDISASM_X86_REG_BX,
        CDISASM_X86_REG_BP, CDISASM_X86_REG_BP,
        CDISASM_X86_REG_SI, CDISASM_X86_REG_DI,
        CDISASM_X86_REG_BP, CDISASM_X86_REG_BX};
    static const cdisasm_x86_reg_id indexes[8] = {
        CDISASM_X86_REG_SI, CDISASM_X86_REG_DI,
        CDISASM_X86_REG_SI, CDISASM_X86_REG_DI,
        CDISASM_X86_REG_NONE, CDISASM_X86_REG_NONE,
        CDISASM_X86_REG_NONE, CDISASM_X86_REG_NONE};
    const uint8_t mod = (uint8_t)(encoding->modrm >> 6);
    const uint8_t rm = (uint8_t)(encoding->modrm & UINT8_C(7));
    const int absolute = mod == 0u && rm == 6u;
    const unsigned int displacement_size = mod == 1u ? 1u
        : mod == 2u || absolute ? 2u : 0u;

    if (mod == 3u || encoding->sib_offset != 0u
        || encoding->displacement_size != displacement_size
        || (((operand->flags & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) != 0u)
            != (displacement_size != 0u))
        || (((operand->flags & CDISASM_OPERAND_FLAG_ABSOLUTE) != 0u)
            != absolute)
        || (operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0u) {
        return 0;
    }
    if (absolute) {
        return operand->base_reg == CDISASM_X86_REG_NONE
            && operand->index_reg == CDISASM_X86_REG_NONE
            && operand->scale == 0u;
    }
    return operand->base_reg == bases[rm]
        && operand->index_reg == indexes[rm]
        && operand->scale == (indexes[rm] == CDISASM_X86_REG_NONE ? 0u : 1u);
}

static int valid_modrm3264_memory_encoding(
    const cdisasm_x86_encoding *encoding,
    const cdisasm_opcode *operand,
    unsigned int address_bits)
{
    const uint8_t mod = (uint8_t)(encoding->modrm >> 6);
    const uint8_t rm = (uint8_t)(encoding->modrm & UINT8_C(7));
    const int has_sib = encoding->sib_offset != 0u;
    const uint8_t sib_base = (uint8_t)(encoding->sib & UINT8_C(7));
    const uint8_t sib_index =
        (uint8_t)((encoding->sib >> 3) & UINT8_C(7));
    const int special_base = mod == 0u
        && ((!has_sib && rm == 5u) || (has_sib && sib_base == 5u));
    const unsigned int displacement_size = mod == 1u ? 1u
        : mod == 2u || special_base ? 4u : 0u;
    const int pc_relative = !has_sib && special_base
        && (operand->base_reg == CDISASM_X86_REG_EIP
            || operand->base_reg == CDISASM_X86_REG_RIP);
    const int absolute = special_base && !pc_relative
        && operand->base_reg == CDISASM_X86_REG_NONE
        && operand->index_reg == CDISASM_X86_REG_NONE;
    uint8_t register_low3;

    if (mod == 3u || has_sib != (rm == 4u)
        || encoding->displacement_size != displacement_size
        || (((operand->flags & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) != 0u)
            != (displacement_size != 0u))
        || (((operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0u)
            != pc_relative)
        || (((operand->flags & CDISASM_OPERAND_FLAG_ABSOLUTE) != 0u)
            != absolute)) {
        return 0;
    }

    if (!has_sib) {
        if (operand->index_reg != CDISASM_X86_REG_NONE
            || operand->scale != 0u) {
            return 0;
        }
        if (special_base) {
            return pc_relative || absolute;
        }
        return address_register_low3(
                operand->base_reg, address_bits, &register_low3)
            && register_low3 == rm;
    }

    if (operand->index_reg == CDISASM_X86_REG_NONE) {
        if (sib_index != 4u || operand->scale != 0u) {
            return 0;
        }
    } else if (!address_register_low3(
            operand->index_reg, address_bits, &register_low3)
        || register_low3 != sib_index
        || operand->scale != (uint8_t)(1u << (encoding->sib >> 6))) {
        return 0;
    }

    if (special_base) {
        return operand->base_reg == CDISASM_X86_REG_NONE;
    }
    return address_register_low3(
            operand->base_reg, address_bits, &register_low3)
        && register_low3 == sib_base;
}

static int valid_modrm_memory_encoding(
    const cdisasm_instruction *instruction,
    const cdisasm_opcode *operand,
    int allow_egpr)
{
    const unsigned int base_bits = address_register_bits(operand->base_reg);
    const unsigned int index_bits = address_register_bits(operand->index_reg);
    const unsigned int address_bits = base_bits != 0u ? base_bits : index_bits;
    const int egpr_base =
        (operand->base_reg >= CDISASM_X86_REG_R16W
            && operand->base_reg <= CDISASM_X86_REG_R31W)
        || (operand->base_reg >= CDISASM_X86_REG_R16D
            && operand->base_reg <= CDISASM_X86_REG_R31D)
        || (operand->base_reg >= CDISASM_X86_REG_R16
            && operand->base_reg <= CDISASM_X86_REG_R31);
    const int egpr_index =
        (operand->index_reg >= CDISASM_X86_REG_R16W
            && operand->index_reg <= CDISASM_X86_REG_R31W)
        || (operand->index_reg >= CDISASM_X86_REG_R16D
            && operand->index_reg <= CDISASM_X86_REG_R31D)
        || (operand->index_reg >= CDISASM_X86_REG_R16
            && operand->index_reg <= CDISASM_X86_REG_R31);

    if ((base_bits == 1u || index_bits == 1u)
        || (base_bits != 0u && index_bits != 0u && base_bits != index_bits)
        || (!allow_egpr && (egpr_base || egpr_index))) {
        return 0;
    }
    if (address_bits == 16u) {
        return valid_modrm16_memory_encoding(&instruction->encoding, operand);
    }
    if (address_bits == 32u || address_bits == 64u) {
        return valid_modrm3264_memory_encoding(
            &instruction->encoding, operand, address_bits);
    }
    return valid_modrm16_memory_encoding(&instruction->encoding, operand)
        || valid_modrm3264_memory_encoding(
            &instruction->encoding, operand, 32u);
}

static int valid_generated_evex_width_groups(
    const cdisasm_instruction *instruction,
    cdisasm_x86_group_id width_group,
    int *allow_egpr)
{
    *allow_egpr = 0;
    if (instruction->x86_group_count == 1u
        && instruction->x86_group_ids[0] == width_group) {
        return 1;
    }
    if (instruction->x86_group_count == 2u
        && instruction->x86_group_ids[0] == CDISASM_X86_GROUP_APX_F
        && instruction->x86_group_ids[1] == width_group) {
        *allow_egpr = 1;
        return 1;
    }
    return 0;
}

static int register_low3_matches(
    cdisasm_x86_reg_id reg,
    cdisasm_x86_reg_id base,
    uint8_t selector)
{
    return ((unsigned int)(reg - base) & 7u) == selector;
}

static int valid_decorators(const cdisasm_instruction *instruction)
{
    if (instruction->default_flags > (CDISASM_X86_DEFAULT_FLAG_CF
            | CDISASM_X86_DEFAULT_FLAG_ZF
            | CDISASM_X86_DEFAULT_FLAG_SF
            | CDISASM_X86_DEFAULT_FLAG_OF)
        || instruction->mask_mode > CDISASM_X86_MASK_ZERO
        || instruction->rounding > CDISASM_X86_ROUNDING_RZ
        || instruction->sae > CDISASM_X86_SAE_ENABLED) {
        return 0;
    }
    if ((instruction->mask_mode == CDISASM_X86_MASK_NONE)
        != (instruction->mask_reg == CDISASM_X86_REG_NONE)) {
        return 0;
    }
    if (instruction->mask_mode != CDISASM_X86_MASK_NONE
        && (instruction->mask_reg < CDISASM_X86_REG_K1
            || instruction->mask_reg > CDISASM_X86_REG_K7)) {
        return 0;
    }
    if (instruction->mask_mode != CDISASM_X86_MASK_NONE
        && (instruction->operand_count == 0
            || (instruction->opcode[0].type != CDISASM_OPERAND_REGISTER
                && instruction->opcode[0].type != CDISASM_OPERAND_MEMORY))) {
        return 0;
    }
    if (instruction->mask_mode == CDISASM_X86_MASK_ZERO
        && (instruction->operand_count == 0
            || instruction->opcode[0].type != CDISASM_OPERAND_REGISTER)) {
        return 0;
    }
    if (instruction->rounding != CDISASM_X86_ROUNDING_NONE
        && instruction->sae != CDISASM_X86_SAE_ENABLED) {
        return 0;
    }
    if (instruction->sae == CDISASM_X86_SAE_ENABLED
        && instruction->operand_count == 0) {
        return 0;
    }
    return valid_encoding(instruction, &instruction->encoding);
}

static int valid_x86_groups(const cdisasm_instruction *instruction)
{
    cdisasm_x86_group_id previous = CDISASM_X86_GROUP_NONE;
    size_t index;

    if (instruction->x86_group_reserved != 0
        || instruction->x86_group_count == 0
        || instruction->x86_group_count > CDISASM_MAX_X86_GROUPS) {
        return 0;
    }
    for (index = 0; index < instruction->x86_group_count; ++index) {
        cdisasm_x86_group_id group_id = instruction->x86_group_ids[index];

        if (group_id < CDISASM_X86_GROUP_FIRST
            || group_id > CDISASM_X86_GROUP_LAST
            || group_id <= previous) {
            return 0;
        }
        previous = group_id;
    }
    for (; index < CDISASM_MAX_X86_GROUPS; ++index) {
        if (instruction->x86_group_ids[index] != CDISASM_X86_GROUP_NONE) {
            return 0;
        }
    }
    return 1;
}

static int is_multidest2_instruction(cdisasm_x86_name_id name_id);

static int valid_multidest2_schema(
    const cdisasm_instruction *instruction)
{
    cdisasm_x86_form_id base;
    unsigned int relative;
    unsigned int vector_size;
    unsigned int element_size;
    unsigned int element_count;
    unsigned int mask_size;
    int memory_form;

    if (!is_multidest2_instruction(instruction->name_id)) {
        return 1;
    }
    base = instruction->name_id == CDISASM_X86_NAME_VP2INTERSECTD
        ? UINT16_C(6074) : UINT16_C(6080);
    if (instruction->form_id < base
        || instruction->form_id > base + UINT16_C(5)
        || instruction->operand_count != 4u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE) {
        return 0;
    }
    relative = instruction->form_id - base;
    vector_size = 16u << (relative / 2u);
    element_size = instruction->name_id
            == CDISASM_X86_NAME_VP2INTERSECTD
        ? 4u : 8u;
    element_count = vector_size / element_size;
    mask_size = (element_count + 7u) / 8u;
    memory_form = (relative & 1u) == 0u;

    if (instruction->opcode[0].type != CDISASM_OPERAND_REGISTER
        || instruction->opcode[0].reg < CDISASM_X86_REG_K0
        || instruction->opcode[0].reg > CDISASM_X86_REG_K6
        || ((instruction->opcode[0].reg - CDISASM_X86_REG_K0) & 1u) != 0u
        || instruction->opcode[0].size != mask_size
        || instruction->opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
        || instruction->opcode[0].flags != 0u
        || instruction->opcode[1].type != CDISASM_OPERAND_REGISTER
        || instruction->opcode[1].reg != instruction->opcode[0].reg + 1u
        || instruction->opcode[1].size != mask_size
        || instruction->opcode[1].access != CDISASM_OPERAND_ACCESS_WRITE
        || instruction->opcode[1].flags
            != CDISASM_OPERAND_FLAG_IMPLICIT
        || instruction->opcode[2].type != CDISASM_OPERAND_REGISTER
        || instruction->opcode[2].size != vector_size
        || instruction->opcode[2].access != CDISASM_OPERAND_ACCESS_READ
        || instruction->opcode[2].flags != 0u
        || instruction->opcode[3].access != CDISASM_OPERAND_ACCESS_READ
        || (memory_form
            && instruction->opcode[3].type != CDISASM_OPERAND_MEMORY)
        || (!memory_form
            && instruction->opcode[3].type != CDISASM_OPERAND_REGISTER)) {
        return 0;
    }
    if (!memory_form) {
        return instruction->opcode[3].size == vector_size
            && instruction->opcode[3].broadcast
                == CDISASM_X86_BROADCAST_NONE
            && instruction->opcode[3].flags == 0u;
    }
    if (instruction->opcode[3].broadcast == CDISASM_X86_BROADCAST_NONE) {
        return instruction->opcode[3].size == vector_size;
    }
    return instruction->opcode[3].size == element_size
        && instruction->opcode[3].broadcast
            == (cdisasm_x86_broadcast)element_count;
}

static int is_vpabs_instruction(cdisasm_x86_name_id name_id)
{
    return name_id == CDISASM_X86_NAME_VPABSB
        || name_id == CDISASM_X86_NAME_VPABSD
        || name_id == CDISASM_X86_NAME_VPABSQ
        || name_id == CDISASM_X86_NAME_VPABSW;
}

static int valid_vpabs_schema(const cdisasm_instruction *instruction)
{
    cdisasm_x86_form_id base;
    unsigned int relative;
    unsigned int vector_size;
    unsigned int element_size;
    cdisasm_x86_reg_id register_base;
    uint32_t modern_prefix;
    int evex;
    int memory_form;

    if (!is_vpabs_instruction(instruction->name_id)) {
        return 1;
    }
    if (instruction->name_id == CDISASM_X86_NAME_VPABSB) {
        base = UINT16_C(6088);
        element_size = 1u;
    } else if (instruction->name_id == CDISASM_X86_NAME_VPABSD) {
        base = UINT16_C(6098);
        element_size = 4u;
    } else if (instruction->name_id == CDISASM_X86_NAME_VPABSQ) {
        base = UINT16_C(6108);
        element_size = 8u;
    } else {
        base = UINT16_C(6114);
        element_size = 2u;
    }
    if (instruction->form_id < base) {
        return 0;
    }
    relative = instruction->form_id - base;
    if (instruction->name_id == CDISASM_X86_NAME_VPABSQ) {
        if (relative > 5u) {
            return 0;
        }
        evex = 1;
        vector_size = 16u << (relative / 2u);
    } else {
        if (relative > 9u) {
            return 0;
        }
        evex = relative >= 2u && relative <= 5u;
        evex |= relative >= 8u;
        vector_size = relative <= 1u ? 16u
            : relative <= 5u ? 16u << ((relative - 2u) / 2u)
            : relative <= 7u ? 32u : 64u;
    }
    memory_form = (relative & 1u) == 0u;
    modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX);
    if (instruction->operand_count != 2u
        || modern_prefix != (evex ? CDISASM_PREFIX_EVEX
                                  : CDISASM_PREFIX_VEX)
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || (!evex && (instruction->mask_mode != CDISASM_X86_MASK_NONE
                || instruction->mask_reg != CDISASM_X86_REG_NONE))) {
        return 0;
    }

    register_base = vector_size == 16u ? CDISASM_X86_REG_XMM0
        : vector_size == 32u ? CDISASM_X86_REG_YMM0
                             : CDISASM_X86_REG_ZMM0;
    if (instruction->opcode[0].type != CDISASM_OPERAND_REGISTER
        || instruction->opcode[0].reg < register_base
        || instruction->opcode[0].reg
            > register_base + (evex ? 31u : 15u)
        || instruction->opcode[0].size != vector_size
        || instruction->opcode[0].access
            != (instruction->mask_mode == CDISASM_X86_MASK_MERGE
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE)
        || instruction->opcode[0].flags != 0u
        || instruction->opcode[0].broadcast
            != CDISASM_X86_BROADCAST_NONE
        || instruction->opcode[1].type != (memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
        || instruction->opcode[1].access != CDISASM_OPERAND_ACCESS_READ) {
        return 0;
    }
    if (!memory_form) {
        return instruction->opcode[1].reg >= register_base
            && instruction->opcode[1].reg
                <= register_base + (evex ? 31u : 15u)
            && instruction->opcode[1].size == vector_size
            && instruction->opcode[1].flags == 0u
            && instruction->opcode[1].broadcast
                == CDISASM_X86_BROADCAST_NONE;
    }
    if ((instruction->opcode[1].flags
            & CDISASM_OPERAND_FLAG_IMPLICIT) != 0u) {
        return 0;
    }
    if (instruction->opcode[1].broadcast
        == CDISASM_X86_BROADCAST_NONE) {
        return instruction->opcode[1].size == vector_size;
    }
    return evex && element_size >= 4u
        && instruction->opcode[1].size == element_size
        && instruction->opcode[1].broadcast
            == (cdisasm_x86_broadcast)(vector_size / element_size);
}

static int is_vpack_instruction(cdisasm_x86_name_id name_id)
{
    return name_id == CDISASM_X86_NAME_VPACKSSDW
        || name_id == CDISASM_X86_NAME_VPACKSSWB
        || name_id == CDISASM_X86_NAME_VPACKUSDW
        || name_id == CDISASM_X86_NAME_VPACKUSWB;
}

static int valid_vpack_schema(const cdisasm_instruction *instruction)
{
    cdisasm_x86_form_id base;
    unsigned int relative;
    unsigned int vector_size;
    unsigned int source_element_size;
    cdisasm_x86_reg_id register_base;
    uint32_t modern_prefix;
    int signed_family;
    int dword_source;
    int evex;
    int memory_form;

    if (!is_vpack_instruction(instruction->name_id)) {
        return 1;
    }
    if (instruction->name_id == CDISASM_X86_NAME_VPACKSSDW) {
        base = UINT16_C(6124);
    } else if (instruction->name_id == CDISASM_X86_NAME_VPACKSSWB) {
        base = UINT16_C(6134);
    } else if (instruction->name_id == CDISASM_X86_NAME_VPACKUSDW) {
        base = UINT16_C(6144);
    } else {
        base = UINT16_C(6154);
    }
    if (instruction->form_id < base
        || instruction->form_id > base + UINT16_C(9)) {
        return 0;
    }
    relative = instruction->form_id - base;
    signed_family = instruction->name_id == CDISASM_X86_NAME_VPACKSSDW
        || instruction->name_id == CDISASM_X86_NAME_VPACKSSWB;
    dword_source = instruction->name_id == CDISASM_X86_NAME_VPACKSSDW
        || instruction->name_id == CDISASM_X86_NAME_VPACKUSDW;
    memory_form = (relative & 1u) == 0u;
    evex = relative >= 2u
        && !(signed_family ? relative >= 6u && relative <= 7u
                          : relative >= 4u && relative <= 5u);
    if (relative <= 3u) {
        vector_size = 16u;
    } else if (relative <= 7u) {
        vector_size = 32u;
    } else {
        vector_size = 64u;
    }
    source_element_size = dword_source ? 4u : 2u;
    modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX);
    if (instruction->operand_count != 3u
        || modern_prefix != (evex ? CDISASM_PREFIX_EVEX
                                  : CDISASM_PREFIX_VEX)
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || (!evex && (instruction->mask_mode != CDISASM_X86_MASK_NONE
                || instruction->mask_reg != CDISASM_X86_REG_NONE))) {
        return 0;
    }

    register_base = vector_size == 16u ? CDISASM_X86_REG_XMM0
        : vector_size == 32u ? CDISASM_X86_REG_YMM0
                             : CDISASM_X86_REG_ZMM0;
    if (instruction->opcode[0].type != CDISASM_OPERAND_REGISTER
        || instruction->opcode[0].reg < register_base
        || instruction->opcode[0].reg
            > register_base + (evex ? 31u : 15u)
        || instruction->opcode[0].size != vector_size
        || instruction->opcode[0].access
            != (instruction->mask_mode == CDISASM_X86_MASK_MERGE
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE)
        || instruction->opcode[0].flags != 0u
        || instruction->opcode[0].broadcast
            != CDISASM_X86_BROADCAST_NONE
        || instruction->opcode[1].type != CDISASM_OPERAND_REGISTER
        || instruction->opcode[1].reg < register_base
        || instruction->opcode[1].reg
            > register_base + (evex ? 31u : 15u)
        || instruction->opcode[1].size != vector_size
        || instruction->opcode[1].access != CDISASM_OPERAND_ACCESS_READ
        || instruction->opcode[1].flags != 0u
        || instruction->opcode[1].broadcast
            != CDISASM_X86_BROADCAST_NONE
        || instruction->opcode[2].type != (memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
        || instruction->opcode[2].access != CDISASM_OPERAND_ACCESS_READ) {
        return 0;
    }
    if (!memory_form) {
        return instruction->opcode[2].reg >= register_base
            && instruction->opcode[2].reg
                <= register_base + (evex ? 31u : 15u)
            && instruction->opcode[2].size == vector_size
            && instruction->opcode[2].flags == 0u
            && instruction->opcode[2].broadcast
                == CDISASM_X86_BROADCAST_NONE;
    }
    if ((instruction->opcode[2].flags
            & CDISASM_OPERAND_FLAG_IMPLICIT) != 0u) {
        return 0;
    }
    if (instruction->opcode[2].broadcast
        == CDISASM_X86_BROADCAST_NONE) {
        return instruction->opcode[2].size == vector_size;
    }
    return evex && dword_source
        && instruction->opcode[2].size == source_element_size
        && instruction->opcode[2].broadcast
            == (cdisasm_x86_broadcast)(vector_size / source_element_size);
}

static int is_vpblend_instruction(cdisasm_x86_name_id name_id)
{
    return name_id == CDISASM_X86_NAME_VBLENDPD
        || name_id == CDISASM_X86_NAME_VBLENDPS
        || name_id == CDISASM_X86_NAME_VPBLENDD
        || name_id == CDISASM_X86_NAME_VPBLENDW;
}

static int valid_vpblend_groups(
    const cdisasm_instruction *instruction, int needs_avx2);

static int valid_vpblend_schema(const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int blend_name = is_vpblend_instruction(instruction->name_id);
    const int blend_form = (instruction->form_id >= UINT16_C(3527)
            && instruction->form_id <= UINT16_C(3534))
        || (instruction->form_id >= UINT16_C(6306)
            && instruction->form_id <= UINT16_C(6309))
        || (instruction->form_id >= UINT16_C(6338)
            && instruction->form_id <= UINT16_C(6341));
    cdisasm_x86_form_id base;
    cdisasm_x86_form_id relative;
    cdisasm_x86_reg_id register_base;
    unsigned int vector_size;
    int memory_form;
    int needs_avx2;
    size_t index;

    if (!blend_name && !blend_form) {
        return 1;
    }
    if (!blend_name) {
        return 0;
    }
    if (instruction->name_id == CDISASM_X86_NAME_VBLENDPD) {
        base = UINT16_C(3527);
    } else if (instruction->name_id == CDISASM_X86_NAME_VBLENDPS) {
        base = UINT16_C(3531);
    } else if (instruction->name_id == CDISASM_X86_NAME_VPBLENDD) {
        base = UINT16_C(6306);
    } else {
        base = UINT16_C(6338);
    }
    if (instruction->form_id < base
        || instruction->form_id > base + UINT16_C(3)
        || instruction->operand_count != 4u
        || (instruction->opcode_flags
                & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX))
            != CDISASM_PREFIX_VEX
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE) {
        return 0;
    }

    relative = instruction->form_id - base;
    vector_size = relative < 2u ? 16u : 32u;
    needs_avx2 = instruction->name_id == CDISASM_X86_NAME_VPBLENDD
        || (instruction->name_id == CDISASM_X86_NAME_VPBLENDW
            && vector_size == 32u);
    if ((instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || (instruction->opcode_flags & CDISASM_PREFIX_VEX) == 0u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 1u
        || instruction->encoding.immediate_size[0] != 1u
        || instruction->encoding.immediate_offset[0]
            != instruction->opcode_size - 1u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, needs_avx2)) {
        return 0;
    }
    register_base = vector_size == 16u
        ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
    memory_form = (relative & 1u) == 0u;
    for (index = 0u; index < 2u; ++index) {
        if (instruction->opcode[index].type != CDISASM_OPERAND_REGISTER
            || instruction->opcode[index].reg < register_base
            || instruction->opcode[index].reg > register_base + 15u
            || instruction->opcode[index].size != vector_size
            || instruction->opcode[index].access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || instruction->opcode[index].flags != 0u
            || instruction->opcode[index].broadcast
                != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
    }
    if (instruction->opcode[2].type != (memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
        || instruction->opcode[2].size != vector_size
        || instruction->opcode[2].access != CDISASM_OPERAND_ACCESS_READ
        || instruction->opcode[2].broadcast
            != CDISASM_X86_BROADCAST_NONE) {
        return 0;
    }
    if (memory_form) {
        if ((instruction->opcode[2].flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u) {
            return 0;
        }
    } else {
        if (instruction->opcode[2].reg < register_base
            || instruction->opcode[2].reg > register_base + 15u
            || instruction->opcode[2].flags != 0u) {
            return 0;
        }
    }
    return instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE
        && instruction->opcode[3].size == 1u
        && instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ
        && instruction->opcode[3].flags == 0u
        && instruction->opcode[3].imm <= UINT8_MAX;
}

static int valid_vdpp_schema(const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const unsigned int legacy_prefix_count =
        ((instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
        + ((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u);
    const int family_name = instruction->name_id == CDISASM_X86_NAME_VDPPD
        || instruction->name_id == CDISASM_X86_NAME_VDPPS;
    const int pd_form = instruction->form_id >= UINT16_C(4507)
        && instruction->form_id <= UINT16_C(4508);
    const int ps_form = instruction->form_id >= UINT16_C(4515)
        && instruction->form_id <= UINT16_C(4518);
    const int family_form = pd_form || ps_form;
    const int identity = (pd_form
            && instruction->name_id == CDISASM_X86_NAME_VDPPD)
        || (ps_form && instruction->name_id == CDISASM_X86_NAME_VDPPS);
    const unsigned int relative = pd_form
        ? instruction->form_id - UINT16_C(4507)
        : ps_form ? instruction->form_id - UINT16_C(4515) : 0u;
    const unsigned int vector_size = ps_form && relative >= 2u
        ? 32u : 16u;
    const cdisasm_x86_reg_id register_base = vector_size == 32u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    const int memory_form = (relative & 1u) == 0u;
    size_t index;

    if (!family_name && !family_form) {
        return 1;
    }
    if (!family_name || !family_form || !identity
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 4u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 3u + legacy_prefix_count
        || (instruction->encoding.prefix_size > 3u
            && (instruction->opcode_flags
                & (CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u)
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || instruction->encoding.immediate_count != 1u
        || instruction->encoding.immediate_size[0] != 1u
        || instruction->encoding.immediate_offset[0]
            != instruction->opcode_size - 1u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 0)) {
        return 0;
    }

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = memory_form && index == 2u;

        if (operand->type != (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != vector_size
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory) {
            const int has_segment_prefix = (instruction->opcode_flags
                & CDISASM_PREFIX_SEGMENT) != 0u;
            const int has_explicit_segment = (operand->flags
                & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0u;

            if (has_segment_prefix != has_explicit_segment
                || has_segment_prefix
                    != (operand->segment_reg != CDISASM_X86_REG_NONE)
                || (operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_modrm_memory_encoding(instruction, operand, 0)) {
                return 0;
            }
        } else if (operand->reg < register_base
            || operand->reg > register_base + 15u
            || operand->flags != 0u) {
            return 0;
        }
    }
    return register_low3_matches(instruction->opcode[0].reg,
               register_base,
               (uint8_t)((instruction->encoding.modrm >> 3)
                   & UINT8_C(7)))
        && (memory_form
            || register_low3_matches(instruction->opcode[2].reg,
                register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))))
        && instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE
        && instruction->opcode[3].size == 1u
        && instruction->opcode[3].access
            == CDISASM_OPERAND_ACCESS_READ
        && instruction->opcode[3].flags == 0u
        && instruction->opcode[3].broadcast
            == CDISASM_X86_BROADCAST_NONE
        && instruction->opcode[3].imm <= UINT8_MAX;
}

static int valid_vmxcsr_schema(const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int family_name =
        instruction->name_id == CDISASM_X86_NAME_VLDMXCSR
        || instruction->name_id == CDISASM_X86_NAME_VSTMXCSR;
    const int family_form = instruction->form_id == UINT16_C(5585)
        || instruction->form_id == UINT16_C(8752);
    const int load = instruction->form_id == UINT16_C(5585);
    const unsigned int legacy_prefix_count =
        ((instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
        + ((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u);
    const cdisasm_opcode *memory = &instruction->opcode[0];
    const int native_c5 = instruction->encoding.prefix_size
        == 2u + legacy_prefix_count;
    const int high_base =
        (memory->base_reg >= CDISASM_X86_REG_R8W
            && memory->base_reg <= CDISASM_X86_REG_R15W)
        || (memory->base_reg >= CDISASM_X86_REG_R8D
            && memory->base_reg <= CDISASM_X86_REG_R15D)
        || (memory->base_reg >= CDISASM_X86_REG_R8
            && memory->base_reg <= CDISASM_X86_REG_R15);
    const int high_index =
        (memory->index_reg >= CDISASM_X86_REG_R8W
            && memory->index_reg <= CDISASM_X86_REG_R15W)
        || (memory->index_reg >= CDISASM_X86_REG_R8D
            && memory->index_reg <= CDISASM_X86_REG_R15D)
        || (memory->index_reg >= CDISASM_X86_REG_R8
            && memory->index_reg <= CDISASM_X86_REG_R15);

    if (!family_name && !family_form) {
        return 1;
    }
    if (!family_name || !family_form
        || instruction->name_id != (load
            ? CDISASM_X86_NAME_VLDMXCSR
            : CDISASM_X86_NAME_VSTMXCSR)
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 1u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 2u + legacy_prefix_count
        || (instruction->encoding.prefix_size > 3u
            && (instruction->opcode_flags
                & (CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u)
        || (native_c5 && (high_base || high_index))
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (instruction->encoding.modrm & UINT8_C(0xc0))
            == UINT8_C(0xc0)
        || ((instruction->encoding.modrm >> 3) & UINT8_C(7))
            != (load ? UINT8_C(2) : UINT8_C(3))
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 0)
        || memory->type != CDISASM_OPERAND_MEMORY
        || memory->size != 4u
        || memory->access != (load
            ? CDISASM_OPERAND_ACCESS_READ
            : CDISASM_OPERAND_ACCESS_WRITE)
        || memory->broadcast != CDISASM_X86_BROADCAST_NONE
        || (memory->flags
            & (CDISASM_OPERAND_FLAG_IMPLICIT
                | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
        || (((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u)
            != ((memory->flags
                & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0u))
        || (((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u)
            != (memory->segment_reg != CDISASM_X86_REG_NONE))
        || !valid_modrm_memory_encoding(instruction, memory, 0)) {
        return 0;
    }
    return 1;
}

static int valid_vmaskmov_schema(const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int family_name =
        instruction->name_id == CDISASM_X86_NAME_VMASKMOVPD
        || instruction->name_id == CDISASM_X86_NAME_VMASKMOVPS;
    const int family_form = instruction->form_id >= UINT16_C(5587)
        && instruction->form_id <= UINT16_C(5594);
    int pd;
    int store;
    int ymm;
    unsigned int vector_size;
    size_t memory_index;
    size_t data_index;
    unsigned int legacy_prefix_count;
    cdisasm_x86_reg_id register_base;
    size_t index;

    /* Own both sides of the name/form relationship so a generated, legacy,
     * or forged object cannot be relabeled into this exact classic-VEX
     * family. */
    if (!family_name && !family_form) {
        return 1;
    }
    if (!family_name || !family_form) {
        return 0;
    }

    pd = instruction->form_id <= UINT16_C(5590);
    store = instruction->form_id <= UINT16_C(5588)
        || (instruction->form_id >= UINT16_C(5591)
            && instruction->form_id <= UINT16_C(5592));
    ymm = (instruction->form_id & UINT16_C(1)) == 0u;
    vector_size = ymm ? 32u : 16u;
    register_base = ymm ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    memory_index = store ? 0u : 2u;
    data_index = store ? 2u : 0u;
    legacy_prefix_count =
        ((instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
        + ((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u);

    if (instruction->name_id != (pd
            ? CDISASM_X86_NAME_VMASKMOVPD
            : CDISASM_X86_NAME_VMASKMOVPS)
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 3u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 3u + legacy_prefix_count
        || (instruction->encoding.prefix_size > 3u
            && (instruction->opcode_flags
                & (CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u)
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (instruction->encoding.modrm & UINT8_C(0xc0))
            == UINT8_C(0xc0)
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 0)) {
        return 0;
    }

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int is_memory = index == memory_index;
        const cdisasm_operand_access expected_access = is_memory
            ? (store ? CDISASM_OPERAND_ACCESS_WRITE
                     : CDISASM_OPERAND_ACCESS_READ)
            : (index == data_index && !store
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ);

        if (operand->type != (is_memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != vector_size
            || operand->access != expected_access
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (is_memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || (((instruction->opcode_flags
                        & CDISASM_PREFIX_SEGMENT) != 0u)
                    != ((operand->flags
                        & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0u))
                || (((instruction->opcode_flags
                        & CDISASM_PREFIX_SEGMENT) != 0u)
                    != (operand->segment_reg
                        != CDISASM_X86_REG_NONE))
                || !valid_modrm_memory_encoding(
                    instruction, operand, 0)) {
                return 0;
            }
        } else if (operand->reg < register_base
            || operand->reg > register_base + 15u
            || operand->flags != 0u) {
            return 0;
        }
    }

    return register_low3_matches(
        instruction->opcode[data_index].reg,
        register_base,
        (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)));
}

static unsigned int exact_register_provenance(cdisasm_x86_reg_id reg)
{
    if ((reg >= CDISASM_X86_REG_EAX && reg <= CDISASM_X86_REG_EDI)
        || reg == CDISASM_X86_REG_EIP
        || reg == CDISASM_X86_REG_FS || reg == CDISASM_X86_REG_GS
        || (reg >= CDISASM_X86_REG_CR0 && reg <= CDISASM_X86_REG_CR7)
        || (reg >= CDISASM_X86_REG_DR0 && reg <= CDISASM_X86_REG_DR7)) {
        return 1u;
    }
    if ((reg >= CDISASM_X86_REG_SPL && reg <= CDISASM_X86_REG_R15B)
        || (reg >= CDISASM_X86_REG_R8W && reg <= CDISASM_X86_REG_R15W)
        || (reg >= CDISASM_X86_REG_R8D && reg <= CDISASM_X86_REG_R15D)
        || (reg >= CDISASM_X86_REG_RAX && reg <= CDISASM_X86_REG_R15)
        || (reg >= CDISASM_X86_REG_XMM8 && reg <= CDISASM_X86_REG_XMM15)
        || (reg >= CDISASM_X86_REG_YMM8 && reg <= CDISASM_X86_REG_YMM15)
        || reg == CDISASM_X86_REG_RIP
        || (reg >= CDISASM_X86_REG_CR8 && reg <= CDISASM_X86_REG_CR15)
        || (reg >= CDISASM_X86_REG_DR8 && reg <= CDISASM_X86_REG_DR15)) {
        return 2u;
    }
    return 0u;
}

static unsigned int exact_instruction_provenance(
    const cdisasm_instruction *instruction)
{
    unsigned int provenance =
        (instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u
            ? 1u : 0u;
    size_t operand_index;

    /* The public prefix bitmap records only the presence of a segment
     * override, not whether its byte was FS/GS (which requires 80386) or an
     * earlier segment prefix.  An ignored FS/GS override on a register-only
     * instruction therefore has no operand segment_reg from which to recover
     * that provenance.  Preserve the decoder's I386 group in that one
     * representationally ambiguous case; without CDISASM_PREFIX_SEGMENT an
     * extra I386 group remains a rejected forgery. */
    if ((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u
        && cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_I386)) {
        provenance |= 1u;
    }

    for (operand_index = 0u; operand_index < instruction->operand_count;
         ++operand_index) {
        const cdisasm_opcode *operand = &instruction->opcode[operand_index];

        provenance |= exact_register_provenance(operand->reg);
        provenance |= exact_register_provenance(operand->base_reg);
        provenance |= exact_register_provenance(operand->index_reg);
        provenance |= exact_register_provenance(operand->segment_reg);
    }
    return provenance;
}

static int valid_vpblend_groups(
    const cdisasm_instruction *instruction, int needs_avx2)
{
    const unsigned int provenance =
        exact_instruction_provenance(instruction);
    size_t expected_index = 0u;

    if ((provenance & 1u) != 0u) {
        if (instruction->x86_group_ids[expected_index++]
            != CDISASM_X86_GROUP_I386) {
            return 0;
        }
    }
    if ((provenance & 2u) != 0u) {
        if (instruction->x86_group_ids[expected_index++]
            != CDISASM_X86_GROUP_AMD64) {
            return 0;
        }
    }
    if (instruction->x86_group_ids[expected_index++]
        != CDISASM_X86_GROUP_AVX) {
        return 0;
    }
    if (needs_avx2 && instruction->x86_group_ids[expected_index++]
        != CDISASM_X86_GROUP_AVX2) {
        return 0;
    }
    return expected_index == instruction->x86_group_count;
}

static int valid_exact_xop_groups(const cdisasm_instruction *instruction)
{
    const unsigned int provenance =
        exact_instruction_provenance(instruction);
    size_t expected_index = 0u;

    if ((provenance & 1u) != 0u) {
        if (instruction->x86_group_ids[expected_index++]
            != CDISASM_X86_GROUP_I386) {
            return 0;
        }
    }
    if ((provenance & 2u) != 0u) {
        if (instruction->x86_group_ids[expected_index++]
            != CDISASM_X86_GROUP_AMD64) {
            return 0;
        }
    }
    return expected_index + 2u == instruction->x86_group_count
        && instruction->x86_group_ids[expected_index]
            == CDISASM_X86_GROUP_AVX
        && instruction->x86_group_ids[expected_index + 1u]
            == CDISASM_X86_GROUP_XOP;
}

static int valid_vpblendvb_groups(
    const cdisasm_instruction *instruction,
    int ymm)
{
    const unsigned int provenance =
        exact_instruction_provenance(instruction);
    size_t expected_index = 0u;

    if ((provenance & 1u) != 0u) {
        if (instruction->x86_group_ids[expected_index++]
            != CDISASM_X86_GROUP_I386) {
            return 0;
        }
    }
    if ((provenance & 2u) != 0u) {
        if (instruction->x86_group_ids[expected_index++]
            != CDISASM_X86_GROUP_AMD64) {
            return 0;
        }
    }
    if (instruction->x86_group_ids[expected_index++]
        != CDISASM_X86_GROUP_AVX) {
        return 0;
    }
    if (ymm && instruction->x86_group_ids[expected_index++]
        != CDISASM_X86_GROUP_AVX2) {
        return 0;
    }
    return expected_index == instruction->x86_group_count;
}

static int valid_vblendv_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int blend_name =
        instruction->name_id == CDISASM_X86_NAME_VBLENDVPD
        || instruction->name_id == CDISASM_X86_NAME_VBLENDVPS;
    const int blend_form = instruction->form_id >= UINT16_C(3535)
        && instruction->form_id <= UINT16_C(3542);
    cdisasm_x86_form_id base;
    cdisasm_x86_form_id relative;
    cdisasm_x86_reg_id register_base;
    unsigned int vector_size;
    int memory_form;
    size_t index;

    /* Match on either side of the name/form relationship so changing only
     * one field cannot bypass this exact SE_IMM8 selector-family schema. */
    if (!blend_name && !blend_form) {
        return 1;
    }
    if (!blend_name) {
        return 0;
    }
    base = instruction->name_id == CDISASM_X86_NAME_VBLENDVPD
        ? UINT16_C(3535) : UINT16_C(3539);
    if (instruction->form_id < base
        || instruction->form_id > base + UINT16_C(3)
        || instruction->operand_count != 4u) {
        return 0;
    }

    relative = instruction->form_id - base;
    vector_size = relative < 2u ? 16u : 32u;
    memory_form = (relative & 1u) == 0u;
    register_base = vector_size == 16u
        ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
    if ((instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || (instruction->opcode_flags & CDISASM_PREFIX_VEX) == 0u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset == 0u
        || instruction->encoding.selector_offset
            != instruction->opcode_size - 1u
        || !valid_vpblend_groups(instruction, 0)) {
        return 0;
    }

    for (index = 0u; index < 4u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const cdisasm_operand_type expected_type =
            index == 2u && memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER;

        if (operand->type != expected_type
            || operand->size != vector_size
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (expected_type == CDISASM_OPERAND_REGISTER) {
            if (operand->flags != 0u
                || operand->reg < register_base
                || operand->reg > register_base + 15u) {
                return 0;
            }
        } else if ((operand->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u) {
            return 0;
        }
    }
    return 1;
}

static int valid_vpblendvb_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int blend_name =
        instruction->name_id == CDISASM_X86_NAME_VPBLENDVB;
    const int blend_form = instruction->form_id >= UINT16_C(6334)
        && instruction->form_id <= UINT16_C(6337);
    const unsigned int relative = blend_form
        ? (unsigned int)(instruction->form_id - UINT16_C(6334)) : 0u;
    const int ymm = relative >= 2u;
    const unsigned int vector_size = ymm ? 32u : 16u;
    const cdisasm_x86_reg_id register_base = ymm
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    const int memory_form = (relative & 1u) == 0u;
    size_t index;

    /* Match on either side of the name/form relationship so changing only
     * one field cannot bypass the exact selector-family schema. */
    if (!blend_name && !blend_form) {
        return 1;
    }
    if (!blend_name || !blend_form
        || instruction->operand_count != 4u
        || (instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || (instruction->opcode_flags & CDISASM_PREFIX_VEX) == 0u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset == 0u
        || !valid_vpblendvb_groups(instruction, ymm)) {
        return 0;
    }

    for (index = 0u; index < 4u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const cdisasm_operand_type expected_type =
            index == 2u && memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER;

        if (operand->type != expected_type
            || operand->size != vector_size
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (expected_type == CDISASM_OPERAND_REGISTER) {
            if (operand->flags != 0u
                || operand->reg < register_base
                || operand->reg > register_base + 15u) {
                return 0;
            }
        } else if ((operand->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u) {
            return 0;
        }
    }
    return 1;
}

static int valid_vpbroadcast_groups(
    const cdisasm_instruction *instruction)
{
    const unsigned int provenance =
        exact_instruction_provenance(instruction);
    size_t expected_index = 0u;

    if ((provenance & 1u) != 0u) {
        if (instruction->x86_group_ids[expected_index++]
            != CDISASM_X86_GROUP_I386) {
            return 0;
        }
    }
    if ((provenance & 2u) != 0u) {
        if (instruction->x86_group_ids[expected_index++]
            != CDISASM_X86_GROUP_AMD64) {
            return 0;
        }
    }
    return expected_index + 2u == instruction->x86_group_count
        && instruction->x86_group_ids[expected_index]
            == CDISASM_X86_GROUP_AVX
        && instruction->x86_group_ids[expected_index + 1u]
            == CDISASM_X86_GROUP_AVX2;
}

static int valid_vpbroadcast_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int broadcast_name =
        (instruction->name_id == CDISASM_X86_NAME_VPBROADCASTB
            || instruction->name_id == CDISASM_X86_NAME_VPBROADCASTW
            || instruction->name_id == CDISASM_X86_NAME_VPBROADCASTD
            || instruction->name_id == CDISASM_X86_NAME_VPBROADCASTQ)
        && (instruction->opcode_flags & CDISASM_PREFIX_VEX) != 0u;
    const int broadcast_form =
        instruction->form_id == UINT16_C(6342)
        || instruction->form_id == UINT16_C(6343)
        || instruction->form_id == UINT16_C(6347)
        || instruction->form_id == UINT16_C(6348)
        || instruction->form_id == UINT16_C(6387)
        || instruction->form_id == UINT16_C(6388)
        || instruction->form_id == UINT16_C(6392)
        || instruction->form_id == UINT16_C(6393)
        || instruction->form_id == UINT16_C(6355)
        || instruction->form_id == UINT16_C(6356)
        || instruction->form_id == UINT16_C(6360)
        || instruction->form_id == UINT16_C(6361)
        || instruction->form_id == UINT16_C(6374)
        || instruction->form_id == UINT16_C(6375)
        || instruction->form_id == UINT16_C(6379)
        || instruction->form_id == UINT16_C(6380);
    const int word = instruction->form_id == UINT16_C(6387)
        || instruction->form_id == UINT16_C(6388)
        || instruction->form_id == UINT16_C(6392)
        || instruction->form_id == UINT16_C(6393);
    const int dword = instruction->form_id == UINT16_C(6355)
        || instruction->form_id == UINT16_C(6356)
        || instruction->form_id == UINT16_C(6360)
        || instruction->form_id == UINT16_C(6361);
    const int qword = instruction->form_id == UINT16_C(6374)
        || instruction->form_id == UINT16_C(6375)
        || instruction->form_id == UINT16_C(6379)
        || instruction->form_id == UINT16_C(6380);
    const int ymm = instruction->form_id == UINT16_C(6347)
        || instruction->form_id == UINT16_C(6348)
        || instruction->form_id == UINT16_C(6392)
        || instruction->form_id == UINT16_C(6393)
        || instruction->form_id == UINT16_C(6360)
        || instruction->form_id == UINT16_C(6361)
        || instruction->form_id == UINT16_C(6379)
        || instruction->form_id == UINT16_C(6380);
    const int memory_form = instruction->form_id == UINT16_C(6342)
        || instruction->form_id == UINT16_C(6347)
        || instruction->form_id == UINT16_C(6387)
        || instruction->form_id == UINT16_C(6392)
        || instruction->form_id == UINT16_C(6355)
        || instruction->form_id == UINT16_C(6360)
        || instruction->form_id == UINT16_C(6374)
        || instruction->form_id == UINT16_C(6379);
    const cdisasm_x86_name_id expected_name = qword
        ? CDISASM_X86_NAME_VPBROADCASTQ
        : (dword ? CDISASM_X86_NAME_VPBROADCASTD
                 : (word ? CDISASM_X86_NAME_VPBROADCASTW
                         : CDISASM_X86_NAME_VPBROADCASTB));
    const unsigned int scalar_bytes = qword
        ? 8u : (dword ? 4u : (word ? 2u : 1u));
    const cdisasm_x86_reg_id destination_base = ymm
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    const cdisasm_opcode *destination = &instruction->opcode[0];
    const cdisasm_opcode *source = &instruction->opcode[1];

    /* Match on both sides of the name/form relationship so a forged object
     * cannot bypass this exact scalar-source recipe by changing one ID. */
    if (!broadcast_name && !broadcast_form) {
        return 1;
    }
    if (!broadcast_name || !broadcast_form
        || instruction->name_id != expected_name
        || instruction->operand_count != 2u
        || (instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || (instruction->opcode_flags & CDISASM_PREFIX_VEX) == 0u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpbroadcast_groups(instruction)
        || destination->type != CDISASM_OPERAND_REGISTER
        || destination->reg < destination_base
        || destination->reg > destination_base + 15u
        || destination->size != (ymm ? 32u : 16u)
        || destination->access != CDISASM_OPERAND_ACCESS_WRITE
        || destination->flags != 0u
        || destination->broadcast != CDISASM_X86_BROADCAST_NONE
        || source->type != (memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
        || source->size != scalar_bytes
        || source->access != CDISASM_OPERAND_ACCESS_READ
        || source->broadcast != CDISASM_X86_BROADCAST_NONE) {
        return 0;
    }
    if (memory_form) {
        return (source->flags
            & (CDISASM_OPERAND_FLAG_IMPLICIT
                | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u;
    }
    return source->reg >= CDISASM_X86_REG_XMM0
        && source->reg <= CDISASM_X86_REG_XMM15
        && source->flags == 0u;
}

static int valid_vpcmpeqq_groups(
    const cdisasm_instruction *instruction,
    int ymm)
{
    const unsigned int provenance =
        exact_instruction_provenance(instruction);
    size_t expected_index = 0u;

    if ((provenance & 1u) != 0u) {
        if (instruction->x86_group_ids[expected_index++]
            != CDISASM_X86_GROUP_I386) {
            return 0;
        }
    }
    if ((provenance & 2u) != 0u) {
        if (instruction->x86_group_ids[expected_index++]
            != CDISASM_X86_GROUP_AMD64) {
            return 0;
        }
    }
    if (instruction->x86_group_ids[expected_index++]
        != CDISASM_X86_GROUP_AVX) {
        return 0;
    }
    if (ymm && instruction->x86_group_ids[expected_index++]
        != CDISASM_X86_GROUP_AVX2) {
        return 0;
    }
    return expected_index == instruction->x86_group_count;
}

static int valid_vpmaskmov_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int family_name =
        instruction->name_id == CDISASM_X86_NAME_VPMASKMOVD
        || instruction->name_id == CDISASM_X86_NAME_VPMASKMOVQ;
    const int family_form = instruction->form_id >= UINT16_C(7152)
        && instruction->form_id <= UINT16_C(7159);
    const int qword = family_form
        && instruction->form_id >= UINT16_C(7156);
    const int load = family_form
        && ((instruction->form_id >= UINT16_C(7154)
                && instruction->form_id <= UINT16_C(7155))
            || instruction->form_id >= UINT16_C(7158));
    const int ymm = family_form
        && (instruction->form_id & UINT16_C(1)) != 0u;
    const unsigned int vector_size = ymm ? 32u : 16u;
    const cdisasm_x86_reg_id register_base = ymm
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    const size_t memory_index = load ? 2u : 0u;
    const size_t data_index = load ? 0u : 2u;
    const unsigned int legacy_prefix_count =
        ((instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
        + ((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u);
    const unsigned int provenance =
        exact_instruction_provenance(instruction);
    size_t expected_group = 0u;
    size_t index;

    /* Bind both name and form ownership: catalog-generated or forged objects
     * cannot borrow these exact classic-VEX identities. */
    if (!family_name && !family_form) {
        return 1;
    }
    if (!family_name || !family_form
        || instruction->name_id != (qword
            ? CDISASM_X86_NAME_VPMASKMOVQ
            : CDISASM_X86_NAME_VPMASKMOVD)
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 3u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size
            < 3u + legacy_prefix_count
        || (instruction->encoding.prefix_size > 3u
            && (instruction->opcode_flags
                & (CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u)
        || instruction->encoding.opcode_offset
            != instruction->encoding.prefix_size
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (instruction->encoding.modrm & UINT8_C(0xc0))
            == UINT8_C(0xc0)
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u) {
        return 0;
    }

    if ((provenance & 1u) != 0u
        && instruction->x86_group_ids[expected_group++]
            != CDISASM_X86_GROUP_I386) {
        return 0;
    }
    if ((provenance & 2u) != 0u
        && instruction->x86_group_ids[expected_group++]
            != CDISASM_X86_GROUP_AMD64) {
        return 0;
    }
    if (instruction->x86_group_ids[expected_group++]
            != CDISASM_X86_GROUP_AVX2
        || expected_group != instruction->x86_group_count) {
        return 0;
    }

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int is_memory = index == memory_index;
        const cdisasm_operand_access expected_access = is_memory
            ? (load ? CDISASM_OPERAND_ACCESS_READ
                    : CDISASM_OPERAND_ACCESS_WRITE)
            : (index == data_index && load
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ);

        if (operand->type != (is_memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != vector_size
            || operand->access != expected_access
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (is_memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                        | CDISASM_OPERAND_FLAG_SIGNED)) != 0u
                || (((instruction->opcode_flags
                        & CDISASM_PREFIX_SEGMENT) != 0u)
                    != ((operand->flags
                        & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0u))
                || (((instruction->opcode_flags
                        & CDISASM_PREFIX_SEGMENT) != 0u)
                    != (operand->segment_reg
                        != CDISASM_X86_REG_NONE))
                || !valid_modrm_memory_encoding(
                    instruction, operand, 0)) {
                return 0;
            }
        } else if (operand->reg < register_base
            || operand->reg > register_base + 15u
            || operand->flags != 0u) {
            return 0;
        }
    }

    return register_low3_matches(
        instruction->opcode[data_index].reg,
        register_base,
        (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)));
}

static int valid_vbroadcast128_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int broadcast_name =
        instruction->name_id == CDISASM_X86_NAME_VBROADCASTF128
        || instruction->name_id == CDISASM_X86_NAME_VBROADCASTI128;
    const int broadcast_form = instruction->form_id == UINT16_C(3543)
        || instruction->form_id == UINT16_C(3554);
    const int integer_form = instruction->form_id == UINT16_C(3554);
    const cdisasm_opcode *destination = &instruction->opcode[0];
    const cdisasm_opcode *source = &instruction->opcode[1];

    /* Match on either half of the name/form relationship.  This prevents a
     * partially forged object from bypassing the memory-only lane-broadcast
     * recipe by changing only its public name or exact form ID. */
    if (!broadcast_name && !broadcast_form) {
        return 1;
    }
    if (!broadcast_name || !broadcast_form
        || (integer_form
            ? instruction->name_id != CDISASM_X86_NAME_VBROADCASTI128
            : instruction->name_id != CDISASM_X86_NAME_VBROADCASTF128)
        || instruction->operand_count != 2u
        || (instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || (instruction->opcode_flags & CDISASM_PREFIX_VEX) == 0u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, integer_form)
        || destination->type != CDISASM_OPERAND_REGISTER
        || destination->reg < CDISASM_X86_REG_YMM0
        || destination->reg > CDISASM_X86_REG_YMM15
        || destination->size != 32u
        || destination->access != CDISASM_OPERAND_ACCESS_WRITE
        || destination->flags != 0u
        || destination->broadcast != CDISASM_X86_BROADCAST_NONE
        || source->type != CDISASM_OPERAND_MEMORY
        || source->size != 16u
        || source->access != CDISASM_OPERAND_ACCESS_READ
        || source->broadcast != CDISASM_X86_BROADCAST_NONE
        || (source->flags
            & (CDISASM_OPERAND_FLAG_IMPLICIT
                | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u) {
        return 0;
    }
    return 1;
}

static int valid_vex_lane128_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int lane_name =
        instruction->name_id == CDISASM_X86_NAME_VEXTRACTF128
        || instruction->name_id == CDISASM_X86_NAME_VEXTRACTI128
        || instruction->name_id == CDISASM_X86_NAME_VINSERTF128
        || instruction->name_id == CDISASM_X86_NAME_VINSERTI128;
    const int lane_form = instruction->form_id == UINT16_C(4539)
        || instruction->form_id == UINT16_C(4540)
        || instruction->form_id == UINT16_C(4553)
        || instruction->form_id == UINT16_C(4554)
        || instruction->form_id == UINT16_C(5551)
        || instruction->form_id == UINT16_C(5552)
        || instruction->form_id == UINT16_C(5565)
        || instruction->form_id == UINT16_C(5566);
    const int is_extract =
        instruction->name_id == CDISASM_X86_NAME_VEXTRACTF128
        || instruction->name_id == CDISASM_X86_NAME_VEXTRACTI128;
    const int is_integer =
        instruction->name_id == CDISASM_X86_NAME_VEXTRACTI128
        || instruction->name_id == CDISASM_X86_NAME_VINSERTI128;
    cdisasm_x86_form_id base;
    size_t memory_index;
    size_t immediate_index;
    size_t index;
    int memory_form;

    /* Match either side so changing only the public name or exact form ID
     * cannot escape the fixed-width VEX lane recipe. */
    if (!lane_name && !lane_form) {
        return 1;
    }
    if (!lane_name) {
        return 0;
    }
    if (instruction->name_id == CDISASM_X86_NAME_VEXTRACTF128) {
        base = UINT16_C(4539);
    } else if (instruction->name_id == CDISASM_X86_NAME_VEXTRACTI128) {
        base = UINT16_C(4553);
    } else if (instruction->name_id == CDISASM_X86_NAME_VINSERTF128) {
        base = UINT16_C(5551);
    } else {
        base = UINT16_C(5565);
    }
    if (instruction->form_id < base
        || instruction->form_id > base + UINT16_C(1)) {
        return 0;
    }

    memory_form = instruction->form_id == base;
    memory_index = is_extract ? 0u : 2u;
    immediate_index = is_extract ? 2u : 3u;
    if (instruction->operand_count != (is_extract ? 3u : 4u)
        || (instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || (instruction->opcode_flags & CDISASM_PREFIX_VEX) == 0u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 1u
        || instruction->encoding.immediate_size[0] != 1u
        || instruction->encoding.immediate_offset[0]
            != instruction->opcode_size - 1u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, is_integer)) {
        return 0;
    }

    for (index = 0u; index < immediate_index; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const unsigned int expected_size =
            index == memory_index ? 16u : 32u;
        const cdisasm_operand_access expected_access = index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ;

        if (operand->type != (memory_form && index == memory_index
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != expected_size
            || operand->access != expected_access
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (operand->type == CDISASM_OPERAND_MEMORY) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u) {
                return 0;
            }
        } else {
            const cdisasm_x86_reg_id register_base = expected_size == 16u
                ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;

            if (operand->reg < register_base
                || operand->reg > register_base + 15u
                || operand->flags != 0u) {
                return 0;
            }
        }
    }
    return instruction->opcode[immediate_index].type
            == CDISASM_OPERAND_IMMEDIATE
        && instruction->opcode[immediate_index].size == 1u
        && instruction->opcode[immediate_index].access
            == CDISASM_OPERAND_ACCESS_READ
        && instruction->opcode[immediate_index].flags == 0u
        && instruction->opcode[immediate_index].broadcast
            == CDISASM_X86_BROADCAST_NONE
        && instruction->opcode[immediate_index].imm <= UINT8_MAX;
}

static int valid_vbroadcast_scalar_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int broadcast_name =
        instruction->name_id == CDISASM_X86_NAME_VBROADCASTSS
        || instruction->name_id == CDISASM_X86_NAME_VBROADCASTSD;
    const int broadcast_form =
        instruction->form_id == UINT16_C(3569)
        || instruction->form_id == UINT16_C(3570)
        || instruction->form_id == UINT16_C(3573)
        || instruction->form_id == UINT16_C(3574)
        || instruction->form_id == UINT16_C(3579)
        || instruction->form_id == UINT16_C(3580);
    const int evex_double_form =
        instruction->form_id == UINT16_C(3567)
        || instruction->form_id == UINT16_C(3568)
        || instruction->form_id == UINT16_C(3571)
        || instruction->form_id == UINT16_C(3572);
    const int evex_single_form =
        (instruction->form_id >= UINT16_C(3575)
            && instruction->form_id <= UINT16_C(3578))
        || instruction->form_id == UINT16_C(3581)
        || instruction->form_id == UINT16_C(3582);
    const int evex_form = evex_double_form || evex_single_form;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int single = instruction->form_id == UINT16_C(3573)
        || instruction->form_id == UINT16_C(3574)
        || instruction->form_id == UINT16_C(3579)
        || instruction->form_id == UINT16_C(3580);
    const int ymm = instruction->form_id == UINT16_C(3569)
        || instruction->form_id == UINT16_C(3570)
        || instruction->form_id == UINT16_C(3579)
        || instruction->form_id == UINT16_C(3580);
    const int memory_form = instruction->form_id == UINT16_C(3569)
        || instruction->form_id == UINT16_C(3573)
        || instruction->form_id == UINT16_C(3579);
    const cdisasm_x86_name_id expected_name = single
        ? CDISASM_X86_NAME_VBROADCASTSS
        : CDISASM_X86_NAME_VBROADCASTSD;
    const cdisasm_x86_reg_id destination_base = ymm
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    const unsigned int scalar_bytes = single ? 4u : 8u;
    const cdisasm_opcode *destination = &instruction->opcode[0];
    const cdisasm_opcode *source = &instruction->opcode[1];

    /* The same public names have ten exact EVEX siblings, which remain under
     * the generic EVEX schema.  Whitelist those form/name relationships and
     * require an unambiguous EVEX prefix before handing them back; otherwise
     * an unrelated form or contradictory VEX|EVEX flags could bypass this
     * six-form VEX recipe. */
    if (evex_form) {
        return instruction->name_id == (evex_single_form
                ? CDISASM_X86_NAME_VBROADCASTSS
                : CDISASM_X86_NAME_VBROADCASTSD)
            && modern_prefix == CDISASM_PREFIX_EVEX;
    }
    if (!broadcast_name && !broadcast_form) {
        return 1;
    }
    if (!broadcast_name || !broadcast_form
        || instruction->name_id != expected_name
        || instruction->operand_count != 2u
        || (instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, !memory_form)
        || destination->type != CDISASM_OPERAND_REGISTER
        || destination->reg < destination_base
        || destination->reg > destination_base + 15u
        || destination->size != (ymm ? 32u : 16u)
        || destination->access != CDISASM_OPERAND_ACCESS_WRITE
        || destination->flags != 0u
        || destination->broadcast != CDISASM_X86_BROADCAST_NONE
        || source->type != (memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
        || source->size != (memory_form ? scalar_bytes : 16u)
        || source->access != CDISASM_OPERAND_ACCESS_READ
        || source->broadcast != CDISASM_X86_BROADCAST_NONE) {
        return 0;
    }
    if (memory_form) {
        return (source->flags
            & (CDISASM_OPERAND_FLAG_IMPLICIT
                | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u;
    }
    return source->reg >= CDISASM_X86_REG_XMM0
        && source->reg <= CDISASM_X86_REG_XMM15
        && source->flags == 0u;
}

static int valid_vex_ps_lane_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int lane_name =
        instruction->name_id == CDISASM_X86_NAME_VEXTRACTPS
        || instruction->name_id == CDISASM_X86_NAME_VINSERTPS;
    const int vex_form = instruction->form_id == UINT16_C(4567)
        || instruction->form_id == UINT16_C(4569)
        || instruction->form_id == UINT16_C(5579)
        || instruction->form_id == UINT16_C(5580);
    const int evex_extract_form =
        instruction->form_id == UINT16_C(4568)
        || instruction->form_id == UINT16_C(4570);
    const int evex_insert_form =
        instruction->form_id == UINT16_C(5581)
        || instruction->form_id == UINT16_C(5582);
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int is_extract =
        instruction->name_id == CDISASM_X86_NAME_VEXTRACTPS;
    const int memory_form = instruction->form_id == UINT16_C(4569)
        || instruction->form_id == UINT16_C(5579);
    const size_t variable_index = is_extract ? 0u : 2u;
    const size_t immediate_index = is_extract ? 2u : 3u;
    size_t index;

    /* The public names also belong to four EVEX forms.  Admit only their
     * exact form/name/prefix relationship for the generic EVEX validator;
     * contradictory VEX/EVEX mutations must not cross this boundary. */
    if (evex_extract_form || evex_insert_form) {
        return instruction->name_id == (evex_extract_form
                ? CDISASM_X86_NAME_VEXTRACTPS
                : CDISASM_X86_NAME_VINSERTPS)
            && modern_prefix == CDISASM_PREFIX_EVEX;
    }
    /* Match independently on name and exact VEX form so name-only, form-only,
     * and opaque-object mutations cannot evade the family recipe. */
    if (!lane_name && !vex_form) {
        return 1;
    }
    if (!lane_name || !vex_form
        || instruction->name_id != (instruction->form_id == UINT16_C(4567)
                || instruction->form_id == UINT16_C(4569)
            ? CDISASM_X86_NAME_VEXTRACTPS
            : CDISASM_X86_NAME_VINSERTPS)
        || instruction->operand_count != (is_extract ? 3u : 4u)
        || (instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 1u
        || instruction->encoding.immediate_size[0] != 1u
        || instruction->encoding.immediate_offset[0]
            != instruction->opcode_size - 1u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 0)) {
        return 0;
    }

    for (index = 0u; index < immediate_index; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int variable = index == variable_index;
        const int gpr_destination = is_extract && index == 0u
            && !memory_form;
        const cdisasm_operand_type expected_type = variable && memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER;
        const unsigned int expected_size = variable && memory_form
            ? 4u : 16u;

        if (operand->type != expected_type
            || operand->size != (gpr_destination ? 4u : expected_size)
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (operand->type == CDISASM_OPERAND_MEMORY) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u) {
                return 0;
            }
        } else if (gpr_destination) {
            if (operand->reg < CDISASM_X86_REG_EAX
                || operand->reg > CDISASM_X86_REG_R15D
                || operand->flags != 0u) {
                return 0;
            }
        } else if (operand->reg < CDISASM_X86_REG_XMM0
            || operand->reg > CDISASM_X86_REG_XMM15
            || operand->flags != 0u) {
            return 0;
        }
    }
    return instruction->opcode[immediate_index].type
            == CDISASM_OPERAND_IMMEDIATE
        && instruction->opcode[immediate_index].size == 1u
        && instruction->opcode[immediate_index].access
            == CDISASM_OPERAND_ACCESS_READ
        && instruction->opcode[immediate_index].flags == 0u
        && instruction->opcode[immediate_index].broadcast
            == CDISASM_X86_BROADCAST_NONE
        && instruction->opcode[immediate_index].imm <= UINT8_MAX;
}

static int valid_vpcmpeqq_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int vpcmpeqq_name =
        instruction->name_id == CDISASM_X86_NAME_VPCMPEQQ;
    const int evex_form = instruction->form_id >= UINT16_C(6448)
        && instruction->form_id <= UINT16_C(6453);
    const int evex_name = vpcmpeqq_name && evex_form
        && (instruction->opcode_flags
            & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_EVEX))
            == CDISASM_PREFIX_EVEX;
    const int vex_form = instruction->form_id >= UINT16_C(6454)
        && instruction->form_id <= UINT16_C(6457);
    const unsigned int relative = vex_form
        ? (unsigned int)(instruction->form_id - UINT16_C(6454)) : 0u;
    const int ymm = relative >= 2u;
    const int memory_form = (relative & 1u) == 0u;
    const unsigned int vector_size = ymm ? 32u : 16u;
    const cdisasm_x86_reg_id register_base = ymm
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    size_t index;

    /* EVEX VPCMPEQQ is a separate mask-destination family.  Validate only
     * the four exact VEX forms here, while matching on either side of the
     * VEX name/form relationship to reject partially forged objects. */
    if (evex_name) {
        return 1;
    }
    if (!vpcmpeqq_name && !vex_form) {
        return 1;
    }
    if (!vpcmpeqq_name || !vex_form
        || instruction->operand_count != 3u
        || (instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || (instruction->opcode_flags & CDISASM_PREFIX_VEX) == 0u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpcmpeqq_groups(instruction, ymm)) {
        return 0;
    }

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const cdisasm_operand_type expected_type =
            index == 2u && memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER;

        if (operand->type != expected_type
            || operand->size != vector_size
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (expected_type == CDISASM_OPERAND_REGISTER) {
            if (operand->flags != 0u
                || operand->reg < register_base
                || operand->reg > register_base + 15u) {
                return 0;
            }
        } else if ((operand->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u) {
            return 0;
        }
    }
    return 1;
}

static int valid_vpcmpgt_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int eqb_name =
        instruction->name_id == CDISASM_X86_NAME_VPCMPEQB;
    const int eqd_name =
        instruction->name_id == CDISASM_X86_NAME_VPCMPEQD;
    const int eqw_name =
        instruction->name_id == CDISASM_X86_NAME_VPCMPEQW;
    const int gtb_name =
        instruction->name_id == CDISASM_X86_NAME_VPCMPGTB;
    const int gtd_name =
        instruction->name_id == CDISASM_X86_NAME_VPCMPGTD;
    const int gtq_name =
        instruction->name_id == CDISASM_X86_NAME_VPCMPGTQ;
    const int gtw_name =
        instruction->name_id == CDISASM_X86_NAME_VPCMPGTW;
    const int family_name = eqb_name || eqd_name || eqw_name
        || gtb_name || gtd_name || gtq_name || gtw_name;
    const int eqb_evex_form = instruction->form_id >= UINT16_C(6428)
        && instruction->form_id <= UINT16_C(6433);
    const int eqd_evex_form = instruction->form_id >= UINT16_C(6438)
        && instruction->form_id <= UINT16_C(6443);
    const int eqw_evex_form = instruction->form_id >= UINT16_C(6458)
        && instruction->form_id <= UINT16_C(6463);
    const int gtb_evex_form = instruction->form_id >= UINT16_C(6476)
        && instruction->form_id <= UINT16_C(6481);
    const int gtd_evex_form = instruction->form_id >= UINT16_C(6486)
        && instruction->form_id <= UINT16_C(6491);
    const int gtq_evex_form = instruction->form_id >= UINT16_C(6496)
        && instruction->form_id <= UINT16_C(6501);
    const int gtw_evex_form = instruction->form_id >= UINT16_C(6506)
        && instruction->form_id <= UINT16_C(6511);
    const int evex_form = eqb_evex_form || eqd_evex_form || eqw_evex_form
        || gtb_evex_form || gtd_evex_form
        || gtq_evex_form || gtw_evex_form;
    const int evex_identity = (eqb_name && eqb_evex_form)
        || (eqd_name && eqd_evex_form)
        || (eqw_name && eqw_evex_form)
        || (gtb_name && gtb_evex_form)
        || (gtd_name && gtd_evex_form)
        || (gtq_name && gtq_evex_form)
        || (gtw_name && gtw_evex_form);
    const int eqb_vex_form = instruction->form_id >= UINT16_C(6434)
        && instruction->form_id <= UINT16_C(6437);
    const int eqd_vex_form = instruction->form_id >= UINT16_C(6444)
        && instruction->form_id <= UINT16_C(6447);
    const int eqw_vex_form = instruction->form_id >= UINT16_C(6464)
        && instruction->form_id <= UINT16_C(6467);
    const int gtb_vex_form = instruction->form_id >= UINT16_C(6482)
        && instruction->form_id <= UINT16_C(6485);
    const int gtd_vex_form = instruction->form_id >= UINT16_C(6492)
        && instruction->form_id <= UINT16_C(6495);
    const int gtq_vex_form = instruction->form_id >= UINT16_C(6502)
        && instruction->form_id <= UINT16_C(6505);
    const int gtw_vex_form = instruction->form_id >= UINT16_C(6512)
        && instruction->form_id <= UINT16_C(6515);
    const int vex_form = eqb_vex_form || eqd_vex_form || eqw_vex_form
        || gtb_vex_form || gtd_vex_form || gtq_vex_form || gtw_vex_form;
    const int vex_identity = (eqb_name && eqb_vex_form)
        || (eqd_name && eqd_vex_form)
        || (eqw_name && eqw_vex_form)
        || (gtb_name && gtb_vex_form)
        || (gtd_name && gtd_vex_form)
        || (gtq_name && gtq_vex_form)
        || (gtw_name && gtw_vex_form);
    const int bw_family = eqb_name || eqw_name || gtb_name || gtw_name
        || eqb_evex_form || eqw_evex_form
        || gtb_evex_form || gtw_evex_form
        || eqb_vex_form || eqw_vex_form || gtb_vex_form || gtw_vex_form;
    const unsigned int element_size = (eqb_name || gtb_name
            || eqb_evex_form || gtb_evex_form
            || eqb_vex_form || gtb_vex_form) ? 1u
        : (eqw_name || gtw_name || eqw_evex_form || gtw_evex_form
            || eqw_vex_form || gtw_vex_form) ? 2u
        : (eqd_name || gtd_name || eqd_evex_form || gtd_evex_form
            || eqd_vex_form || gtd_vex_form) ? 4u : 8u;
    const cdisasm_x86_form_id vex_base = eqb_vex_form
        ? UINT16_C(6434) : eqd_vex_form ? UINT16_C(6444)
        : eqw_vex_form ? UINT16_C(6464)
        : gtb_vex_form ? UINT16_C(6482)
        : gtd_vex_form ? UINT16_C(6492)
        : gtw_vex_form ? UINT16_C(6512) : UINT16_C(6502);
    const unsigned int relative = vex_form
        ? (unsigned int)(instruction->form_id - vex_base) : 0u;
    const int ymm = relative >= 2u;
    const int memory_form = (relative & 1u) == 0u;
    const unsigned int vector_size = ymm ? 32u : 16u;
    const cdisasm_x86_reg_id register_base = ymm
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    const unsigned int legacy_prefix_count =
        ((instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
        + ((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u);
    const cdisasm_opcode *classic_source = &instruction->opcode[2];
    const int native_c5 = vex_form && !gtq_vex_form
        && instruction->encoding.prefix_size
            < 3u + legacy_prefix_count;
    const int c5_high_base =
        (classic_source->base_reg >= CDISASM_X86_REG_R8W
            && classic_source->base_reg <= CDISASM_X86_REG_R15W)
        || (classic_source->base_reg >= CDISASM_X86_REG_R8D
            && classic_source->base_reg <= CDISASM_X86_REG_R15D)
        || (classic_source->base_reg >= CDISASM_X86_REG_R8
            && classic_source->base_reg <= CDISASM_X86_REG_R15);
    const int c5_high_index =
        (classic_source->index_reg >= CDISASM_X86_REG_R8W
            && classic_source->index_reg <= CDISASM_X86_REG_R15W)
        || (classic_source->index_reg >= CDISASM_X86_REG_R8D
            && classic_source->index_reg <= CDISASM_X86_REG_R15D)
        || (classic_source->index_reg >= CDISASM_X86_REG_R8
            && classic_source->index_reg <= CDISASM_X86_REG_R15);
    size_t index;

    /* Own these packed-compare families' generated-EVEX recipes as well. Their
     * k destination, optional writemask, source shape, and width group are
     * structurally different from classic VEX, so identity and generated
     * provenance alone are not sufficient formatter proof. */
    if (evex_form
        || (family_name && modern_prefix == CDISASM_PREFIX_EVEX)) {
        const uint32_t evex_allowed_flags = CDISASM_PREFIX_EVEX
            | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT
            | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        const cdisasm_x86_form_id evex_base = eqb_evex_form
            ? UINT16_C(6428) : eqd_evex_form ? UINT16_C(6438)
            : eqw_evex_form ? UINT16_C(6458)
            : gtb_evex_form ? UINT16_C(6476)
            : gtd_evex_form ? UINT16_C(6486)
            : gtw_evex_form ? UINT16_C(6506) : UINT16_C(6496);
        const unsigned int evex_relative = evex_form
            ? (unsigned int)(instruction->form_id - evex_base) : 0u;
        const unsigned int evex_vector_size =
            16u << (evex_relative / 2u);
        const int evex_memory_form = (evex_relative & 1u) == 0u;
        const cdisasm_x86_reg_id evex_register_base =
            evex_vector_size == 16u ? CDISASM_X86_REG_XMM0
            : evex_vector_size == 32u ? CDISASM_X86_REG_YMM0
                                      : CDISASM_X86_REG_ZMM0;
        const cdisasm_x86_group_id evex_width_group = bw_family
            ? (evex_vector_size == 16u
                ? CDISASM_X86_GROUP_AVX512BW_128
                : evex_vector_size == 32u
                    ? CDISASM_X86_GROUP_AVX512BW_256
                    : CDISASM_X86_GROUP_AVX512BW_512)
            : (evex_vector_size == 16u
                ? CDISASM_X86_GROUP_AVX512F_128
                : evex_vector_size == 32u
                    ? CDISASM_X86_GROUP_AVX512F_256
                    : CDISASM_X86_GROUP_AVX512F_512);
        const unsigned int evex_legacy_prefix_count =
            ((instruction->opcode_flags
                & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
            + ((instruction->opcode_flags
                & CDISASM_PREFIX_SEGMENT) != 0u);
        int allow_egpr;

        if (!evex_identity
            || modern_prefix != CDISASM_PREFIX_EVEX
            || (instruction->opcode_flags & ~evex_allowed_flags) != 0u
            || (instruction->opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u
            || instruction->operand_count != 3u
            || (instruction->mask_mode != CDISASM_X86_MASK_NONE
                && instruction->mask_mode != CDISASM_X86_MASK_MERGE)
            || ((instruction->mask_mode == CDISASM_X86_MASK_NONE)
                != (instruction->mask_reg == CDISASM_X86_REG_NONE))
            || (instruction->mask_mode == CDISASM_X86_MASK_MERGE
                && (instruction->mask_reg < CDISASM_X86_REG_K1
                    || instruction->mask_reg > CDISASM_X86_REG_K7))
            || instruction->rounding != CDISASM_X86_ROUNDING_NONE
            || instruction->sae != CDISASM_X86_SAE_NONE
            || instruction->opcode_groups != CDISASM_GROUP_NONE
            || instruction->branch_target != 0u
            || instruction->encoding.prefix_size
                < 4u + evex_legacy_prefix_count
            || (instruction->encoding.prefix_size > 4u
                && (instruction->opcode_flags
                    & (CDISASM_PREFIX_ADDRESS_SIZE
                        | CDISASM_PREFIX_SEGMENT)) == 0u)
            || instruction->encoding.opcode_offset
                != instruction->encoding.prefix_size
            || instruction->encoding.opcode_size != 1u
            || instruction->encoding.modrm_offset
                != instruction->encoding.opcode_offset + 1u
            || (((instruction->encoding.modrm & UINT8_C(0xc0))
                    == UINT8_C(0xc0)) == evex_memory_form)
            || (!evex_memory_form
                && (instruction->encoding.sib_offset != 0u
                    || instruction->encoding.displacement_offset != 0u
                    || instruction->encoding.displacement_size != 0u))
            || instruction->encoding.immediate_count != 0u
            || instruction->encoding.selector_offset != 0u
            || !valid_generated_evex_width_groups(
                instruction, evex_width_group, &allow_egpr)) {
            return 0;
        }

        if (instruction->opcode[0].type != CDISASM_OPERAND_REGISTER
            || instruction->opcode[0].reg < CDISASM_X86_REG_K0
            || instruction->opcode[0].reg > CDISASM_X86_REG_K7
            || instruction->opcode[0].size != 8u
            || instruction->opcode[0].access
                != CDISASM_OPERAND_ACCESS_WRITE
            || instruction->opcode[0].flags != 0u
            || instruction->opcode[0].broadcast
                != CDISASM_X86_BROADCAST_NONE
            || !register_low3_matches(
                instruction->opcode[0].reg,
                CDISASM_X86_REG_K0,
                (uint8_t)((instruction->encoding.modrm >> 3)
                    & UINT8_C(7)))
            || instruction->opcode[1].type != CDISASM_OPERAND_REGISTER
            || instruction->opcode[1].reg < evex_register_base
            || instruction->opcode[1].reg > evex_register_base + 31u
            || instruction->opcode[1].size != evex_vector_size
            || instruction->opcode[1].access
                != CDISASM_OPERAND_ACCESS_READ
            || instruction->opcode[1].flags != 0u
            || instruction->opcode[1].broadcast
                != CDISASM_X86_BROADCAST_NONE
            || instruction->opcode[2].type != (evex_memory_form
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || instruction->opcode[2].access
                != CDISASM_OPERAND_ACCESS_READ) {
            return 0;
        }

        if (evex_memory_form) {
            const cdisasm_opcode *memory = &instruction->opcode[2];
            const int valid_memory_width =
                (memory->size == evex_vector_size
                    && memory->broadcast == CDISASM_X86_BROADCAST_NONE)
                || (!bw_family && memory->size == element_size
                    && memory->broadcast == (cdisasm_x86_broadcast)(
                        evex_vector_size / element_size));

            if (!valid_memory_width
                || (memory->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                        | CDISASM_OPERAND_FLAG_SIGNED)) != 0u
                || (((instruction->opcode_flags
                        & CDISASM_PREFIX_SEGMENT) != 0u)
                    != ((memory->flags
                        & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0u))
                || (((instruction->opcode_flags
                        & CDISASM_PREFIX_SEGMENT) != 0u)
                    != (memory->segment_reg
                        != CDISASM_X86_REG_NONE))
                || !valid_modrm_memory_encoding(
                    instruction, memory, allow_egpr)) {
                return 0;
            }
        } else if (instruction->opcode[2].reg < evex_register_base
            || instruction->opcode[2].reg > evex_register_base + 31u
            || instruction->opcode[2].size != evex_vector_size
            || instruction->opcode[2].flags != 0u
            || instruction->opcode[2].broadcast
                != CDISASM_X86_BROADCAST_NONE
            || !register_low3_matches(
                instruction->opcode[2].reg,
                evex_register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7)))) {
            return 0;
        }
        return 1;
    }
    if (!family_name && !vex_form) {
        return 1;
    }
    if (!family_name || !vex_form || !vex_identity
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 3u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size
            < (gtq_vex_form ? 3u : 2u) + legacy_prefix_count
        || (instruction->encoding.prefix_size > 3u
            && (instruction->opcode_flags
                & (CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u)
        || instruction->encoding.opcode_offset
            != instruction->encoding.prefix_size
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpcmpeqq_groups(instruction, ymm)) {
        return 0;
    }

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int is_memory = index == 2u && memory_form;

        if (operand->type != (is_memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != vector_size
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (is_memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                        | CDISASM_OPERAND_FLAG_SIGNED)) != 0u
                || (native_c5 && (c5_high_base || c5_high_index))
                || (((instruction->opcode_flags
                        & CDISASM_PREFIX_SEGMENT) != 0u)
                    != ((operand->flags
                        & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0u))
                || (((instruction->opcode_flags
                        & CDISASM_PREFIX_SEGMENT) != 0u)
                    != (operand->segment_reg
                        != CDISASM_X86_REG_NONE))
                || !valid_modrm_memory_encoding(
                    instruction, operand, 0)) {
                return 0;
            }
        } else if (operand->reg < register_base
            || operand->reg > register_base
                + (native_c5 && index == 2u ? 7u : 15u)
            || operand->flags != 0u) {
            return 0;
        }
    }

    return register_low3_matches(
               instruction->opcode[0].reg,
               register_base,
               (uint8_t)((instruction->encoding.modrm >> 3)
                   & UINT8_C(7)))
        && (memory_form
            || register_low3_matches(
                instruction->opcode[2].reg,
                register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))));
}

static int valid_evex_packed_add_sub_minmax_groups(
    const cdisasm_instruction *instruction,
    int bw_family,
    unsigned int vector_size,
    int *allow_egpr)
{
    const unsigned int provenance =
        exact_instruction_provenance(instruction);
    const int avx512_route = cdisasm_instruction_has_x86_group(
        instruction,CDISASM_X86_GROUP_AVX512F);
    const int avx10_route = cdisasm_instruction_has_x86_group(
        instruction,CDISASM_X86_GROUP_AVX10_1);
    const int apx = cdisasm_instruction_has_x86_group(
        instruction,CDISASM_X86_GROUP_APX_F);
    size_t expected = 0u;

    *allow_egpr = apx;
    if (avx512_route == avx10_route) {
        return 0;
    }
    if ((provenance & 1u) != 0u
        && instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_I386) {
        return 0;
    }
    if ((provenance & 2u) != 0u
        && instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_AMD64) {
        return 0;
    }
    if (instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_AVX) {
        return 0;
    }
    if (avx512_route) {
        if (instruction->x86_group_ids[expected++]
                != CDISASM_X86_GROUP_AVX512F
            || (bw_family
                && instruction->x86_group_ids[expected++]
                    != CDISASM_X86_GROUP_AVX512BW)
            || (vector_size < 64u
                && instruction->x86_group_ids[expected++]
                    != CDISASM_X86_GROUP_AVX512VL)) {
            return 0;
        }
    } else if (instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_AVX10_1) {
        return 0;
    }
    if (apx && instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_APX_F) {
        return 0;
    }
    return expected == instruction->x86_group_count;
}

static int valid_exact_avx512f_width_groups(
    const cdisasm_instruction *instruction,
    unsigned int vector_size,
    int *allow_egpr)
{
    const unsigned int provenance =
        exact_instruction_provenance(instruction);
    const int avx512_route = cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512F);
    const int avx10_route = cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX10_1);
    const int apx = cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F);
    const cdisasm_x86_group_id width_group = vector_size == 16u
        ? CDISASM_X86_GROUP_AVX512F_128
        : vector_size == 32u ? CDISASM_X86_GROUP_AVX512F_256
                             : CDISASM_X86_GROUP_AVX512F_512;
    size_t expected = 0u;

    *allow_egpr = apx;
    if (avx512_route == avx10_route) {
        return 0;
    }
    if ((provenance & 1u) != 0u
        && instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_I386) {
        return 0;
    }
    if ((provenance & 2u) != 0u
        && instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_AMD64) {
        return 0;
    }
    if (instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_AVX) {
        return 0;
    }
    if (avx512_route) {
        if (instruction->x86_group_ids[expected++]
                != CDISASM_X86_GROUP_AVX512F
            || (vector_size < 64u
                && instruction->x86_group_ids[expected++]
                    != CDISASM_X86_GROUP_AVX512VL)) {
            return 0;
        }
    } else if (instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_AVX10_1) {
        return 0;
    }
    if (apx && instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_APX_F) {
        return 0;
    }
    return instruction->x86_group_ids[expected++] == width_group
        && expected == instruction->x86_group_count;
}

static int valid_vex_packed_add_sub_minmax_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int family_name =
        instruction->name_id == CDISASM_X86_NAME_VPADDB
        || instruction->name_id == CDISASM_X86_NAME_VPADDW
        || instruction->name_id == CDISASM_X86_NAME_VPADDD
        || instruction->name_id == CDISASM_X86_NAME_VPADDQ
        || instruction->name_id == CDISASM_X86_NAME_VPSUBB
        || instruction->name_id == CDISASM_X86_NAME_VPSUBW
        || instruction->name_id == CDISASM_X86_NAME_VPSUBD
        || instruction->name_id == CDISASM_X86_NAME_VPSUBQ
        || instruction->name_id == CDISASM_X86_NAME_VPMAXSB
        || instruction->name_id == CDISASM_X86_NAME_VPMAXSD
        || instruction->name_id == CDISASM_X86_NAME_VPMAXSQ
        || instruction->name_id == CDISASM_X86_NAME_VPMAXSW
        || instruction->name_id == CDISASM_X86_NAME_VPMAXUB
        || instruction->name_id == CDISASM_X86_NAME_VPMAXUD
        || instruction->name_id == CDISASM_X86_NAME_VPMAXUQ
        || instruction->name_id == CDISASM_X86_NAME_VPMAXUW
        || instruction->name_id == CDISASM_X86_NAME_VPMINSB
        || instruction->name_id == CDISASM_X86_NAME_VPMINSD
        || instruction->name_id == CDISASM_X86_NAME_VPMINSQ
        || instruction->name_id == CDISASM_X86_NAME_VPMINSW
        || instruction->name_id == CDISASM_X86_NAME_VPMINUB
        || instruction->name_id == CDISASM_X86_NAME_VPMINUD
        || instruction->name_id == CDISASM_X86_NAME_VPMINUQ
        || instruction->name_id == CDISASM_X86_NAME_VPMINUW;
    static const struct evex_shape {
        uint16_t name;
        uint16_t xmm_memory;
        uint16_t ymm_memory;
        uint16_t zmm_memory;
        uint8_t element_size;
        uint8_t bw_family;
    } evex_shapes[] = {
        {CDISASM_X86_NAME_VPADDB,6166,6170,6172,1,1},
        {CDISASM_X86_NAME_VPADDW,6236,6240,6242,2,1},
        {CDISASM_X86_NAME_VPADDD,6176,6180,6182,4,0},
        {CDISASM_X86_NAME_VPADDQ,6186,6190,6192,8,0},
        {CDISASM_X86_NAME_VPSUBB,8181,8185,8187,1,1},
        {CDISASM_X86_NAME_VPSUBW,8251,8255,8257,2,1},
        {CDISASM_X86_NAME_VPSUBD,8191,8195,8197,4,0},
        {CDISASM_X86_NAME_VPSUBQ,8201,8205,8207,8,0},
        {CDISASM_X86_NAME_VPMAXSB,7162,7164,7168,1,1},
        {CDISASM_X86_NAME_VPMAXSD,7172,7174,7178,4,0},
        {CDISASM_X86_NAME_VPMAXSQ,7180,7182,7184,8,0},
        {CDISASM_X86_NAME_VPMAXSW,7188,7190,7194,2,1},
        {CDISASM_X86_NAME_VPMAXUB,7198,7202,7204,1,1},
        {CDISASM_X86_NAME_VPMAXUD,7208,7212,7214,4,0},
        {CDISASM_X86_NAME_VPMAXUQ,7216,7218,7220,8,0},
        {CDISASM_X86_NAME_VPMAXUW,7224,7228,7230,2,1},
        {CDISASM_X86_NAME_VPMINSB,7234,7236,7240,1,1},
        {CDISASM_X86_NAME_VPMINSD,7244,7246,7250,4,0},
        {CDISASM_X86_NAME_VPMINSQ,7252,7254,7256,8,0},
        {CDISASM_X86_NAME_VPMINSW,7260,7262,7266,2,1},
        {CDISASM_X86_NAME_VPMINUB,7270,7274,7276,1,1},
        {CDISASM_X86_NAME_VPMINUD,7280,7284,7286,4,0},
        {CDISASM_X86_NAME_VPMINUQ,7288,7290,7292,8,0},
        {CDISASM_X86_NAME_VPMINUW,7296,7300,7302,2,1}
    };
    const unsigned int legacy_prefix_count =
        ((instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
        + ((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u);
    cdisasm_x86_name_id expected_name = CDISASM_X86_NAME_NONE;
    cdisasm_x86_form_id xmm_base = 0u;
    cdisasm_x86_form_id ymm_base = 0u;
    int classic_form;
    int ymm;
    int memory_form;
    int native_c5;
    unsigned int vector_size;
    cdisasm_x86_reg_id register_base;
    const cdisasm_opcode *source = &instruction->opcode[2];
    const struct evex_shape *evex_shape = NULL;
    int c5_high_base;
    int c5_high_index;
    size_t index;

    for (index = 0u;
         index < sizeof(evex_shapes) / sizeof(evex_shapes[0]);
         ++index) {
        const struct evex_shape *candidate = &evex_shapes[index];

        if (instruction->form_id == candidate->xmm_memory
            || instruction->form_id == candidate->xmm_memory + 1u
            || instruction->form_id == candidate->ymm_memory
            || instruction->form_id == candidate->ymm_memory + 1u
            || instruction->form_id == candidate->zmm_memory
            || instruction->form_id == candidate->zmm_memory + 1u) {
            evex_shape = candidate;
            break;
        }
    }

    if ((instruction->form_id >= UINT16_C(6164)
            && instruction->form_id <= UINT16_C(6165))
        || (instruction->form_id >= UINT16_C(6168)
            && instruction->form_id <= UINT16_C(6169))) {
        expected_name = CDISASM_X86_NAME_VPADDB;
        xmm_base = UINT16_C(6164);
        ymm_base = UINT16_C(6168);
    } else if ((instruction->form_id >= UINT16_C(6174)
            && instruction->form_id <= UINT16_C(6175))
        || (instruction->form_id >= UINT16_C(6178)
            && instruction->form_id <= UINT16_C(6179))) {
        expected_name = CDISASM_X86_NAME_VPADDD;
        xmm_base = UINT16_C(6174);
        ymm_base = UINT16_C(6178);
    } else if ((instruction->form_id >= UINT16_C(6184)
            && instruction->form_id <= UINT16_C(6185))
        || (instruction->form_id >= UINT16_C(6188)
            && instruction->form_id <= UINT16_C(6189))) {
        expected_name = CDISASM_X86_NAME_VPADDQ;
        xmm_base = UINT16_C(6184);
        ymm_base = UINT16_C(6188);
    } else if ((instruction->form_id >= UINT16_C(6234)
            && instruction->form_id <= UINT16_C(6235))
        || (instruction->form_id >= UINT16_C(6238)
            && instruction->form_id <= UINT16_C(6239))) {
        expected_name = CDISASM_X86_NAME_VPADDW;
        xmm_base = UINT16_C(6234);
        ymm_base = UINT16_C(6238);
    } else if ((instruction->form_id >= UINT16_C(8179)
            && instruction->form_id <= UINT16_C(8180))
        || (instruction->form_id >= UINT16_C(8183)
            && instruction->form_id <= UINT16_C(8184))) {
        expected_name = CDISASM_X86_NAME_VPSUBB;
        xmm_base = UINT16_C(8179);
        ymm_base = UINT16_C(8183);
    } else if ((instruction->form_id >= UINT16_C(8189)
            && instruction->form_id <= UINT16_C(8190))
        || (instruction->form_id >= UINT16_C(8193)
            && instruction->form_id <= UINT16_C(8194))) {
        expected_name = CDISASM_X86_NAME_VPSUBD;
        xmm_base = UINT16_C(8189);
        ymm_base = UINT16_C(8193);
    } else if ((instruction->form_id >= UINT16_C(8199)
            && instruction->form_id <= UINT16_C(8200))
        || (instruction->form_id >= UINT16_C(8203)
            && instruction->form_id <= UINT16_C(8204))) {
        expected_name = CDISASM_X86_NAME_VPSUBQ;
        xmm_base = UINT16_C(8199);
        ymm_base = UINT16_C(8203);
    } else if ((instruction->form_id >= UINT16_C(8249)
            && instruction->form_id <= UINT16_C(8250))
        || (instruction->form_id >= UINT16_C(8253)
            && instruction->form_id <= UINT16_C(8254))) {
        expected_name = CDISASM_X86_NAME_VPSUBW;
        xmm_base = UINT16_C(8249);
        ymm_base = UINT16_C(8253);
    } else if ((instruction->form_id >= UINT16_C(7160)
            && instruction->form_id <= UINT16_C(7161))
        || (instruction->form_id >= UINT16_C(7166)
            && instruction->form_id <= UINT16_C(7167))) {
        expected_name = CDISASM_X86_NAME_VPMAXSB;
        xmm_base = UINT16_C(7160);
        ymm_base = UINT16_C(7166);
    } else if ((instruction->form_id >= UINT16_C(7170)
            && instruction->form_id <= UINT16_C(7171))
        || (instruction->form_id >= UINT16_C(7176)
            && instruction->form_id <= UINT16_C(7177))) {
        expected_name = CDISASM_X86_NAME_VPMAXSD;
        xmm_base = UINT16_C(7170);
        ymm_base = UINT16_C(7176);
    } else if ((instruction->form_id >= UINT16_C(7186)
            && instruction->form_id <= UINT16_C(7187))
        || (instruction->form_id >= UINT16_C(7192)
            && instruction->form_id <= UINT16_C(7193))) {
        expected_name = CDISASM_X86_NAME_VPMAXSW;
        xmm_base = UINT16_C(7186);
        ymm_base = UINT16_C(7192);
    } else if ((instruction->form_id >= UINT16_C(7196)
            && instruction->form_id <= UINT16_C(7197))
        || (instruction->form_id >= UINT16_C(7200)
            && instruction->form_id <= UINT16_C(7201))) {
        expected_name = CDISASM_X86_NAME_VPMAXUB;
        xmm_base = UINT16_C(7196);
        ymm_base = UINT16_C(7200);
    } else if ((instruction->form_id >= UINT16_C(7206)
            && instruction->form_id <= UINT16_C(7207))
        || (instruction->form_id >= UINT16_C(7210)
            && instruction->form_id <= UINT16_C(7211))) {
        expected_name = CDISASM_X86_NAME_VPMAXUD;
        xmm_base = UINT16_C(7206);
        ymm_base = UINT16_C(7210);
    } else if ((instruction->form_id >= UINT16_C(7222)
            && instruction->form_id <= UINT16_C(7223))
        || (instruction->form_id >= UINT16_C(7226)
            && instruction->form_id <= UINT16_C(7227))) {
        expected_name = CDISASM_X86_NAME_VPMAXUW;
        xmm_base = UINT16_C(7222);
        ymm_base = UINT16_C(7226);
    } else if ((instruction->form_id >= UINT16_C(7232)
            && instruction->form_id <= UINT16_C(7233))
        || (instruction->form_id >= UINT16_C(7238)
            && instruction->form_id <= UINT16_C(7239))) {
        expected_name = CDISASM_X86_NAME_VPMINSB;
        xmm_base = UINT16_C(7232);
        ymm_base = UINT16_C(7238);
    } else if ((instruction->form_id >= UINT16_C(7242)
            && instruction->form_id <= UINT16_C(7243))
        || (instruction->form_id >= UINT16_C(7248)
            && instruction->form_id <= UINT16_C(7249))) {
        expected_name = CDISASM_X86_NAME_VPMINSD;
        xmm_base = UINT16_C(7242);
        ymm_base = UINT16_C(7248);
    } else if ((instruction->form_id >= UINT16_C(7258)
            && instruction->form_id <= UINT16_C(7259))
        || (instruction->form_id >= UINT16_C(7264)
            && instruction->form_id <= UINT16_C(7265))) {
        expected_name = CDISASM_X86_NAME_VPMINSW;
        xmm_base = UINT16_C(7258);
        ymm_base = UINT16_C(7264);
    } else if ((instruction->form_id >= UINT16_C(7268)
            && instruction->form_id <= UINT16_C(7269))
        || (instruction->form_id >= UINT16_C(7272)
            && instruction->form_id <= UINT16_C(7273))) {
        expected_name = CDISASM_X86_NAME_VPMINUB;
        xmm_base = UINT16_C(7268);
        ymm_base = UINT16_C(7272);
    } else if ((instruction->form_id >= UINT16_C(7278)
            && instruction->form_id <= UINT16_C(7279))
        || (instruction->form_id >= UINT16_C(7282)
            && instruction->form_id <= UINT16_C(7283))) {
        expected_name = CDISASM_X86_NAME_VPMINUD;
        xmm_base = UINT16_C(7278);
        ymm_base = UINT16_C(7282);
    } else if ((instruction->form_id >= UINT16_C(7294)
            && instruction->form_id <= UINT16_C(7295))
        || (instruction->form_id >= UINT16_C(7298)
            && instruction->form_id <= UINT16_C(7299))) {
        expected_name = CDISASM_X86_NAME_VPMINUW;
        xmm_base = UINT16_C(7294);
        ymm_base = UINT16_C(7298);
    }

    classic_form = expected_name != CDISASM_X86_NAME_NONE;
    if (evex_shape != NULL
        || (family_name && modern_prefix == CDISASM_PREFIX_EVEX)) {
        const uint32_t evex_allowed_flags = CDISASM_PREFIX_EVEX
            | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
        const unsigned int evex_legacy_prefix_count =
            ((instruction->opcode_flags
                & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
            + ((instruction->opcode_flags
                & CDISASM_PREFIX_SEGMENT) != 0u);
        unsigned int evex_vector_size = 0u;
        cdisasm_x86_reg_id evex_register_base = CDISASM_X86_REG_NONE;
        int evex_memory_form = 0;
        int allow_egpr = 0;

        if (evex_shape != NULL) {
            evex_memory_form =
                instruction->form_id == evex_shape->xmm_memory
                || instruction->form_id == evex_shape->ymm_memory
                || instruction->form_id == evex_shape->zmm_memory;
            if (instruction->form_id == evex_shape->xmm_memory
                || instruction->form_id
                    == evex_shape->xmm_memory + 1u) {
                evex_vector_size = 16u;
                evex_register_base = CDISASM_X86_REG_XMM0;
            } else if (instruction->form_id == evex_shape->ymm_memory
                || instruction->form_id
                    == evex_shape->ymm_memory + 1u) {
                evex_vector_size = 32u;
                evex_register_base = CDISASM_X86_REG_YMM0;
            } else {
                evex_vector_size = 64u;
                evex_register_base = CDISASM_X86_REG_ZMM0;
            }
        }

        if (evex_shape == NULL
            || instruction->name_id != evex_shape->name
            || modern_prefix != CDISASM_PREFIX_EVEX
            || (instruction->opcode_flags & ~evex_allowed_flags) != 0u
            || instruction->operand_count != 3u
            || (instruction->mask_mode != CDISASM_X86_MASK_NONE
                && instruction->mask_mode != CDISASM_X86_MASK_MERGE
                && instruction->mask_mode != CDISASM_X86_MASK_ZERO)
            || ((instruction->mask_mode == CDISASM_X86_MASK_NONE)
                != (instruction->mask_reg == CDISASM_X86_REG_NONE))
            || (instruction->mask_mode != CDISASM_X86_MASK_NONE
                && (instruction->mask_reg < CDISASM_X86_REG_K1
                    || instruction->mask_reg > CDISASM_X86_REG_K7))
            || instruction->rounding != CDISASM_X86_ROUNDING_NONE
            || instruction->sae != CDISASM_X86_SAE_NONE
            || instruction->opcode_groups != CDISASM_GROUP_NONE
            || instruction->branch_target != 0u
            || instruction->encoding.prefix_size
                < 4u + evex_legacy_prefix_count
            || (instruction->encoding.prefix_size > 4u
                && (instruction->opcode_flags
                    & (CDISASM_PREFIX_ADDRESS_SIZE
                        | CDISASM_PREFIX_SEGMENT)) == 0u)
            || instruction->encoding.opcode_offset
                != instruction->encoding.prefix_size
            || instruction->encoding.opcode_size != 1u
            || instruction->encoding.modrm_offset
                != instruction->encoding.opcode_offset + 1u
            || (((instruction->encoding.modrm & UINT8_C(0xc0))
                    == UINT8_C(0xc0)) == evex_memory_form)
            || (!evex_memory_form
                && (instruction->encoding.sib_offset != 0u
                    || instruction->encoding.displacement_offset != 0u
                    || instruction->encoding.displacement_size != 0u))
            || instruction->encoding.immediate_count != 0u
            || instruction->encoding.selector_offset != 0u
            || !valid_evex_packed_add_sub_minmax_groups(
                instruction,evex_shape->bw_family,
                evex_vector_size,&allow_egpr)) {
            return 0;
        }

        for (index = 0u; index < 3u; ++index) {
            const cdisasm_opcode *operand = &instruction->opcode[index];
            const int is_memory = evex_memory_form && index == 2u;
            const cdisasm_operand_access expected_access = index == 0u
                && instruction->mask_mode == CDISASM_X86_MASK_MERGE
                    ? CDISASM_OPERAND_ACCESS_READ_WRITE
                    : index == 0u ? CDISASM_OPERAND_ACCESS_WRITE
                                  : CDISASM_OPERAND_ACCESS_READ;

            if (operand->type != (is_memory
                    ? CDISASM_OPERAND_MEMORY
                    : CDISASM_OPERAND_REGISTER)
                || operand->access != expected_access) {
                return 0;
            }
            if (is_memory) {
                const int full_memory =
                    operand->size == evex_vector_size
                    && operand->broadcast == CDISASM_X86_BROADCAST_NONE;
                const int broadcast_memory = !evex_shape->bw_family
                    && operand->size == evex_shape->element_size
                    && operand->broadcast == (cdisasm_x86_broadcast)(
                        evex_vector_size / evex_shape->element_size);

                if (!(full_memory || broadcast_memory)
                    || (operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                            | CDISASM_OPERAND_FLAG_SIGNED)) != 0u
                    || (((instruction->opcode_flags
                            & CDISASM_PREFIX_SEGMENT) != 0u)
                        != ((operand->flags
                            & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0u))
                    || (((instruction->opcode_flags
                            & CDISASM_PREFIX_SEGMENT) != 0u)
                        != (operand->segment_reg
                            != CDISASM_X86_REG_NONE))
                    || !valid_modrm_memory_encoding(
                        instruction,operand,allow_egpr)) {
                    return 0;
                }
            } else if (operand->size != evex_vector_size
                || operand->reg < evex_register_base
                || operand->reg > evex_register_base + 31u
                || operand->flags != 0u
                || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
                return 0;
            }
        }

        return register_low3_matches(
                   instruction->opcode[0].reg,
                   evex_register_base,
                   (uint8_t)((instruction->encoding.modrm >> 3)
                       & UINT8_C(7)))
            && (evex_memory_form
                || register_low3_matches(
                    instruction->opcode[2].reg,
                    evex_register_base,
                    (uint8_t)(instruction->encoding.modrm & UINT8_C(7))));
    }
    if (!classic_form && !family_name) {
        return 1;
    }
    if (!family_name || !classic_form
        || instruction->name_id != expected_name) {
        return 0;
    }

    ymm = instruction->form_id == ymm_base
        || instruction->form_id == ymm_base + UINT16_C(1);
    memory_form = instruction->form_id == xmm_base
        || instruction->form_id == ymm_base;
    vector_size = ymm ? 32u : 16u;
    register_base = ymm ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    native_c5 = instruction->encoding.prefix_size
        < 3u + legacy_prefix_count;
    c5_high_base =
        (source->base_reg >= CDISASM_X86_REG_R8W
            && source->base_reg <= CDISASM_X86_REG_R15W)
        || (source->base_reg >= CDISASM_X86_REG_R8D
            && source->base_reg <= CDISASM_X86_REG_R15D)
        || (source->base_reg >= CDISASM_X86_REG_R8
            && source->base_reg <= CDISASM_X86_REG_R15);
    c5_high_index =
        (source->index_reg >= CDISASM_X86_REG_R8W
            && source->index_reg <= CDISASM_X86_REG_R15W)
        || (source->index_reg >= CDISASM_X86_REG_R8D
            && source->index_reg <= CDISASM_X86_REG_R15D)
        || (source->index_reg >= CDISASM_X86_REG_R8
            && source->index_reg <= CDISASM_X86_REG_R15);

    if ((instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 3u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size
            < 2u + legacy_prefix_count
        || (instruction->encoding.prefix_size > 3u
            && (instruction->opcode_flags
                & (CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u)
        || instruction->encoding.opcode_offset
            != instruction->encoding.prefix_size
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpcmpeqq_groups(instruction, ymm)) {
        return 0;
    }

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int is_memory = memory_form && index == 2u;

        if (operand->type != (is_memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != vector_size
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (is_memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                        | CDISASM_OPERAND_FLAG_SIGNED)) != 0u
                || (native_c5 && (c5_high_base || c5_high_index))
                || (((instruction->opcode_flags
                        & CDISASM_PREFIX_SEGMENT) != 0u)
                    != ((operand->flags
                        & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0u))
                || (((instruction->opcode_flags
                        & CDISASM_PREFIX_SEGMENT) != 0u)
                    != (operand->segment_reg
                        != CDISASM_X86_REG_NONE))
                || !valid_modrm_memory_encoding(instruction, operand, 0)) {
                return 0;
            }
        } else if (operand->reg < register_base
            || operand->reg > register_base
                + (native_c5 && index == 2u ? 7u : 15u)
            || operand->flags != 0u) {
            return 0;
        }
    }

    return register_low3_matches(
               instruction->opcode[0].reg,
               register_base,
               (uint8_t)((instruction->encoding.modrm >> 3)
                   & UINT8_C(7)))
        && (memory_form
            || register_low3_matches(
                instruction->opcode[2].reg,
                register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))));
}

static int valid_vperm2_128_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int perm_name =
        instruction->name_id == CDISASM_X86_NAME_VPERM2F128
        || instruction->name_id == CDISASM_X86_NAME_VPERM2I128;
    const int perm_form = instruction->form_id >= UINT16_C(6770)
        && instruction->form_id <= UINT16_C(6773);
    const int is_integer = instruction->name_id
        == CDISASM_X86_NAME_VPERM2I128;
    const cdisasm_x86_form_id base = is_integer
        ? UINT16_C(6772) : UINT16_C(6770);
    const int memory_form = instruction->form_id == UINT16_C(6770)
        || instruction->form_id == UINT16_C(6772);
    size_t index;

    /* Match name and exact form independently.  These names have no EVEX
     * siblings, so any partial name/form mutation—including an opaque
     * generated object—must remain owned and fail this VEX-only recipe. */
    if (!perm_name && !perm_form) {
        return 1;
    }
    if (!perm_name || !perm_form
        || instruction->form_id < base
        || instruction->form_id > base + UINT16_C(1)
        || instruction->operand_count != 4u
        || (instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || (instruction->opcode_flags
            & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
                | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
            != CDISASM_PREFIX_VEX
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 1u
        || instruction->encoding.immediate_size[0] != 1u
        || instruction->encoding.immediate_offset[0]
            != instruction->opcode_size - 1u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, is_integer)) {
        return 0;
    }

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = memory_form && index == 2u;

        if (operand->type != (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != 32u
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u) {
                return 0;
            }
        } else if (operand->reg < CDISASM_X86_REG_YMM0
            || operand->reg > CDISASM_X86_REG_YMM15
            || operand->flags != 0u) {
            return 0;
        }
    }
    return instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE
        && instruction->opcode[3].size == 1u
        && instruction->opcode[3].access
            == CDISASM_OPERAND_ACCESS_READ
        && instruction->opcode[3].flags == 0u
        && instruction->opcode[3].broadcast
            == CDISASM_X86_BROADCAST_NONE
        && instruction->opcode[3].imm <= UINT8_MAX;
}

static int valid_vpermd_vpermps_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int perm_name = instruction->name_id == CDISASM_X86_NAME_VPERMD
        || instruction->name_id == CDISASM_X86_NAME_VPERMPS;
    const int perm_form = instruction->form_id == UINT16_C(6780)
        || instruction->form_id == UINT16_C(6781)
        || instruction->form_id == UINT16_C(6886)
        || instruction->form_id == UINT16_C(6887);
    const int evex_permd_form = instruction->form_id >= UINT16_C(6782)
        && instruction->form_id <= UINT16_C(6785);
    const int evex_permps_form = instruction->form_id == UINT16_C(6884)
        || instruction->form_id == UINT16_C(6885)
        || instruction->form_id == UINT16_C(6888)
        || instruction->form_id == UINT16_C(6889);
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int integer = instruction->name_id == CDISASM_X86_NAME_VPERMD;
    const cdisasm_x86_form_id base = integer
        ? UINT16_C(6780) : UINT16_C(6886);
    const int memory_form = instruction->form_id == UINT16_C(6780)
        || instruction->form_id == UINT16_C(6886);
    size_t index;

    /* The generated decoder already owns eight exact EVEX siblings.  Admit
     * only their matching name/form/prefix relationship to the generic EVEX
     * schema; a shared-name EVEX object with any other form remains a
     * forgery.  The four classic forms are then owned independently from the
     * name so partial VEX mutations cannot evade this recipe. */
    if (evex_permd_form || evex_permps_form
        || (perm_name && modern_prefix == CDISASM_PREFIX_EVEX)) {
        return modern_prefix == CDISASM_PREFIX_EVEX
            && (instruction->opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u
            && (instruction->opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u
            && ((evex_permd_form
                    && instruction->name_id == CDISASM_X86_NAME_VPERMD)
                || (evex_permps_form
                    && instruction->name_id == CDISASM_X86_NAME_VPERMPS));
    }
    if (!perm_name && !perm_form) {
        return 1;
    }
    if (!perm_name || !perm_form
        || instruction->form_id < base
        || instruction->form_id > base + UINT16_C(1)
        || instruction->operand_count != 3u
        || (instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 1)) {
        return 0;
    }

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = memory_form && index == 2u;

        if (operand->type != (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != 32u
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u) {
                return 0;
            }
        } else if (operand->reg < CDISASM_X86_REG_YMM0
            || operand->reg > CDISASM_X86_REG_YMM15
            || operand->flags != 0u) {
            return 0;
        }
    }
    return 1;
}

static int valid_vpermilpd_vpermilps_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int perm_name =
        instruction->name_id == CDISASM_X86_NAME_VPERMILPD
        || instruction->name_id == CDISASM_X86_NAME_VPERMILPS;
    const int classic_form =
        (instruction->form_id >= UINT16_C(6834)
            && instruction->form_id <= UINT16_C(6837))
        || (instruction->form_id >= UINT16_C(6846)
            && instruction->form_id <= UINT16_C(6849))
        || (instruction->form_id >= UINT16_C(6854)
            && instruction->form_id <= UINT16_C(6857))
        || (instruction->form_id >= UINT16_C(6866)
            && instruction->form_id <= UINT16_C(6869));
    const int evex_pd_form =
        (instruction->form_id >= UINT16_C(6838)
            && instruction->form_id <= UINT16_C(6845))
        || (instruction->form_id >= UINT16_C(6850)
            && instruction->form_id <= UINT16_C(6853));
    const int evex_ps_form =
        (instruction->form_id >= UINT16_C(6858)
            && instruction->form_id <= UINT16_C(6865))
        || (instruction->form_id >= UINT16_C(6870)
            && instruction->form_id <= UINT16_C(6873));
    const int is_double =
        instruction->name_id == CDISASM_X86_NAME_VPERMILPD;
    unsigned int vector_size;
    cdisasm_x86_reg_id register_base;
    int variable_form;
    int memory_form;
    size_t memory_index;
    size_t index;

    /* Generated EVEX siblings and classic VEX forms share names but not
     * recipes.  Own either side of each name/form relationship so a single
     * forged field cannot escape the corresponding exact schema. */
    if (evex_pd_form || evex_ps_form
        || (perm_name && modern_prefix == CDISASM_PREFIX_EVEX)) {
        const uint32_t allowed_flags = CDISASM_PREFIX_EVEX
            | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT
            | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        const int matching_name = (evex_pd_form
                && instruction->name_id == CDISASM_X86_NAME_VPERMILPD)
            || (evex_ps_form
                && instruction->name_id == CDISASM_X86_NAME_VPERMILPS);
        unsigned int scalar_size;
        cdisasm_x86_group_id width_group;
        int allow_egpr;

        if (evex_pd_form) {
            if (instruction->form_id <= UINT16_C(6841)) {
                vector_size = 16u;
            } else if (instruction->form_id <= UINT16_C(6845)) {
                vector_size = 32u;
            } else {
                vector_size = 64u;
            }
            variable_form = instruction->form_id == UINT16_C(6840)
                || instruction->form_id == UINT16_C(6841)
                || instruction->form_id == UINT16_C(6844)
                || instruction->form_id == UINT16_C(6845)
                || instruction->form_id == UINT16_C(6852)
                || instruction->form_id == UINT16_C(6853);
        } else {
            if (instruction->form_id <= UINT16_C(6861)) {
                vector_size = 16u;
            } else if (instruction->form_id <= UINT16_C(6865)) {
                vector_size = 32u;
            } else {
                vector_size = 64u;
            }
            variable_form = instruction->form_id == UINT16_C(6860)
                || instruction->form_id == UINT16_C(6861)
                || instruction->form_id == UINT16_C(6864)
                || instruction->form_id == UINT16_C(6865)
                || instruction->form_id == UINT16_C(6872)
                || instruction->form_id == UINT16_C(6873);
        }
        memory_form = (instruction->form_id & UINT16_C(1)) == 0u;
        memory_index = variable_form ? 2u : 1u;
        scalar_size = evex_pd_form ? 8u : 4u;
        if (vector_size == 16u) {
            register_base = CDISASM_X86_REG_XMM0;
            width_group = CDISASM_X86_GROUP_AVX512F_128;
        } else if (vector_size == 32u) {
            register_base = CDISASM_X86_REG_YMM0;
            width_group = CDISASM_X86_GROUP_AVX512F_256;
        } else {
            register_base = CDISASM_X86_REG_ZMM0;
            width_group = CDISASM_X86_GROUP_AVX512F_512;
        }

        if (!matching_name || modern_prefix != CDISASM_PREFIX_EVEX
            || (instruction->opcode_flags & ~allowed_flags) != 0u
            || (instruction->opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u
            || instruction->operand_count != 3u
            || instruction->rounding != CDISASM_X86_ROUNDING_NONE
            || instruction->sae != CDISASM_X86_SAE_NONE
            || instruction->opcode_groups != CDISASM_GROUP_NONE
            || instruction->branch_target != 0u
            || instruction->encoding.prefix_size < 4u
            || instruction->encoding.opcode_size != 1u
            || instruction->encoding.modrm_offset
                != instruction->encoding.opcode_offset + 1u
            || (((instruction->encoding.modrm & UINT8_C(0xc0))
                    == UINT8_C(0xc0)) == memory_form)
            || (!memory_form
                && (instruction->encoding.sib_offset != 0u
                    || instruction->encoding.displacement_offset != 0u
                    || instruction->encoding.displacement_size != 0u))
            || instruction->encoding.immediate_count
                != (variable_form ? 0u : 1u)
            || (!variable_form
                && (instruction->encoding.immediate_size[0] != 1u
                    || instruction->encoding.immediate_offset[0]
                        != instruction->opcode_size - 1u))
            || instruction->encoding.selector_offset != 0u
            || !valid_generated_evex_width_groups(
                instruction, width_group, &allow_egpr)) {
            return 0;
        }

        for (index = 0u; index < (variable_form ? 3u : 2u); ++index) {
            const cdisasm_opcode *operand = &instruction->opcode[index];
            const int memory = memory_form && index == memory_index;

            if (operand->type != (memory
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
                || operand->access != (index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ)) {
                return 0;
            }
            if (memory) {
                if ((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                    || !((operand->size == vector_size
                            && operand->broadcast
                                == CDISASM_X86_BROADCAST_NONE)
                    || (operand->size == scalar_size
                            && operand->broadcast
                                == (cdisasm_x86_broadcast)(
                                    vector_size / scalar_size)))
                    || !valid_modrm_memory_encoding(
                        instruction, operand, allow_egpr)) {
                    return 0;
                }
            } else if (operand->reg < register_base
                || operand->reg > register_base + 31u
                || operand->size != vector_size
                || operand->flags != 0u
                || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
                return 0;
            }
        }
        if (!register_low3_matches(instruction->opcode[0].reg,
                register_base,
                (uint8_t)((instruction->encoding.modrm >> 3)
                    & UINT8_C(7)))
            || (!memory_form
                && !register_low3_matches(
                    instruction->opcode[memory_index].reg, register_base,
                    (uint8_t)(instruction->encoding.modrm & UINT8_C(7))))) {
            return 0;
        }
        if (!variable_form) {
            const cdisasm_opcode *immediate = &instruction->opcode[2];

            if (immediate->type != CDISASM_OPERAND_IMMEDIATE
                || immediate->size != 1u
                || immediate->access != CDISASM_OPERAND_ACCESS_READ
                || immediate->flags != 0u
                || immediate->broadcast != CDISASM_X86_BROADCAST_NONE
                || immediate->imm > UINT8_MAX) {
                return 0;
            }
        }
        return 1;
    }

    if (!perm_name && !classic_form) {
        return 1;
    }
    if (!perm_name || !classic_form) {
        return 0;
    }
    {
        const uint32_t allowed_flags = CDISASM_PREFIX_VEX
            | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
        cdisasm_x86_form_id base;
        cdisasm_x86_form_id relative;

        if (is_double) {
            base = instruction->form_id >= UINT16_C(6846)
                ? UINT16_C(6846) : UINT16_C(6834);
        } else {
            base = instruction->form_id >= UINT16_C(6866)
                ? UINT16_C(6866) : UINT16_C(6854);
        }
        if (instruction->form_id < base
            || instruction->form_id > base + UINT16_C(3)) {
            return 0;
        }
        relative = instruction->form_id - base;
        vector_size = base == UINT16_C(6834)
                || base == UINT16_C(6854)
            ? 16u : 32u;
        register_base = vector_size == 16u
            ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
        variable_form = relative >= UINT16_C(2);
        memory_form = (relative & UINT16_C(1)) == 0u;
        memory_index = variable_form ? 2u : 1u;

        if ((instruction->opcode_flags & ~allowed_flags) != 0u
            || modern_prefix != CDISASM_PREFIX_VEX
            || instruction->operand_count != 3u
            || instruction->mask_mode != CDISASM_X86_MASK_NONE
            || instruction->mask_reg != CDISASM_X86_REG_NONE
            || instruction->rounding != CDISASM_X86_ROUNDING_NONE
            || instruction->sae != CDISASM_X86_SAE_NONE
            || instruction->opcode_groups != CDISASM_GROUP_NONE
            || instruction->branch_target != 0u
            || instruction->encoding.prefix_size < 3u
            || instruction->encoding.opcode_size != 1u
            || instruction->encoding.modrm_offset
                != instruction->encoding.opcode_offset + 1u
            || (((instruction->encoding.modrm & UINT8_C(0xc0))
                    == UINT8_C(0xc0)) == memory_form)
            || (!memory_form
                && (instruction->encoding.sib_offset != 0u
                    || instruction->encoding.displacement_offset != 0u
                    || instruction->encoding.displacement_size != 0u))
            || instruction->encoding.immediate_count
                != (variable_form ? 0u : 1u)
            || (!variable_form
                && (instruction->encoding.immediate_size[0] != 1u
                    || instruction->encoding.immediate_offset[0]
                        != instruction->opcode_size - 1u))
            || instruction->encoding.selector_offset != 0u
            || !valid_vpblend_groups(instruction, 0)) {
            return 0;
        }

        for (index = 0u; index < (variable_form ? 3u : 2u); ++index) {
            const cdisasm_opcode *operand = &instruction->opcode[index];
            const int memory = memory_form && index == memory_index;

            if (operand->type != (memory
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
                || operand->size != vector_size
                || operand->access != (index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ)
                || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
                return 0;
            }
            if (memory) {
                if ((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                    || !valid_modrm_memory_encoding(
                        instruction, operand, 0)) {
                    return 0;
                }
            } else if (operand->reg < register_base
                || operand->reg > register_base + 15u
                || operand->flags != 0u) {
                return 0;
            }
        }
        if (!register_low3_matches(instruction->opcode[0].reg,
                register_base,
                (uint8_t)((instruction->encoding.modrm >> 3)
                    & UINT8_C(7)))
            || (!memory_form
                && !register_low3_matches(
                    instruction->opcode[memory_index].reg, register_base,
                    (uint8_t)(instruction->encoding.modrm & UINT8_C(7))))) {
            return 0;
        }
        if (variable_form) {
            return 1;
        }
        return instruction->opcode[2].type == CDISASM_OPERAND_IMMEDIATE
            && instruction->opcode[2].size == 1u
            && instruction->opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ
            && instruction->opcode[2].flags == 0u
            && instruction->opcode[2].broadcast
                == CDISASM_X86_BROADCAST_NONE
            && instruction->opcode[2].imm <= UINT8_MAX;
    }
}

static int valid_vcmp_schema(const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int compare_name =
        instruction->name_id == CDISASM_X86_NAME_VCMPPD
        || instruction->name_id == CDISASM_X86_NAME_VCMPPS
        || instruction->name_id == CDISASM_X86_NAME_VCMPSD
        || instruction->name_id == CDISASM_X86_NAME_VCMPSS;
    const int pd_form = instruction->form_id >= UINT16_C(3595)
        && instruction->form_id <= UINT16_C(3598);
    const int ps_form = instruction->form_id >= UINT16_C(3611)
        && instruction->form_id <= UINT16_C(3614);
    const int sd_form = instruction->form_id >= UINT16_C(3617)
        && instruction->form_id <= UINT16_C(3618);
    const int ss_form = instruction->form_id >= UINT16_C(3623)
        && instruction->form_id <= UINT16_C(3624);
    const int classic_form = pd_form || ps_form || sd_form || ss_form;
    const int evex_pd_form = instruction->form_id >= UINT16_C(3589)
        && instruction->form_id <= UINT16_C(3594);
    const int evex_ps_form = instruction->form_id >= UINT16_C(3605)
        && instruction->form_id <= UINT16_C(3610);
    const int evex_sd_form = instruction->form_id >= UINT16_C(3615)
        && instruction->form_id <= UINT16_C(3616);
    const int evex_ss_form = instruction->form_id >= UINT16_C(3621)
        && instruction->form_id <= UINT16_C(3622);
    const int evex_form = evex_pd_form || evex_ps_form
        || evex_sd_form || evex_ss_form;
    const int evex_identity =
        (evex_pd_form
            && instruction->name_id == CDISASM_X86_NAME_VCMPPD)
        || (evex_ps_form
            && instruction->name_id == CDISASM_X86_NAME_VCMPPS)
        || (evex_sd_form
            && instruction->name_id == CDISASM_X86_NAME_VCMPSD)
        || (evex_ss_form
            && instruction->name_id == CDISASM_X86_NAME_VCMPSS);
    const int scalar = sd_form || ss_form;
    const int memory_form = classic_form
        && ((pd_form ? instruction->form_id - UINT16_C(3595)
             : ps_form ? instruction->form_id - UINT16_C(3611)
             : sd_form ? instruction->form_id - UINT16_C(3617)
                       : instruction->form_id - UINT16_C(3623))
            & UINT16_C(1)) == 0u;
    const unsigned int relative = pd_form
        ? instruction->form_id - UINT16_C(3595)
        : ps_form ? instruction->form_id - UINT16_C(3611) : 0u;
    const unsigned int vector_size = scalar || relative < 2u ? 16u : 32u;
    const unsigned int scalar_size = sd_form ? 8u : 4u;
    const cdisasm_x86_name_id expected_name = pd_form
        ? CDISASM_X86_NAME_VCMPPD
        : ps_form ? CDISASM_X86_NAME_VCMPPS
        : sd_form ? CDISASM_X86_NAME_VCMPSD
                  : CDISASM_X86_NAME_VCMPSS;
    const cdisasm_x86_reg_id vector_base = vector_size == 16u
        ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
    size_t index;

    /* Own the complete generated-EVEX recipe as well as both sides of every
     * classic relationship.  Generated provenance alone is not a schema:
     * without the immutable metadata, decorator, operand, and encoding
     * checks below a relabeled or mutated generated instruction could still
     * be formatted as a valid compare. */
    if (evex_form
        || (compare_name && modern_prefix == CDISASM_PREFIX_EVEX)) {
        const uint32_t evex_allowed_flags = CDISASM_PREFIX_EVEX
            | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT
            | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        const int evex_scalar = evex_sd_form || evex_ss_form;
        const unsigned int evex_relative = evex_pd_form
            ? instruction->form_id - UINT16_C(3589)
            : evex_ps_form
                ? instruction->form_id - UINT16_C(3605) : 0u;
        const unsigned int evex_vector_size = evex_scalar
            ? 16u : 16u << (evex_relative / 2u);
        const unsigned int evex_scalar_size =
            (evex_pd_form || evex_sd_form) ? 8u : 4u;
        const int evex_memory_form = (instruction->form_id & UINT16_C(1))
            != 0u;
        const cdisasm_x86_reg_id evex_register_base =
            evex_vector_size == 16u ? CDISASM_X86_REG_XMM0
            : evex_vector_size == 32u ? CDISASM_X86_REG_YMM0
                                      : CDISASM_X86_REG_ZMM0;
        const cdisasm_x86_group_id evex_width_group = evex_scalar
            ? CDISASM_X86_GROUP_AVX512F_SCALAR
            : evex_vector_size == 16u ? CDISASM_X86_GROUP_AVX512F_128
            : evex_vector_size == 32u ? CDISASM_X86_GROUP_AVX512F_256
                                      : CDISASM_X86_GROUP_AVX512F_512;
        const int may_sae = !evex_memory_form
            && (evex_scalar || evex_vector_size == 64u);
        int allow_egpr;

        if (!evex_identity
            || modern_prefix != CDISASM_PREFIX_EVEX
            || (instruction->opcode_flags & ~evex_allowed_flags) != 0u
            || (instruction->opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u
            || instruction->operand_count != 4u
            || (instruction->mask_mode != CDISASM_X86_MASK_NONE
                && instruction->mask_mode != CDISASM_X86_MASK_MERGE)
            || ((instruction->mask_mode == CDISASM_X86_MASK_NONE)
                != (instruction->mask_reg == CDISASM_X86_REG_NONE))
            || (instruction->mask_mode == CDISASM_X86_MASK_MERGE
                && (instruction->mask_reg < CDISASM_X86_REG_K1
                    || instruction->mask_reg > CDISASM_X86_REG_K7))
            || instruction->rounding != CDISASM_X86_ROUNDING_NONE
            || (instruction->sae != CDISASM_X86_SAE_NONE
                && (instruction->sae != CDISASM_X86_SAE_ENABLED
                    || !may_sae))
            || instruction->opcode_groups != CDISASM_GROUP_NONE
            || instruction->branch_target != 0u
            || instruction->encoding.prefix_size < 4u
            || instruction->encoding.opcode_size != 1u
            || instruction->encoding.modrm_offset
                != instruction->encoding.opcode_offset + 1u
            || (((instruction->encoding.modrm & UINT8_C(0xc0))
                    == UINT8_C(0xc0)) == evex_memory_form)
            || (!evex_memory_form
                && (instruction->encoding.sib_offset != 0u
                    || instruction->encoding.displacement_offset != 0u
                    || instruction->encoding.displacement_size != 0u))
            || instruction->encoding.immediate_count != 1u
            || instruction->encoding.immediate_size[0] != 1u
            || instruction->encoding.immediate_offset[0]
                != instruction->opcode_size - 1u
            || instruction->encoding.selector_offset != 0u
            || !valid_generated_evex_width_groups(
                instruction, evex_width_group, &allow_egpr)) {
            return 0;
        }

        if (instruction->opcode[0].type != CDISASM_OPERAND_REGISTER
            || instruction->opcode[0].reg < CDISASM_X86_REG_K0
            || instruction->opcode[0].reg > CDISASM_X86_REG_K7
            || instruction->opcode[0].size != 8u
            || instruction->opcode[0].access
                != CDISASM_OPERAND_ACCESS_WRITE
            || instruction->opcode[0].flags != 0u
            || instruction->opcode[0].broadcast
                != CDISASM_X86_BROADCAST_NONE
            || !register_low3_matches(instruction->opcode[0].reg,
                CDISASM_X86_REG_K0,
                (uint8_t)((instruction->encoding.modrm >> 3)
                    & UINT8_C(7)))
            || instruction->opcode[1].type != CDISASM_OPERAND_REGISTER
            || instruction->opcode[1].reg < evex_register_base
            || instruction->opcode[1].reg > evex_register_base + 31u
            || instruction->opcode[1].size != evex_vector_size
            || instruction->opcode[1].access
                != CDISASM_OPERAND_ACCESS_READ
            || instruction->opcode[1].flags != 0u
            || instruction->opcode[1].broadcast
                != CDISASM_X86_BROADCAST_NONE
            || instruction->opcode[2].type != (evex_memory_form
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || instruction->opcode[2].access
                != CDISASM_OPERAND_ACCESS_READ) {
            return 0;
        }

        if (evex_memory_form) {
            const cdisasm_opcode *memory = &instruction->opcode[2];
            const int valid_memory_width = evex_scalar
                ? memory->size == evex_scalar_size
                    && memory->broadcast == CDISASM_X86_BROADCAST_NONE
                : (memory->size == evex_vector_size
                        && memory->broadcast
                            == CDISASM_X86_BROADCAST_NONE)
                    || (memory->size == evex_scalar_size
                        && memory->broadcast == (cdisasm_x86_broadcast)(
                            evex_vector_size / evex_scalar_size));

            if ((memory->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_memory_width
                || !valid_modrm_memory_encoding(
                    instruction, memory, allow_egpr)) {
                return 0;
            }
        } else if (instruction->opcode[2].reg < evex_register_base
            || instruction->opcode[2].reg > evex_register_base + 31u
            || instruction->opcode[2].size != evex_vector_size
            || instruction->opcode[2].flags != 0u
            || instruction->opcode[2].broadcast
                != CDISASM_X86_BROADCAST_NONE
            || !register_low3_matches(instruction->opcode[2].reg,
                evex_register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7)))) {
            return 0;
        }

        return instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE
            && instruction->opcode[3].size == 1u
            && instruction->opcode[3].access
                == CDISASM_OPERAND_ACCESS_READ
            && instruction->opcode[3].flags == 0u
            && instruction->opcode[3].broadcast
                == CDISASM_X86_BROADCAST_NONE
            && instruction->opcode[3].imm <= UINT8_MAX;
    }
    if (!classic_form && !compare_name) {
        return 1;
    }
    if (!compare_name || !classic_form
        || instruction->name_id != expected_name
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 4u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 2u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || instruction->encoding.immediate_count != 1u
        || instruction->encoding.immediate_size[0] != 1u
        || instruction->encoding.immediate_offset[0]
            != instruction->opcode_size - 1u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 0)) {
        return 0;
    }

    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = memory_form && index == 2u;
        const unsigned int operand_size = scalar && index == 2u
            ? scalar_size : vector_size;

        if (operand->type != (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != operand_size
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_modrm_memory_encoding(instruction, operand, 0)) {
                return 0;
            }
        } else {
            const cdisasm_x86_reg_id register_base = scalar
                ? CDISASM_X86_REG_XMM0 : vector_base;

            if (operand->reg < register_base
                || operand->reg > register_base + 15u
                || operand->flags != 0u) {
                return 0;
            }
        }
    }
    if (!register_low3_matches(instruction->opcode[0].reg, vector_base,
            (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))
        || (!memory_form
            && !register_low3_matches(instruction->opcode[2].reg,
                scalar ? CDISASM_X86_REG_XMM0 : vector_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))))) {
        return 0;
    }
    return instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE
        && instruction->opcode[3].size == 1u
        && instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ
        && instruction->opcode[3].flags == 0u
        && instruction->opcode[3].broadcast == CDISASM_X86_BROADCAST_NONE
        && instruction->opcode[3].imm <= UINT8_MAX;
}

static int valid_vround_schema(const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int round_name =
        instruction->name_id == CDISASM_X86_NAME_VROUNDPD
        || instruction->name_id == CDISASM_X86_NAME_VROUNDPS
        || instruction->name_id == CDISASM_X86_NAME_VROUNDSD
        || instruction->name_id == CDISASM_X86_NAME_VROUNDSS;
    const int round_form = instruction->form_id >= UINT16_C(8539)
        && instruction->form_id <= UINT16_C(8550);
    cdisasm_x86_name_id expected_name;
    cdisasm_x86_form_id base;
    cdisasm_x86_form_id relative;
    cdisasm_x86_reg_id vector_base;
    unsigned int vector_size;
    unsigned int source_size;
    size_t source_index;
    size_t immediate_index;
    int scalar;
    int memory_form;
    size_t index;

    /* VROUND has no same-name EVEX encoding: EVEX rounding uses the distinct
     * VRNDSCALE names.  Still own both sides of every classic name/form
     * relationship so legacy ROUND and generated/forged objects cannot be
     * relabeled into this exact VEX schema. */
    if (!round_name && !round_form) {
        return 1;
    }
    if (!round_name || !round_form) {
        return 0;
    }

    if (instruction->form_id <= UINT16_C(8542)) {
        expected_name = CDISASM_X86_NAME_VROUNDPD;
        base = UINT16_C(8539);
        scalar = 0;
        source_size = 0u;
    } else if (instruction->form_id <= UINT16_C(8546)) {
        expected_name = CDISASM_X86_NAME_VROUNDPS;
        base = UINT16_C(8543);
        scalar = 0;
        source_size = 0u;
    } else if (instruction->form_id <= UINT16_C(8548)) {
        expected_name = CDISASM_X86_NAME_VROUNDSD;
        base = UINT16_C(8547);
        scalar = 1;
        source_size = 8u;
    } else {
        expected_name = CDISASM_X86_NAME_VROUNDSS;
        base = UINT16_C(8549);
        scalar = 1;
        source_size = 4u;
    }
    if (instruction->name_id != expected_name) {
        return 0;
    }

    relative = instruction->form_id - base;
    memory_form = scalar ? relative == UINT16_C(0)
                         : (relative & UINT16_C(1)) == 0u;
    vector_size = scalar || relative < UINT16_C(2) ? 16u : 32u;
    vector_base = vector_size == 16u
        ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
    source_index = scalar ? 2u : 1u;
    immediate_index = scalar ? 3u : 2u;

    if ((instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != (scalar ? 4u : 3u)
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 3u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || instruction->encoding.immediate_count != 1u
        || instruction->encoding.immediate_size[0] != 1u
        || instruction->encoding.immediate_offset[0]
            != instruction->opcode_size - 1u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 0)) {
        return 0;
    }

    for (index = 0u; index < immediate_index; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = memory_form && index == source_index;
        const unsigned int expected_size = scalar && index == source_index
            ? source_size : vector_size;

        if (operand->type != (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != expected_size
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_modrm_memory_encoding(
                    instruction, operand, 0)) {
                return 0;
            }
        } else {
            const cdisasm_x86_reg_id register_base = scalar
                ? CDISASM_X86_REG_XMM0 : vector_base;

            if (operand->reg < register_base
                || operand->reg > register_base + 15u
                || operand->flags != 0u) {
                return 0;
            }
        }
    }

    if (!register_low3_matches(instruction->opcode[0].reg, vector_base,
            (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))
        || (!memory_form
            && !register_low3_matches(
                instruction->opcode[source_index].reg,
                scalar ? CDISASM_X86_REG_XMM0 : vector_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))))) {
        return 0;
    }

    return instruction->opcode[immediate_index].type
            == CDISASM_OPERAND_IMMEDIATE
        && instruction->opcode[immediate_index].size == 1u
        && instruction->opcode[immediate_index].access
            == CDISASM_OPERAND_ACCESS_READ
        && instruction->opcode[immediate_index].flags == 0u
        && instruction->opcode[immediate_index].broadcast
            == CDISASM_X86_BROADCAST_NONE
        && instruction->opcode[immediate_index].imm <= UINT8_MAX;
}

static int valid_vshufpd_vshufps_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int shuf_name = instruction->name_id == CDISASM_X86_NAME_VSHUFPD
        || instruction->name_id == CDISASM_X86_NAME_VSHUFPS;
    const int classic_pd_form = instruction->form_id == UINT16_C(8664)
        || instruction->form_id == UINT16_C(8665)
        || instruction->form_id == UINT16_C(8670)
        || instruction->form_id == UINT16_C(8671);
    const int classic_ps_form = instruction->form_id == UINT16_C(8674)
        || instruction->form_id == UINT16_C(8675)
        || instruction->form_id == UINT16_C(8680)
        || instruction->form_id == UINT16_C(8681);
    const int evex_pd_form =
        (instruction->form_id >= UINT16_C(8666)
            && instruction->form_id <= UINT16_C(8669))
        || instruction->form_id == UINT16_C(8672)
        || instruction->form_id == UINT16_C(8673);
    const int evex_ps_form =
        (instruction->form_id >= UINT16_C(8676)
            && instruction->form_id <= UINT16_C(8679))
        || instruction->form_id == UINT16_C(8682)
        || instruction->form_id == UINT16_C(8683);
    const int is_double =
        instruction->name_id == CDISASM_X86_NAME_VSHUFPD;
    unsigned int vector_size;
    cdisasm_x86_reg_id register_base;
    int memory_form;
    size_t index;

    /* The generated decoder independently owns the twelve same-name EVEX
     * siblings.  Validate both recipes so a forged form/name/prefix cannot
     * cross from generated EVEX into this classic-VEX tranche. */
    if (evex_pd_form || evex_ps_form
        || (shuf_name && modern_prefix == CDISASM_PREFIX_EVEX)) {
        const uint32_t allowed_flags = CDISASM_PREFIX_EVEX
            | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT
            | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        const int matching_name = (evex_pd_form
                && instruction->name_id == CDISASM_X86_NAME_VSHUFPD)
            || (evex_ps_form
                && instruction->name_id == CDISASM_X86_NAME_VSHUFPS);
        const unsigned int scalar_size = evex_pd_form ? 8u : 4u;
        cdisasm_x86_group_id width_group;
        int allow_egpr;

        if ((evex_pd_form && instruction->form_id <= UINT16_C(8667))
            || (evex_ps_form
                && instruction->form_id <= UINT16_C(8677))) {
            vector_size = 16u;
            register_base = CDISASM_X86_REG_XMM0;
            width_group = CDISASM_X86_GROUP_AVX512F_128;
        } else if ((evex_pd_form
                && instruction->form_id <= UINT16_C(8669))
            || (evex_ps_form
                && instruction->form_id <= UINT16_C(8679))) {
            vector_size = 32u;
            register_base = CDISASM_X86_REG_YMM0;
            width_group = CDISASM_X86_GROUP_AVX512F_256;
        } else {
            vector_size = 64u;
            register_base = CDISASM_X86_REG_ZMM0;
            width_group = CDISASM_X86_GROUP_AVX512F_512;
        }
        memory_form = (instruction->form_id & UINT16_C(1)) == 0u;

        if (!matching_name || modern_prefix != CDISASM_PREFIX_EVEX
            || (instruction->opcode_flags & ~allowed_flags) != 0u
            || (instruction->opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u
            || instruction->operand_count != 4u
            || instruction->rounding != CDISASM_X86_ROUNDING_NONE
            || instruction->sae != CDISASM_X86_SAE_NONE
            || instruction->opcode_groups != CDISASM_GROUP_NONE
            || instruction->branch_target != 0u
            || instruction->encoding.prefix_size < 4u
            || instruction->encoding.opcode_size != 1u
            || instruction->encoding.modrm_offset
                != instruction->encoding.opcode_offset + 1u
            || (((instruction->encoding.modrm & UINT8_C(0xc0))
                    == UINT8_C(0xc0)) == memory_form)
            || (!memory_form
                && (instruction->encoding.sib_offset != 0u
                    || instruction->encoding.displacement_offset != 0u
                    || instruction->encoding.displacement_size != 0u))
            || instruction->encoding.immediate_count != 1u
            || instruction->encoding.immediate_size[0] != 1u
            || instruction->encoding.immediate_offset[0]
                != instruction->opcode_size - 1u
            || instruction->encoding.selector_offset != 0u
            || !valid_generated_evex_width_groups(
                instruction, width_group, &allow_egpr)) {
            return 0;
        }

        for (index = 0u; index < 3u; ++index) {
            const cdisasm_opcode *operand = &instruction->opcode[index];
            const int memory = memory_form && index == 2u;

            if (operand->type != (memory
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
                || operand->access != (index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ)) {
                return 0;
            }
            if (memory) {
                if ((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                    || !((operand->size == vector_size
                            && operand->broadcast
                                == CDISASM_X86_BROADCAST_NONE)
                        || (operand->size == scalar_size
                            && operand->broadcast
                                == (cdisasm_x86_broadcast)(
                                    vector_size / scalar_size)))
                    || !valid_modrm_memory_encoding(
                        instruction, operand, allow_egpr)) {
                    return 0;
                }
            } else if (operand->reg < register_base
                || operand->reg > register_base + 31u
                || operand->size != vector_size
                || operand->flags != 0u
                || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
                return 0;
            }
        }
        if (!register_low3_matches(instruction->opcode[0].reg,
                register_base,
                (uint8_t)((instruction->encoding.modrm >> 3)
                    & UINT8_C(7)))
            || (!memory_form
                && !register_low3_matches(
                    instruction->opcode[2].reg, register_base,
                    (uint8_t)(instruction->encoding.modrm & UINT8_C(7))))) {
            return 0;
        }
        return instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE
            && instruction->opcode[3].size == 1u
            && instruction->opcode[3].access
                == CDISASM_OPERAND_ACCESS_READ
            && instruction->opcode[3].flags == 0u
            && instruction->opcode[3].broadcast
                == CDISASM_X86_BROADCAST_NONE
            && instruction->opcode[3].imm <= UINT8_MAX;
    }

    if (!shuf_name && !classic_pd_form && !classic_ps_form) {
        return 1;
    }
    if (!shuf_name
        || (is_double ? !classic_pd_form : !classic_ps_form)) {
        return 0;
    }
    {
        const uint32_t allowed_flags = CDISASM_PREFIX_VEX
            | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
        const int ymm = instruction->form_id == UINT16_C(8670)
            || instruction->form_id == UINT16_C(8671)
            || instruction->form_id == UINT16_C(8680)
            || instruction->form_id == UINT16_C(8681);

        vector_size = ymm ? 32u : 16u;
        register_base = ymm
            ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
        memory_form = (instruction->form_id & UINT16_C(1)) == 0u;
        if ((instruction->opcode_flags & ~allowed_flags) != 0u
            || modern_prefix != CDISASM_PREFIX_VEX
            || instruction->operand_count != 4u
            || instruction->mask_mode != CDISASM_X86_MASK_NONE
            || instruction->mask_reg != CDISASM_X86_REG_NONE
            || instruction->rounding != CDISASM_X86_ROUNDING_NONE
            || instruction->sae != CDISASM_X86_SAE_NONE
            || instruction->opcode_groups != CDISASM_GROUP_NONE
            || instruction->branch_target != 0u
            || instruction->encoding.prefix_size < 2u
            || instruction->encoding.opcode_size != 1u
            || instruction->encoding.modrm_offset
                != instruction->encoding.opcode_offset + 1u
            || (((instruction->encoding.modrm & UINT8_C(0xc0))
                    == UINT8_C(0xc0)) == memory_form)
            || (!memory_form
                && (instruction->encoding.sib_offset != 0u
                    || instruction->encoding.displacement_offset != 0u
                    || instruction->encoding.displacement_size != 0u))
            || instruction->encoding.immediate_count != 1u
            || instruction->encoding.immediate_size[0] != 1u
            || instruction->encoding.immediate_offset[0]
                != instruction->opcode_size - 1u
            || instruction->encoding.selector_offset != 0u
            || !valid_vpblend_groups(instruction, 0)) {
            return 0;
        }
        for (index = 0u; index < 3u; ++index) {
            const cdisasm_opcode *operand = &instruction->opcode[index];
            const int memory = memory_form && index == 2u;

            if (operand->type != (memory
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
                || operand->size != vector_size
                || operand->access != (index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ)
                || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
                return 0;
            }
            if (memory) {
                if ((operand->flags
                        & (CDISASM_OPERAND_FLAG_IMPLICIT
                            | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                    || !valid_modrm_memory_encoding(
                        instruction, operand, 0)) {
                    return 0;
                }
            } else if (operand->reg < register_base
                || operand->reg > register_base + 15u
                || operand->flags != 0u) {
                return 0;
            }
        }
        if (!register_low3_matches(instruction->opcode[0].reg,
                register_base,
                (uint8_t)((instruction->encoding.modrm >> 3)
                    & UINT8_C(7)))
            || (!memory_form
                && !register_low3_matches(
                    instruction->opcode[2].reg, register_base,
                    (uint8_t)(instruction->encoding.modrm & UINT8_C(7))))) {
            return 0;
        }
        return instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE
            && instruction->opcode[3].size == 1u
            && instruction->opcode[3].access
                == CDISASM_OPERAND_ACCESS_READ
            && instruction->opcode[3].flags == 0u
            && instruction->opcode[3].broadcast
                == CDISASM_X86_BROADCAST_NONE
            && instruction->opcode[3].imm <= UINT8_MAX;
    }
}

static int valid_vtestpd_vtestps_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT
        | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int test_name = instruction->name_id == CDISASM_X86_NAME_VTESTPD
        || instruction->name_id == CDISASM_X86_NAME_VTESTPS;
    const int test_form = instruction->form_id >= UINT16_C(8795)
        && instruction->form_id <= UINT16_C(8802);
    const int is_double = instruction->form_id <= UINT16_C(8798);
    const cdisasm_x86_form_id base = is_double
        ? UINT16_C(8795) : UINT16_C(8799);
    const cdisasm_x86_form_id relative = instruction->form_id - base;
    const int ymm = relative >= UINT16_C(2);
    const int memory_form = (relative & UINT16_C(1)) == 0u;
    const unsigned int vector_size = ymm ? 32u : 16u;
    const cdisasm_x86_reg_id register_base = ymm
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    size_t index;

    /* These names have exactly the eight classic-VEX forms.  Match both
     * sides so a forged name or form cannot escape this exact schema. */
    if (!test_name && !test_form) {
        return 1;
    }
    if (!test_name || !test_form
        || instruction->name_id != (is_double
            ? CDISASM_X86_NAME_VTESTPD : CDISASM_X86_NAME_VTESTPS)
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || (instruction->opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) == 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 2u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 3u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 0)) {
        return 0;
    }

    for (index = 0u; index < 2u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = memory_form && index == 1u;

        if (operand->type != (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != vector_size
            || operand->access != CDISASM_OPERAND_ACCESS_READ
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_modrm_memory_encoding(
                    instruction, operand, 0)) {
                return 0;
            }
        } else if (operand->reg < register_base
            || operand->reg > register_base + 15u
            || operand->flags != 0u) {
            return 0;
        }
    }

    return register_low3_matches(instruction->opcode[0].reg,
               register_base,
               (uint8_t)((instruction->encoding.modrm >> 3)
                   & UINT8_C(7)))
        && (memory_form
            || register_low3_matches(instruction->opcode[1].reg,
                register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))));
}

static int valid_vptest_schema(const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT
        | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int ptest_name = instruction->name_id == CDISASM_X86_NAME_VPTEST;
    const int ptest_form = instruction->form_id >= UINT16_C(8319)
        && instruction->form_id <= UINT16_C(8322);
    const cdisasm_x86_form_id relative =
        instruction->form_id - UINT16_C(8319);
    const int ymm = relative >= UINT16_C(2);
    const int memory_form = (relative & UINT16_C(1)) == 0u;
    const unsigned int vector_size = ymm ? 32u : 16u;
    const cdisasm_x86_reg_id register_base = ymm
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    size_t index;

    /* VPTEST has exactly these four classic-VEX forms.  EVEX VPTESTM* and
     * VPTESTNM* use distinct public names and are decoded independently. */
    if (!ptest_name && !ptest_form) {
        return 1;
    }
    if (!ptest_name || !ptest_form
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || (instruction->opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) == 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 2u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 3u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 0)) {
        return 0;
    }

    for (index = 0u; index < 2u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = memory_form && index == 1u;

        if (operand->type != (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != vector_size
            || operand->access != CDISASM_OPERAND_ACCESS_READ
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_modrm_memory_encoding(instruction, operand, 0)) {
                return 0;
            }
        } else if (operand->reg < register_base
            || operand->reg > register_base + 15u
            || operand->flags != 0u) {
            return 0;
        }
    }

    return register_low3_matches(instruction->opcode[0].reg,
               register_base,
               (uint8_t)((instruction->encoding.modrm >> 3)
                   & UINT8_C(7)))
        && (memory_form
            || register_low3_matches(instruction->opcode[1].reg,
                register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))));
}

static int valid_vpmovmskb_schema(const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int move_name =
        instruction->name_id == CDISASM_X86_NAME_VPMOVMSKB;
    const int move_form = instruction->form_id == UINT16_C(7334)
        || instruction->form_id == UINT16_C(7335);
    const int ymm = instruction->form_id == UINT16_C(7335);
    const unsigned int vector_size = ymm ? 32u : 16u;
    const cdisasm_x86_reg_id vector_base = ymm
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;

    if (!move_name && !move_form) {
        return 1;
    }
    if (!move_name || !move_form
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 2u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 2u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (instruction->encoding.modrm & UINT8_C(0xc0))
            != UINT8_C(0xc0)
        || instruction->encoding.sib_offset != 0u
        || instruction->encoding.displacement_offset != 0u
        || instruction->encoding.displacement_size != 0u
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, ymm)
        || instruction->opcode[0].type != CDISASM_OPERAND_REGISTER
        || instruction->opcode[0].reg < CDISASM_X86_REG_EAX
        || instruction->opcode[0].reg > CDISASM_X86_REG_R15D
        || instruction->opcode[0].size != 4u
        || instruction->opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
        || instruction->opcode[0].flags != 0u
        || instruction->opcode[0].broadcast != CDISASM_X86_BROADCAST_NONE
        || instruction->opcode[1].type != CDISASM_OPERAND_REGISTER
        || instruction->opcode[1].reg < vector_base
        || instruction->opcode[1].reg > vector_base + 15u
        || instruction->opcode[1].size != vector_size
        || instruction->opcode[1].access != CDISASM_OPERAND_ACCESS_READ
        || instruction->opcode[1].flags != 0u
        || instruction->opcode[1].broadcast
            != CDISASM_X86_BROADCAST_NONE) {
        return 0;
    }

    return register_low3_matches(instruction->opcode[0].reg,
               CDISASM_X86_REG_EAX,
               (uint8_t)((instruction->encoding.modrm >> 3)
                   & UINT8_C(7)))
        && register_low3_matches(instruction->opcode[1].reg,
            vector_base,
            (uint8_t)(instruction->encoding.modrm & UINT8_C(7)));
}

static int valid_vpermpd_vpermq_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int perm_name = instruction->name_id == CDISASM_X86_NAME_VPERMPD
        || instruction->name_id == CDISASM_X86_NAME_VPERMQ;
    const int perm_form = instruction->form_id == UINT16_C(6878)
        || instruction->form_id == UINT16_C(6879)
        || instruction->form_id == UINT16_C(6890)
        || instruction->form_id == UINT16_C(6891);
    const int evex_permpd_form =
        (instruction->form_id >= UINT16_C(6874)
            && instruction->form_id <= UINT16_C(6877))
        || (instruction->form_id >= UINT16_C(6880)
            && instruction->form_id <= UINT16_C(6883));
    const int evex_vpermq_form = instruction->form_id >= UINT16_C(6892)
        && instruction->form_id <= UINT16_C(6899);
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int floating = instruction->name_id == CDISASM_X86_NAME_VPERMPD;
    const cdisasm_x86_form_id base = floating
        ? UINT16_C(6878) : UINT16_C(6890);
    const int memory_form = instruction->form_id == UINT16_C(6878)
        || instruction->form_id == UINT16_C(6890);
    size_t index;

    /* The generated decoder independently owns the sixteen EVEX siblings.
     * Validate their complete public schema here as well: merely checking
     * the name/form relationship would let a forged generated object evade
     * operand, mask, group, and encoding checks.  The four classic-VEX forms
     * remain name-owned so no partial mutation can cross this boundary. */
    if (evex_permpd_form || evex_vpermq_form
        || (perm_name && modern_prefix == CDISASM_PREFIX_EVEX)) {
        const uint32_t allowed_evex_flags = CDISASM_PREFIX_EVEX
            | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT
            | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        const int matching_name = (evex_permpd_form
                && instruction->name_id == CDISASM_X86_NAME_VPERMPD)
            || (evex_vpermq_form
                && instruction->name_id == CDISASM_X86_NAME_VPERMQ);
        const int ymm_form = evex_permpd_form
            ? instruction->form_id <= UINT16_C(6877)
            : instruction->form_id <= UINT16_C(6895);
        const int variable_form = instruction->form_id == UINT16_C(6876)
            || instruction->form_id == UINT16_C(6877)
            || instruction->form_id == UINT16_C(6882)
            || instruction->form_id == UINT16_C(6883)
            || instruction->form_id == UINT16_C(6894)
            || instruction->form_id == UINT16_C(6895)
            || instruction->form_id == UINT16_C(6898)
            || instruction->form_id == UINT16_C(6899);
        const int memory_evex_form =
            (instruction->form_id & UINT16_C(1)) == 0u;
        const unsigned int vector_size = ymm_form ? 32u : 64u;
        const cdisasm_x86_reg_id register_base = ymm_form
            ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_ZMM0;
        const size_t memory_index = variable_form ? 2u : 1u;
        int allow_egpr;
        size_t operand_index;

        if (!matching_name
            || modern_prefix != CDISASM_PREFIX_EVEX
            || (instruction->opcode_flags & ~allowed_evex_flags) != 0u
            || (instruction->opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u
            || instruction->operand_count != 3u
            || instruction->rounding != CDISASM_X86_ROUNDING_NONE
            || instruction->sae != CDISASM_X86_SAE_NONE
            || instruction->opcode_groups != CDISASM_GROUP_NONE
            || instruction->branch_target != 0u
            || instruction->encoding.prefix_size < 4u
            || instruction->encoding.opcode_size != 1u
            || instruction->encoding.modrm_offset
                != instruction->encoding.opcode_offset + 1u
            || (((instruction->encoding.modrm & UINT8_C(0xc0))
                    == UINT8_C(0xc0)) == memory_evex_form)
            || (!memory_evex_form
                && (instruction->encoding.sib_offset != 0u
                    || instruction->encoding.displacement_offset != 0u
                    || instruction->encoding.displacement_size != 0u))
            || instruction->encoding.immediate_count
                != (variable_form ? 0u : 1u)
            || (!variable_form
                && (instruction->encoding.immediate_size[0] != 1u
                    || instruction->encoding.immediate_offset[0]
                        != instruction->opcode_size - 1u))
            || instruction->encoding.selector_offset != 0u) {
            return 0;
        }

        if (!valid_generated_evex_width_groups(instruction,
                ymm_form ? CDISASM_X86_GROUP_AVX512F_256
                         : CDISASM_X86_GROUP_AVX512F_512,
                &allow_egpr)) {
            return 0;
        }

        if (instruction->opcode[0].type != CDISASM_OPERAND_REGISTER
            || instruction->opcode[0].reg < register_base
            || instruction->opcode[0].reg > register_base + 31u
            || instruction->opcode[0].size != vector_size
            || instruction->opcode[0].access
                != CDISASM_OPERAND_ACCESS_WRITE
            || instruction->opcode[0].flags != 0u
            || instruction->opcode[0].broadcast
                != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }

        for (operand_index = 1u;
             operand_index <= (variable_form ? 2u : 1u);
             ++operand_index) {
            const cdisasm_opcode *operand =
                &instruction->opcode[operand_index];
            const int memory = memory_evex_form
                && operand_index == memory_index;

            if (operand->type != (memory
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
                || operand->access != CDISASM_OPERAND_ACCESS_READ) {
                return 0;
            }
            if (!memory) {
                if (operand->reg < register_base
                    || operand->reg > register_base + 31u
                    || operand->size != vector_size
                    || operand->flags != 0u
                    || operand->broadcast
                        != CDISASM_X86_BROADCAST_NONE) {
                    return 0;
                }
            } else if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !((operand->size == vector_size
                        && operand->broadcast
                            == CDISASM_X86_BROADCAST_NONE)
                    || (operand->size == 8u
                        && operand->broadcast
                            == (cdisasm_x86_broadcast)(vector_size / 8u)))
                || !valid_modrm_memory_encoding(
                    instruction, operand, allow_egpr)) {
                return 0;
            }
        }
        if (!register_low3_matches(instruction->opcode[0].reg, register_base,
                (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))
            || (!memory_evex_form
                && !register_low3_matches(
                    instruction->opcode[memory_index].reg, register_base,
                    (uint8_t)(instruction->encoding.modrm & UINT8_C(7))))) {
            return 0;
        }
        if (!variable_form) {
            const cdisasm_opcode *immediate = &instruction->opcode[2];

            if (immediate->type != CDISASM_OPERAND_IMMEDIATE
                || immediate->size != 1u
                || immediate->access != CDISASM_OPERAND_ACCESS_READ
                || immediate->flags != 0u
                || immediate->broadcast != CDISASM_X86_BROADCAST_NONE
                || immediate->imm > UINT8_MAX) {
                return 0;
            }
        }
        return 1;
    }
    if (!perm_name && !perm_form) {
        return 1;
    }
    if (!perm_name || !perm_form
        || instruction->form_id < base
        || instruction->form_id > base + UINT16_C(1)
        || instruction->operand_count != 3u
        || (instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 3u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || instruction->encoding.immediate_count != 1u
        || instruction->encoding.immediate_size[0] != 1u
        || instruction->encoding.immediate_offset[0]
            != instruction->opcode_size - 1u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 1)) {
        return 0;
    }

    for (index = 0u; index < 2u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = memory_form && index == 1u;

        if (operand->type != (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != 32u
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_modrm_memory_encoding(instruction, operand, 0)) {
                return 0;
            }
        } else if (operand->reg < CDISASM_X86_REG_YMM0
            || operand->reg > CDISASM_X86_REG_YMM15
            || operand->flags != 0u) {
            return 0;
        }
    }
    if (!register_low3_matches(instruction->opcode[0].reg,
            CDISASM_X86_REG_YMM0,
            (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))
        || (!memory_form
            && !register_low3_matches(instruction->opcode[1].reg,
                CDISASM_X86_REG_YMM0,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))))) {
        return 0;
    }
    return instruction->opcode[2].type == CDISASM_OPERAND_IMMEDIATE
        && instruction->opcode[2].size == 1u
        && instruction->opcode[2].access
            == CDISASM_OPERAND_ACCESS_READ
        && instruction->opcode[2].flags == 0u
        && instruction->opcode[2].broadcast
            == CDISASM_X86_BROADCAST_NONE
        && instruction->opcode[2].imm <= UINT8_MAX;
}

static int valid_vpcmov_schema(const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_XOP
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int vpcmov_name =
        instruction->name_id == CDISASM_X86_NAME_VPCMOV;
    const int vpcmov_form = instruction->form_id >= UINT16_C(6410)
        && instruction->form_id <= UINT16_C(6415);
    cdisasm_x86_reg_id register_base;
    unsigned int relative;
    unsigned int vector_size;
    int memory_operand = -1;
    size_t index;

    /* Match on either side of the name/form relationship so changing only
     * one field cannot bypass the exact family schema. */
    if (!vpcmov_name && !vpcmov_form) {
        return 1;
    }
    if (!vpcmov_name || !vpcmov_form
        || instruction->operand_count != 4u
        || (instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || (instruction->opcode_flags & CDISASM_PREFIX_XOP) == 0u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset == 0u
        || !valid_exact_xop_groups(instruction)) {
        return 0;
    }

    relative = instruction->form_id - UINT16_C(6410);
    vector_size = relative < 3u ? 16u : 32u;
    register_base = vector_size == 16u
        ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;
    if (relative == 0u || relative == 3u) {
        memory_operand = 2;
    } else if (relative == 1u || relative == 4u) {
        memory_operand = 3;
    }

    for (index = 0u; index < 4u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const cdisasm_operand_type expected_type =
            (int)index == memory_operand
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER;

        if (operand->type != expected_type
            || operand->size != vector_size
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (expected_type == CDISASM_OPERAND_REGISTER) {
            if (operand->flags != 0u
                || operand->reg < register_base
                || operand->reg > register_base + 15u) {
                return 0;
            }
        } else if ((operand->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u) {
            return 0;
        }
    }
    return 1;
}

static int valid_vpperm_schema(const cdisasm_instruction *instruction)
{
    const uint32_t allowed_opcode_flags = CDISASM_PREFIX_XOP
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const int vpperm_name =
        instruction->name_id == CDISASM_X86_NAME_VPPERM;
    const int vpperm_form = instruction->form_id >= UINT16_C(7686)
        && instruction->form_id <= UINT16_C(7688);
    int memory_operand = -1;
    size_t index;

    /* Match on either side of the name/form relationship so changing only
     * one field cannot bypass the exact family schema. */
    if (!vpperm_name && !vpperm_form) {
        return 1;
    }
    if (!vpperm_name || !vpperm_form
        || instruction->operand_count != 4u
        || (instruction->opcode_flags & ~allowed_opcode_flags) != 0u
        || (instruction->opcode_flags & CDISASM_PREFIX_XOP) == 0u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset == 0u
        || !valid_exact_xop_groups(instruction)) {
        return 0;
    }

    if (instruction->form_id == UINT16_C(7686)) {
        memory_operand = 2;
    } else if (instruction->form_id == UINT16_C(7687)) {
        memory_operand = 3;
    }

    for (index = 0u; index < 4u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const cdisasm_operand_type expected_type =
            (int)index == memory_operand
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER;

        if (operand->type != expected_type
            || operand->size != 16u
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (expected_type == CDISASM_OPERAND_REGISTER) {
            if (operand->flags != 0u
                || operand->reg < CDISASM_X86_REG_XMM0
                || operand->reg > CDISASM_X86_REG_XMM15) {
                return 0;
            }
        } else if ((operand->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u) {
            return 0;
        }
    }
    return 1;
}

static int valid_vcomi_scalar_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT
        | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int unordered_name =
        instruction->name_id == CDISASM_X86_NAME_VUCOMISD
        || instruction->name_id == CDISASM_X86_NAME_VUCOMISS;
    const int ordered_name =
        instruction->name_id == CDISASM_X86_NAME_VCOMISD
        || instruction->name_id == CDISASM_X86_NAME_VCOMISS;
    const int compare_name = unordered_name || ordered_name;
    const int ordered_form =
        instruction->form_id == UINT16_C(3629)
        || instruction->form_id == UINT16_C(3630)
        || instruction->form_id == UINT16_C(3633)
        || instruction->form_id == UINT16_C(3634);
    const int double_form = instruction->form_id == UINT16_C(3629)
        || instruction->form_id == UINT16_C(3630)
        || instruction->form_id == UINT16_C(8803)
        || instruction->form_id == UINT16_C(8804);
    const int single_form = instruction->form_id == UINT16_C(3633)
        || instruction->form_id == UINT16_C(3634)
        || instruction->form_id == UINT16_C(8809)
        || instruction->form_id == UINT16_C(8810);
    const int classic_form = double_form || single_form;
    const int memory_form = instruction->form_id == UINT16_C(3629)
        || instruction->form_id == UINT16_C(3633)
        || instruction->form_id == UINT16_C(8803)
        || instruction->form_id == UINT16_C(8809);
    const unsigned int scalar_size = double_form ? 8u : 4u;
    const cdisasm_opcode *first = &instruction->opcode[0];
    const cdisasm_opcode *second = &instruction->opcode[1];

    /* Same-name EVEX forms remain owned by the generated decoder and its
     * generic schema. Match classic forms and VEX-prefixed names
     * independently so a forged ordered/unordered identity cannot bypass
     * this exact two-operand recipe. */
    if (!classic_form
        && !(compare_name && modern_prefix == CDISASM_PREFIX_VEX)) {
        return 1;
    }
    if (!compare_name || !classic_form
        || instruction->name_id != (ordered_form
            ? (double_form
                ? CDISASM_X86_NAME_VCOMISD : CDISASM_X86_NAME_VCOMISS)
            : (double_form
                ? CDISASM_X86_NAME_VUCOMISD : CDISASM_X86_NAME_VUCOMISS))
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || (instruction->opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) == 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 2u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 2u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 0)
        || first->type != CDISASM_OPERAND_REGISTER
        || first->reg < CDISASM_X86_REG_XMM0
        || first->reg > CDISASM_X86_REG_XMM15
        || first->size != 16u
        || first->access != CDISASM_OPERAND_ACCESS_READ
        || first->flags != 0u
        || first->broadcast != CDISASM_X86_BROADCAST_NONE
        || second->type != (memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
        || second->size != scalar_size
        || second->access != CDISASM_OPERAND_ACCESS_READ
        || second->broadcast != CDISASM_X86_BROADCAST_NONE) {
        return 0;
    }
    if (!register_low3_matches(first->reg, CDISASM_X86_REG_XMM0,
            (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))) {
        return 0;
    }
    if (memory_form) {
        return (second->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u
            && valid_modrm_memory_encoding(instruction, second, 0);
    }
    return second->reg >= CDISASM_X86_REG_XMM0
        && second->reg <= CDISASM_X86_REG_XMM15
        && second->flags == 0u
        && register_low3_matches(second->reg, CDISASM_X86_REG_XMM0,
            (uint8_t)(instruction->encoding.modrm & UINT8_C(7)));
}

static int valid_vunpck_packed_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int family_name =
        instruction->name_id == CDISASM_X86_NAME_VUNPCKHPD
        || instruction->name_id == CDISASM_X86_NAME_VUNPCKHPS
        || instruction->name_id == CDISASM_X86_NAME_VUNPCKLPD
        || instruction->name_id == CDISASM_X86_NAME_VUNPCKLPS;
    const int hpd_form = instruction->form_id == UINT16_C(8825)
        || instruction->form_id == UINT16_C(8826)
        || instruction->form_id == UINT16_C(8831)
        || instruction->form_id == UINT16_C(8832);
    const int hps_form = instruction->form_id == UINT16_C(8835)
        || instruction->form_id == UINT16_C(8836)
        || instruction->form_id == UINT16_C(8841)
        || instruction->form_id == UINT16_C(8842);
    const int lpd_form = instruction->form_id == UINT16_C(8845)
        || instruction->form_id == UINT16_C(8846)
        || instruction->form_id == UINT16_C(8851)
        || instruction->form_id == UINT16_C(8852);
    const int lps_form = instruction->form_id == UINT16_C(8855)
        || instruction->form_id == UINT16_C(8856)
        || instruction->form_id == UINT16_C(8861)
        || instruction->form_id == UINT16_C(8862);
    const int classic_form = hpd_form || hps_form || lpd_form || lps_form;
    const int evex_hpd_form =
        (instruction->form_id >= UINT16_C(8827)
            && instruction->form_id <= UINT16_C(8830))
        || (instruction->form_id >= UINT16_C(8833)
            && instruction->form_id <= UINT16_C(8834));
    const int evex_hps_form =
        (instruction->form_id >= UINT16_C(8837)
            && instruction->form_id <= UINT16_C(8840))
        || (instruction->form_id >= UINT16_C(8843)
            && instruction->form_id <= UINT16_C(8844));
    const int evex_lpd_form =
        (instruction->form_id >= UINT16_C(8847)
            && instruction->form_id <= UINT16_C(8850))
        || (instruction->form_id >= UINT16_C(8853)
            && instruction->form_id <= UINT16_C(8854));
    const int evex_lps_form =
        (instruction->form_id >= UINT16_C(8857)
            && instruction->form_id <= UINT16_C(8860))
        || (instruction->form_id >= UINT16_C(8863)
            && instruction->form_id <= UINT16_C(8864));
    const int evex_form = evex_hpd_form || evex_hps_form
        || evex_lpd_form || evex_lps_form;
    const int evex_identity =
        (evex_hpd_form
            && instruction->name_id == CDISASM_X86_NAME_VUNPCKHPD)
        || (evex_hps_form
            && instruction->name_id == CDISASM_X86_NAME_VUNPCKHPS)
        || (evex_lpd_form
            && instruction->name_id == CDISASM_X86_NAME_VUNPCKLPD)
        || (evex_lps_form
            && instruction->name_id == CDISASM_X86_NAME_VUNPCKLPS);
    const int classic_identity =
        (hpd_form
            && instruction->name_id == CDISASM_X86_NAME_VUNPCKHPD)
        || (hps_form
            && instruction->name_id == CDISASM_X86_NAME_VUNPCKHPS)
        || (lpd_form
            && instruction->name_id == CDISASM_X86_NAME_VUNPCKLPD)
        || (lps_form
            && instruction->name_id == CDISASM_X86_NAME_VUNPCKLPS);
    unsigned int vector_size;
    cdisasm_x86_reg_id register_base;
    int memory_form;
    size_t index;

    /* Generated EVEX siblings retain their existing schema.  Still bind their
     * form/name/prefix identity here so a forged classic/EVEX crossover cannot
     * bypass the exact classic-VEX checks below. */
    if (evex_form || (family_name && modern_prefix == CDISASM_PREFIX_EVEX)) {
        return evex_identity && modern_prefix == CDISASM_PREFIX_EVEX;
    }
    if (!classic_form && !family_name) {
        return 1;
    }
    if (!classic_identity || !classic_form
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 3u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 2u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 0)) {
        return 0;
    }

    vector_size = instruction->form_id == UINT16_C(8831)
            || instruction->form_id == UINT16_C(8832)
            || instruction->form_id == UINT16_C(8841)
            || instruction->form_id == UINT16_C(8842)
            || instruction->form_id == UINT16_C(8851)
            || instruction->form_id == UINT16_C(8852)
            || instruction->form_id == UINT16_C(8861)
            || instruction->form_id == UINT16_C(8862)
        ? 32u : 16u;
    register_base = vector_size == 32u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    memory_form = (instruction->form_id & UINT16_C(1)) != 0u;
    if ((((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))) {
        return 0;
    }
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = memory_form && index == 2u;

        if (operand->type != (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != vector_size
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_modrm_memory_encoding(
                    instruction, operand, 0)) {
                return 0;
            }
        } else if (operand->reg < register_base
            || operand->reg > register_base + 15u
            || operand->flags != 0u) {
            return 0;
        }
    }
    return register_low3_matches(instruction->opcode[0].reg,
               register_base,
               (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))
        && (memory_form
            || register_low3_matches(instruction->opcode[2].reg,
                register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))));
}

static int valid_vpunpck_integer_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int family_name =
        instruction->name_id == CDISASM_X86_NAME_VPUNPCKHBW
        || instruction->name_id == CDISASM_X86_NAME_VPUNPCKHWD
        || instruction->name_id == CDISASM_X86_NAME_VPUNPCKHDQ
        || instruction->name_id == CDISASM_X86_NAME_VPUNPCKHQDQ
        || instruction->name_id == CDISASM_X86_NAME_VPUNPCKLBW
        || instruction->name_id == CDISASM_X86_NAME_VPUNPCKLWD
        || instruction->name_id == CDISASM_X86_NAME_VPUNPCKLDQ
        || instruction->name_id == CDISASM_X86_NAME_VPUNPCKLQDQ;
    static const struct family_range {
        uint16_t base;
        uint16_t name;
    } families[] = {
        {8323, CDISASM_X86_NAME_VPUNPCKHBW},
        {8333, CDISASM_X86_NAME_VPUNPCKHDQ},
        {8343, CDISASM_X86_NAME_VPUNPCKHQDQ},
        {8353, CDISASM_X86_NAME_VPUNPCKHWD},
        {8363, CDISASM_X86_NAME_VPUNPCKLBW},
        {8373, CDISASM_X86_NAME_VPUNPCKLDQ},
        {8383, CDISASM_X86_NAME_VPUNPCKLQDQ},
        {8393, CDISASM_X86_NAME_VPUNPCKLWD}};
    uint16_t base = 0u;
    uint16_t offset = 0u;
    int identity = 0;
    int classic_form = 0;
    int evex_form = 0;
    unsigned int vector_size;
    cdisasm_x86_reg_id register_base;
    int memory_form;
    size_t index;

    for (index = 0u; index < sizeof(families) / sizeof(families[0]);
         ++index) {
        if (instruction->form_id >= families[index].base
            && instruction->form_id <= families[index].base + 9u) {
            base = families[index].base;
            offset = (uint16_t)(instruction->form_id - base);
            identity = instruction->name_id == families[index].name;
            classic_form = offset <= 1u
                || offset == 4u || offset == 5u;
            evex_form = !classic_form;
            break;
        }
    }

    /* Generated EVEX siblings keep the generated schema, but their identity
     * is bound here so a forged classic/EVEX crossover cannot bypass the
     * exact classic-VEX checks below. */
    if (evex_form || (family_name && modern_prefix == CDISASM_PREFIX_EVEX)) {
        return identity && evex_form
            && modern_prefix == CDISASM_PREFIX_EVEX;
    }
    if (!classic_form && !family_name) {
        return 1;
    }
    if (!identity || !classic_form
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 3u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 2u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u) {
        return 0;
    }

    vector_size = offset >= 4u ? 32u : 16u;
    register_base = vector_size == 32u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    memory_form = offset == 0u || offset == 4u;
    if (!valid_vpblend_groups(instruction, vector_size == 32u)
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))) {
        return 0;
    }
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = memory_form && index == 2u;

        if (operand->type != (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != vector_size
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_modrm_memory_encoding(instruction, operand, 0)) {
                return 0;
            }
        } else if (operand->reg < register_base
            || operand->reg > register_base + 15u
            || operand->flags != 0u) {
            return 0;
        }
    }
    return register_low3_matches(instruction->opcode[0].reg,
               register_base,
               (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))
        && (memory_form
            || register_low3_matches(instruction->opcode[2].reg,
                register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))));
}

static int valid_vpsign_integer_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    static const struct family_range {
        uint16_t base;
        uint16_t name;
    } families[] = {
        {7921, CDISASM_X86_NAME_VPSIGNB},
        {7925, CDISASM_X86_NAME_VPSIGND},
        {7929, CDISASM_X86_NAME_VPSIGNW}};
    const int family_name =
        instruction->name_id == CDISASM_X86_NAME_VPSIGNB
        || instruction->name_id == CDISASM_X86_NAME_VPSIGND
        || instruction->name_id == CDISASM_X86_NAME_VPSIGNW;
    uint16_t offset = 0u;
    int identity = 0;
    int family_form = 0;
    unsigned int vector_size;
    cdisasm_x86_reg_id register_base;
    int memory_form;
    size_t index;

    for (index = 0u; index < sizeof(families) / sizeof(families[0]);
         ++index) {
        if (instruction->form_id >= families[index].base
            && instruction->form_id <= families[index].base + 3u) {
            offset = (uint16_t)(instruction->form_id - families[index].base);
            identity = instruction->name_id == families[index].name;
            family_form = 1;
            break;
        }
    }
    /* Match both halves of the identity relationship so changing only the
     * name or only the public form cannot bypass the exact VEX schema. */
    if (!family_name && !family_form) {
        return 1;
    }
    if (!family_name || !family_form || !identity
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 3u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 3u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u) {
        return 0;
    }

    vector_size = offset >= 2u ? 32u : 16u;
    register_base = vector_size == 32u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    memory_form = (offset & 1u) == 0u;
    if (!valid_vpblend_groups(instruction, vector_size == 32u)
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))) {
        return 0;
    }
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = memory_form && index == 2u;

        if (operand->type != (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != vector_size
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_modrm_memory_encoding(instruction, operand, 0)) {
                return 0;
            }
        } else if (operand->reg < register_base
            || operand->reg > register_base + 15u
            || operand->flags != 0u) {
            return 0;
        }
    }
    return register_low3_matches(instruction->opcode[0].reg,
               register_base,
               (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))
        && (memory_form
            || register_low3_matches(instruction->opcode[2].reg,
                register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))));
}

static int valid_vphminposuw_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int family_name =
        instruction->name_id == CDISASM_X86_NAME_VPHMINPOSUW;
    const int family_form = instruction->form_id == UINT16_C(7040)
        || instruction->form_id == UINT16_C(7041);
    const int memory_form = instruction->form_id == UINT16_C(7040);
    size_t index;

    if (!family_name && !family_form) {
        return 1;
    }
    if (!family_name || !family_form
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 2u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 3u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 0)) {
        return 0;
    }
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = memory_form && index == 1u;

        if (operand->type != (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != 16u
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_modrm_memory_encoding(instruction, operand, 0)) {
                return 0;
            }
        } else if (operand->reg < CDISASM_X86_REG_XMM0
            || operand->reg > CDISASM_X86_REG_XMM15
            || operand->flags != 0u) {
            return 0;
        }
    }
    return register_low3_matches(instruction->opcode[0].reg,
               CDISASM_X86_REG_XMM0,
               (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))
        && (memory_form
            || register_low3_matches(instruction->opcode[1].reg,
                CDISASM_X86_REG_XMM0,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))));
}

static int valid_vpmovx_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    static const struct family_shape {
        uint16_t name;
        uint16_t xmm_memory_form;
        uint16_t ymm_memory_form;
        uint8_t xmm_source_size;
    } families[] = {
        {CDISASM_X86_NAME_VPMOVSXBW, 7419, 7425, 8},
        {CDISASM_X86_NAME_VPMOVSXBD, 7399, 7405, 4},
        {CDISASM_X86_NAME_VPMOVSXBQ, 7409, 7415, 2},
        {CDISASM_X86_NAME_VPMOVSXWD, 7439, 7445, 8},
        {CDISASM_X86_NAME_VPMOVSXWQ, 7449, 7455, 4},
        {CDISASM_X86_NAME_VPMOVSXDQ, 7429, 7435, 8},
        {CDISASM_X86_NAME_VPMOVZXBW, 7524, 7530, 8},
        {CDISASM_X86_NAME_VPMOVZXBD, 7504, 7510, 4},
        {CDISASM_X86_NAME_VPMOVZXBQ, 7514, 7520, 2},
        {CDISASM_X86_NAME_VPMOVZXWD, 7544, 7550, 8},
        {CDISASM_X86_NAME_VPMOVZXWQ, 7554, 7560, 4},
        {CDISASM_X86_NAME_VPMOVZXDQ, 7534, 7540, 8}
    };
    const struct family_shape *shape = NULL;
    const cdisasm_opcode *destination = &instruction->opcode[0];
    const cdisasm_opcode *source = &instruction->opcode[1];
    cdisasm_x86_reg_id destination_base;
    unsigned int vector_size = 0u;
    unsigned int source_size = 0u;
    int memory_form = 0;
    int family_name = 0;
    int family_form = 0;
    size_t index;

    for (index = 0u; index < sizeof(families) / sizeof(families[0]);
         ++index) {
        const struct family_shape *candidate = &families[index];

        family_name |= instruction->name_id == candidate->name;
        if (instruction->form_id == candidate->xmm_memory_form
            || instruction->form_id == candidate->xmm_memory_form + 1u
            || instruction->form_id == candidate->ymm_memory_form
            || instruction->form_id == candidate->ymm_memory_form + 1u) {
            shape = candidate;
            family_form = 1;
        }
    }
    if (!family_name && !family_form) {
        return 1;
    }
    /* Generated EVEX VPMOVSX/VPMOVZX forms already carry their own generated
     * descriptor contract.  This validator hardens only the classic-VEX
     * forms without narrowing those existing siblings. */
    if (family_name && !family_form
        && (instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u
        && (instruction->opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u) {
        return 1;
    }
    if (!family_name || shape == NULL
        || instruction->name_id != shape->name) {
        return 0;
    }
    if (instruction->form_id == shape->xmm_memory_form
        || instruction->form_id == shape->xmm_memory_form + 1u) {
        vector_size = 16u;
        source_size = shape->xmm_source_size;
        memory_form = instruction->form_id == shape->xmm_memory_form;
    } else {
        vector_size = 32u;
        source_size = 2u * shape->xmm_source_size;
        memory_form = instruction->form_id == shape->ymm_memory_form;
    }
    destination_base = vector_size == 16u
        ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0;

    if ((instruction->opcode_flags & ~allowed_flags) != 0u
        || (instruction->opcode_flags & CDISASM_PREFIX_VEX) == 0u
        || instruction->operand_count != 2u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 3u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || !valid_vpblend_groups(instruction, vector_size == 32u)
        || destination->type != CDISASM_OPERAND_REGISTER
        || destination->reg < destination_base
        || destination->reg > destination_base + 15u
        || destination->size != vector_size
        || destination->access != CDISASM_OPERAND_ACCESS_WRITE
        || destination->flags != 0u
        || destination->broadcast != CDISASM_X86_BROADCAST_NONE
        || source->type != (memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
        || source->size != source_size
        || source->access != CDISASM_OPERAND_ACCESS_READ
        || source->broadcast != CDISASM_X86_BROADCAST_NONE) {
        return 0;
    }
    if (memory_form) {
        if ((source->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
            || !valid_modrm_memory_encoding(instruction, source, 0)) {
            return 0;
        }
    } else if (source->reg < CDISASM_X86_REG_XMM0
        || source->reg > CDISASM_X86_REG_XMM15
        || source->flags != 0u) {
        return 0;
    }
    return register_low3_matches(destination->reg, destination_base,
               (uint8_t)((instruction->encoding.modrm >> 3)
                   & UINT8_C(7)))
        && (memory_form
            || register_low3_matches(source->reg, CDISASM_X86_REG_XMM0,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))));
}

static int valid_vpextr_schema(const cdisasm_instruction *instruction)
{
    const uint32_t classic_allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t evex_allowed_flags = CDISASM_PREFIX_EVEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT
        | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const unsigned int legacy_prefix_count =
        ((instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
        + ((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u);
    static const struct family_shape {
        uint16_t classic_name;
        uint16_t evex_name;
        uint16_t classic_register_form;
        uint16_t classic_memory_form;
        uint16_t evex_register_form;
        uint16_t evex_memory_form;
        uint8_t register_size;
        uint8_t memory_size;
        uint8_t map1_c5;
        uint16_t evex_group;
    } families[] = {
        {CDISASM_X86_NAME_VPEXTRB, CDISASM_X86_NAME_VPEXTRB,
            6966, 6968, 6967, 6969, 4, 1, 0,
            CDISASM_X86_GROUP_AVX512BW_128N},
        {CDISASM_X86_NAME_VPEXTRD, CDISASM_X86_NAME_VPEXTRD,
            6970, 6972, 6971, 6973, 4, 4, 0,
            CDISASM_X86_GROUP_AVX512DQ_128N},
        {CDISASM_X86_NAME_VPEXTRQ, CDISASM_X86_NAME_VPEXTRQ,
            6974, 6976, 6975, 6977, 8, 8, 0,
            CDISASM_X86_GROUP_AVX512DQ_128N},
        {CDISASM_X86_NAME_VPEXTRW, CDISASM_X86_NAME_VPEXTRW,
            6978, 6983, 6980, 6982, 4, 2, 0,
            CDISASM_X86_GROUP_AVX512BW_128N},
        {CDISASM_X86_NAME_VPEXTRW, CDISASM_X86_NAME_VPEXTRW_C5,
            6979, 0, 6981, 0, 4, 2, 1,
            CDISASM_X86_GROUP_AVX512BW_128N}};
    const int family_name = instruction->name_id
            == CDISASM_X86_NAME_VPEXTRB
        || instruction->name_id == CDISASM_X86_NAME_VPEXTRD
        || instruction->name_id == CDISASM_X86_NAME_VPEXTRQ
        || instruction->name_id == CDISASM_X86_NAME_VPEXTRW
        || instruction->name_id == CDISASM_X86_NAME_VPEXTRW_C5;
    const struct family_shape *shape = NULL;
    int evex_form = 0;
    int memory_form = 0;
    int allow_egpr = 0;
    unsigned int native_prefix_size;
    cdisasm_x86_reg_id destination_base;
    unsigned int destination_limit;
    unsigned int source_limit;
    const cdisasm_opcode *destination;
    const cdisasm_opcode *source;
    const cdisasm_opcode *immediate;
    size_t index;

    for (index = 0u; index < sizeof(families) / sizeof(families[0]);
         ++index) {
        if (instruction->form_id == families[index].classic_register_form
            || (families[index].classic_memory_form != 0u
                && instruction->form_id
                    == families[index].classic_memory_form)) {
            shape = &families[index];
            memory_form = instruction->form_id
                == families[index].classic_memory_form;
            break;
        }
        if (instruction->form_id == families[index].evex_register_form
            || (families[index].evex_memory_form != 0u
                && instruction->form_id == families[index].evex_memory_form)) {
            shape = &families[index];
            evex_form = 1;
            memory_form = instruction->form_id
                == families[index].evex_memory_form;
            break;
        }
    }

    if (!family_name && shape == NULL) {
        return 1;
    }
    if (!family_name || shape == NULL
        || instruction->name_id != (evex_form
            ? shape->evex_name : shape->classic_name)
        || instruction->operand_count != 3u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 1u
        || instruction->encoding.immediate_size[0] != 1u
        || instruction->encoding.immediate_offset[0]
            != instruction->opcode_size - 1u
        || instruction->encoding.selector_offset != 0u) {
        return 0;
    }

    if (evex_form) {
        native_prefix_size = 4u;
        if (modern_prefix != CDISASM_PREFIX_EVEX
            || (instruction->opcode_flags & ~evex_allowed_flags) != 0u
            || (instruction->opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u
            || !valid_generated_evex_width_groups(
                instruction, shape->evex_group, &allow_egpr)) {
            return 0;
        }
    } else {
        native_prefix_size = shape->map1_c5 ? 2u : 3u;
        if (modern_prefix != CDISASM_PREFIX_VEX
            || (instruction->opcode_flags & ~classic_allowed_flags) != 0u
            || !valid_vpblend_groups(instruction, 0)) {
            return 0;
        }
    }
    if (instruction->encoding.prefix_size
            < native_prefix_size + legacy_prefix_count
        || (instruction->encoding.prefix_size
                > (evex_form ? 4u : 3u)
            && (instruction->opcode_flags
                & (CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u)) {
        return 0;
    }
    if ((((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))) {
        return 0;
    }

    destination = &instruction->opcode[0];
    source = &instruction->opcode[1];
    immediate = &instruction->opcode[2];
    destination_base = shape->register_size == 8u
        ? CDISASM_X86_REG_RAX : CDISASM_X86_REG_EAX;
    destination_limit = allow_egpr ? 31u : 15u;
    source_limit = evex_form ? 31u : 15u;
    if (!evex_form && shape->map1_c5
        && instruction->encoding.prefix_size
            < 3u + legacy_prefix_count) {
        /* A native two-byte C5 spelling has no B extension for ModRM.rm.
         * The same public form can reach XMM8-15 only through C4. */
        source_limit = 7u;
    }

    if (destination->type != (memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
        || destination->size != (memory_form
            ? shape->memory_size : shape->register_size)
        || destination->access != CDISASM_OPERAND_ACCESS_WRITE
        || destination->broadcast != CDISASM_X86_BROADCAST_NONE) {
        return 0;
    }
    if (memory_form) {
        if ((destination->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
            || !valid_modrm_memory_encoding(
                instruction, destination, allow_egpr)) {
            return 0;
        }
    } else if (destination->reg < destination_base
        || destination->reg > destination_base + destination_limit
        || destination->flags != 0u
        || !register_low3_matches(destination->reg, destination_base,
            shape->map1_c5
                ? (uint8_t)((instruction->encoding.modrm >> 3)
                    & UINT8_C(7))
                : (uint8_t)(instruction->encoding.modrm & UINT8_C(7)))) {
        return 0;
    }

    if (source->type != CDISASM_OPERAND_REGISTER
        || source->reg < CDISASM_X86_REG_XMM0
        || source->reg > CDISASM_X86_REG_XMM0 + source_limit
        || source->size != 16u
        || source->access != CDISASM_OPERAND_ACCESS_READ
        || source->flags != 0u
        || source->broadcast != CDISASM_X86_BROADCAST_NONE
        || !register_low3_matches(source->reg, CDISASM_X86_REG_XMM0,
            shape->map1_c5
                ? (uint8_t)(instruction->encoding.modrm & UINT8_C(7))
                : (uint8_t)((instruction->encoding.modrm >> 3)
                    & UINT8_C(7)))) {
        return 0;
    }
    return immediate->type == CDISASM_OPERAND_IMMEDIATE
        && immediate->size == 1u
        && immediate->access == CDISASM_OPERAND_ACCESS_READ
        && immediate->flags == 0u
        && immediate->broadcast == CDISASM_X86_BROADCAST_NONE
        && immediate->imm <= UINT8_MAX;
}

static int valid_vpinsr_schema(const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const unsigned int legacy_prefix_count =
        ((instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
        + ((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u);
    static const struct family_shape {
        uint16_t base;
        uint16_t name;
        uint8_t register_size;
        uint8_t memory_size;
        uint16_t evex_group;
    } families[] = {
        {7060, CDISASM_X86_NAME_VPINSRB, 4, 1,
            CDISASM_X86_GROUP_AVX512BW_128N},
        {7064, CDISASM_X86_NAME_VPINSRD, 4, 4,
            CDISASM_X86_GROUP_AVX512DQ_128N},
        {7068, CDISASM_X86_NAME_VPINSRQ, 8, 8,
            CDISASM_X86_GROUP_AVX512DQ_128N},
        {7072, CDISASM_X86_NAME_VPINSRW, 4, 2,
            CDISASM_X86_GROUP_AVX512BW_128N}};
    const int family_name = instruction->name_id == CDISASM_X86_NAME_VPINSRB
        || instruction->name_id == CDISASM_X86_NAME_VPINSRD
        || instruction->name_id == CDISASM_X86_NAME_VPINSRQ
        || instruction->name_id == CDISASM_X86_NAME_VPINSRW;
    const struct family_shape *shape = NULL;
    int family_form = 0;
    int evex_form = 0;
    int memory_form;
    size_t index;

    for (index = 0u; index < sizeof(families) / sizeof(families[0]);
         ++index) {
        if (instruction->form_id >= families[index].base
            && instruction->form_id <= families[index].base + UINT16_C(1)) {
            family_form = 1;
            shape = &families[index];
            break;
        }
        if (instruction->form_id >= families[index].base + UINT16_C(2)
            && instruction->form_id <= families[index].base + UINT16_C(3)) {
            evex_form = 1;
            shape = &families[index];
            break;
        }
    }

    /* Generated EVEX siblings are part of the same public-name surface.
     * Bind their complete recipe rather than only their form/name identity:
     * otherwise forged decoded objects could cross form parity, operand,
     * decorator, group, or encoding boundaries and still be formatted. */
    if (evex_form || (family_name && modern_prefix == CDISASM_PREFIX_EVEX)) {
        const uint32_t evex_allowed_flags = CDISASM_PREFIX_EVEX
            | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT
            | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        const cdisasm_opcode *scalar;
        const cdisasm_opcode *immediate;
        const cdisasm_x86_reg_id scalar_base = shape != NULL
                && shape->register_size == 8u
            ? CDISASM_X86_REG_RAX : CDISASM_X86_REG_EAX;
        int allow_egpr;

        if (!family_name || !evex_form || shape == NULL
            || instruction->name_id != shape->name
            || modern_prefix != CDISASM_PREFIX_EVEX
            || (instruction->opcode_flags & ~evex_allowed_flags) != 0u
            || (instruction->opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u
            || instruction->operand_count != 4u
            || instruction->mask_mode != CDISASM_X86_MASK_NONE
            || instruction->mask_reg != CDISASM_X86_REG_NONE
            || instruction->rounding != CDISASM_X86_ROUNDING_NONE
            || instruction->sae != CDISASM_X86_SAE_NONE
            || instruction->opcode_groups != CDISASM_GROUP_NONE
            || instruction->branch_target != 0u
            || instruction->encoding.prefix_size < 4u + legacy_prefix_count
            || (instruction->encoding.prefix_size > 4u
                && (instruction->opcode_flags
                    & (CDISASM_PREFIX_ADDRESS_SIZE
                        | CDISASM_PREFIX_SEGMENT)) == 0u)
            || instruction->encoding.opcode_size != 1u
            || instruction->encoding.modrm_offset
                != instruction->encoding.opcode_offset + 1u
            || instruction->encoding.immediate_count != 1u
            || instruction->encoding.immediate_size[0] != 1u
            || instruction->encoding.immediate_offset[0]
                != instruction->opcode_size - 1u
            || instruction->encoding.selector_offset != 0u
            || !valid_generated_evex_width_groups(
                instruction, shape->evex_group, &allow_egpr)) {
            return 0;
        }
        memory_form = (instruction->form_id & UINT16_C(1)) != 0u;
        if ((((instruction->encoding.modrm & UINT8_C(0xc0))
                    == UINT8_C(0xc0)) == memory_form)
            || (!memory_form
                && (instruction->encoding.sib_offset != 0u
                    || instruction->encoding.displacement_offset != 0u
                    || instruction->encoding.displacement_size != 0u))) {
            return 0;
        }
        for (index = 0u; index < 2u; ++index) {
            const cdisasm_opcode *operand = &instruction->opcode[index];

            if (operand->type != CDISASM_OPERAND_REGISTER
                || operand->reg < CDISASM_X86_REG_XMM0
                || operand->reg > CDISASM_X86_REG_XMM31
                || operand->size != 16u
                || operand->access != (index == 0u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ)
                || operand->flags != 0u
                || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
                return 0;
            }
        }
        scalar = &instruction->opcode[2];
        if (scalar->type != (memory_form
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || scalar->size != (memory_form
                ? shape->memory_size : shape->register_size)
            || scalar->access != CDISASM_OPERAND_ACCESS_READ
            || scalar->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory_form) {
            if ((scalar->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_modrm_memory_encoding(
                    instruction, scalar, allow_egpr)) {
                return 0;
            }
        } else if (scalar->reg < scalar_base
            || scalar->reg > scalar_base + (allow_egpr ? 31u : 15u)
            || scalar->flags != 0u
            || !register_low3_matches(scalar->reg, scalar_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7)))) {
            return 0;
        }
        immediate = &instruction->opcode[3];
        return register_low3_matches(instruction->opcode[0].reg,
                   CDISASM_X86_REG_XMM0,
                   (uint8_t)((instruction->encoding.modrm >> 3)
                       & UINT8_C(7)))
            && immediate->type == CDISASM_OPERAND_IMMEDIATE
            && immediate->size == 1u
            && immediate->access == CDISASM_OPERAND_ACCESS_READ
            && immediate->flags == 0u
            && immediate->broadcast == CDISASM_X86_BROADCAST_NONE
            && immediate->imm <= UINT8_MAX;
    }
    if (!family_name && !family_form) {
        return 1;
    }
    if (!family_name || !family_form || shape == NULL
        || instruction->name_id != shape->name
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 4u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size
            < (shape->name == CDISASM_X86_NAME_VPINSRW ? 2u : 3u)
                + legacy_prefix_count
        || (instruction->encoding.prefix_size > 3u
            && (instruction->opcode_flags
                & (CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u)
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 1u
        || instruction->encoding.immediate_size[0] != 1u
        || instruction->encoding.immediate_offset[0]
            != instruction->opcode_size - 1u
        || instruction->encoding.selector_offset != 0u
        || !valid_vpblend_groups(instruction, 0)) {
        return 0;
    }

    memory_form = (instruction->form_id & UINT16_C(1)) != 0u;
    if ((((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))) {
        return 0;
    }
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];

        if (operand->type != CDISASM_OPERAND_REGISTER
            || operand->reg < CDISASM_X86_REG_XMM0
            || operand->reg > CDISASM_X86_REG_XMM15
            || operand->size != 16u
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->flags != 0u
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
    }
    {
        const cdisasm_opcode *scalar = &instruction->opcode[2];
        const cdisasm_x86_reg_id register_base = shape->register_size == 8u
            ? CDISASM_X86_REG_RAX : CDISASM_X86_REG_EAX;

        if (scalar->type != (memory_form
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || scalar->size != (memory_form
                ? shape->memory_size : shape->register_size)
            || scalar->access != CDISASM_OPERAND_ACCESS_READ
            || scalar->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory_form) {
            if ((scalar->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_modrm_memory_encoding(instruction, scalar, 0)) {
                return 0;
            }
        } else if (scalar->reg < register_base
            || scalar->reg > register_base + 15u
            || scalar->flags != 0u
            || !register_low3_matches(scalar->reg, register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7)))) {
            return 0;
        }
    }
    return register_low3_matches(instruction->opcode[0].reg,
               CDISASM_X86_REG_XMM0,
               (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))
        && instruction->opcode[3].type == CDISASM_OPERAND_IMMEDIATE
        && instruction->opcode[3].size == 1u
        && instruction->opcode[3].access == CDISASM_OPERAND_ACCESS_READ
        && instruction->opcode[3].flags == 0u
        && instruction->opcode[3].broadcast == CDISASM_X86_BROADCAST_NONE
        && instruction->opcode[3].imm <= UINT8_MAX;
}

static int valid_horizontal_integer_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    static const struct family_range {
        uint16_t base;
        uint16_t name;
    } families[] = {
        {7012, CDISASM_X86_NAME_VPHADDD},
        {7016, CDISASM_X86_NAME_VPHADDSW},
        {7036, CDISASM_X86_NAME_VPHADDW},
        {7046, CDISASM_X86_NAME_VPHSUBD},
        {7050, CDISASM_X86_NAME_VPHSUBSW},
        {7056, CDISASM_X86_NAME_VPHSUBW}};
    const int family_name =
        instruction->name_id == CDISASM_X86_NAME_VPHADDD
        || instruction->name_id == CDISASM_X86_NAME_VPHADDSW
        || instruction->name_id == CDISASM_X86_NAME_VPHADDW
        || instruction->name_id == CDISASM_X86_NAME_VPHSUBD
        || instruction->name_id == CDISASM_X86_NAME_VPHSUBSW
        || instruction->name_id == CDISASM_X86_NAME_VPHSUBW;
    uint16_t offset = 0u;
    int identity = 0;
    int family_form = 0;
    unsigned int vector_size;
    cdisasm_x86_reg_id register_base;
    int memory_form;
    size_t index;

    for (index = 0u; index < sizeof(families) / sizeof(families[0]);
         ++index) {
        if (instruction->form_id >= families[index].base
            && instruction->form_id <= families[index].base + 3u) {
            offset = (uint16_t)(instruction->form_id - families[index].base);
            identity = instruction->name_id == families[index].name;
            family_form = 1;
            break;
        }
    }
    if (!family_name && !family_form) {
        return 1;
    }
    if (!family_name || !family_form || !identity
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 3u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 3u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u) {
        return 0;
    }

    vector_size = offset >= 2u ? 32u : 16u;
    register_base = vector_size == 32u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    memory_form = (offset & 1u) == 0u;
    if (!valid_vpblend_groups(instruction, vector_size == 32u)
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))) {
        return 0;
    }
    for (index = 0u; index < 3u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = memory_form && index == 2u;

        if (operand->type != (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != vector_size
            || operand->access != (index == 0u
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ)
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !valid_modrm_memory_encoding(instruction, operand, 0)) {
                return 0;
            }
        } else if (operand->reg < register_base
            || operand->reg > register_base + 15u
            || operand->flags != 0u) {
            return 0;
        }
    }
    return register_low3_matches(instruction->opcode[0].reg,
               register_base,
               (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))
        && (memory_form
            || register_low3_matches(instruction->opcode[2].reg,
                register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))));
}

static int valid_vpshuf_integer_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    static const struct family_range {
        uint16_t base;
        uint16_t name;
    } families[] = {
        {7891, CDISASM_X86_NAME_VPSHUFD},
        {7901, CDISASM_X86_NAME_VPSHUFHW},
        {7911, CDISASM_X86_NAME_VPSHUFLW}};
    const int family_name =
        instruction->name_id == CDISASM_X86_NAME_VPSHUFD
        || instruction->name_id == CDISASM_X86_NAME_VPSHUFHW
        || instruction->name_id == CDISASM_X86_NAME_VPSHUFLW;
    uint16_t offset = 0u;
    int identity = 0;
    int classic_form = 0;
    int evex_form = 0;
    unsigned int vector_size;
    cdisasm_x86_reg_id register_base;
    int memory_form;
    const cdisasm_opcode *destination;
    const cdisasm_opcode *source;
    const cdisasm_opcode *immediate;
    size_t index;

    for (index = 0u; index < sizeof(families) / sizeof(families[0]);
         ++index) {
        if (instruction->form_id >= families[index].base
            && instruction->form_id <= families[index].base + 9u) {
            offset = (uint16_t)(instruction->form_id - families[index].base);
            identity = instruction->name_id == families[index].name;
            classic_form = offset <= 1u
                || offset == 4u || offset == 5u;
            evex_form = !classic_form;
            break;
        }
    }

    /* The generated decoder retains the six same-name EVEX siblings per
     * mnemonic.  Validate those recipes too so a forged object cannot cross
     * between the generated EVEX and exact classic-VEX schemas. */
    if (evex_form || (family_name && modern_prefix == CDISASM_PREFIX_EVEX)) {
        const uint32_t evex_allowed_flags = CDISASM_PREFIX_EVEX
            | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT
            | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        cdisasm_x86_group_id width_group;
        unsigned int scalar_size;
        int allow_egpr;

        if (offset <= 3u) {
            vector_size = 16u;
            register_base = CDISASM_X86_REG_XMM0;
        } else if (offset <= 7u) {
            vector_size = 32u;
            register_base = CDISASM_X86_REG_YMM0;
        } else {
            vector_size = 64u;
            register_base = CDISASM_X86_REG_ZMM0;
        }
        if (instruction->name_id == CDISASM_X86_NAME_VPSHUFD) {
            width_group = vector_size == 16u
                ? CDISASM_X86_GROUP_AVX512F_128
                : (vector_size == 32u
                    ? CDISASM_X86_GROUP_AVX512F_256
                    : CDISASM_X86_GROUP_AVX512F_512);
            scalar_size = 4u;
        } else {
            width_group = vector_size == 16u
                ? CDISASM_X86_GROUP_AVX512BW_128
                : (vector_size == 32u
                    ? CDISASM_X86_GROUP_AVX512BW_256
                    : CDISASM_X86_GROUP_AVX512BW_512);
            scalar_size = 2u;
        }
        memory_form = (offset & 1u) == 0u;
        destination = &instruction->opcode[0];
        source = &instruction->opcode[1];
        immediate = &instruction->opcode[2];

        if (!identity || !evex_form
            || modern_prefix != CDISASM_PREFIX_EVEX
            || (instruction->opcode_flags & ~evex_allowed_flags) != 0u
            || (instruction->opcode_flags
                & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u
            || instruction->operand_count != 3u
            || instruction->rounding != CDISASM_X86_ROUNDING_NONE
            || instruction->sae != CDISASM_X86_SAE_NONE
            || instruction->opcode_groups != CDISASM_GROUP_NONE
            || instruction->branch_target != 0u
            || instruction->encoding.prefix_size < 4u
            || instruction->encoding.opcode_size != 1u
            || instruction->encoding.modrm_offset
                != instruction->encoding.opcode_offset + 1u
            || instruction->encoding.immediate_count != 1u
            || instruction->encoding.immediate_size[0] != 1u
            || instruction->encoding.immediate_offset[0]
                != instruction->opcode_size - 1u
            || instruction->encoding.selector_offset != 0u
            || !valid_generated_evex_width_groups(
                instruction, width_group, &allow_egpr)
            || (((instruction->encoding.modrm & UINT8_C(0xc0))
                    == UINT8_C(0xc0)) == memory_form)
            || (!memory_form
                && (instruction->encoding.sib_offset != 0u
                    || instruction->encoding.displacement_offset != 0u
                    || instruction->encoding.displacement_size != 0u))
            || destination->type != CDISASM_OPERAND_REGISTER
            || destination->size != vector_size
            || destination->access != CDISASM_OPERAND_ACCESS_WRITE
            || destination->reg < register_base
            || destination->reg > register_base + 31u
            || destination->flags != 0u
            || destination->broadcast != CDISASM_X86_BROADCAST_NONE
            || source->type != (memory_form
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || source->access != CDISASM_OPERAND_ACCESS_READ) {
            return 0;
        }
        if (memory_form) {
            const int dword_broadcast =
                instruction->name_id == CDISASM_X86_NAME_VPSHUFD
                && source->size == scalar_size
                && source->broadcast
                    == (cdisasm_x86_broadcast)(vector_size / scalar_size);

            if ((source->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
                || !((source->size == vector_size
                        && source->broadcast
                            == CDISASM_X86_BROADCAST_NONE)
                    || dword_broadcast)
                || !valid_modrm_memory_encoding(
                    instruction, source, allow_egpr)) {
                return 0;
            }
        } else if (source->size != vector_size
            || source->reg < register_base
            || source->reg > register_base + 31u
            || source->flags != 0u
            || source->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        return register_low3_matches(destination->reg, register_base,
                   (uint8_t)((instruction->encoding.modrm >> 3)
                       & UINT8_C(7)))
            && (memory_form
                || register_low3_matches(source->reg, register_base,
                    (uint8_t)(instruction->encoding.modrm & UINT8_C(7))))
            && immediate->type == CDISASM_OPERAND_IMMEDIATE
            && immediate->size == 1u
            && immediate->access == CDISASM_OPERAND_ACCESS_READ
            && immediate->flags == 0u
            && immediate->broadcast == CDISASM_X86_BROADCAST_NONE
            && immediate->imm <= UINT8_MAX;
    }
    if (!classic_form && !family_name) {
        return 1;
    }
    if (!classic_form || !family_name || !identity
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || modern_prefix != CDISASM_PREFIX_VEX
        || instruction->operand_count != 3u
        || instruction->mask_mode != CDISASM_X86_MASK_NONE
        || instruction->mask_reg != CDISASM_X86_REG_NONE
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size < 2u
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || instruction->encoding.immediate_count != 1u
        || instruction->encoding.immediate_size[0] != 1u
        || instruction->encoding.immediate_offset[0]
            != instruction->opcode_size - 1u
        || instruction->encoding.selector_offset != 0u) {
        return 0;
    }

    vector_size = offset >= 4u ? 32u : 16u;
    register_base = vector_size == 32u
        ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
    memory_form = offset == 0u || offset == 4u;
    destination = &instruction->opcode[0];
    source = &instruction->opcode[1];
    immediate = &instruction->opcode[2];
    if (!valid_vpblend_groups(instruction, vector_size == 32u)
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || destination->type != CDISASM_OPERAND_REGISTER
        || destination->size != vector_size
        || destination->access != CDISASM_OPERAND_ACCESS_WRITE
        || destination->reg < register_base
        || destination->reg > register_base + 15u
        || destination->flags != 0u
        || destination->broadcast != CDISASM_X86_BROADCAST_NONE
        || source->type != (memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
        || source->size != vector_size
        || source->access != CDISASM_OPERAND_ACCESS_READ
        || source->broadcast != CDISASM_X86_BROADCAST_NONE) {
        return 0;
    }
    if (memory_form) {
        if ((source->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) != 0u
            || !valid_modrm_memory_encoding(instruction, source, 0)) {
            return 0;
        }
    } else if (source->reg < register_base
        || source->reg > register_base + 15u
        || source->flags != 0u) {
        return 0;
    }
    return register_low3_matches(destination->reg, register_base,
               (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))
        && (memory_form
            || register_low3_matches(source->reg, register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))))
        && immediate->type == CDISASM_OPERAND_IMMEDIATE
        && immediate->size == 1u
        && immediate->access == CDISASM_OPERAND_ACCESS_READ
        && immediate->flags == 0u
        && immediate->broadcast == CDISASM_X86_BROADCAST_NONE
        && immediate->imm <= UINT8_MAX;
}

static int valid_vdbpsadbw_groups(
    const cdisasm_instruction *instruction,
    unsigned int vector_size,
    int *allow_egpr)
{
    const unsigned int provenance =
        exact_instruction_provenance(instruction);
    const int avx512_route = cdisasm_instruction_has_x86_group(
        instruction,CDISASM_X86_GROUP_AVX512F);
    const int avx10_route = cdisasm_instruction_has_x86_group(
        instruction,CDISASM_X86_GROUP_AVX10_1);
    const int apx = cdisasm_instruction_has_x86_group(
        instruction,CDISASM_X86_GROUP_APX_F);
    const cdisasm_x86_group_id width_group = vector_size == 16u
        ? CDISASM_X86_GROUP_AVX512BW_128
        : vector_size == 32u ? CDISASM_X86_GROUP_AVX512BW_256
                             : CDISASM_X86_GROUP_AVX512BW_512;
    size_t expected = 0u;

    *allow_egpr = apx;
    if (avx512_route == avx10_route) {
        return 0;
    }
    if ((provenance & 1u) != 0u
        && instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_I386) {
        return 0;
    }
    if ((provenance & 2u) != 0u
        && instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_AMD64) {
        return 0;
    }
    if (instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_AVX) {
        return 0;
    }
    if (avx512_route) {
        if (instruction->x86_group_ids[expected++]
                != CDISASM_X86_GROUP_AVX512F
            || instruction->x86_group_ids[expected++]
                != CDISASM_X86_GROUP_AVX512BW
            || (vector_size < 64u
                && instruction->x86_group_ids[expected++]
                    != CDISASM_X86_GROUP_AVX512VL)) {
            return 0;
        }
    } else if (instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_AVX10_1) {
        return 0;
    }
    if (apx && instruction->x86_group_ids[expected++]
            != CDISASM_X86_GROUP_APX_F) {
        return 0;
    }
    return instruction->x86_group_ids[expected++] == width_group
        && expected == instruction->x86_group_count;
}

static int valid_vdbpsadbw_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_EVEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int family_name =
        instruction->name_id == CDISASM_X86_NAME_VDBPSADBW;
    const int family_form =
        instruction->form_id >= UINT16_C(4453)
        && instruction->form_id <= UINT16_C(4458);
    const unsigned int relative = family_form
        ? instruction->form_id - UINT16_C(4453) : 0u;
    const unsigned int vector_size = 16u << (relative / 2u);
    const int memory_form = (relative & 1u) == 0u;
    const cdisasm_x86_reg_id register_base = vector_size == 16u
        ? CDISASM_X86_REG_XMM0
        : vector_size == 32u ? CDISASM_X86_REG_YMM0
                             : CDISASM_X86_REG_ZMM0;
    const unsigned int legacy_prefix_count =
        ((instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
        + ((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u);
    const cdisasm_opcode *destination = &instruction->opcode[0];
    const cdisasm_opcode *source1 = &instruction->opcode[1];
    const cdisasm_opcode *source2 = &instruction->opcode[2];
    const cdisasm_opcode *immediate = &instruction->opcode[3];
    int allow_egpr = 0;

    /* Match the name and form halves independently.  This prevents a forged
     * VDBPSADBW object from escaping into the generic formatter merely by
     * changing one half of its exact pinned-XED identity. */
    if (!family_name && !family_form) {
        return 1;
    }
    if (!family_name || !family_form
        || modern_prefix != CDISASM_PREFIX_EVEX
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || instruction->operand_count != 4u
        || (instruction->mask_mode != CDISASM_X86_MASK_NONE
            && instruction->mask_mode != CDISASM_X86_MASK_MERGE
            && instruction->mask_mode != CDISASM_X86_MASK_ZERO)
        || ((instruction->mask_mode == CDISASM_X86_MASK_NONE)
            != (instruction->mask_reg == CDISASM_X86_REG_NONE))
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size
            < 4u + legacy_prefix_count
        || (instruction->encoding.prefix_size > 4u
            && (instruction->opcode_flags
                & (CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u)
        || instruction->encoding.opcode_offset
            != instruction->encoding.prefix_size
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || instruction->encoding.immediate_count != 1u
        || instruction->encoding.immediate_size[0] != 1u
        || instruction->encoding.immediate_offset[0]
            != instruction->opcode_size - 1u
        || instruction->encoding.selector_offset != 0u
        || !valid_vdbpsadbw_groups(
            instruction,vector_size,&allow_egpr)
        || destination->type != CDISASM_OPERAND_REGISTER
        || destination->size != vector_size
        || destination->access
            != (instruction->mask_mode == CDISASM_X86_MASK_MERGE
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE)
        || destination->reg < register_base
        || destination->reg > register_base + 31u
        || destination->flags != 0u
        || destination->broadcast != CDISASM_X86_BROADCAST_NONE
        || source1->type != CDISASM_OPERAND_REGISTER
        || source1->size != vector_size
        || source1->access != CDISASM_OPERAND_ACCESS_READ
        || source1->reg < register_base
        || source1->reg > register_base + 31u
        || source1->flags != 0u
        || source1->broadcast != CDISASM_X86_BROADCAST_NONE
        || source2->type != (memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
        || source2->size != vector_size
        || source2->access != CDISASM_OPERAND_ACCESS_READ
        || source2->broadcast != CDISASM_X86_BROADCAST_NONE
        || !register_low3_matches(
            destination->reg,register_base,
            (uint8_t)((instruction->encoding.modrm >> 3)
                & UINT8_C(7)))
        || immediate->type != CDISASM_OPERAND_IMMEDIATE
        || immediate->size != 1u
        || immediate->access != CDISASM_OPERAND_ACCESS_READ
        || immediate->flags != 0u
        || immediate->broadcast != CDISASM_X86_BROADCAST_NONE
        || immediate->imm > UINT8_MAX) {
        return 0;
    }
    if (memory_form) {
        const int has_segment = (instruction->opcode_flags
            & CDISASM_PREFIX_SEGMENT) != 0u;

        return (source2->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                    | CDISASM_OPERAND_FLAG_SIGNED)) == 0u
            && has_segment == ((source2->flags
                & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0u)
            && has_segment
                == (source2->segment_reg != CDISASM_X86_REG_NONE)
            && valid_modrm_memory_encoding(
                instruction,source2,allow_egpr);
    }
    return source2->reg >= register_base
        && source2->reg <= register_base + 31u
        && source2->flags == 0u
        && register_low3_matches(
            source2->reg,register_base,
            (uint8_t)(instruction->encoding.modrm & UINT8_C(7)));
}

static int valid_vpternlog_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_EVEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int family_name =
        instruction->name_id == CDISASM_X86_NAME_VPTERNLOGD
        || instruction->name_id == CDISASM_X86_NAME_VPTERNLOGQ;
    const int family_form =
        instruction->form_id >= UINT16_C(8259)
        && instruction->form_id <= UINT16_C(8270);
    const cdisasm_x86_name_id expected_name =
        instruction->form_id <= UINT16_C(8264)
            ? CDISASM_X86_NAME_VPTERNLOGD
            : CDISASM_X86_NAME_VPTERNLOGQ;
    const cdisasm_x86_form_id form_base =
        expected_name == CDISASM_X86_NAME_VPTERNLOGD
            ? UINT16_C(8259) : UINT16_C(8265);
    const unsigned int relative = family_form
        ? instruction->form_id - form_base : 0u;
    const unsigned int vector_size = 16u << (relative / 2u);
    const unsigned int element_size =
        expected_name == CDISASM_X86_NAME_VPTERNLOGD ? 4u : 8u;
    const int memory_form = (relative & 1u) == 0u;
    const cdisasm_x86_reg_id register_base = vector_size == 16u
        ? CDISASM_X86_REG_XMM0
        : vector_size == 32u ? CDISASM_X86_REG_YMM0
                             : CDISASM_X86_REG_ZMM0;
    const unsigned int legacy_prefix_count =
        ((instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
        + ((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u);
    const cdisasm_opcode *destination = &instruction->opcode[0];
    const cdisasm_opcode *source1 = &instruction->opcode[1];
    const cdisasm_opcode *source2 = &instruction->opcode[2];
    const cdisasm_opcode *immediate = &instruction->opcode[3];
    int allow_egpr = 0;

    /* Both halves of the exact identity are owned.  In particular, no
     * same-name or same-form forgery may fall through to the generic
     * formatter, whose ordinary NDS destination-access rule is not valid
     * for ternary logic. */
    if (!family_name && !family_form) {
        return 1;
    }
    if (!family_name || !family_form
        || instruction->name_id != expected_name
        || modern_prefix != CDISASM_PREFIX_EVEX
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || instruction->operand_count != 4u
        || (instruction->mask_mode != CDISASM_X86_MASK_NONE
            && instruction->mask_mode != CDISASM_X86_MASK_MERGE
            && instruction->mask_mode != CDISASM_X86_MASK_ZERO)
        || ((instruction->mask_mode == CDISASM_X86_MASK_NONE)
            != (instruction->mask_reg == CDISASM_X86_REG_NONE))
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size
            < 4u + legacy_prefix_count
        || (instruction->encoding.prefix_size > 4u
            && (instruction->opcode_flags
                & (CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u)
        || instruction->encoding.opcode_offset
            != instruction->encoding.prefix_size
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || instruction->encoding.immediate_count != 1u
        || instruction->encoding.immediate_size[0] != 1u
        || instruction->encoding.immediate_offset[0]
            != instruction->opcode_size - 1u
        || instruction->encoding.selector_offset != 0u
        || !valid_exact_avx512f_width_groups(
            instruction, vector_size, &allow_egpr)
        || destination->type != CDISASM_OPERAND_REGISTER
        || destination->size != vector_size
        || destination->access != CDISASM_OPERAND_ACCESS_READ_WRITE
        || destination->reg < register_base
        || destination->reg > register_base + 31u
        || destination->flags != 0u
        || destination->broadcast != CDISASM_X86_BROADCAST_NONE
        || source1->type != CDISASM_OPERAND_REGISTER
        || source1->size != vector_size
        || source1->access != CDISASM_OPERAND_ACCESS_READ
        || source1->reg < register_base
        || source1->reg > register_base + 31u
        || source1->flags != 0u
        || source1->broadcast != CDISASM_X86_BROADCAST_NONE
        || source2->type != (memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
        || source2->access != CDISASM_OPERAND_ACCESS_READ
        || !register_low3_matches(
            destination->reg, register_base,
            (uint8_t)((instruction->encoding.modrm >> 3)
                & UINT8_C(7)))
        || immediate->type != CDISASM_OPERAND_IMMEDIATE
        || immediate->size != 1u
        || immediate->access != CDISASM_OPERAND_ACCESS_READ
        || immediate->flags != 0u
        || immediate->broadcast != CDISASM_X86_BROADCAST_NONE
        || immediate->imm > UINT8_MAX) {
        return 0;
    }
    if (memory_form) {
        const int has_segment = (instruction->opcode_flags
            & CDISASM_PREFIX_SEGMENT) != 0u;
        const cdisasm_x86_broadcast expected_broadcast =
            (cdisasm_x86_broadcast)(vector_size / element_size);

        return (source2->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                    | CDISASM_OPERAND_FLAG_SIGNED)) == 0u
            && has_segment == ((source2->flags
                & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0u)
            && has_segment
                == (source2->segment_reg != CDISASM_X86_REG_NONE)
            && ((source2->broadcast == CDISASM_X86_BROADCAST_NONE
                    && source2->size == vector_size)
                || (source2->broadcast == expected_broadcast
                    && source2->size == element_size))
            && valid_modrm_memory_encoding(
                instruction, source2, allow_egpr);
    }
    return source2->size == vector_size
        && source2->broadcast == CDISASM_X86_BROADCAST_NONE
        && source2->reg >= register_base
        && source2->reg <= register_base + 31u
        && source2->flags == 0u
        && register_low3_matches(
            source2->reg, register_base,
            (uint8_t)(instruction->encoding.modrm & UINT8_C(7)));
}

static int valid_fp_compress_expand_schema(
    const cdisasm_instruction *instruction)
{
    const uint32_t allowed_flags = CDISASM_PREFIX_EVEX
        | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
    const uint32_t modern_prefix = instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2);
    const int family_name =
        instruction->name_id == CDISASM_X86_NAME_VCOMPRESSPD
        || instruction->name_id == CDISASM_X86_NAME_VCOMPRESSPS
        || instruction->name_id == CDISASM_X86_NAME_VEXPANDPD
        || instruction->name_id == CDISASM_X86_NAME_VEXPANDPS;
    const unsigned int legacy_prefix_count =
        ((instruction->opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
        + ((instruction->opcode_flags & CDISASM_PREFIX_SEGMENT) != 0u);
    cdisasm_x86_name_id expected_name = CDISASM_X86_NAME_NONE;
    unsigned int relative = 0u;
    unsigned int length = 0u;
    unsigned int vector_size = 0u;
    int compress = 0;
    int memory_form = 0;
    int allow_egpr = 0;
    int memory_operand = -1;
    cdisasm_x86_reg_id register_base = CDISASM_X86_REG_NONE;
    size_t index;

    if (instruction->form_id >= UINT16_C(3637)
        && instruction->form_id <= UINT16_C(3642)) {
        expected_name = CDISASM_X86_NAME_VCOMPRESSPD;
        relative = instruction->form_id - UINT16_C(3637);
        compress = 1;
        memory_form = relative < 3u;
        length = relative % 3u;
    } else if (instruction->form_id >= UINT16_C(3643)
        && instruction->form_id <= UINT16_C(3648)) {
        expected_name = CDISASM_X86_NAME_VCOMPRESSPS;
        relative = instruction->form_id - UINT16_C(3643);
        compress = 1;
        memory_form = relative < 3u;
        length = relative % 3u;
    } else if (instruction->form_id >= UINT16_C(4527)
        && instruction->form_id <= UINT16_C(4532)) {
        expected_name = CDISASM_X86_NAME_VEXPANDPD;
        relative = instruction->form_id - UINT16_C(4527);
        memory_form = (relative & 1u) == 0u;
        length = relative / 2u;
    } else if (instruction->form_id >= UINT16_C(4533)
        && instruction->form_id <= UINT16_C(4538)) {
        expected_name = CDISASM_X86_NAME_VEXPANDPS;
        relative = instruction->form_id - UINT16_C(4533);
        memory_form = (relative & 1u) == 0u;
        length = relative / 2u;
    }

    /* Match both halves of the name/form identity so a forged crossover to
     * the integer compress/expand family cannot bypass this exact recipe. */
    if (!family_name && expected_name == CDISASM_X86_NAME_NONE) {
        return 1;
    }
    vector_size = 16u << length;
    register_base = vector_size == 16u ? CDISASM_X86_REG_XMM0
        : vector_size == 32u ? CDISASM_X86_REG_YMM0
                             : CDISASM_X86_REG_ZMM0;
    memory_operand = memory_form ? (compress ? 0 : 1) : -1;
    if (!family_name || instruction->name_id != expected_name
        || modern_prefix != CDISASM_PREFIX_EVEX
        || (instruction->opcode_flags & ~allowed_flags) != 0u
        || instruction->operand_count != 2u
        || (instruction->mask_mode != CDISASM_X86_MASK_NONE
            && instruction->mask_mode != CDISASM_X86_MASK_MERGE
            && instruction->mask_mode != CDISASM_X86_MASK_ZERO)
        || ((instruction->mask_mode == CDISASM_X86_MASK_NONE)
            != (instruction->mask_reg == CDISASM_X86_REG_NONE))
        || (compress && memory_form
            && instruction->mask_mode == CDISASM_X86_MASK_ZERO)
        || instruction->rounding != CDISASM_X86_ROUNDING_NONE
        || instruction->sae != CDISASM_X86_SAE_NONE
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u
        || instruction->encoding.prefix_size
            < 4u + legacy_prefix_count
        || (instruction->encoding.prefix_size > 4u
            && (instruction->opcode_flags
                & (CDISASM_PREFIX_ADDRESS_SIZE
                    | CDISASM_PREFIX_SEGMENT)) == 0u)
        || instruction->encoding.opcode_offset
            != instruction->encoding.prefix_size
        || instruction->encoding.opcode_size != 1u
        || instruction->encoding.modrm_offset
            != instruction->encoding.opcode_offset + 1u
        || (((instruction->encoding.modrm & UINT8_C(0xc0))
                == UINT8_C(0xc0)) == memory_form)
        || (!memory_form
            && (instruction->encoding.sib_offset != 0u
                || instruction->encoding.displacement_offset != 0u
                || instruction->encoding.displacement_size != 0u))
        || instruction->encoding.immediate_count != 0u
        || instruction->encoding.selector_offset != 0u
        || !valid_exact_avx512f_width_groups(
            instruction,vector_size,&allow_egpr)) {
        return 0;
    }

    for (index = 0u; index < 2u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int is_memory = (int)index == memory_operand;
        const cdisasm_operand_access expected_access = index == 0u
            && !is_memory
            && instruction->mask_mode == CDISASM_X86_MASK_MERGE
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : index == 0u ? CDISASM_OPERAND_ACCESS_WRITE
                              : CDISASM_OPERAND_ACCESS_READ;

        if (operand->type != (is_memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
            || operand->size != vector_size
            || operand->access != expected_access
            || operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
        if (is_memory) {
            if ((operand->flags
                    & (CDISASM_OPERAND_FLAG_IMPLICIT
                        | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                        | CDISASM_OPERAND_FLAG_SIGNED)) != 0u
                || (((instruction->opcode_flags
                        & CDISASM_PREFIX_SEGMENT) != 0u)
                    != ((operand->flags
                        & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0u))
                || (((instruction->opcode_flags
                        & CDISASM_PREFIX_SEGMENT) != 0u)
                    != (operand->segment_reg
                        != CDISASM_X86_REG_NONE))
                || !valid_modrm_memory_encoding(
                    instruction,operand,allow_egpr)) {
                return 0;
            }
        } else if (operand->reg < register_base
            || operand->reg > register_base + 31u
            || operand->flags != 0u) {
            return 0;
        }
    }

    if (compress) {
        return register_low3_matches(
                instruction->opcode[1].reg,register_base,
                (uint8_t)((instruction->encoding.modrm >> 3)
                    & UINT8_C(7)))
            && (memory_form
                || register_low3_matches(
                    instruction->opcode[0].reg,register_base,
                    (uint8_t)(instruction->encoding.modrm & UINT8_C(7))));
    }
    return register_low3_matches(
            instruction->opcode[0].reg,register_base,
            (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))
        && (memory_form
            || register_low3_matches(
                instruction->opcode[1].reg,register_base,
                (uint8_t)(instruction->encoding.modrm & UINT8_C(7))));
}

static int valid_gfni_groups(
    const cdisasm_instruction *instruction,
    int encoding,
    unsigned int vector_size)
{
    unsigned int provenance = exact_instruction_provenance(instruction);
    size_t expected;

    if ((instruction->opcode_flags & CDISASM_PREFIX_REX) != 0u) {
        provenance |= 2u;
    }
    if (encoding == 0) {
        /* All three-byte legacy GFNI encodings have an I386 opcode-map
         * provenance group even when every explicit operand is XMM. */
        provenance |= 1u;
    }
    expected = ((provenance & 1u) != 0u) + ((provenance & 2u) != 0u);
    if ((provenance & 1u) != 0u
        && !cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_I386)) {
        return 0;
    }
    if ((provenance & 2u) != 0u
        && !cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AMD64)) {
        return 0;
    }
    if (!cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_GFNI)) {
        return 0;
    }
    ++expected;
    if (encoding == 0) {
        return expected == instruction->x86_group_count;
    }
    if (!cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX)) {
        return 0;
    }
    ++expected;
    if (encoding == 1) {
        if (!cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX_GFNI)) {
            return 0;
        }
        return expected + 1u == instruction->x86_group_count;
    }
    {
        const int avx512 = cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512F);
        const int avx10 = cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX10_1);
        const int apx = cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_APX_F);
        const cdisasm_x86_group_id width_group =
            vector_size == 16u ? CDISASM_X86_GROUP_AVX512_GFNI_128
            : vector_size == 32u ? CDISASM_X86_GROUP_AVX512_GFNI_256
                                 : CDISASM_X86_GROUP_AVX512_GFNI_512;

        if (avx512 == avx10
            || !cdisasm_instruction_has_x86_group(
                instruction, width_group)
            || (avx512 && vector_size < 64u
                && !cdisasm_instruction_has_x86_group(
                    instruction, CDISASM_X86_GROUP_AVX512VL))) {
            return 0;
        }
        expected += 2u; /* selected foundation plus exact width ISA set */
        if (avx512 && vector_size < 64u) {
            ++expected;
        }
        if (apx) {
            ++expected;
        }
        return expected == instruction->x86_group_count;
    }
}

static int valid_gfni_schema(const cdisasm_instruction *instruction)
{
    const uint32_t modern_mask = CDISASM_PREFIX_VEX
        | CDISASM_PREFIX_XOP | CDISASM_PREFIX_EVEX
        | CDISASM_PREFIX_REX2;
    const int legacy_name =
        instruction->name_id == CDISASM_X86_NAME_GF2P8AFFINEINVQB
        || instruction->name_id == CDISASM_X86_NAME_GF2P8AFFINEQB
        || instruction->name_id == CDISASM_X86_NAME_GF2P8MULB;
    const int vector_name =
        instruction->name_id == CDISASM_X86_NAME_VGF2P8AFFINEINVQB
        || instruction->name_id == CDISASM_X86_NAME_VGF2P8AFFINEQB
        || instruction->name_id == CDISASM_X86_NAME_VGF2P8MULB;
    const int legacy_form = instruction->form_id >= UINT16_C(1308)
        && instruction->form_id <= UINT16_C(1313);
    const int vector_form = instruction->form_id >= UINT16_C(5505)
        && instruction->form_id <= UINT16_C(5534);
    int encoding;
    int affine;
    int memory_form;
    unsigned int vector_size;
    unsigned int family_base;
    unsigned int relative;
    unsigned int source_count;
    unsigned int immediate_count;
    cdisasm_x86_reg_id register_base;
    const cdisasm_opcode *destination;
    const cdisasm_opcode *rm_source;
    size_t index;

    if (!legacy_name && !vector_name && !legacy_form && !vector_form) {
        return 1;
    }
    if ((legacy_name != legacy_form) || (vector_name != vector_form)
        || (legacy_name == vector_name)) {
        return 0;
    }

    if (legacy_form) {
        family_base = instruction->name_id
                == CDISASM_X86_NAME_GF2P8AFFINEINVQB
            ? 1308u
            : instruction->name_id == CDISASM_X86_NAME_GF2P8AFFINEQB
                ? 1310u : 1312u;
        if (instruction->form_id < family_base
            || instruction->form_id > family_base + 1u) {
            return 0;
        }
        relative = instruction->form_id - family_base;
        encoding = 0;
        vector_size = 16u;
    } else {
        family_base = instruction->name_id
                == CDISASM_X86_NAME_VGF2P8AFFINEINVQB
            ? 5505u
            : instruction->name_id == CDISASM_X86_NAME_VGF2P8AFFINEQB
                ? 5515u : 5525u;
        if (instruction->form_id < family_base
            || instruction->form_id > family_base + 9u) {
            return 0;
        }
        relative = instruction->form_id - family_base;
        encoding = relative == 2u || relative == 3u
                || relative == 6u || relative == 7u
            ? 1 : 2;
        vector_size = relative <= 3u ? 16u
            : relative <= 7u ? 32u : 64u;
    }
    affine = instruction->name_id
            == CDISASM_X86_NAME_GF2P8AFFINEINVQB
        || instruction->name_id == CDISASM_X86_NAME_GF2P8AFFINEQB
        || instruction->name_id
            == CDISASM_X86_NAME_VGF2P8AFFINEINVQB
        || instruction->name_id == CDISASM_X86_NAME_VGF2P8AFFINEQB;
    memory_form = (relative & 1u) == 0u;
    source_count = encoding == 0 ? 1u : 2u;
    immediate_count = affine ? 1u : 0u;
    register_base = vector_size == 16u ? CDISASM_X86_REG_XMM0
        : vector_size == 32u ? CDISASM_X86_REG_YMM0
                             : CDISASM_X86_REG_ZMM0;

    {
        const uint32_t allowed = encoding == 0
            ? CDISASM_PREFIX_OPERAND_SIZE | CDISASM_PREFIX_ADDRESS_SIZE
                | CDISASM_PREFIX_SEGMENT | CDISASM_PREFIX_REX
                | CDISASM_PREFIX_REX_W
            : (encoding == 1 ? CDISASM_PREFIX_VEX : CDISASM_PREFIX_EVEX)
                | CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_SEGMENT;
        const uint32_t expected_modern = encoding == 1
            ? CDISASM_PREFIX_VEX
            : encoding == 2 ? CDISASM_PREFIX_EVEX : 0u;

        if ((instruction->opcode_flags & ~allowed) != 0u
            || (instruction->opcode_flags & modern_mask) != expected_modern
            || (encoding == 0
                && (instruction->opcode_flags
                    & CDISASM_PREFIX_OPERAND_SIZE) == 0u)
            || ((instruction->opcode_flags & CDISASM_PREFIX_REX_W) != 0u
                && (instruction->opcode_flags & CDISASM_PREFIX_REX) == 0u)
            || instruction->encoding.opcode_offset
                != instruction->encoding.prefix_size
            || instruction->encoding.opcode_size
                != (encoding == 0 ? 3u : 1u)
            || instruction->encoding.modrm_offset
                != instruction->encoding.opcode_offset
                    + instruction->encoding.opcode_size
            || instruction->encoding.immediate_count != immediate_count
            || (affine
                && (instruction->encoding.immediate_size[0] != 1u
                    || instruction->encoding.immediate_offset[0]
                        != instruction->opcode_size - 1u))
            || instruction->encoding.selector_offset != 0u
            || instruction->operand_count
                != 1u + source_count + immediate_count
            || instruction->rounding != CDISASM_X86_ROUNDING_NONE
            || instruction->sae != CDISASM_X86_SAE_NONE
            || instruction->opcode_groups != CDISASM_GROUP_NONE
            || instruction->branch_target != 0u
            || !valid_gfni_groups(instruction, encoding, vector_size)) {
            return 0;
        }
    }

    if (encoding != 2) {
        if (instruction->mask_mode != CDISASM_X86_MASK_NONE
            || instruction->mask_reg != CDISASM_X86_REG_NONE) {
            return 0;
        }
    } else if ((instruction->mask_mode == CDISASM_X86_MASK_NONE)
            != (instruction->mask_reg == CDISASM_X86_REG_NONE)
        || (instruction->mask_mode != CDISASM_X86_MASK_NONE
            && (instruction->mask_reg < CDISASM_X86_REG_K1
                || instruction->mask_reg > CDISASM_X86_REG_K7))) {
        return 0;
    }

    destination = &instruction->opcode[0];
    rm_source = &instruction->opcode[source_count];
    if (destination->type != CDISASM_OPERAND_REGISTER
        || destination->size != vector_size
        || destination->access != (encoding == 0
            || (encoding == 2
                && instruction->mask_mode == CDISASM_X86_MASK_MERGE)
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE)
        || destination->reg < register_base
        || destination->reg > register_base + (encoding == 2 ? 31u : 15u)
        || destination->flags != 0u
        || destination->broadcast != CDISASM_X86_BROADCAST_NONE
        || rm_source->type != (memory_form
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER)
        || rm_source->access != CDISASM_OPERAND_ACCESS_READ
        || !register_low3_matches(
            destination->reg, register_base,
            (uint8_t)((instruction->encoding.modrm >> 3) & UINT8_C(7)))) {
        return 0;
    }
    for (index = 1u; index < source_count; ++index) {
        const cdisasm_opcode *source = &instruction->opcode[index];

        if (source->type != CDISASM_OPERAND_REGISTER
            || source->size != vector_size
            || source->access != CDISASM_OPERAND_ACCESS_READ
            || source->reg < register_base
            || source->reg > register_base + (encoding == 2 ? 31u : 15u)
            || source->flags != 0u
            || source->broadcast != CDISASM_X86_BROADCAST_NONE) {
            return 0;
        }
    }
    if (memory_form) {
        const int broadcast = encoding == 2 && affine
            && rm_source->size == 8u;
        const int has_segment = (instruction->opcode_flags
            & CDISASM_PREFIX_SEGMENT) != 0u;

        if (!((rm_source->size == vector_size
                    && rm_source->broadcast == CDISASM_X86_BROADCAST_NONE)
                || (broadcast
                    && rm_source->broadcast
                        == (cdisasm_x86_broadcast)(vector_size / 8u)))
            || (rm_source->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY
                    | CDISASM_OPERAND_FLAG_SIGNED)) != 0u
            || has_segment != ((rm_source->flags
                & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0u)
            || has_segment
                != (rm_source->segment_reg != CDISASM_X86_REG_NONE)
            || !valid_modrm_memory_encoding(
                instruction, rm_source,
                cdisasm_instruction_has_x86_group(
                    instruction, CDISASM_X86_GROUP_APX_F))) {
            return 0;
        }
    } else if (rm_source->size != vector_size
        || rm_source->reg < register_base
        || rm_source->reg > register_base + (encoding == 2 ? 31u : 15u)
        || rm_source->flags != 0u
        || rm_source->broadcast != CDISASM_X86_BROADCAST_NONE
        || instruction->encoding.sib_offset != 0u
        || instruction->encoding.displacement_offset != 0u
        || instruction->encoding.displacement_size != 0u
        || !register_low3_matches(
            rm_source->reg, register_base,
            (uint8_t)(instruction->encoding.modrm & UINT8_C(7)))) {
        return 0;
    }
    if (affine) {
        const cdisasm_opcode *immediate =
            &instruction->opcode[1u + source_count];

        if (immediate->type != CDISASM_OPERAND_IMMEDIATE
            || immediate->size != 1u
            || immediate->access != CDISASM_OPERAND_ACCESS_READ
            || immediate->flags != 0u
            || immediate->broadcast != CDISASM_X86_BROADCAST_NONE
            || immediate->imm > UINT8_MAX) {
            return 0;
        }
    }
    return 1;
}

static int valid_instruction(const cdisasm_instruction *instruction)
{
    uint32_t effective_prefix;
    uint32_t hle_prefix;
    size_t index;

    if (instruction == NULL
        || instruction->last_error_id != CDISASM_STATUS_OK
        || instruction->opcode_size == 0
        || instruction->opcode_size > CDISASM_MAX_INSTRUCTION_SIZE
        || instruction->name_id == CDISASM_X86_NAME_NONE
        || instruction->name_id >= CDISASM_X86_NAME_COUNT
        || mnemonic_name(instruction->name_id) == NULL
        || instruction->operand_count > CDISASM_MAX_OPERANDS
        || !valid_x86_groups(instruction)
        || !valid_decorators(instruction)
        || !valid_multidest2_schema(instruction)
        || !valid_vpabs_schema(instruction)
        || !valid_vpack_schema(instruction)
        || !valid_vpblend_schema(instruction)
        || !valid_vdpp_schema(instruction)
        || !valid_vmxcsr_schema(instruction)
        || !valid_vmaskmov_schema(instruction)
        || !valid_vpmaskmov_schema(instruction)
        || !valid_vblendv_schema(instruction)
        || !valid_vpblendvb_schema(instruction)
        || !valid_vpbroadcast_schema(instruction)
        || !valid_vbroadcast128_schema(instruction)
        || !valid_vex_lane128_schema(instruction)
        || !valid_vbroadcast_scalar_schema(instruction)
        || !valid_vex_ps_lane_schema(instruction)
        || !valid_vpcmpeqq_schema(instruction)
        || !valid_vpcmpgt_schema(instruction)
        || !valid_vex_packed_add_sub_minmax_schema(instruction)
        || !valid_vperm2_128_schema(instruction)
        || !valid_vpermd_vpermps_schema(instruction)
        || !valid_vpermilpd_vpermilps_schema(instruction)
        || !valid_vcmp_schema(instruction)
        || !valid_vround_schema(instruction)
        || !valid_vshufpd_vshufps_schema(instruction)
        || !valid_vtestpd_vtestps_schema(instruction)
        || !valid_vptest_schema(instruction)
        || !valid_vpmovmskb_schema(instruction)
        || !valid_vcomi_scalar_schema(instruction)
        || !valid_vunpck_packed_schema(instruction)
        || !valid_vpunpck_integer_schema(instruction)
        || !valid_vpsign_integer_schema(instruction)
        || !valid_vphminposuw_schema(instruction)
        || !valid_vpmovx_schema(instruction)
        || !valid_vpextr_schema(instruction)
        || !valid_vpinsr_schema(instruction)
        || !valid_horizontal_integer_schema(instruction)
        || !valid_vpshuf_integer_schema(instruction)
        || !valid_vpermpd_vpermq_schema(instruction)
        || !valid_vpcmov_schema(instruction)
        || !valid_vpperm_schema(instruction)
        || !valid_vdbpsadbw_schema(instruction)
        || !valid_vpternlog_schema(instruction)
        || !valid_fp_compress_expand_schema(instruction)
        || !valid_gfni_schema(instruction)) {
        return 0;
    }

    effective_prefix = instruction->opcode_flags
        & CDISASM_PREFIX_EFFECTIVE_MASK;
    if (effective_prefix != 0
        && (effective_prefix & (effective_prefix - 1)) != 0) {
        return 0;
    }
    if ((effective_prefix == CDISASM_PREFIX_EFFECTIVE_LOCK
            && (instruction->opcode_flags & CDISASM_PREFIX_LOCK) == 0)
        || (effective_prefix == CDISASM_PREFIX_EFFECTIVE_REP
            && (instruction->opcode_flags & CDISASM_PREFIX_REP) == 0)
        || (effective_prefix == CDISASM_PREFIX_EFFECTIVE_REPNE
            && (instruction->opcode_flags & CDISASM_PREFIX_REPNE) == 0)) {
        return 0;
    }
    hle_prefix = instruction->opcode_flags & CDISASM_PREFIX_HLE_MASK;
    if (hle_prefix != 0 && (hle_prefix & (hle_prefix - 1)) != 0) {
        return 0;
    }
    if ((hle_prefix == CDISASM_PREFIX_XACQUIRE
            && (instruction->opcode_flags & CDISASM_PREFIX_REPNE) == 0)
        || (hle_prefix == CDISASM_PREFIX_XRELEASE
            && (instruction->opcode_flags & CDISASM_PREFIX_REP) == 0)
        || (hle_prefix != 0
            && (effective_prefix == CDISASM_PREFIX_EFFECTIVE_REP
                || effective_prefix == CDISASM_PREFIX_EFFECTIVE_REPNE))
        || (hle_prefix != 0
            && !cdisasm_instruction_has_x86_group(
                instruction,
                CDISASM_X86_GROUP_HLE))) {
        return 0;
    }

    for (index = 0; index < instruction->operand_count; ++index) {
        if (!valid_operand(instruction, &instruction->opcode[index])) {
            return 0;
        }
    }
    for (; index < CDISASM_MAX_OPERANDS; ++index) {
        if (!bytes_are_zero(
                &instruction->opcode[index],
                sizeof(instruction->opcode[index]))) {
            return 0;
        }
    }
    return 1;
}

static void format_prefix(
    text_writer *writer,
    const cdisasm_instruction *instruction,
    uint32_t flags)
{
    uint32_t effective_prefix = instruction->opcode_flags
        & CDISASM_PREFIX_EFFECTIVE_MASK;
    uint32_t hle_prefix = instruction->opcode_flags
        & CDISASM_PREFIX_HLE_MASK;

    if (hle_prefix == CDISASM_PREFIX_XACQUIRE) {
        writer_puts_opcode(writer, "xacquire ", flags);
    } else if (hle_prefix == CDISASM_PREFIX_XRELEASE) {
        writer_puts_opcode(writer, "xrelease ", flags);
    }

    if (effective_prefix == CDISASM_PREFIX_EFFECTIVE_LOCK) {
        writer_puts_opcode(writer, "lock ", flags);
        return;
    }
    if (effective_prefix == CDISASM_PREFIX_EFFECTIVE_REP) {
        if (suppress_rep_prefix(instruction)) {
            return;
        }
        if (is_compare_string_name(instruction->name_id)) {
            writer_puts_opcode(writer, "repe ", flags);
        } else {
            writer_puts_opcode(writer, "rep ", flags);
        }
        return;
    }
    if (effective_prefix == CDISASM_PREFIX_EFFECTIVE_REPNE) {
        if (instruction->name_id == CDISASM_X86_NAME_VMGEXIT
            || instruction->name_id == CDISASM_X86_NAME_VMMCALL) {
            return;
        }
        writer_puts_opcode(writer, "repne ", flags);
    }
}

static void format_immediate(text_writer *writer, const cdisasm_opcode *operand)
{
    if ((operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0) {
        writer_hex(writer, operand->imm);
    } else if ((operand->flags & CDISASM_OPERAND_FLAG_SIGNED) != 0) {
        writer_signed_hex(writer, operand->imm);
    } else if ((operand->flags & CDISASM_OPERAND_FLAG_IMPLICIT) != 0
        && operand->imm == 1) {
        writer_putc(writer, '1');
    } else {
        writer_hex(writer, operand->imm);
    }
}

static void format_memory(
    text_writer *writer,
    const cdisasm_instruction *instruction,
    const cdisasm_opcode *operand)
{
    int has_term = 0;
    int far_pointer_64 = instruction != NULL
        && (instruction->name_id == CDISASM_X86_NAME_CALL_FAR
            || instruction->name_id == CDISASM_X86_NAME_JMP_FAR)
        && ((operand->base_reg >= CDISASM_X86_REG_RAX
                && operand->base_reg <= CDISASM_X86_REG_R15)
            || (operand->base_reg >= CDISASM_X86_REG_R16
                && operand->base_reg <= CDISASM_X86_REG_R31)
            || operand->base_reg == CDISASM_X86_REG_RIP);
    int unsized_pointer = instruction != NULL
        && (instruction->name_id == CDISASM_X86_NAME_PREFETCH_RESERVED
            || far_pointer_64);

    if ((operand->flags & CDISASM_OPERAND_FLAG_ADDRESS_ONLY) == 0) {
        if (unsized_pointer) {
            writer_puts(writer, "ptr ");
        } else {
            writer_puts(writer, pointer_size_name(operand->size));
        }
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0) {
        writer_puts(writer, register_names[operand->segment_reg]);
        writer_putc(writer, ':');
    }

    writer_putc(writer, '[');
    if (operand->base_reg != CDISASM_X86_REG_NONE) {
        writer_puts(writer, register_names[operand->base_reg]);
        has_term = 1;
    }
    if (operand->index_reg != CDISASM_X86_REG_NONE) {
        if (has_term) {
            writer_puts(writer, " + ");
        }
        writer_puts(writer, register_names[operand->index_reg]);
        if (operand->scale != 1) {
            writer_putc(writer, '*');
            writer_putc(writer, (char)('0' + operand->scale));
        }
        has_term = 1;
    }

    if ((operand->flags & CDISASM_OPERAND_FLAG_ABSOLUTE) != 0) {
        writer_hex(writer, operand->address);
        has_term = 1;
    } else if ((operand->flags & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) != 0
        && (operand->imm != 0 || !has_term)) {
        if (has_term) {
            if (value_is_negative(operand->imm)) {
                writer_puts(writer, " - ");
                writer_hex(writer, UINT64_C(0) - operand->imm);
            } else {
                writer_puts(writer, " + ");
                writer_hex(writer, operand->imm);
            }
        } else {
            writer_signed_hex(writer, operand->imm);
        }
        has_term = 1;
    }

    if (!has_term) {
        writer_hex(writer, 0);
    }
    writer_putc(writer, ']');
}

static int is_multisource4_instruction(cdisasm_x86_name_id name_id)
{
    return name_id == CDISASM_X86_NAME_VP4DPWSSD
        || name_id == CDISASM_X86_NAME_VP4DPWSSDS
        || name_id == CDISASM_X86_NAME_V4FMADDPS
        || name_id == CDISASM_X86_NAME_V4FMADDSS
        || name_id == CDISASM_X86_NAME_V4FNMADDPS
        || name_id == CDISASM_X86_NAME_V4FNMADDSS;
}

static int is_multidest2_instruction(cdisasm_x86_name_id name_id)
{
    return name_id == CDISASM_X86_NAME_VP2INTERSECTD
        || name_id == CDISASM_X86_NAME_VP2INTERSECTQ;
}

static unsigned int register_block_offset(
    const cdisasm_instruction *instruction,
    size_t operand_index)
{
    if (operand_index == 0u
        && is_multidest2_instruction(instruction->name_id)) {
        return 1u;
    }
    if (operand_index == 1u
        && is_multisource4_instruction(instruction->name_id)) {
        return 3u;
    }
    return 0u;
}

static void format_operand(
    text_writer *writer,
    const cdisasm_instruction *instruction,
    const cdisasm_opcode *operand,
    unsigned int register_offset)
{
    switch (operand->type) {
        case CDISASM_OPERAND_REGISTER:
            writer_puts(writer, register_names[operand->reg]);
            if (register_offset != 0u) {
                writer_putc(writer, '+');
                writer_decimal(writer, register_offset);
            }
            break;
        case CDISASM_OPERAND_IMMEDIATE:
            format_immediate(writer, operand);
            break;
        case CDISASM_OPERAND_MEMORY:
            format_memory(writer, instruction, operand);
            break;
        default:
            break;
    }
    if (operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
        writer_puts(writer, "{1to");
        writer_decimal(writer, operand->broadcast);
        writer_putc(writer, '}');
    }
}

static void format_att_register(
    text_writer *writer,
    cdisasm_x86_reg_id reg)
{
    writer_putc(writer, '%');
    if (reg >= CDISASM_X86_REG_ST0 && reg <= CDISASM_X86_REG_ST7) {
        writer_puts(writer, "st");
        if (reg != CDISASM_X86_REG_ST0) {
            writer_putc(writer, '(');
            writer_decimal(writer,
                (unsigned int)(reg - CDISASM_X86_REG_ST0));
            writer_putc(writer, ')');
        }
        return;
    }
    writer_puts(writer, register_names[reg]);
}

static void format_att_immediate(
    text_writer *writer,
    const cdisasm_opcode *operand)
{
    if ((operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) == 0) {
        writer_putc(writer, '$');
    }
    format_immediate(writer, operand);
}

static void format_att_memory(
    text_writer *writer,
    const cdisasm_opcode *operand)
{
    int has_base = operand->base_reg != CDISASM_X86_REG_NONE;
    int has_index = operand->index_reg != CDISASM_X86_REG_NONE;
    int has_displacement =
        (operand->flags & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) != 0;

    if ((operand->flags & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0) {
        format_att_register(writer, operand->segment_reg);
        writer_putc(writer, ':');
    }

    if ((operand->flags & CDISASM_OPERAND_FLAG_ABSOLUTE) != 0) {
        writer_hex(writer, operand->address);
        return;
    }

    if (has_displacement && (operand->imm != 0 || (!has_base && !has_index))) {
        writer_signed_hex(writer, operand->imm);
    } else if (!has_base && !has_index) {
        writer_hex(writer, 0);
    }

    if (has_base || has_index) {
        writer_putc(writer, '(');
        if (has_base) {
            format_att_register(writer, operand->base_reg);
        }
        if (has_index) {
            writer_putc(writer, ',');
            format_att_register(writer, operand->index_reg);
            if (operand->scale != 1) {
                writer_putc(writer, ',');
                writer_putc(writer, (char)('0' + operand->scale));
            }
        }
        writer_putc(writer, ')');
    }
}

static void format_att_operand(
    text_writer *writer,
    const cdisasm_opcode *operand,
    unsigned int register_offset)
{
    switch (operand->type) {
        case CDISASM_OPERAND_REGISTER:
            format_att_register(writer, operand->reg);
            if (register_offset != 0u) {
                writer_putc(writer, '+');
                writer_decimal(writer, register_offset);
            }
            break;
        case CDISASM_OPERAND_IMMEDIATE:
            format_att_immediate(writer, operand);
            break;
        case CDISASM_OPERAND_MEMORY:
            format_att_memory(writer, operand);
            break;
        default:
            break;
    }
    if (operand->broadcast != CDISASM_X86_BROADCAST_NONE) {
        writer_puts(writer, "{1to");
        writer_decimal(writer, operand->broadcast);
        writer_putc(writer, '}');
    }
}

static int is_att_indirect_control(
    const cdisasm_instruction *instruction,
    const cdisasm_opcode *operand)
{
    return (instruction->name_id == CDISASM_X86_NAME_CALL
            || instruction->name_id == CDISASM_X86_NAME_JMP)
        && operand->type != CDISASM_OPERAND_IMMEDIATE;
}

static int att_reverse_operands(
    const cdisasm_instruction *instruction)
{
    return instruction->operand_count > 1
        && instruction->name_id != CDISASM_X86_NAME_ENTER
        && instruction->name_id != CDISASM_X86_NAME_INVLPGA;
}

static void format_mask(
    text_writer *writer,
    const cdisasm_instruction *instruction)
{
    if (instruction->mask_mode == CDISASM_X86_MASK_NONE) {
        return;
    }
    writer_puts(writer, " {");
    writer_puts(writer, register_names[instruction->mask_reg]);
    writer_putc(writer, '}');
    if (instruction->mask_mode == CDISASM_X86_MASK_ZERO) {
        writer_puts(writer, "{z}");
    }
}

static void format_att_mask(
    text_writer *writer,
    const cdisasm_instruction *instruction)
{
    if (instruction->mask_mode == CDISASM_X86_MASK_NONE) {
        return;
    }
    writer_putc(writer, '{');
    format_att_register(writer, instruction->mask_reg);
    writer_putc(writer, '}');
    if (instruction->mask_mode == CDISASM_X86_MASK_ZERO) {
        writer_puts(writer, "{z}");
    }
}

static void format_rounding_sae_token(
    text_writer *writer,
    const cdisasm_instruction *instruction)
{
    if (instruction->sae == CDISASM_X86_SAE_NONE) {
        return;
    }
    writer_putc(writer, '{');
    switch (instruction->rounding) {
        case CDISASM_X86_ROUNDING_RN:
            writer_puts(writer, "rn-");
            break;
        case CDISASM_X86_ROUNDING_RD:
            writer_puts(writer, "rd-");
            break;
        case CDISASM_X86_ROUNDING_RU:
            writer_puts(writer, "ru-");
            break;
        case CDISASM_X86_ROUNDING_RZ:
            writer_puts(writer, "rz-");
            break;
        default:
            break;
    }
    writer_puts(writer, "sae}");
}

/* XED places the EVEX rounding/SAE decorator on the destination for the
 * scalar floating-point/integer conversion forms.  The public instruction
 * model keeps decorators independent of operands, so identify this small
 * family by name ID in the formatter rather than adding ABI state. */
static int rounding_sae_on_first_operand(cdisasm_x86_name_id name_id)
{
    switch (name_id) {
        case CDISASM_X86_NAME_VCVTSD2SI:
        case CDISASM_X86_NAME_VCVTSD2USI:
        case CDISASM_X86_NAME_VCVTSH2SI:
        case CDISASM_X86_NAME_VCVTSH2USI:
        case CDISASM_X86_NAME_VCVTSI2SD:
        case CDISASM_X86_NAME_VCVTSI2SH:
        case CDISASM_X86_NAME_VCVTSI2SS:
        case CDISASM_X86_NAME_VCVTSS2SI:
        case CDISASM_X86_NAME_VCVTSS2USI:
        case CDISASM_X86_NAME_VCVTUSI2SD:
        case CDISASM_X86_NAME_VCVTUSI2SH:
        case CDISASM_X86_NAME_VCVTUSI2SS:
        case CDISASM_X86_NAME_VCVTTSD2SI:
        case CDISASM_X86_NAME_VCVTTSD2SIS:
        case CDISASM_X86_NAME_VCVTTSD2USI:
        case CDISASM_X86_NAME_VCVTTSD2USIS:
        case CDISASM_X86_NAME_VCVTTSH2SI:
        case CDISASM_X86_NAME_VCVTTSH2USI:
        case CDISASM_X86_NAME_VCVTTSS2SI:
        case CDISASM_X86_NAME_VCVTTSS2SIS:
        case CDISASM_X86_NAME_VCVTTSS2USI:
        case CDISASM_X86_NAME_VCVTTSS2USIS:
        case CDISASM_X86_NAME_VCOMXSD:
        case CDISASM_X86_NAME_VCOMXSH:
        case CDISASM_X86_NAME_VCOMXSS:
        case CDISASM_X86_NAME_VUCOMXSD:
        case CDISASM_X86_NAME_VUCOMXSH:
        case CDISASM_X86_NAME_VUCOMXSS:
            return 1;
        default:
            return 0;
    }
}

static void format_rounding_sae(
    text_writer *writer,
    const cdisasm_instruction *instruction)
{
    if (instruction->sae == CDISASM_X86_SAE_NONE) {
        return;
    }
    writer_puts(writer, ", ");
    format_rounding_sae_token(writer, instruction);
}

static void format_default_flags(
    text_writer *writer,
    const cdisasm_instruction *instruction)
{
    uint8_t value = instruction->default_flags;
    int first = 1;

    if (value == CDISASM_X86_DEFAULT_FLAGS_NONE) {
        return;
    }
    writer_puts(writer, " {dfv=");
    if ((value & CDISASM_X86_DEFAULT_FLAG_OF) != 0u) {
        writer_puts(writer, "of");
        first = 0;
    }
    if ((value & CDISASM_X86_DEFAULT_FLAG_SF) != 0u) {
        if (!first) {
            writer_putc(writer, ',');
        }
        writer_puts(writer, "sf");
        first = 0;
    }
    if ((value & CDISASM_X86_DEFAULT_FLAG_ZF) != 0u) {
        if (!first) {
            writer_putc(writer, ',');
        }
        writer_puts(writer, "zf");
        first = 0;
    }
    if ((value & CDISASM_X86_DEFAULT_FLAG_CF) != 0u) {
        if (!first) {
            writer_putc(writer, ',');
        }
        writer_puts(writer, "cf");
    }
    writer_putc(writer, '}');
}

static void format_att_instruction(
    text_writer *writer,
    const cdisasm_instruction *instruction,
    uint32_t flags,
    cdisasm_mode mode)
{
    int reverse = att_reverse_operands(instruction);
    size_t display_index;
    size_t emitted = 0u;

    format_prefix(writer, instruction, flags);
    format_att_mnemonic(writer, instruction, flags, mode);
    format_default_flags(writer, instruction);
    if (instruction->sae != CDISASM_X86_SAE_NONE) {
        writer_putc(writer, ' ');
        format_rounding_sae_token(writer, instruction);
        if (instruction->operand_count != 0) {
            writer_puts(writer, ", ");
        }
    } else if (instruction->operand_count != 0) {
        writer_putc(writer, ' ');
    }
    for (display_index = 0;
         display_index < instruction->operand_count;
         ++display_index) {
        size_t operand_index = reverse
            ? (size_t)instruction->operand_count - 1 - display_index
            : display_index;
        const cdisasm_opcode *operand = &instruction->opcode[operand_index];

        if (is_multidest2_instruction(instruction->name_id)
            && operand_index == 1u) {
            continue;
        }
        if (emitted != 0u) {
            writer_puts(writer, ", ");
        }
        if (is_att_indirect_control(instruction, operand)) {
            writer_putc(writer, '*');
        }
        format_att_operand(
            writer, operand,
            register_block_offset(instruction, operand_index));
        if (operand_index == 0) {
            format_att_mask(writer, instruction);
        }
        ++emitted;
    }
}

static size_t cdisasm_x86_format_internal(
    const cdisasm_x86_instruction *instruction,
    cdisasm_mode mode,
    int validate_mode,
    uint32_t flags,
    char *buffer,
    size_t buffer_size)
{
    text_writer writer;
    size_t index;

    if (buffer != NULL && buffer_size != 0) {
        buffer[0] = '\0';
    }
    if ((buffer == NULL && buffer_size != 0)
        || (validate_mode && !valid_format_mode(mode))
        || (flags & ~CDISASM_FORMAT_KNOWN_FLAGS_MASK) != 0
        || !valid_instruction(instruction)) {
        return 0;
    }

    writer.buffer = buffer;
    writer.buffer_size = buffer_size;
    writer.length = 0;

    if ((flags & CDISASM_FORMAT_SYNTAX_MASK)
        == CDISASM_FORMAT_SYNTAX_ATT) {
        format_att_instruction(
            &writer,
            instruction,
            flags,
            validate_mode ? mode : 0);
        writer_finish(&writer);
        return writer.length;
    }

    format_prefix(&writer, instruction, flags);
    writer_puts_opcode(
        &writer,
        mnemonic_name(instruction->name_id),
        flags);
    format_default_flags(&writer, instruction);
    const int rounding_on_destination =
        rounding_sae_on_first_operand(instruction->name_id);
    if (instruction->operand_count != 0) {
        writer_putc(&writer, ' ');
    }
    for (index = 0; index < instruction->operand_count; ++index) {
        if (is_multidest2_instruction(instruction->name_id)
            && index == 1u) {
            continue;
        }
        if (index != 0) {
            writer_puts(&writer, ", ");
        }
        format_operand(
            &writer, instruction, &instruction->opcode[index],
            register_block_offset(instruction, index));
        if (index == 0) {
            format_mask(&writer, instruction);
            if (rounding_on_destination) {
                format_rounding_sae_token(&writer, instruction);
            }
        }
    }
    if (!rounding_on_destination) {
        format_rounding_sae(&writer, instruction);
    }
    writer_finish(&writer);
    return writer.length;
}

size_t CDISASM_CALL cdisasm_x86_format(
    const cdisasm_x86_instruction *instruction,
    uint32_t flags,
    char *buffer,
    size_t buffer_size)
{
    return cdisasm_x86_format_internal(
        instruction,
        0,
        0,
        flags,
        buffer,
        buffer_size);
}

size_t CDISASM_CALL cdisasm_x86_format_mode(
    const cdisasm_x86_instruction *instruction,
    cdisasm_mode mode,
    uint32_t flags,
    char *buffer,
    size_t buffer_size)
{
    return cdisasm_x86_format_internal(
        instruction,
        mode,
        1,
        flags,
        buffer,
        buffer_size);
}

size_t CDISASM_CALL cdisasm_format(
    const cdisasm_instruction *instruction,
    uint32_t flags,
    char *buffer,
    size_t buffer_size)
{
    return cdisasm_x86_format(instruction, flags, buffer, buffer_size);
}

#endif
