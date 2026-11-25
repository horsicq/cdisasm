#ifndef CDISASM_CDISASM_M68K_H
#define CDISASM_CDISASM_M68K_H

/* Motorola 68000 family: MC68000/68008/68010/68020/68030/68040/68060, CPU32,
 * MC68881/68882 floating point (and the 68040/68060 FPUs) and the 68030,
 * 68040, 68060 and MC68851 memory-management instructions; ColdFire ISA_A,
 * ISA_A+, ISA_B and ISA_C with the MAC and EMAC units and the ColdFire FPU.
 * Instructions are big-endian 16-bit words, 2 to 22 bytes long.
 *
 * Decoding is driven by a 64-bit feature mask. Each CPU ID maps to the
 * features of that processor; the `mode` argument of the decoders adds
 * features from the low 32 bits (for example CDISASM_M68K_FEATURE_FPU for a
 * 68020 with a 68881, CDISASM_M68K_FEATURE_MMU851 for a 68851, or
 * CDISASM_M68K_FEATURE_MAC / _EMAC / _CFFPU for a ColdFire core with those
 * units). CDISASM_M68K_CPU_ANY enables every 68000-family feature and
 * CDISASM_M68K_CPU_COLDFIRE every ColdFire feature; the two instruction sets
 * reuse encodings differently and are never mixed. */

#include "cdisasm_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef cdisasm_cpu_id cdisasm_m68k_cpu_id;

#ifndef CDISASM_CPU_GROUP_M68K
#define CDISASM_CPU_GROUP_M68K UINT32_C(0x00040000)
#endif
#define CDISASM_M68K_CPU_ANY (CDISASM_CPU_GROUP_M68K | UINT32_C(0))
#define CDISASM_M68K_CPU_68000 (CDISASM_CPU_GROUP_M68K | UINT32_C(1))
#define CDISASM_M68K_CPU_68008 (CDISASM_CPU_GROUP_M68K | UINT32_C(2))
#define CDISASM_M68K_CPU_68010 (CDISASM_CPU_GROUP_M68K | UINT32_C(3))
#define CDISASM_M68K_CPU_68020 (CDISASM_CPU_GROUP_M68K | UINT32_C(4))
#define CDISASM_M68K_CPU_68030 (CDISASM_CPU_GROUP_M68K | UINT32_C(5))
#define CDISASM_M68K_CPU_68040 (CDISASM_CPU_GROUP_M68K | UINT32_C(6))
#define CDISASM_M68K_CPU_68LC040 (CDISASM_CPU_GROUP_M68K | UINT32_C(7))
#define CDISASM_M68K_CPU_68EC040 (CDISASM_CPU_GROUP_M68K | UINT32_C(8))
#define CDISASM_M68K_CPU_68060 (CDISASM_CPU_GROUP_M68K | UINT32_C(9))
#define CDISASM_M68K_CPU_68LC060 (CDISASM_CPU_GROUP_M68K | UINT32_C(10))
#define CDISASM_M68K_CPU_68EC060 (CDISASM_CPU_GROUP_M68K | UINT32_C(11))
#define CDISASM_M68K_CPU_CPU32 (CDISASM_CPU_GROUP_M68K | UINT32_C(12))
#define CDISASM_M68K_CPU_68EC020 (CDISASM_CPU_GROUP_M68K | UINT32_C(13))
#define CDISASM_M68K_CPU_68EC030 (CDISASM_CPU_GROUP_M68K | UINT32_C(14))
/* ColdFire (CFPRM rev. 3). ISA profiles; MAC, EMAC and the FPU are options
 * of the core and come from `mode` except on CFV4E (EMAC + FPU). */
#define CDISASM_M68K_CPU_CF_ISA_A_NODIV (CDISASM_CPU_GROUP_M68K | UINT32_C(15)) /* "isa-a-nodiv": 5202/5204/5206 */
#define CDISASM_M68K_CPU_CF_ISA_A (CDISASM_CPU_GROUP_M68K | UINT32_C(16))       /* "isa-a": V2/V3 with divide */
#define CDISASM_M68K_CPU_CF_ISA_APLUS (CDISASM_CPU_GROUP_M68K | UINT32_C(17))   /* "isa-aplus": 521x/528x/532x */
#define CDISASM_M68K_CPU_CF_ISA_B_NOUSP (CDISASM_CPU_GROUP_M68K | UINT32_C(18)) /* "isa-b-nousp" */
#define CDISASM_M68K_CPU_CF_ISA_B (CDISASM_CPU_GROUP_M68K | UINT32_C(19))       /* "isa-b": V4 (5407) */
#define CDISASM_M68K_CPU_CF_ISA_C_NODIV (CDISASM_CPU_GROUP_M68K | UINT32_C(20)) /* "isa-c-nodiv" */
#define CDISASM_M68K_CPU_CF_ISA_C (CDISASM_CPU_GROUP_M68K | UINT32_C(21))       /* "isa-c": V1 (51xx) */
#define CDISASM_M68K_CPU_CFV4E (CDISASM_CPU_GROUP_M68K | UINT32_C(22))          /* "cfv4e": 547x/548x, ISA_B + EMAC + FPU */
#define CDISASM_M68K_CPU_COLDFIRE (CDISASM_CPU_GROUP_M68K | UINT32_C(23))       /* "coldfire": every ColdFire feature */
#define CDISASM_M68K_CPU_COUNT 24u

/* Feature bits (order matches tools/isa_codegen/generate_m68k.py). */
#define CDISASM_M68K_FEATURE_BASE (UINT32_C(1) << 0)  /* 68000 instruction set */
#define CDISASM_M68K_FEATURE_010 (UINT32_C(1) << 1)   /* 68010: movec, moves, rtd, bkpt, move from ccr */
#define CDISASM_M68K_FEATURE_EA020 (UINT32_C(1) << 2) /* tst/cmpi with PC-relative, #imm, An */
#define CDISASM_M68K_FEATURE_MULL (UINT32_C(1) << 3)  /* 32-bit mul/div, chk.l, extb.l */
#define CDISASM_M68K_FEATURE_MUL64 (UINT32_C(1) << 4) /* 64-bit mul/div */
#define CDISASM_M68K_FEATURE_LINKL (UINT32_C(1) << 5)
#define CDISASM_M68K_FEATURE_TRAPCC (UINT32_C(1) << 6)
#define CDISASM_M68K_FEATURE_CHK2 (UINT32_C(1) << 7)   /* chk2, cmp2 */
#define CDISASM_M68K_FEATURE_BCCL (UINT32_C(1) << 8)   /* 32-bit branch displacements */
#define CDISASM_M68K_FEATURE_FULLEA (UINT32_C(1) << 9) /* full-format extension words */
#define CDISASM_M68K_FEATURE_SCALE (UINT32_C(1) << 10) /* scaled index */
#define CDISASM_M68K_FEATURE_CAS (UINT32_C(1) << 11)
#define CDISASM_M68K_FEATURE_CAS2 (UINT32_C(1) << 12)
#define CDISASM_M68K_FEATURE_BITFIELD (UINT32_C(1) << 13)
#define CDISASM_M68K_FEATURE_PACK (UINT32_C(1) << 14)
#define CDISASM_M68K_FEATURE_CALLM (UINT32_C(1) << 15)    /* 68020 callm/rtm */
#define CDISASM_M68K_FEATURE_MOVEP (UINT32_C(1) << 16)    /* absent on the 68060 */
#define CDISASM_M68K_FEATURE_BGND (UINT32_C(1) << 17)     /* CPU32 */
#define CDISASM_M68K_FEATURE_TBL (UINT32_C(1) << 18)      /* CPU32 table lookup */
#define CDISASM_M68K_FEATURE_LPSTOP (UINT32_C(1) << 19)   /* CPU32, 68060 */
#define CDISASM_M68K_FEATURE_CACHE040 (UINT32_C(1) << 20) /* cinv, cpush */
#define CDISASM_M68K_FEATURE_MMU040 (UINT32_C(1) << 21)   /* 68040/68060 pflush */
#define CDISASM_M68K_FEATURE_PTEST040 (UINT32_C(1) << 22)
#define CDISASM_M68K_FEATURE_PLPA (UINT32_C(1) << 23) /* 68060 */
#define CDISASM_M68K_FEATURE_MOVE16 (UINT32_C(1) << 24)
#define CDISASM_M68K_FEATURE_MMU030 (UINT32_C(1) << 25) /* 68030 PMMU subset (also 68851) */
#define CDISASM_M68K_FEATURE_MMU851 (UINT32_C(1) << 26) /* MC68851 additions */
#define CDISASM_M68K_FEATURE_FPU (UINT32_C(1) << 27)    /* MC68881/68882 instruction set */
#define CDISASM_M68K_FEATURE_FPU040 (UINT32_C(1) << 28) /* 68040/68060 single/double rounding forms */
/* ColdFire options (may come from `mode`). EMAC implies MAC. */
#define CDISASM_M68K_FEATURE_MAC (UINT32_C(1) << 29)   /* MAC unit: mac/msac, acc, macsr, mask */
#define CDISASM_M68K_FEATURE_EMAC (UINT32_C(1) << 30)  /* EMAC: acc0-acc3, accext01/23, movclr */
#define CDISASM_M68K_FEATURE_CFFPU (UINT32_C(1) << 31) /* ColdFire FPU (double precision); also index scale 8 */
/* ColdFire instruction-set levels. */
#define CDISASM_M68K_FEATURE_CF (UINT64_C(1) << 32)      /* ISA_A */
#define CDISASM_M68K_FEATURE_CFDIV (UINT64_C(1) << 33)   /* hardware divide: divs/divu, rems/remu */
#define CDISASM_M68K_FEATURE_CFAPLUS (UINT64_C(1) << 34) /* bitrev, byterev, ff1 (ISA_A+, ISA_C); strldsr (ISA_A+) */
#define CDISASM_M68K_FEATURE_CFB (UINT64_C(1) << 35)     /* ISA_B/ISA_C: mov3q, mvs, mvz, sats, tas, cmp.b/w, Bcc.L, intouch */
#define CDISASM_M68K_FEATURE_CFUSP (UINT64_C(1) << 36)   /* move to/from usp */
#define CDISASM_M68K_FEATURE_ALL_68K (UINT64_C(0x1fffffff))
#define CDISASM_M68K_FEATURE_ALL_CF (UINT64_C(0x1fe0000000))
#define CDISASM_M68K_FEATURE_ALL (CDISASM_M68K_FEATURE_ALL_68K | CDISASM_M68K_FEATURE_ALL_CF)

/* Operand kinds; also the operand kinds of cdisasm_m68k_form. */
#define CDISASM_M68K_OP_NONE 0u
#define CDISASM_M68K_OP_EA 1u /* effective address; ea_mode says which */
#define CDISASM_M68K_OP_DREG 2u
#define CDISASM_M68K_OP_AREG 3u
#define CDISASM_M68K_OP_RREG 4u    /* Dn or An: reg 0-7 Dn, 8-15 An */
#define CDISASM_M68K_OP_PREDEC 5u  /* -(An) */
#define CDISASM_M68K_OP_POSTINC 6u /* (An)+ */
#define CDISASM_M68K_OP_DISP 7u    /* (d16,An) for movep */
#define CDISASM_M68K_OP_IND 8u     /* (An) */
#define CDISASM_M68K_OP_IMM 9u     /* immediate of the operation size */
#define CDISASM_M68K_OP_IMM_B 10u
#define CDISASM_M68K_OP_IMM_W 11u
#define CDISASM_M68K_OP_IMM_L 12u
#define CDISASM_M68K_OP_QUICK 13u /* 1-8 */
#define CDISASM_M68K_OP_SQ8 14u   /* moveq */
#define CDISASM_M68K_OP_U4 15u    /* trap vector */
#define CDISASM_M68K_OP_U3 16u    /* bkpt */
#define CDISASM_M68K_OP_S16 17u
#define CDISASM_M68K_OP_S32 18u
#define CDISASM_M68K_OP_U16 19u
#define CDISASM_M68K_OP_U32 20u
#define CDISASM_M68K_OP_BITIMM 21u /* bit number */
#define CDISASM_M68K_OP_CCR 22u
#define CDISASM_M68K_OP_SR 23u
#define CDISASM_M68K_OP_USP 24u
#define CDISASM_M68K_OP_BR8 25u /* branch target in imm */
#define CDISASM_M68K_OP_BR16 26u
#define CDISASM_M68K_OP_BR32 27u
#define CDISASM_M68K_OP_RLIST 28u /* value: bit n = Dn (n < 8), An (n >= 8) */
#define CDISASM_M68K_OP_CTL 29u   /* movec control register: reg = 12-bit code */
#define CDISASM_M68K_OP_BITFIELD 30u
#define CDISASM_M68K_OP_PAIR 31u  /* Dh:Dl / Dr:Dq: reg, reg2 */
#define CDISASM_M68K_OP_DPAIR 32u /* Dx:Dy */
#define CDISASM_M68K_OP_RPAIR 33u /* (Rn):(Rn) */
#define CDISASM_M68K_OP_FPREG 34u
#define CDISASM_M68K_OP_FPCTL 35u   /* value: 4 fpcr, 2 fpsr, 1 fpiar */
#define CDISASM_M68K_OP_FPLIST 36u  /* value: bit n = FPn */
#define CDISASM_M68K_OP_FPLISTR 37u /* same, predecrement encoding */
#define CDISASM_M68K_OP_FPDYN 38u   /* dynamic list in Dn */
#define CDISASM_M68K_OP_FSC 39u     /* FPc:FPs */
#define CDISASM_M68K_OP_KFAC 40u    /* static k-factor (imm, signed) */
#define CDISASM_M68K_OP_KDYN 41u    /* dynamic k-factor in Dn */
#define CDISASM_M68K_OP_ROM 42u     /* fmovecr ROM offset */
#define CDISASM_M68K_OP_CACHE 43u   /* 0 nc, 1 dc, 2 ic, 3 bc */
#define CDISASM_M68K_OP_ABSL 44u    /* 32-bit absolute (move16) */
#define CDISASM_M68K_OP_MMU 45u     /* reg: CDISASM_M68K_MMU_* */
#define CDISASM_M68K_OP_FC 46u      /* function code: reg 0 sfc, 1 dfc, 2 Dn (reg2), 3 #imm */
#define CDISASM_M68K_OP_MASK 47u
#define CDISASM_M68K_OP_LEVEL 48u
#define CDISASM_M68K_OP_CFCTL 49u   /* ColdFire movec register: value = 12-bit code */
#define CDISASM_M68K_OP_MACREG 50u  /* MAC/EMAC Rn: reg 0-15; value: half (0 .l, 1 .u, 2 none) | sf << 4 (1 <<, 3 >>) */
#define CDISASM_M68K_OP_MACMASK 51u /* "&": the load uses the MASK register (follows the EA operand) */
#define CDISASM_M68K_OP_ACC 52u     /* EMAC accumulator: reg 0-3 */
#define CDISASM_M68K_OP_MACCTL 53u  /* reg: CDISASM_M68K_MAC_* */
#define CDISASM_M68K_OP_Q3 54u      /* mov3q immediate: -1, 1-7 */

/* Effective-address modes (operand ea_mode). */
#define CDISASM_M68K_EA_DN 0u
#define CDISASM_M68K_EA_AN 1u
#define CDISASM_M68K_EA_IND 2u
#define CDISASM_M68K_EA_POSTINC 3u
#define CDISASM_M68K_EA_PREDEC 4u
#define CDISASM_M68K_EA_DISP 5u  /* (d16,An) */
#define CDISASM_M68K_EA_INDEX 6u /* (d8,An,Xn) or full format with An */
#define CDISASM_M68K_EA_ABS_W 7u
#define CDISASM_M68K_EA_ABS_L 8u
#define CDISASM_M68K_EA_PC_DISP 9u   /* (d16,PC) */
#define CDISASM_M68K_EA_PC_INDEX 10u /* (d8,PC,Xn) or full format with PC */
#define CDISASM_M68K_EA_IMM 11u

/* Operand ext_flags for EA_INDEX / EA_PC_INDEX. */
#define CDISASM_M68K_EXT_FULL 0x01u /* full-format extension word */
#define CDISASM_M68K_EXT_BASE_SUPPRESS 0x02u
#define CDISASM_M68K_EXT_INDEX_SUPPRESS 0x04u
#define CDISASM_M68K_EXT_MEM_INDIRECT 0x08u
#define CDISASM_M68K_EXT_POST_INDEXED 0x10u /* index applied after the indirection */
#define CDISASM_M68K_EXT_BD_SHIFT 5u        /* bd size: 0 none, 1 null, 2 word, 3 long */
#define CDISASM_M68K_EXT_OD_SHIFT 7u        /* (two bits in ext_flags2) */

#define CDISASM_M68K_MMU_TC 0u
#define CDISASM_M68K_MMU_SRP 1u
#define CDISASM_M68K_MMU_CRP 2u
#define CDISASM_M68K_MMU_MMUSR 3u
#define CDISASM_M68K_MMU_TT0 4u
#define CDISASM_M68K_MMU_TT1 5u
#define CDISASM_M68K_MMU_VAL 6u

#define CDISASM_M68K_MAC_ACC 0u /* MAC unit accumulator */
#define CDISASM_M68K_MAC_MACSR 1u
#define CDISASM_M68K_MAC_MASK 2u
#define CDISASM_M68K_MAC_ACCEXT01 3u
#define CDISASM_M68K_MAC_ACCEXT23 4u

/* Instruction flags. */
#define CDISASM_M68K_FLAG_JUMP 0x01u
#define CDISASM_M68K_FLAG_BRANCH 0x02u /* conditional */
#define CDISASM_M68K_FLAG_CALL 0x04u
#define CDISASM_M68K_FLAG_RETURN 0x08u
#define CDISASM_M68K_FLAG_TRAP 0x10u
#define CDISASM_M68K_FLAG_PRIVILEGED 0x20u

#define CDISASM_M68K_ACCESS_READ 1u
#define CDISASM_M68K_ACCESS_WRITE 2u

#define CDISASM_M68K_MAX_OPERANDS 6u
#define CDISASM_M68K_MAX_LENGTH 22u

typedef struct cdisasm_m68k_operand {
    uint8_t type;       /* CDISASM_M68K_OP_* */
    uint8_t ea_mode;    /* CDISASM_M68K_EA_* (type EA) */
    uint8_t size;       /* data size in bytes, 0 when not applicable */
    uint8_t access;     /* CDISASM_M68K_ACCESS_* */
    uint8_t reg;        /* register number, EA register, code (see type) */
    uint8_t reg2;       /* second register (pairs, index register 0-15, k-factor Dn) */
    uint8_t index_size; /* EA index: 2 (.w) or 4 (.l); 0 none */
    uint8_t scale;      /* EA index scale 1, 2, 4, 8 */
    uint8_t ext_flags;  /* CDISASM_M68K_EXT_* */
    uint8_t bd_size;    /* 0 none, 1 null, 2 word, 4 long (full format base displacement) */
    uint8_t od_size;    /* 0 none, 1 null, 2 word, 4 long (outer displacement) */
    uint8_t reserved;
    uint32_t value;       /* register lists, bit-field offset/width, control codes */
    int64_t disp;         /* d8, d16 or bd (sign-extended) */
    int64_t outer;        /* od (sign-extended) */
    uint64_t imm;         /* immediate (low 64 bits), absolute address, target */
    uint32_t imm_high;    /* bits 95-64 of 96-bit immediates */
    uint32_t ext_address; /* low 32 bits of the address of the EA's first extension word */
} cdisasm_m68k_operand;

typedef struct cdisasm_m68k_instruction {
    uint64_t address;
    uint64_t branch_target;
    uint64_t features; /* features the form requires */
    uint32_t length;
    uint32_t flags;   /* CDISASM_M68K_FLAG_* */
    uint16_t form_id; /* index into cdisasm_m68k_forms() */
    uint16_t name_id; /* cdisasm_m68k_name() */
    uint16_t opcode;  /* first word */
    char size;        /* 'b','w','l','q','s','d','x','p' or 0 */
    uint8_t suffix;   /* 1 when the size is spelled in the mnemonic */
    uint8_t operand_count;
    uint8_t reserved[3];
    cdisasm_m68k_operand operand[CDISASM_M68K_MAX_OPERANDS];
    uint8_t bytes[CDISASM_M68K_MAX_LENGTH];
} cdisasm_m68k_instruction;

/* Form descriptors (generated from tools/data/m68k/m68k_opcodes.txt). A
 * field is a bit slice of opcode word `word` (0 = first word); width 0 means
 * the literal `literal`. */
typedef struct cdisasm_m68k_field {
    uint8_t word;
    uint8_t lsb;
    uint8_t width;
    uint8_t literal;
} cdisasm_m68k_field;

typedef struct cdisasm_m68k_form_operand {
    uint8_t kind; /* CDISASM_M68K_OP_* */
    uint8_t access;
    uint8_t ea_class; /* index of the EA class (cdisasm_m68k_ea_class_modes()) */
    uint8_t field_count;
    cdisasm_m68k_field field[4];
} cdisasm_m68k_form_operand;

typedef struct cdisasm_m68k_constraint {
    uint8_t not_equal;
    cdisasm_m68k_field a;
    cdisasm_m68k_field b;
} cdisasm_m68k_constraint;

typedef struct cdisasm_m68k_form {
    uint64_t features; /* all required */
    uint64_t excluded; /* none may be present */
    uint16_t mask[3];
    uint16_t match[3];
    uint16_t name_id;
    char size;
    uint8_t suffix;
    uint8_t word_count; /* opcode words (1-3) */
    uint8_t flags;
    uint8_t operand_count;
    uint8_t constraint_count;
    uint8_t imm_bytes; /* bytes of an EA immediate; 0 = computed (fmovem.l) */
    cdisasm_m68k_form_operand operand[CDISASM_M68K_MAX_OPERANDS];
    cdisasm_m68k_constraint constraint[4];
} cdisasm_m68k_form;

/* Feature mask of a CPU (0 for an ID outside the group). */
CDISASM_API uint64_t CDISASM_CALL cdisasm_m68k_cpu_features(cdisasm_m68k_cpu_id cpu_id);
CDISASM_API const char *CDISASM_CALL cdisasm_m68k_cpu_name(cdisasm_m68k_cpu_id cpu_id);
/* Accepts 68000 ... 68060, 68lc040, cpu32, m68k (= 68000), any, the
 * ColdFire profiles (isa-a, isa-aplus, isa-b, isa-c, ..., cfv4e, coldfire;
 * ':' may replace '-', as in GNU's isa-a:nodiv) and the GNU CPU names
 * 5206e, 5307, 5407, 528x, 5249, 547x, 548x. 0 when unknown. */
CDISASM_API cdisasm_m68k_cpu_id CDISASM_CALL cdisasm_m68k_cpu_from_name(const char *name);
/* Unit options implied by a ColdFire part name ("5206e": MAC, "528x": EMAC):
 * CDISASM_M68K_FEATURE_* bits to pass as `mode`; 0 for other names. */
CDISASM_API uint32_t CDISASM_CALL cdisasm_m68k_cpu_name_options(const char *name);

CDISASM_API cdisasm_status CDISASM_CALL cdisasm_m68k_cpu_decode_flag_mask(cdisasm_m68k_cpu_id cpu_id, uint32_t mode, cdisasm_decode_flags *flags);

/* Decodes one instruction; returns its length (0 when invalid or truncated).
 * mode: extra CDISASM_M68K_FEATURE_* bits. flags may be NULL. */
CDISASM_API uint32_t CDISASM_CALL cdisasm_m68k_decode(cdisasm_m68k_cpu_id cpu_id, uint32_t mode, const uint8_t *code, size_t code_size, uint64_t address,
                                                      const cdisasm_decode_flags *flags, cdisasm_m68k_instruction *instruction);
/* Same with an explicit feature mask. */
CDISASM_API uint32_t CDISASM_CALL cdisasm_m68k_decode_features(uint64_t features, const uint8_t *code, size_t code_size, uint64_t address,
                                                               cdisasm_m68k_instruction *instruction);

CDISASM_API uint32_t CDISASM_CALL cdisasm_m68k_form_count(void);
CDISASM_API const cdisasm_m68k_form *CDISASM_CALL cdisasm_m68k_forms(void);
CDISASM_API const char *CDISASM_CALL cdisasm_m68k_name(uint32_t name_id);
/* Bit i set: EA mode index i (CDISASM_M68K_EA_*) belongs to class `ea_class`. */
CDISASM_API uint32_t CDISASM_CALL cdisasm_m68k_ea_class_modes(uint32_t ea_class);
CDISASM_API const char *CDISASM_CALL cdisasm_m68k_control_register_name(uint32_t code);
/* ColdFire movec register names (CFPRM MOVEC table); NULL when unassigned. */
CDISASM_API const char *CDISASM_CALL cdisasm_m68k_cf_control_register_name(uint32_t code);

/* Formatting (USE_DISASM_FORMAT). Motorola syntax: move.l (8,a0),d1;
 * CDISASM_M68K_FORMAT_REGISTER_PREFIX prints %d0 (GNU/LLVM spelling).
 * Returns the text length, 0 on failure. */
#define CDISASM_M68K_FORMAT_REGISTER_PREFIX 1u
CDISASM_API size_t CDISASM_CALL cdisasm_m68k_format(const cdisasm_m68k_instruction *instruction, uint32_t options, char *text, size_t capacity);
CDISASM_API size_t CDISASM_CALL cdisasm_m68k_format_operand(const cdisasm_m68k_instruction *instruction, uint32_t index, uint32_t options, char *text, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif
