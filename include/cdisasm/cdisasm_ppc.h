#ifndef CDISASM_CDISASM_PPC_H
#define CDISASM_CDISASM_PPC_H

/* Classic PowerPC, with ABI storage reserved for two ordered instruction words.
 * CPU, semantic and form IDs are append-only. Form IDs retain the 12.16.0
 * table indices; new forms append without changing existing indices.
 * mode is execution width 32 or 64 (0 selects 32). Doubleword operations
 * remain available in 32-bit mode on 64-bit processors; address width changes.
 * Byte order is a buffer property: zero flags means BE, not host byte order.
 * No union profile is provided for mutually incompatible PPC dialects. */
#include "cdisasm_common.h"
#ifdef __cplusplus
extern "C" {
#endif
#ifndef CDISASM_CPU_GROUP_PPC
#define CDISASM_CPU_GROUP_PPC UINT32_C(0x00050000)
#endif
typedef cdisasm_cpu_id cdisasm_ppc_cpu_id;
#define CDISASM_PPC_CPU_PPC32 (CDISASM_CPU_GROUP_PPC | 0u)
#define CDISASM_PPC_CPU_601 (CDISASM_CPU_GROUP_PPC | 1u)
#define CDISASM_PPC_CPU_603 (CDISASM_CPU_GROUP_PPC | 2u)
#define CDISASM_PPC_CPU_604 (CDISASM_CPU_GROUP_PPC | 3u)
#define CDISASM_PPC_CPU_750 (CDISASM_CPU_GROUP_PPC | 4u)
#define CDISASM_PPC_CPU_7400 (CDISASM_CPU_GROUP_PPC | 5u)
#define CDISASM_PPC_CPU_7410 (CDISASM_CPU_GROUP_PPC | 6u)
#define CDISASM_PPC_CPU_7450 (CDISASM_CPU_GROUP_PPC | 7u)
#define CDISASM_PPC_CPU_7455 (CDISASM_CPU_GROUP_PPC | 8u)
#define CDISASM_PPC_CPU_750CL (CDISASM_CPU_GROUP_PPC | 9u)
#define CDISASM_PPC_CPU_GEKKO (CDISASM_CPU_GROUP_PPC | 10u)
#define CDISASM_PPC_CPU_BROADWAY (CDISASM_CPU_GROUP_PPC | 11u)
#define CDISASM_PPC_CPU_PPC64 (CDISASM_CPU_GROUP_PPC | 12u)
#define CDISASM_PPC_CPU_970 (CDISASM_CPU_GROUP_PPC | 13u)
#define CDISASM_PPC_CPU_POWER4 (CDISASM_CPU_GROUP_PPC | 14u)
#define CDISASM_PPC_CPU_POWER5 (CDISASM_CPU_GROUP_PPC | 15u)
#define CDISASM_PPC_CPU_POWER6 (CDISASM_CPU_GROUP_PPC | 16u)
#define CDISASM_PPC_CPU_POWER7 (CDISASM_CPU_GROUP_PPC | 17u)
#define CDISASM_PPC_CPU_POWER8 (CDISASM_CPU_GROUP_PPC | 18u)
#define CDISASM_PPC_CPU_POWER9 (CDISASM_CPU_GROUP_PPC | 19u)
#define CDISASM_PPC_CPU_POWER10 (CDISASM_CPU_GROUP_PPC | 20u)
#define CDISASM_PPC_CPU_403 (CDISASM_CPU_GROUP_PPC | 21u)
#define CDISASM_PPC_CPU_405 (CDISASM_CPU_GROUP_PPC | 22u)
#define CDISASM_PPC_CPU_440 (CDISASM_CPU_GROUP_PPC | 23u)
#define CDISASM_PPC_CPU_460 (CDISASM_CPU_GROUP_PPC | 24u)
#define CDISASM_PPC_CPU_E500V1 (CDISASM_CPU_GROUP_PPC | 25u)
#define CDISASM_PPC_CPU_E500V2 (CDISASM_CPU_GROUP_PPC | 26u)
#define CDISASM_PPC_CPU_VLE (CDISASM_CPU_GROUP_PPC | 27u)
#define CDISASM_PPC_CPU_A2 (CDISASM_CPU_GROUP_PPC | 28u)
#define CDISASM_PPC_CPU_A2QPX (CDISASM_CPU_GROUP_PPC | 29u)
#define CDISASM_PPC_CPU_E500MC (CDISASM_CPU_GROUP_PPC | 30u)
#define CDISASM_PPC_CPU_E5500 (CDISASM_CPU_GROUP_PPC | 31u)
#define CDISASM_PPC_CPU_E6500 (CDISASM_CPU_GROUP_PPC | 32u)
#define CDISASM_PPC_CPU_476 (CDISASM_CPU_GROUP_PPC | 33u)
#define CDISASM_PPC_CPU_E200Z0 (CDISASM_CPU_GROUP_PPC | 34u)
#define CDISASM_PPC_CPU_E200Z0H (CDISASM_CPU_GROUP_PPC | 35u)
#define CDISASM_PPC_CPU_E200Z3 (CDISASM_CPU_GROUP_PPC | 36u)
#define CDISASM_PPC_CPU_E200Z4 (CDISASM_CPU_GROUP_PPC | 37u)
#define CDISASM_PPC_CPU_E200Z6 (CDISASM_CPU_GROUP_PPC | 38u)
#define CDISASM_PPC_CPU_E200Z7 (CDISASM_CPU_GROUP_PPC | 39u)
#define CDISASM_PPC_CPU_460EX (CDISASM_CPU_GROUP_PPC | 40u)
#define CDISASM_PPC_CPU_403GCX (CDISASM_CPU_GROUP_PPC | 41u)
#define CDISASM_PPC_CPU_POWER (CDISASM_CPU_GROUP_PPC | 42u)
#define CDISASM_PPC_CPU_POWER2 (CDISASM_CPU_GROUP_PPC | 43u)
#define CDISASM_PPC_CPU_COUNT 44u
#define CDISASM_PPC_MODE_32 32u
#define CDISASM_PPC_MODE_64 64u
#define CDISASM_PPC_MODE_MASK_32 1u
#define CDISASM_PPC_MODE_MASK_64 2u
#define CDISASM_PPC_FEATURE_BASE (UINT64_C(1) << 0)
#define CDISASM_PPC_FEATURE_FPU (UINT64_C(1) << 1)
#define CDISASM_PPC_FEATURE_SYSTEM (UINT64_C(1) << 2)
#define CDISASM_PPC_FEATURE_POWER601 (UINT64_C(1) << 3)
#define CDISASM_PPC_FEATURE_ESTIMATE (UINT64_C(1) << 4)
#define CDISASM_PPC_FEATURE_FSEL (UINT64_C(1) << 5)
#define CDISASM_PPC_FEATURE_TB (UINT64_C(1) << 6)
#define CDISASM_PPC_FEATURE_TLBSYNC (UINT64_C(1) << 7)
#define CDISASM_PPC_FEATURE_ECI (UINT64_C(1) << 8)
#define CDISASM_PPC_FEATURE_TLB603 (UINT64_C(1) << 9)
#define CDISASM_PPC_FEATURE_STFIWX (UINT64_C(1) << 10)
#define CDISASM_PPC_FEATURE_SQRT (UINT64_C(1) << 11)
/* Bits 12-15 remain reserved. VMX/PS are available on explicit profiles;
 * the other allocations below reserve later facilities. */
#define CDISASM_PPC_FEATURE_64 (UINT64_C(1) << 16)
#define CDISASM_PPC_FEATURE_VMX (UINT64_C(1) << 17)
#define CDISASM_PPC_FEATURE_VSX (UINT64_C(1) << 18)
#define CDISASM_PPC_FEATURE_PS (UINT64_C(1) << 19)
#define CDISASM_PPC_FEATURE_BOOKE (UINT64_C(1) << 20)
#define CDISASM_PPC_FEATURE_SPE (UINT64_C(1) << 21)
#define CDISASM_PPC_FEATURE_4XX (UINT64_C(1) << 22)
#define CDISASM_PPC_FEATURE_QPX (UINT64_C(1) << 23)
#define CDISASM_PPC_FEATURE_PREFIXED (UINT64_C(1) << 24)
#define CDISASM_PPC_FEATURE_MMA (UINT64_C(1) << 25)
#define CDISASM_PPC_FEATURE_ISA206 (UINT64_C(1) << 26)
#define CDISASM_PPC_FEATURE_ISA207 (UINT64_C(1) << 27)
#define CDISASM_PPC_FEATURE_ISA300 (UINT64_C(1) << 28)
#define CDISASM_PPC_FEATURE_ISA310 (UINT64_C(1) << 29)
#define CDISASM_PPC_FEATURE_DFP (UINT64_C(1) << 30)
#define CDISASM_PPC_FEATURE_HTM (UINT64_C(1) << 31)
#define CDISASM_PPC_FEATURE_CRYPTO (UINT64_C(1) << 32)
#define CDISASM_PPC_FEATURE_VLE (UINT64_C(1) << 33)
/* Original RS/6000 POWER dialect, distinct from the PowerPC601 subset. */
#define CDISASM_PPC_FEATURE_POWER (UINT64_C(1) << 34)
#define CDISASM_PPC_FEATURE_POWER2 (UINT64_C(1) << 35)
/* bitmap[0]: controls; bitmap[1]: facility enable; bitmap[2]: disable.
 * Enable/disable must not intersect; enable must be available on the profile.
 * FPU, VMX and PS can be disabled when available on the selected profile.
 * PS requires FPU; disabling FPU also makes PS arithmetic/transfers unavailable.
 * VMX/VSX and PS/SPE/QPX dialects cannot be combined.
 * Unknown bits/bitmap words are errors. */
#define CDISASM_PPC_DECODE_LITTLE_ENDIAN UINT64_C(1)
#define CDISASM_PPC_DECODE_BIG_ENDIAN UINT64_C(2)
/* VLE is an explicit instruction storage mode, independent of execution width.
 * It accepts BE storage only and halfword-aligned 16/32-bit instructions. */
#define CDISASM_PPC_DECODE_VLE UINT64_C(4)
#define CDISASM_PPC_ENCODING_CLASSIC 0u
#define CDISASM_PPC_ENCODING_VLE16 1u
#define CDISASM_PPC_ENCODING_VLE32 2u
#define CDISASM_PPC_MAX_LENGTH 8u
#define CDISASM_PPC_MAX_OPERANDS 6u
#define CDISASM_PPC_MAX_FIELD_SLICES 4u
#define CDISASM_PPC_OP_NONE 0u
#define CDISASM_PPC_OP_GPR 1u
#define CDISASM_PPC_OP_FPR 2u
#define CDISASM_PPC_OP_CRFIELD 3u
#define CDISASM_PPC_OP_CRBIT 4u
#define CDISASM_PPC_OP_IMM 5u
#define CDISASM_PPC_OP_SPR 6u
#define CDISASM_PPC_OP_TBR 7u
#define CDISASM_PPC_OP_MEM 8u
#define CDISASM_PPC_OP_MEMX 9u
#define CDISASM_PPC_OP_BRANCH 10u
#define CDISASM_PPC_OP_VR 11u
#define CDISASM_PPC_OP_VSR 12u
#define CDISASM_PPC_OP_QPX 13u
#define CDISASM_PPC_OP_SEGMENT 14u
#define CDISASM_PPC_OP_ACC 15u /* MMA accumulator 0-7, aliases four VSRs */
#define CDISASM_PPC_OPERAND_SIGNED 1u
#define CDISASM_PPC_OPERAND_ZERO_BASE 2u
#define CDISASM_PPC_OPERAND_UPDATE 4u
#define CDISASM_PPC_OPERAND_ABSOLUTE 8u
#define CDISASM_PPC_OPERAND_PC_RELATIVE 16u /* target is CIA plus displacement/immediate */
#define CDISASM_PPC_OPERAND_REDUCED_GPR 32u /* VLE RX/RY/RZ: 0..7,24..31 */
#define CDISASM_PPC_OPERAND_OFFSET_ONE 64u /* VLE OIM5: encoded 0..31 means 1..32 */
#define CDISASM_PPC_OPERAND_ALT_GPR 128u /* VLE ARX/ARY: encoded 0..15 means 8..23 */
#define CDISASM_PPC_ACCESS_READ 1u
#define CDISASM_PPC_ACCESS_WRITE 2u
#define CDISASM_PPC_FLAG_BRANCH 1u
#define CDISASM_PPC_FLAG_CONDITIONAL 2u
#define CDISASM_PPC_FLAG_CALL 4u
#define CDISASM_PPC_FLAG_RETURN 8u
#define CDISASM_PPC_FLAG_PRIVILEGED 16u
#define CDISASM_PPC_FLAG_TRAP 32u

/* Manual bits are numbered MSB-first: manual bit b = C bit 31-b.
 * Slices use C LSB positions. Each slice copies width bits to dst_lsb.
 * SPR halves, for example, are {0,16,5,0},{0,11,5,5}. */
typedef struct cdisasm_ppc_slice { uint8_t word, lsb, width, dst_lsb; } cdisasm_ppc_slice;
typedef struct cdisasm_ppc_field {
    uint64_t literal; /* used exactly when slice_count == 0 */
    uint8_t slice_count, width;
    uint8_t reserved[6];
    cdisasm_ppc_slice slice[CDISASM_PPC_MAX_FIELD_SLICES];
} cdisasm_ppc_field;
typedef struct cdisasm_ppc_form_operand {
    uint8_t kind, access, flags, width;
    uint8_t scale, size, field_count, recipe; /* CDISASM_PPC_RECIPE_*; VSR scale=1: pair index * 2 */
    /* Ordinary: field[0]=value. MEM: displacement,base. MEMX: base,index.
     * MEMX is one normalized operand, printed as two comma-separated GPRs. */
    cdisasm_ppc_field field[3];
} cdisasm_ppc_form_operand;
/* SCI8 width is the encoded 11-bit F:SCL:UI8 field; its value is expanded
 * to 32 bits (VLEPEM Rev.0 Table 3-2). SIGNED selects signed presentation.
 * Decoded IMM disp retains the raw field for exact reassembly; an optional
 * final SCL operand preserves redundant encodings of zero and all ones. */
#define CDISASM_PPC_RECIPE_IDENTITY 0u
#define CDISASM_PPC_RECIPE_SCI8 1u
/* Hash displacement: six encoded bits represent -64..-1, scaled by eight.
 * Power ISA 3.1B/C hashst/hashchk instruction definitions. */
#define CDISASM_PPC_RECIPE_HASH_DISP 2u
#define CDISASM_PPC_CONSTRAINT_EQ 0u
#define CDISASM_PPC_CONSTRAINT_NE 1u
#define CDISASM_PPC_CONSTRAINT_LT 2u
#define CDISASM_PPC_CONSTRAINT_BIT_SET 3u
#define CDISASM_PPC_CONSTRAINT_STRING 4u
#define CDISASM_PPC_CONSTRAINT_LMW 5u
#define CDISASM_PPC_CONSTRAINT_ONEOF 6u
#define CDISASM_PPC_CONSTRAINT_BO 7u /* profile-specific classic y/z or server a/t */
#define CDISASM_PPC_CONSTRAINT_CLEAR 10u /* (a & b) == 0 */
#define CDISASM_PPC_CONSTRAINT_ONEHOT 12u /* exactly one set bit in a */
#define CDISASM_PPC_CONSTRAINT_ROUND 13u /* R=a or RMC=b is 0/3 */
#define CDISASM_PPC_CONSTRAINT_VALUES 14u /* a < 64 and bit a of b is set */
#define CDISASM_PPC_CONSTRAINT_MMA 11u /* VSR b cannot alias accumulator a */
#define CDISASM_PPC_CONSTRAINT_ZEROIF 9u /* b nonzero requires a zero */
#define CDISASM_PPC_CONSTRAINT_NONZERO 8u /* at least one of a,b nonzero */
/* STRING: a=RT,b=RA,c=NB; RA must not be among ceil((NB?NB:32)/4)
 * target registers, wrapping modulo 32; RA=0 still participates in this check. */
typedef struct cdisasm_ppc_constraint {
    uint8_t kind, reserved[7];
    cdisasm_ppc_field a, b, c;
} cdisasm_ppc_constraint;
typedef struct cdisasm_ppc_form {
    uint64_t features, excluded;
    uint32_t mask[2], match[2];
    uint32_t name_id, profile_mask; /* profile ordinals 0..31 */
    uint8_t mode_mask, word_count, flags, operand_count;
    uint8_t constraint_count, encoding;
    /* Formerly reserved: bits 32..39 and 40..47 of the profile mask.
     * Use cdisasm_ppc_form_available() to query the complete selection.
     * VLE16 uses low 16 bits of words[0]. Structure layout is unchanged. */
    uint8_t profile_mask_high[2];
    cdisasm_ppc_field rc, oe, aa, lk;
    cdisasm_ppc_form_operand operand[CDISASM_PPC_MAX_OPERANDS];
    cdisasm_ppc_constraint constraint[4];
    const char *encoding_class;
    const char *provenance;
} cdisasm_ppc_form;
typedef struct cdisasm_ppc_operand {
    uint8_t type, access, flags, width;
    uint8_t scale, size, reg, base;
    uint8_t index, has_index, zero_base, recipe; /* CDISASM_PPC_RECIPE_* */
    int64_t value; /* sign extended where SIGNED; numeric SPR/TBR otherwise */
    int64_t disp;  /* scaled byte displacement; SCI8 raw F:SCL:UI8 */
    uint64_t target; /* branch target, modulo execution address width */
} cdisasm_ppc_operand;
typedef struct cdisasm_ppc_instruction {
    uint64_t address, branch_target, features;
    uint32_t length, flags, form_id, name_id, words[2];
    cdisasm_ppc_cpu_id cpu_id;
    uint8_t mode, operand_count, rc, oe, aa, lk, bo, bi;
    uint8_t bh, pcrel, reserved[6]; /* pcrel preserves the prefixed R control */
    cdisasm_ppc_operand operand[CDISASM_PPC_MAX_OPERANDS];
    uint8_t bytes[CDISASM_PPC_MAX_LENGTH];
} cdisasm_ppc_instruction;

/* Shared reversible alias recipes. base_name_id uses the semantic name table.
 * LI: drop zero RA. DUP: source 1==2, drop 2. SPR_FROM/TO: param SPR.
 * ROTATE: param 0 slwi, 1 srwi, 2 clrlwi, 3 rotlwi.
 * BCOND: param=BO*32+condition-bit; optional CR field then target.
 * BCOUNT: param BO; BI=0. BREG: BO=20,BI=0,BH=0, no operands.
 * BTEST: param BO; operands CR bit,target. NOP: ori 0,0,0.
 * CRDUP: CR logical with equal sources. LA accepted only, MEM->addi. */
#define CDISASM_PPC_ALIAS_LI 1u
#define CDISASM_PPC_ALIAS_DUP 2u
#define CDISASM_PPC_ALIAS_SPR_FROM 3u
#define CDISASM_PPC_ALIAS_SPR_TO 4u
#define CDISASM_PPC_ALIAS_ROTATE 5u
#define CDISASM_PPC_ALIAS_BCOND 6u
#define CDISASM_PPC_ALIAS_BCOUNT 7u
#define CDISASM_PPC_ALIAS_BREG 8u
#define CDISASM_PPC_ALIAS_BTEST 9u
#define CDISASM_PPC_ALIAS_NOP 10u
#define CDISASM_PPC_ALIAS_CRDUP 11u
#define CDISASM_PPC_ALIAS_LA 12u
#define CDISASM_PPC_ALIAS_CRSET 13u
#define CDISASM_PPC_ALIAS_TBR_FROM 14u
/* ROTATE64 parameters: sldi,srdi,clrldi,clrrdi,rotldi,rotrdi,rotld,
 * extldi,extrdi,insrdi,clrlsldi (0..10). */
#define CDISASM_PPC_ALIAS_ROTATE64 15u
#define CDISASM_PPC_ALIAS_PREFIXLI 16u /* param0 pli, param1 pla; paddi D,0,I,param */
#define CDISASM_PPC_ALIAS_BREGCOND 17u /* param BO*32+condition; optional CR field and BH */
#define CDISASM_PPC_ALIAS_BREGTEST 18u /* param BO; CR bit and optional BH */
#define CDISASM_PPC_ALIAS_BREGCOUNT 19u /* param BO; BI=0 and optional BH */
#define CDISASM_PPC_ALIAS_CONST 20u /* no source operands; fixed first immediate; optional second zero */
#define CDISASM_PPC_ALIAS_MEMIMM 21u /* indexed memory plus fixed final immediate param */
#define CDISASM_PPC_ALIAS_CONSTPAIR 22u /* no source operands; fixed L=param&7, SC=param>>3 */
#define CDISASM_PPC_ALIAS_MEMHINT 23u /* accepted indexed memory,TH; param0:TH0..7, param1:TH0/8..15 */
#define CDISASM_PPC_ALIAS_QPXLOGICAL 24u /* QPX truth table; param0/15 unary,5/10 binary,others ternary */
#define CDISASM_PPC_ALIAS_TLBILX 25u /* fixed T: param0/1 omit zero RA/RB, param3 retains RA/RB */
#define CDISASM_PPC_ALIAS_VSXPERM 26u /* xxpermdi: param0/3 fixed DM,2 duplicate XA with DM2,4 splat DM0/3 */
#define CDISASM_PPC_ALIAS_PREFIXSUB 27u /* psubi: negate SI and use paddi R=0; assembly-only */
#define CDISASM_PPC_ALIAS_TLBWORD 28u /* 403GCX: two registers and fixed third operand WS=param */
#define CDISASM_PPC_ALIAS_ESYNC 29u /* e6500: E, L=~E[2]; param0 E=0/lwsync, param1 E!=0/sync */
#define CDISASM_PPC_ALIAS_WCLR 30u /* A2: param2 wclrone RA,RB; param0 wclrall L (0/1), RA=RB=0 */
#define CDISASM_PPC_ALIAS_SUBIMM 31u /* POWER si: negate signed immediate, three operands */
#define CDISASM_PPC_ALIAS_LIL 32u /* POWER lil: cal RT,SI(0) */
#define CDISASM_PPC_ALIAS_PREPEND 33u /* prepend fixed first immediate (trap TO, mtcr FXM) */
#define CDISASM_PPC_ALIAS_TRAP 34u /* no operands: t param,0,0 */
#define CDISASM_PPC_ALIAS_ROTATE32EXPR 35u /* POWER extract/insert/rotate/clear source expressions */
typedef struct cdisasm_ppc_alias {
    const char *name;
    uint32_t base_name_id;
    uint16_t kind, param;
    uint16_t priority, preferred;
    const char *provenance;
} cdisasm_ppc_alias;

CDISASM_API uint64_t CDISASM_CALL cdisasm_ppc_cpu_features(cdisasm_ppc_cpu_id cpu);
CDISASM_API const char *CDISASM_CALL cdisasm_ppc_cpu_name(cdisasm_ppc_cpu_id cpu);
CDISASM_API cdisasm_ppc_cpu_id CDISASM_CALL cdisasm_ppc_cpu_from_name(const char *name);
CDISASM_API uint32_t CDISASM_CALL cdisasm_ppc_cpu_mode_mask(cdisasm_ppc_cpu_id cpu);
CDISASM_API cdisasm_status CDISASM_CALL cdisasm_ppc_cpu_decode_flag_mask(cdisasm_ppc_cpu_id cpu, uint32_t mode, cdisasm_decode_flags *flags);
CDISASM_API uint32_t CDISASM_CALL cdisasm_ppc_decode(cdisasm_ppc_cpu_id cpu, uint32_t mode, const uint8_t *code, size_t code_size, uint64_t address, const cdisasm_decode_flags *flags, cdisasm_ppc_instruction *instruction);
CDISASM_API uint32_t CDISASM_CALL cdisasm_ppc_form_count(void);
CDISASM_API const cdisasm_ppc_form *CDISASM_CALL cdisasm_ppc_forms(void);
CDISASM_API const char *CDISASM_CALL cdisasm_ppc_name(uint32_t name_id);
CDISASM_API uint32_t CDISASM_CALL cdisasm_ppc_alias_count(void);
CDISASM_API const cdisasm_ppc_alias *CDISASM_CALL cdisasm_ppc_aliases(void);
CDISASM_API uint64_t CDISASM_CALL cdisasm_ppc_field_get(const uint32_t words[2], const cdisasm_ppc_field *field);
CDISASM_API int CDISASM_CALL cdisasm_ppc_field_set(uint32_t words[2], const cdisasm_ppc_field *field, uint64_t value);
CDISASM_API int CDISASM_CALL cdisasm_ppc_form_available(const cdisasm_ppc_form *form, cdisasm_ppc_cpu_id cpu, uint32_t mode, const cdisasm_decode_flags *flags);
CDISASM_API int CDISASM_CALL cdisasm_ppc_form_valid(const cdisasm_ppc_form *form, cdisasm_ppc_cpu_id cpu, uint32_t mode, const cdisasm_decode_flags *flags, const uint32_t words[2]);
/* Deterministic valid sample; 0 means unavailable (or malformed form ID).
 * seed varies all operand/control bits. Intended for catalog consumers. */
CDISASM_API uint32_t CDISASM_CALL cdisasm_ppc_form_sample(cdisasm_ppc_cpu_id cpu, uint32_t mode, const cdisasm_decode_flags *flags, uint32_t form_id, uint32_t seed, uint8_t bytes[8]);
/* Published name for this profile/selector, or NULL; does not imply either
 * access direction, current privilege, or successful execution. Generic
 * profiles expose architectural names only. Unknown selectors stay numeric. */
CDISASM_API const char *CDISASM_CALL cdisasm_ppc_spr_name(cdisasm_ppc_cpu_id cpu, uint32_t spr);
/* Resolve a published name in the requested direction (write != 0).
 * Read/write selector pairs and implementation-specific restrictions apply.
 * Facility ownership is architectural; these queries do not take run-time
 * facility-enable or privilege state. Returns -1 for an unavailable name. */
CDISASM_API int32_t CDISASM_CALL cdisasm_ppc_spr_from_name(cdisasm_ppc_cpu_id cpu, const char *name, int write);
#define CDISASM_PPC_FORMAT_REGISTER_NAMES 1u
#define CDISASM_PPC_FORMAT_BASE_MNEMONICS 2u
CDISASM_API size_t CDISASM_CALL cdisasm_ppc_format(const cdisasm_ppc_instruction *instruction, uint32_t options, char *text, size_t capacity);
CDISASM_API size_t CDISASM_CALL cdisasm_ppc_format_operand(const cdisasm_ppc_instruction *instruction, uint32_t index, uint32_t options, char *text, size_t capacity);
#ifdef __cplusplus
}
#endif
#endif
